/*
 * PROJECT:     NitroOS SMB mini-redirector
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The channel to the user-mode SMB engine (see smbupcall.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * Requests live in one of three lists of SmbEngine (Queue -> Copying -> Sent) or in
 * none (completed). Every state change happens under SmbEngine.Lock, and a request
 * is completed exactly once: by its reply, by the timeout of its waiter, or by the
 * detach of the engine. The waiter owns the request; a GET that copies it out holds
 * an extra reference. Message and reply buffers are paged and are only allocated,
 * copied and freed at PASSIVE_LEVEL, outside the lock.
 */

#include "mrxsmb.h"
#include <wdmsec.h>

#define NDEBUG
#include <debug.h>

#define SMB_MAX_QUEUED_REQUESTS 4096

SMB_ENGINE SmbEngine;
PDEVICE_OBJECT SmbEngineDevice;
static LIST_ENTRY SmbCopyingList;

VOID
SmbEngineInitialize(VOID)
{
    RtlZeroMemory(&SmbEngine, sizeof(SmbEngine));
    KeInitializeSpinLock(&SmbEngine.Lock);
    InitializeListHead(&SmbEngine.Queue);
    InitializeListHead(&SmbEngine.Sent);
    InitializeListHead(&SmbCopyingList);
    KeInitializeSemaphore(&SmbEngine.QueueSemaphore, 0, MAXLONG);
    KeInitializeEvent(&SmbEngine.DetachEvent, NotificationEvent, TRUE);
}

NTSTATUS
SmbEngineCreateDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(NITRO_SMBRDR_ENGINE_DEVICE);
    /* SYSTEM, LocalService (the engine service account) and administrators */
    UNICODE_STRING Sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;LS)(A;;GA;;;BA)");

    return IoCreateDeviceSecure(DriverObject,
                                0,
                                &Name,
                                FILE_DEVICE_NETWORK_REDIRECTOR,
                                FILE_DEVICE_SECURE_OPEN,
                                FALSE,
                                &Sddl,
                                NULL,
                                &SmbEngineDevice);
}

VOID
SmbEngineDeleteDevice(VOID)
{
    if (SmbEngineDevice != NULL)
    {
        IoDeleteDevice(SmbEngineDevice);
        SmbEngineDevice = NULL;
    }
}

BOOLEAN
SmbIsEngineProcess(PEPROCESS Process)
{
    /* A racy read is fine: the engine process cannot change while one of its threads asks */
    return Process != NULL && Process == SmbEngine.Process;
}

ULONG
SmbCurrentGeneration(VOID)
{
    return *(volatile ULONG *)&SmbEngine.Generation;
}

static
VOID
SmbFreeRequest(PSMB_REQUEST Request)
{
    PAGED_CODE();

    if (Request->Token != NULL)
        ObDereferenceObject(Request->Token);
    if (Request->Message != NULL)
        ExFreePoolWithTag(Request->Message, TAG_SMB_MESSAGE);
    if (Request->Reply != NULL)
        ExFreePoolWithTag(Request->Reply, TAG_SMB_REPLY);
    ExFreePoolWithTag(Request, TAG_SMB_REQUEST);
}

VOID
SmbReleaseRequest(PSMB_REQUEST Request)
{
    if (InterlockedDecrement(&Request->RefCount) == 0)
        SmbFreeRequest(Request);
}

NTSTATUS
SmbAllocateRequest(
    USHORT Opcode,
    ULONG VariableSize,
    PLUID LogonId,
    PSMB_REQUEST *Out)
{
    PSMB_REQUEST Request;
    ULONGLONG Total;

    PAGED_CODE();

    *Out = NULL;
    if (Opcode <= SmbUpInvalid || Opcode >= SmbUpMaximumOpcode)
        return STATUS_INVALID_PARAMETER;

    /* Room for 8-byte alignment of each variable item (at most 5 per message) */
    Total = (ULONGLONG)sizeof(SMBUP_HEADER) + SMBUP_REQUEST_FIXED_SIZE(Opcode) + VariableSize + 5 * 8;
    if (Total > SMBUP_MAX_MESSAGE)
        return STATUS_INVALID_PARAMETER;

    Request = ExAllocatePoolZero(NonPagedPool, sizeof(*Request), TAG_SMB_REQUEST);
    if (Request == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    Request->Message = ExAllocatePoolZero(PagedPool, (SIZE_T)Total, TAG_SMB_MESSAGE);
    if (Request->Message == NULL)
    {
        ExFreePoolWithTag(Request, TAG_SMB_REQUEST);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Request->RefCount = 1;
    Request->Opcode = Opcode;
    Request->Notification = (Opcode == SmbUpLogoff || Opcode == SmbUpCancel);
    KeInitializeEvent(&Request->Done, NotificationEvent, FALSE);

    /* The size is final once the variable data is in: see SmbRequestPutBytes */
    Request->MessageSize = sizeof(SMBUP_HEADER) + SMBUP_REQUEST_FIXED_SIZE(Opcode);
    Request->Message->Magic = SMBUP_MAGIC;
    Request->Message->Version = SMBUP_VERSION;
    Request->Message->Opcode = Opcode;
    Request->Message->HeaderSize = sizeof(SMBUP_HEADER);
    Request->Message->TotalSize = Request->MessageSize;
    Request->Message->ProcessId = HandleToUlong(PsGetCurrentProcessId());
    Request->Message->Flags = Request->Notification ? SMBUP_FLAG_NOTIFICATION : 0;
    if (LogonId != NULL)
    {
        Request->Message->LogonIdLow = LogonId->LowPart;
        Request->Message->LogonIdHigh = LogonId->HighPart;
    }

    Request->MessageAllocation = (ULONG)Total;

    *Out = Request;
    return STATUS_SUCCESS;
}

PVOID
SmbRequestFixed(PSMB_REQUEST Request)
{
    return (PUCHAR)Request->Message + sizeof(SMBUP_HEADER);
}

/* Appends Length bytes at the next 8-byte boundary; String (optional) gets offset and length */
NTSTATUS
SmbRequestPutBytes(
    PSMB_REQUEST Request,
    ULONG *Cursor,
    const VOID *Data,
    ULONG Length,
    PSMBUP_STRING String)
{
    ULONG Offset = *Cursor ? *Cursor : Request->MessageSize;

    Offset = ALIGN_UP_BY(Offset, 8);
    if (Offset > Request->MessageAllocation || Length > Request->MessageAllocation - Offset)
        return STATUS_BUFFER_OVERFLOW;

    if (Length != 0)
        RtlCopyMemory((PUCHAR)Request->Message + Offset, Data, Length);
    if (String != NULL)
    {
        String->Offset = Length ? Offset : 0;
        String->Length = Length;
    }
    *Cursor = Offset + Length;
    Request->MessageSize = Offset + Length;
    Request->Message->TotalSize = Request->MessageSize;
    return STATUS_SUCCESS;
}

/* Called with the lock held: completes a request that is in one of the lists */
static
VOID
SmbCompleteLocked(PSMB_REQUEST Request, NTSTATUS Status)
{
    ASSERT(Request->State != SmbRequestCompleted);

    if (Request->State == SmbRequestQueued)
        SmbEngine.QueueLength--;
    RemoveEntryList(&Request->Link);
    InitializeListHead(&Request->Link);
    Request->State = SmbRequestCompleted;
    Request->Status = Status;
    KeSetEvent(&Request->Done, IO_NO_INCREMENT, FALSE);
}

static
NTSTATUS
SmbQueueRequest(PSMB_REQUEST Request)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
    if (SmbEngine.FileObject == NULL)
    {
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        return STATUS_REDIRECTOR_NOT_STARTED;
    }
    if (SmbEngine.QueueLength >= SMB_MAX_QUEUED_REQUESTS)
    {
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Request->RequestId = ++SmbEngine.NextRequestId;
    Request->Message->RequestId = Request->RequestId;
    Request->Generation = SmbEngine.Generation;
    Request->State = SmbRequestQueued;
    InsertTailList(&SmbEngine.Queue, &Request->Link);
    SmbEngine.QueueLength++;
    KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

    KeReleaseSemaphore(&SmbEngine.QueueSemaphore, IO_NO_INCREMENT, 1, FALSE);
    return STATUS_SUCCESS;
}

/* A notification (LOGOFF, CANCEL): queued, no reply; the queue owns it */
VOID
SmbSendNotification(PSMB_REQUEST Request)
{
    ASSERT(Request->Notification);

    if (!NT_SUCCESS(SmbQueueRequest(Request)))
        SmbReleaseRequest(Request);
}

static
VOID
SmbSendCancel(ULONGLONG RequestId)
{
    PSMB_REQUEST Cancel;
    PSMBUP_CANCEL_REQUEST Fixed;

    if (!NT_SUCCESS(SmbAllocateRequest(SmbUpCancel, 0, NULL, &Cancel)))
        return;
    Fixed = SmbRequestFixed(Cancel);
    Fixed->RequestId = RequestId;
    SmbSendNotification(Cancel);
}

/*
 * Sends the request and waits for its reply, the engine's detach or the timeout,
 * whichever comes first. Returns the status of the exchange; the reply (if any)
 * is checked with SmbReplyStatus.
 */
NTSTATUS
SmbSendRequest(PSMB_REQUEST Request, ULONG TimeoutSeconds)
{
    NTSTATUS Status;
    LARGE_INTEGER Timeout;
    KIRQL OldIrql;
    BOOLEAN WasSent = FALSE;

    PAGED_CODE();
    ASSERT(!Request->Notification);

    Status = SmbQueueRequest(Request);
    if (!NT_SUCCESS(Status))
        return Status;

    Timeout.QuadPart = -10000000LL * (TimeoutSeconds ? TimeoutSeconds : NITRO_SMBRDR_REQUEST_TIMEOUT_SECONDS);
    Status = KeWaitForSingleObject(&Request->Done, Executive, KernelMode, FALSE, &Timeout);
    if (Status == STATUS_TIMEOUT)
    {
        KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
        if (Request->State != SmbRequestCompleted)
        {
            WasSent = (Request->State != SmbRequestQueued);
            SmbCompleteLocked(Request, STATUS_IO_TIMEOUT);
        }
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

        DPRINT1("mrxsmb: request %I64u (op %u) timed out\n", Request->RequestId, Request->Opcode);
        if (WasSent)
            SmbSendCancel(Request->RequestId);
    }

    /* Completed: Done is set under the lock together with the state */
    return Request->Status;
}

/*
 * Checks the common part of the reply to Request and returns the operation's
 * status. For replies with data (SMBUP_DATA_REPLY), Data/DataLength describe the
 * data, at most MaxDataLength bytes, inside the reply. Anything malformed is
 * STATUS_INVALID_NETWORK_RESPONSE.
 */
NTSTATUS
SmbReplyStatus(PSMB_REQUEST Request, ULONG MaxDataLength, PVOID *Data, PULONG DataLength)
{
    PSMBUP_HEADER Reply = Request->Reply;
    ULONG Fixed = SMBUP_REPLY_FIXED_SIZE(Request->Opcode);
    NTSTATUS Status;

    if (Data != NULL)
        *Data = NULL;
    if (DataLength != NULL)
        *DataLength = 0;

    if (!NT_SUCCESS(Request->Status))
        return Request->Status;
    if (Reply == NULL)
        return STATUS_INVALID_NETWORK_RESPONSE;

    /* The header was checked when the reply was taken; the opcode and id match */
    Status = Reply->Status;

    /* Statuses a caller can get back. Anything else would let the engine steer the
     * I/O manager (STATUS_PENDING, STATUS_REPARSE, other informational codes) */
    if (!NT_ERROR(Status) &&
        Status != STATUS_SUCCESS &&
        Status != STATUS_BUFFER_OVERFLOW &&
        Status != STATUS_NO_MORE_FILES)
    {
        DPRINT1("mrxsmb: engine status %lx refused\n", Status);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (Status == STATUS_PENDING || Status == STATUS_REPARSE)
        return STATUS_INVALID_NETWORK_RESPONSE;

    if (NT_ERROR(Status) || Status == STATUS_NO_MORE_FILES)
        return Status;

    /* Success or overflow: the fixed part must be there */
    if (Request->ReplySize < sizeof(SMBUP_HEADER) + Fixed)
        return STATUS_INVALID_NETWORK_RESPONSE;

    if (Data != NULL && Fixed == sizeof(SMBUP_DATA_REPLY))
    {
        PSMBUP_DATA_REPLY DataReply = (PSMBUP_DATA_REPLY)(Reply + 1);

        if (Request->Opcode == SmbUpWrite)
        {
            /* WRITE: Length is a count, no data */
            if (DataReply->Length > MaxDataLength)
                return STATUS_INVALID_NETWORK_RESPONSE;
            *DataLength = DataReply->Length;
            return Status;
        }

        if (DataReply->Length > MaxDataLength ||
            !SMBUP_RANGE_VALID(DataReply->DataOffset, DataReply->Length,
                               sizeof(SMBUP_HEADER) + Fixed, Request->ReplySize, 1))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *Data = DataReply->Length ? (PUCHAR)Reply + DataReply->DataOffset : NULL;
        *DataLength = DataReply->Length;
    }

    return Status;
}

/* IRP handlers of the engine device ***************************************/

static
NTSTATUS
SmbEngineAttach(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PSMBUP_ATTACH Attach = Irp->AssociatedIrp.SystemBuffer;
    KIRQL OldIrql;
    PEPROCESS Process;

    if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(SMBUP_ATTACH) || Attach == NULL)
        return STATUS_INVALID_PARAMETER;
    if (Attach->Magic != SMBUP_MAGIC || Attach->Version != SMBUP_VERSION)
        return STATUS_REVISION_MISMATCH;
    if (Attach->MaxMessageSize < SMBUP_MAX_MESSAGE)
        return STATUS_INVALID_PARAMETER;

    /* The engine gets users' tokens: it must be allowed to impersonate */
    if (!SeSinglePrivilegeCheck(SeExports->SeImpersonatePrivilege, Irp->RequestorMode))
        return STATUS_PRIVILEGE_NOT_HELD;

    Process = IoGetCurrentProcess();
    ObReferenceObject(Process);

    KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
    if (SmbEngine.FileObject != NULL)
    {
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        ObDereferenceObject(Process);
        return STATUS_SHARING_VIOLATION;
    }
    SmbEngine.FileObject = Stack->FileObject;
    SmbEngine.Process = Process;
    SmbEngine.Generation++;
    KeClearEvent(&SmbEngine.DetachEvent);
    KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

    DPRINT1("mrxsmb: engine attached (process %p, generation %lu)\n", Process, SmbEngine.Generation);
    return STATUS_SUCCESS;
}

/* The engine handle closed (or DETACH): fail everything it has not answered */
static
VOID
SmbEngineDetach(PFILE_OBJECT FileObject)
{
    LIST_ENTRY Release;
    PLIST_ENTRY Lists[3] = { &SmbEngine.Queue, &SmbCopyingList, &SmbEngine.Sent };
    PSMB_REQUEST Request;
    PEPROCESS Process;
    KIRQL OldIrql;
    ULONG i, Failed = 0;

    PAGED_CODE();

    InitializeListHead(&Release);

    KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
    if (SmbEngine.FileObject != FileObject || FileObject == NULL)
    {
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        return;
    }

    SmbEngine.FileObject = NULL;
    Process = SmbEngine.Process;
    SmbEngine.Process = NULL;
    SmbEngine.Generation++;

    for (i = 0; i < RTL_NUMBER_OF(Lists); i++)
    {
        while (!IsListEmpty(Lists[i]))
        {
            Request = CONTAINING_RECORD(Lists[i]->Flink, SMB_REQUEST, Link);
            SmbCompleteLocked(Request, STATUS_CONNECTION_DISCONNECTED);
            Failed++;
            /* Nobody waits for a notification: free it once outside the lock.
             * A notification being copied keeps its GET reference. */
            if (Request->Notification)
                InsertTailList(&Release, &Request->Link);
        }
    }
    KeSetEvent(&SmbEngine.DetachEvent, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

    while (!IsListEmpty(&Release))
    {
        Request = CONTAINING_RECORD(RemoveHeadList(&Release), SMB_REQUEST, Link);
        InitializeListHead(&Request->Link);
        SmbReleaseRequest(Request);
    }

    if (Process != NULL)
        ObDereferenceObject(Process);

    DPRINT1("mrxsmb: engine detached, %lu requests failed\n", Failed);
}

static
NTSTATUS
SmbEngineGet(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PVOID Objects[2] = { &SmbEngine.QueueSemaphore, &SmbEngine.DetachEvent };
    KWAIT_BLOCK WaitBlocks[2];
    PSMB_REQUEST Request;
    NTSTATUS Status;
    KIRQL OldIrql;
    HANDLE TokenHandle;
    BOOLEAN Delivered;
    PUCHAR Out = Irp->AssociatedIrp.SystemBuffer;

    PAGED_CODE();

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < SMBUP_MAX_MESSAGE || Out == NULL)
        return STATUS_BUFFER_TOO_SMALL;

    for (;;)
    {
        if (SmbEngine.FileObject != Stack->FileObject)
            return STATUS_CONNECTION_DISCONNECTED;

        /* Alertable in user mode: the engine's threads can be terminated while they wait */
        Status = KeWaitForMultipleObjects(2, Objects, WaitAny, UserRequest, UserMode, TRUE, NULL, WaitBlocks);
        if (Status == STATUS_WAIT_1)
            return STATUS_CONNECTION_DISCONNECTED;
        if (Status != STATUS_WAIT_0)
            return Status;

        KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
        if (SmbEngine.FileObject != Stack->FileObject)
        {
            KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
            /* Give the count back for the engine that is attached now, if any */
            KeReleaseSemaphore(&SmbEngine.QueueSemaphore, IO_NO_INCREMENT, 1, FALSE);
            return STATUS_CONNECTION_DISCONNECTED;
        }
        if (IsListEmpty(&SmbEngine.Queue))
        {
            /* Its request timed out before we took it */
            KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
            continue;
        }
        Request = CONTAINING_RECORD(RemoveHeadList(&SmbEngine.Queue), SMB_REQUEST, Link);
        SmbEngine.QueueLength--;
        Request->State = SmbRequestCopying;
        InsertTailList(&SmbCopyingList, &Request->Link);
        InterlockedIncrement(&Request->RefCount);
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

        ASSERT(Request->MessageSize <= SMBUP_MAX_MESSAGE);
        RtlCopyMemory(Out, Request->Message, Request->MessageSize);

        /* CONNECT: a handle to the user's token, in this (the engine's) process,
         * allowing query and impersonation only */
        TokenHandle = NULL;
        if (Request->Opcode == SmbUpConnect && Request->Token != NULL)
        {
            Status = ObOpenObjectByPointer(Request->Token,
                                           0,
                                           NULL,
                                           TOKEN_QUERY | TOKEN_IMPERSONATE,
                                           *SeTokenObjectType,
                                           KernelMode,
                                           &TokenHandle);
            if (!NT_SUCCESS(Status))
                TokenHandle = NULL;
            ((PSMBUP_CONNECT_REQUEST)(Out + sizeof(SMBUP_HEADER)))->TokenHandle = (ULONGLONG)(ULONG_PTR)TokenHandle;
        }

        KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
        Delivered = (Request->State == SmbRequestCopying);
        if (Delivered)
        {
            RemoveEntryList(&Request->Link);
            if (Request->Notification)
            {
                /* Done once the engine has it */
                InitializeListHead(&Request->Link);
                Request->State = SmbRequestCompleted;
                Request->Status = STATUS_SUCCESS;
                InterlockedDecrement(&Request->RefCount);   /* the queue's reference */
            }
            else
            {
                Request->State = SmbRequestSent;
                InsertTailList(&SmbEngine.Sent, &Request->Link);
            }
        }
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

        SmbReleaseRequest(Request);

        if (!Delivered)
        {
            /* Timed out or detached meanwhile: do not hand out a token for it */
            if (TokenHandle != NULL)
                ZwClose(TokenHandle);   /* a handle of this (the engine's) process */
            continue;
        }

        Irp->IoStatus.Information = ((PSMBUP_HEADER)Out)->TotalSize;
        return STATUS_SUCCESS;
    }
}

static
NTSTATUS
SmbEngineReply(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG Length = Stack->Parameters.DeviceIoControl.InputBufferLength;
    PSMBUP_HEADER Reply;
    PSMB_REQUEST Request = NULL;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    PAGED_CODE();

    if (SmbEngine.FileObject != Stack->FileObject)
        return STATUS_CONNECTION_DISCONNECTED;
    if (Length < sizeof(SMBUP_HEADER) || Length > SMBUP_MAX_MESSAGE || Irp->AssociatedIrp.SystemBuffer == NULL)
        return STATUS_INVALID_PARAMETER;

    /* Our own copy: the checks below and the waiter's checks see the same bytes */
    Reply = ExAllocatePoolWithTag(PagedPool, Length, TAG_SMB_REPLY);
    if (Reply == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Reply, Irp->AssociatedIrp.SystemBuffer, Length);

    if (Reply->Magic != SMBUP_MAGIC ||
        Reply->Version != SMBUP_VERSION ||
        Reply->HeaderSize != sizeof(SMBUP_HEADER) ||
        Reply->TotalSize != Length ||
        Reply->Opcode <= SmbUpInvalid || Reply->Opcode >= SmbUpMaximumOpcode ||
        Reply->Opcode == SmbUpLogoff || Reply->Opcode == SmbUpCancel)
    {
        ExFreePoolWithTag(Reply, TAG_SMB_REPLY);
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
    for (Entry = SmbEngine.Sent.Flink; Entry != &SmbEngine.Sent; Entry = Entry->Flink)
    {
        PSMB_REQUEST Candidate = CONTAINING_RECORD(Entry, SMB_REQUEST, Link);

        if (Candidate->RequestId == Reply->RequestId)
        {
            Request = Candidate;
            break;
        }
    }
    if (Request == NULL || Request->Opcode != Reply->Opcode || Request->Generation != SmbEngine.Generation)
    {
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        ExFreePoolWithTag(Reply, TAG_SMB_REPLY);
        /* Unknown, already timed out, or the wrong opcode for that id */
        return STATUS_NOT_FOUND;
    }

    Request->Reply = Reply;
    Request->ReplySize = Length;
    SmbCompleteLocked(Request, STATUS_SUCCESS);
    KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

    return STATUS_SUCCESS;
}

/* IRP_MJ_* of \Device\NitroSmbEngine */
NTSTATUS
SmbEngineDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    Irp->IoStatus.Information = 0;

    switch (Stack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            /* The device itself only, no names below it */
            Status = (Stack->FileObject->FileName.Length == 0 && Stack->FileObject->RelatedFileObject == NULL) ?
                     STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
            break;

        case IRP_MJ_CLEANUP:
            SmbEngineDetach(Stack->FileObject);
            Status = STATUS_SUCCESS;
            break;

        case IRP_MJ_CLOSE:
            Status = STATUS_SUCCESS;
            break;

        case IRP_MJ_DEVICE_CONTROL:
            switch (Stack->Parameters.DeviceIoControl.IoControlCode)
            {
                case IOCTL_SMBRDR_ENGINE_ATTACH:
                    Status = SmbEngineAttach(Irp, Stack);
                    break;
                case IOCTL_SMBRDR_ENGINE_GET:
                    Status = SmbEngineGet(Irp, Stack);
                    break;
                case IOCTL_SMBRDR_ENGINE_REPLY:
                    Status = SmbEngineReply(Irp, Stack);
                    break;
                case IOCTL_SMBRDR_ENGINE_DETACH:
                    SmbEngineDetach(Stack->FileObject);
                    Status = STATUS_SUCCESS;
                    break;
                case IOCTL_SMBRDR_QUERY_STATE:
                    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG))
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                        break;
                    }
                    *(PULONG)Irp->AssociatedIrp.SystemBuffer = (SmbEngine.FileObject != NULL);
                    Irp->IoStatus.Information = sizeof(ULONG);
                    Status = STATUS_SUCCESS;
                    break;
                default:
                    Status = STATUS_INVALID_DEVICE_REQUEST;
                    break;
            }
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
