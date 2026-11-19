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
#undef INVALID_HANDLE_VALUE /* the NDK defines it again */
#include <ndk/pstypes.h>    /* ETHREAD.IrpList */

#define NDEBUG
#include <debug.h>

#define SMB_MAX_QUEUED_REQUESTS 4096

SMB_ENGINE SmbEngine;
PDEVICE_OBJECT SmbEngineDevice;
ULONG SmbRequestTimeoutSeconds = NITRO_SMBRDR_REQUEST_TIMEOUT_SECONDS;
static LIST_ENTRY SmbCopyingList;

/* Demand start: the starter (the Workstation service) waits in IOCTL_SMBRDR_WAIT_ENGINE_NEEDED for
 * SmbNeedEvent; a request without an engine sets it and waits for SmbAttachedEvent */
static KEVENT SmbNeedEvent;             /* synchronization: one wake-up per need */
static KEVENT SmbAttachedEvent;         /* notification: set while an engine is attached */
static KEVENT SmbStartFailedEvent;      /* notification: set while the last start of an engine has failed */
static volatile LONG SmbStarterWaiters; /* threads inside IOCTL_SMBRDR_WAIT_ENGINE_NEEDED right now */
/* Interrupt times (100 ns): the starter was woken and is starting an engine until ...; the start has failed,
 * so requests that need an engine fail at once until ... */
static volatile ULONGLONG SmbStarterBusyUntil;
static volatile ULONGLONG SmbStartFailedUntil;
/* Read and written from several threads without a common lock: whole 64-bit values (two halves on x86) */
#define SmbReadTime(p)     ((ULONGLONG)InterlockedCompareExchange64((volatile LONGLONG *)(p), 0, 0))
#define SmbWriteTime(p, v) ((VOID)InterlockedExchange64((volatile LONGLONG *)(p), (LONGLONG)(v)))

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
    KeInitializeEvent(&SmbEngine.BudgetEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&SmbNeedEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&SmbAttachedEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&SmbStartFailedEvent, NotificationEvent, FALSE);
}

/*
 * The caller of this wait gave up the UNC open it is for. MUP asks the providers from inside the
 * caller's own system service, with an IRP of its own: CancelSynchronousIo marks the open's IRP in
 * the thread's list, not that one, so the thread's list is looked at too (as its owner does, at
 * APC_LEVEL); a terminating thread has no use for the answer either.
 */
static
BOOLEAN
SmbCallerGaveUp(PIRP QueryIrp)
{
    PETHREAD Thread = PsGetCurrentThread();
    PLIST_ENTRY Head, Entry;
    BOOLEAN Gave = FALSE;
    KIRQL OldIrql;

    if (SmbIrpCancelled(QueryIrp) || PsIsThreadTerminating(Thread))
        return TRUE;

    KeRaiseIrql(APC_LEVEL, &OldIrql);
    Head = &Thread->IrpList;
    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        PIRP Irp = CONTAINING_RECORD(Entry, IRP, ThreadListEntry);
        PFILE_OBJECT File = Irp->Tail.Overlay.OriginalFileObject;

        if (Irp->Cancel && !(Irp->Flags & (IRP_CLOSE_OPERATION | IRP_PAGING_IO)) &&
            ((Irp->Flags & IRP_SYNCHRONOUS_API) || (File != NULL && (File->Flags & FO_SYNCHRONOUS_IO))))
        {
            Gave = TRUE;
            break;
        }
    }
    KeLowerIrql(OldIrql);
    return Gave;
}

/* The start of an engine has failed (the starter said so, or none attached in time): until then,
 * requests that need an engine fail at once instead of each waiting for the starter again */
static
VOID
SmbNoteStartFailed(VOID)
{
    SmbWriteTime(&SmbStartFailedUntil, KeQueryInterruptTime() + (ULONGLONG)NITRO_SMBRDR_ENGINE_FAIL_CACHE_SECONDS * 10000000ULL);
    SmbWriteTime(&SmbStarterBusyUntil, 0);
    KeSetEvent(&SmbStartFailedEvent, IO_NO_INCREMENT, FALSE);
}

/*
 * An engine for a user's request: at once if one is attached; otherwise, if a starter is
 * there, ask it for one and wait (NITRO_SMBRDR_ENGINE_START_WAIT_SECONDS at most, in slices
 * that end early when the starter reports that it could not start one, and when Irp is
 * given up: cancelled, or its thread terminating). Without a starter (the client is switched
 * off, the Workstation service is stopped, or the engine was started by hand) or after a
 * failed start (for NITRO_SMBRDR_ENGINE_FAIL_CACHE_SECONDS) there is nothing to wait for:
 * the request fails at once, so that a UNC open of any other provider is not held up.
 */
NTSTATUS
SmbEnsureEngine(PIRP Irp)
{
    PVOID Events[2] = { &SmbAttachedEvent, &SmbStartFailedEvent };
    LARGE_INTEGER Slice;
    ULONGLONG Now, Deadline;
    NTSTATUS Status;

    PAGED_CODE();

    if (SmbEngine.FileObject != NULL)
        return STATUS_SUCCESS;
    Now = KeQueryInterruptTime();
    if (SmbStarterWaiters == 0 && Now >= SmbReadTime(&SmbStarterBusyUntil))
        return STATUS_REDIRECTOR_NOT_STARTED;
    if (Now < SmbReadTime(&SmbStartFailedUntil))
        return STATUS_REDIRECTOR_NOT_STARTED;

    KeClearEvent(&SmbStartFailedEvent);
    KeSetEvent(&SmbNeedEvent, IO_NO_INCREMENT, FALSE);
    Deadline = Now + (ULONGLONG)NITRO_SMBRDR_ENGINE_START_WAIT_SECONDS * 10000000ULL;
    Slice.QuadPart = -2500000LL;    /* 250 ms: the longest a cancelled caller waits */
    for (;;)
    {
        Status = KeWaitForMultipleObjects(2, Events, WaitAny, Executive, KernelMode, FALSE, &Slice, NULL);
        if (Status == STATUS_WAIT_0 || SmbEngine.FileObject != NULL)
            return STATUS_SUCCESS;
        if (Status == STATUS_WAIT_1)
            return STATUS_REDIRECTOR_NOT_STARTED;
        if (SmbCallerGaveUp(Irp))
            return STATUS_CANCELLED;
        Now = KeQueryInterruptTime();
        if (SmbStarterWaiters == 0 && Now >= SmbReadTime(&SmbStarterBusyUntil))
            return STATUS_REDIRECTOR_NOT_STARTED;   /* the starter went away meanwhile */
        /* A failed start that another request's KeClearEvent hid from this wait */
        if (Now < SmbReadTime(&SmbStartFailedUntil))
            return STATUS_REDIRECTOR_NOT_STARTED;
        if (Now >= Deadline)
            break;
    }
    DPRINT1("mrxsmb: no engine attached within %lu s\n", NITRO_SMBRDR_ENGINE_START_WAIT_SECONDS);
    SmbNoteStartFailed();
    return STATUS_REDIRECTOR_NOT_STARTED;
}

/* IOCTL_SMBRDR_ENGINE_START_FAILED: the starter could not start an engine (or is going away) */
static
NTSTATUS
SmbEngineStartFailed(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PAGED_CODE();

    if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
        return STATUS_BUFFER_TOO_SMALL;
    DPRINT1("mrxsmb: the starter could not start an engine (%lu)\n", *(PULONG)Irp->AssociatedIrp.SystemBuffer);
    SmbNoteStartFailed();
    return STATUS_SUCCESS;
}

/* IOCTL_SMBRDR_WAIT_ENGINE_NEEDED: the starter's thread waits here (alertable, so it can be
 * terminated), at most 5 minutes per call */
static
NTSTATUS
SmbWaitEngineNeeded(VOID)
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    PAGED_CODE();

    /* While a starter waits here, requests that need an engine wait for it; once it is woken it is
     * counted as busy (starting the engine) for as long as a request would wait, and when it is
     * gone (the Workstation service stopped) requests fail at once */
    InterlockedIncrement(&SmbStarterWaiters);
    Timeout.QuadPart = -10000000LL * 300;
    Status = KeWaitForSingleObject(&SmbNeedEvent, UserRequest, UserMode, TRUE, &Timeout);
    if (Status == STATUS_SUCCESS && SmbEngine.FileObject == NULL)
        SmbWriteTime(&SmbStarterBusyUntil, KeQueryInterruptTime() + (ULONGLONG)NITRO_SMBRDR_ENGINE_START_WAIT_SECONDS * 10000000ULL);
    InterlockedDecrement(&SmbStarterWaiters);
    if (Status == STATUS_SUCCESS)
        return SmbEngine.FileObject == NULL ? STATUS_SUCCESS : STATUS_ALREADY_REGISTERED;
    return Status == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : Status;
}

/*
 * Counts Bytes of a new request against SMB_MAX_OUTSTANDING_BYTES. Over the limit
 * the caller waits for requests of others to be freed, at most the request time
 * limit. A request alone is always admitted. The wait ends within a second when Irp
 * (the user's request this is for; NULL for closes and other cleanup, which must not
 * be given up) is cancelled or its thread terminates (SmbIrpCancelled), as the wait
 * for the reply does: a killed process does not sit out the request time limit when
 * the budget does not move (server or engine stalled).
 */
static
NTSTATUS
SmbReserveBytesFor(ULONG Bytes, PIRP Irp)
{
    LARGE_INTEGER Slice;
    KIRQL OldIrql;
    ULONGLONG Deadline, Now;

    PAGED_CODE();

    /* The limit is real time: every freed request wakes the waiters, so a count of wake-ups
     * would refuse a waiter after a second or two under load */
    Deadline = KeQueryInterruptTime() + (ULONGLONG)SmbRequestTimeoutSeconds * 10000000ULL;
    for (;;)
    {
        KeClearEvent(&SmbEngine.BudgetEvent);
        KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
        if (SmbEngine.OutstandingBytes == 0 ||
            SmbEngine.OutstandingBytes + Bytes <= SMB_MAX_OUTSTANDING_BYTES)
        {
            SmbEngine.OutstandingBytes += Bytes;
            KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
            return STATUS_SUCCESS;
        }
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

        Now = KeQueryInterruptTime();
        if (Now >= Deadline)
        {
            DPRINT1("mrxsmb: %lu bytes of requests outstanding, refused %lu more\n",
                    (ULONG)SmbEngine.OutstandingBytes, Bytes);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (SmbIrpCancelled(Irp))
            return STATUS_CANCELLED;
        /* at most 1 s: a waiter that misses the event looks again */
        Slice.QuadPart = -(LONGLONG)min(Deadline - Now, 10000000ULL);
        KeWaitForSingleObject(&SmbEngine.BudgetEvent, Executive, KernelMode, FALSE, &Slice);
    }
}

static
VOID
SmbUnreserveBytes(ULONG Bytes)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
    ASSERT(SmbEngine.OutstandingBytes >= Bytes);
    SmbEngine.OutstandingBytes -= Bytes;
    KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
    KeSetEvent(&SmbEngine.BudgetEvent, IO_NO_INCREMENT, FALSE);
}

/*
 * A request whose reply carries data as large as it asks (READ, QUERY_DIRECTORY) counts that
 * length too, until it is freed: the budget then bounds the reply buffers this driver holds and
 * the reply buffers the engine allocates for all requests in flight, not only the messages.
 */
NTSTATUS
SmbReserveReplyBytes(PSMB_REQUEST Request, ULONG Bytes)
{
    NTSTATUS Status;

    PAGED_CODE();

    if (Request->Notification || Bytes == 0)
        return STATUS_SUCCESS;
    Status = SmbReserveBytesFor(Bytes, Request->Irp);
    if (NT_SUCCESS(Status))
        Request->ReservedBytes += Bytes;
    return Status;
}

NTSTATUS
SmbEngineCreateDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(NITRO_SMBRDR_ENGINE_DEVICE);
    /*
     * SYSTEM and the service SID of the engine service only: NT SERVICE\smbengine =
     * S-1-5-80-<SHA-1 of "SMBENGINE" in UTF-16LE> (the service controller puts it into the engine's
     * token: ServiceSidType 1). Not LocalService: every LocalService process would be admitted (and
     * receive users' tokens while no engine is attached). Not administrators: test engines that run
     * elevated open the device as SYSTEM.
     */
    UNICODE_STRING Sddl = RTL_CONSTANT_STRING(
        L"D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-80-589501614-767465580-2714278881-1358990225-2449632110)");

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
    {
        /* A CONNECT may carry a password: never leave it in freed pool */
        if (Request->Opcode == SmbUpConnect)
            RtlSecureZeroMemory(Request->Message, Request->MessageAllocation);
        ExFreePoolWithTag(Request->Message, TAG_SMB_MESSAGE);
    }
    if (Request->Reply != NULL)
        ExFreePoolWithTag(Request->Reply, TAG_SMB_REPLY);
    if (Request->ReservedBytes != 0)
        SmbUnreserveBytes(Request->ReservedBytes);
    ExFreePoolWithTag(Request, TAG_SMB_REQUEST);
}

VOID
SmbReleaseRequest(PSMB_REQUEST Request)
{
    if (InterlockedDecrement(&Request->RefCount) == 0)
        SmbFreeRequest(Request);
}

/* Irp: the user's request this message is for, whose cancellation ends the wait for the budget (NULL: none) */
NTSTATUS
SmbAllocateRequestForIrp(
    USHORT Opcode,
    ULONG VariableSize,
    PLUID LogonId,
    PIRP Irp,
    PSMB_REQUEST *Out)
{
    PSMB_REQUEST Request;
    ULONGLONG Total;
    NTSTATUS Status;

    PAGED_CODE();

    *Out = NULL;
    if (Opcode <= SmbUpInvalid || Opcode >= SmbUpMaximumOpcode)
        return STATUS_INVALID_PARAMETER;

    /* Room for 8-byte alignment of each variable item (at most 5 per message) */
    Total = (ULONGLONG)sizeof(SMBUP_HEADER) + SMBUP_REQUEST_FIXED_SIZE(Opcode) + VariableSize + 5 * 8;
    if (Total > SMBUP_MAX_MESSAGE)
        return STATUS_INVALID_PARAMETER;

    /* Notifications (small, sent from callbacks and timeouts) are not held back */
    if (Opcode != SmbUpLogoff && Opcode != SmbUpCancel)
    {
        Status = SmbReserveBytesFor((ULONG)Total, Irp);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    Request = ExAllocatePoolZero(NonPagedPool, sizeof(*Request), TAG_SMB_REQUEST);
    if (Request == NULL)
    {
        if (Opcode != SmbUpLogoff && Opcode != SmbUpCancel)
            SmbUnreserveBytes((ULONG)Total);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (Opcode != SmbUpLogoff && Opcode != SmbUpCancel)
        Request->ReservedBytes = (ULONG)Total;

    /* A CONNECT may carry a password: nonpaged, so that it never reaches the paging file */
    Request->Message = ExAllocatePoolZero(Opcode == SmbUpConnect ? NonPagedPool : PagedPool,
                                          (SIZE_T)Total, TAG_SMB_MESSAGE);
    if (Request->Message == NULL)
    {
        if (Request->ReservedBytes != 0)
            SmbUnreserveBytes(Request->ReservedBytes);
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

NTSTATUS
SmbAllocateRequest(
    USHORT Opcode,
    ULONG VariableSize,
    PLUID LogonId,
    PSMB_REQUEST *Out)
{
    return SmbAllocateRequestForIrp(Opcode, VariableSize, LogonId, NULL, Out);
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

/* The caller gave up: its IRP was cancelled, or the thread that sent it is terminating */
BOOLEAN
SmbIrpCancelled(PIRP Irp)
{
    if (Irp == NULL || BooleanFlagOn(Irp->Flags, IRP_PAGING_IO))
        return FALSE;
    if (Irp->Cancel)
        return TRUE;
    return Irp->Tail.Overlay.Thread != NULL && PsIsThreadTerminating(Irp->Tail.Overlay.Thread);
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
    NTSTATUS Status, Reason = STATUS_IO_TIMEOUT;
    LARGE_INTEGER Timeout;
    KIRQL OldIrql;
    BOOLEAN WasSent = FALSE;
    ULONG Waited;

    PAGED_CODE();
    ASSERT(!Request->Notification);

    Status = SmbQueueRequest(Request);
    if (!NT_SUCCESS(Status))
        return Status;

    if (TimeoutSeconds == 0 || TimeoutSeconds > SmbRequestTimeoutSeconds)
        TimeoutSeconds = SmbRequestTimeoutSeconds;

    /* With the caller's IRP, wait in slices of one second and give up early when the
     * IRP is cancelled (CancelIoEx, IoCancelThreadIo) or its thread is terminating:
     * rdbss has no cancel routine for a mini-redirector, and the thread cannot be
     * stopped in this wait otherwise (normal kernel APCs are disabled in file systems) */
    Timeout.QuadPart = Request->Irp != NULL ? -10000000LL : -10000000LL * TimeoutSeconds;
    for (Waited = 0; ; )
    {
        Status = KeWaitForSingleObject(&Request->Done, Executive, KernelMode, FALSE, &Timeout);
        if (Status != STATUS_TIMEOUT)
            break;
        if (Request->Irp == NULL || ++Waited >= TimeoutSeconds)
        {
            Reason = STATUS_IO_TIMEOUT;
            break;
        }
        if (SmbIrpCancelled(Request->Irp))
        {
            Reason = STATUS_CANCELLED;
            break;
        }
    }
    if (Status == STATUS_TIMEOUT)
    {
        KeAcquireSpinLock(&SmbEngine.Lock, &OldIrql);
        if (Request->State != SmbRequestCompleted)
        {
            WasSent = (Request->State != SmbRequestQueued);
            SmbCompleteLocked(Request, Reason);
        }
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);

        DPRINT1("mrxsmb: request %I64u (op %u) %s\n", Request->RequestId, Request->Opcode,
                Reason == STATUS_CANCELLED ? "cancelled" : "timed out");
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
     * I/O manager (STATUS_PENDING, STATUS_REPARSE, other informational codes) or
     * rdbss and rxce, which act on some error codes of a mini-redirector: STATUS_RETRY
     * (RxFsdCommonDispatch, RxFspDispatch dispatch again) and
     * STATUS_MORE_PROCESSING_REQUIRED (RxCommonCreate opens again), each time with a
     * new upcall, for as long as the engine answers so; STATUS_CONNECTION_ACTIVE as
     * the status of a tree connect makes RxConstructVirtualNetRoot use the virtual
     * net root that RxFindOrCreateConnections has just cleared. An engine passes the
     * server's status through, so these come from the network too. Warnings only where the
     * operation has them: STATUS_BUFFER_OVERFLOW for queries, STATUS_NO_MORE_FILES
     * for directory queries. */
    if (!NT_ERROR(Status) &&
        Status != STATUS_SUCCESS &&
        !(Status == STATUS_BUFFER_OVERFLOW &&
          (Request->Opcode == SmbUpQueryInfo || Request->Opcode == SmbUpQueryVolume ||
           Request->Opcode == SmbUpQueryDirectory)) &&
        !(Status == STATUS_NO_MORE_FILES && Request->Opcode == SmbUpQueryDirectory))
    {
        DPRINT1("mrxsmb: engine status %lx refused (op %u)\n", Status, Request->Opcode);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (Status == STATUS_MORE_PROCESSING_REQUIRED ||
        Status == STATUS_RETRY ||
        Status == STATUS_CANT_WAIT ||
        Status == STATUS_CONNECTION_ACTIVE ||
        Status == STATUS_LOCK_NOT_GRANTED)
    {
        DPRINT1("mrxsmb: engine status %lx refused (op %u)\n", Status, Request->Opcode);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

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
    SmbWriteTime(&SmbStartFailedUntil, 0);
    SmbWriteTime(&SmbStarterBusyUntil, 0);
    KeClearEvent(&SmbStartFailedEvent);
    KeSetEvent(&SmbAttachedEvent, IO_NO_INCREMENT, FALSE);
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
    KeClearEvent(&SmbAttachedEvent);
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
    PSMB_REQUEST Request;
    NTSTATUS Status;
    KIRQL OldIrql;
    HANDLE TokenHandle;
    BOOLEAN Delivered;
    ULONG MessageSize;
    PUCHAR Out;

    PAGED_CODE();

    /* METHOD_OUT_DIRECT: the engine's own pages, locked by the I/O manager, mapped here. Written
     * only, never read back (the engine may change them at any time). */
    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < SMBUP_MAX_MESSAGE || Irp->MdlAddress == NULL)
        return STATUS_BUFFER_TOO_SMALL;
    Out = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (Out == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    for (;;)
    {
        if (SmbEngine.FileObject != Stack->FileObject)
            return STATUS_CONNECTION_DISCONNECTED;

        /* Alertable in user mode: the engine's threads can be terminated while they wait.
         * The thread's own wait blocks (2 <= THREAD_WAIT_OBJECTS): the kernel stack of a
         * user-mode wait may be swapped out, so no wait blocks on it */
        Status = KeWaitForMultipleObjects(2, Objects, WaitAny, UserRequest, UserMode, TRUE, NULL, NULL);
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
        MessageSize = Request->MessageSize;
        RtlCopyMemory(Out, Request->Message, MessageSize);

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
            /* Timed out or detached meanwhile: do not hand out a token for it, and do not leave
             * its message (a CONNECT may carry a password) in the engine's buffer */
            if (TokenHandle != NULL)
                ZwClose(TokenHandle);   /* a handle of this (the engine's) process */
            RtlSecureZeroMemory(Out, MessageSize);
            continue;
        }

        Irp->IoStatus.Information = MessageSize;
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
    BOOLEAN Valid;

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

    Valid = (Reply->Magic == SMBUP_MAGIC &&
             Reply->Version == SMBUP_VERSION &&
             Reply->HeaderSize == sizeof(SMBUP_HEADER) &&
             Reply->TotalSize == Length &&
             Reply->Opcode > SmbUpInvalid && Reply->Opcode < SmbUpMaximumOpcode &&
             Reply->Opcode != SmbUpLogoff && Reply->Opcode != SmbUpCancel);

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
    if (Request == NULL || Request->Generation != SmbEngine.Generation)
    {
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        ExFreePoolWithTag(Reply, TAG_SMB_REPLY);
        /* Unknown or already completed (timed out, cancelled, answered: a late second reply ends here) */
        return Valid ? STATUS_NOT_FOUND : STATUS_INVALID_PARAMETER;
    }
    if (!Valid || Request->Opcode != Reply->Opcode)
    {
        /* A malformed reply, or the wrong opcode, for a request the engine took: that is its answer.
         * Fail the request now; it waited for the full time limit before (and everything queued
         * behind its thread with it). The request leaves the Sent list, so a later reply for the
         * same id finds nothing and is not completed twice. */
        ULONGLONG RequestId = Request->RequestId;

        /* After this the waiter may free the request: do not touch it again */
        SmbCompleteLocked(Request, STATUS_INVALID_NETWORK_RESPONSE);
        KeReleaseSpinLock(&SmbEngine.Lock, OldIrql);
        ExFreePoolWithTag(Reply, TAG_SMB_REPLY);
        DPRINT1("mrxsmb: reply for request %I64u refused (%s), request failed\n",
                RequestId, Valid ? "opcode" : "header");
        return Valid ? STATUS_NOT_FOUND : STATUS_INVALID_PARAMETER;
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
                case IOCTL_SMBRDR_WAIT_ENGINE_NEEDED:
                    /* Not for the engine itself (its handle would hold a GET thread) */
                    Status = (SmbEngine.FileObject == Stack->FileObject) ? STATUS_INVALID_DEVICE_REQUEST :
                             SmbWaitEngineNeeded();
                    break;
                case IOCTL_SMBRDR_ENGINE_START_FAILED:
                    Status = (SmbEngine.FileObject == Stack->FileObject) ? STATUS_INVALID_DEVICE_REQUEST :
                             SmbEngineStartFailed(Irp, Stack);
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
