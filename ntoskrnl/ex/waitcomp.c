/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Wait completion packets (NtCreate/Associate/CancelWaitCompletionPacket, Windows 8 and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A wait completion packet ties one wait on a waitable object to an I/O completion port: when the object is signalled
 * (the wait is satisfied, so an auto-reset event or a semaphore count is consumed as for any wait) one packet with
 * the caller's key, context, status and information is queued to the port. Go 1.26 creates one per OS thread and
 * re-associates it with a high-resolution timer around every idle netpoll.
 *
 * Design: every packet that has been associated owns one system thread (created on first use, ended when the packet
 * is deleted) that waits on {target, command event}. Association first tries the wait without blocking (the target is
 * already signalled: queue the packet in the caller, AlreadySignaled = TRUE); otherwise the packet is "armed" and the
 * thread is woken to wait. Cancel wakes the thread and waits for its acknowledgement, so after Cancel returns the
 * target is no longer being waited on. A fired packet is the packet's own entry (IopCompletionPacketWait) in the
 * port's queue, so Cancel(remove) can take it back and the consumer's unpack hands it to WcpPacketDequeued.
 *
 * States: Idle -> Armed (waiting) -> Queued (entry in the port, holds a reference on the port and on the packet)
 * -> Idle (consumer removed it, or Cancel did). Closing the last handle cancels the association and removes a
 * queued entry, as measured on Windows 10 22H2.
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/*
 * Measured on Windows 10 22H2: type name "WaitCompletionPacket", valid access 0x1F0001 (bit 1 = modify state, needed
 * for Associate and Cancel), generic mapping 0x20001 / 0x20001 / 0x20001 / 0xF0001, invalid attributes
 * OBJ_PERMANENT | OBJ_OPENLINK; desired-access bits outside the valid mask are dropped, not rejected.
 */
#define WAIT_COMPLETION_PACKET_MODIFY_STATE 0x1
#define WAIT_COMPLETION_PACKET_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED | 0x1)
#define WAIT_COMPLETION_PACKET_VALID_ACCESS (WAIT_COMPLETION_PACKET_ALL_ACCESS | SYNCHRONIZE)

/*
 * The thread of an associated packet is charged to the creating process as nonpaged pool quota (a kernel stack and
 * the thread object), so a process quota limits how many a process can have; and, because the default quota is
 * unlimited, the number of such threads is capped: per process (EPROCESS::WaitCompletionPacketThreads), so that one
 * process cannot take them all, and in the system. Windows has no such thread and no such limit (a packet is only
 * its object there); the per-process failure is the status of an exhausted process quota, the system-wide one the
 * status of exhausted pool.
 */
#define WCP_THREAD_QUOTA_CHARGE         0x8000
#define WCP_MAX_THREADS                 4096
#define WCP_MAX_THREADS_PER_PROCESS     1024
static volatile LONG ExpWcpThreads;

typedef enum _WCP_STATE
{
    WcpIdle,
    WcpArmed,
    WcpQueued
} WCP_STATE;

typedef struct _WAIT_COMPLETION_PACKET
{
    IOP_MINI_COMPLETION_PACKET Packet;  /* must be first: the port's queue holds &Packet.ListEntry */
    FAST_MUTEX OpMutex;                 /* serialises Associate, Cancel and close */
    KSPIN_LOCK Lock;                    /* state below */
    WCP_STATE State;
    BOOLEAN CancelRequested;
    BOOLEAN Terminate;
    PVOID TargetObject;                 /* referenced while Armed */
    PVOID WaitObject;                   /* the dispatcher object inside TargetObject */
    PKQUEUE Port;                       /* referenced while Armed or Queued */
    KEVENT Command;                     /* wakes the thread (new association, cancel, terminate) */
    KEVENT Ack;                         /* the thread's answer to a cancel */
    PKTHREAD Thread;
    PEPROCESS ChargedProcess;           /* referenced; the thread's quota was charged to it */
} WAIT_COMPLETION_PACKET, *PWAIT_COMPLETION_PACKET;

POBJECT_TYPE ExWaitCompletionPacketObjectType;

static
GENERIC_MAPPING ExpWaitCompletionMapping =
{
    STANDARD_RIGHTS_READ | WAIT_COMPLETION_PACKET_MODIFY_STATE,
    STANDARD_RIGHTS_WRITE | WAIT_COMPLETION_PACKET_MODIFY_STATE,
    STANDARD_RIGHTS_EXECUTE | WAIT_COMPLETION_PACKET_MODIFY_STATE,
    WAIT_COMPLETION_PACKET_ALL_ACCESS
};

/* PRIVATE FUNCTIONS *********************************************************/

/*
 * The dispatcher object a target handle is waited on, or NULL if the type is not accepted. As measured: events,
 * semaphores, timers (also those of NtCreateTimer2, which Go uses), threads, processes and files are; a mutant, a completion port or another wait completion packet
 * (and any type that is only waitable through the default object) is STATUS_INVALID_PARAMETER_3.
 */
static
PVOID
ExpWcpGetWaitObject(IN PVOID Target)
{
    POBJECT_TYPE Type = OBJECT_TO_OBJECT_HEADER(Target)->Type;

    if (Type == IoFileObjectType) return &((PFILE_OBJECT)Target)->Event;
    if ((Type == ExEventObjectType) || (Type == ExSemaphoreObjectType) || (Type == ExTimerType) ||
        (Type == ExpIRTimerType) || (Type == PsThreadType) || (Type == PsProcessType))
    {
        return Target;
    }
    return NULL;
}

/* The packet is queued: Wcp->Packet is in the port; the caller holds Wcp->Lock. Queue reference on the packet taken. */
static
VOID
ExpWcpInsertLocked(IN PWAIT_COMPLETION_PACKET Wcp)
{
    Wcp->State = WcpQueued;
    ObReferenceObject(Wcp);
    KeInsertQueue(Wcp->Port, &Wcp->Packet.ListEntry);
}

/* Drops the references of a finished association (not under the lock) */
static
VOID
ExpWcpRelease(IN PVOID TargetObject OPTIONAL,
              IN PKQUEUE Port OPTIONAL)
{
    if (TargetObject) ObDereferenceObject(TargetObject);
    if (Port) ObDereferenceObject(Port);
}

static
VOID
NTAPI
ExpWcpThread(IN PVOID Context)
{
    PWAIT_COMPLETION_PACKET Wcp = Context;
    PVOID Objects[2];
    PVOID TargetObject;
    PKQUEUE Port;
    NTSTATUS Status;
    KIRQL OldIrql;

    for (;;)
    {
        /* Idle: wait for a command */
        KeWaitForSingleObject(&Wcp->Command, Executive, KernelMode, FALSE, NULL);

        for (;;)
        {
            KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
            if (Wcp->Terminate)
            {
                KeReleaseSpinLock(&Wcp->Lock, OldIrql);
                PsTerminateSystemThread(STATUS_SUCCESS);
            }
            if (Wcp->State == WcpArmed && Wcp->CancelRequested)
            {
                /* Cancelled while armed: give the target and the port back */
                TargetObject = Wcp->TargetObject;
                Port = Wcp->Port;
                Wcp->TargetObject = NULL;
                Wcp->Port = NULL;
                Wcp->State = WcpIdle;
                Wcp->CancelRequested = FALSE;
                KeReleaseSpinLock(&Wcp->Lock, OldIrql);
                ExpWcpRelease(TargetObject, Port);
                KeSetEvent(&Wcp->Ack, IO_NO_INCREMENT, FALSE);
                break;
            }
            if (Wcp->State != WcpArmed)
            {
                /* A stale wake-up, or a cancel that lost the race against the target */
                if (Wcp->CancelRequested)
                {
                    Wcp->CancelRequested = FALSE;
                    KeSetEvent(&Wcp->Ack, IO_NO_INCREMENT, FALSE);
                }
                KeReleaseSpinLock(&Wcp->Lock, OldIrql);
                break;
            }
            Objects[0] = Wcp->WaitObject;
            Objects[1] = &Wcp->Command;
            KeReleaseSpinLock(&Wcp->Lock, OldIrql);

            Status = KeWaitForMultipleObjects(2, Objects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
            if (Status != STATUS_WAIT_0) continue;      /* a command: the checks above decide */

            /* The target was signalled and this wait consumed it: deliver one packet */
            KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
            TargetObject = Wcp->TargetObject;
            Wcp->TargetObject = NULL;
            ExpWcpInsertLocked(Wcp);
            if (Wcp->CancelRequested)
            {
                Wcp->CancelRequested = FALSE;
                KeSetEvent(&Wcp->Ack, IO_NO_INCREMENT, FALSE);
            }
            KeReleaseSpinLock(&Wcp->Lock, OldIrql);
            ExpWcpRelease(TargetObject, NULL);
            break;
        }
    }
}

/* Cancels an association; the caller holds OpMutex. Returns the NtCancelWaitCompletionPacket status. */
static
NTSTATUS
ExpWcpCancel(IN PWAIT_COMPLETION_PACKET Wcp,
             IN BOOLEAN RemoveSignaledPacket)
{
    KIRQL OldIrql;
    PKQUEUE Port;

    KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
    if (Wcp->State == WcpIdle)
    {
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        return STATUS_CANCELLED;
    }

    if (Wcp->State == WcpArmed)
    {
        /* Take the target away from the thread and wait for its answer */
        Wcp->CancelRequested = TRUE;
        KeSetEvent(&Wcp->Command, IO_NO_INCREMENT, FALSE);
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        KeWaitForSingleObject(&Wcp->Ack, Executive, KernelMode, FALSE, NULL);
        KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
        if (Wcp->State == WcpIdle)
        {
            KeReleaseSpinLock(&Wcp->Lock, OldIrql);
            return STATUS_SUCCESS;
        }
        /* The target fired first: the packet is queued */
    }

    /* Queued: only Cancel(remove) takes it back, otherwise it is too late (the packet stays queued) */
    if (!RemoveSignaledPacket)
    {
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        return STATUS_PENDING;
    }
    if (!KeRemoveEntryQueue(Wcp->Port, &Wcp->Packet.ListEntry))
    {
        /*
         * A consumer has just taken it and ExWcpPacketDequeued has not made the packet idle yet: too late to cancel,
         * and the packet cannot be associated again until then (the caller of a STATUS_CANCELLED may do that at once).
         */
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        return STATUS_PENDING;
    }
    Port = Wcp->Port;
    Wcp->Port = NULL;
    Wcp->State = WcpIdle;
    KeReleaseSpinLock(&Wcp->Lock, OldIrql);
    ObDereferenceObject(Port);
    ObDereferenceObject(Wcp);       /* the queue's reference; the caller's keeps the object */
    return STATUS_SUCCESS;
}

VOID
NTAPI
ExpWcpClose(IN PEPROCESS Process OPTIONAL,
            IN PVOID Object,
            IN ACCESS_MASK GrantedAccess,
            IN ULONG_PTR ProcessHandleCount,
            IN ULONG_PTR SystemHandleCount)
{
    PWAIT_COMPLETION_PACKET Wcp = Object;

    /* The last handle: the association and a queued packet go away with it */
    if (SystemHandleCount == 1)
    {
        ExAcquireFastMutex(&Wcp->OpMutex);
        ExpWcpCancel(Wcp, TRUE);
        ExReleaseFastMutex(&Wcp->OpMutex);
    }
}

VOID
NTAPI
ExpWcpDelete(IN PVOID Object)
{
    PWAIT_COMPLETION_PACKET Wcp = Object;

    if (Wcp->Thread)
    {
        KIRQL OldIrql;

        /* Nothing can be armed or queued once the last reference is gone; be safe anyway */
        ExpWcpCancel(Wcp, TRUE);
        KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
        Wcp->Terminate = TRUE;
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        KeSetEvent(&Wcp->Command, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(Wcp->Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Wcp->Thread);
        PsReturnProcessNonPagedPoolQuota(Wcp->ChargedProcess, WCP_THREAD_QUOTA_CHARGE);
        InterlockedDecrement(&Wcp->ChargedProcess->WaitCompletionPacketThreads);
        ObDereferenceObject(Wcp->ChargedProcess);
        InterlockedDecrement(&ExpWcpThreads);
    }
}

CODE_SEG("INIT")
BOOLEAN
NTAPI
ExpInitializeWaitCompletionPacketImplementation(VOID)
{
    OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
    UNICODE_STRING Name;

    RtlZeroMemory(&ObjectTypeInitializer, sizeof(ObjectTypeInitializer));
    RtlInitUnicodeString(&Name, L"WaitCompletionPacket");
    ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
    ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(WAIT_COMPLETION_PACKET);
    ObjectTypeInitializer.GenericMapping = ExpWaitCompletionMapping;
    ObjectTypeInitializer.PoolType = NonPagedPool;
    ObjectTypeInitializer.ValidAccessMask = WAIT_COMPLETION_PACKET_VALID_ACCESS;
    ObjectTypeInitializer.InvalidAttributes = OBJ_PERMANENT | OBJ_OPENLINK;
    ObjectTypeInitializer.CloseProcedure = ExpWcpClose;
    ObjectTypeInitializer.DeleteProcedure = ExpWcpDelete;
    return NT_SUCCESS(ObCreateObjectType(&Name, &ObjectTypeInitializer, NULL, &ExWaitCompletionPacketObjectType));
}

/* The consumer (NtRemoveIoCompletion) took the entry out of the port: the packet is idle again. */
VOID
NTAPI
ExWcpPacketDequeued(IN PIOP_MINI_COMPLETION_PACKET Packet)
{
    PWAIT_COMPLETION_PACKET Wcp = CONTAINING_RECORD(Packet, WAIT_COMPLETION_PACKET, Packet);
    PKQUEUE Port;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
    Port = Wcp->Port;
    Wcp->Port = NULL;
    Wcp->State = WcpIdle;
    KeReleaseSpinLock(&Wcp->Lock, OldIrql);
    ObDereferenceObject(Port);
    ObDereferenceObject(Wcp);
}

/* SERVICES ******************************************************************/

NTSTATUS
NTAPI
NtCreateWaitCompletionPacket(OUT PHANDLE WaitCompletionPacketHandle,
                             IN ACCESS_MASK DesiredAccess,
                             IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PWAIT_COMPLETION_PACKET Wcp;
    HANDLE Handle;
    NTSTATUS Status;
    PAGED_CODE();

    if (PreviousMode != KernelMode)
    {
        /* Windows faults on an unwritable pointer (also a misaligned one) before it creates anything */
        _SEH2_TRY
        {
            ProbeForWrite(WaitCompletionPacketHandle, sizeof(HANDLE), 1);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    Status = ObCreateObject(PreviousMode,
                            ExWaitCompletionPacketObjectType,
                            ObjectAttributes,
                            PreviousMode,
                            NULL,
                            sizeof(*Wcp),
                            0,
                            0,
                            (PVOID *)&Wcp);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(Wcp, sizeof(*Wcp));
    Wcp->Packet.PacketType = IopCompletionPacketWait;
    ExInitializeFastMutex(&Wcp->OpMutex);
    KeInitializeSpinLock(&Wcp->Lock);
    KeInitializeEvent(&Wcp->Command, SynchronizationEvent, FALSE);
    KeInitializeEvent(&Wcp->Ack, SynchronizationEvent, FALSE);

    /* Generic bits map first, bits outside the type's mask are dropped */
    if (DesiredAccess & MAXIMUM_ALLOWED) DesiredAccess = WAIT_COMPLETION_PACKET_ALL_ACCESS;
    RtlMapGenericMask(&DesiredAccess, &ExpWaitCompletionMapping);
    DesiredAccess &= WAIT_COMPLETION_PACKET_VALID_ACCESS;

    /* Insert it (this dereferences it on failure) */
    Status = ObInsertObject(Wcp, NULL, DesiredAccess, 0, NULL, &Handle);
    if (!NT_SUCCESS(Status)) return Status;

    _SEH2_TRY
    {
        *WaitCompletionPacketHandle = Handle;
    }
    _SEH2_EXCEPT(ExSystemExceptionFilter())
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

NTSTATUS
NTAPI
NtAssociateWaitCompletionPacket(IN HANDLE WaitCompletionPacketHandle,
                                IN HANDLE IoCompletionHandle,
                                IN HANDLE TargetObjectHandle,
                                IN PVOID KeyContext OPTIONAL,
                                IN PVOID ApcContext OPTIONAL,
                                IN NTSTATUS IoStatus,
                                IN ULONG_PTR IoStatusInformation,
                                OUT PBOOLEAN AlreadySignaled OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PWAIT_COMPLETION_PACKET Wcp;
    PKQUEUE Port = NULL;
    PVOID TargetObject = NULL, WaitObject;
    BOOLEAN Signaled = FALSE;
    LARGE_INTEGER NoWait;
    KIRQL OldIrql;
    NTSTATUS Status;
    PAGED_CODE();

    Status = ObReferenceObjectByHandle(WaitCompletionPacketHandle,
                                       WAIT_COMPLETION_PACKET_MODIFY_STATE,
                                       ExWaitCompletionPacketObjectType,
                                       PreviousMode,
                                       (PVOID *)&Wcp,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    Status = ObReferenceObjectByHandle(IoCompletionHandle,
                                       IO_COMPLETION_MODIFY_STATE,
                                       IoCompletionType,
                                       PreviousMode,
                                       (PVOID *)&Port,
                                       NULL);
    if (!NT_SUCCESS(Status)) goto Fail;

    Status = ObReferenceObjectByHandle(TargetObjectHandle,
                                       SYNCHRONIZE,
                                       NULL,
                                       PreviousMode,
                                       &TargetObject,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        TargetObject = NULL;
        goto Fail;
    }

    WaitObject = ExpWcpGetWaitObject(TargetObject);
    if (!WaitObject)
    {
        Status = STATUS_INVALID_PARAMETER_3;
        goto Fail;
    }

    ExAcquireFastMutex(&Wcp->OpMutex);

    if (Wcp->State != WcpIdle)
    {
        ExReleaseFastMutex(&Wcp->OpMutex);
        Status = STATUS_INVALID_PARAMETER_1;
        goto Fail;
    }

    /* The thread comes first: if it cannot be had, nothing has been consumed */
    if (!Wcp->Thread)
    {
        HANDLE ThreadHandle;
        PEPROCESS Process = PsGetCurrentProcess();
        LONG ProcessThreads = InterlockedIncrement(&Process->WaitCompletionPacketThreads);

        if (InterlockedIncrement(&ExpWcpThreads) > WCP_MAX_THREADS)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else if (ProcessThreads > WCP_MAX_THREADS_PER_PROCESS)
        {
            Status = STATUS_QUOTA_EXCEEDED;
        }
        else
        {
            Status = PsChargeProcessNonPagedPoolQuota(Process, WCP_THREAD_QUOTA_CHARGE);
            if (NT_SUCCESS(Status))
            {
                Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, ExpWcpThread, Wcp);
                if (NT_SUCCESS(Status))
                {
                    Status = ObReferenceObjectByHandle(ThreadHandle, SYNCHRONIZE, PsThreadType, KernelMode, (PVOID *)&Wcp->Thread, NULL);
                    ZwClose(ThreadHandle);
                    /* (a thread that cannot be referenced still ends: Terminate is never set, so it stays idle) */
                }
                if (NT_SUCCESS(Status))
                {
                    ObReferenceObject(Process);
                    Wcp->ChargedProcess = Process;
                }
                else
                {
                    PsReturnProcessNonPagedPoolQuota(Process, WCP_THREAD_QUOTA_CHARGE);
                }
            }
        }
        if (!NT_SUCCESS(Status))
        {
            InterlockedDecrement(&Process->WaitCompletionPacketThreads);
            InterlockedDecrement(&ExpWcpThreads);
            ExReleaseFastMutex(&Wcp->OpMutex);
            goto Fail;
        }
    }

    Wcp->Packet.KeyContext = KeyContext;
    Wcp->Packet.ApcContext = ApcContext;
    Wcp->Packet.IoStatus = IoStatus;
    Wcp->Packet.IoStatusInformation = IoStatusInformation;

    /* Already signalled: the wait is satisfied now and the packet is queued before this call returns */
    NoWait.QuadPart = 0;
    if (KeWaitForSingleObject(WaitObject, UserRequest, KernelMode, FALSE, &NoWait) == STATUS_SUCCESS)
    {
        Signaled = TRUE;
        KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
        Wcp->Port = Port;
        ExpWcpInsertLocked(Wcp);
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        Port = NULL;        /* the packet owns this reference now */
        ObDereferenceObject(TargetObject);
        TargetObject = NULL;
    }
    else
    {
        KeAcquireSpinLock(&Wcp->Lock, &OldIrql);
        Wcp->TargetObject = TargetObject;
        Wcp->WaitObject = WaitObject;
        Wcp->Port = Port;
        Wcp->State = WcpArmed;
        KeReleaseSpinLock(&Wcp->Lock, OldIrql);
        KeSetEvent(&Wcp->Command, IO_NO_INCREMENT, FALSE);
        Port = NULL;
        TargetObject = NULL;
    }
    ExReleaseFastMutex(&Wcp->OpMutex);

    /* Windows does not fault on a bad AlreadySignaled pointer, whatever the outcome */
    if (AlreadySignaled)
    {
        _SEH2_TRY
        {
            if (PreviousMode != KernelMode) ProbeForWrite(AlreadySignaled, sizeof(BOOLEAN), 1);
            *AlreadySignaled = Signaled;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
    }
    ObDereferenceObject(Wcp);
    return STATUS_SUCCESS;

Fail:
    ExpWcpRelease(TargetObject, Port);
    ObDereferenceObject(Wcp);
    return Status;
}

NTSTATUS
NTAPI
NtCancelWaitCompletionPacket(IN HANDLE WaitCompletionPacketHandle,
                             IN BOOLEAN RemoveSignaledPacket)
{
    PWAIT_COMPLETION_PACKET Wcp;
    NTSTATUS Status;
    PAGED_CODE();

    Status = ObReferenceObjectByHandle(WaitCompletionPacketHandle,
                                       WAIT_COMPLETION_PACKET_MODIFY_STATE,
                                       ExWaitCompletionPacketObjectType,
                                       ExGetPreviousMode(),
                                       (PVOID *)&Wcp,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    ExAcquireFastMutex(&Wcp->OpMutex);
    Status = ExpWcpCancel(Wcp, RemoveSignaledPacket);
    ExReleaseFastMutex(&Wcp->OpMutex);
    ObDereferenceObject(Wcp);
    return Status;
}
