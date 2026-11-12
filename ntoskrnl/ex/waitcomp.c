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
 * Design: a packet costs memory only. It embeds a kernel wait packet (KWAIT_PACKET, ke/queue.c): a wait block that
 * no thread owns, linked into the target's wait list while the association waits. The code that signals the target
 * satisfies that block in the signal path, under the dispatcher lock, and inserts the packet's own completion entry
 * (IopCompletionPacketWait) into the port's queue; Cancel unlinks the block, or takes a queued entry back out of the
 * queue, under the same lock. So the target is consumed exactly once for a packet that fires and never for one that
 * was cancelled first, and association (test the target, then consume it or link the block) is atomic against
 * signalling. The consumer's unpack (io/iomgr/iocomp.c) hands the entry to ExWcpPacketDequeued.
 *
 * States (KWAIT_PACKET.State, dispatcher lock): Idle -> Armed (waiting) -> Queued (entry handed to the port) -> Idle
 * (the consumer removed it, or Cancel did). From Associate until the packet is Idle again it holds a reference on the
 * target, on the port and on itself, so neither the target, the port nor the packet can go away while the wait block
 * is linked or the entry is in the queue; those references are dropped at PASSIVE_LEVEL by whoever makes it idle,
 * never in the signal path. Closing the last handle cancels the association and removes a queued entry, as measured
 * on Windows 10 22H2; after that the packet cannot be associated again (STATUS_INVALID_HANDLE: its handle is gone).
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

typedef struct _WAIT_COMPLETION_PACKET
{
    IOP_MINI_COMPLETION_PACKET Packet;  /* must be first: the port's queue holds &Packet.ListEntry */
    KWAIT_PACKET Wait;                  /* the wait block on the target and the state */
    FAST_MUTEX OpMutex;                 /* serialises Associate, Cancel and close */
    BOOLEAN Closed;                     /* the last handle was closed (OpMutex) */
    PVOID TargetObject;                 /* referenced while associated (Armed or Queued) */
    PKQUEUE Port;                       /* referenced while associated */
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

/*
 * The packet became idle (the caller made it so): drop the references the association held. PASSIVE_LEVEL or
 * APC_LEVEL. The caller read TargetObject and Port before the packet became idle, or holds OpMutex.
 */
static
VOID
ExpWcpRelease(IN PWAIT_COMPLETION_PACKET Wcp,
              IN PVOID TargetObject,
              IN PKQUEUE Port)
{
    ObDereferenceObject(TargetObject);
    ObDereferenceObject(Port);
    ObDereferenceObject(Wcp);
}

/* Cancels an association; the caller holds OpMutex. Returns the NtCancelWaitCompletionPacket status. */
static
NTSTATUS
ExpWcpCancel(IN PWAIT_COMPLETION_PACKET Wcp,
             IN BOOLEAN RemoveSignaledPacket)
{
    PVOID TargetObject = Wcp->TargetObject;
    PKQUEUE Port = Wcp->Port;
    NTSTATUS Status;

    /*
     * STATUS_SUCCESS: it was waiting (the target was not consumed for it), or queued and taken back out; it is idle.
     * STATUS_PENDING: queued and staying so; or a consumer has just taken the entry and ExWcpPacketDequeued will make
     * it idle (too late to cancel, and it cannot be associated again until then).
     */
    Status = KeCancelWaitPacket(&Wcp->Wait, RemoveSignaledPacket);
    if (Status == STATUS_SUCCESS)
    {
        Wcp->TargetObject = NULL;
        Wcp->Port = NULL;
        ExpWcpRelease(Wcp, TargetObject, Port);     /* the caller's reference keeps the object */
    }
    return Status;
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
        Wcp->Closed = TRUE;
        ExpWcpCancel(Wcp, TRUE);
        ExReleaseFastMutex(&Wcp->OpMutex);
    }
}

VOID
NTAPI
ExpWcpDelete(IN PVOID Object)
{
    PWAIT_COMPLETION_PACKET Wcp = Object;

    /* An association holds a reference on the packet: nothing can be armed or queued once the last one is gone */
    ASSERT(Wcp->Wait.State == KWaitPacketIdle);
    ASSERT(Wcp->TargetObject == NULL && Wcp->Port == NULL);
    UNREFERENCED_PARAMETER(Wcp);
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

/*
 * The consumer (NtRemoveIoCompletion(Ex), after copying the completion out) took the entry out of the port: the
 * packet is idle again. PASSIVE_LEVEL.
 */
VOID
NTAPI
ExWcpPacketDequeued(IN PIOP_MINI_COMPLETION_PACKET Packet)
{
    PWAIT_COMPLETION_PACKET Wcp = CONTAINING_RECORD(Packet, WAIT_COMPLETION_PACKET, Packet);
    PVOID TargetObject = Wcp->TargetObject;
    PKQUEUE Port = Wcp->Port;

    /* Nobody else touches these while the packet is queued; once it is idle an Associate may set them again */
    Wcp->TargetObject = NULL;
    Wcp->Port = NULL;
    KeWaitPacketDequeued(&Wcp->Wait);
    ExpWcpRelease(Wcp, TargetObject, Port);
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
    KeInitializeWaitPacket(&Wcp->Wait, &Wcp->Packet.ListEntry);
    ExInitializeFastMutex(&Wcp->OpMutex);

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
    BOOLEAN Signaled;
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
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(Wcp);
        return Status;
    }

    Status = ObReferenceObjectByHandle(TargetObjectHandle,
                                       SYNCHRONIZE,
                                       NULL,
                                       PreviousMode,
                                       &TargetObject,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(Port);
        ObDereferenceObject(Wcp);
        return Status;
    }

    WaitObject = ExpWcpGetWaitObject(TargetObject);
    if (!WaitObject)
    {
        Status = STATUS_INVALID_PARAMETER_3;
        goto Fail;
    }

    ExAcquireFastMutex(&Wcp->OpMutex);

    if (Wcp->Closed)
    {
        /* Its last handle was closed after this call referenced it: nothing could ever cancel an association */
        ExReleaseFastMutex(&Wcp->OpMutex);
        Status = STATUS_INVALID_HANDLE;
        goto Fail;
    }

    /* Waiting, or queued and not yet removed (a consumer may be removing it right now) */
    if (!KeIsWaitPacketIdle(&Wcp->Wait))
    {
        ExReleaseFastMutex(&Wcp->OpMutex);
        Status = STATUS_INVALID_PARAMETER_1;
        goto Fail;
    }

    /* Idle, and only this call (OpMutex) can change that: the association takes over the three references */
    Wcp->Packet.KeyContext = KeyContext;
    Wcp->Packet.ApcContext = ApcContext;
    Wcp->Packet.IoStatus = IoStatus;
    Wcp->Packet.IoStatusInformation = IoStatusInformation;
    Wcp->TargetObject = TargetObject;
    Wcp->Port = Port;

    /* Already signalled: the wait is satisfied now and the packet is queued before this call returns */
    Signaled = KeArmWaitPacket(&Wcp->Wait, WaitObject, Port);

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

    /* The reference of this call on the packet is now the association's */
    return STATUS_SUCCESS;

Fail:
    ObDereferenceObject(TargetObject);
    ObDereferenceObject(Port);
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
