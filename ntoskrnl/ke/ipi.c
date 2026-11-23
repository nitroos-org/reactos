/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/ipi.c
 * PURPOSE:         Inter-Processor Packet Interface
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern KSPIN_LOCK KiReverseStallIpiLock;

/*
 * T79: coalesce redundant reschedule/DPC IPIs. When a dispatch or APC IPI is
 * sent to a processor that already has the same request pending and unserviced,
 * the physical IPI is redundant and only costs a wrmsr on the sender and an EOI
 * on the target. On the fork's amd64 2-CPU SMP a ready-thread/affinity bounce
 * makes these pile up into a vector-0xE1 IPI storm that pegs a core at idle
 * (ticket T79). Dropping the redundant sends removes ~85% of the storm's IPIs
 * with no missed reschedule (the first setter of the request always sends, so a
 * dispatch interrupt is still guaranteed).
 */

/*
 * The packet fields. x64 has no SignalDone and keeps the packet in a request
 * mailbox; the protocol below uses a single slot per processor, so it takes
 * the first mailbox and PacketBarrier as the slot.
 */
#ifdef _M_AMD64
#define KiIpiSlot(Prcb)         (*(PKPRCB volatile*)&(Prcb)->PacketBarrier)
#define KiIpiSummary(Prcb)      ((Prcb)->RequestMailbox[0].RequestSummary)
#define KiIpiWorker(Prcb)       (*(PKIPI_WORKER*)&(Prcb)->RequestMailbox[0].RequestPacket.WorkerRoutine)
#define KiIpiParameters(Prcb)   ((Prcb)->RequestMailbox[0].RequestPacket.CurrentPacket)
#define KiIpiOrSummary(Prcb, Request) \
    InterlockedOr64(&KiIpiSummary(Prcb), (LONG64)(Request))
#define KiIpiTakeSummary(Prcb) \
    ((ULONG)InterlockedExchange64(&KiIpiSummary(Prcb), 0))
#define KiIpiJoinTargetSet(Prcb, Set) \
    InterlockedOr64((PLONG64)&(Prcb)->TargetSet, (LONG64)(Set))
#define KiIpiLeaveTargetSet(Prcb, Set) \
    InterlockedAnd64((PLONG64)&(Prcb)->TargetSet, ~(LONG64)(Set))
#else
#define KiIpiSlot(Prcb)         ((Prcb)->SignalDone)
#define KiIpiSummary(Prcb)      ((Prcb)->RequestSummary)
#define KiIpiWorker(Prcb)       ((Prcb)->WorkerRoutine)
#define KiIpiParameters(Prcb)   ((Prcb)->CurrentPacket)
#define KiIpiOrSummary(Prcb, Request) \
    InterlockedOr((PLONG)&KiIpiSummary(Prcb), (LONG)(Request))
#define KiIpiTakeSummary(Prcb) \
    ((ULONG)InterlockedExchange((PLONG)&KiIpiSummary(Prcb), 0))
#define KiIpiJoinTargetSet(Prcb, Set) \
    InterlockedOr((PLONG)&(Prcb)->TargetSet, (LONG)(Set))
#define KiIpiLeaveTargetSet(Prcb, Set) \
    InterlockedAnd((PLONG)&(Prcb)->TargetSet, ~(LONG)(Set))
#endif

/* PRIVATE FUNCTIONS *********************************************************/

/*
 * Packet protocol. A sender publishes the worker and its parameters in its
 * own PRCB, then for each target claims the target's single packet slot
 * (SignalDone), adds the target to its TargetSet and sends IPI_PACKET_READY.
 * The target runs the worker at IPI_LEVEL, removes itself from the sender's
 * TargetSet and only then frees its slot, so a late removal can never hit a
 * later packet of the same sender. Senders wait below IPI_LEVEL, so they keep
 * serving packets sent to them and two processors sending to each other do
 * not deadlock.
 */

#ifdef CONFIG_SMP

static
VOID
KiIpiPublishPacket(
    _In_ PKPRCB Prcb,
    _In_ PKIPI_WORKER WorkerRoutine,
    _In_opt_ PVOID Parameter1,
    _In_opt_ PVOID Parameter2,
    _In_opt_ PVOID Parameter3)
{
    ASSERT(Prcb->TargetSet == 0);

    KiIpiWorker(Prcb) = WorkerRoutine;
    KiIpiParameters(Prcb)[0] = Parameter1;
    KiIpiParameters(Prcb)[1] = Parameter2;
    KiIpiParameters(Prcb)[2] = Parameter3;
    KeMemoryBarrier();
}

static
VOID
KiIpiDeliverPacket(
    _In_ PKPRCB Prcb,
    _In_ KAFFINITY TargetSet)
{
    KAFFINITY Remaining = TargetSet;
    PKPRCB TargetPrcb;
    ULONG Processor;

    while (Remaining)
    {
        BitScanForwardAffinity(&Processor, Remaining);
        Remaining &= Remaining - 1;
        TargetPrcb = KiProcessorBlock[Processor];

        /* A processor serves one packet at a time. Claim its slot and signal it
           without interruption: a claimed slot whose IPI waits behind a
           broadcast this processor joined would block that broadcast */
        while (TRUE)
        {
            BOOLEAN Enable = KeDisableInterrupts();

            if (InterlockedCompareExchangePointer((PVOID*)&KiIpiSlot(TargetPrcb), Prcb, NULL) == NULL)
            {
                KiIpiJoinTargetSet(Prcb, AFFINITY_MASK(Processor));
                KiIpiOrSummary(TargetPrcb, IPI_PACKET_READY);
                HalRequestIpi(AFFINITY_MASK(Processor));
                KeRestoreInterrupts(Enable);
                break;
            }

            KeRestoreInterrupts(Enable);
            YieldProcessor();
        }
    }
}

static
LONG
KiIpiCountProcessors(
    _In_ KAFFINITY Set)
{
    LONG Count = 0;

    for (; Set; Set &= Set - 1)
        Count++;

    return Count;
}

static
VOID
KiIpiWaitForPacketDone(
    _In_ PKPRCB Prcb)
{
    while (*(volatile KAFFINITY*)&Prcb->TargetSet != 0)
    {
        YieldProcessor();
    }
}

#endif // CONFIG_SMP

VOID
NTAPI
KiIpiGenericCallTarget(IN PKIPI_CONTEXT PacketContext,
                       IN PVOID BroadcastFunction,
                       IN PVOID Argument,
                       IN PVOID Count)
{
    volatile LONG *Barrier = (volatile LONG*)Count;

    /* Report this processor ready, then wait until every processor is */
    InterlockedDecrement((PLONG)Barrier);
    while (*Barrier != 0)
    {
        YieldProcessor();
    }

    ((PKIPI_BROADCAST_WORKER)BroadcastFunction)((ULONG_PTR)Argument);
}

VOID
FASTCALL
KiIpiSend(IN KAFFINITY TargetProcessors,
          IN ULONG IpiRequest)
{
#ifdef CONFIG_SMP
    KAFFINITY Remaining = TargetProcessors;
    KAFFINITY NeedIpi = TargetProcessors;
    ULONG Processor;

    /* Freezing must reach processors running with interrupts disabled */
    if (IpiRequest & IPI_FREEZE)
    {
        HalSendNMI(TargetProcessors);
        IpiRequest &= ~IPI_FREEZE;
        if (!IpiRequest) return;
    }

    /* Mark the requests before interrupting, the interrupt takes them all;
       an IPI without requests only ends a halt */
    while (Remaining && IpiRequest)
    {
        ULONG Old;
        BitScanForwardAffinity(&Processor, Remaining);
        Remaining &= Remaining - 1;
        Old = KiIpiOrSummary(KiProcessorBlock[Processor], IpiRequest);

        /* T79: if every requested bit was already pending and unserviced on the
           target, a physical IPI for it is already in flight (the target clears
           the summary with an atomic exchange when it serves the IPI, so a set
           bit means no service has consumed it yet) - drop the redundant send.
           The first setter of a bit (Old had it clear) always sends, so the
           target is still guaranteed to take a dispatch interrupt. */
        if ((Old & IpiRequest) == IpiRequest)
            NeedIpi &= ~AFFINITY_MASK(Processor);
    }

    /* An IPI with no requests (IpiRequest == 0) only ends a halt: never
       coalesced, so NeedIpi still covers every target in that case */
    if (NeedIpi)
        HalRequestIpi(NeedIpi);
#else
    /* Uniprocessor systems have no other processor to signal */
    ASSERT(FALSE);
#endif
}

VOID
NTAPI
KiIpiSendPacket(IN KAFFINITY TargetProcessors,
                IN PKIPI_WORKER WorkerFunction,
                IN PKIPI_BROADCAST_WORKER BroadcastFunction,
                IN ULONG_PTR Context,
                IN PULONG Count)
{
    /* FIXME: TODO */
    ASSERTMSG("Not yet implemented\n", FALSE);
}

VOID
FASTCALL
KiIpiSignalPacketDone(IN PKIPI_CONTEXT PacketContext)
{
#ifdef CONFIG_SMP
    PKPRCB Sender = (PKPRCB)PacketContext;

    /* Lets the sender go on early; the slot is freed once the worker returns */
    KiIpiLeaveTargetSet(Sender, KeGetCurrentPrcb()->SetMember);
#endif
}

VOID
FASTCALL
KiIpiSignalPacketDoneAndStall(IN PKIPI_CONTEXT PacketContext,
                              IN volatile PULONG ReverseStall)
{
    /* FIXME: TODO */
    ASSERTMSG("Not yet implemented\n", FALSE);
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
BOOLEAN
NTAPI
KiIpiServiceRoutine(IN PKTRAP_FRAME TrapFrame,
                    IN PKEXCEPTION_FRAME ExceptionFrame)
{
#ifdef CONFIG_SMP
    PKPRCB Prcb = KeGetCurrentPrcb();
    PKPRCB Sender;
    ULONG Request;

    ASSERT(KeGetCurrentIrql() == IPI_LEVEL);

    Request = KiIpiTakeSummary(Prcb);

    if (Request & IPI_APC)
    {
        HalRequestSoftwareInterrupt(APC_LEVEL);
    }

    if (Request & IPI_DPC)
    {
        HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
    }

    if (Request & IPI_PACKET_READY)
    {
        Sender = (PKPRCB)KiIpiSlot(Prcb);
        ASSERT(Sender != NULL);

        KiIpiWorker(Sender)((PKIPI_CONTEXT)Sender,
                            KiIpiParameters(Sender)[0],
                            KiIpiParameters(Sender)[1],
                            KiIpiParameters(Sender)[2]);

        /* Leave the sender's target set before freeing the slot, see the protocol above */
        KiIpiLeaveTargetSet(Sender, Prcb->SetMember);
        InterlockedExchangePointer((PVOID*)&KiIpiSlot(Prcb), NULL);
    }
#endif
    return TRUE;
}

/*
 * @implemented
 */
ULONG_PTR
NTAPI
KeIpiGenericCall(IN PKIPI_BROADCAST_WORKER Function,
                 IN ULONG_PTR Argument)
{
    ULONG_PTR Status;
    KIRQL OldIrql, OldIrql2;
#ifdef CONFIG_SMP
    KAFFINITY Affinity;
    volatile LONG Barrier;
    PKPRCB Prcb = KeGetCurrentPrcb();
#endif

    /* An interrupt below SYNCH_LEVEL could otherwise send a request through
       the packet of this processor while it is published */
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    OldIrql = KeRaiseIrqlToSynchLevel();

    /* Acquire the IPI lock */
    KeAcquireSpinLockAtDpcLevel(&KiReverseStallIpiLock);

#ifdef CONFIG_SMP
    /* The other active processors run the function together with this one */
    Prcb = KeGetCurrentPrcb();
    Affinity = KeActiveProcessors & ~Prcb->SetMember;
    Barrier = 1;
    if (Affinity)
    {
        Barrier += KiIpiCountProcessors(Affinity);
        KiIpiPublishPacket(Prcb,
                           KiIpiGenericCallTarget,
                           (PVOID)Function,
                           (PVOID)Argument,
                           (PVOID)&Barrier);
        KiIpiDeliverPacket(Prcb, Affinity);

        /* Spin until the other processors are ready */
        while (Barrier != 1)
        {
            YieldProcessor();
        }
    }
#endif

    /* Raise to IPI level */
    KeRaiseIrql(IPI_LEVEL, &OldIrql2);

#ifdef CONFIG_SMP
    /* Let the other processors know it is time */
    Barrier = 0;
#endif

    /* Call the function */
    Status = Function(Argument);

#ifdef CONFIG_SMP
    /* Wait for the other processors to finish; their requests stay pending meanwhile */
    if (Affinity)
    {
        ASSERT(Prcb == KeGetCurrentPrcb());
        KiIpiWaitForPacketDone(Prcb);
    }
#endif

    /* Release the lock */
    KeReleaseSpinLockFromDpcLevel(&KiReverseStallIpiLock);

    /* Lower IRQL back */
    KeLowerIrql(OldIrql);
    return Status;
}

VOID
NTAPI
KiIpiSendRequest(
    _In_ KAFFINITY TargetSet,
    _In_ PKIPI_WORKER WorkerRoutine,
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3)
{
    KIRQL OldIrql, WorkerIrql;
#ifdef CONFIG_SMP
    PKPRCB Prcb;
    KAFFINITY Remote;
#endif

    /* Above SYNCH_LEVEL no other processor may be waited for. That happens
       while this is the only one running, and in the debugger with the others
       frozen; it requests TLB flushes, and frozen processors flush their
       entire TLB when they thaw. KDBG lowers the IRQL to DISPATCH_LEVEL while
       the others stay frozen, so the freeze owner never waits either */
    if ((KeGetCurrentIrql() > SYNCH_LEVEL)
#ifdef CONFIG_SMP
        || (KiFreezeOwner == KeGetCurrentPrcb())
#endif
       )
    {
#ifdef CONFIG_SMP
        ASSERT((KiFreezeOwner == KeGetCurrentPrcb()) ||
               (KeGetCurrentPrcb()->IpiFrozen & IPI_FROZEN_FLAG_ACTIVE) ||
               ((TargetSet & KeActiveProcessors & ~KeGetCurrentPrcb()->SetMember) == 0));
#endif
        if (TargetSet & KeGetCurrentPrcb()->SetMember)
            WorkerRoutine((PKIPI_CONTEXT)KeGetCurrentPrcb(), Parameter1, Parameter2, Parameter3);
        return;
    }

    /* Waiting at SYNCH_LEVEL keeps this processor fixed and still serves IPIs */
    OldIrql = KeRaiseIrqlToSynchLevel();

#ifdef CONFIG_SMP
    Prcb = KeGetCurrentPrcb();
    /* KDBG lowers the IRQL while the others stay frozen, and after a KD
       processor switch the debugger runs on a frozen processor: do not
       wait there. A starting processor serves its requests once it enables
       interrupts; it takes the dispatcher and PRCB locks before that, so no
       request may be sent holding them */
    if (Prcb->IpiFrozen & IPI_FROZEN_FLAG_ACTIVE)
        Remote = 0;
    else
        Remote = TargetSet & KiGetTbFlushProcessors() & ~Prcb->SetMember;
    if (Remote)
    {
        KiIpiPublishPacket(Prcb, WorkerRoutine, Parameter1, Parameter2, Parameter3);
        KiIpiDeliverPacket(Prcb, Remote);
    }
#endif

    /* Run the worker here too, at the IRQL the targets run it */
    if (TargetSet & KeGetCurrentPrcb()->SetMember)
    {
        KeRaiseIrql(IPI_LEVEL, &WorkerIrql);
        WorkerRoutine((PKIPI_CONTEXT)KeGetCurrentPrcb(), Parameter1, Parameter2, Parameter3);
        KeLowerIrql(WorkerIrql);
    }

#ifdef CONFIG_SMP
    if (Remote)
    {
        KiIpiWaitForPacketDone(Prcb);
    }
#endif

    KeLowerIrql(OldIrql);
}


static
VOID
NTAPI
KiFlushProcessWriteBuffersTarget(
    _In_ PKIPI_CONTEXT PacketContext,
    _In_ PVOID Parameter1,
    _In_ PVOID Parameter2,
    _In_ PVOID Parameter3)
{
    UNREFERENCED_PARAMETER(PacketContext);
    UNREFERENCED_PARAMETER(Parameter1);
    UNREFERENCED_PARAMETER(Parameter2);
    UNREFERENCED_PARAMETER(Parameter3);

    /* The interrupt serializes this processor; the barrier drains its store buffer */
    KeMemoryBarrier();
}

/*
 * @implemented
 *
 * Every processor that may run a thread of the process drains its write buffer before the call returns, so the
 * caller sees the stores those threads made before (a runtime suspending its threads relies on it).
 */
NTSTATUS
NTAPI
NtFlushProcessWriteBuffers(VOID)
{
    PAGED_CODE();

    KiIpiSendRequest(KeActiveProcessors, KiFlushProcessWriteBuffersTarget, NULL, NULL, NULL);
    return STATUS_SUCCESS;
}
