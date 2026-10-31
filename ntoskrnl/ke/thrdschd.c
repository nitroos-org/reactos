/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/thrdschd.c
 * PURPOSE:         Kernel Thread Scheduler (Affinity, Priority, Scheduling)
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#ifdef _WIN64
# define InterlockedOrSetMember(Destination, SetMember) \
    InterlockedOr64((PLONG64)Destination, SetMember);
#else
# define InterlockedOrSetMember(Destination, SetMember) \
    InterlockedOr((PLONG)Destination, SetMember);
#endif

/* GLOBALS *******************************************************************/

KAFFINITY KiIdleSummary;
KAFFINITY KiIdleSMTSummary;

#ifdef CONFIG_SMP
/* Set while the processor's idle loop polls for work instead of halting */
typedef struct DECLSPEC_ALIGN(64) _KI_IDLE_POLL
{
    volatile LONG Polling;
} KI_IDLE_POLL;

static KI_IDLE_POLL KiIdlePollState[MAXIMUM_PROCESSORS];
ULONG KiIdlePollMicroseconds;

#define KiIsProcessorPolling(Number) (KiIdlePollState[(Number)].Polling != FALSE)
#else
#define KiIsProcessorPolling(Number) FALSE
#endif

/* FUNCTIONS *****************************************************************/

PKTHREAD
FASTCALL
KiIdleSchedule(IN PKPRCB Prcb)
{
    /* FIXME: TODO */
    ASSERTMSG("SMP: Not yet implemented\n", FALSE);
    return NULL;
}

VOID
FASTCALL
KiProcessDeferredReadyList(IN PKPRCB Prcb)
{
    PSINGLE_LIST_ENTRY ListEntry;
    PKTHREAD Thread;

    /* Make sure there is something on the ready list */
    ASSERT(Prcb->DeferredReadyListHead.Next != NULL);

    /* Get the first entry and clear the list */
    ListEntry = Prcb->DeferredReadyListHead.Next;
    Prcb->DeferredReadyListHead.Next = NULL;

    /* Start processing loop */
    do
    {
        /* Get the thread and advance to the next entry */
        Thread = CONTAINING_RECORD(ListEntry, KTHREAD, SwapListEntry);
        ListEntry = ListEntry->Next;

        /* Make the thread ready */
        KiDeferredReadyThread(Thread);
    } while (ListEntry != NULL);

    /* Make sure the ready list is still empty */
    ASSERT(Prcb->DeferredReadyListHead.Next == NULL);
}

VOID
FASTCALL
KiQueueReadyThread(IN PKTHREAD Thread,
                   IN PKPRCB Prcb)
{
    /* Call the macro. We keep the API for compatibility with ASM code */
    KxQueueReadyThread(Thread, Prcb);
}

#ifdef CONFIG_SMP
ULONG
NTAPI
KiFindIdealProcessor(
    _In_ KAFFINITY ProcessorSet,
    _In_ UCHAR OriginalIdealProcessor)
{
    PKPRCB OriginalIdealPrcb;
    KAFFINITY NodeMask;
    ULONG Processor;

    /* Check if we can use the original ideal processor */
    if (ProcessorSet & AFFINITY_MASK(OriginalIdealProcessor))
    {
        /* We can, so use it */
        return OriginalIdealProcessor;
    }

    /* Only use active processors */
    ProcessorSet &= KeActiveProcessors;

    /* Get the original ideal PRCB */
    OriginalIdealPrcb = KiProcessorBlock[OriginalIdealProcessor];

    /* Check if we can use the original node */
    NodeMask = OriginalIdealPrcb->ParentNode->ProcessorMask & ProcessorSet;
    if (NodeMask)
    {
        /* Use the node set instead */
        ProcessorSet = NodeMask;
    }

    /* Calculate the ideal CPU from the affinity set */
    BitScanReverseAffinity(&Processor, ProcessorSet);
    return Processor;
}

static
ULONG
KiSelectNextProcessor(
    _In_ PKTHREAD Thread,
    _Out_ PBOOLEAN Idle)
{
    PKPRCB Prcb = KeGetCurrentPrcb();
    KAFFINITY PreferredSet, IdleSet;
    ULONG Processor;

    /* Start with the affinity */
    PreferredSet = Thread->Affinity;

    /* If we have matching idle processors, use them */
    IdleSet = PreferredSet & KiIdleSummary;
    *Idle = (IdleSet != 0);
    if (IdleSet != 0)
    {
        /* The ideal processor, then the one the thread was last given to,
           whose cache may still hold its data, then this one, which needs
           no interrupt */
        if (IdleSet & AFFINITY_MASK(Thread->IdealProcessor))
            return Thread->IdealProcessor;
        if (IdleSet & AFFINITY_MASK(Thread->NextProcessor))
            return Thread->NextProcessor;
        if (IdleSet & Prcb->SetMember)
            return Prcb->Number;

        /* Otherwise the first idle processor after this one, so that
           processors readying threads at the same time pick different ones */
        PreferredSet = IdleSet & ~(Prcb->SetMember | (Prcb->SetMember - 1));
        if (PreferredSet == 0)
        {
            PreferredSet = IdleSet;
        }
    }
    else if (PreferredSet & AFFINITY_MASK(Thread->IdealProcessor))
    {
        /* Check if we can use the ideal processor */
        return Thread->IdealProcessor;
    }

    /* Return the first set bit */
    NT_VERIFY(BitScanForwardAffinity(&Processor, PreferredSet) != FALSE);
    ASSERT(Processor < KeNumberProcessors);

    return Processor;
}

FORCEINLINE
BOOLEAN
KiIdleHasWork(
    _In_ PKPRCB Prcb)
{
    /* Other processors and interrupts change these while the loop polls */
    return (*(struct _KTHREAD * volatile *)&Prcb->NextThread != NULL) ||
           (Prcb->DpcData[0].DpcQueueDepth != 0) ||
           (*(volatile ULONG_PTR *)&Prcb->TimerRequest != 0) ||
           (*(PSINGLE_LIST_ENTRY volatile *)&Prcb->DeferredReadyListHead.Next != NULL);
}

/*
 * Called by the idle loop with interrupts disabled, instead of halting at
 * once; returns with interrupts disabled. Under a hypervisor a halt usually
 * exits to the host and waking the halted processor takes an IPI and a host
 * wake-up; a thread readied onto a polling processor is seen within the
 * loop, and the readying processor sends no IPI.
 */
BOOLEAN
FASTCALL
KiIdlePollForWork(
    _In_ PKPRCB Prcb)
{
    volatile LONG *Polling = &KiIdlePollState[Prcb->Number].Polling;
    ULONG64 End;
    BOOLEAN Work;

    *Polling = TRUE;
    _enable();

    End = __rdtsc() + (ULONG64)KiIdlePollMicroseconds * Prcb->MHz;
    do
    {
        YieldProcessor();
        Work = KiIdleHasWork(Prcb);
    } while (!Work && ((LONG64)(__rdtsc() - End) < 0));

    _disable();

    /* A processor that saw the flag set did not interrupt this one, and it
       published the next thread before reading the flag: look again */
    InterlockedExchange(Polling, FALSE);
    return KiIdleHasWork(Prcb);
}

static
BOOLEAN
KiIsProcessorIdle(
    _In_ PKPRCB Prcb)
{
    /* Called with the PRCB lock held */
    return (Prcb->NextThread == Prcb->IdleThread) ||
           ((Prcb->NextThread == NULL) && (Prcb->CurrentThread == Prcb->IdleThread));
}

FORCEINLINE
BOOLEAN
KiTryAcquirePrcbLock(
    _In_ PKPRCB Prcb)
{
    ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

    /* Look first, so a held lock's cache line is not written to */
    return !(*(volatile LONG_PTR *)&Prcb->PrcbLock) &&
           !InterlockedExchange((PLONG)&Prcb->PrcbLock, 1);
}

FORCEINLINE
BOOLEAN
KiTryAcquireThreadLock(
    _In_ PKTHREAD Thread)
{
    ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

    return !(*(volatile LONG_PTR *)&Thread->ThreadLock) &&
           !InterlockedExchange((PLONG)&Thread->ThreadLock, 1);
}

/*
 * Called with the PRCB lock of Prcb held. A ready thread waits on the ready
 * list of the processor it was given to, and no other processor takes it
 * from there: while that processor stays busy with threads of the same or a
 * higher priority, the thread can starve, even when another processor it may
 * run on runs a thread of a lower priority or goes idle, and when more
 * threads of one priority are ready than there are processors, the ones that
 * share a processor get a fraction of the time the others get.
 *
 * Take the highest priority ready thread of at least Priority that may run
 * on Prcb's processor from another processor's ready list. Of one priority,
 * a thread whose ideal processor is Prcb's first, so that threads drift back
 * to their ideal processor rather than away from it. Of a priority below
 * AnyAffinityPriority, only a thread that may run on every processor of
 * Prcb's node: Windows shares the ready threads of one priority among the
 * processors only for those (on Windows 10, spinners restricted to 2 of 4
 * processors stay on their processors and share them unevenly).
 *
 * The other PRCB locks and the thread locks are only tried, never waited
 * for, so processors that look at each other's lists cannot deadlock against
 * each other or against the thread-then-PRCB lock order; a busy list or
 * thread is looked at again at the next switch. The thread lock is needed
 * because KiUpdateEffectiveAffinityThread locks the PRCB of NextProcessor
 * under it and does not look at NextProcessor again.
 */
static
PKTHREAD
KiTakeRemoteReadyThread(
    _In_ PKPRCB Prcb,
    _In_ KPRIORITY Priority,
    _In_ KPRIORITY AnyAffinityPriority)
{
    PKPRCB RemotePrcb;
    PKTHREAD Thread;
    PLIST_ENTRY ListHead, ListEntry;
    ULONG Count, Number, Summary, Mask, Index, Pass;
    KAFFINITY NodeSet = 0;

    if (Priority > HIGH_PRIORITY) return NULL;
    ASSERT(Priority >= 0);

    /* The ready summary bits of Priority and above */
    Mask = ~(PRIORITY_MASK(Priority) - 1);

    /* Look without the locks for the priorities ready on other processors;
       most processors have nothing ready */
    Summary = 0;
    for (Count = 1; Count < (ULONG)KeNumberProcessors; Count++)
    {
        RemotePrcb = KiProcessorBlock[(Prcb->Number + Count) % KeNumberProcessors];
        if (RemotePrcb) Summary |= *(volatile ULONG *)&RemotePrcb->ReadySummary & Mask;
    }

    /* Highest priority first, on every processor before a lower priority:
       the threads of one priority may all be bound to their processors.
       Of one priority, a thread whose ideal processor is this one on every
       processor first (pass 0), then any thread that may run here (pass 1) */
    while (Summary)
    {
        BitScanReverse(&Index, Summary);
        Summary &= ~PRIORITY_MASK(Index);

        /* Below AnyAffinityPriority only a thread that may run on every
           processor of the node moves; the node's processors are looked up
           once, when a restricted priority is first scanned. The node of
           this processor stands for all of them: the kernel has a single
           node (KeNodeBlock[0]), while the scan below covers every
           processor. A multi-node port must limit the scan to the node. */
        if (((KPRIORITY)Index < AnyAffinityPriority) && !NodeSet)
        {
            NodeSet = Prcb->ParentNode->ProcessorMask & KeActiveProcessors;
        }

        for (Pass = 0; Pass < 2; Pass++)
        {
            for (Count = 1; Count < (ULONG)KeNumberProcessors; Count++)
            {
                Number = (Prcb->Number + Count) % KeNumberProcessors;
                RemotePrcb = KiProcessorBlock[Number];
                if (!RemotePrcb) continue;
                if (!(*(volatile ULONG *)&RemotePrcb->ReadySummary & PRIORITY_MASK(Index))) continue;
                if (!KiTryAcquirePrcbLock(RemotePrcb)) continue;

                Thread = NULL;
                if (RemotePrcb->ReadySummary & PRIORITY_MASK(Index))
                {
                    ListHead = &RemotePrcb->DispatcherReadyListHead[Index];
                    for (ListEntry = ListHead->Flink;
                         ListEntry != ListHead;
                         ListEntry = ListEntry->Flink)
                    {
                        Thread = CONTAINING_RECORD(ListEntry, KTHREAD, WaitListEntry);
                        if ((Thread->Affinity & Prcb->SetMember) &&
                            (((KPRIORITY)Index >= AnyAffinityPriority) ||
                             ((Thread->Affinity & NodeSet) == NodeSet)) &&
                            ((Pass != 0) || (Thread->IdealProcessor == Prcb->Number)) &&
                            KiTryAcquireThreadLock(Thread))
                        {
                            /* The affinity can change until the thread is
                               locked: look again, now that it cannot */
                            if ((Thread->Affinity & Prcb->SetMember) &&
                                (((KPRIORITY)Index >= AnyAffinityPriority) ||
                                 ((Thread->Affinity & NodeSet) == NodeSet)))
                            {
                                break;
                            }
                            KiReleaseThreadLock(Thread);
                        }
                        Thread = NULL;
                    }
                }

                if (Thread)
                {
                    ASSERT(Thread->State == Ready);
                    ASSERT(Thread->Priority == (KPRIORITY)Index);
                    ASSERT(Thread->NextProcessor == RemotePrcb->Number);

                    /* Remove it from the list */
                    if (RemoveEntryList(&Thread->WaitListEntry))
                    {
                        RemotePrcb->ReadySummary ^= PRIORITY_MASK(Index);
                    }

                    /* The thread stays Ready until the caller, which holds the PRCB
                       lock of the new processor, gives it a state there; anyone
                       that finds it Ready locks that PRCB and looks again */
                    Thread->NextProcessor = Prcb->Number;
                    KiReleaseThreadLock(Thread);
                }

                KiReleasePrcbLock(RemotePrcb);
                if (Thread) return Thread;
            }
        }
    }

    return NULL;
}

/*
 * Called with the PRCB lock held. Select the ready thread the processor
 * runs next: a thread of a priority of at least RemotePriority and above
 * every thread on its own list from another processor's list (of a priority
 * below AnyAffinityPriority, only one that may run on every processor of the
 * node),
 * else the highest priority thread of at least Priority on its own list.
 */
PKTHREAD
FASTCALL
KiSelectReadyThreadAny(
    _In_ PKPRCB Prcb,
    _In_ KPRIORITY Priority,
    _In_ KPRIORITY RemotePriority,
    _In_ KPRIORITY AnyAffinityPriority)
{
    PKTHREAD Thread;
    ULONG Summary, Highest;

    Summary = Prcb->ReadySummary >> Priority;
    if (Summary)
    {
        BitScanReverse(&Highest, Summary);
        Highest += Priority;
        if (RemotePriority <= (KPRIORITY)Highest)
            RemotePriority = Highest + 1;
    }
    if (AnyAffinityPriority < RemotePriority)
        AnyAffinityPriority = RemotePriority;

    Thread = KiTakeRemoteReadyThread(Prcb, RemotePriority, AnyAffinityPriority);
    if (Thread) return Thread;

    return KiSelectReadyThread(Priority, Prcb);
}

/*
 * Called by the idle loop at DISPATCH_LEVEL with interrupts disabled when
 * no thread is scheduled; returns with interrupts disabled. A thread readied
 * while a processor it may run on is idle normally goes to an idle
 * processor, but a thread readied onto a busy processor just before this
 * one went idle waits there: take it. TRUE when the loop has work to look
 * at before halting.
 */
BOOLEAN
FASTCALL
KiIdleTakeReadyThread(
    _In_ PKPRCB Prcb)
{
    PKTHREAD Thread;
    ULONG Number;

    /* Look without the locks first */
    for (Number = 0; Number < (ULONG)KeNumberProcessors; Number++)
    {
        if ((Number != Prcb->Number) && KiProcessorBlock[Number] &&
            *(volatile ULONG *)&KiProcessorBlock[Number]->ReadySummary)
        {
            break;
        }
    }
    if (Number == (ULONG)KeNumberProcessors) return FALSE;

    _enable();
    KfRaiseIrql(SYNCH_LEVEL);
    KiAcquirePrcbLock(Prcb);
    if (!Prcb->NextThread)
    {
        Thread = KiTakeRemoteReadyThread(Prcb, 0, 0);
        if (Thread)
        {
            Thread->State = Standby;
            Prcb->NextThread = Thread;
            if (KiIdleSummary & Prcb->SetMember)
            {
                InterlockedAndAffinity((PLONG_PTR)&KiIdleSummary,
                                       ~(LONG_PTR)Prcb->SetMember);
            }
        }
    }
    KiReleasePrcbLock(Prcb);
    KeLowerIrql(DISPATCH_LEVEL);
    _disable();

    return KiIdleHasWork(Prcb);
}
#else
#define KiSelectNextProcessor(Thread, Idle) (*(Idle) = FALSE, 0)
#define KiIsProcessorIdle(Prcb) TRUE
#endif

VOID
FASTCALL
KiDeferredReadyThread(IN PKTHREAD Thread)
{
    PKPRCB Prcb;
    BOOLEAN Preempted, Idle;
    ULONG Processor, Attempt;
    KPRIORITY OldPriority;
    PKTHREAD NextThread;

Restart:
    /* Sanity checks */
    ASSERT(Thread->State == DeferredReady);
    ASSERT((Thread->Priority >= 0) && (Thread->Priority <= HIGH_PRIORITY));

    /* Check if we have any adjusts to do */
    if (Thread->AdjustReason == AdjustBoost)
    {
        /* Lock the thread */
        KiAcquireThreadLock(Thread);

        /* Check if the priority is low enough to qualify for boosting */
        if ((Thread->Priority <= Thread->AdjustIncrement) &&
            (Thread->Priority < (LOW_REALTIME_PRIORITY - 3)) &&
            !(Thread->DisableBoost))
        {
            /* Calculate the new priority based on the adjust increment */
            OldPriority = min(Thread->AdjustIncrement + 1,
                              LOW_REALTIME_PRIORITY - 3);

            /* Make sure we're not decreasing outside of the priority range */
            ASSERT((Thread->PriorityDecrement >= 0) &&
                   (Thread->PriorityDecrement <= Thread->Priority));

            /* Calculate the new priority decrement based on the boost */
            Thread->PriorityDecrement += ((SCHAR)OldPriority - Thread->Priority);

            /* Again verify that this decrement is valid */
            ASSERT((Thread->PriorityDecrement >= 0) &&
                   (Thread->PriorityDecrement <= OldPriority));

            /* Set the new priority */
            Thread->Priority = (SCHAR)OldPriority;
        }

        /* We need 4 quanta, make sure we have them, then decrease by one */
        if (Thread->Quantum < 4) Thread->Quantum = 4;
        Thread->Quantum--;

        /* Make sure the priority is still valid */
        ASSERT((Thread->Priority >= 0) && (Thread->Priority <= HIGH_PRIORITY));

        /* Release the lock and clear the adjust reason */
        KiReleaseThreadLock(Thread);
        Thread->AdjustReason = AdjustNone;
    }
    else if (Thread->AdjustReason == AdjustUnwait)
    {
        /* Acquire the thread lock and check if this is a real-time thread */
        KiAcquireThreadLock(Thread);
        if (Thread->Priority < LOW_REALTIME_PRIORITY)
        {
            /* It's not real time, but is it time critical? */
            if (Thread->BasePriority >= (LOW_REALTIME_PRIORITY - 2))
            {
                /* It is, so simply reset its quantum */
                Thread->Quantum = Thread->QuantumReset;
            }
            else
            {
                /* Has the priority been adjusted previously? */
                if (!(Thread->PriorityDecrement) && (Thread->AdjustIncrement))
                {
                    /* Yes, reset its quantum */
                    Thread->Quantum = Thread->QuantumReset;
                }

                /* Wait code already handles quantum adjustment during APCs */
                if (Thread->WaitStatus != STATUS_KERNEL_APC)
                {
                    /* Decrease the quantum by one and check if we're out */
                    if (--Thread->Quantum <= 0)
                    {
                        /* We are, reset the quantum and get a new priority */
                        Thread->Quantum = Thread->QuantumReset;
                        Thread->Priority = KiComputeNewPriority(Thread, 1);
                    }
                }
            }

            /* Now check if we have no decrement and boosts are enabled */
            if (!(Thread->PriorityDecrement) && !(Thread->DisableBoost))
            {
                /* Make sure we have an increment */
                ASSERT(Thread->AdjustIncrement >= 0);

                /* Calculate the new priority after the increment */
                OldPriority = Thread->BasePriority + Thread->AdjustIncrement;

                /* Check if this is a foreground process */
                if (CONTAINING_RECORD(Thread->ApcState.Process, EPROCESS, Pcb)->
                    Vm.Flags.MemoryPriority == MEMORY_PRIORITY_FOREGROUND)
                {
                    /* Apply the foreground boost */
                    OldPriority += PsPrioritySeparation;
                }

                /* Check if this new priority is higher */
                if (OldPriority > Thread->Priority)
                {
                    /* Make sure we don't go into the real time range */
                    if (OldPriority >= LOW_REALTIME_PRIORITY)
                    {
                        /* Normalize it back down one notch */
                        OldPriority = LOW_REALTIME_PRIORITY - 1;
                    }

                    /* Check if the priority is higher then the boosted base */
                    if (OldPriority > (Thread->BasePriority +
                                       Thread->AdjustIncrement))
                    {
                        /* Setup a priority decrement to nullify the boost  */
                        Thread->PriorityDecrement = ((SCHAR)OldPriority -
                                                    Thread->BasePriority -
                                                    Thread->AdjustIncrement);
                    }

                    /* Make sure that the priority decrement is valid */
                    ASSERT((Thread->PriorityDecrement >= 0) &&
                           (Thread->PriorityDecrement <= OldPriority));

                    /* Set this new priority */
                    Thread->Priority = (SCHAR)OldPriority;
                }
            }
        }
        else
        {
            /* It's a real-time thread, so just reset its quantum */
            Thread->Quantum = Thread->QuantumReset;
        }

        /* Make sure the priority makes sense */
        ASSERT((Thread->Priority >= 0) && (Thread->Priority <= HIGH_PRIORITY));

        /* Release the thread lock and reset the adjust reason */
        KiReleaseThreadLock(Thread);
        Thread->AdjustReason = AdjustNone;
    }

    /*
     * Hold the thread lock until the thread has left the deferred ready
     * state. KiSetPriorityThread changes the priority of a deferred ready
     * thread under that lock, and the priority read here chooses the
     * ready list the thread goes to. Release it before the PRCB lock:
     * once that is released, the thread may run, exit and be freed.
     */
    KiAcquireThreadLock(Thread);

    /* Clear thread preemption status and save current values */
    Preempted = Thread->Preempted;
    OldPriority = Thread->Priority;
    Thread->Preempted = FALSE;

    for (Attempt = 0; ; Attempt++)
    {
        /* Select a processor to run on */
        Processor = KiSelectNextProcessor(Thread, &Idle);

        /* Get the PRCB and lock it */
        Prcb = KiProcessorBlock[Processor];
        KiAcquirePrcbLock(Prcb);

        /* Another processor may have given the idle processor a thread
           since the selection; pick again while others are idle */
        if (!Idle || KiIsProcessorIdle(Prcb) || (Attempt == 2)) break;
        KiReleasePrcbLock(Prcb);
    }
    Thread->NextProcessor = Processor;

#ifndef CONFIG_SMP
    /* Check if we have an idle summary */
    if (KiIdleSummary)
    {
        /* Clear it and set this thread as the next one */
        KiIdleSummary = 0;
        Thread->State = Standby;
        Prcb->NextThread = Thread;

        /* Unlock the PRCB and return */
        KiReleaseThreadLock(Thread);
        KiReleasePrcbLock(Prcb);
        return;
    }
#endif // !CONFIG_SMP

    /* Get the next scheduled thread */
    NextThread = Prcb->NextThread;
    if (NextThread)
    {
        /* Sanity check */
        ASSERT(NextThread->State == Standby);

        /* The processor is about to switch to its idle thread: take its
           place, the idle thread is never queued */
        if (NextThread == Prcb->IdleThread)
        {
            Thread->State = Standby;
            Prcb->NextThread = Thread;
            if (KiIdleSummary & Prcb->SetMember)
            {
                InterlockedAndAffinity((PLONG_PTR)&KiIdleSummary,
                                       ~(LONG_PTR)Prcb->SetMember);
            }
            KiReleaseThreadLock(Thread);
            KiReleasePrcbLock(Prcb);

            if (KeGetCurrentProcessorNumber() != Processor)
            {
                KiIpiSend(AFFINITY_MASK(Processor), IPI_DPC);
            }
            return;
        }

        /* Check if priority changed */
        if (OldPriority > NextThread->Priority)
        {
            /* Preempt the thread */
            NextThread->Preempted = TRUE;

            /* Put this one as the next one */
            Thread->State = Standby;
            Prcb->NextThread = Thread;

            /* Set it in deferred ready mode */
            NextThread->State = DeferredReady;
            NextThread->DeferredProcessor = Prcb->Number;
            KiReleaseThreadLock(Thread);
            KiReleasePrcbLock(Prcb);

            /* Make the displaced thread ready, without growing the stack */
            Thread = NextThread;
            goto Restart;
        }
    }
    else
    {
        /* Set the next thread as the current thread. An idle processor
           takes a thread of any priority, its idle loop does not look at
           the ready lists; during phase 0 the boot processor's idle thread
           runs the initialization at a high priority */
        NextThread = Prcb->CurrentThread;
        if ((OldPriority > NextThread->Priority) ||
            ((NextThread == Prcb->IdleThread) && (NextThread->Priority == 0)))
        {
            /* Preempt it if it's already running */
            if (NextThread->State == Running) NextThread->Preempted = TRUE;

            /* Set the thread on standby and as the next thread */
            Thread->State = Standby;
            Prcb->NextThread = Thread;

            /* The processor is no longer idle */
            if (KiIdleSummary & Prcb->SetMember)
            {
                InterlockedAndAffinity((PLONG_PTR)&KiIdleSummary,
                                       ~(LONG_PTR)Prcb->SetMember);
            }

            /* Release the locks */
            KiReleaseThreadLock(Thread);
            KiReleasePrcbLock(Prcb);

            /* Check if we're running on another CPU */
            if (KeGetCurrentProcessorNumber() != Processor)
            {
                /* The idle loop checks for a next thread after any interrupt
                   ends its halt, and while it polls it needs no interrupt at
                   all; a busy processor needs a DPC interrupt to switch. The
                   idle loop runs at DISPATCH_LEVEL, so a DPC request would only
                   fire later, uselessly, in the new thread */
                if (NextThread != Prcb->IdleThread)
                {
                    KiIpiSend(AFFINITY_MASK(Processor), IPI_DPC);
                }
                else
                {
                    /* Order the next thread before the polling flag (see
                       KiIdlePollForWork); the interlocked PRCB lock release
                       does too, but a release need not be a full barrier */
                    KeMemoryBarrier();
                    if (!KiIsProcessorPolling(Processor))
                    {
                        KiIpiSend(AFFINITY_MASK(Processor), 0);
                    }
                }
            }
            return;
        }
    }

    /* Sanity check */
    ASSERT((OldPriority >= 0) && (OldPriority <= HIGH_PRIORITY));

    /* Set this thread as ready */
    Thread->State = Ready;
    Thread->WaitTime = KeTickCount.LowPart;

    /* Insert this thread in the appropriate order */
    Preempted ? InsertHeadList(&Prcb->DispatcherReadyListHead[OldPriority],
                               &Thread->WaitListEntry) :
                InsertTailList(&Prcb->DispatcherReadyListHead[OldPriority],
                               &Thread->WaitListEntry);

    /* Update the ready summary */
    Prcb->ReadySummary |= PRIORITY_MASK(OldPriority);

    /* Sanity check */
    ASSERT(OldPriority == Thread->Priority);

    /* Release the locks */
    KiReleaseThreadLock(Thread);
    KiReleasePrcbLock(Prcb);
}

PKTHREAD
FASTCALL
KiSelectNextThread(IN PKPRCB Prcb)
{
    PKTHREAD Thread;

    /* Select a ready thread */
    Thread = KiSelectReadyThreadAny(Prcb, 0, 0, 0);
    if (!Thread)
    {
        /* Didn't find any, get the current idle thread */
        Thread = Prcb->IdleThread;

        /* Enable idle scheduling */
        InterlockedOrSetMember(&KiIdleSummary, Prcb->SetMember);
        Prcb->IdleSchedule = TRUE;

        /* FIXME: SMT support */
        //ASSERTMSG("SMP: Not yet implemented\n", FALSE);
    }

    /* Sanity checks and return the thread */
    ASSERT(Thread != NULL);
    //ASSERT((Thread->BasePriority == 0) || (Thread->Priority != 0));
    return Thread;
}

LONG_PTR
FASTCALL
KiSwapThread(IN PKTHREAD CurrentThread,
             IN PKPRCB Prcb)
{
    BOOLEAN ApcState = FALSE;
    KIRQL WaitIrql;
    LONG_PTR WaitStatus;
    PKTHREAD NextThread;
    ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);
#if defined(_M_IX86) || defined(_M_AMD64)
    /* Until the switch, this processor could not serve IPIs */
    ASSERT(__readeflags() & EFLAGS_INTERRUPT_MASK);
#endif

#ifdef CONFIG_SMP
    /* Threads readied under the dispatcher lock right before this wait (a
       set-and-wait, a queue waiter activated by this thread) are still on
       the deferred ready list: place them first, or the thread chosen below
       may be a lower-priority one and they wait until this processor next
       retires DPCs, which under load is the next quantum end */
    if (Prcb->DeferredReadyListHead.Next)
    {
        KIRQL OldIrql = KeRaiseIrqlToSynchLevel();
        KiProcessDeferredReadyList(Prcb);
        KeLowerIrql(OldIrql);
    }
#endif

    /* Acquire the PRCB lock */
    KiAcquirePrcbLock(Prcb);

    /* Get the next thread */
    NextThread = Prcb->NextThread;
    if (NextThread)
    {
        /* Already got a thread, set it up */
        Prcb->NextThread = NULL;
        Prcb->CurrentThread = NextThread;
        NextThread->State = Running;
    }
    else
    {
        /* Try to find a ready thread */
        NextThread = KiSelectReadyThreadAny(Prcb, 0, 0, 0);
        if (NextThread)
        {
            /* Switch to it */
            Prcb->CurrentThread = NextThread;
            NextThread->State = Running;
        }
        else
        {
            /* Set the idle summary */
            InterlockedOrSetMember(&KiIdleSummary, Prcb->SetMember);

            /* Schedule the idle thread */
            NextThread = Prcb->IdleThread;
            Prcb->CurrentThread = NextThread;
            NextThread->State = Running;
        }
    }

    /* Sanity check and release the PRCB */
    ASSERT(CurrentThread != Prcb->IdleThread);
    KiReleasePrcbLock(Prcb);

    /* Save the wait IRQL */
    WaitIrql = CurrentThread->WaitIrql;

    /* Swap contexts */
    ApcState = KiSwapContext(WaitIrql, CurrentThread);

    /* Get the wait status */
    WaitStatus = CurrentThread->WaitStatus;

    /* Check if we need to deliver APCs */
    if (ApcState)
    {
        /* Lower to APC_LEVEL */
        KeLowerIrql(APC_LEVEL);

        /* Deliver APCs */
        KiDeliverApc(KernelMode, NULL, NULL);
        ASSERT(WaitIrql == 0);
    }

    /* Lower IRQL back to what it was and return the wait status */
    KeLowerIrql(WaitIrql);
    return WaitStatus;
}

VOID
NTAPI
KiReadyThread(IN PKTHREAD Thread)
{
    IN PKPROCESS Process = Thread->ApcState.Process;

    /* Check if the process is paged out */
    if (Process->State != ProcessInMemory)
    {
        /* We don't page out processes in ROS */
        ASSERT(FALSE);
    }
    else if (!Thread->KernelStackResident)
    {
        /* Increase the stack count */
        ASSERT(Process->StackCount != MAXULONG_PTR);
        Process->StackCount++;

        /* Set the thread to transition */
        ASSERT(Thread->State != Transition);
        Thread->State = Transition;

        /* The stack is always resident in ROS */
        ASSERT(FALSE);
    }
    else
    {
        /* Insert the thread on the deferred ready list */
        KiInsertDeferredReadyList(Thread);
    }
}

VOID
FASTCALL
KiSetPriorityThread(IN PKTHREAD Thread,
                    IN KPRIORITY Priority)
{
    PKPRCB Prcb;
    ULONG Processor;
    BOOLEAN RequestInterrupt = FALSE;
    KPRIORITY OldPriority;
    PKTHREAD NewThread;
    UCHAR State;
    ASSERT((Priority >= 0) && (Priority <= HIGH_PRIORITY));

    /* Check if priority changed */
    if (Thread->Priority != Priority)
    {
        /* Loop priority setting in case we need to start over */
        for (;;)
        {
            /*
             * Read the state once. Other processors move the thread out of
             * Ready, Standby or Running holding only their PRCB lock, so the
             * branches below confirm it under that lock and start over.
             */
            State = *(volatile UCHAR *)&Thread->State;

            /* Choose action based on thread's state */
            if (State == Ready)
            {
                /* Make sure we're not on the ready queue */
                if (!Thread->ProcessReadyQueue)
                {
                    /* Get the PRCB for the thread and lock it */
                    Processor = Thread->NextProcessor;
                    Prcb = KiProcessorBlock[Processor];
                    KiAcquirePrcbLock(Prcb);

                    /* Make sure the thread is still ready and on this CPU */
                    if ((Thread->State == Ready) &&
                        (Thread->NextProcessor == Prcb->Number))
                    {
                        /* Sanity check */
                        ASSERT((Prcb->ReadySummary &
                                PRIORITY_MASK(Thread->Priority)));

                        /* Remove it from the current queue */
                        if (RemoveEntryList(&Thread->WaitListEntry))
                        {
                            /* Update the ready summary */
                            Prcb->ReadySummary ^= PRIORITY_MASK(Thread->
                                                                Priority);
                        }

                        /* Update priority */
                        Thread->Priority = (SCHAR)Priority;

                        /* Re-insert it at its current priority */
                        KiInsertDeferredReadyList(Thread);

                        /* Release the PRCB Lock */
                        KiReleasePrcbLock(Prcb);
                    }
                    else
                    {
                        /* Release the lock and loop again */
                        KiReleasePrcbLock(Prcb);
                        continue;
                    }
                }
                else
                {
                    /* It's already on the ready queue, just update priority */
                    Thread->Priority = (SCHAR)Priority;
                }
            }
            else if (State == Standby)
            {
                /* Get the PRCB for the thread and lock it */
                Processor = Thread->NextProcessor;
                Prcb = KiProcessorBlock[Processor];
                KiAcquirePrcbLock(Prcb);

                /* Check if we're still the next thread to run */
                if (Thread == Prcb->NextThread)
                {
                    /* Get the old priority and update ours */
                    OldPriority = Thread->Priority;
                    Thread->Priority = (SCHAR)Priority;

                    /* Check if there was a change */
                    if (Priority < OldPriority)
                    {
                        /* Find a new thread */
                        NewThread = KiSelectReadyThread(Priority + 1, Prcb);
                        if (NewThread)
                        {
                            /* Found a new one, set it on standby */
                            NewThread->State = Standby;
                            Prcb->NextThread = NewThread;

                            /* Dispatch our thread */
                            KiInsertDeferredReadyList(Thread);
                        }
                    }

                    /* Release the PRCB lock */
                    KiReleasePrcbLock(Prcb);
                }
                else
                {
                    /* Release the lock and try again */
                    KiReleasePrcbLock(Prcb);
                    continue;
                }
            }
            else if (State == Running)
            {
                /* Get the PRCB for the thread and lock it */
                Processor = Thread->NextProcessor;
                Prcb = KiProcessorBlock[Processor];
                KiAcquirePrcbLock(Prcb);

                /* Check if we're still the current thread running */
                if (Thread == Prcb->CurrentThread)
                {
                    /* Get the old priority and update ours */
                    OldPriority = Thread->Priority;
                    Thread->Priority = (SCHAR)Priority;

                    /* Check if there was a change and there's no new thread */
                    if ((Priority < OldPriority) && !(Prcb->NextThread))
                    {
                        /* Find a new thread */
                        NewThread = KiSelectReadyThread(Priority + 1, Prcb);
                        if (NewThread)
                        {
                            /* Found a new one, set it on standby */
                            NewThread->State = Standby;
                            Prcb->NextThread = NewThread;

                            /* Request an interrupt */
                            RequestInterrupt = TRUE;
                        }
                    }

                    /* Release the lock and check if we need an interrupt */
                    KiReleasePrcbLock(Prcb);
                    if (RequestInterrupt)
                    {
                        /* Check if we're running on another CPU */
                        if (KeGetCurrentProcessorNumber() != Processor)
                        {
                            /* We are, send an IPI */
                            KiIpiSend(AFFINITY_MASK(Processor), IPI_DPC);
                        }
                    }
                }
                else
                {
                    /* Thread changed, release lock and restart */
                    KiReleasePrcbLock(Prcb);
                    continue;
                }
            }
            else if (State == DeferredReady)
            {
                /* The thread is on no ready list yet. KiDeferredReadyThread
                   reads its priority under the thread lock, which is held
                   here, so it queues the thread at the new priority */
                Thread->Priority = (SCHAR)Priority;
            }
            else
            {
                /* Any other state, just change priority */
                Thread->Priority = (SCHAR)Priority;
            }

            /* If we got here, then thread state was consistent, so bail out */
            break;
        }
    }
}

#ifdef CONFIG_SMP
static
VOID
KiUpdateEffectiveAffinityThread(
    _In_ PKTHREAD Thread)
{
    PKPRCB Prcb;

    /* Acquire the thread lock */
    KiAcquireThreadLock(Thread);

    /* Get the PRCB that the thread is to be run on and lock it */
    Prcb = KiProcessorBlock[Thread->NextProcessor];
    KiAcquirePrcbLock(Prcb);

    /* Set the thread's affinity and ideal processor */
    Thread->Affinity = Thread->UserAffinity;
    Thread->IdealProcessor = Thread->UserIdealProcessor;

    /* Check if the affinity doesn't match with the current processor */
    if ((Prcb->SetMember & Thread->Affinity) == 0)
    {
        if (Thread->State == Running)
        {
            /* Check if there is the next thread is selected already */
            if (Prcb->NextThread == NULL)
            {
                /* It is not, select a new thread and set it on standby */
                Prcb->NextThread = KiSelectNextThread(Prcb);
                Prcb->NextThread->State = Standby;
            }

            /* Check if the thread is running on a different processor */
            if (Prcb != KeGetCurrentPrcb())
            {
                /* It is, send an IPI */
                KiIpiSend(AFFINITY_MASK(Thread->NextProcessor), IPI_DPC);
            }
        }
        else if (Thread->State == Standby)
        {
            /* Select a new thread and set it on standby */
            Prcb->NextThread = KiSelectNextThread(Prcb);
            Prcb->NextThread->State = Standby;

            /* Insert the thread back into the ready list */
            KiInsertDeferredReadyList(Thread);
        }
        else if (Thread->State == Ready)
        {
            /* Remove it from the list */
            if (RemoveEntryList(&Thread->WaitListEntry))
            {
                /* The list is empty now, reset the ready summary */
                Prcb->ReadySummary &= ~PRIORITY_MASK(Thread->Priority);
            }

            /* Insert the thread back into the ready list */
            KiInsertDeferredReadyList(Thread);
        }
    }

    KiReleasePrcbLock(Prcb);
    KiReleaseThreadLock(Thread);
}
#endif // CONFIG_SMP

KAFFINITY
FASTCALL
KiSetAffinityThread(IN PKTHREAD Thread,
                    IN KAFFINITY Affinity)
{
    KAFFINITY OldAffinity;

    /* Get the current affinity */
    OldAffinity = Thread->UserAffinity;

    /* Make sure that the affinity is valid */
    if (((Affinity & Thread->ApcState.Process->Affinity) != (Affinity)) ||
        (!Affinity))
    {
        /* Bugcheck the system */
        KeBugCheck(INVALID_AFFINITY_SET);
    }

    /* Update the new affinity */
    Thread->UserAffinity = Affinity;

#ifdef CONFIG_SMP
    /* Check if system affinity is not active */
    if (!Thread->SystemAffinityActive)
    {
        /* Calculate the new ideal processor from the affinity set */
        Thread->UserIdealProcessor =
            KiFindIdealProcessor(Affinity, Thread->UserIdealProcessor);

        /* Update the effective affinity */
        KiUpdateEffectiveAffinityThread(Thread);
    }
#endif

    /* Return the old affinity */
    return OldAffinity;
}

//
// This macro exists because NtYieldExecution locklessly attempts to read from
// the KPRCB's ready summary, and the usual way of going through KeGetCurrentPrcb
// would require getting fs:1C first (or gs), and then doing another dereference.
// In an attempt to minimize the amount of instructions and potential race/tear
// that could happen, Windows seems to define this as a macro that directly acceses
// the ready summary through a single fs: read by going through the KPCR's PrcbData.
//
// See http://research.microsoft.com/en-us/collaboration/global/asia-pacific/programs/trk_case4_process-thread_management.pdf (DEAD_LINK)
//
// We need this per-arch because sometimes it's Prcb and sometimes PrcbData, and
// because on x86 it's FS, and on x64 it's GS (not sure what it is on ARM/PPC).
//
#ifdef _M_IX86
#define KiGetCurrentReadySummary() __readfsdword(FIELD_OFFSET(KIPCR, PrcbData.ReadySummary))
#elif _M_AMD64
#define KiGetCurrentReadySummary() __readgsdword(FIELD_OFFSET(KIPCR, Prcb.ReadySummary))
#else
#define KiGetCurrentReadySummary() KeGetCurrentPrcb()->ReadySummary
#endif

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtYieldExecution(VOID)
{
    NTSTATUS Status;
    KIRQL OldIrql;
    PKPRCB Prcb;
    PKTHREAD Thread, NextThread;

    /* NB: No instructions (other than entry code) should preceed this line */

    /* Fail if there's no ready summary */
    if (!KiGetCurrentReadySummary()) return STATUS_NO_YIELD_PERFORMED;

    /* Now get the current thread, set the status... */
    Status = STATUS_NO_YIELD_PERFORMED;
    Thread = KeGetCurrentThread();

    /* Raise IRQL to synch and get the KPRCB now */
    OldIrql = KeRaiseIrqlToSynchLevel();
    Prcb = KeGetCurrentPrcb();

    /* Now check if there's still a ready summary */
    if (Prcb->ReadySummary)
    {
        /* Acquire thread and PRCB lock */
        KiAcquireThreadLock(Thread);
        KiAcquirePrcbLock(Prcb);

        /* Find a new thread to run if none was selected */
        if (!Prcb->NextThread) Prcb->NextThread = KiSelectReadyThread(1, Prcb);

        /* Make sure we still have a next thread to schedule */
        NextThread = Prcb->NextThread;
        if (NextThread)
        {
            /* Reset quantum and recalculate priority */
            Thread->Quantum = Thread->QuantumReset;
            Thread->Priority = KiComputeNewPriority(Thread, 1);

            /* Release the thread lock */
            KiReleaseThreadLock(Thread);

            /* Set context swap busy */
            KiSetThreadSwapBusy(Thread);

            /* Set the new thread as running */
            Prcb->NextThread = NULL;
            Prcb->CurrentThread = NextThread;
            NextThread->State = Running;

            /* Setup a yield wait and queue the thread */
            Thread->WaitReason = WrYieldExecution;
            KxQueueReadyThread(Thread, Prcb);

            /* Make it wait at APC_LEVEL */
            Thread->WaitIrql = APC_LEVEL;

            /* Sanity check */
            ASSERT(OldIrql <= DISPATCH_LEVEL);

            /* Swap to new thread */
            KiSwapContext(APC_LEVEL, Thread);
            Status = STATUS_SUCCESS;
        }
        else
        {
            /* Release the PRCB and thread lock */
            KiReleasePrcbLock(Prcb);
            KiReleaseThreadLock(Thread);
        }
    }

    /* Lower IRQL and return */
    KeLowerIrql(OldIrql);
    return Status;
}
