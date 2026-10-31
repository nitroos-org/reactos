/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/dpc.c
 * PURPOSE:         Deferred Procedure Call (DPC) Support
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Philip Susi (phreak@iag.net)
 *                  Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

ULONG KiMaximumDpcQueueDepth = 4;
ULONG KiMinimumDpcRate = 3;
ULONG KiAdjustDpcThreshold = 20;
ULONG KiIdealDpcRate = 20;
BOOLEAN KeThreadDpcEnable;
FAST_MUTEX KiGenericCallDpcMutex;
KDPC KiTimerExpireDpc;
ULONG KiTimeLimitIsrMicroseconds;
ULONG KiDPCTimeout = 110;

/* PRIVATE FUNCTIONS *********************************************************/

VOID
NTAPI
KiCheckTimerTable(IN ULARGE_INTEGER CurrentTime)
{
#if DBG
    ULONG i = 0;
    PLIST_ENTRY ListHead, NextEntry;
    KIRQL OldIrql;
    PKTIMER Timer;

    /* Raise IRQL to high and loop timers */
    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
    do
    {
        /* Loop the current list */
        ListHead = &KiTimerTableListHead[i].Entry;
        NextEntry = ListHead->Flink;
        while (NextEntry != ListHead)
        {
            /* Get the timer and move to the next one */
            Timer = CONTAINING_RECORD(NextEntry, KTIMER, TimerListEntry);
            NextEntry = NextEntry->Flink;

            /* Check if it expired */
            if (Timer->DueTime.QuadPart <= CurrentTime.QuadPart)
            {
                /* Check if the DPC was queued, but didn't run */
                if (!(KeGetCurrentPrcb()->TimerRequest) &&
                    !(*((volatile PULONG*)(&KiTimerExpireDpc.DpcData))))
                {
                    /* This is bad, breakpoint! */
                    DPRINT1("Invalid timer state!\n");
                    DbgBreakPoint();
                }
            }
        }

        /* Move to the next timer */
        i++;
    } while(i < TIMER_TABLE_SIZE);

    /* Lower IRQL and return */
    KeLowerIrql(OldIrql);
#endif
}

VOID
NTAPI
KiTimerExpiration(IN PKDPC Dpc,
                  IN PVOID DeferredContext,
                  IN PVOID SystemArgument1,
                  IN PVOID SystemArgument2)
{
    ULARGE_INTEGER SystemTime, InterruptTime;
    LARGE_INTEGER Interval;
    LONG Limit, Index, i;
    ULONG Timers, ActiveTimers, DpcCalls;
    PLIST_ENTRY ListHead, NextEntry;
    KIRQL OldIrql;
    PKTIMER Timer;
    PKDPC TimerDpc;
    ULONG Period;
    DPC_QUEUE_ENTRY DpcEntry[MAX_TIMER_DPCS];
    PKSPIN_LOCK_QUEUE LockQueue;
    PKPRCB Prcb = KeGetCurrentPrcb();

    /* Disable interrupts */
    _disable();

    /* Query system and interrupt time */
    KeQuerySystemTime((PLARGE_INTEGER)&SystemTime);
    InterruptTime.QuadPart = KeQueryInterruptTime();
    Limit = KeTickCount.LowPart;

    /* Bring interrupts back */
    _enable();

    /* Get the tick count of the request and normalize it: scan from its hand
       to the current one, or the whole table if the tick count moved a table
       revolution or more since (unsigned, across the wrap of the tick count) */
    Index = PtrToLong(SystemArgument1);
    if (((ULONG)Limit - (ULONG)Index) >= TIMER_TABLE_SIZE)
    {
        /* Normalize it */
        Index &= (TIMER_TABLE_SIZE - 1);
        Limit = Index + TIMER_TABLE_SIZE - 1;
    }
    Index &= (TIMER_TABLE_SIZE - 1);

    /* Setup index and actual limit */
    Index--;
    Limit &= (TIMER_TABLE_SIZE - 1);

    /* Setup accounting data */
    DpcCalls = 0;
    Timers = 24;
    ActiveTimers = 4;

    /* Lock the Database and Raise IRQL */
    OldIrql = KiAcquireDispatcherLock();

    /* Start expiration loop */
    do
    {
        /* Get the current index */
        Index = (Index + 1) & (TIMER_TABLE_SIZE - 1);

        /* Get list pointers and loop the list */
        ListHead = &KiTimerTableListHead[Index].Entry;
        while (ListHead != ListHead->Flink)
        {
            /* Lock the timer and go to the next entry */
            LockQueue = KiAcquireTimerLock(Index);
            NextEntry = ListHead->Flink;

            /* Get the current timer and check its due time */
            Timers--;
            Timer = CONTAINING_RECORD(NextEntry, KTIMER, TimerListEntry);
            if ((NextEntry != ListHead) &&
                (Timer->DueTime.QuadPart <= InterruptTime.QuadPart))
            {
                /* It's expired, remove it */
                ActiveTimers--;
                KiRemoveEntryTimer(Timer);

                /* Make it non-inserted, unlock it, and signal it */
                Timer->Header.Inserted = FALSE;
                KiReleaseTimerLock(LockQueue);
                Timer->Header.SignalState = 1;

                /* Get the DPC and period */
                TimerDpc = Timer->Dpc;
                Period = Timer->Period;

                /* Check if there's any waiters */
                if (!IsListEmpty(&Timer->Header.WaitListHead))
                {
                    /* Check the type of event */
                    if (Timer->Header.Type == TimerNotificationObject)
                    {
                        /* Unwait the thread */
                        KxUnwaitThread(&Timer->Header, IO_NO_INCREMENT);
                    }
                    else
                    {
                        /* Otherwise unwait the thread and signal the timer */
                        KxUnwaitThreadForEvent((PKEVENT)Timer, IO_NO_INCREMENT);
                    }
                }

                /* Check if we have a period */
                if (Period)
                {
                    /* Calculate the interval and insert the timer */
                    Interval.QuadPart = Int32x32To64(Period, -10000);
                    while (!KiInsertTreeTimer(Timer, Interval));
                }

                /* Check if we have a DPC */
                if (TimerDpc)
                {
#ifdef CONFIG_SMP
                    /*
                     * If the DPC is targeted to another processor,
                     * then insert it into that processor's DPC queue
                     * instead of delivering it now.
                     * If the DPC is a threaded DPC, and the current CPU
                     * has threaded DPCs enabled (KiExecuteDpc is actively parsing DPCs),
                     * then also insert it into the DPC queue for threaded delivery,
                     * instead of doing it here.
                     */
                    if (((TimerDpc->Number >= MAXIMUM_PROCESSORS) &&
                        ((TimerDpc->Number - MAXIMUM_PROCESSORS) != Prcb->Number)) ||
                        ((TimerDpc->Type == ThreadedDpcObject) && (Prcb->ThreadDpcEnable)))
                    {
                        /* Queue it */
                        KeInsertQueueDpc(TimerDpc,
                                         UlongToPtr(SystemTime.LowPart),
                                         UlongToPtr(SystemTime.HighPart));
                    }
                    else
#endif
                    {
                        /* Setup the DPC Entry */
                        DpcEntry[DpcCalls].Dpc = TimerDpc;
                        DpcEntry[DpcCalls].Routine = TimerDpc->DeferredRoutine;
                        DpcEntry[DpcCalls].Context = TimerDpc->DeferredContext;
                        DpcCalls++;
                        ASSERT(DpcCalls < MAX_TIMER_DPCS);
                    }
                }

                /* Check if we're done processing */
                if (!(ActiveTimers) || !(Timers))
                {
                    /* Release the dispatcher while doing DPCs */
                    KiReleaseDispatcherLock(DISPATCH_LEVEL);

                    /* Start looping all DPC Entries */
                    for (i = 0; DpcCalls; DpcCalls--, i++)
                    {
#if DBG
                        /* Clear DPC Time */
                        Prcb->DebugDpcTime = 0;
#endif

                        /* Call the DPC */
                        DpcEntry[i].Routine(DpcEntry[i].Dpc,
                                            DpcEntry[i].Context,
                                            UlongToPtr(SystemTime.LowPart),
                                            UlongToPtr(SystemTime.HighPart));
                    }

                    /* Reset accounting */
                    Timers = 24;
                    ActiveTimers = 4;

                    /* Lock the dispatcher database */
                    KiAcquireDispatcherLock();
                }
            }
            else
            {
                /* Check if the timer list is empty */
                if (NextEntry != ListHead)
                {
                    /* Sanity check */
                    ASSERT(KiTimerTableListHead[Index].Time.QuadPart <=
                           Timer->DueTime.QuadPart);

                    /* Update the time */
                    _disable();
                    KiTimerTableListHead[Index].Time.QuadPart =
                        Timer->DueTime.QuadPart;
                    _enable();
                }

                /* Release the lock */
                KiReleaseTimerLock(LockQueue);

                /* Check if we've scanned all the timers we could */
                if (!Timers)
                {
                    /* Release the dispatcher while doing DPCs */
                    KiReleaseDispatcherLock(DISPATCH_LEVEL);

                    /* Start looping all DPC Entries */
                    for (i = 0; DpcCalls; DpcCalls--, i++)
                    {
#if DBG
                        /* Clear DPC Time */
                        Prcb->DebugDpcTime = 0;
#endif

                        /* Call the DPC */
                        DpcEntry[i].Routine(DpcEntry[i].Dpc,
                                            DpcEntry[i].Context,
                                            UlongToPtr(SystemTime.LowPart),
                                            UlongToPtr(SystemTime.HighPart));
                    }

                    /* Reset accounting */
                    Timers = 24;
                    ActiveTimers = 4;

                    /* Lock the dispatcher database */
                    KiAcquireDispatcherLock();
                }

                /* Done looping */
                break;
            }
        }
    } while (Index != Limit);

    /* Verify the timer table, on debug builds */
    if (KeNumberProcessors == 1) KiCheckTimerTable(InterruptTime);

    /* Check if we still have DPC entries */
    if (DpcCalls)
    {
        /* Release the dispatcher while doing DPCs */
        KiReleaseDispatcherLock(DISPATCH_LEVEL);

        /* Start looping all DPC Entries */
        for (i = 0; DpcCalls; DpcCalls--, i++)
        {
#if DBG
            /* Clear DPC Time */
            Prcb->DebugDpcTime = 0;
#endif

            /* Call the DPC */
            DpcEntry[i].Routine(DpcEntry[i].Dpc,
                                DpcEntry[i].Context,
                                UlongToPtr(SystemTime.LowPart),
                                UlongToPtr(SystemTime.HighPart));
        }

        /* Lower IRQL if we need to */
        if (OldIrql != DISPATCH_LEVEL) KeLowerIrql(OldIrql);
    }
    else
    {
        /* Unlock the dispatcher */
        KiReleaseDispatcherLock(OldIrql);
    }
}

VOID
FASTCALL
KiTimerListExpire(IN PLIST_ENTRY ExpiredListHead,
                  IN KIRQL OldIrql)
{
    ULARGE_INTEGER SystemTime;
    LARGE_INTEGER Interval;
    LONG i;
    ULONG DpcCalls = 0;
    PKTIMER Timer;
    PKDPC TimerDpc;
    ULONG Period;
    DPC_QUEUE_ENTRY DpcEntry[MAX_TIMER_DPCS];
    PKPRCB Prcb = KeGetCurrentPrcb();

    /* Query system */
    KeQuerySystemTime((PLARGE_INTEGER)&SystemTime);

    /* Loop expired list */
    while (ExpiredListHead->Flink != ExpiredListHead)
    {
        /* Get the current timer */
        Timer = CONTAINING_RECORD(ExpiredListHead->Flink, KTIMER, TimerListEntry);

        /* Remove it */
        RemoveEntryList(&Timer->TimerListEntry);

        /* Not inserted */
        Timer->Header.Inserted = FALSE;

        /* Signal it */
        Timer->Header.SignalState = 1;

        /* Get the DPC and period */
        TimerDpc = Timer->Dpc;
        Period = Timer->Period;

        /* Check if there's any waiters */
        if (!IsListEmpty(&Timer->Header.WaitListHead))
        {
            /* Check the type of event */
            if (Timer->Header.Type == TimerNotificationObject)
            {
                /* Unwait the thread */
                KxUnwaitThread(&Timer->Header, IO_NO_INCREMENT);
            }
            else
            {
                /* Otherwise unwait the thread and signal the timer */
                KxUnwaitThreadForEvent((PKEVENT)Timer, IO_NO_INCREMENT);
            }
        }

        /* Check if we have a period */
        if (Period)
        {
            /* Calculate the interval and insert the timer */
            Interval.QuadPart = Int32x32To64(Period, -10000);
            while (!KiInsertTreeTimer(Timer, Interval));
        }

        /* Check if we have a DPC */
        if (TimerDpc)
        {
#ifdef CONFIG_SMP
            /*
             * If the DPC is targeted to another processor,
             * then insert it into that processor's DPC queue
             * instead of delivering it now.
             * If the DPC is a threaded DPC, and the current CPU
             * has threaded DPCs enabled (KiExecuteDpc is actively parsing DPCs),
             * then also insert it into the DPC queue for threaded delivery,
             * instead of doing it here.
             */
            if (((TimerDpc->Number >= MAXIMUM_PROCESSORS) &&
                ((TimerDpc->Number - MAXIMUM_PROCESSORS) != Prcb->Number)) ||
                ((TimerDpc->Type == ThreadedDpcObject) && (Prcb->ThreadDpcEnable)))
            {
                /* Queue it */
                KeInsertQueueDpc(TimerDpc,
                                 UlongToPtr(SystemTime.LowPart),
                                 UlongToPtr(SystemTime.HighPart));
            }
            else
#endif
            {
                /* Setup the DPC Entry */
                DpcEntry[DpcCalls].Dpc = TimerDpc;
                DpcEntry[DpcCalls].Routine = TimerDpc->DeferredRoutine;
                DpcEntry[DpcCalls].Context = TimerDpc->DeferredContext;
                DpcCalls++;
                ASSERT(DpcCalls < MAX_TIMER_DPCS);
            }
        }
    }

    /* Check if we still have DPC entries */
    if (DpcCalls)
    {
        /* Release the dispatcher while doing DPCs */
        KiReleaseDispatcherLock(DISPATCH_LEVEL);

        /* Start looping all DPC Entries */
        for (i = 0; DpcCalls; DpcCalls--, i++)
        {
#if DBG
            /* Clear DPC Time */
            Prcb->DebugDpcTime = 0;
#endif

            /* Call the DPC */
            DpcEntry[i].Routine(DpcEntry[i].Dpc,
                                DpcEntry[i].Context,
                                UlongToPtr(SystemTime.LowPart),
                                UlongToPtr(SystemTime.HighPart));
        }

        /* Lower IRQL */
        KeLowerIrql(OldIrql);
    }
    else
    {
        /* Unlock the dispatcher */
        KiReleaseDispatcherLock(OldIrql);
    }
}

_Requires_lock_not_held_(Prcb->PrcbLock)
VOID
NTAPI
KiQuantumEnd(VOID)
{
    PKPRCB Prcb = KeGetCurrentPrcb();
    PKTHREAD NextThread, Thread = Prcb->CurrentThread;

    /* Check if a DPC Event was requested to be signaled */
    if (InterlockedExchange(&Prcb->DpcSetEventRequest, 0))
    {
        /* Signal it */
        KeSetEvent(&Prcb->DpcEvent, 0, 0);
    }

    /* Raise to synchronization level and lock the PRCB and thread */
    KeRaiseIrqlToSynchLevel();
    KiAcquireThreadLock(Thread);
    KiAcquirePrcbLock(Prcb);

    /* Check if Quantum expired */
    if (Thread->Quantum <= 0)
    {
        /* Check if we're real-time and with quantums disabled */
        if ((Thread->Priority >= LOW_REALTIME_PRIORITY) &&
            (Thread->ApcState.Process->DisableQuantum))
        {
            /* Otherwise, set maximum quantum */
            Thread->Quantum = MAX_QUANTUM;
        }
        else
        {
            /* Reset the new Quantum */
            Thread->Quantum = Thread->QuantumReset;

            /* Calculate new priority */
            Thread->Priority = KiComputeNewPriority(Thread, 1);

            /* Check if a new thread is scheduled */
            if (!Prcb->NextThread)
            {
                /* Get a new ready thread of at least the same priority, from
                   another processor's list when there is none on this one:
                   when more threads of one priority are ready than there are
                   processors, each processor that ends a quantum takes its
                   turn, so they all share the processors, as on Windows. Of
                   the same priority, only a thread that may run on every
                   processor of the node; Windows leaves the others where
                   they are */
                NextThread = KiSelectReadyThreadAny(Prcb,
                                                    Thread->Priority,
                                                    Thread->Priority,
                                                    Thread->Priority + 1);
                if (NextThread)
                {
                    /* Found one, set it on standby */
                    NextThread->State = Standby;
                    Prcb->NextThread = NextThread;
                }
            }
            else
            {
                /* Otherwise, make sure that this thread doesn't get preempted */
                Thread->Preempted = FALSE;
            }
        }
    }

    /* Release the thread lock */
    KiReleaseThreadLock(Thread);

    /* Check if there's no thread scheduled */
    if (!Prcb->NextThread)
    {
        /* Just leave now */
        KiReleasePrcbLock(Prcb);
        KeLowerIrql(DISPATCH_LEVEL);
        return;
    }

    /* Get the next thread now */
    NextThread = Prcb->NextThread;

    /* Set current thread's swap busy to true */
    KiSetThreadSwapBusy(Thread);

    /* Switch threads in PRCB */
    Prcb->NextThread = NULL;
    Prcb->CurrentThread = NextThread;

    /* Set thread to running and the switch reason to Quantum End */
    NextThread->State = Running;
    Thread->WaitReason = WrQuantumEnd;

    /* Queue it on the ready lists */
    KxQueueReadyThread(Thread, Prcb);

    /* Set wait IRQL to APC_LEVEL */
    Thread->WaitIrql = APC_LEVEL;

    /* Swap threads */
    KiSwapContext(APC_LEVEL, Thread);

    /* Lower IRQL back to DISPATCH_LEVEL */
    KeLowerIrql(DISPATCH_LEVEL);
}

VOID
FASTCALL
KiRetireDpcList(IN PKPRCB Prcb)
{
    PKDPC_DATA DpcData;
    PLIST_ENTRY ListHead, DpcEntry;
    PKDPC Dpc;
    PKDEFERRED_ROUTINE DeferredRoutine;
    PVOID DeferredContext, SystemArgument1, SystemArgument2;
    ULONG_PTR TimerHand;
#ifdef CONFIG_SMP
    KIRQL OldIrql;
#endif

    /* Get data and list variables before starting anything else */
    DpcData = &Prcb->DpcData[DPC_NORMAL];
    ListHead = &DpcData->DpcListHead;

    /* Main outer loop */
    do
    {
        /* Set us as active */
        Prcb->DpcRoutineActive = TRUE;

        /* Check if this is a timer expiration request */
        if (Prcb->TimerRequest)
        {
            /* It is, get the timer hand and disable timer request */
            TimerHand = Prcb->TimerHand;
            Prcb->TimerRequest = 0;

            /* Expire timers with interrupts enabled */
            _enable();
            KiTimerExpiration(NULL, NULL, (PVOID)TimerHand, NULL);
            _disable();
        }

        /* Loop while we have entries in the queue */
        while (DpcData->DpcQueueDepth != 0)
        {
            /* Lock the DPC data and get the DPC entry*/
            KeAcquireSpinLockAtDpcLevel(&DpcData->DpcLock);
            DpcEntry = ListHead->Flink;

            /* Make sure we have an entry */
            if (DpcEntry != ListHead)
            {
                /* Remove the DPC from the list */
                RemoveEntryList(DpcEntry);
                Dpc = CONTAINING_RECORD(DpcEntry, KDPC, DpcListEntry);

                /* Clear its DPC data and save its parameters */
                Dpc->DpcData = NULL;
                DeferredRoutine = Dpc->DeferredRoutine;
                DeferredContext = Dpc->DeferredContext;
                SystemArgument1 = Dpc->SystemArgument1;
                SystemArgument2 = Dpc->SystemArgument2;

                /* Decrease the queue depth */
                DpcData->DpcQueueDepth--;

#if DBG
                /* Clear DPC Time */
                Prcb->DebugDpcTime = 0;
#endif

                /* Release the lock */
                KeReleaseSpinLockFromDpcLevel(&DpcData->DpcLock);

                /* Re-enable interrupts */
                _enable();

                /* Call the DPC */
                DeferredRoutine(Dpc,
                                DeferredContext,
                                SystemArgument1,
                                SystemArgument2);
                ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

                /* Disable interrupts and keep looping */
                _disable();
            }
            else
            {
                /* The queue should be flushed now */
                ASSERT(DpcData->DpcQueueDepth == 0);

                /* Release DPC Lock */
                KeReleaseSpinLockFromDpcLevel(&DpcData->DpcLock);
            }
        }

        /* Clear DPC Flags */
        Prcb->DpcRoutineActive = FALSE;
        Prcb->DpcInterruptRequested = FALSE;
#ifdef CONFIG_SMP
        /* Pairs with the barrier in KeInsertQueueDpc for a DPC from another processor */
        KeMemoryBarrier();
#endif

#ifdef CONFIG_SMP
        /* Check if we have deferred threads */
        if (Prcb->DeferredReadyListHead.Next)
        {

            /* Re-enable interrupts and raise to synch */
            _enable();
            OldIrql = KeRaiseIrqlToSynchLevel();

            /* Process deferred threads */
            KiProcessDeferredReadyList(Prcb);

            /* Lower IRQL back and disable interrupts */
            KeLowerIrql(OldIrql);
            _disable();
        }
#endif
    } while (DpcData->DpcQueueDepth != 0);
}

VOID
NTAPI
KiInitializeDpc(IN PKDPC Dpc,
                IN PKDEFERRED_ROUTINE DeferredRoutine,
                IN PVOID DeferredContext,
                IN KOBJECTS Type)
{
    /* Setup the DPC Object */
    Dpc->Type = Type;
    Dpc->Number = 0;
    Dpc->Importance= MediumImportance;
    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->DeferredContext = DeferredContext;
    Dpc->DpcData = NULL;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
VOID
NTAPI
KeInitializeThreadedDpc(IN PKDPC Dpc,
                        IN PKDEFERRED_ROUTINE DeferredRoutine,
                        IN PVOID DeferredContext)
{
    /* Call the internal routine */
    KiInitializeDpc(Dpc, DeferredRoutine, DeferredContext, ThreadedDpcObject);
}

/*
 * @implemented
 */
VOID
NTAPI
KeInitializeDpc(IN PKDPC Dpc,
                IN PKDEFERRED_ROUTINE DeferredRoutine,
                IN PVOID DeferredContext)
{
    /* Call the internal routine */
    KiInitializeDpc(Dpc, DeferredRoutine, DeferredContext, DpcObject);
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
KeInsertQueueDpc(IN PKDPC Dpc,
                 IN PVOID SystemArgument1,
                 IN PVOID SystemArgument2)
{
    KIRQL OldIrql;
    PKPRCB Prcb, CurrentPrcb;
    ULONG Cpu;
    PKDPC_DATA DpcData;
    BOOLEAN DpcConfigured = FALSE, DpcInserted = FALSE;
    ASSERT_DPC(Dpc);

    /* Check IRQL and Raise it to HIGH_LEVEL */
    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
    CurrentPrcb = KeGetCurrentPrcb();

    /* Check if the DPC has more then the maximum number of CPUs */
    if (Dpc->Number >= MAXIMUM_PROCESSORS)
    {
        /* Then substract the maximum and get that PRCB. */
        Cpu = Dpc->Number - MAXIMUM_PROCESSORS;
        Prcb = KiProcessorBlock[Cpu];
    }
    else
    {
        /* Use the current one */
        Prcb = CurrentPrcb;
        Cpu = Prcb->Number;
    }

    /* Check if this is a threaded DPC and threaded DPCs are enabled */
    if ((Dpc->Type == ThreadedDpcObject) && (Prcb->ThreadDpcEnable))
    {
        /* Then use the threaded data */
        DpcData = &Prcb->DpcData[DPC_THREADED];
    }
    else
    {
        /* Otherwise, use the regular data */
        DpcData = &Prcb->DpcData[DPC_NORMAL];
    }

    /* Acquire the DPC lock */
    KiAcquireSpinLock(&DpcData->DpcLock);

    /* Get the DPC Data */
    if (!InterlockedCompareExchangePointer(&Dpc->DpcData, DpcData, NULL))
    {
        /* Now we can play with the DPC safely */
        Dpc->SystemArgument1 = SystemArgument1;
        Dpc->SystemArgument2 = SystemArgument2;
        DpcData->DpcQueueDepth++;
        DpcData->DpcCount++;
        DpcConfigured = TRUE;

        /* The target clears its DPC flags without the DPC lock, see KiRetireDpcList */
        if (Prcb != CurrentPrcb) KeMemoryBarrier();

        /* Check if this is a high importance DPC */
        if (Dpc->Importance == HighImportance)
        {
            /* Pre-empty other DPCs */
            InsertHeadList(&DpcData->DpcListHead, &Dpc->DpcListEntry);
        }
        else
        {
            /* Add it at the end */
            InsertTailList(&DpcData->DpcListHead, &Dpc->DpcListEntry);
        }

        /* Check if this is the DPC on the threaded list */
        if (&Prcb->DpcData[DPC_THREADED] == DpcData)
        {
            /* Make sure a threaded DPC isn't already active */
            if (!(Prcb->DpcThreadActive) && !(Prcb->DpcThreadRequested))
            {
                /* FIXME: Setup Threaded DPC */
                UNIMPLEMENTED_FATAL("Threaded DPC not supported\n");
            }
        }
        else
        {
            /* Make sure a DPC isn't executing already */
            if (!(Prcb->DpcRoutineActive) && !(Prcb->DpcInterruptRequested))
            {
                /* Check if this is the same CPU */
                if (Prcb != CurrentPrcb)
                {
                    /*
                     * Check if the DPC is of high importance or above the
                     * maximum depth. An idle processor halts, so it needs
                     * the interrupt as well.
                     */
                    if ((Dpc->Importance == HighImportance) ||
                        (DpcData->DpcQueueDepth >=
                         Prcb->MaximumDpcQueueDepth))
                    {
                        /* Set interrupt requested */
                        Prcb->DpcInterruptRequested = TRUE;

                        /* Set DPC inserted */
                        DpcInserted = TRUE;
                    }
                }
                else
                {
                    /* Check if the DPC is of anything but low importance */
                    if ((Dpc->Importance != LowImportance) ||
                        (DpcData->DpcQueueDepth >=
                         Prcb->MaximumDpcQueueDepth) ||
                        (Prcb->DpcRequestRate < Prcb->MinimumDpcRate))
                    {
                        /* Set interrupt requested */
                        Prcb->DpcInterruptRequested = TRUE;

                        /* Set DPC inserted */
                        DpcInserted = TRUE;
                    }
                }
            }
        }
    }

    /* Release the lock */
    KiReleaseSpinLock(&DpcData->DpcLock);

    /* Check if the DPC was inserted */
    if (DpcInserted)
    {
        /* Check if this was SMP */
        if (Prcb != CurrentPrcb)
        {
            /* It was, request and IPI */
            KiIpiSend(AFFINITY_MASK(Cpu), IPI_DPC);
        }
        else
        {
            /* It wasn't, request an interrupt from HAL */
            HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
        }
    }

    /* Lower IRQL */
    KeLowerIrql(OldIrql);
    return DpcConfigured;
}

static
VOID
KiClearDpcInterruptRequest(
    _In_ PKDPC_DATA DpcData)
{
    ULONG i;

    /* Called with the DPC lock held, which KeInsertQueueDpc holds to read the flag */
    for (i = 0; i < (ULONG)KeNumberProcessors; i++)
    {
        if (KiProcessorBlock[i] && (DpcData == &KiProcessorBlock[i]->DpcData[DPC_NORMAL]))
        {
            KiProcessorBlock[i]->DpcInterruptRequested = FALSE;
            break;
        }
    }
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
KeRemoveQueueDpc(IN PKDPC Dpc)
{
    PKDPC_DATA DpcData;
    BOOLEAN Enable, Removed = FALSE;
    ASSERT_DPC(Dpc);

    /* Disable interrupts */
    Enable = KeDisableInterrupts();

    /* Get DPC data */
    DpcData = Dpc->DpcData;
    if (DpcData)
    {
        /* Acquire the DPC lock */
        KiAcquireSpinLock(&DpcData->DpcLock);

        /* Make sure that the data didn't change */
        if (DpcData == Dpc->DpcData)
        {
            /* Remove the DPC */
            DpcData->DpcQueueDepth--;
            RemoveEntryList(&Dpc->DpcListEntry);
            Dpc->DpcData = NULL;
            Removed = TRUE;

            /* The DPC interrupt finds nothing to retire and leaves the request flag set,
               so the next KeInsertQueueDpc would not request an interrupt */
            if (DpcData->DpcQueueDepth == 0)
                KiClearDpcInterruptRequest(DpcData);
        }

        /* Release the lock */
        KiReleaseSpinLock(&DpcData->DpcLock);
    }

    /* Re-enable interrupts */
    KeRestoreInterrupts(Enable);

    /* Another processor may have dequeued it before the lock was taken */
    return Removed;
}

/*
 * @implemented
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
NTAPI
KeFlushQueuedDpcs(VOID)
{
    ULONG ProcessorIndex;
    PKPRCB TargetPrcb;

    PAGED_CODE();
    ASSERT(KeGetCurrentThread()->SystemAffinityActive == FALSE);

    /* Loop all processors */
    for (ProcessorIndex = 0; ProcessorIndex < KeNumberProcessors; ProcessorIndex++)
    {
        /* Get the target processor's PRCB */
        TargetPrcb = KiProcessorBlock[ProcessorIndex];

        /* Check if there are DPCs on either queues, or one is running: it
           left the queue before it started */
        if ((TargetPrcb->DpcData[DPC_NORMAL].DpcQueueDepth > 0) ||
            (TargetPrcb->DpcData[DPC_THREADED].DpcQueueDepth > 0) ||
            TargetPrcb->DpcRoutineActive)
        {
            /* Check if this is the current processor */
            if (TargetPrcb == KeGetCurrentPrcb())
            {
                /* Request a DPC interrupt */
                HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
            }
            else
            {
                /* Attach to the target processor. This will cause a DPC
                   interrupt on the target processor and flush all DPCs. */
                KeSetSystemAffinityThread(TargetPrcb->SetMember);
            }
        }
    }

    /* Revert back to user affinity */
    if (KeGetCurrentThread()->SystemAffinityActive)
    {
        KeRevertToUserAffinityThread();
    }
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
KeIsExecutingDpc(VOID)
{
    /* One load: a thread moved to another processor between finding its
       PRCB and reading the flag would see that processor's DPC state */
#if defined(_M_IX86)
    return __readfsbyte(FIELD_OFFSET(KIPCR, PrcbData.DpcRoutineActive)) != 0;
#elif defined(_M_AMD64)
    return __readgsbyte(FIELD_OFFSET(KIPCR, Prcb.DpcRoutineActive)) != 0;
#else
    return KeGetCurrentPrcb()->DpcRoutineActive != 0;
#endif
}

/*
 * @implemented
 */
VOID
NTAPI
KeSetImportanceDpc (IN PKDPC Dpc,
                    IN KDPC_IMPORTANCE Importance)
{
    /* Set the DPC Importance */
    ASSERT_DPC(Dpc);
    Dpc->Importance = Importance;
}

/*
 * @implemented
 */
VOID
NTAPI
KeSetTargetProcessorDpc(IN PKDPC Dpc,
                        IN CCHAR Number)
{
    /* Set a target CPU */
    ASSERT_DPC(Dpc);
    Dpc->Number = Number + MAXIMUM_PROCESSORS;
}

/*
 * @implemented
 */
VOID
NTAPI
KeGenericCallDpc(IN PKDEFERRED_ROUTINE Routine,
                 IN PVOID Context)
{
    ULONG Barrier;
    KIRQL OldIrql;
    DEFERRED_REVERSE_BARRIER ReverseBarrier;
#ifdef CONFIG_SMP
    KAFFINITY Active, Others;
    ULONG Processor;
    PKDPC Dpc;
#endif
    ASSERT(KeGetCurrentIrql () < DISPATCH_LEVEL);

#ifdef CONFIG_SMP
    /* The processors' call DPCs serve one call at a time */
    ExAcquireFastMutex(&KiGenericCallDpcMutex);
#endif
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    //
    // The barrier is the number of processors, each processor will decrement it
    // by one, so when all processors have run the DPC, the barrier reaches zero
    //
#ifdef CONFIG_SMP
    Active = KeActiveProcessors;
    for (Barrier = 0, Others = Active; Others; Others &= Others - 1) Barrier++;
#else
    Barrier = 1;
#endif
    ReverseBarrier.Barrier = Barrier;
    ReverseBarrier.TotalProcessors = Barrier;

#ifdef CONFIG_SMP
    /* Every other active processor runs the routine in its call DPC */
    Others = Active & ~KeGetCurrentPrcb()->SetMember;
    while (Others)
    {
        BitScanForwardAffinity(&Processor, Others);
        Others &= Others - 1;

        Dpc = &KiProcessorBlock[Processor]->CallDpc;
        KeInitializeDpc(Dpc, Routine, Context);
        KeSetImportanceDpc(Dpc, HighImportance);
        KeSetTargetProcessorDpc(Dpc, (CCHAR)Processor);
        KeInsertQueueDpc(Dpc, &Barrier, &ReverseBarrier);
    }
#endif

    /* This processor runs it directly, at the same IRQL */
    Routine(&KeGetCurrentPrcb()->CallDpc, Context, &Barrier, &ReverseBarrier);

#ifdef CONFIG_SMP
    /* The barrier and the reverse barrier live on this stack */
    while (*(volatile ULONG *)&Barrier != 0)
    {
        YieldProcessor();
    }
#endif

    KeLowerIrql(OldIrql);
#ifdef CONFIG_SMP
    ExReleaseFastMutex(&KiGenericCallDpcMutex);
#endif
}

/*
 * @implemented
 */
VOID
NTAPI
KeSignalCallDpcDone(IN PVOID SystemArgument1)
{
    //
    // Decrement the barrier, which is actually the processor count
    //
    InterlockedDecrement((PLONG)SystemArgument1);
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
KeSignalCallDpcSynchronize(IN PVOID SystemArgument2)
{
#ifdef CONFIG_SMP
    PDEFERRED_REVERSE_BARRIER ReverseBarrier = SystemArgument2;
    LONG Sense, Remaining;

    /* The top bit flips each time all processors have arrived, so the
       routine can synchronize more than once */
    Sense = *(volatile LONG *)&ReverseBarrier->Barrier & 0x80000000;
    Remaining = InterlockedDecrement((PLONG)&ReverseBarrier->Barrier) & 0x7FFFFFFF;
    if (Remaining == 0)
    {
        /* The last processor to arrive resets the barrier and returns TRUE */
        InterlockedExchange((PLONG)&ReverseBarrier->Barrier,
                            (Sense ^ 0x80000000) | ReverseBarrier->TotalProcessors);
        return TRUE;
    }

    while ((*(volatile LONG *)&ReverseBarrier->Barrier & 0x80000000) == Sense)
    {
        YieldProcessor();
    }

    return FALSE;
#else
    //
    // There is nothing to do on UP systems -- the processor calling this wins
    //
    UNREFERENCED_PARAMETER(SystemArgument2);
    return TRUE;
#endif
}

/* EOF */
