/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/queue.c
 * PURPOSE:         Implements kernel queues
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Gunnar Dalsnes
 *                  Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* PRIVATE FUNCTIONS *********************************************************/

/*
 * Called when a thread which has a queue entry is entering a wait state
 */
VOID
FASTCALL
KiActivateWaiterQueue(IN PKQUEUE Queue)
{
    PLIST_ENTRY QueueEntry;
    PLIST_ENTRY WaitEntry;
    PKWAIT_BLOCK WaitBlock;
    PKTHREAD Thread;
    ASSERT_QUEUE(Queue);

    /* Decrement the number of active threads */
    Queue->CurrentCount--;

    /* Make sure the counts are OK */
    if (Queue->CurrentCount < Queue->MaximumCount)
    {
        /* Get the Queue Entry */
        QueueEntry = Queue->EntryListHead.Flink;

        /* Get the Wait Entry */
        WaitEntry = Queue->Header.WaitListHead.Blink;

        /* Make sure that the Queue entries are not part of empty lists */
        if ((WaitEntry != &Queue->Header.WaitListHead) &&
            (QueueEntry != &Queue->EntryListHead))
        {
            /* Remove this entry */
            RemoveEntryList(QueueEntry);
            QueueEntry->Flink = NULL;

            /* Decrease the Signal State */
            Queue->Header.SignalState--;

            /* Unwait the Thread */
            WaitBlock = CONTAINING_RECORD(WaitEntry,
                                          KWAIT_BLOCK,
                                          WaitListEntry);
            Thread = WaitBlock->Thread;
            KiUnwaitThread(Thread, (LONG_PTR)QueueEntry, IO_NO_INCREMENT);
        }
    }
}

/*
 * Returns the previous number of entries in the queue
 */
LONG
NTAPI
KiInsertQueue(IN PKQUEUE Queue,
              IN PLIST_ENTRY Entry,
              IN BOOLEAN Head)
{
    ULONG InitialState;
    PKTHREAD Thread = KeGetCurrentThread();
    PKWAIT_BLOCK WaitBlock;
    PLIST_ENTRY WaitEntry;
    PKTIMER Timer;
    ASSERT_QUEUE(Queue);

    /* Save the old state */
    InitialState = Queue->Header.SignalState;

    /* Get the Entry */
    WaitEntry = Queue->Header.WaitListHead.Blink;

    /*
     * Why the KeGetCurrentThread()->Queue != Queue?
     * KiInsertQueue might be called from an APC for the current thread.
     * -Gunnar
     */
    if ((Queue->CurrentCount < Queue->MaximumCount) &&
        (WaitEntry != &Queue->Header.WaitListHead) &&
        ((Thread->Queue != Queue) ||
         (Thread->WaitReason != WrQueue)))
    {
        /* Remove the wait entry */
        RemoveEntryList(WaitEntry);

        /* Get the Wait Block and Thread */
        WaitBlock = CONTAINING_RECORD(WaitEntry, KWAIT_BLOCK, WaitListEntry);
        Thread = WaitBlock->Thread;

        /* Remove the queue from the thread's wait list */
        Thread->WaitStatus = (LONG_PTR)Entry;
        if (Thread->WaitListEntry.Flink) RemoveEntryList(&Thread->WaitListEntry);

        /* Increase the active threads and remove any wait reason */
        Queue->CurrentCount++;
        Thread->WaitReason = 0;

        /* Check if there's a Thread Timer */
        Timer = &Thread->Timer;
        if (Timer->Header.Inserted) KxRemoveTreeTimer(Timer);

        /* Reschedule the Thread */
        KiReadyThread(Thread);
    }
    else
    {
        /* Increase the Entries */
        Queue->Header.SignalState++;

        /* Check which mode we're using */
        if (Head)
        {
            /* Insert in the head */
            InsertHeadList(&Queue->EntryListHead, Entry);
        }
        else
        {
            /* Insert at the end */
            InsertTailList(&Queue->EntryListHead, Entry);
        }
    }

    /* Return the previous state */
    return InitialState;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
VOID
NTAPI
KeInitializeQueue(IN PKQUEUE Queue,
                  IN ULONG Count OPTIONAL)
{
    /* Initialize the Header */
    Queue->Header.Type = QueueObject;
    Queue->Header.Abandoned = 0;
    Queue->Header.Size = sizeof(KQUEUE) / sizeof(ULONG);
    Queue->Header.SignalState = 0;
    InitializeListHead(&(Queue->Header.WaitListHead));

    /* Initialize the Lists */
    InitializeListHead(&Queue->EntryListHead);
    InitializeListHead(&Queue->ThreadListHead);

    /* Set the Current and Maximum Count */
    Queue->CurrentCount = 0;
    Queue->MaximumCount = (Count == 0) ? (ULONG) KeNumberProcessors : Count;
}

/*
 * @implemented
 */
LONG
NTAPI
KeInsertHeadQueue(IN PKQUEUE Queue,
                  IN PLIST_ENTRY Entry)
{
    LONG PreviousState;
    KIRQL OldIrql;
    ASSERT_QUEUE(Queue);
    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);

    /* Lock the Dispatcher Database */
    OldIrql = KiAcquireDispatcherLock();

    /* Insert the Queue */
    PreviousState = KiInsertQueue(Queue, Entry, TRUE);

    /* Release the Dispatcher Lock */
    KiReleaseDispatcherLock(OldIrql);

    /* Return previous State */
    return PreviousState;
}

/*
 * @implemented
 */
LONG
NTAPI
KeInsertQueue(IN PKQUEUE Queue,
              IN PLIST_ENTRY Entry)
{
    LONG PreviousState;
    KIRQL OldIrql;
    ASSERT_QUEUE(Queue);
    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);

    /* Lock the Dispatcher Database */
    OldIrql = KiAcquireDispatcherLock();

    /* Insert the Queue */
    PreviousState = KiInsertQueue(Queue, Entry, FALSE);

    /* Release the Dispatcher Lock */
    KiReleaseDispatcherLock(OldIrql);

    /* Return previous State */
    return PreviousState;
}

/*
 * @implemented
 *
 * Returns number of entries in the queue
 */
LONG
NTAPI
KeReadStateQueue(IN PKQUEUE Queue)
{
    /* Returns the Signal State */
    ASSERT_QUEUE(Queue);
    return Queue->Header.SignalState;
}

/*
 * Removes up to Count entries from the queue, waiting for the first one.
 * Returns the number of entries written to EntryArray. When the wait ends
 * without an entry, returns 1 and stores the wait status (STATUS_TIMEOUT,
 * STATUS_USER_APC or STATUS_ALERTED) cast to PLIST_ENTRY in EntryArray[0],
 * the same convention KeRemoveQueue uses for its return value.
 *
 * @implemented
 */
ULONG
NTAPI
KeRemoveQueueEx(IN PKQUEUE Queue,
                IN KPROCESSOR_MODE WaitMode,
                IN BOOLEAN Alertable,
                IN PLARGE_INTEGER Timeout OPTIONAL,
                OUT PLIST_ENTRY *EntryArray,
                IN ULONG Count)
{
    PLIST_ENTRY QueueEntry;
    ULONG Removed = 0;
    NTSTATUS WaitStatus;
    LONG_PTR Status;
    PKTHREAD Thread = KeGetCurrentThread();
    PKQUEUE PreviousQueue;
    PKWAIT_BLOCK WaitBlock = &Thread->WaitBlock[0];
    PKWAIT_BLOCK TimerBlock = &Thread->WaitBlock[TIMER_WAIT_BLOCK];
    PKTIMER Timer = &Thread->Timer;
    BOOLEAN Swappable;
    PLARGE_INTEGER OriginalDueTime = Timeout;
    LARGE_INTEGER DueTime = {{0}}, NewDueTime, InterruptTime;
    ULONG Hand = 0;
    ASSERT_QUEUE(Queue);
    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);
    ASSERT(Count != 0);

    /* Check if the Lock is already held */
    if (Thread->WaitNext)
    {
        /* It is, so next time don't do expect this */
        Thread->WaitNext = FALSE;
        KxQueueThreadWait();
    }
    else
    {
        /* Raise IRQL to synch, prepare the wait, then lock the database */
        Thread->WaitIrql = KeRaiseIrqlToSynchLevel();
        KxQueueThreadWait();
        KiAcquireDispatcherLockAtSynchLevel();
    }

    /* Set the alertability of the wait prepared above */
    Thread->Alertable = Alertable;

    /*
     * An alertable caller that is not yet associated with this queue gets its
     * pending user APCs or alerts first, and is not associated with the queue.
     */
    if ((Alertable) && (Thread->Queue != Queue))
    {
        WaitStatus = KiCheckAlertability(Thread, Alertable, WaitMode);
        if (WaitStatus != STATUS_WAIT_0)
        {
            KiReleaseDispatcherLockFromSynchLevel();
            KiExitDispatcher(Thread->WaitIrql);
            EntryArray[0] = (PLIST_ENTRY)(LONG_PTR)WaitStatus;
            return 1;
        }
    }

    /*
     * This is needed so that we can set the new queue right here,
     * before additional processing
     */
    PreviousQueue = Thread->Queue;
    Thread->Queue = Queue;

    /* Check if this is a different queue */
    if (Queue != PreviousQueue)
    {
        /* Get the current entry */
        QueueEntry = &Thread->QueueListEntry;
        if (PreviousQueue)
        {
            /* Remove from this list */
            RemoveEntryList(QueueEntry);

            /* Wake the queue */
            KiActivateWaiterQueue(PreviousQueue);
        }

        /* Insert in this new Queue */
        InsertTailList(&Queue->ThreadListHead, QueueEntry);
    }
    else
    {
        /* Same queue, decrement waiting threads */
        Queue->CurrentCount--;
    }

    /* Loop until the queue is processed */
    while (TRUE)
    {
        /* Check if the counts are valid and if there is still a queued entry */
        QueueEntry = Queue->EntryListHead.Flink;
        if ((Queue->CurrentCount < Queue->MaximumCount) &&
            (QueueEntry != &Queue->EntryListHead))
        {
            /* Decrease the number of entries */
            Queue->Header.SignalState--;

            /* Increase numbef of running threads */
            Queue->CurrentCount++;

            /* Check if the entry is valid. If not, bugcheck */
            if (!(QueueEntry->Flink) || !(QueueEntry->Blink))
            {
                /* Invalid item */
                KeBugCheckEx(INVALID_WORK_QUEUE_ITEM,
                             (ULONG_PTR)QueueEntry,
                             (ULONG_PTR)Queue,
                             (ULONG_PTR)NULL,
                             (ULONG_PTR)((PWORK_QUEUE_ITEM)QueueEntry)->
                                         WorkerRoutine);
            }

            /* Remove the Entry */
            RemoveEntryList(QueueEntry);
            QueueEntry->Flink = NULL;
            EntryArray[Removed++] = QueueEntry;

            /* Take whatever else is already queued, this thread is already counted as running */
            while ((Removed < Count) &&
                   (Queue->EntryListHead.Flink != &Queue->EntryListHead))
            {
                QueueEntry = Queue->EntryListHead.Flink;
                if (!(QueueEntry->Flink) || !(QueueEntry->Blink))
                {
                    KeBugCheckEx(INVALID_WORK_QUEUE_ITEM,
                                 (ULONG_PTR)QueueEntry,
                                 (ULONG_PTR)Queue,
                                 (ULONG_PTR)NULL,
                                 (ULONG_PTR)((PWORK_QUEUE_ITEM)QueueEntry)->
                                             WorkerRoutine);
                }
                Queue->Header.SignalState--;
                RemoveEntryList(QueueEntry);
                QueueEntry->Flink = NULL;
                EntryArray[Removed++] = QueueEntry;
            }

            /* Nothing to wait on */
            break;
        }
        else
        {
            /* Check if a kernel APC is pending and we're below APC_LEVEL */
            if ((Thread->ApcState.KernelApcPending) &&
                !(Thread->SpecialApcDisable) && (Thread->WaitIrql < APC_LEVEL))
            {
                /* Increment the count and unlock the dispatcher */
                Queue->CurrentCount++;
                KiReleaseDispatcherLockFromSynchLevel();
                KiExitDispatcher(Thread->WaitIrql);
            }
            else
            {
                /* Fail if there's a User APC pending, or an alert for an alertable wait */
                WaitStatus = KiCheckAlertability(Thread, Alertable, WaitMode);
                if (WaitStatus != STATUS_WAIT_0)
                {
                    /* Return the status and increase the pending threads */
                    QueueEntry = (PLIST_ENTRY)(LONG_PTR)WaitStatus;
                    Queue->CurrentCount++;
                    break;
                }

                /* Enable the Timeout Timer if there was any specified */
                if (Timeout)
                {
                    /* Check if the timer expired */
                    InterruptTime.QuadPart = KeQueryInterruptTime();
                    if ((ULONG64)InterruptTime.QuadPart >= Timer->DueTime.QuadPart)
                    {
                        /* It did, so we don't need to wait */
                        QueueEntry = (PLIST_ENTRY)STATUS_TIMEOUT;
                        Queue->CurrentCount++;
                        break;
                    }

                    /* It didn't, so activate it */
                    Timer->Header.Inserted = TRUE;
                }

                /* Insert the wait block in the list */
                InsertTailList(&Queue->Header.WaitListHead,
                               &WaitBlock->WaitListEntry);

                /* Setup the wait information */
                Thread->State = Waiting;

                /* Add the thread to the wait list */
                KiAddThreadToWaitList(Thread, Swappable);

                /* Activate thread swap */
                ASSERT(Thread->WaitIrql <= DISPATCH_LEVEL);
                KiSetThreadSwapBusy(Thread);

                /* Check if we have a timer */
                if (Timeout)
                {
                    /* Insert it */
                    KxInsertTimer(Timer, Hand);
                }
                else
                {
                    /* Otherwise, unlock the dispatcher */
                    KiReleaseDispatcherLockFromSynchLevel();
                }

                /* Do the actual swap */
                Status = KiSwapThread(Thread, KeGetCurrentPrcb());

                /* Reset the wait reason */
                Thread->WaitReason = 0;

                /* Check if we were executing an APC */
                if (Status != STATUS_KERNEL_APC)
                {
                    EntryArray[0] = (PLIST_ENTRY)Status;
                    return 1;
                }

                /* Check if we had a timeout */
                if (Timeout)
                {
                    /* Recalculate due times */
                    Timeout = KiRecalculateDueTime(OriginalDueTime,
                                                   &DueTime,
                                                   &NewDueTime);
                }
            }

            /* Start another wait */
            Thread->WaitIrql = KeRaiseIrqlToSynchLevel();
            KxQueueThreadWait();
            Thread->Alertable = Alertable;
            KiAcquireDispatcherLockAtSynchLevel();
            Queue->CurrentCount--;
        }
    }

    /* Unlock Database and return */
    KiReleaseDispatcherLockFromSynchLevel();
    KiExitDispatcher(Thread->WaitIrql);
    if (Removed == 0)
    {
        /* The wait ended without an entry, QueueEntry holds the status */
        EntryArray[0] = QueueEntry;
        Removed = 1;
    }
    return Removed;
}

/*
 * @implemented
 */
PLIST_ENTRY
NTAPI
KeRemoveQueue(IN PKQUEUE Queue,
              IN KPROCESSOR_MODE WaitMode,
              IN PLARGE_INTEGER Timeout OPTIONAL)
{
    PLIST_ENTRY QueueEntry;

    KeRemoveQueueEx(Queue, WaitMode, FALSE, Timeout, &QueueEntry, 1);
    return QueueEntry;
}

/*
 * Wait packets (declared in ke.h): the kernel half of wait completion packets. A KWAIT_PACKET is a wait block of
 * type KI_WAIT_PACKET that no thread owns. Armed, it is linked into one dispatcher object's wait list, at the tail
 * like any new waiter. Whoever signals the object walks that list under the dispatcher lock (KiWaitTest,
 * KxUnwaitThread, KxUnwaitThreadForEvent, KeSetEventBoostPriority); at a wait packet it calls KiSignalWaitPacket,
 * which satisfies the wait as a WaitAny waiter's would be satisfied (an auto-reset event or timer is reset, a
 * semaphore count taken, a notification object left signalled), unlinks the block and inserts the packet's entry
 * into its queue with KiInsertQueue. The dispatcher lock is the only lock taken on that path: KiInsertQueue is the
 * dispatcher-lock-held half of KeInsertQueue (it may ready a thread waiting on the queue, as an unwait readies a
 * waiter), so no lock order changes and nothing has to be deferred. The packet's state is protected by the
 * dispatcher lock too, so arming (test the signal state, then consume or link), signalling, cancelling and taking
 * the entry back out of the queue are each atomic against the others.
 *
 * The entry's Flink tells whether it is still in the queue's entry list: it is NULL from the moment it is queued
 * until KiInsertQueue links it, and every removal from the list (KeRemoveQueueEx, KiActivateWaiterQueue,
 * KeCancelWaitPacket) sets it to NULL again. KiInsertQueue may also hand it straight to a waiting thread, in which
 * case it was never linked.
 */
VOID
NTAPI
KeInitializeWaitPacket(OUT PKWAIT_PACKET Packet,
                       IN PLIST_ENTRY QueueEntry)
{
    RtlZeroMemory(Packet, sizeof(*Packet));
    Packet->WaitBlock.WaitType = KI_WAIT_PACKET;
    Packet->WaitBlock.NextWaitBlock = &Packet->WaitBlock;
    Packet->QueueEntry = QueueEntry;
    Packet->State = KWaitPacketIdle;
}

/* The object was signalled for the packet: its entry goes to the queue. Dispatcher lock held. */
FORCEINLINE
VOID
KiQueueWaitPacket(IN PKWAIT_PACKET Packet)
{
    Packet->State = KWaitPacketQueued;
    Packet->QueueEntry->Flink = NULL;
    Packet->QueueEntry->Blink = NULL;
    KiInsertQueue(Packet->Queue, Packet->QueueEntry, FALSE);
}

/*
 * Called by the signal paths for a KI_WAIT_PACKET block of a signalled object, with the dispatcher lock held:
 * satisfy the wait (consume the object as a WaitAny wait does) and queue the packet.
 */
VOID
FASTCALL
KiSignalWaitPacket(IN PKWAIT_BLOCK WaitBlock)
{
    PKWAIT_PACKET Packet = CONTAINING_RECORD(WaitBlock, KWAIT_PACKET, WaitBlock);
    PKEVENT Object = WaitBlock->Object;

    ASSERT(WaitBlock->WaitType == KI_WAIT_PACKET);
    ASSERT(Packet->State == KWaitPacketArmed);
    ASSERT(Object->Header.Type != MutantObject);
    ASSERT(Object->Header.SignalState > 0);

    RemoveEntryList(&WaitBlock->WaitListEntry);
    KiSatisfyNonMutantWait(Object);
    KiQueueWaitPacket(Packet);
}

/*
 * Arms an idle packet on a dispatcher object (not a mutant: its ownership needs a thread) and a queue. If the object
 * is signalled the wait is satisfied at once and the entry queued (returns TRUE); otherwise the packet waits.
 */
BOOLEAN
NTAPI
KeArmWaitPacket(IN OUT PKWAIT_PACKET Packet,
                IN PVOID Object,
                IN PKQUEUE Queue)
{
    PKEVENT Header = Object;
    BOOLEAN Signaled;
    KIRQL OldIrql;
    ASSERT_QUEUE(Queue);
    ASSERT(Header->Header.Type != MutantObject);
    ASSERT_IRQL_LESS_OR_EQUAL(APC_LEVEL);

    OldIrql = KiAcquireDispatcherLock();
    ASSERT(Packet->State == KWaitPacketIdle);
    Packet->Queue = Queue;
    Packet->WaitBlock.Object = Object;
    if (Header->Header.SignalState > 0)
    {
        KiSatisfyNonMutantWait(Header);
        KiQueueWaitPacket(Packet);
        Signaled = TRUE;
    }
    else
    {
        Packet->State = KWaitPacketArmed;
        InsertTailList(&Header->Header.WaitListHead, &Packet->WaitBlock.WaitListEntry);
        Signaled = FALSE;
    }
    KiReleaseDispatcherLock(OldIrql);
    return Signaled;
}

/*
 * Cancels a packet. STATUS_CANCELLED: it was idle. STATUS_SUCCESS: it was waiting, or queued and still in the queue
 * with RemoveQueued (the entry is taken back out); it is idle now and the object was not consumed for it.
 * STATUS_PENDING: it was queued and stays so (RemoveQueued FALSE, or a consumer has already taken the entry and will
 * call KeWaitPacketDequeued).
 */
NTSTATUS
NTAPI
KeCancelWaitPacket(IN OUT PKWAIT_PACKET Packet,
                   IN BOOLEAN RemoveQueued)
{
    NTSTATUS Status;
    KIRQL OldIrql;
    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);

    OldIrql = KiAcquireDispatcherLock();
    switch (Packet->State)
    {
        case KWaitPacketArmed:
            RemoveEntryList(&Packet->WaitBlock.WaitListEntry);
            Packet->State = KWaitPacketIdle;
            Status = STATUS_SUCCESS;
            break;

        case KWaitPacketQueued:
            if (RemoveQueued && Packet->QueueEntry->Flink)
            {
                RemoveEntryList(Packet->QueueEntry);
                Packet->QueueEntry->Flink = NULL;
                Packet->Queue->Header.SignalState--;
                Packet->State = KWaitPacketIdle;
                Status = STATUS_SUCCESS;
            }
            else
            {
                Status = STATUS_PENDING;
            }
            break;

        default:
            Status = STATUS_CANCELLED;
            break;
    }
    KiReleaseDispatcherLock(OldIrql);
    return Status;
}

/* A consumer removed the packet's entry from the queue: the packet is idle again */
VOID
NTAPI
KeWaitPacketDequeued(IN OUT PKWAIT_PACKET Packet)
{
    KIRQL OldIrql;

    OldIrql = KiAcquireDispatcherLock();
    ASSERT(Packet->State == KWaitPacketQueued);
    ASSERT(Packet->QueueEntry->Flink == NULL);
    Packet->State = KWaitPacketIdle;
    KiReleaseDispatcherLock(OldIrql);
}

BOOLEAN
NTAPI
KeIsWaitPacketIdle(IN PKWAIT_PACKET Packet)
{
    BOOLEAN Idle;
    KIRQL OldIrql;

    OldIrql = KiAcquireDispatcherLock();
    Idle = (Packet->State == KWaitPacketIdle);
    KiReleaseDispatcherLock(OldIrql);
    return Idle;
}

/*
 * @implemented
 */
PLIST_ENTRY
NTAPI
KeRundownQueue(IN PKQUEUE Queue)
{
    PLIST_ENTRY FirstEntry, NextEntry;
    PKTHREAD Thread;
    KIRQL OldIrql;
    ASSERT_QUEUE(Queue);
    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);
    ASSERT(IsListEmpty(&Queue->Header.WaitListHead));

    /* Get the Dispatcher Lock */
    OldIrql = KiAcquireDispatcherLock();

    /* Check if the list is empty */
    FirstEntry = Queue->EntryListHead.Flink;
    if (FirstEntry == &Queue->EntryListHead)
    {
        /* We won't return anything */
        FirstEntry = NULL;
    }
    else
    {
        /* Remove this entry */
        RemoveEntryList(&Queue->EntryListHead);
    }

    /* Loop the list */
    while (!IsListEmpty(&Queue->ThreadListHead))
    {
        /* Get the next entry */
        NextEntry = Queue->ThreadListHead.Flink;

        /* Get the associated thread */
        Thread = CONTAINING_RECORD(NextEntry, KTHREAD, QueueListEntry);

        /* Clear its queue */
        Thread->Queue = NULL;

        /* Remove this entry */
        RemoveEntryList(NextEntry);
    }

    /* Release the dispatcher lock */
    KiReleaseDispatcherLockFromSynchLevel();

    /* Exit the dispatcher and return the first entry (if any) */
    KiExitDispatcher(OldIrql);
    return FirstEntry;
}

/* EOF */
