/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/config/cmdelay.c
 * PURPOSE:         Routines for handling delay close and allocate.
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

WORK_QUEUE_ITEM CmpDelayDerefKCBWorkItem;

ULONG CmpDelayedCloseSize = 2048;
ULONG CmpDelayedCloseElements;
KGUARDED_MUTEX CmpDelayedCloseTableLock;
BOOLEAN CmpDelayCloseWorkItemActive;
WORK_QUEUE_ITEM CmpDelayCloseWorkItem;
LIST_ENTRY CmpDelayedLRUListHead;
ULONG CmpDelayCloseIntervalInSeconds = 5;
KDPC CmpDelayCloseDpc;
KTIMER CmpDelayCloseTimer;

KGUARDED_MUTEX CmpDelayDerefKCBLock;
BOOLEAN CmpDelayDerefKCBWorkItemActive;
LIST_ENTRY CmpDelayDerefKCBListHead;
ULONG CmpDelayDerefKCBIntervalInSeconds = 5;

/*
 * The entries of CmpDelayDerefKCBListHead (changed under CmpDelayDerefKCBLock). Every queued KCB keeps its reference,
 * and with it the one it holds on its parent, until the worker runs: a queue that grows faster than the worker drains
 * it (more threads closing keys than processors) pinned parents at the 16-bit reference limit, and every create below
 * such a parent failed (STATUS_INSUFFICIENT_RESOURCES), for every caller. Above CMP_DELAY_DEREF_INLINE the handle close
 * path, which holds no KCB lock, drops its reference itself (CmpDerefKeyControlBlockOnClose), as the worker would.
 */
ULONG CmpDelayDerefKCBCount;
#define CMP_DELAY_DEREF_INLINE 1024
KDPC CmpDelayDerefKCBDpc;
KTIMER CmpDelayDerefKCBTimer;

/* FUNCTIONS *****************************************************************/

_Function_class_(KDEFERRED_ROUTINE)
VOID
NTAPI
CmpDelayCloseDpcRoutine(IN PKDPC Dpc,
                        IN PVOID DeferredContext,
                        IN PVOID SystemArgument1,
                        IN PVOID SystemArgument2)
{
    /* Sanity check */
    ASSERT(CmpDelayCloseWorkItemActive);

    /* Queue the work item */
    ExQueueWorkItem(&CmpDelayCloseWorkItem, DelayedWorkQueue);
}

_Function_class_(WORKER_THREAD_ROUTINE)
VOID
NTAPI
CmpDelayCloseWorker(IN PVOID Context)
{
    PCM_DELAYED_CLOSE_ENTRY ListEntry;
    ULONG i, ConvKey;
    PAGED_CODE();

    /* Sanity check */
    ASSERT(CmpDelayCloseWorkItemActive);

    /* Lock the registry */
    CmpLockRegistry();

    /* Acquire the delayed close table lock */
    KeAcquireGuardedMutex(&CmpDelayedCloseTableLock);

    /* Iterate */
    for (i = 0; i < (CmpDelayedCloseSize >> 2); i++)
    {
        /* Break out of the loop if there is nothing to process */
        if (CmpDelayedCloseElements <= CmpDelayedCloseSize) break;

        /* Sanity check */
        ASSERT(!IsListEmpty(&CmpDelayedLRUListHead));

        /* Get the entry */
        ListEntry = CONTAINING_RECORD(CmpDelayedLRUListHead.Blink,
                                      CM_DELAYED_CLOSE_ENTRY,
                                      DelayedLRUList);

        /* Save the ConvKey value of the KCB */
        ConvKey = ListEntry->KeyControlBlock->ConvKey;

        /* Release the delayed close table lock */
        KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);

        /* Acquire the KCB lock */
        CmpAcquireKcbLockExclusiveByKey(ConvKey);

        /* Reacquire the delayed close table lock */
        KeAcquireGuardedMutex(&CmpDelayedCloseTableLock);

        /* Get the entry */
        ListEntry = CONTAINING_RECORD(CmpDelayedLRUListHead.Blink,
                                      CM_DELAYED_CLOSE_ENTRY,
                                      DelayedLRUList);

        /* Is the entry we have still the first one? */
        if (CmpDelayedCloseElements <= CmpDelayedCloseSize)
        {
            /* No, someone already inserted an entry there */
            CmpReleaseKcbLockByKey(ConvKey);
            break;
        }

        /* Is it a different entry? */
        if (ConvKey != ListEntry->KeyControlBlock->ConvKey)
        {
            /* Release the delayed close table lock */
            KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);

            /* Release the KCB lock */
            CmpReleaseKcbLockByKey(ConvKey);

            /* Reacquire the delayed close table lock */
            KeAcquireGuardedMutex(&CmpDelayedCloseTableLock);

            /* Iterate again */
            continue;
        }

        /* Remove it from the end of the list */
        ListEntry =
            (PCM_DELAYED_CLOSE_ENTRY)RemoveTailList(&CmpDelayedLRUListHead);

        /* Get the containing entry */
        ListEntry = CONTAINING_RECORD(ListEntry,
                                      CM_DELAYED_CLOSE_ENTRY,
                                      DelayedLRUList);

        /* Process the entry */
        if ((ListEntry->KeyControlBlock->RefCount) ||
            (ListEntry->KeyControlBlock->DelayedCloseIndex))
        {
            /* Add it to the beginning of the list */
            InsertHeadList(&CmpDelayedLRUListHead, &ListEntry->DelayedLRUList);

            /* Release the delayed close table lock */
            KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);
        }
        else
        {
            /* Release the delayed close table lock */
            KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);

            /* Zero out the DelayCloseEntry pointer */
            ListEntry->KeyControlBlock->DelayCloseEntry = NULL;

            /* Cleanup the KCB cache */
            CmpCleanUpKcbCacheWithLock(ListEntry->KeyControlBlock, FALSE);

            /* Free the delay item */
            CmpFreeDelayItem(ListEntry);

            /* Decrement delayed close elements count */
            InterlockedDecrement((PLONG)&CmpDelayedCloseElements);
        }

        /* Release the KCB lock */
        CmpReleaseKcbLockByKey(ConvKey);

        /* Reacquire the delayed close table lock */
        KeAcquireGuardedMutex(&CmpDelayedCloseTableLock);
    }

    if (CmpDelayedCloseElements <= CmpDelayedCloseSize)
    {
        /* We're not active anymore */
        CmpDelayCloseWorkItemActive = FALSE;
    }
    else
    {
        /* We didn't process all things, so reschedule for the next time */
        CmpArmDelayedCloseTimer();
    }

    /* Release the delayed close table lock */
    KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);

    /* Unlock the registry */
    CmpUnlockRegistry();
}

CODE_SEG("INIT")
VOID
NTAPI
CmpInitializeDelayedCloseTable(VOID)
{

    /* Setup the delayed close lock */
    KeInitializeGuardedMutex(&CmpDelayedCloseTableLock);

    /* Setup the work item */
    ExInitializeWorkItem(&CmpDelayCloseWorkItem, CmpDelayCloseWorker, NULL);

    /* Setup the list head */
    InitializeListHead(&CmpDelayedLRUListHead);

    /* Setup the DPC and its timer */
    KeInitializeDpc(&CmpDelayCloseDpc, CmpDelayCloseDpcRoutine, NULL);
    KeInitializeTimer(&CmpDelayCloseTimer);
}

_Function_class_(KDEFERRED_ROUTINE)
VOID
NTAPI
CmpDelayDerefKCBDpcRoutine(IN PKDPC Dpc,
                           IN PVOID DeferredContext,
                           IN PVOID SystemArgument1,
                           IN PVOID SystemArgument2)
{
    /* Sanity check */
    ASSERT(CmpDelayDerefKCBWorkItemActive);

    /* Queue the work item */
    ExQueueWorkItem(&CmpDelayDerefKCBWorkItem, DelayedWorkQueue);
}

_Function_class_(WORKER_THREAD_ROUTINE)
VOID
NTAPI
CmpDelayDerefKCBWorker(IN PVOID Context)
{
    PCM_DELAY_DEREF_KCB_ITEM Entry;
    PAGED_CODE();

    /* Sanity check */
    ASSERT(CmpDelayDerefKCBWorkItemActive);

    /* Lock the registry and and list lock */
    CmpLockRegistry();
    KeAcquireGuardedMutex(&CmpDelayDerefKCBLock);

    /* Check if the list is empty */
    while (!IsListEmpty(&CmpDelayDerefKCBListHead))
    {
        /* Grab an entry */
        Entry = (PVOID)RemoveHeadList(&CmpDelayDerefKCBListHead);
        CmpDelayDerefKCBCount--;

        /* We can release the lock now */
        KeReleaseGuardedMutex(&CmpDelayDerefKCBLock);

        /* Now grab the actual entry */
        Entry = CONTAINING_RECORD(Entry, CM_DELAY_DEREF_KCB_ITEM, ListEntry);
        Entry->ListEntry.Flink = Entry->ListEntry.Blink = NULL;

        /* Dereference and free */
        CmpDereferenceKeyControlBlock(Entry->Kcb);
        CmpFreeDelayItem(Entry);

        /* Lock the list again */
        KeAcquireGuardedMutex(&CmpDelayDerefKCBLock);
    }

    /* We're done */
    CmpDelayDerefKCBWorkItemActive = FALSE;
    KeReleaseGuardedMutex(&CmpDelayDerefKCBLock);
    CmpUnlockRegistry();
}

VOID
NTAPI
CmpFlushDelayDerefKCBs(VOID)
{
    PCM_DELAY_DEREF_KCB_ITEM Entry;
    PAGED_CODE();

    /* The caller holds the registry lock exclusively, as the worker does */
    CMP_ASSERT_EXCLUSIVE_REGISTRY_LOCK();

    /* Do now what the timer would do later: release the references that are waiting to be dropped */
    KeAcquireGuardedMutex(&CmpDelayDerefKCBLock);
    while (!IsListEmpty(&CmpDelayDerefKCBListHead))
    {
        Entry = (PVOID)RemoveHeadList(&CmpDelayDerefKCBListHead);
        CmpDelayDerefKCBCount--;
        KeReleaseGuardedMutex(&CmpDelayDerefKCBLock);

        Entry = CONTAINING_RECORD(Entry, CM_DELAY_DEREF_KCB_ITEM, ListEntry);
        Entry->ListEntry.Flink = Entry->ListEntry.Blink = NULL;

        CmpDereferenceKeyControlBlock(Entry->Kcb);
        CmpFreeDelayItem(Entry);

        KeAcquireGuardedMutex(&CmpDelayDerefKCBLock);
    }
    KeReleaseGuardedMutex(&CmpDelayDerefKCBLock);
}

CODE_SEG("INIT")
VOID
NTAPI
CmpInitDelayDerefKCBEngine(VOID)
{
    /* Initialize lock and list */
    KeInitializeGuardedMutex(&CmpDelayDerefKCBLock);
    InitializeListHead(&CmpDelayDerefKCBListHead);

    /* Setup the work item */
    ExInitializeWorkItem(&CmpDelayDerefKCBWorkItem,
                         CmpDelayDerefKCBWorker,
                         NULL);

    /* Setup the DPC and timer for it */
    KeInitializeDpc(&CmpDelayDerefKCBDpc, CmpDelayDerefKCBDpcRoutine, NULL);
    KeInitializeTimer(&CmpDelayDerefKCBTimer);
}

VOID
NTAPI
CmpDelayDerefKeyControlBlock(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    LONG OldRefCount, NewRefCount;
    LARGE_INTEGER Timeout;
    PCM_DELAY_DEREF_KCB_ITEM Entry;
    PAGED_CODE();
    CMTRACE(CM_REFERENCE_DEBUG,
            "%s - Dereferencing KCB: %p\n", __FUNCTION__, Kcb);

    /* Get the previous reference count */
    OldRefCount = *(PLONG)&Kcb->RefCount;
    NewRefCount = OldRefCount - 1;
    if (((NewRefCount & 0xFFFF) > 0) &&
        (InterlockedCompareExchange((PLONG)&Kcb->RefCount,
                                    NewRefCount,
                                    OldRefCount) == OldRefCount))
    {
        /* KCB still had references, so we're done */
        return;
    }

    /* Allocate a delay item */
    Entry = CmpAllocateDelayItem();
    if (!Entry) return;

    /* Set the KCB */
    Entry->Kcb = Kcb;

    /* Acquire the delayed deref table lock */
    KeAcquireGuardedMutex(&CmpDelayDerefKCBLock);

    /* Insert the entry into the list */
    InsertTailList(&CmpDelayDerefKCBListHead, &Entry->ListEntry);
    CmpDelayDerefKCBCount++;

    /* Check if we need to enable anything */
    if (!CmpDelayDerefKCBWorkItemActive)
    {
        /* Yes, we have no work item, setup the interval */
        CmpDelayDerefKCBWorkItemActive = TRUE;
        Timeout.QuadPart = -(LONGLONG)CmpDelayDerefKCBIntervalInSeconds * 10 * 1000 * 1000;
        KeSetTimer(&CmpDelayDerefKCBTimer, Timeout, &CmpDelayDerefKCBDpc);
    }

    /* Release the table lock */
    KeReleaseGuardedMutex(&CmpDelayDerefKCBLock);
}

/*
 * The reference of a key body that goes away (CmpDeleteKeyObject: the registry lock held shared, the context the worker
 * dereferences in). Queued as before while the queue is short; dropped here when it is long (CMP_DELAY_DEREF_INLINE
 * entries or more), so the queue, and the references it pins, stay bounded however many threads close keys. Always
 * queued when the caller holds the KCB's lock (KcbLocked: an open whose access check failed drops its body inside the
 * parse), since the last dereference takes that lock. The count is read without the lock: a bound, not an exact limit.
 */
VOID
NTAPI
CmpDerefKeyControlBlockOnClose(IN PCM_KEY_CONTROL_BLOCK Kcb,
                               IN BOOLEAN KcbLocked)
{
    PAGED_CODE();

    if (!KcbLocked && *(volatile ULONG *)&CmpDelayDerefKCBCount >= CMP_DELAY_DEREF_INLINE)
    {
        static LONG Reported;

        /* Once per boot: the queue reached its bound (a sign of a key create/close storm) */
        if (!InterlockedExchange(&Reported, 1))
            DPRINT1("CM: %lu delayed KCB dereferences queued: closing handles dereference inline\n", CmpDelayDerefKCBCount);
        CmpDereferenceKeyControlBlock(Kcb);
        return;
    }
    CmpDelayDerefKeyControlBlock(Kcb);
}

VOID
NTAPI
CmpArmDelayedCloseTimer(VOID)
{
    LARGE_INTEGER Timeout;
    PAGED_CODE();

    /* Set the worker active */
    CmpDelayCloseWorkItemActive = TRUE;

    /* Setup the interval: a relative time, in negative 100 ns units. The product of the unsigned number of seconds
       and a negative constant is an unsigned 32-bit number, a positive absolute time long in the past, and the timer
       expired at once: the worker, which arms the timer again while the table is over its limit, then ran back to
       back, a DPC and a work item many thousand times a second */
    Timeout.QuadPart = -(LONGLONG)CmpDelayCloseIntervalInSeconds * 10 * 1000 * 1000;
    KeSetTimer(&CmpDelayCloseTimer, Timeout, &CmpDelayCloseDpc);
}

VOID
NTAPI
CmpAddToDelayedClose(IN PCM_KEY_CONTROL_BLOCK Kcb,
                     IN BOOLEAN LockHeldExclusively)
{
    ULONG i;
    ULONG OldRefCount, NewRefCount;
    PCM_DELAYED_CLOSE_ENTRY Entry;
    PAGED_CODE();

    /* Sanity check */
    CMP_ASSERT_KCB_LOCK(Kcb);

    /* Make sure it's valid */
    if (Kcb->DelayedCloseIndex != CmpDelayedCloseSize) ASSERT(FALSE);

    /* Sanity checks */
    ASSERT(Kcb->RefCount == 0);
    ASSERT(IsListEmpty(&Kcb->KeyBodyListHead) == TRUE);
    for (i = 0; i < 4; i++) ASSERT(Kcb->KeyBodyArray[i] == NULL);

    /* Allocate a delay item */
    Entry = CmpAllocateDelayItem();
    if (!Entry)
    {
        /* Cleanup immediately */
        CmpCleanUpKcbCacheWithLock(Kcb, LockHeldExclusively);
        return;
    }

    /* Sanity check */
    if (Kcb->InDelayClose) ASSERT(FALSE);

    /* Get the previous reference count */
    OldRefCount = *(PLONG)&Kcb->InDelayClose;
    ASSERT(OldRefCount == 0);

    /* Write the new one */
    NewRefCount = 1;
    if (InterlockedCompareExchange((PLONG)&Kcb->InDelayClose,
                                   NewRefCount,
                                   OldRefCount) != OldRefCount)
    {
        /* Sanity check */
        ASSERT(FALSE);
    }

    /* Reset the delayed close index */
    Kcb->DelayedCloseIndex = 0;

    /* Set up the close entry */
    Kcb->DelayCloseEntry = Entry;
    Entry->KeyControlBlock = Kcb;

    /* Increase the number of elements */
    InterlockedIncrement((PLONG)&CmpDelayedCloseElements);

    /* Acquire the delayed close table lock */
    KeAcquireGuardedMutex(&CmpDelayedCloseTableLock);

    /* Insert the entry into the list */
    InsertHeadList(&CmpDelayedLRUListHead, &Entry->DelayedLRUList);

    /* Check if we need to enable anything */
    if ((CmpDelayedCloseElements > CmpDelayedCloseSize) &&
        !(CmpDelayCloseWorkItemActive))
    {
        /* Yes, we have too many elements to close, and no work item */
        CmpArmDelayedCloseTimer();
    }

    /* Release the table lock */
    KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);
}

VOID
NTAPI
CmpRemoveFromDelayedClose(IN PCM_KEY_CONTROL_BLOCK Kcb)
{
    PCM_DELAYED_CLOSE_ENTRY Entry;
    ULONG NewRefCount, OldRefCount;
    PAGED_CODE();

    /* Sanity checks */
    CMP_ASSERT_KCB_LOCK(Kcb);
    if (Kcb->DelayedCloseIndex == CmpDelayedCloseSize) ASSERT(FALSE);

    /* Get the entry and lock the table */
    Entry = Kcb->DelayCloseEntry;
    ASSERT(Entry);
    KeAcquireGuardedMutex(&CmpDelayedCloseTableLock);

    /* Remove the entry */
    RemoveEntryList(&Entry->DelayedLRUList);

    /* Release the lock */
    KeReleaseGuardedMutex(&CmpDelayedCloseTableLock);

    /* Free the entry */
    CmpFreeDelayItem(Entry);

    /* Reduce the number of elements */
    InterlockedDecrement((PLONG)&CmpDelayedCloseElements);

    /* Sanity check */
    if (!Kcb->InDelayClose) ASSERT(FALSE);

    /* Get the previous reference count */
    OldRefCount = *(PLONG)&Kcb->InDelayClose;
    ASSERT(OldRefCount == 1);

    /* Write the new one */
    NewRefCount = 0;
    if (InterlockedCompareExchange((PLONG)&Kcb->InDelayClose,
                                   NewRefCount,
                                   OldRefCount) != OldRefCount)
    {
        /* Sanity check */
        ASSERT(FALSE);
    }

    /* Remove the link to the entry */
    Kcb->DelayCloseEntry = NULL;

    /* Set new delay size and remove the delete flag */
    Kcb->DelayedCloseIndex = CmpDelayedCloseSize;
}
