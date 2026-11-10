/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/lazywrite.c
 * PURPOSE:         Cache manager
 *
 * PROGRAMMERS:     Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* Counters:
 * - Amount of pages flushed by lazy writer
 * - Number of times lazy writer ran
 */
ULONG CcLazyWritePages = 0;
ULONG CcLazyWriteIos = 0;

/* Internal vars (MS):
 * - Lazy writer status structure
 * - Lookaside list where to allocate work items
 * - Queue for high priority work items (read ahead)
 * - Queue for regular work items
 * - Available worker threads
 * - Queue for stuff to be queued after lazy writer is done
 * - Marker for throttling queues
 * - Number of ongoing workers
 * - Three seconds delay for lazy writer
 * - One second delay for lazy writer
 * - Zero delay for lazy writer
 * - Number of worker threads
 */
LAZY_WRITER LazyWriter;
/*
 * Write-behind runs queued or running: a scan does not queue more than CcWriteBehindMax (counted up by CcLazyWriteScan,
 * down by CcWriteBehind).  One at a time normally; two when much dirty data is waiting: the disk was idle for the part of
 * each request that the writer spends on the set-up and the completion of the request, and with two runs writing different
 * parts of a stream (NTFS-NG orders those transfers itself) the next request is on its way while the last one is on the disk.
 */
#define CC_WRITEBEHIND_RUNS 2
static volatile LONG CcWriteBehindPending = 0;
NPAGED_LOOKASIDE_LIST CcTwilightLookasideList;
LIST_ENTRY CcExpressWorkQueue;
LIST_ENTRY CcRegularWorkQueue;
LIST_ENTRY CcIdleWorkerThreadList;
LIST_ENTRY CcPostTickWorkQueue;
BOOLEAN CcQueueThrottle = FALSE;
ULONG CcNumberActiveWorkerThreads = 0;
LARGE_INTEGER CcFirstDelay = RTL_CONSTANT_LARGE_INTEGER((LONGLONG)-1*3000*1000*10);
LARGE_INTEGER CcIdleDelay = RTL_CONSTANT_LARGE_INTEGER((LONGLONG)-1*1000*1000*10);
LARGE_INTEGER CcNoDelay = RTL_CONSTANT_LARGE_INTEGER((LONGLONG)0);
ULONG CcNumberWorkerThreads;

/* FUNCTIONS *****************************************************************/

VOID
CcPostWorkQueue(
    IN PWORK_QUEUE_ENTRY WorkItem,
    IN PLIST_ENTRY WorkQueue)
{
    KIRQL OldIrql;
    PWORK_QUEUE_ITEM ThreadToSpawn;

    /* First of all, insert the item in the queue */
    OldIrql = KeAcquireQueuedSpinLock(LockQueueWorkQueueLock);
    InsertTailList(WorkQueue, &WorkItem->WorkQueueLinks);

    /* Now, define whether we have to spawn a new work thread
     * We will spawn a new one if:
     * - There's no throttle in action
     * - There's still at least one idle thread
     */
    ThreadToSpawn = NULL;
    if (!CcQueueThrottle && !IsListEmpty(&CcIdleWorkerThreadList))
    {
        PLIST_ENTRY ListEntry;

        /* Get the idle thread */
        ListEntry = RemoveHeadList(&CcIdleWorkerThreadList);
        ThreadToSpawn = CONTAINING_RECORD(ListEntry, WORK_QUEUE_ITEM, List);

        /* We're going to have one more! */
        CcNumberActiveWorkerThreads += 1;
    }

    KeReleaseQueuedSpinLock(LockQueueWorkQueueLock, OldIrql);

    /* If we have a thread to spawn, do it! */
    if (ThreadToSpawn != NULL)
    {
        /* We NULLify it to be consistent with initialization */
        ThreadToSpawn->List.Flink = NULL;
        ExQueueWorkItem(ThreadToSpawn, CriticalWorkQueue);
    }
}

VOID
NTAPI
CcScanDpc(
    IN PKDPC Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2)
{
    PWORK_QUEUE_ENTRY WorkItem;

    /* Allocate a work item */
    WorkItem = ExAllocateFromNPagedLookasideList(&CcTwilightLookasideList);
    if (WorkItem == NULL)
    {
        LazyWriter.ScanActive = FALSE;
        return;
    }

    /* And post it, it will be for lazy write */
    WorkItem->Function = LazyScan;
    CcPostWorkQueue(WorkItem, &CcRegularWorkQueue);
}

/*
 * Streaming write-behind: dirty data beyond a few megabytes is not left to the one-eighth-a-second scans (or
 * to the first scan, three seconds after the first dirty page): a writer that produces more than that starts a
 * run at once, and the run brings the cache down to the low mark, so the disk is busy while the writer runs and
 * the data that is left for a flush at the end is small.  Both marks are at most a quarter / an eighth of the
 * threshold at which writers are throttled, where Mm starts pacing page requests (MmRequestPageMemoryConsumer).
 */
#define CC_STREAM_START_PAGES (32 * 1024 * 1024 / PAGE_SIZE)
#define CC_STREAM_LOW_PAGES   (16 * 1024 * 1024 / PAGE_SIZE)
#define CC_STREAM_FILE_PAGES  (1024 * 1024 / PAGE_SIZE)     /* dirty data of one file that makes a writer a stream */
static volatile LONG CcStreamingKicked = 0;

static
ULONG
CcpDirtyPageTarget(VOID)
{
    return min(CcDirtyPageThreshold / 8, (ULONG)CC_STREAM_LOW_PAGES);
}

/*
 * The lazy writer leaves dirty data alone that is younger than CC_LAZY_MIN_AGE (the first scan comes three seconds after
 * the first dirty page anyway): files created, read back and deleted within that time are never written, and a writer of
 * many small files does not share the volume with the lazy writer.  Not under pressure: a stream (a writer that makes
 * much dirty data of one file), writers paced by the amount of dirty data (a quarter of the throttle threshold), or
 * closed files waiting in numbers that near the limit past which a close writes its data itself.  Master lock held.
 */
BOOLEAN
CcLazyUnderPressure(VOID)
{
    return CcStreamingKicked != 0 ||
           CcTotalDirtyPages > CcDirtyPageThreshold / 4 ||
           CcRosDeferredBacklogHigh();
}

/*
 * Called with the master lock held when a view became dirty; @FileDirtyPages is what the file of that view has dirty.
 * A stream is a writer that keeps producing dirty data of ONE file: the data of many small files that are created and
 * soon read back or deleted (a build, an unpacking) is left to the lazy writer's normal schedule, which writes it only
 * if it is still dirty after the first scan delay, as Windows does; writing it out at once only competes with the
 * creating thread for the volume (an NTFS-NG create takes the file system lock for every write-back request).
 */
VOID
CcKickStreamingWriteBehind(ULONG FileDirtyPages)
{
    if ((FileDirtyPages >= CC_STREAM_FILE_PAGES) &&
        (CcTotalDirtyPages > min(CcDirtyPageThreshold / 4, (ULONG)CC_STREAM_START_PAGES)) &&
        (InterlockedCompareExchange(&CcStreamingKicked, 1, 0) == 0))
    {
        CcScheduleLazyWriteScan(TRUE);
    }
}

VOID
CcWriteBehind(VOID)
{
    ULONG Target, Count, Chunk, Passes;

    /*
     * One eighth of the dirty pages per run, plus everything above the dirty page target: closed files
     * leave their dirty data to the lazy writer, and with writers waiting for it (CcCanIWrite throttles
     * at CcDirtyPageThreshold, Mm paces page requests from a quarter of it) one eighth a second would
     * make them wait for the scan timer.  The work goes in chunks, and the writers that waited are let
     * go after each one; while the cache stays above the target, or many closed files wait for their
     * data to be written (CcRosDeferredBacklog), the run goes on.
     */
    Target = CcTotalDirtyPages / 8;
    if (Target == 0)
        Target = CcTotalDirtyPages;
    if (CcTotalDirtyPages > CcpDirtyPageTarget())
        Target += CcTotalDirtyPages - CcpDirtyPageTarget();

    for (Passes = 0; Target != 0 && Passes < 256; Passes++)
    {
        Chunk = min(Target, 256);

        /* Flush! */
        DPRINT("Lazy writer starting (%d)\n", Chunk);
        CcRosFlushDirtyPages(Chunk, &Count, FALSE, TRUE);

        /* And update stats */
        CcLazyWritePages += Count;
        ++CcLazyWriteIos;
        DPRINT("Lazy writer done (%d)\n", Count);

        if (!IsListEmpty(&CcDeferredWrites))
            CcPostDeferredWrites();
        /* Writers paced by the amount of dirty data (MmRequestPageMemoryConsumer) go on after each chunk */
        KePulseEvent(&CcWriteBehindProgress, IO_NO_INCREMENT, FALSE);

        /* Nothing could be written (all busy or failing): the next scan tries again */
        if (Count == 0)
            break;

        Target = (Target > Count) ? Target - Count : 0;
        if (Target == 0 && CcTotalDirtyPages > CcpDirtyPageTarget())
            Target = CcTotalDirtyPages - CcpDirtyPageTarget();
        /* Many closed files waiting (each holds its map and the file system's structures): go on */
        if (Target == 0 && CcRosDeferredBacklog())
            Target = 256;
    }

    /* A scan may queue the next run */
    InterlockedDecrement(&CcWriteBehindPending);
    InterlockedExchange(&CcStreamingKicked, 0);

    /* Make sure we're not throttling writes after this */
    while (MmAvailablePages < MmThrottleTop)
    {
        /* Break if we can't even find one to free */
        if (!CcRosFreeOneUnusedVacb())
        {
            break;
        }
    }
}

VOID
CcLazyWriteScan(VOID)
{
    ULONG Target;
    KIRQL OldIrql;
    PLIST_ENTRY ListEntry;
    LIST_ENTRY ToPost;
    PWORK_QUEUE_ENTRY WorkItem;

    /* Do we have entries to queue after we're done? */
    InitializeListHead(&ToPost);
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    if (LazyWriter.OtherWork)
    {
        while (!IsListEmpty(&CcPostTickWorkQueue))
        {
            ListEntry = RemoveHeadList(&CcPostTickWorkQueue);
            WorkItem = CONTAINING_RECORD(ListEntry, WORK_QUEUE_ENTRY, WorkQueueLinks);
            InsertTailList(&ToPost, &WorkItem->WorkQueueLinks);
        }
        LazyWriter.OtherWork = FALSE;
    }
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    /* Our target is one-eighth of the dirty pages (all of them when there are few) */
    Target = CcTotalDirtyPages / 8;
    if (Target == 0)
        Target = CcTotalDirtyPages;
    /*
     * Dirty pages of temporary files and of files without write-behind are no work: the run skips them.
     * And a run takes longer than a scan period when the disk is slow: a scan queues the next one only
     * when the last has ended, they would otherwise pile up (and all rescan the same maps).
     */
    if (Target != 0 && CcRosHasLazyWritableData())
    {
        LONG Runs = (CcStreamingKicked != 0 || CcTotalDirtyPages > CcpDirtyPageTarget()) ? CC_WRITEBEHIND_RUNS : 1, n;

        /* There is stuff to flush, schedule write-behind operations (up to Runs at once) */
        for (n = 0; n < Runs; n++)
        {
            if (InterlockedIncrement(&CcWriteBehindPending) > Runs)
            {
                InterlockedDecrement(&CcWriteBehindPending);
                break;
            }

            /* Allocate a work item */
            WorkItem = ExAllocateFromNPagedLookasideList(&CcTwilightLookasideList);
            if (WorkItem == NULL)
            {
                InterlockedDecrement(&CcWriteBehindPending);
                break;
            }
            WorkItem->Function = WriteBehind;
            CcPostWorkQueue(WorkItem, &CcRegularWorkQueue);
        }
    }

    /* Post items that were due for end of run */
    while (!IsListEmpty(&ToPost))
    {
        ListEntry = RemoveHeadList(&ToPost);
        WorkItem = CONTAINING_RECORD(ListEntry, WORK_QUEUE_ENTRY, WorkQueueLinks);
        CcPostWorkQueue(WorkItem, &CcRegularWorkQueue);
    }

    /* If we have deferred writes, try them now! */
    if (!IsListEmpty(&CcDeferredWrites))
    {
        CcPostDeferredWrites();
        /* Reschedule immediately a lazy writer run
         * Keep us active to have short idle delay
         */
        CcScheduleLazyWriteScan(FALSE);
    }
    else
    {
        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        if (CcTotalDirtyPages != 0 && CcRosHasLazyWritableDataLocked())
        {
            /*
             * Dirty data is left (a run writes an eighth of it): scan again in a second, as long as
             * there is any the lazy writer writes.  Closed files leave their data to the lazy writer,
             * which must get it to the disk without waiting for more writes to come and schedule it.
             */
            CcScheduleLazyWriteScan(FALSE);
        }
        else
        {
            /* We're no longer active */
            LazyWriter.ScanActive = FALSE;
        }
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }
}

VOID CcScheduleLazyWriteScan(
    IN BOOLEAN NoDelay)
{
    /* If no delay, immediately start lazy writer,
     * no matter it was already started
     */
    if (NoDelay)
    {
        LazyWriter.ScanActive = TRUE;
        KeSetTimer(&LazyWriter.ScanTimer, CcNoDelay, &LazyWriter.ScanDpc);
    }
    /* Otherwise, if it's not running, just wait three seconds to start it */
    else if (!LazyWriter.ScanActive)
    {
        LazyWriter.ScanActive = TRUE;
        KeSetTimer(&LazyWriter.ScanTimer, CcFirstDelay, &LazyWriter.ScanDpc);
    }
    /* Finally, already running, so queue for the next second */
    else
    {
        KeSetTimer(&LazyWriter.ScanTimer, CcIdleDelay, &LazyWriter.ScanDpc);
    }
}

VOID
NTAPI
CcWorkerThread(
    IN PVOID Parameter)
{
    KIRQL OldIrql;
    BOOLEAN DropThrottle, WritePerformed;
    PWORK_QUEUE_ITEM Item;
#if DBG
    PIRP TopLevel;
#endif

    /* Get back our thread item */
    Item = Parameter;
    /* And by default, don't touch throttle */
    DropThrottle = FALSE;
    /* No write performed */
    WritePerformed =  FALSE;

#if DBG
    /* Top level IRP should be clean when started
     * Save it to catch buggy drivers (or bugs!)
     */
    TopLevel = IoGetTopLevelIrp();
    if (TopLevel != NULL)
    {
        DPRINT1("(%p) TopLevel IRP for this thread: %p\n", PsGetCurrentThread(), TopLevel);
    }
#endif

    /* Loop till we have jobs */
    while (TRUE)
    {
        PWORK_QUEUE_ENTRY WorkItem;

        /* Lock queues */
        OldIrql = KeAcquireQueuedSpinLock(LockQueueWorkQueueLock);

        /* If we have to touch throttle, reset it now! */
        if (DropThrottle)
        {
            CcQueueThrottle = FALSE;
            DropThrottle = FALSE;
        }

        /* Check first if we have read ahead to do */
        if (IsListEmpty(&CcExpressWorkQueue))
        {
            /* If not, check regular queue */
            if (IsListEmpty(&CcRegularWorkQueue))
            {
                break;
            }
            else
            {
                WorkItem = CONTAINING_RECORD(CcRegularWorkQueue.Flink, WORK_QUEUE_ENTRY, WorkQueueLinks);
            }
        }
        else
        {
            WorkItem = CONTAINING_RECORD(CcExpressWorkQueue.Flink, WORK_QUEUE_ENTRY, WorkQueueLinks);
        }

        /* Get our work item, if someone is waiting for us to finish
         * and we're not the only thread in queue
         * then, quit running to let the others do
         * and throttle so that noone starts till current activity is over
         */
        if (WorkItem->Function == SetDone && CcNumberActiveWorkerThreads > 1)
        {
            CcQueueThrottle = TRUE;
            break;
        }

        /* Otherwise, remove current entry */
        RemoveEntryList(&WorkItem->WorkQueueLinks);
        KeReleaseQueuedSpinLock(LockQueueWorkQueueLock, OldIrql);

        /* And handle it */
        switch (WorkItem->Function)
        {
            case ReadAhead:
                CcPerformReadAhead(WorkItem->Parameters.Read.FileObject);
                break;

            case WriteBehind:
                PsGetCurrentThread()->MemoryMaker = 1;
                CcWriteBehind();
                PsGetCurrentThread()->MemoryMaker = 0;
                WritePerformed = TRUE;
                break;

            case LazyScan:
                CcLazyWriteScan();
                break;

            case SetDone:
                KeSetEvent(WorkItem->Parameters.Event.Event, IO_NO_INCREMENT, FALSE);
                DropThrottle = TRUE;
                break;

            case DereferenceSharedMap:
                /* The entry is part of the map, which this can free: it does not go back to the lookaside list */
                CcRosDereferenceFlushedCacheMap(
                    (PROS_SHARED_CACHE_MAP)WorkItem->Parameters.Write.SharedCacheMap);
                continue;

            default:
                DPRINT1("Ignored item: %p (%d)\n", WorkItem, WorkItem->Function);
                break;
        }

        /* And release the item */
        ExFreeToNPagedLookasideList(&CcTwilightLookasideList, WorkItem);
    }

    /* Our thread is available again */
    InsertTailList(&CcIdleWorkerThreadList, &Item->List);
    /* One less worker */
    --CcNumberActiveWorkerThreads;
    KeReleaseQueuedSpinLock(LockQueueWorkQueueLock, OldIrql);

    /* If there are pending write openations and we have at least 20 dirty pages */
    if (!IsListEmpty(&CcDeferredWrites) && CcTotalDirtyPages >= 20)
    {
        /* And if we performed a write operation previously, then
         * stress the system a bit and reschedule a scan to find
         * stuff to write
         */
        if (WritePerformed)
        {
            CcLazyWriteScan();
        }
    }

#if DBG
    /* Top level shouldn't have changed */
    if (TopLevel != IoGetTopLevelIrp())
    {
        DPRINT1("(%p) Mismatching TopLevel: %p, %p\n", PsGetCurrentThread(), TopLevel, IoGetTopLevelIrp());
    }
#endif
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
CcWaitForCurrentLazyWriterActivity (
    VOID)
{
    KIRQL OldIrql;
    KEVENT WaitEvent;
    PWORK_QUEUE_ENTRY WorkItem;

    /* Allocate a work item */
    WorkItem = ExAllocateFromNPagedLookasideList(&CcTwilightLookasideList);
    if (WorkItem == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* We want lazy writer to set our event */
    WorkItem->Function = SetDone;
    KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);
    WorkItem->Parameters.Event.Event = &WaitEvent;

    /* Use the post tick queue */
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    InsertTailList(&CcPostTickWorkQueue, &WorkItem->WorkQueueLinks);

    /* Inform the lazy writer it will have to handle the post tick queue */
    LazyWriter.OtherWork = TRUE;
    /* And if it's not running, queue a lazy writer run
     * And start it NOW, we want the response now
     */
    if (!LazyWriter.ScanActive)
    {
        CcScheduleLazyWriteScan(TRUE);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    /* And now, wait until lazy writer replies */
    return KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, NULL);
}
