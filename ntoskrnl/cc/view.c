/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/view.c
 * PURPOSE:         Cache manager
 *
 * PROGRAMMERS:     David Welch (welch@mcmail.com)
 *                  Pierre Schweitzer (pierre@reactos.org)
 */

/* NOTES **********************************************************************
 *
 * This is not the NT implementation of a file cache nor anything much like
 * it.
 *
 * The general procedure for a filesystem to implement a read or write
 * dispatch routine is as follows
 *
 * (1) If caching for the FCB hasn't been initiated then so do by calling
 * CcInitializeFileCache.
 *
 * (2) For each 4k region which is being read or written obtain a cache page
 * by calling CcRequestCachePage.
 *
 * (3) If either the page is being read or not completely written, and it is
 * not up to date then read its data from the underlying medium. If the read
 * fails then call CcReleaseCachePage with VALID as FALSE and return a error.
 *
 * (4) Copy the data into or out of the page as necessary.
 *
 * (5) Release the cache page
 */
/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

LIST_ENTRY DirtyVacbListHead;
static LIST_ENTRY VacbLruListHead;

NPAGED_LOOKASIDE_LIST iBcbLookasideList;
static NPAGED_LOOKASIDE_LIST SharedCacheMapLookasideList;
static NPAGED_LOOKASIDE_LIST VacbLookasideList;

/* Internal vars (MS):
 * - Threshold above which lazy writer will start action
 * - Amount of dirty pages
 * - List for deferred writes
 * - Spinlock when dealing with the deferred list
 * - List for "clean" shared cache maps
 */
ULONG CcDirtyPageThreshold = 0;
ULONG CcTotalDirtyPages = 0;
KEVENT CcWriteBehindProgress;
LIST_ENTRY CcDeferredWrites;
KSPIN_LOCK CcDeferredWriteSpinLock;
LIST_ENTRY CcCleanSharedCacheMapList;

/*
 * Maps that CcRosDeleteFileCache is deleting (master lock): the map is already gone from its
 * SectionObjectPointers (a file system that cuts or regrows the file meanwhile sees no cache map) but
 * the dirty views are still being written and the file object is still held.  See
 * CcRosIsDeleteFlushPending.
 */
static LIST_ENTRY CcDyingSharedCacheMapList;

/*
 * Views of maps that were closed with dirty data and wait for the lazy writer (master lock).  Their
 * mappings are parked (CcRosParkViews), but each such file keeps its map, section, file object and the
 * file system's FCB until the lazy writer wrote it: past this many views a close writes its data itself,
 * as before.  From a quarter of it on the lazy writer keeps writing (CcRosDeferredBacklog).
 */
static ULONG CcDeferredVacbs = 0;
#define CC_LAZY_MIN_AGE (3LL * 10000000)    /* 100 ns units */
#ifdef _WIN64
#define CC_MAX_DEFERRED_VACBS 16384
#else
#define CC_MAX_DEFERRED_VACBS 512
#endif

#if DBG
ULONG CcRosVacbIncRefCount_(PROS_VACB vacb, PCSTR file, INT line)
{
    ULONG Refs;

    Refs = InterlockedIncrement((PLONG)&vacb->ReferenceCount);
    if (vacb->SharedCacheMap->Trace)
    {
        DbgPrint("(%s:%i) VACB %p ++RefCount=%lu, Dirty %u, PageOut %lu\n",
                 file, line, vacb, Refs, vacb->Dirty, vacb->PageOut);
    }

    return Refs;
}
ULONG CcRosVacbDecRefCount_(PROS_VACB vacb, PCSTR file, INT line)
{
    ULONG Refs;
    BOOLEAN VacbDirty = vacb->Dirty;
    BOOLEAN VacbTrace = vacb->SharedCacheMap->Trace;
    BOOLEAN VacbPageOut = vacb->PageOut;

    Refs = InterlockedDecrement((PLONG)&vacb->ReferenceCount);
    ASSERT(!(Refs == 0 && VacbDirty));
    if (VacbTrace)
    {
        DbgPrint("(%s:%i) VACB %p --RefCount=%lu, Dirty %u, PageOut %lu\n",
                 file, line, vacb, Refs, VacbDirty, VacbPageOut);
    }

    if (Refs == 0)
    {
        CcRosInternalFreeVacb(vacb);
    }

    return Refs;
}
ULONG CcRosVacbGetRefCount_(PROS_VACB vacb, PCSTR file, INT line)
{
    ULONG Refs;

    Refs = InterlockedCompareExchange((PLONG)&vacb->ReferenceCount, 0, 0);
    if (vacb->SharedCacheMap->Trace)
    {
        DbgPrint("(%s:%i) VACB %p ==RefCount=%lu, Dirty %u, PageOut %lu\n",
                 file, line, vacb, Refs, vacb->Dirty, vacb->PageOut);
    }

    return Refs;
}
#endif


/* FUNCTIONS *****************************************************************/

VOID
CcRosTraceCacheMap (
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    BOOLEAN Trace )
{
#if DBG
    KIRQL oldirql;
    PLIST_ENTRY current_entry;
    PROS_VACB current;

    if (!SharedCacheMap)
        return;

    SharedCacheMap->Trace = Trace;

    if (Trace)
    {
        DPRINT1("Enabling Tracing for CacheMap 0x%p:\n", SharedCacheMap);

        oldirql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);

        current_entry = SharedCacheMap->CacheMapVacbListHead.Flink;
        while (current_entry != &SharedCacheMap->CacheMapVacbListHead)
        {
            current = CONTAINING_RECORD(current_entry, ROS_VACB, CacheMapVacbListEntry);
            current_entry = current_entry->Flink;

            DPRINT1("  VACB 0x%p enabled, RefCount %lu, Dirty %u, PageOut %lu, BaseAddress %p, FileOffset %I64d\n",
                    current, current->ReferenceCount, current->Dirty, current->PageOut, current->BaseAddress, current->FileOffset.QuadPart);
        }

        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, oldirql);
    }
    else
    {
        DPRINT1("Disabling Tracing for CacheMap 0x%p:\n", SharedCacheMap);
    }

#else
    UNREFERENCED_PARAMETER(SharedCacheMap);
    UNREFERENCED_PARAMETER(Trace);
#endif
}

/*
 * What was written up to End is on the disk: Mm need not read zeros from the file system below it.  Never
 * past the file size: a view ends on a 256 KB boundary, and a valid data length past the end of the file
 * would survive a later growth of the file (a deferred map lives on across a reopen), making Mm read the
 * grown range from the disk instead of leaving it zero.  Not called at DISPATCH_LEVEL.
 */
static
VOID
CcRosRaiseValidDataLength(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _In_ LONGLONG End)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&SharedCacheMap->CacheMapLock, &OldIrql);
    if (End > SharedCacheMap->FileSize.QuadPart)
        End = SharedCacheMap->FileSize.QuadPart;
    if (SharedCacheMap->ValidDataLength.QuadPart < End)
        SharedCacheMap->ValidDataLength.QuadPart = End;
    KeReleaseSpinLock(&SharedCacheMap->CacheMapLock, OldIrql);
}

/*
 * Write-back goes to the disk in requests of up to CC_FLUSH_CLUSTER_VACBS views (2 MB): the dirty views that directly
 * follow the one being flushed, in the same file, are unmarked and written with it, in one MmFlushSegment range.
 * Each is referenced for the flush (returned in Group, Max at most) and marked dirty again if the write fails.
 * Returns how many followed.
 */
#define CC_FLUSH_CLUSTER_VACBS 8

static
ULONG
CcRosTakeDirtyFollowers(
    _In_ PROS_VACB Vacb,
    _Out_writes_(Max) PROS_VACB *Group,
    _In_ ULONG Max)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap = Vacb->SharedCacheMap;
    LONGLONG Next = Vacb->FileOffset.QuadPart + VACB_MAPPING_GRANULARITY;
    PLIST_ENTRY Entry;
    ULONG Count = 0;
    KIRQL OldIrql;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);

    for (Entry = Vacb->CacheMapVacbListEntry.Flink;
         (Count < Max) && (Entry != &SharedCacheMap->CacheMapVacbListHead);
         Entry = Entry->Flink)
    {
        PROS_VACB Follower = CONTAINING_RECORD(Entry, ROS_VACB, CacheMapVacbListEntry);

        if ((Follower->FileOffset.QuadPart != Next) || !Follower->Dirty)
            break;

        CcRosVacbIncRefCount(Follower);
        CcRosUnmarkDirtyVacb(Follower, FALSE);
        Group[Count++] = Follower;
        Next += VACB_MAPPING_GRANULARITY;
    }

    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    return Count;
}

NTSTATUS
CcRosFlushVacb (
    _In_ PROS_VACB Vacb,
    _Out_opt_ PIO_STATUS_BLOCK Iosb)
{
    NTSTATUS Status;
    BOOLEAN HaveLock = FALSE;
    BOOLEAN WasMarked;
    PROS_SHARED_CACHE_MAP SharedCacheMap = Vacb->SharedCacheMap;
    PROS_VACB Group[CC_FLUSH_CLUSTER_VACBS - 1];
    ULONG Followers = 0, i;

    /*
     * Remove the VACB from the dirty list before flushing. The return value
     * tells us whether the VACB was actually dirty at this point.
     * If WasMarked is FALSE a concurrent flush already removed it from the
     * dirty list. We still call MmFlushSegment because the caller expects a
     * reliable status: if we returned STATUS_SUCCESS immediately, the caller
     * would believe the data was safely written when in fact the concurrent
     * flush may have failed. We must not re-mark dirty on failure in this
     * case, however, as we were not the one who removed the VACB from the list.
     */
    WasMarked = CcRosUnmarkDirtyVacb(Vacb, TRUE);

    /* The dirty views that follow are written in the same request (only when this thread unmarked the first one) */
    if (WasMarked)
        Followers = CcRosTakeDirtyFollowers(Vacb, Group, RTL_NUMBER_OF(Group));

    /* Lock for flush, if we are not already the top-level */
    if (IoGetTopLevelIrp() != (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
    {
        Status = FsRtlAcquireFileForCcFlushEx(Vacb->SharedCacheMap->FileObject);
        if (!NT_SUCCESS(Status))
            goto quit;
        HaveLock = TRUE;
    }

    Status = MmFlushSegment(SharedCacheMap->FileObject->SectionObjectPointer,
                            &Vacb->FileOffset,
                            VACB_MAPPING_GRANULARITY * (1 + Followers),
                            Iosb);

    if (HaveLock)
    {
        FsRtlReleaseFileForCcFlush(Vacb->SharedCacheMap->FileObject);
    }

quit:
    if (!NT_SUCCESS(Status))
    {
        /*
         * Only re-mark dirty if we were the thread that removed it from the
         * dirty list. If WasMarked is FALSE, another thread already removed it,
         * so we must not change dirty tracking here (that thread will re-mark on failure).
         * CcRosMarkDirtyVacb itself guards against double-insertion should
         * another thread have concurrently re-marked the VACB dirty.
         */
        if (WasMarked)
            CcRosMarkDirtyVacb(Vacb);
        for (i = 0; i < Followers; i++)
            CcRosMarkDirtyVacb(Group[i]);
    }
    else
    {
        CcRosRaiseValidDataLength(SharedCacheMap,
                                  Vacb->FileOffset.QuadPart + VACB_MAPPING_GRANULARITY * (1 + Followers));
    }

    /* Dropped last, outside any lock: the last reference may free a view */
    for (i = 0; i < Followers; i++)
        CcRosVacbDecRefCount(Group[i]);

    return Status;
}

static
NTSTATUS
CcRosDeleteFileCache (
    PFILE_OBJECT FileObject,
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    PKIRQL OldIrql)
/*
 * FUNCTION: Releases the shared cache map associated with a file object
 */
{
    LIST_ENTRY LocalVacbList;
    PCACHE_UNINITIALIZE_EVENT Events;
    BOOLEAN Discard;

    ASSERT(SharedCacheMap);
    ASSERT(SharedCacheMap == FileObject->SectionObjectPointer->SharedCacheMap);
    ASSERT(SharedCacheMap->OpenCount == 0);
    ASSERT(IsListEmpty(&SharedCacheMap->PrivateList));

    InitializeListHead(&LocalVacbList);

    /*
     * Remove all VACBs from the global lists while holding the lock. By also
     * removing them from CacheMapVacbListHead here (under the lock), we ensure
     * that a concurrent CcRosLookupVacb (which also holds the lock) cannot find
     * any of these VACBs after we release the lock. Without this, a caller that
     * already has a SharedCacheMap pointer without a reference could look up a
     * VACB between our lock release and the point where the second loop removes
     * it from the list — leaving an outstanding reference that races with our
     * CcRosVacbDecRefCount call below.
     */
    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
    while (!IsListEmpty(&SharedCacheMap->CacheMapVacbListHead))
    {
        PROS_VACB Vacb = CONTAINING_RECORD(SharedCacheMap->CacheMapVacbListHead.Flink,
                                           ROS_VACB, CacheMapVacbListEntry);

        RemoveEntryList(&Vacb->VacbLruListEntry);
        InitializeListHead(&Vacb->VacbLruListEntry);

        if (Vacb->Dirty)
        {
            CcRosUnmarkDirtyVacb(Vacb, FALSE);
            /* Mark it as dirty again so we know that we have to flush before freeing it */
            Vacb->Dirty = TRUE;
        }

        /*
         * Move this VACB from the shared cache map list to our private local
         * list. After the lock is released, CcRosLookupVacb can no longer find
         * it, so no new lookup references can be created.
         */
        RemoveEntryList(&Vacb->CacheMapVacbListEntry);
        InsertTailList(&LocalVacbList, &Vacb->CacheMapVacbListEntry);
    }
    SharedCacheMap->LastVacb = NULL;

    /* Make sure there is no trace anymore of this map */
    FileObject->SectionObjectPointer->SharedCacheMap = NULL;
    RemoveEntryList(&SharedCacheMap->SharedCacheMapLinks);
    /* The map is gone for everybody else, but its dirty views are written below: stay visible to a cut */
    InsertTailList(&CcDyingSharedCacheMapList, &SharedCacheMap->SharedCacheMapLinks);
    Discard = BooleanFlagOn(SharedCacheMap->Flags, SHARED_CACHE_MAP_DISCARD);
    Events = SharedCacheMap->UninitializeEvents;
    SharedCacheMap->UninitializeEvents = NULL;
    /* Whoever waited for the deletion is woken below */
    SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_SYNC_DELETE;
    if (SharedCacheMap->Flags & SHARED_CACHE_MAP_DEFERRED)
    {
        CcDeferredVacbs -= SharedCacheMap->DeferredVacbs;
        SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_DEFERRED;
    }

    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, *OldIrql);

    /* Now that we're out of the locks, free everything for real */
    while (!IsListEmpty(&LocalVacbList))
    {
        PROS_VACB Vacb = CONTAINING_RECORD(RemoveHeadList(&LocalVacbList), ROS_VACB, CacheMapVacbListEntry);
        ULONG RefCount;

        InitializeListHead(&Vacb->CacheMapVacbListEntry);

        /* Flush to disk, if needed (not for a map whose writes keep failing: its data is dropped) */
        if (Vacb->Dirty && !Discard)
        {
            IO_STATUS_BLOCK Iosb;
            NTSTATUS Status;

            Status = MmFlushSegment(FileObject->SectionObjectPointer, &Vacb->FileOffset, VACB_MAPPING_GRANULARITY, &Iosb);
            if (!NT_SUCCESS(Status))
            {
                /* Complain. There's not much we can do */
                DPRINT1("Failed to flush VACB to disk while deleting the cache entry. Status: 0x%08x\n", Status);
            }
            Vacb->Dirty = FALSE;
        }
        else
        {
            Vacb->Dirty = FALSE;
        }

        RefCount = CcRosVacbDecRefCount(Vacb);
#if DBG // CORE-14578
        if (RefCount != 0)
        {
            DPRINT1("Leaking VACB %p attached to %p (%I64d)\n", Vacb, FileObject, Vacb->FileOffset.QuadPart);
            DPRINT1("There are: %d references left\n", RefCount);
            DPRINT1("Map: %d\n", Vacb->MappedCount);
            DPRINT1("Dirty: %d\n", Vacb->Dirty);
            if (FileObject->FileName.Length != 0)
            {
                DPRINT1("File was: %wZ\n", &FileObject->FileName);
            }
            else
            {
                DPRINT1("No name for the file\n");
            }
        }
#else
        (void)RefCount;
#endif
    }

    /* Written (or dropped): a cut no longer has anything to order itself against.  Before the file object goes. */
    {
        KIRQL DyingIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        RemoveEntryList(&SharedCacheMap->SharedCacheMapLinks);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, DyingIrql);
    }

    /* Release the references we own */
    if(SharedCacheMap->Section)
        ObDereferenceObject(SharedCacheMap->Section);
    ObDereferenceObject(SharedCacheMap->FileObject);

    ExFreeToNPagedLookasideList(&SharedCacheMapLookasideList, SharedCacheMap);

    /* The map is gone: wake whoever waits for that (CcUninitializeCacheMap's UninitializeCompleteEvent).
     * The waiter may free its entry as soon as it is signalled, so the link is read first. */
    while (Events)
    {
        PCACHE_UNINITIALIZE_EVENT Next = Events->Next;
        KeSetEvent(&Events->Event, IO_NO_INCREMENT, FALSE);
        Events = Next;
    }

    /* Acquire the lock again for our caller */
    *OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    return STATUS_SUCCESS;
}

/*
 * Can the lazy writer take over the dirty data of a map nobody has open?  Only when the file system
 * said so (CcRosAllowLazyClose): a deferred map keeps pointing at the file system's SectionObjectPointers
 * and lazy write context, which the file systems that were not written for that free once they closed
 * their file (vfatfs's directory FCBs, for one), so they get the synchronous flush and delete they
 * always had.  Not for temporary files and files that disabled write-behind, which the lazy writer skips:
 * those are written at their last close, as before.  Not when somebody waits for the map to go
 * (UninitializeCompleteEvent), or when its data is dropped.
 */
static
BOOLEAN
CcRosCanDeferDelete(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap)
{
    return BooleanFlagOn(SharedCacheMap->Flags, SHARED_CACHE_MAP_LAZY_CLOSE) &&
           !BooleanFlagOn(SharedCacheMap->Flags, WRITEBEHIND_DISABLED | SHARED_CACHE_MAP_SYNC_DELETE | SHARED_CACHE_MAP_DISCARD) &&
           !BooleanFlagOn(SharedCacheMap->FileObject->Flags, FO_TEMPORARY_FILE);
}

/*
 * The map's last reference is gone (OpenCount 0: no private cache map, no flush, purge or lazy write
 * using it).  As on Windows, a map that still has dirty views is not flushed and deleted here: it stays,
 * unreferenced, on the lazy writer's dirty list, and the lazy writer deletes it once it wrote them (the
 * next drop of its OpenCount to 0 comes back here, clean).  A clean map is deleted now.
 * Called with the master lock held; TRUE if the map was deleted (that released and reacquired the lock).
 */
static
BOOLEAN
CcRosDeleteOrDeferFileCache(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _Inout_ PKIRQL OldIrql)
{
    ASSERT(SharedCacheMap->OpenCount == 0);

    if (SharedCacheMap->DirtyPages != 0 && CcRosCanDeferDelete(SharedCacheMap))
    {
        if (!(SharedCacheMap->Flags & SHARED_CACHE_MAP_DEFERRED))
        {
            PLIST_ENTRY Entry;
            ULONG Vacbs = 0;

            KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
            for (Entry = SharedCacheMap->CacheMapVacbListHead.Flink;
                 Entry != &SharedCacheMap->CacheMapVacbListHead;
                 Entry = Entry->Flink)
            {
                Vacbs++;
            }
            KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);

            if (CcDeferredVacbs + Vacbs <= CC_MAX_DEFERRED_VACBS)
            {
                SharedCacheMap->Flags |= SHARED_CACHE_MAP_DEFERRED;
                SharedCacheMap->DeferredVacbs = Vacbs;
                CcDeferredVacbs += Vacbs;

                /*
                 * The give-up count starts with the close: failures while the file was open do not count
                 * towards dropping its data (CcRosLazyWriteFailed).  Nobody writes the map now (that would
                 * hold a reference), so this does not race with a count.
                 */
                SharedCacheMap->LazyWriteFailures = 0;
                SharedCacheMap->FirstLazyWriteFailure = 0;

                /* A backlog: do not wait for the next scan */
                if (CcDeferredVacbs > CC_MAX_DEFERRED_VACBS / 4 &&
                    CcDeferredVacbs - Vacbs <= CC_MAX_DEFERRED_VACBS / 4)
                {
                    CcScheduleLazyWriteScan(TRUE);
                }
            }
        }

        if (SharedCacheMap->Flags & SHARED_CACHE_MAP_DEFERRED)
        {
            /* Its dirty views keep the lazy writer scheduled; make sure it runs */
            if (!LazyWriter.ScanActive)
                CcScheduleLazyWriteScan(FALSE);
            return FALSE;
        }
    }

    CcRosDeleteFileCache(SharedCacheMap->FileObject, SharedCacheMap, OldIrql);
    return TRUE;
}

/*
 * Is CcRosDeleteFileCache still writing the dirty views of a map of this file, a map that is already gone
 * from the SectionObjectPointers?  Its writes go through Mm without the file system's locks, so they can
 * land after a cut of the file by a file system that sees no cache map, and after the file grew again.
 */
BOOLEAN
CcRosIsDeleteFlushPending(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
    KIRQL OldIrql;
    PLIST_ENTRY Entry;
    BOOLEAN Pending = FALSE;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    for (Entry = CcDyingSharedCacheMapList.Flink; Entry != &CcDyingSharedCacheMapList; Entry = Entry->Flink)
    {
        PROS_SHARED_CACHE_MAP Dying = CONTAINING_RECORD(Entry, ROS_SHARED_CACHE_MAP, SharedCacheMapLinks);

        /* The file object is held until the map leaves the list (under this lock) */
        if (Dying->FileObject->SectionObjectPointer == SectionObjectPointer)
        {
            Pending = TRUE;
            break;
        }
    }
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    return Pending;
}

/* Are the closed files waiting for the lazy writer near the limit past which a close writes its data itself? */
BOOLEAN
CcRosDeferredBacklogHigh(VOID)
{
    return CcDeferredVacbs > CC_MAX_DEFERRED_VACBS / 4 * 3;
}

/* Are many closed files waiting for the lazy writer?  It then keeps writing (CcWriteBehind). */
BOOLEAN
CcRosDeferredBacklog(VOID)
{
    return CcDeferredVacbs > CC_MAX_DEFERRED_VACBS / 4;
}

static
VOID
CcpPostFlushDereference(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap);

/*
 * Drops the reference CcRosFlushDirtyPages holds on the map while it writes a view.  Deleting a map closes
 * its file object, which runs the file system's close in the thread that drops the last reference.  The lazy
 * writer (a worker thread) and the full flush at shutdown may do that.  The caller that trims the cache for
 * the memory manager, the balancer thread, must not: a close takes locks and memory, and the balancer is what
 * everybody who waits for memory waits for.  A map is no longer deleted by the close of its file: with
 * the dirty data left to the lazy writer, the one that writes the last of it ends up holding the last reference.
 * That one gives it to a worker.  Master lock held; TRUE if it was released and taken again (the dirty list
 * may have changed, the map may be gone).
 */
static
BOOLEAN
CcRosDropFlushReference(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _Inout_ PKIRQL OldIrql,
    _In_ BOOLEAN MayCloseFile)
{
    if (!MayCloseFile && SharedCacheMap->OpenCount == 1)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, *OldIrql);
        CcpPostFlushDereference(SharedCacheMap);
        *OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        return TRUE;
    }

    if (--SharedCacheMap->OpenCount == 0)
        return CcRosDeleteOrDeferFileCache(SharedCacheMap, OldIrql);

    return FALSE;
}

/*
 * Maps whose write failed in one CcRosFlushDirtyPages call are skipped for the rest of it, and so are maps
 * the lazy writer could not lock without waiting (below).
 */
#define CC_FLUSH_FAILED_MAPS 16
/* A full flush waits this many 10 ms in a row, with no dirty page written meanwhile, for the lazy writer to finish with a map before it gives up */
#define CC_FLUSHALL_BUSY_WAITS 1000
/* A closed map whose writes failed this many times in a row, over this long, is dropped */
#define CC_LAZY_WRITE_GIVEUP_FAILURES 5
#define CC_LAZY_WRITE_GIVEUP_TIME (30ULL * 1000 * 1000 * 10)

/*
 * A write of a view of the map failed.  A map that is closed (left to the lazy writer) and whose writes
 * keep failing (media removed or write protected, volume gone) would stay for ever, with its file object,
 * the file system's FCB and the volume, and be retried every second.  As Windows does, the data is given
 * up after a while and the user is told (the lost delayed write popup).  An open map is not touched: the
 * application still has the file.  Called at PASSIVE_LEVEL with the map referenced and marked
 * IN_LAZYWRITE (no other flusher counts at the same time), no lock held.  TRUE if the failures reached
 * the give-up limit; whether the map is still closed is decided by the caller under the master lock
 * (a reopen meanwhile clears DEFERRED and must keep the data), see CcRosFlushDirtyPages.
 */
static
BOOLEAN
CcRosLazyWriteFailed(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap)
{
    ULONGLONG Now;

    if (SharedCacheMap->LazyWriteFailures++ == 0)
        SharedCacheMap->FirstLazyWriteFailure = KeQueryInterruptTime();

    /* Unlocked: only a hint that saves the clock read for open maps; decided again under the lock */
    if (!(SharedCacheMap->Flags & SHARED_CACHE_MAP_DEFERRED) ||
        (SharedCacheMap->Flags & SHARED_CACHE_MAP_DISCARD))
    {
        return FALSE;
    }

    Now = KeQueryInterruptTime();
    return SharedCacheMap->LazyWriteFailures >= CC_LAZY_WRITE_GIVEUP_FAILURES &&
           Now - SharedCacheMap->FirstLazyWriteFailure >= CC_LAZY_WRITE_GIVEUP_TIME;
}

/*
 * A copy of the file name of a map whose data may be dropped, taken while the map is referenced, for the
 * hard error raised once the decision is taken (the map may be deleted by then).  PASSIVE_LEVEL.
 */
static
VOID
CcRosCopyFileName(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _Out_ PUNICODE_STRING Name)
{
    PUNICODE_STRING FileName = &SharedCacheMap->FileObject->FileName;

    RtlInitEmptyUnicodeString(Name, NULL, 0);
    if (FileName->Length == 0)
        return;

    Name->Buffer = ExAllocatePoolWithTag(PagedPool, FileName->Length, TAG_CC);
    if (Name->Buffer)
    {
        RtlCopyMemory(Name->Buffer, FileName->Buffer, FileName->Length);
        Name->Length = Name->MaximumLength = FileName->Length;
    }
}

/* A lazy writer is done with the map (master lock held): its claim goes, and the flag when it was the last */
static
VOID
CcpEndLazyWrite(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _In_ LONG ClaimSlot)
{
    if (ClaimSlot >= 0)
        SharedCacheMap->LazyClaim[ClaimSlot].Used = FALSE;
    if (--SharedCacheMap->LazyWriteActive == 0)
        SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_IN_LAZYWRITE;
}

NTSTATUS
CcRosFlushDirtyPages (
    ULONG Target,
    PULONG Count,
    BOOLEAN Wait,
    BOOLEAN CalledFromLazy)
{
    PLIST_ENTRY current_entry;
    NTSTATUS Status;
    KIRQL OldIrql;
    BOOLEAN FlushAll = (Target == MAXULONG);
    ULONG Failures = 0;
    PROS_SHARED_CACHE_MAP FailedMaps[CC_FLUSH_FAILED_MAPS];
    ULONG FailedCount = 0;
    PROS_SHARED_CACHE_MAP BusyMaps[CC_FLUSH_FAILED_MAPS];
    ULONG BusyCount = 0;
    ULONG LapFlushed = 0;
    ULONG BusyWaits = 0;
    LONG ClaimSlot;
    ULONG TotalWaits = 0;
    ULONG DirtyAtLastWait = MAXULONG;
    BOOLEAN LapBusy = FALSE;
    ULONG i;

    DPRINT("CcRosFlushDirtyPages(Target %lu)\n", Target);

    (*Count) = 0;

    KeEnterCriticalRegion();
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    current_entry = DirtyVacbListHead.Flink;
    if (current_entry == &DirtyVacbListHead)
    {
        DPRINT("No Dirty pages\n");
    }

    while (((current_entry != &DirtyVacbListHead) && (Target > 0)) || FlushAll)
    {
        PROS_SHARED_CACHE_MAP SharedCacheMap;
        PROS_VACB current;
        BOOLEAN Locked;
        BOOLEAN GiveUp, Discarded;
        ULONG DiscardFailures = 0;
        UNICODE_STRING GiveUpName = { 0, 0, NULL };

        if (current_entry == &DirtyVacbListHead)
        {
            ASSERT(FlushAll);
            if (IsListEmpty(&DirtyVacbListHead))
                break;

            if (LapFlushed == 0)
            {
                /*
                 * A whole lap wrote nothing.  What is left belongs to maps whose writes fail (given up
                 * for this call), or to maps the lazy writer is writing at this moment.  That one needs
                 * the master lock to finish with the map and let it go: wait for it, without the lock
                 * (spinning on the list with it held never ended), for a bounded time.
                 */
                /*
                 * The limit is on waiting without progress: a slow disk with much to write (the lazy
                 * writer holding a map for a long write) is waited for as long as the dirty pages go
                 * down, a lazy writer stuck on a map for 10 s with nothing written is given up on.
                 */
                if (!LapBusy)
                    break;
                if (CcTotalDirtyPages < DirtyAtLastWait)
                    BusyWaits = 0;
                DirtyAtLastWait = CcTotalDirtyPages;
                if (++BusyWaits > CC_FLUSHALL_BUSY_WAITS)
                    break;
                TotalWaits++;

                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                {
                    LARGE_INTEGER Interval;
                    Interval.QuadPart = -10 * 1000 * 10; /* 10 ms */
                    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
                }
                OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

                if (IsListEmpty(&DirtyVacbListHead))
                    break;
            }

            LapFlushed = 0;
            LapBusy = FALSE;
            current_entry = DirtyVacbListHead.Flink;
        }

        current = CONTAINING_RECORD(current_entry,
                                    ROS_VACB,
                                    DirtyVacbListEntry);
        current_entry = current_entry->Flink;

        CcRosVacbIncRefCount(current);

        /* Younger dirty data is left to a later scan (the list is in the order the views became dirty) */
        if (CalledFromLazy && !FlushAll && !CcLazyUnderPressure() &&
            KeQueryInterruptTime() - current->DirtySince < CC_LAZY_MIN_AGE)
        {
            CcRosVacbDecRefCount(current);
            break;
        }

        SharedCacheMap = current->SharedCacheMap;

        /* When performing lazy write, don't handle temporary files */
        if (CalledFromLazy && BooleanFlagOn(SharedCacheMap->FileObject->Flags, FO_TEMPORARY_FILE))
        {
            CcRosVacbDecRefCount(current);
            continue;
        }

        /* Don't attempt to lazy write the files that asked not to */
        if (CalledFromLazy && BooleanFlagOn(SharedCacheMap->Flags, WRITEBEHIND_DISABLED))
        {
            CcRosVacbDecRefCount(current);
            continue;
        }

        ASSERT(current->Dirty);

        /* A map whose write failed in this call is left for the next one (compared as a pointer only) */
        for (i = 0; i < FailedCount; i++)
        {
            if (FailedMaps[i] == SharedCacheMap)
                break;
        }
        if (i < FailedCount)
        {
            CcRosVacbDecRefCount(current);
            continue;
        }

        /*
         * A map the file system would not let us lock without waiting (its owner holds the paging resource
         * exclusive: a growing file) is left for the next call, whole.  Going on with its later views would
         * write the file out of order (the file system then zero-fills the gap below each view, under its
         * locks, only for the skipped views to be written again).
         */
        for (i = 0; i < BusyCount; i++)
        {
            if (BusyMaps[i] == SharedCacheMap)
                break;
        }
        if (i < BusyCount)
        {
            CcRosVacbDecRefCount(current);
            continue;
        }

        /*
         * Do not lazy-write the same file concurrently. Fastfat ASSERTS on that.  A map that allows it (CcRosAllowLazyClose:
         * the file system orders the transfers of a stream itself) takes a second worker, which writes other views: the
         * views the first worker has claimed (its cluster, from the view it started with) are not taken again.
         */
        ClaimSlot = -1;
        if (SharedCacheMap->Flags & SHARED_CACHE_MAP_IN_LAZYWRITE)
        {
            if (!(SharedCacheMap->Flags & SHARED_CACHE_MAP_LAZY_CLOSE) ||
                SharedCacheMap->LazyWriteActive >= CC_LAZY_WRITERS_PER_MAP)
            {
                LapBusy = TRUE;
                CcRosVacbDecRefCount(current);
                continue;
            }
            for (i = 0; i < CC_LAZY_WRITERS_PER_MAP; i++)
            {
                if (SharedCacheMap->LazyClaim[i].Used &&
                    current->FileOffset.QuadPart >= SharedCacheMap->LazyClaim[i].Start &&
                    current->FileOffset.QuadPart < SharedCacheMap->LazyClaim[i].End)
                    break;
            }
            if (i < CC_LAZY_WRITERS_PER_MAP)
            {
                LapBusy = TRUE;
                CcRosVacbDecRefCount(current);
                continue;
            }
        }
        if (SharedCacheMap->Flags & SHARED_CACHE_MAP_LAZY_CLOSE)
        {
            for (i = 0; i < CC_LAZY_WRITERS_PER_MAP; i++)
            {
                if (!SharedCacheMap->LazyClaim[i].Used)
                {
                    ClaimSlot = (LONG)i;
                    SharedCacheMap->LazyClaim[i].Start = current->FileOffset.QuadPart;
                    SharedCacheMap->LazyClaim[i].End = current->FileOffset.QuadPart +
                                                       (LONGLONG)CC_FLUSH_CLUSTER_VACBS * VACB_MAPPING_GRANULARITY;
                    SharedCacheMap->LazyClaim[i].Used = TRUE;
                    break;
                }
            }
        }
        SharedCacheMap->LazyWriteActive++;
        SharedCacheMap->Flags |= SHARED_CACHE_MAP_IN_LAZYWRITE;

        /* Keep a ref on the shared cache map */
        SharedCacheMap->OpenCount++;

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        Locked = SharedCacheMap->Callbacks->AcquireForLazyWrite(SharedCacheMap->LazyWriteContext, Wait);
        if (!Locked)
        {
            DPRINT("Not locked\n");
            ASSERT(!Wait);
            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

            /*
             * The dirty list may have changed while the lock was released: a cache map that
             * was deleted meanwhile took its views off it, and the next entry read before the
             * release may be one of them. Go on after this view if it is still listed, from
             * the start otherwise.
             */
            if (IsListEmpty(&current->DirtyVacbListEntry))
                current_entry = DirtyVacbListHead.Flink;
            else
                current_entry = current->DirtyVacbListEntry.Flink;

            /* The cache map still holds the view, so this is not its last reference */
            CcRosVacbDecRefCount(current);

            CcpEndLazyWrite(SharedCacheMap, ClaimSlot);

            /* Compared as a pointer only; with the array full the map is tried again view by view */
            if (BusyCount < CC_FLUSH_FAILED_MAPS)
                BusyMaps[BusyCount++] = SharedCacheMap;

            if (CcRosDropFlushReference(SharedCacheMap, &OldIrql, CalledFromLazy || FlushAll))
            {
                /* That released the lock as well */
                current_entry = DirtyVacbListHead.Flink;
            }

            continue;
        }

        IO_STATUS_BLOCK Iosb;
        Status = CcRosFlushVacb(current, &Iosb);

        SharedCacheMap->Callbacks->ReleaseFromLazyWrite(SharedCacheMap->LazyWriteContext);

        /* We release the VACB before acquiring the lock again, because
         * CcRosVacbDecRefCount might free the VACB, as CcRosFlushVacb dropped a
         * Refcount. Freeing must be done outside of the lock.
         * The refcount is decremented atomically. So this is OK. */
        CcRosVacbDecRefCount(current);

        /* The map is referenced (OpenCount) until the lock is taken again below */
        GiveUp = FALSE;
        if (NT_SUCCESS(Status))
            SharedCacheMap->LazyWriteFailures = 0;
        else
            GiveUp = CcRosLazyWriteFailed(SharedCacheMap);
        if (GiveUp)
            CcRosCopyFileName(SharedCacheMap, &GiveUpName);

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        CcpEndLazyWrite(SharedCacheMap, ClaimSlot);

        /*
         * The data is dropped only if the map is still closed, decided here under the master lock.  A
         * reopen while the write failed (CcRosInitializeFileCache) cleared DEFERRED: the map is open again,
         * maybe dirtied by its new user, and a DISCARD left on it would make its last close drop that new
         * data unwritten.  While this call holds its reference the map cannot be closed and deferred
         * again, so DEFERRED here means nobody reopened it since the failures were counted.
         */
        Discarded = GiveUp &&
                    (SharedCacheMap->Flags & SHARED_CACHE_MAP_DEFERRED) &&
                    !(SharedCacheMap->Flags & SHARED_CACHE_MAP_DISCARD);
        if (Discarded)
        {
            SharedCacheMap->Flags |= SHARED_CACHE_MAP_DISCARD;
            DiscardFailures = SharedCacheMap->LazyWriteFailures;
        }

        CcRosDropFlushReference(SharedCacheMap, &OldIrql, CalledFromLazy || FlushAll);

        if (GiveUp)
        {
            /* Told outside the lock (the map may be gone: the name is a copy); the walk restarts below */
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            if (Discarded)
            {
                DPRINT1("CC: giving up the delayed write of a closed file (status 0x%08lx, %lu failures)\n",
                        Status, DiscardFailures);
                IoRaiseInformationalHardError(STATUS_LOST_WRITEBEHIND_DATA, &GiveUpName, NULL);
            }
            if (GiveUpName.Buffer)
                ExFreePoolWithTag(GiveUpName.Buffer, TAG_CC);
            RtlInitEmptyUnicodeString(&GiveUpName, NULL, 0);
            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        }

        if (!NT_SUCCESS(Status))
        {
            if ((Status != STATUS_END_OF_FILE) && (Status != STATUS_MEDIA_WRITE_PROTECTED))
                DPRINT1("CC: Failed to flush VACB.\n");

            /*
             * The view went back on the dirty list (at its tail), and the walk starts over.  The rest
             * of this map is left for the next call (its other views would fail the same way and wait
             * for the device each), and the views of the other maps are written: media that went away
             * must not hold the writing of the others up.  A call that finds many maps failing gives up.
             */
            if (FailedCount < CC_FLUSH_FAILED_MAPS)
                FailedMaps[FailedCount++] = SharedCacheMap;
            if (FailedCount >= CC_FLUSH_FAILED_MAPS || ++Failures >= 64)
                break;
        }
        else
        {
            ULONG PagesFreed;

            LapFlushed++;

            /* How many pages did we free? */
            PagesFreed = Iosb.Information / PAGE_SIZE;
            (*Count) += PagesFreed;

            if (!Wait)
            {
                /* Make sure we don't overflow target! */
                if (Target < PagesFreed)
                {
                    /* If we would have, jump to zero directly */
                    Target = 0;
                }
                else
                {
                    Target -= PagesFreed;
                }
            }
        }

        current_entry = DirtyVacbListHead.Flink;
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    KeLeaveCriticalRegion();

    if (TotalWaits != 0)
        DPRINT1("CC: the full flush waited %lu x 10 ms for the lazy writer%s\n", TotalWaits,
                BusyWaits > CC_FLUSHALL_BUSY_WAITS ? " and gave up (no progress for 10 s)" : "");

    DPRINT("CcRosFlushDirtyPages() finished\n");
    return STATUS_SUCCESS;
}

/*
 * Writes the dirty views of the map through Mm, without the file system's lazy write locks, as
 * CcRosDeleteFileCache does when it deletes a map; used by CcPurgeCacheSection for the caller that asked
 * to uninitialize the private cache maps.  The caller holds a reference on the map.
 */
VOID
CcRosFlushSharedCacheMapNoCallbacks(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap)
{
    LONGLONG Next = 0;

    for (;;)
    {
        KIRQL OldIrql;
        PLIST_ENTRY Entry;
        PROS_VACB Vacb = NULL;
        IO_STATUS_BLOCK Iosb;
        NTSTATUS Status;

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
        for (Entry = SharedCacheMap->CacheMapVacbListHead.Flink;
             Entry != &SharedCacheMap->CacheMapVacbListHead;
             Entry = Entry->Flink)
        {
            PROS_VACB Candidate = CONTAINING_RECORD(Entry, ROS_VACB, CacheMapVacbListEntry);

            if (Candidate->Dirty && Candidate->FileOffset.QuadPart >= Next)
            {
                Vacb = Candidate;
                CcRosVacbIncRefCount(Vacb);
                break;
            }
        }
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        if (!Vacb)
            break;

        Next = Vacb->FileOffset.QuadPart + VACB_MAPPING_GRANULARITY;
        Status = MmFlushSegment(SharedCacheMap->FileObject->SectionObjectPointer,
                                &Vacb->FileOffset,
                                VACB_MAPPING_GRANULARITY,
                                &Iosb);
        if (NT_SUCCESS(Status))
            CcRosUnmarkDirtyVacb(Vacb, TRUE);
        else
            DPRINT1("CC: Failed to flush a view before purging it. Status: 0x%08x\n", Status);

        /* The map still holds the view: not its last reference */
        CcRosVacbDecRefCount(Vacb);
    }
}

/*
 * Does the lazy writer have anything to write?  Dirty views of temporary files and of files that
 * disabled write-behind count in CcTotalDirtyPages, but the lazy writer skips them: it must not keep
 * scanning for them.  The Locked variant is for a caller that holds the master lock (and must decide
 * under it, or a dirty view added meanwhile finds the scan switched off).
 */
BOOLEAN
CcRosHasLazyWritableDataLocked(VOID)
{
    PLIST_ENTRY Entry;

    for (Entry = DirtyVacbListHead.Flink; Entry != &DirtyVacbListHead; Entry = Entry->Flink)
    {
        PROS_VACB Vacb = CONTAINING_RECORD(Entry, ROS_VACB, DirtyVacbListEntry);
        PROS_SHARED_CACHE_MAP SharedCacheMap = Vacb->SharedCacheMap;

        if (!BooleanFlagOn(SharedCacheMap->Flags, WRITEBEHIND_DISABLED) &&
            !BooleanFlagOn(SharedCacheMap->FileObject->Flags, FO_TEMPORARY_FILE))
        {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
CcRosHasLazyWritableData(VOID)
{
    KIRQL OldIrql;
    BOOLEAN Found;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    Found = CcRosHasLazyWritableDataLocked();
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    return Found;
}

VOID
CcRosTrimCache(
    _In_ ULONG Target,
    _Out_ PULONG NrFreed)
/*
 * FUNCTION: Try to free some memory from the file cache.
 * ARGUMENTS:
 *       Target - The number of pages to be freed.
 *       NrFreed - Points to a variable where the number of pages
 *                 actually freed is returned.
 */
{
    PLIST_ENTRY current_entry;
    PROS_VACB current;
    ULONG PagesFreed;
    KIRQL oldIrql;
    LIST_ENTRY FreeList;
    BOOLEAN FlushedPages = FALSE;

    DPRINT("CcRosTrimCache(Target %lu)\n", Target);

    InitializeListHead(&FreeList);

    *NrFreed = 0;

retry:
    oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    current_entry = VacbLruListHead.Flink;
    while (current_entry != &VacbLruListHead)
    {
        ULONG Refs;

        current = CONTAINING_RECORD(current_entry,
                                    ROS_VACB,
                                    VacbLruListEntry);

        KeAcquireSpinLockAtDpcLevel(&current->SharedCacheMap->CacheMapLock);

        /* Reference the VACB */
        CcRosVacbIncRefCount(current);

        /* Check if it's mapped and not dirty */
        if (InterlockedCompareExchange((PLONG)&current->MappedCount, 0, 0) > 0 && !current->Dirty)
        {
            /* This code is never executed. It is left for reference only. */
#if 1
            DPRINT1("MmPageOutPhysicalAddress unexpectedly called\n");
            ASSERT(FALSE);
#else
            ULONG i;
            PFN_NUMBER Page;

            /* We have to break these locks to call MmPageOutPhysicalAddress */
            KeReleaseSpinLockFromDpcLevel(&current->SharedCacheMap->CacheMapLock);
            KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

            /* Page out the VACB */
            for (i = 0; i < VACB_MAPPING_GRANULARITY / PAGE_SIZE; i++)
            {
                Page = (PFN_NUMBER)(MmGetPhysicalAddress((PUCHAR)current->BaseAddress + (i * PAGE_SIZE)).QuadPart >> PAGE_SHIFT);

                MmPageOutPhysicalAddress(Page);
            }

            /* Reacquire the locks */
            oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
            KeAcquireSpinLockAtDpcLevel(&current->SharedCacheMap->CacheMapLock);
#endif
        }

        /* Only keep iterating though the loop while the lock is held */
        current_entry = current_entry->Flink;

        /* Dereference the VACB */
        Refs = CcRosVacbDecRefCount(current);

        /* Check if we can free this entry now */
        if (Refs < 2)
        {
            ASSERT(!current->Dirty);
            ASSERT(!current->MappedCount);
            ASSERT(Refs == 1);

            if (current->SharedCacheMap->LastVacb == current)
                current->SharedCacheMap->LastVacb = NULL;
            RemoveEntryList(&current->CacheMapVacbListEntry);
            RemoveEntryList(&current->VacbLruListEntry);
            InitializeListHead(&current->VacbLruListEntry);
            InsertHeadList(&FreeList, &current->CacheMapVacbListEntry);

            /* Calculate how many pages we freed for Mm */
            PagesFreed = min(VACB_MAPPING_GRANULARITY / PAGE_SIZE, Target);
            Target -= PagesFreed;
            (*NrFreed) += PagesFreed;
        }

        KeReleaseSpinLockFromDpcLevel(&current->SharedCacheMap->CacheMapLock);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

    /* Try flushing pages if we haven't met our target */
    if ((Target > 0) && !FlushedPages)
    {
        /* Flush dirty pages to disk */
        CcRosFlushDirtyPages(Target, &PagesFreed, FALSE, FALSE);
        FlushedPages = TRUE;

        /* We can only swap as many pages as we flushed */
        if (PagesFreed < Target) Target = PagesFreed;

        /* Check if we flushed anything */
        if (PagesFreed != 0)
        {
            /* Try again after flushing dirty pages */
            DPRINT("Flushed %lu dirty cache pages to disk\n", PagesFreed);
            goto retry;
        }
    }

    while (!IsListEmpty(&FreeList))
    {
        ULONG Refs;

        current_entry = RemoveHeadList(&FreeList);
        current = CONTAINING_RECORD(current_entry,
                                    ROS_VACB,
                                    CacheMapVacbListEntry);
        InitializeListHead(&current->CacheMapVacbListEntry);
        Refs = CcRosVacbDecRefCount(current);
        ASSERT(Refs == 0);
    }

    DPRINT("Evicted %lu cache pages\n", (*NrFreed));
}

/*
 * Dirty pages a view is charged for: its pages below the end of file (at least one), not the whole
 * 256 KB view.  The pages of a view past the end of file are never written, and charging a small
 * file's view in full made a few thousand closed small files look like a cache full of dirty data,
 * which throttles writers (CcCanIWrite, Mm's page request pacing) although little is left to write.
 * The charge grows with the file (CcRosReleaseVacb).  Exact with the view's CacheMapLock held.
 */
static
ULONG
CcRosVacbFilePages(
    _In_ PROS_VACB Vacb)
{
    LONGLONG Bytes = Vacb->SharedCacheMap->FileSize.QuadPart - Vacb->FileOffset.QuadPart;

    if (Bytes >= VACB_MAPPING_GRANULARITY)
        return VACB_MAPPING_GRANULARITY / PAGE_SIZE;
    if (Bytes <= PAGE_SIZE)
        return 1;
    return (ULONG)BYTES_TO_PAGES(Bytes);
}

NTSTATUS
CcRosReleaseVacb (
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    PROS_VACB Vacb,
    BOOLEAN Dirty,
    BOOLEAN Mapped)
{
    ASSERT(SharedCacheMap);

    DPRINT("CcRosReleaseVacb(SharedCacheMap 0x%p, Vacb 0x%p)\n", SharedCacheMap, Vacb);

    /*
     * NOTE: Vacb->Dirty is read here without holding the spinlock as an
     * optimisation to avoid an unnecessary lock acquisition. The check may
     * race with a concurrent CcRosUnmarkDirtyVacb; however CcRosMarkDirtyVacb
     * re-checks Dirty under the lock and is a safe no-op if the VACB has
     * already been re-marked dirty by another thread in the meantime.
     * If Vacb->Dirty is TRUE at the check (so we skip marking) and a concurrent
     * flush then immediately unmarks it, that flush's MmFlushSegment call covers
     * all dirty section pages, including those written by the caller of this
     * function. Should that flush fail, CcRosFlushVacb re-marks the VACB dirty
     * (WasMarked == TRUE path), ensuring those pages are retried. No dirty data
     * can be silently lost through this race.
     */
    if (Dirty && !Vacb->Dirty)
    {
        CcRosMarkDirtyVacb(Vacb);
    }
    else if (Dirty && Vacb->DirtyPagesCharged < CcRosVacbFilePages(Vacb))
    {
        /* Written again while dirty: charge the pages the file grew into since */
        KIRQL OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
        if (Vacb->Dirty)
        {
            ULONG Pages = CcRosVacbFilePages(Vacb);
            if (Pages > Vacb->DirtyPagesCharged)
            {
                CcTotalDirtyPages += Pages - Vacb->DirtyPagesCharged;
                SharedCacheMap->DirtyPages += Pages - Vacb->DirtyPagesCharged;
                Vacb->DirtyPagesCharged = Pages;
            }
        }
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }

    if (Mapped)
    {
        if (InterlockedIncrement((PLONG)&Vacb->MappedCount) == 1)
        {
            CcRosVacbIncRefCount(Vacb);
        }
    }

    /*
     * Release the caller's reference. The return value may legitimately be 0
     * when CcRosDeleteFileCache has concurrently removed the cache-map-list
     * reference while we held a lookup reference: our decrement is then the
     * last one and CcRosVacbDecRefCount frees the VACB. That is safe because
     * callers (e.g. CcFlushCache) do not access the VACB pointer after this
     * call. Do NOT assert the result is > 0 here.
     */
    CcRosVacbDecRefCount(Vacb);

    return STATUS_SUCCESS;
}

/*
 * The view of the map that holds FileOffset, or NULL; the list is sorted by file offset.  *Previous is the last view that
 * starts before FileOffset (and does not hold it), for the sorted insert of a new view.  The walk starts at the nearest
 * of the head, the tail and the view the last lookup found (a reader or writer that goes on finds the next view at
 * once, where a walk from the head took as many steps as the file has views: 4096 for a 1 GB file), under the master
 * lock.  Both locks held.
 */
static
PROS_VACB
CcRosFindVacbLocked(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _In_ LONGLONG FileOffset,
    _Out_opt_ PROS_VACB *Previous)
{
    PLIST_ENTRY Head = &SharedCacheMap->CacheMapVacbListHead, Entry;
    PROS_VACB Current, Next, Start;
    LONGLONG Dist, D;

    if (Previous)
        *Previous = NULL;
    if (IsListEmpty(Head))
        return NULL;

    /* Start at the nearest of the first view, the last view and the last hit */
    Start = CONTAINING_RECORD(Head->Flink, ROS_VACB, CacheMapVacbListEntry);
    Dist = FileOffset - Start->FileOffset.QuadPart;
    if (Dist < 0)
        Dist = -Dist;
    Current = CONTAINING_RECORD(Head->Blink, ROS_VACB, CacheMapVacbListEntry);
    D = FileOffset - Current->FileOffset.QuadPart;
    if (D < 0)
        D = -D;
    if (D < Dist)
    {
        Start = Current;
        Dist = D;
    }
    if (SharedCacheMap->LastVacb != NULL)
    {
        D = FileOffset - SharedCacheMap->LastVacb->FileOffset.QuadPart;
        if (D < 0)
            D = -D;
        if (D <= Dist)
            Start = SharedCacheMap->LastVacb;
    }

    /* Find the last view that starts at or before FileOffset */
    Current = Start;
    if (Current->FileOffset.QuadPart <= FileOffset)
    {
        for (Entry = Current->CacheMapVacbListEntry.Flink; Entry != Head; Entry = Entry->Flink)
        {
            Next = CONTAINING_RECORD(Entry, ROS_VACB, CacheMapVacbListEntry);
            if (Next->FileOffset.QuadPart > FileOffset)
                break;
            Current = Next;
        }
    }
    else
    {
        Current = NULL;
        for (Entry = Start->CacheMapVacbListEntry.Blink; Entry != Head; Entry = Entry->Blink)
        {
            Next = CONTAINING_RECORD(Entry, ROS_VACB, CacheMapVacbListEntry);
            if (Next->FileOffset.QuadPart <= FileOffset)
            {
                Current = Next;
                break;
            }
        }
        if (Current == NULL)
            return NULL;
    }

    if (IsPointInRange(Current->FileOffset.QuadPart, VACB_MAPPING_GRANULARITY, FileOffset))
    {
        SharedCacheMap->LastVacb = Current;
        return Current;
    }
    if (Previous)
        *Previous = Current;
    return NULL;
}

/* Returns with VACB Lock Held! */
PROS_VACB
CcRosLookupVacb (
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    LONGLONG FileOffset)
{
    PROS_VACB current;
    KIRQL oldIrql;

    ASSERT(SharedCacheMap);

    DPRINT("CcRosLookupVacb(SharedCacheMap 0x%p, FileOffset %I64u)\n",
           SharedCacheMap, FileOffset);

    oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);

    current = CcRosFindVacbLocked(SharedCacheMap, FileOffset, NULL);
    if (current != NULL)
    {
        CcRosVacbIncRefCount(current);
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);
        return current;
    }

    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

    return NULL;
}

VOID
CcRosMarkDirtyVacb (
    PROS_VACB Vacb)
{
    KIRQL oldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    SharedCacheMap = Vacb->SharedCacheMap;

    oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);

    if (Vacb->Dirty)
    {
        /*
         * The VACB was already re-marked dirty by another thread between
         * CcRosUnmarkDirtyVacb and this call (e.g. a concurrent writer via
         * CcRosReleaseVacb) and the VACB has already been inserted into
         * the dirty list.
         */
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);
        return;
    }

    InsertTailList(&DirtyVacbListHead, &Vacb->DirtyVacbListEntry);
    Vacb->DirtySince = KeQueryInterruptTime();
    Vacb->DirtyPagesCharged = CcRosVacbFilePages(Vacb);
    CcTotalDirtyPages += Vacb->DirtyPagesCharged;
    Vacb->SharedCacheMap->DirtyPages += Vacb->DirtyPagesCharged;
    CcRosVacbIncRefCount(Vacb);

    /* Move to the tail of the LRU list */
    RemoveEntryList(&Vacb->VacbLruListEntry);
    InsertTailList(&VacbLruListHead, &Vacb->VacbLruListEntry);

    Vacb->Dirty = TRUE;

    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);

    /* Schedule a lazy writer run to now that we have dirty VACB */
    if (!LazyWriter.ScanActive)
    {
        CcScheduleLazyWriteScan(FALSE);
    }
    CcKickStreamingWriteBehind(Vacb->SharedCacheMap->DirtyPages);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);
}

BOOLEAN
CcRosUnmarkDirtyVacb (
    PROS_VACB Vacb,
    BOOLEAN LockViews)
{
    KIRQL oldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    SharedCacheMap = Vacb->SharedCacheMap;

    if (LockViews)
    {
        oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
    }

    if (!Vacb->Dirty)
    {
        ASSERT(LockViews);
        /*
         * The VACB was already unmarked by a concurrent flush (e.g. the lazy
         * writer) between the caller's lockless Dirty check and this call.
         * Proceeding would underflow CcTotalDirtyPages/DirtyPages, drop an
         * extra refcount, and could ultimately free the VACB prematurely.
         */
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

        return FALSE;
    }

    Vacb->Dirty = FALSE;

    RemoveEntryList(&Vacb->DirtyVacbListEntry);
    InitializeListHead(&Vacb->DirtyVacbListEntry);

    CcTotalDirtyPages -= Vacb->DirtyPagesCharged;
    Vacb->SharedCacheMap->DirtyPages -= Vacb->DirtyPagesCharged;
    Vacb->DirtyPagesCharged = 0;

    CcRosVacbDecRefCount(Vacb);

    if (LockViews)
    {
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);
    }

    return TRUE;
}

BOOLEAN
CcRosFreeOneUnusedVacb(
    VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY current_entry;
    PROS_VACB to_free = NULL;

    oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    /* Browse all the available VACB */
    current_entry = VacbLruListHead.Flink;
    while ((current_entry != &VacbLruListHead) && (to_free == NULL))
    {
        ULONG Refs;
        PROS_VACB current;

        current = CONTAINING_RECORD(current_entry,
                                    ROS_VACB,
                                    VacbLruListEntry);

        KeAcquireSpinLockAtDpcLevel(&current->SharedCacheMap->CacheMapLock);

        /* Only deal with unused VACB, we will free them */
        Refs = CcRosVacbGetRefCount(current);
        if (Refs < 2)
        {
            ASSERT(!current->Dirty);
            ASSERT(!current->MappedCount);
            ASSERT(Refs == 1);

            /* Reset it, this is the one we want to free */
            if (current->SharedCacheMap->LastVacb == current)
                current->SharedCacheMap->LastVacb = NULL;
            RemoveEntryList(&current->CacheMapVacbListEntry);
            InitializeListHead(&current->CacheMapVacbListEntry);
            RemoveEntryList(&current->VacbLruListEntry);
            InitializeListHead(&current->VacbLruListEntry);

            to_free = current;
        }

        KeReleaseSpinLockFromDpcLevel(&current->SharedCacheMap->CacheMapLock);

        current_entry = current_entry->Flink;
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

    /* And now, free the VACB that we found, if any. */
    if (to_free == NULL)
    {
        return FALSE;
    }

    /* This must be its last ref */
    NT_VERIFY(CcRosVacbDecRefCount(to_free) == 0);

    return TRUE;
}

static
NTSTATUS
CcRosCreateVacb (
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    LONGLONG FileOffset,
    PROS_VACB *Vacb)
{
    PROS_VACB current;
    PROS_VACB previous;
    NTSTATUS Status;
    KIRQL oldIrql;
    ULONG Refs;
    SIZE_T ViewSize = VACB_MAPPING_GRANULARITY;

    ASSERT(SharedCacheMap);

    DPRINT("CcRosCreateVacb()\n");

    current = ExAllocateFromNPagedLookasideList(&VacbLookasideList);
    if (!current)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    current->BaseAddress = NULL;
    current->Dirty = FALSE;
    current->PageOut = FALSE;
    current->FileOffset.QuadPart = ROUND_DOWN(FileOffset, VACB_MAPPING_GRANULARITY);
    current->SharedCacheMap = SharedCacheMap;
    current->MappedCount = 0;
    current->DirtyPagesCharged = 0;
    current->ReferenceCount = 0;
    InitializeListHead(&current->CacheMapVacbListEntry);
    InitializeListHead(&current->DirtyVacbListEntry);
    InitializeListHead(&current->VacbLruListEntry);

    CcRosVacbIncRefCount(current);

    while (TRUE)
    {
        /* Map VACB in system space */
        Status = MmMapViewInSystemSpaceEx(SharedCacheMap->Section, &current->BaseAddress, &ViewSize, &current->FileOffset, 0);
        if (NT_SUCCESS(Status))
        {
            break;
        }

        /*
         * If no space left, try to prune one unused VACB to recover space to map our VACB.
         * If it succeeds, retry to map, otherwise just fail.
         */
        if (!CcRosFreeOneUnusedVacb())
        {
            ExFreeToNPagedLookasideList(&VacbLookasideList, current);
            return Status;
        }
    }

#if DBG
    if (SharedCacheMap->Trace)
    {
        DPRINT1("CacheMap 0x%p: new VACB: 0x%p, file offset %I64d, BaseAddress %p\n",
                SharedCacheMap, current, current->FileOffset.QuadPart, current->BaseAddress);
    }
#endif

    oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    *Vacb = current;
    /* There is window between the call to CcRosLookupVacb
     * and CcRosCreateVacb. We must check if a VACB for the
     * file offset exist. If there is a VACB, we release
     * our newly created VACB and return the existing one.
     */
    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
    current = CcRosFindVacbLocked(SharedCacheMap, FileOffset, &previous);
    if (current != NULL)
    {
        CcRosVacbIncRefCount(current);
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
#if DBG
        if (SharedCacheMap->Trace)
        {
            DPRINT1("CacheMap 0x%p: deleting newly created VACB 0x%p ( found existing one 0x%p )\n",
                    SharedCacheMap,
                    (*Vacb),
                    current);
        }
#endif
        KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

        Refs = CcRosVacbDecRefCount(*Vacb);
        ASSERT(Refs == 0);

        *Vacb = current;
        return STATUS_SUCCESS;
    }
    /* There was no existing VACB. */
    current = *Vacb;
    if (previous)
    {
        InsertHeadList(&previous->CacheMapVacbListEntry, &current->CacheMapVacbListEntry);
    }
    else
    {
        InsertHeadList(&SharedCacheMap->CacheMapVacbListHead, &current->CacheMapVacbListEntry);
    }
    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
    InsertTailList(&VacbLruListHead, &current->VacbLruListEntry);
    SharedCacheMap->LastVacb = current;

    /* Reference it to allow release */
    CcRosVacbIncRefCount(current);

    KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

    return Status;
}

BOOLEAN
CcRosEnsureVacbResident(
    _In_ PROS_VACB Vacb,
    _In_ BOOLEAN Wait,
    _In_ BOOLEAN NoRead,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _In_ BOOLEAN WaitForPages
)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap = Vacb->SharedCacheMap;

    ASSERT((Offset + Length) <= VACB_MAPPING_GRANULARITY);

#if 0
    if ((Vacb->FileOffset.QuadPart + Offset) > SharedCacheMap->SectionSize.QuadPart)
    {
        DPRINT1("Vacb read beyond the file size!\n");
        return FALSE;
    }
#endif

    /* Check if the pages are resident */
    if (!MmIsDataSectionResident(SharedCacheMap->FileObject->SectionObjectPointer,
                                 Vacb->FileOffset.QuadPart + Offset,
                                 Length))
    {
        if (!Wait)
        {
            return FALSE;
        }

        if (!NoRead)
        {
            NTSTATUS Status = MmMakeDataSectionResident(SharedCacheMap->FileObject->SectionObjectPointer,
                                                        Vacb->FileOffset.QuadPart + Offset,
                                                        Length,
                                                        &SharedCacheMap->ValidDataLength,
                                                        WaitForPages);
            if (!NT_SUCCESS(Status))
                ExRaiseStatus(Status);
        }
    }

    /* The pages the caller goes on to touch: map them in one pass, instead of a fault each */
    if (Vacb->BaseAddress != NULL && Length >= PAGE_SIZE && KeGetCurrentIrql() <= APC_LEVEL)
        MmMapResidentSystemViewPages((PUCHAR)Vacb->BaseAddress + Offset, Length);

    return TRUE;
}


NTSTATUS
CcRosGetVacb (
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    LONGLONG FileOffset,
    PROS_VACB *Vacb)
{
    PROS_VACB current;
    NTSTATUS Status;
    ULONG Refs;
    KIRQL OldIrql;

    ASSERT(SharedCacheMap);

    DPRINT("CcRosGetVacb()\n");

    /*
     * Look for a VACB already mapping the same data.
     */
    current = CcRosLookupVacb(SharedCacheMap, FileOffset);
    if (current == NULL)
    {
        /*
         * Otherwise create a new VACB.
         */
        Status = CcRosCreateVacb(SharedCacheMap, FileOffset, &current);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    /* A view parked when its file was closed (CcRosParkViews) is mapped again */
    if (current->BaseAddress == NULL)
    {
        PVOID BaseAddress = NULL;
        SIZE_T ViewSize = VACB_MAPPING_GRANULARITY;
        LARGE_INTEGER ViewOffset = current->FileOffset;

        while (TRUE)
        {
            Status = MmMapViewInSystemSpaceEx(SharedCacheMap->Section, &BaseAddress, &ViewSize, &ViewOffset, 0);
            if (NT_SUCCESS(Status))
                break;
            if (!CcRosFreeOneUnusedVacb())
            {
                /* The map holds the view too: this is not its last reference */
                CcRosVacbDecRefCount(current);
                return Status;
            }
        }

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
        if (current->BaseAddress == NULL)
        {
            current->BaseAddress = BaseAddress;
            BaseAddress = NULL;
        }
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        /* Another thread mapped it meanwhile */
        if (BaseAddress)
            MmUnmapViewInSystemSpace(BaseAddress);
    }

    Refs = CcRosVacbGetRefCount(current);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    /* Move to the tail of the LRU list */
    RemoveEntryList(&current->VacbLruListEntry);
    InsertTailList(&VacbLruListHead, &current->VacbLruListEntry);

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    /*
     * Return the VACB to the caller.
     */
    *Vacb = current;

    ASSERT(Refs > 1);

    return STATUS_SUCCESS;
}

NTSTATUS
CcRosRequestVacb (
    PROS_SHARED_CACHE_MAP SharedCacheMap,
    LONGLONG FileOffset,
    PROS_VACB *Vacb)
/*
 * FUNCTION: Request a page mapping for a shared cache map
 */
{

    ASSERT(SharedCacheMap);

    if (FileOffset % VACB_MAPPING_GRANULARITY != 0)
    {
        DPRINT1("Bad FileOffset %I64x: should be multiple of %x\n",
                FileOffset, VACB_MAPPING_GRANULARITY);
        KeBugCheck(CACHE_MANAGER);
    }

    return CcRosGetVacb(SharedCacheMap,
                        FileOffset,
                        Vacb);
}

NTSTATUS
CcRosInternalFreeVacb (
    PROS_VACB Vacb)
/*
 * FUNCTION: Releases a VACB associated with a shared cache map
 */
{
    NTSTATUS Status;

    DPRINT("Freeing VACB 0x%p\n", Vacb);
#if DBG
    if (Vacb->SharedCacheMap->Trace)
    {
        DPRINT1("CacheMap 0x%p: deleting VACB: 0x%p\n", Vacb->SharedCacheMap, Vacb);
    }
#endif

    if (Vacb->ReferenceCount != 0)
    {
        DPRINT1("Invalid free: %ld\n", Vacb->ReferenceCount);
        if (Vacb->SharedCacheMap->FileObject && Vacb->SharedCacheMap->FileObject->FileName.Length)
        {
            DPRINT1("For file: %wZ\n", &Vacb->SharedCacheMap->FileObject->FileName);
        }
    }

    ASSERT(Vacb->ReferenceCount == 0);
    ASSERT(IsListEmpty(&Vacb->CacheMapVacbListEntry));
    ASSERT(IsListEmpty(&Vacb->DirtyVacbListEntry));
    ASSERT(IsListEmpty(&Vacb->VacbLruListEntry));

    /* Delete the mapping (a parked view has none, see CcRosParkViews) */
    Status = Vacb->BaseAddress ? MmUnmapViewInSystemSpace(Vacb->BaseAddress) : STATUS_SUCCESS;
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to unmap VACB from System address space! Status 0x%08X\n", Status);
        ASSERT(FALSE);
        /* Proceed with the deĺetion anyway */
    }

    RtlFillMemory(Vacb, sizeof(*Vacb), 0xfd);
    ExFreeToNPagedLookasideList(&VacbLookasideList, Vacb);
    return STATUS_SUCCESS;
}

VOID
CcRosDereferenceFlushedCacheMap(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap)
{
    KIRQL OldIrql;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    if (--SharedCacheMap->OpenCount == 0)
        CcRosDeleteOrDeferFileCache(SharedCacheMap, &OldIrql);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
}

/*
 * Hand the last reference of a flush to a Cc worker thread, so that waiting for the lazy
 * writer's activity also waits for it. The entry is part of the map: only the reference that
 * is handed over can post it, so it is never queued twice.
 */
static
VOID
CcpPostFlushDereference(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap)
{
    PWORK_QUEUE_ENTRY WorkItem = &SharedCacheMap->FlushDereferenceEntry;

    WorkItem->Function = DereferenceSharedMap;
    WorkItem->Parameters.Write.SharedCacheMap = (PVOID)SharedCacheMap;
    CcPostWorkQueue(WorkItem, &CcRegularWorkQueue);
}

/*
 * A temporary reference on the shared cache map of a section, for a Cc call on a file object that may
 * hold no private cache map (a flush, purge, size change or zeroing through any handle): a map nobody
 * has open stays alive until the lazy writer wrote its dirty data, and is then deleted by the lazy writer
 * without any file system lock, so such a call must keep it alive itself.  NULL if there is no map.
 */
PROS_SHARED_CACHE_MAP
CcRosReferenceSharedCacheMap(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointers)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    KIRQL OldIrql;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    SharedCacheMap = SectionObjectPointers->SharedCacheMap;
    if (SharedCacheMap)
        SharedCacheMap->OpenCount++;
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    return SharedCacheMap;
}

/*
 * Drops a reference of CcRosReferenceSharedCacheMap.  A worker drops the last one: deleting the map
 * releases its file object, and the close that follows must not run here, where the caller may hold
 * file system locks.
 */
VOID
CcRosDereferenceSharedCacheMap(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap)
{
    KIRQL OldIrql;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    if (SharedCacheMap->OpenCount > 1)
    {
        SharedCacheMap->OpenCount--;
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }
    else
    {
        ASSERT(SharedCacheMap->OpenCount == 1);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        CcpPostFlushDereference(SharedCacheMap);
    }
}

/*
 * @implemented
 */
VOID
NTAPI
CcFlushCache (
    IN PSECTION_OBJECT_POINTERS SectionObjectPointers,
    IN PLARGE_INTEGER FileOffset OPTIONAL,
    IN ULONG Length,
    OUT PIO_STATUS_BLOCK IoStatus)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    LONGLONG FlushStart, FlushEnd;
    NTSTATUS Status;

    CCTRACE(CC_API_DEBUG, "SectionObjectPointers=%p FileOffset=0x%I64X Length=%lu\n",
        SectionObjectPointers, FileOffset ? FileOffset->QuadPart : 0LL, Length);

    if (!SectionObjectPointers)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto quit;
    }

    /*
     * Reference the shared cache map for the flush: a close of the last cached handle or the
     * lazy writer's dereference can otherwise delete the map while the flush uses it.
     */
    SharedCacheMap = CcRosReferenceSharedCacheMap(SectionObjectPointers);

    if (!SharedCacheMap)
    {
        /* Forward this to Mm */
        MmFlushSegment(SectionObjectPointers, FileOffset, Length, IoStatus);
        return;
    }

    if (FileOffset)
    {
        FlushStart = FileOffset->QuadPart;
        Status = RtlLongLongAdd(FlushStart, Length, &FlushEnd);
        if (!NT_SUCCESS(Status))
            goto dereference;
    }
    else
    {
        FlushStart = 0;
        FlushEnd = SharedCacheMap->FileSize.QuadPart;
    }

    Status = STATUS_SUCCESS;
    if (IoStatus)
    {
        IoStatus->Information = 0;
    }

    KeAcquireGuardedMutex(&SharedCacheMap->FlushCacheLock);

    /*
     * We flush the VACBs that we find here.
     * If there is no (dirty) VACB, it doesn't mean that there is no data to flush, so we call Mm to be sure.
     * This is suboptimal, but this is due to the lack of granularity of how we track dirty cache data
     */
    while (FlushStart < FlushEnd)
    {
        BOOLEAN DirtyVacb = FALSE;
        PROS_VACB vacb = CcRosLookupVacb(SharedCacheMap, FlushStart);

        if (vacb != NULL)
        {
            /*
             * NOTE: vacb->Dirty is read here without holding the spinlock.
             * The lock was released by CcRosLookupVacb before returning. A
             * concurrent flush (lazy writer) may therefore clear Dirty between
             * this check and the CcRosFlushVacb call below. CcRosFlushVacb
             * handles this safely via the guarded CcRosUnmarkDirtyVacb path.
             */
            if (vacb->Dirty)
            {
                IO_STATUS_BLOCK VacbIosb = { 0 };
                Status = CcRosFlushVacb(vacb, &VacbIosb);
                if (!NT_SUCCESS(Status))
                {
                    CcRosReleaseVacb(SharedCacheMap, vacb, FALSE, FALSE);
                    break;
                }
                DirtyVacb = TRUE;

                if (IoStatus)
                    IoStatus->Information += VacbIosb.Information;
            }

            CcRosReleaseVacb(SharedCacheMap, vacb, FALSE, FALSE);
        }

        if (!DirtyVacb)
        {
            IO_STATUS_BLOCK MmIosb;
            LARGE_INTEGER MmOffset;

            MmOffset.QuadPart = FlushStart;

            if (FlushEnd - (FlushEnd % VACB_MAPPING_GRANULARITY) <= FlushStart)
            {
                /* The whole range fits within a VACB chunk. */
                Status = MmFlushSegment(SectionObjectPointers, &MmOffset, FlushEnd - FlushStart, &MmIosb);
            }
            else
            {
                ULONG MmLength = VACB_MAPPING_GRANULARITY - (FlushStart % VACB_MAPPING_GRANULARITY);
                Status = MmFlushSegment(SectionObjectPointers, &MmOffset, MmLength, &MmIosb);
            }

            if (!NT_SUCCESS(Status))
                break;

            if (IoStatus)
                IoStatus->Information += MmIosb.Information;

            CcRosRaiseValidDataLength(SharedCacheMap, FlushEnd);
        }

        if (!NT_SUCCESS(RtlLongLongAdd(FlushStart, VACB_MAPPING_GRANULARITY, &FlushStart)))
        {
            /* We're at the end of file ! */
            break;
        }

        /* Round down to next VACB start now */
        FlushStart -= FlushStart % VACB_MAPPING_GRANULARITY;
    }

    KeReleaseGuardedMutex(&SharedCacheMap->FlushCacheLock);

dereference:
    CcRosDereferenceSharedCacheMap(SharedCacheMap);

quit:
    if (IoStatus)
    {
        IoStatus->Status = Status;
    }
}

/*
 * A map left to the lazy writer at its last close keeps its views, but nobody uses them: the lazy writer
 * writes through Mm by file offset, and the dirty state of the pages is in the segment (Cc marks it there
 * when it copies, zeroes or pins).  Their mappings are taken away (the view's BaseAddress becomes NULL;
 * CcRosGetVacb maps it again if the file is used again), so that thousands of closed files waiting for the
 * lazy writer do not hold thousands of 256 KB system views: views are kernel memory areas, and the gap
 * search for a new one is linear in their number.  Only idle views (no user beyond the map and its dirty
 * list, not mapped for a BCB); each is referenced until the caller unmapped it (CcRosUnparkViews).
 * Called with the master lock held; returns the number of views taken (at most Max).
 */
#define CC_PARK_BATCH 16
static
ULONG
CcRosParkViews(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _Out_writes_(Max) PROS_VACB *Vacbs,
    _Out_writes_(Max) PVOID *BaseAddresses,
    _In_ ULONG Max)
{
    PLIST_ENTRY Entry;
    ULONG Count = 0;

    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
    for (Entry = SharedCacheMap->CacheMapVacbListHead.Flink;
         Entry != &SharedCacheMap->CacheMapVacbListHead && Count < Max;
         Entry = Entry->Flink)
    {
        PROS_VACB Vacb = CONTAINING_RECORD(Entry, ROS_VACB, CacheMapVacbListEntry);

        if (Vacb->BaseAddress == NULL || Vacb->MappedCount != 0 ||
            CcRosVacbGetRefCount(Vacb) != (Vacb->Dirty ? 2 : 1))
        {
            continue;
        }

        BaseAddresses[Count] = Vacb->BaseAddress;
        Vacb->BaseAddress = NULL;
        CcRosVacbIncRefCount(Vacb);
        Vacbs[Count++] = Vacb;
    }
    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);

    return Count;
}

/* Unmaps what CcRosParkViews took and drops its references; master lock not held */
static
VOID
CcRosUnparkViews(
    _In_reads_(Count) PROS_VACB *Vacbs,
    _In_reads_(Count) PVOID *BaseAddresses,
    _In_ ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        MmUnmapViewInSystemSpace(BaseAddresses[i]);
        CcRosVacbDecRefCount(Vacbs[i]);
    }
}

/*
 * UninitializeCompleteEvent is signalled when the shared cache map is deleted, as on Windows.  Queued
 * on a map that stays for now (the lazy writer, a flush or a purge still use it): the map is then
 * deleted by whoever drops its last reference, at once (SYNC_DELETE: not deferred, it flushes what is
 * dirty itself), and wakes the waiter.  Master lock held.
 */
static
VOID
CcRosQueueUninitializeEvent(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _In_ PCACHE_UNINITIALIZE_EVENT UninitializeCompleteEvent)
{
    UninitializeCompleteEvent->Next = SharedCacheMap->UninitializeEvents;
    SharedCacheMap->UninitializeEvents = UninitializeCompleteEvent;
    SharedCacheMap->Flags |= SHARED_CACHE_MAP_SYNC_DELETE;
}

/*
 * A file system that is written for it (it keeps its SectionObjectPointers and lazy write context valid
 * until the file object it cached through is closed, which the map's reference delays until the map is
 * deleted) lets the last close of a file leave the dirty data to the lazy writer: the map is then kept,
 * closed, until it is written.  Call it after CcInitializeCacheMap, for the file objects of files.  Without it the last close writes
 * the data and deletes the map, as it always did.
 */
VOID
NTAPI
CcRosAllowLazyClose (
    _In_ PFILE_OBJECT FileObject)
{
    KIRQL OldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    /*
     * Not for stream file objects (the file system's directories, volume file and the like): their
     * FCBs are torn down by the file system itself, not by the close of a file object, and then
     * nothing would keep a deferred map's SectionObjectPointers and context valid.
     */
    if (FileObject->Flags & FO_STREAM_FILE)
        return;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    if (SharedCacheMap)
        SharedCacheMap->Flags |= SHARED_CACHE_MAP_LAZY_CLOSE;
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
}

NTSTATUS
CcRosReleaseFileCache (
    _In_ PFILE_OBJECT FileObject,
    _In_ BOOLEAN AllowDeferredDelete,
    _In_opt_ PCACHE_UNINITIALIZE_EVENT UninitializeCompleteEvent,
    _Out_opt_ PBOOLEAN EventQueued)
/*
 * FUNCTION: Called by the file system when a handle to a file object
 * has been closed.
 * With AllowDeferredDelete, the last close of a map with dirty data leaves the map to the lazy
 * writer when the file system allows it (see CcRosDeleteOrDeferFileCache).  Otherwise (a truncation,
 * or somebody waits for the deletion) the map is deleted now, writing what is still dirty, as before.
 * UninitializeCompleteEvent is queued on the map if it is not deleted by this (*EventQueued is set);
 * the caller signals it itself otherwise.
 */
{
    KIRQL OldIrql;
    PPRIVATE_CACHE_MAP PrivateMap;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    PROS_VACB ParkedVacbs[CC_PARK_BATCH];
    PVOID ParkedViews[CC_PARK_BATCH];
    ULONG Parked = 0;

    if (EventQueued)
        *EventQueued = FALSE;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    if (FileObject->SectionObjectPointer->SharedCacheMap != NULL)
    {
        SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;

        /* Closing the handle, so kill the private cache map
         * Before you event try to remove it from FO, always
         * lock the master lock, to be sure not to race
         * with a potential read ahead ongoing!
         */
        PrivateMap = FileObject->PrivateCacheMap;
        FileObject->PrivateCacheMap = NULL;

        if (PrivateMap != NULL)
        {
            /* Remove it from the file */
            KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
            RemoveEntryList(&PrivateMap->PrivateLinks);
            KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);

            /* And free it. */
            if (PrivateMap != &SharedCacheMap->PrivateCacheMap)
            {
                ExFreePoolWithTag(PrivateMap, TAG_PRIVATE_CACHE_MAP);
            }
            else
            {
                PrivateMap->NodeTypeCode = 0;
            }

            ASSERT(SharedCacheMap->OpenCount > 0);

            SharedCacheMap->OpenCount--;
            if (SharedCacheMap->OpenCount == 0)
            {
                if (!AllowDeferredDelete)
                {
                    CcRosDeleteFileCache(FileObject, SharedCacheMap, &OldIrql);
                }
                else if (!CcRosDeleteOrDeferFileCache(SharedCacheMap, &OldIrql))
                {
                    /* Left to the lazy writer */
                    Parked = CcRosParkViews(SharedCacheMap, ParkedVacbs, ParkedViews, CC_PARK_BATCH);
                }
            }
            else if (UninitializeCompleteEvent && IsListEmpty(&SharedCacheMap->PrivateList))
            {
                /* Nobody caches through the map any more, but something still uses it: wait for that */
                CcRosQueueUninitializeEvent(SharedCacheMap, UninitializeCompleteEvent);
                *EventQueued = TRUE;
            }
        }
        else if (UninitializeCompleteEvent && IsListEmpty(&SharedCacheMap->PrivateList) &&
                 !(SharedCacheMap->Flags & SHARED_CACHE_MAP_IN_CREATION))
        {
            /*
             * This file object caches nothing, but its file's map is still there, closed: left to the
             * lazy writer, or in use by it.  The caller waits for the map to go before it frees what it
             * points to, and may hold the locks the lazy writer needs: delete it now when nothing uses
             * it, write what is dirty, as it always was done.
             */
            if (SharedCacheMap->OpenCount == 0)
            {
                SharedCacheMap->Flags |= SHARED_CACHE_MAP_SYNC_DELETE;
                CcRosDeleteFileCache(SharedCacheMap->FileObject, SharedCacheMap, &OldIrql);
            }
            else
            {
                CcRosQueueUninitializeEvent(SharedCacheMap, UninitializeCompleteEvent);
                *EventQueued = TRUE;
            }
        }
    }
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    CcRosUnparkViews(ParkedVacbs, ParkedViews, Parked);
    return STATUS_SUCCESS;
}

NTSTATUS
CcRosInitializeFileCache (
    PFILE_OBJECT FileObject,
    PCC_FILE_SIZES FileSizes,
    BOOLEAN PinAccess,
    PCACHE_MANAGER_CALLBACKS CallBacks,
    PVOID LazyWriterContext)
/*
 * FUNCTION: Initializes a shared cache map for a file object
 */
{
    KIRQL OldIrql;
    BOOLEAN Allocated;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    DPRINT("CcRosInitializeFileCache(FileObject 0x%p)\n", FileObject);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    Allocated = FALSE;
    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    if (SharedCacheMap == NULL)
    {
        SharedCacheMap = ExAllocateFromNPagedLookasideList(&SharedCacheMapLookasideList);
        if (SharedCacheMap == NULL)
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(SharedCacheMap, sizeof(*SharedCacheMap));
        SharedCacheMap->NodeTypeCode = NODE_TYPE_SHARED_MAP;
        SharedCacheMap->NodeByteSize = sizeof(*SharedCacheMap);
        SharedCacheMap->FileObject = FileObject;
        SharedCacheMap->Callbacks = CallBacks;
        SharedCacheMap->LazyWriteContext = LazyWriterContext;
        SharedCacheMap->SectionSize = FileSizes->AllocationSize;
        SharedCacheMap->FileSize = FileSizes->FileSize;
        SharedCacheMap->ValidDataLength = FileSizes->ValidDataLength;
        SharedCacheMap->PinAccess = PinAccess;
        SharedCacheMap->DirtyPageThreshold = 0;
        SharedCacheMap->DirtyPages = 0;
        InitializeListHead(&SharedCacheMap->PrivateList);
        KeInitializeSpinLock(&SharedCacheMap->CacheMapLock);
        InitializeListHead(&SharedCacheMap->CacheMapVacbListHead);
        InitializeListHead(&SharedCacheMap->BcbList);
        KeInitializeGuardedMutex(&SharedCacheMap->FlushCacheLock);

        SharedCacheMap->Flags = SHARED_CACHE_MAP_IN_CREATION;

        ObReferenceObjectByPointer(FileObject,
                                   FILE_ALL_ACCESS,
                                   NULL,
                                   KernelMode);

        Allocated = TRUE;
        FileObject->SectionObjectPointer->SharedCacheMap = SharedCacheMap;

        //CcRosTraceCacheMap(SharedCacheMap, TRUE);
    }
    else if (SharedCacheMap->Flags & SHARED_CACHE_MAP_IN_CREATION)
    {
        /* The shared cache map is being created somewhere else. Wait for that to happen */
        KEVENT Waiter;
        PKEVENT PreviousWaiter = SharedCacheMap->CreateEvent;

        KeInitializeEvent(&Waiter, NotificationEvent, FALSE);
        SharedCacheMap->CreateEvent = &Waiter;

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        KeWaitForSingleObject(&Waiter, Executive, KernelMode, FALSE, NULL);

        if (PreviousWaiter)
            KeSetEvent(PreviousWaiter, IO_NO_INCREMENT, FALSE);

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    }

    if (FileObject->PrivateCacheMap == NULL)
    {
        PPRIVATE_CACHE_MAP PrivateMap;

        /* Allocate the private cache map for this handle */
        if (SharedCacheMap->PrivateCacheMap.NodeTypeCode != 0)
        {
            PrivateMap = ExAllocatePoolWithTag(NonPagedPool, sizeof(PRIVATE_CACHE_MAP), TAG_PRIVATE_CACHE_MAP);
        }
        else
        {
            PrivateMap = &SharedCacheMap->PrivateCacheMap;
        }

        if (PrivateMap == NULL)
        {
            /* If we also allocated the shared cache map for this file, kill it */
            if (Allocated)
            {
                RemoveEntryList(&SharedCacheMap->SharedCacheMapLinks);

                FileObject->SectionObjectPointer->SharedCacheMap = NULL;
                ObDereferenceObject(FileObject);
                ExFreeToNPagedLookasideList(&SharedCacheMapLookasideList, SharedCacheMap);
            }

            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Initialize it */
        RtlZeroMemory(PrivateMap, sizeof(PRIVATE_CACHE_MAP));
        PrivateMap->NodeTypeCode = NODE_TYPE_PRIVATE_MAP;
        PrivateMap->ReadAheadMask = PAGE_SIZE - 1;
        PrivateMap->FileObject = FileObject;
        KeInitializeSpinLock(&PrivateMap->ReadAheadSpinLock);

        /* Link it to the file */
        KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
        InsertTailList(&SharedCacheMap->PrivateList, &PrivateMap->PrivateLinks);
        KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);

        FileObject->PrivateCacheMap = PrivateMap;
        SharedCacheMap->OpenCount++;

        /* Open again: no longer a closed map waiting for the lazy writer */
        if (SharedCacheMap->Flags & SHARED_CACHE_MAP_DEFERRED)
        {
            CcDeferredVacbs -= SharedCacheMap->DeferredVacbs;
            SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_DEFERRED;

            /*
             * The map lived on from the last close: the file system's file size and valid data length are
             * the current ones (they may have changed while nobody cached through the map).  Only the values
             * are taken over, here under the lock: a size that needs the section extended or pages purged
             * comes with the file system's own CcSetFileSizes (calling it from here, with the caller's locks
             * held, could wait for a page-in that needs them).  A larger file size only, never past the
             * section; the valid data length never past the file size.
             */
            KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
            if (FileSizes->FileSize.QuadPart > SharedCacheMap->FileSize.QuadPart &&
                FileSizes->FileSize.QuadPart <= SharedCacheMap->SectionSize.QuadPart)
            {
                SharedCacheMap->FileSize = FileSizes->FileSize;
            }
            SharedCacheMap->ValidDataLength.QuadPart = min(FileSizes->ValidDataLength.QuadPart,
                                                           SharedCacheMap->FileSize.QuadPart);
            KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
        }
        SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_DISCARD;
        SharedCacheMap->LazyWriteFailures = 0;
        /* Nobody waits for the deletion any more: deferrable again at the next last close */
        if (!SharedCacheMap->UninitializeEvents)
            SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_SYNC_DELETE;
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    /* Create the section */
    if (Allocated)
    {
        NTSTATUS Status;

        ASSERT(SharedCacheMap->Section == NULL);

        Status = MmCreateSection(
            &SharedCacheMap->Section,
            SECTION_ALL_ACCESS,
            NULL,
            &SharedCacheMap->SectionSize,
            PAGE_READWRITE,
            SEC_RESERVE,
            NULL,
            FileObject);

        ASSERT(NT_SUCCESS(Status));

        if (!NT_SUCCESS(Status))
        {
            CcRosReleaseFileCache(FileObject, FALSE, NULL, NULL);
            return Status;
        }

        MmMarkCacheSection(SharedCacheMap->Section);

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        InsertTailList(&CcCleanSharedCacheMapList, &SharedCacheMap->SharedCacheMapLinks);
        SharedCacheMap->Flags &= ~SHARED_CACHE_MAP_IN_CREATION;

        if (SharedCacheMap->CreateEvent)
        {
            KeSetEvent(SharedCacheMap->CreateEvent, IO_NO_INCREMENT, FALSE);
            SharedCacheMap->CreateEvent = NULL;
        }

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
PFILE_OBJECT
NTAPI
CcGetFileObjectFromSectionPtrs (
    IN PSECTION_OBJECT_POINTERS SectionObjectPointers)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "SectionObjectPointers=%p\n", SectionObjectPointers);

    if (SectionObjectPointers && SectionObjectPointers->SharedCacheMap)
    {
        SharedCacheMap = SectionObjectPointers->SharedCacheMap;
        ASSERT(SharedCacheMap);
        return SharedCacheMap->FileObject;
    }
    return NULL;
}

CODE_SEG("INIT")
VOID
NTAPI
CcInitView (
    VOID)
{
    DPRINT("CcInitView()\n");

    InitializeListHead(&DirtyVacbListHead);
    InitializeListHead(&VacbLruListHead);
    InitializeListHead(&CcDeferredWrites);
    InitializeListHead(&CcCleanSharedCacheMapList);
    InitializeListHead(&CcDyingSharedCacheMapList);
    KeInitializeSpinLock(&CcDeferredWriteSpinLock);
    ExInitializeNPagedLookasideList(&iBcbLookasideList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(INTERNAL_BCB),
                                    TAG_BCB,
                                    20);
    ExInitializeNPagedLookasideList(&SharedCacheMapLookasideList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(ROS_SHARED_CACHE_MAP),
                                    TAG_SHARED_CACHE_MAP,
                                    20);
    ExInitializeNPagedLookasideList(&VacbLookasideList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(ROS_VACB),
                                    TAG_VACB,
                                    20);

    CcInitCacheZeroPage();
}

#if DBG && defined(KDBG)

#include <kdbg/kdb.h>

BOOLEAN
ExpKdbgExtFileCache(ULONG Argc, PCHAR Argv[])
{
    PLIST_ENTRY ListEntry;
    UNICODE_STRING NoName = RTL_CONSTANT_STRING(L"No name for File");

    KdbpPrint("  Usage Summary (in kb)\n");
    KdbpPrint("Shared\t\tMapped\tDirty\tName\n");
    /* No need to lock the spin lock here, we're in DBG */
    for (ListEntry = CcCleanSharedCacheMapList.Flink;
         ListEntry != &CcCleanSharedCacheMapList;
         ListEntry = ListEntry->Flink)
    {
        PLIST_ENTRY Vacbs;
        ULONG Mapped = 0, Dirty = 0;
        PROS_SHARED_CACHE_MAP SharedCacheMap;
        PUNICODE_STRING FileName;
        PWSTR Extra = L"";

        SharedCacheMap = CONTAINING_RECORD(ListEntry, ROS_SHARED_CACHE_MAP, SharedCacheMapLinks);

        /* Dirty size */
        Dirty = (SharedCacheMap->DirtyPages * PAGE_SIZE) / 1024;

        /* First, count for all the associated VACB */
        for (Vacbs = SharedCacheMap->CacheMapVacbListHead.Flink;
             Vacbs != &SharedCacheMap->CacheMapVacbListHead;
             Vacbs = Vacbs->Flink)
        {
            Mapped += VACB_MAPPING_GRANULARITY / 1024;
        }

        /* Setup name */
        if (SharedCacheMap->FileObject != NULL &&
            SharedCacheMap->FileObject->FileName.Length != 0)
        {
            FileName = &SharedCacheMap->FileObject->FileName;
        }
        else if (SharedCacheMap->FileObject != NULL &&
                 SharedCacheMap->FileObject->FsContext != NULL &&
                 ((PFSRTL_COMMON_FCB_HEADER)(SharedCacheMap->FileObject->FsContext))->NodeTypeCode == 0x0502 &&
                 ((PFSRTL_COMMON_FCB_HEADER)(SharedCacheMap->FileObject->FsContext))->NodeByteSize == 0x1F8 &&
                 ((PUNICODE_STRING)(((PUCHAR)SharedCacheMap->FileObject->FsContext) + 0x100))->Length != 0)
        {
            FileName = (PUNICODE_STRING)(((PUCHAR)SharedCacheMap->FileObject->FsContext) + 0x100);
            Extra = L" (FastFAT)";
        }
        else
        {
            FileName = &NoName;
        }

        /* And print */
        KdbpPrint("%p\t%d\t%d\t%wZ%S\n", SharedCacheMap, Mapped, Dirty, FileName, Extra);
    }

    return TRUE;
}

BOOLEAN
ExpKdbgExtDefWrites(ULONG Argc, PCHAR Argv[])
{
    KdbpPrint("CcTotalDirtyPages:\t%lu (%lu Kb)\n", CcTotalDirtyPages,
              (CcTotalDirtyPages * PAGE_SIZE) / 1024);
    KdbpPrint("CcDirtyPageThreshold:\t%lu (%lu Kb)\n", CcDirtyPageThreshold,
              (CcDirtyPageThreshold * PAGE_SIZE) / 1024);
    KdbpPrint("MmAvailablePages:\t%lu (%lu Kb)\n", MmAvailablePages,
              (MmAvailablePages * PAGE_SIZE) / 1024);
    KdbpPrint("MmThrottleTop:\t\t%lu (%lu Kb)\n", MmThrottleTop,
              (MmThrottleTop * PAGE_SIZE) / 1024);
    KdbpPrint("MmThrottleBottom:\t%lu (%lu Kb)\n", MmThrottleBottom,
              (MmThrottleBottom * PAGE_SIZE) / 1024);
    KdbpPrint("MmModifiedPageListHead.Total:\t%lu (%lu Kb)\n", MmModifiedPageListHead.Total,
              (MmModifiedPageListHead.Total * PAGE_SIZE) / 1024);

    if (CcTotalDirtyPages >= CcDirtyPageThreshold)
    {
        KdbpPrint("CcTotalDirtyPages above the threshold, writes should be throttled\n");
    }
    else if (CcTotalDirtyPages + 64 >= CcDirtyPageThreshold)
    {
        KdbpPrint("CcTotalDirtyPages within 64 (max charge) pages of the threshold, writes may be throttled\n");
    }
    else
    {
        KdbpPrint("CcTotalDirtyPages below the threshold, writes should not be throttled\n");
    }

    return TRUE;
}

#endif // DBG && defined(KDBG)

/* EOF */
