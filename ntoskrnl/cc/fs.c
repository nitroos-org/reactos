/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/fs.c
 * PURPOSE:         Implements cache managers functions useful for File Systems
 *
 * PROGRAMMERS:     Alex Ionescu
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS *****************************************************************/

/*
 * @unimplemented
 */
LARGE_INTEGER
NTAPI
CcGetDirtyPages (
    IN PVOID LogHandle,
    IN PDIRTY_PAGE_ROUTINE DirtyPageRoutine,
    IN PVOID Context1,
    IN PVOID Context2)
{
    LARGE_INTEGER i;

    CCTRACE(CC_API_DEBUG, "LogHandle=%p DirtyPageRoutine=%p Context1=%p Context2=%p\n",
        LogHandle, DirtyPageRoutine, Context1, Context2);

    UNIMPLEMENTED;
    i.QuadPart = 0;
    return i;
}

/*
 * @implemented
 */
PFILE_OBJECT
NTAPI
CcGetFileObjectFromBcb (
    IN PVOID Bcb)
{
    PINTERNAL_BCB iBcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    if (((PPUBLIC_BCB)Bcb)->NodeTypeCode == CC_NTC_OBCB)
        iBcb = CONTAINING_RECORD(Bcb, INTERNAL_OBCB, PFCB)->Bcbs[0];
    else
        iBcb = CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB);

    return iBcb->Vacb->SharedCacheMap->FileObject;
}

/*
 * @unimplemented
 */
LARGE_INTEGER
NTAPI
CcGetLsnForFileObject (
    IN PFILE_OBJECT FileObject,
    OUT PLARGE_INTEGER OldestLsn OPTIONAL)
{
    LARGE_INTEGER i;

    CCTRACE(CC_API_DEBUG, "FileObject=%p\n", FileObject);

    UNIMPLEMENTED;
    i.QuadPart = 0;
    return i;
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcInitializeCacheMap (
    IN PFILE_OBJECT FileObject,
    IN PCC_FILE_SIZES FileSizes,
    IN BOOLEAN PinAccess,
    IN PCACHE_MANAGER_CALLBACKS CallBacks,
    IN PVOID LazyWriterContext)
{
    NTSTATUS Status;

    ASSERT(FileObject);
    ASSERT(FileSizes);

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileSizes=%p PinAccess=%d CallBacks=%p LazyWriterContext=%p\n",
        FileObject, FileSizes, PinAccess, CallBacks, LazyWriterContext);

    /* Call old ROS cache init function */
    Status = CcRosInitializeFileCache(FileObject,
                                      FileSizes,
                                      PinAccess,
                                      CallBacks,
                                      LazyWriterContext);
    if (!NT_SUCCESS(Status))
        ExRaiseStatus(Status);
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
CcIsThereDirtyData (
    IN PVPB Vpb)
{
    PROS_VACB Vacb;
    PLIST_ENTRY Entry;
    KIRQL oldIrql;
    /* Assume no dirty data */
    BOOLEAN Dirty = FALSE;

    CCTRACE(CC_API_DEBUG, "Vpb=%p\n", Vpb);

    oldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    /* Browse dirty VACBs */
    for (Entry = DirtyVacbListHead.Flink; Entry != &DirtyVacbListHead; Entry = Entry->Flink)
    {
        Vacb = CONTAINING_RECORD(Entry, ROS_VACB, DirtyVacbListEntry);
        /* Look for these associated with our volume */
        if (Vacb->SharedCacheMap->FileObject->Vpb != Vpb)
        {
            continue;
        }

        /* From now on, we are associated with our VPB */

        /* Temporary files are not counted as dirty */
        if (BooleanFlagOn(Vacb->SharedCacheMap->FileObject->Flags, FO_TEMPORARY_FILE))
        {
            continue;
        }

        /* A single dirty VACB is enough to have dirty data */
        if (Vacb->Dirty)
        {
            Dirty = TRUE;
            break;
        }
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, oldIrql);

    return Dirty;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPurgeCacheSection (
    IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
    IN PLARGE_INTEGER FileOffset OPTIONAL,
    IN ULONG Length,
    IN BOOLEAN UninitializeCacheMaps)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    PPRIVATE_CACHE_MAP PrivateCacheMap;
    LONGLONG StartOffset;
    LONGLONG EndOffset;
    LIST_ENTRY FreeList;
    KIRQL OldIrql;
    PLIST_ENTRY ListEntry;
    PROS_VACB Vacb;
    LONGLONG ViewEnd;
    BOOLEAN Success;

    CCTRACE(CC_API_DEBUG, "SectionObjectPointer=%p\n FileOffset=%p Length=%lu UninitializeCacheMaps=%d",
        SectionObjectPointer, FileOffset, Length, UninitializeCacheMaps);

    /* Obtain the shared cache from the section, referenced: a map nobody has open can otherwise
     * be deleted by the lazy writer meanwhile */
    SharedCacheMap = CcRosReferenceSharedCacheMap(SectionObjectPointer);
    if (!SharedCacheMap)
    {
        Success = TRUE;
        goto purgeMm;
    }

    if (UninitializeCacheMaps)
    {
        /*
         * We have gotten the acknowledgement that
         * the caller wants to unintialize the private
         * cache maps so let's do this. Since we already
         * have the shared cache map from above, iterate
         * over that cache's private lists.
         */
        while (!IsListEmpty(&SharedCacheMap->PrivateList))
        {
            /*
             * This list is not empty, grab the
             * private cache map.
             */
            PrivateCacheMap = CONTAINING_RECORD(SharedCacheMap->PrivateList.Flink, PRIVATE_CACHE_MAP, PrivateLinks);

            /* Unintialize the private cache now: not deferred, the data is written below */
            CcRosReleaseFileCache(PrivateCacheMap->FileObject, FALSE, NULL, NULL);
        }

        /*
         * What was dirty is written before the purge drops it, as it was when the last private map
         * closed and deleted the shared one (the purge is not told to discard it).  This reference
         * keeps the map, which is deleted by the dereference below.
         */
        CcRosFlushSharedCacheMapNoCallbacks(SharedCacheMap);
    }

    StartOffset = FileOffset != NULL ? FileOffset->QuadPart : 0;
    if (Length == 0 || FileOffset == NULL)
    {
        EndOffset = MAXLONGLONG;
    }
    else
    {
        EndOffset = StartOffset + Length;
        ASSERT(EndOffset > StartOffset);
    }

    InitializeListHead(&FreeList);

    /* Assume success */
    Success = TRUE;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    KeAcquireSpinLockAtDpcLevel(&SharedCacheMap->CacheMapLock);
    ListEntry = SharedCacheMap->CacheMapVacbListHead.Flink;
    while (ListEntry != &SharedCacheMap->CacheMapVacbListHead)
    {
        ULONG Refs;

        Vacb = CONTAINING_RECORD(ListEntry, ROS_VACB, CacheMapVacbListEntry);
        ListEntry = ListEntry->Flink;

        /* The list is sorted by file offset: stop at the first VACB past the range */
        if (Vacb->FileOffset.QuadPart >= EndOffset)
        {
            break;
        }

        /* Skip VACBs that end before the range starts */
        if (Vacb->FileOffset.QuadPart + VACB_MAPPING_GRANULARITY <= StartOffset)
        {
            continue;
        }

        Refs = CcRosVacbGetRefCount(Vacb);
        ViewEnd = min(Vacb->FileOffset.QuadPart + VACB_MAPPING_GRANULARITY,
                      SharedCacheMap->SectionSize.QuadPart);
        if (Vacb->FileOffset.QuadPart < StartOffset || ViewEnd > EndOffset)
        {
            /* Only partly in range: release it only when clean and idle, as
             * its dirty data outside the range would leave the lazy writer's
             * list. Otherwise MmPurgeSegment checks the pages it maps */
            if (Vacb->Dirty || Refs > 1)
            {
                continue;
            }
        }
        else if ((Refs > 1 && !Vacb->Dirty) ||
                 (Refs > 2 && Vacb->Dirty))
        {
            /* Still in use, it cannot be purged, fail
             * Allow one ref: VACB is supposed to be always 1-referenced
             */
            Success = FALSE;
            break;
        }

        /* This VACB is in range, so unlink it and mark for free */
        ASSERT(Refs == 1 || Vacb->Dirty);
        RemoveEntryList(&Vacb->VacbLruListEntry);
        InitializeListHead(&Vacb->VacbLruListEntry);
        if (Vacb->Dirty)
        {
            CcRosUnmarkDirtyVacb(Vacb, FALSE);
        }
        RemoveEntryList(&Vacb->CacheMapVacbListEntry);
        InsertHeadList(&FreeList, &Vacb->CacheMapVacbListEntry);
    }
    KeReleaseSpinLockFromDpcLevel(&SharedCacheMap->CacheMapLock);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    while (!IsListEmpty(&FreeList))
    {
        ULONG Refs;

        Vacb = CONTAINING_RECORD(RemoveHeadList(&FreeList),
                                 ROS_VACB,
                                 CacheMapVacbListEntry);
        InitializeListHead(&Vacb->CacheMapVacbListEntry);
        Refs = CcRosVacbDecRefCount(Vacb);
        ASSERT(Refs == 0);
    }

    /* Now make sure that Mm doesn't hold some pages here. */
purgeMm:
    if (Success)
        Success = MmPurgeSegment(SectionObjectPointer, FileOffset, Length);

    /* A map that nobody has open and that the purge left clean is deleted by this (in a worker) */
    if (SharedCacheMap)
        CcRosDereferenceSharedCacheMap(SharedCacheMap);

    return Success;
}


/*
 * @implemented
 */
VOID NTAPI
CcSetFileSizes (
    IN PFILE_OBJECT FileObject,
    IN PCC_FILE_SIZES FileSizes)
{
    KIRQL OldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    LARGE_INTEGER OldSectionSize;
    LARGE_INTEGER OldFileSize;

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileSizes=%p\n",
        FileObject, FileSizes);

    DPRINT("CcSetFileSizes(FileObject 0x%p, FileSizes 0x%p)\n",
           FileObject, FileSizes);
    DPRINT("AllocationSize %I64d, FileSize %I64d, ValidDataLength %I64d\n",
           FileSizes->AllocationSize.QuadPart,
           FileSizes->FileSize.QuadPart,
           FileSizes->ValidDataLength.QuadPart);

    /* Referenced: the file object may hold no private cache map, and then nothing else keeps the map */
    SharedCacheMap = CcRosReferenceSharedCacheMap(FileObject->SectionObjectPointer);

    /*
     * It is valid to call this function on file objects that weren't
     * initialized for caching. In this case it's simple no-op.
     */
    if (SharedCacheMap == NULL)
    {
        /*
         * A map that is being deleted still has dirty views to write (CcRosDeleteFileCache clears the map
         * first, writes them, with none of the file system's locks).  This call comes after the file
         * system cut the file, and a regrow can follow at once: what the old views hold past the new end
         * of file must not be written then, over the new data.  Zero it (the writer then writes zeros,
         * the right content for a range that grew back), as is done below for a file with a map.
         */
        if (CcRosIsDeleteFlushPending(FileObject->SectionObjectPointer))
        {
            MmZeroResidentSegmentRange(FileObject->SectionObjectPointer,
                                       FileSizes->FileSize.QuadPart,
                                       MAXLONGLONG);
        }
        return;
    }

    /* Update the relevant fields */
    KeAcquireSpinLock(&SharedCacheMap->CacheMapLock, &OldIrql);
    OldSectionSize = SharedCacheMap->SectionSize;
    OldFileSize = SharedCacheMap->FileSize;
    SharedCacheMap->SectionSize = FileSizes->AllocationSize;
    SharedCacheMap->FileSize = FileSizes->FileSize;
    SharedCacheMap->ValidDataLength = FileSizes->ValidDataLength;
    KeReleaseSpinLock(&SharedCacheMap->CacheMapLock, OldIrql);

    /* Pages past a reduced file size can stay resident: clear them, so that a regrown file reads zero there.
     * To the segment's end: a view may have written past the old size in its last page */
    if (FileSizes->FileSize.QuadPart < OldFileSize.QuadPart)
    {
        MmZeroResidentSegmentRange(FileObject->SectionObjectPointer,
                                   FileSizes->FileSize.QuadPart,
                                   MAXLONGLONG);
    }

    if (FileSizes->AllocationSize.QuadPart < OldSectionSize.QuadPart)
    {
        CcPurgeCacheSection(FileObject->SectionObjectPointer,
                            &FileSizes->AllocationSize,
                            0,
                            FALSE);
    }
    else
    {
        /* Extend our section object; the file system has already set the file size */
        MmExtendSection(SharedCacheMap->Section, &SharedCacheMap->SectionSize, TRUE);
    }

    CcRosDereferenceSharedCacheMap(SharedCacheMap);
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcSetLogHandleForFile (
    IN PFILE_OBJECT FileObject,
    IN PVOID LogHandle,
    IN PFLUSH_TO_LSN FlushToLsnRoutine)
{
    CCTRACE(CC_API_DEBUG, "FileObject=%p LogHandle=%p FlushToLsnRoutine=%p\n",
        FileObject, LogHandle, FlushToLsnRoutine);

    UNIMPLEMENTED;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcUninitializeCacheMap (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER TruncateSize OPTIONAL,
    IN PCACHE_UNINITIALIZE_EVENT UninitializeCompleteEvent OPTIONAL)
{
    NTSTATUS Status;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    KIRQL OldIrql;
    BOOLEAN EventQueued;

    CCTRACE(CC_API_DEBUG, "FileObject=%p TruncateSize=%p UninitializeCompleteEvent=%p\n",
        FileObject, TruncateSize, UninitializeCompleteEvent);

    if (TruncateSize != NULL &&
        (SharedCacheMap = CcRosReferenceSharedCacheMap(FileObject->SectionObjectPointer)) != NULL)
    {
        KeAcquireSpinLock(&SharedCacheMap->CacheMapLock, &OldIrql);
        if (SharedCacheMap->FileSize.QuadPart > TruncateSize->QuadPart)
        {
            SharedCacheMap->FileSize = *TruncateSize;
        }
        KeReleaseSpinLock(&SharedCacheMap->CacheMapLock, OldIrql);
        /* The purge keeps pages it cannot drop; they must not show the old bytes if the file grows again */
        if (TruncateSize->QuadPart != 0)
        {
            MmZeroResidentSegmentRange(FileObject->SectionObjectPointer, TruncateSize->QuadPart, MAXLONGLONG);
            CcPurgeCacheSection(FileObject->SectionObjectPointer,
                                TruncateSize,
                                0,
                                FALSE);
        }
        else if (!CcPurgeCacheSection(FileObject->SectionObjectPointer,
                                      TruncateSize,
                                      0,
                                      FALSE))
        {
            /* To zero (a delete): the purge drops every page, zeroing them first only cost a mapping of each; zero what it kept */
            MmZeroResidentSegmentRange(FileObject->SectionObjectPointer, 0, MAXLONGLONG);
        }
        CcRosDereferenceSharedCacheMap(SharedCacheMap);
    }

    /*
     * The last close of a file with dirty cached data does not write it when its file system allows
     * that (CcRosAllowLazyClose): the lazy writer does, and deletes the shared cache map afterwards
     * (Windows does the same).  A truncation purged the views past TruncateSize above; one to zero (a
     * delete) leaves nothing to write, and deletes the map now.  A caller that passes an
     * UninitializeCompleteEvent waits for the map to go, and gets it deleted at once (it may hold what
     * the lazy writer needs).  The event is signalled when the map is deleted; at once if this call
     * did not leave it (others still cache through it).
     */
    Status = CcRosReleaseFileCache(FileObject,
                                   (TruncateSize == NULL || TruncateSize->QuadPart != 0) &&
                                       UninitializeCompleteEvent == NULL,
                                   UninitializeCompleteEvent,
                                   &EventQueued);
    if (UninitializeCompleteEvent && !EventQueued)
    {
        KeSetEvent(&UninitializeCompleteEvent->Event, IO_NO_INCREMENT, FALSE);
    }
    return NT_SUCCESS(Status);
}

BOOLEAN
NTAPI
CcGetFileSizes (
    IN PFILE_OBJECT FileObject,
    IN PCC_FILE_SIZES FileSizes)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;

    if (!SharedCacheMap)
        return FALSE;

    FileSizes->AllocationSize = SharedCacheMap->SectionSize;
    FileSizes->FileSize = FileSizes->ValidDataLength = SharedCacheMap->FileSize;
    return TRUE;
}
