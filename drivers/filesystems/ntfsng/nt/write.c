/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP_MJ_WRITE (cached, non-cached, paging), size changes, flush, shutdown,
 *              Cc callbacks and the per-volume metadata flusher
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"

/* ngos_nt.c */
int ngos_dev_read(void *dev, unsigned long long off, void *buf, unsigned int len);
int ngos_dev_write(void *dev, unsigned long long off, void *buf, unsigned int len);

/* Cc maps files in views of this size (VACB_MAPPING_GRANULARITY). */
#define NG_VACB_SIZE (256 * 1024)

/*
 * Lock order: FCB MainResource -> FCB PagingIoResource -> Vcb->CoreLock -> core mutexes, and
 * FCB MainResource -> FCB PagingWriteLock -> Vcb->CoreLock -> Vcb->DataIoGate.
 * CoreLock is never held across a Cc or Mm call or while touching unlocked user memory.  Paging writes
 * take PagingWriteLock (the lazy writer comes with PagingIoResource shared), then PagingIoResource only
 * by a try that never waits, then CoreLock; nobody holding PagingWriteLock waits for PagingIoResource or
 * MainResource, and nobody holding CoreLock waits for PagingWriteLock, so Cc's lazy writer and Mm's
 * writers cannot deadlock with a user thread that holds FCB resources while it waits inside Cc.
 * DataIoGate: see NgPagingWrite.
 *
 * The lazy writer's order differs: Cc takes PagingIoResource shared (NgAcquireForLazyWrite) before it calls in,
 * and the write then takes PagingWriteLock, so it holds PagingIoResource(shared) -> PagingWriteLock, the reverse of
 * the line above.  That is safe only under this rule: nobody blocks on PagingIoResource EXCLUSIVE while holding
 * PagingWriteLock.  The takers are NgSetFileSize (its callers: the cached branch of NgWrite, set-information,
 * create's overwrite and supersede; they hold MainResource and no PagingWriteLock) and NgWaitStreamWrites
 * (read.c, a non-cached read; it holds nothing).  A paging write only ever tries PagingIoResource, never waits
 * for it.  Keep it so: a path that waits for PagingIoResource exclusive with PagingWriteLock held would deadlock
 * against a lazy write of the same stream.
 *
 * Allocation ahead of the size (ngc_set_size, core/ngcore.c) adds no lock and no order.  Growth takes clusters
 * up to the next multiple of 4 MB for a stream that is already 1 MB long and grows by at most 1 MB at a time; the
 * slack is hidden from NT (ngc_stat) and freed by ngc_trim_alloc at the last cleanup, under MainResource and CoreLock
 * like any shrink (the cluster free drains DataIoGate; a transfer in flight never waits for MainResource or CoreLock).
 * Nothing but the stream's own growth uses the slack: reads stop at the size and the initialized size, paging writes
 * are clipped to the size, and a cluster another stream freed before this one took it is committed first
 * (ngc_before_alloc, which a growth inside the allocation does not need).
 *
 * The journal commit (NgCommit, below) runs its journal I/O without CoreLock.  The thread that commits seals the metadata
 * overlay under CoreLock (after the writeback), drops CoreLock, writes the journal, the COMMITTED header, the pages in
 * place and the ACTIVE header (with three device flushes), and takes CoreLock again to release the sealed overlay.  New
 * lock rules, none of them a new lock:
 *   - NgCommit drops CoreLock only at CoreDepth 1 and not once a dismount began.  It is called between core operations
 *     (the flusher, FlushFileBuffers and write-through, and NgSetFileSize before a growth), never from inside one.
 *   - While it is dropped the thread counts in DioActive (not in DataIoGate: a cluster free must not wait for a commit),
 *     so a dismount, which waits for DioActive 0 under CoreLock, cannot free the core under the I/O.  The flusher is
 *     stopped before that wait, so it is never inside NgCommit then.
 *   - The journal I/O takes no lock and needs nothing a CoreLock holder owns, so a CoreLock holder may wait for it
 *     (kshim_jnl_settle / _wait in the shim, from ngc_before_alloc, the old synchronous commit, retire, a resize, deactivate):
 *     the I/O ends without CoreLock.  Only one commit's I/O runs at a time; a second committer waits at the glue
 *     (NGC_COMMIT_BUSY: CoreLock dropped while it waits) and commits afterwards.
 *   - ngc_before_alloc: a free (the watched free-cluster count) that no complete commit covers makes the allocation wait
 *     for it: the glue commits before a growth (NgSetFileSize), else the core waits for the commit in flight and commits
 *     synchronously whatever is still not covered.  A cluster freed by an uncommitted transaction is therefore never
 *     reused before that transaction is in place.
 *   - ngc_mark_dirty (inside core operations) no longer commits at the overlay threshold: it kicks the flusher
 *     (CommitKick) and commits itself only past a hard limit (twice the threshold, at most 3/4 of the journal).
 * Overlay rules (readers see the live overlay, then the sealed one, then the device) are at the top of shim/kshim_jnl.c.
 */

/* At mount, before the core exists. */
VOID NgInitDataIo(PNG_VCB Vcb)
{
    ExInitializeResourceLite(&Vcb->DataIoGate);
    KeInitializeEvent(&Vcb->DioIdle, NotificationEvent, TRUE);
    KeInitializeEvent(&Vcb->CommitKick, SynchronizationEvent, FALSE);
    ExInitializeNPagedLookasideList(&Vcb->DioBounce, NULL, NULL, 0, NG_DIO_BOUNCE, TAG_NTFSNG, 0);
}

/*
 * Waits until no paging write is in its unlocked device transfer (CoreLock held).  Called by the core
 * before it frees clusters, before it marks the medium gone or stops writing, before a resize and at
 * unmount (kshim_dio_drain).  A transfer acquires DataIoGate shared only under CoreLock, so none can
 * start while this waits, and it needs nothing a CoreLock holder has to finish.
 */
VOID NgDrainDataIoCallback(PVOID Context)
{
    PNG_VCB Vcb = Context;
    ASSERT(ExIsResourceAcquiredExclusiveLite(&Vcb->CoreLock));
    ASSERT(!ExIsResourceAcquiredSharedLite(&Vcb->DataIoGate));
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&Vcb->DataIoGate, TRUE);
    ExReleaseResourceLite(&Vcb->DataIoGate);
    KeLeaveCriticalRegion();
}

/*
 * Dismount: returns with CoreLock held once no unlocked paging write is between its start and its end
 * (they pin core nodes).  Vcb->Dismounted is set already, so none starts once this holds CoreLock.
 */
VOID NgWaitDataIoIdle(PNG_VCB Vcb)
{
    for (;;)
    {
        NgAcquireCore(Vcb);
        if (Vcb->DioActive == 0)
            return;
        NgReleaseCore(Vcb);
        KeWaitForSingleObject(&Vcb->DioIdle, Executive, KernelMode, FALSE, NULL);
    }
}

/*
 * The three steps around an unlocked data transfer (paging writes here, paging and non-cached reads in read.c).
 * The caller holds CoreLock once (CoreDepth 1) and has pinned a core node (ngc_dio_begin / ngc_rdio_begin):
 *   NgDataIoBegin:        counts the transfer (DioActive), takes DataIoGate shared and releases CoreLock; the
 *                         inode cache trim comes before the gate (its evictions may free clusters, which drains)
 *   (the transfer, no CoreLock)
 *   NgDataIoTransferred:  releases the gate and takes CoreLock again
 *   (ngc_dio_end / ngc_rdio_end, which unpin the node)
 *   NgDataIoDone:         the transfer is over (DioActive), still under CoreLock
 */
VOID NgDataIoBegin(PNG_VCB Vcb)
{
    ngc_icache_trim(Vcb->Core);
    if (Vcb->DioActive++ == 0)
        KeClearEvent(&Vcb->DioIdle);
    ExAcquireResourceSharedLite(&Vcb->DataIoGate, TRUE);
    NgReleaseCoreNoTrim(Vcb);
}

VOID NgDataIoTransferred(PNG_VCB Vcb)
{
    ExReleaseResourceLite(&Vcb->DataIoGate);
    NgAcquireCore(Vcb);
}

VOID NgDataIoDone(PNG_VCB Vcb)
{
    if (--Vcb->DioActive == 0)
        KeSetEvent(&Vcb->DioIdle, IO_NO_INCREMENT, FALSE);
}

/*
 * A commit with its journal I/O outside CoreLock (ngc_commit_begin, core/ngcore.c).  CoreLock is held on entry and on
 * return; the commit is complete when it returns 0.  Between the seal and the end of the I/O, which is most of a commit's
 * time, other threads take CoreLock and run: their metadata writes go to a new overlay and their reads see the sealed
 * pages (shim/kshim_jnl.c).  CoreLock is dropped only at depth 1 (nobody up the stack depends on what it protects), not
 * once a dismount started, and the thread counts as an unlocked I/O (DioActive, not DataIoGate: a cluster free does not
 * wait for a commit) so that no dismount frees the core under it.  It also waits like that for another commit's I/O, which
 * needs no lock, so waiting for it with CoreLock held (inside a core operation: ngc_before_alloc) cannot deadlock.
 * Lock order: whatever the caller holds (FCB resources) -> CoreLock; the I/O takes nothing.
 */
/* ngc_set_commit_kick: under CoreLock, must not block. */
VOID NgCommitKickCallback(PVOID Context)
{
    KeSetEvent(&((PNG_VCB)Context)->CommitKick, IO_NO_INCREMENT, FALSE);
}

static VOID NgPinUnlocked(PNG_VCB Vcb)
{
    if (Vcb->DioActive++ == 0)
        KeClearEvent(&Vcb->DioIdle);
}

int NgCommit(PNG_VCB Vcb)
{
    for (;;)
    {
        BOOLEAN Unlock = Vcb->CoreDepth == 1 && !Vcb->Dismounted;
        int R = ngc_commit_begin(Vcb->Core);
        if (R == NGC_COMMIT_IO)
        {
            if (Unlock)
            {
                NgPinUnlocked(Vcb);
                NgReleaseCoreNoTrim(Vcb);
                R = ngc_commit_io(Vcb->Core);
                NgAcquireCore(Vcb);
                NgDataIoDone(Vcb);
            }
            else
                R = ngc_commit_io(Vcb->Core);
            ngc_commit_end(Vcb->Core);
            return R;
        }
        if (R != NGC_COMMIT_BUSY)
            return R;
        if (Unlock)
        {
            NgPinUnlocked(Vcb);
            NgReleaseCoreNoTrim(Vcb);
            ngc_commit_wait(Vcb->Core);
            NgAcquireCore(Vcb);
            NgDataIoDone(Vcb);
        }
        else
            ngc_commit_wait(Vcb->Core);
    }
}

BOOLEAN NTAPI NgAcquireForLazyWrite(PVOID Context, BOOLEAN Wait)
{
    PNG_FCB Fcb = Context;
    if (!ExAcquireResourceSharedLite(Fcb->Header.PagingIoResource, Wait))
        return FALSE;
    ASSERT(IoGetTopLevelIrp() == NULL);
    IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
    return TRUE;
}

VOID NTAPI NgReleaseFromLazyWrite(PVOID Context)
{
    PNG_FCB Fcb = Context;
    if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
        IoSetTopLevelIrp(NULL);
    ExReleaseResourceLite(Fcb->Header.PagingIoResource);
}

BOOLEAN NTAPI NgAcquireForReadAhead(PVOID Context, BOOLEAN Wait)
{
    PNG_FCB Fcb = Context;
    if (!ExAcquireResourceSharedLite(Fcb->Header.Resource, Wait))
        return FALSE;
    ASSERT(IoGetTopLevelIrp() == NULL);
    IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
    return TRUE;
}

VOID NTAPI NgReleaseFromReadAhead(PVOID Context)
{
    PNG_FCB Fcb = Context;
    if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
        IoSetTopLevelIrp(NULL);
    ExReleaseResourceLite(Fcb->Header.Resource);
}

/* Under CoreLock, after a change: once the system is shutting down, nothing stays unsynced. */
VOID NgAfterChange(PNG_VCB Vcb)
{
    if (Vcb->WriteThrough)
    {
        int Err = ngc_sync(Vcb->Core);
        Vcb->Syncs++;
        if (Err)
            DPRINT1("ntfsng: write-through sync failed %d\n", Err);
    }
}

/*
 * A write-through write completes only once its data, the metadata it changed (sizes, the contents
 * of a file resident in its MFT record) and their journal commit are on the medium.  The commit
 * flushes the device even when no metadata changed.
 */
static NTSTATUS NgCommitWriteThrough(PNG_VCB Vcb)
{
    int Err;
    NgAcquireCore(Vcb);
    Err = NgCommit(Vcb);
    Vcb->Syncs++;
    NgReleaseCore(Vcb);
    if (Err)
        DPRINT1("ntfsng: write-through commit failed %d\n", Err);
    return Err ? STATUS_UNEXPECTED_IO_ERROR : STATUS_SUCCESS;
}

/* Header sizes from the core inode (caller holds CoreLock and the node). */
static VOID NgSizesFromCore(PNG_FCB Fcb)
{
    LONGLONG Alloc;
    ngc_stat(Fcb->Node, &Fcb->Stat);
    Alloc = (Fcb->Stat.size + PAGE_SIZE - 1) & ~(LONGLONG)(PAGE_SIZE - 1);
    if ((LONGLONG)Fcb->Stat.alloc > Alloc)
        Alloc = Fcb->Stat.alloc;
    Fcb->Header.AllocationSize.QuadPart = Alloc;
    if (Alloc > Fcb->CachedEnd)
        Fcb->CachedEnd = Alloc;
    Fcb->Header.FileSize.QuadPart = Fcb->Stat.size;
    Fcb->Header.ValidDataLength.QuadPart = Fcb->Stat.size;
}

/* Last write and change time to now plus the archive bit, once per modification burst. */
VOID NgApplyModified(PNG_FCB Fcb)
{
    static const long long Now[4] = { 0, 0, -1, -1 };
    static const long long ChangeOnly[4] = { 0, 0, 0, -1 };
    PNG_VCB Vcb = Fcb->Vcb;
    if (!Fcb->Modified || Vcb->ReadOnly || !Fcb->HasNode || Fcb->Deleted)
        return;
    Fcb->Modified = FALSE;
    NgAcquireCore(Vcb);
    if (!NgEnsureNode(Fcb))
    {
        ngc_set_info(Vcb->Core, Fcb->Node, Fcb->UserSetWriteTime ? ChangeOnly : Now,
                     FILE_ATTRIBUTE_ARCHIVE, Fcb->IsDirectory ? 0 : FILE_ATTRIBUTE_ARCHIVE);
        NgAfterChange(Vcb);
        if (Fcb->OpenHandles == 0)
            NgParkNode(Fcb);
    }
    NgReleaseCore(Vcb);
}

/*
 * Whole-stream flushes and purges always name an explicit range.  Given no range (or length 0),
 * ReactOS MmFlushSegment and MmPurgeSegment end at the page table that was created last, which
 * is not the highest one once a file has shrunk and grown: pages above it are neither flushed
 * nor purged (stale data came back after a later grow).  The range ends past every size the
 * stream has had, and goes in chunks because the length is a ULONG.
 */
#define NG_RANGE_CHUNK 0x40000000
static LONGLONG NgCachedLimit(PNG_FCB Fcb)
{
    LONGLONG End = max(Fcb->CachedEnd, Fcb->Header.AllocationSize.QuadPart);
    return ((End + NG_VACB_SIZE - 1) & ~(LONGLONG)(NG_VACB_SIZE - 1)) + NG_VACB_SIZE;
}

VOID NgFlushStream(PNG_FCB Fcb, PIO_STATUS_BLOCK Iosb)
{
    LARGE_INTEGER Li;
    LONGLONG End;

    Iosb->Status = STATUS_SUCCESS;
    Iosb->Information = 0;
    if (Fcb->SectionObjectPointers.SharedCacheMap)
    {
        /* Cc walks its views up to FileSize and hands Mm explicit ranges itself. */
        CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, Iosb);
        return;
    }
    if (!Fcb->SectionObjectPointers.DataSectionObject)
        return;
    End = NgCachedLimit(Fcb);
    for (Li.QuadPart = 0; Li.QuadPart < End; Li.QuadPart += NG_RANGE_CHUNK)
    {
        IO_STATUS_BLOCK One;
        One.Status = STATUS_SUCCESS;
        CcFlushCache(&Fcb->SectionObjectPointers, &Li, (ULONG)min(End - Li.QuadPart, (LONGLONG)NG_RANGE_CHUNK), &One);
        if (!NT_SUCCESS(One.Status) && NT_SUCCESS(Iosb->Status))
            Iosb->Status = One.Status;
    }
}

/* Drops every cached page of the stream from Start on; FALSE if something was in use. */
BOOLEAN NgPurgeFrom(PNG_FCB Fcb, LONGLONG Start)
{
    LARGE_INTEGER Li;
    LONGLONG End = NgCachedLimit(Fcb);
    BOOLEAN Ok;

    /* Cc's views first (its view walk handles an open end correctly), then Mm's pages by range. */
    Li.QuadPart = Start;
    Ok = CcPurgeCacheSection(&Fcb->SectionObjectPointers, &Li, 0, FALSE);
    for (; Ok && Li.QuadPart < End; Li.QuadPart += NG_RANGE_CHUNK)
        Ok = CcPurgeCacheSection(&Fcb->SectionObjectPointers, &Li,
                                 (ULONG)min(End - Li.QuadPart, (LONGLONG)NG_RANGE_CHUNK), FALSE);
    return Ok;
}

/*
 * EOF change.  Caller holds MainResource exclusive.  Core first, then the header, then Cc.
 * A shrink flushes Cc first so the core's on-disk view of the surviving bytes is current.
 */
NTSTATUS NgSetFileSize(PNG_FCB Fcb, PFILE_OBJECT FileObject, LONGLONG NewSize)
{
    PNG_VCB Vcb = Fcb->Vcb;
    LONGLONG OldSize = Fcb->Header.FileSize.QuadPart;
    LARGE_INTEGER Li, Li2;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status = STATUS_SUCCESS;
    int Err;

    if (NewSize < 0)
        return STATUS_INVALID_PARAMETER;
    if (NewSize == OldSize)
        return STATUS_SUCCESS;
    if (NewSize > OldSize)
        Fcb->Grown = TRUE;
    if (NewSize < OldSize)
    {
        Li.QuadPart = NewSize;
        if (!MmCanFileBeTruncated(&Fcb->SectionObjectPointers, &Li))
            return STATUS_USER_MAPPED_FILE;
        NgFlushStream(Fcb, &Iosb);
    }
    ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
    NgAcquireCore(Vcb);
    /*
     * A growth that may allocate waits for the commit of what a free left uncommitted (ngc_before_alloc), and a
     * metadata overlay past its threshold wants a commit: both here, between core operations, with the journal I/O
     * outside CoreLock.  The core still checks for itself (a free since: it commits synchronously).
     */
    if (NewSize > OldSize && Vcb->Core && ngc_commit_wanted(Vcb->Core, 1))
    {
        Err = NgCommit(Vcb);
        if (Err)
            DPRINT1("ntfsng: commit before a growth failed %d\n", Err);
    }
    Err = NgEnsureNode(Fcb);
    if (!Err)
        Err = ngc_set_size(Vcb->Core, Fcb->Node, (unsigned long long)NewSize);
    if (Fcb->Node)
        NgSizesFromCore(Fcb);
    if (!Err)
        NgAfterChange(Vcb);
    if (!Err && Fcb->IsPagingFile && !NT_SUCCESS(NgPagingFileMap(Fcb)))
        Err = -NGC_ENOMEM;
    NgReleaseCore(Vcb);
    ExReleaseResourceLite(Fcb->Header.PagingIoResource);
    if (Err)
    {
        DPRINT1("ntfsng: set size of %I64x to %I64d failed %d\n", Fcb->MftNo, NewSize, Err);
        Status = Err == -NGC_ENOSPC ? STATUS_DISK_FULL : NgErrnoToStatus(Err);
    }
    /*
     * Keep the bytes from before a truncation hidden once the file grows again.  ntfsng zero-fills
     * paging reads only past EOF, so the disk can still hold them past the old size.
     */
    _SEH2_TRY
    {
        if (FileObject && Fcb->SectionObjectPointers.SharedCacheMap)
        {
            if (NewSize > OldSize && NT_SUCCESS(Status))
            {
                /* With the cache map's valid data length held at the old size, CcZeroData reads
                 * nothing past it from the disk and zeroes the exposed range. */
                CC_FILE_SIZES Sizes;
                Sizes.AllocationSize = Fcb->Header.AllocationSize;
                Sizes.FileSize = Fcb->Header.FileSize;
                Sizes.ValidDataLength.QuadPart = OldSize;
                CcSetFileSizes(FileObject, &Sizes);
                Li.QuadPart = OldSize;
                Li2.QuadPart = NewSize;
                CcZeroData(FileObject, &Li, &Li2, TRUE);
            }
            CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
        }
        else if (NewSize > OldSize && Fcb->SectionObjectPointers.DataSectionObject)
        {
            /* No cache map: drop whatever Mm still holds from the old EOF's view on (flushed first:
             * the pages below the old EOF may be dirty). */
            Li.QuadPart = OldSize & ~(LONGLONG)(NG_VACB_SIZE - 1);
            CcFlushCache(&Fcb->SectionObjectPointers, &Li, (ULONG)(OldSize - Li.QuadPart) + PAGE_SIZE, &Iosb);
            if (!NgPurgeFrom(Fcb, Li.QuadPart))
                DPRINT1("ntfsng: purge of %I64x from %I64d after a grow failed\n", Fcb->MftNo, Li.QuadPart);
        }
        if (NewSize < OldSize && NT_SUCCESS(Status) &&
            (Fcb->SectionObjectPointers.SharedCacheMap || Fcb->SectionObjectPointers.DataSectionObject))
        {
            /* Everything was flushed above, so purging from the view boundary loses nothing. */
            Li.QuadPart = NewSize & ~(LONGLONG)(NG_VACB_SIZE - 1);
            if (!NgPurgeFrom(Fcb, Li.QuadPart))
                DPRINT1("ntfsng: purge of %I64x from %I64d after a shrink failed\n", Fcb->MftNo, Li.QuadPart);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (NT_SUCCESS(Status))
    {
        Fcb->Modified = TRUE;
        if (Fcb->LogicalVdl > NewSize)
            Fcb->LogicalVdl = NewSize;
    }
    return Status;
}

/*
 * A page write Mm sends for a file of a volume whose lock holder wrote the disk directly, or that is
 * dismounted: the disk is no longer the mounted state's, so the page is not written.  It completes as
 * written: Mm retries a failed page write until it succeeds (MiShutdownSystem would loop) or drops it
 * on the segment's last release anyway.  Logged once per volume and counted.
 */
NTSTATUS NgDropPagingWrite(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, ULONG Length)
{
    if (InterlockedIncrement(&Vcb->DroppedPagingWrites) == 1)
        DbgPrint("ntfsng: volume %08lx: page writes of mapped files are dropped (file %I64x first): %s\n",
                 Vcb->Vpb->SerialNumber, Fcb->MftNo, Vcb->Dismounted ? "dismounted" : "the lock holder wrote the disk directly");
    Irp->IoStatus.Information = Length;
    return STATUS_SUCCESS;
}

/*
 * A page write of a file (not the volume, not a paging file) that writes nothing: the file is deleted,
 * or the lock holder wrote the disk directly (RawWritten, published under CoreLock and read under it).
 * Decided before the medium and read-only checks, which would refuse it.  TRUE with Status set.
 */
BOOLEAN NgDropIfDiscardable(PNG_VCB Vcb, PIRP Irp, PNTSTATUS Status)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_FCB Fcb = Stack->FileObject ? Stack->FileObject->FsContext : NULL;
    ULONG Length = Stack->Parameters.Write.Length;
    BOOLEAN Drop;

    if (!(Irp->Flags & IRP_PAGING_IO) || !Fcb || Fcb->IsVolume || Fcb->IsPagingFile || !Length)
        return FALSE;
    if (Fcb->Deleted)
    {
        Irp->IoStatus.Information = Length;
        *Status = STATUS_SUCCESS;
        return TRUE;
    }
    /* Neither set: a transition after this read is caught under CoreLock in NgPagingWrite. */
    if (!Vcb->RawWritten && !Vcb->ReadOnly)
        return FALSE;
    NgAcquireCore(Vcb);
    /* also a volume cut off from its device: a refused page write would be retried forever */
    Drop = Vcb->RawWritten || Vcb->WrongMedia;
    NgReleaseCore(Vcb);
    if (!Drop)
        return FALSE;
    *Status = NgDropPagingWrite(Vcb, Fcb, Irp, Length);
    return TRUE;
}

/*
 * The device part of an unlocked paging write (no CoreLock): each run through a bounce buffer, as the
 * core's own data writes go (ngc_dev_write), with the same device request (ngos_dev_write).
 */
static int NgDioTransfer(PNG_VCB Vcb, const struct ngc_dio *Dio, PUCHAR Buffer, PUCHAR Bounce)
{
    ULONG r, Done;
    for (r = 0; r < Dio->nruns; r++)
    {
        for (Done = 0; Done < Dio->run[r].len; )
        {
            ULONG n = min(Dio->run[r].len - Done, NG_DIO_BOUNCE);
            RtlCopyMemory(Bounce, Buffer + Dio->run[r].boff + Done, n);
            if (ngos_dev_write(Vcb->StorageDevice, Dio->run[r].dev + Done, Bounce, n))
                return -1;
            Done += n;
        }
    }
    return 0;
}

/*
 * Paging write from the lazy writer or Mm.  It holds the FCB's PagingWriteLock exclusive (one data write
 * of the stream at a time: no zero fill or initialized-size change of another write overlaps it) and,
 * if a try gets it, its PagingIoResource shared (no size change meanwhile; the lazy writer holds it
 * already).  With both, a write of allocated clusters that needs no metadata change other than raising
 * the initialized size runs its device transfer without CoreLock (ngc_dio_begin/end, core/ngcore.c):
 *
 *   CoreLock:   checks, ngc_dio_begin (maps the clusters, pins the node), DioActive++, DataIoGate shared
 *   no lock:    the transfer
 *   CoreLock:   ngc_dio_end (raises the initialized size, updates the core page cache), DioActive--
 *
 * so a create, cleanup or query of another file does not wait behind the disk.  Everything else is
 * written under CoreLock as before.  Invariants for the unlocked part: DataIoGate is held shared exactly
 * across the transfer and is acquired under CoreLock; every cluster free, medium change, direct write
 * hand-over, resize and unmount waits for it under CoreLock first (NgDrainDataIoCallback), so the clusters
 * written are the stream's and the device is this mount's until the transfer ends; a dismount also waits
 * for DioActive to reach 0 (NgWaitDataIoIdle).
 */
static NTSTATUS NgPagingWrite(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, LONGLONG Offset, ULONG Length)
{
    LONGLONG FileSize = Fcb->Header.FileSize.QuadPart;
    PVOID Buffer;
    PUCHAR Bounce = NULL;
    ULONG Clipped;
    BOOLEAN PagingShared, Unlocked = FALSE, Drop = FALSE;
    struct ngc_dio Dio;
    long Done = 0;
    int IoErr;

    Irp->IoStatus.Information = Length;
    if (Fcb->Deleted || Offset >= FileSize)
        return STATUS_SUCCESS;
    Clipped = (ULONG)min((LONGLONG)Length, FileSize - Offset);
    Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
    if (!Buffer)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ExAcquireResourceExclusiveLite(&Fcb->PagingWriteLock, TRUE);
    PagingShared = ExAcquireResourceSharedLite(Fcb->Header.PagingIoResource, FALSE);
    if (PagingShared && !Vcb->WriteThrough)
        Bounce = ExAllocateFromNPagedLookasideList(&Vcb->DioBounce);
    NgAcquireCore(Vcb);
    /* Deleted under CoreLock: a page writer that raced with the last cleanup's delete drops its data. */
    if (Fcb->Deleted)
    {
        NgReleaseCore(Vcb);
        Done = 0;
        goto out;
    }
    /* RawWritten is published under CoreLock: a writer that passed NgDropIfDiscardable before it is dropped here. */
    if (Vcb->RawWritten)
    {
        NgReleaseCore(Vcb);
        Drop = TRUE;
        goto out;
    }
    Done = NgEnsureNode(Fcb);
    if (!Done && Bounce && Vcb->CoreDepth == 1 && !Vcb->Dismounted && !Vcb->WriteThrough)
    {
        Done = ngc_dio_begin(Vcb->Core, Fcb->Node, Offset, Clipped, Length, &Dio);
        if (!Done)
            Unlocked = TRUE;
        else if (Done == -NGC_EAGAIN)
            Done = 0;
    }
    if (Unlocked)
    {
        NgDataIoBegin(Vcb);

        IoErr = NgDioTransfer(Vcb, &Dio, Buffer, Bounce);

        NgDataIoTransferred(Vcb);
        Done = ngc_dio_end(Vcb->Core, &Dio, Buffer, IoErr);
        NgDataIoDone(Vcb);
        if (Done >= 0)
            Vcb->DioWrites++;
        else if (Done == -NGC_EAGAIN)
        {
            /* The mapping changed under the transfer: write it again under the lock (also drops it if the
             * file went away meanwhile). */
            Vcb->DioRedone++;
            Done = Fcb->Deleted ? 0 : NgEnsureNode(Fcb);
            if (!Done && !Fcb->Deleted)
                Done = ngc_write(Vcb->Core, Fcb->Node, Offset, Clipped, Buffer);
        }
    }
    else if (!Done)
    {
        Vcb->DioFallbacks++;
        Done = ngc_write(Vcb->Core, Fcb->Node, Offset, Clipped, Buffer);
    }
    if (Done >= 0)
        NgAfterChange(Vcb);
    if (Fcb->OpenHandles == 0)
        NgParkNode(Fcb);
    NgReleaseCore(Vcb);
out:
    if (Bounce)
        ExFreeToNPagedLookasideList(&Vcb->DioBounce, Bounce);
    if (PagingShared)
        ExReleaseResourceLite(Fcb->Header.PagingIoResource);
    ExReleaseResourceLite(&Fcb->PagingWriteLock);
    if (Drop)
        return NgDropPagingWrite(Vcb, Fcb, Irp, Length);
    if (Done < 0)
    {
        DPRINT1("ntfsng: paging write of %I64x at %I64d len %lu failed %ld (size %I64d, handles %ld, deleted %u)\n",
                Fcb->MftNo, Offset, Clipped, Done, Fcb->Header.FileSize.QuadPart, Fcb->OpenHandles, Fcb->Deleted);
        Irp->IoStatus.Information = 0;
        return Done == -NGC_EROFS ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_UNEXPECTED_IO_ERROR;
    }
    return STATUS_SUCCESS;
}

/*
 * Writes a locked buffer straight to the storage device, through a sector-aligned pool buffer.  Nothing
 * of the journal orders these writes, so the request completes only once they are on the medium.  A
 * dismounted volume skips the medium check at dispatch, so each chunk is checked here, under the core
 * lock a verify marks the medium gone under: a medium a verify found replaced is never written through
 * this volume.  (A swap after the dismount that no verify sees is not caught: a dismounted volume is not
 * verified again, and the storage driver reports the change only to a mounted volume.)
 */
static NTSTATUS NgWriteDevice(PNG_VCB Vcb, PFILE_OBJECT Holder, LONGLONG Offset, PUCHAR Buffer, ULONG Length)
{
    PUCHAR Bounce = ExAllocatePoolWithTag(NonPagedPool, 64 * 1024, TAG_NTFSNG);
    NTSTATUS Status = STATUS_SUCCESS;
    NG_SHARED_HOLD Hold;
    ULONG Done = 0;

    if (!Bounce)
        return STATUS_INSUFFICIENT_RESOURCES;
    while (Done < Length)
    {
        ULONG n = min(Length - Done, 64 * 1024);
        int Err;
        RtlCopyMemory(Bounce, Buffer + Done, n);
        NgAcquireCoreShared(Vcb, &Hold);
        /*
         * The lock again: an unlock may have run, or be running (LockEnding), since the request started.
         * A dismounted volume's handle writes only while it still holds the lock, as on Windows.
         */
        if (Done == 0 && (Vcb->LockedBy != Holder || Vcb->LockEnding))
        {
            NgReleaseCoreShared(Vcb, &Hold);
            Status = STATUS_ACCESS_DENIED;
            break;
        }
        if (Vcb->WrongMedia)
        {
            NgReleaseCoreShared(Vcb, &Hold);
            Status = STATUS_FILE_INVALID;
            break;
        }
        /* Before the first direct write: no paging write of the mount may land after it (NgPagingWrite). */
        if (Done == 0 && !Vcb->RawWritten)
            NgDrainDataIoCallback(Vcb);
        Err = NgDevWriteDurable(Vcb->StorageDevice, (unsigned long long)Offset + Done, Bounce, n);
        /*
         * The hand-over, in the hold of the first chunk's device write: no core I/O lands between the
         * two, and a write that never reached the device hands nothing over.  From here on the core does
         * no device I/O at all (a read would find what the holder wrote through a stale map), write
         * opens, flushes and the flusher see a read-only volume, a label set is refused (it checks
         * RawWritten under CoreLock), and page writes of files are dropped (NgDropIfDiscardable).  The
         * end of the lock dismounts the volume (NgEndLock), so the next open mounts what is on the disk.
         */
        if (Done == 0 && Err != NG_DEV_NOT_SENT)
        {
            if (!Vcb->RawWritten && !Vcb->Dismounted)
            {
                DPRINT1("ntfsng: the lock holder writes the volume directly (at %I64d len %lu): no I/O of the mount until the lock ends, then a dismount\n",
                        Offset, Length);
                ngc_stop_writes(Vcb->Core);
                ngc_medium_gone(Vcb->Core);
            }
            Vcb->RawWritten = TRUE;
            Vcb->ReadOnly = TRUE;
        }
        NgReleaseCoreShared(Vcb, &Hold);
        if (Err)
        {
            Status = Err == NG_DEV_NOT_SENT ? STATUS_INSUFFICIENT_RESOURCES : STATUS_UNEXPECTED_IO_ERROR;
            break;
        }
        Done += n;
    }
    ExFreePoolWithTag(Bounce, TAG_NTFSNG);
    if (NT_SUCCESS(Status))
    {
        /* Under the same lock: a medium found gone before the flush makes the write fail, not succeed. */
        NgAcquireCoreShared(Vcb, &Hold);
        if (Vcb->WrongMedia)
            Status = STATUS_FILE_INVALID;
        else if (NgDevFlushDurable(Vcb->StorageDevice))
            Status = STATUS_UNEXPECTED_IO_ERROR;
        NgReleaseCoreShared(Vcb, &Hold);
    }
    return Status;
}

/*
 * Writes through a volume handle.  The handle that holds the volume lock writes anywhere, as on
 * Windows (formatters lock the volume and write it).  Once its first direct write was sent to the
 * device, the mounted state no longer describes the disk: the core does no device I/O any more (no
 * flusher pass, lazy write, close or read touches what the holder writes), every later write of the
 * holder goes straight to the disk, the boot code area included, nothing is written back at the
 * dismount, and the end of the lock dismounts the volume.  Without the lock only the boot code
 * ($Boot, the first 8 KiB) may change under the mounted volume: setup installs the boot sector that
 * way, through the core's device path so the journal overlay and the cached boot sector see it.
 */
#define NG_BOOT_REGION 8192
static NTSTATUS NgWriteVolume(PNG_VCB Vcb, PIRP Irp, LONGLONG Offset, ULONG Length)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    BOOLEAN Holder = Vcb->LockedBy == FileObject || Vcb->Dismounted;
    BOOLEAN Raw = Vcb->Dismounted || (Holder && Vcb->RawWritten);
    PMDL Mdl = NULL;
    PVOID Buffer;
    NTSTATUS Status = STATUS_SUCCESS;
    int Err;

    if (Vcb->ReadOnly && !Holder)
        return STATUS_MEDIA_WRITE_PROTECTED;
    if (Offset < 0 || ((ULONG)Offset | Length) & (Vcb->SectorSize - 1))
        return STATUS_INVALID_PARAMETER;
    if (Offset + Length > NG_BOOT_REGION)
    {
        if (!Holder)
        {
            DPRINT1("ntfsng: volume write at %I64d len %lu refused (outside the boot code, volume not locked)\n", Offset, Length);
            return STATUS_ACCESS_DENIED;
        }
        Raw = TRUE;
    }
    if (Offset == 0 && Length < 512)
        return STATUS_INVALID_PARAMETER;
    if (Irp->MdlAddress)
    {
        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    }
    else
    {
        Mdl = IoAllocateMdl(Irp->UserBuffer, Length, FALSE, FALSE, NULL);
        if (!Mdl)
            return STATUS_INSUFFICIENT_RESOURCES;
        _SEH2_TRY
        {
            MmProbeAndLockPages(Mdl, Irp->RequestorMode, IoReadAccess);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        if (!NT_SUCCESS(Status))
        {
            IoFreeMdl(Mdl);
            return Status;
        }
        Buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    }
    if (!Buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    if (Offset == 0 && !Raw)
    {
        /* Only the boot code may change under the mounted volume: the BPB and the signature stay. */
        PUCHAR Old = ExAllocatePoolWithTag(NonPagedPool, 512, TAG_NTFSNG);
        BOOLEAN Same;
        if (!Old)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
        Same = !ngos_dev_read(Vcb->StorageDevice, 0, Old, 512) &&
               RtlCompareMemory(Old + 3, (PUCHAR)Buffer + 3, 0x54 - 3) == 0x54 - 3 &&
               RtlCompareMemory(Old + 510, (PUCHAR)Buffer + 510, 2) == 2;
        ExFreePoolWithTag(Old, TAG_NTFSNG);
        if (!Same && !Holder)
        {
            DPRINT1("ntfsng: volume write at 0 refused: it changes the BPB\n");
            Status = STATUS_ACCESS_DENIED;
            goto out;
        }
        Raw = !Same;
    }
    if (Raw || Vcb->ReadOnly)
    {
        /* Authorized and handed over with its first device write (NgWriteDevice). */
        Status = NgWriteDevice(Vcb, FileObject, Offset, Buffer, Length);
        if (NT_SUCCESS(Status))
            Irp->IoStatus.Information = Length;
        goto out;
    }
    NgAcquireCore(Vcb);
    Err = ngc_raw_write(Vcb->Core, (unsigned long long)Offset, Buffer, Length);
    if (!Err)
        Err = ngc_sync(Vcb->Core);
    NgReleaseCore(Vcb);
    DPRINT1("ntfsng: boot code written through the volume handle at %I64d len %lu: %d\n", Offset, Length, Err);
    if (Err)
        Status = NgErrnoToStatus(Err);
    else
        Irp->IoStatus.Information = Length;
out:
    if (Mdl)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
    return Status;
}

NTSTATUS NgWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    LARGE_INTEGER Offset = Stack->Parameters.Write.ByteOffset;
    ULONG Length = Stack->Parameters.Write.Length;
    BOOLEAN Paging = (Irp->Flags & IRP_PAGING_IO) != 0;
    BOOLEAN NonCached = (Irp->Flags & IRP_NOCACHE) != 0;
    BOOLEAN WriteThrough = (FileObject->Flags & FO_WRITE_THROUGH) || (Stack->Flags & SL_WRITE_THROUGH);
    BOOLEAN Append = (Offset.LowPart == FILE_WRITE_TO_END_OF_FILE && Offset.HighPart == -1);
    PMDL LockedMdl = NULL;
    PVOID Buffer;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status = STATUS_SUCCESS;
    LONGLONG End, OldSize;
    long Done;
    int Err;

    if (Stack->MinorFunction & IRP_MN_MDL)
        return STATUS_INVALID_DEVICE_REQUEST;
    if (Fcb && Fcb->IsVolume && Length)
    {
        if (Offset.LowPart == FILE_USE_FILE_POINTER_POSITION && Offset.HighPart == -1)
            Offset = FileObject->CurrentByteOffset;
        Status = NgWriteVolume(Vcb, Irp, Offset.QuadPart, Length);
        if (NT_SUCCESS(Status) && (FileObject->Flags & FO_SYNCHRONOUS_IO))
            FileObject->CurrentByteOffset.QuadPart = Offset.QuadPart + Irp->IoStatus.Information;
        return Status;
    }
    if (!Fcb || Fcb->IsVolume || Fcb->IsDirectory || !Fcb->HasNode)
        return STATUS_INVALID_DEVICE_REQUEST;
    if (Vcb->ReadOnly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    if (Length == 0)
        return STATUS_SUCCESS;
    if (Paging && Fcb->IsPagingFile)
        return NgPagingFileIo(Vcb, Fcb, Irp, TRUE, Offset.QuadPart, Length);
    if (Fcb->Stat.flags & NGC_ATTR_NOWRITE)
        return STATUS_ACCESS_DENIED;
    if (Paging)
        return NgPagingWrite(Vcb, Fcb, Irp, Offset.QuadPart, Length);

    if (Offset.LowPart == FILE_USE_FILE_POINTER_POSITION && Offset.HighPart == -1)
    {
        /* Only a synchronous handle has a file position. */
        if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
            return STATUS_INVALID_PARAMETER;
        Offset = FileObject->CurrentByteOffset;
    }
    if (Offset.QuadPart < 0 && !Append)
        return STATUS_INVALID_PARAMETER;
    /* A handle with FILE_APPEND_DATA but not FILE_WRITE_DATA writes at the end of the file. */
    if (FileObject->FsContext2 && ((PNG_CCB)FileObject->FsContext2)->AppendOnly)
        Append = TRUE;
    if (!FsRtlCheckLockForWriteAccess(&Fcb->FileLock, Irp))
        return STATUS_FILE_LOCK_CONFLICT;
    if (NonCached && !Append && ((Offset.LowPart | Length) & (Vcb->SectorSize - 1)))
        return STATUS_INVALID_PARAMETER;

    /* The user buffer: locked before any core call so no page fault can happen under CoreLock. */
    if (Irp->MdlAddress)
    {
        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        if (!Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;
    }
    else if (NonCached)
    {
        LockedMdl = IoAllocateMdl(Irp->UserBuffer, Length, FALSE, FALSE, NULL);
        if (!LockedMdl)
            return STATUS_INSUFFICIENT_RESOURCES;
        _SEH2_TRY
        {
            MmProbeAndLockPages(LockedMdl, Irp->RequestorMode, IoReadAccess);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        if (!NT_SUCCESS(Status))
        {
            IoFreeMdl(LockedMdl);
            return Status;
        }
        Buffer = MmGetSystemAddressForMdlSafe(LockedMdl, NormalPagePriority);
        if (!Buffer)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto out_mdl;
        }
    }
    else
    {
        /* Checked before the file grows: a bad buffer must not leave a longer file behind. */
        Buffer = Irp->UserBuffer;
        if (!Buffer)
            return STATUS_INVALID_USER_BUFFER;
        if (Irp->RequestorMode != KernelMode)
        {
            _SEH2_TRY
            {
                ProbeForRead(Buffer, Length, 1);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            if (!NT_SUCCESS(Status))
                return Status;
        }
    }

    ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
    if (Append)
        Offset.QuadPart = Fcb->Header.FileSize.QuadPart;
    if (Offset.QuadPart > MAXLONGLONG - (LONGLONG)Length)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto out_unlock;
    }
    End = Offset.QuadPart + Length;
    OldSize = Fcb->Header.FileSize.QuadPart;
    if (End > Fcb->Header.FileSize.QuadPart)
    {
        Status = NgSetFileSize(Fcb, FileObject, End);
        if (!NT_SUCCESS(Status))
            goto out_unlock;
    }

    /*
     * A non-cached write must not leave older bytes in Cc or in a mapped view, and a paging read
     * can bring a purged range back at any time.  While a data section exists the write goes
     * through the cache and straight on to disk.  Without one, the main resource held exclusive
     * keeps a section from being created and cached reads out until the write is on disk.
     */
    if (NonCached && Fcb->SectionObjectPointers.DataSectionObject)
    {
        NonCached = FALSE;
        WriteThrough = TRUE;
        Vcb->NonCachedViaCache++;
    }
    if (!NonCached)
    {
        _SEH2_TRY
        {
            if (!FileObject->PrivateCacheMap)
            {
                CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize, FALSE,
                                     &NgGlobal.CacheCallbacks, Fcb);
                CcRosAllowLazyClose(FileObject);
            }
            if (!CcCopyWrite(FileObject, &Offset, Length, TRUE, Buffer))
                Status = STATUS_UNSUCCESSFUL;
            else if (WriteThrough)
            {
                CcFlushCache(FileObject->SectionObjectPointer, &Offset, Length, &Iosb);
                Status = Iosb.Status;
                if (NT_SUCCESS(Status))
                    Status = NgCommitWriteThrough(Vcb);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        if (!NT_SUCCESS(Status) && End > OldSize && OldSize < Fcb->Header.FileSize.QuadPart)
            NgSetFileSize(Fcb, FileObject, OldSize);
    }
    else
    {
        /* PagingWriteLock: its zero fill below the start must not overlap a paging write's unlocked transfer. */
        ExAcquireResourceExclusiveLite(&Fcb->PagingWriteLock, TRUE);
        NgAcquireCore(Vcb);
        Err = NgEnsureNode(Fcb);
        Done = Err ? Err : ngc_write(Vcb->Core, Fcb->Node, Offset.QuadPart, Length, Buffer);
        if (Done >= 0)
        {
            NgAfterChange(Vcb);
            if (WriteThrough && ngc_commit_now(Vcb->Core))
                Done = -NGC_EIO;
        }
        NgReleaseCore(Vcb);
        ExReleaseResourceLite(&Fcb->PagingWriteLock);
        if (Done < 0)
        {
            DPRINT1("ntfsng: write of %I64x at %I64d len %lu failed %ld\n", Fcb->MftNo, Offset.QuadPart, Length, Done);
            Status = Done == -NGC_EROFS ? STATUS_MEDIA_WRITE_PROTECTED :
                     Done == -NGC_ENOSPC ? STATUS_DISK_FULL : STATUS_UNEXPECTED_IO_ERROR;
        }
    }
    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = Length;
        Fcb->Modified = TRUE;
        if (End > Fcb->LogicalVdl)
            Fcb->LogicalVdl = End;
        if (FileObject->Flags & FO_SYNCHRONOUS_IO)
            FileObject->CurrentByteOffset.QuadPart = Offset.QuadPart + Length;
        FileObject->Flags |= FO_FILE_MODIFIED;
    }
out_unlock:
    ExReleaseResourceLite(Fcb->Header.Resource);
out_mdl:
    if (LockedMdl)
    {
        MmUnlockPages(LockedMdl);
        IoFreeMdl(LockedMdl);
    }
    return Status;
}

/* Flushes every cached stream of the volume through Cc, then the core metadata. */
int NgFlushVolume(PNG_VCB Vcb)
{
    PLIST_ENTRY Entry;
    PNG_FCB *List;
    ULONG Count = 0, Cap = 0, i;
    IO_STATUS_BLOCK Iosb;
    int Err, StreamErr = 0;

    if (Vcb->ReadOnly)
        return 0;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList; Entry = Entry->Flink)
        Cap++;
    List = Cap ? ExAllocatePoolWithTag(NonPagedPool, Cap * sizeof(PNG_FCB), TAG_NTFSNG) : NULL;
    if (Cap && !List)
    {
        ExReleaseFastMutex(&Vcb->FcbListLock);
        return -NGC_ENOMEM;     /* the streams cannot be listed, so their cached data cannot be flushed */
    }
    if (List)
    {
        for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList && Count < Cap; Entry = Entry->Flink)
        {
            PNG_FCB Fcb = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
            InterlockedIncrement(&Fcb->RefCount);
            List[Count++] = Fcb;
        }
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    for (i = 0; i < Count; i++)
    {
        PNG_FCB Fcb = List[i];
        if (Fcb->SectionObjectPointers.DataSectionObject)
        {
            ExAcquireResourceSharedLite(Fcb->Header.Resource, TRUE);
            NgFlushStream(Fcb, &Iosb);
            ExReleaseResourceLite(Fcb->Header.Resource);
            if (!NT_SUCCESS(Iosb.Status) && !StreamErr)
                StreamErr = -NGC_EIO;
        }
        NgApplyModified(Fcb);
        NgDereferenceFcb(Fcb);
    }
    if (List)
        ExFreePoolWithTag(List, TAG_NTFSNG);
    NgAcquireCore(Vcb);
    Err = ngc_sync(Vcb->Core);
    Vcb->Syncs++;
    NgReleaseCore(Vcb);
    if (Err)
        DPRINT1("ntfsng: volume sync failed %d\n", Err);
    return StreamErr ? StreamErr : Err;
}

NTSTATUS NgFlushBuffers(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    IO_STATUS_BLOCK Iosb;
    int Err;

    /* After the lock holder's direct writes only the disk's cache is flushed, never the mounted state. */
    if (Fcb && Fcb->IsVolume && Vcb->RawWritten)
        return NgDevFlushDurable(Vcb->StorageDevice) ? STATUS_UNEXPECTED_IO_ERROR : STATUS_SUCCESS;
    /* Data written before a failed resize can no longer reach the disk: a flush must not report it there. */
    if (Fcb && Vcb->WritesLost)
        return STATUS_UNEXPECTED_IO_ERROR;
    if (!Fcb || Vcb->ReadOnly)
        return STATUS_SUCCESS;
    if (Fcb->IsVolume)
        return NgFlushVolume(Vcb) ? STATUS_UNEXPECTED_IO_ERROR : STATUS_SUCCESS;
    Iosb.Status = STATUS_SUCCESS;
    if (Fcb->SectionObjectPointers.DataSectionObject)
    {
        ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
        NgFlushStream(Fcb, &Iosb);
        ExReleaseResourceLite(Fcb->Header.Resource);
    }
    NgApplyModified(Fcb);
    NgAcquireCore(Vcb);
    Err = NgCommit(Vcb);
    Vcb->Syncs++;
    NgReleaseCore(Vcb);
    if (Err)
        return STATUS_UNEXPECTED_IO_ERROR;
    return Iosb.Status;
}

/*
 * ReactOS sends IRP_MJ_SHUTDOWN to file system control devices in IoShutdownSystem(1), after
 * the registry and Cc have flushed.  The lazy writer may still run afterwards, so every later
 * change is synced immediately (WriteThrough) and the volume ends clean.
 */
NTSTATUS NgShutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PLIST_ENTRY Entry;
    PNG_VCB Local[16], *Vcbs = Local, *Heap = NULL;
    ULONG Count = 0, Cap = RTL_NUMBER_OF(Local), Live = 0, Skipped = 0, i;
    unsigned long Writes, Syncs, Dirties;
    unsigned long long Bytes;
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    /* A VCB is never freed after its mount, so the pointers stay valid outside the list lock; a
     * dismount is waited for (create gate) and its volume skipped. */
    ExAcquireFastMutex(&NgGlobal.VcbListLock);
    for (Entry = NgGlobal.VcbList.Flink; Entry != &NgGlobal.VcbList; Entry = Entry->Flink)
        if (!CONTAINING_RECORD(Entry, NG_VCB, GlobalLinks)->WrongMedia)
            Live++;
    ExReleaseFastMutex(&NgGlobal.VcbListLock);
    if (Live > Cap)
    {
        /* Room for a volume that mounts between the count and the snapshot. */
        Heap = ExAllocatePoolWithTag(PagedPool, (Live + 8) * sizeof(PNG_VCB), TAG_NTFSNG);
        if (Heap)
        {
            Vcbs = Heap;
            Cap = Live + 8;
        }
    }
    ExAcquireFastMutex(&NgGlobal.VcbListLock);
    for (Entry = NgGlobal.VcbList.Flink; Entry != &NgGlobal.VcbList; Entry = Entry->Flink)
    {
        /* Volumes whose medium went away stay listed: they must not take the slots of live ones. */
        PNG_VCB V = CONTAINING_RECORD(Entry, NG_VCB, GlobalLinks);
        if (V->WrongMedia)
            continue;
        if (Count < Cap)
            Vcbs[Count++] = V;
        else
            Skipped++;
    }
    ExReleaseFastMutex(&NgGlobal.VcbListLock);
    if (Skipped)
        DPRINT1("ntfsng: shutdown: %lu volumes not flushed (no room for them)\n", Skipped);
    for (i = 0; i < Count; i++)
    {
        PNG_VCB Vcb = Vcbs[i];
        if (Vcb->ReadOnly || Vcb->WrongMedia)
            continue;
        ExAcquireResourceSharedLite(&Vcb->CreateGate, TRUE);
        if (Vcb->Dismounted || Vcb->RawWritten)
        {
            /* Gone, or the lock holder wrote the disk directly: mounted state is not written over it. */
            ExReleaseResourceLite(&Vcb->CreateGate);
            continue;
        }
        NgFlushVolume(Vcb);
        Vcb->WriteThrough = TRUE;
        NgAcquireCore(Vcb);
        /* Paging writes in their unlocked transfer reach the device before the sync's flush. */
        NgDrainDataIoCallback(Vcb);
        ngc_sync(Vcb->Core);
        ngc_volinfo(Vcb->Core, &Vcb->Info);
        ngc_jnl_report(Vcb->Core);
        NgReleaseCore(Vcb);
        DPRINT1("ntfsng: shutdown: volume %08lx flushed, %s, %lu syncs, %lu non-cached writes via Cc, paging file %ld reads %ld writes\n",
                Vcb->Vpb->SerialNumber, Vcb->Info.dirty ? "STILL DIRTY" : "clean", Vcb->Syncs, Vcb->NonCachedViaCache,
                Vcb->PagingFileReads, Vcb->PagingFileWrites);
        NgPrintLockStats(Vcb);
        ExReleaseResourceLite(&Vcb->CreateGate);
    }
    if (Heap)
        ExFreePoolWithTag(Heap, TAG_NTFSNG);
    ngc_write_stats(&Writes, &Bytes, &Syncs, &Dirties);
    DPRINT1("ntfsng: shutdown: %lu device writes, %I64u bytes, %lu core syncs, %lu folio dirties, stack max %lu (IRP_MJ 0x%x), core at device %lu\n",
            Writes, Bytes, Syncs, Dirties, NgGlobal.MaxStackUsed, NgGlobal.MaxStackMajor, NgGlobal.MaxStackAtIo);
    return STATUS_SUCCESS;
}

/*
 * Linux's flusher stand-in: writes back dirty core metadata every NG_FLUSH_PERIOD_MS.  It runs at the
 * priority of the critical work queue (13), where Windows runs the lazy writer and the NTFS checkpoint:
 * it holds CoreLock while it writes back and seals the overlay (the journal I/O of a commit is outside it, NgCommit), and at
 * the default 8 it shared the processors round-robin with busy normal-priority threads, so every open, listing and
 * write on the volume waited for their quanta.  It also wakes when the core kicks it (CommitKick).
 */
static VOID NTAPI NgFlusherThread(PVOID Context)
{
    PNG_VCB Vcb = Context;
    LARGE_INTEGER Period;
    PVOID Objects[2];
    NTSTATUS Wait;
    KeSetBasePriorityThread(KeGetCurrentThread(), NG_FLUSHER_PRIORITY_INCREMENT);
    Period.QuadPart = -10000LL * NG_FLUSH_PERIOD_MS;
    Objects[0] = &Vcb->FlusherStop;
    Objects[1] = &Vcb->CommitKick;
    for (;;)
    {
        Wait = KeWaitForMultipleObjects(2, Objects, WaitAny, Executive, KernelMode, FALSE, &Period, NULL);
        if (Wait == STATUS_WAIT_0)
            break;
        NgAcquireCore(Vcb);
        if (Wait == STATUS_WAIT_1)
        {
            /* The core asked for a commit (its overlay is past the threshold): the journal I/O runs without CoreLock. */
            if (!Vcb->WrongMedia && !Vcb->RawWritten && ngc_commit_wanted(Vcb->Core, 0))
            {
                int Err = NgCommit(Vcb);
                Vcb->Syncs++;
                if (Err)
                    DPRINT1("ntfsng: requested commit failed %d\n", Err);
            }
        }
        else if (!Vcb->WrongMedia && !Vcb->RawWritten && ngc_dirty(Vcb->Core))
        {
            /* Busy: commit and keep VOLUME_IS_DIRTY.  Quiet for a whole period: also clear the flag. */
            int Err = ngc_changed(Vcb->Core) ? NgCommit(Vcb) : ngc_sync(Vcb->Core);
            Vcb->Syncs++;
            if (Err)
                DPRINT1("ntfsng: background sync failed %d\n", Err);
        }
        NgReleaseCore(Vcb);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS NgStartFlusher(PNG_VCB Vcb)
{
    HANDLE Thread;
    NTSTATUS Status;
    KeInitializeEvent(&Vcb->FlusherStop, NotificationEvent, FALSE);
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, NgFlusherThread, Vcb);
    if (!NT_SUCCESS(Status))
        return Status;
    ObReferenceObjectByHandle(Thread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID *)&Vcb->Flusher, NULL);
    ZwClose(Thread);
    return STATUS_SUCCESS;
}
