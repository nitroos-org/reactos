/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Driver entry, dispatch, FCB lifetime
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"
#include "../shim/include/ngos.h"

NG_GLOBAL NgGlobal;

#define NG_STACK_FILL 0x4e474e47UL
#define NG_STACK_MAX_SPAN (128 * 1024)

NTSTATUS NgErrnoToStatus(int Err)
{
    switch (-Err)
    {
        case 0: return STATUS_SUCCESS;
        case NGC_ENOENT: return STATUS_OBJECT_NAME_NOT_FOUND;
        case NGC_ENOMEM: return STATUS_INSUFFICIENT_RESOURCES;
        case NGC_ENOTDIR: return STATUS_NOT_A_DIRECTORY;
        case NGC_EISDIR: return STATUS_FILE_IS_A_DIRECTORY;
        case NGC_EROFS: return STATUS_MEDIA_WRITE_PROTECTED;
        case NGC_ENAMETOOLONG: return STATUS_OBJECT_NAME_INVALID;
        case NGC_EOPNOTSUPP: return STATUS_NOT_SUPPORTED;
        case NGC_ENOSPC: return STATUS_DISK_FULL;
        case NGC_EEXIST: return STATUS_OBJECT_NAME_COLLISION;
        case NGC_ENOTEMPTY: return STATUS_DIRECTORY_NOT_EMPTY;
        case NGC_EACCES:
        case NGC_EPERM: return STATUS_ACCESS_DENIED;
        case NGC_EFBIG: return STATUS_DISK_FULL;
        case NGC_EBUSY: return STATUS_SHARING_VIOLATION;
        case NGC_EINVAL:
        case NGC_EUCLEAN: return STATUS_FILE_CORRUPT_ERROR;
        default: return STATUS_UNEXPECTED_IO_ERROR;
    }
}

/* Lock timing uses the TSC (cheap to read), calibrated against the performance counter at load. */
#if DBG
static LONGLONG NgPerfFrequency;
#endif

#if DBG
static ULONGLONG NgTicksToUs(LONGLONG Ticks)
{
    return NgPerfFrequency ? (ULONGLONG)(Ticks * 1000000 / NgPerfFrequency) : 0;
}
#endif

#if DBG
/* Histogram of CoreLock hold times (log2 of microseconds) by the main reason of the hold, under CoreLock. */
#define NG_HOLD_BUCKETS 16
enum { NG_HR_COMMIT, NG_HR_ALLOC, NG_HR_WRITE, NG_HR_OTHER, NG_HR_COUNT };
static const char *const NgHoldReason[NG_HR_COUNT] = { "commit", "alloc+runlist", "locked write", "other" };
static ULONG NgHoldHist[NG_HR_COUNT][NG_HOLD_BUCKETS];
static ULONGLONG NgHoldSumUs[NG_HR_COUNT], NgHoldCompUs[NG_HR_COUNT][NG_HT_COUNT];
ULONGLONG NgHoldTicks[NG_HT_COUNT];

static VOID NgNoteHold(ULONGLONG Ticks)
{
    ULONGLONG Us = NgTicksToUs((LONGLONG)Ticks), C = NgHoldTicks[NG_HT_COMMIT], A, W, O;
    ULONG Reason = NG_HR_OTHER, B = 0, i;
    ULONGLONG Best;
    A = NgHoldTicks[NG_HT_SET_SIZE] > C ? NgHoldTicks[NG_HT_SET_SIZE] - C : 0;
    W = NgHoldTicks[NG_HT_WRITE] > C ? NgHoldTicks[NG_HT_WRITE] - C : 0;
    O = Ticks > C + A + W ? Ticks - C - A - W : 0;
    Best = O;
    if (C > Best) { Best = C; Reason = NG_HR_COMMIT; }
    if (A > Best) { Best = A; Reason = NG_HR_ALLOC; }
    if (W > Best) { Reason = NG_HR_WRITE; }
    while (B < NG_HOLD_BUCKETS - 1 && (1ULL << B) < Us)
        B++;
    NgHoldHist[Reason][B]++;
    NgHoldSumUs[Reason] += Us;
    for (i = 0; i < NG_HT_COUNT; i++)
        NgHoldCompUs[Reason][i] += NgTicksToUs((LONGLONG)NgHoldTicks[i]);
}
#endif

#if DBG
/* The request a CoreLock acquisition serves, from the top-level IRP of the thread. */
static UCHAR NgLockCategory(VOID)
{
    PIRP Top = IoGetTopLevelIrp();
    PIO_STACK_LOCATION Stack;
    if ((ULONG_PTR)Top <= FSRTL_MAX_TOP_LEVEL_IRP_FLAG)
        return NG_LOCK_NO_IRP;
    Stack = IoGetCurrentIrpStackLocation(Top);
    if (Top->Flags & IRP_PAGING_IO)
    {
        if (Stack->MajorFunction == IRP_MJ_READ)
            return NG_LOCK_PAGING_READ;
        if (Stack->MajorFunction == IRP_MJ_WRITE)
            return NG_LOCK_PAGING_WRITE;
    }
    return Stack->MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION ? Stack->MajorFunction : NG_LOCK_NO_IRP;
}
#endif

VOID NgAcquireCore(PNG_VCB Vcb)
{
#if DBG
    LARGE_INTEGER T0, T1;
#endif
    BOOLEAN Waited = FALSE;
    KeEnterCriticalRegion();
    if (ExIsResourceAcquiredExclusiveLite(&Vcb->CoreLock))
    {
        ExAcquireResourceExclusiveLite(&Vcb->CoreLock, TRUE);
        Vcb->CoreDepth++;
        return;
    }
#if DBG
    T0.QuadPart = (LONGLONG)__rdtsc();
#endif
    if (!ExAcquireResourceExclusiveLite(&Vcb->CoreLock, FALSE))
    {
        ExAcquireResourceExclusiveLite(&Vcb->CoreLock, TRUE);
        Waited = TRUE;
    }
    Vcb->CoreDepth = 1;
#if DBG
    T1.QuadPart = (LONGLONG)__rdtsc();
    Vcb->CoreCategory = NgLockCategory();
    Vcb->CoreSince = T1;
    RtlZeroMemory(NgHoldTicks, sizeof(NgHoldTicks));
    Vcb->LockStats.Stat[Vcb->CoreCategory].Acquired++;
    if (Waited)
    {
        Vcb->LockStats.Stat[Vcb->CoreCategory].Contended++;
        Vcb->LockStats.Stat[Vcb->CoreCategory].WaitUs += NgTicksToUs(T1.QuadPart - T0.QuadPart);
    }
#else
    (void)Waited;
#endif
}

VOID NgReleaseCore(PNG_VCB Vcb)
{
    if (Vcb->CoreDepth == 1 && Vcb->Core)
        ngc_icache_trim(Vcb->Core);
    NgReleaseCoreNoTrim(Vcb);
}

/* Releases CoreLock without the inode cache trim (whose evictions may free clusters, which drains DataIoGate). */
VOID NgReleaseCoreNoTrim(PNG_VCB Vcb)
{
    if (--Vcb->CoreDepth == 0)
    {
#if DBG
        LARGE_INTEGER T;
        T.QuadPart = (LONGLONG)__rdtsc();
        Vcb->LockStats.Stat[Vcb->CoreCategory].HeldUs += NgTicksToUs(T.QuadPart - Vcb->CoreSince.QuadPart);
        NgNoteHold((ULONGLONG)(T.QuadPart - Vcb->CoreSince.QuadPart));
#endif
    }
    ExReleaseResourceLite(&Vcb->CoreLock);
    KeLeaveCriticalRegion();
}

/*
 * The "shared" acquisitions (reads, listings, stat, lookups) take CoreLock exclusive.  Parts of the
 * shim were written for one caller at a time (inode reference drops racing lookups, page-cache
 * walks racing a shrink, FGP_NOWAIT not honoured), so the core runs serialised until they are
 * made safe for parallel callers.
 */
VOID NgAcquireCoreShared(PNG_VCB Vcb, NG_SHARED_HOLD *Hold)
{
    Hold->Nested = TRUE;
    NgAcquireCore(Vcb);
}

VOID NgReleaseCoreShared(PNG_VCB Vcb, NG_SHARED_HOLD *Hold)
{
    UNREFERENCED_PARAMETER(Hold);
    NgReleaseCore(Vcb);
}

/* Prints the request types that took CoreLock (at shutdown). */
VOID NgPrintLockStats(PNG_VCB Vcb)
{
    ULONG i;
    DPRINT1("ntfsng: paging writes: %lu with the transfer outside CoreLock, %lu under it, %lu written again\n",
            Vcb->DioWrites, Vcb->DioFallbacks, Vcb->DioRedone);
    DPRINT1("ntfsng: paging and non-cached reads: %lu with the transfer outside CoreLock, %lu under it\n",
            Vcb->DioReads, Vcb->DioReadFallbacks);
#if DBG
    DPRINT1("ntfsng: unlocked paging writes forced to be written again (DioFault): %lu\n", ngc_dio_forced);
#endif
#if DBG
    {
        ULONG r, b;
        for (r = 0; r < NG_HR_COUNT; r++)
        {
            ULONG N = 0;
            for (b = 0; b < NG_HOLD_BUCKETS; b++)
                N += NgHoldHist[r][b];
            if (!N)
                continue;
            DPRINT1("ntfsng: holds by reason '%s': %lu holds, %I64u us total (commit %I64u, set-size %I64u, write %I64u, writeback %I64u, journal %I64u us)\n",
                    NgHoldReason[r], N, NgHoldSumUs[r], NgHoldCompUs[r][NG_HT_COMMIT], NgHoldCompUs[r][NG_HT_SET_SIZE],
                    NgHoldCompUs[r][NG_HT_WRITE], NgHoldCompUs[r][NG_HT_WRITEBACK], NgHoldCompUs[r][NG_HT_JNL]);
            for (b = 0; b < NG_HOLD_BUCKETS; b++)
                if (NgHoldHist[r][b])
                    DPRINT1("ntfsng: hold %s <= %lu us: %lu\n", NgHoldReason[r], 1UL << b, NgHoldHist[r][b]);
        }
    }
#endif
    for (i = 0; i < NG_LOCK_CATEGORIES; i++)
    {
        NG_LOCK_STAT *S = &Vcb->LockStats.Stat[i];
        if (S->Acquired)
            DPRINT1("ntfsng: lock %02lx: %lu acquired, %lu contended, wait %I64u us, held %I64u us\n",
                    i, S->Acquired, S->Contended, S->WaitUs, S->HeldUs);
    }
}

/*
 * Stack measurement.  On entry to every dispatch routine the unused part of
 * the thread's kernel stack is filled with a pattern; on exit the lowest
 * overwritten word gives the deepest use by this request, including the
 * storage stack below us and any interrupt that nested on this stack.
 */
static ULONG_PTR NgStackFill(VOID)
{
#if DBG
    ULONG_PTR Low, High, Here = (ULONG_PTR)&Low, P;
    IoGetStackLimits(&Low, &High);
    /* A diagnostic must not trust limits that do not describe a kernel stack around us. */
    if (Here <= Low || Here > High || High - Low > NG_STACK_MAX_SPAN || (Low & (PAGE_SIZE - 1)))
        return 0;
    for (P = Low + 256; P + 512 < Here; P += sizeof(ULONG))
        *(volatile ULONG *)P = NG_STACK_FILL;
    return Low;
#else
    return 0;
#endif
}

static VOID NgStackScan(ULONG_PTR Low, UCHAR Major)
{
#if DBG
    ULONG_PTR High, L2, P;
    ULONG Used;
    if (!Low)
        return;
    IoGetStackLimits(&L2, &High);
    if (L2 != Low)
        return;
    for (P = Low + 256; P < High; P += sizeof(ULONG))
        if (*(volatile ULONG *)P != NG_STACK_FILL)
            break;
    Used = (ULONG)(High - P);
    if (Used > NgGlobal.MaxStackUsed)
    {
        NgGlobal.MaxStackUsed = Used;
        NgGlobal.MaxStackMajor = Major;
        DPRINT1("ntfsng: stack: new max %lu bytes of %lu (IRP_MJ 0x%x)\n",
                Used, (ULONG)(High - Low), Major);
    }
#else
    UNREFERENCED_PARAMETER(Low);
    UNREFERENCED_PARAMETER(Major);
#endif
}

#if DBG
VOID NgStackSample(VOID)
{
    ULONG_PTR Low, High, Here = (ULONG_PTR)&Low;
    IoGetStackLimits(&Low, &High);
    if (Here > Low && Here <= High && (ULONG)(High - Here) > NgGlobal.MaxStackAtIo)
    {
        NgGlobal.MaxStackAtIo = (ULONG)(High - Here);
        DPRINT1("ntfsng: stack: core at device read %lu bytes deep\n", NgGlobal.MaxStackAtIo);
    }
}
#endif

PNG_FCB NgAllocateFcb(PNG_VCB Vcb)
{
    PNG_FCB Fcb = ExAllocatePoolWithTag(NonPagedPool, sizeof(NG_FCB), TAG_NTFSNG);
    if (!Fcb)
        return NULL;
    RtlZeroMemory(Fcb, sizeof(*Fcb));
    Fcb->Header.NodeTypeCode = NG_NODE_FCB;
    Fcb->Header.NodeByteSize = sizeof(NG_FCB);
    Fcb->Header.Resource = &Fcb->MainResource;
    Fcb->Header.PagingIoResource = &Fcb->PagingIoResource;
    ExInitializeResourceLite(&Fcb->MainResource);
    ExInitializeResourceLite(&Fcb->PagingIoResource);
    ExInitializeResourceLite(&Fcb->PagingWriteLock);
    FsRtlInitializeFileLock(&Fcb->FileLock, NULL, NULL);
    KeInitializeSpinLock(&Fcb->RunLock);
    InitializeListHead(&Fcb->CcbList);
    Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
    Fcb->Vcb = Vcb;
    Fcb->RefCount = 1;
    InterlockedIncrement(&NgGlobal.FcbLive);
    return Fcb;
}

/*
 * Mm and Cc keep file objects (and so FCBs) of cached files alive long after
 * the last handle is closed.  An FCB without open handles therefore parks its
 * core inode and re-acquires it by MFT number on the next paging read.
 * Both run under the core lock, by a caller that holds a counted reference to
 * the FCB (NgDereferenceFcb relies on it).
 */
int NgEnsureNode(PNG_FCB Fcb)
{
    ngc_node *Base, *Stream;
    int Err;
    if (Fcb->Node || !Fcb->HasNode)
        return Fcb->Node ? 0 : -NGC_EINVAL;
    if (Fcb->Deleted)
        return -NGC_ENOENT;
    Err = ngc_iget(Fcb->Vcb->Core, Fcb->MftNo, &Base);
    if (Err)
        return Err;
    if (Fcb->Stat.mft_ref >> 48)
    {
        /* The record number may have been reused since the node was parked: compare the sequence. */
        struct ngc_stat St;
        ngc_stat(Base, &St);
        if ((St.mft_ref >> 48) != (Fcb->Stat.mft_ref >> 48))
        {
            ngc_put(Base);
            return -NGC_ENOENT;
        }
    }
    if (Fcb->Stream.Length)
    {
        Err = ngc_open_stream(Fcb->Vcb->Core, Base, Fcb->Stream.Buffer, Fcb->Stream.Length / sizeof(WCHAR), &Stream);
        ngc_put(Base);
        if (Err)
            return Err;
        Base = Stream;
    }
    /* Two shared holders may get here at once: the first node stays. */
    if (InterlockedCompareExchangePointer((PVOID *)&Fcb->Node, Base, NULL) != NULL)
        ngc_put(Base);
    return 0;
}

/* Only under an exclusive hold: a shared holder may be using the node. */
VOID NgParkNode(PNG_FCB Fcb)
{
    if (Fcb->Node && !Fcb->IsRoot)
    {
        ngc_put(Fcb->Node);
        Fcb->Node = NULL;
    }
}

/* After an unlink (CoreLock held): TRUE when the node's record lost its last name and is free. */
BOOLEAN NgNodeGone(ngc_node *Node)
{
    struct ngc_stat St;
    ngc_stat(Node, &St);
    return St.nlink == 0;
}

/* Fills Fcb->Stat and the Cc file sizes from the core inode. */
static VOID NgFillStatLocked(PNG_FCB Fcb);

/*
 * Refreshes Fcb->Stat and the FCB header sizes from the core.  The main resource (shared) keeps
 * this away from size changes, which hold it exclusive: a size sampled before an extending write
 * and stored after it would make the next write shrink the file.
 */
VOID NgFillStat(PNG_FCB Fcb)
{
    ExAcquireResourceSharedLite(Fcb->Header.Resource, TRUE);
    NgFillStatLocked(Fcb);
    ExReleaseResourceLite(Fcb->Header.Resource);
}

static VOID NgFillStatLocked(PNG_FCB Fcb)
{
    LONGLONG Alloc;
    NG_SHARED_HOLD Hold;
    struct ngc_stat St;
    if (!Fcb->HasNode)
        return;
    NgAcquireCoreShared(Fcb->Vcb, &Hold);
    if (NgEnsureNode(Fcb))
    {
        NgReleaseCoreShared(Fcb->Vcb, &Hold);
        return;
    }
    /* Filled in a local: another shared holder may be reading or filling Fcb->Stat. */
    ngc_stat(Fcb->Node, &St);
    NgReleaseCoreShared(Fcb->Vcb, &Hold);
    Fcb->Stat = St;
    if (Fcb->SectionObjectPointers.SharedCacheMap && Fcb->Header.FileSize.QuadPart != (LONGLONG)Fcb->Stat.size)
        DPRINT1("ntfsng: BUG: cached %I64x header size %I64d, core size %I64u\n", Fcb->MftNo,
                Fcb->Header.FileSize.QuadPart, Fcb->Stat.size);
    Fcb->MftNo = Fcb->Stat.mft_ref & 0xffffffffffffULL;
    Fcb->Header.FileSize.QuadPart = Fcb->Stat.size;
    Fcb->Header.ValidDataLength.QuadPart = Fcb->Stat.size;
    /* Cc needs AllocationSize >= FileSize; compressed and sparse streams report less on disk. */
    Alloc = (Fcb->Stat.size + PAGE_SIZE - 1) & ~(LONGLONG)(PAGE_SIZE - 1);
    if ((LONGLONG)Fcb->Stat.alloc > Alloc)
        Alloc = Fcb->Stat.alloc;
    Fcb->Header.AllocationSize.QuadPart = Alloc;
    if (Alloc > Fcb->CachedEnd)
        Fcb->CachedEnd = Alloc;
}

VOID NgDereferenceFcb(PNG_FCB Fcb)
{
    PNG_VCB Vcb = Fcb->Vcb;
    BOOLEAN Free, Core = FALSE;

    /*
     * A last reference to an FCB with a node is dropped under CoreLock, held from before the FCB
     * leaves the list until its node is put: a dismount either finds the FCB in its snapshot or,
     * as it unmounts under CoreLock, waits for the put.  Every new reference is taken under
     * FcbListLock, and whoever attaches or parks a node holds a counted reference, so with
     * RefCount 1 seen under it nobody else can give the FCB a node meanwhile.
     */
    for (;;)
    {
        ExAcquireFastMutex(&Vcb->FcbListLock);
        if (Core || Fcb->RefCount != 1 || !Fcb->Node)
            break;
        ExReleaseFastMutex(&Vcb->FcbListLock);
        NgAcquireCore(Vcb);
        Core = TRUE;
    }
    Free = (InterlockedDecrement(&Fcb->RefCount) == 0);
    if (Free)
        NgFcbRemoveLocked(Fcb);
    if (Free && Fcb->IsPagingFile)
        Vcb->PagingFiles--;
    if (Free && Vcb->VolumeFcb == Fcb)
        Vcb->VolumeFcb = NULL;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    if (Free && Fcb->Node)
    {
        /* Unreachable without CoreLock (a node with RefCount 1 was seen above); never put into a
         * core a dismount has freed. */
        if (!Core)
        {
            NgAcquireCore(Vcb);
            Core = TRUE;
        }
        if (Vcb->Core)
            ngc_put(Fcb->Node);
        else
            DPRINT1("ntfsng: BUG: FCB %p for %I64x kept a node across the dismount\n", Fcb, Fcb->MftNo);
    }
    if (Core)
        NgReleaseCore(Vcb);
    if (!Free)
        return;
    FsRtlUninitializeFileLock(&Fcb->FileLock);
    if (Fcb->Runs)
        ExFreePoolWithTag(Fcb->Runs, TAG_NTFSNG);
    if (Fcb->DelPath.Buffer)
        ExFreePoolWithTag(Fcb->DelPath.Buffer, TAG_NTFSNG);
    ExDeleteResourceLite(&Fcb->MainResource);
    ExDeleteResourceLite(&Fcb->PagingIoResource);
    ExDeleteResourceLite(&Fcb->PagingWriteLock);
    InterlockedDecrement(&NgGlobal.FcbLive);
    ExFreePoolWithTag(Fcb, TAG_NTFSNG);
}

/* EA writes are not implemented. */
static NTSTATUS NgRefuseWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    UNREFERENCED_PARAMETER(Irp);
    return Vcb->ReadOnly ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS NgUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    return STATUS_INVALID_DEVICE_REQUEST;
}

/* TRUE for an open of the volume itself (\\.\C:), whose requests go to the storage stack. */
static BOOLEAN NgIsVolumeOpen(PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    return Fcb && Fcb->IsVolume;
}

/*
 * Requests on a volume handle that may reach the core run under the create gate (shared), as creates
 * and cleanups do: a dismount, which takes it exclusive, then either runs before them (they see the
 * volume dismounted) or after them, never while they use the core it frees.  The lock holder can send
 * them on other threads of an asynchronous handle while its own dismount runs.  Lock, unlock and
 * dismount take the gate themselves, exclusive (an unlock may dismount, NgEndLock).
 */
static BOOLEAN NgVolumeRequestGated(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    UCHAR Major = Stack->MajorFunction;
    if (!NgIsVolumeOpen(Irp) || (Irp->Flags & IRP_PAGING_IO))
        return FALSE;
    if (Major == IRP_MJ_CREATE || Major == IRP_MJ_CLEANUP || Major == IRP_MJ_CLOSE ||
        Major == IRP_MJ_DEVICE_CONTROL || Major == IRP_MJ_LOCK_CONTROL)
        return FALSE;
    if (Major == IRP_MJ_FILE_SYSTEM_CONTROL)
    {
        ULONG Code = Stack->Parameters.FileSystemControl.FsControlCode;
        if (Stack->MinorFunction != IRP_MN_USER_FS_REQUEST && Stack->MinorFunction != IRP_MN_KERNEL_CALL)
            return FALSE;
        if (Code == FSCTL_LOCK_VOLUME || Code == FSCTL_UNLOCK_VOLUME || Code == FSCTL_DISMOUNT_VOLUME)
            return FALSE;
    }
    return TRUE;
}

/*
 * Volume handles pass storage IOCTLs (geometry, partition info, mount manager queries)
 * through.  Files and directories refuse device controls: kernel32 takes a
 * directory whose handle answers IOCTL_MOUNTDEV_QUERY_DEVICE_NAME for a volume root.
 */
static NTSTATUS NgPassToStorage(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    if (!NgIsVolumeOpen(Irp))
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(Vcb->StorageDevice, Irp);
}

/*
 * PnP requests for the storage device under a mounted volume come to the volume device: the I/O
 * manager sends them there through the VPB.  They go on to the storage device, which must see them
 * (a partition device deletes its links and interfaces at its removal).  A query for an orderly
 * removal is refused here when the volume is in use or cannot be written back (NgQueryRemove), and
 * then does not reach the device.  A removal is passed on after NgDismountForRemoval, which writes
 * nothing unless the removal was asked for first: a surprise-removed device is cut off before the
 * request goes down, so no write of this mount reaches it at any point.  Handled before the
 * dismounted and medium checks: a dismounted or fenced volume device still passes them on.
 */
static NTSTATUS NgPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    UCHAR Minor = IoGetCurrentIrpStackLocation(Irp)->MinorFunction;
    NTSTATUS Status = STATUS_SUCCESS;

    FsRtlEnterFileSystem();
    if (Minor == IRP_MN_QUERY_REMOVE_DEVICE)
        Status = NgQueryRemove(Vcb);
    else if (Minor == IRP_MN_CANCEL_REMOVE_DEVICE)
        NgCancelRemove(Vcb);
    else if (Minor == IRP_MN_SURPRISE_REMOVAL || Minor == IRP_MN_REMOVE_DEVICE)
        NgDismountForRemoval(Vcb, Minor == IRP_MN_SURPRISE_REMOVAL);
    FsRtlExitFileSystem();

    if (!NT_SUCCESS(Status))
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(Vcb->StorageDevice, Irp);
}

/* IRP_MJ_CLEANUP on a dismounted volume (from NgCleanup, which gave up the volume lock): only the handle's own state, the core is gone. */
NTSTATUS NgCleanupDismounted(PNG_VCB Vcb, PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_CCB Ccb = FileObject->FsContext2;

    if (!Fcb)
        return STATUS_SUCCESS;
    if (Fcb->IsDirectory && Vcb->NotifySync && Ccb)
        FsRtlNotifyCleanup(Vcb->NotifySync, &Vcb->DirNotifyList, Ccb);
    if (!Fcb->IsDirectory && !Fcb->IsVolume)
    {
        FsRtlFastUnlockAll(&Fcb->FileLock, FileObject, IoGetRequestorProcess(Irp), NULL);
        CcUninitializeCacheMap(FileObject, NULL, NULL);
    }
    ExAcquireFastMutex(&Vcb->FcbListLock);
    IoRemoveShareAccess(FileObject, &Fcb->ShareAccess);
    Fcb->OpenHandles--;
    ExReleaseFastMutex(&Vcb->FcbListLock);
    FileObject->Flags |= FO_CLEANUP_COMPLETE;
    return STATUS_SUCCESS;
}

/*
 * Requests on a dismounted volume: closes and cleanups go on, the volume handle reads and writes the
 * disk directly while it still holds the lock and may unlock, device controls pass to the storage
 * device; everything else fails with STATUS_VOLUME_DISMOUNTED, also the handle's reads and writes
 * after the unlock, as on Windows (the volume may be mounted again under it by then).
 */
static NTSTATUS NgDismountedRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    PNG_FCB Fcb = Stack->FileObject ? Stack->FileObject->FsContext : NULL;
    BOOLEAN Volume = Fcb && Fcb->IsVolume;

    switch (Stack->MajorFunction)
    {
        case IRP_MJ_CLOSE:
            return NgClose(DeviceObject, Irp);
        case IRP_MJ_CLEANUP:
            return NgCleanup(DeviceObject, Irp);
        case IRP_MJ_READ:
            return Volume && Vcb->LockedBy == Stack->FileObject ? NgRead(DeviceObject, Irp) : STATUS_VOLUME_DISMOUNTED;
        case IRP_MJ_WRITE:
            if (!Volume && Fcb && !Fcb->IsPagingFile && (Irp->Flags & IRP_PAGING_IO))
                return NgDropPagingWrite(Vcb, Fcb, Irp, Stack->Parameters.Write.Length);
            return Volume && Vcb->LockedBy == Stack->FileObject ? NgWrite(DeviceObject, Irp) : STATUS_VOLUME_DISMOUNTED;
        case IRP_MJ_FLUSH_BUFFERS:
            return Volume ? STATUS_SUCCESS : STATUS_VOLUME_DISMOUNTED;
        case IRP_MJ_FILE_SYSTEM_CONTROL:
            if (Volume && (Stack->MinorFunction == IRP_MN_USER_FS_REQUEST || Stack->MinorFunction == IRP_MN_KERNEL_CALL) &&
                Stack->Parameters.FileSystemControl.FsControlCode == FSCTL_UNLOCK_VOLUME)
                return NgFileSystemControl(DeviceObject, Irp);
            return STATUS_VOLUME_DISMOUNTED;
        default:
            return STATUS_VOLUME_DISMOUNTED;
    }
}

/* Fast I/O: cached reads go straight to Cc (FsRtlCopyRead); everything else takes the IRP path. */
static BOOLEAN NTAPI NgFastIoCheckIfPossible(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length,
                                             BOOLEAN Wait, ULONG LockKey, BOOLEAN CheckForReadOperation,
                                             PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject)
{
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    LARGE_INTEGER Len;
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(IoStatus);
    UNREFERENCED_PARAMETER(DeviceObject);
    if (!CheckForReadOperation || !Fcb || Fcb->IsVolume || Fcb->IsDirectory)
        return FALSE;
    /* Cached data of a medium that is gone, or may be: the IRP path verifies first. */
    if (Fcb->Vcb->WrongMedia || (Fcb->Vcb->Removable && (Fcb->Vcb->Vpb->RealDevice->Flags & DO_VERIFY_VOLUME)))
        return FALSE;
    Len.QuadPart = Length;
    return FsRtlFastCheckLockForRead(&Fcb->FileLock, FileOffset, &Len, LockKey, FileObject, PsGetCurrentProcess());
}

static BOOLEAN NTAPI NgFastIoWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length,
                                   BOOLEAN Wait, ULONG LockKey, PVOID Buffer, PIO_STATUS_BLOCK IoStatus,
                                   PDEVICE_OBJECT DeviceObject)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FileOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Wait);
    UNREFERENCED_PARAMETER(LockKey);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(IoStatus);
    UNREFERENCED_PARAMETER(DeviceObject);
    return FALSE;
}

static FAST_IO_DISPATCH NgFastIoDispatch;

typedef NTSTATUS (*NG_HANDLER)(PDEVICE_OBJECT, PIRP);
static NG_HANDLER NgHandlers[IRP_MJ_MAXIMUM_FUNCTION + 1];

/*
 * A request on a volume whose medium was replaced fails (cleanup and close aside).  On removable media
 * a pending media change is verified first, so requests on open handles notice it too, not only opens
 * (creates verify in NgCreate, where a new medium means a reparse).  Requests that cannot wait for a
 * verify (paging I/O, raised IRQL) fail while one is pending.
 */
static NTSTATUS NgMediumGone(PNG_VCB Vcb, PIRP Irp, PIO_STACK_LOCATION Stack)
{
    UCHAR Major = Stack->MajorFunction;
    NTSTATUS Status;
    if (Major == IRP_MJ_CLEANUP || Major == IRP_MJ_CLOSE ||
        (Major == IRP_MJ_FILE_SYSTEM_CONTROL && Stack->MinorFunction == IRP_MN_VERIFY_VOLUME))
        return STATUS_SUCCESS;
    /* Locking the volume and ejecting the medium stay possible on a volume whose medium is gone. */
    if (Major == IRP_MJ_FILE_SYSTEM_CONTROL && Stack->MinorFunction == IRP_MN_USER_FS_REQUEST &&
        (Stack->Parameters.FileSystemControl.FsControlCode == FSCTL_LOCK_VOLUME ||
         Stack->Parameters.FileSystemControl.FsControlCode == FSCTL_UNLOCK_VOLUME ||
         Stack->Parameters.FileSystemControl.FsControlCode == FSCTL_DISMOUNT_VOLUME))
        return STATUS_SUCCESS;
    if (Major == IRP_MJ_DEVICE_CONTROL &&
        (Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_STORAGE_EJECT_MEDIA ||
         Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DISK_EJECT_MEDIA ||
         Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_STORAGE_MEDIA_REMOVAL ||
         Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DISK_MEDIA_REMOVAL))
        return STATUS_SUCCESS;
    if (Vcb->Removable && !Vcb->WrongMedia && Major != IRP_MJ_CREATE &&
        (Vcb->Vpb->RealDevice->Flags & DO_VERIFY_VOLUME))
    {
        if ((Irp->Flags & IRP_PAGING_IO) || KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_VERIFY_REQUIRED;
        Status = NgCheckMedium(Vcb);
        if (!NT_SUCCESS(Status))
            return Vcb->WrongMedia ? STATUS_FILE_INVALID : Status;
    }
    return Vcb->WrongMedia ? STATUS_FILE_INVALID : STATUS_SUCCESS;
}

/*
 * The single dispatch entry: enters the file system, measures stack use and
 * completes the IRP with the handler's status (handlers never pend).
 */
static NTSTATUS NTAPI NgDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR Major = Stack->MajorFunction;
    BOOLEAN TopLevel = FALSE;
    PERESOURCE Gate = NULL;
    ULONG_PTR Low;
    NTSTATUS Status;
#if DBG
    ULONGLONG T0 = __rdtsc();
#endif

    /* Not a request of this file system: the storage device completes it (NgPnp). */
    if (DeviceObject != NgGlobal.ControlDevice && Major == IRP_MJ_PNP)
        return NgPnp(DeviceObject, Irp);

    Low = NgStackFill();
    FsRtlEnterFileSystem();
    if (!IoGetTopLevelIrp())
    {
        IoSetTopLevelIrp(Irp);
        TopLevel = TRUE;
    }
    Irp->IoStatus.Information = 0;
    if (DeviceObject != NgGlobal.ControlDevice && NgVolumeRequestGated(Irp, Stack))
    {
        Gate = &((PNG_VCB)DeviceObject->DeviceExtension)->CreateGate;
        ExAcquireResourceSharedLite(Gate, TRUE);
    }
    if (DeviceObject == NgGlobal.ControlDevice && Major != IRP_MJ_FILE_SYSTEM_CONTROL)
    {
        /* The control device only accepts opens/closes and mount requests. */
        if (Major == IRP_MJ_SHUTDOWN)
            Status = NgShutdown(DeviceObject, Irp);
        else
            Status = (Major == IRP_MJ_CREATE || Major == IRP_MJ_CLEANUP || Major == IRP_MJ_CLOSE)
                     ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
        if (Major == IRP_MJ_CREATE)
            Irp->IoStatus.Information = FILE_OPENED;
    }
    else if (DeviceObject != NgGlobal.ControlDevice && ((PNG_VCB)DeviceObject->DeviceExtension)->Dismounted &&
             !(Major == IRP_MJ_DEVICE_CONTROL && NgIsVolumeOpen(Irp)))
    {
        Status = NgDismountedRequest(DeviceObject, Irp);
    }
    else if (DeviceObject != NgGlobal.ControlDevice && Major == IRP_MJ_WRITE &&
             NgDropIfDiscardable((PNG_VCB)DeviceObject->DeviceExtension, Irp, &Status))
    {
        /* Before the medium checks: a refused page write is retried forever (see NgDropPagingWrite). */
    }
    else if (DeviceObject != NgGlobal.ControlDevice &&
             !NT_SUCCESS(Status = NgMediumGone((PNG_VCB)DeviceObject->DeviceExtension, Irp, Stack)))
    {
        /* Status says why */
    }
    else if (Major == IRP_MJ_DEVICE_CONTROL && DeviceObject != NgGlobal.ControlDevice)
    {
        /* Passed down: the storage stack completes it. */
        Status = NgPassToStorage(DeviceObject, Irp);
        goto out;
    }
    else if (Major == IRP_MJ_LOCK_CONTROL)
    {
        /* FsRtl completes lock IRPs itself. */
        Status = NgLockControl(DeviceObject, Irp);
        goto out;
    }
    else
    {
        Status = NgHandlers[Major](DeviceObject, Irp);
    }
    if (Gate)
    {
        /* Before completion: a completion routine may lock or dismount the volume, which takes the gate exclusive. */
        ExReleaseResourceLite(Gate);
        Gate = NULL;
    }
    if (Status != STATUS_PENDING)
    {
        NgDiagLogRequest(DeviceObject, Irp, Status);
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, NT_SUCCESS(Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
    }
out:
    if (Gate)
        ExReleaseResourceLite(Gate);
    if (TopLevel)
        IoSetTopLevelIrp(NULL);
    FsRtlExitFileSystem();
    NgStackScan(Low, Major);
#if DBG
    ngos_prof(NGP_IRP + Major, T0, 0);
#endif
    return Status;
}

/* Reads a REG_DWORD from the service key; 0 if it is absent. */
ULONG NgReadDword(PUNICODE_STRING KeyPath, PCWSTR Name)
{
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING ValueName;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length, Value = 0;
    NTSTATUS Status;

    InitializeObjectAttributes(&Oa, KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenKey(&Key, KEY_READ, &Oa);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ntfsng: cannot open %wZ (0x%08lx)\n", KeyPath, Status);
        return 0;
    }
    RtlInitUnicodeString(&ValueName, Name);
    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Status) && Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
        Value = *(PULONG)Info->Data;
    ZwClose(Key);
    return Value;
}

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING Name;
    NTSTATUS Status;
    ULONG i;
    int Err;

    DPRINT1("ntfsng: NTFS on the Linux fs/ntfs core (v7.3-rc6), loading\n");
    /* Queried once here, at PASSIVE_LEVEL: later callers may hold a spin lock. */
    ngos_physical_pages();
    ExInitializeFastMutex(&NgGlobal.VcbListLock);
    InitializeListHead(&NgGlobal.VcbList);
#if DBG
    {
        LARGE_INTEGER F, P0, P1, Delay;
        ULONGLONG C0, C1;
        P0 = KeQueryPerformanceCounter(&F);
        C0 = __rdtsc();
        Delay.QuadPart = -20 * 10000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        P1 = KeQueryPerformanceCounter(NULL);
        C1 = __rdtsc();
        if (P1.QuadPart > P0.QuadPart)
            NgPerfFrequency = (LONGLONG)((C1 - C0) * (ULONGLONG)F.QuadPart / (ULONGLONG)(P1.QuadPart - P0.QuadPart));
        NgProfile.TicksPerSecond = (ULONGLONG)NgPerfFrequency;
        DPRINT1("ntfsng: lock timing at %I64d ticks/s\n", NgPerfFrequency);
    }
#endif
    NgGlobal.PermissiveOpen = NgReadDword(RegistryPath, L"PermissiveOpen");
    NgGlobal.ForceReadOnly = NgReadDword(RegistryPath, L"ReadOnly");
    NgGlobal.Verbose = NgReadDword(RegistryPath, L"Verbose");
    /* "MountCheck": 0 or absent = after an unclean shutdown and for small MFTs, 1 = always, 2 = never. */
    i = NgReadDword(RegistryPath, L"MountCheck");
    ngc_check_policy = i == 1 ? 2 : i == 2 ? 0 : 1;
    {
        /* The system-wide NTFS switch for short names (0 = create them, as on Windows). */
        UNICODE_STRING Fs = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\FileSystem");
        NgGlobal.Disable8dot3 = NgReadDword(&Fs, L"NtfsDisable8dot3NameCreation") == 1;
    }
    DPRINT1("ntfsng: ReadOnly=%lu\n", NgGlobal.ForceReadOnly);
#if DBG
    i = NgReadDword(RegistryPath, L"JournalFault");
    if (i)
    {
        /* Test only: stop the machine inside one commit between JournalFault and 2*JournalFault. */
        LARGE_INTEGER Now;
        ULONG Target;
        KeQuerySystemTime(&Now);
        Target = i + (ULONG)((ULONGLONG)Now.QuadPart / 10000 % i);
        ngc_set_journal_fault(Target);
        DPRINT1("ntfsng: JournalFault: the system stops in the middle of commit %lu\n", Target);
    }
#endif
#if DBG
    i = NgReadDword(RegistryPath, L"JournalFaultStage");
    if (i)
        ngc_set_journal_fault_stage(i);
    i = NgReadDword(RegistryPath, L"JournalStall");
    if (i)
    {
        /* Test only: the unlocked journal I/O of a commit pauses this many ms between its phases. */
        ngc_set_journal_stall(i);
        DPRINT1("ntfsng: JournalStall: the journal I/O of a commit pauses %lu ms between its phases\n", i);
    }
#endif
    /* NoUnlockedCommit=1: every commit is synchronous under CoreLock, as before the journal I/O left it (comparison, fallback). */
    if (NgReadDword(RegistryPath, L"NoUnlockedCommit"))
    {
        ngc_unlocked_commit = 0;
        DPRINT1("ntfsng: NoUnlockedCommit: commits run under CoreLock\n");
    }
#if DBG
    i = NgReadDword(RegistryPath, L"DioFault");
    if (i)
    {
        /* Test only: every DioFault'th unlocked paging write is reported as changed under the transfer and written again. */
        ngc_set_dio_fault(i);
        DPRINT1("ntfsng: DioFault: every %lu'th unlocked paging write is forced to be written again\n", i);
    }
#endif
    DPRINT1("ntfsng: service key %wZ, PermissiveOpen=%lu%s\n", RegistryPath, NgGlobal.PermissiveOpen,
            NgGlobal.PermissiveOpen ? " (opens with write access are granted, modifications are still refused)" : "");

    Err = ngc_init();
    if (Err)
    {
        DPRINT1("ntfsng: core init failed %d\n", Err);
        return STATUS_UNSUCCESSFUL;
    }

    RtlInitUnicodeString(&Name, L"\\NtfsNg");
    Status = IoCreateDevice(DriverObject, 0, &Name, FILE_DEVICE_DISK_FILE_SYSTEM, 0, FALSE,
                            &NgGlobal.ControlDevice);
    if (!NT_SUCCESS(Status))
        return Status;
    NgGlobal.DriverObject = DriverObject;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        NgHandlers[i] = NgUnsupported;
        DriverObject->MajorFunction[i] = NgDispatch;
    }
    NgHandlers[IRP_MJ_CREATE] = NgCreate;
    NgHandlers[IRP_MJ_CLEANUP] = NgCleanup;
    NgHandlers[IRP_MJ_CLOSE] = NgClose;
    NgHandlers[IRP_MJ_READ] = NgRead;
    NgHandlers[IRP_MJ_WRITE] = NgWrite;
    NgHandlers[IRP_MJ_QUERY_INFORMATION] = NgQueryInformation;
    NgHandlers[IRP_MJ_SET_INFORMATION] = NgSetInformation;
    NgHandlers[IRP_MJ_SET_EA] = NgRefuseWrite;
    NgHandlers[IRP_MJ_SET_VOLUME_INFORMATION] = NgSetVolumeInformation;
    NgHandlers[IRP_MJ_SET_SECURITY] = NgSetSecurity;
    NgHandlers[IRP_MJ_QUERY_SECURITY] = NgQuerySecurity;
    NgHandlers[IRP_MJ_FLUSH_BUFFERS] = NgFlushBuffers;
    NgHandlers[IRP_MJ_SHUTDOWN] = NgShutdown;
    NgHandlers[IRP_MJ_QUERY_VOLUME_INFORMATION] = NgQueryVolumeInformation;
    NgHandlers[IRP_MJ_DIRECTORY_CONTROL] = NgDirectoryControl;
    NgHandlers[IRP_MJ_FILE_SYSTEM_CONTROL] = NgFileSystemControl;
    DriverObject->DriverUnload = NULL;

    NgFastIoDispatch.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
    NgFastIoDispatch.FastIoCheckIfPossible = NgFastIoCheckIfPossible;
    NgFastIoDispatch.FastIoRead = FsRtlCopyRead;
    NgFastIoDispatch.FastIoWrite = NgFastIoWrite;
    DriverObject->FastIoDispatch = &NgFastIoDispatch;

    NgGlobal.CacheCallbacks.AcquireForLazyWrite = NgAcquireForLazyWrite;
    NgGlobal.CacheCallbacks.ReleaseFromLazyWrite = NgReleaseFromLazyWrite;
    NgGlobal.CacheCallbacks.AcquireForReadAhead = NgAcquireForReadAhead;
    NgGlobal.CacheCallbacks.ReleaseFromReadAhead = NgReleaseFromReadAhead;

    NgGlobal.ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    IoRegisterFileSystem(NgGlobal.ControlDevice);
    DPRINT1("ntfsng: registered file system\n");
    return STATUS_SUCCESS;
}
