/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Paging file: Mm's page reads and writes go straight to the clusters of the
 *              preallocated file, without the core, the volume lock or memory allocation
 *              beyond the device request itself.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"

#define NDEBUG
#include <debug.h>

/* The largest paging transfer the volume's reserve IRP and MDL can carry (64 KB plus one page of offset) */
#define NG_PAGING_RESERVE_PAGES 17

static VOID NgPagingReserveInit(PNG_VCB Vcb);

/*
 * Test (NitroPagerDebug 0x80 in Session Manager\Memory Management, read once by DriverEntry, before any
 * volume or CoreLock exists: no registry access on the paging path): every third IRP or partial MDL
 * allocation of NgPagingDevIo fails, so that the reserve IRP and MDL carry real paging I/O (the kernel
 * does the same for its own paging IRPs).
 */
#define NG_PAGING_DEBUG_FAIL_ALLOC 0x80
static ULONG NgPagingDebug;
static LONG NgPagingAllocCalls;

VOID NgPagingSetDebug(ULONG Value)
{
    NgPagingDebug = Value;
    if (NgPagingDebug & NG_PAGING_DEBUG_FAIL_ALLOC)
        DbgPrint("ntfsng: test: every third paging IRP/MDL allocation fails\n");
}

static BOOLEAN NgPagingInjectFailure(VOID)
{
    return (NgPagingDebug & NG_PAGING_DEBUG_FAIL_ALLOC) && ((InterlockedIncrement(&NgPagingAllocCalls) % 3) == 0);
}

/* IO_DISK_INCREMENT for the waiter, as for the core's transfers (NgReadCompletion). */
static NTSTATUS NTAPI NgPagingCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent(Context, IO_DISK_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * One device transfer of a piece of Mm's MDL.  The pages are already locked and may be in the
 * middle of being paged out, so they are described by the caller's MDL (or a partial MDL of it)
 * and never probed and locked again.
 */
static NTSTATUS NgPagingDevIo(PNG_VCB Vcb, UCHAR Major, ULONGLONG Dev, PMDL Mdl, ULONG MdlOffset, ULONG Length)
{
    PDEVICE_OBJECT Target = Vcb->StorageDevice;
    PIO_STACK_LOCATION Next;
    PMDL Partial = NULL;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;
    BOOLEAN Reserve = FALSE;

    /* Paging I/O cannot wait for the core lock: a transfer issued before a verify completes still goes out. */
    if (Vcb->WrongMedia)
        return STATUS_FILE_INVALID;
    Irp = NgPagingInjectFailure() ? NULL : IoAllocateIrp(Target->StackSize, FALSE);
    if (Irp && (MdlOffset || Length != MmGetMdlByteCount(Mdl)))
    {
        PCHAR Va = (PCHAR)MmGetMdlVirtualAddress(Mdl) + MdlOffset;
        Partial = NgPagingInjectFailure() ? NULL : IoAllocateMdl(Va, Length, FALSE, FALSE, NULL);
        if (!Partial)
        {
            IoFreeIrp(Irp);
            Irp = NULL;
        }
        else
        {
            IoBuildPartialMdl(Mdl, Partial, Va, Length);
        }
    }
    if (!Irp)
    {
        /*
         * No pool: this transfer may be the one that frees memory (a page written out). Wait for the
         * volume's reserve IRP and partial MDL, if the transfer fits them; otherwise fail as before.
         */
        PCHAR Va = (PCHAR)MmGetMdlVirtualAddress(Mdl) + MdlOffset;

        if (!Vcb->PagingReserveReady ||
            Target->StackSize > Vcb->PagingReserveIrp->StackCount ||
            ADDRESS_AND_SIZE_TO_SPAN_PAGES(Va, Length) > NG_PAGING_RESERVE_PAGES)
            return STATUS_INSUFFICIENT_RESOURCES;
        KeWaitForSingleObject(&Vcb->PagingReserveFree, Executive, KernelMode, FALSE, NULL);
        Reserve = TRUE;
        {
            /* Evidence on the debug channel (free builds too): the 1st, 2nd, 4th, 8th ... use */
            LONG Uses = InterlockedIncrement(&Vcb->PagingReserveUses);
            if ((Uses & (Uses - 1)) == 0)
                DbgPrint("ntfsng: paging reserve IRP/MDL used %ld times\n", Uses);
        }
        Irp = Vcb->PagingReserveIrp;
        IoInitializeIrp(Irp, IoSizeOfIrp(Target->StackSize), Target->StackSize);
        if (MdlOffset || Length != MmGetMdlByteCount(Mdl))
        {
            Partial = Vcb->PagingReserveMdl;
            MmInitializeMdl(Partial, Va, Length);
            IoBuildPartialMdl(Mdl, Partial, Va, Length);
        }
    }
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp->MdlAddress = Partial ? Partial : Mdl;
    Irp->Flags = IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO |
                 (Major == IRP_MJ_READ ? IRP_READ_OPERATION : IRP_WRITE_OPERATION);
    Irp->RequestorMode = KernelMode;
    Irp->Tail.Overlay.Thread = PsGetCurrentThread();
    Next = IoGetNextIrpStackLocation(Irp);
    Next->MajorFunction = Major;
    Next->Flags = SL_OVERRIDE_VERIFY_VOLUME | (Major == IRP_MJ_WRITE ? SL_WRITE_THROUGH : 0);
    Next->Parameters.Read.Length = Length;
    Next->Parameters.Read.ByteOffset.QuadPart = (LONGLONG)Dev;
    IoSetCompletionRoutine(Irp, NgPagingCompletion, &Event, TRUE, TRUE, TRUE);
    Status = IoCallDriver(Target, Irp);
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    Status = Irp->IoStatus.Status;
    Irp->MdlAddress = NULL;
    if (Reserve)
    {
        if (Partial && (Partial->MdlFlags & MDL_PARTIAL_HAS_BEEN_MAPPED))
            MmPrepareMdlForReuse(Partial);
        KeSetEvent(&Vcb->PagingReserveFree, IO_NO_INCREMENT, FALSE);
        return Status;
    }
    IoFreeIrp(Irp);
    if (Partial)
        IoFreeMdl(Partial);
    return Status;
}

/*
 * The volume's paging reserve (NgPagingDevIo), once, when a paging file is first mapped. Caller holds
 * CoreLock. It lives as long as the volume device: ntfsng never deletes a mounted volume's device
 * object (nor its Vcb), so there is no teardown that could free it.
 */
static VOID NgPagingReserveInit(PNG_VCB Vcb)
{
    PDEVICE_OBJECT Target = Vcb->StorageDevice;

    if (Vcb->PagingReserveReady)
        return;
    /* Room for a deeper stack than today's, should a filter be attached later */
    Vcb->PagingReserveIrp = IoAllocateIrp((CCHAR)(Target->StackSize + 2), FALSE);
    Vcb->PagingReserveMdl = IoAllocateMdl(NULL, NG_PAGING_RESERVE_PAGES * PAGE_SIZE, FALSE, FALSE, NULL);
    if (!Vcb->PagingReserveIrp || !Vcb->PagingReserveMdl)
    {
        if (Vcb->PagingReserveIrp)
            IoFreeIrp(Vcb->PagingReserveIrp);
        if (Vcb->PagingReserveMdl)
            IoFreeMdl(Vcb->PagingReserveMdl);
        Vcb->PagingReserveIrp = NULL;
        Vcb->PagingReserveMdl = NULL;
        DPRINT1("ntfsng: no paging reserve for this volume (no pool now), tried again at the next map\n");
        return;
    }
    KeInitializeEvent(&Vcb->PagingReserveFree, SynchronizationEvent, TRUE);
    Vcb->PagingReserveReady = TRUE;
}

typedef struct
{
    PNG_RUN Runs;
    ULONG Count;
    ULONG Cap;
} NG_RUN_BUILD;

static int NgCollectRun(void *Context, unsigned long long Vcn, long long Lcn, unsigned long long Len)
{
    NG_RUN_BUILD *B = Context;
    if (B->Count == B->Cap)
    {
        ULONG Cap = B->Cap ? B->Cap * 2 : 64;
        PNG_RUN New = ExAllocatePoolWithTag(NonPagedPool, Cap * sizeof(NG_RUN), TAG_NTFSNG);
        if (!New)
            return -NGC_ENOMEM;
        if (B->Runs)
        {
            RtlCopyMemory(New, B->Runs, B->Count * sizeof(NG_RUN));
            ExFreePoolWithTag(B->Runs, TAG_NTFSNG);
        }
        B->Runs = New;
        B->Cap = Cap;
    }
    B->Runs[B->Count].Vcn = Vcn;
    B->Runs[B->Count].Lcn = Lcn;
    B->Runs[B->Count].Len = Len;
    B->Count++;
    return 0;
}

/* Rebuilds the cluster map of a paging file after a size change.  Caller holds CoreLock. */
NTSTATUS NgPagingFileMap(PNG_FCB Fcb)
{
    NG_RUN_BUILD B = { NULL, 0, 0 };
    PNG_RUN Old;
    KIRQL Irql;
    int Err;

    Err = NgEnsureNode(Fcb);
    if (!Err)
        Err = ngc_runs(Fcb->Vcb->Core, Fcb->Node, NgCollectRun, &B);
    if (Err == -NGC_EINVAL)
        Err = 0;    /* still resident (empty): nothing to map */
    if (Err)
    {
        if (B.Runs)
            ExFreePoolWithTag(B.Runs, TAG_NTFSNG);
        DPRINT1("ntfsng: paging file map failed %d\n", Err);
        return NgErrnoToStatus(Err);
    }
    NgPagingReserveInit(Fcb->Vcb);
    KeAcquireSpinLock(&Fcb->RunLock, &Irql);
    Old = Fcb->Runs;
    Fcb->Runs = B.Runs;
    Fcb->RunCount = B.Count;
    KeReleaseSpinLock(&Fcb->RunLock, Irql);
    if (Old)
        ExFreePoolWithTag(Old, TAG_NTFSNG);
    DPRINT1("ntfsng: paging file %I64x: %I64d bytes in %lu runs\n", Fcb->MftNo, Fcb->Header.FileSize.QuadPart, B.Count);
    return STATUS_SUCCESS;
}

/* Device offset and contiguous length for Offset, from the map; FALSE outside it or in a hole. */
static BOOLEAN NgPagingFileLookup(PNG_FCB Fcb, LONGLONG Offset, ULONG ClusterSize, ULONGLONG *Dev, ULONGLONG *Avail)
{
    LONGLONG Vcn = Offset / ClusterSize;
    BOOLEAN Found = FALSE;
    KIRQL Irql;
    ULONG i;

    KeAcquireSpinLock(&Fcb->RunLock, &Irql);
    for (i = 0; i < Fcb->RunCount; i++)
    {
        PNG_RUN R = &Fcb->Runs[i];
        if (Vcn >= R->Vcn && Vcn < R->Vcn + R->Len)
        {
            if (R->Lcn >= 0)
            {
                *Dev = (ULONGLONG)(R->Lcn + (Vcn - R->Vcn)) * ClusterSize + Offset % ClusterSize;
                *Avail = (ULONGLONG)(R->Vcn + R->Len) * ClusterSize - Offset;
                Found = TRUE;
            }
            break;
        }
    }
    KeReleaseSpinLock(&Fcb->RunLock, Irql);
    return Found;
}

NTSTATUS NgPagingFileIo(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, BOOLEAN Write, LONGLONG Offset, ULONG Length)
{
    ULONG Done = 0;
    /* UF-22: use the cluster size cached immutably at mount. ngc_volinfo() refills the shared
     * Vcb->Info by zeroing it first, so a concurrent volume-info query exposes a transient
     * cluster_size of 0 and the per-cluster divide below would bugcheck (STOP 0x7E) on this
     * hot path, where a failed page-in cannot be retried. The mount-time value never changes. */
    ULONG ClusterSize = Vcb->ClusterSize;

    if (!Irp->MdlAddress || Offset < 0 || Offset + Length > Fcb->Header.AllocationSize.QuadPart ||
        Length > MmGetMdlByteCount(Irp->MdlAddress))
        return STATUS_INVALID_PARAMETER;
    while (Done < Length)
    {
        ULONGLONG Dev, Avail;
        NTSTATUS Status;
        ULONG N;
        if (!NgPagingFileLookup(Fcb, Offset + Done, ClusterSize, &Dev, &Avail))
        {
            DPRINT1("ntfsng: paging file %s at %I64d is outside the map\n", Write ? "write" : "read", Offset + Done);
            return STATUS_UNEXPECTED_IO_ERROR;
        }
        N = (ULONG)min((ULONGLONG)(Length - Done), Avail);
        Status = NgPagingDevIo(Vcb, Write ? IRP_MJ_WRITE : IRP_MJ_READ, Dev, Irp->MdlAddress, Done, N);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ntfsng: paging file %s at %I64d failed 0x%lx\n", Write ? "write" : "read", Offset + Done, Status);
            return Status;
        }
        Done += N;
    }
    if (InterlockedIncrement(Write ? &Vcb->PagingFileWrites : &Vcb->PagingFileReads) == 1)
        DPRINT1("ntfsng: first paging file %s done (%lu bytes at %I64d)\n", Write ? "write" : "read", Length, Offset);
    Irp->IoStatus.Information = Length;
    return STATUS_SUCCESS;
}
