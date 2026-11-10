/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP_MJ_READ: cached (CcCopyRead), non-cached and paging reads
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"

int ngos_dev_read(void *dev, unsigned long long off, void *buf, unsigned int len);

/*
 * Raw read of an open volume (DASD): whole sectors, offsets relative to the partition, read
 * from the storage device into the locked user buffer.  The disk stack needs an MDL, which the
 * user request does not carry, so the request is not passed down as it is.
 */
static NTSTATUS NgReadVolume(PNG_VCB Vcb, PIRP Irp, LONGLONG Offset, ULONG Length)
{
    PMDL Mdl = NULL;
    PUCHAR Buffer, Bounce;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Done = 0;
    NG_SHARED_HOLD Hold;

    if (((ULONG)Offset | Length) & (Vcb->SectorSize - 1) || Offset < 0)
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
            MmProbeAndLockPages(Mdl, Irp->RequestorMode, IoWriteAccess);
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
    /* Through an aligned pool buffer: IDE DMA refuses odd user addresses. */
    Bounce = ExAllocatePoolWithTag(NonPagedPool, 64 * 1024, TAG_NTFSNG);
    if (!Bounce)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    /* Per chunk under the core lock: a verify cannot mark the medium gone between the check and the read. */
    while (Done < Length)
    {
        ULONG n = min(Length - Done, 64 * 1024);
        BOOLEAN Failed;
        NgAcquireCoreShared(Vcb, &Hold);
        if (Vcb->WrongMedia)
        {
            NgReleaseCoreShared(Vcb, &Hold);
            Status = STATUS_FILE_INVALID;
            break;
        }
        Failed = ngos_dev_read(Vcb->StorageDevice, (unsigned long long)Offset + Done, Bounce, n) != 0;
        NgReleaseCoreShared(Vcb, &Hold);
        if (Failed)
        {
            Status = Done ? STATUS_SUCCESS : STATUS_END_OF_FILE;
            break;
        }
        RtlCopyMemory(Buffer + Done, Bounce, n);
        Done += n;
    }
    ExFreePoolWithTag(Bounce, TAG_NTFSNG);
    Irp->IoStatus.Information = Done;
out:
    if (Mdl)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
    return Status;
}

/* The device part of an unlocked read (no CoreLock): straight into the caller's locked buffer, zeros for the rest. */
static int NgRdioTransfer(PNG_VCB Vcb, const struct ngc_dio *Dio, PUCHAR Buffer)
{
    ULONG r;
    for (r = 0; r < Dio->nruns; r++)
    {
        if (Dio->run[r].dev == NGC_DIO_ZERO)
            RtlZeroMemory(Buffer + Dio->run[r].boff, Dio->run[r].len);
        else if (ngos_dev_read(Vcb->StorageDevice, Dio->run[r].dev, Buffer + Dio->run[r].boff, Dio->run[r].len))
            return -1;
    }
    return 0;
}

/*
 * A non-cached read comes after the data writes of its stream that are in flight.  CcFlushCache above does not
 * wait for a VACB another thread is flushing (the lazy writer clears its dirty mark first), and the unlocked
 * transfer of such a write no longer holds CoreLock, which used to make the reader wait; so a read could return
 * the clusters before that write reached them or raised the initialized size (zeros, seen by pwchk).  A lazy writer holds
 * PagingIoResource shared from before it marks the view clean until its write is done: taking it exclusive waits
 * for that (every paging write transfer holds it shared until its ngc_dio_end); a non-cached write holds PagingWriteLock exclusive throughout.  Both are
 * taken one after the other and dropped at once, with nothing else held (MainResource was released after the flush).
 */
static VOID NgWaitStreamWrites(PNG_FCB Fcb)
{
    ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
    ExReleaseResourceLite(Fcb->Header.PagingIoResource);
    ExAcquireResourceSharedLite(&Fcb->PagingWriteLock, TRUE);
    ExReleaseResourceLite(&Fcb->PagingWriteLock);
}

/*
 * Paging and non-cached reads of a stream ngc_read_direct handles do their device transfer without CoreLock
 * (ngc_rdio_begin/end, core/ngcore.c; the steps and invariants are those of the paging write in write.c):
 * under CoreLock the runs are mapped and the node pinned, the transfer runs with DataIoGate held shared, and
 * CoreLock is taken again only to unpin.  So a create, cleanup or query of another file, and other readers,
 * do not wait behind the disk.  Everything else (resident, compressed, unaligned, dirty shim pages, more than
 * NGC_DIO_RUNS runs, journal-held sectors) takes the locked path below, unchanged.
 */
NTSTATUS NgRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;
    PNG_FCB Fcb = FileObject->FsContext;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    LARGE_INTEGER Offset = Stack->Parameters.Read.ByteOffset;
    ULONG Length = Stack->Parameters.Read.Length;
    BOOLEAN Paging = (Irp->Flags & IRP_PAGING_IO) != 0;
    BOOLEAN NonCached = (Irp->Flags & IRP_NOCACHE) != 0;
    LONGLONG FileSize;
    PVOID Buffer;
    PMDL LockedMdl = NULL;
    NTSTATUS Status;
    long Done;

    if (Stack->MinorFunction & IRP_MN_MDL)
        return STATUS_INVALID_DEVICE_REQUEST;
    if (Fcb && Fcb->IsVolume && Length)
    {
        if (Offset.LowPart == FILE_USE_FILE_POINTER_POSITION && Offset.HighPart == -1)
            Offset = FileObject->CurrentByteOffset;
        Status = NgReadVolume(Vcb, Irp, Offset.QuadPart, Length);
        if (NT_SUCCESS(Status) && (FileObject->Flags & FO_SYNCHRONOUS_IO))
            FileObject->CurrentByteOffset.QuadPart = Offset.QuadPart + Irp->IoStatus.Information;
        return Status;
    }
    if (!Fcb || Fcb->IsVolume || Fcb->IsDirectory || !Fcb->HasNode)
        return STATUS_INVALID_DEVICE_REQUEST;
    if (Offset.LowPart == FILE_USE_FILE_POINTER_POSITION && Offset.HighPart == -1)
    {
        if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
            return STATUS_INVALID_PARAMETER;
        Offset = FileObject->CurrentByteOffset;
    }
    if (Offset.QuadPart < 0)
        return STATUS_INVALID_PARAMETER;
    if (Length == 0)
        return STATUS_SUCCESS;

    FileSize = Fcb->Header.FileSize.QuadPart;
    if (Offset.QuadPart >= FileSize)
        return STATUS_END_OF_FILE;
    if (!Paging && !FsRtlCheckLockForReadAccess(&Fcb->FileLock, Irp))
        return STATUS_FILE_LOCK_CONFLICT;
    if (!Paging && Offset.QuadPart + Length > FileSize)
        Length = (ULONG)(FileSize - Offset.QuadPart);
    /* Before any mapping of Mm's MDL: the paging file's pages go straight to its clusters. */
    if (Paging && Fcb->IsPagingFile)
        return NgPagingFileIo(Vcb, Fcb, Irp, FALSE, Offset.QuadPart, Length);

    if (Irp->MdlAddress)
    {
        Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        if (!Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;
    }
    else if (NonCached && !Paging)
    {
        /* Locked before CoreLock is taken: no page fault and no bad address under it. */
        LockedMdl = IoAllocateMdl(Irp->UserBuffer, Length, FALSE, FALSE, NULL);
        if (!LockedMdl)
            return STATUS_INSUFFICIENT_RESOURCES;
        Status = STATUS_SUCCESS;
        _SEH2_TRY
        {
            MmProbeAndLockPages(LockedMdl, Irp->RequestorMode, IoWriteAccess);
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
            MmUnlockPages(LockedMdl);
            IoFreeMdl(LockedMdl);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        Buffer = Irp->UserBuffer;
    }

    if (NonCached && !Paging && Fcb->SectionObjectPointers.DataSectionObject)
    {
        /* Dirty cached bytes of the range reach the disk before a non-cached read. */
        IO_STATUS_BLOCK Iosb;
        ExAcquireResourceSharedLite(Fcb->Header.Resource, TRUE);
        CcFlushCache(&Fcb->SectionObjectPointers, &Offset, Length, &Iosb);
        ExReleaseResourceLite(Fcb->Header.Resource);
    }
    if (NonCached && !Paging)
        NgWaitStreamWrites(Fcb);
    if (Paging || NonCached)
    {
        /* Straight from the clusters or through the shim page cache; bytes past EOF come back zeroed. */
        NG_SHARED_HOLD Hold;
        BOOLEAN Unlocked = FALSE;
        struct ngc_dio Dio;
        NgAcquireCoreShared(Vcb, &Hold);
        Done = NgEnsureNode(Fcb);
        if (!Done && Vcb->CoreDepth == 1 && !Vcb->Dismounted)
            Unlocked = ngc_rdio_begin(Vcb->Core, Fcb->Node, Offset.QuadPart, Length, Buffer, &Dio) == 0;
        if (Unlocked)
        {
            int IoErr;
            NgDataIoBegin(Vcb);
            IoErr = NgRdioTransfer(Vcb, &Dio, Buffer);
            NgDataIoTransferred(Vcb);
            ngc_rdio_end(Vcb->Core, &Dio);
            NgDataIoDone(Vcb);
            Vcb->DioReads++;
            Done = IoErr ? -NGC_EIO : (long)Length;
        }
        else if (!Done)
        {
            Vcb->DioReadFallbacks++;
            Done = ngc_read_direct(Vcb->Core, Fcb->Node, Offset.QuadPart, Length, Buffer);
            if (Done == -NGC_EAGAIN)
                Done = ngc_read(Fcb->Node, Offset.QuadPart, Length, Buffer, 1);
        }
        else if (Fcb->Deleted)
        {
            /* A deleted file's pages can still be faulted in by a mapping: zeros. */
            RtlZeroMemory(Buffer, Length);
            Done = Length;
        }
        if (Paging && Fcb->OpenHandles == 0 && Hold.Nested)
            NgParkNode(Fcb);
        NgReleaseCoreShared(Vcb, &Hold);
        if (LockedMdl)
        {
            MmUnlockPages(LockedMdl);
            IoFreeMdl(LockedMdl);
        }
        if (Done < 0)
        {
            DPRINT1("ntfsng: read of %I64x at %I64d len %lu failed %ld\n", Fcb->MftNo, Offset.QuadPart, Length, Done);
            return NgErrnoToStatus((int)Done);
        }
        Irp->IoStatus.Information = Length;
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* Shared with other readers, but not with a write or a size change; the size is read again under it. */
        ExAcquireResourceSharedLite(Fcb->Header.Resource, TRUE);
        FileSize = Fcb->Header.FileSize.QuadPart;
        if (Offset.QuadPart >= FileSize)
        {
            ExReleaseResourceLite(Fcb->Header.Resource);
            return STATUS_END_OF_FILE;
        }
        if (Offset.QuadPart + Length > FileSize)
            Length = (ULONG)(FileSize - Offset.QuadPart);
        _SEH2_TRY
        {
            if (!FileObject->PrivateCacheMap)
            {
                CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize, FALSE,
                                     &NgGlobal.CacheCallbacks, Fcb);
                CcRosAllowLazyClose(FileObject);
            }
            if (CcCopyRead(FileObject, &Offset, Length, TRUE, Buffer, &Irp->IoStatus))
                Status = Irp->IoStatus.Status;
            else
                Status = STATUS_UNSUCCESSFUL;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
            Irp->IoStatus.Information = 0;
        }
        _SEH2_END;
        ExReleaseResourceLite(Fcb->Header.Resource);
    }

    if (NT_SUCCESS(Status) && !Paging && (FileObject->Flags & FO_SYNCHRONOUS_IO))
        FileObject->CurrentByteOffset.QuadPart = Offset.QuadPart + Irp->IoStatus.Information;
    return Status;
}
