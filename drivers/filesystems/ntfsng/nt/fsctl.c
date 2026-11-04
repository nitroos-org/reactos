/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP_MJ_FILE_SYSTEM_CONTROL: mount, verify, volume FSCTLs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"
#include "../shim/include/ngos.h"
#include <ntstrsafe.h>
#include <reactos/ntfsng_check.h>

#ifndef FSCTL_SHRINK_VOLUME
/* Vista and later; the kernel-mode headers expose them only for NTDDI_VISTA builds. */
#define FSCTL_SHRINK_VOLUME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 108, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
typedef enum _SHRINK_VOLUME_REQUEST_TYPES
{
    ShrinkPrepare = 1,
    ShrinkCommit,
    ShrinkAbort
} SHRINK_VOLUME_REQUEST_TYPES, *PSHRINK_VOLUME_REQUEST_TYPES;
typedef struct _SHRINK_VOLUME_INFORMATION
{
    SHRINK_VOLUME_REQUEST_TYPES ShrinkRequestType;
    ULONGLONG Flags;
    LONGLONG NewNumberOfSectors;
} SHRINK_VOLUME_INFORMATION, *PSHRINK_VOLUME_INFORMATION;
#endif

static NTSTATUS NgDeviceIoctlEx(PDEVICE_OBJECT Device, ULONG Code, PVOID Out, ULONG OutLength, BOOLEAN Override);

static NTSTATUS NgDeviceIoctl(PDEVICE_OBJECT Device, ULONG Code, PVOID Out, ULONG OutLength)
{
    return NgDeviceIoctlEx(Device, Code, Out, OutLength, TRUE);
}

/*
 * Before an open on removable media: the device driver reports a medium change when asked
 * (IOCTL_DISK_CHECK_VERIFY), and the volume is verified then.  The I/O manager does not verify
 * on its own, and the volume's own device I/O overrides verification, so without this a swapped
 * medium would never be noticed.
 */
NTSTATUS NgCheckMedium(PNG_VCB Vcb)
{
    PDEVICE_OBJECT Real = Vcb->Vpb->RealDevice;
    NTSTATUS Status;

    if (!Vcb->Removable)
        return STATUS_SUCCESS;
    if (Vcb->WrongMedia)
        return STATUS_WRONG_VOLUME;
    Status = NgDeviceIoctlEx(Vcb->StorageDevice, IOCTL_DISK_CHECK_VERIFY, NULL, 0, FALSE);
    if (!NT_SUCCESS(Status) && Status != STATUS_VERIFY_REQUIRED)
        return Status;      /* no medium, device error: nothing cached may be used */
    if (NT_SUCCESS(Status) && !(Real->Flags & DO_VERIFY_VOLUME))
    {
        /* Some drivers (floppy) notice a change only when they touch the medium: read one sector. */
        PVOID Sector = ExAllocatePoolWithTag(NonPagedPool, Vcb->SectorSize, TAG_NTFSNG);
        if (!Sector)
            return STATUS_INSUFFICIENT_RESOURCES;
        {
            IO_STATUS_BLOCK Iosb;
            LARGE_INTEGER Offset;
            KEVENT Event;
            PIRP Irp;
            Offset.QuadPart = 0;
            KeInitializeEvent(&Event, NotificationEvent, FALSE);
            Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, Vcb->StorageDevice, Sector, Vcb->SectorSize, &Offset, &Event, &Iosb);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            if (Irp)
            {
                Status = IoCallDriver(Vcb->StorageDevice, Irp);
                if (Status == STATUS_PENDING)
                {
                    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                    Status = Iosb.Status;
                }
            }
            ExFreePoolWithTag(Sector, TAG_NTFSNG);
            if (!NT_SUCCESS(Status) && Status != STATUS_VERIFY_REQUIRED)
                return Status;
        }
    }
    if (Status == STATUS_VERIFY_REQUIRED || (Real->Flags & DO_VERIFY_VOLUME))
    {
        Status = IoVerifyVolume(Real, FALSE);
        if (Vcb->WrongMedia)
            return STATUS_WRONG_VOLUME;
        if (!NT_SUCCESS(Status))
            return Status;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NgDeviceIoctlEx(PDEVICE_OBJECT Device, ULONG Code, PVOID Out, ULONG OutLength, BOOLEAN Override)
{
    IO_STATUS_BLOCK Iosb;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildDeviceIoControlRequest(Code, Device, NULL, 0, Out, OutLength, FALSE, &Event, &Iosb);
    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (Override)
        IoGetNextIrpStackLocation(Irp)->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    Status = IoCallDriver(Device, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }
    return Status;
}

NTSYSAPI NTSTATUS NTAPI ExRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
                                          PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

#define NG_HARDERROR_OVERRIDE_ERRORMODE 0x10000000
#define NG_OPTION_OK 1
#define NG_RESPONSE_RETURN_TO_CALLER 0
#define NG_MB_ICONERROR 0x10

typedef struct _NG_DAMAGE_NOTE
{
    UNICODE_STRING Text, Caption;
    WCHAR Buffer[512];
} NG_DAMAGE_NOTE, *PNG_DAMAGE_NOTE;

/*
 * Tells the user that a volume was mounted read-only because it is damaged: a message box through
 * the hard error port once the session's error port exists (until then ExRaiseHardError returns
 * ResponseReturnToCaller without showing anything), for at most about ten minutes after the mount.
 */
static VOID NTAPI NgDamageNotifyThread(PVOID Context)
{
    PNG_DAMAGE_NOTE Note = Context;
    ULONG_PTR Params[3] = { (ULONG_PTR)&Note->Text, (ULONG_PTR)&Note->Caption, NG_MB_ICONERROR };
    ULONG Response = NG_RESPONSE_RETURN_TO_CALLER, Try;
    LARGE_INTEGER Delay;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Delay.QuadPart = -10 * 1000 * 1000 * 5LL;
    for (Try = 0; Try < 120; Try++)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        Status = ExRaiseHardError(STATUS_SERVICE_NOTIFICATION | NG_HARDERROR_OVERRIDE_ERRORMODE, 3, 3, Params,
                                  NG_OPTION_OK, &Response);
        if (NT_SUCCESS(Status) && Response != NG_RESPONSE_RETURN_TO_CALLER)
            break;
    }
    DPRINT1("ntfsng: damage notice %s (status %lx, response %lu, %lu tries)\n",
            Response != NG_RESPONSE_RETURN_TO_CALLER ? "shown" : "NOT shown", Status, Response, Try + 1);
    ExFreePoolWithTag(Note, TAG_NTFSNG);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Damage, or a disk the volume cannot be written to safely: both keep the volume read-only for good. */
static VOID NgReportDamage(PNG_VCB Vcb, const char *Why, BOOLEAN Damage)
{
    PNG_DAMAGE_NOTE Note;
    HANDLE Thread;
    ULONG i;

    for (i = 0; i < 3; i++)
        DPRINT1("ntfsng: ********** VOLUME %08lx %s: mounted READ-ONLY, nothing will be written to it **********\n",
                Vcb->Vpb->SerialNumber, Damage ? "IS DAMAGED" : "CANNOT BE WRITTEN SAFELY");
    DPRINT1("ntfsng: %s: %s\n", Damage ? "damage" : "read-only", Why ? Why : "?");
    Note = ExAllocatePoolWithTag(PagedPool, sizeof(*Note), TAG_NTFSNG);
    if (!Note)
        return;
    RtlZeroMemory(Note, sizeof(*Note));
    RtlInitUnicodeString(&Note->Caption, Damage ? L"NTFS volume damaged" : L"NTFS volume read-only");
    Note->Text.Buffer = Note->Buffer;
    Note->Text.MaximumLength = sizeof(Note->Buffer) - 2 * sizeof(WCHAR);
    if (Damage)
        RtlStringCbPrintfW(Note->Buffer, Note->Text.MaximumLength,
                           L"The NTFS volume with serial number %04lX-%04lX is damaged (%hs).\n\n"
                           L"It was mounted read-only to protect it: changes made to it in this session, "
                           L"including registry changes on the system volume, are not saved. "
                           L"Check and repair the volume with a disk checker on another system.",
                           Vcb->Vpb->SerialNumber >> 16, Vcb->Vpb->SerialNumber & 0xffff, Why ? Why : "unknown");
    else
        RtlStringCbPrintfW(Note->Buffer, Note->Text.MaximumLength,
                           L"The NTFS volume with serial number %04lX-%04lX was mounted read-only (%hs).\n\n"
                           L"Changes made to it in this session, including registry changes on the system "
                           L"volume, are not saved.",
                           Vcb->Vpb->SerialNumber >> 16, Vcb->Vpb->SerialNumber & 0xffff, Why ? Why : "unknown");
    Note->Text.Length = (USHORT)(wcslen(Note->Buffer) * sizeof(WCHAR));
    if (NT_SUCCESS(PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, NgDamageNotifyThread, Note)))
        ZwClose(Thread);
    else
        ExFreePoolWithTag(Note, TAG_NTFSNG);
}

/*
 * The journal orders its writes with cache flushes.  A stack that refuses them is acceptable only on a
 * disk that reports no volatile write cache; otherwise the volume is mounted read-only.
 */
static BOOLEAN NgFlushUsable(PDEVICE_OBJECT Target)
{
    DISK_CACHE_INFORMATION Cache;
    IO_STATUS_BLOCK Iosb;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS, Target, NULL, 0, NULL, &Event, &Iosb);
    if (!Irp)
        return FALSE;
    IoGetNextIrpStackLocation(Irp)->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    Status = IoCallDriver(Target, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }
    if (NT_SUCCESS(Status))
        return TRUE;
    if (Status != STATUS_INVALID_DEVICE_REQUEST && Status != STATUS_NOT_SUPPORTED && Status != STATUS_NOT_IMPLEMENTED)
        return FALSE;
    if (!NT_SUCCESS(NgDeviceIoctl(Target, IOCTL_DISK_GET_CACHE_INFORMATION, &Cache, sizeof(Cache))) ||
        Cache.WriteCacheEnabled)
        return FALSE;
    NgSetFlushOptional(Target);
    return TRUE;
}

static NTSTATUS NgMountVolume(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT Target = Stack->Parameters.MountVolume.DeviceObject;
    PVPB Vpb = Stack->Parameters.MountVolume.Vpb;
    DISK_GEOMETRY Geometry;
    PARTITION_INFORMATION PartInfo;
    PDEVICE_OBJECT Vdo = NULL;
    PNG_VCB Vcb;
    PUCHAR Boot;
    ULONG SectorSize = 512, i;
    ULONGLONG Size = 0, BootSectors;
    NTSTATUS Status;
    const char *WhyRo = NULL;
    BOOLEAN Removable, NoFlush;
    int Err;

    if (DeviceObject != NgGlobal.ControlDevice)
        return STATUS_INVALID_DEVICE_REQUEST;

    if (NT_SUCCESS(NgDeviceIoctl(Target, IOCTL_DISK_GET_DRIVE_GEOMETRY, &Geometry, sizeof(Geometry))) &&
        Geometry.BytesPerSector >= 512 && Geometry.BytesPerSector <= 4096)
    {
        SectorSize = Geometry.BytesPerSector;
    }
    if (NT_SUCCESS(NgDeviceIoctl(Target, IOCTL_DISK_GET_PARTITION_INFO, &PartInfo, sizeof(PartInfo))))
        Size = PartInfo.PartitionLength.QuadPart;

    Boot = ExAllocatePoolWithTag(NonPagedPool, 4096, TAG_NTFSNG);
    if (!Boot)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (ngos_dev_read(Target, 0, Boot, SectorSize) ||
        RtlCompareMemory(Boot + 3, "NTFS    ", 8) != 8 ||
        Boot[510] != 0x55 || Boot[511] != 0xAA)
    {
        ExFreePoolWithTag(Boot, TAG_NTFSNG);
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    if (!Size)
    {
        /* No partition information (superfloppy): trust the boot sector, plus its backup copy. */
        Size = (*(ULONGLONG UNALIGNED *)(Boot + 0x28) + 1) * *(USHORT UNALIGNED *)(Boot + 0x0b);
    }
    BootSectors = *(ULONGLONG UNALIGNED *)(Boot + 0x28);
    ExFreePoolWithTag(Boot, TAG_NTFSNG);
    /*
     * Device I/O carries SL_OVERRIDE_VERIFY_VOLUME (the core cannot stop half way through an
     * operation to verify), so after a media change it would reach the new medium.  Removable
     * media are therefore mounted read-only: nothing of this volume can be written over another.
     */
    Removable = (Target->Characteristics & FILE_REMOVABLE_MEDIA) ||
                (Vpb->RealDevice && (Vpb->RealDevice->Characteristics & FILE_REMOVABLE_MEDIA));

    /* The page index is 32 bits, so a byte offset at or above 16 TiB (2^32 pages of 4 KiB) wraps.
     * Refuse such a volume rather than alias its block-device and file I/O onto low offsets. */
    if (Size >= NGC_MAX_DEVICE_BYTES)
    {
        DPRINT1("ntfsng: volume of %I64u bytes is 16 TiB or larger, not mounting (32-bit page index)\n", Size);
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    Status = IoCreateDevice(NgGlobal.DriverObject, sizeof(NG_VCB), NULL, FILE_DEVICE_DISK_FILE_SYSTEM,
                            0, FALSE, &Vdo);
    if (!NT_SUCCESS(Status))
        return Status;
    Vcb = Vdo->DeviceExtension;
    RtlZeroMemory(Vcb, sizeof(*Vcb));
    Vcb->NodeType = NG_NODE_VCB;
    Vcb->VolumeDevice = Vdo;
    Vcb->StorageDevice = Target;
    Vcb->Vpb = Vpb;
    Vcb->SectorSize = SectorSize;
    Vcb->Removable = Removable;
    Vcb->BootSectors = BootSectors;
    ExInitializeResourceLite(&Vcb->CoreLock);
    ExInitializeResourceLite(&Vcb->CreateGate);
    ExInitializeResourceLite(&Vcb->NotifyPathLock);
    NgInitDataIo(Vcb);
    ExInitializeFastMutex(&Vcb->FcbListLock);
    InitializeListHead(&Vcb->FcbList);
    InitializeListHead(&Vcb->IdleList);
    for (ULONG b = 0; b < NG_FCB_HASH; b++)
        InitializeListHead(&Vcb->FcbHash[b]);
    InitializeListHead(&Vcb->DirNotifyList);
    FsRtlNotifyInitializeSync(&Vcb->NotifySync);
    FsRtlInitializeTunnelCache(&Vcb->Tunnel);
    Vdo->StackSize = Target->StackSize + 1;
    Vdo->AlignmentRequirement = Target->AlignmentRequirement;
    Vdo->SectorSize = (USHORT)SectorSize;

    NgAcquireCore(Vcb);
    NoFlush = !NgGlobal.ForceReadOnly && !Removable && !NgFlushUsable(Target);
    Err = ngc_mount(Target, Size, SectorSize, !NgGlobal.ForceReadOnly && !Removable && !NoFlush, &Vcb->Core, &WhyRo);
    if (!Err && Removable && !NgGlobal.ForceReadOnly)
        WhyRo = "removable media";
    if (!Err && NoFlush)
        WhyRo = "the storage stack cannot flush the disk's write cache";
    if (!Err)
    {
        ngc_volinfo(Vcb->Core, &Vcb->Info);
        Vcb->ClusterSize = Vcb->Info.cluster_size;   /* immutable for a mounted volume */
        Vcb->MajorVersion = Vcb->Info.major;
        Vcb->Serial = Vcb->Info.serial;
        ngc_set_dio_drain(Vcb->Core, NgDrainDataIoCallback, Vcb);
        ngc_set_commit_kick(Vcb->Core, NgCommitKickCallback, Vcb);
        if (!Vcb->Info.read_only)
        {
            /* Files a POSIX delete moved to $Extend\$Deleted and a crash (or another system) left there go before
             * anything is opened, as on Windows (info.c, NgPosixUnlink). */
            unsigned int Purged = 0;
            ngc_node *DelDir;
            int PErr = ngc_purge_deleted(Vcb->Core, &Purged);
            if (PErr)
                DPRINT1("ntfsng: removing what is left in $Extend\\$Deleted failed %d (%u removed)\n", PErr, Purged);
            else if (Purged)
                DPRINT1("ntfsng: %u files left in $Extend\\$Deleted removed\n", Purged);
            if (Purged && ngc_commit_now(Vcb->Core))
                DPRINT1("ntfsng: commit after the $Deleted cleanup failed\n");
            if (!ngc_deleted_dir(Vcb->Core, 0, &DelDir))
            {
                struct ngc_stat DSt;
                ngc_stat(DelDir, &DSt);
                Vcb->DeletedMftNo = DSt.mft_ref & 0xffffffffffffULL;
                ngc_put(DelDir);
            }
        }
    }
    NgReleaseCore(Vcb);
    if (Err)
    {
        DPRINT1("ntfsng: fs/ntfs refused the volume (%d), leaving it to other file systems\n", Err);
        FsRtlNotifyUninitializeSync(&Vcb->NotifySync);
        FsRtlDeleteTunnelCache(&Vcb->Tunnel);
        ExDeleteResourceLite(&Vcb->CoreLock);
        ExDeleteResourceLite(&Vcb->CreateGate);
        ExDeleteResourceLite(&Vcb->NotifyPathLock);
        ExDeleteResourceLite(&Vcb->DataIoGate);
        ExDeleteNPagedLookasideList(&Vcb->DioBounce);
        IoDeleteDevice(Vdo);
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    Vpb->DeviceObject = Vdo;
    Vpb->SerialNumber = (ULONG)Vcb->Info.serial;
    Vpb->VolumeLabelLength = (USHORT)(min(Vcb->Info.label_len, MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)) * sizeof(WCHAR));
    for (i = 0; i < Vpb->VolumeLabelLength / sizeof(WCHAR); i++)
        Vpb->VolumeLabel[i] = Vcb->Info.label[i];
    Vcb->LabelStale = !Vcb->Info.label_valid;
    Vcb->ReadOnly = Vcb->Info.read_only ? TRUE : FALSE;
    /*
     * Read-only for good on a disk that cannot flush, or whose sectors the journal cannot use: the
     * system volume boots read-only there, as a damaged one does.
     */
    Vcb->Damaged = Vcb->Info.damaged || NoFlush || (SectorSize != 512 && !Removable && !NgGlobal.ForceReadOnly) ? TRUE : FALSE;
    /*
     * The boot volume that the policy kept read-only although the mount asked for read-write (a dirty
     * volume whose $LogFile is in use, flags only a checker clears): the registry needs write opens on
     * it before anything can show the user why, and a bugcheck there (0xC0000218 from the SYSTEM hive,
     * 0xC000021A from smss) leaves no recoverable state.  It boots read-only like a damaged one, with a notice.
     */
    if (Vcb->ReadOnly && !Vcb->Damaged && WhyRo && !Removable && !NgGlobal.ForceReadOnly &&
        Vpb->RealDevice && (Vpb->RealDevice->Flags & DO_SYSTEM_BOOT_PARTITION))
        Vcb->Damaged = TRUE;
    if (!Vcb->ReadOnly && !NT_SUCCESS(NgStartFlusher(Vcb)))
    {
        DPRINT1("ntfsng: no flusher thread, mounting read-only\n");
        Vcb->ReadOnly = TRUE;
    }
    ExAcquireFastMutex(&NgGlobal.VcbListLock);
    InsertTailList(&NgGlobal.VcbList, &Vcb->GlobalLinks);
    ExReleaseFastMutex(&NgGlobal.VcbListLock);
    Vdo->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT1("ntfsng: mounted NTFS %u.%u size %I64u, sector %lu, cluster %u, %I64u clusters (%I64u free), serial %08lx, %s%s%s\n",
            Vcb->Info.major, Vcb->Info.minor, Size, SectorSize, Vcb->Info.cluster_size,
            Vcb->Info.total_clusters, Vcb->Info.free_clusters, Vpb->SerialNumber,
            Vcb->ReadOnly ? "READ-ONLY" : "read-write", WhyRo ? ": " : "", WhyRo ? WhyRo : "");
    if (Vcb->Damaged)
        NgReportDamage(Vcb, WhyRo, Vcb->Info.damaged ? TRUE : FALSE);
    return STATUS_SUCCESS;
}

/*
 * Before a volume lock: STATUS_ACCESS_DENIED while a file of the volume is a paging file (Mm keeps its
 * file object, and writes it past the core, after shutdown closed the handle, which also deletes and
 * unlists it: Vcb->PagingFiles counts paging-file FCBs until they are freed) or has a section object
 * that is in use: a data mapping that outlived its file handle, or an image (a running program, a
 * mapped or merely created image section), as on Windows.  An image section nothing uses is
 * discarded first.  Nothing is purged: ReactOS keeps a file's data pages after its last close, and
 * the flush before the lock wrote them.  Users this check cannot see (a mapped file deleted before
 * the lock and so unlisted, a section whose creation was past its file object reference) go through
 * the core until the holder writes the disk directly; from then on their page writes are dropped
 * (NgDropIfDiscardable) and their page reads fail.  A new paging file needs an open, which the lock
 * refuses.
 */
static NTSTATUS NgLockCheckSections(PNG_VCB Vcb, PNG_FCB VolumeFcb)
{
    PNG_FCB *List = NULL;
    ULONG Count = 0, Cap = 0, i;
    PLIST_ENTRY Entry;
    NTSTATUS Status = STATUS_SUCCESS;

    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (Vcb->PagingFiles)
    {
        ExReleaseFastMutex(&Vcb->FcbListLock);
        return STATUS_ACCESS_DENIED;
    }
    for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
        if (F == VolumeFcb)
            continue;
        if (F->OpenHandles || F->IsPagingFile)
        {
            ExReleaseFastMutex(&Vcb->FcbListLock);
            return STATUS_ACCESS_DENIED;
        }
        if (F->SectionObjectPointers.DataSectionObject || F->SectionObjectPointers.ImageSectionObject)
            Cap++;
    }
    List = Cap ? ExAllocatePoolWithTag(NonPagedPool, Cap * sizeof(PNG_FCB), TAG_NTFSNG) : NULL;
    if (Cap && !List)
    {
        ExReleaseFastMutex(&Vcb->FcbListLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList && Count < Cap; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
        if (F != VolumeFcb &&
            (F->SectionObjectPointers.DataSectionObject || F->SectionObjectPointers.ImageSectionObject))
        {
            InterlockedIncrement(&F->RefCount);
            List[Count++] = F;
        }
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);

    for (i = 0; i < Count; i++)
    {
        PNG_FCB F = List[i];
        if (NT_SUCCESS(Status))
        {
            ExAcquireResourceExclusiveLite(F->Header.Resource, TRUE);
            if (F->SectionObjectPointers.ImageSectionObject)
                MmFlushImageSection(&F->SectionObjectPointers, MmFlushForWrite);
            if (!MmCanFileBeTruncated(&F->SectionObjectPointers, NULL))
            {
                Status = STATUS_ACCESS_DENIED;
                DPRINT1("ntfsng: volume lock refused: file %I64x is mapped\n", F->MftNo);
            }
            ExReleaseResourceLite(F->Header.Resource);
        }
        NgDereferenceFcb(F);
    }
    if (List)
        ExFreePoolWithTag(List, TAG_NTFSNG);
    return Status;
}

/*
 * FSCTL_LOCK_VOLUME through a volume handle: after a flush, granted only while that handle is the
 * only open one on the volume and no file has a section object or is a paging file
 * (NgLockCheckSections); then every other open is refused until FSCTL_UNLOCK_VOLUME or the holder's
 * cleanup.
 */
static NTSTATUS NgLockVolume(PNG_VCB Vcb, PFILE_OBJECT FileObject)
{
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    PLIST_ENTRY Entry;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Fcb || !Fcb->IsVolume)
        return STATUS_INVALID_PARAMETER;
    /* No create runs while the lock is decided, the volume flushed for it, or a dismount runs:
     * a running create finishes first (see NgCreate). */
    ExAcquireResourceExclusiveLite(&Vcb->CreateGate, TRUE);
    if (Vcb->Dismounted || Vcb->LockedBy || !FileObject->FsContext2)
    {
        Status = Vcb->Dismounted ? STATUS_VOLUME_DISMOUNTED : STATUS_ACCESS_DENIED;
        ExReleaseResourceLite(&Vcb->CreateGate);
        return Status;
    }
    if (NgFlushVolume(Vcb))
    {
        ExReleaseResourceLite(&Vcb->CreateGate);
        return STATUS_UNEXPECTED_IO_ERROR;
    }
    Status = NgLockCheckSections(Vcb, Fcb);
    if (!NT_SUCCESS(Status))
    {
        ExReleaseResourceLite(&Vcb->CreateGate);
        return Status;
    }
    NgAcquireCore(Vcb);
    ExAcquireFastMutex(&Vcb->FcbListLock);
    /* Checked again after the flush, in the hold that publishes the lock: also refused for a handle
     * whose cleanup ran meanwhile (nothing would ever unlock it). */
    if (Vcb->Dismounted || Vcb->LockedBy || ((PNG_CCB)FileObject->FsContext2)->CleanedUp || Vcb->PagingFiles)
        Status = STATUS_ACCESS_DENIED;
    for (Entry = Vcb->FcbList.Flink; NT_SUCCESS(Status) && Entry != &Vcb->FcbList; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
        if (F != Fcb && (F->OpenHandles || F->IsPagingFile))
        {
            Status = STATUS_ACCESS_DENIED;
            break;
        }
    }
    if (NT_SUCCESS(Status) && Fcb->OpenHandles != 1)
        Status = STATUS_ACCESS_DENIED;
    if (NT_SUCCESS(Status))
    {
        /* Owner and VPB flag in one hold: an unlock or cleanup in between cannot leave either behind. */
        KIRQL Irql;
        Vcb->LockEnding = FALSE;
        Vcb->LockedBy = FileObject;
        IoAcquireVpbSpinLock(&Irql);
        Vcb->Vpb->Flags |= VPB_LOCKED;
        IoReleaseVpbSpinLock(Irql);
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    NgReleaseCore(Vcb);
    ExReleaseResourceLite(&Vcb->CreateGate);
    return Status;
}

/*
 * Unlocks the volume if FileObject holds the lock (a later holder's lock is not dropped), for NgEndLock,
 * which holds the create gate exclusive.  The lock is published and removed under CoreLock and
 * FcbListLock, so a direct write's check under CoreLock (NgWriteDevice) sees LockedBy and LockEnding
 * together.  FALSE if FileObject did not hold the lock.
 */
static BOOLEAN NgUnlockVolume(PNG_VCB Vcb, PFILE_OBJECT FileObject)
{
    BOOLEAN Held;
    ASSERT(ExIsResourceAcquiredExclusiveLite(&Vcb->CreateGate));
    NgAcquireCore(Vcb);
    ExAcquireFastMutex(&Vcb->FcbListLock);
    Held = Vcb->LockedBy == FileObject;
    if (Held)
    {
        KIRQL Irql;
        Vcb->LockedBy = NULL;
        Vcb->LockEnding = FALSE;
        IoAcquireVpbSpinLock(&Irql);
        Vcb->Vpb->Flags &= ~VPB_LOCKED;
        IoReleaseVpbSpinLock(Irql);
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    NgReleaseCore(Vcb);
    return Held;
}

/* The I/O manager frees a VPB that lost its last reference with this tag (TAG_VPB). */
#define NG_TAG_VPB ' BPV'

/*
 * Dismounts the volume, with the create gate held exclusive.  The volume is flushed unless the lock
 * holder already wrote the disk directly, the core is unmounted, and the storage device gets a new
 * VPB, so the next open mounts the volume again; the file objects of this mount keep the old one and
 * every request on them fails with STATUS_VOLUME_DISMOUNTED (the lock holder's direct reads and
 * writes aside, NgDismountedRequest).  Not for a volume with a paging file.  For a removal of the
 * storage device (Removal) a flush that fails does not keep the volume mounted: what did not reach
 * the disk is dropped, as the device goes away whatever this mount does.
 */
static NTSTATUS NgDismountMount(PNG_VCB Vcb, BOOLEAN Removal, PBOOLEAN Dropped)
{
    PNG_FCB *List = NULL;
    ULONG Count = 0, Capacity, i;
    PLIST_ENTRY Entry;
    BOOLEAN Discard;
    PVPB NewVpb;
    KIRQL Irql;

    NewVpb = ExAllocatePoolWithTag(NonPagedPool, sizeof(VPB), NG_TAG_VPB);
    if (!NewVpb)
        return STATUS_INSUFFICIENT_RESOURCES;
    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (Vcb->PagingFiles)
    {
        ExReleaseFastMutex(&Vcb->FcbListLock);
        ExFreePoolWithTag(NewVpb, NG_TAG_VPB);
        return STATUS_ACCESS_DENIED;
    }
    for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
        if (F->IsPagingFile)
        {
            ExReleaseFastMutex(&Vcb->FcbListLock);
            ExFreePoolWithTag(NewVpb, NG_TAG_VPB);
            return STATUS_ACCESS_DENIED;
        }
        Count++;
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);

    /* A volume that cannot be flushed (a write or cache flush fails, or no memory to list its streams)
     * stays mounted (and locked), as NgLockVolume does; a removal goes on without what was not written. */
    Discard = Vcb->RawWritten;
    if (!Discard && !Vcb->ReadOnly && NgFlushVolume(Vcb))
    {
        if (!Removal)
        {
            ExFreePoolWithTag(NewVpb, NG_TAG_VPB);
            return STATUS_UNEXPECTED_IO_ERROR;
        }
        DPRINT1("ntfsng: volume %08lx: the flush before the removal failed: uncommitted changes are dropped\n",
                Vcb->Vpb->SerialNumber);
        Discard = TRUE;
        *Dropped = TRUE;
    }

    /* Cached files lose their views; later paging I/O on them fails.  Every FCB is taken (the array is
     * sized again if the list grew, which the create gate now prevents). */
    for (Capacity = Count + 16;; Capacity = Count + 16)
    {
        List = ExAllocatePoolWithTag(PagedPool, Capacity * sizeof(PNG_FCB), TAG_NTFSNG);
        if (!List)
        {
            /* Without the snapshot the teardown would leave core inodes behind: the volume stays mounted. */
            ExFreePoolWithTag(NewVpb, NG_TAG_VPB);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Count = 0;
        ExAcquireFastMutex(&Vcb->FcbListLock);
        for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList; Entry = Entry->Flink)
            Count++;
        if (Count <= Capacity)
            break;
        ExReleaseFastMutex(&Vcb->FcbListLock);
        ExFreePoolWithTag(List, TAG_NTFSNG);
        List = NULL;
    }
    Count = 0;
    for (Entry = Vcb->FcbList.Flink; Entry != &Vcb->FcbList; Entry = Entry->Flink)
    {
        PNG_FCB F = CONTAINING_RECORD(Entry, NG_FCB, VcbLinks);
        F->Header.IsFastIoPossible = FastIoIsNotPossible;
        InterlockedIncrement(&F->RefCount);
        List[Count++] = F;
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    for (i = 0; i < Count; i++)
    {
        if (List[i]->SectionObjectPointers.DataSectionObject || List[i]->SectionObjectPointers.SharedCacheMap)
            CcPurgeCacheSection(&List[i]->SectionObjectPointers, NULL, 0, FALSE);
        if (List[i]->SectionObjectPointers.ImageSectionObject)
            MmFlushImageSection(&List[i]->SectionObjectPointers, MmFlushForDelete);
    }
    Vcb->Dismounted = TRUE;

    ExAcquireFastMutex(&NgGlobal.VcbListLock);
    RemoveEntryList(&Vcb->GlobalLinks);
    ExReleaseFastMutex(&NgGlobal.VcbListLock);
    if (Vcb->Flusher)
    {
        KeSetEvent(&Vcb->FlusherStop, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(Vcb->Flusher, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(Vcb->Flusher);
        Vcb->Flusher = NULL;
    }

    /* Paging writes in their unlocked transfer pin core nodes: they end before the core goes (CoreLock held on return). */
    NgWaitDataIoIdle(Vcb);
    for (i = 0; i < Count; i++)
    {
        List[i]->Deleted = TRUE;
        if (List[i]->Node)
        {
            ngc_put(List[i]->Node);
            List[i]->Node = NULL;
        }
    }
    /*
     * Past the purge there is no way back.  After a final sync that fails the teardown writes nothing
     * more (a discard): what is on the medium then decides whether the next mount replays the journal
     * or finds the volume in need of repair.
     */
    if (!Discard && !Vcb->ReadOnly && ngc_sync(Vcb->Core))
    {
        DPRINT1("ntfsng: volume %08lx: the last sync before the dismount failed: nothing more is written, uncommitted changes are dropped\n",
                Vcb->Vpb->SerialNumber);
        Discard = TRUE;
        if (Dropped)
            *Dropped = TRUE;
    }
    ngc_umount(Vcb->Core, Discard);
    Vcb->Core = NULL;
    NgReleaseCore(Vcb);
    for (i = 0; i < Count; i++)
        NgDereferenceFcb(List[i]);
    if (List)
        ExFreePoolWithTag(List, TAG_NTFSNG);

    RtlZeroMemory(NewVpb, sizeof(VPB));
    NewVpb->Type = IO_TYPE_VPB;
    NewVpb->Size = sizeof(VPB);
    IoAcquireVpbSpinLock(&Irql);
    NewVpb->RealDevice = Vcb->Vpb->RealDevice;
    NewVpb->Flags = Vcb->Vpb->Flags & VPB_REMOVE_PENDING;
    if (Vcb->Vpb->RealDevice->Vpb == Vcb->Vpb)
    {
        Vcb->Vpb->RealDevice->Vpb = NewVpb;
        NewVpb = NULL;
    }
    IoReleaseVpbSpinLock(Irql);
    if (NewVpb)
        ExFreePoolWithTag(NewVpb, NG_TAG_VPB);
    DPRINT1("ntfsng: volume %08lx dismounted%s\n", Vcb->Vpb->SerialNumber,
            (Dropped && *Dropped) ? " (its storage device is removed; changes not written back are lost)" :
            Removal ? " (its storage device is removed)" :
            Vcb->RawWritten ? " (written directly by the lock holder: mounted state dropped)" : "");
    return STATUS_SUCCESS;
}

/*
 * FSCTL_DISMOUNT_VOLUME through the handle that holds the volume lock (a busy volume is not
 * dismounted by force), or the end of a lock after a direct write (NgEndLock).  That handle still
 * reads and writes the disk directly until it unlocks (or dismounted at the end of the lock, not at
 * all).
 */
static NTSTATUS NgDismountVolumeGated(PNG_VCB Vcb, PFILE_OBJECT FileObject)
{
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    PNG_CCB Ccb = FileObject ? FileObject->FsContext2 : NULL;

    if (!Fcb || !Fcb->IsVolume || !Ccb)
        return STATUS_INVALID_PARAMETER;
    if (Vcb->LockedBy != FileObject)
        return STATUS_ACCESS_DENIED;
    return NgDismountMount(Vcb, FALSE, NULL);
}

/*
 * The mount is cut off from its storage device, which is gone or no longer holds this volume (a
 * surprise removal, or a removal that was not asked for first): nothing more reaches the device
 * (ngc_medium_gone), every request but a cleanup or close fails from now on (WrongMedia, as for a
 * replaced medium; cleanups only release the handle's state), and the device gets a new VPB, so
 * that a device that takes its place mounts afresh.  The core stays allocated: requests already
 * past dispatch, which do not take the create gate, keep a valid core and fail in it.  TRUE when
 * the core held changes that never reached the disk.
 */
static BOOLEAN NgFenceRemoved(PNG_VCB Vcb)
{
    PVPB NewVpb = ExAllocatePoolWithTag(NonPagedPool, sizeof(VPB), NG_TAG_VPB);
    BOOLEAN Lost = FALSE;
    KIRQL Irql;

    NgAcquireCore(Vcb);
    Vcb->WrongMedia = TRUE;
    Vcb->ReadOnly = TRUE;
    if (Vcb->Core)
    {
        Lost = ngc_dirty(Vcb->Core) != 0;
        ngc_medium_gone(Vcb->Core);
    }
    NgReleaseCore(Vcb);

    if (NewVpb)
    {
        RtlZeroMemory(NewVpb, sizeof(VPB));
        NewVpb->Type = IO_TYPE_VPB;
        NewVpb->Size = sizeof(VPB);
        IoAcquireVpbSpinLock(&Irql);
        NewVpb->RealDevice = Vcb->Vpb->RealDevice;
        NewVpb->Flags = Vcb->Vpb->Flags & VPB_REMOVE_PENDING;
        if (Vcb->Vpb->RealDevice->Vpb == Vcb->Vpb)
        {
            Vcb->Vpb->RealDevice->Vpb = NewVpb;
            NewVpb = NULL;
        }
        IoReleaseVpbSpinLock(Irql);
        if (NewVpb)
            ExFreePoolWithTag(NewVpb, NG_TAG_VPB);
    }
    else
    {
        DPRINT1("ntfsng: volume %08lx: no memory for a new VPB: the removed device stays mounted (every request fails)\n",
                Vcb->Vpb->SerialNumber);
    }
    return Lost;
}

/*
 * IRP_MN_SURPRISE_REMOVAL (Surprise) or IRP_MN_REMOVE_DEVICE of the storage device under the
 * volume; neither can be refused.  After a granted IRP_MN_QUERY_REMOVE_DEVICE (no handle, no mapped
 * file, nothing cached left, no new open since) the device is still there and the volume is
 * dismounted in full, its last changes written.  Otherwise the device may already be gone or hold
 * something else (a partition table change makes the old partition device go while the new one at
 * the same place is another device), so nothing is written: the mount is fenced (NgFenceRemoved).
 * STATUS_LOST_WRITEBEHIND_DATA when changes did not reach the disk.
 */
NTSTATUS NgDismountForRemoval(PNG_VCB Vcb, BOOLEAN Surprise)
{
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN Orderly, Dropped = FALSE;

    ExAcquireResourceExclusiveLite(&Vcb->CreateGate, TRUE);
    Orderly = !Surprise && Vcb->RemovePending;
    Vcb->RemovePending = FALSE;
    if (!Vcb->Dismounted && !Vcb->WrongMedia)
    {
        if (Orderly)
        {
            Status = NgDismountMount(Vcb, TRUE, &Dropped);
            if (!NT_SUCCESS(Status))
                Dropped = NgFenceRemoved(Vcb);
        }
        else
        {
            Dropped = NgFenceRemoved(Vcb);
        }
        Status = Dropped ? STATUS_LOST_WRITEBEHIND_DATA : STATUS_SUCCESS;
    }
    ExReleaseResourceLite(&Vcb->CreateGate);
    DPRINT1("ntfsng: volume %08lx: its device is removed (%s)%s\n", Vcb->Vpb->SerialNumber,
            Orderly ? "orderly" : "not asked first: nothing written",
            Status == STATUS_LOST_WRITEBEHIND_DATA ? ": changes not written back are lost" : "");
    return Status;
}

/*
 * IRP_MN_QUERY_REMOVE_DEVICE: an orderly removal of the storage device is refused, as Windows file
 * systems refuse it, while the volume is in use (an open handle on a file or on the volume, a
 * mapped file, a paging file, the volume lock) or when what is cached cannot be written back; once granted, no new open is accepted
 * until the removal or IRP_MN_CANCEL_REMOVE_DEVICE, so the removal finds nothing new to write.
 */
NTSTATUS NgQueryRemove(PNG_VCB Vcb)
{
    NTSTATUS Status = STATUS_SUCCESS;

    ExAcquireResourceExclusiveLite(&Vcb->CreateGate, TRUE);
    if (!Vcb->Dismounted)
    {
        if (!Vcb->RawWritten && !Vcb->ReadOnly && NgFlushVolume(Vcb))
            Status = STATUS_UNEXPECTED_IO_ERROR;
        else if (Vcb->LockedBy)
            Status = STATUS_ACCESS_DENIED;
        else
        {
            BOOLEAN VolumeOpen;

            /* The volume FCB is not on FcbList: its handles (\\.\X:) are counted here, as FastFAT counts them. */
            ExAcquireFastMutex(&Vcb->FcbListLock);
            VolumeOpen = Vcb->VolumeFcb && Vcb->VolumeFcb->OpenHandles;
            ExReleaseFastMutex(&Vcb->FcbListLock);
            Status = VolumeOpen ? STATUS_ACCESS_DENIED : NgLockCheckSections(Vcb, NULL);
        }
        Vcb->RemovePending = NT_SUCCESS(Status);
    }
    ExReleaseResourceLite(&Vcb->CreateGate);
    if (!NT_SUCCESS(Status))
        DPRINT1("ntfsng: volume %08lx: removal of its device refused: 0x%08lx\n", Vcb->Vpb->SerialNumber, Status);
    return Status;
}

VOID NgCancelRemove(PNG_VCB Vcb)
{
    ExAcquireResourceExclusiveLite(&Vcb->CreateGate, TRUE);
    Vcb->RemovePending = FALSE;
    ExReleaseResourceLite(&Vcb->CreateGate);
}

/*
 * The dismount runs with the create gate held exclusive: no create, cleanup or shutdown flush is
 * inside the core it frees.  The dismount notification goes out before the gate is taken
 * (its callbacks may open files on the volume from another thread).
 */
static NTSTATUS NgDismountVolume(PNG_VCB Vcb, PFILE_OBJECT FileObject)
{
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    PNG_CCB Ccb = FileObject ? FileObject->FsContext2 : NULL;
    NTSTATUS Status;
    if (!Fcb || !Fcb->IsVolume || !Ccb)
        return STATUS_INVALID_PARAMETER;
    if (!Ccb->ManageVolume)
        return STATUS_ACCESS_DENIED;
    if (Vcb->LockedBy != FileObject)
        return STATUS_ACCESS_DENIED;
    FsRtlNotifyVolumeEvent(FileObject, FSRTL_VOLUME_DISMOUNT);
    ExAcquireResourceExclusiveLite(&Vcb->CreateGate, TRUE);
    Status = Vcb->Dismounted ? STATUS_VOLUME_DISMOUNTED : NgDismountVolumeGated(Vcb, FileObject);
    ExReleaseResourceLite(&Vcb->CreateGate);
    if (!NT_SUCCESS(Status) && Status != STATUS_VOLUME_DISMOUNTED)
        FsRtlNotifyVolumeEvent(FileObject, FSRTL_VOLUME_DISMOUNT_FAILED);
    return Status;
}

/*
 * The end of the volume lock: FSCTL_UNLOCK_VOLUME, or the cleanup of the holder's handle.  If the
 * holder wrote the disk directly, the mount describes nothing on the disk and has done no device I/O
 * since (NgWriteDevice), so the volume is dismounted, its state dropped, before the lock goes, and the
 * next open mounts what the holder left; Windows also dismounts a volume under the handle that locked
 * and unlocked it.  The handle of a dismounted volume then fails every request with
 * STATUS_VOLUME_DISMOUNTED, as on Windows (NgDismountedRequest).  LockEnding, set under CoreLock with
 * the read of RawWritten, refuses a direct write of the holder that has not reached its first device
 * write yet (NgWriteDevice), so no hand-over follows this decision; the holder's requests already
 * past that point finish before the lock goes (the create gate, taken exclusive).  With Cleanup the
 * handle is also marked cleaned up, so a lock request still running on it is refused.  A dismount
 * that fails (no memory) leaves the volume mounted without device I/O until a later lock dismounts
 * it.  FALSE if FileObject did not hold the lock, or another end of it runs.
 */
BOOLEAN NgEndLock(PNG_VCB Vcb, PFILE_OBJECT FileObject, BOOLEAN Cleanup)
{
    PNG_CCB Ccb = FileObject->FsContext2;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN Own, Raw = FALSE, Held;

    /* One end per lock: a second unlock or the cleanup racing with this one does nothing. */
    NgAcquireCore(Vcb);
    ExAcquireFastMutex(&Vcb->FcbListLock);
    if (Cleanup && Ccb)
        Ccb->CleanedUp = TRUE;
    Own = Vcb->LockedBy == FileObject && !Vcb->LockEnding;
    if (Own)
    {
        Vcb->LockEnding = TRUE;
        Raw = Vcb->RawWritten && !Vcb->Dismounted;
    }
    ExReleaseFastMutex(&Vcb->FcbListLock);
    NgReleaseCore(Vcb);
    if (!Own)
        return FALSE;
    if (Raw)
        FsRtlNotifyVolumeEvent(FileObject, FSRTL_VOLUME_DISMOUNT);
    /* Exclusive: the holder's reads and writes still running (they hold the gate shared) finish first,
     * all of their chunks included, dismounted or not. */
    ExAcquireResourceExclusiveLite(&Vcb->CreateGate, TRUE);
    if (Raw && !Vcb->Dismounted)
        Status = NgDismountVolumeGated(Vcb, FileObject);
    Held = NgUnlockVolume(Vcb, FileObject);
    ExReleaseResourceLite(&Vcb->CreateGate);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ntfsng: volume %08lx: the dismount at the end of the lock failed 0x%08lx: no I/O until a later dismount\n",
                Vcb->Vpb->SerialNumber, Status);
        FsRtlNotifyVolumeEvent(FileObject, FSRTL_VOLUME_DISMOUNT_FAILED);
    }
    return Held;
}

/* FSCTL_GET/SET/DELETE_REPARSE_POINT on a file or directory (not a stream, not the volume). */
static NTSTATUS NgReparseFsctl(PNG_VCB Vcb, PNG_FCB Fcb, PNG_CCB Ccb, PIRP Irp, PIO_STACK_LOCATION Stack, ULONG Code)
{
    PREPARSE_DATA_BUFFER Rp = Irp->AssociatedIrp.SystemBuffer;
    ULONG In = Stack->Parameters.FileSystemControl.InputBufferLength;
    ULONG Out = Stack->Parameters.FileSystemControl.OutputBufferLength;
    ULONG Header;
    NTSTATUS Status = STATUS_SUCCESS;
    void *Data = NULL;
    unsigned int Len = 0;
    int Err;

    if (!Fcb || Fcb->IsVolume || Fcb->Stream.Length || !Fcb->HasNode)
        return STATUS_INVALID_PARAMETER;
    if (Code != FSCTL_GET_REPARSE_POINT && Ccb && !(Ccb->Granted & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES)))
        return STATUS_ACCESS_DENIED;
    /* The root and the $Extend metadata files never become reparse points. */
    if (Code == FSCTL_SET_REPARSE_POINT && (Fcb->IsRoot || !Ccb || Ccb->ParentMftNo == 11))
        return STATUS_ACCESS_DENIED;
    if (Code != FSCTL_GET_REPARSE_POINT && Vcb->ReadOnly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    if (Code != FSCTL_GET_REPARSE_POINT)
    {
        /* The buffer is a REPARSE_DATA_BUFFER, or the GUID form for third-party tags. */
        if (!Rp || In < REPARSE_DATA_BUFFER_HEADER_SIZE || In > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
            return STATUS_IO_REPARSE_DATA_INVALID;
        if (Rp->ReparseTag == IO_REPARSE_TAG_RESERVED_ZERO || Rp->ReparseTag == IO_REPARSE_TAG_RESERVED_ONE)
            return STATUS_IO_REPARSE_TAG_INVALID;
        Header = IsReparseTagMicrosoft(Rp->ReparseTag) ? REPARSE_DATA_BUFFER_HEADER_SIZE : REPARSE_GUID_DATA_BUFFER_HEADER_SIZE;
        if (In < Header || Rp->ReparseDataLength + Header != In)
            return STATUS_IO_REPARSE_DATA_INVALID;
        if (Code == FSCTL_DELETE_REPARSE_POINT && Rp->ReparseDataLength)
            return STATUS_IO_REPARSE_DATA_INVALID;
        /* Tags the core would turn into special files, or read data through (WOF), are refused. */
        if (Code == FSCTL_SET_REPARSE_POINT &&
            (Rp->ReparseTag == 0x80000017 /* WOF */ || Rp->ReparseTag == 0x80000023 /* AF_UNIX */ ||
             Rp->ReparseTag == 0x80000024 || Rp->ReparseTag == 0x80000025 || Rp->ReparseTag == 0x80000026 ||
             Rp->ReparseTag == 0xA000001D /* LX_* */))
            return STATUS_IO_REPARSE_TAG_INVALID;
        if (Code == FSCTL_SET_REPARSE_POINT && Rp->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
        {
            ULONG Path = In - FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer);
            if (In < FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) ||
                (ULONG)Rp->MountPointReparseBuffer.SubstituteNameOffset + Rp->MountPointReparseBuffer.SubstituteNameLength > Path ||
                (ULONG)Rp->MountPointReparseBuffer.PrintNameOffset + Rp->MountPointReparseBuffer.PrintNameLength > Path ||
                ((Rp->MountPointReparseBuffer.SubstituteNameOffset | Rp->MountPointReparseBuffer.SubstituteNameLength |
                  Rp->MountPointReparseBuffer.PrintNameOffset | Rp->MountPointReparseBuffer.PrintNameLength) & 1) ||
                !Rp->MountPointReparseBuffer.SubstituteNameLength)
                return STATUS_IO_REPARSE_DATA_INVALID;
            if (!Fcb->IsDirectory)
                return STATUS_NOT_A_DIRECTORY;
        }
    }

    ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
    NgAcquireCore(Vcb);
    Err = NgEnsureNode(Fcb);
    if (!Err && Code == FSCTL_GET_REPARSE_POINT)
    {
        Err = ngc_get_reparse(Fcb->Node, &Data, &Len);
        if (Err == -NGC_ENODATA)
            Status = STATUS_NOT_A_REPARSE_POINT;
        Err = Status == STATUS_SUCCESS ? Err : 0;
    }
    else if (!Err && !IsReparseTagMicrosoft(Rp->ReparseTag) && !ngc_get_reparse(Fcb->Node, &Data, &Len) &&
             ((PREPARSE_GUID_DATA_BUFFER)Data)->ReparseTag == Rp->ReparseTag &&
             (Len < REPARSE_GUID_DATA_BUFFER_HEADER_SIZE ||
              !IsEqualGUID(&((PREPARSE_GUID_DATA_BUFFER)Data)->ReparseGuid, &((PREPARSE_GUID_DATA_BUFFER)Rp)->ReparseGuid)))
    {
        /* A third-party tag is also identified by its GUID. */
        Status = STATUS_REPARSE_ATTRIBUTE_CONFLICT;
    }
    else if (!Err && Code == FSCTL_SET_REPARSE_POINT)
    {
        /* A directory becomes a reparse point only while it is empty. */
        if (Fcb->IsDirectory && ngc_dir_empty(Vcb->Core, Fcb->Node) != 1)
            Status = STATUS_DIRECTORY_NOT_EMPTY;
        else
            Err = ngc_set_reparse(Vcb->Core, Fcb->Node, Rp, In);
    }
    else if (!Err)
    {
        Err = ngc_delete_reparse(Vcb->Core, Fcb->Node, Rp->ReparseTag);
        if (Err == -NGC_ENODATA)
        {
            Status = STATUS_NOT_A_REPARSE_POINT;
            Err = 0;
        }
    }
    if (Code != FSCTL_GET_REPARSE_POINT && Data)
    {
        ngc_free(Data);
        Data = NULL;
    }
    if (Err == -NGC_EXDEV)
        Status = STATUS_IO_REPARSE_TAG_MISMATCH;
    else if (Err == -NGC_EINVAL || Err == -NGC_EFBIG)
        Status = STATUS_IO_REPARSE_DATA_INVALID;
    else if (Err)
        Status = NgErrnoToStatus(Err);
    if (Code != FSCTL_GET_REPARSE_POINT && Fcb->Node)
    {
        /* Also after a failure: a failed replace may have removed the old reparse point. */
        ngc_stat(Fcb->Node, &Fcb->Stat);
        NgAfterChange(Vcb);
    }
    NgReleaseCore(Vcb);
    ExReleaseResourceLite(Fcb->Header.Resource);

    if (Code == FSCTL_GET_REPARSE_POINT && NT_SUCCESS(Status))
    {
        PVOID Buf = Irp->AssociatedIrp.SystemBuffer;
        if (!Buf || Out < REPARSE_DATA_BUFFER_HEADER_SIZE)
            Status = STATUS_BUFFER_TOO_SMALL;
        else if (Out < Len)
        {
            RtlCopyMemory(Buf, Data, Out);
            Irp->IoStatus.Information = Out;
            Status = STATUS_BUFFER_OVERFLOW;
        }
        else
        {
            RtlCopyMemory(Buf, Data, Len);
            Irp->IoStatus.Information = Len;
        }
    }
    if (Data)
        ngc_free(Data);
    if (Code != FSCTL_GET_REPARSE_POINT && NT_SUCCESS(Status) && Ccb)
        NgNotifyCcb(Vcb, Ccb, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_ACTION_MODIFIED);
    return Status;
}

#if DBG
/* Test only: the "ResizeFault" DWORD of the service key arms a failure inside the next resize. */
static VOID NgArmResizeFault(VOID)
{
    UNICODE_STRING Key = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Ntfs");
    ngc_resize_fault = (int)NgReadDword(&Key, L"ResizeFault");
    if (ngc_resize_fault)
        DPRINT1("ntfsng: ResizeFault %d armed\n", ngc_resize_fault);
}
#endif

/* Errors of the resize requests: a size the volume cannot take is an invalid parameter there. */
static NTSTATUS NgResizeStatus(int Err)
{
    if (Err == -NGC_EINVAL)
        return STATUS_INVALID_PARAMETER;
    return NgErrnoToStatus(Err);
}

/*
 * After a resize (CoreLock held): the volume information again, and a core that a failed resize left
 * read-only (nothing more may be written) makes the whole mount read-only, so that no write, cached
 * or paging, is accepted that could never reach the disk.  A core that stopped writing for good also
 * makes flushes fail (WritesLost): what was written before can no longer reach the disk either.
 */
static VOID NgResizeEnded(PNG_VCB Vcb)
{
    ngc_volinfo(Vcb->Core, &Vcb->Info);
    if (ngc_failed(Vcb->Core))
        Vcb->WritesLost = TRUE;
    if (!ngc_is_rw(Vcb->Core) && !Vcb->ReadOnly)
    {
        DPRINT1("ntfsng: volume %08lx: a resize failed half way, the volume is read-only now\n", Vcb->Vpb->SerialNumber);
        Vcb->ReadOnly = TRUE;
    }
}

/* A volume handle that may change the volume (as FSCTL_LOCK_VOLUME), on a volume the core may write. */
static NTSTATUS NgResizeAllowed(PNG_VCB Vcb, PNG_FCB Fcb, PFILE_OBJECT FileObject)
{
    if (!Fcb || !Fcb->IsVolume)
        return STATUS_INVALID_PARAMETER;
    if (!((PNG_CCB)FileObject->FsContext2)->ManageVolumeMutate)
        return STATUS_ACCESS_DENIED;
    if (Vcb->ReadOnly || Vcb->Damaged)
        return STATUS_MEDIA_WRITE_PROTECTED;
    return STATUS_SUCCESS;
}

/*
 * FSCTL_EXTEND_VOLUME: after the partition under it grew (IOCTL_DISK_GROW_PARTITION), the volume
 * takes the given number of sectors, its last one holding the boot sector copy (as on Windows
 * Server 2008 R2: the boot sector then counts one sector less).  A size with fewer clusters than
 * the volume has is invalid; one with the same number succeeds and changes nothing.
 */
static NTSTATUS NgExtendVolume(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, PIO_STACK_LOCATION Stack)
{
    GET_LENGTH_INFORMATION Length;
    LONGLONG Sectors;
    NTSTATUS Status;
    int Err;

    Status = NgResizeAllowed(Vcb, Fcb, Stack->FileObject);
    if (!NT_SUCCESS(Status))
        return Status;
    if (Stack->Parameters.FileSystemControl.InputBufferLength < sizeof(LONGLONG) || !Irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_PARAMETER;
    Sectors = *(PLONGLONG)Irp->AssociatedIrp.SystemBuffer;
    if (Sectors <= 0)
        return STATUS_INVALID_PARAMETER;
    Status = NgDeviceIoctl(Vcb->StorageDevice, IOCTL_DISK_GET_LENGTH_INFO, &Length, sizeof(Length));
    if (!NT_SUCCESS(Status))
        return Status;
#if DBG
    NgArmResizeFault();
#endif
    NgAcquireCore(Vcb);
    if (!Vcb->Core || Vcb->RawWritten)
        Err = -NGC_EROFS;
    else
        Err = ngc_extend(Vcb->Core, (unsigned long long)Sectors - 1, (unsigned long long)Length.Length.QuadPart);
    if (Vcb->Core)
    {
        struct ngc_ntfsdata d;
        NgResizeEnded(Vcb);
        ngc_ntfs_data(Vcb->Core, &d);
        if (d.sectors)
            Vcb->BootSectors = d.sectors;
    }
    NgReleaseCore(Vcb);
    DPRINT1("ntfsng: volume %08lx: extend to %I64d sectors (device %I64d bytes): %d, %I64u clusters\n",
            Vcb->Vpb->SerialNumber, Sectors, Length.Length.QuadPart, Err, Vcb->Info.total_clusters);
    return NgResizeStatus(Err);
}

/*
 * FSCTL_SHRINK_VOLUME, as on Windows Server 2008 R2: the size counts the boot sector copy (the boot
 * sector then says one sector less) and must leave fewer clusters.  ShrinkPrepare records the size
 * for the handle (another handle's pending request makes it STATUS_DEVICE_BUSY; the same handle may
 * prepare again); ShrinkCommit shrinks, STATUS_ACCESS_DENIED while a cluster past the new end is in
 * use (this driver moves no data); ShrinkAbort forgets it; commit and abort without a prepare on the
 * handle are invalid.  The handle's cleanup forgets its request.  Nothing is reserved meanwhile: an
 * allocation past the new end makes the commit fail.
 */
static NTSTATUS NgShrinkVolume(PNG_VCB Vcb, PNG_FCB Fcb, PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PSHRINK_VOLUME_INFORMATION Info = Irp->AssociatedIrp.SystemBuffer;
    PFILE_OBJECT FileObject = Stack->FileObject;
    NTSTATUS Status;
    int Err;

    Status = NgResizeAllowed(Vcb, Fcb, FileObject);
    if (!NT_SUCCESS(Status))
        return Status;
    if (Stack->Parameters.FileSystemControl.InputBufferLength < sizeof(*Info) || !Info)
        return STATUS_INVALID_PARAMETER;
#if DBG
    if (Info->ShrinkRequestType == ShrinkCommit)
        NgArmResizeFault();
#endif
    NgAcquireCore(Vcb);
    if (!Vcb->Core || Vcb->RawWritten)
    {
        NgReleaseCore(Vcb);
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    switch (Info->ShrinkRequestType)
    {
        case ShrinkPrepare:
            /* A handle whose cleanup ran (it forgot the handle's request) may not prepare again. */
            if (((PNG_CCB)FileObject->FsContext2)->CleanedUp)
            {
                Status = STATUS_INVALID_HANDLE;
                break;
            }
            if (Vcb->ShrinkOwner && Vcb->ShrinkOwner != FileObject)
            {
                Status = STATUS_DEVICE_BUSY;
                break;
            }
            if (Info->NewNumberOfSectors <= 1 ||
                ngc_shrink_valid(Vcb->Core, (unsigned long long)Info->NewNumberOfSectors - 1))
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            Vcb->ShrinkOwner = FileObject;
            Vcb->ShrinkSectors = (ULONGLONG)Info->NewNumberOfSectors - 1;
            Status = STATUS_SUCCESS;
            break;
        case ShrinkCommit:
            if (Vcb->ShrinkOwner != FileObject)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            Err = ngc_shrink(Vcb->Core, Vcb->ShrinkSectors);
            NgResizeEnded(Vcb);
            if (Err == -NGC_ENOSPC)
            {
                /* Data past the new end: the request stays prepared, as on Windows. */
                Status = STATUS_ACCESS_DENIED;
                break;
            }
            {
                struct ngc_ntfsdata d;
                ngc_ntfs_data(Vcb->Core, &d);
                if (d.sectors)
                    Vcb->BootSectors = d.sectors;
            }
            Vcb->ShrinkOwner = NULL;
            Vcb->ShrinkSectors = 0;
            Status = NgResizeStatus(Err);
            break;
        case ShrinkAbort:
            if (Vcb->ShrinkOwner != FileObject)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            Vcb->ShrinkOwner = NULL;
            Vcb->ShrinkSectors = 0;
            Status = STATUS_SUCCESS;
            break;
        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }
    NgReleaseCore(Vcb);
    DPRINT1("ntfsng: volume %08lx: shrink request %d to %I64d sectors: 0x%08lx\n", Vcb->Vpb->SerialNumber,
            Info->ShrinkRequestType, Info->NewNumberOfSectors, Status);
    return Status;
}

/*
 * FSCTL_GET_NTFS_VOLUME_DATA: NTFS_VOLUME_DATA_BUFFER, then as much of NTFS_EXTENDED_VOLUME_DATA
 * (ByteCount, MajorVersion, MinorVersion) as whole fields fit, ByteCount saying how much; Windows
 * Server 2008 R2 does the same (96, 100, 102 or 104 bytes).
 */
static NTSTATUS NgGetNtfsVolumeData(PNG_VCB Vcb, PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PNTFS_VOLUME_DATA_BUFFER Out = Irp->AssociatedIrp.SystemBuffer;
    PNTFS_EXTENDED_VOLUME_DATA Ext;
    ULONG Room, ExtLength;
    struct ngc_ntfsdata d;

    if (Stack->Parameters.FileSystemControl.OutputBufferLength < sizeof(*Out) || !Out)
        return STATUS_BUFFER_TOO_SMALL;
    Room = Stack->Parameters.FileSystemControl.OutputBufferLength - sizeof(*Out);
    Ext = (PNTFS_EXTENDED_VOLUME_DATA)(Out + 1);
    NgAcquireCore(Vcb);
    if (!Vcb->Core)
    {
        NgReleaseCore(Vcb);
        return STATUS_VOLUME_DISMOUNTED;
    }
    ngc_ntfs_data(Vcb->Core, &d);
    NgReleaseCore(Vcb);
    RtlZeroMemory(Out, sizeof(*Out));
    Out->VolumeSerialNumber.QuadPart = (LONGLONG)d.serial;
    Out->NumberSectors.QuadPart = (LONGLONG)d.sectors;
    Out->TotalClusters.QuadPart = (LONGLONG)d.total_clusters;
    Out->FreeClusters.QuadPart = (LONGLONG)d.free_clusters;
    Out->BytesPerSector = d.bytes_per_sector;
    Out->BytesPerCluster = d.bytes_per_cluster;
    Out->BytesPerFileRecordSegment = d.bytes_per_record;
    Out->ClustersPerFileRecordSegment = d.bytes_per_cluster ? d.bytes_per_record / d.bytes_per_cluster : 0;
    Out->MftValidDataLength.QuadPart = (LONGLONG)d.mft_valid_data;
    Out->MftStartLcn.QuadPart = (LONGLONG)d.mft_lcn;
    Out->Mft2StartLcn.QuadPart = (LONGLONG)d.mft2_lcn;
    Out->MftZoneStart.QuadPart = (LONGLONG)d.mft_zone_start;
    Out->MftZoneEnd.QuadPart = (LONGLONG)d.mft_zone_end;
    ExtLength = Room >= sizeof(*Ext) ? sizeof(*Ext) :
                Room >= FIELD_OFFSET(NTFS_EXTENDED_VOLUME_DATA, MinorVersion) ? FIELD_OFFSET(NTFS_EXTENDED_VOLUME_DATA, MinorVersion) :
                Room >= FIELD_OFFSET(NTFS_EXTENDED_VOLUME_DATA, MajorVersion) ? FIELD_OFFSET(NTFS_EXTENDED_VOLUME_DATA, MajorVersion) : 0;
    if (ExtLength)
        Ext->ByteCount = ExtLength;
    if (ExtLength > FIELD_OFFSET(NTFS_EXTENDED_VOLUME_DATA, MajorVersion))
        Ext->MajorVersion = d.major;
    if (ExtLength > FIELD_OFFSET(NTFS_EXTENDED_VOLUME_DATA, MinorVersion))
        Ext->MinorVersion = d.minor;
    Irp->IoStatus.Information = sizeof(*Out) + ExtLength;
    return STATUS_SUCCESS;
}

/*
 * FSCTL_GET_VOLUME_BITMAP (METHOD_NEITHER): the cluster bitmap from StartingLcn (rounded down to a
 * multiple of 8); STATUS_BUFFER_OVERFLOW when the caller's buffer holds only part of it.
 */
static NTSTATUS NgGetVolumeBitmap(PNG_VCB Vcb, PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PSTARTING_LCN_INPUT_BUFFER In = Stack->Parameters.FileSystemControl.Type3InputBuffer;
    PVOLUME_BITMAP_BUFFER Out = Irp->UserBuffer;
    ULONG InLen = Stack->Parameters.FileSystemControl.InputBufferLength;
    ULONG OutLen = Stack->Parameters.FileSystemControl.OutputBufferLength;
    ULONG Header = FIELD_OFFSET(VOLUME_BITMAP_BUFFER, Buffer), Bytes, Room;
    LONGLONG Start, Total, Count;
    NTSTATUS Status = STATUS_SUCCESS;
    PUCHAR Bits;
    int Err;

    if (!In || InLen < sizeof(*In))
        return STATUS_INVALID_PARAMETER;
    if (!Out || OutLen < Header)
        return STATUS_BUFFER_TOO_SMALL;
    _SEH2_TRY
    {
        if (Irp->RequestorMode != KernelMode)
        {
            ProbeForRead(In, sizeof(*In), sizeof(UCHAR));
            ProbeForWrite(Out, OutLen, sizeof(UCHAR));
        }
        Start = In->StartingLcn.QuadPart;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;
    NgAcquireCore(Vcb);
    if (!Vcb->Core)
    {
        NgReleaseCore(Vcb);
        return STATUS_VOLUME_DISMOUNTED;
    }
    ngc_volinfo(Vcb->Core, &Vcb->Info);
    Total = (LONGLONG)Vcb->Info.total_clusters;
    if (Start < 0 || Start >= Total)
    {
        NgReleaseCore(Vcb);
        return STATUS_INVALID_PARAMETER;
    }
    Start &= ~7LL;
    Count = Total - Start;
    Bytes = (ULONG)min((Count + 7) / 8, (LONGLONG)MAXULONG - Header);
    Room = OutLen - Header;
    if (Room < Bytes)
    {
        Bytes = Room;
        Status = STATUS_BUFFER_OVERFLOW;
    }
    Bits = Bytes ? ExAllocatePoolWithTag(PagedPool, Bytes, TAG_NTFSNG) : NULL;
    if (Bytes && !Bits)
    {
        NgReleaseCore(Vcb);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Err = Bytes ? ngc_read_bitmap(Vcb->Core, (unsigned long long)Start / 8, Bytes, Bits) : 0;
    NgReleaseCore(Vcb);
    if (Err)
    {
        if (Bits)
            ExFreePoolWithTag(Bits, TAG_NTFSNG);
        return NgErrnoToStatus(Err);
    }
    _SEH2_TRY
    {
        Out->StartingLcn.QuadPart = Start;
        Out->BitmapSize.QuadPart = Count;
        if (Bytes)
            RtlCopyMemory(Out->Buffer, Bits, Bytes);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (Bits)
        ExFreePoolWithTag(Bits, TAG_NTFSNG);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        Irp->IoStatus.Information = Header + Bytes;
    return Status;
}

/*
 * FSCTL_NG_CHECK (sdk/include/reactos/ntfsng_check.h): the mount-time consistency check on the mounted volume, from
 * chkdsk and autochk.  A volume handle with manage-volume access.  The core runs it under the volume lock, so it works
 * on the system volume; with NG_CHECK_FIX it frees leaks when nothing is damaged and otherwise makes the volume
 * read-only (nothing destructive is ever repaired).
 */
static NTSTATUS NgCheckVolume(PNG_VCB Vcb, PNG_FCB Fcb, PFILE_OBJECT FileObject, PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PNG_CHECK_RESULT Out = Irp->AssociatedIrp.SystemBuffer;
    PNG_CHECK_REQUEST In = Irp->AssociatedIrp.SystemBuffer;
    ULONG InLen = Stack->Parameters.FileSystemControl.InputBufferLength;
    ULONG OutLen = Stack->Parameters.FileSystemControl.OutputBufferLength;
    ULONG Flags, Version;
    struct ngc_check *C;
    NTSTATUS Status = STATUS_SUCCESS;
    int Err;

    if (!Fcb || !Fcb->IsVolume)
        return STATUS_INVALID_PARAMETER;
    if (!((PNG_CCB)FileObject->FsContext2)->ManageVolume)
        return STATUS_ACCESS_DENIED;
    if (!In || InLen < sizeof(NG_CHECK_REQUEST) || OutLen < sizeof(NG_CHECK_RESULT))
        return STATUS_BUFFER_TOO_SMALL;
    Version = In->Version;
    Flags = In->Flags;
    if (Version != NG_CHECK_VERSION || (Flags & ~(NG_CHECK_FIX | NG_CHECK_QUERY)))
        return STATUS_INVALID_PARAMETER;
    C = ExAllocatePoolWithTag(PagedPool, sizeof(*C), TAG_NTFSNG);
    if (!C)
        return STATUS_INSUFFICIENT_RESOURCES;
    NgAcquireCore(Vcb);
    if (!Vcb->Core)
    {
        NgReleaseCore(Vcb);
        ExFreePoolWithTag(C, TAG_NTFSNG);
        return STATUS_VOLUME_DISMOUNTED;
    }
    Err = ngc_check(Vcb->Core, Flags, C);
    ngc_volinfo(Vcb->Core, &Vcb->Info);
    if (!Err && (C->flags & NGC_CHK_NOW_READONLY))
    {
        Vcb->ReadOnly = TRUE;
        Vcb->Damaged = TRUE;
    }
    NgReleaseCore(Vcb);
    if (Err)
        Status = NgErrnoToStatus(Err);
    else
    {
        RtlZeroMemory(Out, sizeof(*Out));
        Out->Version = NG_CHECK_VERSION;
        Out->Flags = C->flags;
        Out->ClusterSize = C->cluster_size;
        Out->Fatal = C->fatal;
        Out->Leaks = C->leaks;
        Out->LeakedRecords = C->leaked_records;
        Out->FixedRecords = C->fixed_records;
        Out->DirsSkipped = C->dirs_skipped;
        Out->ClustersSkipped = C->clusters_skipped;
        Out->Ms = C->ms;
        Out->RepairErrors = C->repair_errors;
        Out->JournalReplayed = C->replayed;
        Out->PassMs[0] = C->pass_ms[0];
        Out->PassMs[1] = C->pass_ms[1];
        Out->PassMs[2] = C->pass_ms[2];
        Out->Records = C->records;
        Out->InUse = C->inuse;
        Out->Dirs = C->dirs;
        Out->IndexEntries = C->ientries;
        Out->Clusters = C->clusters;
        Out->LeakedClusters = C->leaked_clusters;
        Out->FixedClusters = C->fixed_clusters;
        Out->TotalClusters = C->total_clusters;
        Out->FreeClusters = C->free_clusters;
        Out->ExtRecords = C->ext_records;
        Out->Reparse = C->reparse;
        Out->SysClusters = C->sys_clusters;
        Out->LogClusters = C->log_clusters;
        Out->IndexClusters = C->index_clusters;
        RtlCopyMemory(Out->Why, C->why, sizeof(Out->Why));
        Out->Why[sizeof(Out->Why) - 1] = 0;
        Irp->IoStatus.Information = sizeof(*Out);
        if (C->flags & NGC_CHK_NOW_READONLY)
            NgReportDamage(Vcb, C->why, TRUE);
        DPRINT1("ntfsng: volume %08lx check%s: flags %x, %lu errors, %lu leaks\n", Vcb->Vpb->SerialNumber,
                (Flags & NG_CHECK_FIX) ? " with repair" : "", C->flags, C->fatal, C->leaks);
    }
    ExFreePoolWithTag(C, TAG_NTFSNG);
    return Status;
}

static NTSTATUS NgUserFsRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    PFILE_OBJECT FileObject = Stack->FileObject;
    PNG_FCB Fcb = FileObject ? FileObject->FsContext : NULL;
    switch (Stack->Parameters.FileSystemControl.FsControlCode)
    {
        case FSCTL_IS_VOLUME_MOUNTED:
            return STATUS_SUCCESS;
        case FSCTL_SET_COMPRESSION:
        {
            /* Turning compression off on an uncompressed stream is a no-op (the registry asks). */
            PUSHORT Format = Irp->AssociatedIrp.SystemBuffer;
            if (Vcb->ReadOnly)
                return STATUS_MEDIA_WRITE_PROTECTED;
            if (!Format || Stack->Parameters.FileSystemControl.InputBufferLength < sizeof(USHORT))
                return STATUS_INVALID_PARAMETER;
            if (*Format == COMPRESSION_FORMAT_NONE && Fcb && !(Fcb->Stat.flags & NGC_ATTR_COMPRESSED))
                return STATUS_SUCCESS;
            return STATUS_NOT_SUPPORTED;
        }
        case FSCTL_GET_COMPRESSION:
        {
            PUSHORT Format = Irp->AssociatedIrp.SystemBuffer;
            if (!Format || Stack->Parameters.FileSystemControl.OutputBufferLength < sizeof(USHORT))
                return STATUS_BUFFER_TOO_SMALL;
            *Format = (Fcb && (Fcb->Stat.flags & NGC_ATTR_COMPRESSED)) ? COMPRESSION_FORMAT_LZNT1 : COMPRESSION_FORMAT_NONE;
            Irp->IoStatus.Information = sizeof(USHORT);
            return STATUS_SUCCESS;
        }
        case FSCTL_MARK_AS_SYSTEM_HIVE:
            /* Advisory: the driver never dismounts a volume with open hives anyway. */
            return STATUS_SUCCESS;
        case FSCTL_MARK_VOLUME_DIRTY:
        {
            /*
             * As Windows (a check scheduled with chkdsk or chkntfs, fsutil dirty set): a volume handle with
             * manage-volume access, as for locking (the handle itself may be read-only), on a volume the core may write.
             */
            int Err;
            if (!Fcb || !Fcb->IsVolume)
                return STATUS_INVALID_PARAMETER;
            if (!((PNG_CCB)FileObject->FsContext2)->ManageVolume)
                return STATUS_ACCESS_DENIED;
            if (Vcb->ReadOnly || Vcb->Damaged)
                return STATUS_MEDIA_WRITE_PROTECTED;
            NgAcquireCore(Vcb);
            Err = ngc_mark_volume_dirty(Vcb->Core);
            ngc_volinfo(Vcb->Core, &Vcb->Info);
            NgReleaseCore(Vcb);
            DPRINT1("ntfsng: volume %08lx marked dirty on request: %d\n", Vcb->Vpb->SerialNumber, Err);
            return Err ? NgErrnoToStatus(Err) : STATUS_SUCCESS;
        }
        case FSCTL_IS_VOLUME_DIRTY:
        {
            PULONG Out = Irp->AssociatedIrp.SystemBuffer;
            if (!Out || Stack->Parameters.FileSystemControl.OutputBufferLength < sizeof(ULONG))
                return STATUS_INVALID_PARAMETER;
            NgAcquireCore(Vcb);
            ngc_volinfo(Vcb->Core, &Vcb->Info);
            NgReleaseCore(Vcb);
            *Out = Vcb->Info.dirty ? VOLUME_IS_DIRTY : 0;
            Irp->IoStatus.Information = sizeof(ULONG);
            return STATUS_SUCCESS;
        }
        /* Lock, unlock, dismount and the bitmap need a volume handle that may manage the volume
         * (create.c); as on Windows, other volume handles get STATUS_ACCESS_DENIED. */
        case FSCTL_LOCK_VOLUME:
            if (Fcb && Fcb->IsVolume && !((PNG_CCB)FileObject->FsContext2)->ManageVolume)
                return STATUS_ACCESS_DENIED;
            return NgLockVolume(Vcb, FileObject);
        case FSCTL_UNLOCK_VOLUME:
            if (Fcb && Fcb->IsVolume && !((PNG_CCB)FileObject->FsContext2)->ManageVolume)
                return STATUS_ACCESS_DENIED;
            if (!Fcb || !Fcb->IsVolume || !NgEndLock(Vcb, FileObject, FALSE))
                return STATUS_NOT_LOCKED;
            return STATUS_SUCCESS;
        case FSCTL_REQUEST_OPLOCK_LEVEL_1:
        case FSCTL_REQUEST_OPLOCK_LEVEL_2:
        case FSCTL_REQUEST_BATCH_OPLOCK:
        case FSCTL_REQUEST_FILTER_OPLOCK:
            /* Oplocks are never granted; callers fall back to uncached sharing. */
            return STATUS_OPLOCK_NOT_GRANTED;
        case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
        case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
        case FSCTL_OPLOCK_BREAK_NOTIFY:
        case FSCTL_OPLOCK_BREAK_ACK_NO_2:
            return STATUS_INVALID_OPLOCK_PROTOCOL;
#if DBG
        case FSCTL_NG_LOCK_STATS:
        {
            /* Diagnostic: a snapshot of the CoreLock statistics (benchmark tools diff two). */
            ULONG Out = Stack->Parameters.FileSystemControl.OutputBufferLength;
            /* A volume handle with manage-volume (administrator) authority only. */
            if (!Fcb || !Fcb->IsVolume || !((PNG_CCB)FileObject->FsContext2)->ManageVolume)
                return STATUS_ACCESS_DENIED;
            if (!Irp->AssociatedIrp.SystemBuffer || Out < sizeof(NG_LOCK_STATS))
                return STATUS_BUFFER_TOO_SMALL;
            NgAcquireCore(Vcb);
            Vcb->LockStats.Version = 1;
            Vcb->LockStats.Categories = NG_LOCK_CATEGORIES;
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Vcb->LockStats, sizeof(NG_LOCK_STATS));
            NgReleaseCore(Vcb);
            Irp->IoStatus.Information = sizeof(NG_LOCK_STATS);
            return STATUS_SUCCESS;
        }
        case FSCTL_NG_PROFILE:
        {
            /* Diagnostic: a snapshot of the time per stage (benchmark tools diff two). */
            ULONG Out = Stack->Parameters.FileSystemControl.OutputBufferLength;
            /* A volume handle with manage-volume (administrator) authority only. */
            if (!Fcb || !Fcb->IsVolume || !((PNG_CCB)FileObject->FsContext2)->ManageVolume)
                return STATUS_ACCESS_DENIED;
            if (!Irp->AssociatedIrp.SystemBuffer || Out < sizeof(NG_PROFILE))
                return STATUS_BUFFER_TOO_SMALL;
            NgProfile.Version = 1;
            NgProfile.Stages = NG_PROFILE_STAGES;
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &NgProfile, sizeof(NG_PROFILE));
            Irp->IoStatus.Information = sizeof(NG_PROFILE);
            return STATUS_SUCCESS;
        }
#endif
        case FSCTL_GET_REPARSE_POINT:
        case FSCTL_SET_REPARSE_POINT:
        case FSCTL_DELETE_REPARSE_POINT:
            return NgReparseFsctl(Vcb, Fcb, FileObject ? FileObject->FsContext2 : NULL, Irp, Stack,
                                  Stack->Parameters.FileSystemControl.FsControlCode);
        case FSCTL_DISMOUNT_VOLUME:
            return NgDismountVolume(Vcb, FileObject);
        case FSCTL_EXTEND_VOLUME:
            return NgExtendVolume(Vcb, Fcb, Irp, Stack);
        case FSCTL_SHRINK_VOLUME:
            return NgShrinkVolume(Vcb, Fcb, Irp, Stack);
        case FSCTL_GET_NTFS_VOLUME_DATA:
            if (!Fcb || !Fcb->IsVolume)
                return STATUS_INVALID_PARAMETER;
            return NgGetNtfsVolumeData(Vcb, Irp, Stack);
        case FSCTL_NG_CHECK:
            return NgCheckVolume(Vcb, Fcb, FileObject, Irp, Stack);
        case FSCTL_GET_VOLUME_BITMAP:
            if (!Fcb || !Fcb->IsVolume)
                return STATUS_INVALID_PARAMETER;
            if (!((PNG_CCB)FileObject->FsContext2)->ManageVolume)
                return STATUS_ACCESS_DENIED;
            return NgGetVolumeBitmap(Vcb, Irp, Stack);
        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}

/*
 * IRP_MN_VERIFY_VOLUME: the storage driver saw a possible media change.  The medium is this volume
 * only while its boot sector still says so (OEM name, serial number, sector size and count).
 * Otherwise every later request on the volume fails, nothing more is written to the device, and the
 * I/O manager mounts the new medium (STATUS_WRONG_VOLUME).
 */
static NTSTATUS NgVerifyVolume(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PVPB Vpb = Stack->Parameters.VerifyVolume.Vpb;
    PNG_VCB Vcb;
    PUCHAR Boot;
    NTSTATUS Status = STATUS_WRONG_VOLUME;

    if (DeviceObject == NgGlobal.ControlDevice)
        return STATUS_INVALID_DEVICE_REQUEST;
    Vcb = DeviceObject->DeviceExtension;
    if (Vcb->WrongMedia)
    {
        Vpb->RealDevice->Flags &= ~DO_VERIFY_VOLUME;
        return STATUS_WRONG_VOLUME;
    }
    if (!(Vpb->RealDevice->Flags & DO_VERIFY_VOLUME))
        return STATUS_SUCCESS;
    Boot = ExAllocatePoolWithTag(NonPagedPool, 4096, TAG_NTFSNG);
    if (!Boot)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (ngos_dev_read(Vcb->StorageDevice, 0, Boot, Vcb->SectorSize))
    {
        /* Unreadable is not "another medium": keep the volume, verify again later. */
        ExFreePoolWithTag(Boot, TAG_NTFSNG);
        return STATUS_IO_DEVICE_ERROR;
    }
    if (RtlCompareMemory(Boot + 3, "NTFS    ", 8) == 8 &&
        *(ULONGLONG UNALIGNED *)(Boot + 0x48) == Vcb->Info.serial &&
        *(ULONGLONG UNALIGNED *)(Boot + 0x28) == Vcb->BootSectors &&
        *(USHORT UNALIGNED *)(Boot + 0x0b) == Vcb->Info.sector_size)
    {
        Status = STATUS_SUCCESS;
    }
    ExFreePoolWithTag(Boot, TAG_NTFSNG);
    if (Status == STATUS_WRONG_VOLUME)
    {
        /*
         * Stops the flusher and every request before the next one reaches the new medium.  A dismount
         * may have won the race for the lock (a verify does not take the create gate): its core is
         * gone, but the dismounted volume handle must not write the new medium either.
         */
        NgAcquireCore(Vcb);
        Vcb->WrongMedia = TRUE;
        Vcb->ReadOnly = TRUE;
        if (Vcb->Core)
            ngc_medium_gone(Vcb->Core); /* requests already past dispatch fail in the core */
        NgReleaseCore(Vcb);
        DPRINT1("ntfsng: volume %08lx: the medium was changed; the volume is no longer usable\n", Vpb->SerialNumber);
    }
    Vpb->RealDevice->Flags &= ~DO_VERIFY_VOLUME;
    return Status;
}

NTSTATUS NgFileSystemControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    switch (Stack->MinorFunction)
    {
        case IRP_MN_MOUNT_VOLUME:
            return NgMountVolume(DeviceObject, Irp);
        case IRP_MN_VERIFY_VOLUME:
            return NgVerifyVolume(DeviceObject, Irp);
        case IRP_MN_USER_FS_REQUEST:
        case IRP_MN_KERNEL_CALL:
            if (DeviceObject == NgGlobal.ControlDevice)
                return STATUS_INVALID_DEVICE_REQUEST;
            return NgUserFsRequest(DeviceObject, Irp);
        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}
