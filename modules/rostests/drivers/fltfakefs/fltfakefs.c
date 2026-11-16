/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     A minimal file system for the tests of the filter manager: see fltfakefs.h.
 *              Written against the WDK documentation of file system drivers.
 *
 * The driver stays loaded until the next boot (no unload routine): the I/O manager and the filter
 * manager keep pointers to its devices.
 */

#include <ntifs.h>

#include "fltfakefs.h"

#define NDEBUG
#include <debug.h>

#define TAG_FAKEFS 'sFkF'

typedef struct _DPC_ITEM
{
    KDPC Dpc;
    PIRP Irp;

} DPC_ITEM, *PDPC_ITEM;

static PDRIVER_OBJECT FakeDriver;
static PDEVICE_OBJECT ControlDevice;    /* \Device\FltFakeFsCtl: the tests' requests */
static PDEVICE_OBJECT FsDevice;         /* the file system's control device */
static PDEVICE_OBJECT DiskDevice;       /* \Device\FltFakeDisk */
static PDEVICE_OBJECT VolumeDevice;     /* the mounted volume, if any */
static FAST_MUTEX VolumeLock;
static volatile LONG OpenFiles;         /* file objects of the volume not closed yet */
static FLTFAKEFS_STATS Stats;

/* One stream for every file: the files are all empty */
static ULONG_PTR FakeFcb[8];

DRIVER_INITIALIZE DriverEntry;
static DRIVER_DISPATCH FakeDispatch;
static KDEFERRED_ROUTINE CompleteDpc;

static
BOOLEAN
IsDpcName(_In_ PFILE_OBJECT FileObject)
{
    static const WCHAR Suffix[] = L".dpc";
    USHORT Length = sizeof(Suffix) - sizeof(WCHAR);
    UNICODE_STRING Tail, Expected;

    if (FileObject == NULL || FileObject->FileName.Buffer == NULL || FileObject->FileName.Length < Length)
        return FALSE;

    Tail.Buffer = (PWCHAR)((PUCHAR)FileObject->FileName.Buffer + FileObject->FileName.Length - Length);
    Tail.Length = Tail.MaximumLength = Length;
    RtlInitUnicodeString(&Expected, Suffix);
    return RtlEqualUnicodeString(&Tail, &Expected, TRUE);
}

static
VOID
NTAPI
CompleteDpc(_In_ PKDPC Dpc,
            _In_opt_ PVOID Context,
            _In_opt_ PVOID Argument1,
            _In_opt_ PVOID Argument2)
{
    PDPC_ITEM Item = Context;
    PIRP Irp = Item->Irp;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ExFreePoolWithTag(Item, TAG_FAKEFS);
    InterlockedIncrement((PLONG)&Stats.DpcCompletions);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* The request is done with Status and Information: now, or from a DPC if the file wants that */
static
NTSTATUS
Complete(_Inout_ PIRP Irp,
         _In_ NTSTATUS Status,
         _In_ ULONG_PTR Information,
         _In_ BOOLEAN FromDpc)
{
    PDPC_ITEM Item = NULL;

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;

    if (FromDpc)
        Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Item), TAG_FAKEFS);

    if (Item == NULL)
    {
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }

    Item->Irp = Irp;
    KeInitializeDpc(&Item->Dpc, CompleteDpc, Item);
    IoMarkIrpPending(Irp);
    KeInsertQueueDpc(&Item->Dpc, NULL, NULL);
    return STATUS_PENDING;
}

static
NTSTATUS
MountVolume(_Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PVPB Vpb = Stack->Parameters.MountVolume.Vpb;
    PDEVICE_OBJECT Real = Stack->Parameters.MountVolume.DeviceObject;
    PDEVICE_OBJECT Volume;
    NTSTATUS Status;

    /* Our disk and nothing else */
    if (Real != DiskDevice || Vpb == NULL)
        return STATUS_UNRECOGNIZED_VOLUME;

    ExAcquireFastMutex(&VolumeLock);
    if (VolumeDevice)
    {
        ExReleaseFastMutex(&VolumeLock);
        return STATUS_UNRECOGNIZED_VOLUME;
    }

    Status = IoCreateDevice(FakeDriver, 0, NULL, FILE_DEVICE_DISK_FILE_SYSTEM, 0, FALSE, &Volume);
    if (!NT_SUCCESS(Status))
    {
        ExReleaseFastMutex(&VolumeLock);
        return Status;
    }

    Volume->StackSize = Real->StackSize + 1;
    Volume->Flags |= DO_BUFFERED_IO;
    Volume->Flags &= ~DO_DEVICE_INITIALIZING;
    Vpb->DeviceObject = Volume;
    Vpb->SerialNumber = 0x464B4653;
    Vpb->VolumeLabelLength = 0;
    VolumeDevice = Volume;
    InterlockedIncrement((PLONG)&Stats.Mounts);
    ExReleaseFastMutex(&VolumeLock);
    return STATUS_SUCCESS;
}

/* The medium is gone: the volume device goes, without a dismount request (fltfakefs.h) */
static
NTSTATUS
DeleteVolume(VOID)
{
    PDEVICE_OBJECT Volume;
    KIRQL OldIrql;
    PVPB Vpb = DiskDevice->Vpb;

    ExAcquireFastMutex(&VolumeLock);
    Volume = VolumeDevice;
    if (Volume == NULL)
    {
        ExReleaseFastMutex(&VolumeLock);
        return STATUS_NOT_FOUND;
    }

    /* Files still open: not now (the VPB keeps a reference of the mount, our own count is what tells) */
    if (OpenFiles != 0)
    {
        ExReleaseFastMutex(&VolumeLock);
        return STATUS_DEVICE_BUSY;
    }

    IoAcquireVpbSpinLock(&OldIrql);
    Vpb->Flags &= ~VPB_MOUNTED;
    Vpb->DeviceObject = NULL;
    IoReleaseVpbSpinLock(OldIrql);

    VolumeDevice = NULL;
    InterlockedIncrement((PLONG)&Stats.VolumesDeleted);
    ExReleaseFastMutex(&VolumeLock);

    IoDeleteDevice(Volume);
    return STATUS_SUCCESS;
}

static
NTSTATUS
ControlRequest(_Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG_PTR Information = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
    {
        switch (Stack->Parameters.DeviceIoControl.IoControlCode)
        {
            case FLTFAKEFS_IOCTL_GET_STATS:
                if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(Stats))
                {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                Stats.Size = sizeof(Stats);
                Stats.Mounted = VolumeDevice != NULL;
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Stats, sizeof(Stats));
                Information = sizeof(Stats);
                break;

            case FLTFAKEFS_IOCTL_DELETE_VOLUME:
                Status = DeleteVolume();
                break;

            default:
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }

    return Complete(Irp, Status, NT_SUCCESS(Status) ? Information : 0, FALSE);
}

static
NTSTATUS
VolumeRequest(_Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = Stack->FileObject;

    switch (Stack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            InterlockedIncrement((PLONG)&Stats.Creates);
            InterlockedIncrement(&OpenFiles);
            if (FileObject)
                FileObject->FsContext = FakeFcb;
            return Complete(Irp, STATUS_SUCCESS, FILE_OPENED, IsDpcName(FileObject));

        case IRP_MJ_CLOSE:
            InterlockedDecrement(&OpenFiles);
            return Complete(Irp, STATUS_SUCCESS, 0, FALSE);

        case IRP_MJ_CLEANUP:
            return Complete(Irp, STATUS_SUCCESS, 0, FALSE);

        case IRP_MJ_READ:
            if (Irp->AssociatedIrp.SystemBuffer && Stack->Parameters.Read.Length)
                RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, Stack->Parameters.Read.Length);
            return Complete(Irp, STATUS_SUCCESS, Stack->Parameters.Read.Length, IsDpcName(FileObject));

        case IRP_MJ_WRITE:
            return Complete(Irp, STATUS_SUCCESS, Stack->Parameters.Write.Length, IsDpcName(FileObject));

        default:
            return Complete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0, FALSE);
    }
}

static
NTSTATUS
NTAPI
FakeDispatch(_In_ PDEVICE_OBJECT DeviceObject,
             _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    if (DeviceObject == ControlDevice)
        return ControlRequest(Irp);

    if (DeviceObject == FsDevice)
    {
        /* The file system's own device: mounts, and the opens and closes of it */
        if (Stack->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL && Stack->MinorFunction == IRP_MN_MOUNT_VOLUME)
            return Complete(Irp, MountVolume(Irp), 0, FALSE);
        if (Stack->MajorFunction == IRP_MJ_CREATE || Stack->MajorFunction == IRP_MJ_CLEANUP ||
            Stack->MajorFunction == IRP_MJ_CLOSE)
        {
            return Complete(Irp, STATUS_SUCCESS, 0, FALSE);
        }
        return Complete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0, FALSE);
    }

    if (DeviceObject == DiskDevice)
    {
        /* Nothing on it any file system could recognize */
        return Complete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0, FALSE);
    }

    /* A volume device, the current one or one which is being deleted */
    return VolumeRequest(Irp);
}

NTSTATUS
NTAPI
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING Name, Link;
    NTSTATUS Status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    FakeDriver = DriverObject;
    ExInitializeFastMutex(&VolumeLock);
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = FakeDispatch;

    RtlInitUnicodeString(&Name, L"\\Device\\FltFakeFsCtl");
    Status = IoCreateDevice(DriverObject, 0, &Name, FILE_DEVICE_UNKNOWN, 0, FALSE, &ControlDevice);
    if (!NT_SUCCESS(Status))
        return Status;
    RtlInitUnicodeString(&Link, L"\\??\\FltFakeFsCtl");
    IoCreateSymbolicLink(&Link, &Name);
    ControlDevice->Flags |= DO_BUFFERED_IO;
    ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&Name, FLTFAKEFS_DISK_NAME);
    Status = IoCreateDevice(DriverObject, 0, &Name, FILE_DEVICE_DISK, 0, FALSE, &DiskDevice);
    if (!NT_SUCCESS(Status))
        goto Fail;
    DiskDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&Name, L"\\FltFakeFs");
    Status = IoCreateDevice(DriverObject, 0, &Name, FILE_DEVICE_DISK_FILE_SYSTEM, 0, FALSE, &FsDevice);
    if (!NT_SUCCESS(Status))
        goto Fail;
    FsDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    /* The filter manager hears of us here and attaches to the file system's device */
    IoRegisterFileSystem(FsDevice);
    return STATUS_SUCCESS;

Fail:
    if (DiskDevice)
        IoDeleteDevice(DiskDevice);
    IoDeleteSymbolicLink(&Link);
    IoDeleteDevice(ControlDevice);
    return Status;
}
