/*
 * PROJECT:     ReactOS test suite
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Pass-through function driver for QEMU's "edu" PCI test device (1234:11e8)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * It does nothing with the device. Binding it makes the PnP manager assign and translate
 * the device's resources (a device without a function driver gets none), so that the
 * kmtest IoInterrupt can call IoConnectInterruptEx on the device's PDO.
 */

#include <ntddk.h>

typedef struct _STUB_EXT
{
    PDEVICE_OBJECT Lower;
} STUB_EXT, *PSTUB_EXT;

static
NTSTATUS
NTAPI
OnLowerDone(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent(Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
NTAPI
StubPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PSTUB_EXT Ext = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    if (Stack->MinorFunction == IRP_MN_START_DEVICE)
    {
        KEVENT Event;

        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, OnLowerDone, &Event, TRUE, TRUE, TRUE);
        Status = IoCallDriver(Ext->Lower, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = Irp->IoStatus.Status;
        }
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }

    if (Stack->MinorFunction == IRP_MN_REMOVE_DEVICE)
    {
        PDEVICE_OBJECT Lower = Ext->Lower;

        IoSkipCurrentIrpStackLocation(Irp);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Status = IoCallDriver(Lower, Irp);
        IoDetachDevice(Lower);
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(Ext->Lower, Irp);
}

static
NTSTATUS
NTAPI
StubPower(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PSTUB_EXT Ext = DeviceObject->DeviceExtension;

    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(Ext->Lower, Irp);
}

static
NTSTATUS
NTAPI
StubForward(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PSTUB_EXT Ext = DeviceObject->DeviceExtension;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(Ext->Lower, Irp);
}

static
NTSTATUS
NTAPI
StubAddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT Pdo)
{
    PDEVICE_OBJECT Fdo;
    PSTUB_EXT Ext;
    NTSTATUS Status;

    Status = IoCreateDevice(DriverObject, sizeof(*Ext), NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &Fdo);
    if (!NT_SUCCESS(Status))
        return Status;

    Ext = Fdo->DeviceExtension;
    Ext->Lower = IoAttachDeviceToDeviceStack(Fdo, Pdo);
    if (!Ext->Lower)
    {
        IoDeleteDevice(Fdo);
        return STATUS_NO_SUCH_DEVICE;
    }
    Fdo->Flags |= Ext->Lower->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = StubForward;
    DriverObject->MajorFunction[IRP_MJ_PNP] = StubPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = StubPower;
    DriverObject->DriverExtension->AddDevice = StubAddDevice;
    return STATUS_SUCCESS;
}
