/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Minimal WDM driver to practise kernel debugging on: DriverEntry,
 *              an unload routine, a ping IOCTL, DbgPrint and a deliberate bug
 *              check. Plain WDM, so the same file also builds with the WDK.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ntddk.h>

#define KDHELLO_DEVICE_NAME   L"\\Device\\KdHello"
#define KDHELLO_LINK_NAME     L"\\DosDevices\\KdHello"

/* METHOD_BUFFERED: the input is a ULONG, the output the same ULONG plus one */
#define IOCTL_KDHELLO_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* Deliberate bug check (MANUALLY_INITIATED_CRASH1), for practising crash analysis */
#define IOCTL_KDHELLO_BUGCHECK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KDHELLO_BUGCHECK_CODE 0xDEADDEAD

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD KdHelloUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
static DRIVER_DISPATCH KdHelloCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH KdHelloDeviceControl;

static ULONG KdHelloPingCount;

static
ULONG
KdHelloPing(
    _In_ ULONG Value)
{
    ULONG Result;

    /* A separate function, so that there is something to step into */
    Result = Value + 1;
    KdHelloPingCount++;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "KdHello: ping %lu -> %lu (call %lu)\n",
               Value, Result, KdHelloPingCount);
    return Result;
}

static
NTSTATUS
NTAPI
KdHelloCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
KdHelloDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR Information = 0;
    PULONG Buffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_KDHELLO_BUGCHECK)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "KdHello: bug check requested\n");
        KeBugCheckEx(KDHELLO_BUGCHECK_CODE, 0x4B44, KdHelloPingCount, 0, 0);
    }
    else if (Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_KDHELLO_PING)
    {
        if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) ||
            Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG))
        {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            Buffer = Irp->AssociatedIrp.SystemBuffer;
            *Buffer = KdHelloPing(*Buffer);
            Information = sizeof(ULONG);
            Status = STATUS_SUCCESS;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static
VOID
NTAPI
KdHelloUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING LinkName = RTL_CONSTANT_STRING(KDHELLO_LINK_NAME);

    IoDeleteSymbolicLink(&LinkName);
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "KdHello: unloaded after %lu pings\n", KdHelloPingCount);
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(KDHELLO_DEVICE_NAME);
    UNICODE_STRING LinkName = RTL_CONSTANT_STRING(KDHELLO_LINK_NAME);
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "KdHello: DriverEntry, registry path %wZ\n", RegistryPath);

    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = IoCreateSymbolicLink(&LinkName, &DeviceName);
    if (!NT_SUCCESS(Status))
    {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KdHelloCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KdHelloCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KdHelloDeviceControl;
    DriverObject->DriverUnload = KdHelloUnload;
    return STATUS_SUCCESS;
}
