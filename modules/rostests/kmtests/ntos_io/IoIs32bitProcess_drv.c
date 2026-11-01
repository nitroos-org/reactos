/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test driver that reports IoIs32bitProcess for the requests it gets
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <kmt_test.h>
#include "IoIs32bitProcess.h"

#define NDEBUG
#include <debug.h>

C_ASSERT(IOIS32_MJ_CREATE == IRP_MJ_CREATE);
C_ASSERT(IOIS32_MJ_QUERY_INFORMATION == IRP_MJ_QUERY_INFORMATION);
C_ASSERT(IOIS32_MJ_SET_INFORMATION == IRP_MJ_SET_INFORMATION);
C_ASSERT(IOIS32_MJ_FLUSH_BUFFERS == IRP_MJ_FLUSH_BUFFERS);
C_ASSERT(IOIS32_MJ_QUERY_VOLUME_INFORMATION == IRP_MJ_QUERY_VOLUME_INFORMATION);
C_ASSERT(IOIS32_MJ_LOCK_CONTROL == IRP_MJ_LOCK_CONTROL);

static KMT_IRP_HANDLER TestIrpHandler;
static KMT_IRP_HANDLER TestOtherHandler;
static IOIS32_LAST Last[IRP_MJ_MAXIMUM_FUNCTION + 1];
static IO_WORKITEM_ROUTINE TestWorkItem;

NTSTATUS
TestEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _Out_ PCWSTR *DeviceName,
    _Inout_ INT *Flags)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    *DeviceName = L"IoIs32bitProcess";
    *Flags = TESTENTRY_NO_EXCLUSIVE_DEVICE |
             TESTENTRY_BUFFERED_IO_DEVICE |
             TESTENTRY_NO_READONLY_DEVICE;

    KmtRegisterIrpHandler(IRP_MJ_DEVICE_CONTROL, NULL, TestIrpHandler);
    KmtRegisterIrpHandler(IRP_MJ_CREATE, NULL, TestOtherHandler);
    KmtRegisterIrpHandler(IRP_MJ_QUERY_INFORMATION, NULL, TestOtherHandler);
    KmtRegisterIrpHandler(IRP_MJ_SET_INFORMATION, NULL, TestOtherHandler);
    KmtRegisterIrpHandler(IRP_MJ_FLUSH_BUFFERS, NULL, TestOtherHandler);
    KmtRegisterIrpHandler(IRP_MJ_QUERY_VOLUME_INFORMATION, NULL, TestOtherHandler);
    KmtRegisterIrpHandler(IRP_MJ_LOCK_CONTROL, NULL, TestOtherHandler);

    return STATUS_SUCCESS;
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
}

static
ULONG
Is32(
    _In_opt_ PIRP Irp)
{
#ifdef _WIN64
    return IoIs32bitProcess(Irp) ? 1 : 0;
#else
    /* 32-bit kernels have no such function: nobody is a WoW64 process */
    UNREFERENCED_PARAMETER(Irp);
    return 0;
#endif
}

/* The answer for a request of this thread that the driver builds itself: a kernel-mode request */
static
ULONG
AskAsKernel(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    ULONG Answer = 0xdead;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp;
    NTSTATUS Status;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildDeviceIoControlRequest(IOIS32_CODE_KERNEL, DeviceObject, NULL, 0, &Answer, sizeof(Answer),
                                        FALSE, &Event, &IoStatus);
    if (!Irp)
        return 0xdead;
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    return Answer;
}

static
VOID
Fill(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ ULONG Completion)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    IOIS32_REPORT *Report = Irp->AssociatedIrp.SystemBuffer;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*Report))
    {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        return;
    }
    RtlZeroMemory(Report, sizeof(*Report));
    Report->ForIrp = Is32(Irp);
    Report->ForCurrent = Is32(NULL);
    Report->ForKernelIrp = AskAsKernel(DeviceObject);
    Report->RequestorMode = Irp->RequestorMode;
    Report->KernelIosb = (PVOID)Irp->UserIosb > MmHighestUserAddress;
    Report->Completion = Completion;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(*Report);
}

static
VOID
NTAPI
TestWorkItem(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PIRP Irp = Context;

    IoFreeWorkItem(Irp->Tail.Overlay.DriverContext[0]);
    /* A system thread: the request is the only thing that tells the process */
    Fill(DeviceObject, Irp, 2);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* Writes down what the request looks like and completes it */
static
NTSTATUS
TestOtherHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation)
{
    IOIS32_LAST *Entry = &Last[IoStackLocation->MajorFunction];

    UNREFERENCED_PARAMETER(DeviceObject);

    Entry->ForIrp = Is32(Irp);
    Entry->RequestorMode = Irp->RequestorMode;
    Entry->KernelIosb = (PVOID)Irp->UserIosb > MmHighestUserAddress;
    Entry->Seen = 1;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
TestIrpHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation)
{
    ULONG Code = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    if (Code == IOIS32_CODE_KERNEL)
    {
        /* the nested request: only the answer */
        if (IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG))
        {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = Is32(Irp);
            Irp->IoStatus.Information = sizeof(ULONG);
            Status = STATUS_SUCCESS;
        }
        else
            Status = STATUS_BUFFER_TOO_SMALL;
    }
    else if (Code == IOIS32_CODE_LAST)
    {
        ULONG Major = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG) ?
                      *(PULONG)Irp->AssociatedIrp.SystemBuffer : MAXULONG;

        if (Major > IRP_MJ_MAXIMUM_FUNCTION ||
            IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(IOIS32_LAST))
        {
            Status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            *(IOIS32_LAST *)Irp->AssociatedIrp.SystemBuffer = Last[Major];
            RtlZeroMemory(&Last[Major], sizeof(Last[Major]));
            Irp->IoStatus.Information = sizeof(IOIS32_LAST);
            Status = STATUS_SUCCESS;
        }
    }
    else if (Code == IOIS32_CODE_SYNC)
    {
        Fill(DeviceObject, Irp, 1);
        Status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }
    else if (Code == IOIS32_CODE_PENDING)
    {
        PIO_WORKITEM Item = IoAllocateWorkItem(DeviceObject);

        if (Item)
        {
            Irp->Tail.Overlay.DriverContext[0] = Item;
            IoMarkIrpPending(Irp);
            IoQueueWorkItem(Item, TestWorkItem, DelayedWorkQueue, Irp);
            return STATUS_PENDING;
        }
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    Irp->IoStatus.Status = Status;
    if (!NT_SUCCESS(Status))
        Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
