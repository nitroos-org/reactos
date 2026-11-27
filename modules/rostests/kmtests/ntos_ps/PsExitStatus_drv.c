/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test driver that holds an exiting thread in the thread notify routine
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The notify routine runs early in the exit of a thread, before the thread is counted out of its process.
 * Holding it there lets the user-mode part decide which thread of the process is the last to exit.
 */

#include <kmt_test.h>
#include "PsExitStatus.h"

#define NDEBUG
#include <debug.h>

static KMT_MESSAGE_HANDLER TestMessageHandler;
static BOOLEAN NotifyRegistered;
static KEVENT HeldEvent;
static KEVENT ReleaseEvent;
static volatile LONG Armed;
static HANDLE TargetProcessId;
static HANDLE SkipThreadId;
static HANDLE HeldThreadId;

static
VOID
NTAPI
ThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    LARGE_INTEGER Timeout;

    if (Create || !Armed || ProcessId != TargetProcessId || ThreadId == SkipThreadId)
        return;
    if (InterlockedCompareExchange(&Armed, 0, 1) != 1)
        return;

    HeldThreadId = ThreadId;
    KeSetEvent(&HeldEvent, IO_NO_INCREMENT, FALSE);

    /* never longer than 30 s, whatever the user-mode part does */
    Timeout.QuadPart = -30LL * 1000 * 1000 * 10;
    KeWaitForSingleObject(&ReleaseEvent, Executive, KernelMode, FALSE, &Timeout);
}

NTSTATUS
TestEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PCUNICODE_STRING RegistryPath,
    _Out_ PCWSTR *DeviceName,
    _Inout_ INT *Flags)
{
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    *DeviceName = L"PsExitStatus";
    *Flags = TESTENTRY_NO_EXCLUSIVE_DEVICE;

    KeInitializeEvent(&HeldEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&ReleaseEvent, NotificationEvent, FALSE);
    Status = PsSetCreateThreadNotifyRoutine(ThreadNotify);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return Status;
    NotifyRegistered = TRUE;

    KmtRegisterMessageHandler(0, NULL, TestMessageHandler);

    return STATUS_SUCCESS;
}

VOID
TestUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    InterlockedExchange(&Armed, 0);
    KeSetEvent(&ReleaseEvent, IO_NO_INCREMENT, FALSE);
    if (NotifyRegistered)
        PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
}

static
NTSTATUS
TestMessageHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG ControlCode,
    _In_opt_ PVOID Buffer,
    _In_ SIZE_T InLength,
    _Inout_ PSIZE_T OutLength)
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (ControlCode)
    {
        case IOCTL_PSEXIT_ARM:
        {
            PPSEXIT_ARM Arm = Buffer;

            *OutLength = 0;
            if (!Buffer || InLength < sizeof(*Arm))
                return STATUS_INVALID_PARAMETER;
            InterlockedExchange(&Armed, 0);
            KeClearEvent(&HeldEvent);
            KeClearEvent(&ReleaseEvent);
            HeldThreadId = NULL;
            TargetProcessId = ULongToHandle(Arm->ProcessId);
            SkipThreadId = ULongToHandle(Arm->SkipThreadId);
            InterlockedExchange(&Armed, 1);
            return STATUS_SUCCESS;
        }
        case IOCTL_PSEXIT_WAIT:
        {
            if (!Buffer || InLength < sizeof(ULONG) || *OutLength < sizeof(ULONG))
            {
                *OutLength = 0;
                return STATUS_INVALID_PARAMETER;
            }
            Timeout.QuadPart = -(LONGLONG)*(PULONG)Buffer * 1000 * 10;
            Status = KeWaitForSingleObject(&HeldEvent, Executive, KernelMode, FALSE, &Timeout);
            if (Status != STATUS_SUCCESS)
            {
                *OutLength = 0;
                return STATUS_IO_TIMEOUT;
            }
            *(PULONG)Buffer = HandleToULong(HeldThreadId);
            *OutLength = sizeof(ULONG);
            return STATUS_SUCCESS;
        }
        case IOCTL_PSEXIT_RELEASE:
            *OutLength = 0;
            InterlockedExchange(&Armed, 0);
            KeSetEvent(&ReleaseEvent, IO_NO_INCREMENT, FALSE);
            return STATUS_SUCCESS;
        default:
            *OutLength = 0;
            return STATUS_NOT_SUPPORTED;
    }
}
