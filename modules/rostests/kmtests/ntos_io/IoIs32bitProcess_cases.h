/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IoIs32bitProcess test: the requests, shared by kmtest.exe and the 32-bit client
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Needs ok(), trace(), ok_eq_ulong(), ok_eq_long() and ok_eq_hex() from the includer.
 */

#include "IoIs32bitProcess.h"

#define DEVICE_PATH L"\\\\.\\Global\\GLOBALROOT\\Device\\Kmtest-IoIs32bitProcess"

static BOOLEAN Expected;
static volatile LONG ApcCalls;

static
VOID
NTAPI
TestApc(
    _In_ PVOID Context,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(IoStatusBlock);
    UNREFERENCED_PARAMETER(Reserved);
    InterlockedIncrement(&ApcCalls);
}

static
VOID
Check(
    _In_ PCSTR Case,
    _In_ ULONG Code,
    _In_ const IOIS32_REPORT *Report)
{
    trace("%-34s code %08lx: irp=%lu current=%lu kernelirp=%lu mode=%lu kernel-iosb=%lu completion=%lu\n",
          Case, Code, Report->ForIrp, Report->ForCurrent, Report->ForKernelIrp, Report->RequestorMode,
          Report->KernelIosb, Report->Completion);
    ok_eq_ulong(Report->ForIrp, Expected ? 1 : 0);
    ok_eq_ulong(Report->RequestorMode, UserMode);
    /* the thread of the dispatch routine is the caller's; a work item runs in a system thread */
    ok_eq_ulong(Report->ForCurrent, (Expected && Report->Completion == 1) ? 1 : 0);
    ok_eq_ulong(Report->Completion, Code == IOIS32_CODE_SYNC ? 1 : 2);
    /* a request the driver builds is a kernel-mode request, from a WoW64 thread too */
    ok_eq_ulong(Report->ForKernelIrp, 0);
}

static
HANDLE
OpenDevice(
    _In_ BOOLEAN Overlapped)
{
    HANDLE Device = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                Overlapped ? FILE_FLAG_OVERLAPPED : 0, NULL);
    ok(Device != INVALID_HANDLE_VALUE, "CreateFile failed with %lu\n", GetLastError());
    return Device;
}

/* a) synchronous handle, no event: the case that used to give a kernel IO_STATUS_BLOCK */
static
VOID
TestSynchronous(
    _In_ ULONG Code)
{
    HANDLE Device = OpenDevice(FALSE);
    IOIS32_REPORT Report;
    DWORD Returned = 0;
    BOOL Ret;

    if (Device == INVALID_HANDLE_VALUE) return;
    RtlFillMemory(&Report, sizeof(Report), 0x55);
    Ret = DeviceIoControl(Device, Code, NULL, 0, &Report, sizeof(Report), &Returned, NULL);
    ok(Ret, "DeviceIoControl failed with %lu\n", GetLastError());
    ok_eq_ulong(Returned, sizeof(Report));
    if (Ret) Check("synchronous, no event", Code, &Report);
    CloseHandle(Device);
}

/* a2) synchronous handle through the native call, with and without an event */
static
VOID
TestSynchronousNt(
    _In_ ULONG Code,
    _In_ BOOLEAN WithEvent)
{
    HANDLE Device = OpenDevice(FALSE);
    HANDLE Event = NULL;
    IOIS32_REPORT Report;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    if (Device == INVALID_HANDLE_VALUE) return;
    if (WithEvent) Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    RtlFillMemory(&Report, sizeof(Report), 0x55);
    RtlFillMemory(&IoStatus, sizeof(IoStatus), 0x55);
    Status = NtDeviceIoControlFile(Device, Event, NULL, NULL, &IoStatus, Code, NULL, 0, &Report, sizeof(Report));
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_hex(IoStatus.Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status)) Check(WithEvent ? "synchronous, Nt, event" : "synchronous, Nt, no event", Code, &Report);
    if (Event) CloseHandle(Event);
    CloseHandle(Device);
}

/* b) overlapped handle with an event in the OVERLAPPED */
static
VOID
TestOverlappedEvent(
    _In_ ULONG Code)
{
    HANDLE Device = OpenDevice(TRUE);
    IOIS32_REPORT Report;
    OVERLAPPED Overlapped = { 0 };
    DWORD Returned = 0;
    BOOL Ret;

    if (Device == INVALID_HANDLE_VALUE) return;
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    RtlFillMemory(&Report, sizeof(Report), 0x55);
    Ret = DeviceIoControl(Device, Code, NULL, 0, &Report, sizeof(Report), &Returned, &Overlapped);
    if (!Ret && GetLastError() == ERROR_IO_PENDING)
        Ret = GetOverlappedResult(Device, &Overlapped, &Returned, TRUE);
    ok(Ret, "DeviceIoControl failed with %lu\n", GetLastError());
    ok_eq_ulong(Returned, sizeof(Report));
    if (Ret) Check("overlapped, event", Code, &Report);
    CloseHandle(Overlapped.hEvent);
    CloseHandle(Device);
}

/* c1) APC routine */
static
VOID
TestApcForm(
    _In_ ULONG Code)
{
    HANDLE Device = OpenDevice(TRUE);
    IOIS32_REPORT Report;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    DWORD Wait;
    int i;

    if (Device == INVALID_HANDLE_VALUE) return;
    ApcCalls = 0;
    RtlFillMemory(&Report, sizeof(Report), 0x55);
    IoStatus.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(Device, NULL, TestApc, NULL, &IoStatus, Code, NULL, 0, &Report, sizeof(Report));
    ok(Status == STATUS_SUCCESS || Status == STATUS_PENDING, "NtDeviceIoControlFile returned %08lx\n", Status);
    for (i = 0; i < 50 && ApcCalls == 0; i++)
    {
        Wait = SleepEx(100, TRUE);
        ok(Wait == 0 || Wait == WAIT_IO_COMPLETION, "SleepEx returned %lu\n", Wait);
    }
    ok_eq_long(ApcCalls, 1);
    ok_eq_hex(IoStatus.Status, STATUS_SUCCESS);
    if (ApcCalls == 1 && IoStatus.Status == STATUS_SUCCESS) Check("APC routine", Code, &Report);
    CloseHandle(Device);
}

/* c2) completion port */
static
VOID
TestCompletionPort(
    _In_ ULONG Code)
{
    HANDLE Device = OpenDevice(TRUE);
    HANDLE Port;
    IOIS32_REPORT Report;
    OVERLAPPED Overlapped = { 0 };
    LPOVERLAPPED Completed = NULL;
    DWORD Returned = 0;
    ULONG_PTR Key = 0;
    BOOL Ret;

    if (Device == INVALID_HANDLE_VALUE) return;
    Port = CreateIoCompletionPort(Device, NULL, 0x1234, 0);
    ok(Port != NULL, "CreateIoCompletionPort failed with %lu\n", GetLastError());
    if (!Port)
    {
        CloseHandle(Device);
        return;
    }
    RtlFillMemory(&Report, sizeof(Report), 0x55);
    Ret = DeviceIoControl(Device, Code, NULL, 0, &Report, sizeof(Report), &Returned, &Overlapped);
    ok(Ret || GetLastError() == ERROR_IO_PENDING, "DeviceIoControl failed with %lu\n", GetLastError());
    Ret = GetQueuedCompletionStatus(Port, &Returned, &Key, &Completed, 5000);
    ok(Ret, "GetQueuedCompletionStatus failed with %lu\n", GetLastError());
    ok(Completed == &Overlapped, "completed %p, expected %p\n", Completed, &Overlapped);
    ok_eq_ulong(Returned, sizeof(Report));
    if (Ret && Completed == &Overlapped) Check("completion port", Code, &Report);
    CloseHandle(Port);
    CloseHandle(Device);
}


/* What the driver saw for the last request of the given function */
static
VOID
CheckLast(
    _In_ HANDLE Device,
    _In_ ULONG Major,
    _In_ PCSTR Name)
{
    IOIS32_LAST Last;
    DWORD Returned = 0;
    BOOL Ret;

    RtlFillMemory(&Last, sizeof(Last), 0x55);
    Ret = DeviceIoControl(Device, IOIS32_CODE_LAST, &Major, sizeof(Major), &Last, sizeof(Last), &Returned, NULL);
    ok(Ret, "DeviceIoControl failed with %lu\n", GetLastError());
    if (!Ret) return;
    trace("%-34s : seen=%lu irp=%lu mode=%lu kernel-iosb=%lu\n",
          Name, Last.Seen, Last.ForIrp, Last.RequestorMode, Last.KernelIosb);
    ok_eq_ulong(Last.Seen, 1);
    ok_eq_ulong(Last.ForIrp, Expected ? 1 : 0);
    ok_eq_ulong(Last.RequestorMode, UserMode);
}

/* Requests the I/O manager sends with an IO_STATUS_BLOCK of its own on a synchronous handle: the answer
 * must not depend on it */
static
VOID
TestKernelIosbRequests(VOID)
{
    HANDLE Device = OpenDevice(FALSE);
    IO_STATUS_BLOCK IoStatus;
    FILE_BASIC_INFORMATION Basic;
    FILE_FS_SIZE_INFORMATION Size;
    NTSTATUS Status;

    if (Device == INVALID_HANDLE_VALUE) return;
    CheckLast(Device, IOIS32_MJ_CREATE, "create");

    RtlZeroMemory(&Basic, sizeof(Basic));
    Status = NtQueryInformationFile(Device, &IoStatus, &Basic, sizeof(Basic), FileBasicInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckLast(Device, IOIS32_MJ_QUERY_INFORMATION, "query information");

    Status = NtSetInformationFile(Device, &IoStatus, &Basic, sizeof(Basic), FileBasicInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckLast(Device, IOIS32_MJ_SET_INFORMATION, "set information");

    ok(FlushFileBuffers(Device), "FlushFileBuffers failed with %lu\n", GetLastError());
    CheckLast(Device, IOIS32_MJ_FLUSH_BUFFERS, "flush buffers");

    RtlZeroMemory(&Size, sizeof(Size));
    Status = NtQueryVolumeInformationFile(Device, &IoStatus, &Size, sizeof(Size), FileFsSizeInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    CheckLast(Device, IOIS32_MJ_QUERY_VOLUME_INFORMATION, "query volume information");

    ok(UnlockFile(Device, 0, 0, 1, 0), "UnlockFile failed with %lu\n", GetLastError());
    CheckLast(Device, IOIS32_MJ_LOCK_CONTROL, "unlock");

    CloseHandle(Device);
}

/* Every request the device gets from this process, with what IoIs32bitProcess must answer for it */
static
VOID
RunIoIs32Requests(
    _In_ BOOLEAN ExpectedAnswer)
{
    static const ULONG Codes[] = { IOIS32_CODE_SYNC, IOIS32_CODE_PENDING };
    ULONG i;

    Expected = ExpectedAnswer;
    for (i = 0; i < RTL_NUMBER_OF(Codes); i++)
    {
        TestSynchronous(Codes[i]);
        TestSynchronousNt(Codes[i], FALSE);
        TestSynchronousNt(Codes[i], TRUE);
        TestOverlappedEvent(Codes[i]);
        TestApcForm(Codes[i]);
        TestCompletionPort(Codes[i]);
    }
    TestKernelIosbRequests();
}

/* TRUE for a process that runs on the 64-bit kernel as a 32-bit one */
static
BOOLEAN
IsWow64Caller(VOID)
{
    typedef BOOL (WINAPI *PIS_WOW64)(HANDLE, PBOOL);
    PIS_WOW64 pIsWow64Process;
    BOOL Wow64 = FALSE;

    pIsWow64Process = (PIS_WOW64)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    if (pIsWow64Process)
        pIsWow64Process(GetCurrentProcess(), &Wow64);
    return Wow64 != FALSE;
}
