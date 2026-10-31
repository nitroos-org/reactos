/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RtlWow64GetProcessMachines
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (build 19045, x64), in a native and in a WoW64 process.
 */

#include "precomp.h"

#include <strsafe.h>

typedef NTSTATUS (NTAPI *PFN_RtlWow64GetProcessMachines)(HANDLE, USHORT *, USHORT *);

#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386 0x014c
#endif
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif

static PFN_RtlWow64GetProcessMachines pRtlWow64GetProcessMachines;

static USHORT GetNativeMachine(void)
{
    SYSTEM_INFO Info;

    GetNativeSystemInfo(&Info);
    switch (Info.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_AMD64: return IMAGE_FILE_MACHINE_AMD64;
        case PROCESSOR_ARCHITECTURE_ARM64: return 0xAA64;
        case PROCESSOR_ARCHITECTURE_ARM: return 0x01c4;
        default: return IMAGE_FILE_MACHINE_I386;
    }
}

static void Check(PCSTR Name, HANDLE Process, USHORT ExpectedProcess, USHORT ExpectedNative)
{
    USHORT ProcessMachine = 0xAAAA, NativeMachine = 0xBBBB;
    NTSTATUS Status;

    Status = pRtlWow64GetProcessMachines(Process, &ProcessMachine, &NativeMachine);
    ok(Status == STATUS_SUCCESS, "%s: status 0x%08lx\n", Name, Status);
    ok(ProcessMachine == ExpectedProcess, "%s: process machine is %04x, expected %04x\n", Name, ProcessMachine, ExpectedProcess);
    ok(NativeMachine == ExpectedNative, "%s: native machine is %04x, expected %04x\n", Name, NativeMachine, ExpectedNative);

    /* the native machine is optional */
    ProcessMachine = 0xAAAA;
    Status = pRtlWow64GetProcessMachines(Process, &ProcessMachine, NULL);
    ok(Status == STATUS_SUCCESS, "%s, no native machine: status 0x%08lx\n", Name, Status);
    ok(ProcessMachine == ExpectedProcess, "%s, no native machine: process machine is %04x, expected %04x\n", Name, ProcessMachine, ExpectedProcess);
}

static void CheckFailure(PCSTR Name, HANDLE Handle, NTSTATUS ExpectedStatus)
{
    USHORT ProcessMachine = 0xAAAA, NativeMachine = 0xBBBB;
    NTSTATUS Status;

    Status = pRtlWow64GetProcessMachines(Handle, &ProcessMachine, &NativeMachine);
    ok(Status == ExpectedStatus, "%s: status 0x%08lx, expected 0x%08lx\n", Name, Status, ExpectedStatus);
    ok(ProcessMachine == 0xAAAA && NativeMachine == 0xBBBB, "%s: the results were written (%04x %04x)\n", Name, ProcessMachine, NativeMachine);
}

static void TestOpenedHandles(DWORD Pid, PCSTR Name, USHORT ExpectedProcess, USHORT ExpectedNative)
{
    CHAR Text[64];
    HANDLE Process;

    /* the limited query right is enough */
    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    ok(Process != NULL, "%s: OpenProcess failed with %lu\n", Name, GetLastError());
    if (Process)
    {
        StringCchPrintfA(Text, ARRAYSIZE(Text), "%s, PROCESS_QUERY_LIMITED_INFORMATION", Name);
        Check(Text, Process, ExpectedProcess, ExpectedNative);
        CloseHandle(Process);
    }

    Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (Process)
    {
        StringCchPrintfA(Text, ARRAYSIZE(Text), "%s, PROCESS_QUERY_INFORMATION", Name);
        Check(Text, Process, ExpectedProcess, ExpectedNative);
        CloseHandle(Process);
    }

    /* any other right is not */
    Process = OpenProcess(PROCESS_VM_READ, FALSE, Pid);
    if (Process)
    {
        StringCchPrintfA(Text, ARRAYSIZE(Text), "%s, PROCESS_VM_READ", Name);
        CheckFailure(Text, Process, STATUS_ACCESS_DENIED);
        CloseHandle(Process);
    }

    Process = OpenProcess(SYNCHRONIZE, FALSE, Pid);
    if (Process)
    {
        StringCchPrintfA(Text, ARRAYSIZE(Text), "%s, SYNCHRONIZE", Name);
        CheckFailure(Text, Process, STATUS_ACCESS_DENIED);
        CloseHandle(Process);
    }
}

static void TestChild(PCSTR Name, PCWSTR Directory, USHORT ExpectedProcess, USHORT ExpectedNative)
{
    WCHAR Path[MAX_PATH], CmdLine[MAX_PATH + 16];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%ls\\cmd.exe", Directory);
    if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
    {
        skip("%s: no %ls\n", Name, Path);
        return;
    }

    StringCchPrintfW(CmdLine, ARRAYSIZE(CmdLine), L"\"%ls\" /c exit", Path);
    if (!CreateProcessW(NULL, CmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        ok(FALSE, "%s: CreateProcess failed with %lu\n", Name, GetLastError());
        return;
    }

    Check(Name, pi.hProcess, ExpectedProcess, ExpectedNative);
    TestOpenedHandles(pi.dwProcessId, Name, ExpectedProcess, ExpectedNative);

    /* a thread is not a process */
    CheckFailure("thread of a child", pi.hThread, STATUS_OBJECT_TYPE_MISMATCH);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

START_TEST(RtlWow64GetProcessMachines)
{
    USHORT Native = GetNativeMachine();
    USHORT Self;
    BOOL Wow64 = FALSE;
    HANDLE Handle;
    WCHAR Directory[MAX_PATH];
    UINT Length;

    pRtlWow64GetProcessMachines = (PFN_RtlWow64GetProcessMachines)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                                                "RtlWow64GetProcessMachines");
    if (!pRtlWow64GetProcessMachines && is_reactos())
    {
        /* ReactOS exports it from ntdll_vista.dll, not from ntdll.dll */
        HMODULE Vista = LoadLibraryW(L"ntdll_vista.dll");

        if (Vista)
        {
            pRtlWow64GetProcessMachines = (PFN_RtlWow64GetProcessMachines)GetProcAddress(Vista,
                                                                                         "RtlWow64GetProcessMachines");
        }
        ok(pRtlWow64GetProcessMachines != NULL, "RtlWow64GetProcessMachines is not exported by ntdll_vista.dll\n");
    }
    if (!pRtlWow64GetProcessMachines)
    {
        skip("RtlWow64GetProcessMachines is not available\n");
        return;
    }

    IsWow64Process(GetCurrentProcess(), &Wow64);
    Self = Wow64 ? IMAGE_FILE_MACHINE_I386 : 0;

    /* this process: the machine it emulates, or 0 for a native one (not the machine it runs as) */
    Check("current process pseudo handle", NtCurrentProcess(), Self, Native);
    TestOpenedHandles(GetCurrentProcessId(), "current process", Self, Native);

    /* NULL is not rejected, it reads as a native process, even in a WoW64 process */
    Check("NULL handle", NULL, 0, Native);

    /* handles that are not a process handle */
    CheckFailure("current thread pseudo handle", NtCurrentThread(), STATUS_OBJECT_TYPE_MISMATCH);
    CheckFailure("thread handle", GetCurrentThread(), STATUS_OBJECT_TYPE_MISMATCH);
    Handle = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(Handle != NULL, "CreateEvent failed with %lu\n", GetLastError());
    if (Handle)
    {
        CheckFailure("event handle", Handle, STATUS_OBJECT_TYPE_MISMATCH);
        CloseHandle(Handle);
    }

    /* bad handles */
    CheckFailure("invalid handle", (HANDLE)(ULONG_PTR)0xdeadbeef, STATUS_INVALID_HANDLE);
    CheckFailure("pseudo handle -3", (HANDLE)(LONG_PTR)-3, STATUS_INVALID_HANDLE);

    /* another process: a native child, and a 32-bit one on a 64-bit system */
    if (!Wow64)
    {
        Length = GetSystemDirectoryW(Directory, ARRAYSIZE(Directory));
        if (Length && Length < ARRAYSIZE(Directory))
            TestChild("native child", Directory, 0, Native);
    }

    if (Native == IMAGE_FILE_MACHINE_AMD64)
    {
        Length = GetSystemWow64DirectoryW(Directory, ARRAYSIZE(Directory));
        if (Length && Length < ARRAYSIZE(Directory))
            TestChild("32-bit child", Directory, IMAGE_FILE_MACHINE_I386, Native);
    }
}
