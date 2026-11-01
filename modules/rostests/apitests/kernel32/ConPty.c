/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Pseudoconsole process attachment, output, input, resize and shutdown.
 */

#include "precomp.h"
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef HRESULT (WINAPI *CREATE_PTY)(COORD, HANDLE, HANDLE, DWORD, PVOID *);
typedef HRESULT (WINAPI *RESIZE_PTY)(PVOID, COORD);
typedef VOID (WINAPI *CLOSE_PTY)(PVOID);
typedef BOOL (WINAPI *INITIALIZE_LIST)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *UPDATE_ATTRIBUTE)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR,
                                        PVOID, SIZE_T, PVOID, PSIZE_T);

static CREATE_PTY CreatePty;
static RESIZE_PTY ResizePty;
static CLOSE_PTY ClosePty;
static INITIALIZE_LIST InitializeList;
static UPDATE_ATTRIBUTE UpdateAttribute;

static BOOL
WaitForText(HANDLE Output, PCSTR Expected, DWORD Timeout)
{
    CHAR Text[32768];
    DWORD Start = GetTickCount(), Available, Count, Used = 0;

    Text[0] = 0;
    while (GetTickCount() - Start < Timeout)
    {
        Available = 0;
        if (!PeekNamedPipe(Output, NULL, 0, NULL, &Available, NULL))
            break;
        if (Available)
        {
            if (Available > sizeof(Text) - Used - 1)
                Available = sizeof(Text) - Used - 1;
            if (!Available) return FALSE;
            if (!ReadFile(Output, Text + Used, Available, &Count, NULL))
                break;
            Used += Count;
            Text[Used] = 0;
            if (strstr(Text, Expected)) return TRUE;
        }
        Sleep(10);
    }
    return FALSE;
}

static VOID
CheckSession(BOOL Interactive)
{
    HANDLE InputRead = NULL, InputWrite = NULL, OutputRead = NULL, OutputWrite = NULL;
    STARTUPINFOEXW Startup = {0};
    PROCESS_INFORMATION Process;
    SIZE_T AttributeSize = 0;
    WCHAR Command[MAX_PATH];
    PVOID PseudoConsole = NULL;
    COORD Size = {80, 25};
    DWORD Written;
    BOOL Created;
    HRESULT Status;

    if (!CreatePipe(&InputRead, &InputWrite, NULL, 0) ||
        !CreatePipe(&OutputRead, &OutputWrite, NULL, 0))
    {
        ok(FALSE, "CreatePipe failed: %lu\n", GetLastError());
        goto Cleanup;
    }
    Status = CreatePty(Size, InputRead, OutputWrite, 0, &PseudoConsole);
    ok(Status == S_OK, "CreatePseudoConsole failed: %08lx\n", Status);
    if (Status != S_OK) goto Cleanup;
    CloseHandle(InputRead);
    InputRead = NULL;
    CloseHandle(OutputWrite);
    OutputWrite = NULL;

    ZeroMemory(&Startup, sizeof(Startup));
    Startup.StartupInfo.cb = sizeof(Startup);
    InitializeList(NULL, 1, 0, &AttributeSize);
    Startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, AttributeSize);
    if (!Startup.lpAttributeList) goto Cleanup;
    Created = InitializeList(Startup.lpAttributeList, 1, 0, &AttributeSize) &&
              UpdateAttribute(Startup.lpAttributeList, 0,
                              PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                              PseudoConsole, sizeof(PseudoConsole), NULL, NULL);
    ok(Created, "Pseudoconsole attribute failed: %lu\n", GetLastError());
    if (!Created) goto Cleanup;

    if (Interactive)
        lstrcpyW(Command, L"cmd.exe");
    else
        lstrcpyW(Command, L"cmd.exe /c echo hello");
    ZeroMemory(&Process, sizeof(Process));
    Created = CreateProcessW(NULL, Command, NULL, NULL, FALSE,
                             EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                             &Startup.StartupInfo, &Process);
    ok(Created, "CreateProcessW with pseudoconsole failed: %lu\n", GetLastError());
    if (Created)
    {
        CloseHandle(Process.hThread);
        if (Interactive)
        {
            Created = WriteFile(InputWrite, "echo world\r", 11, &Written, NULL);
            ok(Created && Written == 11, "Input pipe write failed: %lu\n", GetLastError());
            ok(WaitForText(OutputRead, "world", 10000), "No interactive output\n");
            Size.X = 100;
            Size.Y = 30;
            Status = ResizePty(PseudoConsole, Size);
            ok(Status == S_OK, "ResizePseudoConsole failed: %08lx\n", Status);
            ClosePty(PseudoConsole);
            PseudoConsole = NULL;
            ok(WaitForSingleObject(Process.hProcess, 5000) == WAIT_OBJECT_0,
               "Client remained alive after ClosePseudoConsole\n");
        }
        else
        {
            ok(WaitForText(OutputRead, "hello", 10000), "No command output\n");
            ok(WaitForSingleObject(Process.hProcess, 5000) == WAIT_OBJECT_0,
               "Command did not exit\n");
        }
        CloseHandle(Process.hProcess);
    }
Cleanup:
    if (Startup.lpAttributeList) HeapFree(GetProcessHeap(), 0, Startup.lpAttributeList);
    if (PseudoConsole) ClosePty(PseudoConsole);
    if (InputRead) CloseHandle(InputRead);
    if (InputWrite) CloseHandle(InputWrite);
    if (OutputRead) CloseHandle(OutputRead);
    if (OutputWrite) CloseHandle(OutputWrite);
}

/* Mirrors the private layout kernel32 keeps behind an HPCON. */
typedef struct _FAKE_PTY
{
    ULONG Magic;
    HANDLE Process;
    HANDLE Signal;
    HANDLE Console;
    HANDLE Input;
    HANDLE Output;
    DWORD ProcessId;
} FAKE_PTY;

#define FAKE_PTY_MAGIC 0x43545052

static BOOL
SpawnWithPty(PVOID Pty, PCWSTR CommandLine, BOOL InheritHandles, PPROCESS_INFORMATION Process)
{
    STARTUPINFOEXW Startup = {0};
    SIZE_T AttributeSize = 0;
    BOOL Created = FALSE;
    WCHAR Command[MAX_PATH * 2];

    Startup.StartupInfo.cb = sizeof(Startup);
    InitializeList(NULL, 1, 0, &AttributeSize);
    Startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, AttributeSize);
    if (!Startup.lpAttributeList) return FALSE;
    if (InitializeList(Startup.lpAttributeList, 1, 0, &AttributeSize) &&
        UpdateAttribute(Startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                        Pty, sizeof(Pty), NULL, NULL))
    {
        lstrcpyW(Command, CommandLine);
        ZeroMemory(Process, sizeof(*Process));
        Created = CreateProcessW(NULL, Command, NULL, NULL, InheritHandles,
                                 EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                                 &Startup.StartupInfo, Process);
    }
    HeapFree(GetProcessHeap(), 0, Startup.lpAttributeList);
    return Created;
}

static VOID
ExpectForgedRejected(DWORD ProcessId, PCSTR Name)
{
    FAKE_PTY Fake;
    PROCESS_INFORMATION Process;
    HANDLE Self = NULL;
    BOOL Created;
    DWORD Error;

    ZeroMemory(&Fake, sizeof(Fake));
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &Self,
                    SYNCHRONIZE, FALSE, 0);
    Fake.Magic = FAKE_PTY_MAGIC;
    Fake.Process = Self;
    Fake.ProcessId = ProcessId;
    Fake.Console = GetStdHandle(STD_ERROR_HANDLE);
    Fake.Input = GetStdHandle(STD_INPUT_HANDLE);
    Fake.Output = GetStdHandle(STD_OUTPUT_HANDLE);

    SetLastError(0xdeadbeef);
    Created = SpawnWithPty(&Fake, L"cmd.exe /c exit", FALSE, &Process);
    Error = GetLastError();
    ok(!Created, "%s: CreateProcess with a forged pseudoconsole host succeeded\n", Name);
    if (Created)
    {
        TerminateProcess(Process.hProcess, 1);
        CloseHandle(Process.hThread);
        CloseHandle(Process.hProcess);
    }
    else
    {
        ok(Error == ERROR_INVALID_HANDLE, "%s: error %lu, expected ERROR_INVALID_HANDLE\n", Name, Error);
    }
    if (Self) CloseHandle(Self);
}

static BOOL
ReadLineTimeout(HANDLE Pipe, PSTR Line, DWORD Size, DWORD Timeout)
{
    DWORD Start = GetTickCount(), Used = 0, Count, Available;

    while (GetTickCount() - Start < Timeout && Used + 1 < Size)
    {
        Available = 0;
        if (!PeekNamedPipe(Pipe, NULL, 0, NULL, &Available, NULL)) break;
        if (Available)
        {
            if (!ReadFile(Pipe, Line + Used, 1, &Count, NULL) || !Count) break;
            Used += Count;
            if (Line[Used - 1] == '\n')
            {
                Line[Used] = 0;
                return TRUE;
            }
            continue;
        }
        Sleep(10);
    }
    Line[Used] = 0;
    return FALSE;
}

/* A second process owns a real pseudoconsole; its host is not our child. */
static VOID
CheckForgedOtherProcess(PCWSTR ExePath)
{
    SECURITY_ATTRIBUTES Inherit = {sizeof(Inherit), NULL, TRUE};
    HANDLE InRead = NULL, InWrite = NULL, OutRead = NULL, OutWrite = NULL;
    STARTUPINFOW Startup = {0};
    PROCESS_INFORMATION Helper;
    WCHAR Command[MAX_PATH * 2];
    CHAR Line[64];
    DWORD Pid = 0, Written;

    if (!CreatePipe(&InRead, &InWrite, &Inherit, 0) || !CreatePipe(&OutRead, &OutWrite, &Inherit, 0))
    {
        ok(FALSE, "CreatePipe failed: %lu\n", GetLastError());
        return;
    }
    SetHandleInformation(InWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(OutRead, HANDLE_FLAG_INHERIT, 0);
    Startup.cb = sizeof(Startup);
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = InRead;
    Startup.hStdOutput = OutWrite;
    Startup.hStdError = OutWrite;
    StringCchPrintfW(Command, _countof(Command), L"\"%ls\" ConPty helper-pid", ExePath);
    if (!CreateProcessW(NULL, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Helper))
    {
        ok(FALSE, "Cannot start helper: %lu\n", GetLastError());
        goto Done;
    }
    CloseHandle(InRead);
    InRead = NULL;
    CloseHandle(OutWrite);
    OutWrite = NULL;
    if (ReadLineTimeout(OutRead, Line, sizeof(Line), 30000) && sscanf(Line, "PTYHOST %lu", &Pid) == 1)
        ExpectForgedRejected(Pid, "pseudoconsole of another process");
    else
        ok(FALSE, "Helper reported no pseudoconsole host: '%s'\n", Line);
    WriteFile(InWrite, "x", 1, &Written, NULL);
    if (WaitForSingleObject(Helper.hProcess, 20000) == WAIT_TIMEOUT)
        TerminateProcess(Helper.hProcess, 1);
    CloseHandle(Helper.hThread);
    CloseHandle(Helper.hProcess);
Done:
    if (InRead) CloseHandle(InRead);
    if (InWrite) CloseHandle(InWrite);
    if (OutRead) CloseHandle(OutRead);
    if (OutWrite) CloseHandle(OutWrite);
}

static VOID
RunHelperPid(VOID)
{
    HANDLE InRead, InWrite, OutRead, OutWrite;
    COORD Size = {80, 25};
    PVOID Pty = NULL;
    CHAR Line[64], Byte;
    DWORD Written, Count;

    if (!CreatePipe(&InRead, &InWrite, NULL, 0) || !CreatePipe(&OutRead, &OutWrite, NULL, 0)) return;
    if (CreatePty(Size, InRead, OutWrite, 0, &Pty) != S_OK) return;
    StringCchPrintfA(Line, sizeof(Line), "PTYHOST %lu\n", ((FAKE_PTY *)Pty)->ProcessId);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), Line, lstrlenA(Line), &Written, NULL);
    ReadFile(GetStdHandle(STD_INPUT_HANDLE), &Byte, 1, &Count, NULL);
    ClosePty(Pty);
}

static VOID
CheckForgedRequests(VOID)
{
    PROCESS_BASIC_INFORMATION Info;
    WCHAR ExePath[MAX_PATH];

    ExpectForgedRejected(GetCurrentProcessId(), "the caller itself");
    if (NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation,
                                             &Info, sizeof(Info), NULL)) &&
        Info.InheritedFromUniqueProcessId)
        ExpectForgedRejected((DWORD)Info.InheritedFromUniqueProcessId, "the caller's parent");
    GetModuleFileNameW(NULL, ExePath, _countof(ExePath));
    CheckForgedOtherProcess(ExePath);
}

/* A later child created with bInheritHandles=TRUE must not receive the
 * parent-side signal pipe: ClosePseudoConsole then ends conhost at once
 * instead of waiting out the 3 s fallback. */
static VOID
CheckCloseWithInheritingChild(PCWSTR ExePath)
{
    HANDLE InRead, InWrite, OutRead, OutWrite;
    STARTUPINFOW Startup = {0};
    PROCESS_INFORMATION Child;
    WCHAR Command[MAX_PATH * 2];
    COORD Size = {80, 25};
    PVOID Pty = NULL;
    DWORD Flags = 0, Start, Elapsed;

    if (!CreatePipe(&InRead, &InWrite, NULL, 0) || !CreatePipe(&OutRead, &OutWrite, NULL, 0))
    {
        ok(FALSE, "CreatePipe failed\n");
        return;
    }
    if (CreatePty(Size, InRead, OutWrite, 0, &Pty) != S_OK)
    {
        ok(FALSE, "CreatePseudoConsole failed\n");
        return;
    }
    ok(GetHandleInformation(((FAKE_PTY *)Pty)->Signal, &Flags), "GetHandleInformation failed\n");
    ok(!(Flags & HANDLE_FLAG_INHERIT), "Signal handle is inheritable (flags %lx)\n", Flags);

    Startup.cb = sizeof(Startup);
    StringCchPrintfW(Command, _countof(Command), L"\"%ls\" ConPty helper-sleep", ExePath);
    if (!CreateProcessW(NULL, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Child))
    {
        ok(FALSE, "Cannot start sleeping child: %lu\n", GetLastError());
        ClosePty(Pty);
        return;
    }
    Start = GetTickCount();
    ClosePty(Pty);
    Elapsed = GetTickCount() - Start;
    trace("ClosePseudoConsole took %lu ms\n", Elapsed);
    ok(Elapsed < 2000, "ClosePseudoConsole waited %lu ms (a leaked signal handle?)\n", Elapsed);
    TerminateProcess(Child.hProcess, 0);
    CloseHandle(Child.hThread);
    CloseHandle(Child.hProcess);
    CloseHandle(InRead);
    CloseHandle(InWrite);
    CloseHandle(OutRead);
    CloseHandle(OutWrite);
}

START_TEST(ConPty)
{
    HMODULE Module = GetModuleHandleW(L"kernel32.dll");
    CreatePty = (CREATE_PTY)GetProcAddress(Module, "CreatePseudoConsole");
    ResizePty = (RESIZE_PTY)GetProcAddress(Module, "ResizePseudoConsole");
    ClosePty = (CLOSE_PTY)GetProcAddress(Module, "ClosePseudoConsole");
    InitializeList = (INITIALIZE_LIST)GetProcAddress(Module, "InitializeProcThreadAttributeList");
    UpdateAttribute = (UPDATE_ATTRIBUTE)GetProcAddress(Module, "UpdateProcThreadAttribute");
    ok(CreatePty && ResizePty && ClosePty && InitializeList && UpdateAttribute,
       "Pseudoconsole API exports missing\n");
    if (!CreatePty || !ResizePty || !ClosePty || !InitializeList || !UpdateAttribute) return;
    {
        PSTR *argv;
        int argc = winetest_get_mainargs(&argv);
        WCHAR ExePath[MAX_PATH];

        if (argc >= 3 && !strcmp(argv[2], "helper-pid"))
        {
            RunHelperPid();
            return;
        }
        if (argc >= 3 && !strcmp(argv[2], "helper-sleep"))
        {
            Sleep(30000);
            return;
        }
        GetModuleFileNameW(NULL, ExePath, _countof(ExePath));
        CheckSession(FALSE);
        CheckSession(TRUE);
        CheckForgedRequests();
        CheckCloseWithInheritingChild(ExePath);
    }
}
