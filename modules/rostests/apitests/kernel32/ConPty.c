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
static WCHAR TestPath[MAX_PATH];

static VOID
ConsoleSay(PCSTR Text)
{
    DWORD Written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), Text, lstrlenA(Text), &Written, NULL);
}

static BOOL WINAPI
HelperCtrlHandler(DWORD Event)
{
    if (Event != CTRL_C_EVENT) return FALSE;
    ConsoleSay("GOTCTRLC\r\n");
    ExitProcess(0);
    return TRUE;
}

/* Runs inside the pseudoconsole: report the window size, or wait for Ctrl+C. */
static VOID
RunConsoleHelper(PCSTR Mode)
{
    CONSOLE_SCREEN_BUFFER_INFO Info;
    CHAR Text[64];

    if (!strcmp(Mode, "helper-size"))
    {
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &Info))
            StringCchPrintfA(Text, sizeof(Text), "SIZE=%dx%d,BUF=%dx%d\r\n",
                             Info.srWindow.Right - Info.srWindow.Left + 1,
                             Info.srWindow.Bottom - Info.srWindow.Top + 1,
                             Info.dwSize.X, Info.dwSize.Y);
        else
            StringCchPrintfA(Text, sizeof(Text), "SIZE=error%lu\r\n", GetLastError());
        ConsoleSay(Text);
    }
    else
    {
        SetConsoleCtrlHandler(HelperCtrlHandler, TRUE);
        ConsoleSay("READYCTRL\r\n");
        Sleep(30000);
    }
}

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

/* What the terminal sends in CheckVtInput, and the characters the application must read:
 * ESC [ A, Ctrl+Right (a modifier the key events of the host cannot carry), an unknown
 * sequence, Alt+x, F5, Ctrl+A, e-acute in UTF-8, F1, q. */
#define VT_INPUT_BYTES  "\x1b[A" "\x1b[1;5C" "\x1b[99z" "\x1b" "x" "\x1b[15~" "\x01" "\xc3\xa9" "\x1b" "OP" "q"
#define VT_INPUT_CHARS  27
#define VT_INPUT_HEX    "001B005B0041" "001B005B0031003B00350043" "001B005B00390039007A" "001B0078" \
                        "001B005B00310035007E" "0001" "00E9" "001B004F0050" "0071"

/* Runs inside the pseudoconsole: ENABLE_VIRTUAL_TERMINAL_INPUT, then report what arrives. */
static VOID
RunVtInputHelper(VOID)
{
    HANDLE Input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    WCHAR Chars[VT_INPUT_CHARS + 1];
    CHAR Text[16 + 4 * VT_INPUT_CHARS];
    DWORD Count = 0, Read, Used;

    if (Input == INVALID_HANDLE_VALUE || !SetConsoleMode(Input, ENABLE_VIRTUAL_TERMINAL_INPUT))
    {
        ConsoleSay("VTIN=error\r\n");
        return;
    }
    ConsoleSay("READYVT\r\n");
    while (Count < VT_INPUT_CHARS)
    {
        Read = 0;
        if (!ReadConsoleW(Input, Chars + Count, VT_INPUT_CHARS - Count, &Read, NULL) || !Read) break;
        Count += Read;
    }
    StringCchCopyA(Text, sizeof(Text), "VTIN=");
    Used = lstrlenA(Text);
    for (Read = 0; Read < Count; ++Read, Used += 4)
        StringCchPrintfA(Text + Used, sizeof(Text) - Used, "%04X", Chars[Read]);
    StringCchCatA(Text, sizeof(Text), "\r\n");
    ConsoleSay(Text);
}

static VOID
TypeCommand(HANDLE Input, PCSTR Mode)
{
    CHAR Text[MAX_PATH * 2];
    DWORD Written;

    StringCchPrintfA(Text, sizeof(Text), "\"%ls\" ConPty %s\r", TestPath, Mode);
    WriteFile(Input, Text, lstrlenA(Text), &Written, NULL);
}

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
    for (Count = 0; Count < Used; ++Count)
        if ((UCHAR)Text[Count] < 0x20 || (UCHAR)Text[Count] > 0x7e) Text[Count] = '.';
    trace("Waiting for '%s', received %lu bytes, tail: %s\n", Expected, Used, Text + (Used > 700 ? Used - 700 : 0));
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
            TypeCommand(InputWrite, "helper-size");
            ok(WaitForText(OutputRead, "SIZE=80x25,BUF=80x25", 10000), "Initial window size is not 80x25\n");
            Size.X = 100;
            Size.Y = 30;
            Status = ResizePty(PseudoConsole, Size);
            ok(Status == S_OK, "ResizePseudoConsole failed: %08lx\n", Status);
            Sleep(500);
            TypeCommand(InputWrite, "helper-size");
            ok(WaitForText(OutputRead, "SIZE=100x30", 10000), "Window size did not change to 100x30\n");
            /* sshd drives conhost through the signal pipe directly: WORD 8, WORD columns, WORD rows. */
            {
                WORD Frame[3] = {8, 90, 28};
                ok(WriteFile(((FAKE_PTY *)PseudoConsole)->Signal, Frame, sizeof(Frame), &Written, NULL) &&
                   Written == sizeof(Frame), "Raw resize frame write failed\n");
            }
            Sleep(500);
            TypeCommand(InputWrite, "helper-size");
            ok(WaitForText(OutputRead, "SIZE=90x28", 10000), "Raw WORD resize frame (sshd protocol) not applied\n");
            /* A pseudoconsole has no display: its window is not bounded by the monitor
               (a client terminal of 250x70 does not fit any 800x600 console window). */
            Size.X = 250;
            Size.Y = 70;
            Status = ResizePty(PseudoConsole, Size);
            ok(Status == S_OK, "ResizePseudoConsole(250x70) failed: %08lx\n", Status);
            Sleep(500);
            TypeCommand(InputWrite, "helper-size");
            ok(WaitForText(OutputRead, "SIZE=250x70,BUF=250x70", 10000),
               "Window/buffer did not change to 250x70\n");
            /* ENABLE_VIRTUAL_TERMINAL_INPUT: the application gets the bytes the terminal sent,
               not key events that the console would translate back (losing the modifier,
               the unknown sequence and the UTF-8 character). */
            TypeCommand(InputWrite, "helper-vtinput");
            ok(WaitForText(OutputRead, "READYVT", 10000), "VT input helper did not start\n");
            ok(WriteFile(InputWrite, VT_INPUT_BYTES, sizeof(VT_INPUT_BYTES) - 1, &Written, NULL) &&
               Written == sizeof(VT_INPUT_BYTES) - 1, "Input pipe write failed: %lu\n", GetLastError());
            ok(WaitForText(OutputRead, "VTIN=" VT_INPUT_HEX, 10000),
               "ENABLE_VIRTUAL_TERMINAL_INPUT did not deliver the sequences unchanged\n");
            TypeCommand(InputWrite, "helper-ctrlc");
            ok(WaitForText(OutputRead, "READYCTRL", 10000), "Ctrl+C helper did not start\n");
            WriteFile(InputWrite, "\003", 1, &Written, NULL);
            ok(WaitForText(OutputRead, "GOTCTRLC", 10000), "Ctrl+C typed into the pseudoconsole did not reach the client\n");
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

/* Spawns a child naming ProcessId as pseudoconsole host. Returns TRUE if it was created. */
static BOOL
TryForged(DWORD ProcessId, PDWORD ErrorCode)
{
    FAKE_PTY Fake;
    PROCESS_INFORMATION Process;
    HANDLE Self = NULL;
    BOOL Created;

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
    *ErrorCode = GetLastError();
    if (Created)
    {
        TerminateProcess(Process.hProcess, 1);
        CloseHandle(Process.hThread);
        CloseHandle(Process.hProcess);
    }
    if (Self) CloseHandle(Self);
    return Created;
}

static VOID
ExpectForgedRejected(DWORD ProcessId, PCSTR Name)
{
    DWORD Error;
    BOOL Created = TryForged(ProcessId, &Error);

    ok(!Created, "%s: CreateProcess with a forged pseudoconsole host succeeded\n", Name);
    if (!Created)
        ok(Error == ERROR_INVALID_HANDLE, "%s: error %lu, expected ERROR_INVALID_HANDLE\n", Name, Error);
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

/*
 * Process IDs are recycled. A process whose parent has exited still reports the
 * parent's old ID, which can later belong to an unrelated new process. Build
 * exactly that: A starts P (which has a console) and exits; the test then starts
 * processes until one gets A's ID, and that process names P as its pseudoconsole
 * host. P was not created by it, so the attach must still be refused.
 */
static VOID
RunHelperMid(VOID)
{
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    WCHAR Command[MAX_PATH * 2];
    CHAR Line[64];
    DWORD Written;

    StringCchPrintfW(Command, _countof(Command), L"\"%ls\" ConPty helper-sleep", TestPath);
    if (!CreateProcessW(NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                        &Startup, &Process))
        return;
    StringCchPrintfA(Line, sizeof(Line), "MID %lu %lu\n", GetCurrentProcessId(), Process.dwProcessId);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), Line, lstrlenA(Line), &Written, NULL);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
}

static VOID
RunHelperRecycled(DWORD OldParentId, DWORD HostId)
{
    CHAR Line[64];
    DWORD Written, Error;

    if (GetCurrentProcessId() != OldParentId)
        StringCchCopyA(Line, sizeof(Line), "SKIP\n");
    else
        StringCchPrintfA(Line, sizeof(Line), "%s %lu\n",
                         TryForged(HostId, &Error) ? "ACCEPTED" : "REJECTED", Error);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), Line, lstrlenA(Line), &Written, NULL);
}

/* Starts "ConPty Mode Arg1 Arg2" with stdout on a pipe and returns its first line. */
static BOOL
RunHelperForLine(PCWSTR ExePath, PCWSTR Arguments, PSTR Line, DWORD Size, PDWORD ProcessId)
{
    SECURITY_ATTRIBUTES Inherit = {sizeof(Inherit), NULL, TRUE};
    STARTUPINFOW Startup = {0};
    PROCESS_INFORMATION Process;
    WCHAR Command[MAX_PATH * 2];
    HANDLE OutRead = NULL, OutWrite = NULL;
    BOOL Result = FALSE;

    Line[0] = 0;
    if (!CreatePipe(&OutRead, &OutWrite, &Inherit, 0)) return FALSE;
    SetHandleInformation(OutRead, HANDLE_FLAG_INHERIT, 0);
    Startup.cb = sizeof(Startup);
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Startup.hStdOutput = OutWrite;
    Startup.hStdError = OutWrite;
    StringCchPrintfW(Command, _countof(Command), L"\"%ls\" ConPty %ls", ExePath, Arguments);
    if (CreateProcessW(NULL, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Process))
    {
        CloseHandle(OutWrite);
        OutWrite = NULL;
        Result = ReadLineTimeout(OutRead, Line, Size, 30000);
        if (WaitForSingleObject(Process.hProcess, 20000) == WAIT_TIMEOUT)
            TerminateProcess(Process.hProcess, 1);
        if (ProcessId) *ProcessId = Process.dwProcessId;
        CloseHandle(Process.hThread);
        CloseHandle(Process.hProcess);
    }
    if (OutWrite) CloseHandle(OutWrite);
    CloseHandle(OutRead);
    return Result;
}

#define MAX_RECYCLE_TRIES 300
#define MAX_RECYCLE_MS    15000

static VOID
CheckForgedRecycledParent(PCWSTR ExePath)
{
    CHAR Line[64];
    WCHAR Arguments[64];
    DWORD OldParentId = 0, HostId = 0, Pid, Try;
    HANDLE Host;
    BOOL Reached = FALSE;
    DWORD Start;

    if (!RunHelperForLine(ExePath, L"helper-mid", Line, sizeof(Line), NULL) ||
        sscanf(Line, "MID %lu %lu", &OldParentId, &HostId) != 2)
    {
        ok(FALSE, "Helper did not report its child: '%s'\n", Line);
        return;
    }
    StringCchPrintfW(Arguments, _countof(Arguments), L"helper-recycled %lu %lu", OldParentId, HostId);
    /*
     * Best effort: nothing lets a test pick its own process ID, so churn short-lived
     * helpers (bounded by count and time) hoping the old ID is reissued. IDs come
     * round again only after the ID table has used up its fresh entries, which often
     * takes longer than this; then the check is reported as skipped, not passed.
     */
    Start = GetTickCount();
    for (Try = 0; Try < MAX_RECYCLE_TRIES && !Reached && GetTickCount() - Start < MAX_RECYCLE_MS; ++Try)
    {
        if (!RunHelperForLine(ExePath, Arguments, Line, sizeof(Line), &Pid))
        {
            ok(FALSE, "Recycled-ID helper reported nothing\n");
            break;
        }
        if (!strncmp(Line, "SKIP", 4)) continue;
        Reached = TRUE;
        ok(!strncmp(Line, "REJECTED", 8),
           "recycled parent ID: CreateProcess naming a process the caller did not create succeeded: '%s'\n", Line);
        if (sscanf(Line, "REJECTED %lu", &Pid) == 1)
            ok(Pid == ERROR_INVALID_HANDLE, "recycled parent ID: error %lu, expected ERROR_INVALID_HANDLE\n", Pid);
    }
    if (!Reached)
        skip("The old parent ID was not reused within %lu processes\n", Try);
    Host = OpenProcess(PROCESS_TERMINATE, FALSE, HostId);
    if (Host)
    {
        TerminateProcess(Host, 1);
        CloseHandle(Host);
    }
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
    CheckForgedRecycledParent(ExePath);
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

/* A pseudoconsole created larger than any monitor-derived console window. */
static VOID
CheckLargeCreate(PCWSTR ExePath)
{
    HANDLE InRead = NULL, InWrite = NULL, OutRead = NULL, OutWrite = NULL;
    PROCESS_INFORMATION Child;
    WCHAR Command[MAX_PATH * 2];
    COORD Size = {250, 70};
    PVOID Pty = NULL;
    HRESULT Status;

    if (!CreatePipe(&InRead, &InWrite, NULL, 0) || !CreatePipe(&OutRead, &OutWrite, NULL, 0))
    {
        ok(FALSE, "CreatePipe failed\n");
        return;
    }
    Status = CreatePty(Size, InRead, OutWrite, 0, &Pty);
    ok(Status == S_OK, "CreatePseudoConsole(250x70) failed: %08lx\n", Status);
    if (Status == S_OK)
    {
        StringCchPrintfW(Command, _countof(Command), L"\"%ls\" ConPty helper-size", ExePath);
        if (SpawnWithPty(Pty, Command, FALSE, &Child))
        {
            ok(WaitForText(OutRead, "SIZE=250x70,BUF=250x70", 10000),
               "A pseudoconsole created as 250x70 does not report a 250x70 window and buffer\n");
            WaitForSingleObject(Child.hProcess, 5000);
            CloseHandle(Child.hThread);
            CloseHandle(Child.hProcess);
        }
        else
            ok(FALSE, "CreateProcess with the 250x70 pseudoconsole failed: %lu\n", GetLastError());
        ClosePty(Pty);
    }
    CloseHandle(InRead);
    CloseHandle(InWrite);
    CloseHandle(OutRead);
    CloseHandle(OutWrite);
}

/* node-pty (VS Code, conpty.cc): overlapped-capable named pipes, flags RESIZE_QUIRK|WIN32_INPUT_MODE
 * (|INHERIT_CURSOR), NULL standard handles in STARTUPINFOEX, CreateProcessW without inheritance. */
static VOID
CheckNodePtSequence(DWORD Flags)
{
    static const DWORD Sizes[][2] = {{80, 24}, {120, 30}};
    HANDLE PipeIn, PipeOut, ClientIn = INVALID_HANDLE_VALUE, ClientOut = INVALID_HANDLE_VALUE;
    STARTUPINFOEXW Startup = {0};
    PROCESS_INFORMATION Process;
    SIZE_T AttributeSize = 0;
    WCHAR InName[64], OutName[64], Command[MAX_PATH];
    PVOID Pty = NULL;
    COORD Size = {(SHORT)Sizes[0][0], (SHORT)Sizes[0][1]};
    HRESULT Status;
    BOOL Created;

    StringCchPrintfW(InName, _countof(InName), L"\\\\.\\pipe\\conpty-nodepty-in-%lu-%lx", GetCurrentProcessId(), Flags);
    StringCchPrintfW(OutName, _countof(OutName), L"\\\\.\\pipe\\conpty-nodepty-out-%lu-%lx", GetCurrentProcessId(), Flags);
    PipeIn = CreateNamedPipeW(InName, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                              PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 30000, NULL);
    PipeOut = CreateNamedPipeW(OutName, PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 30000, NULL);
    ok(PipeIn != INVALID_HANDLE_VALUE && PipeOut != INVALID_HANDLE_VALUE,
       "CreateNamedPipe failed: %lu\n", GetLastError());
    if (PipeIn == INVALID_HANDLE_VALUE || PipeOut == INVALID_HANDLE_VALUE) goto Cleanup;
    ClientIn = CreateFileW(InName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ClientOut = CreateFileW(OutName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(ClientIn != INVALID_HANDLE_VALUE && ClientOut != INVALID_HANDLE_VALUE,
       "Opening the pipe client ends failed: %lu\n", GetLastError());
    if (ClientIn == INVALID_HANDLE_VALUE || ClientOut == INVALID_HANDLE_VALUE) goto Cleanup;

    Status = CreatePty(Size, PipeIn, PipeOut, Flags, &Pty);
    ok(Status == S_OK, "CreatePseudoConsole(flags %lx) failed: %08lx\n", Flags, Status);
    if (Status != S_OK) goto Cleanup;
    CloseHandle(PipeIn);
    PipeIn = INVALID_HANDLE_VALUE;
    CloseHandle(PipeOut);
    PipeOut = INVALID_HANDLE_VALUE;

    Startup.StartupInfo.cb = sizeof(Startup);
    Startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    InitializeList(NULL, 1, 0, &AttributeSize);
    Startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, AttributeSize);
    if (!Startup.lpAttributeList) goto Cleanup;
    Created = InitializeList(Startup.lpAttributeList, 1, 0, &AttributeSize) &&
              UpdateAttribute(Startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                              Pty, sizeof(Pty), NULL, NULL);
    ok(Created, "Pseudoconsole attribute failed: %lu\n", GetLastError());
    if (Created)
    {
        lstrcpyW(Command, L"cmd.exe");
        ZeroMemory(&Process, sizeof(Process));
        Created = CreateProcessW(NULL, Command, NULL, NULL, FALSE,
                                 EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                                 NULL, NULL, &Startup.StartupInfo, &Process);
        ok(Created, "CreateProcessW (node-pty style) failed: %lu\n", GetLastError());
        if (Created)
        {
            COORD NewSize = {(SHORT)Sizes[1][0], (SHORT)Sizes[1][1]};
            DWORD Written;
            ok(WriteFile(ClientIn, "echo hel^lo\r\n", 13, &Written, NULL) && Written == 13,
               "Input pipe write failed: %lu\n", GetLastError());
            ok(WaitForText(ClientOut, "hello", 10000), "No command output through the named pipe\n");
            Status = ResizePty(Pty, NewSize);
            ok(Status == S_OK, "ResizePseudoConsole failed: %08lx\n", Status);
            ok(WriteFile(ClientIn, "exit\r\n", 6, &Written, NULL) && Written == 6,
               "Input pipe write failed: %lu\n", GetLastError());
            ok(WaitForSingleObject(Process.hProcess, 5000) == WAIT_OBJECT_0, "Child did not exit\n");
            CloseHandle(Process.hThread);
            CloseHandle(Process.hProcess);
        }
    }
    HeapFree(GetProcessHeap(), 0, Startup.lpAttributeList);
    ClosePty(Pty);
    Pty = NULL;

Cleanup:
    if (Pty) ClosePty(Pty);
    if (PipeIn != INVALID_HANDLE_VALUE && PipeIn) CloseHandle(PipeIn);
    if (PipeOut != INVALID_HANDLE_VALUE && PipeOut) CloseHandle(PipeOut);
    if (ClientIn != INVALID_HANDLE_VALUE) CloseHandle(ClientIn);
    if (ClientOut != INVALID_HANDLE_VALUE) CloseHandle(ClientOut);
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
        if (argc >= 3 && (!strcmp(argv[2], "helper-size") || !strcmp(argv[2], "helper-ctrlc")))
        {
            RunConsoleHelper(argv[2]);
            return;
        }
        if (argc >= 3 && !strcmp(argv[2], "helper-vtinput"))
        {
            RunVtInputHelper();
            return;
        }
        if (argc >= 3 && !strcmp(argv[2], "helper-mid"))
        {
            GetModuleFileNameW(NULL, TestPath, _countof(TestPath));
            RunHelperMid();
            return;
        }
        if (argc >= 5 && !strcmp(argv[2], "helper-recycled"))
        {
            RunHelperRecycled(strtoul(argv[3], NULL, 10), strtoul(argv[4], NULL, 10));
            return;
        }
        if (argc >= 3 && !strcmp(argv[2], "helper-sleep"))
        {
            Sleep(30000);
            return;
        }
        GetModuleFileNameW(NULL, ExePath, _countof(ExePath));
        lstrcpyW(TestPath, ExePath);
        CheckSession(FALSE);
        CheckSession(TRUE);
        CheckForgedRequests();
        CheckCloseWithInheritingChild(ExePath);
        CheckLargeCreate(ExePath);
        CheckNodePtSequence(0x6);   /* RESIZE_QUIRK | WIN32_INPUT_MODE */
        CheckNodePtSequence(0x7);   /* ... | INHERIT_CURSOR */
        CheckNodePtSequence(0x8);   /* PASSTHROUGH (Windows 11) */
    }
}
