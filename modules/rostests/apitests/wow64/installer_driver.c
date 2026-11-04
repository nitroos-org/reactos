/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     installer_driver
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Native observer for installer UI and installed-program startup.
 * The capture mode also forwards a helper's stdout/stderr to the harness and
 * serial log, so a stalled installer can be diagnosed without reading its disk. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
ULONG __cdecl DbgPrint(const char *, ...);

static DWORD Target;
static HWND MainWindow;
static ULONG Hash;
static const WCHAR *ExpectedClass;
static struct { DWORD Id; HANDLE Handle; BOOL Exited; } Children[64];
static UINT ChildCount;

static void CaptureOutput(HANDLE Pipe)
{
    CHAR Text[1024];
    DWORD Available, Read;
    while (PeekNamedPipe(Pipe, NULL, 0, NULL, &Available, NULL) && Available)
    {
        if (!ReadFile(Pipe, Text, min(Available, sizeof(Text) - 1), &Read, NULL) || !Read) break;
        Text[Read] = 0;
        printf("%s", Text);
        DbgPrint("INSTALL OUTPUT %s", Text);
    }
}

static BOOL InFamily(DWORD Id)
{
    UINT i;
    if (Id == Target) return TRUE;
    for (i = 0; i < ChildCount; ++i)
        if (Children[i].Id == Id && WaitForSingleObject(Children[i].Handle, 0) == WAIT_TIMEOUT)
            return TRUE;
    return FALSE;
}

static void FindChildren(void)
{
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), Child;
    PROCESSENTRY32W Entry = {sizeof(Entry)};
    UINT i;
    if (Snapshot == INVALID_HANDLE_VALUE) return;
    if (Process32FirstW(Snapshot, &Entry)) do
    {
        for (i = 0; i < ChildCount; ++i)
            if (Children[i].Id == Entry.th32ProcessID) break;
        if (i < ChildCount) continue;
        if (!InFamily(Entry.th32ProcessID) && InFamily(Entry.th32ParentProcessID) && ChildCount < 64)
        {
            Child = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                                FALSE, Entry.th32ProcessID);
            if (Child)
            {
                Children[ChildCount].Id = Entry.th32ProcessID;
                Children[ChildCount++].Handle = Child;
                DbgPrint("INSTALL CHILD pid=%lu parent=%lu name=%S\n",
                         Entry.th32ProcessID, Entry.th32ParentProcessID, Entry.szExeFile);
            }
        }
    } while (Process32NextW(Snapshot, &Entry));
    CloseHandle(Snapshot);
}

static BOOL CALLBACK Observe(HWND Window, LPARAM Dump)
{
    WCHAR Class[128], Text[512];
    DWORD Process;
    unsigned i;
    GetWindowThreadProcessId(Window, &Process);
    if (!IsWindowVisible(Window) || (!Dump && !InFamily(Process))) return TRUE;
    GetClassNameW(Window, Class, 128);
    GetWindowTextW(Window, Text, 512);
    if (!GetParent(Window) && (!ExpectedClass || !wcscmp(Class, ExpectedClass))) MainWindow = Window;
    Hash = Hash * 33 + (ULONG)(ULONG_PTR)Window;
    for (i = 0; Text[i]; ++i) Hash = Hash * 33 + Text[i];
    if (Dump)
        DbgPrint("INSTALL WINDOW %p pid=%lu class=%S text=%S enabled=%u\n",
                 Window, Process, Class, Text, IsWindowEnabled(Window));
    return TRUE;
}

static BOOL CALLBACK ObserveTop(HWND Window, LPARAM Dump)
{
    DWORD Process;
    GetWindowThreadProcessId(Window, &Process);
    if (!InFamily(Process) || !IsWindowVisible(Window)) return TRUE;
    Observe(Window, Dump);
    EnumChildWindows(Window, Observe, Dump);
    return TRUE;
}

static DWORD DebugProcess(PROCESS_INFORMATION *Process)
{
    DEBUG_EVENT Event;
    DWORD Begin = GetTickCount(), Continue;
    while (GetTickCount() - Begin < 60000)
    {
        if (!WaitForDebugEvent(&Event, 1000)) continue;
        Continue = DBG_CONTINUE;
        /* Some compatibility paths also deliver child events. Do not read
         * their addresses through the root handle or mistake their exit for
         * completion of the process under observation. */
        if (Event.dwProcessId != Process->dwProcessId)
        {
            if (Event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && Event.u.CreateProcessInfo.hFile)
                CloseHandle(Event.u.CreateProcessInfo.hFile);
            else if (Event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && Event.u.LoadDll.hFile)
                CloseHandle(Event.u.LoadDll.hFile);
            else if (Event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
                printf("DEBUG CHILD EXIT pid=%lu code=%lx\n", Event.dwProcessId, Event.u.ExitProcess.dwExitCode);
            else if (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                     Event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT &&
                     Event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_SINGLE_STEP)
                Continue = DBG_EXCEPTION_NOT_HANDLED;
            ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, Continue);
            continue;
        }
        if (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            EXCEPTION_RECORD *Record = &Event.u.Exception.ExceptionRecord;
            HANDLE Thread = OpenThread(THREAD_GET_CONTEXT, FALSE, Event.dwThreadId);
            CONTEXT Context = {0};
            Context.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
            printf("DEBUG EXCEPTION pid=%lu code=%lx address=%p first=%lu info=%Ix,%Ix\n",
                   Event.dwProcessId, Record->ExceptionCode, Record->ExceptionAddress, Event.u.Exception.dwFirstChance,
                   Record->ExceptionInformation[0], Record->ExceptionInformation[1]);
            if (Record->ExceptionCode == 0x80000100 && Record->NumberParameters == 2)
            {
                CHAR Name[2][128] = {{0}};
                SIZE_T Read;
                unsigned Field, Byte;
                for (Field = 0; Field < 2; ++Field)
                    for (Byte = 0; Byte < sizeof(Name[Field]) - 1; ++Byte)
                        if (!ReadProcessMemory(Process->hProcess,
                            (PBYTE)(ULONG_PTR)Record->ExceptionInformation[Field] + Byte,
                            &Name[Field][Byte], 1, &Read) || Read != 1 || !Name[Field][Byte]) break;
                printf("DEBUG STUB module=%s function=%s\n", Name[0], Name[1]);
            }
#ifdef _WIN64
            if (Thread && GetThreadContext(Thread, &Context))
                printf("DEBUG CONTEXT tid=%lu cs=%x gs=%x fs=%x ip=%p sp=%p ax=%Ix\n",
                       Event.dwThreadId, Context.SegCs, Context.SegGs, Context.SegFs,
                       (PVOID)Context.Rip, (PVOID)Context.Rsp, Context.Rax);
#else
            if (Thread && GetThreadContext(Thread, &Context))
                printf("DEBUG CONTEXT tid=%lu cs=%x gs=%x fs=%x ip=%p sp=%p ax=%lx\n",
                       Event.dwThreadId, Context.SegCs, Context.SegGs, Context.SegFs,
                       (PVOID)Context.Eip, (PVOID)Context.Esp, Context.Eax);
#endif
            if (Thread) CloseHandle(Thread);
            if (Record->ExceptionCode != EXCEPTION_BREAKPOINT && Record->ExceptionCode != EXCEPTION_SINGLE_STEP &&
                Record->ExceptionCode != 0x406d1388 /* debugger thread-name notification */)
                Continue = DBG_EXCEPTION_NOT_HANDLED;
        }
        else if (Event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            if (Event.u.CreateProcessInfo.hFile) CloseHandle(Event.u.CreateProcessInfo.hFile);
        }
        else if (Event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            if (Event.u.LoadDll.hFile) CloseHandle(Event.u.LoadDll.hFile);
        }
        else if (Event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT &&
                 !Event.u.DebugString.fUnicode)
        {
            CHAR Text[1024];
            SIZE_T Read = 0, Length = min(Event.u.DebugString.nDebugStringLength, sizeof(Text) - 1);
            if (ReadProcessMemory(Process->hProcess, Event.u.DebugString.lpDebugStringData,
                                  Text, Length, &Read))
            {
                Text[Read] = 0;
                printf("DEBUG PRINT %s\n", Text);
            }
        }
        else if (Event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            DWORD Code = Event.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, DBG_CONTINUE);
            printf("DEBUG EXIT code=%lx\n", Code);
            return Code;
        }
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, Continue);
    }
    TerminateProcess(Process->hProcess, 98);
    return 98;
}

int wmain(int argc, WCHAR **argv)
{
    WCHAR Command[4096];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    DWORD Code = 1, Begin, Limit;
    ULONG OldHash = 0;
    BOOL Wow = FALSE, Check, Debug, Capture, Running, RootExited = FALSE;
    SECURITY_ATTRIBUTES Security = {sizeof(Security), NULL, TRUE};
    HANDLE OutputRead = NULL, OutputWrite = NULL;
    UINT Child;
    int i, Executable;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) return 2;
    Check = !wcscmp(argv[1], L"check");
    Debug = !wcscmp(argv[1], L"debug");
    Capture = !wcscmp(argv[1], L"capture");
    if (Check && argc < 4) return 2;
    Executable = Check ? 3 : 2;
    if (Check) ExpectedClass = argv[2];
    _snwprintf(Command, 4096, L"\"%ls\"", argv[Executable]);
    for (i = Executable + 1; i < argc; ++i)
    {
        BOOL Quote = !argv[i][0] || wcspbrk(argv[i], L" \t") != NULL;
        if (wcslen(Command) + wcslen(argv[i]) + 4 >= 4096) return 2;
        /* Some tools parse their option prefixes before removing quotes.
         * Quote paths/values only when their whitespace requires it. */
        wcscat(Command, Quote ? L" \"" : L" ");
        wcscat(Command, argv[i]);
        if (Quote) wcscat(Command, L"\"");
    }
    if (Capture)
    {
        if (!CreatePipe(&OutputRead, &OutputWrite, &Security, 0)) return 1;
        if (!SetHandleInformation(OutputRead, HANDLE_FLAG_INHERIT, 0))
        {
            CloseHandle(OutputRead); CloseHandle(OutputWrite);
            return 1;
        }
        Startup.dwFlags |= STARTF_USESTDHANDLES;
        Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        Startup.hStdOutput = Startup.hStdError = OutputWrite;
    }
    if (!CreateProcessW(argv[Executable], Command, NULL, NULL, Capture,
                        Debug ? DEBUG_ONLY_THIS_PROCESS : 0, NULL, NULL, &Startup, &Process))
    {
        printf("INSTALL START FAILED error=%lu\n", GetLastError());
        if (OutputRead) CloseHandle(OutputRead);
        if (OutputWrite) CloseHandle(OutputWrite);
        return 1;
    }
    if (OutputWrite) CloseHandle(OutputWrite);
    Target = Process.dwProcessId;
    IsWow64Process(Process.hProcess, &Wow);
    printf("INSTALL START pid=%lu wow64=%u path=%ls\n", Target, Wow, argv[Executable]);
    DbgPrint("INSTALL START pid=%lu wow64=%u path=%S\n", Target, Wow, argv[Executable]);
    if (Debug)
    {
        Code = DebugProcess(&Process);
        CloseHandle(Process.hThread);
        CloseHandle(Process.hProcess);
        return Code;
    }
    Begin = GetTickCount(); Limit = Check ? 30000 : 900000;
    while (GetTickCount() - Begin < Limit)
    {
        FindChildren();
        if (Capture) CaptureOutput(OutputRead);
        Running = WaitForSingleObject(Process.hProcess, 500) == WAIT_TIMEOUT;
        if (!Running && !RootExited)
        {
            GetExitCodeProcess(Process.hProcess, &Code);
            DbgPrint("INSTALL ROOT EXIT pid=%lu code=%lu\n", Target, Code);
            RootExited = TRUE;
        }
        for (Child = 0; Child < ChildCount; ++Child)
        {
            if (WaitForSingleObject(Children[Child].Handle, 0) == WAIT_TIMEOUT) Running = TRUE;
            else if (!Children[Child].Exited)
            {
                GetExitCodeProcess(Children[Child].Handle, &Code);
                DbgPrint("INSTALL CHILD EXIT pid=%lu code=%lu\n", Children[Child].Id, Code);
                Children[Child].Exited = TRUE;
            }
        }
        if (!Running) break;
        Hash = 0; MainWindow = NULL;
        EnumWindows(ObserveTop, 0);
        if (Hash != OldHash)
        {
            OldHash = Hash;
            EnumWindows(ObserveTop, 1);
        }
        if (Check && MainWindow && GetTickCount() - Begin >= 10000)
        {
            printf("PROGRAM STARTED pid=%lu hwnd=%p wow64=%u\n", Target, MainWindow, Wow);
            DbgPrint("PROGRAM STARTED pid=%lu hwnd=%p wow64=%u\n", Target, MainWindow, Wow);
            Sleep(5000);
            PostMessageW(MainWindow, WM_CLOSE, 0, 0);
            if (WaitForSingleObject(Process.hProcess, 10000) != WAIT_OBJECT_0)
                TerminateProcess(Process.hProcess, 0);
            for (Child = 0; Child < ChildCount; ++Child) CloseHandle(Children[Child].Handle);
            CloseHandle(Process.hThread); CloseHandle(Process.hProcess);
            return 0;
        }
    }
    GetExitCodeProcess(Process.hProcess, &Code);
    if (Capture) { CaptureOutput(OutputRead); CloseHandle(OutputRead); }
    printf("INSTALL EXIT code=%lu elapsed=%lu\n", Code, GetTickCount() - Begin);
    DbgPrint("INSTALL EXIT code=%lu elapsed=%lu\n", Code, GetTickCount() - Begin);
    if (Code == STILL_ACTIVE) TerminateProcess(Process.hProcess, 98);
    for (Child = 0; Child < ChildCount; ++Child)
    {
        if (GetTickCount() - Begin >= Limit) TerminateProcess(Children[Child].Handle, 98);
        CloseHandle(Children[Child].Handle);
    }
    CloseHandle(Process.hThread); CloseHandle(Process.hProcess);
    return Check || Code == STILL_ACTIVE ? 1 : Code;
}
