/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Test the debug events a user-mode debugger receives, under WoW64 as well
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * The parent debugs a copy of itself. "catch": the child, created with
 * DEBUG_ONLY_THIS_PROCESS, starts a thread, prints a debug string, raises a
 * software exception with two parameters, then writes to address 0x1234; the
 * parent terminates it at the first-chance access violation. "attach": the
 * child waits on an event, the parent attaches with DebugActiveProcess, waits
 * for the break-in, detaches with DebugActiveProcessStop and the child exits on
 * its own. Run as a 32-bit program on x64 this tests the WoW64 debug services:
 * the events must be what Windows 10 gives a 32-bit debugger of a 32-bit
 * debuggee (one initial breakpoint, STATUS_BREAKPOINT, 32-bit modules, x86
 * thread contexts).
 *
 * "exit": the child, created with DEBUG_ONLY_THIS_PROCESS, prints a debug
 * string and ends with its own exit code. The debugger continues every event
 * but the exceptions it does not know with DBG_CONTINUE. The events are
 * CREATE_PROCESS, LOAD_DLL, the initial breakpoint, the debug string and
 * EXIT_PROCESS with the child's exit code: a debug print exception of a layer
 * the debugger does not see (the native part of a WoW64 child) must not end
 * the child with 0x40010006.
 */

#define CHILD_EXIT_THREAD 0x77
#define CHILD_EXIT_WAIT   0x55
#define CHILD_EXIT_CODE   0x4b
#define EXIT_MAX_EVENTS   20000
#define CHILD_EXCEPTION   0xE0000001
#define FAULT_ADDRESS     0x1234
#define MAX_EVENTS        400
#define EVENT_TIMEOUT     20000

static const char DebugString[] = "debugapi-ods";

static DWORD WINAPI ChildThread(LPVOID Parameter)
{
    (void)Parameter;
    return CHILD_EXIT_THREAD;
}

static DECLSPEC_NOINLINE int ChildFault(void)
{
    ULONG_PTR Info[2] = { 0x11111111, 0x22222222 };
    HANDLE Thread = CreateThread(NULL, 0, ChildThread, NULL, 0, NULL);
    if (Thread)
    {
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    /* A DLL loaded after start-up: its LOAD_DLL file handle is made from the section, not by name */
    LoadLibraryW(L"version.dll");
    OutputDebugStringA(DebugString);
    RaiseException(CHILD_EXCEPTION, 0, 2, Info);
    *(volatile int *)FAULT_ADDRESS = 1;
    return 0x66;
}

static BOOL IsWow64;
static HANDLE DebuggeeProcess;
static ULONG_PTR DebuggeeBase;
static struct { DWORD Id; HANDLE Handle; ULONG_PTR Teb, Start; } Threads[64];
static ULONG ThreadCount;

/* The child is this executable: an address of this process at the same offset from the image base */
static ULONG_PTR ChildAddress(PVOID Address)
{
    return (ULONG_PTR)Address - (ULONG_PTR)GetModuleHandleW(NULL) + DebuggeeBase;
}

static void AddThread(DWORD Id, HANDLE Handle, PVOID Teb, PVOID Start)
{
    if (ThreadCount < _countof(Threads))
    {
        Threads[ThreadCount].Id = Id;
        Threads[ThreadCount].Handle = Handle;
        Threads[ThreadCount].Teb = (ULONG_PTR)Teb;
        Threads[ThreadCount].Start = (ULONG_PTR)Start;
        ThreadCount++;
    }
}

static int FindThread(DWORD Id)
{
    ULONG i;
    for (i = 0; i < ThreadCount; i++)
        if (Threads[i].Id == Id) return (int)i;
    return -1;
}

/* NT_TIB.Self of a debuggee TEB is the TEB itself, for the TEB of the debugger's own bitness */
static void CheckTeb(ULONG_PTR Teb, const char *What)
{
    ULONG_PTR Self = 0;
    SIZE_T Read = 0;
    ok(Teb != 0, "%s: no TEB\n", What);
    if (!Teb) return;
    ok(ReadProcessMemory(DebuggeeProcess, (PVOID)(Teb + FIELD_OFFSET(NT_TIB, Self)), &Self, sizeof(Self), &Read),
       "%s: cannot read the TEB at %p: %lu\n", What, (PVOID)Teb, GetLastError());
    ok(Self == Teb, "%s: TEB %p, NtTib.Self %p\n", What, (PVOID)Teb, (PVOID)Self);
}

/* GetThreadContext of a stopped debuggee thread: the context of the debugger's bitness */
static BOOL GetPc(DWORD ThreadId, ULONG_PTR *Pc, const char *What)
{
    CONTEXT Context;
    int i = FindThread(ThreadId);
    ok(i >= 0, "%s: no handle for thread %lu\n", What, ThreadId);
    if (i < 0) return FALSE;
    RtlZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(Threads[i].Handle, &Context))
    {
        ok(0, "%s: GetThreadContext failed: %lu\n", What, GetLastError());
        return FALSE;
    }
#ifdef _M_IX86
    *Pc = Context.Eip;
    if (IsWow64) ok(Context.SegCs == 0x23, "%s: SegCs %lx\n", What, Context.SegCs);
#else
    *Pc = (ULONG_PTR)Context.Rip;
    ok(Context.SegCs == 0x33, "%s: SegCs %x\n", What, Context.SegCs);
#endif
    return TRUE;
}

static BOOL ReadImageName(PVOID NamePointer, WCHAR *Name, SIZE_T Count)
{
    ULONG_PTR Address = 0;
    SIZE_T Read = 0;
    Name[0] = 0;
    if (!NamePointer) return FALSE;
    if (!ReadProcessMemory(DebuggeeProcess, NamePointer, &Address, sizeof(Address), &Read) || !Address)
        return FALSE;
    RtlZeroMemory(Name, Count * sizeof(WCHAR));
    if (!ReadProcessMemory(DebuggeeProcess, (PVOID)Address, Name, (Count - 1) * sizeof(WCHAR), &Read) && !Read)
        return FALSE;
    Name[Count - 1] = 0;
    return TRUE;
}

static BOOL EndsWith(const WCHAR *String, const WCHAR *Suffix)
{
    SIZE_T Length = wcslen(String), SuffixLength = wcslen(Suffix);
    return Length >= SuffixLength && !_wcsicmp(String + Length - SuffixLength, Suffix);
}

static DWORD FinalPath(HANDLE File, WCHAR *Path, DWORD Count)
{
    typedef DWORD (WINAPI *PGETFINALPATH)(HANDLE, LPWSTR, DWORD, DWORD);
    PGETFINALPATH Get = (PGETFINALPATH)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFinalPathNameByHandleW");

    SetLastError(0xdeadbeef);
    return Get ? Get(File, Path, Count, 0 /* VOLUME_NAME_DOS */) : 0;
}

static void CheckCreateProcess(const DEBUG_EVENT *Event, BOOL Attach)
{
    const CREATE_PROCESS_DEBUG_INFO *Info = &Event->u.CreateProcessInfo;
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    SIZE_T Read;

    DebuggeeProcess = Info->hProcess;
    DebuggeeBase = (ULONG_PTR)Info->lpBaseOfImage;
    ok(Info->hProcess != NULL, "no process handle\n");
    ok(Info->hThread != NULL, "no thread handle\n");
    ok(Info->hFile != NULL, "no file handle\n");
    ok(Info->lpThreadLocalBase != NULL, "no TEB\n");
    AddThread(Event->dwThreadId, Info->hThread, Info->lpThreadLocalBase, NULL);
    ok(ReadProcessMemory(Info->hProcess, Info->lpBaseOfImage, &Dos, sizeof(Dos), &Read) && Dos.e_magic == IMAGE_DOS_SIGNATURE,
       "no image at %p\n", Info->lpBaseOfImage);
    if (ReadProcessMemory(Info->hProcess, (PUCHAR)Info->lpBaseOfImage + Dos.e_lfanew, &Nt, sizeof(Nt), &Read))
    {
        ok(Nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC, "image magic %x\n", Nt.OptionalHeader.Magic);
        /* Windows reports the entry point of the image for a new process, nothing for one it attaches to */
        if (!Attach)
            ok((ULONG_PTR)Info->lpStartAddress == DebuggeeBase + Nt.OptionalHeader.AddressOfEntryPoint,
               "start %p, entry %p\n", Info->lpStartAddress, (PVOID)(DebuggeeBase + Nt.OptionalHeader.AddressOfEntryPoint));
    }
    else ok(0, "cannot read the NT headers: %lu\n", GetLastError());
    if (Info->hFile)
    {
        WCHAR Path[MAX_PATH + 8];
        DWORD Length = FinalPath(Info->hFile, Path, _countof(Path));
        ok(Length != 0 && Length < _countof(Path) && EndsWith(Path, L".exe"),
           "image file: length %lu, '%ls', error %lu\n", Length, Path, GetLastError());
    }
    if (Info->hFile) CloseHandle(Info->hFile);
}

/* The file of a LOAD_DLL event is a handle to the DLL's file: Windows answers GetFinalPathNameByHandle for it */
static BOOL CheckLoadDllFile(const LOAD_DLL_DEBUG_INFO *Info, const WCHAR *Suffix)
{
    typedef DWORD (WINAPI *PGETFINALPATH)(HANDLE, LPWSTR, DWORD, DWORD);
    PGETFINALPATH GetFinalPathNameByHandleW =
        (PGETFINALPATH)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFinalPathNameByHandleW");
    WCHAR Path[MAX_PATH + 8];
    DWORD Length;

    if (!GetFinalPathNameByHandleW)
    {
        skip("GetFinalPathNameByHandleW is not available\n");
        return TRUE;
    }
    ok(Info->hFile != NULL, "no file handle for %ls\n", Suffix);
    if (!Info->hFile)
        return FALSE;

    SetLastError(0xdeadbeef);
    Length = GetFinalPathNameByHandleW(Info->hFile, Path, _countof(Path), 0 /* VOLUME_NAME_DOS */);
    ok(Length != 0 && Length < _countof(Path), "DOS: length %lu, error %lu\n", Length, GetLastError());
    if (Length && Length < _countof(Path))
        ok(!wcsncmp(Path, L"\\\\?\\", 4) && EndsWith(Path, Suffix), "DOS name '%ls', expected ...%ls\n", Path, Suffix);

    /* The handle reads the DLL file: a debugger reads the image headers and symbols from it */
    {
        UCHAR Magic[2] = { 0, 0 };
        DWORD Read = 0;

        SetFilePointer(Info->hFile, 0, NULL, FILE_BEGIN);
        ok(ReadFile(Info->hFile, Magic, sizeof(Magic), &Read, NULL) && Read == 2 && Magic[0] == 'M' && Magic[1] == 'Z',
           "ReadFile: %lu bytes %02x%02x, error %lu\n", Read, Magic[0], Magic[1], GetLastError());
    }

    /* Every flag combination answers what it does for a handle opened by name to the same file */
    if (Length && Length < _countof(Path))
    {
        static const DWORD FlagSets[] = { 0, 1, 2, 4, 8, 9, 10, 12 }; /* VOLUME_NAME_*, FILE_NAME_OPENED (8) */
        HANDLE Control = CreateFileW(Path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                     OPEN_EXISTING, 0, NULL);
        ULONG i;

        ok(Control != INVALID_HANDLE_VALUE, "cannot open '%ls': %lu\n", Path, GetLastError());
        for (i = 0; Control != INVALID_HANDLE_VALUE && i < _countof(FlagSets); i++)
        {
            WCHAR Expected[MAX_PATH + 8], Actual[MAX_PATH + 8];
            DWORD ExpectedLength, ActualLength;

            Expected[0] = Actual[0] = 0;
            ExpectedLength = GetFinalPathNameByHandleW(Control, Expected, _countof(Expected), FlagSets[i]);
            ActualLength = GetFinalPathNameByHandleW(Info->hFile, Actual, _countof(Actual), FlagSets[i]);
            ok(ActualLength == ExpectedLength, "flags %lx: length %lu, expected %lu (error %lu)\n",
               FlagSets[i], ActualLength, ExpectedLength, GetLastError());
            ok(!wcscmp(Actual, Expected), "flags %lx: '%ls', expected '%ls'\n", FlagSets[i], Actual, Expected);
        }
        if (Control != INVALID_HANDLE_VALUE) CloseHandle(Control);
    }

    SetLastError(0xdeadbeef);
    Length = GetFinalPathNameByHandleW(Info->hFile, Path, _countof(Path), 0x2 /* VOLUME_NAME_NT */);
    ok(Length != 0 && Length < _countof(Path), "NT: length %lu, error %lu\n", Length, GetLastError());
    if (Length && Length < _countof(Path))
        ok(!_wcsnicmp(Path, L"\\Device\\", 8) && EndsWith(Path, Suffix), "NT name '%ls', expected ...%ls\n", Path, Suffix);
    return TRUE;
}

static void TestCatch(const WCHAR *FileName)
{
    WCHAR CommandLine[MAX_PATH + 64], Name[MAX_PATH];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DEBUG_EVENT Event;
    ULONG_PTR Kernel32 = (ULONG_PTR)GetModuleHandleW(L"kernel32.dll");
    ULONG_PTR Ntdll = (ULONG_PTR)GetModuleHandleW(L"ntdll.dll");
    ULONG Events, Breakpoints = 0, NtdllLoads = 0, Kernel32Loads = 0, Strings = 0, Raised = 0, Faults = 0, VersionLoads = 0;
    ULONG ThreadCreates = 0, ThreadExits = 0;
    BOOL Exited = FALSE, CreateSeen = FALSE;
    ULONG_PTR Pc;

    ThreadCount = 0;
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" DebugApi fault", FileName);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    for (Events = 0; Events < MAX_EVENTS && !Exited; Events++)
    {
        DWORD Continue = DBG_CONTINUE;
        if (!WaitForDebugEvent(&Event, EVENT_TIMEOUT))
        {
            ok(0, "WaitForDebugEvent failed after %lu events: %lu\n", Events, GetLastError());
            break;
        }
        ok(Event.dwProcessId == ProcessInfo.dwProcessId, "event %lu of process %lu\n", Events, Event.dwProcessId);
        if (!Events)
            ok(Event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT, "first event %lu\n", Event.dwDebugEventCode);
        switch (Event.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            ok(!CreateSeen, "second CREATE_PROCESS\n");
            CreateSeen = TRUE;
            CheckCreateProcess(&Event, FALSE);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            ThreadCreates++;
            AddThread(Event.dwThreadId, Event.u.CreateThread.hThread, Event.u.CreateThread.lpThreadLocalBase,
                      Event.u.CreateThread.lpStartAddress);
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            if (Event.u.ExitThread.dwExitCode == CHILD_EXIT_THREAD)
            {
                int i = FindThread(Event.dwThreadId);
                ThreadExits++;
                ok(i > 0, "ChildThread %lu exits without a CREATE_THREAD\n", Event.dwThreadId);
                if (i <= 0) break;
                CheckTeb(Threads[i].Teb, "ChildThread");
                /* Windows reports the thread routine (the Win32 start address); native ReactOS reports where
                 * the thread starts (BaseThreadStartupThunk), its WoW64 layer the routine */
                todo_if(is_reactos() && !IsWow64)
                ok(Threads[i].Start == ChildAddress(ChildThread), "ChildThread start %p, expected %p\n",
                   (PVOID)Threads[i].Start, (PVOID)ChildAddress(ChildThread));
            }
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if ((ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Ntdll) NtdllLoads++;
            if ((ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Kernel32)
            {
                Kernel32Loads++;
                ok(ReadImageName(Event.u.LoadDll.lpImageName, Name, _countof(Name)) && EndsWith(Name, L"\\kernel32.dll"),
                   "kernel32 load: name pointer %p, name '%ls'\n", Event.u.LoadDll.lpImageName, Name);
            }
            if ((ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Kernel32 || (ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Ntdll)
                CheckLoadDllFile(&Event.u.LoadDll,
                                 (ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Ntdll ? L"\\ntdll.dll" : L"\\kernel32.dll");
            else if (Event.u.LoadDll.hFile)
            {
                /* Any other module (the one the child loads at run time): the file handle names a .dll file */
                WCHAR Path[MAX_PATH + 8];
                DWORD Length = FinalPath(Event.u.LoadDll.hFile, Path, _countof(Path));
                ok(Length != 0 && Length < _countof(Path), "DLL at %p: length %lu, error %lu\n",
                   Event.u.LoadDll.lpBaseOfDll, Length, GetLastError());
                if (Length && Length < _countof(Path) && EndsWith(Path, L"\\version.dll"))
                    VersionLoads++;
            }
            if (Event.u.LoadDll.hFile) CloseHandle(Event.u.LoadDll.hFile);
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
        {
            char String[64] = { 0 };
            SIZE_T Read = 0;
            Strings++;
            ok(Event.u.DebugString.nDebugStringLength == sizeof(DebugString),
               "debug string length %u\n", Event.u.DebugString.nDebugStringLength);
            ok(!Event.u.DebugString.fUnicode, "debug string unicode %u\n", Event.u.DebugString.fUnicode);
            ReadProcessMemory(DebuggeeProcess, Event.u.DebugString.lpDebugStringData, String,
                              min(sizeof(String) - 1, Event.u.DebugString.nDebugStringLength), &Read);
            ok(!strcmp(String, DebugString), "debug string '%s'\n", String);
            break;
        }
        case EXCEPTION_DEBUG_EVENT:
        {
            const EXCEPTION_RECORD *Record = &Event.u.Exception.ExceptionRecord;
            ULONG_PTR Address = (ULONG_PTR)Record->ExceptionAddress;
            ok(Record->ExceptionCode != (DWORD)STATUS_WX86_BREAKPOINT, "STATUS_WX86_BREAKPOINT at %p\n", Record->ExceptionAddress);
            if (Record->ExceptionCode == (DWORD)STATUS_BREAKPOINT)
            {
                Breakpoints++;
                ok(Event.u.Exception.dwFirstChance, "breakpoint not first chance\n");
                /* The exception address is the INT 3, the thread context is already after it */
                if (GetPc(Event.dwThreadId, &Pc, "breakpoint"))
                {
                    ok(Pc == Address + 1, "breakpoint at %p, pc %p\n", Record->ExceptionAddress, (PVOID)Pc);
                }
                /* The initial thread runs guest code by now */
                if (Breakpoints == 1 && ThreadCount)
                    CheckTeb(Threads[0].Teb, "initial thread");
            }
            else if (Record->ExceptionCode == CHILD_EXCEPTION)
            {
                Raised++;
                ok(Event.u.Exception.dwFirstChance, "raised exception not first chance\n");
                ok(Record->ExceptionFlags == 0, "flags %lx\n", Record->ExceptionFlags);
                ok(Record->ExceptionRecord == NULL, "nested record %p\n", Record->ExceptionRecord);
                ok(Record->NumberParameters == 2, "%lu parameters\n", Record->NumberParameters);
                ok(Record->ExceptionInformation[0] == 0x11111111 && Record->ExceptionInformation[1] == 0x22222222,
                   "parameters %p %p\n", (PVOID)Record->ExceptionInformation[0], (PVOID)Record->ExceptionInformation[1]);
                if (GetPc(Event.dwThreadId, &Pc, "raised exception"))
                    ok(Pc == Address, "raised at %p, pc %p\n", Record->ExceptionAddress, (PVOID)Pc);
            }
            else if (Record->ExceptionCode == (DWORD)STATUS_ACCESS_VIOLATION && Event.u.Exception.dwFirstChance)
            {
                Faults++;
                ok(Record->NumberParameters == 2, "%lu parameters\n", Record->NumberParameters);
                ok(Record->ExceptionInformation[0] == 1 && Record->ExceptionInformation[1] == FAULT_ADDRESS,
                   "parameters %p %p\n", (PVOID)Record->ExceptionInformation[0], (PVOID)Record->ExceptionInformation[1]);
                ok(Address >= ChildAddress(ChildFault) && Address < ChildAddress(ChildFault) + 0x400,
                   "fault at %p, ChildFault at %p\n", Record->ExceptionAddress, (PVOID)ChildAddress(ChildFault));
                if (GetPc(Event.dwThreadId, &Pc, "access violation"))
                    ok(Pc == Address, "fault at %p, pc %p\n", Record->ExceptionAddress, (PVOID)Pc);
                TerminateProcess(ProcessInfo.hProcess, STATUS_ACCESS_VIOLATION);
            }
            else
            {
                trace("exception %08lx at %p, first chance %lu\n", Record->ExceptionCode, Record->ExceptionAddress,
                      Event.u.Exception.dwFirstChance);
                Continue = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            ok(Event.u.ExitProcess.dwExitCode == (DWORD)STATUS_ACCESS_VIOLATION, "exit code %lx\n", Event.u.ExitProcess.dwExitCode);
            Exited = TRUE;
            break;
        default:
            break;
        }
        ok(ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, Continue), "ContinueDebugEvent failed: %lu\n",
           GetLastError());
    }
    ok(Exited, "no EXIT_PROCESS after %lu events\n", Events);
    ok(Breakpoints == 1, "%lu initial breakpoints\n", Breakpoints);
    ok(NtdllLoads == 1, "%lu ntdll loads\n", NtdllLoads);
    ok(Kernel32Loads == 1, "%lu kernel32 loads\n", Kernel32Loads);
    ok(VersionLoads == 1, "%lu version.dll loads with a file handle that names it\n", VersionLoads);
    ok(ThreadCreates >= 1, "%lu thread starts\n", ThreadCreates);
    ok(ThreadExits == 1, "%lu ChildThread exits\n", ThreadExits);
    ok(Strings == 1, "%lu debug strings\n", Strings);
    ok(Raised == 1, "%lu raised exceptions\n", Raised);
    ok(Faults == 1, "%lu access violations\n", Faults);
    if (!Exited) TerminateProcess(ProcessInfo.hProcess, 1);
    ok(WaitForSingleObject(ProcessInfo.hProcess, 10000) == WAIT_OBJECT_0, "child did not end\n");
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

static void TestExit(const WCHAR *FileName)
{
    WCHAR CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DEBUG_EVENT Event;
    ULONG_PTR Ntdll = (ULONG_PTR)GetModuleHandleW(L"ntdll.dll");
    ULONG Events, Creates = 0, Loads = 0, NtdllLoads = 0, Breakpoints = 0, Strings = 0, Others = 0;
    ULONG ExitCode = 0, Exits = 0;
    BOOL Exited = FALSE;

    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" DebugApi exit", FileName);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    for (Events = 0; Events < EXIT_MAX_EVENTS && !Exited; Events++)
    {
        DWORD Continue = DBG_CONTINUE;
        if (!WaitForDebugEvent(&Event, EVENT_TIMEOUT))
        {
            ok(0, "WaitForDebugEvent failed after %lu events: %lu\n", Events, GetLastError());
            break;
        }
        switch (Event.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            Creates++;
            if (Event.u.CreateProcessInfo.hFile) CloseHandle(Event.u.CreateProcessInfo.hFile);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            Loads++;
            if ((ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Ntdll) NtdllLoads++;
            if (Event.u.LoadDll.hFile) CloseHandle(Event.u.LoadDll.hFile);
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
        {
            /* Other strings are the child's modules' own (debug builds, the native layer of a native
             * debugger's view); only the child's string counts */
            char String[64] = { 0 };
            SIZE_T Read = 0;
            ReadProcessMemory(ProcessInfo.hProcess, Event.u.DebugString.lpDebugStringData, String,
                              min(sizeof(String) - 1, Event.u.DebugString.nDebugStringLength), &Read);
            if (!strcmp(String, DebugString)) Strings++;
            break;
        }
        case EXCEPTION_DEBUG_EVENT:
            if (Event.u.Exception.ExceptionRecord.ExceptionCode == (DWORD)STATUS_BREAKPOINT)
            {
                Breakpoints++;
                break;
            }
            Others++;
            trace("exception %08lx at %p, first chance %lu\n", Event.u.Exception.ExceptionRecord.ExceptionCode,
                  Event.u.Exception.ExceptionRecord.ExceptionAddress, Event.u.Exception.dwFirstChance);
            Continue = DBG_EXCEPTION_NOT_HANDLED;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            Exits++;
            ExitCode = Event.u.ExitProcess.dwExitCode;
            Exited = TRUE;
            break;
        default:
            break;
        }
        ok(ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, Continue), "ContinueDebugEvent failed: %lu\n",
           GetLastError());
    }
    ok(Exited, "no EXIT_PROCESS after %lu events\n", Events);
    ok(Creates == 1, "%lu CREATE_PROCESS events\n", Creates);
    ok(Loads >= 1, "%lu LOAD_DLL events\n", Loads);
    ok(NtdllLoads == 1, "%lu ntdll loads\n", NtdllLoads);
    ok(Breakpoints == 1, "%lu initial breakpoints\n", Breakpoints);
    ok(Strings == 1, "%lu debug strings of the child\n", Strings);
    ok(Others == 0, "%lu other exceptions\n", Others);
    ok(Exits == 1 && ExitCode == CHILD_EXIT_CODE, "%lu EXIT_PROCESS events, exit code %lx\n", Exits, ExitCode);
    if (!Exited) TerminateProcess(ProcessInfo.hProcess, 1);
    ok(WaitForSingleObject(ProcessInfo.hProcess, 10000) == WAIT_OBJECT_0, "child did not end\n");
    ExitCode = 0;
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    ok(ExitCode == CHILD_EXIT_CODE, "child exit code %lx\n", ExitCode);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

static void TestAttach(const WCHAR *FileName)
{
    WCHAR CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    SECURITY_ATTRIBUTES Inherit = { sizeof(Inherit), NULL, TRUE };
    DEBUG_EVENT Event;
    HANDLE Release;
    ULONG_PTR Kernel32 = (ULONG_PTR)GetModuleHandleW(L"kernel32.dll");
    ULONG Events, Kernel32Loads = 0;
    BOOL Broken = FALSE;
    DWORD Code = 0;
    ULONG_PTR Pc;

    ThreadCount = 0;
    Release = CreateEventW(&Inherit, TRUE, FALSE, NULL);
    ok(Release != NULL, "CreateEvent failed: %lu\n", GetLastError());
    if (!Release) return;
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" DebugApi wait %lu", FileName,
                    (ULONG)(ULONG_PTR)Release);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(Release);
        return;
    }
    /* Let the child reach its wait, with its modules loaded */
    Sleep(1500);
    if (!DebugActiveProcess(ProcessInfo.dwProcessId))
    {
        ok(0, "DebugActiveProcess failed: %lu\n", GetLastError());
        goto Done;
    }
    for (Events = 0; Events < MAX_EVENTS && !Broken; Events++)
    {
        DWORD Continue = DBG_CONTINUE;
        if (!WaitForDebugEvent(&Event, EVENT_TIMEOUT))
        {
            ok(0, "WaitForDebugEvent failed after %lu events: %lu\n", Events, GetLastError());
            break;
        }
        if (!Events)
            ok(Event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT, "first event %lu\n", Event.dwDebugEventCode);
        switch (Event.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
            CheckCreateProcess(&Event, TRUE);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            AddThread(Event.dwThreadId, Event.u.CreateThread.hThread, Event.u.CreateThread.lpThreadLocalBase,
                      Event.u.CreateThread.lpStartAddress);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if ((ULONG_PTR)Event.u.LoadDll.lpBaseOfDll == Kernel32) Kernel32Loads++;
            /* The modules of an attached process come with file handles that name them too */
            if (Event.u.LoadDll.hFile)
            {
                WCHAR Path[MAX_PATH + 8];
                DWORD Length = FinalPath(Event.u.LoadDll.hFile, Path, _countof(Path));
                ok(Length != 0 && Length < _countof(Path), "attached: DLL at %p: length %lu, error %lu\n",
                   Event.u.LoadDll.lpBaseOfDll, Length, GetLastError());
            }
            if (Event.u.LoadDll.hFile) CloseHandle(Event.u.LoadDll.hFile);
            break;
        case EXCEPTION_DEBUG_EVENT:
            ok(Event.u.Exception.ExceptionRecord.ExceptionCode == (DWORD)STATUS_BREAKPOINT, "exception %08lx at %p\n",
               Event.u.Exception.ExceptionRecord.ExceptionCode, Event.u.Exception.ExceptionRecord.ExceptionAddress);
            if (Event.u.Exception.ExceptionRecord.ExceptionCode == (DWORD)STATUS_BREAKPOINT)
            {
                Broken = TRUE;
                if (GetPc(Event.dwThreadId, &Pc, "break-in"))
                {
                    ULONG_PTR Address = (ULONG_PTR)Event.u.Exception.ExceptionRecord.ExceptionAddress;
                    ok(Pc == Address + 1, "break-in at %p, pc %p\n", (PVOID)Address, (PVOID)Pc);
                }
            }
            else Continue = DBG_EXCEPTION_NOT_HANDLED;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            ok(0, "the child exited\n");
            Events = MAX_EVENTS;
            break;
        default:
            break;
        }
        ok(ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, Continue), "ContinueDebugEvent failed: %lu\n",
           GetLastError());
    }
    ok(Broken, "no break-in\n");
    ok(Kernel32Loads == 1, "%lu kernel32 loads\n", Kernel32Loads);
    ok(DebugSetProcessKillOnExit(FALSE), "DebugSetProcessKillOnExit failed: %lu\n", GetLastError());
    ok(DebugActiveProcessStop(ProcessInfo.dwProcessId), "DebugActiveProcessStop failed: %lu\n", GetLastError());
    /* Nothing is left to wait for */
    SetLastError(0xdeadbeef);
    ok(!WaitForDebugEvent(&Event, 0), "event %lu after the detach\n", Event.dwDebugEventCode);
    ok(GetLastError() == ERROR_SEM_TIMEOUT, "error %lu\n", GetLastError());
Done:
    SetEvent(Release);
    if (WaitForSingleObject(ProcessInfo.hProcess, 15000) != WAIT_OBJECT_0)
    {
        ok(0, "the child did not exit\n");
        TerminateProcess(ProcessInfo.hProcess, 1);
    }
    GetExitCodeProcess(ProcessInfo.hProcess, &Code);
    ok(Code == CHILD_EXIT_WAIT, "child exit code %lx\n", Code);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(Release);
}

START_TEST(DebugApi)
{
    WCHAR FileName[MAX_PATH];
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv);

    if (Argc >= 3 && !strcmp(Argv[2], "fault")) ExitProcess(ChildFault());
    if (Argc >= 3 && !strcmp(Argv[2], "exit"))
    {
        OutputDebugStringA(DebugString);
        ExitProcess(CHILD_EXIT_CODE);
    }
    if (Argc >= 4 && !strcmp(Argv[2], "wait"))
    {
        HANDLE Release = (HANDLE)(ULONG_PTR)strtoul(Argv[3], NULL, 10);
        ExitProcess(WaitForSingleObject(Release, 30000) == WAIT_OBJECT_0 ? CHILD_EXIT_WAIT : CHILD_EXIT_WAIT + 1);
    }
    if (!IsWow64Process(GetCurrentProcess(), &IsWow64)) IsWow64 = FALSE;
    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    TestExit(FileName);
    TestCatch(FileName);
    TestAttach(FileName);
}
