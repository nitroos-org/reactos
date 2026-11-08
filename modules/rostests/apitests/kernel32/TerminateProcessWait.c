/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     TerminateProcess ends a process whatever its threads are doing
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * TerminateProcess always completes: a thread blocked in any kind of wait or pending I/O is
 * interrupted, and a thread that is ready to run but starved by CPU-bound threads of a higher priority
 * (the content processes of Firefox run in the idle priority class, next to a busy media decoder) still
 * gets to run its exit path promptly. Each wait kind is exercised in a child process that blocks one
 * thread in it, and the starvation case runs an idle-priority child with many ready threads while
 * normal-priority threads keep every processor busy. Windows 10 22H2 (4 processors, 151 ready threads,
 * 4 busy threads) needs 33 to 43 seconds to end that child, so the test only requires that it ends.
 */

#include "precomp.h"

#define SETTLE_MS       500
#define EXIT_WAIT_MS    20000
#define STARVE_THREADS  150
#define STARVE_WAIT_MS  180000

static HANDLE g_Mutex;
static RTL_SRWLOCK g_Srw = RTL_SRWLOCK_INIT;
static RTL_CONDITION_VARIABLE g_Cv = RTL_CONDITION_VARIABLE_INIT;
static CRITICAL_SECTION g_Cs;

typedef NTSTATUS (NTAPI *PFN_NWFKE)(HANDLE, PVOID, BOOLEAN, PLARGE_INTEGER);

static
DWORD
WINAPI
SleepForever(LPVOID Context)
{
    Sleep(INFINITE);
    return 0;
}

static VOID WaitEvent(VOID) { WaitForSingleObject(CreateEventW(NULL, TRUE, FALSE, NULL), INFINITE); }
static VOID WaitEventAlertable(VOID) { WaitForSingleObjectEx(CreateEventW(NULL, TRUE, FALSE, NULL), INFINITE, TRUE); }
static VOID WaitMultipleAll(VOID)
{
    HANDLE Events[3];
    ULONG i;

    for (i = 0; i < _countof(Events); i++)
        Events[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
    WaitForMultipleObjects(_countof(Events), Events, TRUE, INFINITE);
}
static VOID WaitSleep(VOID) { Sleep(INFINITE); }
static VOID WaitSleepEx(VOID) { SleepEx(INFINITE, TRUE); }
static VOID WaitSemaphore(VOID) { WaitForSingleObject(CreateSemaphoreW(NULL, 0, 10, NULL), INFINITE); }
static VOID WaitThreadHandle(VOID) { WaitForSingleObject(CreateThread(NULL, 0, SleepForever, NULL, 0, NULL), INFINITE); }

static
DWORD
WINAPI
HoldMutex(LPVOID Context)
{
    WaitForSingleObject(g_Mutex, INFINITE);
    Sleep(INFINITE);
    return 0;
}

static VOID WaitOwnedMutex(VOID)
{
    g_Mutex = CreateMutexW(NULL, FALSE, NULL);
    CreateThread(NULL, 0, HoldMutex, NULL, 0, NULL);
    Sleep(300);
    WaitForSingleObject(g_Mutex, INFINITE);
}

static VOID WaitSrw(VOID)
{
    RtlAcquireSRWLockExclusive(&g_Srw);
    RtlAcquireSRWLockExclusive(&g_Srw);
}

static VOID WaitCondVar(VOID)
{
    RtlAcquireSRWLockExclusive(&g_Srw);
    RtlSleepConditionVariableSRW(&g_Cv, &g_Srw, NULL, 0);
}

static
DWORD
WINAPI
HoldCs(LPVOID Context)
{
    EnterCriticalSection(&g_Cs);
    Sleep(INFINITE);
    return 0;
}

static VOID WaitCritSec(VOID)
{
    InitializeCriticalSection(&g_Cs);
    CreateThread(NULL, 0, HoldCs, NULL, 0, NULL);
    Sleep(300);
    EnterCriticalSection(&g_Cs);
}

static VOID WaitKeyedEvent(VOID)
{
    PFN_NWFKE Wait = (PFN_NWFKE)GetProcAddress(GetModuleHandleW(L"ntdll"), "NtWaitForKeyedEvent");

    Wait(NULL, (PVOID)0x1000, FALSE, NULL);
}

static VOID WaitCompletionPort(VOID)
{
    HANDLE Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    DWORD Bytes;
    ULONG_PTR Key;
    LPOVERLAPPED Overlapped;

    GetQueuedCompletionStatus(Port, &Bytes, &Key, &Overlapped, INFINITE);
}

static VOID WaitAnonymousPipe(VOID)
{
    HANDLE Read, Write;
    CHAR Buffer[8];
    DWORD Bytes;

    CreatePipe(&Read, &Write, NULL, 0);
    ReadFile(Read, Buffer, sizeof(Buffer), &Bytes, NULL);
}

static VOID WaitNamedPipeConnect(VOID)
{
    HANDLE Pipe = CreateNamedPipeW(L"\\\\.\\pipe\\TerminateProcessWaitConnect", PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);

    ConnectNamedPipe(Pipe, NULL);
}

static VOID WaitNamedPipeRead(VOID)
{
    HANDLE Server = CreateNamedPipeW(L"\\\\.\\pipe\\TerminateProcessWaitRead", PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    HANDLE Client = CreateFileW(L"\\\\.\\pipe\\TerminateProcessWaitRead", GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    CHAR Buffer[8];
    DWORD Bytes;

    (VOID)Client;
    ReadFile(Server, Buffer, sizeof(Buffer), &Bytes, NULL);
}

static VOID WaitOverlappedPipe(VOID)
{
    HANDLE Server = CreateNamedPipeW(L"\\\\.\\pipe\\TerminateProcessWaitOvl", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    HANDLE Client = CreateFileW(L"\\\\.\\pipe\\TerminateProcessWaitOvl", GENERIC_READ | GENERIC_WRITE,
                                0, NULL, OPEN_EXISTING, 0, NULL);
    CHAR Buffer[8];
    DWORD Bytes;
    OVERLAPPED Overlapped;

    (VOID)Client;
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ReadFile(Server, Buffer, sizeof(Buffer), &Bytes, &Overlapped);
    GetOverlappedResult(Server, &Overlapped, &Bytes, TRUE);
}

static VOID WaitMailslot(VOID)
{
    HANDLE Slot = CreateMailslotW(L"\\\\.\\mailslot\\TerminateProcessWait", 0, MAILSLOT_WAIT_FOREVER, NULL);
    CHAR Buffer[16];
    DWORD Bytes;

    ReadFile(Slot, Buffer, sizeof(Buffer), &Bytes, NULL);
}

static VOID WaitLockedRange(VOID)
{
    WCHAR Path[MAX_PATH];
    HANDLE First, Second;
    OVERLAPPED Overlapped;

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    GetTempPathW(_countof(Path), Path);
    StringCchCatW(Path, _countof(Path), L"TerminateProcessWait.tmp");
    First = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    Second = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    LockFileEx(First, LOCKFILE_EXCLUSIVE_LOCK, 0, 100, 0, &Overlapped);
    LockFileEx(Second, LOCKFILE_EXCLUSIVE_LOCK, 0, 100, 0, &Overlapped);
}

static VOID WaitTimer(VOID) { WaitForSingleObject(CreateWaitableTimerW(NULL, TRUE, NULL), INFINITE); }
static VOID WaitJob(VOID) { WaitForSingleObject(CreateJobObjectW(NULL, NULL), INFINITE); }

static const struct
{
    PCSTR Name;
    VOID (*Function)(VOID);
} Waits[] =
{
    { "event", WaitEvent },
    { "event, alertable", WaitEventAlertable },
    { "wait for all of three events", WaitMultipleAll },
    { "Sleep(INFINITE)", WaitSleep },
    { "SleepEx(INFINITE, TRUE)", WaitSleepEx },
    { "semaphore", WaitSemaphore },
    { "thread handle", WaitThreadHandle },
    { "mutex owned by another thread", WaitOwnedMutex },
    { "SRW lock taken twice", WaitSrw },
    { "condition variable", WaitCondVar },
    { "critical section owned by another thread", WaitCritSec },
    { "keyed event", WaitKeyedEvent },
    { "completion port", WaitCompletionPort },
    { "anonymous pipe read", WaitAnonymousPipe },
    { "ConnectNamedPipe", WaitNamedPipeConnect },
    { "named pipe read", WaitNamedPipeRead },
    { "overlapped named pipe read, GetOverlappedResult", WaitOverlappedPipe },
    { "mailslot read", WaitMailslot },
    { "LockFileEx on a locked range", WaitLockedRange },
    { "waitable timer", WaitTimer },
    { "job object", WaitJob },
};

static volatile LONG g_Stop;
static volatile LONG g_Spin;

static
DWORD
WINAPI
Spinner(LPVOID Context)
{
    while (!g_Stop)
        InterlockedIncrement(&g_Spin);
    return 0;
}

static
DWORD
WINAPI
WaitThread(LPVOID Context)
{
    Waits[(ULONG_PTR)Context].Function();
    Sleep(INFINITE);
    return 0;
}

/* Child: block a thread in wait N (the main thread sleeps) */
static
INT
RunWaitChild(ULONG Index)
{
    CreateThread(NULL, 0, WaitThread, (LPVOID)(ULONG_PTR)Index, 0, NULL);
    Sleep(INFINITE);
    return 0;
}

/* Child: idle priority class, many threads that are ready to run and never wait */
static
INT
RunStarveChild(HANDLE Ready)
{
    ULONG i;

    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
    for (i = 0; i < STARVE_THREADS; i++)
        CloseHandle(CreateThread(NULL, 0, Spinner, NULL, 0, NULL));
    SetEvent(Ready);
    Spinner(NULL);
    return 0;
}

static
BOOL
StartChild(
    _In_ PCWSTR Arguments,
    _In_ BOOL Inherit,
    _In_ DWORD Flags,
    _Out_ PROCESS_INFORMATION *ProcessInfo)
{
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 96];
    STARTUPINFOW StartupInfo;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" TerminateProcessWait %ls", FileName, Arguments);
    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    return CreateProcessW(FileName, CommandLine, NULL, NULL, Inherit, Flags, NULL, NULL, &StartupInfo, ProcessInfo);
}

static
VOID
TestWait(ULONG Index)
{
    WCHAR Arguments[32];
    PROCESS_INFORMATION ProcessInfo;
    DWORD Wait;

    StringCbPrintfW(Arguments, sizeof(Arguments), L"wait %lu", Index);
    if (!StartChild(Arguments, FALSE, 0, &ProcessInfo))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return;
    }
    CloseHandle(ProcessInfo.hThread);
    Sleep(SETTLE_MS);

    Wait = WaitForSingleObject(ProcessInfo.hProcess, 0);
    ok(Wait == WAIT_TIMEOUT, "%s: the child ended by itself (%lu)\n", Waits[Index].Name, Wait);
    if (Wait == WAIT_TIMEOUT)
    {
        ok(TerminateProcess(ProcessInfo.hProcess, 0x77), "%s: TerminateProcess failed with %lu\n",
           Waits[Index].Name, GetLastError());
        Wait = WaitForSingleObject(ProcessInfo.hProcess, EXIT_WAIT_MS);
        ok(Wait == WAIT_OBJECT_0, "%s: the process is still alive %d s after TerminateProcess\n",
           Waits[Index].Name, EXIT_WAIT_MS / 1000);
    }
    CloseHandle(ProcessInfo.hProcess);
}

static
VOID
TestStarvedExit(VOID)
{
    SECURITY_ATTRIBUTES Attributes = { sizeof(Attributes), NULL, TRUE };
    HANDLE Ready = CreateEventW(&Attributes, TRUE, FALSE, NULL);
    HANDLE Hogs[64];
    SYSTEM_INFO SystemInfo;
    PROCESS_INFORMATION ProcessInfo;
    WCHAR Arguments[32];
    ULONG i, HogCount;
    DWORD Wait, Start, Elapsed;

    StringCbPrintfW(Arguments, sizeof(Arguments), L"starve %Iu", (ULONG_PTR)Ready);
    if (!StartChild(Arguments, TRUE, 0, &ProcessInfo))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        CloseHandle(Ready);
        return;
    }
    CloseHandle(ProcessInfo.hThread);

    /* The child creates its threads at idle priority: allow for that */
    Wait = WaitForSingleObject(Ready, 60000);
    if (Wait != WAIT_OBJECT_0)
    {
        skip("the child did not get ready (%lu)\n", Wait);
        TerminateProcess(ProcessInfo.hProcess, 1);
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(Ready);
        return;
    }

    /* Keep every processor busy with normal-priority threads */
    GetSystemInfo(&SystemInfo);
    HogCount = min(SystemInfo.dwNumberOfProcessors, _countof(Hogs));
    g_Stop = 0;
    for (i = 0; i < HogCount; i++)
        Hogs[i] = CreateThread(NULL, 0, Spinner, NULL, 0, NULL);
    Sleep(1500);

    ok(WaitForSingleObject(ProcessInfo.hProcess, 0) == WAIT_TIMEOUT, "the child ended by itself\n");
    Start = GetTickCount();
    ok(TerminateProcess(ProcessInfo.hProcess, 0x55), "TerminateProcess failed with %lu\n", GetLastError());
    Wait = WaitForSingleObject(ProcessInfo.hProcess, STARVE_WAIT_MS);
    Elapsed = GetTickCount() - Start;

    g_Stop = 1;
    WaitForMultipleObjects(HogCount, Hogs, TRUE, 10000);
    for (i = 0; i < HogCount; i++)
        CloseHandle(Hogs[i]);

    ok(Wait == WAIT_OBJECT_0, "the idle-priority process is still alive %d s after TerminateProcess\n",
       STARVE_WAIT_MS / 1000);
    trace("the idle-priority process with %d ready threads ended %lu ms after TerminateProcess, %lu busy threads\n",
          STARVE_THREADS + 1, Elapsed, HogCount);

    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(Ready);
}

START_TEST(TerminateProcessWait)
{
    int argc;
    char **argv;
    ULONG i;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "wait"))
        ExitProcess(RunWaitChild(strtoul(argv[3], NULL, 10)));
    if (argc >= 4 && !strcmp(argv[2], "starve"))
        ExitProcess(RunStarveChild((HANDLE)(ULONG_PTR)strtoul(argv[3], NULL, 10)));

    for (i = 0; i < _countof(Waits); i++)
        TestWait(i);
    TestStarvedExit();
}
