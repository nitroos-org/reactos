/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     csrss registers only what the client really created:
 *              - BasepCreateProcess: the process and thread ids must be those
 *                of the handles the client passes, and the process must be the
 *                client's child;
 *              - the Sb port of csrss serves only the Session Manager that
 *                started it ("svc" mode only: the port admits LocalSystem).
 *              Run it as an administrator ("csrids [file]") and as LocalSystem:
 *                sc create csrids binPath= "C:\ReactOS\bin\csrids.exe svc C:\harness\out\csrids-svc.txt"
 *              One line per check, PASS or FAIL, to the file (or stdout) and
 *              to the debugger.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winsvc.h>
#include <tlhelp32.h>
#define NTOS_MODE_USER
#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/lpcfuncs.h>
#include <ndk/mmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <csr/csr.h>
#include <win/basemsg.h>
#include <sm/smmsg.h>

/* The ntdll export (the NDK declares the Windows 7 form for this NTDDI) */
typedef NTSTATUS (NTAPI *PRTL_CREATE_USER_THREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T,
                                                  PTHREAD_START_ROUTINE, PVOID, PHANDLE, PCLIENT_ID);

#define CHILD_OK 0x5E55

static FILE *Out;
static ULONG Failures;

static
VOID
Log(const char *Format, ...)
{
    char Buffer[512];
    va_list Args;

    va_start(Args, Format);
    _vsnprintf(Buffer, sizeof(Buffer) - 1, Format, Args);
    va_end(Args);
    Buffer[sizeof(Buffer) - 1] = 0;
    OutputDebugStringA(Buffer);
    fputs(Buffer, Out ? Out : stdout);
    fflush(Out ? Out : stdout);
}

static
VOID
Check(const char *Name, NTSTATUS Status, NTSTATUS Expected)
{
    BOOL Pass = (Status == Expected);
    Log("CSRIDS %s status=%08lx expect=%08lx %s\n", Name, Status, Expected, Pass ? "PASS" : "FAIL");
    if (!Pass) Failures++;
}

/* A child of ours that nobody registered: the process object of our own image and one suspended thread */
static
NTSTATUS
CreateBareChild(PHANDLE Process, PHANDLE Thread, PCLIENT_ID ClientId)
{
    WCHAR Self[MAX_PATH];
    HANDLE File, Section = NULL;
    SECTION_IMAGE_INFORMATION ImageInfo;
    PRTL_CREATE_USER_THREAD CreateUserThread;
    NTSTATUS Status;

    *Process = *Thread = NULL;
    CreateUserThread = (PRTL_CREATE_USER_THREAD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    if (!CreateUserThread) return STATUS_PROCEDURE_NOT_FOUND;
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    File = CreateFileW(Self, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, File);
    CloseHandle(File);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtQuerySection(Section, SectionImageInformation, &ImageInfo, sizeof(ImageInfo), NULL);
    if (NT_SUCCESS(Status))
        Status = NtCreateProcessEx(Process, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), 0, Section, NULL, NULL, FALSE);
    NtClose(Section);
    if (!NT_SUCCESS(Status)) return Status;

    Status = CreateUserThread(*Process, NULL, TRUE, 0, 0, 0, (PTHREAD_START_ROUTINE)ImageInfo.TransferAddress,
                              NULL, Thread, ClientId);
    if (!NT_SUCCESS(Status))
    {
        NtTerminateProcess(*Process, Status);
        NtClose(*Process);
        *Process = NULL;
    }
    return Status;
}

/* BasepCreateProcess to our csrss, as kernel32 sends it, with the given handles and ids */
static
NTSTATUS
CallBaseCreateProcess(HANDLE Process, HANDLE Thread, PCLIENT_ID ClientId)
{
    BASE_API_MESSAGE ApiMessage;
    PBASE_CREATE_PROCESS Request = &ApiMessage.Data.CreateProcessRequest;

    RtlZeroMemory(&ApiMessage, sizeof(ApiMessage));
    /* Bit 1: a GUI application (no console) */
    Request->ProcessHandle = (HANDLE)((ULONG_PTR)Process | 2);
    Request->ThreadHandle = Thread;
    Request->ClientId = *ClientId;
#ifdef _WIN64
    Request->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#else
    Request->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif
    CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage, NULL,
                        CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess),
                        sizeof(*Request));
    return ApiMessage.Status;
}

/* Our parent process (not our child) and one of its threads */
static
BOOL
OpenParent(PHANDLE Process, PHANDLE Thread, PCLIENT_ID ClientId)
{
    PROCESS_BASIC_INFORMATION Info;
    HANDLE Snapshot;
    THREADENTRY32 Entry;
    DWORD Pid;

    *Process = *Thread = NULL;
    if (!NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &Info, sizeof(Info), NULL)))
        return FALSE;
    Pid = (DWORD)Info.InheritedFromUniqueProcessId;
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return FALSE;
    Entry.dwSize = sizeof(Entry);
    if (Thread32First(Snapshot, &Entry))
    {
        do
        {
            if (Entry.th32OwnerProcessID == Pid)
            {
                *Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
                *Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, Entry.th32ThreadID);
                ClientId->UniqueProcess = UlongToHandle(Pid);
                ClientId->UniqueThread = UlongToHandle(Entry.th32ThreadID);
                break;
            }
        } while (Thread32Next(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    if (*Process && *Thread) return TRUE;
    if (*Process) CloseHandle(*Process);
    if (*Thread) CloseHandle(*Thread);
    return FALSE;
}

/* BasepCreateThread to our csrss, as kernel32 sends it */
static
NTSTATUS
CallBaseCreateThread(HANDLE Thread, PCLIENT_ID ClientId)
{
    BASE_API_MESSAGE ApiMessage;
    PBASE_CREATE_THREAD Request = &ApiMessage.Data.CreateThreadRequest;

    RtlZeroMemory(&ApiMessage, sizeof(ApiMessage));
    Request->ThreadHandle = Thread;
    Request->ClientId = *ClientId;
    CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage, NULL,
                        CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateThread),
                        sizeof(*Request));
    return ApiMessage.Status;
}

static DWORD WINAPI Idle(LPVOID Arg) { Sleep(INFINITE); return 0; }

/* CSRSS-basesrv-createthread-trusts-clientid: a thread is registered under the ids of its handle only */
static
VOID
ThreadTests(VOID)
{
    PROCESS_BASIC_INFORMATION Info;
    HANDLE Thread, Remote;
    CLIENT_ID Ids;
    DWORD Tid, Code = 0;
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;

    /* A thread of ours that kernel32 did not register (created suspended through ntdll would be cleaner;
       CREATE_SUSPENDED keeps it from running, its own registration already happened) */
    Thread = CreateThread(NULL, 0, Idle, NULL, CREATE_SUSPENDED, &Tid);
    Check("createthread", Thread ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
    if (!Thread) return;

    /* Negative: another thread id than the handle's */
    Ids.UniqueProcess = UlongToHandle(GetCurrentProcessId());
    Ids.UniqueThread = UlongToHandle(Tid + 4);
    Check("thread-wrong-tid", CallBaseCreateThread(Thread, &Ids), STATUS_INVALID_CID);

    /* Negative: our thread, claimed for another registered process (our parent) */
    if (NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &Info, sizeof(Info), NULL)))
    {
        Ids.UniqueProcess = (HANDLE)Info.InheritedFromUniqueProcessId;
        Ids.UniqueThread = UlongToHandle(Tid);
        Check("thread-claimed-for-other-process", CallBaseCreateThread(Thread, &Ids), STATUS_INVALID_CID);
    }
    TerminateThread(Thread, 0);
    CloseHandle(Thread);

    /* Positive: CreateRemoteThread into a registered child (kernel32 registers it under its real ids) */
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" childwait", Self);
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        Sleep(1000);
        Remote = CreateRemoteThread(ProcessInfo.hProcess, NULL, 0,
                                    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread"),
                                    (LPVOID)0x5E55, 0, NULL);
        if (Remote)
        {
            WaitForSingleObject(Remote, 10000);
            GetExitCodeThread(Remote, &Code);
            CloseHandle(Remote);
        }
        Check("createremotethread", (Remote && Code == 0x5E55) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
        TerminateProcess(ProcessInfo.hProcess, 0);
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
    }
    else
    {
        Check("createremotethread-setup", STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
    }
}

/* The ids of a thread handle, as csrss reads them */
static
BOOL
IdsOfThread(HANDLE Thread, PCLIENT_ID Ids)
{
    THREAD_BASIC_INFORMATION Info;

    if (!NT_SUCCESS(NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), NULL)))
        return FALSE;
    *Ids = Info.ClientId;
    return TRUE;
}

/* Handle count of the first csrss.exe, 0 when it cannot be read */
static
DWORD
CsrssHandleCount(VOID)
{
    HANDLE Snapshot, Process;
    PROCESSENTRY32W Entry;
    DWORD Count = 0, Pid = 0;

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return 0;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snapshot, &Entry))
        do
            if (!_wcsicmp(Entry.szExeFile, L"csrss.exe")) { Pid = Entry.th32ProcessID; break; }
        while (Process32NextW(Snapshot, &Entry));
    CloseHandle(Snapshot);
    if (!Pid) return 0;
    Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!Process) Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!Process) return 0;
    if (!GetProcessHandleCount(Process, &Count)) Count = 0;
    CloseHandle(Process);
    return Count;
}

static DWORD WINAPI Quick(LPVOID Arg) { return 0x77; }

/* A thread of ours through kernel32 (registered with csrss) that runs and returns 0x77 */
static
NTSTATUS
QuickThreadWorks(VOID)
{
    HANDLE Thread = CreateThread(NULL, 0, Quick, NULL, 0, NULL);
    DWORD Code = 0;

    if (!Thread) return STATUS_UNSUCCESSFUL;
    WaitForSingleObject(Thread, 10000);
    GetExitCodeThread(Thread, &Code);
    CloseHandle(Thread);
    return (Code == 0x77) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*
 * A thread that is already dead is registered with the ids of its own handle: the ids check passes and
 * the insert fails (STATUS_THREAD_IS_TERMINATING). That failure must leave csrss as it was: its process
 * lock and references balanced (for our own process and for a remote one), no handle kept, and later
 * registrations still working.
 */
static
VOID
DeadThreadTests(VOID)
{
    HANDLE Dead, Remote, RemoteDead;
    CLIENT_ID Ids, RemoteIds;
    DWORD Before, After, Code, I, Bad = 0, RemoteBad = 0;
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    LPTHREAD_START_ROUTINE Exit = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread");

    /* Our own dead thread */
    Dead = CreateThread(NULL, 0, Quick, NULL, 0, NULL);
    if (!Dead || WaitForSingleObject(Dead, 10000) != WAIT_OBJECT_0 || !IdsOfThread(Dead, &Ids))
    {
        Check("deadthread-setup", STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
        if (Dead) CloseHandle(Dead);
        return;
    }
    Check("deadthread-register", CallBaseCreateThread(Dead, &Ids), STATUS_THREAD_IS_TERMINATING);

    Before = CsrssHandleCount();
    for (I = 0; I < 1000; I++)
        if (CallBaseCreateThread(Dead, &Ids) != STATUS_THREAD_IS_TERMINATING) Bad++;
    After = CsrssHandleCount();
    Log("CSRIDS deadthread-own: 1000 calls, %lu with another status; csrss handles %lu -> %lu\n", Bad, Before, After);
    Check("deadthread-own-repeat", Bad ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS, STATUS_SUCCESS);
    if (Before)
        Check("deadthread-own-no-handle-leak", (After <= Before + 8) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
    else
        Log("CSRIDS deadthread-own-no-handle-leak: csrss handle count not readable SKIP\n");
    CloseHandle(Dead);
    Check("deadthread-own-then-createthread", QuickThreadWorks(), STATUS_SUCCESS);

    /* The same for a remote target: a dead thread of a registered child, named with the child's ids */
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" childwait", Self);
    if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        Check("deadthread-remote-setup", STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
        return;
    }
    Sleep(1000);
    RemoteDead = CreateRemoteThread(ProcessInfo.hProcess, NULL, 0, Exit, (LPVOID)0x5E55, 0, NULL);
    if (!RemoteDead || WaitForSingleObject(RemoteDead, 10000) != WAIT_OBJECT_0 || !IdsOfThread(RemoteDead, &RemoteIds))
    {
        Check("deadthread-remote-setup", STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
    }
    else
    {
        Check("deadthread-remote-register", CallBaseCreateThread(RemoteDead, &RemoteIds), STATUS_THREAD_IS_TERMINATING);
        Before = CsrssHandleCount();
        for (I = 0; I < 1000; I++)
            if (CallBaseCreateThread(RemoteDead, &RemoteIds) != STATUS_THREAD_IS_TERMINATING) RemoteBad++;
        After = CsrssHandleCount();
        Log("CSRIDS deadthread-remote: 1000 calls, %lu with another status; csrss handles %lu -> %lu\n", RemoteBad, Before, After);
        Check("deadthread-remote-repeat", RemoteBad ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS, STATUS_SUCCESS);
        if (Before)
            Check("deadthread-remote-no-handle-leak", (After <= Before + 8) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
        else
            Log("CSRIDS deadthread-remote-no-handle-leak: csrss handle count not readable SKIP\n");

        /* The child is still registered and still takes threads (its process lock and references are intact) */
        Remote = CreateRemoteThread(ProcessInfo.hProcess, NULL, 0, Exit, (LPVOID)0x5E55, 0, NULL);
        Code = 0;
        if (Remote)
        {
            WaitForSingleObject(Remote, 10000);
            GetExitCodeThread(Remote, &Code);
            CloseHandle(Remote);
        }
        Check("deadthread-remote-then-createremotethread", (Remote && Code == 0x5E55) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
    }
    if (RemoteDead) CloseHandle(RemoteDead);

    /* Ending the child runs its teardown in csrss with the references as they should be */
    TerminateProcess(ProcessInfo.hProcess, 0);
    WaitForSingleObject(ProcessInfo.hProcess, 10000);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
    Sleep(500);
    Check("deadthread-after-child-exit-createthread", QuickThreadWorks(), STATUS_SUCCESS);
}

/*
 * A failed thread registration must not keep the process: CsrCreateThread's insert-failure branch gives
 * back the process reference CsrAllocateThread took. With that reference left behind, a process that
 * once registered a dead thread (its own, or a remote one through the process lock) stays in csrss
 * after it exits: its process handle and its port handle are never closed (2 handles per process).
 * Count the csrss handles around 20 such processes; readable in the LocalSystem service run only. The
 * children have no console: a console of their own would add a handle per child to csrss that has
 * nothing to do with thread registration.
 */
#define LEAK_CHILDREN 20

static
VOID
ProcessLeakTests(VOID)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    LPTHREAD_START_ROUTINE Exit = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread");
    DWORD Before, After, I, Code, Bad = 0;

    Before = CsrssHandleCount();
    if (!Before)
    {
        Log("CSRIDS deadthread-own-process-gone: csrss handle count not readable SKIP\n");
        Log("CSRIDS deadthread-remote-process-gone: csrss handle count not readable SKIP\n");
        return;
    }

    /* Own: each child registers a dead thread of its own, then exits */
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" deadself", Self);
    for (I = 0; I < LEAK_CHILDREN; I++)
    {
        if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) { Bad++; continue; }
        Code = 0;
        WaitForSingleObject(ProcessInfo.hProcess, 20000);
        GetExitCodeProcess(ProcessInfo.hProcess, &Code);
        if (Code != CHILD_OK) Bad++;
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
    }
    Sleep(1000);
    After = CsrssHandleCount();
    Log("CSRIDS deadthread-own-process-gone: %lu children, %lu failed; csrss handles %lu -> %lu\n", (DWORD)LEAK_CHILDREN, Bad, Before, After);
    Check("deadthread-own-process-gone", (!Bad && After <= Before + 8) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);

    /* Remote: we register a dead thread of each child (named with the child's ids), then end the child */
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" childwait", Self);
    Before = CsrssHandleCount();
    Bad = 0;
    for (I = 0; I < LEAK_CHILDREN; I++)
    {
        HANDLE RemoteDead;
        CLIENT_ID RemoteIds;

        if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) { Bad++; continue; }
        Sleep(100);
        RemoteDead = CreateRemoteThread(ProcessInfo.hProcess, NULL, 0, Exit, (LPVOID)0x5E55, 0, NULL);
        if (!RemoteDead || WaitForSingleObject(RemoteDead, 10000) != WAIT_OBJECT_0 || !IdsOfThread(RemoteDead, &RemoteIds) ||
            CallBaseCreateThread(RemoteDead, &RemoteIds) != STATUS_THREAD_IS_TERMINATING)
            Bad++;
        if (RemoteDead) CloseHandle(RemoteDead);
        TerminateProcess(ProcessInfo.hProcess, 0);
        WaitForSingleObject(ProcessInfo.hProcess, 10000);
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
    }
    Sleep(1000);
    After = CsrssHandleCount();
    Log("CSRIDS deadthread-remote-process-gone: %lu children, %lu failed; csrss handles %lu -> %lu\n", (DWORD)LEAK_CHILDREN, Bad, Before, After);
    Check("deadthread-remote-process-gone", (!Bad && After <= Before + 8) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
}

/*
 * Every console created for a process that has none (a child of a service) opens a desktop handle for the
 * console input thread of its desktop. The thread cannot close the handle it is assigned to, so once it
 * left the desktop first the handle must go with the thread. With the handle left behind, csrss grows by one
 * Desktop handle per console child (and in a session without a shared desktop heap view the heaps run out
 * after a few hundred). Readable in the LocalSystem service run only: the service has no console, so each
 * child below gets one of its own (no DETACHED_PROCESS).
 */
#define CONSOLE_CHILDREN 20

static
VOID
ConsoleChildLeakTest(VOID)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DWORD Before, After, I, Code, Bad = 0;

    Before = CsrssHandleCount();
    if (!Before)
    {
        Log("CSRIDS console-child-no-handle-leak: csrss handle count not readable SKIP\n");
        return;
    }

    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" child", Self);
    for (I = 0; I < CONSOLE_CHILDREN; I++)
    {
        if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo)) { Bad++; continue; }
        Code = 0;
        WaitForSingleObject(ProcessInfo.hProcess, 20000);
        GetExitCodeProcess(ProcessInfo.hProcess, &Code);
        if (Code != CHILD_OK) Bad++;
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
    }
    Sleep(1500);
    After = CsrssHandleCount();
    Log("CSRIDS console-child-no-handle-leak: %lu children, %lu failed; csrss handles %lu -> %lu\n", (DWORD)CONSOLE_CHILDREN, Bad, Before, After);
    Check("console-child-no-handle-leak", (!Bad && After <= Before + 8) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL, STATUS_SUCCESS);
}

/*
 * rvcsrss 2: the create-time branch of BaseSrvCheckNewProcess. A spawner process creates an unregistered
 * child and exits; once its pid is free we create processes until one gets that pid. That process names the
 * orphan as its new process: the parent pid matches, but the orphan is older than it: refused.
 */
static
VOID
PidReuseTest(VOID)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 32], File[MAX_PATH];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION Spawner, Candidate;
    DWORD OrphanPid = 0, SpawnerPid, Code = 0, Tries;
    HANDLE Orphan = NULL, OrphanThread = NULL, Snapshot, DupProcess, DupThread;
    THREADENTRY32 Entry;
    FILE *f;

    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" spawner", Self);
    if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &Spawner))
    {
        Log("CSRIDS pid-reuse: spawner not started SKIP\n");
        return;
    }
    SpawnerPid = Spawner.dwProcessId;
    WaitForSingleObject(Spawner.hProcess, 30000);
    GetExitCodeProcess(Spawner.hProcess, &OrphanPid);
    CloseHandle(Spawner.hProcess);
    CloseHandle(Spawner.hThread);
    /* The orphan must be older than the process that takes the pid: more than a clock tick (create times compare with <) */
    Sleep(100);
    Orphan = OpenProcess(PROCESS_ALL_ACCESS, FALSE, OrphanPid);
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Entry.dwSize = sizeof(Entry);
    if (Snapshot != INVALID_HANDLE_VALUE && Thread32First(Snapshot, &Entry))
        do
            if (Entry.th32OwnerProcessID == OrphanPid) { OrphanThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Entry.th32ThreadID); break; }
        while (Thread32Next(Snapshot, &Entry));
    if (Snapshot != INVALID_HANDLE_VALUE) CloseHandle(Snapshot);
    if (!Orphan || !OrphanThread)
    {
        Log("CSRIDS pid-reuse: orphan %lu not found SKIP\n", OrphanPid);
        if (Orphan) CloseHandle(Orphan);
        return;
    }

    /* A new process with the spawner's old pid */
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" reuser", Self);
    for (Tries = 0; Tries < 400; Tries++)
    {
        if (!CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &Candidate)) break;
        if (Candidate.dwProcessId == SpawnerPid) break;
        TerminateProcess(Candidate.hProcess, 0);
        WaitForSingleObject(Candidate.hProcess, 5000);
        CloseHandle(Candidate.hProcess);
        CloseHandle(Candidate.hThread);
        Candidate.hProcess = NULL;
    }
    if (Tries >= 400 || !Candidate.hProcess)
    {
        Log("CSRIDS pid-reuse: pid %lu not reused in %lu tries SKIP\n", SpawnerPid, Tries);
        TerminateProcess(Orphan, 0); CloseHandle(Orphan); CloseHandle(OrphanThread);
        return;
    }

    /* Hand the orphan to it and let it ask csrss to register the orphan as its new process */
    DuplicateHandle(GetCurrentProcess(), Orphan, Candidate.hProcess, &DupProcess, 0, FALSE, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(GetCurrentProcess(), OrphanThread, Candidate.hProcess, &DupThread, 0, FALSE, DUPLICATE_SAME_ACCESS);
    GetTempPathW(MAX_PATH, File); wcscat(File, L"csrids-reuse.txt");
    f = _wfopen(File, L"w");
    if (f)
    {
        fprintf(f, "%p %p %lu %lu\n", DupProcess, DupThread, OrphanPid, GetThreadId(OrphanThread));
        fclose(f);
    }
    ResumeThread(Candidate.hThread);
    WaitForSingleObject(Candidate.hProcess, 30000);
    GetExitCodeProcess(Candidate.hProcess, &Code);
    Log("CSRIDS pid-reuse: process %lu took pid %lu after %lu tries; orphan %lu\n", Candidate.dwProcessId, SpawnerPid, Tries, OrphanPid);
    Check("pid-reuse-older-orphan", (NTSTATUS)Code, STATUS_ACCESS_DENIED);
    TerminateProcess(Candidate.hProcess, 0);
    CloseHandle(Candidate.hProcess); CloseHandle(Candidate.hThread);
    TerminateProcess(Orphan, 0); CloseHandle(Orphan); CloseHandle(OrphanThread);
}

static
VOID
BaseTests(VOID)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    HANDLE Process, Thread, OwnThread;
    CLIENT_ID ClientId, Ids;
    DWORD ExitCode = 0;
    NTSTATUS Status;

    /* Control: CreateProcess, as every program does */
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" child", Self);
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        WaitForSingleObject(ProcessInfo.hProcess, 60000);
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
    }
    Check("createprocess-child", (NTSTATUS)ExitCode, CHILD_OK);

    /* An unregistered child of ours */
    Status = CreateBareChild(&Process, &Thread, &ClientId);
    Log("CSRIDS bare-child status=%08lx pid=%lu tid=%lu\n", Status,
        HandleToUlong(ClientId.UniqueProcess), HandleToUlong(ClientId.UniqueThread));
    if (!NT_SUCCESS(Status))
    {
        Failures++;
        return;
    }

    /* Negative: the request names another thread than the handle's */
    Ids = ClientId;
    Ids.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Check("wrong-tid", CallBaseCreateProcess(Process, Thread, &Ids), STATUS_INVALID_CID);

    /* Negative: the request names another process than the handle's (ours) */
    Ids = ClientId;
    Ids.UniqueProcess = UlongToHandle(GetCurrentProcessId());
    Check("wrong-pid", CallBaseCreateProcess(Process, Thread, &Ids), STATUS_INVALID_CID);

    /* Negative: a thread of another process (ours, with its own id) */
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &OwnThread,
                    0, FALSE, DUPLICATE_SAME_ACCESS);
    Ids.UniqueProcess = ClientId.UniqueProcess;
    Ids.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Check("thread-of-another-process", CallBaseCreateProcess(Process, OwnThread, &Ids), STATUS_INVALID_CID);
    CloseHandle(OwnThread);

    /* Positive: our child with its own ids */
    Check("own-child", CallBaseCreateProcess(Process, Thread, &ClientId), STATUS_SUCCESS);

    NtTerminateProcess(Process, STATUS_SUCCESS);
    NtClose(Thread);
    NtClose(Process);

    /* Negative: a process that is not our child (our parent), with its own ids */
    if (OpenParent(&Process, &Thread, &ClientId))
    {
        Check("not-our-child", CallBaseCreateProcess(Process, Thread, &ClientId), STATUS_ACCESS_DENIED);
        CloseHandle(Process);
        CloseHandle(Thread);
    }
    else
    {
        Log("CSRIDS not-our-child: cannot open the parent FAIL\n");
        Failures++;
    }
}

/* LocalSystem only: the Sb port of our session's csrss refuses anyone but the Session Manager */
static
VOID
SbTests(VOID)
{
    UNICODE_STRING Name;
    SECURITY_QUALITY_OF_SERVICE Qos;
    HANDLE Port = NULL;
    ULONG Session = 0;
    WCHAR PortName[64];
    NTSTATUS Status;

    NtQueryInformationProcess(NtCurrentProcess(), ProcessSessionInformation, &Session, sizeof(Session), NULL);
    if (Session)
        _snwprintf(PortName, RTL_NUMBER_OF(PortName), L"\\Sessions\\%lu\\Windows\\SbApiPort", Session);
    else
        _snwprintf(PortName, RTL_NUMBER_OF(PortName), L"\\Windows\\SbApiPort");
    RtlInitUnicodeString(&Name, PortName);
    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityIdentification;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = TRUE;
    Status = NtConnectPort(&Port, &Name, &Qos, NULL, NULL, NULL, NULL, NULL);
    Check("sb-connect-from-system", Status, STATUS_PORT_CONNECTION_REFUSED);
    if (NT_SUCCESS(Status)) NtClose(Port);
}

static
VOID
Tests(BOOL System)
{
    Log("CSRIDS start pid=%lu system=%d\n", GetCurrentProcessId(), System);
    BaseTests();
    ThreadTests();
    DeadThreadTests();
    ProcessLeakTests();
    ConsoleChildLeakTest();
    PidReuseTest();
    if (System) SbTests();
    Log("CSRIDS done failures=%lu\n", Failures);
}

static SERVICE_STATUS_HANDLE StatusHandle;

static
VOID
Report(DWORD State)
{
    SERVICE_STATUS Status = { SERVICE_WIN32_OWN_PROCESS, State, 0, NO_ERROR, 0, 0, 0 };
    SetServiceStatus(StatusHandle, &Status);
}

static
VOID
WINAPI
ServiceMain(DWORD Argc, LPWSTR *Argv)
{
    StatusHandle = RegisterServiceCtrlHandlerW(L"csrids", NULL);
    Report(SERVICE_RUNNING);
    Tests(TRUE);
    Report(SERVICE_STOPPED);
}

int
wmain(int argc, wchar_t *argv[])
{
    if ((argc > 1) && !_wcsicmp(argv[1], L"child")) return CHILD_OK;
    if ((argc > 1) && !_wcsicmp(argv[1], L"childwait")) { Sleep(30000); return 0; }
    if ((argc > 1) && !_wcsicmp(argv[1], L"deadself"))
    {
        /* Register a thread of ours that is already dead (refused), then end */
        HANDLE Dead = CreateThread(NULL, 0, Quick, NULL, 0, NULL);
        CLIENT_ID Ids;

        if (!Dead || WaitForSingleObject(Dead, 10000) != WAIT_OBJECT_0 || !IdsOfThread(Dead, &Ids)) return 1;
        if (CallBaseCreateThread(Dead, &Ids) != STATUS_THREAD_IS_TERMINATING) return 2;
        CloseHandle(Dead);
        return CHILD_OK;
    }
    if ((argc > 1) && !_wcsicmp(argv[1], L"spawner"))
    {
        /* An unregistered child of ours; our exit code is its pid */
        HANDLE P, T;
        CLIENT_ID Id;
        if (!NT_SUCCESS(CreateBareChild(&P, &T, &Id))) return 0;
        return HandleToUlong(Id.UniqueProcess);
    }
    if ((argc > 1) && !_wcsicmp(argv[1], L"reuser"))
    {
        WCHAR File[MAX_PATH];
        void *P = NULL, *T = NULL;
        unsigned long Pid = 0, Tid = 0;
        CLIENT_ID Id;
        FILE *f;
        GetTempPathW(MAX_PATH, File); wcscat(File, L"csrids-reuse.txt");
        f = _wfopen(File, L"r");
        if (!f || fscanf(f, "%p %p %lu %lu", &P, &T, &Pid, &Tid) != 4) return 1;
        fclose(f);
        DeleteFileW(File);
        Id.UniqueProcess = UlongToHandle(Pid);
        Id.UniqueThread = UlongToHandle(Tid);
        return (int)CallBaseCreateProcess((HANDLE)P, (HANDLE)T, &Id);
    }

    if ((argc > 1) && !_wcsicmp(argv[1], L"threads"))
    {
        /* Only the thread registration cases (a 32-bit build under WoW64 runs these) */
        if (argc > 2) Out = _wfopen(argv[2], L"w");
        Log("CSRIDS start pid=%lu threads-only %s\n", GetCurrentProcessId(), sizeof(void *) == 4 ? "32-bit" : "64-bit");
        ThreadTests();
        DeadThreadTests();
        ProcessLeakTests();
        Log("CSRIDS done failures=%lu\n", Failures);
        if (Out) fclose(Out);
        return Failures ? 1 : 0;
    }

    if ((argc > 1) && !_wcsicmp(argv[1], L"svc"))
    {
        SERVICE_TABLE_ENTRYW Table[] = { { L"csrids", ServiceMain }, { NULL, NULL } };

        if (argc > 2) Out = _wfopen(argv[2], L"w");
        StartServiceCtrlDispatcherW(Table);
        if (Out) fclose(Out);
        return 0;
    }

    if (argc > 1) Out = _wfopen(argv[1], L"w");
    Tests(FALSE);
    if (Out) fclose(Out);
    return Failures ? 1 : 0;
}
