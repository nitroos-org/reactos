/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Test that a debuggee's threads run again after overlapping debug event freezes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Every debug event that a thread of the debuggee reports with the process
 * suspended (create thread, exception, DLL load) freezes the other threads of
 * the process until the debugger continues it. A thread that starts while an
 * earlier create-thread event is still pending is not frozen; its own
 * create-thread event freezes the process a second time, on top of the first.
 *
 * The parent debugs a copy of itself ("child": waits). It starts a worker in
 * the child that counts in a loop and continues its create-thread event. It
 * starts thread A and receives its create-thread event (the worker is frozen),
 * starts thread B and waits until B has reported (B's freeze overlaps A's),
 * continues A, receives and continues B's event. Nothing is pending then: the
 * worker must count again. Before the fix the second freeze queued the
 * worker's suspend APC a second time and the worker stayed suspended after
 * the last thaw: a breakpoint written into its loop was never reported.
 */

#define FREEZE_ROUNDS   10
#define EVENT_TIMEOUT   20000

static volatile LONG ChildCounter;

static DWORD WINAPI ChildWorker(LPVOID Parameter)
{
    (void)Parameter;
    for (;;)
        InterlockedIncrement(&ChildCounter);
    return 0;
}

static DWORD WINAPI ChildIdle(LPVOID Parameter)
{
    (void)Parameter;
    Sleep(INFINITE);
    return 0;
}

static ULONG_PTR DebuggeeBase;

static ULONG_PTR ChildAddress(PVOID Address)
{
    return (ULONG_PTR)Address - (ULONG_PTR)GetModuleHandleW(NULL) + DebuggeeBase;
}

/* Wait for the next event of the debuggee; DLL and debug string events are continued here */
static BOOL NextEvent(DEBUG_EVENT *Event)
{
    for (;;)
    {
        if (!WaitForDebugEvent(Event, EVENT_TIMEOUT))
            return FALSE;
        if (Event->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
        {
            if (Event->u.LoadDll.hFile) CloseHandle(Event->u.LoadDll.hFile);
        }
        else if (Event->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            if (Event->u.CreateProcessInfo.hFile) CloseHandle(Event->u.CreateProcessInfo.hFile);
            DebuggeeBase = (ULONG_PTR)Event->u.CreateProcessInfo.lpBaseOfImage;
        }
        else if (Event->dwDebugEventCode != OUTPUT_DEBUG_STRING_EVENT &&
                 Event->dwDebugEventCode != UNLOAD_DLL_DEBUG_EVENT)
            return TRUE;
        ContinueDebugEvent(Event->dwProcessId, Event->dwThreadId, DBG_CONTINUE);
    }
}

/* Start a thread in the debuggee and get its create-thread event; the event stays pending */
static BOOL StartThread(HANDLE Process, PVOID Routine, DEBUG_EVENT *Event, DWORD *Tid, DWORD SleepBeforeWait,
                        const DEBUG_EVENT *ContinueFirst)
{
    HANDLE Thread = CreateRemoteThread(Process, NULL, 0, (LPTHREAD_START_ROUTINE)ChildAddress(Routine), NULL, 0, Tid);
    ok(Thread != NULL, "CreateRemoteThread failed: %lu\n", GetLastError());
    if (!Thread) return FALSE;
    CloseHandle(Thread);
    if (SleepBeforeWait) Sleep(SleepBeforeWait);
    if (ContinueFirst)
        ok(ContinueDebugEvent(ContinueFirst->dwProcessId, ContinueFirst->dwThreadId, DBG_CONTINUE),
           "ContinueDebugEvent failed: %lu\n", GetLastError());
    for (;;)
    {
        if (!NextEvent(Event))
        {
            ok(0, "No create-thread event for the new thread %lu\n", *Tid);
            return FALSE;
        }
        if (Event->dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && Event->dwThreadId == *Tid)
            return TRUE;
        /* An event of another thread of the debuggee (a thread of its own that exits): go on */
        ContinueDebugEvent(Event->dwProcessId, Event->dwThreadId, DBG_CONTINUE);
    }
}

/* Continue every event that comes for Milliseconds: the debuggee is not frozen for long by one of them */
static void ContinueFor(DWORD Milliseconds)
{
    DEBUG_EVENT Event;
    DWORD Start = GetTickCount(), Elapsed;

    while ((Elapsed = GetTickCount() - Start) < Milliseconds)
    {
        if (!WaitForDebugEvent(&Event, Milliseconds - Elapsed))
            break;
        if (Event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && Event.u.LoadDll.hFile)
            CloseHandle(Event.u.LoadDll.hFile);
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, DBG_CONTINUE);
    }
}

static LONG ReadCounter(HANDLE Process)
{
    LONG Value = -1;
    SIZE_T Read;
    if (!ReadProcessMemory(Process, (PVOID)ChildAddress((PVOID)&ChildCounter), &Value, sizeof(Value), &Read))
        return -1;
    return Value;
}

static void TestNestedFreeze(PCWSTR FileName)
{
    WCHAR CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DEBUG_EVENT Event, EventA, EventB;
    DWORD Tid, Round, Wait, Stuck = 0;

    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" DebugFreezeNested child", FileName);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess failed: %lu\n", GetLastError());
        return;
    }

    /* Run the child to its initial breakpoint */
    for (;;)
    {
        if (!NextEvent(&Event))
        {
            ok(0, "No initial breakpoint\n");
            goto Cleanup;
        }
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, DBG_CONTINUE);
        if (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            Event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
            break;
    }

    for (Round = 0; Round < FREEZE_ROUNDS; Round++)
    {
        LONG Before, After;
        DWORD WorkerTid;

        /* The worker, running freely */
        if (!StartThread(ProcessInfo.hProcess, ChildWorker, &Event, &WorkerTid, 0, NULL)) break;
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, DBG_CONTINUE);
        ContinueFor(20);

        /* A reports: the worker is frozen */
        if (!StartThread(ProcessInfo.hProcess, ChildIdle, &EventA, &Tid, 0, NULL)) break;
        /* B starts while A's event is pending and reports before A is continued */
        if (!StartThread(ProcessInfo.hProcess, ChildIdle, &EventB, &Tid, 200, &EventA)) break;

        ContinueDebugEvent(EventB.dwProcessId, EventB.dwThreadId, DBG_CONTINUE);

        /* Nothing is pending now: the workers must run (on a busy machine a worker may wait for a CPU a while) */
        Before = ReadCounter(ProcessInfo.hProcess);
        for (Wait = 0; Wait < 30; Wait++)
        {
            ContinueFor(100);
            After = ReadCounter(ProcessInfo.hProcess);
            if (After != Before) break;
        }
        if (After == Before) Stuck++;
    }

    ok(Stuck == 0, "The workers did not run after overlapping freezes in %lu of %d rounds\n", Stuck, FREEZE_ROUNDS);

Cleanup:
    TerminateProcess(ProcessInfo.hProcess, 0);
    for (;;)
    {
        if (!WaitForDebugEvent(&Event, EVENT_TIMEOUT))
        {
            ok(0, "No exit-process event\n");
            break;
        }
        if (Event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && Event.u.LoadDll.hFile)
            CloseHandle(Event.u.LoadDll.hFile);
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, DBG_CONTINUE);
        if (Event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
    }
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

START_TEST(DebugFreezeNested)
{
    WCHAR FileName[MAX_PATH];
    char **Argv;
    int Argc = winetest_get_mainargs(&Argv);

    if (Argc >= 3 && !strcmp(Argv[2], "child"))
    {
        Sleep(60000);
        ExitProcess(0);
    }
    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    TestNestedFreeze(FileName);
}
