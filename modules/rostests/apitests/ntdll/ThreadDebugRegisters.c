/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for hardware breakpoints set on a thread that has not started yet (x64 and WoW64)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A thread created suspended can be given debug registers before it runs, and then runs with the breakpoint
 * armed. Measured on Windows 10 22H2, x64 and WOW64 processes: a write breakpoint set that way hits in the new
 * thread, as it does on a thread that already ran. A WoW64 thread has its 32-bit start context until it first
 * runs, and the debug registers have to reach that context in a form its first load applies.
 */

#include "precomp.h"

#define DR7_WRITE4_DR0 (0x1 | (0x1 << 16) | (0x3 << 18))

static volatile LONG DtTarget;
static volatile LONG DtHits;
static volatile LONG DtHitsInNew;
static volatile LONG DtNewId;
static volatile LONG DtStarted;

static LONG CALLBACK DtHandler(PEXCEPTION_POINTERS Info)
{
    if (Info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&DtHits);
    if (GetCurrentThreadId() == (DWORD)DtNewId)
        InterlockedIncrement(&DtHitsInNew);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI DtThread(PVOID Param)
{
    ULONG i;

    if (Param)
    {
        /* the thread already runs when its breakpoint is set */
        InterlockedExchange(&DtStarted, 1);
        while (DtStarted != 2)
            Sleep(1);
    }
    for (i = 0; i < 3; i++)
    {
        DtTarget = i + 1;
        Sleep(10);
    }
    return 0;
}

static BOOL DtSet(HANDLE Thread, ULONG ContextFlags)
{
    CONTEXT Context;

    ZeroMemory(&Context, sizeof(Context));
    if (ContextFlags != CONTEXT_DEBUG_REGISTERS)
    {
        /* the other groups are the start state of a thread that has not run: keep them as they are */
        Context.ContextFlags = ContextFlags;
        ok(GetThreadContext(Thread, &Context), "GetThreadContext failed %lu\n", GetLastError());
    }
    Context.ContextFlags = ContextFlags;
    Context.Dr0 = (ULONG_PTR)&DtTarget;
    Context.Dr1 = Context.Dr2 = Context.Dr3 = 0;
    Context.Dr6 = 0;
    Context.Dr7 = DR7_WRITE4_DR0;
    return SetThreadContext(Thread, &Context);
}

static void DtRun(const char *Name, BOOL Running, ULONG ContextFlags)
{
    HANDLE Thread;
    CONTEXT Context;
    DWORD Wait;

    DtHits = DtHitsInNew = DtNewId = DtStarted = 0;
    DtTarget = 0;
    Thread = CreateThread(NULL, 0, DtThread, Running ? (PVOID)1 : NULL, Running ? 0 : CREATE_SUSPENDED, NULL);
    ok(Thread != NULL, "%s: CreateThread failed %lu\n", Name, GetLastError());
    if (!Thread)
        return;
    DtNewId = (LONG)GetThreadId(Thread);
    if (Running)
    {
        while (!DtStarted)
            Sleep(1);
        ok(SuspendThread(Thread) != (DWORD)-1, "%s: SuspendThread failed %lu\n", Name, GetLastError());
    }
    ok(DtSet(Thread, ContextFlags), "%s: SetThreadContext failed %lu\n", Name, GetLastError());

    ZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    ok(GetThreadContext(Thread, &Context), "%s: GetThreadContext failed %lu\n", Name, GetLastError());
    ok(Context.Dr0 == (ULONG_PTR)&DtTarget, "%s: Dr0 %Ix\n", Name, (ULONG_PTR)Context.Dr0);
    ok((Context.Dr7 & 0xf0003) == 0xd0001, "%s: Dr7 %Ix\n", Name, (ULONG_PTR)Context.Dr7);

    ResumeThread(Thread);
    if (Running)
        InterlockedExchange(&DtStarted, 2);
    Wait = WaitForSingleObject(Thread, 30000);
    ok_eq_ulong(Wait, WAIT_OBJECT_0);
    CloseHandle(Thread);
    ok(DtTarget == 3, "%s: the thread wrote %ld\n", Name, DtTarget);
    ok(DtHitsInNew == 3, "%s: %ld breakpoint hits in the new thread, expected 3 (%ld in all)\n", Name, DtHitsInNew, DtHits);
}

START_TEST(ThreadDebugRegisters)
{
    PVOID Handler;
#ifdef _M_IX86
    BOOL IsWow64 = FALSE;

    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (!IsWow64)
    {
        skip("Debug register checks run on x64 and WoW64 only\n");
        return;
    }
#endif
    Handler = AddVectoredExceptionHandler(TRUE, DtHandler);
    ok(Handler != NULL, "AddVectoredExceptionHandler failed\n");

    DtRun("running thread", TRUE, CONTEXT_DEBUG_REGISTERS);
    DtRun("new thread", FALSE, CONTEXT_DEBUG_REGISTERS);
    DtRun("new thread, full", FALSE, CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS);
    DtRun("new thread again", FALSE, CONTEXT_DEBUG_REGISTERS);

    RemoveVectoredExceptionHandler(Handler);
}
