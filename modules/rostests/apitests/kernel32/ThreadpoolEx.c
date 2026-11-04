/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for SetThreadpoolWaitEx and SetThreadpoolTimerEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef struct _TP_WAIT *PTP_WAIT_X;

typedef VOID (CALLBACK *PFN_WAIT_CB)(PVOID, PVOID, PVOID, ULONG);
typedef VOID (CALLBACK *PFN_TIMER_CB)(PVOID, PVOID, PVOID);

static PVOID (WINAPI *pCreateThreadpoolWait)(PFN_WAIT_CB, PVOID, PVOID);
static VOID (WINAPI *pCloseThreadpoolWait)(PVOID);
static VOID (WINAPI *pWaitForThreadpoolWaitCallbacks)(PVOID, BOOL);
static BOOL (WINAPI *pSetThreadpoolWaitEx)(PVOID, HANDLE, PFILETIME, PVOID);
static PVOID (WINAPI *pCreateThreadpoolTimer)(PFN_TIMER_CB, PVOID, PVOID);
static VOID (WINAPI *pCloseThreadpoolTimer)(PVOID);
static VOID (WINAPI *pWaitForThreadpoolTimerCallbacks)(PVOID, BOOL);
static BOOL (WINAPI *pSetThreadpoolTimerEx)(PVOID, PFILETIME, DWORD, DWORD);

static HANDLE g_Done;
static volatile LONG g_WaitResult = -1;
static volatile LONG g_TimerCalls;

static VOID CALLBACK WaitCallback(PVOID Instance, PVOID Context, PVOID Wait, ULONG WaitResult)
{
    InterlockedExchange(&g_WaitResult, (LONG)WaitResult);
    SetEvent(g_Done);
}

static VOID CALLBACK TimerCallback(PVOID Instance, PVOID Context, PVOID Timer)
{
    InterlockedIncrement(&g_TimerCalls);
    SetEvent(g_Done);
}

START_TEST(ThreadpoolEx)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    HANDLE Event;
    PVOID Wait, Timer;
    FILETIME Due;
    LARGE_INTEGER Relative;
    BOOL Ret;

    pSetThreadpoolWaitEx = (void *)GetProcAddress(Kernel32, "SetThreadpoolWaitEx");
    pSetThreadpoolTimerEx = (void *)GetProcAddress(Kernel32, "SetThreadpoolTimerEx");
    pCreateThreadpoolWait = (void *)GetProcAddress(Kernel32, "CreateThreadpoolWait");
    pCloseThreadpoolWait = (void *)GetProcAddress(Kernel32, "CloseThreadpoolWait");
    pWaitForThreadpoolWaitCallbacks = (void *)GetProcAddress(Kernel32, "WaitForThreadpoolWaitCallbacks");
    pCreateThreadpoolTimer = (void *)GetProcAddress(Kernel32, "CreateThreadpoolTimer");
    pCloseThreadpoolTimer = (void *)GetProcAddress(Kernel32, "CloseThreadpoolTimer");
    pWaitForThreadpoolTimerCallbacks = (void *)GetProcAddress(Kernel32, "WaitForThreadpoolTimerCallbacks");

    if (!pSetThreadpoolWaitEx || !pSetThreadpoolTimerEx)
    {
        ok(!is_reactos(), "SetThreadpoolWaitEx or SetThreadpoolTimerEx is not exported\n");
        skip("SetThreadpoolWaitEx is not available\n");
        return;
    }

    g_Done = CreateEventW(NULL, FALSE, FALSE, NULL);
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(g_Done && Event, "CreateEvent failed\n");

    /* wait: signalled event */
    Wait = pCreateThreadpoolWait(WaitCallback, NULL, NULL);
    ok(Wait != NULL, "CreateThreadpoolWait failed with %lu\n", GetLastError());
    if (Wait)
    {
        SetLastError(0xdeadbeef);
        Ret = pSetThreadpoolWaitEx(Wait, Event, NULL, (PVOID)1);
        ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "reserved != NULL: %d, error %lu\n", Ret, GetLastError());

        Ret = pSetThreadpoolWaitEx(Wait, Event, NULL, NULL);
        ok(Ret, "SetThreadpoolWaitEx failed with %lu\n", GetLastError());
        Sleep(100);
        ok(g_WaitResult == -1, "the callback ran before the event was signalled\n");
        SetEvent(Event);
        ok(WaitForSingleObject(g_Done, 10000) == WAIT_OBJECT_0, "the wait callback did not run\n");
        ok(g_WaitResult == WAIT_OBJECT_0, "wait result %ld\n", g_WaitResult);

        /* a timeout of 100 ms of a reset event: WAIT_TIMEOUT */
        ResetEvent(Event);
        g_WaitResult = -1;
        Relative.QuadPart = -100 * 10000LL;
        Due.dwLowDateTime = Relative.LowPart;
        Due.dwHighDateTime = Relative.HighPart;
        Ret = pSetThreadpoolWaitEx(Wait, Event, &Due, NULL);
        ok(Ret, "SetThreadpoolWaitEx with a timeout failed with %lu\n", GetLastError());
        ok(WaitForSingleObject(g_Done, 10000) == WAIT_OBJECT_0, "the timeout callback did not run\n");
        ok(g_WaitResult == WAIT_TIMEOUT, "timeout result %ld\n", g_WaitResult);

        pSetThreadpoolWaitEx(Wait, NULL, NULL, NULL);
        pWaitForThreadpoolWaitCallbacks(Wait, TRUE);
        pCloseThreadpoolWait(Wait);
    }

    /* timer */
    Timer = pCreateThreadpoolTimer(TimerCallback, NULL, NULL);
    ok(Timer != NULL, "CreateThreadpoolTimer failed with %lu\n", GetLastError());
    if (Timer)
    {
        Relative.QuadPart = -50 * 10000LL;
        Due.dwLowDateTime = Relative.LowPart;
        Due.dwHighDateTime = Relative.HighPart;
        Ret = pSetThreadpoolTimerEx(Timer, &Due, 0, 0);
        ok(Ret, "SetThreadpoolTimerEx failed with %lu\n", GetLastError());
        ok(WaitForSingleObject(g_Done, 10000) == WAIT_OBJECT_0, "the timer callback did not run\n");
        ok(g_TimerCalls == 1, "timer calls %ld\n", g_TimerCalls);

        /* cancel a pending timer */
        Relative.QuadPart = -10000 * 10000LL;
        Due.dwLowDateTime = Relative.LowPart;
        Due.dwHighDateTime = Relative.HighPart;
        pSetThreadpoolTimerEx(Timer, &Due, 0, 0);
        Ret = pSetThreadpoolTimerEx(Timer, NULL, 0, 0);
        ok(Ret, "cancelling the timer failed with %lu\n", GetLastError());
        pWaitForThreadpoolTimerCallbacks(Timer, TRUE);
        ok(g_TimerCalls == 1, "the cancelled timer fired: %ld calls\n", g_TimerCalls);
        pCloseThreadpoolTimer(Timer);
    }

    CloseHandle(Event);
    CloseHandle(g_Done);
}
