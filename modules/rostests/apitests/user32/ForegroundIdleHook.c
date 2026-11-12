/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         WH_FOREGROUNDIDLE runs when the foreground thread is about to wait for input
 *                  (GetMessage, WaitMessage, MsgWaitForMultipleObjectsEx), not from PeekMessage.
 *                  Toolkits whose hook posts a message to the thread (SWT does) depend on it.
 */

#include "precomp.h"

static volatile LONG g_calls;
static volatile LONG g_repost;
static DWORD g_tid;

static LRESULT CALLBACK IdleProc(int code, WPARAM wParam, LPARAM lParam)
{
    InterlockedIncrement(&g_calls);
    if (g_repost)
        PostThreadMessageW(g_tid, WM_NULL, 0, 0);
    return CallNextHookEx(NULL, code, wParam, lParam);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

START_TEST(ForegroundIdleHook)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    HHOOK hook;
    MSG msg;
    DWORD start;
    LONG before, timers, capped, i;
    int k;

    g_tid = GetCurrentThreadId();
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ForegroundIdleHookClass";
    RegisterClassW(&wc);
    hwnd = CreateWindowW(wc.lpszClassName, L"idle", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 200, 100,
                         NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "CreateWindow failed %lu\n", GetLastError());
    if (!hwnd)
        return;
    SetForegroundWindow(hwnd);
    for (i = 0; i < 20; i++)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(25);
    }
    if (GetForegroundWindow() != hwnd)
    {
        skip("the test window is not in the foreground, no idle hook\n");
        DestroyWindow(hwnd);
        return;
    }

    hook = SetWindowsHookExW(WH_FOREGROUNDIDLE, IdleProc, NULL, g_tid);
    ok(hook != NULL, "SetWindowsHookEx failed %lu\n", GetLastError());
    if (!hook)
    {
        DestroyWindow(hwnd);
        return;
    }

    /* PeekMessage with an empty queue does not call the hook, however often it is called */
    before = g_calls;
    start = GetTickCount();
    while (GetTickCount() - start < 300)
        PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE);
    ok(g_calls == before, "PeekMessage: %ld hook calls\n", g_calls - before);

    /* ... so a hook that posts to the thread cannot keep a polling loop fed */
    g_repost = 1;
    before = g_calls;
    start = GetTickCount();
    while (GetTickCount() - start < 300)
    {
        if (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
    g_repost = 0;
    ok(g_calls == before, "PeekMessage with a reposting hook: %ld hook calls\n", g_calls - before);
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);

    /* GetMessage and WaitMessage that block call it, once per wait */
    SetTimer(hwnd, 1, 50, NULL);
    before = g_calls;
    timers = 0;
    while (timers < 5 && GetMessageW(&msg, NULL, 0, 0))
    {
        if (msg.message == WM_TIMER)
            timers++;
        DispatchMessageW(&msg);
    }
    ok(g_calls - before >= 1, "GetMessage: no hook call\n");
    ok(g_calls - before <= 3 * timers, "GetMessage: %ld hook calls for %ld timer messages\n", g_calls - before, timers);

    before = g_calls;
    timers = 0;
    while (timers < 5)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_TIMER)
                timers++;
            DispatchMessageW(&msg);
        }
        WaitMessage();
    }
    ok(g_calls - before >= 1, "WaitMessage: no hook call\n");
    ok(g_calls - before <= 3 * timers, "WaitMessage: %ld hook calls for %ld timer messages\n", g_calls - before, timers);
    KillTimer(hwnd, 1);
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);

    /* MsgWaitForMultipleObjectsEx: once per wait that has nothing to return at once */
    before = g_calls;
    for (i = 0; i < 5; i++)
        MsgWaitForMultipleObjectsEx(0, NULL, 50, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    ok(g_calls - before == 5, "MsgWaitForMultipleObjectsEx: %ld hook calls for 5 waits\n", g_calls - before);

    /* The loop of a toolkit: read until the queue is empty, then wait; the hook posts a message each time it
     * runs. The wait returns at once, and the next read drains that message and ends */
    g_repost = 1;
    capped = 0;
    for (i = 0; i < 100; i++)
    {
        k = 0;
        while (k < 2000 && PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            k++;
            DispatchMessageW(&msg);
        }
        if (k >= 2000)
            capped++;
        MsgWaitForMultipleObjectsEx(0, NULL, 50, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    }
    g_repost = 0;
    ok(capped == 0, "%ld of 100 read loops never saw the queue empty\n", capped);
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);

    UnhookWindowsHookEx(hook);
    DestroyWindow(hwnd);
}
