/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows of a desktop stay in the window list of that desktop
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A thread on a desktop that is not the input desktop creates windows, takes the foreground
 * and moves the focus (the input method window of the thread is then re-ordered). ReactOS
 * linked windows of that desktop into the top-level list of the input desktop, after the
 * last top-most window there. The windows then outlived their desktop: closing it destroyed
 * the desktop heap while the input desktop's list still pointed into it, and a broadcast or
 * a window enumeration of the input desktop used freed memory (a lock count underflow in
 * win32k, an access violation in the shell).
 * The test checks, for the top-level windows of the default desktop, that none belongs to
 * the helper threads of this process, and that the helper's window list holds none of the
 * windows of the default desktop. It then broadcasts a message and closes the desktop.
 */

#include "precomp.h"

#define CYCLE_COUNT 25
#define CHAIN_LIMIT 2000

static const WCHAR g_ClassName[] = L"DesktopWindowSiblingsClass";
static HINSTANCE g_hInst;
static HWND g_hTop;
static HANDLE g_hReady, g_hGo;
static HDESK g_hDesk;
static UINT g_Cycle;
static BOOL g_ThreadOk;

static LRESULT CALLBACK
WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void
Pump(DWORD Ms)
{
    DWORD Start = GetTickCount();
    MSG Msg;

    while (GetTickCount() - Start < Ms)
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&Msg);
            DispatchMessageW(&Msg);
        }
        Sleep(1);
    }
}

/* Count the top-level windows of this desktop (the list GetWindow returns) that belong to Tid
   of this process, and whether Needle is among them. Returns -1 if the list does not end. */
static int
WalkTopLevel(HWND Start, DWORD Tid, HWND Needle, BOOL *pFound)
{
    DWORD Pid, WndTid;
    HWND h;
    int Count = 0, Steps = 0;

    *pFound = FALSE;
    for (h = GetWindow(Start, GW_HWNDFIRST); h; h = GetWindow(h, GW_HWNDNEXT))
    {
        if (++Steps > CHAIN_LIMIT)
            return -1;
        if (h == Needle)
            *pFound = TRUE;
        WndTid = GetWindowThreadProcessId(h, &Pid);
        if (Pid == GetCurrentProcessId() && WndTid == Tid)
            Count++;
    }
    return Count;
}

static DWORD WINAPI
DesktopThread(LPVOID Param)
{
    HWND hwnd1 = NULL, hwnd2 = NULL;
    BOOL Found;
    int Count;

    g_ThreadOk = FALSE;
    if (!SetThreadDesktop(g_hDesk))
    {
        trace("SetThreadDesktop failed, error %lu\n", GetLastError());
        SetEvent(g_hReady);
        return 1;
    }

    hwnd1 = CreateWindowExW(0, g_ClassName, L"one", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                            10, 10, 200, 100, NULL, NULL, g_hInst, NULL);
    if (hwnd1)
    {
        SetForegroundWindow(hwnd1);
        SetActiveWindow(hwnd1);
        SetFocus(hwnd1);
    }
    Pump(20);

    /* The main thread now switches back to the default desktop */
    SetEvent(g_hReady);
    WaitForSingleObject(g_hGo, 15000);

    /* The thread keeps the foreground and moves the focus on a desktop that is not the input desktop */
    hwnd2 = CreateWindowExW(0, g_ClassName, L"two", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                            20, 20, 200, 100, NULL, NULL, g_hInst, NULL);
    if (hwnd2)
        SetFocus(hwnd2);
    if (hwnd1)
        SetFocus(hwnd1);
    Pump(20);

    ok(hwnd1 && hwnd2, "cycle %u: CreateWindow failed, error %lu\n", g_Cycle, GetLastError());

    /* This thread's top-level list must not hold the top-most window of the default desktop */
    Count = WalkTopLevel(hwnd1 ? hwnd1 : hwnd2, GetWindowThreadProcessId(g_hTop, NULL), g_hTop, &Found);
    ok(Count != -1, "cycle %u: the window list of the helper desktop does not end\n", g_Cycle);
    ok(!Found, "cycle %u: the window of the default desktop %p is in the list of the helper desktop\n", g_Cycle, g_hTop);

    if (hwnd2)
        DestroyWindow(hwnd2);
    if (hwnd1)
        DestroyWindow(hwnd1);
    Pump(10);
    g_ThreadOk = TRUE;
    return 0;
}

START_TEST(DesktopWindowSiblings)
{
    HDESK hDefault;
    WNDCLASSW wc;
    DWORD MainTid = GetCurrentThreadId();
    UINT Msg;
    UINT i;
    int bad = 0;

    g_hInst = GetModuleHandleW(NULL);
    hDefault = GetThreadDesktop(MainTid);

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = g_ClassName;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (!RegisterClassW(&wc))
    {
        skip("RegisterClass failed, error %lu\n", GetLastError());
        return;
    }

    /* A top-most window on the default desktop: the window the helper's list was wrongly built after */
    g_hTop = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, g_ClassName, L"top",
                             WS_POPUP | WS_VISIBLE, 0, 0, 20, 20, NULL, NULL, g_hInst, NULL);
    if (!g_hTop)
    {
        skip("CreateWindow failed, error %lu\n", GetLastError());
        return;
    }

    Msg = RegisterWindowMessageW(L"DesktopWindowSiblingsBroadcast");
    g_hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hGo = CreateEventW(NULL, FALSE, FALSE, NULL);

    for (i = 0; i < CYCLE_COUNT; i++)
    {
        WCHAR Name[64];
        HANDLE hThread;
        DWORD ThreadId;
        BOOL Found;
        int Count;
        DWORD_PTR Result;

        wsprintfW(Name, L"DesktopWindowSiblings%lu_%u", GetCurrentProcessId(), i);
        g_hDesk = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        if (!g_hDesk)
        {
            skip("CreateDesktop failed, error %lu\n", GetLastError());
            break;
        }

        g_Cycle = i;
        if (!SwitchDesktop(g_hDesk))
        {
            skip("SwitchDesktop failed, error %lu\n", GetLastError());
            CloseDesktop(g_hDesk);
            break;
        }
        hThread = CreateThread(NULL, 0, DesktopThread, NULL, 0, &ThreadId);
        ok(hThread != NULL, "CreateThread failed, error %lu\n", GetLastError());
        if (!hThread || WaitForSingleObject(g_hReady, 15000) != WAIT_OBJECT_0)
        {
            SwitchDesktop(hDefault);
            ok(0, "cycle %u: the helper thread did not start\n", i);
            break;
        }

        ok(SwitchDesktop(hDefault), "cycle %u: SwitchDesktop back failed, error %lu\n", i, GetLastError());
        SetEvent(g_hGo);

        /* While the helper works: the default desktop's top-level windows must all be ours or other processes' */
        Pump(15);
        Count = WalkTopLevel(g_hTop, ThreadId, NULL, &Found);
        ok(Count != -1, "cycle %u: the window list of the default desktop does not end\n", i);
        if (Count != 0)
            bad++;
        ok(Count == 0, "cycle %u: %d window(s) of the helper thread %lu are in the list of the default desktop\n",
           i, Count, ThreadId);

        ok(WaitForSingleObject(hThread, 15000) == WAIT_OBJECT_0, "cycle %u: the helper thread hung\n", i);
        CloseHandle(hThread);
        ok(g_ThreadOk, "cycle %u: the helper thread failed\n", i);

        ok(CloseDesktop(g_hDesk), "cycle %u: CloseDesktop failed, error %lu\n", i, GetLastError());

        /* Every window of the default desktop must still be usable: a broadcast reaches them all */
        Result = 0;
        SendMessageTimeoutW(HWND_BROADCAST, Msg, 0, 0, SMTO_ABORTIFHUNG, 200, &Result);
        Count = WalkTopLevel(g_hTop, MainTid, g_hTop, &Found);
        ok(Count != -1 && Found, "cycle %u: the default desktop's window list is damaged (%d, found %d)\n", i, Count, Found);

        if (bad > 3)
        {
            skip("stopping after repeated failures\n");
            break;
        }
    }

    DestroyWindow(g_hTop);
    CloseHandle(g_hReady);
    CloseHandle(g_hGo);
    UnregisterClassW(g_ClassName, g_hInst);
}
