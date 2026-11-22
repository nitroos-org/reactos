/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The foreground window comes back when the input desktop is deleted
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The test switches the input to a desktop it made and closes its only handle while that desktop
 * has the input: the desktop is deleted and the input goes back to the desktop the test runs on.
 * The foreground window of that desktop is the foreground window again, and keys reach it, as
 * after SwitchDesktop back.
 */

#include "precomp.h"

static LONG g_Keys;

static LRESULT CALLBACK
WndProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_KEYDOWN && wParam == 'Q')
        InterlockedIncrement(&g_Keys);
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static void
Pump(DWORD Ms)
{
    DWORD End = GetTickCount() + Ms;
    MSG msg;

    while ((LONG)(End - GetTickCount()) > 0)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

static BOOL
InputDesktopIs(PCWSTR Name)
{
    WCHAR Buffer[64] = L"";
    DWORD Needed;
    HDESK hDesk = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    BOOL Ret = FALSE;

    if (hDesk)
    {
        if (GetUserObjectInformationW(hDesk, UOI_NAME, Buffer, sizeof(Buffer), &Needed))
            Ret = !_wcsicmp(Buffer, Name);
        CloseDesktop(hDesk);
    }
    return Ret;
}

/* A thread on the new desktop asks for its desktop window to be the foreground window (the queue of the desktop
   window thread, which serves every desktop, can then be remembered as that desktop's foreground queue) */
static DWORD WINAPI
DesktopWindowForeground(LPVOID Param)
{
    if (!SetThreadDesktop((HDESK)Param))
        return 1;
    SetForegroundWindow(GetDesktopWindow());
    trace("Foreground window on the new desktop %p (desktop window %p)\n", GetForegroundWindow(), GetDesktopWindow());
    return 0;
}

START_TEST(InputDesktopDeleted)
{
    WNDCLASSW wc = { 0 };
    WCHAR HomeName[64] = L"";
    DWORD Needed, i;
    HDESK hHome, hDesk;
    HWND hWnd;
    HANDLE hThread;
    BOOL Ret;

    hHome = GetThreadDesktop(GetCurrentThreadId());
    if (!GetUserObjectInformationW(hHome, UOI_NAME, HomeName, sizeof(HomeName), &Needed) ||
        !InputDesktopIs(HomeName))
    {
        skip("The test does not run on the input desktop\n");
        return;
    }

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"InputDesktopDeleted";
    RegisterClassW(&wc);
    hWnd = CreateWindowW(L"InputDesktopDeleted", L"InputDesktopDeleted", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                         100, 100, 300, 200, NULL, NULL, wc.hInstance, NULL);
    ok(hWnd != NULL, "CreateWindow failed: %lu\n", GetLastError());
    if (!hWnd)
        return;
    SetForegroundWindow(hWnd);
    Pump(200);
    if (GetForegroundWindow() != hWnd)
    {
        skip("The test window is not the foreground window (%p)\n", GetForegroundWindow());
        DestroyWindow(hWnd);
        return;
    }

    hDesk = CreateDesktopW(L"InputDesktopDeletedB", NULL, NULL, 0, GENERIC_ALL, NULL);
    ok(hDesk != NULL, "CreateDesktop failed: %lu\n", GetLastError());
    if (!hDesk)
    {
        DestroyWindow(hWnd);
        return;
    }
    Ret = SwitchDesktop(hDesk);
    ok(Ret, "SwitchDesktop failed: %lu\n", GetLastError());
    if (Ret)
    {
        ok(InputDesktopIs(L"InputDesktopDeletedB"), "The new desktop does not have the input\n");
        ok(GetForegroundWindow() == NULL, "Foreground window %p while another desktop has the input\n", GetForegroundWindow());
        hThread = CreateThread(NULL, 0, DesktopWindowForeground, hDesk, 0, NULL);
        ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (hThread)
        {
            ok(WaitForSingleObject(hThread, 5000) == WAIT_OBJECT_0, "The thread did not end\n");
            CloseHandle(hThread);
        }
    }

    /* The only handle: the desktop is deleted, the input goes back */
    ok(CloseDesktop(hDesk), "CloseDesktop failed: %lu\n", GetLastError());
    for (i = 0; i < 50 && !InputDesktopIs(HomeName); i++)
        Sleep(20);
    ok(InputDesktopIs(HomeName), "The input did not come back to %ls\n", HomeName);
    Pump(100);

    ok(GetForegroundWindow() == hWnd, "Foreground window %p, expected %p\n", GetForegroundWindow(), hWnd);

    g_Keys = 0;
    keybd_event('Q', 0, 0, 0);
    keybd_event('Q', 0, KEYEVENTF_KEYUP, 0);
    Pump(200);
    ok(g_Keys == 1, "%ld keys reached the foreground window, expected 1\n", g_Keys);

    if (GetForegroundWindow() != hWnd)
        SwitchDesktop(hHome);
    DestroyWindow(hWnd);
    UnregisterClassW(L"InputDesktopDeleted", wc.hInstance);
}
