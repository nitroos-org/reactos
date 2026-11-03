/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that a window left to paint when its desktop stops being the input desktop is painted
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static const WCHAR s_szClassName[] = L"PaintDesktopSwitchTest";
static const WCHAR s_szDesktopName[] = L"PaintDesktopSwitchTest";

static HANDLE s_hReady, s_hQuit, s_hBlock, s_hBlocked, s_hUnblock;
static HWND s_hwnd;
static volatile LONG s_cPaints;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        InterlockedIncrement(&s_cPaints);
        return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

/* Owns the window and pumps messages like an application waiting in its message loop; when told to,
   it stops pumping (busy elsewhere) until it is released */
static DWORD WINAPI PainterThread(LPVOID Param)
{
    HANDLE ahWait[2] = { s_hQuit, s_hBlock };
    MSG msg;

    s_hwnd = CreateWindowExW(0, s_szClassName, L"PaintDesktopSwitch", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             50, 50, 200, 200, NULL, NULL, GetModuleHandleW(NULL), NULL);
    SetEvent(s_hReady);
    if (!s_hwnd)
        return 1;
    for (;;)
    {
        DWORD dwRet = MsgWaitForMultipleObjects(2, ahWait, FALSE, INFINITE, QS_ALLINPUT);
        if (dwRet == WAIT_OBJECT_0 + 1)
        {
            SetEvent(s_hBlocked);
            WaitForSingleObject(s_hUnblock, 30000);
            continue;
        }
        /* Also checked here: a paint that was never delivered kept QS_PAINT set, so input was always
           reported and the quit event never was (the thread spun) */
        if (dwRet != WAIT_OBJECT_0 + 2 || WaitForSingleObject(s_hQuit, 0) == WAIT_OBJECT_0)
            break;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    DestroyWindow(s_hwnd);
    return 0;
}

/* Wait until the window has no update region, at most dwTimeout ms */
static BOOL WaitPainted(DWORD dwTimeout)
{
    DWORD dwStart = GetTickCount();

    while (GetUpdateRect(s_hwnd, NULL, FALSE))
    {
        if (GetTickCount() - dwStart >= dwTimeout)
            return FALSE;
        Sleep(20);
    }
    return TRUE;
}

START_TEST(PaintDesktopSwitch)
{
    WNDCLASSW wc = { 0 };
    HDESK hdeskInput, hdeskTest = NULL;
    HANDLE hThread = NULL;
    BOOL bOnTestDesktop = FALSE, bBlocked, bAway;
    LONG cPaints;

    hdeskInput = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (!hdeskInput)
    {
        skip("OpenInputDesktop failed (%lu)\n", GetLastError());
        return;
    }

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = s_szClassName;
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed (%lu)\n", GetLastError());

    s_hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
    s_hBlock = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hBlocked = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hUnblock = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(s_hReady && s_hQuit && s_hBlock && s_hBlocked && s_hUnblock, "CreateEventW failed (%lu)\n", GetLastError());
    if (!s_hReady || !s_hQuit || !s_hBlock || !s_hBlocked || !s_hUnblock)
        goto Cleanup;

    hThread = CreateThread(NULL, 0, PainterThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed (%lu)\n", GetLastError());
    if (!hThread || WaitForSingleObject(s_hReady, 30000) != WAIT_OBJECT_0 || !s_hwnd)
    {
        ok(FALSE, "The window was not created\n");
        goto Cleanup;
    }
    ok(WaitPainted(5000), "The window was not painted after its creation\n");

    hdeskTest = CreateDesktopW(s_szDesktopName, NULL, NULL, 0, GENERIC_ALL, NULL);
    ok(hdeskTest != NULL, "CreateDesktopW failed (%lu)\n", GetLastError());
    if (!hdeskTest)
        goto Cleanup;

    /* The window needs painting, its thread is busy, and then another desktop becomes the input desktop */
    SetEvent(s_hBlock);
    bBlocked = (WaitForSingleObject(s_hBlocked, 30000) == WAIT_OBJECT_0);
    ok(bBlocked, "The thread did not stop pumping\n");
    if (!bBlocked)
        goto Cleanup;
    cPaints = s_cPaints;
    ok(InvalidateRect(s_hwnd, NULL, TRUE), "InvalidateRect failed (%lu)\n", GetLastError());
    bOnTestDesktop = SwitchDesktop(hdeskTest);
    ok(bOnTestDesktop, "SwitchDesktop(test) failed (%lu)\n", GetLastError());
    /* The thread gets back to its message loop while its desktop is not the input desktop */
    SetEvent(s_hUnblock);
    Sleep(1000);
    bAway = GetUpdateRect(s_hwnd, NULL, FALSE);
    trace("while away: update region %d, WM_PAINT %ld -> %ld\n", bAway, cPaints, s_cPaints);
    if (!bOnTestDesktop)
        goto Cleanup;

    bOnTestDesktop = !SwitchDesktop(hdeskInput);
    ok(!bOnTestDesktop, "SwitchDesktop(input) failed (%lu)\n", GetLastError());
    if (bOnTestDesktop)
        goto Cleanup;

    /* Back on the input desktop the window is painted (it was left dirty with no paint pending, and
       never got WM_PAINT again: stale pixels where a closed window had been) */
    ok(WaitPainted(3000), "The window was not painted after the switch back\n");
    ok(s_cPaints > cPaints, "No WM_PAINT after the switch back (%ld, %ld)\n", s_cPaints, cPaints);
    cPaints = s_cPaints;
    ok(InvalidateRect(s_hwnd, NULL, TRUE), "InvalidateRect failed (%lu)\n", GetLastError());
    ok(WaitPainted(3000), "The window was not painted after a later invalidation\n");
    ok(s_cPaints > cPaints, "No WM_PAINT after a later invalidation (%ld, %ld)\n", s_cPaints, cPaints);

Cleanup:
    if (bOnTestDesktop)
        ok(SwitchDesktop(hdeskInput), "SwitchDesktop(input) failed in cleanup (%lu)\n", GetLastError());
    if (hThread)
    {
        SetEvent(s_hUnblock);
        SetEvent(s_hQuit);
        if (WaitForSingleObject(hThread, 30000) != WAIT_OBJECT_0)
        {
            skip("The thread is still running, resources are left in place\n");
            return;
        }
        CloseHandle(hThread);
    }
    if (hdeskTest)
        CloseDesktop(hdeskTest);
    if (s_hReady)
        CloseHandle(s_hReady);
    if (s_hQuit)
        CloseHandle(s_hQuit);
    if (s_hBlock)
        CloseHandle(s_hBlock);
    if (s_hBlocked)
        CloseHandle(s_hBlocked);
    if (s_hUnblock)
        CloseHandle(s_hUnblock);
    CloseDesktop(hdeskInput);
    UnregisterClassW(s_szClassName, GetModuleHandleW(NULL));
}
