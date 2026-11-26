/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The class DC of a CS_CLASSDC class works after the window that had it was destroyed and after the
 *              thread that created the class's first window ended
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A class DC belongs to the thread of the window it was made for. When that window is destroyed the DC goes to the
 * DC cache and is freed when the thread ends, while the class lives on in the process. Windows of the class made
 * later, or still there, by another thread must get a working DC (GetDC and the paint DC draw into the window).
 */

#include "precomp.h"

#define CLASSNAME L"ClassDCThreadExitClass"
#define PAINTCOLOUR RGB(0x21, 0x43, 0x65)

static HDC g_hdcPaint;
static COLORREF g_PaintPixel;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        RECT rc;
        HBRUSH hbr;
        HDC hdc = BeginPaint(hwnd, &ps);

        g_hdcPaint = hdc;
        if (hdc)
        {
            GetClientRect(hwnd, &rc);
            hbr = CreateSolidBrush(PAINTCOLOUR);
            FillRect(hdc, &rc, hbr);
            DeleteObject(hbr);
            g_PaintPixel = GetPixel(hdc, 5, 5);
        }
        EndPaint(hwnd, &ps);
        /* Without a paint DC nothing was validated: no endless WM_PAINT (the test fails instead of hanging) */
        if (!hdc)
            ValidateRect(hwnd, NULL);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static HWND MakeWindow(int x)
{
    return CreateWindowExW(0, CLASSNAME, L"classdc", WS_POPUP | WS_VISIBLE, x, 100, 120, 90, NULL, NULL,
                           GetModuleHandleW(NULL), NULL);
}

static void Pump(void)
{
    MSG msg;
    DWORD Start = GetTickCount();

    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE) && GetTickCount() - Start < 2000)
        DispatchMessageW(&msg);
}

/* The class's first window: made, drawn through the class DC, destroyed (or left to the thread's end) */
static DWORD WINAPI FirstWindowThread(LPVOID Param)
{
    HWND hwnd = MakeWindow(50);
    HDC hdc;

    if (!hwnd)
        return 1;
    UpdateWindow(hwnd);
    hdc = GetDC(hwnd);
    if (hdc)
        ReleaseDC(hwnd, hdc);
    Pump();
    if (Param)
        DestroyWindow(hwnd);
    return 0;
}

static HDESK g_hDesk2;
static LONG g_OtherDeskResult;

/* Round 3: on a second desktop, a window of the class (a clone of it there) draws through its class DC */
static DWORD WINAPI OtherDesktopThread(LPVOID Param)
{
    HWND hwnd;
    HDC hdc;
    HBRUSH hbr;
    RECT rc = { 0, 0, 20, 20 };

    g_OtherDeskResult = -1;
    if (!SetThreadDesktop(g_hDesk2))
        return 1;
    hwnd = MakeWindow(50);
    if (!hwnd)
        return 2;
    UpdateWindow(hwnd);
    /* (Its pixels are not checked: on a desktop that is not shown a window DC draws nothing on i386) */
    hdc = GetDC(hwnd);
    g_OtherDeskResult = 0;
    if (hdc)
    {
        hbr = CreateSolidBrush(RGB(0x10, 0x80, 0x30));
        g_OtherDeskResult = FillRect(hdc, &rc, hbr) ? 1 : 2;
        DeleteObject(hbr);
        ReleaseDC(hwnd, hdc);
    }
    DestroyWindow(hwnd);
    Pump();
    return 0;
}

static void CheckWindow(HWND hwnd, const char *what)
{
    HDC hdc;
    HBRUSH hbr;
    RECT rc = { 0, 0, 20, 20 };

    ok(hwnd != NULL, "%s: no window\n", what);
    if (!hwnd)
        return;
    hdc = GetDC(hwnd);
    ok(hdc != NULL, "%s: GetDC failed\n", what);
    if (hdc)
    {
        hbr = CreateSolidBrush(RGB(0x10, 0x80, 0x30));
        ok(FillRect(hdc, &rc, hbr), "%s: FillRect through the class DC failed\n", what);
        DeleteObject(hbr);
        ok(GetPixel(hdc, 5, 5) == RGB(0x10, 0x80, 0x30), "%s: the class DC does not draw into the window: %06lx\n",
           what, GetPixel(hdc, 5, 5));
        ReleaseDC(hwnd, hdc);
    }
    g_hdcPaint = NULL;
    g_PaintPixel = CLR_INVALID;
    InvalidateRect(hwnd, NULL, TRUE);
    UpdateWindow(hwnd);
    ok(g_hdcPaint != NULL, "%s: BeginPaint gave no DC\n", what);
    ok(g_PaintPixel == PAINTCOLOUR, "%s: the paint DC does not draw into the window: %06lx\n", what, g_PaintPixel);
}

START_TEST(ClassDCThreadExit)
{
    WNDCLASSW wc = { 0 };
    HANDLE hThread;
    HWND hwndLater, hwndThere;
    int Round;

    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = CLASSNAME;
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    for (Round = 0; Round < 2; Round++)
    {
        /* Round 0: the first window is destroyed by its thread; round 1: it goes with its thread */
        hwndThere = (Round == 1) ? MakeWindow(400) : NULL;
        if (hwndThere)
            UpdateWindow(hwndThere);
        hThread = CreateThread(NULL, 0, FirstWindowThread, (LPVOID)(INT_PTR)(Round == 0), 0, NULL);
        ok(hThread != NULL, "CreateThread failed\n");
        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
        Pump();

        hwndLater = MakeWindow(250);
        CheckWindow(hwndLater, Round ? "round 1, a later window" : "round 0, a later window");
        if (hwndThere)
            CheckWindow(hwndThere, "round 1, a window that was there");
        DestroyWindow(hwndLater);
        if (hwndThere)
            DestroyWindow(hwndThere);
        Pump();
    }

    /* Round 2: one thread; the window that had the class DC is destroyed, the next window of the class draws */
    FirstWindowThread((LPVOID)1);
    Pump();
    hwndLater = MakeWindow(250);
    CheckWindow(hwndLater, "round 2, the same thread");
    DestroyWindow(hwndLater);
    Pump();

    /*
     * Round 3: a window of the class on a second desktop (the class is cloned there), drawn through its class DC by a
     * thread that then ends; a window of the class here still draws, and the class goes away cleanly
     */
    hwndThere = MakeWindow(400);
    UpdateWindow(hwndThere);
    g_hDesk2 = CreateDesktopW(L"ClassDCThreadExitDesk", NULL, NULL, 0, GENERIC_ALL, NULL);
    ok(g_hDesk2 != NULL, "CreateDesktopW failed, error %lu\n", GetLastError());
    if (g_hDesk2)
    {
        hThread = CreateThread(NULL, 0, OtherDesktopThread, NULL, 0, NULL);
        WaitForSingleObject(hThread, 10000);
        CloseHandle(hThread);
        ok(g_OtherDeskResult == 1, "round 3: the window of the class on the second desktop got no class DC (%ld)\n", g_OtherDeskResult);
    }
    Pump();
    CheckWindow(hwndThere, "round 3, a window here after the clone's thread ended");
    DestroyWindow(hwndThere);
    Pump();
    ok(UnregisterClassW(CLASSNAME, GetModuleHandleW(NULL)), "UnregisterClassW failed, error %lu\n", GetLastError());
    if (g_hDesk2)
        CloseDesktop(g_hDesk2);
}
