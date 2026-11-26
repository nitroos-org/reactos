/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A thread of one desktop reads and draws nothing of a window of another desktop through its DC or
 *              PrintWindow (window surfaces on amd64 keep a window's pixels while its desktop is not on the screen)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A window is created on a second desktop of the window station (not the input desktop) by a thread of that
 * desktop and paints itself one colour. This thread, of the input desktop, takes DCs of it: GetPixel and BitBlt
 * must not return the window's colour, and a fill through such a DC must not reach what the window's own thread
 * reads of it. PrintWindow with PW_RENDERFULLCONTENT (the copy of a surface) does not return its colour either.
 * On i386 (no surfaces) all of this holds as well: the window's DC there draws on the screen, which shows the
 * input desktop.
 */

#include "precomp.h"

#define PW_RENDERFULLCONTENT_ 0x00000002

#define WCOLOUR RGB(0x12, 0x34, 0x56)
#define FCOLOUR RGB(0xAB, 0xCD, 0xEF)

static HDESK g_hDesk;
static HWND g_hwnd;
static HANDLE g_hReady, g_hAsk, g_hAnswer, g_hQuit;
static COLORREF g_SelfPixel;

static LRESULT CALLBACK DeskWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        RECT rc;
        HDC hdc = BeginPaint(hwnd, &ps);
        HBRUSH hbr = CreateSolidBrush(WCOLOUR);

        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, hbr);
        DeleteObject(hbr);
        EndPaint(hwnd, &ps);
        return 0;
    }
    if (msg == WM_ERASEBKGND)
        return 1;
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI DeskThread(LPVOID Param)
{
    HANDLE Events[2];
    MSG msg;

    if (!SetThreadDesktop(g_hDesk))
    {
        SetEvent(g_hReady);
        return 1;
    }
    g_hwnd = CreateWindowExW(WS_EX_NOACTIVATE, L"RedirDesktopClass", L"RedirDesktop", WS_POPUP | WS_VISIBLE,
                             100, 100, 200, 150, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (g_hwnd)
        UpdateWindow(g_hwnd);
    SetEvent(g_hReady);
    Events[0] = g_hQuit;
    Events[1] = g_hAsk;
    for (;;)
    {
        DWORD r = MsgWaitForMultipleObjects(2, Events, FALSE, INFINITE, QS_ALLINPUT);

        if (r == WAIT_OBJECT_0)
            break;
        if (r == WAIT_OBJECT_0 + 1)
        {
            /* What the window's own thread reads of it */
            HDC hdc = GetDC(g_hwnd);
            g_SelfPixel = hdc ? GetPixel(hdc, 10, 10) : CLR_INVALID;
            if (hdc)
                ReleaseDC(g_hwnd, hdc);
            SetEvent(g_hAnswer);
        }
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
    if (g_hwnd)
        DestroyWindow(g_hwnd);
    return 0;
}

static COLORREF AskSelfPixel(void)
{
    SetEvent(g_hAsk);
    WaitForSingleObject(g_hAnswer, 5000);
    return g_SelfPixel;
}

START_TEST(RedirDesktop)
{
    WNDCLASSW wc = { 0 };
    HANDLE hThread;
    HDC hdc, hdcMem;
    HBITMAP hbm;
    COLORREF c, cSelfBefore;
    BOOL bRet;
    RECT rc = { 0, 0, 50, 50 };
    HBRUSH hbr;

    wc.lpfnWndProc = DeskWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"RedirDesktopClass";
    RegisterClassW(&wc);

    g_hDesk = CreateDesktopW(L"RedirDesktopTest", NULL, NULL, 0, GENERIC_ALL, NULL);
    ok(g_hDesk != NULL, "CreateDesktopW failed, error %lu\n", GetLastError());
    if (!g_hDesk)
        return;
    g_hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hAsk = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hAnswer = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, DeskThread, NULL, 0, NULL);
    WaitForSingleObject(g_hReady, 10000);
    ok(g_hwnd != NULL, "No window on the second desktop\n");
    if (!g_hwnd)
        goto Cleanup;
    Sleep(300);
    cSelfBefore = AskSelfPixel();

    /* A DC of the window, taken by a thread of the input desktop */
    hdc = GetDC(g_hwnd);
    ok(hdc != NULL, "GetDC failed, error %lu\n", GetLastError());
    if (hdc)
    {
        c = GetPixel(hdc, 10, 10);
        ok(c != WCOLOUR, "GetPixel through a DC of another desktop's window read its colour\n");

        hdcMem = CreateCompatibleDC(hdc);
        hbm = CreateCompatibleBitmap(hdc, 8, 8);
        SelectObject(hdcMem, hbm);
        bRet = BitBlt(hdcMem, 0, 0, 8, 8, hdc, 8, 8, SRCCOPY);
        c = GetPixel(hdcMem, 2, 2);
        ok(!bRet || c != WCOLOUR, "BitBlt from a DC of another desktop's window copied its colour\n");
        DeleteDC(hdcMem);
        DeleteObject(hbm);

        /* What is drawn through it does not reach the window */
        hbr = CreateSolidBrush(FCOLOUR);
        FillRect(hdc, &rc, hbr);
        DeleteObject(hbr);
        ReleaseDC(g_hwnd, hdc);
    }
    /* (What the window's own thread reads may change meanwhile: a window of a desktop that is not shown paints
       into its surface when its thread first takes a DC of it) */
    c = AskSelfPixel();
    ok(c != FCOLOUR, "A fill through a DC of another desktop's thread reached the window\n");
    trace("Read by the window's own thread: before %06lx, after %06lx\n", cSelfBefore, c);

    /* From here on, read outside the 50 x 50 the fill above aimed at */
    hdc = GetWindowDC(g_hwnd);
    ok(hdc != NULL, "GetWindowDC failed, error %lu\n", GetLastError());
    if (hdc)
    {
        c = GetPixel(hdc, 100, 100);
        ok(c != WCOLOUR, "GetPixel through a window DC of another desktop's window read its colour\n");
        ReleaseDC(g_hwnd, hdc);
    }

    /* PrintWindow with PW_RENDERFULLCONTENT copies a surface: not one of another desktop */
    hdc = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdc);
    hbm = CreateCompatibleBitmap(hdc, 200, 150);
    SelectObject(hdcMem, hbm);
    PatBlt(hdcMem, 0, 0, 200, 150, BLACKNESS);
    bRet = PrintWindow(g_hwnd, hdcMem, PW_RENDERFULLCONTENT_);
    c = GetPixel(hdcMem, 100, 100);
    ok(!bRet || c != WCOLOUR, "PrintWindow(PW_RENDERFULLCONTENT) copied another desktop's window\n");
    DeleteDC(hdcMem);
    DeleteObject(hbm);
    ReleaseDC(NULL, hdc);

Cleanup:
    SetEvent(g_hQuit);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseDesktop(g_hDesk);
    UnregisterClassW(L"RedirDesktopClass", GetModuleHandleW(NULL));
}
