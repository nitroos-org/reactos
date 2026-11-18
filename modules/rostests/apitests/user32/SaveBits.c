/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for CS_SAVEBITS: what a hidden popup covered is back on the screen at once
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A popup window of a class with CS_SAVEBITS saves the screen under it when it is shown. When it is hidden
 * the saved pixels go back at once, before the window below (owned by a thread that does not run its message
 * loop meanwhile) has painted anything.
 */

#include "precomp.h"

#define BG_COLOR    RGB(0, 0, 160)
#define POP_COLOR   RGB(255, 255, 255)

static BOOL g_bPopPainted, g_bMainPainted;
static COLORREF g_clrMain = BG_COLOR;

static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_ERASEBKGND)
        return 1;
    if (msg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        HBRUSH hbr = CreateSolidBrush(g_clrMain);
        HDC hdc = BeginPaint(hwnd, &ps);
        FillRect(hdc, &ps.rcPaint, hbr);
        EndPaint(hwnd, &ps);
        DeleteObject(hbr);
        g_bMainPainted = TRUE;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK PopProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_ERASEBKGND)
        return 1;
    if (msg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        RECT rc;
        HBRUSH hbr = CreateSolidBrush(POP_COLOR);
        HDC hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, hbr);
        EndPaint(hwnd, &ps);
        DeleteObject(hbr);
        g_bPopPainted = TRUE;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void Pump(DWORD ms)
{
    MSG msg;
    DWORD end = GetTickCount() + ms;

    while (GetTickCount() < end)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

/* Counts the sample points of the rectangle (screen coordinates) that show the colour */
static int CountColor(HDC hdcScreen, const RECT *prc, COLORREF clr)
{
    int x, y, n = 0;

    for (y = prc->top; y < prc->bottom; y += 7)
        for (x = prc->left; x < prc->right; x += 7)
            if (GetPixel(hdcScreen, x, y) == clr)
                n++;
    return n;
}

static int CountPoints(const RECT *prc)
{
    int x, y, n = 0;

    for (y = prc->top; y < prc->bottom; y += 7)
        for (x = prc->left; x < prc->right; x += 7)
            n++;
    return n;
}


#define NEW_COLOR RGB(160, 0, 0)

/* What the screen shows must never be older than what it shows without saved bits: where the window below was
   invalidated or drew while the popup was up, the pixels from before the popup must not come back. */
static void TestTouched(HWND hwndMain, const RECT *prcPop, HDC hdcScreen, BOOL bDirectDraw)
{
    HWND hwndPop;
    int nOld, nPop;

    g_clrMain = BG_COLOR;
    InvalidateRect(hwndMain, NULL, TRUE);
    Pump(200);
    g_bPopPainted = FALSE;
    hwndPop = CreateWindowExW(WS_EX_TOOLWINDOW, L"SaveBitsPop", L"", WS_POPUP | WS_VISIBLE,
                              prcPop->left, prcPop->top, prcPop->right - prcPop->left, prcPop->bottom - prcPop->top,
                              hwndMain, NULL, GetModuleHandleW(NULL), NULL);
    Pump(200);
    nPop = CountColor(hdcScreen, prcPop, POP_COLOR);
    if (!hwndPop || nPop < CountPoints(prcPop) / 2)
    {
        skip("The screen does not show the popup\n");
        if (hwndPop) DestroyWindow(hwndPop);
        return;
    }

    g_clrMain = NEW_COLOR;
    if (bDirectDraw)
    {
        HDC hdc = GetDC(hwndMain);
        HBRUSH hbr = CreateSolidBrush(NEW_COLOR);
        RECT rc;
        GetClientRect(hwndMain, &rc);
        FillRect(hdc, &rc, hbr);
        DeleteObject(hbr);
        ReleaseDC(hwndMain, hdc);
    }
    else
    {
        InvalidateRect(hwndMain, NULL, FALSE);
    }
    ShowWindow(hwndPop, SW_HIDE);
    Sleep(150);
    nOld = CountColor(hdcScreen, prcPop, BG_COLOR);
    /* Drawing through a DC of the window below is clipped away by the popup and cannot be seen by win32k: that case is
       measured by the capture loop (evidence), only the invalidated window is a row */
    if (!bDirectDraw)
        ok(nOld == 0, "Invalidated under the popup: %d of %d points show the colour from before the popup\n", nOld, CountPoints(prcPop));
    Pump(300);
    nOld = CountColor(hdcScreen, prcPop, NEW_COLOR);
    ok(nOld == CountPoints(prcPop), "After the paint %d of %d points show the new colour\n", nOld, CountPoints(prcPop));
    DestroyWindow(hwndPop);
    g_clrMain = BG_COLOR;
    InvalidateRect(hwndMain, NULL, TRUE);
    Pump(200);
}

/* The displayed desktop changes while a popup is shown (the Ctrl+Alt+Del path): what was saved is of no use afterwards.
   Windows of a desktop that is not displayed do not take part: their desktop window is hidden, so showing and hiding them
   never reaches the screen. */
static void TestSwitchDesktop(HWND hwndMain, const RECT *prcPop, HDC hdcScreen)
{
    HDESK hdeskOld = GetThreadDesktop(GetCurrentThreadId()), hdesk2;
    HWND hwndPop;
    int n;

    hdesk2 = CreateDesktopW(L"SaveBitsDesk", NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!hdesk2)
    {
        skip("CreateDesktop failed %lu\n", GetLastError());
        return;
    }
    g_clrMain = BG_COLOR;
    InvalidateRect(hwndMain, NULL, TRUE);
    Pump(200);
    hwndPop = CreateWindowExW(WS_EX_TOOLWINDOW, L"SaveBitsPop", L"", WS_POPUP | WS_VISIBLE,
                              prcPop->left, prcPop->top, prcPop->right - prcPop->left, prcPop->bottom - prcPop->top,
                              hwndMain, NULL, GetModuleHandleW(NULL), NULL);
    Pump(200);

    /* The screen under the popup changes without anything win32k can see (drawn through the DC of the window below) */
    g_clrMain = NEW_COLOR;
    {
        HDC hdc = GetDC(hwndMain);
        HBRUSH hbr = CreateSolidBrush(NEW_COLOR);
        RECT rc;
        GetClientRect(hwndMain, &rc);
        FillRect(hdc, &rc, hbr);
        DeleteObject(hbr);
        ReleaseDC(hwndMain, hdc);
    }
    if (!SwitchDesktop(hdesk2))
    {
        skip("SwitchDesktop failed %lu\n", GetLastError());
    }
    else
    {
        Sleep(200);
        SwitchDesktop(hdeskOld);
        Sleep(300);
        ShowWindow(hwndPop, SW_HIDE);
        Sleep(150);
        /* what is there is for the repaint of the switch to decide; never the pixels from before the popup */
        n = CountColor(hdcScreen, prcPop, BG_COLOR);
        ok(n == 0, "After a desktop switch %d of %d points show the colour from before the popup\n", n, CountPoints(prcPop));
    }
    Pump(300);
    DestroyWindow(hwndPop);
    CloseDesktop(hdesk2);
    g_clrMain = BG_COLOR;
    InvalidateRect(hwndMain, NULL, TRUE);
    Pump(300);
}

/* The display mode changes while a popup is shown: no crash, no pixels of the old mode afterwards */
static void TestModeChange(HWND hwndMain, const RECT *prcPop)
{
    DEVMODEW cur = { .dmSize = sizeof(cur) }, dm = { .dmSize = sizeof(dm) };
    DWORD i;
    BOOL bFound = FALSE;
    HWND hwndPop;
    LONG lRet;

    if (!EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &cur))
        return;
    for (i = 0; EnumDisplaySettingsW(NULL, i, &dm); i++)
    {
        if (dm.dmBitsPerPel == cur.dmBitsPerPel && dm.dmPelsWidth != cur.dmPelsWidth && dm.dmPelsWidth >= 800)
        {
            bFound = TRUE;
            break;
        }
    }
    if (!bFound)
    {
        skip("No other display mode of the same depth\n");
        return;
    }
    hwndPop = CreateWindowExW(WS_EX_TOOLWINDOW, L"SaveBitsPop", L"", WS_POPUP | WS_VISIBLE,
                              prcPop->left, prcPop->top, prcPop->right - prcPop->left, prcPop->bottom - prcPop->top,
                              hwndMain, NULL, GetModuleHandleW(NULL), NULL);
    Pump(200);
    lRet = ChangeDisplaySettingsW(&dm, CDS_FULLSCREEN);
    ok(lRet == DISP_CHANGE_SUCCESSFUL, "ChangeDisplaySettings returned %ld\n", lRet);
    Pump(500);
    if (hwndPop)
    {
        ShowWindow(hwndPop, SW_HIDE);
        DestroyWindow(hwndPop);
    }
    Pump(300);
    ChangeDisplaySettingsW(&cur, CDS_FULLSCREEN);
    Pump(500);
    ok(IsWindow(hwndMain), "The main window is gone\n");
}

START_TEST(SaveBits)
{
    WNDCLASSW wc = { 0 };
    HWND hwndMain, hwndPop;
    HDC hdcScreen;
    RECT rcPop;
    int nPop, nBg;

    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpfnWndProc = MainProc;
    wc.lpszClassName = L"SaveBitsMain";
    ok(RegisterClassW(&wc) != 0, "RegisterClass failed %lu\n", GetLastError());
    wc.style = CS_SAVEBITS;
    wc.lpfnWndProc = PopProc;
    wc.lpszClassName = L"SaveBitsPop";
    ok(RegisterClassW(&wc) != 0, "RegisterClass failed %lu\n", GetLastError());

    hwndMain = CreateWindowExW(0, L"SaveBitsMain", L"main", WS_POPUP | WS_VISIBLE,
                               0, 0, 400, 300, NULL, NULL, wc.hInstance, NULL);
    ok(hwndMain != NULL, "CreateWindow failed %lu\n", GetLastError());
    if (!hwndMain)
        return;
    Pump(300);
    ok(g_bMainPainted, "The main window was not painted\n");

    hdcScreen = GetDC(NULL);
    SetRect(&rcPop, 60, 50, 200, 190);
    g_bPopPainted = FALSE;
    hwndPop = CreateWindowExW(WS_EX_TOOLWINDOW, L"SaveBitsPop", L"", WS_POPUP | WS_VISIBLE,
                              rcPop.left, rcPop.top, rcPop.right - rcPop.left, rcPop.bottom - rcPop.top,
                              hwndMain, NULL, wc.hInstance, NULL);
    ok(hwndPop != NULL, "CreateWindow failed %lu\n", GetLastError());
    Pump(300);
    ok(g_bPopPainted, "The popup was not painted\n");

    nPop = CountColor(hdcScreen, &rcPop, POP_COLOR);
    if (nPop < CountPoints(&rcPop) / 2)
    {
        skip("The screen does not show the popup (%d of %d points)\n", nPop, CountPoints(&rcPop));
    }
    else
    {
        /* Hide it and look at the screen before this thread dispatches another message */
        ShowWindow(hwndPop, SW_HIDE);
        Sleep(150);
        nBg = CountColor(hdcScreen, &rcPop, BG_COLOR);
        ok(nBg == CountPoints(&rcPop), "After SW_HIDE %d of %d points show the window below\n", nBg, CountPoints(&rcPop));

        /* The same when the window is destroyed */
        ShowWindow(hwndPop, SW_SHOWNA);
        Pump(300);
        nPop = CountColor(hdcScreen, &rcPop, POP_COLOR);
        ok(nPop == CountPoints(&rcPop), "The popup shown again: %d of %d points show it\n", nPop, CountPoints(&rcPop));
        DestroyWindow(hwndPop);
        Sleep(150);
        nBg = CountColor(hdcScreen, &rcPop, BG_COLOR);
        ok(nBg == CountPoints(&rcPop), "After DestroyWindow %d of %d points show the window below\n", nBg, CountPoints(&rcPop));

        Pump(200);
        nBg = CountColor(hdcScreen, &rcPop, BG_COLOR);
        ok(nBg == CountPoints(&rcPop), "After the message loop ran %d of %d points show the window below\n", nBg, CountPoints(&rcPop));
    }

    TestTouched(hwndMain, &rcPop, hdcScreen, FALSE);
    TestTouched(hwndMain, &rcPop, hdcScreen, TRUE);
    TestSwitchDesktop(hwndMain, &rcPop, hdcScreen);
    ReleaseDC(NULL, hdcScreen);
    TestModeChange(hwndMain, &rcPop);
    if (IsWindow(hwndPop))
        DestroyWindow(hwndPop);
    DestroyWindow(hwndMain);
    UnregisterClassW(L"SaveBitsPop", wc.hInstance);
    UnregisterClassW(L"SaveBitsMain", wc.hInstance);
}
