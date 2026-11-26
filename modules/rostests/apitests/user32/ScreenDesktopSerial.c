/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A screen DC got for a desktop that is gone does not reach the screen of a desktop made later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A helper thread on a scratch desktop X opens CreateDC("DISPLAY"), moves to the desktop of the test and X is closed (it is
 * freed). Then a new desktop Y, made the same way (a freed desktop's address is likely to be taken by the next one), gets the
 * input and a window of a known colour. The DC of the dead desktop must read nothing of Y's screen (it names X, and X is not
 * the desktop with the input): BitBlt from it fails with 6, GetPixel gives CLR_INVALID. Several rounds, to make the reuse likely.
 */

#include "precomp.h"

#define Y_COLOR RGB(0x21, 0x84, 0xC6)

static HDESK s_hdeskX, s_hdeskA, s_hdeskY;
static HDC s_hdcHeld;
static HANDLE s_hMade, s_hQuit, s_hReadyY;
static HWND s_hwndY;
static int s_cx, s_cy;

static DWORD WINAPI MakerThread(LPVOID Param)
{
    if (!SetThreadDesktop(s_hdeskX))
        return 1;
    s_hdcHeld = CreateDCW(L"DISPLAY", NULL, NULL, NULL);
    SetThreadDesktop(s_hdeskA);
    SetEvent(s_hMade);
    return 0;
}

static LRESULT CALLBACK WndProcY(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static DWORD WINAPI ThreadY(LPVOID Param)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    MSG msg;

    if (!SetThreadDesktop(s_hdeskY))
        return 1;
    wc.lpfnWndProc = WndProcY;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ScreenDesktopSerialY";
    wc.hbrBackground = CreateSolidBrush(Y_COLOR);
    RegisterClassW(&wc);
    hwnd = CreateWindowExW(0, wc.lpszClassName, L"Y", WS_POPUP | WS_VISIBLE, 0, 0, s_cx, s_cy, NULL, NULL, wc.hInstance, NULL);
    s_hwndY = hwnd;
    SetEvent(s_hReadyY);
    while (hwnd && WaitForSingleObject(s_hQuit, 20) == WAIT_TIMEOUT)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
    if (hwnd)
        DestroyWindow(hwnd);
    return 0;
}

START_TEST(ScreenDesktopSerial)
{
    int round, x, y;

    s_hdeskA = GetThreadDesktop(GetCurrentThreadId());
    s_cx = GetSystemMetrics(SM_CXSCREEN);
    s_cy = GetSystemMetrics(SM_CYSCREEN);
    s_hMade = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hReadyY = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);

    for (round = 0; round < 6; round++)
    {
        HANDLE hMaker, hY;
        DWORD err;
        BOOL ret;
        COLORREF px;
        HDC hdcMem;
        HBITMAP hbm, hbmOld;
        int cColor = 0;

        s_hdeskX = CreateDesktopW(L"ScreenDesktopSerialX", NULL, NULL, 0, GENERIC_ALL, NULL);
        if (!s_hdeskX)
        {
            skip("CreateDesktop failed (%lu)\n", GetLastError());
            return;
        }
        s_hdcHeld = NULL;
        hMaker = CreateThread(NULL, 0, MakerThread, NULL, 0, NULL);
        ok(WaitForSingleObject(s_hMade, 10000) == WAIT_OBJECT_0, "the helper thread did not finish\n");
        WaitForSingleObject(hMaker, 5000);
        CloseHandle(hMaker);
        ok(s_hdcHeld != NULL, "CreateDC failed\n");
        CloseDesktop(s_hdeskX);   /* X is freed (nothing is on it, no thread is attached) */

        s_hdeskY = CreateDesktopW(L"ScreenDesktopSerialY", NULL, NULL, 0, GENERIC_ALL, NULL);
        ok(s_hdeskY != NULL, "CreateDesktop Y failed (%lu)\n", GetLastError());
        if (!s_hdeskY)
            break;
        ResetEvent(s_hQuit);
        hY = CreateThread(NULL, 0, ThreadY, NULL, 0, NULL);
        WaitForSingleObject(s_hReadyY, 10000);
        if (!SwitchDesktop(s_hdeskY))
        {
            skip("SwitchDesktop failed (%lu)\n", GetLastError());
            SetEvent(s_hQuit);
            WaitForSingleObject(hY, 5000);
            CloseHandle(hY);
            CloseDesktop(s_hdeskY);
            DeleteDC(s_hdcHeld);
            break;
        }
        Sleep(500);   /* Y paints */

        /* the DC of the dead desktop X: blind while Y has the input */
        px = GetPixel(s_hdcHeld, s_cx / 2, s_cy / 2);
        ok(px == CLR_INVALID, "round %d: GetPixel through the DC of a dead desktop read 0x%08lx\n", round, px);
        hdcMem = CreateCompatibleDC(s_hdcHeld);
        hbm = CreateCompatibleBitmap(s_hdcHeld, 64, 64);
        hbmOld = SelectObject(hdcMem, hbm);
        PatBlt(hdcMem, 0, 0, 64, 64, BLACKNESS);
        SetLastError(0);
        ret = BitBlt(hdcMem, 0, 0, 64, 64, s_hdcHeld, s_cx / 2, s_cy / 2, SRCCOPY);
        err = ret ? 0 : GetLastError();
        for (y = 0; y < 64; y++)
            for (x = 0; x < 64; x++)
                if (GetPixel(hdcMem, x, y) == Y_COLOR)
                    cColor++;
        ok(!ret && err == ERROR_INVALID_HANDLE, "round %d: BitBlt through the DC of a dead desktop: %d, error %lu\n", round, ret, err);
        ok(cColor == 0, "round %d: %d pixels of the screen of the desktop with the input were copied\n", round, cColor);
        SelectObject(hdcMem, hbmOld);

        /* Window handles are not checked against the desktop of the caller: the DC of a window of Y (the desktop with the input)
           asked for by this thread on A reaches the screen of A, which is not shown */
        {
            HDC hdcWnd = GetWindowDC(s_hwndY);

            ok(hdcWnd != NULL, "round %d: no DC of the window of the other desktop\n", round);
            if (hdcWnd)
            {
                px = GetPixel(hdcWnd, 2, 2);
                ok(px == CLR_INVALID, "round %d: GetPixel through the DC of a window of the desktop with the input read 0x%08lx\n", round, px);
                SetLastError(0);
                ret = BitBlt(hdcMem, 0, 0, 64, 64, hdcWnd, 0, 0, SRCCOPY);
                ok(!ret, "round %d: BitBlt from the DC of a window of the desktop with the input succeeded\n", round);
                ReleaseDC(s_hwndY, hdcWnd);
            }
        }
        DeleteObject(hbm);
        DeleteDC(hdcMem);

        SwitchDesktop(s_hdeskA);
        SetEvent(s_hQuit);
        WaitForSingleObject(hY, 5000);
        CloseHandle(hY);
        CloseDesktop(s_hdeskY);
        DeleteDC(s_hdcHeld);
    }
    SwitchDesktop(s_hdeskA);
    CloseHandle(s_hMade);
    CloseHandle(s_hReadyY);
    CloseHandle(s_hQuit);
}
