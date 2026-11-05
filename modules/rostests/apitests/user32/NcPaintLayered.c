/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     A layered window without a non-client area gets no WM_NCPAINT
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows 10 22H2: the borderless layered tool windows that applications draw with UpdateLayeredWindow (shadow
 * and glow borders) never get WM_NCPAINT, however they are shown, sized or moved. A borderless window that is
 * not layered, and a layered window with a caption, do get it. */

static INT g_cNcPaint;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_NCPAINT)
        g_cNcPaint++;
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void Pump(void)
{
    MSG Msg;
    DWORD Start = GetTickCount();

    while (GetTickCount() - Start < 150)
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Msg);
        Sleep(10);
    }
}

START_TEST(NcPaintLayered)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    HDC hdcScreen, hdcMem;
    HBITMAP hbm;
    BITMAPINFO bi = { { sizeof(BITMAPINFOHEADER), 100, -20, 1, 32, BI_RGB } };
    void *bits;
    POINT pt = { 200, 300 }, ptSrc = { 0, 0 };
    SIZE sz = { 100, 20 };
    BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    BOOL ret;

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"NcPaintLayeredTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    hdcScreen = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdcScreen);
    hbm = CreateDIBSection(hdcMem, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    ok(hbm != NULL, "CreateDIBSection failed\n");
    if (!hbm)
        goto Cleanup;
    memset(bits, 0x40, 100 * 20 * 4);
    SelectObject(hdcMem, hbm);

    /* Borderless layered: shown, painted by UpdateLayeredWindow, sized, hidden, shown again */
    hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW, wc.lpszClassName, L"", WS_POPUP | WS_CLIPSIBLINGS | WS_DISABLED,
                           0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "window not created\n");
    if (hwnd)
    {
        g_cNcPaint = 0;
        ok(SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE | SWP_SHOWWINDOW | SWP_NOOWNERZORDER), "SetWindowPos failed\n");
        Pump();
        ret = UpdateLayeredWindow(hwnd, NULL, &pt, &sz, hdcMem, &ptSrc, 0, &bf, ULW_ALPHA);
        ok(ret, "UpdateLayeredWindow failed, error %lu\n", GetLastError());
        Pump();
        ok(SetWindowPos(hwnd, NULL, 10, 10, 200, 30, SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos failed\n");
        Pump();
        ok(SetWindowPos(hwnd, NULL, 20, 20, 0, 0, SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSIZE), "SetWindowPos failed\n");
        Pump();
        ShowWindow(hwnd, SW_HIDE);
        Pump();
        ShowWindow(hwnd, SW_SHOWNA);
        Pump();
        ok(g_cNcPaint == 0, "a borderless layered window got %d WM_NCPAINT\n", g_cNcPaint);
        DestroyWindow(hwnd);
    }

    /* Control: a borderless window that is not layered gets WM_NCPAINT */
    hwnd = CreateWindowExW(0, wc.lpszClassName, L"", WS_POPUP | WS_CLIPSIBLINGS, 20, 20, 200, 100, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "window not created\n");
    if (hwnd)
    {
        g_cNcPaint = 0;
        ShowWindow(hwnd, SW_SHOWNA);
        Pump();
        /* Windows paints the non-client area when the window is shown; ReactOS only when it is sized */
        todo_ros ok(g_cNcPaint >= 1, "a borderless window got no WM_NCPAINT when it was shown\n");
        g_cNcPaint = 0;
        ok(SetWindowPos(hwnd, NULL, 20, 20, 250, 120, SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos failed\n");
        Pump();
        ok(g_cNcPaint >= 1, "a borderless window got no WM_NCPAINT when it was sized\n");
        DestroyWindow(hwnd);
    }

    /* Control: a layered window with a caption gets it, once it is given its alpha */
    hwnd = CreateWindowExW(WS_EX_LAYERED, wc.lpszClassName, L"layered", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 20, 20, 300, 200, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "window not created\n");
    if (hwnd)
    {
        Pump();
        g_cNcPaint = 0;
        ok(SetWindowPos(hwnd, NULL, 20, 20, 320, 220, SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos failed\n");
        ok(SetLayeredWindowAttributes(hwnd, 0, 200, LWA_ALPHA), "SetLayeredWindowAttributes failed\n");
        Pump();
        ok(g_cNcPaint >= 1, "a layered window with a caption got no WM_NCPAINT\n");
        DestroyWindow(hwnd);
    }

Cleanup:
    if (hbm)
        DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
