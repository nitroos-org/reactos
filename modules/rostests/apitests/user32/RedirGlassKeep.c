/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A call that does not change the glass state of a window keeps what the window drew
 *              (NitroRedirection levels 0, 1 and 2)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * dwmapi's DwmExtendFrameIntoClientArea marks a window as glass through the private user32 export
 * NitroSetWindowGlass, and programs such as Firefox call it again and again. At levels 1 and 2 a window keeps
 * what it drew in a surface of its own and is not painted again when it is uncovered (Windows with the Desktop
 * Window Manager does the same); a call that did not change the state must not drop that surface, or a window
 * that is covered at the time comes up empty (Firefox x86, first start, a black window). The window here paints
 * once and later only validates, as a program does that thinks its content is kept.
 */

#include "precomp.h"
#include <winreg.h>

#define WX  96
#define WY  96
#define WCX 320
#define WCY 240

#define RED     RGB(255, 0, 0)
#define GREEN   RGB(0, 255, 0)

typedef BOOL (WINAPI *PFN_SETGLASS)(HWND, BOOL);

static int g_Level;
static LONG g_cPaint;

static int GetRedirectionLevel(void)
{
    HKEY hKey;
    DWORD Value = 0, cb = sizeof(Value);
    WCHAR Options[512] = L"";
    SYSTEM_INFO si;

    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
        return 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(hKey, L"NitroRedirection", NULL, NULL, (BYTE *)&Value, &cb) != ERROR_SUCCESS || Value > 2)
            Value = 0;
        RegCloseKey(hKey);
    }
    if (Value && RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        cb = sizeof(Options) - sizeof(WCHAR);
        if (RegQueryValueExW(hKey, L"SystemStartOptions", NULL, NULL, (BYTE *)Options, &cb) == ERROR_SUCCESS)
        {
            _wcsupr(Options);
            if (wcsstr(Options, L"NOREDIRECTION"))
                Value = 0;
        }
        RegCloseKey(hKey);
    }
    return (int)Value;
}

static void Pump(void)
{
    MSG msg;
    DWORD Start = GetTickCount();

    do
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(10);
    } while (GetTickCount() - Start < 250);
}

/* Window A paints its colour on its first WM_PAINT and only validates after that; B paints its colour every time */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            BOOL bOnce = GetWindowLongPtrW(hwnd, 0) != 0;

            if (!bOnce || InterlockedIncrement(&g_cPaint) == 1)
            {
                HBRUSH hbr = CreateSolidBrush((COLORREF)GetWindowLongPtrW(hwnd, GWLP_USERDATA));
                RECT rc;

                GetClientRect(hwnd, &rc);
                FillRect(hdc, &rc, hbr);
                DeleteObject(hbr);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static HWND MakeWindow(COLORREF Color, BOOL bOnce)
{
    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST, L"RedirGlassKeepTest", L"RedirGlassKeep", WS_POPUP,
                                WX, WY, WCX, WCY, NULL, NULL, GetModuleHandleW(NULL), NULL);

    ok(hwnd != NULL, "CreateWindowExW failed: %lu\n", GetLastError());
    if (hwnd)
    {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)Color);
        SetWindowLongPtrW(hwnd, 0, bOnce);
    }
    return hwnd;
}

/* The share (percent) of sampled points of the window rectangle the screen shows as colour c */
static int ScreenShare(COLORREF c)
{
    HDC hdcScreen = GetDC(NULL), hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, WCX, WCY);
    HGDIOBJ old = SelectObject(hdcMem, hbm);
    int px, py, n = 0, hit = 0;

    BitBlt(hdcMem, 0, 0, WCX, WCY, hdcScreen, WX, WY, SRCCOPY);
    for (py = 2; py < WCY; py += 8)
    {
        for (px = 2; px < WCX; px += 8)
        {
            n++;
            if (GetPixel(hdcMem, px, py) == c)
                hit++;
        }
    }
    SelectObject(hdcMem, old);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    return n ? hit * 100 / n : 0;
}

START_TEST(RedirGlassKeep)
{
    WNDCLASSW wc = { 0 };
    PFN_SETGLASS pSetGlass;
    HDC hdcScreen;
    HWND hwndA, hwndB;
    int Share, i;

    g_Level = GetRedirectionLevel();
    trace("NitroRedirection level %d\n", g_Level);

    pSetGlass = (PFN_SETGLASS)GetProcAddress(GetModuleHandleW(L"user32.dll"), "NitroSetWindowGlass");
    if (!pSetGlass)
    {
        skip("NitroSetWindowGlass is not exported\n");
        return;
    }
    hdcScreen = GetDC(NULL);
    if (GetDeviceCaps(hdcScreen, BITSPIXEL) < 24)
    {
        skip("screen has fewer than 24 bits per pixel\n");
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    ReleaseDC(NULL, hdcScreen);

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.cbWndExtra = sizeof(LONG_PTR);
    wc.lpszClassName = L"RedirGlassKeepTest";
    RegisterClassW(&wc);

    hwndA = MakeWindow(RED, TRUE);
    hwndB = MakeWindow(GREEN, FALSE);
    if (!hwndA || !hwndB)
        goto Done;

    ShowWindow(hwndA, SW_SHOWNOACTIVATE);
    UpdateWindow(hwndA);
    Pump();
    Share = ScreenShare(RED);
    ok(Share >= 95, "A shows %d%% red when it is painted\n", Share);

    /* Nothing changes: not glass before, not glass after (what DwmExtendFrameIntoClientArea does again and again) */
    for (i = 0; i < 3; i++)
        ok(pSetGlass(hwndA, FALSE) == TRUE, "NitroSetWindowGlass(FALSE) failed\n");

    /* B covers A completely, then goes away */
    ShowWindow(hwndB, SW_SHOWNOACTIVATE);
    UpdateWindow(hwndB);
    Pump();
    Share = ScreenShare(GREEN);
    ok(Share >= 95, "B shows %d%% green on top of A\n", Share);

    for (i = 0; i < 3; i++)
        ok(pSetGlass(hwndA, FALSE) == TRUE, "NitroSetWindowGlass(FALSE) failed while A is covered\n");

    ShowWindow(hwndB, SW_HIDE);
    Pump();
    Share = ScreenShare(RED);
    /* Level 0 draws on the screen: a window that does not paint again is not shown again, by design of the test */
    if (g_Level >= 1)
        ok(Share >= 95, "A shows %d%% red after B left (level %d): its content was dropped\n", Share, g_Level);
    else
        trace("level 0: A shows %d%% red after B left\n", Share);

Done:
    if (hwndB)
        DestroyWindow(hwndB);
    if (hwndA)
        DestroyWindow(hwndA);
    Pump();
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
