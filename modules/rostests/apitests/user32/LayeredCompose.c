/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Layered and glass windows on the screen: alpha, colour key, UpdateLayeredWindow, what is below
 *              changing, PrintWindow, hit testing (NitroRedirection levels 0, 1 and 2)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations are those of Windows 10 with the Desktop Window Manager (measured on the oracle 2026-11-09,
 * W3 and W4, where noted). NitroOS composes layered and glass windows only at NitroRedirection 2 (amd64): at
 * levels 0 and 1 SetLayeredWindowAttributes is not applied and the screen is blended once, so those checks are
 * todo there. Checks marked "level 2 only" are NitroOS behaviour not measured on Windows yet; they run only at
 * level 2.
 */

#include "precomp.h"
#include <winreg.h>

#ifndef PW_RENDERFULLCONTENT
#define PW_RENDERFULLCONTENT 2
#endif

static int g_Level;
static LONG g_cPaint;
static HBRUSH g_hbrRed;

/* The window redirection level in effect: NitroRedirection on an amd64 system without /NOREDIRECTION */
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
    } while (GetTickCount() - Start < 150);
}

static COLORREF ScreenPixel(int x, int y)
{
    HDC hdcScreen = GetDC(NULL), hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, 1, 1);
    HGDIOBJ old = SelectObject(hdcMem, hbm);
    COLORREF c;

    BitBlt(hdcMem, 0, 0, 1, 1, hdcScreen, x, y, SRCCOPY | CAPTUREBLT);
    c = GetPixel(hdcMem, 0, 0);
    SelectObject(hdcMem, old);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    return c;
}

static BOOL Near(COLORREF c, COLORREF e)
{
    return abs((int)GetRValue(c) - (int)GetRValue(e)) <= 3 && abs((int)GetGValue(c) - (int)GetGValue(e)) <= 3 &&
           abs((int)GetBValue(c) - (int)GetBValue(e)) <= 3;
}

/* Paints its client area with its class brush, the left half in the colour key magenta when GWLP_USERDATA is 1 */
static LRESULT CALLBACK PaintProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch (Msg)
    {
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            RECT rc;
            HDC hdc = BeginPaint(hWnd, &ps);

            InterlockedIncrement(&g_cPaint);
            GetClientRect(hWnd, &rc);
            if (GetClassLongPtrW(hWnd, GCLP_HBRBACKGROUND))
                FillRect(hdc, &rc, (HBRUSH)GetClassLongPtrW(hWnd, GCLP_HBRBACKGROUND));
            if (GetWindowLongPtrW(hWnd, GWLP_USERDATA) == 1)
            {
                HBRUSH hbr = CreateSolidBrush(RGB(255, 0, 255));
                rc.right /= 2;
                FillRect(hdc, &rc, hbr);
                DeleteObject(hbr);
            }
            EndPaint(hWnd, &ps);
            return 0;
        }
        case WM_PRINTCLIENT:
        {
            RECT rc;
            GetClientRect(hWnd, &rc);
            if (GetClassLongPtrW(hWnd, GCLP_HBRBACKGROUND))
                FillRect((HDC)wParam, &rc, (HBRUSH)GetClassLongPtrW(hWnd, GCLP_HBRBACKGROUND));
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static void RegisterColour(LPCWSTR Name, COLORREF Colour)
{
    WNDCLASSW wc = { 0 };

    wc.lpfnWndProc = PaintProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hbrBackground = CreateSolidBrush(Colour);
    if (Colour == RGB(200, 0, 0))
        g_hbrRed = wc.hbrBackground;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = Name;
    RegisterClassW(&wc);
}

/* The window below turns black (its class brush; RestoreBack gives the class its red back) */
static void BackToBlack(HWND hBack)
{
    SetClassLongPtrW(hBack, GCLP_HBRBACKGROUND, (LONG_PTR)GetStockObject(BLACK_BRUSH));
    InvalidateRect(hBack, NULL, TRUE);
    UpdateWindow(hBack);
}

static void RestoreBack(HWND hBack)
{
    SetClassLongPtrW(hBack, GCLP_HBRBACKGROUND, (LONG_PTR)g_hbrRed);
}

/* An opaque red window below the test windows */
static HWND CreateBack(void)
{
    HWND hWnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"LcRed", L"", WS_POPUP | WS_VISIBLE,
                                50, 50, 500, 350, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hWnd != NULL, "CreateWindowExW failed: %lu\n", GetLastError());
    UpdateWindow(hWnd);
    return hWnd;
}

static HWND CreateTop(LPCWSTR Class, DWORD ExStyle, BOOL bShow)
{
    HWND hWnd = CreateWindowExW(ExStyle | WS_EX_TOPMOST | WS_EX_TOOLWINDOW, Class, L"", WS_POPUP,
                                100, 100, 200, 150, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hWnd != NULL, "CreateWindowExW failed: %lu\n", GetLastError());
    if (hWnd && bShow)
        ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    return hWnd;
}

/* Windows 10 (oracle W3): a layered window that had neither call shows nothing and gets no WM_PAINT */
static void Test_LayeredUnset(void)
{
    HWND hBack = CreateBack(), hWnd;
    COLORREF c;

    Pump();
    g_cPaint = 0;
    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
    Pump();
    c = ScreenPixel(200, 175);
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(200, 0, 0)), "layered window not set: 0x%06lx on the screen, expected what is below (red)\n", c);
    todo_ros_if(g_Level < 2)
    ok(g_cPaint == 0, "layered window not set: %ld WM_PAINT, expected none\n", g_cPaint);

    /* Set: it paints (one WM_PAINT on Windows) and shows */
    ok(SetLayeredWindowAttributes(hWnd, 0, 255, LWA_ALPHA), "SetLayeredWindowAttributes failed: %lu\n", GetLastError());
    Pump();
    ok(g_cPaint >= 1, "no WM_PAINT after SetLayeredWindowAttributes\n");
    c = ScreenPixel(200, 175);
    ok(Near(c, RGB(0, 0, 200)), "alpha 255: 0x%06lx, expected the window's blue\n", c);

    DestroyWindow(hWnd);
    DestroyWindow(hBack);
}

/* Windows 10 (oracle W4): SetLayeredWindowAttributes alpha and colour key apply to what the window paints */
static void Test_AlphaAndKey(void)
{
    HWND hBack = CreateBack(), hWnd;
    COLORREF c;

    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, FALSE);
    SetLayeredWindowAttributes(hWnd, 0, 128, LWA_ALPHA);
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    Pump();
    c = ScreenPixel(200, 175);
    /* blue 200 at 128/255 over red 200 */
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(100, 0, 100)), "LWA_ALPHA 128: 0x%06lx, expected (100,0,100)\n", c);

    /* The window below changes: the blend follows it */
    BackToBlack(hBack);
    Pump();
    c = ScreenPixel(200, 175);
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(0, 0, 100)), "LWA_ALPHA 128 over a window that turned black: 0x%06lx, expected (0,0,100)\n", c);
    c = ScreenPixel(60, 60);
    ok(Near(c, RGB(0, 0, 0)), "the window below: 0x%06lx, expected black\n", c);

    /* A new alpha applies at once */
    SetLayeredWindowAttributes(hWnd, 0, 255, LWA_ALPHA);
    Pump();
    c = ScreenPixel(200, 175);
    ok(Near(c, RGB(0, 0, 200)), "LWA_ALPHA 255: 0x%06lx, expected blue\n", c);
    DestroyWindow(hWnd);
    RestoreBack(hBack);
    DestroyWindow(hBack);

    /* Colour key: the magenta left half shows what is below */
    hBack = CreateBack();
    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, FALSE);
    SetWindowLongPtrW(hWnd, GWLP_USERDATA, 1);
    SetLayeredWindowAttributes(hWnd, RGB(255, 0, 255), 0, LWA_COLORKEY);
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    Pump();
    c = ScreenPixel(150, 175);
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(200, 0, 0)), "LWA_COLORKEY: key pixel 0x%06lx, expected what is below (red)\n", c);
    c = ScreenPixel(250, 175);
    ok(Near(c, RGB(0, 0, 200)), "LWA_COLORKEY: other pixel 0x%06lx, expected blue\n", c);
    DestroyWindow(hWnd);
    DestroyWindow(hBack);
}

static HBITMAP MakeDib(HDC *phdc, DWORD Colour, int cx, int cy, DWORD **pBits)
{
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), 0, 0, 1, 32, BI_RGB } };
    DWORD *Bits = NULL;
    HBITMAP hbm;
    int i;

    bmi.bmiHeader.biWidth = cx;
    bmi.bmiHeader.biHeight = -cy;
    *phdc = CreateCompatibleDC(NULL);
    hbm = CreateDIBSection(*phdc, &bmi, DIB_RGB_COLORS, (PVOID *)&Bits, NULL, 0);
    SelectObject(*phdc, hbm);
    for (i = 0; Bits && i < cx * cy; i++)
        Bits[i] = Colour;
    if (pBits)
        *pBits = Bits;
    return hbm;
}

/* UpdateLayeredWindow: blended with what is below; the blend follows when what is below changes */
static void Test_UlwFollows(void)
{
    BLENDFUNCTION Blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    POINT Pos = { 100, 100 }, Src = { 0, 0 };
    SIZE Size = { 200, 150 };
    HWND hGreen = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"LcGreen", L"", WS_POPUP | WS_VISIBLE,
                                  60, 60, 450, 300, NULL, NULL, GetModuleHandleW(NULL), NULL);
    HWND hBack = CreateBack(), hWnd;
    HDC hdc;
    HBITMAP hbm = MakeDib(&hdc, 0x80000080, 200, 150, NULL);   /* 50% blue, premultiplied */
    COLORREF c;
    LONG cPaint;

    g_cPaint = 0;
    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
    Pump();
    ok(UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdc, &Src, 0, &Blend, ULW_ALPHA), "UpdateLayeredWindow failed: %lu\n", GetLastError());
    Pump();
    c = ScreenPixel(200, 175);
    /* Levels 0 and 1 paint the window before (no W3) and blend over that */
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(100, 0, 128)), "50%% blue over red: 0x%06lx, expected (100,0,128)\n", c);

    BackToBlack(hBack);
    Pump();
    c = ScreenPixel(200, 175);
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(0, 0, 128)), "50%% blue over a window that turned black: 0x%06lx, expected (0,0,128)\n", c);

    /* The window below moves away: the green window under it shows through */
    UpdateWindow(hGreen);
    SetWindowPos(hBack, NULL, 600, 50, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    Pump();
    c = ScreenPixel(200, 175);
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(0, 100, 128)), "the window below moved away: 0x%06lx, expected 50%% blue over green (0,100,128)\n", c);

    if (g_Level >= 2)
    {
        /* Level 2 only (not measured on Windows): content kept while hidden, GDI drawing shows nothing */
        HDC hdcWnd;
        RECT rc = { 0, 0, 200, 150 };

        SetWindowPos(hBack, NULL, 50, 50, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        Pump();
        cPaint = g_cPaint;
        ShowWindow(hWnd, SW_HIDE);
        Pump();
        ShowWindow(hWnd, SW_SHOWNOACTIVATE);
        Pump();
        c = ScreenPixel(200, 175);
        ok(Near(c, RGB(0, 0, 128)), "hidden and shown again: 0x%06lx, expected the content (0,0,128)\n", c);
        ok(g_cPaint == cPaint, "hidden and shown again: %ld WM_PAINT\n", g_cPaint - cPaint);
        hdcWnd = GetDC(hWnd);
        FillRect(hdcWnd, &rc, GetStockObject(WHITE_BRUSH));
        ReleaseDC(hWnd, hdcWnd);
        Pump();
        c = ScreenPixel(200, 175);
        ok(Near(c, RGB(0, 0, 128)), "GDI drawing into it: 0x%06lx, expected the content (0,0,128)\n", c);
    }

    DestroyWindow(hWnd);
    RestoreBack(hBack);
    DestroyWindow(hBack);
    DestroyWindow(hGreen);
    DeleteDC(hdc);
    DeleteObject(hbm);
}

/* Glass (DwmExtendFrameIntoClientArea -1): the per-pixel alpha blend follows the window below */
typedef struct { int l, r, t, b; } LC_MARGINS;

static void Test_GlassFollows(void)
{
    HRESULT (WINAPI *pExtend)(HWND, const LC_MARGINS *);
    LC_MARGINS Glass = { -1, -1, -1, -1 };
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    HWND hBack, hWnd;
    HDC hdc, hdcWnd;
    HBITMAP hbm;
    COLORREF c;

    pExtend = hDwm ? (PVOID)GetProcAddress(hDwm, "DwmExtendFrameIntoClientArea") : NULL;
    if (!pExtend)
    {
        skip("DwmExtendFrameIntoClientArea is not available\n");
        return;
    }
    hBack = CreateBack();
    hWnd = CreateTop(L"LcNone", 0, FALSE);
    ok(pExtend(hWnd, &Glass) == S_OK, "DwmExtendFrameIntoClientArea failed\n");
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    Pump();
    hbm = MakeDib(&hdc, 0x80000080, 200, 150, NULL);
    hdcWnd = GetDC(hWnd);
    BitBlt(hdcWnd, 0, 0, 200, 150, hdc, 0, 0, SRCCOPY);
    ReleaseDC(hWnd, hdcWnd);
    Pump();
    c = ScreenPixel(200, 175);
    ok(Near(c, RGB(100, 0, 128)), "glass 50%% blue over red: 0x%06lx, expected (100,0,128)\n", c);

    BackToBlack(hBack);
    Pump();
    c = ScreenPixel(200, 175);
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(0, 0, 128)), "glass over a window that turned black: 0x%06lx, expected (0,0,128)\n", c);

    DestroyWindow(hWnd);
    RestoreBack(hBack);
    DestroyWindow(hBack);
    DeleteDC(hdc);
    DeleteObject(hbm);
    FreeLibrary(hDwm);
}

/* PrintWindow of a layered window gives its own content, not the blend */
static void Test_PrintLayered(void)
{
    BLENDFUNCTION Blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    POINT Pos = { 100, 100 }, Src = { 0, 0 };
    SIZE Size = { 200, 150 };
    HWND hBack = CreateBack(), hWnd;
    HDC hdcScreen = GetDC(NULL), hdcMem = CreateCompatibleDC(hdcScreen), hdcSrc;
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, 200, 150), hbmSrc;
    HGDIOBJ old = SelectObject(hdcMem, hbm);
    COLORREF c;

    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, FALSE);
    SetLayeredWindowAttributes(hWnd, 0, 128, LWA_ALPHA);
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    Pump();
    ok(PrintWindow(hWnd, hdcMem, 0), "PrintWindow failed: %lu\n", GetLastError());
    c = GetPixel(hdcMem, 100, 75);
    ok(Near(c, RGB(0, 0, 200)), "PrintWindow of an alpha 128 window: 0x%06lx, expected its own blue\n", c);
    DestroyWindow(hWnd);

    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
    hbmSrc = MakeDib(&hdcSrc, 0xFF00C800, 200, 150, NULL);   /* opaque green */
    ok(UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdcSrc, &Src, 0, &Blend, ULW_ALPHA), "UpdateLayeredWindow failed: %lu\n", GetLastError());
    Pump();
    c = ScreenPixel(200, 175);
    /* Levels 0 and 1 send the shown window a WM_PAINT (no W3), which paints over the content */
    todo_ros_if(g_Level < 2)
    ok(Near(c, RGB(0, 200, 0)), "opaque green ULW window: 0x%06lx\n", c);
    if (g_Level >= 2)
    {
        /* Level 2 only: from its surface (Windows: not measured) */
        SetPixel(hdcMem, 100, 75, RGB(1, 2, 3));
        ok(PrintWindow(hWnd, hdcMem, PW_RENDERFULLCONTENT), "PrintWindow PW_RENDERFULLCONTENT failed: %lu\n", GetLastError());
        c = GetPixel(hdcMem, 100, 75);
        ok(Near(c, RGB(0, 200, 0)), "PrintWindow of an UpdateLayeredWindow window: 0x%06lx, expected its green\n", c);
    }
    DestroyWindow(hWnd);
    DeleteDC(hdcSrc);
    DeleteObject(hbmSrc);

    SelectObject(hdcMem, old);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    DestroyWindow(hBack);
}

/* Hit testing stays by rectangle (per-pixel hit testing is not done): a translucent window is hit,
   WS_EX_TRANSPARENT lets the pointer through */
static void Test_HitTest(void)
{
    HWND hBack = CreateBack(), hWnd, hHit;
    POINT pt = { 200, 175 };

    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, FALSE);
    SetLayeredWindowAttributes(hWnd, 0, 128, LWA_ALPHA);
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    Pump();
    hHit = WindowFromPoint(pt);
    ok(hHit == hWnd, "WindowFromPoint over an alpha 128 window: %p, expected %p\n", hHit, hWnd);
    DestroyWindow(hWnd);

    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED | WS_EX_TRANSPARENT, FALSE);
    SetLayeredWindowAttributes(hWnd, 0, 128, LWA_ALPHA);
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    Pump();
    hHit = WindowFromPoint(pt);
    ok(hHit == hBack, "WindowFromPoint over a transparent layered window: %p, expected the window below %p\n", hHit, hBack);
    DestroyWindow(hWnd);
    DestroyWindow(hBack);
}

/*
 * UpdateLayeredWindow with a source point far outside the source bitmap (near INT_MAX / INT_MIN), and with a wide
 * source: nothing outside the bitmap is read. The window keeps the content it had (level 2: checked through
 * PrintWindow; other levels: no crash, the return value is traced).
 */
static void Test_UlwSourceRange(void)
{
    BLENDFUNCTION Blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    POINT Pos = { 100, 100 }, Src = { 0, 0 };
    SIZE Size = { 200, 150 };
    static const POINT Far[] = { { 0x7FFFFFF0, 0 }, { (LONG)0x80000010, 0 }, { 0, 0x7FFFFFF0 }, { 0, (LONG)0x80000010 },
                                 { 0x7FFFFF00, 0x7FFFFF00 }, { -100, -100 }, { 150, 100 } };
    HWND hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
    HDC hdcSrc, hdcWide, hdcScreen = GetDC(NULL), hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmSrc = MakeDib(&hdcSrc, 0xFF00C800, 200, 150, NULL), hbmWide;
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, 200, 150);
    HGDIOBJ old = SelectObject(hdcMem, hbm);
    COLORREF c;
    BOOL Ret;
    int i;

    Pump();
    ok(UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdcSrc, &Src, 0, &Blend, ULW_ALPHA), "UpdateLayeredWindow failed: %lu\n", GetLastError());
    Pump();
    for (i = 0; i < (int)(sizeof(Far) / sizeof(Far[0])); i++)
    {
        POINT p = Far[i];
        SetLastError(0xdeadbeef);
        Ret = UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdcSrc, &p, 0, &Blend, ULW_ALPHA);
        trace("source point (%ld,%ld): ret %d, error %lu\n", p.x, p.y, Ret, GetLastError());
        Pump();
        if (g_Level >= 2 && (p.x <= -200 || p.x >= 200 || p.y <= -150 || p.y >= 150))
        {
            /* Level 2: nothing of the source is in range, the content stays green */
            SetPixel(hdcMem, 100, 75, RGB(1, 2, 3));
            ok(PrintWindow(hWnd, hdcMem, PW_RENDERFULLCONTENT), "PrintWindow failed: %lu\n", GetLastError());
            c = GetPixel(hdcMem, 100, 75);
            ok(Near(c, RGB(0, 200, 0)), "source point (%ld,%ld): content 0x%06lx, expected the earlier green\n", p.x, p.y, c);
        }
    }

    /* A wide source (a large scan line) at its right edge: only the columns that exist are copied */
    hbmWide = MakeDib(&hdcWide, 0xFFC80000, 65536, 4, NULL);   /* opaque red */
    if (hbmWide)
    {
        POINT p = { 65536 - 50, 2 };
        Ret = UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdcWide, &p, 0, &Blend, ULW_ALPHA);
        trace("wide source at (%ld,%ld): ret %d\n", p.x, p.y, Ret);
        Pump();
        if (g_Level >= 2)
        {
            SetPixel(hdcMem, 10, 1, RGB(1, 2, 3));
            SetPixel(hdcMem, 100, 75, RGB(1, 2, 3));
            ok(PrintWindow(hWnd, hdcMem, PW_RENDERFULLCONTENT), "PrintWindow failed: %lu\n", GetLastError());
            c = GetPixel(hdcMem, 10, 1);
            ok(Near(c, RGB(200, 0, 0)), "wide source, a column in range: 0x%06lx, expected red\n", c);
            c = GetPixel(hdcMem, 100, 75);
            ok(Near(c, RGB(0, 200, 0)), "wide source, out of range: 0x%06lx, expected the earlier green\n", c);
        }
        DeleteDC(hdcWide);
        DeleteObject(hbmWide);
    }

    DestroyWindow(hWnd);
    DeleteDC(hdcSrc);
    DeleteObject(hbmSrc);
    SelectObject(hdcMem, old);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

/*
 * A glass child window (DwmExtendFrameIntoClientArea on a child) of an opaque top-level window. Levels 0 and 1 keep
 * what they did before level 2 existed (the pixel is traced, to compare builds); level 2 draws it opaque: DWM glass
 * is for top-level windows (verify on the oracle).
 */
static void Test_GlassChild(void)
{
    HRESULT (WINAPI *pExtend)(HWND, const LC_MARGINS *);
    LC_MARGINS Glass = { -1, -1, -1, -1 };
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    HWND hTop, hChild;
    HDC hdc, hdcWnd;
    HBITMAP hbm;
    COLORREF c;

    pExtend = hDwm ? (PVOID)GetProcAddress(hDwm, "DwmExtendFrameIntoClientArea") : NULL;
    if (!pExtend)
    {
        skip("DwmExtendFrameIntoClientArea is not available\n");
        return;
    }
    hTop = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"LcRed", L"", WS_POPUP | WS_VISIBLE | WS_CLIPCHILDREN,
                           50, 50, 400, 300, NULL, NULL, GetModuleHandleW(NULL), NULL);
    hChild = CreateWindowExW(0, L"LcNone", L"", WS_CHILD, 50, 50, 200, 150, hTop, NULL, GetModuleHandleW(NULL), NULL);
    trace("glass child: DwmExtendFrameIntoClientArea 0x%08lx\n", pExtend(hChild, &Glass));
    ShowWindow(hChild, SW_SHOWNA);
    UpdateWindow(hTop);
    Pump();
    hbm = MakeDib(&hdc, 0x80000080, 200, 150, NULL);
    hdcWnd = GetDC(hChild);
    BitBlt(hdcWnd, 0, 0, 200, 150, hdc, 0, 0, SRCCOPY);
    ReleaseDC(hChild, hdcWnd);
    Pump();
    c = ScreenPixel(200, 175);
    trace("glass child, level %d: 0x%06lx\n", g_Level, c);
    if (g_Level >= 2)
        ok(Near(c, RGB(0, 0, 128)), "glass child at level 2: 0x%06lx, expected the pixels as they are (0,0,128)\n", c);
    DestroyWindow(hTop);
    DeleteDC(hdc);
    DeleteObject(hbm);
    FreeLibrary(hDwm);
}

/*
 * Level 2: the surface budget is used up (windows of falling sizes until what is left is less than the smallest, then
 * a larger compose pass grows the compose frame buffer, which is counted but never refused, past it). An UpdateLayeredWindow window of constant size keeps animating: its content
 * follows each update. A resize that no longer fits shows the new content too, not a surface kept from before.
 */
static void SetUlwColour(DWORD *Bits, int cx, int cy, DWORD Colour)
{
    int i;

    for (i = 0; i < cx * cy; i++)
        Bits[i] = Colour;
}

static BOOL Ulw(HWND hWnd, HDC hdc, int x, int y, int cx, int cy)
{
    BLENDFUNCTION Blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    POINT Pos = { x, y }, Src = { 0, 0 };
    SIZE Size = { cx, cy };

    return UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdc, &Src, 0, &Blend, ULW_ALPHA);
}

static void Test_UlwBudget(void)
{
    static const int Sizes[] = { 4096, 2048, 1024, 512, 256, 128, 64 };
    HWND hBack, hBig, hWnd, Fillers[7 * 5] = { 0 };
    HDC hdc, hdcBig;
    DWORD *Bits, *BitsBig;
    HBITMAP hbm, hbmBig;
    int i, j, cFillers = 0;
    COLORREF c;
    const DWORD Green = 0xFF00C800, Blue = 0xFF0000C8;
    static const POINT Pos[2] = { { 100, 100 }, { 300, 200 } };

    if (g_Level < 2)
        return;

    hBack = CreateBack();
    hbm = MakeDib(&hdc, Green, 200, 150, &Bits);
    hbmBig = MakeDib(&hdcBig, Green, 300, 200, &BitsBig);
    /* A translucent window with its surface: moving it away later makes one compose pass over it and the ULW window, which needs a larger frame buffer than any pass so far */
    hBig = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"LcGreen", L"", WS_POPUP | WS_VISIBLE,
                           0, 0, 300, 300, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hBig != NULL, "CreateWindowExW failed: %lu\n", GetLastError());
    SetLayeredWindowAttributes(hBig, 0, 200, LWA_ALPHA);
    Pump();
    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
    Pump();
    ok(Ulw(hWnd, hdc, 100, 100, 200, 150), "UpdateLayeredWindow failed: %lu\n", GetLastError());
    Pump();
    c = ScreenPixel(200, 175);
    ok(Near(c, RGB(0, 200, 0)), "ULW window: 0x%06lx, expected (0,200,0)\n", c);

    /* Opaque windows, each painted so that it has a surface; those past the budget are refused (drawn nowhere visible) */
    for (i = 0; i < 7; i++)
    {
        for (j = 0; j < 5; j++)
        {
            HWND hFill = CreateWindowExW(WS_EX_TOOLWINDOW, L"LcNone", L"", WS_POPUP | WS_VISIBLE, 0, 0, Sizes[i], Sizes[i],
                                         NULL, NULL, GetModuleHandleW(NULL), NULL);
            if (!hFill)
                continue;
            {
                HDC hdcFill = GetDC(hFill);
                RECT rc = { 0, 0, 16, 16 };
                if (hdcFill)
                {
                    FillRect(hdcFill, &rc, GetStockObject(WHITE_BRUSH));
                    ReleaseDC(hFill, hdcFill);
                }
            }
            Fillers[cFillers++] = hFill;
        }
        Pump();
    }
    trace("%d filler windows\n", cFillers);
    SetWindowPos(hBig, NULL, 500, 300, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    Pump();

    /* Constant size, moving back and forth (the compose frame buffer grows past the budget), the colour changes each time */
    for (i = 0; i < 8; i++)
    {
        DWORD Colour = (i & 1) ? Blue : Green;
        COLORREF Expected = (i & 1) ? RGB(0, 0, 200) : RGB(0, 200, 0);
        int x = Pos[(i + 1) & 1].x, y = Pos[(i + 1) & 1].y;

        SetUlwColour(Bits, 200, 150, Colour);
        ok(Ulw(hWnd, hdc, x, y, 200, 150), "UpdateLayeredWindow %d failed: %lu\n", i, GetLastError());
        Pump();
        c = ScreenPixel(x + 100, y + 75);
        ok(Near(c, Expected), "animated ULW window at the budget, step %d: 0x%06lx, expected 0x%06lx\n", i, c, Expected);
    }

    /* Bigger than what is left: the new content (twice) and nothing of the surface it had */
    for (i = 0; i < 2; i++)
    {
        DWORD Colour = i ? Green : Blue;
        COLORREF Expected = i ? RGB(0, 200, 0) : RGB(0, 0, 200);

        SetUlwColour(BitsBig, 300, 200, Colour);
        ok(Ulw(hWnd, hdcBig, 100, 100, 300, 200), "UpdateLayeredWindow (resize) %d failed: %lu\n", i, GetLastError());
        Pump();
        c = ScreenPixel(150, 150);
        ok(Near(c, Expected), "resized over the budget, step %d, inside the old size: 0x%06lx, expected 0x%06lx\n", i, c, Expected);
        c = ScreenPixel(350, 250);
        ok(Near(c, Expected), "resized over the budget, step %d, outside the old size: 0x%06lx, expected 0x%06lx\n", i, c, Expected);
    }

    DestroyWindow(hWnd);
    DestroyWindow(hBig);
    for (i = 0; i < cFillers; i++)
        DestroyWindow(Fillers[i]);
    DestroyWindow(hBack);
    DeleteDC(hdc);
    DeleteObject(hbm);
    DeleteDC(hdcBig);
    DeleteObject(hbmBig);
}

/* Level 2: WS_EX_LAYERED removed and set again ends the UpdateLayeredWindow history: a layered window not set shows nothing */
static void Test_UlwHistoryReset(void)
{
    HWND hBack, hWnd;
    HDC hdc;
    HBITMAP hbm = MakeDib(&hdc, 0xFF00C800, 200, 150, NULL);
    COLORREF c;
    LONG_PTR ExStyle;

    if (g_Level < 2)
    {
        DeleteDC(hdc);
        DeleteObject(hbm);
        return;
    }

    hBack = CreateBack();
    hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
    Pump();
    ok(Ulw(hWnd, hdc, 100, 100, 200, 150), "UpdateLayeredWindow failed: %lu\n", GetLastError());
    Pump();
    c = ScreenPixel(200, 175);
    ok(Near(c, RGB(0, 200, 0)), "ULW window: 0x%06lx, expected (0,200,0)\n", c);

    ExStyle = GetWindowLongPtrW(hWnd, GWL_EXSTYLE);
    SetWindowLongPtrW(hWnd, GWL_EXSTYLE, ExStyle & ~WS_EX_LAYERED);
    SetWindowLongPtrW(hWnd, GWL_EXSTYLE, ExStyle);
    Pump();
    /* A compose pass over it (the old pixels stay until one runs) */
    SetWindowPos(hWnd, NULL, 101, 100, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    Pump();
    c = ScreenPixel(200, 175);
    ok(Near(c, RGB(200, 0, 0)), "layered again, not set: 0x%06lx, expected what is below (200,0,0)\n", c);

    DestroyWindow(hWnd);
    DestroyWindow(hBack);
    DeleteDC(hdc);
    DeleteObject(hbm);
}

/* Level 2: a whole update whose source range is outside the source bitmap copies nothing: the content stays premultiplied */
static void Test_UlwAlphaKept(void)
{
    BLENDFUNCTION Blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    POINT Far = { 0x7FFFFFF0, 0 };
    HDC hdc;
    HBITMAP hbm = MakeDib(&hdc, 0x80000080, 200, 150, NULL);   /* 50% blue, premultiplied */
    HWND hBack, hWnd;
    COLORREF c;

    if (g_Level >= 2)
    {
        hBack = CreateBack();
        hWnd = CreateTop(L"LcBlue", WS_EX_LAYERED, TRUE);
        Pump();
        ok(Ulw(hWnd, hdc, 100, 100, 200, 150), "UpdateLayeredWindow failed: %lu\n", GetLastError());
        Pump();
        c = ScreenPixel(200, 175);
        ok(Near(c, RGB(100, 0, 128)), "50%% blue over red: 0x%06lx, expected (100,0,128)\n", c);
        {
            POINT Pos = { 100, 100 };
            SIZE Size = { 200, 150 };
            UpdateLayeredWindow(hWnd, NULL, &Pos, &Size, hdc, &Far, 0, &Blend, ULW_ALPHA);
        }
        Pump();
        c = ScreenPixel(200, 175);
        ok(Near(c, RGB(100, 0, 128)), "after an update with the source out of range: 0x%06lx, expected the same blend (100,0,128)\n", c);
        DestroyWindow(hWnd);
        DestroyWindow(hBack);
    }
    DeleteDC(hdc);
    DeleteObject(hbm);
}

START_TEST(LayeredCompose)
{
    g_Level = GetRedirectionLevel();
    trace("window redirection level %d\n", g_Level);
    RegisterColour(L"LcRed", RGB(200, 0, 0));
    RegisterColour(L"LcBlue", RGB(0, 0, 200));
    RegisterColour(L"LcGreen", RGB(0, 200, 0));
    /* No brush: paints nothing (the glass test draws with BitBlt only) */
    {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = PaintProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.lpszClassName = L"LcNone";
        RegisterClassW(&wc);
    }

    Test_LayeredUnset();
    Test_AlphaAndKey();
    Test_UlwFollows();
    Test_GlassFollows();
    Test_PrintLayered();
    Test_HitTest();
    Test_UlwSourceRange();
    Test_GlassChild();
    Test_UlwBudget();
    Test_UlwHistoryReset();
    Test_UlwAlphaKept();
}
