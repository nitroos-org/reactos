/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What a window draws through its DC is on the screen when the DC is released or the paint ends, for each
 *              kind of primitive, and nothing else of the window is copied there (NitroRedirection levels 0, 1 and 2)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * At level 0 a window draws on the screen. At levels 1 and 2 (amd64) it draws into its surface, and what each
 * primitive wrote is copied to the screen at ReleaseDC/EndPaint. Windows 10 with the Desktop Window Manager shows
 * GDI drawing at once (oracle W7, 2026-11-09) and leaves drawing on the screen DC alone until that part of the
 * window changes (W5). The "rest stays" checks are W5 applied to a window that draws elsewhere, or not at all, in
 * its paint; level 0 behaves so by construction.
 */

#include "precomp.h"
#include <winreg.h>

#define WX  96
#define WY  96
#define WCX 320
#define WCY 240

#define WHITE   RGB(255, 255, 255)
#define RED     RGB(255, 0, 0)
#define GREEN   RGB(0, 255, 0)
#define BLUE    RGB(0, 0, 255)
#define BLACK   RGB(0, 0, 0)
#define YELLOW  RGB(255, 255, 0)
#define MAGENTA RGB(255, 0, 255)
#define CYAN    RGB(0, 255, 255)

static int g_Level;
static int g_PaintMode;   /* 0: the paint draws nothing, 1: a red line at y 200 */
static LONG g_cPaint;

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

/* Pixel x, y of the window (client = window: a popup without a frame) as the screen shows it */
static COLORREF ScreenPixel(int x, int y)
{
    HDC hdcScreen = GetDC(NULL);
    COLORREF c = GetPixel(hdcScreen, WX + x, WY + y);

    ReleaseDC(NULL, hdcScreen);
    return c;
}

/* Whether the screen shows colour c somewhere in the window rectangle l, t, r, b */
static BOOL ScreenHas(int l, int t, int r, int b, COLORREF c)
{
    HDC hdcScreen = GetDC(NULL), hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, r - l, b - t);
    HGDIOBJ old = SelectObject(hdcMem, hbm);
    BOOL bFound = FALSE;
    int x, y;

    BitBlt(hdcMem, 0, 0, r - l, b - t, hdcScreen, WX + l, WY + t, SRCCOPY);
    for (y = 0; y < b - t && !bFound; y++)
        for (x = 0; x < r - l && !bFound; x++)
            bFound = (GetPixel(hdcMem, x, y) == c);
    SelectObject(hdcMem, old);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    return bFound;
}

/* Colour c on the screen DC at window position x, y (a 4 x 4 block), not through the window */
static void ScreenMark(int x, int y, COLORREF c)
{
    HDC hdcScreen = GetDC(NULL);
    HBRUSH hbr = CreateSolidBrush(c);
    RECT rc = { WX + x, WY + y, WX + x + 4, WY + y + 4 };

    FillRect(hdcScreen, &rc, hbr);
    DeleteObject(hbr);
    ReleaseDC(NULL, hdcScreen);
}

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

            InterlockedIncrement(&g_cPaint);
            if (g_PaintMode == 1)
            {
                HPEN hpen = CreatePen(PS_SOLID, 1, RED), old = SelectObject(hdc, hpen);

                MoveToEx(hdc, 20, 200, NULL);
                LineTo(hdc, 300, 200);
                DeleteObject(SelectObject(hdc, old));
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* The whole window white, drawn through its DC */
static void Clear(HWND hwnd)
{
    HDC hdc = GetDC(hwnd);
    RECT rc = { 0, 0, WCX, WCY };

    FillRect(hdc, &rc, GetStockObject(WHITE_BRUSH));
    ReleaseDC(hwnd, hdc);
}

static void Test_Primitives(HWND hwnd)
{
    HDC hdc;
    HPEN hpen, hpenOld;
    HBRUSH hbr, hbrOld;
    HFONT hfont, hfontOld;
    POINT pt[4];

    /* Horizontal and vertical one-pixel lines (their bounding boxes are empty) */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    hpen = CreatePen(PS_SOLID, 1, RED);
    hpenOld = SelectObject(hdc, hpen);
    MoveToEx(hdc, 20, 30, NULL);
    LineTo(hdc, 200, 30);
    MoveToEx(hdc, 250, 20, NULL);
    LineTo(hdc, 250, 120);
    SelectObject(hdc, hpenOld);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(100, 30) == RED, "horizontal LineTo: 0x%06lx\n", ScreenPixel(100, 30));
    ok(ScreenPixel(250, 70) == RED, "vertical LineTo: 0x%06lx\n", ScreenPixel(250, 70));

    /* Polyline, diagonal */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    hpenOld = SelectObject(hdc, hpen);
    pt[0].x = 20; pt[0].y = 40; pt[1].x = 120; pt[1].y = 140; pt[2].x = 140; pt[2].y = 140;
    Polyline(hdc, pt, 3);
    SelectObject(hdc, hpenOld);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(70, 90) == RED, "Polyline: 0x%06lx\n", ScreenPixel(70, 90));
    ok(ScreenPixel(130, 140) == RED, "Polyline end: 0x%06lx\n", ScreenPixel(130, 140));

    /* PolylineTo from the current position */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    hpenOld = SelectObject(hdc, hpen);
    MoveToEx(hdc, 10, 220, NULL);
    pt[0].x = 300; pt[0].y = 220;
    PolylineTo(hdc, pt, 1);
    SelectObject(hdc, hpenOld);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(150, 220) == RED, "PolylineTo: 0x%06lx\n", ScreenPixel(150, 220));
    DeleteObject(hpen);

    /* Text: opaque cells, then glyphs only */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    hfont = CreateFontW(-40, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, NONANTIALIASED_QUALITY, 0, L"Arial");
    hfontOld = SelectObject(hdc, hfont);
    SetBkMode(hdc, OPAQUE);
    SetBkColor(hdc, BLUE);
    SetTextColor(hdc, BLACK);
    TextOutW(hdc, 20, 150, L"MMM", 3);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, GREEN);
    TextOutW(hdc, 20, 60, L"WWW", 3);
    SelectObject(hdc, hfontOld);
    ReleaseDC(hwnd, hdc);
    ok(ScreenHas(20, 150, 140, 200, BLUE), "opaque text: no background cell on the screen\n");
    ok(ScreenHas(20, 150, 140, 200, BLACK), "opaque text: no glyph on the screen\n");
    ok(ScreenHas(20, 60, 140, 110, GREEN), "transparent text: no glyph on the screen\n");

    /* ExtTextOut ETO_OPAQUE with a rectangle and no string, and a clipped string */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    {
        RECT rc = { 200, 150, 260, 180 }, rcClip = { 20, 20, 60, 50 };

        SetBkColor(hdc, MAGENTA);
        ExtTextOutW(hdc, 0, 0, ETO_OPAQUE, &rc, NULL, 0, NULL);
        hfontOld = SelectObject(hdc, hfont);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, GREEN);
        ExtTextOutW(hdc, 20, 15, ETO_CLIPPED, &rcClip, L"WWWW", 4, NULL);
        SelectObject(hdc, hfontOld);
    }
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(230, 165) == MAGENTA, "ETO_OPAQUE rectangle: 0x%06lx\n", ScreenPixel(230, 165));
    ok(ScreenHas(20, 20, 60, 50, GREEN), "ETO_CLIPPED text: no glyph on the screen\n");
    ok(!ScreenHas(60, 15, 200, 60, GREEN), "ETO_CLIPPED text: drawn outside its rectangle\n");
    DeleteObject(hfont);

    /* Rectangle with a one-pixel pen, then with a wide pen (it reaches past the rectangle) */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    hpen = CreatePen(PS_SOLID, 1, BLACK);
    hbr = CreateSolidBrush(YELLOW);
    hpenOld = SelectObject(hdc, hpen);
    hbrOld = SelectObject(hdc, hbr);
    Rectangle(hdc, 150, 40, 250, 120);
    SelectObject(hdc, hpenOld);
    DeleteObject(hpen);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(150, 80) == BLACK, "Rectangle left edge: 0x%06lx\n", ScreenPixel(150, 80));
    ok(ScreenPixel(249, 80) == BLACK, "Rectangle right edge: 0x%06lx\n", ScreenPixel(249, 80));
    ok(ScreenPixel(200, 119) == BLACK, "Rectangle bottom edge: 0x%06lx\n", ScreenPixel(200, 119));
    ok(ScreenPixel(200, 80) == YELLOW, "Rectangle inside: 0x%06lx\n", ScreenPixel(200, 80));

    Clear(hwnd);
    hdc = GetDC(hwnd);
    hpen = CreatePen(PS_SOLID, 9, RED);
    hpenOld = SelectObject(hdc, hpen);
    hbrOld = SelectObject(hdc, hbr);
    Rectangle(hdc, 150, 40, 250, 120);
    SelectObject(hdc, hpenOld);
    SelectObject(hdc, hbrOld);
    DeleteObject(hpen);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(147, 80) == RED, "Rectangle, wide pen outside the rectangle: 0x%06lx\n", ScreenPixel(147, 80));
    ok(ScreenPixel(200, 80) == YELLOW, "Rectangle, wide pen inside: 0x%06lx\n", ScreenPixel(200, 80));

    /* Polygon (filled, one-pixel pen) */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    DeleteObject(hbr);
    hbr = CreateSolidBrush(MAGENTA);
    hbrOld = SelectObject(hdc, hbr);
    hpenOld = SelectObject(hdc, GetStockObject(BLACK_PEN));
    pt[0].x = 20; pt[0].y = 160; pt[1].x = 100; pt[1].y = 160; pt[2].x = 60; pt[2].y = 230;
    Polygon(hdc, pt, 3);
    SelectObject(hdc, hpenOld);
    SelectObject(hdc, hbrOld);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(60, 180) == MAGENTA, "Polygon inside: 0x%06lx\n", ScreenPixel(60, 180));
    ok(ScreenPixel(60, 160) == BLACK, "Polygon edge: 0x%06lx\n", ScreenPixel(60, 160));
    DeleteObject(hbr);

    /* GradientFill, a rectangle of one colour */
    Clear(hwnd);
    hdc = GetDC(hwnd);
    {
        TRIVERTEX v[2] = { { 200, 190, 0xff00, 0, 0, 0 }, { 300, 230, 0xff00, 0, 0, 0 } };
        GRADIENT_RECT gr = { 0, 1 };

        GdiGradientFill(hdc, v, 2, &gr, 1, GRADIENT_FILL_RECT_H);
    }
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(250, 210) == RED, "GradientFill: 0x%06lx\n", ScreenPixel(250, 210));
    ok(ScreenPixel(299, 229) == RED, "GradientFill corner: 0x%06lx\n", ScreenPixel(299, 229));

    /* DrawIconEx of a cyan icon */
    Clear(hwnd);
    {
        HDC hdcMem = CreateCompatibleDC(NULL);
        BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), 16, -16, 1, 32, BI_RGB } };
        PULONG pBits;
        HBITMAP hbmColor = CreateDIBSection(hdcMem, &bmi, DIB_RGB_COLORS, (void **)&pBits, NULL, 0);
        HBITMAP hbmMask = CreateBitmap(16, 16, 1, 1, NULL);
        ICONINFO ii = { TRUE, 0, 0, hbmMask, hbmColor };
        HICON hIcon;
        RECT rcMask = { 0, 0, 16, 16 };
        HGDIOBJ hbmOld;
        int i;

        for (i = 0; i < 16 * 16; i++)
            pBits[i] = 0x0000ffff;   /* cyan, alpha 0: drawn as an opaque icon */
        hbmOld = SelectObject(hdcMem, hbmMask);
        FillRect(hdcMem, &rcMask, GetStockObject(BLACK_BRUSH));
        SelectObject(hdcMem, hbmOld);
        hIcon = CreateIconIndirect(&ii);
        hdc = GetDC(hwnd);
        DrawIconEx(hdc, 270, 20, hIcon, 32, 32, 0, NULL, DI_NORMAL);
        ReleaseDC(hwnd, hdc);
        ok(ScreenPixel(285, 35) == CYAN, "DrawIconEx: 0x%06lx\n", ScreenPixel(285, 35));
        DestroyIcon(hIcon);
        DeleteObject(hbmColor);
        DeleteObject(hbmMask);
        DeleteDC(hdcMem);
    }
}

static void Test_RestStays(HWND hwnd)
{
    HDC hdc;
    HFONT hfont, hfontOld;
    LONG cPaint;

    /* A mark on the screen DC over the window stays when the window draws elsewhere (a line, text) */
    Clear(hwnd);
    ScreenMark(300, 10, GREEN);
    ok(ScreenPixel(301, 11) == GREEN, "mark not on the screen: 0x%06lx\n", ScreenPixel(301, 11));
    hdc = GetDC(hwnd);
    MoveToEx(hdc, 20, 30, NULL);
    LineTo(hdc, 200, 30);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(301, 11) == GREEN, "a line elsewhere copied the window over the mark: 0x%06lx\n", ScreenPixel(301, 11));
    hdc = GetDC(hwnd);
    hfont = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, L"Arial");
    hfontOld = SelectObject(hdc, hfont);
    TextOutW(hdc, 20, 100, L"text", 4);
    SelectObject(hdc, hfontOld);
    DeleteObject(hfont);
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(301, 11) == GREEN, "text elsewhere copied the window over the mark: 0x%06lx\n", ScreenPixel(301, 11));

    /* A paint that draws nothing leaves the mark */
    g_PaintMode = 0;
    cPaint = g_cPaint;
    InvalidateRect(hwnd, NULL, FALSE);
    UpdateWindow(hwnd);
    ok(g_cPaint == cPaint + 1, "%ld paints\n", g_cPaint - cPaint);
    ok(ScreenPixel(301, 11) == GREEN, "a paint that drew nothing copied the window over the mark: 0x%06lx\n", ScreenPixel(301, 11));

    /* A paint that draws a line shows the line and leaves the mark */
    g_PaintMode = 1;
    cPaint = g_cPaint;
    InvalidateRect(hwnd, NULL, FALSE);
    UpdateWindow(hwnd);
    ok(g_cPaint == cPaint + 1, "%ld paints\n", g_cPaint - cPaint);
    ok(ScreenPixel(150, 200) == RED, "line drawn in the paint: 0x%06lx\n", ScreenPixel(150, 200));
    ok(ScreenPixel(301, 11) == GREEN, "a paint with a line elsewhere copied the window over the mark: 0x%06lx\n", ScreenPixel(301, 11));
    g_PaintMode = 0;

    /* Drawing over the mark replaces it */
    hdc = GetDC(hwnd);
    {
        RECT rc = { 298, 8, 310, 20 };
        FillRect(hdc, &rc, GetStockObject(BLACK_BRUSH));
    }
    ReleaseDC(hwnd, hdc);
    ok(ScreenPixel(301, 11) == BLACK, "drawing over the mark: 0x%06lx\n", ScreenPixel(301, 11));
}

START_TEST(RedirPresent)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    HDC hdcScreen;

    g_Level = GetRedirectionLevel();
    trace("NitroRedirection level %d\n", g_Level);

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
    wc.lpszClassName = L"RedirPresentTest";
    RegisterClassW(&wc);
    hwnd = CreateWindowExW(WS_EX_TOPMOST, wc.lpszClassName, L"RedirPresent", WS_POPUP | WS_VISIBLE,
                           WX, WY, WCX, WCY, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "CreateWindowExW failed: %lu\n", GetLastError());
    if (!hwnd)
        return;
    SetForegroundWindow(hwnd);
    UpdateWindow(hwnd);
    Pump();

    Test_Primitives(hwnd);
    Test_RestStays(hwnd);

    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
