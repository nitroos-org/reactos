/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What a window shows after ScrollWindowEx and ScrollDC is the same at every NitroRedirection level
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A pattern that depends on the pixel position is painted into a popup window (and a child window of it). The
 * window is scrolled, the exposed part is painted again, and the result is compared pixel by pixel with a model
 * made here from the documented behaviour: the scroll rectangle moves by dx, dy within the clip rectangle, and the
 * part not covered by the moved content is invalid and painted with the pattern. The comparison reads the window
 * through its DC (at levels 1 and 2 the surface of the window) and the screen through the screen DC, once at once
 * after a single scroll and once more when the window has been idle: a burst of scrolls may reach the screen up to two
 * frames after its end at levels 1 and 2 (Test_BurstTail measures it), but never differ from the window.
 */

#include "precomp.h"
#include <winreg.h>

#define WX  96
#define WY  96
#define CX  320
#define CY  240
#define CHILD_ID 7

static LONG g_cPaint;
static HBITMAP g_hbmPattern;
static HDC g_hdcPattern;

static COLORREF Pat(int x, int y)
{
    return RGB((x * 5 + y * 3) & 0xFF, ((x * 7) ^ (y * 11)) & 0xFF, (x + y * 2 + 40) & 0xFF);
}

static void Pump(DWORD ms)
{
    MSG msg;
    DWORD Start = GetTickCount();

    do
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(5);
    } while (GetTickCount() - Start < ms);
}

static LRESULT CALLBACK ParentProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
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
            BitBlt(hdc, ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right - ps.rcPaint.left, ps.rcPaint.bottom - ps.rcPaint.top,
                   g_hdcPattern, ps.rcPaint.left, ps.rcPaint.top, SRCCOPY);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            HBRUSH hbr = CreateSolidBrush(RGB(0, 0, 255));

            FillRect(hdc, &ps.rcPaint, hbr);
            DeleteObject(hbr);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* One frame of pixels, 0x00RRGGBB, top-down */
typedef struct { DWORD a[CX * CY]; } FRAME;

static BOOL Inside(const RECT *prc, int x, int y)
{
    return x >= prc->left && x < prc->right && y >= prc->top && y < prc->bottom;
}

static void FillPattern(FRAME *f)
{
    int x, y;

    for (y = 0; y < CY; y++)
        for (x = 0; x < CX; x++)
        {
            COLORREF c = Pat(x, y);
            f->a[y * CX + x] = (GetRValue(c) << 16) | (GetGValue(c) << 8) | GetBValue(c);
        }
}

static void FillChild(FRAME *f, const RECT *prc)
{
    int x, y;

    for (y = max(prc->top, 0); y < min(prc->bottom, CY); y++)
        for (x = max(prc->left, 0); x < min(prc->right, CX); x++)
            f->a[y * CX + x] = 0x0000FF;
}

/*
 * The documented result of a scroll of the rectangle pScroll (NULL: the client area) by dx, dy within pClip (NULL:
 * the client area): the part of the scroll rectangle inside the clip rectangle moves, what the moved content does not
 * cover of (scroll rectangle moved) + (scroll rectangle) inside the clip rectangle is invalid and painted with the
 * pattern again. A child window outside the exposed part is not painted by the parent (WS_CLIPCHILDREN).
 */
static void ModelScroll(FRAME *f, int dx, int dy, const RECT *pScroll, const RECT *pClip, const RECT *prcChild)
{
    static FRAME old;
    RECT rcClient = { 0, 0, CX, CY }, S = rcClient, C = rcClient, src, dst;
    int x, y;

    if (pScroll)
        IntersectRect(&S, &rcClient, pScroll);
    if (pClip)
        IntersectRect(&C, &rcClient, pClip);
    IntersectRect(&src, &S, &C);
    dst = src;
    OffsetRect(&dst, dx, dy);
    IntersectRect(&dst, &dst, &C);
    old = *f;
    for (y = dst.top; y < dst.bottom; y++)
        for (x = dst.left; x < dst.right; x++)
            f->a[y * CX + x] = old.a[(y - dy) * CX + (x - dx)];
    for (y = 0; y < CY; y++)
        for (x = 0; x < CX; x++)
        {
            RECT movedScroll = S, movedSrc = src;
            BOOL bInvalid;

            OffsetRect(&movedScroll, dx, dy);
            OffsetRect(&movedSrc, dx, dy);
            bInvalid = ((Inside(&movedScroll, x, y) && Inside(&C, x, y)) || Inside(&src, x, y)) && !Inside(&movedSrc, x, y);
            if (bInvalid && !(prcChild && Inside(prcChild, x, y)))
            {
                COLORREF c = Pat(x, y);
                f->a[y * CX + x] = (GetRValue(c) << 16) | (GetGValue(c) << 8) | GetBValue(c);
            }
        }
    if (prcChild)
        FillChild(f, prcChild);
}

/* Reads w x h pixels of hdc at x0, y0 */
static void ReadDC(HDC hdc, int x0, int y0, FRAME *f)
{
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), CX, -CY, 1, 32, BI_RGB } };
    VOID *pBits = NULL;
    HDC hdcMem = CreateCompatibleDC(hdc);
    HBITMAP hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
    HGDIOBJ old = SelectObject(hdcMem, hbm);
    int i;

    BitBlt(hdcMem, 0, 0, CX, CY, hdc, x0, y0, SRCCOPY);
    GdiFlush();
    for (i = 0; i < CX * CY; i++)
        f->a[i] = ((DWORD *)pBits)[i] & 0x00FFFFFF;
    SelectObject(hdcMem, old);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
}

static int Diff(const FRAME *a, const FRAME *b, int *px, int *py)
{
    int i, n = 0;

    for (i = 0; i < CX * CY; i++)
        if (a->a[i] != b->a[i])
        {
            if (!n)
            {
                *px = i % CX;
                *py = i / CX;
            }
            n++;
        }
    return n;
}

static void CheckWindow(HWND hwnd, const FRAME *model, const char *what)
{
    static FRAME got;
    HDC hdc = GetDC(hwnd);
    int n, x = 0, y = 0;

    ReadDC(hdc, 0, 0, &got);
    ReleaseDC(hwnd, hdc);
    n = Diff(&got, model, &x, &y);
    ok(n == 0, "%s: the window differs from the model in %d pixels, first at %d, %d (%06lx, model %06lx)\n",
       what, n, x, y, n ? got.a[y * CX + x] : 0, n ? model->a[y * CX + x] : 0);
}

static void CheckScreen(const FRAME *model, const char *what)
{
    static FRAME got;
    HDC hdc = GetDC(NULL);
    int n, x = 0, y = 0;

    ReadDC(hdc, WX, WY, &got);
    ReleaseDC(NULL, hdc);
    n = Diff(&got, model, &x, &y);
    ok(n == 0, "%s: the screen differs from the model in %d pixels, first at %d, %d (%06lx, model %06lx)\n",
       what, n, x, y, n ? got.a[y * CX + x] : 0, n ? model->a[y * CX + x] : 0);
}

/* The screen shows the model within a second (a burst of scrolls reaches the screen a few frames after its end) */
static void CheckScreenIdle(const FRAME *model, const char *what)
{
    static FRAME got;
    DWORD Start = GetTickCount(), Waited;
    int n, x = 0, y = 0;

    for (;;)
    {
        HDC hdc = GetDC(NULL);

        ReadDC(hdc, WX, WY, &got);
        ReleaseDC(NULL, hdc);
        n = Diff(&got, model, &x, &y);
        Waited = GetTickCount() - Start;
        if (n == 0 || Waited >= 1000)
            break;
        Pump(10);
    }
    ok(n == 0, "%s: the screen differs from the model in %d pixels a second after the last scroll, first at %d, %d (%06lx, model %06lx)\n",
       what, n, x, y, n ? got.a[y * CX + x] : 0, n ? model->a[y * CX + x] : 0);
    if (n == 0 && Waited > 100)
        trace("%s: the screen showed it %lu ms after the last scroll\n", what, Waited);
}

static void Reset(HWND hwnd, FRAME *model, HWND hChild, RECT *prcChild)
{
    FillPattern(model);
    if (hChild)
    {
        SetRect(prcChild, 100, 80, 160, 140);
        MoveWindow(hChild, prcChild->left, prcChild->top, 60, 60, FALSE);
        FillChild(model, prcChild);
    }
    InvalidateRect(hwnd, NULL, FALSE);
    if (hChild)
        InvalidateRect(hChild, NULL, FALSE);
    UpdateWindow(hwnd);
    if (hChild)
        UpdateWindow(hChild);
    Pump(120);
}

typedef struct
{
    const char *name;
    int dx, dy;
    BOOL bScroll, bClip;
    RECT rcScroll, rcClip;
    BOOL bChild;      /* SW_SCROLLCHILDREN, with the child window in the way */
} CASE;

static const CASE g_Cases[] =
{
    { "whole client, up 16",          0, -16, FALSE, FALSE, { 0 }, { 0 }, FALSE },
    { "whole client, down 16",        0,  16, FALSE, FALSE, { 0 }, { 0 }, FALSE },
    { "whole client, left 7, up 5",  -7,  -5, FALSE, FALSE, { 0 }, { 0 }, FALSE },
    { "scroll rectangle",            -7,   5, TRUE,  FALSE, { 40, 30, 280, 200 }, { 0 }, FALSE },
    { "scroll and clip rectangle",    9,  -6, TRUE,  TRUE,  { 20, 20, 300, 220 }, { 60, 40, 260, 180 }, FALSE },
    { "clip rectangle only",         -3,  11, FALSE, TRUE,  { 0 }, { 30, 50, 250, 210 }, FALSE },
    { "larger than the window",       0, -300, FALSE, FALSE, { 0 }, { 0 }, FALSE },
    { "with a child window",         10,   0, FALSE, FALSE, { 0 }, { 0 }, TRUE },
    { "child window, up 13",          0, -13, FALSE, FALSE, { 0 }, { 0 }, TRUE },
};

static void Test_ScrollWindowEx(HWND hwnd, HWND hChild)
{
    FRAME model;
    RECT rcChild;
    char buf[100];
    UINT i;

    for (i = 0; i < ARRAYSIZE(g_Cases); i++)
    {
        const CASE *c = &g_Cases[i];
        BOOL bUseChild = c->bChild;
        UINT flags = SW_INVALIDATE | SW_ERASE | (bUseChild ? SW_SCROLLCHILDREN : 0);

        ShowWindow(hChild, bUseChild ? SW_SHOWNA : SW_HIDE);
        Reset(hwnd, &model, bUseChild ? hChild : NULL, &rcChild);
        ScrollWindowEx(hwnd, c->dx, c->dy, c->bScroll ? &c->rcScroll : NULL, c->bClip ? &c->rcClip : NULL, NULL, NULL, flags);
        UpdateWindow(hwnd);
        if (bUseChild)
        {
            RECT moved = rcChild;

            OffsetRect(&moved, c->dx, c->dy);
            ModelScroll(&model, c->dx, c->dy, c->bScroll ? &c->rcScroll : NULL, c->bClip ? &c->rcClip : NULL, &moved);
        }
        else
        {
            ModelScroll(&model, c->dx, c->dy, c->bScroll ? &c->rcScroll : NULL, c->bClip ? &c->rcClip : NULL, NULL);
        }
        sprintf(buf, "ScrollWindowEx %s, window", c->name);
        CheckWindow(hwnd, &model, buf);
        sprintf(buf, "ScrollWindowEx %s, screen at once", c->name);
        CheckScreen(&model, buf);
        sprintf(buf, "ScrollWindowEx %s, screen when idle", c->name);
        CheckScreenIdle(&model, buf);
        if (bUseChild)
            ShowWindow(hChild, SW_HIDE);
    }
}

/* ScrollDC on the window DC, the exposed region painted through the same DC */
static void Test_ScrollDC(HWND hwnd, HWND hChild)
{
    static const struct { int dx, dy; BOOL bScroll, bClip; RECT rcScroll, rcClip; } cases[] =
    {
        { 0, -16, FALSE, FALSE, { 0 }, { 0 } },
        { -5, 9, TRUE, TRUE, { 10, 10, 310, 230 }, { 50, 60, 270, 200 } },
        { 12, 0, TRUE, FALSE, { 0, 100, 320, 160 }, { 0 } },
    };
    FRAME model;
    RECT rcChild, rcUpd;
    char buf[100];
    UINT i;

    ShowWindow(hChild, SW_HIDE);
    for (i = 0; i < ARRAYSIZE(cases); i++)
    {
        HDC hdc;
        HRGN hrgn = CreateRectRgn(0, 0, 0, 0);
        BOOL ret;

        Reset(hwnd, &model, NULL, &rcChild);
        FillPattern(&model);
        hdc = GetDC(hwnd);
        ret = ScrollDC(hdc, cases[i].dx, cases[i].dy, cases[i].bScroll ? &cases[i].rcScroll : NULL,
                       cases[i].bClip ? &cases[i].rcClip : NULL, hrgn, &rcUpd);
        ok(ret, "ScrollDC case %u failed: %lu\n", i, GetLastError());
        SelectClipRgn(hdc, hrgn);
        BitBlt(hdc, 0, 0, CX, CY, g_hdcPattern, 0, 0, SRCCOPY);
        SelectClipRgn(hdc, NULL);
        ReleaseDC(hwnd, hdc);
        DeleteObject(hrgn);
        ModelScroll(&model, cases[i].dx, cases[i].dy, cases[i].bScroll ? &cases[i].rcScroll : NULL,
                    cases[i].bClip ? &cases[i].rcClip : NULL, NULL);
        sprintf(buf, "ScrollDC case %u, window", i);
        CheckWindow(hwnd, &model, buf);
        sprintf(buf, "ScrollDC case %u, screen at once", i);
        CheckScreen(&model, buf);
        sprintf(buf, "ScrollDC case %u, screen when idle", i);
        CheckScreenIdle(&model, buf);
    }
}

/* Many scrolls without a pause, as an application scrolling a list does: window and screen end up the same */
static void Test_Burst(HWND hwnd, HWND hChild)
{
    FRAME model;
    RECT rcChild;
    int i, pass;

    ShowWindow(hChild, SW_HIDE);
    for (pass = 0; pass < 2; pass++)
    {
        Reset(hwnd, &model, NULL, &rcChild);
        FillPattern(&model);
        for (i = 0; i < 60; i++)
        {
            int dx = pass ? ((i & 1) ? 3 : -4) : 0, dy = (i % 3 == 2) ? 16 : -16;

            ScrollWindowEx(hwnd, dx, dy, NULL, NULL, NULL, NULL, SW_INVALIDATE | SW_ERASE);
            UpdateWindow(hwnd);
            ModelScroll(&model, dx, dy, NULL, NULL, NULL);
        }
        CheckWindow(hwnd, &model, pass ? "burst of 60 scrolls in both directions, window" : "burst of 60 scrolls, window");
        CheckScreenIdle(&model, pass ? "burst of 60 scrolls in both directions, screen when idle" : "burst of 60 scrolls, screen when idle");
    }
}

/* Something else draws into the window while a burst runs: its drawing is not lost or shown twice */
static void Test_BurstThenDraw(HWND hwnd, HWND hChild)
{
    FRAME model;
    RECT rcChild, rc = { 50, 40, 90, 70 };
    HBRUSH hbr = CreateSolidBrush(RGB(255, 0, 0));
    int i, x, y;

    ShowWindow(hChild, SW_HIDE);
    Reset(hwnd, &model, NULL, &rcChild);
    FillPattern(&model);
    for (i = 0; i < 10; i++)
    {
        ScrollWindowEx(hwnd, 0, -16, NULL, NULL, NULL, NULL, SW_INVALIDATE | SW_ERASE);
        UpdateWindow(hwnd);
        ModelScroll(&model, 0, -16, NULL, NULL, NULL);
    }
    {
        HDC hdc = GetDC(hwnd);

        FillRect(hdc, &rc, hbr);
        ReleaseDC(hwnd, hdc);
        for (y = rc.top; y < rc.bottom; y++)
            for (x = rc.left; x < rc.right; x++)
                model.a[y * CX + x] = 0xFF0000;
    }
    for (i = 0; i < 10; i++)
    {
        ScrollWindowEx(hwnd, 0, 16, NULL, NULL, NULL, NULL, SW_INVALIDATE | SW_ERASE);
        UpdateWindow(hwnd);
        ModelScroll(&model, 0, 16, NULL, NULL, NULL);
    }
    DeleteObject(hbr);
    CheckWindow(hwnd, &model, "scrolls around a FillRect, window");
    CheckScreenIdle(&model, "scrolls around a FillRect, screen when idle");
}

/*
 * The last scroll of a burst reaches the screen within two frames (33 ms): the screen is sampled at pixels the last
 * scroll changed, from the end of the last UpdateWindow until all of them show the model.
 */
#define TAIL_BURSTS     12
#define TAIL_SAMPLES    32
#define TAIL_LIMIT_MS   33.0

static void Test_BurstTail(HWND hwnd, HWND hChild)
{
    static FRAME model, prev;
    RECT rcChild;
    LARGE_INTEGER Freq, t0, t1;
    double Worst = 0, Ms[TAIL_BURSTS];
    int burst, i;

    QueryPerformanceFrequency(&Freq);
    ShowWindow(hChild, SW_HIDE);
    for (burst = 0; burst < TAIL_BURSTS; burst++)
    {
        int cSample = 0, sx[TAIL_SAMPLES], sy[TAIL_SAMPLES], nDiff = 0, k, bOk;
        HDC hdcScr;

        Reset(hwnd, &model, NULL, &rcChild);
        FillPattern(&model);
        for (i = 0; i < 40; i++)
        {
            int dy = (i & 1) ? 16 : -16;

            if (i == 39)
                prev = model;
            ScrollWindowEx(hwnd, 0, dy, NULL, NULL, NULL, NULL, SW_INVALIDATE | SW_ERASE);
            UpdateWindow(hwnd);
            ModelScroll(&model, 0, dy, NULL, NULL, NULL);
            /* Odd bursts: a scroll every 4 ms (a burst slower than a loop, still within a frame of each scroll) */
            if ((burst & 1) && i != 39)
            {
                LARGE_INTEGER a, b;

                QueryPerformanceCounter(&a);
                do
                    QueryPerformanceCounter(&b);
                while ((b.QuadPart - a.QuadPart) * 1000 < 4 * Freq.QuadPart);
            }
        }
        QueryPerformanceCounter(&t0);
        for (i = 0; i < CX * CY; i++)
            if (prev.a[i] != model.a[i])
                nDiff++;
        for (i = 0, k = 0; i < CX * CY && cSample < TAIL_SAMPLES; i++)
        {
            if (prev.a[i] == model.a[i])
                continue;
            if (k++ % (nDiff / TAIL_SAMPLES + 1) == 0)
            {
                sx[cSample] = i % CX;
                sy[cSample] = i / CX;
                cSample++;
            }
        }
        hdcScr = GetDC(NULL);
        for (;;)
        {
            bOk = TRUE;
            for (i = 0; i < cSample; i++)
            {
                COLORREF c = GetPixel(hdcScr, WX + sx[i], WY + sy[i]);
                DWORD got = ((c & 0xFF) << 16) | (c & 0xFF00) | ((c >> 16) & 0xFF);

                if (got != model.a[sy[i] * CX + sx[i]])
                {
                    bOk = FALSE;
                    break;
                }
            }
            QueryPerformanceCounter(&t1);
            if (bOk || (t1.QuadPart - t0.QuadPart) * 1000 / Freq.QuadPart >= 1000)
                break;
        }
        ReleaseDC(NULL, hdcScr);
        Ms[burst] = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)Freq.QuadPart;
        ok(bOk, "burst %d: the screen did not show the last scroll within a second\n", burst);
        ok(nDiff > 0 && cSample > 0, "burst %d: the last scroll changed nothing (%d pixels)\n", burst, nDiff);
        ok(Ms[burst] <= TAIL_LIMIT_MS, "burst %d: the last scroll reached the screen %.1f ms after the scroll\n", burst, Ms[burst]);
        if (Ms[burst] > Worst)
            Worst = Ms[burst];
        CheckScreenIdle(&model, "burst tail, screen when idle");
    }
    for (burst = 0; burst < TAIL_BURSTS; burst++)
        trace("tail %d: %.1f ms\n", burst, Ms[burst]);
    trace("tail worst %.1f ms\n", Worst);
}

START_TEST(RedirScroll)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd, hChild;
    HDC hdcScreen;
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), CX, -CY, 1, 32, BI_RGB } };
    VOID *pBits;
    static FRAME pat;
    int i;

    hdcScreen = GetDC(NULL);
    if (GetDeviceCaps(hdcScreen, BITSPIXEL) < 24)
    {
        skip("screen has fewer than 24 bits per pixel\n");
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    g_hdcPattern = CreateCompatibleDC(hdcScreen);
    g_hbmPattern = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
    ReleaseDC(NULL, hdcScreen);
    SelectObject(g_hdcPattern, g_hbmPattern);
    FillPattern(&pat);
    for (i = 0; i < CX * CY; i++)
        ((DWORD *)pBits)[i] = pat.a[i];

    wc.lpfnWndProc = ParentProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = L"RedirScrollParent";
    RegisterClassW(&wc);
    wc.lpfnWndProc = ChildProc;
    wc.lpszClassName = L"RedirScrollChild";
    RegisterClassW(&wc);

    hwnd = CreateWindowExW(WS_EX_TOPMOST, L"RedirScrollParent", L"RedirScroll", WS_POPUP | WS_VISIBLE | WS_CLIPCHILDREN,
                           WX, WY, CX, CY, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "CreateWindowExW failed: %lu\n", GetLastError());
    if (!hwnd)
        return;
    hChild = CreateWindowExW(0, L"RedirScrollChild", L"", WS_CHILD | WS_VISIBLE, 100, 80, 60, 60, hwnd,
                             (HMENU)(ULONG_PTR)CHILD_ID, wc.hInstance, NULL);
    ok(hChild != NULL, "CreateWindowExW of the child failed: %lu\n", GetLastError());
    SetForegroundWindow(hwnd);
    UpdateWindow(hwnd);
    Pump(150);

    if (hChild)
    {
        Test_ScrollWindowEx(hwnd, hChild);
        Test_ScrollDC(hwnd, hChild);
        Test_Burst(hwnd, hChild);
        Test_BurstThenDraw(hwnd, hChild);
        Test_BurstTail(hwnd, hChild);
    }

    DestroyWindow(hwnd);
    Pump(50);
    UnregisterClassW(L"RedirScrollParent", wc.hInstance);
    UnregisterClassW(L"RedirScrollChild", wc.hInstance);
    DeleteDC(g_hdcPattern);
    DeleteObject(g_hbmPattern);
}
