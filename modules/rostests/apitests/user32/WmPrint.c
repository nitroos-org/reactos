/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for DefWindowProc's WM_PRINT and for PrintWindow
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winreg.h>

#ifndef PW_CLIENTONLY
#define PW_CLIENTONLY 1
#endif

/*
 * Every test window paints solid colours of its own: WM_ERASEBKGND fills the client area with the
 * "erase" colour, WM_PRINTCLIENT fills the client area less a 2 pixel ring with the "print" colour,
 * WM_PAINT fills the same inset with the "paint" colour. The target bitmap starts filled with SENTINEL.
 */
enum { W_P, W_A, W_B, W_C, W_D, W_F, W_O, W_U, W_V, W_W, W_X, W_Y, W_Z, W_Q, W_R, W_MAX };
enum { COL_ERASE, COL_PRINT, COL_PAINT };
#define SENTINEL RGB(0x12, 0x34, 0x56)
#define MARGIN 16

static HWND g_hwnd[W_MAX];
static BOOL g_paintonly[W_MAX];
static HDC g_hdc;
static HBITMAP g_hbm;
static DWORD *g_bits;
static INT g_cx, g_cy;
static BOOL g_log;

typedef struct
{
    int w;
    UINT msg;
    LPARAM flags;
    BOOL target;
    POINT org;
    BOOL clip;
    RECT rcClip;
} PRINTMSG;

#define MAX_LOG 128
static PRINTMSG g_got[MAX_LOG], g_exp[MAX_LOG];
static int g_ngot, g_nexp;
/* WM_NCUAHDRAWFRAME: sent by Windows 10 (and ReactOS), not by Windows 7, which draws the frame itself */
static int g_ncgot, g_ncexp, g_ncbad;

static COLORREF color(int w, int type)
{
    return RGB(0x10 + w * 0x0f, 0x28 + type * 0x48, 0xA7);
}

static int windex(HWND hwnd)
{
    int i;
    for (i = 0; i < W_MAX; i++)
        if (hwnd && g_hwnd[i] == hwnd)
            return i;
    return -1;
}

static void fill(HDC hdc, int r, int b, COLORREF c, int inset)
{
    HBRUSH hbr = CreateSolidBrush(c);
    RECT rc = { inset, inset, r - inset, b - inset };
    FillRect(hdc, &rc, hbr);
    DeleteObject(hbr);
}

static void log_msg(HWND hwnd, UINT msg, HDC hdc, LPARAM flags)
{
    PRINTMSG *p;
    HRGN hrgn;
    if (!g_log || g_ngot >= MAX_LOG)
        return;
    p = &g_got[g_ngot++];
    p->w = windex(hwnd);
    p->msg = msg;
    p->flags = flags;
    p->target = (hdc == g_hdc);
    GetWindowOrgEx(hdc, &p->org);
    hrgn = CreateRectRgn(0, 0, 0, 0);
    p->clip = (GetClipRgn(hdc, hrgn) == 1);
    SetRectEmpty(&p->rcClip);
    if (p->clip)
        GetRgnBox(hrgn, &p->rcClip);
    DeleteObject(hrgn);
}

static LRESULT CALLBACK TestProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int w = windex(hwnd);
    RECT rc;
    switch (msg)
    {
    case WM_PRINT:
        log_msg(hwnd, msg, (HDC)wParam, lParam);
        break;
    case WM_NCUAHDRAWFRAME:
        if (g_log)
        {
            g_ncgot++;
            if ((HDC)wParam != g_hdc)
                g_ncbad++;
        }
        break;
    case WM_ERASEBKGND:
        log_msg(hwnd, msg, (HDC)wParam, 0);
        if (w < 0)
            break;
        GetClientRect(hwnd, &rc);
        fill((HDC)wParam, rc.right, rc.bottom, color(w, COL_ERASE), 0);
        return 1;
    case WM_PRINTCLIENT:
        log_msg(hwnd, msg, (HDC)wParam, lParam);
        if (w < 0 || g_paintonly[w])
            break;
        GetClientRect(hwnd, &rc);
        fill((HDC)wParam, rc.right, rc.bottom, color(w, COL_PRINT), 2);
        return 0;
    case WM_PAINT:
        if (w >= 0)
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            GetClientRect(hwnd, &rc);
            fill(hdc, rc.right, rc.bottom, color(w, COL_PAINT), 2);
            EndPaint(hwnd, &ps);
            return 0;
        }
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void pump(void)
{
    MSG msg;
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 200)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

static void new_target(int cx, int cy)
{
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER) } };
    if (g_hdc)
    {
        DeleteDC(g_hdc);
        DeleteObject(g_hbm);
    }
    bmi.bmiHeader.biWidth = cx;
    bmi.bmiHeader.biHeight = -cy;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    g_hdc = CreateCompatibleDC(NULL);
    g_hbm = CreateDIBSection(g_hdc, &bmi, DIB_RGB_COLORS, (void **)&g_bits, NULL, 0);
    SelectObject(g_hdc, g_hbm);
    g_cx = cx;
    g_cy = cy;
}

static void clear_target(void)
{
    int i;
    GdiFlush();
    for (i = 0; i < g_cx * g_cy; i++)
        g_bits[i] = (GetRValue(SENTINEL) << 16) | (GetGValue(SENTINEL) << 8) | GetBValue(SENTINEL);
}

/* pixel at device coordinates of the target */
static COLORREF pixel(int x, int y)
{
    DWORD px;
    GdiFlush();
    if (x < 0 || y < 0 || x >= g_cx || y >= g_cy)
        return CLR_INVALID;
    px = g_bits[y * g_cx + x];
    return RGB((px >> 16) & 0xff, (px >> 8) & 0xff, px & 0xff);
}

static void get_rects(int w, RECT *prcWindow, RECT *prcClient)
{
    GetWindowRect(g_hwnd[w], prcWindow);
    GetClientRect(g_hwnd[w], prcClient);
    MapWindowPoints(g_hwnd[w], NULL, (POINT *)prcClient, 2);
}

static void add_exp(int w, UINT msg, LPARAM flags, POINT org, const RECT *prcClip)
{
    PRINTMSG *p;
    if (g_nexp >= MAX_LOG)
        return;
    p = &g_exp[g_nexp++];
    p->w = w;
    p->msg = msg;
    p->flags = flags;
    p->target = TRUE;
    p->org = org;
    p->clip = (prcClip != NULL);
    if (prcClip)
        p->rcClip = *prcClip;
    else
        SetRectEmpty(&p->rcClip);
}

/* device rectangle of a w x h area whose top left corner is at logical (0, 0) with window origin org */
static void dev_rect(RECT *prc, POINT org, int w, int h, POINT vp, const RECT *prcClip)
{
    SetRect(prc, vp.x - org.x, vp.y - org.y, vp.x - org.x + w, vp.y - org.y + h);
    if (prcClip && !IntersectRect(prc, prc, prcClip))
        SetRectEmpty(prc);
}

/* The Windows model of DefWindowProc(WM_PRINT), as measured on Server 2008 R2 and Windows 10 */
static void expect_print(int w, LPARAM flags, POINT org, POINT vp, const RECT *prcClip)
{
    RECT rcWindow, rcClient, rcChildWindow, rcChildClient, rc;
    POINT corg;
    HWND hwnd;

    add_exp(w, WM_PRINT, flags, org, prcClip);
    if ((flags & PRF_CHECKVISIBLE) && !IsWindowVisible(g_hwnd[w]))
        return;
    if (flags & PRF_NONCLIENT)
        g_ncexp++;
    if (!(flags & PRF_CLIENT))
        return;

    get_rects(w, &rcWindow, &rcClient);
    corg = org;
    if (flags & PRF_NONCLIENT)
    {
        corg.x -= rcClient.left - rcWindow.left;
        corg.y -= rcClient.top - rcWindow.top;
    }
    dev_rect(&rc, corg, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, vp, prcClip);
    if (flags & PRF_ERASEBKGND)
        add_exp(w, WM_ERASEBKGND, 0, corg, &rc);
    add_exp(w, WM_PRINTCLIENT, flags, corg, &rc);

    if (flags & PRF_CHILDREN)
    {
        for (hwnd = GetWindow(g_hwnd[w], GW_CHILD); hwnd; hwnd = GetWindow(hwnd, GW_HWNDNEXT))
        {
            int c = windex(hwnd);
            if (c < 0 || !(GetWindowLongW(hwnd, GWL_STYLE) & WS_VISIBLE))
                continue;
            get_rects(c, &rcChildWindow, &rcChildClient);
            corg.x = org.x - (rcChildWindow.left - rcWindow.left);
            corg.y = org.y - (rcChildWindow.top - rcWindow.top);
            dev_rect(&rc, corg, rcChildWindow.right - rcChildWindow.left,
                     rcChildWindow.bottom - rcChildWindow.top, vp, prcClip);
            expect_print(c, (flags | PRF_NONCLIENT | PRF_ERASEBKGND) & ~PRF_CHECKVISIBLE, corg, vp, &rc);
        }
    }
    if (flags & PRF_OWNED)
    {
        for (hwnd = GetTopWindow(NULL); hwnd; hwnd = GetWindow(hwnd, GW_HWNDNEXT))
        {
            int o = windex(hwnd);
            if (o < 0 || GetWindow(hwnd, GW_OWNER) != g_hwnd[w] ||
                !(GetWindowLongW(hwnd, GWL_STYLE) & WS_VISIBLE))
                continue;
            get_rects(o, &rcChildWindow, &rcChildClient);
            corg.x = org.x - (rcChildWindow.left - rcWindow.left);
            corg.y = org.y - (rcChildWindow.top - rcWindow.top);
            expect_print(o, flags, corg, vp, prcClip);
        }
    }
}

static const char *msgname(UINT msg)
{
    switch (msg)
    {
    case WM_PRINT: return "WM_PRINT";
    case WM_PRINTCLIENT: return "WM_PRINTCLIENT";
    case WM_ERASEBKGND: return "WM_ERASEBKGND";
    }
    return "?";
}

static const char g_names[] = "PABCDFOUVWXYZQR";

/* compare the logged sequence with the model; returns the index of the first difference or -1 */
static int compare_log(char *buf, size_t cb)
{
    int i;
    for (i = 0; i < g_nexp || i < g_ngot; i++)
    {
        PRINTMSG *e = &g_exp[i], *g = &g_got[i];
        if (i >= g_ngot)
        {
            _snprintf(buf, cb, "missing #%d %c %s %#lx", i, g_names[e->w], msgname(e->msg), (long)e->flags);
            return i;
        }
        if (i >= g_nexp)
        {
            _snprintf(buf, cb, "extra #%d %c %s %#lx", i, g->w >= 0 ? g_names[g->w] : '?', msgname(g->msg), (long)g->flags);
            return i;
        }
        if (e->w != g->w || e->msg != g->msg ||
            ((e->msg == WM_PRINT || e->msg == WM_PRINTCLIENT) && e->flags != g->flags) ||
            !g->target || e->org.x != g->org.x || e->org.y != g->org.y || e->clip != g->clip ||
            (e->clip && !EqualRect(&e->rcClip, &g->rcClip)))
        {
            _snprintf(buf, cb, "#%d expected %c %s %#lx org %ld,%ld clip %d %ld,%ld-%ld,%ld, got %c %s %#lx target %d org %ld,%ld clip %d %ld,%ld-%ld,%ld",
                      i, g_names[e->w], msgname(e->msg), (long)e->flags, e->org.x, e->org.y, e->clip,
                      e->rcClip.left, e->rcClip.top, e->rcClip.right, e->rcClip.bottom,
                      g->w >= 0 ? g_names[g->w] : '?', msgname(g->msg), (long)g->flags, g->target, g->org.x, g->org.y,
                      g->clip, g->rcClip.left, g->rcClip.top, g->rcClip.right, g->rcClip.bottom);
            return i;
        }
    }
    return -1;
}

static HWND create(int w, LPCWSTR cls, DWORD exstyle, DWORD style, int x, int y, int cx, int cy, HWND parent)
{
    g_hwnd[w] = CreateWindowExW(exstyle, cls, NULL, style, x, y, cx, cy, parent,
                                (style & WS_CHILD) ? (HMENU)(INT_PTR)(w + 1) : NULL, GetModuleHandleW(NULL), NULL);
    ok(g_hwnd[w] != NULL, "CreateWindowEx %c failed: %lu\n", g_names[w], GetLastError());
    return g_hwnd[w];
}

static void register_class(void)
{
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = TestProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = L"WmPrintTest";
    RegisterClassW(&wc);
}

/* WM_PRINT to window w with the given flags; returns DefWindowProc's result */
static LRESULT do_print(int w, LPARAM flags, POINT vp, const RECT *prcCallerClip, POINT callerOrg)
{
    LRESULT ret;
    POINT org;
    HRGN hrgn;

    clear_target();
    SetViewportOrgEx(g_hdc, vp.x, vp.y, NULL);
    SetWindowOrgEx(g_hdc, callerOrg.x, callerOrg.y, NULL);
    SelectClipRgn(g_hdc, NULL);
    if (prcCallerClip)
    {
        hrgn = CreateRectRgnIndirect(prcCallerClip);
        SelectClipRgn(g_hdc, hrgn);
        DeleteObject(hrgn);
    }
    g_nexp = g_ngot = 0;
    g_ncexp = g_ncgot = g_ncbad = 0;
    expect_print(w, flags, callerOrg, vp, prcCallerClip);
    g_log = TRUE;
    ret = SendMessageW(g_hwnd[w], WM_PRINT, (WPARAM)g_hdc, flags);
    g_log = FALSE;
    GetWindowOrgEx(g_hdc, &org);
    ok(org.x == callerOrg.x && org.y == callerOrg.y, "flags %#lx: window origin after %ld,%ld\n", (long)flags, org.x, org.y);
    GetViewportOrgEx(g_hdc, &org);
    ok(org.x == vp.x && org.y == vp.y, "flags %#lx: viewport origin after %ld,%ld\n", (long)flags, org.x, org.y);
    return ret;
}

static void check_sequence(LPARAM flags, const char *what)
{
    char buf[512];
    int i = compare_log(buf, sizeof(buf));
    ok(i < 0, "%s flags %#lx: %s\n", what, (long)flags, buf);
    ok(g_ncgot == 0 || g_ncgot == g_ncexp, "%s flags %#lx: %d WM_NCUAHDRAWFRAME, expected %d\n", what, (long)flags, g_ncgot, g_ncexp);
    ok(g_ncbad == 0, "%s flags %#lx: WM_NCUAHDRAWFRAME without the DC\n", what, (long)flags);
}

/* device point of window-relative point (x, y) of window w, when the printed window is at vp */
static POINT wpt(int w, int x, int y)
{
    RECT rcP, rcW;
    POINT pt;
    GetWindowRect(g_hwnd[W_P], &rcP);
    GetWindowRect(g_hwnd[w], &rcW);
    pt.x = MARGIN + (rcW.left - rcP.left) + x;
    pt.y = MARGIN + (rcW.top - rcP.top) + y;
    return pt;
}

static void check_pixels(LPARAM flags)
{
    RECT rcWindow, rcClient;
    POINT co, pt;
    COLORREF c, exp;
    BOOL client = (flags & PRF_CLIENT) != 0;
    BOOL children = client && (flags & PRF_CHILDREN);
    BOOL owned = client && (flags & PRF_OWNED);
    int ch;

    get_rects(W_P, &rcWindow, &rcClient);
    ch = rcClient.bottom - rcClient.top;
    /* client origin of P in the target */
    co.x = MARGIN + ((flags & PRF_NONCLIENT) ? rcClient.left - rcWindow.left : 0);
    co.y = MARGIN + ((flags & PRF_NONCLIENT) ? rcClient.top - rcWindow.top : 0);

    /* inside P's client area, away from the children */
    c = pixel(co.x + 100, co.y + 120);
    exp = client ? color(W_P, COL_PRINT) : SENTINEL;
    ok(c == exp, "flags %#lx: P client %06lx, expected %06lx\n", (long)flags, c, exp);

    /* the ring of P's client area: background only with PRF_ERASEBKGND */
    c = pixel(co.x + 1, co.y + ch / 2);
    exp = (client && (flags & PRF_ERASEBKGND)) ? color(W_P, COL_ERASE) : SENTINEL;
    ok(c == exp, "flags %#lx: P client edge %06lx, expected %06lx\n", (long)flags, c, exp);

    /* bottom left of the frame */
    c = pixel(MARGIN + 1, MARGIN + (rcWindow.bottom - rcWindow.top) - 2);
    if (flags & PRF_NONCLIENT)
        ok(c != SENTINEL && c != CLR_INVALID, "flags %#lx: frame not drawn\n", (long)flags);
    else
        ok(c == SENTINEL, "flags %#lx: frame %06lx drawn\n", (long)flags, c);

    /* child A: its own client, and its border, at its offset from P's window origin */
    pt = wpt(W_A, 30, 20);
    c = pixel(pt.x, pt.y);
    exp = children ? color(W_A, COL_PRINT) : (client ? color(W_P, COL_PRINT) : SENTINEL);
    ok(c == exp, "flags %#lx: A %06lx, expected %06lx\n", (long)flags, c, exp);
    pt = wpt(W_A, 0, 20);
    c = pixel(pt.x, pt.y);
    if (children)
        ok(c != SENTINEL && c != color(W_P, COL_PRINT) && c != color(W_A, COL_ERASE), "flags %#lx: A border %06lx\n", (long)flags, c);

    /* grandchild C inside B, and B's background ring */
    pt = wpt(W_C, 10, 10);
    c = pixel(pt.x, pt.y);
    exp = children ? color(W_C, COL_PRINT) : (client ? color(W_P, COL_PRINT) : SENTINEL);
    ok(c == exp, "flags %#lx: C %06lx, expected %06lx\n", (long)flags, c, exp);
    pt = wpt(W_B, 30, 1);
    c = pixel(pt.x, pt.y);
    if (children)
        ok(c == color(W_B, COL_ERASE), "flags %#lx: B edge %06lx\n", (long)flags, c);

    /* the part of child F beyond P's window: children are not clipped to the parent */
    pt.x = MARGIN + (rcWindow.right - rcWindow.left) + 4;
    pt.y = wpt(W_F, 0, 30).y;
    c = pixel(pt.x, pt.y);
    exp = children ? color(W_F, COL_PRINT) : SENTINEL;
    ok(c == exp, "flags %#lx: F outside %06lx, expected %06lx\n", (long)flags, c, exp);

    /* hidden child D is never drawn */
    pt = wpt(W_D, 20, 15);
    c = pixel(pt.x, pt.y);
    ok(c != color(W_D, COL_PRINT) && c != color(W_D, COL_ERASE), "flags %#lx: hidden D drawn\n", (long)flags);

    /* owned window O */
    pt = wpt(W_O, 25, 20);
    c = pixel(pt.x, pt.y);
    if (owned)
        ok(c == color(W_O, COL_PRINT), "flags %#lx: O %06lx\n", (long)flags, c);
    else
        ok(c != color(W_O, COL_PRINT), "flags %#lx: O drawn\n", (long)flags);
}

static void destroy_all(void)
{
    int i;
    for (i = W_MAX - 1; i >= 0; i--)
    {
        if (g_hwnd[i] && IsWindow(g_hwnd[i]))
            DestroyWindow(g_hwnd[i]);
        g_hwnd[i] = NULL;
        g_paintonly[i] = FALSE;
    }
}

static void create_tree(void)
{
    create(W_P, L"WmPrintTest", 0, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, 100, 100, 240, 180, NULL);
    create(W_A, L"WmPrintTest", 0, WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 10, 60, 40, g_hwnd[W_P]);
    create(W_B, L"WmPrintTest", 0, WS_CHILD | WS_VISIBLE, 90, 10, 60, 40, g_hwnd[W_P]);
    create(W_C, L"WmPrintTest", 0, WS_CHILD | WS_VISIBLE, 8, 8, 20, 20, g_hwnd[W_B]);
    create(W_D, L"WmPrintTest", 0, WS_CHILD, 10, 70, 40, 30, g_hwnd[W_P]);
    create(W_F, L"WmPrintTest", 0, WS_CHILD | WS_VISIBLE, 180, 90, 80, 60, g_hwnd[W_P]);
    create(W_O, L"WmPrintTest", 0, WS_POPUP | WS_BORDER, 160, 160, 50, 40, g_hwnd[W_P]);
    ShowWindow(g_hwnd[W_P], SW_SHOWNORMAL);
    ShowWindow(g_hwnd[W_O], SW_SHOWNOACTIVATE);
    UpdateWindow(g_hwnd[W_P]);
    pump();
}

START_TEST(WmPrint)
{
    RECT rcWindow, rcClient, rcClip;
    POINT vp = { MARGIN, MARGIN }, org0 = { 0, 0 }, org = { -7, -9 };
    LRESULT ret;
    int f;

    register_class();
    create_tree();
    get_rects(W_P, &rcWindow, &rcClient);
    new_target(rcWindow.right - rcWindow.left + 2 * MARGIN + 64, rcWindow.bottom - rcWindow.top + 2 * MARGIN + 64);

    /* every combination of the six flags */
    for (f = 0; f < 64; f++)
    {
        LPARAM flags = 0;
        if (f & 1) flags |= PRF_CHECKVISIBLE;
        if (f & 2) flags |= PRF_NONCLIENT;
        if (f & 4) flags |= PRF_CLIENT;
        if (f & 8) flags |= PRF_ERASEBKGND;
        if (f & 16) flags |= PRF_CHILDREN;
        if (f & 32) flags |= PRF_OWNED;
        ret = do_print(W_P, flags, vp, NULL, org0);
        ok(ret == 1, "flags %#lx: ret %ld\n", (long)flags, (long)ret);
        check_sequence(flags, "P");
        check_pixels(flags);
    }

    /* unknown flags are passed on to the children */
    ret = do_print(W_P, PRF_CLIENT | PRF_CHILDREN | 0x100, vp, NULL, org0);
    ok(ret == 1, "ret %ld\n", (long)ret);
    check_sequence(PRF_CLIENT | PRF_CHILDREN | 0x100, "P");

    /* a hidden child: PRF_CHECKVISIBLE skips it and DefWindowProc returns 0 */
    ret = do_print(W_D, PRF_CHECKVISIBLE | PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND, vp, NULL, org0);
    ok(ret == 0, "ret %ld\n", (long)ret);
    check_sequence(PRF_CHECKVISIBLE | PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND, "D");
    ret = do_print(W_D, PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND, vp, NULL, org0);
    ok(ret == 1, "ret %ld\n", (long)ret);
    check_sequence(PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND, "D");

    /* a child printed directly, with its grandchild */
    ret = do_print(W_B, PRF_CLIENT | PRF_CHILDREN, vp, NULL, org0);
    ok(ret == 1, "ret %ld\n", (long)ret);
    check_sequence(PRF_CLIENT | PRF_CHILDREN, "B");

    /* the caller's window origin and clip region are respected */
    ret = do_print(W_P, PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND | PRF_CHILDREN, vp, NULL, org);
    check_sequence(PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND | PRF_CHILDREN, "P caller origin");
    SetRect(&rcClip, 40, 40, 120, 100);
    ret = do_print(W_P, PRF_CLIENT | PRF_ERASEBKGND | PRF_CHILDREN | PRF_OWNED, vp, &rcClip, org0);
    check_sequence(PRF_CLIENT | PRF_ERASEBKGND | PRF_CHILDREN | PRF_OWNED, "P caller clip");
    {
        HRGN hrgn = CreateRectRgn(0, 0, 0, 0);
        RECT rc;
        ok(GetClipRgn(g_hdc, hrgn) == 1, "caller clip region lost\n");
        GetRgnBox(hrgn, &rc);
        ok(EqualRect(&rc, &rcClip), "caller clip region %ld,%ld-%ld,%ld\n", rc.left, rc.top, rc.right, rc.bottom);
        DeleteObject(hrgn);
    }
    SelectClipRgn(g_hdc, NULL);

    /* a hidden window: PRF_CHECKVISIBLE stops everything, otherwise the frame is printed too */
    ShowWindow(g_hwnd[W_O], SW_HIDE);
    ShowWindow(g_hwnd[W_P], SW_HIDE);
    pump();
    ret = do_print(W_P, PRF_CHECKVISIBLE | PRF_CLIENT | PRF_CHILDREN, vp, NULL, org0);
    ok(ret == 0, "ret %ld\n", (long)ret);
    check_sequence(PRF_CHECKVISIBLE | PRF_CLIENT | PRF_CHILDREN, "hidden P");
    ret = do_print(W_P, PRF_NONCLIENT | PRF_CLIENT | PRF_CHILDREN, vp, NULL, org0);
    ok(ret == 1, "ret %ld\n", (long)ret);
    check_sequence(PRF_NONCLIENT | PRF_CLIENT | PRF_CHILDREN, "hidden P");
    {
        COLORREF c = pixel(MARGIN + 1, MARGIN + (rcWindow.bottom - rcWindow.top) - 2);
        ok(c != SENTINEL && c != CLR_INVALID, "hidden P: frame not drawn\n");
    }
    ShowWindow(g_hwnd[W_P], SW_SHOWNORMAL);
    pump();

    /* owned windows of owned windows; hidden owned windows are skipped */
    create(W_U, L"WmPrintTest", 0, WS_POPUP | WS_BORDER, 230, 230, 50, 40, g_hwnd[W_P]);
    create(W_V, L"WmPrintTest", 0, WS_POPUP | WS_BORDER, 120, 230, 50, 40, g_hwnd[W_P]);
    create(W_W, L"WmPrintTest", 0, WS_POPUP, 250, 120, 40, 30, g_hwnd[W_U]);
    ShowWindow(g_hwnd[W_O], SW_SHOWNOACTIVATE);
    ShowWindow(g_hwnd[W_U], SW_SHOWNOACTIVATE);
    ShowWindow(g_hwnd[W_W], SW_SHOWNOACTIVATE);
    pump();
    ret = do_print(W_P, PRF_NONCLIENT | PRF_CLIENT | PRF_OWNED, vp, NULL, org0);
    ok(ret == 1, "ret %ld\n", (long)ret);
    check_sequence(PRF_NONCLIENT | PRF_CLIENT | PRF_OWNED, "owned chain");
    destroy_all();

    /* overlapping children: the lower window in the Z order is printed later, over the upper one */
    {
        int pass;
        for (pass = 0; pass < 2; pass++)
        {
            DWORD style = WS_CHILD | WS_VISIBLE | (pass ? WS_CLIPSIBLINGS : 0);
            HWND lower;
            int l;
            create(W_Z, L"WmPrintTest", 0, WS_POPUP | WS_VISIBLE | WS_CLIPCHILDREN, 420, 100, 200, 150, NULL);
            create(W_X, L"WmPrintTest", 0, style, 10, 10, 80, 60, g_hwnd[W_Z]);
            create(W_Y, L"WmPrintTest", 0, style, 50, 40, 80, 60, g_hwnd[W_Z]);
            pump();
            ret = do_print(W_Z, PRF_CLIENT | PRF_CHILDREN, vp, NULL, org0);
            check_sequence(PRF_CLIENT | PRF_CHILDREN, "overlap");
            lower = GetWindow(GetWindow(g_hwnd[W_Z], GW_CHILD), GW_HWNDNEXT);
            l = windex(lower);
            ok(l == W_X || l == W_Y, "Z order\n");
            if (l >= 0)
                ok(pixel(MARGIN + 70, MARGIN + 55) == color(l, COL_PRINT), "overlap: %06lx, lower window %c\n",
                   pixel(MARGIN + 70, MARGIN + 55), g_names[l]);
            SetWindowPos(g_hwnd[W_Y], HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            ret = do_print(W_Z, PRF_CLIENT | PRF_CHILDREN, vp, NULL, org0);
            check_sequence(PRF_CLIENT | PRF_CHILDREN, "overlap raised");
            ok(pixel(MARGIN + 70, MARGIN + 55) == color(W_X, COL_PRINT), "overlap raised: %06lx\n",
               pixel(MARGIN + 70, MARGIN + 55));
            destroy_all();
        }
    }

    DeleteDC(g_hdc);
    DeleteObject(g_hbm);
    g_hdc = NULL;
}

/* PrintWindow */

static HWND g_hwndThread;

static DWORD WINAPI thread_proc(LPVOID arg)
{
    MSG msg;
    g_hwndThread = CreateWindowExW(WS_EX_TOPMOST, L"WmPrintTest", NULL, WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                   400, 300, 160, 120, NULL, NULL, GetModuleHandleW(NULL), NULL);
    g_hwnd[W_R] = g_hwndThread;
    SetEvent((HANDLE)arg);
    while (GetMessageW(&msg, NULL, 0, 0))
        DispatchMessageW(&msg);
    return 0;
}

static BOOL print_window(int w, UINT flags, int off)
{
    BOOL ret;
    clear_target();
    SetViewportOrgEx(g_hdc, off, off, NULL);
    ret = PrintWindow(g_hwnd[w], g_hdc, flags);
    SetViewportOrgEx(g_hdc, 0, 0, NULL);
    return ret;
}

/* NitroRedirection >= 1: win32k keeps window content in redirection surfaces, as Windows with DWM */
static BOOL nitro_redirected(void)
{
    static int r = -1;
    HKEY hKey;
    DWORD v = 0, cb = sizeof(v);

    if (r < 0)
    {
        r = 0;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            if (RegQueryValueExW(hKey, L"NitroRedirection", NULL, NULL, (BYTE *)&v, &cb) == ERROR_SUCCESS && v != 0)
                r = 1;
            RegCloseKey(hKey);
        }
    }
    return r;
}

/* a pixel of window w's own content: what WM_PAINT draws, as Windows' redirection gives */
static void check_content(int w, int x, int y, BOOL offscreen, const char *what)
{
    COLORREF c = pixel(x, y);
    if (offscreen)
    {
        /* Without redirection (NitroRedirection 0): off the screen, the image is the window's WM_PRINT output */
        ok(c == color(w, COL_PAINT) || c == color(w, COL_PRINT) || (g_paintonly[w] && c == color(w, COL_ERASE)),
           "%s: %06lx is not the window's content\n", what, c);
        todo_ros_if(!nitro_redirected())
        ok(c == color(w, COL_PAINT), "%s: %06lx, expected the WM_PAINT colour %06lx\n", what, c, color(w, COL_PAINT));
    }
    else
    {
        ok(c == color(w, COL_PAINT), "%s: %06lx, expected the WM_PAINT colour %06lx\n", what, c, color(w, COL_PAINT));
    }
}

/*
 * A window whose thread ends inside WM_ERASEBKGND while it is being printed. The print in progress
 * must not leave GDI objects behind in the process.
 */
static volatile LONG g_exitArmed;
static HWND g_hwndExit;
static HDC g_hdcExit;
static HBITMAP g_hbmExit;

static LRESULT CALLBACK ExitProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_ERASEBKGND && InterlockedExchange(&g_exitArmed, 0))
        ExitThread(2);
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* arg: an event to signal and a message loop (PrintWindow from the main thread), or NULL (WM_PRINT here) */
static DWORD WINAPI exit_thread_proc(LPVOID arg)
{
    MSG msg;
    HWND hwnd;

    hwnd = CreateWindowExW(WS_EX_TOPMOST, L"WmPrintExit", NULL, WS_OVERLAPPEDWINDOW | (arg ? WS_VISIBLE : 0),
                           300, 200, 160, 120, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!arg)
    {
        g_hdcExit = CreateCompatibleDC(NULL);
        g_hbmExit = CreateCompatibleBitmap(g_hdcExit, 160, 120);
        SelectObject(g_hdcExit, g_hbmExit);
        InterlockedExchange(&g_exitArmed, 1);
        SendMessageW(hwnd, WM_PRINT, (WPARAM)g_hdcExit, PRF_NONCLIENT | PRF_CLIENT | PRF_ERASEBKGND);
        return 1;
    }
    g_hwndExit = hwnd;
    SetEvent((HANDLE)arg);
    while (GetMessageW(&msg, NULL, 0, 0))
        DispatchMessageW(&msg);
    return 0;
}

/* One window thread that ends while printed; bPrintWindow: through PrintWindow from this thread, else WM_PRINT in its own */
static void exit_while_printing(BOOL bPrintWindow)
{
    HANDLE hEvent = NULL, hThread;
    DWORD tid, wait, code = 0;

    g_hwndExit = NULL;
    g_hdcExit = NULL;
    g_hbmExit = NULL;
    InterlockedExchange(&g_exitArmed, 0);
    if (bPrintWindow)
        hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, exit_thread_proc, hEvent, 0, &tid);
    if (bPrintWindow)
    {
        WaitForSingleObject(hEvent, 5000);
        /* let the window paint first */
        Sleep(300);
        if (g_hwndExit)
        {
            InterlockedExchange(&g_exitArmed, 1);
            clear_target();
            PrintWindow(g_hwndExit, g_hdc, 0);
        }
        CloseHandle(hEvent);
    }
    wait = WaitForSingleObject(hThread, 5000);
    ok(wait == WAIT_OBJECT_0, "%s: the window thread did not end\n", bPrintWindow ? "PrintWindow" : "WM_PRINT");
    if (wait != WAIT_OBJECT_0)
    {
        if (g_hwndExit)
            PostThreadMessageW(tid, WM_QUIT, 0, 0);
        WaitForSingleObject(hThread, 5000);
    }
    GetExitCodeThread(hThread, &code);
    ok(code == 2, "%s: the window thread did not end in WM_ERASEBKGND (%lu)\n",
       bPrintWindow ? "PrintWindow" : "WM_PRINT", code);
    CloseHandle(hThread);
    if (g_hdcExit)
        DeleteDC(g_hdcExit);
    if (g_hbmExit)
        DeleteObject(g_hbmExit);
}

static void test_thread_exit(void)
{
    WNDCLASSW wc = { 0 };
    DWORD before, after;
    int pass, i;
    static const int count = 10;

    wc.lpfnWndProc = ExitProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WmPrintExit";
    RegisterClassW(&wc);

    for (pass = 0; pass < 2; pass++)
    {
        /* the first round allocates what a process keeps anyway */
        exit_while_printing(pass == 0);
        before = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        for (i = 0; i < count; i++)
            exit_while_printing(pass == 0);
        after = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        ok(after < before + count / 2, "%s: GDI objects %lu -> %lu after %d thread exits\n",
           pass == 0 ? "PrintWindow" : "WM_PRINT", before, after, count);
    }
    UnregisterClassW(L"WmPrintExit", GetModuleHandleW(NULL));
}

/*
 * Child process for the saved-DC case: when its window is printed into a memory DC, it moves the bitmap
 * of that DC into a DC of its own, saves that DC's state (which keeps a reference to the bitmap), and
 * puts the bitmap back. The saved states live until the child ends; the printing process must not be
 * left with anything of them.
 */
static HDC g_hdcSaved[32];
static int g_nSaved;
static BOOL g_saveFailed;

static LRESULT CALLBACK SaveProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HDC hdc = (HDC)wParam, hdc2;
    HBITMAP hbm, hbmTmp, hbmOld2;

    if (msg == WM_DESTROY)
        PostQuitMessage(0);
    if (msg == WM_ERASEBKGND && GetObjectType(hdc) == OBJ_MEMDC)
    {
        hbmTmp = CreateBitmap(1, 1, 1, 1, NULL);
        hbm = SelectObject(hdc, hbmTmp);
        hdc2 = CreateCompatibleDC(hdc);
        hbmOld2 = hbm ? SelectObject(hdc2, hbm) : NULL;
        if (hbmOld2 && SaveDC(hdc2) && g_nSaved < ARRAYSIZE(g_hdcSaved))
        {
            SelectObject(hdc2, hbmOld2);
            g_hdcSaved[g_nSaved++] = hdc2;
        }
        else
        {
            g_saveFailed = TRUE;
            if (hbmOld2)
                SelectObject(hdc2, hbmOld2);
            DeleteDC(hdc2);
        }
        if (hbm)
            SelectObject(hdc, hbm);
        DeleteObject(hbmTmp);
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void savedc_child(void)
{
    WNDCLASSW wc = { 0 };
    MSG msg;
    int i;

    wc.lpfnWndProc = SaveProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WmPrintSave";
    RegisterClassW(&wc);
    CreateWindowExW(WS_EX_TOPMOST, L"WmPrintSave", NULL, WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                    300, 200, 160, 120, NULL, NULL, GetModuleHandleW(NULL), NULL);
    while (GetMessageW(&msg, NULL, 0, 0))
        DispatchMessageW(&msg);
    for (i = 0; i < g_nSaved; i++)
        DeleteDC(g_hdcSaved[i]);
    /* no test summary from the child */
    ExitProcess(0x100 | (g_saveFailed ? 0x200 : 0) | g_nSaved);
}

static void test_savedc_child(void)
{
    char **argv;
    char cmd[MAX_PATH + 32];
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    HWND hwnd = NULL;
    DWORD before, after, code = 0, wait;
    BOOL ret;
    int i;
    static const int count = 10;

    winetest_get_mainargs(&argv);
    sprintf(cmd, "\"%s\" PrintWindow savedc", argv[0]);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        skip("CreateProcess failed: %lu\n", GetLastError());
        return;
    }
    for (i = 0; i < 50 && !hwnd; i++)
    {
        Sleep(100);
        hwnd = FindWindowW(L"WmPrintSave", NULL);
    }
    ok(hwnd != NULL, "child window not found\n");
    if (hwnd)
    {
        /* let the window paint first */
        Sleep(300);
        before = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        for (i = 0; i < count; i++)
        {
            ret = PrintWindow(hwnd, g_hdc, 0);
            ok(ret == TRUE, "saved DC child: PrintWindow failed: %lu\n", GetLastError());
        }
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    }
    wait = WaitForSingleObject(pi.hProcess, 10000);
    ok(wait == WAIT_OBJECT_0, "saved DC child did not end\n");
    if (wait != WAIT_OBJECT_0)
        TerminateProcess(pi.hProcess, 1);
    GetExitCodeProcess(pi.hProcess, &code);
    ok((code & ~0xff) == 0x100, "saved DC child: exit code %#lx\n", code);
    if (hwnd && (code & 0xff) == 0)
    {
        /* Windows paints into its redirection surface, not into a memory DC */
        skip("saved DC child: the window was never printed into a memory DC\n");
    }
    else if (hwnd)
    {
        ok((code & 0xff) == count, "saved DC child: %lu saved states, expected %d\n", code & 0xff, count);
        after = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        ok(after < before + count / 2, "saved DC child: GDI objects %lu -> %lu after %d prints\n", before, after, count);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

START_TEST(PrintWindow)
{
    RECT rcWindow, rcClient;
    POINT co;
    BOOL ret;
    COLORREF c;
    HANDLE hEvent, hThread;
    DWORD tid;
    int off, i, ww, wh;
    static const UINT badflags[] = { 4, 8, 0x10, 0x80000000 };
    char **argv;

    if (winetest_get_mainargs(&argv) >= 3 && !strcmp(argv[2], "savedc"))
    {
        savedc_child();
        return;
    }

    register_class();
    create(W_P, L"WmPrintTest", WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, 100, 100, 240, 180, NULL);
    create(W_A, L"WmPrintTest", 0, WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 10, 60, 40, g_hwnd[W_P]);
    create(W_F, L"WmPrintTest", 0, WS_CHILD | WS_VISIBLE, 180, 90, 80, 60, g_hwnd[W_P]);
    create(W_O, L"WmPrintTest", WS_EX_TOPMOST, WS_POPUP | WS_BORDER, 160, 160, 50, 40, g_hwnd[W_P]);
    ShowWindow(g_hwnd[W_P], SW_SHOWNORMAL);
    ShowWindow(g_hwnd[W_O], SW_SHOWNOACTIVATE);
    UpdateWindow(g_hwnd[W_P]);
    pump();
    get_rects(W_P, &rcWindow, &rcClient);
    ww = rcWindow.right - rcWindow.left;
    wh = rcWindow.bottom - rcWindow.top;
    new_target(ww + 64, wh + 64);

    for (off = 0; off <= MARGIN; off += MARGIN)
    {
        /* the whole window, drawn at the DC's logical origin */
        ret = print_window(W_P, 0, off);
        ok(ret == TRUE, "PrintWindow failed: %lu\n", GetLastError());
        co.x = off + rcClient.left - rcWindow.left;
        co.y = off + rcClient.top - rcWindow.top;
        check_content(W_P, co.x + 100, co.y + 100, FALSE, "P client");
        c = pixel(co.x + 1, co.y + 60);
        ok(c == color(W_P, COL_ERASE), "P client edge %06lx\n", c);
        c = pixel(off + 1, off + wh - 2);
        ok(c != SENTINEL && c != RGB(0, 0, 0), "frame %06lx\n", c);
        check_content(W_A, co.x + 10 + 30, co.y + 10 + 20, FALSE, "A");
        c = pixel(co.x + 10, co.y + 10 + 20);
        ok(c != SENTINEL && c != color(W_P, COL_PAINT) && c != color(W_A, COL_PAINT), "A border %06lx\n", c);
        /* the child is clipped to the parent's client area; the owned window is not included */
        check_content(W_F, co.x + 180 + 10, co.y + 90 + 10, FALSE, "F");
        c = pixel(co.x + (rcClient.right - rcClient.left) + 1, co.y + 90 + 10);
        ok(c != color(W_F, COL_PAINT) && c != color(W_F, COL_PRINT) && c != SENTINEL, "F outside the client area %06lx\n", c);
        c = pixel(off + ww + 2, co.y + 90 + 10);
        ok(c == SENTINEL, "outside the window %06lx\n", c);
        c = pixel(off + 60 + 25, off + 60 + 20);
        ok(c != color(W_O, COL_PAINT) && c != color(W_O, COL_PRINT), "owned window drawn\n");

        /* the client area only */
        ret = print_window(W_P, PW_CLIENTONLY, off);
        ok(ret == TRUE, "PrintWindow failed: %lu\n", GetLastError());
        check_content(W_P, off + 100, off + 100, FALSE, "PW_CLIENTONLY P client");
        c = pixel(off + 1, off + 60);
        ok(c == color(W_P, COL_ERASE), "PW_CLIENTONLY edge %06lx\n", c);
        check_content(W_A, off + 10 + 30, off + 10 + 20, FALSE, "PW_CLIENTONLY A");
        c = pixel(off + (rcClient.right - rcClient.left) + 1, off + 60);
        ok(c == SENTINEL, "PW_CLIENTONLY outside %06lx\n", c);
    }

    /* a child window */
    ret = print_window(W_A, 0, 0);
    ok(ret == TRUE, "PrintWindow failed: %lu\n", GetLastError());
    check_content(W_A, 30, 20, FALSE, "A alone");

    /* flags */
    for (i = 0; i < ARRAYSIZE(badflags); i++)
    {
        SetLastError(0xdeadbeef);
        ret = print_window(W_P, badflags[i], 0);
        ok(ret == FALSE, "flags %#x: ret %d\n", badflags[i], ret);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "flags %#x: error %lu\n", badflags[i], GetLastError());
    }
    SetLastError(0xdeadbeef);
    ret = PrintWindow(NULL, g_hdc, 0);
    ok(ret == FALSE, "NULL window: ret %d\n", ret);
    ret = PrintWindow(g_hwnd[W_P], NULL, 0);
    ok(ret == TRUE, "NULL DC: ret %d\n", ret);
    ret = PrintWindow(GetDesktopWindow(), g_hdc, 0);
    ok(ret == FALSE, "desktop: ret %d\n", ret);

    /* partly off the screen */
    SetWindowPos(g_hwnd[W_P], NULL, -100, 100, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    pump();
    ret = print_window(W_P, 0, 0);
    ok(ret == TRUE, "PrintWindow failed: %lu\n", GetLastError());
    get_rects(W_P, &rcWindow, &rcClient);
    co.x = rcClient.left - rcWindow.left;
    co.y = rcClient.top - rcWindow.top;
    check_content(W_P, co.x + 30, co.y + 100, TRUE, "P off screen");
    check_content(W_P, co.x + 150, co.y + 100, FALSE, "P on screen");

    /* a window that paints only in WM_PAINT */
    g_paintonly[W_P] = TRUE;
    ret = print_window(W_P, 0, 0);
    ok(ret == TRUE, "PrintWindow failed: %lu\n", GetLastError());
    check_content(W_P, co.x + 30, co.y + 100, TRUE, "paint-only P off screen");
    check_content(W_P, co.x + 150, co.y + 100, FALSE, "paint-only P on screen");
    g_paintonly[W_P] = FALSE;

    /* a hidden window gives a black image */
    ShowWindow(g_hwnd[W_O], SW_HIDE);
    ShowWindow(g_hwnd[W_P], SW_HIDE);
    pump();
    ret = print_window(W_P, 0, 0);
    ok(ret == TRUE, "hidden: ret %d\n", ret);
    c = pixel(co.x + 100, co.y + 100);
    ok(c == RGB(0, 0, 0), "hidden: %06lx\n", c);
    destroy_all();

    /* a window of another thread */
    hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, thread_proc, hEvent, 0, &tid);
    WaitForSingleObject(hEvent, 5000);
    Sleep(300);
    ok(g_hwndThread != NULL, "thread window not created\n");
    if (g_hwndThread)
    {
        get_rects(W_R, &rcWindow, &rcClient);
        ret = print_window(W_R, PW_CLIENTONLY, 0);
        ok(ret == TRUE, "other thread: PrintWindow failed: %lu\n", GetLastError());
        check_content(W_R, 40, 40, FALSE, "other thread");
        PostMessageW(g_hwndThread, WM_CLOSE, 0, 0);
    }
    PostThreadMessageW(tid, WM_QUIT, 0, 0);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    CloseHandle(hEvent);
    g_hwnd[W_R] = NULL;

    test_thread_exit();
    test_savedc_child();

    DeleteDC(g_hdc);
    DeleteObject(g_hbm);
    g_hdc = NULL;
}
