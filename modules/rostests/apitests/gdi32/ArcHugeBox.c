/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Arc, Pie, Chord, Ellipse and RoundRect with boxes near the ends of the coordinate range or very large:
 *              the ring rasterisers found the intersection of a radial line with a scan line in 32 bits (the product
 *              overflowed and INT_MIN / -1 was a kernel divide error) and stepped along the outline of the whole
 *              box (a box of 2^27 pixels took minutes). Every call must return at once, draw only what lies in the
 *              view, and leave the DC usable.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <math.h>

#define DIMS 256
#define SLOW_MS 2000

static DWORD *g_bits;
static HDC g_dc;
static int g_slow;
static char g_firstSlow[128];
static int g_calls;

static void Clear(void)
{
    int i;

    for (i = 0; i < DIMS * DIMS; i++)
        g_bits[i] = 0xFFFFFF;
}

static int CountInk(int *pminx, int *pmaxx)
{
    int x, y, n = 0;

    GdiFlush();
    if (pminx) *pminx = DIMS;
    if (pmaxx) *pmaxx = -1;
    for (y = 0; y < DIMS; y++)
    {
        for (x = 0; x < DIMS; x++)
        {
            if ((g_bits[y * DIMS + x] & 0xFFFFFF) != 0xFFFFFF)
            {
                n++;
                if (pminx && x < *pminx) *pminx = x;
                if (pmaxx && x > *pmaxx) *pmaxx = x;
            }
        }
    }
    return n;
}

static void ResetDC_(void)
{
    SelectClipRgn(g_dc, NULL);
    ModifyWorldTransform(g_dc, NULL, MWT_IDENTITY);
    SetGraphicsMode(g_dc, GM_COMPATIBLE);
    SetMapMode(g_dc, MM_TEXT);
    SetWindowOrgEx(g_dc, 0, 0, NULL);
    SetViewportOrgEx(g_dc, 0, 0, NULL);
    SetWindowExtEx(g_dc, 1, 1, NULL);
    SetViewportExtEx(g_dc, 1, 1, NULL);
    SetArcDirection(g_dc, AD_COUNTERCLOCKWISE);
    SetROP2(g_dc, R2_COPYPEN);
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    SelectObject(g_dc, GetStockObject(NULL_BRUSH));
}

static void Note(DWORD t0, const char *what)
{
    DWORD dt = GetTickCount() - t0;

    g_calls++;
    if (dt >= SLOW_MS)
    {
        if (!g_slow)
            StringCchPrintfA(g_firstSlow, sizeof(g_firstSlow), "%s (%lu ms)", what, dt);
        g_slow++;
    }
}

typedef struct { int l, t, r, b; } BOX;

static const BOX g_boxes[] =
{
    { 2147483646, 129, -2147483615, 390 },          /* the Chord of the divide error */
    { -2147483647 - 1, -2147483647 - 1, 2147483647, 2147483647 },
    { -134217728, -134217728, 134217727, 134217727 },
    { 0, 0, 2147483647, 100 },
    { -72590, 134217727, 97, -1 },                  /* a cosmetic Ellipse that stalled for minutes */
    { 0, 0, 134217727, 134217727 },
    { -1000000, 100, 1000000, 150 },
    { 100, -1000000, 150, 1000000 },
    { 20, 128 - 50000, 20 + 100000, 128 + 50000 },
    { -3000, -3000, 3000, 3000 },
    { 4, 4, 5000, 4000 },
};

static const int g_rad[][4] =
{
    { 200, 184, 242, 187 },
    { 0, 0, 255, 255 },
    { 1, 1, 1, 1 },
    { 2147483647, -2147483647 - 1, -2147483647 - 1, 2147483647 },
};

/* Every shape, every kind of pen and brush, both arc directions, a few mapping modes and world transforms: only that the
   calls return in time and the DC stays usable (the return value is not checked: it is TRUE for what is drawn, and
   the shapes that are entirely out of range draw nothing) */
static void test_NoStall(void)
{
    HPEN hpenNull = CreatePen(PS_NULL, 0, 0);
    HPEN hpenInside = CreatePen(PS_INSIDEFRAME, 1, RGB(0, 0, 0));
    HPEN hpenOne = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    HPEN pens[4];
    HBRUSH hbrSolid = CreateSolidBrush(RGB(255, 0, 0));
    HBRUSH brs[2];
    int ib, ip, ir, ibr, dir, mode, n, minx, maxx;
    char what[128];

    pens[0] = GetStockObject(BLACK_PEN);
    pens[1] = hpenNull;
    pens[2] = hpenInside;
    pens[3] = hpenOne;
    brs[0] = GetStockObject(NULL_BRUSH);
    brs[1] = hbrSolid;

    for (mode = 0; mode < 3; mode++)
    {
        for (ib = 0; ib < (int)(sizeof(g_boxes) / sizeof(g_boxes[0])); ib++)
        {
            const BOX *b = &g_boxes[ib];

            for (ip = 0; ip < 4; ip++)
            {
                for (ibr = 0; ibr < 2; ibr++)
                {
                    DWORD t0;

                    ResetDC_();
                    Clear();
                    SelectObject(g_dc, pens[ip]);
                    SelectObject(g_dc, brs[ibr]);
                    if (mode == 1)
                    {
                        XFORM xf = { 1000000.0f, 0.0f, 0.0f, -1000000.0f, 100.0f, 100.0f };

                        SetGraphicsMode(g_dc, GM_ADVANCED);
                        SetWorldTransform(g_dc, &xf);
                    }
                    else if (mode == 2)
                    {
                        XFORM xf = { 0.001f, 0.0f, 0.0f, 0.001f, 0.0f, 0.0f };

                        SetGraphicsMode(g_dc, GM_ADVANCED);
                        SetWorldTransform(g_dc, &xf);
                    }

                    StringCchPrintfA(what, sizeof(what), "Ellipse box %d pen %d brush %d mode %d", ib, ip, ibr, mode);
                    t0 = GetTickCount();
                    Ellipse(g_dc, b->l, b->t, b->r, b->b);
                    Note(t0, what);

                    StringCchPrintfA(what, sizeof(what), "RoundRect box %d pen %d brush %d mode %d", ib, ip, ibr, mode);
                    t0 = GetTickCount();
                    RoundRect(g_dc, b->l, b->t, b->r, b->b, 20, 14);
                    RoundRect(g_dc, b->l, b->t, b->r, b->b, 2147483647, 2147483647);
                    RoundRect(g_dc, b->l, b->t, b->r, b->b, 100000, 7);
                    Note(t0, what);

                    for (dir = 0; dir < 2; dir++)
                    {
                        SetArcDirection(g_dc, dir ? AD_CLOCKWISE : AD_COUNTERCLOCKWISE);
                        for (ir = 0; ir < 4; ir++)
                        {
                            const int *p = g_rad[ir];

                            StringCchPrintfA(what, sizeof(what), "Arc/Pie/Chord box %d pen %d brush %d mode %d dir %d rad %d",
                                             ib, ip, ibr, mode, dir, ir);
                            t0 = GetTickCount();
                            Arc(g_dc, b->l, b->t, b->r, b->b, p[0], p[1], p[2], p[3]);
                            Pie(g_dc, b->l, b->t, b->r, b->b, p[0], p[1], p[2], p[3]);
                            Chord(g_dc, b->l, b->t, b->r, b->b, p[0], p[1], p[2], p[3]);
                            Note(t0, what);
                        }
                    }
                }
            }
        }
    }

    ok(g_slow == 0, "%d of %d calls took %d ms or more, first: %s\n", g_slow, g_calls, SLOW_MS, g_firstSlow);

    /* the DC still draws an ordinary ellipse */
    ResetDC_();
    Clear();
    Ellipse(g_dc, 20, 20, 120, 100);
    n = CountInk(&minx, &maxx);
    ok(n >= 200 && n <= 400, "ordinary Ellipse painted %d pixels\n", n);
    ok(minx == 20 && maxx == 119, "ordinary Ellipse spans %d..%d\n", minx, maxx);

    ResetDC_();
    DeleteObject(hpenNull);
    DeleteObject(hpenInside);
    DeleteObject(hpenOne);
    DeleteObject(hbrSolid);
}

/* The ticket's Chord alone, the stock pen and no other state */
static void test_TicketChord(void)
{
    DWORD t0;
    BOOL ret;
    int n;

    ResetDC_();
    Clear();
    t0 = GetTickCount();
    ret = Chord(g_dc, 2147483646, 129, -2147483615, 390, 200, 184, 242, 187);
    ok(GetTickCount() - t0 < SLOW_MS, "Chord took %lu ms\n", GetTickCount() - t0);
    ok(ret == TRUE || ret == FALSE, "Chord returned %d\n", ret);
    n = CountInk(NULL, NULL);
    ok(n >= 0, "ink %d\n", n);

    SelectObject(g_dc, GetStockObject(BLACK_BRUSH));
    t0 = GetTickCount();
    Chord(g_dc, 2147483646, 129, -2147483615, 390, 200, 184, 242, 187);
    Pie(g_dc, 2147483646, 129, -2147483615, 390, 200, 184, 242, 187);
    ok(GetTickCount() - t0 < SLOW_MS, "Chord and Pie with a brush took %lu ms\n", GetTickCount() - t0);
    ResetDC_();
}

/* A circle of 50000 pixels radius whose left edge crosses the view at x = 20: the view shows a vertical edge. The
   outline is one pixel per row, the fill is everything to the right of the edge, an arc of the left side shows the same
   edge, and an arc of the right side shows nothing */
static void test_ViewOfHugeCircle(void)
{
    HBRUSH hbr = CreateSolidBrush(RGB(0, 0, 0));
    const int L = 20, T = 128 - 50000, R = 20 + 100000, B = 128 + 50000;
    /* rays from the centre (50020, 128) to the upper left and the lower left */
    const int sx = 50020 - 1000, sy = 128 - 100, ex = 50020 - 1000, ey = 128 + 100;
    int n, minx, maxx;
    const int fill = (DIMS - 20) * DIMS;

    /* outline */
    ResetDC_();
    Clear();
    Ellipse(g_dc, L, T, R, B);
    n = CountInk(&minx, &maxx);
    ok(n >= DIMS && n <= DIMS + 40, "Ellipse outline: %d pixels\n", n);
    ok(minx >= 19 && maxx <= 22, "Ellipse outline spans columns %d..%d\n", minx, maxx);

    /* fill */
    ResetDC_();
    SelectObject(g_dc, GetStockObject(NULL_PEN));
    SelectObject(g_dc, hbr);
    Clear();
    Ellipse(g_dc, L, T, R, B);
    n = CountInk(&minx, &maxx);
    ok(n >= fill - 300 && n <= fill + 300, "Ellipse fill: %d pixels, expected about %d\n", n, fill);
    ok(minx >= 19 && minx <= 21 && maxx == DIMS - 1, "Ellipse fill spans columns %d..%d\n", minx, maxx);

    /* the arc of the left side */
    ResetDC_();
    Clear();
    Arc(g_dc, L, T, R, B, sx, sy, ex, ey);
    n = CountInk(&minx, &maxx);
    ok(n >= DIMS && n <= DIMS + 40, "Arc of the left side: %d pixels\n", n);
    ok(minx >= 19 && maxx <= 22, "Arc of the left side spans columns %d..%d\n", minx, maxx);

    /* the other way round: the right side, out of view */
    SetArcDirection(g_dc, AD_CLOCKWISE);
    Clear();
    Arc(g_dc, L, T, R, B, sx, sy, ex, ey);
    n = CountInk(NULL, NULL);
    ok(n == 0, "Arc of the right side: %d pixels in view\n", n);
    ResetDC_();

    /* the pie of the left side fills up to the edge, with the null pen */
    SelectObject(g_dc, GetStockObject(NULL_PEN));
    SelectObject(g_dc, hbr);
    Clear();
    Pie(g_dc, L, T, R, B, sx, sy, ex, ey);
    n = CountInk(&minx, &maxx);
    ok(n >= fill - 300 && n <= fill + 300, "Pie of the left side: %d pixels, expected about %d\n", n, fill);
    /* the chord of such a thin cap (the radial points are on the box, so the chord is the left edge itself) paints
       nothing or the cap, never more than the disc */
    Clear();
    Chord(g_dc, L, T, R, B, sx, sy, ex, ey);
    n = CountInk(&minx, &maxx);
    ok(n <= fill + 300, "Chord of the left side: %d pixels, at most %d expected\n", n, fill);
    SetArcDirection(g_dc, AD_CLOCKWISE);
    Clear();
    Pie(g_dc, L, T, R, B, sx, sy, ex, ey);
    n = CountInk(NULL, NULL);
    ok(n == 0, "Pie of the right side: %d pixels in view\n", n);
    ResetDC_();
    DeleteObject(hbr);
}

/* An ellipse of 3000 pixels: the 32 bit stepping of the old routines overflowed above about 1800 pixels and drew
   a distorted shape; the fill must follow the equation of the ellipse */
static void test_BigEllipseShape(void)
{
    HBRUSH hbr = CreateSolidBrush(RGB(0, 0, 0));
    int y, x, n = 0, expect = 0;

    ResetDC_();
    SelectObject(g_dc, GetStockObject(NULL_PEN));
    SelectObject(g_dc, hbr);
    Clear();
    Ellipse(g_dc, 20, 128 - 1500, 20 + 3000, 128 + 1500);
    GdiFlush();
    for (y = 0; y < DIMS; y++)
    {
        double dy = y + 0.5 - 128;
        double xe = 1520.0 - sqrt(1500.0 * 1500.0 - dy * dy);
        int e = DIMS - (int)ceil(xe - 0.5);

        if (e < 0) e = 0;
        if (e > DIMS) e = DIMS;
        expect += e;
        for (x = 0; x < DIMS; x++)
            if ((g_bits[y * DIMS + x] & 0xFFFFFF) == 0)
                n++;
    }
    ok(abs(n - expect) <= DIMS, "Ellipse of 3000 pixels: %d pixels filled, expected %d\n", n, expect);
    ResetDC_();
    DeleteObject(hbr);
}

START_TEST(ArcHugeBox)
{
    BITMAPINFO bi;
    HBITMAP bmp, bmpOld;

    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = DIMS;
    bi.bmiHeader.biHeight = -DIMS;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    g_dc = CreateCompatibleDC(NULL);
    bmp = CreateDIBSection(g_dc, &bi, DIB_RGB_COLORS, (void **)&g_bits, NULL, 0);
    if (!g_dc || !bmp || !g_bits)
    {
        skip("no DIB\n");
        return;
    }
    bmpOld = SelectObject(g_dc, bmp);

    test_TicketChord();
    test_ViewOfHugeCircle();
    test_BigEllipseShape();
    test_NoStall();

    SelectObject(g_dc, bmpOld);
    DeleteObject(bmp);
    DeleteDC(g_dc);
}
