/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LineTo, Polyline, PolyBezier and StrokePath with long lines and end points near the ends of the
 *              coordinate range: the line rasteriser stepped along the whole line, also where it left the surface
 *              (a line to the end of the range took tens of seconds), a solid line that reached the coordinate
 *              MAXLONG met "% cStyles" with cStyles == 0, and a user style whose segments add up to 2^32 was a
 *              division by zero. Every call must return at once, and the pixels on the surface must be those of the
 *              whole line (position, error term and dash phase as if the line had been stepped from its start).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define DIMS 256
#define SLOW_MS 2000

static DWORD *g_bits;
static HDC g_dc;

static void Clear(void)
{
    int i;

    for (i = 0; i < DIMS * DIMS; i++)
        g_bits[i] = 0xFFFFFF;
}

static int CountInk(void)
{
    int i, n = 0;

    GdiFlush();
    for (i = 0; i < DIMS * DIMS; i++)
        if ((g_bits[i] & 0xFFFFFF) != 0xFFFFFF)
            n++;
    return n;
}

typedef struct { LONG x1, y1, x2, y2; } SEG;

typedef struct
{
    const char *name;
    int cStyles;
    DWORD aStyles[8];
} PENDEF;

static const PENDEF g_pens[] =
{
    { "solid", 0, { 0 } },
    { "us{3,2}", 2, { 3, 2 } },
    { "us{4,1,2,1}", 4, { 4, 1, 2, 1 } },
};

static HPEN MakePen(const PENDEF *pd)
{
    LOGBRUSH lb;

    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    if (pd->cStyles == 0)
        return CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    return ExtCreatePen(PS_COSMETIC | PS_USERSTYLE, 1, &lb, pd->cStyles, pd->aStyles);
}

/* The pixels of a line on the surface, from the definition of the stepping: along the axis of the larger delta
   (x when the deltas are equal) the coordinate is a + s * i for i = 0 .. D - 1, along the other one
   a + s * ((D / 2 + i * m) / D). The line is drawn in the segments of the style with an even index, the pattern
   counted forwards or, when that axis runs down, backwards from its start. */
static void RefLine(LONG x1, LONG y1, LONG x2, LONG y2, const PENDEF *pd, BYTE *ex)
{
    LONGLONG dx = (LONGLONG)x2 - x1, dy = (LONGLONG)y2 - y1;
    LONGLONG adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
    LONGLONG sx = dx < 0 ? -1 : 1, sy = dy < 0 ? -1 : 1;
    BOOL bX = adx >= ady;
    LONGLONG D = bX ? adx : ady, m = bX ? ady : adx, i, a, b, sa, sb, v, size = 0;
    int k;

    for (k = 0; k < pd->cStyles; k++)
        size += pd->aStyles[k];
    if (D == 0)
        return;
    a = bX ? x1 : y1; sa = bX ? sx : sy;        /* the axis that counts */
    b = bX ? y1 : x1; sb = bX ? sy : sx;        /* the other one */

    for (v = 0; v < DIMS; v++)
    {
        LONGLONG c;

        i = (v - a) * sa;
        if (i < 0 || i >= D)
            continue;
        c = b + sb * ((D / 2 + i * m) / D);
        if (c < 0 || c >= DIMS)
            continue;
        if (pd->cStyles)
        {
            LONGLONG q = sa > 0 ? i : -i, cum = 0;

            q %= size;
            if (q < 0) q += size;
            for (k = 0; k < pd->cStyles; k++)
            {
                cum += pd->aStyles[k];
                if (q < cum)
                    break;
            }
            if (k & 1)
                continue;
        }
        if (bX)
            ex[c * DIMS + v] = 1;
        else
            ex[v * DIMS + c] = 1;
    }
}

static int Compare(const BYTE *ex)
{
    int i, bad = 0;

    GdiFlush();
    for (i = 0; i < DIMS * DIMS; i++)
    {
        BOOL drawn = (g_bits[i] & 0xFFFFFF) != 0xFFFFFF;

        if (drawn != (ex[i] != 0))
            bad++;
    }
    return bad;
}

/* Lines through the view with an end far out: the pixels on the surface are those of the whole line, for all
   directions and slopes, both ways round, solid and dashed */
static void test_ExactPixels(void)
{
    static const LONG d[][2] =
    {
        { 100000000, 37 }, { 99999999, 99999999 }, { 70000, 69999 }, { 65537, 1 }, { 123457, 654321 },
        { 1, 100000000 }, { 50000000, 0 }, { 0, 50000000 }, { 99999999, 1 }, { 3000000, 2999999 },
    };
    static BYTE ex[DIMS * DIMS];
    int ip, id, sgnx, sgny, rev;

    for (ip = 0; ip < 3; ip++)
    {
        HPEN pen = MakePen(&g_pens[ip]), old = SelectObject(g_dc, pen);
        int bad = 0, n = 0, drawn = 0;

        for (id = 0; id < (int)_countof(d); id++)
        {
            for (sgnx = -1; sgnx <= 1; sgnx += 2)
            {
                for (sgny = -1; sgny <= 1; sgny += 2)
                {
                    for (rev = 0; rev < 2; rev++)
                    {
                        LONG ax = 100 + id * 7, ay = 90 + id * 5;
                        LONG bx = ax + sgnx * d[id][0], by = ay + sgny * d[id][1];
                        DWORD t = GetTickCount();
                        int nb;

                        Clear();
                        ZeroMemory(ex, sizeof(ex));
                        if (!rev)
                        {
                            MoveToEx(g_dc, ax, ay, NULL);
                            LineTo(g_dc, bx, by);
                            RefLine(ax, ay, bx, by, &g_pens[ip], ex);
                        }
                        else
                        {
                            MoveToEx(g_dc, bx, by, NULL);
                            LineTo(g_dc, ax, ay);
                            RefLine(bx, by, ax, ay, &g_pens[ip], ex);
                        }
                        ok(GetTickCount() - t < SLOW_MS, "%s: line took %lu ms\n", g_pens[ip].name, GetTickCount() - t);
                        nb = Compare(ex);
                        bad += nb;
                        drawn += CountInk();
                        n++;
                        if (nb)
                            ok(0, "%s: (%ld,%ld)-(%ld,%ld): %d pixels differ from the line\n", g_pens[ip].name,
                               rev ? bx : ax, rev ? by : ay, rev ? ax : bx, rev ? ay : by, nb);
                    }
                }
            }
        }
        ok(bad == 0, "%s: %d pixels differ in %d lines\n", g_pens[ip].name, bad, n);
        ok(drawn > 0, "%s: nothing drawn\n", g_pens[ip].name);
        SelectObject(g_dc, old);
        DeleteObject(pen);
    }
}

/* Lines of 2^30 steps and more, which the 32 bit error term of the old stepping got wrong (a line to the corner of the
   range was drawn as a horizontal one). These lines are taken as they are, without wrapping the end points to 28 bits
   the way Windows does for some calls: when that is done the end points here change. */
static void test_ExactPixelsFar(void)
{
    static const SEG s[] =
    {
        { 120, 100, 2147483120, 100 + 1073741000 },
        { 120, 100, -2147482880, 100 - 1073741000 },
        { 120, 100, 120 + 1500000000, 100 + 2000000000 },
        { 120, 100, 120 - 1500000000, 100 - 1999999000 },
        { 50, -2147483647 - 1, 60, 2147483647 },
        { 60, 2147483647, 50, -2147483647 - 1 },
        { -2147483647 - 1, 130, 2147483647, 140 },
        { 20, 20, 2147483647, 2147483647 },
        { 2147483647, 2147483647, 20, 20 },
    };
    static BYTE ex[DIMS * DIMS];
    int ip, is;

    for (ip = 0; ip < 3; ip++)
    {
        HPEN pen = MakePen(&g_pens[ip]), old = SelectObject(g_dc, pen);

        for (is = 0; is < (int)_countof(s); is++)
        {
            DWORD t = GetTickCount();
            int nb;

            Clear();
            ZeroMemory(ex, sizeof(ex));
            MoveToEx(g_dc, s[is].x1, s[is].y1, NULL);
            LineTo(g_dc, s[is].x2, s[is].y2);
            RefLine(s[is].x1, s[is].y1, s[is].x2, s[is].y2, &g_pens[ip], ex);
            ok(GetTickCount() - t < SLOW_MS, "%s: line %d took %lu ms\n", g_pens[ip].name, is, GetTickCount() - t);
            nb = Compare(ex);
            ok(nb == 0, "%s: line %d: %d pixels differ from the line\n", g_pens[ip].name, is, nb);
        }
        SelectObject(g_dc, old);
        DeleteObject(pen);
    }
}

/* An ordinary line afterwards (and a short one with a style) still gives the exact pixels */
static void test_OrdinaryLines(void)
{
    static BYTE ex[DIMS * DIMS];
    static const LONG l[][4] =
    {
        { 20, 20, 230, 200 }, { 230, 200, 20, 20 }, { 20, 200, 230, 20 }, { 230, 20, 20, 200 },
        { 10, 100, 240, 100 }, { 120, 5, 120, 250 }, { 5, 5, 250, 250 }, { 250, 5, 5, 250 },
        { 60, 10, 200, 14 }, { 10, 60, 14, 200 },
    };
    int ip, i;

    for (ip = 0; ip < 3; ip++)
    {
        HPEN pen = MakePen(&g_pens[ip]), old = SelectObject(g_dc, pen);

        for (i = 0; i < (int)_countof(l); i++)
        {
            int nb;

            Clear();
            ZeroMemory(ex, sizeof(ex));
            MoveToEx(g_dc, l[i][0], l[i][1], NULL);
            LineTo(g_dc, l[i][2], l[i][3]);
            RefLine(l[i][0], l[i][1], l[i][2], l[i][3], &g_pens[ip], ex);
            nb = Compare(ex);
            ok(nb == 0, "%s: (%ld,%ld)-(%ld,%ld): %d pixels differ\n", g_pens[ip].name, l[i][0], l[i][1], l[i][2],
               l[i][3], nb);
        }
        SelectObject(g_dc, old);
        DeleteObject(pen);
    }
}

static const SEG g_ext[] =
{
    { 20, 20, 2147483647, 2147483647 },
    { 20, 20, 2147483647, 20 },
    { 20, 20, 20, 2147483647 },
    { -2147483647 - 1, -2147483647 - 1, 2147483647, 2147483647 },
    { -2147483647 - 1, 100, 2147483647, 150 },
    { -1000000000, -500000000, 1000000000, 500000000 },
    { 100, 2147483647, 100, -2147483647 - 1 },
    { -2147483647 - 1, -2147483647 - 1, 5, 5 },
    { 50, -2147483647, 60, 2147483647 },
    { 5, 2147483647, 5, 10 },                       /* solid line that reaches y == MAXLONG */
    { 1073741824, 1073741824, 2147483647, 2147483647 }, /* 2^30 steps to x == y == MAXLONG: % cStyles with 0 */
    { 5, 1073741824, 10, 2147483647 },              /* the same along y */
    { 2147483647, 2147483647, 1073741824, 1073741824 },
    { 2147483647, 2147483647, 100, 100 },
    { 2147483647, 20, 20, 40 },
    { 0, 0, 134217727, 100000000 },
    { -134217728, 20, 134217727, 30 },
};

/* Every kind of call with extreme end points returns in time and leaves the DC usable */
static void test_NoStall(void)
{
    static BYTE ex[DIMS * DIMS];
    int ip, is, op;
    char what[96];

    for (ip = 0; ip < 3; ip++)
    {
        HPEN pen = MakePen(&g_pens[ip]), old = SelectObject(g_dc, pen);

        for (is = 0; is < (int)_countof(g_ext); is++)
        {
            for (op = 0; op < 4; op++)
            {
                const SEG *s = &g_ext[is];
                POINT p[4];
                DWORD t;
                int nb;

                Clear();
                t = GetTickCount();
                switch (op)
                {
                case 0:
                    MoveToEx(g_dc, s->x1, s->y1, NULL);
                    LineTo(g_dc, s->x2, s->y2);
                    break;
                case 1:
                    p[0].x = s->x1; p[0].y = s->y1; p[1].x = s->x2; p[1].y = s->y2;
                    Polyline(g_dc, p, 2);
                    break;
                case 2:
                    p[0].x = s->x1; p[0].y = s->y1; p[1] = p[0];
                    p[2].x = s->x2; p[2].y = s->y2; p[3] = p[2];
                    PolyBezier(g_dc, p, 4);
                    break;
                default:
                    BeginPath(g_dc);
                    MoveToEx(g_dc, s->x1, s->y1, NULL);
                    LineTo(g_dc, s->x2, s->y2);
                    EndPath(g_dc);
                    StrokePath(g_dc);
                    break;
                }
                StringCchPrintfA(what, _countof(what), "%s op %d seg %d", g_pens[ip].name, op, is);
                ok(GetTickCount() - t < SLOW_MS, "%s: took %lu ms\n", what, GetTickCount() - t);

                /* the DC is usable: an ordinary line has its exact pixels */
                Clear();
                ZeroMemory(ex, sizeof(ex));
                MoveToEx(g_dc, 20, 30, NULL);
                LineTo(g_dc, 200, 90);
                RefLine(20, 30, 200, 90, &g_pens[ip], ex);
                nb = Compare(ex);
                ok(nb == 0, "%s: ordinary line afterwards: %d pixels differ\n", what, nb);
            }
        }
        SelectObject(g_dc, old);
        DeleteObject(pen);
    }
}

/* The radial lines of a Pie and the line of a Chord with a huge box are lines of this kind: with a styled pen they
   have to return at once as well, and the pattern is that of the whole line (they are no longer cut before the
   rasteriser) */
static void test_PieChordStyled(void)
{
    static const int box[][4] =
    {
        { 2147483646, 129, -2147483615, 390 },
        { -2147483647 - 1, -2147483647 - 1, 2147483647, 2147483647 },
        { -134217728, -134217728, 134217727, 134217727 },
        { -1000000, 100, 1000000, 150 },
        { 20, 128 - 50000, 20 + 100000, 128 + 50000 },
    };
    static const int rad[][4] = { { 200, 184, 242, 187 }, { 0, 0, 255, 255 }, { 2147483647, -2147483647 - 1, -2147483647 - 1, 2147483647 } };
    int ip, ib, ir, dir;

    SelectObject(g_dc, GetStockObject(NULL_BRUSH));
    for (ip = 1; ip < 3; ip++)
    {
        HPEN pen = MakePen(&g_pens[ip]), old = SelectObject(g_dc, pen);

        for (ib = 0; ib < (int)_countof(box); ib++)
        {
            for (ir = 0; ir < (int)_countof(rad); ir++)
            {
                for (dir = 0; dir < 2; dir++)
                {
                    DWORD t = GetTickCount();

                    SetArcDirection(g_dc, dir ? AD_CLOCKWISE : AD_COUNTERCLOCKWISE);
                    Clear();
                    Chord(g_dc, box[ib][0], box[ib][1], box[ib][2], box[ib][3], rad[ir][0], rad[ir][1], rad[ir][2], rad[ir][3]);
                    Pie(g_dc, box[ib][0], box[ib][1], box[ib][2], box[ib][3], rad[ir][0], rad[ir][1], rad[ir][2], rad[ir][3]);
                    ok(GetTickCount() - t < SLOW_MS, "%s box %d radials %d: Chord and Pie took %lu ms\n", g_pens[ip].name, ib, ir,
                       GetTickCount() - t);
                }
            }
        }
        SelectObject(g_dc, old);
        DeleteObject(pen);
    }
    SetArcDirection(g_dc, AD_COUNTERCLOCKWISE);
    SelectObject(g_dc, GetStockObject(WHITE_BRUSH));
}

/* The segments of this style add up to 2^32: no division by zero, the line is drawn */
static void test_StyleSumWraps(void)
{
    LOGBRUSH lb;
    DWORD st[3] = { 0x7FFFFFFF, 0x7FFFFFFF, 2 };
    HPEN pen, old;
    DWORD t;

    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    pen = ExtCreatePen(PS_COSMETIC | PS_USERSTYLE, 1, &lb, 3, st);
    if (!pen)
    {
        skip("no pen\n");
        return;
    }
    old = SelectObject(g_dc, pen);
    Clear();
    t = GetTickCount();
    MoveToEx(g_dc, 10, 10, NULL);
    LineTo(g_dc, 200, 120);
    MoveToEx(g_dc, 200, 10, NULL);
    LineTo(g_dc, 10, 120);
    ok(GetTickCount() - t < SLOW_MS, "took %lu ms\n", GetTickCount() - t);
    ok(CountInk() > 0, "nothing drawn\n");
    SelectObject(g_dc, old);
    DeleteObject(pen);
}

START_TEST(LineHugeCoords)
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
    SetROP2(g_dc, R2_COPYPEN);

    test_OrdinaryLines();
    test_ExactPixels();
    test_ExactPixelsFar();
    test_PieChordStyled();
    test_StyleSumWraps();
    test_NoStall();

    SelectObject(g_dc, bmpOld);
    DeleteObject(bmp);
    DeleteDC(g_dc);
}
