/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A filled polygon is the same with and without a clip: with a rectangle or a complex clip region (holes,
 *              several rectangles, a one pixel and a one row piece) the pixels are those of the unclipped polygon that
 *              lie inside the region, whatever the polygon: starting above, below or beside the surface, partly or
 *              fully outside, one pixel, one row, with horizontal edges, convex, concave or self-intersecting, both
 *              fill modes. The fill steps its edges to the first row inside the clip bounds instead of through every
 *              row of the polygon, so a polygon that reaches far past the surface must still draw what is inside.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define DIMS_X 160
#define DIMS_Y 120
#define BACKGROUND 0x00808080
#define POLYGONS 2500

static ULONG g_seed = 0x13579BDF;

static ULONG Rand(void)
{
    g_seed = g_seed * 1103515245 + 12345;
    return g_seed >> 4;
}

static LONG Range(LONG lo, LONG hi)
{
    return lo + (LONG)(Rand() % (ULONG)(hi - lo + 1));
}

static HDC g_dc;
static DWORD *g_bits;

static void Clear(void)
{
    int i;

    for (i = 0; i < DIMS_X * DIMS_Y; i++)
        g_bits[i] = BACKGROUND;
}

/* The pixels a region covers: a mask made by painting the region white on a black DIB */
static void MakeMask(HRGN rgn, BYTE *mask)
{
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    int i;

    SelectClipRgn(g_dc, NULL);
    Clear();
    FillRgn(g_dc, rgn, white);
    GdiFlush();
    for (i = 0; i < DIMS_X * DIMS_Y; i++)
        mask[i] = (g_bits[i] & 0xFFFFFF) == 0xFFFFFF;
    DeleteObject(white);
}

/* Polygon number i: 3 to 10 points around a centre that is inside, beside, above, below or far from the surface */
static int MakePolygon(POINT *pt, int *pCount)
{
    static const LONG sizes[] = { 1, 2, 5, 9, 20, 60, 200, 1000 };
    static const LONG dists[] = { 0, 1, 3, 30, 300, 5000, 65536 };
    LONG size = sizes[Rand() % _countof(sizes)], dist = dists[Rand() % _countof(dists)];

    /* a polygon that reaches a million rows past the surface: every row of it is a call on a fill that does not skip them */
    if (Rand() % 100 == 0)
        dist = 1 << 20;
    LONG cx, cy, overlap = (Rand() & 1) ? Range(0, 2 * size) : 0;
    int n = 3 + Rand() % 8, kind = Rand() % 6, k;

    switch (Rand() % 11)
    {
        case 0: case 1: case 2: cx = Range(0, DIMS_X - 1); cy = Range(0, DIMS_Y - 1); break;
        case 3: cx = Range(0, DIMS_X - 1); cy = -dist - size + overlap; break;
        case 4: cx = Range(0, DIMS_X - 1); cy = DIMS_Y + dist + size - overlap; break;
        case 5: cx = -dist - size + overlap; cy = Range(0, DIMS_Y - 1); break;
        case 6: cx = DIMS_X + dist + size - overlap; cy = Range(0, DIMS_Y - 1); break;
        case 7: cx = Range(0, DIMS_X - 1); cy = Range(-size, size); break;
        case 8: cx = Range(0, DIMS_X - 1); cy = DIMS_Y + Range(-size, size); break;
        case 9: cx = DIMS_X / 2; cy = DIMS_Y / 2; size += 200; break;
        default: cx = -dist - size + overlap; cy = -dist - size + overlap; break;
    }
    for (k = 0; k < n; k++)
    {
        switch (kind)
        {
            case 0: /* anywhere in the box: concave and self-intersecting */
                pt[k].x = cx + Range(-size, size); pt[k].y = cy + Range(-size, size); break;
            case 1: /* steps: horizontal and vertical edges */
                pt[k].x = cx + Range(-size, size) / 4 * 4; pt[k].y = cy + (k / 2) * size / 3 - size; if (k & 1) pt[k].y -= size / 3; break;
            case 2: /* one row */
                pt[k].x = cx + Range(-size, size); pt[k].y = cy + (Rand() % 4 == 0); break;
            case 3: /* one pixel */
                pt[k].x = cx + Range(0, 1); pt[k].y = cy + Range(0, 1); break;
            case 4: /* thin: one or two columns */
                pt[k].x = cx + Range(0, 2); pt[k].y = cy + Range(-size, size); break;
            default: /* a triangle fan with a flat base */
                pt[k].x = cx + Range(-size, size); pt[k].y = cy + ((k % 3) ? size : -size); break;
        }
    }
    *pCount = n;
    return kind;
}

static void test_ClipInvariance(void)
{
    HRGN rgnRect, rgnOne, rgnComplex[3], rgn;
    HBRUSH brush[3];
    BYTE *mask[5];
    DWORD *ref;
    HRGN list[5];
    int i, k, bad = 0, drawn = 0, checked = 0;
    POINT pt[16];
    int count;

    ref = HeapAlloc(GetProcessHeap(), 0, DIMS_X * DIMS_Y * sizeof(DWORD));
    if (!ref)
    {
        skip("no memory\n");
        return;
    }
    rgnRect = CreateRectRgn(10, 10, DIMS_X - 10, DIMS_Y - 10);
    rgnOne = CreateRectRgn(60, 40, 61, 41);
    for (k = 0; k < 3; k++)
    {
        HRGN t;

        rgn = CreateRectRgn(4 + k, 6 + k, DIMS_X - 4 - k, DIMS_Y - 5);
        t = CreateRectRgn(30 + 9 * k, 20, 70 + 9 * k, 60); CombineRgn(rgn, rgn, t, RGN_DIFF); DeleteObject(t);
        t = CreateRectRgn(90, 50 + 6 * k, 130, 90); CombineRgn(rgn, rgn, t, RGN_DIFF); DeleteObject(t);
        t = CreateRectRgn(40, 30, 50, 40); CombineRgn(rgn, rgn, t, RGN_OR); DeleteObject(t);              /* island in a hole */
        t = CreateRectRgn(0, 0, 3, 3); CombineRgn(rgn, rgn, t, RGN_OR); DeleteObject(t);                  /* separate rectangle */
        t = CreateRectRgn(DIMS_X - 20, 0, DIMS_X, 1 + k); CombineRgn(rgn, rgn, t, RGN_OR); DeleteObject(t); /* a thin piece at the top */
        t = CreateRectRgn(0, DIMS_Y - 2, 40 + k, DIMS_Y); CombineRgn(rgn, rgn, t, RGN_OR); DeleteObject(t);
        rgnComplex[k] = rgn;
    }
    list[0] = rgnRect; list[1] = rgnOne; list[2] = rgnComplex[0]; list[3] = rgnComplex[1]; list[4] = rgnComplex[2];
    for (k = 0; k < 5; k++)
    {
        mask[k] = HeapAlloc(GetProcessHeap(), 0, DIMS_X * DIMS_Y);
        MakeMask(list[k], mask[k]);
    }
    brush[0] = CreateSolidBrush(RGB(200, 30, 30));
    brush[1] = CreateHatchBrush(HS_DIAGCROSS, RGB(30, 200, 30));
    brush[2] = CreateSolidBrush(RGB(30, 30, 200));
    SelectObject(g_dc, GetStockObject(NULL_PEN));

    for (i = 0; i < POLYGONS; i++)
    {
        int kind = MakePolygon(pt, &count), fillmode = (i & 1) ? WINDING : ALTERNATE, which = i % 5;
        int x, y, changed = 0;

        SetPolyFillMode(g_dc, fillmode);
        SelectObject(g_dc, brush[i % 3]);

        /* without a clip */
        SelectClipRgn(g_dc, NULL);
        Clear();
        Polygon(g_dc, pt, count);
        GdiFlush();
        memcpy(ref, g_bits, DIMS_X * DIMS_Y * sizeof(DWORD));
        for (x = 0; x < DIMS_X * DIMS_Y; x++)
            changed += ref[x] != BACKGROUND;

        /* with a clip */
        SelectClipRgn(g_dc, list[which]);
        Clear();
        Polygon(g_dc, pt, count);
        GdiFlush();
        SelectClipRgn(g_dc, NULL);

        for (y = 0; y < DIMS_Y; y++)
        {
            for (x = 0; x < DIMS_X; x++)
            {
                DWORD expect = mask[which][y * DIMS_X + x] ? ref[y * DIMS_X + x] : BACKGROUND;

                if (g_bits[y * DIMS_X + x] != expect)
                    bad++;
            }
        }
        if (bad)
        {
            ok(0, "polygon %d (kind %d, %d points, fill mode %d, clip %d): %d pixels differ from the unclipped polygon\n",
               i, kind, count, fillmode, which, bad);
            bad = 0;
        }
        checked++;
        drawn += changed != 0;
    }
    ok(checked == POLYGONS, "%d polygons checked\n", checked);
    ok(drawn > POLYGONS / 4, "only %d of %d polygons touched the surface\n", drawn, POLYGONS);

    for (k = 0; k < 5; k++)
    {
        HeapFree(GetProcessHeap(), 0, mask[k]);
        DeleteObject(list[k]);
    }
    for (k = 0; k < 3; k++)
        DeleteObject(brush[k]);
    HeapFree(GetProcessHeap(), 0, ref);
}

START_TEST(PolygonClipInvariance)
{
    BITMAPINFO bmi;
    HBITMAP hbmp, hold;

    g_dc = CreateCompatibleDC(NULL);
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = DIMS_X;
    bmi.bmiHeader.biHeight = -DIMS_Y;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    hbmp = CreateDIBSection(g_dc, &bmi, DIB_RGB_COLORS, (PVOID *)&g_bits, NULL, 0);
    if (!hbmp)
    {
        skip("no DIB section\n");
        DeleteDC(g_dc);
        return;
    }
    hold = SelectObject(g_dc, hbmp);

    test_ClipInvariance();

    SelectObject(g_dc, hold);
    DeleteObject(hbmp);
    DeleteDC(g_dc);
}
