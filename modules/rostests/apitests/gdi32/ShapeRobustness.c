/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Ellipse, RoundRect, Arc, Pie and Chord (and the paths built from them) with extreme or degenerate
 *              parameters: huge boxes and pens, transforms that squash an axis or rotate a y-up mapping, a path that
 *              cannot be built. The calls must return promptly, leave the DC and its path usable, and (where the result
 *              is defined) draw what they should. They used to stall for seconds or minutes, halt a Debug build
 *              (assertions in the region code) or divide by zero in the kernel.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define DIMS 64
/* Calls took from several seconds to minutes (or forever) before and return in milliseconds now. The bound is far from
   both: a loaded test machine varies by a factor of ten between runs, which must not fail the test. */
#define MAX_MS 20000.0

static DWORD *g_bits;
static HDC g_dc;
static double g_freq;

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

static DWORD Pixel(int x, int y)
{
    GdiFlush();
    return g_bits[y * DIMS + x] & 0xFFFFFF;
}

static BOOL InkIn(int x0, int y0, int x1, int y1)
{
    int x, y;

    for (y = y0; y <= y1; y++)
        for (x = x0; x <= x1; x++)
            if (Pixel(x, y) != 0xFFFFFF)
                return TRUE;
    return FALSE;
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
    SetLayout(g_dc, 0);
    SetArcDirection(g_dc, AD_COUNTERCLOCKWISE);
    SetMiterLimit(g_dc, 10.0f, NULL);
    SetPolyFillMode(g_dc, ALTERNATE);
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    SelectObject(g_dc, GetStockObject(NULL_BRUSH));
    SetROP2(g_dc, R2_COPYPEN);
}

static double Now(void)
{
    LARGE_INTEGER t;

    QueryPerformanceCounter(&t);
    return t.QuadPart * 1000.0 / g_freq;
}

/* After the calls of a test: the DC still draws an ordinary shape */
static void ok_still_draws(const char *name)
{
    int n;

    ResetDC_();
    Clear();
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    ok(Ellipse(g_dc, 8, 8, 56, 56), "%s: ordinary Ellipse fails\n", name);
    n = CountInk();
    ok(n >= 100 && n <= 400, "%s: ordinary Ellipse painted %d pixels\n", name, n);
}

enum { SH_ELLIPSE, SH_ROUNDRECT, SH_ARC, SH_PIE, SH_CHORD };

static BOOL DrawShape(int sh, const int *b, const int *p)
{
    switch (sh)
    {
        case SH_ELLIPSE: return Ellipse(g_dc, b[0], b[1], b[2], b[3]);
        case SH_ROUNDRECT: return RoundRect(g_dc, b[0], b[1], b[2], b[3], p[0], p[1]);
        case SH_ARC: return Arc(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
        case SH_PIE: return Pie(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
        default: return Chord(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
    }
}

/* A mapping that flips y (an isotropic mapping with a negative viewport extent) and a world rotation: a cosmetic pen
   draws the shape as a path, which is stroked with the device points; the region it builds must not keep the page
   scale of the flipped mapping (its bands then run upwards, an assertion of the region code) */
static void test_RotatedCosmeticPens(void)
{
    static const struct
    {
        int sh, box[4], p[4];
        int mm;
        POINT we, ve, wo;
        XFORM x;
        BOOL clip;
        RECT rcClip;
    } c[] =
    {
        /* seen in a randomised run: an Arc of 1 pixel pen, isotropic 8:8 to 20:-20 */
        { SH_ARC, { -32768, 4, -32773, 218 }, { 2, 16777216, -13365, 215 }, MM_ISOTROPIC, { 8, 8 }, { 20, -20 }, { 249, 1 },
          { 9.61331e-07f, 2.75397e-07f, -3.89365e-07f, 9.61331e-07f, 136.0f, 17.0f }, FALSE, { 0 } },
        /* a Chord, a y-up mapping, a rotation by 90 degrees and a clip rectangle */
        { SH_CHORD, { 219, 137, 453, 325 }, { 124, 69, 281, 197 }, MM_ISOTROPIC, { 2, 6 }, { 5, -15 }, { 0, 0 },
          { -1.15615e-15f, -0.25f, 0.482939f, -1.15615e-15f, 178.0f, 1.07054f }, TRUE, { 124, 145, 203, 197 } },
        { SH_PIE, { 219, 137, 453, 325 }, { 124, 69, 281, 197 }, MM_ISOTROPIC, { 2, 6 }, { 5, -15 }, { 0, 0 },
          { -1.15615e-15f, -0.25f, 0.482939f, -1.15615e-15f, 178.0f, 1.07054f }, TRUE, { 124, 145, 203, 197 } },
        { SH_ELLIPSE, { 219, 137, 453, 325 }, { 0 }, MM_ISOTROPIC, { 2, 6 }, { 5, -15 }, { 0, 0 },
          { -1.15615e-15f, -0.25f, 0.482939f, -1.15615e-15f, 178.0f, 1.07054f }, TRUE, { 124, 145, 203, 197 } },
    };
    HPEN pen = CreatePen(PS_SOLID, 1, 0);
    int i, n;

    for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++)
    {
        HRGN hrgn = NULL;
        double t0;
        BOOL ret;

        ResetDC_();
        Clear();
        SelectObject(g_dc, pen);
        SetMapMode(g_dc, c[i].mm);
        SetWindowExtEx(g_dc, c[i].we.x, c[i].we.y, NULL);
        SetViewportExtEx(g_dc, c[i].ve.x, c[i].ve.y, NULL);
        SetWindowOrgEx(g_dc, c[i].wo.x, c[i].wo.y, NULL);
        SetGraphicsMode(g_dc, GM_ADVANCED);
        SetWorldTransform(g_dc, &c[i].x);
        if (c[i].clip)
        {
            hrgn = CreateRectRgn(c[i].rcClip.left, c[i].rcClip.top, c[i].rcClip.right, c[i].rcClip.bottom);
            SelectClipRgn(g_dc, hrgn);
        }
        t0 = Now();
        ret = DrawShape(c[i].sh, c[i].box, c[i].p);
        ok(Now() - t0 < MAX_MS, "[%d] the call took %.0f ms (returned %d)\n", i, Now() - t0, ret);
        SelectClipRgn(g_dc, NULL);
        if (hrgn)
            DeleteObject(hrgn);
    }

    /* The same kind of mapping where the shape is on the DIB: an ellipse of 30 pixels, y up, turned by 90 degrees
       (x' = 50 - y, y' = x), with the 1 pixel pen, and with a brush */
    {
        static const XFORM x90 = { 0.0f, 1.0f, -1.0f, 0.0f, 50.0f, 0.0f };

        ResetDC_();
        Clear();
        SelectObject(g_dc, pen);
        SetMapMode(g_dc, MM_ISOTROPIC);
        SetWindowExtEx(g_dc, 1, 1, NULL);
        SetViewportExtEx(g_dc, 1, -1, NULL);
        SetViewportOrgEx(g_dc, 0, 63, NULL);
        SetGraphicsMode(g_dc, GM_ADVANCED);
        SetWorldTransform(g_dc, &x90);
        ok(Ellipse(g_dc, 10, 10, 40, 40), "Ellipse (y up, rotated) fails\n");
        n = CountInk();
        ok(n >= 60 && n <= 200, "Ellipse (y up, rotated) painted %d pixels\n", n);
        /* x' = 50 - y in [10, 40], y' = x in [10, 40], the device y is 63 - y': the box is 10..40 by 23..53 */
        ok(InkIn(24, 21, 27, 25), "no ink at the top of the ellipse\n");
        ok(InkIn(24, 51, 27, 55), "no ink at the bottom of the ellipse\n");
        ok(!InkIn(23, 36, 28, 41), "ink in the middle of the (unfilled) ellipse\n");

        Clear();
        SelectObject(g_dc, CreateSolidBrush(RGB(255, 0, 0)));
        ok(Ellipse(g_dc, 10, 10, 40, 40), "filled Ellipse (y up, rotated) fails\n");
        ok(Pixel(25, 38) == 0xFF0000, "middle of the filled ellipse is %06lx\n", Pixel(25, 38));
        DeleteObject(SelectObject(g_dc, GetStockObject(NULL_BRUSH)));
    }
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    DeleteObject(pen);
    ok_still_draws("RotatedCosmeticPens");
}

/* A round rectangle with a geometric pen of 2^31 - 1 under a transform that scales y by 1e20: the widened outline has
   points far beyond the coordinate range of a DC, and the polygon set-up of the region divided by a wrapped height */
static void test_WideRoundRectRange(void)
{
    static const struct
    {
        DWORD style;
        DWORD width;
        int box[4], p[2];
        int mm;
        POINT vo;
        BOOL xf;
        XFORM x;
        int rop;
        BOOL clip;
        RECT rcClip;
        POINT moveto;
    } c[] =
    {
        { PS_GEOMETRIC | PS_ENDCAP_SQUARE | PS_JOIN_MITER, 2147483647, { 243, 2147483647, 296, -2147483643 }, { -32768, 289 },
          MM_HIMETRIC, { 0, 0 }, TRUE, { -3.36893f, 0.5f, 0.0f, 1e20f, 15.0f, 45.0f }, R2_MASKPENNOT, TRUE, { 81, 214, 48, 238 },
          { 0, 0 } },
        { PS_GEOMETRIC | PS_DOT | PS_JOIN_MITER, 2147483647, { 232, 34, 355, 279 }, { 60, 27 },
          MM_TEXT, { -74713, -30 }, TRUE, { 2.33333f, 0.0f, -0.0f, 2.33333f, -2.36109f, 3.4e38f }, R2_MASKPENNOT, FALSE, { 0 },
          { 1073741824, 33 } },
        { PS_GEOMETRIC | PS_SOLID, 2147483647, { 0, 0, 100, 100 }, { 20, 20 },
          MM_TEXT, { 0, 0 }, TRUE, { 1.0f, 0.0f, 0.0f, 1e30f, 0.0f, 0.0f }, R2_COPYPEN, FALSE, { 0 }, { 0, 0 } },
    };
    LOGBRUSH lb = { BS_SOLID, RGB(0, 128, 0), 0 };
    int i;

    for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++)
    {
        HPEN pen = ExtCreatePen(c[i].style, c[i].width, &lb, 0, NULL);
        HBRUSH hbr = CreateHatchBrush(HS_DIAGCROSS, RGB(160, 0, 0));
        HRGN hrgn = NULL;
        double t0;

        ok(pen != NULL, "[%d] no pen\n", i);
        ResetDC_();
        SelectObject(g_dc, pen);
        SelectObject(g_dc, hbr);
        SetMapMode(g_dc, c[i].mm);
        SetViewportOrgEx(g_dc, c[i].vo.x, c[i].vo.y, NULL);
        SetGraphicsMode(g_dc, GM_ADVANCED);
        if (c[i].xf)
            SetWorldTransform(g_dc, &c[i].x);
        SetROP2(g_dc, c[i].rop);
        if (c[i].moveto.x)
            MoveToEx(g_dc, c[i].moveto.x, c[i].moveto.y, NULL);
        if (c[i].clip)
        {
            hrgn = CreateRectRgn(c[i].rcClip.left, c[i].rcClip.top, c[i].rcClip.right, c[i].rcClip.bottom);
            SelectClipRgn(g_dc, hrgn);
        }
        t0 = Now();
        RoundRect(g_dc, c[i].box[0], c[i].box[1], c[i].box[2], c[i].box[3], c[i].p[0], c[i].p[1]);
        ok(Now() - t0 < MAX_MS, "[%d] RoundRect took %.0f ms\n", i, Now() - t0);
        t0 = Now();
        BeginPath(g_dc);
        RoundRect(g_dc, c[i].box[0], c[i].box[1], c[i].box[2], c[i].box[3], c[i].p[0], c[i].p[1]);
        EndPath(g_dc);
        StrokeAndFillPath(g_dc);
        ok(Now() - t0 < MAX_MS, "[%d] StrokeAndFillPath took %.0f ms\n", i, Now() - t0);
        SelectClipRgn(g_dc, NULL);
        if (hrgn)
            DeleteObject(hrgn);
        SelectObject(g_dc, GetStockObject(BLACK_PEN));
        SelectObject(g_dc, GetStockObject(NULL_BRUSH));
        DeleteObject(pen);
        DeleteObject(hbr);
    }
    ok_still_draws("WideRoundRectRange");
}

/* ArcTo in a path under a rotation, with a box that does not fit the device range: the points of the arc cannot be
   mapped. The call fails (or draws something), but must not leave the path with the move-to alone (the region of such
   a path has no points and was allocated with the size 0) */
static void test_ArcToFailure(void)
{
    static const XFORM x30 = { 0.8660254f, 0.5f, -0.5f, 0.8660254f, 0.0f, 0.0f };
    static const int box[][8] =
    {
        { 0, 0, 400000000, 400000000, 400000000, 200000000, 200000000, 0 },
        { -400000000, -400000000, 400000000, 400000000, 0, -400000000, 400000000, 0 },
        { 0, 0, 2147483647, 2147483647, 2147483647, 1000000000, 1000000000, 0 },
    };
    int i, n;

    for (i = 0; i < (int)(sizeof(box) / sizeof(box[0])); i++)
    {
        BOOL r1, r2, r3;
        HRGN hrgn;

        ResetDC_();
        Clear();
        SetGraphicsMode(g_dc, GM_ADVANCED);
        SetWorldTransform(g_dc, &x30);
        SelectObject(g_dc, GetStockObject(DKGRAY_BRUSH));
        MoveToEx(g_dc, 10, 10, NULL);
        r1 = BeginPath(g_dc);
        ok(r1, "[%d] BeginPath fails\n", i);
        r1 = ArcTo(g_dc, box[i][0], box[i][1], box[i][2], box[i][3], box[i][4], box[i][5], box[i][6], box[i][7]);
        r2 = EndPath(g_dc);
        ok(r2, "[%d] EndPath fails\n", i);
        n = GetPath(g_dc, NULL, NULL, 0);
        ok(n != 1, "[%d] ArcTo returned %d and left a path with %d point (a lone move-to)\n", i, r1, n);
        if (!r1)
            ok(n <= 0 || n >= 2, "[%d] a failed ArcTo changed the path to %d points\n", i, n);
        r3 = FillPath(g_dc);
        trace("[%d] ArcTo %d, %d points, FillPath %d\n", i, r1, n, r3);

        /* the same path as a region */
        ResetDC_();
        SetGraphicsMode(g_dc, GM_ADVANCED);
        SetWorldTransform(g_dc, &x30);
        MoveToEx(g_dc, 10, 10, NULL);
        BeginPath(g_dc);
        ArcTo(g_dc, box[i][0], box[i][1], box[i][2], box[i][3], box[i][4], box[i][5], box[i][6], box[i][7]);
        EndPath(g_dc);
        hrgn = PathToRegion(g_dc);
        if (hrgn)
            DeleteObject(hrgn);
        AbortPath(g_dc);
    }
    ok_still_draws("ArcToFailure");
}

/* The regions of polygons are exact for the whole range of the points (the setup of the edges does not wrap): a point
   far outside the device range (2^28, 2^30) gives a region with that corner, as before the wide pens. */
static void test_PolygonRegions(void)
{
    static const LONG xs[] = { 0x7ffffff, 0x8000001, 0x10000000, 150000000, 178000000, 0x40000000 };
    static const POINT ext[3] = { { -0x7fffffff, 10 }, { 0x7ffffffe, 20 }, { 5, 30 } };
    int i;
    HRGN hrgn;
    RECT rc;

    for (i = 0; i < (int)(sizeof(xs) / sizeof(xs[0])); i++)
    {
        POINT pt[3] = { { 10, 10 }, { xs[i], 20 }, { 10, 200 } };

        hrgn = CreatePolygonRgn(pt, 3, ALTERNATE);
        ok(hrgn != NULL, "CreatePolygonRgn with a point at %ld fails\n", xs[i]);
        if (hrgn)
        {
            ok(GetRgnBox(hrgn, &rc) == COMPLEXREGION, "region at %ld is not complex\n", xs[i]);
            ok(rc.left == 10 && (rc.top == 10 || rc.top == 11) && rc.bottom == 200 && rc.right >= xs[i] - 1 && rc.right <= xs[i],
               "region at %ld has the box %ld,%ld,%ld,%ld\n", xs[i], rc.left, rc.top, rc.right, rc.bottom);
            DeleteObject(hrgn);
        }

        ResetDC_();
        BeginPath(g_dc);
        Polygon(g_dc, pt, 3);
        EndPath(g_dc);
        hrgn = PathToRegion(g_dc);
        ok(hrgn != NULL, "PathToRegion with a point at %ld fails\n", xs[i]);
        if (hrgn)
            DeleteObject(hrgn);
    }

    /* points near both ends of the LONG range: any answer, but no divide error, no hang */
    hrgn = CreatePolygonRgn(ext, 3, WINDING);
    if (hrgn)
        DeleteObject(hrgn);
    ok_still_draws("PolygonRegions");
}

/* The pen and the shape make an outline that does not touch the DC, or reaches millions of pixels past it: the
   region of the outline used to have a scanline for each row it spans, and the call took seconds to minutes (or did
   not return). Nothing of the outline that lies outside the DC is painted, and what lies inside is exact. */
static void test_HugeOutlines(void)
{
    static const struct
    {
        int sh, box[4], p[4];
        int width;
        BOOL rot;
        int ink; /* >= 0: the exact number of pixels painted (-1: not checked) */
    } c[] =
    {
        /* a pen wider than the world: the outline covers the DIB (its pixels are not counted: Windows paints all of
           them, the outline of the widened path keeps a hole as wide as the pen's overhang) */
        { SH_ELLIPSE, { 8, 8, 56, 56 }, { 0 }, 1 << 28, FALSE, -1 },
        { SH_ELLIPSE, { 8, 8, 56, 56 }, { 0 }, 100000, FALSE, -1 },
        { SH_ROUNDRECT, { 8, 8, 56, 56 }, { 10, 10 }, 1 << 28, FALSE, -1 },
        /* a box of 2^30: the outline is nowhere near the DIB */
        { SH_ELLIPSE, { -(1 << 30), -(1 << 30), 1 << 30, 1 << 30 }, { 0 }, 7, FALSE, 0 },
        { SH_CHORD, { -(1 << 30), -(1 << 30), 1 << 30, 1 << 30 }, { 1 << 30, 0, 0, -(1 << 30) }, 7, FALSE, 0 },
        /* a big box under a rotation: the outline is a curve through the DIB's neighbourhood */
        { SH_ELLIPSE, { -(1 << 25), -(1 << 25), 1 << 25, 1 << 25 }, { 0 }, 7, TRUE, -1 },
        { SH_ELLIPSE, { 0, 0, 100000, 100000 }, { 0 }, 7, FALSE, -1 },
        { SH_ROUNDRECT, { 0, 0, 100000, 100000 }, { 5000, 5000 }, 7, FALSE, -1 },
        { SH_ARC, { 0, 0, 100000, 100000 }, { 100000, 50000, 50000, 0 }, 25, FALSE, -1 },
    };
    static const XFORM x30 = { 0.8660254f, 0.5f, -0.5f, 0.8660254f, 32.0f, 32.0f };
    int i, n;

    for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++)
    {
        HPEN pen = CreatePen(PS_SOLID, c[i].width, RGB(0, 128, 0));
        double t0;
        BOOL ret;

        ResetDC_();
        Clear();
        SelectObject(g_dc, pen);
        SelectObject(g_dc, GetStockObject(NULL_BRUSH));
        if (c[i].rot)
        {
            SetGraphicsMode(g_dc, GM_ADVANCED);
            SetWorldTransform(g_dc, &x30);
        }
        t0 = Now();
        ret = DrawShape(c[i].sh, c[i].box, c[i].p);
        ok(Now() - t0 < MAX_MS, "[%d] the call took %.0f ms (returned %d)\n", i, Now() - t0, ret);
        n = CountInk();
        if (c[i].ink >= 0)
            ok(n == c[i].ink, "[%d] painted %d pixels, expected %d\n", i, n, c[i].ink);
        SelectObject(g_dc, GetStockObject(BLACK_PEN));
        DeleteObject(pen);
    }

    /* An outline cut at a distance of 100000 pixels leaves the visible part exact: a circle of radius 100000 whose
       rightmost point is at x = 32; its edge is a vertical line there (it bends by 0.005 pixel over the DIB). With a
       black pen of 7 and a red brush: red to the left, the pen in columns 29..35, white to the right. */
    {
        HBRUSH hbr = CreateSolidBrush(RGB(255, 0, 0));
        int y, x, black;
        double t0_;

        ResetDC_();
        Clear();
        SelectObject(g_dc, CreatePen(PS_SOLID, 7, 0));
        SelectObject(g_dc, hbr);
        t0_ = Now();
        BeginPath(g_dc);
        ok(Ellipse(g_dc, 32 - 200000, 32 - 100000, 32, 32 + 100000), "big Ellipse fails\n");
        EndPath(g_dc);
        ok(StrokeAndFillPath(g_dc), "StrokeAndFillPath fails\n");
        ok(Now() - t0_ < MAX_MS, "big Ellipse took %.0f ms\n", Now() - t0_);
        for (y = 2; y < DIMS - 2; y += 10)
        {
            ok(Pixel(10, y) == 0xFF0000, "row %d: x=10 is %06lx\n", y, Pixel(10, y));
            ok(Pixel(50, y) == 0xFFFFFF, "row %d: x=50 is %06lx\n", y, Pixel(50, y));
            black = 0;
            for (x = 20; x < 45; x++)
                if (Pixel(x, y) == 0)
                    black++;
            ok(black >= 6 && black <= 8, "row %d: the pen is %d pixels wide\n", y, black);
            ok(Pixel(31, y) == 0 && Pixel(32, y) == 0, "row %d: x=31, 32 are %06lx, %06lx\n", y, Pixel(31, y), Pixel(32, y));
        }
        DeleteObject(SelectObject(g_dc, GetStockObject(BLACK_PEN)));
        SelectObject(g_dc, GetStockObject(NULL_BRUSH));
        DeleteObject(hbr);
    }
    ok_still_draws("HugeOutlines");
}

/* A transform that squashes an axis (a zero extent of an isotropic mapping, a -Inf entry in the world transform): the
   corners of the shape lie on a line, the normalized points divide by the radius 0 and the angles are NaN. The loop that
   adds the Bezier parts of an arc ran forever and grew the path without end. */
static void test_DegenerateTransform(void)
{
    static const int arc[] = { 194, -403197, 237, -402937, 143, 123, 43, -995077 };
    static const XFORM xw = { -0.815967f, -0.946544f, 0.0f, -1.44263f, 130.0f, 158.0f };
    XFORM xinf = { -2.64025e-29f, -2.77164f, 0.0f, -1.0f, 126.0f, 0.0f };
    LOGBRUSH lb = { BS_SOLID, RGB(0, 128, 0), 0 };
    int dd, n, sh;
    BOOL bZero = FALSE;
    double t0;
    HPEN pen;

    /* the isotropic mapping adjusts the viewport extent: window 18:5 and viewport -2:d gives -2:0 for some d */
    for (dd = 1; dd <= 20 && !bZero; dd++)
    {
        SIZE ve;

        ResetDC_();
        SetMapMode(g_dc, MM_ISOTROPIC);
        SetWindowExtEx(g_dc, 18, 5, NULL);
        SetViewportExtEx(g_dc, -2, dd, NULL);
        GetViewportExtEx(g_dc, &ve);
        bZero = (ve.cx == -2 && ve.cy == 0);
    }
    if (!bZero)
        skip("the isotropic mapping does not give a zero extent here\n");
    else
    {
        pen = CreatePen(PS_SOLID, 132, RGB(0, 128, 0));
        for (sh = SH_ARC; sh <= SH_CHORD; sh++)
        {
            HRGN hrgn;

            SelectObject(g_dc, pen);
            SelectObject(g_dc, GetStockObject(DKGRAY_BRUSH));
            SetGraphicsMode(g_dc, GM_ADVANCED);
            SetWorldTransform(g_dc, &xw);
            SetArcDirection(g_dc, AD_CLOCKWISE);
            t0 = Now();
            DrawShape(sh, arc, arc + 4);
            ok(Now() - t0 < MAX_MS, "shape %d under a zero extent took %.0f ms\n", sh, Now() - t0);

            t0 = Now();
            BeginPath(g_dc);
            DrawShape(sh, arc, arc + 4);
            EndPath(g_dc);
            n = GetPath(g_dc, NULL, NULL, 0);
            ok(n <= 0 || n >= 2, "shape %d: the path holds %d points\n", sh, n);
            hrgn = PathToRegion(g_dc);
            if (hrgn)
                DeleteObject(hrgn);
            AbortPath(g_dc);
            ok(Now() - t0 < MAX_MS, "shape %d in a path under a zero extent took %.0f ms\n", sh, Now() - t0);
        }
        SelectObject(g_dc, GetStockObject(BLACK_PEN));
        DeleteObject(pen);
    }

    /* a -Inf entry: SetWorldTransform may refuse it (and Windows might), then there is nothing to test */
    pen = ExtCreatePen(PS_GEOMETRIC | PS_DASH | PS_JOIN_BEVEL | PS_ENDCAP_SQUARE, 7, &lb, 0, NULL);
    ResetDC_();
    SelectObject(g_dc, pen);
    SelectObject(g_dc, CreateSolidBrush(RGB(116, 0, 0)));
    SetGraphicsMode(g_dc, GM_ADVANCED);
    xinf.eM22 = -1.0f / 0.0f;
    if (SetWorldTransform(g_dc, &xinf))
    {
        SetLayout(g_dc, LAYOUT_RTL);
        SetMiterLimit(g_dc, 8.0f, NULL);
        SetROP2(g_dc, R2_NOTMERGEPEN);
        t0 = Now();
        Pie(g_dc, 153, 127, 2147483647, 245, 7, 50, -4, 1073741824);
        ok(Now() - t0 < MAX_MS, "Pie under a -Inf transform took %.0f ms\n", Now() - t0);
        t0 = Now();
        Ellipse(g_dc, 153, 127, 2147483647, 245);
        ok(Now() - t0 < MAX_MS, "Ellipse under a -Inf transform took %.0f ms\n", Now() - t0);
    }
    DeleteObject(SelectObject(g_dc, GetStockObject(NULL_BRUSH)));
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    DeleteObject(pen);
    ok_still_draws("DegenerateTransform");
}

START_TEST(ShapeRobustness)
{
    BITMAPINFO bi;
    HBITMAP bmp, bmpOld;
    LARGE_INTEGER f;

    QueryPerformanceFrequency(&f);
    g_freq = (double)f.QuadPart;
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

    test_RotatedCosmeticPens();
    test_WideRoundRectRange();
    test_ArcToFailure();
    test_PolygonRegions();
    test_HugeOutlines();
    test_DegenerateTransform();

    SelectObject(g_dc, bmpOld);
    DeleteObject(bmp);
    DeleteDC(g_dc);
}
