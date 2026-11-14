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
/* Calls took from several seconds to forever before; a loaded virtual machine is slow, but not this slow */
#define MAX_MS 2000.0

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

    SelectObject(g_dc, bmpOld);
    DeleteObject(bmp);
    DeleteDC(g_dc);
}
