/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Beziers with coordinates near the ends of the device range: flattening a curve works in
 *              fixed point (the coordinates shifted up by 4 bits), which overflowed 32 bits and divided
 *              INT_MIN by -1 (a kernel divide error). The calls must return, flatten to a polyline that
 *              runs from the first to the last point, and leave the DC usable.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define DIMS 64
#define B27 0x8000000

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
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    SelectObject(g_dc, GetStockObject(NULL_BRUSH));
    SetROP2(g_dc, R2_COPYPEN);
}

/* After a call with extreme coordinates: the DC still draws an ordinary curve (a flattening that went wrong, or a
   state left behind, shows as nothing or as a wrong amount of ink) */
static void ok_still_draws(const char *name)
{
    static const POINT pts[4] = { { 4, 50 }, { 20, 4 }, { 44, 4 }, { 60, 50 } };
    int n;

    ResetDC_();
    Clear();
    ok(PolyBezier(g_dc, pts, 4), "%s: ordinary PolyBezier fails\n", name);
    n = CountInk();
    ok(n >= 60 && n <= 400, "%s: ordinary PolyBezier painted %d pixels\n", name, n);
}

/* The path of a curve through points that overflow the shifted fixed point: it flattens to a polyline from the first
   to the last point */
static void test_FlattenExtreme(void)
{
    static const struct { int x0, y0, x1, y1, x2, y2, x3, y3; } c[] =
    {
        /* around +-100000 (coordinates the random draw tests use) */
        { -100000, -100000, 100000, -100000, -100000, 100000, 100000, 100000 },
        { 100000, 0, -100000, 50000, 100000, 100000, -100000, 100000 },
        /* around the 27 bit limit: x << 4 does not fit 32 bits */
        { -B27, -B27, B27 - 1, -B27, -B27, B27 - 1, B27 - 1, B27 - 1 },
        { 0, B27 - 1, B27 - 1, B27 - 1, -B27, -B27, 0, -B27 },
        { 67108864, 5, 67108865, 6, 134217727, 7, 134217700, 9 },
        { 1, 2, 134217727, 3, -134217728, 4, 5, 6 },
        /* a shallow and a steep line with a control point at the other end of the range */
        { -B27, 0, B27 - 1, 1, B27 - 1, 2, -B27, 3 },
        { 0, -B27, 1, B27 - 1, 2, B27 - 1, 3, -B27 },
    };
    int i;

    for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++)
    {
        POINT pts[4] = { { c[i].x0, c[i].y0 }, { c[i].x1, c[i].y1 }, { c[i].x2, c[i].y2 }, { c[i].x3, c[i].y3 } };
        POINT *out;
        int n;
        BOOL ret;

        ResetDC_();
        ret = BeginPath(g_dc);
        ok(ret, "[%d] BeginPath fails\n", i);
        PolyBezier(g_dc, pts, 4);
        EndPath(g_dc);
        ret = FlattenPath(g_dc);
        ok(ret, "[%d] FlattenPath fails\n", i);
        n = GetPath(g_dc, NULL, NULL, 0);
        ok(n >= 2, "[%d] flattened path has %d points\n", i, n);
        if (n >= 2)
        {
            out = HeapAlloc(GetProcessHeap(), 0, n * (sizeof(POINT) + 1));
            if (out)
            {
                BYTE *types = (BYTE *)(out + n);

                ok_int(GetPath(g_dc, out, types, n), n);                ok(out[0].x == c[i].x0 && out[0].y == c[i].y0, "[%d] starts at %ld,%ld\n", i, out[0].x, out[0].y);
                ok(out[n - 1].x == c[i].x3 && out[n - 1].y == c[i].y3, "[%d] ends at %ld,%ld, expected %d,%d\n", i,
                   out[n - 1].x, out[n - 1].y, c[i].x3, c[i].y3);
                HeapFree(GetProcessHeap(), 0, out);
            }
        }
        AbortPath(g_dc);
    }
    ok_still_draws("FlattenExtreme");
}

/* PolyBezier, PolyBezierTo and PolyDraw with coordinates of +-100000 under mapping modes that scale them */
static void test_DrawExtreme(void)
{
    /* The calls of the randomised screen-versus-memory comparison that bugchecked: a world transform (rotation, scale 1.8
       to 2), a point near +-100000, and a Bezier with the points that follow. Also with every coordinate scaled up, to the
       range where the device coordinates reach and pass 2^27. */
    static const struct
    {
        int kind; /* 0 PolyBezier, 1 PolyBezierTo, 2 PolyDraw */
        XFORM xf;
        POINT cur;
        int n;
        POINT pt[12];
        BYTE type[12];
    } c[] =
    {
        { 2, { 1.75387f, 0.404912f, -0.404912f, 1.75387f, 93.0f, 146.0f }, { 288, -12 }, 7,
          { { 188, -29 }, { 195, 325 }, { 77, 236 }, { 108, -43 }, { 300, 154 }, { 101457, 1 }, { 112, 295 } },
          { PT_BEZIERTO, PT_BEZIERTO, PT_BEZIERTO, PT_LINETO, PT_BEZIERTO, PT_BEZIERTO, PT_BEZIERTO } },
        { 0, { -0.517638f, 1.93185f, -1.93185f, -0.517638f, 63.0f, 195.0f }, { 0, 0 }, 7,
          { { 139, 276 }, { 186, 256 }, { 113, -104653 }, { 122, -44 }, { 19, 30 }, { 104868, 70 }, { 345, 108 } } },
        { 1, { 1.9997f, -0.0349048f, 0.0349048f, 1.9997f, 139.0f, 189.0f }, { 441, -30 }, 12,
          { { -50, -4 }, { 158, 72 }, { 327, 272 }, { 341, -102623 }, { 161, 80 }, { 413, -50 }, { 163, -100093 },
            { 173, 148 }, { 363, 224 }, { 270, -100248 }, { 362, 143 }, { 75, 273 } } },
    };
    static const int mul[] = { 1, 100, 1000, 10000, 100000 };
    HPEN pen = CreatePen(PS_SOLID, 1, 0);
    int i, m, j;

    for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++)
    {
        for (m = 0; m < (int)(sizeof(mul) / sizeof(mul[0])); m++)
        {
            POINT pt[12];
            BOOL ret;

            for (j = 0; j < c[i].n; j++)
            {
                pt[j].x = c[i].pt[j].x * mul[m];
                pt[j].y = c[i].pt[j].y * mul[m];
            }
            ResetDC_();
            SelectObject(g_dc, pen);
            SetGraphicsMode(g_dc, GM_ADVANCED);
            ok(SetWorldTransform(g_dc, &c[i].xf), "[%d] SetWorldTransform fails\n", i);
            MoveToEx(g_dc, c[i].cur.x, c[i].cur.y, NULL);
            if (c[i].kind == 0)
                ret = PolyBezier(g_dc, pt, c[i].n);
            else if (c[i].kind == 1)
                ret = PolyBezierTo(g_dc, pt, c[i].n);
            else
                ret = PolyDraw(g_dc, pt, c[i].type, c[i].n);
            ok(ret || mul[m] > 1, "[%d x%d] call fails\n", i, mul[m]);
        }
    }
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    DeleteObject(pen);
    ok_still_draws("DrawExtreme");
}

/* A path drawn at the far end of the device range: the viewport origin moves its points to 2^27 */
static void test_PathStrokeAtOrigin(void)
{
    static const int org[][2] = { { B27, 0 }, { 0, B27 }, { -B27, 0 }, { 0, -B27 }, { B27, B27 }, { B27 - 50, -B27 + 50 },
                                  { 134217728, 76 }, { 76, -134217728 } };
    LOGBRUSH lb = { BS_SOLID, 0, 0 };
    int i, k;

    for (k = 0; k < 3; k++)
    {
        for (i = 0; i < (int)(sizeof(org) / sizeof(org[0])); i++)
        {
            HPEN pen;

            ResetDC_();
            if (k == 0)
                pen = CreatePen(PS_SOLID, 1, 0);
            else if (k == 1)
                pen = CreatePen(PS_SOLID, 7, 0);
            else
                pen = ExtCreatePen(PS_GEOMETRIC | PS_DASHDOT | PS_ENDCAP_FLAT | PS_JOIN_MITER, 7, &lb, 0, NULL);
            SelectObject(g_dc, pen);
            SetViewportOrgEx(g_dc, org[i][0], org[i][1], NULL);
            BeginPath(g_dc);
            Ellipse(g_dc, 0, 0, 100, 100);
            EndPath(g_dc);
            StrokePath(g_dc);
            BeginPath(g_dc);
            MoveToEx(g_dc, 0, 0, NULL);
            PolyBezierTo(g_dc, (const POINT[]){ { 40, 90 }, { 90, -40 }, { 100, 100 } }, 3);
            EndPath(g_dc);
            StrokePath(g_dc);
            BeginPath(g_dc);
            RoundRect(g_dc, 0, 0, 100, 100, 30, 30);
            EndPath(g_dc);
            StrokeAndFillPath(g_dc);
            SelectObject(g_dc, GetStockObject(BLACK_PEN));
            DeleteObject(pen);
        }
    }
    ok_still_draws("PathStrokeAtOrigin");
}

/* A plain Pie with a geometric pen near the far end of the range (the outline of the shape is flattened) */
static void test_PieAtOrigin(void)
{
    LOGBRUSH lb = { BS_SOLID, RGB(0, 255, 0), 0 };
    HPEN pen = ExtCreatePen(PS_GEOMETRIC | PS_DASHDOT | PS_ENDCAP_FLAT | PS_JOIN_MITER, 7, &lb, 0, NULL);
    HBRUSH br = CreateSolidBrush(RGB(48, 0, 0));
    static const int orgy[] = { -134217728, 134217728, -134217700, 100000000 };
    int i;

    for (i = 0; i < (int)(sizeof(orgy) / sizeof(orgy[0])); i++)
    {
        ResetDC_();
        SelectObject(g_dc, pen);
        SelectObject(g_dc, br);
        SetArcDirection(g_dc, AD_CLOCKWISE);
        SetMiterLimit(g_dc, 1e6f, NULL);
        SetROP2(g_dc, R2_NOTXORPEN);
        SetPolyFillMode(g_dc, WINDING);
        SetViewportOrgEx(g_dc, 76, orgy[i], NULL);
        Pie(g_dc, -684, 281, -505, 412, 185, 67946, 222, 48);
        Ellipse(g_dc, 0, 0, 100, 100);
        Chord(g_dc, -684, 281, -505, 412, 185, 67946, 222, 48);
        RoundRect(g_dc, 0, 0, 100, 100, 20, 20);
        Arc(g_dc, -684, 281, -505, 412, 185, 67946, 222, 48);
    }
    SelectObject(g_dc, GetStockObject(BLACK_PEN));
    SelectObject(g_dc, GetStockObject(NULL_BRUSH));
    DeleteObject(pen);
    DeleteObject(br);
    ok_still_draws("PieAtOrigin");
}

enum { SH_ELLIPSE, SH_ROUNDRECT, SH_ARC, SH_PIE, SH_CHORD, SH_ARCTO, SH_COUNT };
enum { OP_STROKE, OP_WIDEN, OP_STROKEFILL };

static BOOL DrawShape(int sh, const int *b, const int *p)
{
    switch (sh)
    {
        case SH_ELLIPSE: return Ellipse(g_dc, b[0], b[1], b[2], b[3]);
        case SH_ROUNDRECT: return RoundRect(g_dc, b[0], b[1], b[2], b[3], p[0], p[1]);
        case SH_ARC: return Arc(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
        case SH_PIE: return Pie(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
        case SH_CHORD: return Chord(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
        default: return ArcTo(g_dc, b[0], b[1], b[2], b[3], p[0], p[1], p[2], p[3]);
    }
}

/* Calls of a randomised run of the shape functions inside a path (every shape for each row; the run does not record
   which one it was) that made the flattening divide: the viewport origin or the window origin and the extents put the
   device points near 2^27 and beyond */
static void test_PathRows(void)
{
    static const struct
    {
        int op, style, width, mm;
        int box[4], p[4];
        POINT wo, vo, we, ve;
        BOOL xf;
        XFORM x;
        int moveto;
        POINT mt;
    } c[] =
    {
        /* a path stroked with a 100 wide inside-frame pen at viewport origin 2^27 */
        { OP_STROKE, PS_INSIDEFRAME, 100, MM_TEXT, { 32767, -80068, 32796, -79816 }, { 221, 122, -37, 265 },
          { 0, 0 }, { 134217728, -30 }, { 1, 1 }, { 1, 1 }, FALSE, { 0 }, TRUE, { -2, 280 } },
        /* a path widened under a rotation, window origin x = 2^31 - 1, MM_HIMETRIC, a pen of 806089035 */
        { OP_WIDEN, PS_DASH, 806089035, MM_HIMETRIC, { -32768, 8, 204, 211 }, { 263, 284, 112, 135 },
          { 2147483647, 51285 }, { 139, 103 }, { 21100, 15800 }, { 800, -600 }, TRUE,
          { -0.000618658f, -0.000785661f, 0.00109132f, -0.000618658f, 29.0f, 124.0f }, FALSE, { 0, 0 } },
        /* the same with a stroked and filled path under a plain scale */
        { OP_STROKEFILL, PS_SOLID, 7, MM_TEXT, { 0, 0, 100, 100 }, { 20, 20, 50, 50 },
          { 0, 0 }, { 134217727, 134217727 }, { 1, 1 }, { 1, 1 }, FALSE, { 0 }, FALSE, { 0, 0 } },
    };
    int i, sh;

    for (i = 0; i < (int)(sizeof(c) / sizeof(c[0])); i++)
    {
        for (sh = 0; sh < SH_COUNT; sh++)
        {
            HPEN pen;

            ResetDC_();
            pen = CreatePen(c[i].style, c[i].width, RGB(0, 128, 0));
            SelectObject(g_dc, pen);
            SelectObject(g_dc, GetStockObject(DKGRAY_BRUSH));
            SetMapMode(g_dc, c[i].mm);
            if (c[i].mm == MM_ISOTROPIC || c[i].mm == MM_ANISOTROPIC)
            {
                SetWindowExtEx(g_dc, c[i].we.x, c[i].we.y, NULL);
                SetViewportExtEx(g_dc, c[i].ve.x, c[i].ve.y, NULL);
            }
            SetWindowOrgEx(g_dc, c[i].wo.x, c[i].wo.y, NULL);
            SetViewportOrgEx(g_dc, c[i].vo.x, c[i].vo.y, NULL);
            if (c[i].xf)
            {
                SetGraphicsMode(g_dc, GM_ADVANCED);
                SetWorldTransform(g_dc, &c[i].x);
            }
            if (c[i].moveto)
                MoveToEx(g_dc, c[i].mt.x, c[i].mt.y, NULL);
            BeginPath(g_dc);
            DrawShape(sh, c[i].box, c[i].p);
            EndPath(g_dc);
            if (c[i].op == OP_STROKE)
                StrokePath(g_dc);
            else if (c[i].op == OP_WIDEN)
                WidenPath(g_dc);
            else
                StrokeAndFillPath(g_dc);
            AbortPath(g_dc);
            SelectObject(g_dc, GetStockObject(BLACK_PEN));
            DeleteObject(pen);
        }
    }
    ok_still_draws("PathRows");
}

START_TEST(BezierExtremeCoords)
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

    test_FlattenExtreme();
    test_DrawExtreme();
    test_PathStrokeAtOrigin();
    test_PieAtOrigin();
    test_PathRows();

    SelectObject(g_dc, bmpOld);
    DeleteObject(bmp);
    DeleteDC(g_dc);
}
