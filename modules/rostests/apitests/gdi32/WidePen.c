/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Wide pens: Polyline, PolyPolyline and PolyBezier neither use nor change the current position,
 *              PolylineTo and PolyBezierTo start at it and end at the last point; the width of a pen is in logical
 *              units and the mapping mode and the world transform scale it (lines, arcs, ellipses, round rectangles,
 *              polygons, rectangles and stroked paths)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 (build 19045) with the same drawing code: horizontal and
 * vertical lines of 80 device pixels in a 256x256 32 bpp DIB, the pen thickness counted in the middle column / row.
 */

#include "precomp.h"

#define DIMS 256

static DWORD *g_bits;
static HDC g_dc;
static HBITMAP g_bmp, g_bmpOld;

static void Clear(void)
{
    int i;

    for (i = 0; i < DIMS * DIMS; i++)
        g_bits[i] = 0xFFFFFF;
}

typedef struct { int cnt, l, t, r, b, col, row; DWORD hash; } STAT;

static STAT Measure(int mc, int mr)
{
    STAT s;
    int x, y;
    DWORD h = 2166136261u;

    ZeroMemory(&s, sizeof(s));
    s.l = s.t = 9999;
    s.r = s.b = -1;
    GdiFlush();
    for (y = 0; y < DIMS; y++)
    {
        for (x = 0; x < DIMS; x++)
        {
            DWORD p = g_bits[y * DIMS + x] & 0xFFFFFF;

            h = (h ^ p) * 16777619u;
            if (p == 0xFFFFFF)
                continue;
            s.cnt++;
            if (x < s.l) s.l = x;
            if (x > s.r) s.r = x;
            if (y < s.t) s.t = y;
            if (y > s.b) s.b = y;
            if (x == mc) s.col++;
            if (y == mr) s.row++;
        }
    }
    s.hash = h;
    return s;
}

enum { P_COS1, P_W5, P_G5, P_W7, P_G7, P_W25, P_G25, P_COS0, P_EC1, P_COUNT };
static const char *g_PenName[P_COUNT] = { "cos1", "w5", "g5", "w7", "g7", "w25", "g25", "cos0", "ec1" };

static HPEN MakePen(int k)
{
    LOGBRUSH lb = { BS_SOLID, 0, 0 };
    DWORD g = PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | PS_JOIN_BEVEL;

    switch (k)
    {
        case P_COS1: return CreatePen(PS_SOLID, 1, 0);
        case P_W5:   return CreatePen(PS_SOLID, 5, 0);
        case P_G5:   return ExtCreatePen(g, 5, &lb, 0, NULL);
        case P_W7:   return CreatePen(PS_SOLID, 7, 0);
        case P_G7:   return ExtCreatePen(g, 7, &lb, 0, NULL);
        case P_W25:  return CreatePen(PS_SOLID, 25, 0);
        case P_G25:  return ExtCreatePen(g, 25, &lb, 0, NULL);
        case P_COS0: return CreatePen(PS_SOLID, 0, 0);
        case P_EC1:  return ExtCreatePen(PS_COSMETIC | PS_SOLID, 1, &lb, 0, NULL);
    }
    return NULL;
}

/* ---- the current position ---- */

static const POINT P3[3] = { {120, 60}, {200, 60}, {200, 120} };
static const POINT PB[4] = { {120, 60}, {160, 20}, {200, 100}, {220, 140} };
static const POINT PB3[3] = { {160, 20}, {200, 100}, {220, 140} };
static const POINT PP[5] = { {100, 40}, {180, 40}, {180, 90}, {100, 160}, {180, 160} };
static const DWORD PPc[2] = { 3, 2 };

enum { F_POLYLINE, F_POLYPOLYLINE, F_POLYBEZIER, F_POLYLINETO, F_POLYBEZIERTO, F_POLYGON, F_COUNT };
static const char *g_FuncName[F_COUNT] = { "Polyline", "PolyPolyline", "PolyBezier", "PolylineTo", "PolyBezierTo", "Polygon" };

static STAT DrawFunc(int f, int pen, int sx, int sy, POINT *pCur)
{
    HPEN hpen = MakePen(pen), hold;
    STAT s;

    Clear();
    hold = SelectObject(g_dc, hpen);
    MoveToEx(g_dc, sx, sy, NULL);
    switch (f)
    {
        case F_POLYLINE: Polyline(g_dc, P3, 3); break;
        case F_POLYPOLYLINE: PolyPolyline(g_dc, PP, PPc, 2); break;
        case F_POLYBEZIER: PolyBezier(g_dc, PB, 4); break;
        case F_POLYLINETO: PolylineTo(g_dc, P3, 3); break;
        case F_POLYBEZIERTO: PolyBezierTo(g_dc, PB3, 3); break;
        case F_POLYGON: Polygon(g_dc, P3, 3); break;
    }
    GetCurrentPositionEx(g_dc, pCur);
    s = Measure(160, 60);
    SelectObject(g_dc, hold);
    DeleteObject(hpen);
    return s;
}

static void test_CurrentPosition(void)
{
    static const int pens[] = { P_COS1, P_W7, P_G7 };
    int pi, f;

    for (pi = 0; pi < 3; pi++)
    {
        for (f = 0; f < F_COUNT; f++)
        {
            POINT start, c0, c1;
            STAT a, b;
            int p = pens[pi];

            switch (f)
            {
                case F_POLYPOLYLINE: start = PP[0]; break;
                case F_POLYBEZIER:   start = PB[0]; break;
                default:             start = P3[0]; break;
            }
            /* current position far from the first point, and equal to it */
            a = DrawFunc(f, p, 15, 220, &c0);
            b = DrawFunc(f, p, start.x, start.y, &c1);
            ok(a.cnt > 0, "%s %s: something is drawn\n", g_PenName[p], g_FuncName[f]);
            switch (f)
            {
                case F_POLYLINETO:
                case F_POLYBEZIERTO:
                    /* they start at the current position and end at the last point */
                    ok(c0.x == c1.x && c0.y == c1.y, "%s %s: ends at (%ld,%ld) and (%ld,%ld)\n",
                       g_PenName[p], g_FuncName[f], c0.x, c0.y, c1.x, c1.y);
                    if (f == F_POLYLINETO)
                        ok(c0.x == 200 && c0.y == 120, "%s PolylineTo: ends at (%ld,%ld)\n", g_PenName[p], c0.x, c0.y);
                    else
                        ok(c0.x == 220 && c0.y == 140, "%s PolyBezierTo: ends at (%ld,%ld)\n", g_PenName[p], c0.x, c0.y);
                    ok(a.l <= 15 + 1 && a.b >= 220 - 1, "%s %s: starts at the current position, bbox %d,%d,%d,%d\n",
                       g_PenName[p], g_FuncName[f], a.l, a.t, a.r, a.b);
                    break;
                default:
                    /* Polyline, PolyPolyline, PolyBezier, Polygon neither use nor change it */
                    ok(a.hash == b.hash, "%s %s: the current position changes the picture\n", g_PenName[p], g_FuncName[f]);
                    ok(c0.x == 15 && c0.y == 220, "%s %s: moved the current position to (%ld,%ld)\n",
                       g_PenName[p], g_FuncName[f], c0.x, c0.y);
                    ok(c1.x == start.x && c1.y == start.y, "%s %s: moved the current position to (%ld,%ld)\n",
                       g_PenName[p], g_FuncName[f], c1.x, c1.y);
                    break;
            }
        }
    }

    /* PolyBezierTo draws the curve PolyBezier draws from the current position (the end point is the third point) */
    for (pi = 0; pi < 3; pi++)
    {
        POINT c0, c1;
        STAT a = DrawFunc(F_POLYBEZIER, pens[pi], 120, 60, &c0);
        STAT b = DrawFunc(F_POLYBEZIERTO, pens[pi], 120, 60, &c1);

        ok(a.hash == b.hash, "%s: PolyBezierTo does not draw the curve PolyBezier draws (bbox %d,%d,%d,%d and %d,%d,%d,%d)\n",
           g_PenName[pens[pi]], a.l, a.t, a.r, a.b, b.l, b.t, b.r, b.b);
    }
}

/* ---- the pen width under mapping modes and world transforms ---- */

enum { M_TEXT, M_LOENG, M_HIENG, M_ANISO, M_ANISOFLIP, M_WT2X3, M_WTROT, M_LOENGWT2, M_WT15, M_COUNT };
static const char *g_ModeName[M_COUNT] =
{ "MM_TEXT", "MM_LOENGLISH", "MM_HIENGLISH", "aniso 2x3", "aniso 2x-3", "world 2x3", "world rot 30", "MM_LOENGLISH + world 2", "world 1.5" };

/* thickness {across a horizontal line, across a vertical line} per pen */
static const int g_Expect[M_COUNT][P_COUNT][2] =
{
    { {1, 1}, {5, 5}, {5, 5}, {7, 7}, {7, 7}, {25, 25}, {25, 25}, {1, 1}, {1, 1} },
    { {1, 1}, {5, 5}, {5, 5}, {7, 7}, {7, 7}, {24, 24}, {24, 24}, {1, 1}, {1, 1} },
    { {1, 1}, {1, 1}, {1, 1}, {1, 1}, {1, 1}, {2, 2}, {2, 2}, {1, 1}, {1, 1} },
    { {3, 2}, {15, 10}, {15, 10}, {21, 14}, {21, 14}, {75, 50}, {75, 50}, {1, 1}, {1, 1} },
    { {3, 2}, {15, 10}, {15, 10}, {21, 14}, {21, 14}, {75, 50}, {75, 50}, {1, 1}, {1, 1} },
    { {3, 2}, {15, 10}, {15, 10}, {21, 14}, {21, 14}, {75, 50}, {75, 50}, {1, 1}, {1, 1} },
    { {1, 1}, {5, 5}, {5, 5}, {7, 7}, {7, 7}, {25, 25}, {25, 25}, {1, 1}, {1, 1} },
    { {2, 2}, {10, 10}, {10, 10}, {14, 14}, {14, 13}, {48, 48}, {48, 48}, {1, 1}, {1, 1} },
    { {2, 2}, {8, 8}, {8, 8}, {11, 11}, {11, 10}, {38, 38}, {38, 37}, {1, 1}, {1, 1} },
};

static void SetMode(int m)
{
    XFORM x = { 1, 0, 0, 1, 0, 0 };

    SetGraphicsMode(g_dc, GM_COMPATIBLE);
    SetMapMode(g_dc, MM_TEXT);
    ModifyWorldTransform(g_dc, NULL, MWT_IDENTITY);
    SetWindowOrgEx(g_dc, 0, 0, NULL);
    SetViewportOrgEx(g_dc, 0, 0, NULL);
    switch (m)
    {
        case M_LOENG: SetMapMode(g_dc, MM_LOENGLISH); break;
        case M_HIENG: SetMapMode(g_dc, MM_HIENGLISH); break;
        case M_ANISO:
            SetMapMode(g_dc, MM_ANISOTROPIC);
            SetWindowExtEx(g_dc, 100, 100, NULL);
            SetViewportExtEx(g_dc, 200, 300, NULL);
            break;
        case M_ANISOFLIP:
            SetMapMode(g_dc, MM_ANISOTROPIC);
            SetWindowExtEx(g_dc, 100, 100, NULL);
            SetViewportExtEx(g_dc, 200, -300, NULL);
            break;
        case M_WT2X3: x.eM11 = 2; x.eM22 = 3; SetGraphicsMode(g_dc, GM_ADVANCED); SetWorldTransform(g_dc, &x); break;
        case M_WTROT:
            x.eM11 = 0.8660254f; x.eM12 = 0.5f; x.eM21 = -0.5f; x.eM22 = 0.8660254f;
            SetGraphicsMode(g_dc, GM_ADVANCED);
            SetWorldTransform(g_dc, &x);
            break;
        case M_LOENGWT2:
            SetMapMode(g_dc, MM_LOENGLISH);
            x.eM11 = 2; x.eM22 = 2;
            SetGraphicsMode(g_dc, GM_ADVANCED);
            SetWorldTransform(g_dc, &x);
            break;
        case M_WT15: x.eM11 = 1.5f; x.eM22 = 1.5f; SetGraphicsMode(g_dc, GM_ADVANCED); SetWorldTransform(g_dc, &x); break;
    }
}

static void test_PenWidth(void)
{
    int m, p, dr, orient;

    for (m = 0; m < M_COUNT; m++)
    {
        for (p = 0; p < P_COUNT; p++)
        {
            for (dr = 0; dr < 2; dr++)
            {
                for (orient = 0; orient < 2; orient++)
                {
                    HPEN hpen = MakePen(p), hold;
                    POINT a, b;
                    STAT s;
                    int th, expect = g_Expect[m][p][orient];
                    /* half-integer device widths: Windows draws the pen types one pixel apart */
                    int tol = (m == M_LOENGWT2 || m == M_WT15) ? 1 : 0;
                    /* a rotated pen: the logical end points are rounded, one pixel of slack */
                    if (m == M_WTROT) tol = 1;

                    Clear();
                    hold = SelectObject(g_dc, hpen);
                    SetMode(m);
                    if (!orient) { a.x = 30; a.y = 128; b.x = 110; b.y = 128; }
                    else         { a.x = 128; a.y = 30; b.x = 128; b.y = 110; }
                    DPtoLP(g_dc, &a, 1);
                    DPtoLP(g_dc, &b, 1);
                    MoveToEx(g_dc, a.x, a.y, NULL);
                    if (!dr)
                        LineTo(g_dc, b.x, b.y);
                    else
                    {
                        POINT q[2];

                        q[0] = a;
                        q[1] = b;
                        Polyline(g_dc, q, 2);
                    }
                    s = Measure(70, 70);
                    th = orient ? s.row : s.col;
                    ok(th >= expect - tol && th <= expect + tol, "%s pen %s %s %c: thickness %d, expected %d (+-%d)\n",
                       g_ModeName[m], g_PenName[p], dr ? "Polyline" : "LineTo", orient ? 'V' : 'H', th, expect, tol);
                    SetMode(M_TEXT);
                    SelectObject(g_dc, hold);
                    DeleteObject(hpen);
                }
            }
        }
    }
}

/* ---- Arc, Ellipse, RoundRect, Rectangle, Polygon and stroked paths with a wide pen under odd page scales and world
 * transforms. The pen is in logical units and the extent on each device axis is rounded once after both transforms
 * (width 7 under 7/3 and a world scale of 1.5 is 25 pixels, width 25 is 88). Expected values measured on Windows 10
 * (build 19045): runs of pixels along row 128 from the left and right and along column 128 from the top and bottom,
 * a shape of 160 device pixels placed with DPtoLP. ---- */

enum { N_TEXT, N_LOENG, N_HIENG, N_ANISO, N_WT15, N_PG73WT15, N_PG73WT2, N_PG53WT2, N_PG135WT2, N_PG125WT2, N_COUNT };
/* a world rotation of 30 degrees: not in the table of lines (a rotated pen is as wide as it is) */
#define N_ROT30 N_COUNT
static const char *g_ModeNameN[N_COUNT] =
{ "MM_TEXT", "MM_LOENGLISH", "MM_HIENGLISH", "aniso 2x3", "world 1.5", "page 7/3 + world 1.5", "page 7/3 + world 2",
  "page 5/3 + world 2", "page 13/5 + world 2", "page 12/5 + world 2" };

/* thickness {across a horizontal line, across a vertical line} for w7, g7, w25 */
static const int g_ExpectLines[N_COUNT][3][2] =
{
    { {7, 7}, {7, 7}, {25, 25} },
    { {7, 7}, {7, 7}, {24, 24} },
    { {1, 1}, {1, 1}, {2, 2} },
    { {21, 14}, {21, 14}, {75, 50} },
    { {11, 11}, {11, 10}, {38, 38} },
    { {25, 25}, {25, 25}, {88, 88} },
    { {33, 33}, {33, 33}, {117, 117} },
    { {23, 23}, {23, 23}, {83, 83} },
    { {36, 36}, {36, 36}, {130, 130} },
    { {34, 34}, {34, 34}, {120, 120} },
};

static void SetModeN(int m)
{
    XFORM x = { 1, 0, 0, 1, 0, 0 };
    int ext = 0, vext = 0;

    /* back to the identity world transform (it can only be reset in the advanced graphics mode) */
    SetGraphicsMode(g_dc, GM_ADVANCED);
    ModifyWorldTransform(g_dc, NULL, MWT_IDENTITY);
    SetGraphicsMode(g_dc, GM_COMPATIBLE);
    SetMapMode(g_dc, MM_TEXT);
    SetWindowOrgEx(g_dc, 0, 0, NULL);
    SetViewportOrgEx(g_dc, 0, 0, NULL);
    switch (m)
    {
        case N_LOENG: SetMapMode(g_dc, MM_LOENGLISH); return;
        case N_HIENG: SetMapMode(g_dc, MM_HIENGLISH); return;
        case N_ANISO:
            SetMapMode(g_dc, MM_ANISOTROPIC);
            SetWindowExtEx(g_dc, 100, 100, NULL);
            SetViewportExtEx(g_dc, 200, 300, NULL);
            return;
        case N_WT15: x.eM11 = 1.5f; x.eM22 = 1.5f; break;
        case N_PG73WT15: ext = 3; vext = 7; x.eM11 = 1.5f; x.eM22 = 1.5f; break;
        case N_PG73WT2: ext = 3; vext = 7; x.eM11 = 2; x.eM22 = 2; break;
        case N_PG53WT2: ext = 3; vext = 5; x.eM11 = 2; x.eM22 = 2; break;
        case N_PG135WT2: ext = 5; vext = 13; x.eM11 = 2; x.eM22 = 2; break;
        case N_PG125WT2: ext = 5; vext = 12; x.eM11 = 2; x.eM22 = 2; break;
        case N_ROT30: x.eM11 = 0.8660254f; x.eM12 = 0.5f; x.eM21 = -0.5f; x.eM22 = 0.8660254f; break;
        default: return;
    }
    if (ext)
    {
        SetMapMode(g_dc, MM_ANISOTROPIC);
        SetWindowExtEx(g_dc, ext, ext, NULL);
        SetViewportExtEx(g_dc, vext, vext, NULL);
    }
    SetGraphicsMode(g_dc, GM_ADVANCED);
    SetWorldTransform(g_dc, &x);
}

static void test_PenWidthPageScales(void)
{
    static const int pens[3] = { P_W7, P_G7, P_W25 };
    int m, pi, orient;

    for (m = 0; m < N_COUNT; m++)
    {
        for (pi = 0; pi < 3; pi++)
        {
            for (orient = 0; orient < 2; orient++)
            {
                HPEN hpen = MakePen(pens[pi]), hold;
                POINT a, b;
                STAT s;
                int th, expect = g_ExpectLines[m][pi][orient];
                /* a pen of half-integer device width: Windows draws the pen types a pixel apart */
                int tol = (m == N_WT15) ? 1 : 0;

                Clear();
                hold = SelectObject(g_dc, hpen);
                SetModeN(m);
                if (!orient) { a.x = 30; a.y = 128; b.x = 110; b.y = 128; }
                else         { a.x = 128; a.y = 30; b.x = 128; b.y = 110; }
                DPtoLP(g_dc, &a, 1);
                DPtoLP(g_dc, &b, 1);
                MoveToEx(g_dc, a.x, a.y, NULL);
                LineTo(g_dc, b.x, b.y);
                s = Measure(70, 70);
                th = orient ? s.row : s.col;
                ok(th >= expect - tol && th <= expect + tol, "%s pen %s LineTo %c: thickness %d, expected %d (+-%d)\n",
                   g_ModeNameN[m], g_PenName[pens[pi]], orient ? 'V' : 'H', th, expect, tol);
                SetModeN(N_TEXT);
                SelectObject(g_dc, hold);
                DeleteObject(hpen);
            }
        }
    }
}

enum { S_ELLIPSE, S_ROUNDRECT, S_INSIDEFRAME, S_RECTANGLE, S_POLYGON, S_STROKEELL, S_STROKERECT, S_ARC, S_PIE, S_CHORD, S_COUNT };
static const char *g_ShapeName[S_COUNT] =
{ "Ellipse", "RoundRect", "InsideFrame Ellipse", "Rectangle", "Polygon", "StrokePath(Ellipse)", "StrokePath(Rectangle)", "Arc",
  "Pie", "Chord" };

static const struct { int mode, pen, shape, runs[4]; } g_Shapes[] =
{
    { N_TEXT, P_W7, S_ELLIPSE, { 7, 7, 7, 7 } },
    { N_TEXT, P_G7, S_ELLIPSE, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_ELLIPSE, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_ELLIPSE, { 7, 7, 7, 7 } },
    { N_LOENG, P_G7, S_ELLIPSE, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_ELLIPSE, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_ELLIPSE, { 1, 1, 1, 1 } },
    { N_HIENG, P_G7, S_ELLIPSE, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_ELLIPSE, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_ELLIPSE, { 14, 14, 21, 21 } },
    { N_ANISO, P_G7, S_ELLIPSE, { 14, 14, 21, 21 } },
    { N_WT15, P_W7, S_ELLIPSE, { 11, 11, 11, 11 } },
    /* Windows draws the sides of a geometric pen of 10.5 pixels 10 pixels wide; the stroke of the outline here is 11 pixels
       plus the pixel of the rounding of the outline at the sides */
    { N_WT15, P_G7, S_ELLIPSE, { -1, -1, 11, 11 } },
    { N_WT15, P_W25, S_ELLIPSE, { 38, 38, 38, 38 } },
    { N_PG73WT15, P_W7, S_ELLIPSE, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_G7, S_ELLIPSE, { 25, 25, 25, 25 } },
    { N_PG73WT2, P_W7, S_ELLIPSE, { 33, 33, 33, 33 } },
    { N_PG73WT2, P_G7, S_ELLIPSE, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_ELLIPSE, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_G7, S_ELLIPSE, { 23, 23, 23, 23 } },
    { N_PG135WT2, P_W7, S_ELLIPSE, { 36, 36, 36, 36 } },
    { N_PG135WT2, P_G7, S_ELLIPSE, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_ELLIPSE, { 34, 34, 34, 34 } },
    { N_PG125WT2, P_G7, S_ELLIPSE, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_ROUNDRECT, { 7, 7, 7, 7 } },
    { N_TEXT, P_G7, S_ROUNDRECT, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_ROUNDRECT, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_ROUNDRECT, { 7, 7, 7, 7 } },
    { N_LOENG, P_G7, S_ROUNDRECT, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_ROUNDRECT, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_ROUNDRECT, { 1, 1, 1, 1 } },
    { N_HIENG, P_G7, S_ROUNDRECT, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_ROUNDRECT, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_ROUNDRECT, { 14, 14, 21, 21 } },
    { N_ANISO, P_G7, S_ROUNDRECT, { 14, 14, 21, 21 } },
    { N_WT15, P_W7, S_ROUNDRECT, { 11, 11, 11, 11 } },
    { N_WT15, P_G7, S_ROUNDRECT, { 10, 10, 11, 11 } },
    { N_WT15, P_W25, S_ROUNDRECT, { 38, 38, 38, 38 } },
    { N_PG73WT15, P_W7, S_ROUNDRECT, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_G7, S_ROUNDRECT, { 25, 25, 25, 25 } },
    { N_PG73WT2, P_W7, S_ROUNDRECT, { 33, 33, 33, 33 } },
    { N_PG73WT2, P_G7, S_ROUNDRECT, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_ROUNDRECT, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_G7, S_ROUNDRECT, { 23, 23, 23, 23 } },
    { N_PG135WT2, P_W7, S_ROUNDRECT, { 36, 36, 36, 36 } },
    { N_PG135WT2, P_G7, S_ROUNDRECT, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_ROUNDRECT, { 34, 34, 34, 34 } },
    { N_PG125WT2, P_G7, S_ROUNDRECT, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_INSIDEFRAME, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_INSIDEFRAME, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_INSIDEFRAME, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_INSIDEFRAME, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_INSIDEFRAME, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_INSIDEFRAME, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_INSIDEFRAME, { 14, 14, 21, 21 } },
    { N_WT15, P_W7, S_INSIDEFRAME, { 11, 11, 11, 11 } },
    { N_WT15, P_W25, S_INSIDEFRAME, { 38, 38, 38, 38 } },
    { N_PG73WT15, P_W7, S_INSIDEFRAME, { 25, 25, 25, 25 } },
    { N_PG73WT2, P_W7, S_INSIDEFRAME, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_INSIDEFRAME, { 23, 23, 23, 23 } },
    { N_PG135WT2, P_W7, S_INSIDEFRAME, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_INSIDEFRAME, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_RECTANGLE, { 7, 7, 7, 7 } },
    { N_TEXT, P_G7, S_RECTANGLE, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_RECTANGLE, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_RECTANGLE, { 7, 7, 7, 7 } },
    { N_LOENG, P_G7, S_RECTANGLE, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_RECTANGLE, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_RECTANGLE, { 1, 1, 1, 1 } },
    { N_HIENG, P_G7, S_RECTANGLE, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_RECTANGLE, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_RECTANGLE, { 14, 14, 21, 21 } },
    { N_ANISO, P_G7, S_RECTANGLE, { 14, 14, 21, 21 } },
    { N_ANISO, P_W25, S_RECTANGLE, { 50, 50, 75, 75 } },
    { N_WT15, P_W7, S_RECTANGLE, { 10, 10, 11, 11 } },
    { N_WT15, P_G7, S_RECTANGLE, { 10, 10, 11, 11 } },
    { N_WT15, P_W25, S_RECTANGLE, { 37, 37, 38, 38 } },
    { N_PG73WT15, P_W7, S_RECTANGLE, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_G7, S_RECTANGLE, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_W25, S_RECTANGLE, { 87, 87, 88, 88 } },
    { N_PG73WT2, P_W7, S_RECTANGLE, { 33, 33, 33, 33 } },
    { N_PG73WT2, P_G7, S_RECTANGLE, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_RECTANGLE, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_G7, S_RECTANGLE, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_W25, S_RECTANGLE, { 83, 83, 83, 83 } },
    { N_PG135WT2, P_W7, S_RECTANGLE, { 36, 36, 36, 36 } },
    { N_PG135WT2, P_G7, S_RECTANGLE, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_RECTANGLE, { 34, 34, 34, 34 } },
    { N_PG125WT2, P_G7, S_RECTANGLE, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_POLYGON, { 7, 7, 7, 7 } },
    { N_TEXT, P_G7, S_POLYGON, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_POLYGON, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_POLYGON, { 7, 7, 7, 7 } },
    { N_LOENG, P_G7, S_POLYGON, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_POLYGON, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_POLYGON, { 1, 1, 1, 1 } },
    { N_HIENG, P_G7, S_POLYGON, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_POLYGON, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_POLYGON, { 14, 14, 21, 21 } },
    { N_ANISO, P_G7, S_POLYGON, { 14, 14, 21, 21 } },
    { N_ANISO, P_W25, S_POLYGON, { 50, 50, 75, 75 } },
    { N_WT15, P_W7, S_POLYGON, { 11, 11, 11, 11 } },
    { N_WT15, P_G7, S_POLYGON, { 10, 10, 11, 11 } },
    { N_WT15, P_W25, S_POLYGON, { 38, 38, 38, 38 } },
    { N_PG73WT15, P_W7, S_POLYGON, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_G7, S_POLYGON, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_W25, S_POLYGON, { 88, 88, 88, 88 } },
    { N_PG73WT2, P_W7, S_POLYGON, { 33, 33, 33, 33 } },
    { N_PG73WT2, P_G7, S_POLYGON, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_POLYGON, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_G7, S_POLYGON, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_W25, S_POLYGON, { 83, 83, 83, 83 } },
    { N_PG135WT2, P_W7, S_POLYGON, { 36, 36, 36, 36 } },
    { N_PG135WT2, P_G7, S_POLYGON, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_POLYGON, { 34, 34, 34, 34 } },
    { N_PG125WT2, P_G7, S_POLYGON, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_STROKEELL, { 7, 7, 7, 7 } },
    { N_TEXT, P_G7, S_STROKEELL, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_STROKEELL, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_STROKEELL, { 7, 7, 7, 7 } },
    { N_LOENG, P_G7, S_STROKEELL, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_STROKEELL, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_STROKEELL, { 1, 1, 1, 1 } },
    { N_HIENG, P_G7, S_STROKEELL, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_STROKEELL, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_STROKEELL, { 14, 14, 21, 21 } },
    { N_ANISO, P_G7, S_STROKEELL, { 14, 14, 21, 21 } },
    { N_ANISO, P_W25, S_STROKEELL, { 50, 50, 75, 75 } },
    { N_WT15, P_W7, S_STROKEELL, { 11, 11, 11, 11 } },
    { N_WT15, P_W25, S_STROKEELL, { 38, 38, 38, 38 } },
    { N_PG73WT15, P_W7, S_STROKEELL, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_G7, S_STROKEELL, { 25, 25, 25, 25 } },
    { N_PG73WT2, P_W7, S_STROKEELL, { 33, 33, 33, 33 } },
    { N_PG73WT2, P_G7, S_STROKEELL, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_STROKEELL, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_G7, S_STROKEELL, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_W25, S_STROKEELL, { 83, 83, 83, 83 } },
    { N_PG135WT2, P_W7, S_STROKEELL, { 36, 36, 36, 36 } },
    { N_PG135WT2, P_G7, S_STROKEELL, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_STROKEELL, { 34, 34, 34, 34 } },
    { N_PG125WT2, P_G7, S_STROKEELL, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_STROKERECT, { 7, 7, 7, 7 } },
    { N_TEXT, P_G7, S_STROKERECT, { 7, 7, 7, 7 } },
    { N_TEXT, P_W25, S_STROKERECT, { 25, 25, 25, 25 } },
    { N_LOENG, P_W7, S_STROKERECT, { 7, 7, 7, 7 } },
    { N_LOENG, P_G7, S_STROKERECT, { 7, 7, 7, 7 } },
    { N_LOENG, P_W25, S_STROKERECT, { 24, 24, 24, 24 } },
    { N_HIENG, P_W7, S_STROKERECT, { 1, 1, 1, 1 } },
    { N_HIENG, P_G7, S_STROKERECT, { 1, 1, 1, 1 } },
    { N_HIENG, P_W25, S_STROKERECT, { 2, 2, 2, 2 } },
    { N_ANISO, P_W7, S_STROKERECT, { 14, 14, 21, 21 } },
    { N_ANISO, P_G7, S_STROKERECT, { 14, 14, 21, 21 } },
    { N_ANISO, P_W25, S_STROKERECT, { 50, 50, 75, 75 } },
    { N_WT15, P_W7, S_STROKERECT, { 11, 11, 11, 11 } },
    { N_WT15, P_G7, S_STROKERECT, { 10, 10, 11, 11 } },
    { N_WT15, P_W25, S_STROKERECT, { 38, 38, 38, 38 } },
    { N_PG73WT15, P_W7, S_STROKERECT, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_G7, S_STROKERECT, { 25, 25, 25, 25 } },
    { N_PG73WT15, P_W25, S_STROKERECT, { 88, 88, 88, 88 } },
    { N_PG73WT2, P_W7, S_STROKERECT, { 33, 33, 33, 33 } },
    { N_PG73WT2, P_G7, S_STROKERECT, { 33, 33, 33, 33 } },
    { N_PG53WT2, P_W7, S_STROKERECT, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_G7, S_STROKERECT, { 23, 23, 23, 23 } },
    { N_PG53WT2, P_W25, S_STROKERECT, { 83, 83, 83, 83 } },
    { N_PG135WT2, P_W7, S_STROKERECT, { 36, 36, 36, 36 } },
    { N_PG135WT2, P_G7, S_STROKERECT, { 36, 36, 36, 36 } },
    { N_PG125WT2, P_W7, S_STROKERECT, { 34, 34, 34, 34 } },
    { N_PG125WT2, P_G7, S_STROKERECT, { 34, 34, 34, 34 } },
    { N_TEXT, P_W7, S_ARC, { -1, -1, 7, 7 } },
    { N_TEXT, P_G7, S_ARC, { -1, -1, 7, 7 } },
    { N_TEXT, P_W25, S_ARC, { -1, -1, 25, 25 } },
    { N_LOENG, P_W7, S_ARC, { -1, -1, 7, 7 } },
    { N_LOENG, P_G7, S_ARC, { -1, -1, 7, 7 } },
    { N_LOENG, P_W25, S_ARC, { -1, -1, 24, 24 } },
    { N_HIENG, P_W7, S_ARC, { -1, -1, 1, 1 } },
    { N_HIENG, P_G7, S_ARC, { -1, -1, 1, 1 } },
    { N_HIENG, P_W25, S_ARC, { -1, -1, 2, 2 } },
    { N_ANISO, P_W7, S_ARC, { -1, -1, 21, 21 } },
    { N_ANISO, P_G7, S_ARC, { -1, -1, 21, 21 } },
    { N_WT15, P_W7, S_ARC, { -1, -1, 11, 11 } },
    { N_WT15, P_G7, S_ARC, { -1, -1, 11, 11 } },
    { N_WT15, P_W25, S_ARC, { -1, -1, 38, 38 } },
    { N_PG73WT15, P_W7, S_ARC, { -1, -1, 25, 25 } },
    { N_PG73WT2, P_W7, S_ARC, { -1, -1, 33, 33 } },
    { N_PG73WT2, P_G7, S_ARC, { -1, -1, 33, 33 } },
    { N_PG53WT2, P_W7, S_ARC, { -1, -1, 23, 23 } },
    { N_PG53WT2, P_G7, S_ARC, { -1, -1, 23, 23 } },
};

/* the runs of pixels along row 128 (from the left, from the right) and column 128 (from the top, from the bottom) */
static void Runs(int *rl, int *rr, int *rt, int *rb)
{
    int x, y;

    GdiFlush();
    *rl = *rr = *rt = *rb = 0;
    for (x = 0; x < DIMS && (g_bits[128 * DIMS + x] & 0xFFFFFF) == 0xFFFFFF; x++);
    for (; x < DIMS && (g_bits[128 * DIMS + x] & 0xFFFFFF) != 0xFFFFFF; x++) (*rl)++;
    for (x = DIMS - 1; x >= 0 && (g_bits[128 * DIMS + x] & 0xFFFFFF) == 0xFFFFFF; x--);
    for (; x >= 0 && (g_bits[128 * DIMS + x] & 0xFFFFFF) != 0xFFFFFF; x--) (*rr)++;
    for (y = 0; y < DIMS && (g_bits[y * DIMS + 128] & 0xFFFFFF) == 0xFFFFFF; y++);
    for (; y < DIMS && (g_bits[y * DIMS + 128] & 0xFFFFFF) != 0xFFFFFF; y++) (*rt)++;
    for (y = DIMS - 1; y >= 0 && (g_bits[y * DIMS + 128] & 0xFFFFFF) == 0xFFFFFF; y--);
    for (; y >= 0 && (g_bits[y * DIMS + 128] & 0xFFFFFF) != 0xFFFFFF; y--) (*rb)++;
}

static void DrawShape(int shape, int pen)
{
    POINT r[2], st, en, q[4];

    r[0].x = 48; r[0].y = 48; r[1].x = 208; r[1].y = 208;
    st.x = 208; st.y = 128; en.x = 128; en.y = 48;
    q[0].x = 48; q[0].y = 48; q[1].x = 208; q[1].y = 48; q[2].x = 208; q[2].y = 208; q[3].x = 48; q[3].y = 208;
    DPtoLP(g_dc, r, 2);
    DPtoLP(g_dc, &st, 1);
    DPtoLP(g_dc, &en, 1);
    DPtoLP(g_dc, q, 4);
    switch (shape)
    {
        case S_ELLIPSE: Ellipse(g_dc, r[0].x, r[0].y, r[1].x, r[1].y); break;
        case S_ROUNDRECT: RoundRect(g_dc, r[0].x, r[0].y, r[1].x, r[1].y, 40, 40); break;
        case S_INSIDEFRAME:
        {
            LOGBRUSH lb = { BS_SOLID, 0, 0 };
            HPEN hip = ExtCreatePen(PS_GEOMETRIC | PS_INSIDEFRAME, pen == P_W25 ? 25 : 7, &lb, 0, NULL), hold;

            hold = SelectObject(g_dc, hip);
            Ellipse(g_dc, r[0].x, r[0].y, r[1].x, r[1].y);
            SelectObject(g_dc, hold);
            DeleteObject(hip);
            break;
        }
        case S_RECTANGLE: Rectangle(g_dc, r[0].x, r[0].y, r[1].x, r[1].y); break;
        case S_POLYGON: Polygon(g_dc, q, 4); break;
        case S_STROKEELL:
            BeginPath(g_dc); Ellipse(g_dc, r[0].x, r[0].y, r[1].x, r[1].y); EndPath(g_dc); StrokePath(g_dc);
            break;
        case S_STROKERECT:
            BeginPath(g_dc); Rectangle(g_dc, r[0].x, r[0].y, r[1].x, r[1].y); EndPath(g_dc); StrokePath(g_dc);
            break;
        case S_ARC: Arc(g_dc, r[0].x, r[0].y, r[1].x, r[1].y, st.x, st.y, en.x, en.y); break;
        case S_PIE: Pie(g_dc, r[0].x, r[0].y, r[1].x, r[1].y, st.x, st.y, en.x, en.y); break;
        case S_CHORD: Chord(g_dc, r[0].x, r[0].y, r[1].x, r[1].y, st.x, st.y, en.x, en.y); break;
    }
}

static void test_ShapeWidths(void)
{
    int i;

    for (i = 0; i < (int)ARRAYSIZE(g_Shapes); i++)
    {
        HPEN hpen = MakePen(g_Shapes[i].pen), hold;
        HBRUSH hbr, hbrOld;
        int run[4], k, tol;

        Clear();
        hold = SelectObject(g_dc, hpen);
        hbr = GetStockObject(NULL_BRUSH);
        hbrOld = SelectObject(g_dc, hbr);
        SetModeN(g_Shapes[i].mode);
        DrawShape(g_Shapes[i].shape, g_Shapes[i].pen);
        Runs(&run[0], &run[1], &run[2], &run[3]);
        /* the pen types differ by a pixel where the device width is half an integer, and the outline of a curve by a
           pixel at the sides */
        tol = 1;
        for (k = 0; k < 4; k++)
        {
            int expect = g_Shapes[i].runs[k];

            if (expect < 0)
                continue;
            ok(run[k] >= expect - tol && run[k] <= expect + tol, "%s pen %s %s: run %d is %d, expected %d (+-%d)\n",
               g_ModeNameN[g_Shapes[i].mode], g_PenName[g_Shapes[i].pen], g_ShapeName[g_Shapes[i].shape], k, run[k], expect, tol);
        }
        SetModeN(N_TEXT);
        SelectObject(g_dc, hbrOld);
        SelectObject(g_dc, hold);
        DeleteObject(hpen);
    }
}


/* ---- Where the wide pen lies: it is centred on the outline (Ellipse(48, 48, 208, 208) with width 7 covers the pixels
 * 45 to 210, with width 25 the pixels 36 to 219), the radial and chord edges of Pie and Chord are drawn with the wide pen, a
 * rotated world transform rotates the shape. Measured on Windows 10 (build 19045): the box of the pixels and the runs
 * (row 128 from the left and right, column 128 from the top and bottom) of a shape of 160 device pixels placed with
 * DPtoLP, NULL brush, in the same DIB. The box of the coordinates the shape is made of is one or two pixels apart where
 * the conversions between logical and device points round differently, hence the tolerance. ---- */

static const struct { int mode, pen, shape, bbox[4], runs[4], tol; } g_Placement[] =
{
    { N_TEXT, P_W7, S_ELLIPSE, { 45, 45, 210, 210 }, { 7, 7, 7, 7 }, 2 },
    { N_TEXT, P_W7, S_ROUNDRECT, { 45, 45, 210, 210 }, { 7, 7, 7, 7 }, 2 },
    { N_TEXT, P_W7, S_PIE, { 124, 45, 210, 130 }, { 86, 86, 86, 86 }, 2 },
    { N_TEXT, P_W7, S_CHORD, { 124, 45, 210, 130 }, { 8, 8, 9, 9 }, 2 },
    { N_TEXT, P_W25, S_ELLIPSE, { 36, 36, 219, 219 }, { 25, 25, 25, 25 }, 2 },
    { N_TEXT, P_W25, S_ROUNDRECT, { 36, 36, 219, 219 }, { 25, 25, 25, 25 }, 2 },
    { N_TEXT, P_W25, S_PIE, { 115, 36, 219, 139 }, { 104, 104, 104, 104 }, 2 },
    { N_TEXT, P_W25, S_CHORD, { 115, 36, 219, 139 }, { 30, 30, 31, 31 }, 2 },
    { N_TEXT, P_G7, S_ELLIPSE, { 45, 45, 210, 210 }, { 7, 7, 7, 7 }, 2 },
    { N_TEXT, P_G7, S_ROUNDRECT, { 45, 45, 210, 210 }, { 7, 7, 7, 7 }, 2 },
    { N_TEXT, P_G7, S_PIE, { 124, 45, 210, 130 }, { 85, 85, 86, 86 }, 2 },
    { N_TEXT, P_G7, S_CHORD, { 126, 45, 210, 129 }, { 7, 7, 9, 9 }, 2 },
    { N_ANISO, P_W7, S_ELLIPSE, { 41, 38, 213, 216 }, { 14, 14, 21, 21 }, 2 },
    { N_ANISO, P_W7, S_ROUNDRECT, { 41, 38, 213, 216 }, { 14, 14, 21, 21 }, 2 },
    { N_ANISO, P_W25, S_ELLIPSE, { 23, 11, 231, 243 }, { 50, 50, 75, 75 }, 2 },
    { N_ANISO, P_W25, S_ROUNDRECT, { 23, 11, 231, 243 }, { 50, 50, 75, 75 }, 2 },
    { N_ANISO, P_G7, S_ELLIPSE, { 41, 38, 213, 216 }, { 14, 14, 21, 21 }, 2 },
    { N_ANISO, P_G7, S_ROUNDRECT, { 41, 38, 213, 216 }, { 14, 14, 21, 21 }, 2 },
    { N_WT15, P_W7, S_ELLIPSE, { 43, 43, 213, 213 }, { 11, 11, 11, 11 }, 2 },
    { N_WT15, P_W7, S_ROUNDRECT, { 43, 43, 213, 213 }, { 11, 11, 11, 11 }, 2 },
    { N_WT15, P_W7, S_PIE, { 122, 43, 213, 133 }, { 91, 91, 91, 91 }, 2 },
    { N_WT15, P_W25, S_ELLIPSE, { 30, 30, 227, 227 }, { 38, 38, 38, 38 }, 2 },
    { N_WT15, P_W25, S_ROUNDRECT, { 29, 29, 227, 227 }, { 38, 38, 38, 38 }, 2 },
    { N_WT15, P_G7, S_ROUNDRECT, { 43, 43, 213, 213 }, { 10, 10, 11, 11 }, 2 },
    { N_ROT30, P_W7, S_ROUNDRECT, { 24, 53, 232, 203 }, { 14, 14, 8, 8 }, 2 },
    { N_ROT30, P_G7, S_ROUNDRECT, { 24, 53, 232, 203 }, { 14, 14, 8, 8 }, 2 },
    { N_ROT30, P_G7, S_PIE, { 125, 93, 182, 131 }, { 57, 57, 39, 39 }, 2 },
    /* a pen wider than half the shape fills it like Windows: a ring around the outline, not a disc; the box of the
       logical points differs by a few pixels here (page scale 7/3 is rounded at each conversion) */
    { N_PG73WT15, P_W25, S_ELLIPSE, { 6, 6, 250, 250 }, { 88, 88, 88, 88 }, 5 },
    { N_PG73WT2, P_W25, S_ELLIPSE, { 0, 0, 255, 255 }, { 106, 104, 106, 104 }, 6 },
};

static const char *PlacementModeName(int m)
{
    return m == N_ROT30 ? "world rotation 30" : g_ModeNameN[m];
}

static void test_ShapePlacement(void)
{
    int i;

    for (i = 0; i < (int)ARRAYSIZE(g_Placement); i++)
    {
        HPEN hpen = MakePen(g_Placement[i].pen), hold;
        HBRUSH hbrOld;
        STAT s;
        int run[4], k, tol = g_Placement[i].tol;
        int box[4];

        Clear();
        hold = SelectObject(g_dc, hpen);
        hbrOld = SelectObject(g_dc, GetStockObject(NULL_BRUSH));
        SetModeN(g_Placement[i].mode);
        DrawShape(g_Placement[i].shape, g_Placement[i].pen);
        s = Measure(128, 128);
        Runs(&run[0], &run[1], &run[2], &run[3]);
        box[0] = s.l; box[1] = s.t; box[2] = s.r; box[3] = s.b;
        for (k = 0; k < 4; k++)
        {
            ok(abs(box[k] - g_Placement[i].bbox[k]) <= tol, "%s pen %s %s: pixel box %d,%d,%d,%d, expected %d,%d,%d,%d (+-%d)\n",
               PlacementModeName(g_Placement[i].mode), g_PenName[g_Placement[i].pen], g_ShapeName[g_Placement[i].shape],
               box[0], box[1], box[2], box[3], g_Placement[i].bbox[0], g_Placement[i].bbox[1], g_Placement[i].bbox[2],
               g_Placement[i].bbox[3], tol);
            /* the radial edges of a pie and the edge of a chord: the end of the line is rounded one pixel more in the 32-bit
               build */
            ok(abs(run[k] - g_Placement[i].runs[k]) <= (tol > 2 ? tol : (g_Placement[i].shape == S_PIE || g_Placement[i].shape == S_CHORD) ? 2 : 1), "%s pen %s %s: run %d is %d, expected %d\n",
               PlacementModeName(g_Placement[i].mode), g_PenName[g_Placement[i].pen], g_ShapeName[g_Placement[i].shape],
               k, run[k], g_Placement[i].runs[k]);
        }
        SetModeN(N_TEXT);
        SelectObject(g_dc, hbrOld);
        SelectObject(g_dc, hold);
        DeleteObject(hpen);
    }
}

/* Whether the pixels written to a window of the test can be read back (a window of its own: the DC of the test below has
   to meet its first drawing call fresh, the clip box is computed by it) */
static BOOL WindowReadable(void)
{
    HWND hwnd;
    HDC hdc;
    HPEN hpen, hpenOld;
    BOOL ret;

    hwnd = CreateWindowExW(0, L"STATIC", NULL, WS_POPUP | WS_VISIBLE, 96, 96, 200, 200, NULL, NULL, NULL, NULL);
    if (!hwnd)
        return FALSE;
    hdc = GetDC(hwnd);
    if (!hdc)
    {
        DestroyWindow(hwnd);
        return FALSE;
    }
    PatBlt(hdc, 0, 0, 200, 200, WHITENESS);
    hpen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    hpenOld = SelectObject(hdc, hpen);
    MoveToEx(hdc, 120, 150, NULL);
    LineTo(hdc, 190, 150);
    ret = GetPixel(hdc, 150, 150) == RGB(0, 0, 0);
    SelectObject(hdc, hpenOld);
    DeleteObject(hpen);
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
    return ret;
}

/* The shape is drawn in a window DC whose origin is not the origin of the screen, at the right and bottom of the client
   area. The clip box of such a DC is the client area in DC coordinates: the stroked outline must be tested against that,
   not against the box moved by the origin (the shapes of the strip beyond it were not drawn). */
static void test_WindowDC(void)
{
    static const struct { int shape; const char *name; } sh[] = { { 0, "Ellipse" }, { 1, "RoundRect" }, { 2, "Rectangle" } };
    LOGBRUSH lb = { BS_SOLID, RGB(0, 0, 0), 0 };
    int i;

    if (!WindowReadable())
    {
        skip("window pixels cannot be read back\n");
        return;
    }

    for (i = 0; i < 5; i++)
    {
        HWND hwnd;
        HDC hdc;
        HPEN hpen, hpenOld;

        /* a new window and DC for every shape: the first call that draws decides */
        hwnd = CreateWindowExW(0, L"STATIC", NULL, WS_POPUP | WS_VISIBLE, 96, 96, 200, 200, NULL, NULL, NULL, NULL);
        hdc = hwnd ? GetDC(hwnd) : NULL;
        if (!hdc)
        {
            skip("no window DC\n");
            if (hwnd)
                DestroyWindow(hwnd);
            return;
        }
        PatBlt(hdc, 0, 0, 200, 200, WHITENESS);
        hpen = ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | PS_JOIN_MITER, 7, &lb, 0, NULL);
        hpenOld = SelectObject(hdc, hpen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        if (i < 3)
        {
            /* the left edge of the shape lies at x = 110 (the DC origin is 96: the strip is beyond x = 104) */
            switch (sh[i].shape)
            {
                case 0: Ellipse(hdc, 110, 110, 190, 190); break;
                case 1: RoundRect(hdc, 110, 110, 190, 190, 20, 20); break;
                default: Rectangle(hdc, 110, 110, 190, 190); break;
            }
            ok(GetPixel(hdc, 110, 150) == RGB(0, 0, 0), "%s with a wide pen: the left edge is not drawn in a window DC\n", sh[i].name);
            ok(GetPixel(hdc, 150, 190) == RGB(0, 0, 0), "%s with a wide pen: the bottom edge is not drawn in a window DC\n", sh[i].name);
        }
        else if (i == 3)
        {
            BeginPath(hdc);
            MoveToEx(hdc, 110, 110, NULL);
            LineTo(hdc, 190, 110);
            LineTo(hdc, 190, 190);
            LineTo(hdc, 110, 190);
            CloseFigure(hdc);
            EndPath(hdc);
            StrokePath(hdc);
            ok(GetPixel(hdc, 190, 150) == RGB(0, 0, 0), "StrokePath with a wide pen: the right edge is not drawn in a window DC\n");
        }
        else
        {
            SelectObject(hdc, GetStockObject(BLACK_BRUSH));
            BeginPath(hdc);
            Rectangle(hdc, 110, 110, 190, 190);
            EndPath(hdc);
            FillPath(hdc);
            ok(GetPixel(hdc, 150, 150) == RGB(0, 0, 0), "FillPath is not drawn in the strip of a window DC\n");
        }
        SelectObject(hdc, hpenOld);
        DeleteObject(hpen);
        ReleaseDC(hwnd, hdc);
        DestroyWindow(hwnd);
    }
}

START_TEST(WidePen)
{
    BITMAPINFO bi;

    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = DIMS;
    bi.bmiHeader.biHeight = -DIMS;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    g_dc = CreateCompatibleDC(NULL);
    g_bmp = CreateDIBSection(g_dc, &bi, DIB_RGB_COLORS, (void **)&g_bits, NULL, 0);
    if (!g_dc || !g_bmp || !g_bits)
    {
        skip("no DIB\n");
        return;
    }
    g_bmpOld = SelectObject(g_dc, g_bmp);

    test_CurrentPosition();
    test_PenWidth();
    test_PenWidthPageScales();
    test_ShapeWidths();
    test_ShapePlacement();
    test_WindowDC();

    SelectObject(g_dc, g_bmpOld);
    DeleteObject(g_bmp);
    DeleteDC(g_dc);
}
