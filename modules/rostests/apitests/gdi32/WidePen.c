/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Wide pens: Polyline, PolyPolyline and PolyBezier neither use nor change the current position,
 *              PolylineTo and PolyBezierTo start at it and end at the last point; the width of a pen is in logical
 *              units and the mapping mode and the world transform scale it
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

    SelectObject(g_dc, g_bmpOld);
    DeleteObject(g_bmp);
    DeleteDC(g_dc);
}
