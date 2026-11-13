/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The same GDI call draws the same pixels into a window DC and into a memory DC: Arc, Pie and Chord
 *              (hatch brushes, negative coordinates, rotation) and dashed lines at 45 degrees
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Each case is drawn into a DIB section through a memory DC and into a popup window and a child window (their DC
 * origins on the screen are not multiples of 8 and differ in x - y) through the window DCs; the window picture is read
 * back with BitBlt. The pictures must be equal; the reference must not be blank.
 */

#include "precomp.h"

#include <math.h>

#define CW 200
#define CH 150

typedef void (*DRAWFN)(HDC hdc);

typedef struct
{
    const char *name;
    DRAWFN draw;
    int minPixels;
} CASE;

static void Rotate(HDC hdc, int deg, int dx, int dy, double s)
{
    XFORM xf;
    double a = deg * 3.14159265358979 / 180.0;

    SetGraphicsMode(hdc, GM_ADVANCED);
    xf.eM11 = (FLOAT)(s * cos(a));
    xf.eM12 = (FLOAT)(s * sin(a));
    xf.eM21 = (FLOAT)(-s * sin(a));
    xf.eM22 = (FLOAT)(s * cos(a));
    xf.eDx = (FLOAT)dx;
    xf.eDy = (FLOAT)dy;
    SetWorldTransform(hdc, &xf);
}

static void Select(HDC hdc, HBRUSH hbr, HPEN hpen)
{
    SelectObject(hdc, hbr);
    SelectObject(hdc, hpen);
}

/* Hatch brushes: the pattern is aligned to the DC origin, so it is the same in any DC */
static void Draw_PieHatch(HDC hdc)
{
    Select(hdc, CreateHatchBrush(HS_DIAGCROSS, RGB(200, 0, 0)), CreatePen(PS_SOLID, 1, RGB(0, 0, 0)));
    Pie(hdc, 10, 10, 150, 110, 150, 60, 80, 10);
}

static void Draw_ChordHatch(HDC hdc)
{
    Select(hdc, CreateHatchBrush(HS_CROSS, RGB(0, 120, 0)), CreatePen(PS_SOLID, 3, RGB(0, 0, 200)));
    Chord(hdc, 20, 5, 170, 120, 170, 40, 30, 100);
}

static void Draw_PieHatchVP(HDC hdc)
{
    SetViewportOrgEx(hdc, 17, -9, NULL);
    Select(hdc, CreateHatchBrush(HS_BDIAGONAL, RGB(0, 0, 0)), CreatePen(PS_NULL, 0, 0));
    Pie(hdc, 0, 20, 120, 130, 120, 70, 60, 20);
}

/* Negative device coordinates (odd sums of the bounds): the centre is rounded the same way in any DC */
static void Draw_PieNeg(HDC hdc)
{
    Select(hdc, CreateSolidBrush(RGB(220, 120, 20)), CreatePen(PS_SOLID, 2, RGB(0, 0, 0)));
    Pie(hdc, -41, -33, 99, 77, 99, 20, -10, 60);
}

static void Draw_ChordNeg(HDC hdc)
{
    Select(hdc, CreateSolidBrush(RGB(20, 120, 220)), CreatePen(PS_SOLID, 1, RGB(0, 0, 0)));
    Chord(hdc, -57, -23, 91, 85, -30, 90, 80, -10);
}

static void Draw_ArcNeg(HDC hdc)
{
    Select(hdc, GetStockObject(NULL_BRUSH), CreatePen(PS_SOLID, 4, RGB(150, 0, 150)));
    Arc(hdc, -37, -35, 103, 75, 103, 20, -5, 74);
}

static void Draw_ArcViewport(HDC hdc)
{
    SetViewportOrgEx(hdc, -45, -31, NULL);
    Select(hdc, GetStockObject(NULL_BRUSH), CreatePen(PS_SOLID, 3, RGB(0, 0, 0)));
    Arc(hdc, 11, 3, 151, 113, 151, 60, 70, 3);
}

static void Draw_EllipseNeg(HDC hdc)
{
    Select(hdc, CreateHatchBrush(HS_VERTICAL, RGB(120, 0, 120)), CreatePen(PS_SOLID, 1, RGB(0, 0, 0)));
    Ellipse(hdc, -41, -33, 98, 77);
}

static void Draw_EllipseNegSolid(HDC hdc)
{
    Select(hdc, CreateSolidBrush(RGB(230, 200, 20)), CreatePen(PS_SOLID, 1, RGB(0, 0, 0)));
    Ellipse(hdc, -57, -25, 38, 66);
    Ellipse(hdc, -13, 40, 56, 109);
}

/* A world transform with a rotation turns the bounds: the arc is computed on what the transform makes of them */
static void Draw_ArcRot(HDC hdc)
{
    Rotate(hdc, 188, 160, 61, 1.0);
    Select(hdc, GetStockObject(NULL_BRUSH), CreatePen(PS_SOLID, 9, RGB(0, 100, 200)));
    Arc(hdc, 10, 10, 130, 90, 130, 50, 40, 10);
}

static void Draw_PieRot(HDC hdc)
{
    Rotate(hdc, 226, 120, 90, 1.2);
    Select(hdc, CreateHatchBrush(HS_DIAGCROSS, RGB(0, 80, 0)), CreatePen(PS_INSIDEFRAME, 5, RGB(200, 0, 0)));
    Pie(hdc, 10, 10, 100, 70, 100, 40, 20, 10);
}

static void Draw_ChordRot(HDC hdc)
{
    Rotate(hdc, 287, 70, 70, 1.2);
    Select(hdc, CreateSolidBrush(RGB(10, 200, 10)), GetStockObject(BLACK_PEN));
    Chord(hdc, 10, 10, 110, 80, 110, 20, 10, 60);
}

/* A dashed line at 45 degrees: the dashes start at its first point wherever it lies */
static void Draw_Dash45(HDC hdc)
{
    HPEN pen = CreatePen(PS_DASH, 1, RGB(0, 0, 0));

    SelectObject(hdc, pen);
    MoveToEx(hdc, 10, 30, NULL);
    LineTo(hdc, 100, 120);
    MoveToEx(hdc, 170, 10, NULL);
    LineTo(hdc, 70, 110);
    MoveToEx(hdc, 120, 120, NULL);
    LineTo(hdc, 160, 80);
    MoveToEx(hdc, 100, 10, NULL);
    LineTo(hdc, 140, 50);
}

static void Draw_DotPolygon45(HDC hdc)
{
    POINT pt[4] = { { 20, 60 }, { 80, 0 }, { 140, 60 }, { 80, 120 } };

    SelectObject(hdc, CreatePen(PS_DOT, 1, RGB(0, 0, 0)));
    SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Polygon(hdc, pt, 4);
}

/* A thin rotated rectangle with a dashed pen: its long sides run at about 45 degrees, in the pixels of a 45 degree line */
static void Draw_DashRotRect(HDC hdc)
{
    Rotate(hdc, 316, 162, 142, 0.8);
    Select(hdc, CreateSolidBrush(RGB(30, 220, 70)), CreatePen(PS_DASH, 1, RGB(0, 0, 0)));
    Rectangle(hdc, -28, -50, -30, -87);
}

static const CASE g_Cases[] =
{
    { "Pie, hatch brush", Draw_PieHatch, 300 },
    { "Chord, hatch brush, wide pen", Draw_ChordHatch, 300 },
    { "Pie, hatch brush, viewport origin", Draw_PieHatchVP, 200 },
    { "Pie, negative coordinates", Draw_PieNeg, 300 },
    { "Chord, negative coordinates", Draw_ChordNeg, 300 },
    { "Arc, negative coordinates", Draw_ArcNeg, 60 },
    { "Ellipse, hatch brush, negative coordinates", Draw_EllipseNeg, 300 },
    { "Ellipses, negative coordinates", Draw_EllipseNegSolid, 300 },
    { "Arc, viewport origin", Draw_ArcViewport, 60 },
    { "Arc, rotation", Draw_ArcRot, 100 },
    { "Pie, rotation, hatch brush", Draw_PieRot, 100 },
    { "Chord, rotation", Draw_ChordRot, 100 },
    { "dashed lines at 45 degrees", Draw_Dash45, 40 },
    { "dotted polygon at 45 degrees", Draw_DotPolygon45, 40 },
    { "dashed rotated rectangle", Draw_DashRotRect, 60 },
};

typedef struct
{
    HDC hdc;
    HBITMAP hbm, hbmOld;
    DWORD *bits;
} DIBDC;

static BOOL DibCreate(DIBDC *d)
{
    BITMAPINFO bmi;

    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = CW;
    bmi.bmiHeader.biHeight = -CH;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    d->hdc = CreateCompatibleDC(NULL);
    d->bits = NULL;
    d->hbm = CreateDIBSection(d->hdc, &bmi, DIB_RGB_COLORS, (void **)&d->bits, NULL, 0);
    if (!d->hdc || !d->hbm || !d->bits)
        return FALSE;
    d->hbmOld = SelectObject(d->hdc, d->hbm);
    PatBlt(d->hdc, 0, 0, CW, CH, WHITENESS);
    return TRUE;
}

static void DibDestroy(DIBDC *d)
{
    if (d->hdc && d->hbmOld)
        SelectObject(d->hdc, d->hbmOld);
    if (d->hbm)
        DeleteObject(d->hbm);
    if (d->hdc)
        DeleteDC(d->hdc);
}

/* Draws a case through hdc with the default objects restored afterwards (the case's own are deleted) */
static void DrawCase(HDC hdc, const CASE *c)
{
    HGDIOBJ hbr, hpen;

    PatBlt(hdc, 0, 0, CW, CH, WHITENESS);
    SaveDC(hdc);
    c->draw(hdc);
    hbr = SelectObject(hdc, GetStockObject(WHITE_BRUSH));
    hpen = SelectObject(hdc, GetStockObject(BLACK_PEN));
    RestoreDC(hdc, -1);
    if (GetObjectType(hbr) == OBJ_BRUSH && hbr != GetStockObject(NULL_BRUSH))
        DeleteObject(hbr);
    if (GetObjectType(hpen) == OBJ_PEN)
        DeleteObject(hpen);
}

static void Compare(const DWORD *test, const DWORD *ref, const CASE *c, const char *where)
{
    int x, y, nDiff = 0, nShape = 0, bl = CW, bt = CH, br = -1, bb = -1;

    for (y = 0; y < CH; y++)
    {
        for (x = 0; x < CW; x++)
        {
            DWORD t = test[y * CW + x] & 0xFFFFFF, r = ref[y * CW + x] & 0xFFFFFF;

            if (r != 0xFFFFFF)
                nShape++;
            if (t != r)
            {
                nDiff++;
                bl = min(bl, x);
                bt = min(bt, y);
                br = max(br, x);
                bb = max(bb, y);
            }
        }
    }
    ok(nShape >= c->minPixels, "%s, %s: the reference has only %d pixels\n", where, c->name, nShape);
    ok(nDiff == 0, "%s, %s: %d pixels differ from the memory DC, in (%d,%d)-(%d,%d)\n", where, c->name, nDiff,
       bl, bt, br, bb);
}

static void Pump(void)
{
    MSG msg;

    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);
}

START_TEST(WindowMemoryDC)
{
    DIBDC ref, rb;
    HWND hwndTop, hwndChild;
    int i, pass;

    if (!DibCreate(&ref) || !DibCreate(&rb))
    {
        skip("no DIB sections\n");
        return;
    }

    /* a popup at (43,37) and a child of it at (50,40): origins 43,37 and 93,77 on the screen */
    hwndTop = CreateWindowExW(0, L"STATIC", L"top", WS_POPUP | WS_VISIBLE, 43, 37, 2 * CW, 2 * CH, NULL, NULL,
                              GetModuleHandleW(NULL), NULL);
    hwndChild = hwndTop ? CreateWindowExW(0, L"STATIC", L"child", WS_CHILD | WS_VISIBLE, 50, 40, CW, CH, hwndTop,
                                          NULL, GetModuleHandleW(NULL), NULL) : NULL;
    if (!hwndTop || !hwndChild)
    {
        skip("no windows\n");
        goto Cleanup;
    }
    UpdateWindow(hwndTop);
    Pump();

    for (i = 0; i < (int)(sizeof(g_Cases) / sizeof(g_Cases[0])); i++)
    {
        DrawCase(ref.hdc, &g_Cases[i]);
        GdiFlush();

        for (pass = 0; pass < 2; pass++)
        {
            HWND hwnd = pass ? hwndChild : hwndTop;
            HDC hdc = GetDC(hwnd);

            DrawCase(hdc, &g_Cases[i]);
            BitBlt(rb.hdc, 0, 0, CW, CH, hdc, 0, 0, SRCCOPY);
            ReleaseDC(hwnd, hdc);
            GdiFlush();
            Compare(rb.bits, ref.bits, &g_Cases[i], pass ? "child window DC" : "popup window DC");
        }
    }

Cleanup:
    if (hwndTop)
        DestroyWindow(hwndTop);
    DibDestroy(&ref);
    DibDestroy(&rb);
}
