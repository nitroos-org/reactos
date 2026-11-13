/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Polygon and Rectangle draw the same pixels wherever the DC places them: mapping modes, viewport and
 *              window origins, flipped axes, a world transform, a window DC with a frame, cosmetic and wide pens
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Each case places a shape on fixed device pixels (the logical points come from DPtoLP of a scratch DC with the same
 * setup, the device points the drawing must hit from LPtoDP of the same), draws it through the DC under test and
 * draws the same device points into a DIB in an untransformed DC. The two DIBs must be equal, and a few pixels are
 * checked against their expected colours (fill, pen, outside) so that two empty pictures do not pass.
 */

#include "precomp.h"

#define W 200
#define H 200

#define DIB_WHITE 0x00FFFFFF
#define DIB_RED   0x00FF0000
#define DIB_BLUE  0x000000FF

enum { M_TEXT, M_VPORG, M_LOENG, M_FLIPX, M_FLIPY, M_FLIPXY, M_ROT, M_ROTVP, M_ROTSTALE, M_COUNT };

static const char *g_ModeName[M_COUNT] =
{
    "MM_TEXT", "viewport/window origin", "MM_LOENGLISH", "flipped x", "flipped y", "flipped x and y",
    "rotation", "rotation + viewport origin", "rotation after an unrotated draw"
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
    bmi.bmiHeader.biWidth = W;
    bmi.bmiHeader.biHeight = -H;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    d->hdc = CreateCompatibleDC(NULL);
    d->bits = NULL;
    d->hbm = CreateDIBSection(d->hdc, &bmi, DIB_RGB_COLORS, (void **)&d->bits, NULL, 0);
    if (!d->hdc || !d->hbm || !d->bits)
        return FALSE;
    d->hbmOld = SelectObject(d->hdc, d->hbm);
    PatBlt(d->hdc, 0, 0, W, H, WHITENESS);
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

static void SetupMode(HDC hdc, int mode)
{
    XFORM xf;

    switch (mode)
    {
        case M_VPORG:
            SetViewportOrgEx(hdc, 23, 17, NULL);
            SetWindowOrgEx(hdc, -9, 4, NULL);
            break;
        case M_LOENG:
            SetMapMode(hdc, MM_LOENGLISH);
            SetViewportOrgEx(hdc, 10, 190, NULL);
            break;
        case M_FLIPX:
        case M_FLIPY:
        case M_FLIPXY:
            SetMapMode(hdc, MM_ANISOTROPIC);
            SetWindowExtEx(hdc, 1, 1, NULL);
            SetViewportExtEx(hdc, (mode == M_FLIPY) ? 1 : -1, (mode == M_FLIPX) ? 1 : -1, NULL);
            SetViewportOrgEx(hdc, (mode == M_FLIPY) ? 0 : 190, (mode == M_FLIPX) ? 0 : 190, NULL);
            break;
        case M_ROTVP:
            SetViewportOrgEx(hdc, 12, 9, NULL);
            /* fall through */
        case M_ROT:
        case M_ROTSTALE:
            SetGraphicsMode(hdc, GM_ADVANCED);
            xf.eM11 = 0.8660254f; xf.eM12 = 0.5f;
            xf.eM21 = -0.5f;      xf.eM22 = 0.8660254f;
            xf.eDx = 60.0f;       xf.eDy = -30.0f;
            SetWorldTransform(hdc, &xf);
            break;
        default:
            break;
    }
}

static BOOL IsRotation(int mode)
{
    return mode == M_ROT || mode == M_ROTVP || mode == M_ROTSTALE;
}

/* The wide pen width in logical units: WantDev, in MM_LOENGLISH 25 (about 24 pixels) */
static int LogicalPenWidth(int mode, int WantDev)
{
    if (WantDev == 1)
        return 0;   /* cosmetic */
    return (mode == M_LOENG) ? 25 : WantDev;
}

/* One case: shape 0 = Polygon (3 points), 1 = Rectangle; WantDev 1 (cosmetic) or 7/24 (wide) */
typedef struct
{
    int mode, shape, WantDev;
    POINT dev[4];   /* the device points the drawing must hit */
    int cDev;
    int PenDev;     /* pen width on the device */
} CASE;

/* The device thickness the wide pen of a mode draws: a long horizontal Polyline through a DC of that mode, measured on
   one column. (The pen width is not what these tests are about, and MM_LOENGLISH scales 25 logical units to 24 or 25
   pixels depending on the system: take what the system draws, and compare the placement of the shape.) The current
   position is set first so that the line starts at its first point. */
static int MeasurePenWidth(int mode, int LogW)
{
    static int Cache[M_COUNT][2];
    DIBDC d;
    POINT pt[2] = { { 30, 100 }, { 170, 100 } };
    HPEN hPen, hOld;
    int y, n = 0, slot = (LogW > 1);

    if (Cache[mode][slot])
        return Cache[mode][slot];
    if (!DibCreate(&d))
        return LogW;
    SetupMode(d.hdc, mode);
    DPtoLP(d.hdc, pt, 2);
    hPen = CreatePen(PS_SOLID, LogW, RGB(255, 0, 0));
    hOld = SelectObject(d.hdc, hPen);
    MoveToEx(d.hdc, pt[0].x, pt[0].y, NULL);
    Polyline(d.hdc, pt, 2);
    SelectObject(d.hdc, hOld);
    DeleteObject(hPen);
    for (y = 0; y < H; y++)
        n += (d.bits[y * W + 100] & 0xFFFFFF) == DIB_RED;
    DibDestroy(&d);
    Cache[mode][slot] = n;
    return n;
}

static void PlaceCase(CASE *c, POINT *log, int *pcLog)
{
    static const POINT TriDev[3] = { { 50, 40 }, { 165, 70 }, { 80, 160 } };
    static const POINT RectDev[2] = { { 45, 50 }, { 150, 140 } };
    HDC hdcS = CreateCompatibleDC(NULL);
    POINT pt[4];
    int i, n;

    SetupMode(hdcS, c->mode);
    if (c->shape == 0)
    {
        n = 3;
        for (i = 0; i < 3; i++)
            pt[i] = TriDev[i];
    }
    else
    {
        n = 2;
        pt[0] = RectDev[0];
        pt[1] = RectDev[1];
    }
    DPtoLP(hdcS, pt, n);
    for (i = 0; i < n; i++)
        log[i] = pt[i];
    *pcLog = n;

    if (c->shape == 1 && IsRotation(c->mode))
    {
        /* the four corners of the rotated rectangle, in the order of the polygon the system draws */
        POINT cr[4];

        cr[0].x = log[0].x; cr[0].y = log[0].y;
        cr[1].x = log[1].x; cr[1].y = log[0].y;
        cr[2].x = log[1].x; cr[2].y = log[1].y;
        cr[3].x = log[0].x; cr[3].y = log[1].y;
        LPtoDP(hdcS, cr, 4);
        for (i = 0; i < 4; i++)
            c->dev[i] = cr[i];
        c->cDev = 4;
    }
    else
    {
        for (i = 0; i < n; i++)
            pt[i] = log[i];
        LPtoDP(hdcS, pt, n);
        for (i = 0; i < n; i++)
            c->dev[i] = pt[i];
        c->cDev = n;
    }

    if (c->WantDev == 1)
        c->PenDev = 1;
    else
        c->PenDev = MeasurePenWidth(c->mode, LogicalPenWidth(c->mode, c->WantDev));
    DeleteDC(hdcS);
}

static void SelectPenBrush(HDC hdc, int LogW, HPEN *phPen, HBRUSH *phBrush, HGDIOBJ *pOldPen, HGDIOBJ *pOldBrush)
{
    *phPen = CreatePen(PS_SOLID, LogW, RGB(255, 0, 0));
    *phBrush = CreateSolidBrush(RGB(0, 0, 255));
    *pOldPen = SelectObject(hdc, *phPen);
    *pOldBrush = SelectObject(hdc, *phBrush);
}

static void DeselectPenBrush(HDC hdc, HPEN hPen, HBRUSH hBrush, HGDIOBJ OldPen, HGDIOBJ OldBrush)
{
    SelectObject(hdc, OldPen);
    SelectObject(hdc, OldBrush);
    DeleteObject(hPen);
    DeleteObject(hBrush);
}

/* The reference: the device points in an untransformed DC */
static void DrawReference(HDC hdc, const CASE *c)
{
    HPEN hPen;
    HBRUSH hBrush;
    HGDIOBJ OldPen, OldBrush;

    SelectPenBrush(hdc, (c->PenDev == 1) ? 0 : c->PenDev, &hPen, &hBrush, &OldPen, &OldBrush);
    if (c->shape == 1 && c->cDev == 2)
    {
        /* an axis-aligned rectangle: its corners in any order are the same rectangle */
        Rectangle(hdc, min(c->dev[0].x, c->dev[1].x), min(c->dev[0].y, c->dev[1].y),
                  max(c->dev[0].x, c->dev[1].x), max(c->dev[0].y, c->dev[1].y));
    }
    else
    {
        Polygon(hdc, c->dev, c->cDev);
    }
    DeselectPenBrush(hdc, hPen, hBrush, OldPen, OldBrush);
}

/* The drawing under test: logical points through the DC's own transform */
static void DrawUnderTest(HDC hdc, const CASE *c, const POINT *log, int cLog)
{
    HPEN hPen;
    HBRUSH hBrush;
    HGDIOBJ OldPen, OldBrush;

    SelectPenBrush(hdc, LogicalPenWidth(c->mode, c->WantDev), &hPen, &hBrush, &OldPen, &OldBrush);
    if (c->shape == 0)
        Polygon(hdc, log, cLog);
    else
        Rectangle(hdc, log[0].x, log[0].y, log[1].x, log[1].y);
    DeselectPenBrush(hdc, hPen, hBrush, OldPen, OldBrush);
}

/* Prepare the DC under test: for M_ROTSTALE an unrotated draw first, so that its transform data describe a scale */
static void PrepareTarget(HDC hdc, const CASE *c)
{
    PatBlt(hdc, 0, 0, W, H, WHITENESS);
    if (c->mode == M_ROTSTALE)
    {
        HGDIOBJ OldBrush = SelectObject(hdc, GetStockObject(BLACK_BRUSH));
        Rectangle(hdc, 5, 5, 20, 20);
        SelectObject(hdc, OldBrush);
        PatBlt(hdc, 0, 0, W, H, WHITENESS);
    }
    SetupMode(hdc, c->mode);
}

static void CheckPictures(const DWORD *test, const DWORD *ref, const CASE *c, const char *where)
{
    int x, y, nDiff = 0, nShape = 0, i, bl = W, bt = H, br = -1, bb = -1;
    LONG cx = 0, cy = 0;

    for (y = 0; y < H; y++)
    {
        for (x = 0; x < W; x++)
        {
            DWORD t = test[y * W + x] & 0xFFFFFF, r = ref[y * W + x] & 0xFFFFFF;

            if (t != r)
            {
                nDiff++;
                bl = min(bl, x); bt = min(bt, y); br = max(br, x); bb = max(bb, y);
            }
            if (r != DIB_WHITE)
                nShape++;
        }
    }

    ok(nShape > 200, "%s: %s, %s, pen %d: the reference is empty (%d pixels)\n", where, g_ModeName[c->mode],
       c->shape ? "Rectangle" : "Polygon", c->PenDev, nShape);
    if (nDiff && nDiff < 40)
    {
        int shown = 0;

        for (y = 0; y < H && shown < 12; y++)
            for (x = 0; x < W && shown < 12; x++)
                if ((test[y * W + x] & 0xFFFFFF) != (ref[y * W + x] & 0xFFFFFF))
                {
                    trace("  diff (%d,%d): test %06lx ref %06lx\n", x, y, (ULONG)(test[y * W + x] & 0xFFFFFF), (ULONG)(ref[y * W + x] & 0xFFFFFF));
                    shown++;
                }
    }
    ok(nDiff == 0, "%s: %s, %s, pen %d: %d pixels differ from the reference, in (%d,%d)-(%d,%d)\n", where, g_ModeName[c->mode],
       c->shape ? "Rectangle" : "Polygon", c->PenDev, nDiff, bl, bt, br, bb);

    /* The centre of the shape is the fill, the middle of an edge is the pen (wide only), on the test picture */
    for (i = 0; i < c->cDev; i++)
    {
        cx += c->dev[i].x;
        cy += c->dev[i].y;
    }
    cx /= c->cDev;
    cy /= c->cDev;
    ok((test[cy * W + cx] & 0xFFFFFF) == DIB_BLUE, "%s: %s, %s, pen %d: the centre (%ld,%ld) is 0x%06lx, not the fill\n", where,
       g_ModeName[c->mode], c->shape ? "Rectangle" : "Polygon", c->PenDev, cx, cy, (ULONG)(test[cy * W + cx] & 0xFFFFFF));
    if (c->PenDev > 1)
    {
        /* Polygon and the rotated rectangle: the first side; the unrotated one: its edge at dev[0].y */
        LONG mx = (c->dev[0].x + c->dev[1].x) / 2, my = (c->cDev == 2) ? c->dev[0].y : (c->dev[0].y + c->dev[1].y) / 2;

        ok((test[my * W + mx] & 0xFFFFFF) == DIB_RED, "%s: %s, %s, pen %d: the middle of an edge (%ld,%ld) is 0x%06lx, not the pen\n",
           where, g_ModeName[c->mode], c->shape ? "Rectangle" : "Polygon", c->PenDev, mx, my,
           (ULONG)(test[my * W + mx] & 0xFFFFFF));
    }
    ok((test[1 * W + 1] & 0xFFFFFF) == DIB_WHITE, "%s: %s, %s, pen %d: the corner (1,1) is not blank\n", where,
       g_ModeName[c->mode], c->shape ? "Rectangle" : "Polygon", c->PenDev);
}

static void Test_MemoryDC(void)
{
    DIBDC tst, ref;
    int mode, shape, pen;
    static const int Pens[2] = { 1, 7 };

    if (!DibCreate(&tst) || !DibCreate(&ref))
    {
        skip("no DIB sections\n");
        return;
    }

    for (mode = 0; mode < M_COUNT; mode++)
    {
        for (shape = 0; shape < 2; shape++)
        {
            for (pen = 0; pen < 2; pen++)
            {
                CASE c;
                POINT log[4];
                int cLog;

                c.mode = mode;
                c.shape = shape;
                c.WantDev = Pens[pen];
                PlaceCase(&c, log, &cLog);

                PatBlt(ref.hdc, 0, 0, W, H, WHITENESS);
                DrawReference(ref.hdc, &c);

                PrepareTarget(tst.hdc, &c);
                DrawUnderTest(tst.hdc, &c, log, cLog);
                GdiFlush();
                CheckPictures(tst.bits, ref.bits, &c, "memory DC");

                /* back to the default state for the next case */
                ModifyWorldTransform(tst.hdc, NULL, MWT_IDENTITY);
                SetGraphicsMode(tst.hdc, GM_COMPATIBLE);
                SetMapMode(tst.hdc, MM_TEXT);
                SetViewportOrgEx(tst.hdc, 0, 0, NULL);
                SetWindowOrgEx(tst.hdc, 0, 0, NULL);
            }
        }
    }
    DibDestroy(&tst);
    DibDestroy(&ref);
}

/* The client DC of a window with a frame: its origin on the screen is not zero */
static void Test_WindowDC(void)
{
    DIBDC ref, rb;
    RECT rc = { 0, 0, W, H };
    HWND hwnd;
    int mode, shape, pen;
    static const int Pens[2] = { 1, 7 };
    static const int Modes[] = { M_TEXT, M_VPORG, M_LOENG, M_FLIPXY, M_ROT, M_ROTSTALE };
    int im;

    if (!DibCreate(&ref) || !DibCreate(&rb))
    {
        skip("no DIB sections\n");
        return;
    }

    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
    hwnd = CreateWindowExW(0, L"STATIC", L"shapes", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 60, 40,
                           rc.right - rc.left, rc.bottom - rc.top, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!hwnd)
    {
        skip("no window\n");
        DibDestroy(&ref);
        DibDestroy(&rb);
        return;
    }
    UpdateWindow(hwnd);
    {
        MSG msg;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }

    for (im = 0; im < (int)(sizeof(Modes) / sizeof(Modes[0])); im++)
    {
        mode = Modes[im];
        for (shape = 0; shape < 2; shape++)
        {
            for (pen = 0; pen < 2; pen++)
            {
                CASE c;
                POINT log[4];
                int cLog;
                HDC hdc;

                c.mode = mode;
                c.shape = shape;
                c.WantDev = Pens[pen];
                PlaceCase(&c, log, &cLog);

                PatBlt(ref.hdc, 0, 0, W, H, WHITENESS);
                DrawReference(ref.hdc, &c);

                hdc = GetDC(hwnd);
                PrepareTarget(hdc, &c);
                DrawUnderTest(hdc, &c, log, cLog);
                ModifyWorldTransform(hdc, NULL, MWT_IDENTITY);
                SetGraphicsMode(hdc, GM_COMPATIBLE);
                SetMapMode(hdc, MM_TEXT);
                SetViewportOrgEx(hdc, 0, 0, NULL);
                SetWindowOrgEx(hdc, 0, 0, NULL);
                BitBlt(rb.hdc, 0, 0, W, H, hdc, 0, 0, SRCCOPY);
                ReleaseDC(hwnd, hdc);
                GdiFlush();
                CheckPictures(rb.bits, ref.bits, &c, "window DC");
            }
        }
    }
    DestroyWindow(hwnd);
    DibDestroy(&ref);
    DibDestroy(&rb);
}

START_TEST(ShapeTransform)
{
    Test_MemoryDC();
    Test_WindowDC();
}
