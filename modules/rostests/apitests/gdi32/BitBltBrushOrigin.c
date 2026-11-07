/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         A pattern ROP of BitBlt, StretchBlt and MaskBlt honours the DC brush origin (SetBrushOrgEx) like PatBlt,
 *                  and the origin a DC reports is the one the pattern fills use after RestoreDC and after the DC went
 *                  back to the cache (the Edge installer dialog painted blue boxes where its controls had been)
 */

#include "precomp.h"

#define SIZE 40
#define PAT  8

static HDC ghdc;
static HBITMAP ghbmTarget;
static ULONG *gpulBits;
static HBRUSH ghbrPat;
static HDC ghdcSrc;

static ULONG
PatColor(int x, int y)
{
    return RGB(x * 30 + 10, y * 30 + 10, 0x55) ;
}

static void
Clear(void)
{
    int i;

    for (i = 0; i < SIZE * SIZE; i++)
        gpulBits[i] = 0;
    GdiFlush();
}

static ULONG
Pixel(int x, int y)
{
    ULONG c;

    GdiFlush();
    c = gpulBits[y * SIZE + x] & 0xFFFFFF;
    /* the DIB holds 0x00RRGGBB, COLORREF is 0x00BBGGRR */
    return ((c & 0xFF) << 16) | (c & 0xFF00) | ((c >> 16) & 0xFF);
}

/* the pixel of the whole target against the brush aligned at (ox, oy); invert: the target started as 0 and PATINVERT xors */
static void
CheckPattern(const char *name, int ox, int oy, int x0, int y0, int x1, int y1, BOOL fInvert)
{
    int x, y, bad = 0, px, py;
    ULONG expect;

    for (y = 0; y < SIZE; y++)
    {
        for (x = 0; x < SIZE; x++)
        {
            if (x >= x0 && x < x1 && y >= y0 && y < y1)
            {
                px = ((x - ox) % PAT + PAT) % PAT;
                py = ((y - oy) % PAT + PAT) % PAT;
                expect = PatColor(px, py);
                (void)fInvert;
            }
            else
                expect = 0;
            if (Pixel(x, y) != expect)
            {
                if (bad < 3)
                    trace("%s: (%d,%d) is %06lx, expected %06lx\n", name, x, y, Pixel(x, y), expect);
                bad++;
            }
        }
    }
    ok(bad == 0, "%s (origin %d,%d): %d wrong pixels\n", name, ox, oy, bad);
}

static void
TestOrigin(int ox, int oy)
{
    HGDIOBJ hOld = SelectObject(ghdc, ghbrPat);
    HBITMAP hbmMask = CreateBitmap(SIZE, SIZE, 1, 1, NULL);
    HDC hdcMask = CreateCompatibleDC(ghdc);
    HGDIOBJ hOldMask = SelectObject(hdcMask, hbmMask);

    SetBrushOrgEx(ghdc, ox, oy, NULL);

    /* the reference */
    Clear();
    PatBlt(ghdc, 4, 3, 30, 25, PATCOPY);
    CheckPattern("PatBlt PATCOPY", ox, oy, 4, 3, 34, 28, FALSE);

    Clear();
    BitBlt(ghdc, 4, 3, 30, 25, NULL, 0, 0, PATCOPY);
    CheckPattern("BitBlt PATCOPY", ox, oy, 4, 3, 34, 28, FALSE);

    Clear();
    /* the source is not used by PATCOPY; the red one shows if it is */
    StretchBlt(ghdc, 4, 3, 30, 25, ghdcSrc, 0, 0, 30, 25, PATCOPY);
    CheckPattern("StretchBlt PATCOPY same size", ox, oy, 4, 3, 34, 28, FALSE);

    /* a mask of all ones selects the foreground ROP (PATCOPY) everywhere */
    PatBlt(hdcMask, 0, 0, SIZE, SIZE, WHITENESS);
    Clear();
    MaskBlt(ghdc, 4, 3, 30, 25, ghdcSrc, 0, 0, hbmMask, 0, 0, MAKEROP4(PATCOPY, 0x00AA0029));
    CheckPattern("MaskBlt PATCOPY", ox, oy, 4, 3, 34, 28, FALSE);

    /* PATINVERT onto zero is the pattern too */
    Clear();
    BitBlt(ghdc, 4, 3, 30, 25, NULL, 0, 0, PATINVERT);
    CheckPattern("BitBlt PATINVERT", ox, oy, 4, 3, 34, 28, TRUE);

    SelectObject(hdcMask, hOldMask);
    DeleteDC(hdcMask);
    DeleteObject(hbmMask);
    SelectObject(ghdc, hOld);
}


/* a window DC and a memory DC: PatBlt must use the brush origin that GetBrushOrgEx reports */
static void
CheckWindowFill(HDC hdc, HBRUSH hbr, const char *name)
{
    POINT pt;
    HGDIOBJ hOld;
    int x, y, bad = 0, px, py;

    GetBrushOrgEx(hdc, &pt);
    hOld = SelectObject(hdc, hbr);
    PatBlt(hdc, 0, 0, 32, 32, PATCOPY);
    SelectObject(hdc, hOld);
    for (y = 0; y < 32; y += 3)
    {
        for (x = 0; x < 32; x += 3)
        {
            px = ((x - pt.x) % PAT + PAT) % PAT;
            py = ((y - pt.y) % PAT + PAT) % PAT;
            if (GetPixel(hdc, x, y) != PatColor(px, py))
                bad++;
        }
    }
    ok(bad == 0, "%s (reported origin %ld,%ld): %d wrong pixels\n", name, pt.x, pt.y, bad);
}

static void
TestStaleOrigin(void)
{
    HWND hwnd;
    HDC hdc;
    POINT pt;
    int saved;

    /* RestoreDC brings the saved origin back for the fills too */
    SelectObject(ghdc, ghbmTarget);
    SetBrushOrgEx(ghdc, 3, 5, NULL);
    saved = SaveDC(ghdc);
    SetBrushOrgEx(ghdc, 0, 0, NULL);
    ok(RestoreDC(ghdc, saved), "RestoreDC failed\n");
    GetBrushOrgEx(ghdc, &pt);
    Clear();
    SelectObject(ghdc, ghbrPat);
    PatBlt(ghdc, 4, 3, 30, 25, PATCOPY);
    CheckPattern("PatBlt after RestoreDC", pt.x, pt.y, 4, 3, 34, 28, FALSE);
    SetBrushOrgEx(ghdc, 0, 0, NULL);

    /* a window DC that was returned to the cache starts again at origin 0,0, for the fills as well */
    hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"STATIC", NULL, WS_POPUP | WS_VISIBLE,
                           0, 0, 40, 40, NULL, NULL, NULL, NULL);
    if (!hwnd)
    {
        skip("no window\n");
        return;
    }
    UpdateWindow(hwnd);
    hdc = GetDC(hwnd);
    SetBrushOrgEx(hdc, -303, -81, NULL);
    ReleaseDC(hwnd, hdc);
    hdc = GetDC(hwnd);
    GetBrushOrgEx(hdc, &pt);
    ok(pt.x == 0 && pt.y == 0, "brush origin of a fresh window DC is %ld,%ld\n", pt.x, pt.y);
    CheckWindowFill(hdc, ghbrPat, "window DC after the cache reset");
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);
}

START_TEST(BitBltBrushOrigin)
{
    BITMAPINFO bmi = {{sizeof(BITMAPINFOHEADER), SIZE, -SIZE, 1, 32, BI_RGB}};
    BITMAPINFO bmiPat = {{sizeof(BITMAPINFOHEADER), PAT, -PAT, 1, 32, BI_RGB}};
    ULONG *pulPat;
    HBITMAP hbmPat, hbmSrc;
    HGDIOBJ hbmOldSrc;
    HDC hdcScreen = GetDC(NULL);
    int x, y;

    ghdc = CreateCompatibleDC(hdcScreen);
    ghbmTarget = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, (PVOID*)&gpulBits, NULL, 0);
    hbmPat = CreateDIBSection(hdcScreen, &bmiPat, DIB_RGB_COLORS, (PVOID*)&pulPat, NULL, 0);
    if (!ghdc || !ghbmTarget || !hbmPat)
    {
        skip("no bitmaps\n");
        return;
    }
    for (y = 0; y < PAT; y++)
    {
        for (x = 0; x < PAT; x++)
        {
            ULONG c = PatColor(x, y);
            pulPat[y * PAT + x] = ((c & 0xFF) << 16) | (c & 0xFF00) | ((c >> 16) & 0xFF);
        }
    }
    GdiFlush();
    ghbrPat = CreatePatternBrush(hbmPat);
    SelectObject(ghdc, ghbmTarget);
    ghdcSrc = CreateCompatibleDC(hdcScreen);
    hbmSrc = CreateCompatibleBitmap(hdcScreen, SIZE, SIZE);
    hbmOldSrc = SelectObject(ghdcSrc, hbmSrc);
    {
        HBRUSH hbrRed = CreateSolidBrush(RGB(255, 0, 0));
        RECT rc = {0, 0, SIZE, SIZE};
        FillRect(ghdcSrc, &rc, hbrRed);
        DeleteObject(hbrRed);
    }

    TestOrigin(0, 0);
    TestOrigin(3, 5);
    TestOrigin(-2, 7);
    TestOrigin(11, 13);
    TestStaleOrigin();

    DeleteObject(ghbrPat);
    DeleteObject(hbmPat);
    SelectObject(ghdcSrc, hbmOldSrc);
    DeleteObject(hbmSrc);
    DeleteDC(ghdcSrc);
    DeleteDC(ghdc);
    DeleteObject(ghbmTarget);
    ReleaseDC(NULL, hdcScreen);
}
