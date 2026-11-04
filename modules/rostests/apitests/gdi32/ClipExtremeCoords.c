/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Clipping and text output with coordinates at the ends of the INT range
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 x64 (2026-11-04).
 * Windows keeps clip coordinates in a 28-bit space [-2^27, 2^27 - 1]:
 * IntersectClipRect/ExcludeClipRect with a rectangle outside it fail with ERROR
 * and leave the clip region alone, so text still draws. user32 DrawText and
 * WinForms TextRenderer pass (x, y, INT_MAX, INT_MAX) bounds.
 */

#include "precomp.h"

#define W 64
#define H 32
#define M27 0x7FFFFFF
#define B27 0x8000000
#define B28 0x10000000

static HDC hdc;
static DWORD *pBits;
static int iFullInk;

static void ResetDC_(void)
{
    int i;
    for (i = 0; i < W * H; i++)
        pBits[i] = 0xFFFFFF;
    SelectClipRgn(hdc, NULL);
    SetMapMode(hdc, MM_TEXT);
    SetWindowOrgEx(hdc, 0, 0, NULL);
    SetViewportOrgEx(hdc, 0, 0, NULL);
    SetTextColor(hdc, RGB(0, 0, 0));
    SetBkColor(hdc, RGB(255, 0, 0));
    SetBkMode(hdc, TRANSPARENT);
    SetTextAlign(hdc, TA_TOP | TA_LEFT);
}

static void CountPixels(int *piInk, int *piRed)
{
    int i;
    GdiFlush();
    *piInk = *piRed = 0;
    for (i = 0; i < W * H; i++)
    {
        DWORD p = pBits[i] & 0xFFFFFF;
        if (p == 0xFF0000)
            (*piRed)++;
        else if (p != 0xFFFFFF)
            (*piInk)++;
    }
}

static int TextInk(void)
{
    int iInk, iRed;
    TextOutA(hdc, 2, 2, "XWXW", 4);
    CountPixels(&iInk, &iRed);
    return iInk;
}

/* The call was refused: no clip region, the whole surface is the clip box, text draws */
static void ExpectNoClip(int iLine, const char *pszWhat, int iRet)
{
    HRGN hrgn = CreateRectRgn(0, 0, 0, 0);
    RECT rc;

    ok_(__FILE__, iLine)(iRet == ERROR, "%s: returned %d, expected ERROR\n", pszWhat, iRet);
    ok_(__FILE__, iLine)(GetClipRgn(hdc, hrgn) == 0, "%s: a clip region was set\n", pszWhat);
    ok_(__FILE__, iLine)(GetClipBox(hdc, &rc) == SIMPLEREGION, "%s: clip box not simple\n", pszWhat);
    ok_(__FILE__, iLine)(rc.left == 0 && rc.top == 0 && rc.right == W && rc.bottom == H,
                         "%s: clip box (%ld,%ld,%ld,%ld)\n", pszWhat, rc.left, rc.top, rc.right, rc.bottom);
    ok_(__FILE__, iLine)(TextInk() == iFullInk, "%s: text not drawn in full\n", pszWhat);
    DeleteObject(hrgn);
}

#define ICR_REFUSED(l, t, r, b) \
    do { ResetDC_(); ExpectNoClip(__LINE__, "ICR " #l "," #t "," #r "," #b, IntersectClipRect(hdc, l, t, r, b)); } while (0)
#define ECR_REFUSED(l, t, r, b) \
    do { ResetDC_(); ExpectNoClip(__LINE__, "ECR " #l "," #t "," #r "," #b, ExcludeClipRect(hdc, l, t, r, b)); } while (0)

static void ExpectClipRgnBox(int iLine, const char *pszWhat, LONG l, LONG t, LONG r, LONG b)
{
    HRGN hrgn = CreateRectRgn(0, 0, 0, 0);
    RECT rc;

    ok_(__FILE__, iLine)(GetClipRgn(hdc, hrgn) == 1, "%s: no clip region\n", pszWhat);
    GetRgnBox(hrgn, &rc);
    ok_(__FILE__, iLine)(rc.left == l && rc.top == t && rc.right == r && rc.bottom == b,
                         "%s: clip region box (%ld,%ld,%ld,%ld), expected (%ld,%ld,%ld,%ld)\n",
                         pszWhat, rc.left, rc.top, rc.right, rc.bottom, l, t, r, b);
    DeleteObject(hrgn);
}

static void Test_IntersectExclude(void)
{
    RECT rc;

    ICR_REFUSED(0, 0, INT_MAX, INT_MAX);
    ICR_REFUSED(0, 0, INT_MAX - 1, INT_MAX - 1);
    ICR_REFUSED(0, 0, INT_MAX - 63, INT_MAX - 63);
    ICR_REFUSED(0, 0, 1 << 30, 1 << 30);
    ICR_REFUSED(0, 0, B28, B28);
    ICR_REFUSED(0, 0, B27, B27);
    ICR_REFUSED(0, 0, B27 + 1, B27 + 1);
    ICR_REFUSED(10, 10, INT_MAX, INT_MAX);
    ICR_REFUSED(INT_MIN, INT_MIN, INT_MAX, INT_MAX);
    ICR_REFUSED(INT_MIN, INT_MIN, 40, 20);
    ICR_REFUSED(INT_MAX, INT_MAX, 0, 0);
    ICR_REFUSED(B27 + 16, 0, INT_MAX, 32);
    ICR_REFUSED(INT_MIN, 0, -B27 - 16, 32);
    ICR_REFUSED(10, 10, INT_MIN + 9, INT_MIN + 9); /* 10 + INT_MAX, wrapped */

    ECR_REFUSED(INT_MIN, INT_MIN, INT_MAX, INT_MAX);
    ECR_REFUSED(30, 0, INT_MAX, INT_MAX);
    ECR_REFUSED(B27 + 16, 0, INT_MAX, 32);

    /* The largest accepted coordinate */
    ResetDC_();
    ok_int(IntersectClipRect(hdc, 0, 0, M27, M27), COMPLEXREGION);
    ExpectClipRgnBox(__LINE__, "ICR 2^27-1", 0, 0, M27, M27);
    ok_int(GetClipBox(hdc, &rc), SIMPLEREGION);
    ok(rc.left == 0 && rc.top == 0 && rc.right == W && rc.bottom == H,
       "clip box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ok_int(TextInk(), iFullInk);

    /* A refused call keeps the clip region already set (follows from the
       refusal above; this sequence itself was not run on Windows) */
    ResetDC_();
    ok_int(IntersectClipRect(hdc, 0, 0, 20, 20), COMPLEXREGION);
    ok_int(IntersectClipRect(hdc, 0, 0, INT_MAX, INT_MAX), ERROR);
    ExpectClipRgnBox(__LINE__, "ICR kept", 0, 0, 20, 20);
    ok_int(ExcludeClipRect(hdc, 10, 0, INT_MAX, INT_MAX), ERROR);
    ExpectClipRgnBox(__LINE__, "ECR kept", 0, 0, 20, 20);

    /* With a window origin offset */
    ResetDC_();
    SetWindowOrgEx(hdc, -10, -10, NULL);
    ok_int(IntersectClipRect(hdc, 0, 0, INT_MAX, INT_MAX), ERROR);
    ok_int(GetClipBox(hdc, &rc), SIMPLEREGION);
    ok(rc.left == -10 && rc.top == -10 && rc.right == W - 10 && rc.bottom == H - 10,
       "clip box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ResetDC_();
    SetWindowOrgEx(hdc, 10, 10, NULL);
    ok_int(IntersectClipRect(hdc, INT_MIN, INT_MIN, INT_MAX, INT_MAX), ERROR);
    ok_int(GetClipBox(hdc, &rc), SIMPLEREGION);
    ok(rc.left == 10 && rc.top == 10 && rc.right == W + 10 && rc.bottom == H + 10,
       "clip box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);

    /* With scaling, a rectangle beyond the coordinate space clips everything away */
    ResetDC_();
    SetMapMode(hdc, MM_ANISOTROPIC);
    SetWindowExtEx(hdc, 1, 1, NULL);
    SetViewportExtEx(hdc, 2, 2, NULL);
    ok_int(IntersectClipRect(hdc, 0, 0, INT_MAX, INT_MAX), COMPLEXREGION);
    ok_int(GetClipBox(hdc, &rc), NULLREGION);
    ExpectClipRgnBox(__LINE__, "aniso x2 ICR INT_MAX", 0, 0, 0, 0);
    ok_int(TextInk(), 0);
    ResetDC_();
    SetMapMode(hdc, MM_ANISOTROPIC);
    SetWindowExtEx(hdc, 1, 1, NULL);
    SetViewportExtEx(hdc, 2, 2, NULL);
    ok_int(IntersectClipRect(hdc, 0, 0, 1 << 29, 1 << 29), COMPLEXREGION);
    ok_int(GetClipBox(hdc, &rc), NULLREGION);
    ResetDC_();
    SetMapMode(hdc, MM_ANISOTROPIC);
    SetWindowExtEx(hdc, 2, 2, NULL);
    SetViewportExtEx(hdc, 1, 1, NULL);
    ok_int(IntersectClipRect(hdc, 0, 0, INT_MAX, INT_MAX), COMPLEXREGION);
    ok_int(GetClipBox(hdc, &rc), NULLREGION);
    ResetDC_();
}

static void Test_Regions(void)
{
    HRGN hrgn;
    RECT rc;

    SetLastError(0xdeadbeef);
    ok(CreateRectRgn(0, 0, INT_MAX, INT_MAX) == NULL, "CreateRectRgn INT_MAX succeeded\n");
    ok_err(ERROR_INVALID_PARAMETER);
    ok(CreateRectRgn(INT_MIN, INT_MIN, INT_MAX, INT_MAX) == NULL, "CreateRectRgn INT_MIN..INT_MAX succeeded\n");
    ok(CreateRectRgn(0, 0, B28, B28) == NULL, "CreateRectRgn 2^28 succeeded\n");
    ok(CreateRectRgn(0, 0, B27, B27) == NULL, "CreateRectRgn 2^27 succeeded\n");
    ok(CreateRectRgn(0, 0, M27, B27) == NULL, "CreateRectRgn 2^27-1,2^27 succeeded\n");
    ok(CreateRectRgn(B27 + 16, 0, INT_MAX, 32) == NULL, "CreateRectRgn beyond 2^27 succeeded\n");

    ResetDC_();
    hrgn = CreateRectRgn(0, 0, M27, M27);
    ok(hrgn != NULL, "CreateRectRgn 2^27-1 failed\n");
    ok_int(GetRgnBox(hrgn, &rc), SIMPLEREGION);
    ok(rc.left == 0 && rc.top == 0 && rc.right == M27 && rc.bottom == M27,
       "rgn box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ok_int(SelectClipRgn(hdc, hrgn), SIMPLEREGION);
    DeleteObject(hrgn);
    ExpectClipRgnBox(__LINE__, "SelectClipRgn 2^27-1", 0, 0, M27, M27);
    ok_int(GetClipBox(hdc, &rc), SIMPLEREGION);
    ok(rc.left == 0 && rc.top == 0 && rc.right == W && rc.bottom == H,
       "clip box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ok_int(TextInk(), iFullInk);

    ResetDC_();
    hrgn = CreateRectRgn(-B27, -B27, 10, 10);
    ok(hrgn != NULL, "CreateRectRgn -2^27 failed\n");
    ok_int(SelectClipRgn(hdc, hrgn), SIMPLEREGION);
    DeleteObject(hrgn);
    ExpectClipRgnBox(__LINE__, "SelectClipRgn -2^27", -B27, -B27, 10, 10);
    ok_int(GetClipBox(hdc, &rc), SIMPLEREGION);
    ok(rc.left == 0 && rc.top == 0 && rc.right == 10 && rc.bottom == 10,
       "clip box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ok(TextInk() > 0, "nothing drawn in (0,0,10,10)\n");

    ResetDC_();
    hrgn = CreateRectRgn(-M27, -M27, 10, 10);
    ok(hrgn != NULL, "CreateRectRgn -(2^27-1) failed\n");
    ok_int(SelectClipRgn(hdc, hrgn), SIMPLEREGION);
    DeleteObject(hrgn);
    ExpectClipRgnBox(__LINE__, "SelectClipRgn -(2^27-1)", -M27, -M27, 10, 10);

    /* SetRectRgn takes the whole INT range */
    hrgn = CreateRectRgn(0, 0, 1, 1);
    ok_int(SetRectRgn(hrgn, 0, 0, INT_MAX, INT_MAX), TRUE);
    ok_int(GetRgnBox(hrgn, &rc), SIMPLEREGION);
    ok(rc.left == 0 && rc.top == 0 && rc.right == INT_MAX && rc.bottom == INT_MAX,
       "rgn box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    ok_int(SetRectRgn(hrgn, INT_MIN, INT_MIN, INT_MAX, INT_MAX), TRUE);
    ok_int(GetRgnBox(hrgn, &rc), SIMPLEREGION);
    ok(rc.left == INT_MIN && rc.top == INT_MIN && rc.right == INT_MAX && rc.bottom == INT_MAX,
       "rgn box (%ld,%ld,%ld,%ld)\n", rc.left, rc.top, rc.right, rc.bottom);
    DeleteObject(hrgn);
    ResetDC_();
}

static void TestEto(int iLine, const char *pszWhat, UINT fuOptions, LONG l, LONG t, LONG r, LONG b,
                    int iExpectInk, int iExpectRed)
{
    RECT rc = { l, t, r, b };
    int iInk, iRed;

    ok_(__FILE__, iLine)(ExtTextOutA(hdc, 2, 2, fuOptions, &rc, "XWXW", 4, NULL), "%s: failed\n", pszWhat);
    CountPixels(&iInk, &iRed);
    ok_(__FILE__, iLine)(iInk == iExpectInk, "%s: ink %d, expected %d\n", pszWhat, iInk, iExpectInk);
    ok_(__FILE__, iLine)(iRed == iExpectRed, "%s: background %d, expected %d\n", pszWhat, iRed, iExpectRed);
}

#define ETO(o, l, t, r, b, ink, red) \
    do { ResetDC_(); TestEto(__LINE__, "ETO " #o " " #l "," #t "," #r "," #b, o, l, t, r, b, ink, red); } while (0)

static void Test_ExtTextOut(void)
{
    const int iBk = W * H - iFullInk;

    ETO(ETO_CLIPPED, 0, 0, INT_MAX, INT_MAX, iFullInk, 0);
    ETO(ETO_CLIPPED, INT_MIN, INT_MIN, INT_MAX, INT_MAX, iFullInk, 0);
    ETO(ETO_CLIPPED, 0, 0, B28, B28, iFullInk, 0);
    ETO(ETO_CLIPPED, B27 + 16, 0, INT_MAX, 32, 0, 0);
    ETO(ETO_OPAQUE, 0, 0, INT_MAX, INT_MAX, iFullInk, iBk);
    ETO(ETO_OPAQUE, INT_MIN, INT_MIN, INT_MAX, INT_MAX, iFullInk, iBk);
    ETO(ETO_OPAQUE | ETO_CLIPPED, 0, 0, INT_MAX, INT_MAX, iFullInk, iBk);
    ETO(ETO_OPAQUE | ETO_CLIPPED, INT_MIN, INT_MIN, INT_MAX, INT_MAX, iFullInk, iBk);

    ResetDC_();
    SetWindowOrgEx(hdc, -10, -10, NULL);
    TestEto(__LINE__, "ETO winorg -10", ETO_CLIPPED, 0, 0, INT_MAX, INT_MAX, iFullInk, 0);

    ResetDC_();
    SetMapMode(hdc, MM_ANISOTROPIC);
    SetWindowExtEx(hdc, 1, 1, NULL);
    SetViewportExtEx(hdc, 2, 2, NULL);
    TestEto(__LINE__, "ETO aniso x2", ETO_CLIPPED, 0, 0, INT_MAX, INT_MAX, iFullInk, 0);
    ResetDC_();
}

static void TestDte(int iLine, const char *pszWhat, UINT uFormat, LONG l, LONG t, LONG r, LONG b, BOOL bFull)
{
    RECT rc = { l, t, r, b };
    int iHeight, iInk, iRed;

    iHeight = DrawTextExA(hdc, "XWXW", -1, &rc, uFormat, NULL);
    CountPixels(&iInk, &iRed);
    ok_(__FILE__, iLine)(iHeight > 0, "%s: height %d\n", pszWhat, iHeight);
    ok_(__FILE__, iLine)(rc.left == l && rc.top == t && rc.right == r && rc.bottom == b,
                         "%s: rect changed to (%ld,%ld,%ld,%ld)\n", pszWhat, rc.left, rc.top, rc.right, rc.bottom);
    if (bFull)
        ok_(__FILE__, iLine)(iInk == iFullInk, "%s: ink %d, expected %d\n", pszWhat, iInk, iFullInk);
    else
        ok_(__FILE__, iLine)(iInk > 0, "%s: nothing drawn\n", pszWhat);
}

#define DTE(f, l, t, r, b, full) \
    do { ResetDC_(); TestDte(__LINE__, "DrawTextEx " #f " " #l "," #t "," #r "," #b, f, l, t, r, b, full); } while (0)

static void Test_DrawTextEx(void)
{
    DTE(0, 10, 10, INT_MAX, INT_MAX, FALSE);
    DTE(0, 0, 0, INT_MAX, INT_MAX, TRUE);
    DTE(DT_SINGLELINE, 0, 0, INT_MAX, INT_MAX, TRUE);
    DTE(DT_WORDBREAK, 2, 2, INT_MAX, INT_MAX, TRUE);
    /* Windows draws this one in full as well; user32 DrawText here puts the
       text at (INT_MIN, INT_MIN), outside the surface */
    ResetDC_();
    {
        RECT rc = { INT_MIN, INT_MIN, INT_MAX, INT_MAX };
        int iInk, iRed;
        ok(DrawTextExA(hdc, "XWXW", -1, &rc, 0, NULL) > 0, "DrawTextEx INT_MIN..INT_MAX failed\n");
        CountPixels(&iInk, &iRed);
        todo_ros ok(iInk == iFullInk, "DrawTextEx INT_MIN..INT_MAX: ink %d, expected %d\n", iInk, iFullInk);
    }
    DTE(0, 0, 0, B28, B28, TRUE);

    ResetDC_();
    SetWindowOrgEx(hdc, -10, -10, NULL);
    TestDte(__LINE__, "DrawTextEx winorg -10", 0, 0, 0, INT_MAX, INT_MAX, FALSE);
    ResetDC_();
}

static void Test_LPtoDP(void)
{
    POINT pt[2];

    ResetDC_();
    pt[0].x = pt[0].y = INT_MAX;
    pt[1].x = pt[1].y = INT_MIN;
    ok_int(LPtoDP(hdc, pt, 2), TRUE);
    ok(pt[0].x == INT_MAX && pt[0].y == INT_MAX, "INT_MAX -> (%ld,%ld)\n", pt[0].x, pt[0].y);
    ok(pt[1].x == INT_MIN && pt[1].y == INT_MIN, "INT_MIN -> (%ld,%ld)\n", pt[1].x, pt[1].y);

    pt[0].x = pt[0].y = B28 + 1;
    pt[1].x = pt[1].y = 0x1000001;
    ok_int(LPtoDP(hdc, pt, 2), TRUE);
    ok(pt[0].x == B28 + 1 && pt[0].y == B28 + 1, "2^28+1 -> (%ld,%ld)\n", pt[0].x, pt[0].y);
    ok(pt[1].x == 0x1000001 && pt[1].y == 0x1000001, "2^24+1 -> (%ld,%ld)\n", pt[1].x, pt[1].y);

    SetWindowOrgEx(hdc, -10, -10, NULL);
    pt[0].x = pt[0].y = INT_MAX - 20;
    pt[1].x = pt[1].y = B27;
    ok_int(LPtoDP(hdc, pt, 2), TRUE);
    ok(pt[0].x == INT_MAX - 10 && pt[0].y == INT_MAX - 10, "INT_MAX-20 -> (%ld,%ld)\n", pt[0].x, pt[0].y);
    ok(pt[1].x == B27 + 10 && pt[1].y == B27 + 10, "2^27 -> (%ld,%ld)\n", pt[1].x, pt[1].y);

    /* the inverse (not run on Windows) */
    pt[0].x = pt[0].y = INT_MAX - 20;
    ok_int(DPtoLP(hdc, pt, 1), TRUE);
    ok(pt[0].x == INT_MAX - 30 && pt[0].y == INT_MAX - 30, "DPtoLP INT_MAX-20 -> (%ld,%ld)\n", pt[0].x, pt[0].y);
    ResetDC_();
}

START_TEST(ClipExtremeCoords)
{
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER), W, -H, 1, 32, BI_RGB } };
    HBITMAP hbmp, hbmpOld;
    HFONT hfont, hfontOld;

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    if (!hdc)
        return;
    hbmp = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, (void **)&pBits, NULL, 0);
    ok(hbmp != NULL, "CreateDIBSection failed\n");
    if (!hbmp)
    {
        DeleteDC(hdc);
        return;
    }
    hbmpOld = SelectObject(hdc, hbmp);
    hfont = CreateFontA(-16, 0, 0, 0, FW_BOLD, 0, 0, 0, ANSI_CHARSET, 0, 0,
                        NONANTIALIASED_QUALITY, 0, "Arial");
    hfontOld = SelectObject(hdc, hfont);

    ResetDC_();
    iFullInk = TextInk();
    ok(iFullInk > 50, "text without a clip region drew %d pixels\n", iFullInk);

    Test_IntersectExclude();
    Test_Regions();
    Test_ExtTextOut();
    Test_DrawTextEx();
    Test_LPtoDP();

    SelectObject(hdc, hfontOld);
    DeleteObject(hfont);
    SelectObject(hdc, hbmpOld);
    DeleteObject(hbmp);
    DeleteDC(hdc);
}
