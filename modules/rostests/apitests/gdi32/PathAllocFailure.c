/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test win32k robustness to path allocation failures
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Each row makes one allocation of a new path fail (the path object, its point array or its flag array) inside
 * one call: the call must fail with ERROR_NOT_ENOUGH_MEMORY or succeed without the failed part, and the DC must
 * work afterwards. Before the fix these calls dereferenced the missing path (a kernel stop).
 */

#include "precomp.h"

/* Debug builds of win32k only, see GDI_DBG_ESCAPE_FAIL_PATH_ALLOC in win32ss/gdi/ntgdi/path.h */
#define ESCAPE_FAIL_PATH_ALLOC 0x7FFE5048

static INT
ArmPathAllocFailure(LONG lAllowed)
{
    return ExtEscape(NULL, ESCAPE_FAIL_PATH_ALLOC, sizeof(lAllowed), (LPCSTR)&lAllowed, 0, NULL);
}

/* Disarms; TRUE if the armed failure was injected */
static BOOL
Disarm(void)
{
    return ArmPathAllocFailure(-1) == 2;
}

static BOOL
MakeClosedPath(HDC hdc)
{
    POINT pts[3] = { { 30, 10 }, { 60, 40 }, { 20, 60 } };

    if (!BeginPath(hdc))
        return FALSE;
    MoveToEx(hdc, 10, 10, NULL);
    PolyBezierTo(hdc, pts, 3);
    LineTo(hdc, 80, 80);
    CloseFigure(hdc);
    return EndPath(hdc);
}

static INT
PathPoints(HDC hdc)
{
    return GetPath(hdc, NULL, NULL, 0);
}

typedef BOOL (WINAPI *PDRAWPATH)(HDC);

static void
TestDrawPath(HDC hdc, PDRAWPATH pfn, PCSTR Name)
{
    LONG n;
    INT cPoints, cFired = 0;
    BOOL ret, bFired;

    for (n = 0; n < 3; n++)
    {
        ok(MakeClosedPath(hdc), "%s, %ld allowed: no path\n", Name, n);
        cPoints = PathPoints(hdc);
        ok(cPoints > 0, "%s, %ld allowed: %d points\n", Name, n, cPoints);

        SetLastError(0xdeadbeef);
        ArmPathAllocFailure(n);
        ret = pfn(hdc);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(!ret, "%s, %ld allowed: TRUE without memory\n", Name, n);
            ok(GetLastError() == ERROR_NOT_ENOUGH_MEMORY, "%s, %ld allowed: error %lu\n", Name, n, GetLastError());
            /* nothing was drawn: the path is still there and can be drawn now */
            ok(PathPoints(hdc) == cPoints, "%s, %ld allowed: path has %d points, expected %d\n",
               Name, n, PathPoints(hdc), cPoints);
            ok(pfn(hdc), "%s after %ld allowed: failed with %lu\n", Name, n, GetLastError());
        }
        else
        {
            ok(ret, "%s, %ld allowed: failed with %lu\n", Name, n, GetLastError());
        }
        ok(PathPoints(hdc) == -1, "%s, %ld allowed: the path is still there\n", Name, n);
    }
    ok(cFired == 3, "%s: %d of 3 failures injected\n", Name, cFired);
}

START_TEST(PathAllocFailure)
{
    HDC hdc;
    HBITMAP hbmp, hbmpOld;
    HPEN hpen, hpenOld;
    POINT pts[4] = { { 10, 10 }, { 90, 10 }, { 90, 90 }, { 10, 90 } };
    LONG n;
    INT ret, cFired;
    BOOL bRet, bFired;

    ret = ArmPathAllocFailure(-1);
    if (ret != 1 && ret != 2)
    {
        skip("No path allocation failure injection (not a Debug build of win32k)\n");
        return;
    }

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    hbmp = CreateBitmap(100, 100, 1, 1, NULL);
    hbmpOld = SelectObject(hdc, hbmp);

    /* BeginPath: no path is made, a later one works */
    cFired = 0;
    for (n = 0; n < 3; n++)
    {
        SetLastError(0xdeadbeef);
        ArmPathAllocFailure(n);
        bRet = BeginPath(hdc);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(!bRet, "BeginPath, %ld allowed: TRUE without memory\n", n);
            ok(GetLastError() == ERROR_NOT_ENOUGH_MEMORY, "BeginPath, %ld allowed: error %lu\n", n, GetLastError());
            ok(!EndPath(hdc), "EndPath after a failed BeginPath, %ld allowed: TRUE\n", n);
        }
        else
        {
            ok(bRet, "BeginPath, %ld allowed: failed with %lu\n", n, GetLastError());
            AbortPath(hdc);
        }
        ok(MakeClosedPath(hdc), "BeginPath after %ld allowed: no path\n", n);
        ok(PathPoints(hdc) > 0, "BeginPath after %ld allowed: %d points\n", n, PathPoints(hdc));
        AbortPath(hdc);
    }
    ok(cFired == 3, "BeginPath: %d of 3 failures injected\n", cFired);

    /* FillPath, StrokePath and StrokeAndFillPath flatten the path into a new one first */
    TestDrawPath(hdc, FillPath, "FillPath");
    TestDrawPath(hdc, StrokePath, "StrokePath");
    TestDrawPath(hdc, StrokeAndFillPath, "StrokeAndFillPath");

    /* SaveDC copies the path, RestoreDC copies it back */
    cFired = 0;
    for (n = 0; n < 3; n++)
    {
        INT iSave;

        ok(MakeClosedPath(hdc), "SaveDC, %ld allowed: no path\n", n);
        ArmPathAllocFailure(n);
        iSave = SaveDC(hdc);
        if (Disarm())
            cFired++;
        ok(iSave > 0, "SaveDC, %ld allowed: %d\n", n, iSave);
        AbortPath(hdc);
        ArmPathAllocFailure(n);
        RestoreDC(hdc, -1);
        if (Disarm())
            cFired++;
        /* with or without the path, the DC works */
        AbortPath(hdc);
        ok(MakeClosedPath(hdc), "after SaveDC/RestoreDC, %ld allowed: no path\n", n);
        AbortPath(hdc);
    }
    ok(cFired >= 3, "SaveDC/RestoreDC: %d failures injected\n", cFired);

    /* Polygon with a wide pen outlines through a path */
    hpen = CreatePen(PS_SOLID, 5, RGB(0, 0, 0));
    hpenOld = SelectObject(hdc, hpen);
    cFired = 0;
    for (n = 0; n < 3; n++)
    {
        ArmPathAllocFailure(n);
        bRet = Polygon(hdc, pts, 4);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(!bRet, "Polygon with a wide pen, %ld allowed: TRUE without the outline\n", n);
        }
        else
        {
            ok(bRet, "Polygon with a wide pen, %ld allowed: failed\n", n);
        }
        ok(Polygon(hdc, pts, 4), "Polygon with a wide pen after %ld allowed: failed\n", n);
    }
    ok(cFired == 3, "Polygon: %d of 3 failures injected\n", cFired);

    /* LineTo, Polyline and Rectangle with a wide pen stroke a path too */
    cFired = 0;
    for (n = 0; n < 3; n++)
    {
        POINT pt;

        MoveToEx(hdc, 5, 5, NULL);
        ArmPathAllocFailure(n);
        bRet = LineTo(hdc, 50, 60);
        bFired = Disarm();
        GetCurrentPositionEx(hdc, &pt);
        if (bFired)
        {
            cFired++;
            ok(!bRet, "LineTo with a wide pen, %ld allowed: TRUE without the path\n", n);
            ok(pt.x == 5 && pt.y == 5, "LineTo with a wide pen, %ld allowed: moved to (%ld,%ld)\n", n, pt.x, pt.y);
        }
        else
        {
            ok(bRet, "LineTo with a wide pen, %ld allowed: failed\n", n);
        }
        ok(LineTo(hdc, 50, 60), "LineTo with a wide pen after %ld allowed: failed\n", n);

        ArmPathAllocFailure(n);
        bRet = Polyline(hdc, pts, 4);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(!bRet, "Polyline with a wide pen, %ld allowed: TRUE without the path\n", n);
        }
        else
        {
            ok(bRet, "Polyline with a wide pen, %ld allowed: failed\n", n);
        }
        ok(Polyline(hdc, pts, 4), "Polyline with a wide pen after %ld allowed: failed\n", n);

        ArmPathAllocFailure(n);
        bRet = Rectangle(hdc, 10, 10, 80, 80);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(!bRet, "Rectangle with a wide pen, %ld allowed: TRUE without the outline\n", n);
        }
        else
        {
            ok(bRet, "Rectangle with a wide pen, %ld allowed: failed\n", n);
        }
        ok(Rectangle(hdc, 10, 10, 80, 80), "Rectangle with a wide pen after %ld allowed: failed\n", n);
    }
    ok(cFired == 9, "LineTo, Polyline, Rectangle: %d of 9 failures injected\n", cFired);
    SelectObject(hdc, hpenOld);
    DeleteObject(hpen);

    SelectObject(hdc, hbmpOld);
    DeleteObject(hbmp);
    DeleteDC(hdc);
}
