/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test win32k robustness to region allocation failures
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Debug builds of win32k only, see GDI_DBG_ESCAPE_FAIL_REGION_ALLOC in win32ss/gdi/ntgdi/region.h */
#define ESCAPE_FAIL_REGION_ALLOC 0x7FFE5247

static INT
ArmRegionAllocFailure(LONG lAllowed)
{
    return ExtEscape(NULL, ESCAPE_FAIL_REGION_ALLOC, sizeof(lAllowed), (LPCSTR)&lAllowed, 0, NULL);
}

/* Disarms; TRUE if the armed failure was injected */
static BOOL
Disarm(void)
{
    return ArmRegionAllocFailure(-1) == 2;
}

static BOOL
HaveInjection(void)
{
    INT ret = ArmRegionAllocFailure(-1);
    if (ret != 1 && ret != 2)
    {
        skip("No region allocation failure injection (not a Debug build of win32k)\n");
        return FALSE;
    }
    return TRUE;
}

static void
SetClip(HDC hdc)
{
    HRGN hrgn = CreateRectRgn(0, 0, 50, 50);
    ok(SelectClipRgn(hdc, hrgn) == SIMPLEREGION, "SelectClipRgn failed\n");
    DeleteObject(hrgn);
}

static BOOL
ClipBoxIs(HDC hdc, LONG left, LONG top, LONG right, LONG bottom)
{
    RECT rc;
    GetClipBox(hdc, &rc);
    return rc.left == left && rc.top == top && rc.right == right && rc.bottom == bottom;
}

static HANDLE hArmed, hRelease;
static BOOL bOtherFired;

static DWORD WINAPI
ArmingThread(LPVOID pv)
{
    ArmRegionAllocFailure(0);
    SetEvent(hArmed);
    WaitForSingleObject(hRelease, INFINITE);
    bOtherFired = Disarm();
    return 0;
}

START_TEST(RegionAllocFailClip)
{
    HDC hdc;
    HBITMAP hbmp, hbmpOld;
    HRGN hrgn;
    HANDLE hThread;
    LONG n;
    INT ret, cFired = 0;
    BOOL bFired;

    if (!HaveInjection())
        return;

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    hbmp = CreateBitmap(100, 100, 1, 1, NULL);
    hbmpOld = SelectObject(hdc, hbmp);

    for (n = 0; n < 4; n++)
    {
        /* With a clip region, IntersectClipRect combines into a new region */
        SetClip(hdc);
        ArmRegionAllocFailure(n);
        ret = IntersectClipRect(hdc, 10, 10, 40, 40);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(ret == ERROR, "IntersectClipRect, %ld allowed: %d\n", n, ret);
            ok(ClipBoxIs(hdc, 0, 0, 50, 50), "IntersectClipRect, %ld allowed: clip changed\n", n);
        }
        else
        {
            ok(ret != ERROR, "IntersectClipRect, %ld allowed: %d\n", n, ret);
        }
        ret = IntersectClipRect(hdc, 10, 10, 40, 40);
        ok(ret != ERROR, "IntersectClipRect after %ld allowed: %d\n", n, ret);
        ok(ClipBoxIs(hdc, 10, 10, 40, 40), "IntersectClipRect after %ld allowed: wrong clip\n", n);

        SetClip(hdc);
        ArmRegionAllocFailure(n);
        ret = ExcludeClipRect(hdc, 10, 10, 20, 20);
        bFired = Disarm();
        if (bFired)
        {
            cFired++;
            ok(ret == ERROR, "ExcludeClipRect, %ld allowed: %d\n", n, ret);
        }
        else
        {
            ok(ret != ERROR, "ExcludeClipRect, %ld allowed: %d\n", n, ret);
        }
        ok(ClipBoxIs(hdc, 0, 0, 50, 50), "ExcludeClipRect, %ld allowed: wrong clip box\n", n);

        SetClip(hdc);
        hrgn = CreateRectRgn(20, 20, 80, 80);
        ArmRegionAllocFailure(n);
        ret = ExtSelectClipRgn(hdc, hrgn, RGN_OR);
        bFired = Disarm();
        if (bFired)
            cFired++;
        if (ret == ERROR)
        {
            ok(bFired, "ExtSelectClipRgn RGN_OR, %ld allowed: ERROR without an injected failure\n", n);
            ok(ClipBoxIs(hdc, 0, 0, 50, 50), "ExtSelectClipRgn RGN_OR, %ld allowed: clip changed\n", n);
        }
        else
        {
            ok(ClipBoxIs(hdc, 0, 0, 80, 80), "ExtSelectClipRgn RGN_OR, %ld allowed: wrong clip box\n", n);
        }

        /* Without a clip region, a new one is built from the Vis region; it only must not crash */
        SelectClipRgn(hdc, NULL);
        ArmRegionAllocFailure(n);
        ExtSelectClipRgn(hdc, hrgn, RGN_DIFF);
        if (Disarm())
            cFired++;
        DeleteObject(hrgn);
        SelectClipRgn(hdc, NULL);
    }

    ok(cFired >= 4, "Only %d injected failures reached a clip operation\n", cFired);

    /* An arming in another thread does not affect this one */
    hArmed = CreateEventW(NULL, FALSE, FALSE, NULL);
    hRelease = CreateEventW(NULL, FALSE, FALSE, NULL);
    hThread = CreateThread(NULL, 0, ArmingThread, NULL, 0, NULL);
    WaitForSingleObject(hArmed, INFINITE);
    SetClip(hdc);
    ret = IntersectClipRect(hdc, 10, 10, 40, 40);
    ok(ret != ERROR, "IntersectClipRect failed while another thread was armed: %d\n", ret);
    SetEvent(hRelease);
    WaitForSingleObject(hThread, INFINITE);
    ok(!bOtherFired, "The other thread's arming was consumed by this thread\n");
    CloseHandle(hThread);
    CloseHandle(hArmed);
    CloseHandle(hRelease);

    SelectObject(hdc, hbmpOld);
    DeleteObject(hbmp);
    DeleteDC(hdc);
}

static void
PumpMessages(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);
}

START_TEST(RegionAllocFailVis)
{
    HWND hwnd, hwndChild1, hwndChild2;
    HDC hdc;
    HRGN hrgn;
    LONG n;
    INT cFired = 0;

    if (!HaveInjection())
        return;

    hwnd = CreateWindowExW(0, L"static", L"RegionAllocFail", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           50, 50, 300, 200, NULL, NULL, NULL, NULL);
    ok(hwnd != NULL, "CreateWindowExW failed\n");
    hwndChild1 = CreateWindowExW(0, L"static", L"1", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                 10, 10, 120, 80, hwnd, NULL, NULL, NULL);
    hwndChild2 = CreateWindowExW(0, L"static", L"2", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                 60, 40, 120, 80, hwnd, NULL, NULL, NULL);
    ok(hwndChild1 != NULL && hwndChild2 != NULL, "child windows not created\n");
    PumpMessages();

    for (n = 0; n < 12; n++)
    {
        /* GetDC computes the visible region of the child, clipped by its parent and sibling */
        ArmRegionAllocFailure(n);
        hdc = GetDC(hwndChild1);
        if (Disarm())
            cFired++;
        if (hdc)
            ReleaseDC(hwndChild1, hdc);

        ArmRegionAllocFailure(n);
        SetWindowPos(hwndChild2, NULL, 60 + (n % 3), 40, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        if (Disarm())
            cFired++;

        ArmRegionAllocFailure(n);
        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);
        if (Disarm())
            cFired++;

        ArmRegionAllocFailure(n);
        SetWindowPos(hwnd, NULL, 50 + n, 50, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        if (Disarm())
            cFired++;

        /* Scrolling with pending damage returns it through the caller's region */
        InvalidateRect(hwnd, NULL, FALSE);
        hrgn = CreateRectRgn(0, 0, 0, 0);
        ArmRegionAllocFailure(n);
        ScrollWindowEx(hwnd, 2, 0, NULL, NULL, hrgn, NULL, SW_INVALIDATE | SW_SCROLLCHILDREN);
        if (Disarm())
            cFired++;
        DeleteObject(hrgn);
        PumpMessages();
    }

    ok(cFired >= 12, "Only %d injected failures reached a window operation\n", cFired);

    /* Everything still works once nothing fails */
    hdc = GetDC(hwndChild1);
    ok(hdc != NULL, "GetDC failed after the injected failures\n");
    if (hdc)
        ReleaseDC(hwndChild1, hdc);
    ok(RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN), "RedrawWindow failed\n");

    DestroyWindow(hwnd);
}

/* Debug builds of win32k only, see GDI_DBG_ESCAPE_FAIL_REGION_BUFFER in win32ss/gdi/ntgdi/region.h */
#define ESCAPE_FAIL_REGION_BUFFER 0x7FFE5242

static INT
ArmRegionBufferFailure(LONG lAllowed)
{
    return ExtEscape(NULL, ESCAPE_FAIL_REGION_BUFFER, sizeof(lAllowed), (LPCSTR)&lAllowed, 0, NULL);
}

static HRGN
MakeComb(INT x)
{
    HRGN hrgn = CreateRectRgn(x, 0, x + 10, 10), hrgn2;
    INT i;

    for (i = 1; i < 6; i++)
    {
        hrgn2 = CreateRectRgn(x + i * 7, i * 15, x + i * 7 + 20, i * 15 + 10);
        CombineRgn(hrgn, hrgn, hrgn2, RGN_OR);
        DeleteObject(hrgn2);
    }
    return hrgn;
}

static BOOL
SameRegion(HRGN hrgn1, HRGN hrgn2)
{
    return EqualRgn(hrgn1, hrgn2);
}

/* A region operation that cannot get its rectangle buffer fails and leaves the destination as it was */
START_TEST(RegionAllocFailCombine)
{
    static const INT Modes[] = { RGN_AND, RGN_OR, RGN_XOR, RGN_DIFF };
    HRGN hrgnDst, hrgnSrc, hrgnBefore, hrgnExpected, hrgnOther;
    INT ret, iMode, cFired = 0;
    LONG n;
    BOOL bFired;

    ret = ArmRegionBufferFailure(-1);
    if (ret != 1 && ret != 2)
    {
        skip("No region buffer allocation failure injection (not a Debug build of win32k)\n");
        return;
    }

    for (iMode = 0; iMode < 4; iMode++)
    {
        for (n = 0; n < 3; n++)
        {
            /* the destination is one of the sources */
            hrgnDst = MakeComb(0);
            hrgnSrc = MakeComb(5);
            hrgnBefore = MakeComb(0);
            hrgnExpected = MakeComb(0);
            CombineRgn(hrgnExpected, hrgnExpected, hrgnSrc, Modes[iMode]);

            ArmRegionBufferFailure(n);
            ret = CombineRgn(hrgnDst, hrgnDst, hrgnSrc, Modes[iMode]);
            bFired = ArmRegionBufferFailure(-1) == 2;
            if (bFired)
            {
                cFired++;
                ok(ret == ERROR, "mode %d, %ld allowed: %d without memory\n", Modes[iMode], n, ret);
                ok(SameRegion(hrgnDst, hrgnBefore), "mode %d, %ld allowed: the destination changed\n", Modes[iMode], n);
            }
            else
            {
                ok(ret != ERROR, "mode %d, %ld allowed: ERROR\n", Modes[iMode], n);
                ok(SameRegion(hrgnDst, hrgnExpected), "mode %d, %ld allowed: wrong result\n", Modes[iMode], n);
            }

            /* it works once nothing fails */
            DeleteObject(hrgnDst);
            hrgnDst = MakeComb(0);
            ret = CombineRgn(hrgnDst, hrgnDst, hrgnSrc, Modes[iMode]);
            ok(ret != ERROR, "mode %d after %ld allowed: ERROR\n", Modes[iMode], n);
            ok(SameRegion(hrgnDst, hrgnExpected), "mode %d after %ld allowed: wrong result\n", Modes[iMode], n);

            /* a destination that is not a source */
            hrgnOther = CreateRectRgn(100, 100, 110, 110);
            DeleteObject(hrgnBefore);
            hrgnBefore = CreateRectRgn(100, 100, 110, 110);
            ArmRegionBufferFailure(n);
            ret = CombineRgn(hrgnOther, hrgnDst, hrgnSrc, Modes[iMode]);
            if (ArmRegionBufferFailure(-1) == 2)
            {
                cFired++;
                ok(ret == ERROR, "mode %d into another region, %ld allowed: %d without memory\n", Modes[iMode], n, ret);
                ok(SameRegion(hrgnOther, hrgnBefore), "mode %d into another region, %ld allowed: it changed\n",
                   Modes[iMode], n);
            }

            DeleteObject(hrgnOther);
            DeleteObject(hrgnDst);
            DeleteObject(hrgnSrc);
            DeleteObject(hrgnBefore);
            DeleteObject(hrgnExpected);
        }
    }
    ok(cFired >= 4, "Only %d injected failures reached a region operation\n", cFired);
}
