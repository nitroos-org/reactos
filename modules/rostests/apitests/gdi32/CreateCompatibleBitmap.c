/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for CreateCompatibleBitmap and for gdi32 calls on a DC without a user mode DC_ATTR
 *
 * win32k keeps going when it cannot allocate the user mode DC_ATTR of a new DC (the GDI handle table
 * entry then has a NULL pUser and the kernel uses its own copy). gdi32 must cope with that.
 * kbswitch.exe died in CreateCompatibleBitmap dereferencing that NULL pointer.
 */

#include "precomp.h"

#include "../gditools/gditools.h"

#define MAX_RESERVATIONS 40000
#define MAX_DCS          3000

static
void
Test_Basic(void)
{
    HDC hdcScreen, hdc;
    HBITMAP hbmp;
    BITMAP bm;

    hdcScreen = GetDC(NULL);
    ok(hdcScreen != NULL, "GetDC failed\n");

    hbmp = CreateCompatibleBitmap(hdcScreen, 16, 8);
    ok(hbmp != NULL, "CreateCompatibleBitmap failed, error %lu\n", GetLastError());
    if (hbmp)
    {
        ok_int(GetObject(hbmp, sizeof(bm), &bm), sizeof(bm));
        ok_int(bm.bmWidth, 16);
        ok_int(bm.bmHeight, 8);
        DeleteObject(hbmp);
    }

    hbmp = CreateCompatibleBitmap(hdcScreen, 0, 8);
    ok(hbmp == GetStockObject(DEFAULT_BITMAP), "Expected the stock bitmap, got %p\n", hbmp);

    hbmp = CreateCompatibleBitmap((HDC)(ULONG_PTR)0x123456, 16, 8);
    ok(hbmp == NULL, "Expected NULL for an invalid DC, got %p\n", hbmp);

    hdc = CreateCompatibleDC(hdcScreen);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    if (hdc)
    {
        hbmp = CreateCompatibleBitmap(hdc, 4, 4);
        ok(hbmp != NULL, "CreateCompatibleBitmap on a memory DC failed\n");
        if (hbmp)
            DeleteObject(hbmp);
        DeleteDC(hdc);
    }

    ReleaseDC(NULL, hdcScreen);
}

#ifndef _WIN64
typedef struct
{
    BOOL bFound;
    BOOL bBitmap;
    BOOL bSetBrushOrg;
    BOOL bGetBrushOrg;
    BOOL bCancelDC;
    BOOL bColorSpace;
    BOOL bIcon;
    ULONG cDCs;
    ULONG cNoAttr;
} NOATTR_RESULT;

/* Fill the address space so that win32k cannot reserve a new 64 KB DC_ATTR pool section, create
   DCs until one comes back without a DC_ATTR and call the functions that used to dereference it.
   Everything the test needs is allocated up front and the results are only reported afterwards,
   because nothing can allocate address space meanwhile. */
static
void
Test_NoDcAttr(void)
{
    PVOID *apvReserved;
    HDC *ahdc;
    ULONG cReserved = 0, i;
    NOATTR_RESULT res = { 0 };
    HDC hdcNoAttr = NULL;

    apvReserved = HeapAlloc(GetProcessHeap(), 0, MAX_RESERVATIONS * sizeof(PVOID));
    ahdc = HeapAlloc(GetProcessHeap(), 0, MAX_DCS * sizeof(HDC));
    if (!apvReserved || !ahdc)
    {
        skip("Out of memory\n");
        goto cleanup;
    }

    /* Exhaust the address space, then keep creating DCs until the existing pool section is full. */
    while (cReserved < MAX_RESERVATIONS)
    {
        PVOID pv = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS);
        if (!pv)
            break;
        apvReserved[cReserved++] = pv;
    }

    for (i = 0; i < MAX_DCS; i++)
    {
        HDC hdc = CreateCompatibleDC(NULL);
        if (!hdc)
            break;
        ahdc[res.cDCs++] = hdc;
        if (GdiGetHandleUserData(hdc) == NULL)
        {
            res.cNoAttr++;
            if (!hdcNoAttr)
                hdcNoAttr = hdc;
        }
    }

    if (hdcNoAttr)
    {
        HBITMAP hbmp;
        POINT pt = { 0 };
        ICONINFO ii;
        HBITMAP hbmMask;
        HICON hIcon;

        res.bFound = TRUE;

        hbmp = CreateCompatibleBitmap(hdcNoAttr, 16, 16);
        res.bBitmap = (hbmp != NULL);
        if (hbmp)
            DeleteObject(hbmp);

        res.bSetBrushOrg = SetBrushOrgEx(hdcNoAttr, 3, 4, NULL);
        /* the value cannot be read back from user mode without DC_ATTR, it must not crash */
        (void)GetBrushOrgEx(hdcNoAttr, &pt);
        res.bGetBrushOrg = TRUE;
        res.bCancelDC = CancelDC(hdcNoAttr);
        (void)GetColorSpace(hdcNoAttr);
        res.bColorSpace = TRUE;

        /* what kbswitch does: build an icon from a bitmap created for a screen-like DC */
        hbmp = CreateCompatibleBitmap(hdcNoAttr, 16, 16);
        hbmMask = CreateBitmap(16, 16, 1, 1, NULL);
        if (hbmp && hbmMask)
        {
            ii.fIcon = TRUE;
            ii.xHotspot = ii.yHotspot = 0;
            ii.hbmColor = hbmp;
            ii.hbmMask = hbmMask;
            hIcon = CreateIconIndirect(&ii);
            res.bIcon = (hIcon != NULL);
            if (hIcon)
                DestroyIcon(hIcon);
        }
        if (hbmp)
            DeleteObject(hbmp);
        if (hbmMask)
            DeleteObject(hbmMask);
    }

cleanup:
    for (i = 0; ahdc && i < res.cDCs; i++)
        DeleteDC(ahdc[i]);
    for (i = 0; i < cReserved; i++)
        VirtualFree(apvReserved[i], 0, MEM_RELEASE);
    if (ahdc)
        HeapFree(GetProcessHeap(), 0, ahdc);
    if (apvReserved)
        HeapFree(GetProcessHeap(), 0, apvReserved);

    if (!res.bFound)
    {
        skip("Could not create a DC without DC_ATTR (%lu DCs, %lu reservations)\n", res.cDCs, cReserved);
        return;
    }

    trace("%lu DCs, %lu without DC_ATTR\n", res.cDCs, res.cNoAttr);
    ok(res.bBitmap, "CreateCompatibleBitmap failed on a DC without DC_ATTR\n");
    ok(res.bSetBrushOrg, "SetBrushOrgEx failed on a DC without DC_ATTR\n");
    ok(res.bGetBrushOrg, "GetBrushOrgEx\n");
    ok(res.bCancelDC, "CancelDC failed on a DC without DC_ATTR\n");
    ok(res.bColorSpace, "GetColorSpace\n");
    ok(res.bIcon, "CreateIconIndirect failed with a bitmap of a DC without DC_ATTR\n");
}
#endif /* !_WIN64 */

START_TEST(CreateCompatibleBitmap)
{
    Test_Basic();
#ifndef _WIN64
    Test_NoDcAttr();
#else
    skip("A 64 bit process cannot run out of address space\n");
#endif
}
