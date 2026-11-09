/*
 * PROJECT:     NitroOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Redirection surfaces of windows: allocation and presentation on the screen (GDI side)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * With NitroRedirection (ntuser/redir.c), a top-level window draws into a 32 bpp surface of its own,
 * the size of its window rectangle. Its DCs select that surface (GreRedirBindDC, dclife.c) and the
 * window's content is copied onto the screen through its visible region when it changed or moved
 * (GreRedirPresent). The surface keeps the content when the window is covered.
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

/*
 * A new surface of cx x cy. Its bits are a paging-file-backed section (not pool), zeroed. With
 * hbmOld, the part both have in common is copied over (a resize keeps what the window drew).
 */
HBITMAP
NTAPI
GreRedirCreateSurface(
    _In_ LONG cx,
    _In_ LONG cy,
    _In_opt_ HBITMAP hbmOld)
{
    SIZEL sizl;
    HBITMAP hbm;

    sizl.cx = cx;
    sizl.cy = cy;
    hbm = EngCreateBitmap(sizl, 0, BMF_32BPP, BMF_TOPDOWN | BMF_KMSECTION, NULL);
    if (!hbm)
        return NULL;

    if (hbmOld)
    {
        SURFACE *psurfNew = SURFACE_ShareLockSurface(hbm);
        SURFACE *psurfOld = SURFACE_ShareLockSurface(hbmOld);

        if (psurfNew && psurfOld)
        {
            RECTL rcl;
            POINTL ptl = { 0, 0 };

            rcl.left = rcl.top = 0;
            rcl.right = min(cx, psurfOld->SurfObj.sizlBitmap.cx);
            rcl.bottom = min(cy, psurfOld->SurfObj.sizlBitmap.cy);
            if (rcl.right > 0 && rcl.bottom > 0)
                EngCopyBits(&psurfNew->SurfObj, &psurfOld->SurfObj, NULL, NULL, &rcl, &ptl);
        }
        if (psurfOld)
            SURFACE_ShareUnlockSurface(psurfOld);
        if (psurfNew)
            SURFACE_ShareUnlockSurface(psurfNew);
    }
    return hbm;
}

/*
 * Copies the surface of a window whose window rectangle starts at xWnd, yWnd on the screen onto the
 * screen, through prgnScreen (screen coordinates: the part of the window that is visible). The pointer
 * is taken off while it is drawn, under the device lock, as for any drawing on the screen.
 */
BOOL
NTAPI
GreRedirPresent(
    _In_ HBITMAP hbmSurface,
    _In_ PREGION prgnScreen,
    _In_ LONG xWnd,
    _In_ LONG yWnd)
{
    PPDEVOBJ ppdev;
    SURFACE *psurf, *psurfScreen;
    RECTL rcBounds, rcLimit;
    POINTL ptlSrc;
    XCLIPOBJ xco;
    EXLATEOBJ exlo;
    BOOL bRet = TRUE;

    if (!gpmdev || !(ppdev = gpmdev->ppdevGlobal))
        return FALSE;
    if (!prgnScreen || prgnScreen->rdh.nCount == 0)
        return TRUE;

    psurf = SURFACE_ShareLockSurface(hbmSurface);
    if (!psurf)
        return FALSE;

    EngAcquireSemaphore(ppdev->hsemDevLock);
    psurfScreen = ppdev->pSurface;
    if (psurfScreen)
    {
        /* The visible part, on the screen and on the surface */
        rcLimit.left = rcLimit.top = 0;
        rcLimit.right = psurfScreen->SurfObj.sizlBitmap.cx;
        rcLimit.bottom = psurfScreen->SurfObj.sizlBitmap.cy;
        if (RECTL_bIntersectRect(&rcBounds, &prgnScreen->rdh.rcBound, &rcLimit))
        {
            rcLimit.left = xWnd;
            rcLimit.top = yWnd;
            rcLimit.right = xWnd + psurf->SurfObj.sizlBitmap.cx;
            rcLimit.bottom = yWnd + psurf->SurfObj.sizlBitmap.cy;
            if (RECTL_bIntersectRect(&rcBounds, &rcBounds, &rcLimit))
            {
                IntEngInitClipObj(&xco);
                IntEngUpdateClipRegion(&xco, prgnScreen->rdh.nCount, prgnScreen->Buffer, &rcBounds);
                EXLATEOBJ_vInitialize(&exlo, psurf->ppal, psurfScreen->ppal, 0, 0, 0);
                ptlSrc.x = rcBounds.left - xWnd;
                ptlSrc.y = rcBounds.top - yWnd;

                MouseSafetyOnDrawStart(ppdev, rcBounds.left, rcBounds.top, rcBounds.right, rcBounds.bottom);
                bRet = IntEngBitBlt(&psurfScreen->SurfObj, &psurf->SurfObj, NULL, (CLIPOBJ *)&xco, &exlo.xlo,
                                    &rcBounds, &ptlSrc, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY));
                MouseSafetyOnDrawEnd(ppdev);

                EXLATEOBJ_vCleanup(&exlo);
                IntEngFreeClipResources(&xco);
            }
        }
    }
    EngReleaseSemaphore(ppdev->hsemDevLock);
    SURFACE_ShareUnlockSurface(psurf);
    return bRet;
}
