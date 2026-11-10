/*
 * PROJECT:     NitroOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Redirection surfaces of windows: allocation and presentation on the screen (GDI side)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * With NitroRedirection (ntuser/redir.c), a top-level window draws into a 32 bpp surface of its own,
 * the size of its window rectangle. Its DCs select that surface (GreRedirBindDC, dclife.c) and what the
 * window drew is copied onto the screen through its visible region (GreRedirPresent). The surface keeps
 * the content when the window is covered.
 *
 * The surface is used by pointer only. Its handle is owned by the System process, which no user-mode
 * caller is, so no process can lock it, select it into a DC or read or write it through the handle.
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

/*
 * A new surface of cx x cy, referenced for the caller (GreRedirDeleteSurface lets it go). Its bits are a
 * paging-file-backed section (not pool), zeroed. With psurfOld, the part both have in common is copied
 * over (a resize keeps what the window drew).
 */
PSURFACE
NTAPI
GreRedirCreateSurface(
    _In_ LONG cx,
    _In_ LONG cy,
    _In_opt_ PSURFACE psurfOld)
{
    PSURFACE psurf;

    psurf = SURFACE_AllocSurface(STYPE_BITMAP, cx, cy, BMF_32BPP, BMF_TOPDOWN | BMF_KMSECTION, 0, 0, NULL);
    if (!psurf)
        return NULL;

    /*
     * Deliberately no API_BITMAP (EngCreateBitmap sets it): NtGdiSelectBitmap, GetBitmapBits and SetBitmapBits
     * refuse a surface without it. Part of what keeps window pixels away from other processes; do not add it.
     */

    /*
     * No process may reach it through its handle: owned by the System process, which no caller of the
     * user-mode GDI calls is (GDI_OBJ_HMGR_NONE would turn into PUBLIC). The reference stays with the caller.
     */
    GDIOBJ_vSetObjectOwner(&psurf->BaseObject, HandleToUlong(PsGetProcessId(PsInitialSystemProcess)));
    GDIOBJ_vReferenceObjectByPointer(&psurf->BaseObject);
    SURFACE_UnlockSurface(psurf);

    if (psurfOld)
    {
        RECTL rcl;
        POINTL ptl = { 0, 0 };

        rcl.left = rcl.top = 0;
        rcl.right = min(cx, psurfOld->SurfObj.sizlBitmap.cx);
        rcl.bottom = min(cy, psurfOld->SurfObj.sizlBitmap.cy);
        if (rcl.right > 0 && rcl.bottom > 0)
            EngCopyBits(&psurf->SurfObj, &psurfOld->SurfObj, NULL, NULL, &rcl, &ptl);
    }
    return psurf;
}

/* Lets go of the reference GreRedirCreateSurface gave; the surface goes when no DC holds it any more */
VOID
NTAPI
GreRedirDeleteSurface(
    _In_ PSURFACE psurf)
{
    /*
     * The handle dies first (GDIOBJ_vDeleteObject clears its valid bit, so no lookup succeeds any more), and
     * only then is the object public again (process-owned objects are counted against the process that frees
     * them). An extra reference keeps it alive for that step.
     */
    GDIOBJ_vReferenceObjectByPointer(&psurf->BaseObject);
    GDIOBJ_vDeleteObject(&psurf->BaseObject);
    GDIOBJ_vSetObjectOwner(&psurf->BaseObject, GDI_OBJ_HMGR_PUBLIC);
    GDIOBJ_vDereferenceObject(&psurf->BaseObject);
}

/* Copies between the screen and a window surface through prgnScreen (screen coordinates); bToScreen: present, else seed */
static
BOOL
RedirScreenCopy(
    _In_ PSURFACE psurf,
    _In_ PREGION prgnScreen,
    _In_ LONG xWnd,
    _In_ LONG yWnd,
    _In_ BOOL bToScreen)
{
    PPDEVOBJ ppdev;
    SURFACE *psurfScreen;
    RECTL rcBounds, rcLimit;
    POINTL ptlSrc;
    XCLIPOBJ xco;
    EXLATEOBJ exlo;
    PREGION prgnSurf;
    BOOL bRet = TRUE;

    if (!gpmdev || !(ppdev = gpmdev->ppdevGlobal))
        return FALSE;
    if (!psurf || !prgnScreen || prgnScreen->rdh.nCount == 0)
        return TRUE;

    EngAcquireSemaphore(ppdev->hsemDevLock);
    psurfScreen = ppdev->pSurface;
    if (psurfScreen)
    {
        /* The part on the screen and on the surface */
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
                MouseSafetyOnDrawStart(ppdev, rcBounds.left, rcBounds.top, rcBounds.right, rcBounds.bottom);
                if (bToScreen)
                {
                    IntEngUpdateClipRegion(&xco, prgnScreen->rdh.nCount, prgnScreen->Buffer, &rcBounds);
                    EXLATEOBJ_vInitialize(&exlo, psurf->ppal, psurfScreen->ppal, 0, 0, 0);
                    ptlSrc.x = rcBounds.left - xWnd;
                    ptlSrc.y = rcBounds.top - yWnd;
                    bRet = IntEngBitBlt(&psurfScreen->SurfObj, &psurf->SurfObj, NULL, (CLIPOBJ *)&xco, &exlo.xlo,
                                        &rcBounds, &ptlSrc, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY));
                    EXLATEOBJ_vCleanup(&exlo);
                }
                else
                {
                    /* Into the surface: the same region in surface coordinates */
                    prgnSurf = IntSysCreateRectpRgn(0, 0, 0, 0);
                    if (prgnSurf && REGION_bCopy(prgnSurf, prgnScreen))
                    {
                        REGION_bOffsetRgn(prgnSurf, -xWnd, -yWnd);
                        RECTL_vOffsetRect(&rcBounds, -xWnd, -yWnd);
                        IntEngUpdateClipRegion(&xco, prgnSurf->rdh.nCount, prgnSurf->Buffer, &rcBounds);
                        EXLATEOBJ_vInitialize(&exlo, psurfScreen->ppal, psurf->ppal, 0, 0, 0);
                        ptlSrc.x = rcBounds.left + xWnd;
                        ptlSrc.y = rcBounds.top + yWnd;
                        bRet = EngCopyBits(&psurf->SurfObj, &psurfScreen->SurfObj, (CLIPOBJ *)&xco, &exlo.xlo,
                                           &rcBounds, &ptlSrc);
                        EXLATEOBJ_vCleanup(&exlo);
                    }
                    if (prgnSurf)
                        REGION_Delete(prgnSurf);
                }
                MouseSafetyOnDrawEnd(ppdev);
                IntEngFreeClipResources(&xco);
            }
        }
    }
    EngReleaseSemaphore(ppdev->hsemDevLock);
    return bRet;
}

/* Copies the surface of a window whose window rectangle starts at xWnd, yWnd onto the screen, through prgnScreen */
BOOL
NTAPI
GreRedirPresent(
    _In_ PSURFACE psurf,
    _In_ PREGION prgnScreen,
    _In_ LONG xWnd,
    _In_ LONG yWnd)
{
    return RedirScreenCopy(psurf, prgnScreen, xWnd, yWnd, TRUE);
}

/* Copies what the screen shows of a window (prgnScreen) into its new surface */
BOOL
NTAPI
GreRedirSeedFromScreen(
    _In_ PSURFACE psurf,
    _In_ PREGION prgnScreen,
    _In_ LONG xWnd,
    _In_ LONG yWnd)
{
    return RedirScreenCopy(psurf, prgnScreen, xWnd, yWnd, FALSE);
}
