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

/* A present of up to this many rectangles copies them one by one (the pointer hidden around each one only) */
#define REDIR_PRESENT_SPLIT 32

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
            /* The window position is the caller's: its far edge is summed in 64 bits and clipped to rcBounds (the screen) */
            LONGLONG xr = (LONGLONG)xWnd + psurf->SurfObj.sizlBitmap.cx;
            LONGLONG yb = (LONGLONG)yWnd + psurf->SurfObj.sizlBitmap.cy;

            rcLimit.left = xWnd;
            rcLimit.top = yWnd;
            rcLimit.right = (LONG)min(xr, (LONGLONG)rcBounds.right);
            rcLimit.bottom = (LONG)min(yb, (LONGLONG)rcBounds.bottom);
            if (RECTL_bIntersectRect(&rcBounds, &rcBounds, &rcLimit))
            {
                IntEngInitClipObj(&xco);
                if (bToScreen && prgnScreen->rdh.nCount <= REDIR_PRESENT_SPLIT)
                {
                    /*
                     * Rectangle by rectangle: the pointer is hidden only while a rectangle it is over is copied, not
                     * over the bounds of all of them (a window that draws a few lines and a caret far apart)
                     */
                    ULONG i;

                    EXLATEOBJ_vInitialize(&exlo, psurf->ppal, psurfScreen->ppal, 0, 0, 0);
                    for (i = 0; i < prgnScreen->rdh.nCount; i++)
                    {
                        RECTL rcPiece;

                        if (!RECTL_bIntersectRect(&rcPiece, &prgnScreen->Buffer[i], &rcBounds))
                            continue;
                        ptlSrc.x = rcPiece.left - xWnd;
                        ptlSrc.y = rcPiece.top - yWnd;
                        MouseSafetyOnDrawStart(ppdev, rcPiece.left, rcPiece.top, rcPiece.right, rcPiece.bottom);
                        if (!IntEngBitBlt(&psurfScreen->SurfObj, &psurf->SurfObj, NULL, NULL, &exlo.xlo,
                                          &rcPiece, &ptlSrc, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)))
                        {
                            bRet = FALSE;
                        }
                        MouseSafetyOnDrawEnd(ppdev);
                    }
                    EXLATEOBJ_vCleanup(&exlo);
                }
                else if (bToScreen)
                {
                    MouseSafetyOnDrawStart(ppdev, rcBounds.left, rcBounds.top, rcBounds.right, rcBounds.bottom);
                    IntEngUpdateClipRegion(&xco, prgnScreen->rdh.nCount, prgnScreen->Buffer, &rcBounds);
                    EXLATEOBJ_vInitialize(&exlo, psurf->ppal, psurfScreen->ppal, 0, 0, 0);
                    ptlSrc.x = rcBounds.left - xWnd;
                    ptlSrc.y = rcBounds.top - yWnd;
                    bRet = IntEngBitBlt(&psurfScreen->SurfObj, &psurf->SurfObj, NULL, (CLIPOBJ *)&xco, &exlo.xlo,
                                        &rcBounds, &ptlSrc, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY));
                    EXLATEOBJ_vCleanup(&exlo);
                    MouseSafetyOnDrawEnd(ppdev);
                }
                else
                {
                    MouseSafetyOnDrawStart(ppdev, rcBounds.left, rcBounds.top, rcBounds.right, rcBounds.bottom);
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
                    MouseSafetyOnDrawEnd(ppdev);
                }
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

/*
 * Level 2 (NitroRedirection 2): a compose pass builds what the screen shows in a frame buffer (psurfFB, whose
 * pixel 0, 0 is at xFB, yFB on the screen), from the bottom window up, and copies it to the screen in one blit.
 * Draws the layer pl through prgnScreen (screen coordinates) into the frame buffer: copied, or blended with
 * what the windows below put there. Both surfaces are 32 bpp B, G, R, A in memory.
 */
static __inline ULONG
RedirMul255(ULONG a, ULONG b)
{
    ULONG t = a * b + 128;
    return (t + (t >> 8)) >> 8;
}

static VOID
RedirBlendRow(PULONG pDst, const ULONG *pSrc, LONG cx, const REDIR_LAYER *pl)
{
    ULONG Mode = pl->Mode & REDIRMODE_MASK, Ca = pl->Alpha;
    BOOL bKey = (pl->Mode & REDIRMODE_KEY) != 0;
    LONG i;

    for (i = 0; i < cx; i++)
    {
        ULONG s = pSrc[i], d, sa, inv;

        if (bKey && (s & 0x00FFFFFF) == pl->Key)
            continue;
        switch (Mode)
        {
            case REDIRMODE_COPY:
                pDst[i] = s;
                continue;
            case REDIRMODE_ALPHA:
                sa = Ca;
                /* Not premultiplied: the colour is scaled by the constant alpha first */
                s = (RedirMul255(s & 0xFF, sa)) | (RedirMul255((s >> 8) & 0xFF, sa) << 8) |
                    (RedirMul255((s >> 16) & 0xFF, sa) << 16);
                break;
            case REDIRMODE_GLASS:
                sa = s >> 24;
                /* GDI leaves alpha 0: such a pixel with a colour is drawn as it is, black with alpha 0 is glass */
                if (sa == 0 && (s & 0x00FFFFFF) != 0)
                {
                    pDst[i] = s | 0xFF000000;
                    continue;
                }
                break;
            default: /* REDIRMODE_PREMUL */
                sa = s >> 24;
                if (Ca != 255)
                {
                    s = (RedirMul255(s & 0xFF, Ca)) | (RedirMul255((s >> 8) & 0xFF, Ca) << 8) |
                        (RedirMul255((s >> 16) & 0xFF, Ca) << 16);
                    sa = RedirMul255(sa, Ca);
                }
                break;
        }
        if (sa == 255)
        {
            pDst[i] = s | 0xFF000000;
            continue;
        }
        /* source + destination * (255 - alpha) / 255, per channel (premultiplied) */
        d = pDst[i];
        inv = 255 - sa;
        {
            ULONG b = (s & 0xFF) + RedirMul255(d & 0xFF, inv);
            ULONG g = ((s >> 8) & 0xFF) + RedirMul255((d >> 8) & 0xFF, inv);
            ULONG r = ((s >> 16) & 0xFF) + RedirMul255((d >> 16) & 0xFF, inv);
            pDst[i] = 0xFF000000 | (min(r, 255) << 16) | (min(g, 255) << 8) | min(b, 255);
        }
    }
}

BOOL
NTAPI
GreRedirComposeLayer(
    _In_ PSURFACE psurfFB,
    _In_ LONG xFB,
    _In_ LONG yFB,
    _In_ const REDIR_LAYER *pl,
    _In_ PREGION prgnScreen)
{
    SURFOBJ *pso = &psurfFB->SurfObj, *psoSrc;
    RECTL rcLimit, rc;
    ULONG i;
    LONG y;

    if (!pl->psurf || !prgnScreen)
        return FALSE;
    psoSrc = &pl->psurf->SurfObj;
    if (pso->iBitmapFormat != BMF_32BPP || psoSrc->iBitmapFormat != BMF_32BPP || !pso->pvScan0 || !psoSrc->pvScan0)
        return FALSE;
    if ((pl->Mode & REDIRMODE_MASK) == REDIRMODE_ALPHA && pl->Alpha == 0)
        return TRUE;

    /* Where both the frame buffer and the layer have pixels (screen coordinates) */
    {
        /* 64-bit: window positions are not bounded; the result lies in the frame buffer, so it fits a LONG */
        LONGLONG l = max((LONGLONG)xFB, (LONGLONG)pl->x), t = max((LONGLONG)yFB, (LONGLONG)pl->y);
        LONGLONG r = min((LONGLONG)xFB + pso->sizlBitmap.cx, (LONGLONG)pl->x + psoSrc->sizlBitmap.cx);
        LONGLONG b = min((LONGLONG)yFB + pso->sizlBitmap.cy, (LONGLONG)pl->y + psoSrc->sizlBitmap.cy);

        if (l >= r || t >= b)
            return TRUE;
        rcLimit.left = (LONG)l;
        rcLimit.top = (LONG)t;
        rcLimit.right = (LONG)r;
        rcLimit.bottom = (LONG)b;
    }

    for (i = 0; i < prgnScreen->rdh.nCount; i++)
    {
        if (!RECTL_bIntersectRect(&rc, &prgnScreen->Buffer[i], &rcLimit))
            continue;
        for (y = rc.top; y < rc.bottom; y++)
        {
            PULONG pDst = (PULONG)((PBYTE)pso->pvScan0 + (LONG_PTR)(y - yFB) * pso->lDelta) + (rc.left - xFB);
            const ULONG *pSrc = (const ULONG *)((PBYTE)psoSrc->pvScan0 + (LONG_PTR)(y - pl->y) * psoSrc->lDelta) + (rc.left - pl->x);

            if (pl->Mode == REDIRMODE_COPY)
                RtlCopyMemory(pDst, pSrc, (rc.right - rc.left) * sizeof(ULONG));
            else
                RedirBlendRow(pDst, pSrc, rc.right - rc.left, pl);
        }
    }
    return TRUE;
}

/* Zeroes the top-left cx x cy of a 32 bpp surface (the frame buffer, before a pass) */
BOOL
NTAPI
GreRedirClearRect(
    _In_ PSURFACE psurf,
    _In_ LONG cx,
    _In_ LONG cy)
{
    SURFOBJ *pso = &psurf->SurfObj;
    LONG y;

    if (pso->iBitmapFormat != BMF_32BPP || !pso->pvScan0 || cx < 0 || cy < 0 ||
        cx > pso->sizlBitmap.cx || cy > pso->sizlBitmap.cy)
    {
        return FALSE;
    }
    for (y = 0; y < cy; y++)
        RtlZeroMemory((PBYTE)pso->pvScan0 + (LONG_PTR)y * pso->lDelta, (SIZE_T)cx * 4);
    return TRUE;
}

/* 32 bpp with bytes B, G, R and a fourth one (alpha), with bits */
static BOOL
RedirIsBgr32(PSURFACE psurf)
{
    PPALETTE ppal = psurf->ppal;

    if (psurf->SurfObj.iBitmapFormat != BMF_32BPP || !psurf->SurfObj.pvScan0 || !ppal || (ppal->flFlags & PAL_INDEXED))
        return FALSE;
    if (ppal->flFlags & PAL_BGR)
        return TRUE;
    return (ppal->flFlags & PAL_BITFIELDS) &&
           ppal->RedMask == 0x00FF0000 && ppal->GreenMask == 0x0000FF00 && ppal->BlueMask == 0x000000FF;
}

/*
 * UpdateLayeredWindow at level 2: copies the bitmap of the memory DC hdcSrc, from xSrc, ySrc, into prclDst of a
 * window's surface, replacing what was there. *pbAlpha: the alpha channel was copied too (a 32 bpp source), so
 * the content has per-pixel alpha. Parts of prclDst the source does not cover are left as they are.
 */
BOOL
NTAPI
GreRedirLoadFromDC(
    _In_ PSURFACE psurfDst,
    _In_ HDC hdcSrc,
    _In_ LONG xSrc,
    _In_ LONG ySrc,
    _In_ const RECTL *prclDst,
    _Out_ PBOOL pbAlpha,
    _Out_ PBOOL pbCopied)
{
    PDC pdc;
    PSURFACE psurfSrc;
    RECTL rcDst = *prclDst, rcSrc;
    BOOL bRet = FALSE;

    *pbAlpha = FALSE;
    *pbCopied = FALSE;
    if (!psurfDst || !psurfDst->SurfObj.pvScan0 || psurfDst->SurfObj.iBitmapFormat != BMF_32BPP)
        return FALSE;
    pdc = DC_LockDc(hdcSrc);
    if (!pdc)
        return FALSE;
    psurfSrc = pdc->dclevel.pSurface;
    if (pdc->dctype != DCTYPE_MEMORY || !psurfSrc)
    {
        DC_UnlockDc(pdc);
        return FALSE;
    }

    /*
     * The source rectangle (device coordinates of the memory DC), both clipped to their surfaces. xSrc and ySrc
     * come from the caller (UpdateLayeredWindow's pptSrc) unchecked: 64-bit arithmetic, so no sum wraps, and the
     * source rectangle is inside the source bitmap before any address is computed.
     */
    {
        LONGLONG xs = (LONGLONG)xSrc + pdc->ptlDCOrig.x, ys = (LONGLONG)ySrc + pdc->ptlDCOrig.y;
        LONGLONG dl = max(rcDst.left, 0), dt = max(rcDst.top, 0);
        LONGLONG dr = min(rcDst.right, psurfDst->SurfObj.sizlBitmap.cx), db = min(rcDst.bottom, psurfDst->SurfObj.sizlBitmap.cy);
        LONGLONG sl = xs + dl, st = ys + dt, sr = xs + dr, sb = ys + db;
        LONGLONG cxs = psurfSrc->SurfObj.sizlBitmap.cx, cys = psurfSrc->SurfObj.sizlBitmap.cy;

        if (sl < 0) { dl -= sl; sl = 0; }
        if (st < 0) { dt -= st; st = 0; }
        if (sr > cxs) { dr -= sr - cxs; sr = cxs; }
        if (sb > cys) { db -= sb - cys; sb = cys; }
        if (dl >= dr || dt >= db || sl >= sr || st >= sb)
        {
            DC_UnlockDc(pdc);
            return TRUE;
        }
        /* All within [0, size] of their surfaces now: they fit in a LONG */
        ASSERT(sl >= 0 && sr <= cxs && st >= 0 && sb <= cys && sr - sl == dr - dl && sb - st == db - dt);
        rcDst.left = (LONG)dl; rcDst.top = (LONG)dt; rcDst.right = (LONG)dr; rcDst.bottom = (LONG)db;
        rcSrc.left = (LONG)sl; rcSrc.top = (LONG)st; rcSrc.right = (LONG)sr; rcSrc.bottom = (LONG)sb;
    }

    if (RedirIsBgr32(psurfSrc))
    {
        /* As it is, alpha included; a DIB section's bits can be user memory */
        _SEH2_TRY
        {
            LONG y;

            for (y = 0; y < rcDst.bottom - rcDst.top; y++)
            {
                RtlCopyMemory((PBYTE)psurfDst->SurfObj.pvScan0 + (LONG_PTR)(rcDst.top + y) * psurfDst->SurfObj.lDelta + (LONG_PTR)rcDst.left * 4,
                              (PBYTE)psurfSrc->SurfObj.pvScan0 + (LONG_PTR)(rcSrc.top + y) * psurfSrc->SurfObj.lDelta + (LONG_PTR)rcSrc.left * 4,
                              (SIZE_T)(rcDst.right - rcDst.left) * 4);
            }
            bRet = TRUE;
            *pbAlpha = TRUE;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            bRet = FALSE;
        }
        _SEH2_END;
    }
    else
    {
        EXLATEOBJ exlo;
        POINTL ptl = { rcSrc.left, rcSrc.top };

        EXLATEOBJ_vInitialize(&exlo, psurfSrc->ppal, psurfDst->ppal, 0, 0, 0);
        /* The same: a DIB section's bits can be user memory another thread unmaps */
        _SEH2_TRY
        {
            bRet = EngCopyBits(&psurfDst->SurfObj, &psurfSrc->SurfObj, NULL, &exlo.xlo, &rcDst, &ptl);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            bRet = FALSE;
        }
        _SEH2_END;
        EXLATEOBJ_vCleanup(&exlo);
    }
    DC_UnlockDc(pdc);
    *pbCopied = bRet;
    return bRet;
}
