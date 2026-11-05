/*
 * PROJECT:     ReactOS win32k
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Per-pixel alpha for GDI output to "glass" windows
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Programs written for the Desktop Window Manager (Firefox and Chromium popups, shaped
 * by DwmExtendFrameIntoClientArea) draw premultiplied ARGB with an ordinary BitBlt of a
 * 32 bpp DIB section into the window and expect the compositor to blend the window with
 * what lies below. There is no compositor here, so the pixels would land with their
 * alpha ignored, and every transparent pixel (rounded corners, the shadow margin of a
 * panel) would show as black.
 *
 * For a window marked as glass (user32 NitroSetWindowGlass, called by dwmapi), a copy
 * of a 32 bpp DIB section onto its DC that has pixels with alpha below 255 is blended
 * over a snapshot of the screen as it was before the window drew anything, not over
 * the previous contents of the window, so that repeated paints do not accumulate.
 * The snapshot is taken at the first such copy after the window's rectangle changed,
 * and dropped when the window is shown, hidden or destroyed.
 *
 * UpdateLayeredWindow(ULW_ALPHA) has the same need: each call replaces the content of
 * the window, blended once with what is below it, not with what the window showed after
 * the previous call. It takes the same snapshot (GlassBackdropPrepare, before the window
 * moves or draws) and reads it back as the base of the blend (GlassBackdropCopyTo).
 */

#include <win32k.h>

#define GLASS_TAG 'gsLG'
#define GLASS_MAX_ENTRIES 8
#define GLASS_MAX_PIXELS (16 * 1024 * 1024)

typedef struct _GLASS_BACKDROP
{
    LIST_ENTRY Entry;
    HWND hwnd;
    RECTL rcWnd;        /* the window, in screen coordinates */
    HBITMAP hbm;        /* BMF_32BPP, the size of rcWnd, top-down */
} GLASS_BACKDROP, *PGLASS_BACKDROP;

static LIST_ENTRY gGlassList = { &gGlassList, &gGlassList };
static FAST_MUTEX gGlassLock;
static BOOLEAN gGlassInit;

VOID
NTAPI
GlassBackdropInit(VOID)
{
    ExInitializeFastMutex(&gGlassLock);
    gGlassInit = TRUE;
}

static
VOID
GlassFreeEntry(PGLASS_BACKDROP pbk)
{
    RemoveEntryList(&pbk->Entry);
    EngDeleteSurface((HSURF)pbk->hbm);
    ExFreePoolWithTag(pbk, GLASS_TAG);
}

/* The window is shown, hidden, destroyed or no longer glass: the next copy takes a new snapshot */
VOID
NTAPI
GlassBackdropDrop(HWND hwnd)
{
    PLIST_ENTRY pe;

    if (!gGlassInit)
        return;

    ExAcquireFastMutex(&gGlassLock);
    for (pe = gGlassList.Flink; pe != &gGlassList; pe = pe->Flink)
    {
        PGLASS_BACKDROP pbk = CONTAINING_RECORD(pe, GLASS_BACKDROP, Entry);
        if (pbk->hwnd == hwnd)
        {
            GlassFreeEntry(pbk);
            break;
        }
    }
    ExReleaseFastMutex(&gGlassLock);
}

/* 32 bpp, bytes B, G, R and a fourth one: the screen (device managed, no bits to read), and a DIB section */
static
BOOL
GlassIsBgr32(SURFACE *psurf, BOOL bNeedBits)
{
    PPALETTE ppal = psurf->ppal;

    if (psurf->SurfObj.iBitmapFormat != BMF_32BPP || (bNeedBits && psurf->SurfObj.pvScan0 == NULL) || ppal == NULL ||
        (ppal->flFlags & PAL_INDEXED))
    {
        return FALSE;
    }
    if (ppal->flFlags & PAL_BGR)
        return TRUE;
    return (ppal->flFlags & PAL_BITFIELDS) &&
           ppal->RedMask == 0x00FF0000 && ppal->GreenMask == 0x0000FF00 && ppal->BlueMask == 0x000000FF;
}

/* Called with the lock held; the snapshot of the window rectangle, or NULL */
static
PGLASS_BACKDROP
GlassGetBackdrop(
    HWND hwnd,
    const RECTL *prcWnd,
    PPDEVOBJ ppdev,
    SURFACE *psurfScreen)
{
    PLIST_ENTRY pe;
    PGLASS_BACKDROP pbk = NULL, pbkOld = NULL;
    ULONG cEntries = 0;
    SIZEL sizl;
    RECTL rcCopy, rcDst, rcScreen, rcKeep;
    POINTL ptlSrc;
    HBITMAP hbm;
    SURFACE *psurfBk;
    BOOL bOk;

    for (pe = gGlassList.Flink; pe != &gGlassList; pe = pe->Flink)
    {
        PGLASS_BACKDROP p = CONTAINING_RECORD(pe, GLASS_BACKDROP, Entry);
        cEntries++;
        if (p->hwnd == hwnd)
        {
            if (RtlEqualMemory(&p->rcWnd, prcWnd, sizeof(RECTL)))
                return p;
            pbkOld = p;
            break;
        }
    }
    /*
     * The window was moved or resized after it drew (Gecko shows a popup at one size and grows it once its
     * content is laid out). What is on the screen under the old rectangle is no longer the backdrop: the window
     * painted there, and the resize erases it. The old snapshot stays valid for the part of the rectangle that
     * both have in common, and only the rest is read from the screen.
     */
    if (pbkOld)
    {
        RemoveEntryList(&pbkOld->Entry);
        cEntries--;
    }
    if (cEntries >= GLASS_MAX_ENTRIES)
        GlassFreeEntry(CONTAINING_RECORD(gGlassList.Blink, GLASS_BACKDROP, Entry));

    sizl.cx = prcWnd->right - prcWnd->left;
    sizl.cy = prcWnd->bottom - prcWnd->top;
    if (sizl.cx <= 0 || sizl.cy <= 0 || (ULONGLONG)sizl.cx * sizl.cy > GLASS_MAX_PIXELS)
        goto fail;

    hbm = EngCreateBitmap(sizl, 0, BMF_32BPP, BMF_TOPDOWN, NULL);
    if (!hbm)
        goto fail;
    psurfBk = SURFACE_ShareLockSurface(hbm);
    if (!psurfBk)
    {
        EngDeleteSurface((HSURF)hbm);
        goto fail;
    }

    /* What is on the screen now, the part of the window that is on it; the pointer is taken off while it is read */
    rcScreen.left = rcScreen.top = 0;
    rcScreen.right = psurfScreen->SurfObj.sizlBitmap.cx;
    rcScreen.bottom = psurfScreen->SurfObj.sizlBitmap.cy;
    bOk = RECTL_bIntersectRect(&rcCopy, prcWnd, &rcScreen);
    if (bOk)
    {
        rcDst.left = rcCopy.left - prcWnd->left;
        rcDst.top = rcCopy.top - prcWnd->top;
        rcDst.right = rcCopy.right - prcWnd->left;
        rcDst.bottom = rcCopy.bottom - prcWnd->top;
        ptlSrc.x = rcCopy.left;
        ptlSrc.y = rcCopy.top;
        MouseSafetyOnDrawStart(ppdev, rcCopy.left, rcCopy.top, rcCopy.right, rcCopy.bottom);
        bOk = EngCopyBits(&psurfBk->SurfObj, &psurfScreen->SurfObj, NULL, NULL, &rcDst, &ptlSrc);
        MouseSafetyOnDrawEnd(ppdev);
    }

    /* Overlay the part that the previous snapshot covers (same screen coordinates) */
    if (bOk && pbkOld && RECTL_bIntersectRect(&rcKeep, &pbkOld->rcWnd, prcWnd))
    {
        SURFACE *psurfOld = SURFACE_ShareLockSurface(pbkOld->hbm);

        if (psurfOld)
        {
            rcDst.left = rcKeep.left - prcWnd->left;
            rcDst.top = rcKeep.top - prcWnd->top;
            rcDst.right = rcKeep.right - prcWnd->left;
            rcDst.bottom = rcKeep.bottom - prcWnd->top;
            ptlSrc.x = rcKeep.left - pbkOld->rcWnd.left;
            ptlSrc.y = rcKeep.top - pbkOld->rcWnd.top;
            EngCopyBits(&psurfBk->SurfObj, &psurfOld->SurfObj, NULL, NULL, &rcDst, &ptlSrc);
            SURFACE_ShareUnlockSurface(psurfOld);
        }
    }
    SURFACE_ShareUnlockSurface(psurfBk);
    if (!bOk)
    {
        EngDeleteSurface((HSURF)hbm);
        goto fail;
    }

    pbk = ExAllocatePoolWithTag(PagedPool, sizeof(*pbk), GLASS_TAG);
    if (!pbk)
    {
        EngDeleteSurface((HSURF)hbm);
        goto fail;
    }
    pbk->hwnd = hwnd;
    pbk->rcWnd = *prcWnd;
    pbk->hbm = hbm;
    InsertHeadList(&gGlassList, &pbk->Entry);
    if (pbkOld)
    {
        EngDeleteSurface((HSURF)pbkOld->hbm);
        ExFreePoolWithTag(pbkOld, GLASS_TAG);
    }
    return pbk;

fail:
    if (pbkOld)
    {
        EngDeleteSurface((HSURF)pbkOld->hbm);
        ExFreePoolWithTag(pbkOld, GLASS_TAG);
    }
    return NULL;
}

/*
 * A copy of a 32 bpp DIB section (the source rectangle) to the screen (the destination rectangle) on the DC of a
 * glass window. When the source has pixels that are not opaque, returns TRUE with a surface that holds the blended
 * pixels, to be copied instead of the source, with the source's palette; release it with GlassBlendDone. The device
 * lock is held, as for the copy itself.
 */
BOOL
NTAPI
GlassBlendSource(
    PDC pdc,
    SURFACE *psurfDest,
    SURFACE *psurfSrc,
    const RECTL *prcDest,
    const RECTL *prcSrc,
    SURFACE **ppsurfOut)
{
    LONG cx = prcDest->right - prcDest->left, cy = prcDest->bottom - prcDest->top, x, y;
    BOOL bTranslucent = FALSE;
    PGLASS_BACKDROP pbk;
    SURFACE *psurfBk = NULL, *psurfOut;
    HBITMAP hbmOut;
    SIZEL sizl;

    if (!gGlassInit || !pdc->hwndGlass || cx <= 0 || cy <= 0 ||
        !psurfSrc->hSecure || !GlassIsBgr32(psurfSrc, TRUE) || !GlassIsBgr32(psurfDest, FALSE) ||
        prcSrc->right - prcSrc->left != cx || prcSrc->bottom - prcSrc->top != cy ||
        prcSrc->left < 0 || prcSrc->top < 0 ||
        prcSrc->right > psurfSrc->SurfObj.sizlBitmap.cx || prcSrc->bottom > psurfSrc->SurfObj.sizlBitmap.cy ||
        prcDest->left < pdc->rclGlass.left || prcDest->top < pdc->rclGlass.top ||
        prcDest->right > pdc->rclGlass.right || prcDest->bottom > pdc->rclGlass.bottom)
    {
        return FALSE;
    }

    for (y = 0; y < cy && !bTranslucent; y++)
    {
        const BYTE *pj = (const BYTE *)psurfSrc->SurfObj.pvScan0 + (prcSrc->top + y) * psurfSrc->SurfObj.lDelta + prcSrc->left * 4;
        for (x = 0; x < cx; x++)
        {
            if (pj[x * 4 + 3] != 0xFF)
            {
                bTranslucent = TRUE;
                break;
            }
        }
    }
    if (!bTranslucent)
        return FALSE;

    ExAcquireFastMutex(&gGlassLock);
    pbk = GlassGetBackdrop(pdc->hwndGlass, &pdc->rclGlass, pdc->ppdev, psurfDest);
    if (pbk)
        psurfBk = SURFACE_ShareLockSurface(pbk->hbm);
    if (!psurfBk)
    {
        ExReleaseFastMutex(&gGlassLock);
        return FALSE;
    }

    sizl.cx = cx;
    sizl.cy = cy;
    hbmOut = EngCreateBitmap(sizl, 0, BMF_32BPP, BMF_TOPDOWN | BMF_NOZEROINIT, NULL);
    psurfOut = hbmOut ? SURFACE_ShareLockSurface(hbmOut) : NULL;
    if (!psurfOut)
    {
        if (hbmOut)
            EngDeleteSurface((HSURF)hbmOut);
        SURFACE_ShareUnlockSurface(psurfBk);
        ExReleaseFastMutex(&gGlassLock);
        return FALSE;
    }

    /* source + backdrop * (255 - alpha) / 255, on every byte (the pixels are premultiplied) */
    for (y = 0; y < cy; y++)
    {
        const BYTE *pjSrc = (const BYTE *)psurfSrc->SurfObj.pvScan0 + (prcSrc->top + y) * psurfSrc->SurfObj.lDelta + prcSrc->left * 4;
        const BYTE *pjBk = (const BYTE *)psurfBk->SurfObj.pvScan0 +
                           (prcDest->top + y - pbk->rcWnd.top) * psurfBk->SurfObj.lDelta +
                           (prcDest->left - pbk->rcWnd.left) * 4;
        BYTE *pjOut = (BYTE *)psurfOut->SurfObj.pvScan0 + y * psurfOut->SurfObj.lDelta;

        for (x = 0; x < cx; x++)
        {
            UINT a = pjSrc[x * 4 + 3], inv = 255 - a, c;
            INT i;

            for (i = 0; i < 3; i++)
            {
                c = pjSrc[x * 4 + i] + (pjBk[x * 4 + i] * inv + 127) / 255;
                pjOut[x * 4 + i] = c > 255 ? 255 : (BYTE)c;
            }
            pjOut[x * 4 + 3] = 0xFF;
        }
    }
    SURFACE_ShareUnlockSurface(psurfBk);
    ExReleaseFastMutex(&gGlassLock);

    /* The pixels have the layout of the source: the palette that describes it goes with them */
    if (psurfOut->ppal)
        PALETTE_ShareUnlockPalette(psurfOut->ppal);
    *(PPALETTE *)&psurfOut->ppal = psurfSrc->ppal;
    GDIOBJ_vReferenceObjectByPointer(&psurfOut->ppal->BaseObject);

    *ppsurfOut = psurfOut;
    return TRUE;
}

VOID
NTAPI
GlassBlendDone(SURFACE *psurf)
{
    HBITMAP hbm = (HBITMAP)psurf->SurfObj.hsurf;

    SURFACE_ShareUnlockSurface(psurf);
    EngDeleteSurface((HSURF)hbm);
}

/*
 * UpdateLayeredWindow: the snapshot of the screen under the window's rectangle (screen coordinates), taken before
 * the window moves or draws, or kept from the previous call (for the part the rectangles have in common).
 * Returns FALSE when there is none (no device, a screen that is not 32 bpp BGR, too large): the caller then blends
 * on the screen as before.
 */
BOOL
NTAPI
GlassBackdropPrepare(
    HWND hwnd,
    const RECTL *prcWnd)
{
    PPDEVOBJ ppdev;
    SURFACE *psurfScreen;
    BOOL bRet = FALSE;

    if (!gGlassInit || !gpmdev || !(ppdev = gpmdev->ppdevGlobal))
        return FALSE;

    EngAcquireSemaphore(ppdev->hsemDevLock);
    psurfScreen = ppdev->pSurface;
    if (psurfScreen && GlassIsBgr32(psurfScreen, FALSE))
    {
        ExAcquireFastMutex(&gGlassLock);
        bRet = GlassGetBackdrop(hwnd, prcWnd, ppdev, psurfScreen) != NULL;
        ExReleaseFastMutex(&gGlassLock);
    }
    EngReleaseSemaphore(ppdev->hsemDevLock);
    return bRet;
}

/*
 * Copies the snapshot of the window to a 32 bpp surface of the size of the window (the base of a blend). Only a
 * snapshot of exactly this rectangle is used.
 */
BOOL
NTAPI
GlassBackdropCopyTo(
    HWND hwnd,
    const RECTL *prcWnd,
    SURFACE *psurfDst)
{
    PLIST_ENTRY pe;
    BOOL bRet = FALSE;
    RECTL rcDst;
    POINTL ptlSrc = { 0, 0 };

    if (!gGlassInit || psurfDst->SurfObj.iBitmapFormat != BMF_32BPP || psurfDst->SurfObj.pvScan0 == NULL ||
        psurfDst->SurfObj.sizlBitmap.cx != prcWnd->right - prcWnd->left ||
        psurfDst->SurfObj.sizlBitmap.cy != prcWnd->bottom - prcWnd->top)
    {
        return FALSE;
    }

    rcDst.left = rcDst.top = 0;
    rcDst.right = psurfDst->SurfObj.sizlBitmap.cx;
    rcDst.bottom = psurfDst->SurfObj.sizlBitmap.cy;

    ExAcquireFastMutex(&gGlassLock);
    for (pe = gGlassList.Flink; pe != &gGlassList; pe = pe->Flink)
    {
        PGLASS_BACKDROP pbk = CONTAINING_RECORD(pe, GLASS_BACKDROP, Entry);

        if (pbk->hwnd == hwnd && RtlEqualMemory(&pbk->rcWnd, prcWnd, sizeof(RECTL)))
        {
            SURFACE *psurfBk = SURFACE_ShareLockSurface(pbk->hbm);

            if (psurfBk)
            {
                bRet = EngCopyBits(&psurfDst->SurfObj, &psurfBk->SurfObj, NULL, NULL, &rcDst, &ptlSrc);
                SURFACE_ShareUnlockSurface(psurfBk);
            }
            break;
        }
    }
    ExReleaseFastMutex(&gGlassLock);
    return bRet;
}
