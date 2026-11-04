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
    PDC pdc,
    SURFACE *psurfScreen)
{
    PLIST_ENTRY pe;
    PGLASS_BACKDROP pbk = NULL;
    ULONG cEntries = 0;
    SIZEL sizl;
    RECTL rcCopy, rcDst, rcScreen;
    POINTL ptlSrc;
    HBITMAP hbm;
    SURFACE *psurfBk;
    BOOL bOk;

    for (pe = gGlassList.Flink; pe != &gGlassList; pe = pe->Flink)
    {
        PGLASS_BACKDROP p = CONTAINING_RECORD(pe, GLASS_BACKDROP, Entry);
        cEntries++;
        if (p->hwnd == pdc->hwndGlass)
        {
            if (RtlEqualMemory(&p->rcWnd, &pdc->rclGlass, sizeof(RECTL)))
                return p;
            pbk = p;
            break;
        }
    }
    if (pbk)
    {
        GlassFreeEntry(pbk);
        cEntries--;
    }
    if (cEntries >= GLASS_MAX_ENTRIES)
        GlassFreeEntry(CONTAINING_RECORD(gGlassList.Blink, GLASS_BACKDROP, Entry));

    sizl.cx = pdc->rclGlass.right - pdc->rclGlass.left;
    sizl.cy = pdc->rclGlass.bottom - pdc->rclGlass.top;
    if (sizl.cx <= 0 || sizl.cy <= 0 || (ULONGLONG)sizl.cx * sizl.cy > GLASS_MAX_PIXELS)
        return NULL;

    hbm = EngCreateBitmap(sizl, 0, BMF_32BPP, BMF_TOPDOWN, NULL);
    if (!hbm)
        return NULL;
    psurfBk = SURFACE_ShareLockSurface(hbm);
    if (!psurfBk)
    {
        EngDeleteSurface((HSURF)hbm);
        return NULL;
    }

    /* What is on the screen now, the part of the window that is on it; the pointer is taken off while it is read */
    rcScreen.left = rcScreen.top = 0;
    rcScreen.right = psurfScreen->SurfObj.sizlBitmap.cx;
    rcScreen.bottom = psurfScreen->SurfObj.sizlBitmap.cy;
    bOk = RECTL_bIntersectRect(&rcCopy, &pdc->rclGlass, &rcScreen);
    if (bOk)
    {
        rcDst.left = rcCopy.left - pdc->rclGlass.left;
        rcDst.top = rcCopy.top - pdc->rclGlass.top;
        rcDst.right = rcCopy.right - pdc->rclGlass.left;
        rcDst.bottom = rcCopy.bottom - pdc->rclGlass.top;
        ptlSrc.x = rcCopy.left;
        ptlSrc.y = rcCopy.top;
        MouseSafetyOnDrawStart(pdc->ppdev, rcCopy.left, rcCopy.top, rcCopy.right, rcCopy.bottom);
        bOk = EngCopyBits(&psurfBk->SurfObj, &psurfScreen->SurfObj, NULL, NULL, &rcDst, &ptlSrc);
        MouseSafetyOnDrawEnd(pdc->ppdev);
    }
    SURFACE_ShareUnlockSurface(psurfBk);
    if (!bOk)
    {
        EngDeleteSurface((HSURF)hbm);
        return NULL;
    }

    pbk = ExAllocatePoolWithTag(PagedPool, sizeof(*pbk), GLASS_TAG);
    if (!pbk)
    {
        EngDeleteSurface((HSURF)hbm);
        return NULL;
    }
    pbk->hwnd = pdc->hwndGlass;
    pbk->rcWnd = pdc->rclGlass;
    pbk->hbm = hbm;
    InsertHeadList(&gGlassList, &pbk->Entry);
    return pbk;
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
    pbk = GlassGetBackdrop(pdc, psurfDest);
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
