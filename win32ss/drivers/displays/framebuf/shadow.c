/*
 * PROJECT:     ReactOS Generic Framebuffer display driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Drawing through a system memory shadow of the frame buffer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The screen surface given to GDI is device managed and has no bits. GDI
 * draws on it by calling the functions below (or, for anything that is not
 * hooked, by reading and writing it through DrvCopyBits). Each of them lets
 * the engine draw on a bitmap in system memory that holds the screen
 * contents, then copies the rectangles it changed to the frame buffer.
 *
 * The frame buffer is mapped write-combined, which makes reading it very
 * slow. GDI reads the screen for every screen to screen blit (moving or
 * scrolling a window), blend and XOR, so it reads the cached copy instead,
 * and the frame buffer is only ever written, line by line.
 *
 * The rectangles an operation changed are copied to the frame buffer at once
 * only by the first operation of a clock tick. Later ones are noted and
 * copied by the next first operation of a tick, or when win32k calls
 * DrvSynchronizeSurface (GCAPS2_SYNCTIMER: about a tick after drawing on the
 * screen, and when the pointer moves). A program that draws many times a
 * frame (200 blits of 640x480 take about 7 ms) then costs one copy to the
 * frame buffer per tick instead of one per operation, and nothing that reads
 * the screen through GDI sees a difference: it reads the shadow. All of this
 * runs under the device lock, as every call GDI makes to the driver.
 *
 * StretchBlt is not hooked: win32k gives DrvStretchBltROP the target
 * rectangle well-ordered, without the mirroring, which only its own
 * EngStretchBltROP fallback applies. Through DrvCopyBits it is right.
 */

#include "framebuf.h"

typedef struct _FB_ENUMRECTS
{
    ULONG c;
    RECTL arcl[16];
} FB_ENUMRECTS;

/* The PDEVs of this driver that have a screen surface. A device managed
 * surface of another driver can reach us in a blit between two displays,
 * and its dhsurf means nothing to this driver */
#define FB_MAX_SCREENS 16
static PPDEV gapdevScreens[FB_MAX_SCREENS];

BOOL
FbRegisterScreen(
    _In_ PPDEV ppdev)
{
    ULONG i;

    for (i = 0; i < FB_MAX_SCREENS; i++)
    {
        if (InterlockedCompareExchangePointer((PVOID *)&gapdevScreens[i],
                                              ppdev, NULL) == NULL)
        {
            return TRUE;
        }
    }

    return FALSE;
}

VOID
FbUnregisterScreen(
    _In_ PPDEV ppdev)
{
    ULONG i;

    for (i = 0; i < FB_MAX_SCREENS; i++)
    {
        InterlockedCompareExchangePointer((PVOID *)&gapdevScreens[i],
                                          NULL, ppdev);
    }
}

/* A device managed surface of this driver: the screen of one of its PDEVs */
static
BOOL
FbIsScreen(
    _In_ SURFOBJ *pso)
{
    ULONG i;

    if (pso->iType != STYPE_DEVICE || pso->dhsurf == NULL)
        return FALSE;

    for (i = 0; i < FB_MAX_SCREENS; i++)
    {
        if ((DHSURF)gapdevScreens[i] == pso->dhsurf)
            return TRUE;
    }

    return FALSE;
}

/* The surface the engine draws on instead of pso: the shadow of a screen,
 * pso itself for a bitmap, NULL for another driver's device surface */
static
SURFOBJ *
FbShadow(
    _In_ SURFOBJ *pso)
{
    if (pso->iType == STYPE_BITMAP)
        return pso;

    if (FbIsScreen(pso))
        return ((PPDEV)pso->dhsurf)->psoShadow;

    return NULL;
}

static
VOID
FbCopyRect(
    _In_ PPDEV ppdev,
    _In_ const RECTL *prcl)
{
    SURFOBJ *psoShadow = ppdev->psoShadow;
    ULONG cjLine = (prcl->right - prcl->left) * ppdev->BytesPerPixel;
    LONG cLines = prcl->bottom - prcl->top;
    PBYTE pjSrc, pjDst;

    pjSrc = (PBYTE)psoShadow->pvScan0 + prcl->top * psoShadow->lDelta +
            prcl->left * ppdev->BytesPerPixel;
    pjDst = (PBYTE)ppdev->ScreenPtr + prcl->top * ppdev->ScreenDelta +
            prcl->left * ppdev->BytesPerPixel;

    while (cLines-- > 0)
    {
        RtlCopyMemory(pjDst, pjSrc, cjLine);
        pjSrc += psoShadow->lDelta;
        pjDst += ppdev->ScreenDelta;
    }
}

static
LONGLONG
FbArea(
    _In_ const RECTL *prcl)
{
    return (LONGLONG)(prcl->right - prcl->left) * (prcl->bottom - prcl->top);
}

static
VOID
FbUnion(
    _Inout_ RECTL *prclDst,
    _In_ const RECTL *prcl)
{
    prclDst->left = min(prclDst->left, prcl->left);
    prclDst->top = min(prclDst->top, prcl->top);
    prclDst->right = max(prclDst->right, prcl->right);
    prclDst->bottom = max(prclDst->bottom, prcl->bottom);
}

/*
 * Note a rectangle of the screen (well ordered, not empty, on the screen) to
 * copy to the frame buffer later. It joins a noted rectangle that it overlaps
 * or touches; when all are in use, the one that grows least. A rectangle may
 * then cover pixels that did not change: copying them again is harmless, the
 * shadow holds what the screen shows.
 */
static
VOID
FbAddDirty(
    _Inout_ PPDEV ppdev,
    _In_ const RECTL *prcl)
{
    RECTL rcl;
    LONGLONG llGrowth, llBest = 0;
    ULONG i, iBest = 0;

    for (i = 0; i < ppdev->cDirty; i++)
    {
        if (prcl->left <= ppdev->arclDirty[i].right &&
            prcl->right >= ppdev->arclDirty[i].left &&
            prcl->top <= ppdev->arclDirty[i].bottom &&
            prcl->bottom >= ppdev->arclDirty[i].top)
        {
            FbUnion(&ppdev->arclDirty[i], prcl);
            return;
        }
    }

    if (ppdev->cDirty < FB_MAX_DIRTY)
    {
        ppdev->arclDirty[ppdev->cDirty++] = *prcl;
        return;
    }

    for (i = 0; i < FB_MAX_DIRTY; i++)
    {
        rcl = ppdev->arclDirty[i];
        FbUnion(&rcl, prcl);
        llGrowth = FbArea(&rcl) - FbArea(&ppdev->arclDirty[i]);
        if (i == 0 || llGrowth < llBest)
        {
            llBest = llGrowth;
            iBest = i;
        }
    }
    FbUnion(&ppdev->arclDirty[iBest], prcl);
}

/* Copy the noted rectangles to the frame buffer */
static
VOID
FbFlushDirty(
    _Inout_ PPDEV ppdev)
{
    ULONG i;

    for (i = 0; i < ppdev->cDirty; i++)
        FbCopyRect(ppdev, &ppdev->arclDirty[i]);

    ppdev->cDirty = 0;
    ppdev->ulFlushTick = (ULONG)EngGetTickCount();
}

/*
 * Note the part of the shadow that an operation may have changed: prcl (any
 * orientation, NULL for the whole screen) within the clip region, and copy
 * what is noted to the frame buffer if nothing was copied for a while.
 * Called whatever the engine returned, as it may have drawn part of an
 * operation before failing.
 */
static
VOID
FbUpdateScreen(
    _In_ SURFOBJ *pso,
    _In_opt_ const RECTL *prcl,
    _In_opt_ CLIPOBJ *pco)
{
    PPDEV ppdev;
    RECTL rclBounds, rcl;
    FB_ENUMRECTS EnumRects;
    BOOL bMore;
    ULONG i;

    /* Only drawing on the screen needs to reach the frame buffer */
    if (!FbIsScreen(pso))
        return;

    ppdev = (PPDEV)pso->dhsurf;

    /* While the display is disabled, the shadow is copied when it comes back */
    if (!ppdev->bScreenEnabled)
        return;

    rclBounds.left = 0;
    rclBounds.top = 0;
    rclBounds.right = ppdev->ScreenWidth;
    rclBounds.bottom = ppdev->ScreenHeight;

    if (prcl != NULL)
    {
        rclBounds.left = max(rclBounds.left, min(prcl->left, prcl->right));
        rclBounds.top = max(rclBounds.top, min(prcl->top, prcl->bottom));
        rclBounds.right = min(rclBounds.right, max(prcl->left, prcl->right));
        rclBounds.bottom = min(rclBounds.bottom, max(prcl->top, prcl->bottom));
    }

    if (pco != NULL && pco->iDComplexity != DC_TRIVIAL)
    {
        rclBounds.left = max(rclBounds.left, pco->rclBounds.left);
        rclBounds.top = max(rclBounds.top, pco->rclBounds.top);
        rclBounds.right = min(rclBounds.right, pco->rclBounds.right);
        rclBounds.bottom = min(rclBounds.bottom, pco->rclBounds.bottom);
    }

    if (rclBounds.left >= rclBounds.right || rclBounds.top >= rclBounds.bottom)
        return;

    if (pco == NULL || pco->iDComplexity != DC_COMPLEX)
    {
        FbAddDirty(ppdev, &rclBounds);
    }
    else
    {
        /* Only note the visible parts, a window partly covered by others has
         * a clip region much smaller than its bounds */
        CLIPOBJ_cEnumStart(pco, FALSE, CT_RECTANGLES, CD_ANY, 0);
        do
        {
            bMore = CLIPOBJ_bEnum(pco, sizeof(EnumRects), (PULONG)&EnumRects);
            for (i = 0; i < EnumRects.c; i++)
            {
                rcl.left = max(rclBounds.left, EnumRects.arcl[i].left);
                rcl.top = max(rclBounds.top, EnumRects.arcl[i].top);
                rcl.right = min(rclBounds.right, EnumRects.arcl[i].right);
                rcl.bottom = min(rclBounds.bottom, EnumRects.arcl[i].bottom);
                if (rcl.left < rcl.right && rcl.top < rcl.bottom)
                    FbAddDirty(ppdev, &rcl);
            }
        } while (bMore);
    }

    /* The first drawing after a quiet time is shown at once; drawing that
     * follows it closely waits for the next copy */
    if (ppdev->cDirty != 0 && (ULONG)EngGetTickCount() - ppdev->ulFlushTick >= FB_FLUSH_MS)
        FbFlushDirty(ppdev);
}

/* Copy the whole shadow to the frame buffer */
VOID
FbUpdateWholeScreen(
    _In_ PPDEV ppdev)
{
    RECTL rcl;

    rcl.left = 0;
    rcl.top = 0;
    rcl.right = ppdev->ScreenWidth;
    rcl.bottom = ppdev->ScreenHeight;
    FbCopyRect(ppdev, &rcl);
    ppdev->cDirty = 0;
    ppdev->ulFlushTick = (ULONG)EngGetTickCount();
}

/*
 * win32k calls this about a clock tick after drawing on the screen
 * (DSS_TIMER_EVENT) and when the pointer moved (DSS_FLUSH_EVENT), with the
 * device lock held: copy what is still only on the shadow.
 */
VOID
APIENTRY
DrvSynchronizeSurface(
    _In_ SURFOBJ *pso,
    _In_opt_ RECTL *prcl,
    _In_ FLONG fl)
{
    PPDEV ppdev;

    UNREFERENCED_PARAMETER(prcl);
    UNREFERENCED_PARAMETER(fl);

    if (!FbIsScreen(pso))
        return;

    ppdev = (PPDEV)pso->dhsurf;

    /* While the display is disabled, the shadow is copied when it comes back */
    if (ppdev->bScreenEnabled && ppdev->cDirty != 0)
        FbFlushDirty(ppdev);
}

/* A rectangle from bounds computed without overflow, clamped to LONG */
static
VOID
FbBoundsRect(
    _Out_ RECTL *prcl,
    _In_ LONGLONG left,
    _In_ LONGLONG top,
    _In_ LONGLONG right,
    _In_ LONGLONG bottom)
{
    /* MINLONG is an unsigned constant */
    const LONGLONG llMax = MAXLONG, llMin = -llMax - 1;

    prcl->left = (LONG)max(min(left, llMax), llMin);
    prcl->top = (LONG)max(min(top, llMax), llMin);
    prcl->right = (LONG)max(min(right, llMax), llMin);
    prcl->bottom = (LONG)max(min(bottom, llMax), llMin);
}

/*
 * AlphaBlend, TransparentBlt, GradientFill and LineTo only clip to the clip
 * object, which can reach past the screen: after a mode change to a smaller
 * mode a DC keeps the visible region of the old one until USER sets the new
 * one. The engine must not draw past the shadow, that is outside its pool
 * block, so these are only drawn on it when what they can touch is on the
 * screen: the clip, or else the area of the operation (prcl, any orientation).
 */
static
BOOL
FbInScreen(
    _In_ SURFOBJ *pso,
    _In_opt_ CLIPOBJ *pco,
    _In_ const RECTL *prcl)
{
    PPDEV ppdev;

    /* A bitmap is not the screen */
    if (!FbIsScreen(pso))
        return TRUE;

    ppdev = (PPDEV)pso->dhsurf;

    if (pco != NULL && pco->iDComplexity != DC_TRIVIAL &&
        pco->rclBounds.left >= 0 && pco->rclBounds.top >= 0 &&
        pco->rclBounds.right <= (LONG)ppdev->ScreenWidth &&
        pco->rclBounds.bottom <= (LONG)ppdev->ScreenHeight)
    {
        return TRUE;
    }

    return min(prcl->left, prcl->right) >= 0 && min(prcl->top, prcl->bottom) >= 0 &&
           max(prcl->left, prcl->right) <= (LONG)ppdev->ScreenWidth &&
           max(prcl->top, prcl->bottom) <= (LONG)ppdev->ScreenHeight;
}

BOOL APIENTRY
DrvBitBlt(
    _Inout_ SURFOBJ *psoTrg,
    _In_opt_ SURFOBJ *psoSrc,
    _In_opt_ SURFOBJ *psoMask,
    _In_ CLIPOBJ *pco,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ RECTL *prclTrg,
    _In_opt_ POINTL *pptlSrc,
    _In_opt_ POINTL *pptlMask,
    _In_opt_ BRUSHOBJ *pbo,
    _In_opt_ POINTL *pptlBrush,
    _In_ ROP4 rop4)
{
    SURFOBJ *psoShadowDst, *psoShadowSrc = NULL;
    BOOL bRet;

    psoShadowDst = FbShadow(psoTrg);
    if (psoSrc != NULL)
        psoShadowSrc = FbShadow(psoSrc);
    if (psoShadowDst == NULL || (psoSrc != NULL && psoShadowSrc == NULL))
        return FALSE;

    bRet = EngBitBlt(psoShadowDst, psoShadowSrc, psoMask, pco, pxlo,
                     prclTrg, pptlSrc, pptlMask, pbo, pptlBrush, rop4);
    FbUpdateScreen(psoTrg, prclTrg, pco);

    return bRet;
}

BOOL APIENTRY
DrvCopyBits(
    _In_ SURFOBJ *psoDest,
    _In_ SURFOBJ *psoSrc,
    _In_ CLIPOBJ *pco,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ RECTL *prclDest,
    _In_ POINTL *pptlSrc)
{
    SURFOBJ *psoShadowDst, *psoShadowSrc = NULL;
    BOOL bRet;

    psoShadowDst = FbShadow(psoDest);
    if (psoSrc != NULL)
        psoShadowSrc = FbShadow(psoSrc);
    if (psoShadowDst == NULL || (psoSrc != NULL && psoShadowSrc == NULL))
        return FALSE;

    bRet = EngCopyBits(psoShadowDst, psoShadowSrc, pco, pxlo,
                       prclDest, pptlSrc);
    FbUpdateScreen(psoDest, prclDest, pco);

    return bRet;
}

BOOL APIENTRY
DrvLineTo(
    _Inout_ SURFOBJ *pso,
    _In_ CLIPOBJ *pco,
    _In_ BRUSHOBJ *pbo,
    _In_ LONG x1,
    _In_ LONG y1,
    _In_ LONG x2,
    _In_ LONG y2,
    _In_opt_ RECTL *prclBounds,
    _In_ MIX mix)
{
    RECTL rcl;
    SURFOBJ *psoShadowDst;
    BOOL bRet;

    psoShadowDst = FbShadow(pso);
    if (psoShadowDst == NULL)
        return FALSE;

    /* Both end points included, whichever way the line is drawn */
    FbBoundsRect(&rcl, min(x1, x2), min(y1, y2),
                 (LONGLONG)max(x1, x2) + 1, (LONGLONG)max(y1, y2) + 1);

    /* Otherwise IntEngLineTo draws it through DrvCopyBits */
    if (!FbInScreen(pso, pco, &rcl))
        return FALSE;

    bRet = EngLineTo(psoShadowDst, pco, pbo, x1, y1, x2, y2, prclBounds, mix);
    FbUpdateScreen(pso, &rcl, pco);

    return bRet;
}

BOOL APIENTRY
DrvAlphaBlend(
    _Inout_ SURFOBJ *psoDest,
    _In_ SURFOBJ *psoSrc,
    _In_ CLIPOBJ *pco,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ RECTL *prclDest,
    _In_ RECTL *prclSrc,
    _In_ BLENDOBJ *pBlendObj)
{
    SURFOBJ *psoShadowDst, *psoShadowSrc = NULL;
    BOOL bRet;

    psoShadowDst = FbShadow(psoDest);
    if (psoSrc != NULL)
        psoShadowSrc = FbShadow(psoSrc);
    if (psoShadowDst == NULL || (psoSrc != NULL && psoShadowSrc == NULL))
        return FALSE;

    /* Otherwise IntEngAlphaBlend blends it through DrvCopyBits */
    if (!FbInScreen(psoDest, pco, prclDest))
        return FALSE;

    bRet = EngAlphaBlend(psoShadowDst, psoShadowSrc, pco, pxlo,
                         prclDest, prclSrc, pBlendObj);
    FbUpdateScreen(psoDest, prclDest, pco);

    return bRet;
}

BOOL APIENTRY
DrvTransparentBlt(
    _Inout_ SURFOBJ *psoDst,
    _In_ SURFOBJ *psoSrc,
    _In_ CLIPOBJ *pco,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ RECTL *prclDst,
    _In_ RECTL *prclSrc,
    _In_ ULONG iTransColor,
    _In_ ULONG ulReserved)
{
    SURFOBJ *psoShadowDst, *psoShadowSrc = NULL;
    RECTL rclDst, rclSrc;
    BOOL bRet;

    psoShadowDst = FbShadow(psoDst);
    if (psoSrc != NULL)
        psoShadowSrc = FbShadow(psoSrc);
    if (psoShadowDst == NULL || (psoSrc != NULL && psoShadowSrc == NULL))
        return FALSE;

    if (prclDst->left > prclDst->right || prclDst->top > prclDst->bottom ||
        prclSrc->left >= prclSrc->right || prclSrc->top >= prclSrc->bottom)
    {
        return FALSE;
    }

    /* Unlike EngAlphaBlend, EngTransparentBlt does not check its source.
     * Keep the part of a screen source that is on the screen and the part of
     * the target it is stretched to: the engine would otherwise read past
     * the shadow, or through DrvCopyBits a copy of which only that part was
     * filled in. */
    rclDst = *prclDst;
    rclSrc = *prclSrc;
    if (psoShadowSrc != psoSrc)
    {
        LONG cxSrc = prclSrc->right - prclSrc->left, cySrc = prclSrc->bottom - prclSrc->top;
        LONG cxDst = prclDst->right - prclDst->left, cyDst = prclDst->bottom - prclDst->top;

        rclSrc.left = max(rclSrc.left, 0);
        rclSrc.top = max(rclSrc.top, 0);
        rclSrc.right = min(rclSrc.right, psoSrc->sizlBitmap.cx);
        rclSrc.bottom = min(rclSrc.bottom, psoSrc->sizlBitmap.cy);
        if (rclSrc.left >= rclSrc.right || rclSrc.top >= rclSrc.bottom)
            return TRUE;

        rclDst.left = prclDst->left + (LONG)((LONGLONG)(rclSrc.left - prclSrc->left) * cxDst / cxSrc);
        rclDst.top = prclDst->top + (LONG)((LONGLONG)(rclSrc.top - prclSrc->top) * cyDst / cySrc);
        rclDst.right = prclDst->right - (LONG)((LONGLONG)(prclSrc->right - rclSrc.right) * cxDst / cxSrc);
        rclDst.bottom = prclDst->bottom - (LONG)((LONGLONG)(prclSrc->bottom - rclSrc.bottom) * cyDst / cySrc);
        if (rclDst.left >= rclDst.right || rclDst.top >= rclDst.bottom)
            return TRUE;
    }

    /* Otherwise IntEngTransparentBlt draws it through DrvCopyBits */
    if (!FbInScreen(psoDst, pco, &rclDst))
        return FALSE;

    bRet = EngTransparentBlt(psoShadowDst, psoShadowSrc, pco, pxlo,
                             &rclDst, &rclSrc, iTransColor, ulReserved);
    FbUpdateScreen(psoDst, &rclDst, pco);

    return bRet;
}

BOOL APIENTRY
DrvGradientFill(
    _Inout_ SURFOBJ *psoDest,
    _In_ CLIPOBJ *pco,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ TRIVERTEX *pVertex,
    _In_ ULONG nVertex,
    _In_ PVOID pMesh,
    _In_ ULONG nMesh,
    _In_ RECTL *prclExtents,
    _In_ POINTL *pptlDitherOrg,
    _In_ ULONG ulMode)
{
    SURFOBJ *psoShadowDst;
    LONGLONG left, top, right, bottom;
    RECTL rcl;
    ULONG i;
    BOOL bRet;

    psoShadowDst = FbShadow(psoDest);
    if (psoShadowDst == NULL || nVertex == 0)
        return FALSE;

    if (ulMode == GRADIENT_FILL_TRIANGLE)
    {
        /* A triangle is drawn only within its extents (and the clip): keep
         * those on the screen */
        rcl.left = max(min(prclExtents->left, prclExtents->right), 0);
        rcl.top = max(min(prclExtents->top, prclExtents->bottom), 0);
        rcl.right = min(max(prclExtents->left, prclExtents->right), (LONG)psoShadowDst->sizlBitmap.cx);
        rcl.bottom = min(max(prclExtents->top, prclExtents->bottom), (LONG)psoShadowDst->sizlBitmap.cy);
        if (rcl.left >= rcl.right || rcl.top >= rcl.bottom)
            return TRUE;

        bRet = EngGradientFill(psoShadowDst, pco, pxlo, pVertex, nVertex,
                               pMesh, nMesh, &rcl, pptlDitherOrg, ulMode);
        FbUpdateScreen(psoDest, &rcl, pco);
        return bRet;
    }

    /* A rectangle is drawn within its vertices, which are in screen
     * coordinates, up to their right and bottom edges */
    left = right = pVertex[0].x;
    top = bottom = pVertex[0].y;
    for (i = 1; i < nVertex; i++)
    {
        left = min(left, pVertex[i].x);
        top = min(top, pVertex[i].y);
        right = max(right, pVertex[i].x);
        bottom = max(bottom, pVertex[i].y);
    }
    FbBoundsRect(&rcl, left, top, right, bottom);

    /* Otherwise let the engine draw it on the screen surface, through
     * DrvCopyBits (IntEngGradientFill does not retry another way). win32k
     * gives an empty clip (a hidden window) as DC_TRIVIAL with empty
     * bounds: nothing to draw, and no copy of the screen to make for it. */
    if (!FbInScreen(psoDest, pco, &rcl))
    {
        if (pco != NULL && pco->iDComplexity == DC_TRIVIAL &&
            (pco->rclBounds.left >= pco->rclBounds.right ||
             pco->rclBounds.top >= pco->rclBounds.bottom))
        {
            return TRUE;
        }

        return EngGradientFill(psoDest, pco, pxlo, pVertex, nVertex,
                               pMesh, nMesh, prclExtents, pptlDitherOrg, ulMode);
    }

    bRet = EngGradientFill(psoShadowDst, pco, pxlo, pVertex, nVertex,
                           pMesh, nMesh, prclExtents, pptlDitherOrg, ulMode);
    FbUpdateScreen(psoDest, &rcl, pco);

    return bRet;
}
