/*
 * COPYRIGHT:        GNU GPL, See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          Bit blit functions
 * FILE:             win32ss/gdi/ntgdi/bitblt.c
 * PROGRAMER:        Unknown
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(GdiBlt);

/*
 * The part of the screen a scaled IntEngStretchBlt can write: IntEngStretchBlt moves the destination of some flipped
 * stretches by a pixel (left one pixel for the cases 0010 and 0111, right for 0000 and 0101, down for 0000 and 1010, named
 * by the signs of the destination and source sizes as in stretchblt.c), so the destination is made wider on those edges only.
 * At the end of the coordinate range the engine's pixel wraps, see below.
 */
VOID
FASTCALL
IntStretchHazard(
    const RECTL *prclDest,
    const RECTL *prclSrc,
    RECTL *prclHazard)
{
    /* the sizes wrap the way they do in the engine, in 32 bits */
    LONG cxD = (LONG)((ULONG)prclDest->right - (ULONG)prclDest->left), cyD = (LONG)((ULONG)prclDest->bottom - (ULONG)prclDest->top);
    LONG cxS = (LONG)((ULONG)prclSrc->right - (ULONG)prclSrc->left), cyS = (LONG)((ULONG)prclSrc->bottom - (ULONG)prclSrc->top);
    BOOL c0000 = (cxD < 0 && cyD < 0 && cxS < 0 && cyS < 0);
    BOOL c0010 = (cxD < 0 && cyD < 0 && cxS > 0 && cyS < 0);
    BOOL c0101 = (cxD < 0 && cyD > 0 && cxS < 0 && cyS > 0);
    BOOL c0111 = (cxD < 0 && cyD > 0 && cxS > 0 && cyS > 0);
    BOOL c1010 = (cxD > 0 && cyD < 0 && cxS > 0 && cyS < 0);

    *prclHazard = *prclDest;
    RECTL_vMakeWellOrdered(prclHazard);

    /* An edge at the end of the range wraps in the engine, which turns the destination into one that can lie anywhere on
     * that axis, so then the whole axis is the hazard */
    if (c0010 || c0111)
    {
        if (prclHazard->left == LONG_MIN)
            prclHazard->left = LONG_MIN, prclHazard->right = LONG_MAX;
        else
            prclHazard->left--;
    }
    if (c0000 || c0101)
    {
        if (prclHazard->right == LONG_MAX)
            prclHazard->left = LONG_MIN, prclHazard->right = LONG_MAX;
        else
            prclHazard->right++;
    }
    if (c0000 || c1010)
    {
        if (prclHazard->bottom == LONG_MAX)
            prclHazard->top = LONG_MIN, prclHazard->bottom = LONG_MAX;
        else
            prclHazard->bottom++;
    }
}

/* The whole source rectangle lies inside the bitmap of the source DC: the engine rejects the whole call otherwise, which pieces would not */
static
BOOL
IntSourceInSurface(
    PDC pdcSrc,
    const RECTL *prclSrc)
{
    SURFACE *psurf = pdcSrc->dclevel.pSurface;

    return psurf != NULL &&
           prclSrc->left >= 0 && prclSrc->top >= 0 &&
           prclSrc->right <= psurf->SurfObj.sizlBitmap.cx &&
           prclSrc->bottom <= psurf->SurfObj.sizlBitmap.cy;
}

/*
 * Draw a rectangle on a direct DC in pieces, so that the pointer is removed
 * only while the piece under it is drawn and the rest of the rectangle never
 * takes it away. The DC must have been prepared with DCPREP_SPLIT_DEST, the
 * source (if any) must not be on the screen, and the call must be one whose
 * pieces only touch what the whole operation touches (a copy, blend or fill
 * that does not scale or flip). prclDest is well ordered.
 *
 * pfnPiece draws one piece: psoDest and pco are what to draw on and with
 * (the saved pixels under the pointer with no clip, or the screen with the
 * DC clip), prclPiece the piece in psoDest coordinates, pptlOffset where the
 * piece lies in prclDest and pptlOrigin where psoDest's top left lies on the
 * screen (0,0 for the screen itself).
 */
typedef BOOL (*PFN_DRAWPIECE)(PVOID pvCtx, SURFOBJ *psoDest, CLIPOBJ *pco, RECTL *prclPiece,
                              const POINTL *pptlOffset, const POINTL *pptlOrigin);

static
BOOL
IntDrawAroundPointer(
    PDC pdc,
    SURFOBJ *psoScreen,
    RECTL *prclDest,
    CLIPLIMIT kind,
    PFN_DRAWPIECE pfnPiece,
    PVOID pvCtx)
{
    static const POINTL ptlZero = {0, 0};
    RECTL rcHit, rcLimit, rcPiece[5];
    POINTL ptlOffset, ptlOrigin;
    SURFOBJ *psoSave;
    BOOL bRet = TRUE;
    ULONG i;

    /* The clip object is what the engine clips to, also when its last update failed */
    DC_vGetClipLimit(pdc, kind, &rcLimit);
    if (!MouseSafetyGetPointerHit(pdc->ppdev, prclDest, &rcLimit, &rcHit))
    {
        return pfnPiece(pvCtx, psoScreen, (CLIPOBJ *)&pdc->co, prclDest, &ptlZero, &ptlZero);
    }

    /* Around the pointer first, the part under it last */
    rcPiece[0] = (RECTL){prclDest->left, prclDest->top, prclDest->right, rcHit.top};
    rcPiece[1] = (RECTL){prclDest->left, rcHit.bottom, prclDest->right, prclDest->bottom};
    rcPiece[2] = (RECTL){prclDest->left, rcHit.top, rcHit.left, rcHit.bottom};
    rcPiece[3] = (RECTL){rcHit.right, rcHit.top, prclDest->right, rcHit.bottom};
    rcPiece[4] = rcHit;

    for (i = 0; i < 5; i++)
    {
        if (rcPiece[i].left >= rcPiece[i].right || rcPiece[i].top >= rcPiece[i].bottom)
            continue;

        ptlOffset.x = rcPiece[i].left - prclDest->left;
        ptlOffset.y = rcPiece[i].top - prclDest->top;

        if (i < 4)
        {
            if (!pfnPiece(pvCtx, psoScreen, (CLIPOBJ *)&pdc->co, &rcPiece[i], &ptlOffset, &ptlZero))
                bRet = FALSE;
            continue;
        }

        /* The part under the pointer. A clip of one rectangle lets it draw into the pixels saved
         * under the pointer, which the pointer is then put over again. Otherwise take the pointer off. */
        if (pdc->co.iDComplexity == DC_RECT && MouseSafetyBeginUnderDraw(pdc->ppdev, &psoSave, &ptlOrigin))
        {
            RECTL rcSave;

            rcSave.left = rcHit.left - ptlOrigin.x;
            rcSave.top = rcHit.top - ptlOrigin.y;
            rcSave.right = rcHit.right - ptlOrigin.x;
            rcSave.bottom = rcHit.bottom - ptlOrigin.y;

            if (!pfnPiece(pvCtx, psoSave, NULL, &rcSave, &ptlOffset, &ptlOrigin))
                bRet = FALSE;

            MouseSafetyEndUnderDraw(pdc->ppdev);
            continue;
        }

        MouseSafetyOnDrawStart(pdc->ppdev, rcHit.left, rcHit.top, rcHit.right, rcHit.bottom);

        if (!pfnPiece(pvCtx, psoScreen, (CLIPOBJ *)&pdc->co, &rcPiece[i], &ptlOffset, &ptlZero))
            bRet = FALSE;

        MouseSafetyOnDrawEnd(pdc->ppdev);
    }

    return bRet;
}

typedef struct _BITBLTPIECE
{
    SURFOBJ *psoSource;
    SURFOBJ *psoMask;
    XLATEOBJ *pxlo;
    POINTL *pptlSource;
    POINTL *pptlMask;
    BRUSHOBJ *pbo;
    POINTL *pptlBrush;
    ROP4 rop4;
} BITBLTPIECE;

static
BOOL
IntBitBltPiece(
    PVOID pvCtx,
    SURFOBJ *psoDest,
    CLIPOBJ *pco,
    RECTL *prclPiece,
    const POINTL *pptlOffset,
    const POINTL *pptlOrigin)
{
    BITBLTPIECE *p = pvCtx;
    POINTL ptlSource, ptlMask, ptlBrush;

    if (p->pptlSource)
    {
        ptlSource.x = p->pptlSource->x + pptlOffset->x;
        ptlSource.y = p->pptlSource->y + pptlOffset->y;
    }
    if (p->pptlMask)
    {
        ptlMask.x = p->pptlMask->x + pptlOffset->x;
        ptlMask.y = p->pptlMask->y + pptlOffset->y;
    }
    if (p->pptlBrush)
    {
        /* The brush origin is in the coordinates of the surface that is drawn on */
        ptlBrush.x = p->pptlBrush->x - pptlOrigin->x;
        ptlBrush.y = p->pptlBrush->y - pptlOrigin->y;
    }

    return IntEngBitBlt(psoDest, p->psoSource, p->psoMask, pco, p->pxlo, prclPiece,
                        p->pptlSource ? &ptlSource : NULL,
                        p->pptlMask ? &ptlMask : NULL,
                        p->pbo, p->pptlBrush ? &ptlBrush : NULL, p->rop4);
}

static
BOOL
IntEngBitBltAvoidPointer(
    PDC pdc,
    SURFOBJ *psoDest,
    SURFOBJ *psoSource,
    SURFOBJ *psoMask,
    XLATEOBJ *pxlo,
    RECTL *prclDest,
    POINTL *pptlSource,
    POINTL *pptlMask,
    BRUSHOBJ *pbo,
    POINTL *pptlBrush,
    ROP4 rop4)
{
    BITBLTPIECE piece = {psoSource, psoMask, pxlo, pptlSource, pptlMask, pbo, pptlBrush, rop4};

    return IntDrawAroundPointer(pdc, psoDest, prclDest, CLIPLIM_BITBLT, IntBitBltPiece, &piece);
}

typedef struct _BLENDPIECE
{
    SURFOBJ *psoSource;
    XLATEOBJ *pxlo;
    RECTL rclSource;
    BLENDOBJ *pBlendObj;
    ULONG iTransColor;
    BOOL bTransparent;
} BLENDPIECE;

static
BOOL
IntBlendPiece(
    PVOID pvCtx,
    SURFOBJ *psoDest,
    CLIPOBJ *pco,
    RECTL *prclPiece,
    const POINTL *pptlOffset,
    const POINTL *pptlOrigin)
{
    BLENDPIECE *p = pvCtx;
    RECTL rclSource;

    /* The source and the destination have the same size */
    rclSource.left = p->rclSource.left + pptlOffset->x;
    rclSource.top = p->rclSource.top + pptlOffset->y;
    rclSource.right = rclSource.left + (prclPiece->right - prclPiece->left);
    rclSource.bottom = rclSource.top + (prclPiece->bottom - prclPiece->top);

    if (p->bTransparent)
    {
        return IntEngTransparentBlt(psoDest, p->psoSource, pco, p->pxlo, prclPiece, &rclSource, p->iTransColor, 0);
    }

    return IntEngAlphaBlend(psoDest, p->psoSource, pco, p->pxlo, prclPiece, &rclSource, p->pBlendObj);
}


BOOL APIENTRY
NtGdiAlphaBlend(
    HDC hDCDest,
    LONG XOriginDest,
    LONG YOriginDest,
    LONG WidthDest,
    LONG HeightDest,
    HDC hDCSrc,
    LONG XOriginSrc,
    LONG YOriginSrc,
    LONG WidthSrc,
    LONG HeightSrc,
    BLENDFUNCTION BlendFunc,
    HANDLE hcmXform)
{
    PDC DCDest;
    PDC DCSrc;
    HDC ahDC[2];
    PGDIOBJ apObj[2];
    SURFACE *BitmapDest, *BitmapSrc;
    RECTL DestRect, SourceRect;
    BOOL bResult;
    EXLATEOBJ exlo;
    BLENDOBJ BlendObj;
    BOOL bSplit;
    BlendObj.BlendFunction = BlendFunc;

    if (WidthDest < 0 || HeightDest < 0 || WidthSrc < 0 || HeightSrc < 0)
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if ((hDCDest == NULL) || (hDCSrc == NULL))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    TRACE("Locking DCs\n");
    ahDC[0] = hDCDest;
    ahDC[1] = hDCSrc ;
    if (!GDIOBJ_bLockMultipleObjects(2, (HGDIOBJ*)ahDC, apObj, GDIObjType_DC_TYPE))
    {
        WARN("Invalid dc handle (dest=0x%p, src=0x%p) passed to NtGdiAlphaBlend\n", hDCDest, hDCSrc);
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    DCDest = apObj[0];
    DCSrc = apObj[1];

    if (DCSrc->dctype == DCTYPE_INFO || DCDest->dctype == DCTYPE_INFO)
    {
        GDIOBJ_vUnlockObject(&DCSrc->BaseObject);
        GDIOBJ_vUnlockObject(&DCDest->BaseObject);
        /* Yes, Windows really returns TRUE in this case */
        return TRUE;
    }

    DestRect.left   = XOriginDest;
    DestRect.top    = YOriginDest;
    DestRect.right  = XOriginDest + WidthDest;
    DestRect.bottom = YOriginDest + HeightDest;
    IntLPtoDP(DCDest, (LPPOINT)&DestRect, 2);

    DestRect.left   += DCDest->ptlDCOrig.x;
    DestRect.top    += DCDest->ptlDCOrig.y;
    DestRect.right  += DCDest->ptlDCOrig.x;
    DestRect.bottom += DCDest->ptlDCOrig.y;

    if (DCDest->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
       IntUpdateBoundsRect(DCDest, &DestRect);
    }

    SourceRect.left   = XOriginSrc;
    SourceRect.top    = YOriginSrc;
    SourceRect.right  = XOriginSrc + WidthSrc;
    SourceRect.bottom = YOriginSrc + HeightSrc;
    IntLPtoDP(DCSrc, (LPPOINT)&SourceRect, 2);

    SourceRect.left   += DCSrc->ptlDCOrig.x;
    SourceRect.top    += DCSrc->ptlDCOrig.y;
    SourceRect.right  += DCSrc->ptlDCOrig.x;
    SourceRect.bottom += DCSrc->ptlDCOrig.y;

    if (!DestRect.right ||
        !DestRect.bottom ||
        !SourceRect.right ||
        !SourceRect.bottom)
    {
        GDIOBJ_vUnlockObject(&DCSrc->BaseObject);
        GDIOBJ_vUnlockObject(&DCDest->BaseObject);
        return TRUE;
    }

    /* A blend that does not scale is drawn in pieces around the pointer; a source on the screen can show it */
    bSplit = DC_IS_SCREEN(DCDest) && !DC_IS_SCREEN(DCSrc) &&
             (DestRect.right > DestRect.left) && (DestRect.bottom > DestRect.top) &&
             (SourceRect.right - SourceRect.left == DestRect.right - DestRect.left) &&
             (SourceRect.bottom - SourceRect.top == DestRect.bottom - DestRect.top) &&
             IntSourceInSurface(DCSrc, &SourceRect);

    /* Prepare DCs for blit */
    TRACE("Preparing DCs for blit\n");
    DC_vPrepareDCsForBlitEx(DCDest, &DestRect, DCSrc, &SourceRect, (bSplit ? DCPREP_SPLIT_DEST : DCPREP_CLIP_ALPHA) | DCPREP_EXACT_DEST);

    /* Determine surfaces to be used in the bitblt */
    BitmapDest = DCDest->dclevel.pSurface;
    if (!BitmapDest)
    {
        bResult = FALSE ;
        goto leave ;
    }

    BitmapSrc = DCSrc->dclevel.pSurface;
    if (!BitmapSrc)
    {
        bResult = FALSE;
        goto leave;
    }

    /* Create the XLATEOBJ. */
    EXLATEOBJ_vInitXlateFromDCs(&exlo, DCSrc, DCDest);

    /* Perform the alpha blend operation */
    TRACE("Performing the alpha blend\n");
    if (bSplit)
    {
        BLENDPIECE piece = {&BitmapSrc->SurfObj, &exlo.xlo, SourceRect, &BlendObj, 0, FALSE};

        bResult = IntDrawAroundPointer(DCDest, &BitmapDest->SurfObj, &DestRect, CLIPLIM_ALPHA, IntBlendPiece, &piece);
    }
    else
    {
        bResult = IntEngAlphaBlend(&BitmapDest->SurfObj,
                                   &BitmapSrc->SurfObj,
                                   (CLIPOBJ *)&DCDest->co,
                                   &exlo.xlo,
                                   &DestRect,
                                   &SourceRect,
                                   &BlendObj);
    }

    EXLATEOBJ_vCleanup(&exlo);
leave :
    TRACE("Finishing blit\n");
    DC_vFinishBlit(DCDest, DCSrc);
    GDIOBJ_vUnlockObject(&DCSrc->BaseObject);
    GDIOBJ_vUnlockObject(&DCDest->BaseObject);

    return bResult;
}

BOOL APIENTRY
NtGdiBitBlt(
    HDC hDCDest,
    INT XDest,
    INT YDest,
    INT Width,
    INT Height,
    HDC hDCSrc,
    INT XSrc,
    INT YSrc,
    DWORD dwRop,
    IN DWORD crBackColor,
    IN FLONG fl)
{

    if (dwRop & CAPTUREBLT)
    {
       return NtGdiStretchBlt(hDCDest,
                              XDest,
                              YDest,
                              Width,
                              Height,
                              hDCSrc,
                              XSrc,
                              YSrc,
                              Width,
                              Height,
                              dwRop,
                              crBackColor);
    }

    dwRop = dwRop & ~(NOMIRRORBITMAP|CAPTUREBLT);

    /* Forward to NtGdiMaskBlt */
    // TODO: What's fl for? LOL not to send this to MaskBit!
    return NtGdiMaskBlt(hDCDest,
                        XDest,
                        YDest,
                        Width,
                        Height,
                        hDCSrc,
                        XSrc,
                        YSrc,
                        NULL,
                        0,
                        0,
                        MAKEROP4(dwRop, dwRop),
                        crBackColor);
}

BOOL APIENTRY
NtGdiTransparentBlt(
    HDC hdcDst,
    INT xDst,
    INT yDst,
    INT cxDst,
    INT cyDst,
    HDC hdcSrc,
    INT xSrc,
    INT ySrc,
    INT cxSrc,
    INT cySrc,
    COLORREF TransColor)
{
    PDC DCDest, DCSrc;
    HDC ahDC[2];
    PGDIOBJ apObj[2];
    RECTL rcDest, rcSrc;
    SURFACE *BitmapDest, *BitmapSrc = NULL;
    ULONG TransparentColor = 0;
    BOOL Ret = FALSE;
    BOOL bSplit;
    EXLATEOBJ exlo;

    if ((hdcDst == NULL) || (hdcSrc == NULL))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    TRACE("Locking DCs\n");
    ahDC[0] = hdcDst;
    ahDC[1] = hdcSrc ;
    if (!GDIOBJ_bLockMultipleObjects(2, (HGDIOBJ*)ahDC, apObj, GDIObjType_DC_TYPE))
    {
        WARN("Invalid dc handle (dest=0x%p, src=0x%p) passed to NtGdiAlphaBlend\n", hdcDst, hdcSrc);
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    DCDest = apObj[0];
    DCSrc = apObj[1];

    if (DCSrc->dctype == DCTYPE_INFO || DCDest->dctype == DCTYPE_INFO)
    {
        GDIOBJ_vUnlockObject(&DCSrc->BaseObject);
        GDIOBJ_vUnlockObject(&DCDest->BaseObject);
        /* Yes, Windows really returns TRUE in this case */
        return TRUE;
    }

    rcDest.left   = xDst;
    rcDest.top    = yDst;
    rcDest.right  = rcDest.left + cxDst;
    rcDest.bottom = rcDest.top + cyDst;
    IntLPtoDP(DCDest, (LPPOINT)&rcDest, 2);

    rcDest.left   += DCDest->ptlDCOrig.x;
    rcDest.top    += DCDest->ptlDCOrig.y;
    rcDest.right  += DCDest->ptlDCOrig.x;
    rcDest.bottom += DCDest->ptlDCOrig.y;

    rcSrc.left   = xSrc;
    rcSrc.top    = ySrc;
    rcSrc.right  = rcSrc.left + cxSrc;
    rcSrc.bottom = rcSrc.top + cySrc;
    IntLPtoDP(DCSrc, (LPPOINT)&rcSrc, 2);

    rcSrc.left   += DCSrc->ptlDCOrig.x;
    rcSrc.top    += DCSrc->ptlDCOrig.y;
    rcSrc.right  += DCSrc->ptlDCOrig.x;
    rcSrc.bottom += DCSrc->ptlDCOrig.y;

    if (DCDest->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
       IntUpdateBoundsRect(DCDest, &rcDest);
    }

    /* A copy that does not scale or flip is drawn in pieces around the pointer; a source on the screen can show it */
    bSplit = DC_IS_SCREEN(DCDest) && !DC_IS_SCREEN(DCSrc) &&
             (rcDest.right > rcDest.left) && (rcDest.bottom > rcDest.top) &&
             (rcSrc.right - rcSrc.left == rcDest.right - rcDest.left) &&
             (rcSrc.bottom - rcSrc.top == rcDest.bottom - rcDest.top) &&
             IntSourceInSurface(DCSrc, &rcSrc);

    /* Prepare for blit */
    DC_vPrepareDCsForBlitEx(DCDest, &rcDest, DCSrc, &rcSrc, (bSplit ? DCPREP_SPLIT_DEST : DCPREP_CLIP_NOTRIVIAL) | DCPREP_EXACT_DEST);

    BitmapDest = DCDest->dclevel.pSurface;
    if (!BitmapDest)
    {
        goto done;
    }

    BitmapSrc = DCSrc->dclevel.pSurface;
    if (!BitmapSrc)
    {
        goto done;
    }

    /* Translate Transparent (RGB) Color to the source palette */
    EXLATEOBJ_vInitialize(&exlo, &gpalRGB, BitmapSrc->ppal, 0, 0, 0);
    TransparentColor = XLATEOBJ_iXlate(&exlo.xlo, (ULONG)TransColor);
    EXLATEOBJ_vCleanup(&exlo);

    EXLATEOBJ_vInitXlateFromDCs(&exlo, DCSrc, DCDest);

    if (bSplit)
    {
        BLENDPIECE piece = {&BitmapSrc->SurfObj, &exlo.xlo, rcSrc, NULL, TransparentColor, TRUE};

        Ret = IntDrawAroundPointer(DCDest, &BitmapDest->SurfObj, &rcDest, CLIPLIM_NOTRIVIAL, IntBlendPiece, &piece);
    }
    else
    {
        Ret = IntEngTransparentBlt(&BitmapDest->SurfObj, &BitmapSrc->SurfObj,
            (CLIPOBJ *)&DCDest->co, &exlo.xlo, &rcDest, &rcSrc,
            TransparentColor, 0);
    }

    EXLATEOBJ_vCleanup(&exlo);

done:
    DC_vFinishBlit(DCDest, DCSrc);
    GDIOBJ_vUnlockObject(&DCDest->BaseObject);
    GDIOBJ_vUnlockObject(&DCSrc->BaseObject);

    return Ret;
}

BOOL APIENTRY
NtGdiMaskBlt(
    HDC hdcDest,
    INT nXDest,
    INT nYDest,
    INT nWidth,
    INT nHeight,
    HDC hdcSrc,
    INT nXSrc,
    INT nYSrc,
    HBITMAP hbmMask,
    INT xMask,
    INT yMask,
    DWORD dwRop4,
    IN DWORD crBackColor)
{
    PDC DCDest;
    PDC DCSrc = NULL;
    HDC ahDC[2];
    PGDIOBJ apObj[2];
    PDC_ATTR pdcattr = NULL;
    SURFACE *BitmapDest, *BitmapSrc = NULL, *psurfMask = NULL;
    RECTL DestRect, SourceRect;
    POINTL SourcePoint, MaskPoint, BrushOrigin;
    BOOL Status = FALSE;
    EXLATEOBJ exlo;
    XLATEOBJ *XlateObj = NULL;
    BOOL UsesSource, UsesPattern, bSplit;
    ROP4 rop4;

    rop4 = WIN32_ROP4_TO_ENG_ROP4(dwRop4);

    if (!hdcDest)
    {
        return FALSE;
    }

    UsesSource = ROP4_USES_SOURCE(rop4);
    UsesPattern = ROP4_USES_PATTERN(rop4);
    if (!hdcSrc && (UsesSource || UsesPattern))
        return FALSE;

    /* Check if we need a mask and have a mask bitmap */
    if (ROP4_USES_MASK(rop4) && (hbmMask != NULL))
    {
        /* Reference the mask bitmap */
        psurfMask = SURFACE_ShareLockSurface(hbmMask);
        if (psurfMask == NULL)
        {
            EngSetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        /* Make sure the mask bitmap is 1 BPP */
        if (gajBitsPerFormat[psurfMask->SurfObj.iBitmapFormat] != 1)
        {
            SURFACE_ShareUnlockSurface(psurfMask);
            EngSetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
    }
    else
    {
        /* We use NULL, if we need a mask, the Eng function will take care of
           that and use the brushobject to get a mask */
        psurfMask = NULL;
    }

    MaskPoint.x = xMask;
    MaskPoint.y = yMask;

    /* Take care of source and destination bitmap */
    TRACE("Locking DCs\n");
    ahDC[0] = hdcDest;
    ahDC[1] = UsesSource ? hdcSrc : NULL;
    if (!GDIOBJ_bLockMultipleObjects(2, (HGDIOBJ*)ahDC, apObj, GDIObjType_DC_TYPE))
    {
        WARN("Invalid dc handle (dest=0x%p, src=0x%p) passed to NtGdiMaskBlt\n", hdcDest, hdcSrc);
        if(psurfMask) SURFACE_ShareUnlockSurface(psurfMask);
        return FALSE;
    }
    DCDest = apObj[0];
    DCSrc = apObj[1];

    ASSERT(DCDest);
    if (NULL == DCDest)
    {
        if(DCSrc) DC_UnlockDc(DCSrc);
        WARN("Invalid destination dc handle (0x%p) passed to NtGdiMaskBlt\n", hdcDest);
        if(psurfMask) SURFACE_ShareUnlockSurface(psurfMask);
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (DCDest->dctype == DCTYPE_INFO)
    {
        if(DCSrc) DC_UnlockDc(DCSrc);
        DC_UnlockDc(DCDest);
        /* Yes, Windows really returns TRUE in this case */
        if(psurfMask) SURFACE_ShareUnlockSurface(psurfMask);
        return TRUE;
    }

    if (UsesSource)
    {
        ASSERT(DCSrc);
        if (DCSrc->dctype == DCTYPE_INFO)
        {
            DC_UnlockDc(DCDest);
            DC_UnlockDc(DCSrc);
            /* Yes, Windows really returns TRUE in this case */
            if(psurfMask) SURFACE_ShareUnlockSurface(psurfMask);
            return TRUE;
        }
    }

    pdcattr = DCDest->pdcattr;

    DestRect.left   = nXDest;
    DestRect.top    = nYDest;
    DestRect.right  = nXDest + nWidth;
    DestRect.bottom = nYDest + nHeight;
    IntLPtoDP(DCDest, (LPPOINT)&DestRect, 2);

    DestRect.left   += DCDest->ptlDCOrig.x;
    DestRect.top    += DCDest->ptlDCOrig.y;
    DestRect.right  += DCDest->ptlDCOrig.x;
    DestRect.bottom += DCDest->ptlDCOrig.y;

    if (DCDest->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
       IntUpdateBoundsRect(DCDest, &DestRect);
    }

    SourcePoint.x = nXSrc;
    SourcePoint.y = nYSrc;

    if (UsesSource)
    {
        IntLPtoDP(DCSrc, (LPPOINT)&SourcePoint, 1);

        SourcePoint.x += DCSrc->ptlDCOrig.x;
        SourcePoint.y += DCSrc->ptlDCOrig.y;
        /* Calculate Source Rect */
        SourceRect.left = SourcePoint.x;
        SourceRect.top = SourcePoint.y;
        SourceRect.right = SourcePoint.x + DestRect.right - DestRect.left;
        SourceRect.bottom = SourcePoint.y + DestRect.bottom - DestRect.top ;
    }
    else
    {
        SourceRect.left = 0;
        SourceRect.top = 0;
        SourceRect.right = 0;
        SourceRect.bottom = 0;
    }

    /* Prepare blit; a source on the screen can show the pointer, so only a memory source is split */
    bSplit = DC_IS_SCREEN(DCDest) && (!UsesSource || !DC_IS_SCREEN(DCSrc));
    DC_vPrepareDCsForBlitEx(DCDest, &DestRect, DCSrc, &SourceRect, (bSplit ? DCPREP_SPLIT_DEST : DCPREP_CLIP_BITBLT) | DCPREP_EXACT_DEST);

    if (pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
        DC_vUpdateFillBrush(DCDest);

    /* The brush origin of the DC (SetBrushOrgEx) applies to a pattern ROP, as in IntPatBlt */
    BrushOrigin.x = DCDest->dclevel.pbrFill->ptOrigin.x + DCDest->dclevel.ptlBrushOrigin.x + DCDest->ptlDCOrig.x;
    BrushOrigin.y = DCDest->dclevel.pbrFill->ptOrigin.y + DCDest->dclevel.ptlBrushOrigin.y + DCDest->ptlDCOrig.y;

    /* Determine surfaces to be used in the bitblt */
    BitmapDest = DCDest->dclevel.pSurface;
    if (!BitmapDest)
        goto cleanup;

    if (UsesSource)
    {
        BitmapSrc = DCSrc->dclevel.pSurface;
        if (!BitmapSrc)
            goto cleanup;

        /* Create the XLATEOBJ. */
        EXLATEOBJ_vInitXlateFromDCsEx(&exlo, DCSrc, DCDest, crBackColor);
        XlateObj = &exlo.xlo;
    }

    TRACE("DestRect: (%d,%d)-(%d,%d) and SourcePoint is (%d,%d)\n",
          DestRect.left, DestRect.top, DestRect.right, DestRect.bottom,
          SourcePoint.x, SourcePoint.y);

    TRACE("nWidth is '%d' and nHeight is '%d'.\n", nWidth, nHeight);

    /* Fix BitBlt so that it will not flip left to right */
    if ((DestRect.left > DestRect.right) && (nWidth < 0))
    {
        SourcePoint.x += nWidth;
        nWidth = -nWidth;
    }

    /* Fix BitBlt so that it will not flip top to bottom */
    if ((DestRect.top > DestRect.bottom) && (nHeight < 0))
    {
        SourcePoint.y += nHeight;
        nHeight = -nHeight;
    }

    /* Make Well Ordered so that we don't flip either way */
    RECTL_vMakeWellOrdered(&DestRect);

    /* Perform the bitblt operation */
    if (bSplit)
    {
        SURFACE *psurfGlass = NULL;

        /* A copy of a 32 bpp DIB with alpha to a glass window is blended over what is below it (glassblt.c) */
        if (DCDest->hwndGlass && UsesSource && !psurfMask && rop4 == 0xCCCC && nWidth > 0 && nHeight > 0 &&
            GlassBlendSource(DCDest, BitmapDest, BitmapSrc, &DestRect, &SourceRect, &psurfGlass))
        {
            SourcePoint.x = 0;
            SourcePoint.y = 0;
        }

        Status = IntEngBitBltAvoidPointer(DCDest,
                                          &BitmapDest->SurfObj,
                                          psurfGlass ? &psurfGlass->SurfObj : BitmapSrc ? &BitmapSrc->SurfObj : NULL,
                                          psurfMask ? &psurfMask->SurfObj : NULL,
                                          XlateObj,
                                          &DestRect,
                                          &SourcePoint,
                                          &MaskPoint,
                                          &DCDest->eboFill.BrushObject,
                                          &BrushOrigin,
                                          rop4);
        if (psurfGlass)
            GlassBlendDone(psurfGlass);
    }
    else
    {
        Status = IntEngBitBlt(&BitmapDest->SurfObj,
                              BitmapSrc ? &BitmapSrc->SurfObj : NULL,
                              psurfMask ? &psurfMask->SurfObj : NULL,
                              (CLIPOBJ *)&DCDest->co,
                              XlateObj,
                              &DestRect,
                              &SourcePoint,
                              &MaskPoint,
                              &DCDest->eboFill.BrushObject,
                              &BrushOrigin,
                              rop4);
    }

    if (UsesSource)
        EXLATEOBJ_vCleanup(&exlo);
cleanup:
    DC_vFinishBlit(DCDest, DCSrc);
    if (UsesSource)
    {
        DC_UnlockDc(DCSrc);
    }
    DC_UnlockDc(DCDest);
    if(psurfMask) SURFACE_ShareUnlockSurface(psurfMask);

    if (!Status)
        EngSetLastError(ERROR_INVALID_PARAMETER);

    return Status;
}

BOOL
APIENTRY
NtGdiPlgBlt(
    IN HDC hdcTrg,
    IN LPPOINT pptlTrg,
    IN HDC hdcSrc,
    IN INT xSrc,
    IN INT ySrc,
    IN INT cxSrc,
    IN INT cySrc,
    IN HBITMAP hbmMask,
    IN INT xMask,
    IN INT yMask,
    IN DWORD crBackColor)
{
    FIXME("NtGdiPlgBlt: unimplemented.\n");
    return FALSE;
}

BOOL
NTAPI
GreStretchBltMask(
    HDC hDCDest,
    INT XOriginDest,
    INT YOriginDest,
    INT WidthDest,
    INT HeightDest,
    HDC hDCSrc,
    INT XOriginSrc,
    INT YOriginSrc,
    INT WidthSrc,
    INT HeightSrc,
    DWORD dwRop4,
    IN DWORD dwBackColor,
    HDC hDCMask,
    INT XOriginMask,
    INT YOriginMask)
{
    PDC DCDest;
    PDC DCSrc  = NULL;
    PDC DCMask = NULL;
    HDC ahDC[3];
    PGDIOBJ apObj[3];
    PDC_ATTR pdcattr;
    SURFACE *BitmapDest, *BitmapSrc = NULL;
    SURFACE *BitmapMask = NULL;
    RECTL DestRect, rcHazard;
    RECTL SourceRect;
    POINTL MaskPoint;
    BOOL Status = FALSE;
    EXLATEOBJ exlo;
    XLATEOBJ *XlateObj = NULL;
    POINTL BrushOrigin;
    BOOL UsesSource;
    BOOL UsesMask;
    BOOL bSplit;
    ROP4 rop4;
    BOOL Case0000, Case0101, Case1010, CaseExcept;

    rop4 = WIN32_ROP4_TO_ENG_ROP4(dwRop4);

    UsesSource = ROP4_USES_SOURCE(rop4);
    UsesMask = ROP4_USES_MASK(rop4);

    if (0 == WidthDest || 0 == HeightDest || 0 == WidthSrc || 0 == HeightSrc)
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return TRUE;
    }

    if (!hDCDest || (UsesSource && !hDCSrc) || (UsesMask && !hDCMask))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ahDC[0] = hDCDest;
    ahDC[1] = UsesSource ? hDCSrc : NULL;
    ahDC[2] = UsesMask ? hDCMask : NULL;
    if (!GDIOBJ_bLockMultipleObjects(3, (HGDIOBJ*)ahDC, apObj, GDIObjType_DC_TYPE))
    {
        WARN("Invalid dc handle (dest=0x%p, src=0x%p) passed to GreStretchBltMask\n", hDCDest, hDCSrc);
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    DCDest = apObj[0];
    DCSrc = apObj[1];
    DCMask = apObj[2];

    if (DCDest->dctype == DCTYPE_INFO)
    {
        if(DCSrc) GDIOBJ_vUnlockObject(&DCSrc->BaseObject);
        if(DCMask) GDIOBJ_vUnlockObject(&DCMask->BaseObject);
        GDIOBJ_vUnlockObject(&DCDest->BaseObject);
        /* Yes, Windows really returns TRUE in this case */
        return TRUE;
    }

    if (UsesSource)
    {
        if (DCSrc->dctype == DCTYPE_INFO)
        {
            GDIOBJ_vUnlockObject(&DCDest->BaseObject);
            GDIOBJ_vUnlockObject(&DCSrc->BaseObject);
            if(DCMask) GDIOBJ_vUnlockObject(&DCMask->BaseObject);
            /* Yes, Windows really returns TRUE in this case */
            return TRUE;
        }
    }


    Case0000 = ((WidthDest < 0) && (HeightDest < 0) && (WidthSrc < 0) && (HeightSrc < 0));
    Case0101 = ((WidthDest < 0) && (HeightDest > 0) && (WidthSrc < 0) && (HeightSrc > 0));
    Case1010 = ((WidthDest > 0) && (HeightDest < 0) && (WidthSrc > 0) && (HeightSrc < 0));
    CaseExcept = (Case0000 || Case0101 || Case1010);

    pdcattr = DCDest->pdcattr;

    DestRect.left   = XOriginDest;
    DestRect.top    = YOriginDest;
    DestRect.right  = XOriginDest+WidthDest;
    DestRect.bottom = YOriginDest+HeightDest;

    /* Account for possible negative span values */
    if ((WidthDest < 0) && !CaseExcept)
    {
        DestRect.left++;
        DestRect.right++;
    }
    if ((HeightDest < 0) && !CaseExcept)
    {
        DestRect.top++;
        DestRect.bottom++;
    }

    IntLPtoDP(DCDest, (LPPOINT)&DestRect, 2);

    DestRect.left   += DCDest->ptlDCOrig.x;
    DestRect.top    += DCDest->ptlDCOrig.y;
    DestRect.right  += DCDest->ptlDCOrig.x;
    DestRect.bottom += DCDest->ptlDCOrig.y;

    if (DCDest->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
       IntUpdateBoundsRect(DCDest, &DestRect);
    }

    SourceRect.left   = XOriginSrc;
    SourceRect.top    = YOriginSrc;
    SourceRect.right  = XOriginSrc+WidthSrc;
    SourceRect.bottom = YOriginSrc+HeightSrc;

    /* Account for possible negative span values */
    if ((WidthSrc < 0) && !CaseExcept)
    {
        SourceRect.left++;
        SourceRect.right++;
    }
    if ((HeightSrc < 0) && !CaseExcept)
    {
        SourceRect.top++;
        SourceRect.bottom++;
    }

    if (UsesSource)
    {
        IntLPtoDP(DCSrc, (LPPOINT)&SourceRect, 2);

        SourceRect.left   += DCSrc->ptlDCOrig.x;
        SourceRect.top    += DCSrc->ptlDCOrig.y;
        SourceRect.right  += DCSrc->ptlDCOrig.x;
        SourceRect.bottom += DCSrc->ptlDCOrig.y;
    }

    /* The DC brush origin (SetBrushOrgEx) applies to a pattern ROP, as in IntPatBlt */
    BrushOrigin.x = DCDest->dclevel.ptlBrushOrigin.x;
    BrushOrigin.y = DCDest->dclevel.ptlBrushOrigin.y;

    /* A copy that does not scale or flip is a BitBlt to IntEngStretchBlt and is split around the
     * pointer like one; a source on the screen can show the pointer, so only a memory source is split */
    bSplit = DC_IS_SCREEN(DCDest) &&
             (!UsesSource || !DC_IS_SCREEN(DCSrc)) &&
             (DestRect.right > DestRect.left) && (DestRect.bottom > DestRect.top) &&
             (SourceRect.right - SourceRect.left == DestRect.right - DestRect.left) &&
             (SourceRect.bottom - SourceRect.top == DestRect.bottom - DestRect.top);

    /* Only prepare Source and Dest, hdcMask represents a DIB. IntEngStretchBlt moves the destination of a flipped
     * stretch by a pixel (stretchblt.c), so the hazard of the unsplit call is the destination wider by that pixel. */
    IntStretchHazard(&DestRect, &SourceRect, &rcHazard);
    DC_vPrepareDCsForBlitEx(DCDest, bSplit ? &DestRect : &rcHazard, DCSrc, &SourceRect, (bSplit ? DCPREP_SPLIT_DEST : DCPREP_CLIP_NOTRIVIAL) | DCPREP_EXACT_DEST);

    if (pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
        DC_vUpdateFillBrush(DCDest);

    /* Determine surfaces to be used in the bitblt */
    BitmapDest = DCDest->dclevel.pSurface;
    if (BitmapDest == NULL)
        goto failed;
    if (UsesSource)
    {
        BitmapSrc = DCSrc->dclevel.pSurface;
        if (BitmapSrc == NULL)
            goto failed;

        /* Create the XLATEOBJ. */
        EXLATEOBJ_vInitXlateFromDCsEx(&exlo, DCSrc, DCDest, dwBackColor);
        XlateObj = &exlo.xlo;
    }

    /* Offset the brush */
    BrushOrigin.x += DCDest->ptlDCOrig.x;
    BrushOrigin.y += DCDest->ptlDCOrig.y;

    /* Make mask surface for source surface */
    if (BitmapSrc && DCMask)
    {
        BitmapMask = DCMask->dclevel.pSurface;
        if (BitmapMask &&
            (BitmapMask->SurfObj.sizlBitmap.cx < WidthSrc ||
             BitmapMask->SurfObj.sizlBitmap.cy < HeightSrc))
        {
            WARN("%dx%d mask is smaller than %dx%d bitmap\n",
                    BitmapMask->SurfObj.sizlBitmap.cx, BitmapMask->SurfObj.sizlBitmap.cy,
                    WidthSrc, HeightSrc);
            EXLATEOBJ_vCleanup(&exlo);
            goto failed;
        }
        /* Create mask offset point */
        MaskPoint.x = XOriginMask;
        MaskPoint.y = YOriginMask;
        IntLPtoDP(DCMask, &MaskPoint, 1);
        MaskPoint.x += DCMask->ptlDCOrig.x;
        MaskPoint.y += DCMask->ptlDCOrig.y;
    }

    TRACE("Calling IntEngStrethBlt SourceRect: (%d,%d)-(%d,%d) and DestRect: (%d,%d)-(%d,%d).\n",
          SourceRect.left, SourceRect.top, SourceRect.right, SourceRect.bottom,
          DestRect.left, DestRect.top, DestRect.right, DestRect.bottom);

    /* Perform the bitblt operation */
    if (bSplit)
    {
        POINTL ptlSource = {SourceRect.left, SourceRect.top};
        SURFACE *psurfGlass = NULL;

        /* A copy of a 32 bpp DIB with alpha to a glass window is blended over what is below it (glassblt.c) */
        if (DCDest->hwndGlass && UsesSource && !BitmapMask && rop4 == 0xCCCC &&
            GlassBlendSource(DCDest, BitmapDest, BitmapSrc, &DestRect, &SourceRect, &psurfGlass))
        {
            ptlSource.x = 0;
            ptlSource.y = 0;
        }

        Status = IntEngBitBltAvoidPointer(DCDest,
                                          &BitmapDest->SurfObj,
                                          psurfGlass ? &psurfGlass->SurfObj : BitmapSrc ? &BitmapSrc->SurfObj : NULL,
                                          BitmapMask ? &BitmapMask->SurfObj : NULL,
                                          XlateObj,
                                          &DestRect,
                                          UsesSource ? &ptlSource : NULL,
                                          BitmapMask ? &MaskPoint : NULL,
                                          &DCDest->eboFill.BrushObject,
                                          &BrushOrigin,
                                          rop4);
        if (psurfGlass)
            GlassBlendDone(psurfGlass);
    }
    else
    {
        Status = IntEngStretchBlt(&BitmapDest->SurfObj,
                                  BitmapSrc ? &BitmapSrc->SurfObj : NULL,
                                  BitmapMask ? &BitmapMask->SurfObj : NULL,
                                  (CLIPOBJ *)&DCDest->co,
                                  XlateObj,
                                  &DCDest->dclevel.ca,
                                  &DestRect,
                                  &SourceRect,
                                  BitmapMask ? &MaskPoint : NULL,
                                  &DCDest->eboFill.BrushObject,
                                  &BrushOrigin,
                                  rop4);
    }
    if (UsesSource)
    {
        EXLATEOBJ_vCleanup(&exlo);
    }

failed:
    DC_vFinishBlit(DCDest, DCSrc);
    if (UsesSource)
    {
        DC_UnlockDc(DCSrc);
    }
    if (DCMask)
    {
        DC_UnlockDc(DCMask);
    }
    DC_UnlockDc(DCDest);

    return Status;
}


BOOL APIENTRY
NtGdiStretchBlt(
    HDC hDCDest,
    INT XOriginDest,
    INT YOriginDest,
    INT WidthDest,
    INT HeightDest,
    HDC hDCSrc,
    INT XOriginSrc,
    INT YOriginSrc,
    INT WidthSrc,
    INT HeightSrc,
    DWORD dwRop3,
    IN DWORD dwBackColor)
{
    dwRop3 = dwRop3 & ~(NOMIRRORBITMAP|CAPTUREBLT);

    return GreStretchBltMask(
                hDCDest,
                XOriginDest,
                YOriginDest,
                WidthDest,
                HeightDest,
                hDCSrc,
                XOriginSrc,
                YOriginSrc,
                WidthSrc,
                HeightSrc,
                MAKEROP4(dwRop3 & 0xFF0000, dwRop3),
                dwBackColor,
                NULL,
                0,
                0);
}


BOOL FASTCALL
IntPatBlt(
    PDC pdc,
    INT XLeft,
    INT YLeft,
    INT Width,
    INT Height,
    DWORD dwRop3,
    PEBRUSHOBJ pebo)
{
    RECTL DestRect;
    SURFACE *psurf;
    POINTL BrushOrigin;
    BOOL ret;
    PBRUSH pbrush;

    ASSERT(pebo);
    pbrush = pebo->pbrush;
    ASSERT(pbrush);

    if (pbrush->flAttrs & BR_IS_NULL)
    {
        return TRUE;
    }

    if (Width >= 0)
    {
        DestRect.left = XLeft;
        DestRect.right = XLeft + Width;
    }
    else
    {
        DestRect.left = XLeft + Width;
        DestRect.right = XLeft;
    }

    if (Height >= 0)
    {
        DestRect.top = YLeft;
        DestRect.bottom = YLeft + Height;
    }
    else
    {
        DestRect.top = YLeft + Height;
        DestRect.bottom = YLeft;
    }

    IntLPtoDP(pdc, (LPPOINT)&DestRect, 2);

    DestRect.left   += pdc->ptlDCOrig.x;
    DestRect.top    += pdc->ptlDCOrig.y;
    DestRect.right  += pdc->ptlDCOrig.x;
    DestRect.bottom += pdc->ptlDCOrig.y;

    if (pdc->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
       IntUpdateBoundsRect(pdc, &DestRect);
    }

    /* A mirroring transform swaps the corners; the pointer hit test needs them in order */
    RECTL_vMakeWellOrdered(&DestRect);

#ifdef _USE_DIBLIB_
    BrushOrigin.x = pbrush->ptOrigin.x + pdc->ptlDCOrig.x + XLeft;
    BrushOrigin.y = pbrush->ptOrigin.y + pdc->ptlDCOrig.y + YLeft;
#else
    /* The brush origin the app set with SetBrushOrgEx (a pattern brush aligned to the parent window by a
     * WM_CTLCOLORSTATIC handler, for instance) applies to the fill; pbrush->ptOrigin is never set */
    BrushOrigin.x = pbrush->ptOrigin.x + pdc->dclevel.ptlBrushOrigin.x + pdc->ptlDCOrig.x;
    BrushOrigin.y = pbrush->ptOrigin.y + pdc->dclevel.ptlBrushOrigin.y + pdc->ptlDCOrig.y;
#endif

    DC_vPrepareDCsForBlitEx(pdc, &DestRect, NULL, NULL, (DC_IS_SCREEN(pdc) ? DCPREP_SPLIT_DEST : 0) | DCPREP_EXACT_DEST);

    psurf = pdc->dclevel.pSurface;

    if (DC_IS_SCREEN(pdc))
    {
        ret = IntEngBitBltAvoidPointer(pdc,
                                       &psurf->SurfObj,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &DestRect,
                                       NULL,
                                       NULL,
                                       &pebo->BrushObject,
                                       &BrushOrigin,
                                       WIN32_ROP3_TO_ENG_ROP4(dwRop3));
    }
    else
    {
        ret = IntEngBitBlt(&psurf->SurfObj,
                           NULL,
                           NULL,
                           (CLIPOBJ *)&pdc->co,
                           NULL,
                           &DestRect,
                           NULL,
                           NULL,
                           &pebo->BrushObject,
                           &BrushOrigin,
                           WIN32_ROP3_TO_ENG_ROP4(dwRop3));
    }

    DC_vFinishBlit(pdc, NULL);

    return ret;
}

BOOL FASTCALL
IntGdiPolyPatBlt(
    HDC hDC,
    DWORD dwRop,
    PPATRECT pRects,
    INT cRects,
    ULONG Reserved)
{
    INT i;
    PBRUSH pbrush;
    PDC pdc;
    EBRUSHOBJ eboFill;

    pdc = DC_LockDc(hDC);
    if (!pdc)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pdc->dctype == DCTYPE_INFO)
    {
        DC_UnlockDc(pdc);
        /* Yes, Windows really returns TRUE in this case */
        return TRUE;
    }

    for (i = 0; i < cRects; i++)
    {
        pbrush = BRUSH_ShareLockBrush(pRects->hBrush);

        /* Check if we could lock the brush */
        if (pbrush != NULL)
        {
            /* Initialize a brush object */
            EBRUSHOBJ_vInitFromDC(&eboFill, pbrush, pdc);

            IntPatBlt(
                pdc,
                pRects->r.left,
                pRects->r.top,
                pRects->r.right,
                pRects->r.bottom,
                dwRop,
                &eboFill);

            /* Cleanup the brush object and unlock the brush */
            EBRUSHOBJ_vCleanup(&eboFill);
            BRUSH_ShareUnlockBrush(pbrush);
        }
        pRects++;
    }

    DC_UnlockDc(pdc);

    return TRUE;
}

BOOL
APIENTRY
NtGdiPatBlt(
    _In_ HDC hdcDest,
    _In_ INT x,
    _In_ INT y,
    _In_ INT cx,
    _In_ INT cy,
    _In_ DWORD dwRop)
{
    BOOL bResult;
    PDC pdc;

    /* Convert the ROP3 to a ROP4 */
    dwRop = MAKEROP4(dwRop & 0xFF0000, dwRop);

    /* Check if the rop uses a source */
    if (WIN32_ROP4_USES_SOURCE(dwRop))
    {
        /* This is not possible */
        return FALSE;
    }

    /* Lock the DC */
    pdc = DC_LockDc(hdcDest);
    if (pdc == NULL)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Check if the DC has no surface (empty mem or info DC) */
    if (pdc->dclevel.pSurface == NULL)
    {
        /* Nothing to do, Windows returns TRUE! */
        DC_UnlockDc(pdc);
        return TRUE;
    }

    /* Update the fill brush, if necessary */
    if (pdc->pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
        DC_vUpdateFillBrush(pdc);

    /* Call the internal function */
    bResult = IntPatBlt(pdc, x, y, cx, cy, dwRop, &pdc->eboFill);

    /* Unlock the DC and return the result */
    DC_UnlockDc(pdc);
    return bResult;
}

BOOL
APIENTRY
NtGdiPolyPatBlt(
    HDC hDC,
    DWORD dwRop,
    IN PPOLYPATBLT pRects,
    IN DWORD cRects,
    IN DWORD Mode)
{
    PPATRECT rb = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOL Ret;

    if (cRects > 0)
    {
        rb = ExAllocatePoolWithTag(PagedPool, sizeof(PATRECT) * cRects, GDITAG_PLGBLT_DATA);
        if (!rb)
        {
            EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        _SEH2_TRY
        {
            ProbeForRead(pRects,
                cRects * sizeof(PATRECT),
                1);
            RtlCopyMemory(rb,
                pRects,
                cRects * sizeof(PATRECT));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(rb, GDITAG_PLGBLT_DATA);
            SetLastNtError(Status);
            return FALSE;
        }
    }

    Ret = IntGdiPolyPatBlt(hDC, dwRop, rb, cRects, Mode);

    if (cRects > 0)
        ExFreePoolWithTag(rb, GDITAG_PLGBLT_DATA);

    return Ret;
}

static
BOOL
FASTCALL
REGION_LPTODP(
    _In_ PDC pdc,
    _Inout_ PREGION prgnDest,
    _In_ PREGION prgnSrc)
{
    if (IntGdiCombineRgn(prgnDest, prgnSrc, NULL, RGN_COPY) == ERROR)
        return FALSE;

    return REGION_bXformRgn(prgnDest, DC_pmxWorldToDevice(pdc));
}

BOOL
APIENTRY
IntGdiBitBltRgn(
    _In_ PDC pdc,
    _In_ PREGION prgn,
    _In_opt_ BRUSHOBJ *pbo,
    _In_opt_ POINTL *pptlBrush,
    _In_ ROP4 rop4)
{
    PREGION prgnClip;
    XCLIPOBJ xcoClip;
    BOOL bResult;
    NT_ASSERT((pdc != NULL) && (prgn != NULL));

    /* Check if we have a surface */
    if (pdc->dclevel.pSurface == NULL)
    {
        return TRUE;
    }

    /* Create an empty clip region */
    prgnClip = IntSysCreateRectpRgn(0, 0, 0, 0);
    if (prgnClip == NULL)
    {
        return FALSE;
    }

    /* Transform given region into device coordinates */
    if (!REGION_LPTODP(pdc, prgnClip, prgn))
    {
        REGION_Delete(prgnClip);
        return FALSE;
    }

    /* Intersect with the system or RAO region (these are (atm) without DC-origin) */
    if (pdc->prgnRao)
        IntGdiCombineRgn(prgnClip, prgnClip, pdc->prgnRao, RGN_AND);
    else
        IntGdiCombineRgn(prgnClip, prgnClip, pdc->prgnVis, RGN_AND);

    /* Now account for the DC-origin */
    if (!REGION_bOffsetRgn(prgnClip, pdc->ptlDCOrig.x, pdc->ptlDCOrig.y))
    {
        REGION_Delete(prgnClip);
        return FALSE;
    }

    if (pdc->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
        RECTL rcrgn;
        REGION_GetRgnBox(prgnClip, &rcrgn);
        IntUpdateBoundsRect(pdc, &rcrgn);
    }

    /* Prepare the DC */
    DC_vPrepareDCsForBlitEx(pdc, &prgnClip->rdh.rcBound, NULL, NULL, DCPREP_EXACT_DEST);

    /* Initialize a clip object */
    IntEngInitClipObj(&xcoClip);
    IntEngUpdateClipRegion(&xcoClip,
                           prgnClip->rdh.nCount,
                           prgnClip->Buffer,
                           &prgnClip->rdh.rcBound);

    /* Call the Eng or Drv function */
    bResult = IntEngBitBlt(&pdc->dclevel.pSurface->SurfObj,
                           NULL,
                           NULL,
                           (CLIPOBJ *)&xcoClip,
                           NULL,
                           &prgnClip->rdh.rcBound,
                           NULL,
                           NULL,
                           pbo,
                           pptlBrush,
                           rop4);

    /* Cleanup */
    DC_vFinishBlit(pdc, NULL);
    REGION_Delete(prgnClip);
    IntEngFreeClipResources(&xcoClip);

    /* Return the result */
    return bResult;
}

BOOL
IntGdiFillRgn(
    _In_ PDC pdc,
    _In_ PREGION prgn,
    _In_opt_ PBRUSH pbrFill)
{
    PREGION prgnClip;
    XCLIPOBJ xcoClip;
    EBRUSHOBJ eboFill;
    BRUSHOBJ *pbo;
    BOOL bRet;
    DWORD rop2Fg;
    MIX mix;
    NT_ASSERT((pdc != NULL) && (prgn != NULL));

    if (pdc->dclevel.pSurface == NULL)
    {
        return TRUE;
    }

    prgnClip = IntSysCreateRectpRgn(0, 0, 0, 0);
    if (prgnClip == NULL)
    {
        return FALSE;
    }

    /* Transform region into device coordinates */
    if (!REGION_LPTODP(pdc, prgnClip, prgn))
    {
        REGION_Delete(prgnClip);
        return FALSE;
    }

    /* Intersect with the system or RAO region (these are (atm) without DC-origin) */
    if (pdc->prgnRao)
        IntGdiCombineRgn(prgnClip, prgnClip, pdc->prgnRao, RGN_AND);
    else
        IntGdiCombineRgn(prgnClip, prgnClip, pdc->prgnVis, RGN_AND);

    /* Now account for the DC-origin */
    if (!REGION_bOffsetRgn(prgnClip, pdc->ptlDCOrig.x, pdc->ptlDCOrig.y))
    {
        REGION_Delete(prgnClip);
        return FALSE;
    }

    if (pdc->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
        RECTL rcrgn;
        REGION_GetRgnBox(prgnClip, &rcrgn);
        IntUpdateBoundsRect(pdc, &rcrgn);
    }

    IntEngInitClipObj(&xcoClip);
    IntEngUpdateClipRegion(&xcoClip,
                           prgnClip->rdh.nCount,
                           prgnClip->Buffer,
                           &prgnClip->rdh.rcBound );

    /* Get the FG rop and create a MIX based on the BK mode */
    rop2Fg = FIXUP_ROP2(pdc->pdcattr->jROP2);
    mix = rop2Fg | (pdc->pdcattr->jBkMode == OPAQUE ? rop2Fg : R2_NOP) << 8;

    /* Prepare DC for blit */
    DC_vPrepareDCsForBlitEx(pdc, &prgnClip->rdh.rcBound, NULL, NULL, DCPREP_EXACT_DEST);

    /* Check if we have a fill brush */
    if (pbrFill != NULL)
    {
        /* Initialize the brush object */
        /// \todo Check parameters
        EBRUSHOBJ_vInit(&eboFill, pbrFill, pdc->dclevel.pSurface, 0x00FFFFFF, 0, NULL);
        pbo = &eboFill.BrushObject;
    }
    else
    {
        /* Update the fill brush if needed */
        if (pdc->pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
            DC_vUpdateFillBrush(pdc);

        /* Use the DC brush object */
        pbo = &pdc->eboFill.BrushObject;
    }

    /* Call the internal function */
    bRet = IntEngPaint(&pdc->dclevel.pSurface->SurfObj,
                       (CLIPOBJ *)&xcoClip,
                       pbo,
                       &pdc->ptlFillOrigin,
                       mix);

    DC_vFinishBlit(pdc, NULL);
    REGION_Delete(prgnClip);
    IntEngFreeClipResources(&xcoClip);

    // Fill the region
    return bRet;
}

BOOL
FASTCALL
IntGdiPaintRgn(
    _In_ PDC pdc,
    _In_ PREGION prgn)
{
    return IntGdiFillRgn(pdc, prgn, NULL);
}

BOOL
APIENTRY
NtGdiFillRgn(
    _In_ HDC hdc,
    _In_ HRGN hrgn,
    _In_ HBRUSH hbrush)
{
    PDC pdc;
    PREGION prgn;
    PBRUSH pbrFill;
    BOOL bResult;

    /* Lock the DC */
    pdc = DC_LockDc(hdc);
    if (pdc == NULL)
    {
        ERR("Failed to lock hdc %p\n", hdc);
        return FALSE;
    }

    /* Check if the DC has no surface (empty mem or info DC) */
    if (pdc->dclevel.pSurface == NULL)
    {
        DC_UnlockDc(pdc);
        return TRUE;
    }

    /* Lock the region */
    prgn = REGION_LockRgn(hrgn);
    if (prgn == NULL)
    {
        ERR("Failed to lock hrgn %p\n", hrgn);
        DC_UnlockDc(pdc);
        return FALSE;
    }

    /* Lock the brush */
    pbrFill = BRUSH_ShareLockBrush(hbrush);
    if (pbrFill == NULL)
    {
        ERR("Failed to lock hbrush %p\n", hbrush);
        REGION_UnlockRgn(prgn);
        DC_UnlockDc(pdc);
        return FALSE;
    }

    /* Call the internal function */
    bResult = IntGdiFillRgn(pdc, prgn, pbrFill);

    /* Cleanup locks */
    BRUSH_ShareUnlockBrush(pbrFill);
    REGION_UnlockRgn(prgn);
    DC_UnlockDc(pdc);

    return bResult;
}

BOOL
APIENTRY
NtGdiFrameRgn(
    _In_ HDC hdc,
    _In_ HRGN hrgn,
    _In_ HBRUSH hbrush,
    _In_ INT xWidth,
    _In_ INT yHeight)
{
    HRGN hrgnFrame;
    BOOL bResult;

    hrgnFrame = GreCreateFrameRgn(hrgn, xWidth, yHeight);
    if (hrgnFrame == NULL)
    {
        return FALSE;
    }

    bResult = NtGdiFillRgn(hdc, hrgnFrame, hbrush);

    GreDeleteObject(hrgnFrame);
    return bResult;
}

BOOL
APIENTRY
NtGdiInvertRgn(
    _In_ HDC hdc,
    _In_ HRGN hrgn)
{
    BOOL bResult;
    PDC pdc;
    PREGION prgn;

    /* Lock the DC */
    pdc = DC_LockDc(hdc);
    if (pdc == NULL)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Check if the DC has no surface (empty mem or info DC) */
    if (pdc->dclevel.pSurface == NULL)
    {
        /* Nothing to do, Windows returns TRUE! */
        DC_UnlockDc(pdc);
        return TRUE;
    }

    /* Lock the region */
    prgn = REGION_LockRgn(hrgn);
    if (prgn == NULL)
    {
        DC_UnlockDc(pdc);
        return FALSE;
    }

    /* Call the internal function */
    bResult = IntGdiBitBltRgn(pdc,
                              prgn,
                              NULL, // pbo
                              NULL, // pptlBrush,
                              ROP4_DSTINVERT);

    /* Unlock the region and DC and return the result */
    REGION_UnlockRgn(prgn);
    DC_UnlockDc(pdc);
    return bResult;
}

COLORREF
APIENTRY
NtGdiSetPixel(
    _In_ HDC hdc,
    _In_ INT x,
    _In_ INT y,
    _In_ COLORREF crColor)
{
    PDC pdc;
    ULONG iOldColor, iSolidColor;
    BOOL bResult;
    PEBRUSHOBJ pebo;
    ULONG ulDirty;
    EXLATEOBJ exlo;

    /* Lock the DC */
    pdc = DC_LockDc(hdc);
    if (!pdc)
    {
        return CLR_INVALID;
    }

    /* Check if the DC has no surface (empty mem or info DC) */
    if (pdc->dclevel.pSurface == NULL)
    {
        /* Fail! */
        DC_UnlockDc(pdc);
        return CLR_INVALID;
    }

    if (pdc->fs & (DC_ACCUM_APP|DC_ACCUM_WMGR))
    {
       RECTL rcDst;

       RECTL_vSetRect(&rcDst, x, y, x+1, y+1);

       IntLPtoDP(pdc, (LPPOINT)&rcDst, 2);

       rcDst.left   += pdc->ptlDCOrig.x;
       rcDst.top    += pdc->ptlDCOrig.y;
       rcDst.right  += pdc->ptlDCOrig.x;
       rcDst.bottom += pdc->ptlDCOrig.y;

       IntUpdateBoundsRect(pdc, &rcDst);
    }

    /* Translate the color to the target format */
    iSolidColor = TranslateCOLORREF(pdc, crColor);

    /* Use the DC's text brush, which is always a solid brush */
    pebo = &pdc->eboText;

    /* Save the old solid color and set the one for the pixel */
    iOldColor = EBRUSHOBJ_iSetSolidColor(pebo, iSolidColor);

    /* Save dirty flags and reset dirty text brush flag */
    ulDirty = pdc->pdcattr->ulDirty_;
    pdc->pdcattr->ulDirty_ &= ~DIRTY_TEXT;

    /* Call the internal function */
    bResult = IntPatBlt(pdc, x, y, 1, 1, PATCOPY, pebo);

    /* Restore old text brush color and dirty flags */
    EBRUSHOBJ_iSetSolidColor(pebo, iOldColor);
    pdc->pdcattr->ulDirty_ = ulDirty;

    /// FIXME: we shouldn't dereference pSurface while the PDEV is not locked!
    /* Initialize an XLATEOBJ from the target surface to RGB without using BkColor */
    EXLATEOBJ_vInitialize(&exlo,
                          pdc->dclevel.pSurface->ppal,
                          &gpalRGB,
                          CLR_INVALID,
                          CLR_INVALID,
                          CLR_INVALID);

    /* Translate the color back to RGB */
    crColor = XLATEOBJ_iXlate(&exlo.xlo, iSolidColor);

    /* Cleanup and return the target format color */
    EXLATEOBJ_vCleanup(&exlo);

    /* Unlock the DC */
    DC_UnlockDc(pdc);

    /* Return the new RGB color or CLR_INVALID (-1) on failure */
    return bResult ? crColor : CLR_INVALID;
}

COLORREF
APIENTRY
NtGdiGetPixel(
    _In_ HDC hdc,
    _In_ INT x,
    _In_ INT y)
{
    PDC pdc;
    ULONG ulRGBColor = CLR_INVALID;
    POINTL ptlSrc;
    RECT rcDest;
    PSURFACE psurfSrc, psurfDest;

    /* Lock the DC */
    pdc = DC_LockDc(hdc);
    if (!pdc)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return CLR_INVALID;
    }

    /* Check if the DC has no surface (empty mem or info DC) */
    if (pdc->dclevel.pSurface == NULL)
    {
        /* Fail! */
        goto leave;
    }

    /* Get the logical coordinates */
    ptlSrc.x = x;
    ptlSrc.y = y;

    /* Translate coordinates to device coordinates */
    IntLPtoDP(pdc, &ptlSrc, 1);
    ptlSrc.x += pdc->ptlDCOrig.x;
    ptlSrc.y += pdc->ptlDCOrig.y;

    rcDest.left = ptlSrc.x;
    rcDest.top = ptlSrc.y;
    rcDest.right = ptlSrc.x + 1;
    rcDest.bottom = ptlSrc.y + 1;

    /* Prepare DC for blit */
    DC_vPrepareDCsForBlitEx(pdc, &rcDest, NULL, NULL, DCPREP_READ_ONLY);

    /* Check if the pixel is outside the surface */
    psurfSrc = pdc->dclevel.pSurface;
    if ((ptlSrc.x >= psurfSrc->SurfObj.sizlBitmap.cx) ||
        (ptlSrc.y >= psurfSrc->SurfObj.sizlBitmap.cy) ||
        (ptlSrc.x < 0) ||
        (ptlSrc.y < 0))
    {
        /* Fail! */
        goto leave;
    }

    /* Allocate a surface */
    psurfDest = SURFACE_AllocSurface(STYPE_BITMAP,
                                     1,
                                     1,
                                     BMF_32BPP,
                                     0,
                                     0,
                                     0,
                                     &ulRGBColor);
    if (psurfDest)
    {
        RECTL rclDest = {0, 0, 1, 1};
        EXLATEOBJ exlo;

        /* Translate from the source palette to RGB color without BkColor */
        EXLATEOBJ_vInitialize(&exlo,
                              psurfSrc->ppal,
                              &gpalRGB,
                              CLR_INVALID,
                              CLR_INVALID,
                              CLR_INVALID);

        /* Call the copy bits function */
        EngCopyBits(&psurfDest->SurfObj,
                    &psurfSrc->SurfObj,
                    NULL,
                    &exlo.xlo,
                    &rclDest,
                    &ptlSrc);

        /* Cleanup the XLATEOBJ */
        EXLATEOBJ_vCleanup(&exlo);

        /* Delete the surface */
        GDIOBJ_vDeleteObject(&psurfDest->BaseObject);

        /* The top byte is zero */
        ulRGBColor &= 0x00FFFFFF;
    }

leave:

    /* Unlock the DC */
    DC_vFinishBlit(pdc, NULL);
    DC_UnlockDc(pdc);

    /* Return the new RGB color or -1 on failure */
    return ulRGBColor;
}

