/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS kernel
 * PURPOSE:           Functions for creation and destruction of DCs
 * FILE:              win32ss/gdi/ntgdi/dclife.c
 * PROGRAMER:         Timo Kreuzer (timo.kreuzer@rectos.org)
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

// FIXME: Windows uses 0x0012009f

PSURFACE psurfDefaultBitmap = NULL;
PBRUSH pbrDefaultBrush = NULL;

const MATRIX gmxWorldToDeviceDefault =
{
    FLOATOBJ_16, FLOATOBJ_0,
    FLOATOBJ_0, FLOATOBJ_16,
    FLOATOBJ_0, FLOATOBJ_0,
    0, 0, 0x4b
};

const MATRIX gmxDeviceToWorldDefault =
{
    FLOATOBJ_1_16, FLOATOBJ_0,
    FLOATOBJ_0, FLOATOBJ_1_16,
    FLOATOBJ_0, FLOATOBJ_0,
    0, 0, 0x53
};

const MATRIX gmxWorldToPageDefault =
{
    FLOATOBJ_1, FLOATOBJ_0,
    FLOATOBJ_0, FLOATOBJ_1,
    FLOATOBJ_0, FLOATOBJ_0,
    0, 0, 0x63
};

// HACK!! Fix XFORMOBJ then use 1:16 / 16:1
#define gmxWorldToDeviceDefault gmxWorldToPageDefault
#define gmxDeviceToWorldDefault gmxWorldToPageDefault

/** Internal functions ********************************************************/

CODE_SEG("INIT")
NTSTATUS
NTAPI
InitDcImpl(VOID)
{
    psurfDefaultBitmap = SURFACE_ShareLockSurface(StockObjects[DEFAULT_BITMAP]);
    if (!psurfDefaultBitmap)
        return STATUS_UNSUCCESSFUL;

    pbrDefaultBrush = BRUSH_ShareLockBrush(StockObjects[BLACK_BRUSH]);
    if (!pbrDefaultBrush)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}


PDC
NTAPI
DC_AllocDcWithHandle(GDILOOBJTYPE eDcObjType)
{
    PDC pdc;

    NT_ASSERT((eDcObjType == GDILoObjType_LO_DC_TYPE) ||
              (eDcObjType == GDILoObjType_LO_ALTDC_TYPE));

    /* Allocate the object */
    pdc = (PDC)GDIOBJ_AllocateObject(GDIObjType_DC_TYPE,
                                     sizeof(DC),
                                     BASEFLAG_LOOKASIDE);
    if (!pdc)
    {
        DPRINT1("Could not allocate a DC.\n");
        return NULL;
    }

    /* Set the actual DC type */
    pdc->BaseObject.hHmgr = UlongToHandle(eDcObjType);

    pdc->pdcattr = &pdc->dcattr;

    /* Insert the object */
    if (!GDIOBJ_hInsertObject(&pdc->BaseObject, GDI_OBJ_HMGR_POWNED))
    {
        DPRINT1("Could not insert DC into handle table.\n");
        GDIOBJ_vFreeObject(&pdc->BaseObject);
        return NULL;
    }

    return pdc;
}


void
DC_InitHack(PDC pdc)
{
    if (defaultDCstate == NULL)
    {
        defaultDCstate = ExAllocatePoolWithTag(PagedPool, sizeof(DC), TAG_DC);
        ASSERT(defaultDCstate);
        RtlZeroMemory(defaultDCstate, sizeof(DC));
        defaultDCstate->pdcattr = &defaultDCstate->dcattr;
        DC_vCopyState(pdc, defaultDCstate, TRUE);
    }

    if (prgnDefault == NULL)
    {
        prgnDefault = IntSysCreateRectpRgn(0, 0, 0, 0);
    }

    TextIntRealizeFont(pdc->pdcattr->hlfntNew,NULL);
    pdc->pdcattr->iCS_CP = ftGdiGetTextCharsetInfo(pdc,NULL,0);

    /* This should never fail */
    ASSERT(pdc->dclevel.ppal);
}

VOID
NTAPI
DC_vInitDc(
    PDC pdc,
    DCTYPE dctype,
    PPDEVOBJ ppdev)
{
    /* Setup some basic fields */
    pdc->dctype = dctype;
    pdc->ppdev = ppdev;
    pdc->dhpdev = ppdev->dhpdev;
    pdc->hsem = ppdev->hsemDevLock;
    pdc->flGraphicsCaps = ppdev->devinfo.flGraphicsCaps;
    pdc->flGraphicsCaps2 = ppdev->devinfo.flGraphicsCaps2;
    pdc->fs = DC_DIRTY_RAO;

    /* Setup dc attribute */
    pdc->pdcattr = &pdc->dcattr;
    pdc->dcattr.pvLDC = NULL;
    pdc->dcattr.ulDirty_ = DIRTY_DEFAULT;
    if (ppdev == gpmdev->ppdevGlobal)
        pdc->dcattr.ulDirty_ |= DC_PRIMARY_DISPLAY;

    /* Setup the DC size */
    if (dctype == DCTYPE_MEMORY)
    {
        /* Memory DCs have a 1 x 1 bitmap by default */
        pdc->dclevel.sizl.cx = 1;
        pdc->dclevel.sizl.cy = 1;
    }
    else
    {
        /* Other DC's are as big as the related PDEV */
	    pdc->dclevel.sizl.cx = ppdev->gdiinfo.ulHorzRes;
	    pdc->dclevel.sizl.cy = ppdev->gdiinfo.ulVertRes;
    }

    /* Setup Window rect based on DC size */
    pdc->erclWindow.left = 0;
    pdc->erclWindow.top = 0;
    pdc->erclWindow.right = pdc->dclevel.sizl.cx;
    pdc->erclWindow.bottom = pdc->dclevel.sizl.cy;

    if (dctype == DCTYPE_DIRECT)
    {
        /* Direct DCs get the surface from the PDEV */
        pdc->dclevel.pSurface = PDEVOBJ_pSurface(ppdev);

        pdc->erclBounds.left = 0x7fffffff;
        pdc->erclBounds.top = 0x7fffffff;
        pdc->erclBounds.right = 0x80000000;
        pdc->erclBounds.bottom = 0x80000000;
        pdc->erclBoundsApp.left = 0xffffffff;
        pdc->erclBoundsApp.top = 0xfffffffc;
        pdc->erclBoundsApp.right = 0x00007ffc; // FIXME
        pdc->erclBoundsApp.bottom = 0x00000333; // FIXME
        pdc->erclClip = pdc->erclBounds;
        pdc->co = gxcoTrivial;
    }
    else
    {
        /* Non-direct DCs don't have a surface by default */
        pdc->dclevel.pSurface = NULL;

        pdc->erclBounds.left = 0;
        pdc->erclBounds.top = 0;
        pdc->erclBounds.right = 0;
        pdc->erclBounds.bottom = 0;
        pdc->erclBoundsApp = pdc->erclBounds;
        pdc->erclClip = pdc->erclWindow;
        pdc->co = gxcoTrivial;
    }

      //pdc->dcattr.VisRectRegion:

    /* Setup coordinate transformation data */
	pdc->dclevel.mxWorldToDevice = gmxWorldToDeviceDefault;
	pdc->dclevel.mxDeviceToWorld = gmxDeviceToWorldDefault;
	pdc->dclevel.mxWorldToPage = gmxWorldToPageDefault;
	pdc->dclevel.efM11PtoD = gef16;
	pdc->dclevel.efM22PtoD = gef16;
	pdc->dclevel.efDxPtoD = gef0;
	pdc->dclevel.efDyPtoD = gef0;
	pdc->dclevel.efM11_TWIPS = gef0;
	pdc->dclevel.efM22_TWIPS = gef0;
	pdc->dclevel.efPr11 = gef0;
	pdc->dclevel.efPr22 = gef0;
	pdc->dcattr.mxWorldToDevice = pdc->dclevel.mxWorldToDevice;
	pdc->dcattr.mxDeviceToWorld = pdc->dclevel.mxDeviceToWorld;
	pdc->dcattr.mxWorldToPage = pdc->dclevel.mxWorldToPage;
	pdc->dcattr.efM11PtoD = pdc->dclevel.efM11PtoD;
	pdc->dcattr.efM22PtoD = pdc->dclevel.efM22PtoD;
	pdc->dcattr.efDxPtoD = pdc->dclevel.efDxPtoD;
	pdc->dcattr.efDyPtoD = pdc->dclevel.efDyPtoD;
	pdc->dcattr.iMapMode = MM_TEXT;
	pdc->dcattr.dwLayout = 0;
	pdc->dcattr.flXform = PAGE_TO_DEVICE_SCALE_IDENTITY |
	                      PAGE_TO_DEVICE_IDENTITY |
	                      WORLD_TO_PAGE_IDENTITY;

    /* Setup more coordinates */
    pdc->ptlDCOrig.x = 0;
    pdc->ptlDCOrig.y = 0;
	pdc->dcattr.lWindowOrgx = 0;
	pdc->dcattr.ptlWindowOrg.x = 0;
	pdc->dcattr.ptlWindowOrg.y = 0;
	pdc->dcattr.szlWindowExt.cx = 1;
	pdc->dcattr.szlWindowExt.cy = 1;
	pdc->dcattr.ptlViewportOrg.x = 0;
	pdc->dcattr.ptlViewportOrg.y = 0;
	pdc->dcattr.szlViewportExt.cx = 1;
	pdc->dcattr.szlViewportExt.cy = 1;
    pdc->dcattr.szlVirtualDevicePixel.cx = ppdev->gdiinfo.ulHorzRes;
    pdc->dcattr.szlVirtualDevicePixel.cy = ppdev->gdiinfo.ulVertRes;
    pdc->dcattr.szlVirtualDeviceMm.cx = ppdev->gdiinfo.ulHorzSize;
    pdc->dcattr.szlVirtualDeviceMm.cy = ppdev->gdiinfo.ulVertSize;
    pdc->dcattr.szlVirtualDeviceSize.cx = 0;
    pdc->dcattr.szlVirtualDeviceSize.cy = 0;

    /* Setup regions */
    pdc->prgnAPI = NULL;
	pdc->prgnRao = NULL;
	pdc->dclevel.prgnClip = NULL;
	pdc->dclevel.prgnMeta = NULL;
    /* Allocate a Vis region */
    pdc->prgnVis = IntSysCreateRectpRgn(0, 0, pdc->dclevel.sizl.cx, pdc->dclevel.sizl.cy);
    if (!pdc->prgnVis)
    {
        /* Out of memory: the DC draws nothing until a Vis region can be allocated */
        pdc->prgnVis = prgnDefault;
    }

    /* Setup Vis Region Attribute information */
    UpdateVisRgn(pdc);

	/* Initialize Clip object */
	IntEngInitClipObj(&pdc->co);

    /* Setup palette */
    pdc->dclevel.hpal = StockObjects[DEFAULT_PALETTE];
    pdc->dclevel.ppal = PALETTE_ShareLockPalette(pdc->dclevel.hpal);

    /* Setup path */
	pdc->dclevel.hPath = NULL;
    pdc->dclevel.flPath = 0;
//	pdc->dclevel.lapath:

    /* Setup colors */
	pdc->dcattr.crBackgroundClr = RGB(0xff, 0xff, 0xff);
	pdc->dcattr.ulBackgroundClr = RGB(0xff, 0xff, 0xff);
	pdc->dcattr.crForegroundClr = RGB(0, 0, 0);
	pdc->dcattr.ulForegroundClr = RGB(0, 0, 0);
	pdc->dcattr.crBrushClr = RGB(0xff, 0xff, 0xff);
	pdc->dcattr.ulBrushClr = RGB(0xff, 0xff, 0xff);
	pdc->dcattr.crPenClr = RGB(0, 0, 0);
	pdc->dcattr.ulPenClr = RGB(0, 0, 0);

    /* Select the default fill and line brush */
	pdc->dcattr.hbrush = StockObjects[WHITE_BRUSH];
	pdc->dcattr.hpen = StockObjects[BLACK_PEN];
    pdc->dclevel.pbrFill = BRUSH_ShareLockBrush(pdc->pdcattr->hbrush);
    pdc->dclevel.pbrLine = PEN_ShareLockPen(pdc->pdcattr->hpen);
	pdc->dclevel.ptlBrushOrigin.x = 0;
	pdc->dclevel.ptlBrushOrigin.y = 0;
	pdc->dcattr.ptlBrushOrigin = pdc->dclevel.ptlBrushOrigin;

    /* Initialize EBRUSHOBJs */
    EBRUSHOBJ_vInitFromDC(&pdc->eboFill, pdc->dclevel.pbrFill, pdc);
    EBRUSHOBJ_vInitFromDC(&pdc->eboLine, pdc->dclevel.pbrLine, pdc);
    EBRUSHOBJ_vInitFromDC(&pdc->eboText, pbrDefaultBrush, pdc);
    EBRUSHOBJ_vInitFromDC(&pdc->eboBackground, pbrDefaultBrush, pdc);

    /* Setup fill data */
	pdc->dcattr.jROP2 = R2_COPYPEN;
	pdc->dcattr.jBkMode = 2;
	pdc->dcattr.lBkMode = 2;
	pdc->dcattr.jFillMode = ALTERNATE;
	pdc->dcattr.lFillMode = 1;
	pdc->dcattr.jStretchBltMode = 1;
	pdc->dcattr.lStretchBltMode = 1;
    pdc->ptlFillOrigin.x = 0;
    pdc->ptlFillOrigin.y = 0;

    /* Setup drawing position */
	pdc->dcattr.ptlCurrent.x = 0;
	pdc->dcattr.ptlCurrent.y = 0;
	pdc->dcattr.ptfxCurrent.x = 0;
	pdc->dcattr.ptfxCurrent.y = 0;

	/* Setup ICM data */
	pdc->dclevel.lIcmMode = 0;
	pdc->dcattr.lIcmMode = 0;
	pdc->dcattr.hcmXform = NULL;
	pdc->dcattr.flIcmFlags = 0;
	pdc->dcattr.IcmBrushColor = CLR_INVALID;
	pdc->dcattr.IcmPenColor = CLR_INVALID;
	pdc->dcattr.pvLIcm = NULL;
    pdc->dcattr.hColorSpace = NULL; // FIXME: 0189001f
	pdc->dclevel.pColorSpace = NULL; // FIXME
    pdc->pClrxFormLnk = NULL;
//	pdc->dclevel.ca =

	/* Setup font data */
    pdc->hlfntCur = NULL; // FIXME: 2f0a0cf8
    pdc->pPFFList = NULL;
    pdc->flSimulationFlags = 0;
    pdc->lEscapement = 0;
    pdc->prfnt = NULL;
	pdc->dcattr.flFontMapper = 0;
	pdc->dcattr.flTextAlign = 0;
	pdc->dcattr.lTextAlign = 0;
	pdc->dcattr.lTextExtra = 0;
	pdc->dcattr.lRelAbs = 1;
	pdc->dcattr.lBreakExtra = 0;
	pdc->dcattr.cBreak = 0;
    pdc->dcattr.hlfntNew = StockObjects[SYSTEM_FONT];
    pdc->dclevel.plfnt = LFONT_ShareLockFont(pdc->dcattr.hlfntNew);

    /* Other stuff */
    pdc->hdcNext = NULL;
    pdc->hdcPrev = NULL;
    pdc->ipfdDevMax = 0;
    pdc->ulCopyCount = -1;
    pdc->ptlDoBanding.x = 0;
    pdc->ptlDoBanding.y = 0;
	pdc->dclevel.lSaveDepth = 1;
	pdc->dclevel.hdcSave = NULL;
	pdc->dcattr.iGraphicsMode = GM_COMPATIBLE;
	pdc->dcattr.iCS_CP = 0;
    pdc->pSurfInfo = NULL;
}

VOID
NTAPI
DC_vCleanup(PVOID ObjectBody)
{
    PDC pdc = (PDC)ObjectBody;

    /* Free DC_ATTR */
    DC_vFreeDcAttr(pdc);

    /* A redirected DC lets go of its window's redirection record */
    if ((pdc->fs & DC_REDIRECTION) && pdc->pvRedir)
    {
        UserRedirDcRelease(pdc->pvRedir);
        pdc->pvRedir = NULL;
    }

    /* Delete saved DCs */
    DC_vRestoreDC(pdc, 1);

    /* Deselect dc objects */
    if (pdc->dclevel.pSurface)
    {
        /* A saved state is not the DC that the bitmap is marked with, so this leaves its bitmap alone */
        InterlockedCompareExchangePointer((PVOID*)&pdc->dclevel.pSurface->hdc, NULL, pdc->BaseObject.hHmgr);
    }
    DC_vSelectSurface(pdc, NULL);
    DC_vSelectFillBrush(pdc, NULL);
    DC_vSelectLineBrush(pdc, NULL);
    DC_vSelectPalette(pdc, NULL);

    /* Cleanup the dc brushes */
    EBRUSHOBJ_vCleanup(&pdc->eboFill);
    EBRUSHOBJ_vCleanup(&pdc->eboLine);
    EBRUSHOBJ_vCleanup(&pdc->eboText);
    EBRUSHOBJ_vCleanup(&pdc->eboBackground);

    /* Release font */
    if (pdc->dclevel.plfnt)
        LFONT_ShareUnlockFont(pdc->dclevel.plfnt);

    /*  Free regions */
    if (pdc->dclevel.prgnClip)
        REGION_Delete(pdc->dclevel.prgnClip);
    if (pdc->dclevel.prgnMeta)
        REGION_Delete(pdc->dclevel.prgnMeta);
    if (pdc->prgnVis)
        REGION_Delete(pdc->prgnVis);
    if (pdc->prgnRao)
        REGION_Delete(pdc->prgnRao);
    if (pdc->prgnAPI)
        REGION_Delete(pdc->prgnAPI);

    /* Free CLIPOBJ resources */
    IntEngFreeClipResources(&pdc->co);

    if (pdc->dclevel.hPath)
    {
       DPRINT("DC_vCleanup Path\n");
       PATH_Delete(pdc->dclevel.hPath);
       pdc->dclevel.hPath = 0;
       pdc->dclevel.flPath = 0;
    }
    if (pdc->dclevel.pSurface)
        SURFACE_ShareUnlockSurface(pdc->dclevel.pSurface);

    if (pdc->ppdev)
        PDEVOBJ_vRelease(pdc->ppdev);
}

VOID
NTAPI
DC_vSetOwner(PDC pdc, ULONG ulOwner)
{
    /* Delete saved DCs */
    DC_vRestoreDC(pdc, 1);

    if (pdc->dclevel.hPath)
    {
        GreSetObjectOwner(pdc->dclevel.hPath, ulOwner);
    }

    /* Dereference current brush and pen */
    BRUSH_ShareUnlockBrush(pdc->dclevel.pbrFill);
    BRUSH_ShareUnlockBrush(pdc->dclevel.pbrLine);

    /* Select the default fill and line brush */
    pdc->dcattr.hbrush = StockObjects[WHITE_BRUSH];
    pdc->dcattr.hpen = StockObjects[BLACK_PEN];
    pdc->dclevel.pbrFill = BRUSH_ShareLockBrush(pdc->pdcattr->hbrush);
    pdc->dclevel.pbrLine = PEN_ShareLockPen(pdc->pdcattr->hpen);

    /* Mark them as dirty */
    pdc->pdcattr->ulDirty_ |= DIRTY_FILL|DIRTY_LINE;

    /* Allocate or free DC attribute */
    if (ulOwner == GDI_OBJ_HMGR_PUBLIC || ulOwner == GDI_OBJ_HMGR_NONE)
    {
        if (pdc->pdcattr != &pdc->dcattr)
            DC_vFreeDcAttr(pdc);
    }
    else if (ulOwner == GDI_OBJ_HMGR_POWNED)
    {
        if (pdc->pdcattr == &pdc->dcattr)
            DC_bAllocDcAttr(pdc);
    }

    /* Set the DC's ownership */
    GDIOBJ_vSetObjectOwner(&pdc->BaseObject, ulOwner);
}

BOOL
NTAPI
GreSetDCOwner(HDC hdc, ULONG ulOwner)
{
    PDC pdc;

    pdc = DC_LockDc(hdc);
    if (!pdc)
    {
        DPRINT1("GreSetDCOwner: Could not lock DC\n");
        return FALSE;
    }

    /* Call the internal DC function */
    DC_vSetOwner(pdc, ulOwner);

    DC_UnlockDc(pdc);
    return TRUE;
}

static
void
DC_vUpdateDCSurface(PDC pdc)
{
    // PREGION VisRgn ;
    PPDEVOBJ ppdev = pdc->ppdev;

    pdc->dhpdev = ppdev->dhpdev;

    SURFACE_ShareUnlockSurface(pdc->dclevel.pSurface);
    pdc->dclevel.pSurface = PDEVOBJ_pSurface(ppdev);

    PDEVOBJ_sizl(pdc->ppdev, &pdc->dclevel.sizl);

    /* The clip region is limited to the surface, which may now be smaller */
    pdc->fs |= DC_DIRTY_RAO;
#if 0
    VisRgn = IntSysCreateRectpRgn(0, 0, pdc->dclevel.sizl.cx, pdc->dclevel.sizl.cy);
    ASSERT(VisRgn);
    GdiSelectVisRgn(pdc->BaseObject.hHmgr, VisRgn);
    REGION_Delete(VisRgn);
#endif

    pdc->flGraphicsCaps = ppdev->devinfo.flGraphicsCaps;
    pdc->flGraphicsCaps2 = ppdev->devinfo.flGraphicsCaps2;
}

static
void
DC_vUpdateDC(PDC pdc)
{
    DC_vUpdateDCSurface(pdc);

    /* Mark EBRUSHOBJs as dirty */
    pdc->pdcattr->ulDirty_ |= DIRTY_DEFAULT ;
}

/* The part of the surface a draw through pdc->co can reach, as the engine call of the given kind clips it. The bounds are
 * what the clip object holds, also when its last update failed and it is an old one; an empty clip is DC_TRIVIAL with empty
 * bounds. Calls that ignore the bounds of a DC_TRIVIAL clip draw everywhere then. */
VOID
FASTCALL
DC_vGetClipLimit(
    PDC pdc,
    CLIPLIMIT kind,
    RECTL *prcl)
{
    BOOL bWhole = FALSE;

    *prcl = pdc->co.rclBounds;

    if (pdc->co.iDComplexity == DC_TRIVIAL)
    {
        if (kind == CLIPLIM_NOTRIVIAL)
            bWhole = TRUE;
        else if (kind == CLIPLIM_ALPHA && prcl->left < prcl->right && prcl->top < prcl->bottom)
            bWhole = TRUE;
    }

    if (bWhole)
    {
        prcl->left = prcl->top = LONG_MIN;
        prcl->right = prcl->bottom = LONG_MAX;
    }
}

/* Take the pointer out of the way of a blit on a direct DC. With bCount only,
 * the pointer stays and the caller removes it around the part of the blit
 * that reaches it. With a clip kind the destination only reaches the clip limit. */
static
VOID
DC_vMouseSafetyStart(
    PDC pdc,
    const RECT *prc,
    BOOL bCount,
    FLONG flClip)
{
    RECTL rcHazard, rcLimit;

    if (!bCount && flClip && prc)
    {
        rcHazard = *prc;
        RECTL_vMakeWellOrdered(&rcHazard);
        DC_vGetClipLimit(pdc,
                         (flClip & DCPREP_CLIP_NOTRIVIAL) ? CLIPLIM_NOTRIVIAL :
                         (flClip & DCPREP_CLIP_ALPHA) ? CLIPLIM_ALPHA : CLIPLIM_BITBLT,
                         &rcLimit);
        if (RECTL_bIntersectRect(&rcHazard, &rcHazard, &rcLimit))
        {
            prc = &rcHazard;
        }
        else
        {
            bCount = TRUE;
        }
    }

    if (bCount)
    {
        MouseSafetyOnDrawEnter(pdc->ppdev);
        return;
    }

    if (!prc)
        prc = &pdc->erclClip;

    MouseSafetyOnDrawStart(pdc->ppdev, prc->left, prc->top, prc->right, prc->bottom);
}

/* Prepare a blit for up to 2 DCs */
/* rc1 and rc2 are the rectangles where we want to draw or
 * from where we take pixels. */
VOID
FASTCALL
DC_vPrepareDCsForBlit(
    PDC pdcDest,
    const RECT* rcDest,
    PDC pdcSrc,
    const RECT* rcSrc)
{
    DC_vPrepareDCsForBlitEx(pdcDest, rcDest, pdcSrc, rcSrc, 0);
}

/* fl: DCPREP_SPLIT_DEST, the caller draws the destination in pieces and removes the
 * pointer only around the piece under it (see IntEngBitBltAvoidPointer);
 * DCPREP_CLIP_*, the destination is drawn through the DC clip object. */
VOID
FASTCALL
DC_vPrepareDCsForBlitEx(
    PDC pdcDest,
    const RECT* rcDest,
    PDC pdcSrc,
    const RECT* rcSrc,
    FLONG fl)
{
    PDC pdcFirst, pdcSecond;
    const RECT *prcFirst, *prcSecond;
    BOOL bFirstIsDest = TRUE;

    /* Update brushes (a DC locked with others did not pass DC_LockDc) */
    DC_vApplyRedirAttrDirty(pdcDest);
    if (pdcDest->pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
        DC_vUpdateFillBrush(pdcDest);
    if (pdcDest->pdcattr->ulDirty_ & (DIRTY_LINE | DC_PEN_DIRTY))
        DC_vUpdateLineBrush(pdcDest);
    if(pdcDest->pdcattr->ulDirty_ & DIRTY_TEXT)
        DC_vUpdateTextBrush(pdcDest);

    /* Lock them in good order */
    if (pdcSrc)
    {
        if((ULONG_PTR)pdcDest->ppdev->hsemDevLock >=
           (ULONG_PTR)pdcSrc->ppdev->hsemDevLock)
        {
            pdcFirst = pdcDest;
            prcFirst = rcDest;
            pdcSecond = pdcSrc;
            prcSecond = rcSrc;
        }
        else
        {
            pdcFirst = pdcSrc;
            prcFirst = rcSrc;
            pdcSecond = pdcDest;
            prcSecond = rcDest;
            bFirstIsDest = FALSE;
        }
    }
    else
    {
        pdcFirst = pdcDest;
        prcFirst = rcDest;
        pdcSecond = NULL;
        prcSecond = NULL;
    }

    if (pdcDest->fs & DC_DIRTY_RAO)
        CLIPPING_UpdateGCRegion(pdcDest);

    /*
     * A redirected window DC draws into its window's surface: where it draws is presented (marked again in
     * DC_vFinishBlit). Only blit-class callers give the exact rectangle they write (DCPREP_EXACT_DEST); for every
     * other primitive the whole clip bounds count as drawn (a horizontal line has an empty bounding box, a
     * rectangle's border and wide pens reach past it).
     */
    if ((pdcDest->fs & DC_REDIRECTION) && pdcDest->pvRedir)
    {
        if (fl & DCPREP_READ_ONLY)
        {
            RECTL_vSetEmptyRect(&pdcDest->rclRedirDraw);
        }
        else if (rcDest && (fl & DCPREP_EXACT_DEST))
        {
            pdcDest->rclRedirDraw = *(const RECTL *)rcDest;
            RECTL_vMakeWellOrdered(&pdcDest->rclRedirDraw);
            if (!RECTL_bIntersectRect(&pdcDest->rclRedirDraw, &pdcDest->rclRedirDraw, &pdcDest->erclClip))
                RECTL_vSetEmptyRect(&pdcDest->rclRedirDraw);
        }
        else
        {
            pdcDest->rclRedirDraw = pdcDest->erclClip;
        }
        if (!RECTL_bIsEmptyRect(&pdcDest->rclRedirDraw))
            UserRedirMarkDirty(pdcDest->pvRedir, &pdcDest->rclRedirDraw);
    }

    /* Lock and update first DC */
    if (DC_IS_SCREEN(pdcFirst))
    {
        EngAcquireSemaphore(pdcFirst->ppdev->hsemDevLock);

        /* Update surface if needed */
        if (pdcFirst->ppdev->pSurface != pdcFirst->dclevel.pSurface)
        {
            DC_vUpdateDC(pdcFirst);
            if (bFirstIsDest)
                CLIPPING_UpdateGCRegion(pdcFirst);
        }
    }

    if (DC_IS_SCREEN(pdcFirst))
    {
        DC_vMouseSafetyStart(pdcFirst, prcFirst, (fl & DCPREP_SPLIT_DEST) && bFirstIsDest, (fl & DCPREP_CLIP_MASK) && bFirstIsDest ? (fl & DCPREP_CLIP_MASK) : 0);
    }

#if DBG
    pdcFirst->fs |= DC_PREPARED;
#endif

    if (!pdcSecond)
        return;

    /* Lock and update second DC */
    if (DC_IS_SCREEN(pdcSecond))
    {
        EngAcquireSemaphore(pdcSecond->ppdev->hsemDevLock);

        /* Update surface if needed */
        if (pdcSecond->ppdev->pSurface != pdcSecond->dclevel.pSurface)
        {
            DC_vUpdateDC(pdcSecond);
            if (!bFirstIsDest)
                CLIPPING_UpdateGCRegion(pdcSecond);
        }
    }

    if (DC_IS_SCREEN(pdcSecond))
    {
        DC_vMouseSafetyStart(pdcSecond, prcSecond, (fl & DCPREP_SPLIT_DEST) && !bFirstIsDest, (fl & DCPREP_CLIP_MASK) && !bFirstIsDest ? (fl & DCPREP_CLIP_MASK) : 0);
    }

#if DBG
    pdcSecond->fs |= DC_PREPARED;
#endif
}

/* Finishes a blit for one or two DCs */
VOID
FASTCALL
DC_vFinishBlit(PDC pdc1, PDC pdc2)
{
    /* Drawn: a present that ran meanwhile may have taken the mark of DC_vPrepareDCsForBlitEx */
    if ((pdc1->fs & DC_REDIRECTION) && pdc1->pvRedir && !RECTL_bIsEmptyRect(&pdc1->rclRedirDraw))
        UserRedirMarkDirty(pdc1->pvRedir, &pdc1->rclRedirDraw);

    if (DC_IS_SCREEN(pdc1))
    {
        MouseSafetyOnDrawEnd(pdc1->ppdev);
        EngReleaseSemaphore(pdc1->ppdev->hsemDevLock);
    }
#if DBG
    pdc1->fs &= ~DC_PREPARED;
#endif

    if (pdc2)
    {
        if (DC_IS_SCREEN(pdc2))
        {
            MouseSafetyOnDrawEnd(pdc2->ppdev);
            EngReleaseSemaphore(pdc2->ppdev->hsemDevLock);
        }
#if DBG
        pdc2->fs &= ~DC_PREPARED;
#endif
    }
}

HDC
NTAPI
GreOpenDCW(
    PUNICODE_STRING pustrDevice,
    DEVMODEW *pdmInit,
    PUNICODE_STRING pustrLogAddr,
    ULONG iType,
    BOOL bDisplay,
    HANDLE hspool,
    VOID *pDriverInfo2,
    PVOID *pUMdhpdev)
{
    PPDEVOBJ ppdev;
    PDC pdc;
    HDC hdc;

    DPRINT("GreOpenDCW(%S, iType=%lu)\n",
           pustrDevice ? pustrDevice->Buffer : NULL, iType);

    /* Get a PDEVOBJ for the device */
    ppdev = EngpGetPDEV(pustrDevice);
    if (!ppdev)
    {
        DPRINT1("Didn't find a suitable PDEV\n");
        return NULL;
    }

    DPRINT("GreOpenDCW - ppdev = %p\n", ppdev);

    pdc = DC_AllocDcWithHandle(GDILoObjType_LO_DC_TYPE);
    if (!pdc)
    {
        DPRINT1("Could not Allocate a DC\n");
        PDEVOBJ_vRelease(ppdev);
        return NULL;
    }
    hdc = pdc->BaseObject.hHmgr;

    /* Lock ppdev and initialize the new DC */
    DC_vInitDc(pdc, iType, ppdev);
    if (pUMdhpdev) *pUMdhpdev = ppdev->dhpdev;
    /* FIXME: HACK! */
    DC_InitHack(pdc);

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (!DC_bAllocDcAttr(pdc) && Win32kUserViewZeroBits(PsGetCurrentProcess()))
    {
        GDIOBJ_vDeleteObject(&pdc->BaseObject);
        return NULL;
    }
#else
    DC_bAllocDcAttr(pdc);
#endif

    DC_UnlockDc(pdc);

    DPRINT("Returning hdc = %p\n", hdc);

    return hdc;
}

__kernel_entry
HDC
APIENTRY
NtGdiOpenDCW(
    _In_opt_ PUNICODE_STRING pustrDevice,
    _In_ DEVMODEW *pdmInit,
    _In_ PUNICODE_STRING pustrLogAddr,
    _In_ ULONG iType,
    _In_ BOOL bDisplay,
    _In_opt_ HANDLE hspool,
    /*_In_opt_ DRIVER_INFO2W *pdDriverInfo2, Need this soon!!!! */
    _At_((PUMDHPDEV*)pUMdhpdev, _Out_) PVOID pUMdhpdev)
{
    UNICODE_STRING ustrDevice;
    WCHAR awcDevice[CCHDEVICENAME];
    PVOID dhpdev;
    HDC hdc;
    WORD dmSize, dmDriverExtra;
    DWORD Size;
    DEVMODEW * _SEH2_VOLATILE pdmAllocated = NULL;

    /* Only if a devicename is given, we need any data */
    if (pustrDevice)
    {
        /* Initialize destination string */
        RtlInitEmptyUnicodeString(&ustrDevice, awcDevice, sizeof(awcDevice));

        _SEH2_TRY
        {
            /* Probe the UNICODE_STRING and the buffer */
            ProbeForRead(pustrDevice, sizeof(UNICODE_STRING), 1);
            ProbeForRead(pustrDevice->Buffer, pustrDevice->Length, 1);

            /* Copy the string */
            RtlCopyUnicodeString(&ustrDevice, pustrDevice);

            /* Allocate and store pdmAllocated if pdmInit is not NULL */
            if (pdmInit)
            {
                ProbeForRead(pdmInit, sizeof(DEVMODEW), 1);

                dmSize = pdmInit->dmSize;
                dmDriverExtra = pdmInit->dmDriverExtra;
                Size = dmSize + dmDriverExtra;
                ProbeForRead(pdmInit, Size, 1);

                pdmAllocated = ExAllocatePoolWithTag(PagedPool | POOL_RAISE_IF_ALLOCATION_FAILURE,
                                                     Size,
                                                     TAG_DC);
                RtlCopyMemory(pdmAllocated, pdmInit, Size);
                pdmAllocated->dmSize = dmSize;
                pdmAllocated->dmDriverExtra = dmDriverExtra;
            }

            if (pUMdhpdev)
            {
                ProbeForWrite(pUMdhpdev, sizeof(HANDLE), 1);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            if (pdmAllocated)
            {
                ExFreePoolWithTag(pdmAllocated, TAG_DC);
            }
            SetLastNtError(_SEH2_GetExceptionCode());
            _SEH2_YIELD(return NULL);
        }
        _SEH2_END
    }
    else
    {
        pdmInit = NULL;
        pUMdhpdev = NULL;
        // return UserGetDesktopDC(iType, FALSE, TRUE);
    }

    /* FIXME: HACK! */
    if (pustrDevice)
    {
        UNICODE_STRING ustrDISPLAY = RTL_CONSTANT_STRING(L"DISPLAY");
        if (RtlEqualUnicodeString(&ustrDevice, &ustrDISPLAY, TRUE))
        {
            pustrDevice = NULL;
        }
    }

    /* Call the internal function */
    hdc = GreOpenDCW(pustrDevice ? &ustrDevice : NULL,
                     pdmAllocated,
                     NULL, // FIXME: pwszLogAddress
                     iType,
                     bDisplay,
                     hspool,
                     NULL, // FIXME: pDriverInfo2
                     pUMdhpdev ? &dhpdev : NULL);

    /* If we got a HDC and a UM dhpdev is requested,... */
    if (hdc && pUMdhpdev)
    {
        /* Copy dhpdev to caller */
        _SEH2_TRY
        {
            /* Pointer was already probed */
            *(HANDLE*)pUMdhpdev = dhpdev;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Ignore error */
            (void)0;
        }
        _SEH2_END
    }

    /* Free the allocated */
    if (pdmAllocated)
    {
        ExFreePoolWithTag(pdmAllocated, TAG_DC);
    }

    return hdc;
}


HDC
APIENTRY
GreCreateCompatibleDC(HDC hdc, BOOL bAltDc)
{
    GDILOOBJTYPE eDcObjType;
    HDC hdcNew;
    PPDEVOBJ ppdev;
    PDC pdc, pdcNew;

    DPRINT("NtGdiCreateCompatibleDC(0x%p)\n", hdc);

    /* Did the caller provide a DC? */
    if (hdc)
    {
        /* Yes, try to lock it */
        pdc = DC_LockDc(hdc);
        if (!pdc)
        {
            DPRINT1("Could not lock source DC %p\n", hdc);
            return NULL;
        }

        /* Get the pdev from the DC */
        ppdev = pdc->ppdev;
        PDEVOBJ_vReference(ppdev);

        /* Unlock the source DC */
        DC_UnlockDc(pdc);
    }
    else
    {
        /* No DC given, get default device */
        ppdev = EngpGetPDEV(NULL);
    }

    if (!ppdev)
    {
        DPRINT1("Didn't find a suitable PDEV\n");
        return NULL;
    }

    /* Allocate a new DC */
    eDcObjType = bAltDc ? GDILoObjType_LO_ALTDC_TYPE : GDILoObjType_LO_DC_TYPE;
    pdcNew = DC_AllocDcWithHandle(eDcObjType);
    if (!pdcNew)
    {
        DPRINT1("Could not allocate a new DC\n");
        PDEVOBJ_vRelease(ppdev);
        return NULL;
    }
    hdcNew = pdcNew->BaseObject.hHmgr;

    /* Lock ppdev and initialize the new DC */
    DC_vInitDc(pdcNew, bAltDc ? DCTYPE_INFO : DCTYPE_MEMORY, ppdev);
    /* FIXME: HACK! */
    DC_InitHack(pdcNew);

    /* Allocate a dc attribute */
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (!DC_bAllocDcAttr(pdcNew) && Win32kUserViewZeroBits(PsGetCurrentProcess()))
    {
        GDIOBJ_vDeleteObject(&pdcNew->BaseObject);
        return NULL;
    }
#else
    DC_bAllocDcAttr(pdcNew);
#endif

    DC_UnlockDc(pdcNew);

    DPRINT("Leave NtGdiCreateCompatibleDC hdcNew = %p\n", hdcNew);

    return hdcNew;
}

HDC
APIENTRY
NtGdiCreateCompatibleDC(HDC hdc)
{
    /* Call the internal function to create a normal memory DC */
    return GreCreateCompatibleDC(hdc, FALSE);
}

BOOL
FASTCALL
IntGdiDeleteDC(HDC hDC, BOOL Force)
{
    PDC DCToDelete = DC_LockDc(hDC);

    if (DCToDelete == NULL)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!Force)
    {
        /* Windows permits NtGdiDeleteObjectApp to delete a permanent DC
         * For some reason, it's still a valid handle, pointing to some kernel data.
         * Not sure if this is a bug, a feature, some cache stuff... Who knows?
         * See NtGdiDeleteObjectApp test for details */
        if (DCToDelete->fs & DC_PERMANANT)
        {
            BOOL Entered = FALSE, Ret;

            DC_UnlockDc(DCToDelete);

            /* The DCE list and window DCs belong to window management: work on them under the USER lock */
            if (!UserIsEnteredExclusive())
            {
                /* Not held shared either: a shared hold cannot become exclusive */
                ASSERT(!UserIsEntered());
                UserEnterExclusive();
                Entered = TRUE;
            }

            if(UserReleaseDC(NULL, hDC, FALSE))
            {
                /* ReactOS feature: Call UserReleaseDC
                 * I don't think Windows does it.
                 * Still, complain, no one should ever call DeleteDC
                 * on a window DC */
                 DPRINT1("No, you naughty application!\n");
                 Ret = TRUE;
            }
            else
            {
                /* This is not a window owned DC.
                 * Force its deletion */
                Ret = IntGdiDeleteDC(hDC, TRUE);
            }

            if (Entered) UserLeave();
            return Ret;
        }
    }

    DC_UnlockDc(DCToDelete);

    if (GreIsHandleValid(hDC))
    {
        if (!GreDeleteObject(hDC))
        {
            DPRINT1("DC_FreeDC failed\n");
            return FALSE;
        }
    }
    else
    {
        DPRINT1("Attempted to Delete 0x%p currently being destroyed!!!\n", hDC);
        return FALSE;
    }

    return TRUE;
}

BOOL
APIENTRY
NtGdiDeleteObjectApp(HANDLE hobj)
{
    if (GDI_HANDLE_IS_STOCKOBJ(hobj)) return TRUE;

    if (GreGetObjectOwner(hobj) != GDI_OBJ_HMGR_POWNED)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (GDI_HANDLE_GET_TYPE(hobj) != GDI_OBJECT_TYPE_DC)
        return GreDeleteObject(hobj);

    // FIXME: Everything should be callback based
    return IntGdiDeleteDC(hobj, FALSE);
}

BOOL
FASTCALL
MakeInfoDC(PDC pdc, BOOL bSet)
{
    PSURFACE pSurface;
    SIZEL sizl;

    /* Can not be a display DC. */
    if (pdc->fs & DC_DISPLAY) return FALSE;
    if (bSet)
    {
        if (pdc->fs & DC_TEMPINFODC || pdc->dctype == DCTYPE_DIRECT)
            return FALSE;

        pSurface = pdc->dclevel.pSurface;
        pdc->fs |= DC_TEMPINFODC;
        pdc->pSurfInfo = pSurface;
        pdc->dctype = DCTYPE_INFO;
        pdc->dclevel.pSurface = NULL;

        PDEVOBJ_sizl(pdc->ppdev, &sizl);

        if ( sizl.cx == pdc->dclevel.sizl.cx &&
             sizl.cy == pdc->dclevel.sizl.cy )
            return TRUE;

        pdc->dclevel.sizl.cx = sizl.cx;
        pdc->dclevel.sizl.cy = sizl.cy;
    }
    else
    {
        if (!(pdc->fs & DC_TEMPINFODC) || pdc->dctype != DCTYPE_INFO)
            return FALSE;

        pSurface = pdc->pSurfInfo;
        pdc->fs &= ~DC_TEMPINFODC;
        pdc->dclevel.pSurface = pSurface;
        pdc->dctype = DCTYPE_DIRECT;
        pdc->pSurfInfo = NULL;

        if ( !pSurface ||
             (pSurface->SurfObj.sizlBitmap.cx == pdc->dclevel.sizl.cx &&
              pSurface->SurfObj.sizlBitmap.cy == pdc->dclevel.sizl.cy) )
            return TRUE;

        pdc->dclevel.sizl.cx = pSurface->SurfObj.sizlBitmap.cx;
        pdc->dclevel.sizl.cy = pSurface->SurfObj.sizlBitmap.cy;
    }
    return IntSetDefaultRegion(pdc);
}

/*
* @implemented
*/
BOOL
APIENTRY
NtGdiMakeInfoDC(
    IN HDC hdc,
    IN BOOL bSet)
{
    BOOL Ret;
    PDC pdc = DC_LockDc(hdc);
    if (pdc)
    {
        Ret = MakeInfoDC(pdc, bSet);
        DC_UnlockDc(pdc);
        return Ret;
    }
    return FALSE;
}


HDC FASTCALL
IntGdiCreateDC(
    PUNICODE_STRING Driver,
    PUNICODE_STRING pustrDevice,
    PVOID pUMdhpdev,
    CONST PDEVMODEW pdmInit,
    BOOL CreateAsIC)
{
    HDC hdc;

    hdc = GreOpenDCW(pustrDevice,
                     pdmInit,
                     NULL,
                     CreateAsIC ? DCTYPE_INFO :
                          (Driver ? DCTYPE_DIRECT : DCTYPE_DIRECT),
                     TRUE,
                     NULL,
                     NULL,
                     pUMdhpdev);

    return hdc;
}

HDC FASTCALL
IntGdiCreateDisplayDC(HDEV hDev, ULONG DcType, BOOL EmptyDC)
{
    HDC hDC;
    UNIMPLEMENTED;

    if (DcType == DCTYPE_MEMORY)
        hDC = GreCreateCompatibleDC(NULL, FALSE);
    else
        hDC = IntGdiCreateDC(NULL, NULL, NULL, NULL, (DcType == DCTYPE_INFO));

    return hDC;
}

/*
 * GreSetDCOrg for a window DC whose binding USER changed: from another process or the frame timer, which
 * DC_LockDc refuses for a DC that a process owns. Only kernel fields of the DC are set.
 */
BOOL
NTAPI
GreRedirSetDCOrg(
    _In_ HDC hdc,
    _In_ LONG x,
    _In_ LONG y,
    _In_opt_ PRECTL prcl)
{
    PDC pdc = DC_LockDcAnyOwner(hdc);

    if (!pdc)
        return FALSE;
    pdc->ptlDCOrig.x = x;
    pdc->ptlDCOrig.y = y;
    pdc->ptlFillOrigin.x = pdc->dclevel.ptlBrushOrigin.x + x;
    pdc->ptlFillOrigin.y = pdc->dclevel.ptlBrushOrigin.y + y;
    if (prcl)
        pdc->erclWindow = *prcl;
    DC_UnlockDc(pdc);
    return TRUE;
}

/*
 * Binds a window DC to a redirection surface (ntuser/redir.c), or with psurf NULL back to the screen.
 * pvRedir is USER's record for the window; *ppvOld gets the record the DC had (USER keeps the
 * references). The DC stays DCTYPE_DIRECT; DC_REDIRECTION makes it draw like a memory DC into the surface.
 * Called from any process and from the frame timer: the DC's user-mode attributes (pdcattr, memory of
 * the process that owns the DC) are not touched here (DC_REDIR_ATTRDIRTY, applied by DC_LockDc).
 */
ULONG
NTAPI
GreRedirBindDC(
    _In_ HDC hdc,
    _In_opt_ PVOID pvRedir,
    _In_opt_ PSURFACE psurf,
    _Out_ PVOID *ppvOld)
{
    PDC pdc;

    *ppvOld = NULL;
    /* Fails for a DC another process holds locked for long: the caller keeps the binding and tries again */
    pdc = DC_LockDcAnyOwner(hdc);
    if (!pdc)
        return GreIsHandleValidAnyOwner(hdc) ? REDIRBIND_BUSY : REDIRBIND_GONE;
    if (pdc->dctype != DCTYPE_DIRECT)
    {
        DC_UnlockDc(pdc);
        return REDIRBIND_GONE;
    }

    *ppvOld = (pdc->fs & DC_REDIRECTION) ? pdc->pvRedir : NULL;
    RECTL_vSetEmptyRect(&pdc->rclRedirDraw);
    if (psurf)
    {
        /* The DC takes its own reference on the surface (by pointer: the handle has no owner) */
        DC_vSelectSurface(pdc, psurf);
        pdc->dclevel.sizl = pdc->dclevel.pSurface->SurfObj.sizlBitmap;
        pdc->fs |= DC_REDIRECTION | DC_DIRTY_RAO | DC_REDIR_ATTRDIRTY;

        /* And on the record, which it marks dirty until it is bound elsewhere or freed */
        if (pvRedir != *ppvOld)
        {
            if (pvRedir)
                UserRedirAddRef(pvRedir);
            if (*ppvOld)
                UserRedirDcRelease(*ppvOld);
        }
        pdc->pvRedir = pvRedir;
    }
    else if (pdc->fs & DC_REDIRECTION)
    {
        pdc->fs &= ~DC_REDIRECTION;
        pdc->fs |= DC_REDIR_ATTRDIRTY;
        if (pdc->pvRedir)
            UserRedirDcRelease(pdc->pvRedir);
        pdc->pvRedir = NULL;
        /* The screen again (drops the DC's reference on the surface) */
        DC_vUpdateDCSurface(pdc);
    }
    DC_UnlockDc(pdc);
    return REDIRBIND_OK;
}

/* Copies cx x cy of a redirection surface, from xSrc, ySrc, to hdcDest at 0, 0 (PrintWindow) */
BOOL
NTAPI
GreRedirCopyToDC(
    _In_ PSURFACE psurf,
    _In_ HDC hdcDest,
    _In_ LONG xSrc,
    _In_ LONG ySrc,
    _In_ LONG cx,
    _In_ LONG cy)
{
    HDC hdcMem;
    PDC pdc;
    PREGION prgn;
    BOOL bRet = FALSE;

    hdcMem = GreCreateCompatibleDC(NULL, FALSE);
    if (!hdcMem)
        return FALSE;

    /* By pointer: the surface handle has no owner a process matches */
    pdc = psurf ? DC_LockDc(hdcMem) : NULL;
    if (pdc)
    {
        /* A reference of its own, without the one-DC mark of a selected bitmap */
        DC_vSelectSurface(pdc, psurf);
        pdc->dclevel.sizl = psurf->SurfObj.sizlBitmap;
        pdc->fs |= DC_DIRTY_RAO;
        DC_UnlockDc(pdc);

        prgn = IntSysCreateRectpRgn(0, 0, psurf->SurfObj.sizlBitmap.cx, psurf->SurfObj.sizlBitmap.cy);
        if (prgn)
        {
            GdiSelectVisRgn(hdcMem, prgn);
            REGION_Delete(prgn);
            bRet = NtGdiBitBlt(hdcDest, 0, 0, cx, cy, hdcMem, xSrc, ySrc, SRCCOPY, CLR_INVALID, 0);
        }

        pdc = DC_LockDc(hdcMem);
        if (pdc)
        {
            DC_vSelectSurface(pdc, NULL);
            DC_UnlockDc(pdc);
        }
    }
    IntGdiDeleteDC(hdcMem, TRUE);
    return bRet;
}

