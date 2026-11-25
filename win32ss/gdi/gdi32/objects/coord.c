/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS System Libraries
 * FILE:            win32ss/gdi/gdi32/objects/coord.c
 * PURPOSE:         Functions for coordinate transformation
 * PROGRAMMER:
 */
#include <precomp.h>

/* Currently we use a MATRIX inside the DC_ATTR containing the
   coordinate transformations, while we deal with XFORM structures
   internally. If we move all coordinate transformation to gdi32,
   we might as well have an XFORM structure in the DC_ATTR. */
void
MatrixToXForm(XFORM *pxform, const MATRIX *pmx)
{
    XFORML *pxforml = (XFORML*)pxform;
    pxforml->eM11 = FOtoF(&pmx->efM11);
    pxforml->eM12 = FOtoF(&pmx->efM12);
    pxforml->eM21 = FOtoF(&pmx->efM21);
    pxforml->eM22 = FOtoF(&pmx->efM22);
    pxforml->eDx = FOtoF(&pmx->efDx);
    pxforml->eDy = FOtoF(&pmx->efDy);
}

void
GdiTransformPoints2(
    _In_ XFORM *pxform,
    _Out_writes_(nCount) PPOINT pptOut,
    _In_reads_(nCount) PPOINT pptIn,
    _In_ ULONG nCount)
{
    ULONG i;
    FLOAT x, y;

    for (i = 0; i < nCount; i++)
    {
        x = pptIn[i].x * pxform->eM11 + pptIn[i].y * pxform->eM12 + pxform->eDx;
        pptOut[i].x = _lrintf(x);
        y = pptIn[i].x * pxform->eM21 + pptIn[i].y * pxform->eM22 + pxform->eDy;
        pptOut[i].y = _lrintf(y);
    }
}

FORCEINLINE
void
GdiTransformPoints(
    _In_ MATRIX *pmx,
    _Out_writes_(nCount) PPOINT pptOut,
    _In_reads_(nCount) PPOINT pptIn,
    _In_ ULONG nCount)
{
    XFORM xform;

    MatrixToXForm(&xform, pmx);
    GdiTransformPoints2(&xform, pptOut, pptIn, nCount);
}

#define MAX_OFFSET 4294967041.0
#define _fmul(x,y) (((x) == 0) ? 0 : (x) * (y))

BOOL
WINAPI
CombineTransform(
    _Out_ LPXFORM pxfResult,
    _In_ const XFORM *pxf1,
    _In_ const XFORM *pxf2)
{
    XFORM xformTmp;

    /* Check paramters */
    if (!pxfResult || !pxf1 || !pxf2) return FALSE;

    /* Do matrix multiplication, start with scaling elements */
    xformTmp.eM11 = (pxf1->eM11 * pxf2->eM11) + (pxf1->eM12 * pxf2->eM21);
    xformTmp.eM22 = (pxf1->eM21 * pxf2->eM12) + (pxf1->eM22 * pxf2->eM22);

    /* Calculate shear/rotate elements only of they are present */
    if ((pxf1->eM12 != 0.) || (pxf1->eM21 != 0.) ||
        (pxf2->eM12 != 0.) || (pxf2->eM21 != 0.))
    {
        xformTmp.eM12 = (pxf1->eM11 * pxf2->eM12) + (pxf1->eM12 * pxf2->eM22);
        xformTmp.eM21 = (pxf1->eM21 * pxf2->eM11) + (pxf1->eM22 * pxf2->eM21);
    }
    else
    {
        xformTmp.eM12 = 0.;
        xformTmp.eM21 = 0.;
    }

    /* Calculate the offset */
    xformTmp.eDx = _fmul(pxf1->eDx, pxf2->eM11) + _fmul(pxf1->eDy, pxf2->eM21) + pxf2->eDx;
    xformTmp.eDy = _fmul(pxf1->eDx, pxf2->eM12) + _fmul(pxf1->eDy, pxf2->eM22) + pxf2->eDy;

    /* Check for invalid offset ranges */
    if ((xformTmp.eDx > MAX_OFFSET) || (xformTmp.eDx < -MAX_OFFSET) ||
        (xformTmp.eDy > MAX_OFFSET) || (xformTmp.eDy < -MAX_OFFSET))
    {
        return FALSE;
    }

    /* All is ok, return the calculated values */
    *pxfResult = xformTmp;
    return TRUE;
}


/*
 * @implemented
 *
 */
int
WINAPI
GetMapMode(
    _In_ HDC hdc)
{
    PDC_ATTR pdcattr;

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Return the map mode */
    return pdcattr->iMapMode;
}

/*
 * @implemented
 */
INT
WINAPI
SetMapMode(
    _In_ HDC hdc,
    _In_ INT iMode)
{
    PDC_ATTR pdcattr;

    /* Handle METADC16 here, since we don't have a DCATTR. */
    if (GDI_HANDLE_GET_TYPE(hdc) == GDILoObjType_LO_METADC16_TYPE) \
    {
        return METADC_SetMapMode(hdc, iMode);
    }

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Force change if Isotropic is set for recompute. */
    if ((iMode != pdcattr->iMapMode) || (iMode == MM_ISOTROPIC))
    {
        pdcattr->ulDirty_ &= ~SLOW_WIDTHS;
        return GetAndSetDCDWord(hdc, GdiGetSetMapMode, iMode, EMR_SETMAPMODE, 0, 0 );
    }

    return pdcattr->iMapMode;
}


/*
 * Windows answers LPtoDP/DPtoLP for a DC whose transform is the identity without a call to the kernel, so
 * a pointer that is NULL or invalid is not looked at and the call succeeds (measured on Windows Server 2022:
 * MM_TEXT and MM_ANISOTROPIC with 1:1 extents, no origin, no world transform; MM_ISOTROPIC and every other
 * state go to the kernel, which fails for a pointer it cannot read or write).
 */
static
BOOL
IntIsIdentityTransformDc(
    _In_ HDC hdc,
    _In_ PDC_ATTR pdcattr)
{
    XFORM xf;

    /* The DC must also never have been changed since it was made (PAGE_TO_DEVICE_IDENTITY is cleared by the changes
       of the map mode, extents, origins, world transform and layout that Windows counts, see the kernel's coord.c):
       MM_TEXT -> MM_ANISOTROPIC -> MM_TEXT is not identity although the matrix is */
    if (!(pdcattr->flXform & PAGE_TO_DEVICE_IDENTITY))
        return FALSE;

    if ((pdcattr->iMapMode != MM_TEXT) && (pdcattr->iMapMode != MM_ANISOTROPIC))
        return FALSE;

    if ((pdcattr->szlWindowExt.cx != 1) || (pdcattr->szlWindowExt.cy != 1) ||
        (pdcattr->szlViewportExt.cx != 1) || (pdcattr->szlViewportExt.cy != 1))
        return FALSE;

    if (pdcattr->ptlWindowOrg.x || pdcattr->ptlWindowOrg.y ||
        pdcattr->ptlViewportOrg.x || pdcattr->ptlViewportOrg.y)
        return FALSE;

    if (pdcattr->iGraphicsMode == GM_ADVANCED)
    {
        if (!NtGdiGetTransform(hdc, GdiWorldSpaceToPageSpace, &xf))
            return FALSE;
        if (xf.eM11 != 1.0f || xf.eM22 != 1.0f || xf.eM12 != 0.0f || xf.eM21 != 0.0f ||
            xf.eDx != 0.0f || xf.eDy != 0.0f)
            return FALSE;
    }

    return TRUE;
}

BOOL
WINAPI
DPtoLP(
    _In_ HDC hdc,
    _Inout_updates_(nCount) LPPOINT lpPoints,
    _In_ INT nCount)
{
    PDC_ATTR pdcattr;
    SIZEL sizlView;

    if (nCount <= 0)
        return TRUE;

    if (hdc == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
        return FALSE;

    if (IntIsIdentityTransformDc(hdc, pdcattr))
        return TRUE;

    if (pdcattr->iMapMode == MM_ISOTROPIC)
    {
        if (NtGdiGetDCPoint(hdc, GdiGetViewPortExt, (PPOINTL)&sizlView))
        {
            if (sizlView.cx == 0 || sizlView.cy == 0)
                return FALSE;
        }
    }

    return NtGdiTransformPoints(hdc, lpPoints, lpPoints, nCount, GdiDpToLp);
}

/*
 * LPtoDP through 28.4 fixed point (see LPtoDP). Coordinates of 2^27 and more do not fit 28.4: a call with one of them,
 * and a coordinate that comes back from the kernel saturated (LONG_MAX / LONG_MIN), keep the plain transform, which is
 * exact for the large values that an offset or a unity scale produces (INT_MAX stays INT_MAX), as before.
 */
#define FIXED_LIMIT 0x08000000L

static
BOOL
IntLPtoDPFixed(
    _In_ HDC hdc,
    _Inout_updates_(nCount) LPPOINT lpPoints,
    _In_ INT nCount)
{
    POINT Stack[16], *pIn = Stack;
    BOOL bRet = TRUE, bLarge = FALSE, bSaturated = FALSE;
    INT i;

    if ((UINT)nCount > _countof(Stack))
    {
        pIn = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)nCount * sizeof(POINT));
        if (!pIn)
            return NtGdiTransformPoints(hdc, lpPoints, lpPoints, nCount, GdiLpToDp);
    }

    /* Our copy of the points (a pointer that cannot be read fails the call, as the kernel did) */
    _SEH2_TRY
    {
        RtlCopyMemory(pIn, lpPoints, (SIZE_T)nCount * sizeof(POINT));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        bRet = FALSE;
    }
    _SEH2_END;

    if (bRet)
    {
        for (i = 0; i < nCount; i++)
        {
            if (pIn[i].x >= FIXED_LIMIT || pIn[i].x < -FIXED_LIMIT || pIn[i].y >= FIXED_LIMIT || pIn[i].y < -FIXED_LIMIT)
                bLarge = TRUE;
        }

        if (bLarge)
        {
            bRet = NtGdiTransformPoints(hdc, lpPoints, lpPoints, nCount, GdiLpToDp);
        }
        else
        {
            /* the 28.4 values go straight to the caller's points: the kernel fails for a buffer it cannot write */
            bRet = NtGdiTransformPoints(hdc, pIn, lpPoints, nCount, 2);
            for (i = 0; bRet && i < nCount; i++)
            {
                if (lpPoints[i].x == LONG_MAX || lpPoints[i].x == LONG_MIN)
                    bSaturated = TRUE;
                else
                    lpPoints[i].x = (LONG)(((LONGLONG)lpPoints[i].x + 8) >> 4);
                if (lpPoints[i].y == LONG_MAX || lpPoints[i].y == LONG_MIN)
                    bSaturated = TRUE;
                else
                    lpPoints[i].y = (LONG)(((LONGLONG)lpPoints[i].y + 8) >> 4);
            }

            if (bRet && bSaturated)
            {
                /* the plain transform of the saved points, for the coordinates that did not fit */
                bRet = NtGdiTransformPoints(hdc, pIn, pIn, nCount, GdiLpToDp);
                for (i = 0; bRet && i < nCount; i++)
                {
                    if (lpPoints[i].x == LONG_MAX || lpPoints[i].x == LONG_MIN)
                        lpPoints[i].x = pIn[i].x;
                    if (lpPoints[i].y == LONG_MAX || lpPoints[i].y == LONG_MIN)
                        lpPoints[i].y = pIn[i].y;
                }
            }
        }
    }

    if (pIn != Stack)
        HeapFree(GetProcessHeap(), 0, pIn);
    return bRet;
}

BOOL
WINAPI
LPtoDP(
    _In_ HDC hdc,
    _Inout_updates_(nCount) LPPOINT lpPoints,
    _In_ INT nCount)
{
    PDC_ATTR pdcattr;

    if (nCount <= 0)
        return TRUE;

    if (hdc == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
        return FALSE;

    if (IntIsIdentityTransformDc(hdc, pdcattr))
        return TRUE;

    /* Windows converts through 28.4 fixed point: f = v * 16 rounded, then (f + 8) >> 4 (recorded Windows Server 2022
       rows: 336 coordinates, 50.4999 gives 51 where plain rounding gives 50). The kernel's mode 2 returns f (a value
       that is exactly n + 0.5 sixteenths rounds away from zero there; the recorded rows do not tell that from
       flooring). Only LPtoDP does this: the points the kernel transforms for drawing keep their rounding, and so
       does DPtoLP. */
    return IntLPtoDPFixed(hdc, lpPoints, nCount);
}

/*
 * @implemented
 *
 */
BOOL
WINAPI
GetCurrentPositionEx(
    _In_ HDC hdc,
    _Out_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if ((pdcattr == NULL) || (lpPoint == NULL))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (pdcattr->ulDirty_ & DIRTY_PTLCURRENT) // have a hit!
    {
        lpPoint->x = pdcattr->ptfxCurrent.x;
        lpPoint->y = pdcattr->ptfxCurrent.y;
        DPtoLP(hdc, lpPoint, 1);          // reconvert back.
        pdcattr->ptlCurrent.x = lpPoint->x; // save it
        pdcattr->ptlCurrent.y = lpPoint->y;
        pdcattr->ulDirty_ &= ~DIRTY_PTLCURRENT; // clear bit
    }
    else
    {
        lpPoint->x = pdcattr->ptlCurrent.x;
        lpPoint->y = pdcattr->ptlCurrent.y;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetWorldTransform(
    _In_ HDC hdc,
    _Out_ LPXFORM pxform)
{
    PDC_ATTR pdcattr;

    pdcattr = GdiGetDcAttr(hdc);
    if (!pdcattr)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
#if 0
    if (pdcattr->flXform & ANY_XFORM_INVALID)
    {
        GdiFixupTransforms(pdcattr);
    }

    MatrixToXForm(pxform, &pdcattr->mxWorldToDevice);
#endif
    return NtGdiGetTransform(hdc, GdiWorldSpaceToPageSpace, pxform);
}


BOOL
WINAPI
SetWorldTransform(
    _In_ HDC hdc,
    _Out_ CONST XFORM *pxform)
{
    return ModifyWorldTransform(hdc, pxform, MWT_SET);
}


BOOL
WINAPI
ModifyWorldTransform(
    _In_ HDC hdc,
    _In_opt_ CONST XFORM *pxform,
    _In_ DWORD dwMode)
{
    PDC_ATTR pdcattr;

    if (GDI_HANDLE_GET_TYPE(hdc) == GDILoObjType_LO_METADC16_TYPE)
        return FALSE;

    if (dwMode == MWT_SET)
    {
       HANDLE_EMETAFDC(BOOL, SetWorldTransform, FALSE, hdc, pxform);
    }
    else
    {
       HANDLE_EMETAFDC(BOOL, ModifyWorldTransform, FALSE, hdc, pxform, dwMode);
    }

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Check that graphics mode is GM_ADVANCED */
    if (pdcattr->iGraphicsMode != GM_ADVANCED)
        return FALSE;

    /* Call win32k to do the work */
    return NtGdiModifyWorldTransform(hdc, (LPXFORM)pxform, dwMode);
}

BOOL
WINAPI
GetViewportExtEx(
    _In_ HDC hdc,
    _Out_ LPSIZE lpSize)
{
    PDC_ATTR pdcattr;

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    /* Check if we need to update values */
    if ((pdcattr->flXform & PAGE_EXTENTS_CHANGED) &&
        (pdcattr->iMapMode == MM_ISOTROPIC))
    {
        /* Call win32k to do the work */
        return NtGdiGetDCPoint(hdc, GdiGetViewPortExt, (PPOINTL)lpSize);
    }

    /* Nothing to calculate, return the current extension */
    lpSize->cx = pdcattr->szlViewportExt.cx;
    lpSize->cy = pdcattr->szlViewportExt.cy;

    return TRUE;
}


BOOL
WINAPI
GetViewportOrgEx(
    _In_ HDC hdc,
    _Out_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    /* Get the current viewport org */
    lpPoint->x = pdcattr->ptlViewportOrg.x;
    lpPoint->y = pdcattr->ptlViewportOrg.y;

    /* Handle right-to-left layout */
    if (pdcattr->dwLayout & LAYOUT_RTL)
        lpPoint->x = -lpPoint->x;

    return TRUE;
}


BOOL
WINAPI
GetWindowExtEx(
    _In_ HDC hdc,
    _Out_ LPSIZE lpSize)
{
    PDC_ATTR pdcattr;

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    /* Get the current window extension */
    lpSize->cx = pdcattr->szlWindowExt.cx;
    lpSize->cy = pdcattr->szlWindowExt.cy;

    /* Handle right-to-left layout */
    if (pdcattr->dwLayout & LAYOUT_RTL)
        lpSize->cx = -lpSize->cx;

    return TRUE;
}


BOOL
WINAPI
GetWindowOrgEx(
    _In_ HDC hdc,
    _Out_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    /* Get the current window origin */
    lpPoint->x = pdcattr->ptlWindowOrg.x;
    lpPoint->y = pdcattr->ptlWindowOrg.y;

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetViewportExtEx(
    _In_ HDC hdc,
    _In_ int nXExtent,
    _In_ int nYExtent,
    _Out_opt_ LPSIZE lpSize)
{
    PDC_ATTR pdcattr;

    HANDLE_METADC(BOOL, SetViewportExtEx, FALSE, hdc, nXExtent, nYExtent);

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Check if the caller wants the old extension */
    if (lpSize)
    {
        /* Return the current viewport extension */
        lpSize->cx = pdcattr->szlViewportExt.cx;
        lpSize->cy = pdcattr->szlViewportExt.cy;
    }

    /* Check for trivial case */
    if ((pdcattr->szlViewportExt.cx == nXExtent) &&
        (pdcattr->szlViewportExt.cy == nYExtent))
        return TRUE;

    if (nXExtent == 0 || nYExtent == 0)
        return TRUE;

    /* Only change viewport extension if we are in iso or aniso mode */
    if ((pdcattr->iMapMode == MM_ISOTROPIC) ||
        (pdcattr->iMapMode == MM_ANISOTROPIC))
    {
        if (W32GetCurrentTeb()->GdiTebBatch.HDC == W32GdiHandle(hdc))
        {
            if (pdcattr->ulDirty_ & DC_MODE_DIRTY)
            {
                NtGdiFlush(); // Sync up pdcattr from Kernel space.
                pdcattr->ulDirty_ &= ~DC_MODE_DIRTY;
            }
        }

        /* Set the new viewport extension */
        pdcattr->szlViewportExt.cx = nXExtent;
        pdcattr->szlViewportExt.cy = nYExtent;
        pdcattr->flXform &= ~PAGE_TO_DEVICE_IDENTITY;

        /* Handle right-to-left layout */
        if (pdcattr->dwLayout & LAYOUT_RTL)
            NtGdiMirrorWindowOrg(hdc);

        /* Update xform flags */
        pdcattr->flXform |= (PAGE_EXTENTS_CHANGED|INVALIDATE_ATTRIBUTES|DEVICE_TO_WORLD_INVALID);
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetWindowOrgEx(
    _In_ HDC hdc,
    _In_ int X,
    _In_ int Y,
    _Out_opt_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    HANDLE_METADC(BOOL, SetWindowOrgEx, FALSE, hdc, X, Y);

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (pdcattr == NULL)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    if (lpPoint)
    {
        lpPoint->x = pdcattr->ptlWindowOrg.x;
        lpPoint->y = pdcattr->ptlWindowOrg.y;
    }

    if ((pdcattr->ptlWindowOrg.x == X) && (pdcattr->ptlWindowOrg.y == Y))
        return TRUE;

    if (W32GetCurrentTeb()->GdiTebBatch.HDC == W32GdiHandle(hdc))
    {
        if (pdcattr->ulDirty_ & DC_MODE_DIRTY)
        {
            NtGdiFlush(); // Sync up pdcattr from Kernel space.
            pdcattr->ulDirty_ &= ~DC_MODE_DIRTY;
        }
    }

    pdcattr->ptlWindowOrg.x = X;
    pdcattr->ptlWindowOrg.y = Y;
    pdcattr->flXform &= ~PAGE_TO_DEVICE_IDENTITY;

    pdcattr->lWindowOrgx    = X;
    if (pdcattr->dwLayout & LAYOUT_RTL) NtGdiMirrorWindowOrg(hdc);
    pdcattr->flXform |= (PAGE_XLATE_CHANGED|WORLD_XFORM_CHANGED|DEVICE_TO_WORLD_INVALID);
    return TRUE;

//    return NtGdiSetWindowOrgEx(hdc, X, Y, lpPoint);
}

/*
 * @implemented
 */
BOOL
WINAPI
SetWindowExtEx(
    _In_ HDC hdc,
    _In_ INT nXExtent,
    _In_ INT nYExtent,
    _Out_opt_ LPSIZE lpSize)
{
    PDC_ATTR pdcattr;

    HANDLE_METADC(BOOL, SetWindowExtEx, FALSE, hdc, nXExtent, nYExtent);

    /* Get the DC attr */
    pdcattr = GdiGetDcAttr(hdc);
    if (!pdcattr)
    {
        /* Set the error value and return failure */
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Check if the caller wants the old extension */
    if (lpSize)
    {
        /* Return the current window extension */
        lpSize->cx = pdcattr->szlWindowExt.cx;
        lpSize->cy = pdcattr->szlWindowExt.cy;

        /* Handle right-to-left layout */
        if (pdcattr->dwLayout & LAYOUT_RTL)
            lpSize->cx = -lpSize->cx;
    }

    if (pdcattr->dwLayout & LAYOUT_RTL)
    {
        NtGdiMirrorWindowOrg(hdc);
        pdcattr->flXform |= (PAGE_EXTENTS_CHANGED|INVALIDATE_ATTRIBUTES|DEVICE_TO_WORLD_INVALID);
    }
    else if ((pdcattr->iMapMode == MM_ISOTROPIC) ||
             (pdcattr->iMapMode == MM_ANISOTROPIC))
    {
        if ((pdcattr->szlWindowExt.cx == nXExtent) &&
            (pdcattr->szlWindowExt.cy == nYExtent))
            return TRUE;

        if ((!nXExtent) || (!nYExtent))
            return FALSE;

        if (W32GetCurrentTeb()->GdiTebBatch.HDC == W32GdiHandle(hdc))
        {
            if (pdcattr->ulDirty_ & DC_MODE_DIRTY)
            {
                NtGdiFlush(); // Sync up Dc_Attr from Kernel space.
                pdcattr->ulDirty_ &= ~DC_MODE_DIRTY;
            }
        }

        pdcattr->szlWindowExt.cx = nXExtent;
        pdcattr->szlWindowExt.cy = nYExtent;
        pdcattr->flXform &= ~PAGE_TO_DEVICE_IDENTITY;
        if (pdcattr->dwLayout & LAYOUT_RTL)
            NtGdiMirrorWindowOrg(hdc);

        pdcattr->flXform |= (PAGE_EXTENTS_CHANGED|INVALIDATE_ATTRIBUTES|DEVICE_TO_WORLD_INVALID);
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetViewportOrgEx(
    _In_ HDC hdc,
    _In_ int X,
    _In_ int Y,
    _Out_opt_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    HANDLE_METADC(BOOL, SetViewportOrgEx, FALSE, hdc, X, Y);

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (!pdcattr)
    {
        /* Do not set LastError here! */
        return FALSE;
    }
    //// HACK : XP+ doesn't do this. See CORE-16656 & CORE-16644.
    if (W32GetCurrentTeb()->GdiTebBatch.HDC == W32GdiHandle(hdc))
    {
        if (pdcattr->ulDirty_ & DC_MODE_DIRTY)
        {
            NtGdiFlush();
            pdcattr->ulDirty_ &= ~DC_MODE_DIRTY;
        }
    }
    ////
    if (lpPoint)
    {
        lpPoint->x = pdcattr->ptlViewportOrg.x;
        lpPoint->y = pdcattr->ptlViewportOrg.y;
        if (pdcattr->dwLayout & LAYOUT_RTL) lpPoint->x = -lpPoint->x;
    }
    pdcattr->flXform |= (PAGE_XLATE_CHANGED|WORLD_XFORM_CHANGED|DEVICE_TO_WORLD_INVALID);
    if (pdcattr->dwLayout & LAYOUT_RTL) X = -X;
    if ((pdcattr->ptlViewportOrg.x != X) || (pdcattr->ptlViewportOrg.y != Y))
        pdcattr->flXform &= ~PAGE_TO_DEVICE_IDENTITY;
    pdcattr->ptlViewportOrg.x = X;
    pdcattr->ptlViewportOrg.y = Y;
    return TRUE;

//    return NtGdiSetViewportOrgEx(hdc,X,Y,lpPoint);
}

/*
 * @implemented
 */
BOOL
WINAPI
ScaleViewportExtEx(
    _In_ HDC hdc,
    _In_ INT xNum,
    _In_ INT xDenom,
    _In_ INT yNum,
    _In_ INT yDenom,
    _Out_ LPSIZE lpSize)
{
    HANDLE_METADC(BOOL, ScaleViewportExtEx, FALSE, hdc, xNum, xDenom, yNum, yDenom);

    if (!GdiGetDcAttr(hdc))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return NtGdiScaleViewportExtEx(hdc, xNum, xDenom, yNum, yDenom, lpSize);
}

/*
 * @implemented
 */
BOOL
WINAPI
ScaleWindowExtEx(
    _In_ HDC hdc,
    _In_ INT xNum,
    _In_ INT xDenom,
    _In_ INT yNum,
    _In_ INT yDenom,
    _Out_ LPSIZE lpSize)
{
    HANDLE_METADC(BOOL, ScaleWindowExtEx, FALSE, hdc, xNum, xDenom, yNum, yDenom);

    if (!GdiGetDcAttr(hdc))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return NtGdiScaleWindowExtEx(hdc, xNum, xDenom, yNum, yDenom, lpSize);
}

/*
 * @implemented
 */
DWORD
WINAPI
GetLayout(
    _In_ HDC hdc)
{
    PDC_ATTR pdcattr;

    /* METADC16 is not supported in this API */
    if (GDI_HANDLE_GET_TYPE(hdc) == GDILoObjType_LO_METADC16_TYPE)
    {
        return GDI_ERROR;
    }

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (!pdcattr)
    {
        /* Set the error value and return failure */
        SetLastError(ERROR_INVALID_PARAMETER);
        return GDI_ERROR;
    }

    /* Return the layout */
    return pdcattr->dwLayout;
}


/*
 * @implemented
 */
DWORD
WINAPI
SetLayout(
    _In_ HDC hdc,
    _In_ DWORD dwLayout)
{
    HANDLE_METADC(DWORD, SetLayout, GDI_ERROR, hdc, dwLayout);

    if (!GdiGetDcAttr(hdc))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return GDI_ERROR;
    }

    return NtGdiSetLayout(hdc, -1, dwLayout);
}

/*
 * @implemented
 */
DWORD
WINAPI
SetLayoutWidth(
    _In_ HDC hdc,
    _In_ LONG wox,
    _In_ DWORD dwLayout)
{
    /* Only normal DCs are handled here */
    if (GDI_HANDLE_GET_TYPE(hdc) != GDILoObjType_LO_DC_TYPE)
    {
        return GDI_ERROR;
    }

    if (!GdiGetDcAttr(hdc))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return GDI_ERROR;
    }

    return NtGdiSetLayout(hdc, wox, dwLayout);
}

/*
 * @implemented
 */
BOOL
WINAPI
GetDCOrgEx(
    _In_ HDC hdc,
    _Out_ LPPOINT lpPoint)
{
    return NtGdiGetDCPoint(hdc, GdiGetDCOrg, (PPOINTL)lpPoint);
}


/*
 * @implemented
 */
LONG
WINAPI
GetDCOrg(
    _In_ HDC hdc)
{
    POINT pt;

    /* Call the new API */
    if (!GetDCOrgEx(hdc, &pt))
        return 0;

    /* Return the point in the old way */
    return(MAKELONG(pt.x, pt.y));
}


/*
 * @implemented
 *
 */
BOOL
WINAPI
OffsetViewportOrgEx(
    _In_ HDC hdc,
    _In_ int nXOffset,
    _In_ int nYOffset,
    _Out_opt_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    HANDLE_METADC16(BOOL, OffsetViewportOrgEx, FALSE, hdc, nXOffset, nYOffset);

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (!pdcattr)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    if (lpPoint)
    {
        *lpPoint = pdcattr->ptlViewportOrg;
        if ( pdcattr->dwLayout & LAYOUT_RTL) lpPoint->x = -lpPoint->x;
    }

    if ( nXOffset || nYOffset != nXOffset )
    {
        if (W32GetCurrentTeb()->GdiTebBatch.HDC == W32GdiHandle(hdc))
        {
            if (pdcattr->ulDirty_ & DC_MODE_DIRTY)
            {
                NtGdiFlush();
                pdcattr->ulDirty_ &= ~DC_MODE_DIRTY;
            }
        }

        pdcattr->flXform |= (PAGE_XLATE_CHANGED|WORLD_XFORM_CHANGED|DEVICE_TO_WORLD_INVALID);
        pdcattr->flXform &= ~PAGE_TO_DEVICE_IDENTITY;
        if (pdcattr->dwLayout & LAYOUT_RTL) nXOffset = -nXOffset;
        pdcattr->ptlViewportOrg.x += nXOffset;
        pdcattr->ptlViewportOrg.y += nYOffset;
    }

    HANDLE_EMETAFDC(BOOL, SetViewportOrgEx, FALSE, hdc, pdcattr->ptlViewportOrg.x, pdcattr->ptlViewportOrg.y);

    return TRUE;

//    return  NtGdiOffsetViewportOrgEx(hdc, nXOffset, nYOffset, lpPoint);
}

/*
 * @implemented
 *
 */
BOOL
WINAPI
OffsetWindowOrgEx(
    _In_ HDC hdc,
    _In_ int nXOffset,
    _In_ int nYOffset,
    _Out_opt_ LPPOINT lpPoint)
{
    PDC_ATTR pdcattr;

    HANDLE_METADC16(BOOL, OffsetWindowOrgEx, FALSE, hdc, nXOffset, nYOffset);

    /* Get the DC attribute */
    pdcattr = GdiGetDcAttr(hdc);
    if (!pdcattr)
    {
        /* Do not set LastError here! */
        return FALSE;
    }

    if ( lpPoint )
    {
        *lpPoint   = pdcattr->ptlWindowOrg;
        //lpPoint->x = pdcattr->lWindowOrgx;
    }

    if ( nXOffset || nYOffset != nXOffset )
    {
        if (W32GetCurrentTeb()->GdiTebBatch.HDC == W32GdiHandle(hdc))
        {
            if (pdcattr->ulDirty_ & DC_MODE_DIRTY)
            {
                NtGdiFlush();
                pdcattr->ulDirty_ &= ~DC_MODE_DIRTY;
            }
        }

        pdcattr->flXform |= (PAGE_XLATE_CHANGED|WORLD_XFORM_CHANGED|DEVICE_TO_WORLD_INVALID);
        pdcattr->flXform &= ~PAGE_TO_DEVICE_IDENTITY;
        pdcattr->ptlWindowOrg.x += nXOffset;
        pdcattr->ptlWindowOrg.y += nYOffset;
        pdcattr->lWindowOrgx += nXOffset;
    }

    HANDLE_EMETAFDC(BOOL, SetWindowOrgEx, FALSE, hdc, pdcattr->ptlWindowOrg.x, pdcattr->ptlWindowOrg.y);

    return TRUE;

//    return NtGdiOffsetWindowOrgEx(hdc, nXOffset, nYOffset, lpPoint);
}

