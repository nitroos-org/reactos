#pragma once

/* Maximum extend of coordinate space */
#define MIN_COORD (INT_MIN / 16)
#define MAX_COORD (INT_MAX / 16)

#if !defined(_M_IX86)
/*
 * Converts a double to a LONG, rounding to the nearest integer (halves away
 * from zero) like Windows and the i386 FLOATOBJ_bConvertToLong (EngMulDiv). A
 * value outside the LONG range gives LONG_MIN or LONG_MAX; returns FALSE when
 * it was saturated.
 */
static
inline
BOOLEAN
INTERNAL_dToLongSat(DOUBLE d, PLONG pl)
{
    if (d != d)
    {
        /* NaN */
        *pl = 0;
        return FALSE;
    }
    if (d >= 2147483647.5)
    {
        *pl = LONG_MAX;
        return FALSE;
    }
    if (d <= -2147483648.5)
    {
        *pl = LONG_MIN;
        return FALSE;
    }
    *pl = (LONG)((d < 0) ? (d - 0.5) : (d + 0.5));
    return TRUE;
}
#endif

/*
 * Converts a FLOATOBJ to a LONG, rounding to nearest like Windows, but a
 * value outside the LONG range gives LONG_MIN or LONG_MAX (never undefined
 * behaviour). Returns FALSE when the value had to be saturated.
 */
static
inline
BOOLEAN
INTERNAL_FLOATOBJ_bToLongSat(FLOATOBJ *pf, PLONG pl)
{
#if defined(_M_IX86)
    if (FLOATOBJ_bConvertToLong(pf, pl))
        return TRUE;
    *pl = (((EFLOAT_S*)pf)->lMant < 0) ? LONG_MIN : LONG_MAX;
    return FALSE;
#else
    return INTERNAL_dToLongSat(*pf, pl);
#endif
}

/* TRUE if the FLOATOBJ holds an integer that fits a LONG; it is returned in *pl */
static
inline
BOOLEAN
INTERNAL_FLOATOBJ_bIsExactLong(FLOATOBJ *pf, PLONG pl)
{
#if defined(_M_IX86)
    return FLOATOBJ_IsLong(pf) && FLOATOBJ_bConvertToLong(pf, pl);
#else
    return INTERNAL_FLOATOBJ_bToLongSat(pf, pl) && ((FLOAT)*pl == *pf);
#endif
}

/* a + b, saturated to the LONG range; clears *pbOk when it saturates */
static
inline
LONG
INTERNAL_lAddSat(LONG a, LONG b, BOOLEAN *pbOk)
{
    LONGLONG ll = (LONGLONG)a + b;

    if (ll > LONG_MAX)
    {
        *pbOk = FALSE;
        return LONG_MAX;
    }
    if (ll < LONG_MIN)
    {
        *pbOk = FALSE;
        return LONG_MIN;
    }
    return (LONG)ll;
}

/* Clamps a value to the device coordinate space [MIN_COORD, MAX_COORD] */
static
inline
LONG
INTERNAL_lClampCoord(LONGLONG ll)
{
    if (ll > MAX_COORD)
        return MAX_COORD;
    if (ll < MIN_COORD)
        return MIN_COORD;
    return (LONG)ll;
}

/*
 * Applies matrix (which is made of FLOATOBJs) to the points array, which are made of integers.
 *
 * A transform without scaling (identity, or an integer offset such as a window
 * or viewport origin) is exact, as on Windows: coordinates up to INT_MAX pass the
 * identity unchanged. (A FLOAT holds 24 bits, so on amd64 they used to be
 * rounded, and INT_MAX became 2^31, which does not fit a LONG.) A result outside
 * the LONG range is saturated and the function returns FALSE; every point is
 * transformed either way.
 */
static
inline
BOOLEAN
INTERNAL_APPLY_MATRIX(PMATRIX matrix, LPPOINT points, UINT count)
{
    BOOLEAN bResult = TRUE;
    LONG lDx, lDy;

    if ((matrix->flAccel & (XFORM_SCALE | XFORM_UNITY)) == (XFORM_SCALE | XFORM_UNITY))
    {
        if (matrix->flAccel & XFORM_NO_TRANSLATION)
            return TRUE;

        if (INTERNAL_FLOATOBJ_bIsExactLong(&matrix->efDx, &lDx) &&
            INTERNAL_FLOATOBJ_bIsExactLong(&matrix->efDy, &lDy))
        {
            while (count--)
            {
                points[count].x = INTERNAL_lAddSat(points[count].x, lDx, &bResult);
                points[count].y = INTERNAL_lAddSat(points[count].y, lDy, &bResult);
            }
            return bResult;
        }
    }

#if defined(_M_IX86)
    while (count--)
    {
        FLOATOBJ x, y;
        FLOATOBJ tmp;

        /* x = x * matrix->efM11 + y * matrix->efM21 + matrix->efDx; */
        FLOATOBJ_SetLong(&x, points[count].x);
        FLOATOBJ_Mul(&x, &matrix->efM11);
        tmp = matrix->efM21;
        FLOATOBJ_MulLong(&tmp, points[count].y);
        FLOATOBJ_Add(&x, &tmp);
        FLOATOBJ_Add(&x, &matrix->efDx);

        /* y = x * matrix->efM12 + y * matrix->efM22 + matrix->efDy; */
        FLOATOBJ_SetLong(&y, points[count].y);
        FLOATOBJ_Mul(&y, &matrix->efM22);
        tmp = matrix->efM12;
        FLOATOBJ_MulLong(&tmp, points[count].x);
        FLOATOBJ_Add(&y, &tmp);
        FLOATOBJ_Add(&y, &matrix->efDy);

        if (!INTERNAL_FLOATOBJ_bToLongSat(&x, &points[count].x))
            bResult = FALSE;
        if (!INTERNAL_FLOATOBJ_bToLongSat(&y, &points[count].y))
            bResult = FALSE;
    }
#else
    /* Accumulate in double: a FLOAT has 24 bits, so a result a hair below x.5 (7/3 * 1.5 * 59 = 206.49999) could land
       on x.5 and round the other way than on i386, where the FLOATOBJ mantissa has 32 bits. */
    while (count--)
    {
        DOUBLE x, y;

        x = (DOUBLE)points[count].x * matrix->efM11 + (DOUBLE)points[count].y * matrix->efM21 + matrix->efDx;
        y = (DOUBLE)points[count].y * matrix->efM22 + (DOUBLE)points[count].x * matrix->efM12 + matrix->efDy;

        if (!INTERNAL_dToLongSat(x, &points[count].x))
            bResult = FALSE;
        if (!INTERNAL_dToLongSat(y, &points[count].y))
            bResult = FALSE;
    }
#endif
    return bResult;
}

static
inline
BOOLEAN
INTERNAL_LPTODP(DC *dc, LPPOINT points, UINT count)
{
    return INTERNAL_APPLY_MATRIX(&dc->pdcattr->mxWorldToDevice, points, count);
}

static
inline
BOOLEAN
INTERNAL_DPTOLP(DC *dc, LPPOINT points, UINT count)
{
    return INTERNAL_APPLY_MATRIX(&dc->pdcattr->mxDeviceToWorld, points, count);
}

FORCEINLINE
void
XFormToMatrix(
    MATRIX *pmx,
    const XFORML *pxform)
{
    XFORMOBJ xo;
    XFORMOBJ_vInit(&xo, pmx);
    XFORMOBJ_iSetXform(&xo, pxform);
}

FORCEINLINE
void
MatrixToXForm(
    XFORML *pxform,
    const MATRIX *pmx)
{
    XFORMOBJ xo;
    XFORMOBJ_vInit(&xo, (MATRIX*)pmx);
    XFORMOBJ_iGetXform(&xo, pxform);
}

FORCEINLINE
void
InvertXform(
    XFORML *pxformDest,
    const XFORML *pxformSource)
{
    XFORMOBJ xo;
    MATRIX mx;

    XFORMOBJ_vInit(&xo, &mx);
    XFORMOBJ_iSetXform(&xo, pxformSource);
    XFORMOBJ_iInverse(&xo, &xo);
    XFORMOBJ_iGetXform(&xo, pxformDest);
}

VOID
FASTCALL
DC_vFixIsotropicMapping(PDC pdc);

VOID
FASTCALL
DC_vGetPageToDevice(PDC pdc, MATRIX *pmx);

VOID
FASTCALL
DC_vUpdateWorldToDevice(PDC pdc);

VOID
FASTCALL
DC_vUpdateDeviceToWorld(PDC pdc);

FORCEINLINE
PSIZEL
DC_pszlViewportExt(PDC pdc)
{
    PDC_ATTR pdcattr = pdc->pdcattr;

    /* Check if we need isotropic fixup */
    if ((pdcattr->flXform & PAGE_EXTENTS_CHANGED) &&
        (pdcattr->iMapMode == MM_ISOTROPIC))
    {
        /* Fixup viewport extension */
        DC_vFixIsotropicMapping(pdc);
    }

    return &pdcattr->szlViewportExt;
}

FORCEINLINE
PMATRIX
DC_pmxWorldToPage(PDC pdc)
{
    return &pdc->pdcattr->mxWorldToPage;
}

FORCEINLINE
PMATRIX
DC_pmxWorldToDevice(PDC pdc)
{
    /* Check if world or page xform was changed */
    if (pdc->pdcattr->flXform & (PAGE_XLATE_CHANGED|PAGE_EXTENTS_CHANGED|WORLD_XFORM_CHANGED))
    {
        /* Update the world-to-device xform */
         DC_vUpdateWorldToDevice(pdc);
    }

    return &pdc->pdcattr->mxWorldToDevice;
}

FORCEINLINE
PMATRIX
DC_pmxDeviceToWorld(PDC pdc)
{
    /* Check if the device-to-world xform is invalid */
    if (pdc->pdcattr->flXform & DEVICE_TO_WORLD_INVALID)
    {
        /* Update the world-to-device xform */
         DC_vUpdateDeviceToWorld(pdc);
    }

    return &pdc->pdcattr->mxDeviceToWorld;
}

BOOL
NTAPI
GreModifyWorldTransform(
    PDC pdc,
    const XFORML *pXForm,
    DWORD dwMode);

VOID FASTCALL IntMirrorWindowOrg(PDC);
int APIENTRY IntGdiSetMapMode(PDC, int);
BOOL FASTCALL GreLPtoDP(HDC, LPPOINT, INT);
BOOL FASTCALL GreDPtoLP(HDC, LPPOINT, INT);
BOOL APIENTRY GreGetDCPoint(HDC,UINT,PPOINTL);
BOOL WINAPI GreGetWindowExtEx( _In_ HDC hdc, _Out_ LPSIZE lpSize);
BOOL WINAPI GreGetViewportExtEx( _In_ HDC hdc, _Out_ LPSIZE lpSize);
BOOL FASTCALL GreSetViewportOrgEx(HDC,int,int,LPPOINT);
BOOL WINAPI GreGetDCOrgEx(_In_ HDC, _Out_ PPOINTL, _Out_ PRECTL);
BOOL WINAPI GreSetDCOrg(_In_  HDC, _In_ LONG, _In_ LONG, _In_opt_ PRECTL);

static
inline
BOOLEAN
IntLPtoDP(DC* pdc, PPOINTL ppt, UINT count)
{
    DC_vUpdateWorldToDevice(pdc);
    return INTERNAL_LPTODP(pdc, (LPPOINT)ppt, count);
}
#define CoordLPtoDP(pdc, ppt) INTERNAL_LPTODP(pdc, ppt, 1)

static
inline
BOOLEAN
IntDPtoLP(DC* pdc, PPOINTL ppt, UINT count)
{
    DC_vUpdateDeviceToWorld(pdc);
    return INTERNAL_DPTOLP(pdc, (LPPOINT)ppt, count);
}
#define CoordDPtoLP(pdc, ppt) INTERNAL_DPTOLP(pdc, ppt, 1)

#define XForm2MatrixS(m, x) XFormToMatrix(m, (XFORML*)x)
#define MatrixS2XForm(x, m) MatrixToXForm((XFORML*)x, m)
