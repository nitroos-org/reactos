/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS win32 subsystem
 * PURPOSE:          Mouse pointer functions
 * FILE:             win32ss/gdi/eng/mouse.c
 * PROGRAMER:        Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                   Timo Kreuzer (timo.kreuzer@reactos.org)
 */
/* INCLUDES ******************************************************************/

#include <win32k.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS *****************************************************************/

#define PTR_NONE     0 /* the bitmaps cannot be used on this screen; the show makes the pointer again from the bitmaps it was given */
#define PTR_CURRENT  1 /* the bitmaps and the saved pixels are those of this framebuffer */
#define PTR_RESET    2 /* a mode switch happened since: the pointer is not on this framebuffer, the bitmaps can be used again */

static
ULONG
IntPointerSync(
    _Inout_ PDEVOBJ *ppdev,
    _In_ SURFOBJ *pso);

static
VOID
IntComposeMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _In_ GDIPOINTER *pgp,
    _Inout_ SURFOBJ *psoDest,
    _In_ RECTL *prclSurf,
    _In_ RECTL *prclPointer);

static
BOOL
IntRebuildMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _In_ SURFOBJ *pso);

__drv_preferredFunction("(see documentation)", "Obsolete, always returns false. ")
BOOL
APIENTRY
EngSetPointerTag(
    _In_ HDEV hdev,
    _In_opt_ SURFOBJ *psoMask,
    _In_opt_ SURFOBJ *psoColor,
    _Reserved_ XLATEOBJ *pxlo,
    _In_ FLONG fl)
{
    // This function is obsolete for Windows 2000 and later.
    // This function is still supported, but always returns FALSE.
    // www.osr.com/ddk/graphics/gdifncs_4yav.htm
    return FALSE;
}

/*
 * FUNCTION: Notify the mouse driver that drawing is about to begin in
 * a rectangle on a particular surface.
 */
_Requires_lock_held_(*ppdev->hsemDevLock)
BOOL
NTAPI
MouseSafetyOnDrawStart(
    _Inout_ PPDEVOBJ ppdev,
    _In_ LONG HazardX1,
    _In_ LONG HazardY1,
    _In_ LONG HazardX2,
    _In_ LONG HazardY2)
{
    LONG tmp;
    GDIPOINTER *pgp;

    ASSERT(ppdev != NULL);
    ASSERT(ppdev->pSurface != NULL);

    pgp = &ppdev->Pointer;

    if (pgp->Exclude.right == -1)
    {
        return FALSE;
    }

    ppdev->SafetyRemoveCount++;

    if (ppdev->SafetyRemoveLevel != 0)
    {
        return FALSE;
    }

    if (HazardX1 > HazardX2)
    {
        tmp = HazardX2;
        HazardX2 = HazardX1;
        HazardX1 = tmp;
    }
    if (HazardY1 > HazardY2)
    {
        tmp = HazardY2;
        HazardY2 = HazardY1;
        HazardY1 = tmp;
    }

    if (pgp->Exclude.right >= HazardX1
        && pgp->Exclude.left <= HazardX2
        && pgp->Exclude.bottom >= HazardY1
        && pgp->Exclude.top <= HazardY2)
    {
        ppdev->SafetyRemoveLevel = ppdev->SafetyRemoveCount;
        if (ppdev->flFlags & PDEV_HARDWARE_POINTER)
            ppdev->pfnMovePointer(&ppdev->pSurface->SurfObj, -1, -1, NULL);
        else if (ppdev->flFlags & PDEV_SOFTWARE_POINTER)
            EngMovePointer(&ppdev->pSurface->SurfObj, -1, -1, NULL);
    }

    return TRUE;
}

/*
 * FUNCTION: Count a drawing operation that is about to start without removing
 * the pointer. The caller either knows the operation cannot touch the pointer
 * or removes it itself around the part that can; MouseSafetyOnDrawEnd pairs with it.
 */
_Requires_lock_held_(*ppdev->hsemDevLock)
VOID
NTAPI
MouseSafetyOnDrawEnter(
    _Inout_ PPDEVOBJ ppdev)
{
    ASSERT(ppdev != NULL);

    if (ppdev->Pointer.Exclude.right == -1)
    {
        return;
    }

    ppdev->SafetyRemoveCount++;
}

/*
 * FUNCTION: Tell whether drawing into prclDraw (clipped to prclClip) can
 * reach the visible pointer, and return the part of the pointer rectangle
 * that it can reach. FALSE when the pointer is hidden, removed by an outer
 * operation, or out of reach.
 */
_Requires_lock_held_(*ppdev->hsemDevLock)
BOOL
NTAPI
MouseSafetyGetPointerHit(
    _In_ PPDEVOBJ ppdev,
    _In_ const RECTL *prclDraw,
    _In_ const RECTL *prclClip,
    _Out_ RECTL *prclHit)
{
    GDIPOINTER *pgp = &ppdev->Pointer;
    RECTL rcPtr;

    if (pgp->Exclude.right == -1 || ppdev->SafetyRemoveLevel != 0)
    {
        return FALSE;
    }

    if (!(ppdev->flFlags & (PDEV_HARDWARE_POINTER | PDEV_SOFTWARE_POINTER)))
    {
        return FALSE;
    }

    rcPtr = pgp->Exclude;

    return RECTL_bIntersectRect(prclHit, prclDraw, &rcPtr) &&
           RECTL_bIntersectRect(prclHit, prclHit, prclClip);
}

/*
 * FUNCTION: Let a drawing operation that reaches the visible software pointer
 * draw into the bitmap that holds the pixels under it instead of the screen.
 * MouseSafetyEndUnderDraw then puts the pointer over the changed pixels in one
 * blit, so the pointer never leaves the screen. The origin is where the
 * bitmap's top left pixel lies on the screen. FALSE: use MouseSafetyOnDrawStart.
 */
_Requires_lock_held_(*ppdev->hsemDevLock)
BOOL
NTAPI
MouseSafetyBeginUnderDraw(
    _In_ PPDEVOBJ ppdev,
    _Out_ SURFOBJ **ppsoSave,
    _Out_ POINTL *pptlOrigin)
{
    GDIPOINTER *pgp = &ppdev->Pointer;

    /* Enabled and the bitmaps exist only while this engine code draws the pointer, also for a driver that
     * hands the shape to EngSetPointerShape and so reads as having a hardware pointer */
    if (!(ppdev->flFlags & (PDEV_HARDWARE_POINTER | PDEV_SOFTWARE_POINTER)) ||
        !pgp->Enabled || !pgp->psurfSave || !pgp->psurfTmp ||
        pgp->Exclude.right == -1 || ppdev->SafetyRemoveLevel != 0)
    {
        return FALSE;
    }

    /* A mode switch since the pixels were saved: this is not their framebuffer */
    if (IntPointerSync(ppdev, &ppdev->pSurface->SurfObj) != PTR_CURRENT)
    {
        return FALSE;
    }

    *ppsoSave = &pgp->psurfSave->SurfObj;
    pptlOrigin->x = ppdev->ptlPointer.x - pgp->HotSpot.x;
    pptlOrigin->y = ppdev->ptlPointer.y - pgp->HotSpot.y;
    return TRUE;
}

_Requires_lock_held_(*ppdev->hsemDevLock)
VOID
NTAPI
MouseSafetyEndUnderDraw(
    _Inout_ PPDEVOBJ ppdev)
{
    GDIPOINTER *pgp = &ppdev->Pointer;
    SURFOBJ *psoDest = &ppdev->pSurface->SurfObj;
    POINTL pt;
    RECTL rclSurf, rclPointer;

    pt.x = ppdev->ptlPointer.x - pgp->HotSpot.x;
    pt.y = ppdev->ptlPointer.y - pgp->HotSpot.y;

    rclSurf.left = max(pt.x, 0);
    rclSurf.top = max(pt.y, 0);
    rclSurf.right = min(pt.x + pgp->Size.cx, psoDest->sizlBitmap.cx);
    rclSurf.bottom = min(pt.y + pgp->Size.cy, psoDest->sizlBitmap.cy);

    rclPointer.left = rclSurf.left - pt.x;
    rclPointer.top = rclSurf.top - pt.y;
    rclPointer.right = min(pgp->Size.cx, psoDest->sizlBitmap.cx - pt.x);
    rclPointer.bottom = min(pgp->Size.cy, psoDest->sizlBitmap.cy - pt.y);

    IntComposeMousePointer(ppdev, pgp, psoDest, &rclSurf, &rclPointer);
}

/*
 * FUNCTION: Notify the mouse driver that drawing has finished on a surface.
 */
_Requires_lock_held_(*ppdev->hsemDevLock)
BOOL
NTAPI
MouseSafetyOnDrawEnd(
    _Inout_ PPDEVOBJ ppdev)
{
    GDIPOINTER *pgp;

    ASSERT(ppdev != NULL);
    ASSERT(ppdev->pSurface != NULL);

    pgp = &ppdev->Pointer;

    if (pgp->Exclude.right == -1)
    {
        return FALSE;
    }

    if (--ppdev->SafetyRemoveCount >= ppdev->SafetyRemoveLevel)
    {
        return FALSE;
    }

    if (ppdev->flFlags & PDEV_HARDWARE_POINTER)
        ppdev->pfnMovePointer(&ppdev->pSurface->SurfObj,
                              gpsi->ptCursor.x,
                              gpsi->ptCursor.y,
                              &pgp->Exclude);
    else if (ppdev->flFlags & PDEV_SOFTWARE_POINTER)
        EngMovePointer(&ppdev->pSurface->SurfObj,
                       gpsi->ptCursor.x,
                       gpsi->ptCursor.y,
                       &pgp->Exclude);

    ppdev->SafetyRemoveLevel = 0;

    return TRUE;
}

/* SOFTWARE MOUSE POINTER IMPLEMENTATION **************************************/

/* The pointer bitmaps are in the format of the screen they were made for. After a display mode that changed the format the
 * caller of the mode switch sets the shape again (UserSetCursor) and that makes new bitmaps; until then the old ones must
 * neither be copied onto the new framebuffer nor drawn there. */
static
BOOL
IntPointerFormatOk(
    _In_ GDIPOINTER *pgp,
    _In_ SURFOBJ *pso)
{
    return (!pgp->psurfSave || pgp->psurfSave->SurfObj.iBitmapFormat == pso->iBitmapFormat) &&
           (!pgp->psurfTmp || pgp->psurfTmp->SurfObj.iBitmapFormat == pso->iBitmapFormat) &&
           (!pgp->psurfMask || pgp->psurfMask->SurfObj.iBitmapFormat == pso->iBitmapFormat) &&
           (!pgp->psurfColor || pgp->psurfColor->SurfObj.iBitmapFormat == pso->iBitmapFormat || (pgp->flags & SPS_ALPHA));
}

/*
 * Every use of the saved pixels and the compose bitmap goes through here. A mode switch gives the PDEV a new framebuffer,
 * and the caller of the switch does not always take the pointer off and set the shape again (UserSetCursor(NULL) leaves
 * the pointer alone when the switching thread's queue does not own the window under it, and UserRefreshDisplay does not
 * call it at all), so the saved pixels and bitmaps are tagged with the PDEV's mode generation. After a switch they hold
 * pixels of the old framebuffer and must not be copied onto the new one: the pointer is then treated as not shown, and
 * if the bitmaps still have the format of the screen they are used for the next show, which saves the pixels of the new
 * framebuffer.
 */
static
ULONG
IntPointerSync(
    _Inout_ PDEVOBJ *ppdev,
    _In_ SURFOBJ *pso)
{
    GDIPOINTER *pgp = &ppdev->Pointer;

    if (!pgp->psurfSave)
        return PTR_CURRENT;

    if (!IntPointerFormatOk(pgp, pso))
    {
        pgp->Enabled = FALSE;
        return PTR_NONE;
    }

    if (pgp->ulModeGen != ppdev->ulModeGen)
    {
        pgp->Enabled = FALSE;
        pgp->ulModeGen = ppdev->ulModeGen;
        return PTR_RESET;
    }

    return PTR_CURRENT;
}

/*
 * Copy a finished image to the screen, or the pixels of the screen to a bitmap. A blit that returns FALSE may still have
 * written part of it; the copy has the same result every time, so it is repeated whole, then row by row, which puts every
 * row that can be written there. TRUE if the whole image arrived.
 */
static
BOOL
IntCopyBitmap(
    _Inout_ SURFOBJ *psoScreen,
    _In_ SURFOBJ *psoSrc,
    _In_ const RECTL *prclDest,
    _In_ const POINTL *pptlSrc)
{
    RECTL rcl;
    POINTL ptl;
    LONG y;
    BOOL bRet = TRUE;
    ULONG i;

    for (i = 0; i < 2; i++)
    {
        rcl = *prclDest;
        ptl = *pptlSrc;
        if (IntEngBitBlt(psoScreen, psoSrc, NULL, NULL, NULL, &rcl, &ptl, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)))
            return TRUE;
    }

    for (y = prclDest->top; y < prclDest->bottom; y++)
    {
        rcl.left = prclDest->left;
        rcl.right = prclDest->right;
        rcl.top = y;
        rcl.bottom = y + 1;
        ptl.x = pptlSrc->x;
        ptl.y = pptlSrc->y + (y - prclDest->top);
        if (!IntEngBitBlt(psoScreen, psoSrc, NULL, NULL, NULL, &rcl, &ptl, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)))
            bRet = FALSE;
    }

    return bRet;
}

VOID
NTAPI
IntHideMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _Inout_ SURFOBJ *psoDest)
{
    GDIPOINTER *pgp;
    POINTL pt;
    RECTL rclDest;
    POINTL ptlSave;

    ASSERT(ppdev);
    ASSERT(psoDest);

    pgp = &ppdev->Pointer;

    if (!pgp->Enabled)
    {
        return;
    }

    pgp->Enabled = FALSE;

    if (!pgp->psurfSave)
    {
        DPRINT("No SaveSurface!\n");
        return;
    }

    /* Pixels saved from the framebuffer of an earlier mode must not go to this one */
    if (IntPointerSync(ppdev, psoDest) != PTR_CURRENT)
    {
        return;
    }

    /* Calculate cursor coordinates */
    pt.x = ppdev->ptlPointer.x - pgp->HotSpot.x;
    pt.y = ppdev->ptlPointer.y - pgp->HotSpot.y;

    rclDest.left = max(pt.x, 0);
    rclDest.top = max(pt.y, 0);
    rclDest.right = min(pt.x + pgp->Size.cx, psoDest->sizlBitmap.cx);
    rclDest.bottom = min(pt.y + pgp->Size.cy, psoDest->sizlBitmap.cy);

    ptlSave.x = rclDest.left - pt.x;
    ptlSave.y = rclDest.top - pt.y;

    /* The pointer is not shown from here on whether every row could be put back or not; a row that could not be written is
     * the framebuffer's problem and is drawn over by the next paint of the window */
    IntCopyBitmap(psoDest, &pgp->psurfSave->SurfObj, &rclDest, &ptlSave);
}

/* Draw the pointer into prclDest of psoDest, taking the pixels from prclPointer of the pointer bitmaps; FALSE if a part failed */
static
BOOL
IntDrawMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _In_ GDIPOINTER *pgp,
    _Inout_ SURFOBJ *psoDest,
    _In_ RECTL *prclDest,
    _In_ RECTL *prclPointer)
{
    RECTL rclSurf = *prclDest, rclPointer = *prclPointer;
    BOOL bRet = TRUE;

    /* Blt the pointer on the surface. */
    if (pgp->psurfColor)
    {
        if(!(pgp->flags & SPS_ALPHA))
        {
            bRet = bRet && !!IntEngBitBlt(psoDest,
                         &pgp->psurfMask->SurfObj,
                         NULL,
                         NULL,
                         NULL,
                         &rclSurf,
                         (POINTL*)&rclPointer,
                         NULL,
                         NULL,
                         NULL,
                         ROP4_SRCAND);

            bRet = bRet && !!IntEngBitBlt(psoDest,
                         &pgp->psurfColor->SurfObj,
                         NULL,
                         NULL,
                         NULL,
                         &rclSurf,
                         (POINTL*)&rclPointer,
                         NULL,
                         NULL,
                         NULL,
                         ROP4_SRCINVERT);
         }
         else
         {
            BLENDOBJ blendobj = { {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA } };
            EXLATEOBJ exlo;
            EXLATEOBJ_vInitialize(&exlo,
                &gpalRGB,
                ppdev->ppalSurf,
                0, 0, 0);
            bRet = bRet && !!IntEngAlphaBlend(psoDest,
                             &pgp->psurfColor->SurfObj,
                             NULL,
                             &exlo.xlo,
                             &rclSurf,
                             &rclPointer,
                             &blendobj);
            EXLATEOBJ_vCleanup(&exlo);
        }
    }
    else
    {
        bRet = bRet && !!IntEngBitBlt(psoDest,
                     &pgp->psurfMask->SurfObj,
                     NULL,
                     NULL,
                     NULL,
                     &rclSurf,
                     (POINTL*)&rclPointer,
                     NULL,
                     NULL,
                     NULL,
                     ROP4_FROM_INDEX(R3_OPINDEX_SRCAND));

        rclPointer.top += pgp->Size.cy;

        bRet = bRet && !!IntEngBitBlt(psoDest,
                     &pgp->psurfMask->SurfObj,
                     NULL,
                     NULL,
                     NULL,
                     &rclSurf,
                     (POINTL*)&rclPointer,
                     NULL,
                     NULL,
                     NULL,
                     ROP4_FROM_INDEX(R3_OPINDEX_SRCINVERT));
    }

    return bRet;
}

/* Put the pointer on the screen over the pixels in the save bitmap. Composed in a second
 * bitmap and drawn in one blit, the screen never shows the AND pass alone as a black arrow. */
static
VOID
IntComposeMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _In_ GDIPOINTER *pgp,
    _Inout_ SURFOBJ *psoDest,
    _In_ RECTL *prclSurf,
    _In_ RECTL *prclPointer)
{
    RECTL rclTmp = *prclPointer;

    /* Compose in the compose bitmap (memory: nothing reaches the screen if this fails) */
    if (pgp->psurfTmp &&
        pgp->psurfTmp->SurfObj.iBitmapFormat == psoDest->iBitmapFormat &&
        IntEngBitBlt(&pgp->psurfTmp->SurfObj,
                     &pgp->psurfSave->SurfObj,
                     NULL,
                     NULL,
                     NULL,
                     &rclTmp,
                     (POINTL*)&rclTmp,
                     NULL,
                     NULL,
                     NULL,
                     ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)) &&
        IntDrawMousePointer(ppdev, pgp, &pgp->psurfTmp->SurfObj, &rclTmp, prclPointer))
    {
        /* The finished image is the one source of truth now: a copy that fails is repeated, never replaced by drawing
         * the pointer again over what the failed copy may have written. Rows that still can not be written stay as
         * they were; the pointer counts as shown, so the next hide puts the saved pixels back over the whole rectangle
         * and removes whatever part of the pointer is there. */
        IntCopyBitmap(psoDest, &pgp->psurfTmp->SurfObj, prclSurf, (POINTL*)prclPointer);
        return;
    }

    /* No usable compose bitmap: the pointer is drawn straight onto the screen, over the saved pixels' place */
    IntDrawMousePointer(ppdev, pgp, psoDest, prclSurf, prclPointer);
}

VOID
NTAPI
IntShowMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _Inout_ SURFOBJ *psoDest)
{
    GDIPOINTER *pgp;
    POINTL pt;
    RECTL rclSurf, rclPointer;

    ASSERT(ppdev);
    ASSERT(psoDest);

    pgp = &ppdev->Pointer;

    if (pgp->Enabled)
    {
        return;
    }

    /* Bitmaps of another format are not drawn on this screen. A mode switch from a thread that does not own the window under
     * the pointer sets no new shape, so the pointer is made again here from the bitmaps it was given; the set shows it.
     * Only with the user lock: destroying a cursor, which changes the owner of its bitmaps and deletes them, takes it too,
     * so the bitmaps cannot go while they are held. A show that a draw without it starts leaves the pointer off, and the
     * next mouse move, which has the lock, makes it. */
    if (IntPointerSync(ppdev, psoDest) == PTR_NONE)
    {
        if (UserIsEnteredExclusive())
            IntRebuildMousePointer(ppdev, psoDest);
        return;
    }

    pgp->Enabled = TRUE;

    /* Check if we have any mouse pointer */
    if (!pgp->psurfSave) return;

    /* Calculate pointer coordinates */
    pt.x = ppdev->ptlPointer.x - pgp->HotSpot.x;
    pt.y = ppdev->ptlPointer.y - pgp->HotSpot.y;

    /* Calculate the rect on the surface */
    rclSurf.left = max(pt.x, 0);
    rclSurf.top = max(pt.y, 0);
    rclSurf.right = min(pt.x + pgp->Size.cx, psoDest->sizlBitmap.cx);
    rclSurf.bottom = min(pt.y + pgp->Size.cy, psoDest->sizlBitmap.cy);

    /* Calculate the rect in the pointer bitmap */
    rclPointer.left = rclSurf.left - pt.x;
    rclPointer.top = rclSurf.top - pt.y;
    rclPointer.right = min(pgp->Size.cx, psoDest->sizlBitmap.cx - pt.x);
    rclPointer.bottom = min(pgp->Size.cy, psoDest->sizlBitmap.cy - pt.y);

    /* Copy the pixels under the cursor to temporary surface. Without all of them the saved pixels are not a background:
     * the pointer stays off (nothing is put back over the screen later) and the next move tries again. */
    if (!IntCopyBitmap(&pgp->psurfSave->SurfObj, psoDest, &rclPointer, (POINTL*)&rclSurf))
    {
        pgp->Enabled = FALSE;
        return;
    }

    /* Draw the pointer over the saved pixels */
    IntComposeMousePointer(ppdev, pgp, psoDest, &rclSurf, &rclPointer);
}

/*
 * @implemented
 */
ULONG
APIENTRY
EngSetPointerShape(
    _In_ SURFOBJ *pso,
    _In_opt_ SURFOBJ *psoMask,
    _In_opt_ SURFOBJ *psoColor,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ LONG xHot,
    _In_ LONG yHot,
    _In_ LONG x,
    _In_ LONG y,
    _In_ RECTL *prcl,
    _In_ FLONG fl)
{
    PDEVOBJ *ppdev;
    GDIPOINTER *pgp;
    LONG lDelta = 0;
    HBITMAP hbmSave = NULL, hbmTmp = NULL, hbmColor = NULL, hbmMask = NULL;
    PSURFACE psurfSave = NULL, psurfTmp = NULL, psurfColor = NULL, psurfMask = NULL;
    RECTL rectl;
    SIZEL sizel = {0, 0};
    BOOL bNoXlate;

    ASSERT(pso);

    ppdev = GDIDEV(pso);
    pgp = &ppdev->Pointer;

    /* Handle the case where we have no XLATEOBJ */
    bNoXlate = (pxlo == NULL);
    if (pxlo == NULL)
        pxlo = &gexloTrivial.xlo;

    /* A monochrome pointer's mask holds the AND and the XOR mask one above the other, so the
       pointer is half the mask high. A mask of one line (an application's cursor can have one)
       leaves a pointer of no lines: there is nothing to draw, and a surface of no lines cannot be
       made (SURFACE_AllocSurface asserts on it). Such a shape hides the pointer. */
    if (!psoColor && psoMask && (psoMask->sizlBitmap.cy < 2))
        psoMask = NULL;

    /* Do we have any bitmap at all? */
    if (psoColor || psoMask)
    {
        /* Get the size of the new pointer */
        if (psoColor)
        {
            sizel.cx = psoColor->sizlBitmap.cx;
            sizel.cy = psoColor->sizlBitmap.cy;
        }
        else// if (psoMask)
        {
            sizel.cx = psoMask->sizlBitmap.cx;
            sizel.cy = psoMask->sizlBitmap.cy / 2;
        }

        rectl.left = 0;
        rectl.top = 0;
        rectl.right = sizel.cx;
        rectl.bottom = sizel.cy;

        /* Calculate lDelta for our surfaces. */
        lDelta = WIDTH_BYTES_ALIGN32(sizel.cx,
                                     BitsPerFormat(pso->iBitmapFormat));

        /* Create a bitmap for saving the pixels under the cursor. */
        hbmSave = EngCreateBitmap(sizel,
                                  lDelta,
                                  pso->iBitmapFormat,
                                  BMF_TOPDOWN | BMF_NOZEROINIT,
                                  NULL);
        psurfSave = SURFACE_ShareLockSurface(hbmSave);
        if (!psurfSave) goto failure;

        /* A second one to compose the pointer in. Without it the pointer is drawn straight onto the screen. */
        hbmTmp = EngCreateBitmap(sizel,
                                 lDelta,
                                 pso->iBitmapFormat,
                                 BMF_TOPDOWN | BMF_NOZEROINIT,
                                 NULL);
        if (hbmTmp)
        {
            psurfTmp = SURFACE_ShareLockSurface(hbmTmp);
            if (!psurfTmp)
            {
                EngDeleteSurface((HSURF)hbmTmp);
            }
        }
    }

    if (psoColor)
    {
        if (fl & SPS_ALPHA)
        {
            /* Always store the alpha cursor in RGB. */
            EXLATEOBJ exloSrcRGB;
            PEXLATEOBJ pexlo;

            pexlo = CONTAINING_RECORD(pxlo, EXLATEOBJ, xlo);
            EXLATEOBJ_vInitialize(&exloSrcRGB, pexlo->ppalSrc, &gpalRGB, 0, 0, 0);

            hbmColor = EngCreateBitmap(psoColor->sizlBitmap,
                WIDTH_BYTES_ALIGN32(sizel.cx, 32),
                BMF_32BPP,
                BMF_TOPDOWN | BMF_NOZEROINIT,
                NULL);
            psurfColor = SURFACE_ShareLockSurface(hbmColor);
            if (!psurfColor) goto failure;

            /* Now copy the given bitmap. */
            rectl.bottom = psoColor->sizlBitmap.cy;
            IntEngCopyBits(&psurfColor->SurfObj,
                           psoColor,
                           NULL,
                           &exloSrcRGB.xlo,
                           &rectl,
                           (POINTL*)&rectl);

            EXLATEOBJ_vCleanup(&exloSrcRGB);
        }
        else
        {
            /* The copy below converts a colour bitmap of another format (a cursor made before a switch to another
               depth) with the XLATEOBJ from its palette to the screen's; without one it cannot */
            if (psoColor->iBitmapFormat != pso->iBitmapFormat && bNoXlate)
            {
                DPRINT1("Screen surface and cursor color bitmap format don't match, and no translation\n");
                goto failure;
            }

            /* Create a bitmap to copy the color bitmap to */
            hbmColor = EngCreateBitmap(psoColor->sizlBitmap,
                               lDelta,
                               pso->iBitmapFormat,
                               BMF_TOPDOWN | BMF_NOZEROINIT,
                               NULL);
            psurfColor = SURFACE_ShareLockSurface(hbmColor);
            if (!psurfColor) goto failure;

            /* Now copy the given bitmap. */
            rectl.bottom = psoColor->sizlBitmap.cy;
            IntEngCopyBits(&psurfColor->SurfObj,
                           psoColor,
                           NULL,
                           pxlo,
                           &rectl,
                           (POINTL*)&rectl);
        }

    }

    /* Create a mask surface */
    if (psoMask)
    {
        EXLATEOBJ exlo;
        PPALETTE ppal;

        lDelta = WIDTH_BYTES_ALIGN32(sizel.cx, BitsPerFormat(pso->iBitmapFormat));

        /* Create a bitmap for the mask */
        hbmMask = EngCreateBitmap(psoMask->sizlBitmap,
                                  lDelta,
                                  pso->iBitmapFormat,
                                  BMF_TOPDOWN | BMF_NOZEROINIT,
                                  NULL);
        psurfMask = SURFACE_ShareLockSurface(hbmMask);
        if (!psurfMask) goto failure;

        /* Initialize an EXLATEOBJ */
        ppal = PALETTE_ShareLockPalette(ppdev->devinfo.hpalDefault);
        EXLATEOBJ_vInitialize(&exlo,
                              gppalMono,
                              ppal,
                              0,
                              RGB(0xff,0xff,0xff),
                              RGB(0,0,0));

        /* Copy the mask bitmap */
        rectl.bottom = psoMask->sizlBitmap.cy;
        IntEngCopyBits(&psurfMask->SurfObj,
                       psoMask,
                       NULL,
                       &exlo.xlo,
                       &rectl,
                       (POINTL*)&rectl);

        /* Cleanup */
        EXLATEOBJ_vCleanup(&exlo);
        if (ppal) PALETTE_ShareUnlockPalette(ppal);
    }

    /* Hide mouse pointer */
    IntHideMousePointer(ppdev, pso);

    /* Free old color bitmap */
    if (pgp->psurfColor)
    {
        EngDeleteSurface(pgp->psurfColor->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfColor);
        pgp->psurfColor = NULL;
    }

    /* Free old mask bitmap */
    if (pgp->psurfMask)
    {
        EngDeleteSurface(pgp->psurfMask->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfMask);
        pgp->psurfMask = NULL;
    }

    /* Free old save bitmap */
    if (pgp->psurfSave)
    {
        EngDeleteSurface(pgp->psurfSave->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfSave);
        pgp->psurfSave = NULL;
    }

    /* Free old compose bitmap */
    if (pgp->psurfTmp)
    {
        EngDeleteSurface(pgp->psurfTmp->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfTmp);
        pgp->psurfTmp = NULL;
    }

    /* The source bitmaps belong to the shape that is gone; GreSetPointerShape records the new ones after this returns */
    pgp->hbmSrcMask = NULL;
    pgp->hbmSrcColor = NULL;
    pgp->ulRebuildGen = 0;
    pgp->ulRetryGen = 0;
    pgp->bShowAfterSwitch = FALSE;

    /* See if we are being asked to hide the pointer. */
    if (psoMask == NULL && psoColor == NULL)
    {
        /* We're done */
        return SPS_ACCEPT_NOEXCLUDE;
    }

    /* Now set the new cursor */
    pgp->psurfColor = psurfColor;
    pgp->psurfMask = psurfMask;
    pgp->psurfSave = psurfSave;
    pgp->psurfTmp = psurfTmp;
    pgp->ulModeGen = ppdev->ulModeGen;
    pgp->HotSpot.x = xHot;
    pgp->HotSpot.y = yHot;
    pgp->Size = sizel;
    pgp->flags = fl;

    if (x != -1)
    {
        ppdev->ptlPointer.x = x;
        ppdev->ptlPointer.y = y;

        IntShowMousePointer(ppdev, pso);

        if (prcl != NULL)
        {
            prcl->left = x - pgp->HotSpot.x;
            prcl->top = y - pgp->HotSpot.y;
            prcl->right = prcl->left + pgp->Size.cx;
            prcl->bottom = prcl->top + pgp->Size.cy;
        }
    }
    else if (prcl != NULL)
    {
        prcl->left = prcl->top = prcl->right = prcl->bottom = -1;
    }

    return SPS_ACCEPT_NOEXCLUDE;

failure:
    /* Cleanup surfaces */
    if (hbmMask) EngDeleteSurface((HSURF)hbmMask);
    if (psurfMask) SURFACE_ShareUnlockSurface(psurfMask);
    if (hbmColor) EngDeleteSurface((HSURF)hbmColor);
    if (psurfColor) SURFACE_ShareUnlockSurface(psurfColor);
    if (hbmSave) EngDeleteSurface((HSURF)hbmSave);
    if (psurfSave) SURFACE_ShareUnlockSurface(psurfSave);
    if (psurfTmp)
    {
        EngDeleteSurface((HSURF)hbmTmp);
        SURFACE_ShareUnlockSurface(psurfTmp);
    }

    return SPS_ERROR;
}

/* The pointer moves in one blit when the old and the new pointer rectangle fit in this */
#define MOVE_CX 192
#define MOVE_CY 192

/*
 * Move the pointer without ever taking it off the screen: copy the rectangle that holds the old and the new place
 * into a bitmap, put the saved pixels back there, keep the pixels under the new place, draw the pointer there and
 * copy the bitmap to the screen in one blit. Only for a shown pointer that has its engine bitmaps in the format of
 * the screen and lies inside the screen before and after. FALSE means the pointer state is as it was (a step that
 * failed leaves only the move bitmap and the compose bitmap changed) and the caller takes the two steps.
 */
static
BOOL
IntMoveMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _Inout_ SURFOBJ *pso,
    _In_ LONG x,
    _In_ LONG y)
{
    GDIPOINTER *pgp = &ppdev->Pointer;
    RECTL rc0, rc1, rcU, rcBuf, rcS, rcDst;
    POINTL pt0;
    SURFOBJ *psoU, *psoNew;
    SURFACE *psurfTmp;
    LONG cx = pgp->Size.cx, cy = pgp->Size.cy;

    if (!pgp->Enabled || !pgp->psurfSave || !pgp->psurfTmp || x == -1 || ppdev->ptlPointer.x == -1)
        return FALSE;

    /* A mode switch can leave bitmaps of another format or size behind */
    if (IntPointerSync(ppdev, pso) != PTR_CURRENT ||
        pgp->psurfSave->SurfObj.sizlBitmap.cx < cx || pgp->psurfSave->SurfObj.sizlBitmap.cy < cy ||
        pgp->psurfTmp->SurfObj.sizlBitmap.cx < cx || pgp->psurfTmp->SurfObj.sizlBitmap.cy < cy)
        return FALSE;

    rc0.left = ppdev->ptlPointer.x - pgp->HotSpot.x;
    rc0.top = ppdev->ptlPointer.y - pgp->HotSpot.y;
    rc0.right = rc0.left + cx;
    rc0.bottom = rc0.top + cy;
    rc1.left = x - pgp->HotSpot.x;
    rc1.top = y - pgp->HotSpot.y;
    rc1.right = rc1.left + cx;
    rc1.bottom = rc1.top + cy;

    rcU.left = min(rc0.left, rc1.left);
    rcU.top = min(rc0.top, rc1.top);
    rcU.right = max(rc0.right, rc1.right);
    rcU.bottom = max(rc0.bottom, rc1.bottom);

    if (rcU.left < 0 || rcU.top < 0 ||
        rcU.right > pso->sizlBitmap.cx || rcU.bottom > pso->sizlBitmap.cy ||
        rcU.right - rcU.left > MOVE_CX || rcU.bottom - rcU.top > MOVE_CY)
        return FALSE;

    /* The move bitmap has the format of the screen, also after a mode switch */
    if (pgp->psurfMove && pgp->psurfMove->SurfObj.iBitmapFormat != pso->iBitmapFormat)
    {
        EngDeleteSurface(pgp->psurfMove->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfMove);
        pgp->psurfMove = NULL;
    }

    if (!pgp->psurfMove)
    {
        SIZEL sizel = {MOVE_CX, MOVE_CY};
        HBITMAP hbm = EngCreateBitmap(sizel,
                                      WIDTH_BYTES_ALIGN32(MOVE_CX, BitsPerFormat(pso->iBitmapFormat)),
                                      pso->iBitmapFormat,
                                      BMF_TOPDOWN | BMF_NOZEROINIT,
                                      NULL);
        if (!hbm)
            return FALSE;
        pgp->psurfMove = SURFACE_ShareLockSurface(hbm);
        if (!pgp->psurfMove)
        {
            EngDeleteSurface((HSURF)hbm);
            return FALSE;
        }
    }
    psoU = &pgp->psurfMove->SurfObj;
    psoNew = &pgp->psurfTmp->SurfObj;

    rcBuf.left = 0;
    rcBuf.top = 0;
    rcBuf.right = rcU.right - rcU.left;
    rcBuf.bottom = rcU.bottom - rcU.top;
    rcS.left = 0;
    rcS.top = 0;
    rcS.right = cx;
    rcS.bottom = cy;

    /* The screen part, with the old pointer on it; the buffer holds nothing until this has worked */
    pt0.x = rcU.left;
    pt0.y = rcU.top;
    rcDst = rcBuf;
    if (!IntEngBitBlt(psoU, pso, NULL, NULL, NULL, &rcDst, &pt0, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)))
        return FALSE;

    /* Put the pixels under the old pointer back */
    rcDst.left = rc0.left - rcU.left;
    rcDst.top = rc0.top - rcU.top;
    rcDst.right = rcDst.left + cx;
    rcDst.bottom = rcDst.top + cy;
    pt0.x = 0;
    pt0.y = 0;
    if (!IntEngBitBlt(psoU, &pgp->psurfSave->SurfObj, NULL, NULL, NULL, &rcDst, &pt0, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)))
        return FALSE;

    /* Keep the pixels under the new place in the compose bitmap; they become the saved ones below */
    rcDst.left = rc1.left - rcU.left;
    rcDst.top = rc1.top - rcU.top;
    rcDst.right = rcDst.left + cx;
    rcDst.bottom = rcDst.top + cy;
    pt0.x = rcDst.left;
    pt0.y = rcDst.top;
    rcS.left = 0;
    rcS.top = 0;
    rcS.right = cx;
    rcS.bottom = cy;
    {
        RECTL rcTmp = rcS;

        if (!IntEngBitBlt(psoNew, psoU, NULL, NULL, NULL, &rcTmp, &pt0, NULL, NULL, NULL, ROP4_FROM_INDEX(R3_OPINDEX_SRCCOPY)))
            return FALSE;
    }

    /* Draw the pointer there */
    {
        RECTL rcPtr = rcS;

        if (!IntDrawMousePointer(ppdev, pgp, psoU, &rcDst, &rcPtr))
            return FALSE;
    }

    /* One blit to the screen. IntCopyBitmap repeats a failed copy whole and then row by row from the move buffer, which holds
     * the whole finished image of the rectangle. Only a complete copy commits the new place. If rows can not be written, the
     * rectangle is made good from what is known to be right (the saved pixels under the old place, the pixels kept under the
     * new place), the pointer is left as not shown, and the caller's two steps show it at the new place. A driver that fails
     * partway through a blit even for these copies leaves part of the old or new pointer on the screen: the next hide, move or
     * repaint of that rectangle removes it, nothing at this layer can do more. */
    pt0.x = 0;
    pt0.y = 0;
    rcDst = rcU;
    if (!IntCopyBitmap(pso, psoU, &rcDst, &pt0))
    {
        POINTL ptlOrigin = {0, 0};

        rcDst.left = rc0.left;
        rcDst.top = rc0.top;
        rcDst.right = rc0.right;
        rcDst.bottom = rc0.bottom;
        IntCopyBitmap(pso, &pgp->psurfSave->SurfObj, &rcDst, &ptlOrigin);

        rcDst.left = rc1.left;
        rcDst.top = rc1.top;
        rcDst.right = rc1.right;
        rcDst.bottom = rc1.bottom;
        IntCopyBitmap(pso, psoNew, &rcDst, &ptlOrigin);

        pgp->Enabled = FALSE;
        return FALSE;
    }

    /* The compose bitmap now holds the pixels under the pointer: it becomes the save bitmap and the old one the scratch one */
    psurfTmp = pgp->psurfTmp;
    pgp->psurfTmp = pgp->psurfSave;
    pgp->psurfSave = psurfTmp;

    ppdev->ptlPointer.x = x;
    ppdev->ptlPointer.y = y;
    return TRUE;
}

/* Delete the pointer bitmaps; the PDEV is going away */
VOID
NTAPI
IntFreeMousePointer(
    _Inout_ PPDEVOBJ ppdev)
{
    GDIPOINTER *pgp = &ppdev->Pointer;

    if (pgp->psurfColor)
    {
        EngDeleteSurface(pgp->psurfColor->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfColor);
        pgp->psurfColor = NULL;
    }

    if (pgp->psurfMask)
    {
        EngDeleteSurface(pgp->psurfMask->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfMask);
        pgp->psurfMask = NULL;
    }

    if (pgp->psurfSave)
    {
        EngDeleteSurface(pgp->psurfSave->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfSave);
        pgp->psurfSave = NULL;
    }

    if (pgp->psurfTmp)
    {
        EngDeleteSurface(pgp->psurfTmp->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfTmp);
        pgp->psurfTmp = NULL;
    }

    if (pgp->psurfMove)
    {
        EngDeleteSurface(pgp->psurfMove->BaseObject.hHmgr);
        SURFACE_ShareUnlockSurface(pgp->psurfMove);
        pgp->psurfMove = NULL;
    }

    pgp->Enabled = FALSE;
}

/*
 * @implemented
 */
VOID
APIENTRY
EngMovePointer(
    _In_ SURFOBJ *pso,
    _In_ LONG x,
    _In_ LONG y,
    _In_ RECTL *prcl)
{
    PDEVOBJ *ppdev;
    GDIPOINTER *pgp;

    ASSERT(pso);

    ppdev = GDIDEV(pso);
    ASSERT(ppdev);

    pgp = &ppdev->Pointer;

    if (!IntMoveMousePointer(ppdev, pso, x, y))
    {
        IntHideMousePointer(ppdev, pso);

        ppdev->ptlPointer.x = x;
        ppdev->ptlPointer.y = y;

        if (x != -1)
        {
            IntShowMousePointer(ppdev, pso);
        }
    }

    if (x != -1)
    {
        if (prcl != NULL)
        {
            prcl->left = x - pgp->HotSpot.x;
            prcl->top = y - pgp->HotSpot.y;
            prcl->right = prcl->left + pgp->Size.cx;
            prcl->bottom = prcl->top + pgp->Size.cy;
        }
    }
    else if (prcl != NULL)
    {
        prcl->left = prcl->top = prcl->right = prcl->bottom = -1;
    }
}

ULONG
NTAPI
IntEngSetPointerShape(
    _In_ SURFOBJ *pso,
    _In_opt_ SURFOBJ *psoMask,
    _In_opt_ SURFOBJ *psoColor,
    _In_opt_ XLATEOBJ *pxlo,
    _In_ LONG xHot,
    _In_ LONG yHot,
    _In_ LONG x,
    _In_ LONG y,
    _In_ RECTL *prcl,
    _In_ FLONG fl)
{
    ULONG ulResult = SPS_DECLINE;
    PFN_DrvSetPointerShape pfnSetPointerShape;
    PPDEVOBJ ppdev = GDIDEV(pso);
    BOOL bHardwarePointer = FALSE;
    BOOL bSoftwarePointer = TRUE;

    pfnSetPointerShape = GDIDEVFUNCS(pso).SetPointerShape;

    if (pfnSetPointerShape)
    {
        /* Drivers expect to get an XLATEOBJ */
        if (pxlo == NULL)
            pxlo = &gexloTrivial.xlo;

        /* Call the driver */
        ulResult = pfnSetPointerShape(pso,
                                      psoMask,
                                      psoColor,
                                      pxlo,
                                      xHot,
                                      yHot,
                                      x,
                                      y,
                                      prcl,
                                      fl);

        /* Check if the driver accepted it */
        if (ulResult == SPS_ACCEPT_NOEXCLUDE)
            bHardwarePointer = TRUE;

        bSoftwarePointer = !bHardwarePointer;
    }

    if (bSoftwarePointer)
    {
        /* Set software pointer */
        ulResult = EngSetPointerShape(pso,
                                      psoMask,
                                      psoColor,
                                      pxlo,
                                      xHot,
                                      yHot,
                                      x,
                                      y,
                                      prcl,
                                      fl);
    }

    if (!bSoftwarePointer && ppdev->flFlags & PDEV_SOFTWARE_POINTER)
    {
        /* Disable software pointer */
        EngMovePointer(pso, -1, -1, NULL);
    }

    if (!bHardwarePointer && ppdev->flFlags & PDEV_HARDWARE_POINTER)
    {
        /* Disable hardware pointer */
        ppdev->pfnMovePointer(pso, -1, -1, NULL);
    }

    /* Update flags */
    if (bSoftwarePointer)
        ppdev->flFlags |= PDEV_SOFTWARE_POINTER;
    else
        ppdev->flFlags &= ~PDEV_SOFTWARE_POINTER;

    if (bHardwarePointer)
        ppdev->flFlags |= PDEV_HARDWARE_POINTER;
    else
        ppdev->flFlags &= ~PDEV_HARDWARE_POINTER;

    return ulResult;
}

/* Set the shape from the two bitmaps a cursor holds, locked by the caller, and keep their handles to make the pointer again after a mode switch */
static
ULONG
IntSetPointerShapeFromSurfaces(
    _Inout_ PDEVOBJ *ppdev,
    _In_ PSURFACE psurf,
    _In_opt_ PSURFACE psurfMask,
    _In_opt_ PSURFACE psurfColor,
    _In_opt_ HBITMAP hbmMask,
    _In_opt_ HBITMAP hbmColor,
    _In_ LONG xHot,
    _In_ LONG yHot,
    _In_ LONG x,
    _In_ LONG y,
    _In_ FLONG fl)
{
    EXLATEOBJ exlo;
    ULONG ulResult;

    if (psurfColor)
    {
        /* Create an XLATEOBJ, no mono support */
        EXLATEOBJ_vInitialize(&exlo, psurfColor->ppal, psurf->ppal, 0, 0, 0);
    }

    /* We must have a valid surface in case of alpha bitmap */
    ASSERT(((fl & SPS_ALPHA) && psurfColor) || !(fl & SPS_ALPHA));

    /* Call the driver or eng function */
    ulResult = IntEngSetPointerShape(&psurf->SurfObj,
                                     psurfMask ? &psurfMask->SurfObj : NULL,
                                     psurfColor ? &psurfColor->SurfObj : NULL,
                                     psurfColor ? &exlo.xlo : NULL,
                                     xHot,
                                     yHot,
                                     x,
                                     y,
                                     &ppdev->Pointer.Exclude,
                                     fl | SPS_CHANGE);

    if (ulResult != SPS_ERROR)
    {
        ppdev->Pointer.hbmSrcMask = hbmMask;
        ppdev->Pointer.hbmSrcColor = hbmColor;
    }

    if (psurfColor)
        EXLATEOBJ_vCleanup(&exlo);

    return ulResult;
}

/* The wait after a remake that failed for want of memory */
#define PTR_REBUILD_RETRY_MS 500

/*
 * The bitmaps of the pointer are in the format of the screen of their time, and a mode switch to another format leaves them
 * unusable. When the switching thread owns the window under the pointer the shape is set again anyway; when it does not,
 * no one does, and the pointer would stay off. The bitmaps the last shape was made from are still the cursor's, so the
 * shape is made again from them; a colour bitmap of the old format is converted. A set that cannot work (a bitmap that is
 * gone, an alpha shape without its colour bitmap) fails the same way for every caller and is not repeated in this mode;
 * one that fails for want of memory is tried again at a show at least PTR_REBUILD_RETRY_MS later. The device lock and the
 * user lock are held: destroying a cursor takes the user lock, so the bitmaps are neither destroyed nor changed in owner
 * while they are locked here (a deleted object that is still locked is freed by the last unlock, which asserts that the
 * owner is the unlocking process), and a cursor destroyed before is seen at the lock and ends the attempt.
 */
static
BOOL
IntRebuildMousePointer(
    _Inout_ PDEVOBJ *ppdev,
    _In_ SURFOBJ *pso)
{
    GDIPOINTER *pgp = &ppdev->Pointer;
    HBITMAP hbmMask = pgp->hbmSrcMask, hbmColor = pgp->hbmSrcColor;
    PSURFACE psurf, psurfMask = NULL, psurfColor = NULL;
    LONG xHot = pgp->HotSpot.x, yHot = pgp->HotSpot.y;
    FLONG fl = pgp->flags;
    BOOL bRet = FALSE, bFinal = TRUE;

    psurf = ppdev->pSurface;
    if (pgp->ulRebuildGen == ppdev->ulModeGen + 1 || (!hbmMask && !hbmColor) || !psurf || &psurf->SurfObj != pso)
        return FALSE;

    /* After an allocation failure in this mode, not before PTR_REBUILD_RETRY_MS have passed: every move shows */
    if (pgp->ulRetryGen == ppdev->ulModeGen + 1 && EngGetTickCount() - pgp->ulRetryTick < PTR_REBUILD_RETRY_MS)
        return FALSE;

    if (hbmMask && !(psurfMask = SURFACE_ShareLockSurface(hbmMask)))
        goto done;

    if (hbmColor && !(psurfColor = SURFACE_ShareLockSurface(hbmColor)))
        goto done;

    if ((fl & SPS_ALPHA) && !psurfColor)
        goto done;

    bRet = IntSetPointerShapeFromSurfaces(ppdev, psurf, psurfMask, psurfColor, hbmMask, hbmColor, xHot, yHot,
                                          ppdev->ptlPointer.x, ppdev->ptlPointer.y, fl) != SPS_ERROR;

    /* EngSetPointerShape converts a colour bitmap of another format; its failures are allocations */
    if (!bRet)
        bFinal = FALSE;

done:
    if (psurfColor)
        SURFACE_ShareUnlockSurface(psurfColor);

    if (psurfMask)
        SURFACE_ShareUnlockSurface(psurfMask);

    /* A successful set started over (ulRebuildGen 0); a failure that can pass leaves a later show to try again */
    if (!bRet && bFinal)
    {
        pgp->ulRebuildGen = ppdev->ulModeGen + 1;
    }
    else if (!bRet)
    {
        pgp->ulRetryGen = ppdev->ulModeGen + 1;
        pgp->ulRetryTick = EngGetTickCount();
    }

    return bRet;
}

/*
 * After a display mode switch, from the thread that switched. A thread that does not own the window under the pointer
 * sets no shape again, and nothing else shows a pointer that does not move until a draw goes across it, so the pointer
 * that was on the screen when the switch began (bShowAfterSwitch, set by PDEVOBJ_bDynamicModeChange) is shown on the new
 * framebuffer here: after a switch that keeps the format from its bitmaps (a new size), after one to another format made
 * again from the bitmaps of its last shape, which needs the user lock (see IntRebuildMousePointer).
 */
VOID
NTAPI
GreRemakePointerAfterModeSwitch(
    _Inout_ PPDEVOBJ ppdev)
{
    GDIPOINTER *pgp = &ppdev->Pointer;
    SURFOBJ *pso;

    EngAcquireSemaphore(ppdev->hsemDevLock);
    /* Not for a pointer that a draw has off now or that was moved off the screen (-1) since */
    if (ppdev->pSurface && pgp->bShowAfterSwitch && ppdev->SafetyRemoveLevel == 0 && pgp->Exclude.right != -1)
    {
        pso = &ppdev->pSurface->SurfObj;
        pgp->bShowAfterSwitch = FALSE;

        /* A draw of another thread may have synced the pointer since the switch, without showing it */
        switch (IntPointerSync(ppdev, pso))
        {
            case PTR_RESET:
            case PTR_CURRENT:
                /* Enabled was set, so this code drew it (also for a driver that hands it to EngSetPointerShape) */
                IntShowMousePointer(ppdev, pso);
                break;
            case PTR_NONE:
                if (UserIsEnteredExclusive())
                    IntRebuildMousePointer(ppdev, pso);
                break;
        }
    }
    EngReleaseSemaphore(ppdev->hsemDevLock);
    PDEVOBJ_vArmDisplaySync(ppdev);
}

ULONG
NTAPI
GreSetPointerShape(
    _In_ HDC hdc,
    _In_opt_ HBITMAP hbmMask,
    _In_opt_ HBITMAP hbmColor,
    _In_ LONG xHot,
    _In_ LONG yHot,
    _In_ LONG x,
    _In_ LONG y,
    _In_ FLONG fl)
{
    PDC pdc;
    PSURFACE psurf, psurfMask, psurfColor;
    ULONG ulResult = 0;

    pdc = DC_LockDc(hdc);
    if (!pdc)
    {
        DPRINT1("Failed to lock the DC.\n");
        return 0;
    }

    ASSERT(pdc->dctype == DCTYPE_DIRECT);
    EngAcquireSemaphore(pdc->ppdev->hsemDevLock);
    /* We're not sure DC surface is the good one */
    psurf = pdc->ppdev->pSurface;
    if (!psurf)
    {
        DPRINT1("DC has no surface.\n");
        EngReleaseSemaphore(pdc->ppdev->hsemDevLock);
        DC_UnlockDc(pdc);
        return 0;
    }

    /* Lock the mask bitmap */
    psurfMask = hbmMask ? SURFACE_ShareLockSurface(hbmMask) : NULL;

    /* Check for color bitmap */
    psurfColor = hbmColor ? SURFACE_ShareLockSurface(hbmColor) : NULL;

    ulResult = IntSetPointerShapeFromSurfaces(pdc->ppdev, psurf, psurfMask, psurfColor, hbmMask, hbmColor, xHot, yHot, x, y, fl);

    /* Cleanup */
    if (psurfColor)
        SURFACE_ShareUnlockSurface(psurfColor);

    if (psurfMask)
        SURFACE_ShareUnlockSurface(psurfMask);

    /* A driver that batches its copies to the screen shows the new pointer now */
    PDEVOBJ_vSyncDisplayNow(pdc->ppdev, DSS_FLUSH_EVENT);
    EngReleaseSemaphore(pdc->ppdev->hsemDevLock);
    PDEVOBJ_vArmDisplaySync(pdc->ppdev);

    /* Unlock the DC */
    DC_UnlockDc(pdc);

    /* Return result */
    return ulResult;
}

VOID
NTAPI
GreMovePointer(
    _In_ HDC hdc,
    _In_ LONG x,
    _In_ LONG y)
{
    PDC pdc;
    PRECTL prcl;

    /* Lock the DC */
    pdc = DC_LockDc(hdc);
    if (!pdc)
    {
        DPRINT1("Failed to lock the DC.\n");
        return;
    }
    ASSERT(pdc->dctype == DCTYPE_DIRECT);

    /* Acquire PDEV lock */
    EngAcquireSemaphore(pdc->ppdev->hsemDevLock);

    /* Check if we need to move it */
    if(pdc->ppdev->SafetyRemoveLevel == 0)
    {
        SURFOBJ* pso = &pdc->ppdev->pSurface->SurfObj;

        /* Store the cursor exclude position in the PDEV */
        prcl = &pdc->ppdev->Pointer.Exclude;

        /* Send new position of the hot spot of the pointer (will likely redraw cursor) */
        if (pdc->ppdev->flFlags & PDEV_HARDWARE_POINTER)
            pdc->ppdev->pfnMovePointer(pso, x, y, prcl);
        else if (pdc->ppdev->flFlags & PDEV_SOFTWARE_POINTER)
            EngMovePointer(pso, x, y, prcl);

        /* If panning device, and we're not hiding the cursor, notify cursor's current position.
         * (driver may already have been called if it also supports hardware pointers) */
        if (pdc->ppdev->devinfo.flGraphicsCaps & GCAPS_PANNING && y >= 0)
            pdc->ppdev->pfnMovePointer(pso, x, y - pso->sizlBitmap.cy, NULL);

        /* A driver that batches its copies to the screen shows the pointer where it is now */
        PDEVOBJ_vSyncDisplayNow(pdc->ppdev, DSS_FLUSH_EVENT);
    }

    /* Release PDEV lock */
    EngReleaseSemaphore(pdc->ppdev->hsemDevLock);
    PDEVOBJ_vArmDisplaySync(pdc->ppdev);

    /* Unlock the DC */
    DC_UnlockDc(pdc);
}


/* EOF */
