#include <win32k.h>

#define NDEBUG
#include <debug.h>

/*
 * A couple of macros to fill a single pixel or a line
 */
#define PUTPIXEL(x,y,BrushInst)        \
  ret = ret && IntEngLineTo(&psurf->SurfObj, \
       (CLIPOBJ *)&dc->co,                       \
       &BrushInst.BrushObject,                   \
       x, y, (x)+1, y,                           \
       &RectBounds,                              \
       ROP2_TO_MIX(pdcattr->jROP2));

#define PUTLINE(x1,y1,x2,y2,BrushInst) \
  ret = ret && IntEngLineTo(&psurf->SurfObj, \
       (CLIPOBJ *)&dc->co,                       \
       &BrushInst.BrushObject,                   \
       x1, y1, x2, y2,                           \
       &RectBounds,                              \
       ROP2_TO_MIX(pdcattr->jROP2));

/* A line of a Pie (the two radial lines) or a Chord (the chord) between points that may lie anywhere in the range of the
 * coordinates. The line rasteriser steps along the whole line, also where it leaves the surface (a point at the end of
 * the range takes seconds, and the sums of its coordinates overflow); a line that is long or has such a point is cut to
 * the part on the surface (and the clip bounds) first. Short lines are drawn as they are. FPU state: the caller's. */
static
BOOL
FASTCALL
IntArcLine(PDC dc,
           SURFACE *psurf,
           PDC_ATTR pdcattr,
           RECTL *pRectBounds,
           LONGLONG x1, LONGLONG y1, LONGLONG x2, LONGLONG y2)
{
    const LONGLONG lim = 0x40000000LL;
    LONGLONG adx = x2 > x1 ? x2 - x1 : x1 - x2;
    LONGLONG ady = y2 > y1 ? y2 - y1 : y1 - y2;

    if (adx > 0x100000LL || ady > 0x100000LL ||
        x1 > lim || x1 < -lim || y1 > lim || y1 < -lim ||
        x2 > lim || x2 < -lim || y2 > lim || y2 < -lim)
    {
        RECTL rc;
        double xmin, xmax, ymin, ymax, t0 = 0.0, t1 = 1.0, dx, dy, p[4], q[4];
        int i;

        /* what IntEngLineTo lets through: the whole surface for a trivial clip, else the bounds of the clip object */
        if (dc->co.iDComplexity == DC_TRIVIAL)
        {
            rc.left = rc.top = 0;
            rc.right = psurf->SurfObj.sizlBitmap.cx;
            rc.bottom = psurf->SurfObj.sizlBitmap.cy;
        }
        else
        {
            rc = dc->co.rclBounds;
        }
        xmin = (double)(rc.left > 0 ? rc.left : 0) - 1.0;
        ymin = (double)(rc.top > 0 ? rc.top : 0) - 1.0;
        xmax = (double)(rc.right < psurf->SurfObj.sizlBitmap.cx ? rc.right : psurf->SurfObj.sizlBitmap.cx);
        ymax = (double)(rc.bottom < psurf->SurfObj.sizlBitmap.cy ? rc.bottom : psurf->SurfObj.sizlBitmap.cy);
        dx = (double)x2 - (double)x1;
        dy = (double)y2 - (double)y1;
        p[0] = -dx; q[0] = (double)x1 - xmin;
        p[1] = dx;  q[1] = xmax - (double)x1;
        p[2] = -dy; q[2] = (double)y1 - ymin;
        p[3] = dy;  q[3] = ymax - (double)y1;

        for (i = 0; i < 4; i++)
        {
            if (p[i] == 0.0)
            {
                if (q[i] < 0.0)
                    return TRUE; /* parallel to the edge and outside: nothing of it on the surface */
            }
            else
            {
                double r = q[i] / p[i];

                if (p[i] < 0.0)
                {
                    if (r > t1)
                        return TRUE;
                    if (r > t0)
                        t0 = r;
                }
                else
                {
                    if (r < t0)
                        return TRUE;
                    if (r < t1)
                        t1 = r;
                }
            }
        }

        if (t0 > 0.0)
        {
            x1 = (LONGLONG)floor((double)x1 + t0 * dx + 0.5);
            y1 = (LONGLONG)floor((double)y1 + t0 * dy + 0.5);
        }
        if (t1 < 1.0)
        {
            x2 = (LONGLONG)floor((double)x2 - (1.0 - t1) * dx + 0.5);
            y2 = (LONGLONG)floor((double)y2 - (1.0 - t1) * dy + 0.5);
        }
    }

    return IntEngLineTo(&psurf->SurfObj,
                        (CLIPOBJ *)&dc->co,
                        &dc->eboLine.BrushObject,
                        (LONG)x1, (LONG)y1, (LONG)x2, (LONG)y2,
                        pRectBounds,
                        ROP2_TO_MIX(pdcattr->jROP2));
}

static
BOOL
FASTCALL
IntArc( DC *dc,
        int  Left,
        int  Top,
        int  Right,
        int  Bottom,
        int  XRadialStart,
        int  YRadialStart,
        int  XRadialEnd,
        int  YRadialEnd,
        ARCTYPE arctype)
{
    PDC_ATTR pdcattr;
    RECTL RectBounds, RectSEpts;
    PBRUSH pbrPen;
    SURFACE *psurf;
    BOOL ret = TRUE;
    LONG PenWidth, PenOrigWidth, PenWidthY;
    double AngleStart, AngleEnd;
    LONG CenterX, CenterY;
    BOOL bStroke, bRot;

    if (Right < Left)
    {
       INT tmp = Right; Right = Left; Left = tmp;
    }
    if (Bottom < Top)
    {
       INT tmp = Bottom; Bottom = Top; Top = tmp;
    }

    /* Check if the target rect is empty */
    if ((Left == Right) || (Top == Bottom)) return TRUE;

    // FIXME: this needs to be verified
    if ((arctype == GdiTypeChord ) || (arctype == GdiTypePie))
    {
        if (((LONGLONG)Right - Left == 1) || ((LONGLONG)Bottom - Top == 1))
           return TRUE;
    }


    pdcattr = dc->pdcattr;

    pbrPen = PEN_ShareLockPen(pdcattr->hpen);
    if (!pbrPen)
    {
        DPRINT1("Arc Fail 1\n");
        EngSetLastError(ERROR_INTERNAL_ERROR);
        return FALSE;
    }

    PenOrigWidth = PenWidth = pbrPen->lWidth;
    if (pbrPen->ulPenStyle == PS_NULL) PenWidth = 0;
    PenWidthY = PenWidth;
    /* The width of the pen is in logical units: the mapping mode and the world transform scale it */
    if (PenWidth)
        PATH_GetPenDeviceWidths(dc, pbrPen, &PenWidth, &PenWidthY);

    RectBounds.left   = Left;
    RectBounds.right  = Right;
    RectBounds.top    = Top;
    RectBounds.bottom = Bottom;

    RectSEpts.left   = XRadialStart;
    RectSEpts.top    = YRadialStart;
    RectSEpts.right  = XRadialEnd;
    RectSEpts.bottom = YRadialEnd;

    IntLPtoDP(dc, (LPPOINT)&RectBounds, 2);
    IntLPtoDP(dc, (LPPOINT)&RectSEpts, 2);

    /* A mapping mode or a world transform that flips an axis turns the box around: the arc is computed on the device
       box (the radial points are device points as well, so the arc runs the same way on the screen) */
    if (RectBounds.left > RectBounds.right)
    {
        INT tmp = RectBounds.right; RectBounds.right = RectBounds.left; RectBounds.left = tmp;
    }
    if (RectBounds.top > RectBounds.bottom)
    {
        INT tmp = RectBounds.bottom; RectBounds.bottom = RectBounds.top; RectBounds.top = tmp;
    }

    /* The ring rasterisers and the rectangles derived from the box keep inside the int range for boxes within these limits
       (the part of a larger shape that reaches a surface is far from the clamped edge) */
    RectBounds.left = IntClampShapeCoord(RectBounds.left);
    RectBounds.right = IntClampShapeCoord(RectBounds.right);
    RectBounds.top = IntClampShapeCoord(RectBounds.top);
    RectBounds.bottom = IntClampShapeCoord(RectBounds.bottom);

    /* The pen of a PS_INSIDEFRAME pen lies inside the box, in device pixels */
    if (pbrPen->ulPenStyle == PS_INSIDEFRAME)
    {
       if (2*(LONGLONG)PenWidth > (LONGLONG)RectBounds.right - RectBounds.left) PenWidth = (RectBounds.right - RectBounds.left + 1)/2;
       if (2*(LONGLONG)PenWidthY > (LONGLONG)RectBounds.bottom - RectBounds.top) PenWidthY = (RectBounds.bottom - RectBounds.top + 1)/2;
       RectBounds.left   += PenWidth / 2;
       RectBounds.right  -= (PenWidth - 1) / 2;
       RectBounds.top    += PenWidthY / 2;
       RectBounds.bottom -= (PenWidthY - 1) / 2;
    }

    if (!PenWidth) PenWidth = 1;
    if (!PenWidthY) PenWidthY = 1;

    /* A wide pen is centred on the outline: the outline is a stroked path. So is the outline under a rotation of the world
       transform, which turns the shape (and its fill) as well. The ring rasteriser draws the other pens, with the pen as wide
       as it is on the device */
    bRot = PATH_IsWorldRotated(dc);
    bStroke = bRot || PATH_IsShapeStroked(dc, pbrPen);
    if (!bStroke)
        pbrPen->lWidth = PenWidth;

    /* From here the shape is computed in the coordinates of the DC without its origin, so that a window DC and a memory
       DC get the same pixels: the centre and the radial points are rounded (and the engine rasteriser steps) the same
       way for any DC origin. The origin is added where the boxes and lines are written. */

    DPRINT("1: StartX: %d, StartY: %d, EndX: %d, EndY: %d\n",
               RectSEpts.left,RectSEpts.top,RectSEpts.right,RectSEpts.bottom);

    DPRINT("1: Left: %d, Top: %d, Right: %d, Bottom: %d\n",
               RectBounds.left,RectBounds.top,RectBounds.right,RectBounds.bottom);

    CenterX = (RectBounds.right + RectBounds.left) / 2;
    CenterY = (RectBounds.bottom + RectBounds.top) / 2;
    AngleEnd   = atan2((double)RectSEpts.bottom - CenterY, (double)RectSEpts.right - CenterX)*(360.0/(M_PI*2));
    AngleStart = atan2((double)RectSEpts.top - CenterY, (double)RectSEpts.left - CenterX)*(360.0/(M_PI*2));

    /* The arc keeps its direction in logical space: a world transform that flips an axis makes it run the other way
       on the screen */
    if (PATH_IsWorldFlipped(dc))
    {
        double tmp = AngleStart; AngleStart = AngleEnd; AngleEnd = tmp;
    }

    /* Edge Case: Check if the start segments overlaps(is equal) the end segment */
    if (AngleEnd == AngleStart)
    {
        AngleStart = AngleEnd + 360.0; // Arc(), ArcTo(), Pie() and Chord() are counterclockwise APIs.
    }

    dc->ptlDrawShift = dc->ptlDCOrig;

    if (((arctype == GdiTypePie) || (arctype == GdiTypeChord)) && !bRot)
    {
        ret = IntFillArc( dc,
              RectBounds.left,
              RectBounds.top,
              abs(RectBounds.right-RectBounds.left), // Width
              abs(RectBounds.bottom-RectBounds.top), // Height
              AngleStart,
              AngleEnd,
              arctype);
    }

    if (ret && !bStroke)
    {
        ret = IntDrawArc( dc,
                  RectBounds.left,
                  RectBounds.top,
                  abs(RectBounds.right-RectBounds.left), // Width
                  abs(RectBounds.bottom-RectBounds.top), // Height
                  AngleStart,
                  AngleEnd,
                  arctype,
                  pbrPen,
                  PenWidthY);
    }

    dc->ptlDrawShift.x = dc->ptlDrawShift.y = 0;

    psurf = dc->dclevel.pSurface;
    if (NULL == psurf)
    {
        DPRINT1("Arc Fail 2\n");
        PEN_ShareUnlockPen(pbrPen);
        EngSetLastError(ERROR_INTERNAL_ERROR);
        return FALSE;
    }

    if (bStroke)
    {
        if (ret)
            ret = PATH_DrawShape(dc, PATH_SHAPE_ARC, Left, Top, Right, Bottom,
                                 XRadialStart, YRadialStart, XRadialEnd, YRadialEnd, arctype, bRot);
    }
    else if (arctype == GdiTypePie)
    {
        ret = ret && IntArcLine(dc, psurf, pdcattr, &RectBounds,
                                (LONGLONG)CenterX + dc->ptlDCOrig.x, (LONGLONG)CenterY + dc->ptlDCOrig.y,
                                (LONGLONG)RectSEpts.left + dc->ptlDCOrig.x, (LONGLONG)RectSEpts.top + dc->ptlDCOrig.y);
        ret = ret && IntArcLine(dc, psurf, pdcattr, &RectBounds,
                                (LONGLONG)RectSEpts.right + dc->ptlDCOrig.x, (LONGLONG)RectSEpts.bottom + dc->ptlDCOrig.y,
                                (LONGLONG)CenterX + dc->ptlDCOrig.x, (LONGLONG)CenterY + dc->ptlDCOrig.y);
    }
    if (!bStroke && arctype == GdiTypeChord)
        ret = ret && IntArcLine(dc, psurf, pdcattr, &RectBounds,
                                (LONGLONG)RectSEpts.right + dc->ptlDCOrig.x, (LONGLONG)RectSEpts.bottom + dc->ptlDCOrig.y,
                                (LONGLONG)RectSEpts.left + dc->ptlDCOrig.x, (LONGLONG)RectSEpts.top + dc->ptlDCOrig.y);

    pbrPen->lWidth = PenOrigWidth;
    PEN_ShareUnlockPen(pbrPen);
    DPRINT("IntArc Exit.\n");
    return ret;
}


BOOL FASTCALL
IntGdiArcInternal(
          ARCTYPE arctype,
          DC  *dc,
          int LeftRect,
          int TopRect,
          int RightRect,
          int BottomRect,
          int XStartArc,
          int YStartArc,
          int XEndArc,
          int YEndArc)
{
  BOOL Ret;
  //PDC_ATTR pdcattr;

  DPRINT("StartX: %d, StartY: %d, EndX: %d, EndY: %d\n",
           XStartArc,YStartArc,XEndArc,YEndArc);
  DPRINT("Left: %d, Top: %d, Right: %d, Bottom: %d\n",
           LeftRect,TopRect,RightRect,BottomRect);

  if ((LeftRect == RightRect) || (TopRect == BottomRect)) return TRUE;

  if (PATH_IsPathOpen(dc->dclevel))
  {
     return PATH_Arc( dc,
                LeftRect,
                 TopRect,
               RightRect,
              BottomRect,
               XStartArc,
               YStartArc,
                 XEndArc,
                 YEndArc,
                       0,
                 arctype);
  }

  //pdcattr = dc->pdcattr;

  if (arctype == GdiTypeArcTo)
  {
    if (dc->dclevel.flPath & DCPATH_CLOCKWISE)
       IntGdiLineTo(dc, XEndArc, YEndArc);
    else
       IntGdiLineTo(dc, XStartArc, YStartArc);
  }

  Ret = IntArc( dc,
          LeftRect,
           TopRect,
         RightRect,
        BottomRect,
         XStartArc,
         YStartArc,
           XEndArc,
           YEndArc,
           arctype);

  if (arctype == GdiTypeArcTo)
  {
     if (dc->dclevel.flPath & DCPATH_CLOCKWISE)
       IntGdiMoveToEx(dc, XStartArc, YStartArc, NULL);
     else
       IntGdiMoveToEx(dc, XEndArc, YEndArc, NULL);
  }
  return Ret;
}

BOOL
FASTCALL
IntGdiAngleArc( PDC pDC,
                  INT x,
                  INT y,
         DWORD dwRadius,
      FLOAT eStartAngle,
      FLOAT eSweepAngle)
{
  INT  x1, y1, x2, y2, arcdir;
  BOOL result;

  /* Calculate the end point */
  x2 = x + (INT)(cos(((eStartAngle+eSweepAngle)/360)*(M_PI*2)) * dwRadius);
  y2 = y - (INT)(sin(((eStartAngle+eSweepAngle)/360)*(M_PI*2)) * dwRadius);

  x1 = x + (INT)(cos((eStartAngle/360)*(M_PI*2)) * dwRadius);
  y1 = y - (INT)(sin((eStartAngle/360)*(M_PI*2)) * dwRadius);

  arcdir = pDC->dclevel.flPath & DCPATH_CLOCKWISE;
  if (eSweepAngle >= 0)
     pDC->dclevel.flPath &= ~DCPATH_CLOCKWISE;
  else
     pDC->dclevel.flPath |= DCPATH_CLOCKWISE;

  result = IntGdiArcInternal( GdiTypeArcTo,
                                       pDC,
                                x-dwRadius,
                                y-dwRadius,
                                x+dwRadius,
                                y+dwRadius,
                                        x1,
                                        y1,
                                        x2,
                                        y2 );

  pDC->dclevel.flPath |= (arcdir & DCPATH_CLOCKWISE);

  if (result)
  {
     IntGdiMoveToEx(pDC, x2, y2, NULL);
  }
  return result;
}

/* FUNCTIONS *****************************************************************/

BOOL
APIENTRY
NtGdiAngleArc(
    IN HDC hDC,
    IN INT x,
    IN INT y,
    IN DWORD dwRadius,
    IN DWORD dwStartAngle,
    IN DWORD dwSweepAngle)
{
  DC *pDC;
  BOOL Ret = FALSE;
  gxf_long worker, worker1;
  KFLOATING_SAVE FloatSave;
  NTSTATUS status;

  pDC = DC_LockDc (hDC);
  if(!pDC)
  {
    EngSetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }

  status = KeSaveFloatingPointState(&FloatSave);
  if (!NT_SUCCESS(status))
  {
      DC_UnlockDc( pDC );
      return FALSE;
  }

  worker.l  = dwStartAngle;
  worker1.l = dwSweepAngle;
  DC_vPrepareDCsForBlit(pDC, NULL, NULL, NULL);
  if (pDC->pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
    DC_vUpdateFillBrush(pDC);
  if (pDC->pdcattr->ulDirty_ & (DIRTY_LINE | DC_PEN_DIRTY))
    DC_vUpdateLineBrush(pDC);
  Ret = IntGdiAngleArc( pDC, x, y, dwRadius, worker.f, worker1.f);
  DC_vFinishBlit(pDC, NULL);
  DC_UnlockDc( pDC );

  KeRestoreFloatingPointState(&FloatSave);

  return Ret;
}

BOOL
APIENTRY
NtGdiArcInternal(
        ARCTYPE arctype,
        HDC  hDC,
        int  LeftRect,
        int  TopRect,
        int  RightRect,
        int  BottomRect,
        int  XStartArc,
        int  YStartArc,
        int  XEndArc,
        int  YEndArc)
{
  DC *dc;
  BOOL Ret;
  KFLOATING_SAVE FloatSave;
  NTSTATUS status;

  dc = DC_LockDc (hDC);
  if(!dc)
  {
    EngSetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
  }
  if (arctype > GdiTypePie)
  {
    DC_UnlockDc(dc);
    EngSetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  DC_vPrepareDCsForBlit(dc, NULL, NULL, NULL);

  if (dc->pdcattr->ulDirty_ & (DIRTY_FILL | DC_BRUSH_DIRTY))
    DC_vUpdateFillBrush(dc);

  if (dc->pdcattr->ulDirty_ & (DIRTY_LINE | DC_PEN_DIRTY))
    DC_vUpdateLineBrush(dc);

  status = KeSaveFloatingPointState(&FloatSave);
  if (!NT_SUCCESS(status))
  {
      DC_UnlockDc( dc );
      return FALSE;
  }

  Ret = IntGdiArcInternal(
                  arctype,
                  dc,
                  LeftRect,
                  TopRect,
                  RightRect,
                  BottomRect,
                  XStartArc,
                  YStartArc,
                  XEndArc,
                  YEndArc);

  KeRestoreFloatingPointState(&FloatSave);
  DC_vFinishBlit(dc, NULL);
  DC_UnlockDc( dc );
  return Ret;
}

