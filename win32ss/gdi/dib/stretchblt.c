/*
 * PROJECT:         ReactOS Win32k subsystem
 * LICENSE:         See COPYING in the top level directory
 * FILE:            win32ss/gdi/dib/stretchblt.c
 * PURPOSE:         StretchBlt implementation suitable for all bit depths
 * PROGRAMMERS:     Magnus Olsen
 *                  Evgeniy Boltik
 *                  Gregor Schneider
 *                  Doug Lyons
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

/*
 * SRCCOPY into a 32 bpp destination from a 8, 16, 24 or 32 bpp source, no mask: the same pixels as the
 * generic loop below, without a function call per pixel and without a division per pixel. The source
 * column of every destination column is looked up once per blit instead of once per pixel, and a
 * destination row whose source row is the same as the one before it is copied from that row
 * (enlargement). Returns FALSE without having drawn anything when it does not apply (a source column
 * outside the source, no memory for the column table), the caller then runs the generic loop.
 */
#define STRETCH_COLUMNS_ON_STACK 256

static
BOOLEAN
DIB_StretchSrcCopyTo32(SURFOBJ *DestSurf, SURFOBJ *SourceSurf,
                       RECTL *DestRect, RECTL *SourceRect,
                       XLATEOBJ *ColorTranslation,
                       BOOLEAN bLeftToRight, BOOLEAN bTopToBottom)
{
  LONG aColumnsOnStack[STRETCH_COLUMNS_ON_STACK];
  LONG *pColumns = aColumnsOnStack;
  LONG DstWidth = DestRect->right - DestRect->left;
  LONG DstHeight = DestRect->bottom - DestRect->top;
  LONG SrcWidth = SourceRect->right - SourceRect->left;
  LONG SrcHeight = SourceRect->bottom - SourceRect->top;
  LONG SourceCx = SourceSurf->sizlBitmap.cx;
  LONG SourceCy = SourceSurf->sizlBitmap.cy;
  LONG DesX, DesY, sx, sy, PrevSy = -1;
  PDWORD pdDest, pdPrev = NULL;
  BOOLEAN bTrivial = (ColorTranslation == NULL) || ((ColorTranslation->flXlate & XO_TRIVIAL) != 0);
  ULONG iFormat = SourceSurf->iBitmapFormat;

  if (DstWidth <= 0 || DstHeight <= 0)
    return FALSE;

  if (DstWidth > STRETCH_COLUMNS_ON_STACK)
  {
    pColumns = ExAllocatePoolWithTag(NonPagedPool, DstWidth * sizeof(LONG), TAG_DIB);
    if (pColumns == NULL)
      return FALSE;
  }

  /* Same expression as the generic loop; a column outside the source makes the generic loop skip that pixel */
  for (DesX = 0; DesX < DstWidth; DesX++)
  {
    if (bLeftToRight)
      sx = SourceRect->right - DesX * SrcWidth / DstWidth;
    else
      sx = SourceRect->left + DesX * SrcWidth / DstWidth;

    if (sx < 0 || sx >= SourceCx)
    {
      if (pColumns != aColumnsOnStack)
        ExFreePoolWithTag(pColumns, TAG_DIB);
      return FALSE;
    }
    pColumns[DesX] = sx;
  }

  for (DesY = 0; DesY < DstHeight; DesY++)
  {
    PBYTE pjSource;

    if (bTopToBottom)
      sy = SourceRect->bottom - DesY * SrcHeight / DstHeight;
    else
      sy = SourceRect->top + DesY * SrcHeight / DstHeight;

    pdDest = (PDWORD)((PBYTE)DestSurf->pvScan0 + (DestRect->top + DesY) * DestSurf->lDelta) + DestRect->left;

    /* A source row outside the source is not drawn by the generic loop either */
    if (sy < 0 || sy >= SourceCy)
    {
      pdPrev = NULL;
      continue;
    }

    if (pdPrev != NULL && sy == PrevSy)
    {
      RtlCopyMemory(pdDest, pdPrev, DstWidth * sizeof(DWORD));
      pdPrev = pdDest;
      continue;
    }

    pjSource = (PBYTE)SourceSurf->pvScan0 + sy * SourceSurf->lDelta;

    if (iFormat == BMF_32BPP)
    {
      PDWORD pdSource = (PDWORD)pjSource;

      if (bTrivial)
      {
        for (DesX = 0; DesX < DstWidth; DesX++)
          pdDest[DesX] = pdSource[pColumns[DesX]];
      }
      else
      {
        for (DesX = 0; DesX < DstWidth; DesX++)
          pdDest[DesX] = XLATEOBJ_iXlate(ColorTranslation, pdSource[pColumns[DesX]]);
      }
    }
    else if (iFormat == BMF_24BPP)
    {
      for (DesX = 0; DesX < DstWidth; DesX++)
      {
        PBYTE pjPixel = pjSource + pColumns[DesX] * 3;
        ULONG ulPixel = *(PUSHORT)pjPixel + (pjPixel[2] << 16);

        pdDest[DesX] = bTrivial ? ulPixel : XLATEOBJ_iXlate(ColorTranslation, ulPixel);
      }
    }
    else if (iFormat == BMF_16BPP)
    {
      PWORD pwSource = (PWORD)pjSource;

      for (DesX = 0; DesX < DstWidth; DesX++)
      {
        ULONG ulPixel = pwSource[pColumns[DesX]];

        pdDest[DesX] = bTrivial ? ulPixel : XLATEOBJ_iXlate(ColorTranslation, ulPixel);
      }
    }
    else /* BMF_8BPP */
    {
      for (DesX = 0; DesX < DstWidth; DesX++)
      {
        ULONG ulPixel = pjSource[pColumns[DesX]];

        pdDest[DesX] = bTrivial ? ulPixel : XLATEOBJ_iXlate(ColorTranslation, ulPixel);
      }
    }

    PrevSy = sy;
    pdPrev = pdDest;
  }

  if (pColumns != aColumnsOnStack)
    ExFreePoolWithTag(pColumns, TAG_DIB);

  return TRUE;
}

BOOLEAN DIB_XXBPP_StretchBlt(SURFOBJ *DestSurf, SURFOBJ *SourceSurf, SURFOBJ *MaskSurf,
                            SURFOBJ *PatternSurface,
                            RECTL *DestRect, RECTL *SourceRect,
                            POINTL *MaskOrigin, BRUSHOBJ *Brush,
                            POINTL *BrushOrigin, XLATEOBJ *ColorTranslation,
                            ROP4 ROP)
{
  LONG sx = 0;
  LONG sy = 0;
  LONG DesX;
  LONG DesY;

  LONG DstHeight;
  LONG DstWidth;
  LONG SrcHeight;
  LONG SrcWidth;
  LONG MaskCy;
  LONG SourceCy;

  ULONG Color;
  ULONG Dest, Source = 0, Pattern = 0;
  ULONG xxBPPMask;
  BOOLEAN CanDraw;

  PFN_DIB_GetPixel fnSource_GetPixel = NULL;
  PFN_DIB_GetPixel fnDest_GetPixel = NULL;
  PFN_DIB_PutPixel fnDest_PutPixel = NULL;
  PFN_DIB_GetPixel fnPattern_GetPixel = NULL;
  PFN_DIB_GetPixel fnMask_GetPixel = NULL;

  LONG PatternX = 0, PatternY = 0;

  BOOL UsesSource = ROP4_USES_SOURCE(ROP);
  BOOL UsesPattern = ROP4_USES_PATTERN(ROP);
  BOOL UsesDest = ROP4_USES_DEST(ROP);
  BOOLEAN bTopToBottom, bLeftToRight;

  ASSERT(IS_VALID_ROP4(ROP));

  fnDest_GetPixel = DibFunctionsForBitmapFormat[DestSurf->iBitmapFormat].DIB_GetPixel;
  fnDest_PutPixel = DibFunctionsForBitmapFormat[DestSurf->iBitmapFormat].DIB_PutPixel;

  DPRINT("Dest BPP: %u, DestRect: (%d,%d)-(%d,%d)\n",
    BitsPerFormat(DestSurf->iBitmapFormat), DestRect->left, DestRect->top, DestRect->right, DestRect->bottom);

  DstHeight = DestRect->bottom - DestRect->top;
  DstWidth = DestRect->right - DestRect->left;
  SrcHeight = SourceRect->bottom - SourceRect->top;
  SrcWidth = SourceRect->right - SourceRect->left;

  /* Here we do the tests and set our conditions */
  if (((SrcWidth < 0) && (DstWidth < 0)) || ((SrcWidth >= 0) && (DstWidth >= 0)))
    bLeftToRight = FALSE;
  else
    bLeftToRight = TRUE;

  if (((SrcHeight < 0) && (DstHeight < 0)) || ((SrcHeight >= 0) && (DstHeight >= 0)))
    bTopToBottom = FALSE;
  else
    bTopToBottom = TRUE;

  /* Make Well Ordered to start */
  RECTL_vMakeWellOrdered(DestRect);

  if (UsesSource)
  {
    SourceCy = SourceSurf->sizlBitmap.cy;
    fnSource_GetPixel = DibFunctionsForBitmapFormat[SourceSurf->iBitmapFormat].DIB_GetPixel;
    DPRINT("Source BPP: %u, SourceRect: (%d,%d)-(%d,%d)\n",
      BitsPerFormat(SourceSurf->iBitmapFormat), SourceRect->left, SourceRect->top, SourceRect->right, SourceRect->bottom);
  }

  if (MaskSurf)
  {
    DPRINT("MaskSurf is not NULL.\n");
    fnMask_GetPixel = DibFunctionsForBitmapFormat[MaskSurf->iBitmapFormat].DIB_GetPixel;
    MaskCy = MaskSurf->sizlBitmap.cy;
  }

  DstHeight = DestRect->bottom - DestRect->top;
  DstWidth = DestRect->right - DestRect->left;
  SrcHeight = SourceRect->bottom - SourceRect->top;
  SrcWidth = SourceRect->right - SourceRect->left;

  /* FIXME: MaskOrigin? */

  switch(DestSurf->iBitmapFormat)
  {
  case BMF_1BPP: xxBPPMask = 0x1; break;
  case BMF_4BPP: xxBPPMask = 0xF; break;
  case BMF_8BPP: xxBPPMask = 0xFF; break;
  case BMF_16BPP: xxBPPMask = 0xFFFF; break;
  case BMF_24BPP: xxBPPMask = 0xFFFFFF; break;
  default:
    xxBPPMask = 0xFFFFFFFF;
  }
  DPRINT("xxBPPMask is 0x%x.\n", xxBPPMask);

  if (UsesPattern)
  {
    DPRINT("UsesPattern is not NULL.\n");
    if (PatternSurface)
    {
      PatternY = (DestRect->top - BrushOrigin->y) % PatternSurface->sizlBitmap.cy;
      if (PatternY < 0)
      {
        PatternY += PatternSurface->sizlBitmap.cy;
      }
      fnPattern_GetPixel = DibFunctionsForBitmapFormat[PatternSurface->iBitmapFormat].DIB_GetPixel;
    }
    else
    {
      if (Brush)
        Pattern = Brush->iSolidColor;
    }
  }

  if (PatternSurface)
  {
    DPRINT("PatternSurface is not NULL.\n");
  }

  DPRINT("bLeftToRight is '%d' and bTopToBottom is '%d'.\n", bLeftToRight, bTopToBottom);

  /* The common case, a copy into a 32 bpp surface, does not need the per pixel generality below */
  if (UsesSource && MaskSurf == NULL && (ROP & 0xFF) == R3_OPINDEX_SRCCOPY &&
      DestSurf->iBitmapFormat == BMF_32BPP && SourceSurf != DestSurf &&
      (SourceSurf->iBitmapFormat == BMF_32BPP || SourceSurf->iBitmapFormat == BMF_24BPP ||
       SourceSurf->iBitmapFormat == BMF_16BPP || SourceSurf->iBitmapFormat == BMF_8BPP) &&
      DIB_StretchSrcCopyTo32(DestSurf, SourceSurf, DestRect, SourceRect, ColorTranslation,
                             bLeftToRight, bTopToBottom))
  {
    return TRUE;
  }

  for (DesY = DestRect->top; DesY < DestRect->bottom; DesY++)
  {
    if (PatternSurface)
    {
      PatternX = (DestRect->left - BrushOrigin->x) % PatternSurface->sizlBitmap.cx;
      if (PatternX < 0)
      {
        PatternX += PatternSurface->sizlBitmap.cx;
      }
    }
    if (UsesSource)
    {
      if (bTopToBottom)
      {
        sy = SourceRect->bottom-(DesY - DestRect->top) * SrcHeight / DstHeight;  // flips about the x-axis
      }
      else
      {
        sy = SourceRect->top+(DesY - DestRect->top) * SrcHeight / DstHeight;
      }
    }

    for (DesX = DestRect->left; DesX < DestRect->right; DesX++)
    {
      CanDraw = TRUE;

      if (fnMask_GetPixel)
      {
        if (bLeftToRight)
        {
          sx = SourceRect->right - (DesX - DestRect->left) * SrcWidth / DstWidth;  // flips about the y-axis
        }
        else
        {
          sx = SourceRect->left+(DesX - DestRect->left) * SrcWidth / DstWidth;
        }
        if (sx < 0 || sy < 0 ||
          MaskSurf->sizlBitmap.cx <= sx || MaskCy <= sy ||
          fnMask_GetPixel(MaskSurf, sx, sy) != 0)
        {
          CanDraw = FALSE;
        }
      }

      if (UsesSource && CanDraw)
      {
        if (bLeftToRight)
        {
          sx = SourceRect->right-(DesX - DestRect->left) * SrcWidth / DstWidth;  // flips about the y-axis
        }
        else
        {
          sx = SourceRect->left + (DesX - DestRect->left) * SrcWidth / DstWidth;
        }
        if (sx >= 0 && sy >= 0 &&
          SourceSurf->sizlBitmap.cx > sx && SourceCy > sy)
        {
          Source = XLATEOBJ_iXlate(ColorTranslation, fnSource_GetPixel(SourceSurf, sx, sy));
        }
        else
        {
          Source = 0;
          CanDraw = ((ROP & 0xFF) != R3_OPINDEX_SRCCOPY);
        }
      }

      if (CanDraw)
      {
        if (UsesPattern && PatternSurface)
        {
          Pattern = fnPattern_GetPixel(PatternSurface, PatternX, PatternY);
          PatternX++;
          PatternX %= PatternSurface->sizlBitmap.cx;
        }

        /* Reading video memory is slow; SRCCOPY and other ROPs without a destination term skip it */
        Dest = UsesDest ? fnDest_GetPixel(DestSurf, DesX, DesY) : 0;
        Color = DIB_DoRop(ROP, Dest, Source, Pattern) & xxBPPMask;

        fnDest_PutPixel(DestSurf, DesX, DesY, Color);
      }
    }

    if (PatternSurface)
    {
      PatternY++;
      PatternY %= PatternSurface->sizlBitmap.cy;
    }
  }

  return TRUE;
}

/* EOF */
