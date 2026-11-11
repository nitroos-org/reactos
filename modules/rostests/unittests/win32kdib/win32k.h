/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     User mode stand-in for win32k.h, for the DIB engine sources
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#include <apitest.h>
#include <stdlib.h>
#include <wingdi.h>
#include <winddi.h>

#define ROP4_USES_DEST(Rop4)    ((((Rop4) & 0xAAAA) >> 1) != ((Rop4) & 0x5555))
#define ROP4_USES_SOURCE(Rop4)  ((((Rop4) & 0xCCCC) >> 2) != ((Rop4) & 0x3333))
#define ROP4_USES_PATTERN(Rop4) ((((Rop4) & 0xF0F0) >> 4) != ((Rop4) & 0x0F0F))
#define IS_VALID_ROP4(rop) (((rop) & 0xFFFF0000) == 0)
#define R3_OPINDEX_SRCCOPY 0xCC

/* The pool allocation of the fast path */
#define NonPagedPool 0
#define TAG_DIB 'bDmS'
#define ExAllocatePoolWithTag(PoolType, Size, Tag) malloc(Size)
#define ExFreePoolWithTag(Ptr, Tag) free(Ptr)

#ifndef FASTCALL
#define FASTCALL __fastcall
#endif

#ifndef ASSERT
#define ASSERT(x) ok((x), "ASSERT(%s)\n", #x)
#endif

typedef VOID (*PFN_DIB_PutPixel)(SURFOBJ *, LONG, LONG, ULONG);
typedef ULONG (*PFN_DIB_GetPixel)(SURFOBJ *, LONG, LONG);

typedef struct
{
    PFN_DIB_PutPixel DIB_PutPixel;
    PFN_DIB_GetPixel DIB_GetPixel;
} DIB_FUNCTIONS;

extern DIB_FUNCTIONS DibFunctionsForBitmapFormat[];
extern UCHAR gajBitsPerFormat[];
#define BitsPerFormat(Format) gajBitsPerFormat[Format]

ULONG DIB_DoRop(ULONG Rop, ULONG Dest, ULONG Source, ULONG Pattern);
VOID FASTCALL RECTL_vMakeWellOrdered(RECTL *prcl);

/* The tests use an identity colour translation. */
#define XLATEOBJ_iXlate(pxlo, iColor) (iColor)

BOOLEAN DIB_XXBPP_StretchBlt(SURFOBJ *DestSurf, SURFOBJ *SourceSurf, SURFOBJ *MaskSurf,
                             SURFOBJ *PatternSurface, RECTL *DestRect, RECTL *SourceRect,
                             POINTL *MaskOrigin, BRUSHOBJ *Brush, POINTL *BrushOrigin,
                             XLATEOBJ *ColorTranslation, ROP4 ROP);
