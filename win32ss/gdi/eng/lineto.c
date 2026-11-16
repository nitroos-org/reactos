/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          Line functions
 * FILE:             win32ss/gdi/eng/lineto.c
 * PROGRAMER:        ReactOS Team
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

static void FASTCALL
TranslateRects(RECT_ENUM *RectEnum, POINTL* Translate)
{
    RECTL* CurrentRect;

    if (0 != Translate->x || 0 != Translate->y)
    {
        for (CurrentRect = RectEnum->arcl; CurrentRect < RectEnum->arcl + RectEnum->c; CurrentRect++)
        {
            CurrentRect->left += Translate->x;
            CurrentRect->right += Translate->x;
            CurrentRect->top += Translate->y;
            CurrentRect->bottom += Translate->y;
        }
    }
}

/*
 * Move the dash state on by "count" steps along the line, exactly as the stepping loops below do it: when a
 * segment is used up the next one is taken (backwards the index goes down, in unsigned arithmetic as in the loops),
 * a segment of length 0 is never left again. Whole turns of the pattern are skipped, so the time does not depend
 * on count.
 */
static VOID
AdvanceStyle(
    PULONG pulStyles,
    ULONG cStyles,
    BOOLEAN bBackwards,
    PULONG piStyle,
    ULONGLONG *pRemain,
    ULONGLONG count)
{
    ULONGLONG remain = *pRemain, first[16];
    ULONG iStyle = *piStyle, i;
    BOOLEAN seen[16];
    BOOLEAN bTurnsSkipped = FALSE;

    for (i = 0; i < 16; i++)
        seen[i] = FALSE;

    while (count != 0 && remain != 0)
    {
        if (count < remain)
        {
            remain -= count;
            break;
        }
        count -= remain;
        if (bBackwards)
            iStyle = (iStyle - 1) % cStyles;
        else
            iStyle = (iStyle + 1) % cStyles;
        remain = pulStyles[iStyle];

        if (!bTurnsSkipped && iStyle < 16)
        {
            if (seen[iStyle])
            {
                ULONGLONG turn = first[iStyle] - count;

                /* the same segment again: a whole turn of the pattern used "turn" steps */
                if (turn != 0)
                    count %= turn;
                bTurnsSkipped = TRUE;
            }
            else
            {
                seen[iStyle] = TRUE;
                first[iStyle] = count;
            }
        }
    }

    *piStyle = iStyle;
    *pRemain = remain;
}

LONG
HandleStyles(
    BRUSHOBJ *pbo,
    POINTL* Translate,
    LONG x,
    LONG y,
    LONGLONG deltax,
    LONGLONG deltay,
    LONG dx,
    LONG dy,
    LONGLONG iFirst,
    PULONG piStyle)
{
    PEBRUSHOBJ pebo = (PEBRUSHOBJ)pbo;
    PULONG pulStyles = pebo->pbrush->pStyle;
    ULONG iStyle, cStyles = pebo->pbrush->dwStyleCount;
    LONG diStyle, offStyle, lStyleMax;

    if (cStyles > 0)
    {
        ULONG ulStyleSize = pebo->pbrush->ulStyleSize;
        ULONGLONG remain;

        /* The line functions step along x unless deltax < deltay: the style counts the same axis (at a 45 degree
           line it counted y, so the dashes started and ended where x == y only: another place in a window DC) */
        if (deltax >= deltay)
        {
            offStyle = (ulStyleSize != 0) ? (- Translate->x) % ulStyleSize : 0;
            diStyle = dx;
            lStyleMax = x;
        }
        else
        {
            offStyle = (ulStyleSize != 0) ? (- Translate->y) % ulStyleSize : 0;
            diStyle = dy;
            lStyleMax = y;
        }

        /* Now loop until we have found the style index */
        for (iStyle = 0; iStyle < cStyles - 1 && (ULONG)offStyle >= pulStyles[iStyle]; iStyle++)
        {
            offStyle -= pulStyles[iStyle];
        }

        /* (only a sum of the segments that wrapped around 2^32 can leave the offset behind the last one) */
        if ((ULONG)offStyle >= pulStyles[iStyle])
        {
            offStyle = 0;
        }

        /* the number of steps until the style changes */
        if (diStyle > 0)
        {
            remain = pulStyles[iStyle] - (ULONG)offStyle;
        }
        else
        {
            remain = (ULONG)offStyle + 1;
        }

        /* A line clipped to its visible part starts iFirst steps into the pattern */
        if (iFirst != 0)
        {
            AdvanceStyle(pulStyles, cStyles, diStyle < 0, &iStyle, &remain, (ULONGLONG)iFirst);
        }

        /* The loops compare the coordinate with this value, modulo 2^32 */
        if (diStyle > 0)
        {
            lStyleMax = (LONG)((ULONG)lStyleMax + (ULONG)remain);
        }
        else
        {
            lStyleMax = (LONG)((ULONG)lStyleMax - (ULONG)remain);
        }
    }
    else
    {
        iStyle = 0;
        lStyleMax = MAXLONG;
    }

    *piStyle = iStyle;
    return lStyleMax;
}

/*
 * Draw a line from top-left to bottom-right
 */
void FASTCALL
NWtoSE(SURFOBJ* OutputObj, CLIPOBJ* Clip,
       BRUSHOBJ* pbo, LONG x, LONG y, LONGLONG deltax, LONGLONG deltay,
       LONGLONG iFirst, LONGLONG count, LONGLONG error0, POINTL* Translate)
{
    LONGLONG i;
    LONGLONG error;
    BOOLEAN EnumMore;
    RECTL* ClipRect;
    RECT_ENUM RectEnum;
    ULONG Pixel = pbo->iSolidColor;
    PEBRUSHOBJ pebo = (PEBRUSHOBJ)pbo;
    PULONG pulStyles = pebo->pbrush->pStyle;
    ULONG iStyle, cStyles = pebo->pbrush->dwStyleCount;
    LONG lStyleMax;

    lStyleMax = HandleStyles(pbo, Translate, x, y, deltax, deltay, 1, 1, iFirst, &iStyle);

    CLIPOBJ_cEnumStart(Clip, FALSE, CT_RECTANGLES, CD_RIGHTDOWN, 0);
    EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
    TranslateRects(&RectEnum, Translate);
    ClipRect = RectEnum.arcl;
    i = 0;
    error = error0;
    while (i < count && (ClipRect < RectEnum.arcl + RectEnum.c || EnumMore))
    {
        while ((ClipRect < RectEnum.arcl + RectEnum.c /* there's still a current clip rect */
                && (ClipRect->bottom <= y             /* but it's above us */
                    || (ClipRect->top <= y && ClipRect->right <= x))) /* or to the left of us */
                || EnumMore)                           /* no current clip rect, but rects left */
        {
            /* Skip to the next clip rect */
            if (RectEnum.arcl + RectEnum.c <= ClipRect)
            {
                EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
                TranslateRects(&RectEnum, Translate);
                ClipRect = RectEnum.arcl;
            }
            else
            {
                ClipRect++;
            }
        }
        if (ClipRect < RectEnum.arcl + RectEnum.c) /* If there's no current clip rect we're done */
        {
            if ((ClipRect->left <= x && ClipRect->top <= y) && ((iStyle & 1) == 0))
            {
                DibFunctionsForBitmapFormat[OutputObj->iBitmapFormat].DIB_PutPixel(
                    OutputObj, x, y, Pixel);
            }
            if (deltax < deltay)
            {
                y++;
                if (y == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle + 1) % cStyles;
                    lStyleMax = y + pulStyles[iStyle];
                }
                error = error + deltax;
                if (deltay <= error)
                {
                    x++;
                    error = error - deltay;
                }
            }
            else
            {
                x++;
                if (x == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle + 1) % cStyles;
                    lStyleMax = x + pulStyles[iStyle];
                }
                error = error + deltay;
                if (deltax <= error)
                {
                    y++;
                    error = error - deltax;
                }
            }
            i++;
        }
    }
}

void FASTCALL
SWtoNE(SURFOBJ* OutputObj, CLIPOBJ* Clip,
       BRUSHOBJ* pbo, LONG x, LONG y, LONGLONG deltax, LONGLONG deltay,
       LONGLONG iFirst, LONGLONG count, LONGLONG error0, POINTL* Translate)
{
    LONGLONG i;
    LONGLONG error;
    BOOLEAN EnumMore;
    RECTL* ClipRect;
    RECT_ENUM RectEnum;
    ULONG Pixel = pbo->iSolidColor;
    PEBRUSHOBJ pebo = (PEBRUSHOBJ)pbo;
    PULONG pulStyles = pebo->pbrush->pStyle;
    ULONG iStyle, cStyles = pebo->pbrush->dwStyleCount;
    LONG lStyleMax;

    lStyleMax = HandleStyles(pbo, Translate, x, y, deltax, deltay, 1, -1, iFirst, &iStyle);

    CLIPOBJ_cEnumStart(Clip, FALSE, CT_RECTANGLES, CD_RIGHTUP, 0);
    EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
    TranslateRects(&RectEnum, Translate);
    ClipRect = RectEnum.arcl;
    i = 0;
    error = error0;
    while (i < count && (ClipRect < RectEnum.arcl + RectEnum.c || EnumMore))
    {
        while ((ClipRect < RectEnum.arcl + RectEnum.c
                && (y < ClipRect->top
                    || (y < ClipRect->bottom && ClipRect->right <= x)))
                || EnumMore)
        {
            if (RectEnum.arcl + RectEnum.c <= ClipRect)
            {
                EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
                TranslateRects(&RectEnum, Translate);
                ClipRect = RectEnum.arcl;
            }
            else
            {
                ClipRect++;
            }
        }
        if (ClipRect < RectEnum.arcl + RectEnum.c)
        {
            if ((ClipRect->left <= x && y < ClipRect->bottom) && ((iStyle & 1) == 0))
            {
                DibFunctionsForBitmapFormat[OutputObj->iBitmapFormat].DIB_PutPixel(
                    OutputObj, x, y, Pixel);
            }
            if (deltax < deltay)
            {
                y--;
                if (y == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle - 1) % cStyles;
                    lStyleMax = y - pulStyles[iStyle];
                }
                error = error + deltax;
                if (deltay <= error)
                {
                    x++;
                    error = error - deltay;
                }
            }
            else
            {
                x++;
                if (x == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle + 1) % cStyles;
                    lStyleMax = x + pulStyles[iStyle];
                }
                error = error + deltay;
                if (deltax <= error)
                {
                    y--;
                    error = error - deltax;
                }
            }
            i++;
        }
    }
}

void FASTCALL
NEtoSW(SURFOBJ* OutputObj, CLIPOBJ* Clip,
       BRUSHOBJ* pbo, LONG x, LONG y, LONGLONG deltax, LONGLONG deltay,
       LONGLONG iFirst, LONGLONG count, LONGLONG error0, POINTL* Translate)
{
    LONGLONG i;
    LONGLONG error;
    BOOLEAN EnumMore;
    RECTL* ClipRect;
    RECT_ENUM RectEnum;
    ULONG Pixel = pbo->iSolidColor;
    PEBRUSHOBJ pebo = (PEBRUSHOBJ)pbo;
    PULONG pulStyles = pebo->pbrush->pStyle;
    ULONG iStyle, cStyles = pebo->pbrush->dwStyleCount;
    LONG lStyleMax;

    lStyleMax = HandleStyles(pbo, Translate, x, y, deltax, deltay, -1, 1, iFirst, &iStyle);

    CLIPOBJ_cEnumStart(Clip, FALSE, CT_RECTANGLES, CD_LEFTDOWN, 0);
    EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
    TranslateRects(&RectEnum, Translate);
    ClipRect = RectEnum.arcl;
    i = 0;
    error = error0;
    while (i < count && (ClipRect < RectEnum.arcl + RectEnum.c || EnumMore))
    {
        while ((ClipRect < RectEnum.arcl + RectEnum.c
                && (ClipRect->bottom <= y
                    || (ClipRect->top <= y && x < ClipRect->left)))
                || EnumMore)
        {
            if (RectEnum.arcl + RectEnum.c <= ClipRect)
            {
                EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
                TranslateRects(&RectEnum, Translate);
                ClipRect = RectEnum.arcl;
            }
            else
            {
                ClipRect++;
            }
        }
        if (ClipRect < RectEnum.arcl + RectEnum.c)
        {
            if ((x < ClipRect->right && ClipRect->top <= y) && ((iStyle & 1) == 0))
            {
                DibFunctionsForBitmapFormat[OutputObj->iBitmapFormat].DIB_PutPixel(
                    OutputObj, x, y, Pixel);
            }
            if (deltax < deltay)
            {
                y++;
                if (y == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle + 1) % cStyles;
                    lStyleMax = y + pulStyles[iStyle];
                }
                error = error + deltax;
                if (deltay <= error)
                {
                    x--;
                    error = error - deltay;
                }
            }
            else
            {
                x--;
                if (x == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle - 1) % cStyles;
                    lStyleMax = x - pulStyles[iStyle];
                }
                error = error + deltay;
                if (deltax <= error)
                {
                    y++;
                    error = error - deltax;
                }
            }
            i++;
        }
    }
}

void FASTCALL
SEtoNW(SURFOBJ* OutputObj, CLIPOBJ* Clip,
       BRUSHOBJ* pbo, LONG x, LONG y, LONGLONG deltax, LONGLONG deltay,
       LONGLONG iFirst, LONGLONG count, LONGLONG error0, POINTL* Translate)
{
    LONGLONG i;
    LONGLONG error;
    BOOLEAN EnumMore;
    RECTL* ClipRect;
    RECT_ENUM RectEnum;
    ULONG Pixel = pbo->iSolidColor;
    PEBRUSHOBJ pebo = (PEBRUSHOBJ)pbo;
    PULONG pulStyles = pebo->pbrush->pStyle;
    ULONG iStyle, cStyles = pebo->pbrush->dwStyleCount;
    LONG lStyleMax;

    lStyleMax = HandleStyles(pbo, Translate, x, y, deltax, deltay, -1, -1, iFirst, &iStyle);

    CLIPOBJ_cEnumStart(Clip, FALSE, CT_RECTANGLES, CD_LEFTUP, 0);
    EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
    TranslateRects(&RectEnum, Translate);
    ClipRect = RectEnum.arcl;
    i = 0;
    error = error0;
    while (i < count && (ClipRect < RectEnum.arcl + RectEnum.c || EnumMore))
    {
        while ((ClipRect < RectEnum.arcl + RectEnum.c
                && (y < ClipRect->top
                    || (y < ClipRect->bottom && x < ClipRect->left)))
                || EnumMore)
        {
            if (RectEnum.arcl + RectEnum.c <= ClipRect)
            {
                EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
                TranslateRects(&RectEnum, Translate);
                ClipRect = RectEnum.arcl;
            }
            else
            {
                ClipRect++;
            }
        }
        if (ClipRect < RectEnum.arcl + RectEnum.c)
        {
            if ((x < ClipRect->right && y < ClipRect->bottom) && ((iStyle & 1) == 0))
            {
                DibFunctionsForBitmapFormat[OutputObj->iBitmapFormat].DIB_PutPixel(
                    OutputObj, x, y, Pixel);
            }
            if (deltax < deltay)
            {
                y--;
                if (y == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle - 1) % cStyles;
                    lStyleMax = y - pulStyles[iStyle];
                }
                error = error + deltax;
                if (deltay <= error)
                {
                    x--;
                    error = error - deltay;
                }
            }
            else
            {
                x--;
                if (x == lStyleMax && cStyles != 0)
                {
                    iStyle = (iStyle - 1) % cStyles;
                    lStyleMax = x - pulStyles[iStyle];
                }
                error = error + deltay;
                if (deltax <= error)
                {
                    y--;
                    error = error - deltax;
                }
            }
            i++;
        }
    }
}

/*
 * @implemented
 */
BOOL APIENTRY
EngLineTo(
    _Inout_ SURFOBJ *DestObj,
    _In_ CLIPOBJ *Clip,
    _In_ BRUSHOBJ *pbo,
    _In_ LONG x1,
    _In_ LONG y1,
    _In_ LONG x2,
    _In_ LONG y2,
    _In_opt_ RECTL *RectBounds,
    _In_ MIX mix)
{
    LONG x, y, xchange, ychange, hx, vy;
    LONGLONG deltax, deltay, iFirst, count, error0;
    ULONG i;
    ULONG Pixel = pbo->iSolidColor;
    SURFOBJ *OutputObj;
    RECTL DestRect, rcVis;
    POINTL Translate;
    INTENG_ENTER_LEAVE EnterLeave;
    RECT_ENUM RectEnum;
    BOOL EnumMore;
    CLIPOBJ *pcoPriv = NULL;
    PEBRUSHOBJ pebo = (PEBRUSHOBJ)pbo;
    ULONG cStyles = pebo->pbrush->dwStyleCount;
    LONGLONG ldx = (LONGLONG)x2 - x1, ldy = (LONGLONG)y2 - y1;

    deltax = (ldx < 0) ? -ldx : ldx;
    deltay = (ldy < 0) ? -ldy : ldy;
    xchange = (ldx < 0) ? -1 : 1;
    ychange = (ldy < 0) ? -1 : 1;

    if (0 == deltax && 0 == deltay)
    {
        /* Nothing to draw */
        return TRUE;
    }

    /* The bounds of what can be drawn: the clip object (or RectBounds) on the surface */
    if (Clip)
        rcVis = Clip->rclBounds;
    else if (RectBounds)
        rcVis = *RectBounds;
    else
    {
        rcVis.left = rcVis.top = 0;
        rcVis.right = DestObj->sizlBitmap.cx;
        rcVis.bottom = DestObj->sizlBitmap.cy;
    }
    if (rcVis.left < 0) rcVis.left = 0;
    if (rcVis.top < 0) rcVis.top = 0;
    if (rcVis.right > DestObj->sizlBitmap.cx) rcVis.right = DestObj->sizlBitmap.cx;
    if (rcVis.bottom > DestObj->sizlBitmap.cy) rcVis.bottom = DestObj->sizlBitmap.cy;
    if (rcVis.right <= rcVis.left || rcVis.bottom <= rcVis.top)
    {
        return TRUE;
    }

    if (rcVis.left <= x1 && x1 < rcVis.right && rcVis.top <= y1 && y1 < rcVis.bottom &&
        rcVis.left <= x2 && x2 < rcVis.right && rcVis.top <= y2 && y2 < rcVis.bottom)
    {
        /* A line inside the bounds (every step can be drawn) is stepped from its start */
        iFirst = 0;
        count = max(deltax, deltay);
        error0 = count >> 1;
        x = x1;
        y = y1;

        /* The end point itself is not drawn, but along the axis of the smaller delta the line reaches the row or
           column of the end point before its last step: the rectangle includes it (IntEngEnter may draw into a
           bitmap of just this size) */
        if (x1 < x2)
        {
            DestRect.left = x1;
            DestRect.right = x2 + 1;
        }
        else
        {
            DestRect.left = x2;
            DestRect.right = x1 + 1;
        }
        if (y1 < y2)
        {
            DestRect.top = y1;
            DestRect.bottom = y2 + 1;
        }
        else
        {
            DestRect.top = y2;
            DestRect.bottom = y1 + 1;
        }
    }
    else
    {
        /* A line that leaves the bounds (it can be long, or have an end far out): only the steps that lie in the
           bounds of the clip object and the surface are taken, from the exact state of the stepping there
           (position, error term, dash state), so the time does not depend on the length. The pixels are those of
           the whole line. The coordinate along the axis of the larger delta is a + s * i, the other one
           a + s * floor((delta / 2 + i * m) / delta): both are monotonic in i, so the steps in the bounds are one
           interval. */
        BOOLEAN bXMajor = (deltax >= deltay);
        ULONGLONG D = bXMajor ? (ULONGLONG)deltax : (ULONGLONG)deltay;
        ULONGLONG m = bXMajor ? (ULONGLONG)deltay : (ULONGLONG)deltax;
        ULONGLONG i0 = 0, i1 = D, t;
        LONGLONG a[2], s[2], lo[2], hi[2], glo, ghi;
        ULONGLONG step, sub;
        int k;

        a[0] = x1; s[0] = xchange; lo[0] = rcVis.left; hi[0] = rcVis.right;
        a[1] = y1; s[1] = ychange; lo[1] = rcVis.top; hi[1] = rcVis.bottom;
        for (k = 0; k < 2; k++)
        {
            BOOLEAN bMajor = (k == 0) == bXMajor;

            /* the values of the coordinate offset g = (c - a) * s that are in the bounds: glo <= g <= ghi */
            if (s[k] > 0)
            {
                glo = lo[k] - a[k];
                ghi = hi[k] - a[k] - 1;
            }
            else
            {
                glo = a[k] - hi[k] + 1;
                ghi = a[k] - lo[k];
            }

            /* i0 = the first step with g >= glo, i1 = the first step with g >= ghi + 1 */
            for (sub = 0; sub < 2; sub++)
            {
                LONGLONG v = sub ? ghi + 1 : glo;

                if (v <= 0)
                {
                    t = 0;
                }
                else if (bMajor)
                {
                    t = ((ULONGLONG)v >= D) ? D : (ULONGLONG)v;
                }
                else if (m == 0 || (ULONGLONG)v > m)
                {
                    t = D;
                }
                else
                {
                    t = ((ULONGLONG)v * D - (D >> 1) + m - 1) / m;
                    if (t > D) t = D;
                }

                if (sub == 0)
                {
                    if (t > i0) i0 = t;
                }
                else
                {
                    if (t < i1) i1 = t;
                }
            }
        }

        if (i0 >= i1)
        {
            /* nothing of the line is in the bounds */
            return TRUE;
        }

        /* the state at step i0 */
        step = ((D >> 1) + i0 * m);
        error0 = step % D;
        step = step / D;
        if (bXMajor)
        {
            x = (LONG)(x1 + xchange * (LONGLONG)i0);
            y = (LONG)(y1 + ychange * (LONGLONG)step);
        }
        else
        {
            y = (LONG)(y1 + ychange * (LONGLONG)i0);
            x = (LONG)(x1 + xchange * (LONGLONG)step);
        }
        iFirst = i0;
        count = i1 - i0;

        /* the pixel of the last step */
        {
            ULONGLONG last = i1 - 1;
            ULONGLONG lstep = ((D >> 1) + last * m) / D;
            LONG xe, ye;

            if (bXMajor)
            {
                xe = (LONG)(x1 + xchange * (LONGLONG)last);
                ye = (LONG)(y1 + ychange * (LONGLONG)lstep);
            }
            else
            {
                ye = (LONG)(y1 + ychange * (LONGLONG)last);
                xe = (LONG)(x1 + xchange * (LONGLONG)lstep);
            }
            DestRect.left = min(x, xe);
            DestRect.right = max(x, xe) + 1;
            DestRect.top = min(y, ye);
            DestRect.bottom = max(y, ye) + 1;
        }
    }

    /* The pixels from here: (x, y) is the first, "count" steps. */
    if (xchange < 0)
        hx = x - (LONG)count + 1;
    else
        hx = x;
    if (ychange < 0)
        vy = y - (LONG)count + 1;
    else
        vy = y;

    if (! IntEngEnter(&EnterLeave, DestObj, &DestRect, FALSE, &Translate, &OutputObj))
    {
        return FALSE;
    }

    if (!Clip)
    {
        Clip = pcoPriv = EngCreateClip();
        if (!Clip)
        {
            IntEngLeave(&EnterLeave);
            return FALSE;
        }
        IntEngUpdateClipRegion((XCLIPOBJ*)Clip, 0, 0, RectBounds);
    }

    x += Translate.x;
    y += Translate.y;
    hx += Translate.x;
    vy += Translate.y;
    /* the horizontal and vertical lines below, and Translate for them */
    x1 = x;
    y1 = y;

    if ((ldy == 0) && (cStyles == 0))
    {
        CLIPOBJ_cEnumStart(Clip, FALSE, CT_RECTANGLES, CD_RIGHTDOWN, 0);
        do
        {
            EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
            for (i = 0; i < RectEnum.c && RectEnum.arcl[i].top + Translate.y <= y1; i++)
            {
                if (y1 < RectEnum.arcl[i].bottom + Translate.y &&
                        RectEnum.arcl[i].left + Translate.x <= hx + (LONG)count &&
                        hx < RectEnum.arcl[i].right + Translate.x &&
                        max(hx, RectEnum.arcl[i].left + Translate.x) <
                        min(hx + (LONG)count, RectEnum.arcl[i].right + Translate.x))
                {
                    DibFunctionsForBitmapFormat[OutputObj->iBitmapFormat].DIB_HLine(
                        OutputObj,
                        max(hx, RectEnum.arcl[i].left + Translate.x),
                        min(hx + (LONG)count, RectEnum.arcl[i].right + Translate.x),
                        y1, Pixel);
                }
            }
        }
        while (EnumMore);
    }
    else if ((ldx == 0) && (cStyles == 0))
    {
        CLIPOBJ_cEnumStart(Clip, FALSE, CT_RECTANGLES, CD_RIGHTDOWN, 0);
        do
        {
            EnumMore = CLIPOBJ_bEnum(Clip, (ULONG) sizeof(RectEnum), (PVOID) &RectEnum);
            for (i = 0; i < RectEnum.c; i++)
            {
                if (RectEnum.arcl[i].left + Translate.x <= x1 &&
                        x1 < RectEnum.arcl[i].right + Translate.x &&
                        RectEnum.arcl[i].top + Translate.y <= vy + (LONG)count &&
                        vy < RectEnum.arcl[i].bottom + Translate.y)
                {
                    DibFunctionsForBitmapFormat[OutputObj->iBitmapFormat].DIB_VLine(
                        OutputObj, x1,
                        max(vy, RectEnum.arcl[i].top + Translate.y),
                        min(vy + (LONG)count, RectEnum.arcl[i].bottom + Translate.y),
                        Pixel);
                }
            }
        }
        while (EnumMore);
    }
    else
    {
        if (0 < xchange)
        {
            if (0 < ychange)
            {
                NWtoSE(OutputObj, Clip, pbo, x, y, deltax, deltay,
                       iFirst, count, error0, &Translate);
            }
            else
            {
                SWtoNE(OutputObj, Clip, pbo, x, y, deltax, deltay,
                       iFirst, count, error0, &Translate);
            }
        }
        else
        {
            if (0 < ychange)
            {
                NEtoSW(OutputObj, Clip, pbo, x, y, deltax, deltay,
                       iFirst, count, error0, &Translate);
            }
            else
            {
                SEtoNW(OutputObj, Clip, pbo, x, y, deltax, deltay,
                       iFirst, count, error0, &Translate);
            }
        }
    }

    if (pcoPriv)
    {
        EngDeleteClip(pcoPriv);
    }

    return IntEngLeave(&EnterLeave);
}

BOOL APIENTRY
IntEngLineTo(SURFOBJ *psoDest,
             CLIPOBJ *ClipObj,
             BRUSHOBJ *pbo,
             LONG x1,
             LONG y1,
             LONG x2,
             LONG y2,
             RECTL *RectBounds,
             MIX Mix)
{
    BOOLEAN ret;
    SURFACE *psurfDest;
    PEBRUSHOBJ GdiBrush;
    RECTL b;

    ASSERT(psoDest);
    psurfDest = CONTAINING_RECORD(psoDest, SURFACE, SurfObj);
    ASSERT(psurfDest);

    GdiBrush = CONTAINING_RECORD(
                   pbo,
                   EBRUSHOBJ,
                   BrushObject);
    ASSERT(GdiBrush);
    ASSERT(GdiBrush->pbrush);

    if (GdiBrush->pbrush->flAttrs & BR_IS_NULL)
        return TRUE;

    /* No success yet */
    ret = FALSE;

    /* Clip lines totally outside the clip region. This is not done as an
     * optimization (there are very few lines drawn outside the region) but
     * as a workaround for what seems to be a problem in the CL54XX driver */
    if (NULL == ClipObj || DC_TRIVIAL == ClipObj->iDComplexity)
    {
        b.left = 0;
        b.right = psoDest->sizlBitmap.cx;
        b.top = 0;
        b.bottom = psoDest->sizlBitmap.cy;
    }
    else
    {
        b = ClipObj->rclBounds;
    }
    if ((x1 < b.left && x2 < b.left) || (b.right <= x1 && b.right <= x2) ||
            (y1 < b.top && y2 < b.top) || (b.bottom <= y1 && b.bottom <= y2))
    {
        return TRUE;
    }

    b.left = min(x1, x2);
    b.right = max(x1, x2);
    b.top = min(y1, y2);
    b.bottom = max(y1, y2);
    if (b.left == b.right) b.right++;
    if (b.top == b.bottom) b.bottom++;

    if (psurfDest->flags & HOOK_LINETO)
    {
        /* Call the driver's DrvLineTo */
        ret = GDIDEVFUNCS(psoDest).LineTo(
                  psoDest, ClipObj, pbo, x1, y1, x2, y2, &b, Mix);
    }

#if 0
    if (! ret && (psurfDest->flags & HOOK_STROKEPATH))
    {
        /* FIXME: Emulate LineTo using drivers DrvStrokePath and set ret on success */
    }
#endif

    if (! ret)
    {
        ret = EngLineTo(psoDest, ClipObj, pbo, x1, y1, x2, y2, RectBounds, Mix);
    }

    return ret;
}

BOOL APIENTRY
IntEngPolyline(SURFOBJ *psoDest,
               CLIPOBJ *Clip,
               BRUSHOBJ *pbo,
               CONST LPPOINT  pt,
               LONG dCount,
               MIX Mix)
{
    LONG i;
    RECTL rect;
    BOOL ret = FALSE;

    // Draw the Polyline with a call to IntEngLineTo for each segment.
    for (i = 1; i < dCount; i++)
    {
        rect.left = min(pt[i-1].x, pt[i].x);
        rect.top = min(pt[i-1].y, pt[i].y);
        rect.right = max(pt[i-1].x, pt[i].x);
        rect.bottom = max(pt[i-1].y, pt[i].y);
        ret = IntEngLineTo(psoDest,
                           Clip,
                           pbo,
                           pt[i-1].x,
                           pt[i-1].y,
                           pt[i].x,
                           pt[i].y,
                           &rect,
                           Mix);
        if (!ret)
        {
            break;
        }
    }

    return ret;
}

/* EOF */
