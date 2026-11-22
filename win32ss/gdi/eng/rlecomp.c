/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS kernel
 * PURPOSE:           RLE compression
 * FILE:              win32ss/gdi/eng/rlecomp.c
 * PROGRAMER:         Jason Filby
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

enum Rle_EscapeCodes
{
    RLE_EOL   = 0, /* End of line */
    RLE_END   = 1, /* End of bitmap */
    RLE_DELTA = 2  /* Delta */
};

/*
 * Decodes cjSizeImage bytes of run length data into a buffer of cjUncompressed bytes that holds
 * Size.cy rows of Delta bytes each. Every write is at row (0 .. Size.cy - 1) * Delta plus a column
 * below Size.cx, so the checks on entry keep the decoder inside the buffer whatever the data says
 * (escapes that move the cursor, runs longer than the row, a missing end marker).
 */
VOID DecompressBitmap(SIZEL Size, BYTE *CompressedBits, BYTE *UncompressedBits,
                      LONG Delta, ULONG Format, ULONG cjSizeImage, ULONG cjUncompressed)
{
    INT x = 0, y = Size.cy - 1;
    INT i, c, c2, length, dx, dy;
    INT width = Size.cx, height = y;
    BYTE *bits = CompressedBits;
    BYTE *temp, *row;
    BOOL is4bpp = FALSE;
    ULONG remaining = cjSizeImage;
    ULONGLONG cjRow;

    if ((Format == BMF_4RLE) || (Format == BMF_4BPP))
        is4bpp = TRUE;
    else if ((Format != BMF_8RLE) && (Format != BMF_8BPP))
        return;

    /* The rows must exist and be wide enough for the width */
    cjRow = is4bpp ? ((ULONGLONG)(ULONG)width + 1) / 2 : (ULONGLONG)(ULONG)width;
    if ((width < 0) || (Size.cy <= 0) || (Delta <= 0) || (cjRow > (ULONG)Delta) ||
        ((ULONGLONG)(ULONG)Size.cy * (ULONG)Delta > cjUncompressed) ||
        (UncompressedBits == NULL) || (CompressedBits == NULL))
    {
        DPRINT1("Refusing to decode %ld x %ld into %lu bytes (stride %ld)\n",
                Size.cx, Size.cy, cjUncompressed, Delta);
        return;
    }

    _SEH2_TRY
    {
        while (y >= 0 && remaining >= 2)
        {
            length = *bits++;
            remaining--;
            if (length)
            {
                c = *bits++;
                remaining--;
                /* y does not change within a run: the row is computed once */
                row = UncompressedBits + (SIZE_T)(height - y) * (SIZE_T)Delta;
                for (i = 0; i < length; i++)
                {
                    if (x >= width) break;
                    temp = row;
                    if (is4bpp)
                    {
                        temp += x / 2;
                        if (i & 1)
                            c2 = c & 0x0F;
                        else
                            c2 = c >> 4;
                        if (x & 1)
                            *temp |= c2;
                        else
                            *temp |= c2 << 4;
                    }
                    else
                    {
                        temp += x;
                        *temp = c;
                    }
                    x++;
                }
            }
            else
            {
                length = *bits++;
                remaining--;
                switch (length)
                {
                case RLE_EOL:
                    x = 0;
                    y--;
                    break;
                case RLE_END:
                    _SEH2_YIELD(return);
                case RLE_DELTA:
                    if (remaining < 2)
                        _SEH2_YIELD(return);
                    /* Read the two bytes first: min() is a macro and evaluated its argument, with the
                       *bits++ in it, twice, so the input pointer ran ahead of remaining by one byte per
                       delta and a stream of deltas read behind the end of the data */
                    dx = bits[0];
                    dy = bits[1];
                    bits += 2;
                    remaining -= 2;
                    x = (INT)min((LONGLONG)x + dx, (LONGLONG)width);
                    y -= dy;
                    break;
                default:
                    row = UncompressedBits + (SIZE_T)(height - y) * (SIZE_T)Delta;
                    for (i = 0; i < length; i++)
                    {
                        if (!(is4bpp && i & 1))
                        {
                            if (!remaining)
                                _SEH2_YIELD(return);
                            c = *bits++;
                            remaining--;
                        }

                        if (x < width)
                        {
                            temp = row;
                            if (is4bpp)
                            {
                                temp += x / 2;
                                if (i & 1)
                                    c2 = c & 0x0F;
                                else
                                    c2 = c >> 4;
                                if (x & 1)
                                    *temp |= c2;
                                else
                                    *temp |= c2 << 4;
                            }
                            else
                            {
                                temp += x;
                                *temp = c;
                            }
                            x++;
                        }
                    }
                    if ((is4bpp ? (length + 1) / 2 : length) & 1)
                    {
                        if (!remaining)
                            _SEH2_YIELD(return);
                        bits++;
                        remaining--;
                    }
                }
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("Decoding error\n");
    }
    _SEH2_END;

    return;
}
