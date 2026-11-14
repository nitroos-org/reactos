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

VOID DecompressBitmap(SIZEL Size, BYTE *CompressedBits, BYTE *UncompressedBits,
                      LONG Delta, ULONG Format, ULONG cjSizeImage)
{
    INT x = 0, y = Size.cy - 1;
    INT i, c, c2, length;
    INT width = Size.cx, height = y;
    BYTE *bits = CompressedBits;
    BYTE *temp;
    BOOL is4bpp = FALSE;
    ULONG remaining = cjSizeImage;

    if ((Format == BMF_4RLE) || (Format == BMF_4BPP))
        is4bpp = TRUE;
    else if ((Format != BMF_8RLE) && (Format != BMF_8BPP))
        return;

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
                for (i = 0; i < length; i++)
                {
                    if (x >= width) break;
                    temp = UncompressedBits + (height - y) * Delta;
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
                    x = (INT)min((LONGLONG)x + *bits++, (LONGLONG)width);
                    y -= *bits++;
                    remaining -= 2;
                    break;
                default:
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
                            temp = UncompressedBits + (height - y) * Delta;
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
