/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A blit into a 4 bpp bitmap at an odd x stays inside its destination rectangle
 *
 * DIB_4BPP_BitBlt draws the first pixel of such a rectangle on its own, then 8 pixels at a time. The
 * count of groups was taken from the left edge: when the width is a multiple of 8 the last group ran
 * one pixel past the right edge, reading a source pixel behind the source rectangle and writing a
 * pixel beside the destination rectangle.
 */

#include "precomp.h"

#define BMP_CX 40
#define BMP_CY 4

static
BYTE
GetNibble(const BYTE *pbBits, int x, int y)
{
    LONG lDelta = ((BMP_CX * 4 + 31) / 32) * 4;
    BYTE b = pbBits[y * lDelta + x / 2];

    return (x & 1) ? (b & 0xF) : (b >> 4);
}

static
void
CheckBlit(HDC hdcDest, const BYTE *pbDest, HDC hdcSrc, int left, int width, DWORD dwRop)
{
    int x, y, bad = 0;

    /* Everything black, then the source (white) into [left, left + width) of every row */
    PatBlt(hdcDest, 0, 0, BMP_CX, BMP_CY, BLACKNESS);
    ok(BitBlt(hdcDest, left, 0, width, BMP_CY, hdcSrc, 0, 0, dwRop), "BitBlt failed, error %lu\n", GetLastError());
    GdiFlush();

    for (y = 0; y < BMP_CY; y++)
    {
        for (x = 0; x < BMP_CX; x++)
        {
            BYTE expected = (x >= left && x < left + width) ? 15 : 0;
            BYTE got = GetNibble(pbDest, x, y);

            if (got != expected && bad++ < 4)
                ok(0, "left %d width %d rop %#lx: pixel (%d,%d) is %u, expected %u\n",
                   left, width, dwRop, x, y, got, expected);
        }
    }
    ok(bad == 0, "left %d width %d rop %#lx: %d pixels differ\n", left, width, dwRop, bad);
}

START_TEST(Dib4bppOddLeft)
{
    HDC hdcDest, hdcSrc;
    HBITMAP hbmDest, hbmSrc, hbmOldDest, hbmOldSrc;
    struct
    {
        BITMAPINFOHEADER hdr;
        RGBQUAD colors[16];
    } bmiDest;
    BITMAPINFO bmiSrc;
    PVOID pvDestBits, pvSrcBits;
    int left, width;

    hdcDest = CreateCompatibleDC(NULL);
    hdcSrc = CreateCompatibleDC(NULL);

    /* The colour table is a grey ramp: index 0 black, index 15 white */
    ZeroMemory(&bmiDest, sizeof(bmiDest));
    bmiDest.hdr.biSize = sizeof(BITMAPINFOHEADER);
    bmiDest.hdr.biWidth = BMP_CX;
    bmiDest.hdr.biHeight = -BMP_CY;
    bmiDest.hdr.biPlanes = 1;
    bmiDest.hdr.biBitCount = 4;
    bmiDest.hdr.biCompression = BI_RGB;
    bmiDest.hdr.biClrUsed = 16;
    for (left = 0; left < 16; left++)
        bmiDest.colors[left].rgbRed = bmiDest.colors[left].rgbGreen = bmiDest.colors[left].rgbBlue = left * 17;
    hbmDest = CreateDIBSection(hdcDest, (BITMAPINFO *)&bmiDest,DIB_RGB_COLORS, &pvDestBits, NULL, 0);
    ok(hbmDest != NULL, "CreateDIBSection failed, error %lu\n", GetLastError());

    /* 32 bpp white source, wider than any rectangle below */
    ZeroMemory(&bmiSrc, sizeof(bmiSrc));
    bmiSrc.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmiSrc.bmiHeader.biWidth = BMP_CX;
    bmiSrc.bmiHeader.biHeight = -BMP_CY;
    bmiSrc.bmiHeader.biPlanes = 1;
    bmiSrc.bmiHeader.biBitCount = 32;
    bmiSrc.bmiHeader.biCompression = BI_RGB;
    hbmSrc = CreateDIBSection(hdcSrc, &bmiSrc, DIB_RGB_COLORS, &pvSrcBits, NULL, 0);
    ok(hbmSrc != NULL, "CreateDIBSection failed, error %lu\n", GetLastError());
    if (!hbmDest || !hbmSrc)
        goto cleanup;
    memset(pvSrcBits, 0xFF, BMP_CX * BMP_CY * 4);

    hbmOldDest = SelectObject(hdcDest, hbmDest);
    hbmOldSrc = SelectObject(hdcSrc, hbmSrc);

    /* The source XOR the black bitmap is the source, white: colour index 15 */
    for (left = 0; left <= 3; left++)
    {
        for (width = 1; width <= 18; width++)
        {
            CheckBlit(hdcDest, pvDestBits, hdcSrc, left, width, SRCINVERT);
            CheckBlit(hdcDest, pvDestBits, hdcSrc, left, width, SRCCOPY);
        }
    }

    SelectObject(hdcDest, hbmOldDest);
    SelectObject(hdcSrc, hbmOldSrc);

cleanup:
    if (hbmDest)
        DeleteObject(hbmDest);
    if (hbmSrc)
        DeleteObject(hbmSrc);
    DeleteDC(hdcDest);
    DeleteDC(hdcSrc);
}
