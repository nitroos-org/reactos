/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetDIBitsToDevice with run length data: where the image lands when its line count
 *              differs from the rectangle, and the result
 *
 * The rows are the results of the calls on Windows Server 2022 (the sequence of the Wine test
 * test_SetDIBitsToDevice_RLE8): the return value, GetLastError and the 64 pixels of an 8 x 8 32 bpp
 * DIB section that starts as 0xAAAAAAAA ('.'), written as the low byte of each pixel.
 */

#include "precomp.h"

typedef struct
{
    int bTopDown;               /* the DIB section is top-down */
    int biWidth, biHeight;      /* of the run length data */
    int xDest, yDest, cx, cy, xSrc, ySrc;
    UINT uStartScan, cScanLines;
    int ret;
    DWORD error;                /* 0: not checked */
    const char *pixels;
} ROW;

static const BYTE rle8_data[20] =
{
    0x04, 0x02, 0x03, 0xf0, 0x00, 0x00,     /* 2, 2, 2, 2, f0, f0, f0, <eol> */
    0x00, 0x03, 0x04, 0x05, 0x06, 0x00,     /* 4, 5, 6, <pad> */
    0x00, 0x02, 0x01, 0x02, 0x05, 0x80,     /* dx=1, dy=2, 80, 80, 80, 80, (80) */
    0x00, 0x01                              /* <eod> */
};

static const ROW g_Rows[] =
{
    { 0, 8, 8, 0, 0, 8, 8, 0, 0, 0, 8, 8, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,.................80,80,80,80,................................" },
    { 0, 8, 8, 0, 0, 8, 8, 0, 0, 1, 8, 8, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,.................80,80,80,80,................................" },
    { 0, 8, 8, 0, 0, 8, 8, 0, 0, 1, 1, 8, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,.................80,80,80,80,................................" },
    { 0, 8, 8, 0, 0, 8, 8, 0, 0, 1, 0, 0, 0,
      "................................................................" },
    { 0, 2, 8, 0, 0, 8, 8, 0, 0, 0, 8, 8, 0,
      "02,02,......04,05,......................................................" },
    { 0, 8, 2, 0, 0, 8, 8, 0, 0, 0, 8, 2, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,....................................................." },
    { 0, 8, 9, 0, 0, 8, 8, 0, 0, 0, 8, 9, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,.................80,80,80,80,................................" },
    { 0, 8, 9, 0, 0, 8, 8, 0, 0, 0, 9, 9, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,.................80,80,80,80,................................" },
    { 0, 8, 8, 0, 0, 8, 8, 0, 0, 1, 9, 8, 0,
      "02,02,02,02,f0,f0,f0,.04,05,06,.................80,80,80,80,................................" },
    { 0, 8, 8, 0, 3, 8, 8, 0, 0, 0, 8, 8, 0,
      "....80,80,80,80,........................................................" },
    { 0, 8, 8, 0, 3, 4, 4, 0, 0, 0, 8, 8, 0,
      "........02,02,02,02,....04,05,06,............................................." },
    { 0, 8, 8, 3, 3, 8, 4, 0, 0, 0, 8, 8, 0,
      "...........02,02,02,02,f0,...04,05,06,.................80,........................" },
    { 0, 8, 8, 2, 3, 8, 4, 2, 0, 0, 8, 8, 0,
      "..........02,02,f0,f0,f0,...06,.................80,80,80,80,........................" },
    { 0, 37, 37, -2, 1, 10, 5, 2, -1, 12, 24, 37, 0,
      "........................f0,f0,f0,.....................80,80,80,80,80,..........." },
    { 0, 8, -8, 0, 0, 8, 8, 0, 0, 0, 8, 0, ERROR_INVALID_PARAMETER,
      "................................................................" },
    { 1, 8, 8, 0, 0, 8, 8, 0, 0, 0, 8, 8, 0,
      "....................................80,80,80,80,........04,05,06,.....02,02,02,02,f0,f0,f0,." },
    { 1, 8, 8, 0, 0, 8, 8, 0, 0, 0, 9, 8, 0,
      "....................................80,80,80,80,........04,05,06,.....02,02,02,02,f0,f0,f0,." },
    { 1, 8, 4, 0, 0, 8, 8, 0, 0, 0, 8, 4, 0,
      "....................................80,80,80,80,........04,05,06,.....02,02,02,02,f0,f0,f0,." },
    { 1, 8, 9, 0, 0, 8, 8, 0, 0, 0, 8, 9, 0,
      "....................................80,80,80,80,........04,05,06,.....02,02,02,02,f0,f0,f0,." },
    { 1, 8, 9, 0, 0, 8, 8, 0, 0, 0, 9, 9, 0,
      "....................................80,80,80,80,........04,05,06,.....02,02,02,02,f0,f0,f0,." },
    { 1, 8, 9, 2, 3, 8, 6, 2, 2, 0, 8, 9, 0,
      "............................................................80,80,80,80," },
    { 1, 37, 37, -2, 1, 10, 5, 2, -1, 12, 24, 37, 0,
      "........80,80,80,80,80,...................f0,f0,f0,............................." },
};

START_TEST(SetDIBitsToDeviceRle)
{
    HDC hdc = CreateCompatibleDC(NULL);
    HBITMAP hbm[2] = { NULL, NULL };
    DWORD *bits[2];
    BITMAPINFO *info = calloc(1, FIELD_OFFSET(BITMAPINFO, bmiColors[256]));
    UINT i, j;
    int k;

    for (k = 0; k < 2; k++)
    {
        ZeroMemory(info, sizeof(info->bmiHeader));
        info->bmiHeader.biSize = sizeof(info->bmiHeader);
        info->bmiHeader.biWidth = 8;
        info->bmiHeader.biHeight = k ? -8 : 8;
        info->bmiHeader.biPlanes = 1;
        info->bmiHeader.biBitCount = 32;
        hbm[k] = CreateDIBSection(NULL, info, DIB_RGB_COLORS, (void **)&bits[k], NULL, 0);
        ok(hbm[k] != NULL, "CreateDIBSection failed\n");
        if (!hbm[k])
            goto cleanup;
    }

    for (i = 0; i < ARRAYSIZE(g_Rows); i++)
    {
        const ROW *row = &g_Rows[i];
        DWORD *dst = bits[row->bTopDown];
        char got[64 * 3 + 1], *p = got;
        int ret;
        DWORD error;

        SelectObject(hdc, hbm[row->bTopDown]);
        memset(dst, 0xaa, 64 * 4);

        ZeroMemory(info, sizeof(info->bmiHeader));
        info->bmiHeader.biSize = sizeof(info->bmiHeader);
        info->bmiHeader.biWidth = row->biWidth;
        info->bmiHeader.biHeight = row->biHeight;
        info->bmiHeader.biPlanes = 1;
        info->bmiHeader.biBitCount = 8;
        info->bmiHeader.biCompression = BI_RLE8;
        info->bmiHeader.biSizeImage = sizeof(rle8_data);
        for (j = 0; j < 256; j++)
            info->bmiColors[j].rgbRed = info->bmiColors[j].rgbGreen = info->bmiColors[j].rgbBlue = j;

        SetLastError(0xdeadbeef);
        ret = SetDIBitsToDevice(hdc, row->xDest, row->yDest, row->cx, row->cy, row->xSrc, row->ySrc,
                                row->uStartScan, row->cScanLines, rle8_data, info, DIB_RGB_COLORS);
        error = GetLastError();
        GdiFlush();

        for (j = 0; j < 64; j++)
        {
            if (dst[j] == 0xaaaaaaaa)
                *p++ = '.';
            else
                p += sprintf(p, "%02lx,", dst[j] & 0xff);
        }
        *p = 0;

        ok(ret == row->ret, "row %u: returned %d, expected %d\n", i, ret, row->ret);
        if (row->error)
            ok(error == row->error, "row %u: error %lu, expected %lu\n", i, error, row->error);
        ok(!strcmp(got, row->pixels), "row %u:\n got      %s\n expected %s\n", i, got, row->pixels);
    }

cleanup:
    SelectObject(hdc, GetStockObject(DEFAULT_BITMAP));
    for (k = 0; k < 2; k++)
        if (hbm[k])
            DeleteObject(hbm[k]);
    DeleteDC(hdc);
    free(info);
}
