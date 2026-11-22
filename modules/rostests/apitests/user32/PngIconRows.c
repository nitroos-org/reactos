/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A PNG icon whose rows are not a multiple of 4 bytes: row size and image size
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* A 3 x 3, 8 bit RGB PNG (9 bytes a row, 12 in a DIB), made with zlib and struct from the pixels below:
   a signature, IHDR, one IDAT of zlib.compress(filter byte 0 + the rows, 9), IEND. */
static const BYTE g_Png[] =
{
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x08, 0x02, 0x00, 0x00, 0x00, 0xD9, 0x4A, 0x22,
    0xE8, 0x00, 0x00, 0x00, 0x22, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0xF8, 0xCF, 0xC0, 0xC0,
    0x00, 0xC1, 0x5C, 0x22, 0x72, 0x1A, 0x46, 0x36, 0x6E, 0x01, 0x51, 0x0C, 0x27, 0x52, 0x8C, 0x18,
    0x99, 0x98, 0x7F, 0xFD, 0xFE, 0x03, 0x00, 0x74, 0x5B, 0x09, 0x15, 0xB3, 0xE4, 0x7D, 0xB1, 0x00,
    0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
};

static const BYTE g_Pixels[3][3][3] =
{
    { { 255, 0, 0 }, { 0, 255, 0 }, { 0, 0, 255 } },
    { { 10, 20, 30 }, { 40, 50, 60 }, { 70, 80, 90 } },
    { { 200, 100, 50 }, { 1, 2, 3 }, { 250, 251, 252 } },
};

static BOOL Near(int a, int b)
{
    return abs(a - b) <= 8;
}

START_TEST(PngIconRows)
{
    HICON hIcon;
    ICONINFO ii;
    BITMAP bm;
    HDC hdc;
    BITMAPINFO bmi;
    BYTE bits[3 * 3 * 4];
    int x, y;
    BYTE *copy;

    /* A copy of the PNG on its own heap block: nothing readable behind it matters for the parser */
    copy = HeapAlloc(GetProcessHeap(), 0, sizeof(g_Png));
    memcpy(copy, g_Png, sizeof(g_Png));

    SetLastError(0xdeadbeef);
    hIcon = CreateIconFromResourceEx(copy, sizeof(g_Png), TRUE, 0x00030000, 3, 3, 0);
    if (!hIcon)
    {
        skip("PNG icons are not available (error %lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, copy);
        return;
    }

    ZeroMemory(&ii, sizeof(ii));
    ok(GetIconInfo(hIcon, &ii), "GetIconInfo failed, error %lu\n", GetLastError());
    ok(ii.hbmColor != NULL, "no colour bitmap\n");
    if (ii.hbmColor)
    {
        ZeroMemory(&bm, sizeof(bm));
        ok(GetObjectW(ii.hbmColor, sizeof(bm), &bm) != 0, "GetObject failed\n");
        ok(bm.bmWidth == 3 && bm.bmHeight == 3, "bitmap is %ld x %ld\n", bm.bmWidth, bm.bmHeight);

        ZeroMemory(&bmi, sizeof(bmi));
        bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
        bmi.bmiHeader.biWidth = 3;
        bmi.bmiHeader.biHeight = -3;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        memset(bits, 0xCD, sizeof(bits));
        hdc = CreateCompatibleDC(NULL);
        ok(GetDIBits(hdc, ii.hbmColor, 0, 3, bits, &bmi, DIB_RGB_COLORS) == 3, "GetDIBits failed\n");
        DeleteDC(hdc);

        for (y = 0; y < 3; y++)
        {
            for (x = 0; x < 3; x++)
            {
                const BYTE *p = &bits[(y * 3 + x) * 4];
                const BYTE *e = g_Pixels[y][x];
                if (!Near(p[2], e[0]) || !Near(p[1], e[1]) || !Near(p[0], e[2]))
                {
                    ok(0, "pixel (%d,%d) is %u,%u,%u, expected %u,%u,%u\n", x, y, p[2], p[1], p[0], e[0], e[1], e[2]);
                }
            }
        }
        DeleteObject(ii.hbmColor);
    }
    if (ii.hbmMask)
        DeleteObject(ii.hbmMask);
    DestroyIcon(hIcon);
    HeapFree(GetProcessHeap(), 0, copy);
}
