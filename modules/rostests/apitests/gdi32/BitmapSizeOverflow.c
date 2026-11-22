/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Bitmap sizes that do not fit the row and image arithmetic, and run length data that
 *              does not fit its image
 *
 * win32k computed the row size of a surface as (cx * bpp + 31) & ~31 in 32 bits. From 2^27 pixels at
 * 32 bpp (2^29 at 8 bpp, 2^30 at 4 bpp) the product wraps: the surface was allocated with short or empty
 * rows while it kept its full width, and the run length decoder and the blits wrote and read behind it.
 * CreateDIBitmap with a 0x7FFFFFFF x 1 BI_RLE4 header stopped the machine. Images that cannot be
 * represented are refused now; large images that can are still made.
 */

#include "precomp.h"

#ifndef DEFAULT_BITMAP
#define DEFAULT_BITMAP 21
#endif

typedef struct
{
    BITMAPINFOHEADER bmiHeader;
    RGBQUAD bmiColors[256];
} BMI256;

static
void
InitInfo(BMI256 *pbmi, LONG cx, LONG cy, WORD cPlanes, WORD cBitCount, DWORD dwCompression, DWORD cjImage)
{
    UINT i;

    ZeroMemory(pbmi, sizeof(*pbmi));
    pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    pbmi->bmiHeader.biWidth = cx;
    pbmi->bmiHeader.biHeight = cy;
    pbmi->bmiHeader.biPlanes = cPlanes;
    pbmi->bmiHeader.biBitCount = cBitCount;
    pbmi->bmiHeader.biCompression = dwCompression;
    pbmi->bmiHeader.biSizeImage = cjImage;
    for (i = 0; i < 256; i++)
    {
        pbmi->bmiColors[i].rgbRed = (BYTE)i;
        pbmi->bmiColors[i].rgbGreen = (BYTE)(255 - i);
        pbmi->bmiColors[i].rgbBlue = (BYTE)(i * 7);
    }
}

/* runs of 255 pixels, then the end of bitmap code */
static
DWORD
MakeRuns(BYTE *pj, DWORD cj)
{
    DWORD i = 0;

    while (i + 4 <= cj)
    {
        pj[i++] = 0xFF;
        pj[i++] = 0x5A;
    }
    pj[i++] = 0;
    pj[i++] = 1;
    return i;
}

/* The row that stopped the machine, and the other ways into the same wrapped surface */
static
void
Test_WideRunLength(void)
{
    BMI256 bmi;
    BYTE ajData[400];
    DWORD cjData;
    HDC hdcScreen, hdcMem;
    HBITMAP hbm, hbmTarget, hbmOld;
    INT iResult;

    hdcScreen = GetDC(NULL);
    ok(hdcScreen != NULL, "GetDC failed\n");
    cjData = MakeRuns(ajData, sizeof(ajData));

    /* CreateDIBitmap with CBM_INIT: the DDB is the device format, the source surface 4 bpp */
    InitInfo(&bmi, 0x7FFFFFFF, 1, 1, 4, BI_RLE4, cjData);
    SetLastError(0xdeadbeef);
    hbm = CreateDIBitmap(hdcScreen, &bmi.bmiHeader, CBM_INIT, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
    ok(hbm == NULL, "CreateDIBitmap(0x7FFFFFFF x 1, BI_RLE4) returned %p\n", hbm);
    if (hbm) DeleteObject(hbm);

    /* An 8 bpp row of 0x7FFFFFFF pixels is 2 GB: more than a row can be, refused */
    InitInfo(&bmi, 0x7FFFFFFF, 1, 1, 8, BI_RLE8, cjData);
    hbm = CreateDIBitmap(hdcScreen, &bmi.bmiHeader, CBM_INIT | CBM_CREATDIB, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
    ok(hbm == NULL, "CreateDIBitmap(CBM_CREATDIB, 0x7FFFFFFF x 1, BI_RLE8) returned %p\n", hbm);
    if (hbm) DeleteObject(hbm);

    /* CBM_CREATDIB makes a DDB of the header's format: a 4 bpp row of 0x7FFFFFFF pixels (1 GB) and an
       8 bpp row of 0x40000001 pixels can be represented. They wrapped to empty rows before; now they
       are either refused for lack of memory or made with their full rows. */
    {
        static const struct { LONG cx; WORD cBitCount; DWORD dwCompression; } aWide[] =
        {
            { 0x7FFFFFFF, 4, BI_RLE4 },
            { 0x40000001, 8, BI_RLE8 },
        };
        UINT i;
        BITMAP bm;

        for (i = 0; i < _countof(aWide); i++)
        {
            InitInfo(&bmi, aWide[i].cx, 1, 1, aWide[i].cBitCount, aWide[i].dwCompression, cjData);
            hbm = CreateDIBitmap(hdcScreen, &bmi.bmiHeader, CBM_INIT | CBM_CREATDIB, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
            if (hbm == NULL)
                continue;
            ok_int(GetObjectW(hbm, sizeof(bm), &bm), (INT)sizeof(bm));
            ok_long(bm.bmWidth, aWide[i].cx);
            ok_long(bm.bmHeight, 1);
            ok_long(bm.bmWidthBytes, (LONG)((((ULONGLONG)aWide[i].cx * aWide[i].cBitCount + 15) & ~15) >> 3));
            DeleteObject(hbm);
        }
    }

    /* SetDIBitsToDevice and StretchDIBits decode into a temporary surface of the header's width */
    hdcMem = CreateCompatibleDC(hdcScreen);
    hbmTarget = CreateCompatibleBitmap(hdcScreen, 16, 16);
    hbmOld = SelectObject(hdcMem, hbmTarget);

    /* gdi32 reports the header's line count for run length data whatever win32k did, so the
       return value says little here; the pixels say what happened. 8 bpp: 2 GB row, refused. */
    InitInfo(&bmi, 0x7FFFFFFF, 1, 1, 8, BI_RLE8, cjData);
    iResult = SetDIBitsToDevice(hdcMem, 0, 0, 16, 1, 0, 0, 0, 1, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
    ok(iResult == 0 || iResult == 1, "SetDIBitsToDevice(0x7FFFFFFF x 1, BI_RLE8) returned %d\n", iResult);
    ok_hex(GetPixel(hdcMem, 0, 0), RGB(0, 0, 0));

    /* 4 bpp: a 1 GB row; refused for lack of memory, or decoded right (the runs start with colour 5) */
    InitInfo(&bmi, 0x7FFFFFFF, 1, 1, 4, BI_RLE4, cjData);
    iResult = SetDIBitsToDevice(hdcMem, 0, 0, 16, 1, 0, 0, 0, 1, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
    ok(iResult == 0 || iResult == 1, "SetDIBitsToDevice(0x7FFFFFFF x 1, BI_RLE4) returned %d\n", iResult);
    {
        COLORREF cr = GetPixel(hdcMem, 0, 0);
        ok(cr == RGB(0, 0, 0) || cr == RGB(5, 255 - 5, 5 * 7), "pixel 0x%06lx\n", cr);
        cr = GetPixel(hdcMem, 1, 0);
        ok(cr == RGB(0, 0, 0) || cr == RGB(10, 255 - 10, 10 * 7), "pixel 0x%06lx\n", cr);
    }

    /* Not SRCCOPY: the image goes through a temporary bitmap of the header's size; must not fault */
    InitInfo(&bmi, 0x7FFFFFFF, 1, 1, 4, BI_RLE4, cjData);
    StretchDIBits(hdcMem, 0, 0, 16, 16, 0, 0, 16, 1, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS, SRCINVERT);
    StretchDIBits(hdcMem, 0, 0, 16, 16, 0, 0, 16, 1, ajData, (BITMAPINFO *)&bmi, DIB_RGB_COLORS, SRCCOPY);

    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbmTarget);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

/* Sizes whose rows or images do not fit: refused, never a smaller bitmap */
static
void
Test_UnrepresentableSizes(void)
{
    static const struct
    {
        LONG cx, cy;
        WORD cPlanes, cBitCount;
        DWORD dwCompression;
    } aDib[] =
    {
        { 0x7FFFFFFF, 1, 1, 32, BI_RGB },     /* row of 8 GB */
        { 0x8000000, 1, 1, 32, BI_RGB },      /* 2^27 x 32 bits wraps 32 bit arithmetic exactly */
        { 0x8000001, 1, 1, 32, BI_RGB },
        { 0x40000001, 4, 1, 8, BI_RGB },
        { 0x10000, 0x10000, 1, 32, BI_RGB },  /* image of 16 GB */
        { 0x10000000, 16, 1, 4, BI_RGB },     /* image of exactly 2 GB: rows of 128 MB; the blits address
                                                 rows in LONG arithmetic, a 64-bit process could make it */
        { 0x8000000, -32, 1, 4, BI_RGB },     /* the same, top-down */
        { 16, MINLONG, 1, 8, BI_RGB },        /* abs(MINLONG) is negative */
        { -1, 1, 1, 8, BI_RGB },
        { 0, 16, 1, 8, BI_RGB },
        { 16, 0, 1, 8, BI_RGB },
        { 16, 16, 1, 3, BI_RGB },             /* a bit count a DIB cannot have */
        { 16, 16, 1, 0, BI_RGB },
        { 16, 16, 1, 33, BI_RGB },
        { 16, 16, 0, 8, BI_RGB },             /* no planes */
    };
    static const struct
    {
        INT cx, cy;
        UINT cPlanes, cBitCount;
    } aDdb[] =
    {
        { 0x8000000, 1, 1, 32 },
        { 0x7FFFFFFF, 1, 1, 1 },
        { 0x7FFFFFF, 0x7FFFFFF, 1, 1 },
        { 0x10000, 0x10000, 1, 32 },
        { 16, 16, 1, 64 },
        { 16, 16, 64, 1 },
    };
    static const INT aCompat[][2] =
    {
        { 0x40000001, 4 },     /* the product wraps to 4 in 32 bits */
        { 0x10000, 0x10000 },
        { 0x7FFFFFFF, 0x7FFFFFFF },
    };
    BMI256 bmi;
    HDC hdcScreen;
    HBITMAP hbm;
    PVOID pvBits;
    UINT i;

    hdcScreen = GetDC(NULL);

    for (i = 0; i < _countof(aDib); i++)
    {
        InitInfo(&bmi, aDib[i].cx, aDib[i].cy, aDib[i].cPlanes, aDib[i].cBitCount, aDib[i].dwCompression, 0);
        pvBits = (PVOID)(ULONG_PTR)0xdeadbeef;
        hbm = CreateDIBSection(hdcScreen, (BITMAPINFO *)&bmi, DIB_RGB_COLORS, &pvBits, NULL, 0);
        ok(hbm == NULL, "[%u] CreateDIBSection(%ld x %ld, %u planes, %u bpp) returned %p\n",
           i, aDib[i].cx, aDib[i].cy, aDib[i].cPlanes, aDib[i].cBitCount, hbm);
        if (hbm) DeleteObject(hbm);
    }

    for (i = 0; i < _countof(aDdb); i++)
    {
        hbm = CreateBitmap(aDdb[i].cx, aDdb[i].cy, aDdb[i].cPlanes, aDdb[i].cBitCount, NULL);
        ok(hbm == NULL, "[%u] CreateBitmap(%d x %d, %u planes, %u bpp) returned %p\n",
           i, aDdb[i].cx, aDdb[i].cy, aDdb[i].cPlanes, aDdb[i].cBitCount, hbm);
        if (hbm) DeleteObject(hbm);
    }

    for (i = 0; i < _countof(aCompat); i++)
    {
        hbm = CreateCompatibleBitmap(hdcScreen, aCompat[i][0], aCompat[i][1]);
        ok(hbm == NULL, "[%u] CreateCompatibleBitmap(%d x %d) returned %p\n", i, aCompat[i][0], aCompat[i][1], hbm);
        if (hbm) DeleteObject(hbm);
    }

    ReleaseDC(NULL, hdcScreen);
}

/* GetDIBits writes a colour table behind the caller's header: it must stay inside the table */
static
void
Test_GetDIBitsColorTable(void)
{
    struct
    {
        BYTE ajHeader[sizeof(BITMAPV5HEADER) + 256 * sizeof(RGBQUAD)];
        BYTE ajGuard[1024];
    } info;
    LOGPALETTE *plp;
    HPALETTE hpal, hpalOld;
    HDC hdcScreen, hdcMem;
    HBITMAP hbm;
    BITMAPINFOHEADER *pbih = (BITMAPINFOHEADER *)info.ajHeader;
    BYTE ajBits[16 * 16];
    INT iResult, i;

    hdcScreen = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdcScreen);
    hbm = CreateBitmap(16, 16, 1, 8, NULL);
    ok(hbm != NULL, "CreateBitmap failed\n");

    /* A logical palette with far more entries than any DIB colour table */
    plp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOGPALETTE) + 1000 * sizeof(PALETTEENTRY));
    plp->palVersion = 0x300;
    plp->palNumEntries = 1000;
    for (i = 0; i < 1000; i++)
        plp->palPalEntry[i].peRed = (BYTE)i;
    hpal = CreatePalette(plp);
    HeapFree(GetProcessHeap(), 0, plp);
    ok(hpal != NULL, "CreatePalette failed\n");
    hpalOld = SelectPalette(hdcMem, hpal, FALSE);

    memset(&info, 0xCC, sizeof(info));
    ZeroMemory(pbih, sizeof(BITMAPINFOHEADER));
    pbih->biSize = sizeof(BITMAPINFOHEADER);
    pbih->biWidth = 16;
    pbih->biHeight = 16;
    pbih->biPlanes = 1;
    pbih->biBitCount = 8;
    iResult = GetDIBits(hdcMem, hbm, 0, 16, ajBits, (BITMAPINFO *)pbih, DIB_RGB_COLORS);
    ok_int(iResult, 16);
    for (i = 0; i < (INT)sizeof(info.ajGuard); i++)
    {
        if (info.ajGuard[i] != 0xCC) break;
    }
    ok_int(i, (INT)sizeof(info.ajGuard));

    /* The largest header GetDIBits accepts, with the colour table behind it */
    memset(&info, 0xCC, sizeof(info));
    ZeroMemory(pbih, sizeof(BITMAPV5HEADER));
    pbih->biSize = sizeof(BITMAPV5HEADER);
    pbih->biWidth = 16;
    pbih->biHeight = 16;
    pbih->biPlanes = 1;
    pbih->biBitCount = 8;
    iResult = GetDIBits(hdcMem, hbm, 0, 16, ajBits, (BITMAPINFO *)pbih, DIB_PAL_COLORS);
    ok(iResult == 16 || iResult == 0, "GetDIBits(V5 header) returned %d\n", iResult);

    /* A core header asking for palette indices of a 4 bpp bitmap */
    {
        BITMAPCOREINFO *pbci = (BITMAPCOREINFO *)info.ajHeader;
        HBITMAP hbm4 = CreateBitmap(16, 16, 1, 4, NULL);

        memset(&info, 0xCC, sizeof(info));
        ZeroMemory(pbci, sizeof(BITMAPCOREHEADER));
        pbci->bmciHeader.bcSize = sizeof(BITMAPCOREHEADER);
        pbci->bmciHeader.bcWidth = 16;
        pbci->bmciHeader.bcHeight = 16;
        pbci->bmciHeader.bcPlanes = 1;
        pbci->bmciHeader.bcBitCount = 4;
        iResult = GetDIBits(hdcMem, hbm4, 0, 16, ajBits, (BITMAPINFO *)pbci, DIB_PAL_COLORS);
        ok(iResult == 16 || iResult == 0, "GetDIBits(core header, DIB_PAL_COLORS) returned %d\n", iResult);
        DeleteObject(hbm4);
    }

    /* A core header asking for palette indices of a 32 bpp bitmap: there are none, the call fails
       (the failed conversion used to be converted back from a NULL info in the kernel) */
    {
        BITMAPCOREINFO *pbci = (BITMAPCOREINFO *)info.ajHeader;
        HBITMAP hbm32 = CreateBitmap(16, 16, 1, 32, NULL);

        memset(&info, 0xCC, sizeof(info));
        ZeroMemory(pbci, sizeof(BITMAPCOREHEADER));
        pbci->bmciHeader.bcSize = sizeof(BITMAPCOREHEADER);
        pbci->bmciHeader.bcWidth = 16;
        pbci->bmciHeader.bcHeight = 16;
        pbci->bmciHeader.bcPlanes = 1;
        pbci->bmciHeader.bcBitCount = 32;
        iResult = GetDIBits(hdcMem, hbm32, 0, 16, NULL, (BITMAPINFO *)pbci, DIB_PAL_COLORS);
        ok_int(iResult, 0);
        iResult = GetDIBits(hdcMem, hbm32, 0, 16, ajBits, (BITMAPINFO *)pbci, DIB_PAL_COLORS);
        ok_int(iResult, 0);
        DeleteObject(hbm32);
    }

    SelectPalette(hdcMem, hpalOld, FALSE);
    DeleteObject(hpal);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

/* Run length data: valid streams still decode, malformed ones stay inside the image */
static
void
Test_RunLengthDecoding(void)
{
    BMI256 bmi;
    BITMAPINFO bmiDst;
    HDC hdcScreen, hdcMem;
    HBITMAP hbmDib, hbmOld;
    DWORD *pdwBits;
    INT iResult;
    UINT i;

    hdcScreen = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdcScreen);

    /* 8 x 4 top-down 32 bpp target, initialised to 0x11111111 */
    ZeroMemory(&bmiDst, sizeof(bmiDst));
    bmiDst.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmiDst.bmiHeader.biWidth = 8;
    bmiDst.bmiHeader.biHeight = -4;
    bmiDst.bmiHeader.biPlanes = 1;
    bmiDst.bmiHeader.biBitCount = 32;
    hbmDib = CreateDIBSection(hdcMem, &bmiDst, DIB_RGB_COLORS, (PVOID *)&pdwBits, NULL, 0);
    ok(hbmDib != NULL, "CreateDIBSection failed\n");
    if (!hbmDib) return;
    hbmOld = SelectObject(hdcMem, hbmDib);

    /* Valid RLE8 4 x 2 image: bottom row 4 x colour 1, top row 2 x colour 2, 2 x colour 3 */
    {
        static const BYTE ajRle[] = { 4, 1, 0, 0, 2, 2, 2, 3, 0, 0, 0, 1 };
        for (i = 0; i < 32; i++) pdwBits[i] = 0x11111111;
        InitInfo(&bmi, 4, 2, 1, 8, BI_RLE8, sizeof(ajRle));
        iResult = SetDIBitsToDevice(hdcMem, 0, 0, 4, 2, 0, 0, 0, 2, ajRle, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
        ok_int(iResult, 2);
        /* top row (y = 0) is the second row of the bottom-up DIB */
        ok_hex(pdwBits[0], (2 << 16) | ((255 - 2) << 8) | (2 * 7));
        ok_hex(pdwBits[2], (3 << 16) | ((255 - 3) << 8) | (3 * 7));
        ok_hex(pdwBits[8], (1 << 16) | ((255 - 1) << 8) | (1 * 7));
        ok_hex(pdwBits[11], (1 << 16) | ((255 - 1) << 8) | (1 * 7));
        /* outside the image: untouched */
        ok_hex(pdwBits[4], 0x11111111);
        ok_hex(pdwBits[12], 0x11111111);
    }

    /* A run longer than the row: clipped at the row end, the next row is not touched */
    {
        static const BYTE ajRle[] = { 255, 5, 0, 1 };
        for (i = 0; i < 32; i++) pdwBits[i] = 0x11111111;
        InitInfo(&bmi, 4, 2, 1, 8, BI_RLE8, sizeof(ajRle));
        iResult = SetDIBitsToDevice(hdcMem, 0, 0, 4, 2, 0, 0, 0, 2, ajRle, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
        ok_int(iResult, 2);
        ok_hex(pdwBits[8 + 3], (5 << 16) | ((255 - 5) << 8) | (5 * 7));
        ok_hex(pdwBits[8 + 4], 0x11111111);
        ok_hex(pdwBits[0], 0x11111111);
    }

    /* Escapes that move the cursor outside the image, an absolute run past the end of the data,
       end of line codes past the last row and no end marker: none of it writes outside */
    {
        static const BYTE aajRle[][12] =
        {
            { 0, 2, 255, 0, 3, 7, 0, 0 },          /* delta far right, then a run */
            { 0, 2, 0, 255, 3, 7 },                /* delta far up */
            { 0, 200, 1, 2, 3 },                   /* absolute run of 200, 3 bytes there */
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 6 },/* end of line storm */
            { 2, 9, 2, 9, 2, 9 },                  /* no end of bitmap */
        };
        UINT j;
        for (j = 0; j < _countof(aajRle); j++)
        {
            for (i = 0; i < 32; i++) pdwBits[i] = 0x11111111;
            InitInfo(&bmi, 4, 2, 1, 8, BI_RLE8, sizeof(aajRle[j]));
            SetDIBitsToDevice(hdcMem, 0, 0, 4, 2, 0, 0, 0, 2, aajRle[j], (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
            for (i = 0; i < 32; i++)
            {
                if ((i % 8) < 4 && i < 16) continue; /* inside the 4 x 2 image */
                if (pdwBits[i] != 0x11111111) break;
            }
            ok(i == 32, "[%u] pixel %u outside the image changed to 0x%08lx\n", j, i, i < 32 ? pdwBits[i] : 0);

            InitInfo(&bmi, 4, 2, 1, 4, BI_RLE4, sizeof(aajRle[j]));
            SetDIBitsToDevice(hdcMem, 0, 0, 4, 2, 0, 0, 0, 2, aajRle[j], (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
        }
    }

    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbmDib);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

/* Large images that can be represented are still made and usable */
static
void
Test_ValidLarge(void)
{
    static const struct
    {
        LONG cx, cy;
        WORD cBitCount;
        BOOL bMayLackMemory; /* 256 MB of address space is not always there for a 32-bit process */
    } aValid[] =
    {
        { 16384, 16384, 1, FALSE },
        { 8192, 8192, 32, TRUE },
        { 65536, 64, 32, FALSE },
        { 1, 65536, 32, FALSE },
    };
    BMI256 bmi;
    HDC hdcScreen, hdcMem;
    HBITMAP hbm, hbmOld;
    PVOID pvBits;
    BITMAP bm;
    UINT i;

    hdcScreen = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdcScreen);

    for (i = 0; i < _countof(aValid); i++)
    {
        InitInfo(&bmi, aValid[i].cx, aValid[i].cy, 1, aValid[i].cBitCount, BI_RGB, 0);
        /* black and white for the monochrome image, so the colours below are exact */
        bmi.bmiColors[0].rgbRed = bmi.bmiColors[0].rgbGreen = bmi.bmiColors[0].rgbBlue = 0;
        bmi.bmiColors[1].rgbRed = bmi.bmiColors[1].rgbGreen = bmi.bmiColors[1].rgbBlue = 255;
        hbm = CreateDIBSection(hdcScreen, (BITMAPINFO *)&bmi, DIB_RGB_COLORS, &pvBits, NULL, 0);
        if (!hbm && aValid[i].bMayLackMemory)
        {
            skip("[%u] no memory for %ld x %ld x %u\n", i, aValid[i].cx, aValid[i].cy, aValid[i].cBitCount);
            continue;
        }
        ok(hbm != NULL, "[%u] CreateDIBSection(%ld x %ld x %u) failed (%lu)\n",
           i, aValid[i].cx, aValid[i].cy, aValid[i].cBitCount, GetLastError());
        if (!hbm) continue;

        ok_int(GetObjectW(hbm, sizeof(bm), &bm), (INT)sizeof(bm));
        ok_long(bm.bmWidth, aValid[i].cx);
        ok_long(bm.bmHeight, aValid[i].cy);
        ok_long(bm.bmWidthBytes, (LONG)((((ULONGLONG)aValid[i].cx * aValid[i].cBitCount + 31) & ~31) >> 3));

        hbmOld = SelectObject(hdcMem, hbm);
        PatBlt(hdcMem, 0, 0, aValid[i].cx, aValid[i].cy, BLACKNESS);
        SetPixel(hdcMem, aValid[i].cx - 1, aValid[i].cy - 1, RGB(255, 255, 255));
        ok_hex(GetPixel(hdcMem, aValid[i].cx - 1, aValid[i].cy - 1), RGB(255, 255, 255));
        ok_hex(GetPixel(hdcMem, 0, 0), RGB(0, 0, 0));
        SelectObject(hdcMem, hbmOld);
        DeleteObject(hbm);
    }

    /* A 16384 x 16384 monochrome DDB (32 MB) */
    hbm = CreateBitmap(16384, 16384, 1, 1, NULL);
    ok(hbm != NULL, "CreateBitmap(16384 x 16384 x 1) failed (%lu)\n", GetLastError());
    if (hbm)
    {
        hbmOld = SelectObject(hdcMem, hbm);
        PatBlt(hdcMem, 0, 0, 16384, 16384, WHITENESS);
        ok_hex(GetPixel(hdcMem, 16383, 16383), RGB(255, 255, 255));
        SelectObject(hdcMem, hbmOld);
        DeleteObject(hbm);
    }

    /* Run length data at a large but representable width still decodes */
    {
        BYTE ajRle[] = { 4, 9, 0, 1 };
        InitInfo(&bmi, 0x10000, 1, 1, 8, BI_RLE8, sizeof(ajRle));
        hbm = CreateDIBitmap(hdcScreen, &bmi.bmiHeader, CBM_INIT, ajRle, (BITMAPINFO *)&bmi, DIB_RGB_COLORS);
        ok(hbm != NULL, "CreateDIBitmap(65536 x 1, BI_RLE8) failed (%lu)\n", GetLastError());
        if (hbm)
        {
            hbmOld = SelectObject(hdcMem, hbm);
            ok_hex(GetPixel(hdcMem, 3, 0), RGB(9, 255 - 9, 9 * 7));
            SelectObject(hdcMem, hbmOld);
            DeleteObject(hbm);
        }
    }

    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

/* Icon resources: user32 must read no further than the size it is given */
static
void
Test_IconResource(void)
{
    SYSTEM_INFO si;
    BYTE *pjBase, *pj;
    BITMAPINFOHEADER *pbih;
    DWORD cjXor = 16 * 16 * 4, cjAnd = 4 * 16, cj, dwOld;
    HICON hicon;

    GetSystemInfo(&si);
    pjBase = VirtualAlloc(NULL, 4 * si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(pjBase != NULL, "VirtualAlloc failed\n");
    if (!pjBase) return;
    /* the last page is not accessible: a read behind the resource faults */
    VirtualProtect(pjBase + 3 * si.dwPageSize, si.dwPageSize, PAGE_NOACCESS, &dwOld);

    /* A complete 16 x 16 32 bpp icon, placed against the inaccessible page */
    cj = sizeof(BITMAPINFOHEADER) + cjXor + cjAnd;
    pj = pjBase + 3 * si.dwPageSize - cj;
    ZeroMemory(pj, cj);
    pbih = (BITMAPINFOHEADER *)pj;
    pbih->biSize = sizeof(BITMAPINFOHEADER);
    pbih->biWidth = 16;
    pbih->biHeight = 32;
    pbih->biPlanes = 1;
    pbih->biBitCount = 32;
    hicon = CreateIconFromResourceEx(pj, cj, TRUE, 0x00030000, 16, 16, LR_DEFAULTCOLOR);
    ok(hicon != NULL, "CreateIconFromResourceEx(complete icon) failed (%lu)\n", GetLastError());
    if (hicon) DestroyIcon(hicon);

    /* Without its AND mask: the colour bits are all there, the mask is taken as empty */
    cj = sizeof(BITMAPINFOHEADER) + cjXor;
    memmove(pjBase + 3 * si.dwPageSize - cj, pbih, sizeof(BITMAPINFOHEADER));
    pj = pjBase + 3 * si.dwPageSize - cj;
    hicon = CreateIconFromResourceEx(pj, cj, TRUE, 0x00030000, 16, 16, LR_DEFAULTCOLOR);
    ok(hicon != NULL, "CreateIconFromResourceEx(no AND mask) failed (%lu)\n", GetLastError());
    if (hicon) DestroyIcon(hicon);

    /* A header that claims more colour bits than there are: refused, nothing read behind them */
    cj = sizeof(BITMAPINFOHEADER) + 64;
    memmove(pjBase + 3 * si.dwPageSize - cj, pbih, sizeof(BITMAPINFOHEADER));
    pj = pjBase + 3 * si.dwPageSize - cj;
    pbih = (BITMAPINFOHEADER *)pj;
    hicon = CreateIconFromResourceEx(pj, cj, TRUE, 0x00030000, 16, 16, LR_DEFAULTCOLOR);
    ok(hicon == NULL, "CreateIconFromResourceEx(truncated) returned %p\n", hicon);
    if (hicon) DestroyIcon(hicon);

    /* A 1 bpp header with no room for its two colours */
    pbih->biBitCount = 1;
    cj = sizeof(BITMAPINFOHEADER) + 4;
    memmove(pjBase + 3 * si.dwPageSize - cj, pbih, sizeof(BITMAPINFOHEADER));
    pj = pjBase + 3 * si.dwPageSize - cj;
    hicon = CreateIconFromResourceEx(pj, cj, TRUE, 0x00030000, 16, 16, LR_DEFAULTCOLOR);
    ok(hicon == NULL, "CreateIconFromResourceEx(1 bpp, no colour table) returned %p\n", hicon);
    if (hicon) DestroyIcon(hicon);

    /* A width whose image size wraps 32 bits */
    pbih = (BITMAPINFOHEADER *)(pjBase + 3 * si.dwPageSize - sizeof(BITMAPINFOHEADER) - 64);
    ZeroMemory(pbih, sizeof(BITMAPINFOHEADER) + 64);
    pbih->biSize = sizeof(BITMAPINFOHEADER);
    pbih->biWidth = 0x8000000;
    pbih->biHeight = 2;
    pbih->biPlanes = 1;
    pbih->biBitCount = 32;
    hicon = CreateIconFromResourceEx((BYTE *)pbih, sizeof(BITMAPINFOHEADER) + 64, TRUE, 0x00030000, 16, 16, LR_DEFAULTCOLOR);
    ok(hicon == NULL, "CreateIconFromResourceEx(0x8000000 wide) returned %p\n", hicon);
    if (hicon) DestroyIcon(hicon);

    VirtualFree(pjBase, 0, MEM_RELEASE);
}

/* A DIB_PAL_COLORS pattern brush of a 32 bpp DIB has no colour indices to translate. Realizing it
   failed and kept a lock on the pattern bitmap, which then outlived the brush: one bitmap (and its
   pool) per brush. */
static
void
Test_PalColorsBrush(void)
{
    struct
    {
        BITMAPINFOHEADER bmiHeader;
        DWORD adwBits[8 * 8];
    } packed;
    HDC hdcScreen, hdcMem;
    HBITMAP hbmTarget, hbmOld;
    HBRUSH hbr, hbrOld;
    DWORD dwBefore, dwAfter;
    INT i;

    ZeroMemory(&packed, sizeof(packed));
    packed.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    packed.bmiHeader.biWidth = 8;
    packed.bmiHeader.biHeight = 8;
    packed.bmiHeader.biPlanes = 1;
    packed.bmiHeader.biBitCount = 32;
    for (i = 0; i < 64; i++)
        packed.adwBits[i] = 0x00336699;

    hdcScreen = GetDC(NULL);
    hdcMem = CreateCompatibleDC(hdcScreen);
    hbmTarget = CreateCompatibleBitmap(hdcScreen, 16, 16);
    hbmOld = SelectObject(hdcMem, hbmTarget);

    dwBefore = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    for (i = 0; i < 100; i++)
    {
        hbr = CreateDIBPatternBrushPt(&packed, DIB_PAL_COLORS);
        if (!hbr) continue;
        hbrOld = SelectObject(hdcMem, hbr);
        PatBlt(hdcMem, 0, 0, 16, 16, PATCOPY);
        SelectObject(hdcMem, hbrOld);
        DeleteObject(hbr);
    }
    dwAfter = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    ok(dwAfter <= dwBefore + 2, "GDI objects %lu -> %lu after 100 DIB_PAL_COLORS brushes\n", dwBefore, dwAfter);

    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbmTarget);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

START_TEST(BitmapSizeOverflow)
{
    Test_WideRunLength();
    Test_UnrepresentableSizes();
    Test_GetDIBitsColorTable();
    Test_RunLengthDecoding();
    Test_ValidLarge();
    Test_IconResource();
    Test_PalColorsBrush();
}
