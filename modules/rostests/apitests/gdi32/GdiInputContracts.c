/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test GDI input checks (sizes, font buffers, batch records, Eng entry points)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/ntndk.h>
#include <prntfont.h>
#include <ntgdi.h>

INT APIENTRY NtGdiAddFontResourceW(PCWCH, ULONG, ULONG, FLONG, DWORD, const DESIGNVECTOR *);
BOOL APIENTRY NtGdiRemoveFontResourceW(PCWCH, ULONG, ULONG, ULONG, DWORD, const DESIGNVECTOR *);

static void test_sizes(HDC dc)
{
    POINT point = { 1, 1 };
    BYTE type = 0;
    TRIVERTEX vertex = { 0 };
    GRADIENT_RECT mesh = { 0, 0 };
    PATRECT rectangle = { { 0, 0, 1, 1 }, NULL };
    BYTE data = 0;

    ok(!NtGdiTransformPoints(dc, &point, &point, 0x40000000, GdiDpToLp),
       "TransformPoints accepted a count whose byte size overflows\n");
    ok(NtGdiGetPath(dc, &point, &type, 0x40000000) == -1,
       "GetPath accepted a count whose byte size overflows\n");
    ok(!NtGdiCreateServerMetaFile(GDITAG_TYPE_MFP, 0xffffffff, &data, 0, 0, 0),
       "CreateServerMetaFile accepted a wrapped object size\n");
    ok(!NtGdiGradientFill(dc, &vertex, 0x10000000, &mesh, 1, GRADIENT_FILL_RECT_H),
       "GradientFill accepted a wrapped vertex size\n");
    ok(!NtGdiPolyPatBlt(dc, PATCOPY, (PPOLYPATBLT)&rectangle, 0x40000000, 0),
       "PolyPatBlt accepted a wrapped rectangle size\n");
    ok(NtGdiTransformPoints(dc, &point, &point, 1, GdiDpToLp),
       "TransformPoints rejected a valid point\n");
}

static void test_fonts(HDC dc)
{
    GLYPHMETRICS metrics = { 0 };
    const MAT2 matrix = { { 0, 1 }, { 0, 0 }, { 0, 0 }, { 0, 1 } };
    const WCHAR names[] = { L'Z', 0, L'X' };
    BYTE data[4];
    DWORD size;

    ok(NtGdiGetGlyphOutline(dc, L'A', GGO_METRICS, &metrics, 0, NULL,
                            (const MAT2 *)(ULONG_PTR)1, FALSE) == GDI_ERROR,
       "GetGlyphOutline accepted an unreadable matrix\n");
    ok(NtGdiGetGlyphOutline(dc, L'A', GGO_METRICS, &metrics, 0, NULL,
                            &matrix, FALSE) != GDI_ERROR,
       "GetGlyphOutline rejected a valid matrix\n");
    size = NtGdiGetFontData(dc, 0, 0, NULL, 0);
    if (size != GDI_ERROR && size >= sizeof(data))
    {
        ok(NtGdiGetFontData(dc, 0, 0, (PVOID)(ULONG_PTR)1, sizeof(data)) == GDI_ERROR,
           "GetFontData accepted an unwritable output buffer\n");
        ok(NtGdiGetFontData(dc, 0, 0, data, sizeof(data)) == sizeof(data),
           "GetFontData rejected a valid output buffer\n");
    }
    else
        skip("Selected font has no accessible table\n");

    ok(!NtGdiAddFontResourceW(names, 3, 2, 0, 0, NULL),
       "AddFontResource accepted a nonterminated name list\n");
    ok(!NtGdiRemoveFontResourceW(names, 3, 2, 0, 0, NULL),
       "RemoveFontResource accepted a nonterminated name list\n");
}

static void test_batch(HDC dc)
{
    PTEB teb = NtCurrentTeb();
    PGDIBATCHHDR header;
    PGDIBSPPATBLT rectangles;

    GdiFlush();
    header = (PGDIBATCHHDR)teb->GdiTebBatch.Buffer;
    header->Cmd = GdiBCPatBlt;
    header->Size = 0;
    teb->GdiBatchCount = 1;
    teb->GdiTebBatch.Offset = sizeof(*header);
    teb->GdiTebBatch.HDC = dc;
    NtGdiFlush();
    ok(!teb->GdiBatchCount && !teb->GdiTebBatch.Offset,
       "Malformed batch was not cleared\n");

    header->Size = 0x7fff;
    teb->GdiBatchCount = 1;
    teb->GdiTebBatch.Offset = sizeof(*header);
    teb->GdiTebBatch.HDC = dc;
    NtGdiFlush();
    ok(!teb->GdiBatchCount && !teb->GdiTebBatch.Offset,
       "Oversized batch record was not cleared\n");

    teb->GdiBatchCount = 0xffffffff;
    teb->GdiTebBatch.Offset = sizeof(*header);
    teb->GdiTebBatch.HDC = dc;
    NtGdiFlush();
    ok(teb->GdiBatchCount == 0xffffffff,
       "Invalid count changed unexpectedly\n");
    teb->GdiBatchCount = 0;
    teb->GdiTebBatch.Offset = 0;
    teb->GdiTebBatch.HDC = 0;

    rectangles = (PGDIBSPPATBLT)teb->GdiTebBatch.Buffer;
    rectangles->gbHdr.Cmd = GdiBCPolyPatBlt;
    rectangles->gbHdr.Size = sizeof(*rectangles);
    rectangles->Count = 1000;
    teb->GdiBatchCount = 1;
    teb->GdiTebBatch.Offset = sizeof(*rectangles);
    teb->GdiTebBatch.HDC = dc;
    NtGdiFlush();
    ok(!teb->GdiBatchCount && !teb->GdiTebBatch.Offset,
       "Out-of-range rectangle count was not cleared\n");

    {
        PGDIBSTEXTOUT text = (PGDIBSTEXTOUT)teb->GdiTebBatch.Buffer;
        text->gbHdr.Cmd = GdiBCTextOut;
        text->gbHdr.Size = sizeof(*text);
        text->cbCount = 1000;
        text->Size = 0;
        teb->GdiBatchCount = 1;
        teb->GdiTebBatch.Offset = sizeof(*text);
        teb->GdiTebBatch.HDC = dc;
        NtGdiFlush();
        ok(!teb->GdiBatchCount && !teb->GdiTebBatch.Offset,
           "Out-of-range text count was not cleared\n");
    }
}

static void test_eng(void)
{
    HPALETTE palette = GetStockObject(DEFAULT_PALETTE);
    ULONG color = RGB(255, 0, 0);
    HPALETTE owned;

    ok(!NtGdiEngLockSurface(NULL), "EngLockSurface returned an object pointer\n");
    ok(!NtGdiEngBitBlt(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0),
       "EngBitBlt accepted unsupported object pointers\n");
    ok(!NtGdiEngStretchBlt(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0),
       "EngStretchBlt accepted unsupported object pointers\n");
    ok(!NtGdiEngAlphaBlend(NULL, NULL, NULL, NULL, NULL, NULL, NULL),
       "EngAlphaBlend accepted unsupported object pointers\n");
    ok(!NtGdiEngDeletePalette(palette), "EngDeletePalette accepted a stock palette\n");
    ok(GetStockObject(DEFAULT_PALETTE) == palette, "Stock palette changed\n");
    owned = NtGdiEngCreatePalette(PAL_INDEXED, 1, &color, 0, 0, 0);
    if (owned)
        ok(NtGdiEngDeletePalette(owned), "Owned palette could not be deleted\n");
    else
        skip("EngCreatePalette is unavailable\n");
}

START_TEST(GdiInputContracts)
{
    HDC dc = CreateCompatibleDC(NULL);
    HFONT font = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             0, 0, 0, 0, L"Tahoma");
    HGDIOBJ old_font;

    if (!dc || !font)
    {
        skip("Could not prepare a font and DC\n");
        if (font) DeleteObject(font);
        if (dc) DeleteDC(dc);
        return;
    }
    old_font = SelectObject(dc, font);
    test_sizes(dc);
    test_fonts(dc);
    test_batch(dc);
    test_eng();
    SelectObject(dc, old_font);
    DeleteObject(font);
    DeleteDC(dc);
}
