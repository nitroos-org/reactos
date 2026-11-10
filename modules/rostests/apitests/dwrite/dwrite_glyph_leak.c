/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Rendering a glyph run at a fractional pixel position must not leak memory. Each such glyph
 *              is rendered by the FreeType anti-aliased bitmap path; the mono renderer in front of it used
 *              to allocate its worker and pool (about 17 KB) and return without freeing them, so a program
 *              drawing a few thousand lines of text with Direct2D or DirectWrite ran out of memory.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <psapi.h>
#include <dwrite_2.h>

#include "wine/test.h"

#define GLYPHS 64
#define RUNS 100
/* The leak was 17.5 KB per glyph, 1.1 MB per run. The allowance covers caches that fill once. */
#define ALLOWED_GROWTH (8 * 1024 * 1024)

static SIZE_T private_bytes(void)
{
    PROCESS_MEMORY_COUNTERS_EX pmc;

    pmc.cb = sizeof(pmc);
    if (!GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc)))
        return 0;
    return pmc.PrivateUsage;
}

static IDWriteFontFace *create_face(IDWriteFactory *factory)
{
    static const WCHAR *families[] = { L"Arial", L"Tahoma", L"Segoe UI", L"Times New Roman" };
    IDWriteFontCollection *collection;
    IDWriteFontFace *face = NULL;
    unsigned int i;
    HRESULT hr;

    hr = IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    if (FAILED(hr))
        return NULL;

    for (i = 0; i < ARRAY_SIZE(families) && !face; i++)
    {
        IDWriteFontFamily *family;
        IDWriteFont *font;
        UINT32 index;
        BOOL exists;

        if (FAILED(IDWriteFontCollection_FindFamilyName(collection, families[i], &index, &exists)) || !exists)
            continue;
        if (FAILED(IDWriteFontCollection_GetFontFamily(collection, index, &family)))
            continue;
        if (SUCCEEDED(IDWriteFontFamily_GetFirstMatchingFont(family, DWRITE_FONT_WEIGHT_NORMAL,
                DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, &font)))
        {
            IDWriteFont_CreateFontFace(font, &face);
            IDWriteFont_Release(font);
        }
        IDWriteFontFamily_Release(family);
    }
    IDWriteFontCollection_Release(collection);
    return face;
}

static void test_run(IDWriteFactory2 *factory, IDWriteFontFace *face, float x, DWRITE_TEXT_ANTIALIAS_MODE aa,
        const char *name)
{
    static const DWRITE_MATRIX identity = { 1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f };
    DWRITE_TEXTURE_TYPE type = aa == DWRITE_TEXT_ANTIALIAS_MODE_CLEARTYPE ?
            DWRITE_TEXTURE_CLEARTYPE_3x1 : DWRITE_TEXTURE_ALIASED_1x1;
    UINT32 codepoints[GLYPHS];
    UINT16 indices[GLYPHS];
    float advances[GLYPHS];
    DWRITE_GLYPH_RUN run;
    SIZE_T before, after;
    unsigned int i, j, nonzero = 0;
    HRESULT hr;

    for (i = 0; i < GLYPHS; i++)
    {
        codepoints[i] = 'a' + (i * 7) % 26;
        advances[i] = 7.0f;
    }
    hr = IDWriteFontFace_GetGlyphIndices(face, codepoints, GLYPHS, indices);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);

    memset(&run, 0, sizeof(run));
    run.fontFace = face;
    run.fontEmSize = 14.0f;
    run.glyphCount = GLYPHS;
    run.glyphIndices = indices;
    run.glyphAdvances = advances;

    before = private_bytes();
    for (i = 0; i < RUNS; i++)
    {
        IDWriteGlyphRunAnalysis *analysis;
        RECT bounds;
        BYTE *texture;
        size_t size;

        hr = IDWriteFactory2_CreateGlyphRunAnalysis(factory, &run, &identity, DWRITE_RENDERING_MODE_NATURAL_SYMMETRIC,
                DWRITE_MEASURING_MODE_NATURAL, DWRITE_GRID_FIT_MODE_DEFAULT, aa, x, 20.0f, &analysis);
        ok(hr == S_OK, "%s: got hr %#lx.\n", name, hr);
        if (FAILED(hr))
            return;

        hr = IDWriteGlyphRunAnalysis_GetAlphaTextureBounds(analysis, type, &bounds);
        ok(hr == S_OK, "%s: got hr %#lx.\n", name, hr);
        size = (size_t)(bounds.right - bounds.left) * (bounds.bottom - bounds.top) * (type == DWRITE_TEXTURE_CLEARTYPE_3x1 ? 3 : 1);
        ok(size > 0, "%s: empty bounds.\n", name);
        texture = calloc(1, size + 1);
        hr = IDWriteGlyphRunAnalysis_CreateAlphaTexture(analysis, type, &bounds, texture, size);
        ok(hr == S_OK, "%s: got hr %#lx.\n", name, hr);
        if (i == 0)
        {
            for (j = 0; j < size; j++)
                nonzero += texture[j] != 0;
            ok(nonzero > 0, "%s: the texture is empty.\n", name);
        }
        free(texture);
        IDWriteGlyphRunAnalysis_Release(analysis);
    }
    after = private_bytes();

    ok(after < before + ALLOWED_GROWTH, "%s: %u runs of %u glyphs grew the process by %lu bytes.\n",
            name, RUNS, GLYPHS, (unsigned long)(after - before));
}

START_TEST(dwrite_glyph_leak)
{
    IDWriteFactory2 *factory2;
    IDWriteFactory *factory;
    IDWriteFontFace *face;
    HRESULT hr;

    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, &IID_IDWriteFactory, (IUnknown **)&factory);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    if (FAILED(hr))
        return;

    if (FAILED(IDWriteFactory_QueryInterface(factory, &IID_IDWriteFactory2, (void **)&factory2)))
    {
        skip("IDWriteFactory2 is not available.\n");
        IDWriteFactory_Release(factory);
        return;
    }

    face = create_face(factory);
    if (!face)
    {
        skip("No system font to draw with.\n");
    }
    else
    {
        /* Whole pixel positions come from the glyph cache; the quarter pixel ones are rendered every time. */
        test_run(factory2, face, 4.0f, DWRITE_TEXT_ANTIALIAS_MODE_GRAYSCALE, "grayscale, whole pixel");
        test_run(factory2, face, 4.25f, DWRITE_TEXT_ANTIALIAS_MODE_GRAYSCALE, "grayscale, quarter pixel");
        test_run(factory2, face, 4.25f, DWRITE_TEXT_ANTIALIAS_MODE_CLEARTYPE, "cleartype, quarter pixel");
        IDWriteFontFace_Release(face);
    }

    IDWriteFactory2_Release(factory2);
    IDWriteFactory_Release(factory);
}
