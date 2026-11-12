/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     System font fallback maps symbols that applications put in their user interface (Chrome draws
 *              U+21E5 RIGHTWARDS ARROW TO BAR, the Tab key, in the omnibox hint) to an installed font that has
 *              a glyph for them
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <windows.h>
#include <dwrite_2.h>

#include "wine/test.h"

struct text_source
{
    IDWriteTextAnalysisSource IDWriteTextAnalysisSource_iface;
    const WCHAR *text;
    UINT32 length;
};

static struct text_source *impl_from_source(IDWriteTextAnalysisSource *iface)
{
    return CONTAINING_RECORD(iface, struct text_source, IDWriteTextAnalysisSource_iface);
}

static HRESULT WINAPI source_QueryInterface(IDWriteTextAnalysisSource *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IDWriteTextAnalysisSource) || IsEqualIID(riid, &IID_IUnknown))
    {
        *obj = iface;
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI source_AddRef(IDWriteTextAnalysisSource *iface)
{
    return 2;
}

static ULONG WINAPI source_Release(IDWriteTextAnalysisSource *iface)
{
    return 1;
}

static HRESULT WINAPI source_GetTextAtPosition(IDWriteTextAnalysisSource *iface, UINT32 position,
        const WCHAR **text, UINT32 *length)
{
    struct text_source *source = impl_from_source(iface);

    if (position >= source->length)
    {
        *text = NULL;
        *length = 0;
    }
    else
    {
        *text = source->text + position;
        *length = source->length - position;
    }
    return S_OK;
}

static HRESULT WINAPI source_GetTextBeforePosition(IDWriteTextAnalysisSource *iface, UINT32 position,
        const WCHAR **text, UINT32 *length)
{
    struct text_source *source = impl_from_source(iface);

    if (!position || position > source->length)
    {
        *text = NULL;
        *length = 0;
    }
    else
    {
        *text = source->text;
        *length = position;
    }
    return S_OK;
}

static DWRITE_READING_DIRECTION WINAPI source_GetParagraphReadingDirection(IDWriteTextAnalysisSource *iface)
{
    return DWRITE_READING_DIRECTION_LEFT_TO_RIGHT;
}

static HRESULT WINAPI source_GetLocaleName(IDWriteTextAnalysisSource *iface, UINT32 position,
        UINT32 *length, const WCHAR **locale)
{
    struct text_source *source = impl_from_source(iface);

    *locale = L"en-us";
    *length = source->length - position;
    return S_OK;
}

static HRESULT WINAPI source_GetNumberSubstitution(IDWriteTextAnalysisSource *iface, UINT32 position,
        UINT32 *length, IDWriteNumberSubstitution **substitution)
{
    struct text_source *source = impl_from_source(iface);

    *substitution = NULL;
    *length = source->length - position;
    return S_OK;
}

static IDWriteTextAnalysisSourceVtbl source_vtbl =
{
    source_QueryInterface,
    source_AddRef,
    source_Release,
    source_GetTextAtPosition,
    source_GetTextBeforePosition,
    source_GetParagraphReadingDirection,
    source_GetLocaleName,
    source_GetNumberSubstitution,
};

static const struct
{
    UINT32 ch;
    const char *what;
}
symbols[] =
{
    { 0x21e5, "RIGHTWARDS ARROW TO BAR (Chrome omnibox hint, the Tab key)" },
    { 0x21e4, "LEFTWARDS ARROW TO BAR" },
    { 0x21b5, "DOWNWARDS ARROW WITH CORNER LEFTWARDS (Enter key)" },
    { 0x2192, "RIGHTWARDS ARROW" },
    { 0x2b7e, "HORIZONTAL TAB KEY" },
    { 0x2002, "EN SPACE" },
    { 0x20b9, "INDIAN RUPEE SIGN" },
};

START_TEST(dwrite_fallback_symbols)
{
    IDWriteFontCollection *collection;
    IDWriteFontFallback *fallback;
    IDWriteFactory2 *factory2;
    IDWriteFactory *factory;
    struct text_source source;
    HRESULT hr;
    int i;

    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, &IID_IDWriteFactory, (IUnknown **)&factory);
    ok(hr == S_OK, "DWriteCreateFactory failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;
    hr = IDWriteFactory_QueryInterface(factory, &IID_IDWriteFactory2, (void **)&factory2);
    if (FAILED(hr))
    {
        skip("IDWriteFactory2 is not available\n");
        IDWriteFactory_Release(factory);
        return;
    }
    hr = IDWriteFactory2_GetSystemFontFallback(factory2, &fallback);
    ok(hr == S_OK, "GetSystemFontFallback failed, hr %#lx\n", hr);
    hr = IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE);
    ok(hr == S_OK, "GetSystemFontCollection failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;

    source.IDWriteTextAnalysisSource_iface.lpVtbl = &source_vtbl;

    for (i = 0; i < ARRAY_SIZE(symbols); ++i)
    {
        WCHAR text[2] = { symbols[i].ch, 0 };
        IDWriteFont *font = NULL;
        BOOL exists = FALSE;
        UINT32 length = 0;
        float scale = 0.0f;

        source.text = text;
        source.length = 1;
        hr = IDWriteFontFallback_MapCharacters(fallback, &source.IDWriteTextAnalysisSource_iface, 0, 1,
                collection, L"Tahoma", DWRITE_FONT_WEIGHT_NORMAL, DWRITE_FONT_STYLE_NORMAL,
                DWRITE_FONT_STRETCH_NORMAL, &length, &font, &scale);
        ok(hr == S_OK, "U+%04X: MapCharacters failed, hr %#lx\n", symbols[i].ch, hr);
        ok(font != NULL, "U+%04X %s: no font in the fallback, the character is drawn as a box\n",
                symbols[i].ch, symbols[i].what);
        ok(length == 1, "U+%04X: mapped length %u\n", symbols[i].ch, length);
        if (font)
        {
            hr = IDWriteFont_HasCharacter(font, symbols[i].ch, &exists);
            ok(hr == S_OK && exists, "U+%04X: the font MapCharacters returned has no glyph, hr %#lx\n",
                    symbols[i].ch, hr);
            IDWriteFont_Release(font);
        }
    }

    IDWriteFontCollection_Release(collection);
    IDWriteFontFallback_Release(fallback);
    IDWriteFactory2_Release(factory2);
    IDWriteFactory_Release(factory);
}
