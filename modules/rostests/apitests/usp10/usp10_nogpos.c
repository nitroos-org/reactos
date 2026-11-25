/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A run shaped with fNoGlyphIndex holds characters, not glyph indices: Uniscribe must not
 *              apply the font's GPOS lookups (keyed by glyph index) to it. Windows Server 2022: the advances
 *              of ScriptShape + ScriptPlace with fNoGlyphIndex are the GetCharWidth32 advances.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <usp10.h>
#include <stdio.h>

#include "wine/test.h"

static void test_face(const WCHAR *file, const WCHAR *face)
{
    static const WCHAR text[] = L"To Ty Yo WAVE fi fl ffi ffl LT P. F, Wa";
    WCHAR path[MAX_PATH], actual[LF_FACESIZE];
    LOGFONTW lf = { 0 };
    HFONT font, old;
    HDC dc;
    SCRIPT_ITEM items[16];
    SCRIPT_CACHE sc = NULL;
    int count = 0, n = (int)lstrlenW(text), i, j, adv[64], plain[64], total = 0, plain_total = 0;
    int checked = 0;

    GetWindowsDirectoryW(path, MAX_PATH);
    lstrcatW(path, L"\\Fonts\\");
    lstrcatW(path, file);
    if (!AddFontResourceExW(path, FR_PRIVATE, NULL))
    {
        skip("%ls is not installed\n", file);
        return;
    }

    dc = CreateCompatibleDC(NULL);
    lf.lfHeight = -32;
    lf.lfCharSet = DEFAULT_CHARSET;
    lstrcpyW(lf.lfFaceName, face);
    font = CreateFontIndirectW(&lf);
    old = SelectObject(dc, font);
    GetTextFaceW(dc, LF_FACESIZE, actual);
    if (lstrcmpiW(actual, face))
    {
        skip("%ls: the font selected is %ls\n", face, actual);
        goto done;
    }

    for (i = 0; i < n; i++)
    {
        INT w = 0;
        GetCharWidth32W(dc, text[i], text[i], &w);
        plain[i] = w;
        plain_total += w;
    }

    ok(SUCCEEDED(ScriptItemize(text, n, 16, NULL, NULL, items, &count)), "ScriptItemize failed\n");
    for (j = 0; j < count; j++)
    {
        SCRIPT_ANALYSIS a = items[j].a;
        int pos = items[j].iCharPos, len = items[j + 1].iCharPos - pos, ng = 0;
        WORD glyphs[64], clusters[64];
        SCRIPT_VISATTR va[64];
        GOFFSET off[64];
        ABC abc;
        HRESULT hr;

        a.fNoGlyphIndex = TRUE;
        hr = ScriptShape(dc, &sc, text + pos, len, 64, &a, glyphs, clusters, va, &ng);
        ok(hr == S_OK, "%ls: ScriptShape returned %#lx\n", face, hr);
        if (hr != S_OK || ng != len)
            continue;
        hr = ScriptPlace(dc, &sc, glyphs, ng, va, &a, adv + pos, off, &abc);
        ok(hr == S_OK, "%ls: ScriptPlace returned %#lx\n", face, hr);
        if (hr != S_OK)
            continue;
        for (i = 0; i < len; i++)
        {
            total += adv[pos + i];
            checked++;
            ok(adv[pos + i] == plain[pos + i], "%ls: character %d (%lc): advance %d, GetCharWidth32 %d\n",
               face, pos + i, text[pos + i], adv[pos + i], plain[pos + i]);
        }
    }
    ok(checked == n, "%ls: %d of %d characters placed\n", face, checked, n);
    ok(total == plain_total, "%ls: total %d, GetCharWidth32 total %d\n", face, total, plain_total);
    ScriptFreeCache(&sc);

done:
    SelectObject(dc, old);
    DeleteObject(font);
    DeleteDC(dc);
    RemoveFontResourceExW(path, FR_PRIVATE, NULL);
}

START_TEST(usp10_nogpos)
{
    test_face(L"Carlito-Regular.ttf", L"Carlito");
    test_face(L"SourceSansPro-Regular.ttf", L"Source Sans Pro");
    test_face(L"FreeSans.ttf", L"FreeSans");
}
