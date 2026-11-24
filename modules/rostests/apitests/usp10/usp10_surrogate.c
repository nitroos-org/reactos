/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ScriptShape of runs made of surrogate pairs, left to right and right to left. A right-to-left run
 *              was shaped past the end of an internal buffer (a corrupted heap on x86). The expected glyph counts
 *              and clusters were measured on Windows Server 2022: one glyph per pair; in a right-to-left run the
 *              cluster numbers count from the end.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <usp10.h>
#include <stdio.h>

#include "wine/test.h"

static void shape_items(const char *name, const WCHAR *text, int length, int level, int override,
                        int item, int expect_glyphs, const WORD *expect_clusters)
{
    SCRIPT_ITEM items[32];
    SCRIPT_CONTROL control = { 0 };
    SCRIPT_STATE state = { 0 };
    SCRIPT_CACHE cache = NULL;
    int count = 0, i, glyphs = 0;
    HRESULT hr;
    HDC dc = CreateCompatibleDC(NULL);
    HGDIOBJ old = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    int pos, len;
    WORD out[64], clusters[64];
    SCRIPT_VISATTR attrs[64];
    SCRIPT_ANALYSIS analysis;

    state.uBidiLevel = level;
    state.fOverrideDirection = override;
    hr = ScriptItemize(text, length, 32, &control, &state, items, &count);
    ok(hr == S_OK, "%s: ScriptItemize returned %#lx\n", name, hr);
    ok(item < count, "%s: %d items\n", name, count);
    if (hr != S_OK || item >= count)
        goto done;

    pos = items[item].iCharPos;
    len = items[item + 1].iCharPos - pos;
    analysis = items[item].a;
    hr = ScriptShape(dc, &cache, text + pos, len, len * 2 + 16, &analysis, out, clusters, attrs, &glyphs);
    ok(hr == S_OK, "%s: ScriptShape returned %#lx\n", name, hr);
    ok(glyphs == expect_glyphs, "%s: %d glyphs, expected %d\n", name, glyphs, expect_glyphs);
    for (i = 0; i < len; i++)
        ok(clusters[i] == expect_clusters[i], "%s: cluster %d is %d, expected %d\n", name, i, clusters[i], expect_clusters[i]);
    ok(HeapValidate(GetProcessHeap(), 0, NULL), "%s: the heap is corrupted\n", name);

done:
    ScriptFreeCache(&cache);
    SelectObject(dc, old);
    DeleteDC(dc);
}

START_TEST(usp10_surrogate)
{
    static const WCHAR two[] = { 0xd83d, 0xde3c, 0xd83d, 0xde23 };
    static const WCHAR one[] = { 0xd83d, 0xde3c };
    static const WCHAR arabic[] = { 0x0627, 0x0644, 0xd83d, 0xde3c, 0x0639, 0x0631 };
    static const WORD ltr_two[] = { 0, 0, 1, 1 }, rtl_two[] = { 1, 1, 0, 0 }, pair[] = { 0, 0 };
    int i;

    /* the run is shaped many times: an overrun of two bytes does not show every time */
    for (i = 0; i < 50; i++)
    {
        shape_items("two pairs, left to right", two, 4, 0, 0, 0, 2, ltr_two);
        shape_items("two pairs, right to left", two, 4, 1, 1, 0, 2, rtl_two);
        shape_items("one pair, left to right", one, 2, 0, 0, 0, 1, pair);
        shape_items("one pair, right to left", one, 2, 1, 1, 0, 1, pair);
        shape_items("pair between Arabic letters", arabic, 6, 0, 0, 1, 1, pair);
    }
}
