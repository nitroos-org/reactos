/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         GetCharacterPlacementW with GCP_REORDER and no output string: the order and the
 *                  widths are returned (SWT asks for exactly that, once for every text it measures)
 */

#include "precomp.h"

START_TEST(GetCharPlacementReorder)
{
    static const WCHAR text[] = L"Hello world";
    const INT cch = 11;
    HDC hdc;
    GCP_RESULTSW res;
    UINT order[16], i;
    INT dx[16];
    WCHAR glyphs[16];
    DWORD ret;

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    if (!hdc)
        return;

    memset(order, 0xFF, sizeof(order));
    memset(dx, 0xFF, sizeof(dx));
    memset(&res, 0, sizeof(res));
    res.lStructSize = sizeof(res);
    res.lpOrder = order;
    res.lpDx = dx;
    res.nGlyphs = cch;

    ret = GetCharacterPlacementW(hdc, text, cch, 0, &res, GCP_REORDER);
    ok(ret != 0, "GetCharacterPlacementW returned 0, error %lu\n", GetLastError());
    for (i = 0; i < cch; i++)
    {
        ok(order[i] == i, "lpOrder[%u] is %u\n", i, order[i]);
        ok(dx[i] > 0 && dx[i] < 100, "lpDx[%u] is %d\n", i, dx[i]);
    }

    /* With the glyph shaping flag and a glyph array: the count that comes back fits the arrays (the widths of
     * a count taken from nowhere went beyond them) */
    memset(order, 0xFF, sizeof(order));
    memset(dx, 0, sizeof(dx));
    memset(glyphs, 0, sizeof(glyphs));
    memset(&res, 0, sizeof(res));
    res.lStructSize = sizeof(res);
    res.lpOrder = order;
    res.lpDx = dx;
    res.lpGlyphs = glyphs;
    res.nGlyphs = cch;

    ret = GetCharacterPlacementW(hdc, text, cch, 0, &res, GCP_REORDER | GCP_GLYPHSHAPE);
    ok(ret != 0, "GetCharacterPlacementW returned 0, error %lu\n", GetLastError());
    ok(res.nGlyphs <= cch, "nGlyphs is %u\n", res.nGlyphs);
    ok(dx[cch] == 0 && dx[cch + 1] == 0, "the widths went beyond the %d characters\n", cch);

    DeleteDC(hdc);
}
