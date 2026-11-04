/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that GDI font linking draws Hangul, kana and Han from a base font that has none
 *              of them, whatever the pitch and family of the base font request
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * GDI text output looks a glyph that the selected font lacks up in the SystemLink chain of the
 * face (HKLM\...\FontLink\SystemLink), then in the default link. The linked face is found by its
 * name; the pitch and family of the request that realized the base font must not take part.
 * Notepad asks for "Lucida Console" with FIXED_PITCH | FF_MODERN, so a fixed-pitch request has to
 * link to the proportional CJK face as well as a proportional one does.
 *
 * A glyph that is drawn from a linked font looks different from the base font's notdef glyph
 * (the box), which is also what a code point nothing has a glyph for (U+E0FF) is drawn as. So the
 * test draws each character into a bitmap and requires ink that differs from that notdef bitmap,
 * and that two different characters differ from each other.
 */

#define CELL_W 48
#define CELL_H 40

static BOOL g_bFound;

static int CALLBACK
FindFaceProc(const LOGFONTW *plf, const TEXTMETRICW *ptm, DWORD FontType, LPARAM lParam)
{
    g_bFound = TRUE;
    return 0;
}

static BOOL
HasFace(HDC hdc, PCWSTR pszFace)
{
    LOGFONTW lf = { 0 };
    lf.lfCharSet = DEFAULT_CHARSET;
    StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), pszFace);
    g_bFound = FALSE;
    EnumFontFamiliesExW(hdc, &lf, FindFaceProc, 0, 0);
    return g_bFound;
}

/* Draws one character, returns the number of dark pixels and the bits in pBits (CELL_W * CELL_H) */
static int
DrawChar(HFONT hFont, WCHAR ch, BYTE *pBits)
{
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER) } };
    HDC hdc = CreateCompatibleDC(NULL);
    HBITMAP hbm, hbmOld;
    HGDIOBJ hOldFont;
    BYTE *pvBits;
    int x, y, ink = 0;

    bmi.bmiHeader.biWidth = CELL_W;
    bmi.bmiHeader.biHeight = -CELL_H;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, (void **)&pvBits, NULL, 0);
    hbmOld = SelectObject(hdc, hbm);
    hOldFont = SelectObject(hdc, hFont);
    FillMemory(pvBits, CELL_W * CELL_H * 4, 0xFF);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(0, 0, 0));
    ExtTextOutW(hdc, 4, 4, 0, NULL, &ch, 1, NULL);
    GdiFlush();
    for (y = 0; y < CELL_H; y++)
    {
        for (x = 0; x < CELL_W; x++)
        {
            BYTE v = pvBits[(y * CELL_W + x) * 4 + 1];
            pBits[y * CELL_W + x] = v;
            if (v < 128)
                ink++;
        }
    }
    SelectObject(hdc, hOldFont);
    SelectObject(hdc, hbmOld);
    DeleteObject(hbm);
    DeleteDC(hdc);
    return ink;
}

static const struct
{
    PCWSTR Face;
    BYTE PitchAndFamily;
} g_Bases[] =
{
    { L"Lucida Console", FIXED_PITCH | FF_MODERN },     /* Notepad */
    { L"Lucida Console", DEFAULT_PITCH | FF_DONTCARE },
    { L"Courier New", FIXED_PITCH | FF_MODERN },
    { L"Consolas", FIXED_PITCH | FF_MODERN },        /* no SystemLink entry here */
    { L"Tahoma", VARIABLE_PITCH | FF_SWISS },
    { L"Arial", VARIABLE_PITCH | FF_SWISS },
};

static const struct
{
    PCSTR Name;
    WCHAR Chars[3];
} g_Scripts[] =
{
    { "Hangul", { 0xD55C, 0xAD6D, 0xC5B4 } },
    { "kana", { 0x3042, 0x30A2, 0x3044 } },
    { "Han", { 0x4E2D, 0x65E5, 0x8A9E } },
};

START_TEST(FontLinkCJK)
{
    HDC hdcScreen = GetDC(NULL);
    BYTE Notdef[CELL_W * CELL_H], Cell[3][CELL_W * CELL_H];
    UINT iBase, iScript, i, j;

    if (!HasFace(hdcScreen, L"Noto Sans KR") && !HasFace(hdcScreen, L"Malgun Gothic"))
    {
        skip("No Korean font installed\n");
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    ReleaseDC(NULL, hdcScreen);

    for (iBase = 0; iBase < _countof(g_Bases); iBase++)
    {
        LOGFONTW lf = { 0 };
        HFONT hFont;
        int NotdefInk;

        lf.lfHeight = -16;
        lf.lfWeight = FW_NORMAL;
        lf.lfCharSet = DEFAULT_CHARSET;
        lf.lfPitchAndFamily = g_Bases[iBase].PitchAndFamily;
        StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), g_Bases[iBase].Face);
        hFont = CreateFontIndirectW(&lf);
        ok(hFont != NULL, "CreateFontIndirectW failed\n");
        if (!hFont)
            continue;

        NotdefInk = DrawChar(hFont, 0xE0FF, Notdef);
        ok(NotdefInk > 0, "%ls: the notdef glyph draws nothing\n", g_Bases[iBase].Face);

        for (iScript = 0; iScript < _countof(g_Scripts); iScript++)
        {
            for (i = 0; i < 3; i++)
            {
                int Ink = DrawChar(hFont, g_Scripts[iScript].Chars[i], Cell[i]);
                ok(Ink > 0, "%ls/0x%02X: %s U+%04X draws nothing\n",
                   g_Bases[iBase].Face, g_Bases[iBase].PitchAndFamily,
                   g_Scripts[iScript].Name, g_Scripts[iScript].Chars[i]);
                ok(memcmp(Cell[i], Notdef, sizeof(Notdef)) != 0,
                   "%ls/0x%02X: %s U+%04X is drawn as the notdef glyph, not from a linked font\n",
                   g_Bases[iBase].Face, g_Bases[iBase].PitchAndFamily,
                   g_Scripts[iScript].Name, g_Scripts[iScript].Chars[i]);
            }
            for (i = 0; i < 3; i++)
            {
                for (j = i + 1; j < 3; j++)
                {
                    ok(memcmp(Cell[i], Cell[j], sizeof(Cell[i])) != 0,
                       "%ls/0x%02X: %s U+%04X and U+%04X are drawn alike\n",
                       g_Bases[iBase].Face, g_Bases[iBase].PitchAndFamily, g_Scripts[iScript].Name,
                       g_Scripts[iScript].Chars[i], g_Scripts[iScript].Chars[j]);
                }
            }
        }
        DeleteObject(hFont);
    }
}
