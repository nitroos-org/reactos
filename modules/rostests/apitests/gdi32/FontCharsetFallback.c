/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A CJK charset request for a face that is not installed gets a font that has the
 *              characters of that charset; a full enumeration leaves out the legacy aliases
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Windows: a request for a face it has no font for (MS Gothic without the font, a Shift-JIS request for a
 * Western face ...) is served by the installed font that has the requested charset, and its glyphs are
 * those of the charset. A full enumeration (empty face name) does not list the aliases of FontSubstitutes
 * that exist for lookups only: Helv, Helvetica, MS Shell Dlg, MS Shell Dlg 2, Times, Tms Rmn.
 */

static BOOL HasFace(PCWSTR Face)
{
    HDC hdc = CreateCompatibleDC(NULL);
    LOGFONTW lf = { -16 };
    HFONT hFont;
    HGDIOBJ hOld;
    WCHAR Name[LF_FACESIZE] = L"";

    lf.lfCharSet = DEFAULT_CHARSET;
    StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), Face);
    hFont = CreateFontIndirectW(&lf);
    hOld = SelectObject(hdc, hFont);
    GetTextFaceW(hdc, _countof(Name), Name);
    SelectObject(hdc, hOld);
    DeleteObject(hFont);
    DeleteDC(hdc);
    return !_wcsicmp(Name, Face);
}

/* Does the font a request gets have all the characters? Returns the face name it got. */
static BOOL RequestHas(PCWSTR Face, BYTE CharSet, const WCHAR *Chars, UINT cChars, PWSTR Got, BOOL *pAll)
{
    HDC hdc = CreateCompatibleDC(NULL);
    LOGFONTW lf = { -20 };
    HFONT hFont;
    HGDIOBJ hOld;
    WORD Index[16];
    UINT i;
    BOOL Ret;
    TEXTMETRICW tm;

    lf.lfWeight = FW_NORMAL;
    lf.lfCharSet = CharSet;
    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), Face);
    hFont = CreateFontIndirectW(&lf);
    hOld = SelectObject(hdc, hFont);
    Got[0] = 0;
    GetTextFaceW(hdc, LF_FACESIZE, Got);
    GetTextMetricsW(hdc, &tm);
    Ret = GetGlyphIndicesW(hdc, Chars, cChars, Index, GGI_MARK_NONEXISTING_GLYPHS) != GDI_ERROR;
    *pAll = Ret;
    for (i = 0; Ret && i < cChars; i++)
        if (Index[i] == 0xFFFF)
            *pAll = FALSE;
    SelectObject(hdc, hOld);
    DeleteObject(hFont);
    DeleteDC(hdc);
    return Ret;
}

static void test_CjkRequest(PCWSTR Face, BYTE CharSet, PCSTR CharSetName, const WCHAR *Chars, UINT cChars)
{
    WCHAR Got[LF_FACESIZE];
    BOOL All;

    ok(RequestHas(Face, CharSet, Chars, cChars, Got, &All), "GetGlyphIndices failed\n");
    ok(All, "%ls (%s): the font it got, '%ls', lacks characters of the charset\n", Face, CharSetName, Got);
    ok(wcscmp(Got, L"Noto Sans KR") != 0 || CharSet == HANGEUL_CHARSET,
       "%ls (%s): got '%ls'\n", Face, CharSetName, Got);
}

static int CALLBACK EnumProc(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD Type, LPARAM lParam)
{
    PCWSTR *Names = (PCWSTR *)lParam;
    static const PCWSTR Hidden[] = { L"Helv", L"Helvetica", L"MS Shell Dlg", L"MS Shell Dlg 2", L"Times", L"Tms Rmn" };
    UINT i;
    for (i = 0; i < _countof(Hidden); i++)
        if (!_wcsicmp(lf->lfFaceName, Hidden[i]))
            Names[i] = Hidden[i];
    return 1;
}

static int CALLBACK HasNameProc(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD Type, LPARAM lParam)
{
    PBOOL pFound = (PBOOL)lParam;
    *pFound = TRUE;
    return 1;
}

static void test_FullEnumeration(void)
{
    HDC hdc = CreateCompatibleDC(NULL);
    LOGFONTW lf;
    PCWSTR Seen[6] = { NULL };
    UINT i;
    BOOL Found;

    ZeroMemory(&lf, sizeof(lf));
    lf.lfCharSet = DEFAULT_CHARSET;
    EnumFontFamiliesExW(hdc, &lf, EnumProc, (LPARAM)Seen, 0);
    for (i = 0; i < 6; i++)
        ok(Seen[i] == NULL, "a full enumeration lists the alias '%ls'\n", Seen[i]);

    /* ... but a lookup by that name still works, as the other substitutes remain listed */
    ZeroMemory(&lf, sizeof(lf));
    lf.lfCharSet = DEFAULT_CHARSET;
    StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), L"MS Shell Dlg");
    Found = FALSE;
    EnumFontFamiliesExW(hdc, &lf, HasNameProc, (LPARAM)&Found, 0);
    ok(Found, "MS Shell Dlg is not found by name\n");
    DeleteDC(hdc);
}

START_TEST(FontCharsetFallback)
{
    /* kana, rare JIS X 0208 kanji (U+5516, U+9BF5), a kana-only sample would pass on a Hangul face */
    static const WCHAR Jis[] = { 0x3042, 0x30A2, 0x5516, 0x9BF5, 0x4E9C };
    /* simplified hanzi of GB 2312 that a Hangul face lacks */
    static const WCHAR Gb[] = { 0x54CE, 0x6D51, 0x4E2D };
    static const WCHAR Hangul[] = { 0xD55C, 0xAE00 };

    test_FullEnumeration();

    if (!HasFace(L"Noto Sans SC"))
    {
        skip("no CJK font is installed\n");
        return;
    }
    test_CjkRequest(L"MS Gothic", SHIFTJIS_CHARSET, "SHIFTJIS", Jis, _countof(Jis));
    test_CjkRequest(L"MS Mincho", SHIFTJIS_CHARSET, "SHIFTJIS", Jis, _countof(Jis));
    test_CjkRequest(L"NoSuchFaceAnywhere", SHIFTJIS_CHARSET, "SHIFTJIS", Jis, _countof(Jis));
    test_CjkRequest(L"SimSun", GB2312_CHARSET, "GB2312", Gb, _countof(Gb));
    test_CjkRequest(L"Batang", HANGEUL_CHARSET, "HANGEUL", Hangul, _countof(Hangul));
}
