/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that "Arial" enumerates as Windows does, also after the app realized it
 *              at other weights and styles
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Measured on Windows 10 22H2 (64-bit):
 * - EnumFontFamiliesExW("Arial", ANSI_CHARSET) gives the four faces: "Arial" (400, upright),
 *   "Arial Bold" (700), "Arial Bold Italic" (700, italic), "Arial Italic" (400, italic).
 * - EnumFontFamiliesW("Arial") gives the regular face first (elfFullName "Arial", weight 400).
 * - Both stay the same after the process realized "Arial" at weights 100 to 900, italic or not
 *   (also with underline and strikeout), and GDI+ GdipCreateFontFamilyFromName("Arial") keeps
 *   succeeding (GDI+ takes the family from the first EnumFontFamiliesW entry; GraphPad Prism 11
 *   checks for Arial this way and then reports "The Arial font ... is not installed").
 */

typedef struct
{
    int Count;
    struct
    {
        WCHAR FullName[LF_FULLFACESIZE];
        LONG Weight;
        BYTE Italic, Underline, StrikeOut, CharSet;
        DWORD FontType;
    } Entry[64];
} ENUM_RESULT;

static
int
CALLBACK
CollectProc(
    _In_ const LOGFONTW *LogFont,
    _In_ const TEXTMETRICW *TextMetric,
    _In_ DWORD FontType,
    _In_ LPARAM lParam)
{
    ENUM_RESULT *Result = (ENUM_RESULT *)lParam;
    const ENUMLOGFONTEXW *Elf = (const ENUMLOGFONTEXW *)LogFont;

    if (Result->Count < (int)ARRAYSIZE(Result->Entry))
    {
        StringCchCopyW(Result->Entry[Result->Count].FullName, LF_FULLFACESIZE, Elf->elfFullName);
        Result->Entry[Result->Count].Weight = LogFont->lfWeight;
        Result->Entry[Result->Count].Italic = LogFont->lfItalic;
        Result->Entry[Result->Count].Underline = LogFont->lfUnderline;
        Result->Entry[Result->Count].StrikeOut = LogFont->lfStrikeOut;
        Result->Entry[Result->Count].CharSet = LogFont->lfCharSet;
        Result->Entry[Result->Count].FontType = FontType;
    }
    Result->Count++;
    return 1;
}

static
void
EnumArial(
    _In_ HDC hdc,
    _In_ BOOL Ex,
    _Out_ ENUM_RESULT *Result)
{
    LOGFONTW lf;

    ZeroMemory(Result, sizeof(*Result));
    if (Ex)
    {
        ZeroMemory(&lf, sizeof(lf));
        lf.lfCharSet = ANSI_CHARSET;
        StringCchCopyW(lf.lfFaceName, ARRAYSIZE(lf.lfFaceName), L"Arial");
        EnumFontFamiliesExW(hdc, &lf, CollectProc, (LPARAM)Result, 0);
    }
    else
    {
        EnumFontFamiliesW(hdc, L"Arial", CollectProc, (LPARAM)Result);
    }
}

/* The ANSI_CHARSET entry of face FullName, or -1 */
static
int
FindFace(
    _In_ const ENUM_RESULT *Result,
    _In_ PCWSTR FullName)
{
    int i;

    for (i = 0; i < Result->Count && i < (int)ARRAYSIZE(Result->Entry); i++)
    {
        if (Result->Entry[i].CharSet == ANSI_CHARSET && !_wcsicmp(Result->Entry[i].FullName, FullName))
            return i;
    }
    return -1;
}

static
void
CheckFaces(
    _In_ HDC hdc,
    _In_ PCSTR When)
{
    static const struct { PCWSTR FullName; LONG Weight; BYTE Italic; } Faces[] =
    {
        { L"Arial", FW_NORMAL, 0 },
        { L"Arial Bold", FW_BOLD, 0 },
        { L"Arial Italic", FW_NORMAL, 0xFF },
        { L"Arial Bold Italic", FW_BOLD, 0xFF },
    };
    ENUM_RESULT Result;
    int i, j;

    EnumArial(hdc, TRUE, &Result);
    ok(Result.Count == 4, "%s: EnumFontFamiliesExW(Arial, ANSI_CHARSET) gave %d entries\n", When, Result.Count);
    for (i = 0; i < (int)ARRAYSIZE(Faces); i++)
    {
        j = FindFace(&Result, Faces[i].FullName);
        ok(j >= 0, "%s: no '%ls' entry\n", When, Faces[i].FullName);
        if (j < 0)
            continue;
        ok(Result.Entry[j].FontType & TRUETYPE_FONTTYPE, "%s: '%ls' type %lu\n", When, Faces[i].FullName, Result.Entry[j].FontType);
        ok(Result.Entry[j].Weight == Faces[i].Weight, "%s: '%ls' weight %ld\n", When, Faces[i].FullName, Result.Entry[j].Weight);
        ok(Result.Entry[j].Italic == Faces[i].Italic, "%s: '%ls' italic %u\n", When, Faces[i].FullName, Result.Entry[j].Italic);
        ok(!Result.Entry[j].Underline, "%s: '%ls' underline %u\n", When, Faces[i].FullName, Result.Entry[j].Underline);
        ok(!Result.Entry[j].StrikeOut, "%s: '%ls' strikeout %u\n", When, Faces[i].FullName, Result.Entry[j].StrikeOut);
    }

    EnumArial(hdc, FALSE, &Result);
    ok(Result.Count >= 4, "%s: EnumFontFamiliesW(Arial) gave %d entries\n", When, Result.Count);
    if (Result.Count > 0)
    {
        ok(!wcscmp(Result.Entry[0].FullName, L"Arial"), "%s: first EnumFontFamiliesW(Arial) entry is '%ls'\n",
           When, Result.Entry[0].FullName);
        ok(Result.Entry[0].Weight == FW_NORMAL && !Result.Entry[0].Italic,
           "%s: first EnumFontFamiliesW(Arial) entry weight %ld italic %u\n", When, Result.Entry[0].Weight, Result.Entry[0].Italic);
    }
}

typedef struct { UINT32 GdiplusVersion; PVOID DebugEventCallback; BOOL SuppressBackgroundThread, SuppressExternalCodecs; } GDIP_STARTUP_INPUT;

static
void
CheckGdiplus(
    _In_ PCSTR When)
{
    static HMODULE hGdiplus;
    static int (WINAPI *pGdipCreateFontFamilyFromName)(PCWSTR, PVOID, PVOID *);
    static int (WINAPI *pGdipCreateFont)(PVOID, float, int, int, PVOID *);
    static int (WINAPI *pGdipDeleteFont)(PVOID);
    static int (WINAPI *pGdipDeleteFontFamily)(PVOID);
    PVOID Family = NULL, Font = NULL;
    int Status;

    if (!hGdiplus)
    {
        int (WINAPI *pGdiplusStartup)(ULONG_PTR *, const GDIP_STARTUP_INPUT *, PVOID);
        GDIP_STARTUP_INPUT Input = { 1, NULL, FALSE, FALSE };
        ULONG_PTR Token;

        hGdiplus = LoadLibraryW(L"gdiplus.dll");
        if (!hGdiplus)
        {
            skip("no gdiplus.dll\n");
            return;
        }
        pGdiplusStartup = (PVOID)GetProcAddress(hGdiplus, "GdiplusStartup");
        pGdipCreateFontFamilyFromName = (PVOID)GetProcAddress(hGdiplus, "GdipCreateFontFamilyFromName");
        pGdipCreateFont = (PVOID)GetProcAddress(hGdiplus, "GdipCreateFont");
        pGdipDeleteFont = (PVOID)GetProcAddress(hGdiplus, "GdipDeleteFont");
        pGdipDeleteFontFamily = (PVOID)GetProcAddress(hGdiplus, "GdipDeleteFontFamily");
        if (!pGdiplusStartup || !pGdipCreateFontFamilyFromName || !pGdipCreateFont)
        {
            skip("gdiplus.dll lacks the font functions\n");
            hGdiplus = NULL;
            return;
        }
        pGdiplusStartup(&Token, &Input, NULL);
    }

    Status = pGdipCreateFontFamilyFromName(L"Arial", NULL, &Family);
    ok(Status == 0, "%s: GdipCreateFontFamilyFromName(Arial) = %d\n", When, Status);
    if (Status == 0)
    {
        Status = pGdipCreateFont(Family, 10.0f, 0 /* FontStyleRegular */, 3 /* UnitPoint */, &Font);
        ok(Status == 0, "%s: GdipCreateFont(Arial, 10pt) = %d\n", When, Status);
        if (Font)
            pGdipDeleteFont(Font);
        pGdipDeleteFontFamily(Family);
    }
}

START_TEST(EnumFontFamiliesArial)
{
    static const LONG Weights[] = { FW_THIN, FW_LIGHT, FW_NORMAL, FW_MEDIUM, FW_SEMIBOLD, FW_BOLD, FW_EXTRABOLD, FW_HEAVY };
    HDC hdc;
    HFONT hFont, hOld;
    LOGFONTW lf;
    int i, Style;

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    if (!hdc)
        return;

    CheckFaces(hdc, "at start");
    CheckGdiplus("at start");

    /* Realize "Arial" the ways an app does: other weights, italic, underline, strikeout */
    for (i = 0; i < (int)ARRAYSIZE(Weights); i++)
    {
        for (Style = 0; Style < 4; Style++)
        {
            ZeroMemory(&lf, sizeof(lf));
            lf.lfHeight = -16;
            lf.lfWeight = Weights[i];
            lf.lfItalic = (Style & 1) ? TRUE : FALSE;
            lf.lfUnderline = (Style == 2);
            lf.lfStrikeOut = (Style == 3);
            lf.lfCharSet = DEFAULT_CHARSET;
            StringCchCopyW(lf.lfFaceName, ARRAYSIZE(lf.lfFaceName), L"Arial");
            hFont = CreateFontIndirectW(&lf);
            ok(hFont != NULL, "CreateFontIndirectW failed\n");
            hOld = SelectObject(hdc, hFont);
            TextOutW(hdc, 0, 0, L"Arial", 5);
            SelectObject(hdc, hOld);
            DeleteObject(hFont);
        }
    }

    CheckFaces(hdc, "after realizing");
    CheckGdiplus("after realizing");

    DeleteDC(hdc);
}
