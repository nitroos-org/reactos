/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Robustness test: the font queries of a DC fail cleanly when its current font handle
 *              names nothing, and survive a font removed while another thread queries it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include "../gditools/gditools.h"

/*
 * Part 1: the current font handle of a DC is kept in its DC_ATTR, which the process can write. A handle
 * that names no font object (null, a stale handle, a handle of another object type, a value that was
 * never a handle) must make each query fail, not crash the system. The original handle is put back
 * before the DC is released.
 *
 * Part 2: threads query the font selected in their own DC while the main thread removes the font
 * resource and deletes the font. Whatever the queries return, nothing may crash or hang.
 */

#define NUM_THREADS     4
#define ROUNDS          1200   /* FNL_ROUNDS in the environment overrides */

typedef BOOL (WINAPI *PFN_GDIREALIZATIONINFO)(HDC, PVOID);

static PFN_GDIREALIZATIONINFO g_pfnRealizationInfo;
static UINT g_uMask;    /* which queries of the last RunQueries succeeded */

/* All the queries that realize the DC's current font; returns how many of them reported success */
static
UINT
RunQueries(HDC hdc)
{
    WCHAR wsz[LF_FACESIZE + 8];
    UINT cOk = 0;
    BYTE ab[1024];
    DWORD abRealization[8];
    TEXTMETRICW tm;
    KERNINGPAIR akp[16];
    DWORD dw;

    g_uMask = 0;
    SetLastError(0);
    if (GetTextFaceW(hdc, _countof(wsz), wsz) != 0) { cOk++; g_uMask |= 1u << 0; }
    if (GetTextFaceW(hdc, 0, NULL) != 0) { cOk++; g_uMask |= 1u << 1; }
    if (GetTextFaceW(hdc, 1, wsz) != 0) { cOk++; g_uMask |= 1u << 2; }
    if (g_pfnRealizationInfo && g_pfnRealizationInfo(hdc, abRealization)) { cOk++; g_uMask |= 1u << 3; }
    dw = GetFontUnicodeRanges(hdc, NULL);
    if (dw != 0) { cOk++; g_uMask |= 1u << 4; }
    dw = GetFontUnicodeRanges(hdc, (LPGLYPHSET)ab);
    if (dw != 0 && dw <= sizeof(ab)) { cOk++; g_uMask |= 1u << 5; }
    if (GetKerningPairsW(hdc, 0, NULL) != 0) { cOk++; g_uMask |= 1u << 6; }
    if (GetKerningPairsW(hdc, _countof(akp), akp) != 0) { cOk++; g_uMask |= 1u << 7; }
    if (GetOutlineTextMetricsW(hdc, 0, NULL) != 0) { cOk++; g_uMask |= 1u << 8; }
    if (GetTextMetricsW(hdc, &tm)) { cOk++; g_uMask |= 1u << 9; }
    if (GetTextCharsetInfo(hdc, NULL, 0) != DEFAULT_CHARSET) { cOk++; g_uMask |= 1u << 10; }
    if (GetFontData(hdc, 0, 0, NULL, 0) != GDI_ERROR) { cOk++; g_uMask |= 1u << 11; }
    return cOk;
}

static
void
Test_BadFontHandle(void)
{
    HDC hdc;
    HFONT hfont, hfontStale;
    HBITMAP hbmp;
    PDC_ATTR pdcattr;
    HANDLE hOriginal;
    UINT i, cOk;
    WCHAR wsz[LF_FACESIZE];
    DWORD abRealization[8];
    HANDLE ahBad[6];
    HGDIOBJ hOld;
    FONTSIGNATURE fs;

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    if (!hdc)
        return;
    pdcattr = GdiGetHandleUserData(hdc);
    if (!pdcattr)
    {
        skip("DC has no DC_ATTR\n");
        DeleteDC(hdc);
        return;
    }

    hfont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Arial");
    hOld = SelectObject(hdc, hfont);
    ok(hOld != NULL, "SelectObject failed\n");

    /* The DC works with its font first */
    SetLastError(0);
    ok(GetTextFaceW(hdc, _countof(wsz), wsz) > 0, "GetTextFaceW failed: %lu\n", GetLastError());

    hfontStale = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Arial");
    DeleteObject(hfontStale);
    hbmp = CreateBitmap(4, 4, 1, 1, NULL);

    ahBad[0] = NULL;
    ahBad[1] = (HANDLE)(ULONG_PTR)0xDEADBEEF;
    ahBad[2] = (HANDLE)(ULONG_PTR)1;
    ahBad[3] = (HANDLE)hfontStale;
    ahBad[4] = (HANDLE)hbmp;
    ahBad[5] = (HANDLE)hdc;     /* a DC handle, not a font */

    hOriginal = pdcattr->hlfntNew;
    ok(hOriginal == hfont, "hlfntNew is %p, expected %p\n", hOriginal, hfont);

    for (i = 0; i < _countof(ahBad); i++)
    {
        pdcattr->hlfntNew = ahBad[i];

        /* Each query must fail and report the error, with no output written beyond what it reports */
        SetLastError(0);
        ok(GetTextFaceW(hdc, _countof(wsz), wsz) == 0, "[%u] GetTextFaceW succeeded\n", i);
        ok(GetLastError() == ERROR_INVALID_HANDLE, "[%u] GetTextFaceW error %lu\n", i, GetLastError());
        ok(GetTextFaceW(hdc, 0, NULL) == 0, "[%u] GetTextFaceW(NULL) succeeded\n", i);
        ok(GetTextFaceW(hdc, 1, wsz) == 0, "[%u] GetTextFaceW(1) succeeded\n", i);

        if (g_pfnRealizationInfo)
        {
            SetLastError(0);
            ok(!g_pfnRealizationInfo(hdc, abRealization), "[%u] GdiRealizationInfo succeeded\n", i);
            ok(GetLastError() == ERROR_INVALID_HANDLE, "[%u] GdiRealizationInfo error %lu\n",
               i, GetLastError());
            ok(!g_pfnRealizationInfo(hdc, NULL), "[%u] GdiRealizationInfo(NULL) succeeded\n", i);
        }

        SetLastError(0);
        ok(GetFontUnicodeRanges(hdc, NULL) == 0, "[%u] GetFontUnicodeRanges succeeded\n", i);
        ok(GetLastError() == ERROR_INVALID_HANDLE, "[%u] GetFontUnicodeRanges error %lu\n",
           i, GetLastError());

        /* The signature is cleared, not left as the caller had it and not filled with stale data */
        memset(&fs, 0xA5, sizeof(fs));
        SetLastError(0);
        ok(GetTextCharsetInfo(hdc, &fs, 0) == DEFAULT_CHARSET, "[%u] GetTextCharsetInfo did not fail\n", i);
        ok(fs.fsCsb[0] == 0 && fs.fsCsb[1] == 0 && fs.fsUsb[0] == 0 && fs.fsUsb[3] == 0,
           "[%u] FONTSIGNATURE not cleared\n", i);

        cOk = RunQueries(hdc);
        ok(cOk == 0, "[%u] %u queries succeeded, mask 0x%x\n", i, cOk, g_uMask);
    }

    /* The failures are not sticky: the DC works again with its font handle back */
    pdcattr->hlfntNew = hOriginal;
    SetLastError(0);
    ok(GetTextFaceW(hdc, _countof(wsz), wsz) > 0, "GetTextFaceW failed after restore: %lu\n", GetLastError());
    ok(RunQueries(hdc) > 0, "No query succeeded after restore\n");

    SelectObject(hdc, hOld);
    DeleteObject(hfont);
    DeleteObject(hbmp);
    DeleteDC(hdc);
}

/* Part 2 */

static volatile LONG g_Round;       /* a new round is published by raising it */
static volatile LONG g_RoundOver;   /* the round of the main thread is done: workers leave their loop */
static volatile LONG g_Selected;    /* workers that have the font in their DC */
static volatile LONG g_Left;        /* workers that left the round */
static volatile LONG g_Quit;
static HFONT volatile g_hfont;
static HANDLE g_hThreads[NUM_THREADS];
static volatile LONG g_Queries;

static
DWORD
WINAPI
WorkerProc(PVOID pv)
{
    HDC hdc = CreateCompatibleDC(NULL);
    LONG lSeen = 0;
    WCHAR wsz[LF_FACESIZE];

    while (!g_Quit)
    {
        HGDIOBJ hOld;

        if (g_Round == lSeen)
        {
            Sleep(0);
            continue;
        }
        lSeen = g_Round;

        hOld = SelectObject(hdc, g_hfont);
        /* Realize the font before it can go away */
        GetTextFaceW(hdc, _countof(wsz), wsz);
        InterlockedIncrement(&g_Selected);

        while (!g_RoundOver)
        {
            RunQueries(hdc);
            InterlockedIncrement(&g_Queries);
        }

        SelectObject(hdc, hOld);
        InterlockedIncrement(&g_Left);
    }
    DeleteDC(hdc);
    return 0;
}

static
void
Test_RemoveWhileQuerying(void)
{
    HMODULE mod = GetModuleHandleW(NULL);
    HRSRC hRsrc = FindResourceA(mod, "PanosePitchTest.ttf", MAKEINTRESOURCE(RT_RCDATA));
    HGLOBAL hTemplate = hRsrc ? LoadResource(mod, hRsrc) : NULL;
    PVOID pFont = hTemplate ? LockResource(hTemplate) : NULL;
    DWORD dwSize = hRsrc ? SizeofResource(mod, hRsrc) : 0;
    UINT i, cRound, cRealized = 0, cRounds = ROUNDS;
    DWORD dw;
    DWORD dwStart;
    CHAR szEnv[16];

    if (GetEnvironmentVariableA("FNL_ROUNDS", szEnv, sizeof(szEnv)) > 0 && atoi(szEnv) > 0)
        cRounds = atoi(szEnv);

    if (!pFont)
    {
        skip("Font resource not found\n");
        return;
    }

    for (i = 0; i < NUM_THREADS; i++)
    {
        g_hThreads[i] = CreateThread(NULL, 0, WorkerProc, NULL, 0, NULL);
        ok(g_hThreads[i] != NULL, "CreateThread failed\n");
    }

    for (cRound = 0; cRound < cRounds; cRound++)
    {
        if (cRound % 100 == 0)
            trace("round %u\n", cRound);
        DWORD dwNum = 0;
        HANDLE hRes = AddFontMemResourceEx(pFont, dwSize, NULL, &dwNum);
        HFONT hfont;
        WCHAR wsz[LF_FACESIZE];
        HDC hdcMain;

        ok(hRes != NULL, "AddFontMemResourceEx failed\n");
        if (!hRes)
            break;

        hfont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                            CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"PanosePitchTest");
        hdcMain = CreateCompatibleDC(NULL);
        SelectObject(hdcMain, hfont);
        if (GetTextFaceW(hdcMain, _countof(wsz), wsz) > 0 && !_wcsicmp(wsz, L"PanosePitchTest"))
            cRealized++;
        DeleteDC(hdcMain);

        g_Selected = 0;
        g_Left = 0;
        g_RoundOver = 0;
        g_hfont = hfont;
        InterlockedIncrement(&g_Round);

        dwStart = GetTickCount();
        while (g_Selected < NUM_THREADS && GetTickCount() - dwStart < 20000)
            Sleep(0);
        ok(g_Selected == NUM_THREADS, "Workers did not pick up the font (%ld)\n", g_Selected);

        /* Vary the point of removal against the queries */
        for (i = 0; i < (cRound % 7) * 3; i++)
            Sleep(0);

        if (cRound & 1)
        {
            RemoveFontMemResourceEx(hRes);
            DeleteObject(hfont);
        }
        else
        {
            DeleteObject(hfont);
            RemoveFontMemResourceEx(hRes);
        }

        for (i = 0; i < (cRound % 5) * 2; i++)
            Sleep(0);

        g_RoundOver = 1;
        dwStart = GetTickCount();
        while (g_Left < NUM_THREADS && GetTickCount() - dwStart < 20000)
            Sleep(0);
        ok(g_Left == NUM_THREADS, "Workers did not leave the round (%ld)\n", g_Left);
        if (g_Left != NUM_THREADS)
            break;
    }

    g_Quit = 1;
    dw = WaitForMultipleObjects(NUM_THREADS, g_hThreads, TRUE, 20000);
    ok(dw == WAIT_OBJECT_0, "Workers did not finish: %lu\n", dw);
    for (i = 0; i < NUM_THREADS; i++)
        CloseHandle(g_hThreads[i]);

    trace("%u rounds, %u of them with the test font realized, %ld query batches\n",
          cRound, cRealized, g_Queries);
    ok(cRound == cRounds, "Only %u rounds ran\n", cRound);
}

START_TEST(FontNullLifetime)
{
    HMODULE hGdi32 = GetModuleHandleW(L"gdi32.dll");

    g_pfnRealizationInfo = (PFN_GDIREALIZATIONINFO)GetProcAddress(hGdi32, "GdiRealizationInfo");

    Test_BadFontHandle();
    Test_RemoveWhileQuerying();
}
