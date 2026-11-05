/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Stress test: threads that use fonts of one face at different sizes get the metrics,
 *              extents and glyph images of their own size, as a single thread does
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * A face has one current size, shared by every DC that realizes a font of it. Each thread here selects
 * its own size of the same face and repeats GetTextMetrics, GetOutlineTextMetrics, GetTextExtentPoint32,
 * GetGlyphOutline (metrics, bitmap, gray bitmaps, native, bezier), GetKerningPairs and ExtTextOut.
 * Every result must equal the one a single thread got for that size before the threads started.
 */

#define NUM_THREADS   8
#define ITERATIONS    180
#define TEXT_W        200
#define TEXT_H        64

static const WCHAR g_Text[] = L"Hamburgefonstiv AVATAR To 0123456789";

typedef struct
{
    LONG Height;
    LONG Width;
    TEXTMETRICW Tm;
    BYTE OtmBuf[sizeof(OUTLINETEXTMETRICW) + 512];
    UINT OtmFixed;
    SIZE Extent;
    GLYPHMETRICS Gm;
    DWORD KernCount;
    KERNINGPAIR *Kern;
    DWORD InkHash;
    LONG InkPixels;
    DWORD GgoBitmap;    /* GGO_BITMAP and the gray bitmaps: results, metrics and bytes */
    DWORD GgoNative;    /* GGO_NATIVE and GGO_BEZIER */
} REFERENCE;

typedef struct
{
    PCWSTR Face;
    REFERENCE Ref;
    HANDLE hThread;
    LONG Bad;       /* operations that gave other than the reference */
    LONG BadTm, BadOtm, BadExt, BadGgo, BadKern, BadInk, BadBitmap, BadNative;
} WORKER;

static HANDLE g_hStart;
static LONG g_Failed;

/* All the kerning pairs of the selected font (every neighbouring pair of characters is listed) */
static DWORD GetKern(HDC hdc, KERNINGPAIR **ppKern)
{
    DWORD n = GetKerningPairsW(hdc, 0, NULL), got;

    *ppKern = NULL;
    if (!n)
        return 0;
    *ppKern = HeapAlloc(GetProcessHeap(), 0, n * sizeof(KERNINGPAIR));
    if (!*ppKern)
        return 0;
    got = GetKerningPairsW(hdc, n, *ppKern);
    return got == n ? n : 0;
}

static DWORD HashBytes(DWORD h, const void *p, SIZE_T n)
{
    const BYTE *b = p;
    while (n--)
        h = (h ^ *b++) * 16777619u;
    return h;
}

/* Everything GetGlyphOutline gives for a few glyphs in a format: return values, metrics and buffer bytes */
static DWORD GgoHash(HDC hdc, UINT Format, BOOL UseMat)
{
    static const WCHAR Glyphs[] = L"Agm%&e";
    MAT2 mat = { {0, 1}, {0, 0}, {0, 0}, {0, 1} };
    DWORD h = 2166136261u;
    UINT i;

    for (i = 0; Glyphs[i]; i++)
    {
        GLYPHMETRICS gm;
        DWORD Size, Ret;
        PVOID Buf;

        ZeroMemory(&gm, sizeof(gm));
        Size = GetGlyphOutlineW(hdc, Glyphs[i], Format, &gm, 0, NULL, UseMat ? &mat : NULL);
        h = HashBytes(h, &Size, sizeof(Size));
        h = HashBytes(h, &gm, sizeof(gm));
        if (Size == GDI_ERROR || Size == 0)
            continue;
        Buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        if (!Buf)
            continue;
        ZeroMemory(&gm, sizeof(gm));
        Ret = GetGlyphOutlineW(hdc, Glyphs[i], Format, &gm, Size, Buf, UseMat ? &mat : NULL);
        h = HashBytes(h, &Ret, sizeof(Ret));
        h = HashBytes(h, &gm, sizeof(gm));
        if (Ret != GDI_ERROR)
            h = HashBytes(h, Buf, min(Ret, Size));
        HeapFree(GetProcessHeap(), 0, Buf);
    }
    return h;
}

static DWORD BitmapGgoHash(HDC hdc)
{
    DWORD h = GgoHash(hdc, GGO_BITMAP, FALSE);
    h = h * 31 + GgoHash(hdc, GGO_BITMAP, TRUE);
    h = h * 31 + GgoHash(hdc, GGO_GRAY2_BITMAP, TRUE);
    h = h * 31 + GgoHash(hdc, GGO_GRAY4_BITMAP, FALSE);
    h = h * 31 + GgoHash(hdc, GGO_GRAY8_BITMAP, TRUE);
    return h;
}

static DWORD NativeGgoHash(HDC hdc)
{
    DWORD h = GgoHash(hdc, GGO_NATIVE, TRUE);
    h = h * 31 + GgoHash(hdc, GGO_BEZIER, TRUE);
    return h;
}

static HFONT MakeFont(PCWSTR Face, LONG Height, LONG Width)
{
    LOGFONTW lf;
    ZeroMemory(&lf, sizeof(lf));
    lf.lfHeight = Height;
    lf.lfWidth = Width;
    lf.lfWeight = FW_NORMAL;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = ANTIALIASED_QUALITY;
    StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), Face);
    return CreateFontIndirectW(&lf);
}

typedef struct
{
    HDC hdc;
    HBITMAP hbm;
    HGDIOBJ hOldBm;
    DWORD *Bits;
} CANVAS;

static BOOL CanvasInit(CANVAS *c)
{
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = TEXT_W;
    bmi.bmiHeader.biHeight = -TEXT_H;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    c->hdc = CreateCompatibleDC(NULL);
    if (!c->hdc)
        return FALSE;
    c->hbm = CreateDIBSection(c->hdc, &bmi, DIB_RGB_COLORS, (PVOID*)&c->Bits, NULL, 0);
    if (!c->hbm)
    {
        DeleteDC(c->hdc);
        return FALSE;
    }
    c->hOldBm = SelectObject(c->hdc, c->hbm);
    return TRUE;
}

static void CanvasFree(CANVAS *c)
{
    SelectObject(c->hdc, c->hOldBm);
    DeleteObject(c->hbm);
    DeleteDC(c->hdc);
}

static void Ink(CANVAS *c, DWORD *pHash, LONG *pPixels)
{
    DWORD h = 2166136261u;
    LONG n = 0;
    UINT i;
    GdiFlush();
    for (i = 0; i < TEXT_W * TEXT_H; i++)
    {
        h = (h ^ (c->Bits[i] & 0xFFFFFF)) * 16777619u;
        n += (c->Bits[i] & 0xFFFFFF) != 0xFFFFFF;
    }
    *pHash = h;
    *pPixels = n;
}

static void DrawText1(CANVAS *c, LONG Height)
{
    RECT rc = { 0, 0, TEXT_W, TEXT_H };
    FillRect(c->hdc, &rc, GetStockObject(WHITE_BRUSH));
    SetBkMode(c->hdc, TRANSPARENT);
    SetTextColor(c->hdc, RGB(0, 0, 0));
    SetTextAlign(c->hdc, TA_LEFT | TA_TOP);
    ExtTextOutW(c->hdc, 2, 2 + (Height < 0 ? 0 : 0), 0, NULL, g_Text, lstrlenW(g_Text), NULL);
}

/* One measurement of everything; Ref is filled by the first (single-threaded) pass */
static void Measure(HDC hdc, CANVAS *c, LONG Height, REFERENCE *Out)
{
    OUTLINETEXTMETRICW *otm = (OUTLINETEXTMETRICW *)Out->OtmBuf;
    MAT2 mat = { {0, 1}, {0, 0}, {0, 0}, {0, 1} };

    ZeroMemory(Out, sizeof(*Out));
    Out->Height = Height;
    GetTextMetricsW(hdc, &Out->Tm);
    otm->otmSize = sizeof(Out->OtmBuf);
    GetOutlineTextMetricsW(hdc, sizeof(Out->OtmBuf), otm);
    Out->OtmFixed = FIELD_OFFSET(OUTLINETEXTMETRICW, otmpFamilyName);
    GetTextExtentPoint32W(hdc, g_Text, lstrlenW(g_Text), &Out->Extent);
    GetGlyphOutlineW(hdc, 'A', GGO_METRICS, &Out->Gm, 0, NULL, &mat);
    Out->KernCount = GetKern(hdc, &Out->Kern);
    DrawText1(c, Height);
    Ink(c, &Out->InkHash, &Out->InkPixels);
    Out->GgoBitmap = BitmapGgoHash(hdc);
    Out->GgoNative = NativeGgoHash(hdc);
}

static DWORD WINAPI Worker(PVOID Param)
{
    WORKER *w = Param;
    CANVAS c;
    HDC hdc;
    HFONT hFont, hOld;
    REFERENCE Cur;
    UINT i;
    OUTLINETEXTMETRICW *otmRef = (OUTLINETEXTMETRICW *)w->Ref.OtmBuf;
    OUTLINETEXTMETRICW *otmCur = (OUTLINETEXTMETRICW *)Cur.OtmBuf;

    hdc = CreateCompatibleDC(NULL);
    hFont = MakeFont(w->Face, w->Ref.Height, w->Ref.Width);
    hOld = SelectObject(hdc, hFont);
    if (!CanvasInit(&c))
    {
        InterlockedIncrement(&g_Failed);
        return 1;
    }
    SelectObject(c.hdc, hFont);

    WaitForSingleObject(g_hStart, INFINITE);

    for (i = 0; i < ITERATIONS; i++)
    {
        BOOL Bad = FALSE;
        MAT2 mat = { {0, 1}, {0, 0}, {0, 0}, {0, 1} };
        TEXTMETRICW tm;
        SIZE ext;
        GLYPHMETRICS gm;
        KERNINGPAIR *kern;
        DWORD n;

        /* Rotate through the calls, each run alone as well as in combination, so that different
         * calls of different threads meet */
        switch (i % 6)
        {
            case 0:
                GetTextMetricsW(hdc, &tm);
                if (memcmp(&tm, &w->Ref.Tm, sizeof(tm)))
                    { InterlockedIncrement(&w->BadTm); Bad = TRUE; }
                break;
            case 1:
                ZeroMemory(&Cur, sizeof(Cur));
                otmCur->otmSize = sizeof(Cur.OtmBuf);
                GetOutlineTextMetricsW(hdc, sizeof(Cur.OtmBuf), otmCur);
                if (memcmp(otmCur, otmRef, w->Ref.OtmFixed))
                    { InterlockedIncrement(&w->BadOtm); Bad = TRUE; }
                break;
            case 2:
                GetTextExtentPoint32W(hdc, g_Text, lstrlenW(g_Text), &ext);
                if (ext.cx != w->Ref.Extent.cx || ext.cy != w->Ref.Extent.cy)
                    { InterlockedIncrement(&w->BadExt); Bad = TRUE; }
                GetGlyphOutlineW(hdc, 'A', GGO_METRICS, &gm, 0, NULL, &mat);
                if (memcmp(&gm, &w->Ref.Gm, sizeof(gm)))
                    { InterlockedIncrement(&w->BadGgo); Bad = TRUE; }
                break;
            case 3:
                n = GetKern(hdc, &kern);
                if (n != w->Ref.KernCount || (n && memcmp(kern, w->Ref.Kern, n * sizeof(kern[0]))))
                    { InterlockedIncrement(&w->BadKern); Bad = TRUE; }
                HeapFree(GetProcessHeap(), 0, kern);
                {
                    DWORD Hash;
                    LONG Pixels;
                    DrawText1(&c, w->Ref.Height);
                    Ink(&c, &Hash, &Pixels);
                    if (Hash != w->Ref.InkHash || Pixels != w->Ref.InkPixels)
                        { InterlockedIncrement(&w->BadInk); Bad = TRUE; }
                }
                break;
            case 4:
                if (BitmapGgoHash(hdc) != w->Ref.GgoBitmap)
                    { InterlockedIncrement(&w->BadBitmap); Bad = TRUE; }
                break;
            case 5:
                if (NativeGgoHash(hdc) != w->Ref.GgoNative)
                    { InterlockedIncrement(&w->BadNative); Bad = TRUE; }
                break;
        }
        if (Bad)
            InterlockedIncrement(&w->Bad);
    }

    CanvasFree(&c);
    SelectObject(hdc, hOld);
    DeleteObject(hFont);
    DeleteDC(hdc);
    return 0;
}

static BOOL HasFace(PCWSTR Face)
{
    HDC hdc = CreateCompatibleDC(NULL);
    HFONT hFont = MakeFont(Face, -16, 0);
    HGDIOBJ hOld = SelectObject(hdc, hFont);
    WCHAR Name[LF_FACESIZE] = L"";
    GetTextFaceW(hdc, _countof(Name), Name);
    SelectObject(hdc, hOld);
    DeleteObject(hFont);
    DeleteDC(hdc);
    return !_wcsicmp(Name, Face);
}

static void RunFace(PCWSTR Face)
{
    static WORKER Workers[NUM_THREADS];
    static const LONG Heights[NUM_THREADS] = { -11, -14, -17, -21, -26, -32, -19, -23 };
    CANVAS c;
    HDC hdc;
    UINT i, j;
    LONG TotalBad = 0;
    DWORD id, Wait;

    ZeroMemory(Workers, sizeof(Workers));
    g_Failed = 0;
    if (!CanvasInit(&c))
    {
        skip("no canvas\n");
        return;
    }
    hdc = CreateCompatibleDC(NULL);

    /* The references: one thread, one size at a time */
    for (i = 0; i < NUM_THREADS; i++)
    {
        HFONT hFont, hOld;
        Workers[i].Face = Face;
        Workers[i].Ref.Height = Heights[i];
        Workers[i].Ref.Width = (i == 3) ? 9 : 0;   /* one has a width request as well */
        hFont = MakeFont(Face, Heights[i], Workers[i].Ref.Width);
        hOld = SelectObject(hdc, hFont);
        SelectObject(c.hdc, hFont);
        Measure(hdc, &c, Heights[i], &Workers[i].Ref);
        Workers[i].Ref.Width = (i == 3) ? 9 : 0;
        SelectObject(c.hdc, GetStockObject(SYSTEM_FONT));
        SelectObject(hdc, hOld);
        DeleteObject(hFont);
    }
    /* Sanity: the sizes really differ, so a mix-up would show */
    for (i = 0; i < NUM_THREADS; i++)
        for (j = i + 1; j < NUM_THREADS; j++)
            if (Workers[i].Ref.Height != Workers[j].Ref.Height)
                ok(Workers[i].Ref.Tm.tmHeight != Workers[j].Ref.Tm.tmHeight ||
                   Workers[i].Ref.Extent.cx != Workers[j].Ref.Extent.cx,
                   "%ls: sizes %ld and %ld measure alike\n", Face, Workers[i].Ref.Height, Workers[j].Ref.Height);

    g_hStart = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < NUM_THREADS; i++)
        Workers[i].hThread = CreateThread(NULL, 0, Worker, &Workers[i], 0, &id);
    Sleep(100);
    SetEvent(g_hStart);
    for (i = 0; i < NUM_THREADS; i++)
    {
        Wait = WaitForSingleObject(Workers[i].hThread, 240000);
        ok(Wait == WAIT_OBJECT_0, "thread %u did not finish\n", i);
        CloseHandle(Workers[i].hThread);
    }
    CloseHandle(g_hStart);

    for (i = 0; i < NUM_THREADS; i++)
    {
        ok(Workers[i].BadTm == 0, "%ls %ld: %ld GetTextMetrics results differ from single-thread\n",
           Face, Workers[i].Ref.Height, Workers[i].BadTm);
        ok(Workers[i].BadOtm == 0, "%ls %ld: %ld GetOutlineTextMetrics results differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadOtm);
        ok(Workers[i].BadExt == 0, "%ls %ld: %ld GetTextExtentPoint32 results differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadExt);
        ok(Workers[i].BadGgo == 0, "%ls %ld: %ld GetGlyphOutline results differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadGgo);
        ok(Workers[i].BadKern == 0, "%ls %ld: %ld GetKerningPairs results differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadKern);
        ok(Workers[i].BadInk == 0, "%ls %ld: %ld ExtTextOut images differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadInk);
        ok(Workers[i].BadBitmap == 0, "%ls %ld: %ld GetGlyphOutline bitmap/gray results differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadBitmap);
        ok(Workers[i].BadNative == 0, "%ls %ld: %ld GetGlyphOutline native/bezier results differ\n",
           Face, Workers[i].Ref.Height, Workers[i].BadNative);
        TotalBad += Workers[i].Bad;
    }
    trace("%ls: %ld of %d operations differed\n", Face, TotalBad, NUM_THREADS * ITERATIONS);
    ok(g_Failed == 0, "a worker could not set up\n");

    for (i = 0; i < NUM_THREADS; i++)
        HeapFree(GetProcessHeap(), 0, Workers[i].Ref.Kern);
    DeleteDC(hdc);
    CanvasFree(&c);
}

/* A kerning query must report the size of the font it is made for, not the last size used */
static void test_KerningSize(PCWSTR Face)
{
    HDC hdc = CreateCompatibleDC(NULL);
    HFONT hSmall = MakeFont(Face, -12, 0), hBig = MakeFont(Face, -48, 0), hOld;
    KERNINGPAIR *ks, *kb, *ks2;
    DWORD ns, nb, ns2, i;
    int Smaller = 0;

    hOld = SelectObject(hdc, hSmall);
    ns = GetKern(hdc, &ks);
    SelectObject(hdc, hBig);
    nb = GetKern(hdc, &kb);
    SelectObject(hdc, hSmall);
    ns2 = GetKern(hdc, &ks2);   /* after the big one used the face last */
    ok(ns2 == ns && (!ns || !memcmp(ks2, ks, ns * sizeof(ks[0]))),
       "%ls: kerning of the small font changed after a big one\n", Face);
    if (ns && nb == ns)
    {
        for (i = 0; i < ns; i++)
            if (abs(kb[i].iKernAmount) < abs(ks[i].iKernAmount))
                Smaller++;
        ok(Smaller == 0, "%ls: %d kerning amounts shrank from 12 to 48 pixels\n", Face, Smaller);
    }
    HeapFree(GetProcessHeap(), 0, ks);
    HeapFree(GetProcessHeap(), 0, kb);
    HeapFree(GetProcessHeap(), 0, ks2);
    SelectObject(hdc, hOld);
    DeleteObject(hSmall);
    DeleteObject(hBig);
    DeleteDC(hdc);
}

START_TEST(FontSizeRace)
{
    if (!HasFace(L"Arial"))
    {
        skip("Arial is not installed\n");
        return;
    }
    test_KerningSize(L"Arial");
    RunFace(L"Arial");
    if (HasFace(L"Tahoma"))
        RunFace(L"Tahoma");
}
