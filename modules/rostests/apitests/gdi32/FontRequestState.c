/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a realized font reports its own request (weight, italic, underline,
 *              strike-out, simulations), not the last request realized with the same face
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Expected values measured on Windows 10 22H2 (64-bit), 2026-11-04:
 * - A real face reports its own weight: Arial at 100-500 gives the regular face, weight 400;
 *   600-900 the Bold face, weight 700. An italic request gives the Arial Italic face (fsSelection
 *   bit 0) at every weight.
 * - Emulated bold (Lucida Console, which has one regular face, at 600-900) reports weight 700
 *   (FW_BOLD), tmAveCharWidth and tmMaxCharWidth one pixel wider, fsSelection 0x20 instead of
 *   0x40; emulated italic reports tmItalic 0xFF and fsSelection 0x01.
 * - tmItalic/tmUnderlined/tmStruckOut are 0 or 0xFF and come from the request; underline and
 *   strike-out set no fsSelection bit.
 * - Two DCs with the same face at different requests each report their own, in any order.
 * - An underlined font draws a line below the baseline as wide as the text, with GDI and with
 *   GDI+ GdipDrawString (WinForms labels draw with GDI+ by default).
 * - GDI+ GdipCreateFont keeps the requested style (GdipGetFontStyle), e.g. Bold stays Bold and
 *   does not pick up italic from an earlier request.
 */

typedef struct
{
    LONG Weight;
    BYTE Italic, Underlined, StruckOut;
    LONG AveCharWidth, MaxCharWidth;
    UINT fsSelection;
    LONG otmWeight;
    BYTE otmItalic, otmUnderlined, otmStruckOut;
} STYLE;

static HFONT MakeFont(PCWSTR Face, LONG Weight, BYTE Italic, BYTE Underline, BYTE StrikeOut)
{
    LOGFONTW lf;
    ZeroMemory(&lf, sizeof(lf));
    lf.lfHeight = -20;
    lf.lfWeight = Weight;
    lf.lfItalic = Italic;
    lf.lfUnderline = Underline;
    lf.lfStrikeOut = StrikeOut;
    lf.lfCharSet = DEFAULT_CHARSET;
    StringCchCopyW(lf.lfFaceName, _countof(lf.lfFaceName), Face);
    return CreateFontIndirectW(&lf);
}

static BOOL GetStyle(HDC hdc, STYLE *s)
{
    TEXTMETRICW tm;
    OUTLINETEXTMETRICW otm;

    ZeroMemory(s, sizeof(*s));
    if (!GetTextMetricsW(hdc, &tm))
        return FALSE;
    otm.otmSize = sizeof(otm);
    if (!GetOutlineTextMetricsW(hdc, sizeof(otm), &otm))
        return FALSE;
    s->Weight = tm.tmWeight;
    s->Italic = tm.tmItalic;
    s->Underlined = tm.tmUnderlined;
    s->StruckOut = tm.tmStruckOut;
    s->AveCharWidth = tm.tmAveCharWidth;
    s->MaxCharWidth = tm.tmMaxCharWidth;
    s->fsSelection = otm.otmfsSelection & 0x7F;
    s->otmWeight = otm.otmTextMetrics.tmWeight;
    s->otmItalic = otm.otmTextMetrics.tmItalic;
    s->otmUnderlined = otm.otmTextMetrics.tmUnderlined;
    s->otmStruckOut = otm.otmTextMetrics.tmStruckOut;
    return TRUE;
}

#define ok_style(s, w, it, ul, so, fs, what) \
    do { \
        ok((s)->Weight == (w), "%s: tmWeight %ld, expected %d\n", what, (s)->Weight, w); \
        ok((s)->Italic == (it), "%s: tmItalic %u, expected %u\n", what, (s)->Italic, it); \
        ok((s)->Underlined == (ul), "%s: tmUnderlined %u, expected %u\n", what, (s)->Underlined, ul); \
        ok((s)->StruckOut == (so), "%s: tmStruckOut %u, expected %u\n", what, (s)->StruckOut, so); \
        ok((s)->fsSelection == (fs), "%s: otmfsSelection 0x%x, expected 0x%x\n", what, (s)->fsSelection, fs); \
        ok((s)->otmWeight == (s)->Weight && (s)->otmItalic == (s)->Italic && \
           (s)->otmUnderlined == (s)->Underlined && (s)->otmStruckOut == (s)->StruckOut, \
           "%s: OUTLINETEXTMETRIC %ld/%u/%u/%u differs from TEXTMETRIC\n", what, \
           (s)->otmWeight, (s)->otmItalic, (s)->otmUnderlined, (s)->otmStruckOut); \
    } while (0)

static BOOL StyleOf(PCWSTR Face, LONG Weight, BYTE Italic, BYTE Underline, BYTE StrikeOut, STYLE *s)
{
    HDC hdc = CreateCompatibleDC(NULL);
    HFONT hFont = MakeFont(Face, Weight, Italic, Underline, StrikeOut);
    HGDIOBJ hOld = SelectObject(hdc, hFont);
    BOOL Ret = GetStyle(hdc, s);
    SelectObject(hdc, hOld);
    DeleteObject(hFont);
    DeleteDC(hdc);
    return Ret;
}

static BOOL HasFace(PCWSTR Face)
{
    HDC hdc = CreateCompatibleDC(NULL);
    HFONT hFont = MakeFont(Face, FW_NORMAL, FALSE, FALSE, FALSE);
    HGDIOBJ hOld = SelectObject(hdc, hFont);
    WCHAR Name[LF_FACESIZE] = L"";
    GetTextFaceW(hdc, _countof(Name), Name);
    SelectObject(hdc, hOld);
    DeleteObject(hFont);
    DeleteDC(hdc);
    return !_wcsicmp(Name, Face);
}

/* Realize the faces with many requests first: these used to leak into every later realization */
static void Pollute(void)
{
    static PCWSTR Faces[] = { L"Arial", L"Lucida Console", L"Tahoma" };
    STYLE s;
    UINT i, w, it;

    for (i = 0; i < _countof(Faces); i++)
        for (w = 100; w <= 900; w += 100)
            for (it = 0; it < 2; it++)
                StyleOf(Faces[i], w, (BYTE)it, (BYTE)it, (BYTE)!it, &s);
}

static void Test_Weights(void)
{
    STYLE s;
    char what[64];
    LONG w;

    for (w = 100; w <= 900; w += 100)
    {
        BOOL Bold = (w >= 600);

        sprintf(what, "Arial %ld", w);
        ok(StyleOf(L"Arial", w, FALSE, FALSE, FALSE, &s), "%s: no metrics\n", what);
        ok_style(&s, Bold ? 700 : 400, 0, 0, 0, Bold ? 0x20 : 0x40, what);

        sprintf(what, "Arial %ld italic", w);
        ok(StyleOf(L"Arial", w, TRUE, FALSE, FALSE, &s), "%s: no metrics\n", what);
        ok_style(&s, Bold ? 700 : 400, 0xFF, 0, 0, Bold ? 0x21 : 0x01, what);
    }
}

static void Test_EmulatedBold(void)
{
    STYLE Regular, s;
    char what[64];
    LONG w;

    if (!HasFace(L"Lucida Console"))
    {
        skip("Lucida Console not installed\n");
        return;
    }
    ok(StyleOf(L"Lucida Console", FW_NORMAL, FALSE, FALSE, FALSE, &Regular), "no metrics\n");
    ok_style(&Regular, 400, 0, 0, 0, 0x40, "Lucida Console 400");

    for (w = 100; w <= 900; w += 100)
    {
        BOOL Emu = (w >= 600);

        sprintf(what, "Lucida Console %ld", w);
        ok(StyleOf(L"Lucida Console", w, FALSE, FALSE, FALSE, &s), "%s: no metrics\n", what);
        ok_style(&s, Emu ? 700 : 400, 0, 0, 0, Emu ? 0x20 : 0x40, what);
        ok(s.AveCharWidth == Regular.AveCharWidth + (Emu ? 1 : 0),
           "%s: tmAveCharWidth %ld, regular %ld\n", what, s.AveCharWidth, Regular.AveCharWidth);
        ok(s.MaxCharWidth == Regular.MaxCharWidth + (Emu ? 1 : 0),
           "%s: tmMaxCharWidth %ld, regular %ld\n", what, s.MaxCharWidth, Regular.MaxCharWidth);

        sprintf(what, "Lucida Console %ld italic", w);
        ok(StyleOf(L"Lucida Console", w, TRUE, FALSE, FALSE, &s), "%s: no metrics\n", what);
        ok_style(&s, Emu ? 700 : 400, 0xFF, 0, 0, Emu ? 0x21 : 0x01, what);
    }
}

static void TwoDCs(PCWSTR Face, LONG wA, BYTE itA, LONG wB, BYTE itB,
                   LONG ExpWeightB, BYTE ExpItalicB, UINT ExpFsB)
{
    HDC a = CreateCompatibleDC(NULL), b = CreateCompatibleDC(NULL);
    HFONT fa = MakeFont(Face, wA, itA, FALSE, FALSE);
    HFONT fb = MakeFont(Face, wB, itB, TRUE, TRUE);
    HGDIOBJ oa = SelectObject(a, fa), ob = SelectObject(b, fb);
    STYLE s;
    char what[80];

    sprintf(what, "%ls DC A first", Face);
    ok(GetStyle(a, &s), "%s: no metrics\n", what);
    ok_style(&s, 400, 0, 0, 0, 0x40, what);

    sprintf(what, "%ls DC B", Face);
    ok(GetStyle(b, &s), "%s: no metrics\n", what);
    ok_style(&s, ExpWeightB, ExpItalicB, 0xFF, 0xFF, ExpFsB, what);

    sprintf(what, "%ls DC A after B", Face);
    ok(GetStyle(a, &s), "%s: no metrics\n", what);
    ok_style(&s, 400, 0, 0, 0, 0x40, what);

    sprintf(what, "%ls DC B after A", Face);
    ok(GetStyle(b, &s), "%s: no metrics\n", what);
    ok_style(&s, ExpWeightB, ExpItalicB, 0xFF, 0xFF, ExpFsB, what);

    SelectObject(a, oa);
    SelectObject(b, ob);
    DeleteObject(fa);
    DeleteObject(fb);
    DeleteDC(a);
    DeleteDC(b);
}

static void Test_TwoDCs(void)
{
    /* Arial 500 is the regular face (400) */
    TwoDCs(L"Arial", 400, FALSE, 500, FALSE, 400, 0, 0x40);
    if (HasFace(L"Lucida Console"))
        TwoDCs(L"Lucida Console", 400, FALSE, 700, TRUE, 700, 0xFF, 0x21);
    /* Tahoma has a Bold face but no italic one: italic is emulated */
    if (HasFace(L"Tahoma"))
        TwoDCs(L"Tahoma", 400, FALSE, 400, TRUE, 400, 0xFF, 0x01);
}

/* "aaaa" has no descender: an underline is the only ink below the baseline */
static void Underline(PCWSTR Face, BOOL Underline, BOOL StrikeOut)
{
    enum { W = 300, H = 80, X = 10, Y = 10 };
    BITMAPINFO bi;
    PDWORD Bits;
    HDC hdc = CreateCompatibleDC(NULL);
    HBITMAP hbm;
    HGDIOBJ hOldBm, hOldFont;
    HFONT hFont;
    TEXTMETRICW tm;
    SIZE Size;
    int x, y, Below = 0, Band = 0;

    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = W;
    bi.bmiHeader.biHeight = -H;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    hbm = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, (PVOID *)&Bits, NULL, 0);
    ok(hbm != NULL, "CreateDIBSection failed\n");
    if (!hbm)
    {
        DeleteDC(hdc);
        return;
    }
    hOldBm = SelectObject(hdc, hbm);
    PatBlt(hdc, 0, 0, W, H, WHITENESS);
    hFont = MakeFont(Face, FW_NORMAL, FALSE, (BYTE)Underline, (BYTE)StrikeOut);
    hOldFont = SelectObject(hdc, hFont);
    GetTextMetricsW(hdc, &tm);
    SetTextColor(hdc, RGB(0, 0, 0));
    SetBkMode(hdc, TRANSPARENT);
    TextOutW(hdc, X, Y, L"aaaa", 4);
    GetTextExtentPoint32W(hdc, L"aaaa", 4, &Size);
    GdiFlush();

    for (y = Y + tm.tmAscent + 1; y < Y + tm.tmHeight + 2 && y < H; y++)
    {
        int n = 0;
        for (x = 0; x < W; x++)
            if ((Bits[y * W + x] & 0xFFFFFF) == 0)
                n++;
        Below = max(Below, n);
    }
    for (y = Y + tm.tmAscent / 2; y < Y + tm.tmAscent; y++)
    {
        int n = 0;
        for (x = 0; x < W; x++)
            if ((Bits[y * W + x] & 0xFFFFFF) == 0)
                n++;
        Band = max(Band, n);
    }

    if (Underline)
        ok(Below >= Size.cx * 8 / 10, "%ls underline: widest dark row below the baseline %d, text %ld\n", Face, Below, Size.cx);
    else
        ok(Below == 0, "%ls: %d dark pixels in a row below the baseline without underline\n", Face, Below);
    if (StrikeOut)
        ok(Band >= Size.cx * 9 / 10, "%ls strike-out: widest dark row %d, text %ld\n", Face, Band, Size.cx);
    else
        ok(Band < Size.cx * 9 / 10, "%ls: a full-width row (%d of %ld) without strike-out\n", Face, Band, Size.cx);

    SelectObject(hdc, hOldFont);
    DeleteObject(hFont);
    SelectObject(hdc, hOldBm);
    DeleteObject(hbm);
    DeleteDC(hdc);
}

static void Test_Underline(void)
{
    Underline(L"Arial", FALSE, FALSE);
    Underline(L"Arial", TRUE, FALSE);
    Underline(L"Arial", FALSE, TRUE);
    Underline(L"Tahoma", TRUE, FALSE);
}

/* GDI+ flat API, loaded at run time */
typedef struct { UINT32 Version; PVOID Callback; BOOL NoThread, NoCodecs; } GSI;
typedef struct { float X, Y, Width, Height; } GRECTF;
typedef int (WINAPI *FN_Startup)(ULONG_PTR *, const GSI *, PVOID);
typedef int (WINAPI *FN_Family)(PCWSTR, PVOID, PVOID *);
typedef int (WINAPI *FN_Font)(PVOID, float, int, int, PVOID *);
typedef int (WINAPI *FN_Style)(PVOID, int *);
typedef int (WINAPI *FN_Bitmap)(int, int, int, int, BYTE *, PVOID *);
typedef int (WINAPI *FN_Context)(PVOID, PVOID *);
typedef int (WINAPI *FN_Clear)(PVOID, DWORD);
typedef int (WINAPI *FN_Fill)(DWORD, PVOID *);
typedef int (WINAPI *FN_Draw)(PVOID, PCWSTR, int, PVOID, const GRECTF *, PVOID, PVOID);
typedef int (WINAPI *FN_Delete)(PVOID);
typedef int (WINAPI *FN_FromHdc)(HDC, PVOID *);

static DWORD g_Thresh = 0x606060; /* a pixel is "dark" below this, per channel */

static int DarkRow(const DWORD *Bits, int W, int y)
{
    int x, n = 0;
    for (x = 0; x < W; x++)
    {
        DWORD p = Bits[y * W + x];
        if ((p & 0xFF) < (g_Thresh & 0xFF) && ((p >> 8) & 0xFF) < ((g_Thresh >> 8) & 0xFF) &&
            ((p >> 16) & 0xFF) < ((g_Thresh >> 16) & 0xFF))
            n++;
    }
    return n;
}
typedef int (WINAPI *FN_FromHdc)(HDC, PVOID *);

/* Rows that are empty in Plain but dark in Styled, grouped in runs of adjacent rows: the lines
 * the style added. Returns the number of runs, *Thickness gets the thickest. */
static int DecorationRuns(const DWORD *Plain, const DWORD *Styled, int W, int H, int *Thickness, int *First)
{
    int y, Runs = 0, Len = 0;

    *Thickness = 0;
    *First = -1;
    for (y = 0; y <= H; y++)
    {
        BOOL New = y < H && DarkRow(Plain, W, y) == 0 && DarkRow(Styled, W, y) >= 20;
        if (New)
        {
            if (*First < 0)
                *First = y;
            Len++;
        }
        else if (Len)
        {
            Runs++;
            *Thickness = max(*Thickness, Len);
            Len = 0;
        }
    }
    return Runs;
}

/* Draw "aaaa" with GDI+ in Arial of the given pixel size and style (underline or none), on a
 * Scan0 bitmap (software path) or on a DIB section DC (GdipCreateFromHDC, GDI path), copy the
 * W x H pixels to Out. */
static FN_Font pFont_; static FN_Bitmap pBitmap_; static FN_Context pContext_; static FN_Clear pClear_;
typedef int (WINAPI *FN_Smooth)(PVOID, int);
static FN_Smooth pSmooth_;
static FN_Draw pDraw_; static FN_Delete pDeleteFont_, pDeleteGraphics_, pDisposeImage_; static FN_FromHdc pFromHdc_;

static BOOL DrawAaaaEx(BOOL UseHdc, PVOID Family, float Size, float OffY, BOOL Underline, PVOID Brush, DWORD *Out, int Smoothing)
{
    enum { W = 300, H = 60 };
    GRECTF R = { 10, 5, 280, 50 };
    PVOID Font = NULL, Graphics = NULL, Bitmap = NULL;
    BITMAPINFO bmi;
    VOID *Bits = NULL;
    HDC hdc = NULL;
    HBITMAP hbm = NULL, hbmOld = NULL;

    R.Y += OffY;
    pFont_(Family, Size, Underline ? 4 : 0, 2 /* UnitPixel */, &Font);
    if (UseHdc)
    {
        hdc = CreateCompatibleDC(NULL);
        ZeroMemory(&bmi, sizeof(bmi));
        bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
        bmi.bmiHeader.biWidth = W;
        bmi.bmiHeader.biHeight = -H;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &Bits, NULL, 0);
        if (hbm)
            hbmOld = SelectObject(hdc, hbm);
        if (Bits)
            pFromHdc_(hdc, &Graphics);
    }
    else
    {
        pBitmap_(W, H, W * 4, 0x26200A /* PixelFormat32bppARGB */, (BYTE *)Out, &Bitmap);
        if (Bitmap)
            pContext_(Bitmap, &Graphics);
    }
    if (!Font || !Graphics)
    {
        ok(0, "GDI+ setup failed (hdc %d)\n", UseHdc);
        if (Graphics) pDeleteGraphics_(Graphics);
        if (Bitmap) pDisposeImage_(Bitmap);
        if (Font) pDeleteFont_(Font);
        if (hdc) { if (hbmOld) SelectObject(hdc, hbmOld); if (hbm) DeleteObject(hbm); DeleteDC(hdc); }
        return FALSE;
    }
    pClear_(Graphics, 0xFFFFFFFF);
    if (Smoothing && pSmooth_)
        pSmooth_(Graphics, Smoothing);
    ok(pDraw_(Graphics, L"aaaa", 4, Font, &R, NULL, Brush) == 0, "GdipDrawString failed\n");
    pDeleteGraphics_(Graphics);
    if (UseHdc)
    {
        GdiFlush();
        CopyMemory(Out, Bits, W * H * sizeof(DWORD));
        SelectObject(hdc, hbmOld);
        DeleteObject(hbm);
        DeleteDC(hdc);
    }
    else
        pDisposeImage_(Bitmap);
    pDeleteFont_(Font);
    return TRUE;
}

/* GDI records drawn through an enhanced metafile DC */
typedef struct { int Total, Text, TextUnderlined, Other; } EMFCOUNT;

static int CALLBACK CountEmfRecord(HDC hdc, HANDLETABLE *Table, const ENHMETARECORD *Rec, int Objs, LPARAM Param)
{
    EMFCOUNT *c = (EMFCOUNT *)Param;
    c->Total++;
    switch (Rec->iType)
    {
        case EMR_EXTTEXTOUTW:
            c->Text++;
            break;
        case EMR_EXTCREATEFONTINDIRECTW:
            if (((const EMREXTCREATEFONTINDIRECTW *)Rec)->elfw.elfLogFont.lfUnderline)
                c->TextUnderlined++;
            break;
        case EMR_HEADER: case EMR_EOF: case EMR_SAVEDC: case EMR_RESTOREDC: case EMR_SETBKMODE:
        case EMR_SETTEXTCOLOR: case EMR_SELECTOBJECT: case EMR_DELETEOBJECT: case EMR_SETTEXTALIGN:
        case EMR_EXTSELECTCLIPRGN: case EMR_SETMAPMODE: case EMR_SETWINDOWEXTEX: case EMR_SETWINDOWORGEX:
        case EMR_SETVIEWPORTEXTEX: case EMR_SETVIEWPORTORGEX: case EMR_SETWORLDTRANSFORM:
        case EMR_MODIFYWORLDTRANSFORM: case EMR_SETBKCOLOR:
        case EMR_GDICOMMENT: case EMR_SETLAYOUT: case EMR_INTERSECTCLIPRECT: case EMR_SELECTCLIPPATH:
        case EMR_SETICMMODE: case EMR_SETPOLYFILLMODE: case EMR_SETROP2: case EMR_SETSTRETCHBLTMODE:
        case EMR_SETMITERLIMIT: case EMR_SETBRUSHORGEX: case EMR_SETMAPPERFLAGS:
            break;
        default:
            c->Other++;
            trace("  EMF record type %lu\n", Rec->iType);
            break;
    }
    return 1;
}

static BOOL DrawAaaa(BOOL UseHdc, PVOID Family, float Size, float OffY, BOOL Underline, PVOID Brush, DWORD *Out)
{
    return DrawAaaaEx(UseHdc, Family, Size, OffY, Underline, Brush, Out, 0);
}

static void Test_Gdiplus(void)
{
    enum { W = 300, H = 60 };
    static DWORD Plain[W * H], Styled[W * H], HdcPlain[W * H], HdcStyled[W * H];
    FN_FromHdc pFromHdc;
    int ScanRuns, ScanThick, ScanRow;
    HMODULE hMod = LoadLibraryW(L"gdiplus.dll");
    FN_Startup pStartup; FN_Family pFamily; FN_Font pFont; FN_Style pStyle; FN_Bitmap pBitmap;
    FN_Context pContext; FN_Clear pClear; FN_Fill pFill; FN_Draw pDraw;
    FN_Delete pDeleteFont, pDeleteFamily, pDeleteGraphics, pDisposeImage, pDeleteBrush;
    ULONG_PTR Token;
    GSI si = { 1, NULL, FALSE, FALSE };
    PVOID Family = NULL, Brush = NULL;
    int Styles[] = { 0, 1, 2, 4, 8, 5 }, i, y, Below, Ink[2];

    if (!hMod)
    {
        skip("no gdiplus\n");
        return;
    }
    {
        WCHAR Path[MAX_PATH] = L"";
        GetModuleFileNameW(hMod, Path, _countof(Path));
        trace("gdiplus: %ls\n", Path);
    }
    pStartup = (FN_Startup)GetProcAddress(hMod, "GdiplusStartup");
    pFamily = (FN_Family)GetProcAddress(hMod, "GdipCreateFontFamilyFromName");
    pFont = (FN_Font)GetProcAddress(hMod, "GdipCreateFont");
    pStyle = (FN_Style)GetProcAddress(hMod, "GdipGetFontStyle");
    pBitmap = (FN_Bitmap)GetProcAddress(hMod, "GdipCreateBitmapFromScan0");
    pContext = (FN_Context)GetProcAddress(hMod, "GdipGetImageGraphicsContext");
    pClear = (FN_Clear)GetProcAddress(hMod, "GdipGraphicsClear");
    pFill = (FN_Fill)GetProcAddress(hMod, "GdipCreateSolidFill");
    pDraw = (FN_Draw)GetProcAddress(hMod, "GdipDrawString");
    pDeleteFont = (FN_Delete)GetProcAddress(hMod, "GdipDeleteFont");
    pDeleteFamily = (FN_Delete)GetProcAddress(hMod, "GdipDeleteFontFamily");
    pDeleteGraphics = (FN_Delete)GetProcAddress(hMod, "GdipDeleteGraphics");
    pDisposeImage = (FN_Delete)GetProcAddress(hMod, "GdipDisposeImage");
    pDeleteBrush = (FN_Delete)GetProcAddress(hMod, "GdipDeleteBrush");
    if (!pStartup || !pFamily || !pFont || !pStyle || !pBitmap || !pContext || !pClear || !pFill ||
        !pDraw || !pDeleteFont || !pDeleteFamily || !pDeleteGraphics || !pDisposeImage || !pDeleteBrush ||
        pStartup(&Token, &si, NULL) != 0)
    {
        skip("gdiplus functions missing\n");
        return;
    }
    pFont_ = pFont; pBitmap_ = pBitmap; pContext_ = pContext; pClear_ = pClear; pDraw_ = pDraw;
    pDeleteFont_ = pDeleteFont; pDeleteGraphics_ = pDeleteGraphics; pDisposeImage_ = pDisposeImage;
    pSmooth_ = (FN_Smooth)GetProcAddress(hMod, "GdipSetSmoothingMode");
    pFromHdc_ = pFromHdc = (FN_FromHdc)GetProcAddress(hMod, "GdipCreateFromHDC");
    ok(pFamily(L"Arial", NULL, &Family) == 0, "GdipCreateFontFamilyFromName(Arial) failed\n");
    if (!Family)
        return;

    for (i = 0; i < _countof(Styles); i++)
    {
        PVOID Font = NULL;
        int Style = -1;
        ok(pFont(Family, 12.0f, Styles[i], 3 /* UnitPoint */, &Font) == 0, "GdipCreateFont(%d) failed\n", Styles[i]);
        if (!Font)
            continue;
        pStyle(Font, &Style);
        ok(Style == Styles[i], "GdipCreateFont(Arial, style %d): GdipGetFontStyle gives %d\n", Styles[i], Style);
        pDeleteFont(Font);
    }

    /* Underline: rows empty in the plain rendering get a line as wide as half the text or more */
    pFill(0xFF000000, &Brush);
    for (i = 0; i < 2; i++)
    {
        if (!DrawAaaa(0, Family, 24.0f, 0.0f, i, Brush, i ? Styled : Plain))
            return;
        Ink[i] = 0;
        for (y = 0; y < H; y++)
            Ink[i] += DarkRow(i ? Styled : Plain, W, y);
    }
    ok(Ink[0] > 0, "GdipDrawString drew nothing\n");
    Below = 0;
    for (y = 0; y < H; y++)
        if (DarkRow(Plain, W, y) == 0)
            Below = max(Below, DarkRow(Styled, W, y));
    ok(Below >= 20, "GdipDrawString with an underlined font: widest new dark row %d (ink %d / %d)\n", Below, Ink[0], Ink[1]);
    ScanRuns = DecorationRuns(Plain, Styled, W, H, &ScanThick, &ScanRow);
    ok(ScanRuns == 1, "GdipDrawString (bitmap): %d underlines, expected 1\n", ScanRuns);
    ok(ScanThick >= 1 && ScanThick <= 3, "GdipDrawString (bitmap): underline thickness %d\n", ScanThick);

    /* GdipCreateFromHDC on a DIB section with an opaque solid brush: GDI draws the text, and
     * win32k draws the font's underline. GDI+ must not add a second one. A second line computed
     * in GDI+ from the same metrics but rounded differently lands on another row at some sizes
     * and origins, and then the line is thicker; compare with the software path, which draws
     * exactly one line, over sizes and fractional origins. */
    if (!pFromHdc)
    {
        skip("no GdipCreateFromHDC\n");
    }
    else
    {
        int Size, Frac, Bad = 0;

        for (Size = 9; Size <= 40; Size++)
        {
            for (Frac = 0; Frac < 4; Frac++)
            {
                int HdcRuns, HdcThick, HdcRow, ScanRuns2, ScanThick2, ScanRow2;
                float Fy = Frac * 0.25f;

                if (!DrawAaaa(0, Family, (float)Size, Fy, 0, Brush, Plain) ||
                    !DrawAaaa(0, Family, (float)Size, Fy, 1, Brush, Styled) ||
                    !DrawAaaa(1, Family, (float)Size, Fy, 0, Brush, HdcPlain) ||
                    !DrawAaaa(1, Family, (float)Size, Fy, 1, Brush, HdcStyled))
                    return;
                ScanRuns2 = DecorationRuns(Plain, Styled, W, H, &ScanThick2, &ScanRow2);
                HdcRuns = DecorationRuns(HdcPlain, HdcStyled, W, H, &HdcThick, &HdcRow);
                trace("underline %dpx +%d/4: bitmap %d line(s) row %d thickness %d, HDC %d line(s) row %d thickness %d\n",
                      Size, Frac, ScanRuns2, ScanRow2, ScanThick2, HdcRuns, HdcRow, HdcThick);
                ok(ScanRuns2 == 1, "GdipDrawString (bitmap, %dpx +%d/4): %d underlines, expected 1\n", Size, Frac, ScanRuns2);
                ok(HdcRuns == 1, "GdipDrawString (HDC, %dpx +%d/4): %d underlines, expected exactly 1\n", Size, Frac, HdcRuns);
                if (HdcRuns == 1 && ScanRuns2 == 1)
                {
                    if (HdcThick > ScanThick2 || abs(HdcRow - ScanRow2) > 1)
                        Bad++;
                    ok(HdcThick <= ScanThick2, "GdipDrawString (HDC, %dpx +%d/4): underline thickness %d, the bitmap path draws %d\n",
                       Size, Frac, HdcThick, ScanThick2);
                }
            }
        }
        ok(Bad == 0, "GdipDrawString: %d size/origin combinations differ between the HDC and bitmap paths\n", Bad);

        /* With anti-aliased fills, a line drawn by GDI+ on top of the one GDI drew has soft
         * edges, which widens the line: count any non-white row. */

        /* Record the same call on an enhanced metafile DC: the text is one ExtTextOutW with an
         * underlined font and nothing else may draw (a filled line would be another record). */
        {
            HDC Emf = CreateEnhMetaFileW(NULL, NULL, NULL, NULL);
            PVOID Font = NULL, Graphics = NULL;
            GRECTF R = { 10, 5, 280, 50 };
            EMFCOUNT Count = { 0 };
            HENHMETAFILE hEmf;

            pFont(Family, 24.0f, 4, 2, &Font);
            if (Emf && Font && pFromHdc(Emf, &Graphics) == 0 && Graphics)
            {
                ok(pDraw(Graphics, L"aaaa", 4, Font, &R, NULL, Brush) == 0, "GdipDrawString (EMF) failed\n");
                pDeleteGraphics(Graphics);
            }
            if (Font)
                pDeleteFont(Font);
            hEmf = Emf ? CloseEnhMetaFile(Emf) : NULL;
            if (hEmf)
            {
                EnumEnhMetaFile(NULL, hEmf, CountEmfRecord, &Count, NULL);
                trace("EMF: %d records, %d ExtTextOutW, %d underlined fonts, %d other\n",
                      Count.Total, Count.Text, Count.TextUnderlined, Count.Other);
                /* Windows GDI+ records EMF+ here instead of GDI text: nothing to check then */
                if (Count.Text == 1)
                {
                    ok(Count.TextUnderlined >= 1, "GdipDrawString (EMF): the text font is not underlined\n");
                    ok(Count.Other == 0, "GdipDrawString (EMF): %d records besides the text, a second underline was drawn\n",
                       Count.Other);
                }
                DeleteEnhMetaFile(hEmf);
            }
        }

        g_Thresh = 0xF0F0F0;
        for (Size = 12; Size <= 30; Size += 3)
            for (Frac = 0; Frac < 4; Frac++)
            {
                int Runs, Thick, Row;
                float Fy = Frac * 0.25f;
                int Runs2, Thick2, Row2;

                if (!DrawAaaaEx(1, Family, (float)Size, Fy, 0, Brush, HdcPlain, 4) ||
                    !DrawAaaaEx(1, Family, (float)Size, Fy, 1, Brush, HdcStyled, 4) ||
                    !DrawAaaaEx(0, Family, (float)Size, Fy, 0, Brush, Plain, 0) ||
                    !DrawAaaaEx(0, Family, (float)Size, Fy, 1, Brush, Styled, 0))
                    break;
                Runs = DecorationRuns(HdcPlain, HdcStyled, W, H, &Thick, &Row);
                Runs2 = DecorationRuns(Plain, Styled, W, H, &Thick2, &Row2);
                trace("AA underline %dpx +%d/4: HDC %d line(s) row %d thickness %d; bitmap %d line(s) thickness %d\n",
                      Size, Frac, Runs, Row, Thick, Runs2, Thick2);
            }
        g_Thresh = 0x606060;
    }

    pDeleteBrush(Brush);
    pDeleteFamily(Family);
}

START_TEST(FontRequestState)
{
    Pollute();
    Test_Weights();
    Test_EmulatedBold();
    Test_TwoDCs();
    Test_Underline();
    Test_Gdiplus();
}
