/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetCharABCWidthsI: the widths of a range of glyph indices are the same whichever way they are asked
 *              for (a range, a glyph at a time, twice), and a glyph that was measured once is not loaded again
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define MAX_FACES 5
#define RANGES_PER_FACE 2000
#define MAX_RANGE 78

static WCHAR g_faces[MAX_FACES][LF_FACESIZE];
static int g_nFaces;

static int CALLBACK EnumProc(const LOGFONTW *lf, const TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
    int i;

    if (type != TRUETYPE_FONTTYPE || lf->lfFaceName[0] == L'@')
        return 1;
    for (i = 0; i < g_nFaces; i++)
        if (!wcscmp(g_faces[i], lf->lfFaceName))
            return 1;
    wcscpy(g_faces[g_nFaces++], lf->lfFaceName);
    return g_nFaces < MAX_FACES;
}

static ULONG g_seed = 12345;

static ULONG Rand(void)
{
    g_seed = g_seed * 1103515245 + 12345;
    return (g_seed >> 8) & 0xFFFFFF;
}

static ULONG Fnv(ULONG h, const void *p, int cb)
{
    const BYTE *b = p;

    while (cb--)
        h = (h ^ *b++) * 16777619;
    return h;
}

static HFONT MakeFont(const WCHAR *face, int height)
{
    LOGFONTW lf = {0};

    lf.lfHeight = height;
    lf.lfCharSet = DEFAULT_CHARSET;
    wcscpy(lf.lfFaceName, face);
    return CreateFontIndirectW(&lf);
}

/* The number of glyphs of the TrueType face in the DC, from its 'maxp' table */
static UINT NumGlyphs(HDC hdc)
{
    BYTE maxp[6];

    if (GetFontData(hdc, 0x7078616D /* the tag 'maxp', as GetFontData wants it (the characters in memory order) */, 0, maxp, sizeof(maxp)) != sizeof(maxp))
        return 0;
    return (maxp[4] << 8) | maxp[5];
}

/* An index beyond the face has no widths. The answer used to be those of the glyph loaded before it. */
static void test_BeyondFace(HDC hdc)
{
    HFONT font = MakeFont(g_faces[0], -14), old = SelectObject(hdc, font);
    UINT n = NumGlyphs(hdc), i;
    ABC abc[16];
    int bad = 0;

    if (n == 0 || n > 60000)
    {
        skip("no glyph count\n");
        goto done;
    }
    for (i = 0; i < 20; i++)
    {
        ABC valid, beyond;

        /* a glyph that loads, then one that does not */
        GetCharABCWidthsI(hdc, 3 + i, 1, NULL, &valid);
        ZeroMemory(&beyond, sizeof(beyond));
        beyond.abcA = 77; beyond.abcB = 77; beyond.abcC = 77;
        GetCharABCWidthsI(hdc, n + i, 1, NULL, &beyond);
        if (beyond.abcA || beyond.abcB || beyond.abcC)
            bad++;
    }
    ok(bad == 0, "%d of 20 glyph indices beyond the face (%u glyphs) had widths\n", bad, n);
    ZeroMemory(abc, sizeof(abc));
done:
    SelectObject(hdc, old);
    DeleteObject(font);
}

static void test_Consistency(HDC hdc)
{
    ULONG hash = 2166136261U;
    int f, r, i, bad = 0, calls = 0;

    for (f = 0; f < g_nFaces; f++)
    {
        HFONT font = MakeFont(g_faces[f], -(11 + f * 3)), old = SelectObject(hdc, font);
        UINT nGlyphs = NumGlyphs(hdc);

        if (nGlyphs <= MAX_RANGE)
        {
            skip("%ls: %u glyphs\n", g_faces[f], nGlyphs);
            SelectObject(hdc, old);
            DeleteObject(font);
            continue;
        }

        for (r = 0; r < RANGES_PER_FACE; r++)
        {
            WORD gi[MAX_RANGE];
            ABC a[MAX_RANGE], b[MAX_RANGE], one;
            UINT cnt = 1 + Rand() % MAX_RANGE, first = Rand() % (nGlyphs - cnt);

            /* a range of consecutive indices, the same indices as an array, and each alone */
            ZeroMemory(a, sizeof(a));
            ZeroMemory(b, sizeof(b));
            if (!GetCharABCWidthsI(hdc, first, cnt, NULL, a))
            {
                bad++;
                continue;
            }
            for (i = 0; i < (int)cnt; i++)
                gi[i] = (WORD)(first + i);
            if (!GetCharABCWidthsI(hdc, 0, cnt, gi, b) || memcmp(a, b, cnt * sizeof(ABC)))
                bad++;
            for (i = 0; i < (int)cnt; i += 7)
            {
                if (!GetCharABCWidthsI(hdc, first + i, 1, NULL, &one) || memcmp(&one, &a[i], sizeof(ABC)))
                    bad++;
                calls++;
            }
            hash = Fnv(hash, a, cnt * sizeof(ABC));
            calls += 2;
        }
        SelectObject(hdc, old);
        DeleteObject(font);
    }
    ok(bad == 0, "%d answers differ between a range, an array and single glyphs\n", bad);
    trace("%d faces, %d calls, result hash %08lx\n", g_nFaces, calls, hash);
}

static double Now(void)
{
    LARGE_INTEGER c, f;

    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    return (double)c.QuadPart * 1e6 / (double)f.QuadPart;
}

/* The widths of a glyph at a size come from the glyph once: the same ranges again are much cheaper than the first
   time (the size is one no other row uses, so the first time is a cold one) */
static void test_Repeat(HDC hdc)
{
    HFONT font = MakeFont(g_faces[0], -37), old = SelectObject(hdc, font);
    ABC abc[MAX_RANGE];
    double t0, cold, warm;
    int r, pass;

    t0 = Now();
    for (r = 0; r < 8; r++)
        GetCharABCWidthsI(hdc, 100 + r * 80, MAX_RANGE, NULL, abc);
    cold = Now() - t0;

    t0 = Now();
    for (pass = 0; pass < 10; pass++)
        for (r = 0; r < 8; r++)
            GetCharABCWidthsI(hdc, 100 + r * 80, MAX_RANGE, NULL, abc);
    warm = (Now() - t0) / 10;

    trace("cold %.0f us, warm %.0f us per 8 ranges of %d glyphs\n", cold, warm, MAX_RANGE);
    ok(warm * 2 < cold, "the same ranges again cost %.0f us, the first time %.0f us\n", warm, cold);

    SelectObject(hdc, old);
    DeleteObject(font);
}

START_TEST(GetCharABCWidthsI)
{
    HDC hdc = CreateCompatibleDC(NULL);
    LOGFONTW lf = {0};

    lf.lfCharSet = DEFAULT_CHARSET;
    EnumFontFamiliesExW(hdc, &lf, EnumProc, 0, 0);
    if (!g_nFaces)
    {
        skip("no TrueType face\n");
        DeleteDC(hdc);
        return;
    }
    test_BeyondFace(hdc);
    test_Consistency(hdc);
    test_Repeat(hdc);
    DeleteDC(hdc);
}
