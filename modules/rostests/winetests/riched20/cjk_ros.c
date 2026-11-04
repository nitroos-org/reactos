/*
 * PROJECT:     ReactOS RichEdit tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a rich edit control draws and measures Hangul, kana and Han when the
 *              character format asks for a font (Courier New) that has none of them
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <stdarg.h>
#include <windows.h>
#include <richedit.h>
#include <wine/test.h>

#define EDIT_W 240
#define EDIT_H 60

static BOOL g_bFound;

static int CALLBACK
FindFaceProc(const LOGFONTW *plf, const TEXTMETRICW *ptm, DWORD FontType, LPARAM lParam)
{
    g_bFound = TRUE;
    return 0;
}

static BOOL
has_face(const WCHAR *face)
{
    HDC hdc = GetDC(NULL);
    LOGFONTW lf = { 0 };

    lf.lfCharSet = DEFAULT_CHARSET;
    lstrcpyW(lf.lfFaceName, face);
    g_bFound = FALSE;
    EnumFontFamiliesExW(hdc, &lf, FindFaceProc, 0, 0);
    ReleaseDC(NULL, hdc);
    return g_bFound;
}

static HWND
create_edit(const WCHAR *text)
{
    CHARFORMAT2W cf = { sizeof(cf) };
    HWND hwnd;

    hwnd = CreateWindowExW(0, L"RichEdit20W", NULL, WS_POPUP | WS_VISIBLE | ES_MULTILINE,
                           0, 0, EDIT_W, EDIT_H, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowExW failed %lu\n", GetLastError());
    if (!hwnd)
        return NULL;

    /* WordPad's default: Courier New 9pt */
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_CHARSET;
    cf.yHeight = 180;
    cf.bCharSet = DEFAULT_CHARSET;
    lstrcpyW(cf.szFaceName, L"Courier New");
    SendMessageW(hwnd, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
    SetWindowTextW(hwnd, text);
    return hwnd;
}

/* Prints the control into a bitmap, returns the number of dark pixels, and the bits in pBits */
static int
print_edit(HWND hwnd, BYTE *pBits)
{
    BITMAPINFO bmi = { { sizeof(BITMAPINFOHEADER) } };
    HDC hdcScreen = GetDC(NULL), hdc = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm, hbmOld;
    BYTE *pv;
    int i, ink = 0;

    bmi.bmiHeader.biWidth = EDIT_W;
    bmi.bmiHeader.biHeight = -EDIT_H;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, (void **)&pv, NULL, 0);
    hbmOld = SelectObject(hdc, hbm);
    FillMemory(pv, EDIT_W * EDIT_H * 4, 0xFF);
    SendMessageW(hwnd, WM_PRINT, (WPARAM)hdc, PRF_CLIENT | PRF_ERASEBKGND);
    GdiFlush();
    for (i = 0; i < EDIT_W * EDIT_H; i++)
    {
        pBits[i] = pv[i * 4 + 1];
        if (pBits[i] < 128)
            ink++;
    }
    SelectObject(hdc, hbmOld);
    DeleteObject(hbm);
    DeleteDC(hdc);
    ReleaseDC(NULL, hdcScreen);
    return ink;
}

static const struct
{
    const char *name;
    WCHAR chars[4];
} scripts[] =
{
    { "Hangul", { 0xD55C, 0xAD6D, 0xC5B4, 0 } },
    { "kana", { 0x3042, 0x30A2, 0x3044, 0 } },
    { "Han", { 0x4E2D, 0x6587, 0x8A9E, 0 } },
};

static BYTE bits_a[EDIT_W * EDIT_H], bits_b[EDIT_W * EDIT_H], bits_blank[EDIT_W * EDIT_H];

static void test_cjk_text(void)
{
    HWND hwnd;
    UINT i;
    int ink_blank, ink;
    LRESULT pos0, pos1, pos3;

    hwnd = create_edit(L" ");
    if (!hwnd) return;
    ink_blank = print_edit(hwnd, bits_blank);
    DestroyWindow(hwnd);

    /* the control and the capture work: Latin text draws */
    hwnd = create_edit(L"ABC abc");
    if (!hwnd) return;
    ink = print_edit(hwnd, bits_a);
    ok(ink > ink_blank + 20, "Latin: draws %d dark pixels, an empty control %d\n", ink, ink_blank);
    DestroyWindow(hwnd);

    for (i = 0; i < ARRAY_SIZE(scripts); i++)
    {
        hwnd = create_edit(scripts[i].chars);
        if (!hwnd) return;

        pos0 = SendMessageW(hwnd, EM_POSFROMCHAR, 0, 0);
        pos1 = SendMessageW(hwnd, EM_POSFROMCHAR, 1, 0);
        pos3 = SendMessageW(hwnd, EM_POSFROMCHAR, 3, 0);
        ok(LOWORD(pos1) > LOWORD(pos0), "%s: second character is at x %d, first at %d\n",
           scripts[i].name, (short)LOWORD(pos1), (short)LOWORD(pos0));
        ok(LOWORD(pos3) - LOWORD(pos0) >= 3 * 4, "%s: three characters are %d pixels wide\n",
           scripts[i].name, (short)(LOWORD(pos3) - LOWORD(pos0)));

        ink = print_edit(hwnd, bits_a);
        ok(ink > ink_blank + 20, "%s: draws %d dark pixels, an empty control %d\n",
           scripts[i].name, ink, ink_blank);
        ok(memcmp(bits_a, bits_blank, sizeof(bits_a)) != 0, "%s: looks like an empty control\n",
           scripts[i].name);
        DestroyWindow(hwnd);

        /* the first character alone differs from the second alone: real glyphs, not one notdef */
        {
            WCHAR one[2] = { scripts[i].chars[0], 0 }, two[2] = { scripts[i].chars[1], 0 };
            hwnd = create_edit(one);
            print_edit(hwnd, bits_a);
            DestroyWindow(hwnd);
            hwnd = create_edit(two);
            print_edit(hwnd, bits_b);
            DestroyWindow(hwnd);
            ok(memcmp(bits_a, bits_b, sizeof(bits_a)) != 0,
               "%s: U+%04X and U+%04X are drawn alike\n", scripts[i].name,
               scripts[i].chars[0], scripts[i].chars[1]);
        }
    }
}

static void test_mixed_text(void)
{
    static const WCHAR mixed[] = { 'A', 'b', 0x4E2D, 0x6587, 0xD55C, 0xAD6D, 'C', 0 };
    HWND hwnd = create_edit(mixed);
    LRESULT pos[8];
    int i;

    if (!hwnd) return;
    for (i = 0; i < 7; i++)
        pos[i] = SendMessageW(hwnd, EM_POSFROMCHAR, i, 0);
    for (i = 1; i < 7; i++)
        ok((short)LOWORD(pos[i]) > (short)LOWORD(pos[i - 1]), "mixed: char %d at x %d, char %d at x %d\n",
           i - 1, (short)LOWORD(pos[i - 1]), i, (short)LOWORD(pos[i]));
    print_edit(hwnd, bits_a);
    DestroyWindow(hwnd);
}

START_TEST(cjk_ros)
{
    HMODULE hmod = LoadLibraryA("riched20.dll");

    if (!hmod)
    {
        win_skip("riched20.dll is not available\n");
        return;
    }
    if (!has_face(L"Noto Sans KR") && !has_face(L"Malgun Gothic"))
    {
        skip("No Korean font installed\n");
        return;
    }
    if (!has_face(L"Courier New"))
    {
        skip("No Courier New\n");
        return;
    }
    test_cjk_text();
    test_mixed_text();
    FreeLibrary(hmod);
}
