/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         Clipboard rows that need an interactive window station: the image formats that
 *                  stand for each other, the death of a clipboard owner with delayed formats,
 *                  the viewer chain, text conversion by CF_LOCALE, malformed packed images and
 *                  the refusals of SetClipboardData. The expected values were measured on
 *                  Windows Server 2022 (20348.587) in the logged-on console session.
 *                  The test skips itself where there is no clipboard (a service session).
 */

#include "precomp.h"
#include <limits.h>

static BOOL (WINAPI *pAddListener)(HWND);
static BOOL (WINAPI *pRemoveListener)(HWND);
static int g_Draw[8], g_Update[8], g_ChainMsg[8], g_RenderAll, g_RenderFmt[8], g_nRenderFmt;
static HWND g_Next[8];
static HWND g_Hwnd[8];

static int Idx(HWND hwnd)
{
    int i;
    for (i = 0; i < 8; i++)
        if (g_Hwnd[i] == hwnd)
            return i;
    return -1;
}

static LRESULT CALLBACK RowsProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int i = Idx(hwnd);

    switch (msg)
    {
        case WM_DRAWCLIPBOARD:
            if (i >= 0)
            {
                g_Draw[i]++;
                if (g_Next[i])
                    SendMessageA(g_Next[i], msg, wParam, lParam);
            }
            return 0;
        case WM_CHANGECBCHAIN:
            if (i >= 0)
            {
                g_ChainMsg[i]++;
                if ((HWND)wParam == g_Next[i])
                    g_Next[i] = (HWND)lParam;
                else if (g_Next[i])
                    return SendMessageA(g_Next[i], msg, wParam, lParam);
            }
            return 0;
        case WM_CLIPBOARDUPDATE:
            if (i >= 0)
                g_Update[i]++;
            return 0;
        case WM_RENDERALLFORMATS:
            g_RenderAll++;
            return 0;
        case WM_RENDERFORMAT:
            if (g_nRenderFmt < 8)
                g_RenderFmt[g_nRenderFmt++] = (int)wParam;
            if (wParam == CF_BITMAP)
                SetClipboardData(CF_BITMAP, CreateBitmap(2, 2, 1, 32, NULL));
            return 0;
        case WM_DESTROYCLIPBOARD:
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void Pump(void)
{
    MSG msg;
    DWORD end = GetTickCount() + 60;

    do
    {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(5);
    } while ((int)(end - GetTickCount()) > 0);
}

static HWND MakeWindow(int slot)
{
    static BOOL registered;
    WNDCLASSA wc;

    if (!registered)
    {
        memset(&wc, 0, sizeof(wc));
        wc.lpfnWndProc = RowsProc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = "ClipboardInteractiveRows";
        RegisterClassA(&wc);
        registered = TRUE;
    }
    g_Hwnd[slot] = CreateWindowExA(0, "ClipboardInteractiveRows", "rows", WS_POPUP, 0, 0, 8, 8, NULL, NULL, GetModuleHandleA(NULL), NULL);
    g_Next[slot] = NULL;
    return g_Hwnd[slot];
}

static HGLOBAL GlobalFrom(const void *p, SIZE_T cb)
{
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, cb ? cb : 1);
    void *q = GlobalLock(h);

    if (p)
        memcpy(q, p, cb);
    GlobalUnlock(h);
    return h;
}

static void ResetClipboard(void)
{
    OpenClipboard(NULL);
    EmptyClipboard();
    CloseClipboard();
    Pump();
}

/* the formats the clipboard lists, in order */
static int ListFormats(UINT *pFmts, int cMax)
{
    int n = 0;
    UINT f = 0;

    if (!OpenClipboard(NULL))
        return -1;
    while ((f = EnumClipboardFormats(f)) != 0 && n < cMax)
        pFmts[n++] = f;
    CloseClipboard();
    return n;
}

static BOOL FormatsAre(const UINT *expected, int cExpected)
{
    UINT fmts[16];
    int n = ListFormats(fmts, 16), i;

    if (n != cExpected)
        return FALSE;
    for (i = 0; i < n; i++)
        if (fmts[i] != expected[i])
            return FALSE;
    return TRUE;
}

static void DescribeFormats(char *buf, size_t cb)
{
    UINT fmts[16];
    int n = ListFormats(fmts, 16), i, o = 0;

    buf[0] = 0;
    for (i = 0; i < n && o < (int)cb - 12; i++)
        o += sprintf(buf + o, "%u ", fmts[i]);
}

static BOOL Interactive(void)
{
    char name[64] = "";
    DWORD len;
    HWINSTA ws = GetProcessWindowStation();

    if (!ws || !GetUserObjectInformationA(ws, UOI_NAME, name, sizeof(name), &len) || strcmp(name, "WinSta0") != 0)
        return FALSE;
    if (!OpenClipboard(NULL))
        return FALSE;
    CloseClipboard();
    return TRUE;
}

/* ------------------------------------------------------------------------------------ owner death */

static void test_owner_death(void)
{
    HWND owner, viewer;
    DWORD seq;
    int draw0, upd0;
    char buf[200];
    static const UINT onlyLocale[] = { CF_LOCALE };
    static const UINT bitmapRows[] = { CF_BITMAP, CF_LOCALE, CF_DIB, CF_DIBV5 };
    static const UINT unicodeRows[] = { CF_UNICODETEXT, CF_LOCALE, CF_OEMTEXT };
    static const UINT realRows[] = { CF_TEXT, CF_LOCALE, CF_OEMTEXT, CF_UNICODETEXT };

    ResetClipboard();
    viewer = MakeWindow(1);
    SetClipboardViewer(viewer);
    pAddListener(viewer);
    Pump();

    /* a delayed text format and the text formats made from it die with the owner */
    owner = MakeWindow(2);
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, NULL);
    CloseClipboard();
    Pump();
    ok(CountClipboardFormats() == 4, "delayed text: %d formats\n", CountClipboardFormats());
    seq = GetClipboardSequenceNumber();
    draw0 = g_Draw[1];
    upd0 = g_Update[1];
    g_RenderAll = 0;
    DestroyWindow(owner);
    Pump();
    ok(g_RenderAll == 1, "WM_RENDERALLFORMATS sent %d times\n", g_RenderAll);
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(onlyLocale, 1), "after the owner died with a delayed text format: %s\n", buf);
    ok(!IsClipboardFormatAvailable(CF_TEXT) && !IsClipboardFormatAvailable(CF_UNICODETEXT), "text formats still available\n");
    ok(GetClipboardSequenceNumber() == seq + 1, "sequence %lu -> %lu\n", seq, GetClipboardSequenceNumber());
    ok(g_Draw[1] == draw0 + 1, "WM_DRAWCLIPBOARD %d -> %d\n", draw0, g_Draw[1]);
    ok(g_Update[1] == upd0 + 1, "WM_CLIPBOARDUPDATE %d -> %d\n", upd0, g_Update[1]);
    ok(GetClipboardOwner() == NULL, "owner not NULL\n");

    /* data that was set is kept, nothing changes, nobody is told */
    owner = MakeWindow(2);
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, GlobalFrom("x", 2));
    CloseClipboard();
    Pump();
    seq = GetClipboardSequenceNumber();
    draw0 = g_Draw[1];
    DestroyWindow(owner);
    Pump();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(realRows, 4), "owner with data died: %s\n", buf);
    ok(GetClipboardSequenceNumber() == seq, "sequence changed %lu -> %lu\n", seq, GetClipboardSequenceNumber());
    ok(g_Draw[1] == draw0, "WM_DRAWCLIPBOARD sent for an owner that left data\n");

    /* a delayed UNICODE text with a real bitmap: the text made from it goes, the images stay */
    owner = MakeWindow(2);
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_BITMAP, CreateBitmap(2, 2, 1, 32, NULL));
    SetClipboardData(CF_UNICODETEXT, NULL);
    CloseClipboard();
    Pump();
    DestroyWindow(owner);
    Pump();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(bitmapRows, 4), "delayed UNICODETEXT + BITMAP, owner died: %s\n", buf);

    /* delayed TEXT next to a real UNICODE text: the delayed one goes, the OEM text made from the real one stays */
    owner = MakeWindow(2);
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, GlobalFrom(L"real", 10));
    SetClipboardData(CF_TEXT, NULL);
    CloseClipboard();
    Pump();
    DestroyWindow(owner);
    Pump();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(unicodeRows, 3), "real UNICODETEXT + delayed TEXT, owner died: %s\n", buf);

    pRemoveListener(viewer);
    ChangeClipboardChain(viewer, NULL);
    DestroyWindow(viewer);
    ResetClipboard();
}

/* ------------------------------------------------------------------------------------ images */

static void test_image_group(void)
{
    HWND owner = MakeWindow(2);
    char buf[200];
    static const UINT fromBitmap[] = { CF_BITMAP, CF_DIB, CF_DIBV5 };
    static const UINT fromDib[] = { CF_DIB, CF_BITMAP, CF_DIBV5 };
    static const UINT fromV5[] = { CF_DIBV5, CF_BITMAP, CF_DIB };
    static const UINT bitmapPalette[] = { CF_BITMAP, CF_PALETTE, CF_DIB, CF_DIBV5 };
    static const UINT dibV5[] = { CF_DIB, CF_DIBV5, CF_BITMAP };
    struct { BITMAPINFOHEADER bih; DWORD px[16]; } dib;
    struct { BITMAPV5HEADER h; DWORD px[16]; } v5;
    LOGPALETTE lp;
    HANDLE h;
    int i;

    /* bitmap source */
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_BITMAP, CreateBitmap(4, 4, 1, 32, NULL));
    CloseClipboard();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(fromBitmap, 3), "BITMAP source: %s\n", buf);
    ok(IsClipboardFormatAvailable(CF_DIBV5), "no CF_DIBV5\n");

    /* the packed images made of it */
    OpenClipboard(NULL);
    h = GetClipboardData(CF_DIB);
    ok(h != NULL, "no CF_DIB\n");
    if (h)
    {
        BITMAPINFOHEADER *bih = GlobalLock(h);
        ok(bih->biSize == 40 && bih->biWidth == 4 && bih->biHeight == 4 && bih->biBitCount == 32 && bih->biCompression == BI_BITFIELDS,
           "CF_DIB header %lu %ld %ld %u %lu\n", bih->biSize, bih->biWidth, bih->biHeight, bih->biBitCount, bih->biCompression);
        ok(GlobalSize(h) == 40 + 12 + 64, "CF_DIB size %lu\n", (unsigned long)GlobalSize(h));
        GlobalUnlock(h);
    }
    h = GetClipboardData(CF_DIBV5);
    ok(h != NULL, "no CF_DIBV5 data\n");
    if (h)
    {
        BITMAPV5HEADER *b5 = GlobalLock(h);
        ok(b5->bV5Size == 124 && b5->bV5Width == 4 && b5->bV5Height == 4 && b5->bV5BitCount == 32 && b5->bV5Compression == BI_BITFIELDS,
           "CF_DIBV5 header %lu %ld %ld %u %lu\n", b5->bV5Size, b5->bV5Width, b5->bV5Height, b5->bV5BitCount, b5->bV5Compression);
        ok(b5->bV5RedMask == 0xff0000 && b5->bV5GreenMask == 0xff00 && b5->bV5BlueMask == 0xff, "masks %lx %lx %lx\n", b5->bV5RedMask, b5->bV5GreenMask, b5->bV5BlueMask);
        ok(b5->bV5CSType == 0x73524742 && b5->bV5Intent == LCS_GM_IMAGES, "colour space %lx intent %lu\n", b5->bV5CSType, b5->bV5Intent);
        ok(GlobalSize(h) == 124 + 12 + 64, "CF_DIBV5 size %lu\n", (unsigned long)GlobalSize(h));
        GlobalUnlock(h);
    }
    CloseClipboard();

    /* DIB source */
    memset(&dib, 0, sizeof(dib));
    dib.bih.biSize = 40; dib.bih.biWidth = 4; dib.bih.biHeight = 4; dib.bih.biPlanes = 1; dib.bih.biBitCount = 32; dib.bih.biSizeImage = 64;
    dib.bih.biXPelsPerMeter = 3780; dib.bih.biYPelsPerMeter = 3781;
    for (i = 0; i < 16; i++)
        dib.px[i] = 0x00112233 + i;
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_DIB, GlobalFrom(&dib, sizeof(dib)));
    CloseClipboard();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(fromDib, 3), "DIB source: %s\n", buf);
    OpenClipboard(NULL);
    h = GetClipboardData(CF_DIBV5);
    ok(h != NULL, "no CF_DIBV5 from a DIB\n");
    if (h)
    {
        BITMAPV5HEADER *b5 = GlobalLock(h);
        ok(GlobalSize(h) == 124 + 64, "V5 from DIB size %lu\n", (unsigned long)GlobalSize(h));
        ok(b5->bV5Size == 124 && b5->bV5Compression == BI_RGB && b5->bV5SizeImage == 64 && b5->bV5XPelsPerMeter == 3780 && b5->bV5YPelsPerMeter == 3781,
           "V5 from DIB fields\n");
        ok(b5->bV5CSType == 0x73524742 && b5->bV5Intent == LCS_GM_IMAGES, "V5 from DIB colour space\n");
        ok(memcmp((BYTE *)b5 + 124, dib.px, 64) == 0, "V5 from DIB pixels\n");
        GlobalUnlock(h);
    }
    CloseClipboard();

    /* DIBV5 source: the DIB and the bitmap made of it */
    memset(&v5, 0, sizeof(v5));
    v5.h.bV5Size = 124; v5.h.bV5Width = 4; v5.h.bV5Height = 4; v5.h.bV5Planes = 1; v5.h.bV5BitCount = 32; v5.h.bV5Compression = BI_BITFIELDS;
    v5.h.bV5SizeImage = 64; v5.h.bV5RedMask = 0xff0000; v5.h.bV5GreenMask = 0xff00; v5.h.bV5BlueMask = 0xff; v5.h.bV5AlphaMask = 0xff000000;
    v5.h.bV5CSType = 0x73524742;
    for (i = 0; i < 16; i++)
        v5.px[i] = 0x80112233 + i;
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_DIBV5, GlobalFrom(&v5, sizeof(v5)));
    CloseClipboard();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(fromV5, 3), "DIBV5 source: %s\n", buf);
    OpenClipboard(NULL);
    h = GetClipboardData(CF_DIB);
    ok(h != NULL, "no CF_DIB from a DIBV5\n");
    if (h)
    {
        BITMAPINFOHEADER *bih = GlobalLock(h);
        ok(GlobalSize(h) == 40 + 12 + 64 && bih->biSize == 40 && bih->biCompression == BI_BITFIELDS, "DIB from V5: size %lu header %lu comp %lu\n",
           (unsigned long)GlobalSize(h), bih->biSize, bih->biCompression);
        GlobalUnlock(h);
    }
    ok(GetClipboardData(CF_BITMAP) != NULL, "no CF_BITMAP from a DIBV5\n");
    CloseClipboard();

    /* a colour space of "calibrated RGB" gives no DIB, but still a bitmap */
    v5.h.bV5CSType = 0;
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_DIBV5, GlobalFrom(&v5, sizeof(v5)));
    CloseClipboard();
    OpenClipboard(NULL);
    ok(IsClipboardFormatAvailable(CF_DIB), "CF_DIB not listed\n");
    ok(GetClipboardData(CF_DIB) == NULL, "CF_DIB made from a calibrated colour space\n");
    ok(GetClipboardData(CF_BITMAP) != NULL, "no CF_BITMAP from a calibrated colour space\n");
    CloseClipboard();

    /* a palette is not one of the three; it keeps its place */
    lp.palVersion = 0x300; lp.palNumEntries = 1; lp.palPalEntry[0].peRed = 1; lp.palPalEntry[0].peGreen = 0; lp.palPalEntry[0].peBlue = 0; lp.palPalEntry[0].peFlags = 0;
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_BITMAP, CreateBitmap(4, 4, 1, 32, NULL));
    SetClipboardData(CF_PALETTE, CreatePalette(&lp));
    CloseClipboard();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(bitmapPalette, 4), "BITMAP + PALETTE: %s\n", buf);
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_PALETTE, CreatePalette(&lp));
    CloseClipboard();
    ok(CountClipboardFormats() == 1, "a palette alone: %d formats\n", CountClipboardFormats());

    /* DIB + DIBV5 */
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_DIB, GlobalFrom(&dib, sizeof(dib)));
    v5.h.bV5CSType = 0x73524742;
    SetClipboardData(CF_DIBV5, GlobalFrom(&v5, sizeof(v5)));
    CloseClipboard();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(dibV5, 3), "DIB + DIBV5: %s\n", buf);

    /* a delayed bitmap: the formats made from it render it, once */
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_BITMAP, NULL);
    CloseClipboard();
    DescribeFormats(buf, sizeof(buf));
    ok(FormatsAre(fromBitmap, 3), "delayed BITMAP: %s\n", buf);
    g_nRenderFmt = 0;
    OpenClipboard(NULL);
    h = GetClipboardData(CF_DIB);
    ok(h != NULL, "CF_DIB of a delayed bitmap\n");
    ok(g_nRenderFmt == 1 && g_RenderFmt[0] == CF_BITMAP, "rendered %d formats, first %d\n", g_nRenderFmt, g_nRenderFmt ? g_RenderFmt[0] : 0);
    ok(GetClipboardData(CF_DIBV5) != NULL, "CF_DIBV5 after the render\n");
    CloseClipboard();
    ok(g_nRenderFmt == 1, "rendered again: %d\n", g_nRenderFmt);

    ResetClipboard();
    DestroyWindow(owner);
}

/* a packed image with a header Windows will not make a bitmap of is listed as available with no data */
static void TryHeader(const char *what, DWORD biSize, LONG w, LONG h, WORD planes, WORD bpp, DWORD comp)
{
    BITMAPINFOHEADER bih;
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 40 + 2048 + 4096);
    BYTE *p = GlobalLock(g);
    HANDLE hb;

    memset(&bih, 0, sizeof(bih));
    bih.biSize = biSize; bih.biWidth = w; bih.biHeight = h; bih.biPlanes = planes; bih.biBitCount = bpp; bih.biCompression = comp;
    memcpy(p, &bih, sizeof(bih));
    memset(p + 40, 0x55, 2048 + 4096);
    GlobalUnlock(g);

    ResetClipboard();
    OpenClipboard(NULL);
    EmptyClipboard();
    SetClipboardData(CF_DIB, g);
    CloseClipboard();

    ok(IsClipboardFormatAvailable(CF_BITMAP), "%s: CF_BITMAP not listed\n", what);
    OpenClipboard(NULL);
    hb = GetClipboardData(CF_BITMAP);
    ok(hb == NULL, "%s: a bitmap was made\n", what);
    CloseClipboard();
}

static void test_bad_headers(void)
{
    HGLOBAL g;
    BITMAPINFOHEADER *bih;
    HANDLE hb;

    TryHeader("width -1", 40, -1, 4, 1, 32, BI_RGB);
    TryHeader("width 0", 40, 0, 4, 1, 32, BI_RGB);
    TryHeader("height 0", 40, 4, 0, 1, 32, BI_RGB);
    TryHeader("height INT_MIN", 40, 4, INT_MIN, 1, 32, BI_RGB);
    TryHeader("planes 0", 40, 4, 4, 0, 32, BI_RGB);
    TryHeader("bpp 0", 40, 4, 4, 1, 0, BI_RGB);
    TryHeader("bpp 2", 40, 4, 4, 1, 2, BI_RGB);
    TryHeader("bpp 7", 40, 4, 4, 1, 7, BI_RGB);
    TryHeader("bpp 33", 40, 4, 4, 1, 33, BI_RGB);
    TryHeader("bpp 64", 40, 4, 4, 1, 64, BI_RGB);
    TryHeader("header size 41", 41, 4, 4, 1, 32, BI_RGB);
    TryHeader("header size 0", 0, 4, 4, 1, 32, BI_RGB);
    TryHeader("header size -1", 0xffffffff, 4, 4, 1, 32, BI_RGB);
    TryHeader("20000 x 20000 on 6 KB", 40, 20000, 20000, 1, 32, BI_RGB);

    /* a header that is sane makes a bitmap from the same bytes */
    g = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 40 + 4096);
    bih = GlobalLock(g);
    bih->biSize = 40; bih->biWidth = 32; bih->biHeight = 32; bih->biPlanes = 1; bih->biBitCount = 32;
    GlobalUnlock(g);
    ResetClipboard();
    OpenClipboard(NULL);
    EmptyClipboard();
    SetClipboardData(CF_DIB, g);
    CloseClipboard();
    OpenClipboard(NULL);
    hb = GetClipboardData(CF_BITMAP);
    ok(hb != NULL, "no bitmap from a 32 x 32 image\n");
    CloseClipboard();
    ResetClipboard();
}

/* ------------------------------------------------------------------------------------ viewer chain */

static void test_viewer_chain(void)
{
    HWND v1, v2, v3, r;
    BOOL ret;
    HWND owner;

    ResetClipboard();
    v1 = MakeWindow(1); v2 = MakeWindow(2); v3 = MakeWindow(3); owner = MakeWindow(4);
    g_Next[1] = SetClipboardViewer(v1);
    g_Next[2] = SetClipboardViewer(v2);
    g_Next[3] = SetClipboardViewer(v3);
    ok(g_Next[1] == NULL && g_Next[2] == v1 && g_Next[3] == v2, "chain order\n");
    ok(GetClipboardViewer() == v3, "head is not the last one registered\n");
    memset(g_ChainMsg, 0, sizeof(g_ChainMsg));

    /* the head leaves: the next window becomes the head, no message, success */
    SetLastError(0xdeadbeef);
    ret = ChangeClipboardChain(v3, v2);
    ok(ret == TRUE, "removing the head returned %d\n", ret);
    ok(g_ChainMsg[1] == 0 && g_ChainMsg[2] == 0 && g_ChainMsg[3] == 0, "WM_CHANGECBCHAIN sent for the head: %d %d %d\n", g_ChainMsg[1], g_ChainMsg[2], g_ChainMsg[3]);
    ok(GetClipboardViewer() == v2, "head after removal\n");

    /* another window: the message goes down the chain from the head */
    ChangeClipboardChain(v1, NULL);
    ok(g_ChainMsg[2] == 1, "WM_CHANGECBCHAIN to the head: %d\n", g_ChainMsg[2]);

    /* the last head */
    ret = ChangeClipboardChain(v2, NULL);
    ok(ret == TRUE, "removing the only window returned %d\n", ret);
    ok(GetClipboardViewer() == NULL, "viewer after the last one left\n");

    /* no viewer: nothing to do */
    ret = ChangeClipboardChain(v2, NULL);
    ok(ret == FALSE, "no chain: %d\n", ret);

    /* SetClipboardViewer(NULL) ends the chain and returns the previous head, without an error */
    g_Next[1] = SetClipboardViewer(v1);
    SetLastError(0xdeadbeef);
    r = SetClipboardViewer(NULL);
    ok(r == v1, "SetClipboardViewer(NULL) returned %p, expected %p\n", r, v1);
    ok(GetLastError() == 0xdeadbeef || GetLastError() == 0, "error %lu\n", GetLastError());
    ok(GetClipboardViewer() == NULL, "viewer remains\n");
    r = SetClipboardViewer(NULL);
    ok(r == NULL, "no viewer, NULL: %p\n", r);

    DestroyWindow(v1); DestroyWindow(v2); DestroyWindow(v3); DestroyWindow(owner);
    ResetClipboard();
}

/* ------------------------------------------------------------------------------------ text */

static BOOL ReadText(UINT fmt, BYTE *out, SIZE_T *pcb, SIZE_T cbMax)
{
    HANDLE h;
    BOOL ok_ = FALSE;

    if (!OpenClipboard(NULL))
        return FALSE;
    h = GetClipboardData(fmt);
    if (h)
    {
        SIZE_T cb = GlobalSize(h);
        BYTE *p = GlobalLock(h);

        if (cb > cbMax)
            cb = cbMax;
        memcpy(out, p, cb);
        *pcb = cb;
        GlobalUnlock(h);
        ok_ = TRUE;
    }
    CloseClipboard();
    return ok_;
}

static void test_text(void)
{
    HWND owner = MakeWindow(2);
    BYTE out[64];
    SIZE_T cb;
    LCID ru = 0x419, cs = 0x405;
    WCHAR wsRu[] = { 0x0416, 'a', 0 };
    WCHAR wsCs[] = { 0x0141, 'a', 0 };
    static const BYTE ruAnsi[] = { 0xC6, 'a', 0 }, ruOem[] = { 0x86, 'a', 0 };
    static const BYTE csAnsi[] = { 0xA3, 'a', 0 }, csOem[] = { 0x9D, 'a', 0 };
    static const BYTE ruNarrow[] = { 0xC6, 'a', 0 };
    CHAR noTerm[8];
    WCHAR wNoTerm[4];
    int i;

    /* UNICODE with a locale: the code pages of that locale (the default ones when there is none) */
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, GlobalFrom(wsRu, sizeof(wsRu)));
    SetClipboardData(CF_LOCALE, GlobalFrom(&ru, sizeof(ru)));
    CloseClipboard();
    ok(ReadText(CF_TEXT, out, &cb, sizeof(out)) && cb == sizeof(ruAnsi) && !memcmp(out, ruAnsi, cb), "ru UNICODE -> TEXT: %lu bytes %02x %02x\n", (unsigned long)cb, out[0], out[1]);
    ok(ReadText(CF_OEMTEXT, out, &cb, sizeof(out)) && cb == sizeof(ruOem) && !memcmp(out, ruOem, cb), "ru UNICODE -> OEM: %lu bytes %02x %02x\n", (unsigned long)cb, out[0], out[1]);

    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, GlobalFrom(wsCs, sizeof(wsCs)));
    SetClipboardData(CF_LOCALE, GlobalFrom(&cs, sizeof(cs)));
    CloseClipboard();
    ok(ReadText(CF_TEXT, out, &cb, sizeof(out)) && cb == sizeof(csAnsi) && !memcmp(out, csAnsi, cb), "cs UNICODE -> TEXT: %lu bytes %02x %02x\n", (unsigned long)cb, out[0], out[1]);
    ok(ReadText(CF_OEMTEXT, out, &cb, sizeof(out)) && cb == sizeof(csOem) && !memcmp(out, csOem, cb), "cs UNICODE -> OEM: %lu bytes %02x %02x\n", (unsigned long)cb, out[0], out[1]);

    /* the narrow formats: through UNICODE with the code pages of the locale */
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, GlobalFrom(ruNarrow, sizeof(ruNarrow)));
    SetClipboardData(CF_LOCALE, GlobalFrom(&ru, sizeof(ru)));
    CloseClipboard();
    ok(ReadText(CF_UNICODETEXT, out, &cb, sizeof(out)) && cb == sizeof(wsRu) && ((WCHAR *)out)[0] == 0x0416 && ((WCHAR *)out)[1] == 'a',
       "ru TEXT -> UNICODE: %lu bytes %04x\n", (unsigned long)cb, ((WCHAR *)out)[0]);
    ok(ReadText(CF_OEMTEXT, out, &cb, sizeof(out)) && cb == sizeof(ruOem) && !memcmp(out, ruOem, cb), "ru TEXT -> OEM: %lu bytes %02x %02x\n", (unsigned long)cb, out[0], out[1]);

    /* a text without its terminator: the converted block is as long as the conversion and ends with one */
    for (i = 0; i < 8; i++)
        noTerm[i] = 'A';
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, GlobalFrom(noTerm, 8));
    CloseClipboard();
    ok(ReadText(CF_UNICODETEXT, out, &cb, sizeof(out)) && cb == 16 && ((WCHAR *)out)[6] == 'A' && ((WCHAR *)out)[7] == 0, "TEXT without terminator -> UNICODE: %lu bytes\n", (unsigned long)cb);
    ok(ReadText(CF_OEMTEXT, out, &cb, sizeof(out)) && cb == 8 && out[6] == 'A' && out[7] == 0, "TEXT without terminator -> OEM: %lu bytes last %02x\n", (unsigned long)cb, out[7]);

    for (i = 0; i < 4; i++)
        wNoTerm[i] = 'A';
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, GlobalFrom(wNoTerm, 8));
    CloseClipboard();
    ok(ReadText(CF_TEXT, out, &cb, sizeof(out)) && cb == 4 && out[2] == 'A' && out[3] == 0, "UNICODE without terminator -> TEXT: %lu bytes last %02x\n", (unsigned long)cb, out[3]);

    /* a single character without terminator is all terminator */
    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, GlobalFrom("A", 1));
    CloseClipboard();
    ok(ReadText(CF_UNICODETEXT, out, &cb, sizeof(out)) && cb == 2 && ((WCHAR *)out)[0] == 0, "one character, no terminator -> UNICODE: %lu bytes %04x\n", (unsigned long)cb, ((WCHAR *)out)[0]);

    ResetClipboard();
    DestroyWindow(owner);
}

/* ------------------------------------------------------------------------------------ handles */

static BOOL IsFreed(HANDLE h)
{
    return GlobalFlags(h) == GMEM_INVALID_HANDLE;
}

/* what a process put on the clipboard comes back as the same handle in that process, other formats are fixed memory,
   and the block goes when another one replaces it or when the process empties the clipboard */
static void test_own_handles(void)
{
    HWND owner = MakeWindow(2);
    HGLOBAL h1, h2, hm;
    HANDLE g;
    UINT fmt = RegisterClipboardFormatA("ClipboardInteractiveRows own");

    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();
    h1 = GlobalFrom("one", 4);
    ok(SetClipboardData(CF_TEXT, h1) == h1, "SetClipboardData did not return the handle\n");
    hm = GlobalFrom("moveable", 9);
    ok(SetClipboardData(fmt, hm) == hm, "SetClipboardData (registered) did not return the handle\n");
    ok(GetClipboardData(CF_TEXT) == h1, "CF_TEXT read back is not the handle that was set\n");
    ok(GetClipboardData(fmt) == hm, "registered format read back is not the handle that was set\n");
    ok((GlobalFlags(h1) & GMEM_DISCARDED) == 0 && !IsFreed(h1), "the block of CF_TEXT is gone while it is on the clipboard\n");

    /* the same format again: the first block is freed */
    h2 = GlobalFrom("two", 4);
    ok(SetClipboardData(fmt, h2) == h2, "second block\n");
    ok(IsFreed(hm), "the replaced block was not freed\n");
    ok(GetClipboardData(fmt) == h2, "the second block is not what is read back\n");
    ok(!IsFreed(h1), "an unrelated block was freed\n");

    /* emptying frees what is left */
    EmptyClipboard();
    ok(IsFreed(h1), "CF_TEXT block not freed by EmptyClipboard\n");
    ok(IsFreed(h2), "registered block not freed by EmptyClipboard\n");
    CloseClipboard();

    /* another process' data, and the data of an empty clipboard, is fixed memory */
    OpenClipboard(owner);
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, GlobalFrom(L"x", 4));
    CloseClipboard();
    OpenClipboard(NULL);
    g = GetClipboardData(CF_TEXT);
    ok(g != NULL && (GlobalFlags(g) & GMEM_LOCKCOUNT) == 0, "no CF_TEXT\n");
    ok(g != NULL && GlobalSize(g) == 2, "synthesized CF_TEXT size %lu\n", (unsigned long)(g ? GlobalSize(g) : 0));
    CloseClipboard();

    ResetClipboard();
    DestroyWindow(owner);
}

/* ------------------------------------------------------------------------------------ refusals */

static void test_refusals(void)
{
    HWND owner = MakeWindow(2);
    HANDLE h;
    char name[32];
    int n;

    ResetClipboard();
    OpenClipboard(owner);
    EmptyClipboard();

    SetLastError(0xdeadbeef);
    h = SetClipboardData(0x10000, GlobalFrom("x", 2));
    ok(h == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "format 0x10000: %p, error %lu\n", h, GetLastError());
    SetLastError(0xdeadbeef);
    h = SetClipboardData(0xC000, GlobalFrom("x", 2));
    ok(h == NULL && GetLastError() == ERROR_INVALID_HANDLE, "unregistered 0xC000: %p, error %lu\n", h, GetLastError());
    SetLastError(0xdeadbeef);
    h = SetClipboardData(0x8000, GlobalFrom("x", 2));
    ok(h != NULL, "0x8000: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    h = SetClipboardData(0x10001, GlobalFrom("x", 2));
    ok(h != NULL, "0x10001: error %lu\n", GetLastError());

    SetLastError(0xdeadbeef);
    h = SetClipboardData(CF_ENHMETAFILE, (HANDLE)(ULONG_PTR)0x1234);
    ok(h == NULL && GetLastError() == ERROR_INVALID_HANDLE, "bad enhanced metafile: %p, error %lu\n", h, GetLastError());
    SetLastError(0xdeadbeef);
    h = SetClipboardData(CF_METAFILEPICT, (HANDLE)(ULONG_PTR)0x1234);
    ok(h == NULL && GetLastError() == ERROR_INVALID_HANDLE, "bad metafile picture: %p, error %lu\n", h, GetLastError());
    CloseClipboard();
    ok(!IsClipboardFormatAvailable(CF_ENHMETAFILE) && !IsClipboardFormatAvailable(CF_METAFILEPICT), "a refused metafile is listed\n");
    ok(!IsClipboardFormatAvailable(0x10000) && !IsClipboardFormatAvailable(0xC000), "a refused format is listed\n");

    /* format names */
    SetLastError(0xdeadbeef);
    n = GetClipboardFormatNameA(CF_TEXT, name, sizeof(name));
    ok(n == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "built-in name: %d, error %lu\n", n, GetLastError());
    {
        UINT rf = RegisterClipboardFormatA("ClipboardInteractiveRows format");

        SetLastError(0xdeadbeef);
        n = GetClipboardFormatNameA(rf, name, 0);
        ok(n == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "size 0: %d, error %lu\n", n, GetLastError());
        n = GetClipboardFormatNameA(rf, name, 5);
        ok(n == 4 && !strcmp(name, "Clip"), "small buffer: %d '%s'\n", n, name);
    }

    ResetClipboard();
    DestroyWindow(owner);
}

START_TEST(ClipboardInteractiveRows)
{
    if (!Interactive())
    {
        skip("no clipboard in this window station (not interactive)\n");
        return;
    }

    pAddListener = (void *)GetProcAddress(GetModuleHandleA("user32.dll"), "AddClipboardFormatListener");
    pRemoveListener = (void *)GetProcAddress(GetModuleHandleA("user32.dll"), "RemoveClipboardFormatListener");
    if (!pAddListener || !pRemoveListener)
    {
        skip("no clipboard format listeners\n");
        return;
    }

    test_owner_death();
    test_image_group();
    test_bad_headers();
    test_viewer_chain();
    test_text();
    test_own_handles();
    test_refusals();
}
