/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         Metafile formats on the clipboard: the handle that was put there comes back, and the process
 *                  holds no GDI object of them once the clipboard is emptied (measured on Windows Server 2022)
 */

#include "precomp.h"

static const UINT g_Formats[] = { CF_ENHMETAFILE, CF_METAFILEPICT, CF_DSPENHMETAFILE, CF_DSPMETAFILEPICT };

static DWORD GdiCount(void)
{
    return GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
}

static HENHMETAFILE MakeEmf(void)
{
    HDC hdc = CreateEnhMetaFileW(NULL, NULL, NULL, NULL);

    Rectangle(hdc, 0, 0, 100, 100);
    LineTo(hdc, 100, 100);
    return CloseEnhMetaFile(hdc);
}

static HGLOBAL MakeMetaFilePict(void)
{
    HDC hdc = CreateMetaFileW(NULL);
    HMETAFILE hmf;
    HGLOBAL hGlobal;
    METAFILEPICT *pInfo;

    Rectangle(hdc, 0, 0, 100, 100);
    hmf = CloseMetaFile(hdc);
    hGlobal = GlobalAlloc(GMEM_MOVEABLE, sizeof(*pInfo));
    pInfo = GlobalLock(hGlobal);
    pInfo->mm = MM_ANISOTROPIC;
    pInfo->xExt = 1000;
    pInfo->yExt = 1000;
    pInfo->hMF = hmf;
    GlobalUnlock(hGlobal);
    return hGlobal;
}

/* EmptyClipboard, SetClipboardData of a metafile, GetClipboardData of every format, CloseClipboard */
static void RoundTrip(UINT uSetFormat, BOOL bGetTwice, BOOL bReopen)
{
    HANDLE hSet;
    UINT i;

    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    hSet = (uSetFormat == CF_ENHMETAFILE) ? (HANDLE)MakeEmf() : (HANDLE)MakeMetaFilePict();
    SetClipboardData(uSetFormat, hSet);
    if (bReopen)
    {
        /* the formats that the system makes from the one that was put there are listed once the clipboard is closed */
        CloseClipboard();
        ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    }
    for (i = 0; i < _countof(g_Formats); i++)
    {
        GetClipboardData(g_Formats[i]);
        if (bGetTwice)
            GetClipboardData(g_Formats[i]);
    }
    CloseClipboard();
}

static void test_enhmetafile_handle(void)
{
    HENHMETAFILE hemf;
    HANDLE hSet, hGet1, hGet2;
    ENHMETAHEADER emh;
    DWORD cBase, cSet, cGet;

    cBase = GdiCount();
    hemf = MakeEmf();
    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    hSet = SetClipboardData(CF_ENHMETAFILE, hemf);
    ok(hSet == hemf, "SetClipboardData returned %p, not %p\n", hSet, hemf);
    cSet = GdiCount();
    hGet1 = GetClipboardData(CF_ENHMETAFILE);
    hGet2 = GetClipboardData(CF_ENHMETAFILE);
    cGet = GdiCount();
    ok(hGet1 == hemf, "GetClipboardData returned %p, the handle that was put there is %p\n", hGet1, hemf);
    ok(hGet2 == hGet1, "the second call returned %p, the first %p\n", hGet2, hGet1);
    ok(cGet == cSet, "GetClipboardData made GDI objects: %lu -> %lu\n", cSet, cGet);
    CloseClipboard();
    ok(GetEnhMetaFileHeader(hemf, sizeof(emh), &emh) != 0, "the metafile is gone after CloseClipboard\n");

    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    CloseClipboard();
    ok(GdiCount() == cBase, "GDI objects after EmptyClipboard: %lu, before: %lu\n", GdiCount(), cBase);
    ok(GetEnhMetaFileHeader(hemf, sizeof(emh), &emh) == 0, "the metafile is still valid after EmptyClipboard\n");
}

static void test_metafilepict_handle(void)
{
    HGLOBAL hGlobal;
    HANDLE hSet, hGet1, hGet2;
    DWORD cBase, cSet, cGet;

    cBase = GdiCount();
    hGlobal = MakeMetaFilePict();
    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    hSet = SetClipboardData(CF_METAFILEPICT, hGlobal);
    ok(hSet == hGlobal, "SetClipboardData returned %p, not %p\n", hSet, hGlobal);
    cSet = GdiCount();
    hGet1 = GetClipboardData(CF_METAFILEPICT);
    hGet2 = GetClipboardData(CF_METAFILEPICT);
    cGet = GdiCount();
    ok(hGet1 == hGlobal, "GetClipboardData returned %p, the handle that was put there is %p\n", hGet1, hGlobal);
    ok(hGet2 == hGet1, "the second call returned %p, the first %p\n", hGet2, hGet1);
    ok(cGet == cSet, "GetClipboardData made GDI objects: %lu -> %lu\n", cSet, cGet);
    CloseClipboard();

    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    CloseClipboard();
    ok(GdiCount() == cBase, "GDI objects after EmptyClipboard: %lu, before: %lu\n", GdiCount(), cBase);
    ok(GlobalFlags(hGlobal) == GMEM_INVALID_HANDLE, "the block is still valid after EmptyClipboard\n");
}

static void test_growth(UINT uSetFormat, const char *pszName, BOOL bReopen)
{
    DWORD cBase, cAfter;
    UINT i;
    const UINT cRounds = 200;

    RoundTrip(uSetFormat, FALSE, bReopen); /* once for lazy initialisation */
    OpenClipboard(NULL); EmptyClipboard(); CloseClipboard();
    cBase = GdiCount();
    for (i = 0; i < cRounds; i++)
        RoundTrip(uSetFormat, i & 1, bReopen);
    OpenClipboard(NULL); EmptyClipboard(); CloseClipboard();
    cAfter = GdiCount();
    ok(cAfter == cBase, "%s%s: %u round trips: GDI objects %lu -> %lu\n", pszName, bReopen ? " (reopened)" : "", cRounds, cBase, cAfter);
}

/* a second metafile put into the format frees the first one */
static void test_replace(void)
{
    HENHMETAFILE h1 = MakeEmf(), h2 = MakeEmf();
    ENHMETAHEADER emh;

    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    SetClipboardData(CF_ENHMETAFILE, h1);
    SetClipboardData(CF_ENHMETAFILE, h2);
    ok(GetClipboardData(CF_ENHMETAFILE) == h2, "the second handle is not what the clipboard returns\n");
    CloseClipboard();
    ok(GetEnhMetaFileHeader(h1, sizeof(emh), &emh) == 0, "the first metafile is still valid after the second replaced it\n");
    OpenClipboard(NULL); EmptyClipboard(); CloseClipboard();
}

START_TEST(ClipboardMetafileLifetime)
{
    test_enhmetafile_handle();
    test_metafilepict_handle();
    test_growth(CF_ENHMETAFILE, "CF_ENHMETAFILE", FALSE);
    test_growth(CF_METAFILEPICT, "CF_METAFILEPICT", FALSE);
    test_growth(CF_ENHMETAFILE, "CF_ENHMETAFILE", TRUE);
    test_growth(CF_METAFILEPICT, "CF_METAFILEPICT", TRUE);
    test_replace();
}
