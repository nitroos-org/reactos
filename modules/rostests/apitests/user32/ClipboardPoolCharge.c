/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What the clipboard keeps in paged pool: data a call could not hand to the clipboard goes back,
 *              the clipboard refuses what it may not hold, and what it drops is given back
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The rows count the paged pool of the system (SystemPerformanceInformation). Windows is not measured here:
 * the limit below is this system's own (it keeps its clipboard data in paged pool).
 */

#include "precomp.h"

typedef LONG (NTAPI *PFN_QSI)(ULONG, PVOID, ULONG, PULONG);

/* The paged pool in use, in megabytes; -1 when it cannot be read */
static LONG PagedPoolMB(void)
{
    static PFN_QSI pQuery;
    ULONG buf[128];

    if (!pQuery)
        pQuery = (PFN_QSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!pQuery)
        return -1;
    memset(buf, 0, sizeof(buf));
    /* SystemPerformanceInformation: PagedPoolPages follows 4 LARGE_INTEGERs, 3 and 17 ULONGs */
    if (pQuery(2, buf, sizeof(buf), NULL) != 0)
        return -1;
    return (LONG)(buf[8 + 3 + 17] / 256);
}

static HGLOBAL MakeBlock(SIZE_T cb)
{
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, cb);
    char *p;

    if (hMem)
    {
        p = GlobalLock(hMem);
        if (p)
        {
            p[0] = 'a';
            p[cb - 1] = 0;
            GlobalUnlock(hMem);
        }
    }
    return hMem;
}

/* SetClipboardData without the clipboard being open fails: the copy the system made of the data must not stay */
static void test_NotOpen(void)
{
    LONG before, after;
    int i;
    HANDLE hRet;

    before = PagedPoolMB();
    for (i = 0; i < 40; i++)
    {
        HGLOBAL hMem = MakeBlock(8 * 1024 * 1024);

        if (!hMem)
            break;
        SetLastError(0xdeadbeef);
        hRet = SetClipboardData(CF_TEXT, hMem);
        ok(hRet == NULL, "SetClipboardData without OpenClipboard returned %p\n", hRet);
        GlobalFree(hMem);
    }
    after = PagedPoolMB();

    if (before < 0)
    {
        skip("the paged pool cannot be read\n");
        return;
    }
    /* 40 x 8 MB were handed over: nothing of that may be left (the paged pool also moves by other activity) */
    ok(after - before < 64, "paged pool grew from %ld to %ld MB\n", before, after);
}

/* The clipboard can be used again after a refusal, and after its data was dropped */
static void test_Roundtrip(void)
{
    HGLOBAL hMem = MakeBlock(1024 * 1024);
    HANDLE hRet, hGet;

    if (!hMem)
    {
        skip("no memory\n");
        return;
    }
    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    ok(EmptyClipboard(), "EmptyClipboard failed %lu\n", GetLastError());
    hRet = SetClipboardData(CF_TEXT, hMem);
    ok(hRet != NULL, "SetClipboardData failed %lu\n", GetLastError());
    hGet = GetClipboardData(CF_TEXT);
    ok(hGet != NULL, "GetClipboardData failed %lu\n", GetLastError());
    if (hGet)
        ok(GlobalSize(hGet) >= 1024 * 1024, "size %lu\n", (ULONG)GlobalSize(hGet));
    EmptyClipboard();
    CloseClipboard();
}

#ifndef _WIN64
/* A 32 bit system has about 360 MB of paged pool: what the clipboard may hold is 288 MB */
static void test_Limit(void)
{
    HGLOBAL hBig = MakeBlock(300 * 1024 * 1024);
    HANDLE hRet;
    DWORD dwError;

    if (!hBig)
    {
        skip("no 300 MB of memory\n");
        return;
    }
    ok(OpenClipboard(NULL), "OpenClipboard failed %lu\n", GetLastError());
    EmptyClipboard();
    SetLastError(0xdeadbeef);
    hRet = SetClipboardData(CF_TEXT, hBig);
    dwError = GetLastError();
    ok(hRet == NULL, "300 MB were taken\n");
    ok(dwError == ERROR_NOT_ENOUGH_MEMORY, "error %lu\n", dwError);
    EmptyClipboard();
    CloseClipboard();
    GlobalFree(hBig);

    /* the refusal left nothing charged */
    test_Roundtrip();
}
#endif

START_TEST(ClipboardPoolCharge)
{
    test_NotOpen();
    test_Roundtrip();
#ifndef _WIN64
    test_Limit();
#endif
}
