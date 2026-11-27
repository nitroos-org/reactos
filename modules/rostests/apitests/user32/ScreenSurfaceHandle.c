/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The bitmap handle of a screen DC does not reach the screen from a desktop without the input
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * GetCurrentObject(OBJ_BITMAP) of a screen DC gives the handle of the screen's own surface. The test shows a window of a
 * known colour on its own desktop (which has the input), then a thread on a scratch desktop of the test (never switched to)
 * passes that handle to every call that takes a bitmap: GetDIBits, GetBitmapBits, SetBitmapBits, SelectObject into a
 * memory DC, CreatePatternBrush and MaskBlt with it as the mask. None may read or write the screen: nothing of the
 * window's colour arrives, and the window keeps its colour. On the desktop with the input GetBitmapBits of the handle
 * must return without stopping the system (it asserted on a surface whose rows are not those of a bitmap).
 * The same thread also tries the DCs of the display that belong to no process (the system's screen DC, the cache DCs
 * GetDC takes back): every process can find them in the GDI handle table, and none may copy the other desktop's screen.
 */

#include "precomp.h"

#define A_COLOR RGB(0xB4, 0x2A, 0x6E)
#define A_PIXEL ((DWORD)((GetRValue(A_COLOR) << 16) | (GetGValue(A_COLOR) << 8) | GetBValue(A_COLOR)))

static HDESK s_hdeskB;
static HBITMAP s_hbmScreen;
static int s_cx, s_cy;

static int CountColor(const DWORD *p, int n)
{
    int i, c = 0;
    for (i = 0; i < n; i++)
        if ((p[i] & 0xFFFFFF) == A_PIXEL)
            c++;
    return c;
}

static HBITMAP MakeDib(HDC hdc, int cx, int cy, DWORD **ppBits)
{
    BITMAPINFO bi = { { sizeof(BITMAPINFOHEADER) } };
    bi.bmiHeader.biWidth = cx;
    bi.bmiHeader.biHeight = -cy;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    return CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, (void **)ppBits, NULL, 0);
}


/* The public DCs of the shared GDI handle table (GDI_TABLE_ENTRY: kernel pointer, owner, unique and type, user pointer) */
static void TestPublicDCs(HDC hdcMem, DWORD *pDib)
{
    BYTE *pPeb = *(BYTE **)((BYTE *)NtCurrentTeb() + (sizeof(void *) == 8 ? 0x60 : 0x30));
    BYTE *pTable = *(BYTE **)(pPeb + (sizeof(void *) == 8 ? 0xF8 : 0x94));
    SIZE_T cbEntry = 2 * sizeof(void *) + 8;
    BOOL bWow64 = FALSE;
    int i, cTried = 0, cRead = 0;

    IsWow64Process(GetCurrentProcess(), &bWow64);
    if (!pTable || bWow64)
    {
        skip("no GDI handle table to scan\n");
        return;
    }
    for (i = 0; i < 0x10000 && cTried < 32; i++)
    {
        BYTE *pEntry = pTable + i * cbEntry;
        if (*(void **)pEntry && *(DWORD *)(pEntry + sizeof(void *)) == 0 && pEntry[sizeof(void *) + 6] == 1)
        {
            HDC hdc = (HDC)(ULONG_PTR)(((ULONG)*(USHORT *)(pEntry + sizeof(void *) + 4) << 16) | i);
            ZeroMemory(pDib, 64 * 64 * 4);
            BitBlt(hdcMem, 0, 0, 64, 64, hdc, 0, 0, SRCCOPY);
            GdiFlush();
            if (CountColor(pDib, 64 * 64))
                cRead++;
            cTried++;
        }
    }
    trace("%d public DCs tried\n", cTried);
    ok(cRead == 0, "%d public DCs copied the other desktop's screen\n", cRead);
}

static DWORD WINAPI ThreadB(LPVOID Param)
{
    HDC hdcScreen, hdcMem;
    HBITMAP hbm, hbmDib;
    HGDIOBJ hOld;
    HBRUSH hbr;
    DWORD *pDib;
    DWORD *pBuf;
    BITMAPINFO bi = { { sizeof(BITMAPINFOHEADER) } };
    RECT rc = { 0, 0, 64, 64 };
    LONG ret;
    int lines;

    if (!SetThreadDesktop(s_hdeskB))
    {
        skip("SetThreadDesktop failed (%lu)\n", GetLastError());
        return 1;
    }

    hdcScreen = GetDC(NULL);
    hbm = (HBITMAP)GetCurrentObject(hdcScreen, OBJ_BITMAP);
    ok(hbm == s_hbmScreen, "the screen bitmap of desktop B is %p, of A %p\n", hbm, s_hbmScreen);
    hbm = s_hbmScreen;
    hdcMem = CreateCompatibleDC(NULL);

    pBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)s_cx * 64 * 4);
    bi.bmiHeader.biWidth = s_cx;
    bi.bmiHeader.biHeight = -64;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    lines = GetDIBits(hdcMem, hbm, 0, 64, pBuf, &bi, DIB_RGB_COLORS);
    ok(lines == 0, "GetDIBits of the screen bitmap returned %d lines\n", lines);
    ok(CountColor(pBuf, s_cx * 64) == 0, "GetDIBits gave pixels of the other desktop\n");

    ZeroMemory(pBuf, (SIZE_T)s_cx * 64 * 4);
    ret = GetBitmapBits(hbm, s_cx * 64 * 4, pBuf);
    ok(ret == 0, "GetBitmapBits of the screen bitmap returned %ld\n", ret);
    ok(CountColor(pBuf, s_cx * 64) == 0, "GetBitmapBits gave pixels of the other desktop\n");

    ret = SetBitmapBits(hbm, s_cx * 64 * 4, pBuf);
    ok(ret == 0, "SetBitmapBits of the screen bitmap returned %ld\n", ret);

    hOld = SelectObject(hdcMem, hbm);
    ok(hOld == NULL, "the screen bitmap was selected into a memory DC\n");
    if (hOld)
        SelectObject(hdcMem, hOld);

    hbr = CreatePatternBrush(hbm);
    ok(hbr == NULL, "a pattern brush was made of the screen bitmap\n");
    hbmDib = MakeDib(hdcMem, 64, 64, &pDib);
    hOld = SelectObject(hdcMem, hbmDib);
    if (hbr)
    {
        FillRect(hdcMem, &rc, hbr);
        GdiFlush();
        ok(CountColor(pDib, 64 * 64) == 0, "the pattern brush painted pixels of the other desktop\n");
        DeleteObject(hbr);
    }

    /* The screen bitmap as the mask of a MaskBlt: a mask is read from the bitmap */
    ok(MaskBlt(hdcMem, 0, 0, 64, 64, hdcMem, 0, 0, hbm, 0, 0, MAKEROP4(WHITENESS, BLACKNESS)) == FALSE,
       "MaskBlt took the screen bitmap as its mask\n");

    TestPublicDCs(hdcMem, pDib);

    SelectObject(hdcMem, hOld);
    DeleteObject(hbmDib);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    HeapFree(GetProcessHeap(), 0, pBuf);
    return 0;
}

static LRESULT CALLBACK WndProcA(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void Pump(DWORD ms)
{
    DWORD t = GetTickCount();
    MSG msg;
    while (GetTickCount() - t < ms)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(10);
    }
}

START_TEST(ScreenSurfaceHandle)
{
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    HDC hdc;
    HANDLE hThread;
    BITMAP bm;
    LONG cb;
    BYTE *pBuf;

    s_cx = GetSystemMetrics(SM_CXSCREEN);
    s_cy = GetSystemMetrics(SM_CYSCREEN);
    wc.lpfnWndProc = WndProcA;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ScreenSurfaceHandleA";
    wc.hbrBackground = CreateSolidBrush(A_COLOR);
    RegisterClassW(&wc);
    hwnd = CreateWindowExW(WS_EX_TOPMOST, wc.lpszClassName, L"A", WS_POPUP | WS_VISIBLE, 0, 0, s_cx, s_cy, NULL, NULL, wc.hInstance, NULL);
    ok(hwnd != NULL, "CreateWindowEx failed (%lu)\n", GetLastError());
    UpdateWindow(hwnd);
    Pump(500);

    hdc = GetDC(NULL);
    s_hbmScreen = (HBITMAP)GetCurrentObject(hdc, OBJ_BITMAP);
    if (!s_hbmScreen)
    {
        skip("a screen DC has no bitmap handle\n");
        ReleaseDC(NULL, hdc);
        DestroyWindow(hwnd);
        return;
    }

    /* The desktop with the input: GetBitmapBits of the screen bitmap returns (a value), the system goes on */
    ZeroMemory(&bm, sizeof(bm));
    GetObjectW(s_hbmScreen, sizeof(bm), &bm);
    cb = bm.bmWidthBytes * 8;
    if (cb <= 0)
        cb = s_cx * 4 * 8;
    pBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
    GetBitmapBits(s_hbmScreen, cb, pBuf);
    HeapFree(GetProcessHeap(), 0, pBuf);
    ok(1, "GetBitmapBits of the screen bitmap returned\n");

    s_hdeskB = CreateDesktopW(L"ScreenSurfaceHandleB", NULL, NULL, 0, GENERIC_ALL, NULL);
    ok(s_hdeskB != NULL, "CreateDesktop failed (%lu)\n", GetLastError());
    if (s_hdeskB)
    {
        hThread = CreateThread(NULL, 0, ThreadB, NULL, 0, NULL);
        while (MsgWaitForMultipleObjects(1, &hThread, FALSE, 30000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
            Pump(10);
        CloseHandle(hThread);
        CloseDesktop(s_hdeskB);
    }

    /* SetBitmapBits from B wrote nothing: the window keeps its colour */
    Pump(300);
    ok(GetPixel(hdc, 10, 10) == A_COLOR, "the screen was changed from the other desktop (0x%08lx)\n", GetPixel(hdc, 10, 10));
    ReleaseDC(NULL, hdc);
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
