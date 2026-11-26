/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A thread on a desktop that does not have the input reads nothing of the screen and draws nothing on it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A second desktop (B) of the test's window station gets a full-screen window of a known colour and the input
 * (SwitchDesktop). Meanwhile this thread, on the desktop it started on (A), takes every route to the screen's pixels: the
 * DC of GetDC(NULL), GetWindowDC / GetDC of the desktop window, CreateDC("DISPLAY"), each fetched fresh and each fetched
 * before the switch and kept. What Windows Server 2022 does with the logon desktop shown (measured by a program on the
 * default desktop across a LockWorkStation, every route alike, before the switch back and with the DC kept or fetched anew):
 * the DC is returned, BitBlt from it fails with ERROR_INVALID_HANDLE and writes nothing, GetPixel returns CLR_INVALID,
 * a fill returns 0 (ours: the batched PatBlt of gdi32 returns TRUE, nothing is drawn); a rectangle drawn meanwhile is not on the monitor. The thread on B reads its own screen as usual, and
 * does not see what A drew. After the switch back A reads and draws as before.
 */

#include "precomp.h"

#define B_COLOR   RGB(0x12, 0xA5, 0x34)
#define A_MARK    RGB(0xFF, 0x00, 0xFF)
#define DESK_B    L"ScreenDesktopReadsB"

static HDESK s_hdeskB;
static HANDLE s_hReady, s_hCmd, s_hDone, s_hQuit;
static volatile LONG s_Cmd;            /* 1: read the screen from B and count the pixels of A_MARK and B_COLOR */
static volatile LONG s_cMarkB, s_cColorB;
static int s_cx, s_cy;

static LRESULT CALLBACK WndProcB(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

/* Counts the pixels of two colours in a copy of the whole screen taken through the DC; -1 when the copy failed */
static BOOL CountScreen(HDC hdc, int *pcMark, int *pcColor, DWORD *pdwError)
{
    HDC hdcMem = CreateCompatibleDC(hdc);
    BITMAPINFO bmi;
    void *pBits = NULL;
    HBITMAP hbm, hbmOld;
    BOOL ret;
    int i, n = s_cx * s_cy;
    DWORD *pdw;

    *pcMark = *pcColor = 0;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = s_cx;
    bmi.bmiHeader.biHeight = -s_cy;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    hbm = CreateDIBSection(hdcMem, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
    if (!hbm)
    {
        DeleteDC(hdcMem);
        *pdwError = 0xFFFFFFFF;
        return FALSE;
    }
    hbmOld = SelectObject(hdcMem, hbm);
    FillMemory(pBits, (SIZE_T)n * 4, 0x5A);   /* what the copy leaves alone stays 0x5A5A5A5A */
    SetLastError(0);
    ret = BitBlt(hdcMem, 0, 0, s_cx, s_cy, hdc, 0, 0, SRCCOPY);
    *pdwError = ret ? 0 : GetLastError();
    GdiFlush();
    pdw = pBits;
    for (i = 0; i < n; i++)
    {
        DWORD px = pdw[i] & 0xFFFFFF;
        if (px == (DWORD)(GetRValue(A_MARK) << 16 | GetGValue(A_MARK) << 8 | GetBValue(A_MARK)))
            (*pcMark)++;
        else if (px == (DWORD)(GetRValue(B_COLOR) << 16 | GetGValue(B_COLOR) << 8 | GetBValue(B_COLOR)))
            (*pcColor)++;
    }
    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    return ret;
}

static DWORD WINAPI ThreadB(LPVOID Param)
{
    HANDLE ahWait[2] = { s_hCmd, s_hQuit };
    WNDCLASSW wc = { 0 };
    HWND hwnd;
    MSG msg;

    if (!SetThreadDesktop(s_hdeskB))
        return 1;
    wc.lpfnWndProc = WndProcB;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"ScreenDesktopReadsClass";
    wc.hbrBackground = CreateSolidBrush(B_COLOR);
    RegisterClassW(&wc);
    hwnd = CreateWindowExW(0, wc.lpszClassName, L"B", WS_POPUP | WS_VISIBLE, 0, 0, s_cx, s_cy, NULL, NULL, wc.hInstance, NULL);
    SetEvent(s_hReady);
    if (!hwnd)
        return 2;
    for (;;)
    {
        DWORD dw = MsgWaitForMultipleObjects(2, ahWait, FALSE, INFINITE, QS_ALLINPUT);
        if (dw == WAIT_OBJECT_0 + 1)
            break;
        if (dw == WAIT_OBJECT_0)
        {
            HDC hdc = GetDC(NULL);
            int cMark = 0, cColor = 0;
            DWORD err;

            if (hdc)
            {
                CountScreen(hdc, &cMark, &cColor, &err);
                ReleaseDC(NULL, hdc);
            }
            s_cMarkB = cMark;
            s_cColorB = cColor;
            SetEvent(s_hDone);
            continue;
        }
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    DestroyWindow(hwnd);
    return 0;
}

typedef struct { const char *name; int kind; HDC hdcHeld; } ROUTE;
enum { K_GETDC_NULL, K_WINDC_DESK, K_GETDC_DESK, K_CREATEDC };

static HDC Acquire(int kind)
{
    switch (kind)
    {
        case K_GETDC_NULL: return GetDC(NULL);
        case K_WINDC_DESK: return GetWindowDC(GetDesktopWindow());
        case K_GETDC_DESK: return GetDC(GetDesktopWindow());
        default:           return CreateDCW(L"DISPLAY", NULL, NULL, NULL);
    }
}

static void Release(int kind, HDC hdc)
{
    if (!hdc)
        return;
    if (kind == K_GETDC_NULL) ReleaseDC(NULL, hdc);
    else if (kind == K_WINDC_DESK || kind == K_GETDC_DESK) ReleaseDC(GetDesktopWindow(), hdc);
    else DeleteDC(hdc);
}

/* The rows of one DC while another desktop has the input */
static void CheckBlind(const char *name, HDC hdc, int ptX, int ptY)
{
    int cMark, cColor;
    DWORD err = 0;
    BOOL ret;
    HBRUSH hbr = CreateSolidBrush(A_MARK);
    RECT rc = { ptX, ptY, ptX + 40, ptY + 40 };

    ok(hdc != NULL, "%s: no DC\n", name);
    if (!hdc)
        return;

    ret = CountScreen(hdc, &cMark, &cColor, &err);
    ok(ret == FALSE, "%s: BitBlt from the screen of the desktop without input succeeded\n", name);
    ok(err == ERROR_INVALID_HANDLE, "%s: BitBlt error %lu, expected 6\n", name, err);
    ok(cColor == 0, "%s: %d pixels of the other desktop's colour were copied\n", name, cColor);
    ok(GetPixel(hdc, s_cx / 2, s_cy / 2) == CLR_INVALID, "%s: GetPixel read 0x%08lx\n", name, GetPixel(hdc, s_cx / 2, s_cy / 2));
    SetLastError(0);
    /* Windows returns 0 here; the batched PatBlt of gdi32 reports success before the kernel refuses it, so only what
       it draws is asserted (nothing: the mark is not on the screen B reads, below) */
    ret = FillRect(hdc, &rc, hbr);
    trace("%s: FillRect on the screen of the desktop without input returned %d\n", name, ret);
    DeleteObject(hbr);
}

START_TEST(ScreenDesktopReads)
{
    static ROUTE fresh[] = { {"GetDC(NULL)", K_GETDC_NULL}, {"GetWindowDC(desktop)", K_WINDC_DESK}, {"GetDC(desktop)", K_GETDC_DESK}, {"CreateDC(DISPLAY)", K_CREATEDC} };
    static ROUTE held[] = { {"kept GetDC(NULL)", K_GETDC_NULL}, {"kept GetWindowDC(desktop)", K_WINDC_DESK}, {"kept GetDC(desktop)", K_GETDC_DESK}, {"kept CreateDC(DISPLAY)", K_CREATEDC} };
    HDESK hdeskA = GetThreadDesktop(GetCurrentThreadId());
    HANDLE hThread;
    HDC hdc;
    int i, n, cMark = 0, cColor;
    DWORD err = 0;
    HBRUSH hbr;
    RECT rc;

    s_cx = GetSystemMetrics(SM_CXSCREEN);
    s_cy = GetSystemMetrics(SM_CYSCREEN);
    s_hReady = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hCmd = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hDone = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_hQuit = CreateEventW(NULL, TRUE, FALSE, NULL);

    s_hdeskB = CreateDesktopW(DESK_B, NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!s_hdeskB)
    {
        skip("CreateDesktop failed (%lu)\n", GetLastError());
        return;
    }

    for (i = 0; i < 4; i++)
        held[i].hdcHeld = Acquire(held[i].kind);

    hThread = CreateThread(NULL, 0, ThreadB, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed\n");
    if (!hThread || WaitForSingleObject(s_hReady, 10000) != WAIT_OBJECT_0)
    {
        skip("the thread on the second desktop did not start\n");
        goto cleanup;
    }

    /* Before: A has the input and reads its own screen */
    hdc = GetDC(NULL);
    ok(CountScreen(hdc, &cMark, &cColor, &err) == TRUE, "BitBlt from the screen of the desktop with the input failed (%lu)\n", err);
    ok(cColor == 0, "the colour of B on the screen before the switch\n");
    ReleaseDC(NULL, hdc);

    if (!SwitchDesktop(s_hdeskB))
    {
        skip("SwitchDesktop failed (%lu)\n", GetLastError());
        goto cleanup;
    }

    /* B has the input: its thread reads the screen, with its colour on it */
    for (i = 0; i < 50; i++)
    {
        SetEvent(s_hCmd);
        WaitForSingleObject(s_hDone, 5000);
        if (s_cColorB > (s_cx * s_cy) / 2)
            break;
        Sleep(100);
    }
    ok(s_cColorB > (s_cx * s_cy) / 2, "B reads %ld pixels of its own colour (of %d)\n", s_cColorB, s_cx * s_cy);

    /* A has no input: every route is blind and cannot draw */
    for (i = 0; i < 4; i++)
    {
        hdc = Acquire(fresh[i].kind);
        CheckBlind(fresh[i].name, hdc, 100 + 60 * i, 100);
        Release(fresh[i].kind, hdc);
    }
    for (i = 0; i < 4; i++)
        CheckBlind(held[i].name, held[i].hdcHeld, 100 + 60 * i, 200);

    /* what A drew is not on the screen B reads */
    SetEvent(s_hCmd);
    WaitForSingleObject(s_hDone, 5000);
    ok(s_cMarkB == 0, "%ld pixels A drew while B had the input are on B's screen\n", s_cMarkB);
    ok(s_cColorB > (s_cx * s_cy) / 2, "B's screen lost its colour (%ld pixels)\n", s_cColorB);

    /* back to A: reads and draws as before, also with the DCs kept over the switch */
    ok(SwitchDesktop(hdeskA), "SwitchDesktop back failed (%lu)\n", GetLastError());
    hbr = CreateSolidBrush(A_MARK);
    rc.left = 300; rc.top = 300; rc.right = 340; rc.bottom = 340;
    for (i = 0; i < 4; i++)
    {
        hdc = held[i].hdcHeld;
        ok(hdc != NULL, "%s: no DC\n", held[i].name);
        if (!hdc)
            continue;
        /* The windows of A repaint after the switch back and may paint over the mark between the draw and the read: try again */
        for (n = 0; n < 20; n++)
        {
            ok(FillRect(hdc, &rc, hbr) != 0, "%s: FillRect after the switch back failed (%lu)\n", held[i].name, GetLastError());
            if (GetPixel(hdc, 320, 320) == A_MARK &&
                CountScreen(hdc, &cMark, &cColor, &err) && cMark >= 40 * 40)
                break;
            Sleep(100);
        }
        ok(n < 20, "%s: the mark was not read back after the switch back (GetPixel 0x%08lx, %d pixels, error %lu)\n",
           held[i].name, GetPixel(hdc, 320, 320), cMark, err);
    }
    DeleteObject(hbr);

cleanup:
    SwitchDesktop(hdeskA);
    for (i = 0; i < 4; i++)
        Release(held[i].kind, held[i].hdcHeld);
    SetEvent(s_hQuit);
    if (hThread)
    {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    CloseDesktop(s_hdeskB);
    CloseHandle(s_hReady);
    CloseHandle(s_hCmd);
    CloseHandle(s_hDone);
    CloseHandle(s_hQuit);
}
