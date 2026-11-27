/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A process of a lower integrity level reads of a window what the screen shows, not what the window's
 *              surface holds where it is covered (window surfaces on amd64)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * This process (Medium or above) shows window A, partly covered by window B (both of this process, topmost). It reads
 * the covered point itself through GetDC(A): with surfaces that is A's own colour (recorded, nothing asserted: on i386
 * it is what the screen shows). A child of Low integrity (a duplicate of the caller's token lowered with
 * SetTokenInformation, CreateProcessAsUser as in MandatoryLabelOpen) takes GetDC(A) and GetWindowDC(A) of this process's
 * window: at the covered point GetPixel and BitBlt must not return A's colour (the screen shows B there), at a visible
 * point they do, and PrintWindow with PW_RENDERFULLCONTENT (the copy of a surface) fails. The PrintWindow message path
 * (flags 0) crosses integrity levels on every architecture (no UIPI) and is not asserted.
 */

#include "precomp.h"
#include <strsafe.h>

#define PW_RENDERFULLCONTENT_ 0x00000002
#define ACOLOUR RGB(0xC0, 0xB0, 0xA0)
#define BCOLOUR RGB(0x20, 0x90, 0x40)

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_PRINTCLIENT)
    {
        RECT rc;
        HBRUSH hbr = CreateSolidBrush(GetWindowLongW(hwnd, GWL_USERDATA));

        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, hbr);
        DeleteObject(hbr);
        return 0;
    }
    if (uMsg == WM_ERASEBKGND)
    {
        RECT rc;
        HBRUSH hbr = CreateSolidBrush(GetWindowLongW(hwnd, GWL_USERDATA));

        GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, hbr);
        DeleteObject(hbr);
        return 1;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static COLORREF PixelOf(HDC hdc, int x, int y)
{
    return GetPixel(hdc, x, y);
}

static COLORREF BlitPixel(HDC hdc, int x, int y)
{
    HDC hdcMem = CreateCompatibleDC(hdc);
    HBITMAP hbm = CreateCompatibleBitmap(hdc, 8, 8), hbmOld = SelectObject(hdcMem, hbm);
    COLORREF Ret = CLR_INVALID;

    PatBlt(hdcMem, 0, 0, 8, 8, BLACKNESS);
    if (BitBlt(hdcMem, 0, 0, 8, 8, hdc, x, y, SRCCOPY))
        Ret = GetPixel(hdcMem, 2, 2);
    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    return Ret;
}

/* Child: argv[3] = hwnd of A (decimal) */
static void Child(HWND hwndA)
{
    HDC hdcA, hdcW, hdcMem;
    HBITMAP hbm, hbmOld;
    BOOL Ret;

    /* Client of A: 300 x 200 at (100, 100); B covers x >= 300 on the screen: client x >= 200 */
    hdcA = GetDC(hwndA);
    ok(hdcA != NULL, "child: GetDC of the window failed (%lu)\n", GetLastError());
    if (hdcA)
    {
        COLORREF c = PixelOf(hdcA, 50, 100), cov = PixelOf(hdcA, 250, 100);
        COLORREF bc = BlitPixel(hdcA, 50, 100), bcov = BlitPixel(hdcA, 250, 100);

        trace("child: GetDC visible %08lx covered %08lx, BitBlt visible %08lx covered %08lx\n", c, cov, bc, bcov);
        ok(cov != ACOLOUR, "child: GetPixel at the covered point read the window's colour %08lx\n", cov);
        ok(bcov != ACOLOUR, "child: BitBlt at the covered point read the window's colour %08lx\n", bcov);
        ok(c == ACOLOUR, "child: GetPixel at the visible point read %08lx, not the window's colour\n", c);
        ok(bc == ACOLOUR, "child: BitBlt at the visible point read %08lx, not the window's colour\n", bc);
        ReleaseDC(hwndA, hdcA);
    }

    hdcW = GetWindowDC(hwndA);
    ok(hdcW != NULL, "child: GetWindowDC of the window failed (%lu)\n", GetLastError());
    if (hdcW)
    {
        /* the window DC origin is the window's corner: the same covered point is at 250 + the frame (0: a popup) */
        COLORREF cov = PixelOf(hdcW, 250, 100);

        trace("child: GetWindowDC covered %08lx\n", cov);
        ok(cov != ACOLOUR, "child: GetWindowDC GetPixel at the covered point read the window's colour %08lx\n", cov);
        ReleaseDC(hwndA, hdcW);
    }

    hdcMem = CreateCompatibleDC(NULL);
    hbm = CreateBitmap(300, 200, 1, 32, NULL);
    hbmOld = SelectObject(hdcMem, hbm);
    SetLastError(0);
    Ret = PrintWindow(hwndA, hdcMem, PW_RENDERFULLCONTENT_);
    trace("child: PrintWindow(PW_RENDERFULLCONTENT) %d (%lu)\n", Ret, GetLastError());
    ok(!Ret, "child: PrintWindow with PW_RENDERFULLCONTENT copied the surface of a window of a higher integrity level\n");
    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
}

static BOOL LoweredToken(PHANDLE Out)
{
    SID_IDENTIFIER_AUTHORITY LabelAuth = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    TOKEN_MANDATORY_LABEL Label;
    HANDLE Token;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Token))
        return FALSE;
    Ret = DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, Out);
    CloseHandle(Token);
    if (!Ret)
        return FALSE;
    InitializeSid((PSID)Sid, &LabelAuth, 1);
    *GetSidSubAuthority((PSID)Sid, 0) = SECURITY_MANDATORY_LOW_RID;
    Label.Label.Sid = (PSID)Sid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Ret = SetTokenInformation(*Out, TokenIntegrityLevel, &Label, sizeof(Label) + GetLengthSid((PSID)Sid));
    if (!Ret)
        CloseHandle(*Out);
    return Ret;
}

static DWORD LevelOf(void)
{
    BYTE Buffer[256];
    HANDLE Token;
    DWORD Length, Level = 0;
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        if (GetTokenInformation(Token, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length))
            Level = *GetSidSubAuthority(Label->Label.Sid, *GetSidSubAuthorityCount(Label->Label.Sid) - 1);
        CloseHandle(Token);
    }
    return Level;
}

START_TEST(RedirIntegrity)
{
    char **Argv;
    WNDCLASSW wc = { 0 };
    HWND hwndA, hwndB;
    HANDLE Low = NULL;
    WCHAR Path[MAX_PATH], Command[MAX_PATH * 2];
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Pi;
    HDC hdc;
    COLORREF Own;
    MSG msg;
    DWORD Wait;

    if (winetest_get_mainargs(&Argv) >= 4 && !strcmp(Argv[2], "child"))
    {
        Child((HWND)(ULONG_PTR)strtoul(Argv[3], NULL, 10));
        return;
    }

    if (LevelOf() < SECURITY_MANDATORY_MEDIUM_RID)
    {
        skip("the test needs a caller at Medium or above\n");
        return;
    }

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"RedirIntegrityClass";
    RegisterClassW(&wc);
    hwndA = CreateWindowExW(WS_EX_TOPMOST, wc.lpszClassName, L"A", WS_POPUP | WS_VISIBLE, 100, 100, 300, 200, NULL, NULL, wc.hInstance, NULL);
    SetWindowLongW(hwndA, GWL_USERDATA, ACOLOUR);
    hwndB = CreateWindowExW(WS_EX_TOPMOST, wc.lpszClassName, L"B", WS_POPUP | WS_VISIBLE, 300, 100, 200, 200, NULL, NULL, wc.hInstance, NULL);
    SetWindowLongW(hwndB, GWL_USERDATA, BCOLOUR);
    ok(hwndA && hwndB, "windows not created\n");
    if (!hwndA || !hwndB)
        return;
    RedrawWindow(hwndA, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
    RedrawWindow(hwndB, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&msg);
    Sleep(300);

    /* the reader at the same level: unchanged, whatever it was (A's colour with surfaces, what the screen shows without) */
    hdc = GetDC(hwndA);
    Own = hdc ? GetPixel(hdc, 250, 100) : CLR_INVALID;
    trace("same level: covered point %08lx (A's colour is %08lx, B's %08lx)\n", Own, ACOLOUR, BCOLOUR);
    if (hdc)
        ReleaseDC(hwndA, hdc);
    hdc = GetDC(hwndA);
    ok(hdc && GetPixel(hdc, 50, 100) == ACOLOUR, "the same-level reader lost the visible point\n");
    if (hdc)
        ReleaseDC(hwndA, hdc);

    if (!LoweredToken(&Low))
    {
        skip("no lowered token (%lu)\n", GetLastError());
        goto cleanup;
    }
    GetModuleFileNameW(NULL, Path, _countof(Path));
    StringCchPrintfW(Command, _countof(Command), L"\"%s\" RedirIntegrity child %lu", Path, (ULONG)(ULONG_PTR)hwndA);
    Startup.dwFlags = STARTF_USESTDHANDLES;
    Startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    Startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    Startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessAsUserW(Low, Path, Command, NULL, NULL, TRUE, 0, NULL, NULL, &Startup, &Pi))
    {
        skip("CreateProcessAsUser failed (%lu)\n", GetLastError());
        goto cleanup;
    }
    /* this process keeps its windows alive and answers messages (PrintWindow asks the owner's thread) while the child reads */
    for (;;)
    {
        Wait = MsgWaitForMultipleObjects(1, &Pi.hProcess, FALSE, 60000, QS_ALLINPUT);
        if (Wait == WAIT_OBJECT_0 + 1)
        {
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
                DispatchMessageW(&msg);
            continue;
        }
        break;
    }
    ok(Wait == WAIT_OBJECT_0, "the child did not finish\n");
    {
        DWORD Code = 1;

        GetExitCodeProcess(Pi.hProcess, &Code);
        ok(Code == 0, "the child reported %lu failures\n", Code);
    }
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);

cleanup:
    if (Low)
        CloseHandle(Low);
    DestroyWindow(hwndA);
    DestroyWindow(hwndB);
}
