/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     SetWindowPos refuses the flags that only win32k itself uses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows 10 22H2, a hidden and a visible overlapped window: SetWindowPos with SWP_NOCLIENTSIZE (0x800),
 * SWP_NOCLIENTMOVE (0x1000), SWP_STATECHANGED (0x8000) or the top bit fails with ERROR_INVALID_FLAGS and sends no
 * message at all (the window procedure sees nothing). The bits above SWP_ASYNCWINDOWPOS (0x10000, 0x20000)
 * were measured to pass. */

#ifndef SWP_NOCLIENTSIZE
#define SWP_NOCLIENTSIZE 0x0800
#define SWP_NOCLIENTMOVE 0x1000
#define SWP_STATECHANGED 0x8000
#endif

static INT g_cMessages;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_WINDOWPOSCHANGING || uMsg == WM_WINDOWPOSCHANGED || uMsg == WM_NCCALCSIZE)
        g_cMessages++;
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void Pump(void)
{
    MSG Msg;
    DWORD Start = GetTickCount();

    while (GetTickCount() - Start < 100)
    {
        while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&Msg);
        Sleep(10);
    }
}

static void CheckFlags(int line, HWND hwnd, const char *what)
{
    static const UINT Refused[] =
    {
        0x183f, 0x0837, 0x1037, 0x1837, 0x0c3f, 0x8037, SWP_NOCLIENTSIZE | SWP_NOMOVE | SWP_NOSIZE,
        SWP_NOCLIENTMOVE | SWP_NOMOVE | SWP_NOSIZE, 0x80000037
    };
    static const UINT Accepted[] = { 0x003f, 0x0037, 0x0027, 0x0237, 0x2037, 0x4037, 0x10037, 0x20037 };
    UINT i;
    BOOL ret;

    for (i = 0; i < ARRAYSIZE(Refused); i++)
    {
        g_cMessages = 0;
        SetLastError(0xdeadbeef);
        ret = SetWindowPos(hwnd, NULL, 0, 0, 0, 0, Refused[i]);
        Pump();
        ok_(__FILE__, line)(!ret, "%s: SetWindowPos %x succeeded\n", what, Refused[i]);
        ok_(__FILE__, line)(GetLastError() == ERROR_INVALID_FLAGS, "%s: SetWindowPos %x error %lu\n", what, Refused[i], GetLastError());
        ok_(__FILE__, line)(g_cMessages == 0, "%s: SetWindowPos %x sent %d messages\n", what, Refused[i], g_cMessages);
    }
    for (i = 0; i < ARRAYSIZE(Accepted); i++)
    {
        SetLastError(0xdeadbeef);
        ret = SetWindowPos(hwnd, NULL, 0, 0, 0, 0, Accepted[i]);
        Pump();
        ok_(__FILE__, line)(ret, "%s: SetWindowPos %x failed, error %lu\n", what, Accepted[i], GetLastError());
    }
}

START_TEST(SetWindowPosFlags)
{
    WNDCLASSW wc = { 0 };
    HWND hwndHidden, hwndVisible;

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SetWindowPosFlagsTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    hwndHidden = CreateWindowExW(0, wc.lpszClassName, L"hidden", WS_OVERLAPPEDWINDOW, 20, 20, 300, 200, NULL, NULL, wc.hInstance, NULL);
    hwndVisible = CreateWindowExW(0, wc.lpszClassName, L"visible", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 400, 20, 300, 200, NULL, NULL, wc.hInstance, NULL);
    ok(hwndHidden && hwndVisible, "windows not created\n");
    if (hwndHidden && hwndVisible)
    {
        Pump();
        CheckFlags(__LINE__, hwndHidden, "hidden window");
        CheckFlags(__LINE__, hwndVisible, "visible window");
    }

    if (hwndHidden)
        DestroyWindow(hwndHidden);
    if (hwndVisible)
        DestroyWindow(hwndVisible);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
