/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DefWindowProc(WM_CANCELMODE) and EnableWindow leave the last error alone when no menu is open.
 *              Chromium (WebView2) takes a non-zero last error after EnableWindow(.., FALSE) as a failure.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

START_TEST(WmCancelModeLastError)
{
    HWND hwnd;
    BOOL ret;

    hwnd = CreateWindowExA(0, "STATIC", "x", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
    if (!hwnd)
        return;

    SetLastError(0);
    DefWindowProcW(hwnd, WM_CANCELMODE, 0, 0);
    ok(GetLastError() == 0, "DefWindowProc(WM_CANCELMODE) set the last error to %lu\n", GetLastError());

    SetLastError(0x1234);
    DefWindowProcW(hwnd, WM_CANCELMODE, 0, 0);
    ok(GetLastError() == 0x1234, "DefWindowProc(WM_CANCELMODE) changed the last error to %lu\n", GetLastError());

    SetLastError(0);
    ret = EnableWindow(hwnd, FALSE);
    ok(!ret, "EnableWindow(FALSE) returned %d for an enabled window\n", ret);
    ok(GetLastError() == 0, "EnableWindow(FALSE) set the last error to %lu\n", GetLastError());
    ok(!IsWindowEnabled(hwnd), "window still enabled\n");

    SetLastError(0);
    ret = EnableWindow(hwnd, TRUE);
    ok(ret, "EnableWindow(TRUE) returned %d for a disabled window\n", ret);
    ok(GetLastError() == 0, "EnableWindow(TRUE) set the last error to %lu\n", GetLastError());
    ok(IsWindowEnabled(hwnd), "window not enabled\n");

    DestroyWindow(hwnd);
}
