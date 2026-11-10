/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DefWindowProc(WM_CANCELMODE), EnableWindow and SetWindowLong(GWL_STYLE, WS_CHILD) leave the last
 *              error alone when no menu is involved. WebView2 (Chromium, EmbeddedBrowserWebView.dll) takes
 *              ERROR_INVALID_MENU_HANDLE left behind by them as a failure of its controller creation.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows 10 leaves the last error untouched for all of these calls, on every standard control class */
static void test_control_class(const char *cls, DWORD style, HWND parent, void *param)
{
    HWND hwnd;
    BOOL ret;
    LONG_PTR old;

    hwnd = CreateWindowExA(0, cls, "x", style, 0, 0, 50, 20, parent, NULL, GetModuleHandleW(NULL), param);
    ok(hwnd != NULL, "%s: CreateWindowExA failed: %lu\n", cls, GetLastError());
    if (!hwnd)
        return;

    SetLastError(0xDEADBEEF);
    ret = EnableWindow(hwnd, FALSE);
    ok(!ret, "%s: EnableWindow(FALSE) returned %d\n", cls, ret);
    ok(GetLastError() == 0xDEADBEEF, "%s: EnableWindow(FALSE) set the last error to %lu\n", cls, GetLastError());

    SetLastError(0xDEADBEEF);
    ret = EnableWindow(hwnd, TRUE);
    ok(ret, "%s: EnableWindow(TRUE) returned %d\n", cls, ret);
    ok(GetLastError() == 0xDEADBEEF, "%s: EnableWindow(TRUE) set the last error to %lu\n", cls, GetLastError());

    SetLastError(0xDEADBEEF);
    SendMessageA(hwnd, WM_ENABLE, FALSE, 0);
    ok(GetLastError() == 0xDEADBEEF, "%s: WM_ENABLE set the last error to %lu\n", cls, GetLastError());

    SetLastError(0xDEADBEEF);
    SendMessageA(hwnd, WM_CANCELMODE, 0, 0);
    ok(GetLastError() == 0xDEADBEEF, "%s: WM_CANCELMODE set the last error to %lu\n", cls, GetLastError());

    SetLastError(0xDEADBEEF);
    SetWindowLongA(hwnd, GWL_EXSTYLE, GetWindowLongA(hwnd, GWL_EXSTYLE));
    ok(GetLastError() == 0xDEADBEEF, "%s: SetWindowLong(GWL_EXSTYLE) set the last error to %lu\n", cls, GetLastError());

    SetLastError(0xDEADBEEF);
    old = SetWindowLongA(hwnd, GWL_STYLE, WS_CHILD);
    ok(old != 0, "%s: SetWindowLong(GWL_STYLE) returned 0\n", cls);
    ok(GetLastError() == 0xDEADBEEF, "%s: SetWindowLong(GWL_STYLE) set the last error to %lu\n", cls, GetLastError());

    /* an ANSI WM_GETTEXTLENGTH of an empty edit (also the one inside a combobox) must not leak the
       ERROR_INVALID_PARAMETER of WideCharToMultiByte(srclen 0) */
    if (!lstrcmpA(cls, "EDIT") || !lstrcmpA(cls, "COMBOBOX"))
    {
        SetWindowTextA(hwnd, "");
        SetLastError(0xDEADBEEF);
        SendMessageA(hwnd, WM_GETTEXTLENGTH, 0, 0);
        ok(GetLastError() == 0xDEADBEEF, "%s: WM_GETTEXTLENGTH set the last error to %lu\n", cls, GetLastError());
    }

    if (!lstrcmpA(cls, "MDICLIENT"))
    {
        MDICREATESTRUCTA mcs = { "STATIC", "child", GetModuleHandleW(NULL), 0, 0, 40, 30, 0, 0 };
        HWND child;

        child = (HWND)SendMessageA(hwnd, WM_MDICREATE, 0, (LPARAM)&mcs);
        ok(child != NULL, "WM_MDICREATE failed: %lu\n", GetLastError());

        SetLastError(0xDEADBEEF);
        SendMessageA(hwnd, WM_MDIGETACTIVE, 0, 0);
        ok(GetLastError() == 0xDEADBEEF, "WM_MDIGETACTIVE set the last error to %lu\n", GetLastError());
        SetLastError(0xDEADBEEF);
        SendMessageA(hwnd, WM_MDITILE, 0, 0);
        ok(GetLastError() == 0xDEADBEEF, "WM_MDITILE set the last error to %lu\n", GetLastError());
        SetLastError(0xDEADBEEF);
        SendMessageA(hwnd, WM_MDICASCADE, 0, 0);
        ok(GetLastError() == 0xDEADBEEF, "WM_MDICASCADE set the last error to %lu\n", GetLastError());
        SetLastError(0xDEADBEEF);
        SendMessageA(hwnd, WM_MDIREFRESHMENU, 0, 0);
        ok(GetLastError() == 0xDEADBEEF, "WM_MDIREFRESHMENU set the last error to %lu\n", GetLastError());
        SetLastError(0xDEADBEEF);
        SendMessageA(hwnd, WM_MDINEXT, 0, 0);
        ok(GetLastError() == 0xDEADBEEF, "WM_MDINEXT set the last error to %lu\n", GetLastError());
        if (child)
        {
            SetLastError(0xDEADBEEF);
            SendMessageA(hwnd, WM_MDIDESTROY, (WPARAM)child, 0);
            ok(GetLastError() == 0xDEADBEEF, "WM_MDIDESTROY set the last error to %lu\n", GetLastError());
        }
    }

    DestroyWindow(hwnd);
}

static void test_controls(void)
{
    static const char *classes[] = { "STATIC", "BUTTON", "EDIT", "LISTBOX", "COMBOBOX", "SCROLLBAR" };
    CLIENTCREATESTRUCT ccs = { NULL, 1000 };
    WNDCLASSA wc = { 0 };
    HWND frame;
    UINT i;

    for (i = 0; i < ARRAY_SIZE(classes); i++)
        test_control_class(classes[i], WS_POPUP, NULL, NULL);
    test_control_class("EDIT", WS_POPUP | ES_MULTILINE, NULL, NULL);
    test_control_class("STATIC", WS_POPUP | SS_NOTIFY, NULL, NULL);

    /* an MDICLIENT is a child of an MDI frame */
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = "WmCancelModeLastErrorFrame";
    ok(RegisterClassA(&wc) != 0, "RegisterClass failed: %lu\n", GetLastError());
    frame = CreateWindowExA(0, wc.lpszClassName, "frame", WS_OVERLAPPEDWINDOW, 0, 0, 200, 150, NULL, NULL, wc.hInstance, NULL);
    ok(frame != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
    if (frame)
    {
        test_control_class("MDICLIENT", WS_CHILD, frame, &ccs);
        DestroyWindow(frame);
    }
    UnregisterClassA(wc.lpszClassName, wc.hInstance);
}

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

    /* a window becoming a child has no menu to release */
    hwnd = CreateWindowExA(0, "STATIC", "x", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
    if (hwnd)
    {
        LONG_PTR old;

        SetLastError(0x1234);
        old = SetWindowLongPtrW(hwnd, GWL_STYLE, (LONG_PTR)(WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN));
        ok(old != 0, "SetWindowLongPtr(GWL_STYLE) returned 0\n");
        ok(GetLastError() == 0x1234, "SetWindowLong(GWL_STYLE, WS_CHILD) changed the last error to %lu\n", GetLastError());
        DestroyWindow(hwnd);
    }

    test_controls();
}
