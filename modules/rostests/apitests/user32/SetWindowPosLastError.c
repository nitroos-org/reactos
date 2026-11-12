/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetWindowPos/MoveWindow, EDIT WM_UNDO, WM_MDICREATE and WM_HELP leave the last error alone, as
 *              Windows 10 does (oracle probe 2026-11-12). Each call is preceded by SetLastError(0xDEADBEEF).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <imm.h>

#ifndef WM_IME_SYSTEM
#define WM_IME_SYSTEM 0x0287
#endif

#define SENTINEL 0xDEADBEEF

static HINSTANCE g_hInst;

/* Windows 10 resets the last error to 0 itself on a geometry change of a COMBOBOX and of a multiline EDIT
   (internal noise of its controls, not copied here): both the sentinel and 0 are accepted for them */
#define CHECK_ERR(lax, what) \
    ok(GetLastError() == SENTINEL || ((lax) && GetLastError() == 0), "%s: %s set the last error to %lu\n", cls, what, GetLastError())

static LRESULT CALLBACK PlainProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void test_pos(const char *cls, HWND hwnd, BOOL lax)
{
    BOOL ret;

    SetLastError(SENTINEL);
    ret = MoveWindow(hwnd, 1, 1, 60, 30, FALSE);
    ok(ret, "%s: MoveWindow failed\n", cls);
    CHECK_ERR(lax, "MoveWindow");

    SetLastError(SENTINEL);
    ret = MoveWindow(hwnd, 3, 3, 62, 32, TRUE);
    ok(ret, "%s: MoveWindow(repaint) failed\n", cls);
    CHECK_ERR(lax, "MoveWindow(repaint)");

    SetLastError(SENTINEL);
    ret = SetWindowPos(hwnd, NULL, 2, 2, 61, 31, SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW);
    ok(ret, "%s: SetWindowPos failed\n", cls);
    CHECK_ERR(lax, "SetWindowPos(move+size)");

    SetLastError(SENTINEL);
    ret = SetWindowPos(hwnd, NULL, 7, 7, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    ok(ret, "%s: SetWindowPos failed\n", cls);
    CHECK_ERR(lax, "SetWindowPos(move)");

    SetLastError(SENTINEL);
    ret = SetWindowPos(hwnd, NULL, 0, 0, 70, 40, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    ok(ret, "%s: SetWindowPos failed\n", cls);
    CHECK_ERR(lax, "SetWindowPos(size)");

    SetLastError(SENTINEL);
    ret = SetWindowPos(hwnd, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    ok(ret, "%s: SetWindowPos failed\n", cls);
    CHECK_ERR(FALSE, "SetWindowPos(z-order)");

    SetLastError(SENTINEL);
    ret = SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    ok(ret, "%s: SetWindowPos failed\n", cls);
    CHECK_ERR(FALSE, "SetWindowPos(frame changed)");
}

static void test_help(const char *cls, HWND hwnd)
{
    HELPINFO hi;

    memset(&hi, 0, sizeof(hi));
    hi.cbSize = sizeof(hi);
    hi.iContextType = HELPINFO_WINDOW;
    hi.hItemHandle = hwnd;

    SetLastError(SENTINEL);
    SendMessageA(hwnd, WM_HELP, 0, 0);
    CHECK_ERR(FALSE, "WM_HELP(NULL)");

    SetLastError(SENTINEL);
    SendMessageA(hwnd, WM_HELP, 0, (LPARAM)&hi);
    CHECK_ERR(FALSE, "WM_HELP(HELPINFO)");

    SetLastError(SENTINEL);
    DefWindowProcA(hwnd, WM_HELP, 0, 0);
    CHECK_ERR(FALSE, "DefWindowProcA(WM_HELP)");

    SetLastError(SENTINEL);
    DefWindowProcW(hwnd, WM_HELP, 0, 0);
    CHECK_ERR(FALSE, "DefWindowProcW(WM_HELP)");
}

/* The default IME window of the thread gets WM_IME_SYSTEM:IMS_UPDATEIMEUI after every geometry change and
   WM_IME_SETCONTEXT from DefWindowProc on focus changes */
static void test_ime(void)
{
    const char *cls = "IME";
    HWND hwnd, ime;

    hwnd = CreateWindowExA(0, "SWPLastErrorPlain", "x", WS_POPUP, 0, 0, 50, 20, NULL, NULL, g_hInst, NULL);
    ok(hwnd != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
    if (!hwnd)
        return;

    ime = ImmGetDefaultIMEWnd(hwnd);
    if (ime)
    {
        SetLastError(SENTINEL);
        SendMessageA(ime, WM_IME_SYSTEM, 6 /* IMS_UPDATEIMEUI */, 0);
        CHECK_ERR(FALSE, "WM_IME_SYSTEM(IMS_UPDATEIMEUI)");

        SetLastError(SENTINEL);
        SendMessageA(ime, WM_IME_SETCONTEXT, 1, 0);
        CHECK_ERR(FALSE, "WM_IME_SETCONTEXT(TRUE)");
    }
    else
        skip("no default IME window\n");

    SetLastError(SENTINEL);
    DefWindowProcA(hwnd, WM_IME_SETCONTEXT, 1, ISC_SHOWUIALL);
    CHECK_ERR(FALSE, "DefWindowProcA(WM_IME_SETCONTEXT)");

    SetLastError(SENTINEL);
    DefWindowProcW(hwnd, WM_IME_SETCONTEXT, 0, 0);
    CHECK_ERR(FALSE, "DefWindowProcW(WM_IME_SETCONTEXT)");

    DestroyWindow(hwnd);
}

static void test_class(const char *cls, DWORD style, HWND parent, void *param, BOOL lax)
{
    HWND hwnd;

    hwnd = CreateWindowExA(0, cls, "x", style, 0, 0, 50, 20, parent, NULL, g_hInst, param);
    ok(hwnd != NULL, "%s: CreateWindowExA failed: %lu\n", cls, GetLastError());
    if (!hwnd)
        return;

    test_pos(cls, hwnd, lax);
    test_help(cls, hwnd);
    DestroyWindow(hwnd);
}

static void test_edit_undo(DWORD style, BOOL multiline)
{
    const char *cls = multiline ? "EDIT(multiline)" : "EDIT";
    HWND hwnd;
    LRESULT res;

    hwnd = CreateWindowExA(0, "EDIT", "", WS_POPUP | style, 0, 0, 50, 20, NULL, NULL, g_hInst, NULL);
    ok(hwnd != NULL, "%s: CreateWindowExA failed: %lu\n", cls, GetLastError());
    if (!hwnd)
        return;

    /* nothing to undo: TRUE for a single-line control, FALSE for a multiline one, last error untouched */
    SetLastError(SENTINEL);
    res = SendMessageA(hwnd, WM_UNDO, 0, 0);
    ok(res == !multiline, "%s: WM_UNDO returned %Id\n", cls, res);
    CHECK_ERR(FALSE, "WM_UNDO");

    SetLastError(SENTINEL);
    res = SendMessageA(hwnd, EM_UNDO, 0, 0);
    ok(res == !multiline, "%s: EM_UNDO returned %Id\n", cls, res);
    CHECK_ERR(FALSE, "EM_UNDO");

    SetLastError(SENTINEL);
    res = SendMessageW(hwnd, WM_UNDO, 0, 0);
    ok(res == !multiline, "%s: WM_UNDO(W) returned %Id\n", cls, res);
    CHECK_ERR(FALSE, "WM_UNDO(W)");

    SendMessageA(hwnd, EM_REPLACESEL, TRUE, (LPARAM)"abc");
    SendMessageA(hwnd, EM_EMPTYUNDOBUFFER, 0, 0);
    SetLastError(SENTINEL);
    res = SendMessageA(hwnd, WM_UNDO, 0, 0);
    ok(res == !multiline, "%s: WM_UNDO after EM_EMPTYUNDOBUFFER returned %Id\n", cls, res);
    CHECK_ERR(FALSE, "WM_UNDO after EM_EMPTYUNDOBUFFER");

    /* a real undo still works */
    SendMessageA(hwnd, EM_SETSEL, 0, -1);
    SendMessageA(hwnd, EM_REPLACESEL, TRUE, (LPARAM)"xyz");
    res = SendMessageA(hwnd, EM_CANUNDO, 0, 0);
    ok(res != 0, "%s: EM_CANUNDO is FALSE after a replacement\n", cls);
    res = SendMessageA(hwnd, WM_UNDO, 0, 0);
    ok(res != 0, "%s: WM_UNDO failed\n", cls);
    {
        char buf[16] = "";
        GetWindowTextA(hwnd, buf, sizeof(buf));
        ok(!lstrcmpA(buf, "abc"), "%s: text after undo is \"%s\"\n", cls, buf);
    }

    DestroyWindow(hwnd);
}

static void test_mdi_create(HWND frame)
{
    const char *cls = "MDICLIENT";
    CLIENTCREATESTRUCT ccs = { NULL, 1000 };
    MDICREATESTRUCTA mcs = { "STATIC", "child", g_hInst, 0, 0, 40, 30, 0, 0 };
    MDICREATESTRUCTW mcw = { L"STATIC", L"child", g_hInst, 0, 0, 40, 30, 0, 0 };
    HWND client, child;

    client = CreateWindowExA(0, "MDICLIENT", NULL, WS_CHILD, 0, 0, 100, 100, frame, NULL, g_hInst, &ccs);
    ok(client != NULL, "CreateWindowExA(MDICLIENT) failed: %lu\n", GetLastError());
    if (!client)
        return;

    SetLastError(SENTINEL);
    child = (HWND)SendMessageA(client, WM_MDICREATE, 0, (LPARAM)&mcs);
    ok(child != NULL, "WM_MDICREATE failed\n");
    CHECK_ERR(FALSE, "WM_MDICREATE(A)");

    SetLastError(SENTINEL);
    child = (HWND)SendMessageW(client, WM_MDICREATE, 0, (LPARAM)&mcw);
    ok(child != NULL, "WM_MDICREATE(W) failed\n");
    CHECK_ERR(FALSE, "WM_MDICREATE(W)");

    SetLastError(SENTINEL);
    child = (HWND)SendMessageA(client, WM_MDICREATE, 0, 0);
    ok(child == NULL, "WM_MDICREATE(NULL) returned %p\n", child);
    CHECK_ERR(FALSE, "WM_MDICREATE(NULL)");

    DestroyWindow(client);
}

START_TEST(SetWindowPosLastError)
{
    static const char *classes[] = { "STATIC", "BUTTON", "EDIT", "LISTBOX", "SCROLLBAR", "SWPLastErrorPlain" };
    CLIENTCREATESTRUCT ccs = { NULL, 1000 };
    WNDCLASSA wc = { 0 };
    HWND frame, child;
    UINT i;

    g_hInst = GetModuleHandleW(NULL);
    wc.hInstance = g_hInst;
    wc.lpfnWndProc = PlainProc;
    wc.lpszClassName = "SWPLastErrorPlain";
    ok(RegisterClassA(&wc) != 0, "RegisterClass failed: %lu\n", GetLastError());

    for (i = 0; i < ARRAY_SIZE(classes); i++)
        test_class(classes[i], WS_POPUP, NULL, NULL, FALSE);
    test_class("EDIT", WS_POPUP | ES_MULTILINE, NULL, NULL, TRUE);
    test_class("COMBOBOX", WS_POPUP, NULL, NULL, TRUE);

    test_ime();

    test_edit_undo(0, FALSE);
    test_edit_undo(ES_MULTILINE, TRUE);

    /* a child of a top-level window: WM_HELP goes up the chain and ends at a window without a parent */
    frame = CreateWindowExA(0, "SWPLastErrorPlain", "frame", WS_OVERLAPPEDWINDOW, 0, 0, 200, 150, NULL, NULL, g_hInst, NULL);
    ok(frame != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
    if (frame)
    {
        child = CreateWindowExA(0, "SWPLastErrorPlain", "child", WS_CHILD, 0, 0, 40, 40, frame, NULL, g_hInst, NULL);
        ok(child != NULL, "CreateWindowExA failed: %lu\n", GetLastError());
        if (child)
        {
            test_pos("plain child", child, FALSE);
            test_help("plain child", child);
            DestroyWindow(child);
        }
        DestroyWindow(frame);
    }

    /* MDICLIENT in an MDI frame */
    frame = CreateWindowExA(0, "SWPLastErrorPlain", "frame", WS_OVERLAPPEDWINDOW, 0, 0, 200, 150, NULL, NULL, g_hInst, NULL);
    if (frame)
    {
        HWND client = CreateWindowExA(0, "MDICLIENT", NULL, WS_CHILD, 0, 0, 100, 100, frame, NULL, g_hInst, &ccs);
        ok(client != NULL, "CreateWindowExA(MDICLIENT) failed: %lu\n", GetLastError());
        if (client)
        {
            test_pos("MDICLIENT", client, FALSE);
            DestroyWindow(client);
        }
        test_mdi_create(frame);
        DestroyWindow(frame);
    }

    UnregisterClassA("SWPLastErrorPlain", g_hInst);
}
