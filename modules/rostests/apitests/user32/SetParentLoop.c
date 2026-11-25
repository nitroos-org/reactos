/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetParent when the hide it does first moves the new parent below the window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * SetParent(W, P) hides W first, which sends WM_SHOWWINDOW to W's procedure. Here that procedure moves P (a
 * top-level window, which keeps its style) below C, a child of W. Measured on Windows Server 2022 (64 and 32 bit):
 * the inner SetParent(P, C) is taken; the outer SetParent(W, P) fails with ERROR_INVALID_PARAMETER and W stays
 * below the desktop: the tree has no loop. A loop (W below P below C below W) made every recursive walk of the
 * subtree run until the kernel stack overflowed.
 */

#include "precomp.h"

static HWND g_W, g_P, g_C;
static BOOL g_Armed;
static INT g_Inner = -1;

static LRESULT CALLBACK LoopProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (hWnd == g_W && Msg == WM_SHOWWINDOW && !wParam && g_Armed)
    {
        g_Armed = FALSE;
        g_Inner = SetParent(g_P, g_C) != NULL;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static BOOL Loops(HWND Wnd)
{
    HWND Up;
    INT i;

    for (Up = GetAncestor(Wnd, GA_PARENT), i = 0; Up && i < 100; Up = GetAncestor(Up, GA_PARENT), i++)
        if (Up == Wnd) return TRUE;
    return FALSE;
}

START_TEST(SetParentLoop)
{
    WNDCLASSW Class = { 0 };
    HWND Ret;
    DWORD Error;

    Class.lpfnWndProc = LoopProc;
    Class.lpszClassName = L"SetParentLoop";
    RegisterClassW(&Class);

    g_W = CreateWindowExW(0, L"SetParentLoop", L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 10, 10, 300, 300,
                          NULL, NULL, NULL, NULL);
    g_C = CreateWindowExW(0, L"SetParentLoop", L"C", WS_CHILD | WS_VISIBLE, 5, 5, 100, 100, g_W, NULL, NULL, NULL);
    g_P = CreateWindowExW(0, L"SetParentLoop", L"P", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 50, 50, 200, 200,
                          NULL, NULL, NULL, NULL);
    ok(g_W && g_C && g_P, "windows %p %p %p\n", g_W, g_C, g_P);

    g_Armed = TRUE;
    SetLastError(0xdeadbeef);
    Ret = SetParent(g_W, g_P);
    Error = GetLastError();
    ok(g_Inner == 1, "the inner SetParent during the hide: %d\n", g_Inner);
    ok(Ret == NULL, "the outer SetParent returned %p\n", Ret);
    ok(Error == ERROR_INVALID_PARAMETER, "error %lu\n", Error);
    ok(GetAncestor(g_W, GA_PARENT) == GetDesktopWindow(), "W is below %p\n", GetAncestor(g_W, GA_PARENT));
    ok(GetAncestor(g_P, GA_PARENT) == g_C, "P is below %p\n", GetAncestor(g_P, GA_PARENT));
    ok(!Loops(g_W) && !Loops(g_P) && !Loops(g_C), "the window tree has a loop\n");

    /* the tree is still walked as a tree: moved, redrawn, destroyed */
    ok(SetWindowPos(g_W, NULL, 20, 20, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos\n");
    ok(RedrawWindow(g_W, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW), "RedrawWindow\n");
    if (!Loops(g_W))
        ok(DestroyWindow(g_W), "DestroyWindow: %lu\n", GetLastError());
    if (IsWindow(g_P)) DestroyWindow(g_P);
    UnregisterClassW(L"SetParentLoop", NULL);
}
