/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DefWindowProc(WM_SETCURSOR) of a child window whose parent destroys the child when it is asked first
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * DefWindowProc of a child window gives WM_SETCURSOR to the parent first (documented: "DefWindowProc passes the
 * WM_SETCURSOR message to a parent window before processing"). A parent that destroys the child at that moment and
 * returns FALSE: the child's DefWindowProc returns without touching the destroyed window, and the system goes on.
 */

#include "precomp.h"

static HWND g_Child;
static INT g_ParentCalls;

static LRESULT CALLBACK ParentProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_SETCURSOR && (HWND)wParam == g_Child && g_Child)
    {
        g_ParentCalls++;
        DestroyWindow(g_Child);
        return FALSE;
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static LRESULT CALLBACK ChildProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

START_TEST(SetCursorParentDestroys)
{
    WNDCLASSW Class = { 0 };
    HWND Parent;
    INT i;

    Class.lpfnWndProc = ParentProc;
    Class.lpszClassName = L"SetCursorParent";
    RegisterClassW(&Class);
    Class.lpfnWndProc = ChildProc;
    Class.lpszClassName = L"SetCursorChild";
    Class.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    RegisterClassW(&Class);

    Parent = CreateWindowExW(0, L"SetCursorParent", L"p", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 300, 300,
                             NULL, NULL, NULL, NULL);
    ok(Parent != NULL, "parent: %lu\n", GetLastError());
    for (i = 0; i < 20; i++)
    {
        g_Child = CreateWindowExW(0, L"SetCursorChild", L"c", WS_CHILD | WS_VISIBLE, 10, 10, 100, 100, Parent,
                                  NULL, NULL, NULL);
        ok(g_Child != NULL, "child: %lu\n", GetLastError());
        /* the child's procedure (DefWindowProc) asks the parent first, which destroys the child */
        SendMessageW(g_Child, WM_SETCURSOR, (WPARAM)g_Child, MAKELPARAM(HTCLIENT, WM_MOUSEMOVE));
        ok(!IsWindow(g_Child), "round %d: the child still exists\n", i);
        g_Child = NULL;
    }
    ok(g_ParentCalls == 20, "the parent was asked %d times\n", g_ParentCalls);
    ok(IsWindow(Parent), "the parent is gone\n");
    DestroyWindow(Parent);
    UnregisterClassW(L"SetCursorParent", NULL);
    UnregisterClassW(L"SetCursorChild", NULL);
}
