/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Tests the position in the WINDOWPOS of WM_WINDOWPOSCHANGED
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* WM_WINDOWPOSCHANGED carries the final position in the coordinates SetWindowPos takes: relative to the
 * client area of the parent for a child window, screen coordinates for a top-level window. */

static HWND g_hwndLast;
static WINDOWPOS g_Changed;
static INT g_cChanged;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_WINDOWPOSCHANGED)
    {
        g_hwndLast = hwnd;
        g_Changed = *(WINDOWPOS *)lParam;
        g_cChanged++;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static void Reset(void)
{
    g_hwndLast = NULL;
    g_cChanged = 0;
    ZeroMemory(&g_Changed, sizeof(g_Changed));
}

#define FLAGS (SWP_NOZORDER | SWP_NOACTIVATE)

static void CheckChanged(int line, HWND hwnd, int x, int y, int cx, int cy)
{
    RECT rc, rcExpect;

    ok_(__FILE__, line)(g_cChanged >= 1 && g_hwndLast == hwnd, "WM_WINDOWPOSCHANGED count %d, hwnd %p (expected %p)\n", g_cChanged, g_hwndLast, hwnd);
    ok_(__FILE__, line)(g_Changed.x == x && g_Changed.y == y, "position %d,%d, expected %d,%d\n", g_Changed.x, g_Changed.y, x, y);
    ok_(__FILE__, line)(g_Changed.cx == cx && g_Changed.cy == cy, "size %dx%d, expected %dx%d\n", g_Changed.cx, g_Changed.cy, cx, cy);

    /* Mapped from the parent's client area to the screen, it is the window rectangle */
    GetWindowRect(hwnd, &rc);
    SetRect(&rcExpect, g_Changed.x, g_Changed.y, g_Changed.x + g_Changed.cx, g_Changed.y + g_Changed.cy);
    MapWindowPoints(GetAncestor(hwnd, GA_PARENT), NULL, (LPPOINT)&rcExpect, 2);
    ok_(__FILE__, line)(EqualRect(&rc, &rcExpect), "window rect (%ld,%ld,%ld,%ld), WINDOWPOS mapped to the screen (%ld,%ld,%ld,%ld)\n",
                        rc.left, rc.top, rc.right, rc.bottom, rcExpect.left, rcExpect.top, rcExpect.right, rcExpect.bottom);
}

START_TEST(WindowPosChanged)
{
    WNDCLASSW wc = { 0 };
    HWND hwndParent, hwndChild, hwndGrandChild;
    RECT rcParent, rcClient;
    POINT pt;

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WindowPosChangedTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    hwndParent = CreateWindowExW(0, wc.lpszClassName, L"parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                 100, 100, 400, 300, NULL, NULL, wc.hInstance, NULL);
    ok(hwndParent != NULL, "parent not created\n");
    hwndChild = CreateWindowExW(0, wc.lpszClassName, L"child", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                10, 20, 100, 50, hwndParent, NULL, wc.hInstance, NULL);
    ok(hwndChild != NULL, "child not created\n");
    hwndGrandChild = CreateWindowExW(0, wc.lpszClassName, L"grandchild", WS_CHILD | WS_VISIBLE,
                                     5, 6, 20, 20, hwndChild, NULL, wc.hInstance, NULL);
    ok(hwndGrandChild != NULL, "grandchild not created\n");
    if (!hwndParent || !hwndChild || !hwndGrandChild)
        return;

    /* The parent has a caption and a border: its client area is not at its window origin */
    GetWindowRect(hwndParent, &rcParent);
    pt.x = pt.y = 0;
    ClientToScreen(hwndParent, &pt);
    ok(pt.x != rcParent.left && pt.y != rcParent.top, "client origin %ld,%ld equals the window origin\n", pt.x, pt.y);

    /* Move and size a child */
    Reset();
    ok(SetWindowPos(hwndChild, NULL, 30, 40, 60, 70, FLAGS), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwndChild, 30, 40, 60, 70);

    /* Size only: the position reported is the current one, still relative to the parent */
    Reset();
    ok(SetWindowPos(hwndChild, NULL, 0, 0, 80, 90, FLAGS | SWP_NOMOVE), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwndChild, 30, 40, 80, 90);

    /* A move of the parent does not change the position of the child relative to it */
    ok(SetWindowPos(hwndParent, NULL, 150, 160, 0, 0, FLAGS | SWP_NOSIZE), "SetWindowPos failed\n");
    Reset();
    ok(SetWindowPos(hwndChild, NULL, 0, 0, 81, 91, FLAGS | SWP_NOMOVE), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwndChild, 30, 40, 81, 91);

    /* A grandchild is relative to its own parent (the child) */
    Reset();
    ok(SetWindowPos(hwndGrandChild, NULL, 7, 8, 21, 22, FLAGS), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwndGrandChild, 7, 8, 21, 22);

    /* MoveWindow goes the same way */
    Reset();
    ok(MoveWindow(hwndChild, 12, 14, 70, 60, TRUE), "MoveWindow failed\n");
    CheckChanged(__LINE__, hwndChild, 12, 14, 70, 60);

    /* A top-level window reports screen coordinates */
    Reset();
    ok(SetWindowPos(hwndParent, NULL, 120, 130, 300, 200, FLAGS), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwndParent, 120, 130, 300, 200);

    /* The client rectangle of the child did not move inside the parent */
    GetClientRect(hwndParent, &rcClient);
    GetWindowRect(hwndChild, &rcParent);
    MapWindowPoints(NULL, hwndParent, (LPPOINT)&rcParent, 2);
    ok(rcParent.left == 12 && rcParent.top == 14, "child at %ld,%ld in the parent's client area\n", rcParent.left, rcParent.top);

    DestroyWindow(hwndParent);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
