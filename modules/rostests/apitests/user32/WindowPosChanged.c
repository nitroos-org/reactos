/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Tests the position in the WINDOWPOS of WM_WINDOWPOSCHANGING and WM_WINDOWPOSCHANGED
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* WM_WINDOWPOSCHANGED carries the final position in the coordinates SetWindowPos takes: relative to the
 * client area of the parent for a child window, screen coordinates for a top-level window (also for a
 * message-only window). Measured on Windows 10 22H2 for a child and a grandchild, MoveWindow, a top-level
 * window, a message-only window and its child, an MDI child, DeferWindowPos of an MDI child and of a top-level
 * window, and SWP_NOSENDCHANGING. A child of a parent with WS_EX_LAYOUTRTL is placed mirrored by SetWindowPos
 * (the x of WM_WINDOWPOSCHANGING is the distance from the right edge of the client area) and
 * WM_WINDOWPOSCHANGED reports the offset of its left edge from the left edge of the client area, which is
 * clientwidth - x - cx. ReactOS places the child without mirroring: those checks are todo. */

static HWND g_hwndChanging, g_hwndChanged;
static WINDOWPOS g_Changing, g_Changed;
static INT g_cChanging, g_cChanged;

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_WINDOWPOSCHANGING)
    {
        g_hwndChanging = hwnd;
        g_Changing = *(WINDOWPOS *)lParam;
        g_cChanging++;
    }
    else if (uMsg == WM_WINDOWPOSCHANGED)
    {
        g_hwndChanged = hwnd;
        g_Changed = *(WINDOWPOS *)lParam;
        g_cChanged++;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

static LRESULT CALLBACK MdiFrameProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HWND hwndClient = (HWND)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    return DefFrameProcW(hwnd, hwndClient, uMsg, wParam, lParam);
}

static LRESULT CALLBACK MdiChildProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_WINDOWPOSCHANGING)
    {
        g_hwndChanging = hwnd;
        g_Changing = *(WINDOWPOS *)lParam;
        g_cChanging++;
    }
    else if (uMsg == WM_WINDOWPOSCHANGED)
    {
        g_hwndChanged = hwnd;
        g_Changed = *(WINDOWPOS *)lParam;
        g_cChanged++;
    }
    return DefMDIChildProcW(hwnd, uMsg, wParam, lParam);
}

static void Reset(void)
{
    g_hwndChanging = g_hwndChanged = NULL;
    g_cChanging = g_cChanged = 0;
    ZeroMemory(&g_Changing, sizeof(g_Changing));
    ZeroMemory(&g_Changed, sizeof(g_Changed));
}

static void Pump(void)
{
    MSG Msg;

    while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&Msg);
}

#define FLAGS (SWP_NOZORDER | SWP_NOACTIVATE)

/* Exactly one WM_WINDOWPOSCHANGED, with the given position and size in the coordinates of SetWindowPos */
static void CheckChanged(int line, HWND hwnd, int x, int y, int cx, int cy)
{
    ok_(__FILE__, line)(g_cChanged == 1 && g_hwndChanged == hwnd, "WM_WINDOWPOSCHANGED count %d, hwnd %p (expected %p)\n", g_cChanged, g_hwndChanged, hwnd);
    ok_(__FILE__, line)(g_Changed.x == x && g_Changed.y == y, "position %d,%d, expected %d,%d\n", g_Changed.x, g_Changed.y, x, y);
    ok_(__FILE__, line)(g_Changed.cx == cx && g_Changed.cy == cy, "size %dx%d, expected %dx%d\n", g_Changed.cx, g_Changed.cy, cx, cy);
}

/* The same, and the WM_WINDOWPOSCHANGING before it was sent once and is the same when both move and size */
static void CheckBoth(int line, HWND hwnd, int x, int y, int cx, int cy)
{
    CheckChanged(line, hwnd, x, y, cx, cy);
    ok_(__FILE__, line)(g_cChanging == 1 && g_hwndChanging == hwnd, "WM_WINDOWPOSCHANGING count %d, hwnd %p (expected %p)\n", g_cChanging, g_hwndChanging, hwnd);
    ok_(__FILE__, line)(g_Changing.x == g_Changed.x && g_Changing.y == g_Changed.y && g_Changing.cx == g_Changed.cx && g_Changing.cy == g_Changed.cy,
                        "WM_WINDOWPOSCHANGING %d,%d %dx%d, WM_WINDOWPOSCHANGED %d,%d %dx%d\n",
                        g_Changing.x, g_Changing.y, g_Changing.cx, g_Changing.cy, g_Changed.x, g_Changed.y, g_Changed.cx, g_Changed.cy);
}

/* Mapped from the parent's client area to the screen, the position is the window rectangle */
static void CheckRect(int line, HWND hwnd)
{
    RECT rc, rcExpect;

    GetWindowRect(hwnd, &rc);
    SetRect(&rcExpect, g_Changed.x, g_Changed.y, g_Changed.x + g_Changed.cx, g_Changed.y + g_Changed.cy);
    MapWindowPoints(GetAncestor(hwnd, GA_PARENT), NULL, (LPPOINT)&rcExpect, 2);
    ok_(__FILE__, line)(EqualRect(&rc, &rcExpect), "window rect (%ld,%ld,%ld,%ld), WINDOWPOS mapped to the screen (%ld,%ld,%ld,%ld)\n",
                        rc.left, rc.top, rc.right, rc.bottom, rcExpect.left, rcExpect.top, rcExpect.right, rcExpect.bottom);
}

static void TestLtr(HINSTANCE hInstance, LPCWSTR pszClass)
{
    HWND hwndParent, hwndChild, hwndGrandChild;
    RECT rcParent, rcClient;
    POINT pt;
    HDWP hdwp;

    hwndParent = CreateWindowExW(0, pszClass, L"parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, NULL, NULL, hInstance, NULL);
    ok(hwndParent != NULL, "parent not created\n");
    hwndChild = CreateWindowExW(0, pszClass, L"child", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 20, 100, 50, hwndParent, NULL, hInstance, NULL);
    ok(hwndChild != NULL, "child not created\n");
    hwndGrandChild = CreateWindowExW(0, pszClass, L"grandchild", WS_CHILD | WS_VISIBLE, 5, 6, 20, 20, hwndChild, NULL, hInstance, NULL);
    ok(hwndGrandChild != NULL, "grandchild not created\n");
    if (!hwndParent || !hwndChild || !hwndGrandChild)
        return;

    /* The parent has a caption and a border: its client area is not at its window origin */
    GetWindowRect(hwndParent, &rcParent);
    pt.x = pt.y = 0;
    ClientToScreen(hwndParent, &pt);
    ok(pt.x != rcParent.left && pt.y != rcParent.top, "client origin %ld,%ld equals the window origin\n", pt.x, pt.y);
    Pump();

    /* Move and size a child */
    Reset();
    ok(SetWindowPos(hwndChild, NULL, 30, 40, 60, 70, FLAGS), "SetWindowPos failed\n");
    CheckBoth(__LINE__, hwndChild, 30, 40, 60, 70);
    CheckRect(__LINE__, hwndChild);

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
    CheckBoth(__LINE__, hwndGrandChild, 7, 8, 21, 22);

    /* MoveWindow goes the same way */
    Reset();
    ok(MoveWindow(hwndChild, 12, 14, 70, 60, TRUE), "MoveWindow failed\n");
    CheckBoth(__LINE__, hwndChild, 12, 14, 70, 60);

    /* SWP_NOSENDCHANGING: no WM_WINDOWPOSCHANGING, the final position all the same */
    Reset();
    ok(SetWindowPos(hwndChild, NULL, 31, 41, 71, 61, FLAGS | SWP_NOSENDCHANGING), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwndChild, 31, 41, 71, 61);
    ok_int(g_cChanging, 0);

    /* DeferWindowPos of a child (the same code as SetWindowPos; Windows was measured with an MDI child) */
    Reset();
    hdwp = BeginDeferWindowPos(1);
    hdwp = DeferWindowPos(hdwp, hwndChild, NULL, 15, 25, 72, 62, FLAGS);
    ok(hdwp != NULL, "DeferWindowPos failed\n");
    ok(EndDeferWindowPos(hdwp), "EndDeferWindowPos failed\n");
    CheckBoth(__LINE__, hwndChild, 15, 25, 72, 62);

    /* DeferWindowPos of a top-level window: screen coordinates */
    Reset();
    hdwp = BeginDeferWindowPos(1);
    hdwp = DeferWindowPos(hdwp, hwndParent, NULL, 120, 130, 380, 280, FLAGS);
    ok(hdwp != NULL, "DeferWindowPos failed\n");
    ok(EndDeferWindowPos(hdwp), "EndDeferWindowPos failed\n");
    CheckBoth(__LINE__, hwndParent, 120, 130, 380, 280);

    /* A top-level window reports screen coordinates */
    Reset();
    ok(SetWindowPos(hwndParent, NULL, 130, 140, 300, 200, FLAGS), "SetWindowPos failed\n");
    CheckBoth(__LINE__, hwndParent, 130, 140, 300, 200);

    /* The client rectangle of the child did not move inside the parent */
    GetClientRect(hwndParent, &rcClient);
    GetWindowRect(hwndChild, &rcParent);
    MapWindowPoints(NULL, hwndParent, (LPPOINT)&rcParent, 2);
    ok(rcParent.left == 15 && rcParent.top == 25, "child at %ld,%ld in the parent's client area\n", rcParent.left, rcParent.top);

    DestroyWindow(hwndParent);
}

static void TestMessageOnly(HINSTANCE hInstance, LPCWSTR pszClass)
{
    HWND hwnd, hwndChild;

    hwnd = CreateWindowExW(0, pszClass, L"message", WS_POPUP, 0, 0, 100, 100, HWND_MESSAGE, NULL, hInstance, NULL);
    ok(hwnd != NULL, "message-only window not created\n");
    if (!hwnd)
        return;
    hwndChild = CreateWindowExW(0, pszClass, L"child", WS_CHILD, 10, 20, 50, 40, hwnd, NULL, hInstance, NULL);
    ok(hwndChild != NULL, "child of the message-only window not created\n");

    /* A message-only window is placed in screen coordinates like a top-level window */
    Reset();
    ok(SetWindowPos(hwnd, NULL, 5, 6, 120, 110, FLAGS), "SetWindowPos failed\n");
    CheckChanged(__LINE__, hwnd, 5, 6, 120, 110);
    ok_int(g_cChanging, 1);

    /* and its child relative to it */
    if (hwndChild)
    {
        Reset();
        ok(SetWindowPos(hwndChild, NULL, 30, 40, 60, 50, FLAGS), "SetWindowPos failed\n");
        CheckBoth(__LINE__, hwndChild, 30, 40, 60, 50);
    }
    DestroyWindow(hwnd);
}

static void TestMdi(HINSTANCE hInstance)
{
    WNDCLASSEXW wc = { sizeof(wc) };
    CLIENTCREATESTRUCT ccs = { NULL, 100 };
    HWND hwndFrame, hwndClient, hwndChild;
    HDWP hdwp;

    wc.lpfnWndProc = MdiFrameProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_APPWORKSPACE + 1);
    wc.lpszClassName = L"WindowPosChangedMdiFrame";
    ok(RegisterClassExW(&wc) != 0, "RegisterClassExW failed\n");
    wc.lpfnWndProc = MdiChildProc;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WindowPosChangedMdiChild";
    ok(RegisterClassExW(&wc) != 0, "RegisterClassExW failed\n");

    hwndFrame = CreateWindowExW(0, L"WindowPosChangedMdiFrame", L"frame", WS_OVERLAPPEDWINDOW | WS_VISIBLE | WS_CLIPCHILDREN,
                                100, 100, 500, 400, NULL, NULL, hInstance, NULL);
    ok(hwndFrame != NULL, "frame not created\n");
    if (!hwndFrame)
        goto Cleanup;
    hwndClient = CreateWindowExW(WS_EX_CLIENTEDGE, L"MDICLIENT", NULL, WS_CHILD | WS_CLIPCHILDREN | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL,
                                 0, 0, 0, 0, hwndFrame, (HMENU)(UINT_PTR)1, hInstance, &ccs);
    ok(hwndClient != NULL, "MDI client not created\n");
    if (!hwndClient)
        goto Cleanup;
    SetWindowLongPtrW(hwndFrame, GWLP_USERDATA, (LONG_PTR)hwndClient);
    Pump();

    hwndChild = CreateMDIWindowW(L"WindowPosChangedMdiChild", L"mdi", WS_CHILD | WS_VISIBLE | WS_OVERLAPPEDWINDOW,
                                 10, 20, 200, 150, hwndClient, hInstance, 0);
    ok(hwndChild != NULL, "MDI child not created\n");
    if (!hwndChild)
        goto Cleanup;
    Pump();

    /* The position of an MDI child is relative to the client area of the MDI client */
    Reset();
    ok(SetWindowPos(hwndChild, NULL, 30, 40, 180, 120, FLAGS), "SetWindowPos failed\n");
    CheckBoth(__LINE__, hwndChild, 30, 40, 180, 120);
    CheckRect(__LINE__, hwndChild);

    Reset();
    hdwp = BeginDeferWindowPos(1);
    hdwp = DeferWindowPos(hdwp, hwndChild, NULL, 15, 25, 160, 100, FLAGS);
    ok(hdwp != NULL, "DeferWindowPos failed\n");
    ok(EndDeferWindowPos(hdwp), "EndDeferWindowPos failed\n");
    CheckBoth(__LINE__, hwndChild, 15, 25, 160, 100);

Cleanup:
    if (hwndFrame)
        DestroyWindow(hwndFrame);
    UnregisterClassW(L"WindowPosChangedMdiChild", hInstance);
    UnregisterClassW(L"WindowPosChangedMdiFrame", hInstance);
}

static void TestRtl(HINSTANCE hInstance, LPCWSTR pszClass)
{
    HWND hwndParent, hwndChild;
    RECT rcClient;
    int expectX;

    hwndParent = CreateWindowExW(WS_EX_LAYOUTRTL, pszClass, L"rtl parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, NULL, NULL, hInstance, NULL);
    ok(hwndParent != NULL, "parent not created\n");
    if (!hwndParent)
        return;
    hwndChild = CreateWindowExW(0, pszClass, L"child", WS_CHILD | WS_VISIBLE | WS_BORDER, 10, 20, 150, 100, hwndParent, NULL, hInstance, NULL);
    ok(hwndChild != NULL, "child not created\n");
    if (hwndChild)
    {
        Pump();
        GetClientRect(hwndParent, &rcClient);

        /* x is the distance from the right edge of the client area; the child reports its left edge from the left edge */
        Reset();
        ok(SetWindowPos(hwndChild, NULL, 30, 40, 100, 60, FLAGS), "SetWindowPos failed\n");
        ok_int(g_cChanging, 1);
        ok(g_Changing.x == 30 && g_Changing.y == 40, "WM_WINDOWPOSCHANGING position %d,%d\n", g_Changing.x, g_Changing.y);
        expectX = rcClient.right - 30 - 100;
        ok_int(g_cChanged, 1);
        ok(g_Changed.y == 40 && g_Changed.cx == 100 && g_Changed.cy == 60, "WM_WINDOWPOSCHANGED %d,%d %dx%d\n", g_Changed.x, g_Changed.y, g_Changed.cx, g_Changed.cy);
        todo_ros ok(g_Changed.x == expectX, "WM_WINDOWPOSCHANGED x %d, expected %d\n", g_Changed.x, expectX);
    }
    DestroyWindow(hwndParent);
}

START_TEST(WindowPosChanged)
{
    WNDCLASSW wc = { 0 };

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WindowPosChangedTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    TestLtr(wc.hInstance, wc.lpszClassName);
    TestMessageOnly(wc.hInstance, wc.lpszClassName);
    TestMdi(wc.hInstance);
    TestRtl(wc.hInstance, wc.lpszClassName);

    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
