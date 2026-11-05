/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     The windows of an owner group are told with WM_WINDOWPOSCHANGING when one of them is z-ordered
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Windows 10 22H2: when an owner or a window it owns (hidden ones too) is z-ordered, every other window of the
 * group gets WM_WINDOWPOSCHANGING with SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE and a zero position and size,
 * once. Nothing is sent with SWP_NOZORDER or SWP_NOOWNERZORDER, to windows of other owners, to the owner when
 * a popup is only shown without z-order (SW_SHOWNOACTIVATE), or when a popup is created. */

enum { OWN, POP1, POP2, UNOWNED, WINDOW_COUNT };

static HWND g_hwnd[WINDOW_COUNT];
static INT g_cChanging[WINDOW_COUNT];
static WINDOWPOS g_Last[WINDOW_COUNT];

static INT IndexOf(HWND hwnd)
{
    INT i;

    for (i = 0; i < WINDOW_COUNT; i++)
        if (g_hwnd[i] == hwnd)
            return i;
    return -1;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    INT i = IndexOf(hwnd);

    if (uMsg == WM_WINDOWPOSCHANGING && i >= 0)
    {
        g_cChanging[i]++;
        g_Last[i] = *(WINDOWPOS *)lParam;
    }
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

static void Reset(void)
{
    ZeroMemory(g_cChanging, sizeof(g_cChanging));
    ZeroMemory(g_Last, sizeof(g_Last));
}

#define EXPECT(line, what, own, pop1, pop2, unowned) \
    CheckCounts(line, what, own, pop1, pop2, unowned)

static void CheckCounts(int line, const char *what, INT own, INT pop1, INT pop2, INT unowned)
{
    static const char *const names[WINDOW_COUNT] = { "owner", "popup 1", "popup 2", "unowned" };
    const INT expected[WINDOW_COUNT] = { own, pop1, pop2, unowned };
    INT i;

    for (i = 0; i < WINDOW_COUNT; i++)
    {
        ok_(__FILE__, line)(g_cChanging[i] == expected[i], "%s: %s got %d WM_WINDOWPOSCHANGING, expected %d\n",
                            what, names[i], g_cChanging[i], expected[i]);
    }
}

/* The notice to a window other than the one that was z-ordered */
static void CheckNotice(int line, const char *what, INT i)
{
    const WINDOWPOS *wp = &g_Last[i];

    ok_(__FILE__, line)((wp->flags & (SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) == (SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE),
                        "%s: flags %04x\n", what, wp->flags);
    ok_(__FILE__, line)(wp->x == 0 && wp->y == 0 && wp->cx == 0 && wp->cy == 0, "%s: %d,%d %dx%d\n", what, wp->x, wp->y, wp->cx, wp->cy);
}

#define ZFLAGS (SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)

static HWND Make(const WCHAR *cls, DWORD style, int x, int y, int w, int h, HWND owner)
{
    return CreateWindowExW(0, cls, L"owner group", style, x, y, w, h, owner, NULL, GetModuleHandleW(NULL), NULL);
}

START_TEST(OwnerZOrderNotice)
{
    WNDCLASSW wc = { 0 };

    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"OwnerZOrderNoticeTest";
    ok(RegisterClassW(&wc) != 0, "RegisterClassW failed\n");

    g_hwnd[OWN] = Make(wc.lpszClassName, WS_OVERLAPPEDWINDOW | WS_VISIBLE, 20, 20, 400, 300, NULL);
    ok(g_hwnd[OWN] != NULL, "owner not created\n");
    if (!g_hwnd[OWN])
        return;
    Pump();

    /* A popup is created: the owner hears nothing */
    Reset();
    g_hwnd[POP1] = Make(wc.lpszClassName, WS_POPUP | WS_CAPTION | WS_SYSMENU, 60, 60, 200, 120, g_hwnd[OWN]);
    ok(g_hwnd[POP1] != NULL, "popup 1 not created\n");
    Pump();
    EXPECT(__LINE__, "creation of a popup", 0, 0, 0, 0);

    /* A hidden popup is raised: the popup itself and the owner */
    Reset();
    ok(SetWindowPos(g_hwnd[POP1], HWND_TOP, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "hidden popup to the top", 1, 1, 0, 0);
    CheckNotice(__LINE__, "owner, hidden popup to the top", OWN);

    /* Shown without z-order: nothing for the owner */
    Reset();
    ShowWindow(g_hwnd[POP1], SW_SHOWNOACTIVATE);
    Pump();
    ok(g_cChanging[OWN] == 0, "owner got %d WM_WINDOWPOSCHANGING when the popup was shown\n", g_cChanging[OWN]);

    /* The owner is raised: the popup is told, and the owner itself */
    Reset();
    ok(SetWindowPos(g_hwnd[OWN], HWND_TOP, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "owner to the top", 1, 1, 0, 0);
    CheckNotice(__LINE__, "popup, owner to the top", POP1);

    /* The popup goes to the bottom */
    Reset();
    ok(SetWindowPos(g_hwnd[POP1], HWND_BOTTOM, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "popup to the bottom", 1, 1, 0, 0);
    CheckNotice(__LINE__, "owner, popup to the bottom", OWN);

    /* SWP_NOOWNERZORDER and SWP_NOZORDER: the owner is left alone */
    Reset();
    ok(SetWindowPos(g_hwnd[POP1], HWND_TOP, 0, 0, 0, 0, ZFLAGS | SWP_NOOWNERZORDER), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "SWP_NOOWNERZORDER", 0, 1, 0, 0);
    Reset();
    ok(SetWindowPos(g_hwnd[POP1], NULL, 70, 70, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "SWP_NOZORDER", 0, 1, 0, 0);

    /* A move that also z-orders (no SWP_NOZORDER) */
    Reset();
    ok(SetWindowPos(g_hwnd[POP1], NULL, 80, 80, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "move and z-order", 1, 1, 0, 0);

    /* A second popup: shown without z-order, nothing for the others */
    g_hwnd[POP2] = Make(wc.lpszClassName, WS_POPUP | WS_CAPTION, 100, 100, 150, 100, g_hwnd[OWN]);
    ok(g_hwnd[POP2] != NULL, "popup 2 not created\n");
    Reset();
    ShowWindow(g_hwnd[POP2], SW_SHOWNOACTIVATE);
    Pump();
    ok(g_cChanging[OWN] == 0 && g_cChanging[POP1] == 0, "owner %d, popup 1 %d WM_WINDOWPOSCHANGING when popup 2 was shown\n",
       g_cChanging[OWN], g_cChanging[POP1]);

    /* With two popups the other one is told as well */
    Reset();
    ok(SetWindowPos(g_hwnd[POP1], HWND_TOP, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "popup 1 to the top, two popups", 1, 1, 1, 0);
    CheckNotice(__LINE__, "popup 2", POP2);
    CheckNotice(__LINE__, "owner", OWN);

    /* A hidden popup is told too */
    ShowWindow(g_hwnd[POP1], SW_HIDE);
    Reset();
    ok(SetWindowPos(g_hwnd[POP2], HWND_TOP, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "popup 2 to the top, popup 1 hidden", 1, 1, 1, 0);

    /* A window of no group: nobody else is told */
    g_hwnd[UNOWNED] = Make(wc.lpszClassName, WS_OVERLAPPEDWINDOW | WS_VISIBLE, 300, 300, 150, 100, NULL);
    ok(g_hwnd[UNOWNED] != NULL, "window not created\n");
    Pump();
    Reset();
    ok(SetWindowPos(g_hwnd[UNOWNED], HWND_TOP, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "unowned window to the top", 0, 0, 0, 1);

    /* The owner goes to the bottom: every popup, and the owner */
    Reset();
    ok(SetWindowPos(g_hwnd[OWN], HWND_BOTTOM, 0, 0, 0, 0, ZFLAGS), "SetWindowPos failed\n");
    Pump();
    EXPECT(__LINE__, "owner to the bottom", 1, 1, 1, 0);

    DestroyWindow(g_hwnd[POP2]);
    DestroyWindow(g_hwnd[POP1]);
    DestroyWindow(g_hwnd[UNOWNED]);
    DestroyWindow(g_hwnd[OWN]);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
