/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     SetWindowRgn must not change the Z order of the window among its siblings
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static UINT g_LastPosFlags;
static INT g_PosChanging;

static LRESULT CALLBACK ChildProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_WINDOWPOSCHANGING)
    {
        g_LastPosFlags = ((WINDOWPOS *)lParam)->flags;
        g_PosChanging++;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* Returns the child windows of hwndParent in sibling order, separated into a string of indices */
static INT ChildIndex(HWND hwndParent, HWND hwnd)
{
    HWND hwndNext;
    INT i = 0;

    for (hwndNext = GetWindow(hwndParent, GW_CHILD); hwndNext; hwndNext = GetWindow(hwndNext, GW_HWNDNEXT), i++)
    {
        if (hwndNext == hwnd)
            return i;
    }
    return -1;
}

static void CheckOrder(const char *label, HWND hwndParent, HWND *phwnd)
{
    ok(ChildIndex(hwndParent, phwnd[0]) == 0, "%s: first child moved, index %d\n", label, ChildIndex(hwndParent, phwnd[0]));
    ok(ChildIndex(hwndParent, phwnd[1]) == 1, "%s: second child moved, index %d\n", label, ChildIndex(hwndParent, phwnd[1]));
    ok(ChildIndex(hwndParent, phwnd[2]) == 2, "%s: third child moved, index %d\n", label, ChildIndex(hwndParent, phwnd[2]));
}

START_TEST(SetWindowRgn)
{
    WNDCLASSW wc;
    HWND hwndParent, hwnd[3];
    HINSTANCE hInst = GetModuleHandleW(NULL);
    HRGN hrgn;
    INT i, round;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = ChildProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SetWindowRgnTest";
    RegisterClassW(&wc);

    hwndParent = CreateWindowExW(0, L"SetWindowRgnTest", L"parent", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                 10, 10, 300, 200, NULL, NULL, hInst, NULL);
    if (!hwndParent)
    {
        skip("Could not create the parent window\n");
        return;
    }
    for (i = 0; i < 3; i++)
        hwnd[i] = CreateWindowExW(0, L"SetWindowRgnTest", L"child", WS_CHILD | WS_VISIBLE,
                                  i * 40, 0, 36, 24, hwndParent, NULL, hInst, NULL);

    CheckOrder("initial", hwndParent, hwnd);

    for (round = 0; round < 2; round++)
    {
        BOOL bRedraw = (round == 0);

        for (i = 2; i >= 0; i--)
        {
            INT ret;

            hrgn = CreateRectRgn(0, 0, 30, 20);
            g_PosChanging = 0;
            g_LastPosFlags = 0;
            ret = SetWindowRgn(hwnd[i], hrgn, bRedraw);
            ok(ret != 0, "SetWindowRgn(%d) failed %lu\n", i, GetLastError());
            ok(g_PosChanging >= 1, "no WM_WINDOWPOSCHANGING for child %d\n", i);
            ok((g_LastPosFlags & SWP_NOZORDER) != 0, "child %d: flags 0x%x lack SWP_NOZORDER\n", i, g_LastPosFlags);
            CheckOrder(bRedraw ? "redraw" : "noredraw", hwndParent, hwnd);
        }
    }

    /* Removing the region keeps the order too */
    for (i = 2; i >= 0; i--)
    {
        SetWindowRgn(hwnd[i], NULL, TRUE);
        CheckOrder("remove", hwndParent, hwnd);
    }

    for (i = 0; i < 3; i++)
        DestroyWindow(hwnd[i]);
    DestroyWindow(hwndParent);
    UnregisterClassW(L"SetWindowRgnTest", hInst);
}
