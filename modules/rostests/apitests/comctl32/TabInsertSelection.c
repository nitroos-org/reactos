/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test that inserting a tab does not select it unless it is the first one
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "wine/test.h"

#include <windows.h>
#include <commctrl.h>

static int g_SelChanging, g_SelChange;

static
LRESULT
CALLBACK
ParentProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    if (Msg == WM_NOTIFY)
    {
        switch (((NMHDR *)lParam)->code)
        {
            case TCN_SELCHANGING: g_SelChanging++; break;
            case TCN_SELCHANGE: g_SelChange++; break;
        }
    }
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static
int
InsertTab(HWND hTab, int Index, PCWSTR Text)
{
    TCITEMW Item = { TCIF_TEXT };

    Item.pszText = (PWSTR)Text;
    return (int)SendMessageW(hTab, TCM_INSERTITEMW, Index, (LPARAM)&Item);
}

START_TEST(tabv6)
{
    WNDCLASSW wc = { 0 };
    HWND hParent, hTab;
    INITCOMMONCONTROLSEX Icc = { sizeof(Icc), ICC_TAB_CLASSES };

    InitCommonControlsEx(&Icc);
    wc.lpfnWndProc = ParentProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"TabInsertSelectionParent";
    RegisterClassW(&wc);
    hParent = CreateWindowW(wc.lpszClassName, L"p", WS_OVERLAPPEDWINDOW, 0, 0, 300, 200, NULL, NULL, wc.hInstance, NULL);
    hTab = CreateWindowW(WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 280, 150, hParent, (HMENU)1, wc.hInstance, NULL);
    ok(hTab != NULL, "No tab control\n");
    if (!hTab)
        return;

    ok_int((int)SendMessageW(hTab, TCM_GETCURSEL, 0, 0), -1);
    ok_int(InsertTab(hTab, 0, L"one"), 0);
    ok_int((int)SendMessageW(hTab, TCM_GETCURSEL, 0, 0), 0);
    ok_int(InsertTab(hTab, 1, L"two"), 1);
    ok_int((int)SendMessageW(hTab, TCM_GETCURSEL, 0, 0), 0);

    /* Nothing selected: an inserted tab stays unselected and announces nothing */
    SendMessageW(hTab, TCM_SETCURSEL, (WPARAM)-1, 0);
    ok_int((int)SendMessageW(hTab, TCM_GETCURSEL, 0, 0), -1);
    g_SelChanging = g_SelChange = 0;
    ok_int(InsertTab(hTab, 2, L"three"), 2);
    ok_int((int)SendMessageW(hTab, TCM_GETCURSEL, 0, 0), -1);
    ok_int(InsertTab(hTab, 0, L"zero"), 0);
    ok_int((int)SendMessageW(hTab, TCM_GETCURSEL, 0, 0), -1);
    ok_int(g_SelChanging, 0);
    ok_int(g_SelChange, 0);

    DestroyWindow(hParent);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
}
