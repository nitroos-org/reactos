/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test TVM_GETITEMSTATE state image bits with TVS_CHECKBOXES
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "wine/test.h"

#include <windows.h>
#include <commctrl.h>

START_TEST(treeviewv6)
{
    HWND hTree;
    HTREEITEM hItem;
    TVINSERTSTRUCTW Ins = { 0 };
    INITCOMMONCONTROLSEX Icc = { sizeof(Icc), ICC_TREEVIEW_CLASSES };
    UINT State;

    InitCommonControlsEx(&Icc);

    /* Without TVS_CHECKBOXES the mask is honoured */
    hTree = CreateWindowW(WC_TREEVIEWW, L"", WS_POPUP | TVS_HASBUTTONS, 0, 0, 200, 200, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hTree != NULL, "No tree view\n");
    if (!hTree)
        return;
    Ins.hParent = TVI_ROOT;
    Ins.hInsertAfter = TVI_LAST;
    Ins.item.mask = TVIF_TEXT;
    Ins.item.pszText = (PWSTR)L"plain";
    hItem = (HTREEITEM)SendMessageW(hTree, TVM_INSERTITEMW, 0, (LPARAM)&Ins);
    ok(hItem != NULL, "Insert failed\n");
    State = (UINT)SendMessageW(hTree, TVM_GETITEMSTATE, (WPARAM)hItem, TVIS_SELECTED);
    ok_hex(State, 0);
    DestroyWindow(hTree);

    /* With TVS_CHECKBOXES the state image bits come back whatever the mask */
    hTree = CreateWindowW(WC_TREEVIEWW, L"", WS_POPUP | TVS_HASBUTTONS | TVS_CHECKBOXES, 0, 0, 200, 200, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hTree != NULL, "No tree view\n");
    if (!hTree)
        return;
    hItem = (HTREEITEM)SendMessageW(hTree, TVM_INSERTITEMW, 0, (LPARAM)&Ins);
    ok(hItem != NULL, "Insert failed\n");
    State = (UINT)SendMessageW(hTree, TVM_GETITEMSTATE, (WPARAM)hItem, TVIS_SELECTED);
    ok_hex(State, 0x1000);
    State = (UINT)SendMessageW(hTree, TVM_GETITEMSTATE, (WPARAM)hItem, 0);
    ok_hex(State, 0x1000);
    State = (UINT)SendMessageW(hTree, TVM_GETITEMSTATE, (WPARAM)hItem, TVIS_STATEIMAGEMASK);
    ok_hex(State, 0x1000);
    State = (UINT)SendMessageW(hTree, TVM_GETITEMSTATE, (WPARAM)hItem, 0xFFFF);
    ok_hex(State, 0x1000);
    DestroyWindow(hTree);
}
