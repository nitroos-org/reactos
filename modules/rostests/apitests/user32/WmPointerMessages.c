/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     System messages whose lParam points to a structure (WM_COMPAREITEM, WM_DELETEITEM, WM_HELP,
 *              CB_GETCOMBOBOXINFO, WM_MDICREATE, WM_MENUGETOBJECT) reach a window procedure with the record
 *              intact, and a record the procedure changes comes back to the sender, in every process flavour.
 *              A 32-bit process under WoW64 used to get ERROR_CALL_NOT_IMPLEMENTED for all of them whenever
 *              the message went through win32k (SendMessageTimeout, a send to another thread, DefWindowProc).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define MSG_CB_GETCOMBOBOXINFO 0x0164
#define MNGO_NOERROR 1

#define ITEM_DATA1 ((ULONG_PTR)0x11111111)
#define ITEM_DATA2 ((ULONG_PTR)0x22222222)
#define CONTEXT_ID ((DWORD_PTR)0x44444444)

static HINSTANCE g_hinst;
static HWND g_frame;
static HMENU g_menu;
static const GUID g_guid = { 0x12345678, 0x1234, 0x5678, { 1, 2, 3, 4, 5, 6, 7, 8 } };
static int g_bad;       /* record contents the procedure did not expect */
static int g_seen[0x400];
static int g_deleted_count;
static ULONG_PTR g_deleted[16];
static int g_compare_count;
static BOOL g_forward_to_def; /* the procedure hands the message to DefWindowProc */

#define BAD(...) do { g_bad++; trace("BAD: " __VA_ARGS__); } while (0)

static LRESULT CALLBACK RecProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg < ARRAYSIZE(g_seen) && (msg == WM_COMPAREITEM || msg == WM_DELETEITEM || msg == WM_HELP ||
        msg == MSG_CB_GETCOMBOBOXINFO || msg == WM_MDICREATE || msg == WM_MENUGETOBJECT))
    {
        if (g_forward_to_def)
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        g_seen[msg]++;
    }

    switch (msg)
    {
    case WM_COMPAREITEM:
    {
        COMPAREITEMSTRUCT *cis = (COMPAREITEMSTRUCT *)lParam;

        g_compare_count++;
        if (cis->itemData1 == ITEM_DATA1 && cis->itemData2 == ITEM_DATA2)
        {
            /* the record of the test */
            if (wParam != 77 || cis->CtlType != ODT_LISTBOX || cis->CtlID != 77 || cis->hwndItem != hwnd ||
                cis->itemID1 != 3 || cis->itemID2 != 5 || cis->dwLocaleId != 0x409)
                BAD("WM_COMPAREITEM record\n");
            return cis->itemData1 < cis->itemData2 ? -1 : 1;
        }
        if (cis->CtlType != ODT_LISTBOX && cis->CtlType != ODT_COMBOBOX)
            BAD("WM_COMPAREITEM record type %u\n", cis->CtlType);
        /* a real owner-draw control: sort by item data */
        return cis->itemData1 < cis->itemData2 ? -1 : cis->itemData1 > cis->itemData2 ? 1 : 0;
    }
    case WM_DELETEITEM:
    {
        DELETEITEMSTRUCT *dis = (DELETEITEMSTRUCT *)lParam;

        if (dis->itemData == (ULONG_PTR)0x33333333)
        {
            /* the record of the test */
            if (wParam != 77 || dis->CtlType != ODT_LISTBOX || dis->CtlID != 77 || dis->itemID != 4 ||
                dis->hwndItem != hwnd)
                BAD("WM_DELETEITEM record\n");
            return TRUE;
        }
        if (g_deleted_count < ARRAYSIZE(g_deleted))
            g_deleted[g_deleted_count++] = dis->itemData;
        return TRUE;
    }
    case WM_HELP:
    {
        HELPINFO *hi = (HELPINFO *)lParam;

        if (hi->cbSize != sizeof(*hi) || hi->iContextType != HELPINFO_WINDOW || hi->iCtrlId != 9 ||
            hi->hItemHandle != (HANDLE)hwnd || hi->dwContextId != CONTEXT_ID || hi->MousePos.x != 10 ||
            hi->MousePos.y != -20)
            BAD("WM_HELP record: size %lu type %d id %d item %p ctx %lx pos %ld,%ld\n", (ULONG)hi->cbSize,
                hi->iContextType, hi->iCtrlId, hi->hItemHandle, (ULONG)hi->dwContextId, hi->MousePos.x,
                hi->MousePos.y);
        /* win32k copies the record to the receiver but not back: a change is not part of the contract */
        return TRUE;
    }
    case MSG_CB_GETCOMBOBOXINFO:
    {
        COMBOBOXINFO *ci = (COMBOBOXINFO *)lParam;

        if (ci->cbSize != sizeof(*ci))
        {
            BAD("CB_GETCOMBOBOXINFO cbSize %lu\n", (ULONG)ci->cbSize);
            return FALSE;
        }
        SetRect(&ci->rcItem, 1, 2, 3, 4);
        SetRect(&ci->rcButton, 5, 6, 7, 8);
        ci->stateButton = STATE_SYSTEM_PRESSED;
        ci->hwndCombo = hwnd;
        ci->hwndItem = (HWND)(ULONG_PTR)0x1234;
        ci->hwndList = hwnd;
        return TRUE;
    }
    case WM_MDICREATE:
    {
        MDICREATESTRUCTW *mcs = (MDICREATESTRUCTW *)lParam;

        if (!mcs->szClass || lstrcmpW(mcs->szClass, L"MdiClassX") || !mcs->szTitle ||
            lstrcmpW(mcs->szTitle, L"Title") || mcs->hOwner != g_hinst || mcs->x != 1 || mcs->y != -2 ||
            mcs->cx != 3 || mcs->cy != 4 || mcs->style != 5 || mcs->lParam != (LPARAM)0x66666666)
            BAD("WM_MDICREATE record\n");
        return 0xABCD;
    }
    case WM_MENUGETOBJECT:
    {
        MENUGETOBJECTINFO *mgo = (MENUGETOBJECTINFO *)lParam;

        if (mgo->dwFlags != MNGOF_BOTTOMGAP || mgo->uPos != 2 || mgo->hmenu != g_menu || mgo->riid != &g_guid ||
            mgo->pvObj != NULL)
            BAD("WM_MENUGETOBJECT record\n");
        mgo->pvObj = (PVOID)&g_guid;
        return MNGO_NOERROR;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void init_records(COMPAREITEMSTRUCT *cis, DELETEITEMSTRUCT *dis, HELPINFO *hi, COMBOBOXINFO *ci,
                         MDICREATESTRUCTW *mcs, MENUGETOBJECTINFO *mgo, HWND hwnd)
{
    memset(cis, 0, sizeof(*cis));
    cis->CtlType = ODT_LISTBOX; cis->CtlID = 77; cis->hwndItem = hwnd; cis->itemID1 = 3;
    cis->itemData1 = ITEM_DATA1; cis->itemID2 = 5; cis->itemData2 = ITEM_DATA2; cis->dwLocaleId = 0x409;
    memset(dis, 0, sizeof(*dis));
    dis->CtlType = ODT_LISTBOX; dis->CtlID = 77; dis->itemID = 4; dis->hwndItem = hwnd;
    dis->itemData = (ULONG_PTR)0x33333333;
    memset(hi, 0, sizeof(*hi));
    hi->cbSize = sizeof(*hi); hi->iContextType = HELPINFO_WINDOW; hi->iCtrlId = 9; hi->hItemHandle = hwnd;
    hi->dwContextId = CONTEXT_ID; hi->MousePos.x = 10; hi->MousePos.y = -20;
    memset(ci, 0, sizeof(*ci));
    ci->cbSize = sizeof(*ci);
    memset(mcs, 0, sizeof(*mcs));
    mcs->szClass = L"MdiClassX"; mcs->szTitle = L"Title"; mcs->hOwner = g_hinst; mcs->x = 1; mcs->y = -2;
    mcs->cx = 3; mcs->cy = 4; mcs->style = 5; mcs->lParam = (LPARAM)0x66666666;
    memset(mgo, 0, sizeof(*mgo));
    mgo->dwFlags = MNGOF_BOTTOMGAP; mgo->uPos = 2; mgo->hmenu = g_menu; mgo->riid = (PVOID)&g_guid;
}

typedef struct
{
    LRESULT ret[6];
    DWORD error[6];
    BOOL sent[6];
    COMPAREITEMSTRUCT cis;
    DELETEITEMSTRUCT dis;
    HELPINFO hi;
    COMBOBOXINFO ci;
    MDICREATESTRUCTW mcs;
    MENUGETOBJECTINFO mgo;
} RESULTS;

static const UINT g_msgs[6] =
{ WM_COMPAREITEM, WM_DELETEITEM, WM_HELP, MSG_CB_GETCOMBOBOXINFO, WM_MDICREATE, WM_MENUGETOBJECT };

/* Send all six messages to hwnd, either with SendMessageTimeout (always through win32k) or with SendMessage */
static void send_all(HWND hwnd, BOOL timeout, RESULTS *r)
{
    int i;

    init_records(&r->cis, &r->dis, &r->hi, &r->ci, &r->mcs, &r->mgo, hwnd);
    for (i = 0; i < 6; i++)
    {
        WPARAM wp = (i < 2) ? 77 : 0;
        LPARAM lp = (LPARAM)(i == 0 ? (void *)&r->cis : i == 1 ? (void *)&r->dis : i == 2 ? (void *)&r->hi :
                             i == 3 ? (void *)&r->ci : i == 4 ? (void *)&r->mcs : (void *)&r->mgo);
        DWORD_PTR res = 0;

        SetLastError(0xDEADBEEF);
        if (timeout)
        {
            r->sent[i] = SendMessageTimeoutW(hwnd, g_msgs[i], wp, lp, SMTO_NORMAL, 10000, &res) != 0;
            r->ret[i] = (LRESULT)res;
        }
        else
        {
            r->ret[i] = SendMessageW(hwnd, g_msgs[i], wp, lp);
            r->sent[i] = TRUE;
        }
        r->error[i] = GetLastError();
    }
}

static void check_results(const char *what, HWND hwnd, const RESULTS *r)
{
    int i;
    static const LRESULT expect[6] = { -1, TRUE, TRUE, TRUE, 0xABCD, MNGO_NOERROR };

    for (i = 0; i < 6; i++)
    {
        ok(r->sent[i], "%s: message %#x failed: %lu\n", what, g_msgs[i], r->error[i]);
        ok(r->ret[i] == expect[i], "%s: message %#x returned %ld, expected %ld\n", what, g_msgs[i],
           (long)r->ret[i], (long)expect[i]);
        ok(r->error[i] == 0xDEADBEEF, "%s: message %#x set the last error to %lu\n", what, g_msgs[i], r->error[i]);
    }
    /* WM_HELP is input only */
    ok(r->hi.dwContextId == CONTEXT_ID && r->hi.iCtrlId == 9 && r->hi.MousePos.x == 10 &&
       r->hi.MousePos.y == -20 && r->hi.cbSize == sizeof(HELPINFO) && r->hi.hItemHandle == (HANDLE)hwnd &&
       r->hi.iContextType == HELPINFO_WINDOW,
       "%s: WM_HELP record came back as ctx %lx id %d pos %ld,%ld size %lu item %p\n", what,
       (ULONG)r->hi.dwContextId, r->hi.iCtrlId, r->hi.MousePos.x, r->hi.MousePos.y, (ULONG)r->hi.cbSize,
       r->hi.hItemHandle);
    /* what the procedure wrote */
    ok(r->ci.rcItem.left == 1 && r->ci.rcItem.bottom == 4 && r->ci.rcButton.left == 5 && r->ci.rcButton.bottom == 8 &&
       r->ci.stateButton == STATE_SYSTEM_PRESSED && r->ci.hwndCombo == hwnd && r->ci.hwndItem == (HWND)(ULONG_PTR)0x1234 &&
       r->ci.hwndList == hwnd,
       "%s: CB_GETCOMBOBOXINFO record came back as %ld %ld %lx %p %p %p\n", what, r->ci.rcItem.left,
       r->ci.rcButton.left, r->ci.stateButton, r->ci.hwndCombo, r->ci.hwndItem, r->ci.hwndList);
    ok(r->mgo.pvObj == (PVOID)&g_guid, "%s: WM_MENUGETOBJECT pvObj came back as %p\n", what, r->mgo.pvObj);
    /* read-only records stay as they were */
    ok(r->cis.itemData1 == ITEM_DATA1 && r->cis.itemData2 == ITEM_DATA2 && r->cis.hwndItem == hwnd,
       "%s: WM_COMPAREITEM record changed\n", what);
    ok(r->dis.itemData == (ULONG_PTR)0x33333333 && r->dis.hwndItem == hwnd, "%s: WM_DELETEITEM record changed\n", what);
    ok(r->mcs.lParam == (LPARAM)0x66666666 && r->mcs.cy == 4, "%s: WM_MDICREATE record changed\n", what);
}

static DWORD WINAPI send_thread(void *param)
{
    RESULTS *r = param;
    send_all(g_frame, FALSE, r);
    return 0;
}

static void pump_until(HANDLE thread)
{
    MSG msg;

    while (MsgWaitForMultipleObjects(1, &thread, FALSE, 20000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
}

/* A thread with an owner window, a message loop and a LISTBOX/COMBOBOX owner role */
static HWND g_owner2;
static HANDLE g_owner_ready, g_owner_quit;

static DWORD WINAPI owner_thread(void *param)
{
    MSG msg;

    g_owner2 = CreateWindowExW(0, L"WmPointerMessagesFrame", L"o", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL,
                               g_hinst, NULL);
    SetEvent(g_owner_ready);
    while (MsgWaitForMultipleObjects(1, &g_owner_quit, FALSE, 30000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
    DestroyWindow(g_owner2);
    return 0;
}

static void test_def_window_proc(void)
{
    RESULTS r;
    int i;

    /* the same records handed down to DefWindowProc: it leaves them alone and the send succeeds */
    g_forward_to_def = TRUE;
    send_all(g_frame, TRUE, &r);
    g_forward_to_def = FALSE;
    for (i = 0; i < 6; i++)
    {
        ok(r.sent[i], "DefWindowProc: message %#x failed: %lu\n", g_msgs[i], r.error[i]);
        ok(r.ret[i] == 0, "DefWindowProc: message %#x returned %ld\n", g_msgs[i], (long)r.ret[i]);
    }
    ok(r.hi.dwContextId == CONTEXT_ID && r.hi.iCtrlId == 9 && r.hi.MousePos.x == 10 && r.hi.MousePos.y == -20,
       "DefWindowProc: WM_HELP record changed (ctx %lx id %d)\n", (ULONG)r.hi.dwContextId, r.hi.iCtrlId);
    ok(r.ci.rcItem.left == 0 && r.ci.hwndCombo == NULL, "DefWindowProc: COMBOBOXINFO changed\n");
    ok(r.mgo.pvObj == NULL, "DefWindowProc: MENUGETOBJECTINFO changed\n");
}

static void test_listbox_owner(const char *what, HWND owner, DWORD style)
{
    /* an owner-draw sorted LISTBOX without strings: each LB_ADDSTRING is a binary search of WM_COMPAREITEM */
    static const ULONG_PTR data[] = { 30, 10, 50, 20, 40 };
    HWND lb;
    int i, n;

    lb = CreateWindowExW(0, L"LISTBOX", L"", WS_CHILD | LBS_OWNERDRAWFIXED | LBS_SORT | style, 0, 0, 100, 100, owner,
                         (HMENU)(ULONG_PTR)77, g_hinst, NULL);
    ok(lb != NULL, "%s: LISTBOX creation failed: %lu\n", what, GetLastError());
    if (!lb)
        return;
    g_compare_count = 0;
    g_deleted_count = 0;
    for (i = 0; i < ARRAYSIZE(data); i++)
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)data[i]);
    n = (int)SendMessageW(lb, LB_GETCOUNT, 0, 0);
    ok(n == ARRAYSIZE(data), "%s: LB_GETCOUNT returned %d\n", what, n);
    ok(g_compare_count > 0, "%s: WM_COMPAREITEM was never sent\n", what);
    for (i = 0; i < n; i++)
    {
        ULONG_PTR v = (ULONG_PTR)SendMessageW(lb, LB_GETITEMDATA, i, 0);
        ok(v == (i + 1) * 10, "%s: sorted item %d has data %lu\n", what, i, (ULONG)v);
    }
    /* deleting one item and clearing the rest: WM_DELETEITEM for each, with the item data */
    SendMessageW(lb, LB_DELETESTRING, 0, 0);
    ok(g_deleted_count == 1 && g_deleted[0] == 10, "%s: LB_DELETESTRING gave %d WM_DELETEITEM (first %lu)\n", what,
       g_deleted_count, g_deleted_count ? (ULONG)g_deleted[0] : 0);
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    ok(g_deleted_count == 5, "%s: LB_RESETCONTENT gave %d WM_DELETEITEM in total\n", what, g_deleted_count);
    for (i = 1; i < g_deleted_count; i++)
        ok(g_deleted[i] >= 20 && g_deleted[i] <= 50 && g_deleted[i] % 10 == 0, "%s: deleted data %lu\n", what,
           (ULONG)g_deleted[i]);
    DestroyWindow(lb);
}

static void test_combobox_owner(const char *what, HWND owner)
{
    static const ULONG_PTR data[] = { 3, 1, 2 };
    HWND cb;
    int i;
    COMBOBOXINFO ci;
    DWORD_PTR res;
    LRESULT ret;

    cb = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_SORT, 0, 0, 100,
                         200, owner, (HMENU)(ULONG_PTR)77, g_hinst, NULL);
    ok(cb != NULL, "%s: COMBOBOX creation failed: %lu\n", what, GetLastError());
    if (!cb)
        return;
    g_compare_count = 0;
    g_deleted_count = 0;
    for (i = 0; i < ARRAYSIZE(data); i++)
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)data[i]);
    ok(g_compare_count > 0, "%s: combo: WM_COMPAREITEM was never sent\n", what);
    for (i = 0; i < ARRAYSIZE(data); i++)
    {
        ULONG_PTR v = (ULONG_PTR)SendMessageW(cb, CB_GETITEMDATA, i, 0);
        ok(v == i + 1, "%s: combo item %d has data %lu\n", what, i, (ULONG)v);
    }
    SendMessageW(cb, CB_RESETCONTENT, 0, 0);
    ok(g_deleted_count == 3, "%s: CB_RESETCONTENT gave %d WM_DELETEITEM\n", what, g_deleted_count);

    /* the control's own answer to CB_GETCOMBOBOXINFO, through win32k */
    memset(&ci, 0, sizeof(ci));
    ci.cbSize = sizeof(ci);
    res = 0;
    SetLastError(0xDEADBEEF);
    ret = SendMessageTimeoutW(cb, MSG_CB_GETCOMBOBOXINFO, 0, (LPARAM)&ci, SMTO_NORMAL, 10000, &res);
    ok(ret != 0 && res == TRUE, "%s: CB_GETCOMBOBOXINFO via SendMessageTimeout: %ld %ld (%lu)\n", what, (long)ret,
       (long)res, GetLastError());
    ok(ci.hwndCombo == cb && ci.hwndList != NULL && IsWindow(ci.hwndList),
       "%s: CB_GETCOMBOBOXINFO: combo %p list %p\n", what, ci.hwndCombo, ci.hwndList);
    ok(ci.rcButton.right > ci.rcButton.left, "%s: CB_GETCOMBOBOXINFO: empty button rectangle\n", what);
    DestroyWindow(cb);
}

static void test_mdi(void)
{
    WNDCLASSW wc = { 0 };
    CLIENTCREATESTRUCT ccs = { 0 };
    MDICREATESTRUCTW mcs;
    HWND frame, client, child, child2;
    DWORD_PTR res;
    LRESULT ret;

    wc.lpfnWndProc = DefMDIChildProcW;
    wc.hInstance = g_hinst;
    wc.lpszClassName = L"MdiClassX";
    RegisterClassW(&wc);
    frame = CreateWindowExW(0, L"WmPointerMessagesFrame", L"mdi", WS_OVERLAPPEDWINDOW, 0, 0, 300, 200, NULL, NULL,
                            g_hinst, NULL);
    client = CreateWindowExW(0, L"MDICLIENT", L"", WS_CHILD | WS_VISIBLE, 0, 0, 200, 100, frame, (HMENU)1, g_hinst,
                             &ccs);
    ok(client != NULL, "MDICLIENT creation failed: %lu\n", GetLastError());
    if (client)
    {
        memset(&mcs, 0, sizeof(mcs));
        mcs.szClass = L"MdiClassX"; mcs.szTitle = L"Child"; mcs.hOwner = g_hinst;
        mcs.x = 5; mcs.y = 6; mcs.cx = 150; mcs.cy = 40; mcs.style = 0;

        /* SendMessage: a same-thread MDICLIENT is called directly */
        SetLastError(0xDEADBEEF);
        child = (HWND)SendMessageW(client, WM_MDICREATE, 0, (LPARAM)&mcs);
        ok(child != NULL && IsWindow(child), "WM_MDICREATE returned %p (%lu)\n", child, GetLastError());

        /* SendMessageTimeout always reaches win32k and the callback */
        res = 0;
        SetLastError(0xDEADBEEF);
        ret = SendMessageTimeoutW(client, WM_MDICREATE, 0, (LPARAM)&mcs, SMTO_NORMAL, 10000, &res);
        child2 = (HWND)res;
        ok(ret != 0, "SendMessageTimeout(WM_MDICREATE) failed: %lu\n", GetLastError());
        ok(child2 != NULL && IsWindow(child2) && child2 != child, "SendMessageTimeout(WM_MDICREATE) returned %p\n",
           child2);
        ok(GetParent(child2) == client, "the MDI child has parent %p\n", GetParent(child2));
        if (child2)
        {
            char title[16] = "";
            RECT rc;

            GetWindowTextA(child2, title, sizeof(title));
            ok(!strcmp(title, "Child"), "the MDI child is called '%s'\n", title);
            GetWindowRect(child2, &rc);
            ok(rc.right - rc.left == 150 && rc.bottom - rc.top == 40, "the MDI child is %ldx%ld\n",
               rc.right - rc.left, rc.bottom - rc.top);
            SendMessageW(client, WM_MDIDESTROY, (WPARAM)child2, 0);
        }
        if (child)
            SendMessageW(client, WM_MDIDESTROY, (WPARAM)child, 0);
    }
    DestroyWindow(frame);
    UnregisterClassW(L"MdiClassX", g_hinst);
}

START_TEST(WmPointerMessages)
{
    WNDCLASSW wc = { 0 };
    RESULTS r;
    HANDLE thread;
    DWORD tid;
    HWND other;

    g_hinst = GetModuleHandleW(NULL);
    g_menu = CreateMenu();
    wc.lpfnWndProc = RecProc;
    wc.hInstance = g_hinst;
    wc.lpszClassName = L"WmPointerMessagesFrame";
    RegisterClassW(&wc);
    g_frame = CreateWindowExW(0, wc.lpszClassName, L"f", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL, g_hinst, NULL);
    ok(g_frame != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!g_frame)
        return;

    /* SendMessage on the same thread: the procedure is called directly */
    g_bad = 0;
    memset(g_seen, 0, sizeof(g_seen));
    send_all(g_frame, FALSE, &r);
    check_results("SendMessage, same thread", g_frame, &r);

    /* SendMessageTimeout: always through win32k and its callback to the window procedure */
    send_all(g_frame, TRUE, &r);
    check_results("SendMessageTimeout, same thread", g_frame, &r);

    /* a send from another thread of this process, which the main thread dispatches */
    memset(&r, 0, sizeof(r));
    thread = CreateThread(NULL, 0, send_thread, &r, 0, &tid);
    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (thread)
    {
        pump_until(thread);
        CloseHandle(thread);
        check_results("SendMessage, other thread", g_frame, &r);
    }

    /* a window of another thread, which this thread sends to */
    g_owner_ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_owner_quit = CreateEventW(NULL, FALSE, FALSE, NULL);
    thread = CreateThread(NULL, 0, owner_thread, NULL, 0, &tid);
    ok(thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (thread)
    {
        WaitForSingleObject(g_owner_ready, 20000);
        other = g_owner2;
        ok(other != NULL, "the owner thread has no window\n");
        if (other)
        {
            send_all(other, FALSE, &r);
            check_results("SendMessage to another thread", other, &r);
            send_all(other, TRUE, &r);
            check_results("SendMessageTimeout to another thread", other, &r);
            /* owner-draw controls whose owner is on another thread: win32k delivers the records */
            test_listbox_owner("LISTBOX, owner on another thread", other, 0);
            test_combobox_owner("COMBOBOX, owner on another thread", other);
        }
        SetEvent(g_owner_quit);
        WaitForSingleObject(thread, 20000);
        CloseHandle(thread);
    }
    CloseHandle(g_owner_ready);
    CloseHandle(g_owner_quit);

    test_def_window_proc();
    /* owner-draw controls whose owner is on the same thread */
    test_listbox_owner("LISTBOX, owner on the same thread", g_frame, 0);
    test_combobox_owner("COMBOBOX, owner on the same thread", g_frame);
    test_mdi();

    ok(g_bad == 0, "%d records did not arrive as sent\n", g_bad);
    ok(g_seen[WM_HELP] >= 4 && g_seen[WM_COMPAREITEM] >= 4 && g_seen[WM_DELETEITEM] >= 4 &&
       g_seen[MSG_CB_GETCOMBOBOXINFO] >= 4 && g_seen[WM_MDICREATE] >= 4 && g_seen[WM_MENUGETOBJECT] >= 4,
       "messages seen: help %d compare %d delete %d combo %d mdi %d menu %d\n", g_seen[WM_HELP],
       g_seen[WM_COMPAREITEM], g_seen[WM_DELETEITEM], g_seen[MSG_CB_GETCOMBOBOXINFO], g_seen[WM_MDICREATE],
       g_seen[WM_MENUGETOBJECT]);

    DestroyWindow(g_frame);
    DestroyMenu(g_menu);
    UnregisterClassW(wc.lpszClassName, g_hinst);
}
