/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Raw DDE (WM_DDE_*) between two processes: initiate, execute, poke, request/data, advise, ack,
 *              terminate. The parent is the client, a copy of the program the server. The packed lParam of
 *              PackDDElParam, the global blocks and the acknowledgements of win32k's DDE hooks must arrive as sent.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <dde.h>

static HINSTANCE g_hinst;
static HWND g_wnd;
static HWND g_partner;
static ATOM g_app, g_topic, g_item;
static BOOL g_server;
static int g_state[16];
static CHAR g_cmd[64];

#define CF_PROBE CF_TEXT

static HGLOBAL make_data(UINT fmt, const char *text, WORD flags)
{
    DWORD len = lstrlenA(text) + 1;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, sizeof(DDEDATA) + len);
    DDEDATA *dd = h ? GlobalLock(h) : NULL;
    if (dd)
    {
        memset(dd, 0, sizeof(DDEDATA));
        dd->fRelease = (flags & 1) != 0; dd->fAckReq = (flags & 2) != 0; dd->cfFormat = (SHORT)fmt;
        memcpy(dd->Value, text, len);
        GlobalUnlock(h);
    }
    return h;
}

static BOOL check_data(HGLOBAL h, const char *text)
{
    DDEDATA *dd = h ? GlobalLock(h) : NULL;
    BOOL ret = dd && dd->cfFormat == CF_PROBE && !strcmp((char *)dd->Value, text);
    if (dd)
        GlobalUnlock(h);
    return ret;
}

static void post_ack(HWND to, UINT_PTR status_or_data, UINT_PTR item)
{
    LPARAM lp = PackDDElParam(WM_DDE_ACK, status_or_data, item);
    if (!PostMessageW(to, WM_DDE_ACK, (WPARAM)g_wnd, lp))
        trace("post ack failed %lu\n", GetLastError());
}

static LRESULT CALLBACK DdeProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    UINT_PTR lo, hi;

    switch (msg)
    {
    case WM_DDE_INITIATE:
        if (g_server && LOWORD(lParam) == g_app && HIWORD(lParam) == g_topic)
        {
            /* a cross-process send of the acknowledgement: the atoms must be duplicated by the sender */
            ATOM a = GlobalAddAtomW(L"WmDdeApp"), t = GlobalAddAtomW(L"WmDdeTopic");
            SendMessageW((HWND)wParam, WM_DDE_ACK, (WPARAM)hwnd, MAKELPARAM(a, t));
            GlobalDeleteAtom(a); GlobalDeleteAtom(t);
        }
        return 0;
    case WM_DDE_ACK:
        if (!g_server && g_state[0] == 0)
        {
            /* the answer to WM_DDE_INITIATE */
            g_partner = (HWND)wParam;
            g_state[0] = 1;
            GlobalDeleteAtom(LOWORD(lParam)); GlobalDeleteAtom(HIWORD(lParam));
            return 0;
        }
        if (UnpackDDElParam(WM_DDE_ACK, lParam, &lo, &hi))
        {
            if (!g_server)
            {
                /* status in the low word, the execute block or the item in the high one */
                g_state[1]++; g_state[2] = (int)lo; g_state[3] = (int)hi;
                if (g_state[1] == 1 && hi)
                    GlobalFree((HGLOBAL)hi);
                if (g_state[1] == 2 && hi)
                    GlobalDeleteAtom((ATOM)hi);
            }
            FreeDDElParam(WM_DDE_ACK, lParam);
        }
        else
            g_state[4]++;
        return 0;
    case WM_DDE_EXECUTE:
        if (g_server)
        {
            const char *s = GlobalLock((HGLOBAL)lParam);
            BOOL good = s && !strcmp(s, "[WmDdeCommand(1,2)]");
            ok(good, "server: execute string '%s'\n", s ? s : "(null)");
            if (s)
                GlobalUnlock((HGLOBAL)lParam);
            g_state[5]++;
            /* the ACK carries the execute block back */
            post_ack((HWND)wParam, 0x8000 | (good ? 0 : 0), lParam);
        }
        return 0;
    case WM_DDE_POKE:
        if (g_server && UnpackDDElParam(WM_DDE_POKE, lParam, &lo, &hi))
        {
            BOOL good = check_data((HGLOBAL)lo, "poked value") && (ATOM)hi == g_item;
            ok(good, "server: poke block %p item %x\n", (void *)lo, (UINT)hi);
            g_state[6]++;
            GlobalFree((HGLOBAL)lo);
            FreeDDElParam(WM_DDE_POKE, lParam);
            post_ack((HWND)wParam, 0x8000, hi);
        }
        return 0;
    case WM_DDE_REQUEST:
        if (g_server && LOWORD(lParam) == CF_PROBE)
        {
            HGLOBAL h = make_data(CF_PROBE, "requested value", 1);
            LPARAM lp = PackDDElParam(WM_DDE_DATA, (UINT_PTR)h, HIWORD(lParam));
            g_state[7]++;
            PostMessageW((HWND)wParam, WM_DDE_DATA, (WPARAM)hwnd, lp);
        }
        return 0;
    case WM_DDE_ADVISE:
        if (g_server && UnpackDDElParam(WM_DDE_ADVISE, lParam, &lo, &hi))
        {
            DDEADVISE *da = GlobalLock((HGLOBAL)lo);
            BOOL good = da && da->cfFormat == CF_PROBE && da->fDeferUpd == 0 && da->fAckReq == 1;
            ok(good, "server: advise block\n");
            if (da)
                GlobalUnlock((HGLOBAL)lo);
            g_state[8]++;
            GlobalFree((HGLOBAL)lo);
            FreeDDElParam(WM_DDE_ADVISE, lParam);
            post_ack((HWND)wParam, 0x8000, hi);
            /* the server pushes the data of the item */
            {
                HGLOBAL h = make_data(CF_PROBE, "advised value", 3);
                PostMessageW((HWND)wParam, WM_DDE_DATA, (WPARAM)hwnd, PackDDElParam(WM_DDE_DATA, (UINT_PTR)h, hi));
            }
        }
        return 0;
    case WM_DDE_DATA:
        if (!g_server && UnpackDDElParam(WM_DDE_DATA, lParam, &lo, &hi))
        {
            if (check_data((HGLOBAL)lo, "requested value")) g_state[9]++;
            else if (check_data((HGLOBAL)lo, "advised value")) g_state[10]++;
            else g_state[4]++;
            GlobalFree((HGLOBAL)lo);
            GlobalDeleteAtom((ATOM)hi);
            FreeDDElParam(WM_DDE_DATA, lParam);
        }
        return 0;
    case WM_DDE_TERMINATE:
        g_state[11]++;
        if (g_server)
        {
            PostMessageW((HWND)wParam, WM_DDE_TERMINATE, (WPARAM)hwnd, 0);
            PostMessageW(hwnd, WM_USER + 1, 0, 0);
        }
        return 0;
    case WM_USER + 1:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static BOOL pump_until_state(int idx, int count, DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG msg;

    while ((int)g_state[idx] < count && (int)(end - GetTickCount()) > 0)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(10);
    }
    return g_state[idx] >= count;
}

static int run_server(void)
{
    MSG msg;
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"WmDdeReady");

    g_server = TRUE;
    g_wnd = CreateWindowExW(0, L"WmDdeClass", L"server", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, g_hinst, NULL);
    g_app = GlobalAddAtomW(L"WmDdeApp"); g_topic = GlobalAddAtomW(L"WmDdeTopic"); g_item = GlobalAddAtomW(L"WmDdeItem");
    if (ready)
        SetEvent(ready);
    {
        DWORD end = GetTickCount() + 30000;
        while ((int)(end - GetTickCount()) > 0)
        {
            if (!PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) { Sleep(10); continue; }
            if (msg.message == WM_QUIT)
                break;
            DispatchMessageW(&msg);
        }
    }
    ok(g_state[5] == 1 && g_state[6] == 1 && g_state[7] == 1 && g_state[8] == 1, "server saw execute %d poke %d request %d advise %d\n",
       g_state[5], g_state[6], g_state[7], g_state[8]);
    return 0;
}

START_TEST(WmDde)
{
    WNDCLASSW wc = { 0 };
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    HANDLE ready, proc;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH + 32];
    HWND srv;
    HGLOBAL h;
    DWORD code;

    g_hinst = GetModuleHandleW(NULL);
    wc.lpfnWndProc = DdeProc;
    wc.hInstance = g_hinst;
    wc.lpszClassName = L"WmDdeClass";
    RegisterClassW(&wc);
    if (argc > 2 && !strcmp(argv[2], "server"))
    {
        run_server();
        return;
    }

    ready = CreateEventW(NULL, FALSE, FALSE, L"WmDdeReady");
    sprintf(cmd, "\"%s\" WmDde server", argv[0]);
    ok(CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi), "CreateProcess failed: %lu\n", GetLastError());
    ok(WaitForSingleObject(ready, 30000) == WAIT_OBJECT_0, "the server did not start\n");
    proc = pi.hProcess;

    g_wnd = CreateWindowExW(0, L"WmDdeClass", L"client", WS_OVERLAPPED, 0, 0, 10, 10, NULL, NULL, g_hinst, NULL);
    g_app = GlobalAddAtomW(L"WmDdeApp"); g_topic = GlobalAddAtomW(L"WmDdeTopic"); g_item = GlobalAddAtomW(L"WmDdeItem");

    /* initiate: a broadcast send, the server answers with a cross-process send of WM_DDE_ACK */
    SendMessageW(HWND_BROADCAST, WM_DDE_INITIATE, (WPARAM)g_wnd, MAKELPARAM(g_app, g_topic));
    ok(g_state[0] == 1 && IsWindow(g_partner), "no acknowledgement of WM_DDE_INITIATE\n");
    srv = g_partner;
    if (!srv)
        goto out;

    /* execute: the lParam is the block itself */
    strcpy(g_cmd, "[WmDdeCommand(1,2)]");
    h = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, sizeof(g_cmd));
    strcpy(GlobalLock(h), g_cmd);
    GlobalUnlock(h);
    ok(PostMessageW(srv, WM_DDE_EXECUTE, (WPARAM)g_wnd, (LPARAM)h), "post execute failed: %lu\n", GetLastError());
    ok(pump_until_state(1, 1, 10000), "no acknowledgement of WM_DDE_EXECUTE\n");
    ok(g_state[2] == 0x8000, "execute ack status %x\n", g_state[2]);

    /* poke */
    h = make_data(CF_PROBE, "poked value", 1);
    ok(PostMessageW(srv, WM_DDE_POKE, (WPARAM)g_wnd, PackDDElParam(WM_DDE_POKE, (UINT_PTR)h, g_item)),
       "post poke failed: %lu\n", GetLastError());
    ok(pump_until_state(1, 2, 10000), "no acknowledgement of WM_DDE_POKE\n");

    /* request / data */
    ok(PostMessageW(srv, WM_DDE_REQUEST, (WPARAM)g_wnd, MAKELPARAM(CF_PROBE, g_item)), "post request failed\n");
    ok(pump_until_state(9, 1, 10000), "no WM_DDE_DATA for the request\n");

    /* advise: the block is a DDEADVISE; the server acknowledges and pushes data */
    h = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, sizeof(DDEADVISE));
    {
        DDEADVISE *da = GlobalLock(h);
        memset(da, 0, sizeof(*da)); da->fAckReq = 1; da->cfFormat = CF_PROBE;
        GlobalUnlock(h);
    }
    ok(PostMessageW(srv, WM_DDE_ADVISE, (WPARAM)g_wnd, PackDDElParam(WM_DDE_ADVISE, (UINT_PTR)h, g_item)),
       "post advise failed: %lu\n", GetLastError());
    ok(pump_until_state(10, 1, 10000), "no WM_DDE_DATA for the advise\n");
    ok(g_state[1] >= 3, "no acknowledgement of WM_DDE_ADVISE\n");

    /* terminate both ways */
    PostMessageW(srv, WM_DDE_TERMINATE, (WPARAM)g_wnd, 0);
    ok(pump_until_state(11, 1, 10000), "no WM_DDE_TERMINATE back\n");
    ok(g_state[4] == 0, "%d malformed messages\n", g_state[4]);
out:
    ok(WaitForSingleObject(proc, 30000) == WAIT_OBJECT_0, "the server did not exit\n");
    GetExitCodeProcess(proc, &code);
    ok(code == 0, "the server process reported %lu failures\n", code);
    CloseHandle(pi.hThread);
    CloseHandle(proc);
    CloseHandle(ready);
    DestroyWindow(g_wnd);
}
