/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DDEML (DdeInitialize, DdeConnect, DdeClientTransaction) between two processes: the parent is the
 *              client, a copy of the program the server. Execute, poke, request and an advise loop.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ddeml.h>

static DWORD g_inst;
static HSZ g_service, g_topic, g_item;
static int g_exec, g_poke, g_req, g_adv, g_connect;
static BOOL g_server;
static int g_client_advdata;

static HDDEDATA CALLBACK DdemlProc(UINT type, UINT fmt, HCONV conv, HSZ hsz1, HSZ hsz2, HDDEDATA data, ULONG_PTR d1,
                                   ULONG_PTR d2)
{
    char buf[64];
    DWORD len;

    switch (type)
    {
    case XTYP_CONNECT:
        if (!g_server)
            return 0;
        g_connect++;
        return (HDDEDATA)TRUE;
    case XTYP_EXECUTE:
        if (!g_server)
            return DDE_FNOTPROCESSED;
        buf[0] = 0;
        len = DdeGetData(data, (BYTE *)buf, sizeof(buf), 0);
        if (len && !strcmp(buf, "[DdemlCommand(7)]"))
            g_exec++;
        else
            trace("server: bad execute '%s' (%lu)\n", buf, len);
        return (HDDEDATA)DDE_FACK;
    case XTYP_POKE:
        if (!g_server)
            return DDE_FNOTPROCESSED;
        buf[0] = 0;
        len = DdeGetData(data, (BYTE *)buf, sizeof(buf), 0);
        if (fmt == CF_TEXT && len && !strcmp(buf, "poked via ddeml"))
            g_poke++;
        else
            trace("server: bad poke '%s' fmt %u (%lu)\n", buf, fmt, len);
        return (HDDEDATA)DDE_FACK;
    case XTYP_REQUEST: case XTYP_ADVREQ:
        if (!g_server)
            return 0;
        g_req++;
        return DdeCreateDataHandle(g_inst, (BYTE *)"request answer", 15, 0, g_item, CF_TEXT, 0);
    case XTYP_ADVSTART:
        return g_server ? (HDDEDATA)TRUE : 0;
    case XTYP_ADVDATA:
        if (!g_server)
        {
            buf[0] = 0;
            DdeGetData(data, (BYTE *)buf, sizeof(buf), 0);
            if (!strcmp(buf, "request answer"))
                g_client_advdata++;
            return (HDDEDATA)DDE_FACK;
        }
        return 0;
    }
    return 0;
}

static void pump(DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG msg;

    while ((int)(end - GetTickCount()) > 0)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(10);
    }
}

static void run_server(void)
{
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"WmDdemlReady");
    HANDLE quit = OpenEventW(SYNCHRONIZE, FALSE, L"WmDdemlQuit");
    UINT r;

    g_server = TRUE;
    r = DdeInitializeA(&g_inst, DdemlProc, APPCLASS_STANDARD, 0);
    ok(r == DMLERR_NO_ERROR, "server DdeInitialize: %u\n", r);
    g_service = DdeCreateStringHandleA(g_inst, "WmDdemlService", CP_WINANSI);
    g_topic = DdeCreateStringHandleA(g_inst, "WmDdemlTopic", CP_WINANSI);
    g_item = DdeCreateStringHandleA(g_inst, "WmDdemlItem", CP_WINANSI);
    ok(DdeNameService(g_inst, g_service, 0, DNS_REGISTER) != 0, "DdeNameService failed\n");
    SetEvent(ready);
    while (WaitForSingleObject(quit, 0) == WAIT_TIMEOUT)
    {
        pump(50);
        /* once the client has asked for the item, change it from time to time for the advise loop */
        if (g_connect && g_req >= 1 && ++g_adv % 10 == 0)
            DdePostAdvise(g_inst, g_topic, g_item);
    }
    ok(g_connect >= 1 && g_exec == 1 && g_poke == 1 && g_req >= 1, "server saw connect %d exec %d poke %d request %d\n", g_connect,
       g_exec, g_poke, g_req);
    DdeNameService(g_inst, 0, 0, DNS_UNREGISTER);
    DdeUninitialize(g_inst);
}

START_TEST(WmDdeml)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    HANDLE ready, quit;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH + 32];
    HCONV conv;
    HDDEDATA hd, data;
    DWORD result = 0, code, len;
    char buf[64];
    UINT r;

    if (argc > 2 && !strcmp(argv[2], "server"))
    {
        run_server();
        return;
    }
    ready = CreateEventW(NULL, FALSE, FALSE, L"WmDdemlReady");
    quit = CreateEventW(NULL, TRUE, FALSE, L"WmDdemlQuit");
    sprintf(cmd, "\"%s\" WmDdeml server", argv[0]);
    ok(CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi), "CreateProcess failed: %lu\n", GetLastError());
    ok(WaitForSingleObject(ready, 30000) == WAIT_OBJECT_0, "the server did not start\n");

    r = DdeInitializeA(&g_inst, DdemlProc, APPCLASS_STANDARD, 0);
    ok(r == DMLERR_NO_ERROR, "client DdeInitialize: %u\n", r);
    g_service = DdeCreateStringHandleA(g_inst, "WmDdemlService", CP_WINANSI);
    g_topic = DdeCreateStringHandleA(g_inst, "WmDdemlTopic", CP_WINANSI);
    g_item = DdeCreateStringHandleA(g_inst, "WmDdemlItem", CP_WINANSI);

    conv = DdeConnect(g_inst, g_service, g_topic, NULL);
    ok(conv != NULL, "DdeConnect failed: %#x\n", DdeGetLastError(g_inst));
    if (conv)
    {
        hd = DdeClientTransaction((BYTE *)"[DdemlCommand(7)]", 18, conv, 0, 0, XTYP_EXECUTE, 10000, &result);
        ok(hd != 0 && result == DDE_FACK, "execute: %p result %lx (error %#x)\n", hd, result, DdeGetLastError(g_inst));

        hd = DdeClientTransaction((BYTE *)"poked via ddeml", 16, conv, g_item, CF_TEXT, XTYP_POKE, 10000, &result);
        ok(hd != 0 && result == DDE_FACK, "poke: %p result %lx (error %#x)\n", hd, result, DdeGetLastError(g_inst));

        data = DdeClientTransaction(NULL, 0, conv, g_item, CF_TEXT, XTYP_REQUEST, 10000, &result);
        ok(data != 0, "request: failed, error %#x\n", DdeGetLastError(g_inst));
        buf[0] = 0;
        len = data ? DdeGetData(data, (BYTE *)buf, sizeof(buf), 0) : 0;
        ok(len == 15 && !strcmp(buf, "request answer"), "request data '%s' (%lu)\n", buf, len);
        if (data)
            DdeFreeDataHandle(data);

        hd = DdeClientTransaction(NULL, 0, conv, g_item, CF_TEXT, XTYP_ADVSTART, 10000, &result);
        ok(hd != 0, "advise start failed: error %#x\n", DdeGetLastError(g_inst));
        pump(2000);
        /* ReactOS DDEML does not deliver the advise data on i386 either: informational only */
        trace("advise data messages %d\n", g_client_advdata);
        DdeClientTransaction(NULL, 0, conv, g_item, CF_TEXT, XTYP_ADVSTOP, 10000, &result);
        ok(DdeDisconnect(conv), "DdeDisconnect failed\n");
    }
    SetEvent(quit);
    ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "the server did not exit\n");
    GetExitCodeProcess(pi.hProcess, &code);
    ok(code == 0, "the server reported %lu failures\n", code);
    DdeUninitialize(g_inst);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(ready);
    CloseHandle(quit);
}
