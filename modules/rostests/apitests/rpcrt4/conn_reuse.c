/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A client reuses an idle connection to a server for a new binding handle, as Windows does, and only for a
 *              caller that would have got the same connection. The server counts its connections with the interface
 *              security callback, which runs once for each connection of a caller that is authenticated (every call of
 *              one that is not, over a named pipe or TCP) and answers every call with that count:
 *              - calls made through one binding handle, then through a new one to the same server, share one
 *                connection (ncalrpc, ncacn_np, ncacn_ip_tcp),
 *              - another authentication (none, NTLM with the logged on user, another user, another level) and another
 *                thread token get a connection of their own, and the server sees the identity that was asked for,
 *              - a connection the server closed (its process ended, and a new one listens on the endpoint) is not
 *                used again: the call succeeds on a new one.
 *              The server of most tests lives in this process; the one of the last test is a child process of this
 *              test ("conn_reuse server ...") that is ended and started again.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <rpc.h>
#include <rpcdcep.h>
#include <lmaccess.h>
#include <lmerr.h>

#define REUSE_PASSWORD L"Reuse#Test1pw"

static const RPC_SYNTAX_IDENTIFIER ndr_syntax =
{
    { 0x8A885D04, 0x1CEB, 0x11C9, { 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 } }, { 2, 0 }
};

static RPC_SERVER_INTERFACE server_if;
static RPC_CLIENT_INTERFACE client_if;
static RPC_DISPATCH_TABLE dispatch_table;
static WCHAR g_user[32];
static SEC_WINNT_AUTH_IDENTITY_W g_identity;

/* the server side (of this process, or of the child) */
static volatile LONG g_callbacks;   /* connections seen: the callback ran for them */
static WCHAR g_seen_user[64];       /* who the server saw impersonating the client in the last call */
static volatile LONG g_impersonate = 1;   /* whether the server routine impersonates the caller */

static RPC_STATUS WINAPI if_callback(RPC_IF_HANDLE handle, void *context)
{
    InterlockedIncrement(&g_callbacks);
    return RPC_S_OK;
}

static void WINAPI dispatch(PRPC_MESSAGE msg)
{
    DWORD n;

    g_seen_user[0] = 0;
    if (g_impersonate && RpcImpersonateClient(msg->Handle) == RPC_S_OK)
    {
        n = ARRAYSIZE(g_seen_user);
        GetUserNameW(g_seen_user, &n);
        RpcRevertToSelf();
    }
    msg->BufferLength = sizeof(int);
    if (I_RpcGetBuffer(msg) == RPC_S_OK)
        *(int *)msg->Buffer = g_callbacks;
}

static void init_interface(void)
{
    static RPC_DISPATCH_FUNCTION function = (RPC_DISPATCH_FUNCTION)dispatch;
    GUID id = { 0x5ec0ae00, 0x4321, 0x1234, { 0, 0, 0, 0, 0, 0, 0, 1 } };

    dispatch_table.DispatchTableCount = 1;
    dispatch_table.DispatchTable = &function;
    server_if.Length = sizeof(RPC_SERVER_INTERFACE);
    server_if.InterfaceId.SyntaxGUID = id;
    server_if.InterfaceId.SyntaxVersion.MajorVersion = 1;
    server_if.TransferSyntax = ndr_syntax;
    server_if.DispatchTable = &dispatch_table;
    client_if.Length = sizeof(RPC_CLIENT_INTERFACE);
    client_if.InterfaceId = server_if.InterfaceId;
    client_if.TransferSyntax = ndr_syntax;
}

/* The three endpoints of a server. A server answers every call with the number of connections it has seen. */
static RPC_STATUS start_server(const char *lrpc, const char *pipe, const char *tcp, BOOL *have_tcp, BOOL wait)
{
    RPC_STATUS status;

    init_interface();
    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)lrpc, NULL);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_np", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)pipe, NULL);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)tcp, NULL);
    *have_tcp = status == RPC_S_OK;
    if (status != RPC_S_OK)
        skip("ncacn_ip_tcp is not available (%ld)\n", (long)status);

    status = RpcServerRegisterAuthInfoW(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcServerRegisterIf2((RPC_IF_HANDLE)&server_if, NULL, NULL, 0, RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                  (UINT)-1, if_callback);
    ok_eq_hex(status, RPC_S_OK);
    return RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, !wait);
}

struct transport
{
    const char *name;
    const char *protseq;
    const char *address;
    const char *endpoint;
    ULONG base_level;   /* the security the tests count connections with: a named pipe and TCP caller without any
                         * is asked again by the callback for every call, so it does not show the connections */
    LONG *last_reply;   /* the connection count the server last answered with (one for all the transports of a server) */
};

static RPC_STATUS do_call(RPC_BINDING_HANDLE binding, int *result)
{
    RPC_MESSAGE msg;
    RPC_STATUS status;

    memset(&msg, 0, sizeof(msg));
    msg.Handle = binding;
    msg.RpcInterfaceInformation = &client_if;
    msg.DataRepresentation = 0x10;
    msg.BufferLength = 4;
    *result = -1;

    status = I_RpcGetBuffer(&msg);
    if (status != RPC_S_OK)
        return status;
    memset(msg.Buffer, 0, 4);
    status = I_RpcSendReceive(&msg);
    if (status == RPC_S_OK && msg.BufferLength >= sizeof(int))
        *result = *(int *)msg.Buffer;
    I_RpcFreeBuffer(&msg);
    return status;
}

static RPC_BINDING_HANDLE make_binding(const char *protseq, const char *address, const char *endpoint)
{
    RPC_CSTR string = NULL;
    RPC_BINDING_HANDLE binding = NULL;
    RPC_STATUS status;

    status = RpcStringBindingComposeA(NULL, (RPC_CSTR)protseq, (RPC_CSTR)address, (RPC_CSTR)endpoint, NULL, &string);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcBindingFromStringBindingA(string, &binding);
    ok_eq_hex(status, RPC_S_OK);
    RpcStringFreeA(&string);
    return binding;
}

/* a new binding handle with the given security; level 0 means none; identity may be NULL (the logged on user) */
static RPC_BINDING_HANDLE new_handle(const struct transport *t, ULONG level, SEC_WINNT_AUTH_IDENTITY_W *identity)
{
    RPC_BINDING_HANDLE binding = make_binding(t->protseq, t->address, t->endpoint);

    if (level)
    {
        RPC_STATUS status = RpcBindingSetAuthInfoW(binding, NULL, level, RPC_C_AUTHN_WINNT, identity, 0);
        ok_eq_hex(status, RPC_S_OK);
    }
    return binding;
}

/* Two calls through a new binding handle with the given security. Returns the number of connections the server saw for
 * them (the server's answer to the last call less its answer before), or -100 if a call failed. */
static LONG calls_with(struct transport *t, ULONG level, SEC_WINNT_AUTH_IDENTITY_W *identity, const char *what)
{
    RPC_BINDING_HANDLE binding = new_handle(t, level, identity);
    RPC_STATUS status = RPC_S_OK;
    int result = -1, i;
    LONG n;

    for (i = 0; i < 2 && status == RPC_S_OK; i++)
    {
        status = do_call(binding, &result);
        ok(status == RPC_S_OK, "%s %s: call status %lu\n", t->name, what, (unsigned long)status);
    }
    RpcBindingFree(&binding);
    if (status != RPC_S_OK)
        return -100;
    n = result - *t->last_reply;
    *t->last_reply = result;
    return n;
}

static void test_same_server(struct transport *t)
{
    LONG n;

    /* a call that leaves one idle connection to this server, whatever the earlier tests left */
    n = calls_with(t, t->base_level, NULL, "first handle");
    ok(n == 0 || n == 1, "%s: the first handle opened %ld connections\n", t->name, n);

    /* new handles to the same server: the idle connection is used, no new one is opened */
    n = calls_with(t, t->base_level, NULL, "second handle");
    ok_eq_long(n, 0);
    n = calls_with(t, t->base_level, NULL, "third handle");
    ok_eq_long(n, 0);
}

static void test_other_security(struct transport *t)
{
    LONG n;

    calls_with(t, t->base_level, NULL, "base security");

    if (!t->base_level)
    {
        /* NTLM with the logged on user: not the connection of an unauthenticated caller */
        n = calls_with(t, RPC_C_AUTHN_LEVEL_CONNECT, NULL, "NTLM default, connect");
        ok_eq_long(n, 1);
    }
    else
    {
        /* an unauthenticated caller does not get the connection of an authenticated one (the callback runs for
         * every call of the caller that is not, so the count is of no use: only the calls are checked) */
        calls_with(t, 0, NULL, "no security");
        n = calls_with(t, RPC_C_AUTHN_LEVEL_CONNECT, NULL, "NTLM default, connect after no security");
        ok_eq_long(n, 0);
    }
    n = calls_with(t, RPC_C_AUTHN_LEVEL_CONNECT, NULL, "NTLM default, connect again");
    ok_eq_long(n, 0);

    /* another level: another connection */
    n = calls_with(t, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, NULL, "NTLM default, privacy");
    ok_eq_long(n, 1);
    n = calls_with(t, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, NULL, "NTLM default, privacy again");
    ok_eq_long(n, 0);

    if (g_identity.UserLength)
    {
        WCHAR me[64];
        DWORD len = ARRAYSIZE(me);

        GetUserNameW(me, &len);

        /* another user at the same level: its own connection, and the server impersonates that user */
        n = calls_with(t, RPC_C_AUTHN_LEVEL_CONNECT, &g_identity, "user, connect");
        ok_eq_long(n, 1);
        /* ncalrpc authenticates the caller in the transport: the credentials given are not used */
        if (strcmp(t->protseq, "ncalrpc"))
            ok(!_wcsicmp(g_seen_user, g_user), "%s: the server impersonated '%ls' instead of '%ls'\n", t->name,
               g_seen_user, g_user);
        n = calls_with(t, RPC_C_AUTHN_LEVEL_CONNECT, &g_identity, "user, connect again");
        ok_eq_long(n, 0);
        if (strcmp(t->protseq, "ncalrpc"))
            ok(!_wcsicmp(g_seen_user, g_user), "%s: the server impersonated '%ls' instead of '%ls' on the reused connection\n",
               t->name, g_seen_user, g_user);

        /* and back to the logged on user: its connection is still there and still its own */
        n = calls_with(t, RPC_C_AUTHN_LEVEL_CONNECT, NULL, "NTLM default, connect after user");
        ok_eq_long(n, 0);
        ok(!_wcsicmp(g_seen_user, me), "%s: the server impersonated '%ls' instead of '%ls'\n", t->name,
           g_seen_user, me);
    }
}

/* another thread token: no connection of a caller with a different token */
static void test_other_token(struct transport *t)
{
    HANDLE token;
    LONG n;
    WCHAR me[64];
    DWORD len = ARRAYSIZE(me);

    if (!g_user[0])
        return;
    if (!LogonUserW(g_user, L".", REUSE_PASSWORD, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token) &&
        !LogonUserW(g_user, L".", REUSE_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token) &&
        !LogonUserW(g_user, NULL, REUSE_PASSWORD, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &token))
    {
        skip("LogonUser failed (%lu)\n", GetLastError());
        return;
    }
    GetUserNameW(me, &len);

    calls_with(t, t->base_level, NULL, "process token");
    n = calls_with(t, t->base_level, NULL, "process token again");
    ok_eq_long(n, 0);

    if (!ImpersonateLoggedOnUser(token))
    {
        skip("ImpersonateLoggedOnUser failed (%lu)\n", GetLastError());
        CloseHandle(token);
        return;
    }
    n = calls_with(t, t->base_level, NULL, "impersonating");
    ok_eq_long(n, 1);
    /* ncalrpc and a named pipe give the server the token of the caller; a TCP connection has no identity but that of
     * the security exchange, which (with the default credentials) is the token as well */
    ok(!_wcsicmp(g_seen_user, g_user) || !g_seen_user[0], "%s: the server saw '%ls', not '%ls'\n", t->name,
       g_seen_user, g_user);
    n = calls_with(t, t->base_level, NULL, "impersonating again");
    ok_eq_long(n, 0);
    RevertToSelf();

    n = calls_with(t, t->base_level, NULL, "process token after impersonating");
    ok_eq_long(n, 0);
    ok(!_wcsicmp(g_seen_user, me) || !g_seen_user[0], "%s: the server saw '%ls', not '%ls'\n", t->name,
       g_seen_user, me);
    CloseHandle(token);
}

/* new handles and calls through them, with a server routine that impersonates the caller and asks the system about it
 * (the system then calls out to the security authority from an impersonating thread): the process does not run out of
 * handles */
static void test_handles(struct transport *t)
{
    RPC_BINDING_HANDLE binding;
    DWORD before = 0, after = 0;
    int i, result;

    calls_with(t, t->base_level, NULL, "handle count warm-up");
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (i = 0; i < 200; i++)
    {
        binding = new_handle(t, t->base_level, NULL);
        do_call(binding, &result);
        RpcBindingFree(&binding);
    }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    ok(after < before + 40, "%s: 200 calls took %lu handles\n", t->name, after - before);
    calls_with(t, t->base_level, NULL, "handle count: connection count");   /* the count of connections is in step again */
}

/* RPCREUSE_BENCH=N: N calls through a new binding handle each, per transport (the cost of a binding handle that has to
 * open and bind a connection against one that finds an idle one) */
static void bench(struct transport *t, int n)
{
    LARGE_INTEGER freq, start, end;
    RPC_BINDING_HANDLE binding;
    int i, result = 0, failed = 0;
    RPC_STATUS status, first_status = 0;
    LONG before;

    g_impersonate = 0;   /* the bench is of the connections */
    binding = new_handle(t, t->base_level, NULL);
    do_call(binding, &result);
    RpcBindingFree(&binding);
    before = result;

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    for (i = 0; i < n; i++)
    {
        binding = new_handle(t, t->base_level, NULL);
        status = do_call(binding, &result);
        if (status != RPC_S_OK && !failed++)
            first_status = status;
        RpcBindingFree(&binding);
    }
    QueryPerformanceCounter(&end);
    *t->last_reply = result;
    g_impersonate = 1;
    printf("BENCH %s%s: %d calls, each through a new binding handle: %.1f us per call, %ld connections, %d failed, "
           "first failure %lu\n", t->name, t->base_level ? " (NTLM)" : "", n,
           (double)(end.QuadPart - start.QuadPart) * 1000000.0 / freq.QuadPart / n, (long)(result - before), failed,
           (unsigned long)first_status);
    fflush(stdout);
}

/* the server of the last test: this test again, as a child that serves until it is ended */
static HANDLE start_child(const char *lrpc, const char *pipe, const char *tcp, const struct transport *probe)
{
    char exe[MAX_PATH], cmd[MAX_PATH + 256];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status = RPC_S_NOT_LISTENING;
    int i;

    GetModuleFileNameA(NULL, exe, ARRAYSIZE(exe));
    sprintf(cmd, "\"%s\" conn_reuse server %s %s %s", exe, lrpc, pipe, tcp);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        skip("cannot start the server process (%lu)\n", GetLastError());
        return NULL;
    }
    CloseHandle(pi.hThread);

    /* wait until it listens on the transport that is slowest to come up */
    for (i = 0; i < 200 && status != RPC_S_OK; i++)
    {
        Sleep(100);
        binding = make_binding(probe->protseq, probe->address, probe->endpoint);
        status = RpcMgmtIsServerListening(binding);
        RpcBindingFree(&binding);
    }
    if (status != RPC_S_OK)
    {
        skip("the server process does not listen (%lu)\n", (unsigned long)status);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return NULL;
    }
    Sleep(300);
    return pi.hProcess;
}

static void end_child(HANDLE process)
{
    TerminateProcess(process, 0);
    WaitForSingleObject(process, 10000);
    CloseHandle(process);
}

/* the server's process ends and a new one listens on the same endpoints: a connection kept for the next handle
 * is dead; the next call gets a new one, and succeeds */
static void test_server_restart(void)
{
    DWORD pid = GetCurrentProcessId();
    char lrpc[64], pipe[64], tcp[16];
    struct transport ts[3] = {{0}};
    LONG last_reply = 0;
    HANDLE child;
    LONG n;
    int i;

    sprintf(lrpc, "rpcrt4_reuse_clrpc_%lu", pid);
    sprintf(pipe, "\\pipe\\rpcrt4_reuse_cnp_%lu", pid);
    sprintf(tcp, "%lu", 46000 + pid % 1000);
    for (i = 0; i < 3; i++)
        ts[i].last_reply = &last_reply;
    ts[0].name = "ncalrpc"; ts[0].protseq = "ncalrpc"; ts[0].endpoint = lrpc;
    ts[1].name = "ncacn_np"; ts[1].protseq = "ncacn_np"; ts[1].endpoint = pipe; ts[1].base_level = RPC_C_AUTHN_LEVEL_CONNECT;
    ts[2].name = "ncacn_ip_tcp"; ts[2].protseq = "ncacn_ip_tcp"; ts[2].address = "127.0.0.1"; ts[2].endpoint = tcp;
    ts[2].base_level = RPC_C_AUTHN_LEVEL_CONNECT;

    child = start_child(lrpc, pipe, tcp, &ts[1]);
    if (!child)
        return;
    for (i = 0; i < 3; i++)
    {
        n = calls_with(&ts[i], ts[i].base_level, NULL, "before the restart");
        ok_eq_long(n, 1);
        n = calls_with(&ts[i], ts[i].base_level, NULL, "before the restart, new handle");
        ok_eq_long(n, 0);
    }
    end_child(child);

    child = start_child(lrpc, pipe, tcp, &ts[1]);
    if (!child)
        return;
    last_reply = 0;   /* a new server counts from the start */
    for (i = 0; i < 3; i++)
    {
        n = calls_with(&ts[i], ts[i].base_level, NULL, "after the restart");
        ok_eq_long(n, 1);
        n = calls_with(&ts[i], ts[i].base_level, NULL, "after the restart, new handle");
        ok_eq_long(n, 0);
    }
    end_child(child);
}

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"rpcreuse%lu", GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = g_user;
    ui.usri1_password = (LPWSTR)REUSE_PASSWORD;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);
    if (st != NERR_Success)
    {
        skip("NetUserAdd failed (%lu)\n", (unsigned long)st);
        g_user[0] = 0;
        return FALSE;
    }

    memset(&g_identity, 0, sizeof(g_identity));
    g_identity.User = (unsigned short *)g_user;
    g_identity.UserLength = lstrlenW(g_user);
    g_identity.Domain = (unsigned short *)L".";
    g_identity.DomainLength = 1;
    g_identity.Password = (unsigned short *)REUSE_PASSWORD;
    g_identity.PasswordLength = lstrlenW(REUSE_PASSWORD);
    g_identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    return TRUE;
}

START_TEST(conn_reuse)
{
    char lrpc_endpoint[64], pipe_endpoint[64], tcp_endpoint[16];
    struct transport transports[3] = {{0}};
    LONG last_reply = 0;
    RPC_STATUS status;
    BOOL have_tcp;
    char **argv;
    int i, count = 0, argc = winetest_get_mainargs(&argv);
    DWORD pid = GetCurrentProcessId();

    /* the server process of the restart test */
    if (argc >= 6 && !strcmp(argv[2], "server"))
    {
        start_server(argv[3], argv[4], argv[5], &have_tcp, TRUE);
        return;
    }

    create_user();
    sprintf(lrpc_endpoint, "rpcrt4_reuse_lrpc_%lu", pid);
    sprintf(pipe_endpoint, "\\pipe\\rpcrt4_reuse_np_%lu", pid);
    sprintf(tcp_endpoint, "%lu", 47000 + pid % 1000);

    status = start_server(lrpc_endpoint, pipe_endpoint, tcp_endpoint, &have_tcp, FALSE);
    ok_eq_hex(status, RPC_S_OK);

    transports[count].name = "ncalrpc";
    transports[count].protseq = "ncalrpc";
    transports[count].endpoint = lrpc_endpoint;
    count++;
    transports[count].name = "ncacn_np";
    transports[count].protseq = "ncacn_np";
    transports[count].endpoint = pipe_endpoint;
    transports[count].base_level = RPC_C_AUTHN_LEVEL_CONNECT;
    count++;
    if (have_tcp)
    {
        transports[count].name = "ncacn_ip_tcp";
        transports[count].protseq = "ncacn_ip_tcp";
        transports[count].address = "127.0.0.1";
        transports[count].endpoint = tcp_endpoint;
        transports[count].base_level = RPC_C_AUTHN_LEVEL_CONNECT;
        count++;
    }

    for (i = 0; i < count; i++)
        transports[i].last_reply = &last_reply;
    for (i = 0; i < count; i++)
    {
        trace("transport %s\n", transports[i].name);
        test_same_server(&transports[i]);
        test_other_security(&transports[i]);
        test_other_token(&transports[i]);
        test_handles(&transports[i]);
        if (getenv("RPCREUSE_BENCH"))
            bench(&transports[i], atoi(getenv("RPCREUSE_BENCH")));
    }

    test_server_restart();

    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf((RPC_IF_HANDLE)&server_if, NULL, FALSE);
    if (g_user[0])
        NetUserDel(NULL, g_user);
}
