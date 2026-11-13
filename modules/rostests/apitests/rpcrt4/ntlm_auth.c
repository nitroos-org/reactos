/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RPC_C_AUTHN_WINNT (NTLM) for RPC clients and servers: an authenticated bind and call over ncacn_np and
 *              ncacn_ip_tcp at every authentication level (CONNECT to PKT_PRIVACY, with a request that spans
 *              fragments), RpcBindingInqAuthClient and RpcImpersonateClient on the server, a wrong password, and the
 *              refusal of a caller without authentication by an RPC_IF_ALLOW_SECURE_ONLY interface.
 *              The server and the clients live in this process; the account is a local one made for the test.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <pseh/pseh2.h>

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <rpc.h>
#include <rpcdcep.h>
#include <lmaccess.h>
#include <lmerr.h>

#include "ntlm_auth_c.h"

#define TEST_PASSWORD L"Ntlm#Test1pw"
#define BIG_SIZE 12000

static const RPC_SYNTAX_IDENTIFIER ndr_syntax =
{
    { 0x8A885D04, 0x1CEB, 0x11C9, { 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 } }, { 2, 0 }
};

enum { IF_AUTH, IF_SECURE, IF_COUNT };

static RPC_SERVER_INTERFACE server_if[IF_COUNT];
static RPC_CLIENT_INTERFACE client_if[IF_COUNT];
static RPC_DISPATCH_TABLE dispatch_table;
static WCHAR g_user[32];
static char lrpc_endpoint[64], pipe_endpoint[64], tcp_endpoint[16];

/* what the server saw of the last call */
static struct
{
    volatile LONG calls;
    RPC_STATUS inq_status;
    ULONG level, svc, authz;
    RPC_STATUS imp_status;
    WCHAR imp_user[64];
    RPC_STATUS revert_status;
    BOOL privs_set;
    WCHAR privs[128];
} seen;

static void WINAPI dispatch(PRPC_MESSAGE msg)
{
    RPC_AUTHZ_HANDLE privs = NULL;
    RPC_WSTR princ = NULL;
    const BYTE *data = msg->Buffer;
    ULONG len = msg->BufferLength, i, sum = 0;
    int idx = !memcmp(&((RPC_SERVER_INTERFACE *)msg->RpcInterfaceInformation)->InterfaceId.SyntaxGUID,
                      &server_if[IF_SECURE].InterfaceId.SyntaxGUID, sizeof(GUID)) ? IF_SECURE : IF_AUTH;

    if (idx == IF_AUTH)
    {
        DWORD n;

        InterlockedIncrement(&seen.calls);
        seen.level = seen.svc = seen.authz = 0xdeadbeef;
        seen.inq_status = RpcBindingInqAuthClientW(msg->Handle, &privs, &princ, &seen.level, &seen.svc, &seen.authz);
        seen.privs_set = FALSE;
        if (seen.inq_status == RPC_S_OK && privs)
        {
            lstrcpynW(seen.privs, privs, ARRAYSIZE(seen.privs));
            seen.privs_set = TRUE;
        }
        if (princ) RpcStringFreeW(&princ);

        seen.imp_user[0] = 0;
        seen.imp_status = RpcImpersonateClient(msg->Handle);
        if (seen.imp_status == RPC_S_OK)
        {
            n = ARRAYSIZE(seen.imp_user);
            GetUserNameW(seen.imp_user, &n);
            seen.revert_status = RpcRevertToSelf();
        }
    }

    for (i = 0; i < len; i++)
        sum += data[i];
    msg->BufferLength = sizeof(int);
    if (I_RpcGetBuffer(msg) == RPC_S_OK)
        *(int *)msg->Buffer = idx == IF_SECURE ? 42 : (int)sum;
}

static void init_interfaces(void)
{
    static RPC_DISPATCH_FUNCTION function = (RPC_DISPATCH_FUNCTION)dispatch;
    int i;

    dispatch_table.DispatchTableCount = 1;
    dispatch_table.DispatchTable = &function;
    for (i = 0; i < IF_COUNT; i++)
    {
        GUID id = { 0x5ec0ad10 + i, 0x4321, 0x1234, { 0, 0, 0, 0, 0, 0, 0, (BYTE)(i + 1) } };

        if (i == IF_SECURE)
        {
            /* the one the client stub of the IDL file calls */
            GUID sid = { 0x5ec0ad00, 0x4321, 0x1234, { 0, 0, 0, 0, 0, 0, 0, 1 } };
            id = sid;
        }
        server_if[i].Length = sizeof(RPC_SERVER_INTERFACE);
        server_if[i].InterfaceId.SyntaxGUID = id;
        server_if[i].InterfaceId.SyntaxVersion.MajorVersion = 1;
        server_if[i].TransferSyntax = ndr_syntax;
        server_if[i].DispatchTable = &dispatch_table;
        client_if[i].Length = sizeof(RPC_CLIENT_INTERFACE);
        client_if[i].InterfaceId = server_if[i].InterfaceId;
        client_if[i].TransferSyntax = ndr_syntax;
    }
}

static RPC_STATUS do_call(RPC_BINDING_HANDLE binding, int index, const BYTE *request, ULONG request_len, int *result)
{
    RPC_MESSAGE msg;
    RPC_STATUS status;

    memset(&msg, 0, sizeof(msg));
    msg.Handle = binding;
    msg.RpcInterfaceInformation = &client_if[index];
    msg.ProcNum = 0;
    msg.DataRepresentation = 0x10;
    msg.BufferLength = request_len;
    *result = -1;

    status = I_RpcGetBuffer(&msg);
    if (status != RPC_S_OK)
        return status;
    memcpy(msg.Buffer, request, request_len);
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

struct transport
{
    const char *name;
    const char *protseq;
    const char *address;
    const char *endpoint;
    BOOL authenticated;     /* the transport does not authenticate the caller by itself: the NTLM exchange is on the wire */
};

static BYTE g_request[BIG_SIZE];
static int g_expected_sum;

static BOOL contains_nocase(const WCHAR *text, const WCHAR *part)
{
    size_t len = wcslen(part);

    for (; *text; text++)
        if (!_wcsnicmp(text, part, len))
            return TRUE;
    return FALSE;
}

static void test_levels(const struct transport *t, SEC_WINNT_AUTH_IDENTITY_W *identity)
{
    static const ULONG levels[] = { RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_PKT,
                                    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY };
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status;
    ULONG i, level, svc, authz;
    int result;
    BYTE tiny[3] = { 1, 2, 3 };

    for (i = 0; i < ARRAYSIZE(levels); i++)
    {
        binding = make_binding(t->protseq, t->address, t->endpoint);
        status = RpcBindingSetAuthInfoW(binding, NULL, levels[i], RPC_C_AUTHN_WINNT, identity, 0);
        ok(status == RPC_S_OK, "%s level %lu: RpcBindingSetAuthInfo %lu\n", t->name, levels[i], (unsigned long)status);
        if (status != RPC_S_OK)
        {
            RpcBindingFree(&binding);
            continue;
        }

        level = svc = authz = 0xdeadbeef;
        status = RpcBindingInqAuthInfoW(binding, NULL, &level, &svc, NULL, &authz);
        ok_eq_hex(status, RPC_S_OK);
        ok_eq_ulong(level, levels[i]);
        ok_eq_ulong(svc, RPC_C_AUTHN_WINNT);

        /* a tiny request, then one that spans fragments */
        seen.calls = 0;
        status = do_call(binding, IF_AUTH, tiny, sizeof(tiny), &result);
        ok(status == RPC_S_OK, "%s level %lu: call status %lu\n", t->name, levels[i], (unsigned long)status);
        ok_eq_int(result, 6);
        ok_eq_long(seen.calls, 1);
        ok_eq_hex(seen.inq_status, RPC_S_OK);
        ok_eq_ulong(seen.level, levels[i]);
        ok_eq_ulong(seen.svc, RPC_C_AUTHN_WINNT);
        ok_eq_hex(seen.imp_status, RPC_S_OK);
        ok(!_wcsicmp(seen.imp_user, g_user), "%s level %lu: the server impersonated '%ls' instead of '%ls'\n", t->name,
           levels[i], seen.imp_user, g_user);
        ok_eq_hex(seen.revert_status, RPC_S_OK);
        ok(seen.privs_set, "%s level %lu: no client principal name\n", t->name, levels[i]);
        if (seen.privs_set)
        {
            /* the name that identifies the client: its user name is part of it */
            ok(contains_nocase(seen.privs, g_user), "%s level %lu: client principal name '%ls'\n", t->name, levels[i],
               seen.privs);
        }

        status = do_call(binding, IF_AUTH, g_request, sizeof(g_request), &result);
        ok(status == RPC_S_OK, "%s level %lu: big call status %lu\n", t->name, levels[i], (unsigned long)status);
        ok_eq_int(result, g_expected_sum);
        ok_eq_long(seen.calls, 2);

        RpcBindingFree(&binding);
    }
}

static void test_wrong_password(const struct transport *t)
{
    /* the lowest level matters most: a connection that fails to authenticate must not go on, whatever the level */
    static const ULONG levels[] = { RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY };
    SEC_WINNT_AUTH_IDENTITY_W identity;
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status;
    int result;
    ULONG i;
    BYTE tiny[1] = { 1 };

    memset(&identity, 0, sizeof(identity));
    identity.User = (unsigned short *)g_user;
    identity.UserLength = lstrlenW(g_user);
    identity.Domain = (unsigned short *)L".";
    identity.DomainLength = 1;
    identity.Password = (unsigned short *)L"not the password";
    identity.PasswordLength = 16;
    identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    for (i = 0; i < ARRAYSIZE(levels); i++)
    {
        binding = make_binding(t->protseq, t->address, t->endpoint);
        status = RpcBindingSetAuthInfoW(binding, NULL, levels[i], RPC_C_AUTHN_WINNT, &identity, 0);
        ok_eq_hex(status, RPC_S_OK);
        seen.calls = 0;
        status = do_call(binding, IF_AUTH, tiny, sizeof(tiny), &result);
        ok(status != RPC_S_OK, "%s level %lu: a call with a wrong password succeeded\n", t->name, levels[i]);
        ok_eq_long(seen.calls, 0);
        trace("%s level %lu: wrong password gives status %lu\n", t->name, levels[i], (unsigned long)status);
        RpcBindingFree(&binding);
    }
}

static void put_le16(BYTE *p, unsigned v) { p[0] = v; p[1] = v >> 8; }
static void put_le32(BYTE *p, unsigned v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

/* a DCE/RPC PDU header (little endian data representation) */
static void put_pdu_header(BYTE *p, BYTE ptype, unsigned frag_len, unsigned auth_len, unsigned call_id)
{
    p[0] = 5; p[1] = 0; p[2] = ptype; p[3] = 3;     /* version, minor, type, first and last fragment */
    p[4] = 0x10; p[5] = p[6] = p[7] = 0;            /* little endian, ASCII, IEEE */
    put_le16(p + 8, frag_len);
    put_le16(p + 10, auth_len);
    put_le32(p + 12, call_id);
}

/* A client that starts the NTLM exchange (it sends the NEGOTIATE message in its bind) and then sends calls without
 * ever sending the AUTHENTICATE message has proved nothing: its calls must not be dispatched. */
static void test_incomplete_authentication(const struct transport *t)
{
    static const BYTE negotiate[32] =
    {
        'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 1, 0, 0, 0, 0x01, 0x82, 0x08, 0x20,
        0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0
    };
    BYTE bind[160], reply[512], request[64];
    ULONG pos, auth_pos;
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    DWORD timeout = 3000;
    int len, received = 0;
    GUID if_id = server_if[IF_AUTH].InterfaceId.SyntaxGUID;
    BOOL served = FALSE;

    if (WSAStartup(MAKEWORD(2, 2), &wsa))
        return;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return; }
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((u_short)atoi(t->endpoint));
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)))
    {
        skip("cannot connect to the server (%d)\n", WSAGetLastError());
        goto done;
    }

    /* bind: one presentation context of the interface, NDR transfer syntax, NTLM at the lowest level */
    memset(bind, 0, sizeof(bind));
    pos = 16;
    put_le16(bind + pos, 4280); put_le16(bind + pos + 2, 4280); put_le32(bind + pos + 4, 0);
    bind[pos + 8] = 1;                                  /* one context element */
    pos += 12;
    put_le16(bind + pos, 0); bind[pos + 2] = 1;         /* context id 0, one transfer syntax */
    pos += 4;
    memcpy(bind + pos, &if_id, 16); put_le16(bind + pos + 16, 1); put_le16(bind + pos + 18, 0); pos += 20;
    memcpy(bind + pos, &ndr_syntax.SyntaxGUID, 16); put_le16(bind + pos + 16, 2); put_le16(bind + pos + 18, 0); pos += 20;
    auth_pos = pos;                                     /* 4 byte aligned already */
    bind[pos] = RPC_C_AUTHN_WINNT; bind[pos + 1] = RPC_C_AUTHN_LEVEL_CONNECT; put_le32(bind + pos + 4, 0);
    memcpy(bind + pos + 8, negotiate, sizeof(negotiate));
    pos += 8 + sizeof(negotiate);
    put_pdu_header(bind, 11, pos, sizeof(negotiate), 1);
    ok(send(sock, (const char *)bind, pos, 0) == (int)pos, "send of the bind failed\n");

    len = recv(sock, (char *)reply, sizeof(reply), 0);
    ok(len >= 16 && reply[2] == 12, "no bind_ack for the NTLM bind (%d bytes, type %d)\n", len, len > 2 ? reply[2] : -1);
    if (len < 16 || reply[2] != 12)
        goto done;
    (void)auth_pos;

    /* a request with no AUTHENTICATE message before it, and no authentication data */
    seen.calls = 0;
    memset(request, 0, sizeof(request));
    put_le32(request + 16, 3); put_le16(request + 20, 0); put_le16(request + 22, 0);   /* alloc hint, context, opnum */
    request[24] = 1; request[25] = 2; request[26] = 3;
    put_pdu_header(request, 0, 27, 0, 2);
    send(sock, (const char *)request, 27, 0);

    /* the server answers with a fault or closes the connection; it never answers a request it did not dispatch with
     * a response */
    received = recv(sock, (char *)reply, sizeof(reply), 0);
    if (received >= 16 && reply[2] == 2)
        served = TRUE;
    ok(!served, "%s: a call was answered on a connection that never authenticated\n", t->name);
    ok_eq_long(seen.calls, 0);

done:
    closesocket(sock);
    WSACleanup();
}

static void test_secure_only(const struct transport *t, SEC_WINNT_AUTH_IDENTITY_W *identity)
{
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status = RPC_S_OK;
    int result = -1;

    /* no authentication: refused, and the server routine does not run */
    binding = make_binding(t->protseq, t->address, t->endpoint);
    _SEH2_TRY
    {
        result = ndr_secure_only_call(binding);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok_eq_hex(status, RPC_S_ACCESS_DENIED);
    ok_eq_int(result, -1);
    RpcBindingFree(&binding);

    /* authenticated, even at the lowest level: served */
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = RpcBindingSetAuthInfoW(binding, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_WINNT, identity, 0);
    ok_eq_hex(status, RPC_S_OK);
    result = -1;
    status = RPC_S_OK;
    _SEH2_TRY
    {
        result = ndr_secure_only_call(binding);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok_eq_hex(status, RPC_S_OK);
    ok_eq_int(result, 42);
    RpcBindingFree(&binding);
}

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"rpcntlm%lu", GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = g_user;
    ui.usri1_password = (LPWSTR)TEST_PASSWORD;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);
    if (st != NERR_Success)
    {
        skip("NetUserAdd failed (%lu)\n", (unsigned long)st);
        return FALSE;
    }
    return TRUE;
}

START_TEST(ntlm_auth)
{
    SEC_WINNT_AUTH_IDENTITY_W identity;
    struct transport transports[3] = {{0}};
    RPC_STATUS status;
    RPC_BINDING_HANDLE binding;
    int i, count = 0, result;
    DWORD pid = GetCurrentProcessId();
    BYTE tiny[2] = { 7, 8 };

    for (i = 0; i < BIG_SIZE; i++)
    {
        g_request[i] = (BYTE)(i * 7 + 3);
        g_expected_sum += g_request[i];
    }

    if (!create_user())
        return;

    init_interfaces();
    sprintf(lrpc_endpoint, "rpcrt4_ntlm_lrpc_%lu", pid);
    sprintf(pipe_endpoint, "\\pipe\\rpcrt4_ntlm_np_%lu", pid);
    sprintf(tcp_endpoint, "%lu", 48000 + pid % 1000);

    memset(&identity, 0, sizeof(identity));
    identity.User = (unsigned short *)g_user;
    identity.UserLength = lstrlenW(g_user);
    identity.Domain = (unsigned short *)L".";
    identity.DomainLength = 1;
    identity.Password = (unsigned short *)TEST_PASSWORD;
    identity.PasswordLength = lstrlenW(TEST_PASSWORD);
    identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_np", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)pipe_endpoint, NULL);
    ok_eq_hex(status, RPC_S_OK);
    transports[count].name = "ncacn_np";
    transports[count].protseq = "ncacn_np";
    transports[count].endpoint = pipe_endpoint;
    transports[count].authenticated = TRUE;
    count++;

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)tcp_endpoint, NULL);
    if (status == RPC_S_OK)
    {
        transports[count].name = "ncacn_ip_tcp (loopback)";
        transports[count].protseq = "ncacn_ip_tcp";
        transports[count].address = "127.0.0.1";
        transports[count].endpoint = tcp_endpoint;
        transports[count].authenticated = TRUE;
        count++;
    }
    else
        skip("ncacn_ip_tcp is not available (%ld)\n", (long)status);

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)lrpc_endpoint, NULL);
    ok_eq_hex(status, RPC_S_OK);

    status = RpcServerRegisterAuthInfoW(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcServerRegisterIf3((RPC_IF_HANDLE)&server_if[IF_AUTH], NULL, NULL, 0, RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                  (UINT)-1, NULL, NULL);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcServerRegisterIf3((RPC_IF_HANDLE)&server_if[IF_SECURE], NULL, NULL, RPC_IF_ALLOW_SECURE_ONLY,
                                  RPC_C_LISTEN_MAX_CALLS_DEFAULT, (UINT)-1, NULL, NULL);
    ok_eq_hex(status, RPC_S_OK);
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    ok_eq_hex(status, RPC_S_OK);

    for (i = 0; i < count; i++)
    {
        trace("transport %s\n", transports[i].name);
        test_levels(&transports[i], &identity);
        test_wrong_password(&transports[i]);
        if (!strcmp(transports[i].protseq, "ncacn_ip_tcp"))
            test_incomplete_authentication(&transports[i]);
        test_secure_only(&transports[i], &identity);
    }

    /* ncalrpc: the transport authenticates the caller, the call works at every level */
    {
        static const ULONG levels[] = { RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                                        RPC_C_AUTHN_LEVEL_PKT_PRIVACY };
        ULONG l;

        for (l = 0; l < ARRAYSIZE(levels); l++)
        {
            binding = make_binding("ncalrpc", NULL, lrpc_endpoint);
            status = RpcBindingSetAuthInfoW(binding, NULL, levels[l], RPC_C_AUTHN_WINNT, NULL, 0);
            ok_eq_hex(status, RPC_S_OK);
            status = do_call(binding, IF_AUTH, tiny, sizeof(tiny), &result);
            ok_eq_hex(status, RPC_S_OK);
            ok_eq_int(result, 15);
            RpcBindingFree(&binding);
        }
    }

    RpcMgmtStopServerListening(NULL);
    for (i = 0; i < IF_COUNT; i++)
        RpcServerUnregisterIf((RPC_IF_HANDLE)&server_if[i], NULL, FALSE);

    NetUserDel(NULL, g_user);
}
