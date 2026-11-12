/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What a server interface was registered with is enforced: the interface security callback
 *              (allow, deny, cached per client connection or not) and RPC_IF_ALLOW_LOCAL_ONLY, and a call
 *              with an operation number the interface does not have fails without harming the server.
 *              A refused call is made through a client stub (NdrClientCall2), which raises the status as an
 *              exception, as Windows 10 does: every refusal (the callback returns RPC_S_ACCESS_DENIED or
 *              another error, a remote client of a local-only interface) is seen as RPC_S_ACCESS_DENIED.
 *              (The low-level I_RpcSendReceive path is not used for a refusal: on Windows 10 it faults.)
 *
 * The server and the clients live in this process, over ncalrpc, ncacn_np and ncacn_ip_tcp on the loopback
 * address. A remote client cannot be made from one machine; the remote refusal is covered by the decision
 * function only through the loopback cases below (they must be allowed).
 */

#include <apitest.h>
#include <pseh/pseh2.h>

#include <stdio.h>
#include <windows.h>
#include <rpc.h>
#include <rpcdcep.h>

#include "interface_access_c.h"

void *__RPC_USER MIDL_user_allocate(SIZE_T size) { return malloc(size); }
void __RPC_USER MIDL_user_free(void *ptr) { free(ptr); }

static const RPC_SYNTAX_IDENTIFIER ndr_syntax =
{
    { 0x8A885D04, 0x1CEB, 0x11C9, { 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 } }, { 2, 0 }
};

enum cb_mode { CB_NONE, CB_ALLOW, CB_DENY, CB_DENY_OTHER };

struct if_def
{
    const char *name;
    UINT flags;
    enum cb_mode cb;
};

enum { IF_PLAIN, IF_LOCAL, IF_ALLOW, IF_DENY, IF_DENY_OTHER, IF_NOCACHE, IF_LOCAL_DENY, IF_COUNT };

static const struct if_def if_defs[IF_COUNT] =
{
    { "plain", 0, CB_NONE },
    { "local", RPC_IF_ALLOW_LOCAL_ONLY, CB_NONE },
    { "allow", 0, CB_ALLOW },
    { "deny", 0, CB_DENY },
    { "deny-other", 0, CB_DENY_OTHER },
    { "nocache", RPC_IF_SEC_NO_CACHE, CB_ALLOW },
    { "local+deny", RPC_IF_ALLOW_LOCAL_ONLY, CB_DENY },
};

static RPC_SERVER_INTERFACE server_if[IF_COUNT];
static RPC_CLIENT_INTERFACE client_if[IF_COUNT];
static RPC_DISPATCH_TABLE dispatch_table;
static volatile LONG callback_count[IF_COUNT];
static volatile LONG dispatch_count[IF_COUNT];
static volatile LONG callback_null_context[IF_COUNT];
static volatile LONG callback_wrong_iface;

static void WINAPI dispatch(PRPC_MESSAGE msg)
{
    int i;

    for (i = 0; i < IF_COUNT; i++)
        if (!memcmp(&((RPC_SERVER_INTERFACE *)msg->RpcInterfaceInformation)->InterfaceId.SyntaxGUID,
                    &server_if[i].InterfaceId.SyntaxGUID, sizeof(GUID)))
            InterlockedIncrement(&dispatch_count[i]);
    msg->BufferLength = sizeof(int);
    if (I_RpcGetBuffer(msg) == RPC_S_OK)
        *(int *)msg->Buffer = 42;
}

static RPC_STATUS CALLBACK if_callback(RPC_IF_HANDLE iface, void *context)
{
    /* Windows passes a pointer to the interface's RPC_SYNTAX_IDENTIFIER (measured), not the RPC_SERVER_INTERFACE */
    const RPC_SYNTAX_IDENTIFIER *id = iface;
    int i;

    for (i = 0; i < IF_COUNT; i++)
        if (!memcmp(&id->SyntaxGUID, &server_if[i].InterfaceId.SyntaxGUID, sizeof(GUID)) &&
            id->SyntaxVersion.MajorVersion == 1 && id->SyntaxVersion.MinorVersion == 0)
            break;
    if (i == IF_COUNT)
    {
        InterlockedIncrement(&callback_wrong_iface);
        return RPC_S_OK;
    }
    InterlockedIncrement(&callback_count[i]);
    if (!context)
        InterlockedIncrement(&callback_null_context[i]);
    switch (if_defs[i].cb)
    {
    case CB_DENY: return RPC_S_ACCESS_DENIED;
    case CB_DENY_OTHER: return 1234;
    default: return RPC_S_OK;
    }
}

static void init_interfaces(void)
{
    static RPC_DISPATCH_FUNCTION function = (RPC_DISPATCH_FUNCTION)dispatch;
    int i;

    dispatch_table.DispatchTableCount = 1;
    dispatch_table.DispatchTable = &function;
    for (i = 0; i < IF_COUNT; i++)
    {
        GUID id = { 0x5ec0ac00 + i, 0x4321, 0x1234, { 0, 0, 0, 0, 0, 0, 0, (BYTE)(i + 1) } };

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

/* one call on a binding; returns the status of the call, *result is the server's answer */
static RPC_STATUS do_call(RPC_BINDING_HANDLE binding, int index, unsigned int procnum, int *result)
{
    RPC_MESSAGE msg;
    RPC_STATUS status;

    memset(&msg, 0, sizeof(msg));
    msg.Handle = binding;
    msg.RpcInterfaceInformation = &client_if[index];
    msg.ProcNum = procnum;
    msg.DataRepresentation = 0x10;
    *result = -1;

    status = I_RpcGetBuffer(&msg);
    if (status != RPC_S_OK)
        return status;
    status = I_RpcSendReceive(&msg);
    if (status == RPC_S_OK && msg.BufferLength >= sizeof(int))
        *result = *(int *)msg.Buffer;
    I_RpcFreeBuffer(&msg);
    return status;
}

static int (__cdecl *const ndr_stub[IF_COUNT])(handle_t) =
{
    ndr_plain_call, ndr_local_call, ndr_allow_call, ndr_deny_call, ndr_deny_other_call, ndr_nocache_call, ndr_local_deny_call
};

/* one call through the client stub: the status of a refused call is the exception code the stub raises
 * (what RpcExceptionCode returns in an RpcTryExcept / RpcExcept block) */
static RPC_STATUS do_ndr_call(RPC_BINDING_HANDLE binding, int index, int *result)
{
    RPC_STATUS status = RPC_S_OK;

    *result = -1;
    _SEH2_TRY
    {
        *result = ndr_stub[index](binding);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
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

static char lrpc_endpoint[64], pipe_endpoint[64], tcp_endpoint[16];

struct transport
{
    const char *name;
    const char *protseq;
    const char *address;
    const char *endpoint;
    BOOL usable;
    BOOL local;       /* counts as local for RPC_IF_ALLOW_LOCAL_ONLY */
    BOOL cached;      /* the callback verdict is kept for the connection (unauthenticated callers: ncalrpc only) */
};

static void reset_counts(void)
{
    int i;

    for (i = 0; i < IF_COUNT; i++)
    {
        callback_count[i] = 0;
        dispatch_count[i] = 0;
    }
}

static void test_transport(struct transport *t)
{
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status;
    int result, i;

    trace("transport %s\n", t->name);

    /* an interface without callback and flags */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_call(binding, IF_PLAIN, 0, &result);
    ok_eq_hex(status, RPC_S_OK);
    ok_eq_int(result, 42);
    ok_eq_long(callback_count[IF_PLAIN], 0);
    RpcBindingFree(&binding);

    /* a local-only interface serves ncalrpc and local named pipe clients; a TCP client is refused, also over
     * the loopback address (measured on Windows 10) */
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_ndr_call(binding, IF_LOCAL, &result);
    ok_eq_hex(status, t->local ? RPC_S_OK : RPC_S_ACCESS_DENIED);
    ok_eq_int(result, t->local ? 42 : -1);
    RpcBindingFree(&binding);

    /* the callback allows: the call is served, the callback ran once for two calls on the binding (twice for a named pipe or TCP caller that set no authentication, as on Windows), got the
     * interface it belongs to and a binding handle */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_call(binding, IF_ALLOW, 0, &result);
    ok_eq_hex(status, RPC_S_OK);
    ok_eq_int(result, 42);
    status = do_call(binding, IF_ALLOW, 0, &result);
    ok_eq_hex(status, RPC_S_OK);
    ok_eq_int(result, 42);
    ok_eq_long(callback_count[IF_ALLOW], t->cached ? 1 : 2);
    ok_eq_long(callback_null_context[IF_ALLOW], 0);
    ok_eq_long(dispatch_count[IF_ALLOW], 2);
    RpcBindingFree(&binding);

    /* the callback denies: the stub raises RPC_S_ACCESS_DENIED (measured on Windows 10 over ncalrpc, ncacn_np and
     * ncacn_ip_tcp, whatever the error the callback returned) and the server routine does not run, also the
     * second time (the verdict is kept) */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_ndr_call(binding, IF_DENY, &result);
    ok_eq_hex(status, RPC_S_ACCESS_DENIED);
    ok_eq_int(result, -1);
    status = do_ndr_call(binding, IF_DENY, &result);
    ok_eq_hex(status, RPC_S_ACCESS_DENIED);
    ok_eq_long(dispatch_count[IF_DENY], 0);
    /* a refusal ends the client's connection, so the second call may ask again */
    ok(callback_count[IF_DENY] >= 1 && callback_count[IF_DENY] <= 2, "callback_count[IF_DENY] = %ld\n", (long)callback_count[IF_DENY]);
    RpcBindingFree(&binding);

    /* any verdict other than RPC_S_OK refuses the call */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_ndr_call(binding, IF_DENY_OTHER, &result);
    ok_eq_hex(status, RPC_S_ACCESS_DENIED);
    ok_eq_long(dispatch_count[IF_DENY_OTHER], 0);
    RpcBindingFree(&binding);

    /* RPC_IF_SEC_NO_CACHE: asked for every call */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    for (i = 0; i < 3; i++)
    {
        status = do_call(binding, IF_NOCACHE, 0, &result);
        ok_eq_hex(status, RPC_S_OK);
    }
    ok_eq_long(callback_count[IF_NOCACHE], 3);
    ok_eq_long(dispatch_count[IF_NOCACHE], 3);
    RpcBindingFree(&binding);

    /* local-only and the callback both apply: a local caller reaches the callback, which denies */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_ndr_call(binding, IF_LOCAL_DENY, &result);
    ok_eq_hex(status, RPC_S_ACCESS_DENIED);
    ok_eq_long(dispatch_count[IF_LOCAL_DENY], 0);
    RpcBindingFree(&binding);

    /* an operation number the interface does not have is an error for the caller, and the server goes on */
    reset_counts();
    binding = make_binding(t->protseq, t->address, t->endpoint);
    status = do_call(binding, IF_PLAIN, 7, &result);
    ok(status != RPC_S_OK, "operation 7 of a one-operation interface succeeded\n");
    ok_eq_long(dispatch_count[IF_PLAIN], 0);
    status = do_call(binding, IF_PLAIN, 0, &result);
    ok_eq_hex(status, RPC_S_OK);
    ok_eq_int(result, 42);
    RpcBindingFree(&binding);

    ok_eq_long(callback_wrong_iface, 0);
}

START_TEST(interface_access)
{
    RPC_STATUS status;
    struct transport transports[3] = {{0}};
    int i, count = 0;
    DWORD pid = GetCurrentProcessId();

    init_interfaces();
    sprintf(lrpc_endpoint, "rpcrt4_apitest_lrpc_%lu", pid);
    sprintf(pipe_endpoint, "\\pipe\\rpcrt4_apitest_np_%lu", pid);
    sprintf(tcp_endpoint, "%lu", 47000 + pid % 1000);

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncalrpc", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)lrpc_endpoint, NULL);
    ok_eq_hex(status, RPC_S_OK);
    transports[count].name = "ncalrpc";
    transports[count].protseq = "ncalrpc";
    transports[count].address = NULL;
    transports[count].endpoint = lrpc_endpoint;
    transports[count].local = TRUE;
    transports[count].cached = TRUE;
    count++;

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_np", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)pipe_endpoint, NULL);
    ok_eq_hex(status, RPC_S_OK);
    transports[count].name = "ncacn_np";
    transports[count].protseq = "ncacn_np";
    transports[count].address = NULL;
    transports[count].endpoint = pipe_endpoint;
    transports[count].local = TRUE;
    count++;

    status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)tcp_endpoint, NULL);
    if (status == RPC_S_OK)
    {
        transports[count].name = "ncacn_ip_tcp (loopback)";
        transports[count].protseq = "ncacn_ip_tcp";
        transports[count].address = "127.0.0.1";
        transports[count].endpoint = tcp_endpoint;
        count++;
    }
    else
        skip("ncacn_ip_tcp is not available (%ld)\n", (long)status);

    for (i = 0; i < IF_COUNT; i++)
    {
        status = RpcServerRegisterIf3((RPC_IF_HANDLE)&server_if[i], NULL, NULL, if_defs[i].flags,
                                      RPC_C_LISTEN_MAX_CALLS_DEFAULT, (UINT)-1,
                                      if_defs[i].cb == CB_NONE ? NULL : if_callback, NULL);
        ok_eq_hex(status, RPC_S_OK);
    }
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    ok_eq_hex(status, RPC_S_OK);

    for (i = 0; i < count; i++)
        test_transport(&transports[i]);

    /* not waiting for the listener to finish: it waits for every client connection to close, and a client of
     * this process may still hold its idle TCP connection */
    RpcMgmtStopServerListening(NULL);
    for (i = 0; i < IF_COUNT; i++)
        RpcServerUnregisterIf((RPC_IF_HANDLE)&server_if[i], NULL, FALSE);
}
