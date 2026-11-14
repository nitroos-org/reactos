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
 *              - callers whose tokens differ in a group made deny-only, a privilege, the integrity level, the restricting
 *                SIDs or the user are each seen by the server (RpcImpersonateClient, and in the interface security
 *                callback) as exactly their current token, with the binding handles freed in between and overlapping,
 *                and a copy of a token whose state did not change still gets the connection back,
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
/* a second interface of the same server, whose security callback admits only a caller that has Administrators enabled
 * and works at the medium integrity level or above (a server that decides on that in its callback) */
static RPC_SERVER_INTERFACE policy_server_if;
static RPC_CLIENT_INTERFACE policy_client_if;
static RPC_CLIENT_INTERFACE *g_client_if = &client_if;   /* the interface the calls are made to */
static RPC_DISPATCH_TABLE dispatch_table;
static WCHAR g_user[32];
static SEC_WINNT_AUTH_IDENTITY_W g_identity;

/* the server side (of this process, or of the child) */
static volatile LONG g_callbacks;   /* connections seen: the callback ran for them */
static WCHAR g_seen_user[64];       /* who the server saw impersonating the client in the last call */
static volatile LONG g_impersonate = 1;   /* whether the server routine impersonates the caller */

/* What a token is, as far as a server decides on it: the user, whether Administrators is enabled or deny-only, whether
 * SeBackupPrivilege is enabled, the integrity level and the restricting SIDs. The server records it for the token it
 * gets from RpcImpersonateClient (in the security callback of a connection and in every call); the test compares it
 * with the token the caller acted with. */
#define VIEW_NONE 0xFFFFFFFFu

typedef struct
{
    DWORD valid;            /* a token was read */
    DWORD user_rid;
    DWORD admin_attr;       /* the enabled and deny-only attributes of Administrators, VIEW_NONE if not in the token */
    DWORD backup_attr;      /* the enabled attribute of SeBackupPrivilege, VIEW_NONE if not in the token */
    DWORD n_restricted;     /* restricting SIDs */
    DWORD restricted_rids;  /* sum of their last subauthorities (tells sets of one size apart) */
    DWORD integrity_rid;    /* VIEW_NONE if the token has none */
} VIEW;

static VIEW g_call_view;    /* in the last call */

static DWORD last_rid(PSID sid)
{
    return *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
}

/* the view of a token handle, or of the impersonation token of the thread if the handle is NULL */
static void read_view(HANDLE token, VIEW *v)
{
    BYTE buf[4096];
    HANDLE own = NULL;
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)buf;
    SID_IDENTIFIER_AUTHORITY nt = {SECURITY_NT_AUTHORITY};
    PSID admins = NULL;
    LUID backup;
    DWORD size, i;

    memset(v, 0xff, sizeof(*v));
    v->valid = 0;
    if (!token)
    {
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &own))
            return;
        token = own;
    }
    v->valid = 1;
    AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins);
    LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &backup);

    if (GetTokenInformation(token, TokenUser, buf, sizeof(buf), &size))
        v->user_rid = last_rid(((TOKEN_USER *)buf)->User.Sid);
    if (GetTokenInformation(token, TokenGroups, buf, sizeof(buf), &size))
        for (i = 0; i < groups->GroupCount; i++)
            if (EqualSid(groups->Groups[i].Sid, admins))
                v->admin_attr = groups->Groups[i].Attributes & (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY);
    if (GetTokenInformation(token, TokenPrivileges, buf, sizeof(buf), &size))
    {
        TOKEN_PRIVILEGES *p = (TOKEN_PRIVILEGES *)buf;

        for (i = 0; i < p->PrivilegeCount; i++)
            if (p->Privileges[i].Luid.LowPart == backup.LowPart && p->Privileges[i].Luid.HighPart == backup.HighPart)
                v->backup_attr = p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED;
    }
    v->n_restricted = 0;
    v->restricted_rids = 0;
    if (GetTokenInformation(token, TokenRestrictedSids, buf, sizeof(buf), &size))
    {
        v->n_restricted = groups->GroupCount;
        for (i = 0; i < groups->GroupCount; i++)
            v->restricted_rids += last_rid(groups->Groups[i].Sid);
    }
    if (GetTokenInformation(token, TokenIntegrityLevel, buf, sizeof(buf), &size))
        v->integrity_rid = last_rid(((TOKEN_MANDATORY_LABEL *)buf)->Label.Sid);

    FreeSid(admins);
    if (own)
        CloseHandle(own);
}

static RPC_STATUS WINAPI if_callback(RPC_IF_HANDLE handle, void *context)
{
    InterlockedIncrement(&g_callbacks);
    return RPC_S_OK;
}

/* whether a server that decides on it in its security callback admits the caller whose token it sees */
static BOOL admitted(const VIEW *v)
{
    return v->valid && v->admin_attr != VIEW_NONE && (v->admin_attr & SE_GROUP_ENABLED) &&
           v->integrity_rid != VIEW_NONE && v->integrity_rid >= SECURITY_MANDATORY_MEDIUM_RID;
}

static RPC_STATUS WINAPI policy_callback(RPC_IF_HANDLE handle, void *context)
{
    VIEW view;

    InterlockedIncrement(&g_callbacks);
    memset(&view, 0, sizeof(view));
    if (RpcImpersonateClient(context) == RPC_S_OK)
    {
        read_view(NULL, &view);
        RpcRevertToSelf();
    }
    return admitted(&view) ? RPC_S_OK : RPC_S_ACCESS_DENIED;
}

static void WINAPI dispatch(PRPC_MESSAGE msg)
{
    DWORD n;

    g_seen_user[0] = 0;
    memset(&g_call_view, 0, sizeof(g_call_view));
    if (g_impersonate && RpcImpersonateClient(msg->Handle) == RPC_S_OK)
    {
        n = ARRAYSIZE(g_seen_user);
        GetUserNameW(g_seen_user, &n);
        read_view(NULL, &g_call_view);
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

    id.Data4[7] = 2;
    policy_server_if = server_if;
    policy_server_if.InterfaceId.SyntaxGUID = id;
    policy_client_if = client_if;
    policy_client_if.InterfaceId = policy_server_if.InterfaceId;
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
    status = RpcServerRegisterIf2((RPC_IF_HANDLE)&policy_server_if, NULL, NULL, 0, RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                                  (UINT)-1, policy_callback);
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
    msg.RpcInterfaceInformation = g_client_if;
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

/* Callers whose tokens differ in what a server decides on (a group made deny-only, a privilege, the integrity level, the
 * restricting SIDs, another user) must each be seen as what they are, never as the caller whose connection was kept:
 * the server records what RpcImpersonateClient gives it in every call, and it has to be the caller's current token; a
 * second interface of the server admits a caller in its security callback by what it sees of the token (Administrators
 * enabled, medium integrity or above), and each caller has to get the verdict of its own token. The two calls are made through new binding handles, in turn (the first
 * handle freed before the second call, so the connection is kept for it) and with the first handle still alive (the
 * connections of the handles of one server are shared while one is). A token and its copy (every impersonation makes
 * one) still share a connection. */
enum { M_PLAIN, M_STATIC, M_DYNAMIC, M_COUNT };
static const char *const mode_name[M_COUNT] = { "default security", "static tracking", "dynamic tracking" };

static RPC_BINDING_HANDLE new_mode_handle(const struct transport *t, int mode)
{
    RPC_BINDING_HANDLE binding = make_binding(t->protseq, t->address, t->endpoint);
    RPC_SECURITY_QOS qos;
    RPC_STATUS status;

    if (mode == M_PLAIN)
    {
        if (t->base_level)
        {
            status = RpcBindingSetAuthInfoW(binding, NULL, t->base_level, RPC_C_AUTHN_WINNT, NULL, 0);
            ok_eq_hex(status, RPC_S_OK);
        }
        return binding;
    }
    memset(&qos, 0, sizeof(qos));
    qos.Version = 1;
    qos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
    qos.IdentityTracking = mode == M_DYNAMIC ? RPC_C_QOS_IDENTITY_DYNAMIC : RPC_C_QOS_IDENTITY_STATIC;
    qos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
    status = RpcBindingSetAuthInfoExW(binding, NULL, t->base_level ? t->base_level : RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                      RPC_C_AUTHN_WINNT, NULL, RPC_C_AUTHZ_NONE, &qos);
    ok_eq_hex(status, RPC_S_OK);
    return binding;
}

/* a call through a new binding handle with the thread acting with the token (NULL: its own); the handle is kept if
 * asked for */
static RPC_STATUS call_as(const struct transport *t, int mode, HANDLE token, RPC_BINDING_HANDLE *keep)
{
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status;
    int result;

    if (token && !SetThreadToken(NULL, token))
        return GetLastError();
    binding = new_mode_handle(t, mode);
    status = do_call(binding, &result);
    if (keep)
        *keep = binding;
    else
        RpcBindingFree(&binding);
    if (token)
        SetThreadToken(NULL, NULL);
    if (status == RPC_S_OK)
        *t->last_reply = result;
    return status;
}

static void format_view(const VIEW *v, char *out)
{
    if (!v->valid)
        strcpy(out, "{no token}");
    else
        sprintf(out, "{user %lu, Administrators %lx, SeBackup %lx, restricting %lu/%lu, integrity %lx}",
                (unsigned long)v->user_rid, (unsigned long)v->admin_attr, (unsigned long)v->backup_attr,
                (unsigned long)v->n_restricted, (unsigned long)v->restricted_rids, (unsigned long)v->integrity_rid);
}

/* what the server saw (a) of the caller's token (b): a transport that gives the server only the effective part of the
 * token (an impersonation of the pipe peer without a copy of the disabled privileges and groups) shows what a caller
 * has disabled as missing; what a caller has enabled must be there, and nothing else may differ */
static BOOL same_view(const VIEW *a, const VIEW *b)
{
    BOOL admins = a->admin_attr == b->admin_attr || (a->admin_attr == VIEW_NONE && !(b->admin_attr & SE_GROUP_ENABLED));
    BOOL backup = a->backup_attr == b->backup_attr || (a->backup_attr == VIEW_NONE && !(b->backup_attr & SE_PRIVILEGE_ENABLED));

    return a->valid == b->valid && a->user_rid == b->user_rid && admins && backup && a->n_restricted == b->n_restricted &&
           a->restricted_rids == b->restricted_rids && a->integrity_rid == b->integrity_rid;
}

static HANDLE impersonation_copy(HANDLE source)
{
    HANDLE token = NULL;

    if (!DuplicateTokenEx(source, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &token))
        return NULL;
    return token;
}

/* a copy of the process token with SeBackupPrivilege enabled or disabled; NULL if it does not have it */
static HANDLE with_backup(BOOL enabled)
{
    HANDLE process_token, token;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &process_token))
        return NULL;
    token = impersonation_copy(process_token);
    CloseHandle(process_token);
    if (!token)
        return NULL;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;
    if (!LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &tp.Privileges[0].Luid) ||
        !AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) || GetLastError() != ERROR_SUCCESS)
    {
        CloseHandle(token);
        return NULL;
    }
    return token;
}

/* a copy of the process token with Administrators deny-only and/or restricting SIDs (Everyone and one of Users and
 * Administrators), or at the low integrity level */
static HANDLE filtered_token(BOOL deny_admins, int restrict_with, BOOL low)
{
    HANDLE process_token, restricted = NULL, token = NULL;
    SID_AND_ATTRIBUTES disable, restricting[2];
    BYTE sids[3][SECURITY_MAX_SID_SIZE];
    DWORD size;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &process_token))
        return NULL;
    if (low)
    {
        TOKEN_MANDATORY_LABEL label;

        token = impersonation_copy(process_token);
        CloseHandle(process_token);
        if (!token)
            return NULL;
        size = sizeof(sids[0]);
        CreateWellKnownSid(WinLowLabelSid, NULL, sids[0], &size);
        label.Label.Sid = sids[0];
        label.Label.Attributes = SE_GROUP_INTEGRITY;
        if (!SetTokenInformation(token, TokenIntegrityLevel, &label, sizeof(label)))
        {
            CloseHandle(token);
            return NULL;
        }
        return token;
    }

    size = sizeof(sids[0]);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sids[0], &size);
    disable.Sid = sids[0];
    disable.Attributes = 0;
    if (restrict_with)
    {
        size = sizeof(sids[1]);
        CreateWellKnownSid(WinWorldSid, NULL, sids[1], &size);
        size = sizeof(sids[2]);
        CreateWellKnownSid(restrict_with == 1 ? WinBuiltinUsersSid : WinBuiltinAdministratorsSid, NULL, sids[2], &size);
        restricting[0].Sid = sids[1];
        restricting[0].Attributes = 0;
        restricting[1].Sid = sids[2];
        restricting[1].Attributes = 0;
    }
    if (CreateRestrictedToken(process_token, 0, deny_admins ? 1 : 0, deny_admins ? &disable : NULL, 0, NULL,
                              restrict_with ? 2 : 0, restrict_with ? restricting : NULL, &restricted))
    {
        token = impersonation_copy(restricted);
        CloseHandle(restricted);
    }
    CloseHandle(process_token);
    return token;
}

static void check_views(const struct transport *t, int mode, const char *what, const char *which, const VIEW *seen,
                        const VIEW *expected)
{
    char s[128], e[128];

    format_view(seen, s);
    format_view(expected, e);
    ok(same_view(seen, expected), "%s, %s, %s, %s: the server saw %s, the caller is %s\n", t->name, mode_name[mode], what,
       which, s, e);
}

static void test_identity_pair(struct transport *t, int mode, BOOL overlap, const char *what, HANDLE first,
                               HANDLE second)
{
    RPC_BINDING_HANDLE kept = NULL;
    VIEW want_first, want_second, seen;
    RPC_STATUS status;

    read_view(first, &want_first);
    read_view(second, &want_second);

    status = call_as(t, mode, first, overlap ? &kept : NULL);
    ok(status == RPC_S_OK, "%s, %s, %s: call as the first token: status %lu\n", t->name, mode_name[mode], what,
       (unsigned long)status);
    seen = g_call_view;
    check_views(t, mode, what, "first caller", &seen, &want_first);

    status = call_as(t, mode, second, NULL);
    ok(status == RPC_S_OK, "%s, %s, %s: call as the second token: status %lu\n", t->name, mode_name[mode], what,
       (unsigned long)status);
    seen = g_call_view;
    check_views(t, mode, what, "second caller", &seen, &want_second);

    if (kept)
        RpcBindingFree(&kept);

    /* a server that admits a caller in its security callback by what it sees of the token: the verdict is the one for
     * the caller's own token, not the one for the caller that used the server before (the same calls to an interface
     * with such a callback; a connection is bound to the interface, so these are connections of their own) */
    g_client_if = &policy_client_if;
    status = call_as(t, mode, first, overlap ? &kept : NULL);
    ok(status == (admitted(&want_first) ? RPC_S_OK : RPC_S_ACCESS_DENIED),
       "%s, %s, %s: first caller, security callback: status %lu\n", t->name, mode_name[mode], what,
       (unsigned long)status);
    status = call_as(t, mode, second, NULL);
    ok(status == (admitted(&want_second) ? RPC_S_OK : RPC_S_ACCESS_DENIED),
       "%s, %s, %s: second caller, security callback: status %lu\n", t->name, mode_name[mode], what,
       (unsigned long)status);
    g_client_if = &client_if;
    if (kept)
        RpcBindingFree(&kept);
}

static void test_identity(struct transport *t)
{
    HANDLE full, copy, copy2, backup_on, backup_off, deny_admins, low, restrict_users, restrict_admins, user = NULL;
    HANDLE process_token;
    BOOL overlap;
    int mode;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &process_token))
    {
        skip("OpenProcessToken failed (%lu)\n", GetLastError());
        return;
    }
    full = impersonation_copy(process_token);
    CloseHandle(process_token);
    backup_on = with_backup(TRUE);
    backup_off = with_backup(FALSE);
    deny_admins = filtered_token(TRUE, 0, FALSE);
    low = filtered_token(FALSE, 0, TRUE);
    restrict_users = filtered_token(FALSE, 1, FALSE);
    restrict_admins = filtered_token(FALSE, 2, FALSE);
    if (g_user[0])
    {
        HANDLE logon;

        if (LogonUserW(g_user, L".", REUSE_PASSWORD, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &logon) ||
            LogonUserW(g_user, L".", REUSE_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &logon))
        {
            user = impersonation_copy(logon);
            CloseHandle(logon);
        }
    }
    ok(full != NULL, "no copy of the process token\n");
    if (!full)
        return;

    for (overlap = FALSE; overlap <= TRUE; overlap++)
    {
        for (mode = 0; mode < M_COUNT; mode++)
        {
            const char *w = overlap ? "overlapping handles" : "handle freed";
            char what[96];

            if (deny_admins)
            {
                sprintf(what, "%s, full then Administrators deny-only", w);
                test_identity_pair(t, mode, overlap, what, full, deny_admins);
                sprintf(what, "%s, Administrators deny-only then full", w);
                test_identity_pair(t, mode, overlap, what, deny_admins, full);
            }
            if (low)
            {
                sprintf(what, "%s, full then low integrity", w);
                test_identity_pair(t, mode, overlap, what, full, low);
                sprintf(what, "%s, low integrity then full", w);
                test_identity_pair(t, mode, overlap, what, low, full);
            }
            if (backup_on && backup_off)
            {
                sprintf(what, "%s, privilege enabled then disabled", w);
                test_identity_pair(t, mode, overlap, what, backup_on, backup_off);
                sprintf(what, "%s, privilege disabled then enabled", w);
                test_identity_pair(t, mode, overlap, what, backup_off, backup_on);
            }
            if (restrict_users && restrict_admins)
            {
                sprintf(what, "%s, restricting SIDs {Everyone, Users} then {Everyone, Administrators}", w);
                test_identity_pair(t, mode, overlap, what, restrict_users, restrict_admins);
                sprintf(what, "%s, restricting SIDs {Everyone, Administrators} then {Everyone, Users}", w);
                test_identity_pair(t, mode, overlap, what, restrict_admins, restrict_users);
            }
            if (user)
            {
                sprintf(what, "%s, the logged on user then another user", w);
                test_identity_pair(t, mode, overlap, what, full, user);
                sprintf(what, "%s, another user then the logged on user", w);
                test_identity_pair(t, mode, overlap, what, user, full);
            }
        }
    }

    /* what the connection key is made of costs nothing for a caller whose token has not changed: another copy of it
     * (every impersonation of a client makes one) and the token of the thread itself get the connection back */
    for (mode = 0; mode < M_COUNT; mode++)
    {
        HANDLE tokens[3] = { backup_off, NULL, NULL };
        LONG n;
        int i;

        if (!backup_off)
            break;
        copy = impersonation_copy(backup_off);
        copy2 = copy ? impersonation_copy(copy) : NULL;
        tokens[1] = copy;
        tokens[2] = copy2;
        if (!copy || !copy2)
        {
            skip("DuplicateTokenEx failed (%lu)\n", GetLastError());
            if (copy) CloseHandle(copy);
            if (copy2) CloseHandle(copy2);
            break;
        }
        ok(call_as(t, mode, tokens[0], NULL) == RPC_S_OK, "%s, %s: first call failed\n", t->name, mode_name[mode]);
        for (i = 1; i < 3; i++)
        {
            LONG before = g_callbacks;

            ok(call_as(t, mode, tokens[i], NULL) == RPC_S_OK, "%s, %s: call %d failed\n", t->name, mode_name[mode], i);
            n = g_callbacks - before;
            ok(n == 0, "%s, %s: a copy of the same token state (%d) opened %ld connections\n", t->name, mode_name[mode],
               i, n);
        }
        CloseHandle(copy);
        CloseHandle(copy2);
    }

    calls_with(t, t->base_level, NULL, "identity tests: connection count");   /* the count is in step again */

    CloseHandle(full);
    if (backup_on) CloseHandle(backup_on);
    if (backup_off) CloseHandle(backup_off);
    if (deny_admins) CloseHandle(deny_admins);
    if (low) CloseHandle(low);
    if (restrict_users) CloseHandle(restrict_users);
    if (restrict_admins) CloseHandle(restrict_admins);
    if (user) CloseHandle(user);
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
        /* before the calls that are refused: on a runtime that keeps the binding of a failed call, later handles
         * find the connections of its association */
        if (getenv("RPCREUSE_BENCH"))
            bench(&transports[i], atoi(getenv("RPCREUSE_BENCH")));
        test_identity(&transports[i]);
        test_handles(&transports[i]);
    }

    test_server_restart();

    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf((RPC_IF_HANDLE)&server_if, NULL, FALSE);
    RpcServerUnregisterIf((RPC_IF_HANDLE)&policy_server_if, NULL, FALSE);
    if (g_user[0])
        NetUserDel(NULL, g_user);
}
