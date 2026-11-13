/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The local call of a same-machine NTLM exchange: with the credentials of the logged on user the NEGOTIATE
 *              names this machine, the server offers a context of the LSA in the CHALLENGE, the client answers with an
 *              empty AUTHENTICATE and the server gets a copy of the client's token (no response is computed or
 *              checked). A context that no client on this machine bound, a context of another process, a reused
 *              context and a NEGOTIATE of another machine never give a token.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <ntlmros.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define LOCAL_CALL      0x00004000
#define DOMAIN_SUPPLIED 0x00001000
#define WS_SUPPLIED     0x00002000
#define CHILD_VAR       "SECUR32_APITEST_LOCALCALL_CHILD"

static ULONG rd16(const BYTE *p) { return p[0] | (p[1] << 8); }
static ULONG rd32(const BYTE *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((ULONG)p[3] << 24); }
static void wr16(BYTE *p, ULONG v) { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); }
static void wr32(BYTE *p, ULONG v) { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); p[2] = (BYTE)(v >> 16); p[3] = (BYTE)(v >> 24); }
static ULONG64 challenge_context(const BYTE *chal) { return rd32(chal + 32) | ((ULONG64)rd32(chal + 36) << 32); }

typedef struct
{
    CredHandle cc, sc;
    CtxtHandle cctx, sctx;
    BOOL have_cctx, have_sctx;
    BYTE neg[512], chal[1024], auth[2048];
    ULONG neg_len, chal_len, auth_len;
} exchange;

static SECURITY_STATUS client_step(exchange *x, ULONG req, const BYTE *in, ULONG in_len, BYTE *out, ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { *out_len, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    TimeStamp ts;
    ULONG attr;
    SECURITY_STATUS st;

    st = InitializeSecurityContextW(&x->cc, x->have_cctx ? &x->cctx : NULL, (SEC_WCHAR *)L"host/localhost", req, 0,
                                    SECURITY_NATIVE_DREP, in ? &id : NULL, 0, &x->cctx, &od, &attr, &ts);
    if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) x->have_cctx = TRUE;
    *out_len = ob.cbBuffer;
    return st;
}

static SECURITY_STATUS server_step(exchange *x, ULONG req, const BYTE *in, ULONG in_len, BYTE *out, ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { *out_len, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    TimeStamp ts;
    ULONG attr;
    SECURITY_STATUS st;

    st = AcceptSecurityContext(&x->sc, x->have_sctx ? &x->sctx : NULL, &id, req, SECURITY_NATIVE_DREP, &x->sctx, &od,
                               &attr, &ts);
    if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) x->have_sctx = TRUE;
    *out_len = ob.cbBuffer;
    return st;
}

static BOOL exchange_init(exchange *x, SEC_WINNT_AUTH_IDENTITY_W *identity)
{
    TimeStamp ts;
    SECURITY_STATUS st;

    memset(x, 0, sizeof(*x));
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, identity, NULL, NULL, &x->cc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) return FALSE;
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &x->sc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) { FreeCredentialsHandle(&x->cc); return FALSE; }
    return TRUE;
}

static void exchange_free(exchange *x)
{
    if (x->have_cctx) DeleteSecurityContext(&x->cctx);
    if (x->have_sctx) DeleteSecurityContext(&x->sctx);
    FreeCredentialsHandle(&x->cc);
    FreeCredentialsHandle(&x->sc);
}

/* NEGOTIATE and CHALLENGE */
static BOOL first_round(exchange *x, ULONG creq, ULONG sreq)
{
    SECURITY_STATUS st;

    x->neg_len = sizeof(x->neg);
    st = client_step(x, creq, NULL, 0, x->neg, &x->neg_len);
    ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
    if (st != SEC_I_CONTINUE_NEEDED) return FALSE;
    x->chal_len = sizeof(x->chal);
    st = server_step(x, sreq, x->neg, x->neg_len, x->chal, &x->chal_len);
    ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
    return st == SEC_I_CONTINUE_NEEDED && x->chal_len >= 48;
}

/* an AUTHENTICATE without any response or name (88 bytes, version and MIC zero) */
static ULONG empty_authenticate(BYTE *t, ULONG flags)
{
    ULONG at;

    memset(t, 0, 88);
    memcpy(t, "NTLMSSP", 8);
    wr32(t + 8, 3);
    for (at = 12; at <= 52; at += 8) wr32(t + at + 4, 88);
    wr32(t + 60, flags);
    return 88;
}

/* a NEGOTIATE with the given OEM names */
static ULONG make_negotiate(BYTE *t, ULONG flags, const char *domain, const char *ws)
{
    ULONG dl = domain ? (ULONG)strlen(domain) : 0, wl = ws ? (ULONG)strlen(ws) : 0, off = 40;

    memset(t, 0, 40);
    memcpy(t, "NTLMSSP", 8);
    wr32(t + 8, 1);
    wr32(t + 12, flags);
    wr16(t + 16, dl); wr16(t + 18, dl); wr32(t + 20, off); if (dl) memcpy(t + off, domain, dl); off += dl;
    wr16(t + 24, wl); wr16(t + 26, wl); wr32(t + 28, off); if (wl) memcpy(t + off, ws, wl); off += wl;
    return off;
}

static BOOL token_stats(HANDLE token, TOKEN_STATISTICS *stats)
{
    DWORD len;
    return GetTokenInformation(token, TokenStatistics, stats, sizeof(*stats), &len);
}

static BOOL same_user(HANDLE a, HANDLE b)
{
    BYTE ua[256], ub[256];
    DWORD len;

    return GetTokenInformation(a, TokenUser, ua, sizeof(ua), &len) && GetTokenInformation(b, TokenUser, ub, sizeof(ub), &len) &&
           EqualSid(((TOKEN_USER *)ua)->User.Sid, ((TOKEN_USER *)ub)->User.Sid);
}

/* The exchange of the default credentials is a local call: the messages as Windows sends them, and the server's
 * token is a copy of the client's (same logon, same user) at the level the client allows */
static void test_local_exchange(ULONG creq, ULONG sreq, SECURITY_IMPERSONATION_LEVEL level, HANDLE client_token,
                                const char *what)
{
    exchange x;
    SECURITY_STATUS st;
    HANDLE token = NULL, me = client_token;
    TOKEN_STATISTICS mine, theirs;
    SecPkgContext_Names names;
    SecPkgContext_SessionKey skey, ckey;
    WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1];
    char oem[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n = ARRAYSIZE(computer);
    ULONG flags;
    int oem_len;

    if (!exchange_init(&x, NULL)) return;
    if (me == NULL) OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &me);
    if (client_token) ok(SetThreadToken(NULL, client_token), "%s: SetThreadToken failed %lu\n", what, GetLastError());
    if (!first_round(&x, creq, sreq)) goto done;

    /* NEGOTIATE: the names of this machine (the workstation as GetComputerName gives it), the version */
    flags = rd32(x.neg + 12);
    ok((flags & (DOMAIN_SUPPLIED | WS_SUPPLIED)) == (DOMAIN_SUPPLIED | WS_SUPPLIED), "%s: NEGOTIATE flags %08lx\n", what, flags);
    ok(flags & 0x02000000, "%s: no version flag %08lx\n", what, flags);
    ok(x.neg_len > 40, "%s: NEGOTIATE of %lu bytes\n", what, x.neg_len);
    ok(rd16(x.neg + 16) > 0, "%s: no domain name\n", what);
    GetComputerNameW(computer, &n);
    oem_len = WideCharToMultiByte(CP_OEMCP, 0, computer, n, oem, sizeof(oem), NULL, NULL);
    ok(rd16(x.neg + 24) == (ULONG)oem_len && rd32(x.neg + 28) + oem_len <= x.neg_len &&
       !memcmp(x.neg + rd32(x.neg + 28), oem, oem_len), "%s: the workstation is not %ls\n", what, computer);

    /* CHALLENGE: the local call with a context */
    ok(rd32(x.chal + 20) & LOCAL_CALL, "%s: CHALLENGE flags %08lx\n", what, rd32(x.chal + 20));
    ok(challenge_context(x.chal) != 0, "%s: no context in the CHALLENGE\n", what);

    /* AUTHENTICATE: nothing derived from a password, no name */
    x.auth_len = sizeof(x.auth);
    st = client_step(&x, creq, x.chal, x.chal_len, x.auth, &x.auth_len);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) goto done;
    if (client_token) RevertToSelf();
    ok_eq_ulong(x.auth_len, 88);
    ok(rd16(x.auth + 12) == 0 && rd16(x.auth + 20) == 0 && rd16(x.auth + 28) == 0 && rd16(x.auth + 36) == 0 &&
       rd16(x.auth + 44) == 0 && rd16(x.auth + 52) == 0, "%s: AUTHENTICATE carries a response or a name\n", what);
    ok(rd32(x.auth + 60) & LOCAL_CALL, "%s: AUTHENTICATE flags %08lx\n", what, rd32(x.auth + 60));

    x.chal_len = sizeof(x.chal);
    st = server_step(&x, sreq, x.auth, x.auth_len, x.chal, &x.chal_len);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) goto done;
    ok_eq_ulong(x.chal_len, 0);

    /* the token: an impersonation token of the client's own logon */
    st = QuerySecurityContextToken(&x.sctx, &token);
    ok_eq_hex(st, SEC_E_OK);
    if (st == SEC_E_OK)
    {
        TOKEN_TYPE type = 0;
        SECURITY_IMPERSONATION_LEVEL lvl = 0;
        DWORD len;

        ok(GetTokenInformation(token, TokenType, &type, sizeof(type), &len), "GetTokenInformation failed\n");
        ok_eq_int(type, TokenImpersonation);
        ok(GetTokenInformation(token, TokenImpersonationLevel, &lvl, sizeof(lvl), &len), "GetTokenInformation failed\n");
        ok(lvl == level, "%s: level %d instead of %d\n", what, lvl, level);
        ok(token_stats(token, &theirs) && token_stats(me, &mine), "token statistics failed\n");
        ok(theirs.AuthenticationId.LowPart == mine.AuthenticationId.LowPart &&
           theirs.AuthenticationId.HighPart == mine.AuthenticationId.HighPart,
           "%s: logon %08lx:%08lx instead of the client's %08lx:%08lx\n", what, theirs.AuthenticationId.HighPart,
           theirs.AuthenticationId.LowPart, mine.AuthenticationId.HighPart, mine.AuthenticationId.LowPart);
        ok(theirs.TokenId.LowPart != mine.TokenId.LowPart || theirs.TokenId.HighPart != mine.TokenId.HighPart,
           "%s: the client's own token object\n", what);
        ok(same_user(token, me), "%s: another user\n", what);
        CloseHandle(token);
    }

    /* the name of the client's account */
    names.sUserName = NULL;
    st = QueryContextAttributesW(&x.sctx, SECPKG_ATTR_NAMES, &names);
    ok_eq_hex(st, SEC_E_OK);
    if (st == SEC_E_OK)
    {
        ok(wcschr((WCHAR *)names.sUserName, L'\\') != NULL, "%s: name %ls\n", what, (WCHAR *)names.sUserName);
        FreeContextBuffer(names.sUserName);
    }

    /* the same session key on both sides; signing and sealing work */
    skey.SessionKey = ckey.SessionKey = NULL;
    st = QueryContextAttributesW(&x.sctx, SECPKG_ATTR_SESSION_KEY, &skey);
    ok_eq_hex(st, SEC_E_OK);
    st = QueryContextAttributesW(&x.cctx, SECPKG_ATTR_SESSION_KEY, &ckey);
    ok_eq_hex(st, SEC_E_OK);
    if (skey.SessionKey && ckey.SessionKey)
        ok(skey.SessionKeyLength == 16 && ckey.SessionKeyLength == 16 && !memcmp(skey.SessionKey, ckey.SessionKey, 16),
           "%s: the session keys differ\n", what);
    if (skey.SessionKey) FreeContextBuffer(skey.SessionKey);
    if (ckey.SessionKey) FreeContextBuffer(ckey.SessionKey);
    if (creq & (ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY))
    {
        BYTE data[32], sig[16];
        SecBuffer b[2] = { { sizeof(data), SECBUFFER_DATA, data }, { sizeof(sig), SECBUFFER_TOKEN, sig } };
        SecBufferDesc d = { SECBUFFER_VERSION, 2, b };

        memset(data, 'L', sizeof(data));
        ok_eq_hex(MakeSignature(&x.cctx, 0, &d, 0), SEC_E_OK);
        ok_eq_hex(VerifySignature(&x.sctx, &d, 0, NULL), SEC_E_OK);
        ok_eq_hex(MakeSignature(&x.sctx, 0, &d, 0), SEC_E_OK);
        ok_eq_hex(VerifySignature(&x.cctx, &d, 0, NULL), SEC_E_OK);
        data[0] ^= 1;
        ok_eq_hex(VerifySignature(&x.cctx, &d, 0, NULL), SEC_E_MESSAGE_ALTERED);
    }

    /* impersonation runs as the client */
    if (level >= SecurityImpersonation)
    {
        HANDLE t = NULL;

        st = ImpersonateSecurityContext(&x.sctx);
        ok_eq_hex(st, SEC_E_OK);
        if (st == SEC_E_OK)
        {
            ok(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &t), "no thread token %lu\n", GetLastError());
            if (t)
            {
                ok(same_user(t, me), "%s: impersonating another user\n", what);
                CloseHandle(t);
            }
            RevertSecurityContext(&x.sctx);
        }
    }

done:
    if (client_token) RevertToSelf();
    if (me != client_token) CloseHandle(me);
    exchange_free(&x);
}

/* explicit credentials: no names in the NEGOTIATE, no local call (as Windows) */
static void test_explicit_identity(void)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    exchange x;
    SECURITY_STATUS st;

    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)L"localcall_nouser";
    id.UserLength = 16;
    id.Domain = (unsigned short *)L".";
    id.DomainLength = 1;
    id.Password = (unsigned short *)L"x";
    id.PasswordLength = 1;
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if (!exchange_init(&x, &id)) return;
    if (first_round(&x, ISC_REQ_CONNECTION, ASC_REQ_CONNECTION))
    {
        ok(!(rd32(x.neg + 12) & (DOMAIN_SUPPLIED | WS_SUPPLIED)), "explicit: NEGOTIATE flags %08lx\n", rd32(x.neg + 12));
        ok(!(rd32(x.chal + 20) & LOCAL_CALL), "explicit: local call offered\n");
        ok(challenge_context(x.chal) == 0, "explicit: a context\n");
        /* the AUTHENTICATE carries the response; it is not handed to the server (no logon of a made-up user) */
        x.auth_len = sizeof(x.auth);
        st = client_step(&x, ISC_REQ_CONNECTION, x.chal, x.chal_len, x.auth, &x.auth_len);
        ok_eq_hex(st, SEC_E_OK);
        ok(rd16(x.auth + 20) > 24, "explicit: NT response of %lu bytes\n", rd16(x.auth + 20));
    }
    exchange_free(&x);
}

/* The server offered the local call, no client answered the CHALLENGE: an empty AUTHENTICATE claiming the local call
 * gets no token (Windows makes it an anonymous logon; this NTLM has no anonymous logon). The context is spent: the
 * client that gets the CHALLENGE afterwards answers with a response. */
static void test_unbound_context(void)
{
    exchange x;
    SECURITY_STATUS st;
    HANDLE token = NULL;
    BYTE t3[88];

    if (!exchange_init(&x, NULL)) return;
    if (first_round(&x, ISC_REQ_CONNECTION, ASC_REQ_CONNECTION))
    {
        ULONG out_len = sizeof(x.auth);

        ok(rd32(x.chal + 20) & LOCAL_CALL, "unbound: no local call offered\n");
        x.auth_len = empty_authenticate(t3, rd32(x.chal + 20));
        st = server_step(&x, ASC_REQ_CONNECTION, t3, x.auth_len, x.auth, &out_len);
        ok_eq_hex(st, SEC_E_LOGON_DENIED);
        st = QuerySecurityContextToken(&x.sctx, &token);
        ok(st != SEC_E_OK, "unbound: the server has a token\n");
        if (st == SEC_E_OK) CloseHandle(token);

        /* the context is gone: the client cannot bind it and answers as usual (or has no credentials) */
        x.auth_len = sizeof(x.auth);
        st = client_step(&x, ISC_REQ_CONNECTION, x.chal, x.chal_len, x.auth, &x.auth_len);
        ok(st == SEC_E_NO_CREDENTIALS || (st == SEC_E_OK && rd16(x.auth + 20) > 24),
           "unbound: client 0x%08lx, NT response of %lu bytes\n", (unsigned long)st,
           st == SEC_E_OK ? rd16(x.auth + 20) : 0);
    }
    exchange_free(&x);
}

/* a NEGOTIATE without names, or with names of another machine: no local call; an empty AUTHENTICATE claiming it
 * is refused */
static void test_other_names(void)
{
    exchange x;
    SECURITY_STATUS st;
    BYTE t1[128], t3[88], chal[1024];
    char dom[64] = "", ws[64] = "", lower[64];
    ULONG len, chal_len, i, base_flags;
    struct { const char *what; const char *d; const char *w; ULONG drop; BOOL local; } cases[] =
    {
        { "own names", dom, ws, 0, TRUE },
        { "other workstation", dom, "LOCALCALL-OTHER", 0, FALSE },
        { "other domain", "LOCALCALLDOM", ws, 0, FALSE },
        { "workstation in lower case", dom, lower, 0, FALSE },
        { "workstation only", NULL, ws, DOMAIN_SUPPLIED, FALSE },
        { "domain only", dom, NULL, WS_SUPPLIED, FALSE },
        { "no names", NULL, NULL, DOMAIN_SUPPLIED | WS_SUPPLIED, FALSE },
    };

    /* the names this machine sends */
    if (!exchange_init(&x, NULL)) return;
    if (!first_round(&x, ISC_REQ_CONNECTION, ASC_REQ_CONNECTION)) { exchange_free(&x); return; }
    base_flags = rd32(x.neg + 12);
    if (rd16(x.neg + 16) < sizeof(dom)) memcpy(dom, x.neg + rd32(x.neg + 20), rd16(x.neg + 16));
    if (rd16(x.neg + 24) < sizeof(ws)) memcpy(ws, x.neg + rd32(x.neg + 28), rd16(x.neg + 24));
    for (i = 0; ws[i]; i++) lower[i] = (char)tolower((unsigned char)ws[i]);
    lower[i] = 0;
    exchange_free(&x);

    for (i = 0; i < ARRAYSIZE(cases); i++)
    {
        if (!exchange_init(&x, NULL)) return;
        len = make_negotiate(t1, base_flags & ~cases[i].drop, cases[i].d, cases[i].w);
        chal_len = sizeof(chal);
        st = server_step(&x, ASC_REQ_CONNECTION, t1, len, chal, &chal_len);
        ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
        if (st == SEC_I_CONTINUE_NEEDED)
        {
            ok(!!(rd32(chal + 20) & LOCAL_CALL) == cases[i].local, "%s: local call %s\n", cases[i].what,
               cases[i].local ? "not offered" : "offered");
            ok((challenge_context(chal) != 0) == cases[i].local, "%s: context %s\n", cases[i].what,
               cases[i].local ? "missing" : "present");
            /* nobody bound a context: an empty AUTHENTICATE claiming the local call gets no token */
            len = empty_authenticate(t3, rd32(chal + 20) | LOCAL_CALL);
            chal_len = sizeof(chal);
            st = server_step(&x, ASC_REQ_CONNECTION, t3, len, chal, &chal_len);
            ok(st == SEC_E_LOGON_DENIED, "%s: empty AUTHENTICATE answered 0x%08lx\n", cases[i].what, (unsigned long)st);
        }
        exchange_free(&x);
    }
}

/* the client gets a CHALLENGE with a context its LSA never issued: no local call, no empty AUTHENTICATE */
static void test_altered_context(void)
{
    exchange x;
    SECURITY_STATUS st;

    if (!exchange_init(&x, NULL)) return;
    if (first_round(&x, ISC_REQ_CONNECTION, ASC_REQ_CONNECTION))
    {
        wr32(x.chal + 32, 0x91c3175a);
        wr32(x.chal + 36, 0x00000001);
        x.auth_len = sizeof(x.auth);
        st = client_step(&x, ISC_REQ_CONNECTION, x.chal, x.chal_len, x.auth, &x.auth_len);
        ok(st == SEC_E_NO_CREDENTIALS || (st == SEC_E_OK && rd16(x.auth + 20) > 24),
           "altered: client 0x%08lx, NT response of %lu bytes\n", (unsigned long)st,
           st == SEC_E_OK ? rd16(x.auth + 20) : 0);
    }
    exchange_free(&x);
}

/* the thread token the package call is made with (set after the connect, reverted after the call) */
static HANDLE call_token;

/* the private messages of the MSV1_0 package, as secur32 sends them */
static NTSTATUS msv_call(void *req, ULONG len, void *out, ULONG out_len)
{
    static const char name[] = MSV1_0_PACKAGE_NAME;
    HANDLE lsa = NULL;
    LSA_STRING package = { sizeof(name) - 1, sizeof(name), (PCHAR)name };
    ULONG id, resp_len = 0;
    void *resp = NULL;
    NTSTATUS st, proto = 0;

    st = LsaConnectUntrusted(&lsa);
    if (st) return st;
    st = LsaLookupAuthenticationPackage(lsa, &package, &id);
    if (!st && call_token && !SetThreadToken(NULL, call_token)) st = STATUS_UNSUCCESSFUL;
    if (!st) st = LsaCallAuthenticationPackage(lsa, id, req, len, &resp, &resp_len, &proto);
    if (call_token) RevertToSelf();
    if (!st && proto) st = proto;
    if (!st && out)
    {
        if (resp && resp_len >= out_len) memcpy(out, resp, out_len);
        else st = STATUS_INVALID_NETWORK_RESPONSE;
    }
    if (resp) LsaFreeReturnBuffer(resp);
    LsaDeregisterLogonProcess(lsa);
    return st;
}

static NTSTATUS lsa_issue(const BYTE *challenge, ULONG64 *context)
{
    MSV1_0_ROS_NTLM_LOCAL_ISSUE req = { MsV1_0RosNtlmLocalIssue };
    MSV1_0_ROS_NTLM_LOCAL_CONTEXT resp;
    NTSTATUS st;

    memcpy(req.ServerChallenge, challenge, 8);
    st = msv_call(&req, sizeof(req), &resp, sizeof(resp));
    *context = st ? 0 : resp.ContextId;
    return st;
}

static NTSTATUS lsa_bind(ULONG64 context, const BYTE *challenge, BYTE *key)
{
    MSV1_0_ROS_NTLM_LOCAL_BIND req = { MsV1_0RosNtlmLocalBind, SecurityImpersonation };
    MSV1_0_ROS_NTLM_LOCAL_RESPONSE resp;
    NTSTATUS st;

    req.ContextId = context;
    memcpy(req.ServerChallenge, challenge, 8);
    st = msv_call(&req, sizeof(req), &resp, sizeof(resp));
    if (!st && key) memcpy(key, resp.SessionKey, 16);
    return st;
}

static NTSTATUS lsa_accept(ULONG64 context, HANDLE *token, BYTE *key)
{
    MSV1_0_ROS_NTLM_LOCAL_ACCEPT req = { MsV1_0RosNtlmLocalAccept };
    MSV1_0_ROS_NTLM_LOCAL_RESPONSE resp;
    NTSTATUS st;

    req.ContextId = context;
    st = msv_call(&req, sizeof(req), &resp, sizeof(resp));
    *token = st ? NULL : (HANDLE)(ULONG_PTR)resp.TokenHandle;
    if (!st && key) memcpy(key, resp.SessionKey, 16);
    return st;
}

/* The table of the LSA: a context binds once, completes once, only for the process that issued it; an id nobody
 * issued is unknown */
static void test_lsa_table(void)
{
    static const BYTE challenge[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, other[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
    ULONG64 context = 0;
    HANDLE token = NULL;
    BYTE ckey[16], skey[16];
    NTSTATUS st;

    ok_ntstatus(lsa_bind(0x0123456789abcdefULL, challenge, NULL), STATUS_NOT_FOUND);
    ok_ntstatus(lsa_accept(0x0123456789abcdefULL, &token, NULL), STATUS_NOT_FOUND);
    ok_ntstatus(lsa_bind(0, challenge, NULL), STATUS_INVALID_PARAMETER);

    st = lsa_issue(challenge, &context);
    ok_ntstatus(st, STATUS_SUCCESS);
    if (st) return;
    ok(context != 0, "context 0\n");
    /* not bound yet: no token, and the context is spent */
    ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_LOGON_FAILURE);
    ok_ntstatus(lsa_bind(context, challenge, NULL), STATUS_NOT_FOUND);

    ok_ntstatus(lsa_issue(challenge, &context), STATUS_SUCCESS);
    /* the challenge must be the context's */
    ok_ntstatus(lsa_bind(context, other, NULL), STATUS_NOT_FOUND);
    ok_ntstatus(lsa_bind(context, challenge, ckey), STATUS_SUCCESS);
    /* a second client cannot take the context over */
    ok_ntstatus(lsa_bind(context, challenge, NULL), STATUS_NOT_FOUND);
    st = lsa_accept(context, &token, skey);
    ok_ntstatus(st, STATUS_SUCCESS);
    if (!st)
    {
        ok(!memcmp(ckey, skey, 16), "the session keys differ\n");
        ok(token != NULL, "no token\n");
        if (token) CloseHandle(token);
    }
    /* once */
    ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_NOT_FOUND);
}

/* A client thread whose token the LSA cannot use is never taken for its process: a thread that impersonates at the
 * anonymous level, and a thread token the LSA may not open, bind nothing */
static void test_unusable_thread_token(void)
{
    static const BYTE challenge[8] = { 3, 1, 4, 1, 5, 9, 2, 6 };
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    PSECURITY_DESCRIPTOR sd = NULL;
    HANDLE me = NULL, anon = NULL, closed = NULL, token = NULL;
    ULONG64 context;
    NTSTATUS st;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &me))
    {
        skip("OpenProcessToken failed %lu\n", GetLastError());
        return;
    }

    /* anonymous level: the LSA cannot open it (STATUS_CANT_OPEN_ANONYMOUS) */
    if (DuplicateTokenEx(me, TOKEN_ALL_ACCESS, NULL, SecurityAnonymous, TokenImpersonation, &anon))
    {
        ok_ntstatus(lsa_issue(challenge, &context), STATUS_SUCCESS);
        call_token = anon;
        st = lsa_bind(context, challenge, NULL);
        call_token = NULL;
        ok(st == STATUS_CANT_OPEN_ANONYMOUS, "anonymous level: bind 0x%08lx\n", (unsigned long)st);
        /* nobody bound it */
        ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_LOGON_FAILURE);
        if (token) CloseHandle(token);
        token = NULL;
        CloseHandle(anon);
    }
    else
        skip("DuplicateTokenEx failed %lu\n", GetLastError());

    /* a token whose DACL denies the LSA (SYSTEM) */
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(D;;GA;;;SY)(A;;GA;;;WD)", SDDL_REVISION_1, &sd, NULL))
    {
        sa.lpSecurityDescriptor = sd;
        if (DuplicateTokenEx(me, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenImpersonation, &closed))
        {
            ok_ntstatus(lsa_issue(challenge, &context), STATUS_SUCCESS);
            call_token = closed;
            st = lsa_bind(context, challenge, NULL);
            call_token = NULL;
            ok(st == STATUS_ACCESS_DENIED, "unopenable: bind 0x%08lx\n", (unsigned long)st);
            ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_LOGON_FAILURE);
            if (token) CloseHandle(token);
            token = NULL;
            CloseHandle(closed);
        }
        else
            skip("DuplicateTokenEx failed %lu\n", GetLastError());
        LocalFree(sd);
    }
    else
        skip("ConvertStringSecurityDescriptorToSecurityDescriptorA failed %lu\n", GetLastError());

    /* the same thread without a token binds its process (control) */
    ok_ntstatus(lsa_issue(challenge, &context), STATUS_SUCCESS);
    ok_ntstatus(lsa_bind(context, challenge, NULL), STATUS_SUCCESS);
    ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_SUCCESS);
    if (token) CloseHandle(token);
    CloseHandle(me);
}

/* a helper process of the other tests, doing what MODE says; its answer comes on the pipe *OUT_R */
static BOOL start_helper(const char *mode, PROCESS_INFORMATION *pi, HANDLE *out_r)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE out_w;
    STARTUPINFOA si;
    char path[MAX_PATH], cmd[MAX_PATH + 32];

    if (!CreatePipe(out_r, &out_w, &sa, 0))
        return FALSE;
    SetHandleInformation(*out_r, HANDLE_FLAG_INHERIT, 0);
    GetModuleFileNameA(NULL, path, sizeof(path));
    sprintf(cmd, "\"%s\" NtlmLocalCall", path);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    SetEnvironmentVariableA(CHILD_VAR, mode);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi))
    {
        SetEnvironmentVariableA(CHILD_VAR, NULL);
        CloseHandle(*out_r);
        CloseHandle(out_w);
        return FALSE;
    }
    SetEnvironmentVariableA(CHILD_VAR, NULL);
    CloseHandle(out_w);
    return TRUE;
}

/* what the helper says until the line that starts with PREFIX (any line when NULL) or its end */
static void read_helper(HANDLE out_r, char *out, DWORD out_size, const char *prefix)
{
    DWORD got, total = 0;
    char *p;

    out[0] = 0;
    while (total + 1 < out_size && ReadFile(out_r, out + total, out_size - 1 - total, &got, NULL) && got)
    {
        total += got;
        out[total] = 0;
        if (prefix && (p = strstr(out, prefix)) && strchr(p, '\n'))
            break;
    }
}

/* the helper's exit code once it ended */
static DWORD finish_helper(PROCESS_INFORMATION *pi, HANDLE out_r)
{
    DWORD code = 0xdead;

    WaitForSingleObject(pi->hProcess, 60000);
    GetExitCodeProcess(pi->hProcess, &code);
    CloseHandle(out_r);
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);
    return code;
}

/* a helper from its start to its end; its answer in OUT */
static DWORD run_helper(const char *mode, DWORD *pid, char *out, DWORD out_size)
{
    PROCESS_INFORMATION pi;
    HANDLE out_r;

    out[0] = 0;
    if (pid) *pid = 0;
    if (!start_helper(mode, &pi, &out_r))
        return 0xdead;
    if (pid) *pid = pi.dwProcessId;
    read_helper(out_r, out, out_size, NULL);
    return finish_helper(&pi, out_r);
}

static const BYTE helper_challenge[8] = { 2, 7, 1, 8, 2, 8, 1, 8 };

/* issue up to MAX contexts; how many the LSA gave */
static ULONG fill_table(ULONG max, ULONG64 *ids)
{
    ULONG64 context;
    ULONG n;

    for (n = 0; n < max; n++)
    {
        if (lsa_issue(helper_challenge, &context))
            break;
        if (ids) ids[n] = context;
    }
    return n;
}

/* the helpers: "issue" issues a context, says its id and exits; "accept <id>" tries to accept that context;
 * "fill <n>" issues up to n contexts, says how many and exits; "fillwait <n> <event>" does the same, then waits
 * for the event before it exits */
static BOOL helper_main(const char *mode)
{
    ULONG64 context = 0;
    HANDLE token = NULL, event;
    char name[64];
    ULONG max;
    NTSTATUS st;

    if (sscanf(mode, "fill %lu", &max) == 1)
    {
        printf("LOCALHELPER filled=%lu\n", fill_table(max, NULL));
        return TRUE;
    }
    if (sscanf(mode, "fillwait %lu %63s", &max, name) == 2)
    {
        printf("LOCALHELPER filled=%lu\n", fill_table(max, NULL));
        fflush(stdout);
        event = OpenEventA(SYNCHRONIZE, FALSE, name);
        if (event)
        {
            WaitForSingleObject(event, 120000);
            CloseHandle(event);
        }
        return TRUE;
    }

    if (!strcmp(mode, "issue"))
    {
        st = lsa_issue(helper_challenge, &context);
        printf("LOCALHELPER issue=%08lx id=%08lx%08lx\n", (unsigned long)st, (unsigned long)(context >> 32),
               (unsigned long)context);
        return TRUE;
    }
    if (!strncmp(mode, "accept ", 7))
    {
        context = _strtoui64(mode + 7, NULL, 16);
        st = lsa_accept(context, &token, NULL);
        printf("LOCALHELPER accept=%08lx\n", (unsigned long)st);
        if (token) CloseHandle(token);
        return TRUE;
    }
    return FALSE;
}

static ULONG helper_filled(const char *out)
{
    const char *p = strstr(out, "LOCALHELPER filled=");
    unsigned long n = 0xffffffff;

    if (p) sscanf(p, "LOCALHELPER filled=%lu", &n);
    return n;
}

static void lsa_delete(ULONG64 context)
{
    MSV1_0_ROS_NTLM_LOCAL_CONTEXT req = { MsV1_0RosNtlmLocalDelete };

    req.ContextId = context;
    msv_call(&req, sizeof(req), NULL, 0);
}

/* The table of the LSA is bounded, but nobody can keep it full for others: the contexts of a process that exited
 * go at the next message, a process holds at most 1024 and all the processes of a user together at most 2048 */
static void test_table_limits(void)
{
    static ULONG64 mine[1100];
    PROCESS_INFORMATION pi;
    HANDLE out_r, event, token = NULL;
    char out[256], name[64], mode[96];
    ULONG64 context;
    ULONG n, i;

    /* processes that filled the table and exited: their contexts are gone, an exchange works */
    for (i = 0; i < 5; i++)
    {
        run_helper("fill 1024", NULL, out, sizeof(out));
        ok(helper_filled(out) == 1024, "helper %lu issued %lu contexts\n", i, helper_filled(out));
    }
    ok_ntstatus(lsa_issue(helper_challenge, &context), STATUS_SUCCESS);
    ok_ntstatus(lsa_bind(context, helper_challenge, NULL), STATUS_SUCCESS);
    ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_SUCCESS);
    if (token) CloseHandle(token);
    token = NULL;
    test_local_exchange(ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY,
                        SecurityImpersonation, NULL, "after full helpers");

    /* a context of an issuer that exited is gone: a client cannot bind it any more */
    run_helper("issue", NULL, out, sizeof(out));
    {
        unsigned long issue = 1, hi = 0, lo = 0;
        char *p = strstr(out, "LOCALHELPER issue=");

        ok(p && sscanf(p, "LOCALHELPER issue=%lx id=%8lx%8lx", &issue, &hi, &lo) == 3 && issue == 0,
           "no context from the helper: %s\n", out);
        if (p && !issue)
            ok_ntstatus(lsa_bind(((ULONG64)hi << 32) | lo, helper_challenge, NULL), STATUS_NOT_FOUND);
    }

    /* per process */
    n = fill_table(ARRAYSIZE(mine), mine);
    ok(n == 1024, "this process issued %lu contexts\n", n);

    /* per user: this process and a live helper of the same user */
    sprintf(name, "ntlmlocalcall_%lu", GetCurrentProcessId());
    event = CreateEventA(NULL, TRUE, FALSE, name);
    sprintf(mode, "fillwait 1024 %s", name);
    if (event && start_helper(mode, &pi, &out_r))
    {
        read_helper(out_r, out, sizeof(out), "LOCALHELPER filled=");
        ok(helper_filled(out) == 1024, "the live helper issued %lu contexts\n", helper_filled(out));
        run_helper("fill 16", NULL, out, sizeof(out));
        ok(helper_filled(out) == 0, "a third process of the user issued %lu contexts\n", helper_filled(out));
        SetEvent(event);
        finish_helper(&pi, out_r);
        /* the live helper is gone: room again */
        run_helper("fill 16", NULL, out, sizeof(out));
        ok(helper_filled(out) == 16, "after the helper exited a process issued %lu contexts\n", helper_filled(out));
    }
    else
        skip("no live helper %lu\n", GetLastError());
    if (event) CloseHandle(event);

    for (i = 0; i < n; i++)
        lsa_delete(mine[i]);
    ok_ntstatus(lsa_issue(helper_challenge, &context), STATUS_SUCCESS);
    lsa_delete(context);
}

/* The issuer of a context is a process, not a process id: a process that is given the id of an issuer that exited
 * (on ReactOS at once, in the same tick of the clock as the issuer, so with the same creation time) gets nothing */
static void test_reused_process_id(void)
{
    char out[256], mode[64], *p;
    unsigned long issue = 1, hi = 0, lo = 0, acc;
    DWORD issuer = 0, pid, i, reused = 0;
    ULONG64 context;

    run_helper("issue", &issuer, out, sizeof(out));
    p = strstr(out, "LOCALHELPER issue=");
    ok(p && sscanf(p, "LOCALHELPER issue=%lx id=%8lx%8lx", &issue, &hi, &lo) == 3, "no id from the issuer: %s\n", out);
    ok(issue == 0, "the issuer's issue failed %08lx\n", issue);
    context = ((ULONG64)hi << 32) | lo;
    if (issue || !context)
        return;

    /* a client on this machine answers the CHALLENGE (the issuer is gone: the context may be gone with it) */
    lsa_bind(context, helper_challenge, NULL);

    sprintf(mode, "accept %08lx%08lx", hi, lo);
    for (i = 0; i < 30; i++)
    {
        acc = run_helper(mode, &pid, out, sizeof(out));
        p = strstr(out, "LOCALHELPER accept=");
        ok(p && sscanf(p, "LOCALHELPER accept=%lx", &acc) == 1, "no answer from helper %lu: %s\n", i, out);
        ok(acc == (unsigned long)STATUS_NOT_FOUND, "helper %lu (pid %lu, issuer pid %lu) accepted: 0x%08lx\n", i, pid,
           issuer, acc);
        if (pid == issuer)
            reused++;
    }
    trace("issuer pid %lu reused by %lu of 30 helpers\n", issuer, reused);
}

/* the child: issues a context, says its id, waits, then tries to accept it */
static void child_main(void)
{
    static const BYTE challenge[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    ULONG64 context = 0;
    HANDLE token = NULL;
    TOKEN_STATISTICS stats;
    char line[64];
    NTSTATUS st;

    st = lsa_issue(challenge, &context);
    printf("LOCALCHILD issue=%08lx id=%08lx%08lx\n", (unsigned long)st, (unsigned long)(context >> 32), (unsigned long)context);
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return;
    st = lsa_accept(context, &token, NULL);
    memset(&stats, 0, sizeof(stats));
    if (token) token_stats(token, &stats);
    printf("LOCALCHILD accept=%08lx logon=%08lx:%08lx\n", (unsigned long)st, stats.AuthenticationId.HighPart,
           stats.AuthenticationId.LowPart);
    fflush(stdout);
    if (token) CloseHandle(token);
}

/* A context of another process: this one can bind it (it is the client) but not accept it; the issuer can */
static void test_other_process(void)
{
    static const BYTE challenge[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE out_r, out_w, in_r, in_w, token = NULL, me;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char path[MAX_PATH], cmd[MAX_PATH + 32], buf[1024], *p;
    DWORD got, total = 0, wrote;
    unsigned long issue = 1, hi = 0, lo = 0, acc = 1, lh = 0, ll = 0;
    ULONG64 context;
    TOKEN_STATISTICS mine;

    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&in_r, &in_w, &sa, 0))
    {
        skip("CreatePipe failed\n");
        return;
    }
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    GetModuleFileNameA(NULL, path, sizeof(path));
    sprintf(cmd, "\"%s\" NtlmLocalCall", path);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_r;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    SetEnvironmentVariableA(CHILD_VAR, "1");
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        SetEnvironmentVariableA(CHILD_VAR, NULL);
        skip("CreateProcess failed %lu\n", GetLastError());
        return;
    }
    SetEnvironmentVariableA(CHILD_VAR, NULL);
    CloseHandle(out_w);
    CloseHandle(in_r);

    /* the id */
    while (total < sizeof(buf) - 1 && ReadFile(out_r, buf + total, sizeof(buf) - 1 - total, &got, NULL) && got)
    {
        total += got;
        buf[total] = 0;
        if ((p = strstr(buf, "LOCALCHILD issue=")) && strchr(p, '\n')) break;
    }
    buf[total] = 0;
    p = strstr(buf, "LOCALCHILD issue=");
    ok(p && sscanf(p, "LOCALCHILD issue=%lx id=%8lx%8lx", &issue, &hi, &lo) == 3, "no id from the child: %s\n", buf);
    ok(issue == 0, "the child's issue failed %08lx\n", issue);
    context = ((ULONG64)hi << 32) | lo;

    if (!issue && context)
    {
        /* this process binds its logon to the child's context, and cannot accept it */
        ok_ntstatus(lsa_bind(context, challenge, NULL), STATUS_SUCCESS);
        ok_ntstatus(lsa_accept(context, &token, NULL), STATUS_NOT_FOUND);
        if (token) CloseHandle(token);
    }
    WriteFile(in_w, "go\n", 3, &wrote, NULL);
    total = 0;
    while (total < sizeof(buf) - 1 && ReadFile(out_r, buf + total, sizeof(buf) - 1 - total, &got, NULL) && got)
        total += got;
    buf[total] = 0;
    WaitForSingleObject(pi.hProcess, 30000);
    p = strstr(buf, "LOCALCHILD accept=");
    ok(p && sscanf(p, "LOCALCHILD accept=%lx logon=%lx:%lx", &acc, &lh, &ll) == 3, "no answer from the child: %s\n", buf);
    /* the issuer gets this process's logon */
    ok(acc == 0, "the child's accept failed %08lx\n", acc);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &me))
    {
        if (token_stats(me, &mine))
            ok(lh == (unsigned long)mine.AuthenticationId.HighPart && ll == mine.AuthenticationId.LowPart,
               "the child got logon %08lx:%08lx instead of %08lx:%08lx\n", lh, ll, mine.AuthenticationId.HighPart,
               mine.AuthenticationId.LowPart);
        CloseHandle(me);
    }
    CloseHandle(out_r);
    CloseHandle(in_w);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

/* A client thread that impersonates another user: the server gets that user's logon, not the process's */
static void test_other_user(void)
{
    WCHAR user[32];
    USER_INFO_1 ui;
    DWORD err;
    HANDLE logon = NULL, imp = NULL;

    _snwprintf(user, ARRAYSIZE(user), L"localcall%lu", GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = user;
    ui.usri1_password = (LPWSTR)L"Ntlm#Local1pw";
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    if (NetUserAdd(NULL, 1, (LPBYTE)&ui, &err) != NERR_Success)
    {
        skip("NetUserAdd failed\n");
        return;
    }
    if (LogonUserW(user, L".", L"Ntlm#Local1pw", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &logon) &&
        DuplicateTokenEx(logon, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &imp))
        test_local_exchange(ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY,
                            SecurityImpersonation, imp, "another user");
    else
        skip("LogonUser failed %lu\n", GetLastError());
    if (imp) CloseHandle(imp);
    if (logon) CloseHandle(logon);
    NetUserDel(NULL, user);
}

START_TEST(NtlmLocalCall)
{
    char mode[64];

    if (GetEnvironmentVariableA(CHILD_VAR, mode, sizeof(mode)))
    {
        if (!helper_main(mode))
            child_main();
        return;
    }

    test_local_exchange(ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY,
                        SecurityImpersonation, NULL, "default");
    test_local_exchange(ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_IDENTIFY, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY,
                        SecurityIdentification, NULL, "identify");
    test_local_exchange(ISC_REQ_CONNECTION | ISC_REQ_DELEGATE, ASC_REQ_CONNECTION, SecurityImpersonation, NULL, "delegate");
    test_local_exchange(ISC_REQ_CONNECTION | ISC_REQ_CONFIDENTIALITY, ASC_REQ_CONNECTION | ASC_REQ_CONFIDENTIALITY,
                        SecurityImpersonation, NULL, "confidentiality");
    test_explicit_identity();
    test_unbound_context();
    test_other_names();
    test_altered_context();
    test_lsa_table();
    test_unusable_thread_token();
    test_other_process();
    test_reused_process_id();
    test_table_limits();
    test_other_user();
}
