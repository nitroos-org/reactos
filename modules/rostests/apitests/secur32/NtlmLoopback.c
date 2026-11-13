/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The NTLM package of secur32 without an external helper: a client and a server context of this process
 *              exchange the three messages for a local account, the server checks the response through the local
 *              security authority (a network logon), gets the token of the client, impersonates it, and both sides
 *              sign and seal. A wrong password, an unknown user, an altered message and a replayed message are refused.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <string.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <winreg.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define TEST_PASSWORD L"Ntlm#Test1pw"

static WCHAR g_user[32];
static const WCHAR *g_expect_user;   /* the account test_exchange expects (g_user unless set) */

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"ntlmtest%lu", GetCurrentProcessId() % 100000);
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

static void delete_user(void)
{
    NetUserDel(NULL, g_user);
}

static void make_identity(SEC_WINNT_AUTH_IDENTITY_W *id, const WCHAR *user, const WCHAR *domain, const WCHAR *password)
{
    memset(id, 0, sizeof(*id));
    id->User = (unsigned short *)user;
    id->UserLength = (ULONG)wcslen(user);
    id->Domain = (unsigned short *)domain;
    id->DomainLength = (ULONG)wcslen(domain);
    id->Password = (unsigned short *)password;
    id->PasswordLength = (ULONG)wcslen(password);
    id->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
}

typedef struct
{
    BYTE neg[512], chal[1024], auth[2048];
    ULONG neg_len, chal_len, auth_len;
} messages;

/* drive the exchange; the hook may change the AUTHENTICATE message. Returns the status of the server's second call. */
static SECURITY_STATUS handshake(CredHandle *cc, CredHandle *sc, ULONG creq, ULONG sreq, CtxtHandle *cctx, CtxtHandle *sctx,
                                 SECURITY_STATUS *client_status, messages *m, void (*hook)(messages *))
{
    SecBufferDesc od, id;
    SecBuffer ob, ib;
    TimeStamp ts;
    ULONG attr;
    SECURITY_STATUS st, sst;

    od.ulVersion = id.ulVersion = SECBUFFER_VERSION;
    od.cBuffers = id.cBuffers = 1;
    od.pBuffers = &ob;
    id.pBuffers = &ib;

    /* NEGOTIATE */
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = m->neg; ob.cbBuffer = sizeof(m->neg);
    st = InitializeSecurityContextW(cc, NULL, (SEC_WCHAR *)L"host", creq, 0, SECURITY_NETWORK_DREP, NULL, 0,
                                    cctx, &od, &attr, &ts);
    ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
    if (st != SEC_I_CONTINUE_NEEDED) { *client_status = st; return st; }
    m->neg_len = ob.cbBuffer;

    /* CHALLENGE */
    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = m->neg; ib.cbBuffer = m->neg_len;
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = m->chal; ob.cbBuffer = sizeof(m->chal);
    sst = AcceptSecurityContext(sc, NULL, &id, sreq, SECURITY_NETWORK_DREP, sctx, &od, &attr, &ts);
    ok_eq_hex(sst, SEC_I_CONTINUE_NEEDED);
    if (sst != SEC_I_CONTINUE_NEEDED) return sst;
    m->chal_len = ob.cbBuffer;

    /* AUTHENTICATE */
    ib.pvBuffer = m->chal; ib.cbBuffer = m->chal_len;
    ob.pvBuffer = m->auth; ob.cbBuffer = sizeof(m->auth);
    st = InitializeSecurityContextW(cc, cctx, (SEC_WCHAR *)L"host", creq, 0, SECURITY_NETWORK_DREP, &id, 0,
                                    cctx, &od, &attr, &ts);
    *client_status = st;
    if (st != SEC_E_OK) return st;
    m->auth_len = ob.cbBuffer;
    if (hook) hook(m);

    ib.pvBuffer = m->auth; ib.cbBuffer = m->auth_len;
    ob.pvBuffer = m->chal; ob.cbBuffer = sizeof(m->chal);
    sst = AcceptSecurityContext(sc, sctx, &id, sreq, SECURITY_NETWORK_DREP, sctx, &od, &attr, &ts);
    return sst;
}

static void tamper_mic(messages *m)
{
    /* the MIC is at offset 72 of the message */
    m->auth[72] ^= 1;
}

static void tamper_response(messages *m)
{
    /* the NT response: its first byte is the proof; the field is at offset 20 (length, max, offset) */
    ULONG off = m->auth[24] | (m->auth[25] << 8) | (m->auth[26] << 16) | ((ULONG)m->auth[27] << 24);

    m->auth[off] ^= 1;
}

static void check_signature(CtxtHandle *a, CtxtHandle *b, const char *what)
{
    BYTE data[40], sig[16];
    SecBuffer bufs[2];
    SecBufferDesc desc;
    SECURITY_STATUS st;
    int i;

    for (i = 0; i < 3; i++)
    {
        memset(data, 'A' + i, sizeof(data));
        desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 2; desc.pBuffers = bufs;
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = data; bufs[0].cbBuffer = sizeof(data);
        bufs[1].BufferType = SECBUFFER_TOKEN; bufs[1].pvBuffer = sig; bufs[1].cbBuffer = sizeof(sig);
        st = MakeSignature(a, 0, &desc, 0);
        ok(st == SEC_E_OK, "%s: MakeSignature %d: 0x%08lx\n", what, i, (unsigned long)st);
        st = VerifySignature(b, &desc, 0, NULL);
        ok(st == SEC_E_OK, "%s: VerifySignature %d: 0x%08lx\n", what, i, (unsigned long)st);
    }

    /* altered data */
    memset(data, 'Z', sizeof(data));
    desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 2; desc.pBuffers = bufs;
    bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = data; bufs[0].cbBuffer = sizeof(data);
    bufs[1].BufferType = SECBUFFER_TOKEN; bufs[1].pvBuffer = sig; bufs[1].cbBuffer = sizeof(sig);
    st = MakeSignature(a, 0, &desc, 0);
    ok(st == SEC_E_OK, "%s: MakeSignature: 0x%08lx\n", what, (unsigned long)st);
    data[3] ^= 0x20;
    st = VerifySignature(b, &desc, 0, NULL);
    ok(st == SEC_E_MESSAGE_ALTERED, "%s: VerifySignature of altered data: 0x%08lx\n", what, (unsigned long)st);
}

static void check_seal(CtxtHandle *a, CtxtHandle *b, const char *what)
{
    BYTE data[100], plain[100], sig[16];
    SecBuffer bufs[2];
    SecBufferDesc desc;
    SECURITY_STATUS st;
    int i;

    for (i = 0; i < 3; i++)
    {
        memset(data, 'a' + i, sizeof(data));
        memcpy(plain, data, sizeof(data));
        desc.ulVersion = SECBUFFER_VERSION; desc.cBuffers = 2; desc.pBuffers = bufs;
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = data; bufs[0].cbBuffer = sizeof(data);
        bufs[1].BufferType = SECBUFFER_TOKEN; bufs[1].pvBuffer = sig; bufs[1].cbBuffer = sizeof(sig);
        st = EncryptMessage(a, 0, &desc, 0);
        ok(st == SEC_E_OK, "%s: EncryptMessage %d: 0x%08lx\n", what, i, (unsigned long)st);
        ok(memcmp(data, plain, sizeof(data)) != 0, "%s: the data was not encrypted\n", what);
        st = DecryptMessage(b, &desc, 0, NULL);
        ok(st == SEC_E_OK, "%s: DecryptMessage %d: 0x%08lx\n", what, i, (unsigned long)st);
        ok(memcmp(data, plain, sizeof(data)) == 0, "%s: the data was not restored\n", what);
    }
}

static void test_exchange(CredHandle *cc, CredHandle *sc, ULONG creq, ULONG sreq, BOOL sign, BOOL seal)
{
    CtxtHandle cctx, sctx;
    SECURITY_STATUS cst, sst;
    SecPkgContext_Names names;
    SecPkgContext_Sizes sizes;
    SecPkgContext_SessionKey key;
    SecPkgContext_Flags flags;
    messages *m = calloc(1, sizeof(*m));
    HANDLE token = NULL;
    WCHAR before[64], during[64], after[64];
    DWORD n;
    const WCHAR *bs;

    sst = handshake(cc, sc, creq, sreq, &cctx, &sctx, &cst, m, NULL);
    ok_eq_hex(cst, SEC_E_OK);
    ok_eq_hex(sst, SEC_E_OK);
    if (cst != SEC_E_OK || sst != SEC_E_OK) { free(m); return; }

    /* the message sizes and the flags of the finished contexts */
    memset(&sizes, 0, sizeof(sizes));
    cst = QueryContextAttributesW(&sctx, SECPKG_ATTR_SIZES, &sizes);
    ok_eq_hex(cst, SEC_E_OK);
    ok_eq_ulong(sizes.cbMaxSignature, 16);
    ok_eq_ulong(sizes.cbSecurityTrailer, 16);
    memset(&flags, 0, sizeof(flags));
    cst = QueryContextAttributesW(&sctx, SECPKG_ATTR_FLAGS, &flags);
    ok_eq_hex(cst, SEC_E_OK);
    ok_eq_bool(!!(flags.Flags & ISC_RET_INTEGRITY), sign);
    ok_eq_bool(!!(flags.Flags & ISC_RET_CONFIDENTIALITY), seal);

    /* the server knows the client by name */
    names.sUserName = NULL;
    sst = QueryContextAttributesW(&sctx, SECPKG_ATTR_NAMES, &names);
    ok_eq_hex(sst, SEC_E_OK);
    if (sst == SEC_E_OK)
    {
        bs = wcsrchr((WCHAR *)names.sUserName, L'\\');
        ok(bs && !_wcsicmp(bs + 1, g_expect_user ? g_expect_user : g_user), "the name is %ls\n", names.sUserName);
        FreeContextBuffer(names.sUserName);
    }

    /* both sides have the same session key */
    key.SessionKey = NULL;
    sst = QueryContextAttributesW(&sctx, SECPKG_ATTR_SESSION_KEY, &key);
    ok_eq_hex(sst, SEC_E_OK);
    if (sst == SEC_E_OK)
    {
        SecPkgContext_SessionKey ckey;

        ok_eq_ulong(key.SessionKeyLength, 16);
        ckey.SessionKey = NULL;
        cst = QueryContextAttributesW(&cctx, SECPKG_ATTR_SESSION_KEY, &ckey);
        ok_eq_hex(cst, SEC_E_OK);
        if (cst == SEC_E_OK)
        {
            ok(ckey.SessionKeyLength == key.SessionKeyLength && !memcmp(ckey.SessionKey, key.SessionKey, 16),
               "the session keys differ\n");
            FreeContextBuffer(ckey.SessionKey);
        }
        FreeContextBuffer(key.SessionKey);
    }

    /* the token of the client */
    sst = QuerySecurityContextToken(&sctx, &token);
    ok_eq_hex(sst, SEC_E_OK);
    if (sst == SEC_E_OK)
    {
        TOKEN_TYPE type = 0;
        DWORD len;

        ok(GetTokenInformation(token, TokenType, &type, sizeof(type), &len), "GetTokenInformation failed\n");
        ok_eq_int(type, TokenImpersonation);
        CloseHandle(token);
    }

    /* the client side has none */
    token = NULL;
    cst = QuerySecurityContextToken(&cctx, &token);
    ok(cst != SEC_E_OK, "the client context gave a token\n");

    /* impersonation: the thread runs as the user until it reverts */
    n = ARRAYSIZE(before); GetUserNameW(before, &n);
    sst = ImpersonateSecurityContext(&sctx);
    ok_eq_hex(sst, SEC_E_OK);
    if (sst == SEC_E_OK)
    {
        n = ARRAYSIZE(during); ok(GetUserNameW(during, &n), "GetUserNameW failed %lu\n", GetLastError());
        ok(!_wcsicmp(during, g_expect_user ? g_expect_user : g_user), "impersonating %ls instead of %ls\n", during,
           g_expect_user ? g_expect_user : g_user);
        sst = RevertSecurityContext(&sctx);
        ok_eq_hex(sst, SEC_E_OK);
        n = ARRAYSIZE(after); GetUserNameW(after, &n);
        ok(!wcscmp(before, after), "%ls after the revert instead of %ls\n", after, before);
    }
    /* a client context cannot impersonate */
    cst = ImpersonateSecurityContext(&cctx);
    ok(cst != SEC_E_OK, "a client context impersonated\n");

    if (sign)
    {
        check_signature(&cctx, &sctx, "client to server");
        check_signature(&sctx, &cctx, "server to client");
    }
    if (seal)
    {
        check_seal(&cctx, &sctx, "client to server");
        check_seal(&sctx, &cctx, "server to client");
    }

    DeleteSecurityContext(&cctx);
    DeleteSecurityContext(&sctx);
    free(m);
}

static void test_refusals(CredHandle *sc, const WCHAR *user, const WCHAR *domain, const WCHAR *password,
                          void (*hook)(messages *), SECURITY_STATUS expected, const char *what)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    CredHandle cc;
    CtxtHandle cctx, sctx;
    SECURITY_STATUS st, cst, sst;
    TimeStamp ts;
    messages *m = calloc(1, sizeof(*m));

    make_identity(&id, user, domain, password);
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &cc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st == SEC_E_OK)
    {
        sst = handshake(&cc, sc, ISC_REQ_INTEGRITY, ASC_REQ_INTEGRITY, &cctx, &sctx, &cst, m, hook);
        ok(sst == expected, "%s: the server answered 0x%08lx instead of 0x%08lx\n", what, (unsigned long)sst,
           (unsigned long)expected);
        FreeCredentialsHandle(&cc);
        if (sst == SEC_E_OK) DeleteSecurityContext(&sctx);
        DeleteSecurityContext(&cctx);
    }
    free(m);
}

#define LSA_KEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define LIMIT_VALUE L"LimitBlankPasswordUse"

/* set (or with value == -1 remove) Lsa\LimitBlankPasswordUse, return the previous state through had and old */
static BOOL set_limit_blank(LONG value, BOOL *had, DWORD *old)
{
    HKEY key;
    DWORD type, size = sizeof(*old);
    LONG err;

    err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (err != ERROR_SUCCESS)
        return FALSE;
    if (had)
    {
        *old = 0;
        *had = (RegQueryValueExW(key, LIMIT_VALUE, NULL, &type, (LPBYTE)old, &size) == ERROR_SUCCESS && type == REG_DWORD);
    }
    if (value < 0)
        err = RegDeleteValueW(key, LIMIT_VALUE);
    else
    {
        DWORD v = (DWORD)value;
        err = RegSetValueExW(key, LIMIT_VALUE, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    }
    RegCloseKey(key);
    return err == ERROR_SUCCESS || (value < 0 && err == ERROR_FILE_NOT_FOUND);
}

/* an account with a blank password: a network logon is refused unless LimitBlankPasswordUse is 0, an interactive one is not */
static void test_blank_password(CredHandle *sc)
{
    WCHAR blank[32];
    USER_INFO_1 ui;
    DWORD err, old;
    BOOL had;
    HANDLE token;
    NET_API_STATUS ns;

    _snwprintf(blank, ARRAYSIZE(blank), L"ntlmblank%lu", GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = blank;
    ui.usri1_password = (LPWSTR)L"";
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    ns = NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);
    if (ns != NERR_Success)
    {
        skip("NetUserAdd (blank password) failed (%lu)\n", (unsigned long)ns);
        return;
    }
    if (!set_limit_blank(-1, &had, &old))
    {
        skip("cannot write the Lsa key\n");
        NetUserDel(NULL, blank);
        return;
    }

    /* the default (value absent): refused */
    test_refusals(sc, blank, L".", L"", NULL, SEC_E_LOGON_DENIED, "blank password, policy default");
    /* value 1: refused */
    ok(set_limit_blank(1, NULL, NULL), "cannot set the value\n");
    test_refusals(sc, blank, L".", L"", NULL, SEC_E_LOGON_DENIED, "blank password, LimitBlankPasswordUse=1");
    /* a wrong (non empty) password for the blank account stays refused with the policy off */
    ok(set_limit_blank(0, NULL, NULL), "cannot set the value\n");
    test_refusals(sc, blank, L".", L"x", NULL, SEC_E_LOGON_DENIED, "blank account, wrong password, policy off");
    /* value 0: accepted, with the full exchange (signing) */
    {
        SEC_WINNT_AUTH_IDENTITY_W id;
        CredHandle cc;
        TimeStamp ts;

        make_identity(&id, blank, L".", L"");
        ok_eq_hex(AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &cc, &ts),
                  SEC_E_OK);
        g_expect_user = blank;
        test_exchange(&cc, sc, ISC_REQ_INTEGRITY, ASC_REQ_INTEGRITY, TRUE, FALSE);
        g_expect_user = NULL;
        FreeCredentialsHandle(&cc);
    }
    /* the interactive logon of the account does not depend on the value */
    ok(set_limit_blank(1, NULL, NULL), "cannot set the value\n");
    token = NULL;
    ok(LogonUserW(blank, L".", L"", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token),
       "interactive logon of the blank account failed (%lu)\n", GetLastError());
    if (token) CloseHandle(token);

    /* the account with a password is not affected by the policy */
    test_refusals(sc, g_user, L".", TEST_PASSWORD, NULL, SEC_E_OK, "account with a password, policy on");

    /* restore */
    set_limit_blank(had ? (LONG)old : -1, NULL, NULL);
    NetUserDel(NULL, blank);
}

static void test_replay(CredHandle *cc, CredHandle *sc)
{
    CtxtHandle cctx, sctx, sctx2;
    SECURITY_STATUS cst, sst, st;
    messages *m = calloc(1, sizeof(*m));
    SecBufferDesc od, id;
    SecBuffer ob, ib;
    TimeStamp ts;
    ULONG attr;

    sst = handshake(cc, sc, ISC_REQ_INTEGRITY, ASC_REQ_INTEGRITY, &cctx, &sctx, &cst, m, NULL);
    ok_eq_hex(sst, SEC_E_OK);

    /* a second server context gets its own challenge: the first AUTHENTICATE does not fit it */
    od.ulVersion = id.ulVersion = SECBUFFER_VERSION;
    od.cBuffers = id.cBuffers = 1;
    od.pBuffers = &ob;
    id.pBuffers = &ib;
    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = m->neg; ib.cbBuffer = m->neg_len;
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = m->chal; ob.cbBuffer = sizeof(m->chal);
    st = AcceptSecurityContext(sc, NULL, &id, ASC_REQ_INTEGRITY, SECURITY_NETWORK_DREP, &sctx2, &od, &attr, &ts);
    ok_eq_hex(st, SEC_I_CONTINUE_NEEDED);
    if (st == SEC_I_CONTINUE_NEEDED)
    {
        ib.pvBuffer = m->auth; ib.cbBuffer = m->auth_len;
        ob.pvBuffer = m->chal; ob.cbBuffer = sizeof(m->chal);
        st = AcceptSecurityContext(sc, &sctx2, &id, ASC_REQ_INTEGRITY, SECURITY_NETWORK_DREP, &sctx2, &od, &attr, &ts);
        ok(st != SEC_E_OK, "a replayed AUTHENTICATE message was accepted\n");
        DeleteSecurityContext(&sctx2);
    }
    DeleteSecurityContext(&cctx);
    if (sst == SEC_E_OK) DeleteSecurityContext(&sctx);
    free(m);
}

/* credentials without an identity: the logged on user of the process, answered by the local security authority */
static void test_default_credentials(CredHandle *sc)
{
    CredHandle cc;
    CtxtHandle cctx, sctx;
    SECURITY_STATUS st, cst, sst;
    TimeStamp ts;
    messages *m = calloc(1, sizeof(*m));
    SecPkgContext_Names names;
    WCHAR me[64];
    DWORD n = ARRAYSIZE(me);

    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &cc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) { free(m); return; }

    sst = handshake(&cc, sc, ISC_REQ_INTEGRITY, ASC_REQ_INTEGRITY, &cctx, &sctx, &cst, m, NULL);
    if (cst == SEC_E_NO_CREDENTIALS)
    {
        skip("no credentials of the logon of this process\n");
    }
    else
    {
        ok_eq_hex(cst, SEC_E_OK);
        ok_eq_hex(sst, SEC_E_OK);
        if (sst == SEC_E_OK)
        {
            GetUserNameW(me, &n);
            names.sUserName = NULL;
            st = QueryContextAttributesW(&sctx, SECPKG_ATTR_NAMES, &names);
            ok_eq_hex(st, SEC_E_OK);
            if (st == SEC_E_OK)
            {
                const WCHAR *bs = wcsrchr((WCHAR *)names.sUserName, L'\\');

                ok(bs && !_wcsicmp(bs + 1, me), "the name is %ls for the user %ls\n", names.sUserName, me);
                FreeContextBuffer(names.sUserName);
            }
            check_signature(&cctx, &sctx, "default credentials");
            DeleteSecurityContext(&sctx);
        }
        DeleteSecurityContext(&cctx);
    }
    FreeCredentialsHandle(&cc);
    free(m);
}

START_TEST(NtlmLoopback)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    CredHandle cc, sc;
    TimeStamp ts;
    SECURITY_STATUS st;
    PSecPkgInfoW pkgs, ntlm = NULL;
    ULONG count, i;

    st = EnumerateSecurityPackagesW(&count, &pkgs);
    ok_eq_hex(st, SEC_E_OK);
    for (i = 0; st == SEC_E_OK && i < count; i++)
        if (!_wcsicmp(pkgs[i].Name, L"NTLM"))
            ntlm = &pkgs[i];
    ok(ntlm != NULL, "no NTLM package\n");
    if (!ntlm)
        return;
    ok_eq_int(ntlm->wRPCID, 10);   /* RPC_C_AUTHN_WINNT */
    ok(!!(ntlm->fCapabilities & SECPKG_FLAG_INTEGRITY), "no integrity\n");
    ok(!!(ntlm->fCapabilities & SECPKG_FLAG_PRIVACY), "no privacy\n");
    FreeContextBuffer(pkgs);

    if (!create_user())
        return;

    make_identity(&id, g_user, L".", TEST_PASSWORD);
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &cc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &sc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) { delete_user(); return; }

    /* no signing requested, signing, sealing */
    test_exchange(&cc, &sc, 0, 0, FALSE, FALSE);
    test_exchange(&cc, &sc, ISC_REQ_INTEGRITY, ASC_REQ_INTEGRITY, TRUE, FALSE);
    test_exchange(&cc, &sc, ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY, ASC_REQ_CONFIDENTIALITY | ASC_REQ_INTEGRITY,
                  TRUE, TRUE);

    test_replay(&cc, &sc);
    {
        /* the logged on user may have a blank password (the test machine's Administrator has): its default
           credentials are refused over the network unless the policy is off */
        BOOL had;
        DWORD old;
        BOOL changed = set_limit_blank(0, &had, &old);

        test_default_credentials(&sc);
        if (changed)
            set_limit_blank(had ? (LONG)old : -1, NULL, NULL);
    }
    test_blank_password(&sc);

    /* the account and the machine name as the domain, in other cases */
    test_refusals(&sc, g_user, L".", L"wrong password", NULL, SEC_E_LOGON_DENIED, "wrong password");
    test_refusals(&sc, L"nosuchuser_ntlm", L".", TEST_PASSWORD, NULL, SEC_E_LOGON_DENIED, "unknown user");
    test_refusals(&sc, g_user, L".", TEST_PASSWORD, tamper_mic, SEC_E_MESSAGE_ALTERED, "altered MIC");
    test_refusals(&sc, g_user, L".", TEST_PASSWORD, tamper_response, SEC_E_LOGON_DENIED, "altered response");

    FreeCredentialsHandle(&cc);
    FreeCredentialsHandle(&sc);

    /* inbound credentials cannot start a client context */
    {
        CtxtHandle ctx;
        BYTE buf[512];
        SecBuffer ob = { sizeof(buf), SECBUFFER_TOKEN, buf };
        SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
        ULONG attr;

        st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &sc, &ts);
        ok_eq_hex(st, SEC_E_OK);
        st = InitializeSecurityContextW(&sc, NULL, (SEC_WCHAR *)L"host", 0, 0, SECURITY_NETWORK_DREP, NULL, 0, &ctx, &od,
                                        &attr, &ts);
        ok(st != SEC_I_CONTINUE_NEEDED && st != SEC_E_OK, "inbound credentials started a client context (0x%08lx)\n",
           (unsigned long)st);
        FreeCredentialsHandle(&sc);
    }

    delete_user();
}
