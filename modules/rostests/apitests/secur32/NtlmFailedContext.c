/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A server context whose AUTHENTICATE failed is dead, as on Windows (measured on Windows Server 2022 with
 *              an SSPI-only probe, NTLM and Negotiate): no impersonation, no token, no names, no session key
 *              (SEC_E_INVALID_HANDLE), and another AUTHENTICATE, even a good one, gets SEC_E_OUT_OF_SEQUENCE. Cases: the
 *              MIC of the AUTHENTICATE altered (the logon itself succeeds before the MIC is checked), and a wrong
 *              password followed by the right one for the same CHALLENGE.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <lmaccess.h>
#include <lmerr.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define TEST_PASSWORD L"Failed#Test1pw"
#define MAXT 8192
#define AUTH_MIC_OFFSET 72

static WCHAR g_user[32];

/* the status of one call (evaluated once) */
#define ok_st(call, expect) do { SECURITY_STATUS st_ = (call); \
    ok(st_ == (expect), "%s: 0x%08lx, expected 0x%08lx\n", #call, (unsigned long)st_, (unsigned long)(expect)); } while (0)

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"failctx%lu", GetCurrentProcessId() % 100000);
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

static SECURITY_STATUS acquire(const WCHAR *pkg, const WCHAR *password, CredHandle *cred)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    TimeStamp ts;

    if (!password)
        return AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)pkg, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, cred, &ts);
    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)g_user; id.UserLength = (ULONG)wcslen(g_user);
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)password; id.PasswordLength = (ULONG)wcslen(password);
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    return AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)pkg, SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, cred, &ts);
}

static SECURITY_STATUS isc(CredHandle *cc, CtxtHandle *ctx, BOOL first, const BYTE *in, ULONG in_len, BYTE *out,
                           ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attr;
    TimeStamp ts;
    SECURITY_STATUS st;

    st = InitializeSecurityContextW(cc, first ? NULL : ctx, NULL, ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY, 0,
                                    SECURITY_NATIVE_DREP, in ? &id : NULL, 0, ctx, &od, &attr, &ts);
    *out_len = ob.cbBuffer;
    return st;
}

static SECURITY_STATUS asc(CredHandle *sc, CtxtHandle *ctx, BOOL first, const BYTE *in, ULONG in_len, BYTE *out,
                           ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attr;
    TimeStamp ts;
    SECURITY_STATUS st;

    st = AcceptSecurityContext(sc, first ? NULL : ctx, &id, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY,
                               SECURITY_NATIVE_DREP, ctx, &od, &attr, &ts);
    *out_len = ob.cbBuffer;
    return st;
}

static void check_dead(const WCHAR *pkg, const char *what, CredHandle *sc, CtxtHandle *s, const BYTE *good,
                       ULONG good_len)
{
    SecPkgContext_NamesW nm;
    SecPkgContext_SessionKey sk;
    SecPkgContext_AccessToken at;
    HANDLE token = NULL;
    BYTE out[MAXT];
    ULONG out_len;
    SECURITY_STATUS st;

    st = ImpersonateSecurityContext(s);
    ok(st == SEC_E_INVALID_HANDLE, "%ls %s: ImpersonateSecurityContext 0x%08lx\n", pkg, what, (unsigned long)st);
    if (st == SEC_E_OK) RevertSecurityContext(s);
    st = QuerySecurityContextToken(s, &token);
    ok(st == SEC_E_INVALID_HANDLE, "%ls %s: QuerySecurityContextToken 0x%08lx\n", pkg, what, (unsigned long)st);
    if (st == SEC_E_OK && token) CloseHandle(token);
    memset(&nm, 0, sizeof(nm));
    st = QueryContextAttributesW(s, SECPKG_ATTR_NAMES, &nm);
    ok(st == SEC_E_INVALID_HANDLE, "%ls %s: NAMES 0x%08lx\n", pkg, what, (unsigned long)st);
    if (st == SEC_E_OK) FreeContextBuffer(nm.sUserName);
    memset(&sk, 0, sizeof(sk));
    st = QueryContextAttributesW(s, SECPKG_ATTR_SESSION_KEY, &sk);
    ok(st == SEC_E_INVALID_HANDLE, "%ls %s: SESSION_KEY 0x%08lx\n", pkg, what, (unsigned long)st);
    if (st == SEC_E_OK) FreeContextBuffer(sk.SessionKey);
    memset(&at, 0, sizeof(at));
    st = QueryContextAttributesW(s, SECPKG_ATTR_ACCESS_TOKEN, &at);
    ok(st != SEC_E_OK, "%ls %s: ACCESS_TOKEN 0x%08lx\n", pkg, what, (unsigned long)st);
    st = asc(sc, s, FALSE, good, good_len, out, &out_len);
    ok(st == SEC_E_OUT_OF_SEQUENCE, "%ls %s: the good AUTHENTICATE afterwards 0x%08lx\n", pkg, what, (unsigned long)st);
    st = ImpersonateSecurityContext(s);
    ok(st == SEC_E_INVALID_HANDLE, "%ls %s: ImpersonateSecurityContext at the end 0x%08lx\n", pkg, what,
       (unsigned long)st);
    if (st == SEC_E_OK) RevertSecurityContext(s);
}

/* the MIC of the AUTHENTICATE altered: the logon succeeds, the MIC does not */
static void test_mic(const WCHAR *pkg)
{
    CredHandle cc, sc;
    CtxtHandle cctx, sctx;
    BYTE n[MAXT], c[MAXT], a[MAXT], bad[MAXT], out[MAXT];
    ULONG nl, cl, al, ol;
    SECURITY_STATUS st;

    ok_st(acquire(pkg, TEST_PASSWORD, &cc), SEC_E_OK);
    ok_st(acquire(pkg, NULL, &sc), SEC_E_OK);
    st = isc(&cc, &cctx, TRUE, NULL, 0, n, &nl);
    ok(st == SEC_I_CONTINUE_NEEDED && nl >= 8 && !memcmp(n, "NTLMSSP", 8), "%ls: NEGOTIATE 0x%08lx\n", pkg,
       (unsigned long)st);
    if (st != SEC_I_CONTINUE_NEEDED) goto done_c;
    st = asc(&sc, &sctx, TRUE, n, nl, c, &cl);
    ok_st(st, SEC_I_CONTINUE_NEEDED);
    if (st != SEC_I_CONTINUE_NEEDED) goto done_c;
    st = isc(&cc, &cctx, FALSE, c, cl, a, &al);
    ok_st(st, SEC_E_OK);
    ok(al > AUTH_MIC_OFFSET + 16, "%ls: AUTHENTICATE of %lu bytes\n", pkg, al);
    if (st != SEC_E_OK || al <= AUTH_MIC_OFFSET + 16) goto done_s;
    memcpy(bad, a, al);
    bad[AUTH_MIC_OFFSET] ^= 0x01;
    st = asc(&sc, &sctx, FALSE, bad, al, out, &ol);
    /* Windows: SEC_E_INVALID_TOKEN */
    ok(st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED, "%ls: AUTHENTICATE with an altered MIC 0x%08lx\n", pkg,
       (unsigned long)st);
    check_dead(pkg, "altered MIC", &sc, &sctx, a, al);
done_s:
    DeleteSecurityContext(&sctx);
done_c:
    DeleteSecurityContext(&cctx);
    FreeCredentialsHandle(&cc);
    FreeCredentialsHandle(&sc);
}

/* two clients answer the same CHALLENGE: a wrong password first, then the right one */
static void test_retry(const WCHAR *pkg)
{
    CredHandle good, wrong, sc;
    CtxtHandle cg, cw, sctx;
    BYTE n[MAXT], c[MAXT], ag[MAXT], aw[MAXT], out[MAXT];
    ULONG nl, cl, agl, awl, ol;
    SECURITY_STATUS st;

    ok_st(acquire(pkg, TEST_PASSWORD, &good), SEC_E_OK);
    ok_st(acquire(pkg, L"Wrong#Test1pw", &wrong), SEC_E_OK);
    ok_st(acquire(pkg, NULL, &sc), SEC_E_OK);
    ok_st(isc(&wrong, &cw, TRUE, NULL, 0, n, &nl), SEC_I_CONTINUE_NEEDED);
    ok_st(isc(&good, &cg, TRUE, NULL, 0, out, &ol), SEC_I_CONTINUE_NEEDED);
    st = asc(&sc, &sctx, TRUE, n, nl, c, &cl);
    ok_st(st, SEC_I_CONTINUE_NEEDED);
    if (st != SEC_I_CONTINUE_NEEDED) goto done;
    ok_st(isc(&wrong, &cw, FALSE, c, cl, aw, &awl), SEC_E_OK);
    ok_st(isc(&good, &cg, FALSE, c, cl, ag, &agl), SEC_E_OK);
    st = asc(&sc, &sctx, FALSE, aw, awl, out, &ol);
    ok(st == SEC_E_LOGON_DENIED, "%ls: wrong password 0x%08lx\n", pkg, (unsigned long)st);
    check_dead(pkg, "after a wrong password", &sc, &sctx, ag, agl);
    DeleteSecurityContext(&sctx);
done:
    DeleteSecurityContext(&cg);
    DeleteSecurityContext(&cw);
    FreeCredentialsHandle(&good);
    FreeCredentialsHandle(&wrong);
    FreeCredentialsHandle(&sc);
}

START_TEST(NtlmFailedContext)
{
    if (!create_user()) return;
    test_mic(L"NTLM");
    test_mic(L"Negotiate");
    test_retry(L"NTLM");
    test_retry(L"Negotiate");
    NetUserDel(NULL, g_user);
}
