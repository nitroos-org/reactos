/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Every byte of an NTLM signature counts: one byte of the 16-byte signature of MakeSignature or
 *              EncryptMessage flipped, the receiver's VerifySignature or DecryptMessage fails with the status Windows
 *              gives (measured on Windows Server 2022 with an SSPI-only probe, each byte in turn, NTLM and Negotiate):
 *              version bytes 0-3 SEC_E_INVALID_TOKEN, checksum bytes 4-11 SEC_E_MESSAGE_ALTERED, sequence bytes 12-15
 *              SEC_E_OUT_OF_SEQUENCE; the next unchanged message verifies. With more than one part wrong the
 *              version comes first, then the checksum (measured the same way).
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

#define TEST_PASSWORD L"SigBytes#Test1pw"
#define MAXT 8192

static WCHAR g_user[32];

/* the status of one call (evaluated once) */
#define ok_st(call, expect) do { SECURITY_STATUS st_ = (call); \
    ok(st_ == (expect), "%s: 0x%08lx, expected 0x%08lx\n", #call, (unsigned long)st_, (unsigned long)(expect)); } while (0)

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"sigbyt%lu", GetCurrentProcessId() % 100000);
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

typedef struct
{
    CredHandle cc, sc;
    CtxtHandle cctx, sctx;
    BOOL hc, hs, hcred;
} pair_t;

static void pair_free(pair_t *p)
{
    if (p->hc) DeleteSecurityContext(&p->cctx);
    if (p->hs) DeleteSecurityContext(&p->sctx);
    if (p->hcred)
    {
        FreeCredentialsHandle(&p->cc);
        FreeCredentialsHandle(&p->sc);
    }
    memset(p, 0, sizeof(*p));
}

/* a raw NTLM exchange (explicit credentials: the Negotiate package also speaks raw NTLM then) */
static BOOL pair_make(const WCHAR *pkg, pair_t *p)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    TimeStamp ts;
    SECURITY_STATUS cs, ss;
    BYTE a[MAXT], b[MAXT];
    SecBuffer ib, ob;
    SecBufferDesc idesc = { SECBUFFER_VERSION, 1, &ib }, odesc = { SECBUFFER_VERSION, 1, &ob };
    ULONG attr, creq = ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY;
    ULONG sreq = ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY | ASC_REQ_CONFIDENTIALITY;

    memset(p, 0, sizeof(*p));
    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)g_user; id.UserLength = (ULONG)wcslen(g_user);
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)TEST_PASSWORD; id.PasswordLength = (ULONG)wcslen(TEST_PASSWORD);
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if (AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)pkg, SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &p->cc, &ts))
        return FALSE;
    if (AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)pkg, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &p->sc, &ts))
    {
        FreeCredentialsHandle(&p->cc);
        return FALSE;
    }
    p->hcred = TRUE;
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = a; ob.cbBuffer = MAXT;
    cs = InitializeSecurityContextW(&p->cc, NULL, NULL, creq, 0, SECURITY_NATIVE_DREP, NULL, 0, &p->cctx, &odesc,
                                    &attr, &ts);
    if (cs != SEC_I_CONTINUE_NEEDED) return FALSE;
    p->hc = TRUE;
    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = a; ib.cbBuffer = ob.cbBuffer;
    ob.pvBuffer = b; ob.cbBuffer = MAXT;
    ss = AcceptSecurityContext(&p->sc, NULL, &idesc, sreq, SECURITY_NATIVE_DREP, &p->sctx, &odesc, &attr, &ts);
    if (ss != SEC_I_CONTINUE_NEEDED) return FALSE;
    p->hs = TRUE;
    ib.pvBuffer = b; ib.cbBuffer = ob.cbBuffer;
    ob.pvBuffer = a; ob.cbBuffer = MAXT;
    cs = InitializeSecurityContextW(&p->cc, &p->cctx, NULL, creq, 0, SECURITY_NATIVE_DREP, &idesc, 0, &p->cctx, &odesc,
                                    &attr, &ts);
    if (cs != SEC_E_OK) return FALSE;
    ib.pvBuffer = a; ib.cbBuffer = ob.cbBuffer;
    ob.pvBuffer = b; ob.cbBuffer = MAXT;
    ss = AcceptSecurityContext(&p->sc, &p->sctx, &idesc, sreq, SECURITY_NATIVE_DREP, &p->sctx, &odesc, &attr, &ts);
    return ss == SEC_E_OK;
}

static SECURITY_STATUS expected(int byte)
{
    if (byte < 4) return SEC_E_INVALID_TOKEN;
    if (byte < 12) return SEC_E_MESSAGE_ALTERED;
    return SEC_E_OUT_OF_SEQUENCE;
}

static void test_bytes(const WCHAR *pkg, BOOL seal)
{
    int byte;

    for (byte = 0; byte < 16; byte++)
    {
        pair_t p;
        BYTE data[32], sig[16];
        SecBuffer bufs[2];
        SecBufferDesc d = { SECBUFFER_VERSION, 2, bufs };
        SECURITY_STATUS st;
        ULONG qop = 0;

        if (!pair_make(pkg, &p))
        {
            ok(0, "%ls: exchange failed\n", pkg);
            pair_free(&p);
            return;
        }
        memset(data, 'm', sizeof(data));
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = data; bufs[0].cbBuffer = sizeof(data);
        bufs[1].BufferType = SECBUFFER_TOKEN; bufs[1].pvBuffer = sig; bufs[1].cbBuffer = sizeof(sig);
        st = seal ? EncryptMessage(&p.cctx, 0, &d, 0) : MakeSignature(&p.cctx, 0, &d, 0);
        ok(st == SEC_E_OK, "%ls %s byte %d: make 0x%08lx\n", pkg, seal ? "seal" : "sign", byte, (unsigned long)st);
        sig[byte] ^= 0x01;
        st = seal ? DecryptMessage(&p.sctx, &d, 0, &qop) : VerifySignature(&p.sctx, &d, 0, &qop);
        ok(st == expected(byte), "%ls %s byte %d flipped: 0x%08lx, expected 0x%08lx\n", pkg, seal ? "seal" : "sign",
           byte, (unsigned long)st, (unsigned long)expected(byte));
        memset(data, 'n', sizeof(data));
        bufs[1].cbBuffer = sizeof(sig);
        st = seal ? EncryptMessage(&p.cctx, 0, &d, 0) : MakeSignature(&p.cctx, 0, &d, 0);
        st = seal ? DecryptMessage(&p.sctx, &d, 0, &qop) : VerifySignature(&p.sctx, &d, 0, &qop);
        ok(st == SEC_E_OK, "%ls %s byte %d: the next message 0x%08lx\n", pkg, seal ? "seal" : "sign", byte,
           (unsigned long)st);
        pair_free(&p);
    }
}

/* more than one part wrong (measured on Windows Server 2022) */
static void test_order(const WCHAR *pkg)
{
    pair_t p;
    BYTE d0[32], d1[32], s0[16], s1[16];
    SecBuffer b0[2], b1[2];
    SecBufferDesc x0 = { SECBUFFER_VERSION, 2, b0 }, x1 = { SECBUFFER_VERSION, 2, b1 };
    ULONG qop;

    if (!pair_make(pkg, &p))
    {
        ok(0, "%ls: exchange failed\n", pkg);
        pair_free(&p);
        return;
    }
    memset(d0, 'a', sizeof(d0)); memset(d1, 'b', sizeof(d1));
    b0[0].BufferType = SECBUFFER_DATA; b0[0].pvBuffer = d0; b0[0].cbBuffer = sizeof(d0);
    b0[1].BufferType = SECBUFFER_TOKEN; b0[1].pvBuffer = s0; b0[1].cbBuffer = sizeof(s0);
    b1[0].BufferType = SECBUFFER_DATA; b1[0].pvBuffer = d1; b1[0].cbBuffer = sizeof(d1);
    b1[1].BufferType = SECBUFFER_TOKEN; b1[1].pvBuffer = s1; b1[1].cbBuffer = sizeof(s1);
    ok_st(MakeSignature(&p.cctx, 0, &x0, 0), SEC_E_OK);
    ok_st(VerifySignature(&p.sctx, &x0, 0, &qop), SEC_E_OK);
    d0[0] ^= 1;     /* the same signature again with other data: sequence and checksum are wrong */
    ok_st(VerifySignature(&p.sctx, &x0, 0, &qop), SEC_E_MESSAGE_ALTERED);
    d0[0] ^= 1;     /* and once more unchanged */
    ok_st(VerifySignature(&p.sctx, &x0, 0, &qop), SEC_E_MESSAGE_ALTERED);
    ok_st(MakeSignature(&p.cctx, 0, &x0, 0), SEC_E_OK);
    ok_st(MakeSignature(&p.cctx, 0, &x1, 0), SEC_E_OK);
    ok_st(VerifySignature(&p.sctx, &x1, 0, &qop), SEC_E_MESSAGE_ALTERED);     /* one skipped */
    s0[0] ^= 1; s0[5] ^= 1; s0[13] ^= 1;
    ok_st(VerifySignature(&p.sctx, &x0, 0, &qop), SEC_E_INVALID_TOKEN);       /* all three parts */
    pair_free(&p);
}

START_TEST(NtlmSignatureBytes)
{
    if (!create_user()) return;
    test_bytes(L"NTLM", FALSE);
    test_bytes(L"NTLM", TRUE);
    test_bytes(L"Negotiate", FALSE);
    test_bytes(L"Negotiate", TRUE);
    test_order(L"NTLM");
    test_order(L"Negotiate");
    NetUserDel(NULL, g_user);
}
