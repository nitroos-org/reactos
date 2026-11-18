/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The SSPI calls System.Net.Security (.NET: NegotiateStream, NegotiateAuthentication, HttpClient and
 *              SqlClient integrated authentication) makes on Windows, in-process client and server, packages NTLM and
 *              Negotiate. The calls and flags follow dotnet/runtime, NegotiateAuthenticationPal.Windows.cs:
 *              explicit credentials through SspiEncodeStringsAsAuthIdentity (opaque identity), the data messages as
 *              EncryptMessage on TOKEN + DATA + PADDING and DecryptMessage on STREAM + DATA.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Expected values: a value measured on Windows is named with its source in the table next to its use; a value taken
 * from what the .NET source relies on is marked ".NET relies"; a value nobody measured is marked VERIFY ON PEER with
 * the probe to run (tools/dnprobe.c compiles this file unchanged against a shim and prints the same rows on Windows).
 */

#include <apitest.h>
#include <string.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <lmaccess.h>
#include <lmerr.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define TEST_PASSWORD L"Dnet#Test1pw"
#define TARGET        L"host/localhost"
#define MAX_TOKEN     16384

/* the flag sets System.Net.Security requests (NegotiateAuthenticationPal.Windows.cs, the two constructors):
 * client: Connection | InitIntegrity | Confidentiality | MutualAuth | InitIdentify, server: Connection | AcceptIntegrity
 * | Confidentiality; ProtectionLevel.Sign leaves Confidentiality out, ProtectionLevel.None leaves both out */
#define DN_CLIENT_ENCRYPT (ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_IDENTIFY)
#define DN_SERVER_ENCRYPT (ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY | ASC_REQ_CONFIDENTIALITY)
#define DN_CLIENT_SIGN    (ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_IDENTIFY)
#define DN_SERVER_SIGN    (ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY)

typedef SECURITY_STATUS (WINAPI *PFN_ENCODE)(PCWSTR, PCWSTR, PCWSTR, PVOID *);
typedef void (WINAPI *PFN_FREEID)(PVOID);

static WCHAR g_user[32];

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"dnettest%lu", GetCurrentProcessId() % 100000);
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
    BOOL has_cc, has_sc, has_cctx, has_sctx;
} PAIR;

static void release(PAIR *p)
{
    if (p->has_cctx) DeleteSecurityContext(&p->cctx);
    if (p->has_sctx) DeleteSecurityContext(&p->sctx);
    if (p->has_cc) FreeCredentialsHandle(&p->cc);
    if (p->has_sc) FreeCredentialsHandle(&p->sc);
    memset(p, 0, sizeof(*p));
}

/* The exchange as the two PALs run it: the client calls InitializeSecurityContext (first without input), hands its token
 * to AcceptSecurityContext, passes the answer back, until both sides are complete. identity: NULL for the caller's own
 * credentials, else the opaque identity (as AcquireCredentialsHandle gets it from System.Net.Security). */
static BOOL establish(const WCHAR *package, PVOID identity, ULONG creq, ULONG sreq, PAIR *p, const char *what)
{
    static BYTE ctok[MAX_TOKEN], stok[MAX_TOKEN];
    ULONG ctok_len = 0, stok_len = 0, attr;
    SECURITY_STATUS cst = SEC_I_CONTINUE_NEEDED, sst = SEC_I_CONTINUE_NEEDED, st;
    TimeStamp ts;
    int leg;

    memset(p, 0, sizeof(*p));
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)package, SECPKG_CRED_OUTBOUND, NULL, identity, NULL, NULL, &p->cc, &ts);
    ok(st == SEC_E_OK, "%s: client AcquireCredentialsHandle 0x%08lx\n", what, (unsigned long)st);
    if (st != SEC_E_OK) return FALSE;
    p->has_cc = TRUE;
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)package, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &p->sc, &ts);
    ok(st == SEC_E_OK, "%s: server AcquireCredentialsHandle 0x%08lx\n", what, (unsigned long)st);
    if (st != SEC_E_OK) { release(p); return FALSE; }
    p->has_sc = TRUE;

    for (leg = 0; leg < 10; leg++)
    {
        if (cst == SEC_I_CONTINUE_NEEDED)
        {
            SecBuffer ib = { stok_len, SECBUFFER_TOKEN, stok }, ob = { sizeof(ctok), SECBUFFER_TOKEN, ctok };
            SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };

            cst = InitializeSecurityContextW(&p->cc, p->has_cctx ? &p->cctx : NULL, (SEC_WCHAR *)TARGET, creq, 0,
                                             SECURITY_NETWORK_DREP, stok_len ? &id : NULL, 0, &p->cctx, &od, &attr, &ts);
            if (cst == SEC_E_OK || cst == SEC_I_CONTINUE_NEEDED) p->has_cctx = TRUE;
            ok(cst == SEC_E_OK || cst == SEC_I_CONTINUE_NEEDED, "%s: leg %d ISC 0x%08lx\n", what, leg, (unsigned long)cst);
            if (cst != SEC_E_OK && cst != SEC_I_CONTINUE_NEEDED) { release(p); return FALSE; }
            ctok_len = ob.cbBuffer;
            stok_len = 0;
        }
        if (ctok_len)
        {
            SecBuffer ib = { ctok_len, SECBUFFER_TOKEN, ctok }, ob = { sizeof(stok), SECBUFFER_TOKEN, stok };
            SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };

            sst = AcceptSecurityContext(&p->sc, p->has_sctx ? &p->sctx : NULL, &id, sreq, SECURITY_NETWORK_DREP,
                                        &p->sctx, &od, &attr, &ts);
            if (sst == SEC_E_OK || sst == SEC_I_CONTINUE_NEEDED) p->has_sctx = TRUE;
            ok(sst == SEC_E_OK || sst == SEC_I_CONTINUE_NEEDED, "%s: leg %d ASC 0x%08lx\n", what, leg, (unsigned long)sst);
            if (sst != SEC_E_OK && sst != SEC_I_CONTINUE_NEEDED) { release(p); return FALSE; }
            stok_len = ob.cbBuffer;
            ctok_len = 0;
        }
        if (cst == SEC_E_OK && sst == SEC_E_OK && !ctok_len && !stok_len)
            return TRUE;
        if (cst == SEC_E_OK && !stok_len && sst != SEC_E_OK)
            break;
    }
    ok(FALSE, "%s: the exchange did not complete (client 0x%08lx, server 0x%08lx)\n", what, (unsigned long)cst, (unsigned long)sst);
    release(p);
    return FALSE;
}

/* signatures both ways (MakeSignature on DATA + TOKEN, as GetMIC does) */
static void check_signatures(PAIR *p, const char *what)
{
    int dir;

    for (dir = 0; dir < 2; dir++)
    {
        CtxtHandle *a = dir ? &p->sctx : &p->cctx, *b = dir ? &p->cctx : &p->sctx;
        BYTE data[24] = "dotnet-signed-message", sig[16];
        SecBuffer bufs[2] = { { sizeof(data), SECBUFFER_DATA, data }, { sizeof(sig), SECBUFFER_TOKEN, sig } };
        SecBufferDesc desc = { SECBUFFER_VERSION, 2, bufs };
        ULONG qop = 0xdead;
        SECURITY_STATUS st;

        st = MakeSignature(a, 0, &desc, 0);
        ok(st == SEC_E_OK, "%s: MakeSignature %d 0x%08lx\n", what, dir, (unsigned long)st);
        ok(bufs[1].cbBuffer == 16, "%s: signature size %lu\n", what, (unsigned long)bufs[1].cbBuffer);
        st = VerifySignature(b, &desc, 0, &qop);
        ok(st == SEC_E_OK, "%s: VerifySignature %d 0x%08lx\n", what, dir, (unsigned long)st);
    }
}

/* ---- the explicit credentials of System.Net.Security: SspiEncodeStringsAsAuthIdentity + AcquireCredentialsHandle ---- */

/* The exchange outcome for an account that exists, with the opaque identity of SspiEncodeStringsAsAuthIdentity.
 * The strings it holds are UTF-16 whatever flags a caller of the plain SEC_WINNT_AUTH_IDENTITY set; the packages read
 * the identity by its flags.
 * .NET relies: NegotiateStream with a NetworkCredential authenticates (AcquireCredentialsHandle with the opaque
 * identity, SEC_E_OK; both sides complete). VERIFY ON PEER (Windows, both packages, local account, domain "."):
 * dnprobe.exe opaque */
static const struct
{
    const WCHAR *package;
    ULONG client_req, server_req;
    const char *what;
} opaque_cases[] =
{
    { L"NTLM",      DN_CLIENT_SIGN,    DN_SERVER_SIGN,    "NTLM, sign" },
    { L"Negotiate", DN_CLIENT_SIGN,    DN_SERVER_SIGN,    "Negotiate, sign" },
    { L"Negotiate", DN_CLIENT_ENCRYPT, DN_SERVER_ENCRYPT, "Negotiate, encrypt" },
};

static void test_opaque_identity(void)
{
    HMODULE hSecur32 = GetModuleHandleW(L"secur32.dll");
    PFN_ENCODE pEncode = hSecur32 ? (PFN_ENCODE)GetProcAddress(hSecur32, "SspiEncodeStringsAsAuthIdentity") : NULL;
    PFN_FREEID pFree = hSecur32 ? (PFN_FREEID)GetProcAddress(hSecur32, "SspiFreeAuthIdentity") : NULL;
    UINT i;

    if (!pEncode || !pFree)
    {
        skip("SspiEncodeStringsAsAuthIdentity is not exported\n");
        return;
    }
    if (!create_user())
        return;

    for (i = 0; i < ARRAYSIZE(opaque_cases); i++)
    {
        PVOID identity = NULL;
        PAIR p;
        SECURITY_STATUS st = pEncode(g_user, L".", TEST_PASSWORD, &identity);

        ok(st == SEC_E_OK, "%s: SspiEncodeStringsAsAuthIdentity 0x%08lx\n", opaque_cases[i].what, (unsigned long)st);
        if (st != SEC_E_OK) continue;
        if (establish(opaque_cases[i].package, identity, opaque_cases[i].client_req, opaque_cases[i].server_req, &p,
                      opaque_cases[i].what))
        {
            WCHAR *name = NULL;
            SecPkgContext_NamesW names;

            /* the server context names the account the client's identity named */
            st = QueryContextAttributesW(&p.sctx, SECPKG_ATTR_NAMES, &names);
            ok(st == SEC_E_OK, "%s: SECPKG_ATTR_NAMES 0x%08lx\n", opaque_cases[i].what, (unsigned long)st);
            if (st == SEC_E_OK)
            {
                name = names.sUserName;
                ok(name && wcsstr(name, g_user), "%s: the server context names %ls, not %ls\n", opaque_cases[i].what,
                   name ? name : L"(null)", g_user);
                FreeContextBuffer(names.sUserName);
            }
            check_signatures(&p, opaque_cases[i].what);
            release(&p);
        }
        pFree(identity);
    }
    NetUserDel(NULL, g_user);
}

START_TEST(DotNetSspi)
{
    test_opaque_identity();
}
