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

/* ---- the data messages: Wrap = EncryptMessage on TOKEN + DATA + PADDING, Unwrap = DecryptMessage on STREAM + DATA ---- */

#define QOP_NO_ENCRYPT 0x80000001   /* SECQOP_WRAP_NO_ENCRYPT, what Wrap(requestEncryption: false) passes */
#define QOP_UNKNOWN    0xfffffffe   /* nobody measured it: the row prints it (VERIFY ON PEER) */

/* NegotiateAuthenticationPal.Wrap: the sizes come from SECPKG_ATTR_SIZES, the three buffers sit in one allocation
 * (token, data, padding) and the result is compacted to what the package returned in the buffer sizes. */
static ULONG dn_wrap(CtxtHandle *ctx, ULONG qop, const BYTE *in, ULONG in_len, BYTE *out, const char *what)
{
    SecPkgContext_Sizes sizes;
    SecBuffer bufs[3];
    SecBufferDesc desc = { SECBUFFER_VERSION, 3, bufs };
    SECURITY_STATUS st;
    BYTE *work;
    ULONG total = 0;

    st = QueryContextAttributesW(ctx, SECPKG_ATTR_SIZES, &sizes);
    ok(st == SEC_E_OK, "%s: SECPKG_ATTR_SIZES 0x%08lx\n", what, (unsigned long)st);
    if (st != SEC_E_OK) return 0;
    work = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, in_len + sizes.cbSecurityTrailer + sizes.cbBlockSize);
    memcpy(work + sizes.cbSecurityTrailer, in, in_len);
    bufs[0].BufferType = SECBUFFER_TOKEN;   bufs[0].pvBuffer = work;                                  bufs[0].cbBuffer = sizes.cbSecurityTrailer;
    bufs[1].BufferType = SECBUFFER_DATA;    bufs[1].pvBuffer = work + sizes.cbSecurityTrailer;        bufs[1].cbBuffer = in_len;
    bufs[2].BufferType = SECBUFFER_PADDING; bufs[2].pvBuffer = work + sizes.cbSecurityTrailer + in_len; bufs[2].cbBuffer = sizes.cbBlockSize;
    st = EncryptMessage(ctx, qop, &desc, 0);
    ok(st == SEC_E_OK, "%s: EncryptMessage(qop 0x%lx) 0x%08lx\n", what, (unsigned long)qop, (unsigned long)st);
    if (st == SEC_E_OK)
    {
        memcpy(out, bufs[0].pvBuffer, bufs[0].cbBuffer); total = bufs[0].cbBuffer;
        memcpy(out + total, bufs[1].pvBuffer, bufs[1].cbBuffer); total += bufs[1].cbBuffer;
        memcpy(out + total, bufs[2].pvBuffer, bufs[2].cbBuffer); total += bufs[2].cbBuffer;
        ok(bufs[1].cbBuffer == in_len, "%s: data size %lu\n", what, (unsigned long)bufs[1].cbBuffer);
    }
    HeapFree(GetProcessHeap(), 0, work);
    return total;
}

/* NegotiateAuthenticationPal.UnwrapInPlace: a STREAM buffer with the whole message and an empty DATA buffer; the data
 * buffer must stay a DATA buffer and point into the stream. .NET relies: SEC_E_OK, then
 * `dataBuffer->BufferType == SECBUFFER_DATA`, `pvBuffer` inside the input (Debug.Assert) and `wasEncrypted = qop !=
 * SECQOP_WRAP_NO_ENCRYPT` (expected_qop). */
static void dn_unwrap_stream(CtxtHandle *ctx, const BYTE *msg, ULONG msg_len, const BYTE *plain, ULONG plain_len,
                             ULONG expected_qop, const char *what)
{
    BYTE *stream = HeapAlloc(GetProcessHeap(), 0, msg_len);
    SecBuffer bufs[2];
    SecBufferDesc desc = { SECBUFFER_VERSION, 2, bufs };
    ULONG qop = 0xdeadbeef;
    SECURITY_STATUS st;

    memcpy(stream, msg, msg_len);
    bufs[0].BufferType = SECBUFFER_STREAM; bufs[0].pvBuffer = stream; bufs[0].cbBuffer = msg_len;
    bufs[1].BufferType = SECBUFFER_DATA;   bufs[1].pvBuffer = NULL;   bufs[1].cbBuffer = 0;
    st = DecryptMessage(ctx, &desc, 0, &qop);
    ok(st == SEC_E_OK, "%s: DecryptMessage(STREAM, DATA) 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_E_OK)
    {
        ok(bufs[1].BufferType == SECBUFFER_DATA, "%s: the data buffer is type 0x%lx\n", what, (unsigned long)bufs[1].BufferType);
        ok((BYTE *)bufs[1].pvBuffer >= stream && (BYTE *)bufs[1].pvBuffer + bufs[1].cbBuffer <= stream + msg_len,
           "%s: the data buffer %p/%lu is outside the stream %p/%lu\n", what, bufs[1].pvBuffer,
           (unsigned long)bufs[1].cbBuffer, stream, (unsigned long)msg_len);
        ok(bufs[1].cbBuffer == plain_len, "%s: %lu data bytes, expected %lu\n", what, (unsigned long)bufs[1].cbBuffer,
           (unsigned long)plain_len);
        ok(bufs[1].cbBuffer == plain_len && !memcmp(bufs[1].pvBuffer, plain, plain_len), "%s: the data differs\n", what);
        if (expected_qop == QOP_UNKNOWN)
            trace("VERIFY ON PEER %s: qop 0x%08lx\n", what, (unsigned long)qop);
        else
            ok(qop == expected_qop, "%s: qop 0x%08lx, expected 0x%08lx\n", what, (unsigned long)qop, (unsigned long)expected_qop);
    }
    HeapFree(GetProcessHeap(), 0, stream);
}

static const ULONG stream_sizes[] = { 1, 23, 300 };

/* a sealed message in each direction, repeated (the RC4 state advances) */
static void check_stream_messages(PAIR *p, ULONG wrap_qop, ULONG expected_qop, const char *what)
{
    int dir;
    UINT i;

    for (dir = 0; dir < 2; dir++)
    {
        CtxtHandle *a = dir ? &p->sctx : &p->cctx, *b = dir ? &p->cctx : &p->sctx;

        for (i = 0; i < ARRAYSIZE(stream_sizes); i++)
        {
            BYTE plain[300], msg[300 + 128];
            ULONG n = stream_sizes[i], msg_len;
            char label[96];

            memset(plain, 'A' + i + dir, sizeof(plain));
            _snprintf(label, sizeof(label), "%s %s %lu bytes", what, dir ? "server->client" : "client->server", (unsigned long)n);
            msg_len = dn_wrap(a, wrap_qop, plain, n, msg, label);
            if (!msg_len) continue;
            ok(msg_len >= n + 16, "%s: message of %lu bytes\n", label, (unsigned long)msg_len);
            dn_unwrap_stream(b, msg, msg_len, plain, n, expected_qop, label);
        }
    }
}

/* the contexts .NET makes: Negotiate and NTLM with the caller's own credentials, Negotiate with explicit ones */
static void test_stream_decrypt(void)
{
    HMODULE hSecur32 = GetModuleHandleW(L"secur32.dll");
    PFN_ENCODE pEncode = hSecur32 ? (PFN_ENCODE)GetProcAddress(hSecur32, "SspiEncodeStringsAsAuthIdentity") : NULL;
    PFN_FREEID pFree = hSecur32 ? (PFN_FREEID)GetProcAddress(hSecur32, "SspiFreeAuthIdentity") : NULL;
    static const WCHAR *packages[] = { L"Negotiate", L"NTLM" };
    PAIR p;
    UINT i;

    for (i = 0; i < ARRAYSIZE(packages); i++)
    {
        char what[64];

        _snprintf(what, sizeof(what), "%ls, own credentials, encrypt", packages[i]);
        if (establish(packages[i], NULL, DN_CLIENT_ENCRYPT, DN_SERVER_ENCRYPT, &p, what))
        {
            /* qop 0 asks for encryption; .NET relies: the receiver reports qop 0 */
            check_stream_messages(&p, 0, 0, what);
            release(&p);
        }
    }

    if (pEncode && pFree && create_user())
    {
        PVOID identity = NULL;

        if (pEncode(g_user, L".", TEST_PASSWORD, &identity) == SEC_E_OK)
        {
            if (establish(L"Negotiate", identity, DN_CLIENT_ENCRYPT, DN_SERVER_ENCRYPT, &p, "Negotiate, explicit, encrypt"))
            {
                check_stream_messages(&p, 0, 0, "Negotiate, explicit, encrypt");
                release(&p);
            }
            pFree(identity);
        }
        NetUserDel(NULL, g_user);
    }
}

/* ---- ProtectionLevel.Sign: the context asked for integrity only (no confidentiality), and Wrap(requestEncryption:
 * false) passes SECQOP_WRAP_NO_ENCRYPT to EncryptMessage ----
 * The message each side makes with such a context must be readable by the other one. Measured on Windows Server 2022
 * (SSPI-only probe, both directions, see the commit that made EncryptMessage seal without SEAL): NTLM with integrity
 * but no confidentiality seals and the peer decrypts it; Negotiate always offers signing, so its messages always work.
 * Not measured: the qop DecryptMessage reports for a message made with SECQOP_WRAP_NO_ENCRYPT; the row prints it
 * (VERIFY ON PEER: `dnprobe.exe` prints it on Windows). */
static void test_sign_only_messages(void)
{
    static const WCHAR *packages[] = { L"Negotiate", L"NTLM" };
    static const ULONG qops[] = { QOP_NO_ENCRYPT, 0 };
    PAIR p;
    UINT i, j;

    for (i = 0; i < ARRAYSIZE(packages); i++)
    {
        char what[96];

        _snprintf(what, sizeof(what), "%ls, own credentials, sign only", packages[i]);
        if (!establish(packages[i], NULL, DN_CLIENT_SIGN, DN_SERVER_SIGN, &p, what))
            continue;
        for (j = 0; j < ARRAYSIZE(qops); j++)
        {
            char label[128];

            _snprintf(label, sizeof(label), "%s, qop 0x%lx", what, (unsigned long)qops[j]);
            check_stream_messages(&p, qops[j], QOP_UNKNOWN, label);
        }
        release(&p);
    }
}

/* A STREAM shorter than a signature: nobody measured the status Windows gives (.NET maps every failure but
 * SEC_E_MESSAGE_ALTERED to InvalidToken, so it does not tell). Not asserted beyond "not OK"; the row prints the status
 * (VERIFY ON PEER: dnprobe.exe). */
static void test_short_stream(void)
{
    PAIR p;
    static const ULONG lengths[] = { 0, 1, 15 };
    UINT i;

    if (!establish(L"NTLM", NULL, DN_CLIENT_ENCRYPT, DN_SERVER_ENCRYPT, &p, "short stream"))
        return;
    for (i = 0; i < ARRAYSIZE(lengths); i++)
    {
        BYTE stream[16] = { 0 };
        SecBuffer bufs[2] = { { lengths[i], SECBUFFER_STREAM, stream }, { 0, SECBUFFER_DATA, NULL } };
        SecBufferDesc desc = { SECBUFFER_VERSION, 2, bufs };
        SECURITY_STATUS st = DecryptMessage(&p.sctx, &desc, 0, NULL);

        ok(st != SEC_E_OK, "a stream of %lu bytes was accepted\n", (unsigned long)lengths[i]);
        trace("VERIFY ON PEER: DecryptMessage(STREAM of %lu bytes, DATA) = 0x%08lx\n", (unsigned long)lengths[i], (unsigned long)st);
    }
    release(&p);
}

START_TEST(DotNetSspi)
{
    test_opaque_identity();
    test_stream_decrypt();
    test_sign_only_messages();
    test_short_stream();
}
