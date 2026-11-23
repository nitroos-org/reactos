/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schannel attributes of an established context: SECPKG_ATTR_CIPHER_INFO, SECPKG_ATTR_STREAM_SIZES
 *              (header and trailer of a record), SECPKG_ATTR_CONNECTION_INFO strengths. A client and a server context
 *              of one process shake hands over memory; Windows Server 2022 rows are in the evidence of kbatch8.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define SECURITY_WIN32
#include <apitest.h>
#include <wincrypt.h>
#include <sspi.h>
#include <schannel.h>

#define SECPKG_ATTR_CIPHER_INFO_X 0x64

typedef struct
{
    DWORD dwVersion, dwProtocol, dwCipherSuite, dwBaseCipherSuite;
    WCHAR szCipherSuite[64], szCipher[64];
    DWORD dwCipherLen, dwCipherBlockLen;
    WCHAR szHash[64];
    DWORD dwHashLen;
    WCHAR szExchange[64];
    DWORD dwMinExchangeLen, dwMaxExchangeLen;
    WCHAR szCertificate[64];
    DWORD dwKeyType;
} CIPHER_INFO_X;

static PCCERT_CONTEXT Cert;

static BOOL MakeCert(void)
{
    HCRYPTPROV Prov = 0;
    HCRYPTKEY Key = 0;
    CERT_NAME_BLOB Name;
    BYTE Buf[256];
    DWORD Len = sizeof(Buf);
    CRYPT_KEY_PROV_INFO Kpi;
    SYSTEMTIME St;

    CryptAcquireContextW(&Prov, L"kb8sch", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
    if (!CryptAcquireContextW(&Prov, L"kb8sch", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET))
    {
        skip("no key container (%lu)\n", GetLastError());
        return FALSE;
    }
    CryptGenKey(Prov, AT_KEYEXCHANGE, (2048u << 16) | CRYPT_EXPORTABLE, &Key);
    CertStrToNameW(X509_ASN_ENCODING, L"CN=kb8sch.test", 0, NULL, Buf, &Len, NULL);
    Name.cbData = Len;
    Name.pbData = Buf;
    ZeroMemory(&Kpi, sizeof(Kpi));
    Kpi.pwszContainerName = L"kb8sch";
    Kpi.pwszProvName = MS_ENH_RSA_AES_PROV_W;
    Kpi.dwProvType = PROV_RSA_AES;
    Kpi.dwKeySpec = AT_KEYEXCHANGE;
    GetSystemTime(&St);
    St.wYear += 1;
    Cert = CertCreateSelfSignCertificate(Prov, &Name, 0, &Kpi, NULL, NULL, &St, NULL);
    if (!Cert)
        skip("no self-signed certificate (%lu)\n", GetLastError());
    return Cert != NULL;
}

typedef struct { BYTE *Data; ULONG Size; } BUF;

static void Put(BUF *B, const BYTE *D, ULONG N)
{
    B->Data = realloc(B->Data, B->Size + N);
    memcpy(B->Data + B->Size, D, N);
    B->Size += N;
}

static SECURITY_STATUS Step(BOOL Server, PCredHandle Cred, PCtxtHandle Ctx, BOOL *Have, BUF *In, BUF *Out)
{
    SecBuffer Ib[2], Ob[1];
    SecBufferDesc Id, Od;
    TimeStamp Ts;
    ULONG Attr;
    SECURITY_STATUS Status;
    ULONG Flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
                  ISC_REQ_STREAM | ISC_REQ_EXTENDED_ERROR;

    Ib[0].BufferType = SECBUFFER_TOKEN; Ib[0].pvBuffer = In->Data; Ib[0].cbBuffer = In->Size;
    Ib[1].BufferType = SECBUFFER_EMPTY; Ib[1].pvBuffer = NULL; Ib[1].cbBuffer = 0;
    Id.ulVersion = SECBUFFER_VERSION; Id.cBuffers = 2; Id.pBuffers = Ib;
    Ob[0].BufferType = SECBUFFER_TOKEN; Ob[0].pvBuffer = NULL; Ob[0].cbBuffer = 0;
    Od.ulVersion = SECBUFFER_VERSION; Od.cBuffers = 1; Od.pBuffers = Ob;

    if (Server)
        Status = AcceptSecurityContext(Cred, *Have ? Ctx : NULL, &Id, Flags, 0, Ctx, &Od, &Attr, &Ts);
    else
        Status = InitializeSecurityContextW(Cred, *Have ? Ctx : NULL, (SEC_WCHAR *)L"kb8sch.test", Flags, 0, 0,
                                            In->Size ? &Id : NULL, 0, Ctx, &Od, &Attr, &Ts);
    *Have = TRUE;
    if (Ob[0].cbBuffer && Ob[0].pvBuffer)
    {
        Put(Out, Ob[0].pvBuffer, Ob[0].cbBuffer);
        FreeContextBuffer(Ob[0].pvBuffer);
    }
    if (Status != SEC_E_INCOMPLETE_MESSAGE)
        In->Size = 0;
    return Status;
}

typedef struct
{
    PCSTR Name;
    DWORD ClientProtocols, ServerProtocols;
    ALG_ID Alg;
} CASE;

static void CheckRecord(PCSTR Name, PCtxtHandle From, PCtxtHandle To, DWORD Header, DWORD Trailer)
{
    SecPkgContext_StreamSizes Sizes;
    SecBuffer B[4];
    SecBufferDesc D;
    BYTE *Buf;
    char Msg[] = "kbatch8 record";
    SECURITY_STATUS Status;
    ULONG Total;

    Status = QueryContextAttributesW(From, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    ok(Status == SEC_E_OK, "%s: STREAM_SIZES returned 0x%08lx\n", Name, Status);
    if (Status != SEC_E_OK)
        return;
    ok(Sizes.cbHeader == Header, "%s: cbHeader %lu, expected %lu\n", Name, Sizes.cbHeader, Header);
    ok(Sizes.cbTrailer == Trailer, "%s: cbTrailer %lu, expected %lu\n", Name, Sizes.cbTrailer, Trailer);

    Buf = calloc(1, Sizes.cbHeader + sizeof(Msg) + Sizes.cbTrailer + 64);
    memcpy(Buf + Sizes.cbHeader, Msg, sizeof(Msg));
    B[0].BufferType = SECBUFFER_STREAM_HEADER; B[0].pvBuffer = Buf; B[0].cbBuffer = Sizes.cbHeader;
    B[1].BufferType = SECBUFFER_DATA; B[1].pvBuffer = Buf + Sizes.cbHeader; B[1].cbBuffer = sizeof(Msg);
    B[2].BufferType = SECBUFFER_STREAM_TRAILER; B[2].pvBuffer = Buf + Sizes.cbHeader + sizeof(Msg); B[2].cbBuffer = Sizes.cbTrailer;
    B[3].BufferType = SECBUFFER_EMPTY; B[3].pvBuffer = NULL; B[3].cbBuffer = 0;
    D.ulVersion = SECBUFFER_VERSION; D.cBuffers = 4; D.pBuffers = B;
    Status = EncryptMessage(From, 0, &D, 0);
    ok(Status == SEC_E_OK, "%s: EncryptMessage returned 0x%08lx\n", Name, Status);
    if (Status == SEC_E_OK)
    {
        SecBuffer R[4];
        SecBufferDesc RD;

        ok(B[0].cbBuffer == Header, "%s: header after EncryptMessage %lu, expected %lu\n", Name, B[0].cbBuffer, Header);
        ok(B[1].cbBuffer == sizeof(Msg), "%s: data after EncryptMessage %lu\n", Name, B[1].cbBuffer);
        ok(B[2].cbBuffer <= Trailer && B[2].cbBuffer > 0, "%s: trailer after EncryptMessage %lu (limit %lu)\n", Name, B[2].cbBuffer, Trailer);
        Total = B[0].cbBuffer + B[1].cbBuffer + B[2].cbBuffer;
        R[0].BufferType = SECBUFFER_DATA; R[0].pvBuffer = Buf; R[0].cbBuffer = Total;
        R[1].BufferType = R[2].BufferType = R[3].BufferType = SECBUFFER_EMPTY;
        R[1].pvBuffer = R[2].pvBuffer = R[3].pvBuffer = NULL;
        R[1].cbBuffer = R[2].cbBuffer = R[3].cbBuffer = 0;
        RD.ulVersion = SECBUFFER_VERSION; RD.cBuffers = 4; RD.pBuffers = R;
        Status = DecryptMessage(To, &RD, 0, NULL);
        ok(Status == SEC_E_OK, "%s: DecryptMessage returned 0x%08lx\n", Name, Status);
    }
    free(Buf);
}

static void Run(const CASE *C)
{
    CredHandle Cc, Sc;
    CtxtHandle Cx, Sx;
    BOOL Ch = FALSE, Sh = FALSE;
    BUF C2S = {0}, S2C = {0}, Tmp = {0};
    SECURITY_STATUS Cs, Ss, A;
    SCHANNEL_CRED Sched, Cl;
    PCCERT_CONTEXT List[1];
    ALG_ID Algs[1];
    TimeStamp Ts;
    int i;
    CIPHER_INFO_X Ci;
    SecPkgContext_ConnectionInfo Info;
    DWORD Header = 0, Trailer = 0;

    List[0] = Cert;
    Algs[0] = C->Alg;
    ZeroMemory(&Sched, sizeof(Sched));
    Sched.dwVersion = SCHANNEL_CRED_VERSION;
    Sched.cCreds = 1;
    Sched.paCred = List;
    Sched.grbitEnabledProtocols = C->ServerProtocols;
    Sched.cSupportedAlgs = C->Alg ? 1 : 0;
    Sched.palgSupportedAlgs = C->Alg ? Algs : NULL;
    A = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &Sched, NULL, NULL, &Sc, &Ts);
    ok(A == SEC_E_OK, "%s: server credentials 0x%08lx\n", C->Name, A);
    if (A != SEC_E_OK)
        return;
    ZeroMemory(&Cl, sizeof(Cl));
    Cl.dwVersion = SCHANNEL_CRED_VERSION;
    Cl.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    Cl.grbitEnabledProtocols = C->ClientProtocols;
    Cl.cSupportedAlgs = C->Alg ? 1 : 0;
    Cl.palgSupportedAlgs = C->Alg ? Algs : NULL;
    A = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &Cl, NULL, NULL, &Cc, &Ts);
    ok(A == SEC_E_OK, "%s: client credentials 0x%08lx\n", C->Name, A);
    if (A != SEC_E_OK)
    {
        FreeCredentialsHandle(&Sc);
        return;
    }

    Cs = Step(FALSE, &Cc, &Cx, &Ch, &Tmp, &C2S);
    Ss = SEC_I_CONTINUE_NEEDED;
    for (i = 0; i < 30 && !(Cs == SEC_E_OK && Ss == SEC_E_OK); i++)
    {
        if (C2S.Size && Ss != SEC_E_OK)
        {
            Put(&Tmp, C2S.Data, C2S.Size); C2S.Size = 0;
            Ss = Step(TRUE, &Sc, &Sx, &Sh, &Tmp, &S2C);
            if (Ss != SEC_I_CONTINUE_NEEDED && Ss != SEC_E_OK) break;
            Tmp.Size = 0;
        }
        if (S2C.Size && Cs != SEC_E_OK)
        {
            Put(&Tmp, S2C.Data, S2C.Size); S2C.Size = 0;
            Cs = Step(FALSE, &Cc, &Cx, &Ch, &Tmp, &C2S);
            if (Cs != SEC_I_CONTINUE_NEEDED && Cs != SEC_E_OK) break;
            Tmp.Size = 0;
        }
    }
    ok(Cs == SEC_E_OK && Ss == SEC_E_OK, "%s: handshake client 0x%08lx server 0x%08lx\n", C->Name, Cs, Ss);
    if (Cs == SEC_E_OK && Ss == SEC_E_OK)
    {
        ZeroMemory(&Ci, sizeof(Ci));
        A = QueryContextAttributesW(&Cx, SECPKG_ATTR_CIPHER_INFO_X, &Ci);
        ok(A == SEC_E_OK, "%s: CIPHER_INFO returned 0x%08lx\n", C->Name, A);
        ZeroMemory(&Info, sizeof(Info));
        ok(QueryContextAttributesW(&Cx, SECPKG_ATTR_CONNECTION_INFO, &Info) == SEC_E_OK, "%s: CONNECTION_INFO failed\n", C->Name);
        if (A == SEC_E_OK)
        {
            BOOL Aead = FALSE, Cbc = FALSE;
            DWORD KeyBits = 0;

            trace("%s: suite 0x%lx %ls cipher %ls/%lu hash '%ls'/%lu exch '%ls' %lu..%lu cert '%ls' type %lu; connection hash %u/%lu exch %u/%lu\n",
                  C->Name, Ci.dwCipherSuite, Ci.szCipherSuite, Ci.szCipher, Ci.dwCipherLen, Ci.szHash, Ci.dwHashLen,
                  Ci.szExchange, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen, Ci.szCertificate, Ci.dwKeyType,
                  Info.aiHash, Info.dwHashStrength, Info.aiExch, Info.dwExchStrength);
            ok(Ci.dwVersion == 1, "%s: dwVersion %lu\n", C->Name, Ci.dwVersion);
            ok(Ci.dwProtocol >= 0x301 && Ci.dwProtocol <= 0x303, "%s: dwProtocol 0x%lx\n", C->Name, Ci.dwProtocol);
            ok(Ci.dwBaseCipherSuite == Ci.dwCipherSuite, "%s: base suite 0x%lx, suite 0x%lx\n", C->Name, Ci.dwBaseCipherSuite, Ci.dwCipherSuite);
            ok(!wcsncmp(Ci.szCipherSuite, L"TLS_", 4), "%s: suite name '%ls'\n", C->Name, Ci.szCipherSuite);
            ok(wcschr(Ci.szCipherSuite, L'-') == NULL, "%s: suite name has hyphens '%ls'\n", C->Name, Ci.szCipherSuite);
            ok(!wcscmp(Ci.szCertificate, L"RSA"), "%s: certificate '%ls'\n", C->Name, Ci.szCertificate);

            /* known suites: the rows of Windows Server 2022 */
            switch (Ci.dwCipherSuite)
            {
                case 0xc030: case 0xc02f: case 0x9d: case 0x9c: case 0x9f: case 0x9e: Aead = TRUE; break;
                case 0xc014: case 0xc013: case 0x35: case 0x2f: case 0xa: Cbc = TRUE; break;
                default: break;
            }
            if (Aead)
            {
                ok(Ci.szHash[0] == 0 && Ci.dwHashLen == 0, "%s: AEAD hash '%ls'/%lu\n", C->Name, Ci.szHash, Ci.dwHashLen);
                ok(Info.dwHashStrength == 0, "%s: AEAD connection hash strength %lu\n", C->Name, Info.dwHashStrength);
                ok(Ci.dwCipherBlockLen == 16, "%s: block %lu\n", C->Name, Ci.dwCipherBlockLen);
                Header = 13; Trailer = 16;
            }
            if (Cbc)
            {
                ok(!wcscmp(Ci.szHash, L"SHA1") && Ci.dwHashLen == 160, "%s: CBC hash '%ls'/%lu\n", C->Name, Ci.szHash, Ci.dwHashLen);
                ok(Info.dwHashStrength == 160, "%s: CBC connection hash strength %lu\n", C->Name, Info.dwHashStrength);
                if (!wcscmp(Ci.szCipher, L"3DES"))
                {
                    ok(Ci.dwCipherLen == 168 && Info.dwCipherStrength == 168, "%s: 3DES key %lu/%lu\n", C->Name, Ci.dwCipherLen, Info.dwCipherStrength);
                    ok(Ci.dwCipherBlockLen == 8, "%s: 3DES block %lu\n", C->Name, Ci.dwCipherBlockLen);
                    Header = 5 + (Ci.dwProtocol >= 0x302 ? 8 : 0); Trailer = 20 + 8;
                }
                else
                {
                    Header = 5 + (Ci.dwProtocol >= 0x302 ? 16 : 0); Trailer = 20 + 16;
                }
            }
            KeyBits = 0;
            if (!wcscmp(Ci.szExchange, L"ECDH"))
            {
                ok(Ci.dwMinExchangeLen == 0 && Ci.dwMaxExchangeLen == 65536, "%s: ECDH range %lu..%lu\n", C->Name, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen);
                ok(Info.dwExchStrength == 255 || Info.dwExchStrength == 256 || Info.dwExchStrength == 384 || Info.dwExchStrength == 521,
                   "%s: ECDH exchange strength %lu\n", C->Name, Info.dwExchStrength);
                ok((Info.dwExchStrength == 256 && Ci.dwKeyType == 23) || (Info.dwExchStrength == 384 && Ci.dwKeyType == 24) ||
                   (Info.dwExchStrength == 521 && Ci.dwKeyType == 25) || (Info.dwExchStrength == 255 && Ci.dwKeyType == 29),
                   "%s: ECDH key type %lu for strength %lu\n", C->Name, Ci.dwKeyType, Info.dwExchStrength);
            }
            else if (!wcscmp(Ci.szExchange, L"RSA"))
            {
                ok(Ci.dwMinExchangeLen == 512 && Ci.dwMaxExchangeLen == 16384, "%s: RSA range %lu..%lu\n", C->Name, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen);
                ok(Info.dwExchStrength == 2048, "%s: RSA exchange strength %lu\n", C->Name, Info.dwExchStrength);
                ok(Ci.dwKeyType == 0, "%s: RSA key type %lu\n", C->Name, Ci.dwKeyType);
            }
            else if (!wcscmp(Ci.szExchange, L"DH"))
            {
                ok(Ci.dwMinExchangeLen == 1024 && Ci.dwMaxExchangeLen == 1024, "%s: DH range %lu..%lu\n", C->Name, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen);
                ok(Info.dwExchStrength >= 1024, "%s: DH exchange strength %lu\n", C->Name, Info.dwExchStrength);
            }
            (void)KeyBits;
            if (Header)
            {
                CheckRecord(C->Name, &Cx, &Sx, Header, Trailer);
                CheckRecord(C->Name, &Sx, &Cx, Header, Trailer);
            }
        }
    }
    if (Ch) DeleteSecurityContext(&Cx);
    if (Sh) DeleteSecurityContext(&Sx);
    FreeCredentialsHandle(&Cc);
    FreeCredentialsHandle(&Sc);
    free(C2S.Data); free(S2C.Data); free(Tmp.Data);
}

START_TEST(SchannelAttributes)
{
    HCRYPTPROV Prov;
    static const CASE Cases[] =
    {
        { "TLS 1.2", SP_PROT_TLS1_2_CLIENT, SP_PROT_TLS1_2_SERVER, 0 },
        { "TLS 1.1", SP_PROT_TLS1_1_CLIENT, SP_PROT_TLS1_1_SERVER, 0 },
        { "TLS 1.0", SP_PROT_TLS1_0_CLIENT, SP_PROT_TLS1_0_SERVER, 0 },
        { "TLS 1.2, RSA key exchange", SP_PROT_TLS1_2_CLIENT, SP_PROT_TLS1_2_SERVER, CALG_RSA_KEYX },
        { "TLS 1.2, DHE", SP_PROT_TLS1_2_CLIENT, SP_PROT_TLS1_2_SERVER, CALG_DH_EPHEM },
        { "TLS 1.2, 3DES", SP_PROT_TLS1_2_CLIENT, SP_PROT_TLS1_2_SERVER, CALG_3DES },
    };
    int i;

    if (!MakeCert())
        return;
    for (i = 0; i < (int)ARRAYSIZE(Cases); i++)
        Run(&Cases[i]);
    CertFreeCertificateContext(Cert);
    CryptAcquireContextW(&Prov, L"kb8sch", MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
}
