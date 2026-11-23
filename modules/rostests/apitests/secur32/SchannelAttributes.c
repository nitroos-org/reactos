/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schannel attributes of an established client context: SECPKG_ATTR_CIPHER_INFO, SECPKG_ATTR_STREAM_SIZES
 *              (header and trailer of a record), SECPKG_ATTR_CONNECTION_INFO strengths. Needs TLS servers that offer
 *              one suite each (openssl s_server -www -cipher ...), named by SCHANNEL_ATTR_HOST and SCHANNEL_ATTR_PORTS
 *              (one port per case, see Cases); without them the test is skipped. Windows Server 2022 rows are in the
 *              evidence of kbatch8.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define SECURITY_WIN32
#include <winsock2.h>
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



typedef struct
{
    PCSTR Name;
    DWORD ClientProtocols;
    ALG_ID Alg;
} CASE;

static BOOL SendAll(SOCKET S, const BYTE *D, int N)
{
    while (N > 0)
    {
        int R = send(S, (const char *)D, N, 0);
        if (R <= 0) return FALSE;
        D += R; N -= R;
    }
    return TRUE;
}

/* One request over the established context: sizes by STREAM_SIZES, the answer of the server proves that the record it
   received (header, data, trailer in the sizes reported) was well formed */
static void CheckRecord(PCSTR Name, SOCKET S, PCtxtHandle Ctx, DWORD Header, DWORD Trailer, BYTE *Extra, ULONG ExtraSize)
{
    SecPkgContext_StreamSizes Sizes;
    SecBuffer B[4];
    SecBufferDesc D;
    BYTE *Buf, *In;
    static const char Req[] = "GET / HTTP/1.0\r\n\r\n";
    SECURITY_STATUS Status;
    ULONG Total, Have = 0, Cap = 65536;
    int Tries;
    BOOL Got = FALSE;

    Status = QueryContextAttributesW(Ctx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    ok(Status == SEC_E_OK, "%s: STREAM_SIZES returned 0x%08lx\n", Name, Status);
    if (Status != SEC_E_OK)
        return;
    ok(Sizes.cbHeader == Header, "%s: cbHeader %lu, expected %lu\n", Name, Sizes.cbHeader, Header);
    ok(Sizes.cbTrailer == Trailer, "%s: cbTrailer %lu, expected %lu\n", Name, Sizes.cbTrailer, Trailer);

    Buf = calloc(1, Sizes.cbHeader + sizeof(Req) + Sizes.cbTrailer + 64);
    memcpy(Buf + Sizes.cbHeader, Req, sizeof(Req) - 1);
    B[0].BufferType = SECBUFFER_STREAM_HEADER; B[0].pvBuffer = Buf; B[0].cbBuffer = Sizes.cbHeader;
    B[1].BufferType = SECBUFFER_DATA; B[1].pvBuffer = Buf + Sizes.cbHeader; B[1].cbBuffer = sizeof(Req) - 1;
    B[2].BufferType = SECBUFFER_STREAM_TRAILER; B[2].pvBuffer = Buf + Sizes.cbHeader + sizeof(Req) - 1; B[2].cbBuffer = Sizes.cbTrailer;
    B[3].BufferType = SECBUFFER_EMPTY; B[3].pvBuffer = NULL; B[3].cbBuffer = 0;
    D.ulVersion = SECBUFFER_VERSION; D.cBuffers = 4; D.pBuffers = B;
    Status = EncryptMessage(Ctx, 0, &D, 0);
    ok(Status == SEC_E_OK, "%s: EncryptMessage returned 0x%08lx\n", Name, Status);
    if (Status == SEC_E_OK)
    {
        ok(B[0].cbBuffer == Header, "%s: header after EncryptMessage %lu, expected %lu\n", Name, B[0].cbBuffer, Header);
        ok(B[1].cbBuffer == sizeof(Req) - 1, "%s: data after EncryptMessage %lu\n", Name, B[1].cbBuffer);
        ok(B[2].cbBuffer > 0 && B[2].cbBuffer <= Trailer, "%s: trailer after EncryptMessage %lu (limit %lu)\n", Name, B[2].cbBuffer, Trailer);
        Total = B[0].cbBuffer + B[1].cbBuffer + B[2].cbBuffer;
        ok(SendAll(S, Buf, Total), "%s: send failed\n", Name);

        In = malloc(Cap);
        if (ExtraSize) { memcpy(In, Extra, ExtraSize); Have = ExtraSize; }
        for (Tries = 0; Tries < 20 && !Got; Tries++)
        {
            SecBuffer R[4];
            SecBufferDesc RD;
            int N;

            for (;;)
            {
                R[0].BufferType = SECBUFFER_DATA; R[0].pvBuffer = In; R[0].cbBuffer = Have;
                R[1].BufferType = R[2].BufferType = R[3].BufferType = SECBUFFER_EMPTY;
                R[1].pvBuffer = R[2].pvBuffer = R[3].pvBuffer = NULL;
                R[1].cbBuffer = R[2].cbBuffer = R[3].cbBuffer = 0;
                RD.ulVersion = SECBUFFER_VERSION; RD.cBuffers = 4; RD.pBuffers = R;
                Status = Have ? DecryptMessage(Ctx, &RD, 0, NULL) : SEC_E_INCOMPLETE_MESSAGE;
                if (Status == SEC_E_OK)
                {
                    int k;
                    for (k = 0; k < 4; k++)
                        if (R[k].BufferType == SECBUFFER_DATA && R[k].cbBuffer >= 8 && !memcmp(R[k].pvBuffer, "HTTP/1.", 7))
                            Got = TRUE;
                    Have = 0;
                    for (k = 0; k < 4; k++)
                        if (R[k].BufferType == SECBUFFER_EXTRA && R[k].cbBuffer) { memmove(In, R[k].pvBuffer, R[k].cbBuffer); Have = R[k].cbBuffer; }
                    if (Got || !Have) break;
                    continue;
                }
                break;
            }
            if (Got || (Status != SEC_E_INCOMPLETE_MESSAGE && Status != SEC_E_OK))
                break;
            N = recv(S, (char *)In + Have, Cap - Have, 0);
            if (N <= 0) break;
            Have += N;
        }
        ok(Got, "%s: no HTTP answer to a record of the sizes reported (last status 0x%08lx)\n", Name, Status);
        free(In);
    }
    free(Buf);
}

static void Run(const CASE *C, PCSTR Host, int Port)
{
    SOCKET S;
    struct sockaddr_in Addr;
    DWORD Timeout = 15000;
    CredHandle Cc;
    CtxtHandle Cx;
    BOOL Have = FALSE;
    SCHANNEL_CRED Cl;
    ALG_ID Algs[1];
    TimeStamp Ts;
    SECURITY_STATUS A, Cs;
    BYTE *In = malloc(65536);
    ULONG InSize = 0, ExtraSize = 0;
    int Rounds;
    CIPHER_INFO_X Ci;
    SecPkgContext_ConnectionInfo Info;
    DWORD Header = 0, Trailer = 0;

    S = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(S, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_port = htons((u_short)Port);
    Addr.sin_addr.s_addr = inet_addr(Host);
    if (connect(S, (struct sockaddr *)&Addr, sizeof(Addr)))
    {
        ok(0, "%s: connect to %s:%d failed (%d)\n", C->Name, Host, Port, WSAGetLastError());
        closesocket(S);
        free(In);
        return;
    }

    Algs[0] = C->Alg;
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
        closesocket(S);
        free(In);
        return;
    }

    Cs = SEC_I_CONTINUE_NEEDED;
    for (Rounds = 0; Rounds < 30 && (Cs == SEC_I_CONTINUE_NEEDED || Cs == SEC_E_INCOMPLETE_MESSAGE); Rounds++)
    {
        SecBuffer Ib[2], Ob[1];
        SecBufferDesc Id, Od;
        ULONG Attr;

        Ib[0].BufferType = SECBUFFER_TOKEN; Ib[0].pvBuffer = In; Ib[0].cbBuffer = InSize;
        Ib[1].BufferType = SECBUFFER_EMPTY; Ib[1].pvBuffer = NULL; Ib[1].cbBuffer = 0;
        Id.ulVersion = SECBUFFER_VERSION; Id.cBuffers = 2; Id.pBuffers = Ib;
        Ob[0].BufferType = SECBUFFER_TOKEN; Ob[0].pvBuffer = NULL; Ob[0].cbBuffer = 0;
        Od.ulVersion = SECBUFFER_VERSION; Od.cBuffers = 1; Od.pBuffers = &Ob[0];
        if (Cs == SEC_E_INCOMPLETE_MESSAGE)
        {
            int N = recv(S, (char *)In + InSize, 65536 - InSize, 0);
            if (N <= 0) break;
            InSize += N;
            Ib[0].cbBuffer = InSize;
        }
        Cs = InitializeSecurityContextW(&Cc, Have ? &Cx : NULL, (SEC_WCHAR *)L"kb8sch.test",
                                        ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_EXTENDED_ERROR, 0, 0,
                                        InSize ? &Id : NULL, 0, &Cx, &Od, &Attr, &Ts);
        Have = TRUE;
        if (Ob[0].cbBuffer && Ob[0].pvBuffer)
        {
            SendAll(S, Ob[0].pvBuffer, Ob[0].cbBuffer);
            FreeContextBuffer(Ob[0].pvBuffer);
        }
        if (Cs == SEC_E_INCOMPLETE_MESSAGE)
            continue;
        if (InSize)
        {
            if (Ib[1].BufferType == SECBUFFER_EXTRA && Ib[1].cbBuffer)
            {
                memmove(In, In + InSize - Ib[1].cbBuffer, Ib[1].cbBuffer);
                ExtraSize = InSize = Ib[1].cbBuffer;
            }
            else
                ExtraSize = InSize = 0;
        }
        if (Cs == SEC_I_CONTINUE_NEEDED && !InSize)
        {
            int N = recv(S, (char *)In, 65536, 0);
            if (N <= 0) break;
            InSize = N;
            ExtraSize = 0;
        }
    }
    ok(Cs == SEC_E_OK, "%s: handshake 0x%08lx\n", C->Name, Cs);
    if (Cs == SEC_E_OK)
    {
        BOOL Aead = FALSE, Cbc = FALSE;

        ZeroMemory(&Ci, sizeof(Ci));
        A = QueryContextAttributesW(&Cx, SECPKG_ATTR_CIPHER_INFO_X, &Ci);
        ok(A == SEC_E_OK, "%s: CIPHER_INFO returned 0x%08lx\n", C->Name, A);
        ZeroMemory(&Info, sizeof(Info));
        ok(QueryContextAttributesW(&Cx, SECPKG_ATTR_CONNECTION_INFO, &Info) == SEC_E_OK, "%s: CONNECTION_INFO failed\n", C->Name);
        if (A == SEC_E_OK)
        {
            trace("%s: proto 0x%lx suite 0x%lx %ls cipher %ls/%lu/%lu hash '%ls'/%lu exch '%ls' %lu..%lu cert '%ls' type %lu; connection proto 0x%lx cipher 0x%x/%lu hash 0x%x/%lu exch 0x%x/%lu\n",
                  C->Name, Ci.dwProtocol, Ci.dwCipherSuite, Ci.szCipherSuite, Ci.szCipher, Ci.dwCipherLen, Ci.dwCipherBlockLen,
                  Ci.szHash, Ci.dwHashLen, Ci.szExchange, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen, Ci.szCertificate,
                  Ci.dwKeyType, Info.dwProtocol, Info.aiCipher, Info.dwCipherStrength, Info.aiHash, Info.dwHashStrength,
                  Info.aiExch, Info.dwExchStrength);
            ok(Ci.dwVersion == 1, "%s: dwVersion %lu\n", C->Name, Ci.dwVersion);
            ok(Ci.dwProtocol >= 0x301 && Ci.dwProtocol <= 0x303, "%s: dwProtocol 0x%lx\n", C->Name, Ci.dwProtocol);
            ok(Ci.dwBaseCipherSuite == Ci.dwCipherSuite, "%s: base suite 0x%lx, suite 0x%lx\n", C->Name, Ci.dwBaseCipherSuite, Ci.dwCipherSuite);
            ok(!wcsncmp(Ci.szCipherSuite, L"TLS_", 4), "%s: suite name '%ls'\n", C->Name, Ci.szCipherSuite);
            ok(wcschr(Ci.szCipherSuite, L'-') == NULL, "%s: suite name has hyphens '%ls'\n", C->Name, Ci.szCipherSuite);
            ok(!wcscmp(Ci.szCertificate, L"RSA"), "%s: certificate '%ls'\n", C->Name, Ci.szCertificate);

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
                    /* TLS 1.0: two records (the first byte alone, a countermeasure that Windows does not take: 5 + 28 there) */
                    if (Ci.dwProtocol == 0x301) Trailer = 2 * (20 + 8) + 5;
                }
                else
                {
                    Header = 5 + (Ci.dwProtocol >= 0x302 ? 16 : 0); Trailer = 20 + 16;
                    /* TLS 1.0: two records (the first byte alone, a countermeasure that Windows does not take: 5 + 36 there) */
                    if (Ci.dwProtocol == 0x301) Trailer = 2 * (20 + 16) + 5;
                }
            }
            if (!wcscmp(Ci.szExchange, L"ECDH"))
            {
                ok(Ci.dwMinExchangeLen == 0 && Ci.dwMaxExchangeLen == 65536, "%s: ECDH range %lu..%lu\n", C->Name, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen);
                ok((Info.dwExchStrength == 256 && Ci.dwKeyType == 23) || (Info.dwExchStrength == 384 && Ci.dwKeyType == 24) ||
                   (Info.dwExchStrength == 521 && Ci.dwKeyType == 25) || (Info.dwExchStrength == 255 && Ci.dwKeyType == 29),
                   "%s: ECDH key type %lu for strength %lu\n", C->Name, Ci.dwKeyType, Info.dwExchStrength);
            }
            else if (!wcscmp(Ci.szExchange, L"RSA"))
            {
                ok(Ci.dwMinExchangeLen == 512 && Ci.dwMaxExchangeLen == 16384, "%s: RSA range %lu..%lu\n", C->Name, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen);
                ok(Info.dwExchStrength == 2048 || Info.dwExchStrength == 4096 || Info.dwExchStrength == 3072, "%s: RSA exchange strength %lu\n", C->Name, Info.dwExchStrength);
                ok(Ci.dwKeyType == 0, "%s: RSA key type %lu\n", C->Name, Ci.dwKeyType);
            }
            else if (!wcscmp(Ci.szExchange, L"DH"))
            {
                ok(Ci.dwMinExchangeLen == 1024 && Ci.dwMaxExchangeLen == 1024, "%s: DH range %lu..%lu\n", C->Name, Ci.dwMinExchangeLen, Ci.dwMaxExchangeLen);
                ok(Info.dwExchStrength >= 1024, "%s: DH exchange strength %lu\n", C->Name, Info.dwExchStrength);
            }
            if (Header)
                CheckRecord(C->Name, S, &Cx, Header, Trailer, In, ExtraSize);
        }
    }
    if (Have) DeleteSecurityContext(&Cx);
    FreeCredentialsHandle(&Cc);
    closesocket(S);
    free(In);
}

START_TEST(SchannelAttributes)
{
    /* Port i of SCHANNEL_ATTR_PORTS offers only Cases[i] (openssl s_server -www -no_tls1_3 -cipher / -tls1_1 ...):
       0: TLS 1.2 ECDHE-RSA-AES256-GCM-SHA384, 1: TLS 1.1 ECDHE-RSA-AES256-SHA, 2: TLS 1.0 AES256-SHA,
       3: TLS 1.2 AES256-GCM-SHA384 (RSA), 4: TLS 1.2 DHE-RSA-AES256-GCM-SHA384, 5: TLS 1.2 DES-CBC3-SHA */
    static const CASE Cases[] =
    {
        { "TLS 1.2 ECDHE GCM", SP_PROT_TLS1_2_CLIENT, 0 },
        { "TLS 1.1 ECDHE CBC", SP_PROT_TLS1_1_CLIENT, 0 },
        { "TLS 1.0 RSA CBC", SP_PROT_TLS1_0_CLIENT, 0 },
        { "TLS 1.2 RSA GCM", SP_PROT_TLS1_2_CLIENT, 0 },
        { "TLS 1.2 DHE GCM", SP_PROT_TLS1_2_CLIENT, 0 },
        { "TLS 1.2 3DES", SP_PROT_TLS1_2_CLIENT, 0 },
    };
    char Host[64], Ports[128], *P;
    WSADATA Wsa;
    int i;

    if (!GetEnvironmentVariableA("SCHANNEL_ATTR_HOST", Host, sizeof(Host)) ||
        !GetEnvironmentVariableA("SCHANNEL_ATTR_PORTS", Ports, sizeof(Ports)))
    {
        skip("SCHANNEL_ATTR_HOST / SCHANNEL_ATTR_PORTS name no TLS servers\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Wsa);
    P = Ports;
    for (i = 0; i < (int)ARRAYSIZE(Cases) && *P; i++)
    {
        int Port = atoi(P);
        P = strchr(P, ',');
        Run(&Cases[i], Host, Port);
        if (!P) break;
        P++;
    }
    WSACleanup();
}
