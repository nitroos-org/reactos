/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     schannel AcquireCredentialsHandle with SCHANNEL_CRED (versions 3/4) and SCH_CREDENTIALS (version 5)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <apitest.h>
#include <ntsecapi.h>
#include <wincrypt.h>
#include <sspi.h>
#include <schannel.h>

/* Expected values are those of Windows 10 22H2 (x64 native). A 32-bit process on 64-bit Windows gets
 * SEC_E_INTERNAL_ERROR instead of SEC_E_INVALID_PARAMETER for two NULL arrays (WOW64_ALT below). */
#define WOW64_ALT SEC_E_INTERNAL_ERROR

#define CLIENT_PROTOCOLS (SP_PROT_PCT1_CLIENT | SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_TLS1_0_CLIENT | \
                          SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)
#define SERVER_PROTOCOLS (SP_PROT_PCT1_SERVER | SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_TLS1_0_SERVER | \
                          SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER)
/* TLS/SSL bits only: Windows also reports DTLS and other bits this provider has no equivalent for */
#define TLS_PROTOCOLS    (CLIENT_PROTOCOLS | SERVER_PROTOCOLS)

static DWORD DefaultClientProtocols;

static SECURITY_STATUS Acquire(ULONG Use, PVOID Auth, PDWORD Protocols)
{
    SecPkgCred_SupportedProtocols Supported;
    CredHandle Cred;
    TimeStamp Expiry;
    SECURITY_STATUS Status;

    *Protocols = 0;
    Status = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, Use, NULL, Auth, NULL, NULL, &Cred, &Expiry);
    if (Status != SEC_E_OK)
        return Status;

    Supported.grbitProtocol = 0;
    if (QueryCredentialsAttributesW(&Cred, SECPKG_ATTR_SUPPORTED_PROTOCOLS, &Supported) == SEC_E_OK)
        *Protocols = Supported.grbitProtocol & TLS_PROTOCOLS;
    else
        *Protocols = 0xdeadbeef;
    ok(FreeCredentialsHandle(&Cred) == SEC_E_OK, "FreeCredentialsHandle failed\n");
    return Status;
}

#define ExpectStatus(Use, Auth, Expected, Name) ExpectStatusAlt(Use, Auth, Expected, Expected, Name)

static void ExpectStatusAlt(ULONG Use, PVOID Auth, SECURITY_STATUS Expected, SECURITY_STATUS Alternative, PCSTR Name)
{
    DWORD Protocols;
    SECURITY_STATUS Status = Acquire(Use, Auth, &Protocols);

    ok(Status == Expected || Status == Alternative, "%s (%s): expected 0x%08lx, got 0x%08lx\n",
       Name, Use == SECPKG_CRED_OUTBOUND ? "outbound" : "inbound", (ULONG)Expected, Status);
}

static void ExpectProtocols(ULONG Use, PVOID Auth, DWORD Expected, PCSTR Name)
{
    DWORD Protocols;
    SECURITY_STATUS Status = Acquire(Use, Auth, &Protocols);

    ok(Status == SEC_E_OK, "%s: AcquireCredentialsHandle returned 0x%08lx\n", Name, Status);
    if (Status == SEC_E_OK)
        ok(Protocols == Expected, "%s: expected protocols 0x%lx, got 0x%lx\n", Name, Expected, Protocols);
}

static UNICODE_STRING MakeString(PCWSTR String)
{
    UNICODE_STRING Result;

    Result.Buffer = (PWSTR)String;
    Result.Length = (USHORT)(wcslen(String) * sizeof(WCHAR));
    Result.MaximumLength = Result.Length + sizeof(WCHAR);
    return Result;
}

static void InitV5(SCH_CREDENTIALS *Cred, TLS_PARAMETERS *Params, DWORD Count)
{
    ZeroMemory(Cred, sizeof(*Cred));
    Cred->dwVersion = SCH_CREDENTIALS_VERSION;
    if (Params)
        ZeroMemory(Params, sizeof(*Params) * 20);
    Cred->cTlsParameters = Count;
    Cred->pTlsParameters = Params;
}

static void TestLayout(void)
{
    /* Windows SDK layout */
#ifdef _WIN64
    ok(sizeof(SCH_CREDENTIALS) == 72, "sizeof(SCH_CREDENTIALS) = %u\n", (UINT)sizeof(SCH_CREDENTIALS));
    ok(FIELD_OFFSET(SCH_CREDENTIALS, paCred) == 16, "paCred at %u\n", (UINT)FIELD_OFFSET(SCH_CREDENTIALS, paCred));
    ok(FIELD_OFFSET(SCH_CREDENTIALS, dwFlags) == 52, "dwFlags at %u\n", (UINT)FIELD_OFFSET(SCH_CREDENTIALS, dwFlags));
    ok(FIELD_OFFSET(SCH_CREDENTIALS, pTlsParameters) == 64, "pTlsParameters at %u\n", (UINT)FIELD_OFFSET(SCH_CREDENTIALS, pTlsParameters));
    ok(sizeof(TLS_PARAMETERS) == 40, "sizeof(TLS_PARAMETERS) = %u\n", (UINT)sizeof(TLS_PARAMETERS));
    ok(FIELD_OFFSET(TLS_PARAMETERS, grbitDisabledProtocols) == 16, "grbitDisabledProtocols at %u\n", (UINT)FIELD_OFFSET(TLS_PARAMETERS, grbitDisabledProtocols));
    ok(FIELD_OFFSET(TLS_PARAMETERS, dwFlags) == 32, "dwFlags at %u\n", (UINT)FIELD_OFFSET(TLS_PARAMETERS, dwFlags));
    ok(sizeof(CRYPTO_SETTINGS) == 48, "sizeof(CRYPTO_SETTINGS) = %u\n", (UINT)sizeof(CRYPTO_SETTINGS));
    ok(FIELD_OFFSET(CRYPTO_SETTINGS, rgstrChainingModes) == 32, "rgstrChainingModes at %u\n", (UINT)FIELD_OFFSET(CRYPTO_SETTINGS, rgstrChainingModes));
#else
    ok(sizeof(SCH_CREDENTIALS) == 44, "sizeof(SCH_CREDENTIALS) = %u\n", (UINT)sizeof(SCH_CREDENTIALS));
    ok(FIELD_OFFSET(SCH_CREDENTIALS, paCred) == 12, "paCred at %u\n", (UINT)FIELD_OFFSET(SCH_CREDENTIALS, paCred));
    ok(FIELD_OFFSET(SCH_CREDENTIALS, dwFlags) == 32, "dwFlags at %u\n", (UINT)FIELD_OFFSET(SCH_CREDENTIALS, dwFlags));
    ok(FIELD_OFFSET(SCH_CREDENTIALS, pTlsParameters) == 40, "pTlsParameters at %u\n", (UINT)FIELD_OFFSET(SCH_CREDENTIALS, pTlsParameters));
    ok(sizeof(TLS_PARAMETERS) == 24, "sizeof(TLS_PARAMETERS) = %u\n", (UINT)sizeof(TLS_PARAMETERS));
    ok(FIELD_OFFSET(TLS_PARAMETERS, grbitDisabledProtocols) == 8, "grbitDisabledProtocols at %u\n", (UINT)FIELD_OFFSET(TLS_PARAMETERS, grbitDisabledProtocols));
    ok(FIELD_OFFSET(TLS_PARAMETERS, dwFlags) == 20, "dwFlags at %u\n", (UINT)FIELD_OFFSET(TLS_PARAMETERS, dwFlags));
    ok(sizeof(CRYPTO_SETTINGS) == 28, "sizeof(CRYPTO_SETTINGS) = %u\n", (UINT)sizeof(CRYPTO_SETTINGS));
    ok(FIELD_OFFSET(CRYPTO_SETTINGS, rgstrChainingModes) == 16, "rgstrChainingModes at %u\n", (UINT)FIELD_OFFSET(CRYPTO_SETTINGS, rgstrChainingModes));
#endif
}

static void TestVersions(void)
{
    BYTE Raw[128];
    DWORD Protocols, Version;
    SECURITY_STATUS Status;
    char Name[64];

    /* System defaults */
    Status = Acquire(SECPKG_CRED_OUTBOUND, NULL, &DefaultClientProtocols);
    ok(Status == SEC_E_OK, "default credentials: 0x%08lx\n", Status);
    ok(DefaultClientProtocols & SP_PROT_TLS1_2_CLIENT, "TLS 1.2 not enabled by default (0x%lx)\n", DefaultClientProtocols);
    ok(!(DefaultClientProtocols & ~CLIENT_PROTOCOLS), "server protocols in a client credential (0x%lx)\n", DefaultClientProtocols);
    /* Never enabled by default on Windows 10 */
    ok(!(DefaultClientProtocols & (SP_PROT_PCT1_CLIENT | SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT)),
       "PCT/SSL enabled by default (0x%lx)\n", DefaultClientProtocols);
    ExpectStatus(SECPKG_CRED_INBOUND, NULL, SEC_E_NO_CREDENTIALS, "no auth data");

    for (Version = 0; Version <= 7; Version++)
    {
        ZeroMemory(Raw, sizeof(Raw));
        *(DWORD *)Raw = Version;
        sprintf(Name, "zeroed version %lu", Version);

        Status = Acquire(SECPKG_CRED_OUTBOUND, Raw, &Protocols);
        switch (Version)
        {
            case SCH_CRED_V3:
            case SCHANNEL_CRED_VERSION:
            case SCH_CREDENTIALS_VERSION:
                ok(Status == SEC_E_OK, "%s outbound: 0x%08lx\n", Name, Status);
                ok(Protocols == DefaultClientProtocols, "%s outbound: protocols 0x%lx, default 0x%lx\n",
                   Name, Protocols, DefaultClientProtocols);
                break;
            default:
                ok(Status == SEC_E_UNKNOWN_CREDENTIALS, "%s outbound: 0x%08lx\n", Name, Status);
                break;
        }

        Status = Acquire(SECPKG_CRED_INBOUND, Raw, &Protocols);
        switch (Version)
        {
            case SCH_CRED_V3:
            case SCHANNEL_CRED_VERSION:
                /* ReactOS keeps the pre-Vista answer for SCHANNEL_CRED */
                ok(Status == SEC_E_OK || Status == SEC_E_NO_CREDENTIALS, "%s inbound: 0x%08lx\n", Name, Status);
                break;
            case SCH_CREDENTIALS_VERSION:
                ok(Status == SEC_E_OK, "%s inbound: 0x%08lx\n", Name, Status);
                ok((Protocols & SP_PROT_TLS1_2_SERVER) && !(Protocols & CLIENT_PROTOCOLS),
                   "%s inbound: protocols 0x%lx\n", Name, Protocols);
                ok(!(Protocols & (SP_PROT_PCT1_SERVER | SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER)),
                   "%s inbound: PCT/SSL enabled (0x%lx)\n", Name, Protocols);
                break;
            default:
                ok(Status == SEC_E_UNKNOWN_CREDENTIALS, "%s inbound: 0x%08lx\n", Name, Status);
                break;
        }
    }

    ZeroMemory(Raw, sizeof(Raw));
    *(DWORD *)Raw = SCH_CREDENTIALS_VERSION;
    ExpectStatus(SECPKG_CRED_BOTH, Raw, SEC_E_OK, "zeroed version 5, both directions");
}

static void TestProtocolMapping(void)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params[20];
    UNICODE_STRING Alpn[1];
    SCHANNEL_CRED Cred4;

    /* SCHANNEL_CRED, unchanged */
    ZeroMemory(&Cred4, sizeof(Cred4));
    Cred4.dwVersion = SCHANNEL_CRED_VERSION;
    Cred4.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred4, SP_PROT_TLS1_2_CLIENT, "v4 TLS 1.2 only");

    /* grbitDisabledProtocols removes protocols from the system defaults */
    InitV5(&Cred, Params, 1);
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, "v5 nothing disabled");

    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_2;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, SP_PROT_TLS1_2_CLIENT, "v5 all but TLS 1.2 disabled");
    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_2_CLIENT;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, SP_PROT_TLS1_2_CLIENT, "v5 all but TLS 1.2 client disabled");
    Params[0].grbitDisabledProtocols = SP_PROT_TLS1_0 | SP_PROT_TLS1_1;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols & ~(SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT),
                    "v5 TLS 1.0 and 1.1 disabled");
    Params[0].grbitDisabledProtocols = SP_PROT_TLS1_2_CLIENT;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols & ~SP_PROT_TLS1_2_CLIENT, "v5 TLS 1.2 client disabled");
    Params[0].grbitDisabledProtocols = SP_PROT_TLS1_2_SERVER;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, "v5 TLS 1.2 server disabled");
    Params[0].grbitDisabledProtocols = SERVER_PROTOCOLS;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, "v5 all server bits disabled");
    /* the server bits do not count as a client protocol that stays enabled (Windows 10 22H2) */
    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_2_SERVER;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_ALGORITHM_MISMATCH, "v5 all but TLS 1.2 server disabled");

    /* Disabling everything that is enabled leaves nothing; a protocol off by default cannot be enabled */
    Params[0].grbitDisabledProtocols = 0xffffffff;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_ALGORITHM_MISMATCH, "v5 everything disabled");
    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_SSL3;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_ALGORITHM_MISMATCH, "v5 all but SSL 3 disabled");
    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_3;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_ALGORITHM_MISMATCH, "v5 all but TLS 1.3 disabled");

    /* Entries without ALPN ids add up */
    InitV5(&Cred, Params, 2);
    Params[0].grbitDisabledProtocols = SP_PROT_TLS1_0;
    Params[1].grbitDisabledProtocols = SP_PROT_TLS1_1;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols & ~(SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT),
                    "v5 two entries");

    /* An entry scoped to ALPN ids does not restrict the credential */
    Alpn[0] = MakeString(L"h2");
    Params[1].cAlpnIds = 1;
    Params[1].rgstrAlpnIds = Alpn;
    Params[1].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_2;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols & ~SP_PROT_TLS1_0_CLIENT, "v5 entry for h2");
    InitV5(&Cred, Params, 1);
    Params[0].cAlpnIds = 1;
    Params[0].rgstrAlpnIds = Alpn;
    Params[0].grbitDisabledProtocols = 0xffffffff;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, "v5 only an entry for h2, everything disabled");

    /* Optional entries are ignored */
    InitV5(&Cred, Params, 1);
    Params[0].dwFlags = TLS_PARAMS_OPTIONAL;
    Params[0].grbitDisabledProtocols = 0xffffffff;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, "v5 optional entry, everything disabled");
    InitV5(&Cred, Params, 2);
    Params[0].dwFlags = TLS_PARAMS_OPTIONAL;
    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_3;
    Params[1].grbitDisabledProtocols = SP_PROT_TLS1_1;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols & ~SP_PROT_TLS1_1_CLIENT,
                    "v5 optional TLS 1.3-only entry and a mandatory one");
    InitV5(&Cred, Params, 1);
    Params[0].dwFlags = 0x80;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, "v5 unknown entry flag");

    /* Inbound uses the server bits */
    InitV5(&Cred, Params, 1);
    Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_2;
    ExpectProtocols(SECPKG_CRED_INBOUND, &Cred, SP_PROT_TLS1_2_SERVER, "v5 inbound all but TLS 1.2 disabled");
    Params[0].grbitDisabledProtocols = 0xffffffff;
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_ALGORITHM_MISMATCH, "v5 everything disabled");
}

static void TestInvalidParameters(void)
{
    SCH_CREDENTIALS Cred;
    TLS_PARAMETERS Params[20];
    CRYPTO_SETTINGS Crypto[20];
    UNICODE_STRING Strings[20];
    DWORD i;

    for (i = 0; i < ARRAYSIZE(Strings); i++)
        Strings[i] = MakeString(L"x");

    InitV5(&Cred, NULL, 1);
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "cTlsParameters 1, no array");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_INVALID_PARAMETER, "cTlsParameters 1, no array");
    InitV5(&Cred, Params, 0);
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "cTlsParameters 0, array");
    InitV5(&Cred, Params, SCH_CRED_MAX_SUPPORTED_PARAMETERS);
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "cTlsParameters 16");
    InitV5(&Cred, Params, SCH_CRED_MAX_SUPPORTED_PARAMETERS + 1);
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "cTlsParameters 17");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_INVALID_PARAMETER, "cTlsParameters 17");

    /* ALPN ids */
    InitV5(&Cred, Params, 1);
    Params[0].cAlpnIds = 1;
    ExpectStatusAlt(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, WOW64_ALT, "cAlpnIds 1, no array");
    Params[0].rgstrAlpnIds = Strings;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "one ALPN id");
    Params[0].cAlpnIds = SCH_CRED_MAX_SUPPORTED_ALPN_IDS;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "16 ALPN ids");
    Params[0].cAlpnIds = SCH_CRED_MAX_SUPPORTED_ALPN_IDS + 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "17 ALPN ids");
    Params[0].cAlpnIds = 1;
    Strings[0].Length = 0;
    Strings[0].Buffer = NULL;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "empty ALPN id");
    Strings[0] = MakeString(L"x");

    /* Disabled crypto: validated, accepted whatever the algorithm */
    InitV5(&Cred, Params, 1);
    ZeroMemory(Crypto, sizeof(Crypto));
    for (i = 0; i < ARRAYSIZE(Crypto); i++)
    {
        Crypto[i].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
        Crypto[i].strCngAlgId = MakeString(L"RC4");
    }
    Params[0].cDisabledCrypto = 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INTERNAL_ERROR, "cDisabledCrypto 1, no array");
    Params[0].pDisabledCrypto = Crypto;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "RC4 disabled");
    Params[0].cDisabledCrypto = SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "16 crypto settings");
    Params[0].cDisabledCrypto = SCH_CRED_MAX_SUPPORTED_CRYPTO_SETTINGS + 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "17 crypto settings");
    Params[0].cDisabledCrypto = 0;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "cDisabledCrypto 0, array");

    Params[0].cDisabledCrypto = 1;
    Crypto[0].strCngAlgId = MakeString(L"AES");
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "AES disabled");
    Crypto[0].strCngAlgId = MakeString(L"NoSuchAlgorithm");
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "unknown algorithm");
    Crypto[0].eAlgorithmUsage = (eTlsAlgorithmUsage)99;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "unknown usage");
    Crypto[0].eAlgorithmUsage = TlsParametersCngAlgUsageDigest;
    Crypto[0].strCngAlgId = MakeString(L"SHA1");
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "SHA1 digest disabled");
    Crypto[0].strCngAlgId.Length = 0;
    Crypto[0].strCngAlgId.Buffer = NULL;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "empty algorithm");
    Crypto[0].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    Crypto[0].strCngAlgId = MakeString(L"AES");
    Crypto[0].cChainingModes = 1;
    ExpectStatusAlt(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, WOW64_ALT, "cChainingModes 1, no array");
    Crypto[0].rgstrChainingModes = Strings;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "one chaining mode");
    Crypto[0].cChainingModes = SCH_CRED_MAX_SUPPORTED_CHAINING_MODES;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "16 chaining modes");
    Crypto[0].cChainingModes = SCH_CRED_MAX_SUPPORTED_CHAINING_MODES + 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "17 chaining modes");
    Crypto[0].cChainingModes = 0;
    Crypto[0].rgstrChainingModes = NULL;
    Crypto[0].dwMinBitLength = 256;
    Crypto[0].dwMaxBitLength = 128;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_INVALID_PARAMETER, "minimum above maximum");
    Crypto[0].dwMaxBitLength = 0;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "minimum, no maximum");

    /* Credential fields */
    InitV5(&Cred, NULL, 0);
    Cred.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    ExpectProtocols(SECPKG_CRED_OUTBOUND, &Cred, DefaultClientProtocols, ".NET client flags");
    Cred.dwFlags = 0x80000000;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "unknown flag");
    Cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_AUTO_CRED_VALIDATION;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "manual and automatic validation");
    Cred.dwFlags = 0;
    Cred.dwCredFormat = 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "dwCredFormat 1");
    Cred.dwCredFormat = 0;
    Cred.dwSessionLifespan = 1000;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "dwSessionLifespan");
    Cred.dwSessionLifespan = 0;
    Cred.cMappers = 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "cMappers 1, no array");
    Cred.cMappers = 0;
    Cred.cCreds = 1;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "cCreds 1, no array");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_OK, "cCreds 1, no array");
    Cred.cCreds = 0;
    Cred.hRootStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "hRootStore");
    CertCloseStore(Cred.hRootStore, 0);
}

static const WCHAR ContainerName[] = L"ReactOS AcquireCredentialsHandleVersions";

static PCCERT_CONTEXT CreateServerCertificate(HCRYPTPROV *Prov)
{
    CRYPT_KEY_PROV_INFO KeyInfo;
    CERT_NAME_BLOB Name;
    BYTE Encoded[128];
    DWORD Size = sizeof(Encoded);
    HCRYPTKEY Key;
    PCCERT_CONTEXT Cert;

    CryptAcquireContextW(Prov, ContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    if (!CryptAcquireContextW(Prov, ContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET))
    {
        skip("CryptAcquireContext failed (%lu)\n", GetLastError());
        return NULL;
    }
    if (!CryptGenKey(*Prov, AT_KEYEXCHANGE, 2048 << 16, &Key))
    {
        skip("CryptGenKey failed (%lu)\n", GetLastError());
        return NULL;
    }
    CryptDestroyKey(Key);

    if (!CertStrToNameW(X509_ASN_ENCODING, L"CN=schannel-test.reactos.test", CERT_X500_NAME_STR, NULL, Encoded, &Size, NULL))
    {
        skip("CertStrToName failed (%lu)\n", GetLastError());
        return NULL;
    }
    Name.cbData = Size;
    Name.pbData = Encoded;

    ZeroMemory(&KeyInfo, sizeof(KeyInfo));
    KeyInfo.pwszContainerName = (PWSTR)ContainerName;
    KeyInfo.pwszProvName = (PWSTR)MS_ENHANCED_PROV_W;
    KeyInfo.dwProvType = PROV_RSA_FULL;
    KeyInfo.dwKeySpec = AT_KEYEXCHANGE;
    Cert = CertCreateSelfSignCertificate(*Prov, &Name, 0, &KeyInfo, NULL, NULL, NULL, NULL);
    if (!Cert)
        skip("CertCreateSelfSignCertificate failed (%lu)\n", GetLastError());
    return Cert;
}

static void TestCertificates(void)
{
    HCRYPTPROV Prov = 0;
    PCCERT_CONTEXT Cert, NoKey;
    SCH_CREDENTIALS Cred;
    SCHANNEL_CRED Cred4;
    TLS_PARAMETERS Params[20];

    Cert = CreateServerCertificate(&Prov);
    if (Cert)
    {
        InitV5(&Cred, Params, 0);
        Cred.cCreds = 1;
        Cred.paCred = &Cert;
        ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_OK, "v5 certificate");
        ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_OK, "v5 certificate");
        Cred.cTlsParameters = 1;
        Params[0].grbitDisabledProtocols = ~(DWORD)SP_PROT_TLS1_2;
        ExpectProtocols(SECPKG_CRED_INBOUND, &Cred, SP_PROT_TLS1_2_SERVER, "v5 certificate, TLS 1.2 only");
        Params[0].grbitDisabledProtocols = 0xffffffff;
        ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_ALGORITHM_MISMATCH, "v5 certificate, everything disabled");
        Cred.pTlsParameters = NULL;
        ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_INVALID_PARAMETER, "v5 certificate, no parameter array");

        ZeroMemory(&Cred4, sizeof(Cred4));
        Cred4.dwVersion = SCHANNEL_CRED_VERSION;
        Cred4.cCreds = 1;
        Cred4.paCred = &Cert;
        ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_OK, "v4 certificate");
        ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_OK, "v4 certificate");

        /* the same certificate twice (Windows Server 2022: accepted in both directions) */
        {
            PCCERT_CONTEXT Twice[2];

            Twice[0] = Twice[1] = Cert;
            Cred4.cCreds = 2;
            Cred4.paCred = Twice;
            ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_OK, "v4 two certificates");
            ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_OK, "v4 two certificates");
            Cred4.cCreds = 1;
            Cred4.paCred = &Cert;
        }

        /* The same certificate without its key provider */
        NoKey = CertCreateCertificateContext(X509_ASN_ENCODING, Cert->pbCertEncoded, Cert->cbCertEncoded);
        ok(NoKey != NULL, "CertCreateCertificateContext failed (%lu)\n", GetLastError());
        if (NoKey)
        {
            InitV5(&Cred, NULL, 0);
            Cred.cCreds = 1;
            Cred.paCred = &NoKey;
            ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred, SEC_E_NO_CREDENTIALS, "v5 certificate without a private key");
            ExpectStatus(SECPKG_CRED_INBOUND, &Cred, SEC_E_NO_CREDENTIALS, "v5 certificate without a private key");
            Cred4.paCred = &NoKey;
            /* Windows Server 2022, both directions */
            ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_NO_CREDENTIALS, "v4 certificate without a private key");
            ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_NO_CREDENTIALS, "v4 certificate without a private key");
            CertFreeCertificateContext(NoKey);
        }
        CertFreeCertificateContext(Cert);
    }

    if (Prov)
        CryptReleaseContext(Prov, 0);
    CryptAcquireContextW(&Prov, ContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
}

static void TestLegacyNoCertificate(void)
{
    SCHANNEL_CRED Cred4;
    DWORD Protocols;
    PCCERT_CONTEXT NoArray = NULL;

    /* Windows Server 2022: version 3 and 4 credentials without a certificate are accepted in both directions;
     * an inbound one reports the server protocols, an outbound one the client protocols */
    ZeroMemory(&Cred4, sizeof(Cred4));
    Cred4.dwVersion = SCHANNEL_CRED_VERSION;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_OK, "v4 zeroed");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_OK, "v4 zeroed");
    ok(Acquire(SECPKG_CRED_INBOUND, &Cred4, &Protocols) == SEC_E_OK, "v4 zeroed inbound\n");
    ok((Protocols & SERVER_PROTOCOLS) && !(Protocols & CLIENT_PROTOCOLS), "v4 zeroed inbound: protocols 0x%lx\n", Protocols);
    Cred4.dwVersion = SCH_CRED_V3;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_OK, "v3 zeroed");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_OK, "v3 zeroed");
    ok(Acquire(SECPKG_CRED_INBOUND, &Cred4, &Protocols) == SEC_E_OK, "v3 zeroed inbound\n");
    ok((Protocols & SERVER_PROTOCOLS) && !(Protocols & CLIENT_PROTOCOLS), "v3 zeroed inbound: protocols 0x%lx\n", Protocols);

    /* a count without an array is no certificate (the old code dereferenced the NULL array) */
    Cred4.dwVersion = SCHANNEL_CRED_VERSION;
    Cred4.cCreds = 1;
    Cred4.paCred = NULL;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_OK, "v4 cCreds 1, no array");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_OK, "v4 cCreds 1, no array");
    Cred4.cCreds = 2;
    ExpectStatus(SECPKG_CRED_OUTBOUND, &Cred4, SEC_E_OK, "v4 cCreds 2, no array");
    ExpectStatus(SECPKG_CRED_INBOUND, &Cred4, SEC_E_OK, "v4 cCreds 2, no array");
    (void)NoArray;
}

START_TEST(AcquireCredentialsHandleVersions)
{
    TestLayout();
    TestVersions();
    TestProtocolMapping();
    TestInvalidParameters();
    TestLegacyNoCertificate();
    TestCertificates();
}
