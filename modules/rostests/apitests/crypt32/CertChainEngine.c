/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the CERT_CHAIN_ENGINE_CONFIG structure versions of CertCreateCertificateChainEngine
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The structure has three versions: up to CycleDetectionModulus, with hExclusiveRoot and
 * hExclusiveTrustedPeople (Windows 7), and with dwExclusiveFlags as well (Windows 8 and later,
 * the current SDK). A caller built with the current SDK, such as rustls-platform-verifier
 * (rustup, cargo), passes the last one; refusing it with E_INVALIDARG made
 * "failed to initialize platform verifier".
 *
 * Expected values are what Windows 10 22H2 x64 does (probe on the oracle): cbSize 64, 80, 84 and 88
 * are accepted; 0, 60, 68, 72, 92 and 96 are refused with E_INVALIDARG. On i386 the same positions
 * relative to the members are assumed.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <wincrypt.h>
#include <stddef.h>

/* The layout of the current SDK, independent of this tree's header */
typedef struct
{
    DWORD cbSize;
    HCERTSTORE hRestrictedRoot;
    HCERTSTORE hRestrictedTrust;
    HCERTSTORE hRestrictedOther;
    DWORD cAdditionalStore;
    HCERTSTORE *rghAdditionalStore;
    DWORD dwFlags;
    DWORD dwUrlRetrievalTimeout;
    DWORD MaximumCachedCertificates;
    DWORD CycleDetectionModulus;
    HCERTSTORE hExclusiveRoot;
    HCERTSTORE hExclusiveTrustedPeople;
    DWORD dwExclusiveFlags;
} SDK10_CHAIN_ENGINE_CONFIG;

static void TryEngine(DWORD cbSize, BOOL Expected, HCERTSTORE Root)
{
    SDK10_CHAIN_ENGINE_CONFIG Config;
    HCERTCHAINENGINE Engine = (HCERTCHAINENGINE)(ULONG_PTR)1;
    BOOL Ret;

    memset(&Config, 0, sizeof(Config));
    Config.cbSize = cbSize;
    Config.hExclusiveRoot = Root;
    SetLastError(0xdeadbeef);
    Ret = CertCreateCertificateChainEngine((PCERT_CHAIN_ENGINE_CONFIG)&Config, &Engine);
    if (Expected)
    {
        ok(Ret, "cbSize %lu: failed, error %lu\n", cbSize, GetLastError());
        if (Ret)
            CertFreeCertificateChainEngine(Engine);
    }
    else
    {
        ok(!Ret, "cbSize %lu: succeeded\n", cbSize);
        ok(GetLastError() == E_INVALIDARG, "cbSize %lu: error %lx\n", cbSize, GetLastError());
    }
}

START_TEST(CertChainEngine)
{
    HCERTSTORE Store;
    DWORD Base = offsetof(SDK10_CHAIN_ENGINE_CONFIG, hExclusiveRoot);
    DWORD Win7 = offsetof(SDK10_CHAIN_ENGINE_CONFIG, dwExclusiveFlags);

    Store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    ok(Store != NULL, "CertOpenStore failed: %lu\n", GetLastError());

    TryEngine(Base, TRUE, NULL);
    TryEngine(Win7, TRUE, Store);
    TryEngine(Win7 + 4, TRUE, Store);
    TryEngine(sizeof(SDK10_CHAIN_ENGINE_CONFIG), TRUE, NULL);
    TryEngine(sizeof(SDK10_CHAIN_ENGINE_CONFIG), TRUE, Store);

    TryEngine(0, FALSE, NULL);
    TryEngine(Base - 4, FALSE, NULL);
    TryEngine(Base + 4, FALSE, NULL);
#ifdef _WIN64
    TryEngine(Base + 8, FALSE, NULL);
#endif
    TryEngine(sizeof(SDK10_CHAIN_ENGINE_CONFIG) + 4, FALSE, NULL);
    TryEngine(sizeof(SDK10_CHAIN_ENGINE_CONFIG) + 8, FALSE, NULL);

    if (Store)
        CertCloseStore(Store, 0);
}
