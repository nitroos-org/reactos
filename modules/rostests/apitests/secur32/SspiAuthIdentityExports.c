/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     secur32 exports the SspiXxxAuthIdentity family, forwarded to sspicli (as Windows 10 does)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * msedge.dll of the Edge WebView2 runtime imports SspiEncodeAuthIdentityAsStrings, SspiFreeAuthIdentity and
 * SspiLocalFree from secur32.dll; without them msedgewebview2.exe fails with "Entry Point Not Found".
 */

#define SECURITY_WIN32
#include <apitest.h>
#include <sspi.h>
#include <security.h>

typedef SECURITY_STATUS (WINAPI *PFN_ENCODE_STRINGS)(PCWSTR, PCWSTR, PCWSTR, PVOID *);
typedef SECURITY_STATUS (WINAPI *PFN_DECODE_STRINGS)(PVOID, PCWSTR *, PCWSTR *, PCWSTR *);
typedef void (WINAPI *PFN_FREE)(PVOID);

START_TEST(SspiAuthIdentityExports)
{
    static const char *Names[] =
    {
        "SspiEncodeAuthIdentityAsStrings", "SspiEncodeStringsAsAuthIdentity", "SspiFreeAuthIdentity",
        "SspiLocalFree", "SspiPrepareForCredWrite", "SspiZeroAuthIdentity",
    };
    HMODULE hSecur32 = GetModuleHandleW(L"secur32.dll");
    HMODULE hSspicli = LoadLibraryW(L"sspicli.dll");
    PFN_ENCODE_STRINGS pEncode;
    PFN_DECODE_STRINGS pDecode;
    PFN_FREE pFreeIdentity, pLocalFree;
    PVOID Identity = NULL;
    PCWSTR User = NULL, Domain = NULL, Creds = NULL;
    SECURITY_STATUS Status;
    UINT i;

    if (!hSecur32)
        hSecur32 = LoadLibraryW(L"secur32.dll");
    ok(hSecur32 != NULL, "secur32.dll did not load\n");
    ok(hSspicli != NULL, "sspicli.dll did not load\n");
    if (!hSecur32 || !hSspicli)
        return;

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        FARPROC p1 = GetProcAddress(hSecur32, Names[i]);
        FARPROC p2 = GetProcAddress(hSspicli, Names[i]);

        ok(p1 != NULL, "secur32 does not export %s\n", Names[i]);
        ok(p2 != NULL, "sspicli does not export %s\n", Names[i]);
        ok(p1 == p2, "%s: secur32 %p is not the sspicli function %p\n", Names[i], p1, p2);
    }

    pEncode = (PFN_ENCODE_STRINGS)GetProcAddress(hSecur32, "SspiEncodeStringsAsAuthIdentity");
    pDecode = (PFN_DECODE_STRINGS)GetProcAddress(hSecur32, "SspiEncodeAuthIdentityAsStrings");
    pFreeIdentity = (PFN_FREE)GetProcAddress(hSecur32, "SspiFreeAuthIdentity");
    pLocalFree = (PFN_FREE)GetProcAddress(hSecur32, "SspiLocalFree");
    if (!pEncode || !pDecode || !pFreeIdentity || !pLocalFree)
    {
        skip("exports missing\n");
        return;
    }

    Status = pEncode(L"user", L"DOMAIN", L"secret", &Identity);
    ok(Status == SEC_E_OK, "SspiEncodeStringsAsAuthIdentity = 0x%08lx\n", (ULONG)Status);
    ok(Identity != NULL, "no identity\n");
    if (Identity)
    {
        Status = pDecode(Identity, &User, &Domain, &Creds);
        ok(Status == SEC_E_OK, "SspiEncodeAuthIdentityAsStrings = 0x%08lx\n", (ULONG)Status);
        ok(User && !wcscmp(User, L"user"), "user %ls\n", User ? User : L"(null)");
        ok(Domain && !wcscmp(Domain, L"DOMAIN"), "domain %ls\n", Domain ? Domain : L"(null)");
        ok(Creds && !wcscmp(Creds, L"secret"), "creds %ls\n", Creds ? Creds : L"(null)");
        if (User)
            pLocalFree((PVOID)User);
        if (Domain)
            pLocalFree((PVOID)Domain);
        if (Creds)
            pLocalFree((PVOID)Creds);
        pFreeIdentity(Identity);
    }
}
