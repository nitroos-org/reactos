/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The LocalMachine Root store is filled in the registry by setup/boot, not by crypt32
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * crypt32 imports its built-in roots into HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates
 * when the Root store is opened and the registry lacks one. A standard user's first open would then
 * need write access to HKLM. Setup (and the NitroCertSeed service at boot) opens the store as SYSTEM,
 * so the key is filled before any user runs. This test reads the registry only; it never opens a
 * certificate store, so it sees what the install left, not what the test run itself imported.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>

#define ROOT_PATH     L"SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates"
#define AUTHROOT_PATH L"SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates"

/* SHA-1 thumbprints of the five Microsoft roots built into crypt32 (rootstore.c) */
static const WCHAR *const g_BuiltIn[] =
{
    L"7F88CD7223F3C813818C994614A89C99FA3B5247", /* Microsoft Authenticode(tm) Root Authority */
    L"A43489159A520F0D93D032CCAF37E7FE20A8B419", /* Microsoft Root Authority */
    L"CDD4EEAE6000AC7F40C3802C171E30148030C072", /* Microsoft Root Certificate Authority */
    L"3B1EFD3A66EA28B16697394703A72CA340A05BD5", /* Microsoft Root Certificate Authority 2010 */
    L"8F43288AD272F3103B6FB1428485EA3014C0BCFE", /* Microsoft Root Certificate Authority 2011 */
};

static BOOL HasBlob(HKEY Root, const WCHAR *Name)
{
    HKEY hKey;
    DWORD Type, Size = 0;
    LONG Err;
    BOOL Ret;

    if (RegOpenKeyExW(Root, Name, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Err = RegQueryValueExW(hKey, L"Blob", NULL, &Type, NULL, &Size);
    Ret = (Err == ERROR_SUCCESS && Type == REG_BINARY && Size > 0);
    RegCloseKey(hKey);
    return Ret;
}

static BOOL HasKey(HKEY Parent, const WCHAR *Name)
{
    HKEY hKey;

    if (RegOpenKeyExW(Parent, Name, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

/* The stores of the install's hive (hivesft.inf, and AuthRoot from caroots.inf), each of which has its
 * Certificates, CRLs and CTLs keys: the first open of a store creates them, which a standard user
 * cannot do in HKLM. Stores a test registered later (WineTest) are not part of the install. */
static const WCHAR *const g_Stores[] =
{
    L"AuthRoot", L"My", L"Trust", L"CA", L"TrustedPublisher", L"Disallowed", L"TrustedPeople",
    L"ClientAuthIssuer", L"FlightRoot", L"TestSignRoot", L"AAD Token Issuer",
    L"eSIM Certification Authorities", L"Homegroup Machine Certificates", L"Remote Desktop",
    L"SmartCardRoot", L"TrustedAppRoot", L"TrustedDevices", L"Windows Live ID Token Issuer",
    L"WindowsServerUpdateServices",
};

static void TestStoreKeys(void)
{
    static const WCHAR *const SubKeys[] = { L"Certificates", L"CRLs", L"CTLs" };
    HKEY hStores, hStore;
    DWORD i, j;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SystemCertificates", 0, KEY_READ,
                      &hStores) != ERROR_SUCCESS)
    {
        ok(0, "SystemCertificates cannot be opened\n");
        return;
    }
    for (i = 0; i < ARRAYSIZE(g_Stores); i++)
    {
        if (RegOpenKeyExW(hStores, g_Stores[i], 0, KEY_READ, &hStore) != ERROR_SUCCESS)
        {
            ok(0, "store %ls is not in the hive\n", g_Stores[i]);
            continue;
        }
        for (j = 0; j < ARRAYSIZE(SubKeys); j++)
            ok(HasKey(hStore, SubKeys[j]), "store %ls has no %ls key\n", g_Stores[i], SubKeys[j]);
        RegCloseKey(hStore);
    }
    RegCloseKey(hStores);
}

START_TEST(RootStoreSeed)
{
    HKEY hRoot, hAuth;
    LONG Err;
    DWORD i, RootCount = 0, AuthCount = 0, Missing = 0;
    WCHAR Name[64];

    Err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ROOT_PATH, 0, KEY_READ, &hRoot);
    ok(Err == ERROR_SUCCESS, "Root\\Certificates cannot be opened: %ld\n", Err);
    if (Err != ERROR_SUCCESS)
        return;

    /* The Microsoft roots built into crypt32 */
    for (i = 0; i < ARRAYSIZE(g_BuiltIn); i++)
        ok(HasBlob(hRoot, g_BuiltIn[i]), "built-in root %ls is not in the registry\n", g_BuiltIn[i]);

    /* Every AuthRoot entry (the roots of caroots.inf and csroots.inf) is in the Root store too */
    Err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, AUTHROOT_PATH, 0, KEY_READ, &hAuth);
    if (Err == ERROR_SUCCESS)
    {
        for (i = 0; RegEnumKeyW(hAuth, i, Name, ARRAYSIZE(Name)) == ERROR_SUCCESS; i++)
        {
            AuthCount++;
            if (!HasBlob(hRoot, Name))
            {
                if (Missing++ < 5)
                    ok(0, "AuthRoot certificate %ls is not in the Root store\n", Name);
            }
        }
        RegCloseKey(hAuth);
    }
    ok(Missing == 0, "%lu of %lu AuthRoot certificates are missing from Root\n", Missing, AuthCount);

    for (i = 0; RegEnumKeyW(hRoot, i, Name, ARRAYSIZE(Name)) == ERROR_SUCCESS; i++)
        RootCount++;
    ok(RootCount >= AuthCount && RootCount >= ARRAYSIZE(g_BuiltIn),
       "Root holds %lu certificates, AuthRoot %lu\n", RootCount, AuthCount);
    trace("Root: %lu certificates, AuthRoot: %lu\n", RootCount, AuthCount);
    RegCloseKey(hRoot);

    TestStoreKeys();
}
