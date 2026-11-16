/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the check of the Winsock catalog the IPv6 upgrade (UpgradeNetworkCatalog) makes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The six MSAFD entries of nettcpip.inf share one provider id, so the upgrade has to look at the address family and
 * the protocol of the entry in a key as well: a catalog in which an LSP was moved to the top (the base entries are
 * pushed down, an IPv4 entry sits where the INF has an IPv6 one) must be left alone, not rewritten.
 *
 * The test changes the catalog of the running system (and puts it back): it runs only as an administrator with the
 * catalog the INF makes. Otherwise it skips.
 */

#include <apitest.h>
#include <windows.h>
#include <strsafe.h>

#define SERVICES        L"SYSTEM\\CurrentControlSet\\Services"
#define WINSOCK2        SERVICES L"\\Winsock2\\Parameters"
#define ENTRIES         WINSOCK2 L"\\Protocol_Catalog9\\Catalog_Entries"
#define STAMP_VALUE     L"Ipv6CatalogInf"
#define UPGRADE_ORDINAL 302
#define BLOB_MAX        1024

typedef BOOL (WINAPI *PFN_UPGRADE)(VOID);

static PFN_UPGRADE s_Upgrade;

static BOOL
ReadEntry(PCWSTR pszEntry, BYTE *Blob, DWORD *pSize)
{
    WCHAR szKey[128];
    HKEY hKey;
    DWORD Type, Size = BLOB_MAX;
    LONG Err;

    StringCchPrintfW(szKey, ARRAYSIZE(szKey), ENTRIES L"\\%s", pszEntry);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Err = RegQueryValueExW(hKey, L"PackedCatalogItem", NULL, &Type, Blob, &Size);
    RegCloseKey(hKey);
    if (Err != ERROR_SUCCESS || Type != REG_BINARY)
        return FALSE;
    *pSize = Size;
    return TRUE;
}

static BOOL
WriteEntry(PCWSTR pszEntry, const BYTE *Blob, DWORD Size)
{
    WCHAR szKey[128];
    HKEY hKey;
    LONG Err;

    StringCchPrintfW(szKey, ARRAYSIZE(szKey), ENTRIES L"\\%s", pszEntry);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Err = RegSetValueExW(hKey, L"PackedCatalogItem", 0, REG_BINARY, Blob, Size);
    RegCloseKey(hKey);
    return Err == ERROR_SUCCESS;
}

static BOOL
DeleteStamp(VOID)
{
    HKEY hKey;
    LONG Err;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINSOCK2, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Err = RegDeleteValueW(hKey, STAMP_VALUE);
    RegCloseKey(hKey);
    return Err == ERROR_SUCCESS || Err == ERROR_FILE_NOT_FOUND;
}

static BOOL
EntryExists(PCWSTR pszEntry)
{
    WCHAR szKey[128];
    HKEY hKey;

    StringCchPrintfW(szKey, ARRAYSIZE(szKey), ENTRIES L"\\%s", pszEntry);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

START_TEST(NetworkCatalogUpgrade)
{
    BYTE Entry1[BLOB_MAX], Entry4[BLOB_MAX], Check[BLOB_MAX];
    DWORD Size1, Size4, SizeCheck;
    HMODULE hUserenv;
    HKEY hKey;
    BOOL Ret;

    hUserenv = LoadLibraryW(L"userenv.dll");
    s_Upgrade = hUserenv ? (PFN_UPGRADE)GetProcAddress(hUserenv, MAKEINTRESOURCEA(UPGRADE_ORDINAL)) : NULL;
    if (!s_Upgrade)
    {
        skip("UpgradeNetworkCatalog is not exported\n");
        return;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ENTRIES L"\\000000000006", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
    {
        skip("The catalog has no entry 6 or it cannot be written (not an administrator?)\n");
        return;
    }
    RegCloseKey(hKey);
    if (!ReadEntry(L"000000000001", Entry1, &Size1) || !ReadEntry(L"000000000004", Entry4, &Size4))
    {
        skip("The catalog entries 1 and 4 cannot be read\n");
        return;
    }

    /* Control, the catalog in the order of the INF: entry 6 is gone, the upgrade adds it again */
    ok(DeleteStamp(), "The stamp could not be deleted\n");
    ok(RegDeleteKeyW(HKEY_LOCAL_MACHINE, ENTRIES L"\\000000000006") == ERROR_SUCCESS, "Entry 6 could not be deleted\n");
    Ret = s_Upgrade();
    ok(Ret, "UpgradeNetworkCatalog failed (%lu)\n", GetLastError());
    if (!EntryExists(L"000000000006"))
    {
        skip("The upgrade did not restore entry 6 (no INF or a catalog it leaves alone)\n");
        return;
    }
    ok(ReadEntry(L"000000000004", Check, &SizeCheck) && SizeCheck == Size4 && !memcmp(Check, Entry4, Size4),
       "Entry 4 changed by the upgrade of an intact catalog\n");

    /* Reordered: entry 4 holds the IPv4 entry that is entry 1 (same provider id, another family), entry 6 is gone.
       The provider ids all match, so only the family tells that this is not the catalog of the INF: left alone. */
    ok(DeleteStamp(), "The stamp could not be deleted\n");
    ok(WriteEntry(L"000000000004", Entry1, Size1), "Entry 4 could not be written\n");
    ok(RegDeleteKeyW(HKEY_LOCAL_MACHINE, ENTRIES L"\\000000000006") == ERROR_SUCCESS, "Entry 6 could not be deleted\n");
    Ret = s_Upgrade();
    ok(Ret, "UpgradeNetworkCatalog failed (%lu)\n", GetLastError());
    ok(!EntryExists(L"000000000006"), "A reordered catalog got entry 6 added\n");
    ok(ReadEntry(L"000000000004", Check, &SizeCheck) && SizeCheck == Size1 && !memcmp(Check, Entry1, Size1),
       "Entry 4 of a reordered catalog was rewritten\n");

    /* Put the catalog back: the original entry 4, then the upgrade adds entry 6 again */
    ok(WriteEntry(L"000000000004", Entry4, Size4), "Entry 4 could not be restored\n");
    ok(DeleteStamp(), "The stamp could not be deleted\n");
    s_Upgrade();
    ok(EntryExists(L"000000000006"), "Entry 6 was not restored\n");
    ok(ReadEntry(L"000000000004", Check, &SizeCheck) && SizeCheck == Size4 && !memcmp(Check, Entry4, Size4),
       "Entry 4 was not restored\n");
}
