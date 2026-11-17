/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for CertEnumSystemStore and opening the default system stores
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Windows lists the default system stores of the current user and of the
 * local machine; Cert:\CurrentUser and Cert:\LocalMachine of PowerShell are
 * built from this enumeration.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <wincrypt.h>

#define MAX_STORES 64

typedef struct _STORE_LIST
{
    ULONG Count;
    ULONG Duplicates;
    WCHAR Names[MAX_STORES][64];
} STORE_LIST;

static
BOOL
WINAPI
EnumCallback(
    _In_ const void *SystemStore,
    _In_ DWORD Flags,
    _In_ PCERT_SYSTEM_STORE_INFO StoreInfo,
    _In_ void *Reserved,
    _In_opt_ void *Arg)
{
    STORE_LIST *List = Arg;
    ULONG i;

    ok(SystemStore != NULL, "NULL store name\n");
    if (!SystemStore || List->Count >= MAX_STORES)
        return TRUE;

    for (i = 0; i < List->Count; i++)
    {
        if (!_wcsicmp(List->Names[i], SystemStore))
            List->Duplicates++;
    }
    wcsncpy(List->Names[List->Count], SystemStore, 63);
    List->Names[List->Count][63] = UNICODE_NULL;
    List->Count++;
    return TRUE;
}

static
BOOL
Contains(
    _In_ const STORE_LIST *List,
    _In_ PCWSTR Name)
{
    ULONG i;

    for (i = 0; i < List->Count; i++)
    {
        if (!_wcsicmp(List->Names[i], Name))
            return TRUE;
    }
    return FALSE;
}

static
void
CheckLocation(
    _In_ DWORD Location,
    _In_ PCSTR Text)
{
    static const PCWSTR Required[] = { L"My", L"Root", L"Trust", L"CA", L"TrustedPublisher", L"Disallowed", L"TrustedPeople" };
    STORE_LIST *List;
    HCERTSTORE Store;
    BOOL Ret;
    ULONG i;

    List = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*List));
    if (!List)
    {
        skip("Out of memory\n");
        return;
    }

    SetLastError(0xdeadbeef);
    Ret = CertEnumSystemStore(Location, NULL, List, EnumCallback);
    ok(Ret, "%s: CertEnumSystemStore failed with %lu\n", Text, GetLastError());
    ok(List->Count >= ARRAYSIZE(Required), "%s: only %lu stores\n", Text, List->Count);
    ok(List->Duplicates == 0, "%s: %lu duplicate store names\n", Text, List->Duplicates);
    for (i = 0; i < ARRAYSIZE(Required); i++)
        ok(Contains(List, Required[i]), "%s: store %ls is not listed\n", Text, Required[i]);

    /* The default My store can be opened for reading */
    SetLastError(0xdeadbeef);
    Store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                          Location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"My");
    ok(Store != NULL, "%s: opening My failed with %lu\n", Text, GetLastError());
    if (Store)
        CertCloseStore(Store, 0);

    HeapFree(GetProcessHeap(), 0, List);
}

START_TEST(CertEnumSystemStore)
{
    static const WCHAR RootPath[] = L"Software\\Microsoft\\SystemCertificates\\Root";
    HKEY Key;
    DWORD Disposition = 0;
    LONG Err;

    CheckLocation(CERT_SYSTEM_STORE_CURRENT_USER, "CurrentUser");
    CheckLocation(CERT_SYSTEM_STORE_LOCAL_MACHINE, "LocalMachine");

    /* Once the system roots are in the registry the Root key is enumerated
     * from there and must not be listed a second time. Make sure the key
     * exists, whatever the state of the machine was. */
    Err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, RootPath, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &Key, &Disposition);
    if (Err != ERROR_SUCCESS)
    {
        skip("Cannot create the Root key (%ld)\n", Err);
        return;
    }
    RegCloseKey(Key);
    CheckLocation(CERT_SYSTEM_STORE_LOCAL_MACHINE, "LocalMachine with Root key");
    if (Disposition == REG_CREATED_NEW_KEY)
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, RootPath);
}
