/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Fills the LocalMachine Root certificate store in the registry as SYSTEM (and
 *              creates the empty keys of the other stores), so that a standard user's
 *              first use of crypt32 never has to write to HKLM.
 *
 *   nitro-certseed           Open the Root store once (crypt32 imports its built-in roots
 *                            and the restricted AuthRoot entries into
 *                            HKLM\SOFTWARE\Microsoft\SystemCertificates\Root on that open,
 *                            when the registry lacks one) and print the number of roots.
 *   nitro-certseed /service  The same as an auto-start LocalSystem service: it runs at
 *                            every boot before anyone logs on, does nothing when the
 *                            store is up to date (the import writes only what is missing
 *                            or differs), and stops. It covers a fresh install, where
 *                            setup already did it, and an existing install that boots
 *                            with a newer crypt32 or root list.
 *
 * Windows has the roots in the hive from setup; the roots here come from the same
 * built-in list crypt32 imports (the AuthRoot entries of caroots.inf and csroots.inf plus
 * the Microsoft roots built into crypt32), so this adds no certificate data.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include <stdarg.h>
#include <stdio.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <wincrypt.h>

static SERVICE_STATUS_HANDLE g_hStatus;
static SERVICE_STATUS g_Status;

/* Opens the LocalMachine system store Name read-only (the open creates the
 * store's Certificates, CRLs and CTLs keys when they are missing, as the
 * caller that reads a store may not), returns its number of certificates or -1 */
static
int
OpenStoreOnce(PCWSTR Name)
{
    HCERTSTORE hStore;
    PCCERT_CONTEXT pCert = NULL;
    int Count = 0;

    hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                           CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
                           Name);
    if (!hStore)
        return -1;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL)
        Count++;
    CertCloseStore(hStore, 0);
    return Count;
}

/* Returns the number of certificates in the LocalMachine Root store, or -1.
 * The Root open runs the import (store.c). The other stores that exist in the
 * hive are opened too, so that none is left for a standard user to be the
 * first to open: it could not create the keys the open needs. */
static
int
SeedRootStore(VOID)
{
    HKEY hKey;
    WCHAR Name[256];
    DWORD i;
    int Count = OpenStoreOnce(L"Root");

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SystemCertificates", 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        for (i = 0; RegEnumKeyW(hKey, i, Name, ARRAYSIZE(Name)) == ERROR_SUCCESS; i++)
        {
            if (_wcsicmp(Name, L"Root"))
                OpenStoreOnce(Name);
        }
        RegCloseKey(hKey);
    }
    return Count;
}

static
VOID
WINAPI
ServiceHandler(DWORD Control)
{
    UNREFERENCED_PARAMETER(Control);
    SetServiceStatus(g_hStatus, &g_Status);
}

static
VOID
WINAPI
ServiceMain(DWORD argc, LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState = SERVICE_RUNNING;
    g_hStatus = RegisterServiceCtrlHandlerW(L"NitroCertSeed", ServiceHandler);
    if (!g_hStatus)
        return;
    SetServiceStatus(g_hStatus, &g_Status);

    SeedRootStore();

    g_Status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_hStatus, &g_Status);
}

int
wmain(int argc, WCHAR **argv)
{
    int Count;
    SERVICE_TABLE_ENTRYW Table[] = { { L"NitroCertSeed", ServiceMain }, { NULL, NULL } };

    if (argc > 1 && !_wcsicmp(argv[1], L"/service"))
        return StartServiceCtrlDispatcherW(Table) ? 0 : 1;

    Count = SeedRootStore();
    if (Count < 0)
    {
        wprintf(L"The Root store cannot be opened (error %lu)\n", GetLastError());
        return 1;
    }
    wprintf(L"The LocalMachine Root store holds %d certificates\n", Count);
    return 0;
}
