/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Seed marker of the LocalMachine Root store: shared by setup (syssetup) and
 *              the NitroCertSeed boot service, which skips its store opens when it matches
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The marker is the REG_BINARY value SeedMarker of
 * HKLM\SYSTEM\CurrentControlSet\Services\NitroCertSeed. It records what the built-in root
 * list was made of when the Root store was last seeded: the size and write time of crypt32.dll
 * (which carries the built-in Microsoft roots and the import code), the number of entries and
 * write time of the AuthRoot key (the roots of caroots.inf/csroots.inf), and the number of
 * entries and write time of the Root key itself, taken after the seed. A different crypt32,
 * a different AuthRoot list, or a Root key that was emptied or otherwise changed since
 * gives a different marker, so the store is seeded again.
 *
 * The values are read from file attributes and registry key information only; no
 * certificate store is opened.
 */

#ifndef _REACTOS_CERTSEED_H
#define _REACTOS_CERTSEED_H

#include <string.h>

#define CERTSEED_SERVICE_KEY   L"SYSTEM\\CurrentControlSet\\Services\\NitroCertSeed"
#define CERTSEED_MARKER_VALUE  L"SeedMarker"
#define CERTSEED_MARKER_VERSION 1
/* Diagnostics the service leaves: its last run's time in ms and whether it skipped (1) or seeded (0) */
#define CERTSEED_RUNMS_VALUE   L"LastRunMs"
#define CERTSEED_SKIPPED_VALUE L"LastRunSkipped"

/* DWORDs only, so there is no padding and two markers compare with memcmp */
typedef struct _CERTSEED_MARKER
{
    DWORD Version;
    DWORD Crypt32SizeHigh;
    DWORD Crypt32SizeLow;
    DWORD Crypt32TimeHigh;
    DWORD Crypt32TimeLow;
    DWORD AuthCount;
    DWORD AuthTimeHigh;
    DWORD AuthTimeLow;
    DWORD RootCount;
    DWORD RootTimeHigh;
    DWORD RootTimeLow;
} CERTSEED_MARKER;

static inline
VOID
CertSeedKeyInfo(PCWSTR Path, DWORD *pCount, FILETIME *pTime)
{
    HKEY hKey;

    *pCount = 0;
    pTime->dwLowDateTime = pTime->dwHighDateTime = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegQueryInfoKeyW(hKey, NULL, NULL, NULL, pCount, NULL, NULL, NULL, NULL, NULL, NULL,
                         pTime);
        RegCloseKey(hKey);
    }
}

/* Fills Marker with the current state of crypt32.dll, AuthRoot and Root */
static inline
VOID
CertSeedGetState(CERTSEED_MARKER *Marker)
{
    WCHAR szPath[MAX_PATH + 16];
    WIN32_FILE_ATTRIBUTE_DATA Data;
    FILETIME Time;
    UINT Len;

    ZeroMemory(Marker, sizeof(*Marker));
    Marker->Version = CERTSEED_MARKER_VERSION;

    Len = GetSystemDirectoryW(szPath, MAX_PATH);
    if (Len && Len < MAX_PATH)
    {
        lstrcpyW(szPath + Len, L"\\crypt32.dll");
        if (GetFileAttributesExW(szPath, GetFileExInfoStandard, &Data))
        {
            Marker->Crypt32SizeHigh = Data.nFileSizeHigh;
            Marker->Crypt32SizeLow = Data.nFileSizeLow;
            Marker->Crypt32TimeHigh = Data.ftLastWriteTime.dwHighDateTime;
            Marker->Crypt32TimeLow = Data.ftLastWriteTime.dwLowDateTime;
        }
    }

    CertSeedKeyInfo(L"SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates",
                    &Marker->AuthCount, &Time);
    Marker->AuthTimeHigh = Time.dwHighDateTime;
    Marker->AuthTimeLow = Time.dwLowDateTime;

    CertSeedKeyInfo(L"SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates",
                    &Marker->RootCount, &Time);
    Marker->RootTimeHigh = Time.dwHighDateTime;
    Marker->RootTimeLow = Time.dwLowDateTime;
}

/* TRUE when the stored marker is the current state and the Root key holds certificates */
static inline
BOOL
CertSeedMarkerCurrent(VOID)
{
    CERTSEED_MARKER Now, Stored;
    HKEY hKey;
    DWORD Type, Size = sizeof(Stored);
    BOOL Ret = FALSE;

    CertSeedGetState(&Now);
    if (!Now.RootCount)
        return FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CERTSEED_SERVICE_KEY, 0, KEY_QUERY_VALUE,
                      &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, CERTSEED_MARKER_VALUE, NULL, &Type, (PBYTE)&Stored,
                         &Size) == ERROR_SUCCESS &&
        Type == REG_BINARY && Size == sizeof(Stored))
        Ret = !memcmp(&Now, &Stored, sizeof(Now));
    RegCloseKey(hKey);
    return Ret;
}

/* Records the current state as the seeded one (call after the Root store was opened) */
static inline
BOOL
CertSeedWriteMarker(VOID)
{
    CERTSEED_MARKER Now;
    HKEY hKey;
    LONG Err;

    CertSeedGetState(&Now);
    if (!Now.RootCount)
        return FALSE;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, CERTSEED_SERVICE_KEY, 0, NULL, 0, KEY_SET_VALUE,
                        NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;
    Err = RegSetValueExW(hKey, CERTSEED_MARKER_VALUE, 0, REG_BINARY, (const BYTE *)&Now,
                         sizeof(Now));
    RegCloseKey(hKey);
    return Err == ERROR_SUCCESS;
}

/* The service records how its last run went (for the apitest and boot-time measurements) */
static inline
VOID
CertSeedWriteRun(DWORD Ms, DWORD Skipped)
{
    HKEY hKey;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, CERTSEED_SERVICE_KEY, 0, NULL, 0, KEY_SET_VALUE,
                        NULL, &hKey, NULL) != ERROR_SUCCESS)
        return;
    RegSetValueExW(hKey, CERTSEED_RUNMS_VALUE, 0, REG_DWORD, (const BYTE *)&Ms, sizeof(Ms));
    RegSetValueExW(hKey, CERTSEED_SKIPPED_VALUE, 0, REG_DWORD, (const BYTE *)&Skipped,
                   sizeof(Skipped));
    RegCloseKey(hKey);
}

#endif /* _REACTOS_CERTSEED_H */
