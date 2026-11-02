/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The shell reads HKLM ProfileList and never writes it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"

static const WCHAR ProfileListKey[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
static const WCHAR ValueName[] = L"ProfilesDirectory";

/* Windows only reads ProfileList when it expands %VARIABLES% in a shell folder path, so a
 * standard user (who has KEY_READ there and nothing more) gets the same results as an administrator.
 * Take the value away, resolve folders that need the expansion, and check that the shell did not put
 * it back. The test needs write access to the key to set that up and skips without it. */
START_TEST(ProfileListAccess)
{
    static const int s_Csidl[] = { CSIDL_COMMON_APPDATA, CSIDL_APPDATA, CSIDL_PROFILE, CSIDL_COMMON_DESKTOPDIRECTORY };
    HKEY hKey;
    WCHAR szSaved[MAX_PATH];
    DWORD dwType = REG_NONE, dwSize = sizeof(szSaved);
    LONG lError;
    BOOL bHadValue;
    WCHAR szPath[MAX_PATH];
    HRESULT hr;
    UINT i;

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ProfileListKey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
    if (lError != ERROR_SUCCESS)
    {
        skip("No write access to ProfileList (error %ld)\n", lError);
        return;
    }

    lError = RegQueryValueExW(hKey, ValueName, NULL, &dwType, (LPBYTE)szSaved, &dwSize);
    bHadValue = (lError == ERROR_SUCCESS);
    if (!bHadValue)
        dwSize = 0;

    if (bHadValue)
    {
        lError = RegDeleteValueW(hKey, ValueName);
        ok_long(lError, ERROR_SUCCESS);
    }

    for (i = 0; i < _countof(s_Csidl); i++)
    {
        szPath[0] = UNICODE_NULL;
        hr = SHGetFolderPathW(NULL, s_Csidl[i], NULL, SHGFP_TYPE_CURRENT, szPath);
        ok(hr == S_OK, "SHGetFolderPathW(0x%x) returned 0x%lx\n", s_Csidl[i], hr);
        ok(szPath[0] != UNICODE_NULL, "SHGetFolderPathW(0x%x) returned an empty path\n", s_Csidl[i]);
    }

    dwSize = sizeof(szPath);
    lError = RegQueryValueExW(hKey, ValueName, NULL, NULL, (LPBYTE)szPath, &dwSize);
    ok(lError == ERROR_FILE_NOT_FOUND, "ProfilesDirectory was written back by the shell (error %ld)\n", lError);

    /* Put the machine back as it was */
    if (bHadValue)
        RegSetValueExW(hKey, ValueName, 0, dwType, (const BYTE *)szSaved, (DWORD)(wcslen(szSaved) + 1) * sizeof(WCHAR));
    else
        RegDeleteValueW(hKey, ValueName);
    RegCloseKey(hKey);
}
