/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SHCreateSessionKey keeps its key in the user's hive, not in HKLM
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "shelltest.h"

typedef HRESULT (WINAPI *PFN_SHCREATESESSIONKEY)(REGSAM, PHKEY);

static const WCHAR SessionInfoPath[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo";

static DWORD
CountSubKeys(HKEY hRoot)
{
    HKEY hKey;
    DWORD dwCount = 0;

    if (RegOpenKeyExW(hRoot, SessionInfoPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &dwCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    RegCloseKey(hKey);
    return dwCount;
}

/* Windows 10 22H2, measured: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\<session id>
 * exists for the interactive session and HKLM has no SessionInfo key, so a standard user can use the call.
 * (From a non-interactive session 0 process the call itself failed with 0x80070002 there; that is not copied.) */
START_TEST(SHCreateSessionKey)
{
    PFN_SHCREATESESSIONKEY pfn;
    HKEY hKey = (HKEY)(ULONG_PTR)0xdeadbeef, hKey2 = NULL, hCheck;
    HRESULT hr;
    DWORD dwSession, dwMachineBefore, dwMachineAfter;
    WCHAR szPath[MAX_PATH];
    LONG lError;

    pfn = (PFN_SHCREATESESSIONKEY)GetProcAddress(GetModuleHandleW(L"shell32.dll"), (LPCSTR)723);
    if (!pfn)
    {
        skip("SHCreateSessionKey is not exported\n");
        return;
    }

    /* No access at all is refused and leaves a NULL key */
    hr = pfn(0, &hKey);
    ok(hr == E_ACCESSDENIED, "hr = 0x%lx\n", hr);
    ok(hKey == NULL, "hKey = %p\n", hKey);

    dwMachineBefore = CountSubKeys(HKEY_LOCAL_MACHINE);

    hr = pfn(KEY_READ, &hKey);
    ok(hr == S_OK, "hr = 0x%lx\n", hr);
    hr = pfn(KEY_READ, &hKey2);
    ok(hr == S_OK, "hr = 0x%lx\n", hr);
    ok(hKey != hKey2, "the same handle twice: %p\n", hKey);

    /* The key is per session, under HKCU */
    ProcessIdToSessionId(GetCurrentProcessId(), &dwSession);
    swprintf(szPath, _countof(szPath), L"%ls\\%lu", SessionInfoPath, dwSession);
    lError = RegOpenKeyExW(HKEY_CURRENT_USER, szPath, 0, KEY_READ, &hCheck);
    ok(lError == ERROR_SUCCESS, "HKCU\\%ls not found (error %ld)\n", szPath, lError);
    if (lError == ERROR_SUCCESS)
        RegCloseKey(hCheck);

    /* and nothing was created under HKLM */
    dwMachineAfter = CountSubKeys(HKEY_LOCAL_MACHINE);
    ok(dwMachineAfter == dwMachineBefore, "HKLM SessionInfo went from %lu to %lu subkeys\n",
       dwMachineBefore, dwMachineAfter);

    if (hKey)
        RegCloseKey(hKey);
    if (hKey2)
        RegCloseKey(hKey2);
}
