/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion "CurrentVersion" and its companions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 8.1 and Windows 10 22H2 store "6.3" in CurrentVersion (the real version is in
 * CurrentMajorVersionNumber/CurrentMinorVersionNumber, 10 and 0 on Windows 10). Installers compare
 * the string: Oracle Database XE says "Windows 8.1 or higher required" on "10.0".
 * Measured on Windows 10 22H2 build 19045: CurrentVersion REG_SZ "6.3", CurrentMajorVersionNumber
 * REG_DWORD 10, CurrentMinorVersionNumber REG_DWORD 0, CurrentBuild REG_SZ "19045", the same in the
 * 32-bit registry view (this test checks the 32-bit view only for CurrentVersion and the build).
 */

#include "precomp.h"

typedef LONG (WINAPI *PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);

static void CheckView(REGSAM View, const char *Name, const OSVERSIONINFOW *Real)
{
    HKEY Key;
    WCHAR Text[32];
    DWORD Type, Size, Number;
    LONG Result;
    WCHAR Expected[16];

    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                           KEY_QUERY_VALUE | View, &Key);
    ok(Result == ERROR_SUCCESS, "%s: RegOpenKeyEx failed with %ld\n", Name, Result);
    if (Result != ERROR_SUCCESS)
        return;

    /* Windows 8.1 and 10 both say 6.3 */
    if (Real->dwMajorVersion >= 10 || (Real->dwMajorVersion == 6 && Real->dwMinorVersion == 3))
        wcscpy(Expected, L"6.3");
    else
        swprintf(Expected, ARRAYSIZE(Expected), L"%lu.%lu", Real->dwMajorVersion, Real->dwMinorVersion);

    Size = sizeof(Text);
    Result = RegQueryValueExW(Key, L"CurrentVersion", NULL, &Type, (BYTE *)Text, &Size);
    ok(Result == ERROR_SUCCESS, "%s: CurrentVersion failed with %ld\n", Name, Result);
    if (Result == ERROR_SUCCESS)
    {
        ok(Type == REG_SZ, "%s: CurrentVersion type %lu\n", Name, Type);
        ok(!wcscmp(Text, Expected), "%s: CurrentVersion is \"%ls\", expected \"%ls\"\n", Name, Text, Expected);
    }

    /* the 32-bit view of this system lacks the other values (ticket follows); only CurrentVersion and the build are shared */
    if (Real->dwMajorVersion >= 10 && View == KEY_WOW64_64KEY)
    {
        Size = sizeof(Number);
        Result = RegQueryValueExW(Key, L"CurrentMajorVersionNumber", NULL, &Type, (BYTE *)&Number, &Size);
        ok(Result == ERROR_SUCCESS, "%s: CurrentMajorVersionNumber failed with %ld\n", Name, Result);
        if (Result == ERROR_SUCCESS)
            ok(Type == REG_DWORD && Number == Real->dwMajorVersion, "%s: CurrentMajorVersionNumber type %lu value %lu\n",
               Name, Type, Number);
    }

    Size = sizeof(Text);
    Result = RegQueryValueExW(Key, L"CurrentBuildNumber", NULL, &Type, (BYTE *)Text, &Size);
    ok(Result == ERROR_SUCCESS, "%s: CurrentBuildNumber failed with %ld\n", Name, Result);
    if (Result == ERROR_SUCCESS)
    {
        WCHAR Build[16];
        swprintf(Build, ARRAYSIZE(Build), L"%lu", Real->dwBuildNumber);
        ok(!wcscmp(Text, Build), "%s: CurrentBuildNumber is \"%ls\", expected \"%ls\"\n", Name, Text, Build);
    }
    RegCloseKey(Key);
}

START_TEST(RegCurrentVersion)
{
    PFN_RtlGetVersion pRtlGetVersion = (PFN_RtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    OSVERSIONINFOW Real = { sizeof(Real) };
    LONG Status;

    if (!pRtlGetVersion)
    {
        skip("RtlGetVersion is not available\n");
        return;
    }
    /* RtlGetVersion gives the real version whatever the manifest says */
    Status = pRtlGetVersion(&Real);
    ok(Status == 0, "RtlGetVersion failed with %08lx\n", Status);

    CheckView(KEY_WOW64_64KEY, "64-bit view", &Real);
    CheckView(KEY_WOW64_32KEY, "32-bit view", &Real);
}
