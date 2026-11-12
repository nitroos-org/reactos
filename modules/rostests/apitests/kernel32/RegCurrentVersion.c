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
 * REG_DWORD 10, CurrentMinorVersionNumber REG_DWORD 0, CurrentBuild REG_SZ "19045", ProductName and
 * EditionID REG_SZ, the same in the 32-bit registry view: Windows 10 22H2 gave identical type and data for
 * all of them in both views. 32-bit installers read these from Wow6432Node, so both views are checked
 * here, and the two views are compared value by value.
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

    if (Real->dwMajorVersion >= 10)
    {
        static const WCHAR *const Numbers[] = { L"CurrentMajorVersionNumber", L"CurrentMinorVersionNumber" };
        const DWORD Want[] = { Real->dwMajorVersion, Real->dwMinorVersion };
        static const WCHAR *const Strings[] = { L"CurrentBuild", L"ProductName", L"EditionID" };
        ULONG i;

        for (i = 0; i < ARRAYSIZE(Numbers); i++)
        {
            Size = sizeof(Number);
            Number = 0xdeadbeef;
            Result = RegQueryValueExW(Key, Numbers[i], NULL, &Type, (BYTE *)&Number, &Size);
            ok(Result == ERROR_SUCCESS, "%s: %ls failed with %ld\n", Name, Numbers[i], Result);
            if (Result == ERROR_SUCCESS)
                ok(Type == REG_DWORD && Number == Want[i], "%s: %ls type %lu value %lu, expected %lu\n",
                   Name, Numbers[i], Type, Number, Want[i]);
        }
        for (i = 0; i < ARRAYSIZE(Strings); i++)
        {
            Size = sizeof(Text);
            Result = RegQueryValueExW(Key, Strings[i], NULL, &Type, (BYTE *)Text, &Size);
            ok(Result == ERROR_SUCCESS, "%s: %ls failed with %ld\n", Name, Strings[i], Result);
            if (Result == ERROR_SUCCESS)
                ok(Type == REG_SZ && Text[0], "%s: %ls type %lu value \"%ls\"\n", Name, Strings[i], Type, Text);
        }
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

/* Windows has the same version values in both views (measured on 22H2); a value one view has, the other has too */
static void CompareViews(void)
{
    static const WCHAR *const Names[] =
    {
        L"CurrentVersion", L"CurrentMajorVersionNumber", L"CurrentMinorVersionNumber", L"CurrentBuild",
        L"CurrentBuildNumber", L"ProductName", L"EditionID", L"DisplayVersion", L"UBR", L"BuildLab", L"BuildLabEx",
        L"CurrentType", L"SystemRoot", L"CompositionEditionID", L"InstallationType"
    };
    HKEY Key64, Key32;
    ULONG i;
    LONG Result;

    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                           KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key64);
    ok(Result == ERROR_SUCCESS, "64-bit view: RegOpenKeyEx failed with %ld\n", Result);
    if (Result != ERROR_SUCCESS)
        return;
    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                           KEY_QUERY_VALUE | KEY_WOW64_32KEY, &Key32);
    ok(Result == ERROR_SUCCESS, "32-bit view: RegOpenKeyEx failed with %ld\n", Result);
    if (Result != ERROR_SUCCESS)
    {
        RegCloseKey(Key64);
        return;
    }

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        BYTE Data64[256], Data32[256];
        DWORD Type64 = 0, Type32 = 0, Size64 = sizeof(Data64), Size32 = sizeof(Data32);
        LONG R64 = RegQueryValueExW(Key64, Names[i], NULL, &Type64, Data64, &Size64);
        LONG R32 = RegQueryValueExW(Key32, Names[i], NULL, &Type32, Data32, &Size32);

        ok(R64 == R32, "%ls: 64-bit view returns %ld, 32-bit view returns %ld\n", Names[i], R64, R32);
        if (R64 != ERROR_SUCCESS || R32 != ERROR_SUCCESS)
            continue;
        ok(Type64 == Type32, "%ls: type %lu in the 64-bit view, %lu in the 32-bit view\n", Names[i], Type64, Type32);
        ok(Size64 == Size32 && !memcmp(Data64, Data32, Size64 < Size32 ? Size64 : Size32),
           "%ls: data differs between the views (%lu and %lu bytes)\n", Names[i], Size64, Size32);
    }
    RegCloseKey(Key32);
    RegCloseKey(Key64);
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
    CheckView(0, "default view", &Real);
    CompareViews();
}
