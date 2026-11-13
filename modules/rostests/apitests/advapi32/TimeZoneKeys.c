/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the Time Zones registry list: the UTC zone, the MUI_* strings in tzres.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef LONG (WINAPI *FN_REGLOADMUISTRINGW)(HKEY, LPCWSTR, LPWSTR, DWORD, LPDWORD, DWORD, LPCWSTR);
typedef DWORD (WINAPI *FN_ENUMTZ)(DWORD, DYNAMIC_TIME_ZONE_INFORMATION *);

#define ZONES_KEY L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"

typedef struct _TZI_FORMAT
{
    LONG Bias;
    LONG StandardBias;
    LONG DaylightBias;
    SYSTEMTIME StandardDate;
    SYSTEMTIME DaylightDate;
} TZI_FORMAT;

/* like Windows, the module is searched in the base directory (or the current one), not in system32 by itself */
static WCHAR g_SysDir[MAX_PATH];

static void TestMuiValue(FN_REGLOADMUISTRINGW pLoad, HKEY Zone, PCWSTR Zonename, PCWSTR Mui, PCWSTR Plain)
{
    WCHAR Text[256], Expected[256];
    DWORD Size, Type;
    LONG Err;

    Size = sizeof(Text);
    memset(Text, 0, sizeof(Text));
    Err = pLoad(Zone, Mui, Text, Size, &Size, 0, g_SysDir);
    ok(Err == ERROR_SUCCESS, "%ls %ls: error %ld\n", Zonename, Mui, Err);
    ok(Text[0] != 0, "%ls %ls: empty\n", Zonename, Mui);

    /* the plain value is the same text for the language of the registry's strings */
    Size = sizeof(Expected);
    Type = 0;
    if (!RegQueryValueExW(Zone, Plain, NULL, &Type, (PBYTE)Expected, &Size) && Type == REG_SZ && !wcscmp(Expected, Text))
        return;
    trace("%ls: %ls differs from %ls (%ls / %ls)\n", Zonename, Mui, Plain, Text, Expected);
}

/* Windows 10 style: every Display text starts with "(UTC" (the localized ReactOS strings follow it) */
static void TestDisplayStyle(HKEY Zone, PCWSTR Name)
{
    WCHAR Text[256];
    DWORD Size = sizeof(Text), Type = 0;

    ZeroMemory(Text, sizeof(Text));
    if (RegQueryValueExW(Zone, L"Display", NULL, &Type, (PBYTE)Text, &Size) == ERROR_SUCCESS && Type == REG_SZ)
    {
        ok(!wcsncmp(Text, L"(UTC", 4), "%ls: Display '%ls' is not in the (UTC...) style\n", Name, Text);
        ok(wcsncmp(Text, L"(GMT", 4), "%ls: Display '%ls' starts with (GMT\n", Name, Text);
    }
}

/* The zones with IANA-derived per-year data: the entries are 44 bytes, FirstEntry..LastEntry has no gap */
static const struct { PCWSTR Name; DWORD First; } g_DynamicZones[] =
{
    { L"British Columbia Standard Time", 2000 },
    { L"Alberta Standard Time", 2000 },
    { L"Manitoba Standard Time", 2000 },
    { L"Paraguay Standard Time", 2000 },
    { L"Morocco Standard Time", 2000 },
};

static void TestDynamicDst(HKEY Zones)
{
    ULONG i;
    DWORD Year;

    for (i = 0; i < ARRAYSIZE(g_DynamicZones); i++)
    {
        HKEY Dst;
        DWORD First = 0, Last = 0, Size, Type;
        TZI_FORMAT Tzi;
        WCHAR Path[128], YearName[16];
        LONG Err;

        StringCchPrintfW(Path, ARRAYSIZE(Path), L"%ls\\Dynamic DST", g_DynamicZones[i].Name);
        Err = RegOpenKeyExW(Zones, Path, 0, KEY_QUERY_VALUE, &Dst);
        ok(Err == ERROR_SUCCESS, "%ls: no Dynamic DST key (%ld)\n", g_DynamicZones[i].Name, Err);
        if (Err != ERROR_SUCCESS)
            continue;
        Size = sizeof(First);
        Err = RegQueryValueExW(Dst, L"FirstEntry", NULL, &Type, (PBYTE)&First, &Size);
        ok(Err == ERROR_SUCCESS && Type == REG_DWORD, "%ls: FirstEntry %ld\n", g_DynamicZones[i].Name, Err);
        Size = sizeof(Last);
        Err = RegQueryValueExW(Dst, L"LastEntry", NULL, &Type, (PBYTE)&Last, &Size);
        ok(Err == ERROR_SUCCESS && Type == REG_DWORD, "%ls: LastEntry %ld\n", g_DynamicZones[i].Name, Err);
        ok(First == g_DynamicZones[i].First, "%ls: FirstEntry %lu\n", g_DynamicZones[i].Name, First);
        ok(Last >= 2027, "%ls: LastEntry %lu does not cover 2027\n", g_DynamicZones[i].Name, Last);

        for (Year = First; Year <= Last && Year < 3000; Year++)
        {
            StringCchPrintfW(YearName, ARRAYSIZE(YearName), L"%lu", Year);
            Size = sizeof(Tzi);
            Type = 0;
            Err = RegQueryValueExW(Dst, YearName, NULL, &Type, (PBYTE)&Tzi, &Size);
            ok(Err == ERROR_SUCCESS && Type == REG_BINARY && Size == sizeof(Tzi), "%ls %lu: %ld %lu %lu\n",
               g_DynamicZones[i].Name, Year, Err, Type, Size);
            if (Err == ERROR_SUCCESS && Size == sizeof(Tzi) && Tzi.StandardDate.wMonth)
            {
                ok(Tzi.DaylightDate.wMonth, "%ls %lu: standard date without daylight date\n", g_DynamicZones[i].Name, Year);
                ok(Tzi.DaylightBias == -60, "%ls %lu: daylight bias %ld\n", g_DynamicZones[i].Name, Year, Tzi.DaylightBias);
            }
        }
        RegCloseKey(Dst);
    }
}

START_TEST(TimeZoneKeys)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    FN_REGLOADMUISTRINGW pLoad = (FN_REGLOADMUISTRINGW)GetProcAddress(hAdvapi32, "RegLoadMUIStringW");
    FN_ENUMTZ pEnumTz = (FN_ENUMTZ)GetProcAddress(hAdvapi32, "EnumDynamicTimeZoneInformation");
    HKEY Zones, Zone;
    WCHAR Name[256];
    DWORD Index, Count = 0, Size, Type, Ret;
    TZI_FORMAT Tzi;
    BOOL FoundUtc = FALSE;
    DYNAMIC_TIME_ZONE_INFORMATION Info;

    if (!pLoad)
    {
        skip("RegLoadMUIStringW is not available\n");
        return;
    }

    GetSystemDirectoryW(g_SysDir, ARRAYSIZE(g_SysDir));

    Ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ZONES_KEY, 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &Zones);
    ok(Ret == ERROR_SUCCESS, "got %lu\n", Ret);
    if (Ret != ERROR_SUCCESS)
        return;

    for (Index = 0; !RegEnumKeyW(Zones, Index, Name, ARRAYSIZE(Name)); Index++)
    {
        Count++;
        if (RegOpenKeyExW(Zones, Name, 0, KEY_QUERY_VALUE, &Zone))
        {
            ok(0, "cannot open %ls\n", Name);
            continue;
        }
        Size = sizeof(Tzi);
        Type = 0;
        Ret = RegQueryValueExW(Zone, L"TZI", NULL, &Type, (PBYTE)&Tzi, &Size);
        ok(Ret == ERROR_SUCCESS && Type == REG_BINARY && Size == sizeof(Tzi), "%ls: TZI %lu %lu %lu\n", Name, Ret, Type, Size);
        TestMuiValue(pLoad, Zone, Name, L"MUI_Display", L"Display");
        TestMuiValue(pLoad, Zone, Name, L"MUI_Dlt", L"Dlt");
        TestMuiValue(pLoad, Zone, Name, L"MUI_Std", L"Std");
        TestDisplayStyle(Zone, Name);

        if (!wcscmp(Name, L"UTC"))
        {
            WCHAR Std[64];

            FoundUtc = TRUE;
            ok(Tzi.Bias == 0 && Tzi.StandardBias == 0 && Tzi.DaylightBias == 0, "UTC bias %ld %ld %ld\n",
               Tzi.Bias, Tzi.StandardBias, Tzi.DaylightBias);
            ok(!Tzi.StandardDate.wMonth && !Tzi.DaylightDate.wMonth, "UTC has transition dates\n");
            Size = sizeof(Std);
            Ret = pLoad(Zone, L"MUI_Std", Std, Size, &Size, 0, g_SysDir);
            ok(Ret == ERROR_SUCCESS && !wcscmp(Std, L"Coordinated Universal Time"), "UTC MUI_Std %lu %ls\n", Ret, Std);
        }
        RegCloseKey(Zone);
    }
    ok(FoundUtc, "no UTC zone\n");
    if (is_reactos())
        TestDynamicDst(Zones);
    ok(Count >= 140, "only %lu zones\n", Count);

    if (pEnumTz)
    {
        BOOL Seen = FALSE;

        for (Index = 0; Index < 1000; Index++)
        {
            memset(&Info, 0xcc, sizeof(Info));
            if (pEnumTz(Index, &Info) != ERROR_SUCCESS)
                break;
            if (!wcscmp(Info.TimeZoneKeyName, L"UTC"))
            {
                Seen = TRUE;
                ok(Info.Bias == 0, "UTC enumerated with bias %ld\n", Info.Bias);
            }
        }
        ok(Index == Count, "enumerated %lu zones, the key has %lu\n", Index, Count);
        ok(Seen, "UTC is not enumerated\n");
    }
    RegCloseKey(Zones);
}
