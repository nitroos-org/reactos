/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for EnumDynamicTimeZoneInformation and GetDynamicTimeZoneInformationEffectiveYears
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 22H2 (x64 and x86) has 141 zones, sorted by name, enumerates them with ERROR_NO_MORE_ITEMS at the end
 * and for any index beyond it, ERROR_INVALID_PARAMETER for a NULL buffer, and answers ERROR_FILE_NOT_FOUND for the
 * effective years of a zone without a "Dynamic DST" key, of an empty name and of a name that is not a zone.
 * The registry part (a zone with a Dynamic DST key) is only checked on ReactOS, it creates a zone for the test.
 */

#include "precomp.h"

typedef DWORD (WINAPI *FN_ENUMTZ)(DWORD, DYNAMIC_TIME_ZONE_INFORMATION *);
typedef DWORD (WINAPI *FN_YEARS)(const DYNAMIC_TIME_ZONE_INFORMATION *, DWORD *, DWORD *);

#define ZONES_KEY L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
#define TEST_ZONE L"Advexp Test Standard Time"

static void DeleteZone(HKEY Zones)
{
    RegDeleteKeyW(Zones, TEST_ZONE L"\\Dynamic DST");
    RegDeleteKeyW(Zones, TEST_ZONE);
}

static void TestOwnZone(FN_ENUMTZ pEnumTz, FN_YEARS pYears)
{
    HKEY Zones, Zone, Dynamic;
    struct { LONG Bias, StdBias, DltBias; SYSTEMTIME Std, Dlt; } Tzi = { -123, 0, -60, { 0, 10, 0, 5, 3 }, { 0, 3, 0, 5, 2 } };
    DYNAMIC_TIME_ZONE_INFORMATION Info;
    DWORD Index, Ret, First = 0xAAAA, Last = 0xBBBB, Year;
    BOOL Found = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ZONES_KEY, 0, KEY_ALL_ACCESS, &Zones))
    {
        skip("Cannot open the Time Zones key for writing\n");
        return;
    }
    DeleteZone(Zones);
    if (RegCreateKeyExW(Zones, TEST_ZONE, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Zone, NULL))
    {
        RegCloseKey(Zones);
        skip("Cannot create a zone\n");
        return;
    }
    RegSetValueExW(Zone, L"TZI", 0, REG_BINARY, (BYTE *)&Tzi, sizeof(Tzi));
    RegSetValueExW(Zone, L"Std", 0, REG_SZ, (BYTE *)L"Advexp Std", sizeof(L"Advexp Std"));
    RegSetValueExW(Zone, L"Dlt", 0, REG_SZ, (BYTE *)L"Advexp Dlt", sizeof(L"Advexp Dlt"));

    for (Index = 0; Index < 1000; Index++)
    {
        memset(&Info, 0xcc, sizeof(Info));
        Ret = pEnumTz(Index, &Info);
        if (Ret != ERROR_SUCCESS)
            break;
        if (!wcscmp(Info.TimeZoneKeyName, TEST_ZONE))
        {
            Found = TRUE;
            ok(Info.Bias == -123 && Info.StandardBias == 0 && Info.DaylightBias == -60, "biases %ld %ld %ld\n", Info.Bias, Info.StandardBias, Info.DaylightBias);
            ok(Info.StandardDate.wMonth == 10 && Info.StandardDate.wDay == 5 && Info.StandardDate.wHour == 3, "standard date\n");
            ok(Info.DaylightDate.wMonth == 3 && Info.DaylightDate.wDay == 5 && Info.DaylightDate.wHour == 2, "daylight date\n");
            ok(!wcscmp(Info.StandardName, L"Advexp Std") && !wcscmp(Info.DaylightName, L"Advexp Dlt"), "names %ls, %ls\n", Info.StandardName, Info.DaylightName);
            ok(Info.DynamicDaylightTimeDisabled == FALSE, "disabled flag %d\n", Info.DynamicDaylightTimeDisabled);
        }
    }
    ok(Found, "the test zone is not enumerated\n");

    /* no Dynamic DST key yet */
    First = 0xAAAA; Last = 0xBBBB;
    wcscpy(Info.TimeZoneKeyName, TEST_ZONE);
    Ret = pYears(&Info, &First, &Last);
    ok(Ret == ERROR_FILE_NOT_FOUND && First == 0xAAAA && Last == 0xBBBB, "no Dynamic DST key: %lu, %lx, %lx\n", Ret, First, Last);

    if (!RegCreateKeyExW(Zone, L"Dynamic DST", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Dynamic, NULL))
    {
        Year = 2006;
        RegSetValueExW(Dynamic, L"FirstEntry", 0, REG_DWORD, (BYTE *)&Year, sizeof(Year));
        Ret = pYears(&Info, &First, &Last);
        ok(Ret == ERROR_FILE_NOT_FOUND, "LastEntry missing: %lu\n", Ret);
        Year = 2007;
        RegSetValueExW(Dynamic, L"LastEntry", 0, REG_DWORD, (BYTE *)&Year, sizeof(Year));
        Ret = pYears(&Info, &First, &Last);
        ok(Ret == ERROR_SUCCESS && First == 2006 && Last == 2007, "effective years: %lu, %lu, %lu\n", Ret, First, Last);
        wcscpy(Info.TimeZoneKeyName, L"advexp test standard time");
        First = Last = 0;
        Ret = pYears(&Info, &First, &Last);
        ok(Ret == ERROR_SUCCESS && First == 2006 && Last == 2007, "case of the name: %lu, %lu, %lu\n", Ret, First, Last);
        RegCloseKey(Dynamic);
    }

    RegCloseKey(Zone);
    DeleteZone(Zones);
    RegCloseKey(Zones);
}

START_TEST(DynamicTimeZone)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    FN_ENUMTZ pEnumTz = (FN_ENUMTZ)GetProcAddress(hAdvapi32, "EnumDynamicTimeZoneInformation");
    FN_YEARS pYears = (FN_YEARS)GetProcAddress(hAdvapi32, "GetDynamicTimeZoneInformationEffectiveYears");
    DYNAMIC_TIME_ZONE_INFORMATION Info, Previous;
    DWORD Index, Ret, First, Last;
    BOOL Sorted = TRUE;

    if (!pEnumTz && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pEnumTz && pYears, "not exported: %p %p\n", pEnumTz, pYears);
    if (!pEnumTz || !pYears)
        return;

    memset(&Previous, 0, sizeof(Previous));
    for (Index = 0; Index < 1000; Index++)
    {
        memset(&Info, 0xcc, sizeof(Info));
        Ret = pEnumTz(Index, &Info);
        if (Ret != ERROR_SUCCESS)
            break;
        ok(Info.TimeZoneKeyName[0] != 0, "zone %lu has no key name\n", Index);
        ok(Info.StandardName[0] != 0 && Info.DaylightName[0] != 0, "zone %ls has no names\n", Info.TimeZoneKeyName);
        ok(Info.DynamicDaylightTimeDisabled == FALSE, "zone %ls: disabled flag %d\n", Info.TimeZoneKeyName, Info.DynamicDaylightTimeDisabled);
        if (Index && _wcsicmp(Previous.TimeZoneKeyName, Info.TimeZoneKeyName) >= 0)
            Sorted = FALSE;
        Previous = Info;

        /* the years of an enumerated zone: a success has a range, otherwise the zone has no Dynamic DST key */
        First = 0xAAAA;
        Last = 0xBBBB;
        Ret = pYears(&Info, &First, &Last);
        ok((Ret == ERROR_SUCCESS && First <= Last) || (Ret == ERROR_FILE_NOT_FOUND && First == 0xAAAA && Last == 0xBBBB),
           "zone %ls years: %lu, %lu, %lu\n", Info.TimeZoneKeyName, Ret, First, Last);
    }
    ok(Ret == ERROR_NO_MORE_ITEMS, "the end of the zones: %lu\n", Ret);
    ok(Index > 0, "no zones\n");
    ok(Sorted, "the zones are not sorted by name\n");

    memset(&Info, 0xcc, sizeof(Info));
    Ret = pEnumTz(100000, &Info);
    ok(Ret == ERROR_NO_MORE_ITEMS, "index 100000: %lu\n", Ret);
    Ret = pEnumTz(0xffffffff, &Info);
    ok(Ret == ERROR_NO_MORE_ITEMS, "index -1: %lu\n", Ret);
    Ret = pEnumTz(0, NULL);
    ok(Ret == ERROR_INVALID_PARAMETER, "NULL buffer: %lu\n", Ret);

    memset(&Info, 0, sizeof(Info));
    First = 0xAAAA;
    Last = 0xBBBB;
    Ret = pYears(&Info, &First, &Last);
    ok(Ret == ERROR_FILE_NOT_FOUND && First == 0xAAAA && Last == 0xBBBB, "empty name: %lu, %lx, %lx\n", Ret, First, Last);
    wcscpy(Info.TimeZoneKeyName, L"No Such Zone Standard Time");
    Ret = pYears(&Info, &First, &Last);
    ok(Ret == ERROR_FILE_NOT_FOUND && First == 0xAAAA && Last == 0xBBBB, "unknown name: %lu, %lx, %lx\n", Ret, First, Last);

    if (is_reactos())
        TestOwnZone(pEnumTz, pYears);
}
