/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for GetTimeZoneInformationForYear
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows Server 2008 R2 (x86 and x64).
 * Windows 10 differs: it fails for an unknown zone and reads the names from the registry.
 */

#include "precomp.h"

typedef BOOL (WINAPI *FN_GetTimeZoneInformationForYear)(USHORT, PDYNAMIC_TIME_ZONE_INFORMATION, LPTIME_ZONE_INFORMATION);
typedef DWORD (WINAPI *FN_GetDynamicTimeZoneInformation)(PDYNAMIC_TIME_ZONE_INFORMATION);

#define ZONES_KEY L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
#define TEST_ZONE_PREFIX L"ReactOS Test Zone "

typedef struct _TZI_FORMAT
{
    LONG Bias;
    LONG StandardBias;
    LONG DaylightBias;
    SYSTEMTIME StandardDate;
    SYSTEMTIME DaylightDate;
} TZI_FORMAT;

static FN_GetTimeZoneInformationForYear pGetTimeZoneInformationForYear;

/* A name of this process's own, so that runs at the same time cannot meet */
static WCHAR TEST_ZONE[64];

/* A name as printable text, however the array was left (it may be unterminated after a failed call) */
static PCWSTR NameOf(const WCHAR *Name)
{
    static WCHAR Ring[4][33];
    static unsigned Next;
    WCHAR *Copy = Ring[Next++ % ARRAYSIZE(Ring)];

    wcsncpy(Copy, Name, 32);
    Copy[32] = UNICODE_NULL;
    return Copy;
}

/* The tests with a synthetic zone expect what Windows 7 does; Windows 10 reads the names from the registry and fails for an unknown zone */
static BOOL Windows7Behavior(void)
{
    return is_reactos() || GetNTVersion() <= _WIN32_WINNT_WIN7;
}

static void FillInfo(DYNAMIC_TIME_ZONE_INFORMATION *Dynamic, PCWSTR KeyName)
{
    ZeroMemory(Dynamic, sizeof(*Dynamic));
    Dynamic->Bias = -5;
    Dynamic->StandardBias = -6;
    Dynamic->DaylightBias = -7;
    Dynamic->StandardDate.wMonth = 11;
    Dynamic->StandardDate.wDay = 2;
    Dynamic->DaylightDate.wMonth = 3;
    Dynamic->DaylightDate.wDay = 4;
    StringCchCopyW(Dynamic->StandardName, ARRAYSIZE(Dynamic->StandardName), L"Test Standard");
    StringCchCopyW(Dynamic->DaylightName, ARRAYSIZE(Dynamic->DaylightName), L"Test Daylight");
    StringCchCopyW(Dynamic->TimeZoneKeyName, ARRAYSIZE(Dynamic->TimeZoneKeyName), KeyName);
}

/* The year entries of the test zone have these values, derived from the year */
static void MakeYearData(TZI_FORMAT *Data, LONG Year)
{
    ZeroMemory(Data, sizeof(*Data));
    Data->Bias = 1000 + Year;
    Data->StandardBias = 2000 + Year;
    Data->DaylightBias = 3000 + Year;
    Data->StandardDate.wMonth = 10;
    Data->StandardDate.wDay = 5;
    Data->StandardDate.wHour = 2;
    Data->DaylightDate.wMonth = 4;
    Data->DaylightDate.wDay = 1;
    Data->DaylightDate.wHour = 3;
}

static void ExpectYearData(PCSTR What, USHORT QueryYear, LONG Year, const TIME_ZONE_INFORMATION *Info)
{
    TZI_FORMAT Expected;

    MakeYearData(&Expected, Year);
    ok(Info->Bias == Expected.Bias, "%s, year %u: bias %ld, expected %ld\n", What, QueryYear, Info->Bias, Expected.Bias);
    ok(Info->StandardBias == Expected.StandardBias, "%s, year %u: standard bias %ld, expected %ld\n",
       What, QueryYear, Info->StandardBias, Expected.StandardBias);
    ok(Info->DaylightBias == Expected.DaylightBias, "%s, year %u: daylight bias %ld, expected %ld\n",
       What, QueryYear, Info->DaylightBias, Expected.DaylightBias);
    ok(!memcmp(&Info->StandardDate, &Expected.StandardDate, sizeof(SYSTEMTIME)), "%s, year %u: standard date differs\n", What, QueryYear);
    ok(!memcmp(&Info->DaylightDate, &Expected.DaylightDate, sizeof(SYSTEMTIME)), "%s, year %u: daylight date differs\n", What, QueryYear);
    ok(!wcsncmp(Info->StandardName, L"Test Standard", 32), "%s, year %u: standard name '%S'\n", What, QueryYear, NameOf(Info->StandardName));
    ok(!wcsncmp(Info->DaylightName, L"Test Daylight", 32), "%s, year %u: daylight name '%S'\n", What, QueryYear, NameOf(Info->DaylightName));
}

/* The caller's own values, untouched (the names are copied as strings, not as whole arrays) */
static void ExpectOwnData(PCSTR What, USHORT QueryYear, const DYNAMIC_TIME_ZONE_INFORMATION *Own, const TIME_ZONE_INFORMATION *Info)
{
    ok(Info->Bias == Own->Bias, "%s, year %u: bias %ld, expected %ld\n", What, QueryYear, Info->Bias, Own->Bias);
    ok(Info->StandardBias == Own->StandardBias, "%s, year %u: standard bias %ld, expected %ld\n",
       What, QueryYear, Info->StandardBias, Own->StandardBias);
    ok(Info->DaylightBias == Own->DaylightBias, "%s, year %u: daylight bias %ld, expected %ld\n",
       What, QueryYear, Info->DaylightBias, Own->DaylightBias);
    ok(!memcmp(&Info->StandardDate, &Own->StandardDate, sizeof(SYSTEMTIME)), "%s, year %u: standard date differs\n", What, QueryYear);
    ok(!memcmp(&Info->DaylightDate, &Own->DaylightDate, sizeof(SYSTEMTIME)), "%s, year %u: daylight date differs\n", What, QueryYear);
    ok(!wcsncmp(Info->StandardName, Own->StandardName, 32), "%s, year %u: standard name '%S'\n", What, QueryYear, NameOf(Info->StandardName));
    ok(!wcsncmp(Info->DaylightName, Own->DaylightName, 32), "%s, year %u: daylight name '%S'\n", What, QueryYear, NameOf(Info->DaylightName));
}

static BOOL Query(USHORT Year, PCWSTR KeyName, BOOL Disabled, TIME_ZONE_INFORMATION *Info, DYNAMIC_TIME_ZONE_INFORMATION *Own)
{
    DYNAMIC_TIME_ZONE_INFORMATION Dynamic;
    BOOL Ret;

    FillInfo(&Dynamic, KeyName);
    Dynamic.DynamicDaylightTimeDisabled = Disabled;
    *Own = Dynamic;
    RtlFillMemory(Info, sizeof(*Info), 0xBB);
    SetLastError(0xDEADBEEF);
    Ret = pGetTimeZoneInformationForYear(Year, &Dynamic, Info);
    ok(!memcmp(&Dynamic, Own, sizeof(Dynamic)), "The dynamic information was modified\n");
    return Ret;
}

static BOOL SetYear(HKEY hKey, LONG Year)
{
    WCHAR Name[16];
    TZI_FORMAT Data;

    StringCchPrintfW(Name, ARRAYSIZE(Name), L"%ld", Year);
    MakeYearData(&Data, Year);
    return !RegSetValueExW(hKey, Name, 0, REG_BINARY, (const BYTE *)&Data, sizeof(Data));
}

static void SetEntries(HKEY hKey, DWORD First, DWORD Last)
{
    ok(!RegSetValueExW(hKey, L"FirstEntry", 0, REG_DWORD, (const BYTE *)&First, sizeof(First)), "FirstEntry\n");
    ok(!RegSetValueExW(hKey, L"LastEntry", 0, REG_DWORD, (const BYTE *)&Last, sizeof(Last)), "LastEntry\n");
}

/* Values of 4 to 44 bytes are read, the end of the structure staying zero; bigger ones are not read as a year's data */
static void TestValueSizes(HKEY hDynamic)
{
    static const DWORD Read[] = { 4, 12, 20, 43, 44 };
    static const DWORD Refused[] = { 45, 48, 64, 100 };
    TIME_ZONE_INFORMATION Info;
    DYNAMIC_TIME_ZONE_INFORMATION Own;
    TZI_FORMAT Full, Expected;
    BYTE Raw[128];
    unsigned i;
    BOOL Ret;

    SetEntries(hDynamic, 2000, 2000);
    MakeYearData(&Full, 2000);
    ZeroMemory(Raw, sizeof(Raw));
    CopyMemory(Raw, &Full, sizeof(Full));

    for (i = 0; i < ARRAYSIZE(Read); i++)
    {
        ZeroMemory(&Expected, sizeof(Expected));
        CopyMemory(&Expected, &Full, Read[i]);
        ok(!RegSetValueExW(hDynamic, L"2000", 0, REG_BINARY, Raw, Read[i]), "Cannot store %lu bytes\n", Read[i]);
        Ret = Query(2000, TEST_ZONE, FALSE, &Info, &Own);
        ok(Ret, "%lu bytes: failed: %lu\n", Read[i], GetLastError());
        ok(Info.Bias == Expected.Bias, "%lu bytes: bias %ld, expected %ld\n", Read[i], Info.Bias, Expected.Bias);
        ok(Info.StandardBias == Expected.StandardBias, "%lu bytes: standard bias %ld, expected %ld\n",
           Read[i], Info.StandardBias, Expected.StandardBias);
        ok(Info.DaylightBias == Expected.DaylightBias, "%lu bytes: daylight bias %ld, expected %ld\n",
           Read[i], Info.DaylightBias, Expected.DaylightBias);
        ok(!memcmp(&Info.StandardDate, &Expected.StandardDate, sizeof(SYSTEMTIME)), "%lu bytes: standard date differs\n", Read[i]);
        ok(!memcmp(&Info.DaylightDate, &Expected.DaylightDate, sizeof(SYSTEMTIME)), "%lu bytes: daylight date differs\n", Read[i]);
    }

    for (i = 0; i < ARRAYSIZE(Refused); i++)
    {
        ok(!RegSetValueExW(hDynamic, L"2000", 0, REG_BINARY, Raw, Refused[i]), "Cannot store %lu bytes\n", Refused[i]);
        Ret = Query(2000, TEST_ZONE, FALSE, &Info, &Own);
        ok(Ret, "%lu bytes: failed: %lu\n", Refused[i], GetLastError());
        /* Windows Server 2008 R2 hands back values of its own in this case; ReactOS gives the caller's */
        if (is_reactos())
            ExpectOwnData("oversized value", 2000, &Own, &Info);
    }
}

static void TestZoneData(HKEY hDynamic)
{
    TIME_ZONE_INFORMATION Info;
    DYNAMIC_TIME_ZONE_INFORMATION Own;
    BOOL Ret;
    static const struct
    {
        USHORT Year;
        LONG Used;
    } Years[] =
    {
        { 0, 2000 }, { 1, 2000 }, { 1999, 2000 }, { 2000, 2000 }, { 2001, 2001 }, { 2003, 2003 },
        { 2004, 2003 }, { 3000, 2003 }, { 9999, 2003 },
        /* a year as a signed 16-bit number, down to -999, is below the first entry */
        { 64537, 2000 }, { 65000, 2000 }, { 65534, 2000 }, { 65535, 2000 },
    };
    static const USHORT Untouched[] = { 10000, 20000, 30827, 32768, 40000, 64536 };
    unsigned i;

    /* Entries 2000, 2001 and 2003; years outside use the first or last one */
    SetEntries(hDynamic, 2000, 2003);
    ok(SetYear(hDynamic, 2000) && SetYear(hDynamic, 2001) && SetYear(hDynamic, 2003), "Cannot store the years\n");

    for (i = 0; i < ARRAYSIZE(Years); i++)
    {
        Ret = Query(Years[i].Year, TEST_ZONE, FALSE, &Info, &Own);
        ok(Ret, "Year %u: failed: %lu\n", Years[i].Year, GetLastError());
        ExpectYearData("entries", Years[i].Year, Years[i].Used, &Info);
    }

    /* Years that do not fit four characters as a signed number get nothing from the registry */
    for (i = 0; i < ARRAYSIZE(Untouched); i++)
    {
        Ret = Query(Untouched[i], TEST_ZONE, FALSE, &Info, &Own);
        ok(Ret, "Year %u: failed: %lu\n", Untouched[i], GetLastError());
        ExpectOwnData("too many digits", Untouched[i], &Own, &Info);
    }

    /* DynamicDaylightTimeDisabled: the caller's values */
    for (i = 0; i < 4; i++)
    {
        static const USHORT Sample[] = { 1999, 2001, 2003, 2010 };

        Ret = Query(Sample[i], TEST_ZONE, TRUE, &Info, &Own);
        ok(Ret, "Disabled, year %u: failed: %lu\n", Sample[i], GetLastError());
        ExpectOwnData("disabled", Sample[i], &Own, &Info);
    }

    /* A first entry above the last: below the first entry uses the first, otherwise above the last uses the last */
    SetEntries(hDynamic, 2003, 2001);
    Ret = Query(1999, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectYearData("first above last", 1999, 2003, &Info);
    Ret = Query(2003, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectYearData("first above last", 2003, 2001, &Info);
    Ret = Query(2010, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectYearData("first above last", 2010, 2001, &Info);

    /* Without both entries nothing is read */
    SetEntries(hDynamic, 2000, 2003);
    ok(!RegDeleteValueW(hDynamic, L"FirstEntry"), "Cannot delete FirstEntry\n");
    Ret = Query(2001, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectOwnData("no FirstEntry", 2001, &Own, &Info);
    SetEntries(hDynamic, 2000, 2003);
    ok(!RegDeleteValueW(hDynamic, L"LastEntry"), "Cannot delete LastEntry\n");
    Ret = Query(2001, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectOwnData("no LastEntry", 2001, &Own, &Info);

    TestValueSizes(hDynamic);
}

static void TestNoDynamicData(HKEY hZone)
{
    TIME_ZONE_INFORMATION Info;
    DYNAMIC_TIME_ZONE_INFORMATION Own;
    HKEY hDynamic = NULL;
    LONG Error;
    BOOL Ret;

    /* The zone exists but has no "Dynamic DST" key */
    Ret = Query(2005, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectOwnData("no Dynamic DST key", 2005, &Own, &Info);

    /* A key without entries */
    Error = RegCreateKeyExW(hZone, L"Dynamic DST", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hDynamic, NULL);
    ok(Error == ERROR_SUCCESS, "Cannot create Dynamic DST: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;

    Ret = Query(2005, TEST_ZONE, FALSE, &Info, &Own);
    ok(Ret, "Failed: %lu\n", GetLastError());
    ExpectOwnData("empty Dynamic DST key", 2005, &Own, &Info);

    TestZoneData(hDynamic);
    RegCloseKey(hDynamic);
    Error = RegDeleteKeyW(hZone, L"Dynamic DST");
    ok(Error == ERROR_SUCCESS, "Cannot delete Dynamic DST: %ld\n", Error);
}

static void TestUnknownZones(void)
{
    static const PCWSTR Names[] = { L"No Such Zone", L"", L"ReactOS Test Zone  " };
    TIME_ZONE_INFORMATION Info;
    DYNAMIC_TIME_ZONE_INFORMATION Own;
    unsigned i;
    BOOL Ret;

    /* Windows Server 2008 R2 and Windows 7 succeed with the caller's values for a zone they do not know */
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        Ret = Query(2005, Names[i], FALSE, &Info, &Own);
        ok(Ret, "Zone '%S': failed: %lu\n", Names[i], GetLastError());
        ExpectOwnData("unknown zone", 2005, &Own, &Info);
    }
}

static BOOL ReadDword(HKEY hKey, PCWSTR Name, DWORD *Value)
{
    DWORD Type, Size = sizeof(*Value);

    return !RegQueryValueExW(hKey, Name, NULL, &Type, (BYTE *)Value, &Size) && Type == REG_DWORD && Size == sizeof(*Value);
}

enum { YEAR_NONE, YEAR_DATA, YEAR_UNKNOWN };

/*
 * What the zone gives for the year. YEAR_DATA: the value that the function reads (a binary value of 4 to 44 bytes; a
 * shorter one is zero padded, as measured), returned in Data. YEAR_NONE: no entry range, so the zone in effect.
 * YEAR_UNKNOWN: a value that is missing, of another type or of a size that Windows and ReactOS treat in their own ways.
 */
static int GetYearData(PCWSTR KeyName, USHORT Year, TZI_FORMAT *Data)
{
    WCHAR Path[256], Name[16];
    HKEY hKey;
    DWORD First, Last, Type, Size = 0;
    LONG Used = (SHORT)Year;
    int Result = YEAR_UNKNOWN;

    if (!KeyName[0])
        return YEAR_NONE;
    StringCchPrintfW(Path, ARRAYSIZE(Path), ZONES_KEY L"\\%s\\Dynamic DST", KeyName);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey))
        return YEAR_NONE;
    if (!ReadDword(hKey, L"FirstEntry", &First) || !ReadDword(hKey, L"LastEntry", &Last))
    {
        RegCloseKey(hKey);
        return YEAR_NONE;
    }
    if (Used < (LONG)First)
        Used = (LONG)First;
    else if (Used > (LONG)Last)
        Used = (LONG)Last;
    StringCchPrintfW(Name, ARRAYSIZE(Name), L"%ld", Used);
    if (!RegQueryValueExW(hKey, Name, NULL, &Type, NULL, &Size) && Type == REG_BINARY &&
        Size >= sizeof(DWORD) && Size <= sizeof(*Data))
    {
        ZeroMemory(Data, sizeof(*Data));
        if (!RegQueryValueExW(hKey, Name, NULL, &Type, (BYTE *)Data, &Size) && Type == REG_BINARY)
            Result = YEAR_DATA;
    }
    RegCloseKey(hKey);
    return Result;
}

static void ExpectSameZone(PCSTR What, const TIME_ZONE_INFORMATION *Info, const TIME_ZONE_INFORMATION *Expected, BOOL All)
{
    ok(Info->Bias == Expected->Bias, "%s: bias %ld, expected %ld\n", What, Info->Bias, Expected->Bias);
    ok(!wcsncmp(Info->StandardName, Expected->StandardName, 32), "%s: standard name '%S', expected '%S'\n",
       What, NameOf(Info->StandardName), NameOf(Expected->StandardName));
    ok(!wcsncmp(Info->DaylightName, Expected->DaylightName, 32), "%s: daylight name '%S', expected '%S'\n",
       What, NameOf(Info->DaylightName), NameOf(Expected->DaylightName));
    if (!All)
        return;
    ok(Info->StandardBias == Expected->StandardBias, "%s: standard bias %ld, expected %ld\n", What, Info->StandardBias, Expected->StandardBias);
    ok(Info->DaylightBias == Expected->DaylightBias, "%s: daylight bias %ld, expected %ld\n", What, Info->DaylightBias, Expected->DaylightBias);
    ok(!memcmp(&Info->StandardDate, &Expected->StandardDate, sizeof(SYSTEMTIME)), "%s: standard date differs\n", What);
    ok(!memcmp(&Info->DaylightDate, &Expected->DaylightDate, sizeof(SYSTEMTIME)), "%s: daylight date differs\n", What);
}

/* The names always come from the zone in effect; the other fields from the year's value when the zone has one */
static void ExpectCurrentZone(PCSTR What, const TIME_ZONE_INFORMATION *Info, const TIME_ZONE_INFORMATION *Current,
                              int Kind, const TZI_FORMAT *Data)
{
    if (Kind == YEAR_DATA)
    {
        ExpectSameZone(What, Info, Current, FALSE);
        ok(Info->Bias == Data->Bias, "%s: bias %ld, the year's value has %ld\n", What, Info->Bias, Data->Bias);
        ok(Info->StandardBias == Data->StandardBias, "%s: standard bias %ld, the year's value has %ld\n",
           What, Info->StandardBias, Data->StandardBias);
        ok(Info->DaylightBias == Data->DaylightBias, "%s: daylight bias %ld, the year's value has %ld\n",
           What, Info->DaylightBias, Data->DaylightBias);
        ok(!memcmp(&Info->StandardDate, &Data->StandardDate, sizeof(SYSTEMTIME)), "%s: standard date differs from the year's value\n", What);
        ok(!memcmp(&Info->DaylightDate, &Data->DaylightDate, sizeof(SYSTEMTIME)), "%s: daylight date differs from the year's value\n", What);
    }
    else if (Kind == YEAR_NONE)
    {
        ExpectSameZone(What, Info, Current, TRUE);
    }
    else
    {
        skip("%s: the year's value is not one that every version reads in the same way\n", What);
    }
}

static void TestCurrentZone(void)
{
    FN_GetDynamicTimeZoneInformation pGetDynamicTimeZoneInformation;
    DYNAMIC_TIME_ZONE_INFORMATION Dynamic;
    TIME_ZONE_INFORMATION Info, Current, Explicit;
    TZI_FORMAT Data = {0};
    SYSTEMTIME Now;
    BOOL Ret;
    int Kind;

    pGetDynamicTimeZoneInformation = (FN_GetDynamicTimeZoneInformation)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetDynamicTimeZoneInformation");
    if (!pGetDynamicTimeZoneInformation)
        return;

    GetLocalTime(&Now);
    if (GetTimeZoneInformation(&Current) == TIME_ZONE_ID_INVALID || pGetDynamicTimeZoneInformation(&Dynamic) == TIME_ZONE_ID_INVALID)
    {
        skip("Cannot read the current zone\n");
        return;
    }
    Dynamic.TimeZoneKeyName[ARRAYSIZE(Dynamic.TimeZoneKeyName) - 1] = UNICODE_NULL;

    /* A zone with yearly data has the values of that year, the others the ones in effect */
    Kind = Dynamic.DynamicDaylightTimeDisabled ? YEAR_NONE : GetYearData(Dynamic.TimeZoneKeyName, Now.wYear, &Data);

    /* No dynamic information: the zone in effect */
    RtlFillMemory(&Info, sizeof(Info), 0xBB);
    SetLastError(0xDEADBEEF);
    Ret = pGetTimeZoneInformationForYear(Now.wYear, NULL, &Info);
    ok(Ret, "Failed: %lu\n", GetLastError());
    if (Ret)
    {
        ok(Info.Bias != (LONG)0xBBBBBBBB, "The structure was not filled\n");
        ExpectCurrentZone("no dynamic information", &Info, &Current, Kind, &Data);
    }

    /* The information of GetDynamicTimeZoneInformation gives the same, all of it */
    RtlFillMemory(&Explicit, sizeof(Explicit), 0xBB);
    Ret = pGetTimeZoneInformationForYear(Now.wYear, &Dynamic, &Explicit);
    ok(Ret, "Failed: %lu\n", GetLastError());
    if (Ret)
    {
        ok(Explicit.Bias != (LONG)0xBBBBBBBB, "The structure was not filled\n");
        ExpectCurrentZone("explicit information", &Explicit, &Current, Kind, &Data);
        if (Info.Bias != (LONG)0xBBBBBBBB)
            ExpectSameZone("explicit and implicit", &Explicit, &Info, TRUE);
    }
}

/* The zones that carry IANA-derived "Dynamic DST" years: 2025-2027 as generated from the tz database (see TestIrregularZones) */
typedef struct _IRREGULAR_YEAR
{
    PCWSTR Key;
    USHORT Year;
    LONG Bias, DaylightBias;
    WORD StdMonth, StdDay, StdWeek, StdHour;  /* wMonth, wDayOfWeek, wDay, wHour; month 0: no transition */
    WORD DltMonth, DltDay, DltWeek, DltHour;
} IRREGULAR_YEAR;

static const IRREGULAR_YEAR g_Irregular[] =
{
    /* British Columbia, Alberta and Manitoba: the last year of daylight saving time is 2025; from November 2026 the zones stay on the summer offset */
    { L"British Columbia Standard Time", 2025, 480, -60, 11, 0, 1, 2, 3, 0, 2, 2 },
    { L"British Columbia Standard Time", 2026, 420, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"British Columbia Standard Time", 2027, 420, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"Alberta Standard Time", 2025, 420, -60, 11, 0, 1, 2, 3, 0, 2, 2 },
    { L"Alberta Standard Time", 2026, 360, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"Alberta Standard Time", 2027, 360, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"Manitoba Standard Time", 2025, 360, -60, 11, 0, 1, 2, 3, 0, 2, 2 },
    { L"Manitoba Standard Time", 2026, 300, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"Manitoba Standard Time", 2027, 300, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* Paraguay: permanent -03 since October 2024 */
    { L"Paraguay Standard Time", 2025, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"Paraguay Standard Time", 2026, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    { L"Paraguay Standard Time", 2027, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* Morocco: +01 with the Ramadan break (standard time is +00); the last two changes of 2026 are modelled, from 2027 it stays +00 */
    { L"Morocco Standard Time", 2025, 0, -60, 2, 0, 5, 3, 4, 0, 1, 2 },
    { L"Morocco Standard Time", 2026, 0, -60, 9, 0, 3, 2, 3, 0, 4, 2 },
    { L"Morocco Standard Time", 2027, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

static void TestIrregularZones(void)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(g_Irregular); i++)
    {
        const IRREGULAR_YEAR *Y = &g_Irregular[i];
        DYNAMIC_TIME_ZONE_INFORMATION Dynamic;
        TIME_ZONE_INFORMATION Info;
        BOOL Ret;

        ZeroMemory(&Dynamic, sizeof(Dynamic));
        StringCchCopyW(Dynamic.TimeZoneKeyName, ARRAYSIZE(Dynamic.TimeZoneKeyName), Y->Key);
        Ret = pGetTimeZoneInformationForYear(Y->Year, &Dynamic, &Info);
        ok(Ret, "%ls %u: failed %lu\n", Y->Key, Y->Year, GetLastError());
        if (!Ret)
            continue;
        ok(Info.Bias == Y->Bias, "%ls %u: bias %ld, expected %ld\n", Y->Key, Y->Year, Info.Bias, Y->Bias);
        ok(Info.StandardBias == 0, "%ls %u: standard bias %ld\n", Y->Key, Y->Year, Info.StandardBias);
        ok(Info.DaylightBias == Y->DaylightBias, "%ls %u: daylight bias %ld, expected %ld\n",
           Y->Key, Y->Year, Info.DaylightBias, Y->DaylightBias);
        ok(Info.StandardDate.wMonth == Y->StdMonth && Info.StandardDate.wDayOfWeek == Y->StdDay &&
           Info.StandardDate.wDay == Y->StdWeek && Info.StandardDate.wHour == Y->StdHour,
           "%ls %u: standard date %u-%u-%u %u\n", Y->Key, Y->Year, Info.StandardDate.wMonth,
           Info.StandardDate.wDayOfWeek, Info.StandardDate.wDay, Info.StandardDate.wHour);
        ok(Info.DaylightDate.wMonth == Y->DltMonth && Info.DaylightDate.wDayOfWeek == Y->DltDay &&
           Info.DaylightDate.wDay == Y->DltWeek && Info.DaylightDate.wHour == Y->DltHour,
           "%ls %u: daylight date %u-%u-%u %u\n", Y->Key, Y->Year, Info.DaylightDate.wMonth,
           Info.DaylightDate.wDayOfWeek, Info.DaylightDate.wDay, Info.DaylightDate.wHour);
    }
}

START_TEST(GetTimeZoneInformationForYear)
{
    HKEY hZones, hZone;
    LONG Error;
    DWORD Disposition;

    pGetTimeZoneInformationForYear = (FN_GetTimeZoneInformationForYear)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTimeZoneInformationForYear");
    if (!pGetTimeZoneInformationForYear && ((is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64")) ||
                                            (!is_reactos() && GetNTVersion() < _WIN32_WINNT_VISTA)))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pGetTimeZoneInformationForYear != NULL, "GetTimeZoneInformationForYear is not exported\n");
    if (!pGetTimeZoneInformationForYear)
        return;

    StringCchPrintfW(TEST_ZONE, ARRAYSIZE(TEST_ZONE), TEST_ZONE_PREFIX L"%lu", GetCurrentProcessId());

    TestCurrentZone();
    if (is_reactos())
        TestIrregularZones();
    if (!Windows7Behavior())
    {
        skip("Newer Windows versions read the names from the registry and fail for an unknown zone\n");
        return;
    }
    TestUnknownZones();

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, ZONES_KEY, 0, KEY_CREATE_SUB_KEY, &hZones);
    if (Error)
    {
        skip("Cannot open the time zones key: %ld\n", Error);
        return;
    }
    Error = RegCreateKeyExW(hZones, TEST_ZONE, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hZone, &Disposition);
    if (Error)
    {
        skip("Cannot create a time zone: %ld\n", Error);
        RegCloseKey(hZones);
        return;
    }
    if (Disposition != REG_CREATED_NEW_KEY)
    {
        skip("The test zone exists already\n");
        RegCloseKey(hZone);
        RegCloseKey(hZones);
        return;
    }

    TestNoDynamicData(hZone);

    RegCloseKey(hZone);
    Error = RegDeleteKeyW(hZones, TEST_ZONE);
    ok(Error == ERROR_SUCCESS, "Cannot delete the test zone: %ld\n", Error);
    RegCloseKey(hZones);
}
