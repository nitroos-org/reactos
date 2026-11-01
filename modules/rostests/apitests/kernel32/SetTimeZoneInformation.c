/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for SetTimeZoneInformation and SetSystemTimeAdjustment (NtSetSystemInformation)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static
BOOL
EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Ret = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid))
    {
        AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL);
        Ret = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(Token);
    return Ret;
}

static
VOID
TestTimeZone(VOID)
{
    TIME_ZONE_INFORMATION Old, Zone, Read;
    DWORD Id;
    BOOL Ret;

    Id = GetTimeZoneInformation(&Old);
    if (Id == TIME_ZONE_ID_INVALID)
    {
        skip("GetTimeZoneInformation failed, error %lu\n", GetLastError());
        return;
    }
    if (!EnablePrivilege(L"SeTimeZonePrivilege"))
    {
        skip("SeTimeZonePrivilege not available, error %lu\n", GetLastError());
        return;
    }

    memset(&Zone, 0, sizeof(Zone));
    Zone.Bias = 420;
    Zone.DaylightBias = -60;
    wcscpy(Zone.StandardName, L"SetTz Standard Time");
    wcscpy(Zone.DaylightName, L"SetTz Daylight Time");
    Zone.StandardDate.wMonth = 11;
    Zone.StandardDate.wDayOfWeek = 0;
    Zone.StandardDate.wDay = 1;
    Zone.StandardDate.wHour = 2;
    Zone.DaylightDate.wMonth = 3;
    Zone.DaylightDate.wDayOfWeek = 0;
    Zone.DaylightDate.wDay = 2;
    Zone.DaylightDate.wHour = 2;

    SetLastError(0xdeadbeef);
    Ret = SetTimeZoneInformation(&Zone);
    ok(Ret, "SetTimeZoneInformation failed, error %lu\n", GetLastError());
    if (!Ret)
        return;

    memset(&Read, 0xcc, sizeof(Read));
    Id = GetTimeZoneInformation(&Read);
    ok(Id != TIME_ZONE_ID_INVALID, "GetTimeZoneInformation failed, error %lu\n", GetLastError());
    ok(Read.Bias == Zone.Bias, "Bias = %ld, expected %ld\n", Read.Bias, Zone.Bias);
    ok(Read.StandardBias == Zone.StandardBias, "StandardBias = %ld\n", Read.StandardBias);
    ok(Read.DaylightBias == Zone.DaylightBias, "DaylightBias = %ld, expected %ld\n",
       Read.DaylightBias, Zone.DaylightBias);
    ok(Read.StandardDate.wMonth == 11 && Read.StandardDate.wDay == 1 && Read.StandardDate.wHour == 2,
       "StandardDate = %u-%u %u:00\n", Read.StandardDate.wMonth, Read.StandardDate.wDay,
       Read.StandardDate.wHour);
    ok(Read.DaylightDate.wMonth == 3 && Read.DaylightDate.wDay == 2 && Read.DaylightDate.wHour == 2,
       "DaylightDate = %u-%u %u:00\n", Read.DaylightDate.wMonth, Read.DaylightDate.wDay,
       Read.DaylightDate.wHour);
    ok(!wcscmp(Read.StandardName, Zone.StandardName), "StandardName = %ls\n", Read.StandardName);
    ok(!wcscmp(Read.DaylightName, Zone.DaylightName), "DaylightName = %ls\n", Read.DaylightName);

    ok(SetTimeZoneInformation(&Old), "could not restore the time zone, error %lu\n", GetLastError());
    memset(&Read, 0xcc, sizeof(Read));
    GetTimeZoneInformation(&Read);
    ok(Read.Bias == Old.Bias, "restored Bias = %ld, expected %ld\n", Read.Bias, Old.Bias);
    ok(Read.DaylightBias == Old.DaylightBias, "restored DaylightBias = %ld, expected %ld\n",
       Read.DaylightBias, Old.DaylightBias);
    ok(!wcscmp(Read.StandardName, Old.StandardName), "restored StandardName = %ls\n", Read.StandardName);
}

static
VOID
TestTimeAdjustment(VOID)
{
    DWORD Adj, Inc, Adj2, Inc2;
    BOOL Disabled, Disabled2, Ret;

    if (!GetSystemTimeAdjustment(&Adj, &Inc, &Disabled))
    {
        skip("GetSystemTimeAdjustment failed, error %lu\n", GetLastError());
        return;
    }
    if (!EnablePrivilege(L"SeSystemtimePrivilege"))
    {
        skip("SeSystemtimePrivilege not available, error %lu\n", GetLastError());
        return;
    }

    /* Write back what is there: the clock does not change */
    SetLastError(0xdeadbeef);
    Ret = SetSystemTimeAdjustment(Adj, Disabled);
    ok(Ret, "SetSystemTimeAdjustment failed, error %lu\n", GetLastError());
    if (!Ret)
        return;

    ok(GetSystemTimeAdjustment(&Adj2, &Inc2, &Disabled2), "GetSystemTimeAdjustment failed\n");
    ok(Adj2 == Adj, "adjustment = %lu, expected %lu\n", Adj2, Adj);
    ok(Inc2 == Inc, "increment = %lu, expected %lu\n", Inc2, Inc);
    ok(Disabled2 == Disabled, "disabled = %d, expected %d\n", Disabled2, Disabled);
}

START_TEST(SetTimeZoneInformation)
{
    TestTimeZone();
    TestTimeAdjustment();
}
