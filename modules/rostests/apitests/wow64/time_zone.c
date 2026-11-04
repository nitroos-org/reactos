/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Native-width-independent time-zone query and calendar conversion
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Native-width-independent time-zone query and calendar conversion. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)
int main(void)
{
    typedef LONG (WINAPI *QUERY)(ULONG, PVOID, ULONG, PULONG);
    QUERY Query = (QUERY)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    struct { DWORD Before; BYTE Data[172]; DWORD After; } Raw;
    TIME_ZONE_INFORMATION Zone;
    SYSTEMTIME Utc = {2026, 2, 0, 14, 12, 30, 15, 0}, Local, RoundTrip;
    ULONG Size = 0;
    DWORD Id = GetTimeZoneInformation(&Zone);
    CHECK(Id != TIME_ZONE_ID_INVALID);
    if (Id != TIME_ZONE_ID_INVALID)
    {
        CHECK(SystemTimeToTzSpecificLocalTime(&Zone, &Utc, &Local));
        CHECK(TzSpecificLocalTimeToSystemTime(&Zone, &Local, &RoundTrip));
        CHECK(RoundTrip.wYear == Utc.wYear && RoundTrip.wMonth == Utc.wMonth && RoundTrip.wDay == Utc.wDay);
        CHECK(RoundTrip.wHour == Utc.wHour && RoundTrip.wMinute == Utc.wMinute && RoundTrip.wSecond == Utc.wSecond);
    }
    CHECK(Query != NULL);
    if (Query)
    {
        memset(&Raw, 0xa5, sizeof(Raw));
        CHECK(Query(44 /* SystemCurrentTimeZoneInformation */, Raw.Data, sizeof(Raw.Data), &Size) == 0);
        CHECK(Size == sizeof(Raw.Data));
        CHECK(Raw.Before == 0xa5a5a5a5 && Raw.After == 0xa5a5a5a5);
        CHECK(Query(44, Raw.Data, sizeof(Raw.Data) - 1, &Size) == (LONG)0xc0000004);
    }
    printf("TIME ZONE: %u checks, %u failures\n", Checks, Failures);
    return Failures ? 1 : 0;
}
