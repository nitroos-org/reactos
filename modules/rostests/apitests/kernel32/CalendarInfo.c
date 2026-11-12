/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for GetCalendarInfoW/Ex and the en-US date formats of GetLocaleInfoW/Ex
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The expected values were measured on Windows 10 22H2 (build 19045).
 */

#include "precomp.h"

#include <winnls.h>

#ifndef CAL_SSHORTESTDAYNAME1
#define CAL_SSHORTESTDAYNAME1 49
#endif
#ifndef CAL_SMONTHDAY
#define CAL_SMONTHDAY 56
#endif

typedef int (WINAPI *PFN_GetCalendarInfoEx)(LPCWSTR, CALID, LPCWSTR, CALTYPE, LPWSTR, int, LPDWORD);

#define EN_US 0x0409

static
void
ExpectCal(
    _In_ PCSTR Name,
    _In_ CALTYPE Type,
    _In_ PCWSTR Expected)
{
    WCHAR Buffer[64];
    int Ret, Needed;

    SetLastError(0xdeadbeef);
    Needed = GetCalendarInfoW(EN_US, CAL_GREGORIAN, Type, NULL, 0, NULL);
    ok(Needed == (int)wcslen(Expected) + 1, "%s: size query returned %d, expected %d (error %lu)\n",
       Name, Needed, (int)wcslen(Expected) + 1, GetLastError());

    RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
    SetLastError(0xdeadbeef);
    Ret = GetCalendarInfoW(EN_US, CAL_GREGORIAN, Type, Buffer, ARRAYSIZE(Buffer), NULL);
    ok(Ret == (int)wcslen(Expected) + 1, "%s: returned %d, expected %d (error %lu)\n",
       Name, Ret, (int)wcslen(Expected) + 1, GetLastError());
    if (Ret > 0)
        ok(!wcscmp(Buffer, Expected), "%s: got '%ls', expected '%ls'\n", Name, Buffer, Expected);
}

static
void
Test_ShortestDayNamesAndMonthDay(void)
{
    static const WCHAR *Days[7] = { L"Mo", L"Tu", L"We", L"Th", L"Fr", L"Sa", L"Su" };
    PFN_GetCalendarInfoEx pGetCalendarInfoEx;
    WCHAR Buffer[64];
    CHAR Name[] = "CAL_SSHORTESTDAYNAME1";
    int i, Ret;

    /* CAL_SSHORTESTDAYNAME1 is Monday */
    for (i = 0; i < 7; i++)
    {
        Name[sizeof(Name) - 2] = (CHAR)('1' + i);
        ExpectCal(Name, CAL_SSHORTESTDAYNAME1 + i, Days[i]);
    }
    ExpectCal("CAL_SMONTHDAY", CAL_SMONTHDAY, L"MMMM d");

    pGetCalendarInfoEx = (PFN_GetCalendarInfoEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCalendarInfoEx");
    if (!pGetCalendarInfoEx)
    {
        skip("GetCalendarInfoEx is not available\n");
        return;
    }
    Buffer[0] = 0;
    SetLastError(0xdeadbeef);
    Ret = pGetCalendarInfoEx(L"en-US", CAL_GREGORIAN, NULL, CAL_SSHORTESTDAYNAME1 + 6, Buffer, ARRAYSIZE(Buffer), NULL);
    ok(Ret == 3, "GetCalendarInfoEx returned %d (error %lu)\n", Ret, GetLastError());
    ok(!wcscmp(Buffer, L"Su"), "got '%ls'\n", Buffer);

    Buffer[0] = 0;
    SetLastError(0xdeadbeef);
    Ret = pGetCalendarInfoEx(L"de-DE", CAL_GREGORIAN, NULL, CAL_SSHORTESTDAYNAME1 + 6, Buffer, ARRAYSIZE(Buffer), NULL);
    ok(Ret == 3, "GetCalendarInfoEx(de-DE) returned %d (error %lu)\n", Ret, GetLastError());
    ok(!wcscmp(Buffer, L"So"), "got '%ls'\n", Buffer);

    /* A buffer that is too small */
    SetLastError(0xdeadbeef);
    Ret = GetCalendarInfoW(EN_US, CAL_GREGORIAN, CAL_SMONTHDAY, Buffer, 3, NULL);
    ok(Ret == 0, "returned %d\n", Ret);
    ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "error %lu\n", GetLastError());
}

static
void
Test_YearRange(void)
{
    DWORD Value;
    WCHAR Buffer[16];
    int Ret;

    /* The default two-digit year window ends in 2049 since Windows 10 */
    Value = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = GetCalendarInfoW(EN_US, CAL_GREGORIAN, CAL_ITWODIGITYEARMAX | CAL_RETURN_NUMBER, NULL, 0, &Value);
    ok(Ret == 2, "returned %d (error %lu)\n", Ret, GetLastError());
    ok(Value == 2049, "CAL_ITWODIGITYEARMAX = %lu\n", Value);

    RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
    Ret = GetCalendarInfoW(EN_US, CAL_GREGORIAN, CAL_ITWODIGITYEARMAX, Buffer, ARRAYSIZE(Buffer), NULL);
    ok(Ret == 5, "returned %d (error %lu)\n", Ret, GetLastError());
    ok(!wcscmp(Buffer, L"2049"), "got '%ls'\n", Buffer);

    /* No offset range for the Gregorian calendar */
    RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
    SetLastError(0xdeadbeef);
    Ret = GetCalendarInfoW(EN_US, CAL_GREGORIAN, CAL_IYEAROFFSETRANGE, Buffer, ARRAYSIZE(Buffer), NULL);
    ok(Ret == 2, "returned %d (error %lu)\n", Ret, GetLastError());
    ok(!wcscmp(Buffer, L"0"), "got '%ls'\n", Buffer);

    Value = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Ret = GetCalendarInfoW(EN_US, CAL_GREGORIAN, CAL_IYEAROFFSETRANGE | CAL_RETURN_NUMBER, NULL, 0, &Value);
    ok(Ret == 2, "returned %d (error %lu)\n", Ret, GetLastError());
    ok(Value == 0, "CAL_IYEAROFFSETRANGE = %lu\n", Value);
}

static
void
ExpectLocale(
    _In_ PCSTR Name,
    _In_ LCTYPE Type,
    _In_ PCWSTR Expected)
{
    WCHAR Buffer[64];
    int Ret;

    RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
    SetLastError(0xdeadbeef);
    Ret = GetLocaleInfoW(EN_US, Type, Buffer, ARRAYSIZE(Buffer));
    ok(Ret == (int)wcslen(Expected) + 1, "%s: returned %d, expected %d (error %lu)\n",
       Name, Ret, (int)wcslen(Expected) + 1, GetLastError());
    if (Ret > 0)
        ok(!wcscmp(Buffer, Expected), "%s: got '%ls', expected '%ls'\n", Name, Buffer, Expected);
}

static
void
Test_EnUsDateFormats(void)
{
    /* Windows 10 dropped the zero padding of the day and the comma after the month */
    ExpectLocale("LOCALE_SLONGDATE", LOCALE_SLONGDATE, L"dddd, MMMM d, yyyy");
    ExpectLocale("LOCALE_SSHORTDATE", LOCALE_SSHORTDATE, L"M/d/yyyy");
    ExpectLocale("LOCALE_SYEARMONTH", LOCALE_SYEARMONTH, L"MMMM yyyy");
    ExpectLocale("LOCALE_SMONTHDAY", 0x78 /* LOCALE_SMONTHDAY */, L"MMMM d");
    ExpectLocale("LOCALE_STIMEFORMAT", LOCALE_STIMEFORMAT, L"h:mm:ss tt");
    ExpectLocale("LOCALE_SSHORTESTDAYNAME1", 0x60 /* LOCALE_SSHORTESTDAYNAME1 */, L"Mo");
    ExpectLocale("LOCALE_SSHORTESTDAYNAME7", 0x66 /* LOCALE_SSHORTESTDAYNAME7 */, L"Su");

    /* The formats themselves */
    {
        WCHAR Buffer[64];
        SYSTEMTIME St = { 2020, 1, 3, 1, 0, 0, 0, 0 };
        int Ret;

        Ret = GetDateFormatW(EN_US, DATE_LONGDATE, &St, NULL, Buffer, ARRAYSIZE(Buffer));
        ok(Ret == 27, "GetDateFormatW returned %d (error %lu)\n", Ret, GetLastError());
        ok(!wcscmp(Buffer, L"Wednesday, January 1, 2020"), "got '%ls'\n", Buffer);

        Ret = GetDateFormatW(EN_US, DATE_YEARMONTH, &St, NULL, Buffer, ARRAYSIZE(Buffer));
        ok(Ret == 13, "GetDateFormatW(YEARMONTH) returned %d (error %lu)\n", Ret, GetLastError());
        ok(!wcscmp(Buffer, L"January 2020"), "got '%ls'\n", Buffer);
    }
}

static
DWORD
WINAPI
GenitiveThread(LPVOID Param)
{
    SYSTEMTIME St = { 2026, 11, 0, 8, 0, 0, 0, 0 };
    WCHAR *Buffer = Param;

    /* MMMM followed by a quoted literal and a numeric day: the look-ahead for the genitive month name must skip the literal */
    return GetDateFormatW(MAKELCID(0x0419, SORT_DEFAULT), 0, &St, L"yyyy' of 'MMMM'x' d", Buffer, 64);
}

static
void
Test_GenitiveLookAhead(void)
{
    WCHAR Buffer[64] = L"";
    HANDLE Thread = CreateThread(NULL, 0, GenitiveThread, Buffer, 0, NULL);

    if (!Thread)
    {
        skip("CreateThread failed (error %lu)\n", GetLastError());
        return;
    }
    if (WaitForSingleObject(Thread, 10000) != WAIT_OBJECT_0)
    {
        ok(0, "GetDateFormatW with a literal after MMMM does not return\n");
        TerminateThread(Thread, 1);
    }
    else
    {
        /* the genitive form of November in Russian */
        ok(!wcscmp(Buffer, L"2026 of \x043d\x043e\x044f\x0431\x0440\x044f" L"x 8"), "got '%ls'\n", Buffer);
    }
    CloseHandle(Thread);
}

START_TEST(CalendarInfo)
{
    Test_GenitiveLookAhead();
    Test_ShortestDayNamesAndMonthDay();
    Test_YearRange();
    Test_EnUsDateFormats();
}
