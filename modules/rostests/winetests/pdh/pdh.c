/*
 * Tests for pdh.dll (Performance Data Helper)
 *
 * Copyright 2007 Hans Leidekker
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "windows.h"

#include "pdh.h"
#include "pdhmsg.h"
#include "winperf.h"

#include "wine/test.h"

static HMODULE pdh;

static PDH_STATUS   (WINAPI *pPdhAddEnglishCounterA)(PDH_HQUERY, LPCSTR, DWORD_PTR, PDH_HCOUNTER *);
static PDH_STATUS   (WINAPI *pPdhAddEnglishCounterW)(PDH_HQUERY, LPCWSTR, DWORD_PTR, PDH_HCOUNTER *);
static PDH_STATUS   (WINAPI *pPdhCollectQueryDataWithTime)(PDH_HQUERY, LONGLONG *);
static PDH_STATUS   (WINAPI *pPdhValidatePathExA)(PDH_HLOG, LPCSTR);
static PDH_STATUS   (WINAPI *pPdhValidatePathExW)(PDH_HLOG, LPCWSTR);
static double       (WINAPI *pPdhVbGetDoubleCounterValue)(PDH_HCOUNTER, PDH_STATUS *);

#define GETFUNCPTR(func) p##func = (void *)GetProcAddress( pdh, #func );


/* Returns true if the user interface is in English. Note that this does not
 * presume of the formatting of dates, numbers, etc.
 */
static BOOL is_lang_english(void)
{
    static HMODULE hkernel32 = NULL;
    static LANGID (WINAPI *pGetThreadUILanguage)(void) = NULL;
    static LANGID (WINAPI *pGetUserDefaultUILanguage)(void) = NULL;
    LANGID lang;

    if (!hkernel32)
    {
        hkernel32 = GetModuleHandleA("kernel32.dll");
        pGetThreadUILanguage = (void*)GetProcAddress(hkernel32, "GetThreadUILanguage");
        pGetUserDefaultUILanguage = (void*)GetProcAddress(hkernel32, "GetUserDefaultUILanguage");
    }
    /* a zero language id means "not available" (some systems only stub GetThreadUILanguage) */
    if (pGetThreadUILanguage && (lang = pGetThreadUILanguage()))
        return PRIMARYLANGID(lang) == LANG_ENGLISH;
    if (pGetUserDefaultUILanguage && (lang = pGetUserDefaultUILanguage()))
        return PRIMARYLANGID(lang) == LANG_ENGLISH;

    return PRIMARYLANGID(GetUserDefaultLangID()) == LANG_ENGLISH;
}

static void init_function_ptrs( void )
{
    pdh = GetModuleHandleA( "pdh" );
    GETFUNCPTR( PdhAddEnglishCounterA )
    GETFUNCPTR( PdhAddEnglishCounterW )
    GETFUNCPTR( PdhCollectQueryDataWithTime )
    GETFUNCPTR( PdhValidatePathExA )
    GETFUNCPTR( PdhValidatePathExW )
    GETFUNCPTR( PdhVbGetDoubleCounterValue )
}

static const WCHAR processor_time[] = L"% Processor Time";
static const WCHAR uptime[] = L"System Up Time";

static const WCHAR system_uptime[] = L"\\System\\System Up Time";
static const WCHAR nonexistent_counter[] = L"\\System\\System Down Time";
static const WCHAR percentage_processor_time[] = L"\\Processor(_Total)\\% Processor Time";

static void test_PdhOpenQueryA( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;

    ret = PdhOpenQueryA( NULL, 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( NULL );
    ok(ret == PDH_INVALID_HANDLE, "PdhCloseQuery failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( &query );
    ok(ret == PDH_INVALID_HANDLE, "PdhCloseQuery failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == PDH_INVALID_HANDLE, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhOpenQueryW( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;

    ret = PdhOpenQueryW( NULL, 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhOpenQueryW failed 0x%08lx\n", ret);

    ret = PdhOpenQueryW( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryW failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( NULL );
    ok(ret == PDH_INVALID_HANDLE, "PdhCloseQuery failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( &query );
    ok(ret == PDH_INVALID_HANDLE, "PdhCloseQuery failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == PDH_INVALID_HANDLE, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhAddCounterA( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( NULL, "\\System\\System Up Time", 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( NULL, "\\System\\System Up Time", 0, &counter );
    ok(ret == PDH_INVALID_HANDLE, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, NULL, 0, &counter );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\Nonexistent Counter", 0, &counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER ||
       broken(ret == PDH_INVALID_PATH), /* Win2K */
       "PdhAddCounterA failed 0x%08lx\n", ret);
    ok(!counter, "PdhAddCounterA failed %p\n", counter);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( NULL );
    ok(ret == PDH_INVALID_HANDLE, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( counter );
    ok(ret == PDH_INVALID_HANDLE, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhRemoveCounter( NULL );
    ok(ret == PDH_INVALID_HANDLE, "PdhRemoveCounter failed 0x%08lx\n", ret);

    ret = PdhRemoveCounter( counter );
    ok(ret == ERROR_SUCCESS, "PdhRemoveCounter failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhAddCounterW( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;

    ret = PdhOpenQueryW( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( NULL, percentage_processor_time, 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( NULL, percentage_processor_time, 0, &counter );
    ok(ret == PDH_INVALID_HANDLE, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( query, NULL, 0, &counter );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( query, percentage_processor_time, 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( query, nonexistent_counter, 0, &counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER ||
       broken(ret == PDH_INVALID_PATH), /* Win2K */
       "PdhAddCounterW failed 0x%08lx\n", ret);
    ok(!counter, "PdhAddCounterW failed %p\n", counter);

    ret = PdhAddCounterW( query, percentage_processor_time, 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( NULL );
    ok(ret == PDH_INVALID_HANDLE, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( counter );
    ok(ret == PDH_INVALID_HANDLE, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhRemoveCounter( NULL );
    ok(ret == PDH_INVALID_HANDLE, "PdhRemoveCounter failed 0x%08lx\n", ret);

    ret = PdhRemoveCounter( counter );
    ok(ret == ERROR_SUCCESS, "PdhRemoveCounter failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhAddEnglishCounterA( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == PDH_NO_DATA, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterA( NULL, "\\System\\System Up Time", 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddEnglishCounterA failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterA( NULL, "\\System\\System Up Time", 0, &counter );
    ok(ret == PDH_INVALID_HANDLE || broken(ret == PDH_INVALID_ARGUMENT) /* win10 <= 1909 */,
       "PdhAddEnglishCounterA failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterA( query, NULL, 0, &counter );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddEnglishCounterA failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterA( query, "\\System\\System Up Time", 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddEnglishCounterA failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterA( query, "\\System\\System Down Time", 0, &counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhAddEnglishCounterA failed 0x%08lx\n", ret);
    ok(!counter, "PdhAddEnglishCounterA failed %p\n", counter);

    ret = pPdhAddEnglishCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterA failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhRemoveCounter( counter );
    ok(ret == ERROR_SUCCESS, "PdhRemoveCounter failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhAddEnglishCounterW( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;

    ret = PdhOpenQueryW( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryW failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == PDH_NO_DATA, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterW( NULL, system_uptime, 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterW( NULL, system_uptime, 0, &counter );
    ok(ret == PDH_INVALID_HANDLE || broken(ret == PDH_INVALID_ARGUMENT) /* win10 <= 1909 */,
       "PdhAddEnglishCounterW failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterW( query, NULL, 0, &counter );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterW( query, system_uptime, 0, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);

    ret = pPdhAddEnglishCounterW( query, nonexistent_counter, 0, &counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    ok(!counter, "PdhAddEnglishCounterA failed %p\n", counter);

    ret = pPdhAddEnglishCounterW( query, system_uptime, 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhRemoveCounter( counter );
    ok(ret == ERROR_SUCCESS, "PdhRemoveCounter failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhCollectQueryDataWithTime( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    LONGLONG time;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == PDH_NO_DATA, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = pPdhCollectQueryDataWithTime( NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhCollectQueryDataWithTime failed 0x%08lx\n", ret);

    ret = pPdhCollectQueryDataWithTime( query, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhCollectQueryDataWithTime failed 0x%08lx\n", ret);

    ret = pPdhCollectQueryDataWithTime( NULL, &time );
    ok(ret == PDH_INVALID_HANDLE, "PdhCollectQueryDataWithTime failed 0x%08lx\n", ret);

    ret = pPdhCollectQueryDataWithTime( query, &time );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryDataWithTime failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhGetFormattedCounterValue( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    PDH_FMT_COUNTERVALUE value;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( NULL, PDH_FMT_LARGE, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( NULL, PDH_FMT_LARGE, NULL, &value );
    ok(ret == PDH_INVALID_HANDLE, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE | PDH_FMT_NOSCALE, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE | PDH_FMT_NOCAP100, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE | PDH_FMT_1000, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( counter, 2 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhGetRawCounterValue( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    PDH_RAW_COUNTER value;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhGetRawCounterValue( NULL, NULL, &value );
    ok(ret == PDH_INVALID_HANDLE, "PdhGetRawCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetRawCounterValue( counter, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetRawCounterValue failed 0x%08lx\n", ret);

    ret = PdhGetRawCounterValue( counter, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetRawCounterValue failed 0x%08lx\n", ret);
    ok(value.CStatus == ERROR_SUCCESS, "expected ERROR_SUCCESS got %lx\n", value.CStatus);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhGetRawCounterValue( counter, NULL, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetRawCounterValue failed 0x%08lx\n", ret);
    ok(value.CStatus == ERROR_SUCCESS, "expected ERROR_SUCCESS got %lx\n", value.CStatus);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhVbGetDoubleCounterValue(void)
{
    PDH_FMT_COUNTERVALUE value;
    PDH_HCOUNTER counter;
    PDH_STATUS status;
    PDH_HQUERY query;
    double ret;

    status = PdhOpenQueryA( NULL, 0, &query );
    ok(status == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", status);

    status = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(status == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", status);

    status = PdhCollectQueryData(query);
    ok(status == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", status);

    status = PdhGetFormattedCounterValue( counter, PDH_FMT_DOUBLE, NULL, &value );
    ok(status == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", status);

    ret = pPdhVbGetDoubleCounterValue( NULL, NULL );
    ok(ret == 0.0, "Unexpected value %f\n", ret);

    status = PDH_FUNCTION_NOT_FOUND;
    ret = pPdhVbGetDoubleCounterValue( NULL, &status );
    ok(status == PDH_INVALID_HANDLE, "PdhVbGetDoubleCounterValue failed 0x%08lx\n", status);
    ok(ret == 0.0, "Unexpected value %f\n", ret);

    ret = pPdhVbGetDoubleCounterValue( counter, NULL );
    ok(ret == value.doubleValue, "Unexpected value %f\n", ret);

    status = PDH_FUNCTION_NOT_FOUND;
    ret = pPdhVbGetDoubleCounterValue( counter, &status );
    ok(status == ERROR_SUCCESS, "PdhVbGetDoubleCounterValue failed 0x%08lx\n", status);
    ok(ret == value.doubleValue, "Unexpected value %f\n", ret);

    status = PdhCloseQuery(query);
    ok(status == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", status);
}

static void test_PdhSetCounterScaleFactor( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( NULL, 8 );
    ok(ret == PDH_INVALID_HANDLE, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( NULL, 1 );
    ok(ret == PDH_INVALID_HANDLE, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( counter, 8 );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( counter, -8 );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( counter, 7 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhSetCounterScaleFactor( counter, 0 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhGetCounterTimeBase( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    LONGLONG base;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhGetCounterTimeBase( NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetCounterTimeBase failed 0x%08lx\n", ret);

    ret = PdhGetCounterTimeBase( NULL, &base );
    ok(ret == PDH_INVALID_HANDLE, "PdhGetCounterTimeBase failed 0x%08lx\n", ret);

    ret = PdhGetCounterTimeBase( counter, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetCounterTimeBase failed 0x%08lx\n", ret);

    ret = PdhGetCounterTimeBase( counter, &base );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterTimeBase failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhGetCounterInfoA( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    PDH_COUNTER_INFO_A info;
    DWORD size;

    ret = PdhOpenQueryA( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryA failed 0x%08lx\n", ret);

    ret = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoA( NULL, 0, NULL, NULL );
    ok(ret == PDH_INVALID_HANDLE || ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoA failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoA( counter, 0, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoA failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoA( counter, 0, NULL, &info );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoA failed 0x%08lx\n", ret);

    size = sizeof(info) - 1;
    ret = PdhGetCounterInfoA( counter, 0, &size, NULL );
    ok(ret == PDH_MORE_DATA || ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoA failed 0x%08lx\n", ret);

    size = sizeof(info);
    ret = PdhGetCounterInfoA( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoA failed 0x%08lx\n", ret);
    ok(size == sizeof(info), "PdhGetCounterInfoA failed %ld\n", size);

    ret = PdhGetCounterInfoA( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoA failed 0x%08lx\n", ret);
    ok(info.lScale == 0, "lScale %ld\n", info.lScale);

    ret = PdhSetCounterScaleFactor( counter, 0 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoA( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoA failed 0x%08lx\n", ret);
    ok(info.lScale == 0, "lScale %ld\n", info.lScale);

    ret = PdhSetCounterScaleFactor( counter, -5 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoA( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoA failed 0x%08lx\n", ret);
    ok(info.lScale == -5, "lScale %ld\n", info.lScale);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhGetCounterInfoW( void )
{
    PDH_STATUS ret;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    PDH_COUNTER_INFO_W info;
    DWORD size;

    ret = PdhOpenQueryW( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( query, percentage_processor_time, 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoW( NULL, 0, NULL, NULL );
    ok(ret == PDH_INVALID_HANDLE || ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoW failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoW( counter, 0, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoW failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoW( counter, 0, NULL, &info );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoW failed 0x%08lx\n", ret);

    size = sizeof(info) - 1;
    ret = PdhGetCounterInfoW( counter, 0, &size, NULL );
    ok(ret == PDH_MORE_DATA || ret == PDH_INVALID_ARGUMENT, "PdhGetCounterInfoW failed 0x%08lx\n", ret);

    size = sizeof(info);
    ret = PdhGetCounterInfoW( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoW failed 0x%08lx\n", ret);
    ok(size == sizeof(info), "PdhGetCounterInfoW failed %ld\n", size);

    ret = PdhGetCounterInfoW( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoW failed 0x%08lx\n", ret);
    ok(info.lScale == 0, "lScale %ld\n", info.lScale);

    ret = PdhSetCounterScaleFactor( counter, 0 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoW( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoW failed 0x%08lx\n", ret);
    ok(info.lScale == 0, "lScale %ld\n", info.lScale);

    ret = PdhSetCounterScaleFactor( counter, -5 );
    ok(ret == ERROR_SUCCESS, "PdhSetCounterScaleFactor failed 0x%08lx\n", ret);

    ret = PdhGetCounterInfoW( counter, 0, &size, &info );
    ok(ret == ERROR_SUCCESS, "PdhGetCounterInfoW failed 0x%08lx\n", ret);
    ok(info.lScale == -5, "lScale %ld\n", info.lScale);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhLookupPerfIndexByNameA( void )
{
    PDH_STATUS ret;
    DWORD index;

    ret = PdhLookupPerfIndexByNameA( NULL, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfIndexByNameA failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameA( NULL, NULL, &index );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfIndexByNameA failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameA( NULL, "No Counter", &index );
    ok(ret == PDH_STRING_NOT_FOUND, "PdhLookupPerfIndexByNameA failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameA( NULL, "% Processor Time", NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfIndexByNameA failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameA( NULL, "% Processor Time", &index );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfIndexByNameA failed 0x%08lx\n", ret);
    ok(index == 6, "PdhLookupPerfIndexByNameA failed %ld\n", index);

    ret = PdhLookupPerfIndexByNameA( NULL, "System Up Time", &index );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfIndexByNameA failed 0x%08lx\n", ret);
    ok(index == 674, "PdhLookupPerfIndexByNameA failed %ld\n", index);
}

static void test_PdhLookupPerfIndexByNameW( void )
{
    PDH_STATUS ret;
    DWORD index;

    ret = PdhLookupPerfIndexByNameW( NULL, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameW( NULL, NULL, &index );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameW( NULL, L"No Counter", &index );
    ok(ret == PDH_STRING_NOT_FOUND, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameW( NULL, processor_time, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);

    ret = PdhLookupPerfIndexByNameW( NULL, processor_time, &index );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);
    ok(index == 6, "PdhLookupPerfIndexByNameW failed %ld\n", index);

    ret = PdhLookupPerfIndexByNameW( NULL, uptime, &index );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);
    ok(index == 674, "PdhLookupPerfIndexByNameW failed %ld\n", index);
}

static void test_PdhLookupPerfNameByIndexA( void )
{
    PDH_STATUS ret;
    char buffer[PDH_MAX_COUNTER_NAME] = "!!";
    DWORD size;

    ret = PdhLookupPerfNameByIndexA( NULL, 0, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfNameByIndexA failed 0x%08lx\n", ret);

    size = 0;
    ret = PdhLookupPerfNameByIndexA( NULL, 6, buffer, &size );
    ok(ret == PDH_MORE_DATA || ret == PDH_INSUFFICIENT_BUFFER, "PdhLookupPerfNameByIndexA failed 0x%08lx\n", ret);

    size = sizeof(buffer);
    ret = PdhLookupPerfNameByIndexA( NULL, 6, buffer, &size );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfNameByIndexA failed 0x%08lx\n", ret);
    ok(!lstrcmpA( buffer, "% Processor Time" ),
       "PdhLookupPerfNameByIndexA failed, got %s expected \'%% Processor Time\'\n", buffer);
    ok(size == sizeof("% Processor Time"), "PdhLookupPerfNameByIndexA failed %ld\n", size);

    size = sizeof(buffer);
    ret = PdhLookupPerfNameByIndexA( NULL, 674, NULL, &size );
    ok(ret == PDH_INVALID_ARGUMENT ||
       ret == PDH_MORE_DATA, /* win2k3 */
       "PdhLookupPerfNameByIndexA failed 0x%08lx\n", ret);

    size = sizeof(buffer);
    ret = PdhLookupPerfNameByIndexA( NULL, 674, buffer, &size );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfNameByIndexA failed 0x%08lx\n", ret);
    ok(!lstrcmpA( buffer, "System Up Time" ),
       "PdhLookupPerfNameByIndexA failed, got %s expected \'System Up Time\'\n", buffer);
    ok(size == sizeof("System Up Time"), "PdhLookupPerfNameByIndexA failed %ld\n", size);
}

static void test_PdhLookupPerfNameByIndexW( void )
{
    PDH_STATUS ret;
    WCHAR buffer[PDH_MAX_COUNTER_NAME];
    DWORD size;

    ret = PdhLookupPerfNameByIndexW( NULL, 0, NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);

    size = 0;
    ret = PdhLookupPerfNameByIndexW( NULL, 6, buffer, &size );
    ok(ret == PDH_MORE_DATA || ret == PDH_INSUFFICIENT_BUFFER, "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);

    size = ARRAY_SIZE(buffer);
    ret = PdhLookupPerfNameByIndexW( NULL, 6, buffer, &size );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);
    ok(size == ARRAY_SIZE(processor_time), "PdhLookupPerfNameByIndexW failed %ld\n", size);

    size = ARRAY_SIZE(buffer);
    ret = PdhLookupPerfNameByIndexW( NULL, 674, NULL, &size );
    ok(ret == PDH_INVALID_ARGUMENT ||
       ret == PDH_MORE_DATA, /* win2k3 */
       "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);

    size = ARRAY_SIZE(buffer);
    ret = PdhLookupPerfNameByIndexW( NULL, 674, buffer, &size );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);
    ok(size == ARRAY_SIZE(uptime), "PdhLookupPerfNameByIndexW failed %ld\n", size);
}

static void test_PdhValidatePathA( void )
{
    PDH_STATUS ret;

    ret = PdhValidatePathA( NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathA failed 0x%08lx\n", ret);

    ret = PdhValidatePathA( "" );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathA failed 0x%08lx\n", ret);

    ret = PdhValidatePathA( "\\System" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathA failed 0x%08lx\n", ret);

    ret = PdhValidatePathA( "System Up Time" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathA failed 0x%08lx\n", ret);

    ret = PdhValidatePathA( "\\System\\Nonexistent Counter" );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhValidatePathA failed 0x%08lx\n", ret);

    ret = PdhValidatePathA( "\\System\\System Up Time" );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathA failed 0x%08lx\n", ret);
}

static void test_PdhValidatePathW( void )
{
    PDH_STATUS ret;

    ret = PdhValidatePathW( NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathW failed 0x%08lx\n", ret);

    ret = PdhValidatePathW( L"" );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathW failed 0x%08lx\n", ret);

    ret = PdhValidatePathW( L"\\System" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathW failed 0x%08lx\n", ret);

    ret = PdhValidatePathW( uptime );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathW failed 0x%08lx\n", ret);

    ret = PdhValidatePathW( nonexistent_counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhValidatePathW failed 0x%08lx\n", ret);

    ret = PdhValidatePathW( system_uptime );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathW failed 0x%08lx\n", ret);
}

static void test_PdhValidatePathExA( void )
{
    PDH_STATUS ret;

    ret = pPdhValidatePathExA( NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathExA failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExA( NULL, "" );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathExA failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExA( NULL, "\\System" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathExA failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExA( NULL, "System Up Time" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathExA failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExA( NULL, "\\System\\System Down Time" );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhValidatePathExA failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExA( NULL, "\\System\\System Up Time" );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathExA failed 0x%08lx\n", ret);
}

static void test_PdhValidatePathExW( void )
{
    PDH_STATUS ret;

    ret = pPdhValidatePathExW( NULL, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathExW failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExW( NULL, L"" );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhValidatePathExW failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExW( NULL, L"\\System" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathExW failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExW( NULL, uptime );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathExW failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExW( NULL, nonexistent_counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhValidatePathExW failed 0x%08lx\n", ret);

    ret = pPdhValidatePathExW( NULL, system_uptime );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathExW failed 0x%08lx\n", ret);
}

static void test_PdhCollectQueryDataEx(void)
{
    PDH_STATUS status;
    PDH_HQUERY query;
    PDH_HCOUNTER counter;
    HANDLE event;
    BOOL ret;
    UINT i;

    status = PdhOpenQueryA( NULL, 0, &query );
    ok(status == ERROR_SUCCESS, "PdhOpenQuery failed 0x%08lx\n", status);

    event = CreateEventA( NULL, FALSE, FALSE, "winetest" );
    ok(event != NULL, "CreateEvent failed\n");

    status = PdhAddCounterA( query, "\\System\\System Up Time", 0, &counter );
    ok(status == ERROR_SUCCESS, "PdhAddCounterA failed 0x%08lx\n", status);

    status = PdhCollectQueryDataEx( NULL, 1, event );
    ok(status == PDH_INVALID_HANDLE, "PdhCollectQueryDataEx failed 0x%08lx\n", status);

    status = PdhCollectQueryDataEx( query, 1, NULL );
    ok(status == ERROR_SUCCESS, "PdhCollectQueryDataEx failed 0x%08lx\n", status);

    status = PdhCollectQueryDataEx( query, 1, event );
    ok(status == ERROR_SUCCESS, "PdhCollectQueryDataEx failed 0x%08lx\n", status);

    status = PdhCollectQueryData( query );
    ok(status == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", status);

    for (i = 0; i < 3; i++)
    {
        if (WaitForSingleObject( event, INFINITE ) == WAIT_OBJECT_0)
        {
            PDH_FMT_COUNTERVALUE value;

            status = PdhGetFormattedCounterValue( counter, PDH_FMT_LARGE, NULL, &value );
            ok(status == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", status);

            trace( "uptime %s\n", wine_dbgstr_longlong(value.largeValue) );
        }
    }

    ret = CloseHandle( event );
    ok(ret, "CloseHandle failed\n");

    status = PdhCloseQuery( query );
    ok(status == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", status);
}

static void test_PdhMakeCounterPathA(void)
{
    PDH_STATUS ret;
    PDH_COUNTER_PATH_ELEMENTS_A e;
    char buffer[1024];
    DWORD buflen;

    ret = PdhMakeCounterPathA(NULL, NULL, NULL, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);

    buflen = 0;
    ret = PdhMakeCounterPathA(NULL, NULL, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);

    if (0) { /* Crashes on Windows 10 >= 2004 */
    buflen = 0;
    ret = PdhMakeCounterPathA(NULL, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    }

    buflen = sizeof(buffer);
    memset(&e, 0, sizeof(e));
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szMachineName = (char *)"machine";
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, ""), "expected \"machine\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szObjectName = (char *)"object";
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, ""), "expected \"machine\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szInstanceName = (char *)"instance";
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, ""), "expected \"machine\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szParentInstance = (char *)"parent";
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, ""), "expected \"machine\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.dwInstanceIndex = 1;
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, ""), "expected \"machine\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szCounterName = (char *)"counter";
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, "\\\\machine\\object(parent/instance#1)\\counter"),
       "expected \"\\\\machine\\object(parent/instance#1)\\counter\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szParentInstance = NULL;
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, "\\\\machine\\object(instance#1)\\counter"),
       "expected \"\\\\machine\\object(instance#1)\\counter\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szInstanceName = NULL;
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, "\\\\machine\\object\\counter"),
       "expected \"\\\\machine\\object\\counter\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szMachineName = NULL;
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
    ok(!strcmp(buffer, "\\object\\counter"),
       "expected \"\\object\\counter\" got %s\n", buffer);

    buffer[0] = 0;
    buflen = sizeof(buffer);
    e.szObjectName = NULL;
    ret = PdhMakeCounterPathA(&e, buffer, &buflen, 0);
    ok(ret == PDH_INVALID_ARGUMENT, "PdhMakeCounterPathA failed 0x%08lx\n", ret);
}

static void test_PdhMakeCounterPath_machine(void)
{
    PDH_COUNTER_PATH_ELEMENTS_W e;
    WCHAR buffer[256];
    DWORD size;
    PDH_STATUS ret;

    memset( &e, 0, sizeof(e) );
    e.szMachineName = (WCHAR *)L"\\\\machine";
    e.szObjectName = (WCHAR *)L"object";
    e.szCounterName = (WCHAR *)L"counter";
    size = ARRAY_SIZE(buffer);
    ret = PdhMakeCounterPathW( &e, buffer, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(!lstrcmpW( buffer, L"\\\\machine\\object\\counter" ), "got %s\n", debugstr_w(buffer));

    e.szInstanceName = (WCHAR *)L"instance";
    e.dwInstanceIndex = ~0u;
    size = ARRAY_SIZE(buffer);
    ret = PdhMakeCounterPathW( &e, buffer, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(!lstrcmpW( buffer, L"\\\\machine\\object(instance)\\counter" ), "got %s\n", debugstr_w(buffer));

    e.dwInstanceIndex = 0;
    size = ARRAY_SIZE(buffer);
    ret = PdhMakeCounterPathW( &e, buffer, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(!lstrcmpW( buffer, L"\\\\machine\\object(instance)\\counter" ), "got %s\n", debugstr_w(buffer));
}

static void test_PdhMakeCounterPathW_long(void)
{
    PDH_COUNTER_PATH_ELEMENTS_W e;
    WCHAR *name, *buffer;
    DWORD size, i;
    PDH_STATUS ret;

    name = malloc( 2001 * sizeof(WCHAR) );
    buffer = malloc( 4096 * sizeof(WCHAR) );
    for (i = 0; i < 2000; i++) name[i] = 'a';
    name[2000] = 0;

    memset( &e, 0, sizeof(e) );
    e.szObjectName = (WCHAR *)L"Memory";
    e.szCounterName = name;

    size = 0;
    ret = PdhMakeCounterPathW( &e, NULL, &size, 0 );
    ok(ret == PDH_MORE_DATA, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(size == 2009, "got %lu\n", size);

    size = 100;
    ret = PdhMakeCounterPathW( &e, buffer, &size, 0 );
    ok(ret == PDH_MORE_DATA, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(size == 2009, "got %lu\n", size);

    size = 4096;
    ret = PdhMakeCounterPathW( &e, buffer, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(size == 2009 && lstrlenW( buffer ) == 2008, "got %lu, length %d\n", size, lstrlenW( buffer ));
    ok(!memcmp( buffer, L"\\Memory\\aaa", 11 * sizeof(WCHAR) ), "got %s\n", debugstr_wn( buffer, 16 ));

    e.szMachineName = (WCHAR *)L"HOST";
    e.szInstanceName = name;
    e.dwInstanceIndex = 3;
    size = 4096;
    ret = PdhMakeCounterPathW( &e, buffer, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhMakeCounterPathW failed 0x%08lx\n", ret);
    ok(size == 4019 && lstrlenW( buffer ) == 4018, "got %lu, length %d\n", size, lstrlenW( buffer ));

    free( name );
    free( buffer );
}

static void test_PdhGetDllVersion(void)
{
    PDH_STATUS ret;
    DWORD version;

    ret = PdhGetDllVersion(NULL);
    ok(ret == PDH_INVALID_ARGUMENT ||
       broken(ret == ERROR_SUCCESS), /* Vista+ */
       "Expected PdhGetDllVersion to return PDH_INVALID_ARGUMENT, got %ld\n", ret);

    ret = PdhGetDllVersion(&version);
    ok(ret == ERROR_SUCCESS,
       "Expected PdhGetDllVersion to return ERROR_SUCCESS, got %ld\n", ret);

    if (ret == ERROR_SUCCESS)
    {
        ok(version == PDH_CVERSION_WIN50 ||
           version == PDH_VERSION,
           "Expected version number to be PDH_CVERSION_WIN50 or PDH_VERSION, got %lu\n", version);
    }
}

static WCHAR computer_prefix[MAX_COMPUTERNAME_LENGTH + 3];

static void init_computer_prefix(void)
{
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;

    computer_prefix[0] = computer_prefix[1] = '\\';
    ok(GetComputerNameW( computer_prefix + 2, &len ), "GetComputerNameW failed %lu\n", GetLastError());
}

/* does the multi-sz list contain the string (case sensitive)? */
static BOOL list_contains( const WCHAR *list, const WCHAR *str )
{
    for (; *list; list += lstrlenW( list ) + 1)
        if (!lstrcmpW( list, str )) return TRUE;
    return FALSE;
}

static DWORD list_count( const WCHAR *list )
{
    DWORD n = 0;
    for (; *list; list += lstrlenW( list ) + 1) n++;
    return n;
}

static WCHAR *get_object_list(void)
{
    DWORD size = 0;
    PDH_STATUS ret;
    WCHAR *buf;

    ret = PdhEnumObjectsW( NULL, NULL, NULL, &size, PERF_DETAIL_WIZARD, FALSE );
    ok(ret == PDH_MORE_DATA, "PdhEnumObjectsW failed 0x%08lx\n", ret);
    ok(size > 2, "size %lu\n", size);
    buf = malloc( size * sizeof(WCHAR) );
    ret = PdhEnumObjectsW( NULL, NULL, buf, &size, PERF_DETAIL_WIZARD, FALSE );
    ok(ret == ERROR_SUCCESS, "PdhEnumObjectsW failed 0x%08lx\n", ret);
    return buf;
}

static void test_PdhEnumObjectsW(void)
{
    PDH_STATUS ret;
    DWORD size;
    WCHAR *buf, tiny[4];

    buf = get_object_list();
    ok(list_contains( buf, L"Memory" ), "Memory not in the list\n");
    ok(list_contains( buf, L"Processor" ), "Processor not in the list\n");
    ok(list_contains( buf, L"System" ), "System not in the list\n");
    ok(list_contains( buf, L"PhysicalDisk" ), "PhysicalDisk not in the list\n");
    ok(!list_contains( buf, L"bad-name-DAD288C0-72F8-47D3-8C54-C69481B528DF" ), "unexpected object\n");
    free( buf );

    size = 0;
    ret = PdhEnumObjectsW( NULL, NULL, tiny, &size, PERF_DETAIL_WIZARD, FALSE );
    ok(ret == PDH_MORE_DATA, "PdhEnumObjectsW failed 0x%08lx\n", ret);
    ok(size > ARRAY_SIZE(tiny), "size %lu\n", size);

    size = 0;
    ret = PdhEnumObjectsW( NULL, L"nosuchhost", NULL, &size, PERF_DETAIL_WIZARD, FALSE );
    ok(ret == PDH_CSTATUS_NO_MACHINE, "PdhEnumObjectsW failed 0x%08lx\n", ret);

    size = 0;
    ret = PdhEnumObjectsW( NULL, computer_prefix, NULL, &size, PERF_DETAIL_WIZARD, FALSE );
    ok(ret == PDH_MORE_DATA, "PdhEnumObjectsW failed 0x%08lx\n", ret);
}

static void test_PdhEnumObjectItemsW(void)
{
    DWORD csize, isize, csize2, isize2;
    WCHAR *counters, *instances;
    PDH_STATUS ret;

    csize = isize = 0;
    ret = PdhEnumObjectItemsW( NULL, NULL, L"Memory", NULL, &csize, NULL, &isize, PERF_DETAIL_WIZARD, 0 );
    ok(ret == PDH_MORE_DATA, "PdhEnumObjectItemsW failed 0x%08lx\n", ret);
    ok(csize > 2, "csize %lu\n", csize);
    ok(!isize, "Memory has no instances, isize %lu\n", isize);
    counters = malloc( csize * sizeof(WCHAR) );
    csize2 = csize;
    isize2 = 0;
    ret = PdhEnumObjectItemsW( NULL, NULL, L"Memory", counters, &csize2, NULL, &isize2, PERF_DETAIL_WIZARD, 0 );
    ok(ret == ERROR_SUCCESS, "PdhEnumObjectItemsW failed 0x%08lx\n", ret);
    ok(csize2 == csize, "got %lu, expected %lu\n", csize2, csize);
    ok(list_contains( counters, L"Available Bytes" ), "Available Bytes not found\n");
    ok(list_contains( counters, L"% Committed Bytes In Use" ), "%% Committed Bytes In Use not found\n");
    ok(list_contains( counters, L"Cache Faults/sec" ), "Cache Faults/sec not found\n");
    free( counters );

    csize = isize = 0;
    ret = PdhEnumObjectItemsW( NULL, NULL, L"Processor", NULL, &csize, NULL, &isize, PERF_DETAIL_WIZARD, 0 );
    ok(ret == PDH_MORE_DATA, "PdhEnumObjectItemsW failed 0x%08lx\n", ret);
    ok(csize > 2 && isize > 2, "csize %lu, isize %lu\n", csize, isize);
    counters = malloc( csize * sizeof(WCHAR) );
    instances = malloc( isize * sizeof(WCHAR) );
    csize2 = csize;
    isize2 = isize - 1;
    ret = PdhEnumObjectItemsW( NULL, NULL, L"Processor", counters, &csize2, instances, &isize2, PERF_DETAIL_WIZARD, 0 );
    ok(ret == PDH_MORE_DATA, "PdhEnumObjectItemsW failed 0x%08lx\n", ret);
    csize2 = csize;
    isize2 = isize;
    ret = PdhEnumObjectItemsW( NULL, NULL, L"Processor", counters, &csize2, instances, &isize2, PERF_DETAIL_WIZARD, 0 );
    ok(ret == ERROR_SUCCESS, "PdhEnumObjectItemsW failed 0x%08lx\n", ret);
    ok(list_contains( counters, L"% Processor Time" ), "%% Processor Time not found\n");
    ok(list_contains( instances, L"0" ), "instance 0 not found\n");
    ok(list_contains( instances, L"_Total" ), "_Total not found\n");
    ok(list_count( instances ) >= 2, "got %lu instances\n", list_count( instances ));
    free( counters );
    free( instances );

    csize = isize = 0;
    ret = PdhEnumObjectItemsW( NULL, NULL, L"bad-name-DAD288C0-72F8-47D3-8C54-C69481B528DF", NULL, &csize, NULL, &isize,
                               PERF_DETAIL_WIZARD, 0 );
    ok(ret == PDH_CSTATUS_NO_OBJECT, "PdhEnumObjectItemsW failed 0x%08lx\n", ret);
}

static WCHAR *expand( const WCHAR *path, PDH_STATUS *ret )
{
    DWORD size = 0;
    WCHAR *buf;

    *ret = PdhExpandWildCardPathW( NULL, path, NULL, &size, 0 );
    if (*ret != PDH_MORE_DATA) return NULL;
    ok(size > 2, "size %lu\n", size);
    buf = malloc( size * sizeof(WCHAR) );
    *ret = PdhExpandWildCardPathW( NULL, path, buf, &size, 0 );
    return buf;
}

static void test_PdhExpandWildCardPathW(void)
{
    WCHAR *buf, want[MAX_PATH];
    PDH_STATUS ret;

    buf = expand( L"\\Processor(*)\\% Processor Time", &ret );
    ok(ret == ERROR_SUCCESS, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    if (buf)
    {
        lstrcpyW( want, computer_prefix );
        lstrcatW( want, L"\\Processor(_Total)\\% Processor Time" );
        ok(list_contains( buf, want ), "%s not found\n", debugstr_w(want));
        ok(list_count( buf ) >= 2, "got %lu paths\n", list_count( buf ));
        free( buf );
    }

    buf = expand( L"\\Memory\\Available Bytes", &ret );
    ok(ret == ERROR_SUCCESS, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    if (buf)
    {
        lstrcpyW( want, computer_prefix );
        lstrcatW( want, L"\\Memory\\Available Bytes" );
        ok(list_count( buf ) == 1, "got %lu paths\n", list_count( buf ));
        ok(list_contains( buf, want ), "%s not found, got %s\n", debugstr_w(want), debugstr_w(buf));
        free( buf );
    }

    buf = expand( L"\\Memory\\*", &ret );
    ok(ret == ERROR_SUCCESS, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    if (buf)
    {
        lstrcpyW( want, computer_prefix );
        lstrcatW( want, L"\\Memory\\Page Faults/sec" );
        ok(list_contains( buf, want ), "%s not found\n", debugstr_w(want));
        ok(list_count( buf ) > 5, "got %lu paths\n", list_count( buf ));
        free( buf );
    }

    buf = expand( L"\\Memory\\No Such Counter", &ret );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    free( buf );
    buf = expand( L"\\No Such Object(*)\\Counter", &ret );
    ok(ret == PDH_CSTATUS_NO_OBJECT, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    free( buf );
    buf = expand( L"bad-name", &ret );
    ok(ret == PDH_INVALID_PATH, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    free( buf );
    buf = expand( L"\\Processor\\% Processor Time", &ret );
    ok(ret == PDH_INVALID_PATH, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    free( buf );
    buf = expand( L"\\\\nosuchhost\\Memory\\Available Bytes", &ret );
    ok(ret == PDH_CSTATUS_NO_MACHINE, "PdhExpandWildCardPathW failed 0x%08lx\n", ret);
    free( buf );
}

static void test_PdhParseCounterPathW(void)
{
    PDH_COUNTER_PATH_ELEMENTS_W *e;
    DWORD size;
    PDH_STATUS ret;

    size = 0;
    ret = PdhParseCounterPathW( L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", NULL, &size, 0 );
    ok(ret == PDH_MORE_DATA, "PdhParseCounterPathW failed 0x%08lx\n", ret);
    ok(size > sizeof(*e), "size %lu\n", size);
    e = malloc( size );
    ret = PdhParseCounterPathW( L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", e, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhParseCounterPathW failed 0x%08lx\n", ret);
    ok(!lstrcmpW( e->szMachineName, computer_prefix ), "got %s\n", debugstr_w(e->szMachineName));
    ok(!lstrcmpW( e->szObjectName, L"PhysicalDisk" ), "got %s\n", debugstr_w(e->szObjectName));
    ok(!lstrcmpW( e->szInstanceName, L"_Total" ), "got %s\n", debugstr_w(e->szInstanceName));
    ok(!e->szParentInstance, "got %s\n", debugstr_w(e->szParentInstance));
    ok(e->dwInstanceIndex == 0, "got %lu\n", e->dwInstanceIndex);
    ok(!lstrcmpW( e->szCounterName, L"Disk Read Bytes/sec" ), "got %s\n", debugstr_w(e->szCounterName));
    free( e );

    size = 0;
    ret = PdhParseCounterPathW( L"\\\\HOST\\Memory\\Available Bytes", NULL, &size, 0 );
    ok(ret == PDH_MORE_DATA, "PdhParseCounterPathW failed 0x%08lx\n", ret);
    e = malloc( size );
    ret = PdhParseCounterPathW( L"\\\\HOST\\Memory\\Available Bytes", e, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhParseCounterPathW failed 0x%08lx\n", ret);
    ok(!lstrcmpW( e->szMachineName, L"\\\\HOST" ), "got %s\n", debugstr_w(e->szMachineName));
    ok(!e->szInstanceName, "got %s\n", debugstr_w(e->szInstanceName));
    ok(e->dwInstanceIndex == ~0u, "got %lu\n", e->dwInstanceIndex);
    free( e );

    size = 0;
    ret = PdhParseCounterPathW( L"\\Process(foo#1)\\ID Process", NULL, &size, 0 );
    ok(ret == PDH_MORE_DATA, "PdhParseCounterPathW failed 0x%08lx\n", ret);
    e = malloc( size );
    ret = PdhParseCounterPathW( L"\\Process(foo#1)\\ID Process", e, &size, 0 );
    ok(ret == ERROR_SUCCESS, "PdhParseCounterPathW failed 0x%08lx\n", ret);
    ok(!lstrcmpW( e->szInstanceName, L"foo" ), "got %s\n", debugstr_w(e->szInstanceName));
    ok(e->dwInstanceIndex == 1, "got %lu\n", e->dwInstanceIndex);
    free( e );

    size = 0;
    ret = PdhParseCounterPathW( L"bad-name", NULL, &size, 0 );
    ok(ret == PDH_INVALID_PATH, "PdhParseCounterPathW failed 0x%08lx\n", ret);
}

static void test_PdhValidatePath_sets(void)
{
    PDH_STATUS ret;

    ret = PdhValidatePathW( L"\\Memory\\Available Bytes" );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\memory\\available bytes" );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\Memory\\No Such Counter" );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\No Such Object\\Counter" );
    ok(ret == PDH_CSTATUS_NO_OBJECT, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\Processor(_Total)\\% Processor Time" );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\Processor(*)\\% Processor Time" );
    ok(ret == ERROR_SUCCESS, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\Processor(99999)\\% Processor Time" );
    ok(ret == PDH_CSTATUS_NO_INSTANCE, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\Processor\\% Processor Time" );
    ok(ret == PDH_CSTATUS_NO_INSTANCE, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\Memory(x)\\Available Bytes" );
    ok(ret == PDH_CSTATUS_NO_INSTANCE, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"\\\\nosuchhost\\Memory\\Available Bytes" );
    ok(ret == PDH_CSTATUS_NO_MACHINE, "PdhValidatePathW failed 0x%08lx\n", ret);
    ret = PdhValidatePathW( L"bad-name" );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhValidatePathW failed 0x%08lx\n", ret);
}

static void test_name_table(void)
{
    static const struct { DWORD index; const WCHAR *name; } names[] =
    {
        { 2, L"System" }, { 4, L"Memory" }, { 6, L"% Processor Time" }, { 24, L"Available Bytes" },
        { 230, L"Process" }, { 234, L"PhysicalDisk" }, { 238, L"Processor" }, { 510, L"Network Interface" },
        { 674, L"System Up Time" }, { 1406, L"% Committed Bytes In Use" },
    };
    WCHAR buffer[PDH_MAX_COUNTER_NAME];
    DWORD size, index, i;
    PDH_STATUS ret;

    for (i = 0; i < ARRAY_SIZE(names); i++)
    {
        size = ARRAY_SIZE(buffer);
        ret = PdhLookupPerfNameByIndexW( NULL, names[i].index, buffer, &size );
        ok(ret == ERROR_SUCCESS, "%lu: PdhLookupPerfNameByIndexW failed 0x%08lx\n", names[i].index, ret);
        ok(!lstrcmpW( buffer, names[i].name ), "%lu: got %s\n", names[i].index, debugstr_w(buffer));

        size = ARRAY_SIZE(buffer);
        ret = PdhLookupPerfNameByIndexW( computer_prefix, names[i].index, buffer, &size );
        ok(ret == ERROR_SUCCESS, "%lu: PdhLookupPerfNameByIndexW failed 0x%08lx\n", names[i].index, ret);

        ret = PdhLookupPerfIndexByNameW( NULL, names[i].name, &index );
        ok(ret == ERROR_SUCCESS, "%s: PdhLookupPerfIndexByNameW failed 0x%08lx\n", debugstr_w(names[i].name), ret);
        ok(index == names[i].index, "%s: got %lu\n", debugstr_w(names[i].name), index);
    }

    size = ARRAY_SIZE(buffer);
    ret = PdhLookupPerfNameByIndexW( L"nosuchhost", 4, buffer, &size );
    ok(ret == PDH_CSTATUS_NO_MACHINE, "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);
    size = ARRAY_SIZE(buffer);
    ret = PdhLookupPerfNameByIndexW( NULL, 99999, buffer, &size );
    ok(ret == PDH_INVALID_ARGUMENT, "PdhLookupPerfNameByIndexW failed 0x%08lx\n", ret);
}

static void test_data_source(void)
{
    PDH_HLOG source = NULL;
    PDH_HQUERY query;
    DWORD size;
    WCHAR *machines;
    PDH_STATUS ret;

    ret = PdhBindInputDataSourceW( &source, NULL );
    ok(ret == ERROR_SUCCESS, "PdhBindInputDataSourceW failed 0x%08lx\n", ret);

    ret = PdhOpenQueryH( source, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryH failed 0x%08lx\n", ret);
    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);

    size = 0;
    ret = PdhEnumMachinesHW( source, NULL, &size );
    ok(ret == PDH_MORE_DATA, "PdhEnumMachinesHW failed 0x%08lx\n", ret);
    machines = malloc( size * sizeof(WCHAR) );
    ret = PdhEnumMachinesHW( source, machines, &size );
    ok(ret == ERROR_SUCCESS, "PdhEnumMachinesHW failed 0x%08lx\n", ret);
    ok(list_count( machines ) <= 1 || list_contains( machines, computer_prefix ), "%s not found\n", debugstr_w(computer_prefix));
    free( machines );

    if (source)
    {
        ret = PdhCloseLog( source, 0 );
        ok(ret == ERROR_SUCCESS, "PdhCloseLog failed 0x%08lx\n", ret);
    }
}

static void test_counter_values(void)
{
    PDH_HCOUNTER avail, cpu, procs, uptime, queue;
    PDH_FMT_COUNTERVALUE value;
    PDH_HQUERY query;
    PDH_STATUS ret;
    DWORD type, index;

    ret = PdhOpenQueryW( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryW failed 0x%08lx\n", ret);
    ret = PdhAddEnglishCounterW( query, L"\\Memory\\Available Bytes", 0, &avail );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    ret = PdhAddEnglishCounterW( query, L"\\Processor(_Total)\\% Processor Time", 0, &cpu );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    ret = PdhAddEnglishCounterW( query, L"\\System\\Processes", 0, &procs );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    ret = PdhAddEnglishCounterW( query, L"\\System\\System Up Time", 0, &uptime );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    /* btop4win and other monitors read the run queue through this counter */
    ret = PdhAddEnglishCounterW( query, L"\\System\\Processor Queue Length", 0, &queue );
    ok(ret == ERROR_SUCCESS, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    ret = PdhLookupPerfIndexByNameW( NULL, L"Processor Queue Length", &index );
    ok(ret == ERROR_SUCCESS, "PdhLookupPerfIndexByNameW failed 0x%08lx\n", ret);
    ok(index == 44, "got index %lu\n", index);

    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    /* a rate or a timer needs two collections */
    ret = PdhGetFormattedCounterValue( cpu, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &type, &value );
    ok(ret == PDH_INVALID_DATA, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);
    ok(value.CStatus == PDH_CSTATUS_INVALID_DATA, "got 0x%08lx\n", value.CStatus);

    ret = PdhGetFormattedCounterValue( avail, PDH_FMT_LARGE, &type, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);
    ok(type == PERF_COUNTER_LARGE_RAWCOUNT, "got type %#lx\n", type);
    ok(value.largeValue > 1024 * 1024, "available bytes %s\n", wine_dbgstr_longlong( value.largeValue ));

    ret = PdhGetFormattedCounterValue( procs, PDH_FMT_LONG, &type, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);
    ok(value.longValue >= 1, "processes %ld\n", value.longValue);

    ret = PdhGetFormattedCounterValue( queue, PDH_FMT_LONG, &type, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);
    ok(type == PERF_COUNTER_RAWCOUNT, "got type %#lx\n", type);
    ok(value.CStatus == PDH_CSTATUS_VALID_DATA, "got 0x%08lx\n", value.CStatus);
    ok(value.longValue >= 0 && value.longValue < 1000, "processor queue length %ld\n", value.longValue);

    Sleep( 1100 );
    ret = PdhCollectQueryData( query );
    ok(ret == ERROR_SUCCESS, "PdhCollectQueryData failed 0x%08lx\n", ret);

    ret = PdhGetFormattedCounterValue( cpu, PDH_FMT_DOUBLE, &type, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);
    ok(type == PERF_100NSEC_TIMER_INV, "got type %#lx\n", type);
    ok(value.doubleValue >= 0.0 && value.doubleValue <= 100.0, "processor time %f\n", value.doubleValue);

    ret = PdhGetFormattedCounterValue( uptime, PDH_FMT_DOUBLE, &type, &value );
    ok(ret == ERROR_SUCCESS, "PdhGetFormattedCounterValue failed 0x%08lx\n", ret);
    ok(type == PERF_ELAPSED_TIME, "got type %#lx\n", type);
    ok(value.doubleValue >= GetTickCount() / 1000.0 - 60, "up time %f\n", value.doubleValue);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

static void test_PdhFormatFromRawValue(void)
{
    static const struct
    {
        DWORD type, format;
        LONGLONG timebase;          /* -1: a NULL pointer */
        LONGLONG new_first, new_second, old_first, old_second;
        BOOL has_old;
        PDH_STATUS status;
        double expected;
    } tests[] =
    {
        /* values without a time reference */
        { PERF_COUNTER_RAWCOUNT, PDH_FMT_DOUBLE, 10000000, 42, 0, 0, 0, TRUE, ERROR_SUCCESS, 42.0 },
        { PERF_COUNTER_RAWCOUNT, PDH_FMT_DOUBLE, 10000000, 42, 0, 0, 0, FALSE, ERROR_SUCCESS, 42.0 },
        { PERF_COUNTER_RAWCOUNT, PDH_FMT_DOUBLE, -1, 42, 0, 0, 0, FALSE, ERROR_SUCCESS, 42.0 },
        { PERF_COUNTER_LARGE_RAWCOUNT, PDH_FMT_DOUBLE, 10000000, 0x123456789LL, 0, 0, 0, FALSE, ERROR_SUCCESS, 4886718345.0 },
        { PERF_COUNTER_RAWCOUNT_HEX, PDH_FMT_DOUBLE, 10000000, 7000000, 0, 0, 0, FALSE, ERROR_SUCCESS, 7000000.0 },
        /* rates: the time stamps are in ticks of the time base */
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 1000, 20000000, 500, 10000000, TRUE, ERROR_SUCCESS, 500.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 20000000, 1000, 20000000, 500, 10000000, TRUE, ERROR_SUCCESS, 1000.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 0, 1000, 20000000, 500, 10000000, TRUE, ERROR_SUCCESS, 0.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, -1, 1000, 20000000, 500, 10000000, TRUE, ERROR_SUCCESS, 0.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_1000, 10000000, 1000, 20000000, 500, 10000000, TRUE, ERROR_SUCCESS, 500000.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 1000, 20000000, 500, 10000000, FALSE, PDH_CSTATUS_INVALID_DATA, 0.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 1000, 20000000, 1000, 20000000, TRUE, ERROR_SUCCESS, 0.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 1000, 5000000, 500, 10000000, TRUE, PDH_CALC_NEGATIVE_DENOMINATOR, 0.0 },
        { PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 100, 20000000, 500, 10000000, TRUE, PDH_CALC_NEGATIVE_VALUE, 0.0 },
        { PERF_COUNTER_BULK_COUNT, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 7000000, 20000000, 2000000, 10000000, TRUE, ERROR_SUCCESS, 5000000.0 },
        /* timers use their own time stamps, the time base does not matter */
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 7000000, 20000000, 2000000, 10000000, TRUE, ERROR_SUCCESS, 50.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, -1, 7000000, 20000000, 2000000, 10000000, TRUE, ERROR_SUCCESS, 50.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 1, 7000000, 20000000, 2000000, 10000000, TRUE, ERROR_SUCCESS, 50.0 },
        { PERF_100NSEC_TIMER_INV, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_NOCAP100, 10000000, 7000000, 20000000, 2000000, 10000000, TRUE, ERROR_SUCCESS, 50.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 7000000, 20000000, 2000000, 10000000, FALSE, PDH_CSTATUS_INVALID_DATA, 0.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 15000000, 20000000, 0, 10000000, TRUE, ERROR_SUCCESS, 100.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_NOCAP100, 10000000, 15000000, 20000000, 0, 10000000, TRUE, ERROR_SUCCESS, 150.0 },
        { PERF_100NSEC_TIMER_INV, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_NOCAP100, 10000000, 15000000, 20000000, 0, 10000000, TRUE, PDH_CALC_NEGATIVE_DENOMINATOR, 0.0 },
        { PERF_100NSEC_TIMER_INV, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_NOCAP100, 10000000, 2000000, 20000000, 7000000, 10000000, TRUE, PDH_CALC_NEGATIVE_VALUE, 0.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 1000, 5000000, 500, 10000000, TRUE, PDH_CALC_NEGATIVE_DENOMINATOR, 0.0 },
        { PERF_100NSEC_TIMER, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 1000, 10000000, 500, 10000000, TRUE, ERROR_SUCCESS, 0.0 },
        /* fractions: the second value is the base */
        { PERF_RAW_FRACTION, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 25, 100, 0, 0, FALSE, ERROR_SUCCESS, 25.0 },
        { PERF_RAW_FRACTION, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 5, 200, 3, 100, TRUE, ERROR_SUCCESS, 2.5 },
        { PERF_RAW_FRACTION, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 25, 0, 0, 0, FALSE, ERROR_SUCCESS, 0.0 },
        { PERF_RAW_FRACTION, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 150, 100, 0, 0, FALSE, ERROR_SUCCESS, 100.0 },
        { PERF_RAW_FRACTION, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE | PDH_FMT_NOCAP100, 10000000, 150, 100, 0, 0, FALSE, ERROR_SUCCESS, 150.0 },
        { 0x20570500 /* PERF_PRECISION_100NS_TIMER */, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 7000000, 20000000, 2000000, 10000000, TRUE, ERROR_SUCCESS, 50.0 },
        { 0x30020400 /* PERF_AVERAGE_TIMER */, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 60000000, 12, 20000000, 4, TRUE, ERROR_SUCCESS, 0.5 },
        { 0x40020500 /* PERF_AVERAGE_BULK */, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 4000, 12, 1000, 4, TRUE, ERROR_SUCCESS, 375.0 },
        { 0x20C20400 /* PERF_SAMPLE_FRACTION */, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, 10000000, 30, 100, 10, 50, TRUE, ERROR_SUCCESS, 40.0 },
    };
    PDH_RAW_COUNTER raw1, raw2;
    PDH_FMT_COUNTERVALUE value;
    LONGLONG timebase;
    PDH_STATUS ret;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        memset( &raw1, 0, sizeof(raw1) );
        memset( &raw2, 0, sizeof(raw2) );
        raw1.FirstValue = tests[i].new_first;
        raw1.SecondValue = tests[i].new_second;
        raw2.FirstValue = tests[i].old_first;
        raw2.SecondValue = tests[i].old_second;
        timebase = tests[i].timebase;
        memset( &value, 0xcc, sizeof(value) );

        ret = PdhFormatFromRawValue( tests[i].type, tests[i].format, tests[i].timebase == -1 ? NULL : &timebase,
                                     &raw1, tests[i].has_old ? &raw2 : NULL, &value );
        ok(ret == tests[i].status, "%u: got 0x%08lx, expected 0x%08lx\n", i, ret, tests[i].status);
        if (tests[i].status == ERROR_SUCCESS)
        {
            ok(value.CStatus == PDH_CSTATUS_VALID_DATA, "%u: got status 0x%08lx\n", i, value.CStatus);
            ok(fabs( value.doubleValue - tests[i].expected ) < 0.0001, "%u: got %f, expected %f\n", i, value.doubleValue,
               tests[i].expected);
        }
        else
            ok(value.CStatus == tests[i].status || value.CStatus == 0, "%u: got status 0x%08lx\n", i, value.CStatus);
    }

    /* formats */
    timebase = 10000000;
    memset( &raw1, 0, sizeof(raw1) );
    memset( &raw2, 0, sizeof(raw2) );
    raw1.FirstValue = 1000;
    raw1.SecondValue = 20000000;
    raw2.FirstValue = 500;
    raw2.SecondValue = 10000000;

    memset( &value, 0, sizeof(value) );
    ret = PdhFormatFromRawValue( PERF_COUNTER_COUNTER, PDH_FMT_LONG | PDH_FMT_NOSCALE, &timebase, &raw1, &raw2, &value );
    ok(ret == ERROR_SUCCESS, "got 0x%08lx\n", ret);
    ok(value.longValue == 500, "got %ld\n", value.longValue);

    memset( &value, 0, sizeof(value) );
    ret = PdhFormatFromRawValue( PERF_COUNTER_COUNTER, PDH_FMT_LARGE | PDH_FMT_NOSCALE, &timebase, &raw1, &raw2, &value );
    ok(ret == ERROR_SUCCESS, "got 0x%08lx\n", ret);
    ok(value.largeValue == 500, "got %s\n", wine_dbgstr_longlong( value.largeValue ));

    ret = PdhFormatFromRawValue( PERF_COUNTER_COUNTER, 0, &timebase, &raw1, &raw2, &value );
    ok(ret == PDH_INVALID_ARGUMENT, "got 0x%08lx\n", ret);
    ret = PdhFormatFromRawValue( PERF_COUNTER_COUNTER, PDH_FMT_LARGE | PDH_FMT_DOUBLE, &timebase, &raw1, &raw2, &value );
    ok(ret == PDH_INVALID_ARGUMENT, "got 0x%08lx\n", ret);
    ret = PdhFormatFromRawValue( PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE, &timebase, &raw1, &raw2, NULL );
    ok(ret == PDH_INVALID_ARGUMENT, "got 0x%08lx\n", ret);
    ret = PdhFormatFromRawValue( PERF_COUNTER_COUNTER, PDH_FMT_DOUBLE, &timebase, NULL, &raw2, &value );
    ok(ret == PDH_INVALID_ARGUMENT, "got 0x%08lx\n", ret);
    ret = PdhFormatFromRawValue( 0x12345678, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, &timebase, &raw1, &raw2, &value );
    ok(ret == PDH_FUNCTION_NOT_FOUND, "got 0x%08lx\n", ret);
}

static void test_add_counter_sets(void)
{
    PDH_HCOUNTER counter;
    PDH_HQUERY query;
    PDH_STATUS ret;

    ret = PdhOpenQueryW( NULL, 0, &query );
    ok(ret == ERROR_SUCCESS, "PdhOpenQueryW failed 0x%08lx\n", ret);

    ret = PdhAddCounterW( query, L"\\Memory\\No Such Counter", 0, &counter );
    ok(ret == PDH_CSTATUS_NO_COUNTER, "PdhAddCounterW failed 0x%08lx\n", ret);
    ret = PdhAddCounterW( query, L"\\No Such Object\\Counter", 0, &counter );
    ok(ret == PDH_CSTATUS_NO_OBJECT, "PdhAddCounterW failed 0x%08lx\n", ret);
    ret = PdhAddCounterW( query, L"\\Processor\\% Processor Time", 0, &counter );
    ok(ret == PDH_CSTATUS_BAD_COUNTERNAME, "PdhAddCounterW failed 0x%08lx\n", ret);
    ret = PdhAddEnglishCounterW( query, L"\\\\nosuchhost\\Memory\\Available Bytes", 0, &counter );
    ok(ret == PDH_CSTATUS_NO_MACHINE, "PdhAddEnglishCounterW failed 0x%08lx\n", ret);
    ret = PdhAddCounterW( query, L"\\\\nosuchhost\\Memory\\Available Bytes", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterW failed 0x%08lx\n", ret);
    ret = PdhAddCounterW( query, L"\\memory\\AVAILABLE bytes", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterW failed 0x%08lx\n", ret);
    ret = PdhAddCounterW( query, L"\\Processor(_Total)\\% Processor Time", 0, &counter );
    ok(ret == ERROR_SUCCESS, "PdhAddCounterW failed 0x%08lx\n", ret);

    ret = PdhCloseQuery( query );
    ok(ret == ERROR_SUCCESS, "PdhCloseQuery failed 0x%08lx\n", ret);
}

START_TEST(pdh)
{
    if (!is_lang_english())
    {
        skip("An English UI is needed for the pdh tests\n");
        return;
    }
    init_function_ptrs();

    test_PdhOpenQueryA();
    test_PdhOpenQueryW();

    test_PdhAddCounterA();
    test_PdhAddCounterW();

    if (pPdhAddEnglishCounterA) test_PdhAddEnglishCounterA();
    if (pPdhAddEnglishCounterW) test_PdhAddEnglishCounterW();
    if (pPdhCollectQueryDataWithTime) test_PdhCollectQueryDataWithTime();

    test_PdhGetFormattedCounterValue();
    test_PdhFormatFromRawValue();
    test_PdhGetRawCounterValue();
    test_PdhSetCounterScaleFactor();
    test_PdhGetCounterTimeBase();

    test_PdhVbGetDoubleCounterValue();

    test_PdhGetCounterInfoA();
    test_PdhGetCounterInfoW();

    test_PdhLookupPerfIndexByNameA();
    test_PdhLookupPerfIndexByNameW();

    test_PdhLookupPerfNameByIndexA();
    test_PdhLookupPerfNameByIndexW();

    test_PdhValidatePathA();
    test_PdhValidatePathW();

    if (pPdhValidatePathExA) test_PdhValidatePathExA();
    if (pPdhValidatePathExW) test_PdhValidatePathExW();

    test_PdhCollectQueryDataEx();
    test_PdhMakeCounterPathA();
    test_PdhMakeCounterPath_machine();
    test_PdhMakeCounterPathW_long();
    test_PdhGetDllVersion();

    init_computer_prefix();
    test_name_table();
    test_PdhEnumObjectsW();
    test_PdhEnumObjectItemsW();
    test_PdhExpandWildCardPathW();
    test_PdhParseCounterPathW();
    test_PdhValidatePath_sets();
    test_data_source();
    test_add_counter_sets();
    test_counter_values();
}
