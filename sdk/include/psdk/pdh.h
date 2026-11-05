/*
 * Performance Data Helper
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

#ifndef _PDH_H_
#define _PDH_H_

#ifdef __WINESRC__
# include <windef.h>
#else
# include <windows.h>
#endif
#include <winperf.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef LONG   PDH_STATUS;
typedef HANDLE PDH_HQUERY;
typedef HANDLE PDH_HCOUNTER;
typedef HANDLE PDH_HLOG;

#define PDH_CVERSION_WIN40  0x0400
#define PDH_CVERSION_WIN50  0x0500
#define PDH_VERSION         0x0503

#define PDH_MAX_SCALE 7
#define PDH_MIN_SCALE (-7)

#define PDH_MAX_COUNTER_NAME    1024
#define PDH_MAX_INSTANCE_NAME   1024
#define PDH_MAX_COUNTER_PATH    2048
#define PDH_MAX_DATASOURCE_PATH 1024

#define PDH_FMT_LONG        0x00000100
#define PDH_FMT_DOUBLE      0x00000200
#define PDH_FMT_LARGE       0x00000400
#define PDH_FMT_NOSCALE     0x00001000
#define PDH_FMT_1000        0x00002000
#define PDH_FMT_NOCAP100    0x00008000

#define DATA_SOURCE_REGISTRY    0x00000001
#define DATA_SOURCE_LOGFILE     0x00000002
#define DATA_SOURCE_WBEM        0x00000004

typedef struct _PDH_FMT_COUNTERVALUE
{
    DWORD CStatus;
    union
    {
        LONG     longValue;
        double   doubleValue;
        LONGLONG largeValue;
        LPCSTR   AnsiStringValue;
        LPCWSTR  WideStringValue;
    } DUMMYUNIONNAME;
} PDH_FMT_COUNTERVALUE, *PPDH_FMT_COUNTERVALUE;

typedef struct _PDH_RAW_COUNTER
{
    DWORD    CStatus;
    FILETIME TimeStamp;
    LONGLONG FirstValue;
    LONGLONG SecondValue;
    DWORD    MultiCount;
} PDH_RAW_COUNTER, *PPDH_RAW_COUNTER;

typedef struct _PDH_STATISTICS
{
    DWORD dwFormat;
    DWORD count;
    PDH_FMT_COUNTERVALUE min;
    PDH_FMT_COUNTERVALUE max;
    PDH_FMT_COUNTERVALUE mean;
} PDH_STATISTICS, *PPDH_STATISTICS;

typedef struct _PDH_FMT_COUNTERVALUE_ITEM_A
{
    LPSTR szName;
    PDH_FMT_COUNTERVALUE FmtValue;
} PDH_FMT_COUNTERVALUE_ITEM_A, *PPDH_FMT_COUNTERVALUE_ITEM_A;

typedef struct _PDH_FMT_COUNTERVALUE_ITEM_W
{
    LPWSTR szName;
    PDH_FMT_COUNTERVALUE FmtValue;
} PDH_FMT_COUNTERVALUE_ITEM_W, *PPDH_FMT_COUNTERVALUE_ITEM_W;

typedef struct _PDH_RAW_COUNTER_ITEM_A
{
    LPSTR szName;
    PDH_RAW_COUNTER RawValue;
} PDH_RAW_COUNTER_ITEM_A, *PPDH_RAW_COUNTER_ITEM_A;

typedef struct _PDH_RAW_COUNTER_ITEM_W
{
    LPWSTR szName;
    PDH_RAW_COUNTER RawValue;
} PDH_RAW_COUNTER_ITEM_W, *PPDH_RAW_COUNTER_ITEM_W;

typedef struct _PDH_COUNTER_PATH_ELEMENTS_A
{
    LPSTR szMachineName;
    LPSTR szObjectName;
    LPSTR szInstanceName;
    LPSTR szParentInstance;
    DWORD dwInstanceIndex;
    LPSTR szCounterName;
} PDH_COUNTER_PATH_ELEMENTS_A, *PPDH_COUNTER_PATH_ELEMENTS_A;

typedef struct _PDH_COUNTER_PATH_ELEMENTS_W
{
    LPWSTR szMachineName;
    LPWSTR szObjectName;
    LPWSTR szInstanceName;
    LPWSTR szParentInstance;
    DWORD  dwInstanceIndex;
    LPWSTR szCounterName;
} PDH_COUNTER_PATH_ELEMENTS_W, *PPDH_COUNTER_PATH_ELEMENTS_W;

typedef struct _PDH_DATA_ITEM_PATH_ELEMENTS_A
{
    LPSTR szMachineName;
    GUID  ObjectGUID;
    DWORD dwItemId;
    LPSTR szInstanceName;
} PDH_DATA_ITEM_PATH_ELEMENTS_A, *PPDH_DATA_ITEM_PATH_ELEMENTS_A;

typedef struct _PDH_DATA_ITEM_PATH_ELEMENTS_W
{
    LPWSTR szMachineName;
    GUID   ObjectGUID;
    DWORD  dwItemId;
    LPWSTR szInstanceName;
} PDH_DATA_ITEM_PATH_ELEMENTS_W, *PPDH_DATA_ITEM_PATH_ELEMENTS_W;

typedef struct _PDH_COUNTER_INFO_A
{
    DWORD     dwLength;
    DWORD     dwType;
    DWORD     CVersion;
    DWORD     CStatus;
    LONG      lScale;
    LONG      lDefaultScale;
    DWORD_PTR dwUserData;
    DWORD_PTR dwQueryUserData;
    LPSTR     szFullPath;
    union
    {
        PDH_DATA_ITEM_PATH_ELEMENTS_A DataItemPath;
        PDH_COUNTER_PATH_ELEMENTS_A   CounterPath;
        struct
        {
            LPSTR szMachineName;
            LPSTR szObjectName;
            LPSTR szInstanceName;
            LPSTR szParentInstance;
            DWORD dwInstanceIndex;
            LPSTR szCounterName;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    LPSTR szExplainText;
    DWORD DataBuffer[1];
} PDH_COUNTER_INFO_A, *PPDH_COUNTER_INFO_A;

typedef struct _PDH_COUNTER_INFO_W
{
    DWORD     dwLength;
    DWORD     dwType;
    DWORD     CVersion;
    DWORD     CStatus;
    LONG      lScale;
    LONG      lDefaultScale;
    DWORD_PTR dwUserData;
    DWORD_PTR dwQueryUserData;
    LPWSTR    szFullPath;
    union
    {
        PDH_DATA_ITEM_PATH_ELEMENTS_W DataItemPath;
        PDH_COUNTER_PATH_ELEMENTS_W   CounterPath;
        struct
        {
            LPWSTR szMachineName;
            LPWSTR szObjectName;
            LPWSTR szInstanceName;
            LPWSTR szParentInstance;
            DWORD  dwInstanceIndex;
            LPWSTR szCounterName;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    LPWSTR szExplainText;
    DWORD DataBuffer[1];
} PDH_COUNTER_INFO_W, *PPDH_COUNTER_INFO_W;

PDH_STATUS WINAPI PdhAddCounterA(PDH_HQUERY, LPCSTR, DWORD_PTR, PDH_HCOUNTER *);
PDH_STATUS WINAPI PdhAddCounterW(PDH_HQUERY, LPCWSTR, DWORD_PTR, PDH_HCOUNTER *);
#define    PdhAddCounter WINELIB_NAME_AW(PdhAddCounter)
PDH_STATUS WINAPI PdhAddEnglishCounterA(PDH_HQUERY, LPCSTR, DWORD_PTR, PDH_HCOUNTER *);
PDH_STATUS WINAPI PdhAddEnglishCounterW(PDH_HQUERY, LPCWSTR, DWORD_PTR, PDH_HCOUNTER *);
#define    PdhAddEnglishCounter WINELIB_NAME_AW(PdhAddEnglishCounter)
PDH_STATUS WINAPI PdhCloseQuery(PDH_HQUERY);
PDH_STATUS WINAPI PdhCollectQueryData(PDH_HQUERY);
PDH_STATUS WINAPI PdhCollectQueryDataEx(PDH_HQUERY, DWORD, HANDLE);
PDH_STATUS WINAPI PdhCollectQueryDataWithTime(PDH_HQUERY,LONGLONG *);
PDH_STATUS WINAPI PdhEnumObjectItemsA(LPCSTR, LPCSTR, LPCSTR, LPSTR, LPDWORD, LPSTR, LPDWORD, DWORD, DWORD);
PDH_STATUS WINAPI PdhEnumObjectItemsW(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, LPDWORD, LPWSTR, LPDWORD, DWORD, DWORD);
#define    PdhEnumObjectItems WINELIB_NAME_AW(PdhEnumObjectItems)
PDH_STATUS WINAPI PdhEnumObjectItemsHA(PDH_HLOG, LPCSTR, LPCSTR, LPSTR, LPDWORD, LPSTR, LPDWORD, DWORD, DWORD);
PDH_STATUS WINAPI PdhEnumObjectItemsHW(PDH_HLOG, LPCWSTR, LPCWSTR, LPWSTR, LPDWORD, LPWSTR, LPDWORD, DWORD, DWORD);
#define    PdhEnumObjectItemsH WINELIB_NAME_AW(PdhEnumObjectItemsH)
PDH_STATUS WINAPI PdhBindInputDataSourceA(PDH_HLOG *, LPCSTR);
PDH_STATUS WINAPI PdhBindInputDataSourceW(PDH_HLOG *, LPCWSTR);
#define    PdhBindInputDataSource WINELIB_NAME_AW(PdhBindInputDataSource)
PDH_STATUS WINAPI PdhCloseLog(PDH_HLOG, DWORD);
PDH_STATUS WINAPI PdhEnumMachinesA(LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhEnumMachinesW(LPCWSTR, LPWSTR, LPDWORD);
#define    PdhEnumMachines WINELIB_NAME_AW(PdhEnumMachines)
PDH_STATUS WINAPI PdhEnumMachinesHA(PDH_HLOG, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhEnumMachinesHW(PDH_HLOG, LPWSTR, LPDWORD);
#define    PdhEnumMachinesH WINELIB_NAME_AW(PdhEnumMachinesH)
PDH_STATUS WINAPI PdhEnumObjectsA(LPCSTR, LPCSTR, LPSTR, LPDWORD, DWORD, BOOL);
PDH_STATUS WINAPI PdhEnumObjectsW(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD, DWORD, BOOL);
#define    PdhEnumObjects WINELIB_NAME_AW(PdhEnumObjects)
PDH_STATUS WINAPI PdhEnumObjectsHA(PDH_HLOG, LPCSTR, LPSTR, LPDWORD, DWORD, BOOL);
PDH_STATUS WINAPI PdhEnumObjectsHW(PDH_HLOG, LPCWSTR, LPWSTR, LPDWORD, DWORD, BOOL);
#define    PdhEnumObjectsH WINELIB_NAME_AW(PdhEnumObjectsH)
PDH_STATUS WINAPI PdhExpandCounterPathA(LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhExpandCounterPathW(LPCWSTR, LPWSTR, LPDWORD);
#define    PdhExpandCounterPath WINELIB_NAME_AW(PdhExpandCounterPath)
PDH_STATUS WINAPI PdhExpandWildCardPathA(LPCSTR, LPCSTR, LPSTR, LPDWORD, DWORD);
PDH_STATUS WINAPI PdhExpandWildCardPathW(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD, DWORD);
#define    PdhExpandWildCardPath WINELIB_NAME_AW(PdhExpandWildCardPath)
PDH_STATUS WINAPI PdhExpandWildCardPathHA(PDH_HLOG, LPCSTR, LPSTR, LPDWORD, DWORD);
PDH_STATUS WINAPI PdhExpandWildCardPathHW(PDH_HLOG, LPCWSTR, LPWSTR, LPDWORD, DWORD);
#define    PdhExpandWildCardPathH WINELIB_NAME_AW(PdhExpandWildCardPathH)
PDH_STATUS WINAPI PdhOpenQueryH(PDH_HLOG, DWORD_PTR, PDH_HQUERY *);
PDH_STATUS WINAPI PdhParseCounterPathA(LPCSTR, PDH_COUNTER_PATH_ELEMENTS_A *, LPDWORD, DWORD);
PDH_STATUS WINAPI PdhParseCounterPathW(LPCWSTR, PDH_COUNTER_PATH_ELEMENTS_W *, LPDWORD, DWORD);
#define    PdhParseCounterPath WINELIB_NAME_AW(PdhParseCounterPath)
PDH_STATUS WINAPI PdhGetCounterInfoA(PDH_HCOUNTER, BOOLEAN, LPDWORD, PPDH_COUNTER_INFO_A);
PDH_STATUS WINAPI PdhGetCounterInfoW(PDH_HCOUNTER, BOOLEAN, LPDWORD, PPDH_COUNTER_INFO_W);
#define    PdhGetCounterInfo WINELIB_NAME_AW(PdhGetCounterInfo)
PDH_STATUS WINAPI PdhGetCounterTimeBase(PDH_HCOUNTER, LONGLONG *);
PDH_STATUS WINAPI PdhComputeCounterStatistics(PDH_HCOUNTER, DWORD, DWORD, DWORD, PPDH_RAW_COUNTER, PPDH_STATISTICS);
PDH_STATUS WINAPI PdhConnectMachineA(LPCSTR);
PDH_STATUS WINAPI PdhConnectMachineW(LPCWSTR);
#define    PdhConnectMachine WINELIB_NAME_AW(PdhConnectMachine)
PDH_STATUS WINAPI PdhGetDefaultPerfCounterA(LPCSTR, LPCSTR, LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhGetDefaultPerfCounterW(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, LPDWORD);
#define    PdhGetDefaultPerfCounter WINELIB_NAME_AW(PdhGetDefaultPerfCounter)
PDH_STATUS WINAPI PdhGetDefaultPerfCounterHA(PDH_HLOG, LPCSTR, LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhGetDefaultPerfCounterHW(PDH_HLOG, LPCWSTR, LPCWSTR, LPWSTR, LPDWORD);
#define    PdhGetDefaultPerfCounterH WINELIB_NAME_AW(PdhGetDefaultPerfCounterH)
PDH_STATUS WINAPI PdhGetDefaultPerfObjectA(LPCSTR, LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhGetDefaultPerfObjectW(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD);
#define    PdhGetDefaultPerfObject WINELIB_NAME_AW(PdhGetDefaultPerfObject)
PDH_STATUS WINAPI PdhGetDefaultPerfObjectHA(PDH_HLOG, LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhGetDefaultPerfObjectHW(PDH_HLOG, LPCWSTR, LPWSTR, LPDWORD);
#define    PdhGetDefaultPerfObjectH WINELIB_NAME_AW(PdhGetDefaultPerfObjectH)
PDH_STATUS WINAPI PdhGetFormattedCounterArrayA(PDH_HCOUNTER, DWORD, LPDWORD, LPDWORD, PPDH_FMT_COUNTERVALUE_ITEM_A);
PDH_STATUS WINAPI PdhGetFormattedCounterArrayW(PDH_HCOUNTER, DWORD, LPDWORD, LPDWORD, PPDH_FMT_COUNTERVALUE_ITEM_W);
#define    PdhGetFormattedCounterArray WINELIB_NAME_AW(PdhGetFormattedCounterArray)
PDH_STATUS WINAPI PdhGetRawCounterArrayA(PDH_HCOUNTER, LPDWORD, LPDWORD, PPDH_RAW_COUNTER_ITEM_A);
PDH_STATUS WINAPI PdhGetRawCounterArrayW(PDH_HCOUNTER, LPDWORD, LPDWORD, PPDH_RAW_COUNTER_ITEM_W);
#define    PdhGetRawCounterArray WINELIB_NAME_AW(PdhGetRawCounterArray)
BOOL WINAPI PdhIsRealTimeQuery(PDH_HQUERY);
PDH_STATUS WINAPI PdhParseInstanceNameA(LPCSTR, LPSTR, LPDWORD, LPSTR, LPDWORD, LPDWORD);
PDH_STATUS WINAPI PdhParseInstanceNameW(LPCWSTR, LPWSTR, LPDWORD, LPWSTR, LPDWORD, LPDWORD);
#define    PdhParseInstanceName WINELIB_NAME_AW(PdhParseInstanceName)
PDH_STATUS WINAPI PdhTranslate009CounterA(LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhTranslate009CounterW(LPCWSTR, LPWSTR, LPDWORD);
#define    PdhTranslate009Counter WINELIB_NAME_AW(PdhTranslate009Counter)
PDH_STATUS WINAPI PdhTranslateLocaleCounterA(LPCSTR, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhTranslateLocaleCounterW(LPCWSTR, LPWSTR, LPDWORD);
#define    PdhTranslateLocaleCounter WINELIB_NAME_AW(PdhTranslateLocaleCounter)
PDH_STATUS WINAPI PdhGetDllVersion(LPDWORD);
PDH_STATUS WINAPI PdhFormatFromRawValue(DWORD, DWORD, LONGLONG *, PPDH_RAW_COUNTER, PPDH_RAW_COUNTER, PPDH_FMT_COUNTERVALUE);
PDH_STATUS WINAPI PdhGetFormattedCounterValue(PDH_HCOUNTER, DWORD, LPDWORD, PPDH_FMT_COUNTERVALUE);
PDH_STATUS WINAPI PdhGetRawCounterValue(PDH_HCOUNTER, LPDWORD, PPDH_RAW_COUNTER);
PDH_STATUS WINAPI PdhLookupPerfIndexByNameA(LPCSTR, LPCSTR, LPDWORD);
PDH_STATUS WINAPI PdhLookupPerfIndexByNameW(LPCWSTR, LPCWSTR, LPDWORD);
#define    PdhLookupPerfIndexByName WINELIB_NAME_AW(PdhLookupPerfIndexByName)
PDH_STATUS WINAPI PdhLookupPerfNameByIndexA(LPCSTR, DWORD, LPSTR, LPDWORD);
PDH_STATUS WINAPI PdhLookupPerfNameByIndexW(LPCWSTR, DWORD, LPWSTR, LPDWORD);
#define    PdhLookupPerfNameByIndex WINELIB_NAME_AW(PdhLookupPerfNameByIndex)
PDH_STATUS WINAPI PdhMakeCounterPathA(PDH_COUNTER_PATH_ELEMENTS_A *, LPSTR, LPDWORD, DWORD);
PDH_STATUS WINAPI PdhMakeCounterPathW(PDH_COUNTER_PATH_ELEMENTS_W *, LPWSTR, LPDWORD, DWORD);
#define    PdhMakeCounterPath WINELIB_NAME_AW(PdhMakeCounterPath)
PDH_STATUS WINAPI PdhOpenQueryA(LPCSTR, DWORD_PTR, PDH_HQUERY *);
PDH_STATUS WINAPI PdhOpenQueryW(LPCWSTR, DWORD_PTR, PDH_HQUERY *);
#define    PdhOpenQuery WINELIB_NAME_AW(PdhOpenQuery)
PDH_STATUS WINAPI PdhRemoveCounter(PDH_HCOUNTER);
PDH_STATUS WINAPI PdhSetCounterScaleFactor(PDH_HCOUNTER, LONG);
PDH_STATUS WINAPI PdhSetDefaultRealTimeDataSource(DWORD);
PDH_STATUS WINAPI PdhValidatePathA(LPCSTR);
PDH_STATUS WINAPI PdhValidatePathW(LPCWSTR);
#define    PdhValidatePath WINELIB_NAME_AW(PdhValidatePath)
PDH_STATUS WINAPI PdhValidatePathExA(PDH_HLOG, LPCSTR);
PDH_STATUS WINAPI PdhValidatePathExW(PDH_HLOG, LPCWSTR);
#define    PdhValidatePathEx WINELIB_NAME_AW(PdhValidatePathEx)

#ifdef __cplusplus
}
#endif

#endif /* _PDH_H_ */
