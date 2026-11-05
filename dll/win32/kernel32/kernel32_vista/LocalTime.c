/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     LocalFileTimeToLocalSystemTime, LocalSystemTimeToLocalFileTime, SystemTimeToTzSpecificLocalTimeEx
 *              and TzSpecificLocalTimeToSystemTimeEx (Windows 10 1709 and later for the first two)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86):
 *  - LocalFileTimeToLocalSystemTime and LocalSystemTimeToLocalFileTime ignore the time zone (it may be NULL) and convert
 *    like FileTimeToSystemTime and SystemTimeToFileTime: an invalid time is ERROR_INVALID_PARAMETER, the last error is
 *    not touched on success.
 *  - The Ex functions take the DYNAMIC_TIME_ZONE_INFORMATION (NULL is the current one). The year of the time selects the
 *    bias and the transition dates of the "Dynamic DST" entry of the zone key, as GetTimeZoneInformationForYear does. A
 *    zone whose daylight saving time is marked as not dynamic is used as it stands. Otherwise the key must exist: an empty
 *    key name is ERROR_FILE_NOT_FOUND (an unknown name is taken to be the same). An invalid time, or a UTC time whose local
 *    time falls before the year 1601, is ERROR_INVALID_PARAMETER whatever the key (the check comes first).
 */

#include "k32_vista.h"
#include <ndk/cmfuncs.h>

BOOL WINAPI GetTimeZoneInformationForYear(_In_ USHORT wYear, _In_opt_ PDYNAMIC_TIME_ZONE_INFORMATION pdtzi, _Out_ LPTIME_ZONE_INFORMATION ptzi);

#define NDEBUG
#include <debug.h>

BOOL
WINAPI
LocalFileTimeToLocalSystemTime(
    _In_opt_ CONST TIME_ZONE_INFORMATION *TimeZoneInformation,
    _In_ CONST FILETIME *LocalFileTime,
    _Out_ LPSYSTEMTIME LocalSystemTime)
{
    UNREFERENCED_PARAMETER(TimeZoneInformation);
    return FileTimeToSystemTime(LocalFileTime, LocalSystemTime);
}

BOOL
WINAPI
LocalSystemTimeToLocalFileTime(
    _In_opt_ CONST TIME_ZONE_INFORMATION *TimeZoneInformation,
    _In_ CONST SYSTEMTIME *LocalSystemTime,
    _Out_ LPFILETIME LocalFileTime)
{
    UNREFERENCED_PARAMETER(TimeZoneInformation);
    return SystemTimeToFileTime(LocalSystemTime, LocalFileTime);
}

static
BOOL
BasepZoneForYear(
    _In_opt_ CONST DYNAMIC_TIME_ZONE_INFORMATION *DynamicZone,
    _In_ USHORT Year,
    _Out_ PTIME_ZONE_INFORMATION Zone,
    _Out_ PBOOL KeyMissing)
{
    static const WCHAR ZonesPath[] = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\";
    DYNAMIC_TIME_ZONE_INFORMATION Current;
    BOOL Provided = DynamicZone != NULL;

    *KeyMissing = FALSE;
    WCHAR Path[ARRAYSIZE(ZonesPath) + ARRAYSIZE(Current.TimeZoneKeyName)];
    UNICODE_STRING PathName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key;
    SIZE_T Length;

    if (!DynamicZone)
    {
        if (GetDynamicTimeZoneInformation(&Current) == TIME_ZONE_ID_INVALID)
            return FALSE;
        DynamicZone = &Current;
    }

    /* the zone key of a zone the caller passes in must exist. That is found out after the time was converted: an invalid
     * time, or one without a local time, is ERROR_INVALID_PARAMETER whatever the key says */
    if (Provided && !DynamicZone->DynamicDaylightTimeDisabled)
    {
        for (Length = 0; Length < ARRAYSIZE(DynamicZone->TimeZoneKeyName); Length++)
        {
            if (!DynamicZone->TimeZoneKeyName[Length])
                break;
        }

        if (Length == 0 || Length == ARRAYSIZE(DynamicZone->TimeZoneKeyName))
        {
            *KeyMissing = TRUE;
        }
        else
        {
            RtlCopyMemory(Path, ZonesPath, sizeof(ZonesPath) - sizeof(WCHAR));
            RtlCopyMemory(Path + ARRAYSIZE(ZonesPath) - 1, DynamicZone->TimeZoneKeyName, Length * sizeof(WCHAR));
            Path[ARRAYSIZE(ZonesPath) - 1 + Length] = UNICODE_NULL;
            RtlInitUnicodeString(&PathName, Path);
            InitializeObjectAttributes(&ObjectAttributes, &PathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            if (NT_SUCCESS(NtOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttributes)))
                NtClose(Key);
            else
                *KeyMissing = TRUE;
        }
    }

    return GetTimeZoneInformationForYear(Year, (PDYNAMIC_TIME_ZONE_INFORMATION)DynamicZone, Zone);
}

BOOL
WINAPI
SystemTimeToTzSpecificLocalTimeEx(
    _In_opt_ CONST DYNAMIC_TIME_ZONE_INFORMATION *DynamicTimeZoneInformation,
    _In_ CONST SYSTEMTIME *UniversalTime,
    _Out_ LPSYSTEMTIME LocalTime)
{
    TIME_ZONE_INFORMATION Zone;
    BOOL KeyMissing;

    if (!BasepZoneForYear(DynamicTimeZoneInformation, UniversalTime->wYear, &Zone, &KeyMissing))
        return FALSE;

    if (!SystemTimeToTzSpecificLocalTime(&Zone, UniversalTime, LocalTime))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (KeyMissing)
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
}

BOOL
WINAPI
TzSpecificLocalTimeToSystemTimeEx(
    _In_opt_ CONST DYNAMIC_TIME_ZONE_INFORMATION *DynamicTimeZoneInformation,
    _In_ CONST SYSTEMTIME *LocalTime,
    _Out_ LPSYSTEMTIME UniversalTime)
{
    TIME_ZONE_INFORMATION Zone;
    BOOL KeyMissing;

    if (!BasepZoneForYear(DynamicTimeZoneInformation, LocalTime->wYear, &Zone, &KeyMissing))
        return FALSE;

    if (!TzSpecificLocalTimeToSystemTime(&Zone, LocalTime, UniversalTime))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (KeyMissing)
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
}
