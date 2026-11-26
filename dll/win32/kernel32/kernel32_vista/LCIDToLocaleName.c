/*
 * PROJECT:     ReactOS Win32 Base API
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Implementation of LCIDToLocaleName
 * COPYRIGHT:   Copyright 2025 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#include "k32_vista.h"
#include <ndk/rtlfuncs.h>

int
WINAPI
LCIDToLocaleName(
    _In_ LCID Locale,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ int cchName,
    _In_ DWORD dwFlags)
{
    WCHAR Buffer[LOCALE_NAME_MAX_LENGTH];
    UNICODE_STRING LocaleNameString;
    DWORD RtlFlags = 0;
    NTSTATUS Status;

    /* Measured on Windows Server 2022: a negative size and any flag but LOCALE_ALLOW_NEUTRAL_NAMES are refused
       (0x1, 0x2, 0x4, 0x8, 0x80, 0x100, 0x1000, 0x80000000 and 0x10000000 as well), and so is an LCID with no
       language but a sort order or bits above the sort order (0x10000, 0x20000, 0x30000, 0x400000, 0x10000000) */
    if (cchName < 0 || (dwFlags & ~LOCALE_ALLOW_NEUTRAL_NAMES) ||
        (Locale != LOCALE_NEUTRAL && !LANGIDFROMLCID(Locale)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* LOCALE_CUSTOM_UNSPECIFIED stands for a locale the caller did not name; Windows
       resolves it to the user default locale (measured: "en-US" on an en-US system) */
    if (Locale == LOCALE_CUSTOM_UNSPECIFIED)
        Locale = GetUserDefaultLCID();

    /* LOCALE_NEUTRAL, and the LCIDs of the custom range (no primary language, sublanguage 8 to 0x13), resolve to the
       user default locale as well (measured on Windows Server 2022: "en-US" on an en-US system, with or without
       LOCALE_ALLOW_NEUTRAL_NAMES). The sublanguages 5, 6 and 7 (0x1400 to 0x1c00) name no locale. */
    if (Locale == LOCALE_NEUTRAL ||
        (!(Locale & 0xffff03ff) && SUBLANGID(LANGIDFROMLCID(Locale)) >= 8 && SUBLANGID(LANGIDFROMLCID(Locale)) <= 0x13))
        Locale = GetUserDefaultLCID();

    if (dwFlags & LOCALE_ALLOW_NEUTRAL_NAMES)
    {
        RtlFlags |= RTL_LOCALE_ALLOW_NEUTRAL_NAMES;
    }

    /* The name is made in a buffer of our own: a size query (cchName 0) leaves the caller's buffer alone and a
       buffer that is too small is filled as far as it goes (measured on Windows Server 2022: "en" of "en-US"
       for cchName 3, ERROR_INSUFFICIENT_BUFFER) */
    LocaleNameString.Buffer = Buffer;
    LocaleNameString.Length = 0;
    LocaleNameString.MaximumLength = sizeof(Buffer) - sizeof(WCHAR);

    /* Call the RTL function */
    Status = RtlLcidToLocaleName(Locale, &LocaleNameString, RtlFlags, FALSE);
    if (!NT_SUCCESS(Status) && !(dwFlags & LOCALE_ALLOW_NEUTRAL_NAMES))
    {
        /* Without the flag Windows names the locale a neutral LCID stands for; LOCALE_NEUTRAL is the default */
        LCID Specific = Locale ? BasepNeutralLcidToSpecific(Locale) : GetUserDefaultLCID();

        /* a sort order that names no locale is no neutral locale (0x10409 is refused) */
        if (Locale & 0xffff0000)
            Specific = 0;

        if (Specific)
        {
            LocaleNameString.Length = 0;
            Status = RtlLcidToLocaleName(Specific, &LocaleNameString, RtlFlags, FALSE);
        }
    }
    if (!NT_SUCCESS(Status))
    {
        /* A buffer that is too small is reported as such; an LCID that names no locale is ERROR_INVALID_PARAMETER
           (measured on Windows Server 2022: 87 for 0x1400 where the status here maps to 31) */
        SetLastError(Status == STATUS_BUFFER_TOO_SMALL ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER);
        return 0;
    }

    {
        INT Length = (LocaleNameString.Length / sizeof(WCHAR)) + 1;

        if (cchName == 0 || lpName == NULL)
            return Length;

        Buffer[LocaleNameString.Length / sizeof(WCHAR)] = UNICODE_NULL;
        if (cchName < Length)
        {
            RtlCopyMemory(lpName, Buffer, (cchName - 1) * sizeof(WCHAR));
            lpName[cchName - 1] = UNICODE_NULL;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        /* Return the length including the terminating null */
        RtlCopyMemory(lpName, Buffer, Length * sizeof(WCHAR));
        return Length;
    }
}
