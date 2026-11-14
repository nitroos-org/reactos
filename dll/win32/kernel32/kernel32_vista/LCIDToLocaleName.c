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

    if (cchName < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* LOCALE_CUSTOM_UNSPECIFIED stands for a locale the caller did not name; Windows
       resolves it to the user default locale (measured: "en-US" on an en-US system) */
    if (Locale == LOCALE_CUSTOM_UNSPECIFIED)
        Locale = GetUserDefaultLCID();

    if (dwFlags & LOCALE_ALLOW_NEUTRAL_NAMES)
    {
        RtlFlags |= RTL_LOCALE_ALLOW_NEUTRAL_NAMES;
    }

    if (lpName != NULL)
    {
        cchName = min(cchName, LOCALE_NAME_MAX_LENGTH);
        LocaleNameString.Buffer = lpName;
        LocaleNameString.Length = 0;
        LocaleNameString.MaximumLength = (USHORT)(cchName * sizeof(WCHAR));
    }
    else
    {
        LocaleNameString.Buffer = Buffer;
        LocaleNameString.Length = 0;
        LocaleNameString.MaximumLength = sizeof(Buffer);
    }

    /* Call the RTL function */
    Status = RtlLcidToLocaleName(Locale, &LocaleNameString, RtlFlags, FALSE);
    if (!NT_SUCCESS(Status) && !(dwFlags & LOCALE_ALLOW_NEUTRAL_NAMES))
    {
        /* Without the flag Windows names the locale a neutral LCID stands for; LOCALE_NEUTRAL is the default */
        LCID Specific = Locale ? BasepNeutralLcidToSpecific(Locale) : GetUserDefaultLCID();

        if (Specific)
        {
            LocaleNameString.Length = 0;
            Status = RtlLcidToLocaleName(Specific, &LocaleNameString, RtlFlags, FALSE);
        }
    }
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }

    /* Return the length including the terminating null */
    return (LocaleNameString.Length / sizeof(WCHAR)) + 1;
}
