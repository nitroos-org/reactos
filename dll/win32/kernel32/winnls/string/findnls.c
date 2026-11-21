/*
 * PROJECT:     ReactOS Win32 Base API
 * PURPOSE:     FindNLSString and FindNLSStringEx
 * COPYRIGHT:   After Wine's kernel32 (dlls/kernel32/locale.c, Wine 4.x), Copyright 2001 Alexandre Julliard and others, LGPL-2.1+
 *
 * These live in kernel32 proper, next to CompareStringEx (kernel32_vista.dll is linked from the same objects as
 * kernel32_vista_static, so a function there cannot call an internal function of kernel32.dll: the link of
 * kernel32_vista.dll would not find it). The name of the locale and the flags are checked once per search, and the
 * windows are compared without the checks CompareStringEx makes in every call.
 */

#include <k32.h>

#if (DLL_EXPORT_VERSION >= 0x0600) /* FindNLSString and FindNLSStringEx are exported from 0x600 on only */

/* locale.c */
extern BOOL BasepPrepareCompareFlags(DWORD flags, int *wine_flags);
/* sortkey.c */
extern int wine_compare_string(int flags, const WCHAR *str1, int len1, const WCHAR *str2, int len2);
/* kernel32_vista/LocaleNameToLCID.c, kernel32_vista/LCIDToLocaleName.c */
BOOL BasepIsLocaleNameAccepted(LPCWSTR name);
int WINAPI LCIDToLocaleName(LCID Locale, LPWSTR lpName, int cchName, DWORD dwFlags);

/******************************************************************************
 *           FindNLSStringEx    (KERNEL32.@)
 *
 * After Wine's kernel32 (dlls/kernel32/locale.c, Wine 4.x), Copyright 2001 Alexandre Julliard and others, LGPL-2.1+.
 * A window the length of the value slides over the source and the comparison of CompareStringEx decides each position,
 * so a match is always as long as the value: the source is not normalized, and a linguistic match of a different
 * length (ignorable characters, expansions) is not found.
 */
INT
WINAPI
FindNLSStringEx(
    _In_opt_ LPCWSTR lpLocaleName,
    _In_ DWORD dwFindNLSStringFlags,
    _In_ LPCWSTR lpStringSource,
    _In_ INT cchSource,
    _In_ LPCWSTR lpStringValue,
    _In_ INT cchValue,
    _Out_opt_ LPINT pcchFound,
    _In_opt_ LPNLSVERSIONINFO lpVersionInformation,
    _In_opt_ LPVOID lpReserved,
    _In_opt_ LPARAM sortHandle)
{
    const DWORD FindFlags = FIND_FROMSTART | FIND_FROMEND | FIND_STARTSWITH | FIND_ENDSWITH;
    DWORD CompareFlags, Direction;
    INT offset, inc, count;
    int WineFlags;

    /* The version information, the reserved pointer and the sort handle are ignored (Windows takes them without an error) */
    UNREFERENCED_PARAMETER(lpVersionInformation);
    UNREFERENCED_PARAMETER(lpReserved);
    UNREFERENCED_PARAMETER(sortHandle);

    /* The locale name comes first: a name that is no well-formed tag is refused before anything else is looked at
       (measured on Windows Server 2022: ERROR_INVALID_PARAMETER for short, empty and NULL strings and for bad flags) */
    if (lpLocaleName && lpLocaleName[0] && !BasepIsLocaleNameAccepted(lpLocaleName))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (!lpStringSource || cchSource < -1 || !lpStringValue || cchValue < -1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    /* One direction at most, and none means from the start (measured on Windows 10 22H2) */
    Direction = dwFindNLSStringFlags & FindFlags;
    if (Direction & (Direction - 1))
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return -1;
    }
    if (!Direction) dwFindNLSStringFlags |= FIND_FROMSTART;

    /* The comparison flags the search takes (measured on Windows Server 2022): not SORT_STRINGSORT, not the
       undocumented 0x10000000 or 0x8 and nothing above NORM_LINGUISTIC_CASING; NORM_IGNORENONSPACE together with
       LINGUISTIC_IGNOREDIACRITIC is refused too, and so is NORM_IGNORECASE together with LINGUISTIC_IGNORECASE. CompareStringEx itself is more tolerant. */
    if (dwFindNLSStringFlags & ~(FindFlags | NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS |
                                 LINGUISTIC_IGNORECASE | LINGUISTIC_IGNOREDIACRITIC | NORM_IGNOREKANATYPE |
                                 NORM_IGNOREWIDTH | NORM_LINGUISTIC_CASING) ||
        (dwFindNLSStringFlags & (NORM_IGNORENONSPACE | LINGUISTIC_IGNOREDIACRITIC)) ==
        (NORM_IGNORENONSPACE | LINGUISTIC_IGNOREDIACRITIC) ||
        (dwFindNLSStringFlags & (NORM_IGNORECASE | LINGUISTIC_IGNORECASE)) == (NORM_IGNORECASE | LINGUISTIC_IGNORECASE))
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return -1;
    }

    if (cchSource == -1) cchSource = lstrlenW(lpStringSource);
    if (cchValue == -1) cchValue = lstrlenW(lpStringValue);

    CompareFlags = dwFindNLSStringFlags & ~FindFlags;

    /*
     * Zero lengths are no error (measured on Windows 10 22H2), once the flags have passed. An empty value matches
     * at the start, or at the end of the source for FIND_FROMEND and FIND_ENDSWITH, with a found length of 0, and
     * it wins over an empty source; it leaves the last error alone. An empty source finds nothing, with no error.
     */
    if (!cchSource || !cchValue)
    {
        if (!BasepPrepareCompareFlags(CompareFlags, &WineFlags))
            return -1;
        if (!cchValue)
        {
            if (pcchFound) *pcchFound = 0;
            return dwFindNLSStringFlags & (FIND_FROMEND | FIND_ENDSWITH) ? cchSource : 0;
        }
        SetLastError(ERROR_SUCCESS);
        return -1;
    }

    cchSource -= cchValue;
    if (cchSource < 0)
    {
        SetLastError(ERROR_SUCCESS);
        return -1;
    }

    if (!BasepPrepareCompareFlags(CompareFlags, &WineFlags))
        return -1;

    count = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_FROMEND) ? cchSource + 1 : 1;
    offset = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 0 : cchSource;
    inc = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 1 : -1;
    while (count--)
    {
        if (wine_compare_string(WineFlags, lpStringSource + offset, cchValue, lpStringValue, cchValue) == 0)
        {
            if (pcchFound) *pcchFound = cchValue;
            return offset;
        }
        offset += inc;
    }

    /* No match is no error; a match leaves the last error alone (measured on Windows Server 2022) */
    SetLastError(ERROR_SUCCESS);
    return -1;
}

/******************************************************************************
 *           FindNLSString    (KERNEL32.@)
 *
 * The LCID form of FindNLSStringEx. An LCID is taken when LCIDToLocaleName names a locale for it (measured on
 * Windows Server 2022: LOCALE_NEUTRAL, the user and system defaults, custom-range LCIDs, neutral languages and
 * sort-order LCIDs are taken, an LCID that names nothing is ERROR_INVALID_PARAMETER); the rest is FindNLSStringEx.
 */
INT
WINAPI
FindNLSString(
    _In_ LCID Locale,
    _In_ DWORD dwFindNLSStringFlags,
    _In_ LPCWSTR lpStringSource,
    _In_ INT cchSource,
    _In_ LPCWSTR lpStringValue,
    _In_ INT cchValue,
    _Out_opt_ LPINT pcchFound)
{
    WCHAR Name[LOCALE_NAME_MAX_LENGTH];

    if (!LCIDToLocaleName(Locale, Name, RTL_NUMBER_OF(Name), LOCALE_ALLOW_NEUTRAL_NAMES))
        return -1;

    return FindNLSStringEx(Name, dwFindNLSStringFlags, lpStringSource, cchSource, lpStringValue, cchValue,
                           pcchFound, NULL, NULL, 0);
}

#endif /* DLL_EXPORT_VERSION */
