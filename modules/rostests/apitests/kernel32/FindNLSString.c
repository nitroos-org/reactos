/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for FindNLSString (the LCID form), the flags and locale names of FindNLSStringEx and
 *              CompareStringEx, LCIDToLocaleName for LOCALE_NEUTRAL and the custom range, IsNLSDefinedString
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row is a measurement on Windows Server 2022 (build 20348). Calling FindNLSString used to raise an
 * exception: the export was a stub.
 */

#include "precomp.h"

#ifndef LOCALE_NAME_SYSTEM_DEFAULT
#define LOCALE_NAME_SYSTEM_DEFAULT L"!x-sys-default-locale"
#endif
#ifndef LINGUISTIC_IGNORECASE
#define LINGUISTIC_IGNORECASE 0x00000010
#endif
#ifndef LINGUISTIC_IGNOREDIACRITIC
#define LINGUISTIC_IGNOREDIACRITIC 0x00000020
#endif

typedef INT (WINAPI *PFN_FindNLSString)(LCID, DWORD, LPCWSTR, INT, LPCWSTR, INT, LPINT);
typedef INT (WINAPI *PFN_FindNLSStringEx)(LPCWSTR, DWORD, LPCWSTR, INT, LPCWSTR, INT, LPINT, LPNLSVERSIONINFO,
                                          LPVOID, LPARAM);
typedef INT (WINAPI *PFN_CompareStringEx)(LPCWSTR, DWORD, LPCWSTR, INT, LPCWSTR, INT, LPNLSVERSIONINFO, LPVOID,
                                          LPARAM);
typedef INT (WINAPI *PFN_LCIDToLocaleName)(LCID, LPWSTR, INT, DWORD);
typedef BOOL (WINAPI *PFN_IsNLSDefinedString)(DWORD, DWORD, LPNLSVERSIONINFO, LPCWSTR, INT);

#define PENDING_FOUND 0x5a5a
#define NOERR 0xdeadbeef

static PFN_FindNLSString pFindNLSString;
static PFN_FindNLSStringEx pFindNLSStringEx;
static PFN_CompareStringEx pCompareStringEx;
static PFN_LCIDToLocaleName pLCIDToLocaleName;
static PFN_IsNLSDefinedString pIsNLSDefinedString;

static const WCHAR Source[] = L"Hello World hello";
static const WCHAR Value[] = L"hello";

/* ExpectedError NOERR means "the last error is not touched" for a match; no match with no error sets 0 */
static void CheckLcid(LCID Lcid, DWORD Flags, INT Expected, INT ExpectedFound, DWORD ExpectedError, int Line)
{
    INT Result, Found = PENDING_FOUND;

    SetLastError(NOERR);
    Result = pFindNLSString(Lcid, Flags, Source, -1, Value, -1, &Found);
    ok(Result == Expected, "line %d: lcid 0x%lx flags 0x%lx: got %d, expected %d\n", Line, Lcid, Flags, Result, Expected);
    ok(Found == ExpectedFound, "line %d: lcid 0x%lx: found %d, expected %d\n", Line, Lcid, Found, ExpectedFound);
    if (ExpectedError != NOERR || Expected == -1)
        ok(GetLastError() == ExpectedError, "line %d: lcid 0x%lx flags 0x%lx: error %lu, expected %lu\n", Line, Lcid,
           Flags, GetLastError(), ExpectedError);
}

static void CheckEx(LPCWSTR Locale, DWORD Flags, INT Expected, DWORD ExpectedError, int Line)
{
    INT Result, Found = PENDING_FOUND;

    SetLastError(NOERR);
    Result = pFindNLSStringEx(Locale, Flags, Source, -1, Value, -1, &Found, NULL, NULL, 0);
    ok(Result == Expected, "line %d: locale '%ls' flags 0x%lx: got %d, expected %d\n", Line, Locale ? Locale : L"(null)",
       Flags, Result, Expected);
    ok(GetLastError() == ExpectedError, "line %d: locale '%ls' flags 0x%lx: error %lu, expected %lu\n", Line,
           Locale ? Locale : L"(null)", Flags, GetLastError(), ExpectedError);
    if (Expected == -1)
        ok(Found == PENDING_FOUND, "line %d: found was written (%d)\n", Line, Found);
}

static void CheckCompare(LPCWSTR Locale, DWORD Flags, INT Expected, DWORD ExpectedError, int Line)
{
    INT Result;

    SetLastError(NOERR);
    Result = pCompareStringEx(Locale, Flags, Source, -1, Value, -1, NULL, NULL, 0);
    ok(Result == Expected, "line %d: locale '%ls' flags 0x%lx: got %d, expected %d\n", Line, Locale ? Locale : L"(null)",
       Flags, Result, Expected);
    if (!Expected || ExpectedError == NOERR)
        ok(GetLastError() == ExpectedError, "line %d: locale '%ls' flags 0x%lx: error %lu, expected %lu\n", Line,
           Locale ? Locale : L"(null)", Flags, GetLastError(), ExpectedError);
}

static void CheckDefined(DWORD Function, LPCWSTR String, INT Length, BOOL Expected, DWORD ExpectedError, int Line)
{
    NLSVERSIONINFO Version;
    BOOL Result;

    ZeroMemory(&Version, sizeof(Version));
    Version.dwNLSVersionInfoSize = sizeof(Version);
    SetLastError(NOERR);
    Result = pIsNLSDefinedString(Function, 0, &Version, String, Length);
    ok(Result == Expected, "line %d: function %lu: got %d, expected %d\n", Line, Function, Result, Expected);
    ok(GetLastError() == ExpectedError, "line %d: function %lu: error %lu, expected %lu\n", Line, Function,
       GetLastError(), ExpectedError);
}

static void TestNoException(void)
{
    static const DWORD Flags[] =
    {
        0, FIND_FROMSTART, FIND_FROMEND, FIND_STARTSWITH, FIND_ENDSWITH, NORM_IGNORECASE, NORM_IGNORENONSPACE,
        NORM_IGNORESYMBOLS, NORM_IGNOREKANATYPE, NORM_IGNOREWIDTH, SORT_STRINGSORT, LINGUISTIC_IGNORECASE,
        LINGUISTIC_IGNOREDIACRITIC, 0x80000000, 0xffffffff
    };
    static const INT Lengths[] = { -1, 0, 1, 5 };
    ULONG i, j, k;
    INT Result, Found;
    PWSTR Big, BigValue;
    const SIZE_T Count = 200000;

    /* Every flag against NULL and empty strings and a string length does not raise anything */
    for (i = 0; i < ARRAYSIZE(Flags); i++)
        for (j = 0; j < ARRAYSIZE(Lengths); j++)
            for (k = 0; k < ARRAYSIZE(Lengths); k++)
            {
                Result = pFindNLSString(0x409, Flags[i], Source, Lengths[j], Value, Lengths[k], &Found);
                ok(Result >= -1, "flags 0x%lx lengths %d, %d: got %d\n", Flags[i], Lengths[j], Lengths[k], Result);
                Result = pFindNLSString(0x409, Flags[i], NULL, -1, Value, -1, NULL);
                ok(Result == -1, "flags 0x%lx: NULL source got %d\n", Flags[i], Result);
                Result = pFindNLSString(0x409, Flags[i], Source, -1, NULL, -1, NULL);
                ok(Result == -1, "flags 0x%lx: NULL value got %d\n", Flags[i], Result);
            }

    /* A long source, a value that is not in it */
    Big = HeapAlloc(GetProcessHeap(), 0, (Count + 1) * sizeof(WCHAR));
    BigValue = HeapAlloc(GetProcessHeap(), 0, 22 * sizeof(WCHAR));
    if (!Big || !BigValue)
    {
        skip("no memory\n");
        goto Done;
    }
    for (i = 0; i < Count; i++)
        Big[i] = L'a';
    Big[Count] = 0;
    for (i = 0; i < 20; i++)
        BigValue[i] = L'a';
    BigValue[20] = L'b';
    BigValue[21] = 0;
    Found = PENDING_FOUND;
    Result = pFindNLSString(0x409, FIND_FROMSTART, Big, -1, BigValue, -1, &Found);
    ok(Result == -1, "long source: got %d\n", Result);
    Big[Count - 1] = L'b';
    Result = pFindNLSString(0x409, FIND_FROMSTART, Big, -1, BigValue, -1, &Found);
    ok(Result == (INT)Count - 21, "long source with the value at its end: got %d\n", Result);
    ok(Found == 21, "long source: found %d\n", Found);

Done:
    HeapFree(GetProcessHeap(), 0, Big);
    HeapFree(GetProcessHeap(), 0, BigValue);
}

START_TEST(FindNLSString)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    static const LCID Valid[] =
    {
        0x0000, 0x0400, 0x0800, 0x0c00, 0x1000, 0x2000, 0x2400, 0x3000, 0x4000, 0x4c00, 0x007f, 0x0007, 0x0009, 0x0001,
        0x0409, 0x0407, 0x041f, 0x0405, 0x0c0a, 0x040a, 0x10407, 0x0004, 0x7c04, 0x0c04
    };
    static const LCID Invalid[] =
    {
        0x0100, 0x0200, 0x0234, 0x1234, 0x1400, 0x1800, 0x1c00, 0xffff, 0xfffe, 0x8409, 0xf409, 0x10409, 0x20409,
        0x40409, 0x10404, 0x20404, 0x30c04, 0x127f, 0x04000409
    };
    ULONG i;

    pFindNLSString = (PVOID)GetProcAddress(Kernel32, "FindNLSString");
    pFindNLSStringEx = (PVOID)GetProcAddress(Kernel32, "FindNLSStringEx");
    pCompareStringEx = (PVOID)GetProcAddress(Kernel32, "CompareStringEx");
    pLCIDToLocaleName = (PVOID)GetProcAddress(Kernel32, "LCIDToLocaleName");
    pIsNLSDefinedString = (PVOID)GetProcAddress(Kernel32, "IsNLSDefinedString");
    if (!pFindNLSString || !pFindNLSStringEx || !pCompareStringEx || !pLCIDToLocaleName)
    {
        skip("FindNLSString and its neighbours are not exported\n");
        return;
    }

    /* The LCIDs that name a locale are taken, with the matches of the locale-name form */
    for (i = 0; i < ARRAYSIZE(Valid); i++)
    {
        CheckLcid(Valid[i], FIND_FROMSTART, 12, 5, NOERR, __LINE__);
        CheckLcid(Valid[i], FIND_FROMEND, 12, 5, NOERR, __LINE__);
        CheckLcid(Valid[i], 0, 12, 5, NOERR, __LINE__);
        CheckLcid(Valid[i], FIND_FROMSTART | NORM_IGNORECASE, 0, 5, NOERR, __LINE__);
    }

    /* An LCID that names nothing is refused */
    for (i = 0; i < ARRAYSIZE(Invalid); i++)
        CheckLcid(Invalid[i], FIND_FROMSTART, -1, PENDING_FOUND, ERROR_INVALID_PARAMETER, __LINE__);

    /* The flags: a match is as long as the value; the rest of the direction rows is in FindNLSStringEx */
    CheckLcid(0x409, FIND_STARTSWITH, -1, PENDING_FOUND, 0, __LINE__);
    CheckLcid(0x409, FIND_ENDSWITH, 12, 5, NOERR, __LINE__);
    CheckLcid(0x409, FIND_FROMSTART | FIND_FROMEND, -1, PENDING_FOUND, ERROR_INVALID_FLAGS, __LINE__);
    CheckLcid(0x409, SORT_STRINGSORT, -1, PENDING_FOUND, ERROR_INVALID_FLAGS, __LINE__);

    TestNoException();

    /* The comparison flags the search takes: SORT_STRINGSORT, 0x10000000, 0x8, 0x100, 0x8000 and the top bit are
       not, NORM_IGNORENONSPACE together with LINGUISTIC_IGNOREDIACRITIC is not; the others are */
    CheckEx(L"en-US", FIND_FROMSTART | SORT_STRINGSORT, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | 0x10000000, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | 0x00000008, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | 0x00000100, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | 0x00008000, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | 0x01000000, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", 0x80000000, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", 0xffffffff, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | NORM_IGNORENONSPACE | LINGUISTIC_IGNOREDIACRITIC, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | LINGUISTIC_IGNOREDIACRITIC, 12, NOERR, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | LINGUISTIC_IGNOREDIACRITIC | LINGUISTIC_IGNORECASE, 0, NOERR, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | NORM_IGNORESYMBOLS, 12, NOERR, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | NORM_IGNOREKANATYPE, 12, NOERR, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | NORM_IGNOREWIDTH, 12, NOERR, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | NORM_LINGUISTIC_CASING, 12, NOERR, __LINE__);

    /* Locale names: a name that is no well-formed tag is refused by the search and by the comparison */
    CheckEx(L"xx-invalid", FIND_FROMSTART, -1, ERROR_INVALID_PARAMETER, __LINE__);
    CheckEx(L"x", FIND_FROMSTART, -1, ERROR_INVALID_PARAMETER, __LINE__);
    CheckEx(L"en-US-", FIND_FROMSTART, -1, ERROR_INVALID_PARAMETER, __LINE__);
    CheckEx(L"xx-invalid", FIND_FROMSTART | NORM_IGNORECASE, -1, ERROR_INVALID_PARAMETER, __LINE__);
    CheckEx(NULL, FIND_FROMSTART, 12, NOERR, __LINE__);
    CheckEx(L"", FIND_FROMSTART, 12, NOERR, __LINE__);
    CheckEx(LOCALE_NAME_SYSTEM_DEFAULT, FIND_FROMSTART, 12, NOERR, __LINE__);
    CheckEx(L"en", FIND_FROMSTART, 12, NOERR, __LINE__);
    CheckEx(L"cs-CZ", FIND_FROMSTART, 12, NOERR, __LINE__);
    CheckEx(L"tr-TR", FIND_FROMSTART, 12, NOERR, __LINE__);
    CheckEx(L"de-DE_phoneb", FIND_FROMSTART, 12, NOERR, __LINE__);

    CheckCompare(L"xx-invalid", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
    CheckCompare(L"x", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
    CheckCompare(L"en-US-", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
    CheckCompare(L"en-US", 0, CSTR_GREATER_THAN, NOERR, __LINE__);
    CheckCompare(L"", 0, CSTR_GREATER_THAN, NOERR, __LINE__);
    CheckCompare(NULL, 0, CSTR_GREATER_THAN, NOERR, __LINE__);
    CheckCompare(LOCALE_NAME_SYSTEM_DEFAULT, 0, CSTR_GREATER_THAN, NOERR, __LINE__);
    CheckCompare(L"de-DE_phoneb", 0, CSTR_GREATER_THAN, NOERR, __LINE__);
    /* Every well-formed tag is taken, whether the system has a locale for it or not (measured on Windows Server 2022;
       the grammar is the one of the helper in locale.c) */
    {
        static const PCWSTR Taken[] =
        {
            L"en-AT", L"en-001", L"en-150", L"es-419", L"und", L"iw-IL", L"in-ID", L"qq-QQ", L"tlh", L"eng", L"sr-SP-Latn",
            L"en-US-x-foo", L"x-private", L"x-IV_mathan", L"X-IV_MATHAN", L"x_foo", L"en-Latn-x-foo", L"en-u-co-phonebk",
            L"en-US-u-co-phonebk", L"en-US-1996", L"de-DE-1996", L"en-GB-oed", L"en-Latn-US", L"zh-Hant-CN", L"en-US-x",
            L"en-US-US", L"qps-ploc", L"qps-ploca", L"qps-plocm", L"en-US_foo", L"de-DE_phoneb", L"en_US", L"zh_Hant_TW",
            L"EN-us", L"en-123"
        };
        static const PCWSTR Refused[] =
        {
            L"Invariant", L"invariant", L"zh-CHS", L"zh-CHT", L"de_phoneb", L"en_foo", L"de_AB", L"root",
            L"xx-invalid", L"de-1901", L"sl-rozaj", L"en-aaa", L"en-Latn-foo", L"en-Latn-x", L"en-c", L"a", L"x", L"1-foo",
            L"aaaa", L"en-US-", L"-en-US", L"en--US", L"en-US ", L" en-US", L"en.US", L"en_US.UTF-8", L"C", L"POSIX",
            L"en-US-abcdefghi", L"en-1234", L"en-1a",
            /* 85 characters */
            L"x-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaa"
        };
        ULONG n;

        for (n = 0; n < ARRAYSIZE(Taken); n++)
        {
            CheckCompare(Taken[n], 0, CSTR_GREATER_THAN, NOERR, __LINE__);
            CheckEx(Taken[n], FIND_FROMSTART, 12, NOERR, __LINE__);
        }
        for (n = 0; n < ARRAYSIZE(Refused); n++)
        {
            CheckCompare(Refused[n], 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
            CheckEx(Refused[n], FIND_FROMSTART, -1, ERROR_INVALID_PARAMETER, __LINE__);
        }
        /* A name taken once is taken again, and a refused name that shares its start with a taken one stays refused */
        for (n = 0; n < 4; n++)
        {
            CheckCompare(L"en-US", 0, CSTR_GREATER_THAN, NOERR, __LINE__);
            CheckCompare(L"en-US-", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
            CheckCompare(L"en-US-x", 0, CSTR_GREATER_THAN, NOERR, __LINE__);
            CheckCompare(L"en-US-xxxxxxxxx", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
            CheckCompare(L"en-USx", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
            CheckCompare(L"en-AT", 0, CSTR_GREATER_THAN, NOERR, __LINE__);
            CheckCompare(L"en-A", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
            CheckCompare(L"en-ATX", 0, 0, ERROR_INVALID_PARAMETER, __LINE__);
            CheckEx(L"en-US", FIND_FROMSTART, 12, NOERR, __LINE__);
            CheckEx(L"en-US-", FIND_FROMSTART, -1, ERROR_INVALID_PARAMETER, __LINE__);
        }
        /* The name is looked at first by the search: a short source, bad flags, two directions and empty strings do
           not change the error of a name that is refused */
        {
            INT Found = PENDING_FOUND;

#define CHECK_NAME_FIRST(Flags, Src, SrcLen, Val, ValLen) \
    SetLastError(NOERR); \
    ok(pFindNLSStringEx(L"xx-invalid", Flags, Src, SrcLen, Val, ValLen, &Found, NULL, NULL, 0) == -1, "line %d\n", __LINE__); \
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "line %d: error %lu\n", __LINE__, GetLastError()); \
    ok(Found == PENDING_FOUND, "line %d: found was written\n", __LINE__)
            CHECK_NAME_FIRST(FIND_FROMSTART, L"ab", -1, L"abc", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART | SORT_STRINGSORT, L"abc", -1, L"ab", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART | FIND_FROMEND, L"abc", -1, L"ab", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART, NULL, -1, L"ab", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART, L"", -1, L"", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART, L"", -1, L"a", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART, L"a", -1, L"", -1);
            CHECK_NAME_FIRST(FIND_FROMSTART, L"abc", 0, L"ab", 0);
#undef CHECK_NAME_FIRST
        }
        /* 84 characters */
        CheckCompare(L"x-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aa", 0,
                     CSTR_GREATER_THAN, NOERR, __LINE__);
    }
    /* LINGUISTIC_IGNOREDIACRITIC is a comparison flag */
    CheckCompare(L"en-US", LINGUISTIC_IGNOREDIACRITIC, CSTR_GREATER_THAN, NOERR, __LINE__);
    CheckCompare(L"en-US", LINGUISTIC_IGNOREDIACRITIC | LINGUISTIC_IGNORECASE, CSTR_GREATER_THAN, NOERR, __LINE__);
    /* a linguistic flag and the flag it stands for are not combined */
    CheckCompare(L"en-US", NORM_IGNORECASE | LINGUISTIC_IGNORECASE, 0, ERROR_INVALID_FLAGS, __LINE__);
    CheckCompare(L"en-US", NORM_IGNORENONSPACE | LINGUISTIC_IGNOREDIACRITIC, 0, ERROR_INVALID_FLAGS, __LINE__);
    CheckCompare(L"en-US", NORM_IGNORECASE | LINGUISTIC_IGNORECASE | NORM_IGNORENONSPACE, 0, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | NORM_IGNORECASE | LINGUISTIC_IGNORECASE, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckEx(L"en-US", FIND_FROMSTART | 0x8, -1, ERROR_INVALID_FLAGS, __LINE__);
    CheckCompare(L"en-US", 0x80000000, 0, ERROR_INVALID_FLAGS, __LINE__);
    CheckCompare(L"en-US", 0x00000100, 0, ERROR_INVALID_FLAGS, __LINE__);
    CheckCompare(L"en-US", FIND_FROMSTART, 0, ERROR_INVALID_FLAGS, __LINE__);

    /* LCIDToLocaleName: LOCALE_NEUTRAL and the custom range are the user default locale, with and without the
       neutral-names flag; sublanguages 5 to 7 name nothing, with ERROR_INVALID_PARAMETER */
    {
        WCHAR Default[LOCALE_NAME_MAX_LENGTH], Name[LOCALE_NAME_MAX_LENGTH];
        static const LCID Custom[] = { 0x0000, 0x2000, 0x2400, 0x3000, 0x3400, 0x4000, 0x4400, 0x4800, 0x4c00 };
        INT DefaultLength = pLCIDToLocaleName(GetUserDefaultLCID(), Default, ARRAYSIZE(Default), 0);

        ok(DefaultLength > 0, "user default: %d\n", DefaultLength);
        for (i = 0; i < ARRAYSIZE(Custom); i++)
        {
            INT Length;
            DWORD Flags;

            for (Flags = 0; Flags <= LOCALE_ALLOW_NEUTRAL_NAMES; Flags += LOCALE_ALLOW_NEUTRAL_NAMES)
            {
                Name[0] = 0;
                Length = pLCIDToLocaleName(Custom[i], Name, ARRAYSIZE(Name), Flags);
                ok(Length == DefaultLength, "LCIDToLocaleName(0x%lx, 0x%lx) returned %d, expected %d\n", Custom[i],
                   Flags, Length, DefaultLength);
                ok(!wcscmp(Name, Default), "LCIDToLocaleName(0x%lx, 0x%lx) got '%ls', expected '%ls'\n", Custom[i],
                   Flags, Name, Default);
            }
        }
        {
            static const LCID None[] = { 0x1400, 0x1800, 0x1c00, 0x0100, 0x1234 };

            for (i = 0; i < ARRAYSIZE(None); i++)
            {
                SetLastError(NOERR);
                Name[0] = 0;
                ok(pLCIDToLocaleName(None[i], Name, ARRAYSIZE(Name), LOCALE_ALLOW_NEUTRAL_NAMES) == 0,
                   "LCIDToLocaleName(0x%lx) succeeded\n", None[i]);
                ok(GetLastError() == ERROR_INVALID_PARAMETER, "LCIDToLocaleName(0x%lx): error %lu\n", None[i],
                   GetLastError());
            }
        }
    }

    if (!pIsNLSDefinedString)
    {
        skip("IsNLSDefinedString is not exported\n");
        return;
    }

    /* IsNLSDefinedString: only COMPARE_STRING (1) is a function; an unpaired surrogate is not defined */
    CheckDefined(0, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(2, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(3, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(0x10, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(0x80, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(0x100000, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(0x80000000, Source, -1, FALSE, ERROR_INVALID_FLAGS, __LINE__);
    CheckDefined(COMPARE_STRING, Source, -1, TRUE, NOERR, __LINE__);
    CheckDefined(COMPARE_STRING, NULL, -1, FALSE, ERROR_INVALID_PARAMETER, __LINE__);
    CheckDefined(COMPARE_STRING, L"a\xd800", 2, FALSE, NOERR, __LINE__);
    CheckDefined(COMPARE_STRING, L"a\xdc00", 2, FALSE, NOERR, __LINE__);
    CheckDefined(COMPARE_STRING, L"a\xd800\xdc00", 3, TRUE, NOERR, __LINE__);

    /* The order of the checks and the size of the version structure (measured on Windows Server 2022) */
    {
        static const DWORD BadSizes[] = { 0, 4, 8, 11, 13, 16, 20, 24, 28, 36, 40, 0xffffffff };
        NLSVERSIONINFOEX Version;
        BOOL Result;
        ULONG n;

#define CHECK_IND(Size, Func, Flags, Str, Len, Expected, ExpectedError) \
    ZeroMemory(&Version, sizeof(Version)); \
    Version.dwNLSVersionInfoSize = Size; \
    SetLastError(NOERR); \
    Result = pIsNLSDefinedString(Func, Flags, (LPNLSVERSIONINFO)&Version, Str, Len); \
    ok(Result == Expected, "line %d: got %d\n", __LINE__, Result); \
    ok(GetLastError() == ExpectedError, "line %d: error %lu, expected %lu\n", __LINE__, GetLastError(), (DWORD)ExpectedError)
        CHECK_IND(12, COMPARE_STRING, 0, Source, -1, TRUE, NOERR);
        CHECK_IND(32, COMPARE_STRING, 0, Source, -1, TRUE, NOERR);
        for (n = 0; n < ARRAYSIZE(BadSizes); n++)
        {
            CHECK_IND(BadSizes[n], COMPARE_STRING, 0, Source, -1, FALSE, ERROR_INSUFFICIENT_BUFFER);
        }
        CHECK_IND(12, COMPARE_STRING, 0, Source, 0, FALSE, ERROR_INVALID_PARAMETER);
        CHECK_IND(12, COMPARE_STRING, 0, L"", 0, FALSE, ERROR_INVALID_PARAMETER);
        CHECK_IND(12, COMPARE_STRING, 0, L"", -1, TRUE, NOERR);
        CHECK_IND(12, COMPARE_STRING, 0, Source, -2, TRUE, NOERR);
        CHECK_IND(12, COMPARE_STRING, 1, Source, -1, FALSE, ERROR_INVALID_FLAGS);
        CHECK_IND(12, COMPARE_STRING, 0xffff, Source, -1, FALSE, ERROR_INVALID_FLAGS);
        CHECK_IND(12, COMPARE_STRING, 5, NULL, -1, FALSE, ERROR_INVALID_PARAMETER);
        CHECK_IND(12, COMPARE_STRING, 5, Source, 0, FALSE, ERROR_INVALID_PARAMETER);
        CHECK_IND(12, 7, 5, Source, -1, FALSE, ERROR_INVALID_FLAGS);
        CHECK_IND(12, 7, 0, NULL, -1, FALSE, ERROR_INVALID_PARAMETER);
        CHECK_IND(12, 7, 0, Source, 0, FALSE, ERROR_INVALID_PARAMETER);
        CHECK_IND(99, 7, 0, Source, -1, FALSE, ERROR_INSUFFICIENT_BUFFER);
        CHECK_IND(99, COMPARE_STRING, 5, Source, -1, FALSE, ERROR_INSUFFICIENT_BUFFER);
        CHECK_IND(99, COMPARE_STRING, 0, NULL, -1, FALSE, ERROR_INSUFFICIENT_BUFFER);
        CHECK_IND(99, COMPARE_STRING, 0, Source, 0, FALSE, ERROR_INSUFFICIENT_BUFFER);
#undef CHECK_IND
    }
}
