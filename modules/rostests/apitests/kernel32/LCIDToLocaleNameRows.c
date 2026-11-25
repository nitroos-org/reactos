/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for LCIDToLocaleName: sizes, partial copies, flags and LCIDs without a language
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row is a measurement on Windows Server 2022 (build 20348).
 */

#include "precomp.h"

typedef INT (WINAPI *PFN_LCIDToLocaleName)(LCID, LPWSTR, INT, DWORD);

#define NOERR 0xdeadbeef
#define FILL 0xaaaa

static PFN_LCIDToLocaleName pLCIDToLocaleName;

static void CheckRow(LCID Lcid, DWORD Flags, INT Size, INT Expected, DWORD ExpectedError, PCWSTR ExpectedText, int Line)
{
    WCHAR Buffer[16];
    INT Result, i;

    for (i = 0; i < 16; i++)
        Buffer[i] = FILL;
    SetLastError(NOERR);
    Result = pLCIDToLocaleName(Lcid, Buffer, Size, Flags);
    ok(Result == Expected, "line %d: lcid 0x%lx flags 0x%lx size %d: got %d, expected %d\n", Line, Lcid, Flags, Size,
       Result, Expected);
    ok(GetLastError() == ExpectedError, "line %d: lcid 0x%lx flags 0x%lx size %d: error %lu, expected %lu\n", Line, Lcid,
       Flags, Size, GetLastError(), ExpectedError);
    if (ExpectedText)
        ok(!wcscmp(Buffer, ExpectedText), "line %d: lcid 0x%lx size %d: got '%ls', expected '%ls'\n", Line, Lcid, Size,
           Buffer, ExpectedText);
    else
        ok(Buffer[0] == FILL, "line %d: lcid 0x%lx size %d: the buffer was written (0x%x)\n", Line, Lcid, Size, Buffer[0]);
}

START_TEST(LCIDToLocaleNameRows)
{
    static const LCID NoLanguage[] = { 0x10000, 0x20000, 0x30000, 0x400000, 0x10000000, 0x10409, 0x20407, 0x1400, 0xffff };
    static const DWORD BadFlags[] = { 0x1, 0x2, 0x4, 0x8, 0x80, 0x100, 0x1000, 0x10000000, 0x80000000, 0x08000001 };
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    ULONG i, j;
    WCHAR Name[16];

    pLCIDToLocaleName = (PVOID)GetProcAddress(Kernel32, "LCIDToLocaleName");
    if (!pLCIDToLocaleName)
    {
        skip("LCIDToLocaleName is not exported\n");
        return;
    }

    /* A size of 0 asks for the length, even with a buffer: the buffer stays as it is and there is no error */
    CheckRow(0x409, 0, 0, 6, NOERR, NULL, __LINE__);
    CheckRow(0x409, LOCALE_ALLOW_NEUTRAL_NAMES, 0, 6, NOERR, NULL, __LINE__);
    CheckRow(0x407, 0, 0, 6, NOERR, NULL, __LINE__);

    /* A buffer that is too small is filled as far as it goes, with a terminator */
    CheckRow(0x409, 0, 2, 0, ERROR_INSUFFICIENT_BUFFER, L"e", __LINE__);
    CheckRow(0x409, 0, 5, 0, ERROR_INSUFFICIENT_BUFFER, L"en-U", __LINE__);
    CheckRow(0x407, 0, 5, 0, ERROR_INSUFFICIENT_BUFFER, L"de-D", __LINE__);
    CheckRow(0x409, LOCALE_ALLOW_NEUTRAL_NAMES, 2, 0, ERROR_INSUFFICIENT_BUFFER, L"e", __LINE__);

    /* Exact and larger buffers */
    CheckRow(0x409, 0, 6, 6, NOERR, L"en-US", __LINE__);
    CheckRow(0x409, 0, 85, 6, NOERR, L"en-US", __LINE__);

    /* A negative size */
    CheckRow(0x409, 0, -1, 0, ERROR_INVALID_PARAMETER, NULL, __LINE__);

    /* Flags other than LOCALE_ALLOW_NEUTRAL_NAMES */
    for (i = 0; i < ARRAYSIZE(BadFlags); i++)
    {
        CheckRow(0x409, BadFlags[i], 0, 0, ERROR_INVALID_PARAMETER, NULL, __LINE__);
        CheckRow(0x409, BadFlags[i], 6, 0, ERROR_INVALID_PARAMETER, NULL, __LINE__);
    }

    /* LCIDs with no language, or a sort order no locale has */
    for (i = 0; i < ARRAYSIZE(NoLanguage); i++)
    {
        static const DWORD Flags[] = { 0, LOCALE_ALLOW_NEUTRAL_NAMES };

        for (j = 0; j < ARRAYSIZE(Flags); j++)
        {
            CheckRow(NoLanguage[i], Flags[j], 0, 0, ERROR_INVALID_PARAMETER, NULL, __LINE__);
            CheckRow(NoLanguage[i], Flags[j], 85, 0, ERROR_INVALID_PARAMETER, NULL, __LINE__);
        }
    }

    /* The invariant locale has an empty name */
    SetLastError(NOERR);
    Name[0] = FILL;
    ok(pLCIDToLocaleName(0x7f, Name, 16, 0) == 1 && Name[0] == 0, "invariant: '%ls'\n", Name);
}
