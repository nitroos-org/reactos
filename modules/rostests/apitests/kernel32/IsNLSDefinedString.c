/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for IsNLSDefinedString: which code points are defined
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row is a measurement on Windows Server 2022 (build 20348): the answer for the string made of the code point.
 */

#include "precomp.h"

typedef BOOL (WINAPI *PFN_IsNLSDefinedString)(DWORD, DWORD, LPNLSVERSIONINFO, LPCWSTR, INT);

static const struct { ULONG Code; BOOL Defined; } Rows[] =
{
    /* ordinary text, controls, the last assigned characters of a block, the unassigned ones after them */
    { 0x0000 + 1, TRUE }, { 0x0041, TRUE }, { 0x007f, TRUE }, { 0x00a0, TRUE }, { 0x00ad, TRUE }, { 0x0377, TRUE },
    { 0x0378, FALSE }, { 0x0379, FALSE }, { 0x037a, TRUE }, { 0x0530, FALSE }, { 0x0531, TRUE }, { 0x0557, FALSE },
    { 0x05d0, TRUE }, { 0x05eb, FALSE }, { 0x0e3a, TRUE }, { 0x0e3b, FALSE }, { 0x2028, TRUE }, { 0x2064, TRUE },
    { 0x2065, FALSE }, { 0x20b5, TRUE }, { 0x20ba, TRUE }, { 0x3041, TRUE }, { 0x3040, FALSE }, { 0x4db5, TRUE },
    { 0x4db6, FALSE }, { 0x4e00, TRUE }, { 0x9fcb, TRUE }, { 0xac00, TRUE }, { 0xd7a3, TRUE }, { 0xd7a4, FALSE },
    /* private use, noncharacters, the byte order mark, the specials */
    { 0xe000, FALSE }, { 0xf8ff, FALSE }, { 0xf900, TRUE }, { 0xfdcf, FALSE }, { 0xfdd0, FALSE }, { 0xfdef, FALSE },
    { 0xfdf0, TRUE }, { 0xfeff, FALSE }, { 0xfefc, TRUE }, { 0xfffd, TRUE }, { 0xfffe, FALSE }, { 0xffff, FALSE },
    /* the supplementary planes: planes 1 and 2 and the variation selectors supplement */
    { 0x10000, TRUE }, { 0x1000c, TRUE }, { 0x1d11e, TRUE }, { 0x1f600, TRUE }, { 0x1ffff, TRUE }, { 0x20000, TRUE },
    { 0x2a6d6, TRUE }, { 0x2ffff, TRUE }, { 0x30000, FALSE }, { 0xe0000, FALSE }, { 0xe0001, FALSE }, { 0xe00ff, FALSE },
    { 0xe0100, TRUE }, { 0xe01ef, TRUE }, { 0xe01f0, FALSE }, { 0xf0000, FALSE }, { 0x10fffd, FALSE }, { 0x10ffff, FALSE },
};

START_TEST(IsNLSDefinedString)
{
    PFN_IsNLSDefinedString pIsNLSDefinedString;
    NLSVERSIONINFO Version = { sizeof(Version) };
    ULONG i;
    WCHAR Text[3];
    INT Length;
    BOOL Result;

    pIsNLSDefinedString = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsNLSDefinedString");
    if (!pIsNLSDefinedString)
    {
        skip("IsNLSDefinedString is not exported\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(Rows); i++)
    {
        ULONG Code = Rows[i].Code;

        if (Code >= 0x10000)
        {
            Text[0] = (WCHAR)(0xd800 + ((Code - 0x10000) >> 10));
            Text[1] = (WCHAR)(0xdc00 + ((Code - 0x10000) & 0x3ff));
            Length = 2;
        }
        else
        {
            Text[0] = (WCHAR)Code;
            Length = 1;
        }
        Text[Length] = 0;

        SetLastError(0x1234);
        Result = pIsNLSDefinedString(COMPARE_STRING, 0, &Version, Text, Length);
        ok(Result == Rows[i].Defined, "U+%04lX: got %d, expected %d\n", Code, Result, Rows[i].Defined);
        if (!Result)
            ok(GetLastError() == 0x1234, "U+%04lX: the last error is 0x%lx\n", Code, GetLastError());
    }

    /* a defined character does not make a string defined that holds one that is not */
    Text[0] = 'a'; Text[1] = 0x378; Text[2] = 0;
    ok(!pIsNLSDefinedString(COMPARE_STRING, 0, &Version, Text, 2), "a, U+0378\n");
    ok(pIsNLSDefinedString(COMPARE_STRING, 0, &Version, Text, 1), "a\n");
    ok(pIsNLSDefinedString(COMPARE_STRING, 0, &Version, L"Hello", -1), "text\n");
    ok(pIsNLSDefinedString(COMPARE_STRING, 0, &Version, L"", -1), "empty text with -1\n");

    /* unpaired surrogates */
    Text[0] = 0xd800; Text[1] = 0;
    ok(!pIsNLSDefinedString(COMPARE_STRING, 0, &Version, Text, 1), "high surrogate\n");
    Text[0] = 0xdc00;
    ok(!pIsNLSDefinedString(COMPARE_STRING, 0, &Version, Text, 1), "low surrogate\n");
}
