/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CompareStringW / CompareStringEx: the result for two strings does not depend on a start the two
 *              strings have in common, whatever the flags, and equal strings are equal at every length
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The comparison skips the characters both strings start with (a fast path for equal strings). The expected values
 * are what the same comparison gives for the strings without the common start, so this holds for the old code too.
 */

#include "precomp.h"

#include <winnls.h>

static ULONG g_Seed = 12345;

static
ULONG
Rnd(ULONG Range)
{
    g_Seed = g_Seed * 1103515245 + 12345;
    return (g_Seed >> 8) % Range;
}

static
WCHAR
RandomChar(void)
{
    static const WCHAR Interesting[] = { L'a', L'b', L'A', L'B', L'0', L' ', L'-', L'\'', L'_', L'.', L',', 0xe0, 0xc0, 0xe9, 0xfc, 0xdf, 0x3b1, 0x391, 0x430, 0x3042, 0xff21 };

    switch (Rnd(4))
    {
        case 0: return L'a' + (WCHAR)Rnd(26);
        case 1: return Interesting[Rnd(RTL_NUMBER_OF(Interesting))];
        case 2: return 0x20 + (WCHAR)Rnd(0x60);
        default: return (WCHAR)(0x100 + Rnd(0x2f00));
    }
}

static
void
FillRandom(
    _Out_writes_(Count) PWCHAR Buffer,
    _In_ ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        Buffer[i] = RandomChar();
}

START_TEST(CompareStringEqualPrefix)
{
    static const DWORD Flags[] = { 0, NORM_IGNORECASE, NORM_IGNORENONSPACE, NORM_IGNORESYMBOLS, SORT_STRINGSORT,
                                   NORM_IGNORECASE | NORM_IGNORESYMBOLS, NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS,
                                   SORT_STRINGSORT | NORM_IGNORECASE };
    static WCHAR Prefix[300], A[40], B[40], Left[360], Right[360], Long1[5000], Long2[5000];
    ULONG Round, FlagIndex, i, Length;
    int Wrong = 0, Checked = 0;

    /* Equal strings of every length up to 70, and a few long ones, are equal for every flag */
    FillRandom(Long1, RTL_NUMBER_OF(Long1));
    for (Length = 0; Length <= 70; Length++)
    {
        memcpy(Long2, Long1, Length * sizeof(WCHAR));
        for (FlagIndex = 0; FlagIndex < RTL_NUMBER_OF(Flags); FlagIndex++)
        {
            int Result = CompareStringW(LOCALE_USER_DEFAULT, Flags[FlagIndex], Long1, Length, Long2, Length);
            ok(Result == CSTR_EQUAL, "equal strings of %lu characters, flags 0x%lx: %d\n", Length, Flags[FlagIndex], Result);
            Result = CompareStringEx(NULL, Flags[FlagIndex], Long1, Length, Long2, Length, NULL, NULL, 0);
            ok(Result == CSTR_EQUAL, "Ex: equal strings of %lu characters, flags 0x%lx: %d\n", Length, Flags[FlagIndex], Result);
        }
    }
    memcpy(Long2, Long1, sizeof(Long1));
    ok(CompareStringW(LOCALE_USER_DEFAULT, 0, Long1, RTL_NUMBER_OF(Long1), Long2, RTL_NUMBER_OF(Long2)) == CSTR_EQUAL,
       "equal strings of 5000 characters\n");
    Long2[RTL_NUMBER_OF(Long2) - 1] = L'z';
    Long1[RTL_NUMBER_OF(Long1) - 1] = L'a';
    ok(CompareStringW(LOCALE_USER_DEFAULT, 0, Long1, RTL_NUMBER_OF(Long1), Long2, RTL_NUMBER_OF(Long2)) == CSTR_LESS_THAN,
       "strings of 5000 characters that differ in the last one\n");

    /* A common start does not change the result */
    for (Round = 0; Round < 20000; Round++)
    {
        ULONG PrefixLength = (Round % 3 == 0) ? Rnd(8) : Rnd(RTL_NUMBER_OF(Prefix));
        ULONG LenA = Rnd(RTL_NUMBER_OF(A) + 1), LenB = Rnd(RTL_NUMBER_OF(B) + 1);

        FillRandom(Prefix, PrefixLength);
        FillRandom(A, LenA);
        FillRandom(B, LenB);
        switch (Rnd(4))
        {
            case 0: /* B is A with a symbol, hyphen or case change somewhere */
                LenB = LenA;
                memcpy(B, A, LenA * sizeof(WCHAR));
                if (LenA)
                {
                    i = Rnd(LenA);
                    B[i] = (Rnd(2) ? L'-' : (WCHAR)(A[i] ^ 0x20));
                }
                break;
            case 1: /* one is the start of the other */
                LenB = Rnd(LenA + 1);
                memcpy(B, A, LenB * sizeof(WCHAR));
                break;
            default:
                break;
        }
        memcpy(Left, Prefix, PrefixLength * sizeof(WCHAR));
        memcpy(Left + PrefixLength, A, LenA * sizeof(WCHAR));
        memcpy(Right, Prefix, PrefixLength * sizeof(WCHAR));
        memcpy(Right + PrefixLength, B, LenB * sizeof(WCHAR));

        for (FlagIndex = 0; FlagIndex < RTL_NUMBER_OF(Flags); FlagIndex++)
        {
            int With = CompareStringW(LOCALE_USER_DEFAULT, Flags[FlagIndex], Left, PrefixLength + LenA, Right, PrefixLength + LenB);
            int Without = CompareStringW(LOCALE_USER_DEFAULT, Flags[FlagIndex], A, LenA, B, LenB);

            Checked++;
            if (With != Without)
            {
                if (Wrong < 10)
                    ok(0, "prefix %lu, lengths %lu/%lu, flags 0x%lx: %d with the start, %d without\n",
                       PrefixLength, LenA, LenB, Flags[FlagIndex], With, Without);
                Wrong++;
            }
        }
    }
    ok(Wrong == 0, "%d of %d comparisons differ\n", Wrong, Checked);
}
