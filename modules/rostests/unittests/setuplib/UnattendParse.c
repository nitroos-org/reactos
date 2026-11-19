/*
 * PROJECT:     ReactOS Setup Library - Unit-tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the value parsers of the unattended-setup answer file
 *              (UnattendParseBool, UnattendParseUInt, UnattendParseKeyboardLayout)
 */

#include "precomp.h"

START_TEST(UnattendParse)
{
    static const struct { PCWSTR text; BOOLEAN valid; LONG flag; } bools[] =
    {
        { L"yes",     TRUE,  1 }, { L"YES",   TRUE, 1 }, { L"True",  TRUE, 1 }, { L"on",   TRUE, 1 }, { L"1", TRUE, 1 },
        { L" yes ",   TRUE,  1 }, { L"\tno",  TRUE, 0 },
        { L"no",      TRUE,  0 }, { L"false", TRUE, 0 }, { L"OFF",   TRUE, 0 }, { L"0",    TRUE, 0 },
        { L"",        FALSE, 0 }, { L" ",     FALSE, 0 }, { L"2",    FALSE, 0 }, { L"yess", FALSE, 0 },
        { L"y",       FALSE, 0 }, { L"enabled", FALSE, 0 }, { L"yes no", FALSE, 0 },
    };
    static const struct { PCWSTR text; ULONG max; BOOLEAN valid; ULONG value; } uints[] =
    {
        { L"0",          100,        TRUE,  0 },
        { L"40960",      1000000,    TRUE,  40960 },
        { L" 7 ",        100,        TRUE,  7 },
        { L"100",        100,        TRUE,  100 },
        { L"101",        100,        FALSE, 0 },
        { L"",           100,        FALSE, 0 },
        { L"-1",         100,        FALSE, 0 },
        { L"12a",        100,        FALSE, 0 },
        { L"0x10",       100,        FALSE, 0 },
        { L"4294967296", 0xFFFFFFFF, FALSE, 0 },
        { L"99999999999999999999", 0xFFFFFFFF, FALSE, 0 },
    };
    static const struct { PCWSTR text; BOOLEAN valid; PCWSTR klid; } layouts[] =
    {
        { L"00000407", TRUE,  L"00000407" },
        { L"0407",     TRUE,  L"00000407" },
        { L"407",      TRUE,  L"00000407" },
        { L"0000040a", TRUE,  L"0000040a" },
        { L"A0010409", TRUE,  L"A0010409" },
        { L"",         FALSE, NULL },
        { L"07",       FALSE, NULL },
        { L"40",       FALSE, NULL },
        { L"4070",     TRUE,  L"00004070" },
        { L"40707",    FALSE, NULL },
        { L"0000040g", FALSE, NULL },
        { L"000004070", FALSE, NULL },
        { L"de-DE",    FALSE, NULL },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(bools); ++i)
    {
        LONG flag = -1;
        BOOLEAN res = UnattendParseBool(bools[i].text, &flag);
        ok(res == bools[i].valid, "UnattendParseBool('%S') returned %d, expected %d\n", bools[i].text, res, bools[i].valid);
        if (bools[i].valid)
            ok(flag == bools[i].flag, "UnattendParseBool('%S') gave %ld, expected %ld\n", bools[i].text, flag, bools[i].flag);
    }

    for (i = 0; i < RTL_NUMBER_OF(uints); ++i)
    {
        ULONG value = 0xDEAD;
        BOOLEAN res = UnattendParseUInt(uints[i].text, uints[i].max, &value);
        ok(res == uints[i].valid, "UnattendParseUInt('%S') returned %d, expected %d\n", uints[i].text, res, uints[i].valid);
        if (uints[i].valid)
            ok(value == uints[i].value, "UnattendParseUInt('%S') gave %lu, expected %lu\n", uints[i].text, value, uints[i].value);
    }

    for (i = 0; i < RTL_NUMBER_OF(layouts); ++i)
    {
        WCHAR klid[9] = L"?";
        BOOLEAN res = UnattendParseKeyboardLayout(layouts[i].text, klid);
        ok(res == layouts[i].valid, "UnattendParseKeyboardLayout('%S') returned %d, expected %d\n", layouts[i].text, res, layouts[i].valid);
        if (layouts[i].valid)
            ok(!_wcsicmp(klid, layouts[i].klid), "UnattendParseKeyboardLayout('%S') gave '%S', expected '%S'\n",
               layouts[i].text, klid, layouts[i].klid);
    }

    /* Hostile values: over-long text, numeric edges, characters that only look like digits or yes/no */
    {
        enum { Long = 100000 };
        PWSTR text = HeapAlloc(GetProcessHeap(), 0, (Long + 16) * sizeof(WCHAR));
        WCHAR klid[9];
        LONG flag = -1;
        ULONG value = 0xDEAD;
        ULONG k;

        ok(text != NULL, "no memory for the long values\n");
        if (!text)
            return;

        /* blanks around a good value, a hundred thousand of them: still the value */
        for (k = 0; k < Long; ++k)
            text[k] = L' ';
        wcscpy(text + Long, L"yes");
        ok(UnattendParseBool(text, &flag) && flag == 1, "yes behind %d blanks\n", Long);
        wcscpy(text, L"no");
        for (k = 2; k < Long; ++k)
            text[k] = L'\t';
        text[Long] = UNICODE_NULL;
        flag = -1;
        ok(UnattendParseBool(text, &flag) && flag == 0, "no followed by %d blanks\n", Long);

        /* a long run of other characters is never a yes/no, a number or a layout, and nothing is written past the output */
        for (k = 0; k < Long; ++k)
            text[k] = L'x';
        text[Long] = UNICODE_NULL;
        ok(!UnattendParseBool(text, &flag), "a long word is no yes/no\n");
        ok(!UnattendParseUInt(text, 0x7FFFFFFF, &value) && value == 0xDEAD, "a long word is no number\n");
        for (k = 0; k < Long; ++k)
            text[k] = L'1';
        ok(!UnattendParseUInt(text, 0x7FFFFFFF, &value) && value == 0xDEAD, "a long run of digits overflows\n");
        ok(!UnattendParseKeyboardLayout(text, klid), "a long run of digits is no layout\n");
        for (k = 0; k < Long; ++k)
            text[k] = L'0';
        wcscpy(text + Long, L"7");
        ok(UnattendParseUInt(text, 0x7FFFFFFF, &value) && value == 7, "leading zeros do not overflow\n");

        HeapFree(GetProcessHeap(), 0, text);
    }

    {
        ULONG value = 0xDEAD;
        WCHAR klid[9] = L"?";

        /* PartitionSizeMB, AutoLogonCount style numbers at the edges of 31 and 32 bits */
        ok(UnattendParseUInt(L"2147483647", 0x7FFFFFFF, &value) && value == 0x7FFFFFFF, "2^31-1\n");
        value = 0xDEAD;
        ok(!UnattendParseUInt(L"2147483648", 0x7FFFFFFF, &value) && value == 0xDEAD, "2^31 is too much\n");
        ok(UnattendParseUInt(L"4294967295", 0xFFFFFFFF, &value) && value == 0xFFFFFFFF, "2^32-1 with the 32 bit maximum\n");
        value = 0xDEAD;
        ok(!UnattendParseUInt(L"4294967296", 0xFFFFFFFF, &value) && value == 0xDEAD, "2^32\n");
        ok(!UnattendParseUInt(L"+5", 100, &value), "a sign is not a digit\n");
        ok(!UnattendParseUInt(L"5.0", 100, &value), "a decimal point\n");
        ok(!UnattendParseUInt(L"\xFF15", 100, &value), "a full-width digit is no digit\n");
        ok(!UnattendParseUInt(L"\x0665", 100, &value), "an Arabic-Indic digit is no digit\n");
        ok(!UnattendParseUInt(L"5 6", 100, &value), "two numbers\n");

        /* yes/no spelled with other characters */
        ok(!UnattendParseBool(L"y\x0435s", &(LONG){0}), "a Cyrillic e in yes\n");
        ok(!UnattendParseBool(L"yes\x0001", &(LONG){0}), "a control character after yes\n");
        ok(!UnattendParseBool(L"\"yes\"", &(LONG){0}), "quotes are removed by the caller, not here\n");

        /* layouts: odd lengths, signs, hex prefix */
        ok(!UnattendParseKeyboardLayout(L"0x407", klid), "0x407\n");
        ok(!UnattendParseKeyboardLayout(L"-407", klid), "-407\n");
        ok(!UnattendParseKeyboardLayout(L"00000407 ", klid), "a blank after the layout\n");
        ok(!UnattendParseKeyboardLayout(L"\xFF14\xFF10\xFF17", klid), "full-width digits\n");
    }
}
