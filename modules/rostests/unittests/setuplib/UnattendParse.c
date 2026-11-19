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
}
