/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_WcsDefault(void);
extern void func_ProfileObject(void);

const struct test winetest_testlist[] =
{
    { "WcsDefault", func_WcsDefault },
    { "ProfileObject", func_ProfileObject },

    { 0, 0 }
};
