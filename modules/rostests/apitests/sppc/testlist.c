/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_licenses(void);
extern void func_slc(void);

const struct test winetest_testlist[] =
{
    { "licenses", func_licenses },
    { "slc", func_slc },
    { 0, 0 }
};
