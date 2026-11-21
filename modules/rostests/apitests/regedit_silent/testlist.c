/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_regedit_silent(void);

const struct test winetest_testlist[] =
{
    { "regedit_silent", func_regedit_silent },
    { 0, 0 }
};
