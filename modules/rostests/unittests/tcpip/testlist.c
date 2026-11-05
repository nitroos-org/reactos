/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_IfType(void);
extern void func_Reassembly(void);

const struct test winetest_testlist[] =
{
    { "IfType", func_IfType },
    { "Reassembly", func_Reassembly },
    { 0, 0 }
};
