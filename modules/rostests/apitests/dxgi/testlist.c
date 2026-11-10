/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_CreateSwapChainForComposition(void);
extern void func_EnumWarpAdapter(void);
extern void func_SharedResource(void);
extern void func_SharedResourceChild(void);

const struct test winetest_testlist[] =
{
    { "CreateSwapChainForComposition", func_CreateSwapChainForComposition },
    { "EnumWarpAdapter", func_EnumWarpAdapter },
    { "SharedResource", func_SharedResource },
    { "SharedResourceChild", func_SharedResourceChild },

    { 0, 0 }
};
