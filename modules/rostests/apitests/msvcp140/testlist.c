/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_Msvcp140MoneyIds(void);
extern void func_Msvcp140ThrowCppError(void);

const struct test winetest_testlist[] =
{
    { "Msvcp140MoneyIds", func_Msvcp140MoneyIds },

    { "Msvcp140ThrowCppError", func_Msvcp140ThrowCppError },
    { 0, 0 }
};
