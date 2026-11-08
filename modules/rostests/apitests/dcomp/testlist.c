/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_Composition(void);
extern void func_DCompositionCreateDevice(void);

const struct test winetest_testlist[] =
{
    { "Composition", func_Composition },
    { "DCompositionCreateDevice", func_DCompositionCreateDevice },

    { 0, 0 }
};
