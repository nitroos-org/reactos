/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_DiskModel(void);
extern void func_DiskLayout(void);
extern void func_DiskOps(void);

const struct test winetest_testlist[] =
{
    { "DiskModel", func_DiskModel },
    { "DiskLayout", func_DiskLayout },
    { "DiskOps", func_DiskOps },
    { 0, 0 }
};
