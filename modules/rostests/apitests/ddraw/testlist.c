/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_NoDriverNotice(void);
extern void func_VideoMemory(void);

const struct test winetest_testlist[] =
{
    { "NoDriverNotice", func_NoDriverNotice },
    { "VideoMemory", func_VideoMemory },
    { 0, 0 }
};
