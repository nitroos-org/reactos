/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_DwmExtendFrame(void);
extern void func_DwmFlush(void);

const struct test winetest_testlist[] =
{
    { "DwmExtendFrame", func_DwmExtendFrame },
    { "DwmFlush", func_DwmFlush },

    { 0, 0 }
};
