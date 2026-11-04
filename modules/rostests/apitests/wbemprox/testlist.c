/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_StandardCimv2(void);
extern void func_Win32_Process(void);

const struct test winetest_testlist[] =
{
    { "StandardCimv2", func_StandardCimv2 },
    { "Win32_Process", func_Win32_Process },
    { 0, 0 }
};
