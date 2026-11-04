/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     clientpfn_testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>
extern void func_ClientPfn(void);
const struct test winetest_testlist[] =
{
    { "ClientPfn", func_ClientPfn },
    { 0, 0 }
};
