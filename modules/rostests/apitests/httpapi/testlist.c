/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_HttpServerApi(void);
extern void func_HttpServerFlow(void);

const struct test winetest_testlist[] =
{
    { "HttpServerApi", func_HttpServerApi },
    { "HttpServerFlow", func_HttpServerFlow },

    { 0, 0 }
};
