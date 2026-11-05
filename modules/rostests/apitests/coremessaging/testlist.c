/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test list for coremessaging_apitest
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_DispatcherQueue(void);

const struct test winetest_testlist[] =
{
    { "DispatcherQueue", func_DispatcherQueue },
    { 0, 0 }
};
