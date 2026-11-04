/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_FakeMiniport(void);
extern void func_TcpipUnbind(void);

const struct test winetest_testlist[] =
{
    { "FakeMiniport", func_FakeMiniport },
    { "TcpipUnbind", func_TcpipUnbind },

    { 0, 0 }
};
