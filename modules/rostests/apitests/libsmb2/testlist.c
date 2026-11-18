/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_Smb2ErrorMap(void);
extern void func_Smb2Server(void);

const struct test winetest_testlist[] =
{
    { "Smb2ErrorMap", func_Smb2ErrorMap },
    { "Smb2Server", func_Smb2Server },

    { 0, 0 }
};
