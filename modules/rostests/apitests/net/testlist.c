/*
 * PROJECT:     ReactOS net.exe Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Test list
 */

#define STANDALONE
#include <apitest.h>

extern void func_NetExit(void);
extern void func_NetStartArgs(void);
extern void func_NetShare(void);

const struct test winetest_testlist[] =
{
    { "NetExit", func_NetExit },
    { "NetStartArgs", func_NetStartArgs },
    { "NetShare", func_NetShare },

    { 0, 0 }
};
