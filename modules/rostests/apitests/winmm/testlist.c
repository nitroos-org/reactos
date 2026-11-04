/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_DriverLoad(void);
extern void func_LoadUnload(void);
extern void func_MidiMapperLongMsg(void);
extern void func_timeBeginPeriod(void);
extern void func_timeGetTime(void);

const struct test winetest_testlist[] =
{
    { "DriverLoad", func_DriverLoad },
    { "LoadUnload", func_LoadUnload },
    { "MidiMapperLongMsg", func_MidiMapperLongMsg },
    { "timeBeginPeriod", func_timeBeginPeriod },
    { "timeGetTime", func_timeGetTime },

    { 0, 0 }
};
