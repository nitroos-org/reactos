/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_CommandLineToArgvW(void);
extern void func_GetDpiForMonitor(void);
extern void func_ProcessDpiAwareness(void);
extern void func_FeatureStaging(void);
extern void func_GetScaleFactor(void);
extern void func_IStreamFunctions(void);
extern void func_SHCreateThreadWithHandle(void);
extern void func_SHRegGetValueFromHKCUHKLM(void);

const struct test winetest_testlist[] =
{
    { "CommandLineToArgvW", func_CommandLineToArgvW },
    { "GetDpiForMonitor", func_GetDpiForMonitor },
    { "ProcessDpiAwareness", func_ProcessDpiAwareness },
    { "FeatureStaging", func_FeatureStaging },
    { "GetScaleFactor", func_GetScaleFactor },
    { "IStreamFunctions", func_IStreamFunctions },
    { "SHCreateThreadWithHandle", func_SHCreateThreadWithHandle },
    { "SHRegGetValueFromHKCUHKLM", func_SHRegGetValueFromHKCUHKLM },
    { 0, 0 }
};
