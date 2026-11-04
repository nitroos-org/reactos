/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for version.dll
 * COPYRIGHT:   Copyright 2024 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#define STANDALONE
#include <apitest.h>

extern void func_VerQueryValue(void);
extern void func_GetFileVersionInfoSize(void);

const struct test winetest_testlist[] =
{
    { "VerQueryValue",                 func_VerQueryValue },
    { "GetFileVersionInfoSize",        func_GetFileVersionInfoSize },

    { 0, 0 }
};
