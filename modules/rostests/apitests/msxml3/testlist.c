/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_DOMDocument(void);
extern void func_SchemaCache(void);

const struct test winetest_testlist[] =
{
    { "DOMDocument", func_DOMDocument },
    { "SchemaCache", func_SchemaCache },
    { 0, 0 }
};
