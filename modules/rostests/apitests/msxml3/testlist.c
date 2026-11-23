/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_AttributeEntities(void);
extern void func_DOMDocument(void);
extern void func_SchemaCache(void);
extern void func_XPathFunc(void);

const struct test winetest_testlist[] =
{
    { "AttributeEntities", func_AttributeEntities },
    { "DOMDocument", func_DOMDocument },
    { "SchemaCache", func_SchemaCache },
    { "XPathFunc", func_XPathFunc },
    { 0, 0 }
};
