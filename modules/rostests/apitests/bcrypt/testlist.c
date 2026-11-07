/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_BCryptDeriveKey(void);
extern void func_BCryptKeyExport(void);
extern void func_BCryptEccPublicKey(void);

const struct test winetest_testlist[] =
{
    { "BCryptDeriveKey", func_BCryptDeriveKey },
    { "BCryptKeyExport", func_BCryptKeyExport },
    { "BCryptEccPublicKey", func_BCryptEccPublicKey },

    { 0, 0 }
};
