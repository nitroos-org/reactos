/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test list for ncrypt
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_SecretAgreement(void);

const struct test winetest_testlist[] =
{
    { "SecretAgreement", func_SecretAgreement },

    { 0, 0 }
};
