/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test list for combase
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_ApartmentEndpoint(void);
extern void func_RoFailFast(void);

const struct test winetest_testlist[] =
{
    { "ApartmentEndpoint", func_ApartmentEndpoint },
    { "RoFailFast", func_RoFailFast },

    { 0, 0 }
};
