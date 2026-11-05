/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test list for combase
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_ActivationFilter(void);
extern void func_ApartmentEndpoint(void);
extern void func_InprocLoadFailure(void);
extern void func_LocalServerStartup(void);
extern void func_RoFailFast(void);
extern void func_StubReleaseInCall(void);
extern void func_WireHandles(void);

const struct test winetest_testlist[] =
{
    { "ActivationFilter", func_ActivationFilter },
    { "ApartmentEndpoint", func_ApartmentEndpoint },
    { "InprocLoadFailure", func_InprocLoadFailure },
    { "LocalServerStartup", func_LocalServerStartup },
    { "RoFailFast", func_RoFailFast },
    { "StubReleaseInCall", func_StubReleaseInCall },
    { "WireHandles", func_WireHandles },

    { 0, 0 }
};
