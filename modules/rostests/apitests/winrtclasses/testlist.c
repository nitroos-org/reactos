/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test list for winrtclasses_apitest
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_NetworkInformation(void);
extern void func_OnlineIdSystemAuthenticator(void);
extern void func_Language(void);
extern void func_OnlineIdServiceTicketRequest(void);
extern void func_PropertyValue(void);

const struct test winetest_testlist[] =
{
    { "NetworkInformation", func_NetworkInformation },
    { "OnlineIdSystemAuthenticator", func_OnlineIdSystemAuthenticator },
    { "Language", func_Language },
    { "OnlineIdServiceTicketRequest", func_OnlineIdServiceTicketRequest },
    { "PropertyValue", func_PropertyValue },
    { 0, 0 }
};
