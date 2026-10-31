/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test list for secur32
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_AcquireCredentialsHandleVersions(void);
extern void func_InvalidHandles(void);
extern void func_LsaLogonContext(void);
extern void func_ReadConfigHandles(void);
extern void func_SchannelHandshake(void);
extern void func_SchannelServerCert(void);
extern void func_SetCredentialsAttributes(void);
extern void func_QueryContextAttributesEx(void);

const struct test winetest_testlist[] =
{
    { "AcquireCredentialsHandleVersions", func_AcquireCredentialsHandleVersions },
    { "InvalidHandles", func_InvalidHandles },
    { "LsaLogonContext", func_LsaLogonContext },
    { "ReadConfigHandles", func_ReadConfigHandles },
    { "SchannelHandshake", func_SchannelHandshake },
    { "SchannelServerCert", func_SchannelServerCert },
    { "SetCredentialsAttributes", func_SetCredentialsAttributes },

    { "QueryContextAttributesEx", func_QueryContextAttributesEx },
    { 0, 0 }
};
