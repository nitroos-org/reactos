/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Test list
 * COPYRIGHT:   Copyright 2017 Colin Finck (colin@reactos.org)
 */

#define STANDALONE
#include <apitest.h>

extern void func_DavPaths(void);
extern void func_DsRoleGetPrimaryDomainInformation(void);
extern void func_NetApiLeak(void);
extern void func_NetEnum(void);
extern void func_NetGetAadJoinInformation(void);
extern void func_NetLocalGroup(void);
extern void func_NetLocalGroupServiceMember(void);
extern void func_NetLocalGroupUnknownMember(void);
extern void func_NetScheduleJob(void);
extern void func_NetServerGetInfo(void);
extern void func_NetUserPassword(void);
extern void func_NetShare(void);

const struct test winetest_testlist[] =
{
    { "DavPaths", func_DavPaths },
    { "DsRoleGetPrimaryDomainInformation", func_DsRoleGetPrimaryDomainInformation },
    { "NetApiLeak", func_NetApiLeak },
    { "NetEnum", func_NetEnum },
    { "NetGetAadJoinInformation", func_NetGetAadJoinInformation },
    { "NetLocalGroup", func_NetLocalGroup },
    { "NetLocalGroupServiceMember", func_NetLocalGroupServiceMember },
    { "NetLocalGroupUnknownMember", func_NetLocalGroupUnknownMember },
    { "NetScheduleJob", func_NetScheduleJob },
    { "NetServerGetInfo", func_NetServerGetInfo },
    { "NetShare", func_NetShare },
    { "NetUserPassword", func_NetUserPassword },

    { 0, 0 }
};
