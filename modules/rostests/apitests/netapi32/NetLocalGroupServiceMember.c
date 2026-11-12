/*
 * PROJECT:     ReactOS netapi32.dll API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A virtual service account, NT SERVICE\<service>, as a member of a local group
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <sddl.h>
#include <lm.h>

/*
 * Oracle Database 21c adds the service SID of its services to the group ORA_<home>_SVCACCTS
 * with NetLocalGroupAddMembers, level 3, "NT SERVICE\<service>", and the group's access to the Oracle
 * directories is what the service runs with. The member the group lists is the service SID
 * S-1-5-80-a-b-c-d-e, five numbers after the 80. ReactOS built the SID from the domain SID (S-1-5-80) and
 * the last number, the one it kept as the relative id: S-1-5-80-e.
 */

START_TEST(NetLocalGroupServiceMember)
{
    static const WCHAR Group[] = L"apitest-svc-member-group";
    static const WCHAR Member[] = L"NT SERVICE\\EventLog";
    static const char Expected[] = "S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122";
    LOCALGROUP_INFO_0 Info;
    LOCALGROUP_MEMBERS_INFO_3 Add;
    LOCALGROUP_MEMBERS_INFO_0 *Members = NULL;
    DWORD Read = 0, Total = 0;
    NET_API_STATUS Status;
    LPSTR SidString = NULL;

    Info.lgrpi0_name = (LPWSTR)Group;
    NetLocalGroupDel(NULL, Group);
    Status = NetLocalGroupAdd(NULL, 0, (LPBYTE)&Info, NULL);
    if (Status != NERR_Success)
    {
        skip("NetLocalGroupAdd failed with %lu\n", Status);
        return;
    }

    Add.lgrmi3_domainandname = (LPWSTR)Member;
    Status = NetLocalGroupAddMembers(NULL, Group, 3, (LPBYTE)&Add, 1);
    ok(Status == NERR_Success, "NetLocalGroupAddMembers(%ls) returned %lu\n", Member, Status);

    Status = NetLocalGroupGetMembers(NULL, Group, 0, (LPBYTE *)&Members, MAX_PREFERRED_LENGTH, &Read, &Total, NULL);
    ok(Status == NERR_Success, "NetLocalGroupGetMembers returned %lu\n", Status);
    ok(Read == 1 && Total == 1, "%lu of %lu members\n", Read, Total);
    if (Status == NERR_Success && Read == 1)
    {
        ok(ConvertSidToStringSidA(Members[0].lgrmi0_sid, &SidString), "ConvertSidToStringSid failed\n");
        if (SidString)
        {
            ok(strcmp(SidString, Expected) == 0, "member SID %s, expected %s\n", SidString, Expected);
            LocalFree(SidString);
        }
    }
    if (Members)
        NetApiBufferFree(Members);

    /* once more: it is a member already */
    Status = NetLocalGroupAddMembers(NULL, Group, 3, (LPBYTE)&Add, 1);
    ok(Status == ERROR_MEMBER_IN_ALIAS, "second NetLocalGroupAddMembers returned %lu\n", Status);

    Status = NetLocalGroupDelMembers(NULL, Group, 3, (LPBYTE)&Add, 1);
    ok(Status == NERR_Success, "NetLocalGroupDelMembers returned %lu\n", Status);

    Status = NetLocalGroupDel(NULL, Group);
    ok(Status == NERR_Success, "NetLocalGroupDel returned %lu\n", Status);
}
