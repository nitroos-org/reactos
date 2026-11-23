/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     AdjustTokenGroups changes the groups it names and no other
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Measured on a Windows Server 2022 reference (the token of a service process, a copy of the process token here):
 * disabling a group that is mandatory (the logon SID of a service, attributes 0xc0000007 or 0xc000000f) fails with
 * ERROR_CANT_DISABLE_MANDATORY (1310) and leaves the token as it was; enabling a group that is enabled succeeds and
 * leaves every group's attributes as they were; disabling and enabling a service SID (attributes 0xa and 0xe) succeeds.
 * The kernel used a stale attribute value for the groups the call did not name, so every group of the token (service
 * SIDs, the logon SID, the user's groups) showed the same arbitrary attributes afterwards.
 */

#include "precomp.h"

#define MAX_GROUPS 64

static DWORD
Attributes(HANDLE Token, PSID *Sids, DWORD *Attrs, DWORD Max)
{
    DWORD Size = 0, i;
    PTOKEN_GROUPS Groups;
    DWORD Count = 0;

    GetTokenInformation(Token, TokenGroups, NULL, 0, &Size);
    Groups = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Groups && GetTokenInformation(Token, TokenGroups, Groups, Size, &Size))
    {
        for (i = 0; i < Groups->GroupCount && i < Max; i++)
        {
            DWORD Len = GetLengthSid(Groups->Groups[i].Sid);

            Sids[i] = HeapAlloc(GetProcessHeap(), 0, Len);
            CopySid(Len, Sids[i], Groups->Groups[i].Sid);
            Attrs[i] = Groups->Groups[i].Attributes;
        }
        Count = min(Groups->GroupCount, Max);
    }
    if (Groups)
        HeapFree(GetProcessHeap(), 0, Groups);
    return Count;
}

static void
Free(PSID *Sids, DWORD Count)
{
    DWORD i;

    for (i = 0; i < Count; i++)
        HeapFree(GetProcessHeap(), 0, Sids[i]);
}

static void
CompareGroups(PCSTR Tag, HANDLE Token, PSID *Sids, DWORD *Attrs, DWORD Count)
{
    PSID Sids2[MAX_GROUPS];
    DWORD Attrs2[MAX_GROUPS], Count2, i;

    Count2 = Attributes(Token, Sids2, Attrs2, MAX_GROUPS);
    ok(Count2 == Count, "%s: %lu groups, expected %lu\n", Tag, Count2, Count);
    for (i = 0; i < Count && i < Count2; i++)
        ok(EqualSid(Sids[i], Sids2[i]) && Attrs[i] == Attrs2[i], "%s: group %lu has the attributes 0x%lx, expected 0x%lx\n",
           Tag, i, Attrs2[i], Attrs[i]);
    Free(Sids2, Count2);
}

START_TEST(AdjustTokenGroupsRows)
{
    HANDLE Process, Token = NULL;
    PSID Sids[MAX_GROUPS];
    DWORD Attrs[MAX_GROUPS], Count, i, Mandatory = MAXDWORD, Optional = MAXDWORD;
    TOKEN_GROUPS One;
    BOOL Ret;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &Process), "no process token (%lu)\n", GetLastError());
    ok(DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token),
       "no duplicate (%lu)\n", GetLastError());
    CloseHandle(Process);
    if (!Token)
        return;

    Count = Attributes(Token, Sids, Attrs, MAX_GROUPS);
    ok(Count > 1, "%lu groups\n", Count);
    for (i = 0; i < Count; i++)
    {
        if ((Attrs[i] & SE_GROUP_MANDATORY) && (Attrs[i] & SE_GROUP_ENABLED) && !(Attrs[i] & SE_GROUP_USE_FOR_DENY_ONLY) && Mandatory == MAXDWORD)
            Mandatory = i;
        if (!(Attrs[i] & SE_GROUP_MANDATORY) && (Attrs[i] & SE_GROUP_ENABLED) && !(Attrs[i] & SE_GROUP_USE_FOR_DENY_ONLY) && Optional == MAXDWORD)
            Optional = i;
    }

    /* enabling a group that is enabled: nothing changes, anywhere */
    if (Mandatory != MAXDWORD)
    {
        One.GroupCount = 1;
        One.Groups[0].Sid = Sids[Mandatory];
        One.Groups[0].Attributes = Attrs[Mandatory] | SE_GROUP_ENABLED;
        SetLastError(0xdeadbeef);
        Ret = AdjustTokenGroups(Token, FALSE, &One, 0, NULL, NULL);
        ok(Ret && GetLastError() == ERROR_SUCCESS, "enabling an enabled group: %d, error %lu\n", Ret, GetLastError());
        CompareGroups("enable an enabled group", Token, Sids, Attrs, Count);

        /* the groups are reset to what they are by default: those enabled by default are enabled, nothing else moves */
        Ret = AdjustTokenGroups(Token, TRUE, NULL, 0, NULL, NULL);
        ok(Ret, "resetting the groups failed (%lu)\n", GetLastError());
        {
            PSID Sids2[MAX_GROUPS];
            DWORD Attrs2[MAX_GROUPS], Count2;

            Count2 = Attributes(Token, Sids2, Attrs2, MAX_GROUPS);
            ok(Count2 == Count, "%lu groups after the reset, expected %lu\n", Count2, Count);
            for (i = 0; i < Count && i < Count2; i++)
            {
                DWORD Expected = Attrs[i];

                if ((Attrs[i] & SE_GROUP_ENABLED_BY_DEFAULT) && !(Attrs[i] & SE_GROUP_ENABLED))
                    Expected |= SE_GROUP_ENABLED;
                else if (!(Attrs[i] & SE_GROUP_ENABLED_BY_DEFAULT) && (Attrs[i] & SE_GROUP_ENABLED))
                    Expected &= ~SE_GROUP_ENABLED;
                ok(Attrs2[i] == Expected, "group %lu has the attributes 0x%lx after the reset, expected 0x%lx\n", i, Attrs2[i], Expected);
            }
            Free(Sids2, Count2);
        }

        /* a mandatory group cannot be disabled (the error measured for the logon SID of a service) */
        One.Groups[0].Attributes = Attrs[Mandatory] & ~SE_GROUP_ENABLED;
        SetLastError(0xdeadbeef);
        Ret = AdjustTokenGroups(Token, FALSE, &One, 0, NULL, NULL);
        ok(!Ret && GetLastError() == ERROR_CANT_DISABLE_MANDATORY, "disabling a mandatory group: %d, error %lu, expected 0 and %u\n",
           Ret, GetLastError(), ERROR_CANT_DISABLE_MANDATORY);
        CompareGroups("disable a mandatory group", Token, Sids, Attrs, Count);
    }
    else
        skip("The token has no mandatory enabled group\n");

    /* an optional group (a service SID, owner and default but not mandatory): disabled, then enabled; the others stay */
    if (Optional != MAXDWORD)
    {
        DWORD Moved[MAX_GROUPS];

        One.GroupCount = 1;
        One.Groups[0].Sid = Sids[Optional];
        One.Groups[0].Attributes = Attrs[Optional] & ~SE_GROUP_ENABLED;
        Ret = AdjustTokenGroups(Token, FALSE, &One, 0, NULL, NULL);
        ok(Ret, "disabling an optional group failed (%lu)\n", GetLastError());
        for (i = 0; i < Count; i++)
            Moved[i] = Attrs[i];
        Moved[Optional] = Attrs[Optional] & ~SE_GROUP_ENABLED;
        CompareGroups("disable an optional group", Token, Sids, Moved, Count);

        One.Groups[0].Attributes = Attrs[Optional];
        Ret = AdjustTokenGroups(Token, FALSE, &One, 0, NULL, NULL);
        ok(Ret, "enabling an optional group failed (%lu)\n", GetLastError());
        CompareGroups("enable an optional group", Token, Sids, Attrs, Count);
    }
    else
        skip("The token has no optional enabled group\n");

    Free(Sids, Count);
    CloseHandle(Token);
}
