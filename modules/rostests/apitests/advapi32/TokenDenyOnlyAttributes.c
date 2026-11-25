/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The attributes of a group that CreateRestrictedToken made deny-only
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (build 20348) with the token of an administrator: Everyone and Users (attributes 0x7)
 * and Administrators (0xf) become exactly SE_GROUP_USE_FOR_DENY_ONLY (0x10), also the mandatory and owner bits go,
 * and a group that is deny-only already stays 0x10. Groups that were not named keep their attributes.
 */

#include "precomp.h"

static BOOL GroupAttributes(HANDLE hToken, PSID Sid, DWORD *Attributes)
{
    BYTE Buffer[8192];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(hToken, TokenGroups, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if (EqualSid(Groups->Groups[i].Sid, Sid))
        {
            *Attributes = Groups->Groups[i].Attributes;
            return TRUE;
        }
    }
    return FALSE;
}

static HANDLE DenyOnly(HANDLE hToken, PSID *Sids, ULONG Count)
{
    SID_AND_ATTRIBUTES Disable[3];
    HANDLE hNew = NULL;
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        Disable[i].Sid = Sids[i];
        Disable[i].Attributes = 0;
    }
    if (!CreateRestrictedToken(hToken, 0, Count, Disable, 0, NULL, 0, NULL, &hNew))
        return NULL;
    return hNew;
}

START_TEST(TokenDenyOnlyAttributes)
{
    BYTE EveryoneBuffer[SECURITY_MAX_SID_SIZE], UsersBuffer[SECURITY_MAX_SID_SIZE], AdminsBuffer[SECURITY_MAX_SID_SIZE];
    DWORD Size, Before, After;
    PSID Sids[3] = { EveryoneBuffer, UsersBuffer, AdminsBuffer };
    HANDLE hToken = NULL, hFirst, hSecond;
    ULONG i;

    Size = sizeof(EveryoneBuffer);
    CreateWellKnownSid(WinWorldSid, NULL, EveryoneBuffer, &Size);
    Size = sizeof(UsersBuffer);
    CreateWellKnownSid(WinBuiltinUsersSid, NULL, UsersBuffer, &Size);
    Size = sizeof(AdminsBuffer);
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminsBuffer, &Size);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        skip("OpenProcessToken: %lu\n", GetLastError());
        return;
    }

    hFirst = DenyOnly(hToken, Sids, 3);
    ok(hFirst != NULL, "CreateRestrictedToken: %lu\n", GetLastError());
    if (!hFirst)
    {
        CloseHandle(hToken);
        return;
    }

    for (i = 0; i < 3; i++)
    {
        if (!GroupAttributes(hToken, Sids[i], &Before) || (Before & SE_GROUP_USE_FOR_DENY_ONLY))
        {
            skip("group %lu is not in the token or deny-only already\n", i);
            continue;
        }
        ok(GroupAttributes(hFirst, Sids[i], &After), "group %lu: not in the new token\n", i);
        ok(After == SE_GROUP_USE_FOR_DENY_ONLY, "group %lu: attributes 0x%lx (were 0x%lx), expected 0x10\n", i, After, Before);
    }

    /* once more: nothing changes */
    hSecond = DenyOnly(hFirst, Sids, 3);
    ok(hSecond != NULL, "second CreateRestrictedToken: %lu\n", GetLastError());
    if (hSecond)
    {
        for (i = 0; i < 3; i++)
        {
            if (GroupAttributes(hSecond, Sids[i], &After))
                ok(After == SE_GROUP_USE_FOR_DENY_ONLY, "group %lu again: attributes 0x%lx\n", i, After);
        }
        CloseHandle(hSecond);
    }

    /* a group that was not named is left alone */
    {
        PSID Only[1] = { UsersBuffer };
        DWORD EveryoneBefore, EveryoneAfter;
        HANDLE hOne = DenyOnly(hToken, Only, 1);

        ok(hOne != NULL, "CreateRestrictedToken(Users): %lu\n", GetLastError());
        if (hOne)
        {
            if (GroupAttributes(hToken, EveryoneBuffer, &EveryoneBefore) && GroupAttributes(hOne, EveryoneBuffer, &EveryoneAfter))
                ok(EveryoneBefore == EveryoneAfter, "Everyone changed: 0x%lx to 0x%lx\n", EveryoneBefore, EveryoneAfter);
            CloseHandle(hOne);
        }
    }

    CloseHandle(hFirst);
    CloseHandle(hToken);
}
