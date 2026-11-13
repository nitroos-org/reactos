/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests for the NtFilterToken API
 * COPYRIGHT:       Copyright 2021 George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"

static
HANDLE
GetTokenProcess(VOID)
{
    BOOL Success;
    HANDLE Token;

    Success = OpenProcessToken(GetCurrentProcess(),
                               TOKEN_DUPLICATE | TOKEN_QUERY,
                               &Token);
    if (!Success)
    {
        skip("GetTokenProcess() has failed to get the process' token (error code: %lu)!\n", GetLastError());
        return NULL;
    }

    return Token;
}

/*
 * Contract for T125: a SID named in SidsToDisable must actually be disabled
 * (turned deny-only) in the filtered token. The group-matching RtlEqualSid in
 * SepPerformTokenFiltering used to be passed the address of the SID pointer
 * (&...Sid) instead of the SID, so it never matched and filtering was a silent
 * no-op: the SID stayed enabled. Everyone (S-1-1-0) is present and enabled in
 * every token, so it is a reliable target.
 */
static
VOID
TestSidToDisableIsDisabled(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    HANDLE FilteredToken = NULL;
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    PSID EveryoneSid;
    BYTE SidsBuffer[sizeof(TOKEN_GROUPS)];
    PTOKEN_GROUPS SidsToDisable = (PTOKEN_GROUPS)SidsBuffer;
    BYTE GroupsBuffer[4096];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)GroupsBuffer;
    ULONG Length, i;
    BOOLEAN Found = FALSE;

    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0, &EveryoneSid);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to build the Everyone SID (0x%lx)\n", Status);
        return;
    }

    SidsToDisable->GroupCount = 1;
    SidsToDisable->Groups[0].Sid = EveryoneSid;
    SidsToDisable->Groups[0].Attributes = 0;

    Status = NtFilterToken(Token, 0, SidsToDisable, NULL, NULL, &FilteredToken);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeSid(EveryoneSid);
        return;
    }

    Status = NtQueryInformationToken(FilteredToken, TokenGroups, Groups, sizeof(GroupsBuffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if (RtlEqualSid(Groups->Groups[i].Sid, EveryoneSid))
            {
                Found = TRUE;
                ok(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY,
                   "Everyone must be deny-only after filtering, attributes = 0x%lx\n",
                   Groups->Groups[i].Attributes);
                ok(!(Groups->Groups[i].Attributes & SE_GROUP_ENABLED),
                   "Everyone must not be enabled after filtering, attributes = 0x%lx\n",
                   Groups->Groups[i].Attributes);
                break;
            }
        }
        ok(Found, "Everyone SID must still be present in the filtered token\n");
    }

    RtlFreeSid(EveryoneSid);
    CloseHandle(FilteredToken);
}

/*
 * The restricting SID list is optional: no list means no restriction, a list
 * with a SID makes the token restricted with that SID.
 */
static
VOID
TestRestrictingSids(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    HANDLE FilteredToken = NULL;
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    PSID EveryoneSid;
    BYTE SidsBuffer[sizeof(TOKEN_GROUPS)];
    PTOKEN_GROUPS Restrict = (PTOKEN_GROUPS)SidsBuffer;
    BYTE GroupsBuffer[1024];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)GroupsBuffer;
    ULONG Length, IsRestricted;

    Status = NtFilterToken(Token, 0, NULL, NULL, NULL, &FilteredToken);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        IsRestricted = 0xDEAD;
        Status = NtQueryInformationToken(FilteredToken, TokenIsRestricted, &IsRestricted, sizeof(IsRestricted), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_int(IsRestricted, 0);
        Status = NtQueryInformationToken(FilteredToken, TokenRestrictedSids, Groups, sizeof(GroupsBuffer), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_int(Groups->GroupCount, 0);
        CloseHandle(FilteredToken);
    }

    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0, &EveryoneSid);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to build the Everyone SID (0x%lx)\n", Status);
        return;
    }

    Restrict->GroupCount = 1;
    Restrict->Groups[0].Sid = EveryoneSid;
    Restrict->Groups[0].Attributes = 0;
    FilteredToken = NULL;
    Status = NtFilterToken(Token, 0, NULL, NULL, Restrict, &FilteredToken);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        IsRestricted = 0xDEAD;
        Status = NtQueryInformationToken(FilteredToken, TokenIsRestricted, &IsRestricted, sizeof(IsRestricted), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_int(IsRestricted, 1);
        Status = NtQueryInformationToken(FilteredToken, TokenRestrictedSids, Groups, sizeof(GroupsBuffer), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_int(Groups->GroupCount, 1);
        CloseHandle(FilteredToken);
    }

    RtlFreeSid(EveryoneSid);
}

START_TEST(NtFilterToken)
{
    NTSTATUS Status;
    HANDLE FilteredToken, Token;
    TOKEN_PRIVILEGES Priv;
    ULONG Size;
    PTOKEN_STATISTICS TokenStats;

    /* We don't give a token */
    Status = NtFilterToken(NULL,
                           0,
                           NULL,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_hex(Status, STATUS_INVALID_HANDLE);

    /* Get the token from process now */
    Token = GetTokenProcess();

    /* We don't give any privileges to delete */
    Status = NtFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_hex(Status, STATUS_SUCCESS);

    /* Query the total size to hold the statistics */
    Status = NtQueryInformationToken(Token, TokenStatistics, NULL, 0, &Size);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL)
    {
        skip("Failed to query the total size for token statistics structure! (Status -> 0x%lx)\n", Status);
        return;
    }

    /* Total size queried, time to allocate our buffer based on that size */
    TokenStats = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (TokenStats == NULL)
    {
        skip("Failed to allocate our token statistics buffer!\n");
        return;
    }

    /* Time to query our token statistics, prior disabling token's privileges */
    Status = NtQueryInformationToken(Token, TokenStatistics, TokenStats, Size, &Size);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to query the token statistics! (Status -> 0x%lx)\n", Status);
        return;
    }

    trace("Number of privileges before token filtering -- %lu\n\n", TokenStats->PrivilegeCount);

    /* Disable the privileges and make the token a safer inert one */
    Status = NtFilterToken(Token,
                           DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
                           NULL,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_hex(Status, STATUS_SUCCESS);

    /* We've disabled privileges, query the stats again */
    Status = NtQueryInformationToken(FilteredToken, TokenStatistics, TokenStats, Size, &Size);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to query the token statistics! (Status -> 0x%lx)\n", Status);
        return;
    }

    trace("Number of privileges after token filtering (privileges disabled with DISABLE_MAX_PRIVILEGE) -- %lu\n\n", TokenStats->PrivilegeCount);

    /* Close the filtered token and do another test */
    CloseHandle(FilteredToken);

    /* Fill in a privilege to delete */
    Priv.PrivilegeCount = 1;

    Priv.Privileges[0].Luid = RtlConvertUlongToLuid(SE_BACKUP_PRIVILEGE);
    Priv.Privileges[0].Attributes = 0;

    /* Delete the privileges */
    Status = NtFilterToken(Token,
                           0,
                           NULL,
                           &Priv,
                           NULL,
                           &FilteredToken);
    ok_hex(Status, STATUS_SUCCESS);

    /* We've deleted a privilege, query the stats again */
    Status = NtQueryInformationToken(FilteredToken, TokenStatistics, TokenStats, Size, &Size);
    if (!NT_SUCCESS(Status))
    {
        skip("Failed to query the token statistics! (Status -> 0x%lx)\n", Status);
        return;
    }

    trace("Number of privileges after token filtering (manually deleted privilege) -- %lu\n\n", TokenStats->PrivilegeCount);

    /* T125 contract: disabling a SID must actually turn it deny-only */
    TestSidToDisableIsDisabled(Token);

    TestRestrictingSids(Token);

    /* We're done */
    RtlFreeHeap(RtlGetProcessHeap(), 0, TokenStats);
    CloseHandle(Token);
    CloseHandle(FilteredToken);
}
