/*
 * PROJECT:         ReactOS API tests
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Tests for the NtQueryInformationToken API
 * COPYRIGHT:       Copyright 2022 George Bișoc <george.bisoc@reactos.org>
 */

#include "precomp.h"

static
HANDLE
OpenCurrentToken(VOID)
{
    BOOL Success;
    HANDLE Token;

    Success = OpenProcessToken(GetCurrentProcess(),
                               TOKEN_READ | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,
                               &Token);
    if (!Success)
    {
        ok(FALSE, "OpenProcessToken() has failed to get the process' token (error code: %lu)!\n", GetLastError());
        return NULL;
    }

    return Token;
}

static
VOID
QueryTokenUserTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_USER UserToken;
    ULONG BufferLength;
    UNICODE_STRING SidString;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenUser,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    UserToken = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!UserToken)
    {
        ok(FALSE, "Failed to allocate from heap for token user (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /* Now do the actual query */
    Status = NtQueryInformationToken(Token,
                                     TokenUser,
                                     UserToken,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    RtlConvertSidToUnicodeString(&SidString, UserToken->User.Sid, TRUE);
    trace("=============== TokenUser ===============\n");
    trace("The SID of current token user is: %s\n", wine_dbgstr_w(SidString.Buffer));
    trace("=========================================\n\n");
    RtlFreeUnicodeString(&SidString);

    RtlFreeHeap(RtlGetProcessHeap(), 0, UserToken);
}

static
VOID
QueryTokenGroupsTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_GROUPS Groups;
    ULONG BufferLength;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenGroups,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    Groups = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Groups)
    {
        ok(FALSE, "Failed to allocate from heap for token groups (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /*
     * Now do the actual query and validate the
     * number of groups.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenGroups,
                                     Groups,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Groups->GroupCount == 10, "The number of groups must be 10 (current number %lu)!\n", Groups->GroupCount);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Groups);
}

#ifndef SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE 36
#endif

/* The privileges an administrator's token holds (Administrators, Users and Everyone in defltwk.inf) */
static const ULONG AdminPrivileges[] =
{
    SE_INCREASE_QUOTA_PRIVILEGE,
    SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
    SE_LOAD_DRIVER_PRIVILEGE,
    SE_SYSTEM_PROFILE_PRIVILEGE,
    SE_SYSTEMTIME_PRIVILEGE,
    SE_PROF_SINGLE_PROCESS_PRIVILEGE,
    SE_INC_BASE_PRIORITY_PRIVILEGE,
    SE_CREATE_PAGEFILE_PRIVILEGE,
    SE_BACKUP_PRIVILEGE,
    SE_RESTORE_PRIVILEGE,
    SE_SHUTDOWN_PRIVILEGE,
    SE_DEBUG_PRIVILEGE,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    SE_CHANGE_NOTIFY_PRIVILEGE,
    SE_REMOTE_SHUTDOWN_PRIVILEGE,
    SE_UNDOCK_PRIVILEGE,
    SE_MANAGE_VOLUME_PRIVILEGE,
    SE_IMPERSONATE_PRIVILEGE,
    SE_CREATE_GLOBAL_PRIVILEGE,
    SE_TIME_ZONE_PRIVILEGE,
};

/* Granted to administrators by Windows' default policy only */
static const ULONG WindowsOnlyAdminPrivileges[] =
{
    SE_INC_WORKING_SET_PRIVILEGE,
    SE_CREATE_SYMBOLIC_LINK_PRIVILEGE,
    SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE,
};

static
PLUID_AND_ATTRIBUTES
FindPrivilege(
    _In_ PTOKEN_PRIVILEGES Privileges,
    _In_ ULONG Privilege)
{
    ULONG i;

    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.HighPart == 0 &&
            Privileges->Privileges[i].Luid.LowPart == Privilege)
        {
            return &Privileges->Privileges[i];
        }
    }

    return NULL;
}

static
VOID
QueryTokenPrivilegesTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_PRIVILEGES Privileges;
    PLUID_AND_ATTRIBUTES Entry;
    ULONG BufferLength;
    ULONG i, Known;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenPrivileges,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    Privileges = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Privileges)
    {
        ok(FALSE, "Failed to allocate from heap for token privileges (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /*
     * Now do the actual query and validate the
     * privileges an administrator holds.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenPrivileges,
                                     Privileges,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Privileges);
        return;
    }

    for (i = 0; i < _countof(AdminPrivileges); i++)
    {
        ok(FindPrivilege(Privileges, AdminPrivileges[i]) != NULL,
           "Privilege %lu is missing from the token\n", AdminPrivileges[i]);
    }

    Known = _countof(AdminPrivileges);
    for (i = 0; i < _countof(WindowsOnlyAdminPrivileges); i++)
    {
        if (FindPrivilege(Privileges, WindowsOnlyAdminPrivileges[i]))
            Known++;
    }

    /* Each privilege appears once, so a larger count means a privilege the tables do not list */
    ok(Privileges->PrivilegeCount == Known,
       "The token holds %lu privileges, expected %lu\n", Privileges->PrivilegeCount, Known);

    /* Held but disabled, as on Windows; changing the time zone enables it first */
    Entry = FindPrivilege(Privileges, SE_TIME_ZONE_PRIVILEGE);
    if (Entry)
    {
        ok((Entry->Attributes & SE_PRIVILEGE_ENABLED) == 0,
           "SeTimeZonePrivilege is enabled (attributes 0x%lx)\n", Entry->Attributes);
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, Privileges);
}

static
VOID
QueryTokenOwnerTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_OWNER Owner;
    ULONG BufferLength;
    UNICODE_STRING SidString;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenOwner,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    Owner = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Owner)
    {
        ok(FALSE, "Failed to allocate from heap for token owner (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /*
     * Now do the actual query and validate the
     * token owner (must be the local admin).
     */
    Status = NtQueryInformationToken(Token,
                                     TokenOwner,
                                     Owner,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    RtlConvertSidToUnicodeString(&SidString, Owner->Owner, TRUE);
    ok_wstr(SidString.Buffer, L"S-1-5-32-544");
    RtlFreeUnicodeString(&SidString);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Owner);
}

static
VOID
QueryTokenPrimaryGroupTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_PRIMARY_GROUP PrimaryGroup;
    ULONG BufferLength;
    UNICODE_STRING SidString;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenPrimaryGroup,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    PrimaryGroup = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!PrimaryGroup)
    {
        ok(FALSE, "Failed to allocate from heap for token primary group (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /* Now do the actual query */
    Status = NtQueryInformationToken(Token,
                                     TokenPrimaryGroup,
                                     PrimaryGroup,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    RtlConvertSidToUnicodeString(&SidString, PrimaryGroup->PrimaryGroup, TRUE);
    trace("=============== TokenPrimaryGroup ===============\n");
    trace("The primary group SID of current token is: %s\n", wine_dbgstr_w(SidString.Buffer));
    trace("=========================================\n\n");
    RtlFreeUnicodeString(&SidString);

    RtlFreeHeap(RtlGetProcessHeap(), 0, PrimaryGroup);
}

static
VOID
QueryTokenDefaultDaclTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_DEFAULT_DACL Dacl;
    ULONG BufferLength;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenDefaultDacl,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    Dacl = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Dacl)
    {
        ok(FALSE, "Failed to allocate from heap for token default DACL (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /*
     * Now do the actual query and validate the
     * ACL revision and number count of ACEs.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenDefaultDacl,
                                     Dacl,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Dacl->DefaultDacl->AclRevision == 2, "The ACL revision of token default DACL must be 2 (current revision %u)!\n", Dacl->DefaultDacl->AclRevision);
    ok(Dacl->DefaultDacl->AceCount == 2, "The ACL's ACE count must be 2 (current ACE count %u)!\n", Dacl->DefaultDacl->AceCount);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);
}

static
VOID
QueryTokenSourceTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_SOURCE Source;
    ULONG BufferLength;
    CHAR SourceName[8];

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenSource,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    Source = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Source)
    {
        ok(FALSE, "Failed to allocate from heap for token source (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /* Now do the actual query */
    Status = NtQueryInformationToken(Token,
                                     TokenSource,
                                     Source,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    /*
     * Subtract the source name from the queried buffer
     * and compare it. The source name in question must be
     * "User32" as the primary token of the current calling
     * process is generated when the user has successfully
     * logged in and he's into the desktop.
     */
    SourceName[0] = Source->SourceName[0];
    SourceName[1] = Source->SourceName[1];
    SourceName[2] = Source->SourceName[2];
    SourceName[3] = Source->SourceName[3];
    SourceName[4] = Source->SourceName[4];
    SourceName[5] = Source->SourceName[5];
    SourceName[6] = '\0';
    ok_str(SourceName, "User32");

    RtlFreeHeap(RtlGetProcessHeap(), 0, Source);
}

static
VOID
QueryTokenTypeTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    TOKEN_TYPE Type;
    ULONG BufferLength;

    /*
     * Query the token type. The token of the
     * current calling process must be primary
     * since we aren't impersonating the security
     * context of a client.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenType,
                                     &Type,
                                     sizeof(TOKEN_TYPE),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Type == TokenPrimary, "The current token is not primary!\n");
}

static
VOID
QueryTokenImpersonationTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    SECURITY_IMPERSONATION_LEVEL Level;
    ULONG BufferLength;
    HANDLE DupToken;
    OBJECT_ATTRIBUTES ObjectAttributes;

    /*
     * Windows throws STATUS_INVALID_INFO_CLASS here
     * because one cannot simply query the impersonation
     * level of a primary token.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenImpersonationLevel,
                                     &Level,
                                     sizeof(SECURITY_IMPERSONATION_LEVEL),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);

    /*
     * Initialize the object attribute and duplicate
     * the token into an actual impersonation one.
     */
    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               0,
                               NULL,
                               NULL);

    Status = NtDuplicateToken(Token,
                              TOKEN_QUERY,
                              &ObjectAttributes,
                              FALSE,
                              TokenImpersonation,
                              &DupToken);
    if (!NT_SUCCESS(Status))
    {
        ok(FALSE, "Failed to duplicate token (Status code %lx)!\n", Status);
        return;
    }

    /* Now do the actual query */
    Status = NtQueryInformationToken(DupToken,
                                     TokenImpersonationLevel,
                                     &Level,
                                     sizeof(SECURITY_IMPERSONATION_LEVEL),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Level == SecurityAnonymous, "The current token impersonation level is not anonymous!\n");
    NtClose(DupToken);
}

static
VOID
QueryTokenStatisticsTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_STATISTICS Statistics;
    ULONG BufferLength;

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenStatistics,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    Statistics = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!Statistics)
    {
        ok(FALSE, "Failed to allocate from heap for token statistics (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /* Do the actual query */
    Status = NtQueryInformationToken(Token,
                                     TokenStatistics,
                                     Statistics,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    trace("=============== TokenStatistics ===============\n");
    trace("Token ID: %lu %lu\n", Statistics->TokenId.LowPart, Statistics->TokenId.HighPart);
    trace("Authentication ID: %lu %lu\n", Statistics->AuthenticationId.LowPart, Statistics->AuthenticationId.HighPart);
    trace("Dynamic Charged: %lu\n", Statistics->DynamicCharged);
    trace("Dynamic Available: %lu\n", Statistics->DynamicAvailable);
    trace("Modified ID: %lu %lu\n", Statistics->ModifiedId.LowPart, Statistics->ModifiedId.HighPart);
    trace("=========================================\n\n");

    RtlFreeHeap(RtlGetProcessHeap(), 0, Statistics);
}

static
VOID
QueryTokenPrivilegesAndGroupsTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_GROUPS_AND_PRIVILEGES PrivsAndGroups;
    TOKEN_GROUPS SidToRestrict;
    HANDLE FilteredToken;
    PSID WorldSid;
    ULONG BufferLength;
    static SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};

    /*
     * Create a World SID and filter the token
     * by adding a restricted SID.
     */
    Status = RtlAllocateAndInitializeSid(&WorldAuthority,
                                         1,
                                         SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &WorldSid);
    if (!NT_SUCCESS(Status))
    {
        ok(FALSE, "Failed to allocate World SID (Status code %lx)!\n", Status);
        return;
    }

    SidToRestrict.GroupCount = 1;
    SidToRestrict.Groups[0].Attributes = 0;
    SidToRestrict.Groups[0].Sid = WorldSid;

    Status = NtFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           &SidToRestrict,
                           &FilteredToken);
    if (!NT_SUCCESS(Status))
    {
        ok(FALSE, "Failed to filter the current token (Status code %lx)!\n", Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, WorldSid);
        return;
    }

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(FilteredToken,
                                     TokenGroupsAndPrivileges,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    PrivsAndGroups = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!PrivsAndGroups)
    {
        ok(FALSE, "Failed to allocate from heap for token privileges and groups (required buffer length %lu)!\n", BufferLength);
        RtlFreeHeap(RtlGetProcessHeap(), 0, WorldSid);
        NtClose(FilteredToken);
        return;
    }

    /* Do the actual query */
    Status = NtQueryInformationToken(FilteredToken,
                                     TokenGroupsAndPrivileges,
                                     PrivsAndGroups,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);

    trace("=============== TokenGroupsAndPrivileges ===============\n");
    trace("SID count: %lu\n", PrivsAndGroups->SidCount);
    trace("SID length: %lu\n", PrivsAndGroups->SidLength);
    trace("Restricted SID count: %lu\n", PrivsAndGroups->RestrictedSidCount);
    trace("Restricted SID length: %lu\n", PrivsAndGroups->RestrictedSidLength);
    trace("Privilege count: %lu\n", PrivsAndGroups->PrivilegeCount);
    trace("Privilege length: %lu\n", PrivsAndGroups->PrivilegeLength);
    trace("Authentication ID: %lu %lu\n", PrivsAndGroups->AuthenticationId.LowPart, PrivsAndGroups->AuthenticationId.HighPart);
    trace("=========================================\n\n");

    RtlFreeHeap(RtlGetProcessHeap(), 0, PrivsAndGroups);
    RtlFreeHeap(RtlGetProcessHeap(), 0, WorldSid);
    NtClose(FilteredToken);
}

static
VOID
QueryTokenRestrictedSidsTest(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    PTOKEN_GROUPS RestrictedGroups;
    TOKEN_GROUPS SidToRestrict;
    ULONG BufferLength;
    HANDLE FilteredToken;
    PSID WorldSid;
    static SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};

    /*
     * Query the exact buffer length to hold
     * our stuff, STATUS_BUFFER_TOO_SMALL must
     * be expected here.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenRestrictedSids,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    /* Allocate the buffer based on the size we got */
    RestrictedGroups = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!RestrictedGroups)
    {
        ok(FALSE, "Failed to allocate from heap for restricted SIDs (required buffer length %lu)!\n", BufferLength);
        return;
    }

    /*
     * Query the number of restricted SIDs. Originally the token
     * doesn't have any restricted SIDs inserted.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenRestrictedSids,
                                     RestrictedGroups,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(RestrictedGroups->GroupCount == 0, "There mustn't be any restricted SIDs before filtering (number of restricted SIDs %lu)!\n", RestrictedGroups->GroupCount);

    RtlFreeHeap(RtlGetProcessHeap(), 0, RestrictedGroups);
    RestrictedGroups = NULL;

    Status = RtlAllocateAndInitializeSid(&WorldAuthority,
                                         1,
                                         SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0,
                                         &WorldSid);
    if (!NT_SUCCESS(Status))
    {
        ok(FALSE, "Failed to allocate World SID (Status code %lx)!\n", Status);
        return;
    }

    SidToRestrict.GroupCount = 1;
    SidToRestrict.Groups[0].Attributes = 0;
    SidToRestrict.Groups[0].Sid = WorldSid;

    Status = NtFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           &SidToRestrict,
                           &FilteredToken);
    if (!NT_SUCCESS(Status))
    {
        ok(FALSE, "Failed to filter the current token (Status code %lx)!\n", Status);
        RtlFreeHeap(RtlGetProcessHeap(), 0, WorldSid);
        return;
    }

    Status = NtQueryInformationToken(FilteredToken,
                                     TokenRestrictedSids,
                                     NULL,
                                     0,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);

    RestrictedGroups = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferLength);
    if (!RestrictedGroups)
    {
        ok(FALSE, "Failed to allocate from heap for restricted SIDs (required buffer length %lu)!\n", BufferLength);
        RtlFreeHeap(RtlGetProcessHeap(), 0, WorldSid);
        return;
    }

    /*
     * Do a query again, this time we must have a
     * restricted SID inserted into the token.
     */
    Status = NtQueryInformationToken(FilteredToken,
                                     TokenRestrictedSids,
                                     RestrictedGroups,
                                     BufferLength,
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(RestrictedGroups->GroupCount == 1, "There must be only one restricted SID added in token (number of restricted SIDs %lu)!\n", RestrictedGroups->GroupCount);

    RtlFreeHeap(RtlGetProcessHeap(), 0, RestrictedGroups);
    RtlFreeHeap(RtlGetProcessHeap(), 0, WorldSid);
    NtClose(FilteredToken);
}

static
VOID
QueryTokenSessionIdTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    ULONG SessionId;
    ULONG BufferLength;

    /*
     * Query the session ID. Generally the current
     * process token is not under any terminal service
     * so the ID must be 0.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenSessionId,
                                     &SessionId,
                                     sizeof(ULONG),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(SessionId == 0, "The session ID of current token must be 0 (current session %lu)!\n", SessionId);
}

static
VOID
QueryTokenIsSandboxInert(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    ULONG IsTokenInert;
    ULONG BufferLength;
    HANDLE FilteredToken;

    /*
     * Query the sandbox inert token information,
     * it must not be inert.
     */
    Status = NtQueryInformationToken(Token,
                                     TokenSandBoxInert,
                                     &IsTokenInert,
                                     sizeof(ULONG),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(IsTokenInert == FALSE, "The token must not be a sandbox inert one!\n");

    /*
     * Try to turn the token into an inert
     * one by filtering it.
     */
    Status = NtFilterToken(Token,
                           SANDBOX_INERT,
                           NULL,
                           NULL,
                           NULL,
                           &FilteredToken);
    if (!NT_SUCCESS(Status))
    {
        ok(FALSE, "Failed to filter the current token (Status code %lx)!\n", Status);
        return;
    }

    /*
     * Now do a query again, this time
     * the token should be inert.
     */
    Status = NtQueryInformationToken(FilteredToken,
                                     TokenSandBoxInert,
                                     &IsTokenInert,
                                     sizeof(ULONG),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(IsTokenInert == TRUE, "The token must be a sandbox inert one after filtering!\n");

    NtClose(FilteredToken);
}

static
VOID
QueryTokenOriginTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    TOKEN_ORIGIN Origin;
    ULONG BufferLength;

    /* Query the token origin */
    Status = NtQueryInformationToken(Token,
                                     TokenOrigin,
                                     &Origin,
                                     sizeof(TOKEN_ORIGIN),
                                     &BufferLength);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Origin.OriginatingLogonSession.LowPart == 0x3e7, "The LowPart field of the originating logon session must be SYSTEM_LUID (current value %lu)!\n",
       Origin.OriginatingLogonSession.LowPart);
    ok(Origin.OriginatingLogonSession.HighPart == 0x0, "The HighPart field of the logon session must be 0 (current value %lu)!\n",
       Origin.OriginatingLogonSession.HighPart);
}

/*
 * Elevation queries (T121). Burn/WiX read TokenElevation and TokenElevationType;
 * both used to fail with STATUS_INVALID_INFO_CLASS (GetTokenInformation: error 87).
 *
 * ReactOS has no UAC, so the expectations are those of Windows with UAC off
 * (EnableLUA = 0, measured on Windows 10 22H2): TokenElevationType is always
 * TokenElevationTypeDefault, whatever the groups, privileges and integrity level;
 * TokenElevation is 1 when the Administrators group is in the token and not
 * deny-only, or when the token holds one of the privileges below.
 */
static
BOOLEAN
TokenHoldsElevatingPrivilege(
    _In_ HANDLE Token,
    _In_ BOOLEAN IncludeImpersonate)
{
    static const ULONG Elevating[] =
    {
        SE_CREATE_TOKEN_PRIVILEGE, SE_TCB_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE,
        SE_LOAD_DRIVER_PRIVILEGE, SE_BACKUP_PRIVILEGE, SE_RESTORE_PRIVILEGE,
        SE_DEBUG_PRIVILEGE, SE_IMPERSONATE_PRIVILEGE, SE_RELABEL_PRIVILEGE
    };
    BYTE Buffer[2048];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    ULONG Length, i, j;

    if (!NT_SUCCESS(NtQueryInformationToken(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length)))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        for (j = 0; j < RTL_NUMBER_OF(Elevating); j++)
        {
            if (Privileges->Privileges[i].Luid.HighPart == 0 &&
                Privileges->Privileges[i].Luid.LowPart == Elevating[j] &&
                (IncludeImpersonate || Elevating[j] != SE_IMPERSONATE_PRIVILEGE))
                return TRUE;
        }
    }
    return FALSE;
}

static
BOOLEAN
TokenHasEnabledAdminGroup(
    _In_ HANDLE Token)
{
    BYTE Buffer[4096];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    ULONG Length, i;
    PSID AdminSid;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    BOOLEAN Result = FALSE;

    if (!NT_SUCCESS(NtQueryInformationToken(Token, TokenGroups, Groups, sizeof(Buffer), &Length)))
        return FALSE;
    if (!NT_SUCCESS(RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid)))
        return FALSE;
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if (RtlEqualSid(Groups->Groups[i].Sid, AdminSid) &&
            !(Groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
            Result = TRUE;
    }
    RtlFreeSid(AdminSid);
    return Result;
}

static
VOID
CheckElevation(
    _In_ HANDLE Token,
    _In_ PCSTR Name,
    _In_ ULONG ExpectedElevated,
    _In_ ULONG ExpectedType)
{
    NTSTATUS Status;
    TOKEN_ELEVATION Elevation;
    TOKEN_ELEVATION_TYPE Type;
    ULONG Length;

    Elevation.TokenIsElevated = 0xDEADBEEF;
    Status = NtQueryInformationToken(Token, TokenElevation, &Elevation, sizeof(Elevation), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_dec(Length, (ULONG)sizeof(TOKEN_ELEVATION));
    ok(Elevation.TokenIsElevated == ExpectedElevated,
       "%s: TokenIsElevated = %lu, expected %lu\n", Name, Elevation.TokenIsElevated, ExpectedElevated);

    Type = 0;
    Status = NtQueryInformationToken(Token, TokenElevationType, &Type, sizeof(Type), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_dec(Length, (ULONG)sizeof(TOKEN_ELEVATION_TYPE));
    ok(Type == ExpectedType, "%s: TokenElevationType = %d, expected %lu\n", Name, Type, ExpectedType);

    trace("%s: IsElevated=%lu Type=%d\n", Name, Elevation.TokenIsElevated, Type);
}

/* Creates a token with the given groups, to cover the standard and deny-only cases */
static
HANDLE
CreateTestToken(
    _In_ HANDLE Token,
    _In_ BOOLEAN WithAdmins,
    _In_ ULONG AdminAttributes)
{
    NTSTATUS Status;
    HANDLE NewToken = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    SECURITY_QUALITY_OF_SERVICE Qos;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    PSID UserSid, UsersSid, AdminsSid, EveryoneSid;
    BYTE GroupsBuffer[sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES)];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)GroupsBuffer;
    TOKEN_USER User;
    TOKEN_PRIVILEGES Privileges;
    TOKEN_OWNER Owner;
    TOKEN_PRIMARY_GROUP PrimaryGroup;
    TOKEN_SOURCE Source;
    TOKEN_STATISTICS Stats;
    ULONG Length;
    LARGE_INTEGER Expiration;
    BOOLEAN WasEnabled;

    Status = RtlAdjustPrivilege(SE_CREATE_TOKEN_PRIVILEGE, TRUE, FALSE, &WasEnabled);
    if (!NT_SUCCESS(Status))
        return NULL;
    if (!NT_SUCCESS(NtQueryInformationToken(Token, TokenStatistics, &Stats, sizeof(Stats), &Length)))
        return NULL;

    RtlAllocateAndInitializeSid(&NtAuthority, 5, SECURITY_NT_NON_UNIQUE, 1, 2, 3, 1000, 0, 0, 0, &UserSid);
    RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &UsersSid);
    RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminsSid);
    RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &EveryoneSid);

    Groups->GroupCount = WithAdmins ? 3 : 2;
    Groups->Groups[0].Sid = UsersSid;
    Groups->Groups[0].Attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
    Groups->Groups[1].Sid = EveryoneSid;
    Groups->Groups[1].Attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
    Groups->Groups[2].Sid = AdminsSid;
    Groups->Groups[2].Attributes = AdminAttributes;

    User.User.Sid = UserSid;
    User.User.Attributes = 0;
    Privileges.PrivilegeCount = 0;
    Owner.Owner = UserSid;
    PrimaryGroup.PrimaryGroup = UsersSid;
    RtlCopyMemory(Source.SourceName, "T121\0\0\0\0", 8);
    Source.SourceIdentifier = Stats.TokenId;
    Expiration.QuadPart = -1;

    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    Qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ObjectAttributes.SecurityQualityOfService = &Qos;

    Status = NtCreateToken(&NewToken, TOKEN_ALL_ACCESS, &ObjectAttributes, TokenPrimary,
                           &Stats.AuthenticationId, &Expiration, &User, Groups, &Privileges,
                           &Owner, &PrimaryGroup, NULL, &Source);
    if (!NT_SUCCESS(Status))
        NewToken = NULL;

    RtlFreeSid(UserSid);
    RtlFreeSid(UsersSid);
    RtlFreeSid(AdminsSid);
    RtlFreeSid(EveryoneSid);
    return NewToken;
}

/*
 * Contract for T125: the stored integrity level of a freshly created token.
 * SepComputeIntegrityLevel must grant High only when the Administrators group
 * is effective (enabled, not deny-only); a deny-only admin group must leave the
 * token at Medium. Before the fix it keyed off TOKEN_HAS_ADMIN_GROUP (set even
 * for a deny-only group) and wrongly returned High.
 */
static
VOID
CheckIntegrityLevel(
    _In_ HANDLE Token,
    _In_ PCSTR Name,
    _In_ ULONG ExpectedRid)
{
    NTSTATUS Status;
    ULONG Length, Rid;
    BYTE LabelBuffer[64];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)LabelBuffer;

    Status = NtQueryInformationToken(Token, TokenIntegrityLevel, LabelBuffer, sizeof(LabelBuffer), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Rid = *RtlSubAuthoritySid(Label->Label.Sid, 0);
    ok(Rid == ExpectedRid, "%s: integrity RID = 0x%lx, expected 0x%lx\n", Name, Rid, ExpectedRid);
    trace("%s: integrity=0x%lx\n", Name, Rid);
}

static
VOID
QueryTokenElevationCreatedTests(
    _In_ HANDLE Token)
{
    HANDLE Created;

    /* Creating a token needs SeCreateTokenPrivilege, which only SYSTEM holds */

    /* A standard user: no Administrators group */
    Created = CreateTestToken(Token, FALSE, 0);
    if (!Created)
    {
        skip("SeCreateTokenPrivilege is not held (run as SYSTEM): no standard/deny-only token tests\n");
        return;
    }
    CheckElevation(Created, "created standard user", 0, 1 /* Default */);
    CheckIntegrityLevel(Created, "created standard user", SECURITY_MANDATORY_MEDIUM_RID);
    NtClose(Created);

    /* Administrators enabled, default (High) integrity */
    Created = CreateTestToken(Token, TRUE, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED);
    if (Created)
    {
        CheckElevation(Created, "created admin (group enabled)", 1, 1 /* Default */);
        CheckIntegrityLevel(Created, "created admin (group enabled)", SECURITY_MANDATORY_HIGH_RID);
        NtClose(Created);
    }

    /* Administrators present but deny-only: an admin user whose token is filtered */
    Created = CreateTestToken(Token, TRUE, SE_GROUP_USE_FOR_DENY_ONLY);
    if (Created)
    {
        CheckElevation(Created, "created admin (deny-only group)", 0, 1 /* Default: no UAC */);
        CheckIntegrityLevel(Created, "created admin (deny-only group)", SECURITY_MANDATORY_MEDIUM_RID);
        NtClose(Created);
    }
}

/* A copy of Token made by NtFilterToken: the Administrators group deny-only, privileges optionally deleted */
static
HANDLE
FilterTokenForElevation(
    _In_ HANDLE Token,
    _In_ BOOLEAN DenyAdmins,
    _In_ BOOLEAN KeepOnlyImpersonate,
    _In_ BOOLEAN DeleteImpersonate)
{
    NTSTATUS Status;
    HANDLE Filtered = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID AdminSid = NULL;
    union
    {
        TOKEN_GROUPS Groups;
        BYTE Buffer[sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)];
    } Disable;
    BYTE Current[2048], Delete[2048];
    PTOKEN_PRIVILEGES CurrentPrivileges = (PTOKEN_PRIVILEGES)Current;
    PTOKEN_PRIVILEGES DeletePrivileges = (PTOKEN_PRIVILEGES)Delete;
    ULONG Length, i;

    RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0, &AdminSid);
    Disable.Groups.GroupCount = 1;
    Disable.Groups.Groups[0].Sid = AdminSid;
    Disable.Groups.Groups[0].Attributes = 0;

    DeletePrivileges->PrivilegeCount = 0;
    if (!NT_SUCCESS(NtQueryInformationToken(Token, TokenPrivileges, Current, sizeof(Current), &Length)))
        return NULL;
    for (i = 0; i < CurrentPrivileges->PrivilegeCount; i++)
    {
        BOOLEAN IsImpersonate = CurrentPrivileges->Privileges[i].Luid.HighPart == 0 &&
                                CurrentPrivileges->Privileges[i].Luid.LowPart == SE_IMPERSONATE_PRIVILEGE;

        if ((KeepOnlyImpersonate && !IsImpersonate) || (DeleteImpersonate && IsImpersonate))
            DeletePrivileges->Privileges[DeletePrivileges->PrivilegeCount++] = CurrentPrivileges->Privileges[i];
    }

    Status = NtFilterToken(Token, 0, DenyAdmins ? &Disable.Groups : NULL,
                           DeletePrivileges->PrivilegeCount ? DeletePrivileges : NULL, NULL, &Filtered);
    ok_ntstatus(Status, STATUS_SUCCESS);
    RtlFreeSid(AdminSid);
    return NT_SUCCESS(Status) ? Filtered : NULL;
}

static
VOID
QueryTokenElevationTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    ULONG Length, Value[2];
    HANDLE Dup = NULL, Filtered;
    OBJECT_ATTRIBUTES ObjectAttributes;
    BOOLEAN Admin = TokenHasEnabledAdminGroup(Token);
    ULONG Integrity, Rid, RidIndex;
    static const ULONG Rids[] = { SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_LOW_RID };
    BYTE LabelBuffer[64];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)LabelBuffer;

    /* TokenElevation insists on the exact size, TokenElevationType takes anything from 4 up (measured on Windows 10) */
    Length = 0;
    Status = NtQueryInformationToken(Token, TokenElevation, NULL, 0, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, (ULONG)sizeof(TOKEN_ELEVATION));

    Length = 0;
    Status = NtQueryInformationToken(Token, TokenElevation, Value, sizeof(Value), &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, (ULONG)sizeof(TOKEN_ELEVATION));

    Length = 0;
    Status = NtQueryInformationToken(Token, TokenElevation, Value, sizeof(TOKEN_ELEVATION) - 1, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);

    Length = 0;
    Status = NtQueryInformationToken(Token, TokenElevationType, Value, sizeof(ULONG) - 1, &Length);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);
    ok_dec(Length, (ULONG)sizeof(TOKEN_ELEVATION_TYPE));

    Length = 0;
    Value[0] = Value[1] = 0xdeadbeef;
    Status = NtQueryInformationToken(Token, TokenElevationType, Value, sizeof(Value), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_dec(Length, (ULONG)sizeof(TOKEN_ELEVATION_TYPE));
    ok_dec(Value[0], 1UL);
    ok_hex(Value[1], 0xdeadbeef);

    /* The current token */
    Status = NtQueryInformationToken(Token, TokenIntegrityLevel, LabelBuffer, sizeof(LabelBuffer), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Integrity = *RtlSubAuthoritySid(Label->Label.Sid, 0);
    trace("current token: admin=%d integrity=0x%lx\n", Admin, Integrity);

    CheckElevation(Token, "current", Admin || TokenHoldsElevatingPrivilege(Token, TRUE), TokenElevationTypeDefault);

    if (!Admin)
    {
        skip("Current token has no Administrators group, cannot derive elevated tokens from it\n");
        return;
    }

    /* The integrity level does not matter: a medium or low copy of an administrator's token is elevated too */
    for (RidIndex = 0; RidIndex < RTL_NUMBER_OF(Rids); RidIndex++)
    {
        Rid = Rids[RidIndex];
        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
        Status = NtDuplicateToken(Token, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenPrimary, &Dup);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            SID_IDENTIFIER_AUTHORITY LabelAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
            CHAR Name[64];

            RtlInitializeSid((PSID)(Label + 1), &LabelAuthority, 1);
            *RtlSubAuthoritySid((PSID)(Label + 1), 0) = Rid;
            Label->Label.Sid = (PSID)(Label + 1);
            Label->Label.Attributes = SE_GROUP_INTEGRITY;
            Status = NtSetInformationToken(Dup, TokenIntegrityLevel, Label, sizeof(LabelBuffer));
            ok_ntstatus(Status, STATUS_SUCCESS);
            sprintf(Name, "duplicate (admin, integrity 0x%lx)", Rid);
            if (NT_SUCCESS(Status))
                CheckElevation(Dup, Name, 1, TokenElevationTypeDefault);
            NtClose(Dup);
        }
    }

    /* Impersonation copies are the same */
    Status = NtDuplicateToken(Token, TOKEN_ALL_ACCESS, NULL, FALSE, TokenImpersonation, &Dup);
    if (NT_SUCCESS(Status))
    {
        CheckElevation(Dup, "impersonation duplicate", 1, TokenElevationTypeDefault);
        NtClose(Dup);
    }

    /* Filtered copies. The Administrators group deny-only does not make a token elevated, a privilege does */
    if (TokenHoldsElevatingPrivilege(Token, TRUE))
    {
        Filtered = FilterTokenForElevation(Token, TRUE, FALSE, FALSE);
        if (Filtered)
        {
            CheckElevation(Filtered, "filtered (admins deny-only, privileges kept)", 1, TokenElevationTypeDefault);
            NtClose(Filtered);
        }

        Filtered = FilterTokenForElevation(Token, FALSE, FALSE, TRUE);
        if (Filtered)
        {
            CheckElevation(Filtered, "filtered (admins enabled, no SeImpersonate)", 1, TokenElevationTypeDefault);
            NtClose(Filtered);
        }

        Filtered = FilterTokenForElevation(Token, TRUE, TRUE, FALSE);
        if (Filtered)
        {
            CheckElevation(Filtered, "filtered (admins deny-only, only SeImpersonate)", 1, TokenElevationTypeDefault);
            NtClose(Filtered);
        }
    }
    else
    {
        skip("Current token holds no elevating privilege, no filtered token tests\n");
    }

    QueryTokenElevationCreatedTests(Token);
}

/*
 * The other NT 6 classes, with UAC off: no linked token, UI access and
 * virtualization off, the default mandatory policy, not an AppContainer.
 * Lengths and statuses as measured on Windows 10 (x64 and WoW64).
 */
static
VOID
QueryTokenNt6ClassesTests(
    _In_ HANDLE Token)
{
    static const struct
    {
        TOKEN_INFORMATION_CLASS Class;
        PCSTR Name;
        ULONG Expected;
    } Classes[] =
    {
        { TokenVirtualizationAllowed, "TokenVirtualizationAllowed", 0 },
        { TokenVirtualizationEnabled, "TokenVirtualizationEnabled", 0 },
        { TokenUIAccess, "TokenUIAccess", 0 },
        { TokenMandatoryPolicy, "TokenMandatoryPolicy", TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN },
        { TokenIsAppContainer, "TokenIsAppContainer", 0 },
    };
    NTSTATUS Status;
    ULONG Length, Value[2], i;
    HANDLE Linked[2];

    for (i = 0; i < RTL_NUMBER_OF(Classes); i++)
    {
        Length = 0;
        Value[0] = Value[1] = 0xdeadbeef;
        Status = NtQueryInformationToken(Token, Classes[i].Class, Value, sizeof(ULONG), &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_dec(Length, (ULONG)sizeof(ULONG));
        ok(Value[0] == Classes[i].Expected, "%s = %lu, expected %lu\n", Classes[i].Name, Value[0], Classes[i].Expected);

        /* Larger buffers are fine, smaller ones are not */
        Length = 0;
        Status = NtQueryInformationToken(Token, Classes[i].Class, Value, sizeof(Value), &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_dec(Length, (ULONG)sizeof(ULONG));

        Length = 0;
        Status = NtQueryInformationToken(Token, Classes[i].Class, Value, sizeof(ULONG) - 1, &Length);
        ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);
        ok_dec(Length, (ULONG)sizeof(ULONG));

        Length = 0;
        Status = NtQueryInformationToken(Token, Classes[i].Class, NULL, 0, &Length);
        ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);
        ok_dec(Length, (ULONG)sizeof(ULONG));
    }

    /* No token has a linked token without UAC; the length has to be exactly that of a handle */
    Length = 0;
    Linked[0] = Linked[1] = (HANDLE)(ULONG_PTR)0xdeadbeef;
    Status = NtQueryInformationToken(Token, TokenLinkedToken, Linked, sizeof(HANDLE), &Length);
    ok_ntstatus(Status, STATUS_NO_SUCH_LOGON_SESSION);
    ok_dec(Length, (ULONG)sizeof(HANDLE));
    ok(Linked[0] == (HANDLE)(ULONG_PTR)0xdeadbeef, "handle written: %p\n", Linked[0]);

    Length = 0;
    Status = NtQueryInformationToken(Token, TokenLinkedToken, Linked, sizeof(HANDLE) * 2, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, (ULONG)sizeof(HANDLE));

    Length = 0;
    Status = NtQueryInformationToken(Token, TokenLinkedToken, Linked, sizeof(HANDLE) - 1, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);

    Length = 0;
    Status = NtQueryInformationToken(Token, TokenLinkedToken, NULL, 0, &Length);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
    ok_dec(Length, (ULONG)sizeof(HANDLE));
}

static
VOID
QueryTokenHasRestrictionsTests(
    _In_ HANDLE Token)
{
    NTSTATUS Status;
    ULONG Length, Value;
    ULONG FlagStorage;
    PBOOLEAN Flag = (PBOOLEAN)&FlagStorage;
    HANDLE FilteredToken;
    PSID WorldSid;
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    union
    {
        TOKEN_GROUPS Groups;
        BYTE Buffer[sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)];
    } SidToRestrict;

    /*
     * The result is a single byte on Windows 10 (measured on 22H2): too small buffers report
     * one byte, a larger buffer is accepted and only its first byte is written.
     */
    Length = 0;
    Status = NtQueryInformationToken(Token, TokenHasRestrictions, NULL, 0, &Length);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);
    ok_dec(Length, (ULONG)sizeof(BOOLEAN));

    Length = 0;
    *Flag = 0xCC;
    Status = NtQueryInformationToken(Token, TokenHasRestrictions, Flag, 0, &Length);
    ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);
    ok_dec(Length, (ULONG)sizeof(BOOLEAN));
    ok_hex(*Flag, 0xCC);

    /* The current token is not restricted */
    Length = 0;
    Value = 0xdeadbeef;
    Status = NtQueryInformationToken(Token, TokenHasRestrictions, &Value, sizeof(Value), &Length);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_dec(Length, (ULONG)sizeof(BOOLEAN));
    ok_hex(Value, 0xdeadbe00);

    /* A token with a restricting SID is restricted */
    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID,
                                         0, 0, 0, 0, 0, 0, 0, &WorldSid);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    SidToRestrict.Groups.GroupCount = 1;
    SidToRestrict.Groups.Groups[0].Attributes = 0;
    SidToRestrict.Groups.Groups[0].Sid = WorldSid;

    Status = NtFilterToken(Token, 0, NULL, NULL, &SidToRestrict.Groups, &FilteredToken);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Length = 0;
        Value = 0xdeadbeef;
        Status = NtQueryInformationToken(FilteredToken, TokenHasRestrictions, &Value, sizeof(Value), &Length);
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok_dec(Length, (ULONG)sizeof(BOOLEAN));
        ok_hex(Value, 0xdeadbe01);

        Length = 0;
        Status = NtQueryInformationToken(FilteredToken, TokenHasRestrictions, Flag, 0, &Length);
        ok_ntstatus(Status, STATUS_BUFFER_TOO_SMALL);
        ok_dec(Length, (ULONG)sizeof(BOOLEAN));

        NtClose(FilteredToken);
    }

    RtlFreeSid(WorldSid);
}

START_TEST(NtQueryInformationToken)
{
    NTSTATUS Status;
    HANDLE Token;
    PVOID Dummy;
    ULONG DummyReturnLength;

    /* ReturnLength is NULL */
    Status = NtQueryInformationToken(NULL,
                                     TokenUser,
                                     NULL,
                                     0,
                                     NULL);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);

    /* We don't give any token here */
    Status = NtQueryInformationToken(NULL,
                                     TokenUser,
                                     &Dummy,
                                     0,
                                     &DummyReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);

    Token = OpenCurrentToken();

    /* Class 0 is unused on Windows */
    Status = NtQueryInformationToken(Token,
                                     0,
                                     &Dummy,
                                     0,
                                     &DummyReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);

    /* We give a bogus info class */
    Status = NtQueryInformationToken(Token,
                                     0xa0a,
                                     &Dummy,
                                     0,
                                     &DummyReturnLength);
    ok_ntstatus(Status, STATUS_INVALID_INFO_CLASS);

    /* Now perform tests for each class */
    QueryTokenUserTests(Token);
    QueryTokenGroupsTests(Token);
    QueryTokenPrivilegesTests(Token);
    QueryTokenOwnerTests(Token);
    QueryTokenPrimaryGroupTests(Token);
    QueryTokenDefaultDaclTests(Token);
    QueryTokenSourceTests(Token);
    QueryTokenTypeTests(Token);
    QueryTokenImpersonationTests(Token);
    QueryTokenStatisticsTests(Token);
    QueryTokenPrivilegesAndGroupsTests(Token);
    QueryTokenRestrictedSidsTest(Token);
    QueryTokenSessionIdTests(Token);
    QueryTokenIsSandboxInert(Token);
    QueryTokenOriginTests(Token);
    QueryTokenElevationTests(Token);
    QueryTokenNt6ClassesTests(Token);
    QueryTokenHasRestrictionsTests(Token);

    NtClose(Token);
}
