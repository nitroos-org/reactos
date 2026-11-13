/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel mode tests for token filtering implementation
 * COPYRIGHT:   Copyright 2021 George Bisoc <george.bisoc@reactos.org>
 */

#include <kmt_test.h>
#include <ntifs.h>

static
VOID
FilterToken(VOID)
{
    NTSTATUS Status;
    PSECURITY_SUBJECT_CONTEXT SubjectContext;
    PACCESS_TOKEN Token, FilteredToken;
    TOKEN_GROUPS SidsToDisable, RestrictedGroups;
    TOKEN_PRIVILEGES Privilege;

    /* Capture the subject context and token for tests */
    SubjectContext = ExAllocatePool(PagedPool, sizeof(SECURITY_SUBJECT_CONTEXT));
    if (SubjectContext == NULL)
    {
        trace("Failed to allocate memory pool for the subject context!\n");
        return;
    }

    SeCaptureSubjectContext(SubjectContext);
    SeLockSubjectContext(SubjectContext);
    Token = SeQuerySubjectContextToken(SubjectContext);
    ok(Token != NULL, "Token mustn't be NULL...\n");

    /* Delete a privilege */
    Privilege.PrivilegeCount = 1;
    Privilege.Privileges[0].Attributes = 0;
    Privilege.Privileges[0].Luid = SeExports->SeSystemEnvironmentPrivilege;

    Status = SeFilterToken(Token,
                           0,
                           NULL,
                           &Privilege,
                           NULL,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /* Disable all the privileges */
    Status = SeFilterToken(Token,
                           DISABLE_MAX_PRIVILEGE,
                           NULL,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /*
     * All three lists are optional: NULL means none, and a token only becomes
     * restricted when restricting SIDs are given. A NULL RestrictedSids used to
     * reach SepPerformTokenFiltering as (NULL + member offset, 0), which made a
     * restricted token with an empty restricting list that every access check
     * refuses.
     */
    if (NT_SUCCESS(Status))
    {
        ok(!SeTokenIsRestricted(FilteredToken),
           "A token filtered with NULL RestrictedSids must not be restricted\n");
    }

    /* Disable a SID */
    SidsToDisable.GroupCount = 1;
    SidsToDisable.Groups[0].Attributes = 0;
    SidsToDisable.Groups[0].Sid = SeExports->SeWorldSid;

    Status = SeFilterToken(Token,
                           0,
                           &SidsToDisable,
                           NULL,
                           NULL,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /*
     * T125 contract: disabling a SID must actually turn it deny-only in the
     * filtered token. The group match in SepPerformTokenFiltering used to pass
     * RtlEqualSid the address of the SID pointer (&...Sid) instead of the SID,
     * so it never matched and the filter was a silent no-op (the SID stayed
     * enabled). Verifying the attributes here (not just the status) also guards
     * the follow-on fix that had to drop a stray index rewind which would
     * otherwise loop forever once the match worked.
     */
    if (NT_SUCCESS(Status))
    {
        PTOKEN_GROUPS FilteredGroups = NULL;
        ULONG Index;
        BOOLEAN FoundWorld = FALSE;

        Status = SeQueryInformationToken(FilteredToken, TokenGroups, (PVOID *)&FilteredGroups);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status) && FilteredGroups != NULL)
        {
            for (Index = 0; Index < FilteredGroups->GroupCount; Index++)
            {
                if (RtlEqualSid(FilteredGroups->Groups[Index].Sid, SeExports->SeWorldSid))
                {
                    FoundWorld = TRUE;
                    ok((FilteredGroups->Groups[Index].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0,
                       "World SID must be deny-only after filtering, attributes = 0x%lx\n",
                       FilteredGroups->Groups[Index].Attributes);
                    ok((FilteredGroups->Groups[Index].Attributes & SE_GROUP_ENABLED) == 0,
                       "World SID must not be enabled after filtering, attributes = 0x%lx\n",
                       FilteredGroups->Groups[Index].Attributes);
                }
            }
            ok(FoundWorld, "World SID must still be present in the filtered token\n");
            ExFreePool(FilteredGroups);
        }
    }

    /*
     * Add a restricted SID but we're going to fail...
     * Because no attributes must be within restricted
     * SIDs.
     */
    RestrictedGroups.GroupCount = 1;
    RestrictedGroups.Groups[0].Attributes = SE_GROUP_ENABLED;
    RestrictedGroups.Groups[0].Sid = SeExports->SeDialupSid;

    Status = SeFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           &RestrictedGroups,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);

    /* Add a restricted SID now */
    RestrictedGroups.GroupCount = 1;
    RestrictedGroups.Groups[0].Attributes = 0;
    RestrictedGroups.Groups[0].Sid = SeExports->SeDialupSid;

    Status = SeFilterToken(Token,
                           0,
                           NULL,
                           NULL,
                           &RestrictedGroups,
                           &FilteredToken);
    ok_irql(PASSIVE_LEVEL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(SeTokenIsRestricted(FilteredToken),
           "A token filtered with a restricting SID must be restricted\n");
    }

    /* We're done */
    SeUnlockSubjectContext(SubjectContext);
    if (SubjectContext)
        ExFreePool(SubjectContext);
}

START_TEST(SeTokenFiltering)
{
    FilterToken();
}
