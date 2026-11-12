/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtOpenSection: user mode cannot open \Device\PhysicalMemory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Windows 10 22H2 refuses every user-mode open of \Device\PhysicalMemory with
 * STATUS_ACCESS_DENIED: for an elevated administrator, for SYSTEM (with
 * SeTcbPrivilege), for a standard-user token and for every access mask,
 * READ_CONTROL included (the object is kernel-exclusive).
 */
static const ACCESS_MASK PhysMemAccess[] =
{
    READ_CONTROL,
    SECTION_QUERY,
    SECTION_MAP_READ,
    SECTION_MAP_READ | SECTION_MAP_WRITE,
    SECTION_ALL_ACCESS,
    MAXIMUM_ALLOWED,
};

static
void
TestPhysicalMemoryOpen(PCSTR Who)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    NTSTATUS Status;
    ULONG i;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    for (i = 0; i < _countof(PhysMemAccess); i++)
    {
        Handle = (HANDLE)(ULONG_PTR)0x55555555;
        Status = NtOpenSection(&Handle, PhysMemAccess[i], &ObjectAttributes);
        ok(Status == STATUS_ACCESS_DENIED, "%s, access 0x%lx: Status = 0x%lx\n", Who, PhysMemAccess[i], Status);
        if (NT_SUCCESS(Status))
            NtClose(Handle);
    }
}

/* Our token without the Administrators group (deny-only), without privileges, at Medium integrity */
static
HANDLE
MakeStandardUserToken(void)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY LabelAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    PSID AdminsSid = NULL, MediumSid = NULL;
    TOKEN_GROUPS Disable;
    TOKEN_MANDATORY_LABEL Label;
    OBJECT_ATTRIBUTES ObjectAttributes;
    SECURITY_QUALITY_OF_SERVICE Qos;
    HANDLE ProcessToken = NULL, Filtered = NULL, Impersonation = NULL;
    NTSTATUS Status;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &ProcessToken);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return NULL;
    Status = RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                         0, 0, 0, 0, 0, 0, &AdminsSid);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = RtlAllocateAndInitializeSid(&LabelAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID,
                                         0, 0, 0, 0, 0, 0, 0, &MediumSid);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (AdminsSid == NULL || MediumSid == NULL)
        goto Cleanup;

    Disable.GroupCount = 1;
    Disable.Groups[0].Sid = AdminsSid;
    Disable.Groups[0].Attributes = 0;
    Status = NtFilterToken(ProcessToken, DISABLE_MAX_PRIVILEGE, &Disable, NULL, NULL, &Filtered);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    Qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ObjectAttributes.SecurityQualityOfService = &Qos;
    Status = NtDuplicateToken(Filtered, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenImpersonation, &Impersonation);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Label.Label.Sid = MediumSid;
    Label.Label.Attributes = SE_GROUP_INTEGRITY;
    Status = NtSetInformationToken(Impersonation, TokenIntegrityLevel, &Label,
                                   sizeof(Label) + RtlLengthSid(MediumSid));
    /* Lowering the integrity of our own token copy; not fatal for the test if unsupported */
    ok(NT_SUCCESS(Status) || Status == STATUS_INVALID_INFO_CLASS, "Setting Medium IL: 0x%lx\n", Status);

Cleanup:
    if (Filtered) NtClose(Filtered);
    if (ProcessToken) NtClose(ProcessToken);
    if (MediumSid) RtlFreeSid(MediumSid);
    if (AdminsSid) RtlFreeSid(AdminsSid);
    return Impersonation;
}

/*
 * Only an elevated administrator or SYSTEM would pass the DACL, so only for them
 * does an ACCESS_DENIED prove the kernel-exclusive flag; for anyone else the DACL
 * alone produces it.
 */
static
BOOLEAN
IsElevatedOrSystem(void)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID SystemSid = NULL;
    HANDLE ProcessToken = NULL;
    TOKEN_ELEVATION Elevation;
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER User = (PTOKEN_USER)Buffer;
    ULONG Length;
    BOOLEAN Result = FALSE;

    if (!NT_SUCCESS(NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &ProcessToken)))
        return FALSE;
    if (NT_SUCCESS(NtQueryInformationToken(ProcessToken, TokenElevation, &Elevation, sizeof(Elevation), &Length)) &&
        Elevation.TokenIsElevated)
    {
        Result = TRUE;
    }
    else if (NT_SUCCESS(NtQueryInformationToken(ProcessToken, TokenUser, User, sizeof(Buffer), &Length)) &&
             NT_SUCCESS(RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                                    0, 0, 0, 0, 0, 0, 0, &SystemSid)))
    {
        Result = RtlEqualSid(User->User.Sid, SystemSid);
    }
    if (SystemSid) RtlFreeSid(SystemSid);
    NtClose(ProcessToken);
    return Result;
}

START_TEST(NtOpenSection)
{
    HANDLE Token, NoToken = NULL;
    NTSTATUS Status;

    /* Our own token: an administrator in the test runs, SYSTEM when run from a service */
    TestPhysicalMemoryOpen("own token");
    if (!IsElevatedOrSystem())
        skip("Not elevated: the refusals above come from the DACL, kernel-exclusivity is not proven by this run\n");

    /* A standard user */
    Token = MakeStandardUserToken();
    if (Token == NULL)
    {
        skip("No standard-user token\n");
        return;
    }
    Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &Token, sizeof(Token));
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        TestPhysicalMemoryOpen("standard user");
        Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &NoToken, sizeof(NoToken));
        ok_ntstatus(Status, STATUS_SUCCESS);
    }
    NtClose(Token);
}
