/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the mandatory label in AccessCheck (integrity levels below the object's)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/sefuncs.h>

/*
 * Every expected value was measured on Windows Server 2022 (AccessCheck, AccessCheckByTypeResultList):
 * the label of an object is the first mandatory label ACE of its SACL that is not inherit-only, an
 * implicit Medium one without; a token below it gets at most GenericRead | READ_CONTROL (unless
 * NO_READ_UP) and GenericExecute | SYNCHRONIZE (unless NO_EXECUTE_UP), never a write right; a request
 * for another right is denied before the privileges and the DACL count.
 */

static BOOL (WINAPI *pAddMandatoryAce)(PACL, DWORD, DWORD, DWORD, PSID);
static GENERIC_MAPPING Mapping = {0x1 | READ_CONTROL, 0x2 | WRITE_DAC, 0x4 | SYNCHRONIZE, 0x3F | STANDARD_RIGHTS_REQUIRED};
static SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
static SID_IDENTIFIER_AUTHORITY LabelAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};

#define LABEL_NONE 0xFFFFFFFF

typedef struct
{
    ULONG Level;    /* LABEL_NONE: no label ACE */
    ULONG Policy;
    UCHAR Flags;
} LABEL_SPEC;

/* A self-relative descriptor: owner and group a SID nobody holds / Users, DACL Everyone 0x1F01FF (or NULL), up to two labels */
static PSECURITY_DESCRIPTOR MakeSd(BOOL NullDacl, const LABEL_SPEC *Labels, ULONG LabelCount)
{
    static BYTE Buffer[1024];
    BYTE AbsBuffer[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR Abs = (PSECURITY_DESCRIPTOR)AbsBuffer;
    BYTE DaclBuffer[128], SaclBuffer[128];
    PACL Dacl = (PACL)DaclBuffer, Sacl = (PACL)SaclBuffer;
    PSID Everyone, Nobody, Users;
    DWORD Length = sizeof(Buffer), i;

    AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone);
    AllocateAndInitializeSid(&NtAuthority, 5, SECURITY_NT_NON_UNIQUE, 1, 2, 3, 1001, 0, 0, 0, &Nobody);
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &Users);
    InitializeSecurityDescriptor(Abs, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(Abs, Nobody, FALSE);
    SetSecurityDescriptorGroup(Abs, Users, FALSE);
    if (NullDacl)
    {
        SetSecurityDescriptorDacl(Abs, TRUE, NULL, FALSE);
    }
    else
    {
        InitializeAcl(Dacl, sizeof(DaclBuffer), ACL_REVISION);
        AddAccessAllowedAce(Dacl, ACL_REVISION, 0x1F01FF, Everyone);
        SetSecurityDescriptorDacl(Abs, TRUE, Dacl, FALSE);
    }
    if (LabelCount)
    {
        InitializeAcl(Sacl, sizeof(SaclBuffer), ACL_REVISION);
        for (i = 0; i < LabelCount; i++)
        {
            PSID Label;
            AllocateAndInitializeSid(&LabelAuthority, 1, Labels[i].Level, 0, 0, 0, 0, 0, 0, 0, &Label);
            ok(pAddMandatoryAce(Sacl, ACL_REVISION, Labels[i].Flags, Labels[i].Policy, Label), "AddMandatoryAce failed: %lu\n", GetLastError());
            FreeSid(Label);
        }
        SetSecurityDescriptorSacl(Abs, TRUE, Sacl, FALSE);
    }
    ok(MakeSelfRelativeSD(Abs, Buffer, &Length), "MakeSelfRelativeSD failed: %lu\n", GetLastError());
    FreeSid(Everyone);
    FreeSid(Nobody);
    FreeSid(Users);
    return (PSECURITY_DESCRIPTOR)Buffer;
}

/* An impersonation token of this process at the integrity level Rid */
static HANDLE MakeToken(DWORD Rid)
{
    HANDLE Process, Token = NULL;
    BYTE Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;
    PSID Sid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
        return NULL;
    if (!DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Token))
        Token = NULL;
    CloseHandle(Process);
    if (!Token)
        return NULL;
    /* SeSecurityPrivilege disabled (an elevated WinRM session has it enabled): ACCESS_SYSTEM_SECURITY then needs it */
    {
        TOKEN_PRIVILEGES Privileges;
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = 0;
        if (LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &Privileges.Privileges[0].Luid))
            AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL);
    }
    AllocateAndInitializeSid(&LabelAuthority, 1, Rid, 0, 0, 0, 0, 0, 0, 0, &Sid);
    Label->Label.Sid = Sid;
    Label->Label.Attributes = SE_GROUP_INTEGRITY;
    if (!SetTokenInformation(Token, TokenIntegrityLevel, Label, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)))
    {
        skip("Cannot set integrity level 0x%lx: %lu\n", Rid, GetLastError());
        CloseHandle(Token);
        Token = NULL;
    }
    FreeSid(Sid);
    return Token;
}

static void Check(int Line, HANDLE Token, PSECURITY_DESCRIPTOR Sd, DWORD Desired, BOOL ExpectStatus, DWORD ExpectGranted, DWORD ExpectError)
{
    BYTE PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted = 0xCCCCCCCC;
    BOOL Status = 0xCC, Result;

    SetLastError(0xDEADBEEF);
    Result = AccessCheck(Sd, Token, Desired, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, &Granted, &Status);
    ok_(__FILE__, Line)(Result, "AccessCheck failed: %lu\n", GetLastError());
    ok_(__FILE__, Line)(Status == ExpectStatus, "Access status %d, expected %d (granted 0x%lx, error %lu)\n", Status, ExpectStatus, Granted, GetLastError());
    ok_(__FILE__, Line)(Granted == ExpectGranted, "Granted 0x%lx, expected 0x%lx\n", Granted, ExpectGranted);
    if (!ExpectStatus)
        ok_(__FILE__, Line)(GetLastError() == ExpectError, "Error %lu, expected %lu\n", GetLastError(), ExpectError);
}
#define CHECK(t, sd, d, s, g, e) Check(__LINE__, t, sd, d, s, g, e)

static void TestLevels(void)
{
    static const LABEL_SPEC LowNw = {SECURITY_MANDATORY_LOW_RID, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, 0};
    static const LABEL_SPEC HighNr = {SECURITY_MANDATORY_HIGH_RID, SYSTEM_MANDATORY_LABEL_NO_READ_UP, 0};
    static const LABEL_SPEC HighNone = {SECURITY_MANDATORY_HIGH_RID, 0, 0};
    static const LABEL_SPEC HighNx = {SECURITY_MANDATORY_HIGH_RID, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, 0};
    static const LABEL_SPEC LowNwInheritOnly = {SECURITY_MANDATORY_LOW_RID, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE};
    static const LABEL_SPEC UntrustedNw = {SECURITY_MANDATORY_UNTRUSTED_RID, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, 0};
    LABEL_SPEC Two[2];
    HANDLE Low, Untrusted, Medium;
    PSECURITY_DESCRIPTOR Sd;

    Low = MakeToken(SECURITY_MANDATORY_LOW_RID);
    Untrusted = MakeToken(SECURITY_MANDATORY_UNTRUSTED_RID);
    Medium = MakeToken(SECURITY_MANDATORY_MEDIUM_RID);
    if (!Low || !Untrusted || !Medium)
    {
        skip("No tokens\n");
        return;
    }

    /* No label: implicit Medium, no write up */
    Sd = MakeSd(FALSE, NULL, 0);
    CHECK(Low, Sd, MAXIMUM_ALLOWED, TRUE, 0x120005, 0);
    CHECK(Low, Sd, 1, TRUE, 1, 0);
    CHECK(Low, Sd, 4 | SYNCHRONIZE, TRUE, 4 | SYNCHRONIZE, 0);
    CHECK(Low, Sd, READ_CONTROL, TRUE, READ_CONTROL, 0);
    CHECK(Low, Sd, 2, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Low, Sd, 0x10, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Low, Sd, DELETE, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Low, Sd, WRITE_DAC, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Low, Sd, MAXIMUM_ALLOWED | 2, FALSE, 0, ERROR_ACCESS_DENIED);
    /* Denied before the privilege is looked at (no SeSecurityPrivilege: not ERROR_PRIVILEGE_NOT_HELD) */
    CHECK(Low, Sd, ACCESS_SYSTEM_SECURITY, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Untrusted, Sd, MAXIMUM_ALLOWED, TRUE, 0x120005, 0);
    CHECK(Untrusted, Sd, 2, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Medium, Sd, MAXIMUM_ALLOWED, TRUE, 0x1F01FF, 0);
    CHECK(Medium, Sd, 2, TRUE, 2, 0);
    CHECK(Medium, Sd, ACCESS_SYSTEM_SECURITY, FALSE, 0, ERROR_PRIVILEGE_NOT_HELD);

    /* A NULL DACL grants GenericAll, within the label */
    Sd = MakeSd(TRUE, NULL, 0);
    CHECK(Low, Sd, MAXIMUM_ALLOWED, TRUE, 0x20005, 0);
    CHECK(Low, Sd, 2, FALSE, 0, ERROR_ACCESS_DENIED);

    /* At the level of the label: not restricted */
    Sd = MakeSd(FALSE, &LowNw, 1);
    CHECK(Low, Sd, MAXIMUM_ALLOWED, TRUE, 0x1F01FF, 0);
    CHECK(Low, Sd, 2, TRUE, 2, 0);
    CHECK(Untrusted, Sd, MAXIMUM_ALLOWED, TRUE, 0x120005, 0);
    Sd = MakeSd(FALSE, &UntrustedNw, 1);
    CHECK(Untrusted, Sd, 2, TRUE, 2, 0);

    /* The policies: no read up, no execute up; no write up also without the flag */
    Sd = MakeSd(FALSE, &HighNr, 1);
    CHECK(Medium, Sd, MAXIMUM_ALLOWED, TRUE, 0x100004, 0);
    CHECK(Medium, Sd, 1, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Medium, Sd, READ_CONTROL, FALSE, 0, ERROR_ACCESS_DENIED);
    Sd = MakeSd(FALSE, &HighNone, 1);
    CHECK(Medium, Sd, MAXIMUM_ALLOWED, TRUE, 0x120005, 0);
    CHECK(Medium, Sd, 2, FALSE, 0, ERROR_ACCESS_DENIED);
    Sd = MakeSd(FALSE, &HighNx, 1);
    CHECK(Medium, Sd, MAXIMUM_ALLOWED, TRUE, 0x20001, 0);
    CHECK(Medium, Sd, SYNCHRONIZE, FALSE, 0, ERROR_ACCESS_DENIED);

    /* The first label counts; an inherit-only one does not */
    Two[0] = HighNr; Two[1] = LowNw;
    Sd = MakeSd(FALSE, Two, 2);
    CHECK(Low, Sd, MAXIMUM_ALLOWED, TRUE, 0x100004, 0);
    Two[0] = LowNw; Two[1] = HighNr;
    Sd = MakeSd(FALSE, Two, 2);
    CHECK(Low, Sd, MAXIMUM_ALLOWED, TRUE, 0x1F01FF, 0);
    Sd = MakeSd(FALSE, &LowNwInheritOnly, 1);
    CHECK(Low, Sd, MAXIMUM_ALLOWED, TRUE, 0x120005, 0);

    CloseHandle(Low);
    CloseHandle(Untrusted);
    CloseHandle(Medium);
}

static void TestResultList(void)
{
    static GUID Guids[3] = {{0x11111111, 0x1111, 0x1111, {1, 1, 1, 1, 1, 1, 1, 1}},
                            {0xaaaaaaaa, 0xaaaa, 0xaaaa, {1, 2, 3, 4, 5, 6, 7, 8}},
                            {0xcccccccc, 0xcccc, 0xcccc, {1, 2, 3, 4, 5, 6, 7, 8}}};
    OBJECT_TYPE_LIST List[3] = {{0, 0, &Guids[0]}, {1, 0, &Guids[1]}, {1, 0, &Guids[2]}};
    BYTE PrivBuffer[256];
    DWORD PrivLength = sizeof(PrivBuffer), Granted[3], Status[3], i;
    HANDLE Low = MakeToken(SECURITY_MANDATORY_LOW_RID);
    PSECURITY_DESCRIPTOR Sd = MakeSd(FALSE, NULL, 0);

    if (!Low)
        return;
    ok(AccessCheckByTypeResultList(Sd, NULL, Low, MAXIMUM_ALLOWED, List, 3, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, Granted, (LPBOOL)Status),
       "AccessCheckByTypeResultList failed: %lu\n", GetLastError());
    for (i = 0; i < 3; i++)
    {
        ok(Status[i] == ERROR_SUCCESS, "Entry %lu: status %lu\n", i, Status[i]);
        ok(Granted[i] == 0x120005, "Entry %lu: granted 0x%lx\n", i, Granted[i]);
    }
    PrivLength = sizeof(PrivBuffer);
    ok(AccessCheckByTypeResultList(Sd, NULL, Low, 2, List, 3, &Mapping, (PPRIVILEGE_SET)PrivBuffer, &PrivLength, Granted, (LPBOOL)Status),
       "AccessCheckByTypeResultList failed: %lu\n", GetLastError());
    for (i = 0; i < 3; i++)
    {
        ok(Status[i] == ERROR_ACCESS_DENIED, "Entry %lu: status %lu\n", i, Status[i]);
        ok(Granted[i] == 0, "Entry %lu: granted 0x%lx\n", i, Granted[i]);
    }
    CloseHandle(Low);
}

/* The anonymous logon token: Untrusted (Low when EveryoneIncludesAnonymous is set), its level is a group of the token */
static void TestAnonymous(void)
{
    BYTE Buffer[512];
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, Value = 0, Size = sizeof(Value), i, Rid = 0xFFFFFFFF, Attributes = 0;
    BOOL Everyone = FALSE;
    HANDLE Token, Imp;
    HKEY Key;
    PSECURITY_DESCRIPTOR Sd;
    NTSTATUS Status;

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_QUERY_VALUE, &Key))
    {
        RegQueryValueExW(Key, L"EveryoneIncludesAnonymous", NULL, NULL, (PBYTE)&Value, &Size);
        RegCloseKey(Key);
    }

    Status = NtImpersonateAnonymousToken(GetCurrentThread());
    ok(Status == STATUS_SUCCESS, "NtImpersonateAnonymousToken: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    ok(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token), "OpenThreadToken failed: %lu\n", GetLastError());
    RevertToSelf();
    ok(GetTokenInformation(Token, TokenGroups, Buffer, sizeof(Buffer), &Length), "TokenGroups failed: %lu\n", GetLastError());
    for (i = 0; i < Groups->GroupCount; i++)
    {
        PSID_IDENTIFIER_AUTHORITY Authority = GetSidIdentifierAuthority(Groups->Groups[i].Sid);
        if (!memcmp(Authority, &LabelAuthority, sizeof(LabelAuthority)))
        {
            Rid = *GetSidSubAuthority(Groups->Groups[i].Sid, 0);
            Attributes = Groups->Groups[i].Attributes;
        }
        else if (!memcmp(Authority, &WorldAuthority, sizeof(WorldAuthority)))
        {
            Everyone = TRUE;
        }
    }
    ok(Groups->GroupCount == (Value ? 2 : 1), "%lu groups (EveryoneIncludesAnonymous %lu)\n", Groups->GroupCount, Value);
    ok(Everyone == (Value != 0), "Everyone %d (EveryoneIncludesAnonymous %lu)\n", Everyone, Value);
    ok(Rid == (Value ? SECURITY_MANDATORY_LOW_RID : SECURITY_MANDATORY_UNTRUSTED_RID), "Integrity group 0x%lx\n", Rid);
    ok(Attributes == (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED), "Integrity group attributes 0x%lx\n", Attributes);

    /* A NULL DACL: read and execute only (the 'anonymous logon token' rows of the matrix) */
    CloseHandle(Token);
    Status = NtImpersonateAnonymousToken(GetCurrentThread());
    ok(Status == STATUS_SUCCESS, "NtImpersonateAnonymousToken: 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    ok(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &Token), "OpenThreadToken failed: %lu\n", GetLastError());
    RevertToSelf();
    ok(DuplicateTokenEx(Token, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &Imp), "DuplicateTokenEx failed: %lu\n", GetLastError());
    CloseHandle(Token);
    Sd = MakeSd(TRUE, NULL, 0);
    CHECK(Imp, Sd, 1, TRUE, 1, 0);
    CHECK(Imp, Sd, 2, FALSE, 0, ERROR_ACCESS_DENIED);
    CHECK(Imp, Sd, MAXIMUM_ALLOWED, TRUE, 0x20005, 0);
    CloseHandle(Imp);
}

/* Membership is about the SIDs, also for a token below Medium */
static void TestMembership(void)
{
    HANDLE Low = MakeToken(SECURITY_MANDATORY_LOW_RID), Untrusted = MakeToken(SECURITY_MANDATORY_UNTRUSTED_RID);
    PSID Everyone, Nobody;
    BOOL Member;

    if (!Low || !Untrusted)
        return;
    AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone);
    AllocateAndInitializeSid(&NtAuthority, 5, SECURITY_NT_NON_UNIQUE, 1, 2, 3, 1001, 0, 0, 0, &Nobody);
    Member = 2;
    ok(CheckTokenMembership(Low, Everyone, &Member), "CheckTokenMembership failed: %lu\n", GetLastError());
    ok(Member == TRUE, "Low token: Everyone member %d\n", Member);
    Member = 2;
    ok(CheckTokenMembership(Untrusted, Everyone, &Member), "CheckTokenMembership failed: %lu\n", GetLastError());
    ok(Member == TRUE, "Untrusted token: Everyone member %d\n", Member);
    Member = 2;
    ok(CheckTokenMembership(Low, Nobody, &Member), "CheckTokenMembership failed: %lu\n", GetLastError());
    ok(Member == FALSE, "Low token: nobody member %d\n", Member);
    FreeSid(Everyone);
    FreeSid(Nobody);
    CloseHandle(Low);
    CloseHandle(Untrusted);
}

START_TEST(AccessCheckMandatory)
{
    /* Not in the headers for this API version: Windows Vista and later */
    pAddMandatoryAce = (void *)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "AddMandatoryAce");
    if (!pAddMandatoryAce)
    {
        skip("No AddMandatoryAce\n");
        return;
    }
    TestLevels();
    TestResultList();
    TestAnonymous();
    TestMembership();
}
