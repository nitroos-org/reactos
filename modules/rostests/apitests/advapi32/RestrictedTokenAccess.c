/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Access checks for deny-only groups and restricting SIDs (CreateRestrictedToken)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Measured on Windows 10 22H2 as an elevated administrator, a 64-bit and a 32-bit process alike.
 * AccessCheck on a security descriptor whose owner and group are the SID given, with the DACL
 * given, through an impersonation copy of each token:
 *
 * - A token where BUILTIN\Administrators is deny-only (SidsToDisable, with or without
 *   DISABLE_MAX_PRIVILEGE, and LUA_TOKEN): CheckTokenMembership(Administrators) is FALSE; an
 *   Administrators owner gives no implicit READ_CONTROL or WRITE_DAC (an empty DACL grants
 *   nothing, MAXIMUM_ALLOWED included); an allow ACE for Administrators grants nothing; a deny
 *   ACE for Administrators still denies. The user owner keeps READ_CONTROL | WRITE_DAC.
 * - A token whose only restricting SID is Everyone: the rights are those that both the normal
 *   SIDs and the restricting SIDs are granted. An allow ACE for Administrators grants nothing,
 *   with MAXIMUM_ALLOWED as with an explicit request, and a user owner gets no implicit rights
 *   (the user is not a restricting SID). ReactOS used to hand out the union of the two passes
 *   for MAXIMUM_ALLOWED.
 * - Positive control, restricted to Everyone: allow(Everyone, read) + allow(User, read|write) grants
 *   read (the intersection; MAXIMUM_ALLOWED and an explicit read) and denies write;
 *   allow(Everyone, read|write) + allow(User, read) grants read | write (Everyone is a normal SID too);
 *   allow(User, read) alone grants nothing (harness evidence g5fix-20261106).
 *   Not covered: an object type list (AccessCheckByType). Windows 10 grants plain ACEs for a list; ReactOS
 *   grants nothing for a list with a plain or an object ACE, restricted or not, and the WoW64 thunk
 *   fails it, so the restricted branch for lists cannot be reached from a test yet.
 * - CheckTokenMembership with a primary token fails with ERROR_NO_IMPERSONATION_TOKEN.
 */

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif

static GENERIC_MAPPING Mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };

static ACCESS_MASK Check(HANDLE Token, PSID Owner, PACL Dacl, ACCESS_MASK Desired, int Line)
{
    SECURITY_DESCRIPTOR Sd;
    BYTE PrivilegeSet[256];
    DWORD PrivilegeSetLength = sizeof(PrivilegeSet);
    DWORD Granted = 0xdeadbeef;
    BOOL Status = 2, Ret;

    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Sd, Owner, FALSE);
    SetSecurityDescriptorGroup(&Sd, Owner, FALSE);
    SetSecurityDescriptorDacl(&Sd, TRUE, Dacl, FALSE);
    Ret = AccessCheck(&Sd, Token, Desired, &Mapping, (PPRIVILEGE_SET)PrivilegeSet, &PrivilegeSetLength,
                      &Granted, &Status);
    ok_(__FILE__, Line)(Ret, "AccessCheck failed: %lu\n", GetLastError());
    if (!Ret)
        return 0xffffffff;
    ok_(__FILE__, Line)(Status == (Granted != 0), "status %d, granted %08lx\n", Status, Granted);
    return Granted;
}

#define CHECK(Token, Owner, Dacl, Desired, Expected) \
    do { \
        ACCESS_MASK Got_ = Check(Token, Owner, Dacl, Desired, __LINE__); \
        ok(Got_ == (Expected), "%s: desired %08lx granted %08lx, expected %08lx\n", What, \
           (ACCESS_MASK)(Desired), Got_, (ACCESS_MASK)(Expected)); \
    } while (0)

static void TestToken(HANDLE Primary, PCSTR What, BOOL RestrictedToEveryone)
{
    BYTE Admins[SECURITY_MAX_SID_SIZE], UserBuffer[512], AclBuffer[256];
    DWORD Size = sizeof(Admins), Length;
    PSID User;
    PACL Acl = (PACL)AclBuffer;
    HANDLE Token;
    BOOL IsMember, Ret;

    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Admins, &Size);
    ok(GetTokenInformation(Primary, TokenUser, UserBuffer, sizeof(UserBuffer), &Length),
       "%s: TokenUser failed: %lu\n", What, GetLastError());
    User = ((PTOKEN_USER)UserBuffer)->User.Sid;

    IsMember = 2;
    SetLastError(0xdeadbeef);
    Ret = CheckTokenMembership(Primary, Admins, &IsMember);
    ok(!Ret && GetLastError() == ERROR_NO_IMPERSONATION_TOKEN, "%s: primary token: %d, error %lu\n", What, Ret,
       GetLastError());

    if (!DuplicateToken(Primary, SecurityImpersonation, &Token))
    {
        ok(0, "%s: DuplicateToken failed: %lu\n", What, GetLastError());
        return;
    }

    IsMember = 2;
    ok(CheckTokenMembership(Token, Admins, &IsMember), "%s: CheckTokenMembership failed: %lu\n", What, GetLastError());
    ok(IsMember == FALSE, "%s: member of Administrators: %d\n", What, IsMember);
    IsMember = 2;
    ok(CheckTokenMembership(Token, User, &IsMember), "%s: CheckTokenMembership(user) failed\n", What);
    ok(IsMember == !RestrictedToEveryone, "%s: member as the user: %d\n", What, IsMember);

    /* Administrators owner, empty DACL: no owner rights for a deny-only (or unrestricted) group */
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    CHECK(Token, Admins, Acl, READ_CONTROL, 0);
    CHECK(Token, Admins, Acl, WRITE_DAC, 0);
    CHECK(Token, Admins, Acl, MAXIMUM_ALLOWED, 0);

    /* User owner, empty DACL: the owner rights, unless the user is not a restricting SID */
    CHECK(Token, User, Acl, READ_CONTROL | WRITE_DAC, RestrictedToEveryone ? 0 : READ_CONTROL | WRITE_DAC);
    CHECK(Token, User, Acl, MAXIMUM_ALLOWED, RestrictedToEveryone ? 0 : READ_CONTROL | WRITE_DAC);

    /* An allow ACE for Administrators grants nothing */
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_GENERIC_READ, Admins);
    CHECK(Token, User, Acl, FILE_GENERIC_READ, 0);
    CHECK(Token, User, Acl, MAXIMUM_ALLOWED, RestrictedToEveryone ? 0 : READ_CONTROL | WRITE_DAC);

    /* A deny ACE for Administrators, then everything for the user */
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    AddAccessDeniedAce(Acl, ACL_REVISION, FILE_GENERIC_READ, Admins);
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_ALL_ACCESS, User);
    CHECK(Token, User, Acl, MAXIMUM_ALLOWED,
          RestrictedToEveryone ? 0 : ((FILE_ALL_ACCESS & ~FILE_GENERIC_READ) | READ_CONTROL));

    CloseHandle(Token);
}

static void Intersection(HANDLE Primary)
{
    BYTE Everyone[SECURITY_MAX_SID_SIZE], UserBuffer[512], AclBuffer[256];
    DWORD Size = sizeof(Everyone), Length;
    PSID User;
    PACL Acl = (PACL)AclBuffer;
    HANDLE Token;
    static const PCSTR What = "restricted to Everyone, positive control";

    CreateWellKnownSid(WinWorldSid, NULL, Everyone, &Size);
    ok(GetTokenInformation(Primary, TokenUser, UserBuffer, sizeof(UserBuffer), &Length), "TokenUser failed\n");
    User = ((PTOKEN_USER)UserBuffer)->User.Sid;
    if (!DuplicateToken(Primary, SecurityImpersonation, &Token))
    {
        ok(0, "DuplicateToken failed: %lu\n", GetLastError());
        return;
    }

    /* Both passes grant read, only the normal pass grants write: the intersection is read */
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_GENERIC_READ, Everyone);
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_GENERIC_READ | FILE_GENERIC_WRITE, User);
    CHECK(Token, User, Acl, MAXIMUM_ALLOWED, FILE_GENERIC_READ);
    CHECK(Token, User, Acl, FILE_GENERIC_READ, FILE_GENERIC_READ);
    CHECK(Token, User, Acl, FILE_GENERIC_WRITE, 0);

    /* Everyone is a normal SID of the user as well: read | write from both passes */
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_GENERIC_READ | FILE_GENERIC_WRITE, Everyone);
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_GENERIC_READ, User);
    CHECK(Token, User, Acl, MAXIMUM_ALLOWED, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
    CHECK(Token, User, Acl, FILE_GENERIC_WRITE, FILE_GENERIC_WRITE);

    /* Only the user is granted: the restricted pass grants nothing */
    InitializeAcl(Acl, sizeof(AclBuffer), ACL_REVISION);
    AddAccessAllowedAce(Acl, ACL_REVISION, FILE_GENERIC_READ, User);
    CHECK(Token, User, Acl, MAXIMUM_ALLOWED, 0);

    CloseHandle(Token);
}

START_TEST(RestrictedTokenAccess)
{
    BYTE Admins[SECURITY_MAX_SID_SIZE], Everyone[SECURITY_MAX_SID_SIZE];
    DWORD Size = sizeof(Admins), EveryoneSize = sizeof(Everyone);
    SID_AND_ATTRIBUTES Disable, Restrict;
    HANDLE Process, Token;
    BOOL IsAdmin = FALSE;

    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Admins, &Size);
    CreateWellKnownSid(WinWorldSid, NULL, Everyone, &EveryoneSize);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }
    if (!CheckTokenMembership(NULL, Admins, &IsAdmin) || !IsAdmin)
    {
        skip("The test needs an elevated administrator\n");
        CloseHandle(Process);
        return;
    }

    Disable.Sid = Admins;
    Disable.Attributes = 0;
    if (CreateRestrictedToken(Process, 0, 1, &Disable, 0, NULL, 0, NULL, &Token))
    {
        TestToken(Token, "deny-only Administrators", FALSE);
        CloseHandle(Token);
    }
    else
        ok(0, "CreateRestrictedToken failed: %lu\n", GetLastError());

    if (CreateRestrictedToken(Process, DISABLE_MAX_PRIVILEGE, 1, &Disable, 0, NULL, 0, NULL, &Token))
    {
        TestToken(Token, "DISABLE_MAX_PRIVILEGE, deny-only Administrators", FALSE);
        CloseHandle(Token);
    }
    else
        ok(0, "CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) failed: %lu\n", GetLastError());

    if (CreateRestrictedToken(Process, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &Token))
    {
        TestToken(Token, "LUA_TOKEN", FALSE);
        CloseHandle(Token);
    }
    else
        ok(0, "CreateRestrictedToken(LUA_TOKEN) failed: %lu\n", GetLastError());

    Restrict.Sid = Everyone;
    Restrict.Attributes = 0;
    if (CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 1, &Restrict, &Token))
    {
        /* Administrators stays enabled here, but is not a restricting SID */
        TestToken(Token, "restricted to Everyone", TRUE);
        Intersection(Token);
        CloseHandle(Token);
    }
    else
        ok(0, "CreateRestrictedToken(restricting Everyone) failed: %lu\n", GetLastError());

    CloseHandle(Process);
}
