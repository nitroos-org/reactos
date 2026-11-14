/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     OWNER RIGHTS (S-1-3-4) in AccessCheck and AccessCheckByType*
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * AccessCheck on a private security descriptor whose owner and group are the token user (or
 * another SID), through an impersonation copy of the process token.
 *
 * The expectations follow Microsoft's public documentation of the OWNER RIGHTS SID (Windows
 * Vista and later): an ACE for OWNER RIGHTS applies to the owner of the object, and when the
 * DACL has one for the object, the owner does not get its implicit READ_CONTROL | WRITE_DAC;
 * an inherit-only ACE does not apply to the object. Not measured on Windows yet (the rows
 * marked "verify" are points the documentation leaves open): see the harness evidence
 * ownerrights-20261114.
 */

#define RC READ_CONTROL
#define WD WRITE_DAC

static GENERIC_MAPPING Mapping = { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2,
                                   STANDARD_RIGHTS_EXECUTE | 4, STANDARD_RIGHTS_ALL | 7 };

static GUID RootGuid = { 0x5d2f8a31, 0x41c7, 0x4b0e, { 0x8e, 0x33, 0x52, 0x0c, 0x6a, 0x10, 0x00, 0x01 } };
static GUID ChildGuid = { 0x5d2f8a31, 0x41c7, 0x4b0e, { 0x8e, 0x33, 0x52, 0x0c, 0x6a, 0x10, 0x00, 0x02 } };

typedef enum { CALL_PLAIN, CALL_BYTYPE, CALL_RESULTLIST } CALL_KIND;

static PSID OwnerRights, Everyone, OtherSid, User;

typedef struct
{
    char Type;          /* A allow, D deny, O allowed object ACE without an object type */
    DWORD Flags;
    ACCESS_MASK Mask;
    PSID *Sid;
} ACE_SPEC;

#define MAX_ACES 4

static BOOL BuildDacl(PACL Acl, DWORD AclSize, const ACE_SPEC *Aces, int Count)
{
    int i;
    BOOL Ret = TRUE;

    if (!InitializeAcl(Acl, AclSize, ACL_REVISION_DS))
        return FALSE;
    for (i = 0; i < Count && Ret; i++)
    {
        switch (Aces[i].Type)
        {
            case 'A':
                Ret = AddAccessAllowedAceEx(Acl, ACL_REVISION_DS, Aces[i].Flags, Aces[i].Mask, *Aces[i].Sid);
                break;
            case 'D':
                Ret = AddAccessDeniedAceEx(Acl, ACL_REVISION_DS, Aces[i].Flags, Aces[i].Mask, *Aces[i].Sid);
                break;
            case 'O':
                Ret = AddAccessAllowedObjectAce(Acl, ACL_REVISION_DS, Aces[i].Flags, Aces[i].Mask, NULL, NULL,
                                                *Aces[i].Sid);
                break;
            default:
                Ret = FALSE;
        }
    }
    return Ret;
}

static void Check_(int Line, HANDLE Token, CALL_KIND Kind, PSID Owner, const ACE_SPEC *Aces, int Count,
                   ACCESS_MASK Desired, BOOL ExpectedStatus, ACCESS_MASK ExpectedGranted)
{
    SECURITY_DESCRIPTOR Sd;
    union { ACL Acl; BYTE Buffer[512]; } AclBuffer;
    union { PRIVILEGE_SET Set; ULONG_PTR Align; BYTE Buffer[256]; } PrivilegeSet;
    DWORD PrivilegeSetLength = sizeof(PrivilegeSet);
    OBJECT_TYPE_LIST List[2];
    DWORD Granted[2] = { 0xdeadbeef, 0xdeadbeef };
    DWORD Status[2] = { 7, 7 };
    BOOL Ret;
    int i, Entries;

    if (!BuildDacl(&AclBuffer.Acl, sizeof(AclBuffer), Aces, Count))
    {
        ok_(__FILE__, Line)(0, "building the DACL failed: %lu\n", GetLastError());
        return;
    }
    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Sd, Owner, FALSE);
    SetSecurityDescriptorGroup(&Sd, Owner, FALSE);
    SetSecurityDescriptorDacl(&Sd, TRUE, &AclBuffer.Acl, FALSE);

    List[0].Level = ACCESS_OBJECT_GUID;
    List[0].Sbz = 0;
    List[0].ObjectType = &RootGuid;
    List[1].Level = ACCESS_PROPERTY_SET_GUID;
    List[1].Sbz = 0;
    List[1].ObjectType = &ChildGuid;

    SetLastError(0xdead);
    switch (Kind)
    {
        case CALL_PLAIN:
            Ret = AccessCheck(&Sd, Token, Desired, &Mapping, &PrivilegeSet.Set,
                              &PrivilegeSetLength, &Granted[0], (PBOOL)&Status[0]);
            Entries = 1;
            break;
        case CALL_BYTYPE:
            Ret = AccessCheckByType(&Sd, NULL, Token, Desired, List, 2, &Mapping, &PrivilegeSet.Set,
                                    &PrivilegeSetLength, &Granted[0], (PBOOL)&Status[0]);
            Entries = 1;
            break;
        default:
            Ret = AccessCheckByTypeResultList(&Sd, NULL, Token, Desired, List, 2, &Mapping,
                                              &PrivilegeSet.Set, &PrivilegeSetLength, Granted, (void *)Status);
            Entries = 2;
            break;
    }
    ok_(__FILE__, Line)(Ret, "call %d desired %08lx: failed with %lu\n", Kind, Desired, GetLastError());
    if (!Ret)
        return;

    for (i = 0; i < Entries; i++)
    {
        /* AccessCheckByTypeResultList reports an error code per entry, the others a BOOL */
        BOOL Allowed = (Kind == CALL_RESULTLIST) ? (Status[i] == ERROR_SUCCESS) : (Status[i] != FALSE);

        ok_(__FILE__, Line)(Allowed == ExpectedStatus, "call %d entry %d desired %08lx: status %lu, expected %s\n",
                            Kind, i, Desired, Status[i], ExpectedStatus ? "granted" : "denied");
        if (ExpectedStatus)
        {
            ok_(__FILE__, Line)(Granted[i] == ExpectedGranted, "call %d entry %d desired %08lx: granted %08lx, expected %08lx\n",
                                Kind, i, Desired, Granted[i], ExpectedGranted);
        }
    }
}

#define CHECK(Token, Kind, Owner, Aces, Desired, Status, Granted) \
    Check_(__LINE__, Token, Kind, Owner, Aces, (int)(sizeof(Aces) / sizeof((Aces)[0])), Desired, Status, Granted)

static void TestPlain(HANDLE Token, CALL_KIND Kind)
{
    const ACCESS_MASK All = STANDARD_RIGHTS_ALL | 7;

    /* No OWNER RIGHTS ACE: implicit READ_CONTROL | WRITE_DAC */
    {
        ACE_SPEC Aces[] = { { 'A', 0, 1, &Everyone } };
        CHECK(Token, Kind, User, Aces, RC, TRUE, RC);
        CHECK(Token, Kind, User, Aces, WD, TRUE, WD);
        CHECK(Token, Kind, User, Aces, 2, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, RC | WD | 1);
    }

    /* Allow OWNER RIGHTS: what it grants, no implicit rights */
    {
        ACE_SPEC Aces[] = { { 'A', 0, 1, &OwnerRights } };
        CHECK(Token, Kind, User, Aces, 1, TRUE, 1);
        CHECK(Token, Kind, User, Aces, RC, FALSE, 0);
        CHECK(Token, Kind, User, Aces, WD, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, 1);
    }
    {
        ACE_SPEC Aces[] = { { 'A', 0, RC | 2, &OwnerRights } };
        CHECK(Token, Kind, User, Aces, RC, TRUE, RC);
        CHECK(Token, Kind, User, Aces, WD, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, RC | 2);
    }
    {
        ACE_SPEC Aces[] = { { 'A', 0, GENERIC_ALL, &OwnerRights } };
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, All);
    }

    /* Inherit-only OWNER RIGHTS ACE: does not apply, the implicit rights stay */
    {
        ACE_SPEC Aces[] = { { 'A', OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, 1, &OwnerRights },
                            { 'A', 0, 2, &Everyone } };
        CHECK(Token, Kind, User, Aces, RC, TRUE, RC);
        CHECK(Token, Kind, User, Aces, 1, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, RC | WD | 2);
    }

    /* Deny OWNER RIGHTS (verify) */
    {
        ACE_SPEC Aces[] = { { 'D', 0, WD, &OwnerRights }, { 'A', 0, RC | WD | 1, &Everyone } };
        CHECK(Token, Kind, User, Aces, WD, FALSE, 0);
        CHECK(Token, Kind, User, Aces, RC, TRUE, RC);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, RC | 1);
    }
    {
        ACE_SPEC Aces[] = { { 'D', 0, 2, &OwnerRights }, { 'A', 0, 1, &Everyone } };
        CHECK(Token, Kind, User, Aces, RC, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, 1);
    }

    /* Not the owner: OWNER RIGHTS ACEs grant nothing */
    {
        ACE_SPEC Aces[] = { { 'A', 0, GENERIC_ALL, &OwnerRights }, { 'A', 0, 1, &Everyone } };
        CHECK(Token, Kind, OtherSid, Aces, 1, TRUE, 1);
        CHECK(Token, Kind, OtherSid, Aces, 2, FALSE, 0);
        CHECK(Token, Kind, OtherSid, Aces, RC, FALSE, 0);
        CHECK(Token, Kind, OtherSid, Aces, MAXIMUM_ALLOWED, TRUE, 1);
    }

    /* ACE order: OWNER RIGHTS allow before a deny for the user */
    {
        ACE_SPEC Aces[] = { { 'A', 0, RC | 1, &OwnerRights }, { 'D', 0, 3, &User }, { 'A', 0, 2, &Everyone } };
        CHECK(Token, Kind, User, Aces, 1, TRUE, 1);
        CHECK(Token, Kind, User, Aces, 2, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, RC | 1);
    }

    /* Allowed object ACE without an object type for OWNER RIGHTS (verify) */
    {
        ACE_SPEC Aces[] = { { 'O', 0, 1, &OwnerRights } };
        CHECK(Token, Kind, User, Aces, 1, TRUE, 1);
        CHECK(Token, Kind, User, Aces, RC, FALSE, 0);
        CHECK(Token, Kind, User, Aces, MAXIMUM_ALLOWED, TRUE, 1);
    }
}

static HANDLE Impersonation(HANDLE Primary)
{
    HANDLE Token = NULL;
    ok(DuplicateToken(Primary, SecurityImpersonation, &Token), "DuplicateToken failed: %lu\n", GetLastError());
    return Token;
}

START_TEST(OwnerRightsAccess)
{
    SID_IDENTIFIER_AUTHORITY CreatorAuthority = { SECURITY_CREATOR_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    union { TOKEN_USER User; ULONG_PTR Align; BYTE Buffer[512]; } UserBuffer;
    DWORD Length;
    HANDLE Process = NULL, Token, Primary2 = NULL, Restricted;
    SID_AND_ATTRIBUTES Restrict[2];

    ok(AllocateAndInitializeSid(&CreatorAuthority, 1, 4 /* SECURITY_CREATOR_OWNER_RIGHTS_RID */,
                                0, 0, 0, 0, 0, 0, 0, &OwnerRights), "OWNER RIGHTS SID\n");
    ok(AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &Everyone),
       "Everyone SID\n");
    ok(AllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &OtherSid),
       "LocalService SID\n");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }
    if (!GetTokenInformation(Process, TokenUser, &UserBuffer, sizeof(UserBuffer), &Length))
    {
        skip("TokenUser failed: %lu\n", GetLastError());
        CloseHandle(Process);
        return;
    }
    User = UserBuffer.User.User.Sid;
    ok(!EqualSid(User, OtherSid), "running as LocalService\n");

    Token = Impersonation(Process);
    if (Token)
    {
        TestPlain(Token, CALL_PLAIN);
        TestPlain(Token, CALL_BYTYPE);
        TestPlain(Token, CALL_RESULTLIST);
        CloseHandle(Token);
    }

    /*
     * A restricted token whose restricting SIDs are the user and Everyone: an OWNER RIGHTS ACE
     * applies in both passes (the owner is a restricting SID too) (verify).
     */
    Restrict[0].Sid = User;
    Restrict[0].Attributes = 0;
    Restrict[1].Sid = Everyone;
    Restrict[1].Attributes = 0;
    if (CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 2, Restrict, &Primary2))
    {
        Restricted = Impersonation(Primary2);
        if (Restricted)
        {
            ACE_SPEC Aces[] = { { 'A', 0, RC | 1, &OwnerRights } };
            ACE_SPEC Aces2[] = { { 'A', 0, 1, &OwnerRights }, { 'A', 0, 2, &Everyone } };
            CHECK(Restricted, CALL_PLAIN, User, Aces, RC | 1, TRUE, RC | 1);
            CHECK(Restricted, CALL_PLAIN, User, Aces, WD, FALSE, 0);
            CHECK(Restricted, CALL_PLAIN, User, Aces, MAXIMUM_ALLOWED, TRUE, RC | 1);
            CHECK(Restricted, CALL_PLAIN, User, Aces2, MAXIMUM_ALLOWED, TRUE, 3);
            CloseHandle(Restricted);
        }
        CloseHandle(Primary2);
    }
    else
    {
        ok(0, "CreateRestrictedToken failed: %lu\n", GetLastError());
    }

    /* Restricted to Everyone only: the owner is not a restricting SID, OWNER RIGHTS grants nothing (verify) */
    Restrict[0].Sid = Everyone;
    if (CreateRestrictedToken(Process, 0, 0, NULL, 0, NULL, 1, Restrict, &Primary2))
    {
        Restricted = Impersonation(Primary2);
        if (Restricted)
        {
            ACE_SPEC Aces[] = { { 'A', 0, RC | 1, &OwnerRights }, { 'A', 0, 2, &Everyone } };
            CHECK(Restricted, CALL_PLAIN, User, Aces, 1, FALSE, 0);
            CHECK(Restricted, CALL_PLAIN, User, Aces, RC, FALSE, 0);
            CHECK(Restricted, CALL_PLAIN, User, Aces, MAXIMUM_ALLOWED, TRUE, 2);
            CloseHandle(Restricted);
        }
        CloseHandle(Primary2);
    }
    else
    {
        ok(0, "CreateRestrictedToken failed: %lu\n", GetLastError());
    }

    CloseHandle(Process);
    FreeSid(OwnerRights);
    FreeSid(Everyone);
    FreeSid(OtherSid);
}
