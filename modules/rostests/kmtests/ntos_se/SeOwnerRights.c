/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test for OWNER RIGHTS (S-1-3-4) in SeAccessCheck
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The expectations follow Microsoft's public documentation of the OWNER RIGHTS
 * SID (Windows Vista and later): an ACE for it applies to the owner of the object,
 * and when the DACL has one for the object, the owner's implicit READ_CONTROL and
 * WRITE_DAC are not granted. Rows marked "verify" are points the documentation
 * leaves open (not measured on Windows).
 */

#include <kmt_test.h>

#define OR_RC READ_CONTROL
#define OR_WD WRITE_DAC

static GENERIC_MAPPING OrMapping =
{
    STANDARD_RIGHTS_READ    | 0x0001,
    STANDARD_RIGHTS_WRITE   | 0x0002,
    STANDARD_RIGHTS_EXECUTE | 0x0004,
    STANDARD_RIGHTS_ALL     | 0x0007,
};

static SID OwnerRightsSid = { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_RIGHTS_RID } };

typedef struct _OR_ACE
{
    UCHAR Type;
    UCHAR Flags;
    ACCESS_MASK Mask;
    PSID Sid;
} OR_ACE, *POR_ACE;

#define OR_ALLOW        ACCESS_ALLOWED_ACE_TYPE
#define OR_DENY         ACCESS_DENIED_ACE_TYPE
#define OR_ALLOW_OBJ    ACCESS_ALLOWED_OBJECT_ACE_TYPE

typedef struct _OR_SD
{
    SECURITY_DESCRIPTOR Sd;
    ULONG_PTR Align;
    UCHAR AclBuffer[512];
} OR_SD, *POR_SD;

static
POR_SD
OrMakeSd(
    _In_ PSID Owner,
    _In_ ULONG AceCount,
    _In_reads_(AceCount) const OR_ACE *Aces)
{
    POR_SD OrSd;
    PACL Acl;
    NTSTATUS Status;
    ULONG i;
    UCHAR AceBuffer[sizeof(ACCESS_ALLOWED_OBJECT_ACE) + SECURITY_MAX_SID_SIZE];
    PACE_HEADER Header = (PACE_HEADER)AceBuffer;
    USHORT AceSize;

    OrSd = ExAllocatePoolWithTag(PagedPool, sizeof(*OrSd), 'rOmK');
    if (!OrSd)
        return NULL;

    Acl = (PACL)OrSd->AclBuffer;
    Status = RtlCreateAcl(Acl, sizeof(OrSd->AclBuffer), ACL_REVISION4);
    ok_eq_hex(Status, STATUS_SUCCESS);

    for (i = 0; i < AceCount; i++)
    {
        RtlZeroMemory(AceBuffer, sizeof(AceBuffer));
        Header->AceType = Aces[i].Type;
        Header->AceFlags = Aces[i].Flags;
        if (Aces[i].Type == OR_ALLOW_OBJ)
        {
            /* No object type, no inherited object type: applies as a plain allow ACE */
            PACCESS_ALLOWED_OBJECT_ACE ObjAce = (PACCESS_ALLOWED_OBJECT_ACE)AceBuffer;
            ObjAce->Mask = Aces[i].Mask;
            ObjAce->Flags = 0;
            AceSize = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType) + RtlLengthSid(Aces[i].Sid));
            RtlCopySid(RtlLengthSid(Aces[i].Sid), (PSID)&ObjAce->ObjectType, Aces[i].Sid);
        }
        else
        {
            PACCESS_ALLOWED_ACE PlainAce = (PACCESS_ALLOWED_ACE)AceBuffer;
            PlainAce->Mask = Aces[i].Mask;
            AceSize = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Aces[i].Sid));
            RtlCopySid(RtlLengthSid(Aces[i].Sid), (PSID)&PlainAce->SidStart, Aces[i].Sid);
        }
        Header->AceSize = AceSize;
        Status = RtlAddAce(Acl, ACL_REVISION4, MAXULONG, Header, AceSize);
        ok_eq_hex(Status, STATUS_SUCCESS);
    }

    Status = RtlCreateSecurityDescriptor(&OrSd->Sd, SECURITY_DESCRIPTOR_REVISION);
    ok_eq_hex(Status, STATUS_SUCCESS);
    /* Owner NULL builds a descriptor without an owner (and group) */
    Status = RtlSetOwnerSecurityDescriptor(&OrSd->Sd, Owner, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlSetGroupSecurityDescriptor(&OrSd->Sd, Owner, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = RtlSetDaclSecurityDescriptor(&OrSd->Sd, TRUE, Acl, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    return OrSd;
}

static
VOID
OrCheck_(
    _In_ PCSTR FileAndLine,
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext,
    _In_ POR_SD OrSd,
    _In_ ACCESS_MASK Desired,
    _In_ BOOLEAN ExpectedResult,
    _In_ ACCESS_MASK ExpectedGranted)
{
    BOOLEAN Result;
    ACCESS_MASK Granted = 0xdeadbeef;
    NTSTATUS AccessStatus = 0xdeadbeef;
    PPRIVILEGE_SET Privileges = NULL;

    if (!OrSd)
    {
        KmtOk(FALSE, FileAndLine, "no descriptor\n");
        return;
    }

    Result = SeAccessCheck(&OrSd->Sd,
                           SubjectContext,
                           FALSE,
                           Desired,
                           0,
                           &Privileges,
                           &OrMapping,
                           UserMode,
                           &Granted,
                           &AccessStatus);
    if (Privileges)
        SeFreePrivileges(Privileges);

    KmtOk(Result == ExpectedResult, FileAndLine,
          "desired 0x%lx: result %u, expected %u (granted 0x%lx, status 0x%lx)\n",
          Desired, Result, ExpectedResult, Granted, AccessStatus);
    if (ExpectedResult)
    {
        KmtOk(Granted == ExpectedGranted, FileAndLine,
              "desired 0x%lx: granted 0x%lx, expected 0x%lx\n", Desired, Granted, ExpectedGranted);
        KmtOk(AccessStatus == STATUS_SUCCESS, FileAndLine,
              "desired 0x%lx: status 0x%lx\n", Desired, AccessStatus);
    }
    else
    {
        KmtOk(AccessStatus == STATUS_ACCESS_DENIED, FileAndLine,
              "desired 0x%lx: status 0x%lx, expected STATUS_ACCESS_DENIED\n", Desired, AccessStatus);
    }
}

#define OR_STRINGIZE(x) KMT_STRINGIZE(x)
#define OrCheck(Ctx, Sd, Desired, Result, Granted) \
    OrCheck_(__FILE__ ":" OR_STRINGIZE(__LINE__), Ctx, Sd, Desired, Result, Granted)

static
BOOLEAN
OrTokenHasEnabledGroup(
    _In_ PACCESS_TOKEN Token,
    _In_ PSID Sid)
{
    PTOKEN_GROUPS Groups = NULL;
    NTSTATUS Status;
    ULONG i;
    BOOLEAN Found = FALSE;

    Status = SeQueryInformationToken(Token, TokenGroups, (PVOID*)&Groups);
    if (!NT_SUCCESS(Status) || !Groups)
        return FALSE;
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if (RtlEqualSid(Groups->Groups[i].Sid, Sid) &&
            (Groups->Groups[i].Attributes & SE_GROUP_ENABLED))
        {
            Found = TRUE;
            break;
        }
    }
    ExFreePool(Groups);
    return Found;
}

static
VOID
OrBench(
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext,
    _In_ PCSTR Name,
    _In_ POR_SD OrSd,
    _In_ ACCESS_MASK Desired)
{
    LARGE_INTEGER Frequency, Start, End;
    ULONG i, Loops = 1000000;
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    PPRIVILEGE_SET Privileges;
    ULONG Passed = 0;
    ULONGLONG Ns;

    if (!OrSd)
        return;

    Start = KeQueryPerformanceCounter(&Frequency);
    for (i = 0; i < Loops; i++)
    {
        Privileges = NULL;
        if (SeAccessCheck(&OrSd->Sd, SubjectContext, FALSE, Desired, 0, &Privileges,
                          &OrMapping, UserMode, &Granted, &AccessStatus))
        {
            Passed++;
        }
        if (Privileges)
            SeFreePrivileges(Privileges);
    }
    End = KeQueryPerformanceCounter(NULL);

    Ns = (ULONGLONG)(End.QuadPart - Start.QuadPart) * 1000000000ULL / (ULONGLONG)Frequency.QuadPart;
    trace("ORBENCH %s: %lu calls, %lu granted, %I64u ns total, %I64u ps/call\n",
          Name, Loops, Passed, Ns, Ns * 1000ULL / Loops);
}

START_TEST(SeOwnerRights)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PACCESS_TOKEN Token;
    PTOKEN_USER UserInfo = NULL;
    NTSTATUS Status;
    PSID User, World, Other, Admins;
    POR_SD Sd;
    const ACCESS_MASK All = STANDARD_RIGHTS_ALL | 0x7;

    SeCaptureSubjectContext(&SubjectContext);
    Token = SeQuerySubjectContextToken(&SubjectContext);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID*)&UserInfo);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status) && UserInfo, "No token user\n"))
    {
        SeReleaseSubjectContext(&SubjectContext);
        return;
    }

    User = UserInfo->User.Sid;
    World = SeExports->SeWorldSid;
    Other = SeExports->SeLocalServiceSid;
    Admins = SeExports->SeAliasAdminsSid;
    ok(!RtlEqualSid(User, Other), "test runs as LocalService\n");

    /* 1. No OWNER RIGHTS ACE: the owner gets READ_CONTROL and WRITE_DAC implicitly */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, 0x1, World } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_RC, TRUE, OR_RC);
        OrCheck(&SubjectContext, Sd, OR_WD, TRUE, OR_WD);
        OrCheck(&SubjectContext, Sd, OR_RC | OR_WD | 0x1, TRUE, OR_RC | OR_WD | 0x1);
        OrCheck(&SubjectContext, Sd, 0x2, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | OR_WD | 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 2. Allow OWNER RIGHTS 0x1: the owner gets 0x1 and nothing implicitly */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, 0x1, &OwnerRightsSid } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, 0x1, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, OR_RC, FALSE, 0);
        OrCheck(&SubjectContext, Sd, OR_WD, FALSE, 0);
        OrCheck(&SubjectContext, Sd, OR_RC | 0x1, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED | OR_RC, FALSE, 0);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 3. Allow OWNER RIGHTS READ_CONTROL | 0x2: READ_CONTROL yes, WRITE_DAC no */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, OR_RC | 0x2, &OwnerRightsSid } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_RC, TRUE, OR_RC);
        OrCheck(&SubjectContext, Sd, OR_WD, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | 0x2);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 4. Allow OWNER RIGHTS GENERIC_ALL: mapped */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, GENERIC_ALL, &OwnerRightsSid } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_WD | 0x7, TRUE, OR_WD | 0x7);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, All);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 5. Inherit-only OWNER RIGHTS ACE: does not apply, the implicit rights stay */
    {
        OR_ACE Aces[] = { { OR_ALLOW, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, 0x1, &OwnerRightsSid },
                          { OR_ALLOW, 0, 0x2, World } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_RC, TRUE, OR_RC);
        OrCheck(&SubjectContext, Sd, OR_WD, TRUE, OR_WD);
        OrCheck(&SubjectContext, Sd, 0x1, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | OR_WD | 0x2);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 6. Deny OWNER RIGHTS WRITE_DAC, Everyone allowed READ_CONTROL | WRITE_DAC | 0x1 (verify) */
    {
        OR_ACE Aces[] = { { OR_DENY, 0, OR_WD, &OwnerRightsSid },
                          { OR_ALLOW, 0, OR_RC | OR_WD | 0x1, World } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_WD, FALSE, 0);
        OrCheck(&SubjectContext, Sd, OR_RC, TRUE, OR_RC);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 7. A deny OWNER RIGHTS ACE alone also takes the implicit rights (verify) */
    {
        OR_ACE Aces[] = { { OR_DENY, 0, 0x2, &OwnerRightsSid },
                          { OR_ALLOW, 0, 0x1, World } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_RC, FALSE, 0);
        OrCheck(&SubjectContext, Sd, 0x1, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 8. Not the owner: an OWNER RIGHTS ACE grants nothing */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, GENERIC_ALL, &OwnerRightsSid },
                          { OR_ALLOW, 0, 0x1, World } };
        Sd = OrMakeSd(Other, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, 0x1, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, 0x2, FALSE, 0);
        OrCheck(&SubjectContext, Sd, OR_RC, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 9. OWNER RIGHTS allow before a deny for the user: allow wins by order */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, OR_RC | 0x1, &OwnerRightsSid },
                          { OR_DENY, 0, 0x1 | 0x2, User },
                          { OR_ALLOW, 0, 0x2, World } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, 0x1, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, 0x2, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 10. An allowed object ACE without an object type for OWNER RIGHTS (verify) */
    {
        OR_ACE Aces[] = { { OR_ALLOW_OBJ, 0, 0x1, &OwnerRightsSid } };
        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, 0x1, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, OR_RC, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 11. The owner is a group of the token (Administrators) */
    if (!skip(OrTokenHasEnabledGroup(Token, Admins), "Administrators not enabled in the token\n"))
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, 0x1, &OwnerRightsSid } };
        Sd = OrMakeSd(Admins, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, 0x1, TRUE, 0x1);
        OrCheck(&SubjectContext, Sd, OR_RC, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    /* 12. Kernel mode: everything, as before */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, 0x1, &OwnerRightsSid } };
        BOOLEAN Result;
        ACCESS_MASK Granted = 0;
        NTSTATUS AccessStatus = 0xdeadbeef;
        PPRIVILEGE_SET Privileges = NULL;

        Sd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        if (Sd)
        {
            Result = SeAccessCheck(&Sd->Sd, &SubjectContext, FALSE, OR_RC, 0, &Privileges,
                                   &OrMapping, KernelMode, &Granted, &AccessStatus);
            ok(Result == TRUE, "kernel mode result %u\n", Result);
            ok_eq_hex(Granted, OR_RC);
            ok_eq_hex(AccessStatus, STATUS_SUCCESS);
            if (Privileges) SeFreePrivileges(Privileges);
            ExFreePoolWithTag(Sd, 'rOmK');
        }
    }

    /* 13. A descriptor without an owner: the DACL decides, OWNER RIGHTS ACEs apply to nobody, no crash */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, 0x1, &OwnerRightsSid },
                          { OR_ALLOW, 0, OR_RC | 0x2, World } };
        BOOLEAN Result;
        ACCESS_MASK Granted = 0;
        NTSTATUS AccessStatus = 0xdeadbeef;
        PPRIVILEGE_SET Privileges = NULL;

        Sd = OrMakeSd(NULL, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_RC, TRUE, OR_RC);
        OrCheck(&SubjectContext, Sd, OR_WD, FALSE, 0);
        OrCheck(&SubjectContext, Sd, OR_RC | OR_WD, FALSE, 0);
        OrCheck(&SubjectContext, Sd, 0x2, TRUE, 0x2);
        OrCheck(&SubjectContext, Sd, 0x1, FALSE, 0);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | 0x2);
        if (Sd)
        {
            /* Kernel mode grants everything without looking at the descriptor */
            Result = SeAccessCheck(&Sd->Sd, &SubjectContext, FALSE, OR_WD, 0, &Privileges,
                                   &OrMapping, KernelMode, &Granted, &AccessStatus);
            ok(Result == TRUE, "kernel mode result %u\n", Result);
            ok_eq_hex(Granted, OR_WD);
            ok_eq_hex(AccessStatus, STATUS_SUCCESS);
            if (Privileges) SeFreePrivileges(Privileges);
            ExFreePoolWithTag(Sd, 'rOmK');
        }
    }

    /* 14. Without an owner and with the DACL granting everything: MAXIMUM_ALLOWED gives the DACL's rights only */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, OR_RC | OR_WD | 0x1, World } };
        Sd = OrMakeSd(NULL, RTL_NUMBER_OF(Aces), Aces);
        OrCheck(&SubjectContext, Sd, OR_WD, TRUE, OR_WD);
        OrCheck(&SubjectContext, Sd, OR_RC | OR_WD, TRUE, OR_RC | OR_WD);
        OrCheck(&SubjectContext, Sd, MAXIMUM_ALLOWED, TRUE, OR_RC | OR_WD | 0x1);
        if (Sd) ExFreePoolWithTag(Sd, 'rOmK');
    }

    ExFreePool(UserInfo);
    SeReleaseSubjectContext(&SubjectContext);
}

/*
 * Cost of the access check for a typical DACL without OWNER RIGHTS. Timing only,
 * no assertion: a hidden test ("-" in the list), run by name when wanted.
 */
START_TEST(SeOwnerRightsPerf)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PACCESS_TOKEN Token;
    PTOKEN_USER UserInfo = NULL;
    NTSTATUS Status;
    PSID User, World, Other, Admins, System;

    SeCaptureSubjectContext(&SubjectContext);
    Token = SeQuerySubjectContextToken(&SubjectContext);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID*)&UserInfo);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (skip(NT_SUCCESS(Status) && UserInfo, "No token user\n"))
    {
        SeReleaseSubjectContext(&SubjectContext);
        return;
    }

    User = UserInfo->User.Sid;
    World = SeExports->SeWorldSid;
    Other = SeExports->SeLocalServiceSid;
    Admins = SeExports->SeAliasAdminsSid;
    System = SeExports->SeLocalSystemSid;

    /* A typical DACL without OWNER RIGHTS (SYSTEM, Administrators, user, Everyone) */
    {
        OR_ACE Aces[] = { { OR_ALLOW, 0, GENERIC_ALL, System },
                          { OR_ALLOW, 0, GENERIC_ALL, Admins },
                          { OR_ALLOW, 0, GENERIC_READ, User },
                          { OR_ALLOW, 0, GENERIC_READ, World } };
        POR_SD OwnSd = OrMakeSd(User, RTL_NUMBER_OF(Aces), Aces);
        POR_SD OtherSd = OrMakeSd(Other, RTL_NUMBER_OF(Aces), Aces);

        OrBench(&SubjectContext, "owner-RC", OwnSd, OR_RC);
        OrBench(&SubjectContext, "owner-RC|1", OwnSd, OR_RC | 0x1);
        OrBench(&SubjectContext, "owner-MAX", OwnSd, MAXIMUM_ALLOWED);
        OrBench(&SubjectContext, "other-1", OtherSd, 0x1);
        OrBench(&SubjectContext, "other-MAX", OtherSd, MAXIMUM_ALLOWED);
        if (OwnSd) ExFreePoolWithTag(OwnSd, 'rOmK');
        if (OtherSd) ExFreePoolWithTag(OtherSd, 'rOmK');
    }

    ExFreePool(UserInfo);
    SeReleaseSubjectContext(&SubjectContext);
}
