/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SeAccessCheck: the OWNER RIGHTS scan and the mandatory label walk fail closed on a malformed ACL
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * SeAccessCheck takes the descriptor of its kernel-mode caller as it is (a file system's descriptor read from the
 * disk is not validated again). Two of its walks look for an entry that RESTRICTS: an OWNER RIGHTS ACE in the DACL
 * (it takes the implicit READ_CONTROL and WRITE_DAC away from the owner) and the mandatory label in the SACL.
 * Both stop at the first ACE that does not lie within the ACL. Cut short there, they used to answer as for an ACL
 * without the entry they look for: the owner got its implicit rights, and the object counted as labelled Medium.
 * A malformed ACL must never grant more than a well-formed one: cut short, they now answer as for the most
 * restrictive entry (an OWNER RIGHTS ACE; a System label with every policy). The descriptors here are built by
 * hand; what Windows does with them is not asserted (verify on the Windows reference).
 */

#include <kmt_test.h>

static GENERIC_MAPPING MsMapping =
{
    STANDARD_RIGHTS_READ    | 0x0001,
    STANDARD_RIGHTS_WRITE   | 0x0002,
    STANDARD_RIGHTS_EXECUTE | 0x0004,
    STANDARD_RIGHTS_ALL     | 0x0007,
};

#define MS_BUFFER 512

typedef struct _MS_SD
{
    SECURITY_DESCRIPTOR Sd;
    ULONG_PTR Align1;
    UCHAR Dacl[MS_BUFFER];
    ULONG_PTR Align2;
    UCHAR Sacl[MS_BUFFER];
} MS_SD, *PMS_SD;

static SID MsOwnerRightsSid = { SID_REVISION, 1, { SECURITY_CREATOR_SID_AUTHORITY }, { SECURITY_CREATOR_OWNER_RIGHTS_RID } };
static SID MsSystemLabelSid = { SID_REVISION, 1, { SECURITY_MANDATORY_LABEL_AUTHORITY }, { SECURITY_MANDATORY_SYSTEM_RID } };
static SID MsLocalServiceSid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SERVICE_RID } };

/* An ACE of any type with a mask and a SID at Offset of an ACL buffer; AceSize as given (rows make bad ones) */
static
VOID
MsPutAce(
    _Inout_ PUCHAR Acl,
    _In_ ULONG Offset,
    _In_ UCHAR Type,
    _In_ USHORT AceSize,
    _In_ ACCESS_MASK Mask,
    _In_ PSID Sid)
{
    PACCESS_ALLOWED_ACE Ace = (PACCESS_ALLOWED_ACE)(Acl + Offset);

    Ace->Header.AceType = Type;
    Ace->Header.AceFlags = 0;
    Ace->Header.AceSize = AceSize;
    RtlCopyMemory(&Ace->Mask, &Mask, sizeof(Mask));
    RtlCopyMemory((PUCHAR)Ace + FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart), Sid, RtlLengthSid(Sid));
}

static
VOID
MsInitAcl(
    _Out_ PUCHAR Buffer,
    _In_ USHORT AclSize,
    _In_ USHORT AceCount)
{
    PACL Acl = (PACL)Buffer;

    RtlZeroMemory(Buffer, MS_BUFFER);
    Acl->AclRevision = ACL_REVISION;
    Acl->AclSize = AclSize;
    Acl->AceCount = AceCount;
}

/* A descriptor owned by Owner, with the DACL of the buffer and, if bSacl, the SACL of the buffer */
static
VOID
MsInitSd(
    _Inout_ PMS_SD MsSd,
    _In_ PSID Owner,
    _In_ BOOLEAN bSacl)
{
    RtlCreateSecurityDescriptor(&MsSd->Sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&MsSd->Sd, Owner, FALSE);
    RtlSetGroupSecurityDescriptor(&MsSd->Sd, Owner, FALSE);
    RtlSetDaclSecurityDescriptor(&MsSd->Sd, TRUE, (PACL)MsSd->Dacl, FALSE);
    if (bSacl)
        RtlSetSaclSecurityDescriptor(&MsSd->Sd, TRUE, (PACL)MsSd->Sacl, FALSE);
}

#define MS_STRINGIZE(x) KMT_STRINGIZE(x)
#define MsExpect(Ctx, Sd, Desired, ExpResult, ExpGranted) MsExpect_(__FILE__ ":" MS_STRINGIZE(__LINE__), Ctx, Sd, Desired, ExpResult, ExpGranted)
static
VOID
MsExpect_(
    _In_ PCSTR FileAndLine,
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext,
    _In_ PMS_SD MsSd,
    _In_ ACCESS_MASK Desired,
    _In_ BOOLEAN ExpectedResult,
    _In_ ACCESS_MASK ExpectedGranted)
{
    PPRIVILEGE_SET Privileges = NULL;
    ACCESS_MASK Granted = 0xdeadbeef;
    NTSTATUS AccessStatus = 0xdeadbeef;
    BOOLEAN Result;

    Result = SeAccessCheck(&MsSd->Sd, SubjectContext, FALSE, Desired, 0, &Privileges, &MsMapping, UserMode,
                           &Granted, &AccessStatus);
    if (Privileges)
        SeFreePrivileges(Privileges);
    KmtOk(Result == ExpectedResult, FileAndLine, "desired 0x%lx: result %u (granted 0x%lx), expected %u\n",
          Desired, Result, Granted, ExpectedResult);
    if (ExpectedResult && Result)
        KmtOk(Granted == ExpectedGranted, FileAndLine, "desired 0x%lx: granted 0x%lx, expected 0x%lx\n",
              Desired, Granted, ExpectedGranted);
}

/* The integrity level of the token the checks are made for */
static
ULONG
MsIntegrityLevel(
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectContext)
{
    UCHAR Buffer[sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE];
    PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)Buffer;
    HANDLE hToken;
    ULONG Length;
    NTSTATUS Status;
    ULONG Level = MAXULONG;

    Status = ObOpenObjectByPointer(SeQuerySubjectContextToken(SubjectContext), OBJ_KERNEL_HANDLE, NULL, TOKEN_QUERY,
                                   *SeTokenObjectType, KernelMode, &hToken);
    if (!NT_SUCCESS(Status))
        return Level;
    Status = ZwQueryInformationToken(hToken, TokenIntegrityLevel, Buffer, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Status) && Label->Label.Sid && ((PISID)Label->Label.Sid)->SubAuthorityCount >= 1)
        Level = ((PISID)Label->Label.Sid)->SubAuthority[((PISID)Label->Label.Sid)->SubAuthorityCount - 1];
    ZwClose(hToken);
    return Level;
}

START_TEST(SeAccessCheckMalformedScans)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PTOKEN_USER UserInfo = NULL;
    PMS_SD MsSd;
    PSID World, User;
    USHORT AceWorld, AceOwnerRights, AceLabel;
    ULONG Level;
    NTSTATUS Status;

    SeCaptureSubjectContext(&SubjectContext);
    Status = SeQueryInformationToken(SeQuerySubjectContextToken(&SubjectContext), TokenUser, (PVOID *)&UserInfo);
    ok_eq_hex(Status, STATUS_SUCCESS);
    MsSd = ExAllocatePoolWithTag(NonPagedPool, sizeof(*MsSd), 'sMmK');
    if (skip(NT_SUCCESS(Status) && UserInfo && MsSd, "No token user or memory\n"))
        goto done;

    World = SeExports->SeWorldSid;
    User = UserInfo->User.Sid;
    AceWorld = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(World));
    AceOwnerRights = (USHORT)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(&MsOwnerRightsSid));
    AceLabel = (USHORT)(FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + RtlLengthSid(&MsSystemLabelSid));

    /*
     * OWNER RIGHTS. The caller owns the object (owner = its user SID).
     * O1. Well formed [allow Everyone 0x1]: the owner gets READ_CONTROL and WRITE_DAC as well
     */
    MsInitAcl(MsSd->Dacl, sizeof(ACL) + AceWorld, 1);
    MsPutAce(MsSd->Dacl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, AceWorld, 0x1, World);
    MsInitSd(MsSd, User, FALSE);
    MsExpect(&SubjectContext, MsSd, MAXIMUM_ALLOWED, TRUE, 0x1 | READ_CONTROL | WRITE_DAC);

    /* O2. Well formed [allow OWNER RIGHTS 0x1]: the ACE replaces the implicit rights */
    MsInitAcl(MsSd->Dacl, sizeof(ACL) + AceOwnerRights, 1);
    MsPutAce(MsSd->Dacl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, AceOwnerRights, 0x1, &MsOwnerRightsSid);
    MsInitSd(MsSd, User, FALSE);
    MsExpect(&SubjectContext, MsSd, MAXIMUM_ALLOWED, TRUE, 0x1);
    MsExpect(&SubjectContext, MsSd, READ_CONTROL, FALSE, 0);

    /* O3. [an allow ACE of size 0, allow OWNER RIGHTS 0x1], AceCount 2: the scan cannot see the OWNER RIGHTS ACE:
       no implicit rights (before: READ_CONTROL and WRITE_DAC, more than O2) */
    MsInitAcl(MsSd->Dacl, sizeof(ACL) + AceWorld + AceOwnerRights, 2);
    MsPutAce(MsSd->Dacl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, 0, 0x1, World);
    MsPutAce(MsSd->Dacl, sizeof(ACL) + AceWorld, ACCESS_ALLOWED_ACE_TYPE, AceOwnerRights, 0x1, &MsOwnerRightsSid);
    MsInitSd(MsSd, User, FALSE);
    MsExpect(&SubjectContext, MsSd, READ_CONTROL, FALSE, 0);
    MsExpect(&SubjectContext, MsSd, WRITE_DAC, FALSE, 0);
    MsExpect(&SubjectContext, MsSd, MAXIMUM_ALLOWED, FALSE, 0);

    /* O4. [allow Everyone 0x1, an ACE that runs past AclSize]: the first ACE counts, no implicit rights */
    MsInitAcl(MsSd->Dacl, sizeof(ACL) + AceWorld + AceOwnerRights - 4, 2);
    MsPutAce(MsSd->Dacl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, AceWorld, 0x1, World);
    MsPutAce(MsSd->Dacl, sizeof(ACL) + AceWorld, ACCESS_DENIED_ACE_TYPE, AceOwnerRights, READ_CONTROL,
             &MsOwnerRightsSid);
    MsInitSd(MsSd, User, FALSE);
    MsExpect(&SubjectContext, MsSd, MAXIMUM_ALLOWED, TRUE, 0x1);
    MsExpect(&SubjectContext, MsSd, READ_CONTROL, FALSE, 0);

    /* O5. The same DACL as O4 for an owner that is not the caller: unchanged by the scan */
    MsInitSd(MsSd, &MsLocalServiceSid, FALSE);
    MsExpect(&SubjectContext, MsSd, MAXIMUM_ALLOWED, TRUE, 0x1);

    /*
     * The mandatory label. Everyone is granted everything by the DACL; the owner is not the caller. The rows need a
     * caller below System.
     */
    Level = MsIntegrityLevel(&SubjectContext);
    trace("caller integrity level 0x%lx\n", Level);
    if (skip(Level < SECURITY_MANDATORY_SYSTEM_RID, "the caller is not below System (0x%lx)\n", Level))
        goto done;

    MsInitAcl(MsSd->Dacl, sizeof(ACL) + AceWorld, 1);
    /* The ACE carries the specific rights (SeAccessCheck does not map generic rights inside ACEs) */
    MsPutAce(MsSd->Dacl, sizeof(ACL), ACCESS_ALLOWED_ACE_TYPE, AceWorld, MsMapping.GenericAll, World);

    /* L1. Well formed [System label NO_WRITE_UP]: read and execute, no write */
    MsInitAcl(MsSd->Sacl, sizeof(ACL) + AceLabel, 1);
    MsPutAce(MsSd->Sacl, sizeof(ACL), SYSTEM_MANDATORY_LABEL_ACE_TYPE, AceLabel, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
             &MsSystemLabelSid);
    MsInitSd(MsSd, &MsLocalServiceSid, TRUE);
    MsExpect(&SubjectContext, MsSd, 0x1, TRUE, 0x1);
    MsExpect(&SubjectContext, MsSd, 0x2, FALSE, 0);

    /* L2. [an ACE of size 0, System label], AceCount 2: the label cannot be read: System with every policy, nothing
       (before: the implicit Medium label, everything for a caller at Medium or above, more than L1) */
    MsInitAcl(MsSd->Sacl, sizeof(ACL) + AceWorld + AceLabel, 2);
    MsPutAce(MsSd->Sacl, sizeof(ACL), SYSTEM_AUDIT_ACE_TYPE, 0, 0, World);
    MsPutAce(MsSd->Sacl, sizeof(ACL) + AceWorld, SYSTEM_MANDATORY_LABEL_ACE_TYPE, AceLabel,
             SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, &MsSystemLabelSid);
    MsInitSd(MsSd, &MsLocalServiceSid, TRUE);
    MsExpect(&SubjectContext, MsSd, 0x2, FALSE, 0);
    MsExpect(&SubjectContext, MsSd, 0x1, FALSE, 0);
    MsExpect(&SubjectContext, MsSd, MAXIMUM_ALLOWED, FALSE, 0);

    /* L3. [System label NO_WRITE_UP, an ACE that runs past AclSize]: the label was found first and counts as in L1 */
    MsInitAcl(MsSd->Sacl, sizeof(ACL) + AceLabel + AceWorld - 4, 2);
    MsPutAce(MsSd->Sacl, sizeof(ACL), SYSTEM_MANDATORY_LABEL_ACE_TYPE, AceLabel, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
             &MsSystemLabelSid);
    MsPutAce(MsSd->Sacl, sizeof(ACL) + AceLabel, SYSTEM_AUDIT_ACE_TYPE, AceWorld, 0, World);
    MsInitSd(MsSd, &MsLocalServiceSid, TRUE);
    MsExpect(&SubjectContext, MsSd, 0x1, TRUE, 0x1);
    MsExpect(&SubjectContext, MsSd, 0x2, FALSE, 0);

    /* L4. A label ACE whose SID runs 4 bytes past its AceSize: its level cannot be read: nothing (before: passed
       over, the implicit Medium label) */
    MsInitAcl(MsSd->Sacl, sizeof(ACL) + AceLabel, 1);
    MsPutAce(MsSd->Sacl, sizeof(ACL), SYSTEM_MANDATORY_LABEL_ACE_TYPE, AceLabel - 4,
             SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, &MsSystemLabelSid);
    MsInitSd(MsSd, &MsLocalServiceSid, TRUE);
    MsExpect(&SubjectContext, MsSd, 0x2, FALSE, 0);
    MsExpect(&SubjectContext, MsSd, 0x1, FALSE, 0);

    /* L5. A SACL whose AclSize cannot hold its header: nothing (before: no label, the implicit Medium label) */
    MsInitAcl(MsSd->Sacl, sizeof(ACL) - 1, 0);
    MsInitSd(MsSd, &MsLocalServiceSid, TRUE);
    MsExpect(&SubjectContext, MsSd, 0x1, FALSE, 0);

    /* L6. A well-formed SACL without a label (an audit ACE): the implicit Medium label, unchanged */
    MsInitAcl(MsSd->Sacl, sizeof(ACL) + AceWorld, 1);
    MsPutAce(MsSd->Sacl, sizeof(ACL), SYSTEM_AUDIT_ACE_TYPE, AceWorld, 0, World);
    MsInitSd(MsSd, &MsLocalServiceSid, TRUE);
    if (Level >= SECURITY_MANDATORY_MEDIUM_RID)
        MsExpect(&SubjectContext, MsSd, 0x2, TRUE, 0x2);

done:
    if (MsSd)
        ExFreePoolWithTag(MsSd, 'sMmK');
    if (UserInfo)
        ExFreePool(UserInfo);
    SeReleaseSubjectContext(&SubjectContext);
}
