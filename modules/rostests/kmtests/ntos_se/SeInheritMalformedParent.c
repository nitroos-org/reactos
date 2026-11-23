/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SeAssignSecurity with a parent (or a kernel caller's explicit) DACL that RtlValidAcl would refuse
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The parent descriptor of SeAssignSecurity can come from the disk (a file created in a directory whose
 * descriptor a file system read and did not validate again), and a kernel-mode caller's explicit descriptor is
 * not captured. The propagation walks each ACL up to its first ACE that does not lie within the ACL, with the
 * fields it reads (RtlValidAcl's rules: a header, a size of at least a header and within the ACL, even, and for
 * allow/deny/audit/alarm ACEs a multiple of 4 holding the whole SID): the ACEs before it are used, it and the
 * ones after it in the same ACL are not, in every build. Before, the sizes were only asserted: a checked kernel
 * stopped, a free kernel copied AceSize bytes, or a SID of the length its own count claims, from beyond the ACE.
 *
 * Each row builds the parent DACL by hand in a buffer that holds well-formed bytes behind AclSize (an ACE for
 * 0x4), so a walk that reads past the ACL shows up as an extra ACE instead of a fault. The rows whose old
 * behaviour was an assertion come last.
 */

#include <kmt_test.h>

#define SM_BUFFER 512
#define SM_SID_SIZE 12 /* S-1-1-0 */
#define SM_ACE (FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + SM_SID_SIZE)

static GENERIC_MAPPING SmMapping =
{
    STANDARD_RIGHTS_READ    | 0x0001,
    STANDARD_RIGHTS_WRITE   | 0x0002,
    STANDARD_RIGHTS_EXECUTE | 0x0004,
    STANDARD_RIGHTS_ALL     | 0x0007,
};

typedef struct _SM_ACL
{
    ULONG Buffer[SM_BUFFER / sizeof(ULONG)];
} SM_ACL, *PSM_ACL;

static
VOID
SmInit(PSM_ACL Acl, USHORT AclSize, USHORT AceCount)
{
    PACL Header = (PACL)Acl->Buffer;
    RtlZeroMemory(Acl, sizeof(*Acl));
    Header->AclRevision = ACL_REVISION;
    Header->AclSize = AclSize;
    Header->AceCount = AceCount;
}

/* An allow ACE for World at Offset; Size is what its header claims, the SID is always written whole */
static
VOID
SmPut(PSM_ACL Acl, ULONG Offset, UCHAR Flags, USHORT Size, ACCESS_MASK Mask, UCHAR SubAuthorityCount)
{
    PACCESS_ALLOWED_ACE Ace = (PACCESS_ALLOWED_ACE)((PUCHAR)Acl->Buffer + Offset);
    PISID Sid;

    Ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    Ace->Header.AceFlags = Flags;
    Ace->Header.AceSize = Size;
    Ace->Mask = Mask;
    RtlCopyMemory(&Ace->SidStart, SeExports->SeWorldSid, SM_SID_SIZE);
    Sid = (PISID)&Ace->SidStart;
    Sid->SubAuthorityCount = SubAuthorityCount;
}

/* Every ACE of the ACL lies within it and keeps the next one aligned (RtlValidAcl's size rules; it is not exported to drivers) */
static
BOOLEAN
SmValidAcl(PACL Acl)
{
    PUCHAR End = (PUCHAR)Acl + Acl->AclSize, Ace = (PUCHAR)(Acl + 1);
    ULONG i;

    if (Acl->AclSize < sizeof(ACL) || (Acl->AclSize % sizeof(ULONG)) != 0)
        return FALSE;
    for (i = 0; i < Acl->AceCount; i++)
    {
        PACE_HEADER Header = (PACE_HEADER)Ace;

        if (Ace + sizeof(ACE_HEADER) > End || Header->AceSize < sizeof(ACE_HEADER) ||
            Ace + Header->AceSize > End || (Header->AceSize % sizeof(ULONG)) != 0)
        {
            return FALSE;
        }
        Ace += Header->AceSize;
    }
    return TRUE;
}

/* Expected: Count ACEs with these masks (in order), a DACL whose ACEs lie within it */
static
VOID
SmCheck(PCSTR Row, PSECURITY_DESCRIPTOR Sd, ULONG Count, ACCESS_MASK M0, ACCESS_MASK M1)
{
    BOOLEAN Present = FALSE, Defaulted;
    PACL Dacl = NULL;
    PACCESS_ALLOWED_ACE Ace;
    NTSTATUS Status;
    ULONG i;
    ACCESS_MASK Masks[2] = { M0, M1 };

    Status = RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted);
    ok(NT_SUCCESS(Status) && Present && Dacl, "%s: no DACL (0x%lx)\n", Row, Status);
    if (!NT_SUCCESS(Status) || !Present || !Dacl)
        return;
    ok(Dacl->AceCount == Count, "%s: %u ACEs, expected %lu\n", Row, Dacl->AceCount, Count);
    ok(SmValidAcl(Dacl), "%s: the new DACL is not valid (size %u)\n", Row, Dacl->AclSize);
    if (Dacl->AceCount != Count || !SmValidAcl(Dacl))
        return;
    for (i = 0; i < Count && i < 2; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
        {
            ok(FALSE, "%s: ACE %lu missing\n", Row, i);
            return;
        }
        ok(Ace->Mask == Masks[i], "%s: ACE %lu mask 0x%lx, expected 0x%lx\n", Row, i, Ace->Mask, Masks[i]);
        ok(RtlEqualSid(&Ace->SidStart, SeExports->SeWorldSid), "%s: ACE %lu has another SID\n", Row, i);
    }
}

static
VOID
SmAssign(PCSTR Row, PSECURITY_SUBJECT_CONTEXT SubjectContext, PSM_ACL ParentAcl, PSM_ACL ExplicitAcl,
         BOOLEAN IsDirectory, ULONG AutoInherit, ULONG Count, ACCESS_MASK M0, ACCESS_MASK M1)
{
    SECURITY_DESCRIPTOR Parent, Explicit;
    PSECURITY_DESCRIPTOR New = NULL;
    NTSTATUS Status;

    RtlCreateSecurityDescriptor(&Parent, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&Parent, SeExports->SeAliasAdminsSid, FALSE);
    RtlSetGroupSecurityDescriptor(&Parent, SeExports->SeLocalSystemSid, FALSE);
    if (ParentAcl)
        RtlSetDaclSecurityDescriptor(&Parent, TRUE, (PACL)ParentAcl->Buffer, FALSE);
    RtlCreateSecurityDescriptor(&Explicit, SECURITY_DESCRIPTOR_REVISION);
    if (ExplicitAcl)
        RtlSetDaclSecurityDescriptor(&Explicit, TRUE, (PACL)ExplicitAcl->Buffer, FALSE);

    Status = SeAssignSecurityEx(ParentAcl ? &Parent : NULL, ExplicitAcl ? &Explicit : NULL, &New, NULL,
                                IsDirectory, AutoInherit, SubjectContext, &SmMapping, PagedPool);
    ok(Status == STATUS_SUCCESS, "%s: SeAssignSecurityEx 0x%lx\n", Row, Status);
    if (NT_SUCCESS(Status) && New)
    {
        SmCheck(Row, New, Count, M0, M1);
        SeDeassignSecurity(&New);
    }
}

START_TEST(SeInheritMalformedParent)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PSM_ACL Parent, Explicit;
    const UCHAR OI = OBJECT_INHERIT_ACE, CI = CONTAINER_INHERIT_ACE;

    Parent = ExAllocatePoolWithTag(PagedPool, sizeof(SM_ACL), 'mSmK');
    Explicit = ExAllocatePoolWithTag(PagedPool, sizeof(SM_ACL), 'mSmK');
    if (!Parent || !Explicit)
    {
        skip(FALSE, "no memory\n");
        goto done;
    }
    SeCaptureSubjectContext(&SubjectContext);

    /* A. control: two inheritable allow ACEs, both inherited */
    SmInit(Parent, sizeof(ACL) + 2 * SM_ACE, 2);
    SmPut(Parent, sizeof(ACL), OI, SM_ACE, 0x1, 1);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI, SM_ACE, 0x2, 1);
    SmPut(Parent, sizeof(ACL) + 2 * SM_ACE, OI, SM_ACE, 0x4, 1);
    SmAssign("A file", &SubjectContext, Parent, NULL, FALSE, 0, 2, 0x1, 0x2);
    SmAssign("A directory", &SubjectContext, Parent, NULL, TRUE, 0, 2, 0x1, 0x2);

    /* B. the last ACE runs 8 bytes past AclSize: only the first is inherited */
    SmInit(Parent, sizeof(ACL) + 2 * SM_ACE - 8, 2);
    SmPut(Parent, sizeof(ACL), OI | CI, SM_ACE, 0x1, 1);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI | CI, SM_ACE, 0x2, 1);
    SmPut(Parent, sizeof(ACL) + 2 * SM_ACE, OI | CI, SM_ACE, 0x4, 1);
    SmAssign("B file", &SubjectContext, Parent, NULL, FALSE, 0, 1, 0x1, 0);
    SmAssign("B directory", &SubjectContext, Parent, NULL, TRUE, 0, 1, 0x1, 0);

    /* D. AceCount 3, two ACEs fill AclSize: the third index is not an ACE of the ACL (an ACE for 0x4 behind it) */
    SmInit(Parent, sizeof(ACL) + 2 * SM_ACE, 3);
    SmPut(Parent, sizeof(ACL), OI, SM_ACE, 0x1, 1);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI, SM_ACE, 0x2, 1);
    SmPut(Parent, sizeof(ACL) + 2 * SM_ACE, OI, SM_ACE, 0x4, 1);
    SmAssign("D", &SubjectContext, Parent, NULL, FALSE, 0, 2, 0x1, 0x2);

    /* F. a kernel caller's explicit DACL whose second ACE runs past AclSize: only the first is kept */
    SmInit(Explicit, sizeof(ACL) + 2 * SM_ACE - 8, 2);
    SmPut(Explicit, sizeof(ACL), 0, SM_ACE, 0x1, 1);
    SmPut(Explicit, sizeof(ACL) + SM_ACE, 0, SM_ACE, 0x2, 1);
    SmPut(Explicit, sizeof(ACL) + 2 * SM_ACE, 0, SM_ACE, 0x4, 1);
    SmAssign("F", &SubjectContext, NULL, Explicit, FALSE, 0, 1, 0x1, 0);

    /* G. the same explicit DACL with auto-inheritance from a valid parent (one inheritable ACE for 0x4): the
       explicit walk stops at its bad ACE and the parent's ACE is still inherited after it */
    SmInit(Parent, sizeof(ACL) + SM_ACE, 1);
    SmPut(Parent, sizeof(ACL), OI, SM_ACE, 0x4, 1);
    SmAssign("G", &SubjectContext, Parent, Explicit, FALSE, SEF_DACL_AUTO_INHERIT, 2, 0x1, 0x4);

    /* The rows a checked kernel asserted on before */

    /* C. the second ACE's SID claims 15 subauthorities in an ACE of 20 bytes, with room in the ACL behind it */
    SmInit(Parent, sizeof(ACL) + 2 * SM_ACE + 64, 2);
    SmPut(Parent, sizeof(ACL), OI, SM_ACE, 0x1, 1);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI, SM_ACE, 0x2, 15);
    SmAssign("C", &SubjectContext, Parent, NULL, FALSE, 0, 1, 0x1, 0);

    /* E. the second ACE has size 0, then 6 (not a multiple of 4), then 2 */
    SmInit(Parent, sizeof(ACL) + 2 * SM_ACE, 2);
    SmPut(Parent, sizeof(ACL), OI, SM_ACE, 0x1, 1);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI, 0, 0x2, 1);
    SmAssign("E size 0", &SubjectContext, Parent, NULL, FALSE, 0, 1, 0x1, 0);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI, SM_ACE - 2, 0x2, 1);
    SmAssign("E size 18", &SubjectContext, Parent, NULL, FALSE, 0, 1, 0x1, 0);
    SmPut(Parent, sizeof(ACL) + SM_ACE, OI, 2, 0x2, 1);
    SmAssign("E size 2", &SubjectContext, Parent, NULL, FALSE, 0, 1, 0x1, 0);

    /* H. the first ACE does not fit: nothing is inherited; the object gets the creator's default DACL instead */
    SmInit(Parent, sizeof(ACL) + SM_ACE, 1);
    SmPut(Parent, sizeof(ACL), OI, SM_ACE + 8, 0x1, 1);
    {
        SECURITY_DESCRIPTOR Sd;
        PSECURITY_DESCRIPTOR New = NULL;
        BOOLEAN Present = FALSE, Defaulted;
        PACL Dacl = NULL;
        PACCESS_ALLOWED_ACE Ace;
        NTSTATUS Status;
        ULONG i;

        RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
        RtlSetOwnerSecurityDescriptor(&Sd, SeExports->SeAliasAdminsSid, FALSE);
        RtlSetGroupSecurityDescriptor(&Sd, SeExports->SeLocalSystemSid, FALSE);
        RtlSetDaclSecurityDescriptor(&Sd, TRUE, (PACL)Parent->Buffer, FALSE);
        Status = SeAssignSecurity(&Sd, NULL, &New, FALSE, &SubjectContext, &SmMapping, PagedPool);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status) && New)
        {
            RtlGetDaclSecurityDescriptor(New, &Present, &Dacl, &Defaulted);
            if (Present && Dacl)
            {
                ok(SmValidAcl(Dacl), "H: the new DACL is not valid\n");
                for (i = 0; i < Dacl->AceCount && NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)); i++)
                    ok(Ace->Mask != 0x1, "H: the ACE that does not fit was inherited\n");
            }
            SeDeassignSecurity(&New);
        }
    }

    SeReleaseSubjectContext(&SubjectContext);
done:
    if (Parent)
        ExFreePoolWithTag(Parent, 'mSmK');
    if (Explicit)
        ExFreePoolWithTag(Explicit, 'mSmK');
}
