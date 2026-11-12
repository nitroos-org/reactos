/*
 * PROJECT:     ReactOS NTFS-NG file system driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP_MJ_QUERY_SECURITY and IRP_MJ_SET_SECURITY
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ntfsng.h"

#define NDEBUG
#include <debug.h>

/*
 * A file without a usable descriptor (none of its own, no $Secure entry, or an invalid one) is
 * treated as owned by the administrators, with only SYSTEM and the administrators allowed in.
 */
static NTSTATUS NgDefaultSecurity(PSECURITY_DESCRIPTOR *Out)
{
    SECURITY_DESCRIPTOR Abs;
    UCHAR AclBuffer[sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE)];
    PACL Dacl = (PACL)AclBuffer;
    ULONG Len = 0;
    PSECURITY_DESCRIPTOR Rel;
    NTSTATUS Status;

    RtlCreateAcl(Dacl, sizeof(AclBuffer), ACL_REVISION);
    RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeLocalSystemSid);
    RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeAliasAdminsSid);
    RtlCreateSecurityDescriptor(&Abs, SECURITY_DESCRIPTOR_REVISION);
    RtlSetOwnerSecurityDescriptor(&Abs, SeExports->SeAliasAdminsSid, FALSE);
    RtlSetGroupSecurityDescriptor(&Abs, SeExports->SeLocalSystemSid, FALSE);
    RtlSetDaclSecurityDescriptor(&Abs, TRUE, Dacl, FALSE);
    RtlAbsoluteToSelfRelativeSD(&Abs, NULL, &Len);
    Rel = ExAllocatePoolWithTag(PagedPool, Len, TAG_NTFSNG);
    if (!Rel)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = RtlAbsoluteToSelfRelativeSD(&Abs, Rel, &Len);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Rel, TAG_NTFSNG);
        return Status;
    }
    *Out = Rel;
    return STATUS_SUCCESS;
}

/* The descriptor of Node in paged pool (ExFreePoolWithTag); caller holds CoreLock. */
NTSTATUS NgReadSecurity(PNG_VCB Vcb, ngc_node *Node, PSECURITY_DESCRIPTOR *Out)
{
    void *Raw = NULL;
    unsigned int Len = 0;
    PSECURITY_DESCRIPTOR Sd;
    int Err;

    *Out = NULL;
    Err = ngc_get_security(Vcb->Core, Node, &Raw, &Len);
    if (Err)
        return NgErrnoToStatus(Err);
    if (!Raw)
        return NgDefaultSecurity(Out);
    if (!RtlValidRelativeSecurityDescriptor(Raw, Len, 0))
    {
        ngc_free(Raw);
        DPRINT1("ntfsng: invalid security descriptor, using the default\n");
        return NgDefaultSecurity(Out);
    }
    {
        /* SeAccessCheck dereferences the owner SID; a descriptor without one (some Windows-written
         * metadata) would fault, so fall back to the default. */
        PSID Owner = NULL;
        BOOLEAN Defaulted;
        if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Raw, &Owner, &Defaulted)) || !Owner)
        {
            ngc_free(Raw);
            return NgDefaultSecurity(Out);
        }
    }
    Sd = ExAllocatePoolWithTag(PagedPool, Len, TAG_NTFSNG);
    if (Sd)
        RtlCopyMemory(Sd, Raw, Len);
    ngc_free(Raw);
    if (!Sd)
        return STATUS_INSUFFICIENT_RESOURCES;
    *Out = Sd;
    return STATUS_SUCCESS;
}

/* The file's descriptor in paged pool (the caller frees it with ExFreePoolWithTag). */
static NTSTATUS NgGetSecurity(PNG_VCB Vcb, PNG_FCB Fcb, PSECURITY_DESCRIPTOR *Out)
{
    NG_SHARED_HOLD Hold;
    NTSTATUS Status;
    int Err;

    *Out = NULL;
    NgAcquireCoreShared(Vcb, &Hold);
    Err = NgEnsureNode(Fcb);
    Status = Err ? NgErrnoToStatus(Err) : NgReadSecurity(Vcb, Fcb->Node, Out);
    NgReleaseCoreShared(Vcb, &Hold);
    return Status;
}

NTSTATUS NgQuerySecurity(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_FCB Fcb = Stack->FileObject ? Stack->FileObject->FsContext : NULL;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    SECURITY_INFORMATION Info = Stack->Parameters.QuerySecurity.SecurityInformation;
    ULONG Length = Stack->Parameters.QuerySecurity.Length;
    PSECURITY_DESCRIPTOR Sd = NULL;
    NTSTATUS Status;

    if (!Fcb || Fcb->IsVolume || !Fcb->HasNode)
        return STATUS_INVALID_DEVICE_REQUEST;   /* the I/O manager supplies its default */
    Status = NgGetSecurity(Vcb, Fcb, &Sd);
    if (!NT_SUCCESS(Status))
        return Status;
    /* No probe: the buffer was checked by the caller, and RequestorMode is the thread's previous
     * mode even for the kernel buffer of an object manager access check. */
    _SEH2_TRY
    {
        Status = SeQuerySecurityDescriptorInfo(&Info, Irp->UserBuffer, &Length, &Sd);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ExFreePoolWithTag(Sd, TAG_NTFSNG);
    if (Status == STATUS_BUFFER_TOO_SMALL)
    {
        Irp->IoStatus.Information = Length;
        return STATUS_BUFFER_OVERFLOW;
    }
    if (NT_SUCCESS(Status))
        Irp->IoStatus.Information = Length;
    return Status;
}

/*
 * Generic rights in effective DACL ACEs become file rights, as Windows stores them; ReactOS'
 * SeSetSecurityDescriptorInfo leaves them as they came.  Inherit-only ACEs keep theirs.
 */
static VOID NgMapGenericDacl(PSECURITY_DESCRIPTOR Sd)
{
    BOOLEAN Present = FALSE, Defaulted;
    PACL Dacl = NULL;
    PACE_HEADER Ace;
    ULONG i;

    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Dacl, &Defaulted)) || !Present || !Dacl)
        return;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            break;
        if (Ace->AceType <= SYSTEM_ALARM_ACE_TYPE && !(Ace->AceFlags & INHERIT_ONLY_ACE))
            RtlMapGenericMask(&((PACCESS_ALLOWED_ACE)Ace)->Mask, IoGetFileObjectGenericMapping());
    }
}

/* Merges the requested parts into the file's descriptor and stores it as the file's own. */
NTSTATUS NgSetSecurity(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PNG_FCB Fcb = Stack->FileObject ? Stack->FileObject->FsContext : NULL;
    PNG_VCB Vcb = DeviceObject->DeviceExtension;
    SECURITY_INFORMATION Info = Stack->Parameters.SetSecurity.SecurityInformation;
    PSECURITY_DESCRIPTOR Sd = NULL, Old;
    SECURITY_DESCRIPTOR_CONTROL Keep = 0;
    NTSTATUS Status;
    int Err;

    if (!Fcb || Fcb->IsVolume || !Fcb->HasNode)
        return STATUS_INVALID_DEVICE_REQUEST;   /* the I/O manager supplies its default */
    if (Vcb->ReadOnly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
    Status = NgGetSecurity(Vcb, Fcb, &Sd);
    if (NT_SUCCESS(Status))
    {
        Old = Sd;
        /* An ACL the set does not replace keeps its marks; SeSetSecurityDescriptorInfo drops them. */
        if (!(Info & DACL_SECURITY_INFORMATION))
            Keep |= ((PISECURITY_DESCRIPTOR)Old)->Control & (SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED);
        if (!(Info & SACL_SECURITY_INFORMATION))
            Keep |= ((PISECURITY_DESCRIPTOR)Old)->Control & (SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED);
        Status = SeSetSecurityDescriptorInfo(NULL, &Info, Stack->Parameters.SetSecurity.SecurityDescriptor, &Sd,
                                             PagedPool, IoGetFileObjectGenericMapping());
        if (NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(Old, TAG_NTFSNG);
            ((PISECURITY_DESCRIPTOR)Sd)->Control |= Keep;
            NgMapGenericDacl(Sd);
            NgAcquireCore(Vcb);
            Err = NgEnsureNode(Fcb);
            if (!Err)
                Err = ngc_set_security(Vcb->Core, Fcb->Node, Sd, RtlLengthSecurityDescriptor(Sd));
            if (!Err)
                NgAfterChange(Vcb);
            NgReleaseCore(Vcb);
            if (Err)
                Status = NgErrnoToStatus(Err);
            ExFreePool(Sd);
        }
        else
        {
            ExFreePoolWithTag(Sd, TAG_NTFSNG);
        }
    }
    ExReleaseResourceLite(Fcb->Header.Resource);
    if (NT_SUCCESS(Status))
        NgNotifyCcb(Vcb, Stack->FileObject->FsContext2, Fcb, FILE_NOTIFY_CHANGE_SECURITY, FILE_ACTION_MODIFIED);
    return Status;
}

/*
 * The descriptor of a new file or directory: inherited from its directory's descriptor ParentSd
 * (CREATOR OWNER and CREATOR GROUP replaced, generic rights mapped, inheritance flags applied),
 * merged with a descriptor given to the create; owner and group come from the creator's token.
 * Stored as the file's own descriptor before the create completes; caller holds CoreLock
 * exclusive, so the new file and its descriptor reach the volume in one transaction.  When
 * SeAssignSecurityEx refuses (invalid owner, privilege not held, ...), its status is in *Rejected.
 */
int NgAssignNewSecurity(PNG_VCB Vcb, ngc_node *Node, PSECURITY_DESCRIPTOR ParentSd, PACCESS_STATE As, BOOLEAN IsDir,
                        NTSTATUS *Rejected)
{
    PSECURITY_DESCRIPTOR New = NULL;
    SECURITY_DESCRIPTOR_CONTROL Parent, Creator;
    ULONG AutoInherit = 0;
    NTSTATUS Status;
    int Err;

    if (!As)
        return 0;
    /* Auto-inheritance only below an ACL marked auto-inherited, and only for an ACL the create does not supply. */
    Parent = ParentSd ? ((PISECURITY_DESCRIPTOR)ParentSd)->Control : 0;
    Creator = As->SecurityDescriptor ? ((PISECURITY_DESCRIPTOR)As->SecurityDescriptor)->Control : 0;
    if ((Parent & SE_DACL_AUTO_INHERITED) && !(Creator & SE_DACL_PRESENT))
        AutoInherit |= SEF_DACL_AUTO_INHERIT;
    if ((Parent & SE_SACL_AUTO_INHERITED) && !(Creator & SE_SACL_PRESENT))
        AutoInherit |= SEF_SACL_AUTO_INHERIT;
    Status = SeAssignSecurityEx(ParentSd, As->SecurityDescriptor, &New, NULL, IsDir, AutoInherit,
                                &As->SubjectSecurityContext, IoGetFileObjectGenericMapping(), PagedPool);
    if (!NT_SUCCESS(Status))
    {
        /* The create fails with SeAssignSecurityEx's own status. */
        DPRINT1("ntfsng: no descriptor for a new file (0x%08lx)\n", Status);
        *Rejected = Status;
        return -NGC_EINVAL;
    }
    NgMapGenericDacl(New);
    Err = ngc_set_security(Vcb->Core, Node, New, RtlLengthSecurityDescriptor(New));
    SeDeassignSecurity(&New);
    return Err;
}
