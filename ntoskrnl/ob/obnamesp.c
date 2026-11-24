/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Private namespaces: NtCreatePrivateNamespace and NtOpenPrivateNamespace
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The documented contract (Microsoft Learn, "Object Namespaces", CreatePrivateNamespaceW,
 * AddIntegrityLabelToBoundaryDescriptor; paraphrased):
 * - a namespace is identified by its name and its boundaries; namespaces with the same name and
 *   other boundaries are different ones;
 * - creating one succeeds only for a caller within the boundary; a process can create one only
 *   with an integrity level equal to or lower than its own; a new boundary descriptor must have
 *   at least one SID;
 * - a process outside the boundary can still open an existing namespace unless the creator
 *   restricted access through the security attributes: the namespace's security descriptor
 *   decides who opens it, and with what access.
 *
 * Here a namespace is a directory object in \PrivateNamespaces, a directory only the kernel can
 * create in (SYSTEM full, Administrators read), named after its whole boundary descriptor (the
 * name, the set of SIDs, the label, hex-encoded): the boundary is the key, so no other boundary
 * reaches it and no process can make one with a name of its choosing. The creator must hold every
 * SID of the boundary as an enabled user or group SID (and as a restricting SID when its token
 * is restricted), and the level of the label must not be above its own. The directory is created
 * with its whole descriptor in one step: the owner, group and DACL of the creator's security
 * attributes where it gave them (an owner it may assign, SepCheckOwnerSid), its mandatory label
 * (up to its own level unless it holds SeRelabelPrivilege) or else the label of the boundary (a
 * lower level cannot write in it), and the creator's defaults for the rest. No opener finds the
 * directory before that descriptor is in place. Opening is an access check of the caller's token against
 * the directory's descriptor and label. The directory is not permanent: it goes away with its
 * last handle.
 *
 * Choices the documentation leaves open, the stricter one taken (to verify on Windows): a SID
 * held only for deny (or not enabled) does not count; the name is compared exactly (case
 * included); the SIDs are a set (order and repetition do not matter); a boundary without SIDs
 * cannot be created (STATUS_INVALID_PARAMETER); audit entries of the creator's SACL are not
 * applied (only its mandatory label), and a SACL without a label leaves the boundary's label in
 * place; an owner the creator may not assign is refused (STATUS_INVALID_OWNER), as for a
 * registry key it creates.
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include <reactos/boundarydesc.h>
#define NDEBUG
#include <debug.h>

#define TAG_OB_NAMESPACE 'snbO'

static const WCHAR ObpPrivateNamespacesRoot[] = L"\\PrivateNamespaces\\";

/* PRIVATE FUNCTIONS **********************************************************/

typedef struct _OBP_BOUNDARY
{
    PBOUNDARY_DESCRIPTOR_HEADER Header;     /* the captured copy */
    PBOUNDARY_DESCRIPTOR_ENTRY Name;
    PBOUNDARY_DESCRIPTOR_ENTRY Label;
    ULONG SidCount;
    PBOUNDARY_DESCRIPTOR_ENTRY *Sids;       /* sorted, without repeats */
} OBP_BOUNDARY, *POBP_BOUNDARY;

static
VOID
ObpFreeBoundary(
    _Inout_ POBP_BOUNDARY Boundary)
{
    if (Boundary->Sids)
        ExFreePoolWithTag(Boundary->Sids, TAG_OB_NAMESPACE);
    if (Boundary->Header)
        ExFreePoolWithTag(Boundary->Header, TAG_OB_NAMESPACE);
    RtlZeroMemory(Boundary, sizeof(*Boundary));
}

/* Orders two SID entries: shorter first, then by their bytes */
static
LONG
ObpCompareSidEntries(
    _In_ PBOUNDARY_DESCRIPTOR_ENTRY A,
    _In_ PBOUNDARY_DESCRIPTOR_ENTRY B)
{
    SIZE_T Same;

    if (A->DataSize != B->DataSize)
        return A->DataSize < B->DataSize ? -1 : 1;
    Same = RtlCompareMemory(A + 1, B + 1, A->DataSize);
    if (Same == A->DataSize)
        return 0;
    return ((PUCHAR)(A + 1))[Same] < ((PUCHAR)(B + 1))[Same] ? -1 : 1;
}

/* Probes, copies and validates a boundary descriptor of the caller */
static
NTSTATUS
ObpCaptureBoundary(
    _In_ PVOID UserBoundary,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ POBP_BOUNDARY Boundary)
{
    PBOUNDARY_DESCRIPTOR_HEADER Header;
    PBOUNDARY_DESCRIPTOR_ENTRY Entry, *Sids;
    ULONG TotalSize, Offset, i, j, Count;
    NTSTATUS Status = STATUS_SUCCESS;

    RtlZeroMemory(Boundary, sizeof(*Boundary));
    if (UserBoundary == NULL)
        return STATUS_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
            ProbeForRead(UserBoundary, sizeof(BOUNDARY_DESCRIPTOR_HEADER), sizeof(ULONG));
        TotalSize = ((volatile BOUNDARY_DESCRIPTOR_HEADER *)UserBoundary)->TotalSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    if (TotalSize < sizeof(BOUNDARY_DESCRIPTOR_HEADER) || TotalSize > BOUNDARY_DESCRIPTOR_MAX_SIZE ||
        (TotalSize & 3))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Header = ExAllocatePoolWithTag(PagedPool, TotalSize, TAG_OB_NAMESPACE);
    if (Header == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
            ProbeForRead(UserBoundary, TotalSize, sizeof(ULONG));
        RtlCopyMemory(Header, UserBoundary, TotalSize);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    Boundary->Header = Header;
    if (!NT_SUCCESS(Status))
        goto fail;

    /* Only the copy is used from here on */
    Status = STATUS_INVALID_PARAMETER;
    if (Header->Version != BOUNDARY_DESCRIPTOR_VERSION || Header->TotalSize != TotalSize ||
        Header->EntryCount > (TotalSize - sizeof(*Header)) / sizeof(BOUNDARY_DESCRIPTOR_ENTRY))
    {
        goto fail;
    }

    Count = 0;
    Offset = sizeof(*Header);
    for (i = 0; i < Header->EntryCount; i++)
    {
        if (TotalSize - Offset < sizeof(BOUNDARY_DESCRIPTOR_ENTRY))
            goto fail;
        Entry = (PBOUNDARY_DESCRIPTOR_ENTRY)((PUCHAR)Header + Offset);
        if (Entry->Size < sizeof(*Entry) || (Entry->Size & 3) || Entry->Size > TotalSize - Offset ||
            Entry->DataSize > Entry->Size - sizeof(*Entry) ||
            ALIGN_UP_BY(Entry->DataSize, sizeof(ULONG)) != Entry->Size - sizeof(*Entry))
        {
            goto fail;
        }

        switch (Entry->Type)
        {
            case BOUNDARY_ENTRY_NAME:
                if (Boundary->Name != NULL || (Entry->DataSize & 1))
                    goto fail;
                Boundary->Name = Entry;
                break;

            case BOUNDARY_ENTRY_SID:
            case BOUNDARY_ENTRY_INTEGRITY_LABEL:
                if (Entry->DataSize < FIELD_OFFSET(SID, SubAuthority) ||
                    !RtlValidSid((PSID)(Entry + 1)) ||
                    RtlLengthSid((PSID)(Entry + 1)) != Entry->DataSize)
                {
                    goto fail;
                }
                if (Entry->Type == BOUNDARY_ENTRY_SID)
                {
                    Count++;
                }
                else
                {
                    /* Windows takes any SID with a sub-authority as the label (measured, kernel32) */
                    if (Boundary->Label != NULL || *RtlSubAuthorityCountSid((PSID)(Entry + 1)) == 0)
                        goto fail;
                    Boundary->Label = Entry;
                }
                break;

            default:
                goto fail;
        }
        Offset += Entry->Size;
    }
    if (Offset != TotalSize || Boundary->Name == NULL)
        goto fail;

    /* The SIDs as a set: sorted, repeats dropped */
    if (Count != 0)
    {
        Sids = ExAllocatePoolWithTag(PagedPool, Count * sizeof(*Sids), TAG_OB_NAMESPACE);
        if (Sids == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto fail;
        }
        Boundary->Sids = Sids;
        Offset = sizeof(*Header);
        for (i = 0; i < Header->EntryCount; i++)
        {
            Entry = (PBOUNDARY_DESCRIPTOR_ENTRY)((PUCHAR)Header + Offset);
            Offset += Entry->Size;
            if (Entry->Type != BOUNDARY_ENTRY_SID)
                continue;
            /* insertion into the sorted part; a SID that is there already is not added again */
            for (j = 0; j < Boundary->SidCount && ObpCompareSidEntries(Sids[j], Entry) < 0; j++)
                ;
            if (j < Boundary->SidCount && ObpCompareSidEntries(Sids[j], Entry) == 0)
                continue;
            RtlMoveMemory(&Sids[j + 1], &Sids[j], (Boundary->SidCount - j) * sizeof(*Sids));
            Sids[j] = Entry;
            Boundary->SidCount++;
        }
    }
    return STATUS_SUCCESS;

fail:
    ObpFreeBoundary(Boundary);
    return Status;
}

static
VOID
ObpAppendHex(
    _Inout_ PUNICODE_STRING Name,
    _In_ WCHAR Tag,
    _In_reads_bytes_(Size) const UCHAR *Data,
    _In_ ULONG Size)
{
    static const WCHAR Digits[] = L"0123456789ABCDEF";
    PWCHAR p = (PWCHAR)((PUCHAR)Name->Buffer + Name->Length);
    ULONG i;

    *p++ = Tag;
    for (i = 0; i < Size; i++)
    {
        *p++ = Digits[Data[i] >> 4];
        *p++ = Digits[Data[i] & 15];
    }
    Name->Length += (USHORT)((1 + 2 * Size) * sizeof(WCHAR));
}

/* The full name of the namespace directory of a boundary: the root and the boundary, hex-encoded */
static
NTSTATUS
ObpBuildNamespaceName(
    _In_ POBP_BOUNDARY Boundary,
    _Out_ PUNICODE_STRING Name)
{
    ULONG Chars, i;

    Chars = RTL_NUMBER_OF(ObpPrivateNamespacesRoot) - 1 + 1 + 2 * Boundary->Name->DataSize;
    for (i = 0; i < Boundary->SidCount; i++)
        Chars += 1 + 2 * Boundary->Sids[i]->DataSize;
    if (Boundary->Label)
        Chars += 1 + 2 * Boundary->Label->DataSize;
    if (Chars * sizeof(WCHAR) > UNICODE_STRING_MAX_BYTES)
        return STATUS_INVALID_PARAMETER;

    Name->Buffer = ExAllocatePoolWithTag(PagedPool, Chars * sizeof(WCHAR), TAG_OB_NAMESPACE);
    if (Name->Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    Name->MaximumLength = (USHORT)(Chars * sizeof(WCHAR));
    Name->Length = sizeof(ObpPrivateNamespacesRoot) - sizeof(WCHAR);
    RtlCopyMemory(Name->Buffer, ObpPrivateNamespacesRoot, Name->Length);

    ObpAppendHex(Name, L'N', (PUCHAR)(Boundary->Name + 1), Boundary->Name->DataSize);
    for (i = 0; i < Boundary->SidCount; i++)
        ObpAppendHex(Name, L'S', (PUCHAR)(Boundary->Sids[i] + 1), Boundary->Sids[i]->DataSize);
    if (Boundary->Label)
        ObpAppendHex(Name, L'L', (PUCHAR)(Boundary->Label + 1), Boundary->Label->DataSize);
    ASSERT(Name->Length == Name->MaximumLength);
    return STATUS_SUCCESS;
}

/* The level a label SID stands for: its last sub-authority */
static
ULONG
ObpBoundaryLevel(
    _In_ PBOUNDARY_DESCRIPTOR_ENTRY Label)
{
    PSID Sid = (PSID)(Label + 1);

    return *RtlSubAuthoritySid(Sid, *RtlSubAuthorityCountSid(Sid) - 1);
}

/* The caller is within the boundary: it holds every SID and runs at or above the label's level */
static
NTSTATUS
ObpCheckWithinBoundary(
    _In_ POBP_BOUNDARY Boundary)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PTOKEN Token;
    BOOLEAN Restricted;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    SeCaptureSubjectContext(&SubjectContext);

    /*
     * A thread impersonating below SecurityImpersonation (identification or anonymous) may not act as its
     * client: it is not judged by the client's SIDs, it is refused. Measured on Windows Server 2022: a create at
     * either level fails with ERROR_ACCESS_DENIED, while an open (the access check of the directory) fails with
     * ERROR_BAD_IMPERSONATION_LEVEL.
     */
    if (SubjectContext.ClientToken != NULL && SubjectContext.ImpersonationLevel < SecurityImpersonation)
    {
        SeReleaseSubjectContext(&SubjectContext);
        return STATUS_ACCESS_DENIED;
    }

    Token = (PTOKEN)SeQuerySubjectContextToken(&SubjectContext);
    SepAcquireTokenLockShared(Token);

    Restricted = (Token->TokenFlags & TOKEN_IS_RESTRICTED) != 0;
    for (i = 0; i < Boundary->SidCount; i++)
    {
        PSID Sid = (PSID)(Boundary->Sids[i] + 1);

        if (!SepSidInTokenEx(Token, NULL, Sid, FALSE, FALSE) ||
            (Restricted && !SepSidInTokenEx(Token, NULL, Sid, FALSE, TRUE)))
        {
            Status = STATUS_ACCESS_DENIED;
            break;
        }
    }
    if (NT_SUCCESS(Status) && Boundary->Label && ObpBoundaryLevel(Boundary->Label) > Token->IntegrityLevel)
        Status = STATUS_ACCESS_DENIED;

    SepReleaseTokenLock(Token);
    SeReleaseSubjectContext(&SubjectContext);
    return Status;
}

/*
 * The SACL of a new namespace directory, in pool (NULL when it gets none): the mandatory label ACEs of the
 * creator's SACL when it holds any (only those: its audit entries are not applied), else the label of the
 * boundary when that is a mandatory label SID (NO_WRITE_UP at the boundary's level)
 */
static
NTSTATUS
ObpBuildNamespaceSacl(
    _In_opt_ PACL CallerSacl,
    _In_ POBP_BOUNDARY Boundary,
    _Out_ PACL *Sacl)
{
    SID_IDENTIFIER_AUTHORITY MandatoryAuthority = {SECURITY_MANDATORY_LABEL_AUTHORITY};
    UCHAR SidBuffer[FIELD_OFFSET(SID, SubAuthority) + sizeof(ULONG)];
    PSID LabelSid = (PSID)SidBuffer;
    PACE_HEADER Ace;
    ULONG Size = sizeof(ACL), Count = 0, i;
    PACL Acl;
    NTSTATUS Status;

    *Sacl = NULL;

    /* The creator's labels (its descriptor was captured, so its SACL is valid) */
    if (CallerSacl)
    {
        for (i = 0; i < CallerSacl->AceCount && NT_SUCCESS(RtlGetAce(CallerSacl, i, (PVOID *)&Ace)); i++)
        {
            if (Ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            {
                Size += Ace->AceSize;
                Count++;
            }
        }
    }
    if (Count == 0)
    {
        if (Boundary->Label == NULL || !SepIsMandatoryLabelSid((PSID)(Boundary->Label + 1), NULL))
            return STATUS_SUCCESS;
        Size += FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + sizeof(SidBuffer);
    }

    Acl = ExAllocatePoolWithTag(PagedPool, Size, TAG_OB_NAMESPACE);
    if (!Acl)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = RtlCreateAcl(Acl, Size, ACL_REVISION);
    if (NT_SUCCESS(Status) && Count != 0)
    {
        for (i = 0; i < CallerSacl->AceCount && NT_SUCCESS(Status); i++)
        {
            Status = RtlGetAce(CallerSacl, i, (PVOID *)&Ace);
            if (NT_SUCCESS(Status) && Ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                Status = RtlAddAce(Acl, ACL_REVISION, MAXULONG, Ace, Ace->AceSize);
        }
    }
    else if (NT_SUCCESS(Status))
    {
        RtlInitializeSid(LabelSid, &MandatoryAuthority, 1);
        *RtlSubAuthoritySid(LabelSid, 0) = ObpBoundaryLevel(Boundary->Label);
        Status = RtlAddMandatoryAce(Acl, ACL_REVISION, 0, LabelSid, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                                    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
    }
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Acl, TAG_OB_NAMESPACE);
        return Status;
    }
    *Sacl = Acl;
    return STATUS_SUCCESS;
}

/* SYSTEM CALLS ***************************************************************/

NTSTATUS
NTAPI
NtCreatePrivateNamespace(
    _Out_ PHANDLE NamespaceHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PVOID BoundaryDescriptor)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PSECURITY_DESCRIPTOR UserSd = NULL, CapturedSd = NULL;
    SECURITY_DESCRIPTOR NewSd;
    PACL CallerSacl = NULL, Sacl = NULL;
    OBJECT_ATTRIBUTES KernelAttributes;
    UNICODE_STRING Name = {0};
    OBP_BOUNDARY Boundary;
    HANDLE KernelHandle = NULL, Handle = NULL;
    ULONG Attributes = 0;
    PVOID Directory = NULL;
    NTSTATUS Status;

    PAGED_CODE();

    /* The handle, and what the attributes carry: inheritance and the security descriptor (no name) */
    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            ProbeForWriteHandle(NamespaceHandle);
            if (ObjectAttributes)
                ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(ULONG));
        }
        if (ObjectAttributes)
        {
            if (ObjectAttributes->Length != sizeof(OBJECT_ATTRIBUTES) || ObjectAttributes->ObjectName != NULL)
                _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
            Attributes = ObjectAttributes->Attributes & OBJ_INHERIT;
            UserSd = ObjectAttributes->SecurityDescriptor;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* The creator gets what it asks for, as with any object it creates; the SACL still needs the privilege */
    if (DesiredAccess & MAXIMUM_ALLOWED)
        DesiredAccess = (DesiredAccess & ~MAXIMUM_ALLOWED) | DIRECTORY_ALL_ACCESS;
    if ((DesiredAccess & ACCESS_SYSTEM_SECURITY) &&
        !SeSinglePrivilegeCheck(SeSecurityPrivilege, PreviousMode))
    {
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    Status = ObpCaptureBoundary(BoundaryDescriptor, PreviousMode, &Boundary);
    if (!NT_SUCCESS(Status))
        return Status;

    /* "A new boundary descriptor must have at least one SID"; the caller must be within the boundary */
    if (Boundary.SidCount == 0)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    Status = ObpCheckWithinBoundary(&Boundary);
    if (!NT_SUCCESS(Status))
        goto done;

    /*
     * The descriptor of the directory, complete before it exists: the creator's owner, group and DACL as it gave
     * them (read once, from the captured copy), its label or else the boundary's; what it leaves out comes from
     * its token, as for any object it creates. The parts whose validity depends on the creator's token are
     * checked against it first, as a set by the creator would check them: a label above its own level needs
     * SeRelabelPrivilege (SeCheckLabelChange), and an owner must be one it may assign (SepCheckOwnerSid).
     * The kernel-mode create then assigns all of it at the insert: no opener ever finds the directory with
     * another descriptor, and no handle with WRITE_DAC or WRITE_OWNER is made on the way.
     */
    Status = RtlCreateSecurityDescriptor(&NewSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
        goto done;
    if (UserSd)
    {
        BOOLEAN Present, Defaulted;
        PSID Sid;
        PACL Acl;

        Status = SeCaptureSecurityDescriptor(UserSd, PreviousMode, PagedPool, TRUE, &CapturedSd);
        if (!NT_SUCCESS(Status))
            goto done;
        if (NT_SUCCESS(RtlGetOwnerSecurityDescriptor(CapturedSd, &Sid, &Defaulted)) && Sid)
        {
            SECURITY_SUBJECT_CONTEXT SubjectContext;

            SeCaptureSubjectContext(&SubjectContext);
            Status = SepCheckOwnerSid(Sid, &SubjectContext, PreviousMode);
            SeReleaseSubjectContext(&SubjectContext);
            if (!NT_SUCCESS(Status))
                goto done;
            RtlSetOwnerSecurityDescriptor(&NewSd, Sid, FALSE);
        }
        if (NT_SUCCESS(RtlGetGroupSecurityDescriptor(CapturedSd, &Sid, &Defaulted)) && Sid)
            RtlSetGroupSecurityDescriptor(&NewSd, Sid, FALSE);
        if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(CapturedSd, &Present, &Acl, &Defaulted)) && Present)
            RtlSetDaclSecurityDescriptor(&NewSd, TRUE, Acl, FALSE);
        if (NT_SUCCESS(RtlGetSaclSecurityDescriptor(CapturedSd, &Present, &Acl, &Defaulted)) && Present)
        {
            Status = SeCheckLabelChange(CapturedSd, PreviousMode);
            if (!NT_SUCCESS(Status))
                goto done;
            CallerSacl = Acl;
        }
    }
    Status = ObpBuildNamespaceSacl(CallerSacl, &Boundary, &Sacl);
    if (!NT_SUCCESS(Status))
        goto done;
    if (Sacl)
        RtlSetSaclSecurityDescriptor(&NewSd, TRUE, Sacl, FALSE);

    Status = ObpBuildNamespaceName(&Boundary, &Name);
    if (!NT_SUCCESS(Status))
        goto done;

    /* The directory, with that descriptor (and the creator's subject context); an existing one is a collision */
    InitializeObjectAttributes(&KernelAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &NewSd);
    Status = ZwCreateDirectoryObject(&KernelHandle, DIRECTORY_ALL_ACCESS, &KernelAttributes);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = ObReferenceObjectByHandle(KernelHandle, 0, ObpDirectoryObjectType, KernelMode, &Directory, NULL);
    if (!NT_SUCCESS(Status))
        goto done;

    /* The creator's handle, with the access it asked for */
    Status = ObOpenObjectByPointer(Directory, Attributes, NULL, DesiredAccess, ObpDirectoryObjectType,
                                   KernelMode, &Handle);
    if (!NT_SUCCESS(Status))
        goto done;

    _SEH2_TRY
    {
        *NamespaceHandle = Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ObCloseHandle(Handle, KernelMode);
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

done:
    if (Directory)
        ObDereferenceObject(Directory);
    if (KernelHandle)
        ZwClose(KernelHandle);
    if (Name.Buffer)
        ExFreePoolWithTag(Name.Buffer, TAG_OB_NAMESPACE);
    if (Sacl)
        ExFreePoolWithTag(Sacl, TAG_OB_NAMESPACE);
    if (CapturedSd)
        SeReleaseSecurityDescriptor(CapturedSd, PreviousMode, TRUE);
    ObpFreeBoundary(&Boundary);
    return Status;
}

NTSTATUS
NTAPI
NtOpenPrivateNamespace(
    _Out_ PHANDLE NamespaceHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PVOID BoundaryDescriptor)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    UNICODE_STRING Name = {0};
    OBP_BOUNDARY Boundary;
    PVOID Directory = NULL;
    ULONG Attributes = 0;
    HANDLE Handle;
    NTSTATUS Status;

    PAGED_CODE();

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            ProbeForWriteHandle(NamespaceHandle);
            if (ObjectAttributes)
                ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(ULONG));
        }
        if (ObjectAttributes)
        {
            if (ObjectAttributes->Length != sizeof(OBJECT_ATTRIBUTES) || ObjectAttributes->ObjectName != NULL)
                _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
            Attributes = ObjectAttributes->Attributes & OBJ_INHERIT;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    Status = ObpCaptureBoundary(BoundaryDescriptor, PreviousMode, &Boundary);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = ObpBuildNamespaceName(&Boundary, &Name);
    if (!NT_SUCCESS(Status))
        goto done;

    /* Found by its boundary; opened with an access check of the caller against its descriptor */
    Status = ObReferenceObjectByName(&Name, OBJ_CASE_INSENSITIVE, NULL, 0, ObpDirectoryObjectType, KernelMode,
                                     NULL, &Directory);
    if (!NT_SUCCESS(Status))
        goto done;
    Status = ObOpenObjectByPointer(Directory, Attributes, NULL, DesiredAccess, ObpDirectoryObjectType,
                                   PreviousMode, &Handle);
    if (!NT_SUCCESS(Status))
        goto done;

    _SEH2_TRY
    {
        *NamespaceHandle = Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ObCloseHandle(Handle, PreviousMode);
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

done:
    if (Directory)
        ObDereferenceObject(Directory);
    if (Name.Buffer)
        ExFreePoolWithTag(Name.Buffer, TAG_OB_NAMESPACE);
    ObpFreeBoundary(&Boundary);
    return Status;
}

/* EOF */
