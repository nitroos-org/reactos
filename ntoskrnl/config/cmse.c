/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/config/cmse.c
 * PURPOSE:         Configuration Manager - Security Subsystem Interface
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "ntoskrnl.h"
#define NDEBUG
#include "debug.h"

/* GLOBALS *******************************************************************/

/*
 * The descriptor every key had before keys had their own (owner and group
 * Everyone, a DACL that grants Everyone GENERIC_ALL, a NULL SACL): what the
 * open decision is still made against (CmpCheckKeyOpenAccess) until key
 * access is enforced, and what a key reports in legacy mode.
 */
typedef struct _CMP_LEGACY_KEY_SD
{
    SECURITY_DESCRIPTOR_RELATIVE Header;
    SID Owner;
    SID Group;
    ACL Dacl;
    struct
    {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
        SID Sid;
    } Ace;
} CMP_LEGACY_KEY_SD;

static CMP_LEGACY_KEY_SD CmpLegacyKeySd =
{
    {
        SECURITY_DESCRIPTOR_REVISION, 0,
        SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT,
        FIELD_OFFSET(CMP_LEGACY_KEY_SD, Owner),
        FIELD_OFFSET(CMP_LEGACY_KEY_SD, Group),
        0,
        FIELD_OFFSET(CMP_LEGACY_KEY_SD, Dacl)
    },
    { SID_REVISION, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID} },
    { SID_REVISION, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID} },
    { ACL_REVISION, 0, sizeof(ACL) + sizeof(((CMP_LEGACY_KEY_SD *)0)->Ace), 1, 0 },
    {
        { ACCESS_ALLOWED_ACE_TYPE, 0, sizeof(((CMP_LEGACY_KEY_SD *)0)->Ace) },
        GENERIC_ALL,
        { SID_REVISION, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID} }
    }
};

/* Room for the legacy descriptor, whatever part of it is asked for */
#define CMP_LEGACY_SD_BUFFER 128
C_ASSERT(sizeof(CMP_LEGACY_KEY_SD) <= CMP_LEGACY_SD_BUFFER);

/* FUNCTIONS *****************************************************************/

/*
 * The access decision of a key open (CmpDoOpen), made in the configuration
 * manager rather than by the object manager: ObCheckObjectAccess would check
 * the descriptor the key reports (NtQuerySecurityObject), which is now the
 * key's real one, and so would enforce key security in every mode. Until
 * enforcement exists (registry ACL plan R8, mode 2 only), the decision is the
 * one opens always had: the check runs against the legacy descriptor, so it
 * grants what was granted before (and still asks for SeSecurityPrivilege for
 * ACCESS_SYSTEM_SECURITY), and the audit mode's shadow check (CmpDoOpen)
 * records what Windows would decide. Same steps as ObCheckObjectAccess: the
 * privileges used go into the access state, the granted access moves from
 * the remaining to the granted mask, and the open audit alarm runs.
 *
 * The handle the open returns is created with ObCreateHandle (the key body
 * is a new object), which checks no descriptor again; a duplicate that asks
 * for more access is refused for keys (no default security method), so this
 * is the only access decision taken on a key's descriptor.
 */
BOOLEAN
NTAPI
CmpCheckKeyOpenAccess(
    _In_ PVOID Object,
    _Inout_ PACCESS_STATE AccessState,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PNTSTATUS AccessStatus)
{
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)&CmpLegacyKeySd;
    PPRIVILEGE_SET Privileges = NULL;
    ACCESS_MASK GrantedAccess = 0;
    BOOLEAN Result;

    PAGED_CODE();

    SeLockSubjectContext(&AccessState->SubjectSecurityContext);

    Result = SeAccessCheck(Sd,
                           &AccessState->SubjectSecurityContext,
                           TRUE,
                           AccessState->RemainingDesiredAccess,
                           AccessState->PreviouslyGrantedAccess,
                           &Privileges,
                           &CmpKeyObjectType->TypeInfo.GenericMapping,
                           AccessMode,
                           &GrantedAccess,
                           AccessStatus);
    if (Privileges)
    {
        SeAppendPrivileges(AccessState, Privileges);
        SeFreePrivileges(Privileges);
    }

    if (Result)
    {
        AccessState->RemainingDesiredAccess &= ~(GrantedAccess | MAXIMUM_ALLOWED);
        AccessState->PreviouslyGrantedAccess |= GrantedAccess;
    }
    else if (*AccessStatus == STATUS_PRIVILEGE_NOT_HELD)
    {
        /*
         * ACCESS_SYSTEM_SECURITY without SeSecurityPrivilege: opening an
         * existing key fails with STATUS_ACCESS_DENIED on Windows (oracle,
         * administrator with the privilege disabled, every key tried).
         */
        *AccessStatus = STATUS_ACCESS_DENIED;
    }

    SeOpenObjectAuditAlarm(&CmpKeyObjectType->Name,
                           Object,
                           NULL,
                           Sd,
                           AccessState,
                           FALSE,
                           Result,
                           AccessMode,
                           &AccessState->GenerateOnClose);

    SeUnlockSubjectContext(&AccessState->SubjectSecurityContext);
    return Result;
}

PSECURITY_DESCRIPTOR
NTAPI
CmpHiveRootSecurityDescriptor(VOID)
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PACL Acl, AclCopy;
    PSID Sid[4];
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    ULONG AceLength, AclLength, SidLength;
    PACE_HEADER AceHeader;
    ULONG i;
    PAGED_CODE();

    /* Phase 1: Allocate SIDs */
    SidLength = RtlLengthRequiredSid(1);
    Sid[0] = ExAllocatePoolWithTag(PagedPool, SidLength, TAG_CMSD);
    Sid[1] = ExAllocatePoolWithTag(PagedPool, SidLength, TAG_CMSD);
    Sid[2] = ExAllocatePoolWithTag(PagedPool, SidLength, TAG_CMSD);
    SidLength = RtlLengthRequiredSid(2);
    Sid[3] = ExAllocatePoolWithTag(PagedPool, SidLength, TAG_CMSD);

    /* Make sure all SIDs were allocated */
    if (!Sid[0] || !Sid[1] || !Sid[2] || !Sid[3])
    {
        /* Bugcheck */
        KeBugCheckEx(REGISTRY_ERROR, 11, 1, 0, 0);
    }

    /* Phase 2: Initialize all SIDs */
    Status = RtlInitializeSid(Sid[0], &WorldAuthority, 1);
    Status |= RtlInitializeSid(Sid[1], &NtAuthority, 1);
    Status |= RtlInitializeSid(Sid[2], &NtAuthority, 1);
    Status |= RtlInitializeSid(Sid[3], &NtAuthority, 2);
    if (!NT_SUCCESS(Status)) KeBugCheckEx(REGISTRY_ERROR, 11, 2, 0, 0);

    /* Phase 2: Setup SID Sub Authorities */
    *RtlSubAuthoritySid(Sid[0], 0) = SECURITY_WORLD_RID;
    *RtlSubAuthoritySid(Sid[1], 0) = SECURITY_RESTRICTED_CODE_RID;
    *RtlSubAuthoritySid(Sid[2], 0) = SECURITY_LOCAL_SYSTEM_RID;
    *RtlSubAuthoritySid(Sid[3], 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(Sid[3], 1) = DOMAIN_ALIAS_RID_ADMINS;

    /* Make sure all SIDs are valid */
    ASSERT(RtlValidSid(Sid[0]));
    ASSERT(RtlValidSid(Sid[1]));
    ASSERT(RtlValidSid(Sid[2]));
    ASSERT(RtlValidSid(Sid[3]));

    /* Phase 3: Calculate ACL Length */
    AclLength = sizeof(ACL);
    for (i = 0; i < 4; i++)
    {
        /* This is what MSDN says to do */
        AceLength = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
        AceLength += SeLengthSid(Sid[i]);
        AclLength += AceLength;
    }

    /* Phase 3: Allocate the ACL */
    Acl = ExAllocatePoolWithTag(PagedPool, AclLength, TAG_CMSD);
    if (!Acl) KeBugCheckEx(REGISTRY_ERROR, 11, 3, 0, 0);

    /* Phase 4: Create the ACL */
    Status = RtlCreateAcl(Acl, AclLength, ACL_REVISION);
    if (!NT_SUCCESS(Status)) KeBugCheckEx(REGISTRY_ERROR, 11, 4, Status, 0);

    /* Phase 5: Build the ACL */
    Status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, KEY_ALL_ACCESS, Sid[2]);
    Status |= RtlAddAccessAllowedAce(Acl, ACL_REVISION, KEY_ALL_ACCESS, Sid[3]);
    Status |= RtlAddAccessAllowedAce(Acl, ACL_REVISION, KEY_READ, Sid[0]);
    Status |= RtlAddAccessAllowedAce(Acl, ACL_REVISION, KEY_READ, Sid[1]);
    if (!NT_SUCCESS(Status)) KeBugCheckEx(REGISTRY_ERROR, 11, 5, Status, 0);

    /* Phase 5: Make the ACEs inheritable */
    Status = RtlGetAce(Acl, 0, (PVOID*)&AceHeader);
    ASSERT(NT_SUCCESS(Status));
    AceHeader->AceFlags |= CONTAINER_INHERIT_ACE;
    Status = RtlGetAce(Acl, 1, (PVOID*)&AceHeader);
    ASSERT(NT_SUCCESS(Status));
    AceHeader->AceFlags |= CONTAINER_INHERIT_ACE;
    Status = RtlGetAce(Acl, 2, (PVOID*)&AceHeader);
    ASSERT(NT_SUCCESS(Status));
    AceHeader->AceFlags |= CONTAINER_INHERIT_ACE;
    Status = RtlGetAce(Acl, 3, (PVOID*)&AceHeader);
    ASSERT(NT_SUCCESS(Status));
    AceHeader->AceFlags |= CONTAINER_INHERIT_ACE;

    /* Phase 6: Allocate the security descriptor and make space for the ACL */
    SecurityDescriptor = ExAllocatePoolWithTag(PagedPool,
                                               sizeof(SECURITY_DESCRIPTOR) +
                                               AclLength,
                                               TAG_CMSD);
    if (!SecurityDescriptor) KeBugCheckEx(REGISTRY_ERROR, 11, 6, 0, 0);

    /* Phase 6: Make a copy of the ACL */
    AclCopy = (PACL)((PISECURITY_DESCRIPTOR)SecurityDescriptor + 1);
    RtlCopyMemory(AclCopy, Acl, AclLength);

    /* Phase 7: Create the security descriptor */
    Status = RtlCreateSecurityDescriptor(SecurityDescriptor,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status)) KeBugCheckEx(REGISTRY_ERROR, 11, 7, Status, 0);

    /* Phase 8: Set the ACL as a DACL */
    Status = RtlSetDaclSecurityDescriptor(SecurityDescriptor,
                                          TRUE,
                                          AclCopy,
                                          FALSE);
    if (!NT_SUCCESS(Status)) KeBugCheckEx(REGISTRY_ERROR, 11, 8, Status, 0);

    /* Free the SIDs and original ACL */
    for (i = 0; i < 4; i++) ExFreePoolWithTag(Sid[i], TAG_CMSD);
    ExFreePoolWithTag(Acl, TAG_CMSD);

    /* Return the security descriptor */
    return SecurityDescriptor;
}

NTSTATUS
CmpQuerySecurityDescriptor(IN PCM_KEY_CONTROL_BLOCK Kcb,
                           IN SECURITY_INFORMATION SecurityInformation,
                           OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
                           IN OUT PULONG BufferLength)
{
    PISECURITY_DESCRIPTOR_RELATIVE RelSd;
    ULONG SidSize;
    ULONG AclSize;
    ULONG SdSize;
    NTSTATUS Status;
    SECURITY_DESCRIPTOR_CONTROL Control = 0;
    ULONG Owner = 0;
    ULONG Group = 0;
    ULONG Dacl = 0;

    DBG_UNREFERENCED_PARAMETER(Kcb);

    DPRINT("CmpQuerySecurityDescriptor()\n");

    if (SecurityInformation == 0)
    {
        return STATUS_ACCESS_DENIED;
    }

    SidSize = RtlLengthSid(SeWorldSid);
    RelSd = SecurityDescriptor;
    SdSize = sizeof(*RelSd);

    if (SecurityInformation & OWNER_SECURITY_INFORMATION)
    {
        Owner = SdSize;
        SdSize += SidSize;
    }

    if (SecurityInformation & GROUP_SECURITY_INFORMATION)
    {
        Group = SdSize;
        SdSize += SidSize;
    }

    if (SecurityInformation & DACL_SECURITY_INFORMATION)
    {
        Control |= SE_DACL_PRESENT;
        Dacl = SdSize;
        AclSize = sizeof(ACL) + sizeof(ACE) + SidSize;
        SdSize += AclSize;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
    {
        Control |= SE_SACL_PRESENT;
    }

    if (*BufferLength < SdSize)
    {
        *BufferLength = SdSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    *BufferLength = SdSize;

    Status = RtlCreateSecurityDescriptorRelative(RelSd,
                                                 SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
        return Status;

    RelSd->Control |= Control;
    RelSd->Owner = Owner;
    RelSd->Group = Group;
    RelSd->Dacl = Dacl;

    if (Owner)
        RtlCopyMemory((PUCHAR)RelSd + Owner,
                      SeWorldSid,
                      SidSize);

    if (Group)
        RtlCopyMemory((PUCHAR)RelSd + Group,
                      SeWorldSid,
                      SidSize);

    if (Dacl)
    {
        Status = RtlCreateAcl((PACL)((PUCHAR)RelSd + Dacl),
                              AclSize,
                              ACL_REVISION);
        if (NT_SUCCESS(Status))
        {
            Status = RtlAddAccessAllowedAce((PACL)((PUCHAR)RelSd + Dacl),
                                            ACL_REVISION,
                                            GENERIC_ALL,
                                            SeWorldSid);
        }
    }

    ASSERT(Status == STATUS_SUCCESS);
    return Status;
}

/*
 * What Windows does to a key's DACL when it is set (oracle, NtSetSecurityObject
 * with DACL_SECURITY_INFORMATION):
 *  - generic rights in an ACE that applies to the key are mapped to key rights
 *    (GR -> KR, GA -> KA); an inherit-only ACE keeps them (it applies to no key yet);
 *  - SE_DACL_AUTO_INHERITED stays only if the caller asked for auto-inheritance
 *    (SE_DACL_AUTO_INHERIT_REQ): "D:AI" comes back as "D:", "D:ARAI" as "D:AI"
 *    (the request itself is not stored, and nothing is inherited from the parent);
 *  - a descriptor without a DACL sets a NULL DACL ("D:NO_ACCESS_CONTROL"), as one
 *    with a NULL DACL does.
 * NewSd is the merged self-relative descriptor (our pool copy), changed in place.
 */
static
VOID
CmpAdjustSetDacl(IN PSECURITY_DESCRIPTOR NewSd,
                 IN PSECURITY_DESCRIPTOR CallerSd,
                 IN PGENERIC_MAPPING GenericMapping)
{
    PISECURITY_DESCRIPTOR_RELATIVE Sd = NewSd;
    SECURITY_DESCRIPTOR_CONTROL CallerControl;
    ULONG Revision;
    PACE_HEADER Ace;
    PACL Dacl;
    ULONG i;

    if (!NT_SUCCESS(RtlGetControlSecurityDescriptor(CallerSd, &CallerControl, &Revision)))
        CallerControl = 0;

    Sd->Control |= SE_DACL_PRESENT;
    if (CallerControl & SE_DACL_AUTO_INHERIT_REQ)
        Sd->Control |= SE_DACL_AUTO_INHERITED;
    else
        Sd->Control &= ~SE_DACL_AUTO_INHERITED;
    Sd->Control &= ~SE_DACL_AUTO_INHERIT_REQ;

    if (!Sd->Dacl)
        return;
    Dacl = (PACL)((PUCHAR)Sd + Sd->Dacl);
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!NT_SUCCESS(RtlGetAce(Dacl, i, (PVOID *)&Ace)))
            break;
        if (Ace->AceFlags & INHERIT_ONLY_ACE)
            continue;
        /* Every ACE type the kernel knows has the mask right after the header */
        if (Ace->AceSize < sizeof(ACE_HEADER) + sizeof(ACCESS_MASK))
            continue;
        if (*(PACCESS_MASK)(Ace + 1) & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL))
            RtlMapGenericMask((PACCESS_MASK)(Ace + 1), GenericMapping);
    }
}

/*
 * NtSetSecurityObject on a key. The parts the caller names are merged into
 * the key's descriptor (its stored one, or the one it reports: see
 * CmpCaptureKeySecurity) by SeSetSecurityDescriptorInfoEx, which keeps the
 * other parts; the result goes to an 'sk' cell of the key's storage type,
 * shared with the keys that already have the same bytes, and the key's old
 * cell loses the key's reference (and goes with its last one). Nothing is
 * propagated to subkeys (Windows leaves that to user mode). The key's last
 * write time changes, and REG_NOTIFY_CHANGE_SECURITY (and _ATTRIBUTES)
 * watchers of the key (and of a tree above it) are told (oracle).
 *
 * An owner set from user mode must be one the caller may assign
 * (SepCheckOwnerSid): STATUS_INVALID_OWNER otherwise (ERROR_INVALID_OWNER,
 * as Windows). The rights to the handle (WRITE_DAC, WRITE_OWNER,
 * ACCESS_SYSTEM_SECURITY) and the label rule were checked by the object
 * manager before this runs.
 *
 * In legacy mode (and before the tables exist) nothing is stored: success,
 * as before. The caller holds the registry lock shared and the KCB
 * exclusively.
 */
static
NTSTATUS
CmpSetSecurityDescriptor(IN PCM_KEY_CONTROL_BLOCK Kcb,
                         IN PSECURITY_INFORMATION SecurityInformation,
                         IN PSECURITY_DESCRIPTOR SecurityDescriptor,
                         IN PGENERIC_MAPPING GenericMapping,
                         IN KPROCESSOR_MODE AccessMode)
{
    PHHIVE Hive = Kcb->KeyHive;
    PSECURITY_DESCRIPTOR Current, NewSd;
    SECURITY_INFORMATION Information;
    SECURITY_SUBJECT_CONTEXT Subject;
    PCM_KEY_NODE Node;
    HCELL_INDEX OldCell, NewCell;
    BOOLEAN Defaulted, Acquired;
    PSID Owner;
    ULONG Length;
    NTSTATUS Status;

    DPRINT("CmpSetSecurityDescriptor(%p, 0x%lx)\n", Kcb, *SecurityInformation);

    if (!CmpStoreExplicitKeySecurity() ||
        !Hive || Kcb->KeyCell == HCELL_NIL || (Kcb->ExtFlags & CM_KCB_KEY_NON_EXIST))
    {
        return STATUS_SUCCESS;
    }
    if (Kcb->ExtFlags & CM_KCB_READ_ONLY_KEY)
        return STATUS_ACCESS_DENIED;

    /* The owner: the caller's own, one of its owner groups, or any with SeRestorePrivilege */
    if ((*SecurityInformation & OWNER_SECURITY_INFORMATION) && AccessMode != KernelMode)
    {
        Status = RtlGetOwnerSecurityDescriptor(SecurityDescriptor, &Owner, &Defaulted);
        if (!NT_SUCCESS(Status) || !Owner)
            return STATUS_INVALID_OWNER;
        SeCaptureSubjectContext(&Subject);
        Status = SepCheckOwnerSid(Owner, &Subject, AccessMode);
        SeReleaseSubjectContext(&Subject);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    /*
     * Merge into what the key has (or reports). The (UN)PROTECTED_*_SECURITY_INFORMATION
     * flags are not looked at: on Windows a key's DACL is protected by the control bit of
     * the descriptor set, whatever the flags say (oracle; SetSecurityInfo turns the flags
     * into the control bit in user mode).
     */
    Information = *SecurityInformation &
                  ~(PROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION |
                    PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION);
    Current = CmpCaptureKeySecurity(Kcb);
    if (!Current)
        return STATUS_INSUFFICIENT_RESOURCES;
    NewSd = Current;
    Status = SeSetSecurityDescriptorInfoEx(NULL,
                                           &Information,
                                           SecurityDescriptor,
                                           &NewSd,
                                           0,
                                           PagedPool,
                                           GenericMapping);
    CmpFreeParentSecurity(Current);
    if (!NT_SUCCESS(Status))
        return Status;
    if (Information & DACL_SECURITY_INFORMATION)
        CmpAdjustSetDacl(NewSd, SecurityDescriptor, GenericMapping);

    Length = RtlLengthSecurityDescriptor(NewSd);
    if (Length > CMP_MAX_STORED_SD_LENGTH ||
        !RtlValidRelativeSecurityDescriptor(NewSd, Length, 0))
    {
        ExFreePoolWithTag(NewSd, TAG_SD);
        return STATUS_INVALID_SECURITY_DESCR;
    }

    Node = (PCM_KEY_NODE)HvGetCell(Hive, Kcb->KeyCell);
    if (!Node)
    {
        ExFreePoolWithTag(NewSd, TAG_SD);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (Node->Signature != CM_KEY_NODE_SIGNATURE)
    {
        HvReleaseCell(Hive, Kcb->KeyCell);
        ExFreePoolWithTag(NewSd, TAG_SD);
        return STATUS_REGISTRY_CORRUPT;
    }

    CmpLockHiveFlusherShared((PCMHIVE)Hive);
    if (!HvMarkCellDirty(Hive, Kcb->KeyCell, FALSE))
    {
        Status = STATUS_NO_LOG_SPACE;
    }
    else
    {
        /*
         * The new cell takes its reference before the old one gives its own
         * back (the same cell, if the bytes did not change), and the key
         * changes cells under the security lock: a reader that copies the
         * key's descriptor under it (CmpAclCopyStoredSd) sees the old cell or
         * the new one, never a released one.
         */
        Acquired = CmpAcquireHiveSecurityLock(Hive);
        Status = CmpInsertSecurityDescriptor((PCMHIVE)Hive,
                                             NewSd,
                                             Length,
                                             HvGetCellType(Kcb->KeyCell),
                                             &NewCell);
        if (NT_SUCCESS(Status))
        {
            OldCell = Node->Security;
            Node->Security = NewCell;
            if (OldCell != HCELL_NIL && !CmpReleaseSecurityCell(Hive, OldCell))
            {
                /* A count one too high is safe (the hive check corrects it), a freed shared cell is not */
                DPRINT1("Key 0x%x: old security cell 0x%x not released\n", Kcb->KeyCell, OldCell);
            }
        }
        CmpReleaseHiveSecurityLock(Hive, Acquired);

        /* A set changes the key's last write time on Windows (oracle) */
        if (NT_SUCCESS(Status))
        {
            KeQuerySystemTime(&Node->LastWriteTime);
            Kcb->KcbLastWriteTime = Node->LastWriteTime;
        }
    }
    CmpUnlockHiveFlusher((PCMHIVE)Hive);
    HvReleaseCell(Hive, Kcb->KeyCell);
    ExFreePoolWithTag(NewSd, TAG_SD);

    /*
     * Measured on the oracle: a set wakes a watcher of REG_NOTIFY_CHANGE_SECURITY, and one
     * of LAST_SET | NAME | ATTRIBUTES (not told apart by the probe); ATTRIBUTES is the
     * filter documented for descriptor changes.
     */
    if (NT_SUCCESS(Status))
        CmpReportNotify(Kcb, Hive, Kcb->KeyCell, REG_NOTIFY_CHANGE_SECURITY | REG_NOTIFY_CHANGE_ATTRIBUTES);
    return Status;
}

/*
 * NtQuerySecurityObject on a key (and ObGetObjectSecurity): the parts of the
 * key's descriptor named by SecurityInformation, as SeQuerySecurityDescriptorInfo
 * selects them. The SACL needs ACCESS_SYSTEM_SECURITY on the handle, which the
 * object manager checked (SeQuerySecurityAccessMask). The descriptor is taken
 * (a validated copy) under the locks; it is written to the caller's buffer,
 * which may be user memory, after they are released, under SEH.
 */
static
NTSTATUS
CmpQueryKeySecurity(IN PSECURITY_DESCRIPTOR KeySd,
                    IN SECURITY_INFORMATION SecurityInformation,
                    OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
                    IN OUT PULONG BufferLength)
{
    NTSTATUS Status;

    _SEH2_TRY
    {
        Status = SeQuerySecurityDescriptorInfo(&SecurityInformation,
                                               SecurityDescriptor,
                                               BufferLength,
                                               &KeySd);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

/* The legacy descriptor (built by CmpQuerySecurityDescriptor in a buffer of ours) to the caller's buffer */
static
NTSTATUS
CmpCopyLegacyKeySecurity(IN PVOID Legacy,
                         IN ULONG LegacyLength,
                         OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
                         IN OUT PULONG BufferLength)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (*BufferLength < LegacyLength)
    {
        *BufferLength = LegacyLength;
        return STATUS_BUFFER_TOO_SMALL;
    }

    _SEH2_TRY
    {
        RtlCopyMemory(SecurityDescriptor, Legacy, LegacyLength);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    if (NT_SUCCESS(Status))
        *BufferLength = LegacyLength;
    return Status;
}

/*
 * The object manager's assign operation. Keys get their descriptor when they
 * are created (CmpDoCreateChild), so a key normally never sees this; should
 * it, the descriptor is stored on a key that has none yet (in legacy mode,
 * nothing is stored, as before). The caller holds the KCB exclusively.
 */
NTSTATUS
CmpAssignSecurityDescriptor(IN PCM_KEY_CONTROL_BLOCK Kcb,
                            IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{
    PHHIVE Hive = Kcb->KeyHive;
    PCM_KEY_NODE Node;
    HCELL_INDEX SecurityCell;
    ULONG Length;
    NTSTATUS Status;

    DPRINT("CmpAssignSecurityDescriptor(%p %p)\n",
           Kcb, SecurityDescriptor);

    if (!CmpStoreKeySecurity() || !SecurityDescriptor ||
        !Hive || Kcb->KeyCell == HCELL_NIL || (Kcb->ExtFlags & CM_KCB_KEY_NON_EXIST))
    {
        return STATUS_SUCCESS;
    }

    /* A self-relative descriptor is what an 'sk' cell holds */
    Length = RtlLengthSecurityDescriptor(SecurityDescriptor);
    if (!(((PISECURITY_DESCRIPTOR)SecurityDescriptor)->Control & SE_SELF_RELATIVE) ||
        !RtlValidRelativeSecurityDescriptor(SecurityDescriptor, Length, 0))
    {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    Node = (PCM_KEY_NODE)HvGetCell(Hive, Kcb->KeyCell);
    if (!Node)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (Node->Signature != CM_KEY_NODE_SIGNATURE || Node->Security != HCELL_NIL)
    {
        /* It has one: replacing it is a set, not an assign */
        HvReleaseCell(Hive, Kcb->KeyCell);
        return STATUS_SUCCESS;
    }

    Status = STATUS_NO_LOG_SPACE;
    if (HvMarkCellDirty(Hive, Kcb->KeyCell, FALSE))
    {
        Status = CmpInsertSecurityDescriptor((PCMHIVE)Hive,
                                             SecurityDescriptor,
                                             Length,
                                             HvGetCellType(Kcb->KeyCell),
                                             &SecurityCell);
        if (NT_SUCCESS(Status))
            Node->Security = SecurityCell;
    }
    HvReleaseCell(Hive, Kcb->KeyCell);
    return Status;
}

/*
 * Copying a key into another hive (save, merge): the destination key gets a
 * reference to a cell of the destination hive holding the same descriptor,
 * shared with the keys copied before that have it. The source cell is read
 * under its hive's security lock and the bytes are validated as a copy (the
 * hive is untrusted); a source cell that is not sound gives the copy no
 * descriptor (HCELL_NIL), as the hive check would. The two security locks are
 * never held together.
 *
 * Known race (save against delete, not closed here): CmSaveKey holds the
 * registry lock shared and only the root KCB of the saved tree, without the
 * flusher lock, so a key deeper in the tree can be deleted while the copy
 * runs (that is older than stored descriptors, for the key node itself).
 * The cell index read from the source node can then be released, and the
 * cell reused for another key's descriptor, before the lock below is taken.
 * The cell is checked again under the lock ('sk' signature, bounds, a
 * reference count above zero, the copy validated), so the worst case is a
 * saved key with another key's valid descriptor: no fault, no leak. Closing
 * it needs the source key's KCB or the flusher lock held across the copy.
 */
NTSTATUS
NTAPI
CmpCopyKeySecurityCell(
    _In_ PHHIVE SourceHive,
    _In_ HCELL_INDEX SourceCell,
    _In_ PHHIVE DestinationHive,
    _In_ HSTORAGE_TYPE StorageType,
    _Out_ PHCELL_INDEX DestinationCell)
{
    PCM_KEY_SECURITY Security;
    PVOID Copy = NULL;
    ULONG Length = 0;
    BOOLEAN Acquired;
    NTSTATUS Status;

    *DestinationCell = HCELL_NIL;

    Acquired = CmpAcquireHiveSecurityLock(SourceHive);
    Security = CmpGetCheckedSecurityCell(SourceHive, SourceCell, NULL);
    if (Security &&
        Security->ReferenceCount != 0 &&
        Security->DescriptorLength >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) &&
        Security->DescriptorLength <= CMP_MAX_STORED_SD_LENGTH)
    {
        Length = Security->DescriptorLength;
        Copy = ExAllocatePoolWithTag(PagedPool, Length, TAG_CMSD);
        if (Copy)
            RtlCopyMemory(Copy, &Security->Descriptor, Length);
    }
    CmpReleaseHiveSecurityLock(SourceHive, Acquired);

    if (!Length)
    {
        DPRINT1("Security cell 0x%x is not sound, the copy of its key has none\n", SourceCell);
        return STATUS_SUCCESS;
    }
    if (!Copy)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (RtlValidRelativeSecurityDescriptor(Copy, Length, 0))
    {
        Status = CmpInsertSecurityDescriptor((PCMHIVE)DestinationHive,
                                             Copy,
                                             Length,
                                             StorageType,
                                             DestinationCell);
    }
    else
    {
        DPRINT1("Security cell 0x%x holds no valid descriptor, the copy of its key has none\n", SourceCell);
        Status = STATUS_SUCCESS;
    }
    ExFreePoolWithTag(Copy, TAG_CMSD);
    return Status;
}

NTSTATUS
NTAPI
CmpSecurityMethod(IN PVOID ObjectBody,
                  IN SECURITY_OPERATION_CODE OperationCode,
                  IN PSECURITY_INFORMATION SecurityInformation,
                  IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
                  IN OUT PULONG BufferLength,
                  IN OUT PSECURITY_DESCRIPTOR *OldSecurityDescriptor,
                  IN POOL_TYPE PoolType,
                  IN PGENERIC_MAPPING GenericMapping,
                  IN KPROCESSOR_MODE AccessMode)
{
    PCM_KEY_CONTROL_BLOCK Kcb;
    NTSTATUS Status = STATUS_SUCCESS;
    SECURITY_INFORMATION QueryInformation = 0;
    PSECURITY_DESCRIPTOR KeySd = NULL;
    ULONG Legacy[CMP_LEGACY_SD_BUFFER / sizeof(ULONG)];
    ULONG LegacyLength = 0;

    DBG_UNREFERENCED_PARAMETER(OldSecurityDescriptor);
    DBG_UNREFERENCED_PARAMETER(PoolType);

    Kcb = ((PCM_KEY_BODY)ObjectBody)->KeyControlBlock;

    /* Acquire the hive lock */
    CmpLockRegistry();

    /* Acquire the KCB lock */
    if (OperationCode == QuerySecurityDescriptor)
    {
        /* Avoid recursive locking if somebody already holds it */
        if (!((PCM_KEY_BODY)ObjectBody)->KcbLocked)
        {
            CmpAcquireKcbLockShared(Kcb);
        }
    }
    else
    {
        ASSERT(!((PCM_KEY_BODY)ObjectBody)->KcbLocked);
        CmpAcquireKcbLockExclusive(Kcb);
    }

    /* Don't touch deleted keys */
    if (Kcb->Delete)
    {
        /* Release the KCB lock */
        CmpReleaseKcbLock(Kcb);

        /* Release the hive lock */
        CmpUnlockRegistry();
        return STATUS_KEY_DELETED;
    }

    switch (OperationCode)
    {
        case SetSecurityDescriptor:
            DPRINT("Set security descriptor\n");
            ASSERT((PoolType == PagedPool) || (PoolType == NonPagedPool));
            Status = CmpSetSecurityDescriptor(Kcb,
                                              SecurityInformation,
                                              SecurityDescriptor,
                                              GenericMapping,
                                              AccessMode);
            break;

        case QuerySecurityDescriptor:
            DPRINT("Query security descriptor\n");
            /* Taken here, written out once the locks are released */
            QueryInformation = *SecurityInformation;
            if (CmpStoreExplicitKeySecurity())
            {
                /* The key's own descriptor, or the one it would have on Windows */
                KeySd = CmpCaptureKeySecurity(Kcb);
                if (!KeySd)
                    Status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else
            {
                /* Legacy mode (and early boot): the descriptor keys always reported */
                LegacyLength = sizeof(Legacy);
                Status = CmpQuerySecurityDescriptor(Kcb,
                                                    QueryInformation,
                                                    Legacy,
                                                    &LegacyLength);
            }
            break;

        case DeleteSecurityDescriptor:
            DPRINT("Delete security descriptor\n");
            /* HACK */
            break;

        case AssignSecurityDescriptor:
            DPRINT("Assign security descriptor\n");
            Status = CmpAssignSecurityDescriptor(Kcb,
                                                 SecurityDescriptor);
            break;

        default:
            KeBugCheckEx(SECURITY_SYSTEM, 0, STATUS_INVALID_PARAMETER, 0, 0);
    }

    /*
     * Release the KCB lock, but only if we locked it ourselves and
     * nobody else was locking it by themselves.
     */
    if (!((PCM_KEY_BODY)ObjectBody)->KcbLocked)
    {
        CmpReleaseKcbLock(Kcb);
    }

    /* Release the hive lock */
    CmpUnlockRegistry();

    /* A query writes to the caller's buffer only now */
    if (OperationCode == QuerySecurityDescriptor && NT_SUCCESS(Status))
    {
        if (KeySd)
            Status = CmpQueryKeySecurity(KeySd, QueryInformation, SecurityDescriptor, BufferLength);
        else
            Status = CmpCopyLegacyKeySecurity(Legacy, LegacyLength, SecurityDescriptor, BufferLength);
    }
    if (KeySd)
        CmpFreeParentSecurity(KeySd);

    return Status;
}
