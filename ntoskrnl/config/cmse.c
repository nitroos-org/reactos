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

/* FUNCTIONS *****************************************************************/

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

NTSTATUS
CmpSetSecurityDescriptor(IN PCM_KEY_CONTROL_BLOCK Kcb,
                         IN PSECURITY_INFORMATION SecurityInformation,
                         IN PSECURITY_DESCRIPTOR SecurityDescriptor,
                         IN POOL_TYPE PoolType,
                         IN PGENERIC_MAPPING GenericMapping)
{
    DPRINT("CmpSetSecurityDescriptor()\n");
    return STATUS_SUCCESS;
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

    DBG_UNREFERENCED_PARAMETER(OldSecurityDescriptor);
    DBG_UNREFERENCED_PARAMETER(GenericMapping);

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
                                              PoolType,
                                              GenericMapping);
            break;

        case QuerySecurityDescriptor:
            DPRINT("Query security descriptor\n");
            Status = CmpQuerySecurityDescriptor(Kcb,
                                                *SecurityInformation,
                                                SecurityDescriptor,
                                                BufferLength);
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

    return Status;
}
