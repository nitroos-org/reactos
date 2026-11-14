/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/security.c
 * PURPOSE:           Security related functions and Security Objects
 * PROGRAMMER:        Eric Kohl
 */

/* INCLUDES *******************************************************************/

#include <rtl.h>
#define NDEBUG
#include <debug.h>

/* PRIVATE FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
RtlpSetSecurityObject(IN PVOID Object OPTIONAL,
                      IN SECURITY_INFORMATION SecurityInformation,
                      IN PSECURITY_DESCRIPTOR ModificationDescriptor,
                      IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
                      IN ULONG AutoInheritFlags,
                      IN ULONG PoolType,
                      IN PGENERIC_MAPPING GenericMapping,
                      IN HANDLE Token OPTIONAL)
{
    PISECURITY_DESCRIPTOR_RELATIVE pNewSd = NULL;
    PSID pOwnerSid = NULL;
    PSID pGroupSid = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    BOOLEAN Defaulted;
    BOOLEAN Present;
    ULONG ulOwnerSidSize = 0, ulGroupSidSize = 0;
    ULONG ulDaclSize = 0, ulSaclSize = 0;
    ULONG ulNewSdSize;
    SECURITY_DESCRIPTOR_CONTROL Control = SE_SELF_RELATIVE;
    PUCHAR pDest;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("RtlpSetSecurityObject()\n");

    /* Change the Owner SID */
    if (SecurityInformation & OWNER_SECURITY_INFORMATION)
    {
        Status = RtlGetOwnerSecurityDescriptor(ModificationDescriptor, &pOwnerSid, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;
    }
    else
    {
        Status = RtlGetOwnerSecurityDescriptor(*ObjectsSecurityDescriptor, &pOwnerSid, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    if (pOwnerSid == NULL || !RtlValidSid(pOwnerSid))
        return STATUS_INVALID_OWNER;

    ulOwnerSidSize = RtlLengthSid(pOwnerSid);

    /* Change the Group SID */
    if (SecurityInformation & GROUP_SECURITY_INFORMATION)
    {
        Status = RtlGetGroupSecurityDescriptor(ModificationDescriptor, &pGroupSid, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;
    }
    else
    {
        Status = RtlGetGroupSecurityDescriptor(*ObjectsSecurityDescriptor, &pGroupSid, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    if (pGroupSid == NULL || !RtlValidSid(pGroupSid))
        return STATUS_INVALID_PRIMARY_GROUP;

    ulGroupSidSize = ROUND_UP(RtlLengthSid(pGroupSid), sizeof(ULONG));

    /* Change the DACL */
    if (SecurityInformation & DACL_SECURITY_INFORMATION)
    {
        Status = RtlGetDaclSecurityDescriptor(ModificationDescriptor, &Present, &pDacl, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;

        Control |= SE_DACL_PRESENT;
    }
    else
    {
        Status = RtlGetDaclSecurityDescriptor(*ObjectsSecurityDescriptor, &Present, &pDacl, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;

        if (Present)
            Control |= SE_DACL_PRESENT;

        if (Defaulted)
            Control |= SE_DACL_DEFAULTED;
    }

    if (pDacl != NULL)
        ulDaclSize = pDacl->AclSize;

    /* Change the SACL */
    if (SecurityInformation & SACL_SECURITY_INFORMATION)
    {
        Status = RtlGetSaclSecurityDescriptor(ModificationDescriptor, &Present, &pSacl, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;

        Control |= SE_SACL_PRESENT;
    }
    else
    {
        Status = RtlGetSaclSecurityDescriptor(*ObjectsSecurityDescriptor, &Present, &pSacl, &Defaulted);
        if (!NT_SUCCESS(Status))
            return Status;

        if (Present)
            Control |= SE_SACL_PRESENT;

        if (Defaulted)
            Control |= SE_SACL_DEFAULTED;
    }

    if (pSacl != NULL)
        ulSaclSize = pSacl->AclSize;

    /* Calculate the size of the new security descriptor */
    ulNewSdSize = sizeof(SECURITY_DESCRIPTOR_RELATIVE) +
                  ROUND_UP(ulOwnerSidSize, sizeof(ULONG)) +
                  ROUND_UP(ulGroupSidSize, sizeof(ULONG)) +
                  ROUND_UP(ulDaclSize, sizeof(ULONG)) +
                  ROUND_UP(ulSaclSize, sizeof(ULONG));

    /* Allocate the new security descriptor */
    pNewSd = RtlAllocateHeap(RtlGetProcessHeap(), 0, ulNewSdSize);
    if (pNewSd == NULL)
    {
        Status = STATUS_NO_MEMORY;
        DPRINT1("New security descriptor allocation failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Initialize the new security descriptor */
    Status = RtlCreateSecurityDescriptorRelative(pNewSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("New security descriptor creation failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Set the security descriptor control flags */
    pNewSd->Control = Control;

    pDest = (PUCHAR)((ULONG_PTR)pNewSd + sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    /* Copy the SACL */
    if (pSacl != NULL)
    {
        RtlCopyMemory(pDest, pSacl, ulSaclSize);
        pNewSd->Sacl = (ULONG_PTR)pDest - (ULONG_PTR)pNewSd;
        pDest = pDest + ROUND_UP(ulSaclSize, sizeof(ULONG));
    }

    /* Copy the DACL */
    if (pDacl != NULL)
    {
        RtlCopyMemory(pDest, pDacl, ulDaclSize);
        pNewSd->Dacl = (ULONG_PTR)pDest - (ULONG_PTR)pNewSd;
        pDest = pDest + ROUND_UP(ulDaclSize, sizeof(ULONG));
    }

    /* Copy the Owner SID */
    RtlCopyMemory(pDest, pOwnerSid, ulOwnerSidSize);
    pNewSd->Owner = (ULONG_PTR)pDest - (ULONG_PTR)pNewSd;
    pDest = pDest + ROUND_UP(ulOwnerSidSize, sizeof(ULONG));

    /* Copy the Group SID */
    RtlCopyMemory(pDest, pGroupSid, ulGroupSidSize);
    pNewSd->Group = (ULONG_PTR)pDest - (ULONG_PTR)pNewSd;

    /* Free the old security descriptor */
    RtlFreeHeap(RtlGetProcessHeap(), 0, (PVOID)*ObjectsSecurityDescriptor);

    /* Return the new security descriptor */
    *ObjectsSecurityDescriptor = (PSECURITY_DESCRIPTOR)pNewSd;

done:
    if (!NT_SUCCESS(Status))
    {
        if (pNewSd != NULL)
            RtlFreeHeap(RtlGetProcessHeap(), 0, pNewSd);
    }

    return Status;
}

/*
 * Inheritance and selection of ACLs for new security objects. This is the user mode
 * counterpart of SepShouldPropagateAce/SepPropagateAcl/SepSelectAcl in ntoskrnl/se.
 */
static
BOOLEAN
RtlpShouldPropagateAce(
    IN UCHAR AceFlags,
    OUT PUCHAR NewAceFlags,
    IN BOOLEAN IsInherited,
    IN BOOLEAN IsDirectoryObject)
{
    if (!IsInherited)
    {
        *NewAceFlags = AceFlags;
        return TRUE;
    }

    if (!IsDirectoryObject)
    {
        if (AceFlags & OBJECT_INHERIT_ACE)
        {
            *NewAceFlags = AceFlags & ~VALID_INHERIT_FLAGS;
            return TRUE;
        }
        return FALSE;
    }

    if (AceFlags & NO_PROPAGATE_INHERIT_ACE)
    {
        if (AceFlags & CONTAINER_INHERIT_ACE)
        {
            *NewAceFlags = AceFlags & ~VALID_INHERIT_FLAGS;
            return TRUE;
        }
        return FALSE;
    }

    if (AceFlags & CONTAINER_INHERIT_ACE)
    {
        *NewAceFlags = CONTAINER_INHERIT_ACE | (AceFlags & OBJECT_INHERIT_ACE) | (AceFlags & ~VALID_INHERIT_FLAGS);
        return TRUE;
    }

    if (AceFlags & OBJECT_INHERIT_ACE)
    {
        *NewAceFlags = INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE | (AceFlags & ~VALID_INHERIT_FLAGS);
        return TRUE;
    }

    return FALSE;
}

/* Whether every ACE of the ACL is in bounds and keeps the next one ULONG aligned */
static
BOOLEAN
RtlpAclIsSane(
    IN PACL Acl)
{
    PUCHAR End = (PUCHAR)Acl + Acl->AclSize;
    PACE_HEADER Ace = (PACE_HEADER)(Acl + 1);
    ULONG i;

    if (!RtlValidAcl(Acl))
        return FALSE;

    for (i = 0; i < Acl->AceCount; i++)
    {
        if ((PUCHAR)(Ace + 1) > End ||
            Ace->AceSize < sizeof(ACE_HEADER) ||
            (Ace->AceSize % sizeof(ULONG)) != 0 ||
            (PUCHAR)Ace + Ace->AceSize > End)
            return FALSE;

        /* The simple ACE types are interpreted below, so they must hold a whole SID */
        if (Ace->AceType <= ACCESS_MAX_MS_V2_ACE_TYPE)
        {
            PACCESS_ALLOWED_ACE Simple = (PACCESS_ALLOWED_ACE)Ace;
            PISID Sid = (PISID)&Simple->SidStart;

            if (Ace->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 8 ||
                Ace->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthRequiredSid(Sid->SubAuthorityCount) ||
                !RtlValidSid(Sid))
                return FALSE;
        }
        Ace = (PACE_HEADER)((PUCHAR)Ace + Ace->AceSize);
    }
    return TRUE;
}

/*
 * Copies ExplicitAcl, then the inheritable ACEs of ParentAcl, into AclDest. With a too small
 * *AclLength nothing beyond the sizes is written, and *AclLength returns the required size.
 */
static
NTSTATUS
RtlpPropagateAcl(
    OUT PACL AclDest OPTIONAL,
    IN OUT PULONG AclLength,
    IN PACL ExplicitAcl OPTIONAL,
    IN PACL ParentAcl OPTIONAL,
    IN PSID Owner,
    IN PSID Group,
    IN BOOLEAN AutoInherit,
    IN BOOLEAN IsDirectoryObject,
    IN PGENERIC_MAPPING GenericMapping)
{
    static const SID_IDENTIFIER_AUTHORITY CreatorAuthority = {SECURITY_CREATOR_SID_AUTHORITY};
    UCHAR CreatorOwnerBuffer[SECURITY_MAX_SID_SIZE], CreatorGroupBuffer[SECURITY_MAX_SID_SIZE];
    PSID CreatorOwnerSid = (PSID)CreatorOwnerBuffer, CreatorGroupSid = (PSID)CreatorGroupBuffer;
    PACL AclSource = ExplicitAcl ? ExplicitAcl : ParentAcl;
    BOOLEAN IsInherited = FALSE;
    ULONG ExplicitCount = ExplicitAcl ? ExplicitAcl->AceCount : 0;
    ULONG TotalCount = ExplicitCount + (ParentAcl ? ParentAcl->AceCount : 0);
    UCHAR InheritedFlag;
    ACCESS_MASK Mask;
    PACCESS_ALLOWED_ACE AceSource;
    PACCESS_ALLOWED_ACE AceDest;
    PUCHAR CurrentDest;
    PUCHAR CurrentSource;
    ULONG i;
    ULONG Written;
    UCHAR AceFlags;
    USHORT AceSize;
    USHORT AceCount = 0;
    PSID Sid;
    BOOLEAN WriteTwoAces;

    RtlInitializeSid(CreatorOwnerSid, (PSID_IDENTIFIER_AUTHORITY)&CreatorAuthority, 1);
    *RtlSubAuthoritySid(CreatorOwnerSid, 0) = SECURITY_CREATOR_OWNER_RID;
    RtlInitializeSid(CreatorGroupSid, (PSID_IDENTIFIER_AUTHORITY)&CreatorAuthority, 1);
    *RtlSubAuthoritySid(CreatorGroupSid, 0) = SECURITY_CREATOR_GROUP_RID;

    Written = 0;
    if (*AclLength >= Written + sizeof(ACL))
    {
        RtlCopyMemory(AclDest, AclSource, sizeof(ACL));
        AclDest->Sbz1 = 0;
        AclDest->Sbz2 = 0;
        if (ExplicitAcl && ParentAcl)
            AclDest->AclRevision = max(ExplicitAcl->AclRevision, ParentAcl->AclRevision);
    }
    Written += sizeof(ACL);

    CurrentDest = AclDest ? (PUCHAR)(AclDest + 1) : NULL;
    CurrentSource = (PUCHAR)(AclSource + 1);
    for (i = 0; i < TotalCount; i++)
    {
        if (i == ExplicitCount)
        {
            /* The inherited ACEs follow the explicit ones */
            CurrentSource = (PUCHAR)(ParentAcl + 1);
            IsInherited = TRUE;
        }

        AceDest = (PACCESS_ALLOWED_ACE)CurrentDest;
        AceSource = (PACCESS_ALLOWED_ACE)CurrentSource;

        if ((AutoInherit && !IsInherited && (AceSource->Header.AceFlags & INHERITED_ACE)) ||
            !RtlpShouldPropagateAce(AceSource->Header.AceFlags,
                                    &AceFlags,
                                    IsInherited,
                                    IsDirectoryObject))
        {
            CurrentSource += AceSource->Header.AceSize;
            continue;
        }
        InheritedFlag = (AutoInherit && IsInherited) ? INHERITED_ACE : 0;

        if (AceSource->Header.AceType > ACCESS_MAX_MS_V2_ACE_TYPE)
        {
            /* Object and compound ACEs are copied as they are */
            AceSize = AceSource->Header.AceSize;

            if (*AclLength >= Written + AceSize)
            {
                RtlCopyMemory(AceDest, AceSource, AceSize);
                AceDest->Header.AceFlags = AceFlags | InheritedFlag;
            }
            if (CurrentDest)
                CurrentDest += AceSize;
            CurrentSource += AceSize;
            Written += AceSize;
            AceCount++;
            continue;
        }

        /* Allowed, denied, audit and alarm ACEs have the same structure */
        AceSize = AceSource->Header.AceSize;
        Mask = AceSource->Mask;
        Sid = (PSID)&AceSource->SidStart;

        WriteTwoAces = FALSE;
        /* Map effective ACE to specific rights */
        if (!(AceFlags & INHERIT_ONLY_ACE))
        {
            RtlMapGenericMask(&Mask, GenericMapping);
            Mask &= GenericMapping->GenericAll;

            if (IsInherited)
            {
                if (RtlEqualSid(Sid, CreatorOwnerSid))
                    Sid = Owner;
                else if (RtlEqualSid(Sid, CreatorGroupSid))
                    Sid = Group;
                AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid);

                /*
                 * A generic container ACE becomes two ACEs: a specific effective
                 * ACE with no inheritance flags, and an inherit-only ACE that keeps
                 * the generic rights.
                 */
                if (IsDirectoryObject &&
                    (AceFlags & CONTAINER_INHERIT_ACE) &&
                    (Mask != AceSource->Mask || Sid != (PSID)&AceSource->SidStart))
                {
                    WriteTwoAces = TRUE;
                }
            }
        }

        while (1)
        {
            if (*AclLength >= Written + AceSize)
            {
                AceDest->Header.AceType = AceSource->Header.AceType;
                AceDest->Header.AceFlags = (WriteTwoAces ? AceFlags & ~VALID_INHERIT_FLAGS
                                                         : AceFlags) | InheritedFlag;
                AceDest->Header.AceSize = AceSize;
                AceDest->Mask = Mask;
                RtlCopySid(AceSize - FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart),
                           (PSID)&AceDest->SidStart,
                           Sid);
            }
            Written += AceSize;

            AceCount++;
            if (CurrentDest)
                CurrentDest += AceSize;

            if (!WriteTwoAces)
                break;

            /* The second ACE keeps all the generics of the source ACE */
            WriteTwoAces = FALSE;
            AceDest = (PACCESS_ALLOWED_ACE)CurrentDest;
            AceSize = AceSource->Header.AceSize;
            Mask = AceSource->Mask;
            Sid = (PSID)&AceSource->SidStart;
            AceFlags |= INHERIT_ONLY_ACE;
        }

        CurrentSource += AceSource->Header.AceSize;
    }

    if (*AclLength >= sizeof(ACL))
    {
        AclDest->AceCount = AceCount;
        AclDest->AclSize = (USHORT)Written;
    }

    if (Written > *AclLength)
    {
        *AclLength = Written;
        return STATUS_BUFFER_TOO_SMALL;
    }
    *AclLength = Written;
    return STATUS_SUCCESS;
}

static
PACL
RtlpSelectAcl(
    IN PACL ExplicitAcl OPTIONAL,
    IN BOOLEAN ExplicitPresent,
    IN BOOLEAN ExplicitDefaulted,
    IN PACL ParentAcl OPTIONAL,
    IN PACL DefaultAcl OPTIONAL,
    OUT PULONG AclLength,
    IN PSID Owner,
    IN PSID Group,
    OUT PBOOLEAN AclPresent,
    OUT PACL *InheritedAcl,
    IN BOOLEAN ExplicitProtected,
    IN BOOLEAN AutoInherit,
    IN BOOLEAN IsDirectoryObject,
    IN PGENERIC_MAPPING GenericMapping)
{
    PACL Acl;

    *AclPresent = TRUE;
    *InheritedAcl = NULL;
    if (ExplicitPresent && !ExplicitDefaulted)
    {
        Acl = ExplicitAcl;

        /* Auto-inheritance appends the inheritable ACEs of the parent */
        if (Acl && AutoInherit && !ExplicitProtected)
            *InheritedAcl = ParentAcl;
    }
    else
    {
        if (ParentAcl)
        {
            *AclLength = 0;
            RtlpPropagateAcl(NULL, AclLength, NULL, ParentAcl, Owner, Group,
                             AutoInherit, IsDirectoryObject, GenericMapping);

            /* Use the parent ACL only if anything is inherited from it */
            if (*AclLength != sizeof(ACL))
            {
                *InheritedAcl = ParentAcl;
                return NULL;
            }
        }

        if (ExplicitPresent)
        {
            Acl = ExplicitAcl;
        }
        else if (DefaultAcl)
        {
            Acl = DefaultAcl;
        }
        else
        {
            *AclPresent = FALSE;
            Acl = NULL;
        }
    }

    *AclLength = 0;
    if (Acl)
    {
        RtlpPropagateAcl(NULL, AclLength, Acl, *InheritedAcl, Owner, Group,
                         AutoInherit, IsDirectoryObject, GenericMapping);
    }
    return Acl;
}

/* Reads a token information class into a heap buffer, which the caller frees */
static
NTSTATUS
RtlpQueryTokenInfo(
    IN HANDLE Token,
    IN TOKEN_INFORMATION_CLASS Class,
    OUT PVOID *Buffer)
{
    ULONG Length = 0;
    NTSTATUS Status;

    *Buffer = NULL;
    Status = NtQueryInformationToken(Token, Class, NULL, 0, &Length);
    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW &&
        Status != STATUS_INFO_LENGTH_MISMATCH)
        return NT_SUCCESS(Status) ? STATUS_UNSUCCESSFUL : Status;

    *Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (*Buffer == NULL)
        return STATUS_NO_MEMORY;

    Status = NtQueryInformationToken(Token, Class, *Buffer, Length, &Length);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, *Buffer);
        *Buffer = NULL;
    }
    return Status;
}

NTSTATUS
NTAPI
RtlpNewSecurityObject(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                      IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                      OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                      IN LPGUID *ObjectTypes,
                      IN ULONG GuidCount,
                      IN BOOLEAN IsDirectoryObject,
                      IN ULONG AutoInheritFlags,
                      IN HANDLE Token,
                      IN PGENERIC_MAPPING GenericMapping)
{
    PSID Owner = NULL, Group = NULL;
    PTOKEN_OWNER OwnerInfo = NULL;
    PTOKEN_PRIMARY_GROUP GroupInfo = NULL;
    PTOKEN_DEFAULT_DACL DaclInfo = NULL;
    HANDLE LocalToken = NULL;
    PACL ExplicitAcl, ParentAcl, Dacl = NULL, Sacl = NULL, DaclInherited, SaclInherited;
    BOOLEAN ExplicitPresent, ExplicitDefaulted, ExplicitProtected;
    BOOLEAN DaclPresent, SaclPresent, Present, Defaulted;
    BOOLEAN DaclAutoInherit = (AutoInheritFlags & SEF_DACL_AUTO_INHERIT) != 0;
    BOOLEAN SaclAutoInherit = (AutoInheritFlags & SEF_SACL_AUTO_INHERIT) != 0;
    SECURITY_DESCRIPTOR_CONTROL Control = 0, ExplicitControl, ParentControl;
    ULONG Revision, OwnerLength, GroupLength, DaclLength = 0, SaclLength = 0, Length, Current;
    PISECURITY_DESCRIPTOR_RELATIVE Descriptor;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(ObjectTypes);
    UNREFERENCED_PARAMETER(GuidCount);

    if (NewDescriptor == NULL || GenericMapping == NULL)
        return STATUS_INVALID_PARAMETER;
    *NewDescriptor = NULL;

    if ((ParentDescriptor && !RtlValidSecurityDescriptor(ParentDescriptor)) ||
        (CreatorDescriptor && !RtlValidSecurityDescriptor(CreatorDescriptor)))
        return STATUS_INVALID_SECURITY_DESCR;

    /* Without a token the effective one of the thread (or else of the process) is used */
    if (Token == NULL)
    {
        Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &LocalToken);
        if (!NT_SUCCESS(Status))
            Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &LocalToken);
        if (!NT_SUCCESS(Status))
            return Status;
        Token = LocalToken;
    }

    /* Owner and group: explicit, else from the parent if asked for, else the token's */
    if (CreatorDescriptor != NULL)
    {
        RtlGetOwnerSecurityDescriptor(CreatorDescriptor, &Owner, &Defaulted);
        RtlGetGroupSecurityDescriptor(CreatorDescriptor, &Group, &Defaulted);
    }

    if (Owner == NULL)
    {
        if (AutoInheritFlags & SEF_DEFAULT_OWNER_FROM_PARENT)
        {
            if (ParentDescriptor != NULL)
                RtlGetOwnerSecurityDescriptor(ParentDescriptor, &Owner, &Defaulted);
            if (Owner == NULL)
            {
                Status = STATUS_INVALID_OWNER;
                goto done;
            }
        }
        else
        {
            Status = RtlpQueryTokenInfo(Token, TokenOwner, (PVOID *)&OwnerInfo);
            if (!NT_SUCCESS(Status))
                goto done;
            Owner = OwnerInfo->Owner;
        }
    }

    if (Group == NULL)
    {
        if (AutoInheritFlags & SEF_DEFAULT_GROUP_FROM_PARENT)
        {
            if (ParentDescriptor != NULL)
                RtlGetGroupSecurityDescriptor(ParentDescriptor, &Group, &Defaulted);
            if (Group == NULL)
            {
                Status = STATUS_INVALID_PRIMARY_GROUP;
                goto done;
            }
        }
        else
        {
            Status = RtlpQueryTokenInfo(Token, TokenPrimaryGroup, (PVOID *)&GroupInfo);
            if (!NT_SUCCESS(Status))
                goto done;
            Group = GroupInfo->PrimaryGroup;
        }
    }

    if (Owner == NULL || !RtlValidSid(Owner))
    {
        Status = STATUS_INVALID_OWNER;
        goto done;
    }
    if (Group == NULL || !RtlValidSid(Group))
    {
        Status = STATUS_INVALID_PRIMARY_GROUP;
        goto done;
    }
    OwnerLength = ROUND_UP(RtlLengthSid(Owner), sizeof(ULONG));
    GroupLength = ROUND_UP(RtlLengthSid(Group), sizeof(ULONG));

    ExplicitControl = 0;
    ParentControl = 0;
    if (CreatorDescriptor != NULL)
        RtlGetControlSecurityDescriptor(CreatorDescriptor, &ExplicitControl, &Revision);
    if (ParentDescriptor != NULL)
        RtlGetControlSecurityDescriptor(ParentDescriptor, &ParentControl, &Revision);

    /* The DACL */
    ExplicitAcl = NULL;
    ExplicitPresent = FALSE;
    ExplicitDefaulted = FALSE;
    ExplicitProtected = FALSE;
    if (CreatorDescriptor != NULL && (ExplicitControl & SE_DACL_PRESENT))
    {
        RtlGetDaclSecurityDescriptor(CreatorDescriptor, &Present, &ExplicitAcl, &Defaulted);
        ExplicitPresent = TRUE;
        if (ExplicitControl & SE_DACL_DEFAULTED)
            ExplicitDefaulted = TRUE;
        else if (ExplicitControl & SE_DACL_PROTECTED)
            ExplicitProtected = TRUE;
    }
    ParentAcl = NULL;
    if (ParentDescriptor != NULL && (ParentControl & SE_DACL_PRESENT))
        RtlGetDaclSecurityDescriptor(ParentDescriptor, &Present, &ParentAcl, &Defaulted);

    Status = RtlpQueryTokenInfo(Token, TokenDefaultDacl, (PVOID *)&DaclInfo);
    if (!NT_SUCCESS(Status))
        goto done;

    if ((ExplicitAcl && !RtlpAclIsSane(ExplicitAcl)) ||
        (ParentAcl && !RtlpAclIsSane(ParentAcl)) ||
        (DaclInfo->DefaultDacl && !RtlpAclIsSane(DaclInfo->DefaultDacl)))
    {
        Status = STATUS_INVALID_ACL;
        goto done;
    }

    Dacl = RtlpSelectAcl(ExplicitAcl, ExplicitPresent, ExplicitDefaulted, ParentAcl,
                         DaclInfo->DefaultDacl, &DaclLength, Owner, Group, &DaclPresent,
                         &DaclInherited, ExplicitProtected, DaclAutoInherit,
                         IsDirectoryObject, GenericMapping);
    if (DaclPresent)
        Control |= SE_DACL_PRESENT;
    if (ExplicitProtected)
        Control |= SE_DACL_PROTECTED;
    if (DaclAutoInherit)
        Control |= SE_DACL_AUTO_INHERITED;

    /* The SACL */
    ExplicitAcl = NULL;
    ExplicitPresent = FALSE;
    ExplicitDefaulted = FALSE;
    ExplicitProtected = FALSE;
    if (CreatorDescriptor != NULL && (ExplicitControl & SE_SACL_PRESENT))
    {
        RtlGetSaclSecurityDescriptor(CreatorDescriptor, &Present, &ExplicitAcl, &Defaulted);
        ExplicitPresent = TRUE;
        if (ExplicitControl & SE_SACL_DEFAULTED)
            ExplicitDefaulted = TRUE;
        else if (ExplicitControl & SE_SACL_PROTECTED)
            ExplicitProtected = TRUE;
    }
    ParentAcl = NULL;
    if (ParentDescriptor != NULL && (ParentControl & SE_SACL_PRESENT))
        RtlGetSaclSecurityDescriptor(ParentDescriptor, &Present, &ParentAcl, &Defaulted);

    if ((ExplicitAcl && !RtlpAclIsSane(ExplicitAcl)) ||
        (ParentAcl && !RtlpAclIsSane(ParentAcl)))
    {
        Status = STATUS_INVALID_ACL;
        goto done;
    }

    Sacl = RtlpSelectAcl(ExplicitAcl, ExplicitPresent, ExplicitDefaulted, ParentAcl,
                         NULL, &SaclLength, Owner, Group, &SaclPresent,
                         &SaclInherited, ExplicitProtected, SaclAutoInherit,
                         IsDirectoryObject, GenericMapping);
    if (SaclPresent)
        Control |= SE_SACL_PRESENT;
    if (ExplicitProtected)
        Control |= SE_SACL_PROTECTED;
    if (SaclAutoInherit)
        Control |= SE_SACL_AUTO_INHERITED;

    /* A merged ACL can exceed what AclSize can describe */
    if (DaclLength > MAXUSHORT || SaclLength > MAXUSHORT)
    {
        Status = STATUS_BAD_INHERITANCE_ACL;
        goto done;
    }

    Length = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + OwnerLength + GroupLength + DaclLength + SaclLength;
    Descriptor = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (Descriptor == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto done;
    }

    RtlCreateSecurityDescriptorRelative(Descriptor, SECURITY_DESCRIPTOR_REVISION);
    Descriptor->Control = Control | SE_SELF_RELATIVE;
    Current = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (SaclLength != 0)
    {
        Status = RtlpPropagateAcl((PACL)((PUCHAR)Descriptor + Current), &SaclLength, Sacl,
                                  SaclInherited, Owner, Group, SaclAutoInherit,
                                  IsDirectoryObject, GenericMapping);
        if (!NT_SUCCESS(Status))
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, Descriptor);
            goto done;
        }
        Descriptor->Sacl = Current;
        Current += SaclLength;
    }

    if (DaclLength != 0)
    {
        Status = RtlpPropagateAcl((PACL)((PUCHAR)Descriptor + Current), &DaclLength, Dacl,
                                  DaclInherited, Owner, Group, DaclAutoInherit,
                                  IsDirectoryObject, GenericMapping);
        if (!NT_SUCCESS(Status))
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, Descriptor);
            goto done;
        }
        Descriptor->Dacl = Current;
        Current += DaclLength;
    }

    RtlCopyMemory((PUCHAR)Descriptor + Current, Owner, RtlLengthSid(Owner));
    Descriptor->Owner = Current;
    Current += OwnerLength;

    RtlCopyMemory((PUCHAR)Descriptor + Current, Group, RtlLengthSid(Group));
    Descriptor->Group = Current;

    *NewDescriptor = Descriptor;
    Status = STATUS_SUCCESS;

done:
    if (OwnerInfo) RtlFreeHeap(RtlGetProcessHeap(), 0, OwnerInfo);
    if (GroupInfo) RtlFreeHeap(RtlGetProcessHeap(), 0, GroupInfo);
    if (DaclInfo) RtlFreeHeap(RtlGetProcessHeap(), 0, DaclInfo);
    if (LocalToken) NtClose(LocalToken);
    return Status;
}

NTSTATUS
NTAPI
RtlpConvertToAutoInheritSecurityObject(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                                       IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                                       OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                                       IN LPGUID ObjectType,
                                       IN BOOLEAN IsDirectoryObject,
                                       IN PGENERIC_MAPPING GenericMapping)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlDefaultNpAcl(OUT PACL *pAcl)
{
    NTSTATUS Status;
    HANDLE TokenHandle;
    PTOKEN_OWNER OwnerSid;
    ULONG ReturnLength = 0;
    ULONG AclSize;
    SID_IDENTIFIER_AUTHORITY NtAuthority    = {SECURITY_NT_AUTHORITY};
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};

    C_ASSERT(sizeof(ACE) == FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart));

    /*
     * Temporary buffer large enough to hold a maximum of two SIDs.
     * An alternative is to call RtlAllocateAndInitializeSid many times...
     */
    UCHAR SidBuffer[FIELD_OFFSET(SID, SubAuthority)
                    + 2*RTL_FIELD_SIZE(SID, SubAuthority)];
    PSID Sid = (PSID)&SidBuffer;

    ASSERT(RtlLengthRequiredSid(2) == sizeof(SidBuffer));

    /* Initialize the user ACL pointer */
    *pAcl = NULL;

    /*
     * Try to retrieve the SID of the current owner. For that,
     * we first attempt to get the current thread level token.
     */
    Status = NtOpenThreadToken(NtCurrentThread(),
                               TOKEN_QUERY,
                               TRUE,
                               &TokenHandle);
    if (Status == STATUS_NO_TOKEN)
    {
        /*
         * No thread level token, so use the process level token.
         * This is the common case since the only time a thread
         * has a token is when it is impersonating.
         */
        Status = NtOpenProcessToken(NtCurrentProcess(),
                                    TOKEN_QUERY,
                                    &TokenHandle);
    }
    /* Fail if we didn't succeed in retrieving a handle to the token */
    if (!NT_SUCCESS(Status)) return Status;

    /*
     * Retrieve the owner SID from the token.
     */

    /* Query the needed size... */
    Status = NtQueryInformationToken(TokenHandle,
                                     TokenOwner,
                                     NULL, 0,
                                     &ReturnLength);
    /* ... so that we must fail with STATUS_BUFFER_TOO_SMALL error */
    if (Status != STATUS_BUFFER_TOO_SMALL) goto Cleanup1;

    /* Allocate space for the owner SID */
    OwnerSid = RtlAllocateHeap(RtlGetProcessHeap(), 0, ReturnLength);
    if (OwnerSid == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto Cleanup1;
    }

    /* Retrieve the owner SID; we must succeed */
    Status = NtQueryInformationToken(TokenHandle,
                                     TokenOwner,
                                     OwnerSid,
                                     ReturnLength,
                                     &ReturnLength);
    if (!NT_SUCCESS(Status)) goto Cleanup2;

    /*
     * Allocate one ACL with 5 ACEs.
     */
    AclSize = sizeof(ACL) +                     // Header
              5 * sizeof(ACE) +                 // 5 ACEs:
              RtlLengthRequiredSid(1) +         // LocalSystem
              RtlLengthRequiredSid(2) +         // Administrators
              RtlLengthRequiredSid(1) +         // Anonymous
              RtlLengthRequiredSid(1) +         // World
              RtlLengthSid(OwnerSid->Owner);    // Owner

    *pAcl = RtlAllocateHeap(RtlGetProcessHeap(), 0, AclSize);
    if (*pAcl == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto Cleanup2;
    }

    /*
     * Build the ACL and add the five ACEs.
     */
    Status = RtlCreateAcl(*pAcl, AclSize, ACL_REVISION2);
    ASSERT(NT_SUCCESS(Status));

    /* Local System SID - Generic All */
    Status = RtlInitializeSid(Sid, &NtAuthority, 1);
    ASSERT(NT_SUCCESS(Status));
    *RtlSubAuthoritySid(Sid, 0) = SECURITY_LOCAL_SYSTEM_RID;
    Status = RtlAddAccessAllowedAce(*pAcl, ACL_REVISION2, GENERIC_ALL, Sid);
    ASSERT(NT_SUCCESS(Status));

    /* Administrators SID - Generic All */
    Status = RtlInitializeSid(Sid, &NtAuthority, 2);
    ASSERT(NT_SUCCESS(Status));
    *RtlSubAuthoritySid(Sid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(Sid, 1) = DOMAIN_ALIAS_RID_ADMINS;
    Status = RtlAddAccessAllowedAce(*pAcl, ACL_REVISION2, GENERIC_ALL, Sid);
    ASSERT(NT_SUCCESS(Status));

    /* Owner SID - Generic All */
    RtlAddAccessAllowedAce(*pAcl, ACL_REVISION2, GENERIC_ALL, OwnerSid->Owner);
    ASSERT(NT_SUCCESS(Status));

    /* Anonymous SID - Generic Read */
    Status = RtlInitializeSid(Sid, &NtAuthority, 1);
    ASSERT(NT_SUCCESS(Status));
    *RtlSubAuthoritySid(Sid, 0) = SECURITY_ANONYMOUS_LOGON_RID;
    Status = RtlAddAccessAllowedAce(*pAcl, ACL_REVISION2, GENERIC_READ, Sid);
    ASSERT(NT_SUCCESS(Status));

    /* World SID - Generic Read */
    Status = RtlInitializeSid(Sid, &WorldAuthority, 1);
    ASSERT(NT_SUCCESS(Status));
    *RtlSubAuthoritySid(Sid, 0) = SECURITY_WORLD_RID;
    Status = RtlAddAccessAllowedAce(*pAcl, ACL_REVISION2, GENERIC_READ, Sid);
    ASSERT(NT_SUCCESS(Status));

    /* If some problem happened, cleanup everything */
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, *pAcl);
        *pAcl = NULL;
    }

Cleanup2:
    /* Get rid of the owner SID */
    RtlFreeHeap(RtlGetProcessHeap(), 0, OwnerSid);

Cleanup1:
    /* Close the token handle */
    NtClose(TokenHandle);

    /* Done */
    return Status;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
RtlCreateAndSetSD(IN PRTL_ACE_DATA AceData,
                  IN ULONG AceCount,
                  IN PSID OwnerSid OPTIONAL,
                  IN PSID GroupSid OPTIONAL,
                  OUT PSECURITY_DESCRIPTOR *NewDescriptor)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlDeleteSecurityObject(IN PSECURITY_DESCRIPTOR *ObjectDescriptor)
{
    DPRINT1("RtlDeleteSecurityObject(%p)\n", ObjectDescriptor);

    /* Free the object from the heap */
    RtlFreeHeap(RtlGetProcessHeap(), 0, *ObjectDescriptor);
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlNewSecurityObject(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                     IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                     OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                     IN BOOLEAN IsDirectoryObject,
                     IN HANDLE Token,
                     IN PGENERIC_MAPPING GenericMapping)
{
    DPRINT1("RtlNewSecurityObject(%p)\n", ParentDescriptor);

    /* Call the internal API */
    return RtlpNewSecurityObject(ParentDescriptor,
                                 CreatorDescriptor,
                                 NewDescriptor,
                                 NULL,
                                 0,
                                 IsDirectoryObject,
                                 0,
                                 Token,
                                 GenericMapping);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlNewSecurityObjectEx(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                       IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                       OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                       IN LPGUID ObjectType,
                       IN BOOLEAN IsDirectoryObject,
                       IN ULONG AutoInheritFlags,
                       IN HANDLE Token,
                       IN PGENERIC_MAPPING GenericMapping)
{
    DPRINT("RtlNewSecurityObjectEx(%p)\n", ParentDescriptor);

    /* Call the internal API */
    return RtlpNewSecurityObject(ParentDescriptor,
                                 CreatorDescriptor,
                                 NewDescriptor,
                                 ObjectType ? &ObjectType : NULL,
                                 ObjectType ? 1 : 0,
                                 IsDirectoryObject,
                                 AutoInheritFlags,
                                 Token,
                                 GenericMapping);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlNewSecurityObjectWithMultipleInheritance(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                                            IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                                            OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                                            IN LPGUID *ObjectTypes,
                                            IN ULONG GuidCount,
                                            IN BOOLEAN IsDirectoryObject,
                                            IN ULONG AutoInheritFlags,
                                            IN HANDLE Token,
                                            IN PGENERIC_MAPPING GenericMapping)
{
    DPRINT1("RtlNewSecurityObjectWithMultipleInheritance(%p)\n", ParentDescriptor);

    /* Call the internal API */
    return RtlpNewSecurityObject(ParentDescriptor,
                                 CreatorDescriptor,
                                 NewDescriptor,
                                 ObjectTypes,
                                 GuidCount,
                                 IsDirectoryObject,
                                 AutoInheritFlags,
                                 Token,
                                 GenericMapping);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlNewInstanceSecurityObject(IN BOOLEAN ParentDescriptorChanged,
                             IN BOOLEAN CreatorDescriptorChanged,
                             IN PLUID OldClientTokenModifiedId,
                             OUT PLUID NewClientTokenModifiedId,
                             IN PSECURITY_DESCRIPTOR ParentDescriptor,
                             IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                             OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                             IN BOOLEAN IsDirectoryObject,
                             IN HANDLE Token,
                             IN PGENERIC_MAPPING GenericMapping)
{
    TOKEN_STATISTICS TokenStats;
    ULONG Size;
    NTSTATUS Status;
    DPRINT1("RtlNewInstanceSecurityObject(%p)\n", ParentDescriptor);

    /* Query the token statistics */
    Status = NtQueryInformationToken(Token,
                                     TokenStatistics,
                                     &TokenStats,
                                     sizeof(TokenStats),
                                     &Size);
    if (!NT_SUCCESS(Status)) return Status;

    /* Return the LUID */
    *NewClientTokenModifiedId = TokenStats.ModifiedId;

    /* Check if the LUID changed */
    if (RtlEqualLuid(NewClientTokenModifiedId, OldClientTokenModifiedId))
    {
        /* Did nothing change? */
        if (!(ParentDescriptorChanged) && !(CreatorDescriptorChanged))
        {
            /* There's no new descriptor, we're done */
            *NewDescriptor = NULL;
            return STATUS_SUCCESS;
        }
    }

    /* Call the standard API */
    return RtlNewSecurityObject(ParentDescriptor,
                                CreatorDescriptor,
                                NewDescriptor,
                                IsDirectoryObject,
                                Token,
                                GenericMapping);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlCreateUserSecurityObject(IN PRTL_ACE_DATA AceData,
                            IN ULONG AceCount,
                            IN PSID OwnerSid,
                            IN PSID GroupSid,
                            IN BOOLEAN IsDirectoryObject,
                            IN PGENERIC_MAPPING GenericMapping,
                            OUT PSECURITY_DESCRIPTOR *NewDescriptor)
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR Sd;
    HANDLE TokenHandle;
    DPRINT1("RtlCreateUserSecurityObject(%p)\n", AceData);

    /* Create the security descriptor based on the ACE Data */
    Status = RtlCreateAndSetSD(AceData,
                               AceCount,
                               OwnerSid,
                               GroupSid,
                               &Sd);
    if (!NT_SUCCESS(Status)) return Status;

    /* Open the process token */
    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &TokenHandle);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Create the security object */
    Status = RtlNewSecurityObject(NULL,
                                  Sd,
                                  NewDescriptor,
                                  IsDirectoryObject,
                                  TokenHandle,
                                  GenericMapping);

    /* We're done, close the token handle */
    NtClose(TokenHandle);

Quickie:
    /* Free the SD and return status */
    RtlFreeHeap(RtlGetProcessHeap(), 0, Sd);
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlNewSecurityGrantedAccess(IN ACCESS_MASK DesiredAccess,
                            OUT PPRIVILEGE_SET Privileges,
                            IN OUT PULONG Length,
                            IN HANDLE Token,
                            IN PGENERIC_MAPPING GenericMapping,
                            OUT PACCESS_MASK RemainingDesiredAccess)
{
    NTSTATUS Status;
    BOOLEAN Granted, CallerToken;
    TOKEN_STATISTICS TokenStats;
    ULONG Size;
    DPRINT1("RtlNewSecurityGrantedAccess(%lx)\n", DesiredAccess);

    /* Has the caller passed a token? */
    if (!Token)
    {
        /* Remember that we'll have to close the handle */
        CallerToken = FALSE;

        /* Nope, open it */
        Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &Token);
        if (!NT_SUCCESS(Status)) return Status;
    }
    else
    {
        /* Yep, use it */
        CallerToken = TRUE;
    }

    /* Get information on the token */
    Status = NtQueryInformationToken(Token,
                                     TokenStatistics,
                                     &TokenStats,
                                     sizeof(TokenStats),
                                     &Size);
    ASSERT(NT_SUCCESS(Status));

    /* Windows doesn't do anything with the token statistics! */

    /* Map the access and return it back decoded */
    RtlMapGenericMask(&DesiredAccess, GenericMapping);
    *RemainingDesiredAccess = DesiredAccess;

    /* Check if one of the rights requested was the SACL right */
    if (DesiredAccess & ACCESS_SYSTEM_SECURITY)
    {
        /* Pretend that it's allowed FIXME: Do privilege check */
        DPRINT1("Missing privilege check for SE_SECURITY_PRIVILEGE");
        Granted = TRUE;
        *RemainingDesiredAccess &= ~ACCESS_SYSTEM_SECURITY;
    }
    else
    {
        /* Nothing to grant */
        Granted = FALSE;
    }

    /* If the caller did not pass in a token, close the handle to ours */
    if (!CallerToken) NtClose(Token);

    /* We need space to return only 1 privilege -- already part of the struct */
    Size = sizeof(PRIVILEGE_SET);
    if (Size > *Length)
    {
        /* Tell the caller how much space we need and fail */
        *Length = Size;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Check if the SACL right was granted */
    RtlZeroMemory(Privileges, Size);
    if (Granted)
    {
        /* Yes, return it in the structure */
        Privileges->PrivilegeCount = 1;
        Privileges->Privilege[0].Luid.LowPart = SE_SECURITY_PRIVILEGE;
        Privileges->Privilege[0].Luid.HighPart = 0;
        Privileges->Privilege[0].Attributes = SE_PRIVILEGE_USED_FOR_ACCESS;
    }

    /* All done */
    return STATUS_SUCCESS;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
RtlQuerySecurityObject(IN PSECURITY_DESCRIPTOR ObjectDescriptor,
                       IN SECURITY_INFORMATION SecurityInformation,
                       OUT PSECURITY_DESCRIPTOR ResultantDescriptor,
                       IN ULONG DescriptorLength,
                       OUT PULONG ReturnLength)
{
    NTSTATUS Status;
    SECURITY_DESCRIPTOR desc;
    BOOLEAN defaulted, present;
    PACL pacl;
    PSID psid;

    Status = RtlCreateSecurityDescriptor(&desc, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status)) return Status;

    if (SecurityInformation & OWNER_SECURITY_INFORMATION)
    {
        Status = RtlGetOwnerSecurityDescriptor(ObjectDescriptor, &psid, &defaulted);
        if (!NT_SUCCESS(Status)) return Status;
        Status = RtlSetOwnerSecurityDescriptor(&desc, psid, defaulted);
        if (!NT_SUCCESS(Status)) return Status;
    }

    if (SecurityInformation & GROUP_SECURITY_INFORMATION)
    {
        Status = RtlGetGroupSecurityDescriptor(ObjectDescriptor, &psid, &defaulted);
        if (!NT_SUCCESS(Status)) return Status;
        Status = RtlSetGroupSecurityDescriptor(&desc, psid, defaulted);
        if (!NT_SUCCESS(Status)) return Status;
    }

    if (SecurityInformation & DACL_SECURITY_INFORMATION)
    {
        Status = RtlGetDaclSecurityDescriptor(ObjectDescriptor, &present, &pacl, &defaulted);
        if (!NT_SUCCESS(Status)) return Status;
        Status = RtlSetDaclSecurityDescriptor(&desc, present, pacl, defaulted);
        if (!NT_SUCCESS(Status)) return Status;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION)
    {
        Status = RtlGetSaclSecurityDescriptor(ObjectDescriptor, &present, &pacl, &defaulted);
        if (!NT_SUCCESS(Status)) return Status;
        Status = RtlSetSaclSecurityDescriptor(&desc, present, pacl, defaulted);
        if (!NT_SUCCESS(Status)) return Status;
    }

    *ReturnLength = DescriptorLength;
    Status = RtlAbsoluteToSelfRelativeSD(&desc, ResultantDescriptor, ReturnLength);
    if (NT_SUCCESS(Status))
    {
        /* The length that was needed, not the length of the buffer */
        *ReturnLength = RtlLengthSecurityDescriptor(ResultantDescriptor);
    }
    return Status;
}


/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlSetSecurityObject(IN SECURITY_INFORMATION SecurityInformation,
                     IN PSECURITY_DESCRIPTOR ModificationDescriptor,
                     IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
                     IN PGENERIC_MAPPING GenericMapping,
                     IN HANDLE Token OPTIONAL)
{
    /* Call the internal API */
    return RtlpSetSecurityObject(NULL,
                                 SecurityInformation,
                                 ModificationDescriptor,
                                 ObjectsSecurityDescriptor,
                                 0,
                                 PagedPool,
                                 GenericMapping,
                                 Token);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlSetSecurityObjectEx(IN SECURITY_INFORMATION SecurityInformation,
                       IN PSECURITY_DESCRIPTOR ModificationDescriptor,
                       IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
                       IN ULONG AutoInheritFlags,
                       IN PGENERIC_MAPPING GenericMapping,
                       IN HANDLE Token OPTIONAL)
{
    /* Call the internal API */
    return RtlpSetSecurityObject(NULL,
                                 SecurityInformation,
                                 ModificationDescriptor,
                                 ObjectsSecurityDescriptor,
                                 AutoInheritFlags,
                                 PagedPool,
                                 GenericMapping,
                                 Token);

}

/*
 * @implemented
 */
NTSTATUS
NTAPI
RtlConvertToAutoInheritSecurityObject(IN PSECURITY_DESCRIPTOR ParentDescriptor,
                                      IN PSECURITY_DESCRIPTOR CreatorDescriptor,
                                      OUT PSECURITY_DESCRIPTOR *NewDescriptor,
                                      IN LPGUID ObjectType,
                                      IN BOOLEAN IsDirectoryObject,
                                      IN PGENERIC_MAPPING GenericMapping)
{
    /* Call the internal API */
    return RtlpConvertToAutoInheritSecurityObject(ParentDescriptor,
                                                  CreatorDescriptor,
                                                  NewDescriptor,
                                                  ObjectType,
                                                  IsDirectoryObject,
                                                  GenericMapping);
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
RtlRegisterSecureMemoryCacheCallback(IN PRTL_SECURE_MEMORY_CACHE_CALLBACK Callback)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
RtlFlushSecureMemoryCache(IN PVOID MemoryCache,
                          IN OPTIONAL SIZE_T MemoryLength)
{
    UNIMPLEMENTED;
    return FALSE;
}
