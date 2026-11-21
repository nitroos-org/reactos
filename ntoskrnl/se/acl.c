/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Access control lists (ACLs) implementation
 * COPYRIGHT:   Copyright David Welch <welch@cwcom.net>
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PACL SePublicDefaultDacl = NULL;
PACL SeSystemDefaultDacl = NULL;
PACL SePublicDefaultUnrestrictedDacl = NULL;
PACL SePublicOpenDacl = NULL;
PACL SePublicOpenUnrestrictedDacl = NULL;
PACL SeUnrestrictedDacl = NULL;
PACL SeSystemAnonymousLogonDacl = NULL;

/* FUNCTIONS ******************************************************************/

/**
 * @brief
 * Initializes known discretionary access control lists in the system upon
 * kernel and Executive initialization procedure.
 *
 * @return
 * Returns TRUE if all the DACLs have been successfully initialized,
 * FALSE otherwise.
 */
CODE_SEG("INIT")
BOOLEAN
NTAPI
SepInitDACLs(VOID)
{
    ULONG AclLength;

    /* create PublicDefaultDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeWorldSid)) +
                (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
                (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid));

    SePublicDefaultDacl = ExAllocatePoolWithTag(PagedPool,
                                                AclLength,
                                                TAG_ACL);
    if (SePublicDefaultDacl == NULL)
        return FALSE;

    RtlCreateAcl(SePublicDefaultDacl,
                 AclLength,
                 ACL_REVISION);

    RtlAddAccessAllowedAce(SePublicDefaultDacl,
                           ACL_REVISION,
                           GENERIC_EXECUTE,
                           SeWorldSid);

    RtlAddAccessAllowedAce(SePublicDefaultDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeLocalSystemSid);

    RtlAddAccessAllowedAce(SePublicDefaultDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeAliasAdminsSid);

    /* create PublicDefaultUnrestrictedDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeWorldSid)) +
                (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
                (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid)) +
                (sizeof(ACE) + RtlLengthSid(SeRestrictedCodeSid));

    SePublicDefaultUnrestrictedDacl = ExAllocatePoolWithTag(PagedPool,
                                                            AclLength,
                                                            TAG_ACL);
    if (SePublicDefaultUnrestrictedDacl == NULL)
        return FALSE;

    RtlCreateAcl(SePublicDefaultUnrestrictedDacl,
                 AclLength,
                 ACL_REVISION);

    RtlAddAccessAllowedAce(SePublicDefaultUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_EXECUTE,
                           SeWorldSid);

    RtlAddAccessAllowedAce(SePublicDefaultUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeLocalSystemSid);

    RtlAddAccessAllowedAce(SePublicDefaultUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeAliasAdminsSid);

    RtlAddAccessAllowedAce(SePublicDefaultUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_READ | GENERIC_EXECUTE | READ_CONTROL,
                           SeRestrictedCodeSid);

    /* create PublicOpenDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeWorldSid)) +
                (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
                (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid));

    SePublicOpenDacl = ExAllocatePoolWithTag(PagedPool,
                                             AclLength,
                                             TAG_ACL);
    if (SePublicOpenDacl == NULL)
        return FALSE;

    RtlCreateAcl(SePublicOpenDacl,
                 AclLength,
                 ACL_REVISION);

    RtlAddAccessAllowedAce(SePublicOpenDacl,
                           ACL_REVISION,
                           GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
                           SeWorldSid);

    RtlAddAccessAllowedAce(SePublicOpenDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeLocalSystemSid);

    RtlAddAccessAllowedAce(SePublicOpenDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeAliasAdminsSid);

    /* create PublicOpenUnrestrictedDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeWorldSid)) +
                (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
                (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid)) +
                (sizeof(ACE) + RtlLengthSid(SeRestrictedCodeSid));

    SePublicOpenUnrestrictedDacl = ExAllocatePoolWithTag(PagedPool,
                                                         AclLength,
                                                         TAG_ACL);
    if (SePublicOpenUnrestrictedDacl == NULL)
        return FALSE;

    RtlCreateAcl(SePublicOpenUnrestrictedDacl,
                 AclLength,
                 ACL_REVISION);

    /* Everyone gets read, write and execute but not DELETE, WRITE_DAC, WRITE_OWNER or FILE_DELETE_CHILD:
       (A;;0x1201bf;;;WD) on \Device\NamedPipe, \Device\Null, \Device\Afd, \Device\Mailslot and \Device\KsecDD
       of Windows Server 2022 */
    RtlAddAccessAllowedAce(SePublicOpenUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
                           SeWorldSid);

    RtlAddAccessAllowedAce(SePublicOpenUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeLocalSystemSid);

    RtlAddAccessAllowedAce(SePublicOpenUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeAliasAdminsSid);

    RtlAddAccessAllowedAce(SePublicOpenUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_READ | GENERIC_EXECUTE,
                           SeRestrictedCodeSid);

    /* create SystemDefaultDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
                (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid));

    SeSystemDefaultDacl = ExAllocatePoolWithTag(PagedPool,
                                                AclLength,
                                                TAG_ACL);
    if (SeSystemDefaultDacl == NULL)
        return FALSE;

    RtlCreateAcl(SeSystemDefaultDacl,
                 AclLength,
                 ACL_REVISION);

    RtlAddAccessAllowedAce(SeSystemDefaultDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeLocalSystemSid);

    RtlAddAccessAllowedAce(SeSystemDefaultDacl,
                           ACL_REVISION,
                           GENERIC_READ | GENERIC_EXECUTE | READ_CONTROL,
                           SeAliasAdminsSid);

    /* create UnrestrictedDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeWorldSid)) +
                (sizeof(ACE) + RtlLengthSid(SeRestrictedCodeSid));

    SeUnrestrictedDacl = ExAllocatePoolWithTag(PagedPool,
                                               AclLength,
                                               TAG_ACL);
    if (SeUnrestrictedDacl == NULL)
        return FALSE;

    RtlCreateAcl(SeUnrestrictedDacl,
                 AclLength,
                 ACL_REVISION);

    RtlAddAccessAllowedAce(SeUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeWorldSid);

    RtlAddAccessAllowedAce(SeUnrestrictedDacl,
                           ACL_REVISION,
                           GENERIC_READ | GENERIC_EXECUTE,
                           SeRestrictedCodeSid);

    /* create SystemAnonymousLogonDacl */
    AclLength = sizeof(ACL) +
                (sizeof(ACE) + RtlLengthSid(SeWorldSid)) +
                (sizeof(ACE) + RtlLengthSid(SeAnonymousLogonSid));

    SeSystemAnonymousLogonDacl = ExAllocatePoolWithTag(PagedPool,
                                                       AclLength,
                                                       TAG_ACL);
    if (SeSystemAnonymousLogonDacl == NULL)
        return FALSE;

    RtlCreateAcl(SeSystemAnonymousLogonDacl,
                 AclLength,
                 ACL_REVISION);

    RtlAddAccessAllowedAce(SeSystemAnonymousLogonDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeWorldSid);

    RtlAddAccessAllowedAce(SeSystemAnonymousLogonDacl,
                           ACL_REVISION,
                           GENERIC_ALL,
                           SeAnonymousLogonSid);

    return TRUE;
}

/**
 * @brief
 * Allocates a discretionary access control list based on certain properties
 * of a regular and primary access tokens.
 *
 * @param[in] Token
 * An access token.
 *
 * @param[in] PrimaryToken
 * A primary access token.
 *
 * @param[out] Dacl
 * The returned allocated DACL.
 *
 * @return
 * Returns STATUS_SUCCESS if DACL creation from tokens has completed
 * successfully. STATUS_INSUFFICIENT_RESOURCES is returned if DACL
 * allocation from memory pool fails otherwise.
 */
NTSTATUS
NTAPI
SepCreateImpersonationTokenDacl(
    _In_ PTOKEN Token,
    _In_ PTOKEN PrimaryToken,
    _Out_ PACL* Dacl)
{
    ULONG AclLength;
    PACL TokenDacl;

    PAGED_CODE();

    *Dacl = NULL;

    AclLength = sizeof(ACL) +
        (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid)) +
        (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) +
        (sizeof(ACE) + RtlLengthSid(SeRestrictedCodeSid)) +
        (sizeof(ACE) + RtlLengthSid(Token->UserAndGroups->Sid)) +
        (sizeof(ACE) + RtlLengthSid(PrimaryToken->UserAndGroups->Sid));

    TokenDacl = ExAllocatePoolWithTag(PagedPool, AclLength, TAG_ACL);
    if (TokenDacl == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCreateAcl(TokenDacl, AclLength, ACL_REVISION);
    RtlAddAccessAllowedAce(TokenDacl, ACL_REVISION, GENERIC_ALL,
                           Token->UserAndGroups->Sid);
    RtlAddAccessAllowedAce(TokenDacl, ACL_REVISION, GENERIC_ALL,
                           PrimaryToken->UserAndGroups->Sid);
    RtlAddAccessAllowedAce(TokenDacl, ACL_REVISION, GENERIC_ALL,
                           SeAliasAdminsSid);
    RtlAddAccessAllowedAce(TokenDacl, ACL_REVISION, GENERIC_ALL,
                           SeLocalSystemSid);

    if (Token->RestrictedSids != NULL || PrimaryToken->RestrictedSids != NULL)
    {
        RtlAddAccessAllowedAce(TokenDacl, ACL_REVISION, GENERIC_ALL,
                               SeRestrictedCodeSid);
    }

    *Dacl = TokenDacl;

    return STATUS_SUCCESS;
}

/**
 * @brief
 * Captures an access control list from an already valid input ACL.
 *
 * @param[in] InputAcl
 * A valid ACL.
 *
 * @param[in] AccessMode
 * Processor level access mode. The processor mode determines how
 * the input arguments are probed.
 *
 * @param[in] PoolType
 * Pool type for new captured ACL for creation. The pool type determines
 * in which memory pool the ACL data should reside.
 *
 * @param[in] CaptureIfKernel
 * If set to TRUE and the processor access mode being KernelMode, we are
 * capturing an ACL directly in the kernel. Otherwise we are capturing
 * within a kernel mode driver.
 *
 * @param[out] CapturedAcl
 * The returned and allocated captured ACL.
 *
 * @return
 * Returns STATUS_SUCCESS if the ACL has been successfully captured.
 * STATUS_INSUFFICIENT_RESOURCES is returned otherwise.
 */
NTSTATUS
NTAPI
SepCaptureAcl(
    _In_ PACL InputAcl,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ POOL_TYPE PoolType,
    _In_ BOOLEAN CaptureIfKernel,
    _Out_ PACL *CapturedAcl)
{
    PACL NewAcl;
    ULONG AclSize;

    PAGED_CODE();

    /* If in kernel mode and we do not capture, just
     * return the given ACL and don't validate it. */
    if ((AccessMode == KernelMode) && !CaptureIfKernel)
    {
        *CapturedAcl = InputAcl;
        return STATUS_SUCCESS;
    }

    /* Otherwise, capture and validate the ACL, depending on the access mode */
    if (AccessMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForRead(InputAcl,
                         sizeof(ACL),
                         sizeof(ULONG));
            AclSize = InputAcl->AclSize;
            ProbeForRead(InputAcl,
                         AclSize,
                         sizeof(ULONG));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;

        /* Validate the minimal size an ACL can have */
        if (AclSize < sizeof(ACL))
            return STATUS_INVALID_ACL;

        NewAcl = ExAllocatePoolWithTag(PoolType,
                                       AclSize,
                                       TAG_ACL);
        if (!NewAcl)
            return STATUS_INSUFFICIENT_RESOURCES;

        _SEH2_TRY
        {
            RtlCopyMemory(NewAcl, InputAcl, AclSize);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Free the ACL and return the exception code */
            ExFreePoolWithTag(NewAcl, TAG_ACL);
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        AclSize = InputAcl->AclSize;

        /* Validate the minimal size an ACL can have */
        if (AclSize < sizeof(ACL))
            return STATUS_INVALID_ACL;

        NewAcl = ExAllocatePoolWithTag(PoolType,
                                       AclSize,
                                       TAG_ACL);
        if (!NewAcl)
            return STATUS_INSUFFICIENT_RESOURCES;

        RtlCopyMemory(NewAcl, InputAcl, AclSize);
    }

    /* Validate the captured ACL */
    if (!RtlValidAcl(NewAcl))
    {
        /* Free the ACL and fail */
        ExFreePoolWithTag(NewAcl, TAG_ACL);
        return STATUS_INVALID_ACL;
    }

    /* It's valid, return it */
    *CapturedAcl = NewAcl;
    return STATUS_SUCCESS;
}

/**
 * @brief
 * Releases (frees) a captured ACL from the memory pool.
 *
 * @param[in] CapturedAcl
 * A valid captured ACL to free.
 *
 * @param[in] AccessMode
 * Processor level access mode.
 *
 * @param[in] CaptureIfKernel
 * If set to TRUE and the processor access mode being KernelMode, we're
 * releasing an ACL directly in the kernel. Otherwise we're releasing
 * within a kernel mode driver.
 *
 * @return
 * Nothing.
 */
VOID
NTAPI
SepReleaseAcl(
    _In_ PACL CapturedAcl,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ BOOLEAN CaptureIfKernel)
{
    PAGED_CODE();

    if (CapturedAcl != NULL &&
        (AccessMode != KernelMode ||
         (AccessMode == KernelMode && CaptureIfKernel)))
    {
        ExFreePoolWithTag(CapturedAcl, TAG_ACL);
    }
}

/**
 * @brief
 * Determines if a certain ACE can or cannot be propagated based on
 * ACE inheritation flags and whatnot.
 *
 * @param[in] AceFlags
 * Bit flags of an ACE to perform propagation checks.
 *
 * @param[out] NewAceFlags
 * New ACE bit blags based on the specific ACE flags of the first
 * argument parameter.
 *
 * @param[in] IsInherited
 * If set to TRUE, an ACE is deemed as directly inherited from another
 * instance. In that case we're allowed to propagate.
 *
 * @param[in] IsDirectoryObject
 * If set to TRUE, an object directly inherits this ACE so we can propagate
 * it.
 *
 * @return
 * Returns TRUE if an ACE can be propagated, FALSE otherwise.
 */
BOOLEAN
SepShouldPropagateAce(
    _In_ UCHAR AceFlags,
    _Out_ PUCHAR NewAceFlags,
    _In_ BOOLEAN IsInherited,
    _In_ BOOLEAN IsDirectoryObject)
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

/**
 * @brief
 * Propagates (copies) an access control list.
 *
 * @param[out] AclDest
 * The destination parameter with propagated ACL.
 *
 * @param[in,out] AclLength
 * The length of the ACL that we propagate.
 *
 * @param[in] ExplicitAcl
 * If specified, a valid ACL whose ACEs are copied with their
 * inheritance flags unchanged.
 *
 * @param[in] ParentAcl
 * If specified, a valid ACL of the parent object whose inheritable
 * ACEs are inherited after the explicit ones. At least one of
 * ExplicitAcl and ParentAcl must be specified.
 *
 * @param[in] Owner
 * A SID that represents the main user that identifies the ACL.
 *
 * @param[in] Group
 * A SID that represents a group that identifies the ACL.
 *
 * @param[in] AutoInherit
 * If set to TRUE, the inherited ACEs are marked with INHERITED_ACE
 * and explicit ACEs marked with INHERITED_ACE are dropped.
 *
 * @param[in] IsDirectoryObject
 * If set to TRUE, that means the ACL is directly inherited because
 * of the object that inherits it.
 *
 * @param[in] GenericMapping
 * Generic mapping of access rights to map only certain effective
 * ACEs.
 *
 * @return
 * Returns STATUS_SUCCESS if ACL has been propagated successfully.
 * STATUS_BUFFER_TOO_SMALL is returned if the ACL length is not greater
 * than the maximum written size of the buffer for ACL propagation
 * otherwise.
 */
NTSTATUS
SepPropagateAcl(
    _Out_writes_bytes_opt_(AclLength) PACL AclDest,
    _Inout_ PULONG AclLength,
    _In_opt_ PACL ExplicitAcl,
    _In_opt_ PACL ParentAcl,
    _In_ PSID Owner,
    _In_ PSID Group,
    _In_ BOOLEAN AutoInherit,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ PGENERIC_MAPPING GenericMapping)
{
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

    /* RtlValidAcl lets a caller's ACL size and reserved fields through, as Windows does */
    ASSERT(AclSource != NULL);
    ASSERT(!ExplicitAcl || RtlValidAcl(ExplicitAcl));
    ASSERT(!ParentAcl || RtlValidAcl(ParentAcl));

    Written = 0;
    if (*AclLength >= Written + sizeof(ACL))
    {
        RtlCopyMemory(AclDest,
                      AclSource,
                      sizeof(ACL));
        AclDest->Sbz1 = 0;
        AclDest->Sbz2 = 0;
        if (ExplicitAcl && ParentAcl)
            AclDest->AclRevision = max(ExplicitAcl->AclRevision, ParentAcl->AclRevision);
    }
    Written += sizeof(ACL);

    CurrentDest = (PUCHAR)(AclDest + 1);
    CurrentSource = (PUCHAR)(AclSource + 1);
    for (i = 0; i < TotalCount; i++)
    {
        if (i == ExplicitCount)
        {
            /* The inherited ACEs follow the explicit ones */
            CurrentSource = (PUCHAR)(ParentAcl + 1);
            IsInherited = TRUE;
        }

        ASSERT((ULONG_PTR)CurrentDest % sizeof(ULONG) == 0);
        ASSERT((ULONG_PTR)CurrentSource % sizeof(ULONG) == 0);
        AceDest = (PACCESS_ALLOWED_ACE)CurrentDest;
        AceSource = (PACCESS_ALLOWED_ACE)CurrentSource;

        if ((AutoInherit && !IsInherited && (AceSource->Header.AceFlags & INHERITED_ACE)) ||
            !SepShouldPropagateAce(AceSource->Header.AceFlags,
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
            /* FIXME: handle object & compound ACEs */
            AceSize = AceSource->Header.AceSize;

            if (*AclLength >= Written + AceSize)
            {
                RtlCopyMemory(AceDest, AceSource, AceSize);
                AceDest->Header.AceFlags = AceFlags | InheritedFlag;
            }
            CurrentDest += AceSize;
            CurrentSource += AceSize;
            Written += AceSize;
            AceCount++;
            continue;
        }

        /* These all have the same structure */
        ASSERT(AceSource->Header.AceType == ACCESS_ALLOWED_ACE_TYPE ||
               AceSource->Header.AceType == ACCESS_DENIED_ACE_TYPE ||
               AceSource->Header.AceType == SYSTEM_AUDIT_ACE_TYPE ||
               AceSource->Header.AceType == SYSTEM_ALARM_ACE_TYPE);

        ASSERT(AceSource->Header.AceSize % sizeof(ULONG) == 0);
        ASSERT(AceSource->Header.AceSize >= sizeof(*AceSource));

        /* FIXME: filter out duplicate ACEs */
        AceSize = AceSource->Header.AceSize;
        Mask = AceSource->Mask;
        Sid = (PSID)&AceSource->SidStart;
        ASSERT(AceSize >= FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid));

        WriteTwoAces = FALSE;
        /* Map effective ACE to specific rights */
        if (!(AceFlags & INHERIT_ONLY_ACE))
        {
            RtlMapGenericMask(&Mask, GenericMapping);
            Mask &= GenericMapping->GenericAll;

            if (IsInherited)
            {
                if (RtlEqualSid(Sid, SeCreatorOwnerSid))
                    Sid = Owner;
                else if (RtlEqualSid(Sid, SeCreatorGroupSid))
                    Sid = Group;
                AceSize = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(Sid);

                /*
                 * A generic container ACE becomes two ACEs:
                 * - a specific effective ACE with no inheritance flags
                 * - an inherit-only ACE that keeps the generic rights
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
            CurrentDest += AceSize;

            if (!WriteTwoAces)
                break;

            /* Second ACE keeps all the generics from the source ACE */
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
        AclDest->AclSize = Written;
    }

    if (Written > *AclLength)
    {
        *AclLength = Written;
        return STATUS_BUFFER_TOO_SMALL;
    }
    *AclLength = Written;
    return STATUS_SUCCESS;
}

/**
 * @brief
 * Selects an ACL and returns it to the caller.
 *
 * @param[in] ExplicitAcl
 * If specified, the specified ACL to the call will be
 * the selected ACL for the caller.
 *
 * @param[in] ExplicitPresent
 * If set to TRUE and with specific ACL filled to the call, the
 * function will immediately return the specific ACL as the selected
 * ACL for the caller.
 *
 * @param[in] ExplicitDefaulted
 * If set to FALSE and with specific ACL filled to the call, the ACL
 * is not a default ACL. Otherwise it's a default ACL that we cannot
 * select it as is.
 *
 * @param[in] ParentAcl
 * If specified, the ACL of the parent object. If the ACL inherited from
 * it is not empty, it is returned in InheritedAcl.
 *
 * @param[in] DefaultAcl
 * If specified, the default ACL will be the selected one for the caller.
 *
 * @param[out] AclLength
 * The size length of an ACL.
 *
 * @param[in] Owner
 * A SID that represents the main user that identifies the ACL.
 *
 * @param[in] Group
 * A SID that represents a group that identifies the ACL.
 *
 * @param[out] AclPresent
 * The returned boolean value, indicating if the ACL that we want to select
 * does actually exist.
 *
 * @param[out] InheritedAcl
 * The returned parent ACL whose inheritable ACEs the new ACL inherits,
 * or NULL if it inherits none. These ACEs follow the ACEs of the
 * returned ACL.
 *
 * @param[in] ExplicitProtected
 * If set to TRUE, the explicit ACL is protected from inheritance.
 *
 * @param[in] AutoInherit
 * If set to TRUE, a non-default explicit ACL also inherits the
 * inheritable ACEs of the parent ACL, and inherited ACEs are marked
 * with INHERITED_ACE.
 *
 * @param[in] IsDirectoryObject
 * If set to TRUE, the object inherits this ACL.
 *
 * @param[in] GenericMapping
 * Generic mapping of access rights to map only certain effective
 * ACEs of an ACL that we want to select it.
 *
 * @return
 * Returns the selected non-inherited access control list (ACL): the
 * explicit or the default ACL. NULL is returned if the new ACL only
 * inherits from the parent ACL or if no ACL is selected.
 */
PACL
SepSelectAcl(
    _In_opt_ PACL ExplicitAcl,
    _In_ BOOLEAN ExplicitPresent,
    _In_ BOOLEAN ExplicitDefaulted,
    _In_opt_ PACL ParentAcl,
    _In_opt_ PACL DefaultAcl,
    _Out_ PULONG AclLength,
    _In_ PSID Owner,
    _In_ PSID Group,
    _Out_ PBOOLEAN AclPresent,
    _Out_ PACL *InheritedAcl,
    _In_ BOOLEAN ExplicitProtected,
    _In_ BOOLEAN AutoInherit,
    _In_ BOOLEAN IsDirectoryObject,
    _In_ PGENERIC_MAPPING GenericMapping)
{
    PACL Acl;
    NTSTATUS Status;

    *AclPresent = TRUE;
    *InheritedAcl = NULL;
    if (ExplicitPresent && !ExplicitDefaulted)
    {
        Acl = ExplicitAcl;

        /* Auto-inheritance appends the parent's inheritable ACEs */
        if (Acl && AutoInherit && !ExplicitProtected)
            *InheritedAcl = ParentAcl;
    }
    else
    {
        if (ParentAcl)
        {
            *AclLength = 0;
            Status = SepPropagateAcl(NULL,
                                     AclLength,
                                     NULL,
                                     ParentAcl,
                                     Owner,
                                     Group,
                                     AutoInherit,
                                     IsDirectoryObject,
                                     GenericMapping);
            ASSERT(Status == STATUS_BUFFER_TOO_SMALL);

            /* Use the parent ACL only if it's not empty */
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
        /* Get the length */
        Status = SepPropagateAcl(NULL,
                                 AclLength,
                                 Acl,
                                 *InheritedAcl,
                                 Owner,
                                 Group,
                                 AutoInherit,
                                 IsDirectoryObject,
                                 GenericMapping);
        ASSERT(Status == STATUS_BUFFER_TOO_SMALL);
    }
    return Acl;
}

/* EOF */
