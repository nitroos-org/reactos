/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Security access check control implementation
 * COPYRIGHT:   Copyright 2014 Timo Kreuzer <timo.kreuzer@reactos.org>
 *              Copyright 2014 Eric Kohl
 *              Copyright 2022-2023 George Bișoc <george.bisoc@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* PRIVATE FUNCTIONS **********************************************************/

/*
 * OWNER RIGHTS (S-1-3-4, Windows Vista and later; Microsoft's public documentation
 * of the well-known SIDs and of the access check):
 * - An ACE for OWNER RIGHTS applies to the owner of the object: it is checked as an
 *   ACE for the owner SID of the descriptor (so the owner must be in the token as
 *   for the implicit owner rights, also in the restricting SIDs pass of a
 *   restricted token, and a deny ACE also matches a deny-only owner group).
 *   A descriptor without an owner has nobody for OWNER RIGHTS ACEs to apply to.
 *   The owner is only tried when the ACE's SID itself is not in the token (tokens
 *   do not carry S-1-3-4), which keeps the cost off the ACEs that match.
 * - When the DACL has an OWNER RIGHTS ACE that applies to the object (not
 *   INHERIT_ONLY), the owner does not get the implicit READ_CONTROL | WRITE_DAC:
 *   it gets what the ACEs of the DACL grant it, the OWNER RIGHTS ACEs included.
 * - An inherit-only OWNER RIGHTS ACE neither grants nor takes the implicit rights.
 * Points the documentation leaves open (deny and object ACEs for OWNER RIGHTS as
 * the trigger, OWNER RIGHTS in a SACL) are listed for an oracle check in the
 * change's evidence; this follows the rules above for all of them.
 */

/**
 * @brief
 * Checks if a SID is OWNER RIGHTS (S-1-3-4).
 *
 * @param[in] Sid
 * A valid SID.
 *
 * @return
 * TRUE if the SID is OWNER RIGHTS, FALSE otherwise.
 */
FORCEINLINE
BOOLEAN
SepIsOwnerRightsSid(
    _In_ PSID Sid)
{
    PISID IdSid = (PISID)Sid;

    /*
     * The common case (any other SID) fails on the first comparisons; the
     * sub-authority is only read once the SID is known to have one
     */
    return IdSid->Revision == SID_REVISION &&
           IdSid->SubAuthorityCount == 1 &&
           IdSid->IdentifierAuthority.Value[5] == 3 &&
           IdSid->SubAuthority[0] == SECURITY_CREATOR_OWNER_RIGHTS_RID &&
           IdSid->IdentifierAuthority.Value[4] == 0 &&
           IdSid->IdentifierAuthority.Value[3] == 0 &&
           IdSid->IdentifierAuthority.Value[2] == 0 &&
           IdSid->IdentifierAuthority.Value[1] == 0 &&
           IdSid->IdentifierAuthority.Value[0] == 0;
}

/* The bytes of S-1-3-4: revision, count, 6-byte authority, one RID */
#define SEP_OWNER_RIGHTS_SID_LENGTH (FIELD_OFFSET(SID, SubAuthority) + sizeof(ULONG))

/**
 * @brief
 * Checks if a DACL has an OWNER RIGHTS ACE that applies to the object,
 * that is, an allow or deny ACE (plain or object) for S-1-3-4 that is
 * not INHERIT_ONLY.
 *
 * @param[in] Dacl
 * A DACL (of a captured or kernel descriptor). The walk stays inside
 * AclSize; it stops at the first ACE that does not fit.
 *
 * @return
 * TRUE if the DACL has such an ACE, FALSE otherwise.
 *
 * @remarks
 * Runs on every access check by the owner that asks for READ_CONTROL,
 * WRITE_DAC or MAXIMUM_ALLOWED, so it walks the ACEs directly instead
 * of through RtlGetAce (which starts over from the first ACE each time).
 */
static
BOOLEAN
SepDaclHasOwnerRightsAce(
    _In_ PACL Dacl)
{
    PACE_HEADER Ace;
    PUCHAR AclEnd;
    ULONG AceIndex;
    ULONG SidOffset;

    PAGED_CODE();

    Ace = (PACE_HEADER)(Dacl + 1);
    AclEnd = (PUCHAR)Dacl + Dacl->AclSize;

    for (AceIndex = 0; AceIndex < Dacl->AceCount; AceIndex++)
    {
        if ((PUCHAR)Ace + sizeof(ACE_HEADER) > AclEnd ||
            Ace->AceSize < sizeof(ACE_HEADER) ||
            (PUCHAR)Ace + Ace->AceSize > AclEnd)
        {
            break;
        }

        if (!(Ace->AceFlags & INHERIT_ONLY_ACE))
        {
            /* The ACE types the access check evaluates */
            switch (Ace->AceType)
            {
                case ACCESS_ALLOWED_ACE_TYPE:
                case ACCESS_DENIED_ACE_TYPE:
                    SidOffset = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
                    break;

                case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                case ACCESS_DENIED_OBJECT_ACE_TYPE:
                    /* The flags say which GUIDs come before the SID */
                    if (Ace->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType))
                        SidOffset = 0;
                    else
                        SidOffset = (ULONG)((PUCHAR)SepGetSidFromAce((PACE)Ace) - (PUCHAR)Ace);
                    break;

                default:
                    SidOffset = 0;
                    break;
            }

            if (SidOffset != 0 &&
                SidOffset + SEP_OWNER_RIGHTS_SID_LENGTH <= Ace->AceSize &&
                SepIsOwnerRightsSid((PUCHAR)Ace + SidOffset))
            {
                return TRUE;
            }
        }

        Ace = (PACE_HEADER)((PUCHAR)Ace + Ace->AceSize);
    }

    return FALSE;
}

/**
 * @brief
 * Tells whether an ACE of a DACL walk lies within the ACL: its header, its
 * size (at least a header, not past the ACL) and, for the ACE types the access
 * check evaluates (allow and deny, plain and object), every field the check
 * reads (mask, flags, object types, the whole SID) within that size.
 *
 * @param[in] Ace
 * The ACE the walk is at; it starts inside the ACL.
 *
 * @param[in] AclEnd
 * The first byte behind the ACL (the ACL plus its AclSize).
 *
 * @return
 * TRUE if the ACE lies within the ACL, FALSE otherwise.
 *
 * @remarks
 * The object opens (SeAccessCheck) pass descriptors that were not captured
 * here: a file system's descriptor read from the disk is not validated again.
 * The DACL walks stop at the first ACE that does not lie within the ACL, as
 * the label walk (SepMandatoryAllowedAccess) and the OWNER RIGHTS scan do:
 * the ACEs before it count, it and the ACEs after it do not. Stopping early
 * never grants more than walking on (a later allow ACE can only grant, a
 * later deny ACE can only refuse what was not granted yet). Captured
 * descriptors (every user-mode caller: RtlValidAcl at capture) always pass.
 */
static
BOOLEAN
SepAceWithinAcl(
    _In_ PACE_HEADER Ace,
    _In_ PUCHAR AclEnd)
{
    ULONG_PTR Left = (ULONG_PTR)(AclEnd - (PUCHAR)Ace);
    ULONG_PTR SidOffset;
    PISID Sid;
    ULONG Flags;

    if (Left < sizeof(ACE_HEADER) || Ace->AceSize < sizeof(ACE_HEADER) || Left < Ace->AceSize)
        return FALSE;

    /*
     * The fields the check reads must lie within the ACE itself (as RtlValidAcl
     * and the label walk require), not only within the ACL: the bytes behind
     * AceSize belong to the next ACE, and an ACE does not mean something else
     * depending on what follows it
     */
    Left = Ace->AceSize;

    switch (Ace->AceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
            SidOffset = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
            break;

        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
            if (Left < FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType))
                return FALSE;
            Flags = ((PACCESS_ALLOWED_OBJECT_ACE)Ace)->Flags;
            SidOffset = FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType);
            if (Flags & ACE_OBJECT_TYPE_PRESENT)
                SidOffset += sizeof(GUID);
            if (Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)
                SidOffset += sizeof(GUID);
            break;

        default:
            /* Passed over by the walks: nothing behind the header is read */
            return TRUE;
    }

    if (Left < SidOffset + FIELD_OFFSET(SID, SubAuthority))
        return FALSE;
    Sid = (PISID)((PUCHAR)Ace + SidOffset);
    return Left >= SidOffset + RtlLengthRequiredSid(Sid->SubAuthorityCount);
}

/**
 * @brief
 * Tells which restricting SIDs pass a token needs for an access check, and for
 * which rights.
 *
 * A token with restricting SIDs gets, for every right, only what both the
 * normal and the restricting SIDs are granted. A write restricted token (see
 * SEP_TOKEN_WRITE_RESTRICTED) compares the restricting SIDs only for write
 * access, also when it has none (then no write access is granted). Measured on
 * Windows Server 2022 with files, directories, registry keys and events, and
 * with generic mappings of their own, for tokens from
 * CreateRestrictedToken(WRITE_RESTRICTED): the restricting SIDs have to grant
 * the rights of GenericMapping->GenericWrite that GenericRead and GenericExecute
 * do not hold (so READ_CONTROL and SYNCHRONIZE of a file, a key or an event are
 * not compared, a right that the write and the read mapping share is not, and
 * READ_CONTROL or SYNCHRONIZE that only the write mapping holds is), and DELETE,
 * WRITE_DAC and WRITE_OWNER always; every other right (the file rights
 * FILE_DELETE_CHILD, FILE_EXECUTE, the key rights KEY_NOTIFY and KEY_CREATE_LINK)
 * stays with the normal pass.
 *
 * @param[in] Token
 * The token the access check is for.
 *
 * @param[in] GenericMapping
 * The generic mapping of the object.
 *
 * @param[out] RestrictedMask
 * The rights the restricting SIDs have to grant: all of them for a restricted
 * token, the write rights for a write restricted one, none for another token.
 *
 * @return
 * TRUE if the restricting SIDs pass has to be done for some right.
 */
static
BOOLEAN
SepGetRestrictedAccessMask(
    _In_ PACCESS_TOKEN Token,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_ PACCESS_MASK RestrictedMask)
{
    PAGED_CODE();

    if (((PTOKEN)Token)->TokenFlags & SEP_TOKEN_WRITE_RESTRICTED)
    {
        *RestrictedMask = (GenericMapping->GenericWrite &
                           ~(GenericMapping->GenericRead | GenericMapping->GenericExecute)) |
                          DELETE | WRITE_DAC | WRITE_OWNER;
        return TRUE;
    }

    if (SeTokenIsRestricted(Token))
    {
        *RestrictedMask = 0xFFFFFFFF;
        return TRUE;
    }

    *RestrictedMask = 0;
    return FALSE;
}

/**
 * @brief
 * Checks if the token gets the implicit owner rights (READ_CONTROL and
 * WRITE_DAC) on an object: it is the owner, and the DACL of the object
 * has no OWNER RIGHTS ACE that applies to the object.
 *
 * @param[in] Token
 * The token the access check is for.
 *
 * @param[in] SecurityDescriptor
 * The security descriptor of the object, with an owner.
 *
 * @return
 * TRUE if the token gets the implicit owner rights, FALSE otherwise.
 */
static
BOOLEAN
SepTokenGetsImplicitOwnerRights(
    _In_ PACCESS_TOKEN Token,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor)
{
    PACL Dacl;

    PAGED_CODE();

    if (!SepTokenIsOwner(Token, SecurityDescriptor, FALSE))
        return FALSE;

    /* No DACL (NULL or none) grants everything anyway */
    Dacl = SepGetDaclFromDescriptor(SecurityDescriptor);
    if (Dacl == NULL)
        return TRUE;

    return !SepDaclHasOwnerRightsAce(Dacl);
}

/*
 * Mandatory integrity in the access check services (NtAccessCheck,
 * NtAccessCheckByType, NtAccessCheckByTypeResultList and their audit alarm
 * forms) and in the object opens (SeAccessCheck). Measured on Windows Server 2022 with impersonation tokens of every
 * level (Untrusted to System, the anonymous logon token, Low restricted and
 * write restricted tokens, a standard user at Medium and Low), descriptors
 * without a label and with labels of every level and policy, three generic
 * mappings, 17 requests and object type lists (101,000 compared results):
 * - The label of the object is the first mandatory label ACE of its SACL
 *   that is not INHERIT_ONLY; one without has an implicit Medium label.
 * - A token at or above the level of the label is not restricted by it.
 * - A token below it is granted at most the read rights (GenericRead of the
 *   mapping and READ_CONTROL) unless the label has NO_READ_UP, and the
 *   execute rights (GenericExecute and SYNCHRONIZE) unless it has
 *   NO_EXECUTE_UP; never any other right: there is no write up, also when
 *   the label does not have NO_WRITE_UP.
 * - A request for any other right (also ACCESS_SYSTEM_SECURITY, WRITE_OWNER
 *   and the WRITE_DAC the owner would get implicitly) is denied before the
 *   privileges and the DACL are looked at; MAXIMUM_ALLOWED gets what the DACL
 *   grants within those rights.
 * The object opens of the kernel (SeAccessCheck) apply the same function:
 * measured on the same system, opens of named objects, files and keys by an
 * Untrusted, Low or anonymous client are limited the same way (NtOpenEvent
 * MAXIMUM_ALLOWED of a Low owner on an empty DACL: READ_CONTROL, no
 * WRITE_DAC; the hosts file for write by LocalSystem lowered to Low: denied).
 * "Windows Integrity Mechanism Design" (How access checks work with mandatory
 * policy): SeAccessCheck enforces the policy as AccessCheck does.
 */

/**
 * @brief
 * Works out the rights the mandatory label of a descriptor leaves a token.
 *
 * @param[in] Token
 * The token the access check is for. The caller holds its lock.
 *
 * @param[in] SecurityDescriptor
 * A captured (validated) security descriptor.
 *
 * @param[in] GenericMapping
 * The generic mapping of the object.
 *
 * @param[out] LabelLevel
 * The level of the label of the object (the implicit Medium one without a label).
 *
 * @return
 * The rights the token may be granted at most, or MAXULONG when the label
 * does not restrict the token.
 */
static
ACCESS_MASK
SepMandatoryAllowedAccess(
    _In_ PTOKEN Token,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_opt_ PULONG LabelLevel)
{
    ULONG Level = SECURITY_MANDATORY_MEDIUM_RID;
    ACCESS_MASK Policy = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
    ACCESS_MASK Allowed = 0;
    BOOLEAN Present, Defaulted;
    PACL Sacl = NULL;
    PACE_HEADER Ace;
    PISID LabelSid;
    PUCHAR AclEnd;
    ULONG AceIndex;
    ULONG Rid;

    PAGED_CODE();

    /*
     * The object opens (SeAccessCheck) pass descriptors that were not
     * captured here (file systems read theirs from the disk): every ACE must
     * lie within the ACL; the walk stops at the first one that does not, and
     * the label found so far (or the implicit one) counts. Most descriptors
     * have no SACL (every object opens through here): the control bit says
     * so without the lookup.
     */
    if ((((PISECURITY_DESCRIPTOR)SecurityDescriptor)->Control & SE_SACL_PRESENT) &&
        NT_SUCCESS(RtlGetSaclSecurityDescriptor(SecurityDescriptor, &Present, &Sacl, &Defaulted)) &&
        Present && Sacl != NULL && Sacl->AclSize >= sizeof(ACL))
    {
        AclEnd = (PUCHAR)Sacl + Sacl->AclSize;
        Ace = (PACE_HEADER)(Sacl + 1);
        for (AceIndex = 0; AceIndex < Sacl->AceCount; AceIndex++,
             Ace = (PACE_HEADER)((PUCHAR)Ace + Ace->AceSize))
        {
            if ((ULONG_PTR)(AclEnd - (PUCHAR)Ace) < sizeof(ACE_HEADER) ||
                Ace->AceSize < sizeof(ACE_HEADER) ||
                (ULONG_PTR)(AclEnd - (PUCHAR)Ace) < Ace->AceSize)
            {
                break;
            }

            if (Ace->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE || (Ace->AceFlags & INHERIT_ONLY_ACE))
                continue;

            /* The ACE must hold a whole mandatory label SID; another one is passed over */
            LabelSid = (PISID)&((PSYSTEM_MANDATORY_LABEL_ACE)Ace)->SidStart;
            if (Ace->AceSize < FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + FIELD_OFFSET(SID, SubAuthority) ||
                Ace->AceSize < FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) +
                               RtlLengthRequiredSid(LabelSid->SubAuthorityCount) ||
                !SepIsMandatoryLabelSid((PSID)LabelSid, &Rid))
            {
                continue;
            }

            Level = Rid;
            Policy = ((PSYSTEM_MANDATORY_LABEL_ACE)Ace)->Mask;
            break;
        }
    }

    if (LabelLevel)
        *LabelLevel = Level;

    if (Token->IntegrityLevel >= Level)
        return MAXULONG;

    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_READ_UP))
        Allowed |= GenericMapping->GenericRead | READ_CONTROL;
    if (!(Policy & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP))
        Allowed |= GenericMapping->GenericExecute | SYNCHRONIZE;

    return Allowed;
}

/*
 * The AppContainer pass. A lowbox (AppContainer) token is granted only what both the normal
 * pass and an AppContainer pass grant (Microsoft Learn, "AppContainer isolation" and "Launch an
 * AppContainer", paraphrased: the package and capability SIDs of the token are separate from its
 * user and group SIDs, and a resource is reachable only where the DACL grants them access).
 * Measured on Windows Server 2022 (the rvac matrix of the access check
 * services, 2,277 lowbox rows, and object opens of named objects, files, keys and processes by
 * an impersonated lowbox token): a lowbox token gets nothing without an ACE for its package SID,
 * a capability it holds or ALL APPLICATION PACKAGES, also on a NULL DACL, a descriptor without
 * a DACL and as the owner (no implicit READ_CONTROL); the open of another process of its user,
 * whose DACL has no such ACE, is refused.
 *
 * In the AppContainer pass an ACE applies when its SID is the token's package SID, one of its
 * capability SIDs that is enabled, ALL APPLICATION PACKAGES (S-1-15-2-1) or ALL RESTRICTED
 * APPLICATION PACKAGES (S-1-15-2-2); its rights are worked out as for MAXIMUM_ALLOWED (an allow
 * grants what was not denied before it, a deny denies what was not granted before it). Not
 * measured, the choice taken (to verify on Windows): OWNER RIGHTS and PRINCIPAL SELF ACEs do not
 * apply in the AppContainer pass; rights a privilege grants (ACCESS_SYSTEM_SECURITY) and rights
 * the caller of SeAccessCheck grants itself stay granted; for an object type list the pass of
 * the object (the root) bounds every entry.
 */
typedef struct _SEP_SID2
{
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[2];
} SEP_SID2;

static const SEP_SID2 SepAllAppPackagesSid =
    { SID_REVISION, 2, { SECURITY_APP_PACKAGE_AUTHORITY }, { SECURITY_APP_PACKAGE_BASE_RID, SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE } };
static const SEP_SID2 SepAllRestrictedAppPackagesSid =
    { SID_REVISION, 2, { SECURITY_APP_PACKAGE_AUTHORITY }, { SECURITY_APP_PACKAGE_BASE_RID, 2 } };

/* The SID is one an ACE of the AppContainer pass applies to for the lowbox data */
static
BOOLEAN
SepIsAppContainerSidOf(
    _In_ PSEP_LOWBOX Lowbox,
    _In_ PISID Sid,
    _In_ ULONG SidLength)
{
    ULONG i;

    if (Sid->IdentifierAuthority.Value[5] != 15 || Sid->IdentifierAuthority.Value[0] != 0)
        return FALSE;
    if ((SidLength == sizeof(SEP_SID2) && RtlEqualSid(Sid, (PSID)&SepAllAppPackagesSid)) ||
        (SidLength == sizeof(SEP_SID2) && RtlEqualSid(Sid, (PSID)&SepAllRestrictedAppPackagesSid)) ||
        (SidLength == RtlLengthSid(Lowbox->PackageSid) && RtlEqualSid(Sid, Lowbox->PackageSid)))
    {
        return TRUE;
    }
    for (i = 0; i < Lowbox->CapabilityCount; i++)
    {
        if ((Lowbox->Capabilities[i].Attributes & SE_GROUP_ENABLED) &&
            SidLength == RtlLengthSid(Lowbox->Capabilities[i].Sid) &&
            RtlEqualSid(Sid, Lowbox->Capabilities[i].Sid))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * @brief
 * Works out the rights the AppContainer pass leaves a token.
 *
 * @param[in] Token
 * The token the access check is for. The caller holds its lock.
 *
 * @param[in] SecurityDescriptor
 * The security descriptor of the object (captured, or a kernel caller's).
 *
 * @param[in] OwnPackageOnly
 * TRUE to count only the entries of the token's own package SID (the rights the mandatory label does not
 * hold back: see the callers); FALSE for all the SIDs the pass applies to.
 *
 * @return
 * MAXULONG when the token is not a lowbox token (no AppContainer pass),
 * else the rights the DACL grants the token's AppContainer SIDs (none
 * without a DACL, with a NULL or an empty one).
 */
static
ACCESS_MASK
SepAppContainerAllowedAccess(
    _In_ PTOKEN Token,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN OwnPackageOnly)
{
    ACCESS_MASK Granted = 0, Denied = 0, Mask;
    BOOLEAN Present, Defaulted, IsDenied;
    PACE_HEADER Ace;
    PUCHAR AclEnd;
    ULONG AceIndex, SidOffset, Left, Flags;
    PISID Sid;
    PACL Dacl;

    PAGED_CODE();

    if (Token->Lowbox == NULL)
        return MAXULONG;

    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor(SecurityDescriptor, &Present, &Dacl, &Defaulted)) ||
        !Present || Dacl == NULL || Dacl->AclSize < sizeof(ACL))
    {
        return 0;
    }

    /* Every ACE must lie within the ACL (a kernel caller's descriptor is not validated): the walk stops at one that does not */
    AclEnd = (PUCHAR)Dacl + Dacl->AclSize;
    Ace = (PACE_HEADER)(Dacl + 1);
    for (AceIndex = 0; AceIndex < Dacl->AceCount; AceIndex++, Ace = (PACE_HEADER)((PUCHAR)Ace + Ace->AceSize))
    {
        if ((PUCHAR)Ace >= AclEnd)
            break;
        Left = (ULONG)(AclEnd - (PUCHAR)Ace);
        if (Left < sizeof(ACE_HEADER) || Ace->AceSize < sizeof(ACE_HEADER) || Left < Ace->AceSize)
            break;
        Left = Ace->AceSize;

        switch (Ace->AceType)
        {
            case ACCESS_ALLOWED_ACE_TYPE:
            case ACCESS_DENIED_ACE_TYPE:
                IsDenied = (Ace->AceType == ACCESS_DENIED_ACE_TYPE);
                SidOffset = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
                Flags = 0;
                break;

            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                /* An allow or deny ACE whose fields do not lie within it ends the walk, as in the normal pass */
                if (Left < FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType))
                    goto Stop;
                IsDenied = (Ace->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE);
                Flags = ((PACCESS_ALLOWED_OBJECT_ACE)Ace)->Flags;
                SidOffset = FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType) +
                            ((Flags & ACE_OBJECT_TYPE_PRESENT) ? sizeof(GUID) : 0) +
                            ((Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) ? sizeof(GUID) : 0);
                break;

            default:
                continue;
        }

        /*
         * The SID must lie within the ACE; one that does not ends the walk (the normal pass stops there too, so
         * skipping it here could leave a later allow in the AppContainer pass that the normal pass never sees)
         */
        if (Left < SidOffset + FIELD_OFFSET(SID, SubAuthority))
            goto Stop;
        Sid = (PISID)((PUCHAR)Ace + SidOffset);
        if (Left < SidOffset + RtlLengthRequiredSid(Sid->SubAuthorityCount))
            goto Stop;

        if (Ace->AceFlags & INHERIT_ONLY_ACE)
            continue;

        /* As the normal pass: an allow with an object type is for the list only, a deny denies */
        if (!IsDenied && (Flags & ACE_OBJECT_TYPE_PRESENT))
            continue;

        if (!SepIsAppContainerSidOf(Token->Lowbox, Sid, RtlLengthRequiredSid(Sid->SubAuthorityCount)))
            continue;
        if (OwnPackageOnly && !RtlEqualSid(Sid, Token->Lowbox->PackageSid))
            continue;

        Mask = ((PACCESS_ALLOWED_ACE)Ace)->Mask;
        if (IsDenied)
            Denied |= Mask & ~Granted;
        else
            Granted |= Mask & ~Denied;
    }

Stop:
    return Granted;
}

/**
 * @brief
 * Tells whether the mandatory label of a descriptor denies a token some of
 * the rights it asks for (the precedence of the label over a missing
 * privilege: an Untrusted or Low client asking for ACCESS_SYSTEM_SECURITY
 * without SeSecurityPrivilege is denied access, measured).
 *
 * @param[in] Token
 * The client token. The function takes its lock.
 *
 * @param[in] CapturedSecurityDescriptor
 * A captured (validated) security descriptor.
 *
 * @param[in] DesiredAccess
 * The rights asked for, without generic rights; MAXIMUM_ALLOWED is ignored.
 *
 * @param[in] GenericMapping
 * The generic mapping of the object.
 *
 * @return
 * TRUE if the label denies some of the rights.
 */
BOOLEAN
SepMandatoryAccessDenied(
    _In_ PTOKEN Token,
    _In_ PSECURITY_DESCRIPTOR CapturedSecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping)
{
    ACCESS_MASK Allowed;

    PAGED_CODE();

    SepAcquireTokenLockShared(Token);
    Allowed = SepMandatoryAllowedAccess(Token, CapturedSecurityDescriptor, GenericMapping, NULL);
    SepReleaseTokenLock(Token);

    return Allowed != MAXULONG && (DesiredAccess & ~(MAXIMUM_ALLOWED | Allowed)) != 0;
}

/*
 * Object type lists (NtAccessCheckByType and NtAccessCheckByTypeResultList).
 *
 * The list is a tree in pre-order: the object itself (the root, level 0) and its property sets and
 * properties below it; it was validated when it was captured, so the first entry is the only root
 * and each entry is at most one level below the one before it. Every entry has granted and denied
 * rights of its own, worked out as for MAXIMUM_ALLOWED: an ACE grants the rights it allows that
 * were not denied before it and denies the rights it denies that were not granted before it.
 *
 * Measured on Windows 10 22H2 (AccessCheckObjectTypeList apitest):
 * - An ACE without an object type (a plain ACE, or an object ACE without ACE_OBJECT_TYPE_PRESENT)
 *   applies to the root and so to the whole list.
 * - An object ACE applies to the entry with its object type and to the entries below it; an object
 *   type that is not in the list makes the ACE count for nothing.
 * - An entry is also granted the rights that all of the entries directly below it are granted,
 *   up to the root; a right denied to an entry is denied to the entries above it as well (when they
 *   were not granted it already).
 * - A token with restricting SIDs gets, per entry, the rights both passes grant.
 * - NtAccessCheckByType reports the result for the root, NtAccessCheckByTypeResultList the result
 *   of each entry.
 * Without a list, an allowed object ACE with an object type grants nothing (see SepAnalyzeAcesFromDacl).
 */

/**
 * @brief
 * Finds the parent of a non-root entry of a captured object type list.
 *
 * @param[in] ObjectTypeList
 * The captured (validated) object type list.
 *
 * @param[in] ObjectTypeIndex
 * The index of an entry that is not the root.
 *
 * @return
 * The index of the nearest entry before it with a lower level.
 */
static
ULONG
SepObjectTypeParent(
    _In_ POBJECT_TYPE_LIST_INTERNAL ObjectTypeList,
    _In_ ULONG ObjectTypeIndex)
{
    ULONG ParentIndex = ObjectTypeIndex;

    ASSERT(ObjectTypeIndex != 0);
    ASSERT(ObjectTypeList[ObjectTypeIndex].Level != ACCESS_OBJECT_GUID);

    /* The root at index 0 has the lowest level, so this stops there at the latest */
    do
    {
        ParentIndex--;
    } while (ObjectTypeList[ParentIndex].Level >= ObjectTypeList[ObjectTypeIndex].Level);

    return ParentIndex;
}

/**
 * @brief
 * Applies the rights of one ACE to an entry of an object type list,
 * the entries below it and the entries above it.
 *
 * @param[in,out] ObjectTypeList
 * The captured (validated) object type list.
 *
 * @param[in] ObjectTypeListLength
 * The number of entries in the list.
 *
 * @param[in] ObjectTypeIndex
 * The entry the ACE is for (0, the root, for an ACE without an object type).
 *
 * @param[in] AccessMask
 * The (mapped) rights of the ACE.
 *
 * @param[in] IsDenied
 * TRUE for a deny ACE, FALSE for an allow ACE.
 */
static
VOID
SepApplyAceToObjectTypeList(
    _Inout_ POBJECT_TYPE_LIST_INTERNAL ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ ULONG ObjectTypeIndex,
    _In_ ACCESS_MASK AccessMask,
    _In_ BOOLEAN IsDenied)
{
    PACCESS_CHECK_RIGHTS Rights;
    ACCESS_MASK ChildrenGranted, NewlyDenied;
    ULONG Index, ChildIndex, ParentIndex;
    USHORT Level = ObjectTypeList[ObjectTypeIndex].Level;

    /* A deny ACE denies the entries above only what the entry itself is denied (Windows 10 22H2 measured):
       a right the entry already holds is not taken from them */
    NewlyDenied = AccessMask & ~ObjectTypeList[ObjectTypeIndex].ObjectAccessRights.GrantedAccessRights;

    /* The entry itself and every entry below it */
    for (Index = ObjectTypeIndex; Index < ObjectTypeListLength; Index++)
    {
        if (Index != ObjectTypeIndex && ObjectTypeList[Index].Level <= Level)
            break;

        Rights = &ObjectTypeList[Index].ObjectAccessRights;
        if (IsDenied)
            Rights->DeniedAccessRights |= (AccessMask & ~Rights->GrantedAccessRights);
        else
            Rights->GrantedAccessRights |= (AccessMask & ~Rights->DeniedAccessRights);
    }

    /* The entries above it, up to the root */
    for (ChildIndex = ObjectTypeIndex;
         ObjectTypeList[ChildIndex].Level != ACCESS_OBJECT_GUID;
         ChildIndex = ParentIndex)
    {
        ParentIndex = SepObjectTypeParent(ObjectTypeList, ChildIndex);
        Rights = &ObjectTypeList[ParentIndex].ObjectAccessRights;

        if (IsDenied)
        {
            Rights->DeniedAccessRights |= (NewlyDenied & ~Rights->GrantedAccessRights);
            continue;
        }

        /* A parent is granted what all of its direct children are granted */
        ChildrenGranted = ~(ACCESS_MASK)0;
        for (Index = ParentIndex + 1;
             Index < ObjectTypeListLength && ObjectTypeList[Index].Level > ObjectTypeList[ParentIndex].Level;
             Index++)
        {
            if (ObjectTypeList[Index].Level == ObjectTypeList[ParentIndex].Level + 1)
                ChildrenGranted &= ObjectTypeList[Index].ObjectAccessRights.GrantedAccessRights;
        }

        Rights->GrantedAccessRights |= (ChildrenGranted & ~Rights->DeniedAccessRights);
    }
}

/**
 * @brief
 * Works out the granted and denied rights of every entry of an object
 * type list from the ACEs of a DACL, for one pass (normal or restricting SIDs).
 *
 * @param[in] Dacl
 * The DACL, with at least one ACE.
 *
 * @param[in] AccessToken
 * The token whose SIDs are compared with the SIDs of the ACEs.
 *
 * @param[in] IsTokenRestricted
 * TRUE to compare the restricting SIDs of the token, FALSE for its normal SIDs.
 *
 * @param[in] PrincipalSelfSid
 * The SID that replaces the principal self SID in ACEs, if any.
 *
 * @param[in] OwnerSid
 * The owner SID of the descriptor, which OWNER RIGHTS ACEs are checked as;
 * NULL if it has none (OWNER RIGHTS ACEs then apply to nobody).
 *
 * @param[in] GenericMapping
 * The generic mapping for the rights of the ACEs.
 *
 * @param[in,out] ObjectTypeList
 * The captured (validated) object type list; the rights of its entries must be clear.
 *
 * @param[in] ObjectTypeListLength
 * The number of entries in the list.
 */
static
VOID
SepAnalyzeAcesForObjectTypeList(
    _In_ PACL Dacl,
    _In_ PACCESS_TOKEN AccessToken,
    _In_ BOOLEAN IsTokenRestricted,
    _In_opt_ PSID PrincipalSelfSid,
    _In_opt_ PSID OwnerSid,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Inout_ POBJECT_TYPE_LIST_INTERNAL ObjectTypeList,
    _In_ ULONG ObjectTypeListLength)
{
    SEP_ACE_CURSOR Cursor;
    BOOLEAN Found;
    PACE CurrentAce;
    ULONG AceIndex;
    ULONG ObjectTypeIndex;
    PSID Sid;
    PGUID ObjectTypeGuid;
    ACCESS_MASK Access;
    BOOLEAN IsDenied;

    PAGED_CODE();

    /* One pass (RtlGetAce per index starts over from the first ACE), see SepAnalyzeAcesFromDacl */
    SepInitAceCursor(&Cursor, Dacl);
    for (AceIndex = 0; AceIndex < Dacl->AceCount; AceIndex++)
    {
        /* An AceCount larger than the ACEs the ACL holds (a descriptor from the disk) ends the walk as well */
        Found = SepNextAce(&Cursor, (PVOID*)&CurrentAce);
        if (!Found)
            break;

        /* An ACE that does not lie within the ACL ends the walk (SepAceWithinAcl) */
        if (!SepAceWithinAcl(&CurrentAce->Header, Cursor.End))
            break;

        if (CurrentAce->Header.AceFlags & INHERIT_ONLY_ACE)
            continue;

        switch (CurrentAce->Header.AceType)
        {
            case ACCESS_ALLOWED_ACE_TYPE:
                IsDenied = FALSE;
                ObjectTypeGuid = NULL;
                break;

            case ACCESS_DENIED_ACE_TYPE:
                IsDenied = TRUE;
                ObjectTypeGuid = NULL;
                break;

            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                IsDenied = FALSE;
                ObjectTypeGuid = SepGetObjectTypeGuidFromAce(CurrentAce, FALSE);
                break;

            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                IsDenied = TRUE;
                ObjectTypeGuid = SepGetObjectTypeGuidFromAce(CurrentAce, TRUE);
                break;

            default:
                DPRINT("Unsupported ACE type 0x%lx\n", CurrentAce->Header.AceType);
                continue;
        }

        Sid = SepGetSidFromAce(CurrentAce);
        ASSERT(Sid);

        if (!SepSidInTokenEx(AccessToken, PrincipalSelfSid, Sid, IsDenied, IsTokenRestricted))
        {
            /* An OWNER RIGHTS ACE is for the owner (looked at only when no SID matched) */
            if (OwnerSid == NULL ||
                !SepIsOwnerRightsSid(Sid) ||
                !SepSidInTokenEx(AccessToken, NULL, OwnerSid, IsDenied, IsTokenRestricted))
            {
                continue;
            }
        }

        /* An ACE without an object type is for the root; one with a type not in the list is for nothing */
        if (ObjectTypeGuid == NULL)
        {
            ObjectTypeIndex = 0;
        }
        else if (!SepObjectTypeGuidInList(ObjectTypeList,
                                          ObjectTypeListLength,
                                          ObjectTypeGuid,
                                          &ObjectTypeIndex))
        {
            continue;
        }

        /* The ACE's mask as stored: generic rights in it are not mapped (see SepAnalyzeAcesFromDacl) */
        Access = CurrentAce->AccessMask;

        SepApplyAceToObjectTypeList(ObjectTypeList,
                                    ObjectTypeListLength,
                                    ObjectTypeIndex,
                                    Access,
                                    IsDenied);
    }
}

/**
 * @brief
 * Works out the granted rights of every entry of an object type list,
 * including the restricting SIDs pass of a restricted token.
 *
 * @param[in] Dacl
 * The DACL, with at least one ACE.
 *
 * @param[in] AccessToken
 * The token the access check is for.
 *
 * @param[in] PrincipalSelfSid
 * The SID that replaces the principal self SID in ACEs, if any.
 *
 * @param[in] OwnerSid
 * The owner SID of the descriptor (for OWNER RIGHTS ACEs), if any.
 *
 * @param[in] GenericMapping
 * The generic mapping for the rights of the ACEs.
 *
 * @param[in,out] ObjectTypeList
 * The captured (validated) object type list. On success the granted
 * rights of each entry are those the DACL grants the token.
 *
 * @param[in] ObjectTypeListLength
 * The number of entries in the list.
 *
 * @return
 * STATUS_SUCCESS, or STATUS_INSUFFICIENT_RESOURCES.
 */
static
NTSTATUS
SepAccessCheckObjectTypeList(
    _In_ PACL Dacl,
    _In_ PACCESS_TOKEN AccessToken,
    _In_opt_ PSID PrincipalSelfSid,
    _In_opt_ PSID OwnerSid,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Inout_ POBJECT_TYPE_LIST_INTERNAL ObjectTypeList,
    _In_ ULONG ObjectTypeListLength)
{
    PACCESS_MASK NormalGranted;
    ACCESS_MASK RestrictedMask;
    ULONG Index;

    PAGED_CODE();

    for (Index = 0; Index < ObjectTypeListLength; Index++)
    {
        RtlZeroMemory(&ObjectTypeList[Index].ObjectAccessRights, sizeof(ACCESS_CHECK_RIGHTS));
    }

    SepAnalyzeAcesForObjectTypeList(Dacl,
                                    AccessToken,
                                    FALSE,
                                    PrincipalSelfSid,
                                    OwnerSid,
                                    GenericMapping,
                                    ObjectTypeList,
                                    ObjectTypeListLength);

    if (!SepGetRestrictedAccessMask(AccessToken, GenericMapping, &RestrictedMask))
        return STATUS_SUCCESS;

    /* The length was bounded when the list was captured */
    NormalGranted = ExAllocatePoolWithTag(PagedPool,
                                          ObjectTypeListLength * sizeof(ACCESS_MASK),
                                          TAG_SE);
    if (NormalGranted == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    for (Index = 0; Index < ObjectTypeListLength; Index++)
    {
        NormalGranted[Index] = ObjectTypeList[Index].ObjectAccessRights.GrantedAccessRights;
        RtlZeroMemory(&ObjectTypeList[Index].ObjectAccessRights, sizeof(ACCESS_CHECK_RIGHTS));
    }

    SepAnalyzeAcesForObjectTypeList(Dacl,
                                    AccessToken,
                                    TRUE,
                                    PrincipalSelfSid,
                                    OwnerSid,
                                    GenericMapping,
                                    ObjectTypeList,
                                    ObjectTypeListLength);

    /*
     * Only what both the normal and the restricting SIDs are granted; of the
     * rights the restricting SIDs are not compared for (a write restricted
     * token), what the normal SIDs are granted.
     */
    for (Index = 0; Index < ObjectTypeListLength; Index++)
    {
        ObjectTypeList[Index].ObjectAccessRights.GrantedAccessRights =
            NormalGranted[Index] &
            (ObjectTypeList[Index].ObjectAccessRights.GrantedAccessRights | ~RestrictedMask);
    }

    ExFreePoolWithTag(NormalGranted, TAG_SE);
    return STATUS_SUCCESS;
}

/**
 * @brief
 * Analyzes an access control entry that is present in a discretionary
 * access control list (DACL) for access right masks of each entry with
 * the purpose to judge whether the calling thread can be warranted
 * access check to a certain object or not. This is for an access check
 * without an object type list (see SepAccessCheckObjectTypeList for one
 * with a list).
 *
 * @param[in] ActionType
 * The type of analysis to be done against an access entry. This type
 * influences how access rights are gathered. This can either be AccessCheckMaximum
 * which means the algorithm will perform analysis against ACEs on behalf of the
 * requestor that gave us the acknowledgement that he desires MAXIMUM_ALLOWED access
 * right or AccessCheckRegular if the requestor wants a subset of access rights.
 *
 * @param[in] RemainingAccess
 * The remaining access rights that have yet to be granted to the calling thread
 * whomst requests access to a certain object. This parameter mustn't be 0 as
 * the remaining rights are left to be addressed. This is the case if we have
 * to address the remaining rights on a regular subset basis (the requestor
 * didn't ask for MAXIMUM_ALLOWED). Otherwise this parameter can be 0.
 *
 * @param[in] Dacl
 * The discretionary access control list to be given to this function. This DACL
 * must have at least one ACE currently present in the list.
 *
 * @param[in] AccessToken
 * A pointer to an access token, where an equality comparison check is performed if
 * the security identifier (SID) from a ACE of a certain object is present in this
 * token. This token represents the effective (calling thread) token of the caller.
 *
 * @param[in] PrimaryAccessToken
 * A pointer to an access token, represented as an access token associated with the
 * primary calling process. This token describes the primary security context of the
 * main process.
 *
 * @param[in] IsTokenRestricted
 * If this parameter is set to TRUE, the function considers the token pointed by
 * AccessToken parameter argument as restricted. That is, the token has restricted
 * SIDs therefore the function will act accordingly against that token by checking
 * for restricted SIDs only when doing an equaility comparison check between the
 * two identifiers.
 *
 * @param[in] PrincipalSelfSid
 * A pointer to a security identifier that represents a principal. A principal
 * identifies a user object which is associated with its own security descriptor.
 *
 * @param[in] OwnerSid
 * The owner SID of the descriptor, which OWNER RIGHTS ACEs are checked as;
 * NULL if it has none (OWNER RIGHTS ACEs then apply to nobody).
 *
 * @param[in] GenericMapping
 * A pointer to a generic mapping that is associated with the object in question
 * being checked for access. If certain set of desired access rights have
 * a generic access right, this parameter is needed to map generic rights.
 *
 * @param[in,out] AccessCheckRights
 * A pointer to a structure that contains the access check rights. This function fills
 * up this structure with remaining, granted and denied rights to the caller for
 * access check. Henceforth, this parameter must not be NULL!
 *
 * @remarks
 * Without an object type list, as on Windows 10 (measured with NtAccessCheckByType
 * and no list, AccessCheckObjectTypeList apitest): an allowed object ACE with an
 * object type grants nothing, one without (no ACE_OBJECT_TYPE_PRESENT) grants as an
 * allow ACE; a denied object ACE denies as a deny ACE, with an object type or not.
 */
static
VOID
SepAnalyzeAcesFromDacl(
    _In_ ACCESS_CHECK_RIGHT_TYPE ActionType,
    _In_ ACCESS_MASK RemainingAccess,
    _In_ PACL Dacl,
    _In_ PACCESS_TOKEN AccessToken,
    _In_ PACCESS_TOKEN PrimaryAccessToken,
    _In_ BOOLEAN IsTokenRestricted,
    _In_opt_ PSID PrincipalSelfSid,
    _In_opt_ PSID OwnerSid,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Inout_ PACCESS_CHECK_RIGHTS AccessCheckRights)
{
    SEP_ACE_CURSOR Cursor;
    BOOLEAN Found;
    PACE CurrentAce;
    ULONG AceIndex;
    PSID Sid;
    ACCESS_MASK Access;
    BOOLEAN IsDenied;

    PAGED_CODE();

    /* These parameters are really needed */
    ASSERT(Dacl);
    ASSERT(AccessToken);

    /* TODO: To be removed once we support compound ACEs handling in Se */
    DBG_UNREFERENCED_PARAMETER(PrimaryAccessToken);

    if (ActionType == AccessCheckRegular)
    {
        /* Cache the remaining access rights to be addressed */
        ASSERT(RemainingAccess != 0);
        AccessCheckRights->RemainingAccessRights = RemainingAccess;
    }

    /*
     * Loop over the DACL in one pass: the cursor gives the ACE RtlGetAce gives
     * for each index (RtlGetAce itself starts over from the first ACE for every
     * index, quadratic in the ACE count). Where RtlGetAce fails (a bad revision,
     * an AceCount larger than the ACEs the ACL holds: an ACE at or beyond the
     * end of the ACL) the walk ends, in every build: the descriptor may come
     * from the disk unvalidated, so this is a malformed input like the others
     * here, not a broken invariant. An ACE that starts inside the ACL but does
     * not lie within it (SepAceWithinAcl) ends the walk too.
     */
    SepInitAceCursor(&Cursor, Dacl);
    for (AceIndex = 0; AceIndex < Dacl->AceCount; AceIndex++)
    {
        Found = SepNextAce(&Cursor, (PVOID*)&CurrentAce);
        if (!Found)
            break;

        if (!SepAceWithinAcl(&CurrentAce->Header, Cursor.End))
            break;

        if (CurrentAce->Header.AceFlags & INHERIT_ONLY_ACE)
            continue;

        switch (CurrentAce->Header.AceType)
        {
            case ACCESS_ALLOWED_ACE_TYPE:
                IsDenied = FALSE;
                break;

            case ACCESS_DENIED_ACE_TYPE:
                IsDenied = TRUE;
                break;

            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                /* Only for the object types of a list */
                if (SepGetObjectTypeGuidFromAce(CurrentAce, FALSE) != NULL)
                    continue;
                IsDenied = FALSE;
                break;

            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                /* Denies, with an object type or not */
                IsDenied = TRUE;
                break;

            default:
                DPRINT1("Unsupported ACE type 0x%lx\n", CurrentAce->Header.AceType);
                continue;
        }

        /* Get the SID from this ACE */
        Sid = SepGetSidFromAce(CurrentAce);
        ASSERT(Sid);

        if (!SepSidInTokenEx(AccessToken, PrincipalSelfSid, Sid, IsDenied, IsTokenRestricted))
        {
            /* An OWNER RIGHTS ACE is for the owner (looked at only when no SID matched) */
            if (OwnerSid == NULL ||
                !SepIsOwnerRightsSid(Sid) ||
                !SepSidInTokenEx(AccessToken, NULL, OwnerSid, IsDenied, IsTokenRestricted))
            {
                continue;
            }
        }

        /*
         * The ACE's mask as stored. Generic rights in it are not mapped: on
         * Windows (Server 2022, measured with every access check service) an
         * allow or deny ACE grants or denies nothing for GENERIC_READ/WRITE/
         * EXECUTE/ALL bits in its mask, and MAXIMUM_ALLOWED returns them as
         * they are. Generic rights are mapped when a descriptor is assigned
         * (SeAssignSecurity, inheritance) or set (SeSetSecurityDescriptorInfoEx,
         * RtlSetSecurityObject), so stored effective ACEs carry none.
         */
        Access = CurrentAce->AccessMask;

        if (ActionType == AccessCheckMaximum)
        {
            if (IsDenied)
            {
                /* Deny access rights that have not been granted yet */
                AccessCheckRights->DeniedAccessRights |= (Access & ~AccessCheckRights->GrantedAccessRights);
                DPRINT("DeniedAccessRights 0x%08lx\n", AccessCheckRights->DeniedAccessRights);
            }
            else
            {
                /* Grant access rights that have not been denied yet */
                AccessCheckRights->GrantedAccessRights |= (Access & ~AccessCheckRights->DeniedAccessRights);
                DPRINT("GrantedAccessRights 0x%08lx\n", AccessCheckRights->GrantedAccessRights);
            }
        }
        else if (IsDenied)
        {
            /*
             * The caller requests a right that cannot be
             * granted. Access is implicitly denied for
             * the calling thread. Track this access right.
             */
            if (AccessCheckRights->RemainingAccessRights & Access)
            {
                DPRINT("Refuted access 0x%08lx\n", Access);
                AccessCheckRights->DeniedAccessRights |= Access;
                break;
            }
        }
        else
        {
            /* Remove the remaining rights */
            DPRINT("RemainingAccessRights 0x%08lx  Access 0x%08lx\n", AccessCheckRights->RemainingAccessRights, Access);
            AccessCheckRights->RemainingAccessRights &= ~Access;
            DPRINT("RemainingAccessRights 0x%08lx\n", AccessCheckRights->RemainingAccessRights);

            /* Track the granted access right */
            AccessCheckRights->GrantedAccessRights |= Access;
        }
    }
}

/**
 * @brief
 * Private worker function that determines whether security access rights can be
 * givento the calling thread in order to access an object depending on the
 * security descriptor and other security context entities, such as an owner. This
 * function is the heart and brain of the whole access check algorithm in the kernel.
 *
 * @param[in] ClientAccessToken
 * A pointer to a client (thread) access token that requests access rights
 * of an object or subset of multiple objects.
 *
 * @param[in] PrimaryAccessToken
 * A pointer to a primary access token that describes the primary security
 * context of the main calling process.
 *
 * @param[in] PrincipalSelfSid
 * A pointer to a security identifier that represents a security principal,
 * that is, a user object associated with its security descriptor.
 *
 * @param[in] DesiredAccess
 * The access rights desired by the calling thread to acquire in order to
 * access an object.
 *
 * @param[in] ObjectTypeList
 * An array list of object types to be checked against for access. The function
 * will act accordingly in this case by checking each sub-object of an object
 * of primary level and such. If this parameter is NULL, the function will
 * perform a normal access check against the target object itself.
 *
 * @param[in] ObjectTypeListLength
 * The length of a object type list. Such length represents the number of
 * elements in this list.
 *
 * @param[in] PreviouslyGrantedAccess
 * The access rights previously acquired in the past. If this parameter is 0,
 * it is deemed that the calling thread hasn't acquired any rights. Access checks
 * are more tighten in this case.
 *
 * @param[in] GenericMapping
 * A pointer to a generic mapping of access rights of the target object.
 *
 * @param[in] AccessMode
 * The processor request level mode.
 *
 * @param[in] UseResultList
 * If set to TRUE, the function will return a list of granted access rights
 * of each sub-object as well as status code for each. If this parameter is
 * set to FALSE, then the function will just return only the granted access
 * rights and status code for single object that's been target for access
 * checks.
 *
 * @param[out] Privileges
 * A pointer to a definite set of privileges that have been audited
 * whilst doing access check procedures. Such set of privileges are
 * optionally returned to the caller. This can be set to NULL if
 * the caller doesn't want to obtain a set of privileges.
 *
 * @param[out] GrantedAccessList
 * A list of granted access rights returned to the caller. This list
 * can comprehend multiple elements which represent the sub-objects
 * that have been checked or a single element which is the target
 * object itself.
 *
 * @param[out] AccessStatusList
 * A list of access status codes returned to the caller. This list
 * can comprehend multiple elements which represent the sub-objects
 * that have been checked or a single element which is the target
 * object itself.
 *
 * @return
 * Returns TRUE if access onto the specific object is allowed, FALSE
 * otherwise.
 */
static
BOOLEAN
SepAccessCheckWorker(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PACCESS_TOKEN ClientAccessToken,
    _In_ PACCESS_TOKEN PrimaryAccessToken,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE_LIST_INTERNAL ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ ACCESS_MASK PreviouslyGrantedAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ BOOLEAN UseResultList,
    _Out_opt_ PPRIVILEGE_SET* Privileges,
    _Out_ PACCESS_MASK GrantedAccessList,
    _Out_ PNTSTATUS AccessStatusList)
{
    ACCESS_MASK RemainingAccess;
    ACCESS_MASK WantedRights;
    ACCESS_MASK MaskDesired;
    ACCESS_MASK GrantedRights = 0;
    ULONG ResultListIndex;
    ULONG ObjectTypeIndex;
    PACL Dacl;
    PSID OwnerSid;
    BOOLEAN Present;
    BOOLEAN Defaulted;
    NTSTATUS Status;
    PACCESS_TOKEN Token = NULL;
    ACCESS_CHECK_RIGHTS AccessCheckRights = {0};
    ACCESS_MASK RestrictedMask;
    BOOLEAN ResultListFilled = FALSE;

    PAGED_CODE();

    /* A security descriptor must be expected for access checks */
    ASSERT(SecurityDescriptor);

    /* Check for no access desired */
    if (!DesiredAccess)
    {
        /* Check if we had no previous access */
        if (!PreviouslyGrantedAccess)
        {
            /* Then there's nothing to give */
            DPRINT1("The caller has no previously granted access gained!\n");
            Status = STATUS_ACCESS_DENIED;
            goto ReturnCommonStatus;
        }

        /* Return the previous access only */
        Status = STATUS_SUCCESS;
        *Privileges = NULL;
        goto ReturnCommonStatus;
    }

    /* Map given accesses */
    RtlMapGenericMask(&DesiredAccess, GenericMapping);
    if (PreviouslyGrantedAccess)
        RtlMapGenericMask(&PreviouslyGrantedAccess, GenericMapping);

    /* Initialize remaining access rights */
    RemainingAccess = DesiredAccess;

    /*
     * Initialize the required rights if the caller wants to know access
     * for the object and each sub-object in the list.
     */
    if (UseResultList)
    {
        if (DesiredAccess & MAXIMUM_ALLOWED)
        {
            WantedRights = (DesiredAccess | PreviouslyGrantedAccess) & ~MAXIMUM_ALLOWED;
            MaskDesired = ~MAXIMUM_ALLOWED;
        }
        else
        {
            WantedRights = MaskDesired = DesiredAccess | PreviouslyGrantedAccess;
        }
    }

    /*
     * Obtain the token provided by the caller. Client (or also
     * called impersonation or thread) token takes precedence over
     * the primary token which is the token associated with the security
     * context of the main calling process. This is because it is the
     * client itself that requests access of an object or subset of
     * multiple objects. Otherwise obtain the security context of the
     * main process (the actual primary token).
     */
    Token = ClientAccessToken ? ClientAccessToken : PrimaryAccessToken;

    /*
     * We should at least expect a primary token
     * to be present if client token is not
     * available.
     */
    ASSERT(Token);

    /*
     * Check for ACCESS_SYSTEM_SECURITY and WRITE_OWNER access.
     * Write down a set of privileges that have been checked
     * if the caller wants it.
     */
    Status = SePrivilegePolicyCheck(&RemainingAccess,
                                    &PreviouslyGrantedAccess,
                                    NULL,
                                    Token,
                                    Privileges,
                                    AccessMode);
    if (!NT_SUCCESS(Status))
    {
        goto ReturnCommonStatus;
    }

    /* Succeed if there are no more rights to grant */
    if (RemainingAccess == 0)
    {
        Status = STATUS_SUCCESS;
        goto ReturnCommonStatus;
    }

    /*
     * HACK: Temporary hack that checks if the caller passed an empty
     * generic mapping. In such cases we cannot mask out the remaining
     * access rights without a proper mapping so the only option we
     * can do is to check if the client is an administrator,
     * since they are powerful users.
     *
     * See CORE-18576 for information.
     */
    if (GenericMapping->GenericRead == 0 &&
        GenericMapping->GenericWrite == 0 &&
        GenericMapping->GenericExecute == 0 &&
        GenericMapping->GenericAll == 0)
    {
        if (SeTokenIsAdmin(Token))
        {
            /* Grant him access */
            PreviouslyGrantedAccess |= RemainingAccess;
            Status = STATUS_SUCCESS;
            goto ReturnCommonStatus;
        }

        /* It's not an admin so bail out */
        PreviouslyGrantedAccess = 0;
        Status = STATUS_ACCESS_DENIED;
        goto ReturnCommonStatus;
    }

    /* Get the DACL */
    Status = RtlGetDaclSecurityDescriptor(SecurityDescriptor,
                                          &Present,
                                          &Dacl,
                                          &Defaulted);
    if (!NT_SUCCESS(Status))
    {
        goto ReturnCommonStatus;
    }

    /* Grant desired access if the object is unprotected */
    if (Present == FALSE || Dacl == NULL)
    {
        PreviouslyGrantedAccess |= RemainingAccess;
        if (RemainingAccess & MAXIMUM_ALLOWED)
        {
            PreviouslyGrantedAccess &= ~MAXIMUM_ALLOWED;
            PreviouslyGrantedAccess |= GenericMapping->GenericAll;
        }

        Status = STATUS_SUCCESS;
        goto ReturnCommonStatus;
    }

    /* Deny access if the DACL is empty */
    if (Dacl->AceCount == 0)
    {
        if (RemainingAccess == MAXIMUM_ALLOWED && PreviouslyGrantedAccess != 0)
        {
            Status = STATUS_SUCCESS;
        }
        else
        {
            DPRINT1("The DACL has no ACEs and the caller has no previously granted access!\n");
            PreviouslyGrantedAccess = 0;
            Status = STATUS_ACCESS_DENIED;
        }
        goto ReturnCommonStatus;
    }

    /* OWNER RIGHTS ACEs are checked as ACEs for the owner */
    OwnerSid = SepGetOwnerFromDescriptor(SecurityDescriptor);

    /*
     * With an object type list, work out the rights of every entry in the
     * list (SepAccessCheckObjectTypeList, for MAXIMUM_ALLOWED and explicit
     * requests alike) and report them for the root or for each entry.
     */
    if (ObjectTypeList && ObjectTypeListLength)
    {
        Status = SepAccessCheckObjectTypeList(Dacl,
                                              Token,
                                              PrincipalSelfSid,
                                              OwnerSid,
                                              GenericMapping,
                                              ObjectTypeList,
                                              ObjectTypeListLength);
        if (!NT_SUCCESS(Status))
        {
            PreviouslyGrantedAccess = 0;
            goto ReturnCommonStatus;
        }

        if (!UseResultList)
        {
            /*
             * The caller wants to know if access can be granted to the
             * object itself, that is the root of the list.
             */
            GrantedRights = ObjectTypeList[0].ObjectAccessRights.GrantedAccessRights;
            if (RemainingAccess & ~(MAXIMUM_ALLOWED | GrantedRights))
            {
                DPRINT("Failed to grant access rights to the object of the list, access denied. RemainingAccess = 0x%08lx  DesiredAccess = 0x%08lx\n",
                    RemainingAccess, DesiredAccess);
                PreviouslyGrantedAccess = 0;
                Status = STATUS_ACCESS_DENIED;
                goto ReturnCommonStatus;
            }

            /* MAXIMUM_ALLOWED gets all the rights of the root, an explicit request what it asked for */
            if (RemainingAccess & MAXIMUM_ALLOWED)
                PreviouslyGrantedAccess |= GrantedRights;
            else
                PreviouslyGrantedAccess |= RemainingAccess;

            if (PreviouslyGrantedAccess != 0)
            {
                Status = STATUS_SUCCESS;
            }
            else
            {
                DPRINT("Failed to grant access rights to the object of the list, access denied. PreviouslyGrantedAccess == 0  DesiredAccess = %08lx\n",
                    DesiredAccess);
                Status = STATUS_ACCESS_DENIED;
            }

            /* We are done here */
            goto ReturnCommonStatus;
        }

        /*
         * We have a list and the caller wants to know access for each
         * sub-object in the list. Report the access status and granted
         * rights for the object and each sub-object in the list (the
         * granted rights are reported even when they are not all the
         * rights asked for, as Windows does).
         */
        for (ObjectTypeIndex = 0;
             ObjectTypeIndex < ObjectTypeListLength;
             ObjectTypeIndex++)
        {
            /* Check if we have some rights */
            GrantedRights = (ObjectTypeList[ObjectTypeIndex].ObjectAccessRights.GrantedAccessRights | PreviouslyGrantedAccess) & MaskDesired;
            if (GrantedRights != 0)
            {
                /*
                 * If we still have some remaining rights to grant the ultimate
                 * conclusion is that the caller has no access to the object itself.
                 */
                RemainingAccess = (~GrantedRights & WantedRights);
                if (RemainingAccess != 0)
                {
                    DPRINT("Failed to grant access rights at specific object at index %lu, access denied. RemainingAccess = 0x%08lx  DesiredAccess = 0x%08lx\n",
                        ObjectTypeIndex, RemainingAccess, DesiredAccess);
                    AccessStatusList[ObjectTypeIndex] = STATUS_ACCESS_DENIED;
                }
                else
                {
                    AccessStatusList[ObjectTypeIndex] = STATUS_SUCCESS;
                }
            }
            else
            {
                /* No access is given */
                DPRINT("Failed to grant access rights at specific object at index %lu. No access is given\n", ObjectTypeIndex);
                AccessStatusList[ObjectTypeIndex] = STATUS_ACCESS_DENIED;
            }

            /* Return the access rights to the caller */
            GrantedAccessList[ObjectTypeIndex] = GrantedRights;
        }

        /*
         * We have built a list of access statuses for each object but
         * we still need to figure out the common status for the
         * function. The same status code will be used to check if
         * we should report any security debug stuff once we are done.
         */
        Status = STATUS_SUCCESS;
        for (ResultListIndex = 0; ResultListIndex < ObjectTypeListLength; ResultListIndex++)
        {
            /* There is at least one sub-object of which access cannot be granted */
            if (AccessStatusList[ResultListIndex] == STATUS_ACCESS_DENIED)
            {
                Status = AccessStatusList[ResultListIndex];
                break;
            }
        }

        /* We are done here */
        ResultListFilled = TRUE;
        goto ReturnCommonStatus;
    }

    /* Determine the MAXIMUM_ALLOWED access rights according to the DACL */
    if (DesiredAccess & MAXIMUM_ALLOWED)
    {
        /* Perform access checks against ACEs from this DACL */
        SepAnalyzeAcesFromDacl(AccessCheckMaximum,
                               0,
                               Dacl,
                               Token,
                               PrimaryAccessToken,
                               FALSE,
                               PrincipalSelfSid,
                               OwnerSid,
                               GenericMapping,
                               &AccessCheckRights);

        /*
         * A token with restricting SIDs gets only the rights that both the
         * normal and the restricting SIDs are granted: the restricted pass
         * gets rights of its own and the two sets are intersected (as for
         * the regular check, which runs the passes one after the other).
         * Adding the restricted pass to the same rights handed out the
         * union, e.g. the rights of an allow ACE for a SID that is not
         * in the restricting list (Windows 10 grants nothing there).
         */
        if (SepGetRestrictedAccessMask(Token, GenericMapping, &RestrictedMask))
        {
            ACCESS_CHECK_RIGHTS RestrictedRights = {0};

            SepAnalyzeAcesFromDacl(AccessCheckMaximum,
                                   0,
                                   Dacl,
                                   Token,
                                   PrimaryAccessToken,
                                   TRUE,
                                   PrincipalSelfSid,
                                   OwnerSid,
                                   GenericMapping,
                                   &RestrictedRights);

            /* A write restricted token keeps what the normal SIDs grant of the rights that are not write rights */
            AccessCheckRights.GrantedAccessRights &= (RestrictedRights.GrantedAccessRights | ~RestrictedMask);
        }

        /* Fail if some rights have not been granted */
        RemainingAccess &= ~(MAXIMUM_ALLOWED | AccessCheckRights.GrantedAccessRights);
        if (RemainingAccess != 0)
        {
            DPRINT("Failed to grant access rights, access denied. RemainingAccess = 0x%08lx  DesiredAccess = 0x%08lx\n", RemainingAccess, DesiredAccess);
            PreviouslyGrantedAccess = 0;
            Status = STATUS_ACCESS_DENIED;
            goto ReturnCommonStatus;
        }

        /* Set granted access right and access status */
        PreviouslyGrantedAccess |= AccessCheckRights.GrantedAccessRights;
        if (PreviouslyGrantedAccess != 0)
        {
            Status = STATUS_SUCCESS;
        }
        else
        {
            DPRINT("Failed to grant access rights, access denied. PreviouslyGrantedAccess == 0  DesiredAccess = %08lx\n", DesiredAccess);
            Status = STATUS_ACCESS_DENIED;
        }

        /* We are done here */
        goto ReturnCommonStatus;
    }

    /* Grant rights according to the DACL */
    SepAnalyzeAcesFromDacl(AccessCheckRegular,
                           RemainingAccess,
                           Dacl,
                           Token,
                           PrimaryAccessToken,
                           FALSE,
                           PrincipalSelfSid,
                           OwnerSid,
                           GenericMapping,
                           &AccessCheckRights);

    /* Fail if some rights have not been granted */
    if (AccessCheckRights.RemainingAccessRights != 0)
    {
        DPRINT("Failed to grant access rights, access denied. RemainingAccess = 0x%08lx  DesiredAccess = 0x%08lx\n", AccessCheckRights.RemainingAccessRights, DesiredAccess);
        PreviouslyGrantedAccess = 0;
        Status = STATUS_ACCESS_DENIED;
        goto ReturnCommonStatus;
    }

    /*
     * Perform further access checks if this token
     * has restricted SIDs.
     */
    if (SepGetRestrictedAccessMask(Token, GenericMapping, &RestrictedMask) &&
        (RemainingAccess & RestrictedMask) != 0)
    {
        SepAnalyzeAcesFromDacl(AccessCheckRegular,
                               RemainingAccess & RestrictedMask,
                               Dacl,
                               Token,
                               PrimaryAccessToken,
                               TRUE,
                               PrincipalSelfSid,
                               OwnerSid,
                               GenericMapping,
                               &AccessCheckRights);

        /* Fail if some rights have not been granted */
        if (AccessCheckRights.RemainingAccessRights != 0)
        {
            DPRINT("Failed to grant access rights, access denied. RemainingAccess = 0x%08lx  DesiredAccess = 0x%08lx\n", AccessCheckRights.RemainingAccessRights, DesiredAccess);
            PreviouslyGrantedAccess = 0;
            Status = STATUS_ACCESS_DENIED;
            goto ReturnCommonStatus;
        }
    }

    /* Set granted access rights */
    PreviouslyGrantedAccess |= DesiredAccess;

    /* Fail if no rights have been granted */
    if (PreviouslyGrantedAccess == 0)
    {
        DPRINT("Failed to grant access rights, access denied. PreviouslyGrantedAccess == 0  DesiredAccess = %08lx\n", DesiredAccess);
        Status = STATUS_ACCESS_DENIED;
        goto ReturnCommonStatus;
    }

    /*
     * If we're here then we granted all the desired
     * access rights the caller wanted.
     */
    Status = STATUS_SUCCESS;

ReturnCommonStatus:
    if (!UseResultList)
    {
        *GrantedAccessList = PreviouslyGrantedAccess;
        *AccessStatusList = Status;
    }
    else if (!ResultListFilled)
    {
        /* The result was decided before the per-object checks; it applies to every entry */
        for (ResultListIndex = 0; ResultListIndex < ObjectTypeListLength; ResultListIndex++)
        {
            GrantedAccessList[ResultListIndex] = PreviouslyGrantedAccess;
            AccessStatusList[ResultListIndex] = Status;
        }
    }

#if DBG
    /* Dump security debug info on access denied case */
    if (Status == STATUS_ACCESS_DENIED)
    {
        SepDumpSdDebugInfo(SecurityDescriptor);
        SepDumpTokenDebugInfo(Token);

        if (ObjectTypeList && (ObjectTypeListLength != 0))
        {
            SepDumpAccessAndStatusList(GrantedAccessList,
                                       AccessStatusList,
                                       UseResultList,
                                       ObjectTypeList,
                                       ObjectTypeListLength);
        }
        else
        {
            SepDumpAccessRightsStats(&AccessCheckRights);
        }
    }
#endif

    return NT_SUCCESS(Status);
}

/**
 * @brief
 * Retrieves the length size of a set list of privileges structure.
 *
 * @param[in] PrivilegeSet
 * A valid set of privileges.
 *
 * @return
 * Returns the total length of a set of privileges.
 */
static
ULONG
SepGetPrivilegeSetLength(
    _In_ PPRIVILEGE_SET PrivilegeSet)
{
    if (PrivilegeSet == NULL)
        return 0;

    if (PrivilegeSet->PrivilegeCount == 0)
        return (ULONG)(sizeof(PRIVILEGE_SET) - sizeof(LUID_AND_ATTRIBUTES));

    return (ULONG)(sizeof(PRIVILEGE_SET) +
                   (PrivilegeSet->PrivilegeCount - 1) * sizeof(LUID_AND_ATTRIBUTES));
}

/**
 * @brief
 * Gives one result to the object, or to every entry of the object
 * type list when the caller asked for a result list.
 *
 * @param[out] GrantedAccessList
 * Kernel buffer of one entry, or of ObjectTypeListLength entries
 * with UseResultList.
 *
 * @param[out] AccessStatusList
 * Kernel buffer of one entry, or of ObjectTypeListLength entries
 * with UseResultList.
 */
VOID
SepSetAccessCheckResults(
    _Out_writes_(UseResultList ? ObjectTypeListLength : 1) PACCESS_MASK GrantedAccessList,
    _Out_writes_(UseResultList ? ObjectTypeListLength : 1) PNTSTATUS AccessStatusList,
    _In_ BOOLEAN UseResultList,
    _In_ ULONG ObjectTypeListLength,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ NTSTATUS AccessStatus)
{
    ULONG ResultListIndex;
    ULONG ResultListLength = UseResultList ? ObjectTypeListLength : 1;

    for (ResultListIndex = 0; ResultListIndex < ResultListLength; ResultListIndex++)
    {
        GrantedAccessList[ResultListIndex] = GrantedAccess;
        AccessStatusList[ResultListIndex] = AccessStatus;
    }
}

/**
 * @brief
 * The access check of the NtAccessCheck* and the NtAccessCheck*AndAuditAlarm
 * system services, on input that the caller has already captured and
 * validated. Both families call this, so for the same descriptor, token,
 * request, object type list and mapping they give the same results.
 *
 * @param[in] CapturedSecurityDescriptor
 * The captured descriptor of the object; it has an owner and a group.
 *
 * @param[in] Token
 * The referenced token of the client. The function takes its lock.
 *
 * @param[in] PrimaryToken
 * The primary token of the caller (only a fallback of the worker).
 *
 * @param[in] CapturedPrincipalSelfSid
 * The captured principal self SID, or NULL.
 *
 * @param[in] DesiredAccess
 * The rights asked for, with no generic rights and without the rights
 * that SePrivilegePolicyCheck has granted already.
 *
 * @param[in] PreviouslyGrantedAccess
 * The rights that SePrivilegePolicyCheck has granted.
 *
 * @param[in] CapturedObjectTypeList
 * The captured object type list, or NULL.
 *
 * @param[in] ObjectTypeListLength
 * The number of entries of the list (not 0 with UseResultList).
 *
 * @param[in] CapturedGenericMapping
 * The captured generic mapping.
 *
 * @param[in] UseResultList
 * TRUE for a result per entry of the list.
 *
 * @param[out] GrantedAccessList
 * Kernel buffer for the granted rights (one entry, or one per list entry).
 *
 * @param[out] AccessStatusList
 * Kernel buffer for the access status (one entry, or one per list entry).
 */
VOID
SepAccessCheckCaptured(
    _In_ PSECURITY_DESCRIPTOR CapturedSecurityDescriptor,
    _In_ PTOKEN Token,
    _In_ PACCESS_TOKEN PrimaryToken,
    _In_opt_ PSID CapturedPrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK PreviouslyGrantedAccess,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST_INTERNAL CapturedObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING CapturedGenericMapping,
    _In_ BOOLEAN UseResultList,
    _Out_writes_(UseResultList ? ObjectTypeListLength : 1) PACCESS_MASK GrantedAccessList,
    _Out_writes_(UseResultList ? ObjectTypeListLength : 1) PNTSTATUS AccessStatusList)
{
    ACCESS_MASK MandatoryAllowed, AppContainerAllowed;
    ULONG ResultIndex, LabelLevel;

    PAGED_CODE();

    ASSERT(CapturedSecurityDescriptor != NULL);
    ASSERT(Token != NULL);
    ASSERT(!UseResultList || (CapturedObjectTypeList != NULL && ObjectTypeListLength != 0));

    /* Lock the token */
    SepAcquireTokenLockShared(Token);

    /*
     * The mandatory label first: a client below the level of the object is
     * denied every right it asks for that the label does not leave it, also
     * one a privilege granted, whatever the DACL says
     */
    MandatoryAllowed = SepMandatoryAllowedAccess(Token, CapturedSecurityDescriptor, CapturedGenericMapping, &LabelLevel);
    if (MandatoryAllowed != MAXULONG && LabelLevel <= SECURITY_MANDATORY_MEDIUM_RID)
    {
        /*
         * What the descriptor grants the package SID of a lowbox token itself is not held back by the label
         * (Windows: an AppContainer writes the storage key of its package, which has no label, through its
         * package SID's entry; the other SIDs of the pass, ALL APPLICATION PACKAGES and the capabilities, do
         * not lift the label). Only for a label of Medium or below: measured on Windows Server 2022, a lowbox
         * token is granted what the package ACE and the user's ACE allow with no label, a Low and a Medium
         * label, and nothing with a High one
         */
        ACCESS_MASK PackageGranted = SepAppContainerAllowedAccess(Token, CapturedSecurityDescriptor, TRUE);

        if (PackageGranted != MAXULONG)
            MandatoryAllowed |= PackageGranted;
    }
    if (MandatoryAllowed != MAXULONG &&
        ((DesiredAccess | PreviouslyGrantedAccess) & ~(MAXIMUM_ALLOWED | MandatoryAllowed)) != 0)
    {
        SepSetAccessCheckResults(GrantedAccessList,
                                 AccessStatusList,
                                 UseResultList,
                                 ObjectTypeListLength,
                                 0,
                                 STATUS_ACCESS_DENIED);
        SepReleaseTokenLock(Token);
        return;
    }

    /*
     * The AppContainer pass of a lowbox token (SepAppContainerAllowedAccess): a right it does not
     * grant is refused, as the label's, before the owner's implicit rights and the DACL count
     */
    AppContainerAllowed = SepAppContainerAllowedAccess(Token, CapturedSecurityDescriptor, FALSE);
    if (AppContainerAllowed != MAXULONG)
    {
        ACCESS_MASK MappedAccess = DesiredAccess | PreviouslyGrantedAccess;

        RtlMapGenericMask(&MappedAccess, CapturedGenericMapping);
        if (MappedAccess & ~(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY | AppContainerAllowed))
        {
            SepSetAccessCheckResults(GrantedAccessList,
                                     AccessStatusList,
                                     UseResultList,
                                     ObjectTypeListLength,
                                     0,
                                     STATUS_ACCESS_DENIED);
            SepReleaseTokenLock(Token);
            return;
        }
    }

    /*
     * Check if the token is the owner and grant WRITE_DAC and READ_CONTROL rights,
     * unless the DACL has an OWNER RIGHTS ACE for the object
     */
    if (DesiredAccess & (WRITE_DAC | READ_CONTROL | MAXIMUM_ALLOWED))
    {
        if (SepTokenGetsImplicitOwnerRights(Token, CapturedSecurityDescriptor))
        {
            if (DesiredAccess & MAXIMUM_ALLOWED)
                PreviouslyGrantedAccess |= (WRITE_DAC | READ_CONTROL);
            else
                PreviouslyGrantedAccess |= (DesiredAccess & (WRITE_DAC | READ_CONTROL));

            DesiredAccess &= ~(WRITE_DAC | READ_CONTROL);
        }
    }

    if (DesiredAccess == 0)
    {
        /*
         * Nothing is left to check: the rights granted already (privileges,
         * the implicit owner rights) are the result, for the whole hierarchy
         * of the list or just the target object. A request for no rights at
         * all grants nothing and is denied, as SeAccessCheck does: measured on
         * Windows Server 2022, NtAccessCheck, NtAccessCheckByType and
         * NtAccessCheckByTypeResultList and their audit alarm forms with a
         * DesiredAccess of 0 succeed with the access status
         * STATUS_ACCESS_DENIED and nothing granted, for every descriptor and
         * client token (2,240 rows), and every object open with an access of
         * 0 (NtOpenEvent, NtOpenKey, NtOpenFile and the others) is refused.
         */
        SepSetAccessCheckResults(GrantedAccessList,
                                 AccessStatusList,
                                 UseResultList,
                                 ObjectTypeListLength,
                                 PreviouslyGrantedAccess,
                                 PreviouslyGrantedAccess ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
    }
    else
    {
        /* Now perform the access check */
        SepAccessCheckWorker(CapturedSecurityDescriptor,
                             Token,
                             PrimaryToken,
                             CapturedPrincipalSelfSid,
                             DesiredAccess,
                             CapturedObjectTypeList,
                             ObjectTypeListLength,
                             PreviouslyGrantedAccess,
                             CapturedGenericMapping,
                             UserMode,
                             UseResultList,
                             NULL,
                             GrantedAccessList,
                             AccessStatusList);
    }

    /* MAXIMUM_ALLOWED: what the DACL grants, within what the label leaves */
    if (MandatoryAllowed != MAXULONG && (DesiredAccess & MAXIMUM_ALLOWED))
    {
        for (ResultIndex = 0; ResultIndex < (UseResultList ? ObjectTypeListLength : 1); ResultIndex++)
        {
            GrantedAccessList[ResultIndex] &= MandatoryAllowed;
            if (AccessStatusList[ResultIndex] == STATUS_SUCCESS && GrantedAccessList[ResultIndex] == 0)
                AccessStatusList[ResultIndex] = STATUS_ACCESS_DENIED;
        }
    }

    /* MAXIMUM_ALLOWED of a lowbox token: within what the AppContainer pass grants (the owner's rights too) */
    if (AppContainerAllowed != MAXULONG && (DesiredAccess & MAXIMUM_ALLOWED))
    {
        for (ResultIndex = 0; ResultIndex < (UseResultList ? ObjectTypeListLength : 1); ResultIndex++)
        {
            GrantedAccessList[ResultIndex] &= AppContainerAllowed | ACCESS_SYSTEM_SECURITY;
            if (AccessStatusList[ResultIndex] == STATUS_SUCCESS && GrantedAccessList[ResultIndex] == 0)
                AccessStatusList[ResultIndex] = STATUS_ACCESS_DENIED;
        }
    }

    /* Unlock the token */
    SepReleaseTokenLock(Token);
}

/**
 * @brief
 * Internal function that performs a security check against the
 * client who requests access on a resource object. This function
 * is used by access check NT system calls.
 *
 * @param[in] SecurityDescriptor
 * A pointer to a security descriptor that identifies the security
 * information of an object being accessed. This function walks
 * through this descriptor for any ACLs and respective access
 * rights if access can be granted.
 *
 * @param[in] ClientToken
 * A handle to an access token, that identifies the client of which
 * requests access to the target object.
 *
 * @param[in] PrincipalSelfSid
 * A pointer to a principal self SID. This parameter can be NULL if
 * the associated object being checked for access does not represent
 * a principal.
 *
 * @param[in] DesiredAccess
 * The access right bitmask where the client wants to acquire. This
 * can be an OR'ed set of multiple access rights or MAXIMUM_ALLOWED
 * to request all of possible access rights the target object allows.
 * If only some rights were granted but not all the access is deemed
 * as denied.
 *
 * @param[in] GenericMapping
 * The generic mapping of access rights of an object type.
 *
 * @param[out] PrivilegeSet
 * A pointer to a set of privileges that were used to perform the
 * access check, returned to caller. This function will return no
 * privileges (privilege count set to 0) if no privileges were used
 * to accomplish the access check. This parameter must not be NULL!
 *
 * @param[in,out] PrivilegeSetLength
 * The total length size of a set of privileges. This length represents
 * the count of elements in the privilege set array.
 *
 * @param[in] ObjectTypeList
 * A pointer to a given object type list. If this parameter is not NULL
 * the function will perform an access check against the main object
 * and sub-objects of this list. If this parameter is NULL and
 * ObjectTypeListLength is 0, the function will perform a normal
 * access check instead.
 *
 * @param[in] ObjectTypeListLength
 * The length of the object type list array, pointed by ObjectTypeList.
 * This length in question represents the number of elements in such array.
 * This parameter must be 0 if no array list is provided.
 *
 * @param[in] UseResultList
 * If this parameter is set to TRUE, the function will return the GrantedAccess
 * and AccessStatus parameter as arrays of granted rights and status value for
 * each individual object element pointed by ObjectTypeList.
 *
 * @param[out] GrantedAccess
 * A pointer to granted access rights, returned to the caller. If ObjectTypeList
 * is not NULL this paramater is an array of granted access rights for the object
 * and each individual sub-object of the list.
 *
 * @param[out] AccessStatus
 * A pointer to a status code, returned to the caller. This status code
 * represents whether access is granted or denied to the client on the
 * target object. The difference between the status code of the function
 * is that code indicates whether the function has successfully completed
 * the access check operation. If ObjectTypeList is not NULL, this
 * parameter is an array of access status for the object and each individual
 * sub-object of the list.
 *
 * @return
 * Returns STATUS_SUCCESS if access check has been done without problems
 * and that the object can be accessed. STATUS_GENERIC_NOT_MAPPED is returned
 * if no generic access right is mapped. STATUS_NO_IMPERSONATION_TOKEN is returned
 * if the token from the handle is not an impersonation token.
 * STATUS_BAD_IMPERSONATION_LEVEL is returned if the token cannot be impersonated
 * because the current security impersonation level doesn't permit so.
 * STATUS_INVALID_SECURITY_DESCR is returned if the security descriptor given
 * to the call is not a valid one. STATUS_BUFFER_TOO_SMALL is returned if
 * the buffer to the captured privileges has a length that is less than the required
 * size of the set of privileges. STATUS_INVALID_PARAMETER is returned if the caller
 * did not provide an object type list but the caller wanted to invoke an object type
 * result list access check, or if the list is out of order or the list is invalid.
 * A failure NTSTATUS code is returned otherwise.
 *
 * @remarks
 * The function performs an access check against the object type list,
 * if provided, depending on the UseResultList parameter. That is, if that
 * parameter was set to TRUE the function will either grant or deny access
 * to each individual sub-object and return an array of access status and
 * granted rights for the corresponding object type list. Otherwise the function
 * will grant or deny access to the object type list hierarchy as a whole.
 */
static
NTSTATUS
SepAccessCheck(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ HANDLE ClientToken,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ BOOLEAN UseResultList,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus)
{
    PSECURITY_DESCRIPTOR CapturedSecurityDescriptor = NULL;
    POBJECT_TYPE_LIST_INTERNAL CapturedObjectTypeList = NULL;
    PSID CapturedPrincipalSelfSid = NULL;
    SECURITY_SUBJECT_CONTEXT SubjectSecurityContext;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    ACCESS_MASK PreviouslyGrantedAccess = 0;
    PPRIVILEGE_SET Privileges = NULL;
    ULONG CapturedPrivilegeSetLength, RequiredPrivilegeSetLength;
    PTOKEN Token = NULL;
    NTSTATUS Status;
    GENERIC_MAPPING CapturedGenericMapping = {0};
    PACCESS_MASK ResultGrantedAccess;
    PNTSTATUS ResultAccessStatus;
    ACCESS_MASK SingleGrantedAccess = 0;
    NTSTATUS SingleAccessStatus = STATUS_ACCESS_DENIED;
    BOOLEAN SubjectContextCaptured = FALSE;
    BOOLEAN IsPseudoHandle = FALSE;
    BOOLEAN OutputAccessResults = FALSE;
    BOOLEAN WriteRequiredLength = FALSE;
    NTSTATUS FunctionStatus = STATUS_SUCCESS;

    PAGED_CODE();

    /* Check if this is kernel mode */
    if (PreviousMode == KernelMode)
    {
        /* Check if kernel wants everything */
        if (DesiredAccess & MAXIMUM_ALLOWED)
        {
            /* Give it */
            *GrantedAccess = GenericMapping->GenericAll;
            *GrantedAccess |= (DesiredAccess &~ MAXIMUM_ALLOWED);
        }
        else
        {
            /* Just give the desired access */
            *GrantedAccess = DesiredAccess;
        }

        /* Success */
        *AccessStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    /* Protect probe in SEH */
    _SEH2_TRY
    {
        /* Probe all pointers */
        ProbeForRead(GenericMapping, sizeof(GENERIC_MAPPING), sizeof(ULONG));
        ProbeForRead(PrivilegeSetLength, sizeof(ULONG), sizeof(ULONG));
        CapturedPrivilegeSetLength = *PrivilegeSetLength;
        ProbeForWrite(PrivilegeSet, CapturedPrivilegeSetLength, sizeof(ULONG));

        /*
         * Probe the access and status list based on the way
         * we are going to fill data in.
         */
        if (UseResultList)
        {
            /* Bail out on an empty list */
            if (!ObjectTypeListLength)
            {
                DPRINT1("The object type list is empty\n");
                _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
            }

            ProbeForWrite(GrantedAccess, sizeof(ACCESS_MASK) * ObjectTypeListLength, sizeof(ULONG));
            ProbeForWrite(AccessStatus, sizeof(NTSTATUS) * ObjectTypeListLength, sizeof(ULONG));
        }
        else
        {
            ProbeForWrite(GrantedAccess, sizeof(ACCESS_MASK), sizeof(ULONG));
            ProbeForWrite(AccessStatus, sizeof(NTSTATUS), sizeof(ULONG));
        }

        /* Capture the mapping */
        CapturedGenericMapping = *GenericMapping;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Return the exception code */
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Check for unmapped access rights */
    if (DesiredAccess & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL))
    {
        DPRINT1("Some generic rights are not mapped\n");
        return STATUS_GENERIC_NOT_MAPPED;
    }

    /* Reference the token */
    Status = SepReferenceTokenHandle(ClientToken,
                                     TOKEN_QUERY,
                                     PreviousMode,
                                     &Token,
                                     &IsPseudoHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to reference token (Status 0x%08lx)\n", Status);
        return Status;
    }

    /*
     * A real handle must name an impersonation token. The token pseudo
     * handles are the exception (as on Windows 10): the primary token
     * they resolve to is checked as it is, with no impersonation level.
     */
    if (Token->TokenType != TokenImpersonation && !IsPseudoHandle)
    {
        DPRINT("No impersonation token\n");
        ObDereferenceObject(Token);
        return STATUS_NO_IMPERSONATION_TOKEN;
    }

    /* Check the impersonation level */
    if (Token->TokenType == TokenImpersonation &&
        Token->ImpersonationLevel < SecurityIdentification)
    {
        DPRINT1("Impersonation level < SecurityIdentification\n");
        ObDereferenceObject(Token);
        return STATUS_BAD_IMPERSONATION_LEVEL;
    }

    /* Capture the object type list, the list is probed by the function itself */
    Status = SeCaptureObjectTypeList(ObjectTypeList,
                                     ObjectTypeListLength,
                                     PreviousMode,
                                     &CapturedObjectTypeList);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to capture the object type list (Status 0x%08lx)\n", Status);
        ObDereferenceObject(Token);
        return Status;
    }

    /* Results are computed in kernel memory and copied out under SEH at the end */
    if (UseResultList)
    {
        ResultGrantedAccess = ExAllocatePoolWithTag(PagedPool,
                                                    sizeof(ACCESS_MASK) * ObjectTypeListLength,
                                                    TAG_SE);
        ResultAccessStatus = ExAllocatePoolWithTag(PagedPool,
                                                   sizeof(NTSTATUS) * ObjectTypeListLength,
                                                   TAG_SE);
        if (ResultGrantedAccess == NULL || ResultAccessStatus == NULL)
        {
            if (ResultGrantedAccess != NULL)
                ExFreePoolWithTag(ResultGrantedAccess, TAG_SE);
            if (ResultAccessStatus != NULL)
                ExFreePoolWithTag(ResultAccessStatus, TAG_SE);
            SeReleaseObjectTypeList(CapturedObjectTypeList, PreviousMode);
            ObDereferenceObject(Token);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        ResultGrantedAccess = &SingleGrantedAccess;
        ResultAccessStatus = &SingleAccessStatus;
    }

    /* Check for ACCESS_SYSTEM_SECURITY and WRITE_OWNER access */
    Status = SePrivilegePolicyCheck(&DesiredAccess,
                                    &PreviouslyGrantedAccess,
                                    NULL,
                                    Token,
                                    &Privileges,
                                    PreviousMode);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SePrivilegePolicyCheck failed (Status 0x%08lx)\n", Status);

        /*
         * A client below the integrity level of the object is denied access
         * before its privileges count (ACCESS_SYSTEM_SECURITY without
         * SeSecurityPrivilege: access denied, measured). The descriptor is
         * captured for that only; when it cannot be, the result stays as it was.
         */
        if (Status == STATUS_PRIVILEGE_NOT_HELD &&
            NT_SUCCESS(SeCaptureSecurityDescriptor(SecurityDescriptor,
                                                   PreviousMode,
                                                   PagedPool,
                                                   FALSE,
                                                   &CapturedSecurityDescriptor)))
        {
            if (CapturedSecurityDescriptor != NULL &&
                SepMandatoryAccessDenied(Token,
                                         CapturedSecurityDescriptor,
                                         DesiredAccess,
                                         &CapturedGenericMapping))
            {
                Status = STATUS_ACCESS_DENIED;
            }

            /* Cleanup releases it */
        }

        /*
         * The caller does not have the required access to do an access check.
         * Propagate the access and status for the whole hierarchy of the list
         * or just to single target object.
         */
        SepSetAccessCheckResults(ResultGrantedAccess,
                                 ResultAccessStatus,
                                 UseResultList,
                                 ObjectTypeListLength,
                                 0,
                                 Status);

        OutputAccessResults = TRUE;
        FunctionStatus = STATUS_SUCCESS;
        goto Cleanup;
    }

    /* Check the size of the privilege set and return the privileges */
    if (Privileges != NULL)
    {
        DPRINT("Privileges != NULL\n");

        /* Calculate the required privilege set buffer size */
        RequiredPrivilegeSetLength = SepGetPrivilegeSetLength(Privileges);

        /* Fail if the privilege set buffer is too small */
        if (CapturedPrivilegeSetLength < RequiredPrivilegeSetLength)
        {
            WriteRequiredLength = TRUE;
            FunctionStatus = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        /* Copy the privilege set to the caller */
        _SEH2_TRY
        {
            RtlCopyMemory(PrivilegeSet,
                          Privileges,
                          RequiredPrivilegeSetLength);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            FunctionStatus = _SEH2_GetExceptionCode();
            _SEH2_YIELD(goto Cleanup);
        }
        _SEH2_END;

        /* Free the local privilege set */
        SeFreePrivileges(Privileges);
        Privileges = NULL;
    }
    else
    {
        DPRINT("Privileges == NULL\n");

        /* Fail if the privilege set buffer is too small */
        if (CapturedPrivilegeSetLength < sizeof(PRIVILEGE_SET))
        {
            RequiredPrivilegeSetLength = sizeof(PRIVILEGE_SET);
            WriteRequiredLength = TRUE;
            FunctionStatus = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        /* Initialize the privilege set */
        _SEH2_TRY
        {
            PrivilegeSet->PrivilegeCount = 0;
            PrivilegeSet->Control = 0;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            FunctionStatus = _SEH2_GetExceptionCode();
            _SEH2_YIELD(goto Cleanup);
        }
        _SEH2_END;
    }

    /* Capture the security descriptor */
    Status = SeCaptureSecurityDescriptor(SecurityDescriptor,
                                         PreviousMode,
                                         PagedPool,
                                         FALSE,
                                         &CapturedSecurityDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to capture the Security Descriptor\n");
        FunctionStatus = Status;
        goto Cleanup;
    }

    /* Check the captured security descriptor */
    if (CapturedSecurityDescriptor == NULL)
    {
        DPRINT1("Security Descriptor is NULL\n");
        FunctionStatus = STATUS_INVALID_SECURITY_DESCR;
        goto Cleanup;
    }

    /* Check security descriptor for valid owner and group */
    if (SepGetOwnerFromDescriptor(CapturedSecurityDescriptor) == NULL ||
        SepGetGroupFromDescriptor(CapturedSecurityDescriptor) == NULL)
    {
        DPRINT1("Security Descriptor does not have a valid group or owner\n");
        FunctionStatus = STATUS_INVALID_SECURITY_DESCR;
        goto Cleanup;
    }

    /* Capture the principal self SID if we have one */
    if (PrincipalSelfSid)
    {
        Status = SepCaptureSid(PrincipalSelfSid,
                               PreviousMode,
                               PagedPool,
                               TRUE,
                               &CapturedPrincipalSelfSid);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to capture the principal self SID (Status 0x%08lx)\n", Status);
            FunctionStatus = Status;
            goto Cleanup;
        }
    }

    /* The primary token is only a fallback of the worker; the client token is always given */
    SeCaptureSubjectContext(&SubjectSecurityContext);
    SubjectContextCaptured = TRUE;

    /* Now perform the access check (the access check and audit alarm services share this) */
    SepAccessCheckCaptured(CapturedSecurityDescriptor,
                           Token,
                           SubjectSecurityContext.PrimaryToken,
                           CapturedPrincipalSelfSid,
                           DesiredAccess,
                           PreviouslyGrantedAccess,
                           CapturedObjectTypeList,
                           ObjectTypeListLength,
                           &CapturedGenericMapping,
                           UseResultList,
                           ResultGrantedAccess,
                           ResultAccessStatus);

    OutputAccessResults = TRUE;
    FunctionStatus = STATUS_SUCCESS;

Cleanup:
    /* Release the subject context */
    if (SubjectContextCaptured)
        SeReleaseSubjectContext(&SubjectSecurityContext);

    /* Release the caputed principal self SID */
    SepReleaseSid(CapturedPrincipalSelfSid,
                  PreviousMode,
                  TRUE);

    /* Release the captured security descriptor */
    SeReleaseSecurityDescriptor(CapturedSecurityDescriptor,
                                PreviousMode,
                                FALSE);

    /* Free the local privilege set if it is still held */
    if (Privileges != NULL)
        SeFreePrivileges(Privileges);

    /* Release the object type list */
    SeReleaseObjectTypeList(CapturedObjectTypeList, PreviousMode);

    /* The caller's pages may have changed since the probe */
    _SEH2_TRY
    {
        if (OutputAccessResults)
        {
            if (UseResultList)
            {
                RtlCopyMemory(GrantedAccess,
                              ResultGrantedAccess,
                              sizeof(ACCESS_MASK) * ObjectTypeListLength);
                RtlCopyMemory(AccessStatus,
                              ResultAccessStatus,
                              sizeof(NTSTATUS) * ObjectTypeListLength);
            }
            else
            {
                *GrantedAccess = SingleGrantedAccess;
                *AccessStatus = SingleAccessStatus;
            }
        }
        else if (WriteRequiredLength)
        {
            *PrivilegeSetLength = RequiredPrivilegeSetLength;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        FunctionStatus = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    /* Free the result storage */
    if (UseResultList)
    {
        ExFreePoolWithTag(ResultGrantedAccess, TAG_SE);
        ExFreePoolWithTag(ResultAccessStatus, TAG_SE);
    }

    /* Dereference the token */
    ObDereferenceObject(Token);

    return FunctionStatus;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/**
 * @brief
 * Determines whether security access rights can be given to an object
 * depending on the security descriptor and other security context
 * entities, such as an owner.
 *
 * @param[in] SecurityDescriptor
 * Security descriptor of the object that is being accessed.
 *
 * @param[in] SubjectSecurityContext
 * The captured subject security context.
 *
 * @param[in] SubjectContextLocked
 * If set to TRUE, the caller acknowledges that the subject context
 * has already been locked by the caller himself. If set to FALSE,
 * the function locks the subject context.
 *
 * @param[in] DesiredAccess
 * Access right bitmask that the calling thread wants to acquire.
 *
 * @param[in] PreviouslyGrantedAccess
 * The access rights previously acquired in the past.
 *
 * @param[out] Privileges
 * The returned set of privileges.
 *
 * @param[in] GenericMapping
 * The generic mapping of access rights of an object type.
 *
 * @param[in] AccessMode
 * The processor request level mode.
 *
 * @param[out] GrantedAccess
 * A list of granted access rights.
 *
 * @param[out] AccessStatus
 * The returned status code specifying why access cannot be made
 * onto an object (if said access is denied in the first place).
 *
 * @return
 * Returns TRUE if access onto the specific object is allowed, FALSE
 * otherwise.
 */
BOOLEAN
NTAPI
SeAccessCheck(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PSECURITY_SUBJECT_CONTEXT SubjectSecurityContext,
    _In_ BOOLEAN SubjectContextLocked,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK PreviouslyGrantedAccess,
    _Out_ PPRIVILEGE_SET* Privileges,
    _In_ PGENERIC_MAPPING GenericMapping,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus)
{
    ACCESS_MASK MandatoryAllowed, MappedAccess, CallerGrantedAccess;
    ULONG LabelLevel;
    ACCESS_MASK AppContainerAllowed, AppContainerCallerGranted;
    PACCESS_TOKEN Token;
    BOOLEAN ret;

    PAGED_CODE();

    /* Check if this is kernel mode */
    if (AccessMode == KernelMode)
    {
        /* Check if kernel wants everything */
        if (DesiredAccess & MAXIMUM_ALLOWED)
        {
            /* Give it */
            *GrantedAccess = GenericMapping->GenericAll;
            *GrantedAccess |= (DesiredAccess &~ MAXIMUM_ALLOWED);
            *GrantedAccess |= PreviouslyGrantedAccess;
        }
        else
        {
            /* Give the desired and previous access */
            *GrantedAccess = DesiredAccess | PreviouslyGrantedAccess;
        }

        /* Success */
        *AccessStatus = STATUS_SUCCESS;
        return TRUE;
    }

    /* Check if we didn't get an SD */
    if (!SecurityDescriptor)
    {
        /* Automatic failure */
        *AccessStatus = STATUS_ACCESS_DENIED;
        return FALSE;
    }

    /* Check for invalid impersonation */
    if ((SubjectSecurityContext->ClientToken) &&
        (SubjectSecurityContext->ImpersonationLevel < SecurityImpersonation))
    {
        *AccessStatus = STATUS_BAD_IMPERSONATION_LEVEL;
        return FALSE;
    }

    /* Acquire the lock if needed */
    if (!SubjectContextLocked)
        SeLockSubjectContext(SubjectSecurityContext);

    Token = SubjectSecurityContext->ClientToken ?
            SubjectSecurityContext->ClientToken : SubjectSecurityContext->PrimaryToken;

    /*
     * The mandatory label first, with the rule of the access check services
     * (SepMandatoryAllowedAccess, measured there): a subject below the level
     * of the object is refused every right it asks for that the label does
     * not leave it, before the owner's implicit rights, the privileges and
     * the DACL count. The rights the caller passes as granted already (a
     * privilege the caller checked itself, such as SeDebugPrivilege for a
     * process open or a backup open of a file) are the caller's decision and
     * stay granted. MAXIMUM_ALLOWED gets the DACL's rights within the label's.
     */
    ASSERT(Token != NULL);
    MandatoryAllowed = SepMandatoryAllowedAccess(Token, SecurityDescriptor, GenericMapping, &LabelLevel);
    CallerGrantedAccess = 0;
    if (MandatoryAllowed != MAXULONG && LabelLevel <= SECURITY_MANDATORY_MEDIUM_RID)
    {
        /* What the descriptor grants the package SID of a lowbox token itself is not held back by the label (see SepAccessCheckCaptured) */
        ACCESS_MASK PackageGranted = SepAppContainerAllowedAccess((PTOKEN)Token, SecurityDescriptor, TRUE);

        if (PackageGranted != MAXULONG)
            MandatoryAllowed |= PackageGranted;
    }
    if (MandatoryAllowed != MAXULONG)
    {
        CallerGrantedAccess = PreviouslyGrantedAccess;
        RtlMapGenericMask(&CallerGrantedAccess, GenericMapping);
        MappedAccess = DesiredAccess;
        RtlMapGenericMask(&MappedAccess, GenericMapping);
        if (MappedAccess & ~(MAXIMUM_ALLOWED | MandatoryAllowed))
        {
            *GrantedAccess = 0;
            *AccessStatus = STATUS_ACCESS_DENIED;
            if (!SubjectContextLocked)
                SeUnlockSubjectContext(SubjectSecurityContext);
            return FALSE;
        }
    }

    /*
     * The AppContainer pass of a lowbox token (SepAppContainerAllowedAccess), with the same rule:
     * a right it does not grant is refused first; the rights the caller grants itself stay
     */
    AppContainerAllowed = SepAppContainerAllowedAccess((PTOKEN)Token, SecurityDescriptor, FALSE);
    AppContainerCallerGranted = 0;
    if (AppContainerAllowed != MAXULONG)
    {
        AppContainerCallerGranted = PreviouslyGrantedAccess;
        RtlMapGenericMask(&AppContainerCallerGranted, GenericMapping);
        MappedAccess = DesiredAccess;
        RtlMapGenericMask(&MappedAccess, GenericMapping);
        if (MappedAccess & ~(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY | AppContainerAllowed))
        {
            *GrantedAccess = 0;
            *AccessStatus = STATUS_ACCESS_DENIED;
            if (!SubjectContextLocked)
                SeUnlockSubjectContext(SubjectSecurityContext);
            return FALSE;
        }
    }

    /*
     * Check if the token is the owner and grant WRITE_DAC and READ_CONTROL rights,
     * unless the DACL has an OWNER RIGHTS ACE for the object
     */
    if (DesiredAccess & (WRITE_DAC | READ_CONTROL | MAXIMUM_ALLOWED))
    {
        if (SepTokenGetsImplicitOwnerRights(Token, SecurityDescriptor))
        {
            if (DesiredAccess & MAXIMUM_ALLOWED)
                PreviouslyGrantedAccess |= (WRITE_DAC | READ_CONTROL);
            else
                PreviouslyGrantedAccess |= (DesiredAccess & (WRITE_DAC | READ_CONTROL));

            DesiredAccess &= ~(WRITE_DAC | READ_CONTROL);
        }
    }

    if (DesiredAccess == 0)
    {
        *GrantedAccess = PreviouslyGrantedAccess;
        if (PreviouslyGrantedAccess == 0)
        {
            DPRINT1("Request for zero access to an object. Denying.\n");
            *AccessStatus = STATUS_ACCESS_DENIED;
            ret = FALSE;
        }
        else
        {
            *AccessStatus = STATUS_SUCCESS;
            ret = TRUE;
        }
    }
    else
    {
        /* Call the internal function */
        ret = SepAccessCheckWorker(SecurityDescriptor,
                                   SubjectSecurityContext->ClientToken,
                                   SubjectSecurityContext->PrimaryToken,
                                   NULL,
                                   DesiredAccess,
                                   NULL,
                                   0,
                                   PreviouslyGrantedAccess,
                                   GenericMapping,
                                   AccessMode,
                                   FALSE,
                                   Privileges,
                                   GrantedAccess,
                                   AccessStatus);
    }

    /* MAXIMUM_ALLOWED below the label: nothing beyond the label's rights, but what the caller granted */
    if (ret && MandatoryAllowed != MAXULONG && (DesiredAccess & MAXIMUM_ALLOWED))
    {
        *GrantedAccess &= MandatoryAllowed | CallerGrantedAccess;
        if (*GrantedAccess == 0)
        {
            *AccessStatus = STATUS_ACCESS_DENIED;
            ret = FALSE;
        }
    }

    /* MAXIMUM_ALLOWED of a lowbox token: within the AppContainer pass (the owner's rights too), but what the caller granted */
    if (ret && AppContainerAllowed != MAXULONG && (DesiredAccess & MAXIMUM_ALLOWED))
    {
        *GrantedAccess &= AppContainerAllowed | AppContainerCallerGranted | ACCESS_SYSTEM_SECURITY;
        if (*GrantedAccess == 0)
        {
            *AccessStatus = STATUS_ACCESS_DENIED;
            ret = FALSE;
        }
    }

    /* Release the lock if needed */
    if (!SubjectContextLocked)
        SeUnlockSubjectContext(SubjectSecurityContext);

    return ret;
}

/**
 * @brief
 * Determines whether security access rights can be given to an object
 * depending on the security descriptor. Unlike the regular access check
 * procedure in the NT kernel, the fast traverse check is a faster way
 * to quickly check if access can be made into an object.
 *
 * @param[in] SecurityDescriptor
 * Security descriptor of the object that is being accessed.
 *
 * @param[in] AccessState
 * An access state to determine if the access token in the current
 * security context of the object is an restricted token.
 *
 * @param[in] DesiredAccess
 * The access right bitmask where the calling thread wants to acquire.
 *
 * @param[in] AccessMode
 * Process level request mode.
 *
 * @return
 * Returns TRUE if access onto the specific object is allowed, FALSE
 * otherwise.
 */
BOOLEAN
NTAPI
SeFastTraverseCheck(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ PACCESS_STATE AccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ KPROCESSOR_MODE AccessMode)
{
    PACL Dacl;
    ULONG AceIndex;
    PKNOWN_ACE Ace;

    PAGED_CODE();

    ASSERT(AccessMode != KernelMode);

    if (SecurityDescriptor == NULL)
        return FALSE;

    /* Get DACL */
    Dacl = SepGetDaclFromDescriptor(SecurityDescriptor);
    /* If no DACL, grant access */
    if (Dacl == NULL)
        return TRUE;

    /* No ACE -> Deny */
    if (!Dacl->AceCount)
        return FALSE;

    /* Can't perform the check on restricted token */
    if (AccessState->Flags & TOKEN_IS_RESTRICTED)
        return FALSE;

    /* Browse the ACEs */
    for (AceIndex = 0, Ace = (PKNOWN_ACE)((ULONG_PTR)Dacl + sizeof(ACL));
         AceIndex < Dacl->AceCount;
         AceIndex++, Ace = (PKNOWN_ACE)((ULONG_PTR)Ace + Ace->Header.AceSize))
    {
        /* An ACE that does not lie within the ACL: the full check decides */
        if ((ULONG_PTR)Ace >= (ULONG_PTR)Dacl + Dacl->AclSize ||
            !SepAceWithinAcl(&Ace->Header, (PUCHAR)Dacl + Dacl->AclSize))
        {
            return FALSE;
        }

        if (Ace->Header.AceFlags & INHERIT_ONLY_ACE)
            continue;

        /* If access-allowed ACE */
        if (Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
            /* Check if all accesses are granted */
            if (!(Ace->Mask & DesiredAccess))
                continue;

            /* Check SID and grant access if matching */
            if (RtlEqualSid(SeWorldSid, &(Ace->SidStart)))
                return TRUE;
        }
        /* If access-denied ACE */
        else if (Ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
        {
            /*
             * Here, only check if it denies any access wanted and deny if so
             * (whatever the SID, OWNER RIGHTS included: the full check decides)
             */
            if (Ace->Mask & DesiredAccess)
                return FALSE;
        }
    }

    /* Faulty, deny */
    return FALSE;
}

/* SYSTEM CALLS ***************************************************************/

/**
 * @brief
 * Determines whether security access can be granted to a client
 * that requests such access on an object.
 *
 * @remarks
 * For more documentation details about the parameters and
 * overall function behavior, see SepAccessCheck.
 */
NTSTATUS
NTAPI
NtAccessCheck(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus)
{
    PAGED_CODE();

    /* Invoke the internal function to do the job */
    return SepAccessCheck(SecurityDescriptor,
                          ClientToken,
                          NULL,
                          DesiredAccess,
                          GenericMapping,
                          PrivilegeSet,
                          PrivilegeSetLength,
                          NULL,
                          0,
                          FALSE,
                          GrantedAccess,
                          AccessStatus);
}

/**
 * @brief
 * Determines whether security access can be granted to a client
 * that requests such access on the object type list. The access
 * is either granted or denied for the whole object hierarchy
 * in the list.
 *
 * @remarks
 * For more documentation details about the parameters and
 * overall function behavior, see SepAccessCheck.
 */
NTSTATUS
NTAPI
NtAccessCheckByType(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_ PACCESS_MASK GrantedAccess,
    _Out_ PNTSTATUS AccessStatus)
{
    PAGED_CODE();

    /* Invoke the internal function to do the job */
    return SepAccessCheck(SecurityDescriptor,
                          ClientToken,
                          PrincipalSelfSid,
                          DesiredAccess,
                          GenericMapping,
                          PrivilegeSet,
                          PrivilegeSetLength,
                          ObjectTypeList,
                          ObjectTypeListLength,
                          FALSE,
                          GrantedAccess,
                          AccessStatus);
}

/**
 * @brief
 * Determines whether security access can be granted to a client
 * that requests such access on the object type list. Unlike the
 * NtAccessCheckByType variant, this function will grant or deny
 * access to each individual object and sub-object in the list.
 *
 * @remarks
 * For more documentation details about the parameters and
 * overall function behavior, see SepAccessCheck.
 */
NTSTATUS
NTAPI
NtAccessCheckByTypeResultList(
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_opt_ PSID PrincipalSelfSid,
    _In_ HANDLE ClientToken,
    _In_ ACCESS_MASK DesiredAccess,
    _In_reads_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
    _In_ ULONG ObjectTypeListLength,
    _In_ PGENERIC_MAPPING GenericMapping,
    _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
    _Inout_ PULONG PrivilegeSetLength,
    _Out_writes_(ObjectTypeListLength) PACCESS_MASK GrantedAccess,
    _Out_writes_(ObjectTypeListLength) PNTSTATUS AccessStatus)
{
    PAGED_CODE();

    /* Invoke the internal function to do the job */
    return SepAccessCheck(SecurityDescriptor,
                          ClientToken,
                          PrincipalSelfSid,
                          DesiredAccess,
                          GenericMapping,
                          PrivilegeSet,
                          PrivilegeSetLength,
                          ObjectTypeList,
                          ObjectTypeListLength,
                          TRUE,
                          GrantedAccess,
                          AccessStatus);
}

/* EOF */
