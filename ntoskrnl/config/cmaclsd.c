/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager - the verdict on a stored key descriptor of a per-user hive
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * While registry key access was not enforced, any account could change any
 * key and its descriptor, also in another account's hive (an administrator's
 * HKCU Run key, NetworkService's Software\Classes). The first load of a user
 * hive after the transition to enforcement replaces the stored descriptors
 * that neither the hive's own account nor the system would have set
 * (cmacl.c, CmpAclCheckUserHive). This is the verdict on one descriptor, kept
 * free of kernel state (Rtl calls only) so that a unit test can feed it rows.
 *
 * The reference is the descriptor of a user hive's root on Windows 10 22H2
 * (cmacl.c CmpAclSdUser, oracle capture):
 *   O:BAG:SYD:P(A;OICI;KA;;;<SID>)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;RC)(A;;KR;;;AC)(A;;KR;;;LPAC)
 * Trusted for anything: SYSTEM, Administrators, TrustedInstaller, the hive's
 * own account, and the creator placeholders (CREATOR OWNER, CREATOR GROUP and
 * OWNER RIGHTS never match a token; OWNER RIGHTS is the owner, judged as the
 * owner). Trusted for reading: RESTRICTED anywhere; ALL APPLICATION PACKAGES
 * and the LPAC capability on the root only (no inheritance flags there).
 * Package SIDs: any right below AppContainer\Storage and \Mappings, where the
 * profile code grants them (userenv appcontainer.c, as Windows 10). Nothing
 * else: no other account may read another account's hive on Windows.
 *
 * The descriptor must be a validated self-relative copy; every ACE is still
 * checked for room for its SID before the SID is read.
 */

#include "ntoskrnl.h"
#include "cmaclsd.h"

/* What lets a holder change the key, its descriptor or its existence */
#define CMP_ACL_UH_WRITE_RIGHTS (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | \
                                 WRITE_OWNER | MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY)

/* A well-known SID: S-1-<Authority>-<Sub[0]>-...-<Sub[Count-1]> */
typedef struct _CMP_ACL_UH_SID
{
    UCHAR Authority;
    UCHAR Count;
    ULONG Sub[10];
} CMP_ACL_UH_SID;

static const CMP_ACL_UH_SID CmpAclUhSystem = { 5, 1, { 18 } };
static const CMP_ACL_UH_SID CmpAclUhAdmins = { 5, 2, { 32, 544 } };
static const CMP_ACL_UH_SID CmpAclUhUsers = { 5, 2, { 32, 545 } };
static const CMP_ACL_UH_SID CmpAclUhTrustedInstaller =
    { 5, 6, { 80, 956008885, 3418522649u, 1831038044, 1853292631, 2271478464u } };
static const CMP_ACL_UH_SID CmpAclUhCreatorOwner = { 3, 1, { 0 } };
static const CMP_ACL_UH_SID CmpAclUhCreatorGroup = { 3, 1, { 1 } };
static const CMP_ACL_UH_SID CmpAclUhOwnerRights = { 3, 1, { 4 } };
static const CMP_ACL_UH_SID CmpAclUhWorld = { 1, 1, { 0 } };
static const CMP_ACL_UH_SID CmpAclUhAuthenticated = { 5, 1, { 11 } };
static const CMP_ACL_UH_SID CmpAclUhInteractive = { 5, 1, { 4 } };
static const CMP_ACL_UH_SID CmpAclUhService = { 5, 1, { 6 } };
static const CMP_ACL_UH_SID CmpAclUhThisOrganization = { 5, 1, { 15 } };
static const CMP_ACL_UH_SID CmpAclUhLocal = { 2, 1, { 0 } };
static const CMP_ACL_UH_SID CmpAclUhConsoleLogon = { 2, 1, { 1 } };
static const CMP_ACL_UH_SID CmpAclUhRestricted = { 5, 1, { 12 } };
static const CMP_ACL_UH_SID CmpAclUhAllAppPackages = { 15, 2, { 2, 1 } };
/* The capability SID Windows 10 puts on the hive roots (cmacl.c CmpAclSidLpacCapability, oracle capture) */
static const CMP_ACL_UH_SID CmpAclUhLpacCapability =
    { 15, 10, { 3, 1024, 1065365936, 1281604716, 3511738428u, 1654721687, 432734479, 3232135806u, 4053264122u,
                3456934681u } };

/* SIDs trusted for anything in a user hive besides the hive's own account */
static const CMP_ACL_UH_SID *const CmpAclUhTrustedSids[] =
{
    &CmpAclUhSystem, &CmpAclUhAdmins, &CmpAclUhTrustedInstaller,
    &CmpAclUhCreatorOwner, &CmpAclUhCreatorGroup, &CmpAclUhOwnerRights,
};

/* A deny for one of these (or for the own account) takes rights from the account or the system */
static const CMP_ACL_UH_SID *const CmpAclUhDenyHurtsSids[] =
{
    &CmpAclUhOwnerRights, &CmpAclUhSystem, &CmpAclUhAdmins, &CmpAclUhUsers, &CmpAclUhWorld,
    &CmpAclUhAuthenticated, &CmpAclUhInteractive, &CmpAclUhService, &CmpAclUhThisOrganization,
    &CmpAclUhLocal, &CmpAclUhConsoleLogon,
};

static
BOOLEAN
CmpAclUhSidIs(
    _In_ PSID Sid,
    _In_ const CMP_ACL_UH_SID *Known)
{
    PSID_IDENTIFIER_AUTHORITY Auth = RtlIdentifierAuthoritySid(Sid);
    ULONG i;

    if (*RtlSubAuthorityCountSid(Sid) != Known->Count)
        return FALSE;
    if (Auth->Value[0] || Auth->Value[1] || Auth->Value[2] || Auth->Value[3] || Auth->Value[4] ||
        Auth->Value[5] != Known->Authority)
    {
        return FALSE;
    }
    for (i = 0; i < Known->Count; i++)
    {
        if (*RtlSubAuthoritySid(Sid, i) != Known->Sub[i])
            return FALSE;
    }
    return TRUE;
}

static
BOOLEAN
CmpAclUhSidIn(
    _In_ PSID Sid,
    _In_reads_(Count) const CMP_ACL_UH_SID *const *List,
    _In_ ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        if (CmpAclUhSidIs(Sid, List[i]))
            return TRUE;
    }
    return FALSE;
}

/* SYSTEM, Administrators, TrustedInstaller, the own account, the creator placeholders */
static
BOOLEAN
CmpAclUhTrusted(
    _In_ PSID Sid,
    _In_ PSID OwnSid)
{
    return RtlEqualSid(Sid, OwnSid) ||
           CmpAclUhSidIn(Sid, CmpAclUhTrustedSids, RTL_NUMBER_OF(CmpAclUhTrustedSids));
}

/*
 * A deny for this SID takes rights from the hive's own account or from the
 * system: the account, its owner rights, SYSTEM, Administrators, or a group
 * that every logon of the account holds
 */
static
BOOLEAN
CmpAclUhDenyHurts(
    _In_ PSID Sid,
    _In_ PSID OwnSid)
{
    return RtlEqualSid(Sid, OwnSid) ||
           CmpAclUhSidIn(Sid, CmpAclUhDenyHurtsSids, RTL_NUMBER_OF(CmpAclUhDenyHurtsSids));
}

/* S-1-15-2-<7 numbers>: one application package (not ALL APPLICATION PACKAGES) */
static
BOOLEAN
CmpAclUhIsPackage(
    _In_ PSID Sid)
{
    PSID_IDENTIFIER_AUTHORITY Auth = RtlIdentifierAuthoritySid(Sid);

    return *RtlSubAuthorityCountSid(Sid) == 8 &&
           !Auth->Value[0] && !Auth->Value[1] && !Auth->Value[2] && !Auth->Value[3] && !Auth->Value[4] &&
           Auth->Value[5] == 15 && *RtlSubAuthoritySid(Sid, 0) == 2;
}

/* The SIDs a user hive's root lets read without inheritance: AC and the LPAC capability */
static
BOOLEAN
CmpAclUhIsRootReader(
    _In_ PSID Sid)
{
    return CmpAclUhSidIs(Sid, &CmpAclUhAllAppPackages) || CmpAclUhSidIs(Sid, &CmpAclUhLpacCapability);
}

/*
 * The SID of an ACE of a type that has one right after the mask (allow, deny,
 * audit, label: the types this file reads), or NULL if the ACE has no room for
 * it. The ACL was validated as a whole; this keeps a short ACE from being read
 * past its end whatever the validation accepted.
 */
static
PSID
CmpAclUhAceSid(
    _In_ PACE_HEADER Ace)
{
    PISID Sid;
    ULONG Room;

    if (Ace->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + FIELD_OFFSET(SID, SubAuthority))
        return NULL;
    Room = Ace->AceSize - FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
    Sid = (PISID)&((PACCESS_ALLOWED_ACE)Ace)->SidStart;
    if (Sid->Revision != SID_REVISION || Sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
        FIELD_OFFSET(SID, SubAuthority) + Sid->SubAuthorityCount * sizeof(ULONG) > Room)
    {
        return NULL;
    }
    return (PSID)Sid;
}

/*
 * The ACE at Cursor in Acl, or NULL if it does not fit in the ACL or is
 * shorter than its header and access mask. The ACEs are walked one after the
 * other with this: RtlGetAce starts again from the first ACE for every index,
 * which makes a loop over all of them quadratic, and an ACL of 64 KB in a
 * hive file its user wrote holds thousands of ACEs.
 */
static
PACE_HEADER
CmpAclUhAceAt(
    _In_ PACL Acl,
    _In_ PUCHAR Cursor)
{
    PUCHAR End = (PUCHAR)Acl + Acl->AclSize;
    PACE_HEADER Ace = (PACE_HEADER)Cursor;

    if (Cursor < (PUCHAR)(Acl + 1) || Cursor > End ||
        (ULONG)(End - Cursor) < sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) ||
        Ace->AceSize < sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) ||
        Ace->AceSize > (ULONG)(End - Cursor))
    {
        return NULL;
    }
    return Ace;
}

/*
 * The verdict on a stored descriptor of a key in a user hive: 0 (keep it), or
 * the CMP_ACL_UH_* reasons to replace it.
 *
 *  Sd       a validated self-relative copy
 *  OwnSid   the hive's own account (from the name it is loaded at)
 *  Place    CMP_ACL_UH_PLACE_*: where the key is
 *  Mapping  the key type's generic mapping
 *  Owner    receives the owner (points into Sd; NULL if none)
 *
 * Kept: ACEs of trusted SIDs; inherit-only ACEs that do not flow to subkeys
 * (object inherit only: never effective on a key); deny ACEs for other
 * accounts; audit ACEs; labels at or below Medium. The own account's
 * restrictive descriptors are kept although SYSTEM may be missing from them:
 * nothing of the system needs access to a profile key.
 */
ULONG
NTAPI
CmpAclUserHiveSdVerdict(
    _In_ PSECURITY_DESCRIPTOR Sd,
    _In_ PSID OwnSid,
    _In_ ULONG Place,
    _In_ PGENERIC_MAPPING Mapping,
    _Out_opt_ PSID *Owner)
{
    BOOLEAN Present, Defaulted, Flows, Here;
    PSID OwnerSid = NULL, Sid;
    PACL Acl;
    PACE_HEADER Ace;
    PUCHAR Cursor;
    ACCESS_MASK Mask;
    ULONG Reasons = 0, i;

    if (Owner)
        *Owner = NULL;

    /* The owner has WRITE_DAC: it must be trusted */
    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Sd, &OwnerSid, &Defaulted)) || !OwnerSid ||
        !CmpAclUhTrusted(OwnerSid, OwnSid))
    {
        Reasons |= CMP_ACL_UH_OWNER;
    }
    if (Owner)
        *Owner = OwnerSid;

    Acl = NULL;
    if (!NT_SUCCESS(RtlGetDaclSecurityDescriptor(Sd, &Present, &Acl, &Defaulted)) || !Present || !Acl)
    {
        /* No DACL or a NULL one: everything for everyone */
        Reasons |= CMP_ACL_UH_WRITE;
    }
    else
    {
        for (i = 0, Cursor = (PUCHAR)(Acl + 1); i < Acl->AceCount; i++, Cursor += Ace->AceSize)
        {
            Ace = CmpAclUhAceAt(Acl, Cursor);
            if (!Ace)
            {
                /* Not an ACE the access check could read either: the descriptor is replaced */
                Reasons |= CMP_ACL_UH_ACETYPE;
                break;
            }

            /* Effective on the key itself, or on its subkeys (container inherit) */
            Here = !(Ace->AceFlags & INHERIT_ONLY_ACE);
            Flows = (Ace->AceFlags & CONTAINER_INHERIT_ACE) != 0;
            if (!Here && !Flows)
                continue;

            switch (Ace->AceType)
            {
                case ACCESS_ALLOWED_ACE_TYPE:
                case ACCESS_DENIED_ACE_TYPE:
                    break;
                case ACCESS_DENIED_OBJECT_ACE_TYPE:
                case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                    /* Never stored by the kernel on a key; a deny only takes away: judged below by its mask alone */
                    break;
                default:
                    Reasons |= CMP_ACL_UH_ACETYPE;
                    continue;
            }

            Mask = ((PACCESS_ALLOWED_ACE)Ace)->Mask;
            RtlMapGenericMask(&Mask, Mapping);
            if (!Mask)
                continue;

            if (Ace->AceType != ACCESS_ALLOWED_ACE_TYPE)
            {
                /* A deny of another layout has its SID elsewhere: it counts as hurting whoever it names */
                Sid = (Ace->AceType == ACCESS_DENIED_ACE_TYPE) ? CmpAclUhAceSid(Ace) : NULL;
                if (!Sid || CmpAclUhDenyHurts(Sid, OwnSid))
                    Reasons |= CMP_ACL_UH_DENY;
                continue;
            }

            Sid = CmpAclUhAceSid(Ace);
            if (!Sid)
            {
                Reasons |= CMP_ACL_UH_ACETYPE;
                continue;
            }
            if (CmpAclUhTrusted(Sid, OwnSid))
                continue;
            if (CmpAclUhIsPackage(Sid) && (Place & CMP_ACL_UH_PLACE_APPCONTAINER))
                continue;
            if (Mask & CMP_ACL_UH_WRITE_RIGHTS)
            {
                Reasons |= CMP_ACL_UH_WRITE;
                continue;
            }
            /* Read rights only */
            if (CmpAclUhSidIs(Sid, &CmpAclUhRestricted))
                continue;
            if (CmpAclUhIsRootReader(Sid) && (Place & CMP_ACL_UH_PLACE_ROOT) && Here && !Flows)
                continue;
            Reasons |= CMP_ACL_UH_READ;
        }
    }

    /* A label above Medium keeps the account's own (Medium) processes from writing */
    Acl = NULL;
    if (NT_SUCCESS(RtlGetSaclSecurityDescriptor(Sd, &Present, &Acl, &Defaulted)) && Present && Acl)
    {
        for (i = 0, Cursor = (PUCHAR)(Acl + 1); i < Acl->AceCount; i++, Cursor += Ace->AceSize)
        {
            Ace = CmpAclUhAceAt(Acl, Cursor);
            if (!Ace)
                break;
            if (Ace->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                continue;
            if ((Ace->AceFlags & INHERIT_ONLY_ACE) && !(Ace->AceFlags & CONTAINER_INHERIT_ACE))
                continue;
            Sid = CmpAclUhAceSid(Ace);
            if (!Sid || *RtlSubAuthorityCountSid(Sid) != 1 ||
                RtlIdentifierAuthoritySid(Sid)->Value[5] != 16 /* SECURITY_MANDATORY_LABEL_AUTHORITY */)
            {
                continue;
            }
            if (*RtlSubAuthoritySid(Sid, 0) > SECURITY_MANDATORY_MEDIUM_RID)
                Reasons |= CMP_ACL_UH_LABEL;
        }
    }

    return Reasons;
}
