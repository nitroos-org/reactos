/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         Security Account Manager (SAM) Server
 * FILE:            reactos/dll/win32/samsrv/security.c
 * PURPOSE:         Security descriptor functions
 *
 * PROGRAMMERS:     Eric Kohl
 *
 * The default descriptors are the ones of Windows Server 2022 (build 20348) for a computer that is not a
 * domain controller, read with SamrQuerySecurityObject: the server, the Builtin and the account domain, the
 * aliases, the group, and the users. The access check at the open of a handle ("Standard Handle-Based Access
 * Checks" of [MS-SAMR]) is made against these. The entries for AppContainer capability SIDs are left out.
 */

#include "samsrv.h"

/* GLOBALS *****************************************************************/

static SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};

typedef struct _SAMP_SD_ACE
{
    BOOLEAN Deny;
    ACCESS_MASK Mask;
    PSID Sid;
} SAMP_SD_ACE, *PSAMP_SD_ACE;

/* The default rights of Everyone on the objects */
#define SAMP_SERVER_EVERYONE    (SAM_SERVER_READ | SAM_SERVER_EXECUTE)
#define SAMP_DOMAIN_EVERYONE    (DOMAIN_READ | DOMAIN_EXECUTE)
/* Builtin domain: Administrators may list, look up, create aliases, administer; no write of the parameters */
#define SAMP_BUILTIN_ADMINS     (READ_CONTROL | DOMAIN_READ_PASSWORD_PARAMETERS | DOMAIN_READ_OTHER_PARAMETERS | \
                                 DOMAIN_CREATE_ALIAS | DOMAIN_GET_ALIAS_MEMBERSHIP | DOMAIN_LIST_ACCOUNTS | \
                                 DOMAIN_LOOKUP | DOMAIN_ADMINISTER_SERVER)
#define SAMP_USER_EVERYONE      (READ_CONTROL | USER_READ_GROUP_INFORMATION | USER_LIST_GROUPS | USER_CHANGE_PASSWORD | \
                                 USER_READ_ACCOUNT | USER_READ_LOGON | USER_READ_PREFERENCES | USER_READ_GENERAL)
#define SAMP_USER_SELF          (READ_CONTROL | USER_CHANGE_PASSWORD | USER_WRITE_PREFERENCES)


/* FUNCTIONS ***************************************************************/

static
NTSTATUS
SampAllocSid(IN PSID_IDENTIFIER_AUTHORITY Authority,
             IN UCHAR SubAuthorityCount,
             IN ULONG SubAuthority0,
             IN ULONG SubAuthority1,
             OUT PSID *Sid)
{
    return RtlAllocateAndInitializeSid(Authority,
                                       SubAuthorityCount,
                                       SubAuthority0,
                                       SubAuthority1,
                                       0, 0, 0, 0, 0, 0,
                                       Sid);
}


static
NTSTATUS
SampAllocBuiltinSid(IN ULONG AliasRid,
                    OUT PSID *Sid)
{
    return SampAllocSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, AliasRid, Sid);
}


/*
 * Builds a self-relative descriptor: owner and group Administrators, the DACL with the given entries
 * in the given order, and the audit entries that all the default descriptors have (success and
 * failure of EveryoneAuditMask for Everyone, everything for Anonymous).
 */
static
NTSTATUS
SampBuildSD(IN PSAMP_SD_ACE Aces,
            IN ULONG AceCount,
            IN PSID EveryoneSid,
            IN PSID AdministratorsSid,
            IN ACCESS_MASK EveryoneAuditMask,
            OUT PSECURITY_DESCRIPTOR *Sd,
            OUT PULONG Size)
{
    PSECURITY_DESCRIPTOR AbsSD = NULL;
    PSECURITY_DESCRIPTOR RelSD = NULL;
    PSID AnonymousSid = NULL;
    PACL Dacl = NULL;
    PACL Sacl = NULL;
    ULONG DaclSize, SaclSize, RelSDSize = 0, i;
    NTSTATUS Status;

    Status = SampAllocSid(&NtAuthority, 1, SECURITY_ANONYMOUS_LOGON_RID, 0, &AnonymousSid);
    if (!NT_SUCCESS(Status))
        goto done;

    AbsSD = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECURITY_DESCRIPTOR));
    if (AbsSD == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    Status = RtlCreateSecurityDescriptor(AbsSD, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
        goto done;

    /* The DACL */
    DaclSize = sizeof(ACL);
    for (i = 0; i < AceCount; i++)
        DaclSize += sizeof(ACE) + RtlLengthSid(Aces[i].Sid);

    Dacl = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, DaclSize);
    if (Dacl == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    Status = RtlCreateAcl(Dacl, DaclSize, ACL_REVISION);
    if (!NT_SUCCESS(Status))
        goto done;

    for (i = 0; i < AceCount; i++)
    {
        if (Aces[i].Deny)
            Status = RtlAddAccessDeniedAce(Dacl, ACL_REVISION, Aces[i].Mask, Aces[i].Sid);
        else
            Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, Aces[i].Mask, Aces[i].Sid);
        if (!NT_SUCCESS(Status))
            goto done;
    }

    Status = RtlSetDaclSecurityDescriptor(AbsSD, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status))
        goto done;

    /* The SACL */
    SaclSize = sizeof(ACL) +
               2 * sizeof(ACE) +
               RtlLengthSid(EveryoneSid) +
               RtlLengthSid(AnonymousSid);

    Sacl = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, SaclSize);
    if (Sacl == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    Status = RtlCreateAcl(Sacl, SaclSize, ACL_REVISION);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = RtlAddAuditAccessAce(Sacl, ACL_REVISION, EveryoneAuditMask, EveryoneSid, TRUE, TRUE);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = RtlAddAuditAccessAce(Sacl, ACL_REVISION, STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, AnonymousSid, TRUE, TRUE);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = RtlSetSaclSecurityDescriptor(AbsSD, TRUE, Sacl, FALSE);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = RtlSetOwnerSecurityDescriptor(AbsSD, AdministratorsSid, FALSE);
    if (!NT_SUCCESS(Status))
        goto done;

    Status = RtlSetGroupSecurityDescriptor(AbsSD, AdministratorsSid, FALSE);
    if (!NT_SUCCESS(Status))
        goto done;

    /* The self-relative form */
    Status = RtlAbsoluteToSelfRelativeSD(AbsSD, NULL, &RelSDSize);
    if (Status != STATUS_BUFFER_TOO_SMALL)
        goto done;

    RelSD = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, RelSDSize);
    if (RelSD == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    Status = RtlAbsoluteToSelfRelativeSD(AbsSD, RelSD, &RelSDSize);
    if (!NT_SUCCESS(Status))
        goto done;

    *Sd = RelSD;
    *Size = RelSDSize;
    RelSD = NULL;

done:
    if (RelSD != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, RelSD);

    if (AnonymousSid != NULL)
        RtlFreeSid(AnonymousSid);

    if (Dacl != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Dacl);

    if (Sacl != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Sacl);

    if (AbsSD != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, AbsSD);

    return Status;
}


/* Everyone and Administrators, which every default descriptor needs */
static
NTSTATUS
SampAllocCommonSids(OUT PSID *EveryoneSid,
                    OUT PSID *AdministratorsSid)
{
    NTSTATUS Status;

    *EveryoneSid = NULL;
    *AdministratorsSid = NULL;

    Status = SampAllocSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, EveryoneSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_ADMINS, AdministratorsSid);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeSid(*EveryoneSid);
        *EveryoneSid = NULL;
    }

    return Status;
}


NTSTATUS
SampCreateServerSD(OUT PSECURITY_DESCRIPTOR *ServerSd,
                   OUT PULONG Size)
{
    PSID EveryoneSid, AdministratorsSid;
    SAMP_SD_ACE Aces[2];
    NTSTATUS Status;

    Status = SampAllocCommonSids(&EveryoneSid, &AdministratorsSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Aces[0].Deny = FALSE; Aces[0].Mask = SAMP_SERVER_EVERYONE; Aces[0].Sid = EveryoneSid;
    Aces[1].Deny = FALSE; Aces[1].Mask = SAM_SERVER_ALL_ACCESS; Aces[1].Sid = AdministratorsSid;

    Status = SampBuildSD(Aces, 2, EveryoneSid, AdministratorsSid,
                         ACCESS_SYSTEM_SECURITY | WRITE_DAC | DELETE |
                         SAM_SERVER_CREATE_DOMAIN | SAM_SERVER_INITIALIZE | SAM_SERVER_SHUTDOWN,
                         ServerSd, Size);

    RtlFreeSid(EveryoneSid);
    RtlFreeSid(AdministratorsSid);
    return Status;
}


NTSTATUS
SampCreateBuiltinDomainSD(OUT PSECURITY_DESCRIPTOR *DomainSd,
                          OUT PULONG Size)
{
    PSID EveryoneSid, AdministratorsSid;
    SAMP_SD_ACE Aces[2];
    NTSTATUS Status;

    Status = SampAllocCommonSids(&EveryoneSid, &AdministratorsSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Aces[0].Deny = FALSE; Aces[0].Mask = SAMP_DOMAIN_EVERYONE; Aces[0].Sid = EveryoneSid;
    Aces[1].Deny = FALSE; Aces[1].Mask = SAMP_BUILTIN_ADMINS; Aces[1].Sid = AdministratorsSid;

    Status = SampBuildSD(Aces, 2, EveryoneSid, AdministratorsSid,
                         ACCESS_SYSTEM_SECURITY | WRITE_DAC | DELETE |
                         SAM_SERVER_CREATE_DOMAIN | SAM_SERVER_INITIALIZE | SAM_SERVER_SHUTDOWN,
                         DomainSd, Size);

    RtlFreeSid(EveryoneSid);
    RtlFreeSid(AdministratorsSid);
    return Status;
}


/*
 * The account domain: Everyone, Users and Power Users read; Account Operators also create users and
 * aliases (the earlier descriptor of this code named the Guests alias here); Administrators have all
 * access but the creation of groups. The deny entry for Power Users after the allow entries is the
 * one that Windows has.
 */
NTSTATUS
SampCreateAccountDomainSD(OUT PSECURITY_DESCRIPTOR *DomainSd,
                          OUT PULONG Size)
{
    PSID EveryoneSid, AdministratorsSid;
    PSID UsersSid = NULL, PowerUsersSid = NULL, AccountOperatorsSid = NULL;
    SAMP_SD_ACE Aces[6];
    NTSTATUS Status;

    Status = SampAllocCommonSids(&EveryoneSid, &AdministratorsSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_USERS, &UsersSid);
    if (NT_SUCCESS(Status))
        Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_POWER_USERS, &PowerUsersSid);
    if (NT_SUCCESS(Status))
        Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_ACCOUNT_OPS, &AccountOperatorsSid);
    if (NT_SUCCESS(Status))
    {
        Aces[0].Deny = FALSE; Aces[0].Mask = SAMP_DOMAIN_EVERYONE; Aces[0].Sid = EveryoneSid;
        Aces[1].Deny = FALSE; Aces[1].Mask = SAMP_DOMAIN_EVERYONE; Aces[1].Sid = UsersSid;
        Aces[2].Deny = FALSE; Aces[2].Mask = DOMAIN_ALL_ACCESS & ~DOMAIN_CREATE_GROUP; Aces[2].Sid = AdministratorsSid;
        Aces[3].Deny = FALSE; Aces[3].Mask = SAMP_DOMAIN_EVERYONE; Aces[3].Sid = PowerUsersSid;
        Aces[4].Deny = FALSE; Aces[4].Mask = SAMP_DOMAIN_EVERYONE | DOMAIN_CREATE_USER | DOMAIN_CREATE_ALIAS; Aces[4].Sid = AccountOperatorsSid;
        Aces[5].Deny = TRUE;  Aces[5].Mask = DOMAIN_CREATE_USER | DOMAIN_CREATE_ALIAS; Aces[5].Sid = PowerUsersSid;

        Status = SampBuildSD(Aces, 6, EveryoneSid, AdministratorsSid,
                             ACCESS_SYSTEM_SECURITY | WRITE_DAC | DELETE |
                             SAM_SERVER_CREATE_DOMAIN | SAM_SERVER_INITIALIZE | SAM_SERVER_SHUTDOWN,
                             DomainSd, Size);
    }

    if (UsersSid != NULL) RtlFreeSid(UsersSid);
    if (PowerUsersSid != NULL) RtlFreeSid(PowerUsersSid);
    if (AccountOperatorsSid != NULL) RtlFreeSid(AccountOperatorsSid);
    RtlFreeSid(EveryoneSid);
    RtlFreeSid(AdministratorsSid);
    return Status;
}


/*
 * An alias: everyone reads the information and lists the members; Administrators have all access;
 * Account Operators have all access to every alias but Administrators and Backup Operators; Power
 * Users too for Users, Guests and Power Users. RelativeId is 0 for an alias that is created later.
 */
NTSTATUS
SampCreateAliasSD(IN ULONG RelativeId,
                  OUT PSECURITY_DESCRIPTOR *AliasSd,
                  OUT PULONG Size)
{
    PSID EveryoneSid, AdministratorsSid;
    PSID AccountOperatorsSid = NULL, PowerUsersSid = NULL;
    SAMP_SD_ACE Aces[4];
    ULONG n = 0;
    NTSTATUS Status;

    Status = SampAllocCommonSids(&EveryoneSid, &AdministratorsSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Aces[n].Deny = FALSE; Aces[n].Mask = READ_CONTROL | ALIAS_READ_INFORMATION | ALIAS_LIST_MEMBERS; Aces[n].Sid = EveryoneSid; n++;
    Aces[n].Deny = FALSE; Aces[n].Mask = ALIAS_ALL_ACCESS; Aces[n].Sid = AdministratorsSid; n++;

    Status = STATUS_SUCCESS;
    if (RelativeId != DOMAIN_ALIAS_RID_ADMINS && RelativeId != DOMAIN_ALIAS_RID_BACKUP_OPS)
    {
        Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_ACCOUNT_OPS, &AccountOperatorsSid);
        if (NT_SUCCESS(Status))
        {
            Aces[n].Deny = FALSE; Aces[n].Mask = ALIAS_ALL_ACCESS; Aces[n].Sid = AccountOperatorsSid; n++;
        }
    }

    if (NT_SUCCESS(Status) &&
        (RelativeId == DOMAIN_ALIAS_RID_USERS || RelativeId == DOMAIN_ALIAS_RID_GUESTS ||
         RelativeId == DOMAIN_ALIAS_RID_POWER_USERS))
    {
        Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_POWER_USERS, &PowerUsersSid);
        if (NT_SUCCESS(Status))
        {
            Aces[n].Deny = FALSE; Aces[n].Mask = ALIAS_ALL_ACCESS; Aces[n].Sid = PowerUsersSid; n++;
        }
    }

    if (NT_SUCCESS(Status))
    {
        Status = SampBuildSD(Aces, n, EveryoneSid, AdministratorsSid,
                             ACCESS_SYSTEM_SECURITY | WRITE_DAC | DELETE |
                             ALIAS_WRITE_ACCOUNT | ALIAS_REMOVE_MEMBER | ALIAS_ADD_MEMBER,
                             AliasSd, Size);
    }

    if (AccountOperatorsSid != NULL) RtlFreeSid(AccountOperatorsSid);
    if (PowerUsersSid != NULL) RtlFreeSid(PowerUsersSid);
    RtlFreeSid(EveryoneSid);
    RtlFreeSid(AdministratorsSid);
    return Status;
}


NTSTATUS
SampCreateGroupSD(OUT PSECURITY_DESCRIPTOR *GroupSd,
                  OUT PULONG Size)
{
    PSID EveryoneSid, AdministratorsSid;
    PSID AccountOperatorsSid = NULL;
    SAMP_SD_ACE Aces[3];
    NTSTATUS Status;

    Status = SampAllocCommonSids(&EveryoneSid, &AdministratorsSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_ACCOUNT_OPS, &AccountOperatorsSid);
    if (NT_SUCCESS(Status))
    {
        Aces[0].Deny = FALSE; Aces[0].Mask = READ_CONTROL | GROUP_LIST_MEMBERS | GROUP_READ_INFORMATION; Aces[0].Sid = EveryoneSid;
        Aces[1].Deny = FALSE; Aces[1].Mask = GROUP_ALL_ACCESS; Aces[1].Sid = AdministratorsSid;
        Aces[2].Deny = FALSE; Aces[2].Mask = GROUP_ALL_ACCESS; Aces[2].Sid = AccountOperatorsSid;

        Status = SampBuildSD(Aces, 3, EveryoneSid, AdministratorsSid,
                             ACCESS_SYSTEM_SECURITY | WRITE_DAC | DELETE |
                             GROUP_REMOVE_MEMBER | GROUP_ADD_MEMBER | GROUP_WRITE_ACCOUNT,
                             GroupSd, Size);
    }

    if (AccountOperatorsSid != NULL) RtlFreeSid(AccountOperatorsSid);
    RtlFreeSid(EveryoneSid);
    RtlFreeSid(AdministratorsSid);
    return Status;
}


/*
 * A user: everyone reads (and may change the password with the old one); Administrators have all
 * access; the user may change the password and the preferences; Account Operators have all access
 * to every user but the Administrator account. The Guest account (500 + 1) has no self entry and
 * Everyone cannot change its password.
 */
NTSTATUS
SampCreateUserSD(IN PSID UserSid,
                 OUT PSECURITY_DESCRIPTOR *UserSd,
                 OUT PULONG Size)
{
    PSID EveryoneSid, AdministratorsSid;
    PSID AccountOperatorsSid = NULL;
    SAMP_SD_ACE Aces[4];
    ULONG n = 0, Rid;
    NTSTATUS Status;

    Rid = *RtlSubAuthoritySid(UserSid, (ULONG)(*RtlSubAuthorityCountSid(UserSid)) - 1);

    Status = SampAllocCommonSids(&EveryoneSid, &AdministratorsSid);
    if (!NT_SUCCESS(Status))
        return Status;

    Aces[n].Deny = FALSE;
    Aces[n].Mask = (Rid == DOMAIN_USER_RID_GUEST) ? (SAMP_USER_EVERYONE & ~USER_CHANGE_PASSWORD) : SAMP_USER_EVERYONE;
    Aces[n].Sid = EveryoneSid; n++;
    Aces[n].Deny = FALSE; Aces[n].Mask = USER_ALL_ACCESS; Aces[n].Sid = AdministratorsSid; n++;

    Status = STATUS_SUCCESS;
    if (Rid != DOMAIN_USER_RID_ADMIN)
    {
        Status = SampAllocBuiltinSid(DOMAIN_ALIAS_RID_ACCOUNT_OPS, &AccountOperatorsSid);
        if (NT_SUCCESS(Status))
        {
            Aces[n].Deny = FALSE; Aces[n].Mask = USER_ALL_ACCESS; Aces[n].Sid = AccountOperatorsSid; n++;
        }
    }

    if (NT_SUCCESS(Status) && Rid != DOMAIN_USER_RID_GUEST)
    {
        Aces[n].Deny = FALSE; Aces[n].Mask = SAMP_USER_SELF; Aces[n].Sid = UserSid; n++;
    }

    if (NT_SUCCESS(Status))
    {
        Status = SampBuildSD(Aces, n, EveryoneSid, AdministratorsSid,
                             ACCESS_SYSTEM_SECURITY | WRITE_DAC | DELETE |
                             USER_CHANGE_PASSWORD | USER_WRITE_PREFERENCES,
                             UserSd, Size);
    }

    if (AccountOperatorsSid != NULL) RtlFreeSid(AccountOperatorsSid);
    RtlFreeSid(EveryoneSid);
    RtlFreeSid(AdministratorsSid);
    return Status;
}

/* EOF */
