/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Access token Query/Set information classes implementation
 * COPYRIGHT:   Copyright David Welch <welch@cwcom.net>
 *              Copyright 2021-2022 George Bișoc <george.bisoc@reactos.org>
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#include <ntlsa.h>

/* INFORMATION CLASSES ********************************************************/

static const INFORMATION_CLASS_INFO SeTokenInformationClass[] = {

    /* Class 0 not used, blame MS! */
    IQS_NONE,

    /* TokenUser */
    IQS_SAME(TOKEN_USER, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenGroups */
    IQS_SAME(TOKEN_GROUPS, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenPrivileges */
    IQS_SAME(TOKEN_PRIVILEGES, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenOwner */
    IQS_SAME(TOKEN_OWNER, ULONG, ICIF_QUERY | ICIF_SET | ICIF_SIZE_VARIABLE),
    /* TokenPrimaryGroup */
    IQS_SAME(TOKEN_PRIMARY_GROUP, ULONG, ICIF_QUERY | ICIF_SET | ICIF_SIZE_VARIABLE),
    /* TokenDefaultDacl */
    IQS_SAME(TOKEN_DEFAULT_DACL, ULONG, ICIF_QUERY | ICIF_SET | ICIF_SIZE_VARIABLE),
    /* TokenSource */
    IQS_SAME(TOKEN_SOURCE, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenType */
    IQS_SAME(TOKEN_TYPE, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenImpersonationLevel: Windows accepts a larger buffer */
    IQS_SAME(SECURITY_IMPERSONATION_LEVEL, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenStatistics */
    IQS_SAME(TOKEN_STATISTICS, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenRestrictedSids */
    IQS_SAME(TOKEN_GROUPS, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenSessionId: Windows accepts a larger buffer for the query */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE | ICIF_SET),
    /* TokenGroupsAndPrivileges */
    IQS_SAME(TOKEN_GROUPS_AND_PRIVILEGES, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenSessionReference */
    IQS_SAME(ULONG, ULONG, ICIF_SET),
    /* TokenSandBoxInert */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenAuditPolicy */
    IQS_SAME(TOKEN_AUDIT_POLICY_INFORMATION, ULONG, ICIF_SET | ICIF_SET_SIZE_VARIABLE),
    /* TokenOrigin */
    IQS_SAME(TOKEN_ORIGIN, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE | ICIF_SET),
    /* TokenElevationType */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenLinkedToken: Windows insists on the exact size of a handle */
    IQS_SAME(HANDLE, ULONG, ICIF_QUERY),
    /* TokenElevation: Windows insists on the exact size, unlike TokenElevationType */
    IQS_SAME(TOKEN_ELEVATION, ULONG, ICIF_QUERY),
    /* TokenHasRestrictions: a BOOLEAN on Windows (one byte is written) */
    IQS_SAME(BOOLEAN, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenAccessInformation: variable size, measured on Windows 10 22H2 */
    IQS_NO_TYPE_LENGTH(ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenVirtualizationAllowed */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenVirtualizationEnabled */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenIntegrityLevel */
    IQS_SAME(TOKEN_MANDATORY_LABEL, ULONG, ICIF_QUERY | ICIF_SET | ICIF_SIZE_VARIABLE),
    /* TokenUIAccess */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenMandatoryPolicy */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenLogonSid */
    IQS_SAME(TOKEN_GROUPS, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenIsAppContainer */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenCapabilities: TOKEN_GROUPS, the capabilities of a lowbox token, none for others */
    IQS_NO_TYPE_LENGTH(ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenAppContainerSid: TOKEN_APPCONTAINER_INFORMATION, a SID pointer (and the SID of a lowbox token) */
    IQS_SAME(PVOID, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenAppContainerNumber */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenUserClaimAttributes ... TokenSecurityAttributes (33..39): not implemented */
    IQS_NONE, IQS_NONE, IQS_NONE, IQS_NONE, IQS_NONE, IQS_NONE, IQS_NONE,
    /* TokenIsRestricted */
    IQS_SAME(ULONG, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
    /* TokenProcessTrustLevel: TOKEN_PROCESS_TRUST_LEVEL, a SID pointer */
    IQS_SAME(PVOID, ULONG, ICIF_QUERY | ICIF_QUERY_SIZE_VARIABLE),
};

/* Information classes the DDK headers of this tree do not name (Windows 10 values) */
#define SepTokenCapabilities        30
#define SepTokenAppContainerSid     31
#define SepTokenAppContainerNumber  32
#define SepTokenIsRestricted        40
#define SepTokenProcessTrustLevel   41

C_ASSERT(TokenAccessInformation == 22);
C_ASSERT(TokenIsAppContainer == 29);
C_ASSERT(SepTokenIsRestricted == TokenIsRestricted);

/*
 * The TOKEN_ACCESS_INFORMATION of Windows 10. The DDK header of this tree stops
 * after Flags (the Vista layout); the buffer NtQueryInformationToken fills is
 * this one: a SID hash, a restricted SID hash, the privileges, the logon
 * session, the token type and level, the mandatory policy and flags, then the
 * AppContainer package SID and number, the capability SID hash, the trust
 * level SID and the security attributes, followed by the data they point to.
 */
typedef struct _SEP_TOKEN_ACCESS_INFORMATION
{
    PSID_AND_ATTRIBUTES_HASH SidHash;
    PSID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    PTOKEN_PRIVILEGES Privileges;
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    TOKEN_MANDATORY_POLICY MandatoryPolicy;
    ULONG Flags;
    ULONG AppContainerNumber;
    PSID PackageSid;
    PSID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    PSID TrustLevelSid;
    PVOID SecurityAttributes;
} SEP_TOKEN_ACCESS_INFORMATION, *PSEP_TOKEN_ACCESS_INFORMATION;

/* The TokenFlags Windows 10 reports in TOKEN_ACCESS_INFORMATION.Flags (measured: the privilege summary bits stay out; TOKEN_WRITE_RESTRICTED shares its value with this kernel's TOKEN_HAS_ADMIN_GROUP and is not reported) */
#define SEP_ACCESS_INFORMATION_FLAGS \
    (TOKEN_IS_RESTRICTED | TOKEN_SANDBOX_INERT | TOKEN_VIRTUALIZE_ALLOWED | \
     TOKEN_VIRTUALIZE_ENABLED | TOKEN_IS_FILTERED | TOKEN_UIACCESS | TOKEN_NOT_LOW | TOKEN_LOWBOX)

/* TOKEN_ELEVATION_TYPE values (the enum is declared in user-mode headers only) */
#define SEP_ELEVATION_TYPE_DEFAULT  1 /* TokenElevationTypeDefault */

/* TOKEN_MANDATORY_POLICY of every token: no write up, new process minimum */
#define SEP_MANDATORY_POLICY_DEFAULT (TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN)

/**
 * Privileges that make a token elevated even without the Administrators
 * group, enabled or not. Measured on Windows 7 (Server 2008 R2) with UAC off
 * by restricting an administrator's token down to one privilege at a time;
 * on Windows 10 the service tokens that hold SeImpersonatePrivilege report
 * the same, and the ones that do not, do not.
 */
static const ULONG SepElevatingPrivileges[] =
{
    SE_CREATE_TOKEN_PRIVILEGE,
    SE_TCB_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
    SE_LOAD_DRIVER_PRIVILEGE,
    SE_BACKUP_PRIVILEGE,
    SE_RESTORE_PRIVILEGE,
    SE_DEBUG_PRIVILEGE,
    SE_IMPERSONATE_PRIVILEGE,
    SE_RELABEL_PRIVILEGE,
};

/**
 * @brief
 * Tells whether TokenElevation reports the token as elevated. The caller
 * must hold the token lock.
 *
 * ReactOS has no UAC, so no token is split into a filtered and a full one,
 * and there are no linked tokens. This is what Windows reports with UAC
 * disabled (EnableLUA = 0, measured on Windows 10 22H2 and Windows 7): the
 * elevation type is always TokenElevationTypeDefault, whatever the groups,
 * privileges and integrity level, and TokenIsElevated is 1 when:
 *
 * - the Administrators group is in the token and is not deny-only, or
 * - the token holds one of SepElevatingPrivileges.
 *
 * The integrity level and the user account do not count. Windows 10 also
 * keeps a restricted copy of an elevated token elevated (a stored property
 * that CreateRestrictedToken inherits, except with LUA_TOKEN); this derives
 * the answer from what the token holds, so such a copy reads as not elevated
 * once its Administrators group is deny-only and its privileges are gone.
 */
static
ULONG
SepIsTokenElevated(
    _In_ PTOKEN Token)
{
    ULONG i, j;

    for (i = 1; i < Token->UserAndGroupCount; i++)
    {
        if (!(Token->UserAndGroups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) &&
            RtlEqualSid(Token->UserAndGroups[i].Sid, SeAliasAdminsSid))
        {
            return TRUE;
        }
    }

    for (i = 0; i < Token->PrivilegeCount; i++)
    {
        if (Token->Privileges[i].Luid.HighPart != 0)
            continue;
        for (j = 0; j < RTL_NUMBER_OF(SepElevatingPrivileges); j++)
        {
            if (Token->Privileges[i].Luid.LowPart == SepElevatingPrivileges[j])
                return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief
 * Builds the TokenAccessInformation answer. The caller holds the token lock.
 *
 * Layout (measured on Windows 10 22H2, x64): the header, the SID hash of the
 * user and groups followed by their SID_AND_ATTRIBUTES array and SIDs, the
 * restricted SID hash (and its array and SIDs when there are any), the
 * capability SID hash (empty but for a lowbox token, with its array and SIDs
 * then), and the privileges; a lowbox token's package SID follows them (where
 * Windows puts that SID is not measured). Every pointer in the answer is an
 * address in the caller's buffer. The SID hashes are filled with all bits set:
 * Windows keeps a bloom filter there that nothing in user mode reads, and a
 * saturated filter is the one that is always safe (a reader falls back to
 * comparing the SIDs). No TSA security attributes exist here, so
 * SecurityAttributes is NULL where Windows points at the process-unique attribute.
 *
 * The answer is built in a pool block and copied to the caller by the caller
 * of this routine, once: nothing here reads or writes the user buffer, whose
 * address is only used to compute the pointers stored in the answer (a thread
 * of the caller can change that memory at any time, so no value is ever read
 * back from it).
 *
 * @param[out] Blob
 * A pool block of *Required bytes (free it with ExFreePoolWithTag, TAG_TOKEN_DYNAMIC)
 * when STATUS_SUCCESS is returned, NULL otherwise. With UserBase NULL or a
 * Length that is too small only the size is computed (STATUS_BUFFER_TOO_SMALL).
 */
static
NTSTATUS
SepBuildTokenAccessInformation(
    _In_ PTOKEN Token,
    _In_opt_ PUCHAR UserBase,
    _In_ ULONG Length,
    _Out_ PULONG Required,
    _Outptr_result_maybenull_ PUCHAR *Blob)
{
    ULONG HeaderSize = ALIGN_UP_BY(sizeof(SEP_TOKEN_ACCESS_INFORMATION), sizeof(PVOID));
    ULONG HashSize = ALIGN_UP_BY(sizeof(SID_AND_ATTRIBUTES_HASH), sizeof(PVOID));
    ULONG SidsSize, RestrictedSize = 0, CapabilitiesSize = 0, PackageSize = 0, PrivilegesSize, Total, Offset, i, j;
    PSEP_LOWBOX Lowbox = Token->Lowbox;
    PUCHAR Kernel;
    PSEP_TOKEN_ACCESS_INFORMATION Info;
    PSID_AND_ATTRIBUTES_HASH Hash;
    PSID_AND_ATTRIBUTES Array;
    PVOID SidEnd;
    ULONG Left;
    NTSTATUS Status;

    *Blob = NULL;
    SidsSize = Token->UserAndGroupCount * sizeof(SID_AND_ATTRIBUTES) +
               RtlLengthSidAndAttributes(Token->UserAndGroupCount, Token->UserAndGroups);
    SidsSize = ALIGN_UP_BY(SidsSize, sizeof(PVOID));
    if (Token->RestrictedSidCount > 0)
    {
        RestrictedSize = Token->RestrictedSidCount * sizeof(SID_AND_ATTRIBUTES) +
                         RtlLengthSidAndAttributes(Token->RestrictedSidCount, Token->RestrictedSids);
        RestrictedSize = ALIGN_UP_BY(RestrictedSize, sizeof(PVOID));
    }
    if (Lowbox)
    {
        if (Lowbox->CapabilityCount > 0)
        {
            /* RtlLengthSidAndAttributes counts the array itself as well as the SIDs */
            CapabilitiesSize = RtlLengthSidAndAttributes(Lowbox->CapabilityCount, Lowbox->Capabilities);
            CapabilitiesSize = ALIGN_UP_BY(CapabilitiesSize, sizeof(PVOID));
        }
        PackageSize = ALIGN_UP_BY(RtlLengthSid(Lowbox->PackageSid), sizeof(PVOID));
    }
    PrivilegesSize = ALIGN_UP_BY(FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[Token->PrivilegeCount]), sizeof(PVOID));

    Total = HeaderSize + HashSize + SidsSize + HashSize + RestrictedSize + HashSize + CapabilitiesSize +
            PrivilegesSize + PackageSize;
    *Required = Total;
    if (UserBase == NULL || Length < Total)
        return STATUS_BUFFER_TOO_SMALL;

    Kernel = ExAllocatePoolWithTag(PagedPool, Total, TAG_TOKEN_DYNAMIC);
    if (Kernel == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Kernel, Total);

    /* Kernel + Offset is where a piece is built, UserBase + Offset is the address the caller will see it at */
    Info = (PSEP_TOKEN_ACCESS_INFORMATION)Kernel;
    Info->AuthenticationId = Token->AuthenticationId;
    Info->TokenType = Token->TokenType;
    Info->ImpersonationLevel = Token->ImpersonationLevel;
    Info->MandatoryPolicy.Policy = SEP_MANDATORY_POLICY_DEFAULT;
    Info->Flags = Token->TokenFlags & SEP_ACCESS_INFORMATION_FLAGS;
    if (Token->IntegrityLevel > SECURITY_MANDATORY_LOW_RID)
        Info->Flags |= TOKEN_NOT_LOW;

    /* The user and groups */
    Offset = HeaderSize;
    Hash = (PSID_AND_ATTRIBUTES_HASH)(Kernel + Offset);
    Info->SidHash = (PSID_AND_ATTRIBUTES_HASH)(UserBase + Offset);
    Offset += HashSize;
    Hash->SidCount = Token->UserAndGroupCount;
    Hash->SidAttr = (PSID_AND_ATTRIBUTES)(UserBase + Offset);
    for (i = 0; i < SID_HASH_SIZE; i++)
        Hash->Hash[i] = ~(SID_HASH_ENTRY)0;
    Array = (PSID_AND_ATTRIBUTES)(Kernel + Offset);
    Status = RtlCopySidAndAttributesArray(Token->UserAndGroupCount,
                                          Token->UserAndGroups,
                                          SidsSize - Token->UserAndGroupCount * sizeof(SID_AND_ATTRIBUTES),
                                          Array,
                                          (PSID)&Array[Token->UserAndGroupCount],
                                          &SidEnd,
                                          &Left);
    if (!NT_SUCCESS(Status))
        goto Fail;
    /* the SID pointers the copy stored are kernel addresses: make them the caller's */
    for (j = 0; j < Token->UserAndGroupCount; j++)
        Array[j].Sid = (PSID)(UserBase + ((PUCHAR)Array[j].Sid - Kernel));
    Offset += SidsSize;

    /* The restricted SIDs; the hash exists even when there are none */
    Hash = (PSID_AND_ATTRIBUTES_HASH)(Kernel + Offset);
    Info->RestrictedSidHash = (PSID_AND_ATTRIBUTES_HASH)(UserBase + Offset);
    Offset += HashSize;
    Hash->SidCount = Token->RestrictedSidCount;
    for (i = 0; i < SID_HASH_SIZE; i++)
        Hash->Hash[i] = (Token->RestrictedSidCount > 0) ? ~(SID_HASH_ENTRY)0 : 0;
    if (Token->RestrictedSidCount > 0)
    {
        Hash->SidAttr = (PSID_AND_ATTRIBUTES)(UserBase + Offset);
        Array = (PSID_AND_ATTRIBUTES)(Kernel + Offset);
        Status = RtlCopySidAndAttributesArray(Token->RestrictedSidCount,
                                              Token->RestrictedSids,
                                              RestrictedSize - Token->RestrictedSidCount * sizeof(SID_AND_ATTRIBUTES),
                                              Array,
                                              (PSID)&Array[Token->RestrictedSidCount],
                                              &SidEnd,
                                              &Left);
        if (!NT_SUCCESS(Status))
            goto Fail;
        for (j = 0; j < Token->RestrictedSidCount; j++)
            Array[j].Sid = (PSID)(UserBase + ((PUCHAR)Array[j].Sid - Kernel));
        Offset += RestrictedSize;
    }

    /* The capabilities of a lowbox token; the hash exists even when there are none */
    Hash = (PSID_AND_ATTRIBUTES_HASH)(Kernel + Offset);
    Info->CapabilitiesHash = (PSID_AND_ATTRIBUTES_HASH)(UserBase + Offset);
    Offset += HashSize;
    if (CapabilitiesSize > 0)
    {
        Hash->SidCount = Lowbox->CapabilityCount;
        Hash->SidAttr = (PSID_AND_ATTRIBUTES)(UserBase + Offset);
        for (i = 0; i < SID_HASH_SIZE; i++)
            Hash->Hash[i] = ~(SID_HASH_ENTRY)0;
        Array = (PSID_AND_ATTRIBUTES)(Kernel + Offset);
        Status = RtlCopySidAndAttributesArray(Lowbox->CapabilityCount,
                                              Lowbox->Capabilities,
                                              CapabilitiesSize - Lowbox->CapabilityCount * sizeof(SID_AND_ATTRIBUTES),
                                              Array,
                                              (PSID)&Array[Lowbox->CapabilityCount],
                                              &SidEnd,
                                              &Left);
        if (!NT_SUCCESS(Status))
            goto Fail;
        for (j = 0; j < Lowbox->CapabilityCount; j++)
            Array[j].Sid = (PSID)(UserBase + ((PUCHAR)Array[j].Sid - Kernel));
        Offset += CapabilitiesSize;
    }

    Info->Privileges = (PTOKEN_PRIVILEGES)(UserBase + Offset);
    ((PTOKEN_PRIVILEGES)(Kernel + Offset))->PrivilegeCount = Token->PrivilegeCount;
    RtlCopyMemory(((PTOKEN_PRIVILEGES)(Kernel + Offset))->Privileges,
                  Token->Privileges,
                  Token->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES));
    Offset += PrivilegesSize;

    /* The AppContainer of a lowbox token: its number and package SID (the SID after the privileges) */
    if (Lowbox)
    {
        Info->AppContainerNumber = Lowbox->Number;
        Info->PackageSid = (PSID)(UserBase + Offset);
        RtlCopyMemory(Kernel + Offset, Lowbox->PackageSid, RtlLengthSid(Lowbox->PackageSid));
    }
    *Blob = Kernel;
    return STATUS_SUCCESS;

Fail:
    ExFreePoolWithTag(Kernel, TAG_TOKEN_DYNAMIC);
    return Status;
}

/* PUBLIC FUNCTIONS *****************************************************************/

/**
 * @brief
 * Queries information details about the given token to the call. The difference
 * between NtQueryInformationToken and this routine is that the system call has
 * user mode buffer data probing and additional protection checks whereas this
 * routine doesn't have any of these. The routine is used exclusively in kernel
 * mode.
 *
 * @param[in] AccessToken
 * An access token to be given.
 *
 * @param[in] TokenInformationClass
 * Token information class.
 *
 * @param[out] TokenInformation
 * Buffer with retrieved information. Such information is arbitrary, depending
 * on the requested information class.
 *
 * @return
 * Returns STATUS_SUCCESS if the operation to query the desired information
 * has completed successfully. STATUS_INSUFFICIENT_RESOURCES is returned if
 * pool memory allocation has failed to satisfy an operation. Otherwise
 * STATUS_INVALID_INFO_CLASS is returned indicating that the information
 * class provided is not supported by the routine.
 *
 * @remarks
 * Only certain information classes are not implemented in this function and
 * these are TokenOrigin, TokenGroupsAndPrivileges, TokenRestrictedSids and
 * TokenSandBoxInert. The following classes are implemented in NtQueryInformationToken
 * only.
 */
NTSTATUS
NTAPI
SeQueryInformationToken(
    _In_ PACCESS_TOKEN AccessToken,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Outptr_result_buffer_(_Inexpressible_(token-dependent)) PVOID *TokenInformation)
{
    NTSTATUS Status;
    PTOKEN Token = (PTOKEN)AccessToken;
    ULONG RequiredLength;
    union
    {
        PSID PSid;
        ULONG Ulong;
    } Unused;

    PAGED_CODE();

    /* Lock the token */
    SepAcquireTokenLockShared(Token);

    switch (TokenInformationClass)
    {
        case TokenUser:
        {
            PTOKEN_USER tu;

            DPRINT("SeQueryInformationToken(TokenUser)\n");
            RequiredLength = sizeof(TOKEN_USER) +
                RtlLengthSid(Token->UserAndGroups[0].Sid);

            /* Allocate the output buffer */
            tu = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (tu == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            Status = RtlCopySidAndAttributesArray(1,
                                                  &Token->UserAndGroups[0],
                                                  RequiredLength - sizeof(TOKEN_USER),
                                                  &tu->User,
                                                  (PSID)(tu + 1),
                                                  &Unused.PSid,
                                                  &Unused.Ulong);

            /* Return the structure */
            *TokenInformation = tu;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenGroups:
        {
            PTOKEN_GROUPS tg;
            ULONG SidLen;
            PSID Sid;

            DPRINT("SeQueryInformationToken(TokenGroups)\n");
            RequiredLength = FIELD_OFFSET(TOKEN_GROUPS, Groups) +
                RtlLengthSidAndAttributes(Token->UserAndGroupCount - 1, &Token->UserAndGroups[1]);

            SidLen = RequiredLength - FIELD_OFFSET(TOKEN_GROUPS, Groups) -
                ((Token->UserAndGroupCount - 1) * sizeof(SID_AND_ATTRIBUTES));

            /* Allocate the output buffer */
            tg = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (tg == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            Sid = (PSID)((ULONG_PTR)tg + FIELD_OFFSET(TOKEN_GROUPS, Groups) +
                         ((Token->UserAndGroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));

            tg->GroupCount = Token->UserAndGroupCount - 1;
            Status = RtlCopySidAndAttributesArray(Token->UserAndGroupCount - 1,
                                                  &Token->UserAndGroups[1],
                                                  SidLen,
                                                  &tg->Groups[0],
                                                  Sid,
                                                  &Unused.PSid,
                                                  &Unused.Ulong);

            /* Return the structure */
            *TokenInformation = tg;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenPrivileges:
        {
            PTOKEN_PRIVILEGES tp;

            DPRINT("SeQueryInformationToken(TokenPrivileges)\n");
            RequiredLength = sizeof(tp->PrivilegeCount) +
                (Token->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES));

            /* Allocate the output buffer */
            tp = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (tp == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            tp->PrivilegeCount = Token->PrivilegeCount;
            RtlCopyLuidAndAttributesArray(Token->PrivilegeCount,
                                          Token->Privileges,
                                          &tp->Privileges[0]);

            /* Return the structure */
            *TokenInformation = tp;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenOwner:
        {
            PTOKEN_OWNER to;
            ULONG SidLen;

            DPRINT("SeQueryInformationToken(TokenOwner)\n");
            SidLen = RtlLengthSid(Token->UserAndGroups[Token->DefaultOwnerIndex].Sid);
            RequiredLength = sizeof(TOKEN_OWNER) + SidLen;

            /* Allocate the output buffer */
            to = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (to == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            to->Owner = (PSID)(to + 1);
            Status = RtlCopySid(SidLen,
                                to->Owner,
                                Token->UserAndGroups[Token->DefaultOwnerIndex].Sid);

            /* Return the structure */
            *TokenInformation = to;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenPrimaryGroup:
        {
            PTOKEN_PRIMARY_GROUP tpg;
            ULONG SidLen;

            DPRINT("SeQueryInformationToken(TokenPrimaryGroup)\n");
            SidLen = RtlLengthSid(Token->PrimaryGroup);
            RequiredLength = sizeof(TOKEN_PRIMARY_GROUP) + SidLen;

            /* Allocate the output buffer */
            tpg = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (tpg == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            tpg->PrimaryGroup = (PSID)(tpg + 1);
            Status = RtlCopySid(SidLen,
                                tpg->PrimaryGroup,
                                Token->PrimaryGroup);

            /* Return the structure */
            *TokenInformation = tpg;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenDefaultDacl:
        {
            PTOKEN_DEFAULT_DACL tdd;

            DPRINT("SeQueryInformationToken(TokenDefaultDacl)\n");
            RequiredLength = sizeof(TOKEN_DEFAULT_DACL);

            if (Token->DefaultDacl != NULL)
                RequiredLength += Token->DefaultDacl->AclSize;

            /* Allocate the output buffer */
            tdd = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (tdd == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (Token->DefaultDacl != NULL)
            {
                tdd->DefaultDacl = (PACL)(tdd + 1);
                RtlCopyMemory(tdd->DefaultDacl,
                              Token->DefaultDacl,
                              Token->DefaultDacl->AclSize);
            }
            else
            {
                tdd->DefaultDacl = NULL;
            }

            /* Return the structure */
            *TokenInformation = tdd;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenSource:
        {
            PTOKEN_SOURCE ts;

            DPRINT("SeQueryInformationToken(TokenSource)\n");
            RequiredLength = sizeof(TOKEN_SOURCE);

            /* Allocate the output buffer */
            ts = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (ts == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            *ts = Token->TokenSource;

            /* Return the structure */
            *TokenInformation = ts;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenType:
        {
            PTOKEN_TYPE tt;

            DPRINT("SeQueryInformationToken(TokenType)\n");
            RequiredLength = sizeof(TOKEN_TYPE);

            /* Allocate the output buffer */
            tt = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (tt == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            *tt = Token->TokenType;

            /* Return the structure */
            *TokenInformation = tt;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenImpersonationLevel:
        {
            PSECURITY_IMPERSONATION_LEVEL sil;

            DPRINT("SeQueryInformationToken(TokenImpersonationLevel)\n");
            RequiredLength = sizeof(SECURITY_IMPERSONATION_LEVEL);

            /* Fail if the token is not an impersonation token */
            if (Token->TokenType != TokenImpersonation)
            {
                Status = STATUS_INVALID_INFO_CLASS;
                break;
            }

            /* Allocate the output buffer */
            sil = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (sil == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            *sil = Token->ImpersonationLevel;

            /* Return the structure */
            *TokenInformation = sil;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenStatistics:
        {
            PTOKEN_STATISTICS ts;

            DPRINT("SeQueryInformationToken(TokenStatistics)\n");
            RequiredLength = sizeof(TOKEN_STATISTICS);

            /* Allocate the output buffer */
            ts = ExAllocatePoolWithTag(PagedPool, RequiredLength, TAG_SE);
            if (ts == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            ts->TokenId = Token->TokenId;
            ts->AuthenticationId = Token->AuthenticationId;
            ts->ExpirationTime = Token->ExpirationTime;
            ts->TokenType = Token->TokenType;
            ts->ImpersonationLevel = Token->ImpersonationLevel;
            ts->DynamicCharged = Token->DynamicCharged;
            ts->DynamicAvailable = SepComputeAvailableDynamicSpace(Token->DynamicCharged, Token->PrimaryGroup, Token->DefaultDacl);
            ts->GroupCount = Token->UserAndGroupCount - 1;
            ts->PrivilegeCount = Token->PrivilegeCount;
            ts->ModifiedId = Token->ModifiedId;

            /* Return the structure */
            *TokenInformation = ts;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenElevationType:
        {
            PULONG tet;

            DPRINT("SeQueryInformationToken(TokenElevationType)\n");
            tet = ExAllocatePoolWithTag(PagedPool, sizeof(*tet), TAG_SE);
            if (tet == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            *tet = SEP_ELEVATION_TYPE_DEFAULT;
            *TokenInformation = tet;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenElevation:
        {
            PTOKEN_ELEVATION te;

            DPRINT("SeQueryInformationToken(TokenElevation)\n");
            te = ExAllocatePoolWithTag(PagedPool, sizeof(*te), TAG_SE);
            if (te == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            te->TokenIsElevated = SepIsTokenElevated(Token);
            *TokenInformation = te;
            Status = STATUS_SUCCESS;
            break;
        }

        case TokenSessionId:
        {
            DPRINT("SeQueryInformationToken(TokenSessionId)\n");
            Status = SeQuerySessionIdToken(Token, (PULONG)TokenInformation);
            break;
        }

        default:
            DPRINT1("SeQueryInformationToken(%d) invalid information class\n", TokenInformationClass);
            Status = STATUS_INVALID_INFO_CLASS;
            break;
    }

    /* Release the lock of the token */
    SepReleaseTokenLock(Token);

    return Status;
}

/* SYSTEM CALLS ***************************************************************/

/**
 * @brief
 * Queries a specific type of information in regard of an access token based upon
 * the information class. The calling thread must have specific access rights in order
 * to obtain specific information about the token.
 *
 * @param[in] TokenHandle
 * A handle of a token where information is to be gathered.
 *
 * @param[in] TokenInformationClass
 * Token information class.
 *
 * @param[out] TokenInformation
 * A returned output buffer with token information, which information is arbitrarily upon
 * the information class chosen.
 *
 * @param[in] TokenInformationLength
 * Length of the token information buffer, in bytes.
 *
 * @param[out] ReturnLength
 * A pointer to a variable provided by the caller that receives the actual length
 * of the buffer pointed by TokenInformation, in bytes. If TokenInformation is NULL
 * and TokenInformationLength is 0, this parameter receives the required length
 * needed to store the buffer information in memory. This parameter must not
 * be NULL!
 *
 * @return
 * Returns STATUS_SUCCESS if information querying has completed successfully.
 * STATUS_BUFFER_TOO_SMALL is returned if the information length that represents
 * the token information buffer is not greater than the required length.
 * STATUS_INVALID_HANDLE is returned if the token handle is not a valid one.
 * STATUS_INVALID_INFO_CLASS is returned if the information class is not a valid
 * one (that is, the class doesn't belong to TOKEN_INFORMATION_CLASS).
 * STATUS_ACCESS_VIOLATION is returned if ReturnLength is NULL. A failure NTSTATUS
 * code is returned otherwise.
 */
_Must_inspect_result_
__kernel_entry
NTSTATUS
NTAPI
NtQueryInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength)
        PVOID TokenInformation,
    _In_ ULONG TokenInformationLength,
    _Out_ PULONG ReturnLength)
{
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode;
    PTOKEN Token;
    ULONG RequiredLength = 0;
    union
    {
        PSID PSid;
        ULONG Ulong;
    } Unused;

    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();

    /* Check buffers and class validity */
    Status = DefaultQueryInfoBufferCheck(TokenInformationClass,
                                         SeTokenInformationClass,
                                         RTL_NUMBER_OF(SeTokenInformationClass),
                                         ICIF_PROBE_READ_WRITE | ICIF_FORCE_RETURN_LENGTH_PROBE,
                                         TokenInformation,
                                         TokenInformationLength,
                                         ReturnLength,
                                         NULL,
                                         PreviousMode);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("NtQueryInformationToken() failed, Status: 0x%x\n", Status);

        /* Windows reports the size these two classes insist on, along with the mismatch */
        if (Status == STATUS_INFO_LENGTH_MISMATCH &&
            (TokenInformationClass == TokenElevation || TokenInformationClass == TokenLinkedToken))
        {
            _SEH2_TRY
            {
                if (PreviousMode != KernelMode)
                    ProbeForWriteUlong(ReturnLength);
                *ReturnLength = SeTokenInformationClass[TokenInformationClass].RequiredSizeQUERY;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }

        return Status;
    }

    Status = SepReferenceTokenHandle(TokenHandle,
                                     (TokenInformationClass == TokenSource) ? TOKEN_QUERY_SOURCE : TOKEN_QUERY,
                                     PreviousMode,
                                     &Token,
                                     NULL);
    if (NT_SUCCESS(Status))
    {
        /* Lock the token */
        SepAcquireTokenLockShared(Token);

        switch (TokenInformationClass)
        {
            case TokenUser:
            {
                PTOKEN_USER tu = (PTOKEN_USER)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenUser)\n");
                RequiredLength = sizeof(TOKEN_USER) +
                    RtlLengthSid(Token->UserAndGroups[0].Sid);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        Status = RtlCopySidAndAttributesArray(1,
                                                              &Token->UserAndGroups[0],
                                                              RequiredLength - sizeof(TOKEN_USER),
                                                              &tu->User,
                                                              (PSID)(tu + 1),
                                                              &Unused.PSid,
                                                              &Unused.Ulong);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenGroups:
            {
                PTOKEN_GROUPS tg = (PTOKEN_GROUPS)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenGroups)\n");
                RequiredLength = FIELD_OFFSET(TOKEN_GROUPS, Groups) +
                    RtlLengthSidAndAttributes(Token->UserAndGroupCount - 1, &Token->UserAndGroups[1]);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        ULONG SidLen = RequiredLength - FIELD_OFFSET(TOKEN_GROUPS, Groups) -
                            ((Token->UserAndGroupCount - 1) * sizeof(SID_AND_ATTRIBUTES));
                        PSID Sid = (PSID_AND_ATTRIBUTES)((ULONG_PTR)tg + FIELD_OFFSET(TOKEN_GROUPS, Groups) +
                                                         ((Token->UserAndGroupCount - 1) * sizeof(SID_AND_ATTRIBUTES)));

                        tg->GroupCount = Token->UserAndGroupCount - 1;
                        Status = RtlCopySidAndAttributesArray(Token->UserAndGroupCount - 1,
                                                              &Token->UserAndGroups[1],
                                                              SidLen,
                                                              &tg->Groups[0],
                                                              Sid,
                                                              &Unused.PSid,
                                                              &Unused.Ulong);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenPrivileges:
            {
                PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenPrivileges)\n");
                RequiredLength = sizeof(tp->PrivilegeCount) +
                    (Token->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES));

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        tp->PrivilegeCount = Token->PrivilegeCount;
                        RtlCopyLuidAndAttributesArray(Token->PrivilegeCount,
                                                      Token->Privileges,
                                                      &tp->Privileges[0]);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenOwner:
            {
                PTOKEN_OWNER to = (PTOKEN_OWNER)TokenInformation;
                ULONG SidLen;

                DPRINT("NtQueryInformationToken(TokenOwner)\n");
                SidLen = RtlLengthSid(Token->UserAndGroups[Token->DefaultOwnerIndex].Sid);
                RequiredLength = sizeof(TOKEN_OWNER) + SidLen;

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        to->Owner = (PSID)(to + 1);
                        Status = RtlCopySid(SidLen,
                                            to->Owner,
                                            Token->UserAndGroups[Token->DefaultOwnerIndex].Sid);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                   *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenPrimaryGroup:
            {
                PTOKEN_PRIMARY_GROUP tpg = (PTOKEN_PRIMARY_GROUP)TokenInformation;
                ULONG SidLen;

                DPRINT("NtQueryInformationToken(TokenPrimaryGroup)\n");
                SidLen = RtlLengthSid(Token->PrimaryGroup);
                RequiredLength = sizeof(TOKEN_PRIMARY_GROUP) + SidLen;

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        tpg->PrimaryGroup = (PSID)(tpg + 1);
                        Status = RtlCopySid(SidLen,
                                            tpg->PrimaryGroup,
                                            Token->PrimaryGroup);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenDefaultDacl:
            {
                PTOKEN_DEFAULT_DACL tdd = (PTOKEN_DEFAULT_DACL)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenDefaultDacl)\n");
                RequiredLength = sizeof(TOKEN_DEFAULT_DACL);

                if (Token->DefaultDacl != NULL)
                    RequiredLength += Token->DefaultDacl->AclSize;

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        if (Token->DefaultDacl != NULL)
                        {
                            tdd->DefaultDacl = (PACL)(tdd + 1);
                            RtlCopyMemory(tdd->DefaultDacl,
                                          Token->DefaultDacl,
                                          Token->DefaultDacl->AclSize);
                        }
                        else
                        {
                            tdd->DefaultDacl = NULL;
                        }
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenSource:
            {
                PTOKEN_SOURCE ts = (PTOKEN_SOURCE)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenSource)\n");
                RequiredLength = sizeof(TOKEN_SOURCE);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        *ts = Token->TokenSource;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                   *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenType:
            {
                PTOKEN_TYPE tt = (PTOKEN_TYPE)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenType)\n");
                RequiredLength = sizeof(TOKEN_TYPE);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        *tt = Token->TokenType;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenImpersonationLevel:
            {
                PSECURITY_IMPERSONATION_LEVEL sil = (PSECURITY_IMPERSONATION_LEVEL)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenImpersonationLevel)\n");

                /* Fail if the token is not an impersonation token */
                if (Token->TokenType != TokenImpersonation)
                {
                    Status = STATUS_INVALID_INFO_CLASS;
                    break;
                }

                RequiredLength = sizeof(SECURITY_IMPERSONATION_LEVEL);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        *sil = Token->ImpersonationLevel;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenStatistics:
            {
                PTOKEN_STATISTICS ts = (PTOKEN_STATISTICS)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenStatistics)\n");
                RequiredLength = sizeof(TOKEN_STATISTICS);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        ts->TokenId = Token->TokenId;
                        ts->AuthenticationId = Token->AuthenticationId;
                        ts->ExpirationTime = Token->ExpirationTime;
                        ts->TokenType = Token->TokenType;
                        ts->ImpersonationLevel = Token->ImpersonationLevel;
                        ts->DynamicCharged = Token->DynamicCharged;
                        ts->DynamicAvailable = SepComputeAvailableDynamicSpace(Token->DynamicCharged, Token->PrimaryGroup, Token->DefaultDacl);
                        ts->GroupCount = Token->UserAndGroupCount - 1;
                        ts->PrivilegeCount = Token->PrivilegeCount;
                        ts->ModifiedId = Token->ModifiedId;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenOrigin:
            {
                PTOKEN_ORIGIN to = (PTOKEN_ORIGIN)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenOrigin)\n");
                RequiredLength = sizeof(TOKEN_ORIGIN);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        to->OriginatingLogonSession = Token->AuthenticationId;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenGroupsAndPrivileges:
            {
                PSID Sid, RestrictedSid;
                ULONG SidLen, RestrictedSidLen;
                ULONG UserGroupLength, RestrictedSidLength, PrivilegeLength;
                PTOKEN_GROUPS_AND_PRIVILEGES GroupsAndPrivs = (PTOKEN_GROUPS_AND_PRIVILEGES)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenGroupsAndPrivileges)\n");
                UserGroupLength = RtlLengthSidAndAttributes(Token->UserAndGroupCount, Token->UserAndGroups);
                RestrictedSidLength = RtlLengthSidAndAttributes(Token->RestrictedSidCount, Token->RestrictedSids);
                PrivilegeLength = Token->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES);

                RequiredLength = sizeof(TOKEN_GROUPS_AND_PRIVILEGES) +
                                 UserGroupLength + RestrictedSidLength + PrivilegeLength;

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        GroupsAndPrivs->SidCount = Token->UserAndGroupCount;
                        GroupsAndPrivs->SidLength = UserGroupLength;
                        GroupsAndPrivs->Sids = (PSID_AND_ATTRIBUTES)(GroupsAndPrivs + 1);

                        Sid = (PSID)((ULONG_PTR)GroupsAndPrivs->Sids + (Token->UserAndGroupCount * sizeof(SID_AND_ATTRIBUTES)));
                        SidLen = UserGroupLength - (Token->UserAndGroupCount * sizeof(SID_AND_ATTRIBUTES));
                        Status = RtlCopySidAndAttributesArray(Token->UserAndGroupCount,
                                                              Token->UserAndGroups,
                                                              SidLen,
                                                              GroupsAndPrivs->Sids,
                                                              Sid,
                                                              &Unused.PSid,
                                                              &Unused.Ulong);
                        NT_ASSERT(NT_SUCCESS(Status));

                        GroupsAndPrivs->RestrictedSidCount = Token->RestrictedSidCount;
                        GroupsAndPrivs->RestrictedSidLength = RestrictedSidLength;
                        GroupsAndPrivs->RestrictedSids = NULL;
                        if (SeTokenIsRestricted(Token))
                        {
                            GroupsAndPrivs->RestrictedSids = (PSID_AND_ATTRIBUTES)((ULONG_PTR)GroupsAndPrivs->Sids + UserGroupLength);

                            RestrictedSid = (PSID)((ULONG_PTR)GroupsAndPrivs->RestrictedSids + (Token->RestrictedSidCount * sizeof(SID_AND_ATTRIBUTES)));
                            RestrictedSidLen = RestrictedSidLength - (Token->RestrictedSidCount * sizeof(SID_AND_ATTRIBUTES));
                            Status = RtlCopySidAndAttributesArray(Token->RestrictedSidCount,
                                                                  Token->RestrictedSids,
                                                                  RestrictedSidLen,
                                                                  GroupsAndPrivs->RestrictedSids,
                                                                  RestrictedSid,
                                                                  &Unused.PSid,
                                                                  &Unused.Ulong);
                            NT_ASSERT(NT_SUCCESS(Status));
                        }

                        GroupsAndPrivs->PrivilegeCount = Token->PrivilegeCount;
                        GroupsAndPrivs->PrivilegeLength = PrivilegeLength;
                        GroupsAndPrivs->Privileges = (PLUID_AND_ATTRIBUTES)((ULONG_PTR)(GroupsAndPrivs + 1) +
                                                     UserGroupLength + RestrictedSidLength);
                        RtlCopyLuidAndAttributesArray(Token->PrivilegeCount,
                                                      Token->Privileges,
                                                      GroupsAndPrivs->Privileges);

                        GroupsAndPrivs->AuthenticationId = Token->AuthenticationId;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenRestrictedSids:
            {
                PTOKEN_GROUPS tg = (PTOKEN_GROUPS)TokenInformation;

                DPRINT("NtQueryInformationToken(TokenRestrictedSids)\n");
                RequiredLength = FIELD_OFFSET(TOKEN_GROUPS, Groups) +
                RtlLengthSidAndAttributes(Token->RestrictedSidCount, Token->RestrictedSids);

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        ULONG SidLen = RequiredLength - FIELD_OFFSET(TOKEN_GROUPS, Groups) -
                            (Token->RestrictedSidCount * sizeof(SID_AND_ATTRIBUTES));
                        PSID Sid = (PSID)((ULONG_PTR)tg + FIELD_OFFSET(TOKEN_GROUPS, Groups) +
                                          (Token->RestrictedSidCount * sizeof(SID_AND_ATTRIBUTES)));

                        tg->GroupCount = Token->RestrictedSidCount;
                        Status = RtlCopySidAndAttributesArray(Token->RestrictedSidCount,
                                                              Token->RestrictedSids,
                                                              SidLen,
                                                              &tg->Groups[0],
                                                              Sid,
                                                              &Unused.PSid,
                                                              &Unused.Ulong);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenSandBoxInert:
            {
                ULONG IsTokenSandBoxInert;

                DPRINT("NtQueryInformationToken(TokenSandBoxInert)\n");

                IsTokenSandBoxInert = SeTokenIsInert(Token);
                RequiredLength = sizeof(ULONG);
                _SEH2_TRY
                {
                    /* A larger buffer is fine; a smaller one has failed the class check already, or is NULL */
                    if (TokenInformationLength >= RequiredLength)
                        *(PULONG)TokenInformation = IsTokenSandBoxInert;
                    else
                        Status = STATUS_BUFFER_TOO_SMALL;

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenSessionId:
            {
                ULONG SessionId = 0;

                DPRINT("NtQueryInformationToken(TokenSessionId)\n");

                RequiredLength = sizeof(ULONG);
                Status = SeQuerySessionIdToken(Token, &SessionId);
                if (NT_SUCCESS(Status))
                {
                    _SEH2_TRY
                    {
                        if (TokenInformationLength >= RequiredLength)
                            *(PULONG)TokenInformation = SessionId;
                        else
                            Status = STATUS_BUFFER_TOO_SMALL;

                        *ReturnLength = RequiredLength;
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        Status = _SEH2_GetExceptionCode();
                    }
                    _SEH2_END;
                }

                break;
            }

            /*
             * Classes that report a single ULONG. Without UAC every token has the
             * default elevation type, UI access and virtualization are token
             * flags (never set here), the mandatory policy is the same for all
             * tokens and a lowbox token belongs to an AppContainer.
             */
            case TokenElevationType:
            case TokenElevation:
            case TokenVirtualizationAllowed:
            case TokenVirtualizationEnabled:
            case TokenUIAccess:
            case TokenMandatoryPolicy:
            case TokenIsAppContainer:
            {
                ULONG Value;

                DPRINT("NtQueryInformationToken(%d)\n", TokenInformationClass);
                RequiredLength = sizeof(ULONG);
                switch (TokenInformationClass)
                {
                    case TokenElevationType:
                        Value = SEP_ELEVATION_TYPE_DEFAULT;
                        break;
                    case TokenElevation:
                        Value = SepIsTokenElevated(Token);
                        break;
                    case TokenVirtualizationAllowed:
                        Value = !!(Token->TokenFlags & TOKEN_VIRTUALIZE_ALLOWED);
                        break;
                    case TokenVirtualizationEnabled:
                        Value = !!(Token->TokenFlags & TOKEN_VIRTUALIZE_ENABLED);
                        break;
                    case TokenUIAccess:
                        Value = !!(Token->TokenFlags & TOKEN_UIACCESS);
                        break;
                    case TokenMandatoryPolicy:
                        Value = SEP_MANDATORY_POLICY_DEFAULT;
                        break;
                    case TokenIsAppContainer:
                        Value = (Token->Lowbox != NULL);
                        break;
                    default:
                        Value = FALSE;
                        break;
                }

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        *(PULONG)TokenInformation = Value;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            /*
             * Only a UAC split token has a linked token. Windows answers
             * STATUS_NO_SUCH_LOGON_SESSION for any other, which is every token here.
             */
            case TokenLinkedToken:
            {
                DPRINT("NtQueryInformationToken(TokenLinkedToken)\n");

                _SEH2_TRY
                {
                    *ReturnLength = sizeof(HANDLE);
                    Status = STATUS_NO_SUCH_LOGON_SESSION;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenHasRestrictions:
            {
                BOOLEAN HasRestrictions;

                DPRINT("NtQueryInformationToken(TokenHasRestrictions)\n");
                RequiredLength = sizeof(BOOLEAN);

                /* Every token NtFilterToken made reports it, restricting SIDs or not (measured on Windows 10) */
                HasRestrictions = ((Token->TokenFlags & TOKEN_IS_FILTERED) || Token->RestrictedSidCount > 0) ? TRUE : FALSE;

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        *(PBOOLEAN)TokenInformation = HasRestrictions;
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenIntegrityLevel:
            {
                PTOKEN_MANDATORY_LABEL Label = (PTOKEN_MANDATORY_LABEL)TokenInformation;
                PSID LabelSid = (PSID)(Label + 1);

                DPRINT("NtQueryInformationToken(TokenIntegrityLevel)\n");

                RequiredLength = sizeof(TOKEN_MANDATORY_LABEL) + SEP_MANDATORY_LABEL_SID_LENGTH;

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        /* The SID goes right after the structure; never read the pointer back from the caller's buffer */
                        Label->Label.Sid = LabelSid;
                        Label->Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
                        SepInitializeMandatoryLabelSid(LabelSid, Token->IntegrityLevel);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenLogonSid:
            {
                PTOKEN_GROUPS tg = (PTOKEN_GROUPS)TokenInformation;
                PSID_AND_ATTRIBUTES LogonGroup = NULL;
                ULONG i;

                DPRINT("NtQueryInformationToken(TokenLogonSid)\n");

                /* The first group marked as the logon SID; a token without one has nothing to report */
                for (i = 1; i < Token->UserAndGroupCount; i++)
                {
                    if ((Token->UserAndGroups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                    {
                        LogonGroup = &Token->UserAndGroups[i];
                        break;
                    }
                }

                if (!LogonGroup)
                {
                    Status = STATUS_NOT_FOUND;
                    break;
                }

                RequiredLength = FIELD_OFFSET(TOKEN_GROUPS, Groups[1]) + RtlLengthSid(LogonGroup->Sid);

                _SEH2_TRY
                {
                    /* Windows stores the length first; a result sharing its storage wins */
                    *ReturnLength = RequiredLength;
                    if (TokenInformationLength >= RequiredLength)
                    {
                        tg->GroupCount = 1;
                        Status = RtlCopySidAndAttributesArray(1,
                                                              LogonGroup,
                                                              RequiredLength - FIELD_OFFSET(TOKEN_GROUPS, Groups[1]),
                                                              &tg->Groups[0],
                                                              (PSID)&tg->Groups[1],
                                                              &Unused.PSid,
                                                              &Unused.Ulong);
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            case TokenAccessInformation:
            {
                DPRINT("NtQueryInformationToken(TokenAccessInformation)\n");

                {
                    PUCHAR Blob;

                    /* Built in pool; the user buffer was probed for write over its whole length by the class check */
                    Status = SepBuildTokenAccessInformation(Token,
                                                            (PUCHAR)TokenInformation,
                                                            TokenInformationLength,
                                                            &RequiredLength,
                                                            &Blob);
                    _SEH2_TRY
                    {
                        if (NT_SUCCESS(Status))
                        {
                            RtlCopyMemory(TokenInformation, Blob, RequiredLength);
                            *ReturnLength = RequiredLength;
                        }
                        else if (Status == STATUS_BUFFER_TOO_SMALL)
                        {
                            *ReturnLength = RequiredLength;
                        }
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        Status = _SEH2_GetExceptionCode();
                    }
                    _SEH2_END;

                    if (Blob)
                        ExFreePoolWithTag(Blob, TAG_TOKEN_DYNAMIC);
                }

                break;
            }

            /*
             * The AppContainer classes answer from the lowbox data. Any other
             * token has no capabilities (a TOKEN_GROUPS with no group; Windows
             * writes the count only), a NULL AppContainer SID and number 0.
             * TOKEN_APPCONTAINER_INFORMATION is a SID pointer followed by the
             * SID it points to, like TOKEN_USER.
             */
            case SepTokenCapabilities:
            case SepTokenAppContainerSid:
            case SepTokenAppContainerNumber:
            case SepTokenIsRestricted:
            case SepTokenProcessTrustLevel:
            {
                PSEP_LOWBOX Lowbox = Token->Lowbox;

                DPRINT("NtQueryInformationToken(%d)\n", TokenInformationClass);

                switch (TokenInformationClass)
                {
                    case SepTokenCapabilities:
                        RequiredLength = FIELD_OFFSET(TOKEN_GROUPS, Groups);
                        if (Lowbox && Lowbox->CapabilityCount > 0)
                        {
                            RequiredLength += RtlLengthSidAndAttributes(Lowbox->CapabilityCount,
                                                                        Lowbox->Capabilities);
                        }
                        break;
                    case SepTokenAppContainerSid:
                        RequiredLength = sizeof(PVOID);
                        if (Lowbox)
                            RequiredLength += RtlLengthSid(Lowbox->PackageSid);
                        break;
                    case SepTokenProcessTrustLevel:
                        RequiredLength = sizeof(PVOID);
                        break;
                    default:
                        RequiredLength = sizeof(ULONG);
                        break;
                }

                _SEH2_TRY
                {
                    if (TokenInformationLength >= RequiredLength)
                    {
                        switch (TokenInformationClass)
                        {
                            case SepTokenCapabilities:
                            {
                                PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)TokenInformation;

                                Groups->GroupCount = Lowbox ? Lowbox->CapabilityCount : 0;
                                if (Lowbox && Lowbox->CapabilityCount > 0)
                                {
                                    ULONG ArrayLength = Lowbox->CapabilityCount * sizeof(SID_AND_ATTRIBUTES);

                                    Status = RtlCopySidAndAttributesArray(Lowbox->CapabilityCount,
                                                                          Lowbox->Capabilities,
                                                                          RequiredLength - FIELD_OFFSET(TOKEN_GROUPS, Groups) - ArrayLength,
                                                                          &Groups->Groups[0],
                                                                          (PSID)((PUCHAR)&Groups->Groups[0] + ArrayLength),
                                                                          &Unused.PSid,
                                                                          &Unused.Ulong);
                                }
                                break;
                            }
                            case SepTokenAppContainerSid:
                                if (Lowbox)
                                {
                                    PSID Sid = (PSID)((PUCHAR)TokenInformation + sizeof(PVOID));

                                    RtlCopyMemory(Sid, Lowbox->PackageSid, RtlLengthSid(Lowbox->PackageSid));
                                    *(PVOID *)TokenInformation = Sid;
                                }
                                else
                                {
                                    *(PVOID *)TokenInformation = NULL;
                                }
                                break;
                            case SepTokenProcessTrustLevel:
                                *(PVOID *)TokenInformation = NULL;
                                break;
                            case SepTokenAppContainerNumber:
                                *(PULONG)TokenInformation = Lowbox ? Lowbox->Number : 0;
                                break;
                            case SepTokenIsRestricted:
                                *(PULONG)TokenInformation = !!(Token->TokenFlags & TOKEN_IS_RESTRICTED);
                                break;
                            default:
                                *(PULONG)TokenInformation = 0;
                                break;
                        }
                    }
                    else
                    {
                        Status = STATUS_BUFFER_TOO_SMALL;
                    }

                    *ReturnLength = RequiredLength;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                }
                _SEH2_END;

                break;
            }

            default:
                DPRINT1("NtQueryInformationToken(%d) invalid information class\n", TokenInformationClass);
                Status = STATUS_INVALID_INFO_CLASS;
                break;
        }

        /* Unlock and dereference the token */
        SepReleaseTokenLock(Token);
        ObDereferenceObject(Token);
    }

    return Status;
}

/**
 * @unimplemented
 * @brief
 * Sets (modifies) some specific information in regard of an access token. The
 * calling thread must have specific access rights in order to modify token's
 * information data.
 *
 * @param[in] TokenHandle
 * A handle of a token where information is to be modified.
 *
 * @param[in] TokenInformationClass
 * Token information class.
 *
 * @param[in] TokenInformation
 * An arbitrary pointer to a buffer with token information to set. Such
 * arbitrary buffer depends on the information class chosen that the caller
 * wants to modify such information data of a token.
 *
 * @param[in] TokenInformationLength
 * Length of the token information buffer, in bytes.
 *
 * @return
 * Returns STATUS_SUCCESS if information setting has completed successfully.
 * STATUS_INFO_LENGTH_MISMATCH is returned if the information length of the
 * buffer is less than the required length. STATUS_INSUFFICIENT_RESOURCES is
 * returned if memory pool allocation has failed. STATUS_PRIVILEGE_NOT_HELD
 * is returned if the calling thread hasn't the required privileges to perform
 * the operation in question. A failure NTSTATUS code is returned otherwise.
 *
 * @remarks
 * The function is partly implemented, mainly TokenOrigin.
 */
_Must_inspect_result_
__kernel_entry
NTSTATUS
NTAPI
NtSetInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength)
{
    NTSTATUS Status;
    PTOKEN Token;
    KPROCESSOR_MODE PreviousMode;
    ULONG NeededAccess = TOKEN_ADJUST_DEFAULT;

    PAGED_CODE();

    PreviousMode = ExGetPreviousMode();

    Status = DefaultSetInfoBufferCheck(TokenInformationClass,
                                       SeTokenInformationClass,
                                       RTL_NUMBER_OF(SeTokenInformationClass),
                                       TokenInformation,
                                       TokenInformationLength,
                                       PreviousMode);
    if (!NT_SUCCESS(Status))
    {
        /* Invalid buffers */
        DPRINT("NtSetInformationToken() failed, Status: 0x%x\n", Status);
        return Status;
    }

    if (TokenInformationClass == TokenSessionId)
    {
        NeededAccess |= TOKEN_ADJUST_SESSIONID;
    }

    Status = ObReferenceObjectByHandle(TokenHandle,
                                       NeededAccess,
                                       SeTokenObjectType,
                                       PreviousMode,
                                       (PVOID*)&Token,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        switch (TokenInformationClass)
        {
            case TokenOwner:
            {
                if (TokenInformationLength >= sizeof(TOKEN_OWNER))
                {
                    PTOKEN_OWNER to = (PTOKEN_OWNER)TokenInformation;
                    PSID InputSid = NULL, CapturedSid;
                    ULONG DefaultOwnerIndex;

                    _SEH2_TRY
                    {
                        InputSid = to->Owner;
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        Status = _SEH2_GetExceptionCode();
                        _SEH2_YIELD(goto Cleanup);
                    }
                    _SEH2_END;

                    Status = SepCaptureSid(InputSid,
                                           PreviousMode,
                                           PagedPool,
                                           FALSE,
                                           &CapturedSid);
                    if (NT_SUCCESS(Status))
                    {
                        /* Lock the token */
                        SepAcquireTokenLockExclusive(Token);

                        /* Find the owner amongst the existing token user and groups */
                        Status = SepFindPrimaryGroupAndDefaultOwner(Token,
                                                                    NULL,
                                                                    CapturedSid,
                                                                    NULL,
                                                                    &DefaultOwnerIndex);
                        if (NT_SUCCESS(Status))
                        {
                            /* Found it */
                            Token->DefaultOwnerIndex = DefaultOwnerIndex;
                            ExAllocateLocallyUniqueId(&Token->ModifiedId);
                        }

                        /* Unlock the token */
                        SepReleaseTokenLock(Token);

                        SepReleaseSid(CapturedSid,
                                      PreviousMode,
                                      FALSE);
                    }
                }
                else
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                }
                break;
            }

            case TokenPrimaryGroup:
            {
                if (TokenInformationLength >= sizeof(TOKEN_PRIMARY_GROUP))
                {
                    PTOKEN_PRIMARY_GROUP tpg = (PTOKEN_PRIMARY_GROUP)TokenInformation;
                    ULONG AclSize;
                    ULONG_PTR PrimaryGroup;
                    PSID InputSid = NULL, CapturedSid;
                    ULONG PrimaryGroupIndex, NewDynamicLength;

                    _SEH2_TRY
                    {
                        InputSid = tpg->PrimaryGroup;
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        Status = _SEH2_GetExceptionCode();
                        _SEH2_YIELD(goto Cleanup);
                    }
                    _SEH2_END;

                    Status = SepCaptureSid(InputSid,
                                           PreviousMode,
                                           PagedPool,
                                           FALSE,
                                           &CapturedSid);
                    if (NT_SUCCESS(Status))
                    {
                        /* Lock the token */
                        SepAcquireTokenLockExclusive(Token);

                        /*
                         * We can whack the token's primary group only if
                         * the charged dynamic space boundary allows us
                         * to do so. Exceeding this boundary and we're
                         * busted out.
                         */
                        AclSize = Token->DefaultDacl ? Token->DefaultDacl->AclSize : 0;
                        NewDynamicLength = RtlLengthSid(CapturedSid) + AclSize;
                        if (NewDynamicLength > Token->DynamicCharged)
                        {
                            SepReleaseTokenLock(Token);
                            SepReleaseSid(CapturedSid, PreviousMode, FALSE);
                            Status = STATUS_ALLOTTED_SPACE_EXCEEDED;
                            DPRINT1("NtSetInformationToken(): Couldn't assign new primary group, space exceeded (current length %u, new length %lu)\n",
                                    Token->DynamicCharged, NewDynamicLength);
                            goto Cleanup;
                        }

                        /*
                         * The dynamic part of the token may require a rebuild
                         * if the current dynamic area is too small. If not then
                         * we're pretty much good as is.
                         */
                        Status = SepRebuildDynamicPartOfToken(Token, NewDynamicLength);
                        if (NT_SUCCESS(Status))
                        {
                            /* Find the primary group amongst the existing token user and groups */
                            Status = SepFindPrimaryGroupAndDefaultOwner(Token,
                                                                        CapturedSid,
                                                                        NULL,
                                                                        &PrimaryGroupIndex,
                                                                        NULL);
                            if (NT_SUCCESS(Status))
                            {
                                /*
                                 * We have found it. Add the length of
                                 * the previous primary group SID to the
                                 * available dynamic area.
                                 */
                                Token->DynamicAvailable += RtlLengthSid(Token->PrimaryGroup);

                                /*
                                 * Move the default DACL if it's not at the
                                 * head of the dynamic part.
                                 */
                                if ((Token->DefaultDacl) &&
                                    ((PULONG)(Token->DefaultDacl) != Token->DynamicPart))
                                {
                                    RtlMoveMemory(Token->DynamicPart,
                                                  Token->DefaultDacl,
                                                  RtlLengthSid(Token->PrimaryGroup));
                                    Token->DefaultDacl = (PACL)(Token->DynamicPart);
                                }

                                /* Take away available space from the dynamic area */
                                Token->DynamicAvailable -= RtlLengthSid(Token->UserAndGroups[PrimaryGroupIndex].Sid);

                                /*
                                 * And assign the new primary group. For that
                                 * we have to make sure where the primary group
                                 * is going to stay in memory, so if this token
                                 * has a default DACL then add up its size with
                                 * the address of the dynamic part.
                                 */
                                PrimaryGroup = (ULONG_PTR)(Token->DynamicPart) + AclSize;
                                RtlCopySid(RtlLengthSid(Token->UserAndGroups[PrimaryGroupIndex].Sid),
                                           (PVOID)PrimaryGroup,
                                           Token->UserAndGroups[PrimaryGroupIndex].Sid);
                                Token->PrimaryGroup = (PSID)PrimaryGroup;

                                ExAllocateLocallyUniqueId(&Token->ModifiedId);
                            }
                        }

                        /* Unlock the token */
                        SepReleaseTokenLock(Token);

                        SepReleaseSid(CapturedSid,
                                      PreviousMode,
                                      FALSE);
                    }
                }
                else
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                }
                break;
            }

            case TokenDefaultDacl:
            {
                if (TokenInformationLength >= sizeof(TOKEN_DEFAULT_DACL))
                {
                    PTOKEN_DEFAULT_DACL tdd = (PTOKEN_DEFAULT_DACL)TokenInformation;
                    PACL InputAcl = NULL;

                    _SEH2_TRY
                    {
                        InputAcl = tdd->DefaultDacl;
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        Status = _SEH2_GetExceptionCode();
                        _SEH2_YIELD(goto Cleanup);
                    }
                    _SEH2_END;

                    if (InputAcl != NULL)
                    {
                        PACL CapturedAcl;

                        /* Capture, validate, and copy the DACL */
                        Status = SepCaptureAcl(InputAcl,
                                               PreviousMode,
                                               PagedPool,
                                               TRUE,
                                               &CapturedAcl);
                        if (NT_SUCCESS(Status))
                        {
                            ULONG NewDynamicLength;
                            ULONG_PTR Acl;

                            /* Lock the token */
                            SepAcquireTokenLockExclusive(Token);

                            /*
                             * We can whack the token's default DACL only if
                             * the charged dynamic space boundary allows us
                             * to do so. Exceeding this boundary and we're
                             * busted out.
                             */
                            NewDynamicLength = CapturedAcl->AclSize + RtlLengthSid(Token->PrimaryGroup);
                            if (NewDynamicLength > Token->DynamicCharged)
                            {
                                SepReleaseTokenLock(Token);
                                SepReleaseAcl(CapturedAcl, PreviousMode, TRUE);
                                Status = STATUS_ALLOTTED_SPACE_EXCEEDED;
                                DPRINT1("NtSetInformationToken(): Couldn't assign new default DACL, space exceeded (current length %u, new length %lu)\n",
                                        Token->DynamicCharged, NewDynamicLength);
                                goto Cleanup;
                            }

                            /*
                             * The dynamic part of the token may require a rebuild
                             * if the current dynamic area is too small. If not then
                             * we're pretty much good as is.
                             */
                            Status = SepRebuildDynamicPartOfToken(Token, NewDynamicLength);
                            if (NT_SUCCESS(Status))
                            {
                                /*
                                 * Before setting up a new DACL for the
                                 * token object we add up the size of
                                 * the old DACL to the available dynamic
                                 * area
                                 */
                                if (Token->DefaultDacl)
                                {
                                    Token->DynamicAvailable += Token->DefaultDacl->AclSize;
                                }

                                /*
                                 * Move the primary group if it's not at the
                                 * head of the dynamic part.
                                 */
                                if ((PULONG)(Token->PrimaryGroup) != Token->DynamicPart)
                                {
                                    RtlMoveMemory(Token->DynamicPart,
                                                  Token->PrimaryGroup,
                                                  RtlLengthSid(Token->PrimaryGroup));
                                    Token->PrimaryGroup = (PSID)(Token->DynamicPart);
                                }

                                /* Take away available space from the dynamic area */
                                Token->DynamicAvailable -= CapturedAcl->AclSize;

                                /* Set the new dacl */
                                Acl = (ULONG_PTR)(Token->DynamicPart) + RtlLengthSid(Token->PrimaryGroup);
                                RtlCopyMemory((PVOID)Acl,
                                              CapturedAcl,
                                              CapturedAcl->AclSize);
                                Token->DefaultDacl = (PACL)Acl;

                                ExAllocateLocallyUniqueId(&Token->ModifiedId);
                            }

                            /* Unlock the token and release the ACL */
                            SepReleaseTokenLock(Token);
                            SepReleaseAcl(CapturedAcl, PreviousMode, TRUE);
                        }
                    }
                    else
                    {
                        /* Lock the token */
                        SepAcquireTokenLockExclusive(Token);

                        /* Clear the default dacl if present */
                        if (Token->DefaultDacl != NULL)
                        {
                            Token->DynamicAvailable += Token->DefaultDacl->AclSize;
                            RtlZeroMemory(Token->DefaultDacl, Token->DefaultDacl->AclSize);
                            Token->DefaultDacl = NULL;

                            ExAllocateLocallyUniqueId(&Token->ModifiedId);
                        }

                        /* Unlock the token */
                        SepReleaseTokenLock(Token);
                    }
                }
                else
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                }
                break;
            }

            case TokenSessionId:
            {
                ULONG SessionId = 0;

                _SEH2_TRY
                {
                    /* Buffer size was already verified, no need to check here again */
                    SessionId = *(PULONG)TokenInformation;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                    _SEH2_YIELD(goto Cleanup);
                }
                _SEH2_END;

                /* Check for TCB privilege */
                if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
                {
                    Status = STATUS_PRIVILEGE_NOT_HELD;
                    break;
                }

                /* Lock the token */
                SepAcquireTokenLockExclusive(Token);

                Token->SessionId = SessionId;
                ExAllocateLocallyUniqueId(&Token->ModifiedId);

                /* Unlock the token */
                SepReleaseTokenLock(Token);

                break;
            }

            case TokenIntegrityLevel:
            {
                ULONG LabelSid[(FIELD_OFFSET(SID, SubAuthority[1]) + sizeof(ULONG) - 1) / sizeof(ULONG)];
                PISID InputSid;
                BOOLEAN HasTcb = FALSE;
                ULONG Rid, Level, i;

                if (TokenInformationLength < sizeof(TOKEN_MANDATORY_LABEL))
                {
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }

                /* A mandatory label SID has one sub-authority: capture exactly that much */
                _SEH2_TRY
                {
                    InputSid = ((PTOKEN_MANDATORY_LABEL)TokenInformation)->Label.Sid;
                    if (PreviousMode != KernelMode)
                        ProbeForRead(InputSid, SEP_MANDATORY_LABEL_SID_LENGTH, sizeof(UCHAR));
                    RtlCopyMemory(LabelSid, InputSid, SEP_MANDATORY_LABEL_SID_LENGTH);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                    _SEH2_YIELD(goto Cleanup);
                }
                _SEH2_END;

                if (!SepIsMandatoryLabelSid((PSID)LabelSid, &Rid))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }

                /* A token can be lowered freely; raising it needs the TCB privilege, checked before the token is locked */
                SepAcquireTokenLockShared(Token);
                Level = Token->IntegrityLevel;
                SepReleaseTokenLock(Token);
                if (Rid > Level)
                    HasTcb = SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode);

                SepAcquireTokenLockExclusive(Token);
                if (Rid > Token->IntegrityLevel && !HasTcb)
                {
                    Status = STATUS_PRIVILEGE_NOT_HELD;
                }
                else
                {
                    /* An integrity group the token was created with follows the level (same size SID, changed in place) */
                    Token->IntegrityLevel = Rid;
                    for (i = 1; i < Token->UserAndGroupCount; i++)
                    {
                        if ((Token->UserAndGroups[i].Attributes & SE_GROUP_INTEGRITY) &&
                            SepIsMandatoryLabelSid(Token->UserAndGroups[i].Sid, NULL))
                        {
                            *RtlSubAuthoritySid(Token->UserAndGroups[i].Sid, 0) = Rid;
                        }
                    }
                    ExAllocateLocallyUniqueId(&Token->ModifiedId);
                }
                SepReleaseTokenLock(Token);
                break;
            }

            case TokenSessionReference:
            {
                ULONG SessionReference;

                _SEH2_TRY
                {
                    /* Buffer size was already verified, no need to check here again */
                    SessionReference = *(PULONG)TokenInformation;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                    _SEH2_YIELD(goto Cleanup);
                }
                _SEH2_END;

                /* Check for TCB privilege */
                if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
                {
                    Status = STATUS_PRIVILEGE_NOT_HELD;
                    goto Cleanup;
                }

                /* Check if it is 0 */
                if (SessionReference == 0)
                {
                    ULONG OldTokenFlags;

                    /* Lock the token */
                    SepAcquireTokenLockExclusive(Token);

                    /* Atomically set the flag in the token */
                    OldTokenFlags = RtlInterlockedSetBits(&Token->TokenFlags,
                                                          TOKEN_SESSION_NOT_REFERENCED);
                    /*
                     * If the flag was already set, do not dereference again
                     * the logon session. Use SessionReference as an indicator
                     * to know whether to really dereference the session.
                     */
                    if (OldTokenFlags == Token->TokenFlags)
                        SessionReference = ULONG_MAX;

                    /*
                     * Otherwise if the flag was never set but just for this first time then
                     * remove the referenced logon session data from the token and dereference
                     * the logon session when needed.
                     */
                    if (SessionReference == 0)
                    {
                        SepRmRemoveLogonSessionFromToken(Token);
                        SepRmDereferenceLogonSession(&Token->AuthenticationId);
                    }

                    /* Unlock the token */
                    SepReleaseTokenLock(Token);
                }
                break;
            }

            case TokenAuditPolicy:
            {
                PTOKEN_AUDIT_POLICY_INFORMATION PolicyInformation =
                    (PTOKEN_AUDIT_POLICY_INFORMATION)TokenInformation;
                SEP_AUDIT_POLICY AuditPolicy;
                ULONG i;

                _SEH2_TRY
                {
                    ProbeForRead(PolicyInformation,
                                 FIELD_OFFSET(TOKEN_AUDIT_POLICY_INFORMATION,
                                              Policies[PolicyInformation->PolicyCount]),
                                 sizeof(ULONG));

                    /* Loop all policies in the structure */
                    for (i = 0; i < PolicyInformation->PolicyCount; i++)
                    {
                        /* Set the corresponding bits in the packed structure */
                        switch (PolicyInformation->Policies[i].Category)
                        {
                            case AuditCategorySystem:
                                AuditPolicy.PolicyElements.System = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryLogon:
                                AuditPolicy.PolicyElements.Logon = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryObjectAccess:
                                AuditPolicy.PolicyElements.ObjectAccess = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryPrivilegeUse:
                                AuditPolicy.PolicyElements.PrivilegeUse = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryDetailedTracking:
                                AuditPolicy.PolicyElements.DetailedTracking = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryPolicyChange:
                                AuditPolicy.PolicyElements.PolicyChange = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryAccountManagement:
                                AuditPolicy.PolicyElements.AccountManagement = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryDirectoryServiceAccess:
                                AuditPolicy.PolicyElements.DirectoryServiceAccess = PolicyInformation->Policies[i].Value;
                                break;

                            case AuditCategoryAccountLogon:
                                AuditPolicy.PolicyElements.AccountLogon = PolicyInformation->Policies[i].Value;
                                break;
                        }
                    }
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                    _SEH2_YIELD(goto Cleanup);
                }
                _SEH2_END;

                /* Check for TCB privilege */
                if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
                {
                    Status = STATUS_PRIVILEGE_NOT_HELD;
                    break;
                }

                /* Lock the token */
                SepAcquireTokenLockExclusive(Token);

                /* Set the new audit policy */
                Token->AuditPolicy = AuditPolicy;
                ExAllocateLocallyUniqueId(&Token->ModifiedId);

                /* Unlock the token */
                SepReleaseTokenLock(Token);

                break;
            }

            case TokenOrigin:
            {
                TOKEN_ORIGIN TokenOrigin;

                _SEH2_TRY
                {
                    /* Copy the token origin */
                    TokenOrigin = *(PTOKEN_ORIGIN)TokenInformation;
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    Status = _SEH2_GetExceptionCode();
                    _SEH2_YIELD(goto Cleanup);
                }
                _SEH2_END;

                /* Check for TCB privilege */
                if (!SeSinglePrivilegeCheck(SeTcbPrivilege, PreviousMode))
                {
                    Status = STATUS_PRIVILEGE_NOT_HELD;
                    break;
                }

                /* Lock the token */
                SepAcquireTokenLockExclusive(Token);

                /* Check if there is no token origin set yet */
                if (RtlIsZeroLuid(&Token->OriginatingLogonSession))
                {
                    /* Set the token origin */
                    Token->OriginatingLogonSession =
                        TokenOrigin.OriginatingLogonSession;

                    ExAllocateLocallyUniqueId(&Token->ModifiedId);
                }

                /* Unlock the token */
                SepReleaseTokenLock(Token);

                break;
            }

            default:
            {
                DPRINT1("Invalid TokenInformationClass: 0x%lx\n",
                        TokenInformationClass);
                Status = STATUS_INVALID_INFO_CLASS;
                break;
            }
        }
Cleanup:
        ObDereferenceObject(Token);
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtSetInformationToken failed with Status 0x%lx\n", Status);
    }

    return Status;
}

/* EOF */
