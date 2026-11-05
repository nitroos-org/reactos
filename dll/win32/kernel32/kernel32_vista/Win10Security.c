/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AddScopedPolicyIDAce, GetAppContainerAce and CheckTokenCapability
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Behaviour measured on Windows 10 22H2 (x64 and x86). Windows' kernel32 exports these through the contract
 * api-ms-win-security-base-l1-2-x, which maps to kernel32 here.
 *
 * AddScopedPolicyIDAce(Acl, Revision, AceFlags, Mask, PolicySid):
 *  - the ACL must be valid (ERROR_INVALID_ACL), the revision at most 4 (ERROR_REVISION_MISMATCH); a lower revision is
 *    accepted and the ACL's revision becomes the larger of the two;
 *  - AceFlags are inheritance bits (0x1F measured as valid; 0x80 is not), Mask must be 0, the SID must be a valid SID
 *    (ERROR_INVALID_SID) of the authority 17 (SECURITY_SCOPED_POLICY_ID_AUTHORITY), anything else is
 *    ERROR_INVALID_PARAMETER; a full ACL is ERROR_ALLOTTED_SPACE_EXCEEDED;
 *  - the ACE is type 0x13 (SYSTEM_SCOPED_POLICY_ID_ACE), the header, a zero mask and the SID.
 * GetAppContainerAce(Acl, StartingAceIndex, &Ace, &Index): finds the first ACE at or after the index whose SID is of the
 *  authority 15 (SECURITY_APP_PACKAGE_AUTHORITY: package, capability, group capability SIDs). The index is optional.
 *  Nothing is written on failure; success sets the last error to 0. An empty ACL, an index past the end, a NULL ACL or a NULL Ace pointer is
 *  ERROR_INVALID_PARAMETER; an ACL without such an ACE is ERROR_NOT_FOUND.
 * CheckTokenCapability(Token, CapabilitySid, &HasCapability): the SID must be a capability SID (authority 15, first
 *  subauthority 3), else ERROR_INVALID_PARAMETER and *HasCapability is FALSE. A token that is not an AppContainer token
 *  has every capability; the token handle must be an impersonation token (ERROR_NO_IMPERSONATION_TOKEN), NULL is the
 *  thread's token or else a copy of the process token. A NULL SID leaves *HasCapability alone.
 */

#include "k32_vista.h"
#include <ndk/sefuncs.h>

#define NDEBUG
#include <debug.h>

#define BASEP_SCOPED_POLICY_ID_ACE_TYPE 0x13
#define BASEP_SCOPED_POLICY_AUTHORITY 17
#define BASEP_APP_PACKAGE_AUTHORITY 15
#define BASEP_ACE_FLAGS_MASK 0x1F

static
BOOLEAN
BasepIsSidOfAuthority(
    _In_ PSID Sid,
    _In_ UCHAR Authority)
{
    PSID_IDENTIFIER_AUTHORITY Id = RtlIdentifierAuthoritySid(Sid);

    return Id->Value[0] == 0 && Id->Value[1] == 0 && Id->Value[2] == 0 && Id->Value[3] == 0 && Id->Value[4] == 0 &&
           Id->Value[5] == Authority;
}

static
BOOLEAN
BasepAceHasSidAtMask(
    _In_ PACE_HEADER Ace)
{
    switch (Ace->AceType)
    {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case 0x12: /* SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE */
        case BASEP_SCOPED_POLICY_ID_ACE_TYPE:
            return TRUE;
    }
    return FALSE;
}

BOOL
WINAPI
AddScopedPolicyIDAce(
    _Inout_ PACL Acl,
    _In_ DWORD AceRevision,
    _In_ DWORD AceFlags,
    _In_ DWORD Mask,
    _In_ PSID PolicySid)
{
    struct
    {
        ACE_HEADER Header;
        ACCESS_MASK Mask;
    } *Ace;
    ULONG SidLength, AceSize, i;
    PACE_HEADER Existing;
    PUCHAR End;

    if (!Acl || !RtlValidAcl(Acl))
    {
        SetLastError(ERROR_INVALID_ACL);
        return FALSE;
    }

    if (AceRevision > ACL_REVISION_DS)
    {
        SetLastError(ERROR_REVISION_MISMATCH);
        return FALSE;
    }

    if ((AceFlags & ~BASEP_ACE_FLAGS_MASK) || Mask != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!PolicySid || !RtlValidSid(PolicySid))
    {
        SetLastError(ERROR_INVALID_SID);
        return FALSE;
    }

    if (!BasepIsSidOfAuthority(PolicySid, BASEP_SCOPED_POLICY_AUTHORITY))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SidLength = RtlLengthSid(PolicySid);
    AceSize = sizeof(*Ace) + SidLength;

    /* the first free byte of the ACL */
    End = (PUCHAR)(Acl + 1);
    for (i = 0; i < Acl->AceCount; i++)
    {
        Existing = (PACE_HEADER)End;
        End += Existing->AceSize;
    }
    if (End + AceSize > (PUCHAR)Acl + Acl->AclSize)
    {
        SetLastError(ERROR_ALLOTTED_SPACE_EXCEEDED);
        return FALSE;
    }

    Ace = (PVOID)End;
    Ace->Header.AceType = BASEP_SCOPED_POLICY_ID_ACE_TYPE;
    Ace->Header.AceFlags = (UCHAR)AceFlags;
    Ace->Header.AceSize = (USHORT)AceSize;
    Ace->Mask = 0;
    RtlCopySid(SidLength, (PUCHAR)(Ace + 1), PolicySid);

    Acl->AceCount++;
    if (Acl->AclRevision < AceRevision)
        Acl->AclRevision = (UCHAR)AceRevision;
    return TRUE;
}

BOOL
WINAPI
GetAppContainerAce(
    _In_ PACL Acl,
    _In_ DWORD StartingAceIndex,
    _Outptr_ PVOID *AppContainerAce,
    _Out_opt_ PDWORD AppContainerAceIndex)
{
    PACE_HEADER Ace;
    ULONG i;

    if (!Acl || !AppContainerAce || !RtlValidAcl(Acl) || StartingAceIndex >= Acl->AceCount)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Ace = (PACE_HEADER)(Acl + 1);
    for (i = 0; i < Acl->AceCount; i++)
    {
        if (i >= StartingAceIndex && BasepAceHasSidAtMask(Ace))
        {
            PSID Sid = (PUCHAR)Ace + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK);

            if (RtlValidSid(Sid) && BasepIsSidOfAuthority(Sid, BASEP_APP_PACKAGE_AUTHORITY))
            {
                *AppContainerAce = Ace;
                if (AppContainerAceIndex)
                    *AppContainerAceIndex = i;
                SetLastError(ERROR_SUCCESS);
                return TRUE;
            }
        }
        Ace = (PACE_HEADER)((PUCHAR)Ace + Ace->AceSize);
    }

    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

BOOL
WINAPI
CheckTokenCapability(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID CapabilitySid,
    _Out_ PBOOL HasCapability)
{
    HANDLE Token = TokenHandle, Duplicate = NULL;
    ULONG IsAppContainer = 0, Length, Size;
    NTSTATUS Status;
    PTOKEN_GROUPS Capabilities;
    ULONG i;
    BOOL Result = FALSE;

    if (!CapabilitySid)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *HasCapability = FALSE;

    if (!RtlValidSid(CapabilitySid) ||
        !BasepIsSidOfAuthority(CapabilitySid, BASEP_APP_PACKAGE_AUTHORITY) ||
        *RtlSubAuthorityCountSid(CapabilitySid) == 0 ||
        *RtlSubAuthoritySid(CapabilitySid, 0) != 3)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!Token)
    {
        /* the thread's token, else a copy of the process token that can be queried as an impersonation token */
        Status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, FALSE, &Duplicate);
        if (Status == STATUS_NO_TOKEN)
        {
            HANDLE Primary;
            OBJECT_ATTRIBUTES ObjectAttributes;

            Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &Primary);
            if (NT_SUCCESS(Status))
            {
                InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
                Status = NtDuplicateToken(Primary, TOKEN_QUERY, &ObjectAttributes, FALSE, TokenImpersonation, &Duplicate);
                NtClose(Primary);
            }
        }
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return FALSE;
        }
        Token = Duplicate;
    }
    else
    {
        TOKEN_TYPE Type;

        Status = NtQueryInformationToken(Token, TokenType, &Type, sizeof(Type), &Length);
        if (!NT_SUCCESS(Status))
        {
            BaseSetLastNTError(Status);
            return FALSE;
        }
        if (Type != TokenImpersonation)
        {
            SetLastError(ERROR_NO_IMPERSONATION_TOKEN);
            return FALSE;
        }
    }

    /* only an AppContainer token is limited to the capabilities it holds */
    Status = NtQueryInformationToken(Token, (TOKEN_INFORMATION_CLASS)29 /* TokenIsAppContainer */, &IsAppContainer, sizeof(IsAppContainer), &Length);
    if (!NT_SUCCESS(Status) || !IsAppContainer)
    {
        *HasCapability = TRUE;
        Result = TRUE;
        goto Done;
    }

    Status = NtQueryInformationToken(Token, (TOKEN_INFORMATION_CLASS)30 /* TokenCapabilities */, NULL, 0, &Size);
    if (Status != STATUS_BUFFER_TOO_SMALL || !Size)
    {
        BaseSetLastNTError(NT_SUCCESS(Status) ? STATUS_UNSUCCESSFUL : Status);
        goto Done;
    }
    Capabilities = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!Capabilities)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto Done;
    }
    Status = NtQueryInformationToken(Token, (TOKEN_INFORMATION_CLASS)30, Capabilities, Size, &Length);
    if (NT_SUCCESS(Status))
    {
        for (i = 0; i < Capabilities->GroupCount; i++)
        {
            if (RtlEqualSid(Capabilities->Groups[i].Sid, CapabilitySid))
            {
                *HasCapability = TRUE;
                break;
            }
        }
        Result = TRUE;
    }
    else
    {
        BaseSetLastNTError(Status);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Capabilities);

Done:
    if (Duplicate)
        NtClose(Duplicate);
    return Result;
}
