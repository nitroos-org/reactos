/*
 * PROJECT:     Authentication Package DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Security Account Manager (SAM) related functions
 * COPYRIGHT:   Copyright 2013 Eric Kohl <eric.kohl@reactos.org>
 */

#include "precomp.h"
#include <svcsid.h>

#include "ntlm/ntlmv2.h"

#include "wine/debug.h"
WINE_DEFAULT_DEBUG_CHANNEL(msv1_0_sam);


static
NTSTATUS
GetAccountDomainSid(
    _In_ PRPC_SID *Sid)
{
    LSAPR_HANDLE PolicyHandle = NULL;
    PLSAPR_POLICY_INFORMATION PolicyInfo = NULL;
    ULONG Length = 0;
    NTSTATUS Status;

    Status = LsaIOpenPolicyTrusted(&PolicyHandle);
    if (!NT_SUCCESS(Status))
    {
        TRACE("LsaIOpenPolicyTrusted() failed (Status 0x%08lx)\n", Status);
        return Status;
    }

    Status = LsarQueryInformationPolicy(PolicyHandle,
                                        PolicyAccountDomainInformation,
                                        &PolicyInfo);
    if (!NT_SUCCESS(Status))
    {
        TRACE("LsarQueryInformationPolicy() failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    Length = RtlLengthSid(PolicyInfo->PolicyAccountDomainInfo.Sid);

    *Sid = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (*Sid == NULL)
    {
        ERR("Failed to allocate SID\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    memcpy(*Sid, PolicyInfo->PolicyAccountDomainInfo.Sid, Length);

done:
    if (PolicyInfo != NULL)
        LsaIFree_LSAPR_POLICY_INFORMATION(PolicyAccountDomainInformation,
                                          PolicyInfo);

    if (PolicyHandle != NULL)
        LsarClose(&PolicyHandle);

    return Status;
}


/*
 * The challenge response of a network logon (the NTLM security package of secur32 asks for it). Only an NTLMv2
 * response is checked: an LM or NTLM v1 response is refused. The account's NT OWF is the one of the empty
 * password when it has none. On success the user session key (the NTLMv2 session base key) is returned.
 */
static
NTSTATUS
MsvpCheckNetworkPassword(
    _In_ PLSA_SAM_PWD_DATA UserPwdData,
    _In_ PSAMPR_USER_INFO_BUFFER UserInfo)
{
    PMSV1_0_LM20_LOGON LogonInfo = UserPwdData->LogonInfo;
    UCHAR NtOwf[16];
    UNICODE_STRING EmptyPassword = RTL_CONSTANT_STRING(L"");
    NTSTATUS Status;

    RtlZeroMemory(&UserPwdData->UserSessionKey, sizeof(UserPwdData->UserSessionKey));
    RtlZeroMemory(&UserPwdData->LanmanSessionKey, sizeof(UserPwdData->LanmanSessionKey));
    UserPwdData->LogonType = NetLogonNtKey;

    if (LogonInfo == NULL ||
        LogonInfo->CaseSensitiveChallengeResponse.Length == 0 ||
        LogonInfo->CaseSensitiveChallengeResponse.Buffer == NULL)
        return STATUS_WRONG_PASSWORD;

    if (UserInfo->All.NtPasswordPresent &&
        UserInfo->All.NtOwfPassword.Buffer != NULL &&
        UserInfo->All.NtOwfPassword.Length >= sizeof(NtOwf))
    {
        RtlCopyMemory(NtOwf, UserInfo->All.NtOwfPassword.Buffer, sizeof(NtOwf));
    }
    else if (UserInfo->All.LmPasswordPresent)
    {
        /* Only an LM hash is stored: there is no NT hash to check an NTLMv2 response against */
        return STATUS_WRONG_PASSWORD;
    }
    else
    {
        Status = SystemFunction007(&EmptyPassword, NtOwf);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    Status = MsvpCheckNtlmv2Response(LogonInfo->ChallengeToClient,
                                     &LogonInfo->UserName,
                                     &LogonInfo->LogonDomainName,
                                     NtOwf,
                                     (const UCHAR *)LogonInfo->CaseSensitiveChallengeResponse.Buffer,
                                     LogonInfo->CaseSensitiveChallengeResponse.Length,
                                     (PUCHAR)&UserPwdData->UserSessionKey);
    RtlSecureZeroMemory(NtOwf, sizeof(NtOwf));
    return Status;
}

static
NTSTATUS
MsvpCheckPassword(
    _In_ PLSA_SAM_PWD_DATA UserPwdData,
    _In_ PSAMPR_USER_INFO_BUFFER UserInfo)
{
    ENCRYPTED_NT_OWF_PASSWORD UserNtPassword;
    ENCRYPTED_LM_OWF_PASSWORD UserLmPassword;
    BOOLEAN UserLmPasswordPresent = FALSE;
    BOOLEAN UserNtPasswordPresent = FALSE;
    OEM_STRING LmPwdString;
    CHAR LmPwdBuffer[15];
    NTSTATUS Status;

    TRACE("(%p %p)\n", UserPwdData, UserInfo);

    /* A network logon carries a challenge response, not the password */
    if (UserPwdData->IsNetwork)
        return MsvpCheckNetworkPassword(UserPwdData, UserInfo);

    /* Calculate the LM password and hash for the users password */
    LmPwdString.Length = 15;
    LmPwdString.MaximumLength = 15;
    LmPwdString.Buffer = LmPwdBuffer;
    ZeroMemory(LmPwdString.Buffer, LmPwdString.MaximumLength);

    Status = RtlUpcaseUnicodeStringToOemString(&LmPwdString,
                                               UserPwdData->PlainPwd,
                                               FALSE);
    if (NT_SUCCESS(Status))
    {
        /* Calculate the LM hash value of the users password */
        Status = SystemFunction006(LmPwdString.Buffer,
                                   (LPSTR)&UserLmPassword);
        if (NT_SUCCESS(Status))
        {
            UserLmPasswordPresent = TRUE;
        }
    }

    /* Calculate the NT hash of the users password */
    Status = SystemFunction007(UserPwdData->PlainPwd,
                               (LPBYTE)&UserNtPassword);
    if (NT_SUCCESS(Status))
    {
        UserNtPasswordPresent = TRUE;
    }

    Status = STATUS_WRONG_PASSWORD;

    /* Succeed, if no password has been set */
    if (UserInfo->All.NtPasswordPresent == FALSE &&
        UserInfo->All.LmPasswordPresent == FALSE)
    {
        TRACE("No password check!\n");
        Status = STATUS_SUCCESS;
        goto done;
    }

    /* Succeed, if NT password matches */
    if (UserNtPasswordPresent && UserInfo->All.NtPasswordPresent)
    {
        TRACE("Check NT password hashes:\n");
        if (RtlEqualMemory(&UserNtPassword,
                           UserInfo->All.NtOwfPassword.Buffer,
                           sizeof(ENCRYPTED_NT_OWF_PASSWORD)))
        {
            TRACE("  success!\n");
            Status = STATUS_SUCCESS;
            goto done;
        }

        TRACE("  failed!\n");
    }

    /* Succeed, if LM password matches */
    if (UserLmPasswordPresent && UserInfo->All.LmPasswordPresent)
    {
        TRACE("Check LM password hashes:\n");
        if (RtlEqualMemory(&UserLmPassword,
                           UserInfo->All.LmOwfPassword.Buffer,
                           sizeof(ENCRYPTED_LM_OWF_PASSWORD)))
        {
            TRACE("  success!\n");
            Status = STATUS_SUCCESS;
            goto done;
        }
        TRACE("  failed!\n");
    }

done:
    return Status;
}


static
bool
MsvpCheckLogonHours(
    _In_ PSAMPR_LOGON_HOURS LogonHours,
    _In_ LARGE_INTEGER LogonTime,
    _In_ bool Enforce)
{
    LARGE_INTEGER LocalLogonTime;
    TIME_FIELDS TimeFields;
    ULONG MinutesPerUnit, Offset;

    /* Only an S4U logon with MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS is checked so far */
    if (!Enforce)
        return true;

    /* No logon hours restriction */
    if (LogonHours->UnitsPerWeek == 0 || LogonHours->LogonHours == NULL)
        return true;

    /* The hours are bits, the first one is Sunday 00:00 local time */
    RtlSystemTimeToLocalTime(&LogonTime, &LocalLogonTime);
    RtlTimeToTimeFields(&LocalLogonTime, &TimeFields);

    MinutesPerUnit = 10080 / LogonHours->UnitsPerWeek;
    if (MinutesPerUnit == 0)
        return true;

    Offset = ((TimeFields.Weekday * 24 + TimeFields.Hour) * 60 + TimeFields.Minute) / MinutesPerUnit;
    if (Offset >= LogonHours->UnitsPerWeek)
        return true;

    return (LogonHours->LogonHours[Offset / 8] & (1 << (Offset % 8))) != 0;
}


static
bool
MsvpCheckWorkstations(
    _In_ PRPC_UNICODE_STRING WorkStations,
    _In_ PWSTR ComputerName)
{
    PWSTR pStart, pEnd;
    bool bFound = false;

    TRACE("MsvpCheckWorkstations(%p %S)\n", WorkStations, ComputerName);

    if (WorkStations->Length == 0 || WorkStations->Buffer == NULL)
    {
        TRACE("No workstations!\n");
        return true;
    }

    TRACE("Workstations: %wZ\n", WorkStations);

    pStart = WorkStations->Buffer;
    for (;;)
    {
        pEnd = wcschr(pStart, L',');
        if (pEnd != NULL)
            *pEnd = UNICODE_NULL;

        TRACE("Comparing '%S' and '%S'\n", ComputerName, pStart);
        if (_wcsicmp(ComputerName, pStart) == 0)
        {
            bFound = true;
            if (pEnd != NULL)
                *pEnd = L',';
            break;
        }

        if (pEnd == NULL)
            break;

        *pEnd = L',';
        pStart = pEnd + 1;
    }

    TRACE("Found allowed workstation: %s\n", (bFound) ? "Yes" : "No");

    return bFound;
}


static
NTSTATUS
SamValidateNormalUser(
    _In_ PUNICODE_STRING UserName,
    _In_ PLSA_SAM_PWD_DATA PwdData,
    _In_ PUNICODE_STRING ComputerName,
    _Out_ PRPC_SID* AccountDomainSidPtr,
    _Out_ SAMPR_HANDLE* UserHandlePtr,
    _Out_ PSAMPR_USER_INFO_BUFFER* UserInfoPtr,
    _Out_ PNTSTATUS SubStatus)
{
    NTSTATUS Status;
    SAMPR_HANDLE ServerHandle = NULL;
    SAMPR_HANDLE DomainHandle = NULL;
    PRPC_SID AccountDomainSid;
    RPC_UNICODE_STRING Names[1];
    SAMPR_HANDLE UserHandle = NULL;
    SAMPR_ULONG_ARRAY RelativeIds = {0, NULL};
    SAMPR_ULONG_ARRAY Use = {0, NULL};
    PSAMPR_USER_INFO_BUFFER UserInfo = NULL;
    LARGE_INTEGER LogonTime;
    PWCHAR NameCopy = NULL;

    /* Get the logon time */
    NtQuerySystemTime(&LogonTime);

    /* Get the account domain SID */
    Status = GetAccountDomainSid(&AccountDomainSid);
    if (!NT_SUCCESS(Status))
    {
        ERR("GetAccountDomainSid() failed (Status 0x%08lx)\n", Status);
        return Status;
    }

    /* Connect to the SAM server */
    Status = SamIConnect(NULL, &ServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, TRUE);
    if (!NT_SUCCESS(Status))
    {
        TRACE("SamIConnect() failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    /* Open the account domain */
    Status = SamrOpenDomain(ServerHandle, DOMAIN_LOOKUP, AccountDomainSid, &DomainHandle);
    if (!NT_SUCCESS(Status))
    {
        ERR("SamrOpenDomain failed (Status %08lx)\n", Status);
        goto done;
    }

    /* The lookup expects a terminated name, the caller's string need not be */
    NameCopy = RtlAllocateHeap(RtlGetProcessHeap(), 0, UserName->Length + sizeof(WCHAR));
    if (NameCopy == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }
    RtlCopyMemory(NameCopy, UserName->Buffer, UserName->Length);
    NameCopy[UserName->Length / sizeof(WCHAR)] = UNICODE_NULL;

    Names[0].Length = UserName->Length;
    Names[0].MaximumLength = UserName->Length + sizeof(WCHAR);
    Names[0].Buffer = NameCopy;

    /* Try to get the RID for the user name */
    Status = SamrLookupNamesInDomain(DomainHandle, 1, Names, &RelativeIds, &Use);
    if (!NT_SUCCESS(Status))
    {
        ERR("SamrLookupNamesInDomain failed (Status %08lx)\n", Status);
        Status = STATUS_NO_SUCH_USER;
        // FIXME: Try without domain?
        goto done;
    }

    /* Fail, if it is not a user account */
    if (Use.Element[0] != SidTypeUser)
    {
        ERR("Account is not a user account!\n");
        Status = STATUS_NO_SUCH_USER;
        goto done;
    }

    /* Open the user object */
    Status = SamrOpenUser(DomainHandle,
                          USER_READ_GENERAL | USER_READ_LOGON |
                          USER_READ_ACCOUNT | USER_READ_PREFERENCES, /* FIXME */
                          RelativeIds.Element[0],
                          &UserHandle);
    if (!NT_SUCCESS(Status))
    {
        ERR("SamrOpenUser failed (Status %08lx)\n", Status);
        goto done;
    }

    Status = SamrQueryInformationUser(UserHandle, UserAllInformation, &UserInfo);
    if (!NT_SUCCESS(Status))
    {
        ERR("SamrQueryInformationUser failed (Status %08lx)\n", Status);
        goto done;
    }

    TRACE("UserName: %wZ\n", &UserInfo->All.UserName);

    /* Check the password (an S4U logon has none) */
    if (!PwdData->IsS4U &&
        (PwdData->IsNetwork ||
         (UserInfo->All.UserAccountControl & USER_PASSWORD_NOT_REQUIRED) == 0))
    {
        Status = MsvpCheckPassword(PwdData, UserInfo);
        if (!NT_SUCCESS(Status))
        {
            ERR("MsvpCheckPassword failed (Status %08lx)\n", Status);
            goto done;
        }
    }

    /* Check account restrictions for non-administrator accounts */
    if (RelativeIds.Element[0] != DOMAIN_USER_RID_ADMIN)
    {
        /* Check if the account has been disabled */
        if (UserInfo->All.UserAccountControl & USER_ACCOUNT_DISABLED)
        {
            ERR("Account disabled!\n");
            *SubStatus = STATUS_ACCOUNT_DISABLED;
            Status = STATUS_ACCOUNT_RESTRICTION;
            goto done;
        }

        /* Check if the account has been locked */
        if (UserInfo->All.UserAccountControl & USER_ACCOUNT_AUTO_LOCKED)
        {
            ERR("Account locked!\n");
            *SubStatus = STATUS_ACCOUNT_LOCKED_OUT;
            Status = STATUS_ACCOUNT_RESTRICTION;
            goto done;
        }

        /* Check if the account expired */
        if (LogonTime.QuadPart >= *(UINT64*)&UserInfo->All.AccountExpires)
        {
            ERR("Account expired!\n");
            if (PwdData->IsS4U)
            {
                /* An S4U logon reports it as the status itself */
                Status = STATUS_ACCOUNT_EXPIRED;
            }
            else
            {
                *SubStatus = STATUS_ACCOUNT_EXPIRED;
                Status = STATUS_ACCOUNT_RESTRICTION;
            }
            goto done;
        }

        /* Check if the password expired (an S4U logon does not look at the password) */
        if (!PwdData->IsS4U &&
            LogonTime.QuadPart >= *(UINT64*)&UserInfo->All.PasswordMustChange)
        {
            ERR("Password expired!\n");
            if (*(UINT64*)&UserInfo->All.PasswordLastSet == 0)
                *SubStatus = STATUS_PASSWORD_MUST_CHANGE;
            else
                *SubStatus = STATUS_PASSWORD_EXPIRED;

            Status = STATUS_ACCOUNT_RESTRICTION;
            goto done;
        }

        /* Check logon hours */
        if (!MsvpCheckLogonHours(&UserInfo->All.LogonHours, LogonTime,
                                 PwdData->IsS4U && PwdData->CheckLogonHours))
        {
            ERR("Invalid logon hours!\n");
            *SubStatus = STATUS_INVALID_LOGON_HOURS;
            Status = STATUS_ACCOUNT_RESTRICTION;
            goto done;
        }

        /* Check workstations (not for an S4U logon) */
        if (!PwdData->IsS4U &&
            !MsvpCheckWorkstations(&UserInfo->All.WorkStations, ComputerName->Buffer))
        {
            ERR("Invalid workstation!\n");
            *SubStatus = STATUS_INVALID_WORKSTATION;
            Status = STATUS_ACCOUNT_RESTRICTION;
            goto done;
        }
    }
done:
    if (NT_SUCCESS(Status))
    {
        *UserHandlePtr = UserHandle;
        *AccountDomainSidPtr = AccountDomainSid;
        *UserInfoPtr = UserInfo;
    }
    else
    {
        if (AccountDomainSid != NULL)
            RtlFreeHeap(RtlGetProcessHeap(), 0, AccountDomainSid);

        if (UserHandle != NULL)
            SamrCloseHandle(&UserHandle);

        SamIFree_SAMPR_USER_INFO_BUFFER(UserInfo,
                                        UserAllInformation);
    }

    if (NameCopy != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, NameCopy);

    SamIFree_SAMPR_ULONG_ARRAY(&RelativeIds);
    SamIFree_SAMPR_ULONG_ARRAY(&Use);

    if (DomainHandle != NULL)
        SamrCloseHandle(&DomainHandle);

    if (ServerHandle != NULL)
        SamrCloseHandle(&ServerHandle);

    return Status;
}


static
NTSTATUS
GetNtAuthorityDomainSid(
    _In_ PRPC_SID *Sid)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    ULONG Length = 0;

    Length = RtlLengthRequiredSid(0);
    *Sid = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
    if (*Sid == NULL)
    {
        ERR("Failed to allocate SID\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeSid(*Sid,&NtAuthority, 0);

    return STATUS_SUCCESS;
}


/*
 * NT SERVICE\<service>: the virtual account of a service. It exists for the services that exist
 * and logs on without a password, as a service logon of a trusted caller (SeTcbPrivilege) only.
 * Its SID is the service SID; the domain SID returned is the SID without its last number, which
 * is the relative id.
 */
static
NTSTATUS
SamValidateServiceAccount(
    _In_ SECURITY_LOGON_TYPE LogonType,
    _In_ BOOL TrustedClient,
    _In_ PUNICODE_STRING LogonUserName,
    _Out_ PRPC_SID* AccountDomainSidPtr,
    _Out_ PSAMPR_USER_INFO_BUFFER* UserInfoPtr)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    ULONG SubAuthorities[5];
    ULONG Chars = LogonUserName->Length / sizeof(WCHAR);
    PSID DomainSid;
    ULONG i;

    if (LogonType != Service)
        return STATUS_LOGON_FAILURE;

    /* The logon is without a password: only a caller that holds SeTcbPrivilege (the SCM) may do it.
     * Otherwise any process could become the service SID of any service. */
    if (!TrustedClient)
        return STATUS_LOGON_FAILURE;

    if (!LsapServiceExists(LogonUserName->Buffer, Chars) ||
        !LsapServiceNameToSubAuthorities(LogonUserName->Buffer, Chars, SubAuthorities))
        return STATUS_NO_SUCH_USER;

    DomainSid = RtlAllocateHeap(RtlGetProcessHeap(), 0, RtlLengthRequiredSid(5));
    if (DomainSid == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlInitializeSid(DomainSid, &NtAuthority, 5);
    *RtlSubAuthoritySid(DomainSid, 0) = SECURITY_SERVICE_ID_BASE_RID;
    for (i = 0; i < 4; i++)
        *RtlSubAuthoritySid(DomainSid, i + 1) = SubAuthorities[i];

    *UserInfoPtr = RtlAllocateHeap(RtlGetProcessHeap(),
                                   HEAP_ZERO_MEMORY,
                                   sizeof(SAMPR_USER_ALL_INFORMATION));
    if (*UserInfoPtr == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, DomainSid);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    (*UserInfoPtr)->All.UserId = SubAuthorities[4];
    (*UserInfoPtr)->All.PrimaryGroupId = SubAuthorities[4];
    *AccountDomainSidPtr = DomainSid;

    return STATUS_SUCCESS;
}


NTSTATUS
SamValidateUser(
    _In_ SECURITY_LOGON_TYPE LogonType,
    _In_ PUNICODE_STRING LogonUserName,
    _In_ PUNICODE_STRING LogonDomain,
    _In_ PLSA_SAM_PWD_DATA LogonPwdData,
    _In_ PUNICODE_STRING ComputerName,
    _Out_ PBOOL SpecialAccount,
    _Out_ PRPC_SID* AccountDomainSidPtr,
    _Out_ SAMPR_HANDLE* UserHandlePtr,
    _Out_ PSAMPR_USER_INFO_BUFFER* UserInfoPtr,
    _Out_ PNTSTATUS SubStatus,
    _In_ BOOL TrustedClient)
{
    static const UNICODE_STRING NtAuthorityU = RTL_CONSTANT_STRING(L"NT AUTHORITY");
    static const UNICODE_STRING NtServiceU = RTL_CONSTANT_STRING(L"NT SERVICE");
    static const UNICODE_STRING LocalServiceU = RTL_CONSTANT_STRING(L"LocalService");
    static const UNICODE_STRING NetworkServiceU = RTL_CONSTANT_STRING(L"NetworkService");

    NTSTATUS Status = STATUS_SUCCESS;

    *SpecialAccount = FALSE;
    *UserInfoPtr = NULL;
    *SubStatus = STATUS_SUCCESS;

    /* Check for special accounts */
    // FIXME: Windows does not do this that way!! (msv1_0 does not contain these hardcoded values)
    if (RtlEqualUnicodeString(LogonDomain, &NtAuthorityU, TRUE))
    {
        *SpecialAccount = TRUE;

        /* Get the authority domain SID */
        Status = GetNtAuthorityDomainSid(AccountDomainSidPtr);
        if (!NT_SUCCESS(Status))
        {
            ERR("GetNtAuthorityDomainSid() failed (Status 0x%08lx)\n", Status);
            return Status;
        }

        if (RtlEqualUnicodeString(LogonUserName, &LocalServiceU, TRUE))
        {
            TRACE("SpecialAccount: LocalService\n");

            if (LogonType != Service)
                return STATUS_LOGON_FAILURE;

            /* The logon has no password: it is for a caller that holds SeTcbPrivilege (the SCM) only.
             * Windows answers an untrusted caller with access denied. */
            if (!TrustedClient)
                return STATUS_ACCESS_DENIED;

            *UserInfoPtr = RtlAllocateHeap(RtlGetProcessHeap(),
                                           HEAP_ZERO_MEMORY,
                                           sizeof(SAMPR_USER_ALL_INFORMATION));
            if (*UserInfoPtr == NULL)
                return STATUS_INSUFFICIENT_RESOURCES;

            (*UserInfoPtr)->All.UserId = SECURITY_LOCAL_SERVICE_RID;
            (*UserInfoPtr)->All.PrimaryGroupId = SECURITY_LOCAL_SERVICE_RID;
        }
        else if (RtlEqualUnicodeString(LogonUserName, &NetworkServiceU, TRUE))
        {
            TRACE("SpecialAccount: NetworkService\n");

            if (LogonType != Service)
                return STATUS_LOGON_FAILURE;

            /* The logon has no password: it is for a caller that holds SeTcbPrivilege (the SCM) only.
             * Windows answers an untrusted caller with access denied. */
            if (!TrustedClient)
                return STATUS_ACCESS_DENIED;

            *UserInfoPtr = RtlAllocateHeap(RtlGetProcessHeap(),
                                           HEAP_ZERO_MEMORY,
                                           sizeof(SAMPR_USER_ALL_INFORMATION));
            if (*UserInfoPtr == NULL)
                return STATUS_INSUFFICIENT_RESOURCES;

            (*UserInfoPtr)->All.UserId = SECURITY_NETWORK_SERVICE_RID;
            (*UserInfoPtr)->All.PrimaryGroupId = SECURITY_NETWORK_SERVICE_RID;
        }
        else
        {
            return STATUS_NO_SUCH_USER;
        }
    }
    else if (RtlEqualUnicodeString(LogonDomain, &NtServiceU, TRUE))
    {
        TRACE("SpecialAccount: NT SERVICE\\%wZ\n", LogonUserName);

        *SpecialAccount = TRUE;
        Status = SamValidateServiceAccount(LogonType,
                                           TrustedClient,
                                           LogonUserName,
                                           AccountDomainSidPtr,
                                           UserInfoPtr);
        if (!NT_SUCCESS(Status))
            return Status;
    }
    else
    {
        TRACE("NormalAccount\n");
        Status = SamValidateNormalUser(LogonUserName,
                                       LogonPwdData,
                                       ComputerName,
                                       AccountDomainSidPtr,
                                       UserHandlePtr,
                                       UserInfoPtr,
                                       SubStatus);
        if (!NT_SUCCESS(Status))
        {
            ERR("SamValidateNormalUser() failed (Status 0x%08lx)\n", Status);
            return Status;
        }
    }

    return Status;
}
