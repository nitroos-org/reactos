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
 * Lsa\LimitBlankPasswordUse (default 1 when absent; read at every logon, no restart needed, as measured): while it is
 * on, an account with a blank password can be logged on only by the logon dialog on the console. Every other logon
 * that gives the blank password (LogonUser of every type that checks a password, also from a process in the console
 * session or from LocalSystem with SeTcbPrivilege, CreateProcessWithLogonW, NTLM) fails with STATUS_ACCOUNT_RESTRICTION
 * (substatus the same), measured on Windows Server 2022. Documented: "Accounts: Limit
 * local account use of blank passwords to console logon only".
 */
BOOL
MsvpLimitBlankPasswordUse(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"LimitBlankPasswordUse");
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE KeyHandle;
    ULONG Length;
    bool Limit = true;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return true;

    Status = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, Buffer, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Status) && Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
        Limit = (*(PULONG)Info->Data != 0);

    NtClose(KeyHandle);
    return Limit;
}

/*
 * The challenge response of a network logon (the NTLM security package of secur32 asks for it). Only an NTLMv2
 * response is checked: an LM or NTLM v1 response is refused (VERIFY ON ORACLE: whether a Windows 10 server, default
 * LmCompatibilityLevel 3, accepts an NTLMv1 response; refused for now). The account's NT OWF is the one of the empty
 * password when it has none. On success the user session key (the NTLMv2 session base key) is returned.
 */
static
NTSTATUS
MsvpCheckNetworkPassword(
    _In_ PLSA_SAM_PWD_DATA UserPwdData,
    _In_ PSAMPR_USER_INFO_BUFFER UserInfo,
    _Out_ PBOOLEAN BlankPassword)
{
    PMSV1_0_LM20_LOGON LogonInfo = UserPwdData->LogonInfo;
    UCHAR NtOwf[16];
    BOOLEAN Blank = FALSE;
    UNICODE_STRING EmptyPassword = RTL_CONSTANT_STRING(L"");
    NTSTATUS Status;

    *BlankPassword = FALSE;
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
        Blank = TRUE;
    }

    /* An NT hash that is the one of the empty password is a blank password as well */
    if (!Blank)
    {
        UCHAR BlankOwf[16];

        Status = SystemFunction007(&EmptyPassword, BlankOwf);
        if (!NT_SUCCESS(Status))
            return Status;
        Blank = RtlEqualMemory(NtOwf, BlankOwf, sizeof(NtOwf));
    }

    Status = MsvpCheckNtlmv2Response(LogonInfo->ChallengeToClient,
                                     &LogonInfo->UserName,
                                     &LogonInfo->LogonDomainName,
                                     NtOwf,
                                     (const UCHAR *)LogonInfo->CaseSensitiveChallengeResponse.Buffer,
                                     LogonInfo->CaseSensitiveChallengeResponse.Length,
                                     (PUCHAR)&UserPwdData->UserSessionKey);
    RtlSecureZeroMemory(NtOwf, sizeof(NtOwf));
    if (!NT_SUCCESS(Status))
        return Status;

    /* The blank-password policy is applied by the caller (after the response was found right: a wrong response
       reports the wrong password) */
    *BlankPassword = Blank;
    return STATUS_SUCCESS;
}

/*
 * Checks the password of a logon. An account without a stored password (never set, "net user x /add") has the
 * blank password: only the empty password matches it, exactly like an account whose stored hash is the one of the
 * empty password ("net user x "" /add"). *BlankPassword tells the caller that the account's password is blank,
 * for Lsa\LimitBlankPasswordUse. The UF_PASSWD_NOTREQD flag does not change the check (measured: an account with a
 * password and the flag refuses a wrong and the empty password with 1326).
 */
static
NTSTATUS
MsvpCheckPassword(
    _In_ PLSA_SAM_PWD_DATA UserPwdData,
    _In_ PSAMPR_USER_INFO_BUFFER UserInfo,
    _Out_ PBOOLEAN BlankPassword)
{
    UNICODE_STRING EmptyPassword = RTL_CONSTANT_STRING(L"");
    ENCRYPTED_NT_OWF_PASSWORD UserNtPassword;
    ENCRYPTED_NT_OWF_PASSWORD BlankNtPassword;
    ENCRYPTED_LM_OWF_PASSWORD UserLmPassword;
    OEM_STRING LmPwdString;
    CHAR LmPwdBuffer[15];
    NTSTATUS Status;

    TRACE("(%p %p)\n", UserPwdData, UserInfo);

    *BlankPassword = FALSE;

    /* A network logon carries a challenge response, not the password */
    if (UserPwdData->IsNetwork)
        return MsvpCheckNetworkPassword(UserPwdData, UserInfo, BlankPassword);

    if (UserPwdData->PlainPwd == NULL)
        return STATUS_WRONG_PASSWORD;

    /* The NT hash of the password given and of the blank password */
    Status = SystemFunction007(UserPwdData->PlainPwd, (LPBYTE)&UserNtPassword);
    if (!NT_SUCCESS(Status))
        return STATUS_WRONG_PASSWORD;

    Status = SystemFunction007(&EmptyPassword, (LPBYTE)&BlankNtPassword);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = STATUS_WRONG_PASSWORD;

    if (UserInfo->All.NtPasswordPresent &&
        UserInfo->All.NtOwfPassword.Buffer != NULL &&
        UserInfo->All.NtOwfPassword.Length >= sizeof(ENCRYPTED_NT_OWF_PASSWORD))
    {
        /* The NT hash decides */
        if (RtlEqualMemory(&UserNtPassword, UserInfo->All.NtOwfPassword.Buffer, sizeof(ENCRYPTED_NT_OWF_PASSWORD)))
        {
            *BlankPassword = RtlEqualMemory(UserInfo->All.NtOwfPassword.Buffer, &BlankNtPassword,
                                            sizeof(ENCRYPTED_NT_OWF_PASSWORD));
            Status = STATUS_SUCCESS;
        }
    }
    else if (UserInfo->All.LmPasswordPresent &&
             UserInfo->All.LmOwfPassword.Buffer != NULL &&
             UserInfo->All.LmOwfPassword.Length >= sizeof(ENCRYPTED_LM_OWF_PASSWORD))
    {
        /* Only an LM hash is stored (an old database): the LM hash of the password given decides */
        LmPwdString.Length = 0;
        LmPwdString.MaximumLength = sizeof(LmPwdBuffer);
        LmPwdString.Buffer = LmPwdBuffer;
        RtlZeroMemory(LmPwdBuffer, sizeof(LmPwdBuffer));

        if (UserPwdData->PlainPwd->Length <= 14 * sizeof(WCHAR) &&
            NT_SUCCESS(RtlUpcaseUnicodeStringToOemString(&LmPwdString, UserPwdData->PlainPwd, FALSE)) &&
            NT_SUCCESS(SystemFunction006(LmPwdBuffer, (LPSTR)&UserLmPassword)) &&
            RtlEqualMemory(&UserLmPassword, UserInfo->All.LmOwfPassword.Buffer, sizeof(ENCRYPTED_LM_OWF_PASSWORD)))
        {
            *BlankPassword = (UserPwdData->PlainPwd->Length == 0);
            Status = STATUS_SUCCESS;
        }

        RtlSecureZeroMemory(LmPwdBuffer, sizeof(LmPwdBuffer));
        RtlSecureZeroMemory(&UserLmPassword, sizeof(UserLmPassword));
    }
    else
    {
        /* No password stored: the password is blank, only the empty password matches */
        if (RtlEqualMemory(&UserNtPassword, &BlankNtPassword, sizeof(ENCRYPTED_NT_OWF_PASSWORD)))
        {
            *BlankPassword = TRUE;
            Status = STATUS_SUCCESS;
        }
    }

    RtlSecureZeroMemory(&UserNtPassword, sizeof(UserNtPassword));
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

    /* Check the password (an S4U logon has none). USER_PASSWORD_NOT_REQUIRED only allows a blank password to be
       set: the password is checked all the same (measured) */
    if (!PwdData->IsS4U)
    {
        BOOLEAN BlankPassword = FALSE;

        /* A locked account: every logon with a password fails with STATUS_ACCOUNT_LOCKED_OUT, the right
           password as well, and the attempt is not counted (measured). The built-in Administrator is not
           locked out (documented: "Account lockout threshold"; measured: count and flag, but its logons work) */
        if (RelativeIds.Element[0] != DOMAIN_USER_RID_ADMIN &&
            (UserInfo->All.UserAccountControl & USER_ACCOUNT_AUTO_LOCKED))
        {
            ERR("Account locked out\n");
            Status = STATUS_ACCOUNT_LOCKED_OUT;
            goto done;
        }

        Status = MsvpCheckPassword(PwdData, UserInfo, &BlankPassword);
        if (Status == STATUS_WRONG_PASSWORD)
        {
            SAMPR_USER_INFO_BUFFER InternalInfo;
            NTSTATUS CountStatus;

            /* Count the bad password (SAM locks the account at the threshold) through the trusted handle */
            RtlZeroMemory(&InternalInfo, sizeof(InternalInfo));
            InternalInfo.Internal2.Flags = USER_LOGON_BAD_PASSWORD;
            CountStatus = SamrSetInformationUser(UserHandle, UserInternal2Information, &InternalInfo);
            if (!NT_SUCCESS(CountStatus))
                ERR("Cannot count the bad password (Status %08lx)\n", CountStatus);
        }
        if (!NT_SUCCESS(Status))
        {
            ERR("MsvpCheckPassword failed (Status %08lx)\n", Status);
            goto done;
        }

        /* A blank password is good for the logon dialog on the console only, unless the policy is off. The
           refusal comes before the logon right and the account checks, and is not a bad password (measured) */
        if (BlankPassword && !PwdData->IsConsole && MsvpLimitBlankPasswordUse())
        {
            TRACE("Blank password refused for a logon that is not the console logon\n");
            RtlSecureZeroMemory(&PwdData->UserSessionKey, sizeof(PwdData->UserSessionKey));
            RtlSecureZeroMemory(&PwdData->LanmanSessionKey, sizeof(PwdData->LanmanSessionKey));
            *SubStatus = STATUS_ACCOUNT_RESTRICTION;
            Status = STATUS_ACCOUNT_RESTRICTION;
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
