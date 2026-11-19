/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LogonUser of every logon type: the logon rights (batch, service, interactive, network and the
 *              Deny rights) decide, UNLOCK and NEW_CREDENTIALS work, NETWORK takes a plain password.
 *              The expected values are those measured on Windows Server 2022 (10.0.20348) with the same
 *              calls on scratch accounts: a user in Users: INTERACTIVE, NETWORK, UNLOCK, NETWORK_CLEARTEXT and
 *              NEW_CREDENTIALS succeed, BATCH and SERVICE fail with 1385; with SeBatchLogonRight / SeServiceLogonRight
 *              granted they succeed; a Deny right of the logon type fails it with 1385 even for an allowed account
 *              (SeDenyNetworkLogonRight also stops NETWORK_CLEARTEXT, SeDenyInteractiveLogonRight also UNLOCK);
 *              NEW_CREDENTIALS checks neither the user nor the password and gives a primary token of the caller's user.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>

static WCHAR TestPassword[] = L"Logon-Types-Test-2026!";

static DWORD TryLogon(PCWSTR User, PCWSTR Domain, DWORD Type, DWORD Provider, PHANDLE Token)
{
    HANDLE Tok = NULL;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Ret = LogonUserW((LPWSTR)User, (LPWSTR)Domain, TestPassword, Type, Provider, &Tok);
    if (!Ret)
        return GetLastError();
    if (Token)
        *Token = Tok;
    else
        CloseHandle(Tok);
    return ERROR_SUCCESS;
}

static void SetRight(LSA_HANDLE Policy, PSID Sid, PWSTR Name, BOOL Add)
{
    LSA_UNICODE_STRING Right;
    NTSTATUS Status;

    Right.Buffer = Name;
    Right.Length = (USHORT)(wcslen(Name) * sizeof(WCHAR));
    Right.MaximumLength = Right.Length + sizeof(WCHAR);
    if (Add)
        Status = LsaAddAccountRights(Policy, Sid, &Right, 1);
    else
        Status = LsaRemoveAccountRights(Policy, Sid, FALSE, &Right, 1);
    ok(NT_SUCCESS(Status) || (!Add && Status == STATUS_OBJECT_NAME_NOT_FOUND),
       "%ls %ls: 0x%08lx\n", Add ? L"grant" : L"revoke", Name, Status);
}

static BOOL TokenUserIsNot(HANDLE Token, PSID Sid)
{
    UCHAR Buffer[256];
    DWORD Length;

    return GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Length) &&
           !EqualSid(((PTOKEN_USER)Buffer)->User.Sid, Sid);
}

START_TEST(LogonUserTypes)
{
    WCHAR User[32];
    USER_INFO_1 Info;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    WCHAR Domain[256];
    DWORD SidLength = sizeof(SID), DomainLength = RTL_NUMBER_OF(Domain), Err, Try, Ret;
    SID_NAME_USE Use;
    HANDLE Token = NULL;
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_HANDLE Policy;
    NTSTATUS NtStatus;
    NET_API_STATUS Status = NERR_UserExists;
    TOKEN_STATISTICS Own, Copy;
    DWORD Length;
    HANDLE OwnToken;

    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(User, RTL_NUMBER_OF(User), L"lutypes%lx", (GetTickCount() + Try * 7919) & 0xffffff);
        ZeroMemory(&Info, sizeof(Info));
        Info.usri1_name = User;
        Info.usri1_password = TestPassword;
        Info.usri1_priv = USER_PRIV_USER;
        Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    if (Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return;
    }
    ok(Status == NERR_Success, "NetUserAdd failed: %lu\n", Status);
    if (Status != NERR_Success)
        return;

    SidLength = sizeof(Sid);
    ok(LookupAccountNameW(NULL, User, Sid, &SidLength, Domain, &DomainLength, &Use),
       "LookupAccountName failed: %lu\n", GetLastError());

    NtStatus = LsaOpenPolicy(NULL, &Attributes, POLICY_ALL_ACCESS, &Policy);
    ok(NT_SUCCESS(NtStatus), "LsaOpenPolicy failed: 0x%08lx\n", NtStatus);
    if (!NT_SUCCESS(NtStatus))
        goto done;

    /* A user of the group Users: no batch and no service logon right */
    Ret = TryLogon(User, L".", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "INTERACTIVE: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "NETWORK with the plain password: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_UNLOCK, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "UNLOCK: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "NETWORK_CLEARTEXT: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "BATCH without the right: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "SERVICE without the right: %lu\n", Ret);

    /* A wrong password still fails the typed logons */
    SetLastError(0xdeadbeef);
    ok(!LogonUserW(User, L".", L"Wrong-Password-1!", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &Token),
       "NETWORK with a wrong password succeeded\n");
    ok(GetLastError() == ERROR_LOGON_FAILURE, "NETWORK wrong password: %lu\n", GetLastError());

    /* Granted */
    SetRight(Policy, Sid, (PWSTR)L"SeBatchLogonRight", TRUE);
    Ret = TryLogon(User, L".", LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "BATCH with the right: %lu\n", Ret);
    SetRight(Policy, Sid, (PWSTR)L"SeBatchLogonRight", FALSE);
    Ret = TryLogon(User, L".", LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "BATCH after the right is removed: %lu\n", Ret);

    SetRight(Policy, Sid, (PWSTR)L"SeServiceLogonRight", TRUE);
    Ret = TryLogon(User, L".", LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "SERVICE with the right: %lu\n", Ret);
    SetRight(Policy, Sid, (PWSTR)L"SeServiceLogonRight", FALSE);

    /* A Deny right wins over the right the user has through Users */
    SetRight(Policy, Sid, (PWSTR)L"SeDenyNetworkLogonRight", TRUE);
    Ret = TryLogon(User, L".", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "NETWORK with SeDenyNetworkLogonRight: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "NETWORK_CLEARTEXT with SeDenyNetworkLogonRight: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "INTERACTIVE with SeDenyNetworkLogonRight: %lu\n", Ret);
    SetRight(Policy, Sid, (PWSTR)L"SeDenyNetworkLogonRight", FALSE);

    SetRight(Policy, Sid, (PWSTR)L"SeDenyInteractiveLogonRight", TRUE);
    Ret = TryLogon(User, L".", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "INTERACTIVE with SeDenyInteractiveLogonRight: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_UNLOCK, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "UNLOCK with SeDenyInteractiveLogonRight: %lu\n", Ret);
    Ret = TryLogon(User, L".", LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_SUCCESS, "NETWORK with SeDenyInteractiveLogonRight: %lu\n", Ret);
    SetRight(Policy, Sid, (PWSTR)L"SeDenyInteractiveLogonRight", FALSE);

    SetRight(Policy, Sid, (PWSTR)L"SeBatchLogonRight", TRUE);
    SetRight(Policy, Sid, (PWSTR)L"SeDenyBatchLogonRight", TRUE);
    Ret = TryLogon(User, L".", LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, NULL);
    ok(Ret == ERROR_LOGON_TYPE_NOT_GRANTED, "BATCH with the right and SeDenyBatchLogonRight: %lu\n", Ret);
    SetRight(Policy, Sid, (PWSTR)L"SeDenyBatchLogonRight", FALSE);
    SetRight(Policy, Sid, (PWSTR)L"SeBatchLogonRight", FALSE);

    /* NEW_CREDENTIALS: the credentials are not checked, the token is a copy of the caller's token (a new logon
     * session, the user of the caller, not the one named) */
    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &OwnToken), "OpenProcessToken: %lu\n", GetLastError());
    Ret = TryLogon(User, L".", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &Token);
    ok(Ret == ERROR_SUCCESS, "NEW_CREDENTIALS: %lu\n", Ret);
    if (Ret == ERROR_SUCCESS)
    {
        UCHAR OwnUser[256];

        ok(GetTokenInformation(OwnToken, TokenUser, OwnUser, sizeof(OwnUser), &Length), "TokenUser: %lu\n", GetLastError());
        ok(!TokenUserIsNot(Token, ((PTOKEN_USER)OwnUser)->User.Sid), "the token is not of the caller's user\n");
        ok(GetTokenInformation(Token, TokenStatistics, &Copy, sizeof(Copy), &Length), "TokenStatistics: %lu\n", GetLastError());
        ok(GetTokenInformation(OwnToken, TokenStatistics, &Own, sizeof(Own), &Length), "TokenStatistics: %lu\n", GetLastError());
        ok(Copy.TokenType == TokenPrimary, "token type %d\n", Copy.TokenType);
        ok(Copy.AuthenticationId.LowPart != Own.AuthenticationId.LowPart ||
           Copy.AuthenticationId.HighPart != Own.AuthenticationId.HighPart, "NEW_CREDENTIALS reuses the logon session\n");
        ok(Copy.PrivilegeCount == Own.PrivilegeCount, "privileges %lu, caller %lu\n", Copy.PrivilegeCount, Own.PrivilegeCount);
        ok(Copy.GroupCount >= Own.GroupCount, "groups %lu, caller %lu\n", Copy.GroupCount, Own.GroupCount);
        CloseHandle(Token);
    }
    Ret = TryLogon(L"lutypes-no-such-user", L".", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &Token);
    ok(Ret == ERROR_SUCCESS, "NEW_CREDENTIALS for an unknown user: %lu\n", Ret);
    if (Ret == ERROR_SUCCESS)
        CloseHandle(Token);
    Token = NULL;
    SetLastError(0xdeadbeef);
    ok(LogonUserW(User, L".", L"Wrong-Password-1!", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &Token),
       "NEW_CREDENTIALS with a wrong password: %lu\n", GetLastError());
    if (Token)
        CloseHandle(Token);
    CloseHandle(OwnToken);

    LsaRemoveAccountRights(Policy, Sid, TRUE, NULL, 0);
    LsaClose(Policy);

done:
    NetUserDel(NULL, User);
}
