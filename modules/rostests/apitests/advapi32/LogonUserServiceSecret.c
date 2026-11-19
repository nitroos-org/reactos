/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The name of the LSA secret that holds a service account's password (_SC_<service>)
 *              is no password: nobody, an unprivileged user included, gets a logon as the account
 *              with it. Only the service control manager reads the secret.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Not checked on the Windows 10 oracle: it would write an LSA secret there.
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>

static WCHAR AccountPassword[] = L"Svc-Secret-Test-2026!";
static WCHAR OtherPassword[] = L"Other-User-Test-2026!";
static WCHAR SecretText[] = L"_SC_apitestsvcsecret";

static NTSTATUS StoreSecret(PWSTR Name, PWSTR Value)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_HANDLE Policy;
    LSA_UNICODE_STRING Key, Data;
    NTSTATUS Status;

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_CREATE_SECRET, &Policy);
    if (!NT_SUCCESS(Status))
        return Status;
    Key.Buffer = Name;
    Key.Length = (USHORT)(wcslen(Name) * sizeof(WCHAR));
    Key.MaximumLength = Key.Length + sizeof(WCHAR);
    if (Value)
    {
        Data.Buffer = Value;
        Data.Length = (USHORT)(wcslen(Value) * sizeof(WCHAR));
        Data.MaximumLength = Data.Length + sizeof(WCHAR);
    }
    Status = LsaStorePrivateData(Policy, &Key, Value ? &Data : NULL);
    LsaClose(Policy);
    return Status;
}

/* The secret reads back through the RPC interface: the service control manager reads the password so */
static VOID ExpectSecretValue(PWSTR Name, PWSTR Expected)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_HANDLE Policy;
    LSA_UNICODE_STRING Key;
    PLSA_UNICODE_STRING Data = NULL;
    NTSTATUS Status;

    Status = LsaOpenPolicy(NULL, &Attributes, POLICY_GET_PRIVATE_INFORMATION, &Policy);
    ok(NT_SUCCESS(Status), "LsaOpenPolicy failed: 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    Key.Buffer = Name;
    Key.Length = (USHORT)(wcslen(Name) * sizeof(WCHAR));
    Key.MaximumLength = Key.Length + sizeof(WCHAR);
    Status = LsaRetrievePrivateData(Policy, &Key, &Data);
    ok(NT_SUCCESS(Status), "LsaRetrievePrivateData failed: 0x%08lx\n", Status);
    if (NT_SUCCESS(Status) && Data)
    {
        ok(Data->Length == wcslen(Expected) * sizeof(WCHAR) &&
           !memcmp(Data->Buffer, Expected, Data->Length), "the secret reads back as %u bytes\n", Data->Length);
        LsaFreeMemory(Data);
    }
    LsaClose(Policy);
}

static BOOL AddUser(PWSTR Prefix, PWSTR Password, PWSTR Name, SIZE_T NameLength)
{
    USER_INFO_1 Info;
    NET_API_STATUS Status = NERR_UserExists;
    DWORD Err, Try;

    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(Name, NameLength, L"%ls%lx", Prefix, (GetTickCount() + Try * 7919) & 0xffffff);
        ZeroMemory(&Info, sizeof(Info));
        Info.usri1_name = Name;
        Info.usri1_password = Password;
        Info.usri1_priv = USER_PRIV_USER;
        Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    if (Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return FALSE;
    }
    ok(Status == NERR_Success, "NetUserAdd(%ls) failed: %lu\n", Name, Status);
    return Status == NERR_Success;
}

/* A service logon of Account with the secret's name as the password must be refused */
static VOID ExpectRefused(PCSTR Who, PWSTR Account)
{
    HANDLE Token = (HANDLE)(ULONG_PTR)0xdeadbeef;
    BOOL Ok;

    SetLastError(0xdeadbeef);
    Ok = LogonUserW(Account, L".", SecretText, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
    ok(!Ok, "%s: a service logon with the secret's name as the password succeeded\n", Who);
    ok(GetLastError() == ERROR_LOGON_FAILURE, "%s: error %lu, expected ERROR_LOGON_FAILURE\n", Who, GetLastError());
    if (Ok && Token)
        CloseHandle(Token);
}

START_TEST(LogonUserServiceSecret)
{
    WCHAR Service[32], Other[32];
    HANDLE Token = NULL, OtherToken = NULL;
    NTSTATUS NtStatus;
    BOOL Ok;

    if (!AddUser(L"svcsec", AccountPassword, Service, RTL_NUMBER_OF(Service)))
        return;
    if (!AddUser(L"svcusr", OtherPassword, Other, RTL_NUMBER_OF(Other)))
    {
        NetUserDel(NULL, Service);
        return;
    }

    /* What the service control manager stores when a service is given an account and its password */
    NtStatus = StoreSecret(SecretText, AccountPassword);
    ok(NT_SUCCESS(NtStatus), "LsaStorePrivateData failed: 0x%08lx\n", NtStatus);
    if (NT_SUCCESS(NtStatus))
    {
        ExpectSecretValue(SecretText, AccountPassword);

        /* Nobody gets the account's token with the secret's name: the caller (an administrator) ... */
        ExpectRefused("administrator", Service);

        /* ... and an unprivileged user */
        Ok = LogonUserW(Other, L".", OtherPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &OtherToken);
        ok(Ok, "LogonUser of the unprivileged user failed: %lu\n", GetLastError());
        if (Ok && ImpersonateLoggedOnUser(OtherToken))
        {
            ExpectRefused("unprivileged user", Service);
            RevertToSelf();
        }
        if (OtherToken)
            CloseHandle(OtherToken);

        /* The password itself works for a service logon of an account that has the right (Windows: 1385 without it) */
        {
            LSA_OBJECT_ATTRIBUTES Attributes = {0};
            LSA_HANDLE Policy = NULL;
            LSA_UNICODE_STRING Right;
            static WCHAR RightName[] = L"SeServiceLogonRight";
            BYTE Sid[SECURITY_MAX_SID_SIZE];
            WCHAR Domain[256];
            DWORD SidLength = sizeof(Sid), DomainLength = RTL_NUMBER_OF(Domain);
            SID_NAME_USE Use;

            Ok = LogonUserW(Service, L".", AccountPassword, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
            ok(!Ok && GetLastError() == ERROR_LOGON_TYPE_NOT_GRANTED, "service logon without the right: %d, %lu\n", Ok, GetLastError());
            if (Ok && Token)
                CloseHandle(Token);

            Right.Buffer = RightName;
            Right.Length = (USHORT)(wcslen(RightName) * sizeof(WCHAR));
            Right.MaximumLength = Right.Length + sizeof(WCHAR);
            if (LookupAccountNameW(NULL, Service, Sid, &SidLength, Domain, &DomainLength, &Use) &&
                NT_SUCCESS(LsaOpenPolicy(NULL, &Attributes, POLICY_ALL_ACCESS, &Policy)))
            {
                ok(NT_SUCCESS(LsaAddAccountRights(Policy, Sid, &Right, 1)), "LsaAddAccountRights failed\n");
                Ok = LogonUserW(Service, L".", AccountPassword, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &Token);
                ok(Ok, "service logon with the password failed: %lu\n", GetLastError());
                if (Ok && Token)
                    CloseHandle(Token);
                LsaRemoveAccountRights(Policy, Sid, TRUE, NULL, 0);
                LsaClose(Policy);
            }
        }

        NtStatus = StoreSecret(SecretText, NULL);
        ok(NT_SUCCESS(NtStatus), "deleting the secret failed: 0x%08lx\n", NtStatus);
    }

    NetUserDel(NULL, Service);
    NetUserDel(NULL, Other);
}
