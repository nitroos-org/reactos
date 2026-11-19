/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetUserName under an impersonated LogonUser token of type INTERACTIVE, BATCH and
 *              NETWORK_CLEARTEXT returns the name of the impersonated user (measured on Windows Server 2022, where
 *              OpenThreadToken(TOKEN_QUERY, OpenAsSelf = FALSE) of the same thread fails with 5 for the
 *              INTERACTIVE token and GetUserName still works).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>

static WCHAR TestPassword[] = L"Get-User-Name-2026!";

static void TestType(PCWSTR User, DWORD Type, PCSTR Name)
{
    HANDLE Token = NULL;
    WCHAR Got[128];
    DWORD Size = RTL_NUMBER_OF(Got);

    if (!LogonUserW((LPWSTR)User, L".", TestPassword, Type, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        ok(0, "%s: LogonUser failed: %lu\n", Name, GetLastError());
        return;
    }
    ok(ImpersonateLoggedOnUser(Token), "%s: ImpersonateLoggedOnUser failed: %lu\n", Name, GetLastError());
    SetLastError(0xdeadbeef);
    ok(GetUserNameW(Got, &Size), "%s: GetUserName failed: %lu\n", Name, GetLastError());
    if (Size)
    {
        ok(!wcscmp(Got, User), "%s: GetUserName returned %ls, expected %ls\n", Name, Got, User);
        ok(Size == wcslen(User) + 1, "%s: size %lu\n", Name, Size);
    }
    RevertToSelf();
    CloseHandle(Token);
}

START_TEST(GetUserNameImpersonated)
{
    WCHAR User[32];
    USER_INFO_1 Info;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    WCHAR Domain[256];
    DWORD SidLength = sizeof(Sid), DomainLength = RTL_NUMBER_OF(Domain), Err, Try;
    SID_NAME_USE Use;
    LSA_OBJECT_ATTRIBUTES Attributes = {0};
    LSA_HANDLE Policy = NULL;
    LSA_UNICODE_STRING Right;
    static WCHAR BatchRight[] = L"SeBatchLogonRight";
    NET_API_STATUS Status = NERR_UserExists;

    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(User, RTL_NUMBER_OF(User), L"gunimp%lx", (GetTickCount() + Try * 7919) & 0xffffff);
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

    TestType(User, LOGON32_LOGON_INTERACTIVE, "INTERACTIVE");
    TestType(User, LOGON32_LOGON_NETWORK_CLEARTEXT, "NETWORK_CLEARTEXT");

    /* BATCH needs the right on Windows */
    if (LookupAccountNameW(NULL, User, Sid, &SidLength, Domain, &DomainLength, &Use) &&
        NT_SUCCESS(LsaOpenPolicy(NULL, &Attributes, POLICY_ALL_ACCESS, &Policy)))
    {
        Right.Buffer = BatchRight;
        Right.Length = (USHORT)(wcslen(BatchRight) * sizeof(WCHAR));
        Right.MaximumLength = Right.Length + sizeof(WCHAR);
        ok(NT_SUCCESS(LsaAddAccountRights(Policy, Sid, &Right, 1)), "LsaAddAccountRights failed\n");
        TestType(User, LOGON32_LOGON_BATCH, "BATCH");
        LsaRemoveAccountRights(Policy, Sid, TRUE, NULL, 0);
        LsaClose(Policy);
    }

    NetUserDel(NULL, User);
}
