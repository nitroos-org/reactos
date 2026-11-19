/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     LogonUser of an account that cannot log on: the error names the restriction. Measured on
 *              Windows Server 2022 (10.0.20348) on scratch accounts: "must change the password at the next
 *              logon" gives 1907 (ERROR_PASSWORD_MUST_CHANGE) for INTERACTIVE, NETWORK, BATCH, SERVICE, UNLOCK and
 *              NETWORK_CLEARTEXT (NEW_CREDENTIALS does not look at the account and succeeds); a disabled account
 *              gives 1331 (ERROR_ACCOUNT_DISABLED) for the same types; a wrong password gives 1326.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>

static WCHAR TestPassword[] = L"Account-State-Test-2026!";

static DWORD Logon(PCWSTR User, PCWSTR Password, DWORD Type)
{
    HANDLE Token = NULL;

    SetLastError(0xdeadbeef);
    if (LogonUserW((LPWSTR)User, (LPWSTR)L".", (LPWSTR)Password, Type, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        CloseHandle(Token);
        return ERROR_SUCCESS;
    }
    return GetLastError();
}

static void CheckAllTypes(PCWSTR User, DWORD Expected)
{
    static const DWORD Types[] = { LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_LOGON_BATCH, LOGON32_LOGON_SERVICE,
                                   LOGON32_LOGON_UNLOCK, LOGON32_LOGON_NETWORK_CLEARTEXT };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Types); i++)
        ok_dec(Logon(User, TestPassword, Types[i]), Expected);
}

START_TEST(LogonUserAccountState)
{
    WCHAR User[32];
    USER_INFO_1 Info;
    USER_INFO_4 *Info4 = NULL;
    DWORD Error = 0, Status;

    StringCchPrintfW(User, RTL_NUMBER_OF(User), L"astate%lx", GetTickCount() & 0xffffff);
    ZeroMemory(&Info, sizeof(Info));
    Info.usri1_name = User;
    Info.usri1_password = TestPassword;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    Status = NetUserAdd(NULL, 1, (PBYTE)&Info, &Error);
    if (Status == ERROR_ACCESS_DENIED)
    {
        skip("NetUserAdd needs an elevated administrator\n");
        return;
    }
    ok_dec(Status, NERR_Success);
    if (Status != NERR_Success)
        return;

    ok_dec(Logon(User, L"not-the-password", LOGON32_LOGON_INTERACTIVE), ERROR_LOGON_FAILURE);

    /* the account is disabled */
    Info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE;
    Status = NetUserSetInfo(NULL, User, 1, (PBYTE)&Info, &Error);
    ok_dec(Status, NERR_Success);
    CheckAllTypes(User, ERROR_ACCOUNT_DISABLED);
    ok_dec(Logon(User, TestPassword, LOGON32_LOGON_NEW_CREDENTIALS), ERROR_SUCCESS);

    /* enabled again, but the user must change the password at the next logon */
    Info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    Status = NetUserSetInfo(NULL, User, 1, (PBYTE)&Info, &Error);
    ok_dec(Status, NERR_Success);
    Status = NetUserGetInfo(NULL, User, 4, (PBYTE *)&Info4);
    ok_dec(Status, NERR_Success);
    if (Status == NERR_Success)
    {
        Info4->usri4_password = NULL;
        Info4->usri4_password_expired = 1;
        Status = NetUserSetInfo(NULL, User, 4, (PBYTE)Info4, &Error);
        ok_dec(Status, NERR_Success);
        NetApiBufferFree(Info4);
        CheckAllTypes(User, ERROR_PASSWORD_MUST_CHANGE);
        ok_dec(Logon(User, TestPassword, LOGON32_LOGON_NEW_CREDENTIALS), ERROR_SUCCESS);
    }

    Status = NetUserDel(NULL, User);
    ok_dec(Status, NERR_Success);
}
