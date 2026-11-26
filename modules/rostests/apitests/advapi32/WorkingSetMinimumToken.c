/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Raising the working set minimum of the caller's own process: allowed when the token holds
 *              SeIncreaseWorkingSetPrivilege (enabled or not) or has SeIncreaseQuotaPrivilege enabled
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (rows measured with SetProcessWorkingSetSizeEx under a thread token): a standard user whose token
 * lists SeIncreaseWorkingSetPrivilege with attributes 0 raises the minimum to 8 MB and to 200 MB, with the hard-limit flags
 * in every combination; the same token restricted with DISABLE_MAX_PRIVILEGE (only SeChangeNotifyPrivilege left) gets
 * ERROR_PRIVILEGE_NOT_HELD (1314) for every size; lowering the minimum needs no privilege. The administrator's token
 * (SeIncreaseQuotaPrivilege enabled) raises it also when SeIncreaseWorkingSetPrivilege is deleted from it.
 */

#include "precomp.h"
#include <lm.h>

#ifndef LOGON32_LOGON_NETWORK_CLEARTEXT
#define LOGON32_LOGON_NETWORK_CLEARTEXT 8
#endif

/* Not in the headers at the version this test is built for */
#ifndef QUOTA_LIMITS_HARDWS_MIN_ENABLE
#define QUOTA_LIMITS_HARDWS_MIN_ENABLE  0x00000001
#define QUOTA_LIMITS_HARDWS_MIN_DISABLE 0x00000002
#define QUOTA_LIMITS_HARDWS_MAX_ENABLE  0x00000004
#define QUOTA_LIMITS_HARDWS_MAX_DISABLE 0x00000008
#endif
BOOL WINAPI GetProcessWorkingSetSizeEx(HANDLE, PSIZE_T, PSIZE_T, PDWORD);
BOOL WINAPI SetProcessWorkingSetSizeEx(HANDLE, SIZE_T, SIZE_T, DWORD);

static WCHAR TestPassword[] = L"Working-Set-Test-2026!";

/* TRUE and the error 0, or FALSE and the error */
static BOOL RaiseMinimum(PDWORD Error)
{
    BOOL Ret;
    SIZE_T Min, Max;
    DWORD Flags;

    /* the default numbers first (lowering is allowed to everyone) */
    SetProcessWorkingSetSizeEx(GetCurrentProcess(), 200 * 1024, 1380 * 1024,
                               QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE);
    SetLastError(0);
    Ret = SetProcessWorkingSetSizeEx(GetCurrentProcess(), 8 * 1024 * 1024, 64 * 1024 * 1024,
                                     QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE);
    *Error = Ret ? 0 : GetLastError();
    if (Ret)
    {
        ok(GetProcessWorkingSetSizeEx(GetCurrentProcess(), &Min, &Max, &Flags), "GetProcessWorkingSetSizeEx failed\n");
        ok(Min == 8 * 1024 * 1024 && Max == 64 * 1024 * 1024, "read back %Iu..%Iu\n", Min, Max);
    }
    SetProcessWorkingSetSizeEx(GetCurrentProcess(), 200 * 1024, 1380 * 1024,
                               QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE);
    return Ret;
}

/* The thread impersonates a duplicate of Token for the call */
static BOOL RaiseUnder(HANDLE Token, PDWORD Error)
{
    HANDLE Imp = NULL;
    BOOL Ret = FALSE;

    if (!DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Imp))
    {
        *Error = GetLastError();
        return FALSE;
    }
    if (SetThreadToken(NULL, Imp))
    {
        Ret = RaiseMinimum(Error);
        RevertToSelf();
    }
    else
    {
        *Error = GetLastError();
    }
    CloseHandle(Imp);
    return Ret;
}

START_TEST(WorkingSetMinimumToken)
{
    WCHAR User[32];
    USER_INFO_1 Info;
    DWORD Err, Try, Error;
    HANDLE Token = NULL, Restricted = NULL, Self = NULL, Dup = NULL;
    static WCHAR RightName[] = L"SeIncreaseWorkingSetPrivilege";
    NET_API_STATUS Status = NERR_UserExists;
    LUID Luid;
    LUID_AND_ATTRIBUTES Delete;
    BOOL Ret;

    /* The test's own token (an elevated administrator: SeIncreaseQuotaPrivilege enabled): raising works, also with
       SeIncreaseWorkingSetPrivilege deleted from the token */
    ok(RaiseMinimum(&Error), "the administrator raises the minimum: error %lu\n", Error);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Self))
    {
        if (LookupPrivilegeValueW(NULL, RightName, &Luid) &&
            DuplicateTokenEx(Self, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Dup))
        {
            /* the quota privilege enabled (the remote administrator token of the Windows rows has it so; an elevated one lists it disabled) */
            TOKEN_PRIVILEGES Enable;

            Enable.PrivilegeCount = 1;
            Enable.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (LookupPrivilegeValueW(NULL, L"SeIncreaseQuotaPrivilege", &Enable.Privileges[0].Luid))
                AdjustTokenPrivileges(Dup, FALSE, &Enable, 0, NULL, NULL);

            Delete.Luid = Luid;
            Delete.Attributes = 0;
            if (CreateRestrictedToken(Dup, 0, 0, NULL, 1, &Delete, 0, NULL, &Restricted))
            {
                Ret = RaiseUnder(Restricted, &Error);
                ok(Ret, "token without SeIncreaseWorkingSetPrivilege but with the quota privilege: error %lu\n", Error);
                CloseHandle(Restricted);
                Restricted = NULL;
            }
            CloseHandle(Dup);
        }
        CloseHandle(Self);
    }

    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(User, RTL_NUMBER_OF(User), L"wsmin%lx", (GetTickCount() + Try * 7919) & 0xffffff);
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

    /* a standard user holds SeIncreaseWorkingSetPrivilege through the Users group, attributes 0 (disabled) */
    ok(LogonUserW(User, L".", TestPassword, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, &Token),
       "LogonUser failed: %lu\n", GetLastError());
    if (Token)
    {
        /* the privilege is in the token, whatever its attributes: the minimum can be raised */
        Ret = RaiseUnder(Token, &Error);
        ok(Ret, "token holding SeIncreaseWorkingSetPrivilege: error %lu\n", Error);

        /* every privilege removed from it: not held */
        if (DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Dup))
        {
            if (CreateRestrictedToken(Dup, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &Restricted))
            {
                Ret = RaiseUnder(Restricted, &Error);
                ok(!Ret, "restricted token without privileges raised the minimum\n");
                ok(Error == ERROR_PRIVILEGE_NOT_HELD, "error %lu, expected 1314\n", Error);
                CloseHandle(Restricted);
            }
            CloseHandle(Dup);
        }
        CloseHandle(Token);
    }

    NetUserDel(NULL, User);
}
