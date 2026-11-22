/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Opening the Security event log needs SeSecurityPrivilege: a standard user gets
 *              ERROR_PRIVILEGE_NOT_HELD (measured on Windows Server 2022, standard user). The other
 *              logs stay open to it. Documentation: "Event Logging Security",
 *              https://learn.microsoft.com/windows/win32/eventlog/event-logging-security
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The ANSI entry points answer as the wide ones (measured on Windows Server 2022, standard user: 1314 for
 *              Security in any letter case, success for Application and System).
 *
 * Clearing a log is not tested: the answer of Windows for a standard user was not measured.
 */

#include "precomp.h"
#include <lm.h>

static WCHAR TestPassword[] = L"Event-Log-Test-2026!";

static BOOL TokenHasPrivilege(HANDLE Token, PCWSTR Name)
{
    UCHAR Buffer[2048];
    PTOKEN_PRIVILEGES Privileges = (PTOKEN_PRIVILEGES)Buffer;
    DWORD Length, i;
    LUID Luid;

    if (!LookupPrivilegeValueW(NULL, Name, &Luid) ||
        !GetTokenInformation(Token, TokenPrivileges, Buffer, sizeof(Buffer), &Length))
        return FALSE;
    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (Privileges->Privileges[i].Luid.LowPart == Luid.LowPart &&
            Privileges->Privileges[i].Luid.HighPart == Luid.HighPart)
            return TRUE;
    }
    return FALSE;
}

/* open the log as the user of Token: the error, ERROR_SUCCESS when it opens */
static DWORD OpenAs(HANDLE Token, PCWSTR LogName)
{
    HANDLE hLog;
    DWORD Error;

    if (Token && !ImpersonateLoggedOnUser(Token))
        return GetLastError();
    SetLastError(ERROR_SUCCESS);
    hLog = OpenEventLogW(NULL, LogName);
    Error = hLog ? ERROR_SUCCESS : GetLastError();
    if (Token)
        RevertToSelf();
    if (hLog)
        CloseEventLog(hLog);
    return Error;
}

/* the same through the ANSI entry point (an ANSI RPC call of the service): measured on Windows Server 2022 equal to the wide one */
static DWORD OpenAsA(HANDLE Token, PCSTR LogName)
{
    HANDLE hLog;
    DWORD Error;

    if (Token && !ImpersonateLoggedOnUser(Token))
        return GetLastError();
    SetLastError(ERROR_SUCCESS);
    hLog = OpenEventLogA(NULL, LogName);
    Error = hLog ? ERROR_SUCCESS : GetLastError();
    if (Token)
        RevertToSelf();
    if (hLog)
        CloseEventLog(hLog);
    return Error;
}

START_TEST(EventLogSecurityAccess)
{
    WCHAR User[32];
    USER_INFO_1 Info;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    WCHAR Domain[256];
    DWORD SidLength = sizeof(Sid), DomainLength = RTL_NUMBER_OF(Domain), Err, Try, Error;
    SID_NAME_USE Use;
    HANDLE Token = NULL, Self = NULL;
    LOCALGROUP_MEMBERS_INFO_0 Member;
    static WCHAR RightName[] = L"SeSecurityPrivilege";
    NET_API_STATUS Status = NERR_UserExists;

    /* the caller (an administrator in the harness) holds the privilege: it opens the log */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Self))
    {
        if (TokenHasPrivilege(Self, RightName))
        {
            Error = OpenAs(NULL, L"Security");
            ok(Error == ERROR_SUCCESS, "administrator: OpenEventLog(Security) failed: %lu\n", Error);
            Error = OpenAsA(NULL, "Security");
            ok(Error == ERROR_SUCCESS, "administrator: OpenEventLogA(Security) failed: %lu\n", Error);
        }
        else
            skip("the test is not run by an account that holds SeSecurityPrivilege\n");
        CloseHandle(Self);
    }

    for (Try = 0; Try < 5 && Status == NERR_UserExists; Try++)
    {
        StringCchPrintfW(User, RTL_NUMBER_OF(User), L"evsec%lx", (GetTickCount() + Try * 7919) & 0xffffff);
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

    ok(LookupAccountNameW(NULL, User, Sid, &SidLength, Domain, &DomainLength, &Use),
       "LookupAccountName failed: %lu\n", GetLastError());

    ok(LogonUserW(User, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token),
       "LogonUser failed: %lu\n", GetLastError());
    if (Token)
    {
        /* a standard user */
        Error = OpenAs(Token, L"Security");
        ok(Error == ERROR_PRIVILEGE_NOT_HELD, "standard user: OpenEventLog(Security): error %lu, expected %d\n",
           Error, ERROR_PRIVILEGE_NOT_HELD);
        Error = OpenAs(Token, L"Application");
        ok(Error == ERROR_SUCCESS, "standard user: OpenEventLog(Application) failed: %lu\n", Error);
        Error = OpenAsA(Token, "Security");
        ok(Error == ERROR_PRIVILEGE_NOT_HELD, "standard user: OpenEventLogA(Security): error %lu, expected %d\n",
           Error, ERROR_PRIVILEGE_NOT_HELD);
        Error = OpenAsA(Token, "security");
        ok(Error == ERROR_PRIVILEGE_NOT_HELD, "standard user: OpenEventLogA(security): error %lu, expected %d\n",
           Error, ERROR_PRIVILEGE_NOT_HELD);
        Error = OpenAsA(Token, "Application");
        ok(Error == ERROR_SUCCESS, "standard user: OpenEventLogA(Application) failed: %lu\n", Error);
        CloseHandle(Token);
        Token = NULL;
    }

    /* the same user as a member of Administrators */
    Member.lgrmi0_sid = (PSID)Sid;
    Status = NetLocalGroupAddMembers(NULL, L"Administrators", 0, (PBYTE)&Member, 1);
    ok(Status == NERR_Success, "NetLocalGroupAddMembers failed: %lu\n", Status);
    if (Status == NERR_Success)
    {
        if (LogonUserW(User, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
        {
            Error = OpenAs(Token, L"Security");
            ok(Error == ERROR_SUCCESS, "administrator user: OpenEventLog(Security) failed: %lu\n", Error);
            Error = OpenAsA(Token, "Security");
            ok(Error == ERROR_SUCCESS, "administrator user: OpenEventLogA(Security) failed: %lu\n", Error);
            CloseHandle(Token);
        }
        NetLocalGroupDelMembers(NULL, L"Administrators", 0, (PBYTE)&Member, 1);
    }

    NetUserDel(NULL, User);
}

