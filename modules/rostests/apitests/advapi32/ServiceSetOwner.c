/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetServiceObjectSecurity: which owners a caller may set
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every row is a measurement on Windows Server 2022 (build 20348) with a scratch service. A standard user that
 * holds WRITE_OWNER may set its own user and nothing else; an administrator may set any SID; the token of an
 * administrator without privileges (DISABLE_MAX_PRIVILEGE) may set Administrators, a group with the owner
 * attribute, and nothing else: ERROR_INVALID_OWNER.
 */

#include "precomp.h"
#include <sddl.h>

static const WCHAR ServiceName[] = L"apitest_owner_rows";

static BOOL TrySetOwner(SC_HANDLE hService, PCWSTR SidString, DWORD *pError)
{
    SECURITY_DESCRIPTOR Sd;
    PSID Sid = NULL;
    BOOL Ret;

    ok(ConvertStringSidToSidW(SidString, &Sid), "ConvertStringSidToSid(%ls)\n", SidString);
    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&Sd, Sid, FALSE);
    SetLastError(0xdeadbeef);
    Ret = SetServiceObjectSecurity(hService, OWNER_SECURITY_INFORMATION, &Sd);
    *pError = Ret ? 0 : GetLastError();
    LocalFree(Sid);
    return Ret;
}

static void CheckOwner(SC_HANDLE hService, PCWSTR SidString, BOOL Expected, int Line)
{
    DWORD Error;
    BOOL Ret = TrySetOwner(hService, SidString, &Error);

    ok(Ret == Expected, "line %d: owner %ls: got %d (error %lu), expected %d\n", Line, SidString, Ret, Error, Expected);
    if (!Expected)
        ok(Error == ERROR_INVALID_OWNER, "line %d: owner %ls: error %lu, expected %u\n", Line, SidString, Error,
           ERROR_INVALID_OWNER);
}

START_TEST(ServiceSetOwner)
{
    static const WCHAR RandomSid[] = L"S-1-5-21-1111111111-2222222222-3333333333-4242";
    SC_HANDLE hManager, hService;
    HANDLE hToken = NULL, hRestricted = NULL, hImpersonation = NULL;

    {
        HANDLE hSelf;
        TOKEN_PRIVILEGES Privileges;

        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hSelf))
        {
            if (LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &Privileges.Privileges[0].Luid))
                AdjustTokenPrivileges(hSelf, FALSE, &Privileges, 0, NULL, NULL);
            CloseHandle(hSelf);
        }
    }

    hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hManager)
    {
        skip("OpenSCManager: %lu\n", GetLastError());
        return;
    }
    hService = OpenServiceW(hManager, ServiceName, DELETE);
    if (hService)
    {
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    hService = CreateServiceW(hManager, ServiceName, ServiceName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                              SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, L"C:\\nosuchprogram.exe", NULL, NULL, NULL,
                              NULL, NULL);
    ok(hService != NULL, "CreateService: %lu\n", GetLastError());
    if (!hService)
    {
        CloseServiceHandle(hManager);
        return;
    }

    /* the administrator with SeRestorePrivilege enabled (the service controller sees the enabled privileges of its caller;
       the token of a console logon has it disabled, the one of the remote shell of the reference enabled): any SID */
    CheckOwner(hService, RandomSid, TRUE, __LINE__);
    CheckOwner(hService, L"S-1-1-0", TRUE, __LINE__);
    CheckOwner(hService, L"S-1-5-32-544", TRUE, __LINE__);

    /* the same token without its privileges: a group with the owner attribute, not a SID of nobody or Everyone */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
        CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hRestricted) &&
        DuplicateTokenEx(hRestricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hImpersonation))
    {
        SC_HANDLE hManager2, hService2;

        ok(SetThreadToken(NULL, hImpersonation), "SetThreadToken: %lu\n", GetLastError());
        hManager2 = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        hService2 = hManager2 ? OpenServiceW(hManager2, ServiceName, WRITE_OWNER | READ_CONTROL) : NULL;
        ok(hService2 != NULL, "OpenService with the token without privileges: %lu\n", GetLastError());
        if (hService2)
        {
            CheckOwner(hService2, RandomSid, FALSE, __LINE__);
            CheckOwner(hService2, L"S-1-1-0", FALSE, __LINE__);
            CheckOwner(hService2, L"S-1-5-18", FALSE, __LINE__);
            CheckOwner(hService2, L"S-1-5-32-544", TRUE, __LINE__);
            CloseServiceHandle(hService2);
        }
        if (hManager2)
            CloseServiceHandle(hManager2);
        SetThreadToken(NULL, NULL);
    }
    else
    {
        skip("no token without privileges: %lu\n", GetLastError());
    }

    if (hImpersonation) CloseHandle(hImpersonation);
    if (hRestricted) CloseHandle(hRestricted);
    if (hToken) CloseHandle(hToken);
    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hManager);
}
