/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     OpenProcessToken of the own process with ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege enabled
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022, elevated administrator: with SeSecurityPrivilege enabled the open succeeds and the handle
 * has exactly the requested rights (ACCESS_SYSTEM_SECURITY, also with TOKEN_QUERY); with the privilege disabled or
 * removed it fails with ERROR_PRIVILEGE_NOT_HELD; a request without that right is not affected.
 */

#include "precomp.h"

static BOOL SetSecurityPrivilege(DWORD Attributes)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = Attributes;
    if (!LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &Tp.Privileges[0].Luid))
    {
        CloseHandle(Token);
        return FALSE;
    }
    Ret = AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ret;
}

static void CheckOpen(const char *When, DWORD Access, BOOL Allowed)
{
    HANDLE Token = NULL;
    BOOL Ret;

    SetLastError(0xdeadbeef);
    Ret = OpenProcessToken(GetCurrentProcess(), Access, &Token);
    if (Allowed)
    {
        ok(Ret, "%s: access 0x%lx failed: %lu\n", When, Access, GetLastError());
    }
    else
    {
        ok(!Ret, "%s: access 0x%lx succeeded\n", When, Access);
        ok(GetLastError() == ERROR_PRIVILEGE_NOT_HELD, "%s: error %lu\n", When, GetLastError());
    }
    if (Ret)
        CloseHandle(Token);
}

START_TEST(OpenProcessTokenSystemSecurity)
{
    if (!SetSecurityPrivilege(SE_PRIVILEGE_ENABLED))
    {
        skip("SeSecurityPrivilege is not held\n");
        return;
    }
    CheckOpen("enabled", ACCESS_SYSTEM_SECURITY, TRUE);
    CheckOpen("enabled", ACCESS_SYSTEM_SECURITY | TOKEN_QUERY, TRUE);
    CheckOpen("enabled", TOKEN_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, TRUE);

    SetSecurityPrivilege(0);
    CheckOpen("disabled", ACCESS_SYSTEM_SECURITY, FALSE);
    CheckOpen("disabled", ACCESS_SYSTEM_SECURITY | TOKEN_QUERY, FALSE);
    CheckOpen("disabled", TOKEN_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE);
    CheckOpen("disabled", TOKEN_QUERY, TRUE);
    CheckOpen("disabled", MAXIMUM_ALLOWED, TRUE);

    SetSecurityPrivilege(SE_PRIVILEGE_REMOVED);
    CheckOpen("removed", ACCESS_SYSTEM_SECURITY, FALSE);
    CheckOpen("removed", TOKEN_QUERY, TRUE);
}
