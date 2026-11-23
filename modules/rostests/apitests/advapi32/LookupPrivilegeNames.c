/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     LookupPrivilegeValue, LookupPrivilegeName and LookupPrivilegeDisplayName know every privilege
 *              of the documented list: the numbers 2 to 36, among them SeTrustedCredManAccessPrivilege (31),
 *              SeRelabelPrivilege (32), SeIncreaseWorkingSetPrivilege (33) and
 *              SeDelegateSessionUserImpersonatePrivilege (36), and no other
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The numbers, names and display names were measured on Windows Server 2022 (build 20348, English).
 */

#include "precomp.h"

static const struct
{
    ULONG Luid;
    PCWSTR Name;
} Privileges[] =
{
    { 2, L"SeCreateTokenPrivilege" }, { 3, L"SeAssignPrimaryTokenPrivilege" }, { 4, L"SeLockMemoryPrivilege" },
    { 5, L"SeIncreaseQuotaPrivilege" }, { 6, L"SeMachineAccountPrivilege" }, { 7, L"SeTcbPrivilege" },
    { 8, L"SeSecurityPrivilege" }, { 9, L"SeTakeOwnershipPrivilege" }, { 10, L"SeLoadDriverPrivilege" },
    { 11, L"SeSystemProfilePrivilege" }, { 12, L"SeSystemtimePrivilege" }, { 13, L"SeProfileSingleProcessPrivilege" },
    { 14, L"SeIncreaseBasePriorityPrivilege" }, { 15, L"SeCreatePagefilePrivilege" }, { 16, L"SeCreatePermanentPrivilege" },
    { 17, L"SeBackupPrivilege" }, { 18, L"SeRestorePrivilege" }, { 19, L"SeShutdownPrivilege" },
    { 20, L"SeDebugPrivilege" }, { 21, L"SeAuditPrivilege" }, { 22, L"SeSystemEnvironmentPrivilege" },
    { 23, L"SeChangeNotifyPrivilege" }, { 24, L"SeRemoteShutdownPrivilege" }, { 25, L"SeUndockPrivilege" },
    { 26, L"SeSyncAgentPrivilege" }, { 27, L"SeEnableDelegationPrivilege" }, { 28, L"SeManageVolumePrivilege" },
    { 29, L"SeImpersonatePrivilege" }, { 30, L"SeCreateGlobalPrivilege" }, { 31, L"SeTrustedCredManAccessPrivilege" },
    { 32, L"SeRelabelPrivilege" }, { 33, L"SeIncreaseWorkingSetPrivilege" }, { 34, L"SeTimeZonePrivilege" },
    { 35, L"SeCreateSymbolicLinkPrivilege" }, { 36, L"SeDelegateSessionUserImpersonatePrivilege" },
};

/* Display names measured on Windows (the languages other than English carry the English text for these four) */
static const struct
{
    PCWSTR Name;
    PCWSTR Display;
} Displays[] =
{
    { L"SeTrustedCredManAccessPrivilege", L"Access Credential Manager as a trusted caller" },
    { L"SeRelabelPrivilege", L"Modify an object label" },
    { L"SeIncreaseWorkingSetPrivilege", L"Increase a process working set" },
    { L"SeDelegateSessionUserImpersonatePrivilege", L"Obtain an impersonation token for another user in the same session" },
};

START_TEST(LookupPrivilegeNames)
{
    ULONG i;
    LUID Luid;
    WCHAR Name[128], Display[256];
    DWORD Length, Language;
    BOOL Ret;

    for (i = 0; i < _countof(Privileges); i++)
    {
        SetLastError(0xdeadbeef);
        Ret = LookupPrivilegeValueW(NULL, Privileges[i].Name, &Luid);
        ok(Ret, "LookupPrivilegeValue(%ls) failed with %lu\n", Privileges[i].Name, GetLastError());
        if (Ret)
        {
            ok(Luid.HighPart == 0 && Luid.LowPart == Privileges[i].Luid, "%ls: LUID %lu:%lu, expected %lu\n",
               Privileges[i].Name, Luid.HighPart, Luid.LowPart, Privileges[i].Luid);
        }

        Luid.HighPart = 0;
        Luid.LowPart = Privileges[i].Luid;
        Length = _countof(Name);
        SetLastError(0xdeadbeef);
        Ret = LookupPrivilegeNameW(NULL, &Luid, Name, &Length);
        ok(Ret, "LookupPrivilegeName(%lu) failed with %lu\n", Privileges[i].Luid, GetLastError());
        if (Ret)
            ok(!wcscmp(Name, Privileges[i].Name), "LUID %lu is named %ls, expected %ls\n", Privileges[i].Luid, Name, Privileges[i].Name);

        Length = _countof(Display);
        Language = 0;
        SetLastError(0xdeadbeef);
        Ret = LookupPrivilegeDisplayNameW(NULL, Privileges[i].Name, Display, &Length, &Language);
        ok(Ret, "LookupPrivilegeDisplayName(%ls) failed with %lu\n", Privileges[i].Name, GetLastError());
        if (Ret)
            ok(Display[0] != 0, "%ls: no display name\n", Privileges[i].Name);
    }

    for (i = 0; i < _countof(Displays); i++)
    {
        Length = _countof(Display);
        Language = 0;
        if (LookupPrivilegeDisplayNameW(NULL, Displays[i].Name, Display, &Length, &Language) && Language == 0x409)
            ok(!wcscmp(Display, Displays[i].Display), "%ls: \"%ls\", expected \"%ls\"\n", Displays[i].Name, Display, Displays[i].Display);
    }

    /* Numbers outside 2..36 and names that are none */
    for (i = 0; i < 64; i++)
    {
        if (i >= 2 && i <= 36)
            continue;
        Luid.HighPart = 0;
        Luid.LowPart = i;
        Length = _countof(Name);
        SetLastError(0xdeadbeef);
        Ret = LookupPrivilegeNameW(NULL, &Luid, Name, &Length);
        ok(!Ret && GetLastError() == ERROR_NO_SUCH_PRIVILEGE, "LUID %lu: ret %d, error %lu\n", i, Ret, GetLastError());
    }
    SetLastError(0xdeadbeef);
    Ret = LookupPrivilegeValueW(NULL, L"SeNoSuchPrivilege", &Luid);
    ok(!Ret && GetLastError() == ERROR_NO_SUCH_PRIVILEGE, "unknown name: ret %d, error %lu\n", Ret, GetLastError());
}
