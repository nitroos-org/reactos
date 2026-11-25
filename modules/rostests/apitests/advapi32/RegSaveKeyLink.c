/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests that RegSaveKey keeps a registry symbolic link a link
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/cmfuncs.h>

/*
 * Measured on Windows Server 2022: RegSaveKey of a tree with a link key writes the link key with the
 * symbolic-link flag (0x10) next to the compressed-name flag, and the saved hive, loaded again, opens the link
 * to its target in the same hive (Windows does not follow a link of a loaded hive into another hive). The saved
 * file also gives every key a stored descriptor.
 */

static BOOL EnablePrivilege(LPCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Ok;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Ok = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid) &&
         AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ok;
}

START_TEST(RegSaveKeyLink)
{
    /* The link's target is a key of the same hive, as it will be named once the saved file is loaded */
    static const WCHAR Target[] = L"\\Registry\\User\\ApitestSaveLinkLoaded\\plain";
    static const WCHAR Marker[] = L"plain-marker";
    WCHAR Path[MAX_PATH];
    HKEY Scratch = NULL, Link = NULL, Plain = NULL;
    WCHAR Buffer[64];
    DWORD Type, Size, Disposition;
    LONG Error;

    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege"))
    {
        skip("backup and restore privileges are needed\n");
        return;
    }

    GetTempPathW(RTL_NUMBER_OF(Path), Path);
    wcscat(Path, L"apitest-savelink.hiv");
    DeleteFileW(Path);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"ApitestSaveLink");

    Error = RegCreateKeyExW(HKEY_CURRENT_USER, L"ApitestSaveLink", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Scratch, &Disposition);
    ok_long(Error, ERROR_SUCCESS);
    if (Error != ERROR_SUCCESS)
        return;

    Error = RegCreateKeyExW(Scratch, L"plain", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Plain, &Disposition);
    ok_long(Error, ERROR_SUCCESS);
    if (Plain)
    {
        RegSetValueExW(Plain, L"Marker", 0, REG_SZ, (const BYTE *)Marker, sizeof(Marker));
        RegCloseKey(Plain);
    }
    Error = RegCreateKeyExW(Scratch, L"link", 0, NULL, REG_OPTION_CREATE_LINK, KEY_ALL_ACCESS | KEY_CREATE_LINK, NULL,
                            &Link, &Disposition);
    ok_long(Error, ERROR_SUCCESS);
    if (Link)
    {
        Error = RegSetValueExW(Link, L"SymbolicLinkValue", 0, REG_LINK, (const BYTE *)Target,
                               sizeof(Target) - sizeof(WCHAR));
        ok_long(Error, ERROR_SUCCESS);
        RegCloseKey(Link);
    }

    Error = RegSaveKeyW(Scratch, Path, NULL);
    ok_long(Error, ERROR_SUCCESS);

    if (Error == ERROR_SUCCESS)
    {
        Error = RegLoadKeyW(HKEY_USERS, L"ApitestSaveLinkLoaded", Path);
        ok_long(Error, ERROR_SUCCESS);
    }
    if (Error == ERROR_SUCCESS)
    {
        /* The link key resolves to its target: the target's value is read through it */
        Link = NULL;
        Error = RegOpenKeyExW(HKEY_USERS, L"ApitestSaveLinkLoaded\\link", 0, KEY_READ, &Link);
        ok_long(Error, ERROR_SUCCESS);
        if (Link)
        {
            Size = sizeof(Buffer);
            Buffer[0] = 0;
            Error = RegQueryValueExW(Link, L"Marker", NULL, &Type, (LPBYTE)Buffer, &Size);
            ok_long(Error, ERROR_SUCCESS);
            ok(!wcscmp(Buffer, Marker), "link read the value '%ls', expected the target's\n", Buffer);
            RegCloseKey(Link);
        }

        /* Opened as a link it is the link key itself, with its value */
        Link = NULL;
        Error = RegOpenKeyExW(HKEY_USERS, L"ApitestSaveLinkLoaded\\link", REG_OPTION_OPEN_LINK, KEY_READ, &Link);
        ok_long(Error, ERROR_SUCCESS);
        if (Link)
        {
            Size = sizeof(Buffer);
            Error = RegQueryValueExW(Link, L"SymbolicLinkValue", NULL, &Type, (LPBYTE)Buffer, &Size);
            ok_long(Error, ERROR_SUCCESS);
            ok_long(Type, REG_LINK);
            RegCloseKey(Link);
        }

        Error = RegUnLoadKeyW(HKEY_USERS, L"ApitestSaveLinkLoaded");
        ok_long(Error, ERROR_SUCCESS);
    }

    /* The link key is deleted as a link, not through its target */
    if (RegOpenKeyExW(Scratch, L"link", REG_OPTION_OPEN_LINK, DELETE, &Link) == ERROR_SUCCESS)
    {
        NtDeleteKey(Link);
        RegCloseKey(Link);
    }
    RegDeleteKeyW(Scratch, L"plain");
    RegCloseKey(Scratch);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"ApitestSaveLink");
    DeleteFileW(Path);
}
