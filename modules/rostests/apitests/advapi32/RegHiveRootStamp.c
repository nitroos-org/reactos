/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The root descriptor of the SECURITY hive and of the user's hive goes with the hive file:
 *              save the hive, load the file at another place, read the root's descriptor there
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A loaded hive root reports its own descriptor when it has one; without one, NitroOS reports the
 * policy descriptor of the place it is loaded at (HKLM\<name>: the hive-root one, Users read). So the
 * root of a hive saved from HKLM\SECURITY or HKU\<SID> and loaded at HKLM\<scratch> tells whether
 * the descriptor is stored in the hive: SYSTEM full control and Administrators READ_CONTROL|WRITE_DAC
 * only (SECURITY, Windows 10 value of the design capture), the user's own full-control ACE (HKU\<SID>).
 * Needs an administrator (SeBackupPrivilege and SeRestorePrivilege); writes only %TEMP% files and a
 * hive loaded at HKLM\ReactOS-apitest-RegHiveRootStamp, both removed at the end.
 */

#include "precomp.h"
#include <aclapi.h>

static const WCHAR Mount[] = L"ReactOS-apitest-RegHiveRootStamp";

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Set;
    BOOL Ok;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Set.PrivilegeCount = 1;
    Set.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Ok = LookupPrivilegeValueW(NULL, Name, &Set.Privileges[0].Luid) &&
         AdjustTokenPrivileges(Token, FALSE, &Set, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ok;
}

static PSID AllocWellKnown(WELL_KNOWN_SID_TYPE Type)
{
    DWORD Size = SECURITY_MAX_SID_SIZE;
    PSID Sid = LocalAlloc(LPTR, Size);

    if (Sid && !CreateWellKnownSid(Type, NULL, Sid, &Size))
    {
        LocalFree(Sid);
        Sid = NULL;
    }
    return Sid;
}

/* The mask of the first allow ACE for Sid that applies to the key itself, or 0 */
static ACCESS_MASK AllowedTo(PACL Dacl, PSID Sid)
{
    ACCESS_ALLOWED_ACE *Ace;
    DWORD i;

    for (i = 0; Dacl && i < Dacl->AceCount; i++)
    {
        if (GetAce(Dacl, i, (PVOID *)&Ace) && Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            !(Ace->Header.AceFlags & INHERIT_ONLY_ACE) && EqualSid((PSID)&Ace->SidStart, Sid))
        {
            return Ace->Mask;
        }
    }
    return 0;
}

/* Save Root\Path to a file, load the file at HKLM\Mount and read the root's DACL. Returns the DACL holder (LocalFree) */
static PSECURITY_DESCRIPTOR SaveAndReload(HKEY Root, PCWSTR Path, PACL *Dacl)
{
    WCHAR Dir[MAX_PATH], File[MAX_PATH];
    PSECURITY_DESCRIPTOR Sd = NULL;
    HKEY Key;
    LONG Error;
    BOOL Present, Defaulted;

    *Dacl = NULL;
    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    StringCchPrintfW(File, RTL_NUMBER_OF(File), L"%lsRegHiveRootStamp-%lu.hiv", Dir, GetCurrentProcessId());
    DeleteFileW(File);
    /* RegCreateKeyEx documents REG_OPTION_BACKUP_RESTORE (an existing key is opened): SECURITY grants
       Administrators no read access, the backup privilege does */
    Error = RegCreateKeyExW(Root, Path, 0, NULL, REG_OPTION_BACKUP_RESTORE, KEY_READ, NULL, &Key, NULL);
    if (Error)
        Error = RegOpenKeyExW(Root, Path, 0, KEY_READ, &Key);
    ok(Error == ERROR_SUCCESS, "open %ls: %ld\n", Path, Error);
    if (Error)
        return NULL;
    Error = RegSaveKeyW(Key, File, NULL);
    RegCloseKey(Key);
    ok(Error == ERROR_SUCCESS, "save %ls: %ld\n", Path, Error);
    if (Error)
        goto Done;
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, Mount);
    Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, Mount, File);
    ok(Error == ERROR_SUCCESS, "load the saved %ls: %ld\n", Path, Error);
    if (Error)
        goto Done;
    if (GetNamedSecurityInfoW(L"MACHINE\\ReactOS-apitest-RegHiveRootStamp", SE_REGISTRY_KEY,
                              DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd) == ERROR_SUCCESS)
    {
        GetSecurityDescriptorDacl(Sd, &Present, Dacl, &Defaulted);
    }
    ok(*Dacl != NULL, "no DACL on the loaded root of %ls\n", Path);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, Mount);
Done:
    DeleteFileW(File);
    return Sd;
}

START_TEST(RegHiveRootStamp)
{
    PSID System = AllocWellKnown(WinLocalSystemSid);
    PSID Admins = AllocWellKnown(WinBuiltinAdministratorsSid);
    PSID Users = AllocWellKnown(WinBuiltinUsersSid);
    PSECURITY_DESCRIPTOR Sd;
    PTOKEN_USER User = NULL;
    HANDLE Token;
    DWORD Length = 0;
    PACL Dacl;

    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege"))
    {
        skip("SeBackupPrivilege and SeRestorePrivilege are needed (run as an administrator)\n");
        goto Cleanup;
    }

    /* SECURITY: SYSTEM full control, Administrators READ_CONTROL | WRITE_DAC, nobody else (not the Users read of a hive root) */
    Sd = SaveAndReload(HKEY_LOCAL_MACHINE, L"SECURITY", &Dacl);
    if (Dacl)
    {
        ok(AllowedTo(Dacl, System) == KEY_ALL_ACCESS, "SECURITY root: SYSTEM gets 0x%lx\n", AllowedTo(Dacl, System));
        ok(AllowedTo(Dacl, Admins) == (READ_CONTROL | WRITE_DAC), "SECURITY root: Administrators get 0x%lx\n",
           AllowedTo(Dacl, Admins));
        ok(AllowedTo(Dacl, Users) == 0, "SECURITY root: Users get 0x%lx (the descriptor did not go with the hive)\n",
           AllowedTo(Dacl, Users));
    }
    LocalFree(Sd);

    /* the user's hive: the root keeps its own full-control ACE for the user */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        GetTokenInformation(Token, TokenUser, NULL, 0, &Length);
        User = LocalAlloc(LPTR, Length);
        if (User && !GetTokenInformation(Token, TokenUser, User, Length, &Length))
        {
            LocalFree(User);
            User = NULL;
        }
        CloseHandle(Token);
    }
    if (User)
    {
        Sd = SaveAndReload(HKEY_CURRENT_USER, L"", &Dacl);
        if (Dacl)
        {
            ok(AllowedTo(Dacl, User->User.Sid) == KEY_ALL_ACCESS, "user hive root: the user gets 0x%lx\n",
               AllowedTo(Dacl, User->User.Sid));
            ok(AllowedTo(Dacl, Users) == 0, "user hive root: Users get 0x%lx (the descriptor did not go with the hive)\n",
               AllowedTo(Dacl, Users));
        }
        LocalFree(Sd);
        LocalFree(User);
    }

Cleanup:
    LocalFree(System);
    LocalFree(Admins);
    LocalFree(Users);
}
