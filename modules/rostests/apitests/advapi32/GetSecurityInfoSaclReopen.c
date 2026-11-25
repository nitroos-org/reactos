/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetSecurityInfo reads the SACL of the key the handle names, not of whatever has the name now
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>

typedef LONG (NTAPI *PFN_NtRenameKey)(HANDLE, PUNICODE_STRING);

/* the declaration needs a newer header version than these tests are compiled with */
LONG WINAPI RegDeleteTreeW(HKEY, LPCWSTR);

static BOOL EnableSecurityPrivilege(void)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &Tp.Privileges[0].Luid);
    Ret = AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ret;
}

/* the mask of the first audit ACE of the key's SACL as GetSecurityInfo returns it, or 0xffffffff and *Error */
static ULONG SaclMask(HKEY Key, DWORD *Error)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Sacl = NULL;
    ACCESS_ALLOWED_ACE *Ace;
    ULONG Mask = 0xffffffff;

    *Error = GetSecurityInfo(Key, SE_REGISTRY_KEY, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, &Sacl, &Sd);
    if (*Error == ERROR_SUCCESS && Sacl && Sacl->AceCount >= 1 && GetAce(Sacl, 0, (void **)&Ace))
        Mask = Ace->Mask;
    LocalFree(Sd);
    return Mask;
}

static BOOL SetSaclMask(HKEY Key, ACCESS_MASK Mask)
{
    BYTE AclBuf[256];
    PACL Acl = (PACL)AclBuf;
    BYTE SidBuf[SECURITY_MAX_SID_SIZE];
    DWORD SidSize = sizeof(SidBuf);

    if (!CreateWellKnownSid(WinWorldSid, NULL, SidBuf, &SidSize))
        return FALSE;
    InitializeAcl(Acl, sizeof(AclBuf), ACL_REVISION);
    if (!AddAuditAccessAce(Acl, ACL_REVISION, Mask, SidBuf, TRUE, FALSE))
        return FALSE;
    return SetSecurityInfo(Key, SE_REGISTRY_KEY, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, Acl) == ERROR_SUCCESS;
}

START_TEST(GetSecurityInfoSaclReopen)
{
    PFN_NtRenameKey pNtRenameKey = (PFN_NtRenameKey)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtRenameKey");
    static const WCHAR Base[] = L"Software\\GetSecInfoSaclReopen";
    HKEY Root = NULL, Key, Reader, Other, Deep;
    DWORD Error, Disp, i;
    ULONG Mask;
    WCHAR Path[1024];
    UNICODE_STRING NewName;
    LONG Status;

    if (!EnableSecurityPrivilege())
    {
        skip("SeSecurityPrivilege is not available\n");
        return;
    }

    RegDeleteTreeW(HKEY_CURRENT_USER, Base);
    ok_long(RegCreateKeyExW(HKEY_CURRENT_USER, Base, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Root, &Disp), ERROR_SUCCESS);
    if (!Root)
        return;

    /* the SACL of a plain key, read through a handle that was opened without ACCESS_SYSTEM_SECURITY */
    ok_long(RegCreateKeyExW(Root, L"first", 0, NULL, 0, KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, NULL, &Key, &Disp), ERROR_SUCCESS);
    ok(SetSaclMask(Key, KEY_QUERY_VALUE), "SetSecurityInfo of the SACL failed\n");
    RegCloseKey(Key);
    ok_long(RegOpenKeyExW(Root, L"first", 0, KEY_READ | KEY_WRITE, &Reader), ERROR_SUCCESS);
    Mask = SaclMask(Reader, &Error);
    ok_long(Error, ERROR_SUCCESS);
    ok_hex(Mask, KEY_QUERY_VALUE);

    /* the key is renamed after it was opened and another key takes its name: the handle still names the first one */
    if (pNtRenameKey)
    {
        RtlInitUnicodeString(&NewName, L"renamed");
        Status = pNtRenameKey(Reader, &NewName);
        ok_hex(Status, STATUS_SUCCESS);
        if (Status == STATUS_SUCCESS)
        {
            ok_long(RegCreateKeyExW(Root, L"first", 0, NULL, 0, KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, NULL, &Other, &Disp), ERROR_SUCCESS);
            ok(SetSaclMask(Other, KEY_SET_VALUE), "SetSecurityInfo of the SACL failed\n");
            RegCloseKey(Other);
            Mask = SaclMask(Reader, &Error);
            ok_long(Error, ERROR_SUCCESS);
            ok_hex(Mask, KEY_QUERY_VALUE);
        }
    }
    RegCloseKey(Reader);

    /* a key whose full name is longer than the 520 characters the name based path could hold */
    Path[0] = 0;
    for (i = 0; i < 4; i++)
    {
        SIZE_T Len = wcslen(Path), j;

        if (Len)
            Path[Len++] = L'\\';
        for (j = 0; j < 200; j++)
            Path[Len + j] = L'a' + (WCHAR)i;
        Path[Len + 200] = 0;
    }
    Error = RegCreateKeyExW(Root, Path, 0, NULL, 0, KEY_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, NULL, &Deep, &Disp);
    ok_long(Error, ERROR_SUCCESS);
    if (Error == ERROR_SUCCESS)
    {
        ok(SetSaclMask(Deep, KEY_ENUMERATE_SUB_KEYS), "SetSecurityInfo of the SACL failed\n");
        RegCloseKey(Deep);
        ok_long(RegOpenKeyExW(Root, Path, 0, KEY_READ, &Deep), ERROR_SUCCESS);
        Mask = SaclMask(Deep, &Error);
        ok_long(Error, ERROR_SUCCESS);
        ok_hex(Mask, KEY_ENUMERATE_SUB_KEYS);
        RegCloseKey(Deep);
    }

    RegCloseKey(Root);
    RegDeleteTreeW(HKEY_CURRENT_USER, Base);
}
