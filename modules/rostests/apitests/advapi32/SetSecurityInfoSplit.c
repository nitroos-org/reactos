/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests how SetSecurityInfo and SetNamedSecurityInfo store ACEs with generic rights and inheritance flags
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>
#include <aclapi.h>

/*
 * Measured on Windows Server 2022 (x64 and x86 under WoW64, the same): on a directory or a key an effective ACE with inheritance flags
 * and generic rights is stored as two ACEs, an effective one without inheritance flags (generic rights mapped) and an inherit-only
 * copy with the generic rights as set; on a file the inheritance flags are not stored and inherit-only ACEs are dropped (DACL and
 * SACL); a deny GENERIC_EXECUTE on a key is 0x20039. Compared: the ACEs the call supplied (a protected DACL, so none are inherited).
 */

typedef struct { UCHAR Type, Flags; ULONG Mask; } ACE_ROW;
typedef struct { PCWSTR Sddl; ULONG Count; ACE_ROW Aces[6]; } SET_ROW;

enum { T_KEY, T_DIR, T_FILE, T_COUNT };

static const SET_ROW Rows[T_COUNT][3] =
{
    {   /* key: read 0x20019, write 0x20006, execute 0x20039, all 0xF003F */
        {L"D:(A;CI;GW;;;BA)(A;OI;GR;;;BU)(A;OICI;GA;;;SY)", 6,
         {{0, 0x00, 0x00020006}, {0, 0x0A, 0x40000000}, {0, 0x00, 0x00020019}, {0, 0x09, 0x80000000}, {0, 0x00, 0x000F003F}, {0, 0x0B, 0x10000000}}},
        {L"D:(A;;GA;;;WD)(A;OICI;GR;;;BU)", 3, {{0, 0x00, 0x000F003F}, {0, 0x00, 0x00020019}, {0, 0x0B, 0x80000000}}},
        {L"D:(A;;0x80000001;;;BU)(D;;GX;;;AN)", 2, {{0, 0x00, 0x00020019}, {1, 0x00, 0x00020039}}},
    },
    {   /* directory: read 0x120089, write 0x120116, all 0x1F01FF */
        {L"D:(A;CI;GW;;;BA)(A;OI;GR;;;BU)(A;OICI;GA;;;SY)", 6,
         {{0, 0x00, 0x00120116}, {0, 0x0A, 0x40000000}, {0, 0x00, 0x00120089}, {0, 0x09, 0x80000000}, {0, 0x00, 0x001F01FF}, {0, 0x0B, 0x10000000}}},
        {L"D:(A;;GA;;;WD)(A;OICI;GR;;;BU)", 3, {{0, 0x00, 0x001F01FF}, {0, 0x00, 0x00120089}, {0, 0x0B, 0x80000000}}},
        {L"D:(A;OICIIO;GA;;;CO)(A;CIIO;GR;;;BU)(A;;0x1F01FF;;;SY)", 3, {{0, 0x0B, 0x10000000}, {0, 0x0A, 0x80000000}, {0, 0x00, 0x001F01FF}}},
    },
    {   /* file */
        {L"D:(A;CI;GW;;;BA)(A;OI;GR;;;BU)(A;OICI;GA;;;SY)", 3, {{0, 0x00, 0x00120116}, {0, 0x00, 0x00120089}, {0, 0x00, 0x001F01FF}}},
        {L"D:(A;;GA;;;WD)(A;OICI;GR;;;BU)", 2, {{0, 0x00, 0x001F01FF}, {0, 0x00, 0x00120089}}},
        {L"D:(A;OICIIO;GA;;;CO)(A;CIIO;GR;;;BU)(A;;0x1F01FF;;;SY)", 1, {{0, 0x00, 0x001F01FF}}},
    },
};

static void CheckAcl(PACL Acl, const SET_ROW *Row, const char *What, ULONG Index)
{
    ULONG i;

    ok(Acl != NULL, "%s %lu: no DACL\n", What, Index);
    if (!Acl)
        return;
    ok(Acl->AceCount >= Row->Count, "%s %lu: %u ACEs, expected at least %lu\n", What, Index, Acl->AceCount, Row->Count);
    for (i = 0; i < Row->Count && i < Acl->AceCount; i++)
    {
        ACCESS_ALLOWED_ACE *Ace;

        if (!GetAce(Acl, i, (PVOID *)&Ace))
            break;
        ok(Ace->Header.AceType == Row->Aces[i].Type && (Ace->Header.AceFlags & ~INHERITED_ACE) == Row->Aces[i].Flags &&
           Ace->Mask == Row->Aces[i].Mask,
           "%s %lu ACE %lu: (%u;%02x;%08lx), expected (%u;%02x;%08lx)\n", What, Index, i,
           Ace->Header.AceType, Ace->Header.AceFlags, Ace->Mask, Row->Aces[i].Type, Row->Aces[i].Flags, Row->Aces[i].Mask);
    }
}

static void Run(ULONG Target, PCWSTR Name, BOOL Named, HANDLE Handle, SE_OBJECT_TYPE Type, const char *What)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Rows[Target]); i++)
    {
        PSECURITY_DESCRIPTOR Sd = NULL, Read = NULL;
        PACL Dacl = NULL, ReadDacl = NULL;
        BOOL Present, Defaulted;
        DWORD Error;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Rows[Target][i].Sddl, SDDL_REVISION_1, &Sd, NULL))
        {
            ok(0, "SDDL %ls: %lu\n", Rows[Target][i].Sddl, GetLastError());
            continue;
        }
        GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
        if (Named)
        {
            Error = SetNamedSecurityInfoW((PWSTR)Name, Type, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                          NULL, NULL, Dacl, NULL);
            ok(Error == ERROR_SUCCESS, "%s %lu: SetNamedSecurityInfo: %lu\n", What, i, Error);
            Error = GetNamedSecurityInfoW((PWSTR)Name, Type, DACL_SECURITY_INFORMATION, NULL, NULL, &ReadDacl, NULL, &Read);
        }
        else
        {
            Error = SetSecurityInfo(Handle, Type, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                    NULL, NULL, Dacl, NULL);
            ok(Error == ERROR_SUCCESS, "%s %lu: SetSecurityInfo: %lu\n", What, i, Error);
            Error = GetSecurityInfo(Handle, Type, DACL_SECURITY_INFORMATION, NULL, NULL, &ReadDacl, NULL, &Read);
        }
        ok(Error == ERROR_SUCCESS, "%s %lu: get: %lu\n", What, i, Error);
        if (Error == ERROR_SUCCESS)
        {
            CheckAcl(ReadDacl, &Rows[Target][i], What, i);
            LocalFree(Read);
        }
        LocalFree(Sd);
    }
}

START_TEST(SetSecurityInfoSplit)
{
    WCHAR Dir[MAX_PATH], DirPath[MAX_PATH], FilePath[MAX_PATH], KeyPath[128];
    HKEY Key = NULL;
    HANDLE File, DirHandle;

    /* the key */
    StringCchPrintfW(KeyPath, RTL_NUMBER_OF(KeyPath), L"Software\\SetSecInfoSplit%lu", GetCurrentProcessId());
    if (RegCreateKeyExW(HKEY_CURRENT_USER, KeyPath, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS | WRITE_DAC | READ_CONTROL, NULL, &Key, NULL) == ERROR_SUCCESS)
    {
        WCHAR Named[200];

        StringCchPrintfW(Named, RTL_NUMBER_OF(Named), L"CURRENT_USER\\%ls", KeyPath);
        Run(T_KEY, NULL, FALSE, Key, SE_REGISTRY_KEY, "key SetSecurityInfo");
        Run(T_KEY, Named, TRUE, NULL, SE_REGISTRY_KEY, "key SetNamedSecurityInfo");
        {
            PSECURITY_DESCRIPTOR Open = NULL;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;KA;;;WD)", SDDL_REVISION_1, &Open, NULL))
            {
                RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Open);
                LocalFree(Open);
            }
        }
        RegCloseKey(Key);
        RegDeleteKeyW(HKEY_CURRENT_USER, KeyPath);
    }
    else
        skip("the scratch key could not be created\n");

    /* the directory and the file */
    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    StringCchPrintfW(DirPath, RTL_NUMBER_OF(DirPath), L"%lsSetSecInfoSplit%lu", Dir, GetCurrentProcessId());
    StringCchPrintfW(FilePath, RTL_NUMBER_OF(FilePath), L"%lsSetSecInfoSplit%lu.tmp", Dir, GetCurrentProcessId());
    if (CreateDirectoryW(DirPath, NULL))
    {
        DirHandle = CreateFileW(DirPath, READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (DirHandle != INVALID_HANDLE_VALUE)
        {
            BYTE Probe[512];
            DWORD Needed;

            if (GetFileSecurityW(DirPath, DACL_SECURITY_INFORMATION, Probe, sizeof(Probe), &Needed))
            {
                Run(T_DIR, NULL, FALSE, DirHandle, SE_FILE_OBJECT, "directory SetSecurityInfo");
                Run(T_DIR, DirPath, TRUE, NULL, SE_FILE_OBJECT, "directory SetNamedSecurityInfo");
            }
            else
                skip("the volume keeps no security descriptors (FAT)\n");
            CloseHandle(DirHandle);
        }
        {
            PSECURITY_DESCRIPTOR Open = NULL;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;FA;;;WD)", SDDL_REVISION_1, &Open, NULL))
            {
                SetFileSecurityW(DirPath, DACL_SECURITY_INFORMATION, Open);
                LocalFree(Open);
            }
        }
        RemoveDirectoryW(DirPath);
    }
    File = CreateFileW(FilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        HANDLE Handle;

        CloseHandle(File);
        Handle = CreateFileW(FilePath, READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (Handle != INVALID_HANDLE_VALUE)
        {
            Run(T_FILE, NULL, FALSE, Handle, SE_FILE_OBJECT, "file SetSecurityInfo");
            Run(T_FILE, FilePath, TRUE, NULL, SE_FILE_OBJECT, "file SetNamedSecurityInfo");
            CloseHandle(Handle);
        }
        {
            PSECURITY_DESCRIPTOR Open = NULL;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)", SDDL_REVISION_1, &Open, NULL))
            {
                SetFileSecurityW(FilePath, DACL_SECURITY_INFORMATION, Open);
                LocalFree(Open);
            }
        }
        DeleteFileW(FilePath);
    }
}
