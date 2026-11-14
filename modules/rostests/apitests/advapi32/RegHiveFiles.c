/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Hive file services (save, restore, load, unload, open sub key count) must work from every
 *              process type, including a 32-bit process on a 64-bit system
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/cmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

static PCWSTR SourcePath = L"Software\\ReactOSHiveFilesSource";
static PCWSTR HiveName = L"ReactOSHiveFilesHive";
static PCWSTR HiveName2 = L"ReactOSHiveFilesHive2";
static PCWSTR Suffixes[] = { L"", L".LOG", L".LOG1", L".LOG2" };

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Success;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FALSE;

    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Success = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid) &&
              AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Success;
}

static void DeleteHiveFiles(PCWSTR File)
{
    WCHAR Name[MAX_PATH + 8];
    ULONG i;

    for (i = 0; i < _countof(Suffixes); i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"%s%s", File, Suffixes[i]);
        DeleteFileW(Name);
    }
}

static void CheckLoadedHive(PCWSTR Name, PCSTR What)
{
    HKEY Key;
    DWORD Type, Value, Size;
    LONG Error;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Name, 0, KEY_READ, &Key);
    ok(Error == ERROR_SUCCESS, "%s: RegOpenKeyExW failed: %ld\n", What, Error);
    if (Error != ERROR_SUCCESS)
        return;
    Value = 0;
    Size = sizeof(Value);
    Error = RegQueryValueExW(Key, L"Marker", NULL, &Type, (PBYTE)&Value, &Size);
    ok(Error == ERROR_SUCCESS, "%s: RegQueryValueExW failed: %ld\n", What, Error);
    ok(Type == REG_DWORD && Value == 0x12345678, "%s: Marker is type %lu value 0x%lx\n", What, Type, Value);
    RegCloseKey(Key);
}

static void TestNtSideServices(PCWSTR File)
{
    UNICODE_STRING Name, FileName;
    OBJECT_ATTRIBUTES KeyAttributes, FileAttributes;
    WCHAR KeyPath[128], NtFile[MAX_PATH + 8];
    HKEY Key;
    ULONG Count;
    NTSTATUS Status;
    LONG Error;

    /* NtLoadKey2 (RegLoadKey calls NtLoadKey): a file given as a DOS path in the NT namespace */
    StringCchPrintfW(KeyPath, _countof(KeyPath), L"\\Registry\\Machine\\%s", HiveName2);
    StringCchPrintfW(NtFile, _countof(NtFile), L"\\??\\%s", File);
    RtlInitUnicodeString(&Name, KeyPath);
    RtlInitUnicodeString(&FileName, NtFile);
    InitializeObjectAttributes(&KeyAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&FileAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtLoadKey2(&KeyAttributes, &FileAttributes, 0);
    ok(Status == STATUS_SUCCESS, "NtLoadKey2 returned 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    CheckLoadedHive(HiveName2, "NtLoadKey2");

    /* no handle is open on a sub key of the hive */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, HiveName2, 0, KEY_READ, &Key);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        Count = 0x55555555;
        Status = NtQueryOpenSubKeys(&KeyAttributes, &Count);
        ok(Status == STATUS_SUCCESS, "NtQueryOpenSubKeys returned 0x%lx\n", Status);
        if (NT_SUCCESS(Status))
            ok(Count == 0, "NtQueryOpenSubKeys counted %lu\n", Count);
        RegCloseKey(Key);
    }

    Status = NtUnloadKey2(&KeyAttributes, 0);
    ok(Status == STATUS_SUCCESS, "NtUnloadKey2 returned 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, HiveName2, 0, KEY_READ, &Key);
        ok(Error == ERROR_FILE_NOT_FOUND, "hive still there after NtUnloadKey2: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
            RegCloseKey(Key);
    }

    /* A name that is not a loaded hive is refused with a status of the kernel, not a missing service */
    Status = NtUnloadKey(&KeyAttributes);
    ok(Status != STATUS_INVALID_SYSTEM_SERVICE && !NT_SUCCESS(Status), "NtUnloadKey of an unloaded hive returned 0x%lx\n", Status);
}

START_TEST(RegHiveFiles)
{
    WCHAR File[MAX_PATH], File2[MAX_PATH];
    HKEY Key, Key2;
    DWORD Marker = 0x12345678, Length, Disposition;
    LONG Error;

    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege"))
    {
        skip("Cannot enable the backup and restore privileges\n");
        return;
    }
    Length = GetTempPathW(MAX_PATH, File);
    if (Length == 0 || Length >= MAX_PATH ||
        FAILED(StringCchCopyW(File2, MAX_PATH, File)) ||
        FAILED(StringCchCatW(File, MAX_PATH, L"hivefiles1.hiv")) ||
        FAILED(StringCchCatW(File2, MAX_PATH, L"hivefiles2.hiv")))
    {
        skip("GetTempPathW failed\n");
        return;
    }
    DeleteHiveFiles(File);
    DeleteHiveFiles(File2);

    RegDeleteKeyW(HKEY_CURRENT_USER, SourcePath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, SourcePath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;
    Error = RegSetValueExW(Key, L"Marker", 0, REG_DWORD, (PBYTE)&Marker, sizeof(Marker));
    ok(Error == ERROR_SUCCESS, "RegSetValueExW failed: %ld\n", Error);

    /* NtSaveKey */
    Error = RegSaveKeyW(Key, File, NULL);
    ok(Error == ERROR_SUCCESS, "RegSaveKeyW failed: %ld\n", Error);
    /* NtSaveKeyEx */
    Error = RegSaveKeyExW(Key, File2, NULL, REG_STANDARD_FORMAT);
    ok(Error == ERROR_SUCCESS, "RegSaveKeyExW failed: %ld\n", Error);
    /* an existing file is refused by the kernel */
    Error = RegSaveKeyW(Key, File, NULL);
    ok(Error == ERROR_ALREADY_EXISTS, "RegSaveKeyW over an existing file returned %ld\n", Error);

    if (GetFileAttributesW(File) != INVALID_FILE_ATTRIBUTES)
    {
        /* NtLoadKey / NtUnloadKey */
        Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, HiveName, File);
        ok(Error == ERROR_SUCCESS, "RegLoadKeyW failed: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            CheckLoadedHive(HiveName, "RegLoadKeyW");
            Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HiveName);
            ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW failed: %ld\n", Error);
        }
        /* NtLoadKey2 / NtQueryOpenSubKeys / NtUnloadKey2 */
        TestNtSideServices(File);
    }

    /* NtRestoreKey and NtReplaceKey are not implemented by the kernel here. What matters is that the call
     * reaches it, whatever the process type: the status must not be the one of a missing service. */
    {
        NTSTATUS Status;
        HANDLE FileHandle = CreateFileW(File2, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

        ok(FileHandle != INVALID_HANDLE_VALUE, "cannot open the saved hive: %lu\n", GetLastError());
        if (FileHandle != INVALID_HANDLE_VALUE)
        {
            Status = NtRestoreKey(Key, FileHandle, REG_FORCE_RESTORE);
            ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "NtRestoreKey is not thunked: 0x%lx\n", Status);
            CloseHandle(FileHandle);
        }
        Status = NtReplaceKey(NULL, Key, NULL);
        ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "NtReplaceKey is not thunked: 0x%lx\n", Status);
    }

    /* NtSaveMergedKeys is only reachable through a layered key pair: the nt call must at least reach the kernel */
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, SourcePath, 0, NULL, 0, KEY_READ, NULL, &Key2, &Disposition);
    if (Error == ERROR_SUCCESS)
    {
        NTSTATUS Status = NtSaveMergedKeys(Key, Key2, NULL);
        ok(Status != STATUS_INVALID_SYSTEM_SERVICE, "NtSaveMergedKeys is not thunked: 0x%lx\n", Status);
        RegCloseKey(Key2);
    }

    RegCloseKey(Key);
    RegDeleteKeyW(HKEY_CURRENT_USER, SourcePath);
    DeleteHiveFiles(File);
    DeleteHiveFiles(File2);
}
