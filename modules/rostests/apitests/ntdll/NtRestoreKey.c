/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NtRestoreKey and NtReplaceKey: statuses, REG_WHOLE_HIVE_VOLATILE, the kinds of key a replace accepts.
 *              The expected results are those measured on Windows Server 2022 on scratch keys and hives.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/cmfuncs.h>

#ifndef REG_DWORD
#define REG_DWORD 4
#endif

#define SCRATCH L"\\Registry\\Machine\\SOFTWARE\\ReactOSNtRestoreKey"

static WCHAR Dir[MAX_PATH];

static NTSTATUS Adjust(ULONG Privilege, BOOLEAN Enable)
{
    BOOLEAN Old;
    return RtlAdjustPrivilege(Privilege, Enable, FALSE, &Old);
}

static HANDLE OpenFileRead(PCWSTR Name, ACCESS_MASK Access)
{
    WCHAR Path[MAX_PATH];
    StringCchPrintfW(Path, _countof(Path), L"%s%s", Dir, Name);
    return CreateFileW(Path, Access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static NTSTATUS OpenKey(PHANDLE Handle, PCWSTR Name, ACCESS_MASK Access)
{
    UNICODE_STRING Path;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&Path, Name);
    InitializeObjectAttributes(&Attributes, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenKey(Handle, Access, &Attributes);
}

static NTSTATUS CreateKeyNt(PHANDLE Handle, PCWSTR Name, PCWSTR Class)
{
    UNICODE_STRING Path, ClassName;
    OBJECT_ATTRIBUTES Attributes;

    RtlInitUnicodeString(&Path, Name);
    RtlInitUnicodeString(&ClassName, Class);
    InitializeObjectAttributes(&Attributes, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateKey(Handle, KEY_ALL_ACCESS, &Attributes, 0, Class ? &ClassName : NULL, 0, NULL);
}

static void SetDword(HANDLE Key, PCWSTR Name, ULONG Value)
{
    UNICODE_STRING ValueName;
    NTSTATUS Status;

    RtlInitUnicodeString(&ValueName, Name);
    Status = NtSetValueKey(Key, &ValueName, 0, REG_DWORD, &Value, sizeof(Value));
    ok(Status == STATUS_SUCCESS, "NtSetValueKey(%S) returned 0x%lx\n", Name, Status);
}

/* The DWORD value of a key, or MAXULONG if it has none */
static ULONG GetDword(PCWSTR KeyPath, PCWSTR Name)
{
    HANDLE Key;
    UNICODE_STRING ValueName;
    UCHAR Buffer[64];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length, Result = MAXULONG;

    if (!NT_SUCCESS(OpenKey(&Key, KeyPath, KEY_READ)))
        return MAXULONG;
    RtlInitUnicodeString(&ValueName, Name);
    if (NT_SUCCESS(NtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
        Info->Type == REG_DWORD)
        Result = *(PULONG)Info->Data;
    NtClose(Key);
    return Result;
}

/* The class of a key, "" if it has none or the key is not there */
static void GetClass(PCWSTR KeyPath, PWSTR Out, ULONG Chars)
{
    HANDLE Key;
    UCHAR Buffer[512];
    PKEY_FULL_INFORMATION Info = (PKEY_FULL_INFORMATION)Buffer;
    ULONG Length;

    Out[0] = 0;
    if (!NT_SUCCESS(OpenKey(&Key, KeyPath, KEY_READ)))
        return;
    if (NT_SUCCESS(NtQueryKey(Key, KeyFullInformation, Info, sizeof(Buffer), &Length)) &&
        Info->ClassLength / sizeof(WCHAR) < Chars)
    {
        RtlCopyMemory(Out, (PUCHAR)Info + Info->ClassOffset, Info->ClassLength);
        Out[Info->ClassLength / sizeof(WCHAR)] = 0;
    }
    NtClose(Key);
}

static BOOLEAN KeyExists(PCWSTR KeyPath)
{
    HANDLE Key;

    if (!NT_SUCCESS(OpenKey(&Key, KeyPath, KEY_READ)))
        return FALSE;
    NtClose(Key);
    return TRUE;
}

static void DeleteKeyNt(PCWSTR KeyPath)
{
    HANDLE Key;

    if (NT_SUCCESS(OpenKey(&Key, KeyPath, DELETE)))
    {
        NtDeleteKey(Key);
        NtClose(Key);
    }
}

/* A hive file whose root is KeyName: value rootval = 1, class "cls", subkey child with value cv = 1 */
static void MakeHive(PCWSTR Name, PCWSTR KeyName)
{
    HANDLE Key, Child, File;
    WCHAR Path[MAX_PATH], KeyPath[128];
    NTSTATUS Status;

    StringCchPrintfW(KeyPath, _countof(KeyPath), SCRATCH L"\\%s", KeyName);
    StringCchPrintfW(Path, _countof(Path), L"%s", KeyPath);
    StringCchCatW(Path, _countof(Path), L"\\child");
    DeleteKeyNt(Path);
    DeleteKeyNt(KeyPath);
    Status = CreateKeyNt(&Key, KeyPath, L"cls");
    ok(Status == STATUS_SUCCESS, "NtCreateKey returned 0x%lx\n", Status);
    if (!NT_SUCCESS(Status))
        return;
    SetDword(Key, L"rootval", 1);
    Status = CreateKeyNt(&Child, Path, NULL);
    ok(Status == STATUS_SUCCESS, "NtCreateKey returned 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        SetDword(Child, L"cv", 1);
        NtClose(Child);
    }
    StringCchPrintfW(Path, _countof(Path), L"%s%s", Dir, Name);
    DeleteFileW(Path);
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "cannot create the hive file: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        Status = NtSaveKey(Key, File);
        ok(Status == STATUS_SUCCESS, "NtSaveKey returned 0x%lx\n", Status);
        CloseHandle(File);
    }
    NtClose(Key);
}

START_TEST(NtRestoreKey)
{
    NTSTATUS Status;
    HANDLE Key, File, Machine, User, Event, Sub, Hive;
    ULONG Length;
    WCHAR Path[MAX_PATH], Class[16];

    Length = GetTempPathW(MAX_PATH, Dir);
    if (!Length || Length >= MAX_PATH - 32)
    {
        skip("GetTempPathW failed\n");
        return;
    }
    if (!NT_SUCCESS(Adjust(SE_RESTORE_PRIVILEGE, TRUE)) || !NT_SUCCESS(Adjust(SE_BACKUP_PRIVILEGE, TRUE)))
    {
        skip("Cannot enable the backup and restore privileges\n");
        return;
    }
    Status = CreateKeyNt(&Key, SCRATCH, NULL);
    if (!NT_SUCCESS(Status))
    {
        skip("Cannot create the scratch key: 0x%lx\n", Status);
        return;
    }
    NtClose(Key);
    MakeHive(L"ntrk_a.hiv", L"VolA");
    MakeHive(L"ntrk_b.hiv", L"VolB");
    MakeHive(L"ntrk_c.hiv", L"VolC");
    MakeHive(L"ntrk_d.hiv", L"Plain");

    /* The target: another key, with its own value and child */
    DeleteKeyNt(SCRATCH L"\\Dst\\old");
    DeleteKeyNt(SCRATCH L"\\Dst");
    Status = CreateKeyNt(&Key, SCRATCH L"\\Dst", L"dstclass");
    ok(Status == STATUS_SUCCESS, "NtCreateKey returned 0x%lx\n", Status);
    SetDword(Key, L"dstval", 2);
    Status = CreateKeyNt(&Sub, SCRATCH L"\\Dst\\old", NULL);
    ok(Status == STATUS_SUCCESS, "NtCreateKey returned 0x%lx\n", Status);
    NtClose(Sub);
    File = OpenFileRead(L"ntrk_d.hiv", GENERIC_READ);
    ok(File != INVALID_HANDLE_VALUE, "cannot open the hive file: %lu\n", GetLastError());
    if (!NT_SUCCESS(Status) || File == INVALID_HANDLE_VALUE)
    {
        skip("setup failed\n");
        return;
    }

    /* The order of the checks: privilege, flags, file handle, key handle */
    Adjust(SE_RESTORE_PRIVILEGE, FALSE);
    Status = NtRestoreKey(Key, File, 0);
    ok(Status == STATUS_PRIVILEGE_NOT_HELD, "without SeRestorePrivilege: 0x%lx\n", Status);
    Adjust(SE_RESTORE_PRIVILEGE, TRUE);
    Adjust(SE_BACKUP_PRIVILEGE, FALSE);
    Status = NtRestoreKey(Key, File, REG_REFRESH_HIVE);
    ok(Status == STATUS_INVALID_PARAMETER, "REG_REFRESH_HIVE: 0x%lx\n", Status);
    Status = NtRestoreKey(Key, File, 0xFFFFFFFF);
    ok(Status == STATUS_INVALID_PARAMETER, "all flags: 0x%lx\n", Status);
    Status = NtRestoreKey(Key, NULL, 0);
    ok(Status == STATUS_INVALID_HANDLE, "NULL file: 0x%lx\n", Status);
    Status = NtRestoreKey(Key, (HANDLE)(ULONG_PTR)0x12345, 0);
    ok(Status == STATUS_INVALID_HANDLE, "bogus file: 0x%lx\n", Status);
    Status = NtRestoreKey(NULL, File, 0);
    ok(Status == STATUS_INVALID_HANDLE, "NULL key: 0x%lx\n", Status);
    Status = NtRestoreKey((HANDLE)(ULONG_PTR)0x12345, File, 0);
    ok(Status == STATUS_INVALID_HANDLE, "bogus key: 0x%lx\n", Status);
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    Status = NtRestoreKey(Event, File, 0);
    ok(Status == STATUS_OBJECT_TYPE_MISMATCH, "event as key: 0x%lx\n", Status);
    Status = NtRestoreKey(Key, Event, 0);
    ok(Status == STATUS_OBJECT_TYPE_MISMATCH, "event as file: 0x%lx\n", Status);
    CloseHandle(Event);
    {
        HANDLE WriteOnly = OpenFileRead(L"ntrk_d.hiv", GENERIC_WRITE);

        ok(WriteOnly != INVALID_HANDLE_VALUE, "cannot open for writing: %lu\n", GetLastError());
        Status = NtRestoreKey(Key, WriteOnly, 0);
        ok(Status == STATUS_ACCESS_DENIED, "write-only file handle: 0x%lx\n", Status);
        CloseHandle(WriteOnly);
    }
    Status = NtRestoreKey(Key, File, REG_WHOLE_HIVE_VOLATILE);
    ok(Status == STATUS_INVALID_PARAMETER, "volatile onto an ordinary key: 0x%lx\n", Status);
    ok(GetDword(SCRATCH L"\\Dst", L"dstval") == 2, "the key was changed by a refused restore\n");

    /* Restore: values, class and subkeys are the saved ones; then a handle below the key */
    Adjust(SE_BACKUP_PRIVILEGE, TRUE);
    Status = NtRestoreKey(Key, File, 0);
    ok(Status == STATUS_SUCCESS, "restore: 0x%lx\n", Status);
    ok(GetDword(SCRATCH L"\\Dst", L"rootval") == 1, "rootval after the restore\n");
    ok(GetDword(SCRATCH L"\\Dst", L"dstval") == MAXULONG, "dstval is still there after the restore\n");
    ok(GetDword(SCRATCH L"\\Dst\\child", L"cv") == 1, "child after the restore\n");
    ok(!KeyExists(SCRATCH L"\\Dst\\old"), "old child is still there after the restore\n");
    GetClass(SCRATCH L"\\Dst", Class, _countof(Class));
    ok(!wcscmp(Class, L"cls"), "class after the restore is \"%S\"\n", Class);
    Status = OpenKey(&Sub, SCRATCH L"\\Dst\\child", KEY_READ);
    ok(Status == STATUS_SUCCESS, "NtOpenKey returned 0x%lx\n", Status);
    Status = NtRestoreKey(Key, File, 0);
    ok(Status == STATUS_CANNOT_DELETE, "open subkey, no force: 0x%lx\n", Status);
    Status = NtRestoreKey(Key, File, REG_FORCE_RESTORE);
    ok(Status == STATUS_SUCCESS, "open subkey, force: 0x%lx\n", Status);
    {
        UNICODE_STRING ValueName;
        UCHAR Buffer[64];
        ULONG Result;

        RtlInitUnicodeString(&ValueName, L"cv");
        Status = NtQueryValueKey(Sub, &ValueName, KeyValuePartialInformation, Buffer, sizeof(Buffer), &Result);
        /* STATUS_HIVE_UNLOADED on Windows, STATUS_KEY_DELETED here (both are ERROR_KEY_DELETED in Win32) */
        ok(Status == STATUS_KEY_DELETED || Status == STATUS_HIVE_UNLOADED, "the open handle after a forced restore: 0x%lx\n", Status);
    }
    NtClose(Sub);
    CloseHandle(File);

    /* A volatile hive below \Registry\Machine and \Registry\User, named as the saved root */
    Status = OpenKey(&Machine, L"\\Registry\\Machine", KEY_READ);
    ok(Status == STATUS_SUCCESS, "NtOpenKey returned 0x%lx\n", Status);
    Status = OpenKey(&User, L"\\Registry\\User", KEY_READ);
    ok(Status == STATUS_SUCCESS, "NtOpenKey returned 0x%lx\n", Status);

    File = OpenFileRead(L"ntrk_a.hiv", GENERIC_READ);
    Status = NtRestoreKey(Machine, File, 0);
    ok(Status == STATUS_ACCESS_DENIED, "non-volatile restore onto \\Registry\\Machine: 0x%lx\n", Status);
    Status = NtRestoreKey(Machine, File, REG_FORCE_RESTORE);
    ok(Status == STATUS_ACCESS_DENIED, "forced restore onto \\Registry\\Machine: 0x%lx\n", Status);
    Status = NtRestoreKey(Machine, File, REG_WHOLE_HIVE_VOLATILE);
    ok(Status == STATUS_SUCCESS, "volatile restore onto \\Registry\\Machine: 0x%lx\n", Status);
    ok(KeyExists(L"\\Registry\\Machine\\VolA"), "the volatile hive is not there\n");
    /* its subkeys and class are the saved ones, its root has no values */
    ok(GetDword(L"\\Registry\\Machine\\VolA", L"rootval") == MAXULONG, "a root value of the volatile hive is there\n");
    ok(GetDword(L"\\Registry\\Machine\\VolA\\child", L"cv") == 1, "the child of the volatile hive\n");
    GetClass(L"\\Registry\\Machine\\VolA", Class, _countof(Class));
    ok(!wcscmp(Class, L"cls"), "class of the volatile hive is \"%S\"\n", Class);
    /* the name is taken now */
    Status = NtRestoreKey(Machine, File, REG_WHOLE_HIVE_VOLATILE);
    ok(Status == STATUS_ACCESS_DENIED, "volatile restore of a name that is there: 0x%lx\n", Status);
    CloseHandle(File);
    /* a key opened for reading only is enough, and so is \Registry\User */
    File = OpenFileRead(L"ntrk_b.hiv", GENERIC_READ);
    Status = NtRestoreKey(User, File, REG_WHOLE_HIVE_VOLATILE);
    ok(Status == STATUS_SUCCESS, "volatile restore onto \\Registry\\User: 0x%lx\n", Status);
    ok(KeyExists(L"\\Registry\\User\\VolB"), "the volatile hive below \\Registry\\User is not there\n");
    CloseHandle(File);
    NtClose(Machine);
    NtClose(User);
    /* best effort: Windows does not unload these */
    {
        UNICODE_STRING Name;
        OBJECT_ATTRIBUTES Attributes;

        RtlInitUnicodeString(&Name, L"\\Registry\\Machine\\VolA");
        InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        NtUnloadKey(&Attributes);
        RtlInitUnicodeString(&Name, L"\\Registry\\User\\VolB");
        NtUnloadKey(&Attributes);
    }

    /* NtReplaceKey: the key must belong to a hive that has a file */
    {
        UNICODE_STRING NewName, OldName;
        OBJECT_ATTRIBUTES NewAttributes, OldAttributes;
        PCWSTR Keys[] = { L"\\Registry\\Machine", L"\\Registry\\User", L"\\Registry\\Machine\\HARDWARE",
                          L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION" };
        ULONG i;
        WCHAR NtNew[MAX_PATH], NtOld[MAX_PATH];

        StringCchPrintfW(NtNew, _countof(NtNew), L"\\??\\%sntrk_c.hiv", Dir);
        StringCchPrintfW(NtOld, _countof(NtOld), L"\\??\\%sntrk_c.old", Dir);
        RtlInitUnicodeString(&NewName, NtNew);
        RtlInitUnicodeString(&OldName, NtOld);
        InitializeObjectAttributes(&NewAttributes, &NewName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        InitializeObjectAttributes(&OldAttributes, &OldName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        for (i = 0; i < _countof(Keys); i++)
        {
            Status = OpenKey(&Hive, Keys[i], KEY_ALL_ACCESS);
            ok(Status == STATUS_SUCCESS, "NtOpenKey(%S) returned 0x%lx\n", Keys[i], Status);
            if (!NT_SUCCESS(Status))
                continue;
            Status = NtReplaceKey(&NewAttributes, Hive, &OldAttributes);
            ok(Status == STATUS_INVALID_HANDLE, "NtReplaceKey on %S: 0x%lx\n", Keys[i], Status);
            NtClose(Hive);
        }
        StringCchPrintfW(Path, _countof(Path), L"%sntrk_c.old", Dir);
        ok(GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES, "a backup file exists after the refused replaces\n");

        Adjust(SE_RESTORE_PRIVILEGE, FALSE);
        Status = OpenKey(&Hive, SCRATCH, KEY_READ);
        Status = NtReplaceKey(&NewAttributes, Hive, &OldAttributes);
        ok(Status == STATUS_PRIVILEGE_NOT_HELD, "NtReplaceKey without SeRestorePrivilege: 0x%lx\n", Status);
        NtClose(Hive);
        Adjust(SE_RESTORE_PRIVILEGE, TRUE);
    }

    NtClose(Key);
    DeleteKeyNt(SCRATCH L"\\Dst\\child");
    DeleteKeyNt(SCRATCH L"\\Dst");
    DeleteKeyNt(SCRATCH L"\\VolA\\child");
    DeleteKeyNt(SCRATCH L"\\VolA");
    DeleteKeyNt(SCRATCH L"\\VolB\\child");
    DeleteKeyNt(SCRATCH L"\\VolB");
    DeleteKeyNt(SCRATCH L"\\VolC\\child");
    DeleteKeyNt(SCRATCH L"\\VolC");
    DeleteKeyNt(SCRATCH L"\\Plain\\child");
    DeleteKeyNt(SCRATCH L"\\Plain");
    DeleteKeyNt(SCRATCH);
}
