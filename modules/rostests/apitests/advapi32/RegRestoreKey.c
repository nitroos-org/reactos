/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RegRestoreKey and RegReplaceKey. The expected results are those measured on Windows Server 2022
 *              on scratch keys and scratch hives.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <sddl.h>

static PCWSTR Scratch = L"SOFTWARE\\ReactOSRestoreKeyTest";
static WCHAR Dir[MAX_PATH];


/* RegDeleteTreeW needs a newer header version than these tests are compiled with */
static LONG DeleteTree(HKEY Root, PCWSTR Path)
{
    HKEY Key;
    WCHAR Name[256];
    LONG Error = RegOpenKeyExW(Root, Path, 0, KEY_ALL_ACCESS, &Key);

    if (Error != ERROR_SUCCESS)
        return Error;
    while (RegEnumKeyW(Key, 0, Name, _countof(Name)) == ERROR_SUCCESS)
    {
        if (DeleteTree(Key, Name) != ERROR_SUCCESS)
            break;
    }
    RegCloseKey(Key);
    return RegDeleteKeyW(Root, Path);
}

static BOOL SetPrivilege(PCWSTR Name, BOOL Enable)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Success;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;
    Success = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid) &&
              AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Success;
}

static void File(PWSTR Out, PCWSTR Name)
{
    StringCchPrintfW(Out, MAX_PATH, L"%s%s", Dir, Name);
}

static void RemoveHiveFiles(PCWSTR Name)
{
    static PCWSTR Suffixes[] = { L"", L".LOG", L".LOG1", L".LOG2" };
    WCHAR Path[MAX_PATH + 8];
    ULONG i;

    for (i = 0; i < _countof(Suffixes); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%s%s%s", Dir, Name, Suffixes[i]);
        SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(Path);
    }
}

static void WriteFileBytes(PCWSTR Name, ULONG Length)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle;
    PBYTE Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length ? Length : 1);
    DWORD Written;

    File(Path, Name);
    Handle = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (Handle != INVALID_HANDLE_VALUE)
    {
        memset(Data, 'A', Length);
        if (Length)
            WriteFile(Handle, Data, Length, &Written, NULL);
        CloseHandle(Handle);
    }
    HeapFree(GetProcessHeap(), 0, Data);
}

static HKEY CreateKey(HKEY Parent, PCWSTR Path)
{
    HKEY Key = NULL;
    LONG Error = RegCreateKeyExW(Parent, Path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);

    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW(%S) failed: %ld\n", Path, Error);
    return Key;
}

static void SetDword(HKEY Key, PCWSTR Name, DWORD Value)
{
    LONG Error = RegSetValueExW(Key, Name, 0, REG_DWORD, (PBYTE)&Value, sizeof(Value));
    ok(Error == ERROR_SUCCESS, "RegSetValueExW(%S) failed: %ld\n", Name, Error);
}

static BOOL HasValue(HKEY Key, PCWSTR Name, DWORD Expected)
{
    DWORD Type, Value = 0, Size = sizeof(Value);
    LONG Error = RegQueryValueExW(Key, Name, NULL, &Type, (PBYTE)&Value, &Size);

    return Error == ERROR_SUCCESS && Type == REG_DWORD && Value == Expected;
}

static BOOL NoValue(HKEY Key, PCWSTR Name)
{
    return RegQueryValueExW(Key, Name, NULL, NULL, NULL, NULL) == ERROR_FILE_NOT_FOUND;
}

static BOOL HasSubKey(HKEY Key, PCWSTR Name)
{
    HKEY Sub;
    LONG Error = RegOpenKeyExW(Key, Name, 0, KEY_READ, &Sub);

    if (Error == ERROR_SUCCESS)
        RegCloseKey(Sub);
    return Error == ERROR_SUCCESS;
}

static BOOL GetDacl(HKEY Key, PWSTR Out, ULONG Chars)
{
    BYTE Descriptor[1024];
    DWORD Length = sizeof(Descriptor);
    PWSTR Text = NULL;

    if (RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)Descriptor, &Length) != ERROR_SUCCESS)
        return FALSE;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW((PSECURITY_DESCRIPTOR)Descriptor,
                                                              SDDL_REVISION_1,
                                                              DACL_SECURITY_INFORMATION,
                                                              &Text,
                                                              NULL))
        return FALSE;
    StringCchCopyW(Out, Chars, Text);
    LocalFree(Text);
    return TRUE;
}

/* The saved hive: root values Src1 and Shared, class SrcClass, descriptor SrcSd, subkeys Sub\Deep and SharedSub */
static void MakeSource(PCWSTR FileName, DWORD Flags)
{
    HKEY Parent, Key, Sub;
    PSECURITY_DESCRIPTOR Sd;
    WCHAR Path[MAX_PATH];
    LONG Error;

    DeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Src");
    Parent = CreateKey(HKEY_LOCAL_MACHINE, Scratch);
    Error = RegCreateKeyExW(Parent, L"Src", 0, (PWSTR)L"SrcClass", 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    SetDword(Key, L"Src1", 11);
    SetDword(Key, L"Shared", 1);
    Sub = CreateKey(Key, L"Sub\\Deep");
    SetDword(Sub, L"d", 5);
    RegCloseKey(Sub);
    Sub = CreateKey(Key, L"SharedSub");
    SetDword(Sub, L"which", 1);
    RegCloseKey(Sub);
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;WD)",
                                                             SDDL_REVISION_1,
                                                             &Sd,
                                                             NULL))
    {
        Error = RegSetKeySecurity(Key, DACL_SECURITY_INFORMATION, Sd);
        ok(Error == ERROR_SUCCESS, "RegSetKeySecurity failed: %ld\n", Error);
        LocalFree(Sd);
    }
    File(Path, FileName);
    RemoveHiveFiles(FileName);
    Error = RegSaveKeyExW(Key, Path, NULL, Flags);
    ok(Error == ERROR_SUCCESS, "RegSaveKeyExW(%S) failed: %ld\n", FileName, Error);
    RegCloseKey(Key);
    RegCloseKey(Parent);
}

/* The target: root values Dst1 and Shared, class DstClass, subkeys DstSub\X and SharedSub */
static HKEY MakeTarget(void)
{
    HKEY Parent, Key, Sub;
    LONG Error;

    DeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Dst");
    Parent = CreateKey(HKEY_LOCAL_MACHINE, Scratch);
    Error = RegCreateKeyExW(Parent, L"Dst", 0, (PWSTR)L"DstClass", 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    SetDword(Key, L"Dst1", 22);
    SetDword(Key, L"Shared", 2);
    Sub = CreateKey(Key, L"DstSub\\X");
    SetDword(Sub, L"x", 9);
    RegCloseKey(Sub);
    Sub = CreateKey(Key, L"SharedSub");
    SetDword(Sub, L"which", 2);
    SetDword(Sub, L"dstonly", 3);
    RegCloseKey(Sub);
    RegCloseKey(Parent);
    return Key;
}

static void CheckRestored(HKEY Key, PCSTR What)
{
    WCHAR Class[64], Dacl[256];
    DWORD ClassLength = _countof(Class);

    ok(HasValue(Key, L"Src1", 11), "%s: Src1 is not there\n", What);
    ok(HasValue(Key, L"Shared", 1), "%s: Shared is not 1\n", What);
    ok(NoValue(Key, L"Dst1"), "%s: Dst1 is still there\n", What);
    ok(HasSubKey(Key, L"Sub\\Deep"), "%s: Sub\\Deep is not there\n", What);
    ok(HasSubKey(Key, L"SharedSub"), "%s: SharedSub is not there\n", What);
    ok(!HasSubKey(Key, L"DstSub"), "%s: DstSub is still there\n", What);
    if (HasSubKey(Key, L"SharedSub"))
    {
        HKEY Sub;
        RegOpenKeyExW(Key, L"SharedSub", 0, KEY_READ, &Sub);
        ok(HasValue(Sub, L"which", 1), "%s: SharedSub\\which is not the saved one\n", What);
        ok(NoValue(Sub, L"dstonly"), "%s: SharedSub\\dstonly is still there\n", What);
        RegCloseKey(Sub);
    }
    ok(RegQueryInfoKeyW(Key, Class, &ClassLength, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS &&
       !wcscmp(Class, L"SrcClass"), "%s: class is %S\n", What, Class);
    ok(GetDacl(Key, Dacl, _countof(Dacl)) && !wcscmp(Dacl, L"D:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;WD)"),
       "%s: DACL is %S\n", What, Dacl);
}

static void TestRestore(void)
{
    WCHAR Src[MAX_PATH], SrcLatest[MAX_PATH], Empty[MAX_PATH], Junk[MAX_PATH], Short[MAX_PATH];
    HKEY Target, Sub, Other, Old;
    LONG Error;
    DWORD Value, Size, Type;

    MakeSource(L"rrk_src.hiv", REG_STANDARD_FORMAT);
    MakeSource(L"rrk_latest.hiv", REG_LATEST_FORMAT);
    File(Src, L"rrk_src.hiv");
    File(SrcLatest, L"rrk_latest.hiv");

    /* SeRestorePrivilege is needed, SeBackupPrivilege is not */
    Target = MakeTarget();
    SetPrivilege(L"SeRestorePrivilege", FALSE);
    SetPrivilege(L"SeBackupPrivilege", TRUE);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_PRIVILEGE_NOT_HELD, "restore without SeRestorePrivilege returned %ld\n", Error);
    ok(HasValue(Target, L"Dst1", 22), "the key was changed by a refused restore\n");
    SetPrivilege(L"SeRestorePrivilege", TRUE);
    SetPrivilege(L"SeBackupPrivilege", FALSE);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_SUCCESS, "restore with only SeRestorePrivilege returned %ld\n", Error);
    CheckRestored(Target, "restore");
    SetPrivilege(L"SeBackupPrivilege", TRUE);
    RegCloseKey(Target);

    /* A hive saved with REG_LATEST_FORMAT, and REG_NO_LAZY_FLUSH and unknown high flags are accepted */
    Target = MakeTarget();
    Error = RegRestoreKeyW(Target, SrcLatest, REG_NO_LAZY_FLUSH);
    ok(Error == ERROR_SUCCESS, "restore of a REG_LATEST_FORMAT hive returned %ld\n", Error);
    CheckRestored(Target, "latest format");
    RegCloseKey(Target);
    Target = MakeTarget();
    Error = RegRestoreKeyW(Target, Src, 0x100);
    ok(Error == ERROR_SUCCESS, "restore with flag 0x100 returned %ld\n", Error);
    RegCloseKey(Target);

    /* REG_REFRESH_HIVE is no restore flag; REG_WHOLE_HIVE_VOLATILE needs \Registry\Machine or \Registry\User */
    Target = MakeTarget();
    Error = RegRestoreKeyW(Target, Src, 2);
    ok(Error == ERROR_INVALID_PARAMETER, "restore with flag 2 returned %ld\n", Error);
    Error = RegRestoreKeyW(Target, Src, REG_WHOLE_HIVE_VOLATILE);
    ok(Error == ERROR_INVALID_PARAMETER, "volatile restore onto an ordinary key returned %ld\n", Error);
    ok(HasValue(Target, L"Dst1", 22), "the key was changed by a refused restore\n");

    /* Files that are no hive */
    WriteFileBytes(L"rrk_empty.hiv", 0);
    WriteFileBytes(L"rrk_junk.hiv", 5000);
    File(Empty, L"rrk_empty.hiv");
    File(Junk, L"rrk_junk.hiv");
    Error = RegRestoreKeyW(Target, Empty, 0);
    ok(Error == ERROR_REGISTRY_IO_FAILED, "restore of an empty file returned %ld\n", Error);
    Error = RegRestoreKeyW(Target, Junk, 0);
    ok(Error == ERROR_NOT_REGISTRY_FILE, "restore of a file of junk returned %ld\n", Error);
    {
        HANDLE In = CreateFileW(Src, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        BYTE Buffer[4096];
        DWORD Got = 0;
        HANDLE Out;

        File(Short, L"rrk_short.hiv");
        if (In != INVALID_HANDLE_VALUE &&
            ReadFile(In, Buffer, sizeof(Buffer), &Got, NULL) && Got == sizeof(Buffer))
        {
            Out = CreateFileW(Short, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            WriteFile(Out, Buffer, Got, &Size, NULL);
            CloseHandle(Out);
            Error = RegRestoreKeyW(Target, Short, 0);
            ok(Error == ERROR_BADDB, "restore of a truncated hive returned %ld\n", Error);
        }
        if (In != INVALID_HANDLE_VALUE)
            CloseHandle(In);
    }
    ok(HasValue(Target, L"Dst1", 22), "the key was changed by a refused restore\n");
    RegCloseKey(Target);

    /* A handle open below the key: refused without REG_FORCE_RESTORE, the key stays as it was */
    Target = MakeTarget();
    Error = RegOpenKeyExW(Target, L"SharedSub", 0, KEY_ALL_ACCESS, &Sub);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_ACCESS_DENIED, "restore with an open subkey returned %ld\n", Error);
    ok(HasValue(Target, L"Dst1", 22), "the key was changed by a refused restore\n");
    Error = RegRestoreKeyW(Target, Src, REG_FORCE_RESTORE);
    ok(Error == ERROR_SUCCESS, "forced restore with an open subkey returned %ld\n", Error);
    CheckRestored(Target, "forced restore");
    Size = sizeof(Value);
    Error = RegQueryValueExW(Sub, L"which", NULL, &Type, (PBYTE)&Value, &Size);
    ok(Error == ERROR_KEY_DELETED, "the open handle is not dead after a forced restore: %ld\n", Error);
    RegCloseKey(Sub);
    RegCloseKey(Target);

    /* A second handle to the key itself counts as well */
    Target = MakeTarget();
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Dst", 0, KEY_READ, &Other);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_ACCESS_DENIED, "restore with a second handle to the key returned %ld\n", Error);
    RegCloseKey(Other);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_SUCCESS, "restore after the second handle was closed returned %ld\n", Error);
    RegCloseKey(Target);

    /* The handle needs no access right: the privilege decides */
    Target = MakeTarget();
    RegCloseKey(Target);
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Dst", 0, KEY_READ, &Target);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_SUCCESS, "restore through a KEY_READ handle returned %ld\n", Error);
    RegCloseKey(Target);

    /* A deleted key cannot be restored, not even forced */
    Target = MakeTarget();
    Error = DeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Dst");
    ok(Error == ERROR_SUCCESS, "RegDeleteTreeW failed: %ld\n", Error);
    Error = RegRestoreKeyW(Target, Src, 0);
    ok(Error == ERROR_ACCESS_DENIED, "restore onto a deleted key returned %ld\n", Error);
    Error = RegRestoreKeyW(Target, Src, REG_FORCE_RESTORE);
    ok(Error == ERROR_ACCESS_DENIED, "forced restore onto a deleted key returned %ld\n", Error);
    RegCloseKey(Target);

    /* The root of a loaded hive needs REG_FORCE_RESTORE; a key inside a loaded hive is stored in its file */
    {
        WCHAR Loaded[MAX_PATH];
        HKEY Root;

        File(Loaded, L"rrk_loaded.hiv");
        RemoveHiveFiles(L"rrk_loaded.hiv");
        CopyFileW(SrcLatest, Loaded, FALSE);
        SetFileAttributesW(Loaded, FILE_ATTRIBUTE_NORMAL);
        Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSRestoreKeyLoaded", Loaded);
        ok(Error == ERROR_SUCCESS, "RegLoadKeyW failed: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"ReactOSRestoreKeyLoaded", 0, KEY_ALL_ACCESS, &Root);
            SetDword(Root, L"LoadedOnly", 1);
            Error = RegRestoreKeyW(Root, Src, 0);
            ok(Error == ERROR_ACCESS_DENIED, "restore onto a hive root returned %ld\n", Error);
            ok(HasValue(Root, L"LoadedOnly", 1), "the hive root was changed by a refused restore\n");
            Error = RegRestoreKeyW(Root, Src, REG_FORCE_RESTORE);
            ok(Error == ERROR_SUCCESS, "forced restore onto a hive root returned %ld\n", Error);
            ok(NoValue(Root, L"LoadedOnly") && HasValue(Root, L"Src1", 11), "the hive root was not restored\n");
            Old = CreateKey(Root, L"Inner");
            Error = RegRestoreKeyW(Old, Src, 0);
            ok(Error == ERROR_SUCCESS, "restore onto a key of a loaded hive returned %ld\n", Error);
            RegCloseKey(Old);
            RegCloseKey(Root);
            Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSRestoreKeyLoaded");
            ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW failed: %ld\n", Error);
            /* what a restore did is in the file */
            Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSRestoreKeyLoaded", Loaded);
            ok(Error == ERROR_SUCCESS, "reload failed: %ld\n", Error);
            if (Error == ERROR_SUCCESS)
            {
                RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"ReactOSRestoreKeyLoaded\\Inner", 0, KEY_READ, &Old);
                ok(HasValue(Old, L"Src1", 11), "the restore onto a key of a hive is not in its file\n");
                RegCloseKey(Old);
                RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSRestoreKeyLoaded");
            }
        }
    }
}


/* A saved key with many subkeys and a value too big for one bin; the target has other subkeys of its own */
static void TestBigRestore(void)
{
    WCHAR File2[MAX_PATH], Name[32];
    HKEY Parent, Src, Dst, Sub;
    PBYTE Data, Check;
    DWORD Size = 100000, Type, SubKeys = 0, Values = 0, Got;
    LONG Error;
    ULONG i;

    Data = HeapAlloc(GetProcessHeap(), 0, Size);
    Check = HeapAlloc(GetProcessHeap(), 0, Size);
    for (i = 0; i < Size; i++)
        Data[i] = (BYTE)(i * 7 + 3);

    DeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Big");
    Parent = CreateKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Big");
    Error = RegCreateKeyExW(Parent, L"Src", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Src, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    for (i = 0; i < 150; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"k%03lu", i);
        Sub = CreateKey(Src, Name);
        SetDword(Sub, L"v", i);
        RegCloseKey(Sub);
        if (i % 10 == 0)
        {
            StringCchPrintfW(Name, _countof(Name), L"k%03lu\\sub", i);
            Sub = CreateKey(Src, Name);
            SetDword(Sub, L"w", i);
            RegCloseKey(Sub);
        }
    }
    for (i = 0; i < 40; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"val%02lu", i);
        SetDword(Src, Name, i * 3);
    }
    Error = RegSetValueExW(Src, L"Big", 0, REG_BINARY, Data, Size);
    ok(Error == ERROR_SUCCESS, "RegSetValueExW failed: %ld\n", Error);
    File(File2, L"rrk_big.hiv");
    RemoveHiveFiles(L"rrk_big.hiv");
    Error = RegSaveKeyW(Src, File2, NULL);
    ok(Error == ERROR_SUCCESS, "RegSaveKeyW failed: %ld\n", Error);
    RegCloseKey(Src);

    Error = RegCreateKeyExW(Parent, L"Dst", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Dst, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    for (i = 0; i < 80; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"other%03lu\\x", i);
        Sub = CreateKey(Dst, Name);
        SetDword(Sub, L"o", i);
        RegCloseKey(Sub);
    }
    for (i = 0; i < 20; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"old%02lu", i);
        SetDword(Dst, Name, i);
    }

    for (i = 0; i < 2; i++)
    {
        Error = RegRestoreKeyW(Dst, File2, 0);
        ok(Error == ERROR_SUCCESS, "restore of the big hive (round %lu) returned %ld\n", i, Error);
        Error = RegQueryInfoKeyW(Dst, NULL, NULL, NULL, &SubKeys, NULL, NULL, &Values, NULL, NULL, NULL, NULL);
        ok(Error == ERROR_SUCCESS, "RegQueryInfoKeyW failed: %ld\n", Error);
        ok(SubKeys == 150, "subkeys after the restore: %lu\n", SubKeys);
        ok(Values == 41, "values after the restore: %lu\n", Values);
        Got = Size;
        memset(Check, 0, Size);
        Error = RegQueryValueExW(Dst, L"Big", NULL, &Type, Check, &Got);
        ok(Error == ERROR_SUCCESS && Type == REG_BINARY && Got == Size && !memcmp(Check, Data, Size),
           "the big value after the restore: error %ld, type %lu, size %lu\n", Error, Type, Got);
        ok(HasValue(Dst, L"val39", 117), "val39\n");
        ok(NoValue(Dst, L"old00"), "old00 is still there\n");
        ok(!HasSubKey(Dst, L"other000"), "other000 is still there\n");
        ok(HasSubKey(Dst, L"k149"), "k149 is not there\n");
        ok(HasSubKey(Dst, L"k140\\sub"), "k140\\sub is not there\n");
    }
    RegCloseKey(Dst);
    RegCloseKey(Parent);
    DeleteTree(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOSRestoreKeyTest\\Big");
    RemoveHiveFiles(L"rrk_big.hiv");
    HeapFree(GetProcessHeap(), 0, Data);
    HeapFree(GetProcessHeap(), 0, Check);
}

static void TestReplace(void)
{
    WCHAR Src[MAX_PATH], Hive[MAX_PATH], New1[MAX_PATH], Old1[MAX_PATH], Missing[MAX_PATH], Junk[MAX_PATH], Dir2[MAX_PATH];
    HKEY Root, Sub;
    LONG Error;
    int Round;
    WCHAR NameHive[32], NameNew[32], NameOld[32];

    MakeSource(L"rrp_src.hiv", REG_STANDARD_FORMAT);
    File(Src, L"rrp_src.hiv");
    File(Missing, L"rrp_nosuchfile.hiv");
    File(Junk, L"rrp_junk.hiv");
    WriteFileBytes(L"rrp_junk.hiv", 5000);

    for (Round = 0; Round < 2; Round++)
    {
        /* Round 0 names the root of the loaded hive, round 1 a key inside it: the file of the hive is replaced */
        /* Windows keeps the file at the path of the replaced hive locked until the system restarts: every round
         * has its own files */
        StringCchPrintfW(NameHive, _countof(NameHive), L"rrp_hive%d.hiv", Round);
        StringCchPrintfW(NameNew, _countof(NameNew), L"rrp_new%d.hiv", Round);
        StringCchPrintfW(NameOld, _countof(NameOld), L"rrp_old%d.hiv", Round);
        RemoveHiveFiles(NameHive);
        RemoveHiveFiles(NameNew);
        RemoveHiveFiles(NameOld);
        File(Hive, NameHive);
        File(New1, NameNew);
        File(Old1, NameOld);
        CopyFileW(Src, Hive, FALSE);
        CopyFileW(Src, New1, FALSE);
        SetFileAttributesW(Hive, FILE_ATTRIBUTE_NORMAL);
        SetFileAttributesW(New1, FILE_ATTRIBUTE_NORMAL);

        Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", Hive);
        ok(Error == ERROR_SUCCESS, "RegLoadKeyW failed: %ld\n", Error);
        if (Error != ERROR_SUCCESS)
            return;
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", 0, KEY_ALL_ACCESS, &Root);
        SetDword(Root, L"LiveOnly", 1);
        RegFlushKey(Root);

        /* The privilege */
        SetPrivilege(L"SeRestorePrivilege", FALSE);
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", New1, Old1);
        ok(Error == ERROR_PRIVILEGE_NOT_HELD, "RegReplaceKey without SeRestorePrivilege returned %ld\n", Error);
        SetPrivilege(L"SeRestorePrivilege", TRUE);
        ok(GetFileAttributesW(New1) != INVALID_FILE_ATTRIBUTES && GetFileAttributesW(Old1) == INVALID_FILE_ATTRIBUTES,
           "files touched by a refused replace\n");

        /* Refused: nothing is renamed */
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", Missing, Old1);
        ok(Error == ERROR_FILE_NOT_FOUND, "new file missing: %ld\n", Error);
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", Junk, Old1);
        ok(Error == ERROR_NOT_REGISTRY_FILE, "new file is junk: %ld\n", Error);
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", New1, Src);
        ok(Error == ERROR_ALREADY_EXISTS, "backup name taken: %ld\n", Error);
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", New1, New1);
        ok(Error == ERROR_ALREADY_EXISTS, "backup name is the new file: %ld\n", Error);
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", Hive, Old1);
        ok(Error == ERROR_SHARING_VIOLATION, "new file is the file of the hive: %ld\n", Error);
        StringCchPrintfW(Dir2, MAX_PATH, L"%srrp_nodir\\x.old", Dir);
        Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", New1, Dir2);
        ok(Error == ERROR_PATH_NOT_FOUND, "backup in a missing directory: %ld\n", Error);
        ok(GetFileAttributesW(New1) != INVALID_FILE_ATTRIBUTES && GetFileAttributesW(Old1) == INVALID_FILE_ATTRIBUTES,
           "files touched by refused replaces\n");

        /* The replace: the files change places at once, the hive in memory does not change */
        if (Round == 0)
        {
            Error = RegReplaceKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive", New1, Old1);
        }
        else
        {
            Sub = CreateKey(Root, L"Sub\\Deep");
            Error = RegReplaceKeyW(Sub, NULL, New1, Old1);
            RegCloseKey(Sub);
        }
        ok(Error == ERROR_SUCCESS, "RegReplaceKey (round %d) returned %ld\n", Round, Error);
        ok(GetFileAttributesW(New1) == INVALID_FILE_ATTRIBUTES, "the new file is still under its name\n");
        ok(GetFileAttributesW(Old1) != INVALID_FILE_ATTRIBUTES, "no backup file\n");
        ok(GetFileAttributesW(Hive) != INVALID_FILE_ATTRIBUTES, "no file at the path of the hive\n");
        ok(HasValue(Root, L"LiveOnly", 1), "the hive in memory changed at once\n");
        RegCloseKey(Root);
        Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyHive");
        ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW failed: %ld\n", Error);

        /* What the hive held when it was replaced is in the backup file (its lazy writes went there) */
        Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyOld", Old1);
        ok(Error == ERROR_SUCCESS, "RegLoadKeyW of the backup file failed: %ld\n", Error);
        if (Error == ERROR_SUCCESS)
        {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyOld", 0, KEY_READ, &Root);
            ok(HasValue(Root, L"LiveOnly", 1), "the backup file does not hold the old hive\n");
            RegCloseKey(Root);
            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"ReactOSReplaceKeyOld");
        }
        RemoveHiveFiles(NameOld);
    }
}

START_TEST(RegRestoreKey)
{
    DWORD Length;

    if (!SetPrivilege(L"SeBackupPrivilege", TRUE) || !SetPrivilege(L"SeRestorePrivilege", TRUE))
    {
        skip("Cannot enable the backup and restore privileges\n");
        return;
    }
    Length = GetTempPathW(MAX_PATH, Dir);
    if (!Length || Length >= MAX_PATH - 32)
    {
        skip("GetTempPathW failed\n");
        return;
    }
    DeleteTree(HKEY_LOCAL_MACHINE, Scratch);

    TestRestore();
    TestBigRestore();
    TestReplace();

    DeleteTree(HKEY_LOCAL_MACHINE, Scratch);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, Scratch);
}
