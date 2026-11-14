/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A key with a value larger than 64 KB reports the right MaxValueDataLen,
 *              also when its key control block is created from a freshly loaded hive
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/cmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

#define BIG_VALUE_SIZE 70000

/* Documented KeyCachedInformation layout */
typedef struct _KCB_TEST_CACHED_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG NameLength;
} KCB_TEST_CACHED_INFORMATION;

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

#define CheckMaxValueDataLen(k, e, w) CheckMaxValueDataLen_(__LINE__, k, e, w)
static void CheckMaxValueDataLen_(INT Line, HKEY Key, DWORD Expected, PCSTR What)
{
    KEY_FULL_INFORMATION Full;
    KCB_TEST_CACHED_INFORMATION Cached;
    ULONG Length;
    NTSTATUS Status;
    DWORD MaxData;
    LONG Error;

    Status = NtQueryKey(Key, KeyFullInformation, &Full, sizeof(Full), &Length);
    /* The class and name are not copied: a buffer overflow status is fine */
    ok_(__FILE__, Line)(NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW,
                        "%s: NtQueryKey(KeyFullInformation) returned 0x%lx\n", What, Status);
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        ok_(__FILE__, Line)(Full.MaxValueDataLen == Expected,
                            "%s: KeyFullInformation MaxValueDataLen = %lu, expected %lu\n",
                            What, Full.MaxValueDataLen, Expected);

    RtlZeroMemory(&Cached, sizeof(Cached));
    Status = NtQueryKey(Key, KeyCachedInformation, &Cached, sizeof(Cached), &Length);
    ok_(__FILE__, Line)(NT_SUCCESS(Status),
                        "%s: NtQueryKey(KeyCachedInformation) returned 0x%lx\n", What, Status);
    if (NT_SUCCESS(Status))
        ok_(__FILE__, Line)(Cached.MaxValueDataLen == Expected,
                            "%s: KeyCachedInformation MaxValueDataLen = %lu, expected %lu\n",
                            What, Cached.MaxValueDataLen, Expected);

    MaxData = 0x55555555;
    Error = RegQueryInfoKeyW(Key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &MaxData, NULL, NULL);
    ok_(__FILE__, Line)(Error == ERROR_SUCCESS, "%s: RegQueryInfoKeyW returned %ld\n", What, Error);
    ok_(__FILE__, Line)(MaxData == Expected,
                        "%s: RegQueryInfoKeyW MaxValueLen = %lu, expected %lu\n", What, MaxData, Expected);
}

START_TEST(RegMaxValueDataLen)
{
    static PCWSTR SourcePath = L"Software\\ReactOSKcbMaxDataSource";
    static PCWSTR HiveName = L"ReactOSKcbMaxDataHive";
    WCHAR File[MAX_PATH], Name[MAX_PATH + 8];
    PBYTE Data;
    HKEY Key;
    LONG Error;
    ULONG i;
    DWORD Length;

    Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BIG_VALUE_SIZE);
    ok(Data != NULL, "HeapAlloc failed\n");
    if (!Data)
        return;

    RegDeleteKeyW(HKEY_CURRENT_USER, SourcePath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, SourcePath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        goto Done;

    Error = RegSetValueExW(Key, L"Small", 0, REG_BINARY, Data, 16);
    ok(Error == ERROR_SUCCESS, "RegSetValueExW failed: %ld\n", Error);
    Error = RegSetValueExW(Key, L"Big", 0, REG_BINARY, Data, BIG_VALUE_SIZE);
    ok(Error == ERROR_SUCCESS, "RegSetValueExW failed: %ld\n", Error);
    CheckMaxValueDataLen(Key, BIG_VALUE_SIZE, "created key");
    RegCloseKey(Key);

    /* Reopen: the key control block may come from the delayed close cache */
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, SourcePath, 0, KEY_QUERY_VALUE | KEY_READ, &Key);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        CheckMaxValueDataLen(Key, BIG_VALUE_SIZE, "reopened key");

        if (EnablePrivilege(L"SeBackupPrivilege") && EnablePrivilege(L"SeRestorePrivilege"))
        {
            Length = GetTempPathW(MAX_PATH, File);
            if (Length != 0 && Length < MAX_PATH &&
                SUCCEEDED(StringCchCatW(File, MAX_PATH, L"kcbmaxdata.hiv")))
            {
                static PCWSTR Suffixes[] = { L"", L".LOG", L".LOG1", L".LOG2" };

                for (i = 0; i < _countof(Suffixes); i++)
                {
                    StringCchPrintfW(Name, _countof(Name), L"%s%s", File, Suffixes[i]);
                    DeleteFileW(Name);
                }

                Error = RegSaveKeyW(Key, File, NULL);
                ok(Error == ERROR_SUCCESS, "RegSaveKeyW failed: %ld\n", Error);
                RegCloseKey(Key);
                Key = NULL;

                /* Loading the hive and unloading it again builds fresh key control blocks from the nodes */
                for (i = 0; Error == ERROR_SUCCESS && i < 2; i++)
                {
                    Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, HiveName, File);
                    ok(Error == ERROR_SUCCESS, "RegLoadKeyW failed: %ld\n", Error);
                    if (Error != ERROR_SUCCESS)
                        break;
                    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, HiveName, 0, KEY_READ, &Key);
                    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
                    if (Error == ERROR_SUCCESS)
                    {
                        CheckMaxValueDataLen(Key, BIG_VALUE_SIZE, i == 0 ? "loaded hive" : "reloaded hive");
                        RegCloseKey(Key);
                        Key = NULL;
                    }
                    Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HiveName);
                    ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW failed: %ld\n", Error);
                }

                for (i = 0; i < _countof(Suffixes); i++)
                {
                    StringCchPrintfW(Name, _countof(Name), L"%s%s", File, Suffixes[i]);
                    DeleteFileW(Name);
                }
            }
            else
            {
                skip("GetTempPathW failed\n");
            }
        }
        else
        {
            skip("Cannot enable the backup and restore privileges\n");
        }
        if (Key)
            RegCloseKey(Key);
    }

    RegDeleteKeyW(HKEY_CURRENT_USER, SourcePath);
Done:
    HeapFree(GetProcessHeap(), 0, Data);
}
