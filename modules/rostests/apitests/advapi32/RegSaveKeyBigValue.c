/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RegSaveKeyEx of a key with a value of 1 MiB or more: the standard format (a hive of format 1.3, whose cell
 *              holds 1048572 bytes at most) fails with ERROR_NO_SYSTEM_RESOURCES (rows measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SCRATCH L"Software\\RegSaveKeyBigValueScratch"

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Priv;
    BOOL Ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Priv.PrivilegeCount = 1;
    Priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Ret = LookupPrivilegeValueW(NULL, Name, &Priv.Privileges[0].Luid) &&
          AdjustTokenPrivileges(Token, FALSE, &Priv, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Ret;
}

static HKEY MakeKey(const ULONG *Sizes, ULONG Count)
{
    HKEY Key = NULL;
    ULONG i;

    RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, SCRATCH, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL))
        return NULL;
    for (i = 0; i < Count; i++)
    {
        WCHAR Name[32];
        PBYTE Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Sizes[i]);
        ULONG j;

        StringCchPrintfW(Name, _countof(Name), L"v%lu", Sizes[i]);
        for (j = 0; j < Sizes[i]; j++)
            Data[j] = (BYTE)(Sizes[i] * 31 + j * 7 + (j >> 8));
        ok_long(RegSetValueExW(Key, Name, 0, REG_BINARY, Data, Sizes[i]), ERROR_SUCCESS);
        HeapFree(GetProcessHeap(), 0, Data);
    }
    return Key;
}

static void TempFile(PWSTR Out, PCWSTR Name)
{
    GetTempPathW(MAX_PATH, Out);
    wcscat(Out, Name);
    DeleteFileW(Out);
}

START_TEST(RegSaveKeyBigValue)
{
    HKEY Key;
    WCHAR File[MAX_PATH];
    LONG Result;
    static const ULONG Fits[] = { 100000, 1048572 }, TooBig[] = { 100000, 1048576, 2097152 };

    if (!EnablePrivilege(L"SeBackupPrivilege"))
    {
        skip("SeBackupPrivilege is not available\n");
        return;
    }
    /* 1048572 bytes are the most a hive of format 1.3 holds; the standard format is 1.3 */
    Key = MakeKey(Fits, RTL_NUMBER_OF(Fits));
    if (Key)
    {
        TempFile(File, L"RegSaveKeyBigValue.hiv");
        Result = RegSaveKeyExW(Key, File, NULL, 1);
        ok(Result == ERROR_SUCCESS, "standard format, 1048572 bytes: result %ld\n", Result);
        DeleteFileW(File);
        RegCloseKey(Key);
    }
    Key = MakeKey(TooBig, RTL_NUMBER_OF(TooBig));
    if (!Key)
    {
        skip("Cannot make the scratch key\n");
        return;
    }
    TempFile(File, L"RegSaveKeyBigValue.hiv");
    Result = RegSaveKeyExW(Key, File, NULL, 1);
    ok(Result == ERROR_NO_SYSTEM_RESOURCES, "standard format, 1 MiB and 2 MiB values: result %ld, expected %d\n", Result, ERROR_NO_SYSTEM_RESOURCES);
    DeleteFileW(File);
    RegCloseKey(Key);
    RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH);
}
