/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RegSaveKeyEx: the format flags (measured on Windows Server 2022: 1 writes a hive of format 1.3, 2 a hive
 *              of format 1.5, every other value is ERROR_INVALID_PARAMETER)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SCRATCH L"Software\\RegSaveKeyExFormatScratch"

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

static ULONG HiveMinor(PCWSTR File)
{
    HANDLE Handle = CreateFileW(File, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    BYTE Block[0x20];
    DWORD Read = 0;
    ULONG Minor = 0;

    if (Handle == INVALID_HANDLE_VALUE)
        return 0;
    if (ReadFile(Handle, Block, sizeof(Block), &Read, NULL) && Read == sizeof(Block) && !memcmp(Block, "regf", 4))
        Minor = *(ULONG *)(Block + 0x18);
    CloseHandle(Handle);
    return Minor;
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

START_TEST(RegSaveKeyExFormat)
{
    static const ULONG Sizes[] = { 3, 20000, 100000, 500000 };
    static const struct { DWORD Flags; BOOL Valid; ULONG Minor; } Rows[] =
    {
        { 1, TRUE, 3 }, { 2, TRUE, 5 }, { 0, FALSE, 0 }, { 3, FALSE, 0 }, { 4, FALSE, 0 }, { 5, FALSE, 0 }, { 6, FALSE, 0 },
        { 7, FALSE, 0 }, { 8, FALSE, 0 },
    };
    WCHAR File[MAX_PATH];
    HKEY Key;
    ULONG i;

    if (!EnablePrivilege(L"SeBackupPrivilege"))
    {
        skip("SeBackupPrivilege is not available\n");
        return;
    }
    Key = MakeKey(Sizes, RTL_NUMBER_OF(Sizes));
    if (!Key)
    {
        skip("Cannot make the scratch key\n");
        return;
    }
    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        LONG Result;

        TempFile(File, L"RegSaveKeyExFormat.hiv");
        Result = RegSaveKeyExW(Key, File, NULL, Rows[i].Flags);
        if (Rows[i].Valid)
        {
            ok(Result == ERROR_SUCCESS, "flags %lu: result %ld\n", Rows[i].Flags, Result);
            if (Result == ERROR_SUCCESS)
                ok(HiveMinor(File) == Rows[i].Minor, "flags %lu: hive version 1.%lu, expected 1.%lu\n", Rows[i].Flags, HiveMinor(File), Rows[i].Minor);
        }
        else
            ok(Result == ERROR_INVALID_PARAMETER, "flags %lu: result %ld, expected ERROR_INVALID_PARAMETER\n", Rows[i].Flags, Result);
        DeleteFileW(File);
    }
    RegCloseKey(Key);

    /* a value of 1 MiB and one of 2 MiB: the latest format holds them (big data) */
    {
        static const ULONG Big[] = { 100000, 1048576, 2097152 };
        LONG Result;

        Key = MakeKey(Big, RTL_NUMBER_OF(Big));
        if (Key)
        {
            TempFile(File, L"RegSaveKeyExFormat.hiv");
            Result = RegSaveKeyExW(Key, File, NULL, REG_LATEST_FORMAT);
            ok(Result == ERROR_SUCCESS, "latest format, 1 MiB and 2 MiB values: result %ld\n", Result);
            if (Result == ERROR_SUCCESS)
                ok(HiveMinor(File) == 5, "latest format with big values: hive version 1.%lu\n", HiveMinor(File));
            DeleteFileW(File);
            RegCloseKey(Key);
        }
    }
    RegDeleteKeyW(HKEY_CURRENT_USER, SCRATCH);
}
