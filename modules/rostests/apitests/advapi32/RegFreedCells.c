/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Data of deleted or replaced registry values does not stay in the hive file after a flush
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * A hive is saved to a file of its own and loaded. Values with a pattern of their own are written and flushed, then
 * deleted or replaced with data of another size (the old cell is freed), and the hive is flushed and unloaded. The
 * file is then read: the data of the deleted and replaced values is not in it, the data of the value that stays is
 * (it shows that the file is the one written). Without clearing, a freed cell keeps its bytes in the file until the
 * space is used again.
 */

static PCWSTR SourcePath = L"Software\\ReactOSFreedCellsSource";
static PCWSTR HiveName = L"ReactOSFreedCellsHive";
static PCWSTR Suffixes[] = { L"", L".LOG", L".LOG1", L".LOG2" };

#define SMALL_SIZE  200
#define LARGE_SIZE  (64 * 1024)

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

/* A pattern no other data has: a tag, the size and a running counter in every 16 bytes */
static void FillPattern(PBYTE Buffer, DWORD Size, BYTE Tag)
{
    DWORD i;

    for (i = 0; i < Size; i++)
    {
        switch (i % 16)
        {
            case 0: Buffer[i] = 'N'; break;
            case 1: Buffer[i] = 'F'; break;
            case 2: Buffer[i] = 'C'; break;
            case 3: Buffer[i] = Tag; break;
            case 4: Buffer[i] = (BYTE)Size; break;
            case 5: Buffer[i] = (BYTE)(Size >> 8); break;
            default: Buffer[i] = (BYTE)((i / 16) * 7 + (i % 16) + Tag); break;
        }
    }
}

/* Counts the 64-byte lines of the pattern found in the file: any one of them is data that was not cleared. Cells
   are 8-byte aligned and their data follows a 4-byte size, so the data starts 4 bytes into an 8-byte unit. */
static ULONG CountLines(const BYTE *File, DWORD FileSize, const BYTE *Pattern, DWORD Size)
{
    DWORD Line, Offset;
    ULONG Found = 0;

    for (Line = 0; Line + 64 <= Size; Line += 64)
    {
        for (Offset = 0; Offset + 64 <= FileSize; Offset += 4)
        {
            if (memcmp(File + Offset, Pattern + Line, 64) == 0)
            {
                Found++;
                break;
            }
        }
    }
    return Found;
}

static PBYTE ReadWholeFile(PCWSTR Name, PDWORD Size)
{
    HANDLE File;
    PBYTE Buffer;
    DWORD Read;

    File = CreateFileW(Name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return NULL;
    *Size = GetFileSize(File, NULL);
    Buffer = HeapAlloc(GetProcessHeap(), 0, *Size ? *Size : 1);
    if (Buffer && (!ReadFile(File, Buffer, *Size, &Read, NULL) || Read != *Size))
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = NULL;
    }
    CloseHandle(File);
    return Buffer;
}

static BOOL SetBinary(HKEY Key, PCWSTR Name, const BYTE *Data, DWORD Size)
{
    LONG Error = RegSetValueExW(Key, Name, 0, REG_BINARY, Data, Size);

    ok(Error == ERROR_SUCCESS, "RegSetValueExW(%S, %lu) failed: %ld\n", Name, Size, Error);
    return Error == ERROR_SUCCESS;
}

START_TEST(RegFreedCells)
{
    WCHAR File[MAX_PATH];
    PBYTE Deleted, DeletedLarge, Replaced, ReplacedLarge, Kept, Contents;
    DWORD Length, ContentsSize = 0;
    HKEY Key;
    LONG Error;
    ULONG Lines;

    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege"))
    {
        skip("Cannot enable the backup and restore privileges\n");
        return;
    }
    Length = GetTempPathW(MAX_PATH, File);
    if (Length == 0 || Length >= MAX_PATH || FAILED(StringCchCatW(File, MAX_PATH, L"freedcells.hiv")))
    {
        skip("GetTempPathW failed\n");
        return;
    }
    DeleteHiveFiles(File);

    Deleted = HeapAlloc(GetProcessHeap(), 0, SMALL_SIZE);
    DeletedLarge = HeapAlloc(GetProcessHeap(), 0, LARGE_SIZE);
    Replaced = HeapAlloc(GetProcessHeap(), 0, SMALL_SIZE);
    ReplacedLarge = HeapAlloc(GetProcessHeap(), 0, LARGE_SIZE);
    Kept = HeapAlloc(GetProcessHeap(), 0, LARGE_SIZE);
    if (!Deleted || !DeletedLarge || !Replaced || !ReplacedLarge || !Kept)
    {
        skip("No memory\n");
        return;
    }
    FillPattern(Deleted, SMALL_SIZE, 'd');
    FillPattern(DeletedLarge, LARGE_SIZE, 'D');
    FillPattern(Replaced, SMALL_SIZE, 'r');
    FillPattern(ReplacedLarge, LARGE_SIZE, 'R');
    FillPattern(Kept, LARGE_SIZE, 'K');

    /* A hive file of our own: an empty key saved */
    RegDeleteKeyW(HKEY_CURRENT_USER, SourcePath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, SourcePath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW failed: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
        return;
    Error = RegSaveKeyW(Key, File, NULL);
    ok(Error == ERROR_SUCCESS, "RegSaveKeyW failed: %ld\n", Error);
    RegCloseKey(Key);
    RegDeleteKeyW(HKEY_CURRENT_USER, SourcePath);
    if (Error != ERROR_SUCCESS)
        return;

    Error = RegLoadKeyW(HKEY_LOCAL_MACHINE, HiveName, File);
    ok(Error == ERROR_SUCCESS, "RegLoadKeyW failed: %ld\n", Error);
    if (Error != ERROR_SUCCESS)
    {
        DeleteHiveFiles(File);
        return;
    }
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, HiveName, 0, KEY_ALL_ACCESS, &Key);
    ok(Error == ERROR_SUCCESS, "RegOpenKeyExW failed: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        /* Everything reaches the file once */
        SetBinary(Key, L"Deleted", Deleted, SMALL_SIZE);
        SetBinary(Key, L"DeletedLarge", DeletedLarge, LARGE_SIZE);
        SetBinary(Key, L"Replaced", Replaced, SMALL_SIZE);
        SetBinary(Key, L"ReplacedLarge", ReplacedLarge, LARGE_SIZE);
        SetBinary(Key, L"Kept", Kept, LARGE_SIZE);
        Error = RegFlushKey(Key);
        ok(Error == ERROR_SUCCESS, "RegFlushKey failed: %ld\n", Error);

        /* Deleted, and replaced by data of another size: the old cells are freed */
        Error = RegDeleteValueW(Key, L"Deleted");
        ok(Error == ERROR_SUCCESS, "RegDeleteValueW(Deleted) failed: %ld\n", Error);
        Error = RegDeleteValueW(Key, L"DeletedLarge");
        ok(Error == ERROR_SUCCESS, "RegDeleteValueW(DeletedLarge) failed: %ld\n", Error);
        SetBinary(Key, L"Replaced", (const BYTE *)"x", 1);
        SetBinary(Key, L"ReplacedLarge", (const BYTE *)"yy", 2);
        Error = RegFlushKey(Key);
        ok(Error == ERROR_SUCCESS, "RegFlushKey failed: %ld\n", Error);
        RegCloseKey(Key);
    }
    Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, HiveName);
    ok(Error == ERROR_SUCCESS, "RegUnLoadKeyW failed: %ld\n", Error);

    Contents = ReadWholeFile(File, &ContentsSize);
    ok(Contents != NULL, "Cannot read %S: %lu\n", File, GetLastError());
    if (Contents)
    {
        trace("hive file %lu bytes\n", ContentsSize);

        /* The file is the one written: the value that stays is in it (a line that spans two segments of a
           large value is not found in one piece) */
        Lines = CountLines(Contents, ContentsSize, Kept, LARGE_SIZE);
        ok(Lines >= LARGE_SIZE / 64 - 8, "kept value: %lu of %u lines in the file\n", Lines, LARGE_SIZE / 64);

        Lines = CountLines(Contents, ContentsSize, Deleted, SMALL_SIZE);
        ok(Lines == 0, "deleted value: %lu of %u lines still in the file\n", Lines, SMALL_SIZE / 64);
        Lines = CountLines(Contents, ContentsSize, DeletedLarge, LARGE_SIZE);
        ok(Lines == 0, "deleted large value: %lu of %u lines still in the file\n", Lines, LARGE_SIZE / 64);
        Lines = CountLines(Contents, ContentsSize, Replaced, SMALL_SIZE);
        ok(Lines == 0, "replaced value: %lu of %u lines still in the file\n", Lines, SMALL_SIZE / 64);
        Lines = CountLines(Contents, ContentsSize, ReplacedLarge, LARGE_SIZE);
        ok(Lines == 0, "replaced large value: %lu of %u lines still in the file\n", Lines, LARGE_SIZE / 64);
        HeapFree(GetProcessHeap(), 0, Contents);
    }

    DeleteHiveFiles(File);
    HeapFree(GetProcessHeap(), 0, Deleted);
    HeapFree(GetProcessHeap(), 0, DeletedLarge);
    HeapFree(GetProcessHeap(), 0, Replaced);
    HeapFree(GetProcessHeap(), 0, ReplacedLarge);
    HeapFree(GetProcessHeap(), 0, Kept);
}
