/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the name classes and the set-only classes of GetFileInformationByHandleEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Rows measured on Windows Server 2022, on an NTFS and a FAT volume.
 */

#include "precomp.h"

/* The test builds at NT 5.2 level, where the Vista types are hidden */
enum
{
    TestFileNameInfo = 2,
    TestFileRenameInfo = 3,
    TestFileDispositionInfo = 4,
    TestFileAllocationInfo = 5,
    TestFileEndOfFileInfo = 6,
    TestFileIoPriorityHintInfo = 12,
    TestFileDispositionInfoEx = 21,
    TestFileRenameInfoEx = 22,
    TestFileNormalizedNameInfo = 24,
    TestMaximumFileInfoByHandleClass = 25
};

typedef struct
{
    DWORD FileNameLength;
    WCHAR FileName[1];
} TEST_NAME_INFO;

typedef BOOL (WINAPI *PFN_GetFileInformationByHandleEx)(HANDLE, int, LPVOID, DWORD);

static PFN_GetFileInformationByHandleEx pGetFileInformationByHandleEx;

static HANDLE OpenForQuery(LPCWSTR Path)
{
    return CreateFileW(Path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

/* the name of a class as a string, with the size rules of both name classes checked */
static BOOL QueryName(HANDLE hFile, int Class, WCHAR *Out, ULONG OutChars)
{
    BYTE Buffer[2048];
    TEST_NAME_INFO *Info = (TEST_NAME_INFO *)Buffer;
    DWORD Needed, Size, Error;
    BOOL Ok;

    memset(Buffer, 0xcc, sizeof(Buffer));
    Ok = pGetFileInformationByHandleEx(hFile, Class, Buffer, sizeof(Buffer));
    ok(Ok, "class %d failed: %lu\n", Class, GetLastError());
    if (!Ok)
        return FALSE;
    Needed = FIELD_OFFSET(TEST_NAME_INFO, FileName) + Info->FileNameLength;
    if (Needed < sizeof(TEST_NAME_INFO))
        Needed = sizeof(TEST_NAME_INFO);
    ok(Needed < sizeof(Buffer), "class %d: name length %lu\n", Class, Info->FileNameLength);
    if (Needed >= sizeof(Buffer) || Info->FileNameLength / sizeof(WCHAR) >= OutChars)
        return FALSE;
    memcpy(Out, Info->FileName, Info->FileNameLength);
    Out[Info->FileNameLength / sizeof(WCHAR)] = 0;

    /* sizes below the structure (8 bytes) are a bad length, sizes below the name leave data to read */
    for (Size = 0; Size < sizeof(TEST_NAME_INFO); Size++)
    {
        SetLastError(0xdeadbeef);
        memset(Buffer, 0xcc, sizeof(Buffer));
        Ok = pGetFileInformationByHandleEx(hFile, Class, Buffer, Size);
        Error = GetLastError();
        ok(!Ok, "class %d size %lu: success\n", Class, Size);
        ok_dec(Error, ERROR_BAD_LENGTH);
        ok_hex(Buffer[0], 0xcc);
    }
    for (; Size < Needed; Size += 2)
    {
        SetLastError(0xdeadbeef);
        Ok = pGetFileInformationByHandleEx(hFile, Class, Buffer, Size);
        Error = GetLastError();
        ok(!Ok, "class %d size %lu: success\n", Class, Size);
        ok_dec(Error, ERROR_MORE_DATA);
    }
    Ok = pGetFileInformationByHandleEx(hFile, Class, Buffer, Needed);
    ok(Ok, "class %d exact size failed: %lu\n", Class, GetLastError());
    Ok = pGetFileInformationByHandleEx(hFile, Class, Buffer, Needed + 100);
    ok(Ok, "class %d larger size failed: %lu\n", Class, GetLastError());
    return TRUE;
}

static void CheckUnqueryable(HANDLE hFile)
{
    static const int Classes[] =
    {
        TestFileRenameInfo, TestFileDispositionInfo, TestFileAllocationInfo, TestFileEndOfFileInfo,
        TestFileIoPriorityHintInfo, TestFileDispositionInfoEx, TestFileRenameInfoEx,
        TestMaximumFileInfoByHandleClass, 26, 27, 30
    };
    BYTE Buffer[256];
    ULONG i, Sizes[] = { 0, 4, sizeof(Buffer) };
    ULONG j;

    for (i = 0; i < _countof(Classes); i++)
    {
        for (j = 0; j < _countof(Sizes); j++)
        {
            DWORD Error;
            BOOL Ok;

            SetLastError(0xdeadbeef);
            memset(Buffer, 0xcc, sizeof(Buffer));
            Ok = pGetFileInformationByHandleEx(hFile, Classes[i], Buffer, Sizes[j]);
            Error = GetLastError();
            ok(!Ok, "class %d size %lu: success\n", Classes[i], Sizes[j]);
            ok_dec(Error, ERROR_INVALID_PARAMETER);
            ok_hex(Buffer[0], 0xcc);
        }
    }
}

START_TEST(GetFileInformationByHandleEx)
{
    WCHAR Dir[MAX_PATH], FilePath[MAX_PATH], Short[MAX_PATH], Upper[MAX_PATH];
    WCHAR Name[MAX_PATH], Normalized[MAX_PATH], Expected[MAX_PATH], LongPath[MAX_PATH], DirLong[MAX_PATH];
    HANDLE hFile, hDir;
    DWORD Len;
    PWSTR Remainder;

    pGetFileInformationByHandleEx =
        (PFN_GetFileInformationByHandleEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFileInformationByHandleEx");
    if (!pGetFileInformationByHandleEx)
    {
        skip("GetFileInformationByHandleEx is missing\n");
        return;
    }

    GetTempPathW(_countof(Dir), Dir);
    wcscat(Dir, L"GfibhExNameTest");
    RemoveDirectoryW(Dir);
    if (!CreateDirectoryW(Dir, NULL))
    {
        skip("cannot create %ls: %lu\n", Dir, GetLastError());
        return;
    }
    wcscpy(FilePath, Dir);
    wcscat(FilePath, L"\\LongFileNameTest.txt");
    hFile = CreateFileW(FilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        skip("cannot create %ls: %lu\n", FilePath, GetLastError());
        RemoveDirectoryW(Dir);
        return;
    }
    CloseHandle(hFile);

    /* the path without the drive letter, with the long names and the case of the creation (the temporary directory
       may be given with the short name of a user) */
    Len = GetLongPathNameW(FilePath, LongPath, _countof(LongPath));
    if (!Len || Len >= _countof(LongPath))
        wcscpy(LongPath, FilePath);
    Remainder = LongPath;
    while (*Remainder && *Remainder != L'\\')
        Remainder++;
    wcscpy(Expected, Remainder);
    Len = GetLongPathNameW(Dir, DirLong, _countof(DirLong));
    if (!Len || Len >= _countof(DirLong))
        wcscpy(DirLong, Dir);

    hFile = OpenForQuery(FilePath);
    ok(hFile != INVALID_HANDLE_VALUE, "open failed: %lu\n", GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
    {
        BOOL Ok = QueryName(hFile, TestFileNormalizedNameInfo, Normalized, _countof(Normalized));
        if (Ok)
            ok(!wcsicmp(Normalized, Expected) && !wcscmp(Normalized, Expected), "normalized name %ls, expected %ls\n", Normalized, Expected);
        QueryName(hFile, TestFileNameInfo, Name, _countof(Name));
        CheckUnqueryable(hFile);
        CloseHandle(hFile);
    }

    /* opened with other case: the name of the disk */
    wcscpy(Upper, FilePath);
    _wcsupr(Upper + 2);
    hFile = OpenForQuery(Upper);
    ok(hFile != INVALID_HANDLE_VALUE, "open of the upper case name failed: %lu\n", GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (QueryName(hFile, TestFileNormalizedNameInfo, Normalized, _countof(Normalized)))
            ok(!wcscmp(Normalized, Expected), "normalized name %ls, expected %ls\n", Normalized, Expected);
        CloseHandle(hFile);
    }

    /* opened by its short name: the long name */
    Len = GetShortPathNameW(FilePath, Short, _countof(Short));
    if (Len && Len < _countof(Short) && wcsicmp(Short, FilePath))
    {
        hFile = OpenForQuery(Short);
        ok(hFile != INVALID_HANDLE_VALUE, "open of the short name failed: %lu\n", GetLastError());
        if (hFile != INVALID_HANDLE_VALUE)
        {
            if (QueryName(hFile, TestFileNormalizedNameInfo, Normalized, _countof(Normalized)))
                ok(!wcscmp(Normalized, Expected), "normalized name %ls, expected %ls\n", Normalized, Expected);
            CloseHandle(hFile);
        }
    }
    else
    {
        skip("the volume has no short names\n");
    }

    /* a directory */
    hDir = OpenForQuery(Dir);
    ok(hDir != INVALID_HANDLE_VALUE, "open of the directory failed: %lu\n", GetLastError());
    if (hDir != INVALID_HANDLE_VALUE)
    {
        Remainder = DirLong;
        while (*Remainder && *Remainder != L'\\')
            Remainder++;
        if (QueryName(hDir, TestFileNormalizedNameInfo, Normalized, _countof(Normalized)))
            ok(!wcscmp(Normalized, Remainder), "normalized name %ls, expected %ls\n", Normalized, Remainder);
        CheckUnqueryable(hDir);
        CloseHandle(hDir);
    }

    /* the root of the volume */
    wcsncpy(Name, Dir, 3);
    Name[3] = 0;
    hDir = OpenForQuery(Name);
    if (hDir != INVALID_HANDLE_VALUE)
    {
        if (QueryName(hDir, TestFileNormalizedNameInfo, Normalized, _countof(Normalized)))
            ok(!wcscmp(Normalized, L"\\"), "normalized name of the root %ls\n", Normalized);
        CloseHandle(hDir);
    }

    DeleteFileW(FilePath);
    RemoveDirectoryW(Dir);
}
