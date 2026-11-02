/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the additional flags of FindFirstFileExW and FindFirstFileExA
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#ifndef FIND_FIRST_EX_LARGE_FETCH
#define FIND_FIRST_EX_LARGE_FETCH 2
#endif
#ifndef FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY
#define FIND_FIRST_EX_ON_DISK_ENTRIES_ONLY 4
#endif

static BOOL IsReactOS;
static WCHAR TestDir[MAX_PATH];

static int
CountEntries(DWORD Flags, FINDEX_INFO_LEVELS Level, BOOL *BasicHadAlternate)
{
    WCHAR Pattern[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;
    int Count = 0;

    StringCbPrintfW(Pattern, sizeof(Pattern), L"%s\\*", TestDir);
    SetLastError(0xdeadbeef);
    Find = FindFirstFileExW(Pattern, Level, &Data, FindExSearchNameMatch, NULL, Flags);
    if (Find == INVALID_HANDLE_VALUE)
    {
        ok(0, "flags %lx level %d: FindFirstFileExW failed, error %lu\n", Flags, Level, GetLastError());
        return -1;
    }
    do
    {
        Count++;
        if (Level == FindExInfoBasic && Data.cAlternateFileName[0] != UNICODE_NULL)
            *BasicHadAlternate = TRUE;
    } while (FindNextFileW(Find, &Data));
    ok(GetLastError() == ERROR_NO_MORE_FILES, "flags %lx level %d: error %lu after the last entry\n", Flags, Level, GetLastError());
    FindClose(Find);
    return Count;
}

static void
test_Flags(void)
{
    static const DWORD Accepted[] = { 0, 1, 2, 3 };
    static const DWORD Windows10Only[] = { 4, 5, 6, 7 };
    static const DWORD Rejected[] = { 8, 0x10, 0x100, 0x80000000 };
    static const FINDEX_INFO_LEVELS Levels[] = { FindExInfoStandard, FindExInfoBasic };
    static const FINDEX_SEARCH_OPS Ops[] = { FindExSearchNameMatch, FindExSearchLimitToDirectories };
    WCHAR Pattern[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;
    DWORD Error;
    size_t f, l, o;

    StringCbPrintfW(Pattern, sizeof(Pattern), L"%s\\*", TestDir);

    for (l = 0; l < _countof(Levels); l++)
    for (o = 0; o < _countof(Ops); o++)
    {
        for (f = 0; f < _countof(Accepted); f++)
        {
            SetLastError(0xdeadbeef);
            Find = FindFirstFileExW(Pattern, Levels[l], &Data, Ops[o], NULL, Accepted[f]);
            Error = GetLastError();
            ok(Find != INVALID_HANDLE_VALUE, "level %d op %d flags %lx: failed, error %lu\n", Levels[l], Ops[o], Accepted[f], Error);
            if (Find != INVALID_HANDLE_VALUE)
                FindClose(Find);
        }

        for (f = 0; f < _countof(Windows10Only); f++)
        {
            SetLastError(0xdeadbeef);
            Find = FindFirstFileExW(Pattern, Levels[l], &Data, Ops[o], NULL, Windows10Only[f]);
            Error = GetLastError();
            if (Find != INVALID_HANDLE_VALUE)
                FindClose(Find);
            /* Windows 7 knows no flag above 3; Windows 10 and ReactOS accept 4 to 7 */
            if (IsReactOS)
                ok(Find != INVALID_HANDLE_VALUE, "level %d op %d flags %lx: failed, error %lu\n", Levels[l], Ops[o], Windows10Only[f], Error);
            else
                ok(Find != INVALID_HANDLE_VALUE || Error == ERROR_INVALID_PARAMETER,
                   "level %d op %d flags %lx: error %lu\n", Levels[l], Ops[o], Windows10Only[f], Error);
        }

        for (f = 0; f < _countof(Rejected); f++)
        {
            SetLastError(0xdeadbeef);
            Find = FindFirstFileExW(Pattern, Levels[l], &Data, Ops[o], NULL, Rejected[f]);
            Error = GetLastError();
            ok(Find == INVALID_HANDLE_VALUE, "level %d op %d flags %lx: succeeded\n", Levels[l], Ops[o], Rejected[f]);
            ok(Error == ERROR_INVALID_PARAMETER, "level %d op %d flags %lx: error %lu\n", Levels[l], Ops[o], Rejected[f], Error);
            if (Find != INVALID_HANDLE_VALUE)
                FindClose(Find);
        }
    }
}

static void
test_SameEntries(void)
{
    BOOL BasicHadAlternate = FALSE;
    int Plain, Large;

    Plain = CountEntries(0, FindExInfoStandard, &BasicHadAlternate);
    Large = CountEntries(FIND_FIRST_EX_LARGE_FETCH, FindExInfoStandard, &BasicHadAlternate);
    ok(Plain == 4, "plain enumeration found %d entries, expected 4 (., .., two files)\n", Plain);
    ok(Large == Plain, "large fetch found %d entries, plain %d\n", Large, Plain);
    Large = CountEntries(FIND_FIRST_EX_LARGE_FETCH, FindExInfoBasic, &BasicHadAlternate);
    ok(Large == Plain, "large fetch with basic information found %d entries, plain %d\n", Large, Plain);
    ok(!BasicHadAlternate, "FindExInfoBasic returned an alternate file name\n");
}

static void
test_Ansi(void)
{
    CHAR Pattern[MAX_PATH];
    WIN32_FIND_DATAA Data;
    HANDLE Find;
    DWORD Error;

    WideCharToMultiByte(CP_ACP, 0, TestDir, -1, Pattern, sizeof(Pattern) - 2, NULL, NULL);
    strcat(Pattern, "\\*");

    SetLastError(0xdeadbeef);
    Find = FindFirstFileExA(Pattern, FindExInfoBasic, &Data, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    Error = GetLastError();
    ok(Find != INVALID_HANDLE_VALUE, "FindFirstFileExA with large fetch failed, error %lu\n", Error);
    if (Find != INVALID_HANDLE_VALUE)
        FindClose(Find);

    SetLastError(0xdeadbeef);
    Find = FindFirstFileExA(Pattern, FindExInfoBasic, &Data, FindExSearchNameMatch, NULL, 0x10);
    Error = GetLastError();
    ok(Find == INVALID_HANDLE_VALUE, "FindFirstFileExA with flag 0x10 succeeded\n");
    ok(Error == ERROR_INVALID_PARAMETER, "FindFirstFileExA with flag 0x10: error %lu\n", Error);
    if (Find != INVALID_HANDLE_VALUE)
        FindClose(Find);
}

/*
 * FindExSearchLimitToDirectories is advisory: a file system that cannot filter (NTFS, FAT) ignores it and every
 * entry comes back, files included. Qt6 lists its plugin directories with it and then filters by attribute itself.
 */
static void
test_LimitToDirectories(void)
{
    static const FINDEX_INFO_LEVELS Levels[] = { FindExInfoStandard, FindExInfoBasic };
    WCHAR Pattern[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;
    int Count, Files, l;

    StringCbPrintfW(Pattern, sizeof(Pattern), L"%s\\*", TestDir);
    for (l = 0; l < _countof(Levels); l++)
    {
        Count = Files = 0;
        Find = FindFirstFileExW(Pattern, Levels[l], &Data, FindExSearchLimitToDirectories, NULL, FIND_FIRST_EX_LARGE_FETCH);
        ok(Find != INVALID_HANDLE_VALUE, "level %d: FindFirstFileExW failed, error %lu\n", Levels[l], GetLastError());
        if (Find == INVALID_HANDLE_VALUE)
            continue;
        do
        {
            Count++;
            if (!(Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                Files++;
        } while (FindNextFileW(Find, &Data));
        ok(GetLastError() == ERROR_NO_MORE_FILES, "level %d: error %lu after the last entry\n", Levels[l], GetLastError());
        FindClose(Find);
        ok(Count == 4, "level %d: found %d entries, expected 4 (., .., two files)\n", Levels[l], Count);
        ok(Files == 2, "level %d: found %d files, expected 2\n", Levels[l], Files);
    }
}

START_TEST(FindFirstFileEx)
{
    WCHAR File[MAX_PATH];
    HANDLE Handle;
    HKEY Key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ReactOS", 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
        IsReactOS = TRUE;
        RegCloseKey(Key);
    }

    GetTempPathW(_countof(TestDir), TestDir);
    StringCbPrintfW(TestDir + wcslen(TestDir), sizeof(TestDir) - wcslen(TestDir) * sizeof(WCHAR), L"ffex%lu", GetCurrentProcessId());
    ok(CreateDirectoryW(TestDir, NULL), "CreateDirectoryW failed, error %lu\n", GetLastError());

    StringCbPrintfW(File, sizeof(File), L"%s\\a long file name.txt", TestDir);
    Handle = CreateFileW(File, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFileW failed, error %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);
    StringCbPrintfW(File, sizeof(File), L"%s\\b.txt", TestDir);
    Handle = CreateFileW(File, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFileW failed, error %lu\n", GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);

    test_Flags();
    test_SameEntries();
    test_LimitToDirectories();
    test_Ansi();

    StringCbPrintfW(File, sizeof(File), L"%s\\a long file name.txt", TestDir);
    DeleteFileW(File);
    StringCbPrintfW(File, sizeof(File), L"%s\\b.txt", TestDir);
    DeleteFileW(File);
    RemoveDirectoryW(TestDir);
}
