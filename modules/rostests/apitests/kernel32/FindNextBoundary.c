/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     FindNextFileW must return the entry that ends exactly at the end of its query buffer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * kernel32 queries a directory with a 0x4000 byte buffer (FindFirstFile takes one entry, every
 * later query takes as many as fit).  A file system that packs the buffer fully returns an entry
 * whose name ends on the last byte of the buffer; kernel32 once took that entry for a truncated
 * one and dropped it, so "rmdir /s" and "del /s" left that file behind.  Entries are
 * FILE_BOTH_DIR_INFORMATION: 94 bytes plus the name, each starting on an 8-byte boundary.  With
 * names of Len characters (Need = 94 + 2 * Len, a multiple of 8, so Len = 1 mod 4) the Count-th
 * file ends at byte 0x4000 of the first FindNextFile buffer when 104 + Count * Need = 0x4000
 * (".." takes 104 bytes, "." came with FindFirstFile), or of the second buffer when the first one
 * holds 127 files of 128 bytes and the second Count * 128 = 0x4000.
 */
static const struct
{
    int Len;
    int Count;
} Cases[] =
{
    { 101, 55 },    /* last entry ends at 0x4000 of the first buffer, 296 bytes each */
    { 173, 37 },    /* 440 bytes each */
    { 17, 255 },    /* 127 + 128 files of 128 bytes: the last ends at 0x4000 of the second buffer */
    { 81, 127 },    /* 256 bytes each: 63 + 64 */
    { 20, 100 },    /* nothing exact, 100 names of 20 characters */
};

static void
Name(WCHAR *Out, SIZE_T Size, const WCHAR *Dir, int Len, int Index)
{
    WCHAR Digits[16];
    int i, n;

    /* a fixed-length, sortable name */
    StringCbPrintfW(Digits, sizeof(Digits), L"%04d", Index);
    n = StringCbPrintfW(Out, Size, L"%s\\", Dir) == S_OK ? (int)wcslen(Out) : 0;
    for (i = 0; i < Len; i++)
        Out[n + i] = i < Len - 4 ? L'f' : Digits[i - (Len - 4)];
    Out[n + Len] = UNICODE_NULL;
}

static void
RunCase(const WCHAR *Dir, int Len, int Count)
{
    WCHAR Path[MAX_PATH], Pattern[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find, File;
    BOOLEAN *Seen;
    BOOL Removed;
    int i, Found = 0, Other = 0, Deleted = 0;

    Seen = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Count);
    ok(Seen != NULL, "out of memory\n");
    if (!Seen)
        return;
    ok(CreateDirectoryW(Dir, NULL), "CreateDirectoryW failed, error %lu\n", GetLastError());
    for (i = 0; i < Count; i++)
    {
        Name(Path, sizeof(Path), Dir, Len, i);
        File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (File == INVALID_HANDLE_VALUE)
        {
            ok(0, "len %d: CreateFileW %d failed, error %lu\n", Len, i, GetLastError());
            break;
        }
        CloseHandle(File);
    }

    /* every file is listed once */
    StringCbPrintfW(Pattern, sizeof(Pattern), L"%s\\*", Dir);
    Find = FindFirstFileW(Pattern, &Data);
    ok(Find != INVALID_HANDLE_VALUE, "FindFirstFileW failed, error %lu\n", GetLastError());
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(Data.cFileName, L".") && wcscmp(Data.cFileName, L".."))
            {
                int Index = _wtoi(Data.cFileName + Len - 4);
                if (Index >= 0 && Index < Count && !Seen[Index] && (int)wcslen(Data.cFileName) == Len)
                    Seen[Index] = TRUE;
                else
                    Other++;
                Found++;
            }
        } while (FindNextFileW(Find, &Data));
        ok(GetLastError() == ERROR_NO_MORE_FILES, "error %lu after the last entry\n", GetLastError());
        FindClose(Find);
    }
    ok(Found == Count, "len %d: %d entries listed, %d files exist\n", Len, Found, Count);
    ok(Other == 0, "len %d: %d unexpected or repeated entries\n", Len, Other);
    for (i = 0; i < Count; i++)
        ok(Seen[i], "len %d: file %d not listed\n", Len, i);

    /* enumerate and delete in the same pass, as "rmdir /s" does: nothing may be left */
    Find = FindFirstFileW(Pattern, &Data);
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!wcscmp(Data.cFileName, L".") || !wcscmp(Data.cFileName, L".."))
                continue;
            StringCbPrintfW(Path, sizeof(Path), L"%s\\%s", Dir, Data.cFileName);
            if (DeleteFileW(Path))
                Deleted++;
        } while (FindNextFileW(Find, &Data));
        FindClose(Find);
    }
    ok(Deleted == Count, "len %d: %d files deleted while listing, %d exist\n", Len, Deleted, Count);
    Removed = RemoveDirectoryW(Dir);
    ok(Removed, "len %d: RemoveDirectoryW failed, error %lu\n", Len, GetLastError());
    if (GetFileAttributesW(Dir) != INVALID_FILE_ATTRIBUTES)
    {
        for (i = 0; i < Count; i++)
        {
            Name(Path, sizeof(Path), Dir, Len, i);
            DeleteFileW(Path);
        }
        RemoveDirectoryW(Dir);
    }
    HeapFree(GetProcessHeap(), 0, Seen);
}

START_TEST(FindNextBoundary)
{
    WCHAR Dir[MAX_PATH];
    size_t i;

    for (i = 0; i < _countof(Cases); i++)
    {
        GetTempPathW(_countof(Dir), Dir);
        StringCbPrintfW(Dir + wcslen(Dir), sizeof(Dir) - wcslen(Dir) * sizeof(WCHAR), L"fnb%lu_%d", GetCurrentProcessId(), Cases[i].Len);
        RunCase(Dir, Cases[i].Len, Cases[i].Count);
    }
}
