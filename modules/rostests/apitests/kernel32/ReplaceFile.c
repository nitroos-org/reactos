/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for ReplaceFileW and for opening a mapped image to delete it when closed
 *              (the expected values were measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

static WCHAR g_Dir[MAX_PATH];

static void MakeFile(PCWSTR Name, const char *Data, DWORD Attributes)
{
    WCHAR Path[MAX_PATH];
    HANDLE File;
    DWORD Written;

    _snwprintf(Path, _countof(Path), L"%ls\\%ls", g_Dir, Name);
    SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "Create %ls failed: %lu\n", Name, GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    WriteFile(File, Data, (DWORD)strlen(Data), &Written, NULL);
    CloseHandle(File);
    if (Attributes)
        SetFileAttributesW(Path, Attributes);
}

static void Path(PWSTR Out, PCWSTR Name)
{
    _snwprintf(Out, MAX_PATH, L"%ls\\%ls", g_Dir, Name);
}

static DWORD SizeOf(PCWSTR Name)
{
    WCHAR P[MAX_PATH];
    WIN32_FILE_ATTRIBUTE_DATA Data;

    Path(P, Name);
    if (!GetFileAttributesExW(P, GetFileExInfoStandard, &Data))
        return (DWORD)-1;
    return Data.nFileSizeLow;
}

static DWORD AttrOf(PCWSTR Name)
{
    WCHAR P[MAX_PATH];

    Path(P, Name);
    return GetFileAttributesW(P);
}

static void Cleanup(void)
{
    static PCWSTR Names[] = { L"old.txt", L"new.txt", L"bak.txt", L"img.dll", L"copy.dll" };
    WCHAR P[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE Search;
    UINT i;

    for (i = 0; i < _countof(Names); i++)
    {
        Path(P, Names[i]);
        SetFileAttributesW(P, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(P);
    }
    /* leftovers of a replacement that could not delete its old file */
    _snwprintf(P, _countof(P), L"%ls\\*", g_Dir);
    Search = FindFirstFileW(P, &Find);
    if (Search != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (Find.cFileName[0] != L'.')
            {
                _snwprintf(P, _countof(P), L"%ls\\%ls", g_Dir, Find.cFileName);
                SetFileAttributesW(P, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(P);
            }
        } while (FindNextFileW(Search, &Find));
        FindClose(Search);
    }
}

static void TestPlain(void)
{
    WCHAR Old[MAX_PATH], New[MAX_PATH], Bak[MAX_PATH];
    HANDLE Held;
    BOOL Ret;

    Path(Old, L"old.txt");
    Path(New, L"new.txt");
    Path(Bak, L"bak.txt");

    /* the new content takes the old name, the replacement name is gone */
    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(Ret, "ReplaceFileW failed: %lu\n", GetLastError());
    ok(SizeOf(L"old.txt") == 7, "size %lu\n", SizeOf(L"old.txt"));
    ok(AttrOf(L"new.txt") == INVALID_FILE_ATTRIBUTES, "the replacement is still there\n");

    /* with a backup name the old content goes there */
    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Ret = ReplaceFileW(Old, New, Bak, 0, NULL, NULL);
    ok(Ret, "ReplaceFileW with backup failed: %lu\n", GetLastError());
    ok(SizeOf(L"old.txt") == 7, "size %lu\n", SizeOf(L"old.txt"));
    ok(SizeOf(L"bak.txt") == 3, "backup size %lu\n", SizeOf(L"bak.txt"));
    DeleteFileW(Bak);

    /* a hidden file stays hidden, the attributes of the replacement are dropped, the result is archived */
    MakeFile(L"old.txt", "OLD", FILE_ATTRIBUTE_HIDDEN);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(Ret, "ReplaceFileW failed: %lu\n", GetLastError());
    ok(AttrOf(L"old.txt") == (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE), "attributes %lx\n", AttrOf(L"old.txt"));
    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", FILE_ATTRIBUTE_HIDDEN);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(Ret, "ReplaceFileW failed: %lu\n", GetLastError());
    ok(AttrOf(L"old.txt") == FILE_ATTRIBUTE_ARCHIVE, "attributes %lx\n", AttrOf(L"old.txt"));

    /* a read-only file on either side: access denied, nothing changes */
    MakeFile(L"old.txt", "OLD", FILE_ATTRIBUTE_READONLY);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "read-only old: %d, %lu\n", Ret, GetLastError());
    ok(SizeOf(L"old.txt") == 3 && AttrOf(L"new.txt") != INVALID_FILE_ATTRIBUTES, "changed\n");
    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", FILE_ATTRIBUTE_READONLY);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(!Ret && GetLastError() == ERROR_ACCESS_DENIED, "read-only new: %d, %lu\n", Ret, GetLastError());
    ok(SizeOf(L"old.txt") == 3, "changed\n");

    /* the replaced file may be open (sharing everything), not exclusively; the replacement may not be open */
    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Held = CreateFileW(Old, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(Ret, "open replaced file: failed %lu\n", GetLastError());
    CloseHandle(Held);
    ok(SizeOf(L"old.txt") == 7, "size %lu\n", SizeOf(L"old.txt"));

    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Held = CreateFileW(Old, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(!Ret && GetLastError() == ERROR_SHARING_VIOLATION, "exclusive replaced file: %d, %lu\n", Ret, GetLastError());
    CloseHandle(Held);
    ok(SizeOf(L"old.txt") == 3, "changed\n");

    MakeFile(L"old.txt", "OLD", 0);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Held = CreateFileW(New, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(!Ret && GetLastError() == ERROR_SHARING_VIOLATION, "open replacement: %d, %lu\n", Ret, GetLastError());
    CloseHandle(Held);
    ok(SizeOf(L"old.txt") == 3, "changed\n");

    /* missing files */
    MakeFile(L"old.txt", "OLD", 0);
    DeleteFileW(New);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(!Ret && GetLastError() == ERROR_FILE_NOT_FOUND, "missing replacement: %d, %lu\n", Ret, GetLastError());
    DeleteFileW(Old);
    MakeFile(L"new.txt", "NEWDATA", 0);
    Ret = ReplaceFileW(Old, New, NULL, 0, NULL, NULL);
    ok(!Ret && GetLastError() == ERROR_FILE_NOT_FOUND, "missing replaced: %d, %lu\n", Ret, GetLastError());
}

static void TestImage(void)
{
    WCHAR Sys[MAX_PATH], Img[MAX_PATH], New[MAX_PATH];
    HMODULE Lib;
    HANDLE File;
    BOOL Ret;

    GetSystemDirectoryW(Sys, _countof(Sys));
    wcscat(Sys, L"\\msimg32.dll");
    Path(Img, L"img.dll");
    Path(New, L"new.txt");
    Ret = CopyFileW(Sys, Img, FALSE);
    ok(Ret, "copy failed %lu\n", GetLastError());
    if (!Ret)
        return;
    Lib = LoadLibraryW(Img);
    ok(Lib != NULL, "LoadLibrary failed %lu\n", GetLastError());
    if (!Lib)
        return;

    /* opening a loaded dll to delete it when closed fails, the file stays */
    SetLastError(0);
    File = CreateFileW(Img, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                       FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(File == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "delete on close: %p, %lu\n", File, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    ok(SizeOf(L"img.dll") != (DWORD)-1, "the loaded dll was deleted\n");

    /* a loaded dll is replaced by renaming: the new content is in place at once */
    MakeFile(L"new.txt", "NEWDATA", 0);
    Ret = ReplaceFileW(Img, New, NULL, 0, NULL, NULL);
    ok(Ret, "ReplaceFileW over a loaded dll failed: %lu\n", GetLastError());
    ok(SizeOf(L"img.dll") == 7, "size %lu\n", SizeOf(L"img.dll"));
    ok(AttrOf(L"new.txt") == INVALID_FILE_ATTRIBUTES, "the replacement is still there\n");

    /* the old image cannot be deleted while it is loaded: it stays as img.dll~RFxxxx.TMP with its content */
    {
        WCHAR Pattern[MAX_PATH];
        WIN32_FIND_DATAW Find;
        HANDLE Search;

        Path(Pattern, L"img.dll~RF*.TMP");
        Search = FindFirstFileW(Pattern, &Find);
        ok(Search != INVALID_HANDLE_VALUE, "no leftover of the old image: %lu\n", GetLastError());
        if (Search != INVALID_HANDLE_VALUE)
        {
            ok(Find.nFileSizeLow > 7, "leftover size %lu\n", Find.nFileSizeLow);
            FindClose(Search);
        }
    }

    FreeLibrary(Lib);
}

START_TEST(ReplaceFile)
{
    WCHAR Temp[MAX_PATH];

    GetTempPathW(_countof(Temp), Temp);
    _snwprintf(g_Dir, _countof(g_Dir), L"%lsrfapi%lu", Temp, GetCurrentProcessId());
    if (!CreateDirectoryW(g_Dir, NULL))
    {
        skip("Cannot create %ls: %lu\n", g_Dir, GetLastError());
        return;
    }

    TestPlain();
    Cleanup();
    TestImage();
    Cleanup();
    RemoveDirectoryW(g_Dir);
}
