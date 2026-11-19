/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the rename paths of SetFileInformationByHandle
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* The test builds at NT 5.2 level, where the Vista types are hidden */
enum
{
    TestFileStandardInfo = 1,
    TestFileRenameInfo = 3,
    TestFileDispositionInfo = 4,
    TestFileEndOfFileInfo = 6,
    TestFileIoPriorityHintInfo = 12
};

typedef struct
{
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    DWORD FileNameLength;
    WCHAR FileName[1];
} TEST_RENAME_INFO;

typedef struct
{
    LARGE_INTEGER EndOfFile;
} TEST_END_OF_FILE_INFO;

typedef struct
{
    BOOLEAN Delete;
} TEST_DISPOSITION_INFO;

typedef BOOL (WINAPI *FN_SetFileInformationByHandle)(HANDLE, INT, LPVOID, DWORD);
static FN_SetFileInformationByHandle pSetFileInformationByHandle;

static WCHAR TestDir[MAX_PATH], FileDir[MAX_PATH], CwdDir[MAX_PATH];

static BOOL ExistsIn(PCWSTR Dir, PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    StringCchPrintfW(Path, _countof(Path), L"%s\\%s", Dir, Name);
    return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL FileExists(PCWSTR Name)
{
    return ExistsIn(TestDir, Name);
}

static HANDLE OpenFileIn(PCWSTR Dir, PCWSTR Name, DWORD Disposition)
{
    WCHAR Path[MAX_PATH];
    StringCchPrintfW(Path, _countof(Path), L"%s\\%s", Dir, Name);
    return CreateFileW(Path, GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL, Disposition, 0, NULL);
}

static HANDLE OpenTestFile(PCWSTR Name, DWORD Disposition)
{
    return OpenFileIn(TestDir, Name, Disposition);
}

/* Renames the open file to Name, with the name length in bytes adjusted by Delta */
static BOOL RenameToEx(HANDLE File, HANDLE Root, PCWSTR Name, BOOL Replace, INT Delta)
{
    struct
    {
        TEST_RENAME_INFO Info;
        WCHAR Buffer[MAX_PATH];
    } Rename;
    DWORD Length = (DWORD)wcslen(Name) * sizeof(WCHAR);

    ZeroMemory(&Rename, sizeof(Rename));
    Rename.Info.ReplaceIfExists = Replace;
    Rename.Info.RootDirectory = Root;
    Rename.Info.FileNameLength = Length + Delta;
    CopyMemory(Rename.Info.FileName, Name, Length);
    return pSetFileInformationByHandle(File, TestFileRenameInfo, &Rename, sizeof(Rename));
}

static BOOL RenameTo(HANDLE File, PCWSTR Name, BOOL Replace, INT Delta)
{
    return RenameToEx(File, NULL, Name, Replace, Delta);
}

/* Creates Dir\Name holding Data */
static BOOL WriteFileIn(PCWSTR Dir, PCWSTR Name, const char *Data)
{
    HANDLE File = OpenFileIn(Dir, Name, CREATE_ALWAYS);
    DWORD Written = 0;
    BOOL Ret;

    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(File, Data, (DWORD)strlen(Data), &Written, NULL) && Written == strlen(Data);
    CloseHandle(File);
    return Ret;
}

/* Whether Dir\Name holds exactly Data */
static BOOL FileHolds(PCWSTR Dir, PCWSTR Name, const char *Data)
{
    WCHAR Path[MAX_PATH];
    char Buffer[16];
    DWORD Read = 0;
    HANDLE File;
    BOOL Ret;

    StringCchPrintfW(Path, _countof(Path), L"%s\\%s", Dir, Name);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = ReadFile(File, Buffer, sizeof(Buffer), &Read, NULL) &&
          Read == strlen(Data) && !memcmp(Buffer, Data, Read);
    CloseHandle(File);
    return Ret;
}

/* The file is in FileDir and the current directory is CwdDir; both have a sub directory */
static void Test_Rename(void)
{
    WCHAR FullName[MAX_PATH], FileSub[MAX_PATH], CwdSub[MAX_PATH];
    HANDLE File, Root;
    BOOL Ret;

    StringCchPrintfW(FileSub, _countof(FileSub), L"%s\\sub", FileDir);
    StringCchPrintfW(CwdSub, _countof(CwdSub), L"%s\\sub", CwdDir);

    if (!WriteFileIn(FileDir, L"a.txt", "SRC"))
    {
        ok(0, "Creating the source file failed: %lu\n", GetLastError());
        return;
    }
    File = OpenFileIn(FileDir, L"a.txt", OPEN_EXISTING);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;

    /* A plain name is relative to the current directory, not to the file's directory */
    Ret = RenameTo(File, L"b.txt", FALSE, 0);
    ok(Ret, "Rename to a plain name failed: %lu\n", GetLastError());
    ok(!ExistsIn(FileDir, L"a.txt") && !ExistsIn(FileDir, L"b.txt") && ExistsIn(CwdDir, L"b.txt"),
       "Plain-name rename: a %d, b in the file's directory %d, b in the current directory %d\n",
       ExistsIn(FileDir, L"a.txt"), ExistsIn(FileDir, L"b.txt"), ExistsIn(CwdDir, L"b.txt"));

    /* A full DOS path brings the file back to its directory */
    StringCchPrintfW(FullName, _countof(FullName), L"%s\\c.txt", FileDir);
    Ret = RenameTo(File, FullName, FALSE, 0);
    ok(Ret, "Rename to a full path failed: %lu\n", GetLastError());
    ok(!ExistsIn(CwdDir, L"b.txt") && ExistsIn(FileDir, L"c.txt"), "Full-path rename did not happen\n");

    /* A relative path with a directory part is relative to the current directory too */
    Ret = RenameTo(File, L"sub\\j.txt", FALSE, 0);
    ok(Ret, "Rename to a relative path failed: %lu\n", GetLastError());
    ok(!ExistsIn(FileDir, L"c.txt") && ExistsIn(CwdSub, L"j.txt") && !ExistsIn(FileSub, L"j.txt"),
       "Relative-path rename: j in the current directory's sub %d, in the file directory's sub %d\n",
       ExistsIn(CwdSub, L"j.txt"), ExistsIn(FileSub, L"j.txt"));

    /* An NT path */
    StringCchPrintfW(FullName, _countof(FullName), L"\\??\\%s\\h.txt", FileDir);
    Ret = RenameTo(File, FullName, FALSE, 0);
    ok(Ret, "Rename to an NT path failed: %lu\n", GetLastError());
    ok(!ExistsIn(CwdSub, L"j.txt") && ExistsIn(FileDir, L"h.txt"), "NT-path rename did not happen\n");

    /* The name ends at its NUL: FileNameLength does not shorten it, odd or even */
    StringCchPrintfW(FullName, _countof(FullName), L"%s\\d.txtx", FileDir);
    Ret = RenameTo(File, FullName, FALSE, -1);
    ok(Ret, "Odd full-path length failed: %lu\n", GetLastError());
    ok(!ExistsIn(FileDir, L"h.txt") && ExistsIn(FileDir, L"d.txtx") && !ExistsIn(FileDir, L"d.txt"),
       "Odd full-path length: h %d, d.txtx %d, d.txt %d\n",
       ExistsIn(FileDir, L"h.txt"), ExistsIn(FileDir, L"d.txtx"), ExistsIn(FileDir, L"d.txt"));

    Ret = RenameTo(File, L"e.txtx", FALSE, -2);
    ok(Ret, "Short plain-name length failed: %lu\n", GetLastError());
    ok(!ExistsIn(FileDir, L"d.txtx") && ExistsIn(CwdDir, L"e.txtx") && !ExistsIn(CwdDir, L"e.txt"),
       "Short plain-name length: d %d, e.txtx %d, e.txt %d\n",
       ExistsIn(FileDir, L"d.txtx"), ExistsIn(CwdDir, L"e.txtx"), ExistsIn(CwdDir, L"e.txt"));

    Ret = RenameTo(File, L"e.txt", FALSE, -1);
    ok(Ret, "Odd plain-name length failed: %lu\n", GetLastError());
    ok(!ExistsIn(CwdDir, L"e.txtx") && ExistsIn(CwdDir, L"e.txt"),
       "Odd plain-name length: e.txtx %d, e.txt %d\n", ExistsIn(CwdDir, L"e.txtx"), ExistsIn(CwdDir, L"e.txt"));

    /* Back to the file's directory, so that the cases below can tell it from the current one */
    StringCchPrintfW(FullName, _countof(FullName), L"%s\\h.txt", FileDir);
    Ret = RenameTo(File, FullName, FALSE, 0);
    ok(Ret, "Rename back to the file's directory failed: %lu\n", GetLastError());
    ok(!ExistsIn(CwdDir, L"e.txt") && ExistsIn(FileDir, L"h.txt"), "Rename back did not happen\n");

    /* An empty name */
    SetLastError(0xdeadbeef);
    Ret = RenameTo(File, L"", FALSE, 0);
    ok(!Ret && GetLastError() == ERROR_INVALID_NAME, "Empty name: got %d, error %lu\n", Ret, GetLastError());

    /* A root directory is refused, even with a plain name */
    Root = CreateFileW(CwdDir, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(Root != INVALID_HANDLE_VALUE, "Opening the directory failed: %lu\n", GetLastError());
    if (Root != INVALID_HANDLE_VALUE)
    {
        SetLastError(0xdeadbeef);
        Ret = RenameToEx(File, Root, L"i.txt", FALSE, 0);
        ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER,
           "Root directory: got %d, error %lu\n", Ret, GetLastError());
        ok(ExistsIn(FileDir, L"h.txt") && !ExistsIn(CwdDir, L"i.txt") && !ExistsIn(FileDir, L"i.txt"),
           "Root-directory rename changed the file name\n");
        CloseHandle(Root);
    }

    /* An existing target needs ReplaceIfExists; the one in the current directory is replaced */
    ok(WriteFileIn(FileDir, L"f.txt", "AAA"), "Creating a target failed: %lu\n", GetLastError());
    ok(WriteFileIn(CwdDir, L"f.txt", "BBB"), "Creating a target failed: %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    Ret = RenameTo(File, L"f.txt", FALSE, 0);
    ok(!Ret && GetLastError() == ERROR_ALREADY_EXISTS, "Got %d, error %lu\n", Ret, GetLastError());
    ok(ExistsIn(FileDir, L"h.txt") && FileHolds(FileDir, L"f.txt", "AAA") && FileHolds(CwdDir, L"f.txt", "BBB"),
       "A refused rename changed a file\n");
    Ret = RenameTo(File, L"f.txt", TRUE, 0);
    ok(Ret, "Replacing rename failed: %lu\n", GetLastError());
    CloseHandle(File);
    ok(!ExistsIn(FileDir, L"h.txt"), "The source name is still there\n");
    ok(FileHolds(CwdDir, L"f.txt", "SRC"), "The target in the current directory was not replaced\n");
    ok(FileHolds(FileDir, L"f.txt", "AAA"), "The target in the file's directory changed\n");
}

/* A name starting with a colon renames a stream of the file */
static void Test_RenameStream(void)
{
    WCHAR Path[MAX_PATH], Volume[MAX_PATH];
    DWORD FsFlags = 0, Written = 0;
    HANDLE File;
    BOOL Ret;

    if (!GetVolumePathNameW(FileDir, Volume, _countof(Volume)) ||
        !GetVolumeInformationW(Volume, NULL, 0, NULL, NULL, &FsFlags, NULL, 0))
    {
        ok(0, "Querying the volume of %S failed: %lu\n", FileDir, GetLastError());
        return;
    }
    if (!(FsFlags & FILE_NAMED_STREAMS))
    {
        skip("No named streams on %S\n", Volume);
        return;
    }

    ok(WriteFileIn(FileDir, L"s.txt", "S"), "Creating the file failed: %lu\n", GetLastError());
    File = OpenFileIn(FileDir, L"s.txt:one", CREATE_ALWAYS);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ok(WriteFile(File, "DATA", 4, &Written, NULL) && Written == 4, "Writing the stream failed: %lu\n", GetLastError());

    Ret = RenameTo(File, L":two", FALSE, 0);
    ok(Ret, "Stream rename failed: %lu\n", GetLastError());
    /* the handle goes on with the renamed stream */
    ok(WriteFile(File, "MORE", 4, &Written, NULL) && Written == 4, "Writing after the rename failed: %lu\n", GetLastError());
    CloseHandle(File);
    ok(ExistsIn(FileDir, L"s.txt:two") && !ExistsIn(FileDir, L"s.txt:one") && !ExistsIn(CwdDir, L"two"),
       "Stream rename did not happen\n");
    ok(FileHolds(FileDir, L"s.txt:two", "DATAMORE"), "The renamed stream does not hold its data\n");
    ok(FileHolds(FileDir, L"s.txt", "S"), "The unnamed stream of the file changed\n");

    /* onto a stream that exists: without ReplaceIfExists it stays, with it it is replaced */
    ok(WriteFileIn(FileDir, L"s.txt:three", "OLD"), "Creating the second stream failed: %lu\n", GetLastError());
    File = OpenFileIn(FileDir, L"s.txt:two", OPEN_EXISTING);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        SetLastError(0xdeadbeef);
        Ret = RenameTo(File, L":three", FALSE, 0);
        ok(!Ret && (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_FILE_EXISTS),
           "Rename onto a stream without replace: %d, error %lu\n", Ret, GetLastError());
        ok(FileHolds(FileDir, L"s.txt:three", "OLD") && ExistsIn(FileDir, L"s.txt:two"),
           "A refused rename changed the streams\n");
        Ret = RenameTo(File, L":three", TRUE, 0);
        ok(Ret, "Rename onto a stream with replace failed: %lu\n", GetLastError());
        CloseHandle(File);
        ok(FileHolds(FileDir, L"s.txt:three", "DATAMORE") && !ExistsIn(FileDir, L"s.txt:two"),
           "The replace did not leave the data under the new name\n");
    }

    /* the form with the stream type */
    File = OpenFileIn(FileDir, L"s.txt:three", OPEN_EXISTING);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        Ret = RenameTo(File, L":four:$DATA", FALSE, 0);
        ok(Ret, "Rename to :four:$DATA failed: %lu\n", GetLastError());

        /* names that are no stream names; the stream stays where it is */
        SetLastError(0xdeadbeef);
        ok(!RenameTo(File, L"five", FALSE, 0), "Rename to a name without a colon worked\n");
        ok(!RenameTo(File, L":", FALSE, 0), "Rename to an empty stream name worked\n");
        ok(!RenameTo(File, L"::$DATA", FALSE, 0), "Rename to the unnamed stream worked\n");
        ok(!RenameTo(File, L":a:b", FALSE, 0), "Rename to :a:b worked\n");
        ok(!RenameTo(File, L":a\\b", FALSE, 0), "Rename to :a\\b worked\n");
        ok(!RenameTo(File, L":six", FALSE, 4000), "Rename with a name length past the buffer worked\n");
        CloseHandle(File);
        ok(FileHolds(FileDir, L"s.txt:four", "DATAMORE") && !ExistsIn(FileDir, L"s.txt:three"),
           "The stream is not where it was left\n");
    }

    StringCchPrintfW(Path, _countof(Path), L"%s\\s.txt", FileDir);
    DeleteFileW(Path);
}

static void Test_DispositionAndEndOfFile(void)
{
    TEST_END_OF_FILE_INFO EndOfFile;
    TEST_DISPOSITION_INFO Disposition;
    LARGE_INTEGER Size;
    HANDLE File;
    BOOL Ret;

    File = OpenTestFile(L"g.txt", CREATE_ALWAYS);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;

    EndOfFile.EndOfFile.QuadPart = 12345;
    Ret = pSetFileInformationByHandle(File, TestFileEndOfFileInfo, &EndOfFile, sizeof(EndOfFile));
    ok(Ret, "FileEndOfFileInfo failed: %lu\n", GetLastError());
    Size.QuadPart = 0;
    Ret = GetFileSizeEx(File, &Size);
    ok(Ret && Size.QuadPart == 12345, "GetFileSizeEx returned %d, size %I64d\n", Ret, Size.QuadPart);

    Disposition.Delete = TRUE;
    Ret = pSetFileInformationByHandle(File, TestFileDispositionInfo, &Disposition, sizeof(Disposition));
    ok(Ret, "FileDispositionInfo failed: %lu\n", GetLastError());
    CloseHandle(File);
    ok(!FileExists(L"g.txt"), "File was not deleted on close\n");

    SetLastError(0xdeadbeef);
    Ret = pSetFileInformationByHandle(INVALID_HANDLE_VALUE, TestFileStandardInfo, &Disposition, sizeof(Disposition));
    ok(!Ret && GetLastError() == ERROR_INVALID_PARAMETER, "Got %d, error %lu\n", Ret, GetLastError());

    /* the I/O priority hint is advisory: a valid one succeeds, a closed handle or an event still fails */
    File = OpenTestFile(L"g.txt", CREATE_ALWAYS);
    ok(File != INVALID_HANDLE_VALUE, "CreateFileW failed: %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        DWORD PriorityHint = 2;
        HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);

        Ret = pSetFileInformationByHandle(File, TestFileIoPriorityHintInfo, &PriorityHint, sizeof(PriorityHint));
        ok(Ret, "FileIoPriorityHintInfo failed: %lu\n", GetLastError());
        CloseHandle(File);

        SetLastError(0xdeadbeef);
        Ret = pSetFileInformationByHandle(File, TestFileIoPriorityHintInfo, &PriorityHint, sizeof(PriorityHint));
        ok(!Ret && GetLastError() == ERROR_INVALID_HANDLE, "Got %d, error %lu\n", Ret, GetLastError());

        ok(Event != NULL, "CreateEventW failed: %lu\n", GetLastError());
        if (Event)
        {
            SetLastError(0xdeadbeef);
            Ret = pSetFileInformationByHandle(Event, TestFileIoPriorityHintInfo, &PriorityHint, sizeof(PriorityHint));
            ok(!Ret, "Event: got %d, error %lu\n", Ret, GetLastError());
            CloseHandle(Event);
        }
    }
}

START_TEST(SetFileInformationByHandle)
{
    WCHAR TempPath[MAX_PATH], Path[MAX_PATH], OldCwd[MAX_PATH];
    static const PCWSTR Names[] = { L"a.txt", L"b.txt", L"c.txt", L"d.txt", L"d.txtx", L"e.txt", L"e.txtx",
                                    L"e.tx", L"f.txt", L"g.txt", L"h.txt", L"i.txt", L"s.txt", L"two",
                                    L"sub\\j.txt" };
    WCHAR Dirs[3][MAX_PATH];
    DWORD Length;
    ULONG i, j;

    pSetFileInformationByHandle = (FN_SetFileInformationByHandle)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetFileInformationByHandle");
    if (!pSetFileInformationByHandle)
    {
        skip("SetFileInformationByHandle is not available\n");
        return;
    }

    GetTempPathW(_countof(TempPath), TempPath);
    StringCchPrintfW(TestDir, _countof(TestDir), L"%sSetFileInfoByHandle%lu", TempPath, GetCurrentProcessId());
    StringCchPrintfW(FileDir, _countof(FileDir), L"%s\\file", TestDir);
    StringCchPrintfW(CwdDir, _countof(CwdDir), L"%s\\cwd", TestDir);
    StringCchCopyW(Dirs[0], MAX_PATH, FileDir);
    StringCchCopyW(Dirs[1], MAX_PATH, CwdDir);
    StringCchCopyW(Dirs[2], MAX_PATH, TestDir);

    ok(CreateDirectoryW(TestDir, NULL), "CreateDirectoryW failed: %lu\n", GetLastError());
    for (j = 0; j < 2; j++)
    {
        ok(CreateDirectoryW(Dirs[j], NULL), "CreateDirectoryW failed: %lu\n", GetLastError());
        StringCchPrintfW(Path, _countof(Path), L"%s\\sub", Dirs[j]);
        ok(CreateDirectoryW(Path, NULL), "CreateDirectoryW failed: %lu\n", GetLastError());
    }

    /* Plain names land in the current directory, so the rename tests only run inside the test's own */
    Length = GetCurrentDirectoryW(_countof(OldCwd), OldCwd);
    if (!Length || Length >= _countof(OldCwd))
        skip("Cannot save the current directory (%lu)\n", Length);
    else if (!SetCurrentDirectoryW(CwdDir))
        ok(0, "SetCurrentDirectoryW failed: %lu\n", GetLastError());
    else
    {
        Test_Rename();
        Test_RenameStream();
        ok(SetCurrentDirectoryW(OldCwd), "Restoring the current directory failed: %lu\n", GetLastError());
    }

    Test_DispositionAndEndOfFile();

    for (j = 0; j < _countof(Dirs); j++)
    {
        for (i = 0; i < _countof(Names); i++)
        {
            StringCchPrintfW(Path, _countof(Path), L"%s\\%s", Dirs[j], Names[i]);
            DeleteFileW(Path);
        }
        if (j < 2)
        {
            StringCchPrintfW(Path, _countof(Path), L"%s\\sub", Dirs[j]);
            RemoveDirectoryW(Path);
            RemoveDirectoryW(Dirs[j]);
        }
    }
    ok(RemoveDirectoryW(TestDir), "Removing the test directory failed: %lu\n", GetLastError());
}
