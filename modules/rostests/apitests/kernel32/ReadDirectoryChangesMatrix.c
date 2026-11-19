/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ReadDirectoryChangesW: every FILE_NOTIFY_CHANGE_* filter against the operations that do and do not
 *              match it, with and without the subtree flag, rename old/new name pairs, and the overflow of the
 *              buffer (STATUS_NOTIFY_ENUM_DIR: the read returns TRUE with 0 bytes). The expectations are the
 *              documented ones of ReadDirectoryChangesW; every file system has to agree (FAT == NTFS).
 *              Every cell watches through a directory handle of its own and makes its change while its read is
 *              pending, so the changes of one cell cannot be returned to the read of the next.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define MAX_RECORDS 32
#define NAME_CHARS  48

#ifndef FILE_NOTIFY_CHANGE_CREATION
#define FILE_NOTIFY_CHANGE_CREATION 0x00000040
#endif

typedef struct _RECORD
{
    DWORD Action;
    WCHAR Name[NAME_CHARS];
} RECORD;

typedef struct _EXPECT
{
    DWORD Action;
    PCWSTR Name;
} EXPECT;

typedef VOID (*OPERATION)(VOID);

static WCHAR TestDir[MAX_PATH];
static HANDLE DirHandle;
static HANDLE ReadEvent;
static OVERLAPPED ReadOverlapped;
static ULONGLONG NotifyBuffer[512];
static RECORD Records[MAX_RECORDS];
static int RecordCount;
static int Overflows;

static
PWSTR
PathOf(_Out_writes_(MAX_PATH) PWSTR Buffer, _In_ PCWSTR Name)
{
    wcscpy(Buffer, TestDir);
    wcscat(Buffer, L"\\");
    wcscat(Buffer, Name);
    return Buffer;
}

/* The filter and the subtree flag are those of the first read made through a handle: every cell opens its own. */
static
BOOL
OpenDir(VOID)
{
    DirHandle = CreateFileW(TestDir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    ok(DirHandle != INVALID_HANDLE_VALUE, "open of %ls failed: %lu\n", TestDir, GetLastError());
    return DirHandle != INVALID_HANDLE_VALUE;
}

static
VOID
CloseDir(VOID)
{
    CloseHandle(DirHandle);
    DirHandle = INVALID_HANDLE_VALUE;
}

static
BOOL
Arm(_In_ DWORD Filter, _In_ BOOL Subtree, _In_ DWORD Size)
{
    ResetEvent(ReadEvent);
    RtlZeroMemory(&ReadOverlapped, sizeof(ReadOverlapped));
    ReadOverlapped.hEvent = ReadEvent;
    return ReadDirectoryChangesW(DirHandle, NotifyBuffer, Size, Subtree, Filter, NULL, &ReadOverlapped, NULL);
}

/* Appends the records of a read; a record identical to the one before it is kept once (how often a modification
   is reported differs between a write and the close that follows it). */
static
VOID
TakeRecords(_In_ DWORD Bytes)
{
    DWORD Offset = 0;
    FILE_NOTIFY_INFORMATION *Info;

    if (Bytes == 0)
    {
        Overflows++;
        return;
    }
    for (;;)
    {
        RECORD Rec;

        Info = (FILE_NOTIFY_INFORMATION *)((PUCHAR)NotifyBuffer + Offset);
        if (Offset + FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) + Info->FileNameLength > Bytes)
            break;
        Rec.Action = Info->Action;
        RtlZeroMemory(Rec.Name, sizeof(Rec.Name));
        RtlCopyMemory(Rec.Name, Info->FileName, min(Info->FileNameLength, (NAME_CHARS - 1) * sizeof(WCHAR)));
        if (RecordCount == 0 || Records[RecordCount - 1].Action != Rec.Action ||
            _wcsicmp(Records[RecordCount - 1].Name, Rec.Name))
        {
            if (RecordCount < MAX_RECORDS)
                Records[RecordCount++] = Rec;
        }
        if (Info->NextEntryOffset == 0)
            break;
        Offset += Info->NextEntryOffset;
    }
}

/* Takes what the pending read returns and what the reads after it return, until nothing comes for a while. */
static
VOID
Collect(_In_ DWORD FirstWaitMs, _In_ DWORD Filter, _In_ BOOL Subtree)
{
    DWORD Bytes, Wait = FirstWaitMs;

    for (;;)
    {
        if (WaitForSingleObject(ReadEvent, Wait) != WAIT_OBJECT_0)
            break;
        if (GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, FALSE))
            TakeRecords(Bytes);
        Wait = 300;
        if (!Arm(Filter, Subtree, sizeof(NotifyBuffer)))
            return;
    }
    CancelIo(DirHandle);
    GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, TRUE);
}

/* One cell: the watcher is armed with Filter and Subtree, Operation runs, and what arrives has to be Expected
   (nothing when Count is 0: the wait is shorter then). */
static
VOID
Cell(
    _In_ PCSTR Label,
    _In_ DWORD Filter,
    _In_ BOOL Subtree,
    _In_ OPERATION Operation,
    _In_reads_opt_(Count) const EXPECT *Expected,
    _In_ int Count)
{
    int i;

    RecordCount = 0;
    Overflows = 0;
    if (!OpenDir())
        return;
    if (!Arm(Filter, Subtree, sizeof(NotifyBuffer)))
    {
        ok(0, "%s: ReadDirectoryChangesW failed: %lu\n", Label, GetLastError());
        CloseDir();
        return;
    }
    Operation();
    Collect(Count ? 3000 : 700, Filter, Subtree);
    CloseDir();

    ok(Overflows == 0, "%s: overflow\n", Label);
    ok(RecordCount == Count, "%s: %d records, expected %d\n", Label, RecordCount, Count);
    for (i = 0; i < Count && i < RecordCount; i++)
    {
        ok(Records[i].Action == Expected[i].Action && !_wcsicmp(Records[i].Name, Expected[i].Name),
           "%s: record %d is action %lu '%ls', expected %lu '%ls'\n", Label, i,
           Records[i].Action, Records[i].Name, Expected[i].Action, Expected[i].Name);
    }
    for (; i < RecordCount; i++)
        trace("%s: extra record %d: action %lu '%ls'\n", Label, i, Records[i].Action, Records[i].Name);
}

/* OPERATIONS ***************************************************************/

static
VOID
MakeFile(_In_ PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle = CreateFileW(PathOf(Path, Name), GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);

    ok(Handle != INVALID_HANDLE_VALUE, "create %ls failed: %lu\n", Name, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);
}

static
VOID
Move(_In_ PCWSTR From, _In_ PCWSTR To)
{
    WCHAR Path1[MAX_PATH], Path2[MAX_PATH];

    ok(MoveFileW(PathOf(Path1, From), PathOf(Path2, To)), "move %ls to %ls failed: %lu\n", From, To, GetLastError());
}

static
VOID
Remove(_In_ PCWSTR Name)
{
    WCHAR Path[MAX_PATH];

    ok(DeleteFileW(PathOf(Path, Name)), "delete %ls failed: %lu\n", Name, GetLastError());
}

static VOID OpCreateFile(VOID)      { MakeFile(L"n1.txt"); }
static VOID OpRenameFile(VOID)      { Move(L"n1.txt", L"n2.txt"); }
static VOID OpRenameFileBack(VOID)  { Move(L"n2.txt", L"n1.txt"); }
static VOID OpRenameFileCase(VOID)  { Move(L"n1.txt", L"N1.TXT"); }
static VOID OpDeleteFile(VOID)      { Remove(L"N1.TXT"); }
static VOID OpCreateDir(VOID)       { WCHAR P[MAX_PATH]; ok(CreateDirectoryW(PathOf(P, L"d1"), NULL), "mkdir: %lu\n", GetLastError()); }
static VOID OpRenameDir(VOID)       { Move(L"d1", L"d2"); }
static VOID OpRenameDirBack(VOID)   { Move(L"d2", L"d1"); }
static VOID OpDeleteDir(VOID)       { WCHAR P[MAX_PATH]; ok(RemoveDirectoryW(PathOf(P, L"d1")), "rmdir: %lu\n", GetLastError()); }
static VOID OpCreateInSub(VOID)     { MakeFile(L"sub\\s1.txt"); }
static VOID OpRenameInSub(VOID)     { Move(L"sub\\s1.txt", L"sub\\s2.txt"); }
static VOID OpDeleteInSub(VOID)     { Remove(L"sub\\s2.txt"); }
static VOID OpDeleteInSub1(VOID)    { Remove(L"sub\\s1.txt"); }
static VOID OpMoveIntoSub(VOID)     { Move(L"m1.txt", L"sub\\m1.txt"); }
static VOID OpMoveOutOfSub(VOID)    { Move(L"sub\\m1.txt", L"m1.txt"); }

static
VOID
SetAttributes(_In_ PCWSTR Name)
{
    WCHAR P[MAX_PATH];

    ok(SetFileAttributesW(PathOf(P, Name), FILE_ATTRIBUTE_HIDDEN), "setattr: %lu\n", GetLastError());
    ok(SetFileAttributesW(PathOf(P, Name), FILE_ATTRIBUTE_NORMAL), "setattr: %lu\n", GetLastError());
}

static VOID OpSetAttributes(VOID)   { SetAttributes(L"base.txt"); }
static VOID OpAttributesInSub(VOID) { SetAttributes(L"sub\\inner.txt"); }

static
VOID
SetTime(_In_ PCWSTR Name, _In_ BOOL Creation, _In_ BOOL Access, _In_ BOOL Write)
{
    WCHAR P[MAX_PATH];
    FILETIME Time;
    SYSTEMTIME System = { 2020, 5, 3, 13, 10, 20, 30, 0 };
    HANDLE Handle = CreateFileW(PathOf(P, Name), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    ok(Handle != INVALID_HANDLE_VALUE, "open %ls failed: %lu\n", Name, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    SystemTimeToFileTime(&System, &Time);
    ok(SetFileTime(Handle, Creation ? &Time : NULL, Access ? &Time : NULL, Write ? &Time : NULL),
       "SetFileTime failed: %lu\n", GetLastError());
    CloseHandle(Handle);
}

static VOID OpSetWriteTime(VOID)    { SetTime(L"base.txt", FALSE, FALSE, TRUE); }
static VOID OpSetAccessTime(VOID)   { SetTime(L"base.txt", FALSE, TRUE, FALSE); }
static VOID OpSetCreationTime(VOID) { SetTime(L"base.txt", TRUE, FALSE, FALSE); }
static VOID OpSetTimeInSub(VOID)    { SetTime(L"sub\\inner.txt", FALSE, FALSE, TRUE); }

static
VOID
OpGrowFile(VOID)
{
    WCHAR P[MAX_PATH];
    CHAR Data[512] = { 0 };
    DWORD Written;
    HANDLE Handle = CreateFileW(PathOf(P, L"grow.txt"), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    ok(Handle != INVALID_HANDLE_VALUE, "open grow.txt failed: %lu\n", GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    SetFilePointer(Handle, 0, NULL, FILE_END);
    ok(WriteFile(Handle, Data, sizeof(Data), &Written, NULL), "write failed: %lu\n", GetLastError());
    CloseHandle(Handle);
}

/* TESTS ********************************************************************/

static
VOID
TestNames(VOID)
{
    static const EXPECT Added[] = { { FILE_ACTION_ADDED, L"n1.txt" } };
    static const EXPECT Rename[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"n1.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"n2.txt" } };
    static const EXPECT RenameBack[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"n2.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"n1.txt" } };
    static const EXPECT RenameCase[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"n1.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"N1.TXT" } };
    static const EXPECT Removed[] = { { FILE_ACTION_REMOVED, L"N1.TXT" } };
    static const EXPECT AddedDir[] = { { FILE_ACTION_ADDED, L"d1" } };
    static const EXPECT RenameDir[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"d1" }, { FILE_ACTION_RENAMED_NEW_NAME, L"d2" } };
    static const EXPECT RenameDirBack[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"d2" }, { FILE_ACTION_RENAMED_NEW_NAME, L"d1" } };
    static const EXPECT RemovedDir[] = { { FILE_ACTION_REMOVED, L"d1" } };

    /* file names are FILE_NAME, directory names are DIR_NAME: the other filter sees nothing */
    Cell("create file, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpCreateFile, Added, 1);
    Cell("create directory, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpCreateDir, NULL, 0);
    Cell("rename file, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpRenameFile, NULL, 0);
    Cell("rename file back, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpRenameFileBack, RenameBack, 2);
    Cell("rename file, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpRenameFile, Rename, 2);
    Cell("rename file back again, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpRenameFileBack, RenameBack, 2);
    Cell("rename file, case only", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpRenameFileCase, RenameCase, 2);
    Cell("rename directory, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpRenameDir, NULL, 0);
    Cell("rename directory back, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpRenameDirBack, RenameDirBack, 2);
    Cell("rename directory, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpRenameDir, RenameDir, 2);
    Cell("rename directory back again, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpRenameDirBack, RenameDirBack, 2);
    Cell("remove directory, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpDeleteDir, NULL, 0);
    Cell("create directory, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpCreateDir, AddedDir, 1);
    Cell("remove directory, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpDeleteDir, RemovedDir, 1);
    Cell("delete file, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpDeleteFile, Removed, 1);
}

static
VOID
TestAttributesAndTimes(VOID)
{
    static const EXPECT Modified[] = { { FILE_ACTION_MODIFIED, L"base.txt" } };

    /* a change reports a modification of the file to the filter of what changed; the others see nothing */
    Cell("attributes, ATTRIBUTES", FILE_NOTIFY_CHANGE_ATTRIBUTES, FALSE, OpSetAttributes, Modified, 1);
    Cell("attributes, LAST_WRITE", FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE, OpSetAttributes, NULL, 0);
    Cell("attributes, SIZE", FILE_NOTIFY_CHANGE_SIZE, FALSE, OpSetAttributes, NULL, 0);
    Cell("attributes, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpSetAttributes, NULL, 0);
    Cell("attributes, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpSetAttributes, NULL, 0);
    Cell("write time, LAST_WRITE", FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE, OpSetWriteTime, Modified, 1);
    Cell("write time, ATTRIBUTES", FILE_NOTIFY_CHANGE_ATTRIBUTES, FALSE, OpSetWriteTime, NULL, 0);
    Cell("write time, SIZE", FILE_NOTIFY_CHANGE_SIZE, FALSE, OpSetWriteTime, NULL, 0);
    Cell("write time, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpSetWriteTime, NULL, 0);
    Cell("access time, LAST_ACCESS", FILE_NOTIFY_CHANGE_LAST_ACCESS, FALSE, OpSetAccessTime, Modified, 1);
    Cell("access time, LAST_WRITE", FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE, OpSetAccessTime, NULL, 0);
    Cell("creation time, CREATION", FILE_NOTIFY_CHANGE_CREATION, FALSE, OpSetCreationTime, Modified, 1);
    Cell("creation time, LAST_WRITE", FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE, OpSetCreationTime, NULL, 0);
}

static
VOID
TestSize(VOID)
{
    static const EXPECT Grown[] = { { FILE_ACTION_MODIFIED, L"grow.txt" } };

    /* a write that extends the file (reported at the latest when the handle is closed) */
    Cell("grow, SIZE", FILE_NOTIFY_CHANGE_SIZE, FALSE, OpGrowFile, Grown, 1);
    Cell("grow, LAST_WRITE", FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE, OpGrowFile, Grown, 1);
    Cell("grow, FILE_NAME", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpGrowFile, NULL, 0);
    Cell("grow, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, FALSE, OpGrowFile, NULL, 0);
}

static
VOID
TestSubtree(VOID)
{
    static const EXPECT Added[] = { { FILE_ACTION_ADDED, L"sub\\s1.txt" } };
    static const EXPECT Rename[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"sub\\s1.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"sub\\s2.txt" } };
    static const EXPECT Removed[] = { { FILE_ACTION_REMOVED, L"sub\\s2.txt" } };
    static const EXPECT Modified[] = { { FILE_ACTION_MODIFIED, L"sub\\inner.txt" } };
    static const EXPECT MovedIn[] = { { FILE_ACTION_REMOVED, L"m1.txt" }, { FILE_ACTION_ADDED, L"sub\\m1.txt" } };
    static const EXPECT MovedOut[] = { { FILE_ACTION_REMOVED, L"sub\\m1.txt" }, { FILE_ACTION_ADDED, L"m1.txt" } };

    /* without the subtree flag a change in a subdirectory is not reported */
    Cell("create in sub, no subtree", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpCreateInSub, NULL, 0);
    Cell("rename in sub, no subtree", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpRenameInSub, NULL, 0);
    Cell("delete in sub, no subtree", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpDeleteInSub, NULL, 0);
    Cell("attributes in sub, no subtree", FILE_NOTIFY_CHANGE_ATTRIBUTES, FALSE, OpAttributesInSub, NULL, 0);
    Cell("write time in sub, no subtree", FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE, OpSetTimeInSub, NULL, 0);

    /* with it, the names are relative to the watched directory */
    Cell("create in sub, subtree, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, TRUE, OpCreateInSub, NULL, 0);
    Cell("rename in sub, subtree", FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, OpRenameInSub, Rename, 2);
    Cell("delete in sub, subtree", FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, OpDeleteInSub, Removed, 1);
    Cell("create in sub, subtree", FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, OpCreateInSub, Added, 1);
    Cell("delete in sub, subtree, DIR_NAME", FILE_NOTIFY_CHANGE_DIR_NAME, TRUE, OpDeleteInSub1, NULL, 0);
    Cell("attributes in sub, subtree", FILE_NOTIFY_CHANGE_ATTRIBUTES, TRUE, OpAttributesInSub, Modified, 1);
    Cell("write time in sub, subtree", FILE_NOTIFY_CHANGE_LAST_WRITE, TRUE, OpSetTimeInSub, Modified, 1);

    /* a move from one directory to another is a removal from the old one and an addition to the new one
       (only a rename inside one directory is an old name / new name pair) */
    Cell("move into sub, subtree", FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, OpMoveIntoSub, MovedIn, 2);
    Cell("move out of sub, subtree", FILE_NOTIFY_CHANGE_FILE_NAME, TRUE, OpMoveOutOfSub, MovedOut, 2);
}

/*
 * The first change of a handle completes its pending read. While no read is pending the changes are kept; more
 * than the buffer of the last read holds are not kept, and the next read returns TRUE with 0 bytes
 * (STATUS_NOTIFY_ENUM_DIR).
 */
static
VOID
Overflow(VOID)
{
    static const DWORD Small = 96;      /* room for two or three records of the names below */
    WCHAR Name[40], Path[MAX_PATH];
    DWORD Bytes = 0xdead;
    int i;

    if (!OpenDir())
        return;
    ok(Arm(FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, Small), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
    MakeFile(L"overflow-00.txt");
    ok(WaitForSingleObject(ReadEvent, 3000) == WAIT_OBJECT_0, "the first change was not reported\n");
    ok(GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, FALSE) && Bytes > 0,
       "the first change: %lu bytes, error %lu\n", Bytes, GetLastError());

    for (i = 1; i < 12; i++)
    {
        _snwprintf(Name, RTL_NUMBER_OF(Name), L"overflow-%02d.txt", i);
        MakeFile(Name);
    }
    Bytes = 0xdead;
    ok(Arm(FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, Small), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
    ok(WaitForSingleObject(ReadEvent, 3000) == WAIT_OBJECT_0, "the read after the overflow did not complete\n");
    ok(GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, FALSE), "GetOverlappedResult failed: %lu\n", GetLastError());
    ok(Bytes == 0, "the overflow returned %lu bytes\n", Bytes);

    for (i = 0; i < 12; i++)
    {
        _snwprintf(Name, RTL_NUMBER_OF(Name), L"overflow-%02d.txt", i);
        ok(DeleteFileW(PathOf(Path, Name)), "delete %ls failed: %lu\n", Name, GetLastError());
    }
    Bytes = 0xdead;
    ok(Arm(FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, Small), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
    ok(WaitForSingleObject(ReadEvent, 3000) == WAIT_OBJECT_0, "the read after the overflow did not complete\n");
    ok(GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, FALSE), "GetOverlappedResult failed: %lu\n", GetLastError());
    ok(Bytes == 0, "the overflow of the deletes returned %lu bytes\n", Bytes);
    CloseDir();
}

static
VOID
TestOverflow(VOID)
{
    static const EXPECT Added[] = { { FILE_ACTION_ADDED, L"n1.txt" } };
    DWORD Bytes = 0xdead;

    /* a change that does not fit into the buffer by itself: 0 bytes, TRUE */
    if (OpenDir())
    {
        ok(Arm(FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, 16), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
        MakeFile(L"a-name-longer-than-the-buffer.txt");
        ok(WaitForSingleObject(ReadEvent, 3000) == WAIT_OBJECT_0, "the read did not complete\n");
        ok(GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, FALSE), "GetOverlappedResult failed: %lu\n", GetLastError());
        ok(Bytes == 0, "a change that does not fit returned %lu bytes\n", Bytes);
        CloseDir();
        Remove(L"a-name-longer-than-the-buffer.txt");
    }

    /* many changes while nobody reads */
    Overflow();

    /* after an overflow the changes come by name again */
    Cell("create file after the overflow", FILE_NOTIFY_CHANGE_FILE_NAME, FALSE, OpCreateFile, Added, 1);
}

/* Removes what a run (also one that stopped half way) leaves behind. */
static
VOID
CleanUp(VOID)
{
    static const PCWSTR Files[] =
    {
        L"base.txt", L"grow.txt", L"m1.txt", L"sub\\m1.txt", L"sub\\inner.txt", L"sub\\s1.txt", L"sub\\s2.txt",
        L"n1.txt", L"n2.txt", L"N1.TXT", L"a-name-longer-than-the-buffer.txt"
    };
    WCHAR Path[MAX_PATH];
    int i;

    for (i = 0; i < RTL_NUMBER_OF(Files); i++)
        DeleteFileW(PathOf(Path, Files[i]));
    for (i = 0; i < 12; i++)
    {
        WCHAR Name[40];

        _snwprintf(Name, RTL_NUMBER_OF(Name), L"overflow-%02d.txt", i);
        DeleteFileW(PathOf(Path, Name));
    }
    RemoveDirectoryW(PathOf(Path, L"d1"));
    RemoveDirectoryW(PathOf(Path, L"d2"));
    RemoveDirectoryW(PathOf(Path, L"sub"));
    RemoveDirectoryW(TestDir);
}

START_TEST(ReadDirectoryChangesMatrix)
{
    WCHAR Path[MAX_PATH];

    GetTempPathW(RTL_NUMBER_OF(TestDir), TestDir);
    wcscat(TestDir, L"RdcMatrixTest");
    CleanUp();
    CreateDirectoryW(TestDir, NULL);
    CreateDirectoryW(PathOf(Path, L"sub"), NULL);
    MakeFile(L"base.txt");
    MakeFile(L"grow.txt");
    MakeFile(L"m1.txt");
    MakeFile(L"sub\\inner.txt");

    ReadEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    TestNames();
    TestAttributesAndTimes();
    TestSize();
    TestSubtree();
    TestOverflow();

    CloseHandle(ReadEvent);
    CleanUp();
}
