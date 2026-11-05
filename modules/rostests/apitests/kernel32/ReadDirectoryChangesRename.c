/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ReadDirectoryChangesW: create / rename / delete sequences, as a file manager (the shell's
 *              desktop) sees them. Every change has to arrive, in order, a rename as an OLD_NAME record
 *              directly followed by its NEW_NAME record, and the records of one read have to be linked
 *              by NextEntryOffset up to the last returned byte. Changes made while no read is pending
 *              are returned by the next read, also when an earlier read took buffered changes.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define MAX_RECORDS 64
#define NAME_CHARS  16

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

static WCHAR TestDir[MAX_PATH];
static HANDLE DirHandle;
static HANDLE ReadEvent;
static OVERLAPPED ReadOverlapped;
static ULONGLONG NotifyBuffer[512];   /* 4 KB, DWORD aligned */
static RECORD Records[MAX_RECORDS];
static int RecordCount;
static int LinkErrors;                /* reads whose records did not cover the returned bytes */
static int Overflows;                 /* reads that returned STATUS_NOTIFY_ENUM_DIR (0 bytes) */

static
PWSTR
PathOf(_Out_writes_(MAX_PATH) PWSTR Buffer, _In_ PCWSTR Name)
{
    wcscpy(Buffer, TestDir);
    wcscat(Buffer, L"\\");
    wcscat(Buffer, Name);
    return Buffer;
}

static
BOOL
Arm(VOID)
{
    ResetEvent(ReadEvent);
    RtlZeroMemory(&ReadOverlapped, sizeof(ReadOverlapped));
    ReadOverlapped.hEvent = ReadEvent;
    RtlFillMemory(NotifyBuffer, sizeof(NotifyBuffer), 0xCC);
    return ReadDirectoryChangesW(DirHandle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                 FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
                                 FILE_NOTIFY_CHANGE_CREATION, NULL, &ReadOverlapped, NULL);
}

/* Appends the records of the read that returned Bytes; MODIFIED is not kept: file systems differ in it. */
static
VOID
TakeRecords(_In_ DWORD Bytes)
{
    DWORD Offset = 0, EndOfLast = 0;
    FILE_NOTIFY_INFORMATION *Info;

    if (Bytes == 0)
    {
        Overflows++;
        return;
    }
    for (;;)
    {
        Info = (FILE_NOTIFY_INFORMATION *)((PUCHAR)NotifyBuffer + Offset);
        EndOfLast = Offset + FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) + Info->FileNameLength;
        if (EndOfLast > Bytes)
        {
            LinkErrors++;
            return;
        }
        if (Info->Action != FILE_ACTION_MODIFIED && RecordCount < MAX_RECORDS)
        {
            RECORD *Rec = &Records[RecordCount++];
            Rec->Action = Info->Action;
            RtlZeroMemory(Rec->Name, sizeof(Rec->Name));
            RtlCopyMemory(Rec->Name, Info->FileName,
                          min(Info->FileNameLength, (NAME_CHARS - 1) * sizeof(WCHAR)));
        }
        if (Info->NextEntryOffset == 0)
            break;
        Offset += Info->NextEntryOffset;
    }
    /* what follows the last linked record would be changes the reader can never see */
    if (((EndOfLast + 3) & ~3UL) < Bytes)
        LinkErrors++;
}

/* Reads until nothing comes for a while, then leaves no read pending (changes made after are buffered). */
static
VOID
Drain(_In_ BOOL AlreadyArmed)
{
    DWORD Bytes, Wait = 3000;
    BOOL Armed = AlreadyArmed;

    RecordCount = 0;
    LinkErrors = 0;
    Overflows = 0;
    for (;;)
    {
        if (!Armed)
        {
            if (!Arm())
            {
                ok(0, "ReadDirectoryChangesW failed: %lu\n", GetLastError());
                return;
            }
        }
        Armed = TRUE;
        if (WaitForSingleObject(ReadEvent, Wait) != WAIT_OBJECT_0)
            break;
        Armed = FALSE;
        ok(GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, FALSE),
           "GetOverlappedResult failed: %lu\n", GetLastError());
        TakeRecords(Bytes);
        Wait = 400;
    }
    CancelIo(DirHandle);
    GetOverlappedResult(DirHandle, &ReadOverlapped, &Bytes, TRUE);
}

static
VOID
Check(_In_ PCSTR Label, _In_reads_(Count) const EXPECT *Expected, _In_ int Count)
{
    int i;

    ok(LinkErrors == 0, "%s: %d reads with records that do not cover the returned bytes\n", Label, LinkErrors);
    ok(Overflows == 0, "%s: %d reads overflowed\n", Label, Overflows);
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

static
VOID
Create(_In_ PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    HANDLE Handle = CreateFileW(PathOf(Path, Name), GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "create %ls failed: %lu\n", Name, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);
}

static
VOID
Rename(_In_ PCWSTR From, _In_ PCWSTR To)
{
    WCHAR Path1[MAX_PATH], Path2[MAX_PATH];
    ok(MoveFileW(PathOf(Path1, From), PathOf(Path2, To)), "rename %ls to %ls failed: %lu\n", From, To, GetLastError());
}

static
VOID
Delete(_In_ PCWSTR Name)
{
    WCHAR Path[MAX_PATH];
    ok(DeleteFileW(PathOf(Path, Name)), "delete %ls failed: %lu\n", Name, GetLastError());
}

/* A rename made by another process (cmd.exe), as the user does it. */
static
VOID
RenameByCmd(_In_ PCWSTR From, _In_ PCWSTR To)
{
    WCHAR Command[2 * MAX_PATH + 32] = L"", Path[MAX_PATH];
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    BOOL Ok;

    _snwprintf(Command, RTL_NUMBER_OF(Command) - 1, L"cmd.exe /c ren \"%ls\" \"%ls\"", PathOf(Path, From), To);
    Ok = CreateProcessW(NULL, Command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &Startup, &Process);
    ok(Ok, "cmd failed to start: %lu\n", GetLastError());
    if (Ok)
    {
        WaitForSingleObject(Process.hProcess, 30000);
        CloseHandle(Process.hProcess);
        CloseHandle(Process.hThread);
    }
}

START_TEST(ReadDirectoryChangesRename)
{
    /* armed: the watcher is waiting while the change is made */
    static const EXPECT ArmedCreate[] = { { FILE_ACTION_ADDED, L"a.txt" } };
    static const EXPECT ArmedRename[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"a.txt" },
                                          { FILE_ACTION_RENAMED_NEW_NAME, L"b.txt" } };
    static const EXPECT ArmedCmdRename[] = { { FILE_ACTION_RENAMED_OLD_NAME, L"b.txt" },
                                             { FILE_ACTION_RENAMED_NEW_NAME, L"c.txt" } };
    static const EXPECT ArmedDelete[] = { { FILE_ACTION_REMOVED, L"c.txt" } };
    /* buffered: changes made while no read is pending */
    static const EXPECT Buffered[] =
    {
        { FILE_ACTION_ADDED, L"c1.txt" },
        { FILE_ACTION_RENAMED_OLD_NAME, L"c1.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"d1.txt" },
        { FILE_ACTION_ADDED, L"e1.txt" },
        { FILE_ACTION_RENAMED_OLD_NAME, L"e1.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"f1.txt" },
        { FILE_ACTION_REMOVED, L"d1.txt" }, { FILE_ACTION_REMOVED, L"f1.txt" },
    };
    /* buffered changes taken by a read, then more buffered changes */
    static const EXPECT PhaseOne[] = { { FILE_ACTION_ADDED, L"g.txt" }, { FILE_ACTION_ADDED, L"h.txt" },
                                       { FILE_ACTION_ADDED, L"i.txt" } };
    static const EXPECT PhaseTwo[] =
    {
        { FILE_ACTION_RENAMED_OLD_NAME, L"g.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"g2.txt" },
        { FILE_ACTION_RENAMED_OLD_NAME, L"h.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"h2.txt" },
        { FILE_ACTION_RENAMED_OLD_NAME, L"i.txt" }, { FILE_ACTION_RENAMED_NEW_NAME, L"i2.txt" },
        { FILE_ACTION_REMOVED, L"g2.txt" }, { FILE_ACTION_REMOVED, L"h2.txt" }, { FILE_ACTION_REMOVED, L"i2.txt" },
    };
    int Round;

    GetTempPathW(RTL_NUMBER_OF(TestDir), TestDir);
    wcscat(TestDir, L"RdcRenameTest");
    CreateDirectoryW(TestDir, NULL);
    DirHandle = CreateFileW(TestDir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    ok(DirHandle != INVALID_HANDLE_VALUE, "open of %ls failed: %lu\n", TestDir, GetLastError());
    if (DirHandle == INVALID_HANDLE_VALUE)
    {
        skip("no directory to watch\n");
        return;
    }
    ReadEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* armed create, rename (in this process and by cmd), delete */
    ok(Arm(), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
    Create(L"a.txt");
    Drain(TRUE);
    Check("armed create", ArmedCreate, RTL_NUMBER_OF(ArmedCreate));

    Rename(L"a.txt", L"b.txt");     /* no read is pending: this one is buffered */
    Drain(FALSE);
    Check("rename", ArmedRename, RTL_NUMBER_OF(ArmedRename));

    ok(Arm(), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
    RenameByCmd(L"b.txt", L"c.txt");
    Drain(TRUE);
    Check("rename by cmd", ArmedCmdRename, RTL_NUMBER_OF(ArmedCmdRename));

    ok(Arm(), "ReadDirectoryChangesW failed: %lu\n", GetLastError());
    Delete(L"c.txt");
    Drain(TRUE);
    Check("delete", ArmedDelete, RTL_NUMBER_OF(ArmedDelete));

    /* many changes while nobody reads, then one read */
    Create(L"c1.txt");
    Rename(L"c1.txt", L"d1.txt");
    Create(L"e1.txt");
    Rename(L"e1.txt", L"f1.txt");
    Delete(L"d1.txt");
    Delete(L"f1.txt");
    Drain(FALSE);
    Check("buffered sequence", Buffered, RTL_NUMBER_OF(Buffered));

    /* a read takes buffered changes, more are made, the next read has to return all of them */
    for (Round = 0; Round < 3; Round++)
    {
        Create(L"g.txt");
        Create(L"h.txt");
        Create(L"i.txt");
        Drain(FALSE);
        Check("buffered, first read", PhaseOne, RTL_NUMBER_OF(PhaseOne));

        Rename(L"g.txt", L"g2.txt");
        Rename(L"h.txt", L"h2.txt");
        Rename(L"i.txt", L"i2.txt");
        Delete(L"g2.txt");
        Delete(L"h2.txt");
        Delete(L"i2.txt");
        Drain(FALSE);
        Check("buffered, second read", PhaseTwo, RTL_NUMBER_OF(PhaseTwo));
    }

    CloseHandle(ReadEvent);
    CloseHandle(DirHandle);
    RemoveDirectoryW(TestDir);
}
