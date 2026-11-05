/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: directory change notification across a rename of the watched directory, and
 *              the cost of many / long-path registrations (contract test: every report that is
 *              delivered names exactly the changed file, within the returned bytes)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define NOTIFY_BUFFER 4096
#define MANY_WATCHERS 256

typedef struct _WATCH
{
    HANDLE Dir;
    HANDLE Event;
    OVERLAPPED Ov;
    BYTE Buffer[NOTIFY_BUFFER];
} WATCH;

static BOOLEAN OpenWatch(WATCH *W, PCWSTR Path)
{
    RtlZeroMemory(W, sizeof(*W));
    W->Dir = CreateFileW(Path, FILE_LIST_DIRECTORY, SHARE_ALL, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (W->Dir == INVALID_HANDLE_VALUE)
    {
        W->Dir = NULL;
        return FALSE;
    }
    W->Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    return W->Event != NULL;
}

static VOID CloseWatch(WATCH *W)
{
    if (W->Dir)
        CloseHandle(W->Dir);
    if (W->Event)
        CloseHandle(W->Event);
    W->Dir = W->Event = NULL;
}

/* Starts a watch of the directory and everything below it; the buffer is filled with a marker first. */
static BOOL ArmWatch(WATCH *W, BOOL Tree)
{
    RtlFillMemory(W->Buffer, sizeof(W->Buffer), 0xCC);
    ResetEvent(W->Event);
    RtlZeroMemory(&W->Ov, sizeof(W->Ov));
    W->Ov.hEvent = W->Event;
    return ReadDirectoryChangesW(W->Dir, W->Buffer, sizeof(W->Buffer), Tree, FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &W->Ov, NULL);
}

/* Waits for the armed watch; on a timeout the watch is cancelled and FALSE returned.  *Bytes is 0 when the buffer overflowed. */
static BOOL WaitWatch(WATCH *W, DWORD Ms, DWORD *Bytes)
{
    DWORD Got = 0;
    *Bytes = 0;
    if (WaitForSingleObject(W->Event, Ms) != WAIT_OBJECT_0)
    {
        CancelIo(W->Dir);
        GetOverlappedResult(W->Dir, &W->Ov, &Got, TRUE);
        return FALSE;
    }
    if (!GetOverlappedResult(W->Dir, &W->Ov, &Got, FALSE))
        return FALSE;
    *Bytes = Got;
    return TRUE;
}

/* The next record of Buffer[0..Bytes) at *Off, or NULL at the end; a record that leaves the returned bytes is a failure. */
static FILE_NOTIFY_INFORMATION *NextRecord(const BYTE *Buffer, DWORD Bytes, DWORD *Off, BOOL *Bad)
{
    FILE_NOTIFY_INFORMATION *R;
    DWORD Need;

    if (*Off >= Bytes)
        return NULL;
    R = (FILE_NOTIFY_INFORMATION *)(Buffer + *Off);
    if (Bytes - *Off < FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) ||
        R->FileNameLength % sizeof(WCHAR) ||
        (Need = FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) + R->FileNameLength) > Bytes - *Off)
    {
        *Bad = TRUE;
        return NULL;
    }
    if (R->NextEntryOffset)
    {
        if (R->NextEntryOffset < Need || R->NextEntryOffset >= Bytes - *Off)
        {
            *Bad = TRUE;
            return NULL;
        }
        *Off += R->NextEntryOffset;
    }
    else
        *Off = Bytes;
    return R;
}

static BOOL NameIs(const FILE_NOTIFY_INFORMATION *R, PCWSTR Expected)
{
    SIZE_T Len = wcslen(Expected) * sizeof(WCHAR);
    return R->FileNameLength == Len && !memcmp(R->FileName, Expected, Len);
}

/* "sub\n<digits>.txt" */
static BOOL NameIsRaceFile(const FILE_NOTIFY_INFORMATION *R)
{
    static const WCHAR Prefix[] = L"sub\\n", Suffix[] = L".txt";
    SIZE_T Chars = R->FileNameLength / sizeof(WCHAR), i, Digits = 0;

    if (Chars < 5 + 1 + 4 || memcmp(R->FileName, Prefix, 5 * sizeof(WCHAR)))
        return FALSE;
    for (i = 5; i < Chars - 4; i++, Digits++)
        if (R->FileName[i] < L'0' || R->FileName[i] > L'9')
            return FALSE;
    return Digits && !memcmp(R->FileName + Chars - 4, Suffix, 4 * sizeof(WCHAR));
}

/* Checks a completed watch holds records of Action each naming Expected; returns how many. */
static ULONG CheckRecords(WATCH *W, DWORD Bytes, DWORD Action, PCWSTR Expected, PCSTR What)
{
    DWORD Off = 0;
    ULONG Count = 0;
    BOOL Bad = FALSE;
    FILE_NOTIFY_INFORMATION *R;

    while ((R = NextRecord(W->Buffer, Bytes, &Off, &Bad)) != NULL)
    {
        Count++;
        ok(R->Action == Action, "%s: action %lu, expected %lu\n", What, R->Action, Action);
        ok(NameIs(R, Expected), "%s: a record names %.*ls (%lu bytes), expected %ls\n", What,
           (int)(R->FileNameLength / sizeof(WCHAR)), R->FileName, R->FileNameLength, Expected);
    }
    ok(!Bad, "%s: a record leaves the %lu returned bytes\n", What, Bytes);
    return Count;
}

static VOID MakeLongName(PWSTR Out, WCHAR Fill, ULONG Chars)
{
    ULONG i;
    for (i = 0; i < Chars; i++)
        Out[i] = Fill;
    Out[Chars] = 0;
}

typedef struct _RENAMER
{
    WCHAR A[MAX_PATH], B[MAX_PATH];
    volatile LONG Stop;
    BOOL AtA;
    ULONG Done;
    DWORD LastError;
    ULONG FailedAt;     /* Done when a rename first failed (0: none) */
    ULONG Failures;
} RENAMER;

/* Moves the directory between a short and a long name until told to stop. */
static DWORD WINAPI RenameLoop(PVOID Context)
{
    RENAMER *Rn = Context;

    while (!Rn->Stop)
    {
        if (MoveFileW(Rn->AtA ? Rn->A : Rn->B, Rn->AtA ? Rn->B : Rn->A))
        {
            Rn->AtA = !Rn->AtA;
            Rn->Done++;
        }
        else
        {
            Rn->LastError = GetLastError();
            if (!Rn->Failures++)
                Rn->FailedAt = Rn->Done;
            Sleep(1);
        }
    }
    return 0;
}

/* NtCreateFile of a new file relative to the directory handle (survives the directory's rename). */
static NTSTATUS CreateRelative(HANDLE Dir, PCWSTR Name)
{
    UNICODE_STRING Str;
    OBJECT_ATTRIBUTES Oa;
    IO_STATUS_BLOCK Iosb;
    HANDLE H;
    NTSTATUS Status;

    RtlInitUnicodeString(&Str, Name);
    InitializeObjectAttributes(&Oa, &Str, OBJ_CASE_INSENSITIVE, Dir, NULL);
    Status = NtCreateFile(&H, GENERIC_WRITE | SYNCHRONIZE, &Oa, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL, SHARE_ALL, FILE_CREATE,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(Status))
        NtClose(H);
    return Status;
}

START_TEST(NtfsNotifyRename)
{
    static const ULONG Lengths[] = { 1, 40, 2, 200, 1, 120, 3 };
    WCHAR Next[MAX_PATH], Path[MAX_PATH], Name[MAX_PATH], Rel[64];
    WCHAR Cur[MAX_PATH];
    WATCH W;
    RENAMER Rn;
    HANDLE Thread;
    DWORD Bytes;
    ULONG i, Delivered = 0;
    BOOL Pending;
    NTSTATUS Status;

    if (!NtInit("NtfsNotifyRename"))
        return;

    /* A watch armed before each rename of its directory (growing and shrinking the name) must go on
     * reporting, under the new name, exactly the changed file. */
    NtPath(Cur, L"w");
    ok(CreateDirectoryW(Cur, NULL), "CreateDirectory %lu\n", GetLastError());
    _snwprintf(Path, MAX_PATH - 1, L"%ls\\sub", Cur);
    ok(CreateDirectoryW(Path, NULL), "CreateDirectory sub %lu\n", GetLastError());
    ok(OpenWatch(&W, Cur), "Opening the watched directory: %lu\n", GetLastError());
    if (!W.Dir)
        goto cleanup;

    for (i = 1; i < sizeof(Lengths) / sizeof(Lengths[0]); i++)
    {
        MakeLongName(Name, L'a' + (WCHAR)i, Lengths[i]);
        NtPath(Next, Name);
        ok(ArmWatch(&W, TRUE), "ReadDirectoryChangesW %lu\n", GetLastError());
        ok(MoveFileW(Cur, Next), "Renaming to %lu characters: %lu\n", Lengths[i], GetLastError());
        wcscpy(Cur, Next);

        _snwprintf(Path, MAX_PATH - 1, L"%ls\\sub\\f.txt", Cur);
        if (wcslen(Path) < MAX_PATH - 2)
        {
            HANDLE F = CreateFileW(Path, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
            ok(F != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Path, GetLastError());
            if (F != INVALID_HANDLE_VALUE)
                CloseHandle(F);
            ok(WaitWatch(&W, 5000, &Bytes), "No report for a file created after the rename to %lu characters\n", Lengths[i]);
            if (Bytes)
                ok(CheckRecords(&W, Bytes, FILE_ACTION_ADDED, L"sub\\f.txt", "after rename") >= 1, "no record\n");
            else
                ok(0, "the report holds no bytes\n");
            ok(ArmWatch(&W, TRUE), "ReadDirectoryChangesW %lu\n", GetLastError());
            ok(DeleteFileW(Path), "Deleting %ls: %lu\n", Path, GetLastError());
            ok(WaitWatch(&W, 5000, &Bytes), "No report for the removal after the rename to %lu characters\n", Lengths[i]);
            if (Bytes)
                CheckRecords(&W, Bytes, FILE_ACTION_REMOVED, L"sub\\f.txt", "removal after rename");
        }
        else
        {
            WaitWatch(&W, 0, &Bytes);
            ok(ArmWatch(&W, TRUE), "ReadDirectoryChangesW %lu\n", GetLastError());
        }
    }
    WaitWatch(&W, 0, &Bytes);

    /* A rename racing with reports: a report that is delivered has to name exactly the file made (a
     * report lost while the directory's name changes is allowed). */
    RtlZeroMemory(&Rn, sizeof(Rn));
    wcscpy(Rn.A, Cur);
    MakeLongName(Name, L'z', 200);
    NtPath(Rn.B, Name);
    Rn.AtA = TRUE;
    Thread = CreateThread(NULL, 0, RenameLoop, &Rn, 0, NULL);
    ok(Thread != NULL, "CreateThread %lu\n", GetLastError());
    Pending = FALSE;
    for (i = 0; (i < 300 || (Rn.Done < 40 && i < 3000)) && Thread; i++)
    {
        BOOL Bad = FALSE;
        DWORD Off = 0;
        FILE_NOTIFY_INFORMATION *R;

        if (!Pending)
        {
            ok(ArmWatch(&W, TRUE), "ReadDirectoryChangesW %lu\n", GetLastError());
        }
        Sleep(1);   /* let the renamer run: a single processor switches threads only at a wait or a quantum */
        _snwprintf(Rel, 63, L"sub\\n%lu.txt", i);
        Status = CreateRelative(W.Dir, Rel);
        ok(NT_SUCCESS(Status), "Creating %ls relative to the directory handle: 0x%lx (renames done %lu, first failed at %lu, %lu failures, last error %lu)\n",
           Rel, Status, Rn.Done, Rn.FailedAt, Rn.Failures, Rn.LastError);
        Pending = !WaitWatch(&W, 50, &Bytes);
        if (Pending)
        {
            Pending = FALSE;    /* WaitWatch cancelled it */
            continue;
        }
        if (!Bytes)
            continue;
        while ((R = NextRecord(W.Buffer, Bytes, &Off, &Bad)) != NULL)
        {
            Delivered++;
            ok(NameIsRaceFile(R), "a report during a rename names %.*ls (%lu bytes)\n",
               (int)(R->FileNameLength / sizeof(WCHAR)), R->FileName, R->FileNameLength);
        }
        ok(!Bad, "a report during a rename leaves the %lu returned bytes\n", Bytes);
    }
    if (Thread)
    {
        InterlockedExchange(&Rn.Stop, 1);
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    ok(Rn.Done >= 40, "the renamer made only %lu renames (last error %lu): the race was not exercised\n", Rn.Done, Rn.LastError);
    trace("race: %lu renames, %lu reports delivered of %lu rounds\n", Rn.Done, Delivered, i);

cleanup:
    CloseWatch(&W);
    NtCleanup();
}

START_TEST(NtfsNotifyScale)
{
    static WATCH Many[MANY_WATCHERS];
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    WCHAR Base[8 * MAX_PATH], Deep[8 * MAX_PATH], Comp[256], DeepFile[8 * MAX_PATH];
    WATCH Long;
    DWORD Bytes;
    ULONG i, Opened = 0, Reported = 0;
    HANDLE F;

    if (!NtInit("NtfsNotifyScale"))
        return;

    /* Many handles of one directory, each with a pending registration: every one has to be served. */
    NtPath(Dir, L"n");
    ok(CreateDirectoryW(Dir, NULL), "CreateDirectory %lu\n", GetLastError());
    RtlZeroMemory(Many, sizeof(Many));
    for (i = 0; i < MANY_WATCHERS; i++)
    {
        if (!OpenWatch(&Many[i], Dir) || !ArmWatch(&Many[i], FALSE))
        {
            ok(0, "watcher %lu: %lu\n", i, GetLastError());
            break;
        }
        Opened++;
    }
    _snwprintf(Path, MAX_PATH - 1, L"%ls\\x.txt", Dir);
    F = CreateFileW(Path, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(F != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Path, GetLastError());
    if (F != INVALID_HANDLE_VALUE)
        CloseHandle(F);
    for (i = 0; i < Opened; i++)
    {
        if (WaitWatch(&Many[i], 10000, &Bytes) && Bytes && CheckRecords(&Many[i], Bytes, FILE_ACTION_ADDED, L"x.txt", "many") == 1)
            Reported++;
    }
    ok(Reported == Opened, "%lu of %lu watchers got the report\n", Reported, Opened);
    for (i = 0; i < Opened; i++)
        CloseWatch(&Many[i]);

    /* A registration on a directory whose path is far longer than MAX_PATH. */
    _snwprintf(Base, 8 * MAX_PATH - 1, L"\\\\?\\%ls", NtTestDir());
    wcscpy(Deep, Base);
    MakeLongName(Comp, L'd', 200);
    for (i = 0; i < 4; i++)
    {
        wcscat(Deep, L"\\");
        wcscat(Deep, Comp);
        if (!CreateDirectoryW(Deep, NULL))
        {
            ok(0, "Creating level %lu of the long path: %lu\n", i, GetLastError());
            goto cleanup;
        }
    }
    ok(OpenWatch(&Long, Deep), "Opening the long path: %lu\n", GetLastError());
    if (Long.Dir)
    {
        ok(ArmWatch(&Long, TRUE), "ReadDirectoryChangesW %lu\n", GetLastError());
        _snwprintf(DeepFile, 8 * MAX_PATH - 1, L"%ls\\deep.txt", Deep);
        F = CreateFileW(DeepFile, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(F != INVALID_HANDLE_VALUE, "Creating the file on the long path: %lu\n", GetLastError());
        if (F != INVALID_HANDLE_VALUE)
            CloseHandle(F);
        ok(WaitWatch(&Long, 10000, &Bytes), "No report on the long path\n");
        if (Bytes)
            ok(CheckRecords(&Long, Bytes, FILE_ACTION_ADDED, L"deep.txt", "long path") == 1, "wrong record count\n");
        DeleteFileW(DeepFile);
        CloseWatch(&Long);
    }
    /* innermost first: the cleanup of the test tree takes paths of MAX_PATH */
    for (i = 4; i > 0; i--)
    {
        SIZE_T Cut = wcslen(Base) + i * (1 + 200);
        Deep[Cut] = 0;
        RemoveDirectoryW(Deep);
    }

cleanup:
    NtCleanup();
}

/* A rename to or from a name that is no 8.3 name adds $FILE_NAME attributes to the MFT record, and each attribute added
 * takes the record's next 16-bit instance number.  Once the number wrapped the driver gave a new attribute an instance
 * another attribute of the record still had, and every later change of the directory failed (STATUS_UNEXPECTED_IO_ERROR
 * from the 43687th rename between a short and a 200 character name; the race in NtfsNotifyRename reached it on a fast
 * host).  Names of 180 or more characters. */
START_TEST(NtfsRenameInstanceWrap)
{
    WCHAR Short[MAX_PATH], Long[MAX_PATH], Name[MAX_PATH], Other[MAX_PATH];
    HANDLE F;
    BOOL AtShort = TRUE;
    ULONG i, Done = 0, Failed = 0;
    DWORD Error = 0;

    if (!NtInit("NtfsRenameInstanceWrap"))
        return;

    NtPath(Short, L"iw");
    MakeLongName(Name, L'q', 200);
    NtPath(Long, Name);
    ok(CreateDirectoryW(Short, NULL), "Creating %ls: %lu\n", Short, GetLastError());
    _snwprintf(Other, MAX_PATH - 1, L"%ls\\sub", Short);
    ok(CreateDirectoryW(Other, NULL), "Creating %ls: %lu\n", Other, GetLastError());

    for (i = 0; i < 48000; i++)
    {
        if (MoveFileW(AtShort ? Short : Long, AtShort ? Long : Short))
        {
            AtShort = !AtShort;
            Done++;
        }
        else
        {
            Error = GetLastError();
            Failed++;
            break;
        }
    }
    ok(!Failed, "rename %lu of 48000 failed: %lu\n", Done + 1, Error);
    trace("%lu renames\n", Done);

    /* the directory and its parent still work */
    ok(GetFileAttributesW(AtShort ? Short : Long) != INVALID_FILE_ATTRIBUTES, "the directory is gone: %lu\n", GetLastError());
    NtPath(Other, L"iw2");
    F = CreateFileW(Other, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(F != INVALID_HANDLE_VALUE, "Creating %ls: %lu\n", Other, GetLastError());
    if (F != INVALID_HANDLE_VALUE)
        CloseHandle(F);
    _snwprintf(Other, MAX_PATH - 1, L"%ls\\sub", AtShort ? Short : Long);
    ok(RemoveDirectoryW(Other), "Removing %ls: %lu\n", Other, GetLastError());
    ok(RemoveDirectoryW(AtShort ? Short : Long), "Removing the renamed directory: %lu\n", GetLastError());

    NtCleanup();
}
