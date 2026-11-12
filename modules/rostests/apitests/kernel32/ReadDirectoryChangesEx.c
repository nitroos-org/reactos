/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for ReadDirectoryChangesExW: both information classes, event and completion routine
 *              completion, an invalid class and a buffer too small for the extended record
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#ifndef ReadDirectoryNotifyInformation
#define ReadDirectoryNotifyInformation 1
#define ReadDirectoryNotifyExtendedInformation 2
#endif

typedef BOOL WINAPI FN_ReadDirectoryChangesExW(HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED,
                                               LPOVERLAPPED_COMPLETION_ROUTINE, DWORD);

/* The record layout of the documented structure, without depending on the headers having it */
typedef struct _EXT_RECORD
{
    DWORD NextEntryOffset;
    DWORD Action;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastModificationTime;
    LARGE_INTEGER LastChangeTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER AllocatedLength;
    LARGE_INTEGER FileSize;
    DWORD FileAttributes;
    DWORD ReparsePointTagOrEaSize;
    LARGE_INTEGER FileId;
    LARGE_INTEGER ParentFileId;
    DWORD FileNameLength;
    WCHAR FileName[1];
} EXT_RECORD;

#define NAME_LEN 11
#define BASIC_RECORD_LEN (FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) + NAME_LEN * sizeof(WCHAR))

static FN_ReadDirectoryChangesExW *pReadDirectoryChangesExW;
static WCHAR Dir[MAX_PATH], File[MAX_PATH], File2[MAX_PATH];
static ULONGLONG NotifyBuffer[64];
static volatile LONG RoutineCalls;
static volatile DWORD RoutineError = 0xdeadbeef, RoutineBytes = 0xdeadbeef;
static LPOVERLAPPED RoutineOverlapped;
static BOOL ExtendedSupported = TRUE;

static
HANDLE
OpenDir(VOID)
{
    return CreateFileW(Dir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
}

static
VOID
MakeFile(_In_ PCWSTR Path)
{
    HANDLE Handle = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "CreateFile failed: %lu\n", GetLastError());
    CloseHandle(Handle);
}

static
ULONGLONG
FileIndex(_In_ PCWSTR Path)
{
    BY_HANDLE_FILE_INFORMATION Info;
    HANDLE Handle = CreateFileW(Path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ULONGLONG Index = 0;

    if (Handle != INVALID_HANDLE_VALUE)
    {
        if (GetFileInformationByHandle(Handle, &Info))
            Index = ((ULONGLONG)Info.nFileIndexHigh << 32) | Info.nFileIndexLow;
        CloseHandle(Handle);
    }
    return Index;
}

/* The plain class: the record ReadDirectoryChangesW gives */
static
VOID
CheckBasicRecord(_In_ PCSTR Label, _In_ DWORD Bytes)
{
    FILE_NOTIFY_INFORMATION *Info = (FILE_NOTIFY_INFORMATION *)NotifyBuffer;

    ok(Bytes == BASIC_RECORD_LEN, "%s: %lu bytes, expected %lu\n", Label, Bytes, (DWORD)BASIC_RECORD_LEN);
    ok(Info->NextEntryOffset == 0, "%s: next entry %lu\n", Label, Info->NextEntryOffset);
    ok(Info->Action == FILE_ACTION_ADDED, "%s: action %lu\n", Label, Info->Action);
    ok(Info->FileNameLength == NAME_LEN * sizeof(WCHAR) &&
       !memcmp(Info->FileName, L"newfile.txt", NAME_LEN * sizeof(WCHAR)),
       "%s: name %.*S\n", Label, (int)(Info->FileNameLength / sizeof(WCHAR)), Info->FileName);
}

/* The extended class: a first record for the new file */
static
VOID
CheckExtendedAdded(_In_ PCSTR Label, _In_ DWORD Bytes)
{
    EXT_RECORD *Rec = (EXT_RECORD *)NotifyBuffer;
    ULONGLONG Id = FileIndex(File), Parent = FileIndex(Dir);
    DWORD Length = FIELD_OFFSET(EXT_RECORD, FileName) + NAME_LEN * sizeof(WCHAR);

    ok(FIELD_OFFSET(EXT_RECORD, FileName) == 84, "record layout: header is %lu bytes\n",
       (DWORD)FIELD_OFFSET(EXT_RECORD, FileName));
    ok(Bytes >= Length, "%s: %lu bytes, a record is %lu\n", Label, Bytes, Length);
    if (Bytes < Length)
        return;
    ok(Rec->Action == FILE_ACTION_ADDED, "%s: action %lu\n", Label, Rec->Action);
    ok(Rec->FileNameLength == NAME_LEN * sizeof(WCHAR) &&
       !memcmp(Rec->FileName, L"newfile.txt", NAME_LEN * sizeof(WCHAR)),
       "%s: name %.*S\n", Label, (int)(Rec->FileNameLength / sizeof(WCHAR)), Rec->FileName);
    ok(Rec->NextEntryOffset == 0 || Rec->NextEntryOffset >= Length, "%s: next entry %lu\n", Label, Rec->NextEntryOffset);
    ok(Rec->FileId.QuadPart != 0, "%s: no file id\n", Label);
    ok(Rec->FileId.QuadPart == (LONGLONG)Id, "%s: file id %I64x, the file has %I64x\n", Label,
       Rec->FileId.QuadPart, Id);
    ok((Rec->ParentFileId.QuadPart & 0xFFFFFFFFFFFFLL) == (LONGLONG)(Parent & 0xFFFFFFFFFFFFULL),
       "%s: parent id %I64x, the directory has %I64x\n", Label, Rec->ParentFileId.QuadPart, Parent);
    ok(Rec->CreationTime.QuadPart != 0, "%s: no creation time\n", Label);
    ok(Rec->LastModificationTime.QuadPart != 0, "%s: no modification time\n", Label);
    ok(!(Rec->FileAttributes & FILE_ATTRIBUTE_DIRECTORY), "%s: attributes 0x%lx\n", Label, Rec->FileAttributes);
    ok(Rec->FileSize.QuadPart == 0, "%s: size %I64d\n", Label, Rec->FileSize.QuadPart);
}

static
VOID
TestExport(VOID)
{
    HANDLE Handle = OpenDir();
    OVERLAPPED Ov = {0};
    BOOL Ret;

    ok(Handle != INVALID_HANDLE_VALUE, "OpenDir failed: %lu\n", GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* A class that is neither of the two */
    SetLastError(0xdeadbeef);
    Ret = pReadDirectoryChangesExW(Handle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, NULL, 0);
    ok(!Ret, "class 0 succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "class 0: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    Ret = pReadDirectoryChangesExW(Handle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, NULL, 99);
    ok(!Ret, "class 99 succeeded\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "class 99: error %lu\n", GetLastError());

    /* Both classes may be asked for without a change pending: the request is queued */
    Ret = pReadDirectoryChangesExW(Handle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, NULL,
                                   ReadDirectoryNotifyExtendedInformation);
    if (!Ret && GetLastError() == ERROR_INVALID_FUNCTION)
    {
        /* The file system does not do the extended class (the documentation: only NTFS) */
        skip("the extended class is not supported on this volume\n");
        ExtendedSupported = FALSE;
    }
    else
    {
        ok(Ret, "extended class failed: %lu\n", GetLastError());
        if (Ret)
        {
            CancelIo(Handle);
            WaitForSingleObject(Ov.hEvent, 1000);
        }
    }
    CloseHandle(Ov.hEvent);
    CloseHandle(Handle);
}

static
VOID
TestEvent(_In_ DWORD Class)
{
    OVERLAPPED Ov = {0};
    HANDLE DirHandle = OpenDir();
    DWORD Bytes = 0xdeadbeef;
    BOOL Ret;

    ok(DirHandle != INVALID_HANDLE_VALUE, "OpenDir failed: %lu\n", GetLastError());
    if (DirHandle == INVALID_HANDLE_VALUE)
        return;
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(NotifyBuffer, 0xcc, sizeof(NotifyBuffer));

    Ret = pReadDirectoryChangesExW(DirHandle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, NULL, Class);
    ok(Ret, "class %lu: ReadDirectoryChangesExW failed: %lu\n", Class, GetLastError());
    if (Ret)
    {
        ok(WaitForSingleObject(Ov.hEvent, 100) == WAIT_TIMEOUT, "completed with no change\n");
        ok((NTSTATUS)Ov.Internal == STATUS_PENDING, "Internal is 0x%lx\n", (ULONG)Ov.Internal);
        MakeFile(File);
        ok(WaitForSingleObject(Ov.hEvent, 5000) == WAIT_OBJECT_0, "no completion\n");
        ok((NTSTATUS)Ov.Internal == STATUS_SUCCESS, "Internal is 0x%lx\n", (ULONG)Ov.Internal);
        Ret = GetOverlappedResult(DirHandle, &Ov, &Bytes, FALSE);
        ok(Ret, "GetOverlappedResult failed: %lu\n", GetLastError());
        if (Class == ReadDirectoryNotifyInformation)
            CheckBasicRecord("event", Bytes);
        else
            CheckExtendedAdded("event", Bytes);
    }
    CloseHandle(Ov.hEvent);
    CloseHandle(DirHandle);
    DeleteFileW(File);
}

static
VOID
CALLBACK
Routine(_In_ DWORD Error, _In_ DWORD Bytes, _In_ LPOVERLAPPED Overlapped)
{
    RoutineError = Error;
    RoutineBytes = Bytes;
    RoutineOverlapped = Overlapped;
    InterlockedIncrement(&RoutineCalls);
}

static
VOID
TestRoutine(_In_ DWORD Class)
{
    OVERLAPPED Ov = {0};
    HANDLE DirHandle = OpenDir();
    DWORD Wait;
    BOOL Ret;

    ok(DirHandle != INVALID_HANDLE_VALUE, "OpenDir failed: %lu\n", GetLastError());
    if (DirHandle == INVALID_HANDLE_VALUE)
        return;
    memset(NotifyBuffer, 0xcc, sizeof(NotifyBuffer));
    RoutineCalls = 0;

    Ret = pReadDirectoryChangesExW(DirHandle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, Routine, Class);
    ok(Ret, "class %lu: ReadDirectoryChangesExW failed: %lu\n", Class, GetLastError());
    if (Ret)
    {
        MakeFile(File);
        Wait = SleepEx(5000, TRUE);
        ok(Wait == WAIT_IO_COMPLETION, "SleepEx returned %lu\n", Wait);
        ok(RoutineCalls == 1, "routine called %ld times\n", RoutineCalls);
        ok(RoutineError == ERROR_SUCCESS, "routine error %lu\n", RoutineError);
        ok(RoutineOverlapped == &Ov, "routine overlapped %p, expected %p\n", RoutineOverlapped, &Ov);
        if (Class == ReadDirectoryNotifyInformation)
            CheckBasicRecord("routine", RoutineBytes);
        else
            CheckExtendedAdded("routine", RoutineBytes);
    }
    CloseHandle(DirHandle);
    DeleteFileW(File);
}

/* Changes that happen while no read is pending come back as a chain of records: a rename and a removal */
static
VOID
TestChain(_In_ DWORD Class)
{
    OVERLAPPED Ov = {0};
    HANDLE DirHandle = OpenDir();
    DWORD Bytes = 0xdeadbeef, Offset, Count = 0;
    EXT_RECORD *Rec;
    ULONGLONG Id;
    BOOL Ret, SawOld = FALSE, SawNew = FALSE, SawRemoved = FALSE;

    ok(DirHandle != INVALID_HANDLE_VALUE, "OpenDir failed: %lu\n", GetLastError());
    if (DirHandle == INVALID_HANDLE_VALUE)
        return;
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(NotifyBuffer, 0xcc, sizeof(NotifyBuffer));

    /* the first read registers the watch and ends with the first change */
    Ret = pReadDirectoryChangesExW(DirHandle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, NULL,
                                   Class);
    ok(Ret, "ReadDirectoryChangesExW failed: %lu\n", GetLastError());
    if (Ret)
    {
        MakeFile(File);
        Id = FileIndex(File);
        ok(WaitForSingleObject(Ov.hEvent, 5000) == WAIT_OBJECT_0, "no completion\n");

        /* no read is pending now: these are kept */
        ok(MoveFileW(File, File2), "MoveFile failed: %lu\n", GetLastError());
        ok(DeleteFileW(File2), "DeleteFile failed: %lu\n", GetLastError());

        ResetEvent(Ov.hEvent);
        memset(NotifyBuffer, 0xcc, sizeof(NotifyBuffer));
        Ret = pReadDirectoryChangesExW(DirHandle, NotifyBuffer, sizeof(NotifyBuffer), FALSE,
                                       FILE_NOTIFY_CHANGE_FILE_NAME, NULL, &Ov, NULL,
                                       Class);
        ok(Ret, "second ReadDirectoryChangesExW failed: %lu\n", GetLastError());
        ok(WaitForSingleObject(Ov.hEvent, 5000) == WAIT_OBJECT_0, "no second completion\n");
        Ret = GetOverlappedResult(DirHandle, &Ov, &Bytes, FALSE);
        ok(Ret, "GetOverlappedResult failed: %lu\n", GetLastError());
        trace("chain read: ret %d, %lu bytes, internal 0x%lx\n", Ret, Bytes, (ULONG)Ov.Internal);
        if (Class != ReadDirectoryNotifyExtendedInformation)
            Bytes = 0;
        for (Offset = 0; Ret && Offset + FIELD_OFFSET(EXT_RECORD, FileName) <= Bytes; )
        {
            Rec = (EXT_RECORD *)((PUCHAR)NotifyBuffer + Offset);
            Count++;
            if (Rec->Action == FILE_ACTION_RENAMED_OLD_NAME) SawOld = TRUE;
            if (Rec->Action == FILE_ACTION_RENAMED_NEW_NAME) SawNew = TRUE;
            if (Rec->Action == FILE_ACTION_REMOVED) SawRemoved = TRUE;
            ok(Rec->FileId.QuadPart == (LONGLONG)Id, "record %lu (action %lu): file id %I64x, expected %I64x\n",
               Count, Rec->Action, Rec->FileId.QuadPart, Id);
            if (!Rec->NextEntryOffset)
                break;
            Offset += Rec->NextEntryOffset;
        }
        if (Class == ReadDirectoryNotifyExtendedInformation)
        {
        ok(Count == 3, "%lu records, expected 3\n", Count);
        ok(SawOld && SawNew && SawRemoved, "records: old %d, new %d, removed %d\n", SawOld, SawNew, SawRemoved);
        }
    }
    CloseHandle(Ov.hEvent);
    CloseHandle(DirHandle);
    DeleteFileW(File);
    DeleteFileW(File2);
}

/* A buffer that holds a plain record but not an extended one */
static
VOID
TestSmallBuffer(VOID)
{
    OVERLAPPED Ov = {0};
    HANDLE DirHandle = OpenDir();
    DWORD Bytes = 0xdeadbeef, Class;
    BOOL Ret;

    ok(DirHandle != INVALID_HANDLE_VALUE, "OpenDir failed: %lu\n", GetLastError());
    if (DirHandle == INVALID_HANDLE_VALUE)
        return;
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    for (Class = ReadDirectoryNotifyInformation; Class <= ReadDirectoryNotifyExtendedInformation; Class++)
    {
        if (Class == ReadDirectoryNotifyExtendedInformation && !ExtendedSupported)
            break;
        ResetEvent(Ov.hEvent);
        memset(NotifyBuffer, 0xcc, sizeof(NotifyBuffer));
        Ret = pReadDirectoryChangesExW(DirHandle, NotifyBuffer, 64, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME,
                                       NULL, &Ov, NULL, Class);
        ok(Ret, "class %lu: ReadDirectoryChangesExW failed: %lu\n", Class, GetLastError());
        if (!Ret)
            continue;
        MakeFile(File);
        ok(WaitForSingleObject(Ov.hEvent, 5000) == WAIT_OBJECT_0, "class %lu: no completion\n", Class);
        Bytes = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        Ret = GetOverlappedResult(DirHandle, &Ov, &Bytes, FALSE);
        if (Class == ReadDirectoryNotifyInformation)
        {
            /* 64 bytes hold the 34-byte plain record */
            ok(Ret && Bytes == BASIC_RECORD_LEN, "plain: ret %d, %lu bytes, error %lu\n", Ret, Bytes, GetLastError());
        }
        else
        {
            /* the extended record is 106 bytes: the request completes with nothing in the buffer and the
             * caller has to enumerate the directory (ERROR_NOTIFY_ENUM_DIR, or success with no bytes) */
            ok((Ret && Bytes == 0) || (!Ret && GetLastError() == ERROR_NOTIFY_ENUM_DIR),
               "extended: ret %d, %lu bytes, error %lu\n", Ret, Bytes, GetLastError());
        }
        DeleteFileW(File);
    }
    CloseHandle(Ov.hEvent);
    CloseHandle(DirHandle);
}

START_TEST(ReadDirectoryChangesEx)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");

    pReadDirectoryChangesExW = (FN_ReadDirectoryChangesExW *)GetProcAddress(Kernel32, "ReadDirectoryChangesExW");
    ok(pReadDirectoryChangesExW != NULL, "kernel32 does not export ReadDirectoryChangesExW\n");
    if (!pReadDirectoryChangesExW)
        return;

    GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    StringCchCatW(Dir, RTL_NUMBER_OF(Dir), L"rostest_rdchangesex");
    CreateDirectoryW(Dir, NULL);
    StringCchPrintfW(File, RTL_NUMBER_OF(File), L"%s\\newfile.txt", Dir);
    StringCchPrintfW(File2, RTL_NUMBER_OF(File2), L"%s\\renamed.txt", Dir);
    DeleteFileW(File);
    DeleteFileW(File2);

    TestExport();
    TestEvent(ReadDirectoryNotifyInformation);
    TestRoutine(ReadDirectoryNotifyInformation);
    TestSmallBuffer();
    TestChain(ReadDirectoryNotifyInformation);
    if (ExtendedSupported)
    {
        TestEvent(ReadDirectoryNotifyExtendedInformation);
        TestRoutine(ReadDirectoryNotifyExtendedInformation);
        TestChain(ReadDirectoryNotifyExtendedInformation);
    }

    DeleteFileW(File);
    DeleteFileW(File2);
    RemoveDirectoryW(Dir);
}
