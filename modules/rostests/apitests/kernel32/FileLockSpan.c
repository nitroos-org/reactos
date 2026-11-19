/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Byte-range locks: one read or write that spans two locked ranges of another handle is
 *              refused when either range stops it; a waiting LockFileEx ends with its own handle
 *              (STATUS_RANGE_NOT_LOCKED) and is granted when the handle that blocks it is closed
 *              (the expected values are the ones measured on Windows Server 2022, NTFS)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define STATUS_RANGE_NOT_LOCKED_VALUE 0xC000007E

static HANDLE OpenShared(const char *Path, DWORD Flags)
{
    return CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | Flags, NULL);
}

static BOOL LockNow(HANDLE File, DWORD Offset, DWORD Length, BOOL Exclusive)
{
    OVERLAPPED Ov = { 0 };
    Ov.Offset = Offset;
    return LockFileEx(File, LOCKFILE_FAIL_IMMEDIATELY | (Exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0), 0, Length, 0, &Ov);
}

/* 0 when the I/O went through, else the Win32 error */
static DWORD DoIo(HANDLE File, DWORD Offset, DWORD Length, BOOL Write)
{
    BYTE Buffer[64] = { 0 };
    DWORD Done;
    BOOL Ok;

    SetFilePointer(File, Offset, NULL, FILE_BEGIN);
    Ok = Write ? WriteFile(File, Buffer, Length, &Done, NULL) : ReadFile(File, Buffer, Length, &Done, NULL);
    return Ok ? 0 : GetLastError();
}

static void MakeFile(char *Path, const char *Name)
{
    char Dir[MAX_PATH];
    HANDLE File;
    BYTE Zero[4096] = { 0 };
    DWORD Done;

    GetTempPathA(sizeof(Dir), Dir);
    sprintf(Path, "%sfilelockspan_%lu_%s.tmp", Dir, GetCurrentProcessId(), Name);
    File = CreateFileA(Path, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "create failed %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        WriteFile(File, Zero, sizeof(Zero), &Done, NULL);
        CloseHandle(File);
    }
}

/* A locks [0,10) and [20,30) with the given kinds; B reads and writes across them */
static void TestSpan(BOOL Excl1, BOOL Excl2, DWORD ReadAcross, DWORD ReadTouch, DWORD WriteAcross, DWORD OwnerRead, DWORD OwnerWrite)
{
    char Path[MAX_PATH];
    HANDLE A, B;

    MakeFile(Path, "span");
    A = OpenShared(Path, 0);
    B = OpenShared(Path, 0);
    ok(LockNow(A, 0, 10, Excl1), "lock 1 failed\n");
    ok(LockNow(A, 20, 10, Excl2), "lock 2 failed\n");
    ok_dec(DoIo(B, 5, 20, FALSE), ReadAcross);   /* tail of range 1, the gap, head of range 2 */
    ok_dec(DoIo(B, 0, 30, FALSE), ReadAcross);   /* both ranges whole */
    ok_dec(DoIo(B, 9, 12, FALSE), ReadTouch);    /* one byte of each range */
    ok_dec(DoIo(B, 10, 10, FALSE), 0);           /* exactly the gap */
    ok_dec(DoIo(B, 5, 20, TRUE), WriteAcross);
    ok_dec(DoIo(A, 5, 20, FALSE), OwnerRead);
    ok_dec(DoIo(A, 5, 20, TRUE), OwnerWrite);
    CloseHandle(A);
    CloseHandle(B);
    DeleteFileA(Path);
}

static void TestTwoOwners(BOOL ExclSecond, DWORD ReadAcross)
{
    char Path[MAX_PATH];
    HANDLE A, C, B;

    MakeFile(Path, "owners");
    A = OpenShared(Path, 0);
    C = OpenShared(Path, 0);
    B = OpenShared(Path, 0);
    ok(LockNow(A, 0, 10, FALSE), "lock A failed\n");
    ok(LockNow(C, 20, 10, ExclSecond), "lock C failed\n");
    ok_dec(DoIo(B, 5, 20, FALSE), ReadAcross);
    ok_dec(DoIo(B, 0, 30, FALSE), ReadAcross);
    ok_dec(DoIo(B, 5, 20, TRUE), ERROR_LOCK_VIOLATION);
    CloseHandle(A);
    CloseHandle(C);
    CloseHandle(B);
    DeleteFileA(Path);
}

static BOOL StartWait(HANDLE File, OVERLAPPED *Ov, HANDLE Event)
{
    BOOL Ok;

    ZeroMemory(Ov, sizeof(*Ov));
    Ov->hEvent = Event;
    Ov->Offset = 5;
    ResetEvent(Event);
    Ok = LockFileEx(File, LOCKFILE_EXCLUSIVE_LOCK, 0, 10, 0, Ov);
    return !Ok && GetLastError() == ERROR_IO_PENDING;
}

static void TestWaiting(BOOL HolderExclusive)
{
    char Path[MAX_PATH];
    HANDLE A, B, C, Event;
    OVERLAPPED Ov;

    MakeFile(Path, "wait");
    Event = CreateEventA(NULL, TRUE, FALSE, NULL);

    /* the waiter's own handle is closed: the request ends with STATUS_RANGE_NOT_LOCKED and does not stay in the queue */
    A = OpenShared(Path, 0);
    B = OpenShared(Path, FILE_FLAG_OVERLAPPED);
    ok(LockNow(A, 0, 10, HolderExclusive), "holder lock failed\n");
    ok(StartWait(B, &Ov, Event), "the lock request did not wait\n");
    Sleep(200);
    CloseHandle(B);
    ok_dec(WaitForSingleObject(Event, 5000), WAIT_OBJECT_0);
    ok_hex((ULONG)Ov.Internal, STATUS_RANGE_NOT_LOCKED_VALUE);
    CloseHandle(A);
    /* nothing was left behind: another handle takes the waiter's range at once */
    A = OpenShared(Path, 0);
    C = OpenShared(Path, 0);
    ok(LockNow(C, 5, 10, TRUE), "the range of the closed waiter is still held (error %lu)\n", GetLastError());
    CloseHandle(C);
    CloseHandle(A);

    /* the holder's handle is closed: the waiter is granted and owns the range */
    A = OpenShared(Path, 0);
    B = OpenShared(Path, FILE_FLAG_OVERLAPPED);
    ok(LockNow(A, 0, 10, HolderExclusive), "holder lock failed\n");
    ok(StartWait(B, &Ov, Event), "the lock request did not wait\n");
    Sleep(200);
    CloseHandle(A);
    ok_dec(WaitForSingleObject(Event, 5000), WAIT_OBJECT_0);
    ok_hex((ULONG)Ov.Internal, 0);
    {
        OVERLAPPED Un = { 0 };
        Un.Offset = 5;
        ok(UnlockFileEx(B, 0, 10, 0, &Un), "the granted range is not B's (error %lu)\n", GetLastError());
    }
    CloseHandle(B);

    /* CancelIo ends a waiting request with STATUS_CANCELLED */
    A = OpenShared(Path, 0);
    B = OpenShared(Path, FILE_FLAG_OVERLAPPED);
    ok(LockNow(A, 0, 10, HolderExclusive), "holder lock failed\n");
    ok(StartWait(B, &Ov, Event), "the lock request did not wait\n");
    Sleep(200);
    ok(CancelIo(B), "CancelIo failed\n");
    ok_dec(WaitForSingleObject(Event, 5000), WAIT_OBJECT_0);
    ok_hex((ULONG)Ov.Internal, 0xC0000120);
    CloseHandle(B);
    CloseHandle(A);

    CloseHandle(Event);
    DeleteFileA(Path);
}

START_TEST(FileLockSpan)
{
    /*             excl 1  excl 2  read across      read touch       write across         owner read owner write */
    TestSpan(TRUE,  TRUE,  ERROR_LOCK_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_LOCK_VIOLATION, 0, 0);
    TestSpan(FALSE, FALSE, 0,                    0,                    ERROR_LOCK_VIOLATION, 0, ERROR_LOCK_VIOLATION);
    TestSpan(TRUE,  FALSE, ERROR_LOCK_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_LOCK_VIOLATION, 0, ERROR_LOCK_VIOLATION);
    TestSpan(FALSE, TRUE,  ERROR_LOCK_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_LOCK_VIOLATION, 0, ERROR_LOCK_VIOLATION);
    TestTwoOwners(FALSE, 0);
    TestTwoOwners(TRUE, ERROR_LOCK_VIOLATION);
    TestWaiting(TRUE);
    TestWaiting(FALSE);
}
