/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Byte-range locks of length zero: LockFileEx grants them, they never conflict with another lock and
 *              never block a read or a write, and UnlockFileEx finds them by their exact offset
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations were measured with the same code on Windows Server 2022 (10.0.20348, NTFS): a zero length lock is
 * granted, it sits between two bytes (see Conflicts) and is found again by its exact offset.
 */

#ifdef LOCKZERO_PROBE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int g_fail;
#define ok(c, ...) do { if (!(c)) { g_fail++; printf("MISMATCH: "); printf(__VA_ARGS__); } } while (0)
#define trace(...) printf(__VA_ARGS__)
#else
#include "precomp.h"
#endif

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

/* 0 on success, otherwise the Win32 error */
static DWORD Lock(HANDLE File, DWORD Offset, DWORD Length, BOOL Exclusive)
{
    OVERLAPPED Ov = { 0 };
    Ov.Offset = Offset;
    if (LockFileEx(File, LOCKFILE_FAIL_IMMEDIATELY | (Exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0), 0, Length, 0, &Ov))
        return 0;
    return GetLastError();
}

static DWORD Unlock(HANDLE File, DWORD Offset, DWORD Length)
{
    OVERLAPPED Ov = { 0 };
    Ov.Offset = Offset;
    if (UnlockFileEx(File, 0, Length, 0, &Ov))
        return 0;
    return GetLastError();
}

static DWORD ReadAt(HANDLE File, DWORD Offset)
{
    OVERLAPPED Ov = { 0 };
    BYTE Buffer[4];
    DWORD Read;

    Ov.Offset = Offset;
    return ReadFile(File, Buffer, sizeof(Buffer), &Read, &Ov) ? 0 : GetLastError();
}

static DWORD WriteAt(HANDLE File, DWORD Offset)
{
    OVERLAPPED Ov = { 0 };
    BYTE Buffer[4] = { 0 };
    DWORD Written;

    Ov.Offset = Offset;
    return WriteFile(File, Buffer, sizeof(Buffer), &Written, &Ov) ? 0 : GetLastError();
}

#define EXPECT(Name, Actual, Expected) \
    do { DWORD a_ = (Actual); trace("%s: %lu\n", Name, a_); ok(a_ == (DWORD)(Expected), "%s: got %lu, expected %lu\n", Name, a_, (DWORD)(Expected)); } while (0)

static BOOL Setup(char *Path, HANDLE *A, HANDLE *B)
{
    char Dir[MAX_PATH];
    BYTE Data[4096] = { 0 };
    DWORD Written;

    GetTempPathA(sizeof(Dir), Dir);
    sprintf(Path, "%slockzero_%lu.tmp", Dir, GetCurrentProcessId());
    *A = CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(*A != INVALID_HANDLE_VALUE, "CreateFile failed with %lu\n", GetLastError());
    if (*A == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(*A, Data, sizeof(Data), &Written, NULL);
    *B = CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(*B != INVALID_HANDLE_VALUE, "second open failed with %lu\n", GetLastError());
    if (*B == INVALID_HANDLE_VALUE)
    {
        CloseHandle(*A);
        DeleteFileA(Path);
        return FALSE;
    }
    return TRUE;
}

static void Cleanup(const char *Path, HANDLE A, HANDLE B)
{
    CloseHandle(A);
    CloseHandle(B);
    DeleteFileA(Path);
}

/* The rule measured on Windows Server 2022: a zero length lock at P is a point between the bytes P-1 and P. It conflicts
 * with a range [Start,End) of another lock or of an I/O when Start < P < End (not at the ends of the range), if one of
 * the two is exclusive; zero length locks never conflict with each other. */
static BOOL Conflicts(DWORD P, BOOL ZeroExclusive, DWORD Start, DWORD Length, BOOL RangeExclusive)
{
    return Start < P && P < Start + Length && (ZeroExclusive || RangeExclusive);
}

/* A zero length lock of A at P; B asks for ranges, locks of length zero, reads and writes */
static void TestZeroHeld(DWORD P, BOOL Exclusive)
{
    static const struct { DWORD Start, Length; } Ranges[] =
        { { 100, 100 }, { 150, 1 }, { 149, 1 }, { 149, 2 }, { 50, 50 }, { 99, 2 }, { 199, 2 }, { 200, 10 } };
    char Path[MAX_PATH];
    char Name[96];
    HANDLE A, B;
    SIZE_T i;
    int Mode;

    if (!Setup(Path, &A, &B)) return;
    trace("A holds a zero length %s lock at %lu\n", Exclusive ? "exclusive" : "shared", P);
    EXPECT("A zero length lock", Lock(A, P, 0, Exclusive), 0);
    for (i = 0; i < sizeof(Ranges) / sizeof(Ranges[0]); i++)
    {
        for (Mode = 0; Mode < 2; Mode++)
        {
            DWORD Error = Lock(B, Ranges[i].Start, Ranges[i].Length, Mode);

            sprintf(Name, "B %s [%lu,%lu)", Mode ? "exclusive" : "shared", Ranges[i].Start, Ranges[i].Start + Ranges[i].Length);
            EXPECT(Name, Error, Conflicts(P, Exclusive, Ranges[i].Start, Ranges[i].Length, Mode) ? ERROR_LOCK_VIOLATION : 0);
            if (!Error) Unlock(B, Ranges[i].Start, Ranges[i].Length);
        }
    }
    for (Mode = 0; Mode < 2; Mode++)
    {
        DWORD Error = Lock(B, P, 0, Mode);

        sprintf(Name, "B %s zero length at the same offset", Mode ? "exclusive" : "shared");
        EXPECT(Name, Error, 0);
        if (!Error) Unlock(B, P, 0);
    }
    if (P >= 2 && P + 2 <= 4096)
    {
        EXPECT("B read across the offset", ReadAt(B, P - 2), Exclusive ? ERROR_LOCK_VIOLATION : 0);
        EXPECT("B write across the offset", WriteAt(B, P - 2), ERROR_LOCK_VIOLATION);
    }
    if (P + 4 <= 4096)
    {
        EXPECT("B read from the offset", ReadAt(B, P), 0);
        EXPECT("B write from the offset", WriteAt(B, P), 0);
    }
    /* the owner's own unlock: the exact range once */
    EXPECT("A unlock another length (1)", Unlock(A, P, 1), ERROR_NOT_LOCKED);
    EXPECT("B unlock A's zero length lock", Unlock(B, P, 0), ERROR_NOT_LOCKED);
    EXPECT("A unlock the exact range", Unlock(A, P, 0), 0);
    EXPECT("A unlock the exact range again", Unlock(A, P, 0), ERROR_NOT_LOCKED);
    Cleanup(Path, A, B);
}

/* B holds [100,200); A asks for a zero length lock at P */
static void TestZeroAsked(BOOL RangeExclusive, DWORD P, BOOL ZeroExclusive)
{
    char Path[MAX_PATH];
    char Name[96];
    HANDLE A, B;
    DWORD Error;

    if (!Setup(Path, &A, &B)) return;
    EXPECT("B lock [100,200)", Lock(B, 100, 100, RangeExclusive), 0);
    Error = Lock(A, P, 0, ZeroExclusive);
    sprintf(Name, "A %s zero length at %lu next to a %s [100,200) of B", ZeroExclusive ? "exclusive" : "shared", P,
            RangeExclusive ? "exclusive" : "shared");
    EXPECT(Name, Error, Conflicts(P, ZeroExclusive, 100, 100, RangeExclusive) ? ERROR_LOCK_VIOLATION : 0);
    if (!Error)
        EXPECT("A unlock the exact range", Unlock(A, P, 0), 0);
    EXPECT("B unlock [100,200)", Unlock(B, 100, 100), 0);
    Cleanup(Path, A, B);
}

/* The owner of an exclusive range may take a shared lock of length zero inside it, an exclusive one is refused; the other
 * handle is refused for both (Windows Server 2022) */
static void TestOwnRange(void)
{
    char Path[MAX_PATH];
    HANDLE A, B;

    if (!Setup(Path, &A, &B)) return;
    EXPECT("A lock [100,200)", Lock(A, 100, 100, TRUE), 0);
    EXPECT("A shared zero length at 150 inside its own exclusive range", Lock(A, 150, 0, FALSE), 0);
    EXPECT("A unlock the exact range", Unlock(A, 150, 0), 0);
    EXPECT("A exclusive zero length at 150 inside its own exclusive range", Lock(A, 150, 0, TRUE), ERROR_LOCK_VIOLATION);
    EXPECT("B shared zero length at 150", Lock(B, 150, 0, FALSE), ERROR_LOCK_VIOLATION);
    EXPECT("B exclusive zero length at 150", Lock(B, 150, 0, TRUE), ERROR_LOCK_VIOLATION);
    EXPECT("A unlock [100,200)", Unlock(A, 100, 100), 0);
    Cleanup(Path, A, B);
}

/* A waiting request that a zero length lock blocks goes on when the lock is released */
static void TestWaiter(void)
{
    char Path[MAX_PATH];
    HANDLE A, B;
    OVERLAPPED Ov = { 0 };

    if (!Setup(Path, &A, &B)) return;
    EXPECT("A zero length lock at 150", Lock(A, 150, 0, TRUE), 0);
    EXPECT("B [100,200) refused at once", Lock(B, 100, 100, TRUE), ERROR_LOCK_VIOLATION);
    EXPECT("A unlock the exact range", Unlock(A, 150, 0), 0);
    EXPECT("B [100,200) granted", Lock(B, 100, 100, TRUE), 0);
    Ov.Offset = 100;
    UnlockFileEx(B, 0, 100, 0, &Ov);
    Cleanup(Path, A, B);
}

#ifdef LOCKZERO_PROBE
int main(void)
#else
START_TEST(FileLockZeroLength)
#endif
{
    static const DWORD Offsets[] = { 0, 100, 150, 200, 1000, 4096, 10000 };
    static const DWORD Around[] = { 99, 100, 150, 199, 200 };
    SIZE_T i;

    for (i = 0; i < sizeof(Offsets) / sizeof(Offsets[0]); i++)
    {
        TestZeroHeld(Offsets[i], TRUE);
        TestZeroHeld(Offsets[i], FALSE);
    }
    for (i = 0; i < sizeof(Around) / sizeof(Around[0]); i++)
    {
        TestZeroAsked(TRUE, Around[i], TRUE);
        TestZeroAsked(TRUE, Around[i], FALSE);
        TestZeroAsked(FALSE, Around[i], TRUE);
        TestZeroAsked(FALSE, Around[i], FALSE);
    }
    TestOwnRange();
    TestWaiter();
#ifdef LOCKZERO_PROBE
    printf("mismatches: %d\n", g_fail);
    return g_fail != 0;
#endif
}
