/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Byte-range locks belong to the file object that took them: closing another
 *              file object of the same file (same or other process) must not release them
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifdef LOCKSEP_PROBE
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

/* Result of a lock/unlock call: 0 on success, otherwise the Win32 error */
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

/* Does an exclusive probe lock through Probe succeed (and is released again)? */
static BOOL IsFree(HANDLE Probe, DWORD Offset, DWORD Length)
{
    if (Lock(Probe, Offset, Length, TRUE) != 0) return FALSE;
    Unlock(Probe, Offset, Length);
    return TRUE;
}

static HANDLE Open(const char *Path, DWORD Disposition)
{
    return CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL, Disposition, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void MakePath(char *Path, const char *Name)
{
    char Dir[MAX_PATH];
    GetTempPathA(sizeof(Dir), Dir);
    sprintf(Path, "%slocksep_%lu_%s.tmp", Dir, GetCurrentProcessId(), Name);
}

#define EXPECT(Name, Actual, Expected) \
    do { DWORD a_ = (Actual); trace("%s: %lu\n", Name, a_); ok(a_ == (DWORD)(Expected), "%s: got %lu, expected %lu\n", Name, a_, (DWORD)(Expected)); } while (0)

static BOOL Setup(const char *Name, char *Path, HANDLE *A, HANDLE *B, HANDLE *Probe)
{
    char Data[64] = { 0 };
    DWORD Written;

    MakePath(Path, Name);
    *A = Open(Path, CREATE_ALWAYS);
    ok(*A != INVALID_HANDLE_VALUE, "%s: CreateFile failed with %lu\n", Name, GetLastError());
    if (*A == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(*A, Data, sizeof(Data), &Written, NULL);
    *B = Open(Path, OPEN_EXISTING);
    *Probe = Open(Path, OPEN_EXISTING);
    ok(*B != INVALID_HANDLE_VALUE && *Probe != INVALID_HANDLE_VALUE, "%s: second open failed\n", Name);
    if (*B == INVALID_HANDLE_VALUE || *Probe == INVALID_HANDLE_VALUE)
    {
        CloseHandle(*A);
        DeleteFileA(Path);
        return FALSE;
    }
    return TRUE;
}

static void Cleanup(const char *Path, HANDLE A, HANDLE B, HANDLE Probe)
{
    if (A != INVALID_HANDLE_VALUE) CloseHandle(A);
    if (B != INVALID_HANDLE_VALUE) CloseHandle(B);
    CloseHandle(Probe);
    DeleteFileA(Path);
}

/* The ticket: A locks, B is refused and closed, A's unlock must still work */
static void TestExclusiveRefusedClose(void)
{
    char Path[MAX_PATH];
    HANDLE A, B, Probe;

    if (!Setup("excl", Path, &A, &B, &Probe)) return;
    EXPECT("excl: A lock [0,8)", Lock(A, 0, 8, TRUE), 0);
    EXPECT("excl: B lock [0,8) refused", Lock(B, 0, 8, TRUE), ERROR_LOCK_VIOLATION);
    EXPECT("excl: B unlock A's range", Unlock(B, 0, 8), ERROR_NOT_LOCKED);
    CloseHandle(B);
    B = INVALID_HANDLE_VALUE;
    ok(!IsFree(Probe, 0, 8), "excl: A's range was released by closing B\n");
    EXPECT("excl: A unlock after B closed", Unlock(A, 0, 8), 0);
    ok(IsFree(Probe, 0, 8), "excl: range still locked after A's unlock\n");
    Cleanup(Path, A, B, Probe);
}

/* Both file objects hold a range; closing one releases only its own */
static void TestOwnRangesOnly(void)
{
    char Path[MAX_PATH];
    HANDLE A, B, Probe;

    if (!Setup("own", Path, &A, &B, &Probe)) return;
    EXPECT("own: A lock [0,8)", Lock(A, 0, 8, TRUE), 0);
    EXPECT("own: B lock [16,24)", Lock(B, 16, 8, TRUE), 0);
    CloseHandle(B);
    B = INVALID_HANDLE_VALUE;
    ok(!IsFree(Probe, 0, 8), "own: A's [0,8) released by closing B\n");
    ok(IsFree(Probe, 16, 8), "own: B's [16,24) still locked after B closed\n");
    EXPECT("own: A unlock [0,8)", Unlock(A, 0, 8), 0);
    Cleanup(Path, A, B, Probe);
}

/* Shared ranges: A [0,8) and B [4,12) overlap and merge; B's close drops only B's part */
static void TestSharedMerged(void)
{
    char Path[MAX_PATH];
    HANDLE A, B, Probe;

    if (!Setup("shared", Path, &A, &B, &Probe)) return;
    EXPECT("shared: A lock [0,8)", Lock(A, 0, 8, FALSE), 0);
    EXPECT("shared: B lock [4,12)", Lock(B, 4, 8, FALSE), 0);
    EXPECT("shared: B unlock A's [0,8)", Unlock(B, 0, 8), ERROR_NOT_LOCKED);
    CloseHandle(B);
    B = INVALID_HANDLE_VALUE;
    ok(!IsFree(Probe, 0, 8), "shared: A's [0,8) released by closing B\n");
    ok(IsFree(Probe, 8, 4), "shared: B's [8,12) still locked after B closed\n");
    EXPECT("shared: A unlock [0,8)", Unlock(A, 0, 8), 0);
    ok(IsFree(Probe, 0, 12), "shared: ranges left after both unlocked\n");
    Cleanup(Path, A, B, Probe);
}

/* A duplicate in the same process keeps the file object (and its locks) alive */
static void TestDuplicate(void)
{
    char Path[MAX_PATH];
    HANDLE A, B, Probe, Dup = NULL;

    if (!Setup("dup", Path, &A, &B, &Probe)) return;
    EXPECT("dup: A lock [0,8)", Lock(A, 0, 8, TRUE), 0);
    ok(DuplicateHandle(GetCurrentProcess(), A, GetCurrentProcess(), &Dup, 0, FALSE, DUPLICATE_SAME_ACCESS), "dup: DuplicateHandle failed\n");
    CloseHandle(A);
    ok(!IsFree(Probe, 0, 8), "dup: range released while a duplicate is open\n");
    EXPECT("dup: unlock through the duplicate", Unlock(Dup, 0, 8), 0);
    CloseHandle(Dup);
    Cleanup(Path, INVALID_HANDLE_VALUE, B, Probe);
}

/* Other process opens the file, is refused, locks its own range and exits */
static int RunChild(const char *Path)
{
    HANDLE C = Open(Path, OPEN_EXISTING);
    DWORD Refused, Own;

    if (C == INVALID_HANDLE_VALUE) return 10;
    Refused = Lock(C, 0, 8, TRUE);
    Own = Lock(C, 32, 8, TRUE);
    CloseHandle(C);
    return (Refused == ERROR_LOCK_VIOLATION && Own == 0) ? 0 : 11;
}

static void TestOtherProcess(const char *Exe)
{
    char Path[MAX_PATH], Cmd[3 * MAX_PATH];
    HANDLE A, B, Probe;
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    DWORD ExitCode = 99;

    if (!Setup("proc", Path, &A, &B, &Probe)) return;
    EXPECT("proc: A lock [0,8)", Lock(A, 0, 8, TRUE), 0);
    sprintf(Cmd, "\"%s\" FileLockCloseOther child \"%s\"", Exe, Path);
    if (CreateProcessA(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
    {
        WaitForSingleObject(Pi.hProcess, 30000);
        GetExitCodeProcess(Pi.hProcess, &ExitCode);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
    }
    EXPECT("proc: child exit", ExitCode, 0);
    ok(!IsFree(Probe, 0, 8), "proc: A's [0,8) released by the other process's close\n");
    ok(IsFree(Probe, 32, 8), "proc: the other process's [32,40) still locked after its close\n");
    EXPECT("proc: A unlock after the other process closed", Unlock(A, 0, 8), 0);
    Cleanup(Path, A, B, Probe);
}

#ifdef LOCKSEP_PROBE
int main(int argc, char **argv)
#else
START_TEST(FileLockCloseOther)
#endif
{
    char Exe[MAX_PATH];
#ifdef LOCKSEP_PROBE
    if (argc >= 4 && !strcmp(argv[2], "child")) return RunChild(argv[3]);
#else
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        ExitProcess(RunChild(argv[3]));
        return;
    }
#endif
    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    TestExclusiveRefusedClose();
    TestOwnRangesOnly();
    TestSharedMerged();
    TestDuplicate();
    TestOtherProcess(Exe);
#ifdef LOCKSEP_PROBE
    printf("mismatches: %d\n", g_fail);
    return 0;
#endif
}
