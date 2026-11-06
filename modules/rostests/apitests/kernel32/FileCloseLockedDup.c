/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Closing a duplicated handle of a synchronous, byte-range-locked file
 *              while a (suspended) thread of the owner waits inside a lock request
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define CLOSE_WAIT_MS 5000

typedef enum
{
    CaseDupBlocked,         /* closer duplicates and closes; owner thread waits in a lock request */
    CaseDupSuspended,       /* same, and the waiting owner thread is suspended (Edge crash report) */
    CaseCloseSourceSuspended /* closer takes the owner's handle away with DUPLICATE_CLOSE_SOURCE */
} CLOSE_CASE;

static const char *CaseName[] = { "dup+close, waiter blocked", "dup+close, waiter suspended", "close-source, waiter suspended" };

typedef struct
{
    HANDLE File;
    BOOL Ret;
    DWORD Error;
} WAITER;

static DWORD WINAPI WaiterThread(LPVOID Param)
{
    WAITER *Waiter = Param;
    OVERLAPPED Ov = { 0 };

    /* Conflicts with the range held through the second file object: waits inside the request */
    Waiter->Ret = LockFileEx(Waiter->File, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &Ov);
    Waiter->Error = GetLastError();
    return 0;
}

static BOOL TryLock(HANDLE File, DWORD Offset)
{
    OVERLAPPED Ov = { 0 };
    Ov.Offset = Offset;
    return LockFileEx(File, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &Ov);
}

static void RunCloser(int argc, char **argv)
{
    DWORD OwnerPid = strtoul(argv[3], NULL, 10);
    HANDLE Remote = (HANDLE)(ULONG_PTR)strtoul(argv[4], NULL, 16);
    int Mode = atoi(argv[5]);
    HANDLE Done = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[6]);
    HANDLE Exit = OpenEventA(SYNCHRONIZE, FALSE, argv[7]);
    HANDLE Owner, Keep = NULL, Mine = NULL;
    BOOL Ret;

    (void)argc;
    Owner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, OwnerPid);
    if (!Owner || !Done || !Exit) ExitProcess(10);

    if (Mode == CaseCloseSourceSuspended)
    {
        /* Keep a reference of our own so the owner's close is not the last handle */
        if (!DuplicateHandle(Owner, Remote, GetCurrentProcess(), &Keep, 0, FALSE, DUPLICATE_SAME_ACCESS))
            ExitProcess(11);
        Ret = DuplicateHandle(Owner, Remote, GetCurrentProcess(), &Mine, 0, FALSE,
                              DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
        if (!Ret) ExitProcess(12);
        CloseHandle(Mine);
    }
    else
    {
        if (!DuplicateHandle(Owner, Remote, GetCurrentProcess(), &Mine, 0, FALSE, DUPLICATE_SAME_ACCESS))
            ExitProcess(11);
        /* This process's only handle to the file object: the close that hung */
        CloseHandle(Mine);
    }
    SetEvent(Done);

    WaitForSingleObject(Exit, 60000);
    if (Keep) CloseHandle(Keep);
    ExitProcess(0);
}

static void RunCase(CLOSE_CASE Case, const char *Exe)
{
    char Path[MAX_PATH], TempDir[MAX_PATH], DoneName[64], ExitName[64], Cmd[2 * MAX_PATH];
    HANDLE Locked, File, Thread, Done, Exit;
    STARTUPINFOA Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    WAITER Waiter = { 0 };
    DWORD Written, Wait, Start, CloseMs, ExitCode = 0;
    BOOL Ret, OwnLockFree;
    char Data[64] = { 0 };

    GetTempPathA(sizeof(TempDir), TempDir);
    sprintf(Path, "%sclosehang_%lu_%d.tmp", TempDir, GetCurrentProcessId(), (int)Case);
    sprintf(DoneName, "closehang_done_%lu_%d", GetCurrentProcessId(), (int)Case);
    sprintf(ExitName, "closehang_exit_%lu_%d", GetCurrentProcessId(), (int)Case);

    /* Two synchronous file objects for the same file */
    Locked = CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(Locked != INVALID_HANDLE_VALUE, "%s: CreateFile failed with %lu\n", CaseName[Case], GetLastError());
    if (Locked == INVALID_HANDLE_VALUE) return;
    WriteFile(Locked, Data, sizeof(Data), &Written, NULL);
    File = CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "%s: CreateFile failed with %lu\n", CaseName[Case], GetLastError());
    if (File == INVALID_HANDLE_VALUE) { CloseHandle(Locked); DeleteFileA(Path); return; }

    ok(TryLock(Locked, 0), "%s: lock [0,1) failed with %lu\n", CaseName[Case], GetLastError());
    /* A granted lock of this process through the file object the closer gets */
    ok(TryLock(File, 16), "%s: lock [16,17) failed with %lu\n", CaseName[Case], GetLastError());

    Waiter.File = File;
    Thread = CreateThread(NULL, 0, WaiterThread, &Waiter, 0, NULL);
    ok(Thread != NULL, "%s: CreateThread failed with %lu\n", CaseName[Case], GetLastError());
    if (!Thread) { CloseHandle(File); CloseHandle(Locked); DeleteFileA(Path); return; }
    Sleep(300);
    ok(WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT, "%s: waiter did not wait (ret %d, error %lu)\n",
       CaseName[Case], Waiter.Ret, Waiter.Error);
    if (Case != CaseDupBlocked)
    {
        ok(SuspendThread(Thread) == 0, "%s: SuspendThread failed with %lu\n", CaseName[Case], GetLastError());
        Sleep(200);
    }

    Done = CreateEventA(NULL, TRUE, FALSE, DoneName);
    Exit = CreateEventA(NULL, TRUE, FALSE, ExitName);
    sprintf(Cmd, "\"%s\" FileCloseLockedDup closer %lu %lx %d %s %s", Exe, GetCurrentProcessId(),
            (unsigned long)(ULONG_PTR)File, (int)Case, DoneName, ExitName);
    Ret = CreateProcessA(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi);
    ok(Ret, "%s: CreateProcess failed with %lu\n", CaseName[Case], GetLastError());
    if (Ret)
    {
        HANDLE Objects[2] = { Done, Pi.hProcess };

        Start = GetTickCount();
        Wait = WaitForMultipleObjects(2, Objects, FALSE, Case == CaseCloseSourceSuspended ? 1000 : CLOSE_WAIT_MS);
        CloseMs = GetTickCount() - Start;
        if (Wait == WAIT_OBJECT_0 + 1)
        {
            GetExitCodeProcess(Pi.hProcess, &ExitCode);
            ok(0, "%s: closer exited early with %lu\n", CaseName[Case], ExitCode);
        }
        if (Case == CaseCloseSourceSuspended)
        {
            /* Windows: the owner's last close waits for the request its own thread has in progress */
            ok(Wait == WAIT_TIMEOUT, "%s: close returned while the owner's thread waits inside a request (wait %lu)\n",
               CaseName[Case], Wait);
        }
        else
        {
            /* A process without requests on the file object does not wait for another process's request */
            ok(Wait == WAIT_OBJECT_0, "%s: close did not return within %u ms (wait %lu)\n",
               CaseName[Case], CLOSE_WAIT_MS, Wait);
        }
        trace("%s: close %s after %lu ms\n", CaseName[Case], Wait == WAIT_OBJECT_0 ? "returned" : "still blocked", CloseMs);

        /* Byte-range locks are per process: another process's close leaves the owner's range alone */
        OwnLockFree = TryLock(Locked, 16);
        if (OwnLockFree) UnlockFile(Locked, 16, 0, 1, 0);
        if (Case != CaseCloseSourceSuspended)
            ok(!OwnLockFree, "%s: the owner's range [16,17) was released by another process's close\n", CaseName[Case]);
        trace("%s: owner range [16,17) %s\n", CaseName[Case], OwnLockFree ? "free" : "locked");

        /* Let the waiter go: it gets [0,1) and leaves its request */
        if (Case != CaseDupBlocked) ResumeThread(Thread);
        ok(UnlockFile(Locked, 0, 0, 1, 0), "%s: UnlockFile failed with %lu\n", CaseName[Case], GetLastError());
        ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "%s: waiter did not finish\n", CaseName[Case]);
        ok(Waiter.Ret, "%s: waiter's lock failed with %lu\n", CaseName[Case], Waiter.Error);

        if (Wait != WAIT_OBJECT_0)
        {
            Start = GetTickCount();
            Wait = WaitForSingleObject(Done, 10000);
            trace("%s: close returned %lu ms after the waiter was released (wait %lu)\n", CaseName[Case],
                  GetTickCount() - Start, Wait);
            ok(Wait == WAIT_OBJECT_0, "%s: close did not return after the waiter was released\n", CaseName[Case]);
        }
        if (Case == CaseCloseSourceSuspended && Wait == WAIT_OBJECT_0)
        {
            /* The owner's last handle is gone: its ranges are released (LockFileEx documentation) */
            OwnLockFree = TryLock(Locked, 16);
            ok(OwnLockFree, "%s: the owner's range [16,17) is still locked after its last handle closed\n", CaseName[Case]);
            if (OwnLockFree) UnlockFile(Locked, 16, 0, 1, 0);
        }
        SetEvent(Exit);
        ok(WaitForSingleObject(Pi.hProcess, 10000) == WAIT_OBJECT_0, "%s: closer did not exit\n", CaseName[Case]);
        GetExitCodeProcess(Pi.hProcess, &ExitCode);
        ok(ExitCode == 0, "%s: closer exit code %lu\n", CaseName[Case], ExitCode);
        CloseHandle(Pi.hProcess);
        CloseHandle(Pi.hThread);
    }
    else
    {
        if (Case != CaseDupBlocked) ResumeThread(Thread);
        UnlockFile(Locked, 0, 0, 1, 0);
        WaitForSingleObject(Thread, 10000);
    }

    CloseHandle(Thread);
    CloseHandle(Done);
    CloseHandle(Exit);
    if (Case != CaseCloseSourceSuspended) CloseHandle(File);
    CloseHandle(Locked);
    ok(DeleteFileA(Path), "%s: DeleteFile failed with %lu\n", CaseName[Case], GetLastError());
}

START_TEST(FileCloseLockedDup)
{
    char **argv, Exe[MAX_PATH];
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 8 && !strcmp(argv[2], "closer"))
    {
        RunCloser(argc, argv);
        return;
    }

    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    RunCase(CaseDupBlocked, Exe);
    RunCase(CaseDupSuspended, Exe);
    RunCase(CaseCloseSourceSuspended, Exe);
}
