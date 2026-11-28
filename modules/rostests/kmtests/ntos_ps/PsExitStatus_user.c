/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     PsExitStatus test, user-mode part: the exit status of a process whose last thread exits by itself
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * A child (psexitstatus_child.exe) starts a thread that returns 0. The driver holds that thread in its exit,
 * before it is counted out of the process, so it is the last thread of the child to exit. Then:
 * - TerminateProcess(7): the exit code is 7, not the 0 of the thread that was exiting by itself; until the
 *   last thread is gone the process still reports STILL_ACTIVE;
 * - TerminateProcess(7), then TerminateProcess(9): the first request decides: 7;
 * - ExitProcess(3) in the child, then TerminateProcess(7): 3, the status of the first request for the whole
 *   process;
 * - ExitThread(5) of the main thread and nothing else: nobody terminates the process, so the status of the
 *   last thread decides: 0.
 * When kmtest.exe is a 64-bit process, the same rows run with the i386 build of the child
 * (psexitstatus_child32.exe next to kmtest.exe), a WoW64 process.
 */

#include <kmt_test.h>
#include <stdlib.h>
#include "PsExitStatus.h"

#define WAIT_MS 10000

typedef enum _PSEXIT_ROW
{
    RowTerminate,
    RowTerminateTwice,
    RowExitProcess,
    RowExitThread
} PSEXIT_ROW;

static
VOID
RunRow(
    _In_ PCWSTR ChildPath,
    _In_ PSEXIT_ROW Row)
{
    static const PCWSTR Modes[] = { L"sleep", L"sleep", L"exitprocess", L"exitthread" };
    static const DWORD Codes[] = { 0, 0, 3, 5 };
    static const DWORD Expected[] = { 7, 7, 3, 0 };
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    WCHAR CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    PSEXIT_ARM Arm;
    ULONG HeldThread;
    DWORD Error, Length, Wait, ExitCode;
    HANDLE hGo;
    BOOL Released = FALSE;

    hGo = CreateEventW(&Sa, TRUE, FALSE, NULL);
    if (!hGo)
    {
        ok(0, "CreateEvent failed with %lu\n", GetLastError());
        return;
    }
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" %ls %lu %lu",
                    ChildPath, Modes[Row], HandleToULong(hGo), Codes[Row]);
    if (!CreateProcessW(ChildPath, CommandLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcess(%ls) failed with %lu\n", ChildPath, GetLastError());
        CloseHandle(hGo);
        return;
    }

    Arm.ProcessId = ProcessInfo.dwProcessId;
    Arm.SkipThreadId = ProcessInfo.dwThreadId;
    Length = 0;
    Error = KmtSendBufferToDriver(IOCTL_PSEXIT_ARM, &Arm, sizeof(Arm), &Length);
    ok_eq_int(Error, ERROR_SUCCESS);
    ResumeThread(ProcessInfo.hThread);

    /* The child's own thread is now held in its exit */
    HeldThread = WAIT_MS;
    Length = sizeof(HeldThread);
    Error = KmtSendBufferToDriver(IOCTL_PSEXIT_WAIT, &HeldThread, sizeof(HeldThread), &Length);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        goto Cleanup;
    ok(HeldThread != ProcessInfo.dwThreadId, "the main thread was held\n");

    switch (Row)
    {
        case RowTerminate:
            ok(TerminateProcess(ProcessInfo.hProcess, 7), "TerminateProcess failed with %lu\n", GetLastError());
            break;
        case RowTerminateTwice:
            ok(TerminateProcess(ProcessInfo.hProcess, 7), "TerminateProcess failed with %lu\n", GetLastError());
            ok(TerminateProcess(ProcessInfo.hProcess, 9), "TerminateProcess failed with %lu\n", GetLastError());
            break;
        case RowExitProcess:
        case RowExitThread:
            SetEvent(hGo);
            break;
    }

    /* The main thread is gone; the held thread is still counted in the process */
    Wait = WaitForSingleObject(ProcessInfo.hThread, WAIT_MS);
    ok_eq_ulong(Wait, WAIT_OBJECT_0);
    ExitCode = 0xdeadbeef;
    ok(GetExitCodeThread(ProcessInfo.hThread, &ExitCode), "GetExitCodeThread failed with %lu\n", GetLastError());
    ok_eq_ulong(ExitCode, Row == RowExitThread ? 5 : Row == RowExitProcess ? 3 : 7);
    if (Row == RowExitProcess)
    {
        /* Too late to decide: ExitProcess asked first */
        trace("TerminateProcess after ExitProcess: %d (%lu)\n",
              TerminateProcess(ProcessInfo.hProcess, 7), GetLastError());
    }
    Wait = WaitForSingleObject(ProcessInfo.hProcess, 0);
    ok_eq_ulong(Wait, WAIT_TIMEOUT);
    ExitCode = 0xdeadbeef;
    ok(GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode), "GetExitCodeProcess failed with %lu\n", GetLastError());
    ok_eq_ulong(ExitCode, STILL_ACTIVE);

    Length = 0;
    Error = KmtSendBufferToDriver(IOCTL_PSEXIT_RELEASE, NULL, 0, &Length);
    ok_eq_int(Error, ERROR_SUCCESS);
    Released = TRUE;

    Wait = WaitForSingleObject(ProcessInfo.hProcess, WAIT_MS);
    ok_eq_ulong(Wait, WAIT_OBJECT_0);
    ExitCode = 0xdeadbeef;
    ok(GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode), "GetExitCodeProcess failed with %lu\n", GetLastError());
    ok(ExitCode == Expected[Row], "%ls row %d: exit code %lu, expected %lu\n",
       ChildPath, Row, ExitCode, Expected[Row]);

Cleanup:
    if (!Released)
    {
        Length = 0;
        KmtSendBufferToDriver(IOCTL_PSEXIT_RELEASE, NULL, 0, &Length);
    }
    if (WaitForSingleObject(ProcessInfo.hProcess, 0) != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 0xdead);
        WaitForSingleObject(ProcessInfo.hProcess, WAIT_MS);
    }
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(hGo);
}

static
VOID
RunRows(
    _In_ PCWSTR ChildName,
    _In_ ULONG Rounds)
{
    WCHAR Path[MAX_PATH];
    PWCHAR Name;
    ULONG Round;
    int Row;

    if (!GetModuleFileNameW(NULL, Path, RTL_NUMBER_OF(Path)) || !(Name = wcsrchr(Path, L'\\')))
        return;
    StringCchCopyW(Name + 1, RTL_NUMBER_OF(Path) - (Name + 1 - Path), ChildName);
    if (skip(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "%ls is not there\n", Path))
        return;

    for (Round = 0; Round < Rounds; Round++)
    {
        for (Row = RowTerminate; Row <= RowExitThread; Row++)
            RunRow(Path, (PSEXIT_ROW)Row);
    }
}

START_TEST(PsExitStatus)
{
    DWORD Error;
    ULONG Rounds = 1;
    CHAR Buffer[16];

    /* PSEXIT_ROUNDS=<n> repeats the rows */
    if (GetEnvironmentVariableA("PSEXIT_ROUNDS", Buffer, sizeof(Buffer)) && atoi(Buffer) > 0)
        Rounds = atoi(Buffer);

    Error = KmtLoadAndOpenDriver(L"PsExitStatus", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
        return;

    RunRows(L"psexitstatus_child.exe", Rounds);
    if (sizeof(PVOID) == 8)
        RunRows(L"psexitstatus_child32.exe", Rounds);

    KmtCloseDriver();
    KmtUnloadDriver();
}
