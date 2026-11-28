/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that TerminateProcess decides the exit code while threads of the process exit by themselves
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The child keeps starting threads that return at once (ExitThread(0)); the parent terminates it with
 * TERMINATE_CODE at a moment of its choosing. Whichever thread of the child is the last to exit, the exit
 * code of the process must be TERMINATE_CODE, never the 0 of a thread that was exiting by itself.
 * Rounds: 300 by default, "kernel32_apitest TerminateProcessExitCode <rounds>" for more.
 */

#include "precomp.h"

#define TERMINATE_CODE 7
#define DEFAULT_ROUNDS 300
#define CHILD_TIMEOUT_MS 30000

static
DWORD
WINAPI
ReturnThread(
    _In_ PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    return 0;
}

static
DWORD
WINAPI
StarterThread(
    _In_ PVOID Parameter)
{
    HANDLE hThread;

    UNREFERENCED_PARAMETER(Parameter);
    for (;;)
    {
        hThread = CreateThread(NULL, 0, ReturnThread, NULL, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
        else
            Sleep(1);
    }
    return 0;
}

static
VOID
RunChild(
    _In_ HANDLE hReady)
{
    HANDLE hThread;

    /* Two starters: some thread of the process is nearly always on its way out by itself */
    hThread = CreateThread(NULL, 0, StarterThread, NULL, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
    SetEvent(hReady);
    StarterThread(NULL);
}

START_TEST(TerminateProcessExitCode)
{
    int argc;
    char **argv;
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
    HANDLE hReady;
    DWORD Wait, ExitCode, Delay;
    ULONG Rounds = DEFAULT_ROUNDS, Round, Done = 0, Wrong = 0, Hung = 0, Zero = 0;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        RunChild((HANDLE)(ULONG_PTR)strtoul(argv[3], NULL, 10));
        return;
    }
    if (argc >= 3)
    {
        Rounds = strtoul(argv[2], NULL, 10);
        if (!Rounds)
            Rounds = DEFAULT_ROUNDS;
    }

    hReady = CreateEventW(&Sa, FALSE, FALSE, NULL);
    if (!hReady)
    {
        skip("CreateEvent failed with %lu\n", GetLastError());
        return;
    }

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" TerminateProcessExitCode child %lu",
                    FileName, HandleToULong(hReady));

    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.dwFlags = STARTF_USESTDHANDLES;

    for (Round = 0; Round < Rounds; Round++)
    {
        if (!CreateProcessW(FileName, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
        {
            ok(0, "Round %lu: CreateProcess failed with %lu\n", Round, GetLastError());
            break;
        }
        CloseHandle(ProcessInfo.hThread);

        Wait = WaitForSingleObject(hReady, CHILD_TIMEOUT_MS);
        ok(Wait == WAIT_OBJECT_0, "Round %lu: the child did not start: %lu\n", Round, Wait);

        /* Let the child run its threads for 0-3 ms */
        Delay = Round % 4;
        if (Delay)
            Sleep(Delay - 1);

        ok(TerminateProcess(ProcessInfo.hProcess, TERMINATE_CODE),
           "Round %lu: TerminateProcess failed with %lu\n", Round, GetLastError());
        Wait = WaitForSingleObject(ProcessInfo.hProcess, CHILD_TIMEOUT_MS);
        if (Wait != WAIT_OBJECT_0)
        {
            ok(0, "Round %lu: the child did not end: %lu\n", Round, Wait);
            Hung++;
            CloseHandle(ProcessInfo.hProcess);
            break;
        }

        ExitCode = 0xdeadbeef;
        ok(GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode), "GetExitCodeProcess failed with %lu\n", GetLastError());
        if (ExitCode != TERMINATE_CODE)
        {
            if (Wrong < 10)
                ok(0, "Round %lu: exit code %lu, expected %u\n", Round, ExitCode, TERMINATE_CODE);
            Wrong++;
            if (!ExitCode)
                Zero++;
        }
        Done++;
        CloseHandle(ProcessInfo.hProcess);
    }

    ok(Wrong == 0, "%lu of %lu terminated children had another exit code (%lu of them 0)\n", Wrong, Done, Zero);
    trace("%lu rounds, %lu wrong exit codes (%lu of them 0), %lu hung\n", Done, Wrong, Zero, Hung);
    CloseHandle(hReady);
}
