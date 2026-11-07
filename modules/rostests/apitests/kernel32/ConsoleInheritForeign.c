/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a new process joins only the console of its parent, not any console it names
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/pstypes.h>

/*
 * A console process starts with the console handle of its process parameters, which whoever created
 * the process wrote. The console server must let it join the console its creator had, and nothing
 * else: a handle of another console (another session or user) is refused and the process does not
 * start. Windows' console host attaches by a handle of its own driver, so the forged-handle part is
 * for ReactOS only; sharing the console of the parent and creating a new console must work on both.
 *
 * Test process -> "holder" (new console, reports its console handle) and "joiner" processes.
 */
#define CHILD_TIMEOUT_MS    30000
#define REFUSED_TIMEOUT_MS  15000

#ifndef SW_HIDE
#define SW_HIDE 0
#endif

static
VOID
RunHolder(
    _In_ PCWSTR MapName,
    _In_ PCWSTR ReadyName,
    _In_ PCWSTR StopName)
{
    HANDLE Map, Ready, Stop;
    ULONG_PTR *Value;

    Map = OpenFileMappingW(FILE_MAP_WRITE, FALSE, MapName);
    Ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, ReadyName);
    Stop = OpenEventW(SYNCHRONIZE, FALSE, StopName);
    if (!Map || !Ready || !Stop)
        ExitProcess(2);
    Value = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, sizeof(*Value));
    if (!Value || GetConsoleCP() == 0)
        ExitProcess(3);
    *Value = (ULONG_PTR)NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    SetEvent(Ready);
    WaitForSingleObject(Stop, CHILD_TIMEOUT_MS);
    ExitProcess(0);
}

static
VOID
RunJoiner(
    _In_ PCWSTR JoinedName)
{
    HANDLE Joined = OpenEventW(EVENT_MODIFY_STATE, FALSE, JoinedName);

    if (!Joined)
        ExitProcess(2);
    /* GetConsoleCP asks the console server, so it fails without a console */
    if (GetConsoleCP() == 0)
        ExitProcess(3);
    SetEvent(Joined);
    ExitProcess(0);
}

static
BOOL
StartChild(
    _In_ PCWSTR Role,
    _In_ PCWSTR Arg1,
    _In_opt_ PCWSTR Arg2,
    _In_opt_ PCWSTR Arg3,
    _In_ DWORD Flags,
    _Out_ PROCESS_INFORMATION *ProcessInfo)
{
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 200];
    STARTUPINFOW StartupInfo;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleInheritForeign %ls %ls %ls %ls",
                    FileName, Role, Arg1, Arg2 ? Arg2 : L"-", Arg3 ? Arg3 : L"-");
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = SW_HIDE;
    return CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, Flags, NULL, NULL, &StartupInfo, ProcessInfo);
}

/* Result of a joiner: 1 it joined and ran, 0 it did not start or did not run */
static
BOOL
RunJoinerProcess(
    _In_ HANDLE Joined,
    _In_ PCWSTR JoinedName,
    _In_ DWORD Flags,
    _In_opt_ HANDLE ForgedConsole,
    _In_ DWORD Timeout,
    _Out_ DWORD *ExitCode)
{
    PROCESS_INFORMATION ProcessInfo;
    PRTL_USER_PROCESS_PARAMETERS Params = NtCurrentPeb()->ProcessParameters;
    HANDLE Saved = Params->ConsoleHandle;
    HANDLE Waits[2];
    DWORD Wait;
    BOOL Started, Result;

    ResetEvent(Joined);
    *ExitCode = 0;
    if (ForgedConsole)
        Params->ConsoleHandle = ForgedConsole;
    Started = StartChild(L"joiner", JoinedName, NULL, NULL, Flags, &ProcessInfo);
    Params->ConsoleHandle = Saved;
    if (!Started)
        return FALSE;
    CloseHandle(ProcessInfo.hThread);

    Waits[0] = Joined;
    Waits[1] = ProcessInfo.hProcess;
    Wait = WaitForMultipleObjects(2, Waits, FALSE, Timeout);
    Result = (Wait == WAIT_OBJECT_0);
    if (WaitForSingleObject(ProcessInfo.hProcess, Result ? CHILD_TIMEOUT_MS : 0) != WAIT_OBJECT_0)
        TerminateProcess(ProcessInfo.hProcess, 99);
    WaitForSingleObject(ProcessInfo.hProcess, CHILD_TIMEOUT_MS);
    GetExitCodeProcess(ProcessInfo.hProcess, ExitCode);
    CloseHandle(ProcessInfo.hProcess);
    return Result;
}

START_TEST(ConsoleInheritForeign)
{
    int argc;
    char **argv;
    WCHAR MapName[64], ReadyName[64], StopName[64], JoinedName[64], Arg[3][64];
    PROCESS_INFORMATION Holder;
    HANDLE Map, Ready, Stop, Joined;
    ULONG_PTR *Value, Foreign;
    DWORD ExitCode;
    BOOL Ret;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 6 && (!strcmp(argv[2], "holder") || !strcmp(argv[2], "joiner")))
    {
        MultiByteToWideChar(CP_ACP, 0, argv[3], -1, Arg[0], _countof(Arg[0]));
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, Arg[1], _countof(Arg[1]));
        MultiByteToWideChar(CP_ACP, 0, argv[5], -1, Arg[2], _countof(Arg[2]));
        if (!strcmp(argv[2], "holder"))
            RunHolder(Arg[0], Arg[1], Arg[2]);
        RunJoiner(Arg[0]);
    }

    if (GetConsoleCP() == 0)
    {
        skip("The test process has no console\n");
        return;
    }

    StringCbPrintfW(MapName, sizeof(MapName), L"ConsoleInheritForeign_map_%lu", GetCurrentProcessId());
    StringCbPrintfW(ReadyName, sizeof(ReadyName), L"ConsoleInheritForeign_ready_%lu", GetCurrentProcessId());
    StringCbPrintfW(StopName, sizeof(StopName), L"ConsoleInheritForeign_stop_%lu", GetCurrentProcessId());
    StringCbPrintfW(JoinedName, sizeof(JoinedName), L"ConsoleInheritForeign_joined_%lu", GetCurrentProcessId());
    Map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(*Value), MapName);
    Ready = CreateEventW(NULL, TRUE, FALSE, ReadyName);
    Stop = CreateEventW(NULL, TRUE, FALSE, StopName);
    Joined = CreateEventW(NULL, TRUE, FALSE, JoinedName);
    ok(Map && Ready && Stop && Joined, "Creating the shared objects failed with %lu\n", GetLastError());
    if (!Map || !Ready || !Stop || !Joined)
        return;
    Value = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, sizeof(*Value));
    ok(Value != NULL, "MapViewOfFile failed with %lu\n", GetLastError());
    if (!Value)
        return;
    *Value = 0;

    /* a process that shares the console of its creator starts (control) */
    Ret = RunJoinerProcess(Joined, JoinedName, 0, NULL, CHILD_TIMEOUT_MS, &ExitCode);
    ok(Ret, "A process sharing the console of its creator did not start, exit code %08lx\n", ExitCode);

    /* and so does one that makes a console of its own */
    Ret = RunJoinerProcess(Joined, JoinedName, CREATE_NEW_CONSOLE, NULL, CHILD_TIMEOUT_MS, &ExitCode);
    ok(Ret, "A process with a console of its own did not start, exit code %08lx\n", ExitCode);

    if (!is_reactos())
    {
        skip("Forged console handles are for the ReactOS console server\n");
        goto Done;
    }

    /* a console of another process: a holder creates one and reports its handle */
    if (!StartChild(L"holder", MapName, ReadyName, StopName, CREATE_NEW_CONSOLE, &Holder))
    {
        skip("The console holder did not start: %lu\n", GetLastError());
        goto Done;
    }
    CloseHandle(Holder.hThread);
    ok(WaitForSingleObject(Ready, CHILD_TIMEOUT_MS) == WAIT_OBJECT_0, "The holder did not report its console\n");
    Foreign = *Value;
    if (!Foreign || (HANDLE)Foreign == NtCurrentPeb()->ProcessParameters->ConsoleHandle)
    {
        skip("The holder has no console of its own to name\n");
    }
    else
    {
        /* its handle in the process parameters of a new process is not that process' to use */
        Ret = RunJoinerProcess(Joined, JoinedName, 0, (HANDLE)Foreign, REFUSED_TIMEOUT_MS, &ExitCode);
        ok(!Ret, "A process joined the console of an unrelated process\n");
        ok(ExitCode != 0, "A process naming the console of an unrelated process ran to the end\n");

        /* the refusal leaves the creator's own console and the holder working */
        ok(GetConsoleCP() != 0, "The creator's console is gone after the refusal\n");
        Ret = RunJoinerProcess(Joined, JoinedName, 0, NULL, CHILD_TIMEOUT_MS, &ExitCode);
        ok(Ret, "A process sharing the console of its creator did not start after a refusal, exit code %08lx\n",
           ExitCode);
        ok(WaitForSingleObject(Holder.hProcess, 0) == WAIT_TIMEOUT, "The console holder is gone after the refusal\n");
    }

    SetEvent(Stop);
    WaitForSingleObject(Holder.hProcess, CHILD_TIMEOUT_MS);
    CloseHandle(Holder.hProcess);

Done:
    SetEvent(Stop);
    UnmapViewOfFile(Value);
    CloseHandle(Map);
    CloseHandle(Ready);
    CloseHandle(Stop);
    CloseHandle(Joined);
}
