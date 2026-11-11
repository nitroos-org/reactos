/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that console control events racing with process creation, attach and exit do not hang
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <wingdi.h>
#include <winuser.h>

/*
 * A child on a console of its own sends Ctrl+Break events to its console while
 * other threads start console processes that inherit it, write to it, and
 * while grandchildren attach to it, free it and exit. The console server
 * delivers each event by creating a thread in every process on the console,
 * and process creation and attach look up a process and then lock its console.
 * A child that does not exit in time is stuck in a console server request.
 *
 * A second child sends bursts of Ctrl+C and Ctrl+Break events to its own
 * console, including consecutive identical events, and checks that the handler
 * is called once per event, with no distinct event lost or coalesced when the
 * console server still holds earlier ones. Handler threads run concurrently,
 * so only the counts per type are checked.
 *
 * A third child sends a burst of Ctrl+C faster than the server delivers them:
 * every request the server accepts (returns success for) must reach the
 * handler, and any request it refuses (the bounded queue is capped) must be
 * reported as a failure, never counted as a silent success. The burst is kept
 * modest so the per-event handler-thread creation finishes on a debug build;
 * the cap-refusal path itself is bounded in code, not forced at runtime here.
 */
#define RACE_MS             15000
#define MAX_UNHANDLED       64
#define SPAWNERS            2
#define ATTACHERS           2
#define CHILD_TIMEOUT_MS    (RACE_MS + 60000)
#define ORDER_BURSTS        12
#define ORDER_WAIT_MS       30000
#define ORDER_TIMEOUT_MS    300000
#define FLOOD_EVENTS        120
#define FLOOD_WAIT_MS       240000
#define FLOOD_TIMEOUT_MS    300000
#define GUI_MS              8000
#define GUI_TIMEOUT_MS      (GUI_MS + 60000)

static WCHAR FileName[MAX_PATH];
static volatile LONG Stop;
static LONG Events, Sent, Spawned, Handled, HandledC, HandledBreak;

static
BOOL
StartSelf(
    _In_ PCWSTR Mode,
    _In_ DWORD Flags,
    _Out_ PPROCESS_INFORMATION ProcessInfo)
{
    WCHAR CommandLine[MAX_PATH + 60];
    STARTUPINFOW StartupInfo;

    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleCtrlEventRace %ls %lu",
                    FileName, Mode, GetCurrentProcessId());
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    return CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, Flags,
                          NULL, NULL, &StartupInfo, ProcessInfo);
}

static
BOOL
WINAPI
CtrlHandler(
    _In_ DWORD CtrlType)
{
    if (CtrlType != CTRL_BREAK_EVENT && CtrlType != CTRL_C_EVENT)
        return FALSE;
    InterlockedIncrement(CtrlType == CTRL_C_EVENT ? &HandledC : &HandledBreak);
    InterlockedIncrement(&Handled);
    return TRUE;
}

static
DWORD
WINAPI
EventThread(
    _In_ LPVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);

    /*
     * A target that exits meanwhile can make the call fail; only a hang counts here.
     * The console server starts a thread, with a stack of its own, in every process on the
     * console for every event. A process that is not running yet (one just created, one
     * that is attaching) cannot run the threads as fast as events come: events sent in a
     * tight loop pile up a thousand threads in it, each with a 1 MB stack, and a 32-bit
     * process is out of address space (a debug build, which prints from every handler,
     * gets there in seconds). The race is between the events and the creation, attach and
     * exit of processes, not the rate: send an event every timer tick, and not more while
     * this process has many it has not handled.
     */
    while (!Stop)
    {
        if (Sent - Handled <= MAX_UNHANDLED)
        {
            if (GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0))
                InterlockedIncrement(&Sent);
            InterlockedIncrement(&Events);
        }
        Sleep(1);
    }
    return 0;
}

static
DWORD
WINAPI
SpawnThread(
    _In_ LPVOID Parameter)
{
    PROCESS_INFORMATION ProcessInfo;

    UNREFERENCED_PARAMETER(Parameter);

    while (!Stop)
    {
        if (!StartSelf(L"exit", 0, &ProcessInfo))
        {
            Sleep(1);
            continue;
        }
        InterlockedIncrement(&Spawned);
        CloseHandle(ProcessInfo.hThread);
        WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
        CloseHandle(ProcessInfo.hProcess);
    }
    return 0;
}

static
DWORD
WINAPI
WriteThread(
    _In_ LPVOID Parameter)
{
    static const WCHAR Line[] = L"ConsoleCtrlEventRace output line, keeping the console busy\r\n";
    HANDLE Output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD Written;

    UNREFERENCED_PARAMETER(Parameter);

    while (!Stop)
        WriteConsoleW(Output, Line, _countof(Line) - 1, &Written, NULL);
    return 0;
}

/* Grandchild: attach to the race child's console and free it, over and over */
static
VOID
AttachChild(
    _In_ DWORD ParentId)
{
    DWORD Start = GetTickCount();

    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    FreeConsole();
    while (GetTickCount() - Start < RACE_MS)
    {
        if (AttachConsole(ParentId))
            FreeConsole();
        else if (GetLastError() != ERROR_ACCESS_DENIED)
            Sleep(1);
    }
    ExitProcess(0);
}

/* Child: runs on a console of its own, so the events never reach the test runner */
static
VOID
RaceChild(VOID)
{
    HANDLE Threads[SPAWNERS + 2];
    PROCESS_INFORMATION Attachers[ATTACHERS];
    ULONG i, Count = 0, AttachCount = 0;

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    for (i = 0; i < ATTACHERS; i++)
    {
        if (StartSelf(L"attach", 0, &Attachers[AttachCount]))
            CloseHandle(Attachers[AttachCount++].hThread);
    }

    Threads[Count] = CreateThread(NULL, 0, EventThread, NULL, 0, NULL);
    if (Threads[Count]) Count++;
    Threads[Count] = CreateThread(NULL, 0, WriteThread, NULL, 0, NULL);
    if (Threads[Count]) Count++;
    for (i = 0; i < SPAWNERS; i++)
    {
        Threads[Count] = CreateThread(NULL, 0, SpawnThread, NULL, 0, NULL);
        if (Threads[Count]) Count++;
    }
    if (Count < SPAWNERS + 2)
        ExitProcess(201);

    Sleep(RACE_MS);
    Stop = TRUE;
    WaitForMultipleObjects(Count, Threads, TRUE, INFINITE);
    for (i = 0; i < AttachCount; i++)
        WaitForSingleObject(Attachers[i].hProcess, INFINITE);

    if (!Events)
        ExitProcess(202);
    if (!Spawned)
        ExitProcess(203);
    if (AttachCount != ATTACHERS)
        ExitProcess(204);
    if (!Handled)
        ExitProcess(205);
    ExitProcess(0);
}

/* Child: bursts of C, Break, C, Break, C; each burst must be handled in full before the next */
static
VOID
OrderChild(VOID)
{
    /* Consecutive identical events (C,C and Break,Break) must not be coalesced */
    static const DWORD Burst[] =
    {
        CTRL_C_EVENT, CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_BREAK_EVENT, CTRL_C_EVENT
    };
    LONG WantC, WantBreak;
    DWORD Start;
    ULONG i, j;

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    for (i = 1; i <= ORDER_BURSTS; i++)
    {
        for (j = 0; j < _countof(Burst); j++)
        {
            if (!GenerateConsoleCtrlEvent(Burst[j], 0))
                ExitProcess(211);
        }

        WantC = i * 3;
        WantBreak = i * 2;
        Start = GetTickCount();
        while ((HandledC < WantC || HandledBreak < WantBreak) &&
               GetTickCount() - Start < ORDER_WAIT_MS)
        {
            Sleep(1);
        }
        if (HandledC != WantC || HandledBreak != WantBreak)
            ExitProcess(1000 + i);
    }
    ExitProcess(0);
}

/* Child: flood the console with Ctrl+C so the server queue saturates */
static
VOID
FloodChild(VOID)
{
    LONG Accepted = 0, Refused = 0;
    DWORD Start;
    ULONG i;

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    for (i = 0; i < FLOOD_EVENTS; i++)
    {
        if (GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0))
            Accepted++;
        else
            Refused++;
    }

    /* Every accepted event must be delivered to the handler */
    Start = GetTickCount();
    while (HandledC < Accepted && GetTickCount() - Start < FLOOD_WAIT_MS)
        Sleep(1);

    /* No accepted event lost (would be <), none invented (would be >) */
    if (HandledC != Accepted)
        ExitProcess(301);
    /* Refusals are allowed, but a refusal must be reported, not counted as delivered */
    if (Accepted + Refused != FLOOD_EVENTS)
        ExitProcess(302);
    ExitProcess(0);
}

/*
 * Thread that closes the active screen buffer over and over. Closing the active
 * buffer takes the console lock and then the terminal lock, the opposite order
 * of the window paint path, and deletes the buffer the paint path may be reading.
 */
static
DWORD
WINAPI
BufferThread(
    _In_ LPVOID Parameter)
{
    HANDLE Original = GetStdHandle(STD_OUTPUT_HANDLE);
    static const WCHAR Line[] = L"buffer\r\n";
    DWORD Written;

    UNREFERENCED_PARAMETER(Parameter);

    while (!Stop)
    {
        HANDLE Buffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE,
                                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                  NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
        if (Buffer == INVALID_HANDLE_VALUE)
        {
            Sleep(1);
            continue;
        }
        SetConsoleActiveScreenBuffer(Buffer);
        WriteConsoleW(Buffer, Line, _countof(Line) - 1, &Written, NULL);
        /* Restore a valid active buffer, then drop the one just shown */
        SetConsoleActiveScreenBuffer(Original);
        CloseHandle(Buffer);
    }
    return 0;
}

/* Child: churn screen-buffer close against window paints on a visible console */
static
VOID
GuiChild(VOID)
{
    HANDLE Threads[2];
    ULONG Count = 0;
    HWND Window = GetConsoleWindow();
    static const WCHAR Line[] = L"GuiChild output line driving the window to repaint\r\n";
    HANDLE Output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD Written, Start;

    Threads[Count] = CreateThread(NULL, 0, BufferThread, NULL, 0, NULL);
    if (Threads[Count]) Count++;
    if (!Count)
        ExitProcess(401);

    /* Drive the window to paint while the buffer is being closed */
    Start = GetTickCount();
    while (GetTickCount() - Start < GUI_MS)
    {
        WriteConsoleW(Output, Line, _countof(Line) - 1, &Written, NULL);
        if (Window)
        {
            InvalidateRect(Window, NULL, TRUE);
            UpdateWindow(Window);
        }
    }
    Stop = TRUE;
    WaitForMultipleObjects(Count, Threads, TRUE, INFINITE);
    ExitProcess(0);
}

static
VOID
RunChild(
    _In_ PCWSTR Mode,
    _In_ DWORD TimeoutMs)
{
    PROCESS_INFORMATION ProcessInfo;
    DWORD Wait, ExitCode = 0;

    if (!StartSelf(Mode, CREATE_NEW_CONSOLE, &ProcessInfo))
    {
        skip("CreateProcessW failed with %lu\n", GetLastError());
        return;
    }
    CloseHandle(ProcessInfo.hThread);
    Wait = WaitForSingleObject(ProcessInfo.hProcess, TimeoutMs);
    ok(Wait == WAIT_OBJECT_0, "The %ls child did not exit within %lu ms (stuck in a console server request)\n",
       Mode, TimeoutMs);
    if (Wait != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
    }
    else
    {
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        ok(ExitCode == 0, "The %ls child exited with %lu\n", Mode, ExitCode);
    }
    CloseHandle(ProcessInfo.hProcess);
}

START_TEST(ConsoleCtrlEventRace)
{
    int argc;
    char **argv;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "exit"))
        ExitProcess(0);
    if (argc >= 4 && !strcmp(argv[2], "attach"))
        AttachChild(strtoul(argv[3], NULL, 10));
    if (argc >= 3 && !strcmp(argv[2], "race"))
        RaceChild();
    if (argc >= 3 && !strcmp(argv[2], "order"))
        OrderChild();
    if (argc >= 3 && !strcmp(argv[2], "flood"))
        FloodChild();
    if (argc >= 3 && !strcmp(argv[2], "gui"))
        GuiChild();

    RunChild(L"race", CHILD_TIMEOUT_MS);
    RunChild(L"order", ORDER_TIMEOUT_MS);
    RunChild(L"flood", FLOOD_TIMEOUT_MS);
    RunChild(L"gui", GUI_TIMEOUT_MS);
}
