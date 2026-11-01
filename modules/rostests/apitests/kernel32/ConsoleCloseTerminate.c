/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that closing a console window ends the attached processes, and when
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winuser.h>

/*
 * Closing a console window sends CTRL_CLOSE_EVENT to the processes on the console.
 * Windows then ends each process with STATUS_CONTROL_C_EXIT: at once when its
 * handler takes the event (returns TRUE) or declines it (the default handler),
 * when the handler returns, or after 5 seconds when the handler is still running
 * (it sleeps or never returns). Measured on Windows 10 22H2: a handler that
 * returns TRUE ends the process 2 ms after the window message, one that sleeps
 * 2 s after 2017 ms, one that sleeps 30 s or never returns after 5001 to 5016 ms;
 * the exit code is 0xC000013A in every case, and Alt+F4 acts like WM_CLOSE.
 *
 * Each case runs in a child on a console of its own. The child signals a named
 * event just before it posts WM_CLOSE to its console window; this process times
 * the child's exit from that signal.
 *
 * A handler that faults runs in the control thread the console server started in
 * the process. That thread is started like any other thread: the exception goes
 * to the unhandled exception filter, which runs, and then the process ends with
 * the exception code, at once (kernel32's BaseThreadStartup; under WoW64 the
 * thread is a guest thread entered through the same code). Measured on Windows
 * 10 22H2, a 32-bit and a 64-bit process alike: STATUS_ACCESS_VIOLATION 2 ms
 * after the window message, the filter run on the handler's thread 1 ms after the
 * handler started, whether the filter returns EXECUTE_HANDLER or CONTINUE_SEARCH,
 * and with no filter and the error box off. The exit code is the exception's,
 * not STATUS_CONTROL_C_EXIT.
 */
#define FAST_MAX_MS         2000
#define TIMEOUT_MIN_MS      4500
#define TIMEOUT_MAX_MS      8000
#define SLEEP_MS            2000
#define CHILD_TIMEOUT_MS    30000

static WCHAR FileName[MAX_PATH];
static DWORD HandlerMode;
static HANDLE FilterEvent;

enum { MODE_TRUE, MODE_FALSE, MODE_SLEEP, MODE_HANG, MODE_FAULT, MODE_FAULT_SEARCH, MODE_FAULT_NOFILTER };

/* Unhandled exception filter of the fault cases: tells the parent that it ran */
static
LONG
WINAPI
FaultFilter(
    _In_ PEXCEPTION_POINTERS ExceptionInfo)
{
    if (FilterEvent)
        SetEvent(FilterEvent);
    return (HandlerMode == MODE_FAULT) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

static
BOOL
WINAPI
CloseHandler(
    _In_ DWORD CtrlType)
{
    if (CtrlType != CTRL_CLOSE_EVENT)
        return FALSE;

    switch (HandlerMode)
    {
        case MODE_TRUE:
            return TRUE;
        case MODE_SLEEP:
            Sleep(SLEEP_MS);
            return TRUE;
        case MODE_HANG:
            /* longer than the child timeout, and then returning FALSE would exit the process by itself */
            Sleep(10 * CHILD_TIMEOUT_MS);
            return TRUE;
        case MODE_FAULT:
        case MODE_FAULT_SEARCH:
        case MODE_FAULT_NOFILTER:
            *(volatile int *)NULL = 1;
            return TRUE;
        default:
            return FALSE;
    }
}

/* Child: register a handler, tell the parent, close the console window (or send Alt+F4 to it) */
static
VOID
CloseChild(
    _In_ DWORD Mode,
    _In_ BOOL AltF4,
    _In_ PCWSTR EventName)
{
    HWND Window = GetConsoleWindow();
    HANDLE Event = OpenEventW(EVENT_MODIFY_STATE, FALSE, EventName);
    WCHAR FilterName[80];

    if (!Window || !Event)
        ExitProcess(1);
    HandlerMode = Mode;
    if (Mode >= MODE_FAULT)
    {
        StringCbPrintfW(FilterName, sizeof(FilterName), L"%ls_filter", EventName);
        FilterEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, FilterName);
        if (!FilterEvent)
            ExitProcess(5);
        /* No error box for the cases that reach the default filter */
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        if (Mode != MODE_FAULT_NOFILTER)
            SetUnhandledExceptionFilter(FaultFilter);
    }
    SetConsoleCtrlHandler(CloseHandler, TRUE);
    if (AltF4)
    {
        /* The keys go to the foreground window; give up quietly when the console cannot be it */
        SetForegroundWindow(Window);
        Sleep(500);
        if (GetForegroundWindow() != Window)
            ExitProcess(4);
        SetEvent(Event);
        keybd_event(VK_MENU, 0x38, 0, 0);
        keybd_event(VK_F4, 0x3E, 0, 0);
        keybd_event(VK_F4, 0x3E, KEYEVENTF_KEYUP, 0);
        keybd_event(VK_MENU, 0x38, KEYEVENTF_KEYUP, 0);
    }
    else
    {
        SetEvent(Event);
        if (!PostMessageW(Window, WM_CLOSE, 0, 0))
            ExitProcess(2);
    }
    Sleep(10 * CHILD_TIMEOUT_MS);
    ExitProcess(3);
}

static
VOID
RunCase(
    _In_ PCWSTR Name,
    _In_ PCSTR Mode,
    _In_ BOOL AltF4,
    _In_ DWORD MinMs,
    _In_ DWORD MaxMs,
    _In_ DWORD ExpectedExit,
    _In_ BOOL ExpectFilter)
{
    WCHAR CommandLine[MAX_PATH + 100];
    WCHAR EventName[64];
    WCHAR FilterName[80];
    HANDLE Filter = NULL;
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    HANDLE Event;
    LARGE_INTEGER Frequency, Start, End;
    DWORD Wait, ExitCode = 0, ElapsedMs;

    StringCbPrintfW(EventName, sizeof(EventName), L"ConsoleCloseTerminate_%lu_%ls", GetCurrentProcessId(), Name);
    Event = CreateEventW(NULL, TRUE, FALSE, EventName);
    ok(Event != NULL, "CreateEventW failed with %lu\n", GetLastError());
    if (!Event)
        return;
    StringCbPrintfW(FilterName, sizeof(FilterName), L"%ls_filter", EventName);
    Filter = CreateEventW(NULL, TRUE, FALSE, FilterName);
    ok(Filter != NULL, "CreateEventW failed with %lu\n", GetLastError());
    if (!Filter)
    {
        CloseHandle(Event);
        return;
    }

    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" ConsoleCloseTerminate %hs %d %ls",
                    FileName, Mode, AltF4, EventName);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                        NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        skip("CreateProcessW failed with %lu\n", GetLastError());
        CloseHandle(Filter);
        CloseHandle(Event);
        return;
    }
    CloseHandle(ProcessInfo.hThread);

    Wait = WaitForSingleObject(Event, CHILD_TIMEOUT_MS);
    QueryPerformanceCounter(&Start);
    if (Wait != WAIT_OBJECT_0)
    {
        /* the child ended before it signalled (no console window, or no foreground for Alt+F4) */
        Wait = WaitForSingleObject(ProcessInfo.hProcess, 0);
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        if (Wait == WAIT_OBJECT_0 && ExitCode == 4)
            skip("%ls: the console window cannot be the foreground window\n", Name);
        else
            ok(0, "%ls: the child did not start its test, exit %lu\n", Name, ExitCode);
        if (Wait != WAIT_OBJECT_0)
            TerminateProcess(ProcessInfo.hProcess, 1);
        goto Done;
    }

    Wait = WaitForSingleObject(ProcessInfo.hProcess, CHILD_TIMEOUT_MS);
    QueryPerformanceCounter(&End);
    QueryPerformanceFrequency(&Frequency);
    ElapsedMs = (DWORD)((End.QuadPart - Start.QuadPart) * 1000 / Frequency.QuadPart);

    ok(Wait == WAIT_OBJECT_0, "%ls: the process was still running %lu ms after its console window was closed\n",
       Name, CHILD_TIMEOUT_MS);
    if (Wait != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
        goto Done;
    }

    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    ok(ExitCode == ExpectedExit, "%ls: exit code 0x%lx, expected 0x%lx\n",
       Name, ExitCode, ExpectedExit);
    Wait = WaitForSingleObject(Filter, 0);
    ok((Wait == WAIT_OBJECT_0) == ExpectFilter, "%ls: the unhandled exception filter %s, expected %s\n",
       Name, (Wait == WAIT_OBJECT_0) ? "ran" : "did not run", ExpectFilter ? "to run" : "not to run");
    ok(ElapsedMs >= MinMs && ElapsedMs <= MaxMs, "%ls: the process ended %lu ms after the close, expected %lu to %lu ms\n",
       Name, ElapsedMs, MinMs, MaxMs);

Done:
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(Filter);
    CloseHandle(Event);
}

START_TEST(ConsoleCloseTerminate)
{
    int argc;
    char **argv;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5)
    {
        WCHAR EventName[64];
        DWORD Mode = MODE_FALSE;

        if (!strcmp(argv[2], "true"))
            Mode = MODE_TRUE;
        else if (!strcmp(argv[2], "sleep"))
            Mode = MODE_SLEEP;
        else if (!strcmp(argv[2], "hang"))
            Mode = MODE_HANG;
        else if (!strcmp(argv[2], "fault"))
            Mode = MODE_FAULT;
        else if (!strcmp(argv[2], "faultsearch"))
            Mode = MODE_FAULT_SEARCH;
        else if (!strcmp(argv[2], "faultnofilter"))
            Mode = MODE_FAULT_NOFILTER;
        MultiByteToWideChar(CP_ACP, 0, argv[4], -1, EventName, _countof(EventName));
        CloseChild(Mode, atoi(argv[3]), EventName);
    }

    /* A handler that takes the event, and the default handler, end the process at once */
    RunCase(L"true", "true", FALSE, 0, FAST_MAX_MS, STATUS_CONTROL_C_EXIT, FALSE);
    RunCase(L"false", "false", FALSE, 0, FAST_MAX_MS, STATUS_CONTROL_C_EXIT, FALSE);
    /* A handler that returns ends it when it returns */
    RunCase(L"sleep", "sleep", FALSE, SLEEP_MS - 200, SLEEP_MS + FAST_MAX_MS, STATUS_CONTROL_C_EXIT, FALSE);
    /* A handler still running after the timeout does not keep the process alive */
    RunCase(L"hang", "hang", FALSE, TIMEOUT_MIN_MS, TIMEOUT_MAX_MS, STATUS_CONTROL_C_EXIT, FALSE);
    /* Alt+F4 closes the window like WM_CLOSE */
    RunCase(L"altf4", "true", TRUE, 0, FAST_MAX_MS, STATUS_CONTROL_C_EXIT, FALSE);
    /* A handler that faults: the filter runs, then the process ends with the exception code at once */
    RunCase(L"fault", "fault", FALSE, 0, FAST_MAX_MS, STATUS_ACCESS_VIOLATION, TRUE);
    RunCase(L"faultsearch", "faultsearch", FALSE, 0, FAST_MAX_MS, STATUS_ACCESS_VIOLATION, TRUE);
    RunCase(L"faultnofilter", "faultnofilter", FALSE, 0, FAST_MAX_MS, STATUS_ACCESS_VIOLATION, FALSE);
}
