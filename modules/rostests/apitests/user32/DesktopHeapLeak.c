/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Creating and closing desktops any number of times does not exhaust the desktop heap
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every desktop has a heap of its own in session space. The heap goes away with the desktop,
 * when its last handle is closed: Windows creates and closes desktops without a limit. ReactOS
 * never gave the heap back and failed CreateDesktop with ERROR_NOT_ENOUGH_MEMORY after about 23.
 */

#include "precomp.h"

#define CYCLE_COUNT 200
#define CHILD_COUNT 30
#define SWITCH_COUNT 30

static HDESK
CreateTestDesktop(const char *Label, UINT i)
{
    WCHAR Name[64];
    HDESK Desktop;

    wsprintfW(Name, L"DesktopHeapLeak%lu_%u", GetCurrentProcessId(), i);
    SetLastError(0xDEADBEEF);
    Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    ok(Desktop != NULL, "%s: CreateDesktop failed for desktop %u, error %lu\n", Label, i, GetLastError());
    return Desktop;
}

static void
TestPlainCycles(void)
{
    UINT i;
    HDESK Desktop;

    for (i = 0; i < CYCLE_COUNT; i++)
    {
        Desktop = CreateTestDesktop("plain", i);
        if (Desktop == NULL)
            break;
        ok(CloseDesktop(Desktop), "plain: CloseDesktop failed for desktop %u, error %lu\n", i, GetLastError());
    }
    ok(i == CYCLE_COUNT, "plain: %u of %u cycles done\n", i, CYCLE_COUNT);
}

/* Run in a thread of its own: SetThreadDesktop fails for a thread that has windows */
static DWORD WINAPI
WindowThreadProc(LPVOID Param)
{
    HDESK OldDesktop = GetThreadDesktop(GetCurrentThreadId());
    UINT i;

    for (i = 0; i < CYCLE_COUNT; i++)
    {
        HDESK Desktop = CreateTestDesktop("window", i);
        HWND Window;

        if (Desktop == NULL)
            break;

        if (!SetThreadDesktop(Desktop))
        {
            ok(0, "window: SetThreadDesktop failed for desktop %u, error %lu\n", i, GetLastError());
            CloseDesktop(Desktop);
            break;
        }

        Window = CreateWindowExA(0, "STATIC", "heap", WS_POPUP | WS_VISIBLE, 0, 0, 50, 50,
                                 NULL, NULL, GetModuleHandleW(NULL), NULL);
        ok(Window != NULL, "window: CreateWindow failed on desktop %u, error %lu\n", i, GetLastError());
        if (Window)
            ok(DestroyWindow(Window), "window: DestroyWindow failed on desktop %u, error %lu\n", i, GetLastError());

        ok(SetThreadDesktop(OldDesktop), "window: SetThreadDesktop back failed for desktop %u, error %lu\n",
           i, GetLastError());
        ok(CloseDesktop(Desktop), "window: CloseDesktop failed for desktop %u, error %lu\n", i, GetLastError());
        if (Window == NULL)
            break;
    }
    ok(i == CYCLE_COUNT, "window: %u of %u cycles done\n", i, CYCLE_COUNT);
    return 0;
}

static void
TestWindowCycles(void)
{
    HANDLE Thread = CreateThread(NULL, 0, WindowThreadProc, NULL, 0, NULL);

    ok(Thread != NULL, "CreateThread failed, error %lu\n", GetLastError());
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
}

/* The desktop thread of the window manager follows the input desktop, it must not keep a desktop alive */
static void
TestSwitchCycles(void)
{
    HDESK InputDesktop = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    UINT i;

    if (InputDesktop == NULL)
    {
        skip("OpenInputDesktop failed, error %lu\n", GetLastError());
        return;
    }

    for (i = 0; i < SWITCH_COUNT; i++)
    {
        HDESK Desktop = CreateTestDesktop("switch", i);

        if (Desktop == NULL)
            break;

        if (!SwitchDesktop(Desktop))
        {
            skip("SwitchDesktop failed on desktop %u, error %lu\n", i, GetLastError());
            CloseDesktop(Desktop);
            break;
        }

        ok(SwitchDesktop(InputDesktop), "switch: SwitchDesktop back failed for desktop %u, error %lu\n", i, GetLastError());
        ok(CloseDesktop(Desktop), "switch: CloseDesktop failed for desktop %u, error %lu\n", i, GetLastError());
    }

    /* Desktops that are switched to must be given back too */
    for (i = 0; i < CYCLE_COUNT; i++)
    {
        HDESK Desktop = CreateTestDesktop("after switch", i);

        if (Desktop == NULL)
            break;
        ok(CloseDesktop(Desktop), "after switch: CloseDesktop failed for desktop %u, error %lu\n", i, GetLastError());
    }
    ok(i == CYCLE_COUNT, "after switch: %u of %u cycles done\n", i, CYCLE_COUNT);

    CloseDesktop(InputDesktop);
}

/*
 * A sandbox: the broker closes its handle once the child runs on the desktop, and the child
 * holds the last one. The child signals when it runs; ReactOS finds the desktop by its name
 * when the child starts, so the parent must not close it earlier.
 */
static void
TestChildCycles(void)
{
    CHAR Self[MAX_PATH];
    UINT i;

    GetModuleFileNameA(NULL, Self, sizeof(Self));

    for (i = 0; i < CHILD_COUNT; i++)
    {
        WCHAR Name[64];
        CHAR DesktopName[96], EventName[64], CommandLine[MAX_PATH + 100];
        STARTUPINFOA Startup = { sizeof(Startup) };
        PROCESS_INFORMATION Info;
        HDESK Desktop;
        HANDLE Ready;
        BOOL Created;

        wsprintfW(Name, L"DesktopHeapChild%lu_%u", GetCurrentProcessId(), i);
        wsprintfA(DesktopName, "WinSta0\\DesktopHeapChild%lu_%u", GetCurrentProcessId(), i);
        wsprintfA(EventName, "DesktopHeapChildReady%lu_%u", GetCurrentProcessId(), i);
        Ready = CreateEventA(NULL, TRUE, FALSE, EventName);
        ok(Ready != NULL, "child: CreateEvent failed, error %lu\n", GetLastError());
        if (Ready == NULL)
            break;

        SetLastError(0xDEADBEEF);
        Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        ok(Desktop != NULL, "child: CreateDesktop failed for desktop %u, error %lu\n", i, GetLastError());
        if (Desktop == NULL)
        {
            CloseHandle(Ready);
            break;
        }

        Startup.lpDesktop = DesktopName;
        wsprintfA(CommandLine, "\"%s\" DesktopHeapLeak child %s", Self, EventName);
        Created = CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Info);
        ok(Created, "child: CreateProcess failed on desktop %u, error %lu\n", i, GetLastError());
        if (Created)
        {
            ok(WaitForSingleObject(Ready, 30000) == WAIT_OBJECT_0, "child: process %u did not start\n", i);
            ok(CloseDesktop(Desktop), "child: CloseDesktop failed for desktop %u, error %lu\n", i, GetLastError());
            ok(WaitForSingleObject(Info.hProcess, 30000) == WAIT_OBJECT_0, "child: process %u did not exit\n", i);
            CloseHandle(Info.hThread);
            CloseHandle(Info.hProcess);
        }
        else
        {
            CloseDesktop(Desktop);
        }
        CloseHandle(Ready);
        if (!Created)
            break;
    }
    ok(i == CHILD_COUNT, "child: %u of %u cycles done\n", i, CHILD_COUNT);
}

START_TEST(DesktopHeapLeak)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    /* Make this a GUI process */
    GetSystemMetrics(SM_CXSCREEN);

    if (argc >= 4 && !strcmp(argv[2], "child"))
    {
        HANDLE Ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[3]);

        if (Ready)
        {
            SetEvent(Ready);
            CloseHandle(Ready);
        }
        /* Exit while the parent closes its handle: either one can be the last */
        Sleep(100);
        return;
    }

    TestPlainCycles();
    TestWindowCycles();
    TestSwitchCycles();
    TestChildCycles();
}
