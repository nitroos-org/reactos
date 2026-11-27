/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A process that never got win32k process info can hold a desktop handle and exit
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A child created with an inherited desktop handle, or given one with DuplicateHandle, and ended before it
 * ran (or in its first instants) has no win32k process info when its handle table is closed. Closing the
 * handle must not touch the process info of the current process or of any other, and the desktop must go
 * away when the last handle goes.
 */

#include "precomp.h"

#define CYCLES 40

enum { MODE_INHERIT_NEVER_RUN, MODE_DUPLICATE_NEVER_RUN, MODE_INHERIT_KILL_AT_ONCE, MODE_COUNT };

static BOOL
DesktopExists(PCWSTR Name)
{
    HDESK Desktop = OpenDesktopW(Name, 0, FALSE, DESKTOP_READOBJECTS);

    if (Desktop)
    {
        CloseDesktop(Desktop);
        return TRUE;
    }
    return FALSE;
}

static void
OneCycle(PCSTR Self, UINT Mode, UINT i)
{
    WCHAR Name[64];
    CHAR CommandLine[MAX_PATH + 64];
    SECURITY_ATTRIBUTES Attr = { sizeof(Attr), NULL, TRUE };
    STARTUPINFOA Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Info;
    HDESK Desktop;
    HANDLE Copy = NULL;
    DWORD Flags = CREATE_SUSPENDED;
    UINT n;

    wsprintfW(Name, L"DesktopNoPi%lu_%u_%u", GetCurrentProcessId(), Mode, i);
    Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, &Attr);
    ok(Desktop != NULL, "mode %u: CreateDesktop failed, error %lu\n", Mode, GetLastError());
    if (Desktop == NULL)
        return;

    wsprintfA(CommandLine, "\"%s\" DesktopHandleNoProcessInfo child", Self);
    if (!CreateProcessA(NULL, CommandLine, NULL, NULL, Mode != MODE_DUPLICATE_NEVER_RUN, Flags,
                        NULL, NULL, &Startup, &Info))
    {
        ok(0, "mode %u: CreateProcess failed, error %lu\n", Mode, GetLastError());
        CloseDesktop(Desktop);
        return;
    }

    if (Mode == MODE_DUPLICATE_NEVER_RUN)
    {
        /* Whether the duplicate is made is not the point: the child ends holding it, or without it */
        if (!DuplicateHandle(GetCurrentProcess(), Desktop, Info.hProcess, &Copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
            trace("mode %u: DuplicateHandle into the child failed, error %lu\n", Mode, GetLastError());
    }
    else if (Mode == MODE_INHERIT_KILL_AT_ONCE)
    {
        ResumeThread(Info.hThread);
    }

    ok(TerminateProcess(Info.hProcess, 0), "mode %u: TerminateProcess failed, error %lu\n", Mode, GetLastError());
    ok(WaitForSingleObject(Info.hProcess, 30000) == WAIT_OBJECT_0, "mode %u: child did not end\n", Mode);
    CloseHandle(Info.hThread);
    CloseHandle(Info.hProcess);

    ok(CloseDesktop(Desktop), "mode %u: CloseDesktop failed, error %lu\n", Mode, GetLastError());

    /* Nothing of the ended child holds the desktop: it is gone (the last reference can lag a little) */
    for (n = 0; n < 50 && DesktopExists(Name); n++)
        Sleep(100);
    ok(!DesktopExists(Name), "mode %u: the desktop is still there after every handle was closed\n", Mode);
}

START_TEST(DesktopHandleNoProcessInfo)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    CHAR Self[MAX_PATH];
    UINT Mode, i;

    /* Make this a GUI process */
    GetSystemMetrics(SM_CXSCREEN);

    if (argc >= 3 && !strcmp(argv[2], "child"))
    {
        Sleep(60000);
        return;
    }

    GetModuleFileNameA(NULL, Self, sizeof(Self));

    for (Mode = 0; Mode < MODE_COUNT; Mode++)
        for (i = 0; i < CYCLES; i++)
            OneCycle(Self, Mode, i);

    /* The process still has a working desktop heap and a window station */
    ok(GetProcessWindowStation() != NULL, "no window station after the cycles\n");
}
