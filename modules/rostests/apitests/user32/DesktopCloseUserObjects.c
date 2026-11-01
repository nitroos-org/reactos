/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Closing a desktop frees its windows, also after the desktop was the input desktop
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The desktop window and the message window of a desktop belong to CSRSS (the desktop thread)
 * and go away with the desktop. ReactOS kept the desktop window of every desktop that had been
 * switched away from: one USER object per desktop, until the 4096 USER handles of the session
 * were used up and CreateWindow failed in every process (ERROR_NO_SYSTEM_RESOURCES).
 * The CSRSS USER object count is read with GetGuiResources; the test is skipped where CSRSS
 * cannot be opened (Windows protects it).
 */

#include "precomp.h"
#include <tlhelp32.h>

#define CYCLE_COUNT 50
/* Allowed growth over CYCLE_COUNT desktops: unrelated CSRSS activity, not one per desktop */
#define SLACK 5

static HANDLE
OpenCsrss(void)
{
    HANDLE Token, Snapshot, Process = NULL;
    TOKEN_PRIVILEGES Privileges;
    PROCESSENTRY32W Entry;
    DWORD MySession = 0, Session;
    BOOL More;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
    {
        Privileges.PrivilegeCount = 1;
        Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Privileges.Privileges[0].Luid))
            AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL);
        CloseHandle(Token);
    }

    ProcessIdToSessionId(GetCurrentProcessId(), &MySession);
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return NULL;

    Entry.dwSize = sizeof(Entry);
    for (More = Process32FirstW(Snapshot, &Entry); More && !Process; More = Process32NextW(Snapshot, &Entry))
    {
        if (_wcsicmp(Entry.szExeFile, L"csrss.exe") != 0)
            continue;
        Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Entry.th32ProcessID);
        if (!Process)
            Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Entry.th32ProcessID);
        if (!Process)
            continue;
        if ((ProcessIdToSessionId(Entry.th32ProcessID, &Session) && Session != MySession) ||
            GetGuiResources(Process, GR_USEROBJECTS) == 0)
        {
            CloseHandle(Process);
            Process = NULL;
        }
    }
    CloseHandle(Snapshot);
    return Process;
}

static HDESK
CreateTestDesktop(const char *Label, UINT i)
{
    WCHAR Name[64];
    HDESK Desktop;

    wsprintfW(Name, L"DesktopCloseUserObjects%lu_%u", GetCurrentProcessId(), i);
    SetLastError(0xDEADBEEF);
    Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
    ok(Desktop != NULL, "%s: CreateDesktop failed for desktop %u, error %lu\n", Label, i, GetLastError());
    return Desktop;
}

static void
TestCycles(HANDLE Csrss, HDESK InputDesktop, BOOL Switch)
{
    const char *Label = Switch ? "switch" : "plain";
    DWORD Before, After;
    UINT i;

    Before = GetGuiResources(Csrss, GR_USEROBJECTS);
    for (i = 0; i < CYCLE_COUNT; i++)
    {
        HDESK Desktop = CreateTestDesktop(Label, i);

        if (Desktop == NULL)
            break;

        if (Switch)
        {
            if (!SwitchDesktop(Desktop))
            {
                skip("SwitchDesktop failed on desktop %u, error %lu\n", i, GetLastError());
                CloseDesktop(Desktop);
                return;
            }
            ok(SwitchDesktop(InputDesktop), "%s: SwitchDesktop back failed for desktop %u, error %lu\n",
               Label, i, GetLastError());
        }

        ok(CloseDesktop(Desktop), "%s: CloseDesktop failed for desktop %u, error %lu\n", Label, i, GetLastError());
    }
    ok(i == CYCLE_COUNT, "%s: %u of %u cycles done\n", Label, i, CYCLE_COUNT);

    /* Give the desktop thread time to process the switches */
    Sleep(500);
    After = GetGuiResources(Csrss, GR_USEROBJECTS);
    trace("%s: CSRSS USER objects %lu before, %lu after %u desktops\n", Label, Before, After, i);
    ok(After <= Before + SLACK, "%s: CSRSS USER objects grew from %lu to %lu over %u desktops\n",
       Label, Before, After, i);
}

START_TEST(DesktopCloseUserObjects)
{
    HDESK InputDesktop;
    HANDLE Csrss;

    /* Make this a GUI process */
    GetSystemMetrics(SM_CXSCREEN);

    Csrss = OpenCsrss();
    if (Csrss == NULL)
    {
        skip("Cannot read the USER object count of CSRSS\n");
        return;
    }

    TestCycles(Csrss, NULL, FALSE);

    InputDesktop = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (InputDesktop == NULL)
    {
        skip("OpenInputDesktop failed, error %lu\n", GetLastError());
    }
    else
    {
        TestCycles(Csrss, InputDesktop, TRUE);
        CloseDesktop(InputDesktop);
    }

    CloseHandle(Csrss);
}
