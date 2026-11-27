/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Opening desktops by name while other threads create and close desktops
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A new desktop is linked into the list of its window station before its desktop information exists. The lookup of
 * a desktop by name walks that list: it must not meet a desktop that is not complete, and must not walk the list while
 * a thread changes it.
 */

#include "precomp.h"

#define OPENERS     2
#define CREATE_LOOPS 150
#define OPEN_LOOPS  4000

static volatile LONG g_Stop;
static volatile LONG g_Opened;
static volatile LONG g_BadError;

static DWORD WINAPI OpenerThread(LPVOID Param)
{
    WCHAR Name[64];
    ULONG i = 0;

    wsprintfW(Name, L"DesktopRace%lu_%lu", GetCurrentProcessId(), (ULONG)(ULONG_PTR)Param);
    while (!g_Stop || i < OPEN_LOOPS)
    {
        HDESK Desktop;

        SetLastError(0xDEADBEEF);
        Desktop = OpenDesktopW(Name, 0, FALSE, DESKTOP_READOBJECTS);
        if (Desktop)
        {
            InterlockedIncrement(&g_Opened);
            CloseDesktop(Desktop);
        }
        else if (GetLastError() == 0xDEADBEEF)
        {
            InterlockedIncrement(&g_BadError);
        }
        i++;
        if (g_Stop && i >= OPEN_LOOPS)
            break;
    }
    return 0;
}

START_TEST(DesktopOpenCreateRace)
{
    HANDLE Threads[OPENERS];
    WCHAR Name[64];
    ULONG i, Created = 0;

    /* Make this a GUI process */
    GetSystemMetrics(SM_CXSCREEN);

    for (i = 0; i < OPENERS; i++)
    {
        Threads[i] = CreateThread(NULL, 0, OpenerThread, (LPVOID)(ULONG_PTR)(i & 1), 0, NULL);
        ok(Threads[i] != NULL, "CreateThread failed, error %lu\n", GetLastError());
    }

    for (i = 0; i < CREATE_LOOPS; i++)
    {
        HDESK Desktop;

        /* The names the openers look for, alternating, and one of the creator's own */
        wsprintfW(Name, L"DesktopRace%lu_%lu", GetCurrentProcessId(), i & 1);
        Desktop = CreateDesktopW(Name, NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL);
        if (Desktop)
        {
            Created++;
            CloseDesktop(Desktop);
        }
    }
    g_Stop = 1;

    for (i = 0; i < OPENERS; i++)
    {
        if (Threads[i])
        {
            ok(WaitForSingleObject(Threads[i], 120000) == WAIT_OBJECT_0, "opener %lu did not end\n", i);
            CloseHandle(Threads[i]);
        }
    }

    ok(Created == CREATE_LOOPS, "%lu of %u desktops were created\n", Created, CREATE_LOOPS);
    ok(g_BadError == 0, "%ld failed opens left no error code\n", g_BadError);
    trace("opens that found the desktop: %ld\n", g_Opened);
}
