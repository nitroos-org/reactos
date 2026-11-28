/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Opening desktops by name while other threads create and close desktops
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A new desktop is linked into the list of its window station before its desktop information exists. The lookup of
 * a desktop by name walks that list: it must not meet a desktop that is not complete, and must not walk the list while
 * a thread changes it. So does the enumeration of the desktops of the window station (EnumDesktops, NtUserBuildNameList):
 * every name it returns must be that of a complete desktop (not empty, not cut), the count in the buffer must match the
 * names, and the desktop that is never closed, the one of the calling thread, must be in every list.
 */

#include "precomp.h"

#define OPENERS     2
#define ENUMERATORS 2
#define CREATE_LOOPS 150
#define OPEN_LOOPS  4000
#define ENUM_LOOPS  500

static volatile LONG g_Stop;
static volatile LONG g_Opened;
static volatile LONG g_BadError;
static volatile LONG g_Enumerated;
static volatile LONG g_EnumBad;
static volatile LONG g_EnumFailed;

typedef struct
{
    WCHAR Current[64];
    ULONG Count;
    BOOL SawCurrent;
    BOOL BadName;
} ENUMCTX;

static BOOL CALLBACK EnumDesktopProc(LPWSTR Name, LPARAM Param)
{
    ENUMCTX *Context = (ENUMCTX *)Param;
    SIZE_T Length = wcsnlen(Name, 256);
    SIZE_T i;

    Context->Count++;

    if (Length == 0 || Length >= 255)
        Context->BadName = TRUE;
    for (i = 0; i < Length; i++)
    {
        if (Name[i] < L' ')
            Context->BadName = TRUE;
    }
    if (!_wcsicmp(Name, Context->Current))
        Context->SawCurrent = TRUE;
    return TRUE;
}

static DWORD WINAPI EnumeratorThread(LPVOID Param)
{
    ENUMCTX Context;
    HWINSTA Station = GetProcessWindowStation();
    HDESK Own = GetThreadDesktop(GetCurrentThreadId());
    ULONG i = 0, Needed;

    UNREFERENCED_PARAMETER(Param);
    if (!GetUserObjectInformationW(Own, UOI_NAME, Context.Current, sizeof(Context.Current), &Needed))
        Context.Current[0] = UNICODE_NULL;

    while (!g_Stop || i < ENUM_LOOPS)
    {
        BOOL Ret;

        Context.Count = 0;
        Context.SawCurrent = FALSE;
        Context.BadName = FALSE;
        Ret = EnumDesktopsW(Station, EnumDesktopProc, (LPARAM)&Context);
        if (!Ret)
            InterlockedIncrement(&g_EnumFailed);
        else if (Context.BadName || Context.Count == 0 || (Context.Current[0] && !Context.SawCurrent))
            InterlockedIncrement(&g_EnumBad);
        else
            InterlockedIncrement(&g_Enumerated);
        i++;
        if (g_Stop && i >= ENUM_LOOPS)
            break;
    }
    return 0;
}

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
    HANDLE Threads[OPENERS + ENUMERATORS];
    WCHAR Name[64];
    ULONG i, Created = 0;

    /* Make this a GUI process */
    GetSystemMetrics(SM_CXSCREEN);

    for (i = 0; i < OPENERS; i++)
    {
        Threads[i] = CreateThread(NULL, 0, OpenerThread, (LPVOID)(ULONG_PTR)(i & 1), 0, NULL);
        ok(Threads[i] != NULL, "CreateThread failed, error %lu\n", GetLastError());
    }
    for (; i < OPENERS + ENUMERATORS; i++)
    {
        Threads[i] = CreateThread(NULL, 0, EnumeratorThread, NULL, 0, NULL);
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

    for (i = 0; i < OPENERS + ENUMERATORS; i++)
    {
        if (Threads[i])
        {
            ok(WaitForSingleObject(Threads[i], 120000) == WAIT_OBJECT_0, "thread %lu did not end\n", i);
            CloseHandle(Threads[i]);
        }
    }

    ok(Created == CREATE_LOOPS, "%lu of %u desktops were created\n", Created, CREATE_LOOPS);
    ok(g_BadError == 0, "%ld failed opens left no error code\n", g_BadError);
    ok(g_EnumFailed == 0, "%ld enumerations failed\n", g_EnumFailed);
    ok(g_EnumBad == 0, "%ld enumerations returned an empty or cut name, no desktop, or lost the thread's own desktop\n", g_EnumBad);
    ok(g_Enumerated >= ENUMERATORS * ENUM_LOOPS, "only %ld enumerations ran\n", g_Enumerated);
    trace("opens that found the desktop: %ld, enumerations: %ld\n", g_Opened, g_Enumerated);
}
