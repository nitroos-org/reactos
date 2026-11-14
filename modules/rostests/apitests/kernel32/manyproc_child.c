/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     An idle process for the ManyProcesses test
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Command line: the program name, a semaphore handle and an event handle (inherited, in hex). The process
 * releases the semaphore once, waits for the event and exits.
 */
#include <windows.h>

static
HANDLE
ParseHandle(
    _Inout_ PCWSTR *Text)
{
    ULONG_PTR Value = 0;
    PCWSTR p = *Text;

    while (*p == L' ')
        p++;
    for (;; p++)
    {
        if (*p >= L'0' && *p <= L'9')
            Value = (Value << 4) | (*p - L'0');
        else if (*p >= L'a' && *p <= L'f')
            Value = (Value << 4) | (*p - L'a' + 10);
        else if (*p >= L'A' && *p <= L'F')
            Value = (Value << 4) | (*p - L'A' + 10);
        else
            break;
    }
    *Text = p;
    return (HANDLE)Value;
}

void __cdecl mainCRTStartup(void)
{
    PCWSTR p = GetCommandLineW();
    HANDLE Semaphore, Event;

    /* Skip the program name, quoted or not */
    if (*p == L'"')
    {
        for (p++; *p && *p != L'"'; p++)
            ;
        if (*p)
            p++;
    }
    else
    {
        while (*p && *p != L' ')
            p++;
    }
    Semaphore = ParseHandle(&p);
    Event = ParseHandle(&p);
    ReleaseSemaphore(Semaphore, 1, NULL);
    WaitForSingleObject(Event, 180000);
    ExitProcess(0);
}
