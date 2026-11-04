/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     WoW64 native TEB restoration after a compatibility-mode segment reload
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* WoW64 native TEB restoration after a compatibility-mode segment reload. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

void SegmentReloadTrap(void);
void SegmentReloadResume(void);
static LONG Traps, Failures;

static LONG WINAPI Handler(EXCEPTION_POINTERS *Exception)
{
    if (Exception->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&Traps);
    Exception->ContextRecord->Eip = (DWORD)(ULONG_PTR)SegmentReloadResume;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI Worker(void *Argument)
{
    DWORD Id = GetCurrentThreadId(), Flags;
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    unsigned i;
    if (!Event) { InterlockedIncrement(&Failures); return 1; }
    for (i = 0; i < 32; ++i)
    {
        SegmentReloadTrap();
        if (GetCurrentThreadId() != Id || !GetHandleInformation(Event, &Flags) ||
            !SetEvent(Event) || WaitForSingleObject(Event, 1000) != WAIT_OBJECT_0)
            InterlockedIncrement(&Failures);
    }
    CloseHandle(Event);
    return 0;
}

int main(void)
{
    HANDLE Thread;
    PVOID Registration;
    setvbuf(stdout, NULL, _IONBF, 0);
    Registration = AddVectoredExceptionHandler(1, Handler);
    if (!Registration) return 2;
    printf("SEGMENT RETURN start\n");
    Worker(NULL);
    Thread = CreateThread(NULL, 0, Worker, NULL, 0, NULL);
    if (!Thread || WaitForSingleObject(Thread, 15000) != WAIT_OBJECT_0)
        ++Failures;
    if (Thread) CloseHandle(Thread);
    RemoveVectoredExceptionHandler(Registration);
    if (Traps != 64) ++Failures;
    printf("SEGMENT RETURN traps=%ld failures=%ld\n", Traps, Failures);
    return Failures ? 1 : 0;
}
