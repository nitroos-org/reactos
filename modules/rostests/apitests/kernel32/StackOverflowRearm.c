/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A stack overflow on a worker thread is raised again after the guard pages are armed again
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A language runtime that catches a stack overflow (the JVM, for instance) protects the lowest pages
 * of the stack itself, as guard pages, takes the overflow exception, lets the program unwind, and arms
 * the pages again. The pages are in the stack reservation, below the thread's stack limit: after the
 * first overflow the limit is at the bottom of the stack. The next overflow must raise
 * STATUS_STACK_OVERFLOW again, on the guard pages. If it does not, the thread runs on into the memory
 * below its stack: the JVM stack overflow tests ended the process with STATUS_GUARD_PAGE_VIOLATION.
 */

#include "precomp.h"
#include <pseh/pseh2.h>
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>

#ifdef _MSC_VER
#pragma warning(disable : 4717) // disable warning about recursive function
#elif defined(__GNUC__) && (__GNUC__ >= 12)
#pragma GCC diagnostic ignored "-Winfinite-recursion"
#endif

#define TEST_PAGE_SIZE 0x1000
#define ZONE_PAGES 4            /* the lowest pages of the stack that the runtime owns: 1 red, 3 yellow */
#define ROUNDS 4

typedef struct _ROUND
{
    BOOL Raised;
    ULONG Code;
    ULONG_PTR FaultAddress;
    ULONG_PTR FaultOffset;
    ULONG_PTR Limit;
} ROUND;

typedef struct _REARMCFG
{
    SIZE_T Reserve;
    DWORD Flags;
    BOOL Started;
    ULONG_PTR Bottom;
    ROUND Round[ROUNDS];
} REARMCFG;

static ULONG_PTR StopAddress;
static ULONG FilterCode;
static ULONG_PTR FilterFault;

static LONG
RecordFilter(PEXCEPTION_POINTERS Pointers)
{
    FilterCode = Pointers->ExceptionRecord->ExceptionCode;
    FilterFault = Pointers->ExceptionRecord->NumberParameters > 1 ?
                  Pointers->ExceptionRecord->ExceptionInformation[1] : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}

/* No tracing and no ok() in here: the frames are what uses the stack up */
static void
Recurse(ULONG Depth)
{
    volatile BYTE Buffer[0x500];
    ULONG Sum;

    Buffer[0] = (BYTE)Depth;
    Buffer[sizeof(Buffer) - 1] = (BYTE)Depth;
    if ((ULONG_PTR)&Buffer[0] > StopAddress)
        Recurse(Depth + 1);
    Sum = Buffer[0] + Buffer[sizeof(Buffer) - 1];
    Buffer[1] = (BYTE)Sum;
}

static DWORD WINAPI
RearmWorker(PVOID Param)
{
    REARMCFG *Cfg = Param;
    ULONG_PTR Bottom = (ULONG_PTR)NtCurrentTeb()->DeallocationStack;
    DWORD Old;
    ULONG i;

    Cfg->Bottom = Bottom;
    /* The lowest page is not used for frames: the recursion stops above it, if nothing is raised */
    StopAddress = Bottom + TEST_PAGE_SIZE + 0x700;

    /* The runtime commits its zone and protects it with guard pages at the thread start */
    if (!VirtualAlloc((PVOID)Bottom, ZONE_PAGES * TEST_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE) ||
        !VirtualProtect((PVOID)Bottom, ZONE_PAGES * TEST_PAGE_SIZE, PAGE_READWRITE | PAGE_GUARD, &Old))
        return 0;
    Cfg->Started = TRUE;

    for (i = 0; i < ROUNDS; i++)
    {
        ULONG Code = 0;
        ULONG_PTR Fault = 0;

        if (i > 0)
        {
            /* The overflow was taken and the stack unwound: arm the yellow pages again */
            VirtualProtect((PVOID)(Bottom + TEST_PAGE_SIZE), (ZONE_PAGES - 1) * TEST_PAGE_SIZE,
                           PAGE_READWRITE | PAGE_GUARD, &Old);
        }

        _SEH2_TRY
        {
            Recurse(0);
        }
        _SEH2_EXCEPT(RecordFilter(_SEH2_GetExceptionInformation()))
        {
            Code = FilterCode;
            Fault = FilterFault;
        }
        _SEH2_END;

        Cfg->Round[i].Raised = Code != 0;
        Cfg->Round[i].Code = Code;
        Cfg->Round[i].FaultAddress = Fault;
        Cfg->Round[i].FaultOffset = Fault ? Fault - Bottom : 0;
        Cfg->Round[i].Limit = (ULONG_PTR)NtCurrentTeb()->NtTib.StackLimit;
    }
    return 0x7e57;
}

static void
CheckRearm(SIZE_T Reserve, DWORD Flags)
{
    REARMCFG Cfg;
    HANDLE Thread;
    DWORD Exit = 0;
    ULONG i;

    memset(&Cfg, 0, sizeof(Cfg));
    Cfg.Reserve = Reserve;
    Cfg.Flags = Flags;
    Thread = CreateThread(NULL, Reserve, RearmWorker, &Cfg, Flags, NULL);
    ok(Thread != NULL, "CreateThread(%lx, %lx) failed, error %lu\n", (ULONG)Reserve, Flags, GetLastError());
    if (!Thread)
        return;
    ok(WaitForSingleObject(Thread, 120000) == WAIT_OBJECT_0, "The thread did not end\n");
    GetExitCodeThread(Thread, &Exit);
    CloseHandle(Thread);

    ok(Cfg.Started, "reserve %lx: the stack zone could not be set up\n", (ULONG)Reserve);
    if (!Cfg.Started)
        return;
    ok(Exit == 0x7e57, "reserve %lx: the thread ended with 0x%lx\n", (ULONG)Reserve, Exit);

    for (i = 0; i < ROUNDS; i++)
    {
        trace("reserve %lx round %lu: raised %d code %lx at bottom+%Ix, limit bottom+%Ix\n", (ULONG)Reserve, i,
              Cfg.Round[i].Raised, Cfg.Round[i].Code, Cfg.Round[i].FaultOffset,
              Cfg.Round[i].Limit - Cfg.Bottom);
        ok(Cfg.Round[i].Raised, "reserve %lx round %lu: the overflow was not raised, the stack ran on to the bottom\n",
           (ULONG)Reserve, i);
        if (!Cfg.Round[i].Raised)
            continue;
        ok(Cfg.Round[i].Code == STATUS_STACK_OVERFLOW, "reserve %lx round %lu: exception %lx\n",
           (ULONG)Reserve, i, Cfg.Round[i].Code);
        /* Windows 10 raises it from the highest yellow page, the third above the bottom */
        ok(Cfg.Round[i].FaultAddress >= Cfg.Bottom + (ZONE_PAGES - 1) * TEST_PAGE_SIZE &&
           Cfg.Round[i].FaultAddress < Cfg.Bottom + ZONE_PAGES * TEST_PAGE_SIZE,
           "reserve %lx round %lu: raised at bottom+%Ix\n", (ULONG)Reserve, i, Cfg.Round[i].FaultOffset);
    }
}

START_TEST(StackOverflowRearm)
{
    CheckRearm(0x80000, STACK_SIZE_PARAM_IS_A_RESERVATION);
    CheckRearm(0, 0);
}
