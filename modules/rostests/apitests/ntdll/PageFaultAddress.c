/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     An access violation reports the address that faulted while other threads take page faults
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Some threads read a no-access page and write a read-only page, each fault caught by an exception handler that
   checks the access type and the address in the exception record (ExceptionInformation[0] and [1]). Other threads
   commit memory, touch every page of it and release it again, so that page faults at other addresses happen on
   every processor meanwhile. The kernel used to read CR2 again after the page fault handler, which ran with
   interrupts enabled and could wait: a page fault of another thread on the same processor had changed it by then,
   and the access violation named that thread's address. Programs that tell a deliberate fault by its address
   then crash: the JVM's safepoint poll faults on its polling page, and it took the wrong address for a real access
   violation in compiled Java code. */

#define RUN_MS          4000
#define MAX_RUN_MS      120000
#define MAX_THREADS     16
/* Where one processor runs the fault threads and the noise threads in turn, only some of the faults happen while
   another thread's page fault is in flight on it. The run lasts until this many faults were caught and the noise
   threads have touched this many pages, so that a kernel that reads the address late cannot get through by luck.
   A run that is too slow to get there (a checked kernel) is skipped, not passed. */
#define MIN_FAULTS      1000000
#define MIN_TOUCHES     200000

static PUCHAR NoAccessPage, ReadOnlyPage;
static volatile LONG Stop;
static volatile LONG Faults, Touches, WrongAddress, WrongType;
static volatile ULONG_PTR FirstWrong;

static LONG CheckFault(PEXCEPTION_POINTERS Pointers, PVOID Address, ULONG_PTR Type)
{
    PEXCEPTION_RECORD Record = Pointers->ExceptionRecord;

    if (Record->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    InterlockedIncrement(&Faults);
    if (Record->NumberParameters < 2 || Record->ExceptionInformation[1] != (ULONG_PTR)Address)
    {
        if (InterlockedIncrement(&WrongAddress) == 1)
            FirstWrong = Record->NumberParameters < 2 ? 0 : Record->ExceptionInformation[1];
    }
    else if (Record->ExceptionInformation[0] != Type)
    {
        InterlockedIncrement(&WrongType);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD WINAPI FaultThread(PVOID Parameter)
{
    ULONG Round = 0;

    while (!Stop)
    {
        /* Different offsets in the page, so that the full address is compared */
        PUCHAR Read = NoAccessPage + (Round * 8 % PAGE_SIZE);
        PUCHAR Write = ReadOnlyPage + ((Round * 8 + 4) % PAGE_SIZE);

        _SEH2_TRY
        {
            (void)*(volatile LONG *)Read;
        }
        _SEH2_EXCEPT(CheckFault(_SEH2_GetExceptionInformation(), Read, 0))
        {
        }
        _SEH2_END;

        _SEH2_TRY
        {
            *(volatile LONG *)Write = 1;
        }
        _SEH2_EXCEPT(CheckFault(_SEH2_GetExceptionInformation(), Write, 1))
        {
        }
        _SEH2_END;

        Round++;
    }
    return 0;
}

static DWORD WINAPI NoiseThread(PVOID Parameter)
{
    while (!Stop)
    {
        volatile UCHAR *Memory = VirtualAlloc(NULL, 64 * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ULONG i;

        if (!Memory)
            continue;
        for (i = 0; i < 64; i++)
            Memory[i * PAGE_SIZE] = 1;
        InterlockedExchangeAdd(&Touches, 64);
        VirtualFree((PVOID)Memory, 0, MEM_RELEASE);
    }
    return 0;
}

START_TEST(PageFaultAddress)
{
    SYSTEM_INFO SystemInfo;
    HANDLE Threads[2 * MAX_THREADS];
    ULONG Count, ThreadCount = 0, i;
    DWORD OldProtect, Start, Elapsed;
    BOOL Ended;

    GetSystemInfo(&SystemInfo);
    Count = min(max(2 * SystemInfo.dwNumberOfProcessors, 2), MAX_THREADS);

    NoAccessPage = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
    ReadOnlyPage = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(NoAccessPage != NULL && ReadOnlyPage != NULL, "VirtualAlloc failed: %lu\n", GetLastError());
    if (!NoAccessPage || !ReadOnlyPage)
        return;
    ReadOnlyPage[0] = 1;
    ok(VirtualProtect(ReadOnlyPage, PAGE_SIZE, PAGE_READONLY, &OldProtect), "VirtualProtect failed: %lu\n", GetLastError());

    for (i = 0; i < Count; i++)
    {
        Threads[ThreadCount] = CreateThread(NULL, 0, FaultThread, NULL, 0, NULL);
        if (Threads[ThreadCount]) ThreadCount++;
        Threads[ThreadCount] = CreateThread(NULL, 0, NoiseThread, NULL, 0, NULL);
        if (Threads[ThreadCount]) ThreadCount++;
    }
    ok(ThreadCount == 2 * Count, "Created %lu of %lu threads\n", ThreadCount, 2 * Count);

    /* At least RUN_MS, then until enough faults happened (the rate depends on the number of processors) */
    Start = GetTickCount();
    do
    {
        Sleep(100);
        Elapsed = GetTickCount() - Start;
    } while (Elapsed < RUN_MS || ((Faults < MIN_FAULTS || Touches < MIN_TOUCHES) && Elapsed < MAX_RUN_MS));
    Stop = 1;
    Ended = (WaitForMultipleObjects(ThreadCount, Threads, TRUE, 30000) == WAIT_OBJECT_0);
    ok(Ended, "Threads did not end\n");
    if (Ended)
    {
        for (i = 0; i < ThreadCount; i++)
            CloseHandle(Threads[i]);
    }

    trace("%lu processors, %lu fault threads, %ld faults, %ld noise page touches in %lu ms\n",
          SystemInfo.dwNumberOfProcessors, Count, Faults, Touches, Elapsed);
    /* A slow configuration (a checked kernel) that did not get there in MAX_RUN_MS proves nothing either way */
    if (Faults < MIN_FAULTS || Touches < MIN_TOUCHES)
        skip("Only %ld faults and %ld noise touches in %lu ms, wanted %d and %d\n", Faults, Touches, Elapsed, MIN_FAULTS, MIN_TOUCHES);
    ok(Faults > 0, "No access violation was caught\n");
    ok(WrongAddress == 0, "%ld of %ld access violations reported another address (first %p)\n",
       WrongAddress, Faults, (PVOID)FirstWrong);
    ok(WrongType == 0, "%ld of %ld access violations reported the wrong access type\n", WrongType, Faults);

    /* A thread that did not end still uses the pages: leave them, the process ends with the test */
    if (Ended)
    {
        VirtualFree(NoAccessPage, 0, MEM_RELEASE);
        VirtualFree(ReadOnlyPage, 0, MEM_RELEASE);
    }
}
