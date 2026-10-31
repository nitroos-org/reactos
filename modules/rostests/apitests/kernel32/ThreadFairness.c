/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that more CPU-bound threads of one priority than processors share the processors evenly
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * N + 1 spinner threads of the same priority run on the N processors of the machine. When a ready thread
 * waits only on the ready list of the processor it was given to, two of them share one processor for good
 * and get half the CPU time the others get (min/max 0.50). Windows 10 rotates them over the processors:
 * min/max CPU time over 6 seconds 0.88-0.97 measured on 4 processors (x64 and x86, 10 runs).
 * Windows does so only for threads that may run on every processor: with the process restricted to 2 of
 * 4 processors it measured 0.47-0.82, so the test needs the process to have all processors.
 */

#include "precomp.h"

#define WARMUP_MS 1000
#define WINDOW_MS 6000
#define MAX_SPINNERS 33

static volatile LONG g_Stop;

static DWORD WINAPI Spinner(PVOID Parameter)
{
    volatile ULONG i;
    UNREFERENCED_PARAMETER(Parameter);
    while (!g_Stop)
    {
        for (i = 0; i < 1000; i++);
    }
    return 0;
}

static ULONGLONG CpuTime(HANDLE Thread)
{
    FILETIME Create, Exit, Kernel, User;
    if (!GetThreadTimes(Thread, &Create, &Exit, &Kernel, &User)) return 0;
    return ((((ULONGLONG)Kernel.dwHighDateTime << 32) | Kernel.dwLowDateTime) +
            (((ULONGLONG)User.dwHighDateTime << 32) | User.dwLowDateTime)) / 10000;
}

/* Count: spinners; Mask: SetThreadAffinityMask if not 0; Ideal: SetThreadIdealProcessor if not -1.
   Returns 100 * min / max CPU time over the window, or -1 if the measurement means nothing */
static LONG RunOne(PCSTR Name, ULONG Count, ULONG Processors, DWORD_PTR Mask, LONG Ideal)
{
    HANDLE Threads[MAX_SPINNERS];
    ULONGLONG Start[MAX_SPINNERS], Ms, Min = ~0ULL, Max = 0, Total = 0;
    ULONG i, Created = 0;
    DWORD Wait, Tick = 0;
    LONG Ratio;

    g_Stop = 0;
    for (i = 0; i < Count; i++)
    {
        Threads[i] = CreateThread(NULL, 0, Spinner, NULL, CREATE_SUSPENDED, NULL);
        ok(Threads[i] != NULL, "%s: CreateThread failed (%lu)\n", Name, GetLastError());
        if (!Threads[i]) break;
        Created++;
        if (Mask) ok(SetThreadAffinityMask(Threads[i], Mask) != 0, "%s: SetThreadAffinityMask failed (%lu)\n", Name, GetLastError());
        if (Ideal >= 0) ok(SetThreadIdealProcessor(Threads[i], Ideal) != (DWORD)-1, "%s: SetThreadIdealProcessor failed (%lu)\n", Name, GetLastError());
    }
    for (i = 0; i < Created; i++) ResumeThread(Threads[i]);

    if (Created == Count)
    {
        Sleep(WARMUP_MS);
        for (i = 0; i < Count; i++) Start[i] = CpuTime(Threads[i]);
        Tick = GetTickCount();
        Sleep(WINDOW_MS);
        Tick = GetTickCount() - Tick;
        for (i = 0; i < Count; i++)
        {
            Ms = CpuTime(Threads[i]) - Start[i];
            if (Ms < Min) Min = Ms;
            if (Ms > Max) Max = Ms;
            Total += Ms;
        }
    }

    g_Stop = 1;
    Wait = WaitForMultipleObjects(Created, Threads, TRUE, 10000);
    ok(Wait == WAIT_OBJECT_0, "%s: threads did not stop (%lu)\n", Name, Wait);
    for (i = 0; i < Created; i++) CloseHandle(Threads[i]);
    if (Created != Count) return -1;

    Ratio = Max ? (LONG)(Min * 100 / Max) : 0;
    trace("%s: %lu spinners on %lu processors, CPU time min %I64u max %I64u total %I64u ms in %lu ms, min/max %ld.%02ld\n",
          Name, Count, Processors, Min, Max, Total, Tick, Ratio / 100, Ratio % 100);

    /* The spinners must have had most of the processors, or something else ran and the shares mean nothing */
    if (Total < (ULONGLONG)Tick * Processors * 7 / 10)
    {
        skip("%s: the spinners got %I64u ms of %lu processors x %lu ms, the machine is busy\n",
             Name, Total, Processors, Tick);
        return -1;
    }
    return Ratio;
}

START_TEST(ThreadFairness)
{
    DWORD_PTR ProcessMask, SystemMask;
    ULONG Processors = 0, i;
    LONG Ratio;
    int OldPriority;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask) || !ProcessMask)
    {
        skip("no process affinity mask\n");
        return;
    }
    for (i = 0; i < sizeof(ProcessMask) * 8; i++)
    {
        if (ProcessMask & ((DWORD_PTR)1 << i)) Processors++;
    }
    if (Processors < 2 || Processors + 1 > MAX_SPINNERS)
    {
        skip("%lu processors\n", Processors);
        return;
    }
    if (ProcessMask != SystemMask)
    {
        skip("the process may not run on every processor (0x%Ix of 0x%Ix)\n", ProcessMask, SystemMask);
        return;
    }

    /* The main thread only has to wake up at the end of each window */
    OldPriority = GetThreadPriority(GetCurrentThread());
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    /* Shared for good: 0.50. Rotated: about 1 (Windows 10: 0.88-0.97) */
    Ratio = RunOne("default", Processors + 1, Processors, 0, -1);
    if (Ratio >= 0)
        ok(Ratio >= 70, "default: min/max CPU time of %lu spinners on %lu processors %ld.%02ld, expected about 1\n",
           Processors + 1, Processors, Ratio / 100, Ratio % 100);

    /* All on the first processor as their ideal processor, affinity set to all processors */
    Ratio = RunOne("ideal processor 0", Processors + 1, Processors, ProcessMask, 0);
    if (Ratio >= 0)
        ok(Ratio >= 70, "ideal processor 0: min/max CPU time of %lu spinners on %lu processors %ld.%02ld, expected about 1\n",
           Processors + 1, Processors, Ratio / 100, Ratio % 100);

    SetThreadPriority(GetCurrentThread(), OldPriority);
}
