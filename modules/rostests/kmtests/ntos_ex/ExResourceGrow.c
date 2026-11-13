/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ERESOURCE owner table growth while threads are made ready on
 *              the growing processor. Many threads share one resource, each
 *              pinned to its own processor, so the shared owner table is grown
 *              (first the 3-entry table, then 4 more entries at a time) by
 *              the callers at PASSIVE_LEVEL. Meanwhile DPCs bounce between the
 *              processors and make a higher-priority thread ready on the next
 *              one, so a thread is often selected to run next on a processor
 *              that is inside the growth. The growth must not switch threads
 *              or leave the interrupt flag clear while the resource's lock is
 *              held: that would hang the resource, or the processor.
 *              A pest also takes the resource's internal lock on its
 *              processor, so a sharer switched away while holding it makes
 *              the pest spin forever (the test then times out).
 *              Hidden test: run with "kmtest.exe ExResourceGrow"
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

#define GROW_MAX_CPUS       16
#define GROW_RUN_SECONDS    20
#define GROW_MAX_ROUNDS     1000000
#define GROW_HOLD_TIMEOUT   (10 * 10000000LL) /* 100 ns units */

typedef struct _GROW_WORKER
{
    ULONG Cpu;
    volatile LONG Done;
} GROW_WORKER;

static ERESOURCE GrowResource;
static volatile LONG GrowHolding;
static volatile LONG GrowWorkers;
static volatile LONG GrowErrors;
static volatile LONG GrowTimeouts;
static volatile LONG GrowStop;
static volatile LONG GrowActive;
static volatile LONG GrowPestInside;

static KEVENT GrowPestEvent[GROW_MAX_CPUS];
static volatile LONG GrowPestRuns[GROW_MAX_CPUS];
static KDPC GrowDpc[GROW_MAX_CPUS];
static volatile LONG GrowDpcRuns;

static
VOID
NTAPI
PestThread(
    _In_ PVOID Context)
{
    ULONG Cpu = (ULONG)(ULONG_PTR)Context;

    KeSetSystemAffinityThread((KAFFINITY)1 << Cpu);
    KeSetPriorityThread(KeGetCurrentThread(), 24);
    while (!GrowStop)
    {
        KeWaitForSingleObject(&GrowPestEvent[Cpu], Executive, KernelMode, FALSE, NULL);
        InterlockedIncrement(&GrowPestRuns[Cpu]);

        /* Want the resource's internal lock on this processor: if a sharer
           was switched away on it while holding that lock, this spins forever */
        InterlockedIncrement(&GrowPestInside);
        if (GrowActive)
            (VOID)ExIsResourceAcquiredSharedLite(&GrowResource);
        InterlockedDecrement(&GrowPestInside);
    }
}

static
VOID
NTAPI
GrowDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Arg1,
    _In_opt_ PVOID Arg2)
{
    ULONG Cpu = (ULONG)(ULONG_PTR)Context;
    ULONG Next = (Cpu + 1) % KeNumberProcessors;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    InterlockedIncrement(&GrowDpcRuns);

    /* Make the pest of the next processor ready, then pass the baton there */
    KeSetEvent(&GrowPestEvent[Next], IO_NO_INCREMENT, FALSE);
    KeStallExecutionProcessor(3);
    if (!GrowStop)
        KeInsertQueueDpc(&GrowDpc[Next], NULL, NULL);
}

static
VOID
NTAPI
SharerThread(
    _In_ PVOID Context)
{
    GROW_WORKER *Worker = Context;
    LARGE_INTEGER Start, Now;

    KeSetSystemAffinityThread((KAFFINITY)1 << Worker->Cpu);

    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(&GrowResource, TRUE))
        InterlockedIncrement(&GrowErrors);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !(__readeflags() & EFLAGS_INTERRUPT_MASK))
        InterlockedIncrement(&GrowErrors);
    InterlockedIncrement(&GrowHolding);

    /* Hold until every sharer owns the resource, so the table must hold all */
    KeQuerySystemTime(&Start);
    while (GrowHolding < GrowWorkers)
    {
        KeQuerySystemTime(&Now);
        if (Now.QuadPart - Start.QuadPart > GROW_HOLD_TIMEOUT)
        {
            InterlockedIncrement(&GrowTimeouts);
            break;
        }
        YieldProcessor();
    }

    ExReleaseResourceLite(&GrowResource);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !(__readeflags() & EFLAGS_INTERRUPT_MASK))
        InterlockedIncrement(&GrowErrors);
    KeLeaveCriticalRegion();

    Worker->Done = 1;
}

START_TEST(ExResourceGrow)
{
    PKTHREAD Pests[GROW_MAX_CPUS] = { 0 };
    PKTHREAD Sharers[GROW_MAX_CPUS];
    GROW_WORKER Workers[GROW_MAX_CPUS];
    ULONG Cpus, Cpu, Round;
    ULONGLONG StartTick, Now;
    LARGE_INTEGER Interval;
    ULONG Waited;
    LONG Bounces;

    Cpus = min(KeNumberProcessors, GROW_MAX_CPUS);
    trace("%lu processors\n", Cpus);
    if (skip(Cpus >= 2, "Needs at least 2 processors\n"))
        return;

    GrowStop = 0;
    for (Cpu = 0; Cpu < Cpus; Cpu++)
    {
        KeInitializeEvent(&GrowPestEvent[Cpu], SynchronizationEvent, FALSE);
        Pests[Cpu] = KmtStartThread(PestThread, (PVOID)(ULONG_PTR)Cpu);
        KeInitializeDpc(&GrowDpc[Cpu], GrowDpcRoutine, (PVOID)(ULONG_PTR)Cpu);
        KeSetTargetProcessorDpc(&GrowDpc[Cpu], (CCHAR)Cpu);
        KeSetImportanceDpc(&GrowDpc[Cpu], HighImportance);
    }
    /* KeNumberProcessors may exceed the arrays: the baton wraps at Cpus */
    GrowDpcRuns = 0;

    KeQuerySystemTime((PLARGE_INTEGER)&StartTick);
    KeInsertQueueDpc(&GrowDpc[0], NULL, NULL);

    for (Round = 0; Round < GROW_MAX_ROUNDS; Round++)
    {
        /* A fresh resource: its owner table starts empty and has to grow */
        ExInitializeResourceLite(&GrowResource);
        GrowHolding = 0;
        GrowWorkers = Cpus;
        GrowActive = 1;

        for (Cpu = 0; Cpu < Cpus; Cpu++)
        {
            Workers[Cpu].Cpu = Cpu;
            Workers[Cpu].Done = 0;
            Sharers[Cpu] = KmtStartThread(SharerThread, &Workers[Cpu]);
        }
        for (Cpu = 0; Cpu < Cpus; Cpu++)
            KmtFinishThread(Sharers[Cpu], NULL);

        GrowActive = 0;
        while (GrowPestInside)
            YieldProcessor();

        if (GrowErrors || GrowTimeouts)
            break;

        if (GrowResource.SpinLock != 0 || GrowResource.ActiveEntries != 0)
        {
            InterlockedIncrement(&GrowErrors);
            break;
        }
        ExDeleteResourceLite(&GrowResource);

        KeQuerySystemTime((PLARGE_INTEGER)&Now);
        if ((Now - StartTick) / 10000000 >= GROW_RUN_SECONDS)
        {
            Round++;
            break;
        }
    }

    /* Stop the DPC baton, wake and finish the pests */
    GrowStop = 1;
    Interval.QuadPart = -100 * 10000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    for (Cpu = 0; Cpu < Cpus; Cpu++)
        KmtFinishThread(Pests[Cpu], &GrowPestEvent[Cpu]);

    Bounces = GrowDpcRuns;
    trace("%lu rounds, %ld DPC bounces, pest runs on cpu0 %ld\n",
          Round, Bounces, GrowPestRuns[0]);
    ok(GrowTimeouts == 0, "Sharers timed out waiting for each other: %ld\n", GrowTimeouts);
    ok(GrowErrors == 0, "Errors (IRQL, interrupt flag, acquire, leftover lock state): %ld\n", GrowErrors);
    ok(Bounces > 0, "No DPC bounces\n");
    (void)Waited;
}
