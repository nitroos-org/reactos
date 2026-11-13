/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Cost of IRQL changes (amd64: CR8 accesses) and of the lock
 *              primitives built on them. Timing only: it reports numbers and
 *              checks that the IRQL is restored; it never fails on speed.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include <ndk/halfuncs.h>

#define NDEBUG
#include <debug.h>

#define PERF_ITERATIONS 200000
#define PERF_REPEATS 5

static volatile ULONG_PTR PerfSink;
static volatile UCHAR PerfSoftIrql;

/* Cycles (x100) per iteration, best of PERF_REPEATS runs */
#define PERF_RUN(Name, Iterations, Setup, Body, Teardown)                      \
    do                                                                          \
    {                                                                           \
        ULONG64 Best = ~0ULL, Start, Cycles;                                    \
        ULONG Repeat, Index;                                                    \
        for (Repeat = 0; Repeat < PERF_REPEATS; Repeat++)                       \
        {                                                                       \
            Setup;                                                              \
            Start = __rdtsc();                                                  \
            for (Index = 0; Index < (Iterations); Index++)                      \
            {                                                                   \
                Body;                                                           \
                _ReadWriteBarrier();                                            \
            }                                                                   \
            Cycles = __rdtsc() - Start;                                         \
            Teardown;                                                           \
            if (Cycles < Best) Best = Cycles;                                   \
        }                                                                       \
        PerfReport(Name, Best, (Iterations));                                   \
    } while (0)

static ULONG64 PerfTscPerSecond;
static ULONG64 PerfEmptyX100;

static
VOID
PerfReport(
    _In_ PCSTR Name,
    _In_ ULONG64 Cycles,
    _In_ ULONG Iterations)
{
    ULONG64 CyclesX100 = Cycles * 100 / Iterations;
    ULONG64 NetX100 = (CyclesX100 > PerfEmptyX100) ? CyclesX100 - PerfEmptyX100 : 0;
    /* Net picoseconds = net cycles * 1e12 / TSC Hz (NetX100 is small: no overflow) */
    ULONG64 PicoSeconds = PerfTscPerSecond ? (NetX100 * 10000000000ULL) / PerfTscPerSecond : 0;
    trace("IRQLPERF %-28s cycles=%I64u.%02I64u net=%I64u.%02I64u ns=%I64u.%03I64u\n",
          Name,
          CyclesX100 / 100, CyclesX100 % 100,
          NetX100 / 100, NetX100 % 100,
          PicoSeconds / 1000, PicoSeconds % 1000);
}

static
VOID
PerfCalibrate(VOID)
{
    LARGE_INTEGER Frequency, Start, End;
    ULONG64 TscStart, TscEnd;
    LARGE_INTEGER Interval;

    Start = KeQueryPerformanceCounter(&Frequency);
    TscStart = __rdtsc();
    Interval.QuadPart = -10 * 1000 * 200; /* 200 ms */
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    End = KeQueryPerformanceCounter(NULL);
    TscEnd = __rdtsc();
    if (End.QuadPart > Start.QuadPart)
        PerfTscPerSecond = (TscEnd - TscStart) * (ULONG64)Frequency.QuadPart / (ULONG64)(End.QuadPart - Start.QuadPart);
    trace("IRQLPERF tsc_hz=%I64u\n", PerfTscPerSecond);
}

START_TEST(KeIrqlPerf)
{
    KIRQL OldIrql, Irql;
    KSPIN_LOCK SpinLock;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG_PTR Flags;

    ok_irql(PASSIVE_LEVEL);
    KeInitializeSpinLock(&SpinLock);
    PerfCalibrate();

    PerfEmptyX100 = 0;
    PERF_RUN("empty_loop", PERF_ITERATIONS, (void)0, (void)0, (void)0);
    {
        /* Baseline for the net column */
        ULONG64 Start = __rdtsc();
        ULONG Index;
        for (Index = 0; Index < PERF_ITERATIONS; Index++) _ReadWriteBarrier();
        PerfEmptyX100 = (__rdtsc() - Start) * 100 / PERF_ITERATIONS;
    }

    /* Plain IRQL reads/writes at PASSIVE_LEVEL */
    PERF_RUN("get_irql", PERF_ITERATIONS, (void)0, PerfSink += KeGetCurrentIrql(), (void)0);
    PERF_RUN("lower_same_passive", PERF_ITERATIONS, (void)0, KeLowerIrql(PASSIVE_LEVEL), (void)0);
    PERF_RUN("raise_lower_passive_dpc", PERF_ITERATIONS, (void)0,
             { KeRaiseIrql(DISPATCH_LEVEL, &OldIrql); KeLowerIrql(OldIrql); }, (void)0);
    PERF_RUN("raise_lower_passive_apc", PERF_ITERATIONS, (void)0,
             { KeRaiseIrql(APC_LEVEL, &OldIrql); KeLowerIrql(OldIrql); }, (void)0);
    PERF_RUN("raise_lower_passive_high", PERF_ITERATIONS, (void)0,
             { KeRaiseIrql(HIGH_LEVEL, &OldIrql); KeLowerIrql(OldIrql); }, (void)0);

    /* Redundant pair: already at DISPATCH_LEVEL */
    PERF_RUN("raise_lower_dpc_dpc", PERF_ITERATIONS, KeRaiseIrql(DISPATCH_LEVEL, &Irql),
             { KeRaiseIrql(DISPATCH_LEVEL, &OldIrql); KeLowerIrql(OldIrql); }, KeLowerIrql(Irql));
    PERF_RUN("raise_lower_dpc_high", PERF_ITERATIONS, KeRaiseIrql(DISPATCH_LEVEL, &Irql),
             { KeRaiseIrql(HIGH_LEVEL, &OldIrql); KeLowerIrql(OldIrql); }, KeLowerIrql(Irql));

#ifdef _M_AMD64
    /* The same pairs with a CR8 write only when the level changes */
    PERF_RUN("cond_raise_lower_passive_dpc", PERF_ITERATIONS, (void)0,
             {
                 OldIrql = KeGetCurrentIrql();
                 if (OldIrql != DISPATCH_LEVEL) __writecr8(DISPATCH_LEVEL);
                 if (KeGetCurrentIrql() != OldIrql) __writecr8(OldIrql);
             }, (void)0);
    PERF_RUN("cond_raise_lower_dpc_dpc", PERF_ITERATIONS, KeRaiseIrql(DISPATCH_LEVEL, &Irql),
             {
                 OldIrql = KeGetCurrentIrql();
                 if (OldIrql != DISPATCH_LEVEL) __writecr8(DISPATCH_LEVEL);
                 if (KeGetCurrentIrql() != OldIrql) __writecr8(OldIrql);
             }, KeLowerIrql(Irql));
#endif

    /* Software IRQL model (a byte store instead of CR8) */
    PERF_RUN("soft_irql_store_pair", PERF_ITERATIONS, (void)0,
             { OldIrql = PerfSoftIrql; PerfSoftIrql = DISPATCH_LEVEL; PerfSoftIrql = OldIrql; }, (void)0);

    /* Interrupt flag instead of IRQL */
    PERF_RUN("cli_sti", PERF_ITERATIONS, (void)0, { _disable(); _enable(); }, (void)0);
    PERF_RUN("save_cli_restore", PERF_ITERATIONS, (void)0,
             { Flags = __readeflags(); _disable(); __writeeflags(Flags); }, (void)0);

    /* Lock primitives */
    PERF_RUN("spinlock_raise_to_dpc", PERF_ITERATIONS, (void)0,
             { KeAcquireSpinLock(&SpinLock, &OldIrql); KeReleaseSpinLock(&SpinLock, OldIrql); }, (void)0);
    PERF_RUN("instack_queued_spinlock", PERF_ITERATIONS, (void)0,
             { KeAcquireInStackQueuedSpinLock(&SpinLock, &LockHandle); KeReleaseInStackQueuedSpinLock(&LockHandle); }, (void)0);
    PERF_RUN("spinlock_at_dpc_no_irql", PERF_ITERATIONS, KeRaiseIrql(DISPATCH_LEVEL, &Irql),
             { KeAcquireSpinLockAtDpcLevel(&SpinLock); KeReleaseSpinLockFromDpcLevel(&SpinLock); }, KeLowerIrql(Irql));
    PERF_RUN("instack_queued_spinlock_at_dpc", PERF_ITERATIONS, KeRaiseIrql(DISPATCH_LEVEL, &Irql),
             { KeAcquireInStackQueuedSpinLock(&SpinLock, &LockHandle); KeReleaseInStackQueuedSpinLock(&LockHandle); }, KeLowerIrql(Irql));

    /* Raise, request a DISPATCH_LEVEL software interrupt, lower (delivery on the lower) */
    PERF_RUN("raise_request_dpc_int_lower", PERF_ITERATIONS / 10, (void)0,
             { KeRaiseIrql(DISPATCH_LEVEL, &OldIrql); HalRequestSoftwareInterrupt(DISPATCH_LEVEL); KeLowerIrql(OldIrql); }, (void)0);

    ok_irql(PASSIVE_LEVEL);
}
