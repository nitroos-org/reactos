/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Performance counter, unbiased interrupt time and precise time queries
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES *******************************************************************/

#include <ntdll.h>
#include <reactos/rosqpc.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

/*
 * @implemented
 */
BOOL
NTAPI
RtlQueryPerformanceCounter(
    _Out_ PLARGE_INTEGER PerformanceCounter)
{
    NTSTATUS Status;

#if defined(_M_IX86) || defined(_M_AMD64)
    /* From the TSC in user mode, as the kernel computes it, when it allows */
    if (RosQpcQueryBypass(PerformanceCounter))
        return TRUE;
#endif

    Status = NtQueryPerformanceCounter(PerformanceCounter, NULL);
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
BOOL
NTAPI
RtlQueryPerformanceFrequency(
    _Out_ PLARGE_INTEGER PerformanceFrequency)
{
    LARGE_INTEGER Counter, Frequency;
    NTSTATUS Status;

#if defined(_M_IX86) || defined(_M_AMD64)
    /* The HAL publishes the frequency when the counter is the TSC */
    if (SharedUserData->QpcFrequency)
    {
        PerformanceFrequency->QuadPart = (LONGLONG)SharedUserData->QpcFrequency;
        return TRUE;
    }
#endif

    /* The frequency is optional for the system call, not here */
    Status = NtQueryPerformanceCounter(&Counter, &Frequency);
    if (!NT_SUCCESS(Status))
        return FALSE;

    *PerformanceFrequency = Frequency;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
NTAPI
RtlQueryUnbiasedInterruptTime(
    _Out_ PULONGLONG UnbiasedTime)
{
    LARGE_INTEGER InterruptTime;
    ULONGLONG Bias = 0;

    if (!UnbiasedTime)
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

#if (NTDDI_VERSION >= NTDDI_VISTA)
    /* The bias is the time spent in sleep and hibernation; it must not change while the time is read */
    do
    {
        Bias = SharedUserData->InterruptTimeBias;
        InterruptTime = KiReadSystemTime(&SharedUserData->InterruptTime);
    } while (Bias != SharedUserData->InterruptTimeBias);
#else
    /* Shared user data of this NT version has no bias: the kernel does not take time spent asleep out */
    InterruptTime = KiReadSystemTime(&SharedUserData->InterruptTime);
#endif

    *UnbiasedTime = InterruptTime.QuadPart - Bias;
    return TRUE;
}

/*
 * The precise times. Both are a clock of the shared user data (read in steps of one clock tick) plus the performance
 * counter elapsed since the tick, as measured on Windows 10 22H2: the system time is never before the shared user
 * data time read before the call and not more than a tick after the one read afterwards, the interrupt time is the
 * performance counter in 100 ns units plus a constant, neither goes back, and the counter that
 * RtlGetInterruptTimePrecise reports is the one of the same instant (a QueryPerformanceCounter before and after the
 * call brackets it).
 *
 * Each clock keeps one offset: the clock minus the counter in 100 ns units. The first call sets it from the tick
 * value. Every call predicts with the offset and keeps the prediction in the band that the clock allows (not before
 * the tick value read first, not later than the one read last plus a tick); a prediction outside the band moves
 * the offset into it, so a counter that runs at another rate than the tick clock is followed, and so is the system
 * time when it is set. The value handed out never goes back.
 */
#define RTLP_PRECISE_TICK   156250LL        /* 15.6 ms in 100 ns units */
#define RTLP_PRECISE_SLACK  20000LL         /* 2 ms: jitter of the tick interrupt */
#define RTLP_PRECISE_UNSET  MINLONGLONG

typedef struct _RTLP_PRECISE_CLOCK
{
    volatile LONGLONG Offset;
    volatile LONGLONG Last;
} RTLP_PRECISE_CLOCK;

static RTLP_PRECISE_CLOCK RtlpPreciseSystemTime = { RTLP_PRECISE_UNSET, 0 };
static RTLP_PRECISE_CLOCK RtlpPreciseInterruptTime = { RTLP_PRECISE_UNSET, 0 };
static volatile LONGLONG RtlpPreciseFrequency;

static
LONGLONG
RtlpReadPreciseBase(
    _In_ BOOLEAN System)
{
    LARGE_INTEGER Time;

    if (System)
        Time = KiReadSystemTime(&SharedUserData->SystemTime);
    else
        Time = KiReadSystemTime(&SharedUserData->InterruptTime);

    return Time.QuadPart;
}

static
LONGLONG
RtlpQueryPrecise(
    _Inout_ RTLP_PRECISE_CLOCK *Clock,
    _In_ BOOLEAN System,
    _Out_opt_ PLARGE_INTEGER PerformanceCounter)
{
    LARGE_INTEGER Counter, Frequency;
    LONGLONG First, Last, Offset, Counter100, Time, Seen, Old;

    First = RtlpReadPreciseBase(System);

    Frequency.QuadPart = RtlpPreciseFrequency;
    if (Frequency.QuadPart == 0)
    {
        if (!NT_SUCCESS(NtQueryPerformanceCounter(&Counter, &Frequency)) || Frequency.QuadPart <= 0)
            goto NoCounter;
        RtlpPreciseFrequency = Frequency.QuadPart;
    }

    if (!RtlQueryPerformanceCounter(&Counter))
        goto NoCounter;
    Last = RtlpReadPreciseBase(System);

    /* Whole seconds first, so that a large counter does not overflow the multiplication */
    Counter100 = (Counter.QuadPart / Frequency.QuadPart) * 10000000LL +
                 ((Counter.QuadPart % Frequency.QuadPart) * 10000000LL) / Frequency.QuadPart;

    Offset = InterlockedCompareExchange64(&Clock->Offset, 0, 0);
    if (Offset == RTLP_PRECISE_UNSET)
    {
        /* The first call: if another thread was first, its offset stands */
        Offset = First - Counter100;
        Old = InterlockedCompareExchange64(&Clock->Offset, Offset, RTLP_PRECISE_UNSET);
        if (Old != RTLP_PRECISE_UNSET)
            Offset = Old;
    }

    Time = Counter100 + Offset;
    if (Time < First)
    {
        /* The counter runs slower than the tick clock, or the system time was set forward */
        Old = Offset;
        Offset += First - Time;
        Time = First;
        InterlockedCompareExchange64(&Clock->Offset, Offset, Old);
    }
    else if (Time > Last + RTLP_PRECISE_TICK)
    {
        /* The counter runs faster than the tick clock, or the system time was set back */
        Old = Offset;
        Offset -= Time - (Last + RTLP_PRECISE_TICK);
        Time = Last + RTLP_PRECISE_TICK;
        InterlockedCompareExchange64(&Clock->Offset, Offset, Old);
    }

    /* Never go back: a call that was preempted after it sampled returns the newest value that was handed out */
    Seen = InterlockedCompareExchange64(&Clock->Last, 0, 0);
    for (;;)
    {
        if (Time <= Seen)
        {
            /* Unless the system time was set back to before it: that value the clock cannot have reached */
            if (System && Seen > RtlpReadPreciseBase(TRUE) + RTLP_PRECISE_TICK + 2 * RTLP_PRECISE_SLACK)
            {
                Old = InterlockedCompareExchange64(&Clock->Last, Time, Seen);
                if (Old == Seen)
                    break;
                Seen = Old;
                continue;
            }
            Time = Seen;
            break;
        }

        Old = InterlockedCompareExchange64(&Clock->Last, Time, Seen);
        if (Old == Seen)
            break;

        Seen = Old;
    }

    if (PerformanceCounter)
        *PerformanceCounter = Counter;
    return Time;

NoCounter:
    /* No performance counter: the clock of the shared user data is all there is */
    if (PerformanceCounter)
        PerformanceCounter->QuadPart = 0;
    return First;
}

/*
 * @implemented
 *
 * The system time (100 ns since 1601) with the resolution of the performance counter.
 */
LONGLONG
NTAPI
RtlGetSystemTimePrecise(VOID)
{
    return RtlpQueryPrecise(&RtlpPreciseSystemTime, TRUE, NULL);
}

/*
 * @implemented
 *
 * The interrupt time (100 ns, includes time spent in sleep) with the resolution of the performance counter. The
 * counter that is returned through PerformanceCounter is the one read for this value, in performance counter units.
 */
ULONGLONG
NTAPI
RtlGetInterruptTimePrecise(
    _Out_ PLARGE_INTEGER PerformanceCounter)
{
    return (ULONGLONG)RtlpQueryPrecise(&RtlpPreciseInterruptTime, FALSE, PerformanceCounter);
}
