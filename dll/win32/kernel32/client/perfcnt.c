/*
 * COPYRIGHT:            See COPYING in the top level directory
 * PROJECT:              ReactOS Win32 Base API
 * FILE:                 dll/win32/kernel32/client/perfcnt.c
 * PURPOSE:              Performance Counter
 * PROGRAMMER:           Eric Kohl
 */

/* INCLUDES *******************************************************************/

#include <k32.h>
#include <reactos/rosqpc.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

/*
 * @implemented
 */
BOOL
WINAPI
QueryPerformanceCounter(OUT PLARGE_INTEGER lpPerformanceCount)
{
    LARGE_INTEGER Frequency;
    NTSTATUS Status;

#if defined(_M_IX86) || defined(_M_AMD64)
    /* The kernel's own TSC read and scaling, without the system call when the
       kernel enabled that (a speed choice: the counter is the same either way) */
    if (RosQpcQueryBypass(lpPerformanceCount))
        return TRUE;
#endif

    Status = NtQueryPerformanceCounter(lpPerformanceCount, &Frequency);
    if (Frequency.QuadPart == 0) Status = STATUS_NOT_IMPLEMENTED;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
QueryPerformanceFrequency(OUT PLARGE_INTEGER lpFrequency)
{
    LARGE_INTEGER Count;
    NTSTATUS Status;

#if defined(_M_IX86) || defined(_M_AMD64)
    /* The HAL publishes the frequency when the counter is the TSC */
    if (SharedUserData->QpcFrequency)
    {
        lpFrequency->QuadPart = (LONGLONG)SharedUserData->QpcFrequency;
        return TRUE;
    }
#endif

    Status = NtQueryPerformanceCounter(&Count, lpFrequency);
    if (lpFrequency->QuadPart == 0) Status = STATUS_NOT_IMPLEMENTED;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/* EOF */

/*
 * @implemented
 *
 * Windows 7 implements this in kernel32 (ntdll exports RtlQueryUnbiasedInterruptTime from Windows 8 on).
 */
BOOL
WINAPI
QueryUnbiasedInterruptTime(
    _Out_ PULONGLONG UnbiasedTime)
{
    LARGE_INTEGER InterruptTime;
    ULONGLONG Bias = 0;

    if (!UnbiasedTime)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
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
 * The precise interrupt time (QueryUnbiasedInterruptTimePrecise, exported from NT 6.1 on). Windows has it in
 * kernelbase.dll, which this system does not load into every process: programs reach it through
 * api-ms-win-core-realtime-l1-1-1 (delay-loaded by Chrome), and a sandboxed process cannot load another DLL after
 * its lockdown. So it lives here, and kernelbase_ros forwards its two precise functions to this one.
 */
#define BASEP_PRECISE_TICK  156250LL    /* 15.6 ms in 100 ns units */
#define BASEP_PRECISE_UNSET MINLONGLONG

/* The unbiased interrupt time, read the same way as in QueryUnbiasedInterruptTime */
static
LONGLONG
BasepReadInterruptTimeK(VOID)
{
    ULONGLONG UnbiasedTime;

    QueryUnbiasedInterruptTime(&UnbiasedTime);
    return (LONGLONG)UnbiasedTime;
}

/*
 * The precise interrupt time is the interrupt time of the clock tick plus the performance counter elapsed since. It
 * never reads the system time, so that a change of the wall clock cannot move it.
 *
 * The process keeps one offset: the interrupt time minus the performance counter in 100 ns units. The first call
 * sets it from the tick time. Every call predicts the time with the offset and keeps the prediction in the band
 * that the tick time allows (not before the tick time read first, not later than the one read last plus a tick);
 * a prediction outside the band moves the offset into it, so a counter that runs at another rate than the tick
 * clock is followed. The value never goes back: a call that was preempted after it sampled returns the newest
 * value that was handed out.
 */
static volatile LONGLONG BasepPreciseOffset = BASEP_PRECISE_UNSET;
static volatile LONGLONG BasepPreciseLast;

static
LONGLONG
BasepCounterTo100ns(
    _In_ LONGLONG Counter,
    _In_ LONGLONG Frequency)
{
    /* Split, so that a large counter does not overflow the multiplication */
    return (Counter / Frequency) * 10000000LL + ((Counter % Frequency) * 10000000LL) / Frequency;
}

static
LONGLONG
BasepQueryPrecise(VOID)
{
    LARGE_INTEGER Counter, Frequency;
    LONGLONG First, Last, Offset, Time, Seen, Old;

    if (!QueryPerformanceFrequency(&Frequency) || Frequency.QuadPart <= 0)
        return BasepReadInterruptTimeK();

    First = BasepReadInterruptTimeK();
    if (!QueryPerformanceCounter(&Counter))
        return First;
    Last = BasepReadInterruptTimeK();

    Offset = InterlockedCompareExchange64(&BasepPreciseOffset, 0, 0);
    if (Offset == BASEP_PRECISE_UNSET)
    {
        /* The first call of the process; if another thread was first, its offset stands */
        Offset = First - BasepCounterTo100ns(Counter.QuadPart, Frequency.QuadPart);
        Old = InterlockedCompareExchange64(&BasepPreciseOffset, Offset, BASEP_PRECISE_UNSET);
        if (Old != BASEP_PRECISE_UNSET)
            Offset = Old;
    }

    Time = BasepCounterTo100ns(Counter.QuadPart, Frequency.QuadPart) + Offset;
    if (Time < First)
    {
        /* The counter runs slower than the tick clock */
        Old = Offset;
        Offset += First - Time;
        Time = First;
        InterlockedCompareExchange64(&BasepPreciseOffset, Offset, Old);
    }
    else if (Time > Last + BASEP_PRECISE_TICK)
    {
        /* The counter runs faster than the tick clock */
        Old = Offset;
        Offset -= Time - (Last + BASEP_PRECISE_TICK);
        Time = Last + BASEP_PRECISE_TICK;
        InterlockedCompareExchange64(&BasepPreciseOffset, Offset, Old);
    }

    Seen = InterlockedCompareExchange64(&BasepPreciseLast, 0, 0);
    for (;;)
    {
        if (Time <= Seen)
            return Seen;

        Old = InterlockedCompareExchange64(&BasepPreciseLast, Time, Seen);
        if (Old == Seen)
            return Time;

        Seen = Old;
    }
}

/*
 * @implemented
 *
 * The unbiased time is the interrupt time minus the bias for time spent in sleep and hibernation (the bias is zero
 * while the kernel does not set it, and absent from the shared user data before NT 6).
 */
VOID
WINAPI
QueryUnbiasedInterruptTimePrecise(
    _Out_ PULONGLONG UnbiasedInterruptTime)
{
    *UnbiasedInterruptTime = BasepQueryPrecise();
}
