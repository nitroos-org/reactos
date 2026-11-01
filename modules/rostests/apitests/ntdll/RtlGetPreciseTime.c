/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RtlGetSystemTimePrecise and RtlGetInterruptTimePrecise of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 (WOW64), 10 MHz performance counter:
 *  - RtlGetSystemTimePrecise() returns the system time in 100 ns units since 1601; it is never before the
 *    coarse system time (NtQuerySystemTime) read before the call, and not more than one tick (15.6 ms; the
 *    largest difference seen was 156251) after the one read afterwards. It does not go back over 40 million calls.
 *    It is the value of kernel32 GetSystemTimePreciseAsFileTime (the value of that lies between two calls).
 *  - RtlGetInterruptTimePrecise(&Counter) returns the interrupt time in 100 ns units and writes the performance
 *    counter of the same instant: a QueryPerformanceCounter before and one after the call enclose it. The
 *    interrupt time is that counter in 100 ns units plus a constant (the spread over 3000 calls was 0), is 0.4 to
 *    0.8 ms ahead of the coarse interrupt time, does not go back, and over 200 ms the two advance equally.
 * The constant offset of the interrupt time is the kernel's own on Windows; this system derives the time from the
 * tick and the counter, which can differ by up to one tick, so that the offset is only checked to stay within a tick.
 */

#include "precomp.h"

#define TICK 156250LL
#define ITERATIONS 20000

typedef LONGLONG (NTAPI *PFN_SystemPrecise)(VOID);
typedef ULONGLONG (NTAPI *PFN_InterruptPrecise)(PLARGE_INTEGER);
typedef LONG (NTAPI *PFN_QuerySystemTime)(PLARGE_INTEGER);
typedef BOOL (NTAPI *PFN_QueryUnbiased)(PULONGLONG);

static LONGLONG To100ns(LONGLONG Counter, LONGLONG Frequency)
{
    return (Counter / Frequency) * 10000000LL + (Counter % Frequency) * 10000000LL / Frequency;
}

static void Test_System(HMODULE Ntdll)
{
    PFN_SystemPrecise Precise = (PFN_SystemPrecise)GetProcAddress(Ntdll, "RtlGetSystemTimePrecise");
    PFN_QuerySystemTime Query = (PFN_QuerySystemTime)GetProcAddress(Ntdll, "NtQuerySystemTime");
    void (WINAPI *GetPrecise)(LPFILETIME) = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetSystemTimePreciseAsFileTime");
    LONGLONG Previous, Now, Low = MAXLONGLONG, High = MINLONGLONG;
    LONGLONG KLow = MAXLONGLONG, KHigh = MINLONGLONG;
    ULONG i, Backward = 0;
    DWORD Start;

    if (!Precise)
    {
        ok(!is_reactos(), "RtlGetSystemTimePrecise is not exported by ntdll.dll\n");
        skip("RtlGetSystemTimePrecise is not exported\n");
        return;
    }

    for (i = 0; i < ITERATIONS; i++)
    {
        LARGE_INTEGER Before, After;
        LONGLONG Value;

        Query(&Before);
        Value = Precise();
        Query(&After);
        if (Value - Before.QuadPart < Low)
            Low = Value - Before.QuadPart;
        if (Value - After.QuadPart > High)
            High = Value - After.QuadPart;
        if (i % 64 == 0)
            Sleep(0);
    }
    ok(Low >= 0, "precise time %I64d before the coarse time read before\n", -Low);
    ok(High <= 2 * TICK, "precise time %I64d ahead of the coarse time read after\n", High);
    trace("precise - coarse before: min %I64d, precise - coarse after: max %I64d\n", Low, High);

    /* a 1 s loop must never see the time go back */
    Previous = Precise();
    Start = GetTickCount();
    while (GetTickCount() - Start < 1000)
    {
        Now = Precise();
        if (Now < Previous)
            Backward++;
        Previous = Now;
    }
    ok(Backward == 0, "the precise time went back %lu times\n", Backward);

    /* the precise time as a file time: the same clock */
    if (GetPrecise)
    {
        for (i = 0; i < 2000; i++)
        {
            FILETIME Time;
            LONGLONG Before, After, Value;

            Before = Precise();
            GetPrecise(&Time);
            After = Precise();
            Value = ((LONGLONG)Time.dwHighDateTime << 32) | Time.dwLowDateTime;
            if (Value - Before < KLow)
                KLow = Value - Before;
            if (Value - After > KHigh)
                KHigh = Value - After;
        }
        ok(KLow >= -TICK, "GetSystemTimePreciseAsFileTime %I64d before the ntdll time\n", -KLow);
        ok(KHigh <= TICK, "GetSystemTimePreciseAsFileTime %I64d after the ntdll time\n", KHigh);
        trace("kernel32 - ntdll before: min %I64d, kernel32 - ntdll after: max %I64d\n", KLow, KHigh);
    }
}

static void Test_Interrupt(HMODULE Ntdll)
{
    PFN_InterruptPrecise Precise = (PFN_InterruptPrecise)GetProcAddress(Ntdll, "RtlGetInterruptTimePrecise");
    PFN_QueryUnbiased QueryCoarse = (PFN_QueryUnbiased)GetProcAddress(Ntdll, "RtlQueryUnbiasedInterruptTime");
    LARGE_INTEGER Frequency, Before, After, Counter;
    LONGLONG Low, High, OffsetLow, OffsetHigh, Offset;
    ULONGLONG Value, Previous, CoarseBefore, CoarseAfter;
    ULONG i, Backward = 0, CounterBackward = 0, OutOfRange = 0;
    LARGE_INTEGER PreviousCounter;
    DWORD Start;

    if (!Precise)
    {
        ok(!is_reactos(), "RtlGetInterruptTimePrecise is not exported by ntdll.dll\n");
        skip("RtlGetInterruptTimePrecise is not exported\n");
        return;
    }
    QueryPerformanceFrequency(&Frequency);

    /* run over a few ticks, so that a clock that is set from the tick has settled */
    Start = GetTickCount();
    while (GetTickCount() - Start < 100)
        Precise(&Counter);

    /* the counter that is returned is the one of the call */
    for (i = 0; i < 2000; i++)
    {
        Counter.QuadPart = 0x1122334455667788LL;
        QueryPerformanceCounter(&Before);
        Value = Precise(&Counter);
        QueryPerformanceCounter(&After);
        if (Counter.QuadPart < Before.QuadPart || Counter.QuadPart > After.QuadPart)
            OutOfRange++;
        (void)Value;
    }
    ok(OutOfRange == 0, "the returned counter was out of the bracket of QueryPerformanceCounter %lu times\n", OutOfRange);

    /* the time is the counter in 100 ns units plus a constant */
    OffsetLow = MAXLONGLONG;
    OffsetHigh = MINLONGLONG;
    for (i = 0; i < 3000; i++)
    {
        Value = Precise(&Counter);
        Offset = (LONGLONG)Value - To100ns(Counter.QuadPart, Frequency.QuadPart);
        if (Offset < OffsetLow)
            OffsetLow = Offset;
        if (Offset > OffsetHigh)
            OffsetHigh = Offset;
        if (i % 500 == 0)
            Sleep(5);
    }
    ok(OffsetHigh - OffsetLow <= TICK, "the offset to the counter moved by %I64d\n", OffsetHigh - OffsetLow);
    trace("offset to the counter: spread %I64d\n", OffsetHigh - OffsetLow);

    /* at the coarse interrupt time (the system's sleep bias is zero when it is not asleep) */
    if (QueryCoarse)
    {
        Low = MAXLONGLONG;
        High = MINLONGLONG;
        for (i = 0; i < 2000; i++)
        {
            QueryCoarse(&CoarseBefore);
            Value = Precise(&Counter);
            QueryCoarse(&CoarseAfter);
            if ((LONGLONG)(Value - CoarseBefore) < Low)
                Low = (LONGLONG)(Value - CoarseBefore);
            if ((LONGLONG)(Value - CoarseAfter) > High)
                High = (LONGLONG)(Value - CoarseAfter);
            Sleep(0);
        }
        ok(Low >= 0, "interrupt time precise %I64d before the coarse time read before\n", -Low);
        ok(High <= 2 * TICK, "interrupt time precise %I64d ahead of the coarse time read after\n", High);
        trace("precise - coarse before: min %I64d, precise - coarse after: max %I64d\n", Low, High);
    }

    /* never backwards, the counter too */
    Previous = Precise(&PreviousCounter);
    Start = GetTickCount();
    while (GetTickCount() - Start < 1000)
    {
        Value = Precise(&Counter);
        if (Value < Previous)
            Backward++;
        if (Counter.QuadPart < PreviousCounter.QuadPart)
            CounterBackward++;
        Previous = Value;
        PreviousCounter = Counter;
    }
    ok(Backward == 0, "the interrupt time went back %lu times\n", Backward);
    ok(CounterBackward == 0, "the counter went back %lu times\n", CounterBackward);

    /* 200 ms later the time and the counter have advanced the same */
    {
        LARGE_INTEGER Counter1, Counter2;
        ULONGLONG Time1, Time2;
        LONGLONG DeltaTime, DeltaCounter;

        Time1 = Precise(&Counter1);
        Sleep(200);
        Time2 = Precise(&Counter2);
        DeltaTime = (LONGLONG)(Time2 - Time1);
        DeltaCounter = To100ns(Counter2.QuadPart - Counter1.QuadPart, Frequency.QuadPart);
        ok(DeltaTime >= 1900000, "200 ms advanced the time by %I64d\n", DeltaTime);
        ok(DeltaTime - DeltaCounter <= TICK && DeltaCounter - DeltaTime <= TICK,
           "time advanced %I64d, counter %I64d\n", DeltaTime, DeltaCounter);
        trace("200 ms: time %I64d, counter %I64d\n", DeltaTime, DeltaCounter);
    }
}

START_TEST(RtlGetPreciseTime)
{
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");

    Test_System(Ntdll);
    Test_Interrupt(Ntdll);
}
