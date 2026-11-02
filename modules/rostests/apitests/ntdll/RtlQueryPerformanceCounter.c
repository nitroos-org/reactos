/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for RtlQueryPerformanceCounter, RtlQueryPerformanceFrequency and RtlQueryUnbiasedInterruptTime (Windows 8+);
 *              the counter is the same for every processor and for the system call
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef BOOL (NTAPI *FN_RtlQueryPerformance)(PLARGE_INTEGER);
typedef BOOL (NTAPI *FN_RtlQueryUnbiasedInterruptTime)(PULONGLONG);

/* The QPC fields of ReactOS's shared user data (Windows has them elsewhere) */
#define ROS_SHARED_DATA          ((ULONG_PTR)0x7FFE0000)
#define ROS_QPC_FREQUENCY_OFFSET 0x6c0
#define ROS_QPC_BYPASS_OFFSET    0x6d8

#define MONOTONIC_THREADS 8
#define MONOTONIC_SAMPLES 2000000
#define CONSISTENCY_SAMPLES 200000

static volatile LONGLONG MonotonicLast;
static volatile LONG MonotonicBackwards, MonotonicStart;
static volatile LONGLONG MonotonicWorst;

/*
 * Each thread, on its own processor, reads the newest counter any thread has
 * seen, then the counter: that was read later, so it must not be smaller,
 * whichever processor the newest value came from.
 */
static DWORD WINAPI MonotonicThread(PVOID Parameter)
{
    LARGE_INTEGER Now;
    LONGLONG Seen, Old;
    ULONG Sample;

    while (!MonotonicStart)
        YieldProcessor();

    for (Sample = 0; Sample < MONOTONIC_SAMPLES; Sample++)
    {
        Seen = InterlockedCompareExchange64(&MonotonicLast, 0, 0);
        QueryPerformanceCounter(&Now);
        if (Now.QuadPart < Seen)
        {
            InterlockedIncrement(&MonotonicBackwards);
            if (Seen - Now.QuadPart > MonotonicWorst)
                MonotonicWorst = Seen - Now.QuadPart;
        }
        while (Now.QuadPart > Seen)
        {
            Old = InterlockedCompareExchange64(&MonotonicLast, Now.QuadPart, Seen);
            if (Old == Seen)
                break;
            Seen = Old;
        }
    }
    return 0;
}

static void TestMonotonic(void)
{
    HANDLE Threads[MONOTONIC_THREADS];
    SYSTEM_INFO Info;
    ULONG Count, i;

    GetSystemInfo(&Info);
    Count = min(Info.dwNumberOfProcessors, MONOTONIC_THREADS);
    MonotonicLast = 0;
    MonotonicBackwards = 0;
    MonotonicWorst = 0;
    MonotonicStart = 0;
    for (i = 0; i < Count; i++)
    {
        Threads[i] = CreateThread(NULL, 0, MonotonicThread, NULL, CREATE_SUSPENDED, NULL);
        ok(Threads[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!Threads[i])
        {
            Count = i;
            break;
        }
        SetThreadAffinityMask(Threads[i], (DWORD_PTR)1 << i);
        ResumeThread(Threads[i]);
    }
    MonotonicStart = 1;
    WaitForMultipleObjects(Count, Threads, TRUE, INFINITE);
    for (i = 0; i < Count; i++)
        CloseHandle(Threads[i]);

    ok(MonotonicBackwards == 0, "The counter went back %ld times over %lu processors (by up to %I64d)\n",
       MonotonicBackwards, Count, MonotonicWorst);
    trace("%lu processors, %lu samples each, counter went back %ld times\n",
          Count, (ULONG)MONOTONIC_SAMPLES, MonotonicBackwards);
}

/* The counter from user mode and from the system call is one counter */
static void TestConsistency(void)
{
    LARGE_INTEGER Before, Kernel, After, Frequency, KernelFrequency;
    ULONG Sample, OutOfOrder = 0;
    NTSTATUS Status;

    QueryPerformanceFrequency(&Frequency);
    Status = NtQueryPerformanceCounter(&Kernel, &KernelFrequency);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(KernelFrequency.QuadPart == Frequency.QuadPart, "System call frequency %I64d, user mode %I64d\n",
       KernelFrequency.QuadPart, Frequency.QuadPart);

    for (Sample = 0; Sample < CONSISTENCY_SAMPLES; Sample++)
    {
        QueryPerformanceCounter(&Before);
        NtQueryPerformanceCounter(&Kernel, NULL);
        QueryPerformanceCounter(&After);
        if ((Kernel.QuadPart < Before.QuadPart) || (After.QuadPart < Kernel.QuadPart))
        {
            if (!OutOfOrder)
                trace("%I64d %I64d %I64d\n", Before.QuadPart, Kernel.QuadPart, After.QuadPart);
            OutOfOrder++;
        }
    }
    ok(OutOfOrder == 0, "System call counter outside the user mode reads around it %lu times\n", OutOfOrder);
}

static void TestFrequency(void)
{
    LARGE_INTEGER Frequency;
    ULONGLONG Shared;
    UCHAR Bypass;

    ok(QueryPerformanceFrequency(&Frequency), "QueryPerformanceFrequency failed\n");
    ok(Frequency.QuadPart > 0, "Frequency %I64d\n", Frequency.QuadPart);
    if (!is_reactos())
    {
        /* 10 MHz on Windows 10 on most machines, but not on all */
        trace("Frequency %I64d\n", Frequency.QuadPart);
        return;
    }

    /* The TSC HAL publishes its frequency, 10 MHz when the TSC is faster; the
       user-mode counter is only enabled with it */
    Shared = *(volatile ULONGLONG *)(ROS_SHARED_DATA + ROS_QPC_FREQUENCY_OFFSET);
    Bypass = *(volatile UCHAR *)(ROS_SHARED_DATA + ROS_QPC_BYPASS_OFFSET);
    trace("Frequency %I64d, shared %I64u, bypass flags 0x%02x\n", Frequency.QuadPart, Shared, Bypass);
    if (Shared)
        ok((ULONGLONG)Frequency.QuadPart == Shared, "Frequency %I64d, shared %I64u\n", Frequency.QuadPart, Shared);
    if (Bypass & 1)
    {
        ok(Shared != 0, "Bypass without a shared frequency\n");
        ok(Frequency.QuadPart == 10000000, "Frequency %I64d\n", Frequency.QuadPart);
    }
}

START_TEST(RtlQueryPerformanceCounter)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    FN_RtlQueryPerformance pRtlQueryPerformanceCounter, pRtlQueryPerformanceFrequency;
    FN_RtlQueryUnbiasedInterruptTime pRtlQueryUnbiasedInterruptTime;
    LARGE_INTEGER Before, Counter, After, Frequency, Expected;
    ULONGLONG Time;
    BOOL Ret;

    pRtlQueryPerformanceCounter = (FN_RtlQueryPerformance)GetProcAddress(hNtdll, "RtlQueryPerformanceCounter");
    pRtlQueryPerformanceFrequency = (FN_RtlQueryPerformance)GetProcAddress(hNtdll, "RtlQueryPerformanceFrequency");
    pRtlQueryUnbiasedInterruptTime = (FN_RtlQueryUnbiasedInterruptTime)GetProcAddress(hNtdll, "RtlQueryUnbiasedInterruptTime");
    if (!pRtlQueryPerformanceCounter && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32EnumProcesses"))
    {
        skip("No NT 6.1 exports\n");
        return;
    }
    ok(pRtlQueryPerformanceCounter != NULL, "RtlQueryPerformanceCounter is not exported\n");
    ok(pRtlQueryPerformanceFrequency != NULL, "RtlQueryPerformanceFrequency is not exported\n");

    if (pRtlQueryPerformanceCounter)
    {
        ok(QueryPerformanceCounter(&Before), "QueryPerformanceCounter failed\n");
        Counter.QuadPart = 0;
        Ret = pRtlQueryPerformanceCounter(&Counter);
        ok(QueryPerformanceCounter(&After), "QueryPerformanceCounter failed\n");
        ok(Ret != FALSE, "Ret = %d\n", Ret);
        ok(Counter.QuadPart >= Before.QuadPart && Counter.QuadPart <= After.QuadPart,
           "Counter %I64d is not between %I64d and %I64d\n", Counter.QuadPart, Before.QuadPart, After.QuadPart);
    }

    if (pRtlQueryPerformanceFrequency)
    {
        ok(QueryPerformanceFrequency(&Expected), "QueryPerformanceFrequency failed\n");
        Frequency.QuadPart = 0;
        Ret = pRtlQueryPerformanceFrequency(&Frequency);
        ok(Ret != FALSE, "Ret = %d\n", Ret);
        ok(Frequency.QuadPart == Expected.QuadPart, "Frequency %I64d, expected %I64d\n", Frequency.QuadPart, Expected.QuadPart);
    }

    TestFrequency();
    TestConsistency();
    TestMonotonic();

    /* ntdll exports it from Windows 8 on (Windows 7 implements QueryUnbiasedInterruptTime in kernel32) */
    if (!pRtlQueryUnbiasedInterruptTime)
    {
        skip("RtlQueryUnbiasedInterruptTime is not exported\n");
    }
    else
    {
        Time = 0;
        Ret = pRtlQueryUnbiasedInterruptTime(&Time);
        ok(Ret != FALSE, "Ret = %d\n", Ret);
        ok(Time != 0, "Time is 0\n");

        SetLastError(0xdeadbeef);
        Ret = pRtlQueryUnbiasedInterruptTime(NULL);
        ok(Ret == FALSE, "Ret = %d\n", Ret);
        ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());
    }
}
