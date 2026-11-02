/*
 * PROJECT:     ReactOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The performance counter from the time stamp counter, computed the
 *              same way by the HAL (KeQueryPerformanceCounter) and by user mode
 *              (ntdll, kernel32) from the QPC fields of the shared user data
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#if defined(_M_IX86) || defined(_M_AMD64)

/* The frequency the counter has when the TSC is faster, as on Windows 10 */
#define ROS_QPC_FREQUENCY 10000000ULL

/* The high 64 bits of the 128-bit product */
FORCEINLINE
ULONG64
RosQpcMultiplyHigh(
    _In_ ULONG64 Value,
    _In_ ULONG64 Multiplier)
{
#ifdef _M_AMD64
    return __umulh(Value, Multiplier);
#else
    ULONG64 LowLow, LowHigh, HighLow, Middle;

    LowLow = __emulu((ULONG)Value, (ULONG)Multiplier);
    LowHigh = __emulu((ULONG)Value, (ULONG)(Multiplier >> 32));
    HighLow = __emulu((ULONG)(Value >> 32), (ULONG)Multiplier);
    Middle = (LowLow >> 32) + (ULONG)LowHigh + (ULONG)HighLow;
    return __emulu((ULONG)(Value >> 32), (ULONG)(Multiplier >> 32)) +
           (LowHigh >> 32) + (HighLow >> 32) + (Middle >> 32);
#endif
}

/* The counter for a TSC value; a multiplier of 0 keeps the TSC rate */
FORCEINLINE
LONGLONG
RosQpcFromTsc(
    _In_ ULONG64 Tsc,
    _In_ ULONG64 Multiplier,
    _In_ ULONG64 Bias,
    _In_ UCHAR Shift)
{
    if (Multiplier)
        Tsc = RosQpcMultiplyHigh(Tsc, Multiplier);
    return (LONGLONG)((Tsc + Bias) >> Shift);
}

/* RDTSCP waits for the instructions before it, so the counter cannot be read
   before a value that was read earlier in program order */
FORCEINLINE
ULONG64
RosQpcReadTscp(VOID)
{
#if defined(_MSC_VER)
    unsigned int Aux;
    return __rdtscp(&Aux);
#else
    ULONG Low, High;
    __asm__ __volatile__("rdtscp" : "=a"(Low), "=d"(High) : : "ecx", "memory");
    return ((ULONG64)High << 32) | Low;
#endif
}

#ifdef SharedUserData
/* The same place for x86 and x64: 32-bit code under WoW64 reads this page */
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcFrequency) == 0x6c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcBias) == 0x6c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcMultiplier) == 0x6d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcBypassEnabled) == 0x6d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, QpcShift) == 0x6d9);

/*
 * The counter without a system call, when the kernel enabled it: the HAL
 * publishes the fields once, before it sets QpcBypassEnabled, and they do
 * not change afterwards. Returns FALSE when the system call is needed.
 */
FORCEINLINE
BOOLEAN
RosQpcQueryBypass(
    _Out_ PLARGE_INTEGER PerformanceCounter)
{
    UCHAR Flags;
    ULONG64 Tsc;

    Flags = SharedUserData->QpcBypassEnabled;
    if (!(Flags & SHARED_GLOBAL_FLAGS_QPC_BYPASS_ENABLED))
        return FALSE;
    _ReadWriteBarrier();

    if (Flags & SHARED_GLOBAL_FLAGS_QPC_BYPASS_USE_RDTSCP)
    {
        Tsc = RosQpcReadTscp();
    }
    else
    {
        if (Flags & SHARED_GLOBAL_FLAGS_QPC_BYPASS_USE_MFENCE)
            _mm_mfence();
        if (Flags & SHARED_GLOBAL_FLAGS_QPC_BYPASS_USE_LFENCE)
            _mm_lfence();
        Tsc = __rdtsc();
    }

    PerformanceCounter->QuadPart = RosQpcFromTsc(Tsc,
                                                 SharedUserData->QpcMultiplier,
                                                 SharedUserData->QpcBias,
                                                 SharedUserData->QpcShift);
    return TRUE;
}
#endif /* SharedUserData */

#endif /* _M_IX86 || _M_AMD64 */
