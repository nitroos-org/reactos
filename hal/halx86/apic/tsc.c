/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            hal/halx86/apic/tsc.c
 * PURPOSE:         HAL Routines for TSC handling
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <hal.h>
#include "tsc.h"
#include "apicp.h"
#include <reactos/rosqpc.h>
#define NDEBUG
#include <debug.h>

LARGE_INTEGER HalpCpuClockFrequency = {{INITIAL_STALL_COUNT * 1000000}};

UCHAR TscCalibrationPhase;
ULONG64 TscCalibrationArray[NUM_SAMPLES];

/* TRUE when the frequency came from the hypervisor, or was measured against the
   ACPI power management timer (five windows agreeing to 1/10000, not above the
   RTC calibration); the clock interrupt then counts lost periods with it */
BOOLEAN HalpTscCalibrated;

#define PM_TIMER_FREQUENCY 3579545
#define PM_TIMER_WINDOW (PM_TIMER_FREQUENCY / 20) /* 50 ms */
#define PM_TIMER_WINDOWS 8
#define PM_TIMER_AGREEING 5
#define PM_TIMER_LONGEST 4 /* seconds, below the 4.687 s wrap of a 24-bit timer */
#define PM_TIMER_STEPS 16  /* fewer steps than this can each take over 1/16 of a window */

#define PM_TIMER_TRIES 3

#define RTC_MODE 6 /* Mode 6 is 1024 Hz */
#define SAMPLE_FREQUENCY ((32768 << 1) >> RTC_MODE)

/* A TSC frequency reported by a hypervisor is used within these bounds */
#define HV_TSC_MINIMUM_FREQUENCY 10000000ULL      /* 10 MHz */
#define HV_TSC_MAXIMUM_FREQUENCY 100000000000ULL  /* 100 GHz */

/* KVM paravirtual clock (kvmclock): the hypervisor fills this structure with
   the factors that convert the TSC to nanoseconds, which give the TSC
   frequency it set for the guest */
#define KVM_CPUID_FEATURES_OFFSET 1
#define KVM_FEATURE_CLOCKSOURCE 0x1
#define KVM_FEATURE_CLOCKSOURCE2 0x8
#define MSR_KVM_SYSTEM_TIME 0x12
#define MSR_KVM_SYSTEM_TIME_NEW 0x4b564d01

typedef struct _PVCLOCK_VCPU_TIME_INFO
{
    ULONG Version;
    ULONG Pad0;
    ULONG64 TscTimestamp;
    ULONG64 SystemTime;
    ULONG TscToSystemMul;
    CHAR TscShift;
    UCHAR Flags;
    UCHAR Pad[2];
} PVCLOCK_VCPU_TIME_INFO;

/* Aligned to its size, so it does not cross a page */
static volatile PVCLOCK_VCPU_TIME_INFO DECLSPEC_ALIGN(32) HalpKvmClock;

/* Hyper-V: the TSC frequency in Hz is in a synthetic MSR when the partition
   may access the frequency MSRs */
#define HV_CPUID_FEATURES 0x40000003
#define HV_ACCESS_FREQUENCY_MSRS 0x800
#define HV_FEATURE_FREQUENCY_MSRS_AVAILABLE 0x100 /* CPUID 0x40000003 EDX bit 8 */
#define HV_X64_MSR_TSC_FREQUENCY 0x40000022

/* Hypervisor timing leaf (VMware, and KVM when configured): TSC kHz in EAX */
#define HV_CPUID_TIMING_OFFSET 0x10

/* KVM: the stable bit of the paravirtual clock may be relied on (CPUID), and
   is set (flags of the clock structure) while all virtual processors run
   with the same TSC offset on a host whose own TSC is synchronized and
   constant, which is what an invariant TSC promises */
#define KVM_FEATURE_CLOCKSOURCE_STABLE_BIT 0x1000000
#define PVCLOCK_TSC_STABLE_BIT 0x01
static BOOLEAN HalpKvmTscStable;

/* The performance counter: the TSC scaled to ROS_QPC_FREQUENCY when it is
   faster (the multiplier is 2^64 * ROS_QPC_FREQUENCY / TSC frequency), the
   TSC itself otherwise (multiplier 0). Set once the frequency is known */
static ULONG64 HalpQpcMultiplier;
static LARGE_INTEGER HalpQpcFrequency;

/* Checking that the TSCs of the processors are in step */
#define TSC_WARP_LOOPS 20000
#define TSC_WARP_MINIMUM_LOOPS 2000
static volatile LONG HalpTscWarpLock;
static volatile ULONG64 HalpTscWarpLast;
static volatile LONG HalpTscWarps;
static ULONG HalpTscWarpLoops;
static BOOLEAN HalpTscWarpRdtscp;

/* PRIVATE FUNCTIONS *********************************************************/

static
ULONG64
DoLinearRegression(
    ULONG XMax,
    ULONG64 *ArrayY)
{
    ULONG X, SumXX;
    ULONG64 SumXY;

    /* Calculate the sum of the squares of X */
    SumXX = (XMax * (XMax + 1) * (2*XMax + 1)) / 6;

    /* Calculate the sum of the differences to the first value
       weighted by x */
    for (SumXY = 0, X = 1; X <= XMax; X++)
    {
         SumXY += X * (ArrayY[X] - ArrayY[0]);
    }

    /* Account for sample frequency */
    SumXY *= SAMPLE_FREQUENCY;

    /* Return the quotient of the sums */
    return (SumXY + (SumXX/2)) / SumXX;
}

/* Reads the TSC and the power management timer together; returns the TSC in the
   middle of the closest of several reads and the TSC ticks the read took */
static
ULONG64
HalpReadTscAndPmTimer(
    _In_ USHORT Port,
    _In_ ULONG Mask,
    _Out_ PULONG PmTimer,
    _Out_ PULONG64 Bracket)
{
    ULONG64 Before, After, Tsc = 0;
    ULONG Value, i;

    *Bracket = ~0ULL;
    *PmTimer = 0;
    for (i = 0; i < 8; i++)
    {
        Before = __rdtsc();
        Value = __indword(Port) & Mask;
        After = __rdtsc();
        if (After - Before < *Bracket)
        {
            *Bracket = After - Before;
            *PmTimer = Value;
            Tsc = Before + *Bracket / 2;
        }
    }
    return Tsc;
}

/* Sorts a few values in place */
static
VOID
HalpSortValues(
    _Inout_updates_(Count) PULONG64 Values,
    _In_ ULONG Count)
{
    ULONG64 Value;
    ULONG i, j;

    for (i = 1; i < Count; i++)
    {
        Value = Values[i];
        for (j = i; (j > 0) && (Values[j - 1] > Value); j--)
            Values[j] = Values[j - 1];
        Values[j] = Value;
    }
}

/* Keeps the longest steps between polls of the timer (TSC ticks and counts) */
static
VOID
HalpKeepLongStep(
    _In_ ULONG64 Ticks,
    _In_ ULONG64 Count,
    _Inout_updates_(PM_TIMER_STEPS) PULONG64 StepTicks,
    _Inout_updates_(PM_TIMER_STEPS) PULONG64 StepCounts,
    _Inout_ PULONG Shortest)
{
    ULONG i;

    if (Ticks <= StepTicks[*Shortest])
        return;
    StepTicks[*Shortest] = Ticks;
    StepCounts[*Shortest] = Count;
    for (*Shortest = 0, i = 1; i < PM_TIMER_STEPS; i++)
    {
        if (StepTicks[i] < StepTicks[*Shortest])
            *Shortest = i;
    }
}

/*!
    \brief Measures the TSC frequency against the ACPI power management timer.

    Eight consecutive windows of 50 ms of the timer, each ended by a close
    read of the TSC and the timer (the closest of several reads), each give a
    frequency. The timer is polled, so late or lost interrupts do not matter.
    A pause between two polls longer than a wrap of the timer (4.7 s for 24
    bits) hides the wrap. Such a step between polls takes more than 1/16 of
    its window by the TSC (unless 16 steps of a window each hide a wrap),
    while the timer counts far less than its share. So a window is dropped
    when the TSC ticks per count of a step that takes more than 1/16 of it
    differ from those of the rest of the window by more than 1/8 (a pause the
    timer counted through agrees), or when that rest is under 1/4 of the
    window's count. This needs no other clock.
    A window that took more than twice or less than half the median TSC
    duration of the windows is dropped: a pause there could hide a wrap of the
    timer (4.7 s for 24 bits, nearly 100 windows long), and the TSC sees the
    pause whatever its rate. The result is the median of the remaining
    frequencies, and at least five of them must agree with it to 1/10000.
    As a second guard, a window longer than 4 s by the reference frequency
    (the RTC calibration, or the hypervisor's) is dropped and the result must
    not exceed it by more than 1/8 (lost RTC interrupts only make the RTC
    calibration higher, as a hidden wrap makes this one). Otherwise
    the measurement fails; without a frequency from the hypervisor the RTC
    calibration is then used, without counting lost clock periods.
*/
static
BOOLEAN
HalpCalibrateTscWithPmTimer(
    _In_ ULONG64 ReferenceFrequency)
{
    ULONG64 Ticks[PM_TIMER_WINDOWS], Counts[PM_TIMER_WINDOWS], Frequency[PM_TIMER_WINDOWS];
    ULONG64 Sorted[PM_TIMER_WINDOWS], Last, End, Bracket, Count, Median, Difference;
    ULONG64 StepTicks[PM_TIMER_STEPS], StepCounts[PM_TIMER_STEPS];
    ULONG64 Tsc, Previous, Step, RestTicks, RestCount, Expected, Actual;
    BOOLEAN Suspect[PM_TIMER_WINDOWS];
    ULONG Port, Mask, Timer, Now, Window, Valid, Agreeing, Unchanged, Shortest, i;
    ULONG_PTR Flags;

    Port = HalpGetAcpiTimerPort(&Mask);
    if (!Port)
        return FALSE;

    Flags = __readeflags();
    _disable();
    Last = HalpReadTscAndPmTimer((USHORT)Port, Mask, &Timer, &Bracket);
    for (Window = 0; Window < PM_TIMER_WINDOWS; Window++)
    {
        Previous = Last;
        RtlZeroMemory(StepTicks, sizeof(StepTicks));
        RtlZeroMemory(StepCounts, sizeof(StepCounts));
        Shortest = 0;
        for (Count = 0, Unchanged = 0; Count < PM_TIMER_WINDOW; )
        {
            Now = __indword((USHORT)Port) & Mask;
            Tsc = __rdtsc();

            /* Give up on a timer that does not count */
            if ((Now == Timer) && (++Unchanged > (1UL << 24)))
            {
                __writeeflags(Flags);
                return FALSE;
            }
            if (Now != Timer)
                Unchanged = 0;
            Step = (Now - Timer) & Mask;
            HalpKeepLongStep(Tsc - Previous, Step, StepTicks, StepCounts, &Shortest);
            Count += Step;
            Timer = Now;
            Previous = Tsc;
        }
        End = HalpReadTscAndPmTimer((USHORT)Port, Mask, &Now, &Bracket);
        Step = (Now - Timer) & Mask;
        HalpKeepLongStep(End - Previous, Step, StepTicks, StepCounts, &Shortest);
        Count += Step;
        Timer = Now;
        Ticks[Window] = End - Last;
        Counts[Window] = Count;
        Last = End;

        /* Steps that could hide a wrap, against the rest of the window; the
           bounds keep the products below 2^63 */
        RestTicks = Ticks[Window];
        RestCount = Count;
        for (i = 0; i < PM_TIMER_STEPS; i++)
        {
            if (16 * StepTicks[i] > Ticks[Window])
            {
                RestTicks -= StepTicks[i];
                RestCount -= StepCounts[i];
            }
        }
        Suspect[Window] = (Count > 2 * PM_TIMER_WINDOW) || (Ticks[Window] >= (1ULL << 44)) ||
                          (4 * RestCount < PM_TIMER_WINDOW);
        for (i = 0; !Suspect[Window] && (i < PM_TIMER_STEPS); i++)
        {
            if (16 * StepTicks[i] <= Ticks[Window])
                continue;
            Expected = StepTicks[i] * RestCount;
            Actual = StepCounts[i] * RestTicks;
            Difference = (Expected > Actual) ? Expected - Actual : Actual - Expected;
            Suspect[Window] = (Difference > Expected / 8);
        }
    }
    __writeeflags(Flags);

    /* Median TSC duration of a window */
    for (Window = 0; Window < PM_TIMER_WINDOWS; Window++)
        Sorted[Window] = Ticks[Window];
    HalpSortValues(Sorted, PM_TIMER_WINDOWS);
    Median = Sorted[PM_TIMER_WINDOWS / 2];

    /* Frequencies of the windows of about that duration */
    for (Valid = 0, Window = 0; Window < PM_TIMER_WINDOWS; Window++)
    {
        if (Suspect[Window] || !Ticks[Window] || (Ticks[Window] > 2 * Median) ||
            (2 * Ticks[Window] < Median) || (Ticks[Window] / PM_TIMER_LONGEST > ReferenceFrequency))
            continue;
        Frequency[Valid++] = (Ticks[Window] / Counts[Window]) * PM_TIMER_FREQUENCY +
            ((Ticks[Window] % Counts[Window]) * PM_TIMER_FREQUENCY + Counts[Window] / 2) / Counts[Window];
    }
    if (Valid < PM_TIMER_AGREEING)
        return FALSE;
    HalpSortValues(Frequency, Valid);
    Median = Frequency[Valid / 2];

    for (Agreeing = 0, Window = 0; Window < Valid; Window++)
    {
        Difference = (Frequency[Window] > Median) ? Frequency[Window] - Median : Median - Frequency[Window];
        if (Difference <= Median / 10000)
            Agreeing++;
    }
    if (Agreeing < PM_TIMER_AGREEING)
        return FALSE;

    /* Lost RTC interrupts make the RTC calibration too high, a hidden wrap of
       the timer makes this one too high: only a result above the RTC
       calibration can be a hidden wrap */
    if ((Median > ReferenceFrequency) && (Median - ReferenceFrequency > ReferenceFrequency / 8))
        return FALSE;

    HalpCpuClockFrequency.QuadPart = Median;
    HalpTscCalibrated = TRUE;
    return TRUE;
}

/* The hypervisor interfaces looked for, and where their CPUID leaves start */
#define HV_SIGNATURE_MICROSOFT 0
#define HV_SIGNATURE_KVM       1
#define HV_SIGNATURE_VMWARE    2
#define HV_SIGNATURE_COUNT     3

/*
    Finds the CPUID base of a hypervisor by its signature; returns the highest
    leaf it reports in EAX, as it is (KVM may leave it 0). A hypervisor that
    also presents another one's interface (KVM with the Hyper-V enlightenments)
    moves its own leaves to 0x40000100 and up, so all 256 possible bases are
    probed: that is about a thousand CPUID exits when it is done per question
    and slow when nested or starved, so it is done once and kept.
*/
static
ULONG
HalpFindHypervisorBase(
    _In_ ULONG Interface,
    _Out_ PULONG Base)
{
    static const char Signatures[HV_SIGNATURE_COUNT][12] =
        { "Microsoft Hv", "KVMKVMKVM\0\0\0", "VMwareVMware" };
    static BOOLEAN Scanned;
    static ULONG Bases[HV_SIGNATURE_COUNT], Highests[HV_SIGNATURE_COUNT];
    INT CpuInfo[4];
    ULONG Leaf, Index;

    if (!Scanned)
    {
        __cpuid(CpuInfo, 1);
        if (CpuInfo[2] & 0x80000000)
        {
            for (Leaf = 0x40000000; Leaf < 0x40010000; Leaf += 0x100)
            {
                __cpuid(CpuInfo, Leaf);
                for (Index = 0; Index < HV_SIGNATURE_COUNT; Index++)
                {
                    if (!Bases[Index] && RtlEqualMemory(&CpuInfo[1], Signatures[Index], 12))
                    {
                        Bases[Index] = Leaf;
                        Highests[Index] = (ULONG)CpuInfo[0];
                    }
                }
            }
        }
        Scanned = TRUE;
    }

    *Base = Bases[Interface];
    return Bases[Interface] ? Highests[Interface] : 0;
}

/* Reads the TSC frequency from KVM's paravirtual clock */
static
ULONG64
HalpGetKvmClockFrequency(VOID)
{
    PHYSICAL_ADDRESS Address;
    INT CpuInfo[4];
    ULONG Base, Highest, Msr, Version, Mul, Tries;
    CHAR Shift;
    ULONG64 Frequency;

    /* An old KVM leaves the highest leaf 0 and has the features leaf (Linux
       reads it without looking at the highest leaf); otherwise a highest leaf
       below the features leaf, as the signature leaf alone, means it is not
       there and reading it would return whatever the CPU gives for it */
    Highest = HalpFindHypervisorBase(HV_SIGNATURE_KVM, &Base);
    if (!Base || (Highest && (Highest < Base + KVM_CPUID_FEATURES_OFFSET)))
        return 0;
    __cpuid(CpuInfo, Base + KVM_CPUID_FEATURES_OFFSET);
    if (CpuInfo[0] & KVM_FEATURE_CLOCKSOURCE2)
        Msr = MSR_KVM_SYSTEM_TIME_NEW;
    else if (CpuInfo[0] & KVM_FEATURE_CLOCKSOURCE)
        Msr = MSR_KVM_SYSTEM_TIME;
    else
        return 0;

    Address = MmGetPhysicalAddress((PVOID)&HalpKvmClock);
    if (!Address.QuadPart)
        return 0;

    /* Enable the clock structure of this processor (bit 0), which KVM fills
       before the guest runs again, read it, and disable it again: only the
       conversion factors are needed */
    RtlZeroMemory((PVOID)&HalpKvmClock, sizeof(HalpKvmClock));
    __writemsr(Msr, (ULONG64)Address.QuadPart | 1);
    for (Tries = 0; Tries < 1000; Tries++)
    {
        /* An odd version is an update in progress */
        Version = HalpKvmClock.Version;
        _ReadWriteBarrier();
        Mul = HalpKvmClock.TscToSystemMul;
        Shift = HalpKvmClock.TscShift;
        _ReadWriteBarrier();
        if (!(Version & 1) && (Version == HalpKvmClock.Version) && Mul)
        {
            HalpKvmTscStable = (CpuInfo[0] & KVM_FEATURE_CLOCKSOURCE_STABLE_BIT) &&
                               (HalpKvmClock.Flags & PVCLOCK_TSC_STABLE_BIT);
            break;
        }
        Mul = 0;
    }
    __writemsr(Msr, 0);
    if (!Mul || (Shift < -31) || (Shift > 31))
        return 0;

    /* nanoseconds = ((TSC ticks << Shift) * Mul) >> 32, with a negative Shift
       shifting right: so the frequency is 10^9 * 2^32 / Mul / 2^Shift */
    Frequency = ((1000000000ULL << 32) + Mul / 2) / Mul;
    if (Shift >= 0)
        Frequency = (Frequency + ((1ULL << Shift) >> 1)) >> Shift;
    else if (Frequency > (HV_TSC_MAXIMUM_FREQUENCY >> -Shift))
        return 0;
    else
        Frequency <<= -Shift;
    return Frequency;
}

/*!
    \brief Returns the TSC frequency the hypervisor reports, or 0.

    A hypervisor sets the rate of the guest TSC and can say what it is: the
    Hyper-V frequency MSR, KVM's paravirtual clock, or the timing leaf of
    VMware (and KVM when configured). This does not depend on how the guest
    processors are scheduled, while a calibration against a timer is wrong
    when the host does not run the processor in time.
*/
static
ULONG64
HalpGetHypervisorTscFrequency(VOID)
{
    INT CpuInfo[4];
    ULONG Base, Highest;
    ULONG64 Frequency = 0;

    /* Hyper-V, and hypervisors presenting its interface */
    Highest = HalpFindHypervisorBase(HV_SIGNATURE_MICROSOFT, &Base);
    if ((Base == 0x40000000) && (Highest >= HV_CPUID_FEATURES))
    {
        /* Both bits, as Linux does: reading the MSR without the second is a #GP
           on a host that grants the access but has no frequency to give */
        __cpuid(CpuInfo, HV_CPUID_FEATURES);
        if ((CpuInfo[0] & HV_ACCESS_FREQUENCY_MSRS) &&
            (CpuInfo[3] & HV_FEATURE_FREQUENCY_MSRS_AVAILABLE))
            Frequency = __readmsr(HV_X64_MSR_TSC_FREQUENCY);
    }

    /* KVM */
    if ((Frequency < HV_TSC_MINIMUM_FREQUENCY) || (Frequency > HV_TSC_MAXIMUM_FREQUENCY))
        Frequency = HalpGetKvmClockFrequency();

    /* The timing leaf, in kHz */
    if ((Frequency < HV_TSC_MINIMUM_FREQUENCY) || (Frequency > HV_TSC_MAXIMUM_FREQUENCY))
    {
        Frequency = 0;
        Highest = HalpFindHypervisorBase(HV_SIGNATURE_VMWARE, &Base);
        if (!Base)
            Highest = HalpFindHypervisorBase(HV_SIGNATURE_KVM, &Base);
        if (Base && (Highest >= Base + HV_CPUID_TIMING_OFFSET))
        {
            __cpuid(CpuInfo, Base + HV_CPUID_TIMING_OFFSET);
            Frequency = (ULONG64)(ULONG)CpuInfo[0] * 1000;
        }
    }

    if ((Frequency < HV_TSC_MINIMUM_FREQUENCY) || (Frequency > HV_TSC_MAXIMUM_FREQUENCY))
        return 0;
    return Frequency;
}

/* Measures the TSC frequency over four RTC interrupts */
static
VOID
HalpCalibrateTscWithRtc(VOID)
{
    ULONG_PTR Flags;
    PVOID PreviousHandler;
    UCHAR RegisterA, RegisterB;

     /* Save flags and disable interrupts */
    Flags = __readeflags();
    _disable();

    /* Enable the periodic interrupt in the CMOS */
    RegisterB = HalpReadCmos(RTC_REGISTER_B);
    HalpWriteCmos(RTC_REGISTER_B, RegisterB | RTC_REG_B_PI);

    /* Modify register A to RTC_MODE to get SAMPLE_FREQUENCY */
    RegisterA = HalpReadCmos(RTC_REGISTER_A);
    RegisterA = (RegisterA & 0xF0) | RTC_MODE;
    HalpWriteCmos(RTC_REGISTER_A, RegisterA);

    /* Save old IDT entry */
    PreviousHandler = KeQueryInterruptHandler(APIC_CLOCK_VECTOR);

    /* Set the calibration ISR */
    KeRegisterInterruptHandler(APIC_CLOCK_VECTOR, TscCalibrationISR);

    /* Enable the timer interrupt */
    HalEnableSystemInterrupt(APIC_CLOCK_VECTOR, CLOCK_LEVEL, Latched);

    /* Read register C, so that the next interrupt can happen */
    HalpReadCmos(RTC_REGISTER_C);

    /* Wait for completion */
    _enable();
    while (TscCalibrationPhase < NUM_SAMPLES) _ReadWriteBarrier();
    _disable();

    /* Disable the periodic interrupt in the CMOS */
    HalpWriteCmos(RTC_REGISTER_B, RegisterB & ~RTC_REG_B_PI);

    /* Disable the timer interrupt */
    HalDisableSystemInterrupt(APIC_CLOCK_VECTOR, CLOCK_LEVEL);

    /* Restore the previous handler */
    KeRegisterInterruptHandler(APIC_CLOCK_VECTOR, PreviousHandler);

    /* Calculate an average, using simplified linear regression */
    HalpCpuClockFrequency.QuadPart = DoLinearRegression(NUM_SAMPLES - 1,
                                                        TscCalibrationArray);

    /* Restore flags */
    __writeeflags(Flags);

}

/*
    The performance counter runs at 10 MHz, as on Windows 10, when the TSC is
    faster: the multiplier is floor(2^64 * 10^7 / frequency), found bit by bit
    (the remainder stays below the frequency, so below 2^40).
*/
static
VOID
HalpSetQpcScale(VOID)
{
    ULONG64 Frequency = (ULONG64)HalpCpuClockFrequency.QuadPart;
    ULONG64 Remainder = ROS_QPC_FREQUENCY, Multiplier = 0;
    ULONG Bit;

    if (Frequency <= ROS_QPC_FREQUENCY)
    {
        HalpQpcFrequency = HalpCpuClockFrequency;
        return;
    }

    for (Bit = 0; Bit < 64; Bit++)
    {
        Remainder <<= 1;
        Multiplier <<= 1;
        if (Remainder >= Frequency)
        {
            Remainder -= Frequency;
            Multiplier |= 1;
        }
    }

    HalpQpcMultiplier = Multiplier;
    _ReadWriteBarrier();
    HalpQpcFrequency.QuadPart = ROS_QPC_FREQUENCY;
}

VOID
NTAPI
HalpInitializeTsc(VOID)
{
    ULONG64 Frequency, RtcFrequency;
    ULONG Try;

    /* Check if the CPU supports RDTSC */
    if (!(KeGetCurrentPrcb()->FeatureBits & KF_RDTSC))
    {
        KeBugCheck(HAL_INITIALIZATION_FAILED);
    }

    /* A frequency the hypervisor reports does not depend on the host running
       this processor in time; a calibration is wrong by a lot when it does
       not (over ten times, measured under host load). The power management
       timer follows the host's disciplined clock and can be closer by some
       parts per million (the hypervisor's figure is the host's own TSC
       calibration, in kHz for KVM, and that can itself be off by more than
       0.1%), so its measurement is kept when it passes its own checks and
       agrees with the hypervisor's to 1/100, which still rejects the tenfold
       errors. Otherwise the hypervisor's figure is used.

       Note that the lost-tick catch-up of the clock interrupt then trusts this
       figure: a guest migrated to a host with another TSC frequency and no TSC
       scaling would run with a skewed one */
    Frequency = HalpGetHypervisorTscFrequency();
    if (Frequency)
    {
        PCSTR Source = "power management timer";

        if (!HalpCalibrateTscWithPmTimer(Frequency) ||
            ((ULONG64)HalpCpuClockFrequency.QuadPart > Frequency + Frequency / 100) ||
            ((ULONG64)HalpCpuClockFrequency.QuadPart < Frequency - Frequency / 100))
        {
            HalpCpuClockFrequency.QuadPart = Frequency;
            Source = "hypervisor";
        }
        HalpTscCalibrated = TRUE;
        DPRINT1("TSC frequency %I64u Hz (hypervisor %I64u Hz, using %s)\n",
                HalpCpuClockFrequency.QuadPart, Frequency, Source);
        HalpSetQpcScale();
        return;
    }

    /* Count RTC interrupts, then refine with the power management timer,
       which can be tried again when it was disturbed; the TSC is not reset
       (on this processor alone it would leave the TSCs of the processors
       out of step) */
    HalpCalibrateTscWithRtc();
    RtcFrequency = (ULONG64)HalpCpuClockFrequency.QuadPart;
    for (Try = 0; Try < PM_TIMER_TRIES; Try++)
    {
        if (HalpCalibrateTscWithPmTimer(RtcFrequency))
            break;
    }
    DPRINT1("TSC frequency %I64u Hz (RTC %I64u Hz, power management timer %s)\n",
            HalpCpuClockFrequency.QuadPart, RtcFrequency, HalpTscCalibrated ? "agrees" : "failed");
    HalpSetQpcScale();
}

CODE_SEG("INIT")
VOID
NTAPI
HalpCalibrateStallExecution(VOID)
{
    // Timer interrupt is now active

    HalpInitializeTsc();

    KeGetPcr()->StallScaleFactor = (ULONG)(HalpCpuClockFrequency.QuadPart / 1000000);
}

/* PUBLIC FUNCTIONS ***********************************************************/

LARGE_INTEGER
NTAPI
KeQueryPerformanceCounter(
    OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL)
{
    LARGE_INTEGER Result;

    /* Make sure it's calibrated */
    ASSERT(HalpCpuClockFrequency.QuadPart != 0);

    /* Does the caller want the frequency? */
    if (PerformanceFrequency)
    {
        /* The counter frequency once it is set, the TSC frequency before */
        *PerformanceFrequency = HalpQpcFrequency.QuadPart ? HalpQpcFrequency : HalpCpuClockFrequency;
    }

    /* The TSC, scaled as user mode scales it (rosqpc.h) */
    Result.QuadPart = RosQpcFromTsc(__rdtsc(), HalpQpcMultiplier, 0, 0);
    return Result;
}

VOID
NTAPI
KeStallExecutionProcessor(ULONG MicroSeconds)
{
    ULONG64 StartTime, EndTime;

    /* Get the initial time */
    StartTime = __rdtsc();

    /* Calculate the ending time */
    EndTime = StartTime + KeGetPcr()->StallScaleFactor * MicroSeconds;

    /* Loop until time is elapsed */
    while (__rdtsc() < EndTime);
}

/* All processors at once: each reads the TSC under a lock after the last
   value another one read there; a smaller value is a TSC behind another */
static
ULONG_PTR
NTAPI
HalpTscWarpWorker(
    _In_ ULONG_PTR Context)
{
    ULONG64 Previous, Now;
    ULONG Loop;

    UNREFERENCED_PARAMETER(Context);

    for (Loop = 0; Loop < HalpTscWarpLoops; Loop++)
    {
        while (InterlockedCompareExchange(&HalpTscWarpLock, 1, 0) != 0)
            YieldProcessor();

        Previous = HalpTscWarpLast;
        if (HalpTscWarpRdtscp)
        {
            Now = RosQpcReadTscp();
        }
        else
        {
            _mm_mfence();
            _mm_lfence();
            Now = __rdtsc();
        }
        HalpTscWarpLast = Now;
        InterlockedExchange(&HalpTscWarpLock, 0);

        if (Now < Previous)
            InterlockedIncrement(&HalpTscWarps);
    }

    return 0;
}

/*!
    \brief Lets user mode read the performance counter without a system call.

    Called when all processors run. The counter fields of the shared user
    data are published in any case. User mode reads the TSC of the processor
    it runs on, so the bypass is enabled only when that gives one counter for
    all of them: the TSC must be invariant (CPUID 0x80000007 EDX bit 8, or
    the stable bit of KVM's paravirtual clock) and no processor's TSC may be
    seen behind another's. Otherwise the system call gives the counter.
*/
VOID
NTAPI
HalpPublishPerformanceCounter(VOID)
{
    INT CpuInfo[4];
    ULONG MaximumExtended, Processors;
    BOOLEAN Invariant = FALSE, Rdtscp = FALSE, Amd;
    UCHAR Flags;

    if (!HalpQpcFrequency.QuadPart)
        return;

    SharedUserData->QpcMultiplier = HalpQpcMultiplier;
    SharedUserData->QpcBias = 0;
    SharedUserData->QpcShift = 0;
    SharedUserData->QpcFrequency = (ULONGLONG)HalpQpcFrequency.QuadPart;

    __cpuid(CpuInfo, 0);
    Amd = (CpuInfo[1] == 0x68747541); /* "Auth"enticAMD */
    __cpuid(CpuInfo, 0x80000000);
    MaximumExtended = (ULONG)CpuInfo[0];
    if (MaximumExtended >= 0x80000001)
    {
        __cpuid(CpuInfo, 0x80000001);
        Rdtscp = (CpuInfo[3] & (1 << 27)) != 0;
    }
    if (MaximumExtended >= 0x80000007)
    {
        __cpuid(CpuInfo, 0x80000007);
        Invariant = (CpuInfo[3] & (1 << 8)) != 0;
    }
    if (!Invariant)
    {
        /* Reads the stable bit, on this processor */
        HalpGetKvmClockFrequency();
        Invariant = HalpKvmTscStable;
    }
    if (!Invariant)
    {
        DPRINT1("QPC: TSC not invariant, user mode uses the system call\n");
        return;
    }

    Processors = (ULONG)KeNumberProcessors;
    if (Processors > 1)
    {
        HalpTscWarpLoops = TSC_WARP_LOOPS / Processors;
        if (HalpTscWarpLoops < TSC_WARP_MINIMUM_LOOPS)
            HalpTscWarpLoops = TSC_WARP_MINIMUM_LOOPS;
        HalpTscWarpRdtscp = Rdtscp;
        HalpTscWarpLast = 0;
        HalpTscWarps = 0;
        KeIpiGenericCall(HalpTscWarpWorker, 0);
        if (HalpTscWarps)
        {
            DPRINT1("QPC: TSCs of the %lu processors out of step (%ld times), user mode uses the system call\n",
                    Processors, HalpTscWarps);
            return;
        }
    }

    /* The TSC read in order, as Windows does: RDTSCP, else a fence first */
    Flags = SHARED_GLOBAL_FLAGS_QPC_BYPASS_ENABLED;
    if (Rdtscp)
        Flags |= SHARED_GLOBAL_FLAGS_QPC_BYPASS_USE_RDTSCP;
    else if (Amd)
        Flags |= SHARED_GLOBAL_FLAGS_QPC_BYPASS_USE_MFENCE;
    else
        Flags |= SHARED_GLOBAL_FLAGS_QPC_BYPASS_USE_LFENCE;

    _ReadWriteBarrier();
    SharedUserData->QpcBypassEnabled = Flags;
    DPRINT1("QPC: %I64u Hz in user mode (flags 0x%02x, %lu processors)\n",
            SharedUserData->QpcFrequency, Flags, Processors);
}

VOID
NTAPI
HalCalibratePerformanceCounter(
    IN volatile PLONG Count,
    IN ULONGLONG NewCount)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
}

