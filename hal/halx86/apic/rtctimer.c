/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GNU GPL - See COPYING in the top level directory
 * FILE:            hal/halx86/apic/rtctimer.c
 * PURPOSE:         HAL APIC Management and Control Code
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 * REFERENCES:      https://wiki.osdev.org/RTC
 *                  https://forum.osdev.org/viewtopic.php?f=13&t=20825&start=0
 *                  https://web.archive.org/web/20240119203005/http://www.bioscentral.com/misc/cmosmap.htm
 */

/* INCLUDES *******************************************************************/

#include <hal.h>
#include "apicp.h"
#include "tsc.h"
#include <smp.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

static const UCHAR RtcMinimumClockRate = 6;  /* Minimum rate  6: 1024 Hz / 0.97 ms */
static const UCHAR RtcMaximumClockRate = 10; /* Maximum rate 10: 64 Hz / 15.6 ms */
static UCHAR HalpCurrentClockRate = 10;  /* Initial rate  10: 64 Hz / 15.6 ms */
static ULONG HalpCurrentTimeIncrement;
static ULONG HalpMinimumTimeIncrement;
static ULONG HalpMaximumTimeIncrement;
static ULONG HalpCurrentFractionalIncrement;
static ULONG HalpRunningFraction;
static BOOLEAN HalpSetClockRate;
static UCHAR HalpNextClockRate;

/* The other processors charge run time and decrement the quantum once per clock
   tick (KeMaximumIncrement) in KeUpdateRunTime, as the kernel does on this one in
   KeUpdateSystemTime. The clock IPI is therefore sent only on the interrupts that
   complete a tick: at a raised clock rate (timeBeginPeriod) every interrupt was
   charged as a full tick, about 16 times the elapsed time at 1 ms. This follows
   the kernel tick offset (KiTickOffset) with the same increments. */
static LONG HalpClockIpiTickOffset;

/* The RTC raises its next periodic interrupt only after register C was read, so
   periods that end while an interrupt is still pending are lost (interrupts
   disabled for longer than a period, or a hypervisor that does not run the
   processor in time). The clock interrupt counts them with the TSC, when the
   TSC runs at a constant rate and was calibrated precisely, and reports them
   to the kernel. */
extern BOOLEAN HalpClockCountsLostInterrupts;
static BOOLEAN HalpClockTscUsable;
static ULONG64 HalpClockPeriodTsc;      /* whole TSC ticks per period, 0: do not count */
static ULONG HalpClockPeriodFraction;   /* and this many 1/HalpClockRtcHz ticks */
static ULONG HalpClockRtcHz;
static ULONG HalpClockFractionSum;
static ULONG64 HalpClockLongestPeriodTsc;
static ULONG HalpClockMaximumPeriods;   /* at most this many periods per interrupt */
static ULONG64 HalpClockGridTsc;        /* TSC of the last period end counted */
static LONG64 HalpClockDebtTsc;         /* TSC time the grid moves still owe to the count */
static LONG HalpClockDebtFraction;      /* and this many 1/HalpClockRtcHz ticks */
static ULONG HalpClockGridProcessor;
static BOOLEAN HalpClockGridValid;
static BOOLEAN HalpClockCarry;          /* periods are left to count */
static ULONG HalpClockWindow;

#define CLOCK_PHASE_WINDOW 32
static LONG64 HalpClockOffset[CLOCK_PHASE_WINDOW];

/*!
    \brief Converts the CMOS RTC rate into the time increment in 0.1ns intervals.

    Rate Frequency Interval (ms) Precise increment (0.1ns)
    ------------------------------------------------------
     0   disabled
     1   32768      0.03052            305,175
     2   16384      0.06103            610,351
     3    8192      0.12207          1,220,703
     4    4096      0.24414          2,441,406
     5    2048      0.48828          4,882,812
     6    1024      0.97656          9,765,625 <- minimum
     7     512      1.95313         19,531,250
     8     256      3.90625         39,062,500
     9     128      7.8125          78,125,000
    10      64     15.6250         156,250,000 <- maximum / default
    11      32     31.25           312,500,000
    12      16     62.5            625,000,000
    13       8    125            1,250,000,000
    14       4    250            2,500,000,000
    15       2    500            5,000,000,000

*/
FORCEINLINE
ULONG
RtcClockRateToPreciseIncrement(UCHAR Rate)
{
    /* Calculate frequency */
    ULONG Frequency = 32768 >> (Rate - 1);

    /* Calculate interval in 0.1ns interval: Interval = (1 / Frequency) * 10,000,000,000 */
    return 10000000000ULL / Frequency;
}

VOID
RtcSetClockRate(UCHAR ClockRate)
{
    UCHAR RegisterA;
    ULONG PreciseIncrement, RtcHz;

    /* Update the global values */
    HalpCurrentClockRate = ClockRate;
    PreciseIncrement = RtcClockRateToPreciseIncrement(ClockRate);
    HalpCurrentTimeIncrement = PreciseIncrement / 1000;
    HalpCurrentFractionalIncrement = PreciseIncrement % 1000;

    /* Count periods of the new length from the last period end counted; the
       grid finds the phase of the new periods again, and the debt (TSC time)
       carries over. TSC ticks per period = frequency / RTC frequency, kept as
       quotient and remainder (no product that could overflow) */
    RtcHz = 32768 >> (ClockRate - 1);
    if (HalpClockRtcHz)
    {
        /* The fractions of a TSC tick in units of the new period's fraction */
        HalpClockFractionSum = (ULONG)((ULONG64)HalpClockFractionSum * RtcHz / HalpClockRtcHz);
        HalpClockDebtFraction = (LONG)((LONG64)HalpClockDebtFraction * (LONG)RtcHz / (LONG)HalpClockRtcHz);
    }
    HalpClockRtcHz = RtcHz;
    HalpClockPeriodTsc = HalpClockTscUsable ? (ULONG64)HalpCpuClockFrequency.QuadPart / RtcHz : 0;
    HalpClockPeriodFraction = (ULONG)((ULONG64)HalpCpuClockFrequency.QuadPart % RtcHz);
    HalpClockLongestPeriodTsc = HalpClockTscUsable ?
        (ULONG64)HalpCpuClockFrequency.QuadPart / (32768 >> (RtcMaximumClockRate - 1)) : 0;
    HalpClockMaximumPeriods = 600000000 / HalpCurrentTimeIncrement;
    HalpClockCountsLostInterrupts = (HalpClockPeriodTsc / 8) != 0;
    HalpClockWindow = 0;

    /* Acquire CMOS lock */
    HalpAcquireCmosSpinLock();

    // TODO: disable NMI

    /* Read value of register A */
    RegisterA = HalpReadCmos(RTC_REGISTER_A);

    /* Change lower 4 bits to new rate */
    RegisterA &= 0xF0;
    RegisterA |= ClockRate;

    /* Write the new value */
    HalpWriteCmos(RTC_REGISTER_A, RegisterA);

    /* Release CMOS lock */
    HalpReleaseCmosSpinLock();
}

CODE_SEG("INIT")
VOID
NTAPI
HalpInitializeClock(VOID)
{
    ULONG_PTR EFlags;
    UCHAR RegisterB;

    /* Count lost periods with the TSC only if it runs at a constant rate: an
       invariant TSC, or a hypervisor, which keeps the guest TSC rate fixed */
    if (HalpTscCalibrated)
    {
        INT CpuInfo[4];

        __cpuid(CpuInfo, 1);
        HalpClockTscUsable = (CpuInfo[2] & 0x80000000) != 0;
        __cpuid(CpuInfo, 0x80000000);
        if ((ULONG)CpuInfo[0] >= 0x80000007)
        {
            __cpuid(CpuInfo, 0x80000007);
            HalpClockTscUsable |= (CpuInfo[3] & 0x100) != 0;
        }
    }

    /* Save EFlags and disable interrupts */
    EFlags = __readeflags();
    _disable();

    // TODO: disable NMI

    /* Acquire CMOS lock */
    HalpAcquireCmosSpinLock();

    /* Enable the periodic interrupt in the CMOS */
    RegisterB = HalpReadCmos(RTC_REGISTER_B);
    HalpWriteCmos(RTC_REGISTER_B, RegisterB | RTC_REG_B_PI);

    /* Don't leave already pending */
    HalpReadCmos(RTC_REGISTER_C);
    HalpReadCmos(RTC_REGISTER_D);

    /* Release CMOS lock */
    HalpReleaseCmosSpinLock();

    /* Set initial rate */
    RtcSetClockRate(HalpCurrentClockRate);

    /* Restore interrupt state */
    __writeeflags(EFlags);

    /* Calculate minumum and maximum increment */
    HalpMinimumTimeIncrement = RtcClockRateToPreciseIncrement(RtcMinimumClockRate) / 1000;
    HalpMaximumTimeIncrement = RtcClockRateToPreciseIncrement(RtcMaximumClockRate) / 1000;

    /* Notify the kernel about the maximum and minimum increment */
    KeSetTimeIncrement(HalpMaximumTimeIncrement, HalpMinimumTimeIncrement);
    HalpClockIpiTickOffset = (LONG)HalpMaximumTimeIncrement;

    /* Enable the timer interrupt */
    HalEnableSystemInterrupt(APIC_CLOCK_VECTOR, CLOCK_LEVEL, Latched);

    /* The pin is edge triggered */
    HalpAcquireCmosSpinLock();
    HalpReadCmos(RTC_REGISTER_C);
    HalpReleaseCmosSpinLock();

    DPRINT1("Clock initialized\n");
}

/*!
    \brief Returns the number of clock periods to report for this interrupt,
           counting the periods whose interrupt was lost.

    \param Now
        TSC at the interrupt, taken before register C is read.

    The time is counted with the TSC on a grid of periods: an interrupt reports
    the grid points passed since the last one, so the reported time follows
    the TSC whatever the latency of single interrupts, and can be 0 for an
    interrupt. The grid is kept so that interrupts arrive 1/8 period after a
    grid point, where their jitter does not move the count between
    interrupts: every 32 interrupts it moves by the median offset of their
    arrival from that position (at most 1/8 period). A move would change the
    reported time, so it is kept as debt and paid back in whole periods; the
    reported time stays within a period of the TSC time whatever the moves.
    Without a usable TSC every interrupt reports one period, as before.
*/
static
ULONG
HalpClockElapsedPeriods(
    _In_ ULONG64 Now)
{
    ULONG64 Period = HalpClockPeriodTsc;
    LONG64 Target = (LONG64)(Period / 8);
    ULONG64 Periods;
    LONG64 Elapsed, Offset, Move;
    ULONG Processor = KeGetCurrentProcessorNumber();
    ULONG Reported, i;

    /* The grid can be ahead of the TSC by a move, up to 1/8 of the longest
       period: only more is a counter discontinuity */
    Elapsed = (LONG64)(Now - HalpClockGridTsc);
    if (!Target || !HalpClockGridValid || (Processor != HalpClockGridProcessor) ||
        (Elapsed < -(LONG64)HalpClockLongestPeriodTsc))
    {
        HalpClockGridTsc = Now - Target;
        HalpClockGridProcessor = Processor;
        HalpClockGridValid = (Target != 0);
        HalpClockDebtTsc = 0;
        HalpClockDebtFraction = 0;
        HalpClockFractionSum = 0;
        HalpClockCarry = FALSE;
        HalpClockWindow = 0;
        return 1;
    }

    /* Count exactly, with the fraction of a tick per period: the grid point is
       at HalpClockGridTsc + HalpClockFractionSum / HalpClockRtcHz, a period is
       HalpClockPeriodTsc + HalpClockPeriodFraction / HalpClockRtcHz, less than
       twice HalpClockPeriodTsc. So more than 2 * (maximum count + 1) whole
       periods certainly exceed the maximum count; below that, Elapsed is under
       about two minutes and the products fit 64 bits for any TSC below 100 THz */
    Periods = (Elapsed < 0) ? 0 : (ULONG64)Elapsed / Period;
    if (Periods > 2 * ((ULONG64)HalpClockMaximumPeriods + 1))
        Periods = (ULONG64)HalpClockMaximumPeriods + 1;
    else if (Periods)
        Periods = ((ULONG64)Elapsed * HalpClockRtcHz - HalpClockFractionSum) /
                  (Period * HalpClockRtcHz + HalpClockPeriodFraction);
    HalpClockCarry = (Periods > HalpClockMaximumPeriods);
    if (HalpClockCarry)
    {
        /* Count the rest on the next interrupts */
        Periods = HalpClockMaximumPeriods;
        HalpClockWindow = 0;
    }
    HalpClockFractionSum += (ULONG)Periods * HalpClockPeriodFraction;
    HalpClockGridTsc += Periods * Period + HalpClockFractionSum / HalpClockRtcHz;
    HalpClockFractionSum %= HalpClockRtcHz;
    Reported = (ULONG)Periods;
    if (HalpClockCarry)
        return Reported;

    /* Offset of the arrival from its place in the period, kept sorted */
    Offset = (LONG64)(Now - HalpClockGridTsc) - Target;
    while (Offset >= (LONG64)(Period / 2))
        Offset -= (LONG64)Period;
    while (Offset < -(LONG64)(Period / 2))
        Offset += (LONG64)Period;
    for (i = HalpClockWindow; (i > 0) && (HalpClockOffset[i - 1] > Offset); i--)
        HalpClockOffset[i] = HalpClockOffset[i - 1];
    HalpClockOffset[i] = Offset;

    if (++HalpClockWindow >= CLOCK_PHASE_WINDOW)
    {
        Move = HalpClockOffset[CLOCK_PHASE_WINDOW / 2];
        if (Move > Target)
            Move = Target;
        if (Move < -Target)
            Move = -Target;
        HalpClockGridTsc += Move;
        HalpClockDebtTsc += Move;
        HalpClockWindow = 0;
    }

    /* Pay the debt of the grid moves */
    if (HalpClockDebtTsc >= (LONG64)Period)
    {
        Reported++;
        HalpClockDebtTsc -= (LONG64)Period;
        HalpClockDebtFraction -= (LONG)HalpClockPeriodFraction;
        if (HalpClockDebtFraction <= -(LONG)HalpClockRtcHz)
        {
            HalpClockDebtTsc--;
            HalpClockDebtFraction += (LONG)HalpClockRtcHz;
        }
    }
    else if ((HalpClockDebtTsc <= -(LONG64)Period) && Reported)
    {
        Reported--;
        HalpClockDebtTsc += (LONG64)Period;
        HalpClockDebtFraction += (LONG)HalpClockPeriodFraction;
        if (HalpClockDebtFraction >= (LONG)HalpClockRtcHz)
        {
            HalpClockDebtTsc++;
            HalpClockDebtFraction -= (LONG)HalpClockRtcHz;
        }
    }

    return Reported;
}

VOID
FASTCALL
HalpClockInterruptHandler(IN PKTRAP_FRAME TrapFrame)
{
    ULONG LastIncrement, Periods;
    ULONG64 Now;
    KIRQL Irql;

    /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);

    /* The time of this interrupt, before register C is read and the RTC can
       raise the next one */
    Now = __rdtsc();
#ifdef _M_AMD64
    /* This is for debugging */
    TrapFrame->ErrorCode = 0xc10c4;
#endif

    /* Start the interrupt */
    if (!HalBeginSystemInterrupt(CLOCK_LEVEL, APIC_CLOCK_VECTOR, &Irql))
    {
        /* Spurious, just end the interrupt */
#ifdef _M_IX86
        KiEoiHelper(TrapFrame);
#endif
        return;
    }

    /* Read register C, so that the next interrupt can happen; under the lock,
       or another processor can select a register between the index write and the read */
    HalpAcquireCmosSpinLock();
    HalpReadCmos(RTC_REGISTER_C);
    HalpReleaseCmosSpinLock();

    /* Save increment, one per period that ended since the last interrupt */
    Periods = HalpClockElapsedPeriods(Now);
    LastIncrement = Periods * HalpCurrentTimeIncrement;

    /* Check if the running fraction has accounted for 100 ns */
    HalpRunningFraction += Periods * HalpCurrentFractionalIncrement;
    LastIncrement += HalpRunningFraction / 1000;
    HalpRunningFraction %= 1000;

    /* Check if someone changed the time rate; not while lost periods are
       still counted at the current one */
    if (HalpSetClockRate && !HalpClockCarry)
    {
        /* Set new clock rate */
        RtcSetClockRate(HalpNextClockRate);

        /* We're done */
        HalpSetClockRate = FALSE;
    }

    /* Send the clock IPI to all other CPUs when this interrupt completes a
       clock tick (several ticks when it reports lost periods) */
    HalpClockIpiTickOffset -= (LONG)LastIncrement;
    if (HalpClockIpiTickOffset <= 0)
    {
        HalpClockIpiTickOffset += (LONG)HalpMaximumTimeIncrement *
            (LONG)(1 + (ULONG)(-HalpClockIpiTickOffset) / HalpMaximumTimeIncrement);
        HalpBroadcastClockIpi(CLOCK_IPI_VECTOR);
    }

    /* Update the system time -- on x86 the kernel will exit this trap  */
    KeUpdateSystemTime(TrapFrame, LastIncrement, Irql);

    /* End the interrupt */
    KiEndInterrupt(Irql, TrapFrame);
}

VOID
FASTCALL
HalpClockIpiHandler(IN PKTRAP_FRAME TrapFrame)
{
    KIRQL Irql;

    /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);
#ifdef _M_AMD64
    /* This is for debugging */
    TrapFrame->ErrorCode = 0xc10c4;
#endif

    /* Start the interrupt */
    if (!HalBeginSystemInterrupt(CLOCK_LEVEL, CLOCK_IPI_VECTOR, &Irql))
    {
        /* Spurious, just end the interrupt */
#ifdef _M_IX86
        KiEoiHelper(TrapFrame);
#endif
        return;
    }

    /* Call the kernel to update runtimes */
    KeUpdateRunTime(TrapFrame, Irql);

    /* End the interrupt */
    KiEndInterrupt(Irql, TrapFrame);
}

ULONG
NTAPI
HalSetTimeIncrement(IN ULONG Increment)
{
    UCHAR Rate;
    ULONG NextIncrement;

    /* Lookup largest value below given Increment */
    for (Rate = RtcMinimumClockRate; Rate < RtcMaximumClockRate; Rate++)
    {
        /* Check if this is the largest rate possible */
        NextIncrement = RtcClockRateToPreciseIncrement(Rate + 1) / 1000;
        if (NextIncrement > Increment)
            break;
    }

    /* Set the rate and tell HAL we want to change it */
    HalpNextClockRate = Rate;
    HalpSetClockRate = TRUE;

    /* Return the real increment */
    return RtcClockRateToPreciseIncrement(Rate) / 1000;
}
