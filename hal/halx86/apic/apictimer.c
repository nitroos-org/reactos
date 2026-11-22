/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            hal/halx86/apic/apictimer.c
 * PURPOSE:         System Profiling
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <hal.h>
#include "apicp.h"
#define NDEBUG
#include <debug.h>

extern LARGE_INTEGER HalpCpuClockFrequency;

/* HAL profiling variables, intervals in 100 ns units */
BOOLEAN HalIsProfiling = FALSE;
ULONGLONG HalCurProfileInterval = 78125;
ULONGLONG HalMinProfileInterval = 1221;
ULONGLONG HalMaxProfileInterval = 10000000;

/* Local APIC timer ticks per millisecond at divide-by-1, measured at boot */
static ULONG HalpProfileTimerTicksPerMs = 10000;

/* The clock interrupt comes from the local APIC timer of the boot processor
   when the machine has neither the periodic interrupt of the RTC nor a PIT:
   Hyper-V generation 2 machines have neither ("Should I create a generation 1
   or 2 virtual machine in Hyper-V?", device table: PIT "No longer required";
   their RTC does not set the periodic flag). The timer is then the clock's,
   and there are no profile interrupts. */
BOOLEAN HalpClockUsesApicTimer;

/* TIMER FUNCTIONS ************************************************************/

VOID
NTAPI
ApicSetTimerInterval(ULONG MicroSeconds)
{
    LVT_REGISTER LvtEntry;
    ULONGLONG TimerInterval;

    /* Calculate the Timer interval */
    TimerInterval = HalpCpuClockFrequency.QuadPart * MicroSeconds / 1000000;

    /* Set the count interval */
    ApicWrite(APIC_TICR, (ULONG)TimerInterval);

    /* Set to periodic / masked */
    LvtEntry.Long = 0;
    LvtEntry.TimerMode = 1;
    LvtEntry.Vector = APIC_PROFILE_VECTOR;
    LvtEntry.Mask = 1;
    ApicWrite(APIC_TMRLVTR, LvtEntry.Long);

}

VOID
NTAPI
ApicInitializeTimer(ULONG Cpu)
{

    /* Initialize the TSC */
    //HalpInitializeTsc();

    /* Set clock multiplier to 1 */
    ApicWrite(APIC_TDCR, TIMER_DV_DivideBy1);

    ApicSetTimerInterval(1000);

// KeSetTimeIncrement
}

static
ULONG
HalpProfileIntervalToCount(
    _In_ ULONGLONG Interval)
{
    ULONGLONG Count;

    Count = Interval * HalpProfileTimerTicksPerMs / 10000;
    if (Count == 0)
        return 1;
    if (Count > MAXULONG)
        return MAXULONG;
    return (ULONG)Count;
}

VOID
FASTCALL
HalpProfileInterruptHandler(_In_ PKTRAP_FRAME TrapFrame)
{
#ifdef _M_IX86
    KIRQL Irql;

    /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);

    /* Start the interrupt */
    if (!HalBeginSystemInterrupt(APIC_PROFILE_LEVEL, APIC_PROFILE_VECTOR, &Irql))
    {
        /* Spurious, just end the interrupt */
        KiEoiHelper(TrapFrame);
    }

    KeProfileInterruptWithSource(TrapFrame, ProfileTime);

    /* On x86 this exits the trap: the entry stub must never be returned to */
    KiEndInterrupt(Irql, TrapFrame);
#else
    KeProfileInterruptWithSource(TrapFrame, ProfileTime);
#endif
}

/*!
    \brief Measures the local APIC timer of this processor against the
           calibrated TSC, with the timer masked; interrupts must be disabled.
*/
static
VOID
HalpCalibrateApicTimer(
    _In_ UCHAR Vector)
{
    ULONG64 T0, T1, T2, T3, Wait, Slack, TicksPerMs;
    ULONG Remaining, Attempt;
    LVT_REGISTER LvtEntry;

    /* Count down in one-shot mode with the interrupt masked */
    LvtEntry.Long = 0;
    LvtEntry.TimerMode = 0;
    LvtEntry.Vector = Vector;
    LvtEntry.Mask = 1;
    ApicWrite(APIC_TMRLVTR, LvtEntry.Long);
    ApicWrite(APIC_TDCR, TIMER_DV_DivideBy1);

    Wait = HalpCpuClockFrequency.QuadPart / 1000;
    Slack = Wait / 64;
    for (Attempt = 0; (Wait != 0) && (Attempt < 5); Attempt++)
    {
        /* TSC reads bracket both APIC accesses; a delay at either edge is retried */
        T0 = __rdtsc();
        ApicWrite(APIC_TICR, MAXULONG);
        T1 = __rdtsc();
        do
        {
            YieldProcessor();
            T2 = __rdtsc();
        } while ((T2 - T1) < Wait);
        Remaining = ApicRead(APIC_TCCR);
        T3 = __rdtsc();

        if ((Remaining == 0) || ((T1 - T0) > Slack) || ((T3 - T2) > Slack))
            continue;

        TicksPerMs = (ULONG64)(MAXULONG - Remaining) * Wait / (((T2 + T3) / 2) - ((T0 + T1) / 2));
        if ((TicksPerMs != 0) && (TicksPerMs <= MAXULONG))
        {
            HalpProfileTimerTicksPerMs = (ULONG)TicksPerMs;
            break;
        }
    }

    if ((Wait == 0) || (Attempt == 5))
    {
        DPRINT1("Local APIC timer not calibrated, assuming %lu ticks per ms\n",
                HalpProfileTimerTicksPerMs);
    }

    /* Stop the timer */
    ApicWrite(APIC_TICR, 0);
}

VOID
NTAPI
HalpInitializeProfileTimer(VOID)
{
    ULONG_PTR Flags;
    LVT_REGISTER LvtEntry;

    /* The clock measured the timer and runs on it */
    if (HalpClockUsesApicTimer)
        return;

    Flags = __readeflags();
    _disable();

    HalpCalibrateApicTimer(APIC_PROFILE_VECTOR);

    /* Leave it masked and periodic */
    LvtEntry.Long = 0;
    LvtEntry.TimerMode = 1;
    LvtEntry.Vector = APIC_PROFILE_VECTOR;
    LvtEntry.Mask = 1;
    ApicWrite(APIC_TMRLVTR, LvtEntry.Long);

    __writeeflags(Flags);
}

/*!
    \brief Makes the local APIC timer of the boot processor the clock source,
           masked and stopped until HalpApicTimerSetClockRate and
           HalpApicTimerEnableClock. Interrupts must be disabled.
*/
CODE_SEG("INIT")
VOID
NTAPI
HalpApicTimerStartClock(VOID)
{
    LVT_REGISTER LvtEntry;

    HalpClockUsesApicTimer = TRUE;
    HalpCalibrateApicTimer(APIC_CLOCK_VECTOR);

    LvtEntry.Long = 0;
    LvtEntry.TimerMode = 1;
    LvtEntry.Vector = APIC_CLOCK_VECTOR;
    LvtEntry.Mask = 1;
    ApicWrite(APIC_TMRLVTR, LvtEntry.Long);
}

/*!
    \brief Sets the period of the clock on the local APIC timer; called on the
           boot processor (the clock interrupt runs there).
*/
VOID
NTAPI
HalpApicTimerSetClockRate(
    _In_ ULONG Hz)
{
    ULONG64 Count = ((ULONG64)HalpProfileTimerTicksPerMs * 1000 + Hz / 2) / Hz;

    if (Count == 0)
        Count = 1;
    if (Count > MAXULONG)
        Count = MAXULONG;

    /* Writing the initial count restarts the period */
    ApicWrite(APIC_TICR, (ULONG)Count);
}

CODE_SEG("INIT")
VOID
NTAPI
HalpApicTimerEnableClock(VOID)
{
    LVT_REGISTER LvtEntry;

    LvtEntry.Long = 0;
    LvtEntry.TimerMode = 1;
    LvtEntry.Vector = APIC_CLOCK_VECTOR;
    LvtEntry.Mask = 0;
    ApicWrite(APIC_TMRLVTR, LvtEntry.Long);
}


/* PUBLIC FUNCTIONS ***********************************************************/

VOID
NTAPI
HalInitializeProfiling(VOID)
{
    /* All processors count at the rate measured on the boot processor */
    ApicWrite(APIC_TDCR, TIMER_DV_DivideBy1);
}

VOID
NTAPI
HalStartProfileInterrupt(IN KPROFILE_SOURCE ProfileSource)
{
    LVT_REGISTER LvtEntry;

    /* The local APIC timer is the clock */
    if (HalpClockUsesApicTimer)
        return;

    /* Only handle ProfileTime */
    if (ProfileSource == ProfileTime)
    {
        /* OK, we are profiling now */
        HalIsProfiling = TRUE;

        /* Periodic and unmasked first: a one-shot count could expire before the mode changes */
        LvtEntry.Long = 0;
        LvtEntry.TimerMode = 1;
        LvtEntry.Vector = APIC_PROFILE_VECTOR;
        LvtEntry.Mask = 0;
        ApicWrite(APIC_TMRLVTR, LvtEntry.Long);

        /* Set interrupt interval, which starts the count */
        ApicWrite(APIC_TICR, HalpProfileIntervalToCount(HalCurProfileInterval));
    }
}

VOID
NTAPI
HalStopProfileInterrupt(IN KPROFILE_SOURCE ProfileSource)
{
    LVT_REGISTER LvtEntry;

    /* The local APIC timer is the clock */
    if (HalpClockUsesApicTimer)
        return;

    /* Only handle ProfileTime */
    if (ProfileSource == ProfileTime)
    {
        /* We are not profiling */
        HalIsProfiling = FALSE;

        /* Mask interrupt */
        LvtEntry.Long = 0;
        LvtEntry.TimerMode = 1;
        LvtEntry.Vector = APIC_PROFILE_VECTOR;
        LvtEntry.Mask = 1;
        ApicWrite(APIC_TMRLVTR, LvtEntry.Long);
    }
}

ULONG_PTR
NTAPI
HalSetProfileInterval(IN ULONG_PTR Interval)
{
    ULONGLONG FixedInterval;

    FixedInterval = (ULONGLONG)Interval;

    /* Check bounds */
    if (FixedInterval < HalMinProfileInterval)
    {
        FixedInterval = HalMinProfileInterval;
    }
    else if (FixedInterval > HalMaxProfileInterval)
    {
        FixedInterval = HalMaxProfileInterval;
    }

    /* Remember interval */
    HalCurProfileInterval = FixedInterval;

    /* A running profile timer takes the new interval at once */
    if (HalIsProfiling && !HalpClockUsesApicTimer)
        ApicWrite(APIC_TICR, HalpProfileIntervalToCount(FixedInterval));

    return (ULONG_PTR)FixedInterval;
}
