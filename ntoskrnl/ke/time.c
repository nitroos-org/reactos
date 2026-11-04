/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/ke/time.c
 * PURPOSE:         Implements timebase functionality
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

LONG KiTickOffset;
ULONG KeTimeAdjustment;
BOOLEAN KiTimeAdjustmentEnabled = FALSE;

/* How the time of the last clock interrupt relates to the interrupt time, for
   KiQueryClockPhase. The interrupt time moves in steps at clock interrupts; the
   performance counter value taken at an interrupt (KiClockStamp) is later than
   the time the interrupt time stands for by the latency of that interrupt, and
   that latency is not known. What is known is how much later than the least
   latency seen so far this interrupt was (KiClockLateness, in 100 ns units):
   each interrupt adds the difference between the time the counter measured since
   the last one and the interrupt time it moved, and the sum does not go below
   zero. It is written by the clock interrupt of the boot processor only, and
   read with the sequence number, which is odd while it is written. */
#define KI_CLOCK_SETTLE_UPDATES 16

/* Clock interrupts can arrive earlier than the earliest one seen so far; half a
   millisecond (in 100 ns units) is added to the time counted from the last one */
#define KI_CLOCK_PHASE_MARGIN 5000

/* Clock interrupts can be delayed by more than a period (a virtual processor
   that is not running); the time counted from the last one is not cut before
   this many periods */
#define KI_CLOCK_PHASE_LIMIT 4
static volatile ULONG KiClockSequence;
static volatile ULONGLONG KiClockStamp;
static volatile LONGLONG KiClockLateness;

/* FUNCTIONS ******************************************************************/

FORCEINLINE
LONGLONG
KiScaleCounterDelta(IN ULONGLONG Delta, IN LONGLONG Frequency)
{
    /* Counter ticks to 100 ns; two seconds at most, so that the product fits */
    if (Delta > (ULONGLONG)(2 * Frequency)) Delta = 2 * Frequency;
    return (LONGLONG)((Delta * 10000000ULL) / (ULONGLONG)Frequency);
}

static
VOID
NTAPI
KiRecordClockInterrupt(IN ULONG Increment)
{
    LARGE_INTEGER Now, Frequency;
    LONGLONG Lateness, Diff;
    ULONGLONG Stamp;

    Now = KeQueryPerformanceCounter(&Frequency);
    Stamp = KiClockStamp;
    Lateness = KiClockLateness;

    if (!Stamp || (Frequency.QuadPart <= 0))
    {
        /* The first interrupt, nothing to compare with */
        Lateness = 0;
    }
    else if ((ULONGLONG)Now.QuadPart <= Stamp)
    {
        /* The counter did not move forward: the safe side is the longest delay */
        Lateness = KeMaximumIncrement;
    }
    else
    {
        /* Lateness gained against the interrupt time, forgetting slowly so that
           a difference between the counter and the clock cannot add up */
        Diff = KiScaleCounterDelta(Now.QuadPart - Stamp, Frequency.QuadPart) - (LONGLONG)Increment;
        Lateness = Lateness - (Lateness >> 6) + Diff;
        if (Lateness < 0) Lateness = 0;
        if (Lateness > (LONGLONG)KeMaximumIncrement) Lateness = KeMaximumIncrement;
    }

    KiClockSequence++;
    _ReadWriteBarrier();
    KiClockStamp = Now.QuadPart;
    KiClockLateness = Lateness;
    _ReadWriteBarrier();
    KiClockSequence++;
}

LONGLONG
NTAPI
KiQueryClockPhase(VOID)
{
    LARGE_INTEGER Now, Frequency;
    ULONGLONG Stamp;
    LONGLONG Lateness, Phase;
    ULONG Sequence;

    /* Read the record consistently */
    for (;;)
    {
        Sequence = KiClockSequence;
        _ReadWriteBarrier();
        Stamp = KiClockStamp;
        Lateness = KiClockLateness;
        _ReadWriteBarrier();
        if (!(Sequence & 1) && (Sequence == KiClockSequence)) break;
        YieldProcessor();
    }

    /* While the record settles, or when the counter cannot be related to it,
       assume the longest delay: the safe side, a delay ends later */
    Now = KeQueryPerformanceCounter(&Frequency);
    if ((Sequence < (2 * KI_CLOCK_SETTLE_UPDATES)) || (Frequency.QuadPart <= 0) ||
        ((ULONGLONG)Now.QuadPart < Stamp))
    {
        return KeMaximumIncrement;
    }

    /* The time since that interrupt, and how late the interrupt was; a delay
       counted from the interrupt time is then not shorter than requested */
    Phase = KiScaleCounterDelta(Now.QuadPart - Stamp, Frequency.QuadPart) + Lateness +
            KI_CLOCK_PHASE_MARGIN;
    return (Phase < (LONGLONG)(KI_CLOCK_PHASE_LIMIT * KeMaximumIncrement)) ?
           Phase : (LONGLONG)(KI_CLOCK_PHASE_LIMIT * KeMaximumIncrement);
}

FORCEINLINE
VOID
KiCheckForTimerExpiration(
    PKPRCB Prcb,
    PKTRAP_FRAME TrapFrame,
    LARGE_INTEGER InterruptTime,
    ULONG TickCount)
{
    ULONG Hand;

    /* Check for timer expiration */
    Hand = TickCount & (TIMER_TABLE_SIZE - 1);
    if (KiTimerTableListHead[Hand].Time.QuadPart <= (ULONG64)InterruptTime.QuadPart)
    {
        /* Check if we are already doing expiration */
        if (!Prcb->TimerRequest)
        {
            /* Request a DPC to handle this; the full tick count, so that the
               expiration scan knows how far the tick count moved meanwhile */
            Prcb->TimerRequest = (ULONG_PTR)TrapFrame;
            Prcb->TimerHand = TickCount;
            HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
        }
    }
}

VOID
FASTCALL
KeUpdateSystemTime(IN PKTRAP_FRAME TrapFrame,
                   IN ULONG Increment,
                   IN KIRQL Irql)
{
    PKPRCB Prcb = KeGetCurrentPrcb();
    LARGE_INTEGER CurrentTime, InterruptTime;
    ULARGE_INTEGER TickCount;
    LONG OldTickOffset, NewTickOffset;
    ULONG Ticks, i;

    /* Check if this tick is being skipped */
    if (Prcb->SkipTick)
    {
        /* Handle it next time */
        Prcb->SkipTick = FALSE;

        /* Increase interrupt count and end the interrupt */
        Prcb->InterruptCount++;

#ifdef _M_IX86 // x86 optimization
        KiEndInterrupt(Irql, TrapFrame);
#endif

        /* Note: non-x86 return back to the caller! */
        return;
    }

    /* Add the increment time to the shared data */
    InterruptTime.QuadPart = *(ULONGLONG*)&SharedUserData->InterruptTime;
    InterruptTime.QuadPart += Increment;
    KiWriteSystemTime(&SharedUserData->InterruptTime, InterruptTime);

    /* Remember when that was, for KiQueryClockPhase */
    KiRecordClockInterrupt(Increment);

    /* Check for timer expiration */
    KiCheckForTimerExpiration(Prcb, TrapFrame, InterruptTime, KeTickCount.LowPart);

    /* Update the tick offset */
    OldTickOffset = InterlockedExchangeAdd(&KiTickOffset, -(LONG)Increment);

    /* If the debugger is enabled, check for break-in request */
    if (KdDebuggerEnabled && KdPollBreakIn())
    {
        /* Break-in requested! */
        DbgBreakPointWithStatus(DBG_STATUS_CONTROL_C);
    }

    /* Check for full tick */
    if (OldTickOffset <= (LONG)Increment)
    {
        /* One tick, or several when the HAL reports clock interrupts that
           could not be delivered: every tick the increment covers is counted */
        NewTickOffset = OldTickOffset - (LONG)Increment;
        Ticks = 1 + (ULONG)(-NewTickOffset) / KeMaximumIncrement;

        /* Update the system time */
        CurrentTime.QuadPart = *(ULONGLONG*)&SharedUserData->SystemTime;
        CurrentTime.QuadPart += (ULONGLONG)KeTimeAdjustment * Ticks;
        KiWriteSystemTime(&SharedUserData->SystemTime, CurrentTime);

        /* Update the tick count */
        TickCount.QuadPart = *(ULONGLONG*)&KeTickCount;
        CurrentTime.QuadPart = TickCount.QuadPart + Ticks;
        KiWriteSystemTime(&KeTickCount, CurrentTime);

        /* Update it in the shared user data */
        KiWriteSystemTime(&SharedUserData->TickCount, CurrentTime);

        /* Check for expiration with each new tick count as well, in the order
           they were passed */
        if (Ticks < TIMER_TABLE_SIZE)
        {
            for (i = 1; i <= Ticks; i++)
            {
                KiCheckForTimerExpiration(Prcb, TrapFrame, InterruptTime, TickCount.LowPart + i);
            }
        }
        else
        {
            /* Every hand was passed: request a scan of the whole table, with
               a tick count one revolution back */
            Prcb->TimerRequest = (ULONG_PTR)TrapFrame;
            Prcb->TimerHand = CurrentTime.LowPart - TIMER_TABLE_SIZE;
            HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
        }

        /* Reset the tick offset */
        KiTickOffset += (LONG)(KeMaximumIncrement * Ticks);

        /* Update processor/thread runtime */
        KeUpdateRunTime(TrapFrame, Irql);
    }
    else
    {
        /* Increase interrupt count only */
        Prcb->InterruptCount++;
    }

#ifdef _M_IX86 // x86 optimization
    /* Disable interrupts and end the interrupt */
    KiEndInterrupt(Irql, TrapFrame);
#endif
}

VOID
NTAPI
KeUpdateRunTime(IN PKTRAP_FRAME TrapFrame,
                IN KIRQL Irql)
{
    PKTHREAD Thread = KeGetCurrentThread();
    PKPRCB Prcb = KeGetCurrentPrcb();

    /* Check if this tick is being skipped */
    if (Prcb->SkipTick)
    {
        /* Handle it next time */
        Prcb->SkipTick = FALSE;
        return;
    }

    /* Increase interrupt count */
    Prcb->InterruptCount++;

    /* Check if we came from user mode */
#ifndef _M_ARM
    if (KiUserTrap(TrapFrame) || (TrapFrame->EFlags & EFLAGS_V86_MASK))
#else
    if (TrapFrame->PreviousMode == UserMode)
#endif
    {
        /* Increase thread user time */
        Prcb->UserTime++;
        Thread->UserTime++;
    }
    else
    {
        /* See if we were in an ISR */
        Prcb->KernelTime++;
        if (Irql > DISPATCH_LEVEL)
        {
            /* Handle that */
            Prcb->InterruptTime++;
        }
        else if ((Irql < DISPATCH_LEVEL) || !(Prcb->DpcRoutineActive))
        {
            /* Handle being in kernel mode */
            Thread->KernelTime++;
        }
        else
        {
            /* Handle being in a DPC */
            Prcb->DpcTime++;

#if DBG
            /* Update the DPC time */
            Prcb->DebugDpcTime++;

            /* Check if we have timed out */
            if (Prcb->DebugDpcTime == KiDPCTimeout)
            {
                /* We did! */
                DbgPrint("*** DPC routine > 1 sec --- This is not a break in KeUpdateSystemTime\n");

                /* Break if debugger is enabled */
                if (KdDebuggerEnabled) DbgBreakPoint();

                /* Clear state */
                Prcb->DebugDpcTime = 0;
            }
#endif
        }
    }

    /* Update DPC rates */
    Prcb->DpcRequestRate = ((Prcb->DpcData[0].DpcCount - Prcb->DpcLastCount) +
                            Prcb->DpcRequestRate) >> 1;
    Prcb->DpcLastCount = Prcb->DpcData[0].DpcCount;

    /* Check if the queue is large enough */
    if ((Prcb->DpcData[0].DpcQueueDepth) && !(Prcb->DpcRoutineActive))
    {
        /* Request a DPC */
        Prcb->AdjustDpcThreshold = KiAdjustDpcThreshold;
        HalRequestSoftwareInterrupt(DISPATCH_LEVEL);

        /* Fix the maximum queue depth */
        if ((Prcb->DpcRequestRate < KiIdealDpcRate) &&
            (Prcb->MaximumDpcQueueDepth > 1))
        {
            /* Make it smaller */
            Prcb->MaximumDpcQueueDepth--;
        }
    }
    else
    {
        /* Check if we've reached the adjustment limit */
        if (!(--Prcb->AdjustDpcThreshold))
        {
            /* Reset it, and check the queue maximum */
            Prcb->AdjustDpcThreshold = KiAdjustDpcThreshold;
            if (KiMaximumDpcQueueDepth != Prcb->MaximumDpcQueueDepth)
            {
                /* Increase it */
                Prcb->MaximumDpcQueueDepth++;
            }
        }
    }

    /* Decrement the thread quantum */
    Thread->Quantum -= CLOCK_QUANTUM_DECREMENT;

    /* Check if the time expired */
    if ((Thread->Quantum <= 0) && (Thread != Prcb->IdleThread))
    {
        /* Schedule a quantum end */
        Prcb->QuantumEnd = 1;
        HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
    }
    else if ((Thread != Prcb->IdleThread) && PsPrioritySeparation &&
             (Thread->Priority < LOW_REALTIME_PRIORITY) &&
             (Prcb->ReadySummary & PRIORITY_MASK(Thread->Priority)) &&
             (CONTAINING_RECORD(Thread->ApcState.Process, EPROCESS, Pcb)->
              Vm.Flags.MemoryPriority != MEMORY_PRIORITY_FOREGROUND))
    {
        /* A thread of the foreground process may be waiting behind this
           background thread: let it have the processor now (see
           KiForegroundReclaim) */
        Prcb->QuantumEnd = 1;
        HalRequestSoftwareInterrupt(DISPATCH_LEVEL);
    }
}
