/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         stubs
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

ULONG ProcessCount;
SIZE_T KeXStateLength = sizeof(XSAVE_FORMAT);

PVOID
KiSwitchKernelStackHelper(
    LONG_PTR StackOffset,
    PVOID OldStackBase);

/*
 * Kernel stack layout (example pointers):
 * 0xFFFFFC0F'2D008000 KTHREAD::StackBase
 *    [XSAVE_AREA size == KeXStateLength = 0x440]
 * 0xFFFFFC0F'2D007BC0 KTHREAD::StateSaveArea _XSAVE_FORMAT
 * 0xFFFFFC0F'2D007B90 KTHREAD::InitialStack
 *    [0x190 bytes KTRAP_FRAME]
 * 0xFFFFFC0F'2D007A00 KTHREAD::TrapFrame
 *    [KSTART_FRAME] or ...
 *    [KSWITCH_FRAME]
 * 0xFFFFFC0F'2D007230 KTHREAD::KernelStack
 */

PVOID
NTAPI
KiSwitchKernelStack(PVOID StackBase, PVOID StackLimit)
{
    PKTHREAD CurrentThread;
    PVOID OldStackBase;
    LONG_PTR StackOffset;
    SIZE_T StackSize;
    PKIPCR Pcr;
    ULONG Eflags;

    /* Get the current thread */
    CurrentThread = KeGetCurrentThread();

    /* Save the old stack base */
    OldStackBase = CurrentThread->StackBase;

    /* Get the size of the current stack */
    StackSize = (ULONG_PTR)CurrentThread->StackBase - CurrentThread->StackLimit;
    ASSERT(StackSize <= (ULONG_PTR)StackBase - (ULONG_PTR)StackLimit);

    /* Copy the current stack contents to the new stack */
    RtlCopyMemory((PUCHAR)StackBase - StackSize,
                  (PVOID)CurrentThread->StackLimit,
                  StackSize);

    /* Calculate the offset between the old and the new stack */
    StackOffset = (PUCHAR)StackBase - (PUCHAR)CurrentThread->StackBase;

    /* Disable interrupts while messing with the stack */
    Eflags = KiSaveFlagsAndDisableInterrupts();

    /* Set the new trap frame */
    CurrentThread->TrapFrame = (PKTRAP_FRAME)Add2Ptr(CurrentThread->TrapFrame,
                                                     StackOffset);

    /* Set the new initial stack */
    CurrentThread->InitialStack = Add2Ptr(CurrentThread->InitialStack,
                                          StackOffset);

    /* Switch StateSaveArea */
    CurrentThread->StateSaveArea = Add2Ptr(CurrentThread->StateSaveArea,
                                           StackOffset);

    /* Set the new stack limits */
    CurrentThread->StackBase = StackBase;
    CurrentThread->StackLimit = (ULONG_PTR)StackLimit;
    CurrentThread->LargeStack = TRUE;

    /* Adjust RspBase in the PCR */
    Pcr = (PKIPCR)KeGetPcr();
    Pcr->Prcb.RspBase += StackOffset;

    /* Adjust Rsp0 in the TSS */
    Pcr->TssBase->Rsp0 += StackOffset;

    /* Restore interrupts */
    __writeeflags(Eflags);

    return OldStackBase;
}

DECLSPEC_NORETURN
VOID
KiIdleLoop(VOID)
{
    PKPRCB Prcb = KeGetCurrentPrcb();
    PKTHREAD OldThread, NewThread;

    /* Now loop forever */
    while (TRUE)
    {
        /* Start of the idle loop: disable interrupts */
        _enable();
        YieldProcessor();
        YieldProcessor();
        _disable();

        /* Check for pending timers, pending DPCs, or pending ready threads */
        if ((Prcb->DpcData[0].DpcQueueDepth) ||
            (Prcb->TimerRequest) ||
            (Prcb->DeferredReadyListHead.Next))
        {
            /* Quiesce the DPC software interrupt */
            HalClearSoftwareInterrupt(DISPATCH_LEVEL);

            /* Handle it */
            KiRetireDpcList(Prcb);
        }

        /* Check if a new thread is scheduled for execution */
        if (Prcb->NextThread)
        {
            /* Enable interrupts */
            _enable();

#ifdef CONFIG_SMP
            /* Do the swap at SYNCH_LEVEL */
            KfRaiseIrql(SYNCH_LEVEL);
#endif

            /* Other processors replace NextThread under the PRCB lock */
            KiAcquirePrcbLock(Prcb);
            NewThread = Prcb->NextThread;
            if (NewThread)
            {
                /* Capture current thread data */
                OldThread = Prcb->CurrentThread;

                /* Set new thread data */
                Prcb->NextThread = NULL;
                Prcb->CurrentThread = NewThread;

                /* The thread is now running */
                NewThread->State = Running;
                KiReleasePrcbLock(Prcb);

                /* Switch away from the idle thread */
                KiSwapContext(APC_LEVEL, OldThread);
            }
            else
            {
                KiReleasePrcbLock(Prcb);
            }

#ifdef CONFIG_SMP
            /* Go back to DISPATCH_LEVEL */
            KeLowerIrql(DISPATCH_LEVEL);
#endif
        }
        else
        {
#ifdef CONFIG_SMP
            /* Take a ready thread that waits behind a busy processor */
            if (KiIdleTakeReadyThread(Prcb)) continue;

            /* Poll for a while before halting (see KiIdlePollForWork) */
            if (KiIdlePollMicroseconds && KiIdlePollForWork(Prcb)) continue;
#endif
            /* Continue staying idle. Note the HAL returns with interrupts on */
            Prcb->PowerState.IdleFunction(&Prcb->PowerState);
        }
    }
}

VOID
NTAPI
KiSwapProcess(IN PKPROCESS NewProcess,
              IN PKPROCESS OldProcess)
{
    PKIPCR Pcr = (PKIPCR)KeGetPcr();

#ifdef CONFIG_SMP
    /* TLB flushes target the processors running a process, so join the new
       one before loading its address space and leave the old one after */
    InterlockedOr64((PLONG64)&NewProcess->ActiveProcessors, Pcr->Prcb.SetMember);
#endif

    /* Update CR3 */
    __writecr3(NewProcess->DirectoryTableBase[0]);

#ifdef CONFIG_SMP
    InterlockedAnd64((PLONG64)&OldProcess->ActiveProcessors, ~(LONG64)Pcr->Prcb.SetMember);
#endif

    /* Update IOPM offset */
    Pcr->TssBase->IoMapBase = NewProcess->IopmOffset;
}

NTSTATUS
NTAPI
NtSetLdtEntries(ULONG Selector1, LDT_ENTRY LdtEntry1, ULONG Selector2, LDT_ENTRY LdtEntry2)
{
    /* Not supported */
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NtVdmControl(IN ULONG ControlCode,
             IN PVOID ControlData)
{
    /* Not supported */
    return STATUS_NOT_IMPLEMENTED;
}
