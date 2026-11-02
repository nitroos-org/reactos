/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     CONTEXT related functions for x64
 * COPYRIGHT:   Copyright 2008-2020 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>

#define NDEBUG
#include <debug.h>

/* The EFLAGS a 64-bit user thread can be given, as Windows reads them back (Windows 10 22H2):
 * CF PF AF ZF SF TF IF DF OF, RF and ID. NT, IOPL, VM, AC, VIF, VIP and the reserved bit 1 are
 * dropped; RF stays in the saved state (the CPU clears it after one instruction in user mode).
 * A WoW64 thread (compatibility-mode code) was filtered by wow64 and keeps EFLAGS_USER_SANITIZE. */
#define EFLAGS_USER_LONG_SANITIZE 0x210FD5

/* FUNCTIONS *****************************************************************/
/* Always compiled on amd64 and exported from ntoskrnl so the shared trap-exit
 * macro can reach one definition from both ntoskrnl and the HAL. It is a no-op
 * outside a WoW64 process, where Wow64Process is always NULL. */
VOID NTAPI KiRestoreWow64Gs(VOID)
{
    PKTHREAD Thread = KeGetCurrentThread();
    /* A compatibility-mode segment reload can clear the base installed by
     * the scheduler. Native dispatchers and the WoW64 transition use GS to
     * reach the native TEB, including returns without a context switch. */
    if (PsGetCurrentProcess()->Wow64Process && Thread->Teb &&
        __readmsr(MSR_GS_SWAP) != (ULONG64)Thread->Teb)
        __writemsr(MSR_GS_SWAP, (ULONG64)Thread->Teb);
}

VOID
NTAPI
KeContextToTrapFrame(IN PCONTEXT Context,
                     IN OUT PKEXCEPTION_FRAME ExceptionFrame,
                     IN OUT PKTRAP_FRAME TrapFrame,
                     IN ULONG ContextFlags,
                     IN KPROCESSOR_MODE PreviousMode)
{
    KIRQL OldIrql;

    /* Make sure we have an amd64 context, then remove the flag */
    ASSERT(ContextFlags & CONTEXT_AMD64);
    ContextFlags &= ~CONTEXT_AMD64;

    /* Do this at APC_LEVEL */
    OldIrql = KeGetCurrentIrql();
    if (OldIrql < APC_LEVEL) KeRaiseIrql(APC_LEVEL, &OldIrql);

    /* Handle integer registers */
    if (ContextFlags & CONTEXT_INTEGER)
    {
        TrapFrame->Rax = Context->Rax;
        TrapFrame->Rcx = Context->Rcx;
        TrapFrame->Rdx = Context->Rdx;
        TrapFrame->Rbp = Context->Rbp;
        TrapFrame->R8 = Context->R8;
        TrapFrame->R9 = Context->R9;
        TrapFrame->R10 = Context->R10;
        TrapFrame->R11 = Context->R11;
        if (ExceptionFrame)
        {
            ExceptionFrame->Rbx = Context->Rbx;
            ExceptionFrame->Rsi = Context->Rsi;
            ExceptionFrame->Rdi = Context->Rdi;
            ExceptionFrame->R12 = Context->R12;
            ExceptionFrame->R13 = Context->R13;
            ExceptionFrame->R14 = Context->R14;
            ExceptionFrame->R15 = Context->R15;
        }
    }

    /* Handle floating point registers */
    if (ContextFlags & CONTEXT_FLOATING_POINT)
    {
#ifdef BUILD_WOW64_ENABLED
        /* The trap/exception frames hold SSE registers, but not the legacy
         * x87 state used by compatibility-mode code. Context operations run
         * in the target thread; never change the creator's FPU when building
         * a different thread's initial trap frame. */
        if (((ContextFlags & CONTEXT_CONTROL) ? Context->SegCs : TrapFrame->SegCs) ==
                (KGDT64_R3_CMCODE | RPL_MASK) &&
            KeGetCurrentThread() && TrapFrame == KeGetTrapFrame(KeGetCurrentThread()))
        {
            DECLSPEC_ALIGN(16) XMM_SAVE_AREA32 Floating;
            _ReadWriteBarrier();
            _fxsave(&Floating);
            _ReadWriteBarrier();
            RtlCopyMemory(&Floating, &Context->FltSave,
                          FIELD_OFFSET(XMM_SAVE_AREA32, XmmRegisters));
            Floating.MxCsr &= KiMxCsrMask;
            _ReadWriteBarrier();
            _fxrstor(&Floating);
        }
#endif
        /* Reserved MXCSR bits would fault on the return to user mode. */
        TrapFrame->MxCsr = Context->MxCsr & KiMxCsrMask;
        TrapFrame->Xmm0 = Context->Xmm0;
        TrapFrame->Xmm1 = Context->Xmm1;
        TrapFrame->Xmm2 = Context->Xmm2;
        TrapFrame->Xmm3 = Context->Xmm3;
        TrapFrame->Xmm4 = Context->Xmm4;
        TrapFrame->Xmm5 = Context->Xmm5;
        if (ExceptionFrame)
        {
            ExceptionFrame->Xmm6 = Context->Xmm6;
            ExceptionFrame->Xmm7 = Context->Xmm7;
            ExceptionFrame->Xmm8 = Context->Xmm8;
            ExceptionFrame->Xmm9 = Context->Xmm9;
            ExceptionFrame->Xmm10 = Context->Xmm10;
            ExceptionFrame->Xmm11 = Context->Xmm11;
            ExceptionFrame->Xmm12 = Context->Xmm12;
            ExceptionFrame->Xmm13 = Context->Xmm13;
            ExceptionFrame->Xmm14 = Context->Xmm14;
            ExceptionFrame->Xmm15 = Context->Xmm15;
        }
    }

    /* Handle control registers */
    if (ContextFlags & CONTEXT_CONTROL)
    {
        /* RIP, RSP, EFLAGS */
        TrapFrame->Rip = Context->Rip;
        TrapFrame->Rsp = Context->Rsp;
        TrapFrame->EFlags = Context->EFlags;

        if (PreviousMode == KernelMode)
        {
            /* Set valid selectors */
            TrapFrame->SegCs = KGDT64_R0_CODE;
            TrapFrame->SegSs = KGDT64_R0_DATA;

            /* Set valid EFLAGS */
            TrapFrame->EFlags &= (EFLAGS_USER_SANITIZE | EFLAGS_INTERRUPT_MASK);
        }
        else
        {
            /* Copy selectors */
            TrapFrame->SegCs = Context->SegCs;
            if (TrapFrame->SegCs != (KGDT64_R3_CODE | RPL_MASK))
            {
                TrapFrame->SegCs = (KGDT64_R3_CMCODE | RPL_MASK);
            }

            /* The stack selector is not user controllable */
            TrapFrame->SegSs = KGDT64_R3_DATA | RPL_MASK;

            /* Set valid EFLAGS */
            if (TrapFrame->SegCs == (KGDT64_R3_CODE | RPL_MASK))
                TrapFrame->EFlags &= EFLAGS_USER_LONG_SANITIZE;
            else
                TrapFrame->EFlags &= EFLAGS_USER_SANITIZE;
            TrapFrame->EFlags |= EFLAGS_INTERRUPT_MASK;
        }
    }

    /* Handle segment selectors */
    if (ContextFlags & CONTEXT_SEGMENTS)
    {
        /* Check if this was a Kernel Trap */
        if (PreviousMode == KernelMode)
        {
            /* Set valid selectors */
            TrapFrame->SegDs = KGDT64_R3_DATA | RPL_MASK;
            TrapFrame->SegEs = KGDT64_R3_DATA | RPL_MASK;
            TrapFrame->SegFs = KGDT64_R3_CMTEB | RPL_MASK;
            TrapFrame->SegGs = KGDT64_R3_DATA | RPL_MASK;
        }
        else
        {
            /* The data segment selectors are not user controllable: a bogus
             * value from user mode would fault when they are reloaded on the
             * way back to user mode, with the kernel GS base already in use */
            TrapFrame->SegDs = KGDT64_R3_DATA | RPL_MASK;
            TrapFrame->SegEs = KGDT64_R3_DATA | RPL_MASK;
            TrapFrame->SegFs = KGDT64_R3_CMTEB | RPL_MASK;
            TrapFrame->SegGs = KGDT64_R3_DATA | RPL_MASK;
        }
    }

    /* Handle debug registers */
    if (ContextFlags & CONTEXT_DEBUG_REGISTERS)
    {
        /* Copy the debug registers */
        TrapFrame->Dr0 = Context->Dr0;
        TrapFrame->Dr1 = Context->Dr1;
        TrapFrame->Dr2 = Context->Dr2;
        TrapFrame->Dr3 = Context->Dr3;
        TrapFrame->Dr6 = Context->Dr6;
        TrapFrame->Dr7 = Context->Dr7;

        if (PreviousMode != KernelMode)
        {
            if (TrapFrame->Dr0 > (ULONG64)MmHighestUserAddress)
                TrapFrame->Dr0 = 0;
            if (TrapFrame->Dr1 > (ULONG64)MmHighestUserAddress)
                TrapFrame->Dr1 = 0;
            if (TrapFrame->Dr2 > (ULONG64)MmHighestUserAddress)
                TrapFrame->Dr2 = 0;
            if (TrapFrame->Dr3 > (ULONG64)MmHighestUserAddress)
                TrapFrame->Dr3 = 0;
        }
    }

    /* Restore IRQL */
    if (OldIrql < APC_LEVEL) KeLowerIrql(OldIrql);
}

VOID
NTAPI
KeTrapFrameToContext(IN PKTRAP_FRAME TrapFrame,
                     IN PKEXCEPTION_FRAME ExceptionFrame,
                     IN OUT PCONTEXT Context)
{
    ULONG ContextFlags;
    KIRQL OldIrql;

    /* Do this at APC_LEVEL */
    OldIrql = KeGetCurrentIrql();
    if (OldIrql < APC_LEVEL) KeRaiseIrql(APC_LEVEL, &OldIrql);

    /* Make sure we have an amd64 context, then remove the flag */
    ContextFlags = Context->ContextFlags;
    ASSERT(ContextFlags & CONTEXT_AMD64);
    ContextFlags &= ~CONTEXT_AMD64;

    /* Handle integer registers */
    if (ContextFlags & CONTEXT_INTEGER)
    {
        Context->Rax = TrapFrame->Rax;
        Context->Rcx = TrapFrame->Rcx;
        Context->Rdx = TrapFrame->Rdx;
        Context->Rbp = TrapFrame->Rbp;
        Context->R8 = TrapFrame->R8;
        Context->R9 = TrapFrame->R9;
        Context->R10 = TrapFrame->R10;
        Context->R11 = TrapFrame->R11;

        if (ExceptionFrame)
        {
            Context->Rbx = ExceptionFrame->Rbx;
            Context->Rsi = ExceptionFrame->Rsi;
            Context->Rdi = ExceptionFrame->Rdi;
            Context->R12 = ExceptionFrame->R12;
            Context->R13 = ExceptionFrame->R13;
            Context->R14 = ExceptionFrame->R14;
            Context->R15 = ExceptionFrame->R15;
        }
    }

    /* Handle floating point registers */
    if (ContextFlags & CONTEXT_FLOATING_POINT)
    {
#ifdef BUILD_WOW64_ENABLED
        if (TrapFrame->SegCs == (KGDT64_R3_CMCODE | RPL_MASK) &&
            KeGetCurrentThread() && TrapFrame == KeGetTrapFrame(KeGetCurrentThread()))
        {
            DECLSPEC_ALIGN(16) XMM_SAVE_AREA32 Floating;
            _ReadWriteBarrier();
            _fxsave(&Floating);
            _ReadWriteBarrier();
            RtlCopyMemory(&Context->FltSave, &Floating,
                          FIELD_OFFSET(XMM_SAVE_AREA32, XmmRegisters));

            /* The state of the processor here is the kernel one, its MXCSR is
               not the one of the interrupted code (the 32-bit context is
               built from this area) */
            Context->FltSave.MxCsr = TrapFrame->MxCsr;
        }
#endif
        Context->MxCsr = TrapFrame->MxCsr;
        Context->Xmm0 = TrapFrame->Xmm0;
        Context->Xmm1 = TrapFrame->Xmm1;
        Context->Xmm2 = TrapFrame->Xmm2;
        Context->Xmm3 = TrapFrame->Xmm3;
        Context->Xmm4 = TrapFrame->Xmm4;
        Context->Xmm5 = TrapFrame->Xmm5;
        if (ExceptionFrame)
        {
            Context->Xmm6 = ExceptionFrame->Xmm6;
            Context->Xmm7 = ExceptionFrame->Xmm7;
            Context->Xmm8 = ExceptionFrame->Xmm8;
            Context->Xmm9 = ExceptionFrame->Xmm9;
            Context->Xmm10 = ExceptionFrame->Xmm10;
            Context->Xmm11 = ExceptionFrame->Xmm11;
            Context->Xmm12 = ExceptionFrame->Xmm12;
            Context->Xmm13 = ExceptionFrame->Xmm13;
            Context->Xmm14 = ExceptionFrame->Xmm14;
            Context->Xmm15 = ExceptionFrame->Xmm15;
        }
    }

    /* Handle control registers */
    if (ContextFlags & CONTEXT_CONTROL)
    {
        /* Check if this was a Kernel Trap */
        if ((TrapFrame->SegCs & MODE_MASK) == KernelMode)
        {
            /* Set valid selectors */
            Context->SegCs = KGDT64_R0_CODE;
            Context->SegSs = KGDT64_R0_DATA;
        }
        else
        {
            /* Copy selectors */
            Context->SegCs = TrapFrame->SegCs;
            Context->SegSs = TrapFrame->SegSs;
        }

        /* Copy RIP, RSP, EFLAGS */
        Context->Rip = TrapFrame->Rip;
        Context->Rsp = TrapFrame->Rsp;
        Context->EFlags = TrapFrame->EFlags;
    }

    /* Handle segment selectors */
    if (ContextFlags & CONTEXT_SEGMENTS)
    {
        /* Check if this was a Kernel Trap */
        if ((TrapFrame->SegCs & MODE_MASK) == KernelMode)
        {
            /* Set valid selectors */
            Context->SegDs = KGDT64_R3_DATA | RPL_MASK;
            Context->SegEs = KGDT64_R3_DATA | RPL_MASK;
            Context->SegFs = KGDT64_R3_CMTEB | RPL_MASK;
            Context->SegGs = KGDT64_R3_DATA | RPL_MASK;
        }
        else
        {
            /* Copy selectors */
            Context->SegDs = TrapFrame->SegDs;
            Context->SegEs = TrapFrame->SegEs;
            Context->SegFs = TrapFrame->SegFs;
            Context->SegGs = TrapFrame->SegGs;

            /* DS and ES are not used in 64-bit mode and the processor does not
               save them on a trap, so whatever user mode loaded into them is
               not part of its context: Windows always reports the data selector */
            if (TrapFrame->SegCs == (KGDT64_R3_CODE | RPL_MASK))
            {
                Context->SegDs = KGDT64_R3_DATA | RPL_MASK;
                Context->SegEs = KGDT64_R3_DATA | RPL_MASK;
            }
        }
    }

    /* Handle debug registers */
    if (ContextFlags & CONTEXT_DEBUG_REGISTERS)
    {
        /* Copy the debug registers */
        Context->Dr0 = TrapFrame->Dr0;
        Context->Dr1 = TrapFrame->Dr1;
        Context->Dr2 = TrapFrame->Dr2;
        Context->Dr3 = TrapFrame->Dr3;
        Context->Dr6 = TrapFrame->Dr6;
        Context->Dr7 = TrapFrame->Dr7;
    }

    /* Restore IRQL */
    if (OldIrql < APC_LEVEL) KeLowerIrql(OldIrql);
}

VOID
RtlGetUnwindContext(
    _Out_ PCONTEXT Context,
    _In_ DWORD64 TargetFrame);

VOID
KiGetTrapContextInternal(
    _In_ PKTRAP_FRAME TrapFrame,
    _Out_ PCONTEXT Context)
{
    ULONG64 TargetFrame;

    /* Get the volatile register context from the trap frame */
    KeTrapFrameToContext(TrapFrame, NULL, Context);

    /* The target frame is MAX_SYSCALL_PARAM_SIZE bytes before the trap frame */
    TargetFrame = (ULONG64)TrapFrame - MAX_SYSCALL_PARAM_SIZE;

    /* Get the nonvolatiles on the stack */
    RtlGetUnwindContext(Context, TargetFrame);
}

VOID
RtlSetUnwindContext(
    _In_ PCONTEXT Context,
    _In_ DWORD64 TargetFrame);

VOID
KiSetTrapContextInternal(
    _Out_ PKTRAP_FRAME TrapFrame,
    _In_ PCONTEXT Context,
    _In_ KPROCESSOR_MODE RequestorMode)
{
    ULONG64 TargetFrame;

    /* Save the volatile register context in the trap frame */
    KeContextToTrapFrame(Context,
                         NULL,
                         TrapFrame,
                         Context->ContextFlags,
                         RequestorMode);

    /* The target frame is MAX_SYSCALL_PARAM_SIZE bytes before the trap frame */
    TargetFrame = (ULONG64)TrapFrame - MAX_SYSCALL_PARAM_SIZE ;

    /* Set the nonvolatiles on the stack */
    RtlSetUnwindContext(Context, TargetFrame);
}
