/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/amd64/except.c
 * PURPOSE:         Exception Dispatching for amd64
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 *                  Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

extern KI_INTERRUPT_DISPATCH_ENTRY KiUnexpectedRange[256];

/* GLOBALS *******************************************************************/

KIDT_INIT KiInterruptInitTable[] =
{
  /* Id,   Dpl,  IST,  ServiceRoutine */
    {0x00, 0x00, 0x00, KiDivideErrorFault},
    {0x01, 0x00, 0x00, KiDebugTrapOrFault},
    {0x02, 0x00, 0x03, KiNmiInterrupt},
    {0x03, 0x03, 0x00, KiBreakpointTrap},
    {0x04, 0x03, 0x00, KiOverflowTrap},
    {0x05, 0x00, 0x00, KiBoundFault},
    {0x06, 0x00, 0x00, KiInvalidOpcodeFault},
    {0x07, 0x00, 0x00, KiNpxNotAvailableFault},
    {0x08, 0x00, 0x01, KiDoubleFaultAbort},
    {0x09, 0x00, 0x00, KiNpxSegmentOverrunAbort},
    {0x0A, 0x00, 0x00, KiInvalidTssFault},
    {0x0B, 0x00, 0x00, KiSegmentNotPresentFault},
    {0x0C, 0x00, 0x00, KiStackFault},
    {0x0D, 0x00, 0x00, KiGeneralProtectionFault},
    {0x0E, 0x00, 0x00, KiPageFault},
    {0x10, 0x00, 0x00, KiFloatingErrorFault},
    {0x11, 0x00, 0x00, KiAlignmentFault},
    {0x12, 0x00, 0x02, KiMcheckAbort},
    {0x13, 0x00, 0x00, KiXmmException},
    {0x1F, 0x00, 0x00, KiApcInterrupt},
    {0x29, 0x03, 0x00, KiRaiseSecurityCheckFailure},
    {0x2C, 0x03, 0x00, KiRaiseAssertion},
    {0x2D, 0x03, 0x00, KiDebugServiceTrap},
    {0x2F, 0x00, 0x00, KiDpcInterrupt},
    {0xE1, 0x00, 0x00, KiIpiInterrupt},
    {0, 0, 0, 0}
};

KIDTENTRY64 KiIdt[256];
KDESCRIPTOR KiIdtDescriptor = {{0}, sizeof(KiIdt) - 1, KiIdt};


/* The layout KiUserExceptionDispatcher expects, the one of Windows */
C_ASSERT(FIELD_OFFSET(KUSER_EXCEPTION_STACK, ContextEx) == 0x4d0);
C_ASSERT(FIELD_OFFSET(KUSER_EXCEPTION_STACK, ExceptionRecord) == 0x4f0);
C_ASSERT(FIELD_OFFSET(KUSER_EXCEPTION_STACK, MachineFrame) == 0x590);
C_ASSERT(sizeof(KUSER_EXCEPTION_STACK) == 0x5c0);
C_ASSERT(sizeof(CONTEXT_EX) <= RTL_FIELD_SIZE(KUSER_EXCEPTION_STACK, ContextEx));

/* FUNCTIONS *****************************************************************/

CODE_SEG("INIT")
VOID
NTAPI
KeInitExceptions(VOID)
{
    int i, j;

    /* Initialize the Idt */
    for (j = i = 0; i < 256; i++)
    {
        ULONG64 Offset;

        if (KiInterruptInitTable[j].InterruptId == i)
        {
            Offset = (ULONG64)KiInterruptInitTable[j].ServiceRoutine;
            KiIdt[i].Dpl = KiInterruptInitTable[j].Dpl;
            KiIdt[i].IstIndex = KiInterruptInitTable[j].IstIndex;
            j++;
        }
        else
        {
            Offset = (ULONG64)&KiUnexpectedRange[i]._Op_push;
            KiIdt[i].Dpl = 0;
            KiIdt[i].IstIndex = 0;
        }
        KiIdt[i].OffsetLow = Offset & 0xffff;
        KiIdt[i].Selector = KGDT64_R0_CODE;
        KiIdt[i].Type = 0x0e;
        KiIdt[i].Reserved0 = 0;
        KiIdt[i].Present = 1;
        KiIdt[i].OffsetMiddle = (Offset >> 16) & 0xffff;
        KiIdt[i].OffsetHigh = (Offset >> 32);
        KiIdt[i].Reserved1 = 0;
    }

    KeGetPcr()->IdtBase = KiIdt;
    __lidt(&KiIdtDescriptor.Limit);
}

static
BOOLEAN
KiDispatchExceptionToUser(
    IN PKTRAP_FRAME TrapFrame,
    IN PCONTEXT Context,
    IN PEXCEPTION_RECORD ExceptionRecord)
{
    EXCEPTION_RECORD LocalExceptRecord, FaultRecord;
    PEXCEPTION_RECORD volatile UserRecord = ExceptionRecord;
    volatile BOOLEAN Retried = FALSE;
    ULONG64 UserRsp;
    PKUSER_EXCEPTION_STACK UserStack;
    PCONTEXT_EX UserContextEx;
    KI_XSTATE_CONTEXT XState;
    volatile BOOLEAN HaveXState;
    ULONG ParamCount, i;

    /* Make sure we have a valid SS */
    if (TrapFrame->SegSs != (KGDT64_R3_DATA | RPL_MASK))
    {
        /* Raise an access violation instead. Zero the whole record first:
           it is copied to the user stack in full, so leftover stack bytes
           in the unused ExceptionInformation slots would leak to user mode. */
        RtlZeroMemory(&LocalExceptRecord, sizeof(LocalExceptRecord));
        LocalExceptRecord.ExceptionCode = STATUS_ACCESS_VIOLATION;
        LocalExceptRecord.ExceptionFlags = 0;
        LocalExceptRecord.ExceptionRecord = NULL;
        LocalExceptRecord.ExceptionAddress = ExceptionRecord->ExceptionAddress;
        LocalExceptRecord.NumberParameters = 0;
        UserRecord = &LocalExceptRecord;
    }

    /* Enable interrupts */
    _enable();

    /* Like Windows, pass the extended state with the context: the handlers may change it, and
       NtContinue loads it back. The kernel does not use these registers, they still hold the
       values of user mode. A stack overflow leaves what is left of the stack to the handlers. */
    HaveXState = ((NTSTATUS)UserRecord->ExceptionCode != STATUS_STACK_OVERFLOW) &&
                 KiPrepareXStateDispatch(&XState);
    if (HaveXState)
        KiGetXStateContext(&XState);

DispatchToUser:
    /* Get new stack pointer and align it to 16 bytes, or 64 for the extended state after the frame */
    if (HaveXState)
        UserRsp = (Context->Rsp - sizeof(KUSER_EXCEPTION_STACK) - XState.Length) & ~63;
    else
        UserRsp = (Context->Rsp - sizeof(KUSER_EXCEPTION_STACK)) & ~15;

    /* Get pointer to the usermode context, exception record and machine frame */
    UserStack = (PKUSER_EXCEPTION_STACK)UserRsp;
    UserContextEx = (PCONTEXT_EX)UserStack->ContextEx;

    /* Set up the user-stack */
    _SEH2_TRY
    {
        /* Probe the user stack frame and zero it out */
        ProbeForWrite(UserStack,
                      sizeof(*UserStack) + (HaveXState ? XState.Length : 0),
                      TYPE_ALIGNMENT(KUSER_EXCEPTION_STACK));
        RtlZeroMemory(UserStack, sizeof(*UserStack));

        /* Copy Context */
        UserStack->Context = *Context;

        /* Describe the parts of the context, as RtlInitializeExtendedContext does */
        UserContextEx->All.Offset = -(LONG)sizeof(CONTEXT);
        UserContextEx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
        UserContextEx->Legacy.Length = sizeof(CONTEXT);
        if (HaveXState)
        {
            UserContextEx->XState.Offset = sizeof(KUSER_EXCEPTION_STACK) - FIELD_OFFSET(KUSER_EXCEPTION_STACK, ContextEx);
            UserContextEx->XState.Length = XState.Length;
            UserContextEx->All.Length = sizeof(KUSER_EXCEPTION_STACK) + XState.Length;
            RtlCopyMemory(UserStack + 1, XState.Chunk, XState.Length);
            UserStack->Context.ContextFlags |= CONTEXT_XSTATE;
        }
        else
        {
            UserContextEx->XState.Offset = 25;
            UserContextEx->All.Length = sizeof(CONTEXT) + sizeof(CONTEXT_EX);
        }

        /* Copy only the declared exception parameters. UserStack was zeroed
           above, so the unused ExceptionInformation slots - including the one
           trap.S fills from the volatile R11 register - stay zero instead of
           leaking stale kernel register contents to user mode. */
        UserStack->ExceptionRecord.ExceptionCode = UserRecord->ExceptionCode;
        UserStack->ExceptionRecord.ExceptionFlags = UserRecord->ExceptionFlags;
        UserStack->ExceptionRecord.ExceptionRecord = UserRecord->ExceptionRecord;
        UserStack->ExceptionRecord.ExceptionAddress = UserRecord->ExceptionAddress;
        ParamCount = UserRecord->NumberParameters;
        if (ParamCount > EXCEPTION_MAXIMUM_PARAMETERS)
            ParamCount = EXCEPTION_MAXIMUM_PARAMETERS;
        UserStack->ExceptionRecord.NumberParameters = ParamCount;
        for (i = 0; i < ParamCount; i++)
        {
            UserStack->ExceptionRecord.ExceptionInformation[i] =
                UserRecord->ExceptionInformation[i];
        }

        /* Setup the machine frame */
        UserStack->MachineFrame.Rip = Context->Rip;
        UserStack->MachineFrame.SegCs = Context->SegCs;
        UserStack->MachineFrame.EFlags = Context->EFlags;
        UserStack->MachineFrame.Rsp = Context->Rsp;
        UserStack->MachineFrame.SegSs = Context->SegSs;
    }
    _SEH2_EXCEPT((FaultRecord = *_SEH2_GetExceptionInformation()->ExceptionRecord),
                 EXCEPTION_EXECUTE_HANDLER)
    {
        /* Check if we got a stack overflow and raise that instead. The
           overflow committed the rest of the stack, so one retry is enough.
           This comes before the retry without the extended state below: the
           write hit the last guard page, which is gone now, so the overflow
           is raised only this once. Delivering the original exception in a
           smaller frame instead would lose it, and the thread would later
           fault on the last page with a plain access violation. */
        if (((NTSTATUS)FaultRecord.ExceptionCode == STATUS_STACK_OVERFLOW) && !Retried)
        {
            /* A stack overflow leaves what is left of the stack to the handlers */
            if (HaveXState)
            {
                KiFreeXStateContext(&XState);
                HaveXState = FALSE;
            }

            /* Keep the address of the original exception. The caller's
               record is replaced, so a second chance sees the overflow too. */
            FaultRecord.ExceptionAddress = ExceptionRecord->ExceptionAddress;
            *ExceptionRecord = FaultRecord;
            UserRecord = ExceptionRecord;
            Retried = TRUE;

            /* Do the exception again */
            _SEH2_YIELD(goto DispatchToUser);
        }

        /* The frame with the extended state is about 2.7 KB larger than the one without. If the stack has no
           room for it for another reason, try the frame without it: that one may still fit, and a stack
           overflow while writing that frame is raised as above. */
        if (HaveXState)
        {
            KiFreeXStateContext(&XState);
            HaveXState = FALSE;
            _SEH2_YIELD(goto DispatchToUser);
        }

        /* Nothing we can do here. Keep interrupts enabled, the caller goes
           on to the second-chance path, which can wait and terminate the
           process. */
        _SEH2_YIELD(return FALSE);
    }
    _SEH2_END;

    if (HaveXState)
        KiFreeXStateContext(&XState);

    /* Now set the two params for the user-mode dispatcher */
    TrapFrame->Rcx = (ULONG64)&UserStack->ExceptionRecord;
    TrapFrame->Rdx = (ULONG64)&UserStack->Context;

    /* Set new Stack Pointer */
    TrapFrame->Rsp = UserRsp;

    /* Force correct segments */
    TrapFrame->SegCs = KGDT64_R3_CODE | RPL_MASK;
    TrapFrame->SegDs = KGDT64_R3_DATA | RPL_MASK;
    TrapFrame->SegEs = KGDT64_R3_DATA | RPL_MASK;
    TrapFrame->SegFs = KGDT64_R3_CMTEB | RPL_MASK;
    TrapFrame->SegGs = KGDT64_R3_DATA | RPL_MASK;
    TrapFrame->SegSs = KGDT64_R3_DATA | RPL_MASK;

    /* Set RIP to the User-mode Dispatcher */
    TrapFrame->Rip = (ULONG64)KeUserExceptionDispatcher;

    /* The dispatcher does not run traced, as on Windows: the context on the user stack keeps
       TF, and NtContinue gives it back to the interrupted code. Otherwise a single-step
       exception (or a trap with TF set) traps again in KiUserExceptionDispatcher, for ever. */
    TrapFrame->EFlags &= ~EFLAGS_TF;

    _disable();

    /* Exit to usermode */
    return TRUE;
}

static
VOID
KiPageInDirectory(PVOID ImageBase, USHORT Directory)
{
    volatile CHAR *Pointer;
    ULONG Size;

   /* Get a pointer to the debug directory */
    Pointer = RtlImageDirectoryEntryToData(ImageBase, 1, Directory, &Size);
    if (!Pointer) return;

    /* Loop all pages */
    while ((LONG)Size > 0)
    {
        /* Touch it, to page it in */
        (void)*Pointer;
        Pointer += PAGE_SIZE;
        Size -= PAGE_SIZE;
    }
}

VOID
KiPrepareUserDebugData(void)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PPEB_LDR_DATA PebLdr;
    PLIST_ENTRY ListEntry;
    PTEB Teb;

    /* Get the Teb for this process */
    Teb = KeGetCurrentThread()->Teb;
    if (!Teb) return;

    /* Enable interrupts */
    _enable();

    _SEH2_TRY
    {
        /* Get a pointer to the loader data */
        PebLdr = Teb->ProcessEnvironmentBlock->Ldr;
        if (!PebLdr) _SEH2_LEAVE;

        /* Now loop all entries in the module list */
        for (ListEntry = PebLdr->InLoadOrderModuleList.Flink;
             ListEntry != &PebLdr->InLoadOrderModuleList;
             ListEntry = ListEntry->Flink)
        {
            /* Get the loader entry */
            LdrEntry = CONTAINING_RECORD(ListEntry,
                                         LDR_DATA_TABLE_ENTRY,
                                         InLoadOrderLinks);

            KiPageInDirectory((PVOID)LdrEntry->DllBase,
                              IMAGE_DIRECTORY_ENTRY_DEBUG);

            KiPageInDirectory((PVOID)LdrEntry->DllBase,
                              IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        }

    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;

    /* Leave interrupts enabled: the kernel debugger and the debug port,
       which the caller calls next, can wait */
}

static
BOOLEAN
KiIsDepEnabled(VOID)
{
    PEPROCESS Process = PsGetCurrentProcess();

    /* Same rule as MmGetExecuteOptions: a native 64-bit process has DEP
       unless the system policy is AlwaysOff, another process as it was set */
    if (!Process->Wow64Process)
        return SharedUserData->NXSupportPolicy != NX_SUPPORT_POLICY_ALWAYSOFF;

    return Process->Pcb.Flags.ExecuteDisable;
}

VOID
NTAPI
KiDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
                    IN PKEXCEPTION_FRAME ExceptionFrame,
                    IN PKTRAP_FRAME TrapFrame,
                    IN KPROCESSOR_MODE PreviousMode,
                    IN BOOLEAN FirstChance)
{
    CONTEXT Context;

    /* Increase number of Exception Dispatches */
    KeGetCurrentPrcb()->KeExceptionDispatchCount++;

    /* Zero out the context to avoid leaking kernel stack memor to user mode */
    RtlZeroMemory(&Context, sizeof(Context));

    /* Set the context flags */
    Context.ContextFlags = CONTEXT_ALL;

    /* Get the Context from the trap and exception frame */
    KeTrapFrameToContext(TrapFrame, ExceptionFrame, &Context);

    /* Look at our exception code */
    switch (ExceptionRecord->ExceptionCode)
    {
        /* Breakpoint */
        case STATUS_BREAKPOINT:

            /* Decrement RIP by one */
            Context.Rip--;

            /* The exception address of an int3 is the int3 itself (as on i386
               and Windows); the trap frame, which a debugger reads, keeps the
               address after it. Debug services keep the address after the int3. */
            if ((ExceptionRecord->NumberParameters >= 1) &&
                (ExceptionRecord->ExceptionInformation[0] == BREAKPOINT_BREAK))
            {
                ExceptionRecord->ExceptionAddress = (PVOID)Context.Rip;
            }
            break;

        /* Internal exception */
        case KI_EXCEPTION_ACCESS_VIOLATION:

            /* Set correct code */
            ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
            if ((PreviousMode == UserMode) &&
                (ExceptionRecord->NumberParameters >= 1) &&
                (ExceptionRecord->ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT) &&
                !KiIsDepEnabled())
            {
                /* The fault of an instruction fetch is reported as an
                   execute fault only for a process that has DEP, otherwise
                   as a read fault (like the access to a page that is not
                   accessible at all) */
                ExceptionRecord->ExceptionInformation[0] = EXCEPTION_READ_FAULT;
            }
            break;
    }

    /* Handle kernel-mode first, it's simpler */
    if (PreviousMode == KernelMode)
    {
        /* Check if this is a first-chance exception */
        if (FirstChance)
        {
            /* Break into the debugger for the first time */
            if (KiDebugRoutine(TrapFrame,
                               ExceptionFrame,
                               ExceptionRecord,
                               &Context,
                               PreviousMode,
                               FALSE))
            {
                /* Exception was handled */
                goto Handled;
            }

            /* If the Debugger couldn't handle it, dispatch the exception */
            if (RtlDispatchException(ExceptionRecord, &Context)) goto Handled;
        }

        /* This is a second-chance exception, only for the debugger */
        if (KiDebugRoutine(TrapFrame,
                           ExceptionFrame,
                           ExceptionRecord,
                           &Context,
                           PreviousMode,
                           TRUE))
        {
            /* Exception was handled */
            goto Handled;
        }

        /* Third strike; you're out */
        KeBugCheckEx(KMODE_EXCEPTION_NOT_HANDLED,
                     ExceptionRecord->ExceptionCode,
                     (ULONG_PTR)ExceptionRecord->ExceptionAddress,
                     (ULONG_PTR)TrapFrame,
                     0);
    }
    else
    {
        /* User mode exception, was it first-chance? */
        if (FirstChance)
        {
            /*
             * Break into the kernel debugger unless a user mode debugger
             * is present or user mode exceptions are ignored, except if this
             * is a debug service which we must always pass to KD
             */
            if ((!(PsGetCurrentProcess()->DebugPort) &&
                 !(KdIgnoreUmExceptions)) ||
                 (KdIsThisAKdTrap(ExceptionRecord, &Context, PreviousMode)))
            {
                /* Make sure the debugger can access debug directories */
                KiPrepareUserDebugData();

                /* Call the kernel debugger */
                if (KiDebugRoutine(TrapFrame,
                                   ExceptionFrame,
                                   ExceptionRecord,
                                   &Context,
                                   PreviousMode,
                                   FALSE))
                {
                    /* Exception was handled */
                    goto Handled;
                }
            }

            /* Forward exception to user mode debugger */
            if (DbgkForwardException(ExceptionRecord, TRUE, FALSE)) return;

            /* Forward exception to user mode */
            if (KiDispatchExceptionToUser(TrapFrame, &Context, ExceptionRecord))
            {
                /* Success, the exception will be handled by KiUserExceptionDispatcher */
                return;
            }

            /* Failed to dispatch, fall through for second chance handling */
        }

        /* Try second chance */
        if (DbgkForwardException(ExceptionRecord, TRUE, TRUE))
        {
            /* Handled, get out */
            return;
        }
        /* A fast fail must end the process with its own status, so it skips the
           exception port, whose server may choose another status or continue it */
        else if (!KiIsFastFailException(ExceptionRecord) &&
                 DbgkForwardException(ExceptionRecord, FALSE, TRUE))
        {
            /* Handled, get out */
            return;
        }

        /* 3rd strike, kill the process */
        DPRINT1("Kill %.16s, ExceptionCode: %lx, ExceptionAddress: %lx, BaseAddress: %lx\n",
                PsGetCurrentProcess()->ImageFileName,
                ExceptionRecord->ExceptionCode,
                ExceptionRecord->ExceptionAddress,
                PsGetCurrentProcess()->SectionBaseAddress);

        ZwTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
        KeBugCheckEx(KMODE_EXCEPTION_NOT_HANDLED,
                     ExceptionRecord->ExceptionCode,
                     (ULONG_PTR)ExceptionRecord->ExceptionAddress,
                     (ULONG_PTR)TrapFrame,
                     0);
    }

Handled:
    /* Convert the context back into Trap/Exception Frames */
    KeContextToTrapFrame(&Context,
                         ExceptionFrame,
                         TrapFrame,
                         Context.ContextFlags,
                         PreviousMode);
    return;
}

NTSTATUS
NTAPI
KeRaiseUserException(IN NTSTATUS ExceptionCode)
{
    UNIMPLEMENTED;
    return STATUS_UNSUCCESSFUL;
}


VOID
DECLSPEC_NORETURN
KiSystemFatalException(IN ULONG ExceptionCode,
                       IN PKTRAP_FRAME TrapFrame)
{
    /* Bugcheck the system */
    KeBugCheckWithTf(UNEXPECTED_KERNEL_MODE_TRAP,
                     ExceptionCode,
                     0,
                     0,
                     0,
                     TrapFrame);
}

VOID
DECLSPEC_NORETURN
KiRaiseSecurityCheckFailureKernel(
    _In_ PKTRAP_FRAME TrapFrame)
{
    EXCEPTION_RECORD ExceptionRecord;

    /* A kernel mode __fastfail reports detected corruption, never continue */
    ExceptionRecord.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
    ExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    ExceptionRecord.ExceptionRecord = NULL;
    ExceptionRecord.ExceptionAddress = (PVOID)TrapFrame->Rip;
    ExceptionRecord.NumberParameters = 1;
    ExceptionRecord.ExceptionInformation[0] = TrapFrame->Rcx;

    KeBugCheckWithTf(KERNEL_SECURITY_CHECK_FAILURE,
                     TrapFrame->Rcx,
                     (ULONG_PTR)TrapFrame,
                     (ULONG_PTR)&ExceptionRecord,
                     0,
                     TrapFrame);
}

NTSTATUS
NTAPI
KiNpxNotAvailableFaultHandler(
    IN PKTRAP_FRAME TrapFrame)
{
    UNIMPLEMENTED;
    KeBugCheckWithTf(TRAP_CAUSE_UNKNOWN, 13, 0, 0, 1, TrapFrame);
    return -1;
}

static
BOOLEAN
KiIsPrivilegedInstruction(PUCHAR Ip, BOOLEAN Wow64)
{
    ULONG i;

    /* Handle prefixes */
    for (i = 0; i < 15; i++)
    {
        if (!Wow64)
        {
            /* Check for REX prefix */
            if ((Ip[0] >= 0x40) && (Ip[0] <= 0x4F))
            {
                Ip++;
                continue;
            }
        }

        switch (Ip[0])
        {
            /* Check prefixes */
            case 0x26: // ES
            case 0x2E: // CS / null
            case 0x36: // SS
            case 0x3E: // DS
            case 0x64: // FS
            case 0x65: // GS
            case 0x66: // OP
            case 0x67: // ADDR
            case 0xF0: // LOCK
            case 0xF2: // REP
            case 0xF3: // REP INS/OUTS
                Ip++;
                continue;
        }

        break;
    }

    if (i == 15)
    {
        /* Too many prefixes. Should only happen, when the code was concurrently modified. */
         return FALSE;
    }

    switch (Ip[0])
    {
        /* Port I/O. Without an I/O permission bitmap every access from user
           mode faults, which Windows reports as a privileged instruction. */
        case 0x6C: // INSB
        case 0x6D: // INSW / INSD
        case 0x6E: // OUTSB
        case 0x6F: // OUTSW / OUTSD
        case 0xE4: // IN AL, imm8
        case 0xE5: // IN eAX, imm8
        case 0xE6: // OUT imm8, AL
        case 0xE7: // OUT imm8, eAX
        case 0xEC: // IN AL, DX
        case 0xED: // IN eAX, DX
        case 0xEE: // OUT DX, AL
        case 0xEF: // OUT DX, eAX
        case 0xF4: // HLT
        case 0xFA: // CLI
        case 0xFB: // STI
            return TRUE;

        case 0x0F:
        {
            switch (Ip[1])
            {
                case 0x06: // CLTS
                case 0x07: // SYSRET
                case 0x08: // INVD
                case 0x09: // WBINVD
                case 0x20: // MOV CR, XXX
                case 0x21: // MOV DR, XXX
                case 0x22: // MOV XXX, CR
                case 0x23: // MOV YYY, DR
                case 0x30: // WRMSR
                case 0x32: // RDMSR
                case 0x33: // RDPMC
                case 0x35: // SYSEXIT
                case 0x78: // VMREAD
                case 0x79: // VMWRITE
                    return TRUE;

                case 0x00:
                {
                    /* Check MODRM Reg field */
                    switch ((Ip[2] >> 3) & 0x7)
                    {
                        case 2: // LLDT
                        case 3: // LTR
                            return TRUE;
                    }
                    break;
                }

                case 0x01:
                {
                    switch (Ip[2])
                    {
                        case 0xC1: // VMCALL
                        case 0xC2: // VMLAUNCH
                        case 0xC3: // VMRESUME
                        case 0xC4: // VMXOFF
                        case 0xC8: // MONITOR
                        case 0xC9: // MWAIT
                        case 0xD1: // XSETBV
                        case 0xF8: // SWAPGS
                            return TRUE;
                    }

                    /* Check MODRM Reg field */
                    switch ((Ip[2] >> 3) & 0x7)
                    {
                        case 2: // LGDT
                        case 3: // LIDT
                        case 6: // LMSW
                        case 7: // INVLPG / SWAPGS / RDTSCP
                            return TRUE;
                    }
                    break;
                }

                case 0x38:
                {
                    switch (Ip[2])
                    {
                        case 0x80: // INVEPT
                        case 0x81: // INVVPID
                            return TRUE;
                    }
                    break;
                }

                case 0xC7:
                {
                    /* Check MODRM Reg field */
                    switch ((Ip[2] >> 3) & 0x7)
                    {
                        case 0x06: // VMPTRLD, VMCLEAR, VMXON
                        case 0x07: // VMPTRST
                            return TRUE;
                    }
                    break;
                }
            }

            break;
        }
    }

    return FALSE;
}

static
NTSTATUS
KiGeneralProtectionFaultUserMode(
    _In_ PKTRAP_FRAME TrapFrame)
{
    BOOLEAN Wow64 = TrapFrame->SegCs == (KGDT64_R3_CMCODE | RPL_MASK);
    PUCHAR InstructionPointer;
    NTSTATUS Status;

    /* We need to decode the instruction at RIP */
    InstructionPointer = (PUCHAR)TrapFrame->Rip;

    _SEH2_TRY
    {
        /* Probe the instruction address */
        ProbeForRead(InstructionPointer, 64, 1);

        /* Check if it's a privileged instruction */
        if (KiIsPrivilegedInstruction(InstructionPointer, Wow64))
        {
            Status = STATUS_PRIVILEGED_INSTRUCTION;
        }
        else
        {
            Status = STATUS_ACCESS_VIOLATION;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END

    return Status;
}

/*
 * A kernel-mode #GP that is not explained here ends in KMODE_EXCEPTION_NOT_HANDLED with STATUS_UNSUCCESSFUL,
 * which tells nothing about the cause (a non-canonical address, a bad selector or descriptor, an XSAVE area
 * fault...). Print what the trap knows on the debug port first, in every build: the faulting instruction
 * (bytes at RIP), the error code (a selector, or 0), the selectors and the registers the trap saved.
 */
/* A canonical address with both ends of Length bytes mapped: readable here without a nested fault */
static
BOOLEAN
KiIsKernelRangeReadable(
    _In_ PUCHAR Address,
    _In_ ULONG Length)
{
    LONG64 First = (LONG64)(ULONG_PTR)Address, Last = (LONG64)(ULONG_PTR)(Address + Length - 1);

    if (((First >> 47) != 0 && (First >> 47) != -1) || ((Last >> 47) != 0 && (Last >> 47) != -1))
        return FALSE;
    return MmIsAddressValid(Address) && MmIsAddressValid(Address + Length - 1);
}

/* At most this many reports per boot: kernel #GPs that a handler catches must not flood the debug port */
#define KI_GP_REPORT_LIMIT 32

static
VOID
KiReportKernelGeneralProtectionFault(
    _In_ PKTRAP_FRAME TrapFrame,
    _In_ PCSTR Why)
{
    static LONG Reports;
    PUCHAR Rip = (PUCHAR)TrapFrame->Rip;
    UCHAR Bytes[16];
    ULONG i;
    LONG Number;

    Number = InterlockedIncrement(&Reports);
    if (Number > KI_GP_REPORT_LIMIT)
    {
        if (Number == KI_GP_REPORT_LIMIT + 1)
            DbgPrint("KE-GP: more unexplained kernel #GPs, no more reports\n");
        return;
    }

    DbgPrint("KE-GP: unexplained kernel #GP (%s): rip %p err %I64x cs %04x ss %04x rsp %p efl %08lx irql %u cpu %u "
             "thread %p (%.16s)\n",
             Why, Rip, TrapFrame->ErrorCode, TrapFrame->SegCs, TrapFrame->SegSs, (PVOID)TrapFrame->Rsp,
             TrapFrame->EFlags, KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), KeGetCurrentThread(),
             PsGetCurrentProcess()->ImageFileName);
    DbgPrint("KE-GP: rax %p rcx %p rdx %p r8 %p r9 %p r10 %p r11 %p\n",
             (PVOID)TrapFrame->Rax, (PVOID)TrapFrame->Rcx, (PVOID)TrapFrame->Rdx, (PVOID)TrapFrame->R8,
             (PVOID)TrapFrame->R9, (PVOID)TrapFrame->R10, (PVOID)TrapFrame->R11);
    DbgPrint("KE-GP: rbx %p rsi %p rdi %p rbp %p ds %04x es %04x fs %04x gs %04x\n",
             (PVOID)TrapFrame->Rbx, (PVOID)TrapFrame->Rsi, (PVOID)TrapFrame->Rdi, (PVOID)TrapFrame->Rbp,
             TrapFrame->SegDs, TrapFrame->SegEs, TrapFrame->SegFs, TrapFrame->SegGs);

    /* The instruction: only if canonical and mapped at both ends (a fault here would hide the first one) */
    if (KiIsKernelRangeReadable(Rip, sizeof(Bytes)))
    {
        RtlCopyMemory(Bytes, Rip, sizeof(Bytes));
        DbgPrint("KE-GP: bytes at rip:");
        for (i = 0; i < sizeof(Bytes); i++)
            DbgPrint(" %02x", Bytes[i]);
        DbgPrint("\n");
    }
    else
    {
        DbgPrint("KE-GP: rip not mapped\n");
    }
}

NTSTATUS
NTAPI
KiGeneralProtectionFaultHandler(
    IN PKTRAP_FRAME TrapFrame)
{
    PUCHAR Instructions;

    /* Check for user-mode GPF */
    if (TrapFrame->SegCs & 3)
    {
        return KiGeneralProtectionFaultUserMode(TrapFrame);
    }

    /* Check for lazy segment load */
    if (TrapFrame->SegDs != (KGDT64_R3_DATA | RPL_MASK))
    {
        /* Fix it */
        TrapFrame->SegDs = (KGDT64_R3_DATA | RPL_MASK);
        return STATUS_SUCCESS;
    }
    else if (TrapFrame->SegEs != (KGDT64_R3_DATA | RPL_MASK))
    {
        /* Fix it */
        TrapFrame->SegEs = (KGDT64_R3_DATA | RPL_MASK);
        return STATUS_SUCCESS;
    }

    /* Get Instruction Pointer */
    Instructions = (PUCHAR)TrapFrame->Rip;

    /* Its first two bytes are looked at below: a RIP that cannot be read is reported as it is */
    if (!KiIsKernelRangeReadable(Instructions, 2))
    {
        KiReportKernelGeneralProtectionFault(TrapFrame, "rip not readable");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    /* Check for IRET */
    if (Instructions[0] == 0x48 && Instructions[1] == 0xCF)
    {
        /* Not implemented */
        UNIMPLEMENTED;
        KiReportKernelGeneralProtectionFault(TrapFrame, "iretq");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    /* Check for RDMSR/WRMSR */
    if ((Instructions[0] == 0xF) &&            // 2-byte opcode
        ((Instructions[1] == 0x30) ||        // RDMSR
         (Instructions[1] == 0x32)))         // WRMSR
    {
        /* Unknown CPU MSR, so raise an access violation */
        return STATUS_ACCESS_VIOLATION;
    }

    KiReportKernelGeneralProtectionFault(TrapFrame, "unknown");
    ASSERT(FALSE);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
KiXmmExceptionHandler(
    IN PKTRAP_FRAME TrapFrame)
{
    ULONG ExceptionCode;

    if ((TrapFrame->MxCsr & _MM_EXCEPT_INVALID) &&
        !(TrapFrame->MxCsr & _MM_MASK_INVALID))
    {
        /* Invalid operation */
        ExceptionCode = STATUS_FLOAT_INVALID_OPERATION;
    }
    else if ((TrapFrame->MxCsr & _MM_EXCEPT_DENORM) &&
             !(TrapFrame->MxCsr & _MM_MASK_DENORM))
    {
        /* Denormalized operand. Yes, this is what Windows returns. */
        ExceptionCode = STATUS_FLOAT_INVALID_OPERATION;
    }
    else if ((TrapFrame->MxCsr & _MM_EXCEPT_DIV_ZERO) &&
             !(TrapFrame->MxCsr & _MM_MASK_DIV_ZERO))
    {
        /* Divide by zero */
        ExceptionCode = STATUS_FLOAT_DIVIDE_BY_ZERO;
    }
    else if ((TrapFrame->MxCsr & _MM_EXCEPT_OVERFLOW) &&
             !(TrapFrame->MxCsr & _MM_MASK_OVERFLOW))
    {
        /* Overflow */
        ExceptionCode = STATUS_FLOAT_OVERFLOW;
    }
    else if ((TrapFrame->MxCsr & _MM_EXCEPT_UNDERFLOW) &&
             !(TrapFrame->MxCsr & _MM_MASK_UNDERFLOW))
    {
        /* Underflow */
        ExceptionCode = STATUS_FLOAT_UNDERFLOW;
    }
    else if ((TrapFrame->MxCsr & _MM_EXCEPT_INEXACT) &&
             !(TrapFrame->MxCsr & _MM_MASK_INEXACT))
    {
        /* Precision */
        ExceptionCode = STATUS_FLOAT_INEXACT_RESULT;
    }
    else
    {
        /* Should not happen */
        ASSERT(FALSE);
        ExceptionCode = STATUS_FLOAT_INVALID_OPERATION;
    }

    /* A 32-bit thread gets the one code of the i386 SIMD exception, the cause
       is in the MXCSR value that is passed as the second parameter */
    if (TrapFrame->SegCs == (KGDT64_R3_CMCODE | RPL_MASK))
    {
        ExceptionCode = STATUS_FLOAT_MULTIPLE_TRAPS;
    }

    return ExceptionCode;
}

NTSTATUS
NTAPI
KiFloatingErrorHandler(
    IN PKTRAP_FRAME TrapFrame,
    OUT PULONG64 DataOffset)
{
    DECLSPEC_ALIGN(16) XMM_SAVE_AREA32 FxArea;
    ULONG Mask, Error;

    *DataOffset = 0;

    /* The pending x87 error is still live in the FPU: read it, then clear it
     * (FXSAVE and FNCLEX never raise #MF), otherwise it would fire again at
     * the next waiting x87 instruction after the exception is handled. */
    _fxsave(&FxArea);
    __asm__ __volatile__("fnclex" : : : "memory");

    /* A kernel mode trap only happens for a delayed error; it is dropped */
    if (!(TrapFrame->SegCs & 3))
        return STATUS_SUCCESS;

    /* Exceptions that are unmasked in the control word and pending in the status word */
    Mask = FxArea.ControlWord & (FSW_INVALID_OPERATION | FSW_DENORMAL | FSW_ZERO_DIVIDE |
                                 FSW_OVERFLOW | FSW_UNDERFLOW | FSW_PRECISION);
    Error = FxArea.StatusWord & ~Mask;

    if (Error & FSW_INVALID_OPERATION)
    {
        /* On x86 a stack fault is reported as an invalid operation with the SF bit */
        if (Error & FSW_STACK_FAULT)
        {
            *DataOffset = FxArea.DataOffset;
            return STATUS_FLOAT_STACK_CHECK;
        }
        return STATUS_FLOAT_INVALID_OPERATION;
    }
    if (Error & FSW_ZERO_DIVIDE)
        return STATUS_FLOAT_DIVIDE_BY_ZERO;
    if (Error & FSW_DENORMAL)
        return STATUS_FLOAT_INVALID_OPERATION;
    if (Error & FSW_OVERFLOW)
        return STATUS_FLOAT_OVERFLOW;
    if (Error & FSW_UNDERFLOW)
        return STATUS_FLOAT_UNDERFLOW;
    if (Error & FSW_PRECISION)
        return STATUS_FLOAT_INEXACT_RESULT;

    /* Nothing is pending that software has to handle (spurious or already cleared) */
    return STATUS_SUCCESS;
}

/*
 * Called by KiSystemServiceExit when a system service returns above
 * PASSIVE_LEVEL. Windows: IRQL_GT_ZERO_AT_SYSTEM_SERVICE, parameter 1 the
 * service (here its number, as in the trap frame), parameter 2 the IRQL.
 * Returning to user mode at a raised IRQL leaves the thread unpreemptible
 * by DPCs and APCs and fails later, far from the cause (BAD_POOL_CALLER at
 * the next allocation, a lock that is never released).
 */
DECLSPEC_NORETURN
VOID
NTAPI
KiSystemServiceIrqlFault(
    _In_ ULONG_PTR ServiceNumber,
    _In_ ULONG_PTR Irql)
{
    KeBugCheckEx(IRQL_GT_ZERO_AT_SYSTEM_SERVICE,
                 ServiceNumber,
                 Irql,
                 0,
                 (ULONG_PTR)KeGetCurrentThread());
}
