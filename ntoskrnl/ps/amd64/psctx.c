/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ps/amd64/psctx.c
 * PURPOSE:         Process Manager: Set/Get Context for i386
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/


_IRQL_requires_(APC_LEVEL)
VOID
NTAPI
PspGetOrSetContextKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2)
{
    PGET_SET_CTX_CONTEXT GetSetContext;
    PKTHREAD Thread;
    PKTRAP_FRAME TrapFrame = NULL;
    ULONG Flags, Active = 0;

    PAGED_CODE();

    /* Get the Context Structure */
    GetSetContext = CONTAINING_RECORD(Apc, GET_SET_CTX_CONTEXT, Apc);
    Thread = Apc->SystemArgument2;
    NT_ASSERT(KeGetCurrentThread() == Thread);

    /* If this is a kernel-mode request, grab the saved trap frame */
    if (GetSetContext->Mode == KernelMode)
    {
        TrapFrame = Thread->TrapFrame;
    }

    /* If we don't have one, grab it from the stack */
    if (TrapFrame == NULL)
    {
        /* Get the thread's base trap frame */
        TrapFrame = KeGetTrapFrame(KeGetCurrentThread());
    }

    /* The exception reporting bits are not register groups: strip them for the conversion */
    Flags = GetSetContext->Context.ContextFlags;
    GetSetContext->Context.ContextFlags = Flags & ~PS_CONTEXT_EXCEPTION_FLAGS;

    /* Which kind of kernel entry is the thread in (system call or exception) */
    if (TrapFrame->ExceptionActive == 1)
        Active = PS_CONTEXT_SERVICE_ACTIVE;
    else if (TrapFrame->ExceptionActive == 2)
        Active = PS_CONTEXT_EXCEPTION_ACTIVE;

    /* Check if it's a set or get */
    if (Apc->SystemArgument1 != 0)
    {
        /* Set the nonvolatiles on the stack, target frame is the trap frame */
        KiSetTrapContext(TrapFrame, &GetSetContext->Context, GetSetContext->Mode);

        /* The extended registers are live: this runs in the target thread */
        if (GetSetContext->XState)
            KiSetXStateContext(GetSetContext->XState);
    }
    else
    {
        /* Get the nonvolatiles from the stack */
        KiGetTrapContext(TrapFrame, &GetSetContext->Context);

        /* Report the entry kind to a caller that asked for it */
        GetSetContext->Context.ContextFlags = PS_CONTEXT_FLAGS_REPORT(Flags, Active);

        if (GetSetContext->XState)
            KiGetXStateContext(GetSetContext->XState);
    }

    /* Notify the Native API that we are done */
    KeSetEvent(&GetSetContext->Event, IO_NO_INCREMENT, FALSE);
}

/* EOF */

#ifdef BUILD_WOW64_ENABLED
#include <reactos/wow64context.h>

typedef struct
{
    KAPC Apc;
    KEVENT Event;
    NTSTATUS Status;
    BOOLEAN Set;
    BOOLEAN Report;     /* the caller passed CONTEXT_EXCEPTION_REQUEST */
    WOW64_CONTEXT Context, Original;
    CONTEXT Native;
} WOW64_CONTEXT_REQUEST;

static VOID NTAPI
PspWow64ContextRundown(PKAPC Apc)
{
    WOW64_CONTEXT_REQUEST *Request = CONTAINING_RECORD(Apc, WOW64_CONTEXT_REQUEST, Apc);
    Request->Status = STATUS_THREAD_IS_TERMINATING;
    KeSetEvent(&Request->Event, IO_NO_INCREMENT, FALSE);
}

static VOID NTAPI
PspWow64ContextApc(PKAPC Apc, PKNORMAL_ROUTINE *Routine, PVOID *NormalContext,
                   PVOID *Argument1, PVOID *Argument2)
{
    WOW64_CONTEXT_REQUEST *Request = CONTAINING_RECORD(Apc, WOW64_CONTEXT_REQUEST, Apc);
    PKTRAP_FRAME Trap = KeGetTrapFrame(KeGetCurrentThread());
    PCONTEXT Native = &Request->Native;
    WOW64_CONTEXT *Original = &Request->Original;
    WOW64_CPU_STATE *Cpu;
    PTEB Teb = PsGetCurrentThread()->Tcb.Teb;
    ULONG Flags = Request->Context.ContextFlags, Active = 0;

    *Original = Request->Context;
    UNREFERENCED_PARAMETER(Routine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    Request->Status = STATUS_SUCCESS;
    _SEH2_TRY
    {
        ProbeForRead(Teb, sizeof(*Teb), sizeof(PVOID));
        Cpu = Teb->TlsSlots[WOW64_TLS_CPU];
        RtlZeroMemory(Native, sizeof(*Native));
        Native->ContextFlags = CONTEXT_ALL;
        KiGetTrapContext(Trap, Native);
        /* The state of the entry decides. Only the thread's 32-bit code, interrupted, is "no kernel entry":
         * the service thunk, the 64-bit code of the process and a thread that has not run yet are not. */
        if (Trap->ExceptionActive == 1)
            Active = PS_CONTEXT_SERVICE_ACTIVE;
        else if (Trap->ExceptionActive == 2 || Trap->SegCs != (KGDT64_R3_CMCODE | RPL_MASK))
            Active = PS_CONTEXT_EXCEPTION_ACTIVE;
        if (Trap->SegCs == (KGDT64_R3_CMCODE | RPL_MASK))
        {
            if (Request->Set)
            {
                Wow64ContextToNative(Native, &Request->Context);
                KiSetTrapContext(Trap, Native, UserMode);
            }
            else Wow64NativeToContext(&Request->Context, Native);
        }
        else if (Cpu)
        {
            ProbeForRead(Cpu, sizeof(*Cpu), 16);
            /* The target cannot progress while its special APC runs. A
             * suspended caller must resume and retry to leave the gate. */
            if (Cpu->InTransition) ExRaiseStatus(STATUS_RETRY);
            if (Request->Set)
            {
                ProbeForWrite(Cpu, sizeof(*Cpu), 16);
                /* A get/set round trip must not replace the eventual service
                 * result with its entry service number. Keep explicit edits
                 * sticky across later round trips in this same service. */
                if ((Flags & (WOW64_CONTEXT_INTEGER & ~WOW64_CONTEXT_i386)) &&
                    Request->Context.Eax != Cpu->Eax)
                    Cpu->ContextEaxChanged = TRUE;
                Wow64ContextToCpu(Cpu, &Request->Context);
                /* Hardware debug state also governs the next guest return. */
                if (Flags & (WOW64_CONTEXT_DEBUG_REGISTERS & ~WOW64_CONTEXT_i386))
                {
                    Original->ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
                    Wow64ContextToNative(Native, Original);
                    KiSetTrapContext(Trap, Native, UserMode);
                }
            }
            else
            {
                ProbeForRead(Cpu, sizeof(*Cpu), 16);
                Wow64CpuToContext(&Request->Context, Cpu);
                Request->Context.Dr0 = Native->Dr0; Request->Context.Dr1 = Native->Dr1;
                Request->Context.Dr2 = Native->Dr2; Request->Context.Dr3 = Native->Dr3;
                Request->Context.Dr6 = Native->Dr6; Request->Context.Dr7 = Native->Dr7;
            }
        }
        else
        {
            /* Before first resume the native startup argument points to the
             * context captured by the creator in the new native stack. */
            WOW64_CONTEXT *Initial = (PVOID)(ULONG_PTR)Native->Rcx;
            if (Native->Rdx != WOW64_THREAD_START_MARKER) ExRaiseStatus(STATUS_INVALID_PARAMETER);
            ProbeForRead(Initial, sizeof(*Initial), sizeof(ULONG));
            if (Request->Set)
            {
                ProbeForWrite(Initial, sizeof(*Initial), sizeof(ULONG));
                Wow64CopyContext(Initial, &Request->Context, Flags);
            }
            else Request->Context = *Initial;
        }
        if (!Request->Set)
        {
            Wow64CopyContext(Original, &Request->Context, Flags);
            Request->Context = *Original;
        }
        Request->Context.ContextFlags = Flags;
        if (!Request->Set && Request->Report)
            Request->Context.ContextFlags |= PS_CONTEXT_EXCEPTION_REQUEST | PS_CONTEXT_EXCEPTION_REPORTING | Active;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Request->Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    KeSetEvent(&Request->Event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
NTAPI
PspWow64ContextThread(HANDLE Handle, PVOID Buffer, ULONG Length, BOOLEAN Set,
                      KPROCESSOR_MODE Mode)
{
    WOW64_CONTEXT_REQUEST Request;
    PETHREAD Thread;
    NTSTATUS Status;
    ULONG Flags;
    if (Length != sizeof(Request.Context)) return STATUS_INFO_LENGTH_MISMATCH;
    _SEH2_TRY
    {
        if (Mode != KernelMode)
        {
            ProbeForRead(Buffer, Length, sizeof(ULONG));
            if (!Set) ProbeForWrite(Buffer, Length, sizeof(ULONG));
        }
        Request.Context = *(WOW64_CONTEXT *)Buffer;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    { _SEH2_YIELD(return _SEH2_GetExceptionCode()); }
    _SEH2_END;
    /* CONTEXT_EXCEPTION_REQUEST and friends are reporting bits, not register groups */
    Request.Report = (Request.Context.ContextFlags & PS_CONTEXT_EXCEPTION_REQUEST) != 0;
    Flags = Request.Context.ContextFlags & ~PS_CONTEXT_EXCEPTION_FLAGS;
    Request.Context.ContextFlags = Flags;
    if (!(Flags & WOW64_CONTEXT_i386) || (Flags & ~WOW64_CONTEXT_ALL))
        return STATUS_INVALID_PARAMETER;
    Status = ObReferenceObjectByHandle(Handle, Set ? THREAD_SET_CONTEXT : THREAD_GET_CONTEXT,
                                       PsThreadType, Mode, (PVOID *)&Thread, NULL);
    if (!NT_SUCCESS(Status)) return Status;
    if (!Thread->ThreadsProcess->Wow64Process || Thread->SystemThread)
    {
        ObDereferenceObject(Thread);
        return STATUS_INVALID_PARAMETER;
    }
    Request.Set = Set;
    KeInitializeEvent(&Request.Event, NotificationEvent, FALSE);
    KeInitializeApc(&Request.Apc, &Thread->Tcb, OriginalApcEnvironment,
                    PspWow64ContextApc, PspWow64ContextRundown, NULL, KernelMode, NULL);
    if (Thread == PsGetCurrentThread())
    {
        KeEnterGuardedRegion();
        PspWow64ContextApc(&Request.Apc, NULL, NULL, NULL, NULL);
        KeLeaveGuardedRegion();
        Status = Request.Status;
    }
    else if (KeInsertQueueApc(&Request.Apc, NULL, NULL, 2))
    {
        KeWaitForSingleObject(&Request.Event, Executive, KernelMode, FALSE, NULL);
        Status = Request.Status;
    }
    else Status = STATUS_THREAD_IS_TERMINATING;
    ObDereferenceObject(Thread);
    if (NT_SUCCESS(Status) && !Set)
    {
        _SEH2_TRY { *(WOW64_CONTEXT *)Buffer = Request.Context; }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
        _SEH2_END;
    }
    return Status;
}
#endif
