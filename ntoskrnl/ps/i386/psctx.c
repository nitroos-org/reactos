/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ps/i386/psctx.c
 * PURPOSE:         Process Manager: Set/Get Context for i386
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
PspGetContext(IN PKTRAP_FRAME TrapFrame,
              IN PVOID NonVolatileContext,
              IN OUT PCONTEXT Context)
{
    PAGED_CODE();

    /* Convert the trap frame to a context */
    KeTrapFrameToContext(TrapFrame, NULL, Context);
}

VOID
NTAPI
PspSetContext(OUT PKTRAP_FRAME TrapFrame,
              OUT PVOID NonVolatileContext,
              IN PCONTEXT Context,
              IN KPROCESSOR_MODE Mode)
{
    PAGED_CODE();

    /* Convert the context to a trap frame structure */
    KeContextToTrapFrame(Context, NULL, TrapFrame, Context->ContextFlags, Mode);
}

VOID
NTAPI
PspGetOrSetContextKernelRoutine(IN PKAPC Apc,
                                IN OUT PKNORMAL_ROUTINE* NormalRoutine,
                                IN OUT PVOID* NormalContext,
                                IN OUT PVOID* SystemArgument1,
                                IN OUT PVOID* SystemArgument2)
{
    PGET_SET_CTX_CONTEXT GetSetContext;
    PKEVENT Event;
    PCONTEXT Context;
    PETHREAD Thread;
    KPROCESSOR_MODE Mode;
    PKTRAP_FRAME TrapFrame = NULL;
    ULONG Flags, Active = 0;
    PAGED_CODE();

    /* Get the Context Structure */
    GetSetContext = CONTAINING_RECORD(Apc, GET_SET_CTX_CONTEXT, Apc);
    Context = &GetSetContext->Context;
    Event = &GetSetContext->Event;
    Mode = GetSetContext->Mode;
    Thread = Apc->SystemArgument2;

    /* If this is a kernel-mode request, grab the saved trap frame */
    if (Mode == KernelMode) TrapFrame = Thread->Tcb.TrapFrame;

    /* If we don't have one, grab it from the stack */
    if (!TrapFrame)
    {
        /* Trap frame is right under our initial stack */
        TrapFrame = KeGetTrapFrame(&Thread->Tcb);
    }

    /* The exception reporting bits are not register groups: strip them for the conversion */
    Flags = Context->ContextFlags;
    Context->ContextFlags = Flags & ~PS_CONTEXT_EXCEPTION_FLAGS;

    /* Which kind of kernel entry is the thread in? The entry code marks the error code of
     * a system call frame, and the initial frame of a thread that has not run yet. */
    if (TrapFrame->ErrCode == KI_ERRCODE_SYSTEM_SERVICE)
        Active = PS_CONTEXT_SERVICE_ACTIVE;
    else if (TrapFrame->ErrCode == KI_ERRCODE_INITIAL_THREAD ||
             TrapFrame->ErrCode == KI_ERRCODE_EXCEPTION)
        Active = PS_CONTEXT_EXCEPTION_ACTIVE;

    /* Check if it's a set or get */
    if (Apc->SystemArgument1)
    {
        /* Set the Context */
        PspSetContext(TrapFrame, NULL, Context, Mode);
    }
    else
    {
        /* Get the Context */
        PspGetContext(TrapFrame, NULL, Context);

        /* Report the entry kind to a caller that asked for it */
        Context->ContextFlags = PS_CONTEXT_FLAGS_REPORT(Flags, Active);
    }

    /* Notify the Native API that we are done */
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

/* EOF */
