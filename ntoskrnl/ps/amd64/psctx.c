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

/* While InTransition is set, a thread in 64-bit mode is between the guest and its saved state
 * only inside the WoW64 layer's own code (wow64.h, WOW64_LAYER_CODE). A guest that entered
 * other 64-bit code with a far transfer is not: its saved state is the 32-bit context, as on
 * Windows. A thread without the table is treated as in transition. Known gap: a guest whose
 * 64-bit code calls native ntdll (inside the table) still gets STATUS_RETRY there, where
 * Windows reports the stale 32-bit context. */
static BOOLEAN
PspWow64InLayerCode(const WOW64_CPU_STATE *Cpu, ULONG64 Rip)
{
    const WOW64_LAYER_CODE *Layer = Cpu->LayerCode;
    ULONG i;
    if (!Layer) return TRUE;
    ProbeForRead(Layer, sizeof(*Layer), sizeof(ULONG64));
    for (i = 0; i < WOW64_LAYER_RANGES; ++i)
    {
        if (Rip >= Layer->Range[i].Start && Rip < Layer->Range[i].End) return TRUE;
    }
    return FALSE;
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
    /* An exiting thread frees its stacks, where its CPU area is, and its TEB (PspExitThread)
     * before it stops taking APCs: once it is terminating, it has no 32-bit context to give */
    if (PsGetCurrentThread()->Terminated)
    {
        Request->Status = STATUS_THREAD_IS_TERMINATING;
        KeSetEvent(&Request->Event, IO_NO_INCREMENT, FALSE);
        return;
    }
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
            if (Cpu->InTransition && PspWow64InLayerCode(Cpu, Trap->Rip)) ExRaiseStatus(STATUS_RETRY);
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
                /* Windows reads the sanitized flags back: no NT, no IOPL */
                if (Flags & (WOW64_CONTEXT_CONTROL & ~WOW64_CONTEXT_i386))
                    Initial->EFlags = (Initial->EFlags & WOW64_EFLAGS_USER_SANITIZE) | 0x202;
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

/*
 * A WoW64 process's main thread has its 32-bit state from creation, as on Windows: the guest
 * stack in TEB32 and, in the CPU area at the top of the native stack (TlsSlots[WOW64_TLS_CPU],
 * the new native stack base), the start context. That context enters ntdll32!RtlUserThreadStart
 * once the guest loader has run, with the image's entry in EAX and the PEB32 in EBX, the values
 * Windows 10 reports (oracle probe); Get/SetThreadContext read and change it until wow64.dll takes it over
 * (init.c, Wow64LdrpInitialize). The thread stages it itself, in PspUserThreadStartup before
 * any APC reaches it, so a context request or a suspension never sees it half done. Nothing
 * is staged when the process has no i386 ntdll view: wow64.dll then builds the state itself.
 */
/*
 * The image's entry in the process's own view, as on Windows (also when the view was placed
 * away from the preferred base, where the loader relocates the image later): the entry the
 * section records at its preferred base (TransferAddress) moved by where the view was mapped
 * (SectionBaseAddress). Both and the preferred base (the section's BasedAddress) are kernel-owned:
 * no user memory is read, so neither the PEB (its creator can write it before the thread runs)
 * nor the view's headers (copy-on-write, user-writable) change the result, which is a 32-bit
 * user address inside the view or 0 and is never dereferenced here.
 */
static ULONG_PTR
PspWow64ImageEntry(PEPROCESS Process, const SECTION_IMAGE_INFORMATION *Image)
{
    PSECTION Section = Process->SectionObject;
    PMM_IMAGE_SECTION_OBJECT ImageSection;
    ULONG_PTR Base = (ULONG_PTR)Process->SectionBaseAddress;
    ULONG_PTR Preferred, Transfer = (ULONG_PTR)Image->TransferAddress, Entry;

    if (!Section || !Section->u.Flags.Image || !Base || !Transfer) return 0;
    ImageSection = (PMM_IMAGE_SECTION_OBJECT)Section->Segment;
    Preferred = (ULONG_PTR)ImageSection->BasedAddress;
    /* An entry RVA of 0 (or an entry outside the image) is no entry */
    if (Transfer <= Preferred || Transfer - Preferred >= ImageSection->SizeOfImage) return 0;
    Entry = Base + (Transfer - Preferred);
    if (Entry > MAXULONG || Entry > (ULONG_PTR)MmHighestUserAddress) return 0;
    return Entry;
}

VOID
NTAPI
PspWow64StageMainThread(VOID)
{
    PETHREAD Thread = PsGetCurrentThread();
    PEPROCESS Process = PsGetCurrentProcess();
    PKTRAP_FRAME Trap = KeGetTrapFrame(&Thread->Tcb);
    PTEB Teb = Thread->Tcb.Teb;
    TEB32 *Teb32;
    SECTION_IMAGE_INFORMATION Image;
    SIZE_T Reserve, Commit, MinimumCommit, Size = 0;
    PVOID Base = NULL, Limit, Page, Start;
    ULONG_PTR ZeroBits, Entry = 0, StackBase;
    ULONG OldProtect;
    WOW64_CPU_STATE *Cpu;
    BOOLEAN First, Guard = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    if (!Process->Wow64Process || !Teb) return;
    /* The first thread only; wow64.dll gives the guest threads it creates their own state */
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Process->ProcessLock);
    First = (Process->ThreadListHead.Flink == &Thread->ThreadListEntry);
    ExReleasePushLockShared(&Process->ProcessLock);
    KeLeaveCriticalRegion();
    if (!First || Trap->Rdx == WOW64_THREAD_START_MARKER) return;
    Start = PspGetWow64ProcessStart(Process);
    if (!Start) return;

    /* The stack a native i386 process gets for its first thread, as wow64.dll's CreateGuestStack */
    Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageInformation,
                                       &Image, sizeof(Image), NULL);
    if (!NT_SUCCESS(Status)) return;
    ZeroBits = (Image.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ? 0xfffeffff : 0x7ffeffff;
    Reserve = max(256 * 1024, (ULONG)Image.MaximumStackSize);
    Commit = ROUND_TO_PAGES((ULONG)Image.CommittedStackSize);
    /* MinimumStackCommit is in the PEB, which the process (or its parent) can write: read it once
     * and let it raise the commit only up to the reserve the image asks for */
    _SEH2_TRY
    {
        ProbeForRead(Process->Peb, sizeof(PEB), sizeof(ULONG_PTR));
        MinimumCommit = *(volatile SIZE_T *)&Process->Peb->MinimumStackCommit;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return);
    }
    _SEH2_END;
    if (MinimumCommit > Reserve) MinimumCommit = Reserve;
    if (Commit < MinimumCommit) Commit = ROUND_TO_PAGES(MinimumCommit);
    /* The entry, which the guest loader replaces for an IL-only .NET image */
    Entry = PspWow64ImageEntry(Process, &Image);
    Reserve = ALIGN_UP_BY(Reserve, 64 * 1024);
    if (Commit >= Reserve) Reserve = ALIGN_UP_BY(Commit, 1024 * 1024);
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Base, ZeroBits, &Reserve,
                                     MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) return;
    Limit = (PUCHAR)Base + Reserve - Commit;
    if (Reserve >= Commit + PAGE_SIZE)
    {
        Limit = (PUCHAR)Limit - PAGE_SIZE;
        Commit += PAGE_SIZE;
        Guard = TRUE;
    }
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Limit, 0, &Commit,
                                     MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(Status) && Guard)
    {
        SIZE_T PageSize = PAGE_SIZE;
        Page = Limit;
        Status = ZwProtectVirtualMemory(NtCurrentProcess(), &Page, &PageSize,
                                        PAGE_READWRITE | PAGE_GUARD, &OldProtect);
        Limit = (PUCHAR)Limit + PAGE_SIZE;
    }
    if (!NT_SUCCESS(Status)) goto Fail;
    StackBase = (ULONG_PTR)Base + Reserve;

    _SEH2_TRY
    {
        Teb32 = WOW64_TEB32(Teb);
        Teb32->NtTib.StackBase = (ULONG)StackBase;
        Teb32->NtTib.StackLimit = PtrToUlong(Limit);
        Teb32->DeallocationStack = PtrToUlong(Base);

        /* The CPU area tops the native stack, which the thread's native code runs below */
        Cpu = (WOW64_CPU_STATE *)(((ULONG_PTR)Teb->NtTib.StackBase - sizeof(*Cpu)) & ~(ULONG_PTR)63);
        ProbeForWrite(Cpu, sizeof(*Cpu), 16);
        RtlZeroMemory(Cpu, sizeof(*Cpu));
        Cpu->Eip = PtrToUlong(Start);
        Cpu->Eax = (ULONG)Entry;
        Cpu->Ebx = PtrToUlong(Process->Wow64Process->Peb);
        /* Windows 10 starts it 0x2c4 below the guest stack base (oracle probe); code that runs
         * the stack down to its guard page (StackOverflow apitest) depends on the depth */
        Cpu->Esp = (ULONG)StackBase - 0x2c4;
        Cpu->EFlags = 0x202;
        *(USHORT *)Cpu->ExtendedRegisters = 0x27f;
        *(ULONG *)(Cpu->ExtendedRegisters + 24) = 0x1f80;
        Teb->NtTib.StackBase = Cpu;
        if (Trap->Rsp > ((ULONG_PTR)Cpu & ~(ULONG_PTR)15) - 0x28)
            Trap->Rsp = ((ULONG_PTR)Cpu & ~(ULONG_PTR)15) - 0x28;
        /* Published last: a request that finds it finds it complete */
        Teb->TlsSlots[WOW64_TLS_CPU] = Cpu;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (NT_SUCCESS(Status)) return;

Fail:
    DPRINT1("WoW64: main thread state not staged: %08lx\n", Status);
    _SEH2_TRY
    {
        Teb32 = WOW64_TEB32(Teb);
        Teb32->NtTib.StackBase = Teb32->NtTib.StackLimit = Teb32->DeallocationStack = 0;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
}
#endif
