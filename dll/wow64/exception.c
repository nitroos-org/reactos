/* ReactOS WoW64 integer exception contexts. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"

PVOID Wow64ExceptionDispatcher;

typedef struct _WOW64_APC_FRAME
{
    WOW64_CPU_STATE *Previous;
    CONTEXT *Native;
    WOW64_CONTEXT *Guest;
    LONG PreviousTransition;
} WOW64_APC_FRAME;

PVOID Wow64ApcDispatcher;

/* CONTEXT_XSTATE of a guest context. The processor holds one extended state for
 * both architectures, so the native services get and set it. For the same
 * compaction mask the chunk (XSAVE_AREA_HEADER and the features) has the same
 * layout in a native and a guest CONTEXT_EX, and is copied as it is. */
#define WOW64_XSTATE_FLAG 0x40
#define WOW64_XSTATE_MAX 0x1000

typedef struct { LONG Offset; ULONG Length; } WOW64_CONTEXT_CHUNK;
typedef struct { WOW64_CONTEXT_CHUNK All, Legacy, XState; } WOW64_CONTEXT_EX;

static BOOLEAN Wow64XStateEnabled(VOID)
{
    return (SharedUserData->XState.EnabledFeatures & ~(ULONG64)3) != 0;
}

#define WOW64_XSTATE_BUFFER_OFFSET ALIGN_UP_BY(sizeof(CONTEXT) + sizeof(WOW64_CONTEXT_EX), 64)

/* Builds a native CONTEXT with CONTEXT_XSTATE, its CONTEXT_EX and the chunk of the guest
 * context in one buffer: what NtGetContextThread, NtSetContextThread and NtContinue take.
 * Buffer is 64 byte aligned and WOW64_XSTATE_BUFFER_OFFSET + WOW64_XSTATE_MAX bytes long.
 * For a set the chunk is a copy of the guest's, for a get it is empty but for its
 * compaction mask. */
static NTSTATUS Wow64BuildXStateContext(const WOW64_CONTEXT *Guest, PUCHAR Buffer, BOOLEAN Set,
                                        PUCHAR *OutGuestChunk, PULONG OutLength)
{
    PCONTEXT Native = (PCONTEXT)Buffer;
    WOW64_CONTEXT_EX *NativeEx = (WOW64_CONTEXT_EX *)(Native + 1);
    PUCHAR NativeChunk = Buffer + WOW64_XSTATE_BUFFER_OFFSET;
    WOW64_CONTEXT_EX GuestEx;
    PUCHAR GuestChunk;
    ULONG Length;

    _SEH2_TRY
    {
        GuestEx = *(WOW64_CONTEXT_EX *)(Guest + 1);
        /* As the native kernel does: the CONTEXT_EX has to describe the CONTEXT right before it (the legacy part
         * is the integer part of it or all of it) and the area it spans */
        if (GuestEx.Legacy.Offset != -(LONG)sizeof(WOW64_CONTEXT) ||
            (GuestEx.Legacy.Length != 0xcc && GuestEx.Legacy.Length != sizeof(WOW64_CONTEXT)) ||
            GuestEx.All.Offset != -(LONG)sizeof(WOW64_CONTEXT) ||
            GuestEx.All.Length < sizeof(WOW64_CONTEXT) + sizeof(WOW64_CONTEXT_EX))
            _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
        if (GuestEx.XState.Offset < (LONG)sizeof(GuestEx) || GuestEx.XState.Length < sizeof(XSAVE_AREA_HEADER))
            _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
        GuestChunk = (PUCHAR)(Guest + 1) + GuestEx.XState.Offset;
        Length = min(GuestEx.XState.Length, WOW64_XSTATE_MAX);
        RtlZeroMemory(Native, sizeof(*Native));
        Native->ContextFlags = CONTEXT_XSTATE;
        NativeEx->All.Offset = NativeEx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
        NativeEx->Legacy.Length = sizeof(CONTEXT);
        NativeEx->XState.Offset = (LONG)(NativeChunk - (PUCHAR)NativeEx);
        NativeEx->XState.Length = Length;
        NativeEx->All.Length = (ULONG)(NativeChunk + Length - Buffer);
        if (Set) RtlCopyMemory(NativeChunk, GuestChunk, Length);
        else
        {
            RtlZeroMemory(NativeChunk, Length);
            ((PXSAVE_AREA_HEADER)NativeChunk)->CompactionMask = ((PXSAVE_AREA_HEADER)GuestChunk)->CompactionMask;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    { _SEH2_YIELD(return _SEH2_GetExceptionCode()); }
    _SEH2_END;
    *OutGuestChunk = GuestChunk;
    *OutLength = Length;
    return STATUS_SUCCESS;
}

/* Gets (Set FALSE) or sets the extended state of a thread through the chunk of
 * a guest context with WOW64_CONTEXT_XSTATE. Without extended state the flag is
 * ignored, as the native services do. */
NTSTATUS Wow64XStateContext(HANDLE Thread, WOW64_CONTEXT *Guest, BOOLEAN Set)
{
    DECLSPEC_ALIGN(64) UCHAR Buffer[WOW64_XSTATE_BUFFER_OFFSET + WOW64_XSTATE_MAX];
    PUCHAR GuestChunk;
    ULONG Length;
    NTSTATUS Status;

    if (!Wow64XStateEnabled()) return STATUS_SUCCESS;
    Status = Wow64BuildXStateContext(Guest, Buffer, Set, &GuestChunk, &Length);
    if (!NT_SUCCESS(Status)) return Status;
    Status = Set ? NtSetContextThread(Thread, (PCONTEXT)Buffer) : NtGetContextThread(Thread, (PCONTEXT)Buffer);
    if (NT_SUCCESS(Status) && !Set)
    {
        _SEH2_TRY { RtlCopyMemory(GuestChunk, Buffer + WOW64_XSTATE_BUFFER_OFFSET, Length); }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
        _SEH2_END;
    }
    return Status;
}

/* NtGetContextThread/NtSetContextThread of the guest: the registers through
 * ThreadWow64Context, the extended state through the native services */
NTSTATUS Wow64GetSetContextThread(HANDLE Thread, WOW64_CONTEXT *Guest, BOOLEAN Set)
{
    WOW64_CONTEXT Local;
    ULONG Flags;
    NTSTATUS Status;

    _SEH2_TRY { Flags = Guest->ContextFlags; }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    { _SEH2_YIELD(return _SEH2_GetExceptionCode()); }
    _SEH2_END;
    if ((Flags & WOW64_CONTEXT_i386) == 0 || (Flags & WOW64_XSTATE_FLAG) == 0)
    {
        return Set ? NtSetInformationThread(Thread, ThreadWow64Context, Guest, sizeof(*Guest))
                   : NtQueryInformationThread(Thread, ThreadWow64Context, Guest, sizeof(*Guest), NULL);
    }
    _SEH2_TRY { Local = *Guest; }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    { _SEH2_YIELD(return _SEH2_GetExceptionCode()); }
    _SEH2_END;
    Local.ContextFlags = Flags & ~WOW64_XSTATE_FLAG;
    if (Set)
    {
        Status = NtSetInformationThread(Thread, ThreadWow64Context, &Local, sizeof(Local));
        if (NT_SUCCESS(Status)) Status = Wow64XStateContext(Thread, Guest, TRUE);
        return Status;
    }
    Status = NtQueryInformationThread(Thread, ThreadWow64Context, &Local, sizeof(Local), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    /* The kernel answered CONTEXT_EXCEPTION_REQUEST in the flags it returned: keep them and add the xstate flag */
    Local.ContextFlags |= Flags & WOW64_XSTATE_FLAG;
    _SEH2_TRY { *Guest = Local; }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    { _SEH2_YIELD(return _SEH2_GetExceptionCode()); }
    _SEH2_END;
    return Wow64XStateContext(Thread, Guest, FALSE);
}

NTSTATUS Wow64Continue(const WOW64_CONTEXT *Context, BOOLEAN TestAlert)
{
    /* With extended state the native CONTEXT is followed by its CONTEXT_EX and the chunk, and NtContinue
     * loads everything at once: the registers are not touched between loading the state and leaving. */
    DECLSPEC_ALIGN(64) UCHAR XBuffer[WOW64_XSTATE_BUFFER_OFFSET + WOW64_XSTATE_MAX];
    CONTEXT NativeLocal;
    PCONTEXT Native = &NativeLocal;
    BOOLEAN HaveXState = FALSE;
    WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    WOW64_APC_FRAME *Apc = Cpu->ApcFrame;
    NTSTATUS Status;
    WOW64_CONTEXT Merged;
    const WOW64_CONTEXT *Caller = Context;
    ULONG Flags = Context->ContextFlags, Groups = Flags & 0x3f;
    /* A context taken from an exception dispatch carries the kernel's exception
     * state bits (CONTEXT_EXCEPTION_ACTIVE/SERVICE_ACTIVE/REQUEST/REPORTING).
     * Code that resumes after catching (the CLR, SEH unwinders) passes the
     * context back unchanged; NtContinue accepts and ignores these bits. */
    if ((Flags & WOW64_CONTEXT_i386) == 0 ||
        (Flags & ~(WOW64_CONTEXT_ALL | WOW64_XSTATE_FLAG | WOW64_CONTEXT_EXCEPTION_ACTIVE |
                   WOW64_CONTEXT_SERVICE_ACTIVE | WOW64_CONTEXT_EXCEPTION_REQUEST |
                   WOW64_CONTEXT_EXCEPTION_REPORTING)))
        return STATUS_NOT_SUPPORTED;
    if ((Flags & WOW64_CONTEXT_FULL) != WOW64_CONTEXT_FULL)
    {
        /* A context that names only some register groups restores those and leaves the others as the
         * system call found them (the saved CPU state), as Windows does. Without the control group the
         * call returns to its caller. In both cases EAX takes the value of the context's, whatever
         * groups it names. The extended state chunk of a context without the control group is not loaded. */
        InterlockedExchange(&Cpu->InTransition, 1);
        if ((Groups & 1) == 0)
        {
            Wow64ContextToCpu(Cpu, Context);
            Cpu->Eax = Context->Eax;
            Cpu->ContextEaxChanged = TRUE;
            if (TestAlert) NtTestAlert();
            return STATUS_SUCCESS;
        }
        Wow64CpuToContext(&Merged, Cpu);
        Wow64CopyContext(&Merged, Context, Groups);
        if ((Groups & 8) && !(Groups & 32))
            Wow64LegacyToFloat((XMM_SAVE_AREA32 *)Merged.ExtendedRegisters, &Merged.FloatSave);
        /* The flags of the control group are restored along with the integer or the extended registers only */
        if ((Groups & (2 | 32)) == 0) Merged.EFlags = Cpu->EFlags;
        Merged.Eax = Context->Eax;
        /* The float and debug registers are restored only when the context names them */
        Merged.ContextFlags = WOW64_CONTEXT_FULL | ((Groups & (8 | 32)) ? 32 : 0) | (Groups & 16);
        Context = &Merged;
    }
    if ((Flags & WOW64_XSTATE_FLAG) && Wow64XStateEnabled())
    {
        PUCHAR GuestChunk;
        ULONG Length;

        Status = Wow64BuildXStateContext(Caller, XBuffer, TRUE, &GuestChunk, &Length);
        if (!NT_SUCCESS(Status)) return Status;
        (VOID)GuestChunk;
        (VOID)Length;
        Native = (PCONTEXT)XBuffer;
        HaveXState = TRUE;
    }
    if (Apc && Context == Apc->Guest)
    {
        /* Return through the interrupted native syscall before leaving its
         * translator. It owns temporaries which must remain alive for APCs. */
        InterlockedExchange(&Cpu->InTransition, 1);
        Apc->Previous->FsRedirectionDisabled = Cpu->FsRedirectionDisabled;
        Wow64ContextToCpu(Apc->Previous, Context);
        NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU] = Apc->Previous;
        if (Apc->Native->SegCs == 0x23)
        {
            InterlockedExchange(&Apc->Previous->InTransition, 1);
            Wow64ContextToNative(Apc->Native, Context);
        }
        else InterlockedExchange(&Apc->Previous->InTransition, Apc->PreviousTransition);
        if (HaveXState)
        {
            /* The interrupted native context plus the extended state, in one buffer */
            RtlCopyMemory(Native, Apc->Native, sizeof(CONTEXT));
            Native->ContextFlags |= CONTEXT_XSTATE;
            return NtContinue(Native, TestAlert);
        }
        return NtContinue(Apc->Native, TestAlert);
    }
    InterlockedExchange(&Cpu->InTransition, 1);
    while (Apc && Context->Esp >= Apc->Guest->Esp)
    {
        /* An exception or longjmp can unwind out of an APC instead of
         * returning to its dispatcher. Discard its native simulation frame. */
        Apc->Previous->FsRedirectionDisabled = Cpu->FsRedirectionDisabled;
        Cpu = Apc->Previous;
        NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU] = Cpu;
        Apc = Cpu->ApcFrame;
    }
    /* RtlCaptureContext writes the CONTEXT only: the CONTEXT_EX and chunk behind it stay */
    RtlCaptureContext(Native);
    Wow64ContextToNative(Native, Context);
    if (HaveXState) Native->ContextFlags |= CONTEXT_XSTATE;
    InterlockedExchange(&Cpu->InTransition, 1);
    return NtContinue(Native, TestAlert);
}

/* The lowest guest stack address a dispatch frame may use. The committed
 * limit (StackLimit) only moves down when the guard page below it is touched,
 * which a frame carved below ESP does on its own: the frame may extend into
 * the rest of the reservation, except its last page. */
static ULONG GuestStackFloor(const TEB32 *Teb32)
{
    ULONG Floor = Teb32->NtTib.StackLimit;
    if (Teb32->DeallocationStack && Teb32->DeallocationStack <= MAXULONG - PAGE_SIZE)
        Floor = min(Floor, Teb32->DeallocationStack + PAGE_SIZE);
    return Floor;
}

/* Touches the guest stack pages from the committed limit down to Low in
 * order, so that each one is the guard page when it is reached and the
 * stack grows page by page instead of being skipped. When the stack cannot
 * grow any further the touch raises. A macro, not a call: the frame may lie
 * in pages that are not committed yet. */
#define WOW64_GROW_GUEST_STACK(Teb32, Low) do { \
    ULONG_PTR Page_ = (ULONG_PTR)(Teb32)->NtTib.StackLimit; \
    while (Page_ > ((ULONG_PTR)(Low) & ~((ULONG_PTR)PAGE_SIZE - 1))) \
    { \
        Page_ -= PAGE_SIZE; \
        (void)*(volatile UCHAR *)Page_; \
    } \
} while (0)

/* The native dispatcher supplies its complete interrupted context in R9.
 * Negative routine values encode a guest address; normal native APCs retain
 * the ordinary ntdll dispatch path. The dispatcher calls with RSP at the
 * context, so its P1Home-P4Home are this function's home space and may hold
 * spilled arguments by now: the encoded routine is read from P5Home, where
 * the dispatcher copied it. */
VOID NTAPI Wow64PrepareForApc(PVOID Arg1, PVOID Arg2, PVOID Arg3, PCONTEXT Native)
{
    struct
    {
        ULONG Routine, Arg1, Arg2, Arg3;
        WOW64_CONTEXT Context;
        ULONG Registration[2];
    } *Guest;
    WOW64_CPU_STATE *Previous = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    WOW64_CPU_STATE Cpu;
    WOW64_CONTEXT Context;
    WOW64_APC_FRAME Apc;
    TEB32 *Teb32 = WOW64_TEB32(NtCurrentTeb());

    /* Encoded guest APCs cannot execute on a native-only helper, nor on a main
     * thread whose CPU area the kernel staged and that has not entered the guest
     * yet (NativeStack is set when Wow64CpuRun first runs it), nor before the
     * guest dispatcher is known. Returning drops this APC; ntdll resumes its
     * interrupted native context. (The native loader reaches no alertable point
     * before wow64.dll takes the thread over, so this guards, it is not a path.) */
    if (!Previous || !Previous->NativeStack || !Wow64ApcDispatcher) return;
    /* Context APCs must not update either frame while its saved registers
     * are being cloned or ownership is being transferred to/from it. */
    Apc.PreviousTransition = InterlockedExchange(&Previous->InTransition, 1);
    Cpu = *Previous;
    if (Native->SegCs == 0x23) Wow64NativeToContext(&Context, Native);
    else Wow64CpuToContext(&Context, Previous);
    /* Carve the APC frame from the guest ESP. Validate ESP against the guest
     * stack in 32-bit arithmetic before forming the pointer (ProbeForWrite is
     * kernel-only here), so a tiny or wild ESP cannot wrap the subtraction or
     * the range test; the 15-byte margin covers the 16-byte frame alignment.
     * The write then runs under SEH as a second line of defence. A bad ESP
     * terminates this process cleanly instead of writing an unchecked pointer. */
    if (Context.Esp > Teb32->NtTib.StackBase ||
        Context.Esp < GuestStackFloor(Teb32) ||
        Context.Esp - GuestStackFloor(Teb32) < sizeof(*Guest) + 15)
    {
        NtTerminateProcess(NtCurrentProcess(), STATUS_STACK_OVERFLOW);
        return;
    }
    Guest = (PVOID)(ULONG_PTR)((Context.Esp - sizeof(*Guest)) & ~15);
    _SEH2_TRY
    {
        WOW64_GROW_GUEST_STACK(Teb32, Guest);
        Guest->Routine = (ULONG)(-(LONG64)Native->P5Home >> 2);
        Guest->Arg1 = PtrToUlong(Arg1);
        Guest->Arg2 = PtrToUlong(Arg2);
        Guest->Arg3 = PtrToUlong(Arg3);
        Guest->Context = Context;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        NtTerminateProcess(NtCurrentProcess(), _SEH2_GetExceptionCode());
        _SEH2_YIELD(return);
    }
    _SEH2_END;
    Apc.Previous = Previous;
    Apc.Native = Native;
    Apc.Guest = &Guest->Context;
    Cpu.ApcFrame = &Apc;
    Cpu.Esp = PtrToUlong(Guest);
    Cpu.Eip = PtrToUlong(Wow64ApcDispatcher);
    Wow64CpuRun(&Cpu);
}

/* The guest exception frame: the i386 dispatcher takes two pointers at ESP.
 * The CONTEXT_EX follows the context. With extended state the frame is a
 * WOW64_EXCEPTION_FRAME_XSTATE, whose chunk is 64 byte aligned after it. */
#define WOW64_XSTATE_FRAME 0xc00
typedef struct
{
    ULONG RecordPointer, ContextPointer;
    EXCEPTION_RECORD32 Record;
    WOW64_CONTEXT Context;
    WOW64_CONTEXT_EX ContextEx;
} WOW64_EXCEPTION_FRAME;

typedef struct
{
    WOW64_EXCEPTION_FRAME Frame;
    UCHAR XState[WOW64_XSTATE_FRAME + 64];
} WOW64_EXCEPTION_FRAME_XSTATE;

/* Stack the worker needs below its caller: the guest frame and the native
 * CONTEXT it builds, plus its saved registers and the frames of the calls it
 * makes on the way to NtContinue (Wow64NativeToContext, the copy, NtContinue) */
#define WOW64_DISPATCH_RESERVE (sizeof(WOW64_EXCEPTION_FRAME) + sizeof(CONTEXT) + 0x200)
#define WOW64_DISPATCH_RESERVE_XSTATE (WOW64_DISPATCH_RESERVE + sizeof(WOW64_EXCEPTION_FRAME_XSTATE) - sizeof(WOW64_EXCEPTION_FRAME))

/* Whether the native context carries an extended state chunk the guest frame can take */
static BOOLEAN NativeXState(PCONTEXT Context)
{
    const WOW64_CONTEXT_EX *NativeEx = (const WOW64_CONTEXT_EX *)(Context + 1);

    return (Context->ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE &&
           NativeEx->XState.Offset >= (LONG)sizeof(*NativeEx) &&
           NativeEx->XState.Length >= sizeof(XSAVE_AREA_HEADER) &&
           NativeEx->XState.Length <= WOW64_XSTATE_FRAME;
}

/* Gives the guest context the extended state of the native one, like the
 * native kernel does for an exception: the guest handlers may change it and
 * NtContinue loads it back. Without XState the context has none. */
static VOID DispatchGuestXState(WOW64_EXCEPTION_FRAME *Frame, PUCHAR XState, PCONTEXT Context)
{
    const WOW64_CONTEXT_EX *NativeEx = (const WOW64_CONTEXT_EX *)(Context + 1);
    PUCHAR Chunk;

    Frame->ContextEx.All.Offset = Frame->ContextEx.Legacy.Offset = -(LONG)sizeof(WOW64_CONTEXT);
    Frame->ContextEx.Legacy.Length = sizeof(WOW64_CONTEXT);
    Frame->ContextEx.XState.Offset = 25;
    Frame->ContextEx.XState.Length = 0;
    Frame->ContextEx.All.Length = sizeof(WOW64_CONTEXT) + sizeof(WOW64_CONTEXT_EX);
    if (!XState || !NativeXState(Context))
        return;
    Chunk = ALIGN_UP_POINTER_BY(XState, 64);
    RtlCopyMemory(Chunk, (const UCHAR *)NativeEx + NativeEx->XState.Offset, NativeEx->XState.Length);
    Frame->ContextEx.XState.Offset = (LONG)(Chunk - (PUCHAR)&Frame->ContextEx);
    Frame->ContextEx.XState.Length = NativeEx->XState.Length;
    Frame->ContextEx.All.Length = sizeof(WOW64_CONTEXT) + Frame->ContextEx.XState.Offset + NativeEx->XState.Length;
    Frame->Context.ContextFlags |= WOW64_XSTATE_FLAG;
}

static VOID DispatchGuestFrame(PEXCEPTION_RECORD Record, PCONTEXT Context, TEB32 *Teb32,
                               WOW64_EXCEPTION_FRAME *Frame, PUCHAR XState, PUCHAR FrameEnd)
{
    CONTEXT Native;
    ULONG i;
    NTSTATUS Status;

    if (!Wow64ExceptionDispatcher ||
        (ULONG_PTR)Frame < GuestStackFloor(Teb32) ||
        (ULONG_PTR)&Native < GuestStackFloor(Teb32) ||
        (ULONG_PTR)FrameEnd > Teb32->NtTib.StackBase)
        goto Failed;

    /* The kernel's amd64 frame already lives on the guest stack. A local
     * frame is below it and cannot overwrite the source context or record.
     * The i386 dispatcher takes two pointers at ESP, with no return address. */
    Native = *Context;
    /* The copy has no extended state behind it. The guest's registers still
     * hold that state, so NtContinue must leave it alone. */
    Native.ContextFlags &= ~(CONTEXT_XSTATE & ~CONTEXT_AMD64);
    Wow64NativeToContext(&Frame->Context, Context);
    DispatchGuestXState(Frame, XState, Context);
    RtlZeroMemory(&Frame->Record, sizeof(Frame->Record));
    Frame->Record.ExceptionCode = Record->ExceptionCode;
    Frame->Record.ExceptionFlags = Record->ExceptionFlags;
    Frame->Record.ExceptionAddress = PtrToUlong(Record->ExceptionAddress);
    Frame->Record.NumberParameters = min(Record->NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
    for (i = 0; i < Frame->Record.NumberParameters; ++i)
        Frame->Record.ExceptionInformation[i] = (ULONG)Record->ExceptionInformation[i];
    Frame->RecordPointer = PtrToUlong(&Frame->Record);
    Frame->ContextPointer = PtrToUlong(&Frame->Context);
    Native.Rip = (ULONG_PTR)Wow64ExceptionDispatcher;
    Native.Rsp = (ULONG_PTR)Frame;
    Native.SegCs = 0x23;
    Native.SegSs = Native.SegDs = Native.SegEs = 0x2b;
    Native.SegFs = 0x53;
    InterlockedExchange(&((WOW64_CPU_STATE *)NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU])->InTransition, 1);
    Status = NtContinue(&Native, FALSE);
    DbgPrint("WoW64: exception dispatch failed: %08lx\n", Status);
Failed:
    DbgPrint("WoW64: cannot dispatch guest exception %08lx (frame %p, guest stack %08lx-%08lx)\n",
             Record->ExceptionCode, Frame, Teb32->NtTib.StackLimit, Teb32->NtTib.StackBase);
    NtTerminateProcess(NtCurrentProcess(), Record->ExceptionCode);
}

static DECLSPEC_NOINLINE VOID DispatchGuestException(PEXCEPTION_RECORD Record, PCONTEXT Context, TEB32 *Teb32)
{
    WOW64_EXCEPTION_FRAME Frame;
    DispatchGuestFrame(Record, Context, Teb32, &Frame, NULL, (PUCHAR)(&Frame + 1));
}

static DECLSPEC_NOINLINE VOID DispatchGuestExceptionXState(PEXCEPTION_RECORD Record, PCONTEXT Context, TEB32 *Teb32)
{
    WOW64_EXCEPTION_FRAME_XSTATE Frame;
    DispatchGuestFrame(Record, Context, Teb32, &Frame.Frame, Frame.XState, (PUCHAR)(&Frame + 1));
}

VOID NTAPI Wow64PrepareForException(PEXCEPTION_RECORD Record, PCONTEXT Context)
{
    TEB32 *Teb32;
    ULONG_PTR Low, Deallocation, Guarantee;
    BOOLEAN WithXState;

    if (Context->SegCs != 0x23) return;
    Teb32 = WOW64_TEB32(NtCurrentTeb());
    /* The worker's locals lie below the kernel's frame on the guest stack, in
     * pages that may not be committed yet. Grow the stack over them here,
     * before anything below this small frame has been written. */
#ifdef __GNUC__
    Low = (ULONG_PTR)__builtin_frame_address(0);
#else
    Low = (ULONG_PTR)_AddressOfReturnAddress();
#endif
    /* The frame with extended state only when the stack is far from its end:
     * what is left near it goes to the guest's handlers */
    Low -= WOW64_DISPATCH_RESERVE;
    Deallocation = PAGE_ROUND_DOWN(Teb32->DeallocationStack);
    Guarantee = ROUND_TO_PAGES(min((ULONG_PTR)Teb32->GuaranteedStackBytes, Teb32->NtTib.StackBase - Deallocation));
    WithXState = NativeXState(Context) &&
                 Low > WOW64_DISPATCH_RESERVE_XSTATE &&
                 Low - (WOW64_DISPATCH_RESERVE_XSTATE - WOW64_DISPATCH_RESERVE) >= GuestStackFloor(Teb32) &&
                 PAGE_ROUND_DOWN(Low - (WOW64_DISPATCH_RESERVE_XSTATE - WOW64_DISPATCH_RESERVE)) - Deallocation >
                     2 * PAGE_SIZE + Guarantee + PAGE_SIZE;
    if (WithXState) Low -= WOW64_DISPATCH_RESERVE_XSTATE - WOW64_DISPATCH_RESERVE;
    /* Once the stack is committed down to its floor (a stack overflow was just
     * raised) nothing is left to grow: the worker checks its own frame. */
    if (Low < GuestStackFloor(Teb32) && Teb32->NtTib.StackLimit <= GuestStackFloor(Teb32))
        Low = GuestStackFloor(Teb32);
    if (Low < GuestStackFloor(Teb32) || Low >= Teb32->NtTib.StackBase)
    {
        DbgPrint("WoW64: no guest stack left to dispatch exception %08lx\n", Record->ExceptionCode);
        NtTerminateProcess(NtCurrentProcess(), Record->ExceptionCode);
        return;
    }
    /* Touching the guard pages down to Low would reach the last ones, where MM
     * commits the rest of the stack and raises STATUS_STACK_OVERFLOW
     * (MiCheckForUserStackOverflow): raised here, natively on the guest stack,
     * it would not reach the guest. Do what MM does then, without the fault:
     * commit the stack down to its floor and give the guest the overflow, as
     * i386 does when the exception frame does not fit on the stack. */
    Deallocation = PAGE_ROUND_DOWN(Teb32->DeallocationStack);
    Guarantee = ROUND_TO_PAGES(min((ULONG_PTR)Teb32->GuaranteedStackBytes, Teb32->NtTib.StackBase - Deallocation));
    if (Teb32->NtTib.StackLimit > GuestStackFloor(Teb32) &&
        PAGE_ROUND_DOWN(Low) - Deallocation <= 2 * PAGE_SIZE + Guarantee)
    {
        PVOID Base = (PVOID)(ULONG_PTR)GuestStackFloor(Teb32);
        SIZE_T Size = Teb32->NtTib.StackLimit - PAGE_SIZE - GuestStackFloor(Teb32);
        ULONG OldProtect;
        NTSTATUS Status = STATUS_SUCCESS;

        /* Below the guard page nothing is committed; the guard page loses its guard */
        if (Size)
            Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
        if (NT_SUCCESS(Status))
        {
            Base = (PVOID)(ULONG_PTR)(Teb32->NtTib.StackLimit - PAGE_SIZE);
            Size = PAGE_SIZE;
            Status = NtProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, PAGE_READWRITE, &OldProtect);
        }
        if (!NT_SUCCESS(Status))
        {
            DbgPrint("WoW64: cannot commit the guest stack for exception %08lx: %08lx\n", Record->ExceptionCode, Status);
            NtTerminateProcess(NtCurrentProcess(), Record->ExceptionCode);
            return;
        }
        Teb32->NtTib.StackLimit = GuestStackFloor(Teb32);
        Record->ExceptionCode = STATUS_STACK_OVERFLOW;
        Record->ExceptionFlags = 0;
        Record->NumberParameters = 0;
    }
    else
    {
        WOW64_GROW_GUEST_STACK(Teb32, Low);
    }
    if (WithXState && Record->ExceptionCode != STATUS_STACK_OVERFLOW)
        DispatchGuestExceptionXState(Record, Context, Teb32);
    else
        DispatchGuestException(Record, Context, Teb32);
}

NTSTATUS Wow64RaiseException(const EXCEPTION_RECORD32 *Record, const WOW64_CONTEXT *Context,
                              BOOLEAN FirstChance)
{
    EXCEPTION_RECORD NativeRecord = {0};
    CONTEXT NativeContext;
    ULONG i, Count;
    /* The record is guest memory: read the count once and bound the copy by that value.
     * A larger count is not an error for a 32-bit caller on Windows: the exception is raised
     * with the parameters a record holds. Clamp it, as the native kernel takes no more. */
    Count = *(volatile const ULONG *)&Record->NumberParameters;
    /* Deliberate divergence: the handler is passed this clamped count (at most 15), not the raw
     * guest count that Windows passes through to the handler. */
    if (Count > EXCEPTION_MAXIMUM_PARAMETERS) Count = EXCEPTION_MAXIMUM_PARAMETERS;
    RtlCaptureContext(&NativeContext);
    Wow64ContextToNative(&NativeContext, Context);
    NativeRecord.ExceptionCode = Record->ExceptionCode;
    NativeRecord.ExceptionFlags = Record->ExceptionFlags;
    NativeRecord.ExceptionAddress = PTR32(Record->ExceptionAddress);
    NativeRecord.NumberParameters = Count;
    for (i = 0; i < Count; ++i)
        NativeRecord.ExceptionInformation[i] = Record->ExceptionInformation[i];
    InterlockedExchange(&((WOW64_CPU_STATE *)NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU])->InTransition, 1);
    return NtRaiseException(&NativeRecord, &NativeContext, FirstChance);
}
