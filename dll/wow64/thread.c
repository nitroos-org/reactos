/* ReactOS WoW64 thread translation. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"

VOID Wow64AbortThread(HANDLE Thread, HANDLE Process, NTSTATUS Status)
{
    THREAD_BASIC_INFORMATION Info;
    ULONG Zero = 0;
    /* A failed NtCreateThread leaves the guest stack owned by its caller.
     * The thread has not resumed, so remove its rundown ownership before
     * terminating it. Kernel rundown still releases the native stack. */
    if (NT_SUCCESS(NtQueryInformationThread(Thread, ThreadBasicInformation,
                                            &Info, sizeof(Info), NULL)))
        NtWriteVirtualMemory(Process, &WOW64_TEB32(Info.TebBaseAddress)->DeallocationStack,
                             &Zero, sizeof(Zero), NULL);
    NtTerminateThread(Thread, Status);
    NtWaitForSingleObject(Thread, FALSE, NULL);
    NtClose(Thread);
}

/* A new thread starts with reset debug registers and floating point state, whatever the
 * creating CONTEXT holds (a CONTEXT given to NtCreateThread can name both groups: Windows ignores
 * their values; measured on Windows 10 22H2, x64: Dr0-Dr7 zero, x87 control word 0x27f, MXCSR
 * 0x1f80). The group flags stay as given, so that the startup NtContinue loads the reset values. */
static VOID Wow64ResetInitialState(WOW64_CONTEXT *Context)
{
    /* The flags read back as Windows does: no NT, no IOPL (Windows 10 22H2: 0x202 for kernel32's) */
    Context->EFlags = (Context->EFlags & WOW64_EFLAGS_USER_SANITIZE) | 0x202;
    Context->Dr0 = Context->Dr1 = Context->Dr2 = Context->Dr3 = 0;
    Context->Dr6 = Context->Dr7 = 0;
    RtlZeroMemory(&Context->FloatSave, sizeof(Context->FloatSave));
    Context->FloatSave.ControlWord = 0x27f;
    Context->FloatSave.TagWord = 0xffff;
    RtlZeroMemory(Context->ExtendedRegisters, sizeof(Context->ExtendedRegisters));
    *(USHORT *)Context->ExtendedRegisters = 0x27f;
    *(ULONG *)(Context->ExtendedRegisters + 24) = 0x1f80;
}

NTSTATUS Wow64CreateThread(HANDLE *Handle, ACCESS_MASK Access,
                           OBJECT_ATTRIBUTES *Attributes, HANDLE Process,
                           CLIENT_ID *Id, const WOW64_CONTEXT *Context,
                           const ULONG *InitialTeb, BOOLEAN Suspended)
{
    CONTEXT Native = {0};
    INITIAL_TEB Stack = {0}, GuestStack;
    WOW64_CONTEXT Captured = *Context;
    THREAD_BASIC_INFORMATION Info;
    TEB Teb;
    TEB32 Teb32;
    ULONG_PTR Peb32;
    SIZE_T Size = 1024 * 1024, Zero = 0;
    PVOID ContextAddress, Guard;
    ULONG OldProtect;
    HANDLE Thread = NULL;
    NTSTATUS Status;

    if ((Captured.ContextFlags & WOW64_CONTEXT_FULL) != WOW64_CONTEXT_FULL)
        return STATUS_INVALID_PARAMETER;
    Wow64ResetInitialState(&Captured);
    Status = NtQueryInformationProcess(Process, ProcessWow64Information,
                                       &Peb32, sizeof(Peb32), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    if (!Peb32) return STATUS_INVALID_PARAMETER;
    GuestStack.PreviousStackBase = PTR32(InitialTeb[0]);
    GuestStack.PreviousStackLimit = PTR32(InitialTeb[1]);
    GuestStack.StackBase = PTR32(InitialTeb[2]);
    GuestStack.StackLimit = PTR32(InitialTeb[3]);
    GuestStack.AllocatedStackBase = PTR32(InitialTeb[4]);
    if (GuestStack.PreviousStackBase || GuestStack.PreviousStackLimit)
    {
        GuestStack.StackBase = GuestStack.PreviousStackBase;
        GuestStack.StackLimit = GuestStack.PreviousStackLimit;
    }

    /* Every guest thread needs a separate native stack for the loader and
     * argument translators. Keep the startup context in that allocation. */
    Status = NtAllocateVirtualMemory(Process, &Stack.AllocatedStackBase, 0,
                                     &Size, MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) return Status;
    Stack.StackBase = (PUCHAR)Stack.AllocatedStackBase + Size;
    /* Leave room for growth without charging a megabyte of commit per thread.
     * The ordinary native stack-fault path advances this guard page. */
    Size = 64 * 1024;
    Guard = (PUCHAR)Stack.StackBase - Size;
    Stack.StackLimit = (PUCHAR)Guard + PAGE_SIZE;
    Status = NtAllocateVirtualMemory(Process, &Guard, 0, &Size, MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(Status))
    {
        Size = PAGE_SIZE;
        Status = NtProtectVirtualMemory(Process, &Guard, &Size,
                                         PAGE_READWRITE | PAGE_GUARD, &OldProtect);
    }
    if (!NT_SUCCESS(Status))
    {
        NtFreeVirtualMemory(Process, &Stack.AllocatedStackBase, &Zero, MEM_RELEASE);
        return Status;
    }
    ContextAddress = (PUCHAR)Stack.StackBase - ((sizeof(Captured) + 15) & ~15);
    Native.ContextFlags = CONTEXT_FULL;
    Native.Rsp = (ULONG_PTR)ContextAddress;
    Native.Rcx = (ULONG_PTR)ContextAddress;
    Native.Rdx = WOW64_THREAD_START_MARKER;
    Native.SegCs = 0x33;
    Native.SegSs = 0x2b;
    Native.EFlags = 0x202;
    Status = NtWriteVirtualMemory(Process, ContextAddress, &Captured, sizeof(Captured), NULL);
    if (NT_SUCCESS(Status))
        Status = NtCreateThread(&Thread, Access, Attributes, Process, Id,
                                 &Native, &Stack, TRUE);
    if (NT_SUCCESS(Status))
    {
        /* kernel32's threads start in BaseThreadStartupThunk with the routine in EAX; ntdll's
         * (RtlCreateUserThread, e.g. a debugger's DbgUiRemoteBreakin) start at the routine with
         * EAX zero. Windows reports the routine for both. */
        ULONG_PTR StartAddress = Captured.Eax ? Captured.Eax : Captured.Eip;
        Status = NtSetInformationThread(Thread, ThreadQuerySetWin32StartAddress,
                                        &StartAddress, sizeof(StartAddress));
    }
    if (NT_SUCCESS(Status))
        Status = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), NULL);
    if (NT_SUCCESS(Status))
        Status = NtReadVirtualMemory(Process, Info.TebBaseAddress, &Teb, sizeof(Teb), NULL);
    if (NT_SUCCESS(Status))
    {
        Wow64InitializeTeb(&Teb32, &Teb, Info.TebBaseAddress, &GuestStack);
        Status = NtWriteVirtualMemory(Process, WOW64_TEB32(Info.TebBaseAddress),
                                      &Teb32, sizeof(Teb32), NULL);
    }
    if (NT_SUCCESS(Status) && !Suspended) Status = NtResumeThread(Thread, NULL);
    if (!NT_SUCCESS(Status))
    {
        if (Thread)
            Wow64AbortThread(Thread, Process, Status);
        else
            NtFreeVirtualMemory(Process, &Stack.AllocatedStackBase, &Zero, MEM_RELEASE);
        return Status;
    }
    *Handle = Thread;
    return STATUS_SUCCESS;
}

NTSTATUS Wow64QueryThread(HANDLE Thread, ULONG Class, PVOID Buffer, ULONG Length, PULONG ReturnLength)
{
    NTSTATUS Status;
    if (Class == ThreadBasicInformation)
    {
        THREAD_BASIC_INFORMATION Native;
        struct { ULONG Status, Teb, Process, Thread, Affinity; LONG Priority, BasePriority; } *Guest = Buffer;
        if (Length != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Status = NtQueryInformationThread(Thread, Class, &Native, sizeof(Native), NULL);
        if (NT_SUCCESS(Status))
        {
            Guest->Status = Native.ExitStatus;
            Guest->Teb = Native.TebBaseAddress ? PtrToUlong(WOW64_TEB32(Native.TebBaseAddress)) : 0;
            Guest->Process = HandleToUlong(Native.ClientId.UniqueProcess);
            Guest->Thread = HandleToUlong(Native.ClientId.UniqueThread);
            Guest->Affinity = (ULONG)Native.AffinityMask;
            Guest->Priority = Native.Priority;
            Guest->BasePriority = Native.BasePriority;
            if (ReturnLength) *ReturnLength = sizeof(*Guest);
        }
        return Status;
    }
    if (Class == ThreadQuerySetWin32StartAddress || Class == ThreadAffinityMask)
    {
        ULONG_PTR Value;
        if (Length != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        Status = NtQueryInformationThread(Thread, Class, &Value, sizeof(Value), NULL);
        if (NT_SUCCESS(Status)) *(ULONG *)Buffer = (ULONG)Value;
        if (ReturnLength) *ReturnLength = sizeof(ULONG);
        return Status;
    }
    if (Class == ThreadNameInformation)
    {
        /* A UNICODE_STRING followed by its characters: the guest header is
         * eight bytes, the native one sixteen, so the buffer is widened. */
        UNICODE_STRING *Native;
        WOW64_STRING *Guest = Buffer;
        ULONG Needed = 0, Extra = sizeof(UNICODE_STRING) - sizeof(WOW64_STRING);
        ULONG NativeLength;
        if (Length > MAXULONG - Extra) return STATUS_INVALID_PARAMETER;
        /* A counted string never exceeds 64 KiB, so a larger scratch buffer
         * is never needed whatever length the guest claims. */
        NativeLength = min(Length, WOW64_MAX_INFO_BUFFER) + Extra;
        Native = RtlAllocateHeap(RtlGetProcessHeap(), 0, NativeLength);
        if (!Native) return STATUS_NO_MEMORY;
        /* The guest's ReturnLength and Buffer are unprobed: a fault in the
         * copy-out must still release the scratch buffer. */
        _SEH2_TRY
        {
            Status = NtQueryInformationThread(Thread, Class, Native, NativeLength, &Needed);
            if (ReturnLength && Needed) *ReturnLength = Needed >= sizeof(UNICODE_STRING) ? Needed - Extra : Needed;
            if (NT_SUCCESS(Status))
            {
                Guest->Length = Native->Length;
                Guest->MaximumLength = Native->MaximumLength;
                Guest->Buffer = Native->Buffer ? PtrToUlong(Guest + 1) : 0;
                if (Native->Buffer)
                    RtlCopyMemory(Guest + 1, Native->Buffer, Native->Length);
            }
        }
        _SEH2_FINALLY
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, Native);
        }
        _SEH2_END;
        return Status;
    }
    switch (Class)
    {
    case ThreadTimes: case ThreadPriorityBoost: case ThreadAmILastThread:
    case ThreadIsIoPending: case ThreadHideFromDebugger: case ThreadBreakOnTermination:
    case ThreadIsTerminated: case ThreadPerformanceCount:
        return NtQueryInformationThread(Thread, Class, Buffer, Length, ReturnLength);
    default: return STATUS_NOT_SUPPORTED;
    }
}
