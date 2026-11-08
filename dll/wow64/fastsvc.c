/* ReactOS WoW64 system service entry and the plain services.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file is compiled with -mgeneral-regs-only: nothing in it touches an x87, MMX or SSE register,
 * so the guest's floating-point state is exactly what it was at the gate while a plain service runs
 * (the kernel keeps the registers of a thread across a system call and a context switch). */
#include "wow64p.h"

enum
{
#define WOW64_SYSCALL(Name, Source, Target, SourceSlots, TargetSlots, Flags) W64_##Name = Source,
#include <reactos/wow64/nt32to64.inc>
#undef WOW64_SYSCALL
};

#define H(i) HANDLE32(A(i))
#define P(i) PTR32(A(i))

/* The services of fastlist.inc: the native call takes what the guest passed, handles sign extended and
 * pointers or counts zero extended, and nothing else is translated (no output structure, no handle
 * returned, no information class). */
static BOOLEAN IsPlainService(ULONG Number)
{
    switch (Number)
    {
    case W64_NtQuerySystemTime:
#define FAST_SERVICE(Name, Call) case W64_##Name:
#include "fastlist.inc"
#undef FAST_SERVICE
        return TRUE;
    default:
        return FALSE;
    }
}

/* NtQuerySystemTime: the kernel (KeQuerySystemTime) reads the system time from the shared user data page
 * and stores it, so the thunk does the same without entering the kernel. Same checks, same stores: the
 * output is probed as the kernel's ProbeForWriteLargeInteger does (read and write back; there is no
 * alignment test), and a fault is the status the kernel's SEH would have returned. */
static NTSTATUS QuerySystemTime32(ULONG Address)
{
    volatile ULONGLONG *Time = (volatile ULONGLONG *)PTR32(Address);
    *Time = *Time;
    *Time = *(volatile ULONGLONG *)&SharedUserData->SystemTime;
    return STATUS_SUCCESS;
}

/* The guest's argument list is on its stack, where other guest threads can change it: each
 * argument is read once, by the call that takes it. */
static NTSTATUS PlainService(ULONG Number, const ULONG *Arguments)
{
#define A(i) (((volatile const ULONG *)Arguments)[i])
    switch (Number)
    {
    case W64_NtQuerySystemTime: return QuerySystemTime32(A(0));
#define FAST_SERVICE(Name, Call) case W64_##Name: return Call;
#include "fastlist.inc"
#undef FAST_SERVICE
    default:
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
#undef A
}

NTSTATUS NTAPI Wow64SystemService(ULONG Number, ULONG *Arguments)
{
    NTSTATUS Status;
    WOW64_CPU_STATE *Cpu;
    Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    if (!IsPlainService(Number))
    {
        /* Anything else may run code that uses the registers: keep the guest's, and have the
         * return load them (before InTransition is clear, so no reader sees one without the other) */
        __asm__ __volatile__("fxsave %0" : "=m"(*(UCHAR (*)[512])Cpu->ExtendedRegisters));
        Cpu->FpSaved = TRUE;
        return Wow64SystemServiceFull(Number, Arguments);
    }
    Cpu->FpSaved = FALSE;
    /* As Wow64SystemServiceFull: the saved context is authoritative from here to the return */
    Cpu->ContextEaxChanged = FALSE;
    Cpu->InTransition = 0;
    _ReadWriteBarrier();
    _SEH2_TRY
    {
        Status = PlainService(Number, Arguments);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
#if DBG
    if (!NT_SUCCESS(Status) && Number != W64_NtQueryDebugFilterState)
        DbgPrint("WoW64: service %lx returned %08lx\n", Number, Status);
#endif
    _ReadWriteBarrier();
    Cpu->InTransition = 1;
    _ReadWriteBarrier();
    if (!Cpu->ContextEaxChanged) Cpu->Eax = Status;
    return Status;
}
