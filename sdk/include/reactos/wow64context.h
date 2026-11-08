/* ReactOS WoW64 context conversion. SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <reactos/wow64.h>

static __inline VOID Wow64FloatToLegacy(WOW64_CONTEXT *Context)
{
    const XMM_SAVE_AREA32 *Fx = (const XMM_SAVE_AREA32 *)Context->ExtendedRegisters;
    WOW64_FLOATING_SAVE_AREA *Legacy = &Context->FloatSave;
    ULONG i, Top = (Fx->StatusWord >> 11) & 7, Tags = 0;
    Legacy->ControlWord = Fx->ControlWord;
    Legacy->StatusWord = Fx->StatusWord;
    Legacy->ErrorOffset = Fx->ErrorOffset;
    Legacy->ErrorSelector = Fx->ErrorSelector | ((ULONG)Fx->ErrorOpcode << 16);
    Legacy->DataOffset = Fx->DataOffset;
    Legacy->DataSelector = Fx->DataSelector;
    Legacy->Cr0NpxState = 0;
    for (i = 0; i < 8; ++i)
    {
        const USHORT *Value = (const USHORT *)&Fx->FloatRegisters[(i - Top) & 7];
        ULONG Tag = 3;
        if (Fx->TagWord & (1 << i))
        {
            ULONG Exponent = Value[4] & 0x7fff;
            if (!Exponent)
                Tag = (Value[0] | Value[1] | Value[2] | Value[3]) ? 2 : 1;
            else Tag = (Exponent == 0x7fff || !(Value[3] & 0x8000)) ? 2 : 0;
        }
        Tags |= Tag << (i * 2);
        RtlCopyMemory(Legacy->RegisterArea + i * 10, &Fx->FloatRegisters[i], 10);
    }
    Legacy->TagWord = Tags;
}

static __inline VOID Wow64LegacyToFloat(XMM_SAVE_AREA32 *Fx,
                                       const WOW64_FLOATING_SAVE_AREA *Legacy)
{
    ULONG i;
    Fx->ControlWord = Legacy->ControlWord;
    Fx->StatusWord = Legacy->StatusWord;
    Fx->ErrorOffset = Legacy->ErrorOffset;
    Fx->ErrorSelector = Legacy->ErrorSelector;
    Fx->ErrorOpcode = Legacy->ErrorSelector >> 16;
    Fx->DataOffset = Legacy->DataOffset;
    Fx->DataSelector = Legacy->DataSelector;
    Fx->TagWord = 0;
    for (i = 0; i < 8; ++i)
    {
        if (((Legacy->TagWord >> (i * 2)) & 3) != 3) Fx->TagWord |= 1 << i;
        RtlCopyMemory(&Fx->FloatRegisters[i], Legacy->RegisterArea + i * 10, 10);
    }
}

/* The EFlags a guest thread may hold: everything IRETQ and the guest can use except NT (its
 * return to the guest raises #GP when NT is set, and the thread then faults forever) and IOPL.
 * RF, VM, VIF and VIP stay in the saved state, as a Windows context reads them back; they do not
 * show in the flags a running guest thread sees. */
#define WOW64_EFLAGS_USER_SANITIZE 0x003f0dd7
/* The flags of a guest that runs (what the native kernel loads for a compatibility-mode context) */
#define WOW64_EFLAGS_RUNNING_SANITIZE 0x00240fd7

static __inline VOID Wow64CpuToContext(WOW64_CONTEXT *To, const WOW64_CPU_STATE *From)
{
    RtlZeroMemory(To, sizeof(*To));
    To->ContextFlags = WOW64_CONTEXT_ALL;
#define COPY(x) To->x = From->x
    COPY(Eax); COPY(Ebx); COPY(Ecx); COPY(Edx); COPY(Esi); COPY(Edi);
    COPY(Ebp); COPY(Esp); COPY(Eip); COPY(EFlags);
    COPY(Dr0); COPY(Dr1); COPY(Dr2); COPY(Dr3); COPY(Dr6); COPY(Dr7);
#undef COPY
    /* The selectors wow64cpu loads for the guest (cpu.S Wow64CpuReturn); GS keeps the
     * flat data selector the guest was started with */
    To->SegCs = 0x23; To->SegSs = To->SegDs = To->SegEs = To->SegGs = 0x2b; To->SegFs = 0x53;
    RtlCopyMemory(To->ExtendedRegisters, From->ExtendedRegisters, 512);
    Wow64FloatToLegacy(To);
}

static __inline VOID Wow64ContextToCpu(WOW64_CPU_STATE *To, const WOW64_CONTEXT *From)
{
    ULONG Flags = From->ContextFlags & ~WOW64_CONTEXT_i386;
#define COPY(x) To->x = From->x
    if (Flags & 1) { COPY(Ebp); COPY(Esp); COPY(Eip); COPY(EFlags); }
    if (Flags & 2) { COPY(Eax); COPY(Ebx); COPY(Ecx); COPY(Edx); COPY(Esi); COPY(Edi); }
    if (Flags & 16) { COPY(Dr0); COPY(Dr1); COPY(Dr2); COPY(Dr3); COPY(Dr6); COPY(Dr7); }
#undef COPY
    if (Flags & 32) RtlCopyMemory(To->ExtendedRegisters, From->ExtendedRegisters, 512);
    else if (Flags & 8)
        Wow64LegacyToFloat((XMM_SAVE_AREA32 *)To->ExtendedRegisters, &From->FloatSave);
    /* The registers are given: the return loads them */
    if (Flags & (8 | 32)) To->FpSaved = TRUE;
    *(ULONG *)(To->ExtendedRegisters + 24) &= 0xffbf;
    To->EFlags = (To->EFlags & WOW64_EFLAGS_USER_SANITIZE) | 0x202;
}

static __inline VOID Wow64NativeToContext(WOW64_CONTEXT *To, const CONTEXT *From)
{
    RtlZeroMemory(To, sizeof(*To));
    To->ContextFlags = WOW64_CONTEXT_ALL;
#define REG(x, y) To->x = (ULONG)From->y
    REG(Eax, Rax); REG(Ebx, Rbx); REG(Ecx, Rcx); REG(Edx, Rdx);
    REG(Esi, Rsi); REG(Edi, Rdi); REG(Ebp, Rbp); REG(Esp, Rsp); REG(Eip, Rip);
    REG(EFlags, EFlags);
    REG(SegCs, SegCs); REG(SegSs, SegSs); REG(SegDs, SegDs);
    REG(SegEs, SegEs); REG(SegFs, SegFs); REG(SegGs, SegGs);
    REG(Dr0, Dr0); REG(Dr1, Dr1); REG(Dr2, Dr2); REG(Dr3, Dr3); REG(Dr6, Dr6); REG(Dr7, Dr7);
#undef REG
    RtlCopyMemory(To->ExtendedRegisters, &From->FltSave, 512);
    Wow64FloatToLegacy(To);
}

static __inline VOID Wow64ContextToNative(CONTEXT *To, const WOW64_CONTEXT *From)
{
    ULONG Flags = From->ContextFlags & ~WOW64_CONTEXT_i386;
    To->ContextFlags = CONTEXT_AMD64;
    if (Flags & 2)
    {
        To->ContextFlags |= CONTEXT_INTEGER;
#define REG(x, y) To->x = From->y
        REG(Rax, Eax); REG(Rbx, Ebx); REG(Rcx, Ecx); REG(Rdx, Edx); REG(Rsi, Esi); REG(Rdi, Edi);
#undef REG
    }
    if (Flags & 1)
    {
        To->ContextFlags |= CONTEXT_CONTROL | CONTEXT_INTEGER;
        To->Rbp = From->Ebp; To->Rsp = From->Esp; To->Rip = From->Eip;
        To->EFlags = From->EFlags & WOW64_EFLAGS_RUNNING_SANITIZE; To->SegCs = 0x23; To->SegSs = 0x2b;
    }
    if (Flags & 4)
    {
        To->ContextFlags |= CONTEXT_SEGMENTS;
        /* Native i386 startup uses KGDT_R3_DATA without RPL bits. Both
         * forms name the amd64 compatibility-code descriptor, not data. */
        To->SegDs = (From->SegDs & ~3) == 0x20 ? 0x2b : From->SegDs;
        To->SegEs = (From->SegEs & ~3) == 0x20 ? 0x2b : From->SegEs;
        To->SegFs = 0x53; To->SegGs = From->SegGs;
    }
    if (Flags & (8 | 32))
    {
        To->ContextFlags |= CONTEXT_FLOATING_POINT;
        if (Flags & 32) RtlCopyMemory(&To->FltSave, From->ExtendedRegisters, 512);
        else Wow64LegacyToFloat(&To->FltSave, &From->FloatSave);
        To->MxCsr = To->FltSave.MxCsr &= 0xffbf;
    }
    if (Flags & 16)
    {
        To->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
#define COPY(x) To->x = From->x
        COPY(Dr0); COPY(Dr1); COPY(Dr2); COPY(Dr3); COPY(Dr6); COPY(Dr7);
#undef COPY
    }
}

static __inline VOID Wow64CopyContext(WOW64_CONTEXT *To, const WOW64_CONTEXT *From, ULONG Flags)
{
    if (Flags & 1) RtlCopyMemory(&To->Ebp, &From->Ebp, 6 * sizeof(ULONG));
    if (Flags & 2) RtlCopyMemory(&To->Edi, &From->Edi, 6 * sizeof(ULONG));
    if (Flags & 4) RtlCopyMemory(&To->SegGs, &From->SegGs, 4 * sizeof(ULONG));
    if (Flags & 8) To->FloatSave = From->FloatSave;
    if (Flags & 16) RtlCopyMemory(&To->Dr0, &From->Dr0, 6 * sizeof(ULONG));
    if (Flags & 32) RtlCopyMemory(To->ExtendedRegisters, From->ExtendedRegisters, 512);
}
