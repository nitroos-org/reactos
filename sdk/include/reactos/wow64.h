/* ReactOS user-mode WoW64 ABI. SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/* Kernel builds do not include winnt.h's user-mode context declarations. */
#ifndef WOW64_CONTEXT_i386
#define WOW64_CONTEXT_i386 0x10000
#define WOW64_CONTEXT_CONTROL (WOW64_CONTEXT_i386 | 1)
#define WOW64_CONTEXT_INTEGER (WOW64_CONTEXT_i386 | 2)
#define WOW64_CONTEXT_SEGMENTS (WOW64_CONTEXT_i386 | 4)
#define WOW64_CONTEXT_FLOATING_POINT (WOW64_CONTEXT_i386 | 8)
#define WOW64_CONTEXT_DEBUG_REGISTERS (WOW64_CONTEXT_i386 | 16)
#define WOW64_CONTEXT_EXTENDED_REGISTERS (WOW64_CONTEXT_i386 | 32)
#define WOW64_CONTEXT_FULL (WOW64_CONTEXT_i386 | 7)
#define WOW64_CONTEXT_ALL (WOW64_CONTEXT_i386 | 63)
typedef struct
{
    ULONG ControlWord, StatusWord, TagWord, ErrorOffset, ErrorSelector;
    ULONG DataOffset, DataSelector;
    UCHAR RegisterArea[80];
    ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;
typedef struct _WOW64_CONTEXT
{
    ULONG ContextFlags, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    WOW64_FLOATING_SAVE_AREA FloatSave;
    ULONG SegGs, SegFs, SegEs, SegDs;
    ULONG Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    UCHAR ExtendedRegisters[512];
} WOW64_CONTEXT;
#endif
C_ASSERT(sizeof(WOW64_CONTEXT) == 716);
C_ASSERT(FIELD_OFFSET(WOW64_CONTEXT, ExtendedRegisters) == 204);


/* Reserved in the native loader's TLS bitmap, never exposed to i386 TLS. */
#define WOW64_TLS_CPU 1
#define WOW64_THREAD_START_MARKER 0x574f573332ULL
#define WOW64_PEB32(Peb) ((PEB32 *)((ULONG_PTR)(Peb) + ROUND_TO_PAGES(sizeof(PEB))))
#define WOW64_TEB32(Teb) ((TEB32 *)((ULONG_PTR)(Teb) + ROUND_TO_PAGES(sizeof(TEB))))

/* The descriptor of a selector of a 32-bit thread (GetThreadSelectorEntry, Wow64GetThreadSelectorEntry): the flat
 * code and data segments and the segment of the thread's 32-bit TEB (fs), for any requested privilege level, and an
 * empty descriptor for the null selector, as Windows Server 2022 reports them. Other selectors have none. The eight
 * bytes are an LDT_ENTRY. */
static __inline BOOLEAN Wow64SelectorDescriptor(ULONG Selector, ULONG TebBase, UCHAR Descriptor[8])
{
    ULONG Base = 0, Limit = 0;
    UCHAR Type = 0, High = 0;

    switch (Selector & ~3UL)
    {
    case 0x00: break;
    case 0x20: Limit = 0xFFFFF; Type = 0xFB; High = 0xC0; break;
    case 0x28: Limit = 0xFFFFF; Type = 0xF3; High = 0xC0; break;
    case 0x50: Base = TebBase; Limit = 0xFFF; Type = 0xF3; High = 0x40; break;
    default: return FALSE;
    }
    Descriptor[0] = (UCHAR)Limit;
    Descriptor[1] = (UCHAR)(Limit >> 8);
    Descriptor[2] = (UCHAR)Base;
    Descriptor[3] = (UCHAR)(Base >> 8);
    Descriptor[4] = (UCHAR)(Base >> 16);
    Descriptor[5] = Type;
    Descriptor[6] = High | (UCHAR)((Limit >> 16) & 0xF);
    Descriptor[7] = (UCHAR)(Base >> 24);
    return TRUE;
}

/* The WoW64 layer's own 64-bit code: native ntdll, wow64.dll, wow64win.dll,
 * wow64cpu.dll and the low-address gate page. A thread in 64-bit mode while
 * InTransition is set is in the middle of a transition only when it runs
 * there; anywhere else it runs 64-bit code its guest entered with a far
 * transfer, and the saved state is the guest's last known context. */
#define WOW64_LAYER_RANGES 5
typedef struct _WOW64_LAYER_CODE
{
    struct { ULONG64 Start, End; } Range[WOW64_LAYER_RANGES];
} WOW64_LAYER_CODE;

typedef struct DECLSPEC_ALIGN(16) _WOW64_CPU_STATE
{
    ULONG64 NativeStack;
    ULONG Esp;
    ULONG Eip;
    ULONG EFlags;
    ULONG Eax;
    ULONG Ebx;
    ULONG Esi;
    ULONG Edi;
    ULONG Ebp;
    ULONG FsRedirectionDisabled;
    ULONG Ecx;
    ULONG Edx;
    /* Zero only while the complete saved context is authoritative. It stays
     * set throughout return, guest execution and the next gate entry. */
    volatile LONG InTransition;
    BOOLEAN ContextEaxChanged;
    /* Set while ExtendedRegisters hold the guest's x87/SSE state and the return restores them: a
     * service that can change the registers saves them at entry (fastsvc.c), a context change
     * names them. Clear while the registers still hold the guest's own state (the plain services
     * change only XMM0-XMM5, which the entry saves in ExtendedRegisters and the return loads): a
     * reader then takes the thread's current state instead, with those six from the area. */
    BOOLEAN FpSaved;
    /* The far pointer of the return to the guest: Eip, then the code selector (cpu.S) */
    UCHAR GuestReturn[6];
    UCHAR ExtendedRegisters[512];
    ULONG Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    PVOID ApcFrame;
    PVOID CallbackFrame;
    PVOID ProcessParameters;
    const WOW64_LAYER_CODE *LayerCode;

} WOW64_CPU_STATE;
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, NativeStack) == 0);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Esp) == 8);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Eip) == 12);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, EFlags) == 16);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Eax) == 20);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Ebx) == 24);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Esi) == 28);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Edi) == 32);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Ebp) == 36);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Ecx) == 44);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, Edx) == 48);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, InTransition) == 52);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, FpSaved) == 57);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, GuestReturn) == 58);
C_ASSERT(FIELD_OFFSET(WOW64_CPU_STATE, ExtendedRegisters) == 64);

typedef NTSTATUS (NTAPI *WOW64_SERVICE)(ULONG Number, ULONG *Arguments);
NTSTATUS NTAPI Wow64CpuInitialize(WOW64_SERVICE Service, PVOID *Gate);
DECLSPEC_NORETURN VOID NTAPI Wow64CpuRun(WOW64_CPU_STATE *State);
VOID NTAPI Wow64LdrpInitialize(PCONTEXT Context, BOOLEAN ProcessStartup);

NTSTATUS NTAPI Wow64WinInitialize(PVOID Dispatcher);
NTSTATUS NTAPI Wow64WinSystemService(ULONG Number, ULONG *Arguments);
NTSTATUS NTAPI Wow64WinCallbackReturn(PVOID Buffer, ULONG Length, NTSTATUS Status);
