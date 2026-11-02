/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         Test for NtContinue
 * PROGRAMMER:
 */

#include "precomp.h"

#include <setjmp.h>
#include <time.h>
#include <intrin.h>

#ifdef _MSC_VER
#pragma runtime_checks("s", off)
#endif

#ifdef _M_IX86
#define NTC_SEGMENT_BITS (0xFFFF)
#define NTC_EFLAGS_BITS  (0x3C0CD5)
/* A WoW64 thread never runs with VIF or VIP set (checked on Windows 10 22H2) */
#define NTC_WOW64_EFLAGS_BITS (NTC_EFLAGS_BITS & ~0x180000)
static ULONG NtcEflagsBits = NTC_EFLAGS_BITS;
#endif

void continuePoint(void);

#define NTC_EFL_NT      0x4000
#define NTC_EFL_IOPL    0x3000
#define NTC_EFL_RF      0x10000
#define NTC_EFL_VM      0x20000
#define NTC_EFL_AC      0x40000
#define NTC_EFL_VIF     0x80000
#define NTC_EFL_VIP     0x100000
#define NTC_EFL_ID      0x200000

#ifdef _M_AMD64
/* Second pass: every flag a context may name and Windows drops or keeps (checked on Windows 10 22H2) */
static BOOLEAN NtcFixedFlags;
#endif

static jmp_buf jmpbuf;
static CONTEXT continueContext;
static unsigned int nRandBytes;

static int initrand(void)
{
    unsigned int nRandMax;
    unsigned int nRandMaxBits;
    time_t tLoc;

    nRandMax = RAND_MAX;
    for(nRandMaxBits = 0; nRandMax != 0; nRandMax >>= 1, ++ nRandMaxBits);
    nRandBytes = nRandMaxBits / CHAR_BIT;
    //assert(nRandBytes != 0);
    srand((unsigned)(time(&tLoc) & UINT_MAX));
    return 1;
}

static void randbytes(void * p, size_t n)
{
    unsigned char * b;
    size_t i;
    int r = rand();

    b = (unsigned char *)p;
    for(i = 0; i < n; ++ i)
    {
        if(i % nRandBytes == 0)
        r = rand();
        b[i] = (unsigned char)(r & UCHAR_MAX);
        r >>= CHAR_BIT;
    }
}

static ULONG randULONG(void)
{
    ULONG n;
    randbytes(&n, sizeof(n));
    return n;
}

#ifdef _M_AMD64
static ULONG64 randULONG64(void)
{
    return (ULONG64)randULONG() << 32 | randULONG();
}
#endif

void check(CONTEXT * pContext)
{
#ifdef _M_IX86
    ok(pContext->ContextFlags == CONTEXT_FULL,
       "ContextFlags=0x%lx\n", pContext->ContextFlags);

    /* Random data segments */
    ok((pContext->SegGs & NTC_SEGMENT_BITS) ==
       (continueContext.SegGs & NTC_SEGMENT_BITS),
       "SegGs=0x%lx / 0x%lx\n", pContext->SegGs, continueContext.SegGs);

    ok((pContext->SegFs & NTC_SEGMENT_BITS) ==
       (continueContext.SegFs & NTC_SEGMENT_BITS),
       "SegFs=0x%lx / 0x%lx\n", pContext->SegFs, continueContext.SegFs);

    ok((pContext->SegEs & NTC_SEGMENT_BITS) ==
       (continueContext.SegEs & NTC_SEGMENT_BITS),
       "SegEs=0x%lx / 0x%lx\n", pContext->SegEs, continueContext.SegEs);

    ok((pContext->SegDs & NTC_SEGMENT_BITS) ==
       (continueContext.SegDs & NTC_SEGMENT_BITS),
       "SegDs=0x%lx / 0x%lx\n", pContext->SegDs, continueContext.SegDs);

    /* Integer registers */
    ok(pContext->Edi == continueContext.Edi,
       "Edi: 0x%lx != 0x%lx\n", pContext->Edi, continueContext.Edi);
    ok(pContext->Esi == continueContext.Esi,
       "Esi: 0x%lx != 0x%lx\n", pContext->Esi, continueContext.Esi);
    ok(pContext->Ebx == continueContext.Ebx,
       "Ebx: 0x%lx != 0x%lx\n", pContext->Ebx, continueContext.Ebx);
    ok(pContext->Edx == continueContext.Edx,
       "Edx: 0x%lx != 0x%lx\n", pContext->Edx, continueContext.Edx);
    ok(pContext->Ecx == continueContext.Ecx,
       "Ecx: 0x%lx != 0x%lx\n", pContext->Ecx, continueContext.Ecx);
    ok(pContext->Eax == continueContext.Eax,
       "Eax: 0x%lx != 0x%lx\n", pContext->Eax, continueContext.Eax);

    /* Control registers and segments */
    ok(pContext->Ebp == continueContext.Ebp,
       "Ebp: 0x%lx != 0x%lx\n", pContext->Ebp, continueContext.Ebp);
    ok(pContext->Eip == continueContext.Eip,
       "Eip: 0x%lx != 0x%lx\n", pContext->Eip, continueContext.Eip);
    ok(pContext->Esp == continueContext.Esp,
       "Esp: 0x%lx != 0x%lx\n", pContext->Esp, continueContext.Esp);

    ok((pContext->SegCs & NTC_SEGMENT_BITS) ==
       (continueContext.SegCs & NTC_SEGMENT_BITS),
       "SegCs: 0x%lx != 0x%lx\n", pContext->SegCs, continueContext.SegCs);

    ok((pContext->EFlags & NtcEflagsBits) ==
       (continueContext.EFlags & NtcEflagsBits),
       "EFlags: 0x%lx != 0x%lx\n", pContext->EFlags, continueContext.EFlags);

    ok((pContext->SegSs & NTC_SEGMENT_BITS) ==
       (continueContext.SegSs & NTC_SEGMENT_BITS),
       "SegSs: 0x%lx != 0x%lx\n", pContext->SegSs, continueContext.SegSs);
#else
    ok_eq_hex64(pContext->ContextFlags, CONTEXT_FULL | CONTEXT_SEGMENTS);
    ok_eq_hex(pContext->MxCsr, continueContext.MxCsr);
    ok_eq_hex(pContext->SegCs, continueContext.SegCs);
    ok_eq_hex(pContext->SegDs, 0x2B);
    ok_eq_hex(pContext->SegEs, 0x2B);
    ok_eq_hex(pContext->SegFs, 0x53);
    ok_eq_hex(pContext->SegGs, 0x2B);
    ok_eq_hex(pContext->SegSs, continueContext.SegSs);
    if (NtcFixedFlags)
    {
        /* A 64-bit thread never runs with NT, IOPL, VM, AC, VIF or VIP set; ID stays */
        ok_eq_hex(pContext->EFlags & (NTC_EFL_NT | NTC_EFL_IOPL | NTC_EFL_VM | NTC_EFL_AC |
                                      NTC_EFL_VIF | NTC_EFL_VIP | NTC_EFL_ID), NTC_EFL_ID);
    }
    else
    {
        ok_eq_hex(pContext->EFlags & ~0x1C0000, (continueContext.EFlags & ~0x1C0000) | 0x202);
    }

    ok_eq_hex64(pContext->Rax, continueContext.Rax);
    ok_eq_hex64(pContext->Rdx, continueContext.Rdx);
    ok_eq_hex64(pContext->Rbx, continueContext.Rbx);
    ok_eq_hex64(pContext->Rsp, continueContext.Rsp);
    ok_eq_hex64(pContext->Rbp, continueContext.Rbp);
    ok_eq_hex64(pContext->Rsi, continueContext.Rsi);
    ok_eq_hex64(pContext->Rdi, continueContext.Rdi);
    ok_eq_hex64(pContext->R8, continueContext.R8);
    ok_eq_hex64(pContext->R9, continueContext.R9);
    ok_eq_hex64(pContext->R10, continueContext.R10);
    ok_eq_hex64(pContext->R11, continueContext.R11);
    ok_eq_hex64(pContext->R12, continueContext.R12);
    ok_eq_hex64(pContext->R13, continueContext.R13);
    ok_eq_hex64(pContext->R14, continueContext.R14);
    ok_eq_hex64(pContext->R15, continueContext.R15);
    ok_eq_xmm(pContext->Xmm0, continueContext.Xmm0);
    ok_eq_xmm(pContext->Xmm1, continueContext.Xmm1);
    ok_eq_xmm(pContext->Xmm2, continueContext.Xmm2);
    ok_eq_xmm(pContext->Xmm3, continueContext.Xmm3);
    ok_eq_xmm(pContext->Xmm4, continueContext.Xmm4);
    ok_eq_xmm(pContext->Xmm5, continueContext.Xmm5);
    ok_eq_xmm(pContext->Xmm6, continueContext.Xmm6);
    ok_eq_xmm(pContext->Xmm7, continueContext.Xmm7);
    ok_eq_xmm(pContext->Xmm8, continueContext.Xmm8);
    ok_eq_xmm(pContext->Xmm9, continueContext.Xmm9);
    ok_eq_xmm(pContext->Xmm10, continueContext.Xmm10);
    ok_eq_xmm(pContext->Xmm11, continueContext.Xmm11);
    ok_eq_xmm(pContext->Xmm12, continueContext.Xmm12);
    ok_eq_xmm(pContext->Xmm13, continueContext.Xmm13);
    ok_eq_xmm(pContext->Xmm14, continueContext.Xmm14);
    ok_eq_xmm(pContext->Xmm15, continueContext.Xmm15);

    // Clear the frame register to prevent unwinding, which is broken
    ((_JUMP_BUFFER*)&jmpbuf)->Frame = 0;
#endif

    /* Return where we came from */
    longjmp(jmpbuf, 1);
}

static void DoNtContinue(void)
{
#ifdef _M_IX86
    BOOL IsWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (IsWow64)
        NtcEflagsBits = NTC_WOW64_EFLAGS_BITS;
#endif
    initrand();

    RtlFillMemory(&continueContext, sizeof(continueContext), 0xBBBBBBBB);

    /* First time */
    if(setjmp(jmpbuf) == 0)
    {
        CONTEXT bogus[2];

        RtlFillMemory(&bogus, sizeof(bogus), 0xCCCCCCCC);

        continueContext.ContextFlags = CONTEXT_FULL;
        GetThreadContext(GetCurrentThread(), &continueContext);

#ifdef _M_IX86
        continueContext.ContextFlags = CONTEXT_FULL;

        /* Fill the integer registers with random values */
        continueContext.Edi = randULONG();
        continueContext.Esi = randULONG();
        continueContext.Ebx = randULONG();
        continueContext.Edx = randULONG();
        continueContext.Ecx = randULONG();
        continueContext.Eax = randULONG();
        continueContext.Ebp = randULONG();

        /* Randomize all the allowed flags (determined experimentally with WinDbg) */
        continueContext.EFlags = randULONG() & 0x3C0CD5;

        /* Randomize the stack pointer as much as possible */
        continueContext.Esp = (ULONG)(((ULONG_PTR)&bogus) & 0xFFFFFFFF) +
                              sizeof(bogus) - (randULONG() & 0xF) * 4;

        /* continuePoint() is implemented in assembler */
        continueContext.Eip = (ULONG)((ULONG_PTR)continuePoint & 0xFFFFFFF);

        /* Can't do a lot about segments */
#elif defined(_M_AMD64)
        continueContext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

        /* Fill the integer registers with random values */
        PULONG64 Registers = &continueContext.Rax;
        for (ULONG i = 0; i < 16; i++)
        {
            Registers[i] = randULONG64();
        }

        /* Fill the XMM registers with random values */
        Registers = (PULONG64)&continueContext.Xmm0;
        for (ULONG i = 0; i < 32; i++)
        {
            Registers[i] = randULONG64();
        }

        continueContext.Dr0 = randULONG64() & 0xFFFF;
        continueContext.Dr1 = randULONG64() & 0xFFFF;
        continueContext.Dr2 = randULONG64() & 0xFFFF;
        continueContext.Dr3 = randULONG64() & 0xFFFF;
        continueContext.Dr6 = randULONG64() & 0xFFFF;
        continueContext.Dr7 = randULONG64() & 0xFFFF;

        /* Randomize all the allowed flags (determined experimentally with WinDbg) */
        continueContext.EFlags = randULONG64() & 0x3C0CD5;
        if (NtcFixedFlags)
        {
            continueContext.EFlags = 0x202 | NTC_EFL_NT | NTC_EFL_IOPL | NTC_EFL_RF | NTC_EFL_VM |
                                     NTC_EFL_AC | NTC_EFL_VIF | NTC_EFL_VIP | NTC_EFL_ID;
        }

        /* Randomize the stack pointer as much as possible */
        continueContext.Rsp = (((ULONG_PTR)&bogus)) + (randULONG() & 0xF) * 16;
        continueContext.Rsp = ALIGN_DOWN_BY(continueContext.Rsp, 16);

        /* continuePoint() is implemented in assembler */
        continueContext.Rip = ((ULONG_PTR)continuePoint);
#endif

        NtContinue(&continueContext, FALSE);
        ok(0, "should never get here\n");
    }

    /* Second time */
    return;
}

typedef struct _TC_ROW
{
    ULONG In;           /* EFlags given to SetThreadContext */
    ULONG Readback;     /* what GetThreadContext reads back */
    ULONG SeenSet;      /* flags the running thread sees (PUSHF) that must be set */
    ULONG SeenClear;    /* and that must be clear */
} TC_ROW;

#ifdef _M_AMD64
#define TC_DROP (NTC_EFL_NT | NTC_EFL_IOPL | NTC_EFL_VM | NTC_EFL_AC | NTC_EFL_VIF | NTC_EFL_VIP)
/* Windows 10 22H2, x64: NT, IOPL, VM, AC, VIF and VIP are dropped, RF is kept in the context
 * (but never seen by the running thread), ID is kept, and the context has no reserved bit 1 */
static const TC_ROW TcRows[] =
{
    { 0x202,                 0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_NT,    0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_IOPL,  0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_RF,    0x10200,  0,          TC_DROP },
    { 0x202 | NTC_EFL_VM,    0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_AC,    0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_VIF,   0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_VIP,   0x200,    0,          TC_DROP },
    { 0x202 | NTC_EFL_ID,    0x200200, NTC_EFL_ID, TC_DROP },
};
#else
#define TC_DROP (NTC_EFL_NT | NTC_EFL_IOPL | NTC_EFL_RF | NTC_EFL_VM | NTC_EFL_VIF | NTC_EFL_VIP)
/* Windows 10 22H2, 32-bit under WoW64: NT and IOPL are dropped; RF, VM, VIF and VIP are read
 * back but a running thread never sees them; AC and ID stay */
static const TC_ROW TcRows[] =
{
    { 0x202,                 0x202,    0,          TC_DROP },
    { 0x202 | NTC_EFL_NT,    0x202,    0,          TC_DROP },
    { 0x202 | NTC_EFL_IOPL,  0x202,    0,          TC_DROP },
    { 0x202 | NTC_EFL_RF,    0x10202,  0,          TC_DROP },
    { 0x202 | NTC_EFL_VM,    0x20202,  0,          TC_DROP },
    { 0x202 | NTC_EFL_AC,    0x40202,  NTC_EFL_AC, TC_DROP },
    { 0x202 | NTC_EFL_VIF,   0x80202,  0,          TC_DROP },
    { 0x202 | NTC_EFL_VIP,   0x100202, 0,          TC_DROP },
    { 0x202 | NTC_EFL_ID,    0x200202, NTC_EFL_ID, TC_DROP },
};
#endif

static volatile ULONG TcSeen;

static DWORD WINAPI TcThread(PVOID Param)
{
    TcSeen = (ULONG)__readeflags();
    return 0;
}

static void TestSetThreadContextEFlags(void)
{
    ULONG i;
#ifdef _M_IX86
    BOOL IsWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (!IsWow64)
        return;
#endif
    for (i = 0; i < ARRAYSIZE(TcRows); i++)
    {
        CONTEXT Context;
        HANDLE Thread = CreateThread(NULL, 0, TcThread, NULL, CREATE_SUSPENDED, NULL);
        BOOL Ret;

        ok(Thread != NULL, "row %lu: CreateThread failed %lu\n", i, GetLastError());
        if (!Thread)
            continue;
        ZeroMemory(&Context, sizeof(Context));
        Context.ContextFlags = CONTEXT_CONTROL;
        Ret = GetThreadContext(Thread, &Context);
        ok(Ret, "row %lu: GetThreadContext failed %lu\n", i, GetLastError());
        Context.EFlags = TcRows[i].In;
        Ret = SetThreadContext(Thread, &Context);
        ok(Ret, "row %lu: SetThreadContext failed %lu\n", i, GetLastError());
        ZeroMemory(&Context, sizeof(Context));
        Context.ContextFlags = CONTEXT_CONTROL;
        Ret = GetThreadContext(Thread, &Context);
        ok(Ret, "row %lu: GetThreadContext failed %lu\n", i, GetLastError());
        ok(Context.EFlags == TcRows[i].Readback,
           "row %lu: EFlags 0x%lx given, 0x%lx read back, expected 0x%lx\n",
           i, TcRows[i].In, (ULONG)Context.EFlags, TcRows[i].Readback);

        TcSeen = 0xDEAD0000;
        ResumeThread(Thread);
        ok_eq_ulong(WaitForSingleObject(Thread, 30000), WAIT_OBJECT_0);
        ok((TcSeen & TcRows[i].SeenClear) == 0,
           "row %lu: running thread saw EFlags 0x%lx, bits 0x%lx must be clear\n",
           i, TcSeen, TcSeen & TcRows[i].SeenClear);
        ok((TcSeen & TcRows[i].SeenSet) == TcRows[i].SeenSet,
           "row %lu: running thread saw EFlags 0x%lx, bits 0x%lx must be set\n",
           i, TcSeen, TcRows[i].SeenSet);
        CloseHandle(Thread);
    }
}

/* Hardware breakpoints set with SetThreadContext (CONTEXT_DEBUG_REGISTERS), x64 and WoW64.
 * Expected results measured on Windows 10 22H2 (x64 and WOW64). The current thread reads back
 * the processor's DR6 and DR7, with their reserved bits that read as 1 (DR6 0xffff0ff0, DR7
 * bit 10): only the status bits of DR6 and the defined bits of DR7 are compared. Under WoW64,
 * Windows masks DR7 with the i386 mask (no GE) and sets LE in some cases: LE and GE are not
 * compared there, and a DR7 without an enabled breakpoint is checked on x64 only (WoW64 keeps
 * the addresses and reads DR7 back as 0x100). */
#ifdef _M_AMD64
#define DR7_IGNORED 0x400
#else
#define DR7_IGNORED 0x700
#endif
static volatile LONG DrHits;
static volatile ULONG_PTR DrHitDr6;
static volatile LONG DrTarget;
static volatile ULONG_PTR DrOtherDr7;
static volatile LONG DrOtherHits;
static HANDLE DrGo;

static LONG CALLBACK DrHandler(PEXCEPTION_POINTERS Info)
{
    if (Info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&DrHits);
    DrHitDr6 = Info->ContextRecord->Dr6;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL DrSet(HANDLE Thread, ULONG_PTR Dr0, ULONG_PTR Dr1, ULONG_PTR Dr2, ULONG_PTR Dr3,
                  ULONG_PTR Dr6, ULONG_PTR Dr7)
{
    CONTEXT Context;
    ZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    Context.Dr0 = Dr0;
    Context.Dr1 = Dr1;
    Context.Dr2 = Dr2;
    Context.Dr3 = Dr3;
    Context.Dr6 = Dr6;
    Context.Dr7 = Dr7;
    return SetThreadContext(Thread, &Context);
}

static void DrCheck(int Line, HANDLE Thread, ULONG_PTR Dr0, ULONG_PTR Dr1, ULONG_PTR Dr2, ULONG_PTR Dr3,
                    ULONG_PTR Dr6, ULONG_PTR Dr7)
{
    CONTEXT Context;
    BOOL Ret;
    memset(&Context, 0xcc, sizeof(Context));
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    Ret = GetThreadContext(Thread, &Context);
    ok(Ret, "line %d: GetThreadContext failed %lu\n", Line, GetLastError());
    ok(Context.Dr0 == Dr0, "line %d: Dr0 %Ix, expected %Ix\n", Line, (ULONG_PTR)Context.Dr0, Dr0);
    ok(Context.Dr1 == Dr1, "line %d: Dr1 %Ix, expected %Ix\n", Line, (ULONG_PTR)Context.Dr1, Dr1);
    ok(Context.Dr2 == Dr2, "line %d: Dr2 %Ix, expected %Ix\n", Line, (ULONG_PTR)Context.Dr2, Dr2);
    ok(Context.Dr3 == Dr3, "line %d: Dr3 %Ix, expected %Ix\n", Line, (ULONG_PTR)Context.Dr3, Dr3);
    ok((Context.Dr6 & 0xe00f) == Dr6, "line %d: Dr6 %Ix, expected %Ix\n", Line, (ULONG_PTR)Context.Dr6, Dr6);
    ok((Context.Dr7 & ~(ULONG_PTR)DR7_IGNORED) == (Dr7 & ~(ULONG_PTR)DR7_IGNORED),
       "line %d: Dr7 %Ix, expected %Ix\n", Line, (ULONG_PTR)Context.Dr7, Dr7);
}

static DWORD WINAPI DrOtherThread(PVOID Param)
{
    CONTEXT Context;
    LONG Before = DrHits;

    /* The creator's breakpoint on DrTarget is not this thread's */
    DrTarget = 10;
    DrOtherHits = DrHits - Before;
    ZeroMemory(&Context, sizeof(Context));
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &Context);
    DrOtherDr7 = Context.Dr7;
    return 0;
}

static DWORD WINAPI DrWaitingThread(PVOID Param)
{
    /* Its breakpoint is set by another thread while it waits */
    WaitForSingleObject(DrGo, 30000);
    DrTarget = 20;
    return 0;
}

#define DR7_WRITE4_DR0 (0x1 | (0x1 << 16) | (0x3 << 18))

static void TestDebugRegisters(void)
{
    HANDLE Self = GetCurrentThread(), Thread;
    PVOID Handler;
    ULONG_PTR Target = (ULONG_PTR)&DrTarget;
    DWORD Wait;
#ifdef _M_AMD64
    SYSTEM_BASIC_INFORMATION Basic;
    ULONG_PTR Highest;
#endif
#ifdef _M_IX86
    BOOL IsWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &IsWow64);
    if (!IsWow64)
    {
        skip("Debug register checks run on x64 and WoW64 only\n");
        return;
    }
#endif

    /* Addresses as given, DR6 cleared, DR7 masked to the local enables, LE/GE and the conditions */
    ok(DrSet(Self, 0x42424240, 0x12340000, 0x10000, 0x7ffe0000, 0xffffffff, 0xffff03ff), "SetThreadContext failed\n");
    DrCheck(__LINE__, Self, 0x42424240, 0x12340000, 0x10000, 0x7ffe0000, 0, 0xffff0355);

    /* No global enables, no general detect */
    ok(DrSet(Self, Target, 0, 0, 0, 0, 0x2000 | 0xaa | 0x1), "SetThreadContext failed\n");
    DrCheck(__LINE__, Self, Target, 0, 0, 0, 0, 0x1);

#ifdef _M_AMD64
    /* Without an enabled breakpoint the thread has no debug state */
    ok(DrSet(Self, 0x1000, 0x2000, 0x3000, 0x4000, 0, 0), "SetThreadContext failed\n");
    DrCheck(__LINE__, Self, 0, 0, 0, 0, 0, 0);
    ok(DrSet(Self, 0x1000, 0x2000, 0x3000, 0x4000, 0, 0x400 | 0xaa | 0x2000), "SetThreadContext failed\n");
    DrCheck(__LINE__, Self, 0, 0, 0, 0, 0, 0);

    /* A breakpoint above the highest user address (0x7ffffffeffff on Windows 10) is not armed:
     * the address is cleared */
    if (!NT_SUCCESS(NtQuerySystemInformation(SystemBasicInformation, &Basic, sizeof(Basic), NULL)))
        Basic.MaximumUserModeAddress = 0x7ffffffeffffULL;
    Highest = Basic.MaximumUserModeAddress;
    ok(DrSet(Self, 0xfffff78000000000ULL, Highest + 1, 0x8000000000000000ULL, Highest, 0, 0x55),
       "SetThreadContext failed\n");
    DrCheck(__LINE__, Self, 0, 0, 0, Highest, 0, 0x55);
    ok(DrSet(Self, Highest + 0x1000, 0xffffffffffffffffULL, 0xffff800000000000ULL, Highest & ~(ULONG_PTR)0xfff, 0, 0x55),
       "SetThreadContext failed\n");
    DrCheck(__LINE__, Self, 0, 0, 0, Highest & ~(ULONG_PTR)0xfff, 0, 0x55);
#endif

    /* The breakpoint fires in this thread, also after it was switched out */
    Handler = AddVectoredExceptionHandler(TRUE, DrHandler);
    ok(Handler != NULL, "AddVectoredExceptionHandler failed\n");
    ok(DrSet(Self, Target, 0, 0, 0, 0, DR7_WRITE4_DR0), "SetThreadContext failed\n");
    DrHits = 0;
    DrHitDr6 = 0;
    DrTarget = 1;
    ok(DrHits == 1, "%ld breakpoint hits, expected 1\n", DrHits);
    ok((DrHitDr6 & 0xf) == 1, "Dr6 %Ix in the exception, expected B0\n", (ULONG_PTR)DrHitDr6);
    Sleep(20);
    SwitchToThread();
    DrTarget = 2;
    ok(DrHits == 2, "%ld breakpoint hits after a switch, expected 2\n", DrHits);

    /* Another thread writing the address does not trap */
    DrOtherDr7 = 0xdead;
    DrOtherHits = -1;
    Thread = CreateThread(NULL, 0, DrOtherThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed %lu\n", GetLastError());
    if (Thread)
    {
        ok_eq_ulong(WaitForSingleObject(Thread, 30000), WAIT_OBJECT_0);
        CloseHandle(Thread);
    }
    ok(DrOtherHits == 0, "%ld breakpoint hits in the other thread, expected 0\n", DrOtherHits);
    ok(DrOtherDr7 == 0, "other thread Dr7 %Ix, expected 0\n", (ULONG_PTR)DrOtherDr7);
    ok(DrHits == 2, "%ld breakpoint hits, expected 2\n", DrHits);

    /* Cleared: no more hits here */
    ok(DrSet(Self, 0, 0, 0, 0, 0, 0), "SetThreadContext failed\n");
    DrTarget = 3;
    ok(DrHits == 2, "%ld breakpoint hits after clearing, expected 2\n", DrHits);

    /* Set by this thread on a waiting, suspended thread */
    DrGo = CreateEventW(NULL, TRUE, FALSE, NULL);
    Thread = CreateThread(NULL, 0, DrWaitingThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed %lu\n", GetLastError());
    if (Thread)
    {
        Sleep(50);
        ok(SuspendThread(Thread) != (DWORD)-1, "SuspendThread failed %lu\n", GetLastError());
        ok(DrSet(Thread, Target, 0, 0, 0, 0, DR7_WRITE4_DR0), "SetThreadContext failed %lu\n", GetLastError());
        DrCheck(__LINE__, Thread, Target, 0, 0, 0, 0, DR7_WRITE4_DR0);
        ResumeThread(Thread);
        SetEvent(DrGo);
        Wait = WaitForSingleObject(Thread, 30000);
        ok_eq_ulong(Wait, WAIT_OBJECT_0);
        CloseHandle(Thread);
        ok(DrHits == 3, "%ld breakpoint hits, expected 3 (one in the waiting thread)\n", DrHits);
    }
    CloseHandle(DrGo);
    DrTarget = 4;
    ok(DrHits == 3, "%ld breakpoint hits, expected 3\n", DrHits);
    RemoveVectoredExceptionHandler(Handler);
}

START_TEST(NtContinue)
{
    DoNtContinue();
#ifdef _M_AMD64
    NtcFixedFlags = TRUE;
    DoNtContinue();
    NtcFixedFlags = FALSE;
#endif
    TestSetThreadContextEFlags();
    TestDebugRegisters();
}
