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

START_TEST(NtContinue)
{
    DoNtContinue();
#ifdef _M_AMD64
    NtcFixedFlags = TRUE;
    DoNtContinue();
    NtcFixedFlags = FALSE;
#endif
    TestSetThreadContextEFlags();
}
