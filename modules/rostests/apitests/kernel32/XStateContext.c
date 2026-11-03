/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Extended processor state (CONTEXT_XSTATE) through GetThreadContext, SetThreadContext and the
 *              exception context: the upper halves of the YMM registers make the round trip
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A thread loads known values into the YMM registers and waits in a loop that does not touch them. The test
 * suspends it, reads the AVX state with GetThreadContext, changes it with SetThreadContext and has the thread store
 * its registers after resuming. The same is done for the context a vectored exception handler receives.
 * The expected results were measured on Windows 10 22H2 (x64 and WOW64).
 */

#include "precomp.h"

#define XSC_XSTATE_BIT  0x40UL
#define XSC_AVX         2
#define XSC_MASK_AVX    (1ULL << XSC_AVX)
#define XSC_COMPACTED   (1ULL << 63)

#if defined(_M_AMD64) || defined(__x86_64__)
#define XSC_ARCH        0x100000UL
#define XSC_REGS        16
#define XSC_IP(c)       ((c)->Rip)
#else
#define XSC_ARCH        0x10000UL
#define XSC_REGS        8
#define XSC_IP(c)       ((c)->Eip)
#endif
#define XSC_XSTATE      (XSC_ARCH | XSC_XSTATE_BIT)
#define XSC_ALL         (XSC_ARCH | 0x1fUL | XSC_XSTATE_BIT)

typedef struct _XSC_CHUNK { LONG Offset; ULONG Length; } XSC_CHUNK;
typedef struct _XSC_EX { XSC_CHUNK All; XSC_CHUNK Legacy; XSC_CHUNK XState; } XSC_EX;
typedef struct _XSC_HEADER { ULONG64 Mask; ULONG64 CompactionMask; ULONG64 Reserved[6]; } XSC_HEADER;

typedef DWORD64 (WINAPI *PFN_GetEnabledXStateFeatures)(void);
typedef BOOL (WINAPI *PFN_InitializeContext)(PVOID, DWORD, PCONTEXT *, PDWORD);
typedef BOOL (WINAPI *PFN_InitializeContext2)(PVOID, DWORD, PCONTEXT *, PDWORD, ULONG64);
typedef PVOID (WINAPI *PFN_LocateXStateFeature)(PCONTEXT, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_SetXStateFeaturesMask)(PCONTEXT, DWORD64);
typedef BOOL (WINAPI *PFN_GetXStateFeaturesMask)(PCONTEXT, PDWORD64);
typedef LONG (NTAPI *PFN_NtContextThread)(HANDLE, PCONTEXT);

static PFN_GetEnabledXStateFeatures pGetEnabledXStateFeatures;
static PFN_InitializeContext pInitializeContext;
static PFN_InitializeContext2 pInitializeContext2;
static PFN_LocateXStateFeature pLocateXStateFeature;
static PFN_SetXStateFeaturesMask pSetXStateFeaturesMask;
static PFN_GetXStateFeaturesMask pGetXStateFeaturesMask;
static PFN_NtContextThread pNtGetContextThread, pNtSetContextThread;

static DWORD64 g_Enabled;

#if defined(__x86_64__)
#define XSC_LOAD_YMM \
"vmovdqu 0(%[in]), %%ymm0\n" \
"vmovdqu 32(%[in]), %%ymm1\n" \
"vmovdqu 64(%[in]), %%ymm2\n" \
"vmovdqu 96(%[in]), %%ymm3\n" \
"vmovdqu 128(%[in]), %%ymm4\n" \
"vmovdqu 160(%[in]), %%ymm5\n" \
"vmovdqu 192(%[in]), %%ymm6\n" \
"vmovdqu 224(%[in]), %%ymm7\n" \
"vmovdqu 256(%[in]), %%ymm8\n" \
"vmovdqu 288(%[in]), %%ymm9\n" \
"vmovdqu 320(%[in]), %%ymm10\n" \
"vmovdqu 352(%[in]), %%ymm11\n" \
"vmovdqu 384(%[in]), %%ymm12\n" \
"vmovdqu 416(%[in]), %%ymm13\n" \
"vmovdqu 448(%[in]), %%ymm14\n" \
"vmovdqu 480(%[in]), %%ymm15\n"
#define XSC_STORE_YMM \
"vmovdqu %%ymm0, 0(%[out])\n" \
"vmovdqu %%ymm1, 32(%[out])\n" \
"vmovdqu %%ymm2, 64(%[out])\n" \
"vmovdqu %%ymm3, 96(%[out])\n" \
"vmovdqu %%ymm4, 128(%[out])\n" \
"vmovdqu %%ymm5, 160(%[out])\n" \
"vmovdqu %%ymm6, 192(%[out])\n" \
"vmovdqu %%ymm7, 224(%[out])\n" \
"vmovdqu %%ymm8, 256(%[out])\n" \
"vmovdqu %%ymm9, 288(%[out])\n" \
"vmovdqu %%ymm10, 320(%[out])\n" \
"vmovdqu %%ymm11, 352(%[out])\n" \
"vmovdqu %%ymm12, 384(%[out])\n" \
"vmovdqu %%ymm13, 416(%[out])\n" \
"vmovdqu %%ymm14, 448(%[out])\n" \
"vmovdqu %%ymm15, 480(%[out])\n"
#define XSC_ONES_YMM \
"vpcmpeqd %%ymm0, %%ymm0, %%ymm0\n" \
"vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n" \
"vpcmpeqd %%ymm2, %%ymm2, %%ymm2\n" \
"vpcmpeqd %%ymm3, %%ymm3, %%ymm3\n" \
"vpcmpeqd %%ymm4, %%ymm4, %%ymm4\n" \
"vpcmpeqd %%ymm5, %%ymm5, %%ymm5\n" \
"vpcmpeqd %%ymm6, %%ymm6, %%ymm6\n" \
"vpcmpeqd %%ymm7, %%ymm7, %%ymm7\n" \
"vpcmpeqd %%ymm8, %%ymm8, %%ymm8\n" \
"vpcmpeqd %%ymm9, %%ymm9, %%ymm9\n" \
"vpcmpeqd %%ymm10, %%ymm10, %%ymm10\n" \
"vpcmpeqd %%ymm11, %%ymm11, %%ymm11\n" \
"vpcmpeqd %%ymm12, %%ymm12, %%ymm12\n" \
"vpcmpeqd %%ymm13, %%ymm13, %%ymm13\n" \
"vpcmpeqd %%ymm14, %%ymm14, %%ymm14\n" \
"vpcmpeqd %%ymm15, %%ymm15, %%ymm15\n"
#define XSC_CLOBBER "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
#endif
#if defined(__i386__)
#define XSC_LOAD_YMM \
"vmovdqu 0(%[in]), %%ymm0\n" \
"vmovdqu 32(%[in]), %%ymm1\n" \
"vmovdqu 64(%[in]), %%ymm2\n" \
"vmovdqu 96(%[in]), %%ymm3\n" \
"vmovdqu 128(%[in]), %%ymm4\n" \
"vmovdqu 160(%[in]), %%ymm5\n" \
"vmovdqu 192(%[in]), %%ymm6\n" \
"vmovdqu 224(%[in]), %%ymm7\n"
#define XSC_STORE_YMM \
"vmovdqu %%ymm0, 0(%[out])\n" \
"vmovdqu %%ymm1, 32(%[out])\n" \
"vmovdqu %%ymm2, 64(%[out])\n" \
"vmovdqu %%ymm3, 96(%[out])\n" \
"vmovdqu %%ymm4, 128(%[out])\n" \
"vmovdqu %%ymm5, 160(%[out])\n" \
"vmovdqu %%ymm6, 192(%[out])\n" \
"vmovdqu %%ymm7, 224(%[out])\n"
#define XSC_ONES_YMM \
"vpcmpeqd %%ymm0, %%ymm0, %%ymm0\n" \
"vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n" \
"vpcmpeqd %%ymm2, %%ymm2, %%ymm2\n" \
"vpcmpeqd %%ymm3, %%ymm3, %%ymm3\n" \
"vpcmpeqd %%ymm4, %%ymm4, %%ymm4\n" \
"vpcmpeqd %%ymm5, %%ymm5, %%ymm5\n" \
"vpcmpeqd %%ymm6, %%ymm6, %%ymm6\n" \
"vpcmpeqd %%ymm7, %%ymm7, %%ymm7\n"
#define XSC_CLOBBER "cc" /* no SSE code generation on i386: the compiler does not use these registers */
#endif


#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#define XSC_HAVE_ASM 1

static volatile LONG g_Ready, g_Go;
static BYTE g_In[XSC_REGS][32] __attribute__((aligned(32)));
static BYTE g_Out[XSC_REGS][32] __attribute__((aligned(32)));

/* Mode 0: wait for g_Go; mode 1: vzeroupper first, then wait; mode 2: ud2 instead of waiting */
static DWORD WINAPI AvxThread(LPVOID Param)
{
    LONG Mode = (LONG)(LONG_PTR)Param;

    if (Mode == 2)
    {
        __asm__ __volatile__(
            XSC_LOAD_YMM
            "ud2\n"
            XSC_STORE_YMM
            "vzeroupper\n"
            : : [in] "r" (g_In), [out] "r" (g_Out) : "memory", XSC_CLOBBER);
        return 0;
    }
    __asm__ __volatile__(
        XSC_LOAD_YMM
        "testl %[mode], %[mode]\n"
        "jz 2f\n"
        "vzeroupper\n"
        "2:\n"
        "movl $1, %[ready]\n"
        "1:\n"
        "pause\n"
        "cmpl $0, %[go]\n"
        "je 1b\n"
        XSC_STORE_YMM
        "vzeroupper\n"
        : [ready] "=m" (g_Ready)
        : [in] "r" (g_In), [out] "r" (g_Out), [mode] "r" (Mode), [go] "m" (g_Go)
        : "memory", XSC_CLOBBER);
    return 0;
}

static void FillPattern(BYTE Seed)
{
    ULONG r, b;
    for (r = 0; r < XSC_REGS; r++)
        for (b = 0; b < 32; b++)
            g_In[r][b] = (BYTE)(Seed + r * 32 + b);
    memset(g_Out, 0, sizeof(g_Out));
}

/* The AVX feature holds the upper 16 bytes of each YMM register */
static BOOL UppersEqual(const BYTE *Avx, BYTE Xor)
{
    ULONG r, b;
    for (r = 0; r < XSC_REGS; r++)
        for (b = 0; b < 16; b++)
            if (Avx[r * 16 + b] != (BYTE)(g_In[r][16 + b] ^ Xor))
                return FALSE;
    return TRUE;
}

static BOOL OutUppers(BYTE Xor, BOOL Zero)
{
    ULONG r, b;
    for (r = 0; r < XSC_REGS; r++)
        for (b = 16; b < 32; b++)
            if (g_Out[r][b] != (Zero ? 0 : (BYTE)(g_In[r][b] ^ Xor)))
                return FALSE;
    return TRUE;
}

static BOOL OutLowers(void)
{
    ULONG r;
    for (r = 0; r < XSC_REGS; r++)
        if (memcmp(g_Out[r], g_In[r], 16))
            return FALSE;
    return TRUE;
}

static HANDLE StartWaiter(LONG Mode)
{
    HANDLE Thread;
    g_Ready = g_Go = 0;
    Thread = CreateThread(NULL, 0, AvxThread, (LPVOID)(LONG_PTR)Mode, 0, NULL);
    ok(Thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    if (!Thread)
        return NULL;
    while (!g_Ready)
        Sleep(1);
    Sleep(20);
    ok(SuspendThread(Thread) == 0, "SuspendThread failed\n");
    return Thread;
}

static void FinishWaiter(HANDLE Thread)
{
    g_Go = 1;
    ok(ResumeThread(Thread) == 1, "ResumeThread failed\n");
    ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "thread did not finish\n");
    CloseHandle(Thread);
}

static PCONTEXT AllocContext(DWORD Flags, ULONG64 Compaction, PVOID *Base, DWORD *Length)
{
    PCONTEXT Context = NULL;
    BOOL Result;

    *Length = 0;
    if (Compaction != ~0ULL && pInitializeContext2)
        Result = pInitializeContext2(NULL, Flags, NULL, Length, Compaction);
    else
        Result = pInitializeContext(NULL, Flags, NULL, Length);
    ok(!Result && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "sizing call: %d, %lu\n", Result, GetLastError());
    /* Slack after the context for the malformed CONTEXT_EX cases */
    *Base = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *Length + 4096);
    if (!*Base)
        return NULL;
    if (Compaction != ~0ULL && pInitializeContext2)
        Result = pInitializeContext2(*Base, Flags, &Context, Length, Compaction);
    else
        Result = pInitializeContext(*Base, Flags, &Context, Length);
    ok(Result, "InitializeContext failed with %lu\n", GetLastError());
    return Result ? Context : NULL;
}

static XSC_HEADER *HeaderOf(PCONTEXT Context)
{
    XSC_EX *Ex = (XSC_EX *)(Context + 1);
    return (XSC_HEADER *)((PBYTE)Ex + Ex->XState.Offset);
}

/* Read the AVX state of a suspended thread, write it back changed, check what the thread sees */
static void TestGetSet(ULONG64 Compaction)
{
    PVOID Base;
    DWORD Length, AvxLength = 0;
    DWORD64 Mask = 0;
    PCONTEXT Context;
    HANDLE Thread;
    PBYTE Avx;
    ULONG i;

    FillPattern(0x11);
    Thread = StartWaiter(0);
    if (!Thread)
        return;
    Context = AllocContext(XSC_ALL, Compaction, &Base, &Length);
    if (!Context)
    {
        FinishWaiter(Thread);
        return;
    }
    trace("compaction 0x%I64x: length %lu, XState %ld/%lu, header mask 0x%I64x compaction 0x%I64x\n", Compaction,
          Length, ((XSC_EX *)(Context + 1))->XState.Offset, ((XSC_EX *)(Context + 1))->XState.Length,
          HeaderOf(Context)->Mask, HeaderOf(Context)->CompactionMask);

    ok(pSetXStateFeaturesMask(Context, XSC_MASK_AVX), "SetXStateFeaturesMask failed\n");
    ok(GetThreadContext(Thread, Context), "GetThreadContext failed with %lu\n", GetLastError());
    ok(Context->ContextFlags == XSC_ALL, "ContextFlags 0x%lx\n", Context->ContextFlags);
    ok(pGetXStateFeaturesMask(Context, &Mask), "GetXStateFeaturesMask failed\n");
    ok(Mask & XSC_MASK_AVX, "AVX not in the returned mask 0x%I64x\n", Mask);
    trace("after get: header mask 0x%I64x compaction 0x%I64x\n", HeaderOf(Context)->Mask, HeaderOf(Context)->CompactionMask);
    Avx = pLocateXStateFeature(Context, XSC_AVX, &AvxLength);
    ok(Avx != NULL && AvxLength == 256, "LocateXStateFeature: %p, %lu\n", Avx, AvxLength);
    if (Avx)
    {
        ok(UppersEqual(Avx, 0), "the YMM upper halves read do not match what the thread loaded\n");
        for (i = 0; i < XSC_REGS * 16; i++)
            Avx[i] ^= 0xA5;
    }
#if defined(__x86_64__)
    ok(!memcmp(&Context->Xmm0, g_In[0], 16) && !memcmp(&Context->Xmm15, g_In[15], 16), "XMM registers do not match\n");
#endif
    ok(SetThreadContext(Thread, Context), "SetThreadContext failed with %lu\n", GetLastError());
    FinishWaiter(Thread);
    ok(OutLowers(), "the XMM registers changed\n");
    ok(OutUppers(0xA5, FALSE), "the YMM upper halves were not set: %02x %02x expected %02x\n",
       g_Out[0][16], g_Out[XSC_REGS - 1][31], (BYTE)(g_In[0][16] ^ 0xA5));
    HeapFree(GetProcessHeap(), 0, Base);
}

/* What the mask says for the AVX state in its initial configuration, and what a set without the AVX bit does */
static void TestMasks(void)
{
    PVOID Base;
    DWORD Length;
    DWORD64 Mask;
    PCONTEXT Context;
    HANDLE Thread;

    /* Upper halves zero (vzeroupper): the feature is in its initial state */
    FillPattern(0x22);
    Thread = StartWaiter(1);
    if (!Thread)
        return;
    Context = AllocContext(XSC_ALL, ~0ULL, &Base, &Length);
    if (Context)
    {
        pSetXStateFeaturesMask(Context, XSC_MASK_AVX);
        ok(GetThreadContext(Thread, Context), "GetThreadContext failed with %lu\n", GetLastError());
        Mask = 0xdead;
        pGetXStateFeaturesMask(Context, &Mask);
        ok((Mask & XSC_MASK_AVX) == 0, "AVX in its initial state is in the mask 0x%I64x\n", Mask);
        HeapFree(GetProcessHeap(), 0, Base);
    }
    FinishWaiter(Thread);
    ok(OutUppers(0, TRUE), "upper halves not zero\n");

    /* Requested mask 0: is the AVX state still returned? */
    FillPattern(0x33);
    Thread = StartWaiter(0);
    if (!Thread)
        return;
    Context = AllocContext(XSC_ALL, ~0ULL, &Base, &Length);
    if (Context)
    {
        PBYTE Avx;
        DWORD AvxLength = 0;
        pSetXStateFeaturesMask(Context, 0);
        ok(GetThreadContext(Thread, Context), "GetThreadContext failed with %lu\n", GetLastError());
        Mask = 0xdead;
        pGetXStateFeaturesMask(Context, &Mask);
        Avx = pLocateXStateFeature(Context, XSC_AVX, &AvxLength);
        /* The mask is not a request: every feature the chunk has room for comes back */
        ok(Mask & XSC_MASK_AVX, "AVX not returned for an empty mask, mask 0x%I64x\n", Mask);
        ok(Avx != NULL && UppersEqual(Avx, 0), "the AVX state was not returned for an empty mask\n");

        /* Set with the XSTATE flag and an empty mask: the AVX state goes to its initial configuration */
        pSetXStateFeaturesMask(Context, 0);
        ok(SetThreadContext(Thread, Context), "SetThreadContext failed with %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, Base);
    }
    FinishWaiter(Thread);
    ok(OutUppers(0, TRUE), "the upper halves are not in the initial state after a set with mask 0\n");
    ok(OutLowers(), "the XMM registers changed\n");
}

/*
 * Malformed CONTEXT_EX descriptions. The kernel reads them from the caller, so it has to check them and must never
 * touch memory outside of the chunk described. The statuses are the ones of ReactOS (not measured on Windows); in
 * every case the thread has to keep its state.
 */
#define XSC_REGION      0x10000
#define XSC_COMMITTED   0x4000
#define XSC_TO_RESERVED 0x7ffffff0
#define XSC_TO_EDGE     0x7ffffff1
#define XSC_SAME        1
#define XSC_OVERFLOW    ((LONG)0x80000005 /* STATUS_BUFFER_OVERFLOW */)

static void TestMalformed(void)
{
    static const struct
    {
        const char *Name;
        LONG Offset;            /* replaces XState.Offset when Absolute, else is added to it */
        BOOL Absolute;
        ULONG Length;           /* replaces XState.Length when not 0 */
        LONG Status;            /* expected from ReactOS, for the get and the set */
        LONG GetStatus;         /* for the get when it differs (XSC_SAME: it does not). A chunk too short for the
                                   features asked for answers STATUS_BUFFER_OVERFLOW after the masks are written */
    } Cases[] =
    {
        { "length 1",           0, FALSE, 1,          (LONG)0xC000000D /* STATUS_INVALID_PARAMETER */, XSC_SAME },
        { "length 63",          0, FALSE, 63,         (LONG)0xC000000D, XSC_SAME },
        { "length 64",          0, FALSE, 64,         0, XSC_OVERFLOW },
        { "length 64+255",      0, FALSE, 64 + 255,   0, XSC_OVERFLOW },
        { "length 0x7fffffff",  0, FALSE, 0x7fffffff, (LONG)0xC000000D, XSC_SAME },
        { "offset 0",           0, TRUE,  0,          (LONG)0xC000000D, XSC_SAME },
        { "offset 23",          23, TRUE, 0,          (LONG)0xC000000D, XSC_SAME },
        { "offset -0x100",      -0x100, TRUE, 0,      (LONG)0xC000000D, XSC_SAME },
        { "offset +8",          8, FALSE, 0,          0, XSC_SAME },
        { "offset reserved",    XSC_TO_RESERVED, TRUE, 0, (LONG)0xC0000005 /* STATUS_ACCESS_VIOLATION */, XSC_SAME },
        { "chunk crosses",      XSC_TO_EDGE, TRUE, 0, (LONG)0xC0000005, XSC_SAME },
    };
    PBYTE Region;
    DWORD Length = 0;
    PCONTEXT Context = NULL;
    XSC_EX *Ex, Saved;
    XSC_HEADER *SavedHeader;
    ULONG64 Compaction;
    HANDLE Thread;
    ULONG i;
    LONG Status;
    PBYTE Avx;
    DWORD AvxLength;

    if (!pNtGetContextThread || !pNtSetContextThread)
        return;

    /* The context in committed memory with reserved memory behind it, for the chunks that point outside */
    Region = VirtualAlloc(NULL, XSC_REGION, MEM_RESERVE, PAGE_READWRITE);
    ok(Region != NULL, "VirtualAlloc failed with %lu\n", GetLastError());
    if (!Region || !VirtualAlloc(Region, XSC_COMMITTED, MEM_COMMIT, PAGE_READWRITE))
        return;
    pInitializeContext(NULL, XSC_ALL, NULL, &Length);
    if (Length > XSC_COMMITTED / 2 || !pInitializeContext(Region, XSC_ALL, &Context, &Length))
    {
        ok(0, "InitializeContext failed, length %lu\n", Length);
        VirtualFree(Region, 0, MEM_RELEASE);
        return;
    }

    FillPattern(0x44);
    Thread = StartWaiter(0);
    if (!Thread)
    {
        VirtualFree(Region, 0, MEM_RELEASE);
        return;
    }
    Ex = (XSC_EX *)(Context + 1);
    Saved = *Ex;
    SavedHeader = HeaderOf(Context);
    Compaction = SavedHeader->CompactionMask;

    for (i = 0; i < sizeof(Cases) / sizeof(Cases[0]); i++)
    {
        LONG GetStatus, SetStatus;
        *Ex = Saved;
        memset(SavedHeader, 0, sizeof(*SavedHeader));
        SavedHeader->CompactionMask = Compaction;
        if (Cases[i].Offset == XSC_TO_RESERVED)
            Ex->XState.Offset = (LONG)(Region + XSC_COMMITTED + 0x1000 - (PBYTE)Ex);
        else if (Cases[i].Offset == XSC_TO_EDGE)
            Ex->XState.Offset = (LONG)(Region + XSC_COMMITTED - sizeof(XSC_HEADER) - (PBYTE)Ex);
        else
            Ex->XState.Offset = Cases[i].Absolute ? Cases[i].Offset : Ex->XState.Offset + Cases[i].Offset;
        if (Cases[i].Length)
            Ex->XState.Length = Cases[i].Length;
        /* The moved header (inside of the committed memory) gets the masks too */
        if (Ex->XState.Offset >= (LONG)sizeof(XSC_EX) &&
            (PBYTE)HeaderOf(Context) + sizeof(XSC_HEADER) <= Region + XSC_COMMITTED)
        {
            memset(HeaderOf(Context), 0, sizeof(XSC_HEADER));
            HeaderOf(Context)->CompactionMask = Compaction;
        }
        Context->ContextFlags = XSC_ALL;
        GetStatus = pNtGetContextThread(Thread, Context);
        /* A set with the result of the get: the AVX state, if it was read, is the thread's own */
        Context->ContextFlags = XSC_XSTATE;
        SetStatus = pNtSetContextThread(Thread, Context);
        trace("malformed %-18s: get 0x%08lx set 0x%08lx\n", Cases[i].Name, GetStatus, SetStatus);
        if (is_reactos())
        {
            ok(GetStatus == (Cases[i].GetStatus == XSC_SAME ? Cases[i].Status : Cases[i].GetStatus),
               "%s: get returned 0x%08lx\n", Cases[i].Name, GetStatus);
            ok(SetStatus == Cases[i].Status, "%s: set returned 0x%08lx\n", Cases[i].Name, SetStatus);
        }
    }

    /* A CONTEXT_EX that does not describe the CONTEXT in front of it (CONTEXT_XSTATE left in the flags of a context
       that has none, say) must be refused before anything is read through it. Not run on Windows. */
    if (is_reactos())
    {
        static const struct { const char *Name; int Field; LONG Value; } Fields[] =
        {
            { "legacy offset 0",     0, 0 },
            { "legacy offset +8",    0, 8 },
            { "legacy length 0",     1, 0 },
            { "legacy length +4",    1, (LONG)(sizeof(CONTEXT) + 4) },
            { "legacy length -4",    1, (LONG)(sizeof(CONTEXT) - 4) },
            { "legacy length big",   1, 0x7fffffff },
            { "all offset 0",        2, 0 },
            { "all offset -8",       2, -(LONG)sizeof(CONTEXT) - 8 },
            { "all length 0",        3, 0 },
            { "all length small",    3, (LONG)(sizeof(CONTEXT) + sizeof(XSC_EX) - 1) },
        };
        for (i = 0; i < sizeof(Fields) / sizeof(Fields[0]); i++)
        {
            LONG GetStatus, SetStatus;
            *Ex = Saved;
            memset(SavedHeader, 0, sizeof(*SavedHeader));
            SavedHeader->CompactionMask = Compaction;
            switch (Fields[i].Field)
            {
                case 0: Ex->Legacy.Offset = Fields[i].Value; break;
                case 1: Ex->Legacy.Length = (ULONG)Fields[i].Value; break;
                case 2: Ex->All.Offset = Fields[i].Value; break;
                default: Ex->All.Length = (ULONG)Fields[i].Value; break;
            }
            Context->ContextFlags = XSC_ALL;
            GetStatus = pNtGetContextThread(Thread, Context);
            Context->ContextFlags = XSC_XSTATE;
            SetStatus = pNtSetContextThread(Thread, Context);
            ok(GetStatus == (LONG)0xC000000D, "%s: get returned 0x%08lx\n", Fields[i].Name, GetStatus);
            ok(SetStatus == (LONG)0xC000000D, "%s: set returned 0x%08lx\n", Fields[i].Name, SetStatus);
        }
        *Ex = Saved;
    }

    /* Header masks the caller makes up. Bits of features that are not enabled, the legacy bits and a wrong
       compaction mask must not reach the processor (an XRSTOR fault in the kernel). Not run on Windows. */
    if (is_reactos())
    {
        static const struct { const char *Name; ULONG64 Mask; ULONG64 CompactionXor; } Headers[] =
        {
            { "mask bit 9",              XSC_MASK_AVX | (1ULL << 9), 0 },
            { "mask bit 62",             XSC_MASK_AVX | (1ULL << 62), 0 },
            { "mask bits 0-1",           XSC_MASK_AVX | 3, 0 },
            { "all mask bits",           ~0ULL, 0 },
            { "compaction bit 63",       XSC_MASK_AVX, XSC_COMPACTED },
            { "compaction AVX bit",      XSC_MASK_AVX, XSC_MASK_AVX },
            { "compaction all bits",     XSC_MASK_AVX, ~0ULL },
        };
        *Ex = Saved;
        for (i = 0; i < sizeof(Headers) / sizeof(Headers[0]); i++)
        {
            memset(SavedHeader, 0, sizeof(*SavedHeader));
            SavedHeader->CompactionMask = Compaction;
            Context->ContextFlags = XSC_ALL;
            Status = pNtGetContextThread(Thread, Context);
            ok(Status == 0, "get 0x%08lx\n", Status);
            SavedHeader->Mask = Headers[i].Mask;
            SavedHeader->CompactionMask = Compaction ^ Headers[i].CompactionXor;
            Context->ContextFlags = XSC_XSTATE;
            Status = pNtSetContextThread(Thread, Context);
            ok(Status == 0, "set %s returned 0x%08lx\n", Headers[i].Name, Status);
        }
    }

    /* Put the thread's state back, the thread checks it */
    *Ex = Saved;
    memset(SavedHeader, 0, sizeof(*SavedHeader));
    SavedHeader->CompactionMask = Compaction;
    Context->ContextFlags = XSC_ALL;
    Status = pNtGetContextThread(Thread, Context);
    ok(Status == 0, "get 0x%08lx\n", Status);
    Avx = pLocateXStateFeature(Context, XSC_AVX, &AvxLength);
    ok(Avx != NULL, "no AVX state\n");
    if (Avx)
    {
        ULONG r;
        for (r = 0; r < XSC_REGS; r++)
            memcpy(Avx + r * 16, g_In[r] + 16, 16);
    }
    pSetXStateFeaturesMask(Context, XSC_MASK_AVX);
    Context->ContextFlags = XSC_XSTATE;
    Status = pNtSetContextThread(Thread, Context);
    ok(Status == 0, "set 0x%08lx\n", Status);
    FinishWaiter(Thread);
    ok(OutLowers(), "the XMM registers changed\n");
    ok(OutUppers(0, FALSE), "the YMM upper halves were not restored\n");
    VirtualFree(Region, 0, MEM_RELEASE);
}

static DWORD g_VehThreadId;
static volatile LONG g_VehCalls;
static DWORD g_VehFlags;
static DWORD64 g_VehMask;
static DWORD g_VehAvxLength;
static BOOL g_VehAvxOk, g_VehModify, g_VehClobber, g_VehRestore;
typedef VOID (NTAPI *PFN_RtlRestoreContext)(PCONTEXT, PEXCEPTION_RECORD);
static PFN_RtlRestoreContext pRtlRestoreContext;

static LONG CALLBACK XStateVeh(EXCEPTION_POINTERS *Pointers)
{
    PCONTEXT Context = Pointers->ContextRecord;
    PBYTE Avx;
    ULONG i;

    if (Pointers->ExceptionRecord->ExceptionCode != (DWORD)0xC000001D /* STATUS_ILLEGAL_INSTRUCTION */ ||
        GetCurrentThreadId() != g_VehThreadId)
        return EXCEPTION_CONTINUE_SEARCH;

    g_VehCalls++;
    g_VehFlags = Context->ContextFlags;
    g_VehMask = 0;
    g_VehAvxLength = 0;
    g_VehAvxOk = FALSE;
    if ((Context->ContextFlags & XSC_XSTATE) == XSC_XSTATE)
    {
        pGetXStateFeaturesMask(Context, &g_VehMask);
        Avx = pLocateXStateFeature(Context, XSC_AVX, &g_VehAvxLength);
        if (Avx)
        {
            g_VehAvxOk = UppersEqual(Avx, 0);
            if (g_VehModify)
            {
                for (i = 0; i < XSC_REGS * 16; i++)
                    Avx[i] ^= 0x5A;
                pSetXStateFeaturesMask(Context, g_VehMask | XSC_MASK_AVX);
            }
        }
    }
    if (g_VehClobber)
        __asm__ __volatile__(XSC_ONES_YMM : : : XSC_CLOBBER);
    XSC_IP(Context) += 2;
    /* Resume like the C++ and managed runtimes do, without returning to the dispatcher */
    if (g_VehRestore && pRtlRestoreContext)
        pRtlRestoreContext(Context, NULL);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void RunVeh(BOOL Modify, BOOL Clobber, BOOL Restore)
{
    HANDLE Thread;
    PVOID Handler;

    FillPattern(Modify ? 0x55 : 0x66);
    g_VehModify = Modify;
    g_VehClobber = Clobber;
    g_VehRestore = Restore;
    g_VehCalls = 0;
    Handler = AddVectoredExceptionHandler(1, XStateVeh);
    ok(Handler != NULL, "AddVectoredExceptionHandler failed\n");
    Thread = CreateThread(NULL, 0, AvxThread, (LPVOID)2, CREATE_SUSPENDED, &g_VehThreadId);
    ok(Thread != NULL, "CreateThread failed\n");
    if (Thread)
    {
        ResumeThread(Thread);
        ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "thread did not finish\n");
        CloseHandle(Thread);
    }
    RemoveVectoredExceptionHandler(Handler);
    trace("VEH modify=%d clobber=%d restore=%d: calls %ld flags 0x%lx mask 0x%I64x avxlen %lu avx-matches %d; after: uppers %s, lowers %s\n",
          Modify, Clobber, Restore, g_VehCalls, g_VehFlags, g_VehMask, g_VehAvxLength, g_VehAvxOk,
          OutUppers(0x5A, FALSE) ? "modified" : OutUppers(0, FALSE) ? "original" : OutUppers(0xff ^ 0xff, TRUE) ? "zero" : "other",
          OutLowers() ? "ok" : "changed");
    ok(g_VehCalls == 1, "VEH called %ld times\n", g_VehCalls);
    ok((g_VehFlags & XSC_XSTATE) == XSC_XSTATE, "no CONTEXT_XSTATE in the exception context, flags 0x%lx\n", g_VehFlags);
    ok(g_VehMask & XSC_MASK_AVX, "AVX not in the exception context's mask 0x%I64x\n", g_VehMask);
    ok(g_VehAvxLength == 256 && g_VehAvxOk, "the exception context's AVX state does not match (length %lu)\n", g_VehAvxLength);
    ok(OutLowers(), "the XMM registers changed\n");
    if (Modify)
        ok(OutUppers(0x5A, FALSE), "the changes to the AVX state in the exception context were not applied\n");
    else
        ok(OutUppers(0, FALSE), "the AVX state was not restored from the exception context\n");
}

static void TestException(void)
{
    RunVeh(TRUE, TRUE, FALSE);
    RunVeh(FALSE, TRUE, FALSE);
    pRtlRestoreContext = (PFN_RtlRestoreContext)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlRestoreContext");
    if (pRtlRestoreContext)
    {
        RunVeh(TRUE, TRUE, TRUE);
        RunVeh(FALSE, TRUE, TRUE);
    }
}

/*
 * An exception raised close to the end of the stack. The frame with the extended state is a few KB larger than the
 * one without it; when only that part does not fit, the exception has to be dispatched without it, not turned into
 * a stack overflow. A thread recurses until it is Distance bytes above the end of its stack and raises there. Close
 * to the end the results are with the extended state, then (in a window of a few KB) without it, then stack overflow;
 * a few distances in between may overflow because of where the guard page is.
 */
#define XSC_DEEP_NONE     0
#define XSC_DEEP_XSTATE   1
#define XSC_DEEP_PLAIN    2
#define XSC_DEEP_OVERFLOW 3

typedef LONG (NTAPI *PFN_NtTerminateThread)(HANDLE, LONG);
static PFN_NtTerminateThread pNtTerminateThread;
static volatile LONG g_DeepResult;
static DWORD g_DeepThreadId;

static LONG CALLBACK DeepVeh(EXCEPTION_POINTERS *Pointers)
{
    if (GetCurrentThreadId() != g_DeepThreadId)
        return EXCEPTION_CONTINUE_SEARCH;
    if (Pointers->ExceptionRecord->ExceptionCode == (DWORD)0xC00000FD /* STATUS_STACK_OVERFLOW */)
    {
        g_DeepResult = XSC_DEEP_OVERFLOW;
        pNtTerminateThread((HANDLE)(LONG_PTR)-2, 0);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (Pointers->ExceptionRecord->ExceptionCode != (DWORD)0xC000001D)
        return EXCEPTION_CONTINUE_SEARCH;
    g_DeepResult = ((Pointers->ContextRecord->ContextFlags & XSC_XSTATE) == XSC_XSTATE) ?
                   XSC_DEEP_XSTATE : XSC_DEEP_PLAIN;
    XSC_IP(Pointers->ContextRecord) += 2;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void __attribute__((noinline)) DeepRecurse(PBYTE Base, SIZE_T Distance)
{
    volatile BYTE Pad[256];
    Pad[0] = 1;
    Pad[255] = 2;
    if ((SIZE_T)((PBYTE)Pad - Base) > Distance + sizeof(Pad))
        DeepRecurse(Base, Distance);
    else
        __asm__ __volatile__("ud2");
    Pad[1] = Pad[0];
}

static DWORD WINAPI DeepThread(PVOID Parameter)
{
    MEMORY_BASIC_INFORMATION Info;
    BYTE Local;

    g_DeepThreadId = GetCurrentThreadId();
    if (!VirtualQuery(&Local, &Info, sizeof(Info)))
        return 1;
    DeepRecurse((PBYTE)Info.AllocationBase, (SIZE_T)Parameter);
    return 0;
}

static void TestStackEnd(void)
{
    LONG Sequence[200];
    ULONG Count = 0, i, Xs = 0, Plain = 0, Over = 0;
    SIZE_T Distance;
    PVOID Handler;
    LONG LastXs = -1, FirstPlain = -1;

    pNtTerminateThread = (PFN_NtTerminateThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateThread");
#if !defined(__x86_64__)
    /* The WOW64 guest has its own frames and does not survive a stack overflow in the handler */
    skip("the stack end is tested on amd64 only\n");
    return;
#endif
    if (!is_reactos() || !pNtTerminateThread)
    {
        skip("the frame sizes of the stack end are ReactOS specific\n");
        return;
    }
    Handler = AddVectoredExceptionHandler(1, DeepVeh);
    ok(Handler != NULL, "AddVectoredExceptionHandler failed\n");
    for (Distance = 0x5000; Distance >= 0x400 && Count < 200; Distance -= 0x80)
    {
        HANDLE Thread;
        g_DeepResult = XSC_DEEP_NONE;
        Thread = CreateThread(NULL, 0x20000, DeepThread, (PVOID)Distance, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
        if (!Thread)
            break;
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
        Sequence[Count++] = g_DeepResult;
    }
    RemoveVectoredExceptionHandler(Handler);

    for (i = 0; i < Count; i++)
    {
        trace("stack end, distance 0x%lx: %ld\n", (ULONG)(0x5000 - i * 0x80), Sequence[i]);
        if (Sequence[i] == XSC_DEEP_XSTATE) { Xs++; LastXs = i; }
        else if (Sequence[i] == XSC_DEEP_PLAIN) { Plain++; if (FirstPlain < 0) FirstPlain = i; }
        else Over++;
    }
    trace("stack end: %lu with the extended state, %lu without, %lu overflow or none\n", Xs, Plain, Over);
    ok(Xs != 0, "no exception had room for the extended state\n");
    ok(FirstPlain < 0 || LastXs < FirstPlain, "a frame with the extended state was dispatched after one without it\n");
    ok(Plain != 0, "an exception whose frame fits without the extended state was not dispatched\n");
}
#endif /* __GNUC__ */

static void TestConfiguration(void)
{
    DWORD Length = 0;
    BOOL Result;

    Result = pInitializeContext(NULL, XSC_ALL, NULL, &Length);
    ok(!Result && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "sizing call: %d, %lu\n", Result, GetLastError());
    trace("enabled features 0x%I64x, context with extended state %lu bytes\n", g_Enabled, Length);
}

START_TEST(XStateContext)
{
    HMODULE Kernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");

    pGetEnabledXStateFeatures = (PFN_GetEnabledXStateFeatures)GetProcAddress(Kernel32, "GetEnabledXStateFeatures");
    pInitializeContext = (PFN_InitializeContext)GetProcAddress(Kernel32, "InitializeContext");
    pInitializeContext2 = (PFN_InitializeContext2)GetProcAddress(Kernel32, "InitializeContext2");
    pLocateXStateFeature = (PFN_LocateXStateFeature)GetProcAddress(Kernel32, "LocateXStateFeature");
    pSetXStateFeaturesMask = (PFN_SetXStateFeaturesMask)GetProcAddress(Kernel32, "SetXStateFeaturesMask");
    pGetXStateFeaturesMask = (PFN_GetXStateFeaturesMask)GetProcAddress(Kernel32, "GetXStateFeaturesMask");
    pNtGetContextThread = (PFN_NtContextThread)GetProcAddress(Ntdll, "NtGetContextThread");
    pNtSetContextThread = (PFN_NtContextThread)GetProcAddress(Ntdll, "NtSetContextThread");

    if (!pGetEnabledXStateFeatures || !pInitializeContext || !pLocateXStateFeature ||
        !pSetXStateFeaturesMask || !pGetXStateFeaturesMask)
    {
        skip("the XState functions are missing\n");
        return;
    }
    g_Enabled = pGetEnabledXStateFeatures();
    TestConfiguration();
    if (!(g_Enabled & XSC_MASK_AVX))
    {
        skip("AVX is not enabled (features 0x%I64x)\n", g_Enabled);
        return;
    }
#ifdef XSC_HAVE_ASM
    TestGetSet(~0ULL);
    if (pInitializeContext2)
        TestGetSet(XSC_MASK_AVX);
    else
        skip("no InitializeContext2\n");
    TestMasks();
    if (is_reactos())
        TestMalformed();
    else
        skip("malformed CONTEXT_EX descriptions are not probed on Windows\n");
    TestException();
    TestStackEnd();
#else
    skip("needs GCC inline assembly\n");
#endif
}
