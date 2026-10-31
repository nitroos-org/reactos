/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the bitmap functions of ntdll that the ReactOS headers do not declare as functions:
 *              RtlSetBit, RtlClearBit, RtlCopyBitMap, the *InRange counters, the interlocked bit runs, and
 *              the 64-bit bitmap functions of x64 ntdll (Rtl*BitEx)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef struct { ULONG SizeOfBitMap; PULONG Buffer; } TEST_BITMAP;
typedef struct { ULONG64 SizeOfBitMap; PULONG64 Buffer; } TEST_BITMAP_EX;

typedef VOID (NTAPI *PFN_Bit)(TEST_BITMAP *, ULONG);
typedef VOID (NTAPI *PFN_Copy)(TEST_BITMAP *, TEST_BITMAP *, ULONG);
typedef ULONG (NTAPI *PFN_InRange)(TEST_BITMAP *, ULONG, ULONG);
typedef VOID (NTAPI *PFN_Run)(TEST_BITMAP *, ULONG, ULONG);

typedef VOID (NTAPI *PFN_InitEx)(TEST_BITMAP_EX *, PULONG64, ULONG64);
typedef VOID (NTAPI *PFN_AllEx)(TEST_BITMAP_EX *);
typedef VOID (NTAPI *PFN_BitEx)(TEST_BITMAP_EX *, ULONG64);
typedef VOID (NTAPI *PFN_BitsEx)(TEST_BITMAP_EX *, ULONG64, ULONG64);
typedef BOOLEAN (NTAPI *PFN_TestEx)(TEST_BITMAP_EX *, ULONG64);
typedef BOOLEAN (NTAPI *PFN_AreEx)(TEST_BITMAP_EX *, ULONG64, ULONG64);
typedef ULONG64 (NTAPI *PFN_CountEx)(TEST_BITMAP_EX *);
typedef ULONG64 (NTAPI *PFN_FindEx)(TEST_BITMAP_EX *, ULONG64, ULONG64);

static HMODULE Ntdll;

static void *Get(const char *Name)
{
    void *p = GetProcAddress(Ntdll, Name);

    if (!p)
        ok(!is_reactos(), "%s is not exported by ntdll.dll\n", Name);
    return p;
}

static void Test_Ranges(void)
{
    PFN_Bit pSetBit = Get("RtlSetBit"), pClearBit = Get("RtlClearBit");
    PFN_Copy pCopy = Get("RtlCopyBitMap");
    PFN_InRange pSetCount = Get("RtlNumberOfSetBitsInRange"), pClearCount = Get("RtlNumberOfClearBitsInRange");
    PFN_Run pSetRun = Get("RtlInterlockedSetBitRun"), pClearRun = Get("RtlInterlockedClearBitRun");
    ULONG a[4] = { 0xF0F0F0F0, 0x0000FFFF, 0xAAAAAAAA, 0 }, d[4], b[4] = { 0 };
    TEST_BITMAP A = { 128, a }, D = { 128, d }, S = { 16, a }, B = { 128, b };

    if (pSetBit && pClearBit)
    {
        pSetBit(&B, 5);
        pSetBit(&B, 70);
        pSetBit(&B, 127);
        ok(b[0] == 0x20 && b[2] == 0x40 && b[3] == 0x80000000, "RtlSetBit: %08lx %08lx %08lx %08lx\n", b[0], b[1], b[2], b[3]);
        pClearBit(&B, 5);
        pClearBit(&B, 6);
        ok(b[0] == 0 && b[2] == 0x40, "RtlClearBit: %08lx %08lx %08lx %08lx\n", b[0], b[1], b[2], b[3]);
        pClearBit(&B, 70);
        pClearBit(&B, 127);
    }

    if (pSetCount && pClearCount)
    {
        ok(pSetCount(&A, 0, 32) == 16, "set count (0,32): %lu\n", pSetCount(&A, 0, 32));
        ok(pSetCount(&A, 0, 8) == 4, "set count (0,8): %lu\n", pSetCount(&A, 0, 8));
        ok(pSetCount(&A, 4, 40) == 28, "set count (4,40): %lu\n", pSetCount(&A, 4, 40));
        ok(pSetCount(&A, 0, 128) == 16 + 16 + 16, "set count (0,128): %lu\n", pSetCount(&A, 0, 128));
        ok(pSetCount(&A, 60, 70) == 0xFFFFFFFF, "set count past the end: %lx\n", pSetCount(&A, 60, 70));
        ok(pSetCount(&A, 0, 0) == 0xFFFFFFFF, "set count of nothing: %lx\n", pSetCount(&A, 0, 0));
        ok(pSetCount(&A, 100, 50) == 0xFFFFFFFF, "set count (100,50): %lx\n", pSetCount(&A, 100, 50));
        ok(pClearCount(&A, 0, 32) == 16, "clear count (0,32): %lu\n", pClearCount(&A, 0, 32));
        ok(pClearCount(&A, 4, 40) == 12, "clear count (4,40): %lu\n", pClearCount(&A, 4, 40));
        ok(pClearCount(&A, 60, 70) == 0xFFFFFFFF, "clear count past the end: %lx\n", pClearCount(&A, 60, 70));
        ok(pClearCount(&A, 200, 5) == 0xFFFFFFFF, "clear count beyond the bitmap: %lx\n", pClearCount(&A, 200, 5));
    }

    if (pCopy)
    {
        memset(d, 0, sizeof(d));
        pCopy(&S, &D, 8);
        ok(d[0] == 0x00F0F000 && d[1] == 0 && d[2] == 0, "copy @8: %08lx %08lx %08lx\n", d[0], d[1], d[2]);
        memset(d, 0xff, sizeof(d));
        pCopy(&S, &D, 36);
        ok(d[0] == 0xffffffff && d[1] == 0xffff0f0f && d[2] == 0xffffffff, "copy over ones @36: %08lx %08lx %08lx\n", d[0], d[1], d[2]);
    }

    if (pSetRun && pClearRun)
    {
        memcpy(d, a, sizeof(d));
        pSetRun(&D, 3, 10);
        ok(d[0] == 0xf0f0fff8 && d[1] == 0x0000ffff, "set run (3,10): %08lx %08lx\n", d[0], d[1]);
        pClearRun(&D, 4, 6);
        ok(d[0] == 0xf0f0fc08, "clear run (4,6): %08lx\n", d[0]);
        pSetRun(&D, 30, 40);
        ok(d[0] == 0xf0f0fc08 && d[1] == 0xffffffff && d[2] == 0xaaaaaabf, "set run across words: %08lx %08lx %08lx\n", d[0], d[1], d[2]);
        pClearRun(&D, 120, 8);
        pSetRun(&D, 5, 0);
        ok(d[3] == 0 && d[0] == 0xf0f0fc08, "empty and top runs: %08lx %08lx\n", d[0], d[3]);
        pSetRun(&D, 96, 32);
        ok(d[3] == 0xffffffff, "set whole word: %08lx\n", d[3]);
        pClearRun(&D, 64, 32);
        ok(d[2] == 0 && d[3] == 0xffffffff, "clear whole word: %08lx %08lx\n", d[2], d[3]);
    }
}

#ifdef _WIN64
static void Test_Ex(void)
{
    PFN_InitEx pInit = Get("RtlInitializeBitMapEx");
    PFN_AllEx pClearAll = Get("RtlClearAllBitsEx"), pSetAll = Get("RtlSetAllBitsEx");
    PFN_BitEx pSet = Get("RtlSetBitEx"), pClear = Get("RtlClearBitEx");
    PFN_BitsEx pSetBits = Get("RtlSetBitsEx"), pClearBits = Get("RtlClearBitsEx");
    PFN_TestEx pTest = Get("RtlTestBitEx");
    PFN_AreEx pAreClear = Get("RtlAreBitsClearEx");
    PFN_CountEx pSetCount = Get("RtlNumberOfSetBitsEx"), pClearCount = Get("RtlNumberOfClearBitsEx");
    PFN_FindEx pFindClear = Get("RtlFindClearBitsEx"), pFindSet = Get("RtlFindSetBitsEx");
    PFN_FindEx pFindSetClear = Get("RtlFindSetBitsAndClearEx");
    ULONG64 Buffer[4];
    TEST_BITMAP_EX Bm;

    if (!pInit || !pClearAll || !pSetAll || !pSet || !pClear || !pSetBits || !pClearBits || !pTest ||
        !pAreClear || !pSetCount || !pClearCount || !pFindClear || !pFindSet || !pFindSetClear)
        return;

    memset(Buffer, 0xAA, sizeof(Buffer));
    pInit(&Bm, Buffer, 256);
    ok(Bm.SizeOfBitMap == 256 && Bm.Buffer == Buffer, "RtlInitializeBitMapEx: %I64u %p\n", Bm.SizeOfBitMap, Bm.Buffer);
    ok(Buffer[0] == 0xAAAAAAAAAAAAAAAAULL, "the buffer is not touched by the initialization\n");

    pClearAll(&Bm);
    ok(Buffer[0] == 0 && Buffer[3] == 0, "RtlClearAllBitsEx: %I64x %I64x\n", Buffer[0], Buffer[3]);
    pSet(&Bm, 70);
    ok(Buffer[1] == 0x40, "RtlSetBitEx(70): %I64x\n", Buffer[1]);
    pSet(&Bm, 63);
    pSet(&Bm, 40);
    ok(Buffer[0] == 0x8000010000000000ULL, "RtlSetBitEx(63, 40): %I64x\n", Buffer[0]);
    ok(pTest(&Bm, 70) && pTest(&Bm, 63) && !pTest(&Bm, 71) && !pTest(&Bm, 0), "RtlTestBitEx\n");
    pClear(&Bm, 63);
    pClear(&Bm, 40);
    ok(Buffer[0] == 0 && Buffer[1] == 0x40, "RtlClearBitEx: %I64x %I64x\n", Buffer[0], Buffer[1]);
    pClear(&Bm, 70);

    pSetBits(&Bm, 60, 10);
    ok(Buffer[0] == 0xF000000000000000ULL && Buffer[1] == 0x3F, "RtlSetBitsEx(60,10): %I64x %I64x\n", Buffer[0], Buffer[1]);
    ok(pSetCount(&Bm) == 10, "RtlNumberOfSetBitsEx: %I64u\n", pSetCount(&Bm));
    ok(pClearCount(&Bm) == 246, "RtlNumberOfClearBitsEx: %I64u\n", pClearCount(&Bm));
    ok(pAreClear(&Bm, 0, 60) == TRUE, "RtlAreBitsClearEx(0,60)\n");
    ok(pAreClear(&Bm, 50, 11) == FALSE, "RtlAreBitsClearEx(50,11)\n");
    ok(pAreClear(&Bm, 70, 100) == TRUE, "RtlAreBitsClearEx(70,100)\n");

    ok(pFindClear(&Bm, 5, 0) == 0, "RtlFindClearBitsEx(5,0): %I64u\n", pFindClear(&Bm, 5, 0));
    ok(pFindClear(&Bm, 5, 58) == 70, "RtlFindClearBitsEx(5,58): %I64u\n", pFindClear(&Bm, 5, 58));
    ok(pFindSet(&Bm, 3, 0) == 60, "RtlFindSetBitsEx(3,0): %I64u\n", pFindSet(&Bm, 3, 0));
    ok(pFindSet(&Bm, 11, 0) == 0xFFFFFFFFFFFFFFFFULL, "RtlFindSetBitsEx(11,0): %I64x\n", pFindSet(&Bm, 11, 0));
    ok(pFindSetClear(&Bm, 4, 0) == 60, "RtlFindSetBitsAndClearEx(4,0)\n");
    ok(pSetCount(&Bm) == 6, "set bits after FindSetBitsAndClear: %I64u\n", pSetCount(&Bm));
    pClearBits(&Bm, 64, 6);
    ok(pSetCount(&Bm) == 0 && Buffer[0] == 0 && Buffer[1] == 0, "RtlClearBitsEx: %I64x %I64x\n", Buffer[0], Buffer[1]);
    pSetAll(&Bm);
    ok(pSetCount(&Bm) == 256, "RtlSetAllBitsEx: %I64u\n", pSetCount(&Bm));
    pClearAll(&Bm);

    /* the size is 64-bit: only the first words are touched */
    pInit(&Bm, Buffer, 0x100000100ULL);
    ok(Bm.SizeOfBitMap == 0x100000100ULL, "size above 4G: %I64x\n", Bm.SizeOfBitMap);
    pSet(&Bm, 3);
    ok(pTest(&Bm, 3) && !pTest(&Bm, 4) && Buffer[0] == 8, "bit in a 64-bit sized bitmap: %I64x\n", Buffer[0]);
}

#endif /* _WIN64 */

START_TEST(RtlBitmapRanges)
{
    Ntdll = GetModuleHandleW(L"ntdll.dll");
    Test_Ranges();
#ifdef _WIN64
    Test_Ex();
#endif
}
