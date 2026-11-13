/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The decommit thresholds of a heap (RTL_HEAP_PARAMETERS, PEB HeapDeCommit* fields): free pages
 *              stay committed while the heap holds less free memory than its total threshold allows, and a heap
 *              that did not have to grow for a second gives the surplus back
 */

#include "precomp.h"

#define BLOCK_SIZE (128 * 1024)

/* pages of [Start, Start + Size) that are committed, looked at page by page */
static SIZE_T
CommittedPages(PVOID Start, SIZE_T Size)
{
    PUCHAR Cur = (PUCHAR)(((ULONG_PTR)Start + PAGE_SIZE - 1) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    PUCHAR End = (PUCHAR)(((ULONG_PTR)Start + Size) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    SIZE_T Count = 0;
    MEMORY_BASIC_INFORMATION Mbi;

    for (; Cur < End; Cur += PAGE_SIZE)
    {
        if (VirtualQuery(Cur, &Mbi, sizeof(Mbi)) && Mbi.State == MEM_COMMIT)
            Count++;
    }
    return Count;
}

static SIZE_T
BlockPages(PVOID Start, SIZE_T Size)
{
    PUCHAR Cur = (PUCHAR)(((ULONG_PTR)Start + PAGE_SIZE - 1) & ~(ULONG_PTR)(PAGE_SIZE - 1));
    PUCHAR End = (PUCHAR)(((ULONG_PTR)Start + Size) & ~(ULONG_PTR)(PAGE_SIZE - 1));

    return Cur < End ? (End - Cur) / PAGE_SIZE : 0;
}

static HANDLE
CreateTestHeap(SIZE_T TotalFreeThreshold)
{
    RTL_HEAP_PARAMETERS Params;

    RtlZeroMemory(&Params, sizeof(Params));
    Params.Length = sizeof(Params);
    Params.DeCommitFreeBlockThreshold = PAGE_SIZE;
    Params.DeCommitTotalFreeThreshold = TotalFreeThreshold;
    return RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, &Params);
}

static void
TestPeb(void)
{
    PPEB Peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    /* set from the Session Manager values at process creation */
    ok(Peb->HeapDeCommitTotalFreeThreshold != 0, "PEB HeapDeCommitTotalFreeThreshold is 0\n");
    ok(Peb->HeapDeCommitFreeBlockThreshold != 0, "PEB HeapDeCommitFreeBlockThreshold is 0\n");
    ok(Peb->HeapDeCommitTotalFreeThreshold >= Peb->HeapDeCommitFreeBlockThreshold,
       "total %Iu below block %Iu\n", Peb->HeapDeCommitTotalFreeThreshold, Peb->HeapDeCommitFreeBlockThreshold);
}

/* a large total threshold: a megabyte of free blocks is no reason to decommit anything */
static void
TestLargeThreshold(void)
{
    PUCHAR Blocks[8];
    SIZE_T Pages[8], Committed = 0, Total = 0;
    HANDLE Heap = CreateTestHeap(16 * 1024 * 1024);
    ULONG i;

    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    for (i = 0; i < 8; i++)
    {
        Blocks[i] = RtlAllocateHeap(Heap, 0, BLOCK_SIZE);
        ok(Blocks[i] != NULL, "allocation %lu failed\n", i);
        if (!Blocks[i])
            goto Done;
        memset(Blocks[i], 0xA5, BLOCK_SIZE);
        Pages[i] = BlockPages(Blocks[i], BLOCK_SIZE);
    }
    for (i = 0; i < 8; i++)
        ok(RtlFreeHeap(Heap, 0, Blocks[i]), "free %lu failed\n", i);

    /* the free blocks are coalesced now; every page that lay inside a block is still committed */
    for (i = 0; i < 8; i++)
    {
        Committed += CommittedPages(Blocks[i], BLOCK_SIZE);
        Total += Pages[i];
    }
    ok(Committed == Total, "%Iu of %Iu pages of the free blocks are committed with a 16 MB threshold\n", Committed, Total);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap invalid\n");
Done:
    RtlDestroyHeap(Heap);
}

/* the default threshold (64 KB): a megabyte that was all freed does not stay committed */
static void
TestDefaultThreshold(void)
{
    PUCHAR Blocks[8];
    SIZE_T Committed = 0, Total = 0;
    HANDLE Heap = CreateTestHeap(0);
    ULONG i;

    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    for (i = 0; i < 8; i++)
    {
        Blocks[i] = RtlAllocateHeap(Heap, 0, BLOCK_SIZE);
        if (!Blocks[i])
            goto Done;
        memset(Blocks[i], 0xA5, BLOCK_SIZE);
    }
    for (i = 0; i < 8; i++)
        RtlFreeHeap(Heap, 0, Blocks[i]);
    for (i = 0; i < 8; i++)
    {
        Committed += CommittedPages(Blocks[i], BLOCK_SIZE);
        Total += BlockPages(Blocks[i], BLOCK_SIZE);
    }
    ok(Committed < Total / 2, "%Iu of %Iu pages of the free blocks are still committed\n", Committed, Total);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap invalid\n");
Done:
    RtlDestroyHeap(Heap);
}

/* free memory above the total threshold is cached while the heap is busy growing, trimmed after a quiet second */
static void
TestTrim(void)
{
    PUCHAR Live[12], Small[8], Probe;
    SIZE_T Before, After, Total = 0;
    HANDLE Heap = CreateTestHeap(0);
    ULONG i;

    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    /* 3 MB that stay allocated make the heap big, so 256 KB of free blocks is a cache, not a decommit */
    for (i = 0; i < 12; i++)
    {
        Live[i] = RtlAllocateHeap(Heap, 0, BLOCK_SIZE * 2);
        ok(Live[i] != NULL, "live allocation %lu failed\n", i);
        if (!Live[i])
            goto Done;
        memset(Live[i], 1, BLOCK_SIZE * 2);
    }
    for (i = 0; i < 8; i++)
    {
        Small[i] = RtlAllocateHeap(Heap, 0, 32 * 1024);
        if (!Small[i])
            goto Done;
        memset(Small[i], 2, 32 * 1024);
        Total += BlockPages(Small[i], 32 * 1024);
    }
    /* a free every other block: no coalescing, 4 blocks of 32 KB */
    for (i = 0; i < 8; i += 2)
        RtlFreeHeap(Heap, 0, Small[i]);
    Before = 0;
    for (i = 0; i < 8; i += 2)
        Before += CommittedPages(Small[i], 32 * 1024);
    ok(Before == 4 * BlockPages(Small[0], 32 * 1024), "freed pages decommitted at once: %Iu\n", Before);

    /* a quiet second, then the next free of the heap trims the cache to the 64 KB threshold */
    Sleep(1500);
    Probe = RtlAllocateHeap(Heap, 0, 64);
    if (Probe)
        RtlFreeHeap(Heap, 0, Probe);
    for (i = 1; i < 8; i += 2)
        RtlFreeHeap(Heap, 0, Small[i]);
    Sleep(1500);
    Probe = RtlAllocateHeap(Heap, 0, 64);
    if (Probe)
        RtlFreeHeap(Heap, 0, Probe);
    After = 0;
    for (i = 0; i < 8; i++)
        After += CommittedPages(Small[i], 32 * 1024);
    ok(After < Total, "no page of the 256 KB cache was given back (%Iu of %Iu committed)\n", After, Total);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap invalid after the trim\n");
Done:
    RtlDestroyHeap(Heap);
}

START_TEST(RtlHeapDecommit)
{
    TestPeb();
    TestLargeThreshold();
    TestDefaultThreshold();
    TestTrim();
}
