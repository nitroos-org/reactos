/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A request a little larger than the uncommitted range a decommit left behind is served by committing
 *              what is missing next to the free pages around that range, not by committing a new range and
 *              stranding those pages: the committed size of a heap stays flat while blocks of the same size are
 *              allocated several at a time and freed in the order they were allocated
 */

#include "precomp.h"

#define FILL_BLOCKS 512

/* Bytes of blocks (busy and free) the heap holds in committed memory */
static SIZE_T
CommittedBytes(HANDLE Heap)
{
    RTL_HEAP_WALK_ENTRY Entry;
    SIZE_T Total = 0;

    RtlZeroMemory(&Entry, sizeof(Entry));
    while (NT_SUCCESS(RtlWalkHeap(Heap, &Entry)))
    {
        if (Entry.Flags & (RTL_HEAP_WALK_REGION | RTL_HEAP_WALK_UNCOMMITTED))
            continue;
        Total += Entry.DataSize + Entry.OverheadBytes;
    }
    return Total;
}

/* Count blocks of BlockSize live at once, allocated and then freed in the same order, Cycles times. The fill blocks
   leave the heap enough free memory for the free of a block to decommit. Returns the growth of the committed size
   after a warm-up. */
static SIZE_T
RunCycles(ULONG Count, ULONG Fill, SIZE_T BlockSize, ULONG Cycles)
{
    PVOID FillBlocks[FILL_BLOCKS], Live[16];
    HANDLE Heap;
    ULONG i, j;
    SIZE_T Before = 0, After;

    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return 0;

    for (i = 0; i < Fill; i++)
        FillBlocks[i] = RtlAllocateHeap(Heap, 0, 1900);
    for (i = 0; i < Fill; i++)
    {
        if (i % 4 != 3)
            RtlFreeHeap(Heap, 0, FillBlocks[i]);
    }

    for (i = 0; i < Cycles + 50; i++)
    {
        if (i == 50)
            Before = CommittedBytes(Heap);
        for (j = 0; j < Count; j++)
        {
            Live[j] = RtlAllocateHeap(Heap, 0, BlockSize);
            if (Live[j])
                memset(Live[j], 0x5A, BlockSize);
        }
        for (j = 0; j < Count; j++)
        {
            if (Live[j])
                RtlFreeHeap(Heap, 0, Live[j]);
        }
    }
    After = CommittedBytes(Heap);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap invalid\n");
    RtlDestroyHeap(Heap);
    return After > Before ? After - Before : 0;
}

START_TEST(RtlHeapExtendReuse)
{
    static const struct { ULONG Count, Fill; SIZE_T Size; } Cases[] =
    {
        /* 29000 bytes, the block the console server asks for to enumerate fonts, 4 at once: 7.07 pages */
        { 4, 128, 28944 },
        { 4, 512, 28944 },
        { 8, 128, 28944 },
        { 8, 512, 28944 },
        { 8, 512, 33000 },
        { 8, 512, 61000 },
        { 4, 0, 28944 },
    };
    ULONG i;

    for (i = 0; i < _countof(Cases); i++)
    {
        SIZE_T Growth = RunCycles(Cases[i].Count, Cases[i].Fill, Cases[i].Size, 500);

        /* a stranded page per cycle is 2 MB over 500 cycles */
        ok(Growth <= 16 * PAGE_SIZE, "%lu blocks of %Iu, %lu fill blocks: committed memory grew by %Iu bytes over 500 cycles\n",
           Cases[i].Count, Cases[i].Size, Cases[i].Fill, Growth);
    }
}
