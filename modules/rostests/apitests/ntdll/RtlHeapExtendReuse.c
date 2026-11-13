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

#define PINS 48

/* Every block handed out must hold its requested size: write all of it with a tag of its own, and check the tags of
   all live blocks before they are freed, so a block that is short (it overruns into its neighbour) or overlaps
   another one shows. Busy pin blocks are left behind the freed ranges (one after each group of large blocks, the
   oldest freed when the window is full) so the free blocks next to an uncommitted range often have a busy block
   or the end of the segment behind them and cannot be merged with anything.
   Returns the number of blocks that failed. */
static ULONG
RunPinned(ULONG Count, ULONG Fill, SIZE_T BlockSize, ULONG Cycles, ULONG HeapFlags, SIZE_T Reserve, SIZE_T Commit)
{
    PVOID FillBlocks[FILL_BLOCKS], Live[16], Pin[PINS] = { NULL };
    HANDLE Heap;
    ULONG i, j, Bad = 0, PinNext = 0;
    SIZE_T k;

    Heap = RtlCreateHeap(HeapFlags | HEAP_GROWABLE, NULL, Reserve, Commit, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return 1;

    for (i = 0; i < Fill; i++)
        FillBlocks[i] = RtlAllocateHeap(Heap, 0, 1900);
    for (i = 0; i < Fill; i++)
    {
        if (i % 4 != 3)
            RtlFreeHeap(Heap, 0, FillBlocks[i]);
    }

    for (i = 0; i < Cycles; i++)
    {
        for (j = 0; j < Count; j++)
        {
            PUCHAR Block = RtlAllocateHeap(Heap, 0, BlockSize);

            Live[j] = Block;
            if (!Block)
                continue;
            if (RtlSizeHeap(Heap, 0, Block) < BlockSize)
            {
                Bad++;
                continue;
            }
            memset(Block, 0x40 + j, BlockSize);

            /* a pin right behind the block */
            if (Pin[PinNext])
            {
                RtlFreeHeap(Heap, 0, Pin[PinNext]);
            }
            Pin[PinNext] = RtlAllocateHeap(Heap, 0, 100 + (i % 7) * 40);
            if (Pin[PinNext])
                memset(Pin[PinNext], 0xEE, 100);
            PinNext = (PinNext + 1) % PINS;
        }

        for (j = 0; j < Count; j++)
        {
            PUCHAR Block = Live[j];

            if (!Block || RtlSizeHeap(Heap, 0, Block) < BlockSize)
                continue;
            for (k = 0; k < BlockSize; k++)
            {
                if (Block[k] != 0x40 + j)
                {
                    Bad++;
                    break;
                }
            }
            RtlFreeHeap(Heap, 0, Block);
        }

        for (j = 0; j < PINS; j++)
        {
            PUCHAR P = Pin[j];

            if (P && (P[0] != 0xEE || P[99] != 0xEE))
            {
                Bad++;
                Pin[j] = NULL;
            }
        }

        if (i % 25 == 0 && !RtlValidateHeap(Heap, 0, NULL))
        {
            Bad++;
            break;
        }
    }

    ok(RtlValidateHeap(Heap, 0, NULL), "heap invalid\n");
    RtlDestroyHeap(Heap);
    return Bad;
}

static void
TestPinnedNeighbours(void)
{
    static const struct { ULONG Count, Fill; SIZE_T Size; ULONG Flags; SIZE_T Reserve, Commit; } Cases[] =
    {
        /* default segment, then small segments (the free space ends at the last entry of the segment) */
        { 4, 128, 28944, 0, 0, 0 },
        { 8, 512, 28944, 0, 0, 0 },
        { 8, 512, 33000, 0, 0, 0 },
        { 4, 128, 28944, 0, 0x40000, 0x2000 },
        { 4, 0, 28944, 0, 0x40000, 0x2000 },
        { 8, 128, 61000, 0, 0x80000, 0x4000 },
        { 4, 128, 28944, HEAP_NO_SERIALIZE, 0x40000, 0x1000 },
        { 3, 512, 7 * PAGE_SIZE + 24, 0, 0x30000, 0x1000 },
        { 3, 512, 7 * PAGE_SIZE - 8, 0, 0x30000, 0x1000 },
        /* just under the largest block the heap keeps: the free block in front and the pages committed for the request
           together may be too large to be joined */
        { 3, 128, 0x7F000 - 48, 0, 0, 0 },
        { 3, 128, 0x7F000 - 1200, 0, 0, 0 },
        { 3, 128, 0x7F000 - 2400, 0, 0, 0 },
        { 3, 128, 0x7F000 - 3600, 0, 0, 0 },
        { 2, 512, 0x7F000 - 700, 0, 0x200000, 0x2000 },
        { 4, 512, 0x7E000 + 100, 0, 0x200000, 0x2000 },
    };
    ULONG i;

    for (i = 0; i < _countof(Cases); i++)
    {
        ULONG Bad = RunPinned(Cases[i].Count, Cases[i].Fill, Cases[i].Size, 500,
                              Cases[i].Flags, Cases[i].Reserve, Cases[i].Commit);

        ok(Bad == 0, "%lu blocks of %Iu, %lu fill blocks, reserve %Ix: %lu blocks short, overlapping or corrupt\n",
           Cases[i].Count, Cases[i].Size, Cases[i].Fill, Cases[i].Reserve, Bad);
    }
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

    TestPinnedNeighbours();
}
