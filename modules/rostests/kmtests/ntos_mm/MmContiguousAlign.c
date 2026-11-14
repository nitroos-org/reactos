/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: a small cached contiguous block is cache-line aligned and contiguous
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * A bus-master device takes the base of a descriptor ring from the buffer it was given and ignores the low
 * bits (the e1000 ring base is 16-byte aligned). A cached request is served from nonpaged pool first, and
 * the pool hands out blocks of 8-byte granularity on i386 whatever the cache-aligned type says, so a ring of
 * a few hundred bytes was misaligned and the device read another address. Allocate small cached blocks of
 * many sizes at once (so the pool cannot hand out a naturally aligned run) and check alignment, physical
 * contiguity and that every byte is usable.
 */
#define NUM_SIZES 9
#define PER_SIZE  24

START_TEST(MmContiguousAlign)
{
    static const SIZE_T Sizes[NUM_SIZES] = { 16, 24, 100, 256, 520, 2048, 3000, 4000, 12000 };
    PHYSICAL_ADDRESS Low, High, Boundary;
    PVOID Blocks[NUM_SIZES][PER_SIZE];
    ULONG i, j;
    ULONG Misaligned = 0, NotContiguous = 0, Failed = 0;

    Low.QuadPart = 0;
    High.QuadPart = MAXULONG;
    Boundary.QuadPart = 0;
    RtlZeroMemory(Blocks, sizeof(Blocks));

    for (i = 0; i < NUM_SIZES; i++)
    {
        for (j = 0; j < PER_SIZE; j++)
        {
            PUCHAR Block = MmAllocateContiguousMemorySpecifyCache(Sizes[i], Low, High, Boundary, MmCached);

            Blocks[i][j] = Block;
            if (!Block)
            {
                Failed++;
                continue;
            }
            if ((ULONG_PTR)Block & 63)
                Misaligned++;
            else
            {
                SIZE_T Offset;
                PHYSICAL_ADDRESS Base = MmGetPhysicalAddress(Block);

                for (Offset = PAGE_SIZE; Offset < Sizes[i]; Offset += PAGE_SIZE)
                {
                    PHYSICAL_ADDRESS Page = MmGetPhysicalAddress(Block + Offset);

                    if (Page.QuadPart != Base.QuadPart + (LONGLONG)Offset)
                    {
                        NotContiguous++;
                        break;
                    }
                }
            }
            RtlFillMemory(Block, Sizes[i], (UCHAR)(0x40 + i));
        }
    }

    ok_eq_ulong(Failed, 0);
    ok_eq_ulong(Misaligned, 0);
    ok_eq_ulong(NotContiguous, 0);

    /* nothing written into one block reached another */
    for (i = 0; i < NUM_SIZES; i++)
    {
        for (j = 0; j < PER_SIZE; j++)
        {
            PUCHAR Block = Blocks[i][j];
            SIZE_T Offset;
            ULONG Bad = 0;

            if (!Block)
                continue;
            for (Offset = 0; Offset < Sizes[i]; Offset++)
                if (Block[Offset] != (UCHAR)(0x40 + i))
                    Bad++;
            if (Bad)
                ok_eq_ulong(Bad, 0);
            MmFreeContiguousMemorySpecifyCache(Block, Sizes[i], MmCached);
        }
    }
}
