/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A request of nearly the largest block a heap keeps (0x7F000 bytes), served by committing an
 *              uncommitted range of exactly that many pages: the commit takes the guard entry of the range too,
 *              the free block comes out one entry unit over the largest size, and the heap must still hand out
 *              a block that holds the request
 */

#include "precomp.h"
#include <pseh/pseh2.h>

#define MAX_BLOCK_BYTES 0x7F000

/* One allocation in a new heap whose only uncommitted range is Pages pages. Returns 0 when all is well,
   else what went wrong: 1 a fault inside the heap, 2 a block that is too short, 3 an invalid heap,
   4 a neighbour damaged. */
static ULONG
TryHeap(ULONG ReservePages, SIZE_T Size, ULONG *UncommittedPages)
{
    RTL_HEAP_WALK_ENTRY Entry;
    HANDLE Heap;
    PUCHAR Block = NULL, Small[8];
    ULONG Result = 0, i;
    SIZE_T Uncommitted = 0;

    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, (SIZE_T)ReservePages * PAGE_SIZE, PAGE_SIZE, NULL, NULL);
    if (!Heap)
        return 0;

    RtlZeroMemory(&Entry, sizeof(Entry));
    while (NT_SUCCESS(RtlWalkHeap(Heap, &Entry)))
    {
        if (Entry.Flags & RTL_HEAP_WALK_UNCOMMITTED)
            Uncommitted += Entry.DataSize;
    }
    *UncommittedPages = (ULONG)(Uncommitted / PAGE_SIZE);

    /* small blocks in front, which a block that came out short overruns or shares memory with */
    for (i = 0; i < _countof(Small); i++)
    {
        Small[i] = RtlAllocateHeap(Heap, 0, 64);
        if (Small[i])
            memset(Small[i], 0x11 + i, 64);
    }

    _SEH2_TRY
    {
        Block = RtlAllocateHeap(Heap, 0, Size);
        if (Block)
        {
            if (RtlSizeHeap(Heap, 0, Block) < Size)
                Result = 2;
            else
                memset(Block, 0xA5, Size);
        }
        if (!Result && !RtlValidateHeap(Heap, 0, NULL))
            Result = 3;
        for (i = 0; !Result && i < _countof(Small); i++)
        {
            if (Small[i] && (Small[i][0] != 0x11 + i || Small[i][63] != 0x11 + i))
                Result = 4;
        }
        if (!Result && Block)
        {
            RtlFreeHeap(Heap, 0, Block);
            if (!RtlValidateHeap(Heap, 0, NULL))
                Result = 3;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = 1;
    }
    _SEH2_END;

    /* a heap that faulted or is damaged is left alone */
    if (!Result)
        RtlDestroyHeap(Heap);
    return Result;
}

START_TEST(RtlHeapMaxBlock)
{
    /* Requests whose block is within the last 16 entry units below the largest size, and one further down.
       A free block one unit over the largest size is kept as two blocks, of the largest size less 16 units and of
       17 units. The first is too short for these requests: a block of exactly the largest size (the first entry
       here) and one of 15 units less (the fifth) are the ones that damaged the heap. */
    static const SIZE_T Below[] = { 2 * sizeof(PVOID), 4 * sizeof(PVOID), 16 * sizeof(PVOID), 30 * sizeof(PVOID),
                                    32 * sizeof(PVOID), 80 * sizeof(PVOID) };
    ULONG Pages, i, Result, Uncommitted, ExactSeen = 0;

    for (i = 0; i < _countof(Below); i++)
    {
        /* reserves around the size of the block: with one of them the range left after the heap's own pages
           is exactly the 127 pages the request needs */
        for (Pages = 127; Pages <= 136; Pages++)
        {
            Uncommitted = 0;
            Result = TryHeap(Pages, MAX_BLOCK_BYTES - Below[i], &Uncommitted);
            if (Uncommitted == MAX_BLOCK_BYTES / PAGE_SIZE)
                ExactSeen++;
            ok(Result == 0, "request of 0x7F000 - %lu bytes, reserve %lu pages (uncommitted %lu): %s\n",
               (ULONG)Below[i], Pages, Uncommitted,
               Result == 1 ? "fault inside the heap" :
               Result == 2 ? "block shorter than the request" :
               Result == 3 ? "heap does not validate" : "a neighbour block was overwritten");
        }
    }
    ok(ExactSeen != 0, "no heap had an uncommitted range of exactly 127 pages: the test did not reach its case\n");
}
