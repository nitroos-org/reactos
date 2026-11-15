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
   4 a neighbour damaged, 5 a heap that can grow refused the request, 6 the memory of a request that was
   refused cannot be used for a smaller block. *Refused tells whether the request was refused. */
static ULONG
TryHeap(ULONG HeapFlags, ULONG ReservePages, SIZE_T Size, ULONG *UncommittedPages, BOOLEAN *Refused)
{
    RTL_HEAP_WALK_ENTRY Entry;
    HANDLE Heap;
    PUCHAR Block = NULL, Small[8];
    ULONG Result = 0, i;
    SIZE_T Uncommitted = 0;

    Heap = RtlCreateHeap(HeapFlags, NULL, (SIZE_T)ReservePages * PAGE_SIZE, PAGE_SIZE, NULL, NULL);
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

    *Refused = FALSE;
    _SEH2_TRY
    {
        Block = RtlAllocateHeap(Heap, 0, Size);
        *Refused = (Block == NULL);
        if (Block)
        {
            if (RtlSizeHeap(Heap, 0, Block) < Size)
                Result = 2;
            else
                memset(Block, 0xA5, Size);
        }
        else if (HeapFlags & HEAP_GROWABLE)
        {
            Result = 5;
        }
        else if (*UncommittedPages >= MAX_BLOCK_BYTES / PAGE_SIZE)
        {
            /* A heap of a fixed size may refuse it; what it committed for it stays free and holds a block of a
               page less */
            Block = RtlAllocateHeap(Heap, 0, Size - PAGE_SIZE);
            if (!Block)
                Result = 6;
            else
                memset(Block, 0x5A, Size - PAGE_SIZE);
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
       A free block one unit over the largest size is kept as two blocks. When they were of the largest size less
       16 units and of 17 units, a block of exactly the largest size (the first entry here) and one of 15 units
       less (the fifth) damaged the heap; now they are of the largest size less one unit and of two units, and
       only the first request does not fit. */
    static const SIZE_T Below[] = { 2 * sizeof(PVOID), 4 * sizeof(PVOID), 16 * sizeof(PVOID), 30 * sizeof(PVOID),
                                    32 * sizeof(PVOID), 80 * sizeof(PVOID) };
    /* a heap that grows, one of a fixed size (no other segment to go to) and one without its lock */
    static const ULONG Flags[] = { HEAP_GROWABLE, 0, HEAP_GROWABLE | HEAP_NO_SERIALIZE };
    ULONG Pages, i, f, Result, Uncommitted, ExactSeen;
    BOOLEAN Refused, RefRefused[136 - 127 + 1];

    for (f = 0; f < _countof(Flags); f++)
    {
        ExactSeen = 0;

        /* The request furthest below the largest size, in each heap: a heap of a fixed size that serves it has
           the room for the others too (on ReactOS only a block of exactly the largest size, the first request,
           may then be refused: the free block that the commit makes is one unit short of it) */
        for (Pages = 127; Pages <= 136; Pages++)
        {
            RefRefused[Pages - 127] = TRUE;
            TryHeap(Flags[f], Pages, MAX_BLOCK_BYTES - Below[_countof(Below) - 1], &Uncommitted,
                    &RefRefused[Pages - 127]);
        }

        for (i = 0; i < _countof(Below); i++)
        {
            /* reserves around the size of the block: with one of them the range left after the heap's own pages
               is exactly the 127 pages the request needs */
            for (Pages = 127; Pages <= 136; Pages++)
            {
                Uncommitted = 0;
                Refused = FALSE;
                Result = TryHeap(Flags[f], Pages, MAX_BLOCK_BYTES - Below[i], &Uncommitted, &Refused);
                if (Uncommitted == MAX_BLOCK_BYTES / PAGE_SIZE)
                    ExactSeen++;
                ok(Result == 0, "heap flags 0x%lx, request of 0x7F000 - %lu bytes, reserve %lu pages (uncommitted %lu): %s\n",
                   Flags[f], (ULONG)Below[i], Pages, Uncommitted,
                   Result == 1 ? "fault inside the heap" :
                   Result == 2 ? "block shorter than the request" :
                   Result == 3 ? "heap does not validate" :
                   Result == 4 ? "a neighbour block was overwritten" :
                   Result == 5 ? "refused by a heap that can grow" : "the committed memory cannot be used");
                if (is_reactos() && i != 0 && !RefRefused[Pages - 127])
                {
                    ok(!Refused, "heap flags 0x%lx, request of 0x7F000 - %lu bytes, reserve %lu pages (uncommitted %lu): "
                       "refused, the same heap serves 0x7F000 - %lu bytes\n", Flags[f], (ULONG)Below[i], Pages,
                       Uncommitted, (ULONG)Below[_countof(Below) - 1]);
                }
            }
        }
        ok(ExactSeen != 0, "heap flags 0x%lx: no heap had an uncommitted range of exactly 127 pages: the test did not reach its case\n",
           Flags[f]);
    }
}
