/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RtlCompactHeap (HeapCompact): free blocks that were not merged are merged, the blocks the front end
 *              parked are given back, free pages the heap kept committed are given back, the size of the largest
 *              free block is returned
 */

#include "precomp.h"

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

/* Size of the largest free block a walk of the heap finds */
static SIZE_T
LargestFree(HANDLE Heap)
{
    RTL_HEAP_WALK_ENTRY Entry;
    SIZE_T Largest = 0;

    RtlZeroMemory(&Entry, sizeof(Entry));
    while (NT_SUCCESS(RtlWalkHeap(Heap, &Entry)))
    {
        if (Entry.Flags & (RTL_HEAP_WALK_REGION | RTL_HEAP_WALK_UNCOMMITTED | RTL_HEAP_WALK_BUSY))
            continue;
        if (Entry.DataSize > Largest)
            Largest = Entry.DataSize;
    }
    return Largest;
}

static void
TestInvalid(void)
{
    HANDLE Heap;
    ULONG Ret;
    UCHAR Garbage[256];

    /* A pointer that is not a heap */
    RtlZeroMemory(Garbage, sizeof(Garbage));
    Ret = RtlCompactHeap(Garbage, 0);
    ok_eq_ulong(Ret, 0);

    /* A heap without a free block that is not in use is not a failure, and nothing is lost */
    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;
    Ret = RtlCompactHeap(Heap, 0);
    ok(Ret != 0, "RtlCompactHeap of an empty heap returned 0\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after RtlCompactHeap\n");
    RtlDestroyHeap(Heap);
}

/* Without coalescing on free, neighbours stay apart: the compaction merges them */
static void
TestCoalesce(ULONG HeapFlags, ULONG CompactFlags)
{
    enum { COUNT = 64, RUN = 32, SIZE = 1000 };
    PVOID Blocks[COUNT];
    HANDLE Heap;
    ULONG i, Ret;
    SIZE_T Before;

    Heap = RtlCreateHeap(HEAP_GROWABLE | HEAP_DISABLE_COALESCE_ON_FREE | HeapFlags, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    for (i = 0; i < COUNT; i++)
    {
        Blocks[i] = RtlAllocateHeap(Heap, 0, SIZE);
        ok(Blocks[i] != NULL, "allocation %lu failed\n", i);
        if (!Blocks[i])
            goto done;
    }

    /* A run of neighbours (a heap hands out consecutive addresses here) and one more block apart from it */
    for (i = 8; i < 8 + RUN; i++)
        RtlFreeHeap(Heap, 0, Blocks[i]);
    RtlFreeHeap(Heap, 0, Blocks[COUNT - 2]);

    Before = LargestFree(Heap);
    ok(Before < RUN * SIZE, "largest free block is %Iu before the compaction, blocks were merged on free\n", Before);

    Ret = RtlCompactHeap(Heap, CompactFlags);
    ok(Ret >= RUN * SIZE, "RtlCompactHeap returned %lu, the run is %u\n", Ret, RUN * SIZE);
    ok(LargestFree(Heap) >= RUN * SIZE, "largest free block is %Iu after the compaction\n", LargestFree(Heap));
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after RtlCompactHeap\n");

    /* The heap still works, and a block of the merged run's size fits where the run was */
    Blocks[8] = RtlAllocateHeap(Heap, 0, RUN * SIZE);
    ok(Blocks[8] != NULL, "allocation of the run size failed\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after the allocation\n");

done:
    RtlDestroyHeap(Heap);
}

/* Free pages the heap keeps committed as a cache are given back down to the total threshold */
static void
TestTrim(void)
{
    enum { COUNT = 6000, RUN = 100, SIZE = 1000 };
    PVOID *Blocks;
    HANDLE Heap;
    ULONG i, Run, Ret;
    SIZE_T Before, After, Largest = 0;

    Blocks = RtlAllocateHeap(RtlGetProcessHeap(), 0, COUNT * sizeof(PVOID));
    if (!Blocks)
    {
        skip("no memory for the block table\n");
        return;
    }

    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        goto out;

    for (i = 0; i < COUNT; i++)
    {
        Blocks[i] = RtlAllocateHeap(Heap, 0, SIZE);
        if (!Blocks[i])
            break;
    }
    ok_eq_ulong(i, COUNT);
    if (i != COUNT)
        goto done;

    /* Runs of neighbours go back, a block in between stays: ten runs of about 100 KB, well below a quarter of what the heap has committed */
    for (Run = 0; Run < 10; Run++)
    {
        for (i = 0; i < RUN; i++)
            RtlFreeHeap(Heap, 0, Blocks[Run * 2 * RUN + i]);
    }
    Largest = LargestFree(Heap);
    Before = CommittedBytes(Heap);

    Ret = RtlCompactHeap(Heap, 0);
    After = CommittedBytes(Heap);

    ok(Ret >= Largest, "RtlCompactHeap returned %lu, the largest free block was %Iu\n", Ret, Largest);
    ok(Ret >= RUN * SIZE, "RtlCompactHeap returned %lu, the freed runs are %u\n", Ret, RUN * SIZE);
    ok(After + 512 * 1024 < Before, "committed %Iu before, %Iu after\n", Before, After);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after RtlCompactHeap\n");

    /* A second call has nothing left to give back */
    Before = After;
    Ret = RtlCompactHeap(Heap, 0);
    After = CommittedBytes(Heap);
    ok(After == Before, "committed %Iu before the second call, %Iu after\n", Before, After);
    ok(Ret != 0, "second RtlCompactHeap returned 0\n");

    /* what is in use is intact */
    for (Run = 0; Run < 10; Run++)
    {
        for (i = 0; i < RUN; i++)
        {
            ok(RtlSizeHeap(Heap, 0, Blocks[(Run * 2 + 1) * RUN + i]) == SIZE, "block size changed\n");
            if (RtlSizeHeap(Heap, 0, Blocks[(Run * 2 + 1) * RUN + i]) != SIZE)
                goto done;
        }
    }

done:
    RtlDestroyHeap(Heap);
out:
    RtlFreeHeap(RtlGetProcessHeap(), 0, Blocks);
}

/* The blocks the front end parked count as free after the compaction */
static void
TestFrontEnd(void)
{
    enum { COUNT = 2000, SIZE = 100 };
    PVOID *Blocks;
    HANDLE Heap;
    ULONG i, Type = 2, Ret;
    SIZE_T Largest;

    Blocks = RtlAllocateHeap(RtlGetProcessHeap(), 0, COUNT * sizeof(PVOID));
    if (!Blocks)
    {
        skip("no memory for the block table\n");
        return;
    }

    /* A total threshold that a few hundred KB of free blocks do not reach: the free of the parked blocks does not
       decommit the run they make, so the run is what the compaction reports */
    {
        RTL_HEAP_PARAMETERS Params;

        RtlZeroMemory(&Params, sizeof(Params));
        Params.Length = sizeof(Params);
        Params.DeCommitFreeBlockThreshold = PAGE_SIZE;
        Params.DeCommitTotalFreeThreshold = 16 * 1024 * 1024;
        Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, &Params);
    }
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        goto out;

    if (!HeapSetInformation(Heap, HeapCompatibilityInformation, &Type, sizeof(Type)))
    {
        skip("the heap has no front end\n");
        goto done;
    }

    for (i = 0; i < COUNT; i++)
    {
        Blocks[i] = HeapAlloc(Heap, 0, SIZE);
        ok(Blocks[i] != NULL, "allocation %lu failed\n", i);
        if (!Blocks[i])
            goto done;
    }

    /* one block in use at each end keeps the free run between them from joining the free space around */
    for (i = 1; i < COUNT - 1; i++)
        HeapFree(Heap, 0, Blocks[i]);

    Ret = HeapCompact(Heap, 0);
    Largest = LargestFree(Heap);
    ok(Ret >= (COUNT - 2) * SIZE, "HeapCompact returned %lu, the freed run is %u\n", Ret, (COUNT - 2) * SIZE);
    ok(Largest >= (COUNT - 2) * SIZE, "largest free block is %Iu after the compaction\n", Largest);
    ok(HeapValidate(Heap, 0, NULL), "heap is invalid after HeapCompact\n");

    /* and the heap goes on working */
    for (i = 1; i < COUNT - 1; i++)
    {
        Blocks[i] = HeapAlloc(Heap, 0, SIZE);
        ok(Blocks[i] != NULL, "allocation %lu failed\n", i);
        if (!Blocks[i])
            goto done;
    }
    ok(HeapValidate(Heap, 0, NULL), "heap is invalid after allocating again\n");

done:
    RtlDestroyHeap(Heap);
out:
    RtlFreeHeap(RtlGetProcessHeap(), 0, Blocks);
}

START_TEST(RtlHeapCompact)
{
    TestInvalid();
    TestCoalesce(0, 0);
    TestCoalesce(HEAP_NO_SERIALIZE, 0);
    /* The flag of the call alone, on a serialized heap, as a single thread that holds the heap may pass it */
    TestCoalesce(0, HEAP_NO_SERIALIZE);
    TestTrim();
    TestFrontEnd();
}
