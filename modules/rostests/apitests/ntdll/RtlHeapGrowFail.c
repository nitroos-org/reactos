/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A grow in place that fails (HEAP_REALLOC_IN_PLACE_ONLY) leaves the heap consistent: the free
 *              block it committed is counted once in the total of free blocks the heap keeps
 */

#include "precomp.h"

#define PAGES       64

/* Commits less than a request that needs more than a page, as a heap with a commit routine may */
static NTSTATUS NTAPI
ShortCommit(PVOID Base, PVOID *Address, PSIZE_T Size)
{
    if (*Size > PAGE_SIZE)
        *Size = PAGE_SIZE;

    return NtAllocateVirtualMemory(NtCurrentProcess(), Address, 0, Size, MEM_COMMIT, PAGE_READWRITE);
}

/* The largest free block the heap has: for a heap that is one free block, the whole free space of it */
static BOOLEAN
FindFree(HANDLE Heap, SIZE_T *DataSize, SIZE_T *FreeBytes)
{
    RTL_HEAP_WALK_ENTRY Entry;
    BOOLEAN Found = FALSE;

    *DataSize = 0;
    *FreeBytes = 0;
    RtlZeroMemory(&Entry, sizeof(Entry));
    while (NT_SUCCESS(RtlWalkHeap(Heap, &Entry)))
    {
        if (Entry.Flags & (RTL_HEAP_WALK_REGION | RTL_HEAP_WALK_UNCOMMITTED | RTL_HEAP_WALK_BUSY))
            continue;
        *FreeBytes += Entry.DataSize + Entry.OverheadBytes;
        if (Entry.DataSize >= *DataSize)
        {
            *DataSize = Entry.DataSize;
            Found = TRUE;
        }
    }
    return Found;
}

/* A heap on memory of the test, one page committed, a commit routine that commits one page at a time */
static void
TestShortCommit(void)
{
    RTL_HEAP_PARAMETERS Params;
    PVOID Base = NULL;
    SIZE_T Size = PAGES * PAGE_SIZE, Commit = PAGE_SIZE, DataSize, FreeBytes, Before, After;
    PVOID Block, Grown;
    NTSTATUS Status;
    HANDLE Heap;
    ULONG i;

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Size, MEM_RESERVE, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, 0, &Commit, MEM_COMMIT, PAGE_READWRITE);
    ok_ntstatus(Status, STATUS_SUCCESS);

    RtlZeroMemory(&Params, sizeof(Params));
    Params.Length = sizeof(Params);
    Params.InitialCommit = PAGE_SIZE;
    Params.InitialReserve = PAGES * PAGE_SIZE;
    Params.CommitRoutine = ShortCommit;
    Heap = RtlCreateHeap(HEAP_NO_SERIALIZE, Base, 0, 0, NULL, &Params);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        goto out;
    ok(RtlValidateHeap(Heap, 0, NULL), "new heap is invalid\n");

    /* Take the one free block of the committed page whole: what follows the block is the end of the committed memory */
    if (!FindFree(Heap, &DataSize, &FreeBytes))
    {
        skip("the heap has no free block\n");
        goto done;
    }
    Block = RtlAllocateHeap(Heap, 0, DataSize);
    ok(Block != NULL, "allocation of %Iu failed\n", DataSize);
    if (!Block)
        goto done;
    FindFree(Heap, &DataSize, &FreeBytes);
    trace("%Iu bytes free after taking the block\n", FreeBytes);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after the allocation\n");

    /* The commit routine gives one page where several are needed: the grow fails, whatever it committed is free memory */
    for (i = 0; i < 4; i++)
    {
        SIZE_T Want = RtlSizeHeap(Heap, 0, Block) + 3 * PAGE_SIZE;

        Grown = RtlReAllocateHeap(Heap, HEAP_REALLOC_IN_PLACE_ONLY, Block, Want);
        ok(Grown == NULL, "grow in place to %Iu bytes succeeded\n", Want);
        ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after the failed grow %lu\n", i);
        if (Grown)
            Block = Grown;
    }

    FindFree(Heap, &DataSize, &FreeBytes);
    Before = FreeBytes;
    trace("%Iu bytes free after the failed grows\n", Before);

    /* the committed page is there for the next request, once */
    Grown = RtlAllocateHeap(Heap, 0, PAGE_SIZE / 2);
    ok(Grown != NULL, "allocation in the committed page failed\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after the allocation\n");
    FindFree(Heap, &DataSize, &FreeBytes);
    After = FreeBytes;
    ok(After < Before, "free bytes %Iu before, %Iu after an allocation\n", Before, After);
    if (Grown)
        RtlFreeHeap(Heap, 0, Grown);

    RtlFreeHeap(Heap, 0, Block);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after the free\n");

done:
    RtlDestroyHeap(Heap);
out:
    Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
}

static ULONG
Next(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

/* Grows in place, failing and succeeding, on a heap that grows: the heap stays consistent */
static void
TestMixedGrow(void)
{
    enum { COUNT = 200, ROUNDS = 3000 };
    PVOID Blocks[COUNT];
    SIZE_T Sizes[COUNT];
    HANDLE Heap;
    ULONG Seed = 7, i, Round, Failed = 0, Succeeded = 0, Invalid = 0;

    Heap = RtlCreateHeap(HEAP_GROWABLE | HEAP_NO_SERIALIZE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    for (i = 0; i < COUNT; i++)
    {
        Sizes[i] = 16 + Next(&Seed) % 2000;
        Blocks[i] = RtlAllocateHeap(Heap, 0, Sizes[i]);
    }

    for (Round = 0; Round < ROUNDS; Round++)
    {
        ULONG Pick = Next(&Seed) % COUNT;
        ULONG Op = Next(&Seed) % 4;
        PVOID New;

        if (Op == 0)
        {
            /* free a neighbour, so that the next grow of a block next to it can succeed */
            ULONG Other = (Pick + 1) % COUNT;

            if (Blocks[Other])
            {
                RtlFreeHeap(Heap, 0, Blocks[Other]);
                Blocks[Other] = NULL;
            }
        }
        else if (Op == 1 && !Blocks[Pick])
        {
            Sizes[Pick] = 16 + Next(&Seed) % 2000;
            Blocks[Pick] = RtlAllocateHeap(Heap, 0, Sizes[Pick]);
        }
        else if (Blocks[Pick])
        {
            SIZE_T Want = Sizes[Pick] + Next(&Seed) % 6000;

            New = RtlReAllocateHeap(Heap, HEAP_REALLOC_IN_PLACE_ONLY, Blocks[Pick], Want);
            if (New)
            {
                Blocks[Pick] = New;
                Sizes[Pick] = Want;
                Succeeded++;
            }
            else
            {
                Failed++;
            }
        }

        if (Round % 50 == 0 && !RtlValidateHeap(Heap, 0, NULL))
            Invalid++;
    }

    trace("%lu grows in place failed, %lu succeeded\n", Failed, Succeeded);
    ok(Failed != 0 && Succeeded != 0, "failed %lu, succeeded %lu\n", Failed, Succeeded);
    ok_eq_ulong(Invalid, 0);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid at the end\n");

    for (i = 0; i < COUNT; i++)
    {
        if (Blocks[i])
            RtlFreeHeap(Heap, 0, Blocks[i]);
    }
    ok(RtlValidateHeap(Heap, 0, NULL), "heap is invalid after freeing everything\n");
    RtlDestroyHeap(Heap);
}

START_TEST(RtlHeapGrowFail)
{
    TestShortCommit();
    TestMixedGrow();
}
