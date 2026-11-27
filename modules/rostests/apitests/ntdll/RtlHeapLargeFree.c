/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A heap that holds many free blocks above a page: every request is served, the heap stays valid, and
 *              the block chosen is the smallest free block that holds the request
 */

#include "precomp.h"

#define HOLES       96
#define SEPARATOR   (400 * 1024)
#define MAX_FREE    4096

static SIZE_T HoleSize[HOLES];
static PUCHAR Hole[HOLES];
static PUCHAR Separator[HOLES];

/* The free blocks of the heap: start and size in bytes, header included */
static ULONG_PTR FreeStart[MAX_FREE];
static SIZE_T FreeTotal[MAX_FREE];
static ULONG FreeCount;

/* Hole sizes: all different, between 6 KB and about 290 KB, placed in the heap in a shuffled order of size */
static void
MakeSizes(void)
{
    ULONG i, Seed = 7;

    for (i = 0; i < HOLES; i++)
        HoleSize[i] = 6000 + (SIZE_T)i * 3000;

    for (i = HOLES - 1; i > 0; i--)
    {
        ULONG j;
        SIZE_T t;

        Seed = Seed * 1103515245 + 12345;
        j = (Seed >> 8) % (i + 1);
        t = HoleSize[i]; HoleSize[i] = HoleSize[j]; HoleSize[j] = t;
    }
}

static void
SnapshotFree(HANDLE Heap)
{
    RTL_HEAP_WALK_ENTRY Entry;

    FreeCount = 0;
    RtlZeroMemory(&Entry, sizeof(Entry));
    while (NT_SUCCESS(RtlWalkHeap(Heap, &Entry)) && FreeCount < MAX_FREE)
    {
        if (Entry.Flags & (RTL_HEAP_WALK_REGION | RTL_HEAP_WALK_UNCOMMITTED | RTL_HEAP_WALK_BUSY))
            continue;
        FreeStart[FreeCount] = (ULONG_PTR)Entry.DataAddress - Entry.OverheadBytes;
        FreeTotal[FreeCount] = Entry.DataSize + Entry.OverheadBytes;
        FreeCount++;
    }
}

/* The free block of the snapshot that the block at Address was cut from, MAX_FREE if none */
static ULONG
FreeBlockOf(PVOID Address)
{
    ULONG i;

    for (i = 0; i < FreeCount; i++)
    {
        if ((ULONG_PTR)Address > FreeStart[i] && (ULONG_PTR)Address < FreeStart[i] + FreeTotal[i])
            return i;
    }
    return MAX_FREE;
}

static void
TestHeap(ULONG Flags)
{
    HANDLE Heap;
    ULONG i, Round, Kept = 0, Checked = 0;
    PUCHAR Block[HOLES];
    ULONG Seed = 99;
    /* what a request needs of a free block beyond its size, with a margin for the rounding to the entry unit */
    SIZE_T Margin = 4 * sizeof(PVOID) + ((Flags & HEAP_TAIL_CHECKING_ENABLED) ? 2 * sizeof(PVOID) : 0) + 64;

    Heap = RtlCreateHeap(Flags | HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;

    /* hole, separator, hole, separator...: the separators keep the free blocks apart */
    for (i = 0; i < HOLES; i++)
    {
        Hole[i] = RtlAllocateHeap(Heap, 0, HoleSize[i]);
        Separator[i] = RtlAllocateHeap(Heap, 0, SEPARATOR);
        ok(Hole[i] != NULL && Separator[i] != NULL, "Allocation %lu failed\n", i);
        if (!Hole[i] || !Separator[i])
            goto done;
    }
    for (i = 0; i < HOLES; i++)
        ok(RtlFreeHeap(Heap, 0, Hole[i]), "RtlFreeHeap failed\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "Heap is not valid after the holes were made\n");

    SnapshotFree(Heap);
    for (i = 0; i < HOLES; i++)
        Kept += (FreeBlockOf(Hole[i]) != MAX_FREE);
    trace("%lu of %u holes are free blocks, %lu free blocks\n", Kept, HOLES, FreeCount);
    ok(Kept >= HOLES / 2, "Only %lu of %u holes are free blocks\n", Kept, HOLES);

    /* Requests at, just below and between the hole sizes, and of random sizes, held until the round ends */
    for (Round = 0; Round < 4; Round++)
    {
        ULONG Count = 0;

        for (i = 0; i < HOLES; i++)
        {
            SIZE_T Size;
            ULONG j, Chosen;

            Seed = Seed * 1103515245 + 12345;
            j = (Seed >> 8) % HOLES;
            switch (Round)
            {
                case 0: Size = HoleSize[j]; break;
                case 1: Size = HoleSize[j] - 100; break;
                case 2: Size = HoleSize[j] - 1500; break;
                default: Size = 4500 + (Seed >> 4) % 300000; break;
            }

            SnapshotFree(Heap);
            Block[Count] = RtlAllocateHeap(Heap, 0, Size);
            ok(Block[Count] != NULL, "Allocation of %Iu bytes failed\n", Size);
            if (!Block[Count])
                continue;
            ok(RtlSizeHeap(Heap, 0, Block[Count]) == Size, "RtlSizeHeap %Iu, expected %Iu\n",
               RtlSizeHeap(Heap, 0, Block[Count]), Size);
            RtlFillMemory(Block[Count], Size, (UCHAR)i);

            /* No free block smaller than the one the request was cut from would have held it. A request that no
               free block held is served by committing memory (next to a small free block, or in a range of its
               own): then no free block was large enough. */
            Chosen = FreeBlockOf(Block[Count]);
            if (is_reactos() && FreeCount < MAX_FREE)
            {
                BOOLEAN Grown = (Chosen == MAX_FREE || FreeTotal[Chosen] < Size);
                ULONG k;

                for (k = 0; k < FreeCount; k++)
                {
                    if (FreeTotal[k] >= Size + Margin && (Grown || FreeTotal[k] < FreeTotal[Chosen]))
                    {
                        ok(0, "Round %lu: %Iu bytes from %s at %p, a free block of %Iu bytes at %p fits\n",
                           Round, Size, Grown ? "new memory" : "a larger free block", Block[Count],
                           FreeTotal[k], (PVOID)FreeStart[k]);
                        break;
                    }
                }
                Checked++;
            }
            Count++;
        }

        ok(RtlValidateHeap(Heap, 0, NULL), "Heap is not valid in round %lu\n", Round);

        for (i = 0; i < Count; i++)
            ok(RtlFreeHeap(Heap, 0, Block[i]), "RtlFreeHeap failed\n");

        ok(RtlValidateHeap(Heap, 0, NULL), "Heap is not valid after round %lu\n", Round);
    }
    trace("%lu choices checked\n", Checked);

    /* Freeing the separators joins everything */
    for (i = 0; i < HOLES; i++)
        ok(RtlFreeHeap(Heap, 0, Separator[i]), "RtlFreeHeap failed\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "Heap is not valid with no block in use\n");
    ok(RtlCompactHeap(Heap, 0) != 0, "RtlCompactHeap returned 0\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "Heap is not valid after RtlCompactHeap\n");

done:
    RtlDestroyHeap(Heap);
}

START_TEST(RtlHeapLargeFree)
{
    MakeSizes();
    TestHeap(HEAP_NO_SERIALIZE);
    TestHeap(0);
    TestHeap(HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED);
}
