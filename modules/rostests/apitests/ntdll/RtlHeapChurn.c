/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for a heap that is used like a compiler does: blocks of a few bytes to a few hundred KB,
 *              freed in random order, again and again (free list order, decommit and commit of pages)
 */

#include "precomp.h"

#define SLOTS 2000

static ULONG
Next(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

static SIZE_T
PickSize(ULONG *Seed)
{
    ULONG Class = Next(Seed) % 100;

    if (Class < 60)
        return 16 + Next(Seed) % 113;
    if (Class < 85)
        return 128 + Next(Seed) % 3968;
    if (Class < 97)
        return 4096 + Next(Seed) % (60 * 1024);
    /* below the virtual allocation threshold, so they are blocks of the heap */
    return 64 * 1024 + Next(Seed) % (400 * 1024);
}

static void
Fill(PUCHAR Block, SIZE_T Size, UCHAR Tag)
{
    Block[0] = Tag;
    Block[Size / 2] = (UCHAR)(Tag + 1);
    Block[Size - 1] = (UCHAR)(Tag + 2);
}

static BOOL
Check(PUCHAR Block, SIZE_T Size, UCHAR Tag)
{
    return Block[0] == Tag && Block[Size / 2] == (UCHAR)(Tag + 1) && Block[Size - 1] == (UCHAR)(Tag + 2);
}

static void
TestChurn(ULONG Flags)
{
    static PUCHAR Blocks[SLOTS];
    static SIZE_T Sizes[SLOTS];
    ULONG Seed = 1234 + Flags;
    HANDLE Heap;
    ULONG i, Round, Bad = 0, Failed = 0;
    PROCESS_HEAP_ENTRY Entry;
    SIZE_T Walked, Live;

    Heap = HeapCreate(Flags, 0, 0);
    ok(Heap != NULL, "HeapCreate failed\n");
    if (!Heap)
        return;

    memset(Blocks, 0, sizeof(Blocks));
    for (Round = 0; Round < 8; Round++)
    {
        /* replace a random half of the blocks, the rest stays */
        for (i = 0; i < SLOTS; i++)
        {
            ULONG Slot = Next(&Seed) % SLOTS;

            if (Blocks[Slot])
            {
                if (!Check(Blocks[Slot], Sizes[Slot], (UCHAR)Slot))
                    Bad++;
                ok(HeapFree(Heap, 0, Blocks[Slot]), "HeapFree failed\n");
                Blocks[Slot] = NULL;
            }
            if (Next(&Seed) % 4)
            {
                Sizes[Slot] = PickSize(&Seed);
                Blocks[Slot] = HeapAlloc(Heap, 0, Sizes[Slot]);
                if (!Blocks[Slot])
                    Failed++;
                else
                    Fill(Blocks[Slot], Sizes[Slot], (UCHAR)Slot);
            }
        }
        ok(HeapValidate(Heap, 0, NULL), "HeapValidate failed after round %lu\n", Round);
    }
    ok_eq_ulong(Bad, 0);
    ok_eq_ulong(Failed, 0);

    /* what the heap walk finds as busy is what we hold */
    Walked = 0;
    Live = 0;
    for (i = 0; i < SLOTS; i++)
        if (Blocks[i])
            Live++;
    Entry.lpData = NULL;
    HeapLock(Heap);
    while (HeapWalk(Heap, &Entry))
        if ((Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && !(Entry.wFlags & PROCESS_HEAP_REGION))
            Walked++;
    HeapUnlock(Heap);
    ok(Walked >= Live, "heap walk found %Iu busy blocks, we hold %Iu\n", Walked, Live);

    for (i = 0; i < SLOTS; i++)
    {
        if (Blocks[i])
        {
            if (!Check(Blocks[i], Sizes[i], (UCHAR)i))
                Bad++;
            HeapFree(Heap, 0, Blocks[i]);
            Blocks[i] = NULL;
        }
    }
    ok_eq_ulong(Bad, 0);
    ok(HeapValidate(Heap, 0, NULL), "HeapValidate failed at the end\n");

    /* everything is free again: one big block must be possible */
    Blocks[0] = HeapAlloc(Heap, 0, 400 * 1024);
    ok(Blocks[0] != NULL, "HeapAlloc of 400 KB failed after the churn\n");
    if (Blocks[0])
    {
        memset(Blocks[0], 0x5A, 400 * 1024);
        HeapFree(Heap, 0, Blocks[0]);
    }
    ok(HeapDestroy(Heap), "HeapDestroy failed\n");
}

START_TEST(RtlHeapChurn)
{
    TestChurn(0);
    TestChurn(HEAP_NO_SERIALIZE);
}
