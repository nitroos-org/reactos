/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The segments of a growable heap: the reserve of every new segment doubles up to a cap (1, 2, 4, 8 MB,
 *              then 16192 KB, as measured on Windows for x86 and x64), so that a long run of large blocks in a
 *              32-bit process does not run out of address space; a 64-bit heap can still grow to a GB and more
 */

#include "precomp.h"

#define SEGMENT_CAP     (16192UL * 1024)
#define MAX_SEGS        256
#define SLOTS           8192
#define CHURN_OPS       3000000
#define QUIET_EVERY     40000

typedef struct
{
    PUCHAR Base;
    SIZE_T Reserve;
} SEG;

static SEG Segs[MAX_SEGS];
static ULONG NumSegs;

static SIZE_T
ReserveOf(PVOID Base)
{
    MEMORY_BASIC_INFORMATION Info;
    PUCHAR Address = Base;
    SIZE_T Total = 0;

    while (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), Address, MemoryBasicInformation, &Info, sizeof(Info), NULL)) &&
           Info.AllocationBase == Base && Info.State != MEM_FREE)
    {
        Total += Info.RegionSize;
        Address += Info.RegionSize;
    }
    return Total;
}

/* Notes the segment a block lives in; TRUE when it is a segment the heap did not have before */
static BOOLEAN
Track(PVOID Block)
{
    MEMORY_BASIC_INFORMATION Info;
    ULONG i;

    for (i = 0; i < NumSegs; i++)
    {
        if ((PUCHAR)Block >= Segs[i].Base && (PUCHAR)Block < Segs[i].Base + Segs[i].Reserve)
            return FALSE;
    }
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), Block, MemoryBasicInformation, &Info, sizeof(Info), NULL)))
        return FALSE;
    if (NumSegs >= MAX_SEGS)
        return FALSE;
    Segs[NumSegs].Base = Info.AllocationBase;
    Segs[NumSegs].Reserve = ReserveOf(Info.AllocationBase);
    NumSegs++;
    return TRUE;
}

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
    return 64 * 1024 + Next(Seed) % (396 * 1024);
}

/* Fixed-size blocks until the heap has NewSegs more segments or the live bytes reach Cap */
static ULONG
Grow(HANDLE Heap, PVOID *Blocks, ULONG MaxBlocks, SIZE_T Size, ULONG NewSegs, SIZE_T Cap, BOOLEAN *Failed)
{
    ULONG Count = 0, Target = NumSegs + NewSegs;

    *Failed = FALSE;
    while (Count < MaxBlocks && NumSegs < Target && (SIZE_T)(Count + 1) * Size <= Cap)
    {
        PVOID Block = RtlAllocateHeap(Heap, 0, Size);

        if (!Block)
        {
            *Failed = TRUE;
            break;
        }
        Blocks[Count++] = Block;
        Track(Block);
    }
    return Count;
}

static void
TestSegmentSizes(void)
{
    static PVOID Blocks[4096];
    HANDLE Heap;
    ULONG Count, i;
    BOOLEAN Failed;
    SIZE_T Expected;

    NumSegs = 0;
    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;
    Track(Heap);

    Count = Grow(Heap, Blocks, RTL_NUMBER_OF(Blocks), 64 * 1024, 12, 250UL * 1024 * 1024, &Failed);
    ok(!Failed, "an allocation failed after %lu blocks\n", Count);
    ok(NumSegs == 13, "NumSegs = %lu after %lu blocks\n", NumSegs, Count);

    Expected = (SIZE_T)NtCurrentPeb()->HeapSegmentReserve;
    for (i = 1; i < NumSegs; i++)
    {
        ok(Segs[i].Reserve == Expected, "segment %lu: reserve %lu KB, expected %lu KB\n",
           i, (ULONG)(Segs[i].Reserve >> 10), (ULONG)(Expected >> 10));
        Expected *= 2;
        if (Expected > SEGMENT_CAP)
            Expected = SEGMENT_CAP;
    }

    for (i = 0; i < Count; i++)
        ok(RtlFreeHeap(Heap, 0, Blocks[i]), "RtlFreeHeap failed\n");
    ok(RtlValidateHeap(Heap, 0, NULL), "heap does not validate\n");
    RtlDestroyHeap(Heap);
}

/* Blocks of a few bytes to 460 KB, alive and freed again and again, the live set around 50 MB, every now and then
   everything freed: no allocation fails, and no segment reserves more than the cap and the heap does not use up its segments */
static void
TestChurn(void)
{
    static PUCHAR Slots[SLOTS];
    static SIZE_T Sizes[SLOTS];
    ULONG Seed = 777, Op, Failed = 0, i;
    SIZE_T Total = 0, Live = 0, PeakLive = 0;
    HANDLE Heap;

    NumSegs = 0;
    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;
    Track(Heap);

    for (Op = 1; Op <= CHURN_OPS; Op++)
    {
        i = Next(&Seed) % SLOTS;
        if (Slots[i])
        {
            RtlFreeHeap(Heap, 0, Slots[i]);
            Live -= Sizes[i];
            Slots[i] = NULL;
        }
        else
        {
            SIZE_T Size = PickSize(&Seed);

            Slots[i] = RtlAllocateHeap(Heap, 0, Size);
            if (Slots[i])
            {
                Sizes[i] = Size;
                Live += Size;
                if (Live > PeakLive)
                    PeakLive = Live;
                Track(Slots[i]);
            }
            else
                Failed++;
        }
        if (Op % QUIET_EVERY == 0)
        {
            for (i = 0; i < SLOTS; i++)
            {
                if (Slots[i])
                {
                    RtlFreeHeap(Heap, 0, Slots[i]);
                    Slots[i] = NULL;
                }
            }
            Live = 0;
        }
    }
    for (i = 0; i < NumSegs; i++)
        Total += ReserveOf(Segs[i].Base);

    ok(Failed == 0, "%lu of %lu allocations failed\n", Failed, (ULONG)CHURN_OPS);
    trace("churn: %lu segments, %lu MB reserved, peak live %lu MB\n", NumSegs, (ULONG)(Total >> 20), (ULONG)(PeakLive >> 20));
    for (i = 0; i < NumSegs; i++)
        ok(i < 5 || Segs[i].Reserve <= SEGMENT_CAP, "segment %lu reserves %lu KB\n", i, (ULONG)(Segs[i].Reserve >> 10));
    /* a bound, with room left in the 64 segments of a heap (Windows needs about 10 for this load) */
    ok(NumSegs <= 40, "%lu segments\n", NumSegs);

    for (i = 0; i < SLOTS; i++)
    {
        if (Slots[i])
            RtlFreeHeap(Heap, 0, Slots[i]);
    }
    ok(RtlValidateHeap(Heap, 0, NULL), "heap does not validate\n");
    RtlDestroyHeap(Heap);
}

#ifdef _WIN64
/* The cap of a segment's reserve must not cap the heap: a GB of live blocks still fits in one growable heap
   (more than HEAP_SEGMENTS segments of the cap) */
static void
TestLargeHeap(void)
{
    static PVOID Blocks[16384];
    SYSTEM_PERFORMANCE_INFORMATION Perf;
    HANDLE Heap;
    ULONG Count = 0, i;
    BOOLEAN Failed;
    NTSTATUS Status;
    SIZE_T Want = 1000UL * 1024 * 1024;

    Status = NtQuerySystemInformation(SystemPerformanceInformation, &Perf, sizeof(Perf), NULL);
    if (!NT_SUCCESS(Status) ||
        (ULONGLONG)(Perf.CommitLimit - Perf.CommittedPages) * PAGE_SIZE < (ULONGLONG)Want + 400ULL * 1024 * 1024)
    {
        skip("not enough commit for a heap of %lu MB\n", (ULONG)(Want >> 20));
        return;
    }

    NumSegs = 0;
    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ok(Heap != NULL, "RtlCreateHeap failed\n");
    if (!Heap)
        return;
    Track(Heap);
    Count = Grow(Heap, Blocks, RTL_NUMBER_OF(Blocks), 64 * 1024, MAX_SEGS, Want, &Failed);
    ok(!Failed, "an allocation failed after %lu blocks (%lu MB, %lu segments)\n",
       Count, (ULONG)((SIZE_T)Count * 64 / 1024), NumSegs);
    ok(Count == Want / (64 * 1024), "%lu blocks, expected %lu\n", Count, (ULONG)(Want / (64 * 1024)));
    trace("large heap: %lu segments for %lu MB\n", NumSegs, (ULONG)(Want >> 20));
    for (i = 0; i < Count; i++)
        RtlFreeHeap(Heap, 0, Blocks[i]);
    ok(RtlValidateHeap(Heap, 0, NULL), "heap does not validate\n");
    RtlDestroyHeap(Heap);
}
#endif

START_TEST(RtlHeapSegments)
{
    TestSegmentSizes();
    TestChurn();
#ifdef _WIN64
    TestLargeHeap();
#endif
}
