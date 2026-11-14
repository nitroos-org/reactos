/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for the *CacheAligned pool types
 *              (the public WDK documents that the returned block is aligned
 *              on a processor data cache line)
 */

#include <kmt_test.h>

#define TAG_CALIGN 'nlAC'
#define TAG_CAINFO 'ifAC'

#define MAX_SMALL   4096

typedef struct _CA_TAGSTAT
{
    ULONG Allocs;
    ULONG Frees;
    SIZE_T Used;
    BOOLEAN Valid;
} CA_TAGSTAT;

static
VOID
GetTagStat(
    _In_ ULONG Tag,
    _In_ BOOLEAN Paged,
    _Out_ CA_TAGSTAT *Stat)
{
    PSYSTEM_POOLTAG_INFORMATION Info;
    ULONG Size = 0x80000, Length = 0, i;
    NTSTATUS Status;

    RtlZeroMemory(Stat, sizeof(*Stat));
    Info = ExAllocatePoolWithTag(PagedPool, Size, TAG_CAINFO);
    if (!Info)
        return;
    Status = ZwQuerySystemInformation(SystemPoolTagInformation, Info, Size, &Length);
    if (NT_SUCCESS(Status))
    {
        Stat->Valid = TRUE;
        for (i = 0; i < Info->Count; i++)
        {
            if (Info->TagInfo[i].TagUlong == Tag)
            {
                if (Paged)
                {
                    Stat->Allocs = Info->TagInfo[i].PagedAllocs;
                    Stat->Frees = Info->TagInfo[i].PagedFrees;
                    Stat->Used = Info->TagInfo[i].PagedUsed;
                }
                else
                {
                    Stat->Allocs = Info->TagInfo[i].NonPagedAllocs;
                    Stat->Frees = Info->TagInfo[i].NonPagedFrees;
                    Stat->Used = Info->TagInfo[i].NonPagedUsed;
                }
                break;
            }
        }
    }
    ExFreePoolWithTag(Info, TAG_CAINFO);
}

static
VOID
SweepType(
    _In_ POOL_TYPE Type,
    _In_ PCSTR Name,
    _In_ ULONG Align,
    _In_ BOOLEAN Paged)
{
    static const SIZE_T BigSizes[] = { 4097, 5000, 8192, 12288, 65536, 100000 };
    PVOID *Blocks;
    SIZE_T Size, Count = MAX_SMALL + RTL_NUMBER_OF(BigSizes), i;
    ULONG Misaligned = 0, Failed = 0, Corrupt = 0;
    CA_TAGSTAT Before, During, After;

    Blocks = ExAllocatePoolWithTag(PagedPool, Count * sizeof(PVOID), TAG_CAINFO);
    if (!skip(Blocks != NULL, "No memory for the block table\n"))
    {
        RtlZeroMemory(Blocks, Count * sizeof(PVOID));
        GetTagStat(TAG_CALIGN, Paged, &Before);

        /* Everything live at once, so neighbours would expose overlaps */
        for (i = 0; i < Count; i++)
        {
            Size = (i < MAX_SMALL) ? i + 1 : BigSizes[i - MAX_SMALL];
            Blocks[i] = ExAllocatePoolWithTag(Type, Size, TAG_CALIGN);
            if (!Blocks[i])
            {
                Failed++;
                continue;
            }
            if (((ULONG_PTR)Blocks[i] & (Align - 1)) != 0)
            {
                if (Misaligned++ < 4)
                    trace("%s size %Iu: %p is not %lu-byte aligned\n", Name, Size, Blocks[i], Align);
            }
            RtlFillMemory(Blocks[i], Size, (UCHAR)(i | 1));
        }
        ok(Failed == 0, "%s: %lu allocations failed\n", Name, Failed);
        ok(Misaligned == 0, "%s: %lu blocks not %lu-byte aligned\n", Name, Misaligned, Align);

        GetTagStat(TAG_CALIGN, Paged, &During);

        for (i = 0; i < Count; i++)
        {
            PUCHAR p = Blocks[i];
            SIZE_T j;

            if (!p)
                continue;
            Size = (i < MAX_SMALL) ? i + 1 : BigSizes[i - MAX_SMALL];
            for (j = 0; j < Size; j++)
            {
                if (p[j] != (UCHAR)(i | 1))
                {
                    Corrupt++;
                    break;
                }
            }
        }
        ok(Corrupt == 0, "%s: %lu blocks were overwritten by a neighbour\n", Name, Corrupt);

        /* Free in a scrambled order (odd ones first), the tag is always given */
        for (i = 1; i < Count; i += 2)
            if (Blocks[i])
                ExFreePoolWithTag(Blocks[i], TAG_CALIGN);
        for (i = 0; i < Count; i += 2)
            if (Blocks[i])
                ExFreePoolWithTag(Blocks[i], TAG_CALIGN);

        GetTagStat(TAG_CALIGN, Paged, &After);
        if (!skip(Before.Valid && During.Valid && After.Valid, "Pool tag query failed\n"))
        {
            ok_eq_ulong(During.Allocs - Before.Allocs, (ULONG)(Count - Failed));
            ok_eq_ulong(During.Frees - Before.Frees, 0UL);
            ok(During.Used - Before.Used >= (SIZE_T)(Count - Failed),
               "%s: used bytes grew by only %Iu\n", Name, During.Used - Before.Used);
            ok_eq_ulong(After.Allocs - Before.Allocs, (ULONG)(Count - Failed));
            ok_eq_ulong(After.Frees - Before.Frees, (ULONG)(Count - Failed));
            ok_eq_size(After.Used, Before.Used);
        }
        ExFreePoolWithTag(Blocks, TAG_CAINFO);
    }
}

/* Micro benchmark (informational): batches of allocations freed in order.
 * Prints the best of 5 runs per type and size, in microseconds per 1000 pairs */
static
VOID
Bench(
    _In_ POOL_TYPE Type,
    _In_ PCSTR Name)
{
    static const SIZE_T Sizes[] = { 16, 64, 200, 700, 2000 };
    PVOID Blocks[64];
    LARGE_INTEGER Freq, Start, End;
    ULONG s, run, i, round;
    LONGLONG Best;

    KeQueryPerformanceCounter(&Freq);
    for (s = 0; s < RTL_NUMBER_OF(Sizes); s++)
    {
        Best = MAXLONGLONG;
        for (run = 0; run < 5; run++)
        {
            Start = KeQueryPerformanceCounter(NULL);
            for (round = 0; round < 2000; round++)
            {
                for (i = 0; i < RTL_NUMBER_OF(Blocks); i++)
                    Blocks[i] = ExAllocatePoolWithTag(Type, Sizes[s], TAG_CAINFO);
                for (i = 0; i < RTL_NUMBER_OF(Blocks); i++)
                    if (Blocks[i])
                        ExFreePoolWithTag(Blocks[i], TAG_CAINFO);
            }
            End = KeQueryPerformanceCounter(NULL);
            if (End.QuadPart - Start.QuadPart < Best)
                Best = End.QuadPart - Start.QuadPart;
        }
        /* 2000 * 64 = 128000 alloc/free pairs per run */
        trace("BENCH %s size %Iu: %I64d us per 128000 pairs\n",
              Name, Sizes[s], Best * 1000000 / Freq.QuadPart);
    }
}

START_TEST(ExPoolCacheAligned)
{
    ULONG Align = KeGetRecommendedSharedDataAlignment();
    PVOID Buffer, Buffer2;

    Bench(NonPagedPool, "NonPagedPool");
    Bench(PagedPool, "PagedPool");
    Bench(NonPagedPoolCacheAligned, "NonPagedPoolCacheAligned");
    Bench(PagedPoolCacheAligned, "PagedPoolCacheAligned");

    trace("Recommended shared data alignment: %lu\n", Align);
    ok(Align >= 16 && (Align & (Align - 1)) == 0, "Bad alignment %lu\n", Align);
    if (Align < 16 || (Align & (Align - 1)) != 0)
        return;

    SweepType(NonPagedPoolCacheAligned, "NonPagedPoolCacheAligned", Align, FALSE);
    SweepType(PagedPoolCacheAligned, "PagedPoolCacheAligned", Align, TRUE);
    SweepType(NonPagedPoolCacheAlignedMustS, "NonPagedPoolCacheAlignedMustS", Align, FALSE);

    /* The plain types are unchanged: no extra alignment is promised, but the
     * data must still be pool-block (8 or 16 byte) aligned and freeable */
    Buffer = ExAllocatePoolWithTag(NonPagedPool, 24, TAG_CALIGN);
    Buffer2 = ExAllocatePoolWithTag(PagedPool, 24, TAG_CALIGN);
    ok(Buffer != NULL && Buffer2 != NULL, "plain allocations failed\n");
    if (Buffer)
    {
        ok(((ULONG_PTR)Buffer & (sizeof(PVOID) - 1)) == 0, "Misaligned %p\n", Buffer);
        ExFreePoolWithTag(Buffer, TAG_CALIGN);
    }
    if (Buffer2)
    {
        ok(((ULONG_PTR)Buffer2 & (sizeof(PVOID) - 1)) == 0, "Misaligned %p\n", Buffer2);
        ExFreePoolWithTag(Buffer2, TAG_CALIGN);
    }

    /* ExFreePool without a tag, and a repeat alloc/free churn with fragments
     * coalescing back (same size: the pieces must have been returned) */
    {
        ULONG n;

        for (n = 0; n < 20000; n++)
        {
            Buffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, 1 + (n % 300), TAG_CALIGN);
            if (!Buffer)
                break;
            if (((ULONG_PTR)Buffer & (Align - 1)) != 0)
                break;
            ExFreePool(Buffer);
        }
        ok_eq_ulong(n, 20000UL);
    }
}
