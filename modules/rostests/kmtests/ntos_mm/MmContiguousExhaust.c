/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: non-cached contiguous allocations until they fail must not leak pages
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Allocates non-cached contiguous blocks until one fails (no system PTEs left on 32-bit, no
 * contiguous run left otherwise) and frees them all. The failing allocation must return NULL (and
 * not assert on a debug build) and give back every physical page it had taken: the number of
 * available pages afterwards must be what it was before.
 */
#define BLOCK_SIZE  (256 * 1024)
#define MAX_BYTES   ((ULONGLONG)1024 * 1024 * 1024)
#define SLACK_PAGES 512

static
ULONG
AvailablePages(VOID)
{
    SYSTEM_PERFORMANCE_INFORMATION Perf;

    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemPerformanceInformation, &Perf, sizeof(Perf), NULL)))
        return 0;
    return Perf.AvailablePages;
}

START_TEST(MmContiguousExhaust)
{
    PHYSICAL_ADDRESS Low, High, Boundary;
    PVOID *Blocks;
    ULONG Count = 0, Max, i, Before, During, After;
    PVOID Extra;

    Low.QuadPart = 0;
    High.QuadPart = MAXLONGLONG;
    Boundary.QuadPart = 0;

    Max = (ULONG)(MAX_BYTES / BLOCK_SIZE);
    Blocks = ExAllocatePoolWithTag(NonPagedPool, Max * sizeof(PVOID), 'xEMC');
    if (!Blocks)
    {
        skip(FALSE, "no pool for %lu block pointers\n", Max);
        return;
    }

    Before = AvailablePages();
    if (!Before)
    {
        skip(FALSE, "no performance information\n");
        ExFreePoolWithTag(Blocks, 'xEMC');
        return;
    }

    while (Count < Max)
    {
        PVOID Block = MmAllocateContiguousMemorySpecifyCache(BLOCK_SIZE, Low, High, Boundary, MmNonCached);
        if (!Block)
            break;
        *(volatile ULONG_PTR *)Block = (ULONG_PTR)Count;
        Blocks[Count++] = Block;
    }
    During = AvailablePages();
    DbgPrint("MmContiguousExhaust: %lu blocks of %u KB, ended %s, available pages %lu -> %lu\n",
             Count, BLOCK_SIZE / 1024, Count == Max ? "at the limit" : "by a failed allocation",
             Before, During);
    ok(Count > 0, "no contiguous block at all\n");

    /* Failing again must stay clean and take nothing */
    if (Count < Max)
    {
        Extra = MmAllocateContiguousMemorySpecifyCache(BLOCK_SIZE, Low, High, Boundary, MmNonCached);
        ok(Extra == NULL, "allocation after the failure returned %p\n", Extra);
        if (Extra)
            MmFreeContiguousMemorySpecifyCache(Extra, BLOCK_SIZE, MmNonCached);
        ok(AvailablePages() + SLACK_PAGES >= During, "failed allocations took pages: %lu -> %lu\n",
           During, AvailablePages());
    }

    for (i = 0; i < Count; i++)
    {
        ok(*(volatile ULONG_PTR *)Blocks[i] == (ULONG_PTR)i, "block %lu lost its data\n", i);
        MmFreeContiguousMemorySpecifyCache(Blocks[i], BLOCK_SIZE, MmNonCached);
    }
    ExFreePoolWithTag(Blocks, 'xEMC');

    After = AvailablePages();
    DbgPrint("MmContiguousExhaust: available pages after freeing %lu (before %lu)\n", After, Before);
    ok(After + SLACK_PAGES >= Before, "pages leaked: %lu available before, %lu after\n", Before, After);

    /* The memory can be had again */
    Extra = MmAllocateContiguousMemorySpecifyCache(BLOCK_SIZE, Low, High, Boundary, MmNonCached);
    ok(Extra != NULL, "no block after freeing everything\n");
    if (Extra)
        MmFreeContiguousMemorySpecifyCache(Extra, BLOCK_SIZE, MmNonCached);
}
