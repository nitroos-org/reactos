/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: contiguous allocations while private pages wait on standby (kernel part)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Run by MmContiguousStandby_user.c after it put many private pages of its own on standby. First page
 * MDLs from a physical range (MmAllocatePagesForMdl with a low limit), then non-cached contiguous blocks
 * (no nonpaged pool attempt: the physical page search at once) until the search fails or a size limit
 * is reached; the first word of each page is written, then everything is freed. A page
 * taken from standby would be a page its process can still fault back: the user part checks its data.
 */
#define BLOCK_SIZE (64 * 1024)
#define MDL_CHUNK  (32 * 1024 * 1024)

START_TEST(MmContiguousStandby)
{
    PHYSICAL_ADDRESS Low, High, Boundary;
    SYSTEM_BASIC_INFORMATION Info;
    PVOID *Blocks;
    ULONG Count = 0, Max, i, MdlCount;
    PMDL Mdls[64];
    PHYSICAL_ADDRESS MdlLow;

    Low.QuadPart = 0;
    High.QuadPart = MAXLONGLONG;
    Boundary.QuadPart = 0;
    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemBasicInformation, &Info, sizeof(Info), NULL)))
    {
        skip(FALSE, "no basic information\n");
        return;
    }
    /* 60 percent of the memory, at most 256 MB (64 MB of 32-bit system address space): the test must end
       within the 30 s the user part waits for it on a checked build, and the blocks are mapped all at once */
    Max = (ULONG)(((ULONGLONG)Info.NumberOfPhysicalPages * PAGE_SIZE / BLOCK_SIZE) * 6 / 10);
    Max = min(Max, (ULONG)((sizeof(PVOID) == 4 ? 64 : 256) * 1024 * 1024 / BLOCK_SIZE));
    Blocks = ExAllocatePoolWithTag(NonPagedPool, Max * sizeof(PVOID), 'tSCM');
    if (!Blocks)
    {
        skip(FALSE, "no pool for %lu block pointers\n", Max);
        return;
    }
    /*
     * The physical-range search of MmAllocatePagesForMdl (a low limit of 1 MB): chunks of 32 MB, the first
     * word of each page written through a mapping, up to 45 percent of the physical memory (more than is free
     * after the user part: the range reaches the standby pages), kept until the end
     */
    MdlCount = 0;
    MdlLow.QuadPart = 1024 * 1024;
    while (MdlCount < RTL_NUMBER_OF(Mdls) &&
           (ULONGLONG)(MdlCount + 1) * MDL_CHUNK <= (ULONGLONG)Info.NumberOfPhysicalPages * PAGE_SIZE * 45 / 100)
    {
        PMDL Mdl = MmAllocatePagesForMdl(MdlLow, High, Boundary, MDL_CHUNK);
        PUCHAR Va;
        ULONG Bytes;

        if (!Mdl)
            break;
        Bytes = MmGetMdlByteCount(Mdl);
        Va = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (Va)
        {
            for (i = 0; i < Bytes / PAGE_SIZE; i++)
                *(volatile ULONG_PTR *)(Va + i * PAGE_SIZE) = (ULONG_PTR)0xDDDDDDDDDDDDDDDDULL;
            MmUnmapLockedPages(Va, Mdl);
        }
        Mdls[MdlCount++] = Mdl;
        if (Bytes < MDL_CHUNK)
            break;
    }
    trace("%lu page MDLs from a physical range\n", MdlCount);
    DbgPrint("MmContiguousStandby: %lu page MDLs of up to 32 MB from a physical range\n", MdlCount);

    while (Count < Max)
    {
        PVOID Block = MmAllocateContiguousMemorySpecifyCache(BLOCK_SIZE, Low, High, Boundary, MmNonCached);
        if (!Block)
            break;
        /* The first word of each page: the one the user part checks first (non-cached writes are slow) */
        for (i = 0; i < BLOCK_SIZE / PAGE_SIZE; i++)
            *(volatile ULONG_PTR *)((PUCHAR)Block + i * PAGE_SIZE) = (ULONG_PTR)0xCCCCCCCCCCCCCCCCULL;
        Blocks[Count++] = Block;
    }
    trace("%lu contiguous blocks of 64 KB (at most %lu)\n", Count, Max);
    DbgPrint("MmContiguousStandby: %lu contiguous blocks of 64 KB (at most %lu)\n", Count, Max);
    ok(Count > 0, "no contiguous block at all\n");
    for (i = 0; i < Count; i++)
        MmFreeContiguousMemorySpecifyCache(Blocks[i], BLOCK_SIZE, MmNonCached);
    for (i = 0; i < MdlCount; i++)
    {
        MmFreePagesFromMdl(Mdls[i]);
        ExFreePool(Mdls[i]);
    }
    ExFreePoolWithTag(Blocks, 'tSCM');
}
