/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: MDL mapping sequences must give back every system PTE
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Each sequence below is repeated ITERATIONS times; the free system PTE count
 * (SystemPerformanceInformation.FreeSystemPtes) afterwards must be what it was before,
 * within a small slack for PTEs other kernel activity takes in between.
 * A sequence that leaked one mapping per round would lose at least ITERATIONS PTEs.
 */
#define ITERATIONS  64
#define SLACK_PTES  32
#define MDL_BYTES   (2 * 1024 * 1024)

static
ULONG
FreeSystemPtes(VOID)
{
    SYSTEM_PERFORMANCE_INFORMATION Perf;

    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemPerformanceInformation, &Perf, sizeof(Perf), NULL)))
        return 0;
    return Perf.FreeSystemPtes;
}

static
VOID
CheckLeak(
    _In_ PCSTR Name,
    _In_ ULONG Before)
{
    ULONG After = FreeSystemPtes();
    LONG Lost = (LONG)Before - (LONG)After;

    trace("%s: free system PTEs %lu -> %lu\n", Name, Before, After);
    ok(Lost <= SLACK_PTES, "%s: lost %ld system PTEs over %d rounds\n", Name, Lost, ITERATIONS);
}

static
VOID
TestAllocatePagesMapUnmap(
    _In_ MEMORY_CACHING_TYPE CacheType,
    _In_ PCSTR Name)
{
    PHYSICAL_ADDRESS Low, High, Skip;
    ULONG Before, i;

    Low.QuadPart = 0;
    High.QuadPart = -1;
    Skip.QuadPart = 0;

    Before = FreeSystemPtes();
    for (i = 0; i < ITERATIONS; i++)
    {
        PMDL Mdl = MmAllocatePagesForMdl(Low, High, Skip, MDL_BYTES);
        PVOID Va;

        if (!Mdl)
            break;
        Va = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, CacheType, NULL, FALSE, NormalPagePriority);
        if (Va)
            MmUnmapLockedPages(Va, Mdl);
        MmFreePagesFromMdl(Mdl);
        ExFreePoolWithTag(Mdl, 0);
    }
    ok(i == ITERATIONS, "%s: only %lu rounds ran\n", Name, i);
    CheckLeak(Name, Before);
}

static
VOID
TestNonPagedPoolMap(VOID)
{
    ULONG Before, i;
    PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, 64 * 1024, 'tPSM');

    if (skip(Buffer != NULL, "No pool\n"))
        return;

    Before = FreeSystemPtes();
    for (i = 0; i < ITERATIONS; i++)
    {
        PMDL Mdl = IoAllocateMdl(Buffer, 64 * 1024, FALSE, FALSE, NULL);

        if (!Mdl)
            break;
        /* The MDL already carries a system VA: asking for it must not take a PTE */
        MmBuildMdlForNonPagedPool(Mdl);
        (void)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        IoFreeMdl(Mdl);
    }
    ok(i == ITERATIONS, "NonPagedPool: only %lu rounds ran\n", i);
    CheckLeak("NonPagedPool", Before);
    ExFreePoolWithTag(Buffer, 'tPSM');
}

static
VOID
TestProbeAndLockMap(VOID)
{
    ULONG Before, i;
    PVOID Buffer = ExAllocatePoolWithTag(PagedPool, 64 * 1024, 'tPSM');

    if (skip(Buffer != NULL, "No pool\n"))
        return;
    RtlZeroMemory(Buffer, 64 * 1024);

    Before = FreeSystemPtes();
    for (i = 0; i < ITERATIONS; i++)
    {
        PMDL Mdl = IoAllocateMdl(Buffer, 64 * 1024, FALSE, FALSE, NULL);
        PVOID Va;

        if (!Mdl)
            break;
        MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
        Va = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (Va)
            MmUnmapLockedPages(Va, Mdl);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
    ok(i == ITERATIONS, "ProbeAndLock: only %lu rounds ran\n", i);
    CheckLeak("ProbeAndLock", Before);
    ExFreePoolWithTag(Buffer, 'tPSM');
}

static
VOID
TestReservedMapping(VOID)
{
    PHYSICAL_ADDRESS Low, High, Skip;
    ULONG Before, i;
    const ULONG PoolTag = 'tPSM';

    Low.QuadPart = 0;
    High.QuadPart = -1;
    Skip.QuadPart = 0;

    Before = FreeSystemPtes();
    for (i = 0; i < ITERATIONS; i++)
    {
        PVOID Mapping = MmAllocateMappingAddress(16 * PAGE_SIZE, PoolTag);
        PMDL Mdl;
        PVOID Va;

        if (!Mapping)
            break;
        Mdl = MmAllocatePagesForMdl(Low, High, Skip, 4 * PAGE_SIZE);
        if (Mdl)
        {
            Va = MmMapLockedPagesWithReservedMapping(Mapping, PoolTag, Mdl, MmCached);
            if (Va)
                MmUnmapReservedMapping(Va, PoolTag, Mdl);
            MmFreePagesFromMdl(Mdl);
            ExFreePoolWithTag(Mdl, 0);
        }
        MmFreeMappingAddress(Mapping, PoolTag);
    }
    ok(i == ITERATIONS, "ReservedMapping: only %lu rounds ran\n", i);
    CheckLeak("ReservedMapping", Before);
}

static
VOID
TestMapIoSpace(VOID)
{
    PHYSICAL_ADDRESS Max, Pa;
    ULONG Before, i;
    PVOID Block;

    Max.QuadPart = -1;
    Block = MmAllocateContiguousMemory(PAGE_SIZE * 4, Max);
    if (skip(Block != NULL, "No contiguous memory\n"))
        return;
    Pa = MmGetPhysicalAddress(Block);

    Before = FreeSystemPtes();
    for (i = 0; i < ITERATIONS; i++)
    {
        PVOID Va = MmMapIoSpace(Pa, 4 * PAGE_SIZE, MmNonCached);

        if (!Va)
            break;
        MmUnmapIoSpace(Va, 4 * PAGE_SIZE);
    }
    ok(i == ITERATIONS, "MapIoSpace: only %lu rounds ran\n", i);
    CheckLeak("MapIoSpace", Before);
    MmFreeContiguousMemory(Block);
}

static
VOID
TestContiguous(VOID)
{
    PHYSICAL_ADDRESS Low, High, Boundary;
    ULONG Before, i;

    Low.QuadPart = 0;
    High.QuadPart = -1;
    Boundary.QuadPart = 0;

    Before = FreeSystemPtes();
    for (i = 0; i < ITERATIONS; i++)
    {
        PVOID Block = MmAllocateContiguousMemorySpecifyCache(256 * 1024, Low, High, Boundary, MmNonCached);

        if (!Block)
            break;
        MmFreeContiguousMemorySpecifyCache(Block, 256 * 1024, MmNonCached);
    }
    ok(i == ITERATIONS, "Contiguous: only %lu rounds ran\n", i);
    CheckLeak("Contiguous", Before);
}

START_TEST(MmSystemPtes)
{
    if (!FreeSystemPtes())
    {
        skip(FALSE, "this kernel does not report free system PTEs\n");
        return;
    }

    TestAllocatePagesMapUnmap(MmCached, "AllocatePages/cached");
    TestAllocatePagesMapUnmap(MmNonCached, "AllocatePages/noncached");
    TestAllocatePagesMapUnmap(MmWriteCombined, "AllocatePages/writecombined");
    TestNonPagedPoolMap();
    TestProbeAndLockMap();
    TestReservedMapping();
    TestMapIoSpace();
    TestContiguous();
}
