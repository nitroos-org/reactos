/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: debugger memory copies and page table entries of high physical addresses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>
#include <ndk/kdfuncs.h>

/*
 * The debugger's memory copy (KdSystemDebugControl -> MmDbgCopyMemory) of
 * RAM above 4 GiB: physical reads and writes, and a virtual write to a
 * read-only page, which the memory manager turns into a physical copy of the
 * page frame it reads from the PTE. Then MmMapIoSpace of the highest pages
 * the processor can address: the PTE must give back every bit of the frame.
 * The debugger part needs an active kernel debugger (Vista and later refuse
 * the commands otherwise) and RAM above 4 GiB; it is skipped without them.
 */
#define TEST_PAGES 8
#define FOUR_GB    0x100000000ULL

static
NTSTATUS
(NTAPI *pKdSystemDebugControl)(
    _In_ SYSDBG_COMMAND Command,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Inout_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE PreviousMode);

static
ULONG
MaxPhysicalAddressBits(VOID)
{
#if defined(_M_AMD64) || defined(_M_IX86)
    int Regs[4];

    __cpuid(Regs, 0x80000000);
    if ((ULONG)Regs[0] < 0x80000008)
        return 36;
    __cpuid(Regs, 0x80000008);
    return (ULONG)Regs[0] & 0xFF;
#else
    return 32;
#endif
}

static
NTSTATUS
DbgPhysical(
    _In_ BOOLEAN Write,
    _In_ ULONG64 Address,
    _Inout_ PULONG64 Value)
{
    SYSDBG_PHYSICAL Request;
    ULONG Length = 0;

    Request.Address.QuadPart = Address;
    Request.Buffer = Value;
    Request.Request = sizeof(*Value);
    return pKdSystemDebugControl(Write ? SysDbgWritePhysical : SysDbgReadPhysical,
                                 &Request, sizeof(Request), NULL, 0, &Length, KernelMode);
}

static
NTSTATUS
DbgVirtual(
    _In_ BOOLEAN Write,
    _In_ PVOID Address,
    _Inout_ PULONG64 Value)
{
    SYSDBG_VIRTUAL Request;
    ULONG Length = 0;

    Request.Address = Address;
    Request.Buffer = Value;
    Request.Request = sizeof(*Value);
    return pKdSystemDebugControl(Write ? SysDbgWriteVirtual : SysDbgReadVirtual,
                                 &Request, sizeof(Request), NULL, 0, &Length, KernelMode);
}

static
ULONG64
Pattern(
    _In_ ULONG64 Physical)
{
    return (Physical * 0x9E3779B97F4A7C15ULL) ^ 0x5A5A5A5A5A5A5A5AULL;
}

/* The debugger's virtual copy of an address that no page table entry is indexed by, and of device memory,
 * is refused; a copy of ordinary memory is not */
static
VOID
TestDebuggerRefusals(VOID)
{
    static const ULONG64 Known = 0x1122334455667788ULL;
    PHYSICAL_ADDRESS Apic;
    ULONG64 Value;
    NTSTATUS Status;
    PVOID Va;

    Value = 0;
    Status = DbgVirtual(FALSE, (PVOID)&Known, &Value);
    ok(NT_SUCCESS(Status) && Value == Known, "Virtual read of %p: %lx, %I64x\n", &Known, Status, Value);

    /* A user address of the calling process is read as before */
    {
        PVOID UserVa = NULL;
        SIZE_T UserSize = PAGE_SIZE;

        Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &UserVa, 0, &UserSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!skip(NT_SUCCESS(Status), "No user memory: %lx\n", Status))
        {
            KmtStartSeh()
                *(volatile ULONG64 *)UserVa = Known;
            KmtEndSeh(STATUS_SUCCESS)
            Value = 0;
            Status = DbgVirtual(FALSE, UserVa, &Value);
            ok(NT_SUCCESS(Status) && Value == Known, "Virtual read of the user address %p: %lx, %I64x\n", UserVa, Status, Value);
            UserSize = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &UserVa, &UserSize, MEM_RELEASE);
        }
    }

#ifdef _M_AMD64
    /* Canonical addresses with the high bits of a non-canonical one: the same page tables entries, another address */
    Value = 0xD1D2D3D4D5D6D7D8ULL;
    Status = DbgVirtual(FALSE, (PVOID)((ULONG_PTR)&Known ^ 0x0000800000000000ULL), &Value);
    ok(!NT_SUCCESS(Status), "Virtual read of the non-canonical %p succeeded\n", (PVOID)((ULONG_PTR)&Known ^ 0x0000800000000000ULL));
    ok(Value == 0xD1D2D3D4D5D6D7D8ULL, "A refused read changed the buffer: %I64x\n", Value);
    Status = DbgVirtual(FALSE, (PVOID)0x0000F80003000000ULL, &Value);
    ok(!NT_SUCCESS(Status), "Virtual read of the non-canonical 0000F80003000000 succeeded\n");
#endif

    /* The local APIC page: mapped, never read through the debugger */
    Apic.QuadPart = 0xFEE00000;
    Va = MmMapIoSpace(Apic, PAGE_SIZE, MmNonCached);
    if (!skip(Va != NULL, "The local APIC page cannot be mapped\n"))
    {
        Value = 0xD1D2D3D4D5D6D7D8ULL;
        Status = DbgVirtual(FALSE, Va, &Value);
        ok(!NT_SUCCESS(Status), "Virtual read of the mapped local APIC page %p succeeded: %I64x\n", Va, Value);
        ok(Value == 0xD1D2D3D4D5D6D7D8ULL, "A refused read changed the buffer: %I64x\n", Value);
        MmUnmapIoSpace(Va, PAGE_SIZE);
    }
}

static
VOID
TestDebuggerCopies(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"KdSystemDebugControl");
    PHYSICAL_ADDRESS Low, High, Skip;
    ULONG64 Version[5]; /* DBGKD_GET_VERSION64: 40 bytes */
    PPFN_NUMBER Pfns;
    PULONG64 Va;
    NTSTATUS Status;
    ULONG i, j, Length = 0, Tested = 0;
    PMDL Mdl;

    pKdSystemDebugControl = MmGetSystemRoutineAddress(&Name);
    if (skip(pKdSystemDebugControl != NULL, "KdSystemDebugControl is not exported\n"))
        return;
    Status = pKdSystemDebugControl(SysDbgQueryVersion, NULL, 0, Version, sizeof(Version), &Length, KernelMode);
    if (skip(NT_SUCCESS(Status), "No active kernel debugger (SysDbgQueryVersion: %lx)\n", Status))
        return;

    TestDebuggerRefusals();

    /* Pages of RAM above 4 GiB */
    Low.QuadPart = FOUR_GB;
    High.QuadPart = -1;
    Skip.QuadPart = 0;
    Mdl = MmAllocatePagesForMdlEx(Low, High, Skip, TEST_PAGES * PAGE_SIZE, MmCached, 0);
    if (skip(Mdl != NULL, "No RAM above 4 GiB\n"))
        return;
    if (skip(MmGetMdlByteCount(Mdl) == TEST_PAGES * PAGE_SIZE, "Only %lu bytes of RAM above 4 GiB\n", MmGetMdlByteCount(Mdl)))
    {
        MmFreePagesFromMdl(Mdl);
        ExFreePool(Mdl);
        return;
    }
    Va = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    ok(Va != NULL, "Mapping the pages failed\n");
    if (!Va)
    {
        MmFreePagesFromMdl(Mdl);
        ExFreePool(Mdl);
        return;
    }
    Pfns = MmGetMdlPfnArray(Mdl);
    for (i = 0; i < TEST_PAGES; i++)
    {
        PULONG64 Page = (PULONG64)((PUCHAR)Va + i * PAGE_SIZE);
        ULONG64 Physical = (ULONG64)Pfns[i] << PAGE_SHIFT;

        for (j = 0; j < PAGE_SIZE / sizeof(ULONG64); j++)
            Page[j] = Pattern(Physical + j * sizeof(ULONG64));
    }

    for (i = 0; i < TEST_PAGES; i++)
    {
        PULONG64 Page = (PULONG64)((PUCHAR)Va + i * PAGE_SIZE);
        ULONG64 Physical = (ULONG64)Pfns[i] << PAGE_SHIFT;
        ULONG64 Value, Marker;
        PMMPTE PointerPte;
        MMPTE Saved;

        ok(Physical >= FOUR_GB, "Page %lu at %I64x is below 4 GiB\n", i, Physical);
        ok(MmGetPhysicalAddress(Page).QuadPart == (LONGLONG)Physical,
           "Page %lu: MmGetPhysicalAddress %I64x, expected %I64x\n", i, MmGetPhysicalAddress(Page).QuadPart, Physical);
        trace("Page %lu: %p -> %I64x\n", i, Page, Physical);

        /* Physical read at the start, the middle and the end of the page */
        for (j = 0; j < PAGE_SIZE / sizeof(ULONG64); j += 255)
        {
            Value = 0;
            Status = DbgPhysical(FALSE, Physical + j * sizeof(ULONG64), &Value);
            ok(NT_SUCCESS(Status), "Physical read of %I64x: %lx\n", Physical + j * 8, Status);
            ok(Value == Pattern(Physical + j * sizeof(ULONG64)), "Physical read of %I64x gives %I64x, expected %I64x\n",
               Physical + j * 8, Value, Pattern(Physical + j * sizeof(ULONG64)));
        }

        /* Physical write: seen through the mapping */
        Marker = 0xD1D0000000000000ULL | Physical | 0x10;
        Status = DbgPhysical(TRUE, Physical + 0x10, &Marker);
        ok(NT_SUCCESS(Status), "Physical write of %I64x: %lx\n", Physical + 0x10, Status);
        ok(Page[2] == Marker, "Physical write of %I64x: the page reads %I64x, expected %I64x\n", Physical + 0x10, Page[2], Marker);

#ifdef _M_AMD64
        /* Virtual write to a read-only page: the debugger copies through the frame number of the PTE */
        PointerPte = (PMMPTE)(PTE_BASE + (((ULONG64)Page >> (PTI_SHIFT - 3)) & (0xFFFFFFFFFULL << 3)));
        Saved = *PointerPte;
        ok((Saved.u.Long & 1) != 0, "PTE of %p is not valid: %I64x\n", Page, Saved.u.Long);
        if (Saved.u.Long & 1)
        {
            ok((Saved.u.Long & 0x000FFFFFFFFFF000ULL) == Physical, "PTE %I64x does not hold %I64x\n", Saved.u.Long, Physical);
            /* Hardware write bit (1) and the software write bit (11) off */
            InterlockedExchange64((PLONG64)&PointerPte->u.Long, (LONG64)(Saved.u.Long & ~0x802ULL));
            __invlpg(Page);
            Marker = 0xD1D1000000000000ULL | Physical | 0x20;
            Status = DbgVirtual(TRUE, &Page[4], &Marker);
            ok(NT_SUCCESS(Status), "Virtual write to the read-only %p (%I64x): %lx\n", &Page[4], Physical + 0x20, Status);
            ok(Page[4] == Marker, "Virtual write to the read-only %p (%I64x): the page reads %I64x, expected %I64x\n",
               &Page[4], Physical + 0x20, Page[4], Marker);
            Value = 0;
            Status = DbgVirtual(FALSE, &Page[4], &Value);
            ok(NT_SUCCESS(Status) && Value == Marker, "Virtual read back of %p: %lx, %I64x\n", &Page[4], Status, Value);
            InterlockedExchange64((PLONG64)&PointerPte->u.Long, (LONG64)Saved.u.Long);
            __invlpg(Page);
        }
#else
        UNREFERENCED_PARAMETER(PointerPte);
        UNREFERENCED_PARAMETER(Saved);
#endif

        /* Nothing else of the page changed */
        for (j = 0; j < PAGE_SIZE / sizeof(ULONG64); j++)
        {
            if (j == 2 || j == 4)
                continue;
            if (Page[j] != Pattern(Physical + j * sizeof(ULONG64)))
                break;
        }
        ok(j == PAGE_SIZE / sizeof(ULONG64), "Page %lu (%I64x) changed at word %lu\n", i, Physical, j);
        Tested++;
    }
    trace("%lu pages above 4 GiB through the debugger copy\n", Tested);

    /* Device memory (no PFN database entry): the debugger refuses it, it does not map another page */
    {
        ULONG64 Value = 0;
        ULONG64 Address = 1ULL << (MaxPhysicalAddressBits() - 1);

        Status = DbgPhysical(FALSE, Address, &Value);
        trace("Physical read of %I64x (no RAM): %lx\n", Address, Status);
        ok(!NT_SUCCESS(Status), "Physical read of %I64x (no RAM) succeeded: %I64x\n", Address, Value);
    }

    MmUnmapLockedPages(Va, Mdl);
    MmFreePagesFromMdl(Mdl);
    ExFreePool(Mdl);
}

static
VOID
TestTopPages(VOID)
{
#ifdef _M_AMD64
    ULONG Bits = MaxPhysicalAddressBits();
    ULONG64 Top = (1ULL << Bits) - PAGE_SIZE;
    ULONG64 Probes[3];
    PHYSICAL_ADDRESS Phys;
    PVOID Va;
    ULONG i;

    /* The highest page, a page with every frame bit set below it, and one just above 1 TiB: mapped, never touched */
    Probes[0] = Top;
    Probes[1] = (Top & ~0x5555555555000ULL) | 0x1000;
    Probes[2] = (1ULL << 40) + 0x1000;
    for (i = 0; i < RTL_NUMBER_OF(Probes); i++)
    {
        if (Probes[i] > Top)
            continue;
        Phys.QuadPart = Probes[i];
        Va = MmMapIoSpace(Phys, PAGE_SIZE, MmNonCached);
        ok(Va != NULL, "MmMapIoSpace(%I64x) failed (MAXPHYADDR %lu)\n", Probes[i], Bits);
        if (Va)
        {
            ok(MmGetPhysicalAddress(Va).QuadPart == (LONGLONG)Probes[i], "MmGetPhysicalAddress gives %I64x, expected %I64x\n",
               MmGetPhysicalAddress(Va).QuadPart, Probes[i]);
            MmUnmapIoSpace(Va, PAGE_SIZE);
        }
    }

    /* A range that ends past the highest page is refused */
    Phys.QuadPart = Top;
    Va = MmMapIoSpace(Phys, 2 * PAGE_SIZE, MmNonCached);
    ok(Va == NULL, "MmMapIoSpace(%I64x, 2 pages) past MAXPHYADDR %lu returned %p\n", Top, Bits, Va);
    if (Va) MmUnmapIoSpace(Va, 2 * PAGE_SIZE);
    trace("MAXPHYADDR %lu, highest page %I64x\n", Bits, Top);
#endif
}

START_TEST(MmDbgCopyHigh)
{
    TestTopPages();
    TestDebuggerCopies();
}
