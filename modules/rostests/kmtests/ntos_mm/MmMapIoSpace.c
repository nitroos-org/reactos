/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite: MmMapIoSpace of device memory anywhere the processor can address
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Every 64-bit memory BAR found on the PCI buses is mapped with MmMapIoSpace,
 * read through the mapping, translated back with MmGetPhysicalAddress, mapped
 * again through an MDL and through a view of \Device\PhysicalMemory, and
 * unmapped. Firmware puts such BARs above 1 TiB on machines with a wide
 * physical address (QEMU -cpu host with 3 GB of RAM or more). A QEMU
 * ivshmem-plain device (shared memory BAR 2, 1af4:1110) is also written:
 * the first and the last page of the BAR get a pattern the host can check in
 * the memory backend file. Then 10000 map/unmap rounds must give back every
 * system PTE.
 */
#define IVSHMEM_VENDOR  0x1AF4
#define IVSHMEM_DEVICE  0x1110
#define MAX_BARS        32
#define ROUNDS          10000
#define SLACK_PTES      32

typedef struct _FOUND_BAR
{
    ULONG Bus;
    ULONG Slot;
    USHORT VendorId;
    USHORT DeviceId;
    ULONG Index;
    ULONG64 Address;
    ULONG64 Size;
} FOUND_BAR, *PFOUND_BAR;

static FOUND_BAR Bars[MAX_BARS];
static ULONG BarCount;

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
ULONG
MaxPhysicalAddressBits(VOID)
{
    int Regs[4];

    __cpuid(Regs, 0x80000000);
    if ((ULONG)Regs[0] < 0x80000008)
        return 36;
    __cpuid(Regs, 0x80000008);
    return (ULONG)Regs[0] & 0xFF;
}

/* Size of a 64-bit memory BAR, read the way firmware sizes it, with memory decoding off meanwhile */
static
ULONG64
SizeBar64(
    _In_ ULONG Bus,
    _In_ ULONG Slot,
    _In_ ULONG Offset)
{
    ULONG Low, High, AllOnes = 0xFFFFFFFF, SizeLow, SizeHigh;
    USHORT Command, Off;
    ULONG64 Mask;

    HalGetBusDataByOffset(PCIConfiguration, Bus, Slot, &Command, 4, sizeof(Command));
    Off = Command & ~2;
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot, &Off, 4, sizeof(Off));
    HalGetBusDataByOffset(PCIConfiguration, Bus, Slot, &Low, Offset, sizeof(Low));
    HalGetBusDataByOffset(PCIConfiguration, Bus, Slot, &High, Offset + 4, sizeof(High));
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot, &AllOnes, Offset, sizeof(AllOnes));
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot, &AllOnes, Offset + 4, sizeof(AllOnes));
    HalGetBusDataByOffset(PCIConfiguration, Bus, Slot, &SizeLow, Offset, sizeof(SizeLow));
    HalGetBusDataByOffset(PCIConfiguration, Bus, Slot, &SizeHigh, Offset + 4, sizeof(SizeHigh));
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot, &Low, Offset, sizeof(Low));
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot, &High, Offset + 4, sizeof(High));
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot, &Command, 4, sizeof(Command));

    Mask = ((ULONG64)SizeHigh << 32) | (SizeLow & ~0xFUL);
    if (Mask == 0)
        return 0;
    return ~Mask + 1;
}

static
VOID
FindBars(VOID)
{
    ULONG Bus, Device, Function, i, Length;
    PCI_SLOT_NUMBER Slot;
    PCI_COMMON_CONFIG Config;

    BarCount = 0;
    for (Bus = 0; Bus < 16; Bus++)
    {
        for (Device = 0; Device < PCI_MAX_DEVICES; Device++)
        {
            for (Function = 0; Function < PCI_MAX_FUNCTION; Function++)
            {
                Slot.u.AsULONG = 0;
                Slot.u.bits.DeviceNumber = Device;
                Slot.u.bits.FunctionNumber = Function;
                Length = HalGetBusDataByOffset(PCIConfiguration, Bus, Slot.u.AsULONG,
                                               &Config, 0, PCI_COMMON_HDR_LENGTH);
                if (Length < PCI_COMMON_HDR_LENGTH || Config.VendorID == PCI_INVALID_VENDORID)
                {
                    if (Function == 0) break;
                    continue;
                }
                if (PCI_CONFIGURATION_TYPE(&Config) != PCI_DEVICE_TYPE)
                    continue;

                for (i = 0; i < PCI_TYPE0_ADDRESSES; i++)
                {
                    ULONG Bar = Config.u.type0.BaseAddresses[i];

                    if ((Bar & PCI_ADDRESS_IO_SPACE) ||
                        ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) != PCI_TYPE_64BIT) ||
                        (i + 1 >= PCI_TYPE0_ADDRESSES))
                    {
                        continue;
                    }
                    if (BarCount < MAX_BARS)
                    {
                        PFOUND_BAR Found = &Bars[BarCount];

                        Found->Bus = Bus;
                        Found->Slot = Slot.u.AsULONG;
                        Found->VendorId = Config.VendorID;
                        Found->DeviceId = Config.DeviceID;
                        Found->Index = i;
                        Found->Address = ((ULONG64)Config.u.type0.BaseAddresses[i + 1] << 32) | (Bar & ~0xFUL);
                        /* Sizing turns memory decoding off for a moment: only on the test device, never on a disk controller */
                        if (Config.VendorID == IVSHMEM_VENDOR && Config.DeviceID == IVSHMEM_DEVICE)
                            Found->Size = SizeBar64(Bus, Slot.u.AsULONG, FIELD_OFFSET(PCI_COMMON_CONFIG, u.type0.BaseAddresses[i]));
                        else
                            Found->Size = PAGE_SIZE;
#ifndef _M_AMD64
                        /* No PAE build: nothing at or above 4 GiB can be mapped */
                        if (Found->Address >= 0x100000000ULL)
                        {
                            trace("BAR %lu of %04x:%04x at %I64x: above 4 GiB, skipped on this architecture\n",
                                  i, Config.VendorID, Config.DeviceID, Found->Address);
                            Found->Address = 0;
                        }
#endif
                        if (Found->Address != 0 && Found->Size >= PAGE_SIZE)
                            BarCount++;
                    }
                    i++;
                }
                if (Function == 0 && !(Config.HeaderType & PCI_MULTIFUNCTION))
                    break;
            }
        }
    }
}

static
VOID
TestMdlMapping(
    _In_ PVOID Va,
    _In_ ULONG64 Address)
{
    PMDL Mdl;
    PVOID Va2, UserVa = NULL;
    PPFN_NUMBER Pfns;

    /* MmBuildMdlForNonPagedPool of the mapping: the frame comes back whole, flagged as I/O space */
    Mdl = IoAllocateMdl(Va, PAGE_SIZE, FALSE, FALSE, NULL);
    if (skip(Mdl != NULL, "No MDL\n"))
        return;
    MmBuildMdlForNonPagedPool(Mdl);
    Pfns = MmGetMdlPfnArray(Mdl);
    ok((ULONG64)Pfns[0] == (Address >> PAGE_SHIFT), "MDL PFN %I64x, expected %I64x\n", (ULONG64)Pfns[0], Address >> PAGE_SHIFT);
    ok((Mdl->MdlFlags & MDL_IO_SPACE) != 0, "MDL flags %x: no MDL_IO_SPACE\n", Mdl->MdlFlags);
    ok(MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority) == Va, "System address of the MDL is not the mapping\n");
    IoFreeMdl(Mdl);

    /* A driver's own MDL that names the device page: mapped again for the kernel and for the current process */
    Mdl = IoAllocateMdl(NULL, PAGE_SIZE, FALSE, FALSE, NULL);
    if (skip(Mdl != NULL, "No MDL\n"))
        return;
    MmGetMdlPfnArray(Mdl)[0] = (PFN_NUMBER)(Address >> PAGE_SHIFT);
    Mdl->MdlFlags |= MDL_PAGES_LOCKED | MDL_IO_SPACE;
    Va2 = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    ok(Va2 != NULL, "MmMapLockedPagesSpecifyCache(KernelMode) of %I64x failed\n", Address);
    if (Va2)
    {
        ok(MmGetPhysicalAddress(Va2).QuadPart == (LONGLONG)Address,
           "MDL mapping translates to %I64x, expected %I64x\n", MmGetPhysicalAddress(Va2).QuadPart, Address);
        ok(READ_REGISTER_ULONG((PULONG)Va2) == READ_REGISTER_ULONG((PULONG)Va), "MDL mapping reads differently\n");
        MmUnmapLockedPages(Va2, Mdl);
    }
    _SEH2_TRY
    {
        UserVa = MmMapLockedPagesSpecifyCache(Mdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        UserVa = NULL;
    }
    _SEH2_END;
    ok(UserVa != NULL, "MmMapLockedPagesSpecifyCache(UserMode) of %I64x failed\n", Address);
    if (UserVa)
    {
        ULONG Value = 0;

        _SEH2_TRY
        {
            Value = *(volatile ULONG *)UserVa;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            ok(FALSE, "Reading the user mapping of %I64x raised %lx\n", Address, _SEH2_GetExceptionCode());
        }
        _SEH2_END;
        ok(Value == READ_REGISTER_ULONG((PULONG)Va), "User mapping reads %08lx, the mapping %08lx\n",
           Value, READ_REGISTER_ULONG((PULONG)Va));
        MmUnmapLockedPages(UserVa, Mdl);
    }
    IoFreeMdl(Mdl);
}

static
VOID
TestPhysicalMemoryView(
    _In_ PVOID Va,
    _In_ ULONG64 Address)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Section;
    NTSTATUS Status;
    PVOID View = NULL;
    SIZE_T ViewSize = PAGE_SIZE;
    LARGE_INTEGER Offset;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenSection(&Section, SECTION_MAP_READ | SECTION_MAP_WRITE, &Attributes);
    if (skip(NT_SUCCESS(Status), "Cannot open the physical memory section: %lx\n", Status))
        return;
    Offset.QuadPart = Address;
    Status = ZwMapViewOfSection(Section, ZwCurrentProcess(), &View, 0, PAGE_SIZE, &Offset, &ViewSize,
                                ViewUnmap, 0, PAGE_READWRITE | PAGE_NOCACHE);
    ok(NT_SUCCESS(Status), "View of %I64x: %lx\n", Address, Status);
    if (NT_SUCCESS(Status))
    {
        ULONG Value = 0;

        _SEH2_TRY
        {
            Value = *(volatile ULONG *)View;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            ok(FALSE, "Reading the view of %I64x raised %lx\n", Address, _SEH2_GetExceptionCode());
        }
        _SEH2_END;
        ok(Value == READ_REGISTER_ULONG((PULONG)Va), "View of %I64x reads %08lx, the mapping %08lx\n",
           Address, Value, READ_REGISTER_ULONG((PULONG)Va));
        ZwUnmapViewOfSection(ZwCurrentProcess(), View);
    }
    ZwClose(Section);
}

static
VOID
WritePattern(
    _In_ PULONG Page,
    _In_ ULONG64 Address)
{
    ULONG i;

    /* "MMIOPG" marker, the page's physical address, then a counter the host recomputes */
    WRITE_REGISTER_ULONG(&Page[0], 'OIMM');
    WRITE_REGISTER_ULONG(&Page[1], 'GP');
    WRITE_REGISTER_ULONG(&Page[2], (ULONG)Address);
    WRITE_REGISTER_ULONG(&Page[3], (ULONG)(Address >> 32));
    for (i = 4; i < PAGE_SIZE / sizeof(ULONG); i++)
        WRITE_REGISTER_ULONG(&Page[i], (ULONG)(Address >> PAGE_SHIFT) * 2654435761UL + i);
    for (i = 4; i < PAGE_SIZE / sizeof(ULONG); i++)
    {
        if (READ_REGISTER_ULONG(&Page[i]) != (ULONG)(Address >> PAGE_SHIFT) * 2654435761UL + i)
            break;
    }
    ok(i == PAGE_SIZE / sizeof(ULONG), "Pattern at %I64x reads back wrong at word %lu\n", Address, i);
}

static
VOID
TestBar(
    _In_ PFOUND_BAR Bar)
{
    PHYSICAL_ADDRESS Phys;
    PVOID Va;
    ULONG64 Pages[2];
    ULONG p;
    BOOLEAN Writable = (Bar->VendorId == IVSHMEM_VENDOR && Bar->DeviceId == IVSHMEM_DEVICE && Bar->Index == 2);

    trace("BAR %lu of %04x:%04x at bus %lu slot %lx: %I64x size %I64x%s\n", Bar->Index, Bar->VendorId, Bar->DeviceId,
          Bar->Bus, Bar->Slot, Bar->Address, Bar->Size, Writable ? " (ivshmem memory, written)" : "");

    Pages[0] = Bar->Address;
    Pages[1] = Bar->Address + Bar->Size - PAGE_SIZE;
    for (p = 0; p < (Writable ? 2 : 1); p++)
    {
        Phys.QuadPart = Pages[p];
        Va = MmMapIoSpace(Phys, PAGE_SIZE, MmNonCached);
        ok(Va != NULL, "MmMapIoSpace(%I64x) failed\n", Pages[p]);
        if (!Va)
            continue;
        ok(MmGetPhysicalAddress(Va).QuadPart == (LONGLONG)Pages[p],
           "MmGetPhysicalAddress gives %I64x, expected %I64x\n", MmGetPhysicalAddress(Va).QuadPart, Pages[p]);
        ok(MmIsAddressValid(Va), "Mapping of %I64x is not valid\n", Pages[p]);
        trace("  %I64x -> %p, first dword %08lx\n", Pages[p], Va, READ_REGISTER_ULONG((PULONG)Va));
        if (Writable)
            WritePattern(Va, Pages[p]);
        TestMdlMapping(Va, Pages[p]);
        TestPhysicalMemoryView(Va, Pages[p]);
        MmUnmapIoSpace(Va, PAGE_SIZE);
    }
}

static
VOID
TestRounds(
    _In_ PFOUND_BAR Bar)
{
    PHYSICAL_ADDRESS Phys;
    ULONG Before, After, i;
    SIZE_T Bytes = (Bar->Size >= 16 * PAGE_SIZE) ? 16 * PAGE_SIZE : PAGE_SIZE;

    Phys.QuadPart = Bar->Address;
    Before = FreeSystemPtes();
    for (i = 0; i < ROUNDS; i++)
    {
        PVOID Va = MmMapIoSpace(Phys, (i & 1) ? Bytes : PAGE_SIZE, MmNonCached);

        if (!Va)
            break;
        MmUnmapIoSpace(Va, (i & 1) ? Bytes : PAGE_SIZE);
    }
    After = FreeSystemPtes();
    ok(i == ROUNDS, "Only %lu of %d map/unmap rounds of %I64x\n", i, ROUNDS, Bar->Address);
    trace("%d map/unmap rounds of %I64x: free system PTEs %lu -> %lu\n", ROUNDS, Bar->Address, Before, After);
    ok((LONG)Before - (LONG)After <= SLACK_PTES, "Lost %ld system PTEs\n", (LONG)Before - (LONG)After);
}

START_TEST(MmMapIoSpace)
{
    ULONG i, Bits, High = 0;

    Bits = MaxPhysicalAddressBits();
    trace("MAXPHYADDR %lu bits\n", Bits);

    FindBars();
    trace("%lu 64-bit memory BARs\n", BarCount);
    for (i = 0; i < BarCount; i++)
    {
        TestBar(&Bars[i]);
        if (Bars[i].Address >= (1ULL << 40)) High++;
    }
    trace("%lu of them at or above 1 TiB\n", High);

    /* The highest BAR gets the rounds */
    if (BarCount)
    {
        PFOUND_BAR Top = &Bars[0];

        for (i = 1; i < BarCount; i++)
            if (Bars[i].Address > Top->Address) Top = &Bars[i];
        TestRounds(Top);
    }

#ifdef _M_AMD64
    /* An address the processor cannot address is refused */
    if (Bits < 52)
    {
        PHYSICAL_ADDRESS Phys;
        PVOID Va;

        Phys.QuadPart = 1ULL << Bits;
        Va = MmMapIoSpace(Phys, PAGE_SIZE, MmNonCached);
        ok(Va == NULL, "MmMapIoSpace(%I64x) beyond MAXPHYADDR returned %p\n", Phys.QuadPart, Va);
        if (Va) MmUnmapIoSpace(Va, PAGE_SIZE);
    }
#endif
}
