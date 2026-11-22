/*
 *  FreeLoader
 *
 *  Copyright (C) 2004  Eric Kohl
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <freeldr.h>
#include <drivers/acpi/acpi.h>

#include <debug.h>
DBG_DEFAULT_CHANNEL(HWDETECT);

BOOLEAN AcpiPresent = FALSE;

BOOLEAN IsAcpiPresent(VOID)
{
    return AcpiPresent;
}

static PRSDP_DESCRIPTOR
FindAcpiBios(VOID)
{
    PUCHAR Ptr;

    /* Find the 'Root System Descriptor Table Pointer' */
    Ptr = (PUCHAR)0xE0000;
    while ((ULONG_PTR)Ptr < 0x100000)
    {
        if (!memcmp(Ptr, "RSD PTR ", 8))
        {
            TRACE("ACPI supported\n");

            return (PRSDP_DESCRIPTOR)Ptr;
        }

        Ptr = (PUCHAR)((ULONG_PTR)Ptr + 0x10);
    }

    TRACE("ACPI not supported\n");

    return NULL;
}


#define ACPI_HEADER_SIZE    36
#define ACPI_MADT_FIXED     44      /* ACPI table header, local APIC address, flags */
#define ACPI_MADT_IOAPIC    1       /* interrupt controller structure type: I/O APIC */
#define ACPI_MAX_TABLE      0x20000 /* sanity limit for the tables that are read */

/*
 * Look through the ACPI tables for an I/O APIC. TRUE only when the root table is valid, every table
 * address in it can be used and no MADT (there may be none at all) has an I/O APIC structure: a
 * PIC-only machine. FALSE whenever anything is unclear. Tables are read at their physical address:
 * the 32-bit loader runs with all memory below 4 GB mapped one to one. The 64-bit loader does not
 * (only the low memory is mapped, a table above it faults), and an x64 system never installs a
 * PIC HAL, so it does not look.
 */
#ifdef _M_IX86
static BOOLEAN
AcpiTablesDescribeNoIoApic(PRSDP_DESCRIPTOR Rsdp)
{
    BOOLEAN IsXsdt = (Rsdp->revision > 0);
    ULONGLONG RootAddress = IsXsdt ? Rsdp->xsdt_physical_address : Rsdp->rsdt_physical_address;
    ULONG EntrySize = IsXsdt ? sizeof(ULONGLONG) : sizeof(ULONG);
    PUCHAR Root, Table;
    ULONG Length, Count, i, Pos;

    if (RootAddress == 0 || RootAddress >= 0x100000000ULL)
        return FALSE;

    Root = (PUCHAR)(ULONG_PTR)RootAddress;
    if (memcmp(Root, IsXsdt ? "XSDT" : "RSDT", 4) != 0)
        return FALSE;
    RtlCopyMemory(&Length, Root + 4, sizeof(Length));
    if (Length < ACPI_HEADER_SIZE || Length > ACPI_MAX_TABLE)
        return FALSE;

    Count = (Length - ACPI_HEADER_SIZE) / EntrySize;
    for (i = 0; i < Count; i++)
    {
        ULONGLONG Address = 0;

        RtlCopyMemory(&Address, Root + ACPI_HEADER_SIZE + i * EntrySize, EntrySize);
        if (Address == 0 || Address >= 0x100000000ULL)
            return FALSE;

        Table = (PUCHAR)(ULONG_PTR)Address;
        if (memcmp(Table, "APIC", 4) != 0)
            continue;

        /* A MADT: any I/O APIC structure ends the search */
        RtlCopyMemory(&Length, Table + 4, sizeof(Length));
        if (Length < ACPI_MADT_FIXED || Length > ACPI_MAX_TABLE)
            return FALSE;
        for (Pos = ACPI_MADT_FIXED; Pos + 2 <= Length; Pos += Table[Pos + 1])
        {
            if (Table[Pos + 1] < 2)
                return FALSE; /* damaged table */
            if (Table[Pos] == ACPI_MADT_IOAPIC)
                return FALSE;
        }
    }

    return TRUE;
}
#else
static BOOLEAN
AcpiTablesDescribeNoIoApic(PRSDP_DESCRIPTOR Rsdp)
{
    UNREFERENCED_PARAMETER(Rsdp);
    return FALSE;
}
#endif

VOID
DetectAcpiBios(PCONFIGURATION_COMPONENT_DATA SystemKey, ULONG *BusNumber)
{
    PCONFIGURATION_COMPONENT_DATA BiosKey;
    PCM_PARTIAL_RESOURCE_LIST PartialResourceList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor;
    PRSDP_DESCRIPTOR Rsdp;
    PACPI_BIOS_DATA AcpiBiosData;
    ULONG TableSize, Size;

    Rsdp = FindAcpiBios();

    if (Rsdp)
    {
        /* Set up the flag in the loader block */
        AcpiPresent = TRUE;

        /* Calculate the table size */
        TableSize = PcBiosMapCount * sizeof(BIOS_MEMORY_MAP) +
            sizeof(ACPI_BIOS_DATA) - sizeof(BIOS_MEMORY_MAP);

        /* Set 'Configuration Data' value */
        Size = FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors[1]) + TableSize;
        PartialResourceList = FrLdrHeapAlloc(Size, TAG_HW_RESOURCE_LIST);
        if (PartialResourceList == NULL)
        {
            ERR("Failed to allocate resource descriptor\n");
            return;
        }

        RtlZeroMemory(PartialResourceList, Size);
        PartialResourceList->Version = 0;
        PartialResourceList->Revision = 0;
        PartialResourceList->Count = 1;

        PartialDescriptor = &PartialResourceList->PartialDescriptors[0];
        PartialDescriptor->Type = CmResourceTypeDeviceSpecific;
        PartialDescriptor->ShareDisposition = CmResourceShareUndetermined;
        PartialDescriptor->u.DeviceSpecificData.DataSize = TableSize;
        if (AcpiTablesDescribeNoIoApic(Rsdp))
        {
            TRACE("The ACPI tables describe no I/O APIC\n");
            PartialDescriptor->u.DeviceSpecificData.Reserved1 = ACPI_BIOS_NODE_NO_IOAPIC;
        }

        /* Fill the table */
        AcpiBiosData = (PACPI_BIOS_DATA)(PartialDescriptor + 1);

        if (Rsdp->revision > 0)
        {
            TRACE("ACPI >1.0, using XSDT address\n");
            AcpiBiosData->RSDTAddress.QuadPart = Rsdp->xsdt_physical_address;
        }
        else
        {
            TRACE("ACPI 1.0, using RSDT address\n");
            AcpiBiosData->RSDTAddress.LowPart = Rsdp->rsdt_physical_address;
        }

        AcpiBiosData->Count = PcBiosMapCount;
        RtlCopyMemory(AcpiBiosData->MemoryMap, PcBiosMemoryMap,
                      PcBiosMapCount * sizeof(BIOS_MEMORY_MAP));

        TRACE("RSDT %p, data size %x\n", Rsdp->rsdt_physical_address,
            TableSize);

        /* Create new bus key */
        FldrCreateComponentKey(SystemKey,
                               AdapterClass,
                               MultiFunctionAdapter,
                               0,
                               0,
                               0xFFFFFFFF,
                               "ACPI BIOS",
                               PartialResourceList,
                               Size,
                               &BiosKey);

        /* Increment bus number */
        (*BusNumber)++;
    }
}

/* EOF */
