/*
 * PROJECT:     FreeLoader
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     GPT partitioning scheme support
 * COPYRIGHT:   Copyright 2026 Justin Miller <justin.miller@reactos.org>
 */

/* INCLUDES ******************************************************************/

#ifndef _M_ARM
// #include <freeldr.h>
#include "part_gpt.h"

// #include <debug.h>
// DBG_DEFAULT_CHANNEL(DISK);


/* FUNCTIONS *****************************************************************/

/*
 * Bounds of the entry array of a table this loader reads. The kernel reader
 * (ntoskrnl/fstub/fstubex.c) refuses tables outside of the same bounds: an
 * entry size other than 128 bytes, fewer than 128 or more than 4096 entries
 * (the specification asks for room for at least 16384 bytes for the array,
 * UEFI 2.10 section 5.3.1; the upper bound keeps a damaged header from
 * making the loader read without limit).
 */
#define GPT_MIN_HEADER_SIZE     92
#define GPT_MIN_ENTRIES         128
#define GPT_MAX_ENTRIES         4096
#define GPT_MAX_U64             ((ULONGLONG)~0ULL)

/* CRC-32 (IEEE 802.3, the one of UEFI 2.10 section 5.3.2 and of RtlComputeCrc32), continued from Crc */
static ULONG
GptCrc32(
    _In_ ULONG Crc,
    _In_reads_bytes_(Length) const UCHAR* Data,
    _In_ ULONG Length)
{
    ULONG Bit;

    Crc = ~Crc;
    while (Length--)
    {
        Crc ^= *Data++;
        for (Bit = 0; Bit < 8; Bit++)
            Crc = (Crc >> 1) ^ (0xEDB88320UL & (0UL - (Crc & 1)));
    }
    return ~Crc;
}

/*
 * Checks the header found in Sector (one logical block of SectorSize bytes of
 * the disk of DiskSectors blocks, 0 when unknown) against the rules of
 * UEFI 2.10 section 5.3.2 (GPT header: HeaderSize between 92 and the block
 * size, HeaderCRC32 over HeaderSize bytes with the field zeroed, MyLBA) and
 * against the bounds above. Nothing in the header is used before it passed.
 */
BOOLEAN
GptCheckHeader(
    _In_reads_bytes_(SectorSize) const UCHAR* Sector,
    _In_ ULONG SectorSize,
    _In_ ULONGLONG DiskSectors,
    _In_ ULONGLONG HeaderLba)
{
    const GPT_TABLE_HEADER* Header = (const GPT_TABLE_HEADER*)Sector;
    static const UCHAR Zero[4] = {0, 0, 0, 0};
    ULONG Crc, EntrySectors;

    if (SectorSize < 512)
        return FALSE;

    /* Signature and revision */
    if (!RtlEqualMemory(Header->Signature, EFI_PARTITION_HEADER_SIGNATURE, 8))
        return FALSE;
    if (Header->Revision != EFI_TABLE_REVISION)
    {
        TRACE("GPT header has unsupported revision: 0x%x\n", Header->Revision);
        return FALSE;
    }

    /* HeaderSize: at least 92 bytes and at most one logical block */
    if (Header->HeaderSize < GPT_MIN_HEADER_SIZE || Header->HeaderSize > SectorSize)
    {
        TRACE("GPT header size %lu is out of range\n", Header->HeaderSize);
        return FALSE;
    }

    /* HeaderCRC32 covers HeaderSize bytes with the CRC field itself taken as zero */
    Crc = GptCrc32(0, Sector, FIELD_OFFSET(GPT_TABLE_HEADER, HeaderCrc32));
    Crc = GptCrc32(Crc, Zero, sizeof(Zero));
    Crc = GptCrc32(Crc, Sector + FIELD_OFFSET(GPT_TABLE_HEADER, Reserved),
                   Header->HeaderSize - FIELD_OFFSET(GPT_TABLE_HEADER, Reserved));
    if (Crc != Header->HeaderCrc32)
    {
        TRACE("GPT header CRC mismatch\n");
        return FALSE;
    }

    /* MyLBA is the block this header was read from */
    if (Header->MyLba != HeaderLba)
        return FALSE;

    /* Entry size and count */
    if (Header->SizeOfPartitionEntry != EFI_PARTITION_ENTRY_SIZE ||
        Header->NumberOfPartitionEntries < GPT_MIN_ENTRIES ||
        Header->NumberOfPartitionEntries > GPT_MAX_ENTRIES)
    {
        TRACE("GPT entry size %lu or count %lu is not supported\n",
              Header->SizeOfPartitionEntry, Header->NumberOfPartitionEntries);
        return FALSE;
    }

    /* The entry array and the usable range lie on the disk (their sizes are known only if the disk size is) */
    EntrySectors = (Header->NumberOfPartitionEntries * EFI_PARTITION_ENTRY_SIZE + SectorSize - 1) / SectorSize;
    if (Header->PartitionEntryLba < 2 ||
        Header->FirstUsableLba < 2 ||
        Header->FirstUsableLba > Header->LastUsableLba)
        return FALSE;
    if (DiskSectors != 0 &&
        (Header->PartitionEntryLba >= DiskSectors ||
         EntrySectors > DiskSectors - Header->PartitionEntryLba ||
         Header->LastUsableLba >= DiskSectors))
        return FALSE;
    /* A block number that cannot be converted to a byte offset */
    if (Header->PartitionEntryLba + EntrySectors > GPT_MAX_U64 / SectorSize ||
        Header->LastUsableLba >= GPT_MAX_U64 / SectorSize)
        return FALSE;

    return TRUE;
}

/* A used entry lies in the usable range of the disk and does not end before it starts (UEFI 2.10 section 5.3.3) */
BOOLEAN
GptCheckEntry(
    _In_ const GPT_TABLE_HEADER* Header,
    _In_ const GPT_PARTITION_ENTRY* Entry)
{
    return (Entry->StartingLba >= Header->FirstUsableLba &&
            Entry->EndingLba >= Entry->StartingLba &&
            Entry->EndingLba <= Header->LastUsableLba);
}

//static // Used also in uefidisk.c
BOOLEAN
DiskReadGptHeader(
    _In_ UCHAR DriveNumber,
    _Out_ PGPT_TABLE_HEADER GptHeader)
{
    GEOMETRY Geometry;
    ULONG SectorSize = 512;
    ULONGLONG DiskSectors = 0;

    if (MachDiskGetDriveGeometry(DriveNumber, &Geometry))
    {
        if (Geometry.BytesPerSector >= 512)
            SectorSize = Geometry.BytesPerSector;
        DiskSectors = Geometry.Sectors;
    }

    /* The header is in the block after the (protective) MBR; DiskReadBuffer holds at least one block */
    if (SectorSize > DiskReadBufferSize)
        return FALSE;
    if (MachDiskReadLogicalSectors(DriveNumber, EFI_HEADER_LOCATION, 1, DiskReadBuffer) &&
        GptCheckHeader((const UCHAR*)DiskReadBuffer, SectorSize, DiskSectors, EFI_HEADER_LOCATION))
    {
        RtlCopyMemory(GptHeader, DiskReadBuffer, sizeof(*GptHeader));
        return TRUE;
    }

    /*
     * The primary header is not usable. As the kernel reader does, use the backup header in the last block
     * of the disk (UEFI 2.10 5.3.2: a copy of the header, with the copy of the entry array before it).
     * Only for a disk that has a protective MBR: a disk that was an GPT disk once and was repartitioned
     * with an MBR by a tool that does not wipe the last block must not become a GPT disk again.
     */
    if (DiskSectors > 2 && MachDiskReadLogicalSectors(DriveNumber, 0ULL, 1, DiskReadBuffer))
    {
        const UCHAR* Mbr = (const UCHAR*)DiskReadBuffer;
        BOOLEAN Protective = FALSE;
        ULONG i;

        /* Boot signature 0xAA55 and a partition entry of the GPT protective type (0xEE) */
        if (Mbr[510] == 0x55 && Mbr[511] == 0xAA)
        {
            for (i = 0; i < 4; i++)
            {
                if (Mbr[446 + 16 * i + 4] == PARTITION_GPT)
                    Protective = TRUE;
            }
        }
        if (Protective &&
            MachDiskReadLogicalSectors(DriveNumber, DiskSectors - 1, 1, DiskReadBuffer) &&
            GptCheckHeader((const UCHAR*)DiskReadBuffer, SectorSize, DiskSectors, DiskSectors - 1))
        {
            RtlCopyMemory(GptHeader, DiskReadBuffer, sizeof(*GptHeader));
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
DiskGetGptPartitionEntry(
    _In_ UCHAR DriveNumber,
    _In_ ULONG SectorSize, // BlockSize
    _In_ ULONG PartitionNumber,
    _Out_ PPARTITION_INFORMATION PartitionEntry)
{
    GPT_TABLE_HEADER GptHeader;
    GPT_PARTITION_ENTRY GptEntry;
    ULONGLONG EntryLba;
    ULONG EntryOffset;
    ULONG EntriesPerBlock;
    GUID UnusedGuid = EFI_PART_TYPE_UNUSED_GUID;
    GUID SystemGuid = EFI_PART_TYPE_EFI_SYSTEM_PART_GUID;

    ASSERT(SectorSize >= 512);

    /* Read GPT header */
    if (!DiskReadGptHeader(DriveNumber, &GptHeader))
        return FALSE;

    /* Validate partition number */
    //if (PartitionNumber == 0 || PartitionNumber > GptHeader.NumberOfPartitionEntries)
    if (!(1 <= PartitionNumber && PartitionNumber <= GptHeader.NumberOfPartitionEntries))
        return FALSE;

    /* Convert to 0-based index */
    ULONG EntryIndex = PartitionNumber - 1;

    /* DiskReadGptHeader refused any other entry size or count: a block holds whole entries and the index is bounded */
    if (SectorSize < GptHeader.SizeOfPartitionEntry)
        return FALSE;
    EntriesPerBlock = SectorSize / GptHeader.SizeOfPartitionEntry;
    EntryLba = GptHeader.PartitionEntryLba + (EntryIndex / EntriesPerBlock);
    EntryOffset = (EntryIndex % EntriesPerBlock) * GptHeader.SizeOfPartitionEntry;

    /* Read the block containing the partition entry */
    if (!MachDiskReadLogicalSectors(DriveNumber, EntryLba, 1, DiskReadBuffer))
        return FALSE;

    /* Extract partition entry */
    RtlCopyMemory(&GptEntry, (PUCHAR)DiskReadBuffer + EntryOffset, sizeof(GptEntry));

    /* Check if partition is unused */
    if (RtlEqualMemory(&GptEntry.PartitionTypeGuid, &UnusedGuid, sizeof(UnusedGuid)))
        return FALSE;

    /* The entry must lie in the usable range (this also keeps the size and the byte offsets below from wrapping) */
    if (!GptCheckEntry(&GptHeader, &GptEntry))
        return FALSE;

    /* Calculate partition size in blocks */
    ULONGLONG PartitionSizeBlocks = GptEntry.EndingLba - GptEntry.StartingLba + 1;

    /* Convert GPT entry to standard-style entry */
    PartitionEntry->StartingOffset.QuadPart  = (GptEntry.StartingLba * SectorSize);
    PartitionEntry->PartitionLength.QuadPart = (PartitionSizeBlocks * SectorSize);
    PartitionEntry->HiddenSectors = 0;
    PartitionEntry->PartitionNumber = PartitionNumber;
    PartitionEntry->PartitionType = PARTITION_GPT; /* Mark as GPT partition */
    PartitionEntry->BootIndicator = RtlEqualMemory(&GptEntry.PartitionTypeGuid, &SystemGuid, sizeof(SystemGuid));
    PartitionEntry->RecognizedPartition = TRUE;
    PartitionEntry->RewritePartition = FALSE;

    return TRUE;
}

#endif
