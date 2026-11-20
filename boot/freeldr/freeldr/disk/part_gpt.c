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
 * making the loader read without limit). The header is exactly 92 bytes, as in
 * the kernel reader: a table the kernel refuses must not boot either.
 */
#define GPT_HEADER_SIZE         92
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

    /* HeaderSize: 92 bytes, the only size the kernel reader (and Windows) writes */
    if (Header->HeaderSize != GPT_HEADER_SIZE || Header->HeaderSize > SectorSize)
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
    if (Header->PartitionEntryLba > GPT_MAX_U64 / SectorSize - EntrySectors ||
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

/* The most used entries a table may have: the kernel reader (FstubReadPartitionTableEFI) refuses a table with more */
#ifndef GPT_MAX_USED_PARTITIONS
#define GPT_MAX_USED_PARTITIONS 128
#endif

/*
 * The entry array of a header that passed GptCheckHeader, read as the kernel reader does
 * (FstubReadHeaderEFI, FstubReadPartitionTableEFI): the CRC-32 of the array must match the one in the
 * header, every used entry must lie in the usable range and there are at most 128 of them. A table the
 * kernel refuses (for example an array that a write cut short left half old, half new) is not used by
 * the loader either: the loader would otherwise number the partitions of one table (partition(N) of
 * freeldr.ini) and the kernel those of the other (the backup).
 */
static BOOLEAN
GptCheckEntryArray(
    _In_ UCHAR DriveNumber,
    _In_ const GPT_TABLE_HEADER* Header,
    _In_ ULONG SectorSize)
{
    GPT_PARTITION_ENTRY Entry;
    GUID UnusedGuid = EFI_PART_TYPE_UNUSED_GUID;
    ULONGLONG Remaining = (ULONGLONG)Header->NumberOfPartitionEntries * EFI_PARTITION_ENTRY_SIZE;
    ULONGLONG Lba = Header->PartitionEntryLba;
    ULONG PerRead = (ULONG)(DiskReadBufferSize / SectorSize);
    ULONG Crc = 0, Used = 0, Count, Bytes, Index;

    if (PerRead == 0)
        return FALSE;
    if (PerRead > 64)
        PerRead = 64;

    while (Remaining != 0)
    {
        Count = (ULONG)((Remaining + SectorSize - 1) / SectorSize);
        if (Count > PerRead)
            Count = PerRead;
        if (!MachDiskReadLogicalSectors(DriveNumber, Lba, Count, DiskReadBuffer))
            return FALSE;

        Bytes = (ULONG)(((ULONGLONG)Count * SectorSize < Remaining) ? (ULONGLONG)Count * SectorSize : Remaining);
        Crc = GptCrc32(Crc, (const UCHAR*)DiskReadBuffer, Bytes);

        for (Index = 0; Index < Bytes / EFI_PARTITION_ENTRY_SIZE; Index++)
        {
            RtlCopyMemory(&Entry, (PUCHAR)DiskReadBuffer + Index * EFI_PARTITION_ENTRY_SIZE, sizeof(Entry));
            if (RtlEqualMemory(&Entry.PartitionTypeGuid, &UnusedGuid, sizeof(UnusedGuid)))
                continue;
            if (!GptCheckEntry(Header, &Entry) || ++Used > GPT_MAX_USED_PARTITIONS)
                return FALSE;
        }

        Lba += Count;
        Remaining -= Bytes;
    }

    return (Crc == Header->PartitionEntryArrayCrc32);
}

/*
 * GptCheckEntryArray for a header, remembering the answer: DiskReadGptHeader is called for every
 * partition number and the check reads the whole array (up to 512 KB).
 */
static BOOLEAN
GptCheckTable(
    _In_ UCHAR DriveNumber,
    _In_ const GPT_TABLE_HEADER* Header,
    _In_ ULONG SectorSize)
{
    static struct
    {
        BOOLEAN Known;
        BOOLEAN Result;
        UCHAR DriveNumber;
        ULONGLONG MyLba;
        ULONG HeaderCrc32;
    } Checked[2];
    ULONG Slot = (Header->MyLba == EFI_HEADER_LOCATION) ? 0 : 1;

    if (Checked[Slot].Known && Checked[Slot].DriveNumber == DriveNumber &&
        Checked[Slot].MyLba == Header->MyLba && Checked[Slot].HeaderCrc32 == Header->HeaderCrc32)
        return Checked[Slot].Result;

    Checked[Slot].Result = GptCheckEntryArray(DriveNumber, Header, SectorSize);
    Checked[Slot].Known = TRUE;
    Checked[Slot].DriveNumber = DriveNumber;
    Checked[Slot].MyLba = Header->MyLba;
    Checked[Slot].HeaderCrc32 = Header->HeaderCrc32;
    return Checked[Slot].Result;
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
        /* The check reads the entry array into the same buffer: the header has been copied */
        if (GptCheckTable(DriveNumber, GptHeader, SectorSize))
            return TRUE;
    }

    /*
     * The primary header is not usable. As the kernel reader does, use the backup header in the last block
     * of the disk (UEFI 2.10 5.3.2: a copy of the header, with the copy of the entry array before it).
     * Only for a disk that has a protective MBR, as the kernel reader (FstubDetectPartitionStyle) asks: the
     * first entry of the type 0xEE and no other entry. A disk that was a GPT disk once and was repartitioned
     * with an MBR by a tool that does not wipe the last block must not become a GPT disk again.
     * The same applies when the primary header is fine but its entry array is not.
     */
    if (DiskSectors > 2 && MachDiskReadLogicalSectors(DriveNumber, 0ULL, 1, DiskReadBuffer))
    {
        const UCHAR* Mbr = (const UCHAR*)DiskReadBuffer;
        BOOLEAN Protective = FALSE;
        ULONG i;

        /* Boot signature 0xAA55, the first partition entry of the GPT protective type (0xEE), the others unused */
        if (Mbr[510] == 0x55 && Mbr[511] == 0xAA && Mbr[446 + 4] == PARTITION_GPT)
        {
            Protective = TRUE;
            for (i = 1; i < 4; i++)
            {
                if (Mbr[446 + 16 * i + 4] != 0)
                    Protective = FALSE;
            }
        }
        if (Protective &&
            MachDiskReadLogicalSectors(DriveNumber, DiskSectors - 1, 1, DiskReadBuffer) &&
            GptCheckHeader((const UCHAR*)DiskReadBuffer, SectorSize, DiskSectors, DiskSectors - 1))
        {
            RtlCopyMemory(GptHeader, DiskReadBuffer, sizeof(*GptHeader));
            if (GptCheckTable(DriveNumber, GptHeader, SectorSize))
                return TRUE;
        }
    }

    return FALSE;
}

/* Partitions are numbered over the used entries; the kernel reader refuses a table that has more of them than this */
#define GPT_MAX_USED_PARTITIONS 128

/* The entry that was found by the last call: the next number continues from there */
static struct
{
    BOOLEAN Valid;
    UCHAR DriveNumber;
    ULONG Number;
    ULONG Index;
    ULONG HeaderCrc32;
    ULONG ArrayCrc32;
} GptLast;

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
    ULONG EntryIndex, EntryOffset, EntriesPerBlock, UsedCount;
    BOOLEAN NeedRead;
    GUID UnusedGuid = EFI_PART_TYPE_UNUSED_GUID;
    GUID SystemGuid = EFI_PART_TYPE_EFI_SYSTEM_PART_GUID;

    ASSERT(SectorSize >= 512);

    /* Read GPT header */
    if (!DiskReadGptHeader(DriveNumber, &GptHeader))
        return FALSE;

    if (PartitionNumber == 0 || GptHeader.SizeOfPartitionEntry == 0 ||
        SectorSize < GptHeader.SizeOfPartitionEntry)
        return FALSE;
    EntriesPerBlock = SectorSize / GptHeader.SizeOfPartitionEntry;

    /*
     * Partitions are numbered over the used entries, in table order, as the kernel does
     * (\Device\HarddiskN\PartitionM): an unused slot, e.g. the gap left by a partition that
     * was deleted, has no number. Find the PartitionNumber-th used entry.
     */
    /* The kernel refuses a table with more used entries than this (FstubReadPartitionTableEFI) */
    if (PartitionNumber > GPT_MAX_USED_PARTITIONS)
        return FALSE;

    /*
     * The callers ask for the numbers 1, 2, 3, ... in turn: continue after the entry that was found
     * for the previous number instead of scanning the table again (the table, identified by the
     * checksums of its header and of its entry array, must be the same).
     */
    UsedCount = 0;
    EntryIndex = 0;
    NeedRead = TRUE;
    if (GptLast.Valid && GptLast.DriveNumber == DriveNumber && GptLast.Number + 1 == PartitionNumber &&
        GptLast.HeaderCrc32 == GptHeader.HeaderCrc32 &&
        GptLast.ArrayCrc32 == GptHeader.PartitionEntryArrayCrc32)
    {
        UsedCount = GptLast.Number;
        EntryIndex = GptLast.Index + 1;
    }
    for (; EntryIndex < GptHeader.NumberOfPartitionEntries; EntryIndex++)
    {
        EntryOffset = (EntryIndex % EntriesPerBlock) * GptHeader.SizeOfPartitionEntry;
        if (EntryOffset == 0 || NeedRead)
        {
            /* Read the block containing the next partition entries */
            EntryLba = GptHeader.PartitionEntryLba + (EntryIndex / EntriesPerBlock);
            if (!MachDiskReadLogicalSectors(DriveNumber, EntryLba, 1, DiskReadBuffer))
                return FALSE;
            NeedRead = FALSE;
        }

        /* Extract partition entry */
        RtlCopyMemory(&GptEntry, (PUCHAR)DiskReadBuffer + EntryOffset, sizeof(GptEntry));

        /* Unused slots are skipped */
        if (RtlEqualMemory(&GptEntry.PartitionTypeGuid, &UnusedGuid, sizeof(UnusedGuid)))
            continue;

        if (++UsedCount == PartitionNumber)
            break;
    }
    if (EntryIndex >= GptHeader.NumberOfPartitionEntries)
    {
        GptLast.Valid = FALSE;
        return FALSE;
    }
    GptLast.Valid = TRUE;
    GptLast.DriveNumber = DriveNumber;
    GptLast.Number = PartitionNumber;
    GptLast.Index = EntryIndex;
    GptLast.HeaderCrc32 = GptHeader.HeaderCrc32;
    GptLast.ArrayCrc32 = GptHeader.PartitionEntryArrayCrc32;

    /* The entry must lie in the usable range (this also keeps the size and the byte offsets below from wrapping) */
    if (!GptCheckEntry(&GptHeader, &GptEntry))
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
