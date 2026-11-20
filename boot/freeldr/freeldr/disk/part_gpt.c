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

#ifdef UEFIBOOT

/*
 * Text form of a GUID, as a boot entry names a partition by its unique GUID: 8-4-4-4-12 hexadecimal
 * digits, with or without one pair of braces. Anything else (another length, a sign, a space, an
 * embedded null, a dash in another place) is refused, and Guid is left alone.
 */
BOOLEAN
GptParseGuid(
    _In_ PCSTR Text,
    _Out_ GUID* Guid)
{
    ULONG Length, First, Position, Digit, Nibbles = 0;
    UCHAR Bytes[16] = {0};
    UCHAR Char;

    if (Text == NULL)
        return FALSE;

    /* Length: at most 39 characters are looked at, so that an unterminated or huge string costs nothing */
    for (Length = 0; Length < 39 && Text[Length] != ANSI_NULL; Length++)
        ;
    if (Length == 38)
    {
        if (Text[0] != '{' || Text[37] != '}')
            return FALSE;
        First = 1;
    }
    else if (Length == 36)
    {
        First = 0;
    }
    else
    {
        return FALSE;
    }

    for (Position = 0; Position < 36; Position++)
    {
        Char = (UCHAR)Text[First + Position];
        if (Position == 8 || Position == 13 || Position == 18 || Position == 23)
        {
            if (Char != '-')
                return FALSE;
            continue;
        }

        if (Char >= '0' && Char <= '9')
            Digit = Char - '0';
        else if (Char >= 'a' && Char <= 'f')
            Digit = Char - 'a' + 10;
        else if (Char >= 'A' && Char <= 'F')
            Digit = Char - 'A' + 10;
        else
            return FALSE;

        /* Digits in text order: Bytes holds the GUID as it reads, the first eight digits make Data1 and so on */
        if (Nibbles & 1)
            Bytes[Nibbles / 2] |= (UCHAR)Digit;
        else
            Bytes[Nibbles / 2] = (UCHAR)(Digit << 4);
        Nibbles++;
    }
    if (Nibbles != 32)
        return FALSE;

    Guid->Data1 = ((ULONG)Bytes[0] << 24) | ((ULONG)Bytes[1] << 16) | ((ULONG)Bytes[2] << 8) | Bytes[3];
    Guid->Data2 = (USHORT)(((USHORT)Bytes[4] << 8) | Bytes[5]);
    Guid->Data3 = (USHORT)(((USHORT)Bytes[6] << 8) | Bytes[7]);
    RtlCopyMemory(Guid->Data4, &Bytes[8], 8);
    return TRUE;
}

/*
 * Calls Callback for every used entry of the GPT of the disk, in table order, with the number the entry has
 * (the same one DiskGetGptPartitionEntry takes: partitions are numbered over the used entries, as the kernel
 * does) and its slot (1-based position in the entry array, as the firmware's device path node counts it),
 * until the callback returns TRUE. The table is the one DiskReadGptHeader accepts: the same table, and the
 * same numbering, that the partition(N) of an ARC path means. Returns FALSE when the disk has no such table
 * or an entry block cannot be read; the callback has seen the entries up to there.
 */
BOOLEAN
DiskGptScan(
    _In_ UCHAR DriveNumber,
    _In_ PGPT_SCAN_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_opt_ GUID* DiskGuid)
{
    GPT_TABLE_HEADER GptHeader;
    GPT_PARTITION_ENTRY GptEntry;
    GEOMETRY Geometry;
    ULONG SectorSize = 512;
    ULONG EntriesPerBlock, EntryIndex, EntryOffset, Number = 0;
    GUID UnusedGuid = EFI_PART_TYPE_UNUSED_GUID;

    if (!DiskReadGptHeader(DriveNumber, &GptHeader))
        return FALSE;
    if (DiskGuid)
        RtlCopyMemory(DiskGuid, &GptHeader.DiskGuid, sizeof(GUID));

    /* The block size DiskReadGptHeader used */
    if (MachDiskGetDriveGeometry(DriveNumber, &Geometry) && Geometry.BytesPerSector >= 512)
        SectorSize = Geometry.BytesPerSector;
    if (SectorSize > DiskReadBufferSize || SectorSize < GptHeader.SizeOfPartitionEntry)
        return FALSE;
    EntriesPerBlock = SectorSize / GptHeader.SizeOfPartitionEntry;

    for (EntryIndex = 0; EntryIndex < GptHeader.NumberOfPartitionEntries; EntryIndex++)
    {
        EntryOffset = (EntryIndex % EntriesPerBlock) * GptHeader.SizeOfPartitionEntry;
        if (EntryOffset == 0)
        {
            if (!MachDiskReadLogicalSectors(DriveNumber,
                                            GptHeader.PartitionEntryLba + (EntryIndex / EntriesPerBlock),
                                            1, DiskReadBuffer))
                return FALSE;
        }
        RtlCopyMemory(&GptEntry, (PUCHAR)DiskReadBuffer + EntryOffset, sizeof(GptEntry));

        if (RtlEqualMemory(&GptEntry.PartitionTypeGuid, &UnusedGuid, sizeof(UnusedGuid)))
            continue;
        Number++;

        /* An entry outside of the usable range is numbered but never offered (the table check refuses such a table anyway) */
        if (!GptCheckEntry(&GptHeader, &GptEntry))
            continue;
        if (Callback(Context, Number, EntryIndex + 1, &GptEntry, SectorSize))
            break;
    }
    return TRUE;
}

static BOOLEAN
GptStopCallback(
    _In_opt_ PVOID Context,
    _In_ ULONG Number,
    _In_ ULONG Slot,
    _In_ const GPT_PARTITION_ENTRY* Entry,
    _In_ ULONG SectorSize)
{
    return TRUE;
}

typedef struct _GPT_FIND_CONTEXT
{
    const GUID* PartitionGuid;
    PGPT_PARTITION_MATCH Match;
} GPT_FIND_CONTEXT;

static BOOLEAN
GptFindCallback(
    _In_opt_ PVOID Context,
    _In_ ULONG Number,
    _In_ ULONG Slot,
    _In_ const GPT_PARTITION_ENTRY* Entry,
    _In_ ULONG SectorSize)
{
    GPT_FIND_CONTEXT* Find = (GPT_FIND_CONTEXT*)Context;

    if (!RtlEqualMemory(&Entry->UniquePartitionGuid, Find->PartitionGuid, sizeof(GUID)))
        return FALSE;
    if (Find->Match->Count++ == 0)
    {
        Find->Match->Number = Number;
        Find->Match->Slot = Slot;
        Find->Match->StartLba = Entry->StartingLba;
        Find->Match->EndLba = Entry->EndingLba;
        RtlCopyMemory(&Find->Match->TypeGuid, &Entry->PartitionTypeGuid, sizeof(GUID));
    }
    return FALSE; /* keep going: a second entry with the same GUID is a duplicate the caller must know about */
}

/*
 * The used entries of the disk that carry the unique GUID PartitionGuid: Match->Count of them (0 if none, or
 * if the disk has no acceptable GPT), the first one in Match->Number (numbered as DiskGetGptPartitionEntry
 * does) with its slot, range and type. The all-zero GUID matches nothing. Match->DiskGuid is the disk GUID of
 * the table, whether the partition was found or not.
 */
BOOLEAN
DiskGptFindPartitionByGuid(
    _In_ UCHAR DriveNumber,
    _In_ const GUID* PartitionGuid,
    _Out_ PGPT_PARTITION_MATCH Match)
{
    static const UCHAR ZeroGuid[sizeof(GUID)] = {0};
    GPT_FIND_CONTEXT Find;

    RtlZeroMemory(Match, sizeof(*Match));
    Find.PartitionGuid = PartitionGuid;
    Find.Match = Match;

    /* The all-zero GUID is what an unused entry carries: it names nothing (the scan only fills in the disk GUID) */
    if (RtlEqualMemory(PartitionGuid, ZeroGuid, sizeof(GUID)))
    {
        DiskGptScan(DriveNumber, GptStopCallback, NULL, &Match->DiskGuid);
        return FALSE;
    }

    if (!DiskGptScan(DriveNumber, GptFindCallback, &Find, &Match->DiskGuid))
    {
        /* No table (or a read error half way): no answer is trusted */
        Match->Count = 0;
        return FALSE;
    }
    return (Match->Count != 0);
}

/*
 * The number (over the used entries of the table, as DiskGetGptPartitionEntry and the kernel count) of the
 * GPT partition that the HARDDRIVE node of the loader's own device path names, on the disk it was started
 * from (Signature = the unique GUID the firmware read from the entry, Start and Size in blocks). The
 * partition is identified by that GUID; two entries with it (a duplicated GUID on the boot disk) are told
 * apart by the node's start and size; if the GUID is in no entry of the table the loader reads (the firmware
 * may have read the other copy of the table), a single entry with the node's start and size is taken. FALSE
 * when the disk has no acceptable table or no unique entry fits: the caller decides what the last resort is.
 * The node's PartitionNumber is not used: it is the table SLOT, not this number.
 */
typedef struct _GPT_BOOT_PART_SEARCH
{
    const UCHAR* Signature;
    ULONGLONG Start;
    ULONGLONG Size;
    ULONG GuidMatches;      /* entries with the unique GUID of the node */
    ULONG GuidNumber;
    ULONG ExactMatches;     /* of those, the ones with the start and size of the node as well */
    ULONG ExactNumber;
    ULONG RangeMatches;     /* entries with the start and size of the node, whatever their GUID */
    ULONG RangeNumber;
} GPT_BOOT_PART_SEARCH;

static BOOLEAN
GptBootPartitionCallback(
    _In_opt_ PVOID Context,
    _In_ ULONG Number,
    _In_ ULONG Slot,
    _In_ const GPT_PARTITION_ENTRY* Entry,
    _In_ ULONG SectorSize)
{
    GPT_BOOT_PART_SEARCH* Search = (GPT_BOOT_PART_SEARCH*)Context;
    BOOLEAN SameRange = (Entry->StartingLba == Search->Start &&
                         Entry->EndingLba - Entry->StartingLba + 1 == Search->Size);

    static const UCHAR ZeroGuid[sizeof(GUID)] = {0};

    /* A zero signature (firmware that gave none) identifies nothing: it must not match an entry that has no GUID either */
    if (!RtlEqualMemory(Search->Signature, ZeroGuid, sizeof(GUID)) &&
        RtlEqualMemory(&Entry->UniquePartitionGuid, Search->Signature, sizeof(GUID)))
    {
        if (Search->GuidMatches++ == 0)
            Search->GuidNumber = Number;
        if (SameRange && Search->ExactMatches++ == 0)
            Search->ExactNumber = Number;
    }
    if (SameRange && Search->RangeMatches++ == 0)
        Search->RangeNumber = Number;
    return FALSE;
}

BOOLEAN
GptFindBootPartition(
    _In_ UCHAR DriveNumber,
    _In_reads_bytes_(16) const UCHAR* Signature,
    _In_ ULONGLONG Start,
    _In_ ULONGLONG Size,
    _Out_ PULONG Number)
{
    GPT_BOOT_PART_SEARCH Search;

    RtlZeroMemory(&Search, sizeof(Search));
    Search.Signature = Signature;
    Search.Start = Start;
    Search.Size = Size;
    if (!DiskGptScan(DriveNumber, GptBootPartitionCallback, &Search, NULL))
        return FALSE;

    if (Search.GuidMatches == 1)
    {
        *Number = Search.GuidNumber;
        return TRUE;
    }
    if (Search.GuidMatches > 1)
    {
        if (Search.ExactMatches == 1)
        {
            *Number = Search.ExactNumber;
            return TRUE;
        }
        return FALSE;
    }
    if (Search.RangeMatches == 1)
    {
        *Number = Search.RangeNumber;
        return TRUE;
    }
    return FALSE;
}

/* The GUID the way a freeldr.ini entry spells it */
static VOID
GptFormatGuid(
    _In_ const GUID* Guid,
    _Out_writes_(48) PCHAR Text)
{
    RtlStringCbPrintfA(Text, 48, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                       (ULONG)Guid->Data1, (ULONG)Guid->Data2, (ULONG)Guid->Data3,
                       (ULONG)Guid->Data4[0], (ULONG)Guid->Data4[1], (ULONG)Guid->Data4[2], (ULONG)Guid->Data4[3],
                       (ULONG)Guid->Data4[4], (ULONG)Guid->Data4[5], (ULONG)Guid->Data4[6], (ULONG)Guid->Data4[7]);
}

/* "first-last" in decimal, nothing else; first <= last */
static BOOLEAN
GptParseRange(
    _In_ PCSTR Text,
    _Out_ PULONGLONG First,
    _Out_ PULONGLONG Last)
{
    ULONGLONG Value[2] = {0, 0};
    ULONG Part, Digits;

    for (Part = 0; Part < 2; Part++)
    {
        for (Digits = 0; *Text >= '0' && *Text <= '9'; Digits++, Text++)
        {
            if (Value[Part] > ((ULONGLONG)~0ULL - (ULONG)(*Text - '0')) / 10)
                return FALSE; /* does not fit */
            Value[Part] = Value[Part] * 10 + (ULONG)(*Text - '0');
        }
        if (Digits == 0)
            return FALSE;
        if (Part == 0 && *Text++ != '-')
            return FALSE;
    }
    if (*Text != ANSI_NULL || Value[0] > Value[1])
        return FALSE;
    *First = Value[0];
    *Last = Value[1];
    return TRUE;
}

/* Stops the scan at the first used entry: DiskGptScan has by then read the disk GUID */
static BOOLEAN
GptDiskGuidCallback(
    _In_opt_ PVOID Context,
    _In_ ULONG Number,
    _In_ ULONG Slot,
    _In_ const GPT_PARTITION_ENTRY* Entry,
    _In_ ULONG SectorSize)
{
    return TRUE;
}

typedef struct _GPT_NUMBER_SEARCH
{
    ULONG Number;
    ULONGLONG First;
    ULONGLONG Last;
    BOOLEAN Found;
} GPT_NUMBER_SEARCH;

static BOOLEAN
GptNumberCallback(
    _In_opt_ PVOID Context,
    _In_ ULONG Number,
    _In_ ULONG Slot,
    _In_ const GPT_PARTITION_ENTRY* Entry,
    _In_ ULONG SectorSize)
{
    GPT_NUMBER_SEARCH* Search = (GPT_NUMBER_SEARCH*)Context;

    if (Number != Search->Number)
        return FALSE;
    Search->Found = TRUE;
    Search->First = Entry->StartingLba;
    Search->Last = Entry->EndingLba;
    return TRUE;
}

/* multi(0)disk(0)rdisk(Disk)partition(Number)Rest; FALSE if it does not fit (a cut path would name something else) */
static BOOLEAN
GptBuildArcPath(
    _Out_writes_(Size) PCHAR Path,
    _In_ SIZE_T Size,
    _In_ ULONG Disk,
    _In_ ULONG Number,
    _In_ PCSTR Rest)
{
    SIZE_T Length = 0;

    /* The prefix is "multi(0)disk(0)rdisk(" + at most 10 digits + ")partition(" + at most 10 digits + ")" */
    while (Rest[Length] != ANSI_NULL && Length < Size)
        Length++;
    if (Length + 64 > Size)
        return FALSE;
    RtlStringCbPrintfA(Path, Size, "multi(0)disk(0)rdisk(%lu)partition(%lu)%s", Disk, Number, Rest);
    return TRUE;
}

/*
 * Resolves the system partition of a boot entry that names it by GUID, at this boot.
 *
 * The hard disks are rdisk(0) .. rdisk(HardDisks - 1), disk n being drive 0x80 + n; BootDisk is the one the
 * loader was started from. StoredDisk, StoredNumber and Rest are the parts of the entry's SystemPath
 * multi(0)disk(0)rdisk(StoredDisk)partition(StoredNumber)Rest. PartText, DiskText and RangeText are the values of
 * SystemPathPartitionGuid, SystemPathDiskGuid and SystemPathPartitionRange (DiskText and RangeText may be NULL).
 * On TRUE, NewPath is the path to use. On FALSE nothing is ours and Message says so.
 *
 * 1. Every hard disk's table (the table DiskReadGptHeader accepts, numbered over the used entries as the
 *    kernel does) is searched for a used entry with the unique GUID. Found: the path becomes
 *    multi(0)disk(0)rdisk(R)partition(N) of THAT entry at THIS boot, followed by Rest (GPT_SYSPATH_RESOLVED).
 *    The numbers in the stored path are not consulted.
 * 2. Two or more entries carry the GUID (a cloned disk, a partition copied with its GUID, two entries of one
 *    table): the entry whose disk has the disk GUID of DiskText wins, then the one on the disk the loader was
 *    started from, then the lowest rdisk, then the lowest partition number. Nothing but the rdisk order, which
 *    the firmware gives, enters the choice, so it is the same at every boot of the same hardware.
 * 3. No entry has the GUID (the partition was deleted, or recreated by a tool that gave it a new GUID): the
 *    stored position is used ONLY IF the entry it names now covers exactly the blocks of RangeText, on the disk
 *    with the GUID of DiskText (or rdisk(StoredDisk) when that disk is not there): the same place on the same
 *    disk, i.e. the partition was restored or recreated in place (GPT_SYSPATH_SAME_PLACE). Anything else,
 *    including no range or a range that is not the same, is a failure: nothing is read from the partition
 *    that the stored number now names.
 * 4. A PartText that is not a GUID follows rule 3; an unusable DiskText is ignored (the partition GUID
 *    is the identity). Of two keys with the same name the loader sees the first.
 */
BOOLEAN
GptResolveSystemPartition(
    _In_ ULONG HardDisks,
    _In_ ULONG BootDisk,
    _In_ ULONG StoredDisk,
    _In_ ULONG StoredNumber,
    _In_ PCSTR Rest,
    _In_ PCSTR PartText,
    _In_opt_ PCSTR DiskText,
    _In_opt_ PCSTR RangeText,
    _Out_writes_(NewPathSize) PCHAR NewPath,
    _In_ SIZE_T NewPathSize,
    _Out_writes_(MessageSize) PCHAR Message,
    _In_ SIZE_T MessageSize,
    _Out_ GPT_SYSPATH_STATUS* Status)
{
    GUID PartGuid, DiskGuid;
    BOOLEAN PartGuidOk, DiskGuidOk, RangeOk;
    ULONGLONG First = 0, Last = 0;
    ULONG Disk, Candidates = 0;
    BOOLEAN HaveBest = FALSE, BestDiskGuid = FALSE, BestBoot = FALSE;
    ULONG BestDisk = 0, BestNumber = 0;
    CHAR PartString[48], DiskString[48];

    *Status = GPT_SYSPATH_NOT_FOUND;
    if (NewPathSize)
        *NewPath = ANSI_NULL;
    if (MessageSize)
        *Message = ANSI_NULL;

    PartGuidOk = GptParseGuid(PartText, &PartGuid);
    DiskGuidOk = (DiskText != NULL) && GptParseGuid(DiskText, &DiskGuid);
    RangeOk = (RangeText != NULL) && GptParseRange(RangeText, &First, &Last);

    /* Rules 1 and 2 */
    for (Disk = 0; PartGuidOk && Disk < HardDisks; Disk++)
    {
        GPT_PARTITION_MATCH Match;
        BOOLEAN ThisDiskGuid, ThisBoot;

        if (!DiskGptFindPartitionByGuid((UCHAR)(0x80 + Disk), &PartGuid, &Match))
            continue;

        Candidates += Match.Count;
        ThisDiskGuid = DiskGuidOk && RtlEqualMemory(&Match.DiskGuid, &DiskGuid, sizeof(GUID));
        ThisBoot = (Disk == BootDisk);

        /* Better than the best so far? Disks are visited in rdisk order, so a tie keeps the lower one */
        if (!HaveBest ||
            (ThisDiskGuid && !BestDiskGuid) ||
            (ThisDiskGuid == BestDiskGuid && ThisBoot && !BestBoot))
        {
            HaveBest = TRUE;
            BestDisk = Disk;
            BestNumber = Match.Number;
            BestDiskGuid = ThisDiskGuid;
            BestBoot = ThisBoot;
        }
    }

    if (HaveBest)
    {
        if (!GptBuildArcPath(NewPath, NewPathSize, BestDisk, BestNumber, Rest))
        {
            if (MessageSize)
                RtlStringCbCopyA(Message, MessageSize, "The system path of this boot entry is too long.");
            return FALSE;
        }
        *Status = GPT_SYSPATH_RESOLVED;
        TRACE("%lu partition(s) carry the system partition's GUID: disk %lu partition %lu\n",
              Candidates, BestDisk, BestNumber);
        return TRUE;
    }

    /* Rule 3: the same place on the same disk */
    if (RangeOk)
    {
        ULONG SameDisk = StoredDisk;

        /* The disk with the recorded disk GUID, wherever the firmware put it this time */
        for (Disk = 0; DiskGuidOk && Disk < HardDisks; Disk++)
        {
            GUID Found;

            if (DiskGptScan((UCHAR)(0x80 + Disk), GptDiskGuidCallback, NULL, &Found) &&
                RtlEqualMemory(&Found, &DiskGuid, sizeof(GUID)))
            {
                SameDisk = Disk;
                break;
            }
        }

        if (SameDisk < HardDisks)
        {
            GPT_NUMBER_SEARCH Search;

            RtlZeroMemory(&Search, sizeof(Search));
            Search.Number = StoredNumber;
            if (DiskGptScan((UCHAR)(0x80 + SameDisk), GptNumberCallback, &Search, NULL) &&
                Search.Found && Search.First == First && Search.Last == Last)
            {
                if (!GptBuildArcPath(NewPath, NewPathSize, SameDisk, StoredNumber, Rest))
                {
                    if (MessageSize)
                        RtlStringCbCopyA(Message, MessageSize, "The system path of this boot entry is too long.");
                    return FALSE;
                }
                *Status = GPT_SYSPATH_SAME_PLACE;
                return TRUE;
            }
        }
    }

    /* Nothing that is ours */
    if (PartGuidOk)
        GptFormatGuid(&PartGuid, PartString);
    else
        RtlStringCbCopyA(PartString, sizeof(PartString), "(not a GUID)");
    if (DiskGuidOk)
        GptFormatGuid(&DiskGuid, DiskString);
    else
        RtlStringCbCopyA(DiskString, sizeof(DiskString), "(not recorded)");
    if (MessageSize)
    {
        RtlStringCbPrintfA(Message, MessageSize,
                           "The system partition of this boot entry was not found.\n"
                           "\n"
                           "Partition GUID %s\n"
                           "Disk GUID      %s\n"
                           "\n"
                           "No disk has a partition with that GUID, and the\n"
                           "partition the stored path names is not in the\n"
                           "recorded place. It may have been deleted or\n"
                           "recreated. Nothing was read from another partition.\n"
                           "\n"
                           "Correct SystemPath and SystemPathPartitionGuid of\n"
                           "this entry in freeldr.ini on the EFI system partition.",
                           PartString, DiskString);
    }
    return FALSE;
}

#endif /* UEFIBOOT */

#endif
