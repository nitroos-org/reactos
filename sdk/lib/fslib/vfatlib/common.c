/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS VFAT filesystem library
 * FILE:        lib\fslib\vfatlib\common.c
 * PURPOSE:     Common code for Fat support
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 *              Eric Kohl
 *              Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES *******************************************************************/

#include "vfatlib.h"
#include <reactos/rosrandom.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

ULONG
GetShiftCount(IN ULONG Value)
{
    ULONG i = 1;

    while (Value > 0)
    {
        i++;
        Value /= 2;
    }

    return i - 2;
}

ULONG
CalcVolumeSerialNumber(VOID)
{
    LARGE_INTEGER SystemTime;
    TIME_FIELDS TimeFields;
    ULONG Serial;
    PUCHAR Buffer;

    /* The system generator; the clock is only the fall-back when ksecdd is not there */
    if (RosSystemRandom(&Serial, sizeof(Serial)))
        return Serial;

    NtQuerySystemTime(&SystemTime);
    RtlTimeToTimeFields(&SystemTime, &TimeFields);

    Buffer = (PUCHAR)&Serial;
    Buffer[0] = (UCHAR)(TimeFields.Year & 0xFF) + (UCHAR)(TimeFields.Hour & 0xFF);
    Buffer[1] = (UCHAR)(TimeFields.Year >> 8) + (UCHAR)(TimeFields.Minute & 0xFF);
    Buffer[2] = (UCHAR)(TimeFields.Month & 0xFF) + (UCHAR)(TimeFields.Second & 0xFF);
    Buffer[3] = (UCHAR)(TimeFields.Day & 0xFF) + (UCHAR)(TimeFields.Milliseconds & 0xFF);

    return Serial;
}

/* TRUE when the OEM label converts back to the upper-case Unicode label */
static
BOOLEAN
FatOemLabelIsExact(
    IN PUNICODE_STRING Label,
    IN POEM_STRING OemLabel)
{
    UNICODE_STRING Upcased, RoundTrip;
    BOOLEAN Exact = FALSE;

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&Upcased, Label, TRUE)))
        return FALSE;

    if (NT_SUCCESS(RtlOemStringToUnicodeString(&RoundTrip, OemLabel, TRUE)))
    {
        Exact = RtlEqualUnicodeString(&Upcased, &RoundTrip, FALSE);
        RtlFreeUnicodeString(&RoundTrip);
    }

    RtlFreeUnicodeString(&Upcased);
    return Exact;
}

/*
 * Fills the 11-byte label field of the boot sector with the upper-case
 * OEM form of the label, or "NO NAME" when there is none. *HasLabel says
 * whether there is a label, which then also needs a root directory entry.
 * A label that is too long or has a character FAT does not allow is
 * refused, as the file system driver refuses it when the label is set.
 */
NTSTATUS
FatInitVolumeLabel(
    IN PUNICODE_STRING Label,
    OUT PUCHAR VolumeLabel,
    OUT PBOOLEAN HasLabel)
{
    OEM_STRING OemLabel;
    NTSTATUS Status;
    USHORT i;

    *HasLabel = FALSE;
    RtlCopyMemory(VolumeLabel, "NO NAME    ", 11);

    if (Label == NULL || Label->Buffer == NULL || Label->Length == 0)
        return STATUS_SUCCESS;

    for (i = 0; i < Label->Length / sizeof(WCHAR); i++)
    {
        static const WCHAR Invalid[] = L"*?/\\|.,;:+=[]<>\"";
        WCHAR c = Label->Buffer[i];
        ULONG j;

        for (j = 0; Invalid[j] != UNICODE_NULL && Invalid[j] != c; j++);
        if (c < 0x20 || Invalid[j] != UNICODE_NULL)
            return STATUS_INVALID_VOLUME_LABEL;
    }

    Status = RtlUpcaseUnicodeStringToOemString(&OemLabel, Label, TRUE);
    if (!NT_SUCCESS(Status))
        return Status;

    if (OemLabel.Length > 11)
    {
        RtlFreeOemString(&OemLabel);
        return STATUS_INVALID_VOLUME_LABEL;
    }

    /* A best-fit mapping (U+2044 to '/') could bring in a forbidden character */
    if (!FatOemLabelIsExact(Label, &OemLabel))
    {
        RtlFreeOemString(&OemLabel);
        return STATUS_INVALID_VOLUME_LABEL;
    }

    RtlFillMemory(VolumeLabel, 11, ' ');
    RtlCopyMemory(VolumeLabel, OemLabel.Buffer, OemLabel.Length);
    RtlFreeOemString(&OemLabel);
    *HasLabel = TRUE;
    return STATUS_SUCCESS;
}

/* A cluster is a power-of-two count of 1 to 128 sectors */
BOOLEAN
FatIsValidClusterSize(
    IN ULONG ClusterSize,
    IN ULONG BytesPerSector)
{
    ULONG SectorsPerCluster;

    if (BytesPerSector == 0 || ClusterSize < BytesPerSector ||
        ClusterSize % BytesPerSector != 0)
    {
        return FALSE;
    }

    SectorsPerCluster = ClusterSize / BytesPerSector;
    return (SectorsPerCluster <= 128 &&
            (SectorsPerCluster & (SectorsPerCluster - 1)) == 0);
}

/*
 * Computes the size of one FAT and returns the count of data clusters.
 * The FAT must also hold the two reserved entries, so it grows from the
 * first estimate until it maps every data cluster. Returns 0 when the
 * volume does not even hold the metadata.
 */
ULONG
FatComputeLayout(
    IN ULONG TotalSectors,
    IN ULONG MetadataSectors,
    IN ULONG FatCount,
    IN ULONG SectorsPerCluster,
    IN ULONG BytesPerSector,
    IN ULONG FatEntryBits,
    OUT PULONG FatSectors)
{
    ULONGLONG Available, Entries, Clusters;
    ULONGLONG Fat;

    *FatSectors = 0;
    if (TotalSectors <= MetadataSectors)
        return 0;

    Available = TotalSectors - MetadataSectors;
    Fat = (Available * FatEntryBits + (ULONGLONG)SectorsPerCluster * BytesPerSector * 8 - 1) /
          ((ULONGLONG)SectorsPerCluster * BytesPerSector * 8 + (ULONGLONG)FatCount * FatEntryBits);

    for (;;)
    {
        if (Available <= Fat * FatCount)
            return 0;

        Clusters = (Available - Fat * FatCount) / SectorsPerCluster;
        Entries = Fat * BytesPerSector * 8 / FatEntryBits;
        if (Entries >= Clusters + 2)
            break;

        Fat++;
    }

    *FatSectors = (ULONG)Fat;
    return (ULONG)min(Clusters, MAXULONG);
}

/* Builds the volume label entry of the root directory (32 bytes) */
VOID
FatInitLabelEntry(
    OUT PUCHAR Entry,
    IN PUCHAR VolumeLabel)
{
    LARGE_INTEGER SystemTime, LocalTime;
    TIME_FIELDS TimeFields;
    USHORT Time, Date;

    RtlZeroMemory(Entry, 32);
    RtlCopyMemory(Entry, VolumeLabel, 11);
    /* 0xE5 marks a deleted entry; such a first character is stored as 0x05 */
    if (Entry[0] == 0xE5)
        Entry[0] = 0x05;
    Entry[11] = ATTR_VOLUME;

    NtQuerySystemTime(&SystemTime);
    RtlSystemTimeToLocalTime(&SystemTime, &LocalTime);
    RtlTimeToTimeFields(&LocalTime, &TimeFields);
    if (TimeFields.Year < 1980)
        return;

    Time = (TimeFields.Hour << 11) | (TimeFields.Minute << 5) | (TimeFields.Second / 2);
    Date = ((TimeFields.Year - 1980) << 9) | (TimeFields.Month << 5) | TimeFields.Day;
    Entry[22] = (UCHAR)Time;
    Entry[23] = (UCHAR)(Time >> 8);
    Entry[24] = (UCHAR)Date;
    Entry[25] = (UCHAR)(Date >> 8);
}

/***** Wipe function for FAT12, FAT16 and FAT32 formats *****/
NTSTATUS
FatWipeSectors(
    IN HANDLE FileHandle,
    IN ULONG TotalSectors,
    IN ULONG SectorsPerCluster,
    IN ULONG BytesPerSector,
    IN OUT PFORMAT_CONTEXT Context)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PUCHAR Buffer;
    LARGE_INTEGER FileOffset;
    ULONGLONG Sector;
    ULONG Length;
    NTSTATUS Status;

    Length = SectorsPerCluster * BytesPerSector;

    /* Allocate buffer for the cluster */
    Buffer = (PUCHAR)RtlAllocateHeap(RtlGetProcessHeap(),
                                     HEAP_ZERO_MEMORY,
                                     Length);
    if (Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* Wipe all clusters */
    Sector = 0;
    while (Sector + SectorsPerCluster < TotalSectors)
    {
        FileOffset.QuadPart = Sector * BytesPerSector;

        Status = NtWriteFile(FileHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             Buffer,
                             Length,
                             &FileOffset,
                             NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("NtWriteFile() failed (Status %lx)\n", Status);
            goto done;
        }

        UpdateProgress(Context, SectorsPerCluster);

        Sector += SectorsPerCluster;
    }

    /* Wipe the trailing space behind the last cluster */
    if (Sector < TotalSectors)
    {
        DPRINT("Remaining sectors %lu\n", TotalSectors - Sector);

        FileOffset.QuadPart = Sector * BytesPerSector;
        Length = (TotalSectors - Sector) * BytesPerSector;

        Status = NtWriteFile(FileHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             Buffer,
                             Length,
                             &FileOffset,
                             NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("NtWriteFile() failed (Status %lx)\n", Status);
            goto done;
        }

        UpdateProgress(Context, TotalSectors - Sector);
    }

done:
    /* Free the buffer */
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Status;
}

/* EOF */
