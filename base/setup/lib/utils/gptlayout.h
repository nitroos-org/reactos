/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GUID Partition Table layout rules: usable range, alignment,
 *              the partition sizes of the UEFI/GPT disk layout, type GUIDs.
 *
 * The on-disk format is the one of the UEFI Specification, section 5
 * ("GUID Partition Table (GPT) Disk Layout"). The sizes of the system and
 * the reserved partitions follow Microsoft's "UEFI/GPT-based hard drive
 * partitions" (learn.microsoft.com, windows-hardware/manufacture/desktop/
 * configure-uefigpt-based-hard-drive-partitions).
 */

#pragma once

/* The partition entry array of a GPT disk holds at least 128 entries of 128 bytes (UEFI 2.10, 5.3.2) */
#define GPT_DEFAULT_ENTRY_COUNT     128
#define GPT_ENTRY_SIZE              128

/* Partitions start on a 1 MiB boundary */
#define GPT_ALIGNMENT_BYTES         (1024ULL * 1024ULL)

/* EFI system partition: 200 MB for 512-byte (native or emulated) sectors, 300 MB for 4K native ones */
#define GPT_ESP_BYTES_512           (200ULL * 1024ULL * 1024ULL)
#define GPT_ESP_BYTES_4K            (300ULL * 1024ULL * 1024ULL)

/* Microsoft reserved partition */
#define GPT_MSR_BYTES               (16ULL * 1024ULL * 1024ULL)

typedef enum _GPT_PARTITION_ROLE
{
    GptRoleOther,       /* Any type Setup does not know: left alone */
    GptRoleBasicData,   /* Basic data partition: gets a volume and a drive letter */
    GptRoleEsp,         /* EFI system partition: FAT32, no drive letter */
    GptRoleMsr,         /* Microsoft reserved partition: no volume, no drive letter */
    GptRoleRecovery     /* Windows recovery partition: no drive letter */
} GPT_PARTITION_ROLE;

GPT_PARTITION_ROLE
GptClassifyPartitionType(
    _In_ const GUID* PartitionType);

VOID
GptGetTypeGuid(
    _In_ GPT_PARTITION_ROLE Role,
    _Out_ GUID* PartitionType);

/* Sectors in the partition entry array for the given number of entries (rounded up to whole sectors) */
ULONG
GptEntryArraySectors(
    _In_ ULONG BytesPerSector,
    _In_ ULONG EntryCount);

/*
 * The first and the last sector that a partition may use on a disk of
 * TotalSectors sectors: the primary header is in sector 1 followed by its
 * entry array; the backup entry array ends right before the backup header
 * in the last sector (UEFI 2.10, 5.3.1 and 5.3.2).
 * Returns FALSE if the disk is too small to hold a GPT.
 */
BOOLEAN
GptGetUsableRange(
    _In_ ULONGLONG TotalSectors,
    _In_ ULONG BytesPerSector,
    _In_ ULONG EntryCount,
    _Out_ PULONGLONG FirstUsable,
    _Out_ PULONGLONG LastUsable);

/* Number of sectors that make 1 MiB (at least 1) */
ULONG
GptAlignmentSectors(
    _In_ ULONG BytesPerSector);

/* Sizes in sectors of the system and of the reserved partitions for the given sector size */
ULONGLONG
GptEspSectors(
    _In_ ULONG BytesPerSector);

ULONGLONG
GptMsrSectors(
    _In_ ULONG BytesPerSector);

/*
 * Protective MBR partition size field: the disk size in sectors minus one,
 * or 0xFFFFFFFF if the disk is larger (UEFI 2.10, 5.2.3).
 */
ULONG
GptProtectiveMbrSectors(
    _In_ ULONGLONG TotalSectors);

/* EOF */
