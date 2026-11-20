/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GUID Partition Table layout rules (see gptlayout.h)
 */

#include "precomp.h"

#include "gptlayout.h"

/*
 * Partition type GUIDs. The ESP GUID is defined by the UEFI specification
 * (Table 5.7); the others are the ones of the Microsoft partition types.
 */
static const GUID GptTypeEsp       = {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};
static const GUID GptTypeMsr       = {0xE3C9E316, 0x0B5C, 0x4DB8, {0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE}};
static const GUID GptTypeBasicData = {0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}};
static const GUID GptTypeRecovery  = {0xDE94BBA4, 0x06D1, 0x4D40, {0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC}};

static BOOLEAN
SameGuid(_In_ const GUID* a, _In_ const GUID* b)
{
    return RtlCompareMemory(a, b, sizeof(GUID)) == sizeof(GUID);
}

GPT_PARTITION_ROLE
GptClassifyPartitionType(
    _In_ const GUID* PartitionType)
{
    if (SameGuid(PartitionType, &GptTypeBasicData))
        return GptRoleBasicData;
    if (SameGuid(PartitionType, &GptTypeEsp))
        return GptRoleEsp;
    if (SameGuid(PartitionType, &GptTypeMsr))
        return GptRoleMsr;
    if (SameGuid(PartitionType, &GptTypeRecovery))
        return GptRoleRecovery;
    return GptRoleOther;
}

VOID
GptGetTypeGuid(
    _In_ GPT_PARTITION_ROLE Role,
    _Out_ GUID* PartitionType)
{
    switch (Role)
    {
        case GptRoleEsp:      *PartitionType = GptTypeEsp;       break;
        case GptRoleMsr:      *PartitionType = GptTypeMsr;       break;
        case GptRoleRecovery: *PartitionType = GptTypeRecovery;  break;
        default:              *PartitionType = GptTypeBasicData; break;
    }
}

ULONG
GptEntryArraySectors(
    _In_ ULONG BytesPerSector,
    _In_ ULONG EntryCount)
{
    ULONGLONG Bytes = (ULONGLONG)EntryCount * GPT_ENTRY_SIZE;

    if (BytesPerSector == 0)
        return 0;
    return (ULONG)((Bytes + BytesPerSector - 1) / BytesPerSector);
}

BOOLEAN
GptGetUsableRange(
    _In_ ULONGLONG TotalSectors,
    _In_ ULONG BytesPerSector,
    _In_ ULONG EntryCount,
    _Out_ PULONGLONG FirstUsable,
    _Out_ PULONGLONG LastUsable)
{
    ULONGLONG ArraySectors = GptEntryArraySectors(BytesPerSector, EntryCount);

    *FirstUsable = 0;
    *LastUsable = 0;

    /* Protective MBR, primary header, primary array, [usable], backup array, backup header */
    if (ArraySectors == 0 || TotalSectors < (2 * ArraySectors + 4))
        return FALSE;

    *FirstUsable = 2 + ArraySectors;
    *LastUsable = TotalSectors - 2 - ArraySectors;
    return TRUE;
}

ULONG
GptAlignmentSectors(
    _In_ ULONG BytesPerSector)
{
    ULONG Sectors;

    if (BytesPerSector == 0)
        return 1;
    Sectors = (ULONG)(GPT_ALIGNMENT_BYTES / BytesPerSector);
    return (Sectors ? Sectors : 1);
}

ULONGLONG
GptEspSectors(
    _In_ ULONG BytesPerSector)
{
    if (BytesPerSector == 0)
        return 0;
    return (BytesPerSector >= 4096 ? GPT_ESP_BYTES_4K : GPT_ESP_BYTES_512) / BytesPerSector;
}

ULONGLONG
GptMsrSectors(
    _In_ ULONG BytesPerSector)
{
    if (BytesPerSector == 0)
        return 0;
    return GPT_MSR_BYTES / BytesPerSector;
}

ULONG
GptProtectiveMbrSectors(
    _In_ ULONGLONG TotalSectors)
{
    if (TotalSectors == 0)
        return 0;
    return (TotalSectors - 1 > 0xFFFFFFFFULL) ? 0xFFFFFFFF : (ULONG)(TotalSectors - 1);
}

/* EOF */
