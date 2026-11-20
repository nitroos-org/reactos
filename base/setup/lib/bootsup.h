/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Bootloader support functions
 * COPYRIGHT:   Copyright 2017-2024 Hermès Bélusca-Maïto <hermes.belusca-maito@reactos.org>
 */

#pragma once

/*
 * UEFI, GPT system disk: what names the installation's partition by something that a change of the
 * partition table (a partition deleted or added before it, the entries reordered, the disk on another
 * port) does not move. Written to the boot entries of freeldr.ini, resolved by the loader at every boot.
 */
typedef struct _BOOT_TARGET_IDENTITY
{
    BOOLEAN IsGpt;              /* FALSE: nothing below is valid (MBR or unknown), no key is written */
    GUID DiskGuid;              /* disk GUID of the GPT header */
    GUID PartitionGuid;         /* unique GUID of the partition's GPT entry */
    ULONGLONG FirstSector;      /* first and last block of the partition, in blocks of the disk */
    ULONGLONG LastSector;
} BOOT_TARGET_IDENTITY, *PBOOT_TARGET_IDENTITY;

/* UEFI: TRUE if the last install found another system's loader at \EFI\BOOT and left it there */
BOOLEAN
WasEfiFallbackLoaderKept(VOID);

NTSTATUS
NTAPI
InstallBootManagerAndBootEntries(
    _In_ ARCHITECTURE_TYPE ArchType,
    _In_ PCUNICODE_STRING SystemRootPath,
    _In_ PCUNICODE_STRING SourceRootPath,
    _In_ PCUNICODE_STRING DestinationArcPath,
    _In_ ULONG_PTR Options,
    _In_opt_ const BOOT_TARGET_IDENTITY* TargetIdentity);

NTSTATUS
NTAPI
AddPartitionBootEntry(
    _In_ PCUNICODE_STRING SystemRootPath,
    _In_ ULONG DiskNumber,
    _In_ ULONG PartitionNumber,
    _In_ PCWSTR Section,
    _In_ PCWSTR Description);

NTSTATUS
NTAPI
InstallBootcodeToRemovable(
    _In_ ARCHITECTURE_TYPE ArchType,
    _In_ PCUNICODE_STRING RemovableRootPath,
    _In_ PCUNICODE_STRING SourceRootPath,
    _In_ PCUNICODE_STRING DestinationArcPath);

/* EOF */
