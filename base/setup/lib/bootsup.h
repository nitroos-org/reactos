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

/* Adds the boot entry of the installation at ArcPath to the freeldr.ini in the directory IniPath (an NT path),
 * unless one of that path is there, and the kernel debugging entry unless a ReactOS_KdKit section is listed */
NTSTATUS
UpdateFreeLoaderIni(
    IN PCWSTR IniPath,
    IN PCWSTR ArcPath);

/* The same on a GPT disk: PartitionGuid is the GUID of the partition of ArcPath. A boot entry that has this
 * path but names another partition by its GUID belongs to another installation (the position in its path is
 * out of date, and now equals ours): it is left alone and an entry of our own is added. */
NTSTATUS
UpdateFreeLoaderIniForPartition(
    IN PCWSTR IniPath,
    IN PCWSTR ArcPath,
    IN PCWSTR PartitionGuid OPTIONAL);

/* The same, and an entry that Update adds also gets the keys of the partition (DiskGuid and Range both given) */
NTSTATUS
UpdateFreeLoaderIniForIdentity(
    IN PCWSTR IniPath,
    IN PCWSTR ArcPath,
    IN PCWSTR PartitionGuid OPTIONAL,
    IN PCWSTR DiskGuid OPTIONAL,
    IN PCWSTR Range OPTIONAL);

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
