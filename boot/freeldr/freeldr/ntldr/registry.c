/*
 *  FreeLoader
 *
 *  Copyright (C) 2014  Timo Kreuzer <timo.kreuzer@reactos.org>
 *                2022  George Bișoc <george.bisoc@reactos.org>
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
#include <cmlib.h>
#include "registry.h"
#include <internal/cmboot.h>

#include <debug.h>
DBG_DEFAULT_CHANNEL(REGISTRY);

static PCMHIVE CmSystemHive;
static HCELL_INDEX SystemRootCell;

PHHIVE SystemHive = NULL;
HKEY CurrentControlSetKey = NULL;

#define HCI_TO_HKEY(CellIndex)          ((HKEY)(ULONG_PTR)(CellIndex))
#ifndef HKEY_TO_HCI // See also registry.h
#define HKEY_TO_HCI(hKey)               ((HCELL_INDEX)(ULONG_PTR)(hKey))
#endif

#define GET_HHIVE(CmHive)               (&((CmHive)->Hive))
#define GET_HHIVE_FROM_HKEY(hKey)       GET_HHIVE(CmSystemHive)
#define GET_CM_KEY_NODE(hHive, hKey)    ((PCM_KEY_NODE)HvGetCell(hHive, HKEY_TO_HCI(hKey)))

#define GET_HBASE_BLOCK(ChunkBase)      ((PHBASE_BLOCK)ChunkBase)

PVOID
NTAPI
CmpAllocate(
    IN SIZE_T Size,
    IN BOOLEAN Paged,
    IN ULONG Tag)
{
    UNREFERENCED_PARAMETER(Paged);
    return FrLdrHeapAlloc(Size, Tag);
}

VOID
NTAPI
CmpFree(
    IN PVOID Ptr,
    IN ULONG Quota)
{
    UNREFERENCED_PARAMETER(Quota);
    FrLdrHeapFree(Ptr, 0);
}

/* The check of a hive frees these before it returns */
PVOID
NTAPI
CmpAllocateTemporary(
    IN SIZE_T Size)
{
    return FrLdrTempAlloc(Size, TAG_CM);
}

VOID
NTAPI
CmpFreeTemporary(
    IN PVOID Ptr)
{
    FrLdrTempFree(Ptr, TAG_CM);
}

/**
 * @brief
 * Initializes a flat hive descriptor for the
 * hive and validates the registry hive.
 * Volatile data is purged during this procedure
 * for initialization.
 *
 * @param[in] CmHive
 * A pointer to a CM (in-memory) hive descriptor
 * containing the hive descriptor to be initialized.
 *
 * @param[in] ChunkBase
 * An arbitrary pointer that points to the registry
 * chunk base. This pointer serves as the base block
 * containing the hive file header data.
 *
 * @param[in] LoadAlternate
 * If set to TRUE, the function will initialize the
 * hive as an alternate hive, otherwise FALSE to initialize
 * it as primary.
 *
 * @return
 * Returns TRUE if the hive has been initialized
 * and registry data inside the hive is valid, FALSE
 * otherwise.
 */
static
BOOLEAN
RegInitializeHive(
    _In_ PCMHIVE CmHive,
    _In_ PVOID ChunkBase,
    _In_ BOOLEAN LoadAlternate)
{
    NTSTATUS Status;
    CM_CHECK_REGISTRY_STATUS CmStatusCode;

    /* Initialize the hive */
    Status = HvInitialize(GET_HHIVE(CmHive),
                          HINIT_FLAT, // HINIT_MEMORY_INPLACE
                          0,
                          LoadAlternate ? HFILE_TYPE_ALTERNATE : HFILE_TYPE_PRIMARY,
                          ChunkBase,
                          CmpAllocate,
                          CmpFree,
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          1,
                          NULL);
    if (!NT_SUCCESS(Status))
    {
        ERR("Failed to initialize the flat hive (Status 0x%lx)\n", Status);
        return FALSE;
    }

    /* Now check the hive and purge volatile data */
    CmStatusCode = CmCheckRegistry(CmHive, CM_CHECK_REGISTRY_BOOTLOADER_PURGE_VOLATILES | CM_CHECK_REGISTRY_VALIDATE_HIVE);
    if (!CM_CHECK_REGISTRY_SUCCESS(CmStatusCode))
    {
        ERR("CmCheckRegistry detected problems with the loaded flat hive (check code %lu)\n", CmStatusCode);
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief
 * Checks that the data a flat hive's base block describes
 * lies within the hive as read from disk.
 *
 * @param[in] BaseBlock
 * A pointer to the base block of the flat hive, followed
 * by its data.
 *
 * @param[in] ChunkSize
 * The size of the hive as read from disk.
 *
 * @return
 * Returns TRUE if the hive length fits in ChunkSize and the
 * root cell (its size field, the fixed part of its key node
 * and the size it declares) lies within the hive length,
 * FALSE otherwise.
 *
 * @remarks
 * The hive check walks a flat hive from its root cell
 * without bounds of its own.
 */
static
BOOLEAN
RegIsFlatHiveInBounds(
    _In_ PHBASE_BLOCK BaseBlock,
    _In_ ULONG ChunkSize)
{
    ULONG Length = BaseBlock->Length;
    ULONG RootCell = BaseBlock->RootCell;
    ULONG MinCellSize = sizeof(HCELL) + FIELD_OFFSET(CM_KEY_NODE, Name);
    PHCELL Cell;
    ULONG CellSize;

    if (ChunkSize < HBLOCK_SIZE ||
        Length == 0 ||
        (Length % HBLOCK_SIZE) != 0 ||
        Length > ChunkSize - HBLOCK_SIZE ||
        RootCell >= Length ||
        Length - RootCell < MinCellSize)
    {
        ERR("The hive describes 0x%lx bytes of data (root cell 0x%lx), the hive file holds 0x%lx\n",
            Length, RootCell, ChunkSize < HBLOCK_SIZE ? 0 : ChunkSize - HBLOCK_SIZE);
        return FALSE;
    }

    /* An allocated cell has a negative size */
    Cell = (PHCELL)((PUCHAR)BaseBlock + HBLOCK_SIZE + RootCell);
    CellSize = 0 - (ULONG)Cell->Size;
    if (Cell->Size >= 0 || CellSize < MinCellSize || CellSize > Length - RootCell)
    {
        ERR("The root cell 0x%lx has a bad size %ld\n", RootCell, Cell->Size);
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief
 * Loads and reads a whole hive log.
 *
 * @param[in] DirectoryPath
 * A pointer to a string that denotes the directory
 * path of the hives and logs location.
 *
 * @param[in] LogName
 * A pointer to a string that denotes the name of
 * the desired hive log (e.g. "SYSTEM.LOG").
 *
 * @param[out] LogData
 * A pointer to the returned hive log data that was
 * read, from the start of the file.
 *
 * @param[out] LogDataSize
 * Receives the size of the hive log, which is the
 * number of bytes read.
 *
 * @return
 * Returns TRUE if the hive log was loaded and read
 * completely, FALSE otherwise.
 *
 * @remarks
 * The returned log data pointer to the caller is a
 * virtual address. You must use VaToPa that converts
 * the address to a physical one in order to actually
 * use it!
 */
static
BOOLEAN
RegLoadHiveLog(
    _In_ PCSTR DirectoryPath,
    _In_ PCSTR LogName,
    _Out_ PVOID *LogData,
    _Out_ PULONG LogDataSize)
{
    ARC_STATUS Status;
    ULONG LogId;
    CHAR LogPath[MAX_PATH];
    ULONG LogFileSize;
    FILEINFORMATION FileInfo;
    ULONG BytesRead;
    PVOID LogDataPhysical;

    /* Build the full path to the hive log */
    RtlStringCbCopyA(LogPath, sizeof(LogPath), DirectoryPath);
    RtlStringCbCatA(LogPath, sizeof(LogPath), LogName);

    /* Open the file */
    Status = ArcOpen(LogPath, OpenReadOnly, &LogId);
    if (Status != ESUCCESS)
    {
        ERR("Failed to open %s (ARC code %lu)\n", LogName, Status);
        return FALSE;
    }

    /* Get the file length */
    Status = ArcGetFileInformation(LogId, &FileInfo);
    if (Status != ESUCCESS)
    {
        ERR("Failed to get file information from %s (ARC code %lu)\n", LogName, Status);
        ArcClose(LogId);
        return FALSE;
    }

    /* Capture the size of the hive log file; the page count below must not overflow */
    LogFileSize = FileInfo.EndingAddress.LowPart;
    if (FileInfo.EndingAddress.HighPart != 0 ||
        LogFileSize < HV_LOG_HEADER_SIZE ||
        LogFileSize > MAXULONG - MM_PAGE_MASK)
    {
        ERR("%s is too short or too large (size 0x%lx)\n", LogName, LogFileSize);
        ArcClose(LogId);
        return FALSE;
    }

    /* Allocate memory blocks for our log data */
    LogDataPhysical = MmAllocateMemoryWithType(MM_SIZE_TO_PAGES(LogFileSize) << MM_PAGE_SHIFT,
                                               LoaderRegistryData);
    if (LogDataPhysical == NULL)
    {
        ERR("Failed to allocate memory for log data\n");
        ArcClose(LogId);
        return FALSE;
    }

    /* And read the whole log */
    Status = ArcRead(LogId, LogDataPhysical, LogFileSize, &BytesRead);
    if (Status != ESUCCESS)
    {
        ERR("Failed to read %s (ARC code %lu)\n", LogName, Status);
        ArcClose(LogId);
        return FALSE;
    }

    /* A short read leaves part of the buffer unfilled: never use it */
    if (BytesRead != LogFileSize)
    {
        ERR("Short read of %s: 0x%lx of 0x%lx bytes\n", LogName, BytesRead, LogFileSize);
        ArcClose(LogId);
        return FALSE;
    }

    *LogData = PaToVa(LogDataPhysical);
    *LogDataSize = LogFileSize;
    ArcClose(LogId);
    return TRUE;
}

/**
 * @brief
 * Recovers a dirty flat registry hive from its
 * hive log: the base block and the dirty blocks.
 *
 * @param[in] ChunkBase
 * A pointer to the registry hive chunk base of
 * the dirty hive to be recovered.
 *
 * @param[in] ChunkSize
 * The size of the registry hive chunk in memory.
 * A log describing a longer hive is refused.
 *
 * @param[in] DirectoryPath
 * A pointer to a string that denotes the directory
 * path of the hives and logs location.
 *
 * @param[in] LogName
 * A pointer to a string that denotes the name of
 * the desired hive log (e.g. "SYSTEM").
 *
 * @return
 * Returns TRUE if the hive was recovered from the log,
 * FALSE otherwise. The hive is left untouched when FALSE
 * is returned.
 *
 * @remarks
 * The log is applied only if it belongs to the interrupted
 * write of this hive: its base block is valid (including
 * equal sequence numbers), its time stamp equals the time
 * stamp in the base block of the hive, and, when the base
 * block of the hive has a valid checksum, its sequence
 * number is not older than the last completed write of
 * the hive (the secondary sequence number of the hive).
 * A log left behind by an earlier write, such as the
 * setup-time log of a hive that is no longer logged,
 * fails these checks.
 *
 * The log holds its base block (HV_LOG_HEADER_SIZE bytes),
 * the dirty vector (a signature and one byte per block,
 * rounded up as HvpWriteLog does it), then the dirty blocks.
 * Everything is checked before the hive is written to.
 *
 * The hive check may still fail after the recovery, for
 * example when a block that was not dirty is damaged. The
 * caller then falls back to the alternate hive.
 */
static
BOOLEAN
RegRecoverHiveFromLog(
    _Inout_ PVOID ChunkBase,
    _In_ ULONG ChunkSize,
    _In_ PCSTR DirectoryPath,
    _In_ PCSTR LogName)
{
    BOOLEAN Success;
    CHAR FullLogFileName[MAX_PATH];
    PVOID LogData;
    ULONG LogSize;
    ULONG StorageLength, VectorSize;
    ULONG BlockIndex, LogIndex, DirtyCount;
    PUCHAR LogDataPhysical, DirtyVector, DirtyBlocks;
    PHBASE_BLOCK HiveBaseBlock;
    PHBASE_BLOCK LogBaseBlock;

    /* Build the complete path of the hive log */
    RtlStringCbCopyA(FullLogFileName, sizeof(FullLogFileName), LogName);
    RtlStringCbCatA(FullLogFileName, sizeof(FullLogFileName), ".LOG");
    Success = RegLoadHiveLog(DirectoryPath, FullLogFileName, &LogData, &LogSize);
    if (!Success)
    {
        ERR("Failed to read the hive log\n");
        return FALSE;
    }

    /* Make sure the header from the hive log is actually sane */
    LogDataPhysical = (PUCHAR)VaToPa(LogData);
    LogBaseBlock = GET_HBASE_BLOCK(LogDataPhysical);
    if (!HvpVerifyHiveHeader(LogBaseBlock, HFILE_TYPE_LOG))
    {
        ERR("The hive log has corrupt base block\n");
        return FALSE;
    }

    /*
     * Make sure the log belongs to the interrupted write of this hive.
     * The sequence numbers of the hive are compared only when its base
     * block checksum is right; a damaged base block is matched by its
     * time stamp alone, as the kernel does.
     */
    HiveBaseBlock = GET_HBASE_BLOCK(ChunkBase);
    if (LogBaseBlock->TimeStamp.QuadPart != HiveBaseBlock->TimeStamp.QuadPart ||
        (HvpHiveHeaderChecksum(HiveBaseBlock) == HiveBaseBlock->CheckSum &&
         LogBaseBlock->Sequence1 < HiveBaseBlock->Sequence2))
    {
        ERR("The hive log does not match the hive (log sequence 0x%lx, hive sequences 0x%lx/0x%lx)\n",
            LogBaseBlock->Sequence1, HiveBaseBlock->Sequence1, HiveBaseBlock->Sequence2);
        return FALSE;
    }

    /* The recovered hive must lie within what was read from disk */
    if (LogBaseBlock->Length == 0 ||
        (LogBaseBlock->Length % HBLOCK_SIZE) != 0 ||
        LogBaseBlock->Length > ChunkSize - HBLOCK_SIZE ||
        LogBaseBlock->RootCell >= LogBaseBlock->Length)
    {
        ERR("The hive log describes 0x%lx bytes of data (root cell 0x%lx), the hive file holds 0x%lx\n",
            LogBaseBlock->Length, LogBaseBlock->RootCell, ChunkSize - HBLOCK_SIZE);
        return FALSE;
    }

    /* Make sure the dirty vector is there and holds its signature */
    StorageLength = LogBaseBlock->Length / HBLOCK_SIZE;
    VectorSize = ROUND_UP(sizeof(HV_LOG_DIRTY_SIGNATURE) + ROUND_UP(StorageLength, sizeof(ULONG) * 8), HSECTOR_SIZE);
    DirtyVector = LogDataPhysical + HV_LOG_HEADER_SIZE;
    if (LogSize - HV_LOG_HEADER_SIZE < VectorSize ||
        *((PULONG)DirtyVector) != HV_LOG_DIRTY_SIGNATURE)
    {
        ERR("The hive log dirty vector is missing or has no signature\n");
        return FALSE;
    }

    /* Make sure the log holds every dirty block */
    DirtyCount = 0;
    for (BlockIndex = 0; BlockIndex < StorageLength; ++BlockIndex)
    {
        if (DirtyVector[BlockIndex + sizeof(HV_LOG_DIRTY_SIGNATURE)] == HV_LOG_DIRTY_BLOCK)
            DirtyCount++;
    }
    DirtyBlocks = DirtyVector + VectorSize;
    if ((LogSize - HV_LOG_HEADER_SIZE - VectorSize) / HBLOCK_SIZE < DirtyCount)
    {
        ERR("The hive log holds fewer than its %lu dirty blocks\n", DirtyCount);
        return FALSE;
    }

    /* Everything is checked: copy the healthy base block into the primary hive */
    WARN("Recovering the hive from its log (%lu dirty blocks)...\n", DirtyCount);
    RtlCopyMemory(HiveBaseBlock, LogBaseBlock, HV_LOG_HEADER_SIZE);
    HiveBaseBlock->Type = HFILE_TYPE_PRIMARY;

    /* Copy the dirty blocks; each one lies within ChunkSize, as Length does */
    LogIndex = 0;
    for (BlockIndex = 0; BlockIndex < StorageLength; ++BlockIndex)
    {
        if (DirtyVector[BlockIndex + sizeof(HV_LOG_DIRTY_SIGNATURE)] != HV_LOG_DIRTY_BLOCK)
            continue;

        RtlCopyMemory((PUCHAR)ChunkBase + (BlockIndex + 1) * HBLOCK_SIZE,
                      DirtyBlocks + LogIndex * HBLOCK_SIZE,
                      HBLOCK_SIZE);
        LogIndex++;
    }

    /* Fix the secondary sequence of the primary hive and compute a new checksum */
    HiveBaseBlock->Sequence2 = HiveBaseBlock->Sequence1;
    HiveBaseBlock->CheckSum = HvpHiveHeaderChecksum(HiveBaseBlock);
    return TRUE;
}

/**
 * @brief
 * Imports the SYSTEM binary hive from
 * the registry base chunk that's been
 * provided by the loader block.
 *
 * @param[in] ChunkBase
 * A pointer to the registry base chunk
 * that serves for SYSTEM hive initialization.
 *
 * @param[in] ChunkSize
 * The size of the registry base chunk. This
 * parameter refers to the actual size of
 * the SYSTEM hive. Data recovery from the
 * hive log stays within it.
 *
 * @param[in] LoadAlternate
 * If set to TRUE, the function will initialize the
 * hive as an alternate hive, otherwise FALSE to initialize
 * it as primary.
 *
 * @return
 * Returns TRUE if hive importing and initialization
 * have succeeded, FALSE otherwise.
 */
BOOLEAN
RegImportBinaryHive(
    _In_ PVOID ChunkBase,
    _In_ ULONG ChunkSize,
    _In_ PCSTR SearchPath,
    _In_ BOOLEAN LoadAlternate)
{
    BOOLEAN Success;
    PHBASE_BLOCK BaseBlock;
    PCM_KEY_NODE KeyNode;

    TRACE("RegImportBinaryHive(%p, 0x%lx)\n", ChunkBase, ChunkSize);

    if (ChunkSize < HBLOCK_SIZE)
    {
        ERR("The hive file is shorter than its base block (0x%lx bytes)\n", ChunkSize);
        return FALSE;
    }

    BaseBlock = GET_HBASE_BLOCK(ChunkBase);

    /*
     * A hive whose base block passes the header check (which includes
     * the checksum and equal sequence numbers) is clean: its last write
     * completed. Its log, if any, is older and is never applied to it.
     * Only a dirty hive, one whose write was interrupted, is recovered
     * from its log. The alternate hive is a mirror of the primary hive
     * and has no log of its own.
     */
    if (HvpVerifyHiveHeader(BaseBlock, HFILE_TYPE_PRIMARY))
    {
        if (!RegIsFlatHiveInBounds(BaseBlock, ChunkSize))
            return FALSE;

        CmSystemHive = FrLdrTempAlloc(sizeof(CMHIVE), 'eviH');
        Success = RegInitializeHive(CmSystemHive, ChunkBase, LoadAlternate);
        if (!Success)
        {
            ERR("Corrupted clean hive (sequence 0x%lx), not recovered from the log\n", BaseBlock->Sequence1);
            FrLdrTempFree(CmSystemHive, 'eviH');
            CmSystemHive = NULL;
            return FALSE;
        }

        BaseBlock->BootRecover = HBOOT_NO_BOOT_RECOVER;
    }
    else
    {
        if (LoadAlternate)
        {
            ERR("The alternate hive is dirty or its base block is corrupt\n");
            return FALSE;
        }

        WARN("The hive is dirty (sequences 0x%lx/0x%lx), recovering it from its log\n",
             BaseBlock->Sequence1, BaseBlock->Sequence2);

        if (!RegRecoverHiveFromLog(ChunkBase, ChunkSize, SearchPath, "SYSTEM"))
        {
            ERR("Failed to recover the hive from its log\n");
            return FALSE;
        }

        /* Now initialize the recovered hive */
        if (!RegIsFlatHiveInBounds(BaseBlock, ChunkSize))
            return FALSE;

        CmSystemHive = FrLdrTempAlloc(sizeof(CMHIVE), 'eviH');
        Success = RegInitializeHive(CmSystemHive, ChunkBase, LoadAlternate);
        if (!Success)
        {
            ERR("Corrupted hive (despite recovery) %p\n", ChunkBase);
            FrLdrTempFree(CmSystemHive, 'eviH');
            CmSystemHive = NULL;
            return FALSE;
        }

        /*
         * Acknowledge the kernel we recovered the SYSTEM hive
         * on our side by applying log data.
         */
        BaseBlock->BootRecover = HBOOT_BOOT_RECOVERED_BY_HIVE_LOG;
    }

    /* Save the root key node */
    SystemHive = GET_HHIVE(CmSystemHive);
    SystemRootCell = SystemHive->BaseBlock->RootCell;
    ASSERT(SystemRootCell != HCELL_NIL);

    /* Verify it is accessible */
    KeyNode = (PCM_KEY_NODE)HvGetCell(SystemHive, SystemRootCell);
    ASSERT(KeyNode);
    ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);
    HvReleaseCell(SystemHive, SystemRootCell);

    return TRUE;
}

BOOLEAN
RegInitCurrentControlSet(
    _In_ BOOLEAN LastKnownGood)
{
    UNICODE_STRING ControlSetName;
    HCELL_INDEX ControlCell;
    PCM_KEY_NODE KeyNode;
    BOOLEAN AutoSelect;

    TRACE("RegInitCurrentControlSet\n");

    /* Choose which control set to open and set it as the new "Current" */
    RtlInitUnicodeString(&ControlSetName,
                         LastKnownGood ? L"LastKnownGood"
                                       : L"Default");

    ControlCell = CmpFindControlSet(SystemHive,
                                    SystemRootCell,
                                    &ControlSetName,
                                    &AutoSelect);
    if (ControlCell == HCELL_NIL)
    {
        ERR("CmpFindControlSet('%wZ') failed\n", &ControlSetName);
        return FALSE;
    }

    CurrentControlSetKey = HCI_TO_HKEY(ControlCell);

    /* Verify it is accessible */
    KeyNode = (PCM_KEY_NODE)HvGetCell(SystemHive, ControlCell);
    ASSERT(KeyNode);
    ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);
    HvReleaseCell(SystemHive, ControlCell);

    return TRUE;
}

static
BOOLEAN
GetNextPathElement(
    _Out_ PUNICODE_STRING NextElement,
    _Inout_ PUNICODE_STRING RemainingPath)
{
    /* Check if there are any characters left */
    if (RemainingPath->Length < sizeof(WCHAR))
    {
        /* Nothing left, bail out early */
        return FALSE;
    }

    /* The next path elements starts with the remaining path */
    NextElement->Buffer = RemainingPath->Buffer;

    /* Loop until the path element ends */
    while ((RemainingPath->Length >= sizeof(WCHAR)) &&
           (RemainingPath->Buffer[0] != '\\'))
    {
        /* Skip this character */
        RemainingPath->Buffer++;
        RemainingPath->Length -= sizeof(WCHAR);
    }

    NextElement->Length = (USHORT)(RemainingPath->Buffer - NextElement->Buffer) * sizeof(WCHAR);
    NextElement->MaximumLength = NextElement->Length;

    /* Check if the path element ended with a path separator */
    if (RemainingPath->Length >= sizeof(WCHAR))
    {
        /* Skip the path separator */
        ASSERT(RemainingPath->Buffer[0] == '\\');
        RemainingPath->Buffer++;
        RemainingPath->Length -= sizeof(WCHAR);
    }

    /* Return whether we got any characters */
    return TRUE;
}

#if 0
LONG
RegEnumKey(
    _In_ HKEY Key,
    _In_ ULONG Index,
    _Out_ PWCHAR Name,
    _Inout_ PULONG NameSize,
    _Out_opt_ PHKEY SubKey)
{
    PHHIVE Hive = GET_HHIVE_FROM_HKEY(Key);
    PCM_KEY_NODE KeyNode, SubKeyNode;
    HCELL_INDEX CellIndex;
    USHORT NameLength;

    TRACE("RegEnumKey(%p, %lu, %p, %p->%u)\n",
          Key, Index, Name, NameSize, NameSize ? *NameSize : 0);

    /* Get the key node */
    KeyNode = GET_CM_KEY_NODE(Hive, Key);
    ASSERT(KeyNode);
    ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);

    CellIndex = CmpFindSubKeyByNumber(Hive, KeyNode, Index);
    if (CellIndex == HCELL_NIL)
    {
        TRACE("RegEnumKey index out of bounds (%d) in key (%.*s)\n",
              Index, KeyNode->NameLength, KeyNode->Name);
        HvReleaseCell(Hive, HKEY_TO_HCI(Key));
        return ERROR_NO_MORE_ITEMS;
    }
    HvReleaseCell(Hive, HKEY_TO_HCI(Key));

    /* Get the value cell */
    SubKeyNode = (PCM_KEY_NODE)HvGetCell(Hive, CellIndex);
    ASSERT(SubKeyNode != NULL);
    ASSERT(SubKeyNode->Signature == CM_KEY_NODE_SIGNATURE);

    if (SubKeyNode->Flags & KEY_COMP_NAME)
    {
        NameLength = CmpCompressedNameSize(SubKeyNode->Name, SubKeyNode->NameLength);

        /* Compressed name */
        CmpCopyCompressedName(Name,
                              *NameSize,
                              SubKeyNode->Name,
                              SubKeyNode->NameLength);
    }
    else
    {
        NameLength = SubKeyNode->NameLength;

        /* Normal name */
        RtlCopyMemory(Name, SubKeyNode->Name,
                      min(*NameSize, SubKeyNode->NameLength));
    }

    if (*NameSize >= NameLength + sizeof(WCHAR))
    {
        Name[NameLength / sizeof(WCHAR)] = UNICODE_NULL;
    }

    *NameSize = NameLength + sizeof(WCHAR);

    HvReleaseCell(Hive, CellIndex);

    if (SubKey != NULL)
        *SubKey = HCI_TO_HKEY(CellIndex);

    TRACE("RegEnumKey done -> %u, '%.*S'\n", *NameSize, *NameSize, Name);
    return ERROR_SUCCESS;
}
#endif

LONG
RegOpenKey(
    _In_ HKEY ParentKey,
    _In_z_ PCWSTR KeyName,
    _Out_ PHKEY Key)
{
    UNICODE_STRING RemainingPath, SubKeyName;
    UNICODE_STRING CurrentControlSet = RTL_CONSTANT_STRING(L"CurrentControlSet");
    PHHIVE Hive = (ParentKey ? GET_HHIVE_FROM_HKEY(ParentKey) : GET_HHIVE(CmSystemHive));
    PCM_KEY_NODE KeyNode;
    HCELL_INDEX CellIndex;

    TRACE("RegOpenKey(%p, '%S', %p)\n", ParentKey, KeyName, Key);

    /* Initialize the remaining path name */
    RtlInitUnicodeString(&RemainingPath, KeyName);

    /* Check if we have a parent key */
    if (ParentKey == NULL)
    {
        UNICODE_STRING SubKeyName1, SubKeyName2, SubKeyName3;
        UNICODE_STRING RegistryPath = RTL_CONSTANT_STRING(L"Registry");
        UNICODE_STRING MachinePath = RTL_CONSTANT_STRING(L"MACHINE");
        UNICODE_STRING SystemPath = RTL_CONSTANT_STRING(L"SYSTEM");

        TRACE("RegOpenKey: absolute path\n");

        if ((RemainingPath.Length < sizeof(WCHAR)) ||
            RemainingPath.Buffer[0] != '\\')
        {
            /* The key path is not absolute */
            ERR("RegOpenKey: invalid path '%S' (%wZ)\n", KeyName, &RemainingPath);
            return ERROR_PATH_NOT_FOUND;
        }

        /* Skip initial path separator */
        RemainingPath.Buffer++;
        RemainingPath.Length -= sizeof(WCHAR);

        /* Get the first 3 path elements */
        GetNextPathElement(&SubKeyName1, &RemainingPath);
        GetNextPathElement(&SubKeyName2, &RemainingPath);
        GetNextPathElement(&SubKeyName3, &RemainingPath);
        TRACE("RegOpenKey: %wZ / %wZ / %wZ\n", &SubKeyName1, &SubKeyName2, &SubKeyName3);

        /* Check if we have the correct path */
        if (!RtlEqualUnicodeString(&SubKeyName1, &RegistryPath, TRUE) ||
            !RtlEqualUnicodeString(&SubKeyName2, &MachinePath, TRUE) ||
            !RtlEqualUnicodeString(&SubKeyName3, &SystemPath, TRUE))
        {
            /* The key path is not inside HKLM\Machine\System */
            ERR("RegOpenKey: invalid path '%S' (%wZ)\n", KeyName, &RemainingPath);
            return ERROR_PATH_NOT_FOUND;
        }

        /* Use the root key */
        CellIndex = SystemRootCell;
    }
    else
    {
        /* Use the parent key */
        CellIndex = HKEY_TO_HCI(ParentKey);
    }

    /* Check if this is the root key */
    if (CellIndex == SystemRootCell)
    {
        UNICODE_STRING TempPath = RemainingPath;

        /* Get the first path element */
        GetNextPathElement(&SubKeyName, &TempPath);

        /* Check if this is CurrentControlSet */
        if (RtlEqualUnicodeString(&SubKeyName, &CurrentControlSet, TRUE))
        {
            /* Use the CurrentControlSetKey and update the remaining path */
            CellIndex = HKEY_TO_HCI(CurrentControlSetKey);
            RemainingPath = TempPath;
        }
    }

    /* Get the key node */
    KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, CellIndex);
    ASSERT(KeyNode);
    ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);

    TRACE("RegOpenKey: RemainingPath '%wZ'\n", &RemainingPath);

    /* Loop while there are path elements */
    while (GetNextPathElement(&SubKeyName, &RemainingPath))
    {
        HCELL_INDEX NextCellIndex;

        TRACE("RegOpenKey: next element '%wZ'\n", &SubKeyName);

        /* Get the next sub key */
        NextCellIndex = CmpFindSubKeyByName(Hive, KeyNode, &SubKeyName);
        HvReleaseCell(Hive, CellIndex);
        CellIndex = NextCellIndex;
        if (CellIndex == HCELL_NIL)
        {
            WARN("Did not find sub key '%wZ' (full: %S)\n", &SubKeyName, KeyName);
            return ERROR_PATH_NOT_FOUND;
        }

        /* Get the found key */
        KeyNode = (PCM_KEY_NODE)HvGetCell(Hive, CellIndex);
        ASSERT(KeyNode);
        ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);
    }

    HvReleaseCell(Hive, CellIndex);
    *Key = HCI_TO_HKEY(CellIndex);

    return ERROR_SUCCESS;
}

static
LONG
RepGetValueData(
    _In_ PHHIVE Hive,
    _In_ PCM_KEY_VALUE ValueCell,
    _Out_opt_ PULONG Type,
    _Out_opt_ PUCHAR Data,
    _Inout_opt_ PULONG DataSize)
{
    ULONG DataLength;
    PVOID DataCell;

    /* Does the caller want the type? */
    if (Type != NULL)
        *Type = ValueCell->Type;

    /* Does the caller provide DataSize? */
    if (DataSize != NULL)
    {
        /*
         * The data in place. FreeLdr reads no big data (a value longer than
         * 16344 bytes in a hive of format 1.4 or later): CmpValueToData gives
         * NULL for it, and the value is an error to the caller.
         */
        DataCell = CmpValueToData(Hive, ValueCell, &DataLength);
        if (!DataCell)
        {
            WARN("RegQueryValue: the data of the value cannot be read here (big data)\n");
            *DataSize = 0;
            return ERROR_INVALID_DATA;
        }

        /* Does the caller want the data? */
        if ((Data != NULL) && (*DataSize != 0))
        {
            RtlCopyMemory(Data,
                          DataCell,
                          min(*DataSize, DataLength));
        }

        /* Return the actual data length */
        *DataSize = DataLength;
    }

    return ERROR_SUCCESS;
}

LONG
RegQueryValue(
    _In_ HKEY Key,
    _In_z_ PCWSTR ValueName,
    _Out_opt_ PULONG Type,
    _Out_opt_ PUCHAR Data,
    _Inout_opt_ PULONG DataSize)
{
    PHHIVE Hive = GET_HHIVE_FROM_HKEY(Key);
    PCM_KEY_NODE KeyNode;
    PCM_KEY_VALUE ValueCell;
    HCELL_INDEX CellIndex;
    UNICODE_STRING ValueNameString;
    LONG Result;

    TRACE("RegQueryValue(%p, '%S', %p, %p, %p)\n",
          Key, ValueName, Type, Data, DataSize);

    /* Get the key node */
    KeyNode = GET_CM_KEY_NODE(Hive, Key);
    ASSERT(KeyNode);
    ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);

    /* Initialize value name string */
    RtlInitUnicodeString(&ValueNameString, ValueName);
    CellIndex = CmpFindValueByName(Hive, KeyNode, &ValueNameString);
    if (CellIndex == HCELL_NIL)
    {
        TRACE("RegQueryValue value not found in key (%.*s)\n",
              KeyNode->NameLength, KeyNode->Name);
        HvReleaseCell(Hive, HKEY_TO_HCI(Key));
        return ERROR_FILE_NOT_FOUND;
    }
    HvReleaseCell(Hive, HKEY_TO_HCI(Key));

    /* Get the value cell */
    ValueCell = (PCM_KEY_VALUE)HvGetCell(Hive, CellIndex);
    ASSERT(ValueCell != NULL);

    Result = RepGetValueData(Hive, ValueCell, Type, Data, DataSize);

    HvReleaseCell(Hive, CellIndex);

    return Result;
}

/*
 * NOTE: This function is currently unused in FreeLdr; however it is kept here
 * as an implementation reference of RegEnumValue using CMLIB that may be used
 * elsewhere in ReactOS.
 */
#if 0
LONG
RegEnumValue(
    _In_ HKEY Key,
    _In_ ULONG Index,
    _Out_ PWCHAR ValueName,
    _Inout_ PULONG NameSize,
    _Out_opt_ PULONG Type,
    _Out_opt_ PUCHAR Data,
    _Inout_opt_ PULONG DataSize)
{
    PHHIVE Hive = GET_HHIVE_FROM_HKEY(Key);
    PCM_KEY_NODE KeyNode;
    PCELL_DATA ValueListCell;
    PCM_KEY_VALUE ValueCell;
    USHORT NameLength;

    TRACE("RegEnumValue(%p, %lu, %S, %p, %p, %p, %p (%lu))\n",
          Key, Index, ValueName, NameSize, Type, Data, DataSize, *DataSize);

    /* Get the key node */
    KeyNode = GET_CM_KEY_NODE(Hive, Key);
    ASSERT(KeyNode);
    ASSERT(KeyNode->Signature == CM_KEY_NODE_SIGNATURE);

    /* Check if the index is valid */
    if ((KeyNode->ValueList.Count == 0) ||
        (KeyNode->ValueList.List == HCELL_NIL) ||
        (Index >= KeyNode->ValueList.Count))
    {
        ERR("RegEnumValue: index invalid\n");
        HvReleaseCell(Hive, HKEY_TO_HCI(Key));
        return ERROR_NO_MORE_ITEMS;
    }

    ValueListCell = (PCELL_DATA)HvGetCell(Hive, KeyNode->ValueList.List);
    ASSERT(ValueListCell != NULL);

    /* Get the value cell */
    ValueCell = (PCM_KEY_VALUE)HvGetCell(Hive, ValueListCell->KeyList[Index]);
    ASSERT(ValueCell != NULL);
    ASSERT(ValueCell->Signature == CM_KEY_VALUE_SIGNATURE);

    if (ValueCell->Flags & VALUE_COMP_NAME)
    {
        NameLength = CmpCompressedNameSize(ValueCell->Name, ValueCell->NameLength);

        /* Compressed name */
        CmpCopyCompressedName(ValueName,
                              *NameSize,
                              ValueCell->Name,
                              ValueCell->NameLength);
    }
    else
    {
        NameLength = ValueCell->NameLength;

        /* Normal name */
        RtlCopyMemory(ValueName, ValueCell->Name,
                      min(*NameSize, ValueCell->NameLength));
    }

    if (*NameSize >= NameLength + sizeof(WCHAR))
    {
        ValueName[NameLength / sizeof(WCHAR)] = UNICODE_NULL;
    }

    *NameSize = NameLength + sizeof(WCHAR);

    RepGetValueData(Hive, ValueCell, Type, Data, DataSize);

    HvReleaseCell(Hive, ValueListCell->KeyList[Index]);
    HvReleaseCell(Hive, KeyNode->ValueList.List);
    HvReleaseCell(Hive, HKEY_TO_HCI(Key));

    TRACE("RegEnumValue done -> %u, '%.*S'\n", *NameSize, *NameSize, ValueName);
    return ERROR_SUCCESS;
}
#endif

/* EOF */
