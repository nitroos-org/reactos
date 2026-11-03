/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configuration Manager Library - Registry Hive Loading & Initialization
 * COPYRIGHT:   Copyright 2001 - 2005 Eric Kohl
 *              Copyright 2005 Filip Navara <navaraf@reactos.org>
 *              Copyright 2021 Max Korostil
 *              Copyright 2022 George Bișoc <george.bisoc@reactos.org>
 */

#include "cmlib.h"
#define NDEBUG
#include <debug.h>

/* ENUMERATIONS *************************************************************/

typedef enum _RESULT
{
    NotHive,
    Fail,
    NoMemory,
    HiveSuccess,
    RecoverHeader,
    RecoverData,
    SelfHeal,
    LogRefused,
    LogUnusable
} RESULT;

/* PRIVATE FUNCTIONS ********************************************************/

/**
 * @brief
 * Validates the base block header of a registry
 * file (hive or log).
 *
 * @param[in] BaseBlock
 * A pointer to a base block header to
 * be validated.
 *
 * @param[in] FileType
 * The file type of a registry file to check
 * against the file type of the base block.
 *
 * @return
 * Returns TRUE if the base block header is valid,
 * FALSE otherwise.
 */
BOOLEAN
CMAPI
HvpVerifyHiveHeader(
    _In_ PHBASE_BLOCK BaseBlock,
    _In_ ULONG FileType)
{
    if (BaseBlock->Signature != HV_HBLOCK_SIGNATURE ||
        BaseBlock->Major != HSYS_MAJOR ||
        BaseBlock->Minor < HSYS_MINOR ||
        BaseBlock->Type != FileType ||
        BaseBlock->Format != HBASE_FORMAT_MEMORY ||
        BaseBlock->Cluster != 1 ||
        BaseBlock->Sequence1 != BaseBlock->Sequence2 ||
        HvpHiveHeaderChecksum(BaseBlock) != BaseBlock->CheckSum)
    {
        DPRINT1("Verify Hive Header failed:\n");
        DPRINT1("    Signature: 0x%x, expected 0x%x; Major: 0x%x, expected 0x%x\n",
                BaseBlock->Signature, HV_HBLOCK_SIGNATURE, BaseBlock->Major, HSYS_MAJOR);
        DPRINT1("    Minor: 0x%x expected to be >= 0x%x; Type: 0x%x, expected 0x%x\n",
                BaseBlock->Minor, HSYS_MINOR, BaseBlock->Type, FileType);
        DPRINT1("    Format: 0x%x, expected 0x%x; Cluster: 0x%x, expected 1\n",
                BaseBlock->Format, HBASE_FORMAT_MEMORY, BaseBlock->Cluster);
        DPRINT1("    Sequence: 0x%x, expected 0x%x; Checksum: 0x%x, expected 0x%x\n",
                BaseBlock->Sequence1, BaseBlock->Sequence2,
                HvpHiveHeaderChecksum(BaseBlock), BaseBlock->CheckSum);

        return FALSE;
    }

    return TRUE;
}

/**
 * @brief
 * Frees all the bins within storage space
 * associated with a hive descriptor.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor where
 * all the bins are to be freed.
 */
VOID
CMAPI
HvpFreeHiveBins(
    _In_ PHHIVE Hive)
{
    ULONG i;
    PHBIN Bin;
    ULONG Storage;
    PHMAP_RETIRED_LIST Retired;

    for (Storage = 0; Storage < Hive->StorageTypeCount; Storage++)
    {
        Bin = NULL;
        for (i = 0; i < Hive->Storage[Storage].Length; i++)
        {
            if (Hive->Storage[Storage].BlockList[i].BinAddress == (ULONG_PTR)NULL)
                continue;
            if (Hive->Storage[Storage].BlockList[i].BinAddress != (ULONG_PTR)Bin)
            {
                Bin = (PHBIN)Hive->Storage[Storage].BlockList[i].BinAddress;
                Hive->Free((PHBIN)Hive->Storage[Storage].BlockList[i].BinAddress, 0);
            }
            Hive->Storage[Storage].BlockList[i].BinAddress = (ULONG_PTR)NULL;
            Hive->Storage[Storage].BlockList[i].BlockAddress = (ULONG_PTR)NULL;
        }

        if (Hive->Storage[Storage].Length)
            Hive->Free(Hive->Storage[Storage].BlockList, 0);

        while (Hive->Storage[Storage].RetiredBlockLists)
        {
            Retired = Hive->Storage[Storage].RetiredBlockLists;
            Hive->Storage[Storage].RetiredBlockLists = Retired->Next;
            Hive->Free(Retired->BlockList, 0);
            Hive->Free(Retired, 0);
        }
        Hive->Storage[Storage].BlockListCapacity = 0;
    }
}

/**
 * @brief
 * Allocates a cluster-aligned hive base header block.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor where
 * the header block allocator function is to
 * be gathered from.
 *
 * @param[in] Paged
 * If set to TRUE, the allocated base block will reside
 * in paged pool, otherwise it will reside in non paged
 * pool.
 *
 * @param[in] Tag
 * A tag name to supply for the allocated memory block
 * for identification. This is for debugging purposes.
 *
 * @return
 * Returns an allocated base block header if the function
 * succeeds, otherwise it returns NULL.
 */
static
__inline
PHBASE_BLOCK
HvpAllocBaseBlockAligned(
    _In_ PHHIVE Hive,
    _In_ BOOLEAN Paged,
    _In_ ULONG Tag)
{
    PHBASE_BLOCK BaseBlock;
    ULONG Alignment;

    ASSERT(sizeof(HBASE_BLOCK) >= (HSECTOR_SIZE * Hive->Cluster));

    /* Allocate the buffer */
    BaseBlock = Hive->Allocate(Hive->BaseBlockAlloc, Paged, Tag);
    if (!BaseBlock) return NULL;

    /* Check for, and enforce, alignment */
    Alignment = Hive->Cluster * HSECTOR_SIZE -1;
    if ((ULONG_PTR)BaseBlock & Alignment)
    {
        /* Free the old header and reallocate a new one, always paged */
        Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
        BaseBlock = Hive->Allocate(PAGE_SIZE, TRUE, Tag);
        if (!BaseBlock) return NULL;

        Hive->BaseBlockAlloc = PAGE_SIZE;
    }

    return BaseBlock;
}

/**
 * @brief
 * Initializes a NULL-terminated Unicode hive file name
 * of a hive header by copying the last 31 characters of
 * the hive file name. Mainly used for debugging purposes.
 *
 * @param[in,out] BaseBlock
 * A pointer to a base block header where the hive
 * file name is to be copied to.
 *
 * @param[in] FileName
 * A pointer to a Unicode string structure containing
 * the hive file name to be copied from. If this argument
 * is NULL, the base block will not have any hive file name.
 */
static
VOID
HvpInitFileName(
    _Inout_ PHBASE_BLOCK BaseBlock,
    _In_opt_ PCUNICODE_STRING FileName)
{
    ULONG_PTR Offset;
    SIZE_T    Length;

    /* Always NULL-initialize */
    RtlZeroMemory(BaseBlock->FileName, (HIVE_FILENAME_MAXLEN + 1) * sizeof(WCHAR));

    /* Copy the 31 last characters of the hive file name if any */
    if (!FileName) return;

    if (FileName->Length / sizeof(WCHAR) <= HIVE_FILENAME_MAXLEN)
    {
        Offset = 0;
        Length = FileName->Length;
    }
    else
    {
        Offset = FileName->Length / sizeof(WCHAR) - HIVE_FILENAME_MAXLEN;
        Length = HIVE_FILENAME_MAXLEN * sizeof(WCHAR);
    }

    RtlCopyMemory(BaseBlock->FileName, FileName->Buffer + Offset, Length);
}

/**
 * @brief
 * Initializes a hive descriptor structure for a
 * newly created hive in memory.
 *
 * @param[in,out] RegistryHive
 * A pointer to a registry hive descriptor where
 * the internal structures field are to be initialized
 * for the said hive.
 *
 * @param[in] FileName
 * A pointer to a Unicode string structure containing
 * the hive file name to be copied from. If this argument
 * is NULL, the base block will not have any hive file name.
 *
 * @return
 * Returns STATUS_SUCCESS if the function has created the
 * hive descriptor successfully. STATUS_NO_MEMORY is returned
 * if the base header block could not be allocated.
 */
NTSTATUS
CMAPI
HvpCreateHive(
    _Inout_ PHHIVE RegistryHive,
    _In_opt_ PCUNICODE_STRING FileName)
{
    PHBASE_BLOCK BaseBlock;
    ULONG Index;

    /* Allocate the base block */
    BaseBlock = HvpAllocBaseBlockAligned(RegistryHive, FALSE, TAG_CM);
    if (BaseBlock == NULL)
        return STATUS_NO_MEMORY;

    /* Clear it */
    RtlZeroMemory(BaseBlock, RegistryHive->BaseBlockAlloc);

    BaseBlock->Signature = HV_HBLOCK_SIGNATURE;
    BaseBlock->Major = HSYS_MAJOR;
    BaseBlock->Minor = HSYS_MINOR;
    BaseBlock->Type = HFILE_TYPE_PRIMARY;
    BaseBlock->Format = HBASE_FORMAT_MEMORY;
    BaseBlock->Cluster = 1;
    BaseBlock->RootCell = HCELL_NIL;
    BaseBlock->Length = 0;
    BaseBlock->Sequence1 = 1;
    BaseBlock->Sequence2 = 1;
    BaseBlock->TimeStamp.QuadPart = 0ULL;

    /*
     * No need to compute the checksum since
     * the hive resides only in memory so far.
     */
    BaseBlock->CheckSum = 0;

    /* Set default boot type */
    BaseBlock->BootType = HBOOT_TYPE_REGULAR;

    /* Setup hive data */
    RegistryHive->BaseBlock = BaseBlock;
    RegistryHive->Version = BaseBlock->Minor; // == HSYS_MINOR

    for (Index = 0; Index < 24; Index++)
    {
        RegistryHive->Storage[Stable].FreeDisplay[Index] = HCELL_NIL;
        RegistryHive->Storage[Volatile].FreeDisplay[Index] = HCELL_NIL;
    }

    HvpInitFileName(BaseBlock, FileName);

    return STATUS_SUCCESS;
}

/* Frees the stable bins of BlockList[0, BlockCount) and the block list;
 * entries past BlockCount are not initialized yet */
static
VOID
HvpFreePartialBins(
    _In_ PHHIVE Hive,
    _In_ SIZE_T BlockCount)
{
    SIZE_T i;
    ULONG_PTR Bin = (ULONG_PTR)NULL;

    for (i = 0; i < BlockCount; i++)
    {
        if (Hive->Storage[Stable].BlockList[i].BinAddress != Bin)
        {
            Bin = Hive->Storage[Stable].BlockList[i].BinAddress;
            Hive->Free((PVOID)Bin, 0);
        }
    }
    Hive->Free(Hive->Storage[Stable].BlockList, 0);
}

/**
 * @brief
 * Initializes a hive descriptor from an already loaded
 * registry hive stored in memory. The data of the hive is
 * copied and it is prepared for read/write access.
 *
 * @param[in] Hive
 * A pointer to a registry hive descriptor where
 * the internal structures field are to be initialized
 * from hive data that is already loaded in memory.
 *
 * @param[in] ChunkBase
 * A pointer to a valid base block header containing
 * registry header data for initialization.
 *
 * @param[in] FileName
 * A pointer to a Unicode string structure containing
 * the hive file name to be copied from. If this argument
 * is NULL, the base block will not have any hive file name.
 *
 * @return
 * Returns STATUS_SUCCESS if the function has initialized the
 * hive descriptor successfully. STATUS_REGISTRY_CORRUPT is
 * returned if the base block header contains invalid header
 * data, or if a bin or a cell is damaged beyond self-heal.
 * STATUS_NO_MEMORY is returned if memory could not be
 * allocated for registry stuff.
 */
NTSTATUS
CMAPI
HvpInitializeMemoryHive(
    _In_ PHHIVE Hive,
    _In_ PHBASE_BLOCK ChunkBase,
    _In_opt_ PCUNICODE_STRING FileName)
{
    SIZE_T BlockIndex;
    PHBIN Bin, NewBin;
    ULONG i;
    ULONG BitmapSize;
    PULONG BitmapBuffer;
    SIZE_T ChunkSize;
    NTSTATUS Status;

    ChunkSize = ChunkBase->Length;
    DPRINT("ChunkSize: %zx\n", ChunkSize);

    if (ChunkSize < sizeof(HBASE_BLOCK) ||
        !HvpVerifyHiveHeader(ChunkBase, HFILE_TYPE_PRIMARY))
    {
        DPRINT1("Registry is corrupt: ChunkSize 0x%zx < sizeof(HBASE_BLOCK) 0x%zx, "
                "or HvpVerifyHiveHeader() failed\n", ChunkSize, sizeof(HBASE_BLOCK));
        return STATUS_REGISTRY_CORRUPT;
    }

    /* Allocate the base block */
    Hive->BaseBlock = HvpAllocBaseBlockAligned(Hive, FALSE, TAG_CM);
    if (Hive->BaseBlock == NULL)
        return STATUS_NO_MEMORY;

    RtlCopyMemory(Hive->BaseBlock, ChunkBase, sizeof(HBASE_BLOCK));

    /* Setup hive data */
    Hive->Version = ChunkBase->Minor;

    /*
     * Build a block list from the in-memory chunk and copy the data as
     * we go.
     */

    Hive->Storage[Stable].Length = (ULONG)(ChunkSize / HBLOCK_SIZE);
    Hive->Storage[Stable].BlockList =
        Hive->Allocate(Hive->Storage[Stable].Length *
                       sizeof(HMAP_ENTRY), FALSE, TAG_CM);
    if (Hive->Storage[Stable].BlockList == NULL)
    {
        DPRINT1("Allocating block list failed\n");
        Hive->Free(Hive->BaseBlock, Hive->BaseBlockAlloc);
        return STATUS_NO_MEMORY;
    }

    for (BlockIndex = 0; BlockIndex < Hive->Storage[Stable].Length; )
    {
        Bin = (PHBIN)((ULONG_PTR)ChunkBase + (BlockIndex + 1) * HBLOCK_SIZE);

        /*
         * The original extent of a bin cannot safely be inferred from a damaged
         * size. Shrinking it to one block can split a multi-block bin and leave
         * a referenced cell header that no free-cell walk reaches, with a size
         * past its new bin, so refuse the hive instead.
         */
        if (Bin->Size == 0 ||
            (Bin->Size % HBLOCK_SIZE) != 0 ||
            Bin->Size / HBLOCK_SIZE > Hive->Storage[Stable].Length - BlockIndex)
        {
            DPRINT1("Bin at BlockIndex %lu has an unusable size 0x%x, the hive is corrupt\n",
                    (unsigned long)BlockIndex, (unsigned)Bin->Size);
            HvpFreePartialBins(Hive, BlockIndex);
            Hive->Free(Hive->BaseBlock, Hive->BaseBlockAlloc);
            return STATUS_REGISTRY_CORRUPT;
        }

        if (Bin->Signature != HV_HBIN_SIGNATURE ||
           (Bin->FileOffset / HBLOCK_SIZE) != BlockIndex)
        {
            /*
             * The size is sound but the signature or the offset is out of
             * order: restore both and keep the size, so a multi-block bin
             * keeps all of its blocks.
             */
            if (!CmIsSelfHealEnabled(FALSE))
            {
                DPRINT1("Invalid bin at BlockIndex %lu, Signature 0x%x, Size 0x%x. Self-heal not possible!\n",
                    (unsigned long)BlockIndex, (unsigned)Bin->Signature, (unsigned)Bin->Size);
                HvpFreePartialBins(Hive, BlockIndex);
                Hive->Free(Hive->BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_REGISTRY_CORRUPT;
            }

            /* Fix this bin */
            Bin->Signature = HV_HBIN_SIGNATURE;
            Bin->FileOffset = BlockIndex * HBLOCK_SIZE;
            ChunkBase->BootType |= HBOOT_TYPE_SELF_HEAL;
            DPRINT1("Bin at index %lu is corrupt and it has been repaired!\n", (unsigned long)BlockIndex);
        }

        NewBin = Hive->Allocate(Bin->Size, TRUE, TAG_CM);
        if (NewBin == NULL)
        {
            HvpFreePartialBins(Hive, BlockIndex);
            Hive->Free(Hive->BaseBlock, Hive->BaseBlockAlloc);
            return STATUS_NO_MEMORY;
        }

        Hive->Storage[Stable].BlockList[BlockIndex].BinAddress = (ULONG_PTR)NewBin;
        Hive->Storage[Stable].BlockList[BlockIndex].BlockAddress = (ULONG_PTR)NewBin;

        RtlCopyMemory(NewBin, Bin, Bin->Size);

        if (Bin->Size > HBLOCK_SIZE)
        {
            for (i = 1; i < Bin->Size / HBLOCK_SIZE; i++)
            {
                Hive->Storage[Stable].BlockList[BlockIndex + i].BinAddress = (ULONG_PTR)NewBin;
                Hive->Storage[Stable].BlockList[BlockIndex + i].BlockAddress =
                    ((ULONG_PTR)NewBin + (i * HBLOCK_SIZE));
            }
        }

        BlockIndex += Bin->Size / HBLOCK_SIZE;
    }

    Status = HvpCreateHiveFreeCellList(Hive);
    if (!NT_SUCCESS(Status))
    {
        HvpFreeHiveBins(Hive);
        Hive->Free(Hive->BaseBlock, Hive->BaseBlockAlloc);
        return Status;
    }

    BitmapSize = ROUND_UP(Hive->Storage[Stable].Length,
                          sizeof(ULONG) * 8) / 8;
    BitmapBuffer = (PULONG)Hive->Allocate(BitmapSize, TRUE, TAG_CM);
    if (BitmapBuffer == NULL)
    {
        HvpFreeHiveBins(Hive);
        Hive->Free(Hive->BaseBlock, Hive->BaseBlockAlloc);
        return STATUS_NO_MEMORY;
    }

    RtlInitializeBitMap(&Hive->DirtyVector, BitmapBuffer, BitmapSize * 8);
    RtlClearAllBits(&Hive->DirtyVector);

    /*
     * Mark the entire hive as dirty. Indeed we understand if we charged up
     * the alternate variant of the primary hive (e.g. SYSTEM.ALT) because
     * FreeLdr could not load the main SYSTEM hive, due to corruptions, and
     * repairing it with a LOG did not help at all.
     */
    if (ChunkBase->BootRecover == HBOOT_BOOT_RECOVERED_BY_ALTERNATE_HIVE)
    {
        RtlSetAllBits(&Hive->DirtyVector);
        Hive->DirtyCount = Hive->DirtyVector.SizeOfBitMap;
    }

    HvpInitFileName(Hive->BaseBlock, FileName);

    return STATUS_SUCCESS;
}

/**
 * @brief
 * Initializes a hive descriptor for an already loaded hive
 * that is stored in memory. This descriptor serves to denote
 * such hive as being "flat", that is, the data and properties
 * can be only read and not written into.
 *
 * @param[in] Hive
 * A pointer to a registry hive descriptor where
 * the internal structures fields are to be initialized
 * from hive data that is already loaded in memory. Such
 * hive descriptor will become read-only and flat.
 *
 * @param[in] ChunkBase
 * A pointer to a valid base block header containing
 * registry header data for initialization.
 *
 * @return
 * Returns STATUS_SUCCESS if the function has initialized the
 * flat hive descriptor. STATUS_REGISTRY_CORRUPT is returned if
 * the base block header contains invalid header data.
 */
NTSTATUS
CMAPI
HvpInitializeFlatHive(
    _In_ PHHIVE Hive,
    _In_ PHBASE_BLOCK ChunkBase)
{
    if (!HvpVerifyHiveHeader(ChunkBase, HFILE_TYPE_PRIMARY))
        return STATUS_REGISTRY_CORRUPT;

    /* Setup hive data */
    Hive->BaseBlock = ChunkBase;
    Hive->Version = ChunkBase->Minor;
    Hive->Flat = TRUE;
    Hive->ReadOnly = TRUE;

    Hive->StorageTypeCount = 1;

    /* Set default boot type */
    ChunkBase->BootType = HBOOT_TYPE_REGULAR;

    return STATUS_SUCCESS;
}

/**
 * @brief
 * Retrieves the base block hive header from the
 * primary hive file stored in physical backing storage.
 * This function may invoke a self-healing warning if
 * hive header couldn't be obtained. See Return and Remarks
 * sections for further information.
 *
 * @param[in] Hive
 * A pointer to a registry hive descriptor that points
 * to the primary hive being loaded. This descriptor is
 * needed to obtain the hive header block from said hive.
 *
 * @param[in,out] HiveBaseBlock
 * A pointer returned by the function that contains
 * the hive header base block buffer obtained from
 * the primary hive file pointed by the Hive argument.
 * When RecoverHeader is returned, it receives the base
 * block as read from the hive file if that read succeeded,
 * or NULL. The caller frees the returned buffer.
 * This parameter must not be NULL!
 *
 * @param[in,out] TimeStamp
 * A pointer returned by the function that contains
 * the time-stamp of the registry hive file at the
 * moment of creation or modification. This parameter
 * must not be NULL!
 *
 * @return
 * This function returns a result indicator. That is,
 * HiveSuccess is returned if the hive header was obtained
 * successfully. NoMemory is returned if the hive base block
 * could not be allocated. NotHive is returned if the hive file
 * that's been read isn't actually a hive. RecoverHeader is
 * returned if the header needs to be recovered. RecoverData
 * is returned if the hive data needs to be returned.
 *
 * @remarks
 * RecoverHeader and RecoverData are status indicators that
 * invoke a self-healing procedure if the hive header could not
 * be obtained in a normal way and as a matter of fact the whole
 * registry initialization procedure is orchestrated. RecoverHeader
 * implies that the base block header of a hive is corrupt and it
 * needs to be recovered, whereas RecoverData implies the registry
 * data is corrupt. The latter status indicator is less severe unlike
 * the former because the system can cope with data loss.
 */
RESULT
CMAPI
HvpGetHiveHeader(
    _In_ PHHIVE Hive,
    _Inout_ PHBASE_BLOCK *HiveBaseBlock,
    _Inout_ PLARGE_INTEGER TimeStamp)
{
    PHBASE_BLOCK BaseBlock;
    ULONG Result;
    ULONG FileOffset;
    PHBIN FirstBin;

    ASSERT(sizeof(HBASE_BLOCK) >= (HSECTOR_SIZE * Hive->Cluster));

    /* Assume failure and allocate the base block */
    *HiveBaseBlock = NULL;
    BaseBlock = HvpAllocBaseBlockAligned(Hive, TRUE, TAG_CM);
    if (!BaseBlock)
    {
        DPRINT1("Failed to allocate an aligned base block buffer\n");
        return NoMemory;
    }

    /* Clear it */
    RtlZeroMemory(BaseBlock, sizeof(HBASE_BLOCK));

    /* Now read it from disk */
    FileOffset = 0;
    Result = Hive->FileRead(Hive,
                            HFILE_TYPE_PRIMARY,
                            &FileOffset,
                            BaseBlock,
                            Hive->Cluster * HSECTOR_SIZE);
    if (!Result)
    {
        /*
         * Don't assume the hive is ultimately destroyed
         * but instead try to read the first block of
         * the first bin hive. So that we're sure of
         * ourselves we can somewhat recover this hive.
         */
        FileOffset = HBLOCK_SIZE;
        Result = Hive->FileRead(Hive,
                                HFILE_TYPE_PRIMARY,
                                &FileOffset,
                                (PVOID)BaseBlock,
                                Hive->Cluster * HSECTOR_SIZE);
        if (!Result)
        {
            DPRINT1("Failed to read the first block of the first bin hive (hive too corrupt)\n");
            Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
            return NotHive;
        }

        /*
         * Deconstruct the casted buffer we got
         * into a hive bin. Check if the offset
         * position is in the right place (namely
         * its offset must be 0 because it's the first
         * bin) and it should have a sane signature.
         */
        FirstBin = (PHBIN)BaseBlock;
        if (FirstBin->Signature != HV_HBIN_SIGNATURE ||
            FirstBin->FileOffset != 0)
        {
            DPRINT1("Failed to read the first block of the first bin hive (hive too corrupt)\n");
            Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
            return NotHive;
        }

        /*
         * There's still hope for this hive so acknowledge the
         * caller this hive needs a recoverable header. Nothing
         * is known of the base block, its time stamp included.
         */
        Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
        TimeStamp->QuadPart = 0;
        DPRINT1("The hive is not fully corrupt, the base block needs to be RECOVERED\n");
        return RecoverHeader;
    }

    /*
     * This hive has a base block that's not maimed
     * but is the header data valid?
     *
     * FIXME: We must check if primary and secondary
     * sequences mismatch separately and fire up RecoverData
     * in that case  but due to a hack in HvLoadHive, let
     * HvpVerifyHiveHeader check the sequences for now.
     */
    if (!HvpVerifyHiveHeader(BaseBlock, HFILE_TYPE_PRIMARY))
    {
        DPRINT1("The hive base header block needs to be RECOVERED\n");
        *HiveBaseBlock = BaseBlock;
        *TimeStamp = BaseBlock->TimeStamp;
        return RecoverHeader;
    }

    /* Return information */
    *HiveBaseBlock = BaseBlock;
    *TimeStamp = BaseBlock->TimeStamp;
    return HiveSuccess;
}

/**
 * @brief
 * Queries the size of one of the files of a hive.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor.
 *
 * @param[in] FileType
 * The file to query (HFILE_TYPE_PRIMARY or HFILE_TYPE_LOG).
 *
 * @param[out] FileSize
 * Receives the size of the file in bytes.
 *
 * @return
 * Returns TRUE if the size is known, FALSE otherwise.
 * Only the kernel can query it; only the kernel loads
 * hives from files (HINIT_FILE).
 */
BOOLEAN
CMAPI
HvpQueryFileSize(
    _In_ PHHIVE Hive,
    _In_ ULONG FileType,
    _Out_ PLARGE_INTEGER FileSize)
{
#if !defined(CMLIB_HOST) && !defined(_BLDR_)
    NTSTATUS Status;
    FILE_STANDARD_INFORMATION FileStandard;
    IO_STATUS_BLOCK IoStatusBlock;

    Status = ZwQueryInformationFile(((PCMHIVE)Hive)->FileHandles[FileType],
                                    &IoStatusBlock,
                                    &FileStandard,
                                    sizeof(FILE_STANDARD_INFORMATION),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ZwQueryInformationFile returned 0x%lx\n", Status);
        return FALSE;
    }

    *FileSize = FileStandard.EndOfFile;
    return TRUE;
#else
    FileSize->QuadPart = 0;
    return FALSE;
#endif
}

/*
 * FIXME: Disable compilation for the AMD64 boot loader for now since it
 * makes the FreeLdr binary size so large it makes booting impossible.
 * The kernel needs it: without it a hive whose flush was interrupted
 * cannot be loaded.
 */
#if !defined(_M_AMD64) || !defined(_BLDR_)
/**
 * @brief
 * Computes the hive space size by querying
 * the file size of the associated hive file.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor where the
 * hive length size is to be calculated.
 *
 * @return
 * Returns the computed hive size, the file size
 * less the base block rounded down to whole blocks,
 * or 0 if it could not be determined.
 */
ULONG
CMAPI
HvpQueryHiveSize(
    _In_ PHHIVE Hive)
{
    LARGE_INTEGER FileSize;

    if (!HvpQueryFileSize(Hive, HFILE_TYPE_PRIMARY, &FileSize) ||
        FileSize.QuadPart < HBLOCK_SIZE ||
        FileSize.QuadPart > MAXULONG)
    {
        return 0;
    }

    return ROUND_DOWN(FileSize.u.LowPart - HBLOCK_SIZE, HBLOCK_SIZE);
}

/**
 * @brief
 * Recovers a dirty hive from its log, if the log
 * belongs to the write of the hive that was interrupted.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor associated
 * with the log file where the hive data is to
 * be read from.
 *
 * @param[in] PrimaryBaseBlock
 * A pointer to the base block of the primary hive
 * as read from the hive file. The base block failed
 * the header check.
 *
 * @param[out] RecoveredBaseBlock
 * A pointer returned by the function that receives
 * the base block of the recovered hive when the function
 * returns HiveSuccess. The caller frees it.
 *
 * @return
 * Returns HiveSuccess if the hive was recovered from the log.
 * LogRefused is returned if the log does not belong to the
 * interrupted write: it is shorter than its base block, its base
 * block is not valid, its time stamp differs, or its sequence is
 * older. LogUnusable is returned if the log may belong to the
 * interrupted write but cannot recover the hive: the file sizes
 * cannot be queried, the base block cannot be read, the length or
 * root cell it describes is not valid, its dirty vector is missing
 * or damaged, it does not hold every dirty block, or the hive file
 * does not hold every block the log does not. Nothing has been
 * written to the hive in these two cases. NoMemory is returned if
 * memory could not be allocated. Fail is returned if reading or
 * writing failed once the recovery had started writing the hive;
 * some dirty blocks may have been written then, but the base block
 * is written last, so unless only its final flush failed the hive
 * is still dirty and the recovery is repeated on the next load.
 *
 * @remarks
 * HvpWriteLog writes the log as the base block (sequence S+1,
 * with the time stamp of the write), the dirty vector (a signature
 * and one byte per block, 0xFF for a dirty block, rounded up as
 * HvpWriteLog does it), then the dirty blocks, and flushes it. Only
 * then HvpWriteHive writes the hive, with the same time stamp and the
 * sequences S+2/S+1 until it ends. The log belongs to the interrupted
 * write if:
 *
 * - its base block is valid, with equal sequence numbers;
 * - its time stamp equals the time stamp of the hive;
 * - if the base block of the hive has a valid checksum, its sequence
 *   number is not older than the secondary sequence number of the hive
 *   (the last write that completed). A damaged base block is matched
 *   by its time stamp alone.
 *
 * It is applied only if, in addition, the length it describes is a whole
 * number of blocks and holds its root cell, every byte of the dirty vector
 * is 0 or 0xFF after its signature, the log file holds every dirty block,
 * and the hive file holds every block the log does not. A hive that grew
 * in the interrupted write is recovered, as its new blocks are all dirty.
 *
 * All of this is checked before the first write to the hive. The dirty
 * blocks are written and flushed before the base block, so that a crash
 * during the recovery leaves a dirty hive that is recovered again.
 */
RESULT
CMAPI
HvpRecoverHiveFromLog(
    _In_ PHHIVE Hive,
    _In_ PHBASE_BLOCK PrimaryBaseBlock,
    _Out_ PHBASE_BLOCK *RecoveredBaseBlock)
{
    BOOLEAN Success;
    PHBASE_BLOCK LogHeader;
    PUCHAR DirtyVector = NULL;
    PUCHAR Buffer = NULL;
    ULONG FileOffset;
    ULONG StorageLength;
    ULONG VectorSize;
    ULONG BlockIndex;
    ULONG LogIndex;
    ULONG DirtyCount;
    ULONG LastCleanBlock;
    LARGE_INTEGER LogFileSize;
    LARGE_INTEGER PrimaryFileSize;
    UCHAR DirtyFlag;
    RESULT Result;

    /*
     * The cluster must not be greater than what the
     * base block can permit.
     */
    ASSERT(sizeof(HBASE_BLOCK) >= (HSECTOR_SIZE * Hive->Cluster));

    *RecoveredBaseBlock = NULL;

    /* Allocate an aligned buffer for the log header */
    LogHeader = HvpAllocBaseBlockAligned(Hive, TRUE, TAG_CM);
    if (!LogHeader)
    {
        DPRINT1("Failed to allocate memory for the log header\n");
        return NoMemory;
    }

    /*
     * The file sizes bound every read below: a file system may return
     * the rest of the last sector of a file as data. Until the log is
     * known not to belong to the hive, an error fails the load.
     */
    Result = LogUnusable;
    if (!HvpQueryFileSize(Hive, HFILE_TYPE_LOG, &LogFileSize) ||
        !HvpQueryFileSize(Hive, HFILE_TYPE_PRIMARY, &PrimaryFileSize))
    {
        DPRINT1("The sizes of the hive files are not known\n");
        goto Quit;
    }

    /* A log too short for its base block holds nothing to recover */
    if ((ULONGLONG)LogFileSize.QuadPart < Hive->Cluster * HSECTOR_SIZE)
    {
        DPRINT1("The hive log is empty or shorter than its base block\n");
        Result = LogRefused;
        goto Quit;
    }

    /* Read the base block of the log */
    RtlZeroMemory(LogHeader, sizeof(HBASE_BLOCK));
    FileOffset = 0;
    Success = Hive->FileRead(Hive,
                             HFILE_TYPE_LOG,
                             &FileOffset,
                             LogHeader,
                             Hive->Cluster * HSECTOR_SIZE);
    if (!Success)
    {
        DPRINT1("The hive log base block could not be read\n");
        goto Quit;
    }

    if (!HvpVerifyHiveHeader(LogHeader, HFILE_TYPE_LOG))
    {
        DPRINT1("The hive log base block is not valid\n");
        Result = LogRefused;
        goto Quit;
    }

    /* A larger cluster read the start of the dirty vector too */
    RtlZeroMemory((PUCHAR)LogHeader + HV_LOG_HEADER_SIZE,
                  sizeof(HBASE_BLOCK) - HV_LOG_HEADER_SIZE);

    /* The log must belong to the interrupted write of this hive */
    if (LogHeader->TimeStamp.QuadPart != PrimaryBaseBlock->TimeStamp.QuadPart ||
        (HvpHiveHeaderChecksum(PrimaryBaseBlock) == PrimaryBaseBlock->CheckSum &&
         LogHeader->Sequence1 < PrimaryBaseBlock->Sequence2))
    {
        DPRINT1("The hive log does not match the hive (log sequence 0x%x, hive sequences 0x%x/0x%x)\n",
                LogHeader->Sequence1, PrimaryBaseBlock->Sequence1, PrimaryBaseBlock->Sequence2);
        Result = LogRefused;
        goto Quit;
    }

    /* From here on the log belongs to the hive: a log that cannot recover it fails the load */
    if (LogHeader->Length == 0 ||
        (LogHeader->Length % HBLOCK_SIZE) != 0 ||
        LogHeader->Length > MAXULONG - HBLOCK_SIZE ||
        LogHeader->RootCell >= LogHeader->Length)
    {
        DPRINT1("The hive log describes a bad length 0x%x (root cell 0x%x)\n",
                LogHeader->Length, LogHeader->RootCell);
        goto Quit;
    }

    /* Read the dirty vector, sized from the hive length as HvpWriteLog does it */
    StorageLength = LogHeader->Length / HBLOCK_SIZE;
    VectorSize = ROUND_UP(sizeof(HV_LOG_DIRTY_SIGNATURE) + ROUND_UP(StorageLength, sizeof(ULONG) * 8), HSECTOR_SIZE);
    if ((ULONGLONG)HV_LOG_HEADER_SIZE + VectorSize > (ULONGLONG)LogFileSize.QuadPart)
    {
        DPRINT1("The hive log ends before its dirty vector\n");
        goto Quit;
    }

    DirtyVector = Hive->Allocate(VectorSize, TRUE, TAG_CM);
    Buffer = Hive->Allocate(HBLOCK_SIZE, TRUE, TAG_CM);
    if (!DirtyVector || !Buffer)
    {
        Result = NoMemory;
        goto Quit;
    }

    FileOffset = HV_LOG_HEADER_SIZE;
    Success = Hive->FileRead(Hive,
                             HFILE_TYPE_LOG,
                             &FileOffset,
                             DirtyVector,
                             VectorSize);
    if (!Success || *((PULONG)DirtyVector) != HV_LOG_DIRTY_SIGNATURE)
    {
        DPRINT1("The hive log dirty vector could not be read or has no signature\n");
        goto Quit;
    }

    /* HvpWriteLog writes 0xFF for a dirty block and 0 for any other */
    DirtyCount = 0;
    LastCleanBlock = MAXULONG;
    for (BlockIndex = 0; BlockIndex < StorageLength; BlockIndex++)
    {
        DirtyFlag = DirtyVector[BlockIndex + sizeof(HV_LOG_DIRTY_SIGNATURE)];
        if (DirtyFlag == HV_LOG_DIRTY_BLOCK)
        {
            DirtyCount++;
        }
        else if (DirtyFlag == 0)
        {
            LastCleanBlock = BlockIndex;
        }
        else
        {
            DPRINT1("The hive log dirty vector is damaged (block %u)\n", BlockIndex);
            goto Quit;
        }
    }

    /* The log must hold every dirty block, at offsets that fit in a ULONG */
    if ((ULONGLONG)HV_LOG_HEADER_SIZE + VectorSize + (ULONGLONG)DirtyCount * HBLOCK_SIZE > (ULONGLONG)LogFileSize.QuadPart ||
        (ULONGLONG)HV_LOG_HEADER_SIZE + VectorSize + (ULONGLONG)DirtyCount * HBLOCK_SIZE > MAXULONG)
    {
        DPRINT1("The hive log ends before its %u dirty blocks\n", DirtyCount);
        goto Quit;
    }

    /* The hive file must hold every block the log does not */
    if (LastCleanBlock != MAXULONG &&
        (ULONGLONG)(LastCleanBlock + 2) * HBLOCK_SIZE > (ULONGLONG)PrimaryFileSize.QuadPart)
    {
        DPRINT1("The hive file does not hold block %u, which the log does not hold either\n", LastCleanBlock);
        goto Quit;
    }

    /* Read every dirty block once before the first write */
    for (LogIndex = 0; LogIndex < DirtyCount; LogIndex++)
    {
        FileOffset = HV_LOG_HEADER_SIZE + VectorSize + LogIndex * HBLOCK_SIZE;
        Success = Hive->FileRead(Hive,
                                 HFILE_TYPE_LOG,
                                 &FileOffset,
                                 Buffer,
                                 HBLOCK_SIZE);
        if (!Success)
        {
            DPRINT1("Failed to read the dirty block %u of %u from the hive log\n", LogIndex, DirtyCount);
            goto Quit;
        }
    }

    /* Everything is checked: write the dirty blocks to the hive */
    DPRINT1("Recovering the hive from its log (%u dirty blocks)\n", DirtyCount);
    Result = Fail;
    LogIndex = 0;
    for (BlockIndex = 0; BlockIndex < StorageLength; BlockIndex++)
    {
        if (DirtyVector[BlockIndex + sizeof(HV_LOG_DIRTY_SIGNATURE)] != HV_LOG_DIRTY_BLOCK)
            continue;

        FileOffset = HV_LOG_HEADER_SIZE + VectorSize + LogIndex * HBLOCK_SIZE;
        Success = Hive->FileRead(Hive,
                                 HFILE_TYPE_LOG,
                                 &FileOffset,
                                 Buffer,
                                 HBLOCK_SIZE);
        if (!Success)
        {
            DPRINT1("Failed to read the dirty block (index %u)\n", BlockIndex);
            goto Quit;
        }

        FileOffset = HBLOCK_SIZE + BlockIndex * HBLOCK_SIZE;
        Success = Hive->FileWrite(Hive,
                                  HFILE_TYPE_PRIMARY,
                                  &FileOffset,
                                  Buffer,
                                  HBLOCK_SIZE);
        if (!Success)
        {
            DPRINT1("Failed to write dirty block to hive (index %u)\n", BlockIndex);
            goto Quit;
        }

        LogIndex++;
    }

    /* The blocks must be on the medium before the base block marks the hive clean */
    if (!Hive->FileFlush(Hive, HFILE_TYPE_PRIMARY, NULL, 0))
    {
        DPRINT1("Failed to flush the recovered blocks\n");
        goto Quit;
    }

    /* Write the base block of the log to the hive, as a primary one */
    LogHeader->Type = HFILE_TYPE_PRIMARY;
    LogHeader->CheckSum = HvpHiveHeaderChecksum(LogHeader);
    FileOffset = 0;
    Success = Hive->FileWrite(Hive,
                              HFILE_TYPE_PRIMARY,
                              &FileOffset,
                              LogHeader,
                              Hive->Cluster * HSECTOR_SIZE);
    if (!Success || !Hive->FileFlush(Hive, HFILE_TYPE_PRIMARY, NULL, 0))
    {
        DPRINT1("Couldn't write the base header to primary hive\n");
        goto Quit;
    }

    *RecoveredBaseBlock = LogHeader;
    LogHeader = NULL;
    Result = HiveSuccess;

Quit:
    if (Buffer)
        Hive->Free(Buffer, HBLOCK_SIZE);
    if (DirtyVector)
        Hive->Free(DirtyVector, VectorSize);
    if (LogHeader)
        Hive->Free(LogHeader, Hive->BaseBlockAlloc);
    return Result;
}

/**
 * @brief
 * Makes the base block of a dirty hive that no log
 * can recover usable again, for a self-healing load
 * of the hive as it is on disk.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor.
 *
 * @param[in,out] BaseBlock
 * A pointer to the base block of the primary hive
 * as read from the hive file. It is changed in memory
 * only.
 *
 * @return
 * Returns HiveSuccess if the base block can be used,
 * Fail otherwise.
 *
 * @remarks
 * A base block that is intact but for its sequence numbers
 * is kept with its own length. A damaged one is rebuilt
 * from its own fields, with the length of the hive file
 * (see https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#notes-4).
 * Nothing from a log that does not belong to the hive is
 * used. CmCheckRegistry judges the hive afterwards.
 */
RESULT
CMAPI
HvpHealBaseBlock(
    _In_ PHHIVE Hive,
    _Inout_ PHBASE_BLOCK BaseBlock)
{
    ULONG HiveSize;

    if (BaseBlock->Signature != HV_HBLOCK_SIGNATURE)
    {
        DPRINT1("The hive base block has no signature, it cannot be healed\n");
        return Fail;
    }

    if (HvpHiveHeaderChecksum(BaseBlock) != BaseBlock->CheckSum ||
        BaseBlock->Major != HSYS_MAJOR ||
        BaseBlock->Minor < HSYS_MINOR ||
        BaseBlock->Type != HFILE_TYPE_PRIMARY ||
        BaseBlock->Format != HBASE_FORMAT_MEMORY ||
        BaseBlock->Cluster != 1 ||
        BaseBlock->Length == 0 ||
        (BaseBlock->Length % HBLOCK_SIZE) != 0 ||
        BaseBlock->Length > MAXULONG - HBLOCK_SIZE)
    {
        /* The base block is damaged: rebuild it */
        HiveSize = HvpQueryHiveSize(Hive);
        if (HiveSize == 0)
        {
            DPRINT1("Failed to query the hive size\n");
            return Fail;
        }

        BaseBlock->Type = HFILE_TYPE_PRIMARY;
        BaseBlock->Cluster = 1;
        BaseBlock->Length = HiveSize;
        DPRINT1("The hive base block has been rebuilt (length 0x%x)\n", HiveSize);
    }

    BaseBlock->Sequence2 = BaseBlock->Sequence1;
    BaseBlock->CheckSum = HvpHiveHeaderChecksum(BaseBlock);
    return HiveSuccess;
}
#endif

/**
 * @brief
 * Loads a registry hive from a physical hive file
 * within the physical backing storage. Base block
 * and registry data are read from the said physical
 * hive file. This function can perform registry recovery
 * if hive loading could not be done normally.
 *
 * @param[in] Hive
 * A pointer to a hive descriptor where the said hive
 * is to be loaded from the physical hive file.
 *
 * @param[in] FileName
 * A pointer to a NULL-terminated Unicode string structure
 * containing the hive file name to be copied from.
 *
 * @return
 * STATUS_SUCCESS is returned if the hive has been loaded
 * successfully. STATUS_INSUFFICIENT_RESOURCES is returned
 * if there's not enough memory resources to satisfy registry
 * operations and/or requests. STATUS_NOT_REGISTRY_FILE is returned
 * if the hive is not actually a hive file. STATUS_REGISTRY_CORRUPT
 * is returned if the hive has subdued previous damage and
 * the hive could not be recovered because there's no
 * log present or self healing is disabled, or if its log belongs to
 * it but cannot recover it. STATUS_REGISTRY_IO_FAILED is returned if
 * the recovery from the log failed while writing the hive.
 * STATUS_REGISTRY_RECOVERED is returned if the hive has been
 * recovered from its log. An eventual flush of the registry is needed
 * after the hive's been fully loaded.
 *
 * @remarks
 * A dirty hive (its base block fails the header check) is recovered
 * from its log only if the log belongs to the interrupted write, see
 * HvpRecoverHiveFromLog. A log that may belong to it but is found
 * unable to recover it before the first write fails the load, and
 * nothing is written. If the log does not
 * belong to the hive, with self-healing enabled, the hive is loaded
 * as it is on disk, with its own base block made
 * consistent in memory and every block marked dirty, so that the
 * next flush writes the whole hive through the log. Nothing is
 * written during the load in that case. A hive whose base block
 * cannot be read is not loaded.
 */
NTSTATUS
CMAPI
HvLoadHive(
    _In_ PHHIVE Hive,
    _In_opt_ PCUNICODE_STRING FileName)
{
    NTSTATUS Status;
    BOOLEAN Success;
    PHBASE_BLOCK BaseBlock = NULL;
/* FIXME: See the comment above (near HvpQueryHiveSize) */
#if defined(_M_AMD64) && defined(_BLDR_)
    ULONG Result;
#else
    ULONG Result, Result2;
    PHBASE_BLOCK RecoveredBaseBlock;
#endif
    LARGE_INTEGER TimeStamp;
    ULONG Offset = 0;
    PVOID HiveData;
    ULONG FileSize;
    LARGE_INTEGER HiveFileSize;
    BOOLEAN HiveSelfHeal = FALSE;

    /* Get the hive header */
    Result = HvpGetHiveHeader(Hive, &BaseBlock, &TimeStamp);
    switch (Result)
    {
        /* Out of memory */
        case NoMemory:
        {
            /* Fail */
            DPRINT1("There's no enough memory to get the header\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Not a hive */
        case NotHive:
        {
            /* Fail */
            DPRINT1("The hive is not an actual registry hive file\n");
            return STATUS_NOT_REGISTRY_FILE;
        }

        /* Hive data needs a repair */
        case RecoverData:
        {
            /*
             * FIXME: We must be handling this status
             * case if the header isn't corrupt but
             * the counter sequences do not match but
             * due to a hack in HvLoadHive we have
             * to do both a header + data recovery.
             * RecoverHeader also implies RecoverData
             * anyway. When HvLoadHive gets rid of
             * that hack, data recovery must be done
             * after we read the hive block by block.
             */
            break;
        }

        /* Hive header needs a repair */
        case RecoverHeader:
/* FIXME: See the comment above (near HvpQueryHiveSize) */
#if defined(_M_AMD64) && defined(_BLDR_)
        {
            if (BaseBlock)
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
            return STATUS_REGISTRY_CORRUPT;
        }
#else
        {
            /* Check if this hive has a log at hand to begin with */
            #if (NTDDI_VERSION < NTDDI_VISTA)
            if (!Hive->Log)
            {
                DPRINT1("The hive has no log for header recovery\n");
                if (BaseBlock)
                    Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_REGISTRY_CORRUPT;
            }
            #endif

            /* Without its base block there is nothing to match a log with, or to keep */
            if (!BaseBlock)
            {
                DPRINT1("The hive base block could not be read\n");
                return STATUS_REGISTRY_CORRUPT;
            }

            /* Recover the hive from its log, if the log belongs to it */
            DPRINT1("Attempting to recover the hive from its log...\n");
            Result2 = HvpRecoverHiveFromLog(Hive, BaseBlock, &RecoveredBaseBlock);
            if (Result2 == HiveSuccess)
            {
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                BaseBlock = RecoveredBaseBlock;
                break;
            }

            if (Result2 == NoMemory)
            {
                DPRINT1("There's no enough memory to recover the hive from its log\n");
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (Result2 == Fail)
            {
                DPRINT1("Failed to write the hive recovered from its log\n");
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_REGISTRY_IO_FAILED;
            }

            if (Result2 == LogUnusable)
            {
                DPRINT1("The hive log belongs to the hive but cannot recover it\n");
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_REGISTRY_CORRUPT;
            }

            /* The log does not belong to the hive: keep the hive as it is on disk */
            ASSERT(Result2 == LogRefused);
            if (!CmIsSelfHealEnabled(FALSE))
            {
                DPRINT1("The hive log cannot be used and self-healing mode is disabled\n");
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_REGISTRY_CORRUPT;
            }

            if (HvpHealBaseBlock(Hive, BaseBlock) != HiveSuccess)
            {
                Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
                return STATUS_REGISTRY_CORRUPT;
            }

            DPRINT1("The hive log cannot be used, triggering self-heal mode on the hive as it is\n");
            HiveSelfHeal = TRUE;
            break;
        }
#endif
    }

    /* Set the boot type */
    BaseBlock->BootType = HiveSelfHeal ? HBOOT_TYPE_SELF_HEAL : HBOOT_TYPE_REGULAR;

    /* The hive data must be whole blocks, within the hive file */
    if (BaseBlock->Length == 0 ||
        (BaseBlock->Length % HBLOCK_SIZE) != 0 ||
        BaseBlock->Length > MAXULONG - HBLOCK_SIZE)
    {
        DPRINT1("The hive describes a bad length 0x%x\n", BaseBlock->Length);
        Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
        return STATUS_REGISTRY_CORRUPT;
    }

    FileSize = HBLOCK_SIZE + BaseBlock->Length; // == sizeof(HBASE_BLOCK) + BaseBlock->Length;
    if (!HvpQueryFileSize(Hive, HFILE_TYPE_PRIMARY, &HiveFileSize) || HiveFileSize.QuadPart < FileSize)
    {
        DPRINT1("The hive file is shorter than the 0x%x bytes the hive describes, or its size is not known\n", FileSize);
        Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
        return STATUS_NOT_REGISTRY_FILE;
    }

    /* Setup hive data */
    Hive->BaseBlock = BaseBlock;
    Hive->Version = BaseBlock->Minor;

    /* Allocate a buffer large enough to hold the hive */
    HiveData = Hive->Allocate(FileSize, TRUE, TAG_CM);
    if (!HiveData)
    {
        Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
        DPRINT1("There's no enough memory to allocate hive data\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* HACK (see explanation below): Now read the whole hive */
    Success = Hive->FileRead(Hive,
                             HFILE_TYPE_PRIMARY,
                             &Offset,
                             HiveData,
                             FileSize);
    if (!Success)
    {
        DPRINT1("Failed to read the whole hive\n");
        Hive->Free(HiveData, FileSize);
        Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
        return STATUS_NOT_REGISTRY_FILE;
    }

    /* A hive kept by self-healing has its base block fixed in memory only */
    if (HiveSelfHeal)
    {
        RtlCopyMemory(HiveData, BaseBlock, HV_LOG_HEADER_SIZE);
        ((PHBASE_BLOCK)HiveData)->BootType = HBOOT_TYPE_SELF_HEAL;
    }

    /*
     * HACK (FIXME): Free our base block... it's useless in
     * this implementation.
     *
     * And it's useless because while the idea of reading the
     * hive from physical file is correct, the implementation
     * is hacky and incorrect. Instead of reading the whole hive,
     * we should be instead reading the hive block by block,
     * deconstruct the block buffer and enlist the bins and
     * prepare the storage for the hive. What we currently do
     * is we try to initialize the hive storage and bins enlistment
     * by calling HvpInitializeMemoryHive below. This mixes
     * HINIT_FILE and HINIT_MEMORY together which is disgusting
     * because HINIT_FILE implementation shouldn't be calling
     * HvpInitializeMemoryHive.
     */
    Hive->Free(BaseBlock, Hive->BaseBlockAlloc);
    Status = HvpInitializeMemoryHive(Hive, HiveData, FileName);

    /* The hive has been copied bin by bin: the file image is not needed anymore */
    Hive->Free(HiveData, FileSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to initialize hive from memory\n");
        return Status;
    }

    /*
     * The hive was kept as it is on disk: the next flush writes
     * all of it, through the log, with its base block made consistent.
     */
    if (HiveSelfHeal)
    {
        RtlSetAllBits(&Hive->DirtyVector);
        Hive->DirtyCount = Hive->DirtyVector.SizeOfBitMap;
        return STATUS_SUCCESS;
    }

    /*
     * If we have done some sort of recovery against
     * the hive we were going to load it from file,
     * tell the caller we did recover it. The caller
     * is responsible to flush the data later on.
     */
    return (Result == RecoverHeader) ? STATUS_REGISTRY_RECOVERED : STATUS_SUCCESS;
}

/**
 * @brief
 * Initializes a registry hive. It allocates a hive
 * descriptor and sets up the hive type depending
 * on the type chosen by the caller.
 *
 * @param[in,out] RegistryHive
 * A pointer to a hive descriptor to be initialized.
 *
 * @param[in] OperationType
 * The operation type to choose for hive initialization.
 * For further information about this, see Remarks.
 *
 * @param[in] HiveFlags
 * A hive flag. Such flag is used to determine what kind
 * of action must be taken into the hive or what aspects
 * must be taken into account for such hive. For further
 * information, see Remarks.
 *
 * @param[in] FileType
 * Hive file type. For the newly initialized hive, you can
 * choose from three different types for the hive:
 *
 * HFILE_TYPE_PRIMARY - Initializes a hive as primary hive
 * of the system.
 *
 * HFILE_TYPE_LOG - The newly created hive is a hive log.
 * Logs don't exist per se but they're accompanied with their
 * associated primary hives. The Log field member of the hive
 * descriptor is set to TRUE.
 *
 * HFILE_TYPE_EXTERNAL - The newly created hive is a portable
 * hive, that can be used and copied for different machines,
 * unlike primary hives.
 *
 * HFILE_TYPE_ALTERNATE - The newly created hive is an alternate hive.
 * Technically speaking it is the same as a primary hive (the representation
 * of on-disk image of the registry header is HFILE_TYPE_PRIMARY), with
 * the purpose is to serve as a backup hive. The Alternate field of the
 * hive descriptor is set to TRUE. Only the SYSTEM hive has a backup
 * alternate hive.
 *
 * @param[in] HiveData
 * An arbitrary pointer that points to the hive data. Usually this
 * data is in form of a hive base block given by the caller of this
 * function.
 *
 * @param[in] Allocate
 * A pointer to a ALLOCATE_ROUTINE function that describes
 * the main allocation routine for this hive. This parameter
 * can be NULL.
 *
 * @param[in] Free
 * A pointer to a FREE_ROUTINE function that describes the
 * the main memory freeing routine for this hive. This parameter
 * can be NULL.
 *
 * @param[in] FileSetSize
 * A pointer to a FILE_SET_SIZE_ROUTINE function that describes
 * the file set size routine for this hive. This parameter
 * can be NULL.
 *
 * @param[in] FileWrite
 * A pointer to a FILE_WRITE_ROUTINE function that describes
 * the file writing routine for this hive. This parameter
 * can be NULL.
 *
 * @param[in] FileRead
 * A pointer to a FILE_READ_ROUTINE function that describes
 * the file reading routine for this hive. This parameter
 * can be NULL.
 *
 * @param[in] FileFlush
 * A pointer to a FILE_FLUSH_ROUTINE function that describes
 * the file flushing routine for this hive. This parameter
 * can be NULL.
 *
 * @param[in] Cluster
 * The registry hive cluster to be set. Usually this value
 * is set to 1.
 *
 * @param[in] FileName
 * A to a NULL-terminated Unicode string structure containing
 * the hive file name. This parameter can be NULL.
 *
 * @return
 * Returns STATUS_SUCCESS if the function has successfully
 * initialized the hive. STATUS_REGISTRY_RECOVERED is returned
 * if the hive has subdued previous damage and it's been recovered.
 * This function will perform a hive writing and flushing with
 * healthy and recovered data in that case. STATUS_REGISTRY_IO_FAILED
 * is returned if registry hive writing/flushing of recovered data
 * has failed. STATUS_INVALID_PARAMETER is returned if an invalid
 * operation type pointed by OperationType parameter has been
 * submitted. A failure NTSTATUS code is returned otherwise.
 *
 * @remarks
 * OperationType parameter influences how should the hive be
 * initialized. These are the following supported operation
 * types:
 *
 * HINIT_CREATE -- Creates a new fresh hive.
 *
 * HINIT_MEMORY -- Initializes a registry hive that already exists
 *                 from memory. The hive data is copied from the
 *                 loaded hive in memory and used for read/write
 *                 access.
 *
 * HINIT_FLAT -- Initializes a flat registry hive, with data that can
 *               only be read and not written into. Cells are always
 *               allocated on a flat hive.
 *
 * HINIT_FILE -- Initializes a hive from a hive file from the physical
 *               backing storage of the system. In this situation the
 *               function will perform self-healing and resuscitation
 *               procedures if data read from the physical hive file
 *               is corrupt.
 *
 * HINIT_MEMORY_INPLACE -- This operation type is similar to HINIT_FLAT,
 *                         with the difference is that the hive is initialized
 *                         with hive data from memory. The hive can only be read
 *                         and not written into.
 *
 * HINIT_MAPFILE -- Initializes a hive from a hive file from the physical
 *                  backing storage of the system. Unlike HINIT_FILE, the
 *                  initialized hive is not backed to paged pool in memory
 *                  but rather through mapping views.
 *
 * Alongside the operation type, the hive flags also influence the aspect
 * of the newly initialized hive. These are the following supported hive
 * flags:
 *
 * HIVE_VOLATILE -- Tells the function that this hive will be volatile, that
 *                  is, the data stored inside the hive space resides only
 *                  in volatile memory of the system, aka the RAM, and the
 *                  data will be erased upon shutdown of the system.
 *
 * HIVE_NOLAZYFLUSH -- Tells the function that no lazy flushing must be
 *                     done to this hive.
 */
NTSTATUS
CMAPI
HvInitialize(
    _Inout_ PHHIVE RegistryHive,
    _In_  ULONG OperationType,
    _In_  ULONG HiveFlags,
    _In_  ULONG FileType,
    _In_opt_ PVOID HiveData,
    _In_opt_ PALLOCATE_ROUTINE Allocate,
    _In_opt_ PFREE_ROUTINE Free,
    _In_opt_ PFILE_SET_SIZE_ROUTINE FileSetSize,
    _In_opt_ PFILE_WRITE_ROUTINE FileWrite,
    _In_opt_ PFILE_READ_ROUTINE FileRead,
    _In_opt_ PFILE_FLUSH_ROUTINE FileFlush,
    _In_ ULONG Cluster,
    _In_opt_ PCUNICODE_STRING FileName)
{
    NTSTATUS Status;
    PHHIVE Hive = RegistryHive;

    /*
     * Create a new hive structure that will hold all the maintenance data.
     */

    RtlZeroMemory(Hive, sizeof(HHIVE));
    Hive->Signature = HV_HHIVE_SIGNATURE;

    Hive->Allocate = Allocate;
    Hive->Free = Free;
    Hive->FileSetSize = FileSetSize;
    Hive->FileWrite = FileWrite;
    Hive->FileRead = FileRead;
    Hive->FileFlush = FileFlush;

    Hive->RefreshCount = 0;
    Hive->StorageTypeCount = HTYPE_COUNT;
    Hive->Cluster = Cluster;
    Hive->BaseBlockAlloc = sizeof(HBASE_BLOCK); // == HBLOCK_SIZE

    Hive->Version = HSYS_MINOR;
#if (NTDDI_VERSION < NTDDI_VISTA)
    Hive->Log = (FileType == HFILE_TYPE_LOG);
    Hive->Alternate = (FileType == HFILE_TYPE_ALTERNATE);
#endif
    Hive->HiveFlags = HiveFlags & ~HIVE_NOLAZYFLUSH;

    // TODO: The CellRoutines point to different callbacks
    // depending on the OperationType.
    Hive->GetCellRoutine = HvpGetCellData;
    Hive->ReleaseCellRoutine = NULL;

    switch (OperationType)
    {
        case HINIT_CREATE:
        {
            /* Create a new fresh hive */
            Status = HvpCreateHive(Hive, FileName);
            break;
        }

        case HINIT_MEMORY:
        {
            /* Initialize a hive from memory */
            Status = HvpInitializeMemoryHive(Hive, HiveData, FileName);
            break;
        }

        case HINIT_FLAT:
        {
            /* Initialize a flat read-only hive */
            Status = HvpInitializeFlatHive(Hive, HiveData);
            break;
        }

        case HINIT_FILE:
        {
            /* Initialize a hive by loading it from physical file in backing storage */
            Status = HvLoadHive(Hive, FileName);
            if ((Status != STATUS_SUCCESS) &&
                (Status != STATUS_REGISTRY_RECOVERED))
            {
                /* Unrecoverable failure */
                DPRINT1("Registry hive couldn't be initialized, it's corrupt (hive 0x%p)\n", Hive);
                return Status;
            }

/* FIXME: See the comment above (near HvpQueryHiveSize) */
#if !defined(_M_AMD64) || !defined(_BLDR_)
            /*
             * Check if we have recovered this hive. We are responsible to
             * flush the primary hive back to backing storage afterwards.
             */
            if (Status == STATUS_REGISTRY_RECOVERED)
            {
                if (!HvSyncHiveFromRecover(Hive))
                {
                    DPRINT1("Fail to write healthy data back to hive\n");
                    return STATUS_REGISTRY_IO_FAILED;
                }

                /*
                 * We are saved from hell, now clear out the
                 * dirty bits and dirty count.
                 *
                 * FIXME: We must as well clear out the log
                 * and reset its size to 0 but we are lacking
                 * in code that deals with log growing/shrinking
                 * management. When the time comes to implement
                 * this stuff we must set the LogSize and file size
                 * to 0 here.
                 */
                RtlClearAllBits(&Hive->DirtyVector);
                Hive->DirtyCount = 0;

                /*
                 * Masquerade the status code as success.
                 * STATUS_REGISTRY_RECOVERED is not a failure
                 * code but not STATUS_SUCCESS either so the caller
                 * thinks we failed at our job.
                 */
                Status = STATUS_SUCCESS;
            }
#endif
            break;
        }

        case HINIT_MEMORY_INPLACE:
        {
            // Status = HvpInitializeMemoryInplaceHive(Hive, HiveData);
            // break;
            DPRINT1("HINIT_MEMORY_INPLACE is UNIMPLEMENTED\n");
            return STATUS_NOT_IMPLEMENTED;
        }

        case HINIT_MAPFILE:
        {
            DPRINT1("HINIT_MAPFILE is UNIMPLEMENTED\n");
            return STATUS_NOT_IMPLEMENTED;
        }

        default:
        {
            DPRINT1("Invalid operation type (OperationType = %u)\n", OperationType);
            return STATUS_INVALID_PARAMETER;
        }
    }

    return Status;
}

/**
 * @brief
 * Frees all the bins within the storage, the dirty vector
 * and the base block associated with the given registry
 * hive descriptor.
 *
 * @param[in] RegistryHive
 * A pointer to a hive descriptor where all of its data
 * is to be freed.
 */
VOID
CMAPI
HvFree(
    _In_ PHHIVE RegistryHive)
{
    if (!RegistryHive->ReadOnly)
    {
        /* Release hive bitmap */
        if (RegistryHive->DirtyVector.Buffer)
        {
            RegistryHive->Free(RegistryHive->DirtyVector.Buffer, 0);
        }

        HvpFreeHiveBins(RegistryHive);

        /* Free the BaseBlock */
        if (RegistryHive->BaseBlock)
        {
            RegistryHive->Free(RegistryHive->BaseBlock, RegistryHive->BaseBlockAlloc);
            RegistryHive->BaseBlock = NULL;
        }
    }
}

/* EOF */
