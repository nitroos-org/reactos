/*
 * PROJECT:   Registry manipulation library
 * LICENSE:   GPL - See COPYING in the top level directory
 * COPYRIGHT: Copyright 2005 Filip Navara <navaraf@reactos.org>
 *            Copyright 2005 Hartmut Birr
 *            Copyright 2001 - 2005 Eric Kohl
 */

#include "cmlib.h"

/* A compiler and processor barrier: GCC's MemoryBarrier alone does not stop the compiler */
#ifdef CMLIB_HOST
#define HvpPublishBarrier()
#else
#define HvpPublishBarrier() do { _ReadWriteBarrier(); MemoryBarrier(); _ReadWriteBarrier(); } while (0)
#endif

PHBIN CMAPI
HvpAddBin(
    PHHIVE RegistryHive,
    ULONG Size,
    HSTORAGE_TYPE Storage)
{
    PHMAP_ENTRY BlockList;
    PHBIN Bin;
    ULONG BinSize;
    ULONG i;
    ULONG BitmapSize;
    PULONG BitmapBuffer;
    ULONG BlockCount;
    ULONG OldBlockListSize;
    ULONG NewBlockListSize;
    ULONG Capacity;
    PHMAP_RETIRED_LIST Retired;
    PHCELL Block;

    BinSize = ROUND_UP(Size + sizeof(HBIN), HBLOCK_SIZE);
    BlockCount = BinSize / HBLOCK_SIZE;

    Bin = RegistryHive->Allocate(BinSize, TRUE, TAG_CM);
    if (Bin == NULL)
        return NULL;
    RtlZeroMemory(Bin, BinSize);

    Bin->Signature = HV_HBIN_SIGNATURE;
    Bin->FileOffset = RegistryHive->Storage[Storage].Length *
                      HBLOCK_SIZE;
    Bin->Size = BinSize;

    OldBlockListSize = RegistryHive->Storage[Storage].Length;
    NewBlockListSize = OldBlockListSize + BlockCount;
    Capacity = RegistryHive->Storage[Storage].BlockListCapacity;
    if (Capacity < OldBlockListSize)
        Capacity = OldBlockListSize;

    if (NewBlockListSize > Capacity)
    {
        /*
         * Readers resolve cells through the block list without the hive
         * lock. Grow the list geometrically and keep every list it replaces
         * until the hive is freed, so a reader holding the old pointer still
         * finds the same entries there.
         */
        Capacity *= 2;
        if (Capacity < NewBlockListSize)
            Capacity = NewBlockListSize;
        BlockList = RegistryHive->Allocate(sizeof(HMAP_ENTRY) * Capacity,
                                           TRUE,
                                           TAG_CM);
        if (BlockList == NULL)
        {
            RegistryHive->Free(Bin, 0);
            return NULL;
        }

        Retired = NULL;
        if (OldBlockListSize > 0)
        {
            Retired = RegistryHive->Allocate(sizeof(HMAP_RETIRED_LIST), TRUE, TAG_CM);
            if (Retired == NULL)
            {
                RegistryHive->Free(BlockList, 0);
                RegistryHive->Free(Bin, 0);
                return NULL;
            }

            RtlCopyMemory(BlockList, RegistryHive->Storage[Storage].BlockList,
                          OldBlockListSize * sizeof(HMAP_ENTRY));
        }
        RtlZeroMemory(BlockList + OldBlockListSize,
                      (Capacity - OldBlockListSize) * sizeof(HMAP_ENTRY));
    }
    else
    {
        BlockList = RegistryHive->Storage[Storage].BlockList;
        Retired = NULL;
    }

    /* The dirty vector of a stable hive grows with the bin: get its memory now, while the hive
       is still unchanged and the bin can be given up when there is none */
    BitmapSize = 0;
    BitmapBuffer = NULL;
    if (Storage == Stable)
    {
        /* Calculate bitmap size in bytes (always a multiple of 32 bits). */
        BitmapSize = ROUND_UP(NewBlockListSize, sizeof(ULONG) * 8) / 8;

        if (BitmapSize > RegistryHive->DirtyVector.SizeOfBitMap / 8)
        {
            BitmapBuffer = RegistryHive->Allocate(BitmapSize, TRUE, TAG_CM);
            if (BitmapBuffer == NULL)
            {
                if (BlockList != RegistryHive->Storage[Storage].BlockList)
                    RegistryHive->Free(BlockList, 0);
                if (Retired != NULL)
                    RegistryHive->Free(Retired, 0);
                RegistryHive->Free(Bin, 0);
                return NULL;
            }
        }
    }

    /* The new entries are past Length, so no reader can look them up yet */
    for (i = 0; i < BlockCount; i++)
    {
        BlockList[OldBlockListSize + i].BlockAddress =
            ((ULONG_PTR)Bin + (i * HBLOCK_SIZE));
        BlockList[OldBlockListSize + i].BinAddress = (ULONG_PTR)Bin;
    }

    if (BlockList != RegistryHive->Storage[Storage].BlockList)
    {
        if (Retired != NULL)
        {
            Retired->BlockList = RegistryHive->Storage[Storage].BlockList;
            Retired->Next = RegistryHive->Storage[Storage].RetiredBlockLists;
            RegistryHive->Storage[Storage].RetiredBlockLists = Retired;
        }
        else if (RegistryHive->Storage[Storage].BlockList != NULL)
        {
            /* An empty list that no cell can reference */
            RegistryHive->Free(RegistryHive->Storage[Storage].BlockList, 0);
        }

        /* Publish the filled list before the length that covers the new bin */
        HvpPublishBarrier();
        RegistryHive->Storage[Storage].BlockList = BlockList;
        RegistryHive->Storage[Storage].BlockListCapacity = Capacity;
    }

    HvpPublishBarrier();
    RegistryHive->Storage[Storage].Length = NewBlockListSize;

    /* Initialize a free block in this heap. */
    Block = (PHCELL)(Bin + 1);
    Block->Size = (LONG)(BinSize - sizeof(HBIN));

    if (Storage == Stable)
    {
        /* Grow bitmap if necessary (its memory was taken above). */
        if (BitmapBuffer != NULL)
        {
            RtlZeroMemory(BitmapBuffer, BitmapSize);
            if (RegistryHive->DirtyVector.SizeOfBitMap > 0)
            {
                ASSERT(RegistryHive->DirtyVector.Buffer);
                RtlCopyMemory(BitmapBuffer,
                              RegistryHive->DirtyVector.Buffer,
                              RegistryHive->DirtyVector.SizeOfBitMap / 8);
                RegistryHive->Free(RegistryHive->DirtyVector.Buffer, 0);
            }
            RtlInitializeBitMap(&RegistryHive->DirtyVector, BitmapBuffer,
                                BitmapSize * 8);
        }

        /* Mark new bin dirty. */
        RtlSetBits(&RegistryHive->DirtyVector,
                   Bin->FileOffset / HBLOCK_SIZE,
                   BlockCount);

        /* Update size in the base block */
        RegistryHive->BaseBlock->Length += BinSize;
    }

    return Bin;
}
