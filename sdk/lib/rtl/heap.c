/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/heap.c
 * PURPOSE:         RTL Heap backend allocator
 * PROGRAMMERS:     Copyright 2010 Aleksey Bragin
 *                  Copyright 2020 Katayama Hirofumi MZ
 */

/* Useful references:
   https://learn.microsoft.com/en-us/previous-versions/ms810466(v=msdn.10)
   https://learn.microsoft.com/en-us/previous-versions/ms810603(v=msdn.10)
   http://www.securitylab.ru/analytics/216376.php
   http://binglongx.spaces.live.com/blog/cns!142CBF6D49079DE8!596.entry
   http://www.phreedom.org/research/exploits/asn1-bitstring/
   http://illmatics.com/Understanding_the_LFH.pdf
   http://www.alex-ionescu.com/?p=18
*/

/* INCLUDES *****************************************************************/

#include <rtl.h>
#include <heap.h>

#define NDEBUG
#include <debug.h>

/* Heaps created with HEAP_CREATE_ENABLE_EXECUTE hold code (the CLR keeps its
 * executable stubs in one): their pages must be executable, as on Windows. */
#define RtlpHeapPageProtection(HeapFlags) \
    (((HeapFlags) & HEAP_CREATE_ENABLE_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE)

/* Bitmaps stuff */

/* How many least significant bits are clear */
UCHAR RtlpBitsClearLow[] =
{
    8,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0
};

FORCEINLINE
UCHAR
RtlpFindLeastSetBit(ULONG Bits)
{
    if (Bits & 0xFFFF)
    {
        if (Bits & 0xFF)
            return RtlpBitsClearLow[Bits & 0xFF]; /* Lowest byte */
        else
            return RtlpBitsClearLow[(Bits >> 8) & 0xFF] + 8; /* 2nd byte */
    }
    else
    {
        if ((Bits >> 16) & 0xFF)
            return RtlpBitsClearLow[(Bits >> 16) & 0xFF] + 16; /* 3rd byte */
        else
            return RtlpBitsClearLow[(Bits >> 24) & 0xFF] + 24; /* Highest byte */
    }
}

/* Maximum size of a tail-filling pattern used for compare operation */
UCHAR FillPattern[HEAP_ENTRY_SIZE] =
{
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
#ifdef _WIN64
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL
#endif
};
/* Every byte of the pattern must be initialized */
C_ASSERT(HEAP_ENTRY_SIZE == 2 * sizeof(PVOID));

static
BOOLEAN
RtlpIsLastCommittedEntry(PHEAP_ENTRY Entry)
{
    if (Entry->Flags & HEAP_ENTRY_LAST_ENTRY)
        return TRUE;

    Entry = Entry + Entry->Size;

    /* 1-sized busy last entry are the committed range guard entries */
    if ((Entry->Flags != (HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY)) || (Entry->Size != 1))
        return FALSE;

    /* This must be the last or the penultimate entry in the page  */
    ASSERT(((PVOID)PAGE_ROUND_UP(Entry) == (Entry + 1)) ||
           ((PVOID)PAGE_ROUND_UP(Entry)== (Entry + 2)));
    return TRUE;
}

/* FUNCTIONS *****************************************************************/

NTSTATUS NTAPI
RtlpInitializeHeap(OUT PHEAP Heap,
                   IN ULONG Flags,
                   IN PHEAP_LOCK Lock OPTIONAL,
                   IN PRTL_HEAP_PARAMETERS Parameters)
{
    ULONG NumUCRs = 8;
    ULONG Index;
    SIZE_T HeaderSize;
    NTSTATUS Status;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    SIZE_T DeCommitFreeBlockThreshold;

    /* Preconditions */
    ASSERT(Heap != NULL);
    ASSERT(Parameters != NULL);
    ASSERT(!(Flags & HEAP_LOCK_USER_ALLOCATED));
    ASSERT(!(Flags & HEAP_NO_SERIALIZE) || (Lock == NULL));  /* HEAP_NO_SERIALIZE => no lock */

    /* Make sure we're not doing stupid things */
    DeCommitFreeBlockThreshold = Parameters->DeCommitFreeBlockThreshold >> HEAP_ENTRY_SHIFT;
    /* Start out with the size of a plain Heap header + our hints of free entries + the bitmap */
    HeaderSize = FIELD_OFFSET(HEAP, FreeHints[DeCommitFreeBlockThreshold])
                 + (ROUND_UP(DeCommitFreeBlockThreshold, RTL_BITS_OF(ULONG)) / RTL_BITS_OF(ULONG)) * sizeof(ULONG);

    /* Check if space needs to be added for the Heap Lock */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        if (Lock != NULL)
            /* The user manages the Heap Lock */
            Flags |= HEAP_LOCK_USER_ALLOCATED;
        else
        if (RtlpGetMode() == UserMode)
        {
            /* In user mode, the Heap Lock trails the Heap header */
            Lock = (PHEAP_LOCK) ((ULONG_PTR) (Heap) + HeaderSize);
            HeaderSize += sizeof(HEAP_LOCK);
        }
    }

    /* Add space for the initial Heap UnCommitted Range Descriptor list */
    UcrDescriptor = (PHEAP_UCR_DESCRIPTOR) ((ULONG_PTR) (Heap) + HeaderSize);
    HeaderSize += NumUCRs * sizeof(HEAP_UCR_DESCRIPTOR);

    HeaderSize = ROUND_UP(HeaderSize, HEAP_ENTRY_SIZE);
    /* Sanity check */
    ASSERT(HeaderSize <= PAGE_SIZE);

    /* Initialise the Heap Entry header containing the Heap header */
    Heap->Entry.Size = (USHORT)(HeaderSize >> HEAP_ENTRY_SHIFT);
    Heap->Entry.Flags = HEAP_ENTRY_BUSY;
    Heap->Entry.SmallTagIndex = LOBYTE(Heap->Entry.Size) ^ HIBYTE(Heap->Entry.Size) ^ Heap->Entry.Flags;
    Heap->Entry.PreviousSize = 0;
    Heap->Entry.SegmentOffset = 0;
    Heap->Entry.UnusedBytes = 0;

    /* Initialise the Heap header */
    Heap->Signature = HEAP_SIGNATURE;
    Heap->Flags = Flags;
    Heap->ForceFlags = (Flags & (HEAP_NO_SERIALIZE |
                                 HEAP_GENERATE_EXCEPTIONS |
                                 HEAP_ZERO_MEMORY |
                                 HEAP_REALLOC_IN_PLACE_ONLY |
                                 HEAP_VALIDATE_PARAMETERS_ENABLED |
                                 HEAP_VALIDATE_ALL_ENABLED |
                                 HEAP_TAIL_CHECKING_ENABLED |
                                 HEAP_CREATE_ALIGN_16 |
                                 HEAP_FREE_CHECKING_ENABLED));

    /* Initialise the Heap parameters */
    Heap->VirtualMemoryThreshold = ROUND_UP(Parameters->VirtualMemoryThreshold, sizeof(HEAP_ENTRY)) >> HEAP_ENTRY_SHIFT;
    Heap->SegmentReserve = Parameters->SegmentReserve;
    Heap->SegmentCommit = Parameters->SegmentCommit;
    Heap->DeCommitFreeBlockThreshold = DeCommitFreeBlockThreshold;
    Heap->DeCommitTotalFreeThreshold = Parameters->DeCommitTotalFreeThreshold >> HEAP_ENTRY_SHIFT;
    Heap->MaximumAllocationSize = Parameters->MaximumAllocationSize;
    Heap->CommitRoutine = Parameters->CommitRoutine;

    /* No front end yet (the memory of a heap given by its creator is not necessarily zero) */
    Heap->FrontEndHeap = NULL;
    Heap->FrontEndHeapType = 0;
    Heap->FrontHeapLockCount = 0;
    Heap->Counters.LockCollisions = 0;
    Heap->FeAct = NULL;

    /* Initialise the Heap validation info */
    Heap->HeaderValidateCopy = NULL;
    Heap->HeaderValidateLength = (USHORT)HeaderSize;

    /* Initialise the Heap Lock */
    if (!(Flags & HEAP_NO_SERIALIZE) && !(Flags & HEAP_LOCK_USER_ALLOCATED))
    {
        Status = RtlInitializeHeapLock(&Lock);
        if (!NT_SUCCESS(Status))
            return Status;
    }
    Heap->LockVariable = Lock;

    /* Initialise the Heap alignment info */
    if (Flags & HEAP_CREATE_ALIGN_16)
    {
        Heap->AlignMask = ~(ULONG_PTR)15;
        Heap->AlignRound = 15 + sizeof(HEAP_ENTRY);
    }
    else
    {
        Heap->AlignMask = ~(ULONG_PTR)(sizeof(HEAP_ENTRY) - 1);
        Heap->AlignRound = 2 * sizeof(HEAP_ENTRY) - 1;
    }

    if (Flags & HEAP_TAIL_CHECKING_ENABLED)
        Heap->AlignRound += sizeof(HEAP_ENTRY);

    /* Initialise the Heap Segment list */
    for (Index = 0; Index < HEAP_SEGMENTS; ++Index)
        Heap->Segments[Index] = NULL;

    /* Initialise the free entry lists. */
    InitializeListHead(&Heap->FreeLists);
    RtlInitializeBitMap(&Heap->FreeHintBitmap,
                        (PULONG)&Heap->FreeHints[DeCommitFreeBlockThreshold],
                        DeCommitFreeBlockThreshold);
    RtlClearAllBits(&Heap->FreeHintBitmap);
    RtlZeroMemory(&Heap->FreeHints[0], sizeof(Heap->FreeHints[0]) * DeCommitFreeBlockThreshold);

    /* Initialise the Heap Virtual Allocated Blocks list */
    InitializeListHead(&Heap->VirtualAllocdBlocks);

    /* Initialise the Heap UnCommitted Region lists */
    InitializeListHead(&Heap->UCRSegments);
    InitializeListHead(&Heap->UCRList);

    /* Register the initial Heap UnCommitted Region Descriptors */
    for (Index = 0; Index < NumUCRs; ++Index)
        InsertTailList(&Heap->UCRList, &UcrDescriptor[Index].ListEntry);

    return STATUS_SUCCESS;
}

VOID NTAPI
RtlpInsertFreeBlockHelper(PHEAP Heap,
                          PHEAP_FREE_ENTRY FreeEntry,
                          SIZE_T BlockSize,
                          BOOLEAN NoFill)
{
    ULONG HintIndex, NextHintIndex;

    ASSERT(FreeEntry->Size == BlockSize);

    /* Fill if it's not denied */
    if (!NoFill)
    {
        FreeEntry->Flags &= ~(HEAP_ENTRY_FILL_PATTERN |
                              HEAP_ENTRY_EXTRA_PRESENT |
                              HEAP_ENTRY_BUSY);

        if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED)
        {
            RtlFillMemoryUlong((PCHAR)(FreeEntry + 1),
                               (BlockSize << HEAP_ENTRY_SHIFT) - sizeof(*FreeEntry),
                               ARENA_FREE_FILLER);

            FreeEntry->Flags |= HEAP_ENTRY_FILL_PATTERN;
        }
    }
    else
    {
        /* Clear out all flags except the last entry one */
        FreeEntry->Flags &= HEAP_ENTRY_LAST_ENTRY;
    }

    /* See if this should go to the dedicated list */
    if (BlockSize > Heap->DeCommitFreeBlockThreshold)
    {
        PLIST_ENTRY ListEntry = Heap->FreeHints[0];

        /* Check if we have a hint there */
        if (ListEntry == NULL)
        {
            ASSERT(!RtlTestBit(&Heap->FreeHintBitmap, 0));
            Heap->FreeHints[0] = &FreeEntry->FreeList;
            RtlSetBit(&Heap->FreeHintBitmap, 0);
            InsertTailList(&Heap->FreeLists, &FreeEntry->FreeList);
            return;
        }

        ASSERT(RtlTestBit(&Heap->FreeHintBitmap, 0));

        while (ListEntry != &Heap->FreeLists)
        {
            PHEAP_FREE_ENTRY PreviousEntry = CONTAINING_RECORD(ListEntry,
                                                               HEAP_FREE_ENTRY,
                                                               FreeList);
            if (PreviousEntry->Size >= BlockSize)
            {
                DPRINT("Inserting size %lu before %lu.\n", BlockSize, PreviousEntry->Size);
                break;
            }

            ListEntry = ListEntry->Flink;
        }

        InsertTailList(ListEntry, &FreeEntry->FreeList);

        /* Update our hint if needed */
        if (Heap->FreeHints[0] == ListEntry)
            Heap->FreeHints[0] = &FreeEntry->FreeList;

        return;
    }

    ASSERT(BlockSize >= 2);
    HintIndex = BlockSize - 1;

    if (Heap->FreeHints[HintIndex] != NULL)
    {
        ASSERT(RtlTestBit(&Heap->FreeHintBitmap, HintIndex));

        /* Insert it after our hint. */
        InsertHeadList(Heap->FreeHints[HintIndex], &FreeEntry->FreeList);

        return;
    }

    /* This is the first time we insert such an entry in the list. */
    ASSERT(!RtlTestBit(&Heap->FreeHintBitmap, HintIndex));
    if (IsListEmpty(&Heap->FreeLists))
    {
        /* First entry inserted in this list ever */
        InsertHeadList(&Heap->FreeLists, &FreeEntry->FreeList);
        RtlSetBit(&Heap->FreeHintBitmap, HintIndex);
        Heap->FreeHints[HintIndex] = &FreeEntry->FreeList;
        return;
    }

    /* Find the closest one */
    NextHintIndex = RtlFindSetBits(&Heap->FreeHintBitmap, 1, HintIndex);
    ASSERT(NextHintIndex != 0xFFFFFFFF);
    if ((NextHintIndex == 0) || (NextHintIndex > HintIndex))
    {
        /*
         * We found a larger entry. Insert this one before.
         * It is guaranteed to be our successor in the list.
         */
        InsertTailList(Heap->FreeHints[NextHintIndex], &FreeEntry->FreeList);
    }
    else
    {
        /* We only found an entry smaller than us. Then we will be the largest one. */
        ASSERT(CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY, FreeList)->Size < BlockSize);
        InsertTailList(&Heap->FreeLists, &FreeEntry->FreeList);
    }

    /* Setup our hint */
    RtlSetBit(&Heap->FreeHintBitmap, HintIndex);
    Heap->FreeHints[HintIndex] = &FreeEntry->FreeList;
}

PHEAP_FREE_ENTRY
NTAPI
RtlpInsertFreeBlock(PHEAP Heap,
                    PHEAP_FREE_ENTRY FreeEntry,
                    SIZE_T BlockSize)
{
    USHORT Size, PreviousSize;
    UCHAR SegmentOffset, Flags;
    PHEAP_SEGMENT Segment;
    PHEAP_FREE_ENTRY LastEntry;

    DPRINT("RtlpInsertFreeBlock(%p %p %x)\n", Heap, FreeEntry, BlockSize);

    /* Increase the free size counter */
    Heap->TotalFreeSize += BlockSize;

    /* Remember certain values */
    LastEntry = FreeEntry;
    Flags = FreeEntry->Flags;
    PreviousSize = FreeEntry->PreviousSize;
    SegmentOffset = FreeEntry->SegmentOffset;
    Segment = Heap->Segments[SegmentOffset];

    /* Process it */
    while (BlockSize)
    {
        /* Check for the max size */
        if (BlockSize > HEAP_MAX_BLOCK_SIZE)
        {
            Size = HEAP_MAX_BLOCK_SIZE;

            /* Special compensation if it goes above limit just by 1 */
            if (BlockSize == (HEAP_MAX_BLOCK_SIZE + 1))
                Size -= 16;

            FreeEntry->Flags = 0;
        }
        else
        {
            Size = (USHORT)BlockSize;
            FreeEntry->Flags = Flags;
        }

        /* Change its size and insert it into a free list */
        FreeEntry->Size = Size;
        FreeEntry->PreviousSize = PreviousSize;
        FreeEntry->SegmentOffset = SegmentOffset;

        /* Call a helper to actually insert the block */
        RtlpInsertFreeBlockHelper(Heap, FreeEntry, Size, FALSE);

        /* Update sizes */
        PreviousSize = Size;
        BlockSize -= Size;

        /* Go to the next entry */
        LastEntry = FreeEntry;
        FreeEntry = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)FreeEntry + Size);

        /* Check if that's all */
        if ((PHEAP_ENTRY)FreeEntry >= Segment->LastValidEntry)
        {
            return LastEntry;
        }
    }

    /* Update previous size if needed */
    if (!(Flags & HEAP_ENTRY_LAST_ENTRY))
        FreeEntry->PreviousSize = PreviousSize;

    return LastEntry;
}

static
VOID
RtlpRemoveFreeBlock(PHEAP Heap,
                    PHEAP_FREE_ENTRY FreeEntry,
                    BOOLEAN NoFill)
{
    SIZE_T Result, RealSize;
    ULONG HintIndex;

    /* This was a problem before we handled segments > MAXUSHORT.
     * It may not be needed now, but is left just for safety. */
    ASSERT(FreeEntry->Size != 0);

    /* Remove the free block */
    if (FreeEntry->Size > Heap->DeCommitFreeBlockThreshold)
        HintIndex = 0;
    else
        HintIndex = FreeEntry->Size - 1;

    ASSERT(RtlTestBit(&Heap->FreeHintBitmap, HintIndex));

    /* Are we removing the hint entry for this size ? */
    if (Heap->FreeHints[HintIndex] == &FreeEntry->FreeList)
    {
        PHEAP_FREE_ENTRY NewHintEntry = NULL;
        if (FreeEntry->FreeList.Flink != &Heap->FreeLists)
        {
            NewHintEntry = CONTAINING_RECORD(FreeEntry->FreeList.Flink,
                                             HEAP_FREE_ENTRY,
                                             FreeList);
            /*
             * In non-dedicated list, we just put the next entry as hint.
             * For the dedicated ones, we take care of putting entries of the right size hint.
             */
            if ((HintIndex != 0) && (NewHintEntry->Size != FreeEntry->Size))
            {
                /* Of course this must be a larger one after us */
                ASSERT(NewHintEntry->Size > FreeEntry->Size);
                NewHintEntry = NULL;
            }
        }

        /* Replace the hint, if we can */
        if (NewHintEntry != NULL)
        {
            Heap->FreeHints[HintIndex] = &NewHintEntry->FreeList;
        }
        else
        {
            Heap->FreeHints[HintIndex] = NULL;
            RtlClearBit(&Heap->FreeHintBitmap, HintIndex);
        }
    }

    RemoveEntryList(&FreeEntry->FreeList);

    /* Fill with pattern if necessary */
    if (!NoFill &&
        (FreeEntry->Flags & HEAP_ENTRY_FILL_PATTERN))
    {
        RealSize = (FreeEntry->Size << HEAP_ENTRY_SHIFT) - sizeof(*FreeEntry);

        /* Deduct extra stuff from block's real size */
        if (FreeEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT &&
            RealSize > sizeof(HEAP_FREE_ENTRY_EXTRA))
        {
            RealSize -= sizeof(HEAP_FREE_ENTRY_EXTRA);
        }

        /* Check if the free filler is intact */
        Result = RtlCompareMemoryUlong((PCHAR)(FreeEntry + 1),
                                        RealSize,
                                        ARENA_FREE_FILLER);

        if (Result != RealSize)
        {
            DPRINT1("Free heap block %p modified at %p after it was freed\n",
                FreeEntry,
                (PCHAR)(FreeEntry + 1) + Result);
        }
    }
}

SIZE_T NTAPI
RtlpGetSizeOfBigBlock(PHEAP_ENTRY HeapEntry)
{
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;

    /* Get pointer to the containing record */
    VirtualEntry = CONTAINING_RECORD(HeapEntry, HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);
    ASSERT(VirtualEntry->BusyBlock.Size >= sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));

    /* Restore the real size */
    return VirtualEntry->CommitSize - HeapEntry->Size;
}

PHEAP_UCR_DESCRIPTOR NTAPI
RtlpCreateUnCommittedRange(PHEAP_SEGMENT Segment)
{
    PLIST_ENTRY Entry;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    PHEAP_UCR_SEGMENT UcrSegment;
    PHEAP Heap = Segment->Heap;
    SIZE_T ReserveSize = 16 * PAGE_SIZE;
    SIZE_T CommitSize = 1 * PAGE_SIZE;
    NTSTATUS Status;

    DPRINT("RtlpCreateUnCommittedRange(%p)\n", Segment);

    /* Check if we have unused UCRs */
    if (IsListEmpty(&Heap->UCRList))
    {
        /* Get a pointer to the first UCR segment */
        UcrSegment = CONTAINING_RECORD(Heap->UCRSegments.Flink, HEAP_UCR_SEGMENT, ListEntry);

        /* Check the list of UCR segments */
        if (IsListEmpty(&Heap->UCRSegments) ||
            UcrSegment->ReservedSize == UcrSegment->CommittedSize)
        {
            /* We need to create a new one. Reserve 16 pages for it */
            UcrSegment = NULL;
            Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                             (PVOID *)&UcrSegment,
                                             0,
                                             &ReserveSize,
                                             MEM_RESERVE,
                                             PAGE_READWRITE);

            if (!NT_SUCCESS(Status)) return NULL;

            /* Commit one page */
            Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                             (PVOID *)&UcrSegment,
                                             0,
                                             &CommitSize,
                                             MEM_COMMIT,
                                             PAGE_READWRITE);

            if (!NT_SUCCESS(Status))
            {
                /* Release reserved memory */
                ZwFreeVirtualMemory(NtCurrentProcess(),
                                    (PVOID *)&UcrSegment,
                                    &ReserveSize,
                                    MEM_RELEASE);
                return NULL;
            }

            /* Set it's data */
            UcrSegment->ReservedSize = ReserveSize;
            UcrSegment->CommittedSize = CommitSize;

            /* Add it to the head of the list */
            InsertHeadList(&Heap->UCRSegments, &UcrSegment->ListEntry);

            /* Get a pointer to the first available UCR descriptor */
            UcrDescriptor = (PHEAP_UCR_DESCRIPTOR)(UcrSegment + 1);
        }
        else
        {
            /* It's possible to use existing UCR segment. Commit one more page */
            UcrDescriptor = (PHEAP_UCR_DESCRIPTOR)((PCHAR)UcrSegment + UcrSegment->CommittedSize);
            Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                             (PVOID *)&UcrDescriptor,
                                             0,
                                             &CommitSize,
                                             MEM_COMMIT,
                                             PAGE_READWRITE);

            if (!NT_SUCCESS(Status)) return NULL;

            ASSERT((PCHAR)UcrDescriptor == ((PCHAR)UcrSegment + UcrSegment->CommittedSize));

            /* Update sizes */
            UcrSegment->CommittedSize += CommitSize;
        }

        /* There is a whole bunch of new UCR descriptors. Put them into the unused list */
        while ((PCHAR)(UcrDescriptor + 1) <= (PCHAR)UcrSegment + UcrSegment->CommittedSize)
        {
            InsertTailList(&Heap->UCRList, &UcrDescriptor->ListEntry);
            UcrDescriptor++;
        }
    }

    /* There are unused UCRs, just get the first one */
    Entry = RemoveHeadList(&Heap->UCRList);
    UcrDescriptor = CONTAINING_RECORD(Entry, HEAP_UCR_DESCRIPTOR, ListEntry);
    return UcrDescriptor;
}

VOID NTAPI
RtlpDestroyUnCommittedRange(PHEAP_SEGMENT Segment,
                            PHEAP_UCR_DESCRIPTOR UcrDescriptor)
{
    /* Zero it out */
    UcrDescriptor->Address = NULL;
    UcrDescriptor->Size = 0;

    /* Put it into the heap's list of unused UCRs */
    InsertHeadList(&Segment->Heap->UCRList, &UcrDescriptor->ListEntry);
}

VOID NTAPI
RtlpInsertUnCommittedPages(PHEAP_SEGMENT Segment,
                           ULONG_PTR Address,
                           SIZE_T Size)
{
    PLIST_ENTRY Current;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;

    DPRINT("RtlpInsertUnCommittedPages(%p %08Ix %Ix)\n", Segment, Address, Size);

    /* Go through the list of UCR descriptors, they are sorted from lowest address
       to the highest */
    Current = Segment->UCRSegmentList.Flink;
    while (Current != &Segment->UCRSegmentList)
    {
        UcrDescriptor = CONTAINING_RECORD(Current, HEAP_UCR_DESCRIPTOR, SegmentEntry);

        if ((ULONG_PTR)UcrDescriptor->Address > Address)
        {
            /* Check for a really lucky case */
            if ((Address + Size) == (ULONG_PTR)UcrDescriptor->Address)
            {
                /* Exact match */
                UcrDescriptor->Address = (PVOID)Address;
                UcrDescriptor->Size += Size;
                return;
            }

            /* We found the block before which the new one should go */
            break;
        }
        else if (((ULONG_PTR)UcrDescriptor->Address + UcrDescriptor->Size) == Address)
        {
            /* Modify this entry */
            Address = (ULONG_PTR)UcrDescriptor->Address;
            Size += UcrDescriptor->Size;

            /* Advance to the next descriptor */
            Current = Current->Flink;

            /* Remove the current descriptor from the list and destroy it */
            RemoveEntryList(&UcrDescriptor->SegmentEntry);
            RtlpDestroyUnCommittedRange(Segment, UcrDescriptor);

            Segment->NumberOfUnCommittedRanges--;
        }
        else
        {
            /* Advance to the next descriptor */
            Current = Current->Flink;
        }
    }

    /* Create a new UCR descriptor */
    UcrDescriptor = RtlpCreateUnCommittedRange(Segment);
    if (!UcrDescriptor) return;

    UcrDescriptor->Address = (PVOID)Address;
    UcrDescriptor->Size = Size;

    /* "Current" is the descriptor before which our one should go */
    InsertTailList(Current, &UcrDescriptor->SegmentEntry);

    DPRINT("Added segment UCR with base %08Ix, size 0x%x\n", Address, Size);

    /* Increase counters */
    Segment->NumberOfUnCommittedRanges++;
}

static
PHEAP_FREE_ENTRY
RtlpFindAndCommitPages(PHEAP Heap,
                       PHEAP_SEGMENT Segment,
                       PSIZE_T Size,
                       PVOID AddressRequested)
{
    PLIST_ENTRY Current;
    NTSTATUS Status;

    DPRINT("RtlpFindAndCommitPages(%p %p %Ix %p)\n", Heap, Segment, *Size, AddressRequested);

    /* Go through UCRs in a segment */
    Current = Segment->UCRSegmentList.Flink;
    while (Current != &Segment->UCRSegmentList)
    {
        PHEAP_UCR_DESCRIPTOR UcrDescriptor = CONTAINING_RECORD(Current, HEAP_UCR_DESCRIPTOR, SegmentEntry);

        /* Check if we can use that one right away */
        if (UcrDescriptor->Size >= *Size &&
            (UcrDescriptor->Address == AddressRequested || !AddressRequested))
        {
            PHEAP_ENTRY GuardEntry, FreeEntry;
            PVOID Address = UcrDescriptor->Address;

            /* Commit it */
            if (Heap->CommitRoutine)
            {
                Status = Heap->CommitRoutine(Heap, &Address, Size);
            }
            else
            {
                Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                                 &Address,
                                                 0,
                                                 Size,
                                                 MEM_COMMIT,
                                                 RtlpHeapPageProtection(Heap->Flags));
            }

            DPRINT("Committed %Iu bytes at base %08Ix, UCR size is %lu\n", *Size, Address, UcrDescriptor->Size);

            /* Fail in unsuccessful case */
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("Committing page failed with status 0x%08X\n", Status);
                return NULL;
            }

            /* Update tracking numbers */
            Segment->NumberOfUnCommittedPages -= (ULONG)(*Size / PAGE_SIZE);

            /* Update UCR descriptor */
            UcrDescriptor->Address = (PVOID)((ULONG_PTR)UcrDescriptor->Address + *Size);
            UcrDescriptor->Size -= *Size;

            /* Grab the previous guard entry */
            GuardEntry = (PHEAP_ENTRY)Address - 1;
            ASSERT(GuardEntry->Flags & HEAP_ENTRY_LAST_ENTRY);
            ASSERT(GuardEntry->Flags & HEAP_ENTRY_BUSY);
            ASSERT(GuardEntry->Size == 1);

            /* Did we have a double guard entry ? */
            if (GuardEntry->PreviousSize == 1)
            {
                /* Use the one before instead */
                GuardEntry--;

                ASSERT(GuardEntry->Flags & HEAP_ENTRY_LAST_ENTRY);
                ASSERT(GuardEntry->Flags & HEAP_ENTRY_BUSY);
                ASSERT(GuardEntry->Size == 1);

                /* We gain one slot more */
                *Size += HEAP_ENTRY_SIZE;
            }

            /* This will become our returned free entry.
             * Now we can make it span the whole committed range.
             * But we keep one slot for a guard entry, if needed.
             */
            FreeEntry = GuardEntry;

            FreeEntry->Flags &= ~(HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY);
            FreeEntry->Size = (*Size) >> HEAP_ENTRY_SHIFT;

            DPRINT("Updating UcrDescriptor %p, new Address %p, size %lu\n",
                UcrDescriptor, UcrDescriptor->Address, UcrDescriptor->Size);

            /* Check if anything left in this UCR */
            if (UcrDescriptor->Size == 0)
            {
                /* It's fully exhausted. Take the guard entry for us */
                FreeEntry->Size++;
                *Size += HEAP_ENTRY_SIZE;

                ASSERT((FreeEntry + FreeEntry->Size) == UcrDescriptor->Address);

                /* Check if this is the end of the segment */
                if(UcrDescriptor->Address == Segment->LastValidEntry)
                {
                    FreeEntry->Flags = HEAP_ENTRY_LAST_ENTRY;
                }
                else
                {
                    PHEAP_ENTRY NextEntry = UcrDescriptor->Address;

                    /* We should not have a UCR right behind us */
                    ASSERT((UcrDescriptor->SegmentEntry.Flink == &Segment->UCRSegmentList)
                        || (CONTAINING_RECORD(UcrDescriptor->SegmentEntry.Flink, HEAP_UCR_DESCRIPTOR, SegmentEntry)->Address > UcrDescriptor->Address));

                    ASSERT(NextEntry->PreviousSize == 0);
                    ASSERT(NextEntry == FreeEntry + FreeEntry->Size);
                    NextEntry->PreviousSize = FreeEntry->Size;
                }

                /* This UCR needs to be removed because it became useless */
                RemoveEntryList(&UcrDescriptor->SegmentEntry);

                RtlpDestroyUnCommittedRange(Segment, UcrDescriptor);
                Segment->NumberOfUnCommittedRanges--;
            }
            else
            {
                /* Setup a guard entry */
                GuardEntry = (PHEAP_ENTRY)UcrDescriptor->Address - 1;
                ASSERT(GuardEntry == FreeEntry + FreeEntry->Size);
                GuardEntry->Flags = HEAP_ENTRY_LAST_ENTRY | HEAP_ENTRY_BUSY;
                GuardEntry->Size = 1;
                GuardEntry->PreviousSize = FreeEntry->Size;
                GuardEntry->SegmentOffset = FreeEntry->SegmentOffset;
                DPRINT("Setting %p as UCR guard entry.\n", GuardEntry);
            }

            /* We're done */
            return (PHEAP_FREE_ENTRY)FreeEntry;
        }

        /* Advance to the next descriptor */
        Current = Current->Flink;
    }

    return NULL;
}

static
VOID
RtlpDeCommitFreeBlock(PHEAP Heap,
                      PHEAP_FREE_ENTRY FreeEntry,
                      SIZE_T Size)
{
    PHEAP_SEGMENT Segment;
    PHEAP_ENTRY NextEntry, GuardEntry;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    SIZE_T PrecedingSize, DecommitSize;
    ULONG_PTR DecommitBase, DecommitEnd;
    NTSTATUS Status;

    DPRINT("Decommitting %p %p %x\n", Heap, FreeEntry, Size);

    /* We can't decommit if there is a commit routine! */
    if (Heap->CommitRoutine)
    {
        /* Just add it back the usual way */
        RtlpInsertFreeBlock(Heap, FreeEntry, Size);
        return;
    }

    /* Get the segment */
    Segment = Heap->Segments[FreeEntry->SegmentOffset];

    /* Get the preceding entry */
    DecommitBase = ROUND_UP(FreeEntry, PAGE_SIZE);
    PrecedingSize = (PHEAP_ENTRY)DecommitBase - (PHEAP_ENTRY)FreeEntry;

    if (PrecedingSize == 0)
    {
        /* We need some space in order to insert our guard entry */
        DecommitBase += PAGE_SIZE;
        PrecedingSize += PAGE_SIZE >> HEAP_ENTRY_SHIFT;
    }

    /* Get the entry after this one. */

    /* Do we really have a next entry */
    if (RtlpIsLastCommittedEntry((PHEAP_ENTRY)FreeEntry))
    {
        /* No, Decommit till the next UCR. */
        DecommitEnd = PAGE_ROUND_UP((PHEAP_ENTRY)FreeEntry + FreeEntry->Size);
        NextEntry = NULL;
    }
    else
    {
        NextEntry = (PHEAP_ENTRY)FreeEntry + Size;
        DecommitEnd = PAGE_ROUND_DOWN(NextEntry);

        /* Can we make a free entry out of what's left ? */
        if ((NextEntry - (PHEAP_ENTRY)DecommitEnd) == 1)
        {
            /* Nope. Let's keep one page before this */
            DecommitEnd -= PAGE_SIZE;
        }
    }

    if (DecommitEnd <= DecommitBase)
    {
        /* There's nothing left to decommit. */
        RtlpInsertFreeBlock(Heap, FreeEntry, Size);
        return;
    }

    DecommitSize = DecommitEnd - DecommitBase;

    /* A decommit is necessary. Create a UCR descriptor */
    UcrDescriptor = RtlpCreateUnCommittedRange(Segment);
    if (!UcrDescriptor)
    {
        DPRINT1("HEAP: Failed to create UCR descriptor\n");
        RtlpInsertFreeBlock(Heap, FreeEntry, Size);
        return;
    }

    /* Decommit the memory */
    Status = ZwFreeVirtualMemory(NtCurrentProcess(),
                                 (PVOID *)&DecommitBase,
                                 &DecommitSize,
                                 MEM_DECOMMIT);
    ASSERT((DecommitBase + DecommitSize) == DecommitEnd);

    /* Delete that UCR. This is needed to assure there is an unused UCR entry in the list */
    RtlpDestroyUnCommittedRange(Segment, UcrDescriptor);

    if (!NT_SUCCESS(Status))
    {
        RtlpInsertFreeBlock(Heap, FreeEntry, Size);
        return;
    }

    /* Insert uncommitted pages */
    RtlpInsertUnCommittedPages(Segment, DecommitBase, DecommitSize);
    Segment->NumberOfUnCommittedPages += (ULONG)(DecommitSize / PAGE_SIZE);

    /* Insert our guard entry before this */
    GuardEntry = (PHEAP_ENTRY)DecommitBase - 1;
    GuardEntry->Size = 1;
    GuardEntry->Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
    GuardEntry->SegmentOffset = FreeEntry->SegmentOffset;
    DPRINT("Setting %p as UCR guard entry.\n", GuardEntry);

    /* Now see what's really behind us */
    PrecedingSize--;
    switch (PrecedingSize)
    {
        case 1:
            /* No space left for a free entry. Make this another guard entry */
            GuardEntry->PreviousSize = 1;
            GuardEntry--;
            GuardEntry->Size = 1;
            GuardEntry->Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
            GuardEntry->SegmentOffset = FreeEntry->SegmentOffset;
            /* Fall-through */
        case 0:
            /* There was just enough space four our guard entry */
            ASSERT((PHEAP_ENTRY)FreeEntry == GuardEntry);
            GuardEntry->PreviousSize = FreeEntry->PreviousSize;
            break;
        default:
            /* We can insert this as a free entry */
            GuardEntry->PreviousSize = PrecedingSize;
            FreeEntry->Size = PrecedingSize;
            FreeEntry->Flags &= ~HEAP_ENTRY_LAST_ENTRY;
            FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &PrecedingSize, FALSE);
            RtlpInsertFreeBlock(Heap, FreeEntry, PrecedingSize);
            break;
    }

    /* Now the next one */
    if (NextEntry)
    {
        ASSERT((PHEAP_ENTRY)DecommitEnd <= NextEntry);

        SIZE_T NextSize = NextEntry - (PHEAP_ENTRY)DecommitEnd;
        if (NextSize)
        {
            PHEAP_FREE_ENTRY NextFreeEntry = (PHEAP_FREE_ENTRY)DecommitEnd;

            /* Make sure this is all valid */
            ASSERT((PHEAP_ENTRY)DecommitEnd < Segment->LastValidEntry);
            ASSERT(NextSize >= 2);

            /* Adjust size of this free entry and insert it */
            NextFreeEntry->Flags = 0;
            NextFreeEntry->PreviousSize = 0;
            NextFreeEntry->SegmentOffset = Segment->Entry.SegmentOffset;
            NextFreeEntry->Size = (USHORT)NextSize;

            NextEntry->PreviousSize = NextSize;
            ASSERT(NextEntry == (PHEAP_ENTRY)NextFreeEntry + NextFreeEntry->Size);

            NextFreeEntry = RtlpCoalesceFreeBlocks(Heap, NextFreeEntry, &NextSize, FALSE);
            RtlpInsertFreeBlock(Heap, NextFreeEntry, NextSize);
        }
        else
        {
            /* This one must be at the beginning of a page */
            ASSERT(NextEntry == (PHEAP_ENTRY)PAGE_ROUND_DOWN(NextEntry));
            /* And we must have a gap betwwen */
            ASSERT(NextEntry > (PHEAP_ENTRY)DecommitBase);
            NextEntry->PreviousSize = 0;
        }
    }
}

NTSTATUS
NTAPI
RtlpInitializeHeapSegment(IN OUT PHEAP Heap,
                          OUT PHEAP_SEGMENT Segment,
                          IN UCHAR SegmentIndex,
                          IN ULONG SegmentFlags,
                          IN SIZE_T SegmentReserve,
                          IN SIZE_T SegmentCommit)
{
    /* Preconditions */
    ASSERT(Heap != NULL);
    ASSERT(Segment != NULL);
    ASSERT(SegmentCommit >= PAGE_SIZE);
    ASSERT(ROUND_DOWN(SegmentCommit, PAGE_SIZE) == SegmentCommit);
    ASSERT(SegmentReserve >= SegmentCommit);
    ASSERT(ROUND_DOWN(SegmentReserve, PAGE_SIZE) == SegmentReserve);

    DPRINT("RtlpInitializeHeapSegment(%p %p %x %x %lx %lx)\n", Heap, Segment, SegmentIndex, SegmentFlags, SegmentReserve, SegmentCommit);

    /* Initialise the Heap Entry header if this is not the first Heap Segment */
    if ((PHEAP_SEGMENT) (Heap) != Segment)
    {
        Segment->Entry.Size = ROUND_UP(sizeof(HEAP_SEGMENT), sizeof(HEAP_ENTRY)) >> HEAP_ENTRY_SHIFT;
        Segment->Entry.Flags = HEAP_ENTRY_BUSY;
        Segment->Entry.SmallTagIndex = LOBYTE(Segment->Entry.Size) ^ HIBYTE(Segment->Entry.Size) ^ Segment->Entry.Flags;
        Segment->Entry.PreviousSize = 0;
        Segment->Entry.SegmentOffset = SegmentIndex;
        Segment->Entry.UnusedBytes = 0;
    }

    /* Sanity check */
    ASSERT((Segment->Entry.Size << HEAP_ENTRY_SHIFT) <= PAGE_SIZE);

    /* Initialise the Heap Segment header */
    Segment->SegmentSignature = HEAP_SEGMENT_SIGNATURE;
    Segment->SegmentFlags = SegmentFlags;
    Segment->Heap = Heap;
    Heap->Segments[SegmentIndex] = Segment;

    /* Initialise the Heap Segment location information */
    Segment->BaseAddress = Segment;
    Segment->NumberOfPages = (ULONG)(SegmentReserve >> PAGE_SHIFT);

    /* Initialise the Heap Entries contained within the Heap Segment */
    Segment->FirstEntry = &Segment->Entry + Segment->Entry.Size;
    Segment->LastValidEntry = (PHEAP_ENTRY)((ULONG_PTR)Segment + SegmentReserve);

    /* Initialise the Heap Segment UnCommitted Range information */
    Segment->NumberOfUnCommittedPages = (ULONG)((SegmentReserve - SegmentCommit) >> PAGE_SHIFT);
    Segment->NumberOfUnCommittedRanges = 0;
    InitializeListHead(&Segment->UCRSegmentList);

    /* We must have space for a guard entry ! */
    ASSERT (((SegmentCommit >> HEAP_ENTRY_SHIFT) > Segment->Entry.Size) || (Segment->NumberOfUnCommittedPages == 0));

    if (((SIZE_T)Segment->Entry.Size << HEAP_ENTRY_SHIFT) < SegmentCommit)
    {
        PHEAP_ENTRY FreeEntry = NULL;

        if (Segment->NumberOfUnCommittedPages != 0)
        {
            /* Ensure we put our guard entry at the end of the last committed page */
            PHEAP_ENTRY GuardEntry = &Segment->Entry + (SegmentCommit >> HEAP_ENTRY_SHIFT) - 1;
            SIZE_T PreviousSize;

            ASSERT(GuardEntry > &Segment->Entry);
            GuardEntry->Size = 1;
            GuardEntry->Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
            GuardEntry->SegmentOffset = SegmentIndex;
            PreviousSize = GuardEntry - Segment->FirstEntry;

            /* Check what is left behind us */
            switch (PreviousSize)
            {
                case 1:
                    GuardEntry->PreviousSize = PreviousSize;

                    /* There is not enough space for a free entry. Double the guard entry */
                    GuardEntry--;
                    GuardEntry->Size = 1;
                    GuardEntry->Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
                    GuardEntry->SegmentOffset = SegmentIndex;
                    DPRINT1("Setting %p as UCR guard entry.\n", GuardEntry);
                    /* Fall through */
                case 0:
                    ASSERT(GuardEntry == Segment->FirstEntry);
                    GuardEntry->PreviousSize = Segment->Entry.Size;
                    break;
                default:
                    /* There will be a free entry between the segment and the guard entry */
                    FreeEntry = Segment->FirstEntry;
                    FreeEntry->PreviousSize = Segment->Entry.Size;
                    FreeEntry->SegmentOffset = SegmentIndex;
                    FreeEntry->Size = PreviousSize;
                    FreeEntry->Flags = 0;

                    /* Register the Free Heap Entry */
                    FreeEntry = (PHEAP_ENTRY)RtlpInsertFreeBlock(Heap, (PHEAP_FREE_ENTRY)FreeEntry, PreviousSize);
                    GuardEntry->PreviousSize = FreeEntry->Size;
                    break;
            }
        }
        else
        {
            /* Prepare a Free Heap Entry header */
            FreeEntry = Segment->FirstEntry;
            FreeEntry->PreviousSize = Segment->Entry.Size;
            FreeEntry->SegmentOffset = SegmentIndex;
            FreeEntry->Flags = HEAP_ENTRY_LAST_ENTRY;

            /* The size does not fit the USHORT of an entry when the segment is fully committed and
               bigger than 1 MB: let the insertion cut it into blocks of the maximum size */
            FreeEntry->Size = 0;
            RtlpInsertFreeBlock(Heap,
                                (PHEAP_FREE_ENTRY)FreeEntry,
                                (SegmentCommit >> HEAP_ENTRY_SHIFT) - Segment->Entry.Size);
        }
    }

    /* Register the UnCommitted Range of the Heap Segment */
    if (Segment->NumberOfUnCommittedPages != 0)
        RtlpInsertUnCommittedPages(Segment, (ULONG_PTR) (Segment) + SegmentCommit, SegmentReserve - SegmentCommit);

    return STATUS_SUCCESS;
}

VOID NTAPI
RtlpDestroyHeapSegment(PHEAP_SEGMENT Segment)
{
    NTSTATUS Status;
    PVOID BaseAddress;
    SIZE_T Size = 0;

    /* Make sure it's not user allocated */
    if (Segment->SegmentFlags & HEAP_USER_ALLOCATED) return;

    BaseAddress = Segment->BaseAddress;
    DPRINT("Destroying segment %p, BA %p\n", Segment, BaseAddress);

    /* Release virtual memory */
    Status = ZwFreeVirtualMemory(NtCurrentProcess(),
                                 &BaseAddress,
                                 &Size,
                                 MEM_RELEASE);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HEAP: Failed to release segment's memory with status 0x%08X\n", Status);
    }
}

PHEAP_FREE_ENTRY NTAPI
RtlpCoalesceHeap(PHEAP Heap)
{
    UNIMPLEMENTED;
    return NULL;
}

PHEAP_FREE_ENTRY NTAPI
RtlpCoalesceFreeBlocks (PHEAP Heap,
                        PHEAP_FREE_ENTRY FreeEntry,
                        PSIZE_T FreeSize,
                        BOOLEAN Remove)
{
    PHEAP_FREE_ENTRY CurrentEntry, NextEntry;
    UCHAR SegmentOffset;

    /* Get the previous entry */
    CurrentEntry = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)FreeEntry - FreeEntry->PreviousSize);

    /* Check it */
    if (CurrentEntry != FreeEntry &&
        !(CurrentEntry->Flags & HEAP_ENTRY_BUSY) &&
        (*FreeSize + CurrentEntry->Size) <= HEAP_MAX_BLOCK_SIZE)
    {
        ASSERT(FreeEntry->PreviousSize == CurrentEntry->Size);

        /* Remove it if asked for */
        if (Remove)
        {
            RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
            Heap->TotalFreeSize -= FreeEntry->Size;

            /* Remove it only once! */
            Remove = FALSE;
        }

        /* Remove previous entry too */
        RtlpRemoveFreeBlock(Heap, CurrentEntry, FALSE);

        /* Copy flags */
        CurrentEntry->Flags = FreeEntry->Flags & HEAP_ENTRY_LAST_ENTRY;

        /* Advance FreeEntry and update sizes */
        FreeEntry = CurrentEntry;
        *FreeSize = *FreeSize + CurrentEntry->Size;
        Heap->TotalFreeSize -= CurrentEntry->Size;
        FreeEntry->Size = (USHORT)(*FreeSize);

        /* Also update previous size if needed */
        if (!(FreeEntry->Flags & HEAP_ENTRY_LAST_ENTRY))
        {
            ((PHEAP_ENTRY)FreeEntry + *FreeSize)->PreviousSize = (USHORT)(*FreeSize);
        }
        else
        {
            SegmentOffset = FreeEntry->SegmentOffset;
            ASSERT(SegmentOffset < HEAP_SEGMENTS);
        }
    }

    /* Check the next block if it exists */
    if (!(FreeEntry->Flags & HEAP_ENTRY_LAST_ENTRY))
    {
        NextEntry = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)FreeEntry + *FreeSize);

        if (!(NextEntry->Flags & HEAP_ENTRY_BUSY) &&
            NextEntry->Size + *FreeSize <= HEAP_MAX_BLOCK_SIZE)
        {
            ASSERT(*FreeSize == NextEntry->PreviousSize);

            /* Remove it if asked for */
            if (Remove)
            {
                RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
                Heap->TotalFreeSize -= FreeEntry->Size;
            }

            /* Copy flags */
            FreeEntry->Flags = NextEntry->Flags & HEAP_ENTRY_LAST_ENTRY;

            /* Remove next entry now */
            RtlpRemoveFreeBlock(Heap, NextEntry, FALSE);

            /* Update sizes */
            *FreeSize = *FreeSize + NextEntry->Size;
            Heap->TotalFreeSize -= NextEntry->Size;
            FreeEntry->Size = (USHORT)(*FreeSize);

            /* Also update previous size if needed */
            if (!(FreeEntry->Flags & HEAP_ENTRY_LAST_ENTRY))
            {
                ((PHEAP_ENTRY)FreeEntry + *FreeSize)->PreviousSize = (USHORT)(*FreeSize);
            }
            else
            {
                SegmentOffset = FreeEntry->SegmentOffset;
                ASSERT(SegmentOffset < HEAP_SEGMENTS);
            }
        }
    }
    return FreeEntry;
}

/* Commits pages in an uncommitted range next to free blocks, counting those blocks towards the request.
 *
 * Freeing a block decommits its whole pages but keeps the partial page at each end of it committed, as a free block
 * of just under a page (the one in front also carries the guard entry before the uncommitted range). When the next
 * request is a little larger than the uncommitted range left behind, say 7.07 pages against 7, the range is too short
 * on its own, the heap commits a fresh range somewhere else, and the kept pages stay behind between two uncommitted
 * ranges, where nothing can decommit them again: every such cycle strands another page (the console server asks for
 * a 29000 byte block to enumerate fonts for every console it creates: 57 bytes per console, a megabyte every 18000
 * consoles). The free blocks around the range and the range together hold the request, so commit only what is
 * missing. */
static
PHEAP_FREE_ENTRY
RtlpFindAndCommitPagesAfterFree(PHEAP Heap,
                                PHEAP_SEGMENT Segment,
                                SIZE_T Request,
                                PSIZE_T Size)
{
    PLIST_ENTRY Current;

    if (Heap->CommitRoutine) return NULL;

    for (Current = Segment->UCRSegmentList.Flink;
         Current != &Segment->UCRSegmentList;
         Current = Current->Flink)
    {
        PHEAP_UCR_DESCRIPTOR UcrDescriptor = CONTAINING_RECORD(Current, HEAP_UCR_DESCRIPTOR, SegmentEntry);
        PHEAP_ENTRY GuardEntry, FreeBlock, NextBlock;
        SIZE_T Before = 0, After = 0, Missing = 0;

        /* A range that holds the whole request is committed the usual way */
        if (UcrDescriptor->Size >= *Size) continue;

        /* A single guard entry ends the committed memory in front of the range; a free block may precede it */
        GuardEntry = (PHEAP_ENTRY)UcrDescriptor->Address - 1;
        if ((GuardEntry->Flags & HEAP_ENTRY_LAST_ENTRY) &&
            (GuardEntry->Flags & HEAP_ENTRY_BUSY) &&
            GuardEntry->Size == 1 &&
            GuardEntry->PreviousSize > 1)
        {
            FreeBlock = GuardEntry - GuardEntry->PreviousSize;
            if (!(FreeBlock->Flags & HEAP_ENTRY_BUSY) &&
                FreeBlock->Size == GuardEntry->PreviousSize &&
                FreeBlock->SegmentOffset == GuardEntry->SegmentOffset)
            {
                Before = (SIZE_T)FreeBlock->Size << HEAP_ENTRY_SHIFT;
            }
        }

        /* A free block may follow the range */
        NextBlock = (PHEAP_ENTRY)((PUCHAR)UcrDescriptor->Address + UcrDescriptor->Size);
        if (NextBlock < Segment->LastValidEntry &&
            !(NextBlock->Flags & HEAP_ENTRY_BUSY) &&
            NextBlock->Size != 0 &&
            NextBlock->SegmentOffset == Segment->Entry.SegmentOffset)
        {
            After = (SIZE_T)NextBlock->Size << HEAP_ENTRY_SHIFT;
        }

        /* Commit just what the block in front does not cover; else, if the range with both blocks is enough,
           all of it, which joins it with the block behind */
        if (Before != 0 && Before < Request)
        {
            Missing = ROUND_UP(Request - Before, PAGE_SIZE);
            if (Missing > UcrDescriptor->Size || Missing >= *Size)
                Missing = 0;
        }

        if (Missing == 0 &&
            After != 0 &&
            Before + After + UcrDescriptor->Size >= Request)
        {
            Missing = UcrDescriptor->Size;
        }

        if (Missing != 0)
        {
            SIZE_T CommitSize = Missing;
            PHEAP_FREE_ENTRY Entry = RtlpFindAndCommitPages(Heap, Segment, &CommitSize, UcrDescriptor->Address);

            if (Entry)
            {
                *Size = CommitSize;
                return Entry;
            }
        }
    }

    return NULL;
}

static BOOLEAN RtlpHeapTrim(PHEAP Heap, SIZE_T Keep, ULONG MaxBlocks);

static
PHEAP_FREE_ENTRY
RtlpExtendHeap(PHEAP Heap,
               SIZE_T Size)
{
    ULONG Pages;
    UCHAR Index, EmptyIndex;
    SIZE_T FreeSize, CommitSize, ReserveSize;
    PHEAP_SEGMENT Segment;
    PHEAP_FREE_ENTRY FreeEntry;
    NTSTATUS Status;
    BOOLEAN Trimmed = FALSE;

    DPRINT("RtlpExtendHeap(%p %x)\n", Heap, Size);
    Heap->TrimExtends++;

Retry:

    /* Calculate amount in pages */
    Pages = (ULONG)((Size + PAGE_SIZE - 1) / PAGE_SIZE);
    FreeSize = Pages * PAGE_SIZE;
    DPRINT("Pages %x, FreeSize %x. Going through segments...\n", Pages, FreeSize);

    /* Find an empty segment */
    EmptyIndex = HEAP_SEGMENTS;
    for (Index = 0; Index < HEAP_SEGMENTS; Index++)
    {
        Segment = Heap->Segments[Index];

        if (Segment) DPRINT("Segment[%u] %p with NOUCP %x\n", Index, Segment, Segment->NumberOfUnCommittedPages);

        /* Check if its size suits us */
        if (Segment &&
            Pages <= Segment->NumberOfUnCommittedPages)
        {
            DPRINT("This segment is suitable\n");

            /* Commit needed amount, in a range that follows a free block if that saves committing a new one */
            FreeEntry = RtlpFindAndCommitPagesAfterFree(Heap, Segment, Size, &FreeSize);

            /* That path commits less than the request and counts on the neighbours joining the new pages. The caller
               takes the entry as it is, so an entry that came out short (a neighbour that did not merge) stays on the
               free lists as a free block and the request is committed in full the usual way. */
            if (FreeEntry)
            {
                FreeSize = FreeSize >> HEAP_ENTRY_SHIFT;
                FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &FreeSize, FALSE);
                RtlpInsertFreeBlock(Heap, FreeEntry, FreeSize);
                if ((FreeSize << HEAP_ENTRY_SHIFT) >= Size)
                    return FreeEntry;

                FreeSize = Pages * PAGE_SIZE;
                if (Pages > Segment->NumberOfUnCommittedPages)
                    continue;
            }

            FreeEntry = RtlpFindAndCommitPages(Heap, Segment, &FreeSize, NULL);

            /* Coalesce it with adjacent entries */
            if (FreeEntry)
            {
                FreeSize = FreeSize >> HEAP_ENTRY_SHIFT;
                FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &FreeSize, FALSE);
                RtlpInsertFreeBlock(Heap, FreeEntry, FreeSize);
                return FreeEntry;
            }
        }
        else if (!Segment &&
                 EmptyIndex == HEAP_SEGMENTS)
        {
            /* Remember the first unused segment index */
            EmptyIndex = Index;
        }
    }

    /* No luck, need to grow the heap */
    if ((Heap->Flags & HEAP_GROWABLE) &&
        (EmptyIndex != HEAP_SEGMENTS))
    {
        Segment = NULL;

        /* Reserve the memory */
        if ((Size + PAGE_SIZE) <= Heap->SegmentReserve)
            ReserveSize = Heap->SegmentReserve;
        else
            ReserveSize = Size + PAGE_SIZE;

        Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                         (PVOID)&Segment,
                                         0,
                                         &ReserveSize,
                                         MEM_RESERVE,
                                         RtlpHeapPageProtection(Heap->Flags));

        /* If it failed, retry again with a half division algorithm */
        while (!NT_SUCCESS(Status) &&
            ReserveSize != Size + PAGE_SIZE)
        {
            ReserveSize /= 2;

            if (ReserveSize < (Size + PAGE_SIZE))
                ReserveSize = Size + PAGE_SIZE;

            Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                             (PVOID)&Segment,
                                             0,
                                             &ReserveSize,
                                             MEM_RESERVE,
                                             RtlpHeapPageProtection(Heap->Flags));
        }

        /* Proceed only if it's success */
        if (NT_SUCCESS(Status))
        {
            Heap->SegmentReserve += ReserveSize;

            /* Now commit the memory */
            if ((Size + PAGE_SIZE) <= Heap->SegmentCommit)
                CommitSize = Heap->SegmentCommit;
            else
                CommitSize = Size + PAGE_SIZE;

            Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                             (PVOID)&Segment,
                                             0,
                                             &CommitSize,
                                             MEM_COMMIT,
                                             RtlpHeapPageProtection(Heap->Flags));

            DPRINT("Committed %lu bytes at base %p\n", CommitSize, Segment);

            /* Initialize heap segment if commit was successful */
            if (NT_SUCCESS(Status))
                Status = RtlpInitializeHeapSegment(Heap, Segment, EmptyIndex, 0, ReserveSize, CommitSize);

            /* If everything worked - cool */
            if (NT_SUCCESS(Status)) return (PHEAP_FREE_ENTRY)Segment->FirstEntry;

            DPRINT1("Committing failed with status 0x%08X\n", Status);

            /* Nope, we failed. Free memory */
            ZwFreeVirtualMemory(NtCurrentProcess(),
                                (PVOID)&Segment,
                                &ReserveSize,
                                MEM_RELEASE);
        }
        else
        {
            DPRINT1("Reserving failed with status 0x%08X\n", Status);
        }
    }

    if (RtlpGetMode() == UserMode)
    {
        /* If coalescing on free is disabled in usermode, then do it here */
        if (Heap->Flags & HEAP_DISABLE_COALESCE_ON_FREE)
        {
            FreeEntry = RtlpCoalesceHeap(Heap);

            /* If it's a suitable one - return it */
            if (FreeEntry &&
                FreeEntry->Size >= Size)
            {
                return FreeEntry;
            }
        }

        /* Nowhere to grow: the cached free pages may be what keeps the uncommitted ranges of the
           segments apart. Give all of them back and look again. */
        if (!Trimmed && !Heap->CommitRoutine && RtlpHeapTrim(Heap, 0, MAXULONG))
        {
            Trimmed = TRUE;
            goto Retry;
        }
    }

    return NULL;
}

/***********************************************************************
 *           RtlCreateHeap
 * RETURNS
 * Handle of heap: Success
 * NULL: Failure
 *
 * @implemented
 */
HANDLE NTAPI
RtlCreateHeap(ULONG Flags,
              PVOID Addr,
              SIZE_T TotalSize,
              SIZE_T CommitSize,
              PVOID Lock,
              PRTL_HEAP_PARAMETERS Parameters)
{
    PVOID CommittedAddress = NULL, UncommittedAddress = NULL;
    PHEAP Heap = NULL;
    RTL_HEAP_PARAMETERS SafeParams = {0};
    ULONG_PTR MaximumUserModeAddress;
    SYSTEM_BASIC_INFORMATION SystemInformation;
    MEMORY_BASIC_INFORMATION MemoryInfo;
    ULONG NtGlobalFlags = RtlGetNtGlobalFlags();
    ULONG HeapSegmentFlags = 0;
    NTSTATUS Status;
    ULONG MaxBlockSize;

    /* Check for a special heap */
    if (RtlpPageHeapEnabled && !Addr && !Lock)
    {
        Heap = RtlpPageHeapCreate(Flags, Addr, TotalSize, CommitSize, Lock, Parameters);
        if (Heap) return Heap;

        /* Reset a special Parameters == -1 hack */
        if ((ULONG_PTR)Parameters == (ULONG_PTR)-1)
            Parameters = NULL;
        else
            DPRINT1("Enabling page heap failed\n");
    }

    /* Check validation flags */
    if (!(Flags & HEAP_SKIP_VALIDATION_CHECKS) && (Flags & ~HEAP_CREATE_VALID_MASK))
    {
        DPRINT1("Invalid flags 0x%08x, fixing...\n", Flags);
        Flags &= HEAP_CREATE_VALID_MASK;
    }

    /* Capture parameters */
    if (Parameters)
    {
        _SEH2_TRY
        {
            /* If size of structure correct, then copy it */
            if (Parameters->Length == sizeof(RTL_HEAP_PARAMETERS))
                RtlCopyMemory(&SafeParams, Parameters, sizeof(RTL_HEAP_PARAMETERS));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return NULL);
        }
        _SEH2_END;
    }

    Parameters = &SafeParams;

    /* Check global flags */
    if (NtGlobalFlags & FLG_HEAP_DISABLE_COALESCING)
        Flags |= HEAP_DISABLE_COALESCE_ON_FREE;

    if (NtGlobalFlags & FLG_HEAP_ENABLE_FREE_CHECK)
        Flags |= HEAP_FREE_CHECKING_ENABLED;

    if (NtGlobalFlags & FLG_HEAP_ENABLE_TAIL_CHECK)
        Flags |= HEAP_TAIL_CHECKING_ENABLED;

    if (RtlpGetMode() == UserMode)
    {
        /* Also check these flags if in usermode */
        if (NtGlobalFlags & FLG_HEAP_VALIDATE_ALL)
            Flags |= HEAP_VALIDATE_ALL_ENABLED;

        if (NtGlobalFlags & FLG_HEAP_VALIDATE_PARAMETERS)
            Flags |= HEAP_VALIDATE_PARAMETERS_ENABLED;

        if (NtGlobalFlags & FLG_USER_STACK_TRACE_DB)
            Flags |= HEAP_CAPTURE_STACK_BACKTRACES;
    }

    /* Set tunable parameters */
    RtlpSetHeapParameters(Parameters);

    /* Get the max um address */
    Status = ZwQuerySystemInformation(SystemBasicInformation,
                                      &SystemInformation,
                                      sizeof(SystemInformation),
                                      NULL);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Getting max usermode address failed with status 0x%08x\n", Status);
        return NULL;
    }

    MaximumUserModeAddress = SystemInformation.MaximumUserModeAddress;

    /* Calculate max alloc size */
    if (!Parameters->MaximumAllocationSize)
        Parameters->MaximumAllocationSize = MaximumUserModeAddress - (ULONG_PTR)0x10000 - PAGE_SIZE;

    MaxBlockSize = 0x80000 - PAGE_SIZE;

    if (!Parameters->VirtualMemoryThreshold ||
        Parameters->VirtualMemoryThreshold > MaxBlockSize)
    {
        Parameters->VirtualMemoryThreshold = MaxBlockSize;
    }

    if (Parameters->DeCommitFreeBlockThreshold != PAGE_SIZE)
    {
        DPRINT1("WARNING: Ignoring DeCommitFreeBlockThreshold %lx, setting it to PAGE_SIZE.\n",
                Parameters->DeCommitFreeBlockThreshold);
        Parameters->DeCommitFreeBlockThreshold = PAGE_SIZE;
    }

    /* Check reserve/commit sizes and set default values */
    if (!CommitSize)
    {
        CommitSize = PAGE_SIZE;
        if (TotalSize)
            TotalSize = ROUND_UP(TotalSize, PAGE_SIZE);
        else
            TotalSize = 64 * PAGE_SIZE;
    }
    else
    {
        /* Round up the commit size to be at least the page size */
        CommitSize = ROUND_UP(CommitSize, PAGE_SIZE);

        if (TotalSize)
            TotalSize = ROUND_UP(TotalSize, PAGE_SIZE);
        else
            TotalSize = ROUND_UP(CommitSize, 16 * PAGE_SIZE);
    }

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugCreateHeap(Flags, Addr, TotalSize, CommitSize, Lock, Parameters);

    /* Without serialization, a lock makes no sense */
    if ((Flags & HEAP_NO_SERIALIZE) && (Lock != NULL))
        return NULL;

    /* See if we are already provided with an address for the heap */
    if (Addr)
    {
        if (Parameters->CommitRoutine)
        {
            /* There is a commit routine, so no problem here, check params */
            if ((Flags & HEAP_GROWABLE) ||
                !Parameters->InitialCommit ||
                !Parameters->InitialReserve ||
                (Parameters->InitialCommit > Parameters->InitialReserve))
            {
                /* Fail */
                return NULL;
            }

            /* Calculate committed and uncommitted addresses */
            CommittedAddress = Addr;
            UncommittedAddress = (PCHAR)Addr + Parameters->InitialCommit;
            TotalSize = Parameters->InitialReserve;

            /* Zero the initial page ourselves */
            RtlZeroMemory(CommittedAddress, PAGE_SIZE);
        }
        else
        {
            /* Commit routine is absent, so query how much memory caller reserved */
            Status = ZwQueryVirtualMemory(NtCurrentProcess(),
                                          Addr,
                                          MemoryBasicInformation,
                                          &MemoryInfo,
                                          sizeof(MemoryInfo),
                                          NULL);

            if (!NT_SUCCESS(Status))
            {
                DPRINT1("Querying amount of user supplied memory failed with status 0x%08X\n", Status);
                return NULL;
            }

            /* Validate it */
            if (MemoryInfo.BaseAddress != Addr ||
                MemoryInfo.State == MEM_FREE)
            {
                return NULL;
            }

            /* Validation checks passed, set committed/uncommitted addresses */
            CommittedAddress = Addr;

            /* Check if it's committed or not */
            if (MemoryInfo.State == MEM_COMMIT)
            {
                /* Zero it out because it's already committed */
                RtlZeroMemory(CommittedAddress, PAGE_SIZE);

                /* Calculate uncommitted address value */
                CommitSize = MemoryInfo.RegionSize;
                TotalSize = CommitSize;
                UncommittedAddress = (PCHAR)Addr + CommitSize;

                /* Check if uncommitted address is reserved */
                Status = ZwQueryVirtualMemory(NtCurrentProcess(),
                                              UncommittedAddress,
                                              MemoryBasicInformation,
                                              &MemoryInfo,
                                              sizeof(MemoryInfo),
                                              NULL);

                if (NT_SUCCESS(Status) &&
                    MemoryInfo.State == MEM_RESERVE)
                {
                    /* It is, so add it up to the reserve size */
                    TotalSize += MemoryInfo.RegionSize;
                }
            }
            else
            {
                /* It's not committed, inform following code that a commit is necessary */
                CommitSize = PAGE_SIZE;
                UncommittedAddress = Addr;
            }
        }

        /* Mark this as a user-committed mem */
        HeapSegmentFlags = HEAP_USER_ALLOCATED;
        Heap = (PHEAP)Addr;
    }
    else
    {
        /* Check commit routine */
        if (Parameters->CommitRoutine) return NULL;

        /* Reserve memory */
        Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                         (PVOID *)&Heap,
                                         0,
                                         &TotalSize,
                                         MEM_RESERVE,
                                         RtlpHeapPageProtection(Flags));

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to reserve memory with status 0x%08x\n", Status);
            return NULL;
        }

        /* Set base addresses */
        CommittedAddress = Heap;
        UncommittedAddress = Heap;
    }

    /* Check if we need to commit something */
    if (CommittedAddress == UncommittedAddress)
    {
        /* Commit the required size */
        Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                         &CommittedAddress,
                                         0,
                                         &CommitSize,
                                         MEM_COMMIT,
                                         RtlpHeapPageProtection(Flags));

        DPRINT("Committed %Iu bytes at base %p\n", CommitSize, CommittedAddress);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failure, Status 0x%08X\n", Status);

            /* Release memory if it was reserved */
            if (!Addr) ZwFreeVirtualMemory(NtCurrentProcess(),
                                           (PVOID *)&Heap,
                                           &TotalSize,
                                           MEM_RELEASE);

            return NULL;
        }

        /* Calculate new uncommitted address */
        UncommittedAddress = (PCHAR)UncommittedAddress + CommitSize;
    }

    /* Initialize the heap */
    Status = RtlpInitializeHeap(Heap, Flags, Lock, Parameters);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to initialize heap (%x)\n", Status);
        return NULL;
    }

    /* Initialize heap's first segment */
    Status = RtlpInitializeHeapSegment(Heap, (PHEAP_SEGMENT) (Heap), 0, HeapSegmentFlags, TotalSize, CommitSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to initialize heap segment (%x)\n", Status);
        return NULL;
    }

    DPRINT("Created heap %p, CommitSize %x, ReserveSize %x\n", Heap, CommitSize, TotalSize);

    /* Add heap to process list in case of usermode heap */
    if (RtlpGetMode() == UserMode)
    {
        RtlpAddHeapToProcessList(Heap);

        // FIXME: What about lookasides?
    }

    return Heap;
}

/***********************************************************************
 *           RtlDestroyHeap
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 *
 * RETURNS
 *  Success: A NULL HANDLE, if heap is NULL or it was destroyed
 *  Failure: The Heap handle, if heap is the process heap.
 */
HANDLE NTAPI
RtlDestroyHeap(HANDLE HeapPtr) /* [in] Handle of heap */
{
    PHEAP Heap = (PHEAP)HeapPtr;
    PLIST_ENTRY Current;
    PHEAP_UCR_SEGMENT UcrSegment;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;
    PVOID BaseAddress;
    SIZE_T Size;
    LONG i;
    PHEAP_SEGMENT Segment;

    if (!HeapPtr) return NULL;

    /* Call page heap routine if required */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS) return RtlpPageHeapDestroy(HeapPtr);

    /* Call special heap */
    if (RtlpHeapIsSpecial(Heap->Flags))
    {
        if (!RtlDebugDestroyHeap(Heap)) return HeapPtr;
    }

    /* Check for a process heap */
    if (RtlpGetMode() == UserMode &&
        HeapPtr == NtCurrentPeb()->ProcessHeap) return HeapPtr;

    /* Free up all big allocations */
    Current = Heap->VirtualAllocdBlocks.Flink;
    while (Current != &Heap->VirtualAllocdBlocks)
    {
        VirtualEntry = CONTAINING_RECORD(Current, HEAP_VIRTUAL_ALLOC_ENTRY, Entry);
        BaseAddress = (PVOID)VirtualEntry;
        Current = Current->Flink;
        Size = 0;
        ZwFreeVirtualMemory(NtCurrentProcess(),
                            &BaseAddress,
                            &Size,
                            MEM_RELEASE);
    }

    /* Delete tags and remove heap from the process heaps list in user mode */
    if (RtlpGetMode() == UserMode)
    {
        // FIXME DestroyTags
        RtlpRemoveHeapFromProcessList(Heap);
    }

    /* Release the front end, if any */
    RtlpHeapFeDestroy(Heap);

    /* Delete the heap lock */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE))
    {
        /* Delete it if it wasn't user allocated */
        if (!(Heap->Flags & HEAP_LOCK_USER_ALLOCATED))
            RtlDeleteHeapLock(Heap->LockVariable);

        /* Clear out the lock variable */
        Heap->LockVariable = NULL;
    }

    /* Free UCR segments if any were created */
    Current = Heap->UCRSegments.Flink;
    while (Current != &Heap->UCRSegments)
    {
        UcrSegment = CONTAINING_RECORD(Current, HEAP_UCR_SEGMENT, ListEntry);

        /* Advance to the next descriptor */
        Current = Current->Flink;

        BaseAddress = (PVOID)UcrSegment;
        Size = 0;

        /* Release that memory */
        ZwFreeVirtualMemory(NtCurrentProcess(),
                            &BaseAddress,
                            &Size,
                            MEM_RELEASE);
    }

    /* Go through segments and destroy them */
    for (i = HEAP_SEGMENTS - 1; i >= 0; i--)
    {
        Segment = Heap->Segments[i];
        if (Segment) RtlpDestroyHeapSegment(Segment);
    }

    return NULL;
}

PHEAP_ENTRY NTAPI
RtlpSplitEntry(PHEAP Heap,
               ULONG Flags,
               PHEAP_FREE_ENTRY FreeBlock,
               SIZE_T AllocationSize,
               SIZE_T Index,
               SIZE_T Size)
{
    PHEAP_FREE_ENTRY SplitBlock, SplitBlock2;
    UCHAR FreeFlags, EntryFlags = HEAP_ENTRY_BUSY;
    PHEAP_ENTRY InUseEntry;
    SIZE_T FreeSize;
    UCHAR SegmentOffset;

    /* Add extra flags in case of settable user value feature is requested,
       or there is a tag (small or normal) or there is a request to
       capture stack backtraces */
    if ((Flags & HEAP_EXTRA_FLAGS_MASK) ||
        Heap->PseudoTagEntries)
    {
        /* Add flag which means that the entry will have extra stuff attached */
        EntryFlags |= HEAP_ENTRY_EXTRA_PRESENT;

        /* NB! AllocationSize is already adjusted by RtlAllocateHeap */
    }

    /* Add settable user flags, if any */
    EntryFlags |= (Flags & HEAP_SETTABLE_USER_FLAGS) >> 4;

    /* Save flags, update total free size */
    FreeFlags = FreeBlock->Flags;
    Heap->TotalFreeSize -= FreeBlock->Size;

    /* Make this block an in-use one */
    InUseEntry = (PHEAP_ENTRY)FreeBlock;
    InUseEntry->Flags = EntryFlags;
    InUseEntry->SmallTagIndex = 0;

    /* Calculate the extra amount */
    FreeSize = InUseEntry->Size - Index;

    /* Update it's size fields (we don't need their data anymore) */
    InUseEntry->Size = (USHORT)Index;
    InUseEntry->UnusedBytes = (UCHAR)(AllocationSize - Size);

    /* If there is something to split - do the split */
    if (FreeSize != 0)
    {
        /* Don't split if resulting entry can't contain any payload data
        (i.e. being just HEAP_ENTRY_SIZE) */
        if (FreeSize == 1)
        {
            /* Increase sizes of the in-use entry */
            InUseEntry->Size++;
            InUseEntry->UnusedBytes += sizeof(HEAP_ENTRY);
        }
        else
        {
            /* Calculate a pointer to the new entry */
            SplitBlock = (PHEAP_FREE_ENTRY)(InUseEntry + Index);

            /* Initialize it */
            SplitBlock->Flags = FreeFlags;
            SplitBlock->SegmentOffset = InUseEntry->SegmentOffset;
            SplitBlock->Size = (USHORT)FreeSize;
            SplitBlock->PreviousSize = (USHORT)Index;

            /* Check if it's the last entry */
            if (FreeFlags & HEAP_ENTRY_LAST_ENTRY)
            {
                /* Insert it to the free list if it's the last entry */
                RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);
                Heap->TotalFreeSize += FreeSize;
            }
            else
            {
                /* Not so easy - need to update next's previous size too */
                SplitBlock2 = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize);

                if (SplitBlock2->Flags & HEAP_ENTRY_BUSY)
                {
                    SplitBlock2->PreviousSize = (USHORT)FreeSize;
                    RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);
                    Heap->TotalFreeSize += FreeSize;
                }
                else
                {
                    /* Even more complex - the next entry is free, so we can merge them into one! */
                    SplitBlock->Flags = SplitBlock2->Flags;

                    /* Remove that next entry */
                    RtlpRemoveFreeBlock(Heap, SplitBlock2, FALSE);

                    /* Update sizes */
                    FreeSize += SplitBlock2->Size;
                    Heap->TotalFreeSize -= SplitBlock2->Size;

                    if (FreeSize <= HEAP_MAX_BLOCK_SIZE)
                    {
                        /* Insert it back */
                        SplitBlock->Size = (USHORT)FreeSize;

                        /* Don't forget to update previous size of the next entry! */
                        if (!(SplitBlock->Flags & HEAP_ENTRY_LAST_ENTRY))
                        {
                            ((PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize))->PreviousSize = (USHORT)FreeSize;
                        }

                        /* Actually insert it */
                        RtlpInsertFreeBlockHelper(Heap, SplitBlock, (USHORT)FreeSize, FALSE);

                        /* Update total size */
                        Heap->TotalFreeSize += FreeSize;
                    }
                    else
                    {
                        /* Resulting block is quite big */
                        RtlpInsertFreeBlock(Heap, SplitBlock, FreeSize);
                    }
                }
            }

            /* Reset flags of the free entry */
            FreeFlags = 0;
            if (SplitBlock->Flags & HEAP_ENTRY_LAST_ENTRY)
            {
                SegmentOffset = SplitBlock->SegmentOffset;
                ASSERT(SegmentOffset < HEAP_SEGMENTS);
            }
        }
    }

    /* Set last entry flag */
    if (FreeFlags & HEAP_ENTRY_LAST_ENTRY)
        InUseEntry->Flags |= HEAP_ENTRY_LAST_ENTRY;

    return InUseEntry;
}

/* Free pages a heap keeps committed instead of handing them back at once.
 *
 * A free of a block that spans a whole page used to decommit it whenever the heap held DeCommitTotalFreeThreshold
 * (64 KB, the PEB / Session Manager value) of free blocks in total, which is true of every heap that has run for a
 * while. The next allocation the free lists could not serve committed the same pages again: two system calls made
 * with the heap lock held and one more descriptor in the segment's list of uncommitted ranges, which the commit and
 * decommit paths walk from the start. A program that builds and drops a lot of memory (a JIT compiler) spent a
 * third of its time there.
 *
 * Now a user-mode heap decommits a block of at least DeCommitFreeBlockThreshold only when the free blocks, the new
 * one included, reach a quarter of what the heap has committed (never less than DeCommitTotalFreeThreshold). Below
 * that the free pages are a cache. The cache is trimmed back to DeCommitTotalFreeThreshold when the heap went a
 * whole second without having to grow: then the cache was not needed, and an idle process does not keep memory it
 * stopped using. */
#define HEAP_TRIM_CAP_SHIFT     2
#define HEAP_TRIM_MAX_BLOCKS    512

static SIZE_T
RtlpHeapCommittedUnits(PHEAP Heap)
{
    SIZE_T Units = 0;
    ULONG i;

    for (i = 0; i < HEAP_SEGMENTS; i++)
    {
        PHEAP_SEGMENT Segment = Heap->Segments[i];
        if (Segment)
            Units += (SIZE_T)(Segment->NumberOfPages - Segment->NumberOfUnCommittedPages) * (PAGE_SIZE >> HEAP_ENTRY_SHIFT);
    }
    return Units;
}

/* Gives committed free pages back, largest free block first, until Keep entry units of free blocks are left or
   MaxBlocks blocks were looked at. Returns whether any page was given back. The heap lock is held. */
static BOOLEAN
RtlpHeapTrim(PHEAP Heap, SIZE_T Keep, ULONG MaxBlocks)
{
    ULONG Budget = MaxBlocks;
    BOOLEAN Done = FALSE;

    while (Budget-- &&
           Heap->TotalFreeSize > Keep &&
           !IsListEmpty(&Heap->FreeLists))
    {
        PHEAP_FREE_ENTRY Entry = CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY, FreeList);
        SIZE_T Size = Entry->Size, Before = Heap->TotalFreeSize;

        /* The list is sorted by size: nothing that spans a page is left */
        if (Size <= Heap->DeCommitFreeBlockThreshold)
            break;

        RtlpRemoveFreeBlock(Heap, Entry, FALSE);
        Heap->TotalFreeSize -= Size;
        RtlpDeCommitFreeBlock(Heap, Entry, Size);

        /* The block had no whole page to give back and went into the lists again */
        if (Heap->TotalFreeSize >= Before)
            break;
        Done = TRUE;
    }
    return Done;
}

/* Once per HEAP_TRIM_INTERVAL_MS, on a free: a heap that went a whole interval without growing gets back what it
   parked in the front end, and gives its cached free pages back down to DeCommitTotalFreeThreshold. The caller
   holds the heap lock and holds no front end lock. */
static VOID
RtlpHeapTrimCheck(PHEAP Heap)
{
    ULONG Now = RtlpHeapTickMs();

    if (Now - Heap->TrimTick >= HEAP_TRIM_INTERVAL_MS)
    {
        BOOLEAN Quiet = (Heap->TrimTick != 0 && Heap->TrimExtends == 0);

        /* Set first: giving the parked blocks back frees blocks, which come through here again */
        Heap->TrimTick = Now ? Now : 1;
        Heap->TrimExtends = 0;

        if (Quiet)
        {
            if (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE)
                RtlpHeapFeFlush(Heap);

            if (Heap->TotalFreeSize > Heap->DeCommitTotalFreeThreshold)
                RtlpHeapTrim(Heap, Heap->DeCommitTotalFreeThreshold, HEAP_TRIM_MAX_BLOCKS);
        }
    }
}

/* Gives an in-use block back to the heap proper: coalesce, decommit or insert. The heap lock is held. */
VOID NTAPI
RtlpFreeBlockLocked(PHEAP Heap,
                    PHEAP_ENTRY HeapEntry,
                    BOOLEAN CheckTrim)
{
    SIZE_T BlockSize = HeapEntry->Size;
    BOOLEAN Decommit;

    /* Coalesce in kernel mode, and in usermode if it's not disabled */
    if (RtlpGetMode() == KernelMode ||
        (RtlpGetMode() == UserMode && !(Heap->Flags & HEAP_DISABLE_COALESCE_ON_FREE)))
    {
        HeapEntry = (PHEAP_ENTRY)RtlpCoalesceFreeBlocks(Heap,
                                                       (PHEAP_FREE_ENTRY)HeapEntry,
                                                       &BlockSize,
                                                       FALSE);
    }

    /* See if we should decommit this block */
    if (RtlpGetMode() == UserMode)
    {
        /* The cap costs a walk over the segments: only a block that can be decommitted needs it, and a
           heap whose free blocks do not even reach the minimum cap is below it whatever it has committed */
        Decommit = FALSE;
        if (BlockSize >= Heap->DeCommitFreeBlockThreshold &&
            Heap->TotalFreeSize + BlockSize >= Heap->DeCommitTotalFreeThreshold)
        {
            SIZE_T Cap = RtlpHeapCommittedUnits(Heap) >> HEAP_TRIM_CAP_SHIFT;

            if (Cap < Heap->DeCommitTotalFreeThreshold)
                Cap = Heap->DeCommitTotalFreeThreshold;

            Decommit = (Heap->TotalFreeSize + BlockSize >= Cap);
        }
    }
    else
    {
        Decommit = (BlockSize >= Heap->DeCommitFreeBlockThreshold) ||
                   (Heap->TotalFreeSize + BlockSize >= Heap->DeCommitTotalFreeThreshold);
    }

    if (Decommit)
    {
        RtlpDeCommitFreeBlock(Heap, (PHEAP_FREE_ENTRY)HeapEntry, BlockSize);
    }
    else
    {
        /* Insert into the free list */
        RtlpInsertFreeBlock(Heap, (PHEAP_FREE_ENTRY)HeapEntry, BlockSize);
    }

    /* The check is also made when the block was decommitted: a heap with a front end sends a free here to run
       it only when it is due, and must not be sent again at the next free */
    if (CheckTrim && RtlpGetMode() == UserMode)
        RtlpHeapTrimCheck(Heap);
}

/* Takes the lock of a serialized heap. A user-mode heap that made this wait
   often enough gets the front end, as the caller of the first wait holds the lock. */
static
VOID
RtlpHeapEnterLock(PHEAP Heap)
{
    if (Heap->FrontEndHeapType == 0 &&
        Heap->Counters.LockCollisions < HEAP_FE_AUTO_THRESHOLD)
    {
        if (!RtlTryEnterHeapLock(Heap->LockVariable, TRUE))
        {
            RtlEnterHeapLock(Heap->LockVariable, TRUE);
            if (++Heap->Counters.LockCollisions >= HEAP_FE_AUTO_THRESHOLD)
                RtlpHeapFeEnable(Heap);
        }
        return;
    }

    RtlEnterHeapLock(Heap->LockVariable, TRUE);
}

static
PVOID
RtlpAllocateNonDedicated(PHEAP Heap,
                         ULONG Flags,
                         SIZE_T Size,
                         SIZE_T AllocationSize,
                         SIZE_T Index,
                         BOOLEAN HeapLocked)
{
    PHEAP_FREE_ENTRY FreeBlock;

    /* The entries in the list must be too small for us */
    ASSERT(IsListEmpty(&Heap->FreeLists) ||
           (CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY, FreeList)->Size < Index));

    /* Blocks parked in the front end may make room: give them back and try the heap again.
       Only when a lot is parked (they are bounded per slot, so growing first keeps the size
       classes warm; flushing at every growth would empty the classes the next requests look in)
       or when the heap cannot grow. */
    if (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE &&
        RtlpHeapFeParked(Heap) > HEAP_FE_FLUSH_LIMIT)
    {
        /* While the front end is held out, nothing is parked behind our back */
        ULONG Flushed = RtlpHeapFeLock(Heap);

        if (Flushed)
        {
            PVOID Block = RtlAllocateHeap(Heap, Flags | HEAP_NO_SERIALIZE, Size);

            RtlpHeapFeUnlock(Heap);
            if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);
            return Block;
        }

        RtlpHeapFeUnlock(Heap);
    }

    /* Extend the heap */
    FreeBlock = RtlpExtendHeap(Heap, AllocationSize);

    if (!FreeBlock &&
        Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE)
    {
        ULONG Flushed = RtlpHeapFeLock(Heap);

        if (Flushed)
        {
            PVOID Block = RtlAllocateHeap(Heap, Flags | HEAP_NO_SERIALIZE, Size);

            RtlpHeapFeUnlock(Heap);
            if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);
            return Block;
        }

        RtlpHeapFeUnlock(Heap);
    }

    /* Use the new biggest entry we've got */
    if (FreeBlock)
    {
        PHEAP_ENTRY InUseEntry;
        PHEAP_ENTRY_EXTRA Extra;

        RtlpRemoveFreeBlock(Heap, FreeBlock, TRUE);

        /* Split it */
        InUseEntry = RtlpSplitEntry(Heap, Flags, FreeBlock, AllocationSize, Index, Size);

        if (HeapLocked && Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE)
            RtlpHeapFeRefill(Heap, InUseEntry);

        /* Release the lock */
        if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);

        /* Zero memory if that was requested */
        if (Flags & HEAP_ZERO_MEMORY)
            RtlZeroMemory(InUseEntry + 1, Size);
        else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED)
        {
            /* Fill this block with a special pattern */
            RtlFillMemoryUlong(InUseEntry + 1, Size & ~0x3, ARENA_INUSE_FILLER);
        }

        /* Fill tail of the block with a special pattern too if requested */
        if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED)
        {
            RtlFillMemory((PCHAR)(InUseEntry + 1) + Size, sizeof(HEAP_ENTRY), HEAP_TAIL_FILL);
            InUseEntry->Flags |= HEAP_ENTRY_FILL_PATTERN;
        }

        /* Prepare extra if it's present */
        if (InUseEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
        {
            Extra = RtlpGetExtraStuffPointer(InUseEntry);
            RtlZeroMemory(Extra, sizeof(HEAP_ENTRY_EXTRA));

            // TODO: Tagging
        }

        /* Return pointer to the */
        return InUseEntry + 1;
    }

    /* Really unfortunate, out of memory condition */
    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);

    /* Generate an exception */
    if (Flags & HEAP_GENERATE_EXCEPTIONS)
    {
        EXCEPTION_RECORD ExceptionRecord;

        ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
        ExceptionRecord.ExceptionRecord = NULL;
        ExceptionRecord.NumberParameters = 1;
        ExceptionRecord.ExceptionFlags = 0;
        ExceptionRecord.ExceptionInformation[0] = AllocationSize;

        RtlRaiseException(&ExceptionRecord);
    }

    /* Release the lock */
    if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);
    DPRINT1("HEAP: Allocation failed!\n");
    DPRINT1("Flags %x\n", Heap->Flags);
    return NULL;
}

/***********************************************************************
 *           HeapAlloc   (KERNEL32.334)
 * RETURNS
 * Pointer to allocated memory block
 * NULL: Failure
 * 0x7d030f60--invalid flags in RtlHeapAllocate
 * @implemented
 */
PVOID NTAPI
RtlAllocateHeap(IN PVOID HeapPtr,
                IN ULONG Flags,
                IN SIZE_T Size)
{
    PHEAP Heap = (PHEAP)HeapPtr;
    SIZE_T AllocationSize;
    SIZE_T Index;
    UCHAR EntryFlags = HEAP_ENTRY_BUSY;
    BOOLEAN HeapLocked = FALSE;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualBlock = NULL;
    PHEAP_ENTRY_EXTRA Extra;
    NTSTATUS Status;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugAllocateHeap(Heap, Flags, Size);

    /* Check for the maximum size */
    if (Size >= 0x80000000)
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);
        DPRINT1("HEAP: Allocation failed!\n");
        return NULL;
    }

    if (Flags & (HEAP_CREATE_ENABLE_TRACING))
    {
        DPRINT1("HEAP: RtlAllocateHeap is called with unsupported flags %x, ignoring\n", Flags);
    }

    //DPRINT("RtlAllocateHeap(%p %x %x)\n", Heap, Flags, Size);

    /* Calculate allocation size and index */
    if (Size)
        AllocationSize = Size;
    else
        AllocationSize = 1;
    AllocationSize = (AllocationSize + Heap->AlignRound) & Heap->AlignMask;

    /* Add extra flags in case of settable user value feature is requested,
       or there is a tag (small or normal) or there is a request to
       capture stack backtraces */
    if ((Flags & HEAP_EXTRA_FLAGS_MASK) ||
        Heap->PseudoTagEntries)
    {
        /* Add flag which means that the entry will have extra stuff attached */
        EntryFlags |= HEAP_ENTRY_EXTRA_PRESENT;

        /* Account for extra stuff size */
        AllocationSize += sizeof(HEAP_ENTRY_EXTRA);
    }

    /* Add settable user flags, if any */
    EntryFlags |= (Flags & HEAP_SETTABLE_USER_FLAGS) >> 4;

    Index = AllocationSize >> HEAP_ENTRY_SHIFT;

    /* Small blocks of a heap with a front end: take a cached one, without the heap lock */
    if (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE &&
        EntryFlags == HEAP_ENTRY_BUSY &&
        !(Flags & HEAP_NO_SERIALIZE))
    {
        PHEAP_ENTRY CachedEntry = RtlpHeapFeAlloc(Heap, Index, AllocationSize, Size);

        if (CachedEntry)
        {
            if (Flags & HEAP_ZERO_MEMORY)
                RtlZeroMemory(CachedEntry + 1, Size);

            return CachedEntry + 1;
        }

        /* Nothing cached: the heap serves a block of the size class, so that it files under the
           class a later request like this one looks in when it is freed */
        if (RtlpHeapFeRoundIndex(Index) < HEAP_FE_UNITS)
        {
            Index = RtlpHeapFeRoundIndex(Index);
            AllocationSize = Index << HEAP_ENTRY_SHIFT;
        }
    }

    /* Acquire the lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlpHeapEnterLock(Heap);
        HeapLocked = TRUE;
    }

    /* A heap without a front end counts what it hands out, and gets one as Windows does. A caller that passes
       HEAP_NO_SERIALIZE to a serialized heap holds its lock (HeapLock) or has no other thread using it, as
       it must for the allocation itself, so these are counted too (RtlReAllocateHeap's moves, per-call flags). */
    if (Heap->FrontEndHeapType == 0 && Heap->FeAct != HEAP_FE_ACT_OFF && EntryFlags == HEAP_ENTRY_BUSY)
        RtlpHeapFeCountAlloc(Heap, Index);

    /* Depending on the size, the allocation is going to be done from dedicated,
       non-dedicated lists or a virtual block of memory */
    if (Index <= Heap->VirtualMemoryThreshold)
    {
        PHEAP_ENTRY InUseEntry;
        PHEAP_FREE_ENTRY FreeEntry;

        /* First quick check: Anybody here ? */
        if (IsListEmpty(&Heap->FreeLists))
            return RtlpAllocateNonDedicated(Heap, Flags, Size, AllocationSize, Index, HeapLocked);

        /* Second quick check: Is there someone for us ? */
        FreeEntry = CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY, FreeList);
        if (FreeEntry->Size < Index)
        {
            /* Largest entry in the list doesnt fit. */
            return RtlpAllocateNonDedicated(Heap, Flags, Size, AllocationSize, Index, HeapLocked);
        }

        if (Index > Heap->DeCommitFreeBlockThreshold)
        {
            /* Find an entry from the non dedicated list */
            FreeEntry = CONTAINING_RECORD(Heap->FreeHints[0],
                                      HEAP_FREE_ENTRY,
                                      FreeList);

            while (FreeEntry->Size < Index)
            {
                /* We made sure we had the right size available */
                ASSERT(FreeEntry->FreeList.Flink != &Heap->FreeLists);
                FreeEntry = CONTAINING_RECORD(FreeEntry->FreeList.Flink,
                                              HEAP_FREE_ENTRY,
                                              FreeList);
            }
        }
        else
        {
            /* Get the free entry from the hint */
            ULONG HintIndex = RtlFindSetBits(&Heap->FreeHintBitmap, 1, Index - 1);
            ASSERT(HintIndex != 0xFFFFFFFF);
            ASSERT((HintIndex >= (Index - 1)) || (HintIndex == 0));
            FreeEntry = CONTAINING_RECORD(Heap->FreeHints[HintIndex],
                                          HEAP_FREE_ENTRY,
                                          FreeList);
        }

        /* Remove the free block, split, profit. */
        RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
        InUseEntry = RtlpSplitEntry(Heap, Flags, FreeEntry, AllocationSize, Index, Size);

        /* A thread whose slot keeps missing gets a batch of the class while the lock is held */
        if (HeapLocked && Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE)
            RtlpHeapFeRefill(Heap, InUseEntry);

        /* Release the lock */
        if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);

        /* Zero memory if that was requested */
        if (Flags & HEAP_ZERO_MEMORY)
            RtlZeroMemory(InUseEntry + 1, Size);
        else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED)
        {
            /* Fill this block with a special pattern */
            RtlFillMemoryUlong(InUseEntry + 1, Size & ~0x3, ARENA_INUSE_FILLER);
        }

        /* Fill tail of the block with a special pattern too if requested */
        if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED)
        {
            RtlFillMemory((PCHAR)(InUseEntry + 1) + Size, sizeof(HEAP_ENTRY), HEAP_TAIL_FILL);
            InUseEntry->Flags |= HEAP_ENTRY_FILL_PATTERN;
        }

        /* Prepare extra if it's present */
        if (InUseEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
        {
            Extra = RtlpGetExtraStuffPointer(InUseEntry);
            RtlZeroMemory(Extra, sizeof(HEAP_ENTRY_EXTRA));

            // TODO: Tagging
        }

        /* User data starts right after the entry's header */
        return InUseEntry + 1;
    }

    if (Heap->Flags & HEAP_GROWABLE)
    {
        /* We've got a very big allocation request, satisfy it by directly allocating virtual memory */
        AllocationSize += sizeof(HEAP_VIRTUAL_ALLOC_ENTRY) - sizeof(HEAP_ENTRY);

        Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                         (PVOID *)&VirtualBlock,
                                         0,
                                         &AllocationSize,
                                         MEM_COMMIT,
                                         RtlpHeapPageProtection(Heap->Flags));

        if (!NT_SUCCESS(Status))
        {
            // Set STATUS!
            /* Release the lock */
            if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);
            DPRINT1("HEAP: Allocation failed!\n");
            return NULL;
        }

        /* Initialize the newly allocated block */
        VirtualBlock->BusyBlock.Size = (USHORT)(AllocationSize - Size);
        ASSERT(VirtualBlock->BusyBlock.Size >= sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));
        VirtualBlock->BusyBlock.Flags = EntryFlags | HEAP_ENTRY_VIRTUAL_ALLOC | HEAP_ENTRY_EXTRA_PRESENT;
        VirtualBlock->CommitSize = AllocationSize;
        VirtualBlock->ReserveSize = AllocationSize;

        /* Insert it into the list of virtual allocations */
        InsertTailList(&Heap->VirtualAllocdBlocks, &VirtualBlock->Entry);

        /* Release the lock */
        if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);

        /* Return pointer to user data */
        return VirtualBlock + 1;
    }

    /* Generate an exception */
    if (Flags & HEAP_GENERATE_EXCEPTIONS)
    {
        EXCEPTION_RECORD ExceptionRecord;

        ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
        ExceptionRecord.ExceptionRecord = NULL;
        ExceptionRecord.NumberParameters = 1;
        ExceptionRecord.ExceptionFlags = 0;
        ExceptionRecord.ExceptionInformation[0] = AllocationSize;

        RtlRaiseException(&ExceptionRecord);
    }

    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_BUFFER_TOO_SMALL);

    /* Release the lock */
    if (HeapLocked) RtlLeaveHeapLock(Heap->LockVariable);
    DPRINT1("HEAP: Allocation failed!\n");
    return NULL;
}


/***********************************************************************
 *           HeapFree   (KERNEL32.338)
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN NTAPI RtlFreeHeap(
   HANDLE HeapPtr, /* [in] Handle of heap */
   ULONG Flags,   /* [in] Heap freeing flags */
   PVOID Ptr     /* [in] Address of memory to free */
)
{
    PHEAP Heap;
    PHEAP_ENTRY HeapEntry;
    SIZE_T BlockSize;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;
    BOOLEAN Locked = FALSE;
    NTSTATUS Status;

    /* Freeing NULL pointer is a legal operation */
    if (!Ptr) return TRUE;

    /* Get pointer to the heap and force flags */
    Heap = (PHEAP)HeapPtr;
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugFreeHeap(Heap, Flags, Ptr);

    /* Get pointer to the heap entry */
    HeapEntry = (PHEAP_ENTRY)Ptr - 1;

    /* Protect with SEH in case the pointer is not valid */
    _SEH2_TRY
    {
        /* Check this entry, fail if it's invalid */
        if (!(HeapEntry->Flags & HEAP_ENTRY_BUSY) ||
            (((ULONG_PTR)Ptr & 0x7) != 0) ||
            (HeapEntry->SegmentOffset >= HEAP_SEGMENTS))
        {
            /* This is an invalid block */
            DPRINT1("HEAP: Trying to free an invalid address %p!\n", Ptr);
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
            _SEH2_YIELD(return FALSE);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* The pointer was invalid */
        DPRINT1("HEAP: Trying to free an invalid address %p!\n", Ptr);
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
        _SEH2_YIELD(return FALSE);
    }
    _SEH2_END;

    /* A heap with a front end parks small blocks instead of freeing them, without the heap lock */
    if (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE &&
        !(Flags & HEAP_NO_SERIALIZE))
    {
        ULONG Result = RtlpHeapFeFree(Heap, HeapEntry);

        if (Result == HEAP_FE_CACHED)
            return TRUE;

        if (Result == HEAP_FE_INVALID)
        {
            /* Freed twice */
            DPRINT1("HEAP: Trying to free an already freed block %p!\n", Ptr);
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
            return FALSE;
        }
    }

    /* Lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlpHeapEnterLock(Heap);
        Locked = TRUE;
    }

    /* Counted like the allocations, whether or not this call takes the lock */
    if (Heap->FrontEndHeapType == 0 && Heap->FeAct > HEAP_FE_ACT_OFF &&
        !(HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC))
        RtlpHeapFeCountFree(Heap, HeapEntry);

    if (HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
    {
        /* Big allocation */
        VirtualEntry = CONTAINING_RECORD(HeapEntry, HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);

        /* Remove it from the list */
        RemoveEntryList(&VirtualEntry->Entry);

        // TODO: Tagging

        BlockSize = 0;
        Status = ZwFreeVirtualMemory(NtCurrentProcess(),
                                     (PVOID *)&VirtualEntry,
                                     &BlockSize,
                                     MEM_RELEASE);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("HEAP: Failed releasing memory with Status 0x%08X. Heap %p, ptr %p, base address %p\n",
                Status, Heap, Ptr, VirtualEntry);
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
        }
    }
    else
    {
        /* Normal allocation */
        // TODO: Tagging

        RtlpFreeBlockLocked(Heap, HeapEntry, TRUE);
    }

    /* Release the heap lock */
    if (Locked) RtlLeaveHeapLock(Heap->LockVariable);

    return TRUE;
}

BOOLEAN NTAPI
RtlpGrowBlockInPlace (IN PHEAP Heap,
                      IN ULONG Flags,
                      IN PHEAP_ENTRY InUseEntry,
                      IN SIZE_T Size,
                      IN SIZE_T Index)
{
    UCHAR EntryFlags, RememberFlags;
    PHEAP_FREE_ENTRY FreeEntry, UnusedEntry, FollowingEntry;
    SIZE_T FreeSize, PrevSize, TailPart, AddedSize = 0;
    PHEAP_ENTRY_EXTRA OldExtra, NewExtra;
    UCHAR SegmentOffset;

    /* We can't grow beyond specified threshold */
    if (Index > Heap->VirtualMemoryThreshold)
        return FALSE;

    /* Get entry flags */
    EntryFlags = InUseEntry->Flags;

    if (RtlpIsLastCommittedEntry(InUseEntry))
    {
        /* There is no next block, just uncommitted space. Calculate how much is needed */
        FreeSize = (Index - InUseEntry->Size) << HEAP_ENTRY_SHIFT;
        FreeSize = ROUND_UP(FreeSize, PAGE_SIZE);

        /* Find and commit those pages */
        FreeEntry = RtlpFindAndCommitPages(Heap,
                                           Heap->Segments[InUseEntry->SegmentOffset],
                                           &FreeSize,
                                           (PVOID)PAGE_ROUND_UP(InUseEntry + InUseEntry->Size));

        /* Fail if it failed... */
        if (!FreeEntry) return FALSE;

        /* It was successful, perform coalescing */
        FreeSize = FreeSize >> HEAP_ENTRY_SHIFT;
        FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &FreeSize, FALSE);

        /* Check if it's enough */
        if (FreeSize + InUseEntry->Size < Index)
        {
            /* Still not enough. RtlpInsertFreeBlock counts the block in TotalFreeSize itself */
            RtlpInsertFreeBlock(Heap, FreeEntry, FreeSize);
            return FALSE;
        }

        /* Remember flags of this free entry */
        RememberFlags = FreeEntry->Flags;

        /* Sum up sizes */
        FreeSize += InUseEntry->Size;
    }
    else
    {
        FreeEntry = (PHEAP_FREE_ENTRY)(InUseEntry + InUseEntry->Size);

        /* The next block indeed exists. Check if it's free or in use */
        if (FreeEntry->Flags & HEAP_ENTRY_BUSY) return FALSE;

        /* Next entry is free, check if it can fit the block we need */
        FreeSize = InUseEntry->Size + FreeEntry->Size;
        if (FreeSize < Index) return FALSE;

        /* Remember flags of this free entry */
        RememberFlags = FreeEntry->Flags;

        /* Remove this block from the free list */
        RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
        Heap->TotalFreeSize -= FreeEntry->Size;
    }

    PrevSize = (InUseEntry->Size << HEAP_ENTRY_SHIFT) - InUseEntry->UnusedBytes;
    FreeSize -= Index;

    /* Don't produce too small blocks */
    if (FreeSize <= 2)
    {
        Index += FreeSize;
        FreeSize = 0;
    }

    /* Process extra stuff */
    if (EntryFlags & HEAP_ENTRY_EXTRA_PRESENT)
    {
        /* Calculate pointers */
        OldExtra = (PHEAP_ENTRY_EXTRA)(InUseEntry + InUseEntry->Size - 1);
        NewExtra = (PHEAP_ENTRY_EXTRA)(InUseEntry + Index - 1);

        /* Copy contents */
        *NewExtra = *OldExtra;

        // FIXME Tagging
    }

    /* Update sizes */
    InUseEntry->Size = (USHORT)Index;
    InUseEntry->UnusedBytes = (UCHAR)((Index << HEAP_ENTRY_SHIFT) - Size);

    /* Check if there is a free space remaining after merging those blocks */
    if (!FreeSize)
    {
        /* Update flags and sizes */
        InUseEntry->Flags |= RememberFlags & HEAP_ENTRY_LAST_ENTRY;

        /* Either update previous size of the next entry or mark it as a last
           entry in the segment */
        if (!(RememberFlags & HEAP_ENTRY_LAST_ENTRY))
        {
            (InUseEntry + InUseEntry->Size)->PreviousSize = InUseEntry->Size;
        }
        else
        {
            SegmentOffset = InUseEntry->SegmentOffset;
            ASSERT(SegmentOffset < HEAP_SEGMENTS);
        }
    }
    else
    {
        /* Complex case, we need to split the block to give unused free space
           back to the heap */
        UnusedEntry = (PHEAP_FREE_ENTRY)(InUseEntry + Index);
        UnusedEntry->PreviousSize = (USHORT)Index;
        UnusedEntry->SegmentOffset = InUseEntry->SegmentOffset;

        /* Update the following block or set the last entry in the segment */
        if (RememberFlags & HEAP_ENTRY_LAST_ENTRY)
        {
            SegmentOffset = UnusedEntry->SegmentOffset;
            ASSERT(SegmentOffset < HEAP_SEGMENTS);

            /* Set flags and size */
            UnusedEntry->Flags = RememberFlags;
            UnusedEntry->Size = (USHORT)FreeSize;

            /* Insert it to the heap and update total size  */
            RtlpInsertFreeBlockHelper(Heap, UnusedEntry, FreeSize, FALSE);
            Heap->TotalFreeSize += FreeSize;
        }
        else
        {
            /* There is a block after this one  */
            FollowingEntry = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)UnusedEntry + FreeSize);

            if (FollowingEntry->Flags & HEAP_ENTRY_BUSY)
            {
                /* Update flags and set size of the unused space entry */
                UnusedEntry->Flags = RememberFlags & (~HEAP_ENTRY_LAST_ENTRY);
                UnusedEntry->Size = (USHORT)FreeSize;

                /* Update previous size of the following entry */
                FollowingEntry->PreviousSize = (USHORT)FreeSize;

                /* Insert it to the heap and update total free size */
                RtlpInsertFreeBlockHelper(Heap, UnusedEntry, FreeSize, FALSE);
                Heap->TotalFreeSize += FreeSize;
            }
            else
            {
                /* That following entry is also free, what a fortune! */
                RememberFlags = FollowingEntry->Flags;

                /* Remove it */
                RtlpRemoveFreeBlock(Heap, FollowingEntry, FALSE);
                Heap->TotalFreeSize -= FollowingEntry->Size;

                /* And make up a new combined block */
                FreeSize += FollowingEntry->Size;
                UnusedEntry->Flags = RememberFlags;

                /* Check where to put it */
                if (FreeSize <= HEAP_MAX_BLOCK_SIZE)
                {
                    /* Fine for a dedicated list */
                    UnusedEntry->Size = (USHORT)FreeSize;

                    if (!(RememberFlags & HEAP_ENTRY_LAST_ENTRY))
                    {
                        ((PHEAP_ENTRY)UnusedEntry + FreeSize)->PreviousSize = (USHORT)FreeSize;
                    }
                    else
                    {
                        SegmentOffset = UnusedEntry->SegmentOffset;
                        ASSERT(SegmentOffset < HEAP_SEGMENTS);
                    }

                    /* Insert it back and update total size */
                    RtlpInsertFreeBlockHelper(Heap, UnusedEntry, FreeSize, FALSE);
                    Heap->TotalFreeSize += FreeSize;
                }
                else
                {
                    /* The block is very large, leave all the hassle to the insertion routine */
                    RtlpInsertFreeBlock(Heap, UnusedEntry, FreeSize);
                }
            }
        }
    }

    /* Properly "zero out" (and fill!) the space */
    if (Flags & HEAP_ZERO_MEMORY)
    {
        RtlZeroMemory((PCHAR)(InUseEntry + 1) + PrevSize, Size - PrevSize);
    }
    else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED)
    {
        /* Calculate tail part which we need to fill */
        TailPart = PrevSize & (sizeof(ULONG) - 1);

        /* "Invert" it as usual */
        if (TailPart) TailPart = 4 - TailPart;

        if (Size > (PrevSize + TailPart))
            AddedSize = (Size - (PrevSize + TailPart)) & ~(sizeof(ULONG) - 1);

        if (AddedSize)
        {
            RtlFillMemoryUlong((PCHAR)(InUseEntry + 1) + PrevSize + TailPart,
                               AddedSize,
                               ARENA_INUSE_FILLER);
        }
    }

    /* Fill the new tail */
    if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED)
    {
        RtlFillMemory((PCHAR)(InUseEntry + 1) + Size,
                      HEAP_ENTRY_SIZE,
                      HEAP_TAIL_FILL);
    }

    /* Copy user settable flags */
    InUseEntry->Flags &= ~HEAP_ENTRY_SETTABLE_FLAGS;
    InUseEntry->Flags |= ((Flags & HEAP_SETTABLE_USER_FLAGS) >> 4);

    /* Return success */
    return TRUE;
}

PHEAP_ENTRY_EXTRA NTAPI
RtlpGetExtraStuffPointer(PHEAP_ENTRY HeapEntry)
{
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;

    /* Check if it's a big block */
    if (HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
    {
        VirtualEntry = CONTAINING_RECORD(HeapEntry, HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);

        /* Return a pointer to the extra stuff*/
        return &VirtualEntry->ExtraStuff;
    }
    else
    {
        /* This is a usual entry, which means extra stuff follows this block */
        return (PHEAP_ENTRY_EXTRA)(HeapEntry + HeapEntry->Size - 1);
    }
}


/***********************************************************************
 *           RtlReAllocateHeap
 * PARAMS
 *   Heap   [in] Handle of heap block
 *   Flags    [in] Heap reallocation flags
 *   Ptr,    [in] Address of memory to reallocate
 *   Size     [in] Number of bytes to reallocate
 *
 * RETURNS
 * Pointer to reallocated memory block
 * NULL: Failure
 * 0x7d030f60--invalid flags in RtlHeapAllocate
 * @implemented
 */
PVOID NTAPI
RtlReAllocateHeap(HANDLE HeapPtr,
                  ULONG Flags,
                  PVOID Ptr,
                  SIZE_T Size)
{
    PHEAP Heap = (PHEAP)HeapPtr;
    PHEAP_ENTRY InUseEntry, NewInUseEntry;
    PHEAP_ENTRY_EXTRA OldExtra, NewExtra;
    SIZE_T AllocationSize, FreeSize, DecommitSize;
    BOOLEAN HeapLocked = FALSE;
    PVOID NewBaseAddress;
    PHEAP_FREE_ENTRY SplitBlock, SplitBlock2;
    SIZE_T OldSize, Index, OldIndex;
    UCHAR FreeFlags;
    NTSTATUS Status;
    PVOID DecommitBase;
    SIZE_T RemainderBytes, ExtraSize;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualAllocBlock;
    EXCEPTION_RECORD ExceptionRecord;
    UCHAR SegmentOffset;
    SIZE_T OldCounted;

    /* Return success in case of a null pointer */
    if (!Ptr)
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_SUCCESS);
        return NULL;
    }

    /* Force heap flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugReAllocateHeap(Heap, Flags, Ptr, Size);

    /* Make sure size is valid */
    if (Size >= 0x80000000)
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);
        return NULL;
    }

    /* Calculate allocation size and index */
    if (Size)
        AllocationSize = Size;
    else
        AllocationSize = 1;
    AllocationSize = (AllocationSize + Heap->AlignRound) & Heap->AlignMask;

    /* Add up extra stuff, if it is present anywhere */
    if (((((PHEAP_ENTRY)Ptr)-1)->Flags & HEAP_ENTRY_EXTRA_PRESENT) ||
        (Flags & HEAP_EXTRA_FLAGS_MASK) ||
        Heap->PseudoTagEntries)
    {
        AllocationSize += sizeof(HEAP_ENTRY_EXTRA);
    }

    /* Acquire the lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        HeapLocked = TRUE;
        /* Do not acquire the lock anymore for re-entrant call */
        Flags |= HEAP_NO_SERIALIZE;
    }

    /* Get the pointer to the in-use entry */
    InUseEntry = (PHEAP_ENTRY)Ptr - 1;

    /* If that entry is not really in-use, we have a problem */
    if (!(InUseEntry->Flags & HEAP_ENTRY_BUSY) ||
        (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE && RtlpHeapFeIsCached(InUseEntry)))
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);

        /* Release the lock and return */
        if (HeapLocked)
            RtlLeaveHeapLock(Heap->LockVariable);
        return Ptr;
    }

    if (InUseEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
    {
        /* This is a virtually allocated block. Get its size */
        OldSize = RtlpGetSizeOfBigBlock(InUseEntry);

        /* Convert it to an index */
        OldIndex = (OldSize + InUseEntry->Size) >> HEAP_ENTRY_SHIFT;

        /* Calculate new allocation size and round it to the page size */
        AllocationSize += FIELD_OFFSET(HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);
        AllocationSize = ROUND_UP(AllocationSize, PAGE_SIZE);
    }
    else
    {
        /* Usual entry */
        OldIndex = InUseEntry->Size;

        OldSize = (OldIndex << HEAP_ENTRY_SHIFT) - InUseEntry->UnusedBytes;
    }

    /* The class the block is counted under for the front end's activation, if any */
    OldCounted = 0;
    if (Heap->FrontEndHeapType == 0 && Heap->FeAct > HEAP_FE_ACT_OFF &&
        !(InUseEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC))
    {
        OldCounted = RtlpHeapFeCountedIndex(Heap, InUseEntry);
    }

    /* Calculate new index */
    Index = AllocationSize >> HEAP_ENTRY_SHIFT;

    /* Check for 4 different scenarios (old size, new size, old index, new index) */
    if (Index <= OldIndex)
    {
        /* Difference must be greater than 1, adjust if it's not so */
        if (Index + 1 == OldIndex)
        {
            Index++;
            AllocationSize += sizeof(HEAP_ENTRY);
        }

        /* Calculate new size */
        if (InUseEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
        {
            /* Simple in case of a virtual alloc - just an unused size */
            InUseEntry->Size = (USHORT)(AllocationSize - Size);
            ASSERT(InUseEntry->Size >= sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));
        }
        else if (InUseEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
        {
            /* There is extra stuff, take it into account */
            OldExtra = (PHEAP_ENTRY_EXTRA)(InUseEntry + InUseEntry->Size - 1);
            NewExtra = (PHEAP_ENTRY_EXTRA)(InUseEntry + Index - 1);
            *NewExtra = *OldExtra;

            // FIXME Tagging, TagIndex

            /* Update unused bytes count */
            InUseEntry->UnusedBytes = (UCHAR)(AllocationSize - Size);
        }
        else
        {
            // FIXME Tagging, SmallTagIndex
            InUseEntry->UnusedBytes = (UCHAR)(AllocationSize - Size);
        }

        /* If new size is bigger than the old size */
        if (Size > OldSize)
        {
            /* Zero out that additional space if required */
            if (Flags & HEAP_ZERO_MEMORY)
            {
                RtlZeroMemory((PCHAR)Ptr + OldSize, Size - OldSize);
            }
            else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED)
            {
                /* Fill it on free if required */
                RemainderBytes = OldSize & (sizeof(ULONG) - 1);

                if (RemainderBytes)
                    RemainderBytes = 4 - RemainderBytes;

                if (Size > (OldSize + RemainderBytes))
                {
                    /* Calculate actual amount of extra bytes to fill */
                    ExtraSize = (Size - (OldSize + RemainderBytes)) & ~(sizeof(ULONG) - 1);

                    /* Fill them if there are any */
                    if (ExtraSize != 0)
                    {
                        RtlFillMemoryUlong((PCHAR)(InUseEntry + 1) + OldSize + RemainderBytes,
                                           ExtraSize,
                                           ARENA_INUSE_FILLER);
                    }
                }
            }
        }

        /* Fill tail of the heap entry if required */
        if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED)
        {
            RtlFillMemory((PCHAR)(InUseEntry + 1) + Size,
                          HEAP_ENTRY_SIZE,
                          HEAP_TAIL_FILL);
        }

        /* Check if the difference is significant or not */
        if (Index != OldIndex)
        {
            /* Save flags */
            FreeFlags = InUseEntry->Flags & ~HEAP_ENTRY_BUSY;

            if (FreeFlags & HEAP_ENTRY_VIRTUAL_ALLOC)
            {
                /* This is a virtual block allocation */
                VirtualAllocBlock = CONTAINING_RECORD(InUseEntry, HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);

                // FIXME Tagging!

                DecommitBase = (PCHAR)VirtualAllocBlock + AllocationSize;
                DecommitSize = (OldIndex << HEAP_ENTRY_SHIFT) - AllocationSize;

                /* Release the memory */
                Status = ZwFreeVirtualMemory(NtCurrentProcess(),
                                             (PVOID *)&DecommitBase,
                                             &DecommitSize,
                                             MEM_RELEASE);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("HEAP: Unable to release memory (pointer %p, size 0x%x), Status %08x\n", DecommitBase, DecommitSize, Status);
                }
                else
                {
                    /* Otherwise reduce the commit size */
                    VirtualAllocBlock->CommitSize -= DecommitSize;
                }
            }
            else
            {
                /* Reduce size of the block and possibly split it */
                SplitBlock = (PHEAP_FREE_ENTRY)(InUseEntry + Index);

                /* Initialize this entry */
                SplitBlock->Flags = FreeFlags;
                SplitBlock->PreviousSize = (USHORT)Index;
                SplitBlock->SegmentOffset = InUseEntry->SegmentOffset;

                /* Remember free size */
                FreeSize = InUseEntry->Size - Index;

                /* Set new size */
                InUseEntry->Size = (USHORT)Index;
                InUseEntry->Flags &= ~HEAP_ENTRY_LAST_ENTRY;

                /* Is that the last entry */
                if (FreeFlags & HEAP_ENTRY_LAST_ENTRY)
                {
                    SegmentOffset = SplitBlock->SegmentOffset;
                    ASSERT(SegmentOffset < HEAP_SEGMENTS);

                    /* Set its size and insert it to the list */
                    SplitBlock->Size = (USHORT)FreeSize;
                    RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);

                    /* Update total free size */
                    Heap->TotalFreeSize += FreeSize;
                }
                else
                {
                    /* Get the block after that one */
                    SplitBlock2 = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize);

                    if (SplitBlock2->Flags & HEAP_ENTRY_BUSY)
                    {
                        /* It's in use, add it here*/
                        SplitBlock->Size = (USHORT)FreeSize;

                        /* Update previous size of the next entry */
                        ((PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize))->PreviousSize = (USHORT)FreeSize;

                        /* Insert it to the list */
                        RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);

                        /* Update total size */
                        Heap->TotalFreeSize += FreeSize;
                    }
                    else
                    {
                        /* Next entry is free, so merge with it */
                        SplitBlock->Flags = SplitBlock2->Flags;

                        /* Remove it, update total size */
                        RtlpRemoveFreeBlock(Heap, SplitBlock2, FALSE);
                        Heap->TotalFreeSize -= SplitBlock2->Size;

                        /* Calculate total free size */
                        FreeSize += SplitBlock2->Size;

                        if (FreeSize <= HEAP_MAX_BLOCK_SIZE)
                        {
                            SplitBlock->Size = (USHORT)FreeSize;

                            if (!(SplitBlock->Flags & HEAP_ENTRY_LAST_ENTRY))
                            {
                                /* Update previous size of the next entry */
                                ((PHEAP_FREE_ENTRY)((PHEAP_ENTRY)SplitBlock + FreeSize))->PreviousSize = (USHORT)FreeSize;
                            }
                            else
                            {
                                SegmentOffset = SplitBlock->SegmentOffset;
                                ASSERT(SegmentOffset < HEAP_SEGMENTS);
                            }

                            /* Insert the new one back and update total size */
                            RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);
                            Heap->TotalFreeSize += FreeSize;
                        }
                        else
                        {
                            /* Just add it */
                            RtlpInsertFreeBlock(Heap, SplitBlock, FreeSize);
                        }
                    }
                }
            }
        }
    }
    else
    {
        /* We're growing the block */
        if ((InUseEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC) ||
            !RtlpGrowBlockInPlace(Heap, Flags, InUseEntry, Size, Index))
        {
            /* Growing in place failed, so growing out of place */
            if (Flags & HEAP_REALLOC_IN_PLACE_ONLY)
            {
                DPRINT1("Realloc in place failed, but it was the only option\n");
                Ptr = NULL;
            }
            else
            {
                /* Clear tag bits */
                Flags &= ~HEAP_TAG_MASK;

                /* Process extra stuff */
                if (InUseEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
                {
                    /* Preserve user settable flags */
                    Flags &= ~HEAP_SETTABLE_USER_FLAGS;

                    Flags |= HEAP_SETTABLE_USER_VALUE | ((InUseEntry->Flags & HEAP_ENTRY_SETTABLE_FLAGS) << 4);

                    /* Get pointer to the old extra data */
                    OldExtra = RtlpGetExtraStuffPointer(InUseEntry);

                    /* Save tag index if it was set */
                    if (OldExtra->TagIndex &&
                        !(OldExtra->TagIndex & HEAP_PSEUDO_TAG_FLAG))
                    {
                        Flags |= OldExtra->TagIndex << HEAP_TAG_SHIFT;
                    }
                }
                else if (InUseEntry->SmallTagIndex)
                {
                    /* Take small tag index into account */
                    Flags |= InUseEntry->SmallTagIndex << HEAP_TAG_SHIFT;
                }

                /* Allocate new block from the heap */
                NewBaseAddress = RtlAllocateHeap(HeapPtr,
                                                 Flags & ~HEAP_ZERO_MEMORY,
                                                 Size);

                /* Proceed if it didn't fail */
                if (NewBaseAddress)
                {
                    /* Get new entry pointer */
                    NewInUseEntry = (PHEAP_ENTRY)NewBaseAddress - 1;

                    /* Process extra stuff if it exists */
                    if (NewInUseEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
                    {
                        NewExtra = RtlpGetExtraStuffPointer(NewInUseEntry);

                        if (InUseEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
                        {
                            OldExtra = RtlpGetExtraStuffPointer(InUseEntry);
                            NewExtra->Settable = OldExtra->Settable;
                        }
                        else
                        {
                            RtlZeroMemory(NewExtra, sizeof(*NewExtra));
                        }
                    }

                    /* Copy actual user bits */
                    if (Size < OldSize)
                        RtlMoveMemory(NewBaseAddress, Ptr, Size);
                    else
                        RtlMoveMemory(NewBaseAddress, Ptr, OldSize);

                    /* Zero remaining part if required */
                    if (Size > OldSize &&
                        (Flags & HEAP_ZERO_MEMORY))
                    {
                        RtlZeroMemory((PCHAR)NewBaseAddress + OldSize, Size - OldSize);
                    }

                    /* Free the old block */
                    RtlFreeHeap(HeapPtr, Flags, Ptr);
                }

                Ptr = NewBaseAddress;
            }
        }
    }

    /* A block resized in place changes its size class (a block that moved was counted by the allocation and
       the free of the move) */
    if (OldCounted && Ptr == (PVOID)(InUseEntry + 1))
        RtlpHeapFeCountResized(Heap, OldCounted, RtlpHeapFeCountedIndex(Heap, InUseEntry));

    /* Did resizing fail? */
    if (!Ptr && (Flags & HEAP_GENERATE_EXCEPTIONS))
    {
        /* Generate an exception if required */
        ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
        ExceptionRecord.ExceptionRecord = NULL;
        ExceptionRecord.NumberParameters = 1;
        ExceptionRecord.ExceptionFlags = 0;
        ExceptionRecord.ExceptionInformation[0] = AllocationSize;

        RtlRaiseException(&ExceptionRecord);
    }

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
        RtlLeaveHeapLock(Heap->LockVariable);

    return Ptr;
}


/* Merges every free block with the free blocks next to it. A heap with HEAP_DISABLE_COALESCE_ON_FREE, or one whose
   blocks outgrew what a free block can describe, can hold neighbours that were never merged. The heap lock is held. */
static VOID
RtlpHeapCoalesceAll(PHEAP Heap)
{
    PLIST_ENTRY ListEntry = Heap->FreeLists.Flink;

    while (ListEntry != &Heap->FreeLists)
    {
        PHEAP_FREE_ENTRY Entry = CONTAINING_RECORD(ListEntry, HEAP_FREE_ENTRY, FreeList);
        PLIST_ENTRY Next = ListEntry->Flink;
        SIZE_T OldSize = Entry->Size, NewSize = OldSize;
        PHEAP_FREE_ENTRY Merged;

        /* Takes the block and its neighbours out of the lists only when it merges them */
        Merged = RtlpCoalesceFreeBlocks(Heap, Entry, &NewSize, TRUE);
        if (Merged != Entry || NewSize != OldSize)
        {
            RtlpInsertFreeBlock(Heap, Merged, NewSize);

            /* The block that came next in the list may be one that was merged: look from the start */
            if (Next != &Heap->FreeLists &&
                (PUCHAR)Next >= (PUCHAR)Merged &&
                (PUCHAR)Next < (PUCHAR)Merged + (NewSize << HEAP_ENTRY_SHIFT))
            {
                Next = Heap->FreeLists.Flink;
            }
        }

        ListEntry = Next;
    }
}

/***********************************************************************
 *           RtlCompactHeap
 * Coalesces the free blocks of a heap, gives the memory it does not need back to the system and returns the
 * size of the largest free block.
 *
 * PARAMS
 *   Heap   [in] Handle of heap
 *   Flags  [in] HEAP_NO_SERIALIZE: the caller makes sure no other thread uses the heap
 *
 * RETURNS
 * The size in bytes of the largest free block the heap had after the free blocks were merged. 0 when the heap
 * is not a heap or has no free block.
 *
 * NOTES
 * The blocks the front end parked are given back first. Free pages the heap kept committed as a cache are given back
 * down to DeCommitTotalFreeThreshold (user mode only). The size is that of the largest block before the pages were
 * given back: allocating it needs no more than the commit of the pages that were.
 *
 * @implemented
 */
ULONG NTAPI
RtlCompactHeap(HANDLE HeapPtr,
               ULONG Flags)
{
    PHEAP Heap = (PHEAP)HeapPtr;
    SIZE_T Largest = 0;
    BOOLEAN Locked = FALSE;

    /* A page heap keeps no free blocks of its own */
    if (!Heap || (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS))
        return 0;

    if (Heap->Signature != HEAP_SIGNATURE)
        return 0;

    Flags |= Heap->ForceFlags;

    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        Locked = TRUE;
    }

    /* Keeps the front end out while the blocks it parked are given back; does nothing without one */
    RtlpHeapFeLock(Heap);

    RtlpHeapCoalesceAll(Heap);

    /* The list is sorted by size */
    if (!IsListEmpty(&Heap->FreeLists))
        Largest = CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY, FreeList)->Size;

    if (RtlpGetMode() == UserMode &&
        Heap->TotalFreeSize > Heap->DeCommitTotalFreeThreshold)
    {
        RtlpHeapTrim(Heap, Heap->DeCommitTotalFreeThreshold, MAXULONG);
    }

    RtlpHeapFeUnlock(Heap);

    if (Locked)
        RtlLeaveHeapLock(Heap->LockVariable);

    return (ULONG)(Largest << HEAP_ENTRY_SHIFT);
}


/***********************************************************************
 *           RtlLockHeap
 * Attempts to acquire the critical section object for a specified heap.
 *
 * PARAMS
 *   Heap  [in] Handle of heap to lock for exclusive access
 *
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN NTAPI
RtlLockHeap(IN HANDLE HeapPtr)
{
    PHEAP Heap = (PHEAP)HeapPtr;

    /* Check for page heap */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS)
    {
        return RtlpPageHeapLock(Heap);
    }

    /* Check if it's really a heap */
    if (Heap->Signature != HEAP_SIGNATURE) return FALSE;

    /* Lock if it's lockable */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);

        /* The holder of the lock excludes all allocations, so keep the front end out of it */
        RtlpHeapFeLock(Heap);
    }

    return TRUE;
}


/***********************************************************************
 *           RtlUnlockHeap
 * Releases ownership of the critical section object.
 *
 * PARAMS
 *   Heap  [in] Handle to the heap to unlock
 *
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN NTAPI
RtlUnlockHeap(HANDLE HeapPtr)
{
    PHEAP Heap = (PHEAP)HeapPtr;

    /* Check for page heap */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS)
    {
        return RtlpPageHeapUnlock(Heap);
    }

    /* Check if it's really a heap */
    if (Heap->Signature != HEAP_SIGNATURE) return FALSE;

    /* Unlock if it's lockable */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE))
    {
        RtlpHeapFeUnlock(Heap);
        RtlLeaveHeapLock(Heap->LockVariable);
    }

    return TRUE;
}


/***********************************************************************
 *           RtlSizeHeap
 * PARAMS
 *   Heap  [in] Handle of heap
 *   Flags   [in] Heap size control flags
 *   Ptr     [in] Address of memory to return size for
 *
 * RETURNS
 * Size in bytes of allocated memory
 * 0xffffffff: Failure
 *
 * @implemented
 */
SIZE_T NTAPI
RtlSizeHeap(
   HANDLE HeapPtr,
   ULONG Flags,
   PVOID Ptr
)
{
    PHEAP Heap = (PHEAP)HeapPtr;
    PHEAP_ENTRY HeapEntry;
    SIZE_T EntrySize;

    // FIXME This is a hack around missing SEH support!
    if (!Heap)
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_HANDLE);
        return (SIZE_T)-1;
    }

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugSizeHeap(Heap, Flags, Ptr);

    /* Get the heap entry pointer */
    HeapEntry = (PHEAP_ENTRY)Ptr - 1;

    /* Return -1 if that entry is free (a block parked in the front end is free for the caller) */
    if (!(HeapEntry->Flags & HEAP_ENTRY_BUSY) ||
        (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE && RtlpHeapFeIsCached(HeapEntry)))
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
        return (SIZE_T)-1;
    }

    /* Get size of this block depending if it's a usual or a big one */
    if (HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
    {
        EntrySize = RtlpGetSizeOfBigBlock(HeapEntry);
    }
    else
    {
        /* Calculate it */
        EntrySize = (HeapEntry->Size << HEAP_ENTRY_SHIFT) - HeapEntry->UnusedBytes;
    }

    /* Return calculated size */
    return EntrySize;
}

BOOLEAN NTAPI
RtlpCheckInUsePattern(PHEAP_ENTRY HeapEntry)
{
    SIZE_T Size, Result;
    PCHAR TailPart;

    /* Calculate size */
    if (HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
        Size = RtlpGetSizeOfBigBlock(HeapEntry);
    else
        Size = (HeapEntry->Size << HEAP_ENTRY_SHIFT) - HeapEntry->UnusedBytes;

    /* Calculate pointer to the tail part of the block */
    TailPart = (PCHAR)(HeapEntry + 1) + Size;

    /* Compare tail pattern */
    Result = RtlCompareMemory(TailPart,
                              FillPattern,
                              HEAP_ENTRY_SIZE);

    if (Result != HEAP_ENTRY_SIZE)
    {
        DPRINT1("HEAP: Heap entry (size %x) %p tail is modified at %p\n", Size, HeapEntry, TailPart + Result);
        return FALSE;
    }

    /* All is fine */
    return TRUE;
}

BOOLEAN NTAPI
RtlpValidateHeapHeaders(
    PHEAP Heap,
    BOOLEAN Recalculate)
{
    // We skip header validation for now
    return TRUE;
}

BOOLEAN NTAPI
RtlpValidateHeapEntry(
    PHEAP Heap,
    PHEAP_ENTRY HeapEntry)
{
    BOOLEAN BigAllocation, EntryFound = FALSE;
    PHEAP_SEGMENT Segment;
    ULONG SegmentOffset;

    /* Perform various consistency checks of this entry */
    if (!HeapEntry) goto invalid_entry;
    if ((ULONG_PTR)HeapEntry & (HEAP_ENTRY_SIZE - 1)) goto invalid_entry;
    if (!(HeapEntry->Flags & HEAP_ENTRY_BUSY)) goto invalid_entry;
    if (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE && RtlpHeapFeIsCached(HeapEntry)) goto invalid_entry;

    BigAllocation = HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC;
    Segment = Heap->Segments[HeapEntry->SegmentOffset];

    if (BigAllocation &&
        (((ULONG_PTR)HeapEntry & (PAGE_SIZE - 1)) != FIELD_OFFSET(HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock)))
         goto invalid_entry;

    if (!BigAllocation && (HeapEntry->SegmentOffset >= HEAP_SEGMENTS ||
        !Segment ||
        HeapEntry < Segment->FirstEntry ||
        HeapEntry >= Segment->LastValidEntry))
        goto invalid_entry;

    if ((HeapEntry->Flags & HEAP_ENTRY_FILL_PATTERN) &&
        !RtlpCheckInUsePattern(HeapEntry))
        goto invalid_entry;

    /* Checks are done, if this is a virtual entry, that's all */
    if (HeapEntry->Flags & HEAP_ENTRY_VIRTUAL_ALLOC) return TRUE;

    /* Go through segments and check if this entry fits into any of them */
    for (SegmentOffset = 0; SegmentOffset < HEAP_SEGMENTS; SegmentOffset++)
    {
        Segment = Heap->Segments[SegmentOffset];
        if (!Segment) continue;

        if ((HeapEntry >= Segment->FirstEntry) &&
            (HeapEntry < Segment->LastValidEntry))
        {
            /* Got it */
            EntryFound = TRUE;
            break;
        }
    }

    /* Return our result of finding entry in the segments */
    return EntryFound;

invalid_entry:
    DPRINT1("HEAP: Invalid heap entry %p in heap %p\n", HeapEntry, Heap);
    return FALSE;
}

BOOLEAN NTAPI
RtlpValidateHeapSegment(
    PHEAP Heap,
    PHEAP_SEGMENT Segment,
    UCHAR SegmentOffset,
    PULONG FreeEntriesCount,
    PSIZE_T TotalFreeSize,
    PSIZE_T TagEntries,
    PSIZE_T PseudoTagEntries)
{
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    PLIST_ENTRY UcrEntry;
    SIZE_T ByteSize, Size, Result;
    PHEAP_ENTRY CurrentEntry;
    ULONG UnCommittedPages;
    ULONG UnCommittedRanges;
    ULONG PreviousSize;

    UnCommittedPages = 0;
    UnCommittedRanges = 0;

    if (IsListEmpty(&Segment->UCRSegmentList))
    {
        UcrEntry = NULL;
        UcrDescriptor = NULL;
    }
    else
    {
        UcrEntry = Segment->UCRSegmentList.Flink;
        UcrDescriptor = CONTAINING_RECORD(UcrEntry, HEAP_UCR_DESCRIPTOR, SegmentEntry);
    }

    if (Segment->BaseAddress == Heap)
        CurrentEntry = &Heap->Entry;
    else
        CurrentEntry = &Segment->Entry;

    while (CurrentEntry < Segment->LastValidEntry)
    {
        if (UcrDescriptor &&
            ((PVOID)CurrentEntry >= UcrDescriptor->Address))
        {
            DPRINT1("HEAP: Entry %p is not inside uncommited range [%p .. %p)\n",
                    CurrentEntry, UcrDescriptor->Address,
                    (PCHAR)UcrDescriptor->Address + UcrDescriptor->Size);

            return FALSE;
        }

        PreviousSize = 0;

        while (CurrentEntry < Segment->LastValidEntry)
        {
            if (PreviousSize != CurrentEntry->PreviousSize)
            {
                DPRINT1("HEAP: Entry %p has incorrect PreviousSize %x instead of %x\n",
                    CurrentEntry, CurrentEntry->PreviousSize, PreviousSize);

                return FALSE;
            }

            PreviousSize = CurrentEntry->Size;
            Size = CurrentEntry->Size << HEAP_ENTRY_SHIFT;

            if (CurrentEntry->Flags & HEAP_ENTRY_BUSY)
            {
                if (TagEntries)
                {
                    UNIMPLEMENTED;
                }

                /* Check fill pattern */
                if (CurrentEntry->Flags & HEAP_ENTRY_FILL_PATTERN)
                {
                    if (!RtlpCheckInUsePattern(CurrentEntry))
                        return FALSE;
                }
            }
            else
            {
                /* The entry is free, increase free entries count and total free size */
                *FreeEntriesCount = *FreeEntriesCount + 1;
                *TotalFreeSize += CurrentEntry->Size;

                if ((Heap->Flags & HEAP_FREE_CHECKING_ENABLED) &&
                    (CurrentEntry->Flags & HEAP_ENTRY_FILL_PATTERN))
                {
                    ByteSize = Size - sizeof(HEAP_FREE_ENTRY);

                    if ((CurrentEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT) &&
                        (ByteSize > sizeof(HEAP_FREE_ENTRY_EXTRA)))
                    {
                        ByteSize -= sizeof(HEAP_FREE_ENTRY_EXTRA);
                    }

                    Result = RtlCompareMemoryUlong((PCHAR)((PHEAP_FREE_ENTRY)CurrentEntry + 1),
                                                    ByteSize,
                                                    ARENA_FREE_FILLER);

                    if (Result != ByteSize)
                    {
                        DPRINT1("HEAP: Free heap block %p modified at %p after it was freed\n",
                            CurrentEntry,
                            (PCHAR)(CurrentEntry + 1) + Result);

                        return FALSE;
                    }
                }
            }

            if (CurrentEntry->SegmentOffset != SegmentOffset)
            {
                DPRINT1("HEAP: Heap entry %p SegmentOffset is incorrect %x (should be %x)\n",
                        CurrentEntry, SegmentOffset, CurrentEntry->SegmentOffset);
                return FALSE;
            }

            /* Check if it's the last entry */
            if (CurrentEntry->Flags & HEAP_ENTRY_LAST_ENTRY)
            {
                CurrentEntry = (PHEAP_ENTRY)((PCHAR)CurrentEntry + Size);

                /* RtlpDeCommitFreeBlock can leave two one-unit guard entries before an uncommitted
                   range, when only two units are left in front of it: both are marked as last */
                if (UcrDescriptor &&
                    Size == HEAP_ENTRY_SIZE &&
                    (PVOID)CurrentEntry != UcrDescriptor->Address &&
                    (PVOID)(CurrentEntry + 1) == UcrDescriptor->Address &&
                    CurrentEntry->Size == 1 &&
                    CurrentEntry->Flags == (HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY) &&
                    CurrentEntry->PreviousSize == 1 &&
                    CurrentEntry->SegmentOffset == SegmentOffset)
                {
                    CurrentEntry++;
                }

                if (!UcrDescriptor)
                {
                    /* Check if it's not really the last one */
                    if (CurrentEntry != Segment->LastValidEntry)
                    {
                        DPRINT1("HEAP: Heap entry %p is not last block in segment (%p)\n",
                                CurrentEntry, Segment->LastValidEntry);
                        return FALSE;
                    }
                }
                else if (CurrentEntry != UcrDescriptor->Address)
                {
                    DPRINT1("HEAP: Heap entry %p does not match next uncommitted address (%p)\n",
                        CurrentEntry, UcrDescriptor->Address);

                    return FALSE;
                }
                else
                {
                    UnCommittedPages += (ULONG)(UcrDescriptor->Size / PAGE_SIZE);
                    UnCommittedRanges++;

                    CurrentEntry = (PHEAP_ENTRY)((PCHAR)UcrDescriptor->Address + UcrDescriptor->Size);

                    /* Go to the next UCR descriptor */
                    UcrEntry = UcrEntry->Flink;
                    if (UcrEntry == &Segment->UCRSegmentList)
                    {
                        UcrEntry = NULL;
                        UcrDescriptor = NULL;
                    }
                    else
                    {
                        UcrDescriptor = CONTAINING_RECORD(UcrEntry, HEAP_UCR_DESCRIPTOR, SegmentEntry);
                    }
                }

                break;
            }

            /* Advance to the next entry */
            CurrentEntry = (PHEAP_ENTRY)((PCHAR)CurrentEntry + Size);
        }
    }

    /* Check total numbers of UCP and UCR */
    if (Segment->NumberOfUnCommittedPages != UnCommittedPages)
    {
        DPRINT1("HEAP: Segment %p NumberOfUnCommittedPages is invalid (%x != %x)\n",
            Segment, Segment->NumberOfUnCommittedPages, UnCommittedPages);

        return FALSE;
    }

    if (Segment->NumberOfUnCommittedRanges != UnCommittedRanges)
    {
        DPRINT1("HEAP: Segment %p NumberOfUnCommittedRanges is invalid (%x != %x)\n",
            Segment, Segment->NumberOfUnCommittedRanges, UnCommittedRanges);

        return FALSE;
    }

    return TRUE;
}

BOOLEAN NTAPI
RtlpValidateHeap(PHEAP Heap,
                 BOOLEAN ForceValidation)
{
    UCHAR SegmentOffset;
    SIZE_T TotalFreeSize;
    PLIST_ENTRY ListHead, NextEntry;
    ULONG FreeBlocksCount, FreeListEntriesCount;
    ULONG HintIndex;

    /* Check headers */
    if (!RtlpValidateHeapHeaders(Heap, FALSE))
        return FALSE;

    /* Skip validation if it's not needed */
    if (!ForceValidation && !(Heap->Flags & HEAP_VALIDATE_ALL_ENABLED))
        return TRUE;

    /* Check free list */
    FreeListEntriesCount = 0;
    ListHead = &Heap->FreeLists;
    NextEntry = ListHead->Flink;

    while (NextEntry != ListHead)
    {
        PHEAP_FREE_ENTRY FreeEntry = CONTAINING_RECORD(NextEntry, HEAP_FREE_ENTRY, FreeList);

        NextEntry = NextEntry->Flink;

        if (NextEntry != ListHead)
        {
            PHEAP_FREE_ENTRY NextFreeEntry = CONTAINING_RECORD(NextEntry, HEAP_FREE_ENTRY, FreeList);
            /* Free entries must be sorted */
            if (FreeEntry->Size > NextFreeEntry->Size)
            {
                DPRINT1("Dedicated free entry %p of size %ld is not put in order.\n", FreeEntry, FreeEntry->Size);
            }
        }

        /* Check that the hint is there */
        if (FreeEntry->Size > Heap->DeCommitFreeBlockThreshold)
        {
            if (Heap->FreeHints[0] == NULL)
            {
                DPRINT1("No hint pointing to the non-dedicated list although there is a free entry %p of size %ld.\n",
                        FreeEntry, FreeEntry->Size);
            }
            if (!RtlTestBit(&Heap->FreeHintBitmap, 0))
            {
                DPRINT1("Hint bit 0 is not set although there is a free entry %p of size %ld.\n",
                        FreeEntry, FreeEntry->Size);
            }
        }
        else
        {
            if (Heap->FreeHints[FreeEntry->Size - 1] == NULL)
            {
                DPRINT1("No hint pointing to the dedicated list although there is a free entry %p of size %ld.\n",
                        FreeEntry, FreeEntry->Size);
            }
            if (!RtlTestBit(&Heap->FreeHintBitmap, FreeEntry->Size - 1))
            {
                DPRINT1("Hint bit 0 is not set although there is a free entry %p of size %ld.\n",
                        FreeEntry, FreeEntry->Size);
            }
        }

        /* If there is an in-use entry in a free list - that's quite a big problem */
        if (FreeEntry->Flags & HEAP_ENTRY_BUSY)
        {
            DPRINT1("HEAP: Free element %p is marked in-use\n", FreeEntry);
            return FALSE;
        }

        /* Add up to the total amount of free entries */
        FreeListEntriesCount++;
    }

    /* Check free list hints */
    for (HintIndex = 0; HintIndex < Heap->DeCommitFreeBlockThreshold; HintIndex++)
    {
        if (Heap->FreeHints[HintIndex] != NULL)
        {
            PHEAP_FREE_ENTRY FreeEntry = CONTAINING_RECORD(Heap->FreeHints[HintIndex], HEAP_FREE_ENTRY, FreeList);

            if (!RtlTestBit(&Heap->FreeHintBitmap, HintIndex))
            {
                DPRINT1("Hint bitmap bit at %u is not set, but there is a hint entry.\n", HintIndex);
            }

            if (HintIndex == 0)
            {
                 if (FreeEntry->Size <= Heap->DeCommitFreeBlockThreshold)
                 {
                     DPRINT1("There is an entry %p of size %lu, smaller than the decommit threshold %lu in the non-dedicated free list hint.\n",
                             FreeEntry, FreeEntry->Size, Heap->DeCommitFreeBlockThreshold);
                 }
            }
            else
            {
                if (HintIndex != FreeEntry->Size - 1)
                {
                    DPRINT1("There is an entry %p of size %lu at the position %u in the free entry hint array.\n",
                             FreeEntry, FreeEntry->Size, HintIndex);
                }

                if (FreeEntry->FreeList.Blink != &Heap->FreeLists)
                {
                    /* The entry right before the hint must be smaller. */
                    PHEAP_FREE_ENTRY PreviousFreeEntry = CONTAINING_RECORD(FreeEntry->FreeList.Blink,
                                                                           HEAP_FREE_ENTRY,
                                                                           FreeList);
                    if (PreviousFreeEntry->Size >= FreeEntry->Size)
                    {
                        DPRINT1("Free entry hint %p of size %lu is larger than the entry before it %p, which is of size %lu.\n",
                                FreeEntry, FreeEntry->Size, PreviousFreeEntry, PreviousFreeEntry->Size);
                    }
                }
            }
        }
        else if (RtlTestBit(&Heap->FreeHintBitmap, HintIndex))
        {
            DPRINT1("Hint bitmap bit at %u is set, but there is no hint entry.\n", HintIndex);
        }
    }

    /* Check big allocations */
    ListHead = &Heap->VirtualAllocdBlocks;
    NextEntry = ListHead->Flink;

    while (ListHead != NextEntry)
    {
        PHEAP_VIRTUAL_ALLOC_ENTRY VirtualAllocBlock = CONTAINING_RECORD(NextEntry, HEAP_VIRTUAL_ALLOC_ENTRY, Entry);

        /* We can only check the fill pattern */
        if (VirtualAllocBlock->BusyBlock.Flags & HEAP_ENTRY_FILL_PATTERN)
        {
            if (!RtlpCheckInUsePattern(&VirtualAllocBlock->BusyBlock))
                return FALSE;
        }

        NextEntry = NextEntry->Flink;
    }

    /* Check all segments */
    FreeBlocksCount = 0;
    TotalFreeSize = 0;

    for (SegmentOffset = 0; SegmentOffset < HEAP_SEGMENTS; SegmentOffset++)
    {
        PHEAP_SEGMENT Segment = Heap->Segments[SegmentOffset];

        /* Go to the next one if there is no segment */
        if (!Segment) continue;

        if (!RtlpValidateHeapSegment(Heap,
                                     Segment,
                                     SegmentOffset,
                                     &FreeBlocksCount,
                                     &TotalFreeSize,
                                     NULL,
                                     NULL))
        {
            return FALSE;
        }
    }

    if (FreeListEntriesCount != FreeBlocksCount)
    {
        DPRINT1("HEAP: Free blocks count in arena (%lu) does not match free blocks number in the free lists (%lu)\n", FreeBlocksCount, FreeListEntriesCount);
        return FALSE;
    }

    if (Heap->TotalFreeSize != TotalFreeSize)
    {
        DPRINT1("HEAP: Total size of free blocks in arena (%Iu) does not equal to the one in heap header (%Iu)\n", TotalFreeSize, Heap->TotalFreeSize);
        return FALSE;
    }

    return TRUE;
}

/***********************************************************************
 *           RtlValidateHeap
 * Validates a specified heap.
 *
 * PARAMS
 *   Heap  [in] Handle to the heap
 *   Flags   [in] Bit flags that control access during operation
 *   Block  [in] Optional pointer to memory block to validate
 *
 * NOTES
 * Flags is ignored.
 *
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN NTAPI RtlValidateHeap(
   HANDLE HeapPtr,
   ULONG Flags,
   PVOID Block
)
{
    PHEAP Heap = (PHEAP)HeapPtr;
    BOOLEAN HeapLocked = FALSE;
    BOOLEAN HeapValid;

    /* Check for page heap */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS)
        return RtlpDebugPageHeapValidate(HeapPtr, Flags, Block);

    /* Check signature */
    if (Heap->Signature != HEAP_SIGNATURE)
    {
        DPRINT1("HEAP: Signature %lx is invalid for heap %p\n", Heap->Signature, Heap);
        return FALSE;
    }

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Acquire the lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        HeapLocked = TRUE;
    }

    /* Either validate whole heap or just one entry */
    if (!Block)
        HeapValid = RtlpValidateHeap(Heap, TRUE);
    else
        HeapValid = RtlpValidateHeapEntry(Heap, (PHEAP_ENTRY)Block - 1);

    /* Unlock if it's lockable */
    if (HeapLocked)
    {
        RtlLeaveHeapLock(Heap->LockVariable);
    }

    return HeapValid;
}

/*
 * @unimplemented
 */
NTSTATUS NTAPI
RtlEnumProcessHeaps(PHEAP_ENUMERATION_ROUTINE HeapEnumerationRoutine,
                    PVOID lParam)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
BOOLEAN NTAPI
RtlValidateProcessHeaps(VOID)
{
    UNIMPLEMENTED;
    return TRUE;
}


/*
 * @unimplemented
 */
BOOLEAN NTAPI
RtlZeroHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags
    )
{
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
RtlSetUserValueHeap(IN PVOID HeapHandle,
                    IN ULONG Flags,
                    IN PVOID BaseAddress,
                    IN PVOID UserValue)
{
    PHEAP Heap = (PHEAP)HeapHandle;
    PHEAP_ENTRY HeapEntry;
    PHEAP_ENTRY_EXTRA Extra;
    BOOLEAN HeapLocked = FALSE, ValueSet = FALSE;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugSetUserValueHeap(Heap, Flags, BaseAddress, UserValue);

    /* Lock if it's lockable */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        HeapLocked = TRUE;
    }

    /* Get a pointer to the entry */
    HeapEntry = (PHEAP_ENTRY)BaseAddress - 1;

    /* If it's a free entry - return error */
    if (!(HeapEntry->Flags & HEAP_ENTRY_BUSY))
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);

        /* Release the heap lock if it was acquired */
        if (HeapLocked)
            RtlLeaveHeapLock(Heap->LockVariable);

        return FALSE;
    }

    /* Check if this entry has an extra stuff associated with it */
    if (HeapEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
    {
        /* Use extra to store the value */
        Extra = RtlpGetExtraStuffPointer(HeapEntry);
        Extra->Settable = (ULONG_PTR)UserValue;

        /* Indicate that value was set */
        ValueSet = TRUE;
    }

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
        RtlLeaveHeapLock(Heap->LockVariable);

    return ValueSet;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
RtlSetUserFlagsHeap(IN PVOID HeapHandle,
                    IN ULONG Flags,
                    IN PVOID BaseAddress,
                    IN ULONG UserFlagsReset,
                    IN ULONG UserFlagsSet)
{
    PHEAP Heap = (PHEAP)HeapHandle;
    PHEAP_ENTRY HeapEntry;
    BOOLEAN HeapLocked = FALSE;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugSetUserFlagsHeap(Heap, Flags, BaseAddress, UserFlagsReset, UserFlagsSet);

    /* Lock if it's lockable */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        HeapLocked = TRUE;
    }

    /* Get a pointer to the entry */
    HeapEntry = (PHEAP_ENTRY)BaseAddress - 1;

    /* If it's a free entry - return error */
    if (!(HeapEntry->Flags & HEAP_ENTRY_BUSY))
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);

        /* Release the heap lock if it was acquired */
        if (HeapLocked)
            RtlLeaveHeapLock(Heap->LockVariable);

        return FALSE;
    }

    /* Set / reset flags */
    HeapEntry->Flags &= ~(UserFlagsReset >> 4);
    HeapEntry->Flags |= (UserFlagsSet >> 4);

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
        RtlLeaveHeapLock(Heap->LockVariable);

    return TRUE;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
RtlGetUserInfoHeap(IN PVOID HeapHandle,
                   IN ULONG Flags,
                   IN PVOID BaseAddress,
                   OUT PVOID *UserValue,
                   OUT PULONG UserFlags)
{
    PHEAP Heap = (PHEAP)HeapHandle;
    PHEAP_ENTRY HeapEntry;
    PHEAP_ENTRY_EXTRA Extra;
    BOOLEAN HeapLocked = FALSE;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
        return RtlDebugGetUserInfoHeap(Heap, Flags, BaseAddress, UserValue, UserFlags);

    /* Lock if it's lockable */
    if (!(Flags & HEAP_NO_SERIALIZE))
    {
        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        HeapLocked = TRUE;
    }

    /* Get a pointer to the entry */
    HeapEntry = (PHEAP_ENTRY)BaseAddress - 1;

    /* If it's a free entry - return error */
    if (!(HeapEntry->Flags & HEAP_ENTRY_BUSY))
    {
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);

        /* Release the heap lock if it was acquired */
        if (HeapLocked)
            RtlLeaveHeapLock(Heap->LockVariable);

        return FALSE;
    }

    /* Check if this entry has an extra stuff associated with it */
    if (HeapEntry->Flags & HEAP_ENTRY_EXTRA_PRESENT)
    {
        /* Get pointer to extra data */
        Extra = RtlpGetExtraStuffPointer(HeapEntry);

        /* Pass user value */
        if (UserValue)
            *UserValue = (PVOID)Extra->Settable;
    }

    /* Decode and return user flags */
    if (UserFlags)
        *UserFlags = (HeapEntry->Flags & HEAP_ENTRY_SETTABLE_FLAGS) << 4;

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
        RtlLeaveHeapLock(Heap->LockVariable);

    return TRUE;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
RtlUsageHeap(IN HANDLE Heap,
             IN ULONG Flags,
             OUT PRTL_HEAP_USAGE Usage)
{
    /* TODO */
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

PWSTR
NTAPI
RtlQueryTagHeap(IN PVOID HeapHandle,
                IN ULONG Flags,
                IN USHORT TagIndex,
                IN BOOLEAN ResetCounters,
                OUT PRTL_HEAP_TAG_INFO HeapTagInfo)
{
    /* TODO */
    UNIMPLEMENTED;
    return NULL;
}

ULONG
NTAPI
RtlExtendHeap(IN HANDLE Heap,
              IN ULONG Flags,
              IN PVOID P,
              IN SIZE_T Size)
{
    /* TODO */
    UNIMPLEMENTED;
    return 0;
}

ULONG
NTAPI
RtlCreateTagHeap(_In_ HANDLE HeapHandle,
                 _In_ ULONG Flags,
                 _In_opt_ PWSTR TagName,
                 _In_ PWSTR TagSubName)
{
    /* TODO */
    UNIMPLEMENTED;
    return 0;
}

/* HEAP WALKING **************************************************************/

/*
 * Walking reads every heap structure through a routine, never through the pointer, so that one
 * implementation serves this process (under the heap lock) and another process (see dbgbuffer.c).
 * A reading failure or a chain that does not add up ends the walk with an error; it never faults.
 */

typedef struct _RTLP_HEAP_WALKER
{
    PRTLP_HEAP_READ_ROUTINE Read;
    PVOID ReadContext;
    ULONG_PTR HeapAddress;
    LONG CachedIndex;
    HEAP_SEGMENT Segment;
    HEAP Header;
} RTLP_HEAP_WALKER, *PRTLP_HEAP_WALKER;

#define HEAP_WALK_UNKNOWN_SIZE ((ULONG)-1)
#define HEAP_WALK_MAX_ENTRIES  0x10000000

static
NTSTATUS
NTAPI
RtlpHeapWalkReadLocal(
    _In_opt_ PVOID Context,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size)
{
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Context);

    _SEH2_TRY
    {
        RtlCopyMemory(Buffer, Address, Size);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    return Status;
}

FORCEINLINE
NTSTATUS
RtlpHeapWalkRead(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size)
{
    return Walker->Read(Walker->ReadContext, (PVOID)Address, Buffer, Size);
}

static
NTSTATUS
RtlpHeapWalkOpen(
    _Out_ PRTLP_HEAP_WALKER Walker,
    _In_opt_ PRTLP_HEAP_READ_ROUTINE Read,
    _In_opt_ PVOID ReadContext,
    _In_ ULONG_PTR HeapAddress)
{
    NTSTATUS Status;

    Walker->Read = Read ? Read : RtlpHeapWalkReadLocal;
    Walker->ReadContext = ReadContext;
    Walker->HeapAddress = HeapAddress;
    Walker->CachedIndex = -1;

    /* The copy runs up to and including the segment table */
    RtlZeroMemory(&Walker->Header, sizeof(Walker->Header));
    Status = RtlpHeapWalkRead(Walker, HeapAddress, &Walker->Header, FIELD_OFFSET(HEAP, AllocatorBackTraceIndex));
    if (!NT_SUCCESS(Status))
        return STATUS_INVALID_HANDLE;

    /* The heap is its own first segment */
    if (Walker->Header.Signature != HEAP_SIGNATURE ||
        (ULONG_PTR)Walker->Header.BaseAddress != HeapAddress ||
        (ULONG_PTR)Walker->Header.Segments[0] != HeapAddress)
    {
        return STATUS_INVALID_HANDLE;
    }

    return STATUS_SUCCESS;
}

/* Returns STATUS_NOT_FOUND for an index without a segment */
static
NTSTATUS
RtlpHeapWalkGetSegment(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG Index)
{
    ULONG_PTR Address;
    NTSTATUS Status;

    if (Index >= HEAP_SEGMENTS)
        return STATUS_NOT_FOUND;

    Address = (ULONG_PTR)Walker->Header.Segments[Index];
    if (Address == 0)
        return STATUS_NOT_FOUND;

    if (Walker->CachedIndex == (LONG)Index)
        return STATUS_SUCCESS;

    Walker->CachedIndex = -1;
    Status = RtlpHeapWalkRead(Walker, Address, &Walker->Segment, sizeof(Walker->Segment));
    if (!NT_SUCCESS(Status))
        return Status;

    if (Walker->Segment.SegmentSignature != HEAP_SEGMENT_SIGNATURE ||
        (ULONG_PTR)Walker->Segment.BaseAddress != Address ||
        Walker->Segment.Entry.SegmentOffset != Index ||
        Walker->Segment.Entry.Size == 0 ||
        (ULONG_PTR)Walker->Segment.FirstEntry <= Address ||
        (ULONG_PTR)Walker->Segment.FirstEntry >= (ULONG_PTR)Walker->Segment.LastValidEntry ||
        ((ULONG_PTR)Walker->Segment.FirstEntry & (sizeof(HEAP_ENTRY) - 1)) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Walker->CachedIndex = (LONG)Index;
    return STATUS_SUCCESS;
}

/* Finds the range that starts at Address, or with Above the first range that starts above it */
static
NTSTATUS
RtlpHeapWalkFindUcr(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG_PTR Address,
    _In_ BOOLEAN Above,
    _Out_ PHEAP_UCR_DESCRIPTOR Descriptor)
{
    ULONG_PTR Head, Link, Limit, Floor, Last;
    NTSTATUS Status;

    Head = (ULONG_PTR)Walker->Segment.BaseAddress + FIELD_OFFSET(HEAP_SEGMENT, UCRSegmentList);
    Link = (ULONG_PTR)Walker->Segment.UCRSegmentList.Flink;
    Last = (ULONG_PTR)Walker->Segment.LastValidEntry;

    /* Every range is at least a page of its own, so a list longer than the pages of the segment goes in circles */
    Limit = (Last - (ULONG_PTR)Walker->Segment.BaseAddress) / PAGE_SIZE + 1;
    Floor = (ULONG_PTR)Walker->Segment.FirstEntry;

    while (Link != Head)
    {
        if (Limit-- == 0)
            return STATUS_INVALID_PARAMETER;

        Status = RtlpHeapWalkRead(Walker,
                                  Link - FIELD_OFFSET(HEAP_UCR_DESCRIPTOR, SegmentEntry),
                                  Descriptor,
                                  sizeof(*Descriptor));
        if (!NT_SUCCESS(Status))
            return Status;

        /* The ranges are sorted by address and do not overlap, so a list that goes in circles breaks this at once */
        if ((ULONG_PTR)Descriptor->Address < Floor ||
            (ULONG_PTR)Descriptor->Address >= Last ||
            Descriptor->Size == 0 ||
            Descriptor->Size > Last - (ULONG_PTR)Descriptor->Address)
        {
            return STATUS_INVALID_PARAMETER;
        }
        Floor = (ULONG_PTR)Descriptor->Address + Descriptor->Size;

        if (Above ? ((ULONG_PTR)Descriptor->Address > Address) : ((ULONG_PTR)Descriptor->Address == Address))
            return STATUS_SUCCESS;

        Link = (ULONG_PTR)Descriptor->SegmentEntry.Flink;
    }

    return STATUS_NOT_FOUND;
}

static
VOID
RtlpHeapWalkFillRegion(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG Index,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    PHEAP_SEGMENT Segment = &Walker->Segment;
    SIZE_T Reserved, Uncommitted;

    Reserved = (ULONG_PTR)Segment->LastValidEntry - (ULONG_PTR)Segment->BaseAddress;
    Uncommitted = (SIZE_T)Segment->NumberOfUnCommittedPages * PAGE_SIZE;
    if (Uncommitted > Reserved)
        Uncommitted = Reserved;

    RtlZeroMemory(Entry, sizeof(*Entry));

    /* The data of a region is its header, without the entry that every block starts with */
    Entry->DataAddress = Segment->BaseAddress;
    Entry->DataSize = ((SIZE_T)Segment->Entry.Size << HEAP_ENTRY_SHIFT) - sizeof(HEAP_ENTRY);
    Entry->SegmentIndex = (UCHAR)Index;
    Entry->Flags = RTL_HEAP_WALK_REGION;
    Entry->Segment.CommittedSize = (ULONG)(Reserved - Uncommitted);
    Entry->Segment.UnCommittedSize = (ULONG)Uncommitted;
    Entry->Segment.FirstEntry = Segment->FirstEntry;
    Entry->Segment.LastEntry = Segment->LastValidEntry;
}

static
NTSTATUS
RtlpHeapWalkFillBlock(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG Index,
    _In_ ULONG_PTR Address,
    _In_ PHEAP_ENTRY Header,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    SIZE_T Size = (SIZE_T)Header->Size << HEAP_ENTRY_SHIFT;
    HEAP_ENTRY_EXTRA Extra;
    SIZE_T Unused;
    NTSTATUS Status;

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->SegmentIndex = (UCHAR)Index;

    if (Header->Flags & HEAP_ENTRY_BUSY)
    {
        /* The unused bytes count the entry and the extra data too, as the overhead does */
        Unused = Header->UnusedBytes;
        if (Unused > Size)
            return STATUS_INVALID_PARAMETER;

        Entry->DataAddress = (PVOID)(Address + sizeof(HEAP_ENTRY));
        Entry->DataSize = Size - Unused;
        Entry->OverheadBytes = (UCHAR)Unused;
        Entry->Flags = RTL_HEAP_WALK_BUSY | (Header->Flags & HEAP_ENTRY_SETTABLE_FLAGS);

        if ((Header->Flags & HEAP_ENTRY_EXTRA_PRESENT) && Size >= 2 * sizeof(HEAP_ENTRY))
        {
            Status = RtlpHeapWalkRead(Walker,
                                      Address + Size - sizeof(HEAP_ENTRY_EXTRA),
                                      &Extra,
                                      sizeof(Extra));
            if (!NT_SUCCESS(Status))
                return Status;

            Entry->Flags |= RTL_HEAP_WALK_BLOCK;
            Entry->Block.Settable = Extra.Settable;
            Entry->Block.TagIndex = Extra.TagIndex;
            Entry->Block.AllocatorBackTraceIndex = Extra.AllocatorBackTraceIndex;
        }
    }
    else
    {
        if (Size < sizeof(HEAP_FREE_ENTRY))
            return STATUS_INVALID_PARAMETER;

        Entry->DataAddress = (PVOID)(Address + sizeof(HEAP_FREE_ENTRY));
        Entry->DataSize = Size - sizeof(HEAP_FREE_ENTRY);
        Entry->OverheadBytes = sizeof(HEAP_FREE_ENTRY);
    }

    return STATUS_SUCCESS;
}

static
VOID
RtlpHeapWalkFillUcr(
    _In_ ULONG Index,
    _In_ PHEAP_UCR_DESCRIPTOR Descriptor,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->DataAddress = Descriptor->Address;
    Entry->DataSize = Descriptor->Size;
    Entry->SegmentIndex = (UCHAR)Index;
    Entry->Flags = RTL_HEAP_WALK_UNCOMMITTED;
}

/* The blocks that are too big for the segments are the nodes of a list, after the segments */
static
NTSTATUS
RtlpHeapWalkVirtual(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG_PTR Node,
    _In_ ULONG_PTR Previous,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    HEAP_VIRTUAL_ALLOC_ENTRY Block;
    NTSTATUS Status;

    if (Node == Walker->HeapAddress + FIELD_OFFSET(HEAP, VirtualAllocdBlocks))
        return STATUS_NO_MORE_ENTRIES;

    Status = RtlpHeapWalkRead(Walker, Node, &Block, sizeof(Block));
    if (!NT_SUCCESS(Status))
        return Status;

    /* The list is a ring through the head of the heap: a node must hang on the one before it */
    if (!(Block.BusyBlock.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) || Block.BusyBlock.Size > Block.CommitSize ||
        (ULONG_PTR)Block.Entry.Blink != Previous || (ULONG_PTR)Block.Entry.Flink == Node)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->DataAddress = (PVOID)(Node + sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));
    Entry->DataSize = Block.CommitSize - Block.BusyBlock.Size;
    Entry->OverheadBytes = sizeof(HEAP_VIRTUAL_ALLOC_ENTRY);
    Entry->SegmentIndex = HEAP_SEGMENTS;
    Entry->Flags = RTL_HEAP_WALK_BUSY | RTL_HEAP_WALK_VIRTUAL | (Block.BusyBlock.Flags & HEAP_ENTRY_SETTABLE_FLAGS);

    if (Block.BusyBlock.Flags & HEAP_ENTRY_EXTRA_PRESENT)
    {
        Entry->Flags |= RTL_HEAP_WALK_BLOCK;
        Entry->Block.Settable = Block.ExtraStuff.Settable;
        Entry->Block.TagIndex = Block.ExtraStuff.TagIndex;
        Entry->Block.AllocatorBackTraceIndex = Block.ExtraStuff.AllocatorBackTraceIndex;
    }

    /* The measured entries of Windows leave this alone: here it holds the size that was committed, which the data and the overhead do not add up to */
    Entry->Block.Reserved[0] = (ULONG)Block.CommitSize;

    return STATUS_SUCCESS;
}

/* The first region from Index on, else the first big block, else the end */
static
NTSTATUS
RtlpHeapWalkNextRegion(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG Index,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    NTSTATUS Status;

    for (; Index < HEAP_SEGMENTS; Index++)
    {
        Status = RtlpHeapWalkGetSegment(Walker, Index);
        if (Status == STATUS_NOT_FOUND)
            continue;

        if (!NT_SUCCESS(Status))
            return Status;

        RtlpHeapWalkFillRegion(Walker, Index, Entry);
        return STATUS_SUCCESS;
    }

    return RtlpHeapWalkVirtual(Walker,
                               (ULONG_PTR)Walker->Header.VirtualAllocdBlocks.Flink,
                               Walker->HeapAddress + FIELD_OFFSET(HEAP, VirtualAllocdBlocks),
                               Entry);
}

/*
 * Reports the first entry of the segment that is cached in the walker, from Current on, whose
 * address is above After (0 means any). PreviousSize is what the block at Current must say about
 * its predecessor, or HEAP_WALK_UNKNOWN_SIZE.
 */
static
NTSTATUS
RtlpHeapWalkScan(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG Index,
    _In_ ULONG_PTR Current,
    _In_ ULONG PreviousSize,
    _In_ ULONG_PTR After,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    PHEAP_SEGMENT Segment = &Walker->Segment;
    HEAP_UCR_DESCRIPTOR Ucr;
    HEAP_ENTRY Header;
    ULONG_PTR End;
    BOOLEAN Guard;
    NTSTATUS Status;

    for (;;)
    {
        if (Current >= (ULONG_PTR)Segment->LastValidEntry)
            return RtlpHeapWalkNextRegion(Walker, Index + 1, Entry);

        if (Current < (ULONG_PTR)Segment->FirstEntry || (Current & (sizeof(HEAP_ENTRY) - 1)) != 0)
            return STATUS_INVALID_PARAMETER;

        Status = RtlpHeapWalkRead(Walker, Current, &Header, sizeof(Header));
        if (!NT_SUCCESS(Status))
            return Status;

        End = Current + ((ULONG_PTR)Header.Size << HEAP_ENTRY_SHIFT);
        if (Header.Size == 0 ||
            End > (ULONG_PTR)Segment->LastValidEntry ||
            Header.SegmentOffset != Index ||
            (PreviousSize != HEAP_WALK_UNKNOWN_SIZE && Header.PreviousSize != PreviousSize))
        {
            return STATUS_INVALID_PARAMETER;
        }

        /* One entry long, busy and last: this is the guard that ends a committed range, not a block */
        Guard = (Header.Flags & (HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY)) == (HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY) &&
                Header.Size == 1;
        if (Current > After && !Guard)
            return RtlpHeapWalkFillBlock(Walker, Index, Current, &Header, Entry);

        if (!(Header.Flags & HEAP_ENTRY_LAST_ENTRY))
        {
            Current = End;
            PreviousSize = Header.Size;
            continue;
        }

        /* The committed range ends here: an uncommitted range or the end of the segment follows */
        if (End == (ULONG_PTR)Segment->LastValidEntry)
            return RtlpHeapWalkNextRegion(Walker, Index + 1, Entry);

        Status = RtlpHeapWalkFindUcr(Walker, End, FALSE, &Ucr);
        if (Status == STATUS_NOT_FOUND && Guard)
        {
            /* A range that is too short for a free block ends in two guards */
            Current = End;
            PreviousSize = Header.Size;
            continue;
        }

        if (!NT_SUCCESS(Status))
            return (Status == STATUS_NOT_FOUND) ? STATUS_INVALID_PARAMETER : Status;

        if ((ULONG_PTR)Ucr.Address > After)
        {
            RtlpHeapWalkFillUcr(Index, &Ucr, Entry);
            return STATUS_SUCCESS;
        }

        Current = (ULONG_PTR)Ucr.Address + Ucr.Size;
        PreviousSize = 0;
    }
}

/* The segment that holds Address, cached in the walker */
static
NTSTATUS
RtlpHeapWalkFindSegment(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG Hint,
    _In_ ULONG_PTR Address,
    _Out_ PULONG Index)
{
    ULONG i;
    NTSTATUS Status;

    if (Hint < HEAP_SEGMENTS)
    {
        Status = RtlpHeapWalkGetSegment(Walker, Hint);
        if (NT_SUCCESS(Status) &&
            Address >= (ULONG_PTR)Walker->Segment.BaseAddress &&
            Address < (ULONG_PTR)Walker->Segment.LastValidEntry)
        {
            *Index = Hint;
            return STATUS_SUCCESS;
        }
    }

    for (i = 0; i < HEAP_SEGMENTS; i++)
    {
        Status = RtlpHeapWalkGetSegment(Walker, i);
        if (Status == STATUS_NOT_FOUND)
            continue;

        if (!NT_SUCCESS(Status))
            return Status;

        if (Address >= (ULONG_PTR)Walker->Segment.BaseAddress &&
            Address < (ULONG_PTR)Walker->Segment.LastValidEntry)
        {
            *Index = i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_INVALID_PARAMETER;
}

/* The entry after a big block: the block must still be in the list, with both neighbours agreeing */
static
NTSTATUS
RtlpHeapWalkAfterVirtual(
    _In_ PRTLP_HEAP_WALKER Walker,
    _In_ ULONG_PTR Data,
    _Out_ PRTL_HEAP_WALK_ENTRY Entry)
{
    ULONG_PTR Node, Neighbour;
    HEAP_VIRTUAL_ALLOC_ENTRY Block;
    LIST_ENTRY Link;
    NTSTATUS Status;

    Node = Data - sizeof(HEAP_VIRTUAL_ALLOC_ENTRY);
    Status = RtlpHeapWalkRead(Walker, Node, &Block, sizeof(Block));
    if (!NT_SUCCESS(Status) || !(Block.BusyBlock.Flags & HEAP_ENTRY_VIRTUAL_ALLOC))
        return STATUS_INVALID_PARAMETER;

    if ((ULONG_PTR)Block.Entry.Flink == Node || (ULONG_PTR)Block.Entry.Blink == Node)
        return STATUS_INVALID_PARAMETER;

    Neighbour = (ULONG_PTR)Block.Entry.Blink;
    Status = RtlpHeapWalkRead(Walker, Neighbour, &Link, sizeof(Link));
    if (!NT_SUCCESS(Status) || (ULONG_PTR)Link.Flink != Node)
        return STATUS_INVALID_PARAMETER;

    Neighbour = (ULONG_PTR)Block.Entry.Flink;
    Status = RtlpHeapWalkRead(Walker, Neighbour, &Link, sizeof(Link));
    if (!NT_SUCCESS(Status) || (ULONG_PTR)Link.Blink != Node)
        return STATUS_INVALID_PARAMETER;

    return RtlpHeapWalkVirtual(Walker, Neighbour, Node, Entry);
}

/* Replaces the entry, which marks the place, with the one after it */
static
NTSTATUS
RtlpHeapWalkNext(
    _In_ PRTLP_HEAP_WALKER Walker,
    _Inout_ PRTL_HEAP_WALK_ENTRY Entry)
{
    ULONG_PTR Data = (ULONG_PTR)Entry->DataAddress;
    ULONG Flags = Entry->Flags;
    ULONG Index = Entry->SegmentIndex;
    ULONG_PTR Start;
    HEAP_UCR_DESCRIPTOR Ucr;
    NTSTATUS Status;

    if (Data == 0)
        return RtlpHeapWalkNextRegion(Walker, 0, Entry);

    if (Index == HEAP_SEGMENTS && !(Flags & (RTL_HEAP_WALK_REGION | RTL_HEAP_WALK_UNCOMMITTED)))
        return RtlpHeapWalkAfterVirtual(Walker, Data, Entry);

    if (Flags & RTL_HEAP_WALK_REGION)
    {
        for (Index = 0; Index < HEAP_SEGMENTS; Index++)
        {
            if ((ULONG_PTR)Walker->Header.Segments[Index] == Data)
                break;
        }

        if (Index == HEAP_SEGMENTS)
            return STATUS_INVALID_PARAMETER;

        Status = RtlpHeapWalkGetSegment(Walker, Index);
        if (!NT_SUCCESS(Status))
            return Status;

        return RtlpHeapWalkScan(Walker,
                                Index,
                                (ULONG_PTR)Walker->Segment.FirstEntry,
                                Walker->Segment.Entry.Size,
                                0,
                                Entry);
    }

    if (Flags & RTL_HEAP_WALK_UNCOMMITTED)
        Start = Data;
    else
        Start = Data - ((Flags & RTL_HEAP_WALK_BUSY) ? sizeof(HEAP_ENTRY) : sizeof(HEAP_FREE_ENTRY));

    Status = RtlpHeapWalkFindSegment(Walker, Index, Start, &Index);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Follow the chain on from the entry that marks the place */
    if (Flags & RTL_HEAP_WALK_UNCOMMITTED)
    {
        if (NT_SUCCESS(RtlpHeapWalkFindUcr(Walker, Start, FALSE, &Ucr)))
        {
            Status = RtlpHeapWalkScan(Walker, Index, (ULONG_PTR)Ucr.Address + Ucr.Size, 0, 0, Entry);
            if (NT_SUCCESS(Status) || Status == STATUS_NO_MORE_ENTRIES)
                return Status;
        }
    }
    else
    {
        Status = RtlpHeapWalkScan(Walker, Index, Start, HEAP_WALK_UNKNOWN_SIZE, Start, Entry);
        if (NT_SUCCESS(Status) || Status == STATUS_NO_MORE_ENTRIES)
            return Status;
    }

    /* The place does not match the chain, for instance after its block was freed: find it from the start */
    Status = RtlpHeapWalkFindSegment(Walker, Index, Start, &Index);
    if (!NT_SUCCESS(Status))
        return Status;

    return RtlpHeapWalkScan(Walker,
                            Index,
                            (ULONG_PTR)Walker->Segment.FirstEntry,
                            Walker->Segment.Entry.Size,
                            Start,
                            Entry);
}

/*
 * Takes the lock of a heap in this process and gives it back, which is NULL when the heap needs none.
 * A heap that another thread destroys meanwhile is that thread's mistake, but must not fault the walk.
 */
static
NTSTATUS
RtlpHeapWalkLock(
    _In_ PHEAP Heap,
    _Out_ PHEAP_LOCK *Lock)
{
    NTSTATUS Status = STATUS_SUCCESS;

    *Lock = NULL;

    _SEH2_TRY
    {
        if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS)
        {
            Status = STATUS_NOT_IMPLEMENTED;
        }
        else if (Heap->Signature != HEAP_SIGNATURE)
        {
            Status = STATUS_INVALID_HANDLE;
        }
        else if (!(Heap->Flags & HEAP_NO_SERIALIZE) && Heap->LockVariable != NULL)
        {
            PHEAP_LOCK HeapLock = Heap->LockVariable;

            RtlEnterHeapLock(HeapLock, TRUE);
            RtlpHeapFeLock(Heap);
            *Lock = HeapLock;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_INVALID_HANDLE;
    }
    _SEH2_END;

    return Status;
}

static
VOID
RtlpHeapWalkUnlock(
    _In_ PHEAP Heap,
    _In_ PHEAP_LOCK Lock)
{
    _SEH2_TRY
    {
        RtlpHeapFeUnlock(Heap);
        RtlLeaveHeapLock(Lock);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;
}

NTSTATUS
NTAPI
RtlpEnumerateHeap(
    _In_opt_ PRTLP_HEAP_READ_ROUTINE Read,
    _In_opt_ PVOID ReadContext,
    _In_ PVOID HeapAddress,
    _In_ PRTLP_HEAP_WALK_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext,
    _Out_opt_ PULONG HeapFlags)
{
    RTLP_HEAP_WALKER Walker;
    RTL_HEAP_WALK_ENTRY Entry;
    PHEAP_LOCK Lock = NULL;
    ULONG Count = 0;
    NTSTATUS Status;

    if (!Read)
    {
        /* A heap in this process is locked while it is read */
        Status = RtlpHeapWalkLock(HeapAddress, &Lock);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    Status = RtlpHeapWalkOpen(&Walker, Read, ReadContext, (ULONG_PTR)HeapAddress);
    if (NT_SUCCESS(Status))
    {
        if (HeapFlags)
            *HeapFlags = Walker.Header.Flags;

        RtlZeroMemory(&Entry, sizeof(Entry));
        for (;;)
        {
            Status = RtlpHeapWalkNext(&Walker, &Entry);
            if (!NT_SUCCESS(Status))
                break;

            /* No heap has this many entries; a damaged one can go in circles */
            if (++Count > HEAP_WALK_MAX_ENTRIES)
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!Callback(CallbackContext, &Entry))
                break;
        }

        if (Status == STATUS_NO_MORE_ENTRIES)
            Status = STATUS_SUCCESS;
    }

    if (Lock)
        RtlpHeapWalkUnlock((PHEAP)HeapAddress, Lock);

    return Status;
}

NTSTATUS
NTAPI
RtlWalkHeap(IN HANDLE HeapHandle,
            IN PVOID HeapEntry)
{
    PHEAP Heap = (PHEAP)HeapHandle;
    RTLP_HEAP_WALKER Walker;
    RTL_HEAP_WALK_ENTRY Entry;
    PHEAP_LOCK Lock;
    NTSTATUS Status;

    /* Windows faults on both; an error is kinder */
    if (HeapEntry == NULL)
        return STATUS_INVALID_PARAMETER;

    if (Heap == NULL)
        return STATUS_INVALID_HANDLE;

    Status = RtlpHeapWalkReadLocal(NULL, HeapEntry, &Entry, sizeof(Entry));
    if (!NT_SUCCESS(Status))
        return Status;

    Status = RtlpHeapWalkLock(Heap, &Lock);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = RtlpHeapWalkOpen(&Walker, NULL, NULL, (ULONG_PTR)Heap);
    if (NT_SUCCESS(Status))
        Status = RtlpHeapWalkNext(&Walker, &Entry);

    if (Lock)
        RtlpHeapWalkUnlock(Heap, Lock);

    /* The entry is left alone when there is nothing more to report */
    if (NT_SUCCESS(Status))
    {
        _SEH2_TRY
        {
            RtlCopyMemory(HeapEntry, &Entry, sizeof(Entry));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = STATUS_ACCESS_VIOLATION;
        }
        _SEH2_END;
    }

    return Status;
}

PVOID
NTAPI
RtlProtectHeap(IN PVOID HeapHandle,
               IN BOOLEAN ReadOnly)
{
    UNIMPLEMENTED;
    return NULL;
}

NTSTATUS
NTAPI
RtlSetHeapInformation(IN HANDLE HeapHandle OPTIONAL,
                      IN HEAP_INFORMATION_CLASS HeapInformationClass,
                      IN PVOID HeapInformation,
                      IN SIZE_T HeapInformationLength)
{
    PHEAP Heap = (PHEAP)HeapHandle;
    NTSTATUS Status;

    /* Setting heap information is not really supported except for enabling LFH */
    if (HeapInformationClass == HeapCompatibilityInformation)
    {
        /* Check buffer length */
        if (HeapInformationLength < sizeof(ULONG))
        {
            /* The provided buffer is too small */
            return STATUS_BUFFER_TOO_SMALL;
        }

        /* Check for a special magic value for enabling LFH */
        if (*(PULONG)HeapInformation != 2)
        {
            return STATUS_UNSUCCESSFUL;
        }

        /* No heap, nothing to enable (the call was always accepted) */
        if (!Heap)
            return STATUS_SUCCESS;

        /* Turn the front end on. As on Windows, a heap without a lock, a fixed size one
           and a checking or page heap cannot have it: the request is refused (ERROR_INVALID_PARAMETER) */
        if (Heap->Signature != HEAP_SIGNATURE ||
            (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS) ||
            (Heap->Flags & HEAP_NO_SERIALIZE) ||
            !Heap->LockVariable)
        {
            return STATUS_INVALID_PARAMETER;
        }

        RtlEnterHeapLock(Heap->LockVariable, TRUE);
        Status = RtlpHeapFeEnable(Heap) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        RtlLeaveHeapLock(Heap->LockVariable);

        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlQueryHeapInformation(HANDLE HeapHandle,
                        HEAP_INFORMATION_CLASS HeapInformationClass,
                        PVOID HeapInformation,
                        SIZE_T HeapInformationLength,
                        PSIZE_T ReturnLength OPTIONAL)
{
    PHEAP Heap = (PHEAP)HeapHandle;

    /* Only HeapCompatibilityInformation is supported */
    if (HeapInformationClass == HeapCompatibilityInformation)
    {
        /* Set result length */
        if (ReturnLength)
            *ReturnLength = sizeof(ULONG);

        /* Check buffer length */
        if (HeapInformationLength < sizeof(ULONG))
        {
            /* It's too small, return needed length */
            return STATUS_BUFFER_TOO_SMALL;
        }

        /* Return front end heap type */
        *(PULONG)HeapInformation = Heap->FrontEndHeapType;

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

/* @implemented */
ULONG
NTAPI
RtlMultipleAllocateHeap(IN PVOID HeapHandle,
                        IN ULONG Flags,
                        IN SIZE_T Size,
                        IN ULONG Count,
                        OUT PVOID *Array)
{
    ULONG Index;
    EXCEPTION_RECORD ExceptionRecord;

    for (Index = 0; Index < Count; ++Index)
    {
        Array[Index] = RtlAllocateHeap(HeapHandle, Flags, Size);
        if (Array[Index] == NULL)
        {
            /* ERROR_NOT_ENOUGH_MEMORY */
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);

            if (Flags & HEAP_GENERATE_EXCEPTIONS)
            {
                ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
                ExceptionRecord.ExceptionRecord = NULL;
                ExceptionRecord.NumberParameters = 0;
                ExceptionRecord.ExceptionFlags = 0;

                RtlRaiseException(&ExceptionRecord);
            }
            break;
        }
    }

    return Index;
}

/* @implemented */
ULONG
NTAPI
RtlMultipleFreeHeap(IN PVOID HeapHandle,
                    IN ULONG Flags,
                    IN ULONG Count,
                    OUT PVOID *Array)
{
    ULONG Index;

    for (Index = 0; Index < Count; ++Index)
    {
        if (Array[Index] == NULL)
            continue;

        _SEH2_TRY
        {
            if (!RtlFreeHeap(HeapHandle, Flags, Array[Index]))
            {
                /* ERROR_INVALID_PARAMETER */
                RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
                break;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* ERROR_INVALID_PARAMETER */
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_PARAMETER);
            break;
        }
        _SEH2_END;
    }

    return Index;
}

/*
 * Info:
 * - https://securityxploded.com/enumheaps.php
 * - https://evilcodecave.wordpress.com/2009/04/14/rtlqueryprocessheapinformation-as-anti-dbg-trick/
 */
struct _DEBUG_BUFFER;

NTSTATUS
NTAPI
RtlQueryProcessHeapInformation(
    IN struct _DEBUG_BUFFER *DebugBuffer)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */

