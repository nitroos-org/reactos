/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/pin.c
 * PURPOSE:         Implements cache managers pinning interface
 *
 * PROGRAMMERS:     ?
                    Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern NPAGED_LOOKASIDE_LIST iBcbLookasideList;

/* Counters:
 * - Number of calls to CcMapData that could wait
 * - Number of calls to CcMapData that couldn't wait
 * - Number of calls to CcPinRead that could wait
 * - Number of calls to CcPinRead that couldn't wait
 * - Number of calls to CcPinMappedDataCount
 */
ULONG CcMapDataWait = 0;
ULONG CcMapDataNoWait = 0;
ULONG CcPinReadWait = 0;
ULONG CcPinReadNoWait = 0;
ULONG CcPinMappedDataCount = 0;

/* FUNCTIONS *****************************************************************/

static
PINTERNAL_BCB
NTAPI
CcpFindBcb(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Pinned)
{
    PINTERNAL_BCB Bcb;
    BOOLEAN Found = FALSE;
    PLIST_ENTRY NextEntry;

    for (NextEntry = SharedCacheMap->BcbList.Flink;
         NextEntry != &SharedCacheMap->BcbList;
         NextEntry = NextEntry->Flink)
    {
        Bcb = CONTAINING_RECORD(NextEntry, INTERNAL_BCB, BcbEntry);

        if (Bcb->PFCB.MappedFileOffset.QuadPart <= FileOffset->QuadPart &&
            (Bcb->PFCB.MappedFileOffset.QuadPart + Bcb->PFCB.MappedLength) >=
            (FileOffset->QuadPart + Length))
        {
            /* Discriminate pinned vs mapped BCBs by the stable per-BCB
             * pin-type flag, not the live PinCount. PinCount transiently
             * drops to 0 during an exclusive-pin ownership handoff (the old
             * owner has unpinned and released the ERESOURCE, the next waiter
             * has not yet re-incremented) while the BCB is still linked with
             * RefCount > 0. Keying discovery off PinCount made a pinned BCB
             * momentarily undiscoverable, so a concurrent pinner created a
             * duplicate pinned BCB (its own ERESOURCE) for the same range and
             * two "exclusive" owners ran at once (kmtest CcPinRead TestId 7
             * PinRaceOverlaps). The flag is constant for the BCB's whole
             * linked lifetime, closing that window. */
            if ((Pinned && Bcb->Pinned) || (!Pinned && !Bcb->Pinned))
            {
                Found = TRUE;
                break;
            }
        }
    }

    return (Found ? Bcb : NULL);
}

/*
 * Linked pinned BCBs of a shared cache map never overlap each other. A pin
 * contained in one of them uses it (CcpFindBcb); a pin that overlaps none
 * gets a new one; any other pin is covered by an overlap BCB (CcpCreateObcb)
 * that holds the lock of every pinned BCB its range touches, so overlapping
 * exclusive pins serialize while overlapping shared pins still run together.
 * The new-BCB path (CcpGetAppropriateBcb) and CcpCreateObcb link BCBs only
 * under BcbSpinLock after checking for overlaps, which keeps the invariant.
 */
static
BOOLEAN
CcpPinnedBcbOverlaps(
    IN PINTERNAL_BCB Bcb,
    IN LONGLONG Start,
    IN LONGLONG End)
{
    return Bcb->Pinned &&
           Bcb->PFCB.MappedFileOffset.QuadPart < End &&
           (Bcb->PFCB.MappedFileOffset.QuadPart + Bcb->PFCB.MappedLength) > Start;
}

/* Caller holds BcbSpinLock */
static
ULONG
CcpCountPinnedOverlaps(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN LONGLONG Start,
    IN LONGLONG End)
{
    PLIST_ENTRY NextEntry;
    ULONG Count = 0;

    for (NextEntry = SharedCacheMap->BcbList.Flink;
         NextEntry != &SharedCacheMap->BcbList;
         NextEntry = NextEntry->Flink)
    {
        if (CcpPinnedBcbOverlaps(CONTAINING_RECORD(NextEntry, INTERNAL_BCB, BcbEntry), Start, End))
        {
            Count++;
        }
    }

    return Count;
}

/*
 * Caller holds BcbSpinLock and has just dropped one pin or repin of the BCB.
 * When that was the last, the range is no longer held back from the lazy
 * write. Returns TRUE if it was made dirty while pinned: the caller makes it
 * dirty again (CcpRedirtyBcb) before it lets the pin go.
 */
static
BOOLEAN
CcpEndPinWrite(
    IN PINTERNAL_BCB Bcb)
{
    BOOLEAN Redirty;

    if (Bcb->PinCount != 0 || Bcb->RepinCount != 0)
    {
        return FALSE;
    }

    Redirty = BooleanFlagOn(Bcb->PinWrite, CC_BCB_WRITE_DIRTY);
    Bcb->PinWrite = 0;
    return Redirty;
}

/*
 * The last pin of a BCB made dirty while pinned goes: everything the file
 * system changed under the pin is in the view now. A lazy write leaves such a
 * range alone, but a write that does not (CcFlushCache, a trim or shutdown
 * flush, Mm) may have written it, and cleaned it, between the
 * CcSetDirtyPinnedData call and later changes: mark it dirty again. If it is
 * still dirty this changes nothing.
 */
static
VOID
CcpRedirtyBcb(
    IN PINTERNAL_BCB Bcb)
{
    PROS_VACB Vacb = Bcb->Vacb;

    /* Mm takes the segment lock; CcUnpinData may be called at DISPATCH_LEVEL,
     * where only the view can be marked (its clean pages are not written) */
    if (KeGetCurrentIrql() <= APC_LEVEL)
    {
        MmMakeSegmentDirty(Vacb->SharedCacheMap->FileObject->SectionObjectPointer,
                           Bcb->PFCB.MappedFileOffset.QuadPart,
                           Bcb->PFCB.MappedLength);
    }

    if (!Vacb->Dirty)
    {
        CcRosMarkDirtyVacb(Vacb);
    }
}

/*
 * Which pages of [Start, Start + Pages pages) a lazy write must leave alone:
 * those of a BCB pinned (or repinned) for writing, see CC_BCB_WRITE_*. Start
 * is page aligned. Sets one bit per held page in Held and returns TRUE if any.
 * The answer is a snapshot: a pin taken after it is not held back by the
 * write that asked (if it makes the range dirty, CcSetDirtyPinnedData marks
 * the view again and its last unpin does, see CcpRedirtyBcb).
 */
BOOLEAN
CcpGetPinHeldPages(
    _In_ PROS_SHARED_CACHE_MAP SharedCacheMap,
    _In_ LONGLONG Start,
    _In_ ULONG Pages,
    _Out_writes_((Pages + 31) / 32) PULONG Held)
{
    LONGLONG End = Start + ((LONGLONG)Pages << PAGE_SHIFT);
    LONGLONG First, Last;
    PLIST_ENTRY NextEntry;
    PINTERNAL_BCB Bcb;
    BOOLEAN Any = FALSE;
    KIRQL OldIrql;
    ULONG Page, EndPage;

    RtlZeroMemory(Held, ((Pages + 31) / 32) * sizeof(ULONG));

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    for (NextEntry = SharedCacheMap->BcbList.Flink;
         NextEntry != &SharedCacheMap->BcbList;
         NextEntry = NextEntry->Flink)
    {
        Bcb = CONTAINING_RECORD(NextEntry, INTERNAL_BCB, BcbEntry);

        if (!Bcb->Pinned || Bcb->PinWrite == 0 ||
            (Bcb->PinCount == 0 && Bcb->RepinCount == 0))
        {
            continue;
        }

        First = max(Bcb->PFCB.MappedFileOffset.QuadPart, Start);
        Last = min(Bcb->PFCB.MappedFileOffset.QuadPart + Bcb->PFCB.MappedLength, End);
        if (First >= Last)
        {
            continue;
        }

        EndPage = (ULONG)((Last - Start + PAGE_SIZE - 1) >> PAGE_SHIFT);
        for (Page = (ULONG)((First - Start) >> PAGE_SHIFT); Page < EndPage; Page++)
        {
            Held[Page / 32] |= 1UL << (Page % 32);
        }
        Any = TRUE;
    }
    KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

    return Any;
}

static
VOID
CcpDereferenceBcb(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PINTERNAL_BCB Bcb)
{
    ULONG RefCount;
    KIRQL OldIrql;

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    RefCount = --Bcb->RefCount;
    if (RefCount == 0 && Bcb->PinCount != 0)
    {
        /* Invariant violation: a pinned BCB holds its ERESOURCE, so freeing
         * it here would delete a held resource. Checked builds stop; in
         * release builds keep the BCB linked and referenced (a bounded leak)
         * instead of corrupting pool. */
        DPRINT1("CcpDereferenceBcb: BCB %p dropped with PinCount %lu\n", Bcb, Bcb->PinCount);
        ASSERT(Bcb->PinCount == 0);
        Bcb->RefCount = 1;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
        return;
    }

    if (RefCount == 0)
    {
        RemoveEntryList(&Bcb->BcbEntry);

        /* PinCount is mutated under BcbSpinLock and was verified zero above;
         * with the BCB unlinked no other CPU can reach it after we release. */
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        /*
         * Don't mark dirty, if it was dirty,
         * the VACB was already marked as such
         * following the call to CcSetDirtyPinnedData
         */
        CcRosReleaseVacb(SharedCacheMap,
                         Bcb->Vacb,
                         FALSE,
                         FALSE);

        ExDeleteResourceLite(&Bcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, Bcb);
    }
    else
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }
}

static
PVOID
CcpGetAppropriateBcb(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PROS_VACB Vacb,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG PinFlags,
    IN BOOLEAN ToPin,
    OUT PBOOLEAN Retry)
{
    KIRQL OldIrql;
    BOOLEAN Result;
    PINTERNAL_BCB iBcb, DupBcb;

    *Retry = FALSE;

    iBcb = ExAllocateFromNPagedLookasideList(&iBcbLookasideList);
    if (iBcb == NULL)
    {
        /* The caller releases its VACB reference */
        return NULL;
    }

    RtlZeroMemory(iBcb, sizeof(*iBcb));
    iBcb->PFCB.NodeTypeCode = CC_NTC_BCB; /* As per KMTests */
    iBcb->PFCB.NodeByteSize = 0;
    iBcb->PFCB.MappedLength = Length;
    iBcb->PFCB.MappedFileOffset = *FileOffset;
    iBcb->Vacb = Vacb;
    iBcb->PinCount = 0;
    iBcb->RefCount = 1;
    /* Record the stable pin-type before the BCB can be linked and found. */
    iBcb->Pinned = ToPin;
    ExInitializeResourceLite(&iBcb->Lock);

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);

    /* Check if we raced with another BCB creation */
    DupBcb = CcpFindBcb(SharedCacheMap, FileOffset, Length, ToPin);
    /* Yes, and we've lost */
    if (DupBcb != NULL)
    {
        /* We will return that BCB */
        ++DupBcb->RefCount;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        /* Delete the loser */
        ExDeleteResourceLite(&iBcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);

        if (ToPin)
        {
            /* Pin the winner, as if the caller had found it */
            if (BooleanFlagOn(PinFlags, PIN_EXCLUSIVE))
            {
                Result = ExAcquireResourceExclusiveLite(&DupBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }
            else
            {
                Result = ExAcquireSharedStarveExclusive(&DupBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }

            if (!Result)
            {
                /* The caller still owns its VACB reference */
                CcpDereferenceBcb(SharedCacheMap, DupBcb);
                return NULL;
            }

            /* PinCount is serialized by BcbSpinLock (see CcpDereferenceBcb). */
            KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
            DupBcb->PinCount++;
            if (BooleanFlagOn(PinFlags, PIN_EXCLUSIVE))
                DupBcb->PinWrite |= CC_BCB_WRITE_EXCLUSIVE;
            KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
        }

        /* The winner holds its own VACB reference */
        CcRosReleaseVacb(SharedCacheMap, Vacb, FALSE, FALSE);

        /* Return the winner - no need to update buffer address, it's
         * relative to the VACB, which is unchanged.
         */
        iBcb = DupBcb;
    }
    /* A pinned BCB appeared that partially overlaps the range since the
     * caller looked: linking ours would break the no-overlap invariant of
     * pinned BCBs. Let the caller start over (it releases its VACB). */
    else if (ToPin &&
             CcpCountPinnedOverlaps(SharedCacheMap,
                                    FileOffset->QuadPart,
                                    FileOffset->QuadPart + Length) != 0)
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        ExDeleteResourceLite(&iBcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);

        *Retry = TRUE;
        return NULL;
    }
    /* Nope, insert ourselves */
    else
    {
        if (ToPin)
        {
            iBcb->PinCount++;

            if (BooleanFlagOn(PinFlags, PIN_EXCLUSIVE))
            {
                iBcb->PinWrite |= CC_BCB_WRITE_EXCLUSIVE;
                Result = ExAcquireResourceExclusiveLite(&iBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }
            else
            {
                Result = ExAcquireSharedStarveExclusive(&iBcb->Lock, BooleanFlagOn(PinFlags, PIN_WAIT));
            }

            ASSERT(Result);
        }

        InsertTailList(&SharedCacheMap->BcbList, &iBcb->BcbEntry);
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }

    return iBcb;
}

/*
 * Build the overlap BCB of a pin of [FileOffset, FileOffset + Length) that is
 * not contained in one pinned BCB but overlaps at least one. Called with
 * BcbSpinLock held and returns with it held: the overlapped BCBs are found,
 * referenced and the gaps between them covered by new pinned BCBs linked into
 * BcbList in one hold, so the result cannot race another pin of the range.
 * Everything here is legal at DISPATCH_LEVEL: nonpaged allocations, resource
 * initialization, and the gap BCBs' VACB references, taken on the VACB the
 * overlapped BCBs already reference (a pin never spans VACBs). The member
 * locks are not acquired here - see CcpAcquireObcb.
 * Returns NULL if out of memory, or with PIN_IF_BCB if the range has gaps.
 */
static
PINTERNAL_OBCB
CcpCreateObcb(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG Flags)
{
    LONGLONG Start = FileOffset->QuadPart, End = FileOffset->QuadPart + Length;
    LONGLONG Cursor, GapEnd;
    ULONG Overlaps, Gaps, Count, i, j;
    PINTERNAL_OBCB Obcb;
    PINTERNAL_BCB Bcb, *Sorted;
    PROS_VACB Vacb;
    PLIST_ENTRY NextEntry;
    LIST_ENTRY GapList;

    Overlaps = CcpCountPinnedOverlaps(SharedCacheMap, Start, End);
    ASSERT(Overlaps != 0);

    /* N non-overlapping BCBs leave at most N + 1 gaps in the range: room for
     * the result (2N + 1) and, behind it, the overlapped BCBs sorted (N). */
    Obcb = ExAllocatePoolWithTag(NonPagedPool,
                                 FIELD_OFFSET(INTERNAL_OBCB, Bcbs) +
                                     (3 * Overlaps + 1) * sizeof(PINTERNAL_BCB),
                                 TAG_BCB);
    if (Obcb == NULL)
    {
        return NULL;
    }
    Sorted = &Obcb->Bcbs[2 * Overlaps + 1];

    /* Collect the overlapped BCBs in ascending offset order */
    Count = 0;
    for (NextEntry = SharedCacheMap->BcbList.Flink;
         NextEntry != &SharedCacheMap->BcbList;
         NextEntry = NextEntry->Flink)
    {
        Bcb = CONTAINING_RECORD(NextEntry, INTERNAL_BCB, BcbEntry);
        if (!CcpPinnedBcbOverlaps(Bcb, Start, End))
            continue;

        for (i = Count;
             i > 0 && Sorted[i - 1]->PFCB.MappedFileOffset.QuadPart > Bcb->PFCB.MappedFileOffset.QuadPart;
             i--)
        {
            Sorted[i] = Sorted[i - 1];
        }
        Sorted[i] = Bcb;
        Count++;
    }
    ASSERT(Count == Overlaps);

    Vacb = Sorted[0]->Vacb;

    /* Count the gaps */
    Gaps = 0;
    Cursor = Start;
    for (i = 0; i < Count; i++)
    {
        ASSERT(Sorted[i]->Vacb == Vacb);
        ASSERT(i == 0 || Sorted[i]->PFCB.MappedFileOffset.QuadPart >= Cursor);
        if (Sorted[i]->PFCB.MappedFileOffset.QuadPart > Cursor)
            Gaps++;
        Cursor = Sorted[i]->PFCB.MappedFileOffset.QuadPart + Sorted[i]->PFCB.MappedLength;
    }
    if (Cursor < End)
        Gaps++;

    /* PIN_IF_BCB only pins what is already pinned */
    if (Gaps != 0 && BooleanFlagOn(Flags, PIN_IF_BCB))
    {
        ExFreePoolWithTag(Obcb, TAG_BCB);
        return NULL;
    }

    /* Allocate the gap BCBs before changing anything, so failing is clean */
    InitializeListHead(&GapList);
    for (i = 0; i < Gaps; i++)
    {
        Bcb = ExAllocateFromNPagedLookasideList(&iBcbLookasideList);
        if (Bcb == NULL)
        {
            while (!IsListEmpty(&GapList))
            {
                Bcb = CONTAINING_RECORD(RemoveHeadList(&GapList), INTERNAL_BCB, BcbEntry);
                ExDeleteResourceLite(&Bcb->Lock);
                ExFreeToNPagedLookasideList(&iBcbLookasideList, Bcb);
            }
            ExFreePoolWithTag(Obcb, TAG_BCB);
            return NULL;
        }

        RtlZeroMemory(Bcb, sizeof(*Bcb));
        Bcb->PFCB.NodeTypeCode = CC_NTC_BCB;
        Bcb->PFCB.NodeByteSize = 0;
        Bcb->Vacb = Vacb;
        Bcb->PinCount = 0;
        Bcb->RefCount = 1; /* the overlap BCB's */
        Bcb->Pinned = TRUE;
        ExInitializeResourceLite(&Bcb->Lock);
        InsertTailList(&GapList, &Bcb->BcbEntry);
    }

    /* Merge: gap, overlapped BCB, gap, ... in ascending order. The gap BCBs
     * are linked unlocked: a pin that finds one before we lock it simply
     * goes first, like with any other member. */
    Cursor = Start;
    j = 0;
    for (i = 0; i <= Count; i++)
    {
        GapEnd = (i < Count) ? Sorted[i]->PFCB.MappedFileOffset.QuadPart : End;
        if (GapEnd > Cursor)
        {
            ASSERT(!IsListEmpty(&GapList));
            Bcb = CONTAINING_RECORD(RemoveHeadList(&GapList), INTERNAL_BCB, BcbEntry);
            Bcb->PFCB.MappedFileOffset.QuadPart = Cursor;
            Bcb->PFCB.MappedLength = (ULONG)(GapEnd - Cursor);
            CcRosVacbIncRefCount(Vacb);
            InsertTailList(&SharedCacheMap->BcbList, &Bcb->BcbEntry);
            Obcb->Bcbs[j++] = Bcb;
        }

        if (i < Count)
        {
            Bcb = Sorted[i];
            ++Bcb->RefCount;
            Obcb->Bcbs[j++] = Bcb;
            Cursor = Bcb->PFCB.MappedFileOffset.QuadPart + Bcb->PFCB.MappedLength;
        }
    }
    ASSERT(IsListEmpty(&GapList));
    ASSERT(j == Count + Gaps);

    Obcb->PFCB.NodeTypeCode = CC_NTC_OBCB;
    Obcb->PFCB.NodeByteSize = 0;
    Obcb->PFCB.MappedLength = Length;
    Obcb->PFCB.MappedFileOffset = *FileOffset;
    Obcb->RefCount = 1;
    Obcb->Pinned = FALSE;
    Obcb->Count = j;

    return Obcb;
}

/* Release one pin's acquisition of every member lock, last first */
static
VOID
CcpUnpinObcbMembers(
    IN PINTERNAL_OBCB Obcb,
    IN ULONG Count,
    IN ERESOURCE_THREAD ResourceThreadId)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap = Obcb->Bcbs[0]->Vacb->SharedCacheMap;
    PINTERNAL_BCB Bcb;
    BOOLEAN Pinned, Redirty;
    KIRQL OldIrql;

    while (Count-- > 0)
    {
        Bcb = Obcb->Bcbs[Count];

        /* Same discipline as CcUnpinDataForThread */
        Redirty = FALSE;
        KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
        Pinned = (Bcb->PinCount != 0);
        if (Pinned)
        {
            Bcb->PinCount--;
            Redirty = CcpEndPinWrite(Bcb);
        }
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (Redirty)
        {
            CcpRedirtyBcb(Bcb);
        }

        ASSERT(Pinned);
        if (Pinned)
        {
            ExReleaseResourceForThreadLite(&Bcb->Lock, ResourceThreadId);
        }
    }
}

/* Drop a reference to an overlap BCB; the last one releases the member locks
 * if the pin still holds them (CcUnpinRepinnedBcb without CcUnpinData, like
 * the INTERNAL_BCB path), dereferences the members and frees it. */
static
VOID
CcpDereferenceObcb(
    IN PINTERNAL_OBCB Obcb)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap = Obcb->Bcbs[0]->Vacb->SharedCacheMap;
    ULONG i;

    if (InterlockedDecrement(&Obcb->RefCount) != 0)
    {
        return;
    }

    if (InterlockedExchange(&Obcb->Pinned, FALSE))
    {
        CcpUnpinObcbMembers(Obcb, Obcb->Count, (ERESOURCE_THREAD)PsGetCurrentThread());
    }

    for (i = 0; i < Obcb->Count; i++)
    {
        CcpDereferenceBcb(SharedCacheMap, Obcb->Bcbs[i]);
    }

    ExFreePoolWithTag(Obcb, TAG_BCB);
}

/* Acquire the member locks in ascending file offset order. Every multi-BCB
 * pin uses this order, so two of them cannot deadlock each other; a pin that
 * cannot wait backs out completely. On failure the overlap BCB is gone. */
static
BOOLEAN
CcpAcquireObcb(
    IN PINTERNAL_OBCB Obcb,
    IN ULONG Flags)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap = Obcb->Bcbs[0]->Vacb->SharedCacheMap;
    PINTERNAL_BCB Bcb;
    BOOLEAN Result;
    KIRQL OldIrql;
    ULONG i;

    for (i = 0; i < Obcb->Count; i++)
    {
        Bcb = Obcb->Bcbs[i];

        if (BooleanFlagOn(Flags, PIN_EXCLUSIVE))
            Result = ExAcquireResourceExclusiveLite(&Bcb->Lock, BooleanFlagOn(Flags, PIN_WAIT));
        else
            Result = ExAcquireSharedStarveExclusive(&Bcb->Lock, BooleanFlagOn(Flags, PIN_WAIT));

        if (!Result)
        {
            CcpUnpinObcbMembers(Obcb, i, (ERESOURCE_THREAD)PsGetCurrentThread());
            CcpDereferenceObcb(Obcb);
            return FALSE;
        }

        KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
        Bcb->PinCount++;
        if (BooleanFlagOn(Flags, PIN_EXCLUSIVE))
            Bcb->PinWrite |= CC_BCB_WRITE_EXCLUSIVE;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }

    Obcb->Pinned = TRUE;
    return TRUE;
}

static
BOOLEAN
CcpPinData(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    PINTERNAL_BCB NewBcb;
    PINTERNAL_OBCB Obcb;
    PPUBLIC_BCB Handle;
    PROS_VACB Vacb;
    KIRQL OldIrql;
    ULONG VacbOffset;
    NTSTATUS Status;
    BOOLEAN Retry;
    _SEH2_VOLATILE BOOLEAN Result;

    VacbOffset = (ULONG)(FileOffset->QuadPart % VACB_MAPPING_GRANULARITY);

    if ((VacbOffset + Length) > VACB_MAPPING_GRANULARITY)
    {
        /* Complain loudly, we shoud pin the whole range */
        DPRINT1("TRUNCATING DATA PIN FROM %lu to %lu!\n", Length, VACB_MAPPING_GRANULARITY - VacbOffset);
        Length = VACB_MAPPING_GRANULARITY - VacbOffset;
    }

TryAgain:
    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    NewBcb = CcpFindBcb(SharedCacheMap, FileOffset, Length, TRUE);

    if (NewBcb != NULL)
    {
        BOOLEAN Result;

        ++NewBcb->RefCount;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (BooleanFlagOn(Flags, PIN_EXCLUSIVE))
            Result = ExAcquireResourceExclusiveLite(&NewBcb->Lock, BooleanFlagOn(Flags, PIN_WAIT));
        else
            Result = ExAcquireSharedStarveExclusive(&NewBcb->Lock, BooleanFlagOn(Flags, PIN_WAIT));

        if (!Result)
        {
            CcpDereferenceBcb(SharedCacheMap, NewBcb);
            return FALSE;
        }

        /* PinCount is serialized by BcbSpinLock (see CcpDereferenceBcb). */
        KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
        NewBcb->PinCount++;
        if (BooleanFlagOn(Flags, PIN_EXCLUSIVE))
            NewBcb->PinWrite |= CC_BCB_WRITE_EXCLUSIVE;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        Handle = &NewBcb->PFCB;
        Vacb = NewBcb->Vacb;
    }
    else if (CcpCountPinnedOverlaps(SharedCacheMap,
                                    FileOffset->QuadPart,
                                    FileOffset->QuadPart + Length) != 0)
    {
        /* The range partially overlaps pinned BCBs: one overlap BCB over all
         * of them, so this pin excludes (or shares with) each of their pins */
        Obcb = CcpCreateObcb(SharedCacheMap, FileOffset, Length, Flags);
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (Obcb == NULL)
        {
            return FALSE;
        }

        if (!CcpAcquireObcb(Obcb, Flags))
        {
            return FALSE;
        }

        Handle = &Obcb->PFCB;
        Vacb = Obcb->Bcbs[0]->Vacb;
    }
    else
    {
        LONGLONG ROffset;

        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (BooleanFlagOn(Flags, PIN_IF_BCB))
        {
            return FALSE;
        }

        /* Properly round offset and call internal helper for getting a VACB */
        ROffset = ROUND_DOWN(FileOffset->QuadPart, VACB_MAPPING_GRANULARITY);
        Status = CcRosGetVacb(SharedCacheMap, ROffset, &Vacb);
        if (!NT_SUCCESS(Status))
        {
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                SharedCacheMap->FileObject, FileOffset, Length, Flags);
            ExRaiseStatus(Status);
            return FALSE;
        }

        NewBcb = CcpGetAppropriateBcb(SharedCacheMap, Vacb, FileOffset, Length, Flags, TRUE, &Retry);
        if (NewBcb == NULL)
        {
            CcRosReleaseVacb(SharedCacheMap, Vacb, FALSE, FALSE);
            if (Retry)
            {
                /* A partially overlapping pinned BCB appeared meanwhile */
                goto TryAgain;
            }
            return FALSE;
        }

        Handle = &NewBcb->PFCB;
        Vacb = NewBcb->Vacb;
    }

    Result = FALSE;
    _SEH2_TRY
    {
        /* Ensure the pages are resident */
        Result = CcRosEnsureVacbResident(Vacb,
                BooleanFlagOn(Flags, PIN_WAIT),
                BooleanFlagOn(Flags, PIN_NO_READ),
                VacbOffset, Length, FALSE);
    }
    _SEH2_FINALLY
    {
        if (!Result)
        {
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                            SharedCacheMap->FileObject, FileOffset, Length, Flags);
            CcUnpinData(Handle);
            *Bcb = NULL;
            *Buffer = NULL;
        }
    }
    _SEH2_END;

    if (Result)
    {
        *Bcb = Handle;
        *Buffer = (PVOID)((ULONG_PTR)Vacb->BaseAddress + VacbOffset);
    }

    return Result;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
CcMapData (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG Flags,
    OUT PVOID *pBcb,
    OUT PVOID *pBuffer)
{
    KIRQL OldIrql;
    PINTERNAL_BCB iBcb;
    PROS_VACB Vacb;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    ULONG VacbOffset;
    NTSTATUS Status;
    BOOLEAN Retry;
    _SEH2_VOLATILE BOOLEAN Result;

    CCTRACE(CC_API_DEBUG, "CcMapData(FileObject 0x%p, FileOffset 0x%I64x, Length %lu, Flags 0x%lx,"
           " pBcb 0x%p, pBuffer 0x%p)\n", FileObject, FileOffset->QuadPart,
           Length, Flags, pBcb, pBuffer);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);

    if (Flags & MAP_WAIT)
    {
        ++CcMapDataWait;
    }
    else
    {
        ++CcMapDataNoWait;
    }

    VacbOffset = (ULONG)(FileOffset->QuadPart % VACB_MAPPING_GRANULARITY);
    /* KMTests seem to show that it is allowed to call accross mapping granularity */
    if ((VacbOffset + Length) > VACB_MAPPING_GRANULARITY)
    {
        DPRINT1("TRUNCATING DATA MAP FROM %lu to %lu!\n", Length, VACB_MAPPING_GRANULARITY - VacbOffset);
        Length = VACB_MAPPING_GRANULARITY - VacbOffset;
    }

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    iBcb = CcpFindBcb(SharedCacheMap, FileOffset, Length, FALSE);

    if (iBcb == NULL)
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        /* Call internal helper for getting a VACB */
        Status = CcRosGetVacb(SharedCacheMap, FileOffset->QuadPart, &Vacb);
        if (!NT_SUCCESS(Status))
        {
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                SharedCacheMap->FileObject, FileOffset, Length, Flags);
            ExRaiseStatus(Status);
        }

        iBcb = CcpGetAppropriateBcb(SharedCacheMap, Vacb, FileOffset, Length, 0, FALSE, &Retry);
        if (iBcb == NULL)
        {
            CcRosReleaseVacb(SharedCacheMap, Vacb, FALSE, FALSE);
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                SharedCacheMap->FileObject, FileOffset, Length, Flags);
            *pBcb = NULL; // If you ever remove this for compat, make sure to review all callers for using an unititialized value
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    else
    {
        ++iBcb->RefCount;
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }

    _SEH2_TRY
    {
        Result = FALSE;
        /* Ensure the pages are resident */
        Result = CcRosEnsureVacbResident(iBcb->Vacb, BooleanFlagOn(Flags, MAP_WAIT),
                BooleanFlagOn(Flags, MAP_NO_READ), VacbOffset, Length, FALSE);
    }
    _SEH2_FINALLY
    {
        if (!Result)
        {
            CcpDereferenceBcb(SharedCacheMap, iBcb);
            *pBcb = NULL;
            *pBuffer = NULL;
        }
    }
    _SEH2_END;

    if (Result)
    {
        *pBcb = &iBcb->PFCB;
        *pBuffer = (PVOID)((ULONG_PTR)iBcb->Vacb->BaseAddress + VacbOffset);
    }

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> TRUE Bcb=%p, Buffer %p\n",
        FileObject, FileOffset, Length, Flags, *pBcb, *pBuffer);
    return Result;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPinMappedData (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	ULONG Flags,
    OUT	PVOID * Bcb)
{
    BOOLEAN Result;
    PVOID Buffer;
    PINTERNAL_BCB iBcb;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx\n",
        FileObject, FileOffset, Length, Flags);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);
    if (!SharedCacheMap->PinAccess)
    {
        DPRINT1("FIXME: Pinning a file with no pin access!\n");
        return FALSE;
    }

    iBcb = *Bcb ? CONTAINING_RECORD(*Bcb, INTERNAL_BCB, PFCB) : NULL;

    ++CcPinMappedDataCount;

    Result = CcpPinData(SharedCacheMap, FileOffset, Length, Flags, Bcb, &Buffer);

    /* Drop the reference of the mapped BCB that was passed in, if there was one.
     * PFCB follows the ERESOURCE in INTERNAL_BCB, so &iBcb->PFCB of a NULL iBcb
     * is not NULL and CcUnpinData would dereference garbage. */
    if (Result && iBcb != NULL)
    {
        CcUnpinData(&iBcb->PFCB);
    }

    return Result;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPinRead (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Flags=0x%lx\n",
        FileObject, FileOffset, Length, Flags);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);
    if (!SharedCacheMap->PinAccess)
    {
        DPRINT1("FIXME: Pinning a file with no pin access!\n");
        return FALSE;
    }

    if (Flags & PIN_WAIT)
    {
        ++CcPinReadWait;
    }
    else
    {
        ++CcPinReadNoWait;
    }

    return CcpPinData(SharedCacheMap, FileOffset, Length, Flags, Bcb, Buffer);
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPreparePinWrite (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	BOOLEAN Zero,
    IN	ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Zero=%d Flags=0x%lx\n",
        FileObject, FileOffset, Length, Zero, Flags);

    /*
     * FIXME: This is function is similar to CcPinRead, but doesn't
     * read the data if they're not present. Instead it should just
     * prepare the VACBs and zero them out if Zero != FALSE.
     *
     * For now calling CcPinRead is better than returning error or
     * just having UNIMPLEMENTED here.
     */
    return CcPinRead(FileObject, FileOffset, Length, Flags, Bcb, Buffer);
}

/* A pinned range made dirty is held back from the lazy write until its last
 * pin goes (CC_BCB_WRITE_DIRTY); a mapped BCB (CcMapData) is not pinned */
static
VOID
CcpSetPinWriteDirty(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PINTERNAL_BCB Bcb)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    if (Bcb->Pinned && (Bcb->PinCount != 0 || Bcb->RepinCount != 0))
    {
        Bcb->PinWrite |= CC_BCB_WRITE_DIRTY;
    }
    KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
}

/*
 * @implemented
 */
VOID NTAPI
CcSetDirtyPinnedData (
    IN PVOID Bcb,
    IN PLARGE_INTEGER Lsn)
{
    PPUBLIC_BCB PublicBcb = Bcb;
    PROS_VACB Vacb;
    PINTERNAL_OBCB Obcb;
    ULONG i;

    CCTRACE(CC_API_DEBUG, "Bcb=%p Lsn=%p\n", Bcb, Lsn);

    /* All BCBs of an overlap BCB share the VACB; dirty the pinned range */
    if (PublicBcb->NodeTypeCode == CC_NTC_OBCB)
    {
        Obcb = CONTAINING_RECORD(Bcb, INTERNAL_OBCB, PFCB);
        Vacb = Obcb->Bcbs[0]->Vacb;
        for (i = 0; i < Obcb->Count; i++)
        {
            CcpSetPinWriteDirty(Vacb->SharedCacheMap, Obcb->Bcbs[i]);
        }
    }
    else
    {
        Vacb = CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB)->Vacb;
        CcpSetPinWriteDirty(Vacb->SharedCacheMap, CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB));
    }

    /* Tell Mm */
    MmMakeSegmentDirty(Vacb->SharedCacheMap->FileObject->SectionObjectPointer,
                       PublicBcb->MappedFileOffset.QuadPart,
                       PublicBcb->MappedLength);

    if (!Vacb->Dirty)
    {
        CcRosMarkDirtyVacb(Vacb);
    }
}


/*
 * @implemented
 */
VOID NTAPI
CcUnpinData (
    IN PVOID Bcb)
{
    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    CcUnpinDataForThread(Bcb, (ERESOURCE_THREAD)PsGetCurrentThread());
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcUnpinDataForThread (
    IN	PVOID Bcb,
    IN	ERESOURCE_THREAD ResourceThreadId)
{
    PINTERNAL_BCB iBcb;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    KIRQL OldIrql;
    BOOLEAN Pinned, Redirty = FALSE;

    CCTRACE(CC_API_DEBUG, "Bcb=%p ResourceThreadId=%lu\n", Bcb, ResourceThreadId);

    if (((PPUBLIC_BCB)Bcb)->NodeTypeCode == CC_NTC_OBCB)
    {
        PINTERNAL_OBCB Obcb = CONTAINING_RECORD(Bcb, INTERNAL_OBCB, PFCB);

        /* The pin's member locks go once; a repinned overlap BCB stays
         * referenced until CcUnpinRepinnedBcb */
        if (InterlockedExchange(&Obcb->Pinned, FALSE))
        {
            CcpUnpinObcbMembers(Obcb, Obcb->Count, ResourceThreadId);
        }
        CcpDereferenceObcb(Obcb);
        return;
    }

    iBcb = CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB);
    SharedCacheMap = iBcb->Vacb->SharedCacheMap;

    /* Test-and-decrement PinCount under BcbSpinLock so the counter stays
     * coherent with concurrent pin/unpin on other CPUs. Without this the
     * non-atomic decrement can race a non-atomic increment and lose an
     * update, leaving PinCount != 0 when the last reference is dropped
     * (ASSERT(Bcb->PinCount == 0) bugcheck in CcpDereferenceBcb). */
    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    Pinned = (iBcb->PinCount != 0);
    if (Pinned)
    {
        iBcb->PinCount--;
        Redirty = CcpEndPinWrite(iBcb);
    }
    KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

    if (Redirty)
    {
        CcpRedirtyBcb(iBcb);
    }

    /* Release the resource outside the spinlock: this unpin owns one
     * acquisition of the ERESOURCE and the resource has its own locking. */
    if (Pinned)
    {
        ExReleaseResourceForThreadLite(&iBcb->Lock, ResourceThreadId);
    }

    CcpDereferenceBcb(SharedCacheMap, iBcb);
}

/*
 * @implemented
 */
VOID
NTAPI
CcRepinBcb (
    IN	PVOID Bcb)
{
    PINTERNAL_BCB iBcb;
    KIRQL OldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    if (((PPUBLIC_BCB)Bcb)->NodeTypeCode == CC_NTC_OBCB)
    {
        PINTERNAL_OBCB Obcb = CONTAINING_RECORD(Bcb, INTERNAL_OBCB, PFCB);
        ULONG i;

        /* The overlap BCB holds a reference on each member; the members
         * stay pinned for the lazy writer until CcUnpinRepinnedBcb */
        InterlockedIncrement(&Obcb->RefCount);
        SharedCacheMap = Obcb->Bcbs[0]->Vacb->SharedCacheMap;
        KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
        for (i = 0; i < Obcb->Count; i++)
        {
            Obcb->Bcbs[i]->RepinCount++;
        }
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
        return;
    }

    iBcb = CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB);
    SharedCacheMap = iBcb->Vacb->SharedCacheMap;

    /* RefCount is always serialized by BcbSpinLock (see CcpDereferenceBcb);
     * an unlocked increment can lose an update against a concurrent
     * dereference and free the BCB early or leak it. A repinned BCB is still
     * pinned (for writing, if it was) until CcUnpinRepinnedBcb. */
    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    iBcb->RefCount++;
    iBcb->RepinCount++;
    KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
}

/* CcUnpinRepinnedBcb: one repin of the BCB goes, before the write-through
 * flush, so that a range made dirty under the pin is marked again first */
static
VOID
CcpEndRepin(
    IN PROS_SHARED_CACHE_MAP SharedCacheMap,
    IN PINTERNAL_BCB Bcb)
{
    BOOLEAN Redirty = FALSE;
    KIRQL OldIrql;

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    ASSERT(Bcb->RepinCount != 0);
    if (Bcb->RepinCount != 0)
    {
        Bcb->RepinCount--;
        Redirty = CcpEndPinWrite(Bcb);
    }
    KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

    if (Redirty)
    {
        CcpRedirtyBcb(Bcb);
    }
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcUnpinRepinnedBcb (
    IN	PVOID Bcb,
    IN	BOOLEAN WriteThrough,
    IN	PIO_STATUS_BLOCK IoStatus)
{
    PINTERNAL_BCB iBcb;
    KIRQL OldIrql;
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "Bcb=%p WriteThrough=%d\n", Bcb, WriteThrough);

    if (((PPUBLIC_BCB)Bcb)->NodeTypeCode == CC_NTC_OBCB)
    {
        PINTERNAL_OBCB Obcb = CONTAINING_RECORD(Bcb, INTERNAL_OBCB, PFCB);
        ULONG i;

        for (i = 0; i < Obcb->Count; i++)
        {
            CcpEndRepin(Obcb->Bcbs[0]->Vacb->SharedCacheMap, Obcb->Bcbs[i]);
        }

        if (WriteThrough)
        {
            CcFlushCache(Obcb->Bcbs[0]->Vacb->SharedCacheMap->FileObject->SectionObjectPointer,
                         &Obcb->PFCB.MappedFileOffset,
                         Obcb->PFCB.MappedLength,
                         IoStatus);
        }
        else
        {
            IoStatus->Status = STATUS_SUCCESS;
            IoStatus->Information = 0;
        }

        CcpDereferenceObcb(Obcb);
        return;
    }

    iBcb = CONTAINING_RECORD(Bcb, INTERNAL_BCB, PFCB);

    SharedCacheMap = iBcb->Vacb->SharedCacheMap;
    IoStatus->Status = STATUS_SUCCESS;

    CcpEndRepin(SharedCacheMap, iBcb);

    if (WriteThrough)
    {
        CcFlushCache(iBcb->Vacb->SharedCacheMap->FileObject->SectionObjectPointer,
                     &iBcb->PFCB.MappedFileOffset,
                     iBcb->PFCB.MappedLength,
                     IoStatus);
    }
    else
    {
        IoStatus->Status = STATUS_SUCCESS;
        IoStatus->Information = 0;
    }

    KeAcquireSpinLock(&SharedCacheMap->BcbSpinLock, &OldIrql);
    if (--iBcb->RefCount == 0)
    {
        BOOLEAN Pinned;

        RemoveEntryList(&iBcb->BcbEntry);
        /* Read PinCount while still holding BcbSpinLock, like the other
         * PinCount accesses; the BCB is unreachable once unlinked. */
        Pinned = (iBcb->PinCount != 0);
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);

        if (Pinned)
        {
            ExReleaseResourceLite(&iBcb->Lock);
            iBcb->PinCount--;
            ASSERT(iBcb->PinCount == 0);
            /* Unlinked: nothing else sees the BCB any more */
            if (CcpEndPinWrite(iBcb))
            {
                CcpRedirtyBcb(iBcb);
            }
        }

        /*
         * Don't mark dirty, if it was dirty,
         * the VACB was already marked as such
         * following the call to CcSetDirtyPinnedData
         */
        CcRosReleaseVacb(iBcb->Vacb->SharedCacheMap,
                         iBcb->Vacb,
                         FALSE,
                         FALSE);

        ExDeleteResourceLite(&iBcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
    }
    else
    {
        KeReleaseSpinLock(&SharedCacheMap->BcbSpinLock, OldIrql);
    }
}
