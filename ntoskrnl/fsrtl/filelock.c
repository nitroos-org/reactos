/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/fsrtl/filelock.c
 * PURPOSE:         File Locking implementation for File System Drivers
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

PAGED_LOOKASIDE_LIST FsRtlFileLockLookasideList;

/* Note: this aligns the two types of lock entry structs so we can access the
   FILE_LOCK_INFO part in common.  Add elements after Shared if new stuff is needed.
*/
typedef union _COMBINED_LOCK_ELEMENT
{
    struct
    {
        LIST_ENTRY dummy;
        FILE_SHARED_LOCK_ENTRY Shared;
    };
    FILE_EXCLUSIVE_LOCK_ENTRY Exclusive;
}
    COMBINED_LOCK_ELEMENT, *PCOMBINED_LOCK_ELEMENT;

typedef struct _LOCK_INFORMATION
{
    RTL_GENERIC_TABLE RangeTable;
    IO_CSQ Csq;
    KSPIN_LOCK CsqLock;
    LIST_ENTRY CsqList;
    PFILE_LOCK BelongsTo;
    LIST_ENTRY SharedLocks;
    ULONG Generation;
    /* Guards RangeTable, SharedLocks and Generation; lookups splay the table, so readers take it too.
       A spin lock, because callers may run at APC_LEVEL. Ordered before CsqLock. */
    KSPIN_LOCK RangeLock;
    PKTHREAD RangeLockOwner;
    PLIST_ENTRY DeferredIrps;
    /* Nonpaged copy for the cancel routine, which may run at DISPATCH_LEVEL; FILE_LOCK may be paged */
    PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine;
}
    LOCK_INFORMATION, *PLOCK_INFORMATION;

typedef struct _LOCK_SHARED_RANGE
{
    LIST_ENTRY Entry;
    LARGE_INTEGER Start, End;
    ULONG Key;
    PVOID ProcessId;
    /* The file object that took the lock: a lock belongs to a file object (and process and key) */
    PFILE_OBJECT FileObject;
}
    LOCK_SHARED_RANGE, *PLOCK_SHARED_RANGE;

/* PRIVATE FUNCTIONS *********************************************************/

VOID
NTAPI
FsRtlCompleteLockIrpReal(IN PCOMPLETE_LOCK_IRP_ROUTINE CompleteRoutine,
                         IN PVOID Context,
                         IN PIRP Irp,
                         IN NTSTATUS Status,
                         OUT PNTSTATUS NewStatus,
                         IN PFILE_OBJECT FileObject OPTIONAL);

/* Generic table methods */

static PVOID NTAPI LockAllocate(PRTL_GENERIC_TABLE Table, CLONG Bytes)
{
    PVOID Result;
    Result = ExAllocatePoolWithTag(NonPagedPool, Bytes, TAG_TABLE);
    DPRINT("LockAllocate(%lu) => %p\n", Bytes, Result);
    return Result;
}

static VOID NTAPI LockFree(PRTL_GENERIC_TABLE Table, PVOID Buffer)
{
    DPRINT("LockFree(%p)\n", Buffer);
    ExFreePoolWithTag(Buffer, TAG_TABLE);
}

static RTL_GENERIC_COMPARE_RESULTS NTAPI LockCompare
(PRTL_GENERIC_TABLE Table, PVOID PtrA, PVOID PtrB)
{
    PCOMBINED_LOCK_ELEMENT A = PtrA, B = PtrB;
    RTL_GENERIC_COMPARE_RESULTS Result;
#if 0
    DPRINT("Starting to compare element %x to element %x\n", PtrA, PtrB);
#endif
    /* Match if we overlap. Byte offsets are unsigned: a whole-file lock ends at the
       unsigned 64-bit maximum, which a signed compare reads as negative and misses. */
    if ((((ULONGLONG)A->Exclusive.FileLock.StartingByte.QuadPart <
          (ULONGLONG)B->Exclusive.FileLock.EndingByte.QuadPart) &&
         ((ULONGLONG)A->Exclusive.FileLock.StartingByte.QuadPart >=
          (ULONGLONG)B->Exclusive.FileLock.StartingByte.QuadPart)) ||
        (((ULONGLONG)B->Exclusive.FileLock.StartingByte.QuadPart <
          (ULONGLONG)A->Exclusive.FileLock.EndingByte.QuadPart) &&
         ((ULONGLONG)B->Exclusive.FileLock.StartingByte.QuadPart >=
          (ULONGLONG)A->Exclusive.FileLock.StartingByte.QuadPart)))
        return GenericEqual;
    /* Otherwise, key on the starting byte */
    Result =
        (A->Exclusive.FileLock.StartingByte.QuadPart <
         B->Exclusive.FileLock.StartingByte.QuadPart) ? GenericLessThan :
        (A->Exclusive.FileLock.StartingByte.QuadPart >
         B->Exclusive.FileLock.StartingByte.QuadPart) ? GenericGreaterThan :
        GenericEqual;
#if 0
    DPRINT("Compare(%x:%x) %x-%x to %x-%x => %d\n",
           A,B,
           A->Exclusive.FileLock.StartingByte.LowPart,
           A->Exclusive.FileLock.EndingByte.LowPart,
           B->Exclusive.FileLock.StartingByte.LowPart,
           B->Exclusive.FileLock.EndingByte.LowPart,
           Result);
#endif
    return Result;
}

/* CSQ methods */

static NTSTATUS NTAPI LockInsertIrpEx
(PIO_CSQ Csq,
 PIRP Irp,
 PVOID InsertContext)
{
    PLOCK_INFORMATION LockInfo = CONTAINING_RECORD(Csq, LOCK_INFORMATION, Csq);
    InsertTailList(&LockInfo->CsqList, &Irp->Tail.Overlay.ListEntry);
    return STATUS_SUCCESS;
}

static VOID NTAPI LockRemoveIrp(PIO_CSQ Csq, PIRP Irp)
{
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static PIRP NTAPI LockPeekNextIrp(PIO_CSQ Csq, PIRP Irp, PVOID PeekContext)
{
    // Context will be a COMBINED_LOCK_ELEMENT.  We're looking for a
    // lock that can be acquired, now that the lock matching PeekContext
    // has been removed.
    COMBINED_LOCK_ELEMENT LockElement;
    PCOMBINED_LOCK_ELEMENT WhereUnlock = PeekContext;
    PLOCK_INFORMATION LockInfo = CONTAINING_RECORD(Csq, LOCK_INFORMATION, Csq);
    PLIST_ENTRY Following;
    DPRINT("PeekNextIrp(IRP %p, Context %p)\n", Irp, PeekContext);
    if (!Irp)
    {
        Following = LockInfo->CsqList.Flink;
    }
    else
        Following = Irp->Tail.Overlay.ListEntry.Flink;

    DPRINT("ListEntry %p Head %p\n", Following, &LockInfo->CsqList);
    for (;
         Following != &LockInfo->CsqList;
         Following = Following->Flink)
    {
        PIO_STACK_LOCATION IoStack;
        BOOLEAN Matching;
        Irp = CONTAINING_RECORD(Following, IRP, Tail.Overlay.ListEntry);
        DPRINT("Irp %p\n", Irp);
        IoStack = IoGetCurrentIrpStackLocation(Irp);
        LockElement.Exclusive.FileLock.StartingByte =
            IoStack->Parameters.LockControl.ByteOffset;
        LockElement.Exclusive.FileLock.EndingByte.QuadPart =
            LockElement.Exclusive.FileLock.StartingByte.QuadPart +
            IoStack->Parameters.LockControl.Length->QuadPart;
        /* If a context was specified, it's a range to check to unlock */
        if (WhereUnlock)
        {
            Matching = LockCompare
                (&LockInfo->RangeTable, &LockElement, WhereUnlock) != GenericEqual;
        }
        /* Else get any completable IRP */
        else
        {
            Matching = FALSE;
        }
        if (!Matching)
        {
            // This IRP is fine...
            DPRINT("Returning the IRP %p\n", Irp);
            return Irp;
        }
    }
    DPRINT("Return NULL\n");
    return NULL;
}

static VOID NTAPI
LockAcquireQueueLock(PIO_CSQ Csq, PKIRQL Irql)
{
    PLOCK_INFORMATION LockInfo = CONTAINING_RECORD(Csq, LOCK_INFORMATION, Csq);
    KeAcquireSpinLock(&LockInfo->CsqLock, Irql);
}

static VOID NTAPI
LockReleaseQueueLock(PIO_CSQ Csq, KIRQL Irql)
{
    PLOCK_INFORMATION LockInfo = CONTAINING_RECORD(Csq, LOCK_INFORMATION, Csq);
    KeReleaseSpinLock(&LockInfo->CsqLock, Irql);
}

static VOID NTAPI
LockCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp)
{
    NTSTATUS Status;
    PLOCK_INFORMATION LockInfo = CONTAINING_RECORD(Csq, LOCK_INFORMATION, Csq);
    DPRINT("Complete cancelled IRP %p Status %x\n", Irp, STATUS_CANCELLED);
    /* IoCsqInsertIrpEx cancels inline on the thread that holds RangeLock: complete after the release */
    if (LockInfo->RangeLockOwner == KeGetCurrentThread())
    {
        ASSERT(LockInfo->DeferredIrps != NULL);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        InsertTailList(LockInfo->DeferredIrps, &Irp->Tail.Overlay.ListEntry);
        return;
    }
    FsRtlCompleteLockIrpReal
        (LockInfo->CompleteLockIrpRoutine,
         NULL,
         Irp,
         STATUS_CANCELLED,
         &Status,
         NULL);
}

VOID
NTAPI
FsRtlCompleteLockIrpReal(IN PCOMPLETE_LOCK_IRP_ROUTINE CompleteRoutine,
                         IN PVOID Context,
                         IN PIRP Irp,
                         IN NTSTATUS Status,
                         OUT PNTSTATUS NewStatus,
                         IN PFILE_OBJECT FileObject OPTIONAL)
{
    /* Check if we have a complete routine */
    Irp->IoStatus.Information = 0;
    if (CompleteRoutine)
    {
        /* Check if we have a file object */
        if (FileObject) FileObject->LastLock = NULL;

        /* Set the I/O Status and do completion */
        Irp->IoStatus.Status = Status;
        DPRINT("Calling completion routine %p Status %x\n", Irp, Status);
        *NewStatus = CompleteRoutine(Context, Irp);
    }
    else
    {
        /* Otherwise do a normal I/O complete request */
        DPRINT("Completing IRP %p Status %x\n", Irp, Status);
        FsRtlCompleteRequest(Irp, Status);
        *NewStatus = Status;
    }
}

/* INTERNAL SYNCHRONIZATION ***************************************************/

/*
 * File systems call these routines from several threads at once, often holding
 * only a shared resource. Every access to a LOCK_INFORMATION's RangeTable and
 * SharedLocks therefore happens under its RangeLock. IRPs are never completed
 * and callbacks never called while RangeLock is held: the locked code collects
 * them on a list, and the caller completes them after the release.
 */

static
PLOCK_INFORMATION
FsRtlpGetLockInformation(IN PFILE_LOCK FileLock)
{
    /* Pairs with the interlocked publication in FsRtlpCreateLockInformation */
    return (PLOCK_INFORMATION)*(PVOID volatile *)&FileLock->LockInformation;
}

static
PLOCK_INFORMATION
FsRtlpCreateLockInformation(IN PFILE_LOCK FileLock)
{
    PLOCK_INFORMATION LockInfo, Published;

    LockInfo = FsRtlpGetLockInformation(FileLock);
    if (LockInfo) return LockInfo;

    LockInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(LOCK_INFORMATION), TAG_FLOCK);
    if (!LockInfo) return NULL;

    RtlZeroMemory(LockInfo, sizeof(*LockInfo));
    LockInfo->BelongsTo = FileLock;
    LockInfo->CompleteLockIrpRoutine = FileLock->CompleteLockIrpRoutine;
    InitializeListHead(&LockInfo->SharedLocks);
    RtlInitializeGenericTable(&LockInfo->RangeTable,
                              LockCompare,
                              LockAllocate,
                              LockFree,
                              NULL);
    KeInitializeSpinLock(&LockInfo->CsqLock);
    InitializeListHead(&LockInfo->CsqList);
    IoCsqInitializeEx(&LockInfo->Csq,
                      LockInsertIrpEx,
                      LockRemoveIrp,
                      LockPeekNextIrp,
                      LockAcquireQueueLock,
                      LockReleaseQueueLock,
                      LockCompleteCanceledIrp);
    KeInitializeSpinLock(&LockInfo->RangeLock);

    /* Publish only a complete structure; a concurrent first caller may have won */
    Published = InterlockedCompareExchangePointer(&FileLock->LockInformation, LockInfo, NULL);
    if (Published)
    {
        ExFreePoolWithTag(LockInfo, TAG_FLOCK);
        return Published;
    }
    return LockInfo;
}

static
VOID
FsRtlpAcquireRangeLock(IN PLOCK_INFORMATION LockInfo,
                       IN PLIST_ENTRY DeferredIrps OPTIONAL,
                       OUT PKIRQL OldIrql)
{
    KeAcquireSpinLock(&LockInfo->RangeLock, OldIrql);
    LockInfo->RangeLockOwner = KeGetCurrentThread();
    LockInfo->DeferredIrps = DeferredIrps;
}

static
VOID
FsRtlpReleaseRangeLock(IN PLOCK_INFORMATION LockInfo,
                       IN KIRQL OldIrql)
{
    LockInfo->DeferredIrps = NULL;
    LockInfo->RangeLockOwner = NULL;
    KeReleaseSpinLock(&LockInfo->RangeLock, OldIrql);
}

static
VOID
FsRtlpDeferIrp(IN PLIST_ENTRY DeferredIrps,
               IN PIRP Irp,
               IN NTSTATUS Status)
{
    Irp->IoStatus.Status = Status;
    InsertTailList(DeferredIrps, &Irp->Tail.Overlay.ListEntry);
}

static
VOID
FsRtlpCompleteDeferredIrps(IN PFILE_LOCK FileLock,
                           IN PLIST_ENTRY DeferredIrps)
{
    while (!IsListEmpty(DeferredIrps))
    {
        PLIST_ENTRY Entry = RemoveHeadList(DeferredIrps);
        PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        NTSTATUS Status = Irp->IoStatus.Status, Ignored;
        PFILE_OBJECT FileObject = NULL;

        /* A granted waiter completes as FsRtlPrivateLock completes a lock; a cancelled one without a file object */
        if (Status != STATUS_CANCELLED)
            FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

        FsRtlCompleteLockIrpReal(FileLock->CompleteLockIrpRoutine,
                                 NULL,
                                 Irp,
                                 Status,
                                 &Ignored,
                                 FileObject);
    }
}

static
VOID
FsRtlpInitLockElement(OUT PCOMBINED_LOCK_ELEMENT Element,
                      IN PFILE_OBJECT FileObject,
                      IN LONGLONG Start,
                      IN LONGLONG Length,
                      IN PVOID Process,
                      IN ULONG Key,
                      IN BOOLEAN ExclusiveLock)
{
    RtlZeroMemory(Element, sizeof(*Element));
    Element->Exclusive.FileLock.FileObject = FileObject;
    Element->Exclusive.FileLock.StartingByte.QuadPart = Start;
    Element->Exclusive.FileLock.Length.QuadPart = Length;
    Element->Exclusive.FileLock.EndingByte.QuadPart = (LONGLONG)((ULONGLONG)Start + (ULONGLONG)Length);
    Element->Exclusive.FileLock.ProcessId = Process;
    Element->Exclusive.FileLock.Key = Key;
    Element->Exclusive.FileLock.ExclusiveLock = ExclusiveLock;
}

/* Called with RangeLock held */
static
BOOLEAN
FsRtlpFindLockLocked(IN PLOCK_INFORMATION LockInfo,
                     IN LONGLONG Start,
                     IN LONGLONG End,
                     OUT PFILE_LOCK_INFO Found)
{
    COMBINED_LOCK_ELEMENT ToFind;
    PCOMBINED_LOCK_ELEMENT Entry;

    ToFind.Exclusive.FileLock.StartingByte.QuadPart = Start;
    ToFind.Exclusive.FileLock.EndingByte.QuadPart = End;
    Entry = RtlLookupElementGenericTable(&LockInfo->RangeTable, &ToFind);
    if (!Entry) return FALSE;
    *Found = Entry->Exclusive.FileLock;
    return TRUE;
}

/* Copies the lock that overlaps Start..End, if there is one */
static
BOOLEAN
FsRtlpFindLock(IN PFILE_LOCK FileLock,
               IN LONGLONG Start,
               IN LONGLONG End,
               OUT PFILE_LOCK_INFO Found)
{
    PLOCK_INFORMATION LockInfo = FsRtlpGetLockInformation(FileLock);
    BOOLEAN Result;
    KIRQL OldIrql;

    if (!LockInfo) return FALSE;
    FsRtlpAcquireRangeLock(LockInfo, NULL, &OldIrql);
    Result = FsRtlpFindLockLocked(LockInfo, Start, End, Found);
    FsRtlpReleaseRangeLock(LockInfo, OldIrql);
    return Result;
}

/* PUBLIC FUNCTIONS **********************************************************/

VOID
NTAPI
FsRtlpExpandLockElement
(PCOMBINED_LOCK_ELEMENT ToExpand,
 PCOMBINED_LOCK_ELEMENT Conflict)
{
    /* Unsigned min/max: a whole-file end is the unsigned maximum, not a negative. */
    if ((ULONGLONG)ToExpand->Exclusive.FileLock.StartingByte.QuadPart >
        (ULONGLONG)Conflict->Exclusive.FileLock.StartingByte.QuadPart)
    {
        ToExpand->Exclusive.FileLock.StartingByte =
            Conflict->Exclusive.FileLock.StartingByte;
    }
    if ((ULONGLONG)ToExpand->Exclusive.FileLock.EndingByte.QuadPart <
        (ULONGLONG)Conflict->Exclusive.FileLock.EndingByte.QuadPart)
    {
        ToExpand->Exclusive.FileLock.EndingByte =
            Conflict->Exclusive.FileLock.EndingByte;
    }
    ToExpand->Exclusive.FileLock.Length.QuadPart =
        (LONGLONG)((ULONGLONG)ToExpand->Exclusive.FileLock.EndingByte.QuadPart -
                   (ULONGLONG)ToExpand->Exclusive.FileLock.StartingByte.QuadPart);
}

/* This function expands the conflicting range Conflict by removing and reinserting it,
   then adds a shared range of the same size. Called with RangeLock held. */
static
PCOMBINED_LOCK_ELEMENT
FsRtlpRebuildSharedLockRange
(PLOCK_INFORMATION LockInfo,
 PCOMBINED_LOCK_ELEMENT Conflict)
{
    /* Starting at Conflict->StartingByte and going to Conflict->EndingByte
     * capture and expand a shared range from the shared range list.
     * Finish when we've incorporated all overlapping shared regions.
     */
    BOOLEAN InsertedNew = FALSE, RemovedOld;
    COMBINED_LOCK_ELEMENT NewElement = *Conflict;
    PCOMBINED_LOCK_ELEMENT Entry;
    while ((Entry = RtlLookupElementGenericTable
            (&LockInfo->RangeTable, &NewElement)))
    {
        FsRtlpExpandLockElement(&NewElement, Entry);
        RemovedOld = RtlDeleteElementGenericTable
            (&LockInfo->RangeTable,
             Entry);
        ASSERT(RemovedOld);
    }
    Conflict = RtlInsertElementGenericTable
        (&LockInfo->RangeTable,
         &NewElement,
         sizeof(NewElement),
         &InsertedNew);
    ASSERT(!Conflict || InsertedNew);
    return Conflict;
}

/*
 * Grants or queues one lock. Called with RangeLock held.
 * Returns STATUS_SUCCESS when granted, STATUS_PENDING when the IRP was queued (or
 * the caller would have to wait, without an IRP), or a failure. The caller must
 * not touch a queued IRP: it may already be cancelled and completed.
 */
static
NTSTATUS
FsRtlpLockRangeLocked(IN PLOCK_INFORMATION LockInfo,
                      IN PCOMBINED_LOCK_ELEMENT ToInsert,
                      IN BOOLEAN FailImmediately,
                      IN PIRP Irp OPTIONAL)
{
    PCOMBINED_LOCK_ELEMENT Conflict;
    PLOCK_SHARED_RANGE NewSharedRange = NULL;
    BOOLEAN ExclusiveLock = ToInsert->Exclusive.FileLock.ExclusiveLock;
    BOOLEAN InsertedNew, MustWait;
    ULONG i;

    /* Allocate before changing the table, so that a failure leaves it as it was */
    if (!ExclusiveLock)
    {
        NewSharedRange = ExAllocatePoolWithTag(NonPagedPool, sizeof(*NewSharedRange), TAG_RANGE);
        if (!NewSharedRange) return STATUS_NO_MEMORY;
        NewSharedRange->Start = ToInsert->Exclusive.FileLock.StartingByte;
        NewSharedRange->End = ToInsert->Exclusive.FileLock.EndingByte;
        NewSharedRange->Key = ToInsert->Exclusive.FileLock.Key;
        NewSharedRange->ProcessId = ToInsert->Exclusive.FileLock.ProcessId;
        NewSharedRange->FileObject = ToInsert->Exclusive.FileLock.FileObject;
    }

    Conflict = RtlInsertElementGenericTable(&LockInfo->RangeTable,
                                            ToInsert,
                                            sizeof(*ToInsert),
                                            &InsertedNew);
    if (!Conflict)
    {
        /* Conflict here is (or would be) the newly inserted element, but we ran out of space */
        if (NewSharedRange) ExFreePoolWithTag(NewSharedRange, TAG_RANGE);
        return STATUS_NO_MEMORY;
    }

    if (!InsertedNew)
    {
        DPRINT("Conflict %I64x:%I64x Exc %u (Want Exc %u)\n",
               Conflict->Exclusive.FileLock.StartingByte.QuadPart,
               Conflict->Exclusive.FileLock.EndingByte.QuadPart,
               Conflict->Exclusive.FileLock.ExclusiveLock,
               ExclusiveLock);

        MustWait = Conflict->Exclusive.FileLock.ExclusiveLock || ExclusiveLock;
        if (!MustWait)
        {
            /* We know of at least one lock in range that's shared.  We need to
             * find out if any more exist and any are exclusive. */
            for (i = 0; i < RtlNumberGenericTableElements(&LockInfo->RangeTable); i++)
            {
                Conflict = RtlGetElementGenericTable(&LockInfo->RangeTable, i);
                if (Conflict &&
                    Conflict->Exclusive.FileLock.ExclusiveLock &&
                    LockCompare(&LockInfo->RangeTable, Conflict, ToInsert) == GenericEqual)
                {
                    MustWait = TRUE;
                    break;
                }
            }
        }

        if (MustWait)
        {
            if (NewSharedRange) ExFreePoolWithTag(NewSharedRange, TAG_RANGE);
            if (FailImmediately) return STATUS_FILE_LOCK_CONFLICT;
            if (Irp)
            {
                /* FsRtlpGrantWaitersLocked looks at each waiter once per generation */
                Irp->IoStatus.Information = LockInfo->Generation;
                IoMarkIrpPending(Irp);
                IoCsqInsertIrpEx(&LockInfo->Csq, Irp, NULL, NULL);
            }
            return STATUS_PENDING;
        }

        /* We got here because there were only overlapping shared locks */
        if (!FsRtlpRebuildSharedLockRange(LockInfo, ToInsert))
        {
            ExFreePoolWithTag(NewSharedRange, TAG_RANGE);
            return STATUS_NO_MEMORY;
        }
    }

    /* A shared lock is both a range *and* a list entry. */
    if (NewSharedRange)
        InsertTailList(&LockInfo->SharedLocks, &NewSharedRange->Entry);

    DPRINT("Acquired lock %I64x:%I64x exclusive %u\n",
           ToInsert->Exclusive.FileLock.StartingByte.QuadPart,
           ToInsert->Exclusive.FileLock.EndingByte.QuadPart,
           ExclusiveLock);
    return STATUS_SUCCESS;
}

/*
 * Removes one shared range and rebuilds the table range it was part of from the
 * remaining shared ranges. Unlocked receives the range waiters may now take.
 * Called with RangeLock held.
 */
static
VOID
FsRtlpRemoveSharedRangeLocked(IN PLOCK_INFORMATION LockInfo,
                              IN PLOCK_SHARED_RANGE SharedRange,
                              IN PFILE_OBJECT FileObject,
                              OUT PCOMBINED_LOCK_ELEMENT Unlocked)
{
    COMBINED_LOCK_ELEMENT Find;
    PCOMBINED_LOCK_ELEMENT Entry;
    PLIST_ENTRY SharedEntry;

    FsRtlpInitLockElement(&Find,
                          FileObject,
                          SharedRange->Start.QuadPart,
                          SharedRange->End.QuadPart - SharedRange->Start.QuadPart,
                          SharedRange->ProcessId,
                          SharedRange->Key,
                          FALSE);

    /* Remove the found range from the shared range lists */
    RemoveEntryList(&SharedRange->Entry);
    ExFreePoolWithTag(SharedRange, TAG_RANGE);

    Entry = RtlLookupElementGenericTable(&LockInfo->RangeTable, &Find);
    if (!Entry || Entry->Exclusive.FileLock.ExclusiveLock)
    {
        *Unlocked = Find;
        return;
    }

    /* Remember what was in there and remove it from the table */
    *Unlocked = *Entry;
    RtlDeleteElementGenericTable(&LockInfo->RangeTable, Entry);

    /* Put shared locks back in place */
    for (SharedEntry = LockInfo->SharedLocks.Flink;
         SharedEntry != &LockInfo->SharedLocks;
         SharedEntry = SharedEntry->Flink)
    {
        COMBINED_LOCK_ELEMENT LockElement;
        PLOCK_SHARED_RANGE Range = CONTAINING_RECORD(SharedEntry, LOCK_SHARED_RANGE, Entry);

        FsRtlpInitLockElement(&LockElement,
                              Range->FileObject,
                              Range->Start.QuadPart,
                              Range->End.QuadPart - Range->Start.QuadPart,
                              Range->ProcessId,
                              Range->Key,
                              FALSE);
        if (LockCompare(&LockInfo->RangeTable, Unlocked, &LockElement) != GenericEqual)
            continue;

        DPRINT("Re-creating range %I64x:%I64x\n",
               LockElement.Exclusive.FileLock.StartingByte.QuadPart,
               LockElement.Exclusive.FileLock.EndingByte.QuadPart);
        FsRtlpRebuildSharedLockRange(LockInfo, &LockElement);
    }
}

/* Called with RangeLock held */
static
NTSTATUS
FsRtlpUnlockRangeLocked(IN PLOCK_INFORMATION LockInfo,
                        IN PFILE_OBJECT FileObject,
                        IN LONGLONG Start,
                        IN LONGLONG Length,
                        IN PEPROCESS Process,
                        IN ULONG Key,
                        OUT PCOMBINED_LOCK_ELEMENT Unlocked)
{
    COMBINED_LOCK_ELEMENT Find;
    PCOMBINED_LOCK_ELEMENT Entry;
    PLIST_ENTRY SharedEntry;

    // The region to unlock must correspond exactly to a previously locked region
    // -- msdn
    Find.Exclusive.FileLock.StartingByte.QuadPart = Start;
    Find.Exclusive.FileLock.EndingByte.QuadPart = Start + Length;
    Entry = RtlLookupElementGenericTable(&LockInfo->RangeTable, &Find);
    if (!Entry)
    {
        DPRINT("Range not locked\n");
        return STATUS_RANGE_NOT_LOCKED;
    }

    if (Entry->Exclusive.FileLock.ExclusiveLock)
    {
        if (Entry->Exclusive.FileLock.Key != Key ||
            Entry->Exclusive.FileLock.ProcessId != Process ||
            Entry->Exclusive.FileLock.FileObject != FileObject ||
            Entry->Exclusive.FileLock.StartingByte.QuadPart != Start ||
            Entry->Exclusive.FileLock.EndingByte.QuadPart != Start + Length)
        {
            DPRINT("Range not locked\n");
            return STATUS_RANGE_NOT_LOCKED;
        }
        *Unlocked = *Entry;
        // Remove the old exclusive lock region
        RtlDeleteElementGenericTable(&LockInfo->RangeTable, Entry);
        return STATUS_SUCCESS;
    }

    for (SharedEntry = LockInfo->SharedLocks.Flink;
         SharedEntry != &LockInfo->SharedLocks;
         SharedEntry = SharedEntry->Flink)
    {
        PLOCK_SHARED_RANGE SharedRange = CONTAINING_RECORD(SharedEntry, LOCK_SHARED_RANGE, Entry);
        if (SharedRange->Start.QuadPart == Start &&
            SharedRange->End.QuadPart == Start + Length &&
            SharedRange->Key == Key &&
            SharedRange->ProcessId == Process &&
            SharedRange->FileObject == FileObject)
        {
            FsRtlpRemoveSharedRangeLocked(LockInfo, SharedRange, FileObject, Unlocked);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_RANGE_NOT_LOCKED;
}

/* Removes every lock of FileObject and Process (and Key). Returns TRUE if any was removed. Called with RangeLock held. */
static
BOOLEAN
FsRtlpUnlockAllLocked(IN PLOCK_INFORMATION LockInfo,
                      IN PFILE_OBJECT FileObject,
                      IN PEPROCESS Process,
                      IN BOOLEAN MatchKey,
                      IN ULONG Key)
{
    COMBINED_LOCK_ELEMENT Unlocked;
    PCOMBINED_LOCK_ELEMENT Entry, Next;
    PLIST_ENTRY ListEntry;
    PVOID RestartKey = NULL;
    BOOLEAN Removed = FALSE;

    /* Shared ranges first; removing one only unlinks that list entry */
    for (ListEntry = LockInfo->SharedLocks.Flink;
         ListEntry != &LockInfo->SharedLocks;)
    {
        PLOCK_SHARED_RANGE Range = CONTAINING_RECORD(ListEntry, LOCK_SHARED_RANGE, Entry);
        ListEntry = ListEntry->Flink;
        if (Range->FileObject != FileObject || Range->ProcessId != Process ||
            (MatchKey && Range->Key != Key))
            continue;
        FsRtlpRemoveSharedRangeLocked(LockInfo, Range, FileObject, &Unlocked);
        Removed = TRUE;
    }

    /* Then the exclusive ones. Take the successor before deleting: a deletion
       restructures the tree but leaves every other node in place. */
    Entry = RtlEnumerateGenericTableWithoutSplaying(&LockInfo->RangeTable, &RestartKey);
    while (Entry)
    {
        Next = RtlEnumerateGenericTableWithoutSplaying(&LockInfo->RangeTable, &RestartKey);
        if (Entry->Exclusive.FileLock.ExclusiveLock &&
            Entry->Exclusive.FileLock.FileObject == FileObject &&
            Entry->Exclusive.FileLock.ProcessId == Process &&
            (!MatchKey || Entry->Exclusive.FileLock.Key == Key))
        {
            RtlDeleteElementGenericTable(&LockInfo->RangeTable, Entry);
            Removed = TRUE;
        }
        Entry = Next;
    }

    return Removed;
}

/*
 * Retries queued lock IRPs after an unlock. Unlocked limits it to the waiters
 * that overlap that range; NULL retries every waiter. Granted or failed IRPs go
 * to DeferredIrps. Called with RangeLock held.
 */
static
VOID
FsRtlpGrantWaitersLocked(IN PLOCK_INFORMATION LockInfo,
                         IN PCOMBINED_LOCK_ELEMENT Unlocked OPTIONAL,
                         IN PLIST_ENTRY DeferredIrps)
{
    PIRP Irp;

    LockInfo->Generation++;
    while ((Irp = IoCsqRemoveNextIrp(&LockInfo->Csq, Unlocked)))
    {
        PIO_STACK_LOCATION IoStack;
        COMBINED_LOCK_ELEMENT ToInsert;
        NTSTATUS Status;

        if (Irp->IoStatus.Information == LockInfo->Generation)
        {
            // We've already looked at this one, meaning that we looped.
            // Put it back and exit.
            IoCsqInsertIrpEx(&LockInfo->Csq, Irp, NULL, NULL);
            break;
        }

        // Got a new lock irp... try to do the new lock operation
        IoStack = IoGetCurrentIrpStackLocation(Irp);
        FsRtlpInitLockElement(&ToInsert,
                              IoStack->FileObject,
                              IoStack->Parameters.LockControl.ByteOffset.QuadPart,
                              IoStack->Parameters.LockControl.Length->QuadPart,
                              IoGetRequestorProcess(Irp),
                              IoStack->Parameters.LockControl.Key,
                              BooleanFlagOn(IoStack->Flags, SL_EXCLUSIVE_LOCK));
        DPRINT("Locking another IRP %p\n", Irp);
        Status = FsRtlpLockRangeLocked(LockInfo,
                                       &ToInsert,
                                       BooleanFlagOn(IoStack->Flags, SL_FAIL_IMMEDIATELY),
                                       Irp);
        if (Status != STATUS_PENDING)
            FsRtlpDeferIrp(DeferredIrps, Irp, Status);
    }
}

/* FILE_LOCK.LastReturnedLock after the last range was returned */
static UCHAR FsRtlpEnumerationEnd;

/*
 * Restart enumerates from the start. Otherwise the enumeration continues after
 * the range returned last, which other callers may have splayed away or deleted
 * since. Table ranges never overlap, so their starting bytes are distinct.
 * Called with RangeLock held.
 */
static
PCOMBINED_LOCK_ELEMENT
FsRtlpNextLockLocked(IN PLOCK_INFORMATION LockInfo,
                     IN PFILE_LOCK_INFO Previous)
{
    COMBINED_LOCK_ELEMENT Probe;
    PCOMBINED_LOCK_ELEMENT Entry;
    PVOID RestartKey = NULL;

    /* An empty range at the previous start matches the range containing it */
    Probe.Exclusive.FileLock.StartingByte = Previous->StartingByte;
    Probe.Exclusive.FileLock.EndingByte = Previous->StartingByte;
    if (RtlLookupElementGenericTable(&LockInfo->RangeTable, &Probe))
    {
        /* The lookup splayed that range to the root; take its successor */
        return RtlEnumerateGenericTable(&LockInfo->RangeTable, FALSE);
    }

    for (Entry = RtlEnumerateGenericTableWithoutSplaying(&LockInfo->RangeTable, &RestartKey);
         Entry;
         Entry = RtlEnumerateGenericTableWithoutSplaying(&LockInfo->RangeTable, &RestartKey))
    {
        if (Entry->Exclusive.FileLock.StartingByte.QuadPart > Previous->StartingByte.QuadPart)
            return Entry;
    }
    return NULL;
}

/*
 * @implemented
 */
PFILE_LOCK_INFO
NTAPI
FsRtlGetNextFileLock(IN PFILE_LOCK FileLock,
                     IN BOOLEAN Restart)
{
    PLOCK_INFORMATION LockInfo = FsRtlpGetLockInformation(FileLock);
    PCOMBINED_LOCK_ELEMENT Entry;
    FILE_LOCK_INFO Previous, Found;
    PVOID Cursor;
    KIRQL OldIrql;

    if (!LockInfo) return NULL;

    /* The enumeration state lives in FILE_LOCK, which may be paged: touch it only outside RangeLock.
       Callers serialize enumeration of one FILE_LOCK, as documented. */
    Cursor = Restart ? NULL : FileLock->LastReturnedLock;
    if (Cursor == &FsRtlpEnumerationEnd) return NULL;
    if (Cursor) Previous = FileLock->LastReturnedLockInfo;

    FsRtlpAcquireRangeLock(LockInfo, NULL, &OldIrql);
    if (!Cursor)
        Entry = RtlEnumerateGenericTable(&LockInfo->RangeTable, TRUE);
    else
        Entry = FsRtlpNextLockLocked(LockInfo, &Previous);
    /* Return a copy: the element may be freed as soon as RangeLock is released */
    if (Entry) Found = Entry->Exclusive.FileLock;
    FsRtlpReleaseRangeLock(LockInfo, OldIrql);

    if (!Entry)
    {
        /* Stay at the end until the caller restarts */
        FileLock->LastReturnedLock = &FsRtlpEnumerationEnd;
        return NULL;
    }
    FileLock->LastReturnedLockInfo = Found;
    /* Only a marker that an enumeration is in progress; never dereferenced */
    FileLock->LastReturnedLock = Entry;
    return &FileLock->LastReturnedLockInfo;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
FsRtlPrivateLock(IN PFILE_LOCK FileLock,
                 IN PFILE_OBJECT FileObject,
                 IN PLARGE_INTEGER FileOffset,
                 IN PLARGE_INTEGER Length,
                 IN PEPROCESS Process,
                 IN ULONG Key,
                 IN BOOLEAN FailImmediately,
                 IN BOOLEAN ExclusiveLock,
                 OUT PIO_STATUS_BLOCK IoStatus,
                 IN PIRP Irp OPTIONAL,
                 IN PVOID Context OPTIONAL,
                 IN BOOLEAN AlreadySynchronized)
{
    NTSTATUS Status, CompletionStatus;
    COMBINED_LOCK_ELEMENT ToInsert;
    PLOCK_INFORMATION LockInfo;
    LIST_ENTRY DeferredIrps;
    ULARGE_INTEGER UnsignedStart;
    ULARGE_INTEGER UnsignedEnd;
    KIRQL OldIrql;

    DPRINT("FsRtlPrivateLock(%wZ, Offset %08x%08x (%d), Length %08x%08x (%d), Key %x, FailImmediately %u, Exclusive %u)\n",
           &FileObject->FileName,
           FileOffset->HighPart,
           FileOffset->LowPart,
           (int)FileOffset->QuadPart,
           Length->HighPart,
           Length->LowPart,
           (int)Length->QuadPart,
           Key,
           FailImmediately,
           ExclusiveLock);

    UnsignedStart.QuadPart = FileOffset->QuadPart;
    UnsignedEnd.QuadPart = (ULONGLONG)FileOffset->QuadPart + (ULONGLONG)Length->QuadPart;

    if (UnsignedEnd.QuadPart < UnsignedStart.QuadPart)
    {
        DPRINT("File offset out of range\n");
        Status = STATUS_INVALID_PARAMETER;
    }
    else if (!(LockInfo = FsRtlpCreateLockInformation(FileLock)))
    {
        Status = STATUS_NO_MEMORY;
    }
    else
    {
        FsRtlpInitLockElement(&ToInsert,
                              FileObject,
                              FileOffset->QuadPart,
                              Length->QuadPart,
                              Process,
                              Key,
                              ExclusiveLock);
        InitializeListHead(&DeferredIrps);
        FsRtlpAcquireRangeLock(LockInfo, &DeferredIrps, &OldIrql);
        Status = FsRtlpLockRangeLocked(LockInfo, &ToInsert, FailImmediately, Irp);
        FsRtlpReleaseRangeLock(LockInfo, OldIrql);
        /* Only an IRP cancelled while it was being queued can be here */
        FsRtlpCompleteDeferredIrps(FileLock, &DeferredIrps);
    }

    IoStatus->Status = Status;
    if (Status == STATUS_PENDING)
    {
        /* A queued IRP belongs to the queue now */
        return FALSE;
    }

    if (Irp)
    {
        DPRINT("Complete lock %p Status %x\n", Irp, Status);
        FsRtlCompleteLockIrpReal(FileLock->CompleteLockIrpRoutine,
                                 Context,
                                 Irp,
                                 Status,
                                 &CompletionStatus,
                                 FileObject);
        if (NT_SUCCESS(Status))
            IoStatus->Status = CompletionStatus;
    }

    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
FsRtlCheckLockForReadAccess(IN PFILE_LOCK FileLock,
                            IN PIRP Irp)
{
    BOOLEAN Result;
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    FILE_LOCK_INFO Found;
    PEPROCESS Process = IoGetRequestorProcess(Irp);
    DPRINT("CheckLockForReadAccess(%wZ, Offset %08x%08x, Length %x)\n",
           &IoStack->FileObject->FileName,
           IoStack->Parameters.Read.ByteOffset.HighPart,
           IoStack->Parameters.Read.ByteOffset.LowPart,
           IoStack->Parameters.Read.Length);
    if (!FsRtlpFindLock(FileLock,
                        IoStack->Parameters.Read.ByteOffset.QuadPart,
                        IoStack->Parameters.Read.ByteOffset.QuadPart +
                        IoStack->Parameters.Read.Length,
                        &Found))
    {
        DPRINT("CheckLockForReadAccess(%wZ) => TRUE\n", &IoStack->FileObject->FileName);
        return TRUE;
    }
    Result = !Found.ExclusiveLock ||
        (IoStack->Parameters.Read.Key == Found.Key &&
         Process == Found.ProcessId);
    DPRINT("CheckLockForReadAccess(%wZ) => %s\n", &IoStack->FileObject->FileName, Result ? "TRUE" : "FALSE");
    return Result;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
FsRtlCheckLockForWriteAccess(IN PFILE_LOCK FileLock,
                             IN PIRP Irp)
{
    BOOLEAN Result;
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    FILE_LOCK_INFO Found;
    PEPROCESS Process = Irp->Tail.Overlay.Thread->ThreadsProcess;
    DPRINT("CheckLockForWriteAccess(%wZ, Offset %08x%08x, Length %x)\n",
           &IoStack->FileObject->FileName,
           IoStack->Parameters.Write.ByteOffset.HighPart,
           IoStack->Parameters.Write.ByteOffset.LowPart,
           IoStack->Parameters.Write.Length);
    if (!FsRtlpFindLock(FileLock,
                        IoStack->Parameters.Write.ByteOffset.QuadPart,
                        IoStack->Parameters.Write.ByteOffset.QuadPart +
                        IoStack->Parameters.Write.Length,
                        &Found))
    {
        DPRINT("CheckLockForWriteAccess(%wZ) => TRUE\n", &IoStack->FileObject->FileName);
        return TRUE;
    }
    Result = Process == Found.ProcessId;
    DPRINT("CheckLockForWriteAccess(%wZ) => %s\n", &IoStack->FileObject->FileName, Result ? "TRUE" : "FALSE");
    return Result;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
FsRtlFastCheckLockForRead(IN PFILE_LOCK FileLock,
                          IN PLARGE_INTEGER FileOffset,
                          IN PLARGE_INTEGER Length,
                          IN ULONG Key,
                          IN PFILE_OBJECT FileObject,
                          IN PVOID Process)
{
    PEPROCESS EProcess = Process;
    FILE_LOCK_INFO Found;
    DPRINT("FsRtlFastCheckLockForRead(%wZ, Offset %08x%08x, Length %08x%08x, Key %x)\n",
           &FileObject->FileName,
           FileOffset->HighPart,
           FileOffset->LowPart,
           Length->HighPart,
           Length->LowPart,
           Key);
    if (!FsRtlpFindLock(FileLock,
                        FileOffset->QuadPart,
                        FileOffset->QuadPart + Length->QuadPart,
                        &Found))
        return TRUE;
    if (!Found.ExclusiveLock) return TRUE;
    return Found.Key == Key && Found.ProcessId == EProcess;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
FsRtlFastCheckLockForWrite(IN PFILE_LOCK FileLock,
                           IN PLARGE_INTEGER FileOffset,
                           IN PLARGE_INTEGER Length,
                           IN ULONG Key,
                           IN PFILE_OBJECT FileObject,
                           IN PVOID Process)
{
    BOOLEAN Result;
    PEPROCESS EProcess = Process;
    FILE_LOCK_INFO Found;
    DPRINT("FsRtlFastCheckLockForWrite(%wZ, Offset %08x%08x, Length %08x%08x, Key %x)\n",
           &FileObject->FileName,
           FileOffset->HighPart,
           FileOffset->LowPart,
           Length->HighPart,
           Length->LowPart,
           Key);
    if (!FsRtlpFindLock(FileLock,
                        FileOffset->QuadPart,
                        FileOffset->QuadPart + Length->QuadPart,
                        &Found))
    {
        DPRINT("CheckForWrite(%wZ) => TRUE\n", &FileObject->FileName);
        return TRUE;
    }
    Result = Found.Key == Key && Found.ProcessId == EProcess;
    DPRINT("CheckForWrite(%wZ) => %s\n", &FileObject->FileName, Result ? "TRUE" : "FALSE");
    return Result;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
FsRtlFastUnlockSingle(IN PFILE_LOCK FileLock,
                      IN PFILE_OBJECT FileObject,
                      IN PLARGE_INTEGER FileOffset,
                      IN PLARGE_INTEGER Length,
                      IN PEPROCESS Process,
                      IN ULONG Key,
                      IN PVOID Context OPTIONAL,
                      IN BOOLEAN AlreadySynchronized)
{
    PLOCK_INFORMATION LockInfo = FsRtlpGetLockInformation(FileLock);
    COMBINED_LOCK_ELEMENT Unlocked;
    LIST_ENTRY DeferredIrps;
    LONGLONG Start, Size;
    NTSTATUS Status;
    KIRQL OldIrql;
    DPRINT("FsRtlFastUnlockSingle(%wZ, Offset %08x%08x (%d), Length %08x%08x (%d), Key %x)\n",
           &FileObject->FileName,
           FileOffset->HighPart,
           FileOffset->LowPart,
           (int)FileOffset->QuadPart,
           Length->HighPart,
           Length->LowPart,
           (int)Length->QuadPart,
           Key);
    // Windows 2003 doesn't assert on AlreadySynchronized and simply ignores that parameter
    if (!LockInfo)
    {
        DPRINT("File not previously locked (ever)\n");
        return STATUS_RANGE_NOT_LOCKED;
    }

    /* The caller's offset and length may be pageable: read them before raising IRQL */
    Start = FileOffset->QuadPart;
    Size = Length->QuadPart;
    InitializeListHead(&DeferredIrps);
    FsRtlpAcquireRangeLock(LockInfo, &DeferredIrps, &OldIrql);
    Status = FsRtlpUnlockRangeLocked(LockInfo,
                                     FileObject,
                                     Start,
                                     Size,
                                     Process,
                                     Key,
                                     &Unlocked);
    if (NT_SUCCESS(Status))
        FsRtlpGrantWaitersLocked(LockInfo, &Unlocked, &DeferredIrps);
    FsRtlpReleaseRangeLock(LockInfo, OldIrql);
    FsRtlpCompleteDeferredIrps(FileLock, &DeferredIrps);

    DPRINT("FsRtlFastUnlockSingle => %x\n", Status);
    return Status;
}

static
NTSTATUS
FsRtlpFastUnlockAll(IN PFILE_LOCK FileLock,
                    IN PFILE_OBJECT FileObject,
                    IN PEPROCESS Process,
                    IN BOOLEAN MatchKey,
                    IN ULONG Key)
{
    PLOCK_INFORMATION LockInfo = FsRtlpGetLockInformation(FileLock);
    LIST_ENTRY DeferredIrps;
    KIRQL OldIrql;

    if (!LockInfo)
    {
        DPRINT("Not locked %wZ\n", &FileObject->FileName);
        return STATUS_RANGE_NOT_LOCKED; // no locks
    }

    InitializeListHead(&DeferredIrps);
    FsRtlpAcquireRangeLock(LockInfo, &DeferredIrps, &OldIrql);
    if (FsRtlpUnlockAllLocked(LockInfo, FileObject, Process, MatchKey, Key))
        FsRtlpGrantWaitersLocked(LockInfo, NULL, &DeferredIrps);
    FsRtlpReleaseRangeLock(LockInfo, OldIrql);
    FsRtlpCompleteDeferredIrps(FileLock, &DeferredIrps);

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
FsRtlFastUnlockAll(IN PFILE_LOCK FileLock,
                   IN PFILE_OBJECT FileObject,
                   IN PEPROCESS Process,
                   IN PVOID Context OPTIONAL)
{
    DPRINT("FsRtlFastUnlockAll(%wZ)\n", &FileObject->FileName);
    return FsRtlpFastUnlockAll(FileLock, FileObject, Process, FALSE, 0);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
FsRtlFastUnlockAllByKey(IN PFILE_LOCK FileLock,
                        IN PFILE_OBJECT FileObject,
                        IN PEPROCESS Process,
                        IN ULONG Key,
                        IN PVOID Context OPTIONAL)
{
    DPRINT("FsRtlFastUnlockAllByKey(%wZ,Key %x)\n", &FileObject->FileName, Key);
    return FsRtlpFastUnlockAll(FileLock, FileObject, Process, TRUE, Key);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
FsRtlProcessFileLock(IN PFILE_LOCK FileLock,
                     IN PIRP Irp,
                     IN PVOID Context OPTIONAL)
{
    PIO_STACK_LOCATION IoStackLocation;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Get the I/O Stack location */
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStackLocation->MajorFunction == IRP_MJ_LOCK_CONTROL);

    /* Clear the I/O status block and check what function this is */
    IoStatusBlock.Information = 0;

    DPRINT("FsRtlProcessFileLock(%wZ, MinorFunction %x)\n",
           &IoStackLocation->FileObject->FileName,
           IoStackLocation->MinorFunction);

    switch(IoStackLocation->MinorFunction)
    {
        /* A lock */
    case IRP_MN_LOCK:
    {
        /* Call the private lock routine */
        BOOLEAN Result = FsRtlPrivateLock(FileLock,
                                          IoStackLocation->FileObject,
                                          &IoStackLocation->Parameters.LockControl.ByteOffset,
                                          IoStackLocation->Parameters.LockControl.Length,
                                          IoGetRequestorProcess(Irp),
                                          IoStackLocation->Parameters.LockControl.Key,
                                          IoStackLocation->Flags & SL_FAIL_IMMEDIATELY,
                                          IoStackLocation->Flags & SL_EXCLUSIVE_LOCK,
                                          &IoStatusBlock,
                                          Irp,
                                          Context,
                                          FALSE);
        /* FsRtlPrivateLock has _Must_inspect_result_. Just check this is consistent on debug builds;
           a queued lock returns FALSE with STATUS_PENDING, which is a success code */
        NT_ASSERT(IoStatusBlock.Status == STATUS_PENDING ? !Result : Result == NT_SUCCESS(IoStatusBlock.Status));
        (void)Result;
        return IoStatusBlock.Status;
    }
        /* A single unlock */
    case IRP_MN_UNLOCK_SINGLE:

        /* Call fast unlock */
        IoStatusBlock.Status =
            FsRtlFastUnlockSingle(FileLock,
                                  IoStackLocation->FileObject,
                                  &IoStackLocation->Parameters.LockControl.
                                  ByteOffset,
                                  IoStackLocation->Parameters.LockControl.
                                  Length,
                                  IoGetRequestorProcess(Irp),
                                  IoStackLocation->Parameters.LockControl.
                                  Key,
                                  Context,
                                  FALSE);
        break;

        /* Total unlock */
    case IRP_MN_UNLOCK_ALL:

        /* Do a fast unlock */
        IoStatusBlock.Status = FsRtlFastUnlockAll(FileLock,
                                                  IoStackLocation->
                                                  FileObject,
                                                  IoGetRequestorProcess(Irp),
                                                  Context);
        break;

        /* Unlock by key */
    case IRP_MN_UNLOCK_ALL_BY_KEY:

        /* Do it */
        IoStatusBlock.Status =
            FsRtlFastUnlockAllByKey(FileLock,
                                    IoStackLocation->FileObject,
                                    IoGetRequestorProcess(Irp),
                                    IoStackLocation->Parameters.
                                    LockControl.Key,
                                    Context);
        break;

        /* Invalid request */
    default:

        /* Complete it */
        FsRtlCompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST);
        IoStatusBlock.Status = STATUS_INVALID_DEVICE_REQUEST;
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* Return the status */
    DPRINT("Lock IRP %p %x\n", Irp, IoStatusBlock.Status);
    FsRtlCompleteLockIrpReal
        (FileLock->CompleteLockIrpRoutine,
         Context,
         Irp,
         IoStatusBlock.Status,
         &Status,
         NULL);
    return IoStatusBlock.Status;
}

/*
 * @implemented
 */
VOID
NTAPI
FsRtlInitializeFileLock (IN PFILE_LOCK FileLock,
                         IN PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine OPTIONAL,
                         IN PUNLOCK_ROUTINE UnlockRoutine OPTIONAL)
{
    /* Setup the lock */
    RtlZeroMemory(FileLock, sizeof(*FileLock));
    FileLock->FastIoIsQuestionable = FALSE;
    FileLock->CompleteLockIrpRoutine = CompleteLockIrpRoutine;
    FileLock->UnlockRoutine = UnlockRoutine;
    FileLock->LockInformation = NULL;
}

/*
 * @implemented
 */
VOID
NTAPI
FsRtlUninitializeFileLock(IN PFILE_LOCK FileLock)
{
    PLOCK_INFORMATION LockInfo = FsRtlpGetLockInformation(FileLock);
    PCOMBINED_LOCK_ELEMENT Entry;
    PLIST_ENTRY SharedEntry;
    LIST_ENTRY DeferredIrps;
    PIRP Irp;
    KIRQL OldIrql;

    /* The caller guarantees that nobody else uses the lock any more */
    if (!LockInfo) return;

    InitializeListHead(&DeferredIrps);
    FsRtlpAcquireRangeLock(LockInfo, &DeferredIrps, &OldIrql);
    for (SharedEntry = LockInfo->SharedLocks.Flink;
         SharedEntry != &LockInfo->SharedLocks;)
    {
        PLOCK_SHARED_RANGE SharedRange = CONTAINING_RECORD(SharedEntry, LOCK_SHARED_RANGE, Entry);
        SharedEntry = SharedEntry->Flink;
        RemoveEntryList(&SharedRange->Entry);
        ExFreePoolWithTag(SharedRange, TAG_RANGE);
    }
    while ((Entry = RtlGetElementGenericTable(&LockInfo->RangeTable, 0)) != NULL)
    {
        RtlDeleteElementGenericTable(&LockInfo->RangeTable, Entry);
    }
    // MSDN: this completes any remaining lock IRPs. They were never granted, and the lock goes away.
    while ((Irp = IoCsqRemoveNextIrp(&LockInfo->Csq, NULL)) != NULL)
    {
        FsRtlpDeferIrp(&DeferredIrps, Irp, STATUS_RANGE_NOT_LOCKED);
    }
    FsRtlpReleaseRangeLock(LockInfo, OldIrql);

    FileLock->LockInformation = NULL;
    FileLock->LastReturnedLock = NULL;
    ExFreePoolWithTag(LockInfo, TAG_FLOCK);

    FsRtlpCompleteDeferredIrps(FileLock, &DeferredIrps);
}

/*
 * @implemented
 */
PFILE_LOCK
NTAPI
FsRtlAllocateFileLock(IN PCOMPLETE_LOCK_IRP_ROUTINE CompleteLockIrpRoutine OPTIONAL,
                      IN PUNLOCK_ROUTINE UnlockRoutine OPTIONAL)
{
    PFILE_LOCK FileLock;

    /* Try to allocate it */
    FileLock = ExAllocateFromPagedLookasideList(&FsRtlFileLockLookasideList);
    if (FileLock)
    {
        /* Initialize it */
        FsRtlInitializeFileLock(FileLock,
                                CompleteLockIrpRoutine,
                                UnlockRoutine);
    }

    /* Return the lock */
    return FileLock;
}

/*
 * @implemented
 */
VOID
NTAPI
FsRtlFreeFileLock(IN PFILE_LOCK FileLock)
{
    /* Uninitialize and free the lock */
    FsRtlUninitializeFileLock(FileLock);
    ExFreeToPagedLookasideList(&FsRtlFileLockLookasideList, FileLock);
}

/*
 * The locks of this implementation are granted or refused while the call runs,
 * so none is ever in progress.
 *
 * @implemented
 */
BOOLEAN
NTAPI
FsRtlAreThereCurrentOrInProgressFileLocks(IN PFILE_LOCK FileLock)
{
    return FsRtlAreThereCurrentFileLocks(FileLock);
}
