/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroPager phase P0: page-out of ARM3 private memory on request.
 *              Dirty capture and page-file slot ownership of private PFNs,
 *              standby repurpose, the explicit working set trim
 *              (EmptyWorkingSet), a synchronous modified page writer and the
 *              SystemMemoryListInformation commands
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Design: harness process/PAGER-DESIGN.md rev 2, phase P0. Everything here is
 * reached only when the NitroPager registry value (Session Manager\Memory
 * Management, read once at boot) is not 0. Value 0, the default, keeps the
 * behaviour the memory manager had before.
 *
 * States of a private page (PrototypePte == 0):
 *   valid                  PTE valid; OriginalPte = demand zero with the
 *                          protection, or the page-file PTE of a clean copy
 *   modified list          PTE in transition, Modified = 1, no slot
 *   being written          PTE in transition, WriteInProgress, a slot in
 *                          OriginalPte, off any list, the writer holds a
 *                          reference; a delete only marks the PFN deleted
 *   standby list (pri 2)   PTE in transition, Modified = 0, the slot that
 *                          holds its copy in OriginalPte (owner tag set)
 *   paged out              PTE = page-file PTE (slot + protection), no page
 *
 * Rules:
 *   - A slot is released only by whoever changes OriginalPte (or the PTE)
 *     away from it, under the PFN lock: MiMarkPfnDirty, the free list insert
 *     (MiReleasePfnPageFileSlot), the writer's completion, the delete of a
 *     page-file PTE.
 *   - PTE-1: a transition PTE can change under the PFN lock alone (repurpose,
 *     transition to page-file, protection kept). Code that rewrites a
 *     non-valid PTE that may be in transition does it under the PFN lock.
 *   - Lock order: address space lock, working set lock, PFN lock, hyperspace
 *     lock, MiPagingFileSlotLock (leaf).
 */

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

extern MMPFNLIST MmModifiedPageListByColor[1];
extern MMPFNLIST MmBadPageListHead;
extern ULONG MmTotalPagesForPagingFile;

/* NitroPager / NitroPagerDebug (CmControlVector, read once at boot) */
ULONG MiNitroPagerMode;
ULONG MiNitroPagerDebug;

/* Private pages on the standby lists: repurposable */
ULONG MmTransitionPrivatePages;

MI_PAGER_COUNTERS MiPagerCounters;
static SIZE_T MiRepurposedByPriority[8];

/* Armed by the test commands (NitroPagerDebug) for one page of the arming process, consumed once */
typedef struct _MI_PAGER_INJECTION
{
    PVOID volatile Process;
    PVOID Address;
} MI_PAGER_INJECTION;
static MI_PAGER_INJECTION MiPagerInjection[MI_PAGER_INJECT_MAX];

/* Set by the tag-mismatch test hook: the next mismatch report is expected, no Debug bugcheck */
static volatile LONG MiPagerExpectMismatch;

/* SystemMemoryListInformation set commands (values as in public headers) */
#define MI_MEMORY_CAPTURE_ACCESSED_BITS             0
#define MI_MEMORY_CAPTURE_AND_RESET_ACCESSED_BITS   1
#define MI_MEMORY_EMPTY_WORKING_SETS                2
#define MI_MEMORY_FLUSH_MODIFIED_LIST               3
#define MI_MEMORY_PURGE_STANDBY_LIST                4
#define MI_MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST   5
#define MI_MEMORY_COMMAND_MAX                       6

/* NitroPager test commands, accepted only when NitroPagerDebug is not 0 */
#define MI_PAGER_TEST_COMMAND_BASE                  0x4E500000
#define MI_PAGER_TEST_FAIL_NEXT_READ                (MI_PAGER_TEST_COMMAND_BASE + 1)
#define MI_PAGER_TEST_FAIL_NEXT_WRITE               (MI_PAGER_TEST_COMMAND_BASE + 2)
#define MI_PAGER_TEST_MISMATCH_NEXT_READ            (MI_PAGER_TEST_COMMAND_BASE + 3)
#define MI_PAGER_TEST_STARVE_NEXT_READ              (MI_PAGER_TEST_COMMAND_BASE + 4)
#define MI_PAGER_TEST_PING                          (MI_PAGER_TEST_COMMAND_BASE + 5)

/* Writer batch: pages taken per PFN lock hold */
#define MI_PAGER_WRITE_BATCH 16

/* Standby pages looked at per list for one repurpose */
#define MI_PAGER_REPURPOSE_SCAN 64

/* Consecutive write failures after which a flush stops */
#define MI_PAGER_WRITE_FAILURE_LIMIT 8

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
MiPagerTakeInjection(
    _In_ ULONG Which,
    _In_ PVOID Address)
{
    PEPROCESS Process = PsGetCurrentProcess();

    ASSERT(Which < MI_PAGER_INJECT_MAX);
    if ((MiNitroPagerDebug == 0) ||
        (MiPagerInjection[Which].Process != Process) ||
        (PAGE_ALIGN(MiPagerInjection[Which].Address) != PAGE_ALIGN(Address)))
    {
        return FALSE;
    }

    /* Only for the page the test named, in the process that armed it */
    if (InterlockedCompareExchangePointer(&MiPagerInjection[Which].Process, NULL, Process) != Process)
        return FALSE;

    /* The mismatch it makes the caller report is expected: no Debug bugcheck for it */
    if (Which == MI_PAGER_INJECT_TAG_MISMATCH)
        InterlockedExchange(&MiPagerExpectMismatch, 1);
    return TRUE;
}

static
VOID
MiPagerArmInjection(
    _In_ ULONG Which,
    _In_ PVOID Address)
{
    InterlockedExchangePointer(&MiPagerInjection[Which].Process, NULL);
    MiPagerInjection[Which].Address = Address;
    InterlockedExchangePointer(&MiPagerInjection[Which].Process, PsGetCurrentProcess());
}

/*
 * A slot operation that must not happen in a correct run: a free of a slot
 * that is not allocated, a tag that names another owner. Debug builds stop;
 * free builds count it and go on without returning or releasing anything.
 */
VOID
NTAPI
MiPagerSlotProblem(
    _In_ ULONG Code,
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR Slot,
    _In_ ULONG Expected,
    _In_ ULONG Found)
{
    static LONG Reported;

    if (Code == MI_PAGER_BAD_REPURPOSE)
        InterlockedIncrement((PLONG)&MiPagerCounters.RepurposeSkipped);
    else if ((Code == MI_PAGER_TAG_MISMATCH_FREE) || (Code == MI_PAGER_TAG_MISMATCH_READ))
        InterlockedIncrement((PLONG)&MiPagerCounters.TagMismatches);
    if ((Code == MI_PAGER_BAD_SLOT_FREE) || (Code == MI_PAGER_TAG_MISMATCH_FREE))
        InterlockedIncrement((PLONG)&MiPagerCounters.SlotFreeRefused);

    if (InterlockedExchange(&Reported, 1) == 0)
    {
        DPRINT1("NitroPager: slot problem %lu, file %lu slot %Iu, expected tag %08lx, found %08lx\n",
                Code, FileIndex, Slot, Expected, Found);
    }

#if DBG
    /* The test hook makes one mismatch on purpose */
    if (InterlockedExchange(&MiPagerExpectMismatch, 0) != 0)
        return;
    KeBugCheckEx(MEMORY_MANAGEMENT, 0x50474E00 | Code, Slot | ((ULONG_PTR)FileIndex << 28), Expected, Found);
#endif
}

/*
 * The PFN's clean copy in the paging file goes: release the slot named by
 * OriginalPte and leave a demand-zero OriginalPte with the same protection.
 * The PFN lock is held. A refused release (corrupt tag) leaks the slot.
 */
VOID
NTAPI
MiReleasePfnPageFileSlot(
    _Inout_ PMMPFN Pfn1)
{
    ULONG Protection;

    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(MI_IS_PAGEFILE_PTE(&Pfn1->OriginalPte));
    ASSERT(Pfn1->u3.e1.PrototypePte == 0);
    ASSERT(Pfn1->u3.e1.WriteInProgress == 0);

    Protection = (ULONG)Pfn1->OriginalPte.u.Soft.Protection;
    MiReleasePageFileSlot((ULONG)Pfn1->OriginalPte.u.Soft.PageFileLow,
                          MI_PAGEFILE_PTE_SLOT(&Pfn1->OriginalPte),
                          MiPagerOwnerTagForPfn(Pfn1));
    MI_MAKE_SOFTWARE_PTE(&Pfn1->OriginalPte, Protection);
}

/*
 * D8: the page's contents changed (a dirty PTE was invalidated, a store
 * fault, a write lock). Under the PFN lock. A clean copy in the paging file
 * is stale from now on, so its slot goes, unless the writer is writing the
 * page right now: then the writer's completion sees Modified and releases.
 */
VOID
NTAPI
MiMarkPfnDirty(
    _Inout_ PMMPFN Pfn1)
{
    MI_ASSERT_PFN_LOCK_HELD();

    Pfn1->u3.e1.Modified = 1;
    if ((Pfn1->u3.e1.PrototypePte == 0) &&
        (Pfn1->u3.e1.WriteInProgress == 0) &&
        MI_IS_PAGEFILE_PTE(&Pfn1->OriginalPte))
    {
        MiReleasePfnPageFileSlot(Pfn1);
    }
}

/*
 * Repurpose one private standby page: its owner's transition PTE becomes the
 * page-file PTE that names the copy (protection of the live transition PTE),
 * through the current process's hyperspace, then the page leaves the standby
 * list in the state MiRemovePageByColor leaves a free page in. PFN lock held.
 */
static
BOOLEAN
MiRepurposePrivateStandbyPage(
    _Inout_ PMMPFN Pfn1,
    _In_ PFN_NUMBER PageFrameIndex)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PFN_NUMBER PteFrame;
    PMMPTE MappedPte;
    MMPTE TempPte, NewPte;
    PVOID Mapping;
    KIRQL HyperIrql;
    USHORT Color;

    MI_ASSERT_PFN_LOCK_HELD();

    /* Private pages only until prototype dirty capture (P2) */
    if ((Pfn1->u3.e1.PrototypePte != 0) || MI_IS_ROS_PFN(Pfn1))
        return FALSE;

    PteFrame = Pfn1->u4.PteFrame;
    if ((Pfn1->u3.e2.ReferenceCount != 0) ||
        (Pfn1->u3.e1.ReadInProgress != 0) ||
        (Pfn1->u3.e1.WriteInProgress != 0) ||
        MI_IS_PFN_DELETED(Pfn1) ||
        !MI_IS_PAGEFILE_PTE(&Pfn1->OriginalPte) ||
        !MiIsUserPageTablePte(Pfn1->PteAddress) ||
        (PteFrame == 0) ||
        (MiGetPfnEntry(PteFrame) == NULL))
    {
        /* A clean private page always has its copy: anything else is a bug */
        MiPagerSlotProblem(MI_PAGER_BAD_REPURPOSE, 0, PageFrameIndex, 0, (ULONG)Pfn1->OriginalPte.u.Long);
        return FALSE;
    }

    /* The owner's page table, wherever it is: one PTE write through hyperspace */
    Mapping = MiMapPageInHyperSpace(Process, PteFrame, &HyperIrql);
    MappedPte = (PMMPTE)((ULONG_PTR)Mapping + BYTE_OFFSET(Pfn1->PteAddress));
    TempPte = *MappedPte;
    if ((TempPte.u.Hard.Valid != 0) ||
        (TempPte.u.Soft.Prototype != 0) ||
        (TempPte.u.Soft.Transition == 0) ||
        (TempPte.u.Trans.PageFrameNumber != PageFrameIndex))
    {
        MiUnmapPageInHyperSpace(Process, Mapping, HyperIrql);
        MiPagerSlotProblem(MI_PAGER_BAD_REPURPOSE, 1, PageFrameIndex, 0, (ULONG)TempPte.u.Long);
        return FALSE;
    }
    MI_MAKE_PAGEFILE_PTE(&NewPte,
                         (ULONG)Pfn1->OriginalPte.u.Soft.PageFileLow,
                         Pfn1->OriginalPte.u.Soft.PageFileHigh,
                         (ULONG)TempPte.u.Trans.Protection);
    MI_WRITE_INVALID_PTE(MappedPte, NewPte);
    MiUnmapPageInHyperSpace(Process, Mapping, HyperIrql);

    /* Off the standby list (this clears OriginalPte), and the transition PTE's page table reference goes */
    MiRepurposedByPriority[Pfn1->u4.Priority]++;
    MiUnlinkPageFromList(Pfn1);
    MiDecrementShareCount(MiGetPfnEntry(PteFrame), PteFrame);

    /* As MiRemovePageByColor leaves a page */
    Color = Pfn1->u3.e1.PageColor;
    Pfn1->u3.e2.ShortFlags = 0;
    Pfn1->u3.e1.PageColor = Color;
    Pfn1->u3.e1.CacheAttribute = MiCached;
    Pfn1->u4.InPageError = 0;
    Pfn1->u4.Priority = 3;

    MiPagerCounters.Repurposed++;
    return TRUE;
}

/*
 * MiRemoveAnyPage/MiRemoveZeroPage found no free or zeroed page: take the
 * oldest private standby page, lowest priority first. Returns 0 if there is
 * none. PFN lock held.
 */
PFN_NUMBER
NTAPI
MiRepurposeStandbyPage(VOID)
{
    PMMPFNLIST ListHead;
    PFN_NUMBER PageFrameIndex, Previous;
    PMMPFN Pfn1;
    ULONG Priority, Scanned;

    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(MiNitroPagerMode != 0);

    for (Priority = 0; Priority < 8; Priority++)
    {
        ListHead = &MmStandbyPageListByPriority[Priority];

        /* Pages are inserted at the front: the oldest is at the back */
        PageFrameIndex = ListHead->Blink;
        for (Scanned = 0;
             (PageFrameIndex != LIST_HEAD) && (Scanned < MI_PAGER_REPURPOSE_SCAN);
             Scanned++)
        {
            Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);
            Previous = Pfn1->u2.Blink;
            if ((Pfn1->u3.e1.PrototypePte == 0) &&
                MiRepurposePrivateStandbyPage(Pfn1, PageFrameIndex))
            {
                ASSERT(Pfn1->u3.e2.ReferenceCount == 0);
                ASSERT(Pfn1->u2.ShareCount == 0);
                return PageFrameIndex;
            }
            PageFrameIndex = Previous;
        }
    }

    return 0;
}

/* Purge: every private standby page is repurposed and goes to the free list */
static
ULONG
MiPurgePrivateStandbyPages(VOID)
{
    PFN_NUMBER PageFrameIndex;
    ULONG Count = 0, Held = 0;
    KIRQL OldIrql;

    OldIrql = MiAcquirePfnLock();
    for (;;)
    {
        PageFrameIndex = MiRepurposeStandbyPage();
        if (PageFrameIndex == 0)
            break;
        MiInsertPageInFreeList(PageFrameIndex);
        Count++;

        /* Let others at the PFN lock now and then */
        if (++Held == 64)
        {
            MiReleasePfnLock(OldIrql);
            Held = 0;
            OldIrql = MiAcquirePfnLock();
        }
    }
    MiReleasePfnLock(OldIrql);
    return Count;
}

/*
 * Writer completion for one page, PFN lock held. The write is over (Status);
 * the page keeps its slot only if nothing touched it meanwhile.
 */
static
VOID
MiCompletePageWrite(
    _Inout_ PMMPFN Pfn1,
    _In_ ULONG FileIndex,
    _In_ ULONG_PTR Slot,
    _In_ NTSTATUS Status)
{
    PKEVENT Event;
    ULONG Protection;

    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(Pfn1->u3.e1.WriteInProgress == 1);
    ASSERT(MI_IS_PAGEFILE_PTE(&Pfn1->OriginalPte));
    ASSERT(MI_PAGEFILE_PTE_SLOT(&Pfn1->OriginalPte) == Slot);

    Pfn1->u3.e1.WriteInProgress = 0;
    Protection = (ULONG)Pfn1->OriginalPte.u.Soft.Protection;

    if (!MI_IS_PFN_DELETED(Pfn1) &&
        NT_SUCCESS(Status) &&
        (Pfn1->u3.e1.Modified == 0) &&
        (Pfn1->u2.ShareCount == 0))
    {
        /* Clean copy: the tag says the slot holds this PTE's data now; the page goes to standby */
        MiSetPageFileSlotTag(FileIndex, Slot, MiPagerOwnerTagForPfn(Pfn1));
        MiPagerCounters.Written++;
    }
    else
    {
        /* Deleted, failed, dirtied or mapped again meanwhile: the slot goes (tag 0, ours to free) */
        MiReleasePageFileSlot(FileIndex, Slot, 0);
        MI_MAKE_SOFTWARE_PTE(&Pfn1->OriginalPte, Protection);
        if (!MI_IS_PFN_DELETED(Pfn1))
            Pfn1->u3.e1.Modified = 1;
        if (!NT_SUCCESS(Status))
            MiPagerCounters.WriteErrors++;
    }

    /* Faults that waited for the write retry now */
    Event = Pfn1->u1.Event;
    Pfn1->u1.Event = NULL;
    if (Event != NULL)
        KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    /* Our reference: the page goes to standby, back to modified, or free if it was deleted */
    MiDereferencePfnAndDropLockCount(Pfn1);
}

/*
 * The synchronous core of the modified page writer (P0: runs in the caller
 * that asked for it, with no lock held; P1 gives it a thread). Writes up to
 * MaximumPages private modified pages, one slot each, and returns how many
 * reached standby. The writer takes no working set, address space, paging
 * file creation or file system lock.
 */
ULONG
NTAPI
MiWriteModifiedPrivatePages(
    _In_ ULONG MaximumPages)
{
    PFN_NUMBER Batch[MI_PAGER_WRITE_BATCH];
    ULONG BatchFile[MI_PAGER_WRITE_BATCH];
    ULONG_PTR BatchSlot[MI_PAGER_WRITE_BATCH];
    NTSTATUS BatchStatus[MI_PAGER_WRITE_BATCH];
    PFN_NUMBER PageFrameIndex, Next, Resume = LIST_HEAD;
    ULONG Count, i, Done = 0, Attempts = 0, Failures = 0, FileIndex, Protection;
    ULONG_PTR Slot;
    PMMPFN Pfn1;
    KIRQL OldIrql;
    BOOLEAN NoSlot = FALSE;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    if ((MiNitroPagerMode == 0) || (MmNumberOfPagingFiles == 0))
        return 0;

    while ((Attempts < MaximumPages) && !NoSlot && (Failures < MI_PAGER_WRITE_FAILURE_LIMIT))
    {
        Count = 0;
        OldIrql = MiAcquirePfnLock();

        /* Go on where the last batch stopped, if that page is still waiting */
        PageFrameIndex = MmModifiedPageListByColor[0].Flink;
        if ((Resume != LIST_HEAD) &&
            (MI_PFN_ELEMENT(Resume)->u3.e1.PageLocation == ModifiedPageList) &&
            (MI_PFN_ELEMENT(Resume)->u3.e2.ReferenceCount == 0))
        {
            PageFrameIndex = Resume;
        }

        while ((PageFrameIndex != LIST_HEAD) &&
               (Count < MI_PAGER_WRITE_BATCH) &&
               (Attempts < MaximumPages))
        {
            Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);
            Next = Pfn1->u1.Flink;

            /* Private pages that are not being written and have no copy yet; PFN fields only */
            if ((Pfn1->u3.e1.PrototypePte == 0) &&
                !MI_IS_ROS_PFN(Pfn1) &&
                (Pfn1->u3.e2.ReferenceCount == 0) &&
                (Pfn1->u3.e1.WriteInProgress == 0) &&
                (Pfn1->u3.e1.PageLocation == ModifiedPageList) &&
                !MI_IS_PFN_DELETED(Pfn1) &&
                MiIsUserPageTablePte(Pfn1->PteAddress) &&
                (Pfn1->OriginalPte.u.Soft.Prototype == 0) &&
                (Pfn1->OriginalPte.u.Soft.Transition == 0) &&
                (Pfn1->OriginalPte.u.Soft.PageFileHigh == 0))
            {
                if (!MiAllocatePageFileSlot(&FileIndex, &Slot))
                {
                    MiPagerCounters.WriteNoSlot++;
                    NoSlot = TRUE;
                    break;
                }

                /* The slot is recorded in the PFN before the lock goes: a delete meanwhile finds it */
                Protection = (ULONG)Pfn1->OriginalPte.u.Soft.Protection;
                MiUnlinkPageFromList(Pfn1);
                MI_MAKE_PAGEFILE_PTE(&Pfn1->OriginalPte, FileIndex, Slot + 1, Protection);
                Pfn1->u3.e1.PageLocation = TransitionPage;
                Pfn1->u3.e1.WriteInProgress = 1;
                Pfn1->u3.e1.Modified = 0;
                Pfn1->u1.Event = NULL;
                MiReferenceUnusedPageAndBumpLockCount(Pfn1);

                Batch[Count] = PageFrameIndex;
                BatchFile[Count] = FileIndex;
                BatchSlot[Count] = Slot;
                Count++;
                Attempts++;
            }
            PageFrameIndex = Next;
        }
        Resume = PageFrameIndex;
        MiReleasePfnLock(OldIrql);

        if (Count == 0)
            break;

        /* The I/O, without the PFN lock; the pages are referenced and off every list */
        for (i = 0; i < Count; i++)
        {
            if (MiPagerTakeInjection(MI_PAGER_INJECT_WRITE_ERROR, MiPteToAddress(MI_PFN_ELEMENT(Batch[i])->PteAddress)))
                BatchStatus[i] = STATUS_DEVICE_DATA_ERROR;
            else
                BatchStatus[i] = MiWritePageFileSlot(Batch[i], BatchFile[i], BatchSlot[i]);
        }

        OldIrql = MiAcquirePfnLock();
        for (i = 0; i < Count; i++)
        {
            Pfn1 = MI_PFN_ELEMENT(Batch[i]);
            if (NT_SUCCESS(BatchStatus[i]))
            {
                Failures = 0;
                if (!MI_IS_PFN_DELETED(Pfn1) && (Pfn1->u3.e1.Modified == 0) && (Pfn1->u2.ShareCount == 0))
                    Done++;
            }
            else
            {
                Failures++;
            }
            MiCompletePageWrite(Pfn1, BatchFile[i], BatchSlot[i], BatchStatus[i]);
        }
        MiReleasePfnLock(OldIrql);
    }

    return Done;
}

/* Exclusive working set lock if it is free now (MiLockProcessWorkingSet's bookkeeping) */
static
BOOLEAN
MiTryLockProcessWorkingSet(
    _In_ PEPROCESS Process,
    _In_ PETHREAD Thread)
{
    ASSERT(Thread->OwnsProcessWorkingSetShared == FALSE);
    ASSERT(Thread->OwnsProcessWorkingSetExclusive == FALSE);

    KeEnterGuardedRegion();
    ASSERT(!MM_ANY_WS_LOCK_HELD(Thread));
    if (!ExTryToAcquirePushLockExclusive(&Process->Vm.WorkingSetMutex))
    {
        KeLeaveGuardedRegion();
        return FALSE;
    }
    ASSERT(!MI_IS_WS_UNSAFE(Process));
    Thread->OwnsProcessWorkingSetExclusive = TRUE;
    return TRUE;
}

typedef struct _MI_TRIM_CONTEXT
{
    MM_TB_FLUSH_LIST FlushList;
    PMMPFN Pages[32];
    ULONG Count;
    ULONG Trimmed;
    ULONG Dirty;
} MI_TRIM_CONTEXT, *PMI_TRIM_CONTEXT;

/* No processor can reach the trimmed pages any more: their last share reference goes */
static
VOID
MiTrimFlush(
    _Inout_ PMI_TRIM_CONTEXT Context)
{
    KIRQL OldIrql;
    ULONG i;

    MmFlushTbList(&Context->FlushList);
    if (Context->Count == 0)
        return;

    OldIrql = MiAcquirePfnLock();
    for (i = 0; i < Context->Count; i++)
        MiDecrementShareCount(Context->Pages[i], MiGetPfnEntryIndex(Context->Pages[i]));
    MiReleasePfnLock(OldIrql);
    Context->Count = 0;
}

/*
 * Trim one valid private PTE of the current process (working set lock held):
 * atomic exchange to the transition PTE, Dirty from the returned value (D8),
 * the share reference dropped after the TB flush.
 */
static
VOID
MiTrimPte(
    _In_ PMMPTE PointerPte,
    _In_ PVOID Address,
    _Inout_ PMI_TRIM_CONTEXT Context)
{
    MMPTE TempPte, NewPte, OldPte;
    PFN_NUMBER PageFrameIndex;
    PMMPFN Pfn1;
    KIRQL OldIrql;

    TempPte = *PointerPte;
    if (TempPte.u.Hard.Valid == 0)
        return;
    PageFrameIndex = PFN_FROM_PTE(&TempPte);
    Pfn1 = MiGetPfnEntry(PageFrameIndex);
    if (Pfn1 == NULL)
        return;

    OldIrql = MiAcquirePfnLock();
    TempPte = *PointerPte;
    if ((TempPte.u.Hard.Valid == 0) ||
        (PFN_FROM_PTE(&TempPte) != PageFrameIndex) ||
        MI_IS_ROS_PFN(Pfn1) ||
        (Pfn1->u3.e1.PrototypePte != 0) ||
        (Pfn1->PteAddress != PointerPte) ||
        (Pfn1->u3.e1.PageLocation != ActiveAndValid) ||
        (Pfn1->u2.ShareCount != 1) ||
        (Pfn1->u3.e2.ReferenceCount != 1) ||
        (Pfn1->u3.e1.ReadInProgress != 0) ||
        (Pfn1->u3.e1.WriteInProgress != 0) ||
        Pfn1->Wsle.u1.e1.LockedInWs ||
        Pfn1->Wsle.u1.e1.LockedInMemory ||
        (Pfn1->OriginalPte.u.Soft.Protection == 0))
    {
        /* Shared, locked (VirtualLock or an MDL), or not an ordinary private page */
        MiReleasePfnLock(OldIrql);
        return;
    }

    MI_MAKE_TRANSITION_PTE(&NewPte, PageFrameIndex, (ULONG)Pfn1->OriginalPte.u.Soft.Protection);
    OldPte.u.Long = InterlockedExchangePte(PointerPte, NewPte.u.Long);
    if (OldPte.u.Hard.Dirty)
    {
        MiMarkPfnDirty(Pfn1);
        Context->Dirty++;
        MiPagerCounters.TrimmedDirty++;
    }
    MiReleasePfnLock(OldIrql);

    MiPagerCounters.Trimmed++;
    Context->Trimmed++;
    MmAddToTbFlushList(&Context->FlushList, Address);
    Context->Pages[Context->Count++] = Pfn1;
    if (Context->Count == RTL_NUMBER_OF(Context->Pages))
        MiTrimFlush(Context);
}

/*
 * One pass over the private VADs of the current process, working set lock
 * held. Skipped: RosMm views, section views (P2), AWE, large pages, physical
 * and rotate VADs, write watch (P5), and the kernel-secured PEB/TEB/shared
 * data VADs, whose pages kernel code may touch where it cannot fault.
 * Invalid upper levels are stepped over without touching their PTEs.
 */
static
VOID
MiTrimCurrentProcess(
    _In_ PEPROCESS Process,
    _Inout_ PMI_TRIM_CONTEXT Context)
{
    PMMADDRESS_NODE Node;
    PMMVAD Vad;
    ULONG_PTR Va, End;
    PMMPTE PointerPte;
    PMMPDE PointerPde;

    for (Node = MiGetFirstNode(&Process->VadRoot); Node != NULL; Node = MiGetNextNode(Node))
    {
        Vad = (PMMVAD)Node;
        if (MI_IS_MEMORY_AREA_VAD(Vad) ||
            (Vad->u.VadFlags.PrivateMemory == 0) ||
            (Vad->u.VadFlags.VadType != VadNone) ||
            (Vad->u.VadFlags.NoChange != 0))
        {
            continue;
        }

        Va = Vad->StartingVpn << PAGE_SHIFT;
        End = (Vad->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1);
        if (End > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS)
            End = (ULONG_PTR)MM_HIGHEST_USER_ADDRESS;

        while (Va <= End)
        {
#if (_MI_PAGING_LEVELS >= 4)
            PMMPXE PointerPxe = MiAddressToPxe((PVOID)Va);
            if (!PointerPxe->u.Hard.Valid)
            {
                Va = (ULONG_PTR)MiPxeToAddress(PointerPxe + 1);
                continue;
            }
#endif
#if (_MI_PAGING_LEVELS >= 3)
            {
                PMMPPE PointerPpe = MiAddressToPpe((PVOID)Va);
                if (!PointerPpe->u.Hard.Valid)
                {
                    Va = (ULONG_PTR)MiPpeToAddress(PointerPpe + 1);
                    continue;
                }
            }
#endif
            PointerPde = MiAddressToPde((PVOID)Va);
            if (!PointerPde->u.Hard.Valid || PointerPde->u.Hard.LargePage)
            {
                Va = (ULONG_PTR)MiPdeToAddress(PointerPde + 1);
                continue;
            }

            PointerPte = MiAddressToPte((PVOID)Va);
            do
            {
                if (PointerPte->u.Hard.Valid)
                    MiTrimPte(PointerPte, (PVOID)Va, Context);
                PointerPte++;
                Va += PAGE_SIZE;
            } while ((Va <= End) && (Va != 0) && !MiIsPteOnPdeBoundary(PointerPte));
            if (Va == 0)
                break;
        }
    }
}

/*
 * EmptyWorkingSet of one process (P0: one pass, then the writer for what
 * went to the modified list). The caller is attached to Process with APCs
 * disabled. TryLockOnly: give up if the working set lock is busy.
 */
NTSTATUS
NTAPI
MiEmptyProcessWorkingSet(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN TryLockOnly)
{
    PETHREAD Thread = PsGetCurrentThread();
    MI_TRIM_CONTEXT Context;

    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(MiNitroPagerMode != 0);

    MmLockAddressSpace(&Process->Vm);
    if (Process->VmDeleted)
    {
        MmUnlockAddressSpace(&Process->Vm);
        return STATUS_SUCCESS;
    }

    if (TryLockOnly)
    {
        if (!MiTryLockProcessWorkingSet(Process, Thread))
        {
            MiPagerCounters.WsTryLockMisses++;
            MmUnlockAddressSpace(&Process->Vm);
            return STATUS_SUCCESS;
        }
    }
    else
    {
        MiLockProcessWorkingSet(Process, Thread);
    }

    /* User addresses: only the processors running this process cache them */
    MmInitializeTbFlushList(&Context.FlushList, FALSE);
    Context.Count = 0;
    Context.Trimmed = 0;
    Context.Dirty = 0;
    MiTrimCurrentProcess(Process, &Context);
    MiTrimFlush(&Context);

    MiUnlockProcessWorkingSet(Process, Thread);
    MmUnlockAddressSpace(&Process->Vm);

    /* P0 has no writer thread: write what went to the modified list now */
    if (Context.Dirty != 0)
        MiWriteModifiedPrivatePages(Context.Dirty);

    return STATUS_SUCCESS;
}

/* Memory list command "empty working sets": every process that has an address space */
static
VOID
MiEmptyAllWorkingSets(VOID)
{
    PEPROCESS Process = NULL;
    KAPC_STATE ApcState;

    while ((Process = PsGetNextProcess(Process)) != NULL)
    {
        if ((Process == PsInitialSystemProcess) ||
            (Process == PsIdleProcess) ||
            Process->VmDeleted ||
            (Process->AddressSpaceInitialized < 2))
        {
            continue;
        }

        KeStackAttachProcess(&Process->Pcb, &ApcState);
        KeEnterGuardedRegion();
        MiEmptyProcessWorkingSet(Process, TRUE);
        KeLeaveGuardedRegion();
        KeUnstackDetachProcess(&ApcState);
    }
}

/*
 * NtSetSystemInformation(SystemMemoryListInformation), NitroPager on. Order as
 * on Windows (oracle, 2026-11-06): an unknown command fails before the
 * privilege check, then SeProfileSingleProcessPrivilege.
 */
NTSTATUS
NTAPI
MmSetMemoryListInformation(
    _In_ ULONG Command,
    _In_opt_ PVOID Address,
    _In_ KPROCESSOR_MODE PreviousMode)
{
    BOOLEAN TestCommand;

    PAGED_CODE();
    ASSERT(MiNitroPagerMode != 0);

    /* Test hooks, only with NitroPagerDebug set: they name a user page of the caller */
    TestCommand = (MiNitroPagerDebug != 0) &&
                  (Command > MI_PAGER_TEST_COMMAND_BASE) &&
                  (Command <= MI_PAGER_TEST_PING) &&
                  ((Address != NULL) || (Command == MI_PAGER_TEST_PING)) &&
                  (Address <= MM_HIGHEST_USER_ADDRESS);

    if ((Command >= MI_MEMORY_COMMAND_MAX) && !TestCommand)
        return STATUS_INVALID_PARAMETER;

    if (!SeSinglePrivilegeCheck(SeProfileSingleProcessPrivilege, PreviousMode))
        return STATUS_PRIVILEGE_NOT_HELD;

    switch (Command)
    {
        case MI_MEMORY_CAPTURE_ACCESSED_BITS:
        case MI_MEMORY_CAPTURE_AND_RESET_ACCESSED_BITS:
            /* There is no page aging to capture into (P5) */
            return STATUS_SUCCESS;

        case MI_MEMORY_EMPTY_WORKING_SETS:
            MiEmptyAllWorkingSets();
            return STATUS_SUCCESS;

        case MI_MEMORY_FLUSH_MODIFIED_LIST:
            MiWriteModifiedPrivatePages(MAXULONG);
            return STATUS_SUCCESS;

        case MI_MEMORY_PURGE_STANDBY_LIST:
        case MI_MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST:
            /* One standby priority for private pages in P0: both purges are the same */
            MiPurgePrivateStandbyPages();
            return STATUS_SUCCESS;

        case MI_PAGER_TEST_FAIL_NEXT_READ:
            MiPagerArmInjection(MI_PAGER_INJECT_READ_ERROR, Address);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_FAIL_NEXT_WRITE:
            MiPagerArmInjection(MI_PAGER_INJECT_WRITE_ERROR, Address);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_MISMATCH_NEXT_READ:
            MiPagerArmInjection(MI_PAGER_INJECT_TAG_MISMATCH, Address);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_STARVE_NEXT_READ:
            MiPagerArmInjection(MI_PAGER_INJECT_READ_RESOURCES, Address);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_PING:
            return STATUS_SUCCESS;

        default:
            ASSERT(FALSE);
            return STATUS_INVALID_PARAMETER;
    }
}

/* NtQuerySystemInformation(SystemMemoryListInformation), NitroPager on */
NTSTATUS
NTAPI
MmQueryMemoryListInformation(
    _Out_ PSYSTEM_MEMORY_LIST_INFORMATION Information)
{
    SYSTEM_MEMORY_LIST_INFORMATION Local;
    KIRQL OldIrql;
    ULONG i;

    ASSERT(MiNitroPagerMode != 0);
    RtlZeroMemory(&Local, sizeof(Local));

    /* A consistent snapshot under the lock, copied to the caller's buffer without it */
    OldIrql = MiAcquirePfnLock();
    Local.ZeroPageCount = MmZeroedPageListHead.Total;
    Local.FreePageCount = MmFreePageListHead.Total;
    Local.ModifiedPageCount = MmModifiedPageListHead.Total;
    Local.ModifiedNoWritePageCount = MmModifiedNoWritePageListHead.Total;
    Local.BadPageCount = MmBadPageListHead.Total;
    for (i = 0; i < 8; i++)
    {
        Local.PageCountByPriority[i] = MmStandbyPageListByPriority[i].Total;
        Local.RepurposedPagesByPriority[i] = MiRepurposedByPriority[i];
    }
    Local.ModifiedPageCountPageFile = MmTotalPagesForPagingFile;
    MiReleasePfnLock(OldIrql);

    RtlCopyMemory(Information, &Local, sizeof(Local));
    return STATUS_SUCCESS;
}

/* EOF */
