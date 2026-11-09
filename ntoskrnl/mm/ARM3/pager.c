/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NitroPager phases P0 and P1: page-out of ARM3 private memory.
 *              Dirty capture and page-file slot ownership of private PFNs,
 *              standby repurpose, the explicit working set trim
 *              (EmptyWorkingSet), the modified page writer (synchronous core,
 *              P1 thread with cluster writes), automatic trimming from the
 *              balancer, slot reclaim and the SystemMemoryListInformation
 *              commands
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Design: harness process/PAGER-DESIGN.md rev 2, phases P0/P1. Everything here is
 * reached only when the NitroPager mode (Session Manager\Memory Management
 * value NitroPager, read once at boot) is not 0. The default (the kernel's own
 * value when the registry has none, and what setup writes) is 1 on amd64 and 0
 * on other architectures (MI_NITRO_PAGER_DEFAULT); 0 keeps the behaviour the
 * memory manager had before, the LiveCD sets it.
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

/*
 * NitroPager / NitroPagerDebug (CmControlVector, read once at boot; an absent NitroPager value leaves the
 * default). The default is 1 on amd64 (2026.11-1) and 0 elsewhere: i386 has not passed its gate yet (the
 * 2 h soak at 512 MB, review rvpagerdef). Setup writes the same value per architecture (hivesys_ARCH.inf).
 */
#if defined(_M_AMD64)
#define MI_NITRO_PAGER_DEFAULT 1
#else
#define MI_NITRO_PAGER_DEFAULT 0
#endif
ULONG MiNitroPagerMode = MI_NITRO_PAGER_DEFAULT;
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
#define MI_PAGER_TEST_MISMATCH_NEXT_FREE            (MI_PAGER_TEST_COMMAND_BASE + 6)
#define MI_PAGER_TEST_PAUSE_NEXT_WRITE              (MI_PAGER_TEST_COMMAND_BASE + 7)
#define MI_PAGER_TEST_RESUME_WRITE                  (MI_PAGER_TEST_COMMAND_BASE + 8)
#define MI_PAGER_TEST_QUERY_PAUSED                  (MI_PAGER_TEST_COMMAND_BASE + 9)
#define MI_PAGER_TEST_QUERY_FREE_REFUSED            (MI_PAGER_TEST_COMMAND_BASE + 10)
/* Exhaustion tests (pagerdef): hold every usable page above a floor for Address seconds (the caller waits) */
#define MI_PAGER_TEST_HOLD_PAGES                    (MI_PAGER_TEST_COMMAND_BASE + 11)
/* The next cluster writes (writer thread or synchronous flush) never complete (a hung paging device), until the boot ends */
#define MI_PAGER_TEST_HANG_WRITES                   (MI_PAGER_TEST_COMMAND_BASE + 12)
#define MI_PAGER_TEST_LAST                          MI_PAGER_TEST_HANG_WRITES

/* MI_PAGER_TEST_HOLD_PAGES: the pages it leaves (above the waitable floor, below the balancer's starved mark) */
#define MI_PAGER_TEST_HOLD_FLOOR    (MI_PAGER_WAITABLE_FLOOR + 64)
#define MI_PAGER_TEST_HOLD_SECONDS  1800
static volatile LONG MiPagerHangWrites;

/* Writer pause (test): how long the writer waits for the resume command at most */
#define MI_PAGER_TEST_PAUSE_SECONDS 30
static KEVENT MiPagerPauseEvent;
static volatile LONG MiPagerWriterPaused;
static volatile LONG MiPagerPauseReady;
static volatile ULONG MiPagerFreeRefusedBase;

/* NitroPagerDebug bits that inject write failures (any build; test commands need the value non-zero anyway) */
#define MI_PAGER_DEBUG_FAIL_SOME_WRITES 0x10
#define MI_PAGER_DEBUG_FAIL_ALL_WRITES  0x20
/* Test of the exhaustion check: the trimmer frees nothing, starved means below the low-water mark, the window is 15 s */
#define MI_PAGER_DEBUG_TRIM_NOTHING     0x40
/* Every third IRP or MDL allocation for paging-file I/O fails (Io and NTFS-NG): the reserve IRP/MDL paths run */
#define MI_PAGER_DEBUG_FAIL_PAGING_ALLOC 0x80
/* Every cluster write fails during the first 300 s after the writer starts, then the disk "recovers" */
#define MI_PAGER_DEBUG_FAIL_WRITES_EARLY 0x200
/* No pacing of RosMm page requests (MiPagerPaceRequest): A/B tests */
#define MI_PAGER_DEBUG_NO_PACING         0x400
#define MI_PAGER_FAIL_EARLY_SECONDS      300

/* Writer batch: pages taken per PFN lock hold */
#define MI_PAGER_WRITE_BATCH 16

/* Standby pages looked at per list for one repurpose */
#define MI_PAGER_REPURPOSE_SCAN 64

/* Modified list entries the writer looks at per PFN lock hold */
#define MI_PAGER_SCAN_PER_HOLD 1024

/* Consecutive write failures after which a flush stops */
#define MI_PAGER_WRITE_FAILURE_LIMIT 8

/*
 * P1: the modified page writer thread, automatic trimming, slot reclaim.
 */

/* Paging I/O (writer clusters, page-file reads of faults) in flight: the "game over" check and the reserve watch it */
volatile LONG MiPagingIoInFlight;
/* Interrupt time when paging I/O last started from idle or completed: in-flight I/O older than this window is stuck */
static volatile ULONGLONG MiPagingIoLastEvent;
/*
 * Cluster writes in flight (writer thread and synchronous flushes) and the interrupt
 * time since which at least one has been in flight without any of them completing
 * (0 = none in flight). A completion while others remain restarts the clock: their
 * start is not known, so the age is never overestimated.
 */
static volatile LONG MiPagerClusterWrites;
static volatile ULONGLONG MiPagerWriterIoStart;

/* 64-bit interrupt-time stamps read and written whole, also on i386 (no torn value across a 2^32 boundary) */
FORCEINLINE
ULONGLONG
MiPagerReadStamp(
    _In_ volatile ULONGLONG *Stamp)
{
    return (ULONGLONG)InterlockedCompareExchange64((volatile LONGLONG *)Stamp, 0, 0);
}

FORCEINLINE
VOID
MiPagerWriteStamp(
    _Inout_ volatile ULONGLONG *Stamp,
    _In_ ULONGLONG Value)
{
    LONGLONG Old;

    do
    {
        Old = *(volatile LONGLONG *)Stamp;
    } while (InterlockedCompareExchange64((volatile LONGLONG *)Stamp, (LONGLONG)Value, Old) != Old);
}
#define MI_PAGER_IO_STUCK_AFTER (120ULL * 10 * 1000 * 1000)
/* Fourth NO_PAGES_AVAILABLE parameter: writer state, plus this flag when paging I/O was in flight but stuck */
#define MI_WRITER_IO_STUCK 0x100

/* Writer core instances inside a cluster write (shutdown waits for 0) */
static volatile LONG MiPagerWritesActive;

/* Set once by MiPagerShutdownWriter: no new writes, no more trimming */
static volatile LONG MiPagerShutdown;

/* Writer thread: 0 not started, 1 starting, 2 running */
static volatile LONG MiPagerWriterStarted;
static PETHREAD MiPagerWriterThreadObject;
static ULONGLONG MiPagerWriterStartTime;
static KEVENT MiPagerWriterEvent;
static KEVENT MiPagerWriterStopped;
static volatile LONG MiPagerWakePending;

/* What the writer is doing (fourth parameter of a NO_PAGES_AVAILABLE bugcheck) */
#define MI_WRITER_IDLE      0
#define MI_WRITER_WRITING   1
#define MI_WRITER_NO_SLOT   2
#define MI_WRITER_BACKOFF   3
#define MI_WRITER_STOPPED   4
#define MI_WRITER_NOT_RUNNING 5
static volatile LONG MiPagerWriterState = MI_WRITER_NOT_RUNNING;

/* Interrupt time of the last completed cluster write */
static volatile ULONGLONG MiPagerLastProgress;

/* FALSE after a writer scan found no private page it could write, TRUE again when one is queued */
static volatile LONG MiPagerWritable;
/* Private pages queued on the modified list (wraps): an empty writer scan clears Writable only if none came meanwhile */
static volatile LONG MiPagerQueued;

/* Free ARM3 slots are short: trimming sends no dirty page to the modified list */
static volatile BOOLEAN MiPagerSlotsShort;
#define MI_PAGER_SLOT_LOW 512

/* The writer runs at this many modified pages (1/16 of RAM, at least 256) or when available pages are low */
static PFN_NUMBER MiPagerModifiedMaximum = 256;

/* The balancer's low-water mark of free pages (balance.c) */
extern ULONG MiLowWaterPages;

/*
 * Below an eighth of the low-water mark (at least 512 pages) the trimmer
 * ignores the Accessed bit: with every resident page in use between two
 * passes (a working set that walks all of its memory), aging alone never
 * finds a page. Above it only pages unused since the last pass go: forcing
 * there trims hot pages that fault straight back (a soak with a working set
 * that fits RAM did 7000 trims/s at a threshold of half the mark, tuning).
 */
#define MI_PAGER_FORCE_TRIM_MINIMUM 512

/* Trimmer budgets per process and balancer pass (tuning) */
#define MI_TRIM_EXAMINE_BUDGET  16384
#define MI_TRIM_PAGE_BUDGET     2048
#define MI_TRIM_STARVE_LIMIT    3
/* At least as many cursors as processes per pass: a lookup never evicts a cursor stamped in this pass */
#define MI_TRIM_CURSORS         256
#define MI_TRIM_PROCESSES       256

/* How long the "game over" check counts a completed write as progress */
#define MI_PAGER_PROGRESS_WINDOW (10ULL * 10 * 1000 * 1000)

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
    if ((Which == MI_PAGER_INJECT_TAG_MISMATCH) || (Which == MI_PAGER_INJECT_FREE_MISMATCH))
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
    ULONG Protection, Owner;

    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(MI_IS_PAGEFILE_PTE(&Pfn1->OriginalPte));
    ASSERT(Pfn1->u3.e1.PrototypePte == 0);
    ASSERT(Pfn1->u3.e1.WriteInProgress == 0);

    Protection = (ULONG)Pfn1->OriginalPte.u.Soft.Protection;
    Owner = MiPagerOwnerTagForPfn(Pfn1);
    if (MiPagerTakeInjection(MI_PAGER_INJECT_FREE_MISMATCH, MiPteToAddress(Pfn1->PteAddress)))
    {
        /* Test: the free names another owner, it must be refused (the slot is leaked, never reused) */
        Owner = ~Owner;
        if (Owner == 0)
            Owner = 1;
    }
    MiReleasePageFileSlot((ULONG)Pfn1->OriginalPte.u.Soft.PageFileLow,
                          MI_PAGEFILE_PTE_SLOT(&Pfn1->OriginalPte),
                          Owner);
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
 * The core of the modified page writer: the P1 thread runs it, and so do the
 * explicit requests (EmptyWorkingSet, the memory list flush command) in their
 * own thread with no lock held. Writes up to MaximumPages private modified
 * pages in clusters of up to MI_PAGER_CLUSTER_MAX consecutive slots (one
 * paging write each) and returns how many reached standby. *Attempted gets
 * the pages it took, *NoSlot is set when it stopped for lack of a slot,
 * *Failing when writes kept failing. The writer takes no working set,
 * address space, paging file creation or file system lock.
 */
static
ULONG
MiWriteModifiedPrivatePagesEx(
    _In_ ULONG MaximumPages,
    _Out_ PULONG Attempted,
    _Out_ PBOOLEAN NoSlot,
    _Out_ PBOOLEAN Failing)
{
    PFN_NUMBER Candidates[MI_PAGER_CLUSTER_MAX];
    PFN_NUMBER Batch[MI_PAGER_CLUSTER_MAX];
    PFN_NUMBER PageFrameIndex, Next, Resume = LIST_HEAD, Scanned = 0;
    ULONG Count, Taken, i, Done = 0, Attempts = 0, Failures = 0, FileIndex, Protection, Looked;
    ULONG_PTR FirstSlot;
    NTSTATUS Status;
    PMMPFN Pfn1;
    KIRQL OldIrql;
    BOOLEAN Pause;

    *Attempted = 0;
    *NoSlot = FALSE;
    *Failing = FALSE;
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    if ((MiNitroPagerMode == 0) || (MmNumberOfPagingFiles == 0))
        return 0;

    while ((Attempts < MaximumPages) && (Failures < MI_PAGER_WRITE_FAILURE_LIMIT))
    {
        /* Counted before the shutdown check: shutdown sets its flag, then waits for 0 */
        InterlockedIncrement(&MiPagerWritesActive);
        if (MiPagerShutdown)
        {
            InterlockedDecrement(&MiPagerWritesActive);
            break;
        }

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

        /*
         * Private pages that are not being written and have no copy yet; PFN fields only,
         * at most MI_PAGER_SCAN_PER_HOLD entries per PFN lock hold (pages the writer cannot
         * take, prototype pages until P2, may fill the list)
         */
        Looked = 0;
        while ((PageFrameIndex != LIST_HEAD) &&
               (Count < MI_PAGER_CLUSTER_MAX) &&
               (Attempts + Count < MaximumPages) &&
               (Looked < MI_PAGER_SCAN_PER_HOLD))
        {
            Looked++;
            Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);
            Next = Pfn1->u1.Flink;
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
                Candidates[Count++] = PageFrameIndex;
            }
            PageFrameIndex = Next;
        }
        Resume = PageFrameIndex;
        Scanned += Looked;

        if (Count == 0)
        {
            MiReleasePfnLock(OldIrql);
            InterlockedDecrement(&MiPagerWritesActive);

            /* The end of the list, or a whole list's worth looked at: nothing to write */
            if ((PageFrameIndex == LIST_HEAD) || (Scanned > MmModifiedPageListHead.Total))
                break;
            continue;
        }

        /* One run of consecutive slots for the cluster (slot lock nested, leaf); a shorter run takes fewer pages */
        Taken = MiAllocatePageFileSlots(Count, &FileIndex, &FirstSlot);
        if (Taken == 0)
        {
            MiReleasePfnLock(OldIrql);
            InterlockedDecrement(&MiPagerWritesActive);
            MiPagerCounters.WriteNoSlot++;
            *NoSlot = TRUE;
            break;
        }
        if (Taken < Count)
            Resume = Candidates[Taken];

        for (i = 0; i < Taken; i++)
        {
            /* The slot is recorded in the PFN before the lock goes: a delete meanwhile finds it */
            Pfn1 = MI_PFN_ELEMENT(Candidates[i]);
            Protection = (ULONG)Pfn1->OriginalPte.u.Soft.Protection;
            MiUnlinkPageFromList(Pfn1);
            MI_MAKE_PAGEFILE_PTE(&Pfn1->OriginalPte, FileIndex, FirstSlot + i + 1, Protection);
            Pfn1->u3.e1.PageLocation = TransitionPage;
            Pfn1->u3.e1.WriteInProgress = 1;
            Pfn1->u3.e1.Modified = 0;
            Pfn1->u1.Event = NULL;
            MiReferenceUnusedPageAndBumpLockCount(Pfn1);
            Batch[i] = Candidates[i];
        }
        Attempts += Taken;
        MiReleasePfnLock(OldIrql);

        /* The I/O, without the PFN lock; the pages are referenced and off every list */
        Status = STATUS_SUCCESS;
        Pause = FALSE;
        for (i = 0; i < Taken; i++)
        {
            PVOID PageAddress = MiPteToAddress(MI_PFN_ELEMENT(Batch[i])->PteAddress);

            if (MiPagerTakeInjection(MI_PAGER_INJECT_WRITE_ERROR, PageAddress))
                Status = STATUS_DEVICE_DATA_ERROR;
            if (MiPagerTakeInjection(MI_PAGER_INJECT_WRITE_PAUSE, PageAddress))
                Pause = TRUE;
        }

        /*
         * Test (NitroPagerDebug bits): 0x10 fails every 50th cluster write, 0x20 fails
         * every cluster write (file retirement, the writer must stop, not loop)
         */
        if (NT_SUCCESS(Status) && (MiNitroPagerDebug & (MI_PAGER_DEBUG_FAIL_SOME_WRITES | MI_PAGER_DEBUG_FAIL_ALL_WRITES)))
        {
            static LONG ClusterNumber;

            if ((MiNitroPagerDebug & MI_PAGER_DEBUG_FAIL_ALL_WRITES) ||
                ((InterlockedIncrement(&ClusterNumber) % 50) == 0))
            {
                Status = STATUS_DEVICE_DATA_ERROR;
            }
        }

        /* Test: the disk fails every write for a while after boot, then recovers (retirement and its probe) */
        if (NT_SUCCESS(Status) && (MiNitroPagerDebug & MI_PAGER_DEBUG_FAIL_WRITES_EARLY) &&
            ((KeQueryInterruptTime() - MiPagerWriterStartTime) < MI_PAGER_FAIL_EARLY_SECONDS * 10ULL * 1000 * 1000))
        {
            Status = STATUS_DEVICE_DATA_ERROR;
        }

        MiPagingIoStart();
        if (InterlockedIncrement(&MiPagerClusterWrites) == 1)
            MiPagerWriteStamp(&MiPagerWriterIoStart, KeQueryInterruptTime());
        if (MiPagerHangWrites)
        {
            LARGE_INTEGER Forever;

            /* Test: a paging device that never completes the write (in flight until the boot ends) */
            DbgPrint("NitroPager: test: a cluster write hangs (%s)\n", MiPagerIsWriterThread() ? "writer thread" : "synchronous flush");
            Forever.QuadPart = -3600LL * 10 * 1000 * 1000;
            for (;;)
                KeDelayExecutionThread(KernelMode, FALSE, &Forever);
        }
        if (NT_SUCCESS(Status))
            Status = MiWritePageFileCluster(Batch, Taken, FileIndex, FirstSlot);
        MiPagerWriteStamp(&MiPagerWriterIoStart, (InterlockedDecrement(&MiPagerClusterWrites) == 0) ? 0 : KeQueryInterruptTime());
        MiPagingIoDone();

        /* Test: hold the completion of this cluster until the test says go (written, referenced, off every list) */
        if (Pause)
        {
            LARGE_INTEGER Timeout;

            Timeout.QuadPart = -(LONGLONG)MI_PAGER_TEST_PAUSE_SECONDS * 10 * 1000 * 1000;
            InterlockedExchange(&MiPagerWriterPaused, 1);
            KeWaitForSingleObject(&MiPagerPauseEvent, Executive, KernelMode, FALSE, &Timeout);
            InterlockedExchange(&MiPagerWriterPaused, 0);
        }

        MiPagerPagingFileWriteResult(FileIndex, Status);
        if (NT_SUCCESS(Status))
        {
            Failures = 0;
            MiPagerCounters.Clusters++;
            MiPagerLastProgress = KeQueryInterruptTime();
        }
        else
        {
            Failures++;
        }

        OldIrql = MiAcquirePfnLock();
        for (i = 0; i < Taken; i++)
        {
            Pfn1 = MI_PFN_ELEMENT(Batch[i]);
            if (NT_SUCCESS(Status) && !MI_IS_PFN_DELETED(Pfn1) && (Pfn1->u3.e1.Modified == 0) && (Pfn1->u2.ShareCount == 0))
                Done++;
            MiCompletePageWrite(Pfn1, FileIndex, FirstSlot + i, Status);
        }
        MiReleasePfnLock(OldIrql);
        InterlockedDecrement(&MiPagerWritesActive);

        /* Back off after a failed write (100 ms more per failure, at most 1 s): errors spread over time */
        if (!NT_SUCCESS(Status))
        {
            LARGE_INTEGER Delay;

            Delay.QuadPart = -(LONGLONG)min(Failures * 100, 1000) * 10000;
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        }
    }

    *Attempted = Attempts;
    *Failing = (Failures >= MI_PAGER_WRITE_FAILURE_LIMIT);
    return Done;
}

ULONG
NTAPI
MiWriteModifiedPrivatePages(
    _In_ ULONG MaximumPages)
{
    ULONG Attempted;
    BOOLEAN NoSlot, Failing;

    return MiWriteModifiedPrivatePagesEx(MaximumPages, &Attempted, &NoSlot, &Failing);
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
    /* P1: slots are short, leave pages that would go to the modified list */
    BOOLEAN CleanOnly;
    ULONG Aged;
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
BOOLEAN
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
        return FALSE;
    PageFrameIndex = PFN_FROM_PTE(&TempPte);
    Pfn1 = MiGetPfnEntry(PageFrameIndex);
    if (Pfn1 == NULL)
        return FALSE;

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
        (Pfn1->u3.e1.CacheAttribute != MiCached) ||
        Pfn1->Wsle.u1.e1.LockedInWs ||
        Pfn1->Wsle.u1.e1.LockedInMemory ||
        (Pfn1->OriginalPte.u.Soft.Protection == 0))
    {
        /*
         * Shared, locked (VirtualLock or an MDL), or not an ordinary private page.
         * Non-cached and write-combined pages (PAGE_NOCACHE / PAGE_WRITECOMBINE
         * mappings) are never trimmed: a repurposed page is reused as an ordinary
         * cached page, and nothing here proves that is safe for them.
         */
        MiReleasePfnLock(OldIrql);
        return FALSE;
    }

    /* P1: no slot for a dirty page now, so it would only sit on the modified list */
    if (Context->CleanOnly && (Pfn1->u3.e1.Modified || TempPte.u.Hard.Dirty))
    {
        MiReleasePfnLock(OldIrql);
        MiPagerCounters.TrimSkippedDirty++;
        return FALSE;
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
    return TRUE;
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
    Context.CleanOnly = FALSE;
    Context.Aged = 0;
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

/* P1 ************************************************************************/

/*
 * Wake the writer thread. Any IRQL <= DISPATCH_LEVEL, also under the PFN lock
 * (the dispatcher lock nests inside it, as for the low memory events).
 */
VOID
NTAPI
MiPagerWakeWriter(VOID)
{
    if (MiPagerWriterStarted != 2)
        return;
    if (InterlockedExchange(&MiPagerWakePending, 1) == 0)
        KeSetEvent(&MiPagerWriterEvent, IO_NO_INCREMENT, FALSE);
}

/* Paging I/O starts (any IRQL <= APC_LEVEL; also counted at flag 0, where nothing reads it) */
VOID
NTAPI
MiPagingIoStart(VOID)
{
    /* The stamp first: a reader that sees the count up never pairs it with an old idle-time stamp */
    if (MiPagingIoInFlight == 0)
        MiPagerWriteStamp(&MiPagingIoLastEvent, KeQueryInterruptTime());
    InterlockedIncrement(&MiPagingIoInFlight);
}

/* Paging I/O completed: in-flight I/O made progress now */
VOID
NTAPI
MiPagingIoDone(VOID)
{
    MiPagerWriteStamp(&MiPagingIoLastEvent, KeQueryInterruptTime());
    InterlockedDecrement(&MiPagingIoInFlight);
}

/*
 * Paging I/O is stuck: in flight with nothing started from idle or completed
 * for MI_PAGER_IO_STUCK_AFTER (a hung device), or a cluster write (writer
 * thread or synchronous flush) has been in flight that long with no cluster
 * completing (page reads completing meanwhile do not write modified pages)
 */
static
BOOLEAN
MiPagingIoStuck(VOID)
{
    ULONGLONG Now = KeQueryInterruptTime(), WriteStart = MiPagerReadStamp(&MiPagerWriterIoStart);
    ULONGLONG LastEvent = MiPagerReadStamp(&MiPagingIoLastEvent);

    if (MiPagingIoInFlight <= 0)
        return FALSE;
    if ((Now > LastEvent) && ((Now - LastEvent) >= MI_PAGER_IO_STUCK_AFTER))
        return TRUE;
    /* The write branch only while a cluster write really is in flight (a start left by racing completions is stale) */
    return (MiPagerClusterWrites > 0) && (WriteStart != 0) && (Now > WriteStart) &&
           ((Now - WriteStart) >= MI_PAGER_IO_STUCK_AFTER);
}

BOOLEAN
NTAPI
MiPagerIsWriterThread(VOID)
{
    return (MiPagerWriterThreadObject != NULL) && (PsGetCurrentThread() == MiPagerWriterThreadObject);
}

/*
 * N6 (pagerdef): a RosMm page request that may wait (Cc views, section and
 * image pages: MmRequestPageMemoryConsumer with CanWait, not MC_SYSTEM) while
 * paging I/O is in flight and usable pages are below the waitable floor waits
 * here a little, so that the writer's and the
 * in-page reads' own allocations (IRPs, SRB extensions, S/G lists, work items)
 * find the last pages first, within a per-thread budget (below). It never waits for the balancer or for a lock:
 * the caller may hold file system or segment locks the balancer needs, and a
 * bounded delay cannot deadlock with them. The balancer and the writer never
 * pace (they are the ones freeing pages).
 */
/*
 * Pacing budget (review rvpagerdef: bounded per call is not bounded per operation; a view fill or a
 * process start asks for hundreds of pages): a thread is paced for at most MI_PAGER_PACE_BUDGET_MS in any
 * MI_PAGER_PACE_WINDOW. Kept in a small table hashed by thread; two threads sharing a slot reset each
 * other's window, which only paces one of them a little more or less (heuristic, no lock).
 */
#define MI_PAGER_PACE_SLOTS      64
#define MI_PAGER_PACE_BUDGET_MS  100
#define MI_PAGER_PACE_STEP_MS    10
#define MI_PAGER_PACE_WINDOW     (10ULL * 1000 * 1000)
typedef struct _MI_PAGER_PACE_SLOT
{
    PETHREAD Thread;
    ULONGLONG WindowStart;
    ULONG UsedMs;
} MI_PAGER_PACE_SLOT;
static MI_PAGER_PACE_SLOT MiPagerPaceSlots[MI_PAGER_PACE_SLOTS];

VOID
NTAPI
MiPagerPaceRequest(VOID)
{
    PETHREAD Thread = PsGetCurrentThread();
    MI_PAGER_PACE_SLOT *Slot;
    LARGE_INTEGER Delay;
    ULONGLONG Now;

    if ((MiNitroPagerMode == 0) || (MmNumberOfPagingFiles == 0) || MiPagerShutdown ||
        (MiNitroPagerDebug & MI_PAGER_DEBUG_NO_PACING) ||
        (KeGetCurrentIrql() > APC_LEVEL) || MiPagerIsWriterThread())
    {
        return;
    }
    if ((MiPagingIoInFlight <= 0) || (MiGetUsablePageCount() >= MI_PAGER_WAITABLE_FLOOR))
        return;

    Slot = &MiPagerPaceSlots[((ULONG_PTR)Thread >> 6) % MI_PAGER_PACE_SLOTS];
    Now = KeQueryInterruptTime();
    if ((Slot->Thread != Thread) || ((Now - Slot->WindowStart) >= MI_PAGER_PACE_WINDOW))
    {
        Slot->Thread = Thread;
        Slot->WindowStart = Now;
        Slot->UsedMs = 0;
    }
    if (Slot->UsedMs >= MI_PAGER_PACE_BUDGET_MS)
    {
        InterlockedIncrement((PLONG)&MiPagerCounters.PaceBudgetSpent);
        return;
    }

    InterlockedIncrement((PLONG)&MiPagerCounters.PacedRequests);
    Delay.QuadPart = -(LONGLONG)MI_PAGER_PACE_STEP_MS * 10000;
    while ((Slot->UsedMs < MI_PAGER_PACE_BUDGET_MS) &&
           (MiPagingIoInFlight > 0) &&
           (MiGetUsablePageCount() < MI_PAGER_WAITABLE_FLOOR))
    {
        MmRebalanceMemoryConsumers();
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        Slot->UsedMs += MI_PAGER_PACE_STEP_MS;
    }
}

/*
 * N1 test knob (NitroPagerDebug 0x80): every third IRP or MDL allocation for
 * I/O to a paging file "fails", so that the reserve paths run (Io's reserve
 * IRPs for page reads and writes; NTFS-NG reads the same value for its own
 * reserve IRP and partial MDL). Io calls this before IoAllocateIrp.
 */
BOOLEAN
NTAPI
MmPagerInjectPagingAllocationFailure(
    _In_ PFILE_OBJECT FileObject)
{
    static LONG Calls;

    if (!(MiNitroPagerDebug & MI_PAGER_DEBUG_FAIL_PAGING_ALLOC) || !MmIsFileObjectAPagingFile(FileObject))
        return FALSE;
    if ((InterlockedIncrement(&Calls) % 3) != 0)
        return FALSE;
    InterlockedIncrement((PLONG)&MiPagerCounters.InjectedAllocFailures);
    return TRUE;
}

/* A private page went to the modified list (PFN lock held) */
VOID
NTAPI
MiPagerModifiedPageQueued(VOID)
{
    /*
     * Count first, then set Writable: a writer that cleared Writable (interlocked)
     * and then read the count either sees this increment or comes before it, and
     * then this store of TRUE comes after its FALSE
     */
    InterlockedIncrement(&MiPagerQueued);
    MiPagerWritable = TRUE;
    if (MmModifiedPageListHead.Total >= MiPagerModifiedMaximum)
        MiPagerWakeWriter();
}

/*
 * An available page was taken (PFN lock held). Watch how low usable pages go
 * while paging I/O is in flight (the reserve measurement), and start the
 * writer when available pages are low and modified pages wait.
 */
VOID
NTAPI
MiPagerAvailableDropped(VOID)
{
    PFN_NUMBER Usable = MiGetUsablePageCount();

    if ((MiPagingIoInFlight > 0) && (Usable < MiPagerCounters.ReserveLowWater))
        MiPagerCounters.ReserveLowWater = (ULONG)Usable;
    if ((Usable < MiLowWaterPages) &&
        (MmModifiedPageListHead.Total != 0) &&
        MiPagerWritable &&
        (MiPagerWakePending == 0))
    {
        MiPagerWakeWriter();
    }
}

/*
 * Slot reclaim: resident private pages that still hold a clean copy in the
 * paging file give it up (MiMarkPfnDirty: Modified is set before the slot is
 * released, so no trim can send such a page to standby without a copy). A
 * cursor over the PFN database, 1024 entries per PFN lock hold.
 */
static
ULONG
MiPagerReclaimSlots(
    _In_ ULONG Wanted)
{
    static PFN_NUMBER Cursor;
    static ULONGLONG LastFruitless;
    PFN_NUMBER Highest = MmHighestPhysicalPage, Scanned = 0;
    ULONG Released = 0, Chunk;
    PMMPFN Pfn1;
    KIRQL OldIrql;

    /* A whole scan found nothing to give back: the PFN database is not scanned again for 5 s (N7) */
    if ((LastFruitless != 0) && ((KeQueryInterruptTime() - LastFruitless) < 5ULL * 10 * 1000 * 1000))
        return 0;

    while ((Scanned <= Highest) && (Released < Wanted))
    {
        OldIrql = MiAcquirePfnLock();
        for (Chunk = 0; (Chunk < 1024) && (Scanned <= Highest) && (Released < Wanted); Chunk++, Scanned++)
        {
            if (++Cursor > Highest)
                Cursor = 0;
            Pfn1 = MiGetPfnEntry(Cursor);
            if ((Pfn1 == NULL) ||
                MI_IS_ROS_PFN(Pfn1) ||
                (Pfn1->u3.e1.PageLocation != ActiveAndValid) ||
                (Pfn1->u3.e1.PrototypePte != 0) ||
                (Pfn1->u3.e1.WriteInProgress != 0) ||
                (Pfn1->u3.e1.ReadInProgress != 0) ||
                (Pfn1->u3.e2.ReferenceCount == 0) ||
                !MiIsUserPageTablePte(Pfn1->PteAddress) ||
                !MI_IS_PAGEFILE_PTE(&Pfn1->OriginalPte))
            {
                continue;
            }
            MiMarkPfnDirty(Pfn1);
            Released++;
        }
        MiReleasePfnLock(OldIrql);
    }

    LastFruitless = (Released == 0) ? KeQueryInterruptTime() : 0;
    MiPagerCounters.SlotsReclaimed += Released;
    return Released;
}

/*
 * Free slots are short (or gone): no dirty page goes to the modified list
 * until there are slots again, the growth thread is asked for more (without
 * waiting: it grows toward the file's maximum), and resident pages give back
 * their clean copies.
 */
static
VOID
MiPagerCheckSlots(
    _In_ BOOLEAN Exhausted)
{
    PFN_NUMBER Free = MiPagerFreeSlotCount();

    if (!Exhausted && (Free >= MI_PAGER_SLOT_LOW))
    {
        MiPagerSlotsShort = FALSE;
        return;
    }

    if (!MiPagerSlotsShort)
        MiPagerCounters.SlotShortages++;
    MiPagerSlotsShort = TRUE;
    MiRequestPagingFileGrowth(max((SIZE_T)MmModifiedPageListHead.Total, (SIZE_T)4096));
    MiPagerReclaimSlots(MI_PAGER_SLOT_LOW * 2);
    if (MiPagerFreeSlotCount() >= MI_PAGER_SLOT_LOW)
        MiPagerSlotsShort = FALSE;
}

/* One line of counters on the debug channel, at most once a minute and only when something moved */
/*
 * Called by the writer thread and the balancer's pass check: a writer stuck in
 * a cluster write must not silence the counters (one caller at a time).
 */
static
VOID
MiPagerReport(VOID)
{
    static ULONGLONG LastReportTime;
    static ULONG LastSumValue;
    static volatile LONG Busy;
    PULONGLONG LastReport = &LastReportTime;
    PULONG LastSum = &LastSumValue;
    ULONGLONG Now = KeQueryInterruptTime();
    ULONG Sum;

    if (InterlockedCompareExchange(&Busy, 1, 0) != 0)
        return;
    if ((Now - *LastReport) < 60ULL * 10 * 1000 * 1000)
    {
        InterlockedExchange(&Busy, 0);
        return;
    }
    *LastReport = Now;

    Sum = MiPagerCounters.Trimmed + MiPagerCounters.Written + MiPagerCounters.Repurposed +
          MiPagerCounters.InPageReads + MiPagerCounters.Aged + MiPagerCounters.WriteErrors +
          MiPagerCounters.PacedRequests + MiPagerCounters.InjectedAllocFailures;
    if (Sum == *LastSum)
    {
        InterlockedExchange(&Busy, 0);
        return;
    }
    *LastSum = Sum;

    DbgPrint("NitroPager: trim %lu dirty %lu aged %lu skipdirty %lu | written %lu clusters %lu errors %lu noslot %lu | "
            "repurposed %lu inpage %lu errors %lu retries %lu | tagmismatch %lu freerefused %lu | wsmiss %lu starved %lu | "
            "slotshort %lu reclaimed %lu freeslots %Iu | modified %Iu privstandby %lu usable %Iu reserve-low %lu inflight %ld | "
            "balancer trimmed %lu waits %lu | legacy user %lu system %lu available %Iu legacy-freed %lu asked %lu nopass %lu | "
            "paced %lu pacebudget %lu wsfloor %lu injected %lu ioreserve %ld\n",
            MiPagerCounters.Trimmed, MiPagerCounters.TrimmedDirty, MiPagerCounters.Aged, MiPagerCounters.TrimSkippedDirty,
            MiPagerCounters.Written, MiPagerCounters.Clusters, MiPagerCounters.WriteErrors, MiPagerCounters.WriteNoSlot,
            MiPagerCounters.Repurposed, MiPagerCounters.InPageReads, MiPagerCounters.InPageErrors,
            MiPagerCounters.InPageResourceRetries, MiPagerCounters.TagMismatches, MiPagerCounters.SlotFreeRefused,
            MiPagerCounters.WsTryLockMisses, MiPagerCounters.StarvationRounds, MiPagerCounters.SlotShortages,
            MiPagerCounters.SlotsReclaimed, (SIZE_T)MiPagerFreeSlotCount(), (SIZE_T)MmModifiedPageListHead.Total,
            MmTransitionPrivatePages, (SIZE_T)MiGetUsablePageCount(), MiPagerCounters.ReserveLowWater, MiPagingIoInFlight,
            MiPagerCounters.BalancerTrimmed, MiPagerCounters.BalancerWaits,
            MiMemoryConsumers[MC_USER].PagesUsed, MiMemoryConsumers[MC_SYSTEM].PagesUsed, (SIZE_T)MmAvailablePages,
            MiPagerCounters.LegacyFreed, MiPagerCounters.LegacyAsked, MiPagerCounters.NoProgressPasses,
            MiPagerCounters.PacedRequests, MiPagerCounters.PaceBudgetSpent, MiPagerCounters.WsFloorSkips, MiPagerCounters.InjectedAllocFailures,
            IopReserveIrpUses);
    InterlockedExchange(&Busy, 0);
}

/*
 * The modified page writer thread (P1, D3). Runs when the modified list
 * holds MiPagerModifiedMaximum pages, when available pages are below the
 * balancer's low-water mark with modified pages waiting, or when woken; then
 * writes until the list is below half the maximum and the pressure is gone.
 * It never takes a working set, address space, paging file creation, Cc or
 * file system lock.
 */
static
VOID
NTAPI
MiModifiedPageWriterThread(
    _In_ PVOID Context)
{
    LARGE_INTEGER Timeout;
    ULONG Attempted, Idle = 0;
    LONG Queued;
    BOOLEAN NoSlot, Failing, Pressure;
    PFN_NUMBER Modified;

    UNREFERENCED_PARAMETER(Context);

    for (;;)
    {
        Timeout.QuadPart = -10LL * 1000 * 1000;
        KeWaitForSingleObject(&MiPagerWriterEvent, Executive, KernelMode, FALSE, &Timeout);
        InterlockedExchange(&MiPagerWakePending, 0);
        if (MiPagerShutdown)
            break;

        MiPagerReport();

        /* A scan that found nothing is retried now and then, whatever the list does */
        if (++Idle >= 10)
        {
            Idle = 0;
            MiPagerWritable = TRUE;
        }

        if (MiPagerSlotsShort)
            MiPagerCheckSlots(FALSE);

        for (;;)
        {
            Modified = MmModifiedPageListHead.Total;
            Pressure = (MiGetUsablePageCount() < MiLowWaterPages);
            if (MiPagerShutdown ||
                (Modified == 0) ||
                !MiPagerWritable ||
                (!Pressure && (Modified < MiPagerModifiedMaximum / 2)))
            {
                break;
            }

            MiPagerWriterState = MI_WRITER_WRITING;
            Queued = MiPagerQueued;
            MiWriteModifiedPrivatePagesEx(256, &Attempted, &NoSlot, &Failing);

            if (NoSlot)
            {
                LARGE_INTEGER Delay;

                MiPagerWriterState = MI_WRITER_NO_SLOT;
                MiPagerCheckSlots(TRUE);
                Delay.QuadPart = -250LL * 10000;
                KeDelayExecutionThread(KernelMode, FALSE, &Delay);
                break;
            }
            if (Failing)
            {
                LARGE_INTEGER Delay;

                MiPagerWriterState = MI_WRITER_BACKOFF;
                Delay.QuadPart = -1000LL * 10000;
                KeDelayExecutionThread(KernelMode, FALSE, &Delay);
                break;
            }
            if (Attempted == 0)
            {
                /* Interlocked (a full barrier): the read of the count below cannot pass this store */
                InterlockedExchange(&MiPagerWritable, FALSE);
                /* A page queued during the scan sets it again (its store may have come before ours) */
                if (MiPagerQueued != Queued)
                    MiPagerWritable = TRUE;
                break;
            }
            Idle = 0;

            if (!MiPagerSlotsShort && (MiPagerFreeSlotCount() < MI_PAGER_SLOT_LOW))
                MiPagerCheckSlots(FALSE);
        }
        MiPagerWriterState = MI_WRITER_IDLE;
    }

    MiPagerWriterState = MI_WRITER_STOPPED;
    KeSetEvent(&MiPagerWriterStopped, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* Start the writer thread (NtCreatePagingFile, NitroPager on); a failed start is retried by the next file */
VOID
NTAPI
MiPagerStartWriter(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ThreadHandle;
    PETHREAD Thread;
    NTSTATUS Status;

    ASSERT(MiNitroPagerMode != 0);
    if (InterlockedCompareExchange(&MiPagerWriterStarted, 1, 0) != 0)
        return;

    KeInitializeEvent(&MiPagerWriterEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&MiPagerWriterStopped, NotificationEvent, FALSE);
    MiPagerCounters.ReserveLowWater = MAXULONG;
    MiPagerModifiedMaximum = max(MmNumberOfPhysicalPages / 16, 256);
    MiPagerWritable = TRUE;
    MiPagerWriterStartTime = KeQueryInterruptTime();

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL,
                                  MiModifiedPageWriterThread, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NitroPager: the modified page writer did not start: 0x%lx\n", Status);
        InterlockedExchange(&MiPagerWriterStarted, 0);
        return;
    }

    /* Above the threads that dirty memory (tuning, design 3.5); the reference is kept (MiPagerIsWriterThread) */
    if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, PsThreadType,
                                             KernelMode, (PVOID*)&Thread, NULL)))
    {
        KeSetPriorityThread(&Thread->Tcb, LOW_REALTIME_PRIORITY + 1);
        MiPagerWriterThreadObject = Thread;
    }
    ZwClose(ThreadHandle);

    MiPagerWriterState = MI_WRITER_IDLE;
    InterlockedExchange(&MiPagerWriterStarted, 2);
    DbgPrint("NitroPager: modified page writer started (runs at %Iu modified pages or below %lu available)\n",
            (SIZE_T)MiPagerModifiedMaximum, MiLowWaterPages);
}

/*
 * Shutdown (MiShutdownSystem, before the file systems shut down): the writer
 * stops, a cluster that is being written finishes, no page is written to a
 * paging file again in this boot and the trimmer stops. Private modified
 * pages stay in memory and are discarded with it.
 */
VOID
NTAPI
MiPagerShutdownWriter(VOID)
{
    LARGE_INTEGER Timeout;
    ULONG i;

    if (MiNitroPagerMode == 0)
        return;

    InterlockedExchange(&MiPagerShutdown, 1);
    if (MiPagerWriterStarted == 2)
    {
        KeSetEvent(&MiPagerWriterEvent, IO_NO_INCREMENT, FALSE);
        Timeout.QuadPart = -30LL * 10 * 1000 * 1000;
        if (KeWaitForSingleObject(&MiPagerWriterStopped, Executive, KernelMode, FALSE, &Timeout) == STATUS_TIMEOUT)
            DPRINT1("NitroPager: the writer did not stop within 30 s\n");
    }

    /* A synchronous flush (memory list command, EmptyWorkingSet) finishes its cluster */
    Timeout.QuadPart = -10LL * 10000;
    for (i = 0; (i < 3000) && (MiPagerWritesActive != 0); i++)
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

    DbgPrint("NitroPager: writer stopped for shutdown: %lu pages written in %lu clusters, %Iu modified pages stay in memory\n",
            MiPagerCounters.Written, MiPagerCounters.Clusters, (SIZE_T)MmModifiedPageListHead.Total);
}

/*
 * The balancer's "game over" check (no pass frees anything): with the pager
 * on, waiting is right while paging I/O is in flight (unless it is stuck: no
 * paging I/O completed for MI_PAGER_IO_STUCK_AFTER, F9), a cluster completed
 * in the last 10 s, or the writer has modified private pages it can write
 * (free slots, or a retired file due for its probe: MiPagerFreeSlotCount).
 */
BOOLEAN
NTAPI
MiPagerCanMakeProgress(
    _Out_ PULONG_PTR WriterState)
{
    ULONGLONG Now = KeQueryInterruptTime(), Last = MiPagerLastProgress;

    *WriterState = (ULONG_PTR)MiPagerWriterState;
    if ((MiNitroPagerMode == 0) || MiPagerShutdown)
        return FALSE;
    if (MiPagingIoStuck())
    {
        /* A hung paging device: the bugcheck says so instead of a silent hang */
        *WriterState |= MI_WRITER_IO_STUCK;
        return FALSE;
    }
    if (MiPagingIoInFlight > 0)
        return TRUE;
    if ((Last != 0) && ((Now - Last) < MI_PAGER_PROGRESS_WINDOW))
        return TRUE;
    if ((MmModifiedPageListHead.Total != 0) &&
        MiPagerWritable &&
        (MiPagerWriterStarted == 2) &&
        (MiPagerFreeSlotCount() != 0))
    {
        MiPagerWakeWriter();
        return TRUE;
    }
    return FALSE;
}

/* The balancer gives the writer a moment before its next pass */
VOID
NTAPI
MiPagerWaitForProgress(VOID)
{
    LARGE_INTEGER Delay;

    MiPagerCounters.BalancerWaits++;
    Delay.QuadPart = -50LL * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

/*
 * End of a balancer pass, NitroPager on (balance.c): the exhaustion check the
 * inherited "game over" test cannot make (its target is always 0). Usable
 * pages below MI_PAGER_STARVED_PAGES means waitable user faults are being
 * refused (their floor is 256). Such a pass that freed nothing and did not
 * raise usable pages is a no-progress pass; when the writer can still make
 * progress (I/O in flight, a write completed in the last 10 s, writable
 * modified pages and free slots) the balancer waits for it; otherwise, after
 * 60 s of nothing but no-progress passes, the bugcheck says why:
 * NO_PAGES_AVAILABLE(usable pages, modified pages, paging I/O in flight,
 * writer state, | 0x100 when that I/O was stuck). Without a paging file the
 * pager frees nothing and there is no such bugcheck (as at flag 0 and on
 * Windows: allocations fail instead). Balancer thread only.
 */
#define MI_PAGER_STARVED_PAGES 512
#define MI_PAGER_EXHAUSTED_AFTER (60ULL * 10 * 1000 * 1000)
#define MI_PAGER_EXHAUSTED_AFTER_TEST (15ULL * 10 * 1000 * 1000)
VOID
NTAPI
MiPagerBalancerPassDone(
    _In_ PFN_NUMBER UsableBefore,
    _In_ ULONG Freed)
{
    static ULONGLONG NoProgressSince;
    PFN_NUMBER Usable = MiGetUsablePageCount();
    ULONGLONG Now = KeQueryInterruptTime(), Window;
    ULONG_PTR WriterState;
    LARGE_INTEGER Delay;
    PFN_NUMBER Starved;

    if (MiPagerWriterStarted == 2)
        MiPagerReport();

    /*
     * Test knob 0x40: starved below the low-water mark instead. At flag 1 the commit ceiling
     * (RAM-bound until P4) keeps private memory from exhausting usable pages by itself, so
     * the test needs the higher mark to reach the check.
     */
    Starved = (MiNitroPagerDebug & MI_PAGER_DEBUG_TRIM_NOTHING) ? MiLowWaterPages : MI_PAGER_STARVED_PAGES;
    if (MiNitroPagerDebug & MI_PAGER_DEBUG_TRIM_NOTHING)
    {
        /* Test: the cache and the legacy floor keep freeing a little; only the mark counts */
        Freed = 0;
        UsableBefore = Usable;
    }
    if ((Usable >= Starved) || (Freed != 0) || (Usable > UsableBefore) || MiPagerShutdown ||
        (MmNumberOfPagingFiles == 0))
    {
        NoProgressSince = 0;
        return;
    }

    MiPagerCounters.NoProgressPasses++;
    if (MiPagerCanMakeProgress(&WriterState))
    {
        NoProgressSince = 0;
        MiPagerWaitForProgress();
        return;
    }

    if (NoProgressSince == 0)
        NoProgressSince = Now;
    Window = (MiNitroPagerDebug & MI_PAGER_DEBUG_TRIM_NOTHING) ? MI_PAGER_EXHAUSTED_AFTER_TEST : MI_PAGER_EXHAUSTED_AFTER;
    if ((Now - NoProgressSince) >= Window)
    {
        KeBugCheckEx(NO_PAGES_AVAILABLE,
                     Usable,
                     MmModifiedPageListHead.Total,
                     (ULONG_PTR)MiPagingIoInFlight,
                     WriterState);
    }

    /* Not a busy loop of empty passes while waiting to decide */
    Delay.QuadPart = -50LL * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

/* Per-process trimmer state, keyed by process and id; the balancer thread is the only user */
typedef struct _MI_TRIM_CURSOR
{
    PEPROCESS Process;
    HANDLE ProcessId;
    ULONG_PTR NextVa;
    ULONG Resident;
    ULONG SeenThisCycle;
    ULONG Misses;
    ULONG Stamp;
} MI_TRIM_CURSOR, *PMI_TRIM_CURSOR;

static MI_TRIM_CURSOR MiTrimCursors[MI_TRIM_CURSORS];
static ULONG MiTrimStamp;
static PEPROCESS MiTrimList[MI_TRIM_PROCESSES];
static PMI_TRIM_CURSOR MiTrimListCursor[MI_TRIM_PROCESSES];

static
PMI_TRIM_CURSOR
MiTrimFindCursor(
    _In_ PEPROCESS Process)
{
    PMI_TRIM_CURSOR Cursor, Oldest = &MiTrimCursors[0];
    ULONG i;

    for (i = 0; i < MI_TRIM_CURSORS; i++)
    {
        Cursor = &MiTrimCursors[i];
        if ((Cursor->Process == Process) && (Cursor->ProcessId == Process->UniqueProcessId))
        {
            Cursor->Stamp = MiTrimStamp;
            return Cursor;
        }
        if ((LONG)(Cursor->Stamp - Oldest->Stamp) < 0)
            Oldest = Cursor;
    }

    /* A process not seen lately: a fresh cursor, a middling size guess so it is looked at soon */
    RtlZeroMemory(Oldest, sizeof(*Oldest));
    Oldest->Process = Process;
    Oldest->ProcessId = Process->UniqueProcessId;
    Oldest->Resident = 0x4000;
    Oldest->Stamp = MiTrimStamp;
    return Oldest;
}

/* Clear the Accessed bit of a valid PTE without losing a Dirty bit a processor sets meanwhile */
static
BOOLEAN
MiClearPteAccessed(
    _In_ PMMPTE PointerPte)
{
    MMPTE OldPte, NewPte;
    ULONG Tries;

    for (Tries = 0; Tries < 4; Tries++)
    {
        OldPte = *PointerPte;
        if ((OldPte.u.Hard.Valid == 0) || (OldPte.u.Hard.Accessed == 0))
            return FALSE;
        NewPte = OldPte;
        NewPte.u.Hard.Accessed = 0;
        if ((ULONG_PTR)InterlockedCompareExchangePte(PointerPte, NewPte.u.Long, OldPte.u.Long) == (ULONG_PTR)OldPte.u.Long)
            return TRUE;
    }
    return FALSE;
}

/* A private VAD the trimmer may look at (as MiTrimCurrentProcess) */
static
BOOLEAN
MiIsTrimmableVad(
    _In_ PMMVAD Vad)
{
    /* The same test decides whether its commitment may use the paging files (P4) */
    return MI_IS_PAGEABLE_COMMIT_VAD(Vad);
}

/*
 * The clock hand over one process (working set lock held, attached): from
 * the cursor on, a valid private page whose Accessed bit is set loses it
 * (it was used since the hand passed last); one whose bit is clear is
 * trimmed. Force: trim without looking at the bit. Invalid upper levels are
 * stepped over, each counted as one examined entry, so huge reservations
 * cost a bounded amount per pass.
 */
static
VOID
MiTrimProcessClock(
    _In_ PEPROCESS Process,
    _Inout_ PMI_TRIM_CURSOR Cursor,
    _In_ ULONG Want,
    _In_ BOOLEAN Force,
    _Inout_ PMI_TRIM_CONTEXT Context)
{
    PMMADDRESS_NODE Node;
    PMMVAD Vad;
    ULONG_PTR Va = Cursor->NextVa, Start, End;
    ULONG Examined = 0, Limit = min(Want, (ULONG)MI_TRIM_PAGE_BUDGET);
    BOOLEAN Wrapped = FALSE;
    PMMPTE PointerPte;
    PMMPDE PointerPde;

    for (Node = MiGetFirstNode(&Process->VadRoot); Node != NULL; Node = MiGetNextNode(Node))
    {
        if (((PMMVAD)Node)->EndingVpn >= (Va >> PAGE_SHIFT))
            break;
    }

    while ((Examined < MI_TRIM_EXAMINE_BUDGET) && (Context->Trimmed < Limit))
    {
        if (Node == NULL)
        {
            /* End of the address space: one turn of the hand is complete */
            Cursor->Resident = Cursor->SeenThisCycle;
            Cursor->SeenThisCycle = 0;
            Va = 0;
            if (Wrapped)
                break;
            Wrapped = TRUE;
            Node = MiGetFirstNode(&Process->VadRoot);
            continue;
        }

        Vad = (PMMVAD)Node;
        Examined++;
        Start = Vad->StartingVpn << PAGE_SHIFT;
        End = (Vad->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1);
        if (End > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS)
            End = (ULONG_PTR)MM_HIGHEST_USER_ADDRESS;
        if (!MiIsTrimmableVad(Vad) || (Va > End))
        {
            Node = MiGetNextNode(Node);
            continue;
        }
        if (Va < Start)
            Va = Start;

        while ((Va <= End) && (Examined < MI_TRIM_EXAMINE_BUDGET) && (Context->Trimmed < Limit))
        {
#if (_MI_PAGING_LEVELS >= 4)
            PMMPXE PointerPxe = MiAddressToPxe((PVOID)Va);
            if (!PointerPxe->u.Hard.Valid)
            {
                Examined++;
                Va = (ULONG_PTR)MiPxeToAddress(PointerPxe + 1);
                if (Va == 0)
                    Va = End + 1;
                continue;
            }
#endif
#if (_MI_PAGING_LEVELS >= 3)
            {
                PMMPPE PointerPpe = MiAddressToPpe((PVOID)Va);
                if (!PointerPpe->u.Hard.Valid)
                {
                    Examined++;
                    Va = (ULONG_PTR)MiPpeToAddress(PointerPpe + 1);
                    if (Va == 0)
                        Va = End + 1;
                    continue;
                }
            }
#endif
            PointerPde = MiAddressToPde((PVOID)Va);
            if (!PointerPde->u.Hard.Valid || PointerPde->u.Hard.LargePage)
            {
                Examined++;
                Va = (ULONG_PTR)MiPdeToAddress(PointerPde + 1);
                if (Va == 0)
                    Va = End + 1;
                continue;
            }

            PointerPte = MiAddressToPte((PVOID)Va);
            do
            {
                Examined++;
                if (PointerPte->u.Hard.Valid)
                {
                    Cursor->SeenThisCycle++;
                    if (!Force && PointerPte->u.Hard.Accessed)
                    {
                        if (MiClearPteAccessed(PointerPte))
                        {
                            Context->Aged++;
                            MmAddToTbFlushList(&Context->FlushList, (PVOID)Va);
                        }
                    }
                    else
                    {
                        MiTrimPte(PointerPte, (PVOID)Va, Context);
                    }
                }
                PointerPte++;
                Va += PAGE_SIZE;
            } while ((Va <= End) && (Va != 0) && !MiIsPteOnPdeBoundary(PointerPte) &&
                     (Examined < MI_TRIM_EXAMINE_BUDGET) && (Context->Trimmed < Limit));
            if (Va == 0)
                Va = End + 1;
        }

        if (Va > End)
        {
            Node = MiGetNextNode(Node);
            if (Node == NULL)
                Va = 0;
        }
    }

    Cursor->NextVa = Va;
}

/* Trim results of one process */
#define MI_TRIM_DONE    0
#define MI_TRIM_MISSED  1
#define MI_TRIM_SKIPPED 2

/*
 * Trim one process for the balancer: attach, try (never wait for) the
 * address space lock and the working set lock, one clock pass with budgets.
 */
static
ULONG
MiTrimProcessForPressure(
    _In_ PEPROCESS Process,
    _Inout_ PMI_TRIM_CURSOR Cursor,
    _In_ ULONG Want,
    _In_ BOOLEAN Force,
    _Out_ PULONG Trimmed)
{
    PETHREAD Thread = PsGetCurrentThread();
    MI_TRIM_CONTEXT Context;
    KAPC_STATE ApcState;
    ULONG Result = MI_TRIM_DONE;

    *Trimmed = 0;
    if (!ExAcquireRundownProtection(&Process->RundownProtect))
        return MI_TRIM_SKIPPED;

    KeStackAttachProcess(&Process->Pcb, &ApcState);
    if (!KeTryToAcquireGuardedMutex(&Process->AddressCreationLock))
    {
        Result = MI_TRIM_MISSED;
    }
    else if (Process->VmDeleted || (Process->AddressSpaceInitialized < 2))
    {
        KeReleaseGuardedMutex(&Process->AddressCreationLock);
        Result = MI_TRIM_SKIPPED;
    }
    else if (!MiTryLockProcessWorkingSet(Process, Thread))
    {
        KeReleaseGuardedMutex(&Process->AddressCreationLock);
        Result = MI_TRIM_MISSED;
    }
    else
    {
        /* User addresses: only the processors running this process cache them */
        MmInitializeTbFlushList(&Context.FlushList, FALSE);
        Context.Count = 0;
        Context.Trimmed = 0;
        Context.Dirty = 0;
        Context.Aged = 0;
        Context.CleanOnly = MiPagerSlotsShort;
        MiTrimProcessClock(Process, Cursor, Want, Force, &Context);
        MiTrimFlush(&Context);
        MiPagerCounters.Aged += Context.Aged;

        MiUnlockProcessWorkingSet(Process, Thread);
        KeReleaseGuardedMutex(&Process->AddressCreationLock);
        *Trimmed = Context.Trimmed;
    }
    KeUnstackDetachProcess(&ApcState);
    ExReleaseRundownProtection(&Process->RundownProtect);

    if (Result == MI_TRIM_MISSED)
        MiPagerCounters.WsTryLockMisses++;
    return Result;
}

/*
 * Automatic trimming (P1), from the balancer thread after the clean cache
 * trim: when usable pages (free, zeroed, private standby) are below the
 * low-water mark (by the shortfall, or the balancer's target), private pages of user
 * processes are trimmed, largest resident set first (last full turn of the
 * clock), with the clock's Accessed-bit aging unless usable pages are nearly
 * gone. Dirty pages go to the modified list and the writer is woken. If the
 * largest process's locks stay busy, the others are trimmed without aging
 * (starvation fallback, counted). Returns the pages trimmed.
 */
ULONG
NTAPI
MiPagerBalance(
    _In_ ULONG LowWaterPages,
    _In_ ULONG Target)
{
    PEPROCESS Process = NULL;
    PMI_TRIM_CURSOR Cursor;
    PFN_NUMBER Usable;
    ULONG Need, Trimmed = 0, Got, Count = 0, i, j, Round, Rounds, Result;
    BOOLEAN Force, Starved = FALSE;

    if ((MiNitroPagerMode == 0) || MiPagerShutdown || (MmNumberOfPagingFiles == 0) ||
        (MiNitroPagerDebug & MI_PAGER_DEBUG_TRIM_NOTHING))
    {
        return 0;
    }

    /* Only below the low-water mark: a consumer target alone (legacy pages over their share) is not ours to meet */
    Usable = MiGetUsablePageCount();
    if (Usable >= LowWaterPages)
        return 0;
    Need = max(Target, (ULONG)(LowWaterPages - Usable) + LowWaterPages / 4);
    Force = (Usable < max(LowWaterPages / 8, MI_PAGER_FORCE_TRIM_MINIMUM));

    /* The processes with an address space, referenced, largest first */
    MiTrimStamp++;
    while ((Process = PsGetNextProcess(Process)) != NULL)
    {
        if ((Process == PsInitialSystemProcess) ||
            (Process == PsIdleProcess) ||
            Process->VmDeleted ||
            (Process->AddressSpaceInitialized < 2))
        {
            continue;
        }
        if (Count == MI_TRIM_PROCESSES)
        {
            ObDereferenceObject(Process);
            break;
        }
        ObReferenceObject(Process);
        Cursor = MiTrimFindCursor(Process);
        for (j = Count; (j > 0) && (MiTrimListCursor[j - 1]->Resident < Cursor->Resident); j--)
        {
            MiTrimList[j] = MiTrimList[j - 1];
            MiTrimListCursor[j] = MiTrimListCursor[j - 1];
        }
        MiTrimList[j] = Process;
        MiTrimListCursor[j] = Cursor;
        Count++;
    }

    /*
     * Share the shortfall with the legacy user consumer (RosMm file data, image and
     * section pages, up to half of RAM by its own target). Without this the trimmer
     * kept usable pages just above the legacy floor (256 pages), the legacy pages were
     * never paged out, and private working sets thrashed to feed the file cache: an
     * MSI install took 8 min at flag 1 against 31 s at flag 0 on a 3 GB guest with
     * 1.5 GB of private load, with 1.1 GB held by legacy pages (lane pagerp1, 11-07).
     * The legacy part is in proportion to its size against the private resident
     * pages (the clock's last full turns); legacy pages that were freed count.
     */
    {
        ULONG Legacy = MiMemoryConsumers[MC_USER].PagesUsed, Private = 0, LegacyTarget, Freed = 0;
        ULONGLONG Share;

        for (i = 0; i < Count; i++)
            Private += min(MiTrimListCursor[i]->Resident, 0x100000UL);

        /*
         * With aging (Priority FALSE: the legacy pass clears the accessed bits of the pages
         * it looks at and pages out those not used since; it reports nothing freed, so the
         * private share is trimmed in full), paging out the LRU directly (TRUE) only when
         * usable pages are nearly gone, as Force does for private pages. Not while slots are
         * short: legacy page-out of dirty pages takes slots too. At most MI_TRIM_PAGE_BUDGET
         * pages per pass: this is the legacy path the balancer always ran, with its waits
         * for working set and segment locks, so its share of a pass stays bounded.
         */
        if ((Legacy != 0) && MiMemoryConsumers[MC_USER].Trim && !MiPagerSlotsShort &&
            !(MiNitroPagerDebug & MI_PAGER_DEBUG_TRIM_NOTHING))
        {
            Share = ((ULONGLONG)Need * Legacy) / ((ULONGLONG)Legacy + Private);
            LegacyTarget = (ULONG)min(Share, (ULONGLONG)MI_TRIM_PAGE_BUDGET);
            if (LegacyTarget != 0)
            {
                MiMemoryConsumers[MC_USER].Trim(LegacyTarget, Force, &Freed);
                MiPagerCounters.LegacyFreed += Freed;
                MiPagerCounters.LegacyAsked += LegacyTarget;
                Trimmed += Freed;
            }
        }
    }

    /* A second round only when pages are nearly gone: the hand then trims what the first round aged */
    Rounds = Force ? 2 : 1;
    for (Round = 0; (Round < Rounds) && (Trimmed < Need) && !MiPagerShutdown; Round++)
    {
        for (i = 0; (i < Count) && (Trimmed < Need); i++)
        {
            ULONG Want = Need - Trimmed;

            Cursor = MiTrimListCursor[i];

            /*
             * F6: the working set minimum is a floor for trimming with aging. ARM3 keeps no
             * resident count of private pages (P5), so the clock's last full turn stands in for
             * it (it counts trimmable private pages only, never more than the working set).
             * Forced trimming (usable pages nearly gone, or the starvation fallback) may go
             * below it, as Windows does with the default soft minimum
             * (QUOTA_LIMITS_HARDWS_MIN_DISABLE); hard minimums are not implemented.
             */
            if (!Force && !Starved)
            {
                SIZE_T Minimum = MiTrimList[i]->Vm.MinimumWorkingSetSize;

                /* Every 8th pass a skipped process gets an aging turn anyway: its Resident is refreshed by turns only */
                if ((Cursor->Resident <= Minimum) && ((MiTrimStamp & 7) != 0))
                {
                    MiPagerCounters.WsFloorSkips++;
                    continue;
                }
                if (Cursor->Resident > Minimum)
                    Want = (ULONG)min((SIZE_T)Want, Cursor->Resident - Minimum);
            }

            Result = MiTrimProcessForPressure(MiTrimList[i], Cursor, Want, Force || Starved, &Got);
            if (Result == MI_TRIM_MISSED)
            {
                /* The largest process stays busy: the others give more this pass */
                if ((i == 0) && (++Cursor->Misses >= MI_TRIM_STARVE_LIMIT) && !Starved)
                {
                    Starved = TRUE;
                    MiPagerCounters.StarvationRounds++;
                }
            }
            else
            {
                Cursor->Misses = 0;
            }
            Trimmed += Got;
        }
    }

    for (i = 0; i < Count; i++)
        ObDereferenceObject(MiTrimList[i]);

    if (MmModifiedPageListHead.Total != 0)
        MiPagerWakeWriter();
    MiPagerCounters.BalancerTrimmed += Trimmed;
    return Trimmed;
}

/*
 * Test (MI_PAGER_TEST_HOLD_PAGES): a kernel component that keeps taking every
 * usable page above MI_PAGER_TEST_HOLD_FLOOR for Seconds, in the caller's
 * thread, then gives them back. Below the starved mark (512) and above the
 * waitable floor (256): the balancer trims everything it can and, once nothing
 * is left to trim, the exhaustion check runs on its production predicate (no
 * test bit changes it). Without a paging file the check must stay quiet.
 */
static
NTSTATUS
MiPagerTestHoldPages(
    _In_ ULONG Seconds)
{
    PPFN_NUMBER Held;
    SIZE_T Count = 0, Max = MmNumberOfPhysicalPages, i;
    ULONGLONG End;
    LARGE_INTEGER Delay;
    PFN_NUMBER Page;
    KIRQL OldIrql;

    Seconds = min(max(Seconds, 1), MI_PAGER_TEST_HOLD_SECONDS);
    Held = ExAllocatePoolWithTag(NonPagedPool, Max * sizeof(PFN_NUMBER), 'hPiM');
    if (Held == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    DbgPrint("NitroPager: test: holding usable pages above %lu for %lu s (usable %Iu, paging files %lu)\n",
             MI_PAGER_TEST_HOLD_FLOOR, Seconds, (SIZE_T)MiGetUsablePageCount(), MmNumberOfPagingFiles);
    End = KeQueryInterruptTime() + (ULONGLONG)Seconds * 10 * 1000 * 1000;
    Delay.QuadPart = -20LL * 10000;
    while (KeQueryInterruptTime() < End)
    {
        while ((Count < Max) && (MiGetUsablePageCount() > MI_PAGER_TEST_HOLD_FLOOR))
        {
            Page = MmAllocPage(MC_SYSTEM);
            if (Page == 0)
                break;
            Held[Count++] = Page;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    DbgPrint("NitroPager: test: held %Iu pages, usable %Iu; giving them back\n", Count, (SIZE_T)MiGetUsablePageCount());
    for (i = 0; i < Count; i += 64)
    {
        SIZE_T j;

        OldIrql = MiAcquirePfnLock();
        for (j = i; (j < Count) && (j < i + 64); j++)
            MmDereferencePage(Held[j]);
        MiReleasePfnLock(OldIrql);
    }
    ExFreePoolWithTag(Held, 'hPiM');
    return STATUS_SUCCESS;
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
                  (Command <= MI_PAGER_TEST_LAST) &&
                  ((Address != NULL) ||
                   (Command == MI_PAGER_TEST_PING) ||
                   (Command == MI_PAGER_TEST_RESUME_WRITE) ||
                   (Command == MI_PAGER_TEST_QUERY_PAUSED) ||
                   (Command == MI_PAGER_TEST_QUERY_FREE_REFUSED) ||
                   (Command == MI_PAGER_TEST_HANG_WRITES)) &&
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
        case MI_PAGER_TEST_MISMATCH_NEXT_FREE:
            MiPagerFreeRefusedBase = MiPagerCounters.SlotFreeRefused;
            MiPagerArmInjection(MI_PAGER_INJECT_FREE_MISMATCH, Address);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_QUERY_FREE_REFUSED:
            return (MiPagerCounters.SlotFreeRefused > MiPagerFreeRefusedBase) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        case MI_PAGER_TEST_PAUSE_NEXT_WRITE:
            KeInitializeEvent(&MiPagerPauseEvent, NotificationEvent, FALSE);
            MiPagerPauseReady = 1;
            MiPagerArmInjection(MI_PAGER_INJECT_WRITE_PAUSE, Address);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_QUERY_PAUSED:
            return MiPagerWriterPaused ? STATUS_SUCCESS : STATUS_PENDING;
        case MI_PAGER_TEST_RESUME_WRITE:
            if (MiPagerPauseReady)
                KeSetEvent(&MiPagerPauseEvent, IO_NO_INCREMENT, FALSE);
            return STATUS_SUCCESS;
        case MI_PAGER_TEST_HOLD_PAGES:
            /* Address = seconds */
            return MiPagerTestHoldPages((ULONG)(ULONG_PTR)Address);
        case MI_PAGER_TEST_HANG_WRITES:
            DbgPrint("NitroPager: test: the next cluster writes will hang\n");
            InterlockedExchange(&MiPagerHangWrites, 1);
            MiPagerWakeWriter();
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
