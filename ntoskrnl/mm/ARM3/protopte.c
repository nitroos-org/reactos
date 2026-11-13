/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Sparse Prototype PTE store for large reserved page-file sections
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A page-file-backed section keeps one Prototype PTE per page in a single array (Segment->ThePtes, paged pool).
 * Windows 10 x64 creates an 8 TB SEC_RESERVE section: its array would be 16 GB, far more than paged pool, and
 * almost all of it describes pages that are never committed. On amd64 such arrays live here instead, in a
 * dedicated 1 TB kernel range (MI_SPARSE_PROTO_START):
 *
 *   - Every page-directory entry of the range that holds no committed page points to one shared page table
 *     whose 512 entries map one shared zeroed page read-only. Any Prototype PTE in such a place reads as 0
 *     (not committed), from any code and at any IRQL, without a fault; nothing writes there.
 *   - Committing pages (the only change that makes a zero Prototype PTE non-zero) first populates the pages of
 *     the array that hold them: a private page table for the 1 GB of section, then a private zeroed page per
 *     2 MB of section, at PASSIVE/APC level with this file's mutex held. A non-zero Prototype PTE is therefore
 *     always in a private page, and the existing code that changes committed Prototype PTEs (faults,
 *     transitions, deletion), often under the PFN lock, finds ordinary valid memory there.
 *   - The array stays contiguous, so all the code that indexes Segment->PrototypePte / SubsectionBase is
 *     unchanged. The private pages are freed with the segment.
 *
 * Accounting (the pages are resident and cannot be paged): every page and page table populated here is charged
 * as non-pageable commitment (MiCommitUser, whose ceiling is RAM less the resident headroom, like the section
 * pages themselves) and returned when it is freed, so a process committing one page per 2 MB of a huge section
 * fails with STATUS_COMMITMENT_LIMIT while RAM is still available. The page directories of the range (at most
 * 2 x 512 pages for the whole system, never freed) and the bitmap are not charged. The resident store pages
 * of all sections together are capped at 1/32 of physical memory (MiSparseInitializeStore). A process may hold at most a
 * quarter of the range (MI_SPARSE_OWNER_CHUNKS); a reserved section charges nothing else while it is only
 * reserved.
 */

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

#ifdef _M_AMD64

/* One allocation unit = the VA one page table maps: 2 MB of Prototype PTEs (1 GB of section) */
#define MI_SPARSE_CHUNK_SIZE    PDE_MAPPED_VA
#define MI_SPARSE_CHUNK_COUNT   ((ULONG)((MI_SPARSE_PROTO_END - MI_SPARSE_PROTO_START + 1) / MI_SPARSE_CHUNK_SIZE))

/* What one creating process may hold: a quarter of the range (sixteen 8 TB sections) */
#define MI_SPARSE_OWNER_CHUNKS  (MI_SPARSE_CHUNK_COUNT / 4)

/* Resident store pages and tables are capped at this fraction of physical memory (see MiSparseInitializeStore) */
#define MI_SPARSE_CAP_DIVISOR   32

/* Keep this many pages for everybody else when taking a page for the store */
#define MI_SPARSE_PAGE_RESERVE  256

/* A populate short of pages sleeps this many rounds of MI_SPARSE_PAGE_WAIT_MS before it fails (see MiSparseGetZeroedPage) */
#define MI_SPARSE_PAGE_WAITS    50
#define MI_SPARSE_PAGE_WAIT_MS  10

static KGUARDED_MUTEX MiSparseProtoMutex;
static RTL_BITMAP MiSparseProtoBitmap;
static RTL_AVL_TABLE MiSparseOwnerTable;
static BOOLEAN MiSparseProtoReady;
static SIZE_T MiSparseStorePageCap;
static PFN_NUMBER MiSparseZeroPage;
static PFN_NUMBER MiSparseZeroTable;
static MMPTE MiSparseZeroPte;
static MMPDE MiSparseZeroPde;

/* Chunks of the range per creating process (the process object is referenced while it has some) */
typedef struct _MI_SPARSE_OWNER
{
    PEPROCESS Process;
    ULONG Chunks;
} MI_SPARSE_OWNER, *PMI_SPARSE_OWNER;

/* Statistics, for the debugger: store pages and tables (each charged one page of commitment), chunks in use */
SIZE_T MiSparseProtoPages;
SIZE_T MiSparseProtoTables;
ULONG MiSparseProtoChunksInUse;
ULONG MiSparseProtoChunksLeaked;

/* Point a valid PTE or PDE of the range at another page (one 64-bit store; the caller flushes) */
FORCEINLINE
VOID
MiSparseReplaceValidPte(IN PMMPTE PointerPte,
                        IN MMPTE TempPte)
{
    ASSERT(PointerPte->u.Hard.Valid == 1);
    ASSERT(TempPte.u.Hard.Valid == 1);
    *PointerPte = TempPte;
}

static
RTL_GENERIC_COMPARE_RESULTS
NTAPI
MiSparseOwnerCompare(IN PRTL_AVL_TABLE Table,
                     IN PVOID First,
                     IN PVOID Second)
{
    ULONG_PTR A = (ULONG_PTR)((PMI_SPARSE_OWNER)First)->Process;
    ULONG_PTR B = (ULONG_PTR)((PMI_SPARSE_OWNER)Second)->Process;

    UNREFERENCED_PARAMETER(Table);
    if (A < B) return GenericLessThan;
    if (A > B) return GenericGreaterThan;
    return GenericEqual;
}

static
PVOID
NTAPI
MiSparseOwnerAllocate(IN PRTL_AVL_TABLE Table,
                      IN CLONG ByteSize)
{
    UNREFERENCED_PARAMETER(Table);
    return ExAllocatePoolWithTag(PagedPool, ByteSize, 'oSmM');
}

static
VOID
NTAPI
MiSparseOwnerFree(IN PRTL_AVL_TABLE Table,
                  IN PVOID Buffer)
{
    UNREFERENCED_PARAMETER(Table);
    ExFreePoolWithTag(Buffer, 'oSmM');
}

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeSparsePrototypePtes(VOID)
{
    KeInitializeGuardedMutex(&MiSparseProtoMutex);
    RtlInitializeGenericTableAvl(&MiSparseOwnerTable,
                                 MiSparseOwnerCompare,
                                 MiSparseOwnerAllocate,
                                 MiSparseOwnerFree,
                                 NULL);
}

/*
 * A page off the free lists, zeroed, not mapped anywhere yet. PFN lock not held on entry or exit. Short of
 * pages, kick the balancer and sleep a few milliseconds, a bounded number of rounds, then 0.
 *
 * Lock-hold: the callers run with MiSparseProtoMutex and the caller's MmSectionCommitMutex held (and, from
 * NtAllocateVirtualMemory, the address space lock), so this wait is bounded in time (MI_SPARSE_PAGE_WAITS rounds
 * of MI_SPARSE_PAGE_WAIT_MS, half a second at most) and never waits for a balancer pass to finish
 * (MmRebalanceMemoryConsumersAndWait does, without a timeout: a pass that needs a lock this thread holds, or
 * that another thread holds while it waits for one of ours, would never end). Only a real shortage of usable
 * pages (at most MI_SPARSE_PAGE_RESERVE left) gets here, and the populate then fails cleanly.
 */
static
PFN_NUMBER
MiSparseGetZeroedPage(VOID)
{
    PFN_NUMBER PageFrameIndex;
    BOOLEAN Zero;
    KIRQL OldIrql;
    ULONG Color, Retry;
    LARGE_INTEGER Delay;

    for (Retry = 0; ; Retry++)
    {
        PageFrameIndex = 0;
        Zero = FALSE;
        OldIrql = MiAcquirePfnLock();
        if (MiGetUsablePageCount() > MI_SPARSE_PAGE_RESERVE)
        {
            Color = MI_GET_NEXT_COLOR();
            MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
            MI_SET_PROCESS2("Proto PTEs");
            PageFrameIndex = MiRemoveZeroPageSafe(Color);
            if (PageFrameIndex == 0)
            {
                PageFrameIndex = MiRemoveAnyPageGated(Color);
                Zero = TRUE;
            }
        }
        MiReleasePfnLock(OldIrql);

        if (PageFrameIndex != 0)
        {
            if (Zero) MiZeroPhysicalPage(PageFrameIndex);
            return PageFrameIndex;
        }

        if ((Retry >= MI_SPARSE_PAGE_WAITS) || (KeGetCurrentIrql() > APC_LEVEL))
            return 0;

        /* Start a pass and give it time to free pages */
        MmRebalanceMemoryConsumers();
        Delay.QuadPart = -(LONGLONG)MI_SPARSE_PAGE_WAIT_MS * 10000;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }
}

/* Give back a page from MiSparseGetZeroedPage that was never made part of the store */
static
VOID
MiSparseReturnUnusedPage(IN PFN_NUMBER PageFrameIndex)
{
    KIRQL OldIrql = MiAcquirePfnLock();
    MiInsertPageInFreeList(PageFrameIndex);
    MiReleasePfnLock(OldIrql);
}

/* Fill a page with copies of one PTE value through hyperspace */
static
VOID
MiSparseFillPage(IN PFN_NUMBER PageFrameIndex,
                 IN MMPTE Value)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PMMPTE Page;
    KIRQL OldIrql;
    ULONG i;

    Page = MiMapPageInHyperSpace(Process, PageFrameIndex, &OldIrql);
    for (i = 0; i < PTE_PER_PAGE; i++) Page[i] = Value;
    MiUnmapPageInHyperSpace(Process, Page, OldIrql);
}

/* First use: the bitmap, the shared zero page and the shared zero page table. Mutex held. */
static
NTSTATUS
MiSparseInitializeStore(VOID)
{
    PULONG Buffer;
    PFN_NUMBER ZeroPage, ZeroTable;
    KIRQL OldIrql;

    if (MiSparseProtoReady) return STATUS_SUCCESS;

    Buffer = ExAllocatePoolWithTag(NonPagedPool, MI_SPARSE_CHUNK_COUNT / 8, 'pSmM');
    if (!Buffer) return STATUS_INSUFFICIENT_RESOURCES;

    ZeroPage = MiSparseGetZeroedPage();
    ZeroTable = ZeroPage ? MiSparseGetZeroedPage() : 0;
    if (!ZeroTable)
    {
        if (ZeroPage) MiSparseReturnUnusedPage(ZeroPage);
        ExFreePoolWithTag(Buffer, 'pSmM');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* The zero page, read-only, in every slot of the zero page table */
    MI_MAKE_HARDWARE_PTE_KERNEL(&MiSparseZeroPte, MiAddressToPte((PVOID)MI_SPARSE_PROTO_START), MM_READONLY, ZeroPage);
    MiSparseFillPage(ZeroTable, MiSparseZeroPte);
    MiSparseZeroPde = ValidKernelPde;
    MiSparseZeroPde.u.Hard.PageFrameNumber = ZeroTable;

    /* Both pages live for the life of the system; they belong to no page table */
    OldIrql = MiAcquirePfnLock();
    MiInitializePfnForOtherProcess(ZeroPage, MiAddressToPte((PVOID)MI_SPARSE_PROTO_START), 0);
    MiInitializePfnForOtherProcess(ZeroTable, (PMMPTE)MiAddressToPde((PVOID)MI_SPARSE_PROTO_START), 0);
    MiReleasePfnLock(OldIrql);

    RtlInitializeBitMap(&MiSparseProtoBitmap, Buffer, MI_SPARSE_CHUNK_COUNT);
    RtlClearAllBits(&MiSparseProtoBitmap);
    MiSparseZeroPage = ZeroPage;
    MiSparseZeroTable = ZeroTable;

    /*
     * System-wide cap on resident store pages and tables: 1/32 of physical memory. The store pages cannot be
     * paged, and the charge alone (one commit page per store page) lets a process holding one committed page
     * per 2 MB of a huge section pin about 40 % of RAM. A legitimate user needs about one store page per 512
     * committed pages of section (a contiguous 1 GB commit: 512 pages and one table), so the cap still allows
     * committing about 16 times RAM through sparse sections (Java ZGC, MariaDB). A commit that would populate
     * past the cap fails like one over the commit limit.
     */
    MiSparseStorePageCap = MmNumberOfPhysicalPages / MI_SPARSE_CAP_DIVISOR;
    if (MiSparseStorePageCap < 1024) MiSparseStorePageCap = 1024;
    MiSparseProtoReady = TRUE;
    return STATUS_SUCCESS;
}

/* Make sure the page directory for this address exists (all its entries start on the zero table). Mutex held. */
static
NTSTATUS
MiSparseEnsurePageDirectory(IN PVOID Address)
{
    PMMPDE PointerPpe = MiAddressToPpe(Address);
    PFN_NUMBER PageFrameIndex;
    MMPDE TempPde;
    KIRQL OldIrql;

    /* The PDPTs of the range are built at boot (MiInitializePageTable), so every process shares them */
    ASSERT(MiAddressToPxe(Address)->u.Hard.Valid == 1);
    if (PointerPpe->u.Hard.Valid) return STATUS_SUCCESS;

    PageFrameIndex = MiSparseGetZeroedPage();
    if (!PageFrameIndex) return STATUS_INSUFFICIENT_RESOURCES;
    MiSparseFillPage(PageFrameIndex, MiSparseZeroPde);

    TempPde = ValidKernelPde;
    TempPde.u.Hard.PageFrameNumber = PageFrameIndex;
    OldIrql = MiAcquirePfnLock();
    MiInitializePfnForOtherProcess(PageFrameIndex, (PMMPTE)PointerPpe, PFN_FROM_PXE(MiAddressToPxe(Address)));
    MI_WRITE_VALID_PDE(PointerPpe, TempPde);
    MiReleasePfnLock(OldIrql);
    return STATUS_SUCCESS;
}

static
ULONG
MiSparseChunksFor(IN PFN_COUNT PteCount)
{
    return (ULONG)(((ULONG64)PteCount * sizeof(MMPTE) + MI_SPARSE_CHUNK_SIZE - 1) / MI_SPARSE_CHUNK_SIZE);
}

/*
 * Reserve room for PteCount Prototype PTEs for a section created by Owner. All of them read as 0. Returns
 * STATUS_INSUFFICIENT_RESOURCES when the range is full or Owner holds its share of it already.
 */
NTSTATUS
NTAPI
MiAllocateSparsePrototypePtes(IN PFN_COUNT PteCount,
                              IN PEPROCESS Owner,
                              OUT PMMPTE *PrototypePtes)
{
    MI_SPARSE_OWNER Key, *Entry;
    BOOLEAN NewEntry = FALSE;
    ULONG Chunks, First, i;
    NTSTATUS Status;
    PVOID Base;

    PAGED_CODE();
    ASSERT(PteCount != 0);
    Chunks = MiSparseChunksFor(PteCount);

    KeAcquireGuardedMutex(&MiSparseProtoMutex);
    Status = MiSparseInitializeStore();
    if (!NT_SUCCESS(Status)) goto Done;

    /* The share of the range one process may hold */
    Key.Process = Owner;
    Key.Chunks = 0;
    Entry = RtlLookupElementGenericTableAvl(&MiSparseOwnerTable, &Key);
    if (Entry && ((Entry->Chunks + Chunks) > MI_SPARSE_OWNER_CHUNKS))
    {
        DPRINT1("Process %p holds %lu chunks of the sparse Prototype PTE range, %lu more refused\n", Owner, Entry->Chunks, Chunks);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
    if (!Entry)
    {
        Entry = RtlInsertElementGenericTableAvl(&MiSparseOwnerTable, &Key, sizeof(Key), &NewEntry);
        if (!Entry)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Done;
        }
    }

    First = RtlFindClearBitsAndSet(&MiSparseProtoBitmap, Chunks, 0);
    if (First == MAXULONG)
    {
        DPRINT1("Sparse Prototype PTE range full (%lu chunks wanted)\n", Chunks);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto DropEntry;
    }
    Base = (PVOID)(MI_SPARSE_PROTO_START + (ULONG64)First * MI_SPARSE_CHUNK_SIZE);

    /* One page directory covers 512 chunks */
    for (i = 0; i < Chunks; i++)
    {
        Status = MiSparseEnsurePageDirectory((PCHAR)Base + (ULONG64)i * MI_SPARSE_CHUNK_SIZE);
        if (!NT_SUCCESS(Status))
        {
            /* The directories made so far stay: they are shared by the whole range */
            RtlClearBits(&MiSparseProtoBitmap, First, Chunks);
            goto DropEntry;
        }
    }

    /* The owner stays referenced while it holds chunks, so the key cannot be reused by another process */
    if (NewEntry) ObReferenceObject(Owner);
    Entry->Chunks += Chunks;
    MiSparseProtoChunksInUse += Chunks;
    *PrototypePtes = Base;
    Status = STATUS_SUCCESS;
    goto Done;

DropEntry:
    if (NewEntry) RtlDeleteElementGenericTableAvl(&MiSparseOwnerTable, &Key);
Done:
    KeReleaseGuardedMutex(&MiSparseProtoMutex);
    return Status;
}

/*
 * Make the pages that hold the Prototype PTEs FirstPte..LastPte (inclusive) private, so that they can be
 * written. Their contents stay what they read before (0 for a page that was not populated). Callers: the
 * commit paths, at PASSIVE or APC level, after they charged the committed pages and before they write the
 * PTEs.
 *
 * Every page and page table made here is charged one page of non-pageable commitment first (returned by
 * MiFreeSparsePrototypePtes): STATUS_COMMITMENT_LIMIT if that fails, nothing populated then. Short of free
 * pages after waiting, STATUS_NO_MEMORY; what was populated by then stays populated (and charged).
 */
NTSTATUS
NTAPI
MiPopulateSparsePrototypePtes(IN PMMPTE FirstPte,
                              IN PMMPTE LastPte)
{
    ULONG_PTR Va, LastVa;
    PMMPDE PointerPde;
    PMMPTE PointerPte;
    PFN_NUMBER PageFrameIndex;
    SIZE_T Needed, Made;
    MMPTE TempPte;
    MMPDE TempPde;
    BOOLEAN Changed = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ASSERT(MI_IS_SPARSE_PROTOTYPE_PTE(FirstPte) && MI_IS_SPARSE_PROTOTYPE_PTE(LastPte));
    ASSERT(FirstPte <= LastPte);

    Va = (ULONG_PTR)PAGE_ALIGN(FirstPte);
    LastVa = (ULONG_PTR)PAGE_ALIGN(LastPte);

    KeAcquireGuardedMutex(&MiSparseProtoMutex);
    ASSERT(MiSparseProtoReady);

    /* Count what is missing (tables, then pages; a missing table means all its pages are missing) */
    Needed = 0;
    for (ULONG_PTR CountVa = Va; CountVa <= LastVa; CountVa += PAGE_SIZE)
    {
        if (PFN_FROM_PDE(MiAddressToPde((PVOID)CountVa)) == MiSparseZeroTable)
        {
            ULONG_PTR TableEnd = ((CountVa & ~((ULONG_PTR)MI_SPARSE_CHUNK_SIZE - 1)) + MI_SPARSE_CHUNK_SIZE) - PAGE_SIZE;

            if (TableEnd > LastVa) TableEnd = LastVa;
            Needed += 1 + ((TableEnd - CountVa) >> PAGE_SHIFT) + 1;
            CountVa = TableEnd;
            continue;
        }
        if (PFN_FROM_PTE(MiAddressToPte((PVOID)CountVa)) == MiSparseZeroPage) Needed++;
    }
    if (Needed == 0) goto Done;

    /* The cap on what the store may hold resident (all sections together) */
    if ((MiSparseProtoPages + MiSparseProtoTables + Needed) > MiSparseStorePageCap)
    {
        DPRINT("Sparse Prototype PTEs: %Iu store pages over the cap of %Iu\n", Needed, MiSparseStorePageCap);
        Status = STATUS_COMMITMENT_LIMIT;
        goto Done;
    }

    /* Resident for as long as the section lives: charged like the section pages (RAM less the headroom) */
    if (!MiChargeCommit(Needed, MiCommitUser))
    {
        DPRINT("Sparse Prototype PTEs: %Iu store pages over the commit limit\n", Needed);
        Status = STATUS_COMMITMENT_LIMIT;
        goto Done;
    }
    Made = 0;

    for (; Va <= LastVa; Va += PAGE_SIZE)
    {
        PointerPde = MiAddressToPde((PVOID)Va);
        ASSERT(PointerPde->u.Hard.Valid == 1);

        /* A private page table for this 1 GB of section first, a copy of the zero table */
        if (PFN_FROM_PDE(PointerPde) == MiSparseZeroTable)
        {
            PageFrameIndex = MiSparseGetZeroedPage();
            if (!PageFrameIndex)
            {
                Status = STATUS_NO_MEMORY;
                break;
            }
            MiSparseFillPage(PageFrameIndex, MiSparseZeroPte);

            TempPde = ValidKernelPde;
            TempPde.u.Hard.PageFrameNumber = PageFrameIndex;
            OldIrql = MiAcquirePfnLock();
            MiInitializePfnForOtherProcess(PageFrameIndex, (PMMPTE)PointerPde, PFN_FROM_PPE(MiAddressToPpe((PVOID)Va)));
            /* Same contents seen through either table: a stale translation reads the same zeros */
            MiSparseReplaceValidPte((PMMPTE)PointerPde, TempPde);
            MiReleasePfnLock(OldIrql);
            MiSparseProtoTables++;
            Made++;
            Changed = TRUE;
        }

        /* Then a private zeroed page in place of the zero page */
        PointerPte = MiAddressToPte((PVOID)Va);
        ASSERT(PointerPte->u.Hard.Valid == 1);
        if (PFN_FROM_PTE(PointerPte) != MiSparseZeroPage) continue;

        PageFrameIndex = MiSparseGetZeroedPage();
        if (!PageFrameIndex)
        {
            Status = STATUS_NO_MEMORY;
            break;
        }
        MI_MAKE_HARDWARE_PTE_KERNEL(&TempPte, PointerPte, MM_READWRITE, PageFrameIndex);
        OldIrql = MiAcquirePfnLock();

        /*
         * This processor (the thread may have moved since the table was swapped) may still map the page of the
         * page table, seen through the self-map, to the shared zero table when it touched it before the swap:
         * the write below must reach the private table and never the zero table, which every chunk shares.
         * Invalidate here, at DISPATCH_LEVEL with the PFN lock held, on the processor that writes.
         */
        __invlpg(PointerPte);
        ASSERT(PFN_FROM_PDE(PointerPde) != MiSparseZeroTable);
        MiInitializePfnForOtherProcess(PageFrameIndex, PointerPte, PFN_FROM_PDE(PointerPde));
        MiSparseReplaceValidPte(PointerPte, TempPte);
        MiReleasePfnLock(OldIrql);
        MiSparseProtoPages++;
        Made++;
        Changed = TRUE;
    }

    /* A failure keeps what was made (charged); the rest of the charge goes back */
    ASSERT(Made <= Needed);
    if (Made < Needed) MiReturnCommit(Needed - Made);

    /*
     * Another processor may still translate a populated page to the zero page. Both read as zeros, but the
     * caller is about to write committed PTEs there, which every processor must then see: flush before
     * anyone can write, with the mutex still held so that a second populate of the same page waits for it.
     */
    if (Changed) KeFlushEntireTb(TRUE, TRUE);
Done:
    KeReleaseGuardedMutex(&MiSparseProtoMutex);
    return Status;
}

/*
 * Give back the store of a deleted segment created by Owner. Every Prototype PTE must be 0 by now and no page
 * of the segment may still be accounted to the pages that hold them (MiSegmentDelete). The commitment charged
 * for each page and table goes back. A table whose pages are still referenced (a bug) is kept, with its
 * chunk: the chunk is never handed to another section.
 */
VOID
NTAPI
MiFreeSparsePrototypePtes(IN PMMPTE PrototypePtes,
                          IN PFN_COUNT PteCount,
                          IN PEPROCESS Owner)
{
    PFN_NUMBER Pages[PTE_PER_PAGE];
    ULONG Chunks, First, Chunk, Count, i;
    MI_SPARSE_OWNER Key, *Entry;
    PEPROCESS Dereference = NULL;
    SIZE_T Returned = 0;
    ULONG_PTR Va;
    PMMPDE PointerPde;
    PMMPTE PointerPte;
    PFN_NUMBER TableFrame, DirectoryFrame;
    PMMPFN Pfn1;
    BOOLEAN Busy;
    KIRQL OldIrql;

    PAGED_CODE();
    ASSERT(MI_IS_SPARSE_PROTOTYPE_PTE(PrototypePtes));
    ASSERT(((ULONG_PTR)PrototypePtes & (MI_SPARSE_CHUNK_SIZE - 1)) == 0);
    Chunks = MiSparseChunksFor(PteCount);
    First = (ULONG)(((ULONG_PTR)PrototypePtes - MI_SPARSE_PROTO_START) / MI_SPARSE_CHUNK_SIZE);

    KeAcquireGuardedMutex(&MiSparseProtoMutex);
    for (Chunk = 0; Chunk < Chunks; Chunk++)
    {
        Va = (ULONG_PTR)PrototypePtes + (ULONG64)Chunk * MI_SPARSE_CHUNK_SIZE;
        PointerPde = MiAddressToPde((PVOID)Va);
        TableFrame = PFN_FROM_PDE(PointerPde);
        if (TableFrame != MiSparseZeroTable)
        {
            /* Collect the private pages of this table */
            Count = 0;
            Busy = FALSE;
            PointerPte = MiAddressToPte((PVOID)Va);
            OldIrql = MiAcquirePfnLock();
            for (i = 0; i < PTE_PER_PAGE; i++)
            {
                if (PFN_FROM_PTE(&PointerPte[i]) == MiSparseZeroPage) continue;
                Pages[Count] = PFN_FROM_PTE(&PointerPte[i]);
                Pfn1 = MI_PFN_ELEMENT(Pages[Count]);
                if ((Pfn1->u2.ShareCount != 1) || (Pfn1->u3.e2.ReferenceCount != 1)) Busy = TRUE;
                Count++;
            }
            MiReleasePfnLock(OldIrql);
            if (Busy)
            {
                /* Keep the table, its pages, their charge and the chunk: never reused */
                DPRINT1("Sparse Prototype PTE table %p still referenced: kept, chunk not reused\n", (PVOID)Va);
                MiSparseProtoChunksLeaked++;
                continue;
            }

            /* Back to the zero page and table everywhere, flushed, before any of the pages can be reused */
            for (i = 0; i < PTE_PER_PAGE; i++) MiSparseReplaceValidPte(&PointerPte[i], MiSparseZeroPte);
            MiSparseReplaceValidPte((PMMPTE)PointerPde, MiSparseZeroPde);
            KeFlushEntireTb(TRUE, TRUE);

            DirectoryFrame = PFN_FROM_PPE(MiAddressToPpe((PVOID)Va));
            OldIrql = MiAcquirePfnLock();
            for (i = 0; i < Count; i++)
            {
                Pfn1 = MI_PFN_ELEMENT(Pages[i]);
                MI_SET_PFN_DELETED(Pfn1);
                MiDecrementShareCount(Pfn1, Pages[i]);
                MiDecrementShareCount(MI_PFN_ELEMENT(TableFrame), TableFrame);
            }
            Pfn1 = MI_PFN_ELEMENT(TableFrame);
            ASSERT(Pfn1->u2.ShareCount == 1);
            MI_SET_PFN_DELETED(Pfn1);
            MiDecrementShareCount(Pfn1, TableFrame);
            MiDecrementShareCount(MI_PFN_ELEMENT(DirectoryFrame), DirectoryFrame);
            MiReleasePfnLock(OldIrql);

            MiSparseProtoPages -= Count;
            MiSparseProtoTables--;
            Returned += Count + 1;
        }

        /* This chunk is all zero page again: the address range can be used again */
        RtlClearBits(&MiSparseProtoBitmap, First + Chunk, 1);
        MiSparseProtoChunksInUse--;
    }

    /* The owner's share; its reference goes when it holds nothing */
    Key.Process = Owner;
    Key.Chunks = 0;
    Entry = RtlLookupElementGenericTableAvl(&MiSparseOwnerTable, &Key);
    ASSERT(Entry && (Entry->Chunks >= Chunks));
    if (Entry)
    {
        Entry->Chunks -= min(Entry->Chunks, Chunks);
        if (Entry->Chunks == 0)
        {
            RtlDeleteElementGenericTableAvl(&MiSparseOwnerTable, &Key);
            Dereference = Owner;
        }
    }
    KeReleaseGuardedMutex(&MiSparseProtoMutex);

    if (Returned) MiReturnCommit(Returned);
    /* Possibly the last reference of an exited process: its deletion goes to a worker, not this unmap path */
    if (Dereference) ObDereferenceObjectDeferDelete(Dereference);
}

/*
 * Skip what holds no committed PTE: returns PrototypePte itself when its page is populated, else the first
 * PTE of the next page (or of the next page table, when the whole table is the zero table).
 */
PMMPTE
NTAPI
MiSkipEmptySparsePrototypePtes(IN PMMPTE PrototypePte)
{
    ASSERT(MI_IS_SPARSE_PROTOTYPE_PTE(PrototypePte));
    if (PFN_FROM_PDE(MiAddressToPde(PrototypePte)) == MiSparseZeroTable)
        return (PMMPTE)(((ULONG_PTR)PrototypePte & ~((ULONG_PTR)MI_SPARSE_CHUNK_SIZE - 1)) + MI_SPARSE_CHUNK_SIZE);
    if (PFN_FROM_PTE(MiAddressToPte(PrototypePte)) == MiSparseZeroPage)
        return (PMMPTE)((ULONG_PTR)PAGE_ALIGN(PrototypePte) + PAGE_SIZE);
    return PrototypePte;
}

#endif /* _M_AMD64 */

/*
 * Count the zero (not committed) Prototype PTEs in FirstPte..EndPte (exclusive). For a sparse store, what was
 * never populated is counted a page or a table at a time, so a count over an 8 TB range does not walk 2^31
 * PTEs while the callers hold the section commit mutex.
 */
SIZE_T
NTAPI
MiCountZeroPrototypePtes(IN PMMPTE FirstPte,
                         IN PMMPTE EndPte)
{
    PMMPTE PointerPte = FirstPte, PageEnd;
    SIZE_T Count = 0;

    while (PointerPte < EndPte)
    {
#ifdef _M_AMD64
        if (MI_IS_SPARSE_PROTOTYPE_PTE(PointerPte))
        {
            PMMPTE Next = MiSkipEmptySparsePrototypePtes(PointerPte);
            if (Next != PointerPte)
            {
                if (Next > EndPte) Next = EndPte;
                Count += Next - PointerPte;
                PointerPte = Next;
                continue;
            }
        }
#endif
        /* A populated (or ordinary) page: look at its entries */
        PageEnd = (PMMPTE)((ULONG_PTR)PAGE_ALIGN(PointerPte) + PAGE_SIZE);
        if (PageEnd > EndPte) PageEnd = EndPte;
        for (; PointerPte < PageEnd; PointerPte++)
        {
            if (PointerPte->u.Long == 0) Count++;
        }
    }
    return Count;
}

/* EOF */
