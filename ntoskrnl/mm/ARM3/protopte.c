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
 * The pages are resident system memory, not commit: at most one page per 2 MB of committed section plus one
 * page table per 1 GB, and the committed pages themselves are charged as before. The section charges nothing
 * while it is only reserved.
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

/* Keep this many pages for everybody else: a populate fails (STATUS_INSUFFICIENT_RESOURCES) below it */
#define MI_SPARSE_PAGE_RESERVE  256

static KGUARDED_MUTEX MiSparseProtoMutex;
static RTL_BITMAP MiSparseProtoBitmap;
static BOOLEAN MiSparseProtoReady;
static PFN_NUMBER MiSparseZeroPage;
static PFN_NUMBER MiSparseZeroTable;
static MMPTE MiSparseZeroPte;
static MMPDE MiSparseZeroPde;

/* Statistics, for the debugger */
SIZE_T MiSparseProtoPages;
SIZE_T MiSparseProtoTables;
ULONG MiSparseProtoChunksInUse;

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

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeSparsePrototypePtes(VOID)
{
    KeInitializeGuardedMutex(&MiSparseProtoMutex);
}

/* A page off the free lists, zeroed, not mapped anywhere yet. PFN lock not held on entry or exit. */
static
PFN_NUMBER
MiSparseGetZeroedPage(VOID)
{
    PFN_NUMBER PageFrameIndex = 0;
    BOOLEAN Zero = FALSE;
    KIRQL OldIrql;
    ULONG Color;

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

    if (Zero) MiZeroPhysicalPage(PageFrameIndex);
    return PageFrameIndex;
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

/*
 * Reserve room for PteCount Prototype PTEs. All of them read as 0. Returns STATUS_INSUFFICIENT_RESOURCES
 * when the range is full.
 */
NTSTATUS
NTAPI
MiAllocateSparsePrototypePtes(IN PFN_COUNT PteCount,
                              OUT PMMPTE *PrototypePtes)
{
    ULONG Chunks, First, i;
    NTSTATUS Status;
    PVOID Base;

    PAGED_CODE();
    ASSERT(PteCount != 0);
    Chunks = (ULONG)(((ULONG64)PteCount * sizeof(MMPTE) + MI_SPARSE_CHUNK_SIZE - 1) / MI_SPARSE_CHUNK_SIZE);

    KeAcquireGuardedMutex(&MiSparseProtoMutex);
    Status = MiSparseInitializeStore();
    if (!NT_SUCCESS(Status)) goto Done;

    First = RtlFindClearBitsAndSet(&MiSparseProtoBitmap, Chunks, 0);
    if (First == MAXULONG)
    {
        DPRINT1("Sparse Prototype PTE range full (%lu chunks wanted)\n", Chunks);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
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
            goto Done;
        }
    }

    MiSparseProtoChunksInUse += Chunks;
    *PrototypePtes = Base;
    Status = STATUS_SUCCESS;
Done:
    KeReleaseGuardedMutex(&MiSparseProtoMutex);
    return Status;
}

/*
 * Make the pages that hold the Prototype PTEs FirstPte..LastPte (inclusive) private, so that they can be
 * written. Their contents stay what they read before (0 for a page that was not populated). Callers: the
 * commit paths, at PASSIVE or APC level, before they write the PTEs. May fail with
 * STATUS_INSUFFICIENT_RESOURCES; what was populated stays populated.
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
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            MiSparseFillPage(PageFrameIndex, MiSparseZeroPte);

            TempPde = ValidKernelPde;
            TempPde.u.Hard.PageFrameNumber = PageFrameIndex;
            OldIrql = MiAcquirePfnLock();
            MiInitializePfnForOtherProcess(PageFrameIndex, (PMMPTE)PointerPde, PFN_FROM_PPE(MiAddressToPpe((PVOID)Va)));
            /* Same contents seen through either table: a stale translation reads the same zeros */
            MiSparseReplaceValidPte((PMMPTE)PointerPde, TempPde);

            /*
             * This processor may still map the page-table page of this chunk (seen through the self-map)
             * to the shared zero table: the PTE write below must reach the new table.
             */
            __invlpg(MiAddressToPte((PVOID)Va));
            MiReleasePfnLock(OldIrql);
            MiSparseProtoTables++;
            Changed = TRUE;
        }

        /* Then a private zeroed page in place of the zero page */
        PointerPte = MiAddressToPte((PVOID)Va);
        ASSERT(PointerPte->u.Hard.Valid == 1);
        if (PFN_FROM_PTE(PointerPte) != MiSparseZeroPage) continue;

        PageFrameIndex = MiSparseGetZeroedPage();
        if (!PageFrameIndex)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        MI_MAKE_HARDWARE_PTE_KERNEL(&TempPte, PointerPte, MM_READWRITE, PageFrameIndex);
        OldIrql = MiAcquirePfnLock();
        MiInitializePfnForOtherProcess(PageFrameIndex, PointerPte, PFN_FROM_PDE(PointerPde));
        MiSparseReplaceValidPte(PointerPte, TempPte);
        MiReleasePfnLock(OldIrql);
        MiSparseProtoPages++;
        Changed = TRUE;
    }

    /*
     * Another processor may still translate a populated page to the zero page. Both read as zeros, but the
     * caller is about to write committed PTEs there, which every processor must then see: flush before
     * anyone can write, with the mutex still held so that a second populate of the same page waits for it.
     */
    if (Changed) KeFlushEntireTb(TRUE, TRUE);
    KeReleaseGuardedMutex(&MiSparseProtoMutex);
    return Status;
}

/*
 * Give back the store of a deleted segment. Every Prototype PTE must be 0 by now and no page of the segment
 * may still be accounted to the pages that hold them (MiSegmentDelete).
 */
VOID
NTAPI
MiFreeSparsePrototypePtes(IN PMMPTE PrototypePtes,
                          IN PFN_COUNT PteCount)
{
    PFN_NUMBER Pages[PTE_PER_PAGE];
    ULONG Chunks, First, Chunk, Count, i;
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
    Chunks = (ULONG)(((ULONG64)PteCount * sizeof(MMPTE) + MI_SPARSE_CHUNK_SIZE - 1) / MI_SPARSE_CHUNK_SIZE);
    First = (ULONG)(((ULONG_PTR)PrototypePtes - MI_SPARSE_PROTO_START) / MI_SPARSE_CHUNK_SIZE);

    KeAcquireGuardedMutex(&MiSparseProtoMutex);
    for (Chunk = 0; Chunk < Chunks; Chunk++)
    {
        Va = (ULONG_PTR)PrototypePtes + (ULONG64)Chunk * MI_SPARSE_CHUNK_SIZE;
        PointerPde = MiAddressToPde((PVOID)Va);
        TableFrame = PFN_FROM_PDE(PointerPde);
        if (TableFrame == MiSparseZeroTable) continue;

        /* Collect the private pages of this table; a page still in use keeps the whole table (leaked) */
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
            DPRINT1("Sparse Prototype PTE table %p still referenced, not freed\n", (PVOID)Va);
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
    }

    /* The page directories stay (shared by the range); the address range can be used again */
    RtlClearBits(&MiSparseProtoBitmap, First, Chunks);
    MiSparseProtoChunksInUse -= Chunks;
    KeReleaseGuardedMutex(&MiSparseProtoMutex);
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

/* EOF */
