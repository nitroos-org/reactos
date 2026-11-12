/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/virtual.c
 * PURPOSE:         ARM Memory Manager Virtual Memory Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

#define MI_MAPPED_COPY_PAGES  14
#define MI_POOL_COPY_BYTES    512
#define MI_MAX_TRANSFER_SIZE  64 * 1024

NTSTATUS NTAPI
MiProtectVirtualMemory(IN PEPROCESS Process,
                       IN OUT PVOID *BaseAddress,
                       IN OUT PSIZE_T NumberOfBytesToProtect,
                       IN ULONG NewAccessProtection,
                       OUT PULONG OldAccessProtection  OPTIONAL);

VOID
NTAPI
MiFlushTbAndCapture(IN PMMVAD FoundVad,
                    IN PMMPTE PointerPte,
                    IN ULONG ProtectionMask,
                    IN PMMPFN Pfn1,
                    IN BOOLEAN CaptureDirtyBit);


/* PRIVATE FUNCTIONS **********************************************************/

ULONG
NTAPI
MiCalculatePageCommitment(IN ULONG_PTR StartingAddress,
                          IN ULONG_PTR EndingAddress,
                          IN PMMVAD Vad,
                          IN PEPROCESS Process)
{
    PMMPTE PointerPte, LastPte;
    PMMPDE PointerPde;
    BOOLEAN OnPdeBoundary = TRUE;
#if _MI_PAGING_LEVELS >= 3
    PMMPPE PointerPpe;
    BOOLEAN OnPpeBoundary = TRUE;
#if _MI_PAGING_LEVELS == 4
    PMMPXE PointerPxe;
    BOOLEAN OnPxeBoundary = TRUE;
#endif
#endif

    /* Make sure this all makes sense */
    ASSERT(PsGetCurrentThread()->OwnsProcessWorkingSetExclusive || PsGetCurrentThread()->OwnsProcessWorkingSetShared);
    ASSERT(EndingAddress >= StartingAddress);
    PointerPte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    /*
     * In case this is a committed VAD, assume the whole range is committed
     * and count the individually decommitted pages.
     * In case it is not, assume the range is not committed and count the individually committed pages.
     */
    ULONG_PTR CommittedPages = Vad->u.VadFlags.MemCommit ? BYTES_TO_PAGES(EndingAddress - StartingAddress) : 0;

    while (PointerPte <= LastPte)
    {
#if _MI_PAGING_LEVELS == 4
        /* Check if PXE was ever paged in. */
        if (OnPxeBoundary)
        {
            PointerPxe = MiPteToPxe(PointerPte);

            /* Check that this loop is sane */
            ASSERT(OnPpeBoundary);
            ASSERT(OnPdeBoundary);

            if (PointerPxe->u.Long == 0)
            {
                PointerPxe++;
                PointerPte = MiPxeToPte(PointerPxe);
                continue;
            }

            if (PointerPxe->u.Hard.Valid == 0)
                MiMakeSystemAddressValid(MiPteToPpe(PointerPte), Process);
        }
        ASSERT(PointerPxe->u.Hard.Valid == 1);
#endif

#if _MI_PAGING_LEVELS >= 3
        /* Now PPE */
        if (OnPpeBoundary)
        {
            PointerPpe = MiPteToPpe(PointerPte);

            /* Sanity again */
            ASSERT(OnPdeBoundary);

            if (PointerPpe->u.Long == 0)
            {
                PointerPpe++;
                PointerPte = MiPpeToPte(PointerPpe);
#if _MI_PAGING_LEVELS == 4
                OnPxeBoundary = MiIsPteOnPxeBoundary(PointerPte);
#endif
                continue;
            }

            if (PointerPpe->u.Hard.Valid == 0)
                MiMakeSystemAddressValid(MiPteToPde(PointerPte), Process);
        }
        ASSERT(PointerPpe->u.Hard.Valid == 1);
#endif

        /* Last level is the PDE */
        if (OnPdeBoundary)
        {
            PointerPde = MiPteToPde(PointerPte);
            if (PointerPde->u.Long == 0)
            {
                PointerPde++;
                PointerPte = MiPdeToPte(PointerPde);
#if _MI_PAGING_LEVELS >= 3
                OnPpeBoundary = MiIsPteOnPpeBoundary(PointerPte);
#if _MI_PAGING_LEVELS == 4
                OnPxeBoundary = MiIsPteOnPxeBoundary(PointerPte);
#endif
#endif
                continue;
            }

            if (PointerPde->u.Hard.Valid == 0)
                MiMakeSystemAddressValid(PointerPte, Process);
        }
        ASSERT(PointerPde->u.Hard.Valid == 1);

        /* Is this PTE demand zero? */
        if (PointerPte->u.Long != 0)
        {
            /* It isn't -- is it a decommited, invalid, or faulted PTE? */
            if ((PointerPte->u.Hard.Valid == 0) &&
                (PointerPte->u.Soft.Protection == MM_DECOMMIT) &&
                ((PointerPte->u.Soft.Prototype == 0) ||
                    (PointerPte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)))
            {
                /* It is, so remove it from the count of committed pages if we have to */
                if (Vad->u.VadFlags.MemCommit)
                    CommittedPages--;
            }
            else if (!Vad->u.VadFlags.MemCommit)
            {
                /* It is a valid, non-decommited, non-paged out PTE. Count it in. */
                CommittedPages++;
            }
        }

        /* Move to the next PTE */
        PointerPte++;
        /* Manage page tables */
        OnPdeBoundary = MiIsPteOnPdeBoundary(PointerPte);
#if _MI_PAGING_LEVELS >= 3
        OnPpeBoundary = MiIsPteOnPpeBoundary(PointerPte);
#if _MI_PAGING_LEVELS == 4
        OnPxeBoundary = MiIsPteOnPxeBoundary(PointerPte);
#endif
#endif
    }

    /* Make sure we didn't mess this up */
    ASSERT(CommittedPages <= BYTES_TO_PAGES(EndingAddress - StartingAddress));
    return CommittedPages;
}

ULONG
NTAPI
MiMakeSystemAddressValid(IN PVOID PageTableVirtualAddress,
                         IN PEPROCESS CurrentProcess)
{
    NTSTATUS Status;
    BOOLEAN WsShared = FALSE, WsSafe = FALSE, LockChange = FALSE;
    PETHREAD CurrentThread = PsGetCurrentThread();

    /* Must be a non-pool page table, since those are double-mapped already */
    ASSERT(PageTableVirtualAddress > MM_HIGHEST_USER_ADDRESS);
    ASSERT((PageTableVirtualAddress < MmPagedPoolStart) ||
           (PageTableVirtualAddress > MmPagedPoolEnd));

    /* Working set lock or PFN lock should be held */
    ASSERT(KeAreAllApcsDisabled() == TRUE);

    /* Check if the page table is valid */
    while (!MmIsAddressValid(PageTableVirtualAddress))
    {
        /* Release the working set lock */
        MiUnlockProcessWorkingSetForFault(CurrentProcess,
                                          CurrentThread,
                                          &WsSafe,
                                          &WsShared);

        /* Fault it in */
        Status = MmAccessFault(FALSE, PageTableVirtualAddress, KernelMode, NULL);
        if (!NT_SUCCESS(Status))
        {
            /* This should not fail */
            KeBugCheckEx(KERNEL_DATA_INPAGE_ERROR,
                         1,
                         Status,
                         (ULONG_PTR)CurrentProcess,
                         (ULONG_PTR)PageTableVirtualAddress);
        }

        /* Lock the working set again */
        MiLockProcessWorkingSetForFault(CurrentProcess,
                                        CurrentThread,
                                        WsSafe,
                                        WsShared);

        /* This flag will be useful later when we do better locking */
        LockChange = TRUE;
    }

    /* Let caller know what the lock state is */
    return LockChange;
}

ULONG
NTAPI
MiMakeSystemAddressValidPfn(IN PVOID VirtualAddress,
                            IN KIRQL OldIrql)
{
    NTSTATUS Status;
    BOOLEAN LockChange = FALSE;

    /* Must be e kernel address */
    ASSERT(VirtualAddress > MM_HIGHEST_USER_ADDRESS);

    /* Check if the page is valid */
    while (!MmIsAddressValid(VirtualAddress))
    {
        /* Release the PFN database */
        MiReleasePfnLock(OldIrql);

        /* Fault it in */
        Status = MmAccessFault(FALSE, VirtualAddress, KernelMode, NULL);
        if (!NT_SUCCESS(Status))
        {
            /* This should not fail */
            KeBugCheckEx(KERNEL_DATA_INPAGE_ERROR,
                         3,
                         Status,
                         0,
                         (ULONG_PTR)VirtualAddress);
        }

        /* This flag will be useful later when we do better locking */
        LockChange = TRUE;

        /* Lock the PFN database */
        OldIrql = MiAcquirePfnLock();
    }

    /* Let caller know what the lock state is */
    return LockChange;
}

PFN_COUNT
NTAPI
MiDeleteSystemPageableVm(IN PMMPTE PointerPte,
                         IN PFN_NUMBER PageCount,
                         IN ULONG Flags,
                         OUT PPFN_NUMBER ValidPages)
{
    PFN_COUNT ActualPages = 0;
    PETHREAD CurrentThread = PsGetCurrentThread();
    PMMPFN Pfn1, Pfn2;
    PFN_NUMBER PageFrameIndex, PageTableIndex;
    KIRQL OldIrql;
    MI_DEFERRED_RELEASE Deferred;
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    /*
     * A freed page goes back only after every processor has flushed its
     * translation; the caller owns the range, so nothing maps it meanwhile
     */
    MiInitializeDeferredRelease(&Deferred, TRUE, 0);

    /* Lock the system working set */
    MiLockWorkingSet(CurrentThread, &MmSystemCacheWs);

    /* Loop all pages */
    while (PageCount)
    {
        /* Make sure there's some data about the page */
        if (PointerPte->u.Long)
        {
            /* Normally this is one possibility -- freeing a valid page */
            if (PointerPte->u.Hard.Valid)
            {
                if (MiDeferredReleaseRoom(&Deferred) == 0)
                {
                    /* The flush needs neither lock */
                    MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);
                    MiCompleteDeferredRelease(&Deferred);
                    MiLockWorkingSet(CurrentThread, &MmSystemCacheWs);
                }

                /* Get the page PFN */
                PageFrameIndex = PFN_FROM_PTE(PointerPte);
                Pfn1 = MiGetPfnEntry(PageFrameIndex);

                /* Should not have any working set data yet */
                ASSERT(Pfn1->u1.WsIndex == 0);

                /* Actual valid, legitimate, pages */
                if (ValidPages) (*ValidPages)++;

                /* Get the page table entry */
                PageTableIndex = Pfn1->u4.PteFrame;
                Pfn2 = MiGetPfnEntry(PageTableIndex);

                /* Lock the PFN database */
                OldIrql = MiAcquirePfnLock();

                /* Destroy the PTE */
                MI_ERASE_PTE(PointerPte);

                /*
                 * Delete the page, it is freed after the flush. The release does
                 * not recheck the PTE: nothing else changes these PTEs meanwhile,
                 * because system working set trimming is not implemented. A future
                 * trimmer must not touch a range that is being deleted.
                 */
                MI_SET_PFN_DELETED(Pfn1);
                MiDeferTbFlush(&Deferred, MiPteToAddress(PointerPte));
                MiDeferShareRelease(&Deferred, Pfn1, FALSE);

                /* Decrement the page table too */
                MiDecrementShareCount(Pfn2, PageTableIndex);

                /* Release the PFN database */
                MiReleasePfnLock(OldIrql);
            }
            else
            {
                /* As always, only handle current ARM3 scenarios */
                ASSERT(PointerPte->u.Soft.Prototype == 0);
                ASSERT(PointerPte->u.Soft.Transition == 0);

                /*
                 * The only other ARM3 possibility is a demand zero page, which would
                 * mean freeing some of the paged pool pages that haven't even been
                 * touched yet, as part of a larger allocation.
                 *
                 * Right now, we shouldn't expect any page file information in the PTE
                 */
                ASSERT(PointerPte->u.Soft.PageFileHigh == 0);

                /* Destroy the PTE */
                MI_ERASE_PTE(PointerPte);
            }

            /* Actual legitimate pages */
            ActualPages++;
        }

        /* Keep going */
        PointerPte++;
        PageCount--;
    }

    /* Release the working set */
    MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);

    /* Flush, then free the pages */
    MiCompleteDeferredRelease(&Deferred);
    MiCleanupDeferredRelease(&Deferred);

    /* Done */
    return ActualPages;
}

#define TAG_MM_DEFERRED 'fDmM'

VOID
MiInitializeDeferredRelease(
    _Out_ PMI_DEFERRED_RELEASE Deferred,
    _In_ BOOLEAN AllProcessors,
    _In_ PFN_NUMBER PageHint)
{
    MmInitializeTbFlushList(&Deferred->FlushList, AllProcessors);
    Deferred->Count = 0;
    Deferred->Entries = Deferred->Inline;
    Deferred->Capacity = RTL_NUMBER_OF(Deferred->Inline);

    /* One page holds a whole page table's worth; without it the inline array is flushed more often */
    if (PageHint > RTL_NUMBER_OF(Deferred->Inline))
    {
        PULONG_PTR Entries = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, TAG_MM_DEFERRED);
        if (Entries)
        {
            Deferred->Entries = Entries;
            Deferred->Capacity = PAGE_SIZE / sizeof(ULONG_PTR);
        }
    }
}

VOID
MiCleanupDeferredRelease(
    _Inout_ PMI_DEFERRED_RELEASE Deferred)
{
    ASSERT(Deferred->Count == 0);
    ASSERT(Deferred->FlushList.Count == 0);
    if (Deferred->Entries != Deferred->Inline)
        ExFreePoolWithTag(Deferred->Entries, TAG_MM_DEFERRED);
}

static
VOID
MiReleaseDeferredEntries(
    _Inout_ PMI_DEFERRED_RELEASE Deferred)
{
    ULONG i;
    PMMPFN Pfn1;

    MI_ASSERT_PFN_LOCK_HELD();
    for (i = 0; i < Deferred->Count; i++)
    {
        Pfn1 = (PMMPFN)(Deferred->Entries[i] & ~(ULONG_PTR)1);
        if (Deferred->Entries[i] & 1)
        {
            /* A RosMm page: its owner frees it through its own reference */
            ASSERT(Pfn1->u3.e1.PageLocation == ActiveAndValid);
            ASSERT(Pfn1->u2.ShareCount > 0);
            if (--Pfn1->u2.ShareCount == 0)
                Pfn1->u3.e1.PageLocation = TransitionPage;
        }
        else
        {
            MiDecrementShareCount(Pfn1, MiGetPfnEntryIndex(Pfn1));
        }
    }
    Deferred->Count = 0;
}

VOID
MiCompleteDeferredRelease(
    _Inout_ PMI_DEFERRED_RELEASE Deferred)
{
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    /* Every processor drops its translations before any of the pages can be reused */
    MmFlushTbList(&Deferred->FlushList);
    if (Deferred->Count == 0)
        return;

    OldIrql = MiAcquirePfnLock();
    MiReleaseDeferredEntries(Deferred);
    MiReleasePfnLock(OldIrql);
}

KIRQL
MiCompleteDeferredReleaseLocked(
    _Inout_ PMI_DEFERRED_RELEASE Deferred,
    _In_ KIRQL OldIrql)
{
    MI_ASSERT_PFN_LOCK_HELD();
    if ((Deferred->Count == 0) && (Deferred->FlushList.Count == 0))
        return OldIrql;

    MiReleasePfnLock(OldIrql);
    MmFlushTbList(&Deferred->FlushList);
    OldIrql = MiAcquirePfnLock();
    MiReleaseDeferredEntries(Deferred);
    return OldIrql;
}

/* A VirtualLock on a private page goes with its PTE: drop the lock reference */
static
BOOLEAN
MiDropVirtualLock(IN PMMPFN Pfn1)
{
    MI_ASSERT_PFN_LOCK_HELD();

    if (!Pfn1->Wsle.u1.e1.LockedInWs && !Pfn1->Wsle.u1.e1.LockedInMemory)
        return FALSE;

    Pfn1->Wsle.u1.e1.LockedInWs = 0;
    Pfn1->Wsle.u1.e1.LockedInMemory = 0;
    MiDereferencePfnAndDropLockCount(Pfn1);
    return TRUE;
}

/*
 * Returns TRUE when a valid translation was removed. Without KeepShare the page
 * is released at once and the caller must flush the TB before it releases the
 * PFN lock; with it, the page keeps its last share reference and is returned
 * there (NULL if there is none to drop) for the caller to drop after the flush.
 */
static
BOOLEAN
MiDeletePteCommon(IN PMMPTE PointerPte,
                  IN PVOID VirtualAddress,
                  IN PEPROCESS CurrentProcess,
                  IN PMMPTE PrototypePte,
                  OUT PMMPFN *KeepShare OPTIONAL)
{
    PMMPFN Pfn1;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    PMMPDE PointerPde;

    /* PFN lock must be held */
    MI_ASSERT_PFN_LOCK_HELD();
    if (KeepShare) *KeepShare = NULL;

    /* WorkingSet must be exclusively locked */
    ASSERT(MM_ANY_WS_LOCK_HELD_EXCLUSIVE(PsGetCurrentThread()));

    /* This must be current process. */
    ASSERT(CurrentProcess == PsGetCurrentProcess());

    /* Capture the PTE */
    TempPte = *PointerPte;

    /* See if the PTE is valid */
    if (TempPte.u.Hard.Valid == 0)
    {
        /* Prototype PTEs not supported yet */
        ASSERT(TempPte.u.Soft.Prototype == 0);

        /*
         * NitroPager: a paged-out private page. The PTE, read here under the
         * PFN lock, owns the slot: it goes with the PTE (owner checked). No
         * page, and no page table reference (repurpose dropped it).
         */
        if (MI_IS_PAGEFILE_PTE(&TempPte))
        {
            ASSERT(MiNitroPagerMode != 0);
            MiReleasePageFileSlot((ULONG)TempPte.u.Soft.PageFileLow,
                                  MI_PAGEFILE_PTE_SLOT(&TempPte),
                                  MiPagerOwnerTagForPte(PointerPte));
            MI_ERASE_PTE(PointerPte);
            return FALSE;
        }
        ASSERT((TempPte.u.Soft.PageFileHigh == 0) || (TempPte.u.Soft.Transition == 1));

        if (TempPte.u.Soft.Transition)
        {
            /* Get the PFN entry */
            PageFrameIndex = PFN_FROM_PTE(&TempPte);
            Pfn1 = MiGetPfnEntry(PageFrameIndex);

            DPRINT("Pte %p is transitional!\n", PointerPte);

            /* Make sure the saved PTE address is valid */
            ASSERT((PMMPTE)((ULONG_PTR)Pfn1->PteAddress & ~0x1) == PointerPte);

            /* Destroy the PTE */
            MI_ERASE_PTE(PointerPte);

            /* Drop the reference on the page table. */
            MiDecrementShareCount(MiGetPfnEntry(Pfn1->u4.PteFrame), Pfn1->u4.PteFrame);

            /* In case of shared page, the prototype PTE must be in transition, not the process one */
            ASSERT(Pfn1->u3.e1.PrototypePte == 0);

            /* Delete the PFN */
            MI_SET_PFN_DELETED(Pfn1);

            /* Dropping a VirtualLock frees the page, unless an MDL still holds it */
            if (MiDropVirtualLock(Pfn1))
                return FALSE;

            /*
             * It is either on a list (refcount == 0), being written, or still
             * locked by an MDL, whose unlock frees it.
             */
            ASSERT(Pfn1->u3.e2.ReferenceCount >= Pfn1->u3.e1.WriteInProgress);

            /* See if we must free it ourselves, or if it will be freed once I/O is over */
            if (Pfn1->u3.e2.ReferenceCount == 0)
            {
                MMPTE OriginalPte = Pfn1->OriginalPte;

                /* And it should be in standby or modified list */
                ASSERT((Pfn1->u3.e1.PageLocation == ModifiedPageList) || (Pfn1->u3.e1.PageLocation == StandbyPageList));

                /* Unlink it and set its reference count to one; a clean copy's slot goes with the free (NitroPager) */
                MiUnlinkPageFromList(Pfn1);
                Pfn1->OriginalPte = OriginalPte;
                Pfn1->u3.e2.ReferenceCount++;

                /* This will put it back in free list and clean properly up */
                MiDecrementReferenceCount(Pfn1, PageFrameIndex);
            }
            return FALSE;
        }
    }

    /* Get the PFN entry */
    PageFrameIndex = PFN_FROM_PTE(&TempPte);
    Pfn1 = MiGetPfnEntry(PageFrameIndex);

    /* Check if this is a valid, prototype PTE */
    if (Pfn1->u3.e1.PrototypePte == 1)
    {
        /* Get the PDE and make sure it's faulted in */
        PointerPde = MiPteToPde(PointerPte);
        if (PointerPde->u.Hard.Valid == 0)
        {
#if (_MI_PAGING_LEVELS == 2)
            /* Could be paged pool access from a new process -- synchronize the page directories */
            if (!NT_SUCCESS(MiCheckPdeForPagedPool(VirtualAddress)))
            {
#endif
                /* The PDE must be valid at this point */
                KeBugCheckEx(MEMORY_MANAGEMENT,
                             0x61940,
                             (ULONG_PTR)PointerPte,
                             PointerPte->u.Long,
                             (ULONG_PTR)VirtualAddress);
            }
#if (_MI_PAGING_LEVELS == 2)
        }
#endif
        /* Drop the share count on the page table */
        PointerPde = MiPteToPde(PointerPte);
        MiDecrementShareCount(MiGetPfnEntry(PointerPde->u.Hard.PageFrameNumber),
            PointerPde->u.Hard.PageFrameNumber);

        /*
         * A VirtualLock on a page of a section view goes with the last mapping of the
         * page: its lock reference would otherwise keep the page, and with it the
         * segment's prototype PTE page, in use after the segment is freed.
         */
        if (Pfn1->u2.ShareCount == 1)
            MiDropVirtualLock(Pfn1);

        /* Drop the share count, which may make the page reusable from the standby list */
        if (KeepShare)
            *KeepShare = Pfn1;
        else
            MiDecrementShareCount(Pfn1, PageFrameIndex);

        /* Either a fork, or this is the shared user data page */
        if ((PointerPte <= MiHighestUserPte) && (PrototypePte != Pfn1->PteAddress))
        {
            /* If it's not the shared user page, then crash, since there's no fork() yet */
            if ((PAGE_ALIGN(VirtualAddress) != (PVOID)USER_SHARED_DATA) ||
                 (MmHighestUserAddress <= (PVOID)USER_SHARED_DATA))
            {
                /* Must be some sort of memory corruption */
                KeBugCheckEx(MEMORY_MANAGEMENT,
                             0x400,
                             (ULONG_PTR)PointerPte,
                             (ULONG_PTR)PrototypePte,
                             (ULONG_PTR)Pfn1->PteAddress);
            }
        }

        /* Erase it */
        MI_ERASE_PTE(PointerPte);
    }
    else
    {
        /* Make sure the saved PTE address is valid */
        if ((PMMPTE)((ULONG_PTR)Pfn1->PteAddress & ~0x1) != PointerPte)
        {
            /* The PFN entry is illegal, or invalid */
            KeBugCheckEx(MEMORY_MANAGEMENT,
                         0x401,
                         (ULONG_PTR)PointerPte,
                         PointerPte->u.Long,
                         (ULONG_PTR)Pfn1->PteAddress);
        }

        /* Erase the PTE */
        MI_ERASE_PTE(PointerPte);

        /* There should only be 1 shared reference count */
        ASSERT(Pfn1->u2.ShareCount == 1);

        /* Drop the reference on the page table. */
        MiDecrementShareCount(MiGetPfnEntry(Pfn1->u4.PteFrame), Pfn1->u4.PteFrame);

        /* Mark the PFN for deletion and dereference what should be the last ref */
        MI_SET_PFN_DELETED(Pfn1);
        MiDropVirtualLock(Pfn1);
        if (KeepShare)
            *KeepShare = Pfn1;
        else
            MiDecrementShareCount(Pfn1, PageFrameIndex);

        /* We should eventually do this */
        //CurrentProcess->NumberOfPrivatePages--;
    }

    return TRUE;
}

/* The flush and the last share reference go to the deferred list, if there is one */
BOOLEAN
NTAPI
MiDeletePteDeferred(IN PMMPTE PointerPte,
                    IN PVOID VirtualAddress,
                    IN PEPROCESS CurrentProcess,
                    IN PMMPTE PrototypePte,
                    IN OUT PMI_DEFERRED_RELEASE Deferred OPTIONAL)
{
    PMMPFN Pfn1;

    if (!Deferred)
        return MiDeletePteCommon(PointerPte, VirtualAddress, CurrentProcess, PrototypePte, NULL);

    if (!MiDeletePteCommon(PointerPte, VirtualAddress, CurrentProcess, PrototypePte, &Pfn1))
        return FALSE;

    if (Pfn1)
        MiDeferShareRelease(Deferred, Pfn1, FALSE);
    MiDeferTbFlush(Deferred, VirtualAddress);
    return TRUE;
}

/*
 * Copy-on-write: replace a valid PTE that maps a shared page with a fresh private
 * page, waiting for the TB flush with the PFN lock released. The caller holds the
 * working set lock, which keeps faults off the PTE meanwhile, and the PFN lock,
 * which is held again on return. The new page is initialized before the lock is
 * released, so it cannot be taken; the shared page keeps its share reference until
 * no processor can reach it. No list, so this is cheap on the fault path's stack.
 */
KIRQL
NTAPI
MiReplaceSharedPte(IN PMMPTE PointerPte,
                   IN PVOID VirtualAddress,
                   IN PEPROCESS CurrentProcess,
                   IN PMMPTE PrototypePte,
                   IN PFN_NUMBER NewPageFrameIndex,
                   IN KIRQL OldIrql)
{
    PMMPFN SharedPfn;
    BOOLEAN Flush;

    Flush = MiDeletePteCommon(PointerPte, VirtualAddress, CurrentProcess, PrototypePte, &SharedPfn);
    ASSERT(Flush);
    MiInitializePfn(NewPageFrameIndex, PointerPte, TRUE);

    MiReleasePfnLock(OldIrql);
    if (Flush)
        KeFlushSingleTb(VirtualAddress, TRUE);
    OldIrql = MiAcquirePfnLock();

    /* The PTE is still empty and the new page still ours: nothing else can touch either */
    ASSERT(PointerPte->u.Long == 0);
    if (SharedPfn)
        MiDecrementShareCount(SharedPfn, MiGetPfnEntryIndex(SharedPfn));
    return OldIrql;
}

VOID
NTAPI
MiDeletePte(IN PMMPTE PointerPte,
            IN PVOID VirtualAddress,
            IN PEPROCESS CurrentProcess,
            IN PMMPTE PrototypePte)
{
    if (MiDeletePteDeferred(PointerPte, VirtualAddress, CurrentProcess, PrototypePte, NULL))
        KeFlushEntireTb(TRUE, TRUE);
}

VOID
NTAPI
MiDeleteVirtualAddresses(
    _In_ ULONG_PTR Va,
    _In_ ULONG_PTR EndingAddress,
    _In_opt_ PMMVAD Vad)
{
    PMMPTE PointerPte, PrototypePte, LastPrototypePte;
    PMMPDE PointerPde;
#if (_MI_PAGING_LEVELS >= 3)
    PMMPPE PointerPpe;
#endif
#if (_MI_PAGING_LEVELS >= 4)
    PMMPPE PointerPxe;
#endif
    MMPTE TempPte;
    PEPROCESS CurrentProcess;
    KIRQL OldIrql;
    BOOLEAN AddressGap = FALSE;
    PSUBSECTION Subsection;
    MI_DEFERRED_RELEASE Deferred;

    /* We should never get RosMm memory areas here */
    ASSERT((Vad == NULL) || !MI_IS_MEMORY_AREA_VAD(Vad));

    /*
     * The PTEs are cleared under the PFN lock, the TB is flushed without it, and
     * the pages are released under it again. The working set lock, held by the
     * caller throughout, keeps faults off the range in between. User addresses
     * are cached only by the processors running the current process.
     */
    MiInitializeDeferredRelease(&Deferred,
                                Va > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS,
                                ((EndingAddress - Va) >> PAGE_SHIFT) + 1);

    /* Get the current process */
    CurrentProcess = PsGetCurrentProcess();

    /* Check if this is a section VAD or a VM VAD */
    if (!(Vad) || (Vad->u.VadFlags.PrivateMemory) || !(Vad->FirstPrototypePte))
    {
        /* Don't worry about prototypes */
        PrototypePte = LastPrototypePte = NULL;
    }
    else
    {
        /* Get the prototype PTE */
        PrototypePte = Vad->FirstPrototypePte;
        LastPrototypePte = Vad->FirstPrototypePte + 1;
    }

    /* In all cases, we don't support fork() yet */
    ASSERT(CurrentProcess->CloneRoot == NULL);

    /* Loop the PTE for each VA (EndingAddress is inclusive!) */
    while (Va <= EndingAddress)
    {
#if (_MI_PAGING_LEVELS >= 4)
        /* Get the PXE and check if it's valid */
        PointerPxe = MiAddressToPxe((PVOID)Va);
        if (!PointerPxe->u.Hard.Valid)
        {
            /* Check for unmapped range and skip it */
            if (!PointerPxe->u.Long)
            {
                /* There are gaps in the address space */
                AddressGap = TRUE;

                /* Update Va and continue looping */
                Va = (ULONG_PTR)MiPxeToAddress(PointerPxe + 1);
                continue;
            }

            /* Making it valid can drop the working set lock: flush first */
            MiCompleteDeferredRelease(&Deferred);
            MiMakeSystemAddressValid(MiPteToAddress(PointerPxe), CurrentProcess);
        }
#endif
#if (_MI_PAGING_LEVELS >= 3)
        /* Get the PPE and check if it's valid */
        PointerPpe = MiAddressToPpe((PVOID)Va);
        if (!PointerPpe->u.Hard.Valid)
        {
            /* Check for unmapped range and skip it */
            if (!PointerPpe->u.Long)
            {
                /* There are gaps in the address space */
                AddressGap = TRUE;

                /* Update Va and continue looping */
                Va = (ULONG_PTR)MiPpeToAddress(PointerPpe + 1);
                continue;
            }

            /* Making it valid can drop the working set lock: flush first */
            MiCompleteDeferredRelease(&Deferred);
            MiMakeSystemAddressValid(MiPteToAddress(PointerPpe), CurrentProcess);
        }
#endif
        /* Skip invalid PDEs */
        PointerPde = MiAddressToPde((PVOID)Va);
        if (!PointerPde->u.Long)
        {
            /* There are gaps in the address space */
            AddressGap = TRUE;

            /* Check if all the PDEs are invalid, so there's nothing to free */
            Va = (ULONG_PTR)MiPdeToAddress(PointerPde + 1);
            continue;
        }

        /* Now check if the PDE is mapped in */
        if (!PointerPde->u.Hard.Valid)
        {
            /* It isn't, so map it in; that can drop the working set lock: flush first */
            MiCompleteDeferredRelease(&Deferred);
            PointerPte = MiPteToAddress(PointerPde);
            MiMakeSystemAddressValid(PointerPte, CurrentProcess);
        }

        /* Now we should have a valid PDE, mapped in, and still have some VA */
        ASSERT(PointerPde->u.Hard.Valid == 1);
        ASSERT(Va <= EndingAddress);

        /* Check if this is a section VAD with gaps in it */
        if ((AddressGap) && (LastPrototypePte))
        {
            /* We need to skip to the next correct prototype PTE */
            PrototypePte = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, Va >> PAGE_SHIFT);

            /* And we need the subsection to skip to the next last prototype PTE */
            Subsection = MiLocateSubsection(Vad, Va >> PAGE_SHIFT);
            if (Subsection)
            {
                /* Found it! */
                LastPrototypePte = &Subsection->SubsectionBase[Subsection->PtesInSubsection];
            }
            else
            {
                /* No more subsections, we are done with prototype PTEs */
                PrototypePte = NULL;
            }
        }

        /* Lock the PFN Database while we delete the PTEs */
        OldIrql = MiAcquirePfnLock();
        PointerPte = MiAddressToPte(Va);
        do
        {
            /* Making sure the PDE is still valid */
            ASSERT(PointerPde->u.Hard.Valid == 1);

            /* Room for this PTE's page and the page tables it may empty */
            if (MiDeferredReleaseRoom(&Deferred) < 1 + MI_DEFERRED_PDE_ENTRIES)
                OldIrql = MiCompleteDeferredReleaseLocked(&Deferred, OldIrql);

            /* Capture the PDE and make sure it exists */
            TempPte = *PointerPte;
            if (TempPte.u.Long)
            {
                /* Check if the PTE is actually mapped in */
                if (MI_IS_MAPPED_PTE(&TempPte))
                {
                    /* Are we dealing with section VAD? */
                    if ((LastPrototypePte) && (PrototypePte > LastPrototypePte))
                    {
                        /* We need to skip to the next correct prototype PTE */
                        PrototypePte = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, Va >> PAGE_SHIFT);

                        /* And we need the subsection to skip to the next last prototype PTE */
                        Subsection = MiLocateSubsection(Vad, Va >> PAGE_SHIFT);
                        if (Subsection)
                        {
                            /* Found it! */
                            LastPrototypePte = &Subsection->SubsectionBase[Subsection->PtesInSubsection];
                        }
                        else
                        {
                            /* No more subsections, we are done with prototype PTEs */
                            PrototypePte = NULL;
                        }
                    }

                    /* Check for a user mapping of a locked MDL */
                    if ((Vad) && (Vad->u.VadFlags.VadType == VadDevicePhysicalMemory))
                    {
                        /* The page belongs to the MDL owner, and might not even have
                         * a PFN entry: only drop the page table share count that
                         * MiMapLockedPagesInUserSpace took for this PTE. */
                        ASSERT(TempPte.u.Hard.Valid == 1);
                        MI_ERASE_PTE(PointerPte);
                        MiDecrementShareCount(MiGetPfnEntry(PointerPde->u.Hard.PageFrameNumber),
                                              PointerPde->u.Hard.PageFrameNumber);
                        MiDeferTbFlush(&Deferred, (PVOID)Va);
                    }
                    /* Check for prototype PTE */
                    else if ((TempPte.u.Hard.Valid == 0) &&
                             (TempPte.u.Soft.Prototype == 1))
                    {
                        /* Just nuke it */
                        MI_ERASE_PTE(PointerPte);
                    }
                    else
                    {
                        /* Delete the PTE proper, the page is released after the flush */
                        MiDeletePteDeferred(PointerPte,
                                            (PVOID)Va,
                                            CurrentProcess,
                                            PrototypePte,
                                            &Deferred);
                    }
                }
                else
                {
                    /* The PTE was never mapped, just nuke it here */
                    MI_ERASE_PTE(PointerPte);
                }

                if (MiDecrementPageTableReferences((PVOID)Va) == 0)
                {
                    ASSERT(PointerPde->u.Long != 0);

                    /* Delete the PDE proper, its page tables are released after the flush */
                    MiDeletePdeDeferred(PointerPde, CurrentProcess, &Deferred);

                    /* Continue with the next PDE */
                    Va = (ULONG_PTR)MiPdeToAddress(PointerPde + 1);

                    /* Use this to detect address gaps */
                    PointerPte++;

                    PrototypePte++;
                    break;
                }
            }

            /* Update the address and PTE for it */
            Va += PAGE_SIZE;
            PointerPte++;
            PrototypePte++;
        } while ((Va & (PDE_MAPPED_VA - 1)) && (Va <= EndingAddress));

        /* Release the lock, the pages stay referenced until the flush */
        MiReleasePfnLock(OldIrql);

        if (Va > EndingAddress) break;

        /* Check if we exited the loop regularly */
        AddressGap = (PointerPte != MiAddressToPte(Va));
    }

    /* Flush before the caller can release the working set lock or return */
    MiCompleteDeferredRelease(&Deferred);
    MiCleanupDeferredRelease(&Deferred);
}

LONG
MiGetExceptionInfo(IN PEXCEPTION_POINTERS ExceptionInfo,
                   OUT PBOOLEAN HaveBadAddress,
                   OUT PULONG_PTR BadAddress)
{
    PEXCEPTION_RECORD ExceptionRecord;
    PAGED_CODE();

    //
    // Assume default
    //
    *HaveBadAddress = FALSE;

    //
    // Get the exception record
    //
    ExceptionRecord = ExceptionInfo->ExceptionRecord;

    //
    // Look at the exception code
    //
    if ((ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) ||
        (ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) ||
        (ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR))
    {
        //
        // We can tell the address if we have more than one parameter
        //
        if (ExceptionRecord->NumberParameters > 1)
        {
            //
            // Return the address
            //
            *HaveBadAddress = TRUE;
            *BadAddress = ExceptionRecord->ExceptionInformation[1];
        }
    }

    //
    // Continue executing the next handler
    //
    return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS
NTAPI
MiDoMappedCopy(IN PEPROCESS SourceProcess,
               IN PVOID SourceAddress,
               IN PEPROCESS TargetProcess,
               OUT PVOID TargetAddress,
               IN SIZE_T BufferSize,
               IN KPROCESSOR_MODE PreviousMode,
               OUT PSIZE_T ReturnSize)
{
    PFN_NUMBER MdlBuffer[(sizeof(MDL) / sizeof(PFN_NUMBER)) + MI_MAPPED_COPY_PAGES + 1];
    PMDL Mdl = (PMDL)MdlBuffer;
    SIZE_T TotalSize, CurrentSize, RemainingSize;
    volatile BOOLEAN FailedInProbe = FALSE;
    volatile BOOLEAN PagesLocked = FALSE;
    PVOID CurrentAddress = SourceAddress, CurrentTargetAddress = TargetAddress;
    volatile PVOID MdlAddress = NULL;
    KAPC_STATE ApcState;
    BOOLEAN HaveBadAddress;
    ULONG_PTR BadAddress;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    //
    // Calculate the maximum amount of data to move
    //
    TotalSize = MI_MAPPED_COPY_PAGES * PAGE_SIZE;
    if (BufferSize <= TotalSize) TotalSize = BufferSize;
    CurrentSize = TotalSize;
    RemainingSize = BufferSize;

    //
    // Loop as long as there is still data
    //
    while (RemainingSize > 0)
    {
        //
        // Check if this transfer will finish everything off
        //
        if (RemainingSize < CurrentSize) CurrentSize = RemainingSize;

        //
        // Attach to the source address space
        //
        KeStackAttachProcess(&SourceProcess->Pcb, &ApcState);

        //
        // Check state for this pass
        //
        ASSERT(MdlAddress == NULL);
        ASSERT(PagesLocked == FALSE);
        ASSERT(FailedInProbe == FALSE);

        //
        // Protect user-mode copy
        //
        _SEH2_TRY
        {
            //
            // If this is our first time, probe the buffer
            //
            if ((CurrentAddress == SourceAddress) && (PreviousMode != KernelMode))
            {
                //
                // Catch a failure here
                //
                FailedInProbe = TRUE;

                //
                // Do the probe
                //
                ProbeForRead(SourceAddress, BufferSize, sizeof(CHAR));

                //
                // Passed
                //
                FailedInProbe = FALSE;
            }

            //
            // Initialize and probe and lock the MDL
            //
            MmInitializeMdl(Mdl, CurrentAddress, CurrentSize);
            MmProbeAndLockPages(Mdl, PreviousMode, IoReadAccess);
            PagesLocked = TRUE;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END

        /* Detach from source process */
        KeUnstackDetachProcess(&ApcState);

        if (Status != STATUS_SUCCESS)
        {
            goto Exit;
        }

        //
        // Now map the pages
        //
        MdlAddress = MmMapLockedPagesSpecifyCache(Mdl,
                                                  KernelMode,
                                                  MmCached,
                                                  NULL,
                                                  FALSE,
                                                  HighPagePriority);
        if (!MdlAddress)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        //
        // Grab to the target process
        //
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);

        _SEH2_TRY
        {
            //
            // Check if this is our first time through
            //
            if ((CurrentTargetAddress == TargetAddress) && (PreviousMode != KernelMode))
            {
                //
                // Catch a failure here
                //
                FailedInProbe = TRUE;

                //
                // Do the probe
                //
                ProbeForWrite(TargetAddress, BufferSize, sizeof(CHAR));

                //
                // Passed
                //
                FailedInProbe = FALSE;
            }

            //
            // Now do the actual move
            //
            RtlCopyMemory(CurrentTargetAddress, MdlAddress, CurrentSize);
        }
        _SEH2_EXCEPT(MiGetExceptionInfo(_SEH2_GetExceptionInformation(),
                                        &HaveBadAddress,
                                        &BadAddress))
        {
            *ReturnSize = BufferSize - RemainingSize;
            //
            // Check if we failed during the probe
            //
            if (FailedInProbe)
            {
                //
                // Exit
                //
                Status = _SEH2_GetExceptionCode();
            }
            else
            {
                //
                // Othewise we failed during the move.
                // Check if we know exactly where we stopped copying
                //
                if (HaveBadAddress)
                {
                    //
                    // Return the exact number of bytes copied
                    //
                    *ReturnSize = BadAddress - (ULONG_PTR)SourceAddress;
                }
                //
                // Return partial copy
                //
                Status = STATUS_PARTIAL_COPY;
            }
        }
        _SEH2_END;

        /* Detach from target process */
        KeUnstackDetachProcess(&ApcState);

        //
        // Check for SEH status
        //
        if (Status != STATUS_SUCCESS)
        {
            goto Exit;
        }

        //
        // Unmap and unlock
        //
        MmUnmapLockedPages(MdlAddress, Mdl);
        MdlAddress = NULL;
        MmUnlockPages(Mdl);
        PagesLocked = FALSE;

        //
        // Update location and size
        //
        RemainingSize -= CurrentSize;
        CurrentAddress = (PVOID)((ULONG_PTR)CurrentAddress + CurrentSize);
        CurrentTargetAddress = (PVOID)((ULONG_PTR)CurrentTargetAddress + CurrentSize);
    }

Exit:
    if (MdlAddress != NULL)
        MmUnmapLockedPages(MdlAddress, Mdl);
    if (PagesLocked)
        MmUnlockPages(Mdl);

    //
    // All bytes read
    //
    if (Status == STATUS_SUCCESS)
        *ReturnSize = BufferSize;
    return Status;
}

NTSTATUS
NTAPI
MiDoPoolCopy(IN PEPROCESS SourceProcess,
             IN PVOID SourceAddress,
             IN PEPROCESS TargetProcess,
             OUT PVOID TargetAddress,
             IN SIZE_T BufferSize,
             IN KPROCESSOR_MODE PreviousMode,
             OUT PSIZE_T ReturnSize)
{
    UCHAR StackBuffer[MI_POOL_COPY_BYTES];
    SIZE_T TotalSize, CurrentSize, RemainingSize;
    volatile BOOLEAN FailedInProbe = FALSE, HavePoolAddress = FALSE;
    PVOID CurrentAddress = SourceAddress, CurrentTargetAddress = TargetAddress;
    PVOID PoolAddress;
    KAPC_STATE ApcState;
    BOOLEAN HaveBadAddress;
    ULONG_PTR BadAddress;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    DPRINT("Copying %Iu bytes from process %p (address %p) to process %p (Address %p)\n",
        BufferSize, SourceProcess, SourceAddress, TargetProcess, TargetAddress);

    //
    // Calculate the maximum amount of data to move
    //
    TotalSize = MI_MAX_TRANSFER_SIZE;
    if (BufferSize <= MI_MAX_TRANSFER_SIZE) TotalSize = BufferSize;
    CurrentSize = TotalSize;
    RemainingSize = BufferSize;

    //
    // Check if we can use the stack
    //
    if (BufferSize <= MI_POOL_COPY_BYTES)
    {
        //
        // Use it
        //
        PoolAddress = (PVOID)StackBuffer;
    }
    else
    {
        //
        // Allocate pool
        //
        PoolAddress = ExAllocatePoolWithTag(NonPagedPool, TotalSize, 'VmRw');
        if (!PoolAddress) ASSERT(FALSE);
        HavePoolAddress = TRUE;
    }

    //
    // Loop as long as there is still data
    //
    while (RemainingSize > 0)
    {
        //
        // Check if this transfer will finish everything off
        //
        if (RemainingSize < CurrentSize) CurrentSize = RemainingSize;

        //
        // Attach to the source address space
        //
        KeStackAttachProcess(&SourceProcess->Pcb, &ApcState);

        /* Check that state is sane */
        ASSERT(FailedInProbe == FALSE);
        ASSERT(Status == STATUS_SUCCESS);

        //
        // Protect user-mode copy
        //
        _SEH2_TRY
        {
            //
            // If this is our first time, probe the buffer
            //
            if ((CurrentAddress == SourceAddress) && (PreviousMode != KernelMode))
            {
                //
                // Catch a failure here
                //
                FailedInProbe = TRUE;

                //
                // Do the probe
                //
                ProbeForRead(SourceAddress, BufferSize, sizeof(CHAR));

                //
                // Passed
                //
                FailedInProbe = FALSE;
            }

            //
            // Do the copy
            //
            RtlCopyMemory(PoolAddress, CurrentAddress, CurrentSize);
        }
        _SEH2_EXCEPT(MiGetExceptionInfo(_SEH2_GetExceptionInformation(),
                                        &HaveBadAddress,
                                        &BadAddress))
        {
            *ReturnSize = BufferSize - RemainingSize;

            //
            // Check if we failed during the probe
            //
            if (FailedInProbe)
            {
                //
                // Exit
                //
                Status = _SEH2_GetExceptionCode();
            }
            else
            {
                //
                // We failed during the move.
                // Check if we know exactly where we stopped copying
                //
                if (HaveBadAddress)
                {
                    //
                    // Return the exact number of bytes copied
                    //
                    *ReturnSize = BadAddress - (ULONG_PTR)SourceAddress;
                }
                //
                // Return partial copy
                //
                Status = STATUS_PARTIAL_COPY;
            }
        }
        _SEH2_END

        /* Let go of the source */
        KeUnstackDetachProcess(&ApcState);

        if (Status != STATUS_SUCCESS)
        {
            goto Exit;
        }

        /* Grab the target process */
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);

        _SEH2_TRY
        {
            //
            // Check if this is our first time through
            //
            if ((CurrentTargetAddress == TargetAddress) && (PreviousMode != KernelMode))
            {
                //
                // Catch a failure here
                //
                FailedInProbe = TRUE;

                //
                // Do the probe
                //
                ProbeForWrite(TargetAddress, BufferSize, sizeof(CHAR));

                //
                // Passed
                //
                FailedInProbe = FALSE;
            }

            //
            // Now do the actual move
            //
            RtlCopyMemory(CurrentTargetAddress, PoolAddress, CurrentSize);
        }
        _SEH2_EXCEPT(MiGetExceptionInfo(_SEH2_GetExceptionInformation(),
                                        &HaveBadAddress,
                                        &BadAddress))
        {
            *ReturnSize = BufferSize - RemainingSize;
            //
            // Check if we failed during the probe
            //
            if (FailedInProbe)
            {
                //
                // Exit
                //
                Status = _SEH2_GetExceptionCode();
            }
            else
            {
                //
                // Otherwise we failed during the move.
                // Check if we know exactly where we stopped copying
                //
                if (HaveBadAddress)
                {
                    //
                    // Return the exact number of bytes copied
                    //
                    *ReturnSize = BadAddress - (ULONG_PTR)SourceAddress;
                }
                //
                // Return partial copy
                //
                Status = STATUS_PARTIAL_COPY;
            }
        }
        _SEH2_END;

        //
        // Detach from target
        //
        KeUnstackDetachProcess(&ApcState);

        //
        // Check for SEH status
        //
        if (Status != STATUS_SUCCESS)
        {
            goto Exit;
        }

        //
        // Update location and size
        //
        RemainingSize -= CurrentSize;
        CurrentAddress = (PVOID)((ULONG_PTR)CurrentAddress + CurrentSize);
        CurrentTargetAddress = (PVOID)((ULONG_PTR)CurrentTargetAddress +
                                       CurrentSize);
    }

Exit:
    //
    // Check if we had allocated pool
    //
    if (HavePoolAddress)
        ExFreePoolWithTag(PoolAddress, 'VmRw');

    //
    // All bytes read
    //
    if (Status == STATUS_SUCCESS)
        *ReturnSize = BufferSize;
    return Status;
}

NTSTATUS
NTAPI
MmCopyVirtualMemory(IN PEPROCESS SourceProcess,
                    IN PVOID SourceAddress,
                    IN PEPROCESS TargetProcess,
                    OUT PVOID TargetAddress,
                    IN SIZE_T BufferSize,
                    IN KPROCESSOR_MODE PreviousMode,
                    OUT PSIZE_T ReturnSize)
{
    NTSTATUS Status;
    PEPROCESS Process = SourceProcess;

    //
    // Don't accept zero-sized buffers
    //
    if (!BufferSize) return STATUS_SUCCESS;

    //
    // If we are copying from ourselves, lock the target instead
    //
    if (SourceProcess == PsGetCurrentProcess()) Process = TargetProcess;

    //
    // Acquire rundown protection
    //
    if (!ExAcquireRundownProtection(&Process->RundownProtect))
    {
        //
        // Fail
        //
        return STATUS_PROCESS_IS_TERMINATING;
    }

    //
    // See if we should use the pool copy
    //
    if (BufferSize > MI_POOL_COPY_BYTES)
    {
        //
        // Use MDL-copy
        //
        Status = MiDoMappedCopy(SourceProcess,
                                SourceAddress,
                                TargetProcess,
                                TargetAddress,
                                BufferSize,
                                PreviousMode,
                                ReturnSize);
    }
    else
    {
        //
        // Do pool copy
        //
        Status = MiDoPoolCopy(SourceProcess,
                              SourceAddress,
                              TargetProcess,
                              TargetAddress,
                              BufferSize,
                              PreviousMode,
                              ReturnSize);
    }

    //
    // Release the lock
    //
    ExReleaseRundownProtection(&Process->RundownProtect);
    return Status;
}

NTSTATUS
NTAPI
MmFlushVirtualMemory(IN PEPROCESS Process,
                     IN OUT PVOID *BaseAddress,
                     IN OUT PSIZE_T RegionSize,
                     OUT PIO_STATUS_BLOCK IoStatusBlock)
{
    PAGED_CODE();

    UNIMPLEMENTED;

    // Report actual state.
    IoStatusBlock->Status = STATUS_NOT_IMPLEMENTED;
    IoStatusBlock->Information = 0;

    // Pretend success.
    return STATUS_SUCCESS; // STATUS_NOT_IMPLEMENTED
}

ULONG
NTAPI
MiGetPageProtection(IN PMMPTE PointerPte)
{
    MMPTE TempPte;
    PMMPFN Pfn;
    PEPROCESS CurrentProcess;
    PETHREAD CurrentThread;
    BOOLEAN WsSafe, WsShared;
    ULONG Protect;
    KIRQL OldIrql;
    PAGED_CODE();

    /* Copy this PTE's contents */
    TempPte = *PointerPte;

    /* Assure it's not totally zero */
    ASSERT(TempPte.u.Long);

    /* Check for a special prototype format */
    if ((TempPte.u.Soft.Valid == 0) &&
        (TempPte.u.Soft.Prototype == 1))
    {
        /* Check if the prototype PTE is not yet pointing to a PTE */
        if (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
        {
            /* The prototype PTE contains the protection */
            return MmProtectToValue[TempPte.u.Soft.Protection];
        }

        /* Get a pointer to the underlying shared PTE */
        PointerPte = MiProtoPteToPte(&TempPte);

        /* Since the PTE we want to read can be paged out at any time, we need
           to release the working set lock first, so that it can be paged in */
        CurrentThread = PsGetCurrentThread();
        CurrentProcess = PsGetCurrentProcess();
        MiUnlockProcessWorkingSetForFault(CurrentProcess,
                                          CurrentThread,
                                          &WsSafe,
                                          &WsShared);

        /* Now read the PTE value */
        TempPte = *PointerPte;

        /* Check if that one is invalid */
        if (!TempPte.u.Hard.Valid)
        {
            /* We get the protection directly from this PTE */
            Protect = MmProtectToValue[TempPte.u.Soft.Protection];
        }
        else
        {
            /* The PTE is valid, so we might need to get the protection from
               the PFN. Lock the PFN database */
            OldIrql = MiAcquirePfnLock();

            /* Check if the PDE is still valid */
            if (MiAddressToPte(PointerPte)->u.Hard.Valid == 0)
            {
                /* It's not, make it valid */
                MiMakeSystemAddressValidPfn(PointerPte, OldIrql);
            }

            /* Now it's safe to read the PTE value again */
            TempPte = *PointerPte;
            ASSERT(TempPte.u.Long != 0);

            /* Check again if the PTE is invalid */
            if (!TempPte.u.Hard.Valid)
            {
                /* The PTE is not valid, so we can use it's protection field */
                Protect = MmProtectToValue[TempPte.u.Soft.Protection];
            }
            else
            {
                /* The PTE is valid, so we can find the protection in the
                   OriginalPte field of the PFN */
                Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);
                Protect = MmProtectToValue[Pfn->OriginalPte.u.Soft.Protection];
            }

            /* Release the PFN database */
            MiReleasePfnLock(OldIrql);
        }

        /* Lock the working set again */
        MiLockProcessWorkingSetForFault(CurrentProcess,
                                        CurrentThread,
                                        WsSafe,
                                        WsShared);

        return Protect;
    }

    /* In the easy case of transition or demand zero PTE just return its protection */
    if (!TempPte.u.Hard.Valid) return MmProtectToValue[TempPte.u.Soft.Protection];

    /* If we get here, the PTE is valid, so look up the page in PFN database */
    Pfn = MiGetPfnEntry(TempPte.u.Hard.PageFrameNumber);
    if (!Pfn->u3.e1.PrototypePte)
    {
        /* Return protection of the original pte */
        ASSERT(Pfn->u4.AweAllocation == 0);
        return MmProtectToValue[Pfn->OriginalPte.u.Soft.Protection];
    }

    /* This is software PTE */
    DPRINT("Prototype PTE: %lx %p\n", TempPte.u.Hard.PageFrameNumber, Pfn);
    DPRINT("VA: %p\n", MiPteToAddress(&TempPte));
    DPRINT("Mask: %lx\n", TempPte.u.Soft.Protection);
    DPRINT("Mask2: %lx\n", Pfn->OriginalPte.u.Soft.Protection);
    return MmProtectToValue[TempPte.u.Soft.Protection];
}

ULONG
NTAPI
MiQueryAddressState(IN PVOID Va,
                    IN PMMVAD Vad,
                    IN PEPROCESS TargetProcess,
                    OUT PULONG ReturnedProtect,
                    OUT PVOID *NextVa)
{

    PMMPTE PointerPte, ProtoPte;
    PMMPDE PointerPde;
#if (_MI_PAGING_LEVELS >= 3)
    PMMPPE PointerPpe;
#endif
#if (_MI_PAGING_LEVELS >= 4)
    PMMPXE PointerPxe;
#endif
    MMPTE TempPte, TempProtoPte;
    BOOLEAN DemandZeroPte = TRUE, ValidPte = FALSE;
    ULONG State = MEM_RESERVE, Protect = 0;
    ASSERT((Vad->StartingVpn <= ((ULONG_PTR)Va >> PAGE_SHIFT)) &&
           (Vad->EndingVpn >= ((ULONG_PTR)Va >> PAGE_SHIFT)));

    /* Only normal VADs supported */
    ASSERT(Vad->u.VadFlags.VadType == VadNone);

    /* Get the PDE and PTE for the address */
    PointerPde = MiAddressToPde(Va);
    PointerPte = MiAddressToPte(Va);
#if (_MI_PAGING_LEVELS >= 3)
    PointerPpe = MiAddressToPpe(Va);
#endif
#if (_MI_PAGING_LEVELS >= 4)
    PointerPxe = MiAddressToPxe(Va);
#endif

    /* Return the next range */
    *NextVa = (PVOID)((ULONG_PTR)Va + PAGE_SIZE);

    do
    {
#if (_MI_PAGING_LEVELS >= 4)
        /* Does the PXE exist? */
        if (PointerPxe->u.Long == 0)
        {
            /* It does not, next range starts at the next PXE */
            *NextVa = MiPxeToAddress(PointerPxe + 1);
            break;
        }

        /* Is the PXE valid? */
        if (PointerPxe->u.Hard.Valid == 0)
        {
            /* Is isn't, fault it in (make the PPE accessible) */
            MiMakeSystemAddressValid(PointerPpe, TargetProcess);
        }
#endif
#if (_MI_PAGING_LEVELS >= 3)
        /* Does the PPE exist? */
        if (PointerPpe->u.Long == 0)
        {
            /* It does not, next range starts at the next PPE */
            *NextVa = MiPpeToAddress(PointerPpe + 1);
            break;
        }

        /* Is the PPE valid? */
        if (PointerPpe->u.Hard.Valid == 0)
        {
            /* Is isn't, fault it in (make the PDE accessible) */
            MiMakeSystemAddressValid(PointerPde, TargetProcess);
        }
#endif

        /* Does the PDE exist? */
        if (PointerPde->u.Long == 0)
        {
            /* It does not, next range starts at the next PDE */
            *NextVa = MiPdeToAddress(PointerPde + 1);
            break;
        }

        /* Is the PDE valid? */
        if (PointerPde->u.Hard.Valid == 0)
        {
            /* Is isn't, fault it in (make the PTE accessible) */
            MiMakeSystemAddressValid(PointerPte, TargetProcess);
        }

        /* We have a PTE that we can access now! */
        ValidPte = TRUE;

    } while (FALSE);

    /* Is it safe to try reading the PTE? */
    if (ValidPte)
    {
        /* FIXME: watch out for large pages */
        ASSERT(PointerPde->u.Hard.LargePage == FALSE);

        /* Capture the PTE */
        TempPte = *PointerPte;
        if (TempPte.u.Long != 0)
        {
            /* The PTE is valid, so it's not zeroed out */
            DemandZeroPte = FALSE;

            /* Is it a decommited, invalid, or faulted PTE? */
            if ((TempPte.u.Soft.Protection == MM_DECOMMIT) &&
                (TempPte.u.Hard.Valid == 0) &&
                ((TempPte.u.Soft.Prototype == 0) ||
                 (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)))
            {
                /* Otherwise our defaults should hold */
                ASSERT(Protect == 0);
                ASSERT(State == MEM_RESERVE);
            }
            else
            {
                /* This means it's committed */
                State = MEM_COMMIT;

                /* We don't support these */
                ASSERT(Vad->u.VadFlags.VadType != VadDevicePhysicalMemory);
                ASSERT(Vad->u.VadFlags.VadType != VadRotatePhysical);
                ASSERT(Vad->u.VadFlags.VadType != VadAwe);

                /* Get protection state of this page */
                Protect = MiGetPageProtection(PointerPte);

                /* A resident page of a section view (not private memory) keeps the protection of the view, whatever
                 * the hardware PTE says: a read fault maps it read-only and a write dirties it. Only a page that
                 * copy-on-write replaced by a private copy changed, to the writable form (Windows 10 22H2 measured). */
                if (TempPte.u.Hard.Valid && !Vad->u.VadFlags.PrivateMemory && Vad->ControlArea)
                {
                    PMMPFN SectionPfn = MiGetPfnEntry(TempPte.u.Hard.PageFrameNumber);
                    ULONG ViewProtect = Vad->u.VadFlags.Protection;

                    if (SectionPfn)
                    {
                        if (!SectionPfn->u3.e1.PrototypePte && ((ViewProtect & 5) == MM_WRITECOPY))
                            ViewProtect &= ~1;
                        Protect = MmProtectToValue[ViewProtect];
                    }
                }

                /* Check if this PTE points to a prototype PTE of a section */
                if ((TempPte.u.Soft.Valid == 0) &&
                    (TempPte.u.Soft.Prototype == 1) &&
                    (Vad->u.VadFlags.PrivateMemory == 0) &&
                    (Vad->ControlArea))
                {
                    /* Get the prototype PTE, which holds the real state */
                    if (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
                    {
                        ProtoPte = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad,
                                                                (ULONG_PTR)Va >> PAGE_SHIFT);
                    }
                    else
                    {
                        ProtoPte = MiProtoPteToPte(&TempPte);
                    }

                    /* An empty prototype PTE is a reserved page, for example
                       an uncommitted page of a SEC_RESERVE view that was
                       accessed. Like the demand-zero path below, this reads
                       the paged prototype PTE with the working set lock held */
                    if (!ProtoPte->u.Long)
                    {
                        State = MEM_RESERVE;
                        Protect = 0;
                    }
                }
            }
        }
    }

    /* Check if this was a demand-zero PTE, since we need to find the state */
    if (DemandZeroPte)
    {
        /* Not yet handled */
        ASSERT(Vad->u.VadFlags.VadType != VadDevicePhysicalMemory);
        ASSERT(Vad->u.VadFlags.VadType != VadAwe);

        /* Check if this is private commited memory, or an section-backed VAD */
        if ((Vad->u.VadFlags.PrivateMemory == 0) && (Vad->ControlArea))
        {
            /* Tell caller about the next range */
            *NextVa = (PVOID)((ULONG_PTR)Va + PAGE_SIZE);

            /* Get the prototype PTE for this VAD */
            ProtoPte = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad,
                                                    (ULONG_PTR)Va >> PAGE_SHIFT);
            if (ProtoPte)
            {
                /* We should unlock the working set, but it's not being held! */

                /* Is the prototype PTE actually valid (committed)? */
                TempProtoPte = *ProtoPte;
                if (TempProtoPte.u.Long)
                {
                    /* Unless this is a memory-mapped file, handle it like private VAD */
                    State = MEM_COMMIT;
                    ASSERT(Vad->u.VadFlags.VadType != VadImageMap);
                    Protect = MmProtectToValue[Vad->u.VadFlags.Protection];
                }

                /* We should re-lock the working set */
            }
        }
        else if (Vad->u.VadFlags.MemCommit)
        {
            /* This is committed memory */
            State = MEM_COMMIT;

            /* Convert the protection */
            Protect = MmProtectToValue[Vad->u.VadFlags.Protection];
        }
    }

    /* Return the protection code */
    *ReturnedProtect = Protect;
    return State;
}

static
NTSTATUS
MiReferenceProcessForQuery(IN HANDLE ProcessHandle,
                           IN KPROCESSOR_MODE PreviousMode,
                           OUT PEPROCESS *Process);

NTSTATUS
NTAPI
MiQueryMemoryBasicInformation(IN HANDLE ProcessHandle,
                              IN PVOID BaseAddress,
                              OUT PVOID MemoryInformation,
                              IN SIZE_T MemoryInformationLength,
                              OUT PSIZE_T ReturnLength)
{
    PEPROCESS TargetProcess;
    NTSTATUS Status = STATUS_SUCCESS;
    PMMVAD Vad = NULL;
    PVOID Address, NextAddress;
    BOOLEAN Found = FALSE;
    ULONG NewProtect, NewState;
    ULONG_PTR BaseVpn;
    MEMORY_BASIC_INFORMATION MemoryInfo;
    KAPC_STATE ApcState;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    SIZE_T ResultLength;

    /* Check for illegal addresses in user-space, or the shared memory area */
    if ((BaseAddress > MM_HIGHEST_VAD_ADDRESS) ||
        (PAGE_ALIGN(BaseAddress) == (PVOID)MM_SHARED_USER_DATA_VA))
    {
        Address = PAGE_ALIGN(BaseAddress);

        /* Make up an info structure describing this range */
        MemoryInfo.BaseAddress = Address;
        MemoryInfo.AllocationProtect = PAGE_READONLY;
        MemoryInfo.Type = MEM_PRIVATE;

        /* Special case for shared data */
        if (Address == (PVOID)MM_SHARED_USER_DATA_VA)
        {
            MemoryInfo.AllocationBase = (PVOID)MM_SHARED_USER_DATA_VA;
            MemoryInfo.State = MEM_COMMIT;
            MemoryInfo.Protect = PAGE_READONLY;
            MemoryInfo.RegionSize = PAGE_SIZE;
        }
        else
        {
            MemoryInfo.AllocationBase = (PCHAR)MM_HIGHEST_VAD_ADDRESS + 1;
            MemoryInfo.State = MEM_RESERVE;
            MemoryInfo.Protect = PAGE_NOACCESS;
            MemoryInfo.RegionSize = (ULONG_PTR)MM_HIGHEST_USER_ADDRESS + 1 - (ULONG_PTR)Address;
        }

        /* Return the data, NtQueryInformation already probed it*/
        if (PreviousMode != KernelMode)
        {
            _SEH2_TRY
            {
                *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;
                if (ReturnLength) *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
            }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }
        else
        {
            *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;
            if (ReturnLength) *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
        }

        return Status;
    }

    /* Check if this is for a local or remote process */
    if (ProcessHandle == NtCurrentProcess())
    {
        TargetProcess = PsGetCurrentProcess();
    }
    else
    {
        /* Reference the target process (PROCESS_QUERY_LIMITED_INFORMATION is enough on Windows,
         * for classes 0 and 8) */
        Status = MiReferenceProcessForQuery(ProcessHandle, PreviousMode, &TargetProcess);
        if (!NT_SUCCESS(Status)) return Status;

        /* Attach to it now */
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);
    }

    /* Lock the address space and make sure the process isn't already dead */
    MmLockAddressSpace(&TargetProcess->Vm);
    if (TargetProcess->VmDeleted)
    {
        /* Unlock the address space of the process */
        MmUnlockAddressSpace(&TargetProcess->Vm);

        /* Check if we were attached */
        if (ProcessHandle != NtCurrentProcess())
        {
            /* Detach and dereference the process */
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(TargetProcess);
        }

        /* Bail out */
        DPRINT1("Process is dying\n");
        return STATUS_PROCESS_IS_TERMINATING;
    }

    /* Loop the VADs */
    ASSERT(TargetProcess->VadRoot.NumberGenericTableElements);
    if (TargetProcess->VadRoot.NumberGenericTableElements)
    {
        /* Scan on the right */
        Vad = (PMMVAD)TargetProcess->VadRoot.BalancedRoot.RightChild;
        BaseVpn = (ULONG_PTR)BaseAddress >> PAGE_SHIFT;
        while (Vad)
        {
            /* Check if this VAD covers the allocation range */
            if ((BaseVpn >= Vad->StartingVpn) &&
                (BaseVpn <= Vad->EndingVpn))
            {
                /* We're done */
                Found = TRUE;
                break;
            }

            /* Check if this VAD is too high */
            if (BaseVpn < Vad->StartingVpn)
            {
                /* Stop if there is no left child */
                if (!Vad->LeftChild) break;

                /* Search on the left next */
                Vad = Vad->LeftChild;
            }
            else
            {
                /* Then this VAD is too low, keep searching on the right */
                ASSERT(BaseVpn > Vad->EndingVpn);

                /* Stop if there is no right child */
                if (!Vad->RightChild) break;

                /* Search on the right next */
                Vad = Vad->RightChild;
            }
        }
    }

    /* Was a VAD found? */
    if (!Found)
    {
        Address = PAGE_ALIGN(BaseAddress);

        /* Calculate region size */
        if (Vad)
        {
            if (Vad->StartingVpn >= BaseVpn)
            {
                /* Region size is the free space till the start of that VAD */
                MemoryInfo.RegionSize = (ULONG_PTR)(Vad->StartingVpn << PAGE_SHIFT) - (ULONG_PTR)Address;
            }
            else
            {
                /* Get the next VAD */
                Vad = (PMMVAD)MiGetNextNode((PMMADDRESS_NODE)Vad);
                if (Vad)
                {
                    /* Region size is the free space till the start of that VAD */
                    MemoryInfo.RegionSize = (ULONG_PTR)(Vad->StartingVpn << PAGE_SHIFT) - (ULONG_PTR)Address;
                }
                else
                {
                    /* Maximum possible region size with that base address */
                    MemoryInfo.RegionSize = (PCHAR)MM_HIGHEST_VAD_ADDRESS + 1 - (PCHAR)Address;
                }
            }
        }
        else
        {
            /* Maximum possible region size with that base address */
            MemoryInfo.RegionSize = (PCHAR)MM_HIGHEST_VAD_ADDRESS + 1 - (PCHAR)Address;
        }

        /* Unlock the address space of the process */
        MmUnlockAddressSpace(&TargetProcess->Vm);

        /* Check if we were attached */
        if (ProcessHandle != NtCurrentProcess())
        {
            /* Detach and dereference the process */
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(TargetProcess);
        }

        /* Build the rest of the initial information block */
        MemoryInfo.BaseAddress = Address;
        MemoryInfo.AllocationBase = NULL;
        MemoryInfo.AllocationProtect = 0;
        MemoryInfo.State = MEM_FREE;
        MemoryInfo.Protect = PAGE_NOACCESS;
        MemoryInfo.Type = 0;

        /* Return the data, NtQueryInformation already probed it*/
        if (PreviousMode != KernelMode)
        {
            _SEH2_TRY
            {
                *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;
                if (ReturnLength) *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
            }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }
        else
        {
            *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;
            if (ReturnLength) *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
        }

        return Status;
    }

    /* Set the correct memory type based on what kind of VAD this is */
    if ((Vad->u.VadFlags.PrivateMemory) ||
        (Vad->u.VadFlags.VadType == VadRotatePhysical))
    {
        MemoryInfo.Type = MEM_PRIVATE;
    }
    else if (Vad->u.VadFlags.VadType == VadImageMap)
    {
        MemoryInfo.Type = MEM_IMAGE;
    }
    else
    {
        MemoryInfo.Type = MEM_MAPPED;
    }

    /* Check if this is a RosMM VAD */
    if (MI_IS_ROSMM_VAD(Vad))
    {
        ASSERT(((PMEMORY_AREA)Vad)->Type == MEMORY_AREA_SECTION_VIEW);
        Status = MmQuerySectionView((PMEMORY_AREA)Vad, BaseAddress, &MemoryInfo, &ResultLength);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MmQuerySectionView failed. MemoryArea=%p (%p-%p), BaseAddress=%p\n",
                    Vad, Vad->StartingVpn, Vad->EndingVpn, BaseAddress);
            ASSERT(NT_SUCCESS(Status));
        }
    }
    else
    {
        /* Build the initial information block */
        Address = PAGE_ALIGN(BaseAddress);
        MemoryInfo.BaseAddress = Address;
        MemoryInfo.AllocationBase = (PVOID)(Vad->StartingVpn << PAGE_SHIFT);
        MemoryInfo.AllocationProtect = MmProtectToValue[Vad->u.VadFlags.Protection];

        /* Acquire the working set lock (shared is enough) */
        MiLockProcessWorkingSetShared(TargetProcess, PsGetCurrentThread());

        /* Find the largest chunk of memory which has the same state and protection mask */
        MemoryInfo.State = MiQueryAddressState(Address,
                                               Vad,
                                               TargetProcess,
                                               &MemoryInfo.Protect,
                                               &NextAddress);
        Address = NextAddress;
        while (((ULONG_PTR)Address >> PAGE_SHIFT) <= Vad->EndingVpn)
        {
            /* Keep going unless the state or protection mask changed */
            NewState = MiQueryAddressState(Address, Vad, TargetProcess, &NewProtect, &NextAddress);
            if ((NewState != MemoryInfo.State) || (NewProtect != MemoryInfo.Protect)) break;
            Address = NextAddress;
        }

        /* Release the working set lock */
        MiUnlockProcessWorkingSetShared(TargetProcess, PsGetCurrentThread());

        /* Check if we went outside of the VAD */
         if (((ULONG_PTR)Address >> PAGE_SHIFT) > Vad->EndingVpn)
         {
            /* Set the end of the VAD as the end address */
            Address = (PVOID)((Vad->EndingVpn + 1) << PAGE_SHIFT);
         }

        /* Now that we know the last VA address, calculate the region size */
        MemoryInfo.RegionSize = ((ULONG_PTR)Address - (ULONG_PTR)MemoryInfo.BaseAddress);
    }

    /* Unlock the address space of the process */
    MmUnlockAddressSpace(&TargetProcess->Vm);

    /* Check if we were attached */
    if (ProcessHandle != NtCurrentProcess())
    {
        /* Detach and dereference the process */
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(TargetProcess);
    }

    /* Return the data, NtQueryInformation already probed it */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;
            if (ReturnLength) *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
        }
         _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else
    {
        *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;
        if (ReturnLength) *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
    }

    /* All went well */
    DPRINT("Base: %p AllocBase: %p AllocProtect: %lx Protect: %lx "
            "State: %lx Type: %lx Size: %lx\n",
            MemoryInfo.BaseAddress, MemoryInfo.AllocationBase,
            MemoryInfo.AllocationProtect, MemoryInfo.Protect,
            MemoryInfo.State, MemoryInfo.Type, MemoryInfo.RegionSize);

    return Status;
}

/*
 * MemoryRegionInformation (class 3). Values measured on Windows 10 22H2 x64 and WoW64:
 * - RegionType holds the MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE value of the allocation, and
 *   0x08000000 for a view of a paging-file section (not the bit layout the SDK header suggests);
 * - RegionSize and CommitSize describe the whole allocation (the VAD), whatever the address in it;
 * - PartitionId is 0 and NodePreference is 0xFFFFFFFF;
 * - a short buffer gets the fields that fit completely, ReturnLength says how many bytes were
 *   written; the buffer must hold at least up to RegionSize.
 * TODO: placeholder VADs (feat/mm-placeholders) report no extra bit on Windows 10 22H2 (measured),
 * so nothing is needed for them; PageSize64K/large pages/AWE/physical views are not measured.
 */
#define MI_REGION_TYPE_PAGEFILE 0x08000000

NTSTATUS
NTAPI
MiQueryMemoryRegionInformation(IN HANDLE ProcessHandle,
                               IN PVOID BaseAddress,
                               OUT PVOID MemoryInformation,
                               IN SIZE_T MemoryInformationLength,
                               OUT PSIZE_T ReturnLength,
                               IN BOOLEAN Ex)
{
    PEPROCESS TargetProcess;
    NTSTATUS Status = STATUS_SUCCESS;
    PMMVAD Vad;
    MEMORY_REGION_INFORMATION Info;
    KAPC_STATE ApcState;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    SIZE_T Written;
    ULONG_PTR Start, End;

    if (ProcessHandle == NtCurrentProcess())
    {
        TargetProcess = PsGetCurrentProcess();
    }
    else
    {
        /* PROCESS_QUERY_LIMITED_INFORMATION is enough on Windows */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_QUERY_INFORMATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)&TargetProcess,
                                           NULL);
        if (Status == STATUS_ACCESS_DENIED)
        {
            Status = ObReferenceObjectByHandle(ProcessHandle,
                                               PROCESS_QUERY_LIMITED_INFORMATION,
                                               PsProcessType,
                                               PreviousMode,
                                               (PVOID*)&TargetProcess,
                                               NULL);
        }
        if (!NT_SUCCESS(Status)) return Status;

        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);
    }

    MmLockAddressSpace(&TargetProcess->Vm);
    if (TargetProcess->VmDeleted)
    {
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Done;
    }

    Vad = MiLocateAddress(BaseAddress);
    if (!Vad)
    {
        /* Free memory */
        Status = STATUS_INVALID_ADDRESS;
        goto Done;
    }

    RtlZeroMemory(&Info, sizeof(Info));
    Info.PartitionId = 0;
    Info.NodePreference = 0xFFFFFFFF;
    Start = Vad->StartingVpn << PAGE_SHIFT;
    End = (Vad->EndingVpn + 1) << PAGE_SHIFT;
    Info.AllocationBase = (PVOID)Start;
    Info.AllocationProtect = MmProtectToValue[Vad->u.VadFlags.Protection];

    if (MI_IS_ROSMM_VAD(Vad))
    {
        PMEMORY_AREA MemoryArea = (PMEMORY_AREA)Vad;
        PMM_SECTION_SEGMENT Segment = MemoryArea->SectionData.Segment;

        ASSERT(MemoryArea->Type == MEMORY_AREA_SECTION_VIEW);
        if (Vad->u.VadFlags.VadType == VadImageMap)
        {
            PMMVAD Next = Vad;
            SIZE_T CommitPages = 0;

            /* Same allocation base as MemoryBasicInformation; Windows reports PAGE_EXECUTE_WRITECOPY */
            Info.AllocationBase = (PVOID)(Start - Segment->Image.VirtualAddress);
            Info.AllocationProtect = PAGE_EXECUTE_WRITECOPY;
            Info.RegionType = MEM_IMAGE;

            /* RosMm maps an image as one VAD per section: the allocation is all of them, from the
             * headers (at the allocation base) up. */
            Next = MiLocateAddress(Info.AllocationBase);
            if (!Next) Next = Vad;
            End = Start;
            while (Next && MI_IS_ROSMM_VAD(Next) && (Next->u.VadFlags.VadType == VadImageMap))
            {
                PMEMORY_AREA Area = (PMEMORY_AREA)Next;

                if ((Area->SectionData.Segment->FileObject != Segment->FileObject) ||
                    (((Next->StartingVpn << PAGE_SHIFT) - Area->SectionData.Segment->Image.VirtualAddress) !=
                     (ULONG_PTR)Info.AllocationBase))
                {
                    break;
                }
                End = max(End, (Next->EndingVpn + 1) << PAGE_SHIFT);
                /* Windows only charges the writable sections of an image */
                if (Area->SectionData.Segment->Image.Characteristics & IMAGE_SCN_MEM_WRITE)
                    CommitPages += Area->SectionData.CommitCharge;
                Next = (PMMVAD)MiGetNextNode((PMMADDRESS_NODE)Next);
            }
            Info.CommitSize = CommitPages << PAGE_SHIFT;
        }
        else
        {
            Info.RegionType = Segment->FileObject ? MEM_MAPPED : MI_REGION_TYPE_PAGEFILE;
            Info.CommitSize = MemoryArea->SectionData.CommitCharge << PAGE_SHIFT;
        }
    }
    else if (Vad->u.VadFlags.PrivateMemory || (Vad->u.VadFlags.VadType == VadRotatePhysical))
    {
        Info.RegionType = MEM_PRIVATE;
        Info.CommitSize = (SIZE_T)Vad->u.VadFlags.CommitCharge << PAGE_SHIFT;
    }
    else
    {
        PMMVAD_LONG LongVad = (PMMVAD_LONG)Vad;

        Info.RegionType = (Vad->u.VadFlags.VadType == VadImageMap) ? MEM_IMAGE :
                          (LongVad->ControlArea && LongVad->ControlArea->FilePointer) ? MEM_MAPPED :
                          MI_REGION_TYPE_PAGEFILE;
    }
    Info.RegionSize = End - (ULONG_PTR)Info.AllocationBase;

Done:
    MmUnlockAddressSpace(&TargetProcess->Vm);
    if (ProcessHandle != NtCurrentProcess())
    {
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(TargetProcess);
    }
    if (!NT_SUCCESS(Status)) return Status;

    /* MemoryRegionInformationEx (class 7) is the same structure with RegionType as the bits of the SDK
     * header (Private 1, MappedDataFile 2, MappedImage 4, MappedPageFile 8), measured on Windows 10 22H2 */
    if (Ex)
    {
        switch (Info.RegionType)
        {
            case MEM_PRIVATE: Info.RegionType = 1; break;
            case MEM_MAPPED: Info.RegionType = 2; break;
            case MEM_IMAGE: Info.RegionType = 4; break;
            case MI_REGION_TYPE_PAGEFILE: Info.RegionType = 8; break;
            default: break;
        }
    }

    /* Whole fields only, from CommitSize on */
    Written = FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize);
    if (MemoryInformationLength >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
        Written = FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId);
    if (MemoryInformationLength >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, NodePreference))
        Written = FIELD_OFFSET(MEMORY_REGION_INFORMATION, NodePreference);
    if (MemoryInformationLength >= sizeof(Info)) Written = sizeof(Info);

    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            RtlCopyMemory(MemoryInformation, &Info, Written);
            if (ReturnLength) *ReturnLength = Written;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else
    {
        RtlCopyMemory(MemoryInformation, &Info, Written);
        if (ReturnLength) *ReturnLength = Written;
    }
    return Status;
}

/*
 * MemoryImageInformation (class 6) and MemoryWorkingSetExInformation (class 4), as measured on
 * Windows 10 22H2:
 * - Image: at least 0x18 bytes, 0x18 are written. For an address in an image view the base and
 *   size of the image are returned; any other mapped, private or stack address succeeds with
 *   zeros (flags are 0 for the images measured); a free address gives STATUS_INVALID_ADDRESS.
 * - WorkingSetEx: the buffer is an array of {VirtualAddress, attributes}; at least one entry
 *   (16 bytes) is needed, entries that fit completely are filled and ReturnLength is the length
 *   given. BaseAddress is only checked against the user range. A page that is not resident
 *   (free, reserved, committed but never touched, kernel address) gets 0; a resident one gets
 *   Valid, Win32Protection (the page protection), Priority 5, and for a mapped or image page
 *   Shared, ShareCount (the mapping count as for class 1) and SharedOriginal; a page of a view or image that is
 *   not resident has only Shared and SharedOriginal; KUSER_SHARED_DATA is valid, read-only, count 7. The
 *   access needed on a process handle is PROCESS_QUERY_LIMITED_INFORMATION. Left: Windows uses priority 7 for
 *   the pages of the system DLLs, nitro always 5.
 */
#define MI_MEMORY_WORKING_SET_EX_CLASS 4
#define MI_MEMORY_IMAGE_CLASS 6

typedef struct _MI_WS_EX_ENTRY
{
    PVOID VirtualAddress;
    ULONG_PTR VirtualAttributes;
} MI_WS_EX_ENTRY, *PMI_WS_EX_ENTRY;

/* ImageBase, SizeOfImage, ImageFlags: 0x18 bytes on x64 (measured), the structure size elsewhere */
typedef struct _MI_IMAGE_INFORMATION
{
    PVOID ImageBase;
    SIZE_T SizeOfImage;
    ULONG ImageFlags;
} MI_IMAGE_INFORMATION;
#define MI_IMAGE_INFORMATION_SIZE sizeof(MI_IMAGE_INFORMATION)

#define MI_WS_EX_BATCH 32

static
NTSTATUS
MiQueryMemoryImageInformation(IN HANDLE ProcessHandle,
                              IN PVOID BaseAddress,
                              OUT PVOID MemoryInformation,
                              OUT PSIZE_T ReturnLength)
{
    MEMORY_REGION_INFORMATION Region;
    MI_IMAGE_INFORMATION Info;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;

    Status = MiQueryMemoryRegionInformation(ProcessHandle, BaseAddress, &Region, sizeof(Region), NULL, FALSE);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(&Info, sizeof(Info));
    if (Region.RegionType == MEM_IMAGE)
    {
        Info.ImageBase = Region.AllocationBase;
        Info.SizeOfImage = Region.RegionSize;
    }

    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            RtlCopyMemory(MemoryInformation, &Info, MI_IMAGE_INFORMATION_SIZE);
            if (ReturnLength) *ReturnLength = MI_IMAGE_INFORMATION_SIZE;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else
    {
        RtlCopyMemory(MemoryInformation, &Info, MI_IMAGE_INFORMATION_SIZE);
        if (ReturnLength) *ReturnLength = MI_IMAGE_INFORMATION_SIZE;
    }
    return Status;
}

static
NTSTATUS
MiQueryMemoryWorkingSetEx(IN HANDLE ProcessHandle,
                          OUT PVOID MemoryInformation,
                          IN SIZE_T MemoryInformationLength,
                          OUT PSIZE_T ReturnLength)
{
    PEPROCESS TargetProcess = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PMI_WS_EX_ENTRY UserEntries = MemoryInformation;
    MI_WS_EX_ENTRY Batch[MI_WS_EX_BATCH];
    MEMORY_BASIC_INFORMATION Basic[MI_WS_EX_BATCH];
    SIZE_T Count = MemoryInformationLength / sizeof(MI_WS_EX_ENTRY), Done = 0, Chunk, i;
    KAPC_STATE ApcState;

    if (ProcessHandle != NtCurrentProcess())
    {
        /* PROCESS_QUERY_LIMITED_INFORMATION is enough on Windows */
        Status = MiReferenceProcessForQuery(ProcessHandle, PreviousMode, &TargetProcess);
        if (!NT_SUCCESS(Status)) return Status;
    }

    while (Done < Count)
    {
        Chunk = min(Count - Done, MI_WS_EX_BATCH);

        /* The addresses come from the caller's space, so read them before attaching */
        _SEH2_TRY
        {
            if (PreviousMode != KernelMode) ProbeForRead(&UserEntries[Done], Chunk * sizeof(MI_WS_EX_ENTRY), 1);
            for (i = 0; i < Chunk; i++) Batch[i].VirtualAddress = UserEntries[Done + i].VirtualAddress;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        if (!NT_SUCCESS(Status)) break;

        /* Protection and kind of each page from the VAD (Basic does its own attach and lock) */
        for (i = 0; i < Chunk; i++)
        {
            RtlZeroMemory(&Basic[i], sizeof(Basic[i]));
            Status = MiQueryMemoryBasicInformation(ProcessHandle,
                                                   PAGE_ALIGN(Batch[i].VirtualAddress),
                                                   &Basic[i],
                                                   sizeof(Basic[i]),
                                                   NULL);
            if (!NT_SUCCESS(Status)) break;
        }
        if (!NT_SUCCESS(Status)) break;

        /* Whether each page is resident, in the target's address space */
        if (TargetProcess) KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);
        for (i = 0; i < Chunk; i++)
        {
            ULONG_PTR Attr = 0;
            PVOID Address = Batch[i].VirtualAddress;

            if ((ULONG_PTR)Address > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS)
            {
                /* not a user page */
            }
            else if (PAGE_ALIGN(Address) == (PVOID)MM_SHARED_USER_DATA_VA)
            {
                /* Windows: valid, read-only, the share count saturated, shared */
                Attr = 1 | (7 << 1) | ((ULONG_PTR)PAGE_READONLY << 4) | (1 << 15) | ((ULONG_PTR)5 << 24) | ((ULONG_PTR)1 << 30);
            }
            else if (Basic[i].State == MEM_COMMIT)
            {
                if (MmIsAddressValid(Address))
                {
                    /* The page protection VirtualQuery reports for a resident page of a mapped (not image) view
                     * follows the PTE bits and so changes with the first write; the protection of the view
                     * is what Windows reports here */
                    ULONG Protect = (Basic[i].Type == MEM_MAPPED) ? Basic[i].AllocationProtect : Basic[i].Protect;
                    PMMPTE Pte = MiAddressToPte(Address);
                    BOOLEAN Shared = (Basic[i].Type != MEM_PRIVATE);

                    /* An image page of a writable section is the shared copy-on-write page until it is
                     * written, then a private one (Windows lists it so) */
                    if ((Basic[i].Type == MEM_IMAGE) &&
                        ((Protect == PAGE_READWRITE) || (Protect == PAGE_EXECUTE_READWRITE)))
                    {
                        if (MI_IS_PAGE_WRITEABLE(Pte))
                            Shared = FALSE;
                        else
                            Protect = (Protect == PAGE_READWRITE) ? PAGE_WRITECOPY : PAGE_EXECUTE_WRITECOPY;
                    }

                    Attr = 1 | ((ULONG_PTR)(Protect & 0x7FF) << 4) | ((ULONG_PTR)5 << 24);
                    if (Shared)
                    {
                        /* The processes that map the page, up to 7 as on Windows */
                        ULONG Sharers = MmCountPageMappers(PFN_FROM_PTE(Pte));

                        Sharers = min(max(Sharers, 1UL), 7UL);
                        Attr |= ((ULONG_PTR)Sharers << 1) | (1 << 15) | ((ULONG_PTR)1 << 30);
                    }
                }
                else if (Basic[i].Type != MEM_PRIVATE)
                {
                    /* A page of a view that is not resident: only the shared flags */
                    Attr = (1 << 15) | ((ULONG_PTR)1 << 30);
                }
            }
            Batch[i].VirtualAttributes = Attr;
        }
        if (TargetProcess) KeUnstackDetachProcess(&ApcState);

        _SEH2_TRY
        {
            if (PreviousMode != KernelMode) ProbeForWrite(&UserEntries[Done], Chunk * sizeof(MI_WS_EX_ENTRY), 1);
            for (i = 0; i < Chunk; i++) UserEntries[Done + i].VirtualAttributes = Batch[i].VirtualAttributes;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        if (!NT_SUCCESS(Status)) break;

        Done += Chunk;
    }

    if (TargetProcess) ObDereferenceObject(TargetProcess);

    if (NT_SUCCESS(Status) && ReturnLength)
    {
        _SEH2_TRY
        {
            *ReturnLength = MemoryInformationLength;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    return Status;
}

/*
 * MemoryWorkingSetInformation (class 1), MemorySharedCommitInformation (class 5),
 * MemoryRegionInformationEx (class 7) and MemoryPrivilegedBasicInformation (class 8), as measured on
 * Windows 10 22H2 (x64 and WoW64; the layouts are the public ntddk/ntmmapi ones):
 * - Class 1: MEMORY_WORKING_SET_INFORMATION, a count then one pointer-sized entry per resident page of the
 *   process, in ascending address order: the page address with Protection (5 bits, the MM protection value),
 *   ShareCount (3 bits), Shared (1 bit) and Node (3 bits, 0) in the low 12 bits. BaseAddress is ignored.
 *   A buffer smaller than the list fails with STATUS_INFO_LENGTH_MISMATCH and gets only the count (when it
 *   holds that), a big enough one gets the list and ReturnLength is the size of the list. The access needed
 *   on a process handle is PROCESS_QUERY_LIMITED_INFORMATION (as for class 3). Private pages have
 *   ShareCount 0 and are not Shared; pages of a view or an image are Shared, the ShareCount being the number
 *   of page table entries that map the page, up to 7 (the rmap list of a page of a file or image section,
 *   the PFN share count for a page of a section without a file). An image data page that was not written is
 *   listed write-copy and Shared; once written it is private. Differences left: Windows lists
 *   KUSER_SHARED_DATA first (x64) or after the pages below 0x7ffe0000 are mixed in (WoW64), nitro keeps the
 *   list in ascending order.
 * - Class 5: a SIZE_T written whatever the address, section or handle; 0x64 on the machine measured, for
 *   every address kind (private, free, pagefile view, file view, image, NULL). Kernel address and handle
 *   checks as the other classes.
 * - Class 7: class 3 with the RegionType bits of the SDK header; at least up to CommitSize is needed.
 * - Class 8: the same as class 0 for every kind of address.
 */
#define MI_MEMORY_WORKING_SET_CLASS 1
#define MI_MEMORY_SHARED_COMMIT_CLASS 5
#define MI_MEMORY_REGION_EX_CLASS 7
#define MI_MEMORY_PRIVILEGED_BASIC_CLASS 8
#define MI_WS_LIST_BATCH 128
#define MI_SHARED_COMMIT_VALUE 0x64

static
NTSTATUS
MiReferenceProcessForQuery(IN HANDLE ProcessHandle,
                           IN KPROCESSOR_MODE PreviousMode,
                           OUT PEPROCESS *Process)
{
    NTSTATUS Status;

    *Process = NULL;
    if (ProcessHandle == NtCurrentProcess()) return STATUS_SUCCESS;

    /* PROCESS_QUERY_LIMITED_INFORMATION is enough on Windows */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_QUERY_INFORMATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)Process,
                                       NULL);
    if (Status == STATUS_ACCESS_DENIED)
    {
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_QUERY_LIMITED_INFORMATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)Process,
                                           NULL);
    }
    return Status;
}

static
NTSTATUS
MiQueryMemorySharedCommit(IN HANDLE ProcessHandle,
                          OUT PVOID MemoryInformation,
                          OUT PSIZE_T ReturnLength)
{
    PEPROCESS Process;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;

    Status = MiReferenceProcessForQuery(ProcessHandle, PreviousMode, &Process);
    if (!NT_SUCCESS(Status)) return Status;
    if (Process) ObDereferenceObject(Process);

    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            *(PSIZE_T)MemoryInformation = MI_SHARED_COMMIT_VALUE;
            if (ReturnLength) *ReturnLength = sizeof(SIZE_T);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else
    {
        *(PSIZE_T)MemoryInformation = MI_SHARED_COMMIT_VALUE;
        if (ReturnLength) *ReturnLength = sizeof(SIZE_T);
    }
    return Status;
}

static
ULONG
MiWin32ProtectToMmValue(IN ULONG Protect)
{
    ULONG Mm;

    switch (Protect & 0xFF)
    {
        case PAGE_READONLY: Mm = MM_READONLY; break;
        case PAGE_EXECUTE: Mm = 2; break;
        case PAGE_EXECUTE_READ: Mm = 3; break;
        case PAGE_READWRITE: Mm = MM_READWRITE; break;
        case PAGE_WRITECOPY: Mm = MM_WRITECOPY; break;
        case PAGE_EXECUTE_READWRITE: Mm = 6; break;
        case PAGE_EXECUTE_WRITECOPY: Mm = 7; break;
        default: Mm = 0; break;
    }
    if (Protect & PAGE_NOCACHE) Mm |= MM_NOCACHE;
    if (Protect & PAGE_GUARD) Mm |= MM_GUARDPAGE;
    return Mm & 0x1F;
}

/* The working set list entry of one resident page of the current (possibly attached) process. The caller holds
 * the address space lock and the working set lock. FALSE for a page that has no view to describe. */
static
BOOLEAN
MiWsListBuildEntry(IN PEPROCESS Process,
                   IN ULONG_PTR Address,
                   IN PMMPTE PointerPte,
                   IN OUT PMMVAD *CachedVad,
                   OUT PULONG_PTR Entry)
{
    PMMVAD Vad = *CachedVad;
    ULONG_PTR Vpn = Address >> PAGE_SHIFT;
    ULONG Win32Protect = 0, ViewProtect;
    BOOLEAN Shared = TRUE, Writable = MI_IS_PAGE_WRITEABLE(PointerPte);
    PVOID NextAddress;

    if (Address == (ULONG_PTR)MM_SHARED_USER_DATA_VA)
    {
        /* Windows: read-only, the share count saturated */
        *Entry = Address | MM_READONLY | (7 << 5) | (1 << 8);
        return TRUE;
    }

    if (!Vad || (Vpn < Vad->StartingVpn) || (Vpn > Vad->EndingVpn))
    {
        Vad = MiLocateAddress((PVOID)Address);
        *CachedVad = Vad;
    }
    if (!Vad) return FALSE;

    if (MI_IS_ROSMM_VAD(Vad))
    {
        MEMORY_BASIC_INFORMATION Info;
        SIZE_T Length;

        if (!NT_SUCCESS(MmQuerySectionView((PMEMORY_AREA)Vad, (PVOID)Address, &Info, &Length))) return FALSE;
        Win32Protect = Info.Protect;
        ViewProtect = Win32Protect;

        /* An image page of a writable section that was not written yet is the shared, copy-on-write
         * one (Windows lists it write-copy); once written it is a private copy */
        if (Info.Type == MEM_IMAGE)
        {
            if ((Info.Protect == PAGE_READWRITE) || (Info.Protect == PAGE_EXECUTE_READWRITE))
            {
                if (Writable)
                {
                    Shared = FALSE;
                }
                else
                {
                    Win32Protect = (Info.Protect == PAGE_READWRITE) ? PAGE_WRITECOPY : PAGE_EXECUTE_WRITECOPY;
                    ViewProtect = Win32Protect;
                }
            }
        }
    }
    else if (Vad->u.VadFlags.VadType == VadNone)
    {
        if (MiQueryAddressState((PVOID)Address, Vad, Process, &Win32Protect, &NextAddress) != MEM_COMMIT) return FALSE;
        ViewProtect = MmProtectToValue[Vad->u.VadFlags.Protection];
        if (Vad->u.VadFlags.PrivateMemory) Shared = FALSE;
    }
    else
    {
        return FALSE;
    }

    /* A page of a copy-on-write view that was written is a private copy now */
    if (Shared && Writable && ((ViewProtect == PAGE_WRITECOPY) || (ViewProtect == PAGE_EXECUTE_WRITECOPY)))
        Shared = FALSE;

    *Entry = Address | MiWin32ProtectToMmValue(Win32Protect);
    if (Shared)
    {
        /* The sharers are the processes that map the page, up to 7 as on Windows */
        ULONG Sharers = MmCountPageMappers(PFN_FROM_PTE(PointerPte));

        Sharers = min(max(Sharers, 1UL), 7UL);
        *Entry |= ((ULONG_PTR)Sharers << 5) | ((ULONG_PTR)1 << 8);
    }
    return TRUE;
}

/* Walk the page tables of the current (possibly attached) process from *Resume. With Entries NULL count the
 * resident pages of the whole address space, else store up to Max entries. The caller holds the address space
 * lock and the working set lock (shared). *Finished tells whether the walk reached the end. */
static
ULONG_PTR
MiWsListWalk(IN PEPROCESS Process,
             IN OUT PULONG_PTR Resume,
             OUT PULONG_PTR Entries OPTIONAL,
             IN ULONG_PTR Max,
             OUT PBOOLEAN Finished)
{
    ULONG_PTR Address = *Resume, Count = 0;
    PMMVAD Vad = NULL;

    *Finished = FALSE;
    while (Address <= (ULONG_PTR)MM_HIGHEST_USER_ADDRESS)
    {
        PMMPTE PointerPte;
        PMMPDE PointerPde;
#if (_MI_PAGING_LEVELS >= 4)
        PMMPXE PointerPxe = MiAddressToPxe((PVOID)Address);

        /* A page table that is not resident cannot have a resident page below it */
        if (!PointerPxe->u.Hard.Valid)
        {
            Address = (ULONG_PTR)MiPxeToAddress(PointerPxe + 1);
            continue;
        }
#endif
#if (_MI_PAGING_LEVELS >= 3)
        {
            PMMPPE PointerPpe = MiAddressToPpe((PVOID)Address);

            if (!PointerPpe->u.Hard.Valid)
            {
                Address = (ULONG_PTR)MiPpeToAddress(PointerPpe + 1);
                continue;
            }
        }
#endif
        PointerPde = MiAddressToPde((PVOID)Address);
        if (!PointerPde->u.Hard.Valid || PointerPde->u.Hard.LargePage)
        {
            /* Large pages are not listed */
            Address = (ULONG_PTR)MiPdeToAddress(PointerPde + 1);
            continue;
        }

        PointerPte = MiAddressToPte((PVOID)Address);
        do
        {
            if (Address > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) break;
            if (PointerPte->u.Hard.Valid)
            {
                if (!Entries)
                {
                    Count++;
                }
                else
                {
                    ULONG_PTR Entry;

                    if (MiWsListBuildEntry(Process, Address, PointerPte, &Vad, &Entry))
                    {
                        if (Count == Max)
                        {
                            *Resume = Address;
                            return Count;
                        }
                        Entries[Count++] = Entry;
                    }
                }
            }
            PointerPte++;
            Address += PAGE_SIZE;
        } while (!MiIsPteOnPdeBoundary(PointerPte));
    }

    *Resume = Address;
    *Finished = TRUE;
    return Count;
}

/* Lock the target, run one walk, unlock; Entries NULL counts. STATUS_PROCESS_IS_TERMINATING when it is dying */
static
NTSTATUS
MiWsListPass(IN PEPROCESS TargetProcess,
             IN OUT PULONG_PTR Resume,
             OUT PULONG_PTR Entries OPTIONAL,
             IN ULONG_PTR Max,
             OUT PULONG_PTR Count,
             OUT PBOOLEAN Finished)
{
    KAPC_STATE ApcState;
    NTSTATUS Status = STATUS_SUCCESS;
    PETHREAD Thread = PsGetCurrentThread();
    BOOLEAN Attached = FALSE;

    if (TargetProcess != PsGetCurrentProcess())
    {
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);
        Attached = TRUE;
    }

    MmLockAddressSpace(&TargetProcess->Vm);
    if (TargetProcess->VmDeleted)
    {
        Status = STATUS_PROCESS_IS_TERMINATING;
        *Count = 0;
        *Finished = TRUE;
    }
    else
    {
        MiLockProcessWorkingSetShared(TargetProcess, Thread);
        *Count = MiWsListWalk(TargetProcess, Resume, Entries, Max, Finished);
        MiUnlockProcessWorkingSetShared(TargetProcess, Thread);
    }
    MmUnlockAddressSpace(&TargetProcess->Vm);

    if (Attached) KeUnstackDetachProcess(&ApcState);
    return Status;
}

static
NTSTATUS
MiQueryMemoryWorkingSetList(IN HANDLE ProcessHandle,
                            OUT PVOID MemoryInformation,
                            IN SIZE_T MemoryInformationLength,
                            OUT PSIZE_T ReturnLength)
{
    PEPROCESS Process, TargetProcess;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PULONG_PTR UserList = MemoryInformation;
    ULONG_PTR Batch[MI_WS_LIST_BATCH];
    ULONG_PTR Capacity = (MemoryInformationLength - sizeof(ULONG_PTR)) / sizeof(ULONG_PTR);
    ULONG_PTR Total, Done = 0, Got, Resume = 0, Want;
    BOOLEAN Finished = FALSE, Overflow = FALSE;
    NTSTATUS Status;

    Status = MiReferenceProcessForQuery(ProcessHandle, PreviousMode, &Process);
    if (!NT_SUCCESS(Status)) return Status;
    TargetProcess = Process ? Process : PsGetCurrentProcess();

    /* How many pages are resident now: a buffer that cannot hold them gets the count only */
    Status = MiWsListPass(TargetProcess, &Resume, NULL, 0, &Total, &Finished);
    if (!NT_SUCCESS(Status)) goto Cleanup;
    if (Total > Capacity)
    {
        Overflow = TRUE;
        goto Report;
    }

    /* The list, a batch at a time (the working set lock is not held while the caller's buffer is written) */
    Resume = 0;
    Finished = FALSE;
    while (!Finished)
    {
        Want = min((ULONG_PTR)MI_WS_LIST_BATCH, Capacity - Done);
        Status = MiWsListPass(TargetProcess, &Resume, Batch, Want, &Got, &Finished);
        if (!NT_SUCCESS(Status)) goto Cleanup;

        if (Got)
        {
            _SEH2_TRY
            {
                RtlCopyMemory(&UserList[1 + Done], Batch, Got * sizeof(ULONG_PTR));
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
            if (!NT_SUCCESS(Status)) goto Cleanup;
            Done += Got;
        }

        /* More pages became resident than the buffer holds */
        if (!Finished && (Want == 0))
        {
            Overflow = TRUE;
            Resume = 0;
            MiWsListPass(TargetProcess, &Resume, NULL, 0, &Total, &Finished);
            if (Total <= Done) Total = Done + 1;
            break;
        }
    }
    if (!Overflow) Total = Done;

Report:
    Status = STATUS_SUCCESS;
    _SEH2_TRY
    {
        UserList[0] = Total;
        if (!Overflow && ReturnLength) *ReturnLength = sizeof(ULONG_PTR) + Total * sizeof(ULONG_PTR);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (NT_SUCCESS(Status)) Status = Overflow ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;

Cleanup:
    if (Process) ObDereferenceObject(Process);
    return Status;
}

BOOLEAN
NTAPI
MiIsEntireRangeCommitted(IN ULONG_PTR StartingAddress,
                         IN ULONG_PTR EndingAddress,
                         IN PMMVAD Vad,
                         IN PEPROCESS Process)
{
    PMMPTE PointerPte, LastPte;
    PMMPDE PointerPde;
    BOOLEAN OnPdeBoundary = TRUE;
#if _MI_PAGING_LEVELS >= 3
    PMMPPE PointerPpe;
    BOOLEAN OnPpeBoundary = TRUE;
#if _MI_PAGING_LEVELS == 4
    PMMPXE PointerPxe;
    BOOLEAN OnPxeBoundary = TRUE;
#endif
#endif

    PAGED_CODE();

    /* Check that we hols the right locks */
    ASSERT(PsGetCurrentThread()->OwnsProcessWorkingSetExclusive || PsGetCurrentThread()->OwnsProcessWorkingSetShared);

    /* Get the PTE addresses */
    PointerPte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    /* Loop all the PTEs */
    while (PointerPte <= LastPte)
    {
#if _MI_PAGING_LEVELS == 4
        /* Check for new PXE boundary */
        if (OnPxeBoundary)
        {
            PointerPxe = MiPteToPxe(PointerPte);

            /* Check that this loop is sane */
            ASSERT(OnPpeBoundary);
            ASSERT(OnPdeBoundary);

            if (PointerPxe->u.Long != 0)
            {
                /* Make it valid if needed */
                if (PointerPxe->u.Hard.Valid == 0)
                    MiMakeSystemAddressValid(MiPteToPpe(PointerPte), Process);
            }
            else
            {
                /* Is the entire VAD committed? If not, fail */
                if (!Vad->u.VadFlags.MemCommit) return FALSE;

                PointerPxe++;
                PointerPte = MiPxeToPte(PointerPxe);
                continue;
            }
        }
#endif

#if _MI_PAGING_LEVELS >= 3
        /* Check for new PPE boundary */
        if (OnPpeBoundary)
        {
            PointerPpe = MiPteToPpe(PointerPte);

            /* Check that this loop is sane */
            ASSERT(OnPdeBoundary);

            if (PointerPpe->u.Long != 0)
            {
                /* Make it valid if needed */
                if (PointerPpe->u.Hard.Valid == 0)
                    MiMakeSystemAddressValid(MiPteToPde(PointerPte), Process);
            }
            else
            {
                /* Is the entire VAD committed? If not, fail */
                if (!Vad->u.VadFlags.MemCommit) return FALSE;

                PointerPpe++;
                PointerPte = MiPpeToPte(PointerPpe);
#if _MI_PAGING_LEVELS == 4
                OnPxeBoundary = MiIsPteOnPxeBoundary(PointerPte);
#endif
                continue;
            }
        }
#endif
        /* Check if we've hit a new PDE boundary */
        if (OnPdeBoundary)
        {
            /* Is this PDE demand zero? */
            PointerPde = MiPteToPde(PointerPte);
            if (PointerPde->u.Long != 0)
            {
                /* It isn't -- is it valid? */
                if (PointerPde->u.Hard.Valid == 0)
                {
                    /* Nope, fault it in */
                    MiMakeSystemAddressValid(PointerPte, Process);
                }
            }
            else
            {
                /* Is the entire VAD committed? If not, fail */
                if (!Vad->u.VadFlags.MemCommit) return FALSE;

                /* The PTE was already valid, so move to the next one */
                PointerPde++;
                PointerPte = MiPdeToPte(PointerPde);
#if _MI_PAGING_LEVELS >= 3
                OnPpeBoundary = MiIsPteOnPpeBoundary(PointerPte);
#if _MI_PAGING_LEVELS == 4
                OnPxeBoundary = MiIsPteOnPxeBoundary(PointerPte);
#endif
#endif

                /* New loop iteration with our new, on-boundary PTE. */
                continue;
            }
        }

        /* Is the PTE demand zero? */
        if (PointerPte->u.Long == 0)
        {
            /* Is the entire VAD committed? If not, fail */
            if (!Vad->u.VadFlags.MemCommit) return FALSE;
        }
        else
        {
            /* It isn't -- is it a decommited, invalid, or faulted PTE? */
            if ((PointerPte->u.Soft.Protection == MM_DECOMMIT) &&
                (PointerPte->u.Hard.Valid == 0) &&
                ((PointerPte->u.Soft.Prototype == 0) ||
                 (PointerPte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)))
            {
                /* Then part of the range is decommitted, so fail */
                return FALSE;
            }
        }

        /* Move to the next PTE */
        PointerPte++;
        OnPdeBoundary = MiIsPteOnPdeBoundary(PointerPte);
#if _MI_PAGING_LEVELS >= 3
        OnPpeBoundary = MiIsPteOnPpeBoundary(PointerPte);
#if _MI_PAGING_LEVELS == 4
        OnPxeBoundary = MiIsPteOnPxeBoundary(PointerPte);
#endif
#endif
    }

    /* All PTEs seem valid, and no VAD checks failed, the range is okay */
    return TRUE;
}

/*
 * Flush every protection change made so far, then release the pages made
 * inaccessible: no processor can reach them any more
 */
static
VOID
MiReleaseProtectedPages(IN OUT PMM_TB_FLUSH_LIST FlushList,
                        IN PMMPFN *Pages,
                        IN OUT PULONG Count)
{
    KIRQL OldIrql;
    ULONG i;

    MmFlushTbList(FlushList);
    if (*Count == 0)
        return;

    OldIrql = MiAcquirePfnLock();
    for (i = 0; i < *Count; i++)
        MiDecrementShareCount(Pages[i], MiGetPfnEntryIndex(Pages[i]));
    MiReleasePfnLock(OldIrql);
    *Count = 0;
}

NTSTATUS
NTAPI
MiProtectVirtualMemory(IN PEPROCESS Process,
                       IN OUT PVOID *BaseAddress,
                       IN OUT PSIZE_T NumberOfBytesToProtect,
                       IN ULONG NewAccessProtection,
                       OUT PULONG OldAccessProtection OPTIONAL)
{
    PMMVAD Vad;
    PMMSUPPORT AddressSpace;
    ULONG_PTR StartingAddress, EndingAddress;
    PMMPTE PointerPte, LastPte;
    PMMPDE PointerPde;
    MMPTE PteContents;
    PMMPFN Pfn1;
    ULONG ProtectionMask, OldProtect;
    BOOLEAN Committed, Unlocked = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;
    PETHREAD Thread = PsGetCurrentThread();
    TABLE_SEARCH_RESULT Result;
    MM_TB_FLUSH_LIST FlushList;
    PMMPFN ReleasePfn[32];
    ULONG ReleaseCount = 0;

    /* We must be attached */
    ASSERT(Process == PsGetCurrentProcess());
    MmInitializeTbFlushList(&FlushList, FALSE);

    /* Calculate base address for the VAD */
    StartingAddress = (ULONG_PTR)PAGE_ALIGN((*BaseAddress));
    EndingAddress = (((ULONG_PTR)*BaseAddress + *NumberOfBytesToProtect - 1) | (PAGE_SIZE - 1));

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(NewAccessProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("Invalid protection mask\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Lock the address space and make sure the process isn't already dead */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);
    if (Process->VmDeleted)
    {
        DPRINT1("Process is dying\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto FailPath;
    }

    /* Get the VAD for this address range, and make sure it exists */
    Result = MiCheckForConflictingNode(StartingAddress >> PAGE_SHIFT,
                                       EndingAddress >> PAGE_SHIFT,
                                       &Process->VadRoot,
                                       (PMMADDRESS_NODE*)&Vad);
    if (Result != TableFoundNode)
    {
        DPRINT("Could not find a VAD for this allocation\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    /* Check if this is a ROSMM VAD */
    if (MI_IS_ROSMM_VAD(Vad))
    {
        /* Not too shabby hack */
        ASSERT(((PMEMORY_AREA)Vad)->Type == MEMORY_AREA_SECTION_VIEW);
        *NumberOfBytesToProtect = PAGE_ROUND_UP((ULONG_PTR)(*BaseAddress) + (*NumberOfBytesToProtect)) - PAGE_ROUND_DOWN(*BaseAddress);
        *BaseAddress = (PVOID)PAGE_ROUND_DOWN(*BaseAddress);
        Status = MmProtectSectionView(AddressSpace,
                                      (PMEMORY_AREA)Vad,
                                      *BaseAddress,
                                      *NumberOfBytesToProtect,
                                      NewAccessProtection,
                                      OldAccessProtection);
        MmUnlockAddressSpace(AddressSpace);
        return Status;
    }

    /* Make sure the address is within this VAD's boundaries */
    if ((((ULONG_PTR)StartingAddress >> PAGE_SHIFT) < Vad->StartingVpn) ||
        (((ULONG_PTR)EndingAddress >> PAGE_SHIFT) > Vad->EndingVpn))
    {
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    /* These kinds of VADs are not supported atm  */
    if ((Vad->u.VadFlags.VadType == VadAwe) ||
        (Vad->u.VadFlags.VadType == VadDevicePhysicalMemory) ||
        (Vad->u.VadFlags.VadType == VadLargePages))
    {
        DPRINT1("Illegal VAD for attempting to set protection\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    /* Check for a VAD whose protection can't be changed */
    if (Vad->u.VadFlags.NoChange == 1)
    {
        /*
         * A SEC_NO_CHANGE section mapping is genuinely immutable, and so is the
         * shared user data page. But the PEB and TEBs are kernel-secured PRIVATE
         * VADs (see MiCreatePebOrTeb) which Windows lets their process reprotect;
         * the Chromium renderer sandbox does exactly that during target setup.
         * Only allow that one case.
         */
        if (!Vad->u.VadFlags.PrivateMemory ||
            (Vad->u2.VadFlags2.SecNoChange == 1) ||
            (Vad->StartingVpn == (MM_SHARED_USER_DATA_VA >> PAGE_SHIFT)))
        {
            /* Scalar arguments only: we hold the address space mutex here */
            DPRINT1("Trying to change protection of a NoChange VAD (private %u, base %p)\n",
                    (ULONG)Vad->u.VadFlags.PrivateMemory, (PVOID)StartingAddress);
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto FailPath;
        }

        /* PEB/TEB: fall through and perform the protection change */
    }

    /* Is this section, or private memory? */
    if (Vad->u.VadFlags.PrivateMemory == 0)
    {
        /* Not yet supported */
        if (Vad->u.VadFlags.VadType == VadLargePageSection)
        {
            DPRINT1("Illegal VAD for attempting to set protection\n");
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto FailPath;
        }

        /* Rotate VADs are not yet supported */
        if (Vad->u.VadFlags.VadType == VadRotatePhysical)
        {
            DPRINT1("Illegal VAD for attempting to set protection\n");
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto FailPath;
        }

        /* Not valid on section files */
        if (NewAccessProtection & (PAGE_NOCACHE | PAGE_WRITECOMBINE))
        {
            /* Fail */
            DPRINT1("Invalid protection flags for section\n");
            Status = STATUS_INVALID_PARAMETER_4;
            goto FailPath;
        }

        /* Check if data or page file mapping protection PTE is compatible */
        if (!Vad->ControlArea->u.Flags.Image)
        {
            /* Not yet */
            DPRINT1("Fixme: Not checking for valid protection\n");
        }

        /*
         * The change itself is not applied yet: a resident page of a prototype-backed view has no protection
         * of its own, it takes the protection of the view (see the section view case in the query code),
         * so there is nowhere to keep the new one. The call reports the old protection of the view, which
         * is what a query of the first page shows (the oracle returns 0x40 for a view of a pagefile-backed
         * section mapped executable read-write).
         */
        DPRINT("Section protection change not applied\n");
        OldProtect = MmProtectToValue[Vad->u.VadFlags.Protection];
    }
    else
    {
        /* Private memory, check protection flags */
        if ((NewAccessProtection & PAGE_WRITECOPY) ||
            (NewAccessProtection & PAGE_EXECUTE_WRITECOPY))
        {
            DPRINT1("Invalid protection flags for private memory\n");
            Status = STATUS_INVALID_PARAMETER_4;
            goto FailPath;
        }

        /* Lock the working set */
        MiLockProcessWorkingSetUnsafe(Process, Thread);

        /* Check if all pages in this range are committed */
        Committed = MiIsEntireRangeCommitted(StartingAddress,
                                             EndingAddress,
                                             Vad,
                                             Process);
        if (!Committed)
        {
            /* Fail */
            DPRINT1("The entire range is not committed\n");
            Status = STATUS_NOT_COMMITTED;
            MiUnlockProcessWorkingSetUnsafe(Process, Thread);
            goto FailPath;
        }

        /* Compute starting and ending PTE and PDE addresses */
        PointerPde = MiAddressToPde(StartingAddress);
        PointerPte = MiAddressToPte(StartingAddress);
        LastPte = MiAddressToPte(EndingAddress);

        /* Make this PDE valid */
        MiMakePdeExistAndMakeValid(PointerPde, Process, MM_NOIRQL);

        /* Save protection of the first page */
        if (PointerPte->u.Long != 0)
        {
            /* Capture the page protection and make the PDE valid */
            OldProtect = MiGetPageProtection(PointerPte);
            MiMakePdeExistAndMakeValid(PointerPde, Process, MM_NOIRQL);
        }
        else
        {
            /* Grab the old protection from the VAD itself */
            OldProtect = MmProtectToValue[Vad->u.VadFlags.Protection];
        }

        /* Loop all the PTEs now */
        while (PointerPte <= LastPte)
        {
            /* Check if we've crossed a PDE boundary and make the new PDE valid too */
            if (MiIsPteOnPdeBoundary(PointerPte))
            {
                PointerPde = MiPteToPde(PointerPte);

                /* Making it valid can drop the working set lock, which keeps
                   faults off the pages changed so far: flush them first */
#if (_MI_PAGING_LEVELS == 4)
                if (!MiIsPdeForAddressValid(MiPteToAddress(PointerPte)))
#else
                if (!PointerPde->u.Hard.Valid)
#endif
                    MiReleaseProtectedPages(&FlushList, ReleasePfn, &ReleaseCount);

                MiMakePdeExistAndMakeValid(PointerPde, Process, MM_NOIRQL);
            }

            /* Capture the PTE and check if it was empty */
            PteContents = *PointerPte;
            if (PteContents.u.Long == 0)
            {
                /* This used to be a zero PTE and it no longer is, so we must add a
                   reference to the pagetable. */
                MiIncrementPageTableReferences(MiPteToAddress(PointerPte));
            }

            /* Check what kind of PTE we are dealing with */
            if (PteContents.u.Hard.Valid == 1)
            {
                /* Get the PFN entry */
                Pfn1 = MiGetPfnEntry(PFN_FROM_PTE(&PteContents));

                /* We don't support this yet */
                ASSERT(Pfn1->u3.e1.PrototypePte == 0);

                /* Check if the page should not be accessible at all */
                if ((NewAccessProtection & PAGE_NOACCESS) ||
                    (NewAccessProtection & PAGE_GUARD))
                {
                    KIRQL OldIrql = MiAcquirePfnLock();

                    /* A page locked with VirtualLock is unlocked, as on Windows */
                    if (Pfn1->Wsle.u1.e1.LockedInWs)
                    {
                        Pfn1->Wsle.u1.e1.LockedInWs = 0;
                        if (!Pfn1->Wsle.u1.e1.LockedInMemory)
                            MiDereferencePfnAndDropLockCount(Pfn1);
                        Unlocked = TRUE;
                    }

                    /* Mark the PTE as transition and change its protection */
                    PteContents.u.Hard.Valid = 0;
                    PteContents.u.Soft.Transition = 1;
                    PteContents.u.Trans.Protection = ProtectionMask;
                    /*
                     * Write the PTE, and release the page only when no processor can still use it.
                     * D8: exchange it, so that Dirty comes from the PTE as the processors last
                     * wrote it, and keep it in the PFN (a clean copy in the paging file is stale)
                     */
                    // FIXME: remove the page from the WS
                    {
                        MMPTE OldPte;

                        OldPte.u.Long = InterlockedExchangePte(PointerPte, PteContents.u.Long);
                        if (OldPte.u.Hard.Dirty)
                            MiMarkPfnDirty(Pfn1);
                    }
                    MiReleasePfnLock(OldIrql);

                    /* The working set lock keeps faults off the page until it is released */
                    MmAddToTbFlushList(&FlushList, MiPteToAddress(PointerPte));
                    ReleasePfn[ReleaseCount++] = Pfn1;
                    if (ReleaseCount == RTL_NUMBER_OF(ReleasePfn))
                        MiReleaseProtectedPages(&FlushList, ReleasePfn, &ReleaseCount);
                }
                else
                {
                    /* The TB is flushed with the list; OriginalPte.Protection is
                       stored by MiFlushTbAndCapture under the PFN lock (F4) */
                    MiFlushTbAndCapture(Vad,
                                        PointerPte,
                                        ProtectionMask,
                                        Pfn1,
                                        TRUE);
                    MmAddToTbFlushList(&FlushList, MiPteToAddress(PointerPte));
                }
            }
            else
            {
                /* We don't support these cases yet */
                ASSERT(PteContents.u.Soft.Prototype == 0);
                //ASSERT(PteContents.u.Soft.Transition == 0);

                if (PteContents.u.Soft.Transition)
                {
                    /*
                     * PTE-1: a transition PTE can become a page-file PTE under the PFN
                     * lock alone (NitroPager repurpose): read and rewrite it under it.
                     * The protection field is the same in both forms.
                     */
                    KIRQL OldIrql = MiAcquirePfnLock();
                    PteContents = *PointerPte;
                    PteContents.u.Soft.Protection = ProtectionMask;
                    MI_WRITE_INVALID_PTE(PointerPte, PteContents);
                    MiReleasePfnLock(OldIrql);
                }
                else
                {
                    /* Demand-zero or paged out: only the working set lock changes those */
                    PteContents.u.Soft.Protection = ProtectionMask;
                    MI_WRITE_INVALID_PTE(PointerPte, PteContents);
                }
                ASSERT(PointerPte->u.Long != 0);
            }

            /* Move to the next PTE */
            PointerPte++;
        }

        /* Flush every valid PTE changed above before the call returns, then
           release the pages made inaccessible */
        MiReleaseProtectedPages(&FlushList, ReleasePfn, &ReleaseCount);

        /* Unlock the working set */
        MiUnlockProcessWorkingSetUnsafe(Process, Thread);
    }

    /* Unlock the address space */
    MmUnlockAddressSpace(AddressSpace);

    /* Return parameters and success */
    *NumberOfBytesToProtect = EndingAddress - StartingAddress + 1;
    *BaseAddress = (PVOID)StartingAddress;
    *OldAccessProtection = OldProtect;
    return Unlocked ? STATUS_WAS_UNLOCKED : STATUS_SUCCESS;

FailPath:
    /* Unlock the address space and return the failure code */
    MmUnlockAddressSpace(AddressSpace);
    return Status;
}

VOID
NTAPI
MiMakePdeExistAndMakeValid(IN PMMPDE PointerPde,
                           IN PEPROCESS TargetProcess,
                           IN KIRQL OldIrql)
{
   PMMPTE PointerPte;
#if _MI_PAGING_LEVELS >= 3
   PMMPPE PointerPpe = MiPdeToPpe(PointerPde);
#if _MI_PAGING_LEVELS == 4
   PMMPXE PointerPxe = MiPdeToPxe(PointerPde);
#endif
#endif

   //
   // Sanity checks. The latter is because we only use this function with the
   // PFN lock not held, so it may go away in the future.
   //
   ASSERT(KeAreAllApcsDisabled() == TRUE);
   ASSERT(OldIrql == MM_NOIRQL);

   //
   // If everything is already valid, there is nothing to do.
   //
   if (
#if _MI_PAGING_LEVELS == 4
       (PointerPxe->u.Hard.Valid) &&
#endif
#if _MI_PAGING_LEVELS >= 3
       (PointerPpe->u.Hard.Valid) &&
#endif
       (PointerPde->u.Hard.Valid))
   {
       return;
   }

   //
   // At least something is invalid, so begin by getting the PTE for the PDE itself
   // and then lookup each additional level. We must do it in this precise order
   // because the pagfault.c code (as well as in Windows) depends that the next
   // level up (higher) must be valid when faulting a lower level
   //
   PointerPte = MiPteToAddress(PointerPde);
   do
   {
       //
       // Make sure APCs continued to be disabled
       //
       ASSERT(KeAreAllApcsDisabled() == TRUE);

#if _MI_PAGING_LEVELS == 4
       //
       // First, make the PXE valid if needed
       //
       if (!PointerPxe->u.Hard.Valid)
       {
           MiMakeSystemAddressValid(PointerPpe, TargetProcess);
           ASSERT(PointerPxe->u.Hard.Valid == 1);
       }
#endif

#if _MI_PAGING_LEVELS >= 3
       //
       // Next, the PPE
       //
       if (!PointerPpe->u.Hard.Valid)
       {
           MiMakeSystemAddressValid(PointerPde, TargetProcess);
           ASSERT(PointerPpe->u.Hard.Valid == 1);
       }
#endif

       //
       // And finally, make the PDE itself valid.
       //
       MiMakeSystemAddressValid(PointerPte, TargetProcess);

       /* Do not increment Page table refcount here for the PDE, this must be managed by caller */

       //
       // This should've worked the first time so the loop is really just for
       // show -- ASSERT that we're actually NOT going to be looping.
       //
       ASSERT(PointerPde->u.Hard.Valid == 1);
   } while (
#if _MI_PAGING_LEVELS == 4
        !PointerPxe->u.Hard.Valid ||
#endif
#if _MI_PAGING_LEVELS >= 3
        !PointerPpe->u.Hard.Valid ||
#endif
        !PointerPde->u.Hard.Valid);
}

VOID
NTAPI
MiProcessValidPteList(IN PMMPTE *ValidPteList,
                      IN ULONG Count)
{
    KIRQL OldIrql;
    ULONG i;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    PMMPFN Pfn1, Pfn2;
    MM_TB_FLUSH_LIST FlushList;

    /* Decommitted user pages: only the processors running the process cache them */
    MmInitializeTbFlushList(&FlushList, FALSE);

    //
    // Acquire the PFN lock and loop all the PTEs in the list
    //
    OldIrql = MiAcquirePfnLock();
    for (i = 0; i != Count; i++)
    {
        //
        // The PTE must currently be valid
        //
        TempPte = *ValidPteList[i];
        ASSERT(TempPte.u.Hard.Valid == 1);

        //
        // Get the PFN entry for the page itself, and then for its page table
        //
        PageFrameIndex = PFN_FROM_PTE(&TempPte);
        Pfn1 = MiGetPfnEntry(PageFrameIndex);
        Pfn2 = MiGetPfnEntry(Pfn1->u4.PteFrame);

        //
        // Make the page decommitted
        //
        MI_WRITE_INVALID_PTE(ValidPteList[i], MmDecommittedPte);
        MmAddToTbFlushList(&FlushList, MiPteToAddress(ValidPteList[i]));

        //
        // Decrement the share count on the page table. The page keeps its own
        // share count until the TB flush below, so it cannot be reused before it.
        //
        MiDecrementShareCount(Pfn2, Pfn1->u4.PteFrame);
        MI_SET_PFN_DELETED(Pfn1);
        MiDropVirtualLock(Pfn1);

        // The slot now holds the page to release
        ValidPteList[i] = (PMMPTE)Pfn1;
    }

    //
    // All the PTEs have been made invalid. Flush the TLB without the PFN lock,
    // then free the pages.
    //
    MiReleasePfnLock(OldIrql);
    MmFlushTbList(&FlushList);

    OldIrql = MiAcquirePfnLock();
    for (i = 0; i != Count; i++)
    {
        Pfn1 = (PMMPFN)ValidPteList[i];
        MiDecrementShareCount(Pfn1, MiGetPfnEntryIndex(Pfn1));
    }
    MiReleasePfnLock(OldIrql);
}

#ifdef _WIN64
/*
 * For a reservation (a VAD without MemCommit), a range whose page table does not
 * exist holds only zero PTEs: reserved, not committed, the same state a decommitted
 * PTE gives. Returns the first PTE at or after PointerPte that may have a page table,
 * so a decommit of a large reservation (MariaDB reserves 8 TiB) does not build page
 * tables for all of it. Levels that are present but not resident are not skipped.
 */
static
PMMPTE
MiSkipAbsentPageTables(IN PMMPTE PointerPte)
{
    PMMPDE PointerPde;
#if (_MI_PAGING_LEVELS == 4)
    PMMPXE PointerPxe = MiPteToPxe(PointerPte);
    if (PointerPxe->u.Long == 0) return MiPxeToPte(PointerPxe + 1);
    if (PointerPxe->u.Hard.Valid == 0) return PointerPte;
#endif
#if (_MI_PAGING_LEVELS >= 3)
    PMMPPE PointerPpe = MiPteToPpe(PointerPte);
    if (PointerPpe->u.Long == 0) return MiPpeToPte(PointerPpe + 1);
    if (PointerPpe->u.Hard.Valid == 0) return PointerPte;
#endif
    PointerPde = MiPteToPde(PointerPte);
    if (PointerPde->u.Long == 0) return MiPdeToPte(PointerPde + 1);
    return PointerPte;
}
#endif

PFN_NUMBER
NTAPI
MiDecommitPages(IN PVOID StartingAddress,
                IN PMMPTE EndingPte,
                IN PEPROCESS Process,
                IN PMMVAD Vad)
{
    PMMPTE PointerPte, CommitPte = NULL;
    PMMPDE PointerPde;
    /* A 128 TiB user range has more than 2^32 pages */
    PFN_NUMBER CommitReduction = 0;
    BOOLEAN FirstPte = TRUE;
    PMMPTE ValidPteList[256];
    ULONG PteCount = 0;
    PMMPFN Pfn1;
    MMPTE PteContents;
    PETHREAD CurrentThread = PsGetCurrentThread();

    //
    // Get the PTE and PTE for the address, and lock the working set
    // If this was a VAD for a MEM_COMMIT allocation, also figure out where the
    // commited range ends so that we can do the right accounting.
    //
    PointerPde = MiAddressToPde(StartingAddress);
    PointerPte = MiAddressToPte(StartingAddress);
    if (Vad->u.VadFlags.MemCommit) CommitPte = MiAddressToPte(Vad->EndingVpn << PAGE_SHIFT);
    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

    //
    // Loop through each page's worth of data, making each PDE valid on the way
    //
    while (PointerPte <= EndingPte)
    {
        //
        // Check if this is the first PTE or we've crossed a PDE boundary
        //
        if (FirstPte || MiIsPteOnPdeBoundary(PointerPte))
        {
            //
            // Flush the valid PTEs we had built up until now. This helps
            // reduce the amount of TLB flushing we have to do.
            // Note that Windows does a much better job using timestamps and
            // such, and does not flush the entire TLB all the time, but right
            // now we have bigger problems to worry about than TLB flushing.
            //
            FirstPte = FALSE;
            if (PteCount)
            {
                MiProcessValidPteList(ValidPteList, PteCount);
                PteCount = 0;
            }

#ifdef _WIN64
            //
            // In a reservation, a range without a page table has nothing committed:
            // count it as already decommitted and do not build page tables for it
            //
            if (!Vad->u.VadFlags.MemCommit)
            {
                PMMPTE NextPte = MiSkipAbsentPageTables(PointerPte);
                if (NextPte != PointerPte)
                {
                    if (NextPte > EndingPte) NextPte = EndingPte + 1;
                    CommitReduction += NextPte - PointerPte;
                    PointerPte = NextPte;
                    StartingAddress = MiPteToAddress(PointerPte);
                    FirstPte = TRUE;
                    continue;
                }
            }
#endif

            //
            // Get the new PDE and make it valid
            //
            PointerPde = MiAddressToPde(StartingAddress);
            MiMakePdeExistAndMakeValid(PointerPde, Process, MM_NOIRQL);
        }

        //
        // Read this PTE. It might be active or still demand-zero.
        //
        PteContents = *PointerPte;
        if (PteContents.u.Long)
        {
            //
            // The PTE is active. It might be valid and in a working set, or
            // it might be a prototype PTE or paged out or even in transition.
            //
            if (PointerPte->u.Long == MmDecommittedPte.u.Long)
            {
                //
                // It's already decommited, so there's nothing for us to do here
                //
                CommitReduction++;
            }
            else
            {
                //
                // Remove it from the counters, and check if it was valid or not
                //
                //Process->NumberOfPrivatePages--;
                if (PteContents.u.Hard.Valid)
                {
                    //
                    // It's valid. At this point make sure that it is not a ROS
                    // PFN. Also, we don't support ProtoPTEs in this code path.
                    //
                    Pfn1 = MiGetPfnEntry(PteContents.u.Hard.PageFrameNumber);
                    ASSERT(MI_IS_ROS_PFN(Pfn1) == FALSE);
                    ASSERT(Pfn1->u3.e1.PrototypePte == FALSE);

                    //
                    // Flush any pending PTEs that we had not yet flushed, if our
                    // list has gotten too big, then add this PTE to the flush list.
                    //
                    if (PteCount == 256)
                    {
                        MiProcessValidPteList(ValidPteList, PteCount);
                        PteCount = 0;
                    }
                    ValidPteList[PteCount++] = PointerPte;
                }
                else if ((PteContents.u.Soft.Prototype == 0) &&
                         ((PteContents.u.Soft.Transition == 1) || MI_IS_PAGEFILE_PTE(&PteContents)))
                {
                    //
                    // A page made PAGE_NOACCESS or PAGE_GUARD after it was
                    // touched is in transition, a page NitroPager trimmed is
                    // in transition or paged out. Free it as MEM_RELEASE does
                    // (MiDeletePte reads the PTE again under the PFN lock:
                    // the transition PTE may have been repurposed meanwhile),
                    // then decommit the PTE.
                    //
                    KIRQL OldIrql = MiAcquirePfnLock();
                    MiDeletePte(PointerPte, MiPteToAddress(PointerPte), Process, NULL);
                    MiReleasePfnLock(OldIrql);
                    MI_WRITE_INVALID_PTE(PointerPte, MmDecommittedPte);
                }
                else
                {
                    //
                    // We do not support any of these other scenarios at the moment
                    //
                    ASSERT(PteContents.u.Soft.Prototype == 0);
                    ASSERT(PteContents.u.Soft.PageFileHigh == 0);

                    //
                    // So the only other possibility is that it is still a demand
                    // zero PTE, in which case we undo the accounting we did
                    // earlier and simply make the page decommitted.
                    //
                    //Process->NumberOfPrivatePages++;
                    MI_WRITE_INVALID_PTE(PointerPte, MmDecommittedPte);
                }
            }
        }
        else
        {
            //
            // This used to be a zero PTE and it no longer is, so we must add a
            // reference to the pagetable.
            //
            MiIncrementPageTableReferences(StartingAddress);

            //
            // Next, we account for decommitted PTEs and make the PTE as such
            //
            if (PointerPte > CommitPte) CommitReduction++;
            MI_WRITE_INVALID_PTE(PointerPte, MmDecommittedPte);
        }

        //
        // Move to the next PTE and the next address
        //
        PointerPte++;
        StartingAddress = (PVOID)((ULONG_PTR)StartingAddress + PAGE_SIZE);
    }

    //
    // Flush any dangling PTEs from the loop in the last page table, and then
    // release the working set and return the commit reduction accounting.
    //
    if (PteCount) MiProcessValidPteList(ValidPteList, PteCount);
    MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);
    return CommitReduction;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @unimplemented
 */
PVOID
NTAPI
MmGetVirtualForPhysical(IN PHYSICAL_ADDRESS PhysicalAddress)
{
    UNIMPLEMENTED;
    return 0;
}

/*
 * @unimplemented
 */
PVOID
NTAPI
MmSecureVirtualMemory(IN PVOID Address,
                      IN SIZE_T Length,
                      IN ULONG Mode)
{
    static ULONG Warn; if (!Warn++) UNIMPLEMENTED;
    return Address;
}

/*
 * @unimplemented
 */
VOID
NTAPI
MmUnsecureVirtualMemory(IN PVOID SecureMem)
{
    static ULONG Warn; if (!Warn++) UNIMPLEMENTED;
}

/* SYSTEM CALLS ***************************************************************/

NTSTATUS
NTAPI
NtReadVirtualMemory(IN HANDLE ProcessHandle,
                    IN PVOID BaseAddress,
                    OUT PVOID Buffer,
                    IN SIZE_T NumberOfBytesToRead,
                    OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process;
    NTSTATUS Status = STATUS_SUCCESS;
    SIZE_T BytesRead = 0;
    PAGED_CODE();

    //
    // Check if we came from user mode
    //
    if (PreviousMode != KernelMode)
    {
        //
        // Validate the read addresses
        //
        if ((((ULONG_PTR)BaseAddress + NumberOfBytesToRead) < (ULONG_PTR)BaseAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToRead) < (ULONG_PTR)Buffer) ||
            (((ULONG_PTR)BaseAddress + NumberOfBytesToRead) > MmUserProbeAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToRead) > MmUserProbeAddress))
        {
            //
            // Don't allow to write into kernel space
            //
            return STATUS_ACCESS_VIOLATION;
        }

        //
        // Enter SEH for probe
        //
        _SEH2_TRY
        {
            //
            // Probe the output value
            //
            if (NumberOfBytesRead) ProbeForWriteSize_t(NumberOfBytesRead);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Get exception code
            //
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    //
    // Don't do zero-byte transfers
    //
    if (NumberOfBytesToRead)
    {
        //
        // Reference the process
        //
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_READ,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)(&Process),
                                           NULL);
        if (NT_SUCCESS(Status))
        {
            //
            // Do the copy
            //
            Status = MmCopyVirtualMemory(Process,
                                         BaseAddress,
                                         PsGetCurrentProcess(),
                                         Buffer,
                                         NumberOfBytesToRead,
                                         PreviousMode,
                                         &BytesRead);

            /* Windows ReadProcessMemory semantics: when part of the range is
             * inaccessible, copy the valid prefix and report STATUS_PARTIAL_COPY
             * with the number of bytes transferred, instead of failing the whole
             * transfer with zero bytes. */
            if ((Status == STATUS_ACCESS_VIOLATION) &&
                (BytesRead == 0) &&
                (NumberOfBytesToRead > 1) &&
                (Process != PsGetCurrentProcess()))
            {
                SIZE_T Off = 0, Chunk, Got;
                NTSTATUS SubStatus;
                while (Off < NumberOfBytesToRead)
                {
                    Chunk = PAGE_SIZE - (((ULONG_PTR)BaseAddress + Off) & (PAGE_SIZE - 1));
                    if (Chunk > (NumberOfBytesToRead - Off)) Chunk = NumberOfBytesToRead - Off;
                    Got = 0;
                    SubStatus = MmCopyVirtualMemory(Process,
                                                    (PVOID)((ULONG_PTR)BaseAddress + Off),
                                                    PsGetCurrentProcess(),
                                                    (PVOID)((ULONG_PTR)Buffer + Off),
                                                    Chunk,
                                                    PreviousMode,
                                                    &Got);
                    if (!NT_SUCCESS(SubStatus)) break;
                    Off += Got;
                    if (Got < Chunk) break;
                }
                BytesRead = Off;
                Status = (Off > 0) ? STATUS_PARTIAL_COPY : STATUS_ACCESS_VIOLATION;
            }

            //
            // Dereference the process
            //
            ObDereferenceObject(Process);
        }
    }

    //
    // Check if the caller sent this parameter
    //
    if (NumberOfBytesRead)
    {
        //
        // Enter SEH to guard write
        //
        _SEH2_TRY
        {
            //
            // Return the number of bytes read
            //
            *NumberOfBytesRead = BytesRead;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
    }

    //
    // Return status
    //
    return Status;
}

NTSTATUS
NTAPI
NtWriteVirtualMemory(IN HANDLE ProcessHandle,
                     IN PVOID BaseAddress,
                     IN PVOID Buffer,
                     IN SIZE_T NumberOfBytesToWrite,
                     OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process;
    NTSTATUS Status = STATUS_SUCCESS;
    SIZE_T BytesWritten = 0;
    PAGED_CODE();

    //
    // Check if we came from user mode
    //
    if (PreviousMode != KernelMode)
    {
        //
        // Validate the read addresses
        //
        if ((((ULONG_PTR)BaseAddress + NumberOfBytesToWrite) < (ULONG_PTR)BaseAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToWrite) < (ULONG_PTR)Buffer) ||
            (((ULONG_PTR)BaseAddress + NumberOfBytesToWrite) > MmUserProbeAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToWrite) > MmUserProbeAddress))
        {
            //
            // Don't allow to write into kernel space
            //
            return STATUS_ACCESS_VIOLATION;
        }

        //
        // Enter SEH for probe
        //
        _SEH2_TRY
        {
            //
            // Probe the output value
            //
            if (NumberOfBytesWritten) ProbeForWriteSize_t(NumberOfBytesWritten);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Get exception code
            //
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    //
    // Don't do zero-byte transfers
    //
    if (NumberOfBytesToWrite)
    {
        //
        // Reference the process
        //
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_WRITE,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)&Process,
                                           NULL);
        if (NT_SUCCESS(Status))
        {
            //
            // Do the copy
            //
            Status = MmCopyVirtualMemory(PsGetCurrentProcess(),
                                         Buffer,
                                         Process,
                                         BaseAddress,
                                         NumberOfBytesToWrite,
                                         PreviousMode,
                                         &BytesWritten);

            //
            // Dereference the process
            //
            ObDereferenceObject(Process);
        }
    }

    //
    // Check if the caller sent this parameter
    //
    if (NumberOfBytesWritten)
    {
        //
        // Enter SEH to guard write
        //
        _SEH2_TRY
        {
            //
            // Return the number of bytes written
            //
            *NumberOfBytesWritten = BytesWritten;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
    }

    //
    // Return status
    //
    return Status;
}

NTSTATUS
NTAPI
NtFlushInstructionCache(_In_ HANDLE ProcessHandle,
                        _In_opt_ PVOID BaseAddress,
                        _In_ SIZE_T FlushSize)
{
    KAPC_STATE ApcState;
    PKPROCESS Process;
    NTSTATUS Status;
    PAGED_CODE();

    /* Is a base address given? */
    if (BaseAddress != NULL)
    {
        /* If the requested size is 0, there is nothing to do */
        if (FlushSize == 0)
        {
            return STATUS_SUCCESS;
        }

        /* Is this a user mode call? */
        if (ExGetPreviousMode() != KernelMode)
        {
            /* Make sure the base address is in user space */
            if (BaseAddress > MmHighestUserAddress)
            {
                DPRINT1("Invalid BaseAddress 0x%p\n", BaseAddress);
                return STATUS_ACCESS_VIOLATION;
            }
        }
    }

    /* Is another process requested? */
    if (ProcessHandle != NtCurrentProcess())
    {
        /* Reference the process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_WRITE,
                                           PsProcessType,
                                           ExGetPreviousMode(),
                                           (PVOID*)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to reference the process %p\n", ProcessHandle);
            return Status;
        }

        /* Attach to the process */
        KeStackAttachProcess(Process, &ApcState);
    }

    /* Forward to Ke */
    KeSweepICache(BaseAddress, FlushSize);

    /* Check if we attached */
    if (ProcessHandle != NtCurrentProcess())
    {
        /* Detach from the process and dereference it */
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(Process);
    }

    /* All done, return to caller */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NtProtectVirtualMemory(IN HANDLE ProcessHandle,
                       IN OUT PVOID *UnsafeBaseAddress,
                       IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
                       IN ULONG NewAccessProtection,
                       OUT PULONG UnsafeOldAccessProtection)
{
    PEPROCESS Process;
    ULONG OldAccessProtection;
    ULONG Protection;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PVOID BaseAddress = NULL;
    SIZE_T NumberOfBytesToProtect = 0;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;
    BOOLEAN Attached = FALSE;
    KAPC_STATE ApcState;
    PAGED_CODE();

    //
    // The call target bit goes with an execute protection only, and has no effect here
    //
    if (!MiStripTargetsFlag(&NewAccessProtection)) return STATUS_INVALID_PAGE_PROTECTION;

    //
    // Check for valid protection flags
    //
    Protection = NewAccessProtection & ~(PAGE_GUARD|PAGE_NOCACHE);
    if (Protection != PAGE_NOACCESS &&
        Protection != PAGE_READONLY &&
        Protection != PAGE_READWRITE &&
        Protection != PAGE_WRITECOPY &&
        Protection != PAGE_EXECUTE &&
        Protection != PAGE_EXECUTE_READ &&
        Protection != PAGE_EXECUTE_READWRITE &&
        Protection != PAGE_EXECUTE_WRITECOPY)
    {
        //
        // Fail
        //
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    //
    // Check if we came from user mode
    //
    if (PreviousMode != KernelMode)
    {
        //
        // Enter SEH for probing
        //
        _SEH2_TRY
        {
            //
            // Validate all outputs
            //
            ProbeForWritePointer(UnsafeBaseAddress);
            ProbeForWriteSize_t(UnsafeNumberOfBytesToProtect);
            ProbeForWriteUlong(UnsafeOldAccessProtection);

            //
            // Capture them
            //
            BaseAddress = *UnsafeBaseAddress;
            NumberOfBytesToProtect = *UnsafeNumberOfBytesToProtect;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Get exception code
            //
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        //
        // Capture directly
        //
        BaseAddress = *UnsafeBaseAddress;
        NumberOfBytesToProtect = *UnsafeNumberOfBytesToProtect;
    }

    //
    // Catch illegal base address
    //
    if (BaseAddress > MM_HIGHEST_USER_ADDRESS) return STATUS_INVALID_PARAMETER_2;

    //
    // Catch illegal region size
    //
    if ((MmUserProbeAddress - (ULONG_PTR)BaseAddress) < NumberOfBytesToProtect)
    {
        //
        // Fail
        //
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // 0 is also illegal
    //
    if (!NumberOfBytesToProtect) return STATUS_INVALID_PARAMETER_3;

    //
    // Get a reference to the process
    //
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)(&Process),
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    //
    // Check if we should attach
    //
    if (CurrentProcess != Process)
    {
        //
        // Do it
        //
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    //
    // Do the actual work
    //
    Status = MiProtectVirtualMemory(Process,
                                    &BaseAddress,
                                    &NumberOfBytesToProtect,
                                    NewAccessProtection,
                                    &OldAccessProtection);

    //
    // Detach if needed
    //
    if (Attached) KeUnstackDetachProcess(&ApcState);

    //
    // Release reference
    //
    ObDereferenceObject(Process);

    //
    // Enter SEH to return data
    //
    _SEH2_TRY
    {
        //
        // Return data to user
        //
        *UnsafeOldAccessProtection = OldAccessProtection;
        *UnsafeBaseAddress = BaseAddress;
        *UnsafeNumberOfBytesToProtect = NumberOfBytesToProtect;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;

    //
    // Return status
    //
    return Status;
}

FORCEINLINE
BOOLEAN
MI_IS_LOCKED_VA(
    PMMPFN Pfn1,
    ULONG LockType)
{
    // HACK until we have proper WSLIST support
    PMMWSLE Wsle = &Pfn1->Wsle;

    if ((LockType & MAP_PROCESS) && (Wsle->u1.e1.LockedInWs))
        return TRUE;
    if ((LockType & MAP_SYSTEM) && (Wsle->u1.e1.LockedInMemory))
        return TRUE;

    return FALSE;
}

FORCEINLINE
VOID
MI_LOCK_VA(
    PMMPFN Pfn1,
    ULONG LockType)
{
    // HACK until we have proper WSLIST support
    PMMWSLE Wsle = &Pfn1->Wsle;

    if (!Wsle->u1.e1.LockedInWs &&
        !Wsle->u1.e1.LockedInMemory)
    {
        MiReferenceProbedPageAndBumpLockCount(Pfn1);
    }

    if (LockType & MAP_PROCESS)
        Wsle->u1.e1.LockedInWs = 1;
    if (LockType & MAP_SYSTEM)
        Wsle->u1.e1.LockedInMemory = 1;
}

FORCEINLINE
VOID
MI_UNLOCK_VA(
    PMMPFN Pfn1,
    ULONG LockType)
{
    // HACK until we have proper WSLIST support
    PMMWSLE Wsle = &Pfn1->Wsle;

    if (LockType & MAP_PROCESS)
        Wsle->u1.e1.LockedInWs = 0;
    if (LockType & MAP_SYSTEM)
        Wsle->u1.e1.LockedInMemory = 0;

    if (!Wsle->u1.e1.LockedInWs &&
        !Wsle->u1.e1.LockedInMemory)
    {
        MiDereferencePfnAndDropLockCount(Pfn1);
    }
}

static
NTSTATUS
MiCheckVadsForLockOperation(
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _Inout_ PVOID *EndAddress)

{
    PMMVAD Vad;
    PVOID CurrentVa;

    /* Get the base address and align the start address */
    *EndAddress = (PUCHAR)*BaseAddress + *RegionSize;
    *EndAddress = ALIGN_UP_POINTER_BY(*EndAddress, PAGE_SIZE);
    *BaseAddress = ALIGN_DOWN_POINTER_BY(*BaseAddress, PAGE_SIZE);

    /* First loop and check all VADs */
    CurrentVa = *BaseAddress;
    while (CurrentVa < *EndAddress)
    {
        /* Get VAD */
        Vad = MiLocateAddress(CurrentVa);
        if (Vad == NULL)
        {
            /// FIXME: this might be a memory area for a section view...
            return STATUS_ACCESS_VIOLATION;
        }

        /* Check VAD type */
        if ((Vad->u.VadFlags.VadType != VadNone) &&
            (Vad->u.VadFlags.VadType != VadImageMap) &&
            (Vad->u.VadFlags.VadType != VadWriteWatch))
        {
            *EndAddress = CurrentVa;
            *RegionSize = (PUCHAR)*EndAddress - (PUCHAR)*BaseAddress;
            return STATUS_INCOMPATIBLE_FILE_MAP;
        }

        CurrentVa = (PVOID)((Vad->EndingVpn + 1) << PAGE_SHIFT);
    }

    *RegionSize = (PUCHAR)*EndAddress - (PUCHAR)*BaseAddress;
    return STATUS_SUCCESS;
}

static
NTSTATUS
MiLockVirtualMemory(
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG MapType)
{
    PEPROCESS CurrentProcess;
    PMMSUPPORT AddressSpace;
    PVOID CurrentVa, EndAddress;
    PMMPTE PointerPte, LastPte;
    PMMPDE PointerPde;
#if (_MI_PAGING_LEVELS >= 3)
    PMMPDE PointerPpe;
#endif
#if (_MI_PAGING_LEVELS == 4)
    PMMPDE PointerPxe;
#endif
    PMMPFN Pfn1;
    NTSTATUS Status, TempStatus;

    /* Lock the address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* Make sure we still have an address space */
    CurrentProcess = PsGetCurrentProcess();
    if (CurrentProcess->VmDeleted)
    {
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Cleanup;
    }

    /* Check the VADs in the requested range */
    Status = MiCheckVadsForLockOperation(BaseAddress, RegionSize, &EndAddress);
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    /* Enter SEH for probing */
    _SEH2_TRY
    {
        /* Loop all pages and probe them */
        CurrentVa = *BaseAddress;
        while (CurrentVa < EndAddress)
        {
            (void)(*(volatile CHAR*)CurrentVa);
            CurrentVa = (PUCHAR)CurrentVa + PAGE_SIZE;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
        goto Cleanup;
    }
    _SEH2_END;

    /* All pages were accessible, since we hold the address space lock, nothing
       can be de-committed. Assume success for now. */
    Status = STATUS_SUCCESS;

    /* Get the PTE and PDE */
    PointerPte = MiAddressToPte(*BaseAddress);
    PointerPde = MiAddressToPde(*BaseAddress);
#if (_MI_PAGING_LEVELS >= 3)
    PointerPpe = MiAddressToPpe(*BaseAddress);
#endif
#if (_MI_PAGING_LEVELS == 4)
    PointerPxe = MiAddressToPxe(*BaseAddress);
#endif

    /* Get the last PTE */
    LastPte = MiAddressToPte((PVOID)((ULONG_PTR)EndAddress - 1));

    /* Lock the process working set */
    MiLockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

    /* Loop the pages */
    do
    {
        /* Check for a page that is not accessible */
        while (
#if (_MI_PAGING_LEVELS == 4)
               (PointerPxe->u.Hard.Valid == 0) ||
#endif
#if (_MI_PAGING_LEVELS >= 3)
               (PointerPpe->u.Hard.Valid == 0) ||
#endif
               (PointerPde->u.Hard.Valid == 0) ||
               (PointerPte->u.Hard.Valid == 0))
        {
            /* Release process working set */
            MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

            /* Access the page */
            CurrentVa = MiPteToAddress(PointerPte);

            //HACK: Pass a placeholder TrapInformation so the fault handler knows we're unlocked
            TempStatus = MmAccessFault(TRUE, CurrentVa, KernelMode, (PVOID)(ULONG_PTR)0xBADBADA3BADBADA3ULL);
            if (!NT_SUCCESS(TempStatus))
            {
                // This should only happen, when remote backing storage is not accessible
                ASSERT(FALSE);
                Status = TempStatus;
                goto Cleanup;
            }

            /* Lock the process working set */
            MiLockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());
        }

        /* Get the PFN */
        Pfn1 = MiGetPfnEntry(PFN_FROM_PTE(PointerPte));
        ASSERT(Pfn1 != NULL);

        /* Check the previous lock status */
        if (MI_IS_LOCKED_VA(Pfn1, MapType))
        {
            Status = STATUS_WAS_LOCKED;
        }

        /* Lock it */
        MI_LOCK_VA(Pfn1, MapType);

        /* Go to the next PTE */
        PointerPte++;

        /* Check if we're on a PDE boundary */
        if (MiIsPteOnPdeBoundary(PointerPte)) PointerPde++;
#if (_MI_PAGING_LEVELS >= 3)
        if (MiIsPteOnPpeBoundary(PointerPte)) PointerPpe++;
#endif
#if (_MI_PAGING_LEVELS == 4)
        if (MiIsPteOnPxeBoundary(PointerPte)) PointerPxe++;
#endif
    } while (PointerPte <= LastPte);

    /* Release process working set */
    MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

Cleanup:
    /* Unlock address space */
    MmUnlockAddressSpace(AddressSpace);

    return Status;
}

NTSTATUS
NTAPI
NtLockVirtualMemory(IN HANDLE ProcessHandle,
                    IN OUT PVOID *BaseAddress,
                    IN OUT PSIZE_T NumberOfBytesToLock,
                    IN ULONG MapType)
{
    PEPROCESS Process;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    NTSTATUS Status;
    BOOLEAN Attached = FALSE;
    KAPC_STATE ApcState;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PVOID CapturedBaseAddress;
    SIZE_T CapturedBytesToLock;
    PAGED_CODE();

    //
    // Validate flags
    //
    if ((MapType & ~(MAP_PROCESS | MAP_SYSTEM)))
    {
        //
        // Invalid set of flags
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // At least one flag must be specified
    //
    if (!(MapType & (MAP_PROCESS | MAP_SYSTEM)))
    {
        //
        // No flag given
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Enter SEH for probing
    //
    _SEH2_TRY
    {
        //
        // Validate output data
        //
        ProbeForWritePointer(BaseAddress);
        ProbeForWriteSize_t(NumberOfBytesToLock);

        //
        // Capture it
        //
        CapturedBaseAddress = *BaseAddress;
        CapturedBytesToLock = *NumberOfBytesToLock;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        //
        // Get exception code
        //
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    //
    // Catch illegal base address
    //
    if (CapturedBaseAddress > MM_HIGHEST_USER_ADDRESS) return STATUS_INVALID_PARAMETER;

    //
    // Catch illegal region size
    //
    if ((MmUserProbeAddress - (ULONG_PTR)CapturedBaseAddress) < CapturedBytesToLock)
    {
        //
        // Fail
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 0 is also illegal
    //
    if (!CapturedBytesToLock) return STATUS_INVALID_PARAMETER;

    //
    // Get a reference to the process
    //
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)(&Process),
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    //
    // Check if this is is system-mapped
    //
    if (MapType & MAP_SYSTEM)
    {
        //
        // Check for required privilege
        //
        if (!SeSinglePrivilegeCheck(SeLockMemoryPrivilege, PreviousMode))
        {
            //
            // Fail: Don't have it
            //
            ObDereferenceObject(Process);
            return STATUS_PRIVILEGE_NOT_HELD;
        }
    }

    //
    // Check if we should attach
    //
    if (CurrentProcess != Process)
    {
        //
        // Do it
        //
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    //
    // Call the internal function
    //
    Status = MiLockVirtualMemory(&CapturedBaseAddress,
                                 &CapturedBytesToLock,
                                 MapType);

    //
    // Detach if needed
    //
    if (Attached) KeUnstackDetachProcess(&ApcState);

    //
    // Release reference
    //
    ObDereferenceObject(Process);

    //
    // Enter SEH to return data
    //
    _SEH2_TRY
    {
        //
        // Return data to user
        //
        *BaseAddress = CapturedBaseAddress;
        *NumberOfBytesToLock = CapturedBytesToLock;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        //
        // Get exception code
        //
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    //
    // Return status
    //
    return Status;
}


static
NTSTATUS
MiUnlockVirtualMemory(
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG MapType)
{
    PEPROCESS CurrentProcess;
    PMMSUPPORT AddressSpace;
    PVOID EndAddress;
    PMMPTE PointerPte, LastPte;
    PMMPDE PointerPde;
#if (_MI_PAGING_LEVELS >= 3)
    PMMPDE PointerPpe;
#endif
#if (_MI_PAGING_LEVELS == 4)
    PMMPDE PointerPxe;
#endif
    PMMPFN Pfn1;
    NTSTATUS Status;

    /* Lock the address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* Make sure we still have an address space */
    CurrentProcess = PsGetCurrentProcess();
    if (CurrentProcess->VmDeleted)
    {
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Cleanup;
    }

    /* Check the VADs in the requested range */
    Status = MiCheckVadsForLockOperation(BaseAddress, RegionSize, &EndAddress);

    /* Note: only bail out, if we hit an area without a VAD. If we hit an
       incompatible VAD we continue, like Windows does */
    if (Status == STATUS_ACCESS_VIOLATION)
    {
        Status = STATUS_NOT_LOCKED;
        goto Cleanup;
    }

    /* Get the PTE and PDE */
    PointerPte = MiAddressToPte(*BaseAddress);
    PointerPde = MiAddressToPde(*BaseAddress);
#if (_MI_PAGING_LEVELS >= 3)
    PointerPpe = MiAddressToPpe(*BaseAddress);
#endif
#if (_MI_PAGING_LEVELS == 4)
    PointerPxe = MiAddressToPxe(*BaseAddress);
#endif

    /* Get the last PTE */
    LastPte = MiAddressToPte((PVOID)((ULONG_PTR)EndAddress - 1));

    /* Lock the process working set */
    MiLockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

    /* Loop the pages */
    do
    {
        /* Check for a page that is not present */
        if (
#if (_MI_PAGING_LEVELS == 4)
               (PointerPxe->u.Hard.Valid == 0) ||
#endif
#if (_MI_PAGING_LEVELS >= 3)
               (PointerPpe->u.Hard.Valid == 0) ||
#endif
               (PointerPde->u.Hard.Valid == 0) ||
               (PointerPte->u.Hard.Valid == 0))
        {
            /* Remember it, but keep going */
            Status = STATUS_NOT_LOCKED;
        }
        else
        {
            /* Get the PFN */
            Pfn1 = MiGetPfnEntry(PFN_FROM_PTE(PointerPte));
            ASSERT(Pfn1 != NULL);

            /* Check if all of the requested locks are present */
            if (((MapType & MAP_SYSTEM) && !MI_IS_LOCKED_VA(Pfn1, MAP_SYSTEM)) ||
                ((MapType & MAP_PROCESS) && !MI_IS_LOCKED_VA(Pfn1, MAP_PROCESS)))
            {
                /* Remember it, but keep going */
                Status = STATUS_NOT_LOCKED;

                /* Check if no lock is present */
                if (!MI_IS_LOCKED_VA(Pfn1, MAP_PROCESS | MAP_SYSTEM))
                {
                    DPRINT1("FIXME: Should remove the page from WS\n");
                }
            }
        }

        /* Go to the next PTE */
        PointerPte++;

        /* Check if we're on a PDE boundary */
        if (MiIsPteOnPdeBoundary(PointerPte)) PointerPde++;
#if (_MI_PAGING_LEVELS >= 3)
        if (MiIsPteOnPpeBoundary(PointerPte)) PointerPpe++;
#endif
#if (_MI_PAGING_LEVELS == 4)
        if (MiIsPteOnPxeBoundary(PointerPte)) PointerPxe++;
#endif
    } while (PointerPte <= LastPte);

    /* Check if we hit a page that was not locked */
    if (Status == STATUS_NOT_LOCKED)
    {
        goto CleanupWithWsLock;
    }

    /* All pages in the region were locked, so unlock them all */

    /* Get the PTE and PDE */
    PointerPte = MiAddressToPte(*BaseAddress);
    PointerPde = MiAddressToPde(*BaseAddress);
#if (_MI_PAGING_LEVELS >= 3)
    PointerPpe = MiAddressToPpe(*BaseAddress);
#endif
#if (_MI_PAGING_LEVELS == 4)
    PointerPxe = MiAddressToPxe(*BaseAddress);
#endif

    /* Loop the pages */
    do
    {
        /* Unlock it */
        Pfn1 = MiGetPfnEntry(PFN_FROM_PTE(PointerPte));
        MI_UNLOCK_VA(Pfn1, MapType);

        /* Go to the next PTE */
        PointerPte++;

        /* Check if we're on a PDE boundary */
        if (MiIsPteOnPdeBoundary(PointerPte)) PointerPde++;
#if (_MI_PAGING_LEVELS >= 3)
        if (MiIsPteOnPpeBoundary(PointerPte)) PointerPpe++;
#endif
#if (_MI_PAGING_LEVELS == 4)
        if (MiIsPteOnPxeBoundary(PointerPte)) PointerPxe++;
#endif
    } while (PointerPte <= LastPte);

    /* Everything is done */
    Status = STATUS_SUCCESS;

CleanupWithWsLock:

    /* Release process working set */
    MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

Cleanup:
    /* Unlock address space */
    MmUnlockAddressSpace(AddressSpace);

    return Status;
}


NTSTATUS
NTAPI
NtUnlockVirtualMemory(IN HANDLE ProcessHandle,
                      IN OUT PVOID *BaseAddress,
                      IN OUT PSIZE_T NumberOfBytesToUnlock,
                      IN ULONG MapType)
{
    PEPROCESS Process;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    NTSTATUS Status;
    BOOLEAN Attached = FALSE;
    KAPC_STATE ApcState;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PVOID CapturedBaseAddress;
    SIZE_T CapturedBytesToUnlock;
    PAGED_CODE();

    //
    // Validate flags
    //
    if ((MapType & ~(MAP_PROCESS | MAP_SYSTEM)))
    {
        //
        // Invalid set of flags
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // At least one flag must be specified
    //
    if (!(MapType & (MAP_PROCESS | MAP_SYSTEM)))
    {
        //
        // No flag given
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Enter SEH for probing
    //
    _SEH2_TRY
    {
        //
        // Validate output data
        //
        ProbeForWritePointer(BaseAddress);
        ProbeForWriteSize_t(NumberOfBytesToUnlock);

        //
        // Capture it
        //
        CapturedBaseAddress = *BaseAddress;
        CapturedBytesToUnlock = *NumberOfBytesToUnlock;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        //
        // Get exception code
        //
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    //
    // Catch illegal base address
    //
    if (CapturedBaseAddress > MM_HIGHEST_USER_ADDRESS) return STATUS_INVALID_PARAMETER;

    //
    // Catch illegal region size
    //
    if ((MmUserProbeAddress - (ULONG_PTR)CapturedBaseAddress) < CapturedBytesToUnlock)
    {
        //
        // Fail
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 0 is also illegal
    //
    if (!CapturedBytesToUnlock) return STATUS_INVALID_PARAMETER;

    //
    // Get a reference to the process
    //
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)(&Process),
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    //
    // Check if this is is system-mapped
    //
    if (MapType & MAP_SYSTEM)
    {
        //
        // Check for required privilege
        //
        if (!SeSinglePrivilegeCheck(SeLockMemoryPrivilege, PreviousMode))
        {
            //
            // Fail: Don't have it
            //
            ObDereferenceObject(Process);
            return STATUS_PRIVILEGE_NOT_HELD;
        }
    }

    //
    // Check if we should attach
    //
    if (CurrentProcess != Process)
    {
        //
        // Do it
        //
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    //
    // Call the internal function
    //
    Status = MiUnlockVirtualMemory(&CapturedBaseAddress,
                                   &CapturedBytesToUnlock,
                                   MapType);

    //
    // Detach if needed
    //
    if (Attached) KeUnstackDetachProcess(&ApcState);

    //
    // Release reference
    //
    ObDereferenceObject(Process);

    //
    // Enter SEH to return data
    //
    _SEH2_TRY
    {
        //
        // Return data to user
        //
        *BaseAddress = CapturedBaseAddress;
        *NumberOfBytesToUnlock = CapturedBytesToUnlock;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        //
        // Get exception code
        //
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Return what MiUnlockVirtualMemory reported */
    return Status;
}

NTSTATUS
NTAPI
NtFlushVirtualMemory(IN HANDLE ProcessHandle,
                     IN OUT PVOID *BaseAddress,
                     IN OUT PSIZE_T NumberOfBytesToFlush,
                     OUT PIO_STATUS_BLOCK IoStatusBlock)
{
    PEPROCESS Process;
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PVOID CapturedBaseAddress;
    SIZE_T CapturedBytesToFlush;
    IO_STATUS_BLOCK LocalStatusBlock;
    PAGED_CODE();

    //
    // Check if we came from user mode
    //
    if (PreviousMode != KernelMode)
    {
        //
        // Enter SEH for probing
        //
        _SEH2_TRY
        {
            //
            // Validate all outputs
            //
            ProbeForWritePointer(BaseAddress);
            ProbeForWriteSize_t(NumberOfBytesToFlush);
            ProbeForWriteIoStatusBlock(IoStatusBlock);

            //
            // Capture them
            //
            CapturedBaseAddress = *BaseAddress;
            CapturedBytesToFlush = *NumberOfBytesToFlush;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Get exception code
            //
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        //
        // Capture directly
        //
        CapturedBaseAddress = *BaseAddress;
        CapturedBytesToFlush = *NumberOfBytesToFlush;
    }

    //
    // Catch illegal base address
    //
    if (CapturedBaseAddress > MM_HIGHEST_USER_ADDRESS) return STATUS_INVALID_PARAMETER;

    //
    // Catch illegal region size
    //
    if ((MmUserProbeAddress - (ULONG_PTR)CapturedBaseAddress) < CapturedBytesToFlush)
    {
        //
        // Fail
        //
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Get a reference to the process
    //
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)(&Process),
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    //
    // Do it
    //
    Status = MmFlushVirtualMemory(Process,
                                  &CapturedBaseAddress,
                                  &CapturedBytesToFlush,
                                  &LocalStatusBlock);

    //
    // Release reference
    //
    ObDereferenceObject(Process);

    //
    // Enter SEH to return data
    //
    _SEH2_TRY
    {
        //
        // Return data to user
        //
        *BaseAddress = PAGE_ALIGN(CapturedBaseAddress);
        *NumberOfBytesToFlush = 0;
        *IoStatusBlock = LocalStatusBlock;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;

    //
    // Return status
    //
    return Status;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
NtGetWriteWatch(IN HANDLE ProcessHandle,
                IN ULONG Flags,
                IN PVOID BaseAddress,
                IN SIZE_T RegionSize,
                IN PVOID *UserAddressArray,
                OUT PULONG_PTR EntriesInUserAddressArray,
                OUT PULONG Granularity)
{
    PEPROCESS Process;
    NTSTATUS Status;
    PVOID EndAddress;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    ULONG_PTR CapturedEntryCount;
    PAGED_CODE();

    //
    // Check if we came from user mode
    //
    if (PreviousMode != KernelMode)
    {
        //
        // Enter SEH for probing
        //
        _SEH2_TRY
        {
            //
            // Catch illegal base address
            //
            if (BaseAddress > MM_HIGHEST_USER_ADDRESS) _SEH2_YIELD(return STATUS_INVALID_PARAMETER_2);

            //
            // Catch illegal region size
            //
            if ((MmUserProbeAddress - (ULONG_PTR)BaseAddress) < RegionSize)
            {
                //
                // Fail
                //
                _SEH2_YIELD(return STATUS_INVALID_PARAMETER_3);
            }

            //
            // Validate all data
            //
            ProbeForWriteSize_t(EntriesInUserAddressArray);
            ProbeForWriteUlong(Granularity);

            //
            // Capture them
            //
            CapturedEntryCount = *EntriesInUserAddressArray;

            //
            // Must have a count
            //
            if (CapturedEntryCount == 0) _SEH2_YIELD(return STATUS_INVALID_PARAMETER_5);

            //
            // Can't be larger than the maximum
            //
            if (CapturedEntryCount > (MAXULONG_PTR / sizeof(ULONG_PTR)))
            {
                //
                // Fail
                //
                _SEH2_YIELD(return STATUS_INVALID_PARAMETER_5);
            }

            //
            // Probe the actual array
            //
            ProbeForWrite(UserAddressArray,
                          CapturedEntryCount * sizeof(PVOID),
                          sizeof(PVOID));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Get exception code
            //
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        //
        // Capture directly
        //
        CapturedEntryCount = *EntriesInUserAddressArray;
        ASSERT(CapturedEntryCount != 0);
    }

    //
    // Check if this is a local request
    //
    if (ProcessHandle == NtCurrentProcess())
    {
        //
        // No need to reference the process
        //
        Process = PsGetCurrentProcess();
    }
    else
    {
        //
        // Reference the target
        //
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_OPERATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status)) return Status;
    }

    //
    // Compute the last address and validate it
    //
    EndAddress = (PVOID)((ULONG_PTR)BaseAddress + RegionSize - 1);
    if (BaseAddress > EndAddress)
    {
        //
        // Fail
        //
        if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);
        return STATUS_INVALID_PARAMETER_4;
    }

    //
    // Oops :(
    //
    UNIMPLEMENTED;

    //
    // Dereference if needed
    //
    if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);

    //
    // Enter SEH to return data
    //
    _SEH2_TRY
    {
        //
        // Return data to user
        //
        *EntriesInUserAddressArray = 0;
        *Granularity = PAGE_SIZE;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        //
        // Get exception code
        //
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    //
    // Return success
    //
    return STATUS_SUCCESS;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
NtResetWriteWatch(IN HANDLE ProcessHandle,
                  IN PVOID BaseAddress,
                  IN SIZE_T RegionSize)
{
    PVOID EndAddress;
    PEPROCESS Process;
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    ASSERT (KeGetCurrentIrql() == PASSIVE_LEVEL);

    //
    // Catch illegal base address
    //
    if (BaseAddress > MM_HIGHEST_USER_ADDRESS) return STATUS_INVALID_PARAMETER_2;

    //
    // Catch illegal region size
    //
    if ((MmUserProbeAddress - (ULONG_PTR)BaseAddress) < RegionSize)
    {
        //
        // Fail
        //
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // Check if this is a local request
    //
    if (ProcessHandle == NtCurrentProcess())
    {
        //
        // No need to reference the process
        //
        Process = PsGetCurrentProcess();
    }
    else
    {
        //
        // Reference the target
        //
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_OPERATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status)) return Status;
    }

    //
    // Compute the last address and validate it
    //
    EndAddress = (PVOID)((ULONG_PTR)BaseAddress + RegionSize - 1);
    if (BaseAddress > EndAddress)
    {
        //
        // Fail
        //
        if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // Oops :(
    //
    UNIMPLEMENTED;

    //
    // Dereference if needed
    //
    if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);

    //
    // Return success
    //
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NtQueryVirtualMemory(IN HANDLE ProcessHandle,
                     IN PVOID BaseAddress,
                     IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
                     OUT PVOID MemoryInformation,
                     IN SIZE_T MemoryInformationLength,
                     OUT PSIZE_T ReturnLength)
{
    NTSTATUS Status = STATUS_SUCCESS;
    KPROCESSOR_MODE PreviousMode;

    DPRINT("Querying class %d about address: %p\n", MemoryInformationClass, BaseAddress);

    /* Windows 10 refuses an unknown class before looking at anything else (even the process
     * handle or a kernel address). Classes it has but this kernel does not (working set list,
     * shared commit, region and privileged basic ex, physical contiguity, bad information) are
     * refused the same way instead of reporting success without writing anything. */
    switch ((ULONG)MemoryInformationClass)
    {
        case MemoryBasicInformation:
        case MemorySectionName:
        case MemoryRegionInformation:
        case MI_MEMORY_WORKING_SET_EX_CLASS:
        case MI_MEMORY_IMAGE_CLASS:
        case MI_MEMORY_WORKING_SET_CLASS:
        case MI_MEMORY_SHARED_COMMIT_CLASS:
        case MI_MEMORY_REGION_EX_CLASS:
        case MI_MEMORY_PRIVILEGED_BASIC_CLASS:
            break;

        default:
            DPRINT1("Unsupported memory information class %d\n", MemoryInformationClass);
            return STATUS_INVALID_INFO_CLASS;
    }

    /* MemoryRegionInformation checks its length first (Windows 10), even for a kernel address; so do the
     * classes 1, 5, 7 and 8 (measured, 22H2) */
    switch ((ULONG)MemoryInformationClass)
    {
        case MemoryRegionInformation:
            if (MemoryInformationLength < FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
                return STATUS_INFO_LENGTH_MISMATCH;
            break;
        case MI_MEMORY_REGION_EX_CLASS:
            if (MemoryInformationLength < FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
                return STATUS_INFO_LENGTH_MISMATCH;
            break;
        case MI_MEMORY_PRIVILEGED_BASIC_CLASS:
            if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION))
                return STATUS_INFO_LENGTH_MISMATCH;
            break;
        case MI_MEMORY_SHARED_COMMIT_CLASS:
            if (MemoryInformationLength < sizeof(SIZE_T))
                return STATUS_INFO_LENGTH_MISMATCH;
            break;
        case MI_MEMORY_WORKING_SET_CLASS:
            if (MemoryInformationLength < sizeof(ULONG_PTR))
                return STATUS_INFO_LENGTH_MISMATCH;
            break;
        default:
            break;
    }

    /* Bail out if the address is invalid */
    if (BaseAddress > MM_HIGHEST_USER_ADDRESS) return STATUS_INVALID_PARAMETER;

    /* Probe return buffer */
    PreviousMode =  ExGetPreviousMode();
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWrite(MemoryInformation,
                          MemoryInformationLength,
                          sizeof(ULONG_PTR));

            if (ReturnLength) ProbeForWriteSize_t(ReturnLength);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    switch ((ULONG)MemoryInformationClass)
    {
        case MemoryBasicInformation:
            /* Validate the size information of the class */
            if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION))
            {
                /* The size is invalid */
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            Status = MiQueryMemoryBasicInformation(ProcessHandle,
                                                   BaseAddress,
                                                   MemoryInformation,
                                                   MemoryInformationLength,
                                                   ReturnLength);
            break;

        case MemorySectionName:
            /* The length is checked once the address is known to be backed by a file (Windows 10) */
            Status = MiQueryMemorySectionName(ProcessHandle,
                                              BaseAddress,
                                              MemoryInformation,
                                              MemoryInformationLength,
                                              ReturnLength);
            break;
        case MemoryRegionInformation:
            /* The length was validated before the address, as Windows does */
            Status = MiQueryMemoryRegionInformation(ProcessHandle,
                                                    BaseAddress,
                                                    MemoryInformation,
                                                    MemoryInformationLength,
                                                    ReturnLength,
                                                    FALSE);
            break;

        case MI_MEMORY_REGION_EX_CLASS:
            Status = MiQueryMemoryRegionInformation(ProcessHandle,
                                                    BaseAddress,
                                                    MemoryInformation,
                                                    MemoryInformationLength,
                                                    ReturnLength,
                                                    TRUE);
            break;

        case MI_MEMORY_PRIVILEGED_BASIC_CLASS:
            /* The same answer as MemoryBasicInformation (measured on every kind of address) */
            Status = MiQueryMemoryBasicInformation(ProcessHandle,
                                                   BaseAddress,
                                                   MemoryInformation,
                                                   MemoryInformationLength,
                                                   ReturnLength);
            break;

        case MI_MEMORY_SHARED_COMMIT_CLASS:
            Status = MiQueryMemorySharedCommit(ProcessHandle, MemoryInformation, ReturnLength);
            break;

        case MI_MEMORY_WORKING_SET_CLASS:
            Status = MiQueryMemoryWorkingSetList(ProcessHandle,
                                                 MemoryInformation,
                                                 MemoryInformationLength,
                                                 ReturnLength);
            break;

        case MI_MEMORY_WORKING_SET_EX_CLASS:
            /* One entry is the least; the input array lives in the buffer */
            if (MemoryInformationLength < sizeof(MI_WS_EX_ENTRY))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            Status = MiQueryMemoryWorkingSetEx(ProcessHandle,
                                               MemoryInformation,
                                               MemoryInformationLength,
                                               ReturnLength);
            break;

        case MI_MEMORY_IMAGE_CLASS:
            if (MemoryInformationLength < MI_IMAGE_INFORMATION_SIZE)
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            Status = MiQueryMemoryImageInformation(ProcessHandle,
                                                   BaseAddress,
                                                   MemoryInformation,
                                                   ReturnLength);
            break;

        default:
            ASSERT(FALSE);
            Status = STATUS_INVALID_INFO_CLASS;
            break;
    }

    return Status;
}

/*
 * NtAllocateVirtualMemory and NtAllocateVirtualMemoryEx.
 *
 * Ex only: LowestAddress, HighestRequired and Alignment come from a MEM_ADDRESS_REQUIREMENTS
 * (0 when not given) and bound an automatic placement; MEM_RESERVE_PLACEHOLDER reserves a
 * placeholder, MEM_REPLACE_PLACEHOLDER turns a whole free placeholder into a private allocation
 * (reserved, or committed with MEM_COMMIT) at the placeholder's address and of its size.
 */
static
NTSTATUS
MiAllocateVirtualMemory(IN HANDLE ProcessHandle,
                        IN OUT PVOID* UBaseAddress,
                        IN ULONG_PTR ZeroBits,
                        IN OUT PSIZE_T URegionSize,
                        IN ULONG AllocationType,
                        IN ULONG Protect,
                        IN ULONG_PTR LowestAddress,
                        IN ULONG_PTR HighestRequired,
                        IN ULONG_PTR Alignment,
                        IN BOOLEAN IsEx,
                        IN PVOID CapturedBase,
                        IN SIZE_T CapturedSize)
{
    MI_COMMIT_TIER CommitTier = MiCommitUser;
    BOOLEAN PagerCommit = FALSE;
    PEPROCESS Process;
    PMMVAD Vad = NULL, FoundVad;
    NTSTATUS Status;
    PMMSUPPORT AddressSpace;
    PVOID PBaseAddress;
    ULONG_PTR PRegionSize, StartingAddress, EndingAddress;
    ULONG_PTR HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    PETHREAD CurrentThread = PsGetCurrentThread();
    KAPC_STATE ApcState;
    ULONG ProtectionMask, QuotaCharge = 0, QuotaFree = 0, GrowthRounds = 0;
    SIZE_T CommitPages = 0;
    BOOLEAN Attached = FALSE, ChangeProtection = FALSE, QuotaCharged = FALSE;
    MMPTE TempPte;
    PMMPTE PointerPte, LastPte;
    PMMPDE PointerPde;
    TABLE_SEARCH_RESULT Result;
    PAGED_CODE();

    /* The call target bit goes with an execute protection only, and has no effect here */
    if (!MiStripTargetsFlag(&Protect)) return STATUS_INVALID_PAGE_PROTECTION;

    /* Check for valid Zero bits */
    if (!MiZeroBitsToHighestAddress(ZeroBits, &HighestAddress) ||
        (ZeroBits > 32 && ZeroBits < MM_VIRTMEM_GRANULARITY - 1))
    {
        DPRINT1("Too many zero bits\n");
        return MI_PARAM_STATUS(3);
    }

    /* Placeholders need the Ex service (Windows: STATUS_INVALID_PARAMETER without it) */
    if (AllocationType & (MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        if (!IsEx)
        {
            DPRINT1("Placeholder flags without NtAllocateVirtualMemoryEx\n");
            return STATUS_INVALID_PARAMETER;
        }

        /* A replacement is a reservation of a placeholder's whole range, maybe committed */
        if ((AllocationType & MEM_REPLACE_PLACEHOLDER) &&
            (!(AllocationType & MEM_RESERVE) || (AllocationType & MEM_RESERVE_PLACEHOLDER)))
        {
            return STATUS_INVALID_PARAMETER;
        }

        /* A placeholder is reserved, not committed, and has no access */
        if ((AllocationType & MEM_RESERVE_PLACEHOLDER) &&
            (!(AllocationType & MEM_RESERVE) || (AllocationType & MEM_COMMIT) || (Protect != PAGE_NOACCESS)))
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (AllocationType & (MEM_PHYSICAL | MEM_LARGE_PAGES | MEM_RESET))
            return STATUS_INVALID_PARAMETER;
    }

    /* Check for valid Allocation Types */
    if ((AllocationType & ~(MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_PHYSICAL |
                    MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_LARGE_PAGES |
                    MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER)))
    {
        DPRINT1("Invalid Allocation Type\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* Check for at least one of these Allocation Types to be set */
    if (!(AllocationType & (MEM_COMMIT | MEM_RESERVE | MEM_RESET)))
    {
        DPRINT1("No memory allocation base type\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* MEM_RESET is an exclusive flag, make sure that is valid too */
    if ((AllocationType & MEM_RESET) && (AllocationType != MEM_RESET))
    {
        DPRINT1("Invalid use of MEM_RESET\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* Check if large pages are being used */
    if (AllocationType & MEM_LARGE_PAGES)
    {
        /* Large page allocations MUST be committed */
        if (!(AllocationType & MEM_COMMIT))
        {
            DPRINT1("Must supply MEM_COMMIT with MEM_LARGE_PAGES\n");
            return STATUS_INVALID_PARAMETER_5;
        }

        /* These flags are not allowed with large page allocations */
        if (AllocationType & (MEM_PHYSICAL | MEM_RESET | MEM_WRITE_WATCH))
        {
            DPRINT1("Using illegal flags with MEM_LARGE_PAGES\n");
            return STATUS_INVALID_PARAMETER_5;
        }
    }

    /* MEM_WRITE_WATCH can only be used if MEM_RESERVE is also used */
    if ((AllocationType & MEM_WRITE_WATCH) && !(AllocationType & MEM_RESERVE))
    {
        DPRINT1("MEM_WRITE_WATCH used without MEM_RESERVE\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* Check for valid MEM_PHYSICAL usage */
    if (AllocationType & MEM_PHYSICAL)
    {
        /* MEM_PHYSICAL can only be used if MEM_RESERVE is also used */
        if (!(AllocationType & MEM_RESERVE))
        {
            DPRINT1("MEM_PHYSICAL used without MEM_RESERVE\n");
            return STATUS_INVALID_PARAMETER_5;
        }

        /* Only these flags are allowed with MEM_PHYSIAL */
        if (AllocationType & ~(MEM_RESERVE | MEM_TOP_DOWN | MEM_PHYSICAL))
        {
            DPRINT1("Using illegal flags with MEM_PHYSICAL\n");
            return STATUS_INVALID_PARAMETER_5;
        }

        /* Then make sure PAGE_READWRITE is used */
        if (Protect != PAGE_READWRITE)
        {
            DPRINT1("MEM_PHYSICAL used without PAGE_READWRITE\n");
            return STATUS_INVALID_PARAMETER_6;
        }
    }

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(Protect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("Invalid protection mask\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Check for user-mode parameters */
        if (PreviousMode != KernelMode)
        {
            /* Make sure they are writable */
            ProbeForWritePointer(UBaseAddress);
            ProbeForWriteSize_t(URegionSize);
        }

        /* Capture their values; the Ex service checked its own capture, which must be the one used */
        if (IsEx)
        {
            PBaseAddress = CapturedBase;
            PRegionSize = CapturedSize;
        }
        else
        {
            PBaseAddress = *UBaseAddress;
            PRegionSize = *URegionSize;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Return the exception code */
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Make sure the allocation isn't past the VAD area */
    if (PBaseAddress > MM_HIGHEST_VAD_ADDRESS)
    {
        DPRINT1("Virtual allocation base above User Space\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    /* Make sure the allocation wouldn't overflow past the VAD area */
    if ((((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS + 1) - (ULONG_PTR)PBaseAddress) < PRegionSize)
    {
        DPRINT1("Region size would overflow into kernel-memory\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Make sure there's a size specified */
    if (!PRegionSize)
    {
        DPRINT1("Region size is invalid (zero)\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    //
    // If this is for the current process, just use PsGetCurrentProcess
    //
    if (ProcessHandle == NtCurrentProcess())
    {
        Process = CurrentProcess;
    }
    else
    {
        //
        // Otherwise, reference the process with VM rights and attach to it if
        // this isn't the current process. We must attach because we'll be touching
        // PTEs and PDEs that belong to user-mode memory, and also touching the
        // Working Set which is stored in Hyperspace.
        //
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_OPERATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status)) return Status;
        if (CurrentProcess != Process)
        {
            KeStackAttachProcess(&Process->Pcb, &ApcState);
            Attached = TRUE;
        }
    }

    DPRINT("NtAllocateVirtualMemory: Process 0x%p, Address 0x%p, Zerobits %lu , RegionSize 0x%x, Allocation type 0x%x, Protect 0x%x.\n",
        Process, PBaseAddress, ZeroBits, PRegionSize, AllocationType, Protect);

    //
    // Check for large page allocations and make sure that the required privilege
    // is being held, before attempting to handle them.
    //
    if ((AllocationType & MEM_LARGE_PAGES) &&
        !(SeSinglePrivilegeCheck(SeLockMemoryPrivilege, PreviousMode)))
    {
        /* Fail without it */
        DPRINT1("Privilege not held for MEM_LARGE_PAGES\n");
        Status = STATUS_PRIVILEGE_NOT_HELD;
        goto FailPathNoLock;
    }

    //
    // Fail on the things we don't yet support
    //
    if ((AllocationType & MEM_LARGE_PAGES) == MEM_LARGE_PAGES)
    {
        DPRINT1("MEM_LARGE_PAGES not supported\n");
        Status = STATUS_INVALID_PARAMETER;
        goto FailPathNoLock;
    }
    if ((AllocationType & MEM_PHYSICAL) == MEM_PHYSICAL)
    {
        DPRINT1("MEM_PHYSICAL not supported\n");
        Status = STATUS_INVALID_PARAMETER;
        goto FailPathNoLock;
    }
    if ((AllocationType & MEM_WRITE_WATCH) == MEM_WRITE_WATCH)
    {
        DPRINT1("MEM_WRITE_WATCH not supported\n");
        Status = STATUS_INVALID_PARAMETER;
        goto FailPathNoLock;
    }

    //
    // MEM_REPLACE_PLACEHOLDER: the free placeholder at this address, exactly this size, becomes
    // a private allocation in place
    //
    if (AllocationType & MEM_REPLACE_PLACEHOLDER)
    {
        if (Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))
        {
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto FailPathNoLock;
        }
        if (!PBaseAddress)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto FailPathNoLock;
        }

        /* A placeholder starts on a page, not on an allocation granule */
        StartingAddress = (ULONG_PTR)PAGE_ALIGN(PBaseAddress);
        EndingAddress = ((ULONG_PTR)PBaseAddress + PRegionSize - 1) | (PAGE_SIZE - 1);
        PRegionSize = EndingAddress - StartingAddress + 1;

        /*
         * A committed replacement is charged before anything changes. A placeholder is
         * private memory with no charge: it is charged as pageable when the pager backs
         * commitment now, and marked so below (P4)
         */
        if (AllocationType & MEM_COMMIT)
        {
            CommitPages = BYTES_TO_PAGES(PRegionSize);
            PagerCommit = MiPagerBacksCommit();
            if (!MiChargeCommitWithGrowthEx(CommitPages, PagerCommit ? MiCommitUserPrivate : MiCommitUser))
            {
                Status = STATUS_COMMITMENT_LIMIT;
                goto FailPathNoLock;
            }
        }

        AddressSpace = MmGetCurrentAddressSpace();
        MmLockAddressSpace(AddressSpace);
        if (Process->VmDeleted)
        {
            Status = STATUS_PROCESS_IS_TERMINATING;
        }
        else if (!(FoundVad = MiLocateAddress((PVOID)StartingAddress)))
        {
            Status = STATUS_INVALID_PARAMETER;
        }
        else if ((FoundVad->StartingVpn != (StartingAddress >> PAGE_SHIFT)) ||
                 (FoundVad->EndingVpn != (EndingAddress >> PAGE_SHIFT)))
        {
            Status = STATUS_CONFLICTING_ADDRESSES;
        }
        else if (!MI_IS_PLACEHOLDER_VAD(FoundVad) || MI_IS_MEMORY_AREA_VAD(FoundVad))
        {
            Status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            /* The placeholder never had pages: only its flags change */
            MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
            FoundVad->u2.VadFlags2.Placeholder = 0;
            FoundVad->u2.VadFlags2.FromPlaceholder = 1;
            FoundVad->u.VadFlags.Protection = ProtectionMask;
            if (AllocationType & MEM_COMMIT)
            {
                ASSERT(FoundVad->u.VadFlags.CommitCharge == 0);
                FoundVad->u2.VadFlags2.PagerCommit = PagerCommit;
                FoundVad->u.VadFlags.MemCommit = 1;
                FoundVad->u.VadFlags.CommitCharge = CommitPages;
                MiAddProcessCommit(Process, CommitPages);
                CommitPages = 0;
            }
            MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);
            Status = STATUS_SUCCESS;
        }
        MmUnlockAddressSpace(AddressSpace);

        /* What was charged for a replacement that did not happen goes back */
        if (PagerCommit)
            MiReturnPrivateCommitCredit(CommitPages);
        MiReturnCommit(CommitPages);

        /* On success the exit path writes StartingAddress and PRegionSize back to the caller */
        goto FailPathNoLock;
    }

    //
    // Check if the caller is reserving memory, or committing memory and letting
    // us pick the base address
    //
    if (!(PBaseAddress) || (AllocationType & MEM_RESERVE))
    {
        //
        //  Do not allow COPY_ON_WRITE through this API
        //
        if (Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))
        {
            DPRINT1("Copy on write not allowed through this path\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto FailPathNoLock;
        }

        //
        // Does the caller have an address in mind, or is this a blind commit?
        //
        if (!PBaseAddress)
        {
            //
            // This is a blind commit, all we need is the region size
            //
            PRegionSize = ROUND_TO_PAGES(PRegionSize);
            EndingAddress = 0;
            StartingAddress = 0;

            /* An address requirement bounds the placement */
            if (HighestRequired && (HighestRequired < HighestAddress))
                HighestAddress = HighestRequired;

        }
        else
        {
            //
            // This is a reservation, so compute the starting address on the
            // expected 64KB granularity, and see where the ending address will
            // fall based on the aligned address and the passed in region size
            //
            EndingAddress = ((ULONG_PTR)PBaseAddress + PRegionSize - 1) | (PAGE_SIZE - 1);
            PRegionSize = EndingAddress + 1 - ROUND_DOWN((ULONG_PTR)PBaseAddress, _64K);
            StartingAddress = (ULONG_PTR)PBaseAddress;

            /* ZeroBits only limits automatic placement for allocations. */
            HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
        }

        // Charge quotas for the VAD
        Status = PsChargeProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Quota exceeded.\n");
            goto FailPathNoLock;
        }

        QuotaCharged = TRUE;

        //
        // Allocate and initialize the VAD
        //
        Vad = ExAllocatePoolWithTag(NonPagedPool, sizeof(MMVAD_LONG), 'SdaV');
        if (Vad == NULL)
        {
            DPRINT1("Failed to allocate a VAD!\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto FailPathNoLock;
        }

        RtlZeroMemory(Vad, sizeof(MMVAD_LONG));
        if (AllocationType & MEM_COMMIT) Vad->u.VadFlags.MemCommit = 1;
        Vad->u.VadFlags.Protection = ProtectionMask;
        Vad->u.VadFlags.PrivateMemory = 1;
        Vad->ControlArea = NULL; // For Memory-Area hack
        if (AllocationType & MEM_RESERVE_PLACEHOLDER) Vad->u2.VadFlags2.Placeholder = 1;

        //
        // A committed reservation is charged in full before the VAD is
        // published; inserting it moves the charge to the process
        //
        if (AllocationType & MEM_COMMIT)
        {
            /* A new private VAD (VadNone): its commitment is pageable when the pager backs it now (P4) */
            CommitPages = BYTES_TO_PAGES(PRegionSize);
            MI_DECIDE_PAGER_COMMIT_VAD(Vad);
            if (!MiChargeCommitWithGrowthEx(CommitPages, MI_VAD_COMMIT_TIER(Vad)))
            {
                DPRINT1("Commit limit reached for %Iu pages\n", CommitPages);
                ExFreePoolWithTag(Vad, 'SdaV');
                Status = STATUS_COMMITMENT_LIMIT;
                goto FailPathNoLock;
            }
        }

        //
        // Insert the VAD
        //
        Status = MiInsertVadEx2(Vad,
                                &StartingAddress,
                                PRegionSize,
                                StartingAddress ? 0 : LowestAddress,
                                HighestAddress,
                                StartingAddress ? MM_VIRTMEM_GRANULARITY : max(Alignment, MM_VIRTMEM_GRANULARITY),
                                AllocationType & ~MEM_REPLACE_PLACEHOLDER,
                                !IsEx);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to insert the VAD!\n");
            if (MI_IS_PAGER_COMMIT_VAD(Vad))
                MiReturnPrivateCommitCredit(CommitPages);
            MiReturnCommit(CommitPages);
            ExFreePoolWithTag(Vad, 'SdaV');
            goto FailPathNoLock;
        }

        //
        // Detach and dereference the target process if
        // it was different from the current process
        //
        if (Attached) KeUnstackDetachProcess(&ApcState);
        if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);

        //
        // Use SEH to write back the base address and the region size. In the case
        // of an exception, we do not return back the exception code, as the memory
        // *has* been allocated. The caller would now have to call VirtualQuery
        // or do some other similar trick to actually find out where its memory
        // allocation ended up
        //
        _SEH2_TRY
        {
            *URegionSize = PRegionSize;
            *UBaseAddress = (PVOID)StartingAddress;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Ignore exception!
            //
        }
        _SEH2_END;
        DPRINT("Reserved %x bytes at %p.\n", PRegionSize, StartingAddress);
        return STATUS_SUCCESS;
    }

    //
    // This is a MEM_COMMIT on top of an existing address which must have been
    // MEM_RESERVED already. Compute the start and ending base addresses based
    // on the user input, and then compute the actual region size once all the
    // alignments have been done.
    //
    EndingAddress = (((ULONG_PTR)PBaseAddress + PRegionSize - 1) | (PAGE_SIZE - 1));
    StartingAddress = (ULONG_PTR)PAGE_ALIGN(PBaseAddress);
    PRegionSize = EndingAddress - StartingAddress + 1;

    //
    // Lock the address space and make sure the process isn't already dead.
    // After waiting for the commit limit to grow, everything is looked up and
    // counted again.
    //
RetryCommit:
    QuotaCharge = 0;
    QuotaFree = 0;
    ChangeProtection = FALSE;
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);
    if (Process->VmDeleted)
    {
        DPRINT1("Process is dying\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto FailPath;
    }

    //
    // Get the VAD for this address range, and make sure it exists
    //
    Result = MiCheckForConflictingNode(StartingAddress >> PAGE_SHIFT,
                                       EndingAddress >> PAGE_SHIFT,
                                       &Process->VadRoot,
                                       (PMMADDRESS_NODE*)&FoundVad);
    if (Result != TableFoundNode)
    {
        DPRINT1("Could not find a VAD for this allocation\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    //
    // A free placeholder cannot be committed: it has to be replaced first
    //
    if (MI_IS_PLACEHOLDER_VAD(FoundVad) && !MI_IS_MEMORY_AREA_VAD(FoundVad))
    {
        DPRINT1("Attempt to commit a placeholder\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    if ((AllocationType & MEM_RESET) == MEM_RESET)
    {
        /// @todo HACK: pretend success
        DPRINT("MEM_RESET not supported\n");
        Status = STATUS_SUCCESS;
        goto FailPath;
    }

    //
    // These kinds of VADs are illegal for this Windows function when trying to
    // commit an existing range
    //
    if ((FoundVad->u.VadFlags.VadType == VadAwe) ||
        (FoundVad->u.VadFlags.VadType == VadDevicePhysicalMemory) ||
        (FoundVad->u.VadFlags.VadType == VadLargePages))
    {
        DPRINT1("Illegal VAD for attempting a MEM_COMMIT\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    //
    // Make sure that this address range actually fits within the VAD for it
    //
    if (((StartingAddress >> PAGE_SHIFT) < FoundVad->StartingVpn) ||
        ((EndingAddress >> PAGE_SHIFT) > FoundVad->EndingVpn))
    {
        DPRINT1("Address range does not fit into the VAD\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto FailPath;
    }

    //
    // Make sure this is an ARM3 section
    //
    if (MI_IS_ROSMM_VAD(FoundVad))
    {
        DPRINT1("Illegal commit of non-ARM3 section!\n");
        Status = STATUS_ALREADY_COMMITTED;
        goto FailPath;
    }

    // Is this a previously reserved section being committed? If so, enter the
    // special section path
    //
    if (FoundVad->u.VadFlags.PrivateMemory == FALSE)
    {
        //
        // You cannot commit large page sections through this API
        //
        if (FoundVad->u.VadFlags.VadType == VadLargePageSection)
        {
            DPRINT1("Large page sections cannot be VirtualAlloc'd\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto FailPath;
        }

        //
        // You can only use caching flags on a rotate VAD
        //
        if ((Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE)) &&
            (FoundVad->u.VadFlags.VadType != VadRotatePhysical))
        {
            DPRINT1("Cannot use caching flags with anything but rotate VADs\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto FailPath;
        }

        //
        // We should make sure that the section's permissions aren't being
        // messed with
        //
        if (FoundVad->u.VadFlags.NoChange)
        {
            //
            // Make sure it's okay to touch it
            // Note: The Windows 2003 kernel has a bug here, passing the
            // unaligned base address together with the aligned size,
            // potentially covering a region larger than the actual allocation.
            // Might be exposed through NtGdiCreateDIBSection w/ section handle
            // For now we keep this behavior.
            // TODO: analyze possible implications, create test case
            //
            Status = MiCheckSecuredVad(FoundVad,
                                       PBaseAddress,
                                       PRegionSize,
                                       ProtectionMask);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("Secured VAD being messed around with\n");
                goto FailPath;
            }
        }

        //
        // ARM3 does not support file-backed sections, only shared memory
        //
        ASSERT(FoundVad->ControlArea->FilePointer == NULL);

        //
        // Rotate VADs cannot be guard pages or inaccessible, nor copy on write
        //
        if ((FoundVad->u.VadFlags.VadType == VadRotatePhysical) &&
            (Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY | PAGE_NOACCESS | PAGE_GUARD)))
        {
            DPRINT1("Invalid page protection for rotate VAD\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto FailPath;
        }

        //
        // Compute PTE addresses and the quota charge, then grab the commit lock
        //
        PointerPte = MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, StartingAddress >> PAGE_SHIFT);
        LastPte = MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, EndingAddress >> PAGE_SHIFT);
        QuotaCharge = (ULONG)(LastPte - PointerPte + 1);
        KeAcquireGuardedMutexUnsafe(&MmSectionCommitMutex);

        //
        // Charge exactly the prototype PTEs that are not committed yet. If the
        // limit is reached, wait for a paging file to grow without any lock
        // held, then look everything up again.
        //
        CommitPages = 0;
        for (PMMPTE ProtoPte = PointerPte; ProtoPte <= LastPte; ProtoPte++)
        {
            if (ProtoPte->u.Long == 0) CommitPages++;
        }
        if (!MiChargeCommit(CommitPages, MiCommitUser))
        {
            KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);
            MmUnlockAddressSpace(AddressSpace);
            if ((GrowthRounds++ < 4) && !KeAreAllApcsDisabled() && MiWaitForCommitGrowth(CommitPages))
                goto RetryCommit;

            DPRINT1("Commit limit reached for %Iu section pages\n", CommitPages);
            Status = STATUS_COMMITMENT_LIMIT;
            goto FailPathNoLock;
        }

        //
        // Get the segment template PTE and start looping each page
        //
        TempPte = FoundVad->ControlArea->Segment->SegmentPteTemplate;
        ASSERT(TempPte.u.Long != 0);
        while (PointerPte <= LastPte)
        {
            //
            // For each non-already-committed page, write the invalid template PTE
            //
            if (PointerPte->u.Long == 0)
            {
                MI_WRITE_INVALID_PTE(PointerPte, TempPte);
            }
            else
            {
                QuotaFree++;
            }
            PointerPte++;
        }

        //
        // Now do the commit accounting and release the lock
        //
        ASSERT(QuotaCharge >= QuotaFree);
        QuotaCharge -= QuotaFree;
        ASSERT(QuotaCharge == CommitPages);
        FoundVad->ControlArea->Segment->NumberOfCommittedPages += QuotaCharge;
        InterlockedExchangeAddSizeT(&MmSharedCommit, QuotaCharge);
        KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);

        //
        // We are done with committing the section pages
        //
        Status = STATUS_SUCCESS;
        goto FailPath;
    }

    //
    // This is a specific ReactOS check because we only use normal VADs
    //
    ASSERT(FoundVad->u.VadFlags.VadType == VadNone);

    //
    // While this is an actual Windows check
    //
    ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);

    //
    // Throw out attempts to use copy-on-write through this API path
    //
    if ((Protect & PAGE_WRITECOPY) || (Protect & PAGE_EXECUTE_WRITECOPY))
    {
        DPRINT1("Write copy attempted when not allowed\n");
        Status = STATUS_INVALID_PAGE_PROTECTION;
        goto FailPath;
    }

    //
    // Initialize a demand-zero PTE
    //
    TempPte.u.Long = 0;
    TempPte.u.Soft.Protection = ProtectionMask;
    ASSERT(TempPte.u.Long != 0);

    //
    // Get the PTE, PDE and the last PTE for this address range
    //
    PointerPde = MiAddressToPde(StartingAddress);
    PointerPte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    //
    // Lock the working set while we play with user pages and page tables
    //
    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

    //
    // Charge exactly the pages this call commits, before changing anything:
    // the range less what is committed already, decided PTE by PTE as the
    // loop below does
    //
    CommitPages = BYTES_TO_PAGES(PRegionSize) -
                  MiCalculatePageCommitment(StartingAddress, EndingAddress, FoundVad, Process);
    /*
     * P4: a VAD with no charge yet (reserved, or decommitted in full) is pageable when the
     * pager backs commitment now; a VAD with a charge keeps how that was charged
     */
    if (FoundVad->u.VadFlags.CommitCharge == 0)
        MI_DECIDE_PAGER_COMMIT_VAD(FoundVad);
    CommitTier = MI_VAD_COMMIT_TIER(FoundVad);
    if (!MiChargeCommit(CommitPages, CommitTier))
    {
        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);
        MmUnlockAddressSpace(AddressSpace);
        if ((GrowthRounds++ < 4) && !KeAreAllApcsDisabled() && MiWaitForCommitGrowthEx(CommitPages, CommitTier))
            goto RetryCommit;

        DPRINT1("Commit limit reached for %Iu pages\n", CommitPages);
        Status = STATUS_COMMITMENT_LIMIT;
        goto FailPathNoLock;
    }

    //
    // Make the current page table valid, and then loop each page within it
    //
    MiMakePdeExistAndMakeValid(PointerPde, Process, MM_NOIRQL);
    while (PointerPte <= LastPte)
    {
        //
        // Have we crossed into a new page table?
        //
        if (MiIsPteOnPdeBoundary(PointerPte))
        {
            //
            // Get the PDE and now make it valid too
            //
            PointerPde = MiPteToPde(PointerPte);
            MiMakePdeExistAndMakeValid(PointerPde, Process, MM_NOIRQL);
        }

        //
        // Is this a zero PTE as expected?
        //
        if (PointerPte->u.Long == 0)
        {
            //
            // First increment the count of pages in the page table for this
            // process
            //
            MiIncrementPageTableReferences(MiPteToAddress(PointerPte));

            //
            // And now write the invalid demand-zero PTE as requested
            //
            MI_WRITE_INVALID_PTE(PointerPte, TempPte);

            //
            // In a MEM_COMMIT reservation this page was charged when the VAD
            // was inserted
            //
            if (!FoundVad->u.VadFlags.MemCommit)
            {
                QuotaCharge++;
            }
        }
        else if (PointerPte->u.Long == MmDecommittedPte.u.Long)
        {
            //
            // If the PTE was already decommitted, there is nothing else to do
            // but to write the new demand-zero PTE
            //
            MI_WRITE_INVALID_PTE(PointerPte, TempPte);
            QuotaCharge++;
        }
        else if (!(ChangeProtection) && (Protect != MiGetPageProtection(PointerPte)))
        {
            //
            // We don't handle these scenarios yet
            //
            if (PointerPte->u.Soft.Valid == 0)
            {
                ASSERT(PointerPte->u.Soft.Prototype == 0);
                ASSERT((PointerPte->u.Soft.PageFileHigh == 0) ||
                       (PointerPte->u.Soft.Transition == 1) ||
                       MI_IS_PAGEFILE_PTE(PointerPte));
            }

            //
            // There's a change in protection, remember this for later, but do
            // not yet handle it.
            //
            ChangeProtection = TRUE;
        }

        //
        // Move to the next PTE
        //
        PointerPte++;
    }

    //
    // Charge only the pages this call committed. A page that was already
    // committed stays charged once, so the VAD charge matches what a later
    // decommit takes back. The count above can only be higher than what the
    // loop committed; give the difference back.
    //
    ASSERT(QuotaCharge <= CommitPages);
    if (CommitTier == MiCommitUserPrivate)
        MiReturnPrivateCommitCredit(CommitPages - QuotaCharge);
    MiReturnCommit(CommitPages - QuotaCharge);
    FoundVad->u.VadFlags.CommitCharge += QuotaCharge;
    MiAddProcessCommit(Process, QuotaCharge);

    //
    // Release the working set lock, unlock the address space, and detach from
    // the target process if it was not the current process. Also dereference the
    // target process if this wasn't the case.
    //
    MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);
    Status = STATUS_SUCCESS;
FailPath:
    MmUnlockAddressSpace(AddressSpace);

    if (!NT_SUCCESS(Status))
    {
        if (Vad != NULL)
        {
            ExFreePoolWithTag(Vad, 'SdaV');
        }
    }

    //
    // Check if we need to update the protection
    //
    if (ChangeProtection)
    {
        PVOID ProtectBaseAddress = (PVOID)StartingAddress;
        SIZE_T ProtectSize = PRegionSize;
        ULONG OldProtection;

        //
        // Change the protection of the region
        //
        MiProtectVirtualMemory(Process,
                               &ProtectBaseAddress,
                               &ProtectSize,
                               Protect,
                               &OldProtection);
    }

FailPathNoLock:
    if (Attached) KeUnstackDetachProcess(&ApcState);
    if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);

    //
    // Only write back results on success
    //
    if (NT_SUCCESS(Status))
    {
        //
        // Use SEH to write back the base address and the region size. In the case
        // of an exception, we strangely do return back the exception code, even
        // though the memory *has* been allocated. This mimics Windows behavior and
        // there is not much we can do about it.
        //
        _SEH2_TRY
        {
            *URegionSize = PRegionSize;
            *UBaseAddress = (PVOID)StartingAddress;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else if (QuotaCharged)
    {
        PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
    }

    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtAllocateVirtualMemory(IN HANDLE ProcessHandle,
                        IN OUT PVOID* UBaseAddress,
                        IN ULONG_PTR ZeroBits,
                        IN OUT PSIZE_T URegionSize,
                        IN ULONG AllocationType,
                        IN ULONG Protect)
{
    return MiAllocateVirtualMemory(ProcessHandle,
                                   UBaseAddress,
                                   ZeroBits,
                                   URegionSize,
                                   AllocationType,
                                   Protect,
                                   0,
                                   0,
                                   0,
                                   FALSE,
                                   NULL,
                                   0);
}

/*
 * Capture and check the extended parameters of NtAllocateVirtualMemoryEx and NtMapViewOfSectionEx.
 * What is accepted: one MEM_ADDRESS_REQUIREMENTS, NUMA node 0 (the only node) and attribute flags 0.
 * Partitions, physical page handles, other attribute flags and image machines are refused. The checks of a requirement are Windows': an
 * alignment is a power of two of at least the allocation granularity, the lowest address is a
 * multiple of the granularity and of the alignment, the highest is the last byte of a page above
 * the lowest and within user space.
 */
NTSTATUS
NTAPI
MiCaptureExtendedParameters(
    _In_reads_opt_(Count) PMEM_EXTENDED_PARAMETER Parameters,
    _In_ ULONG Count,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PULONG_PTR LowestAddress,
    _Out_ PULONG_PTR HighestAddress,
    _Out_ PULONG_PTR Alignment)
{
    MEM_EXTENDED_PARAMETER Parameter;
    MEM_ADDRESS_REQUIREMENTS Requirements;
    ULONG i, Present = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    *LowestAddress = 0;
    *HighestAddress = 0;
    *Alignment = 0;

    if (Count == 0) return STATUS_SUCCESS;
    if (!Parameters) return STATUS_INVALID_PARAMETER;

    /* Each type may be given once, so there cannot be more parameters than types */
    if (Count >= MemExtendedParameterMax) return STATUS_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
            ProbeForRead(Parameters, Count * sizeof(MEM_EXTENDED_PARAMETER), sizeof(ULONG));

        for (i = 0; i < Count; i++)
        {
            Parameter = Parameters[i];
            if ((Parameter.Type >= MemExtendedParameterMax) ||
                (Parameter.Type == MemExtendedParameterInvalidType) ||
                (Present & (1UL << Parameter.Type)))
            {
                Status = STATUS_INVALID_PARAMETER;
                _SEH2_LEAVE;
            }
            Present |= 1UL << Parameter.Type;

            switch (Parameter.Type)
            {
                case MemExtendedParameterAddressRequirements:
                    if (PreviousMode != KernelMode)
                        ProbeForRead(Parameter.Pointer, sizeof(MEM_ADDRESS_REQUIREMENTS), sizeof(ULONG));
                    Requirements = *(PMEM_ADDRESS_REQUIREMENTS)Parameter.Pointer;

                    if (Requirements.Alignment &&
                        ((Requirements.Alignment & (Requirements.Alignment - 1)) ||
                         (Requirements.Alignment < MM_VIRTMEM_GRANULARITY)))
                    {
                        Status = STATUS_INVALID_PARAMETER;
                        _SEH2_LEAVE;
                    }
                    if (Requirements.LowestStartingAddress &&
                        (((ULONG_PTR)Requirements.LowestStartingAddress > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) ||
                         ((ULONG_PTR)Requirements.LowestStartingAddress & (MM_VIRTMEM_GRANULARITY - 1)) ||
                         (Requirements.Alignment &&
                          ((ULONG_PTR)Requirements.LowestStartingAddress & (Requirements.Alignment - 1)))))
                    {
                        Status = STATUS_INVALID_PARAMETER;
                        _SEH2_LEAVE;
                    }
                    if (Requirements.HighestEndingAddress &&
                        (((ULONG_PTR)Requirements.HighestEndingAddress > (ULONG_PTR)MM_HIGHEST_USER_ADDRESS) ||
                         ((ULONG_PTR)Requirements.HighestEndingAddress <= (ULONG_PTR)Requirements.LowestStartingAddress) ||
                         (((ULONG_PTR)Requirements.HighestEndingAddress & (PAGE_SIZE - 1)) != (PAGE_SIZE - 1))))
                    {
                        Status = STATUS_INVALID_PARAMETER;
                        _SEH2_LEAVE;
                    }
                    *LowestAddress = (ULONG_PTR)Requirements.LowestStartingAddress;
                    *HighestAddress = (ULONG_PTR)Requirements.HighestEndingAddress;
                    *Alignment = Requirements.Alignment;
                    break;

                case MemExtendedParameterAttributeFlags:
                    /* No attribute (large pages, nonpaged, EC code) is supported; none is fine
                       (kernelbase's VirtualAlloc2 refuses even that, as Windows 10 22H2 does) */
                    if (Parameter.ULong64 != 0)
                    {
                        Status = STATUS_INVALID_PARAMETER;
                        _SEH2_LEAVE;
                    }
                    break;

                case MemExtendedParameterNumaNode:
                    /* The one node of this system */
                    if (Parameter.ULong != 0)
                    {
                        Status = STATUS_INVALID_PARAMETER;
                        _SEH2_LEAVE;
                    }
                    break;

                default:
                    Status = STATUS_INVALID_PARAMETER;
                    _SEH2_LEAVE;
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

/* The Ex services have no parameter-specific invalid-parameter codes */
static
NTSTATUS
MiExStatus(NTSTATUS Status)
{
    if ((Status >= STATUS_INVALID_PARAMETER_1) && (Status <= STATUS_INVALID_PARAMETER_12))
        return STATUS_INVALID_PARAMETER;
    return Status;
}

NTSTATUS
NTAPI
NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *UBaseAddress,
    _Inout_ PSIZE_T URegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount)
{
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    ULONG_PTR LowestAddress, HighestAddress, Alignment;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    NTSTATUS Status;
    PAGED_CODE();

    Status = MiCaptureExtendedParameters(ExtendedParameters,
                                         ExtendedParameterCount,
                                         PreviousMode,
                                         &LowestAddress,
                                         &HighestAddress,
                                         &Alignment);
    if (!NT_SUCCESS(Status)) return Status;

    if (AllocationType & ~(MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_TOP_DOWN | MEM_PHYSICAL |
                           MEM_LARGE_PAGES | MEM_WRITE_WATCH | MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        return STATUS_INVALID_PARAMETER;
    }

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            ProbeForWritePointer(UBaseAddress);
            ProbeForWriteSize_t(URegionSize);
        }
        BaseAddress = *UBaseAddress;
        RegionSize = *URegionSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* An address and a requirement that asks for something exclude each other */
    if (BaseAddress && (LowestAddress || HighestAddress || Alignment)) return STATUS_INVALID_PARAMETER;
    if (!RegionSize) return STATUS_INVALID_PARAMETER;

#ifndef _WIN64
    /* A 32-bit system has nothing above the user space: the address conflicts (Wine's tests) */
    if (BaseAddress &&
        (((ULONG_PTR)BaseAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS) ||
         (RegionSize - 1 > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS - (ULONG_PTR)BaseAddress)))
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }
#endif

    /* The requirement must leave room for the size */
    if (HighestAddress &&
        (ROUND_TO_PAGES(RegionSize) == 0 || ROUND_TO_PAGES(RegionSize) - 1 > HighestAddress - LowestAddress))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MiAllocateVirtualMemory(ProcessHandle,
                                     UBaseAddress,
                                     0,
                                     URegionSize,
                                     AllocationType,
                                     PageProtection,
                                     LowestAddress,
                                     HighestAddress,
                                     Alignment,
                                     TRUE,
                                     BaseAddress,
                                     RegionSize);
    return MiExStatus(Status);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtFreeVirtualMemory(IN HANDLE ProcessHandle,
                    IN PVOID* UBaseAddress,
                    IN PSIZE_T URegionSize,
                    IN ULONG FreeType)
{
    BOOLEAN PageableVad = FALSE;
    SIZE_T PRegionSize;
    PVOID PBaseAddress;
    LONG_PTR AlreadyDecommitted, CommitReduction = 0;
    LONG_PTR FirstCommit;
    ULONG_PTR StartingAddress, EndingAddress;
    PMMVAD Vad;
    PMMVAD NewVad;
    PMMVAD_LONG Placeholder = NULL;
    NTSTATUS Status;
    PEPROCESS Process;
    PMMSUPPORT AddressSpace;
    PETHREAD CurrentThread = PsGetCurrentThread();
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    PAGED_CODE();

    //
    // MEM_RELEASE or MEM_DECOMMIT, exclusively; a release can split a placeholder off
    // (MEM_PRESERVE_PLACEHOLDER) or join placeholders (MEM_COALESCE_PLACEHOLDERS)
    //
    if (FreeType != MEM_RELEASE && FreeType != MEM_DECOMMIT &&
        FreeType != (MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) &&
        FreeType != (MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS))
    {
        DPRINT1("Invalid FreeType (0x%08lx)\n", FreeType);
        return STATUS_INVALID_PARAMETER_4;
    }

    //
    // Enter SEH for probe and capture. On failure, return back to the caller
    // with an exception violation.
    //
    _SEH2_TRY
    {
        //
        // Check for user-mode parameters and make sure that they are writeable
        //
        if (PreviousMode != KernelMode)
        {
            ProbeForWritePointer(UBaseAddress);
            ProbeForWriteUlong(URegionSize);
        }

        //
        // Capture the current values
        //
        PBaseAddress = *UBaseAddress;
        PRegionSize = *URegionSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    //
    // Make sure the allocation isn't past the user area
    //
    if (PBaseAddress >= MM_HIGHEST_USER_ADDRESS)
    {
        DPRINT1("Virtual free base above User Space\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Make sure the allocation wouldn't overflow past the user area
    //
    if (((ULONG_PTR)MM_HIGHEST_USER_ADDRESS - (ULONG_PTR)PBaseAddress) < PRegionSize)
    {
        DPRINT1("Region size would overflow into kernel-memory\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // If this is for the current process, just use PsGetCurrentProcess
    //
    if (ProcessHandle == NtCurrentProcess())
    {
        Process = CurrentProcess;
    }
    else
    {
        //
        // Otherwise, reference the process with VM rights and attach to it if
        // this isn't the current process. We must attach because we'll be touching
        // PTEs and PDEs that belong to user-mode memory, and also touching the
        // Working Set which is stored in Hyperspace.
        //
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_OPERATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID*)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status)) return Status;
        if (CurrentProcess != Process)
        {
            KeStackAttachProcess(&Process->Pcb, &ApcState);
            Attached = TRUE;
        }
    }

    DPRINT("NtFreeVirtualMemory: Process 0x%p, Address 0x%p, Size 0x%Ix, FreeType 0x%08lx\n",
           Process, PBaseAddress, PRegionSize, FreeType);

    //
    // A placeholder split off a range may need a VAD of its own: get it before any lock
    //
    if (FreeType == (MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) && PRegionSize)
    {
        Placeholder = ExAllocatePoolWithTag(NonPagedPool, sizeof(MMVAD_LONG), 'SdaV');
        if (!Placeholder)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto FailPathNoLock;
        }
        Status = PsChargeProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(Placeholder, 'SdaV');
            Placeholder = NULL;
            goto FailPathNoLock;
        }
        MiInitializePlaceholderVad(Placeholder);
    }

    //
    // Lock the address space
    //
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    //
    // If the address space is being deleted, fail the de-allocation since it's
    // too late to do anything about it
    //
    if (Process->VmDeleted)
    {
        DPRINT1("Process is dead\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto FailPath;
    }

    //
    // Compute start and end addresses, and locate the VAD
    //
    StartingAddress = (ULONG_PTR)PAGE_ALIGN(PBaseAddress);
    EndingAddress = ((ULONG_PTR)PBaseAddress + PRegionSize - 1) | (PAGE_SIZE - 1);
    Vad = MiLocateAddress((PVOID)StartingAddress);
    if (!Vad)
    {
        DPRINT1("Unable to find VAD for address 0x%p\n", StartingAddress);
        Status = STATUS_MEMORY_NOT_ALLOCATED;
        goto FailPath;
    }

    //
    // If the range exceeds the VAD's ending VPN, fail this request (a coalescing spans VADs)
    //
    if ((Vad->EndingVpn < (EndingAddress >> PAGE_SHIFT)) && !(FreeType & MEM_COALESCE_PLACEHOLDERS))
    {
        DPRINT1("Address 0x%p is beyond the VAD\n", EndingAddress);
        Status = STATUS_UNABLE_TO_FREE_VM;
        goto FailPath;
    }

    //
    // Only private memory (except rotate VADs) can be freed through here */
    //
    if ((!(Vad->u.VadFlags.PrivateMemory) &&
         (Vad->u.VadFlags.VadType != VadRotatePhysical)) ||
        (Vad->u.VadFlags.VadType == VadDevicePhysicalMemory))
    {
        DPRINT("Attempt to free section memory\n");
        Status = STATUS_UNABLE_TO_DELETE_SECTION;
        goto FailPath;
    }

    //
    // Don't allow freeing of protected VADs (PEB/TEB/shared user page)
    //
    if (Vad->u.VadFlags.NoChange != 0)
    {
        DPRINT1("Attempt to free protected VAD\n");
        Status = STATUS_INVALID_PAGE_PROTECTION;
        goto FailPath;
    }

    //
    // MEM_COALESCE_PLACEHOLDERS: the free placeholders that start at the VAD's base and follow
    // each other without a gap become one, if together they are exactly the given size
    //
    if (FreeType & MEM_COALESCE_PLACEHOLDERS)
    {
        PMMVAD Next, Last;
        ULONG Count = 1;

        if (!PRegionSize)
        {
            Status = STATUS_INVALID_PARAMETER_3;
            goto FailPath;
        }
        if (!MI_IS_PLACEHOLDER_VAD(Vad) ||
            (((ULONG_PTR)PBaseAddress >> PAGE_SHIFT) != Vad->StartingVpn))
        {
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto FailPath;
        }

        /* Find the last placeholder of the range */
        Last = Vad;
        while (Last->EndingVpn < (EndingAddress >> PAGE_SHIFT))
        {
            Next = (PMMVAD)MiGetNextNode((PMMADDRESS_NODE)Last);
            if (!Next || !MI_IS_PLACEHOLDER_VAD(Next) || (Next->StartingVpn != Last->EndingVpn + 1)) break;
            Last = Next;
            Count++;
        }
        if ((Count < 2) || (Last->EndingVpn != (EndingAddress >> PAGE_SHIFT)))
        {
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto FailPath;
        }

        /* The first placeholder grows over the others, which go away */
        MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
        while (Count-- > 1)
        {
            Next = (PMMVAD)MiGetNextNode((PMMADDRESS_NODE)Vad);
            ASSERT(Next && MI_IS_PLACEHOLDER_VAD(Next));
            MiRemoveNode((PMMADDRESS_NODE)Next, &Process->VadRoot);
            Vad->EndingVpn = Next->EndingVpn;
            ExFreePool(Next);
            PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
        }
        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

        StartingAddress = Vad->StartingVpn << PAGE_SHIFT;
        EndingAddress = (Vad->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1);
        PRegionSize = EndingAddress - StartingAddress + 1;
        MmUnlockAddressSpace(AddressSpace);
        Status = STATUS_SUCCESS;
        goto WriteBack;
    }

    //
    // MEM_PRESERVE_PLACEHOLDER: release a range of a placeholder, or of an allocation that
    // replaced one, and leave a placeholder in its place
    //
    if (FreeType & MEM_PRESERVE_PLACEHOLDER)
    {
        if (!PRegionSize)
        {
            Status = STATUS_INVALID_PARAMETER_3;
            goto FailPath;
        }
        if (!MI_IS_PLACEHOLDER_VAD(Vad) && !MI_IS_FROM_PLACEHOLDER_VAD(Vad))
        {
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto FailPath;
        }

        /* A whole free placeholder is one already */
        if (MI_IS_PLACEHOLDER_VAD(Vad) &&
            ((StartingAddress >> PAGE_SHIFT) == Vad->StartingVpn) &&
            ((EndingAddress >> PAGE_SHIFT) == Vad->EndingVpn))
        {
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto FailPath;
        }
    }

    /* What this VAD gives back was counted as pageable when it was charged (P4) */
    PageableVad = MI_IS_PAGER_COMMIT_VAD(Vad);

    //
    //  Now we can try the operation. First check if this is a RELEASE or a DECOMMIT
    //
    if (FreeType & MEM_RELEASE)
    {
        //
        // ARM3 only supports this VAD in this path
        //
        ASSERT(Vad->u.VadFlags.VadType == VadNone);

        //
        // Is the caller trying to remove the whole VAD, or remove only a portion
        // of it? If no region size is specified, then the assumption is that the
        // whole VAD is to be destroyed
        //
        if (!PRegionSize)
        {
            //
            // The caller must specify the base address identically to the range
            // that is stored in the VAD.
            //
            if (((ULONG_PTR)PBaseAddress >> PAGE_SHIFT) != Vad->StartingVpn)
            {
                DPRINT1("Address 0x%p does not match the VAD\n", PBaseAddress);
                Status = STATUS_FREE_VM_NOT_AT_BASE;
                goto FailPath;
            }

            //
            // Now compute the actual start/end addresses based on the VAD
            //
            StartingAddress = Vad->StartingVpn << PAGE_SHIFT;
            EndingAddress = (Vad->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1);

            //
            // Return what the VAD still charges, then lock the working set and
            // remove the VAD from the VAD tree
            //
            CommitReduction = Vad->u.VadFlags.CommitCharge;
            MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
            ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);
            MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);
            PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
        }
        else
        {
            //
            // This means the caller wants to release a specific region within
            // the range. We have to find out which range this is -- the following
            // possibilities exist plus their union (CASE D):
            //
            // STARTING ADDRESS                                   ENDING ADDRESS
            // [<========][========================================][=========>]
            //   CASE A                  CASE B                       CASE C
            //
            //
            // First, check for case A or D
            //
            if ((StartingAddress >> PAGE_SHIFT) == Vad->StartingVpn)
            {
                //
                // Check for case D
                //
                if ((EndingAddress >> PAGE_SHIFT) == Vad->EndingVpn)
                {
                    //
                    // Case D (freeing the entire region)
                    //
                    // This is the easiest one to handle -- it is identical to
                    // the code path above when the caller sets a zero region size
                    // and the whole VAD is destroyed
                    //
                    CommitReduction = Vad->u.VadFlags.CommitCharge;
                    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
                    ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);
                    MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);
                    PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
                }
                else
                {
                    //
                    // Case A (freeing a part at the beginning)
                    //
                    // This case is pretty easy too -- we compute a bunch of
                    // pages to decommit, and then push the VAD's starting address
                    // a bit further down, then decrement the commit charge
                    //
                    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
                    CommitReduction = MiCalculatePageCommitment(StartingAddress,
                                                                EndingAddress,
                                                                Vad,
                                                                Process);
                    Vad->u.VadFlags.CommitCharge -= CommitReduction;
                    Vad->StartingVpn = (EndingAddress + 1) >> PAGE_SHIFT;

                    //
                    // After analyzing the VAD, set it to NULL so that we don't
                    // free it in the exit path
                    //
                    Vad = NULL;
                }
            }
            else
            {
                //
                // This is case B or case C. First check for case C
                //
                if ((EndingAddress >> PAGE_SHIFT) == Vad->EndingVpn)
                {
                    //
                    // Case C (freeing a part at the end)
                    //
                    // This is pretty easy and similar to case A. We compute the
                    // amount of pages to decommit, update the VAD's commit charge
                    // and then change the ending address of the VAD to be a bit
                    // smaller.
                    //
                    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
                    CommitReduction = MiCalculatePageCommitment(StartingAddress,
                                                                EndingAddress,
                                                                Vad,
                                                                Process);
                    Vad->u.VadFlags.CommitCharge -= CommitReduction;
                    Vad->EndingVpn = (StartingAddress - 1) >> PAGE_SHIFT;
                }
                else
                {
                    //
                    // Case B (freeing a part in the middle)
                    //
                    // This is the hardest one. Because we are removing a chunk
                    // of memory from the very middle of the VAD, we must actually
                    // split the VAD into two new VADs and compute the commit
                    // charges for each of them, and reinsert new charges.
                    //
                    NewVad = ExAllocatePoolZero(NonPagedPool, sizeof(MMVAD_LONG), 'SdaV');
                    if (NewVad == NULL)
                    {
                        DPRINT1("Failed to allocate a VAD!\n");
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto FailPath;
                    }

                    // Charge quota for the new VAD
                    Status = PsChargeProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));

                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT1("Ran out of process quota whilst creating new VAD!\n");
                        ExFreePoolWithTag(NewVad, 'SdaV');
                        Status = STATUS_QUOTA_EXCEEDED;
                        goto FailPath;
                    }

                    //
                    // This new VAD describes the second chunk, so we keep the end
                    // address of the original and adjust the start to point past
                    // the released region.
                    // The commit charge will be calculated below.
                    //
                    NewVad->StartingVpn = (EndingAddress + 1) >> PAGE_SHIFT;
                    NewVad->EndingVpn = Vad->EndingVpn;
                    NewVad->u.LongFlags = Vad->u.LongFlags;
                    NewVad->u.VadFlags.CommitCharge = 0;
                    NewVad->u2.VadFlags2.Placeholder = Vad->u2.VadFlags2.Placeholder;
                    NewVad->u2.VadFlags2.FromPlaceholder = Vad->u2.VadFlags2.FromPlaceholder;
                    NewVad->u2.VadFlags2.PagerCommit = Vad->u2.VadFlags2.PagerCommit;
                    ASSERT(NewVad->EndingVpn >= NewVad->StartingVpn);

                    //
                    // Get the commit charge for the released region
                    //
                    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
                    CommitReduction = MiCalculatePageCommitment(StartingAddress,
                                                                EndingAddress,
                                                                Vad,
                                                                Process);

                    //
                    // Adjust the end of the original VAD (first chunk).
                    //
                    Vad->EndingVpn = (StartingAddress - 1) >> PAGE_SHIFT;

                    //
                    // Now the addresses for both VADs are consistent,
                    // so insert the new one.
                    // ReactOS: This will take care of creating a second MEMORY_AREA.
                    //
                    MiInsertVad(NewVad, &Process->VadRoot);

                    //
                    // Calculate the commit charge for the first split.
                    // The second chunk's size is the original size, minus the
                    // released region's size, minus this first chunk.
                    //
                    FirstCommit = MiCalculatePageCommitment(Vad->StartingVpn << PAGE_SHIFT,
                                                            StartingAddress - 1,
                                                            Vad,
                                                            Process);
                    NewVad->u.VadFlags.CommitCharge = Vad->u.VadFlags.CommitCharge - CommitReduction - FirstCommit;
                    Vad->u.VadFlags.CommitCharge = FirstCommit;
                }

                //
                // After analyzing the VAD, set it to NULL so that we don't
                // free it in the exit path
                //
                Vad = NULL;
            }
        }

        //
        // Now we have a range of pages to dereference, so call the right API
        // to do that and then release the working set, since we're done messing
        // around with process pages.
        //
        MiDeleteVirtualAddresses(StartingAddress, EndingAddress, NULL);

        //
        // The released range becomes a placeholder before anybody else can take it
        //
        if (Placeholder)
        {
            Status = MiInsertPlaceholderVad(Process, Placeholder, StartingAddress, EndingAddress);
            ASSERT(NT_SUCCESS(Status));
            if (NT_SUCCESS(Status)) Placeholder = NULL;
        }
        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);
    }
    else
    {
        //
        // This is the decommit path. You cannot decommit from the following VADs in
        // Windows, so fail the vall
        //
        if ((Vad->u.VadFlags.VadType == VadAwe) ||
            (Vad->u.VadFlags.VadType == VadLargePages) ||
            (Vad->u.VadFlags.VadType == VadRotatePhysical))
        {
            DPRINT1("Trying to decommit from invalid VAD\n");
            Status = STATUS_MEMORY_NOT_ALLOCATED;
            goto FailPath;
        }

        //
        // A free placeholder has nothing to decommit (Windows 10 22H2: STATUS_MEMORY_NOT_ALLOCATED)
        //
        if (MI_IS_PLACEHOLDER_VAD(Vad))
        {
            Status = STATUS_MEMORY_NOT_ALLOCATED;
            goto FailPath;
        }

        //
        // If the caller did not specify a region size, first make sure that this
        // region is actually committed. If it is, then compute the ending address
        // based on the VAD.
        //
        if (!PRegionSize)
        {
            if (((ULONG_PTR)PBaseAddress >> PAGE_SHIFT) != Vad->StartingVpn)
            {
                DPRINT1("Decomitting non-committed memory\n");
                Status = STATUS_FREE_VM_NOT_AT_BASE;
                goto FailPath;
            }
            EndingAddress = (Vad->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1);
        }

        //
        // Decommit the PTEs for the range plus the actual backing pages for the
        // range, then reduce that amount from the commit charge in the VAD
        //
        AlreadyDecommitted = MiDecommitPages((PVOID)StartingAddress,
                                             MiAddressToPte(EndingAddress),
                                             Process,
                                             Vad);
        CommitReduction = MiAddressToPte(EndingAddress) -
                          MiAddressToPte(StartingAddress) +
                          1 -
                          AlreadyDecommitted;

        ASSERT(CommitReduction >= 0);
        ASSERT(Vad->u.VadFlags.CommitCharge >= CommitReduction);
        Vad->u.VadFlags.CommitCharge -= CommitReduction;

        //
        // We are done, go to the exit path without freeing the VAD as it remains
        // valid since we have not released the allocation.
        //
        Vad = NULL;
    }

    Status = STATUS_SUCCESS;

    //
    // Update the process counters (a placeholder keeps the address space)
    //
    PRegionSize = EndingAddress - StartingAddress + 1;
    if (PageableVad)
        MiReturnPrivateCommitCredit(CommitReduction);
    MiReturnProcessCommit(Process, CommitReduction);
    if ((FreeType & MEM_RELEASE) && !(FreeType & MEM_PRESERVE_PLACEHOLDER)) Process->VirtualSize -= PRegionSize;

    //
    // Unlock the address space and free the VAD in failure cases. Next,
    // detach from the target process so we can write the region size and the
    // base address to the correct source process, and dereference the target
    // process.
    //
    MmUnlockAddressSpace(AddressSpace);
    if (Vad) ExFreePool(Vad);
WriteBack:
    if (Placeholder)
    {
        ExFreePoolWithTag(Placeholder, 'SdaV');
        PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
    }
    if (Attached) KeUnstackDetachProcess(&ApcState);
    if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);

    //
    // Use SEH to safely return the region size and the base address of the
    // deallocation. If we get an access violation, don't return a failure code
    // as the deallocation *has* happened. The caller will just have to figure
    // out another way to find out where it is (such as VirtualQuery).
    //
    _SEH2_TRY
    {
        *URegionSize = PRegionSize;
        *UBaseAddress = (PVOID)StartingAddress;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;
    return Status;

    //
    // In the failure path, we detach and dereference the target process, and
    // return whatever failure code was sent.
    //
FailPath:
    MmUnlockAddressSpace(AddressSpace);
FailPathNoLock:
    if (Placeholder)
    {
        ExFreePoolWithTag(Placeholder, 'SdaV');
        PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD_LONG));
    }
    if (Attached) KeUnstackDetachProcess(&ApcState);
    if (ProcessHandle != NtCurrentProcess()) ObDereferenceObject(Process);
    return Status;
}


PHYSICAL_ADDRESS
NTAPI
MmGetPhysicalAddress(PVOID Address)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    MMPDE TempPde;
    MMPTE TempPte;

    /* Check if the PXE/PPE/PDE is valid */
    if (
#if (_MI_PAGING_LEVELS == 4)
        (MiAddressToPxe(Address)->u.Hard.Valid) &&
#endif
#if (_MI_PAGING_LEVELS >= 3)
        (MiAddressToPpe(Address)->u.Hard.Valid) &&
#endif
        (MiAddressToPde(Address)->u.Hard.Valid))
    {
        /* Check for large pages */
        TempPde = *MiAddressToPde(Address);
        if (TempPde.u.Hard.LargePage)
        {
            /* Physical address is base page + large page offset */
            PhysicalAddress.QuadPart = (ULONG64)TempPde.u.Hard.PageFrameNumber << PAGE_SHIFT;
            PhysicalAddress.QuadPart += ((ULONG_PTR)Address & (PAGE_SIZE * PTE_PER_PAGE - 1));
            return PhysicalAddress;
        }

        /* Check if the PTE is valid */
        TempPte = *MiAddressToPte(Address);
        if (TempPte.u.Hard.Valid)
        {
            /* Physical address is base page + page offset */
            PhysicalAddress.QuadPart = (ULONG64)TempPte.u.Hard.PageFrameNumber << PAGE_SHIFT;
            PhysicalAddress.QuadPart += ((ULONG_PTR)Address & (PAGE_SIZE - 1));
            return PhysicalAddress;
        }
    }

    KeRosDumpStackFrames(NULL, 20);
    DPRINT1("MM:MmGetPhysicalAddressFailed base address was %p\n", Address);
    PhysicalAddress.QuadPart = 0;
    return PhysicalAddress;
}


/* EOF */
