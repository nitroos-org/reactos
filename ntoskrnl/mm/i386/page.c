/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/mm/i386/page.c
 * PURPOSE:         Low level memory management manipulation
 *
 * PROGRAMMERS:     David Welch (welch@cwcom.net)
 */

/* INCLUDES ***************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#include <mm/ARM3/miarm.h>

#ifndef _MI_PAGING_LEVELS
#error "Dude, fix your stuff before using this file"
#endif

/* GLOBALS *****************************************************************/
const
ULONG_PTR
MmProtectToPteMask[32] =
{
    //
    // These are the base MM_ protection flags
    //
    0,
    PTE_READONLY            | PTE_ENABLE_CACHE,
    PTE_EXECUTE             | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READ        | PTE_ENABLE_CACHE,
    PTE_READWRITE           | PTE_ENABLE_CACHE,
    PTE_WRITECOPY           | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_ENABLE_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_ENABLE_CACHE,
    //
    // These OR in the MM_NOCACHE flag
    //
    0,
    PTE_READONLY            | PTE_DISABLE_CACHE,
    PTE_EXECUTE             | PTE_DISABLE_CACHE,
    PTE_EXECUTE_READ        | PTE_DISABLE_CACHE,
    PTE_READWRITE           | PTE_DISABLE_CACHE,
    PTE_WRITECOPY           | PTE_DISABLE_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_DISABLE_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_DISABLE_CACHE,
    //
    // These OR in the MM_DECOMMIT flag, which doesn't seem supported on x86/64/ARM
    //
    0,
    PTE_READONLY            | PTE_ENABLE_CACHE,
    PTE_EXECUTE             | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READ        | PTE_ENABLE_CACHE,
    PTE_READWRITE           | PTE_ENABLE_CACHE,
    PTE_WRITECOPY           | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_ENABLE_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_ENABLE_CACHE,
    //
    // These OR in the MM_WRITECOMBINE flag
    //
    0,
    PTE_READONLY            | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE             | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE_READ        | PTE_WRITECOMBINED_CACHE,
    PTE_READWRITE           | PTE_WRITECOMBINED_CACHE,
    PTE_WRITECOPY           | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_WRITECOMBINED_CACHE,
};

const
ULONG MmProtectToValue[32] =
{
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,
    PAGE_NOCACHE | PAGE_READONLY,
    PAGE_NOCACHE | PAGE_EXECUTE,
    PAGE_NOCACHE | PAGE_EXECUTE_READ,
    PAGE_NOCACHE | PAGE_READWRITE,
    PAGE_NOCACHE | PAGE_WRITECOPY,
    PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,
    PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,
    PAGE_GUARD | PAGE_READONLY,
    PAGE_GUARD | PAGE_EXECUTE,
    PAGE_GUARD | PAGE_EXECUTE_READ,
    PAGE_GUARD | PAGE_READWRITE,
    PAGE_GUARD | PAGE_WRITECOPY,
    PAGE_GUARD | PAGE_EXECUTE_READWRITE,
    PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,
    PAGE_WRITECOMBINE | PAGE_READONLY,
    PAGE_WRITECOMBINE | PAGE_EXECUTE,
    PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,
    PAGE_WRITECOMBINE | PAGE_READWRITE,
    PAGE_WRITECOMBINE | PAGE_WRITECOPY,
    PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,
    PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY
};

/* FUNCTIONS ***************************************************************/

NTSTATUS
NTAPI
MiFillSystemPageDirectory(IN PVOID Base,
                          IN SIZE_T NumberOfBytes);

static
BOOLEAN
MiIsPageTablePresent(PVOID Address)
{
#if _MI_PAGING_LEVELS == 2
    BOOLEAN Ret = MmWorkingSetList->UsedPageTableEntries[MiGetPdeOffset(Address)] != 0;

    /* Some sanity check while we're here */
    ASSERT(Ret == (MiAddressToPde(Address)->u.Hard.Valid != 0));

    return Ret;
#else
    PMMPDE PointerPde;
    PMMPPE PointerPpe;
#if _MI_PAGING_LEVELS == 4
    PMMPXE PointerPxe;
#endif
    PMMPFN Pfn;

    /* Make sure we're locked */
    ASSERT((PsGetCurrentThread()->OwnsProcessWorkingSetExclusive) || (PsGetCurrentThread()->OwnsProcessWorkingSetShared));

    /* Must not hold the PFN lock! */
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

        /* Check if PXE or PPE have references first. */
#if _MI_PAGING_LEVELS == 4
    PointerPxe = MiAddressToPxe(Address);
    if ((PointerPxe->u.Hard.Valid == 1) || (PointerPxe->u.Soft.Transition == 1))
    {
        Pfn = MiGetPfnEntry(PFN_FROM_PXE(PointerPxe));
        if (Pfn->OriginalPte.u.Soft.UsedPageTableEntries == 0)
            return FALSE;
    }
    else if (PointerPxe->u.Soft.UsedPageTableEntries == 0)
    {
        return FALSE;
    }

    if (PointerPxe->u.Hard.Valid == 0)
    {
        MiMakeSystemAddressValid(MiPteToAddress(PointerPxe), PsGetCurrentProcess());
    }
#endif

    PointerPpe = MiAddressToPpe(Address);
    if ((PointerPpe->u.Hard.Valid == 1) || (PointerPpe->u.Soft.Transition == 1))
    {
        Pfn = MiGetPfnEntry(PFN_FROM_PPE(PointerPpe));
        if (Pfn->OriginalPte.u.Soft.UsedPageTableEntries == 0)
            return FALSE;
    }
    else if (PointerPpe->u.Soft.UsedPageTableEntries == 0)
    {
        return FALSE;
    }

    if (PointerPpe->u.Hard.Valid == 0)
    {
        MiMakeSystemAddressValid(MiPteToAddress(PointerPpe), PsGetCurrentProcess());
    }

    PointerPde = MiAddressToPde(Address);
    if ((PointerPde->u.Hard.Valid == 0) && (PointerPde->u.Soft.Transition == 0))
    {
        return PointerPde->u.Soft.UsedPageTableEntries != 0;
    }

    /* This lies on the PFN */
    Pfn = MiGetPfnEntry(PFN_FROM_PDE(PointerPde));
    return Pfn->OriginalPte.u.Soft.UsedPageTableEntries != 0;
#endif
}

PFN_NUMBER
NTAPI
MmGetPfnForProcess(PEPROCESS Process,
                   PVOID Address)
{
    PMMPTE PointerPte;
    PFN_NUMBER Page;

    /* Must be called for user mode only */
    ASSERT(Process != NULL);
    ASSERT(Address < MmSystemRangeStart);

    /* And for our process */
    ASSERT(Process == PsGetCurrentProcess());

    /* Lock for reading */
    MiLockProcessWorkingSetShared(Process, PsGetCurrentThread());

    if (!MiIsPageTablePresent(Address))
    {
        MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
        return 0;
    }

    /* Make sure we can read the PTE */
    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);
    Page = PointerPte->u.Hard.Valid ? PFN_FROM_PTE(PointerPte) : 0;

    MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
    return Page;
}

static
USHORT
MiPageTableUseCount(PVOID Address)
{
#if _MI_PAGING_LEVELS == 2
    return MmWorkingSetList->UsedPageTableEntries[MiGetPdeOffset(Address)];
#else
    PMMPDE PointerPde = MiAddressToPde(Address);

    ASSERT(PointerPde->u.Hard.Valid == 1);
    return MiGetPfnEntry(PFN_FROM_PDE(PointerPde))->OriginalPte.u.Soft.UsedPageTableEntries;
#endif
}

/*
 * The page table of a user address is valid when every level above it is. Used without the working set lock
 * to decide whether a fault in the page table (MiTryMakePageTableValid) is still needed, and with it to decide
 * that the page table is there to be counted.
 */
static
BOOLEAN
MiIsPageTableChainValid(
    _In_ PMMPDE PointerPde)
{
#if _MI_PAGING_LEVELS == 4
    if (!MiPdeToPxe(PointerPde)->u.Hard.Valid)
        return FALSE;
#endif
#if _MI_PAGING_LEVELS >= 3
    if (!MiPdeToPpe(PointerPde)->u.Hard.Valid)
        return FALSE;
#endif
    return PointerPde->u.Hard.Valid != 0;
}

static
NTSTATUS
MiTouchPagingStructure(
    _In_ PVOID Address)
{
    if (MmIsAddressValid(Address))
        return STATUS_SUCCESS;
    return MmAccessFault(FALSE, Address, KernelMode, NULL);
}

/*
 * Faults the paging structures of a user address in, one level at a time and top down (the fault of a level
 * needs the level above valid), like MiMakePdeExistAndMakeValid, but a page that cannot be had is an error
 * the caller can handle instead of a bugcheck (0x7A, STATUS_NO_MEMORY). The caller holds the address space
 * lock of a fault that cannot wait for the balancer: it gives the lock back and the fault waits and retries
 * (MmAccessFault). The working set lock is not held.
 */
static
NTSTATUS
MiTryMakePageTableValid(
    _In_ PVOID Address)
{
    PMMPDE PointerPde = MiAddressToPde(Address);
    NTSTATUS Status;

#if _MI_PAGING_LEVELS == 4
    if (!MiPdeToPxe(PointerPde)->u.Hard.Valid)
    {
        Status = MiTouchPagingStructure(MiPdeToPpe(PointerPde));
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif
#if _MI_PAGING_LEVELS >= 3
    if (!MiPdeToPpe(PointerPde)->u.Hard.Valid)
    {
        Status = MiTouchPagingStructure(PointerPde);
        if (!NT_SUCCESS(Status))
            return Status;
    }
#endif
    if (!PointerPde->u.Hard.Valid)
    {
        Status = MiTouchPagingStructure(MiPteToAddress(PointerPde));
        if (!NT_SUCCESS(Status))
            return Status;
    }
    return STATUS_SUCCESS;
}

/**
 * @brief Makes the page table of a user address of the current process valid and
 * keeps it until MmReleasePageTable.
 *
 * The page table is counted as in use (UsedPageTableEntries) while it is held: a
 * valid page table nobody counts breaks the two-level invariant (valid PDE <=>
 * nonzero count, asserted by MiIsPageTablePresent), is invisible to the
 * page-table-present tests and is never freed; and an uncounted page table can be
 * freed by the last unmap in it while the caller still relies on it.
 *
 * The hold is taken whatever the count is: a page table kept valid only by
 * other entries (another thread's mapping, or the faulting address's own swap
 * entry, which the section fault deletes and recreates) could otherwise be freed
 * by their unmap during the fault and rebuilt under the segment lock, which is
 * the low-memory lock order the pre-fault exists to avoid (ng7a). The extra
 * count may take the counter past PTE_PER_PAGE by the number of concurrent
 * holders (MI_PAGE_TABLE_HOLD_SLACK in miarm.h).
 *
 * @return STATUS_SUCCESS (a reference was taken; MmReleasePageTable drops it), or STATUS_NO_MEMORY when a
 * page for the page table (or a level above it) cannot be had now. The caller, a fault that holds the address
 * space lock and so cannot wait for the balancer itself, fails with it: MmAccessFault releases the lock, waits
 * for the balancer and retries (ng7a2: the bugcheck 0x7A of MiMakeSystemAddressValid at 512 MB).
 */
NTSTATUS
NTAPI
MmHoldPageTable(
    _In_ PEPROCESS Process,
    _In_ PVOID Address)
{
    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(Address <= MM_HIGHEST_USER_ADDRESS);
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    ULONG Tries;
    NTSTATUS Status;

    for (Tries = 0; Tries < 16; Tries++)
    {
        Status = MiTryMakePageTableValid(Address);
        if (!NT_SUCCESS(Status))
        {
            if ((Status == STATUS_NO_MEMORY) || (Status == STATUS_INSUFFICIENT_RESOURCES))
                return STATUS_NO_MEMORY;
            break;
        }

        MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
        if (MiIsPageTableChainValid(MiAddressToPde(Address)))
        {
            MiIncrementPageTableReferences(Address);
            MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
            return STATUS_SUCCESS;
        }

        /* Trimmed again between the fault and the lock: once more */
        MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
    }

    /* Out of tries (or an error that is no shortage): the old way, which waits under the lock and may bugcheck */
    MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);
    MiIncrementPageTableReferences(Address);
    MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
    return STATUS_SUCCESS;
}

/**
 * @brief Drops the reference MmHoldPageTable took and frees the page table if
 * nothing else uses it.
 */
VOID
NTAPI
MmReleasePageTable(
    _In_ PEPROCESS Process,
    _In_ PVOID Address)
{
    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(Address <= MM_HIGHEST_USER_ADDRESS);
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    /* The hold keeps the count above 0, so the page table (and its PDE) is still there */
    ASSERT(MiAddressToPde(Address)->u.Hard.Valid != 0);
    ASSERT(MiPageTableUseCount(Address) != 0);
    if (MiDecrementPageTableReferences(Address) == 0)
    {
        KIRQL OldIrql = MiAcquirePfnLock();
        MiDeletePde(MiAddressToPde(Address), Process);
        MiReleasePfnLock(OldIrql);
    }

    MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
}

/**
 * @brief Deletes the virtual mapping and optionally gives back the page & dirty bit.
 *
 * @param Process - The process this address belongs to, or NULL if system address.
 * @param Address - The address to unmap.
 * @param WasDirty - Optional param receiving the dirty bit of the PTE.
 * @param Page - Optional param receiving the page number previously mapped to this address.
 *
 * @return Whether there was actually a page mapped at the given address.
 */
_Success_(return)
static
BOOLEAN
MmDeleteVirtualMappingEx(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_opt_ BOOLEAN* WasDirty,
    _Out_opt_ PPFN_NUMBER Page,
    _In_ BOOLEAN IsPhysical,
    _Inout_opt_ PMI_DEFERRED_RELEASE Deferred)
{
    PMMPTE PointerPte;
    MMPTE OldPte;
    BOOLEAN ValidPde;

    OldPte.u.Long = 0;

    DPRINT("MmDeleteVirtualMapping(%p, %p, %p, %p)\n", Process, Address, WasDirty, Page);

    ASSERT(((ULONG_PTR)Address % PAGE_SIZE) == 0);

    /* And we should be at low IRQL */
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    /* Make sure our PDE is valid, and that everything is going fine */
    if (Process == NULL)
    {
        if (Address < MmSystemRangeStart)
        {
            DPRINT1("NULL process given for user-mode mapping at %p\n", Address);
            KeBugCheck(MEMORY_MANAGEMENT);
        }
#if (_MI_PAGING_LEVELS == 2)
        ValidPde = MiSynchronizeSystemPde(MiAddressToPde(Address));
#else
        ValidPde = MiIsPdeForAddressValid(Address);
#endif
    }
    else
    {
        if ((Address >= MmSystemRangeStart) || Add2Ptr(Address, PAGE_SIZE) >= MmSystemRangeStart)
        {
            DPRINT1("Process %p given for kernel-mode mapping at %p\n", Process, Address);
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        /* Only for current process !!! */
        ASSERT(Process == PsGetCurrentProcess());
        MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

        ValidPde = MiIsPageTablePresent(Address);
        if (ValidPde)
        {
            MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);
        }
    }

    /* Get the PTE if we're having anything */
    if (ValidPde)
    {
        PointerPte = MiAddressToPte(Address);
        OldPte.u.Long = InterlockedExchangePte(PointerPte, 0);

        /* System space is shared by every processor, a process only by those running it */
        if (Deferred != NULL)
        {
            ASSERT(Deferred->FlushList.AllProcessors == (Process == NULL));
            ASSERT(MiDeferredReleaseRoom(Deferred) >= 1 + MI_DEFERRED_PDE_ENTRIES);
            MiDeferTbFlush(Deferred, Address);
        }
        else
        {
            KeFlushSingleTb(Address, Process == NULL);
        }

        if (OldPte.u.Long != 0)
        {
            /* It must have been present, or not a swap entry */
            ASSERT(OldPte.u.Hard.Valid || !FlagOn(OldPte.u.Long, 0x800));
            if (WasDirty != NULL)
            {
                *WasDirty = !!OldPte.u.Hard.Dirty;
            }
            if (Page != NULL)
            {
                *Page = OldPte.u.Hard.PageFrameNumber;
            }
        }
    }

    if (Process != NULL)
    {
        BOOLEAN PdeDeleted = FALSE;

        /* Remove PDE reference, if needed */
        if (OldPte.u.Long != 0)
        {
            if (MiDecrementPageTableReferences(Address) == 0)
            {
                KIRQL OldIrql = MiAcquirePfnLock();
                if (Deferred != NULL)
                    MiDeletePdeDeferred(MiAddressToPde(Address), Process, Deferred);
                else
                    MiDeletePde(MiAddressToPde(Address), Process);
                MiReleasePfnLock(OldIrql);
                PdeDeleted = TRUE;
            }
        }

        if (!IsPhysical && OldPte.u.Hard.Valid)
        {
            PMMPFN Pfn1;
            KIRQL OldIrql;

            Pfn1 = &MmPfnDatabase[OldPte.u.Hard.PageFrameNumber];
            if (Deferred != NULL)
            {
                /* The mapping count drops once the deferred flush is done */
                MiDeferShareRelease(Deferred, Pfn1, TRUE);
            }
            else
            {
                OldIrql = MiAcquirePfnLock();
                ASSERT(Pfn1->u3.e1.PageLocation == ActiveAndValid);
                ASSERT(Pfn1->u2.ShareCount > 0);
                if (--Pfn1->u2.ShareCount == 0)
                {
                    Pfn1->u3.e1.PageLocation = TransitionPage;
                }
                MiReleasePfnLock(OldIrql);
            }
        }

        /*
         * An ARM3 fault elsewhere under this PDE needs only the working set lock
         * and would build a new page table, while other processors may still walk
         * the old one through their paging-structure caches: flush first.
         */
        if (PdeDeleted && (Deferred != NULL))
            MiCompleteDeferredRelease(Deferred);

        MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
    }

    return OldPte.u.Long != 0;
}

_Success_(return)
BOOLEAN
MmDeleteVirtualMapping(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_opt_ BOOLEAN * WasDirty,
    _Out_opt_ PPFN_NUMBER Page)
{
    return MmDeleteVirtualMappingEx(Process, Address, WasDirty, Page, FALSE, NULL);
}

_Success_(return)
BOOLEAN
MmDeletePhysicalMapping(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_opt_ BOOLEAN * WasDirty,
    _Out_opt_ PPFN_NUMBER Page)
{
    return MmDeleteVirtualMappingEx(Process, Address, WasDirty, Page, TRUE, NULL);
}

_Success_(return)
BOOLEAN
MmDeleteVirtualMappingDeferFlush(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_opt_ BOOLEAN * WasDirty,
    _Out_opt_ PPFN_NUMBER Page,
    _In_ BOOLEAN IsPhysical,
    _Inout_ PMI_DEFERRED_RELEASE Deferred)
{
    return MmDeleteVirtualMappingEx(Process, Address, WasDirty, Page, IsPhysical, Deferred);
}

VOID
NTAPI
MmDeletePageFileMapping(
    PEPROCESS Process,
    PVOID Address,
    SWAPENTRY* SwapEntry)
{
    PMMPTE PointerPte;
    MMPTE OldPte;

    /* This should not be called for kernel space anymore */
    ASSERT(Process != NULL);
    ASSERT(Address < MmSystemRangeStart);

    /* And we don't support deleting for other process */
    ASSERT(Process == PsGetCurrentProcess());

    /* And we should be at low IRQL */
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    /* We are tinkering with the PDE here. Ensure it will be there */
    MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    /* Callers must ensure there is actually something there */
    ASSERT(MiAddressToPde(Address)->u.Long != 0);

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);
    OldPte.u.Long = InterlockedExchangePte(PointerPte, 0);
    /* This must be a swap entry ! */
    if (!FlagOn(OldPte.u.Long, 0x800) || OldPte.u.Hard.Valid)
    {
        KeBugCheckEx(MEMORY_MANAGEMENT, OldPte.u.Long, (ULONG_PTR)Process, (ULONG_PTR)Address, 0);
    }

    /* This used to be a non-zero PTE, now we can let the PDE go. */
    if (MiDecrementPageTableReferences(Address) == 0)
    {
        /* We can let it go */
        KIRQL OldIrql = MiAcquirePfnLock();
        MiDeletePde(MiPteToPde(PointerPte), Process);
        MiReleasePfnLock(OldIrql);
    }

    MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    *SwapEntry = OldPte.u.Long >> 1;
}

BOOLEAN
NTAPI
MmIsPagePresent(PEPROCESS Process, PVOID Address)
{
    BOOLEAN Ret;

    if (Address >= MmSystemRangeStart)
    {
        ASSERT(Process == NULL);
#if _MI_PAGING_LEVELS == 2
        if (!MiSynchronizeSystemPde(MiAddressToPde(Address)))
#else
        if (!MiIsPdeForAddressValid(Address))
#endif
        {
            /* It can't be present if there is no PDE */
            return FALSE;
        }

        return MiAddressToPte(Address)->u.Hard.Valid;
    }

    ASSERT(Process != NULL);
    ASSERT(Process == PsGetCurrentProcess());

    MiLockProcessWorkingSetShared(Process, PsGetCurrentThread());

    if (!MiIsPageTablePresent(Address))
    {
        /* It can't be present if there is no PDE */
        MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
        return FALSE;
    }

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    Ret = MiAddressToPte(Address)->u.Hard.Valid;

    MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());

    return Ret;
}

BOOLEAN
NTAPI
MmIsDisabledPage(PEPROCESS Process, PVOID Address)
{
    BOOLEAN Ret;
    PMMPTE PointerPte;

    if (Address >= MmSystemRangeStart)
    {
        ASSERT(Process == NULL);
#if _MI_PAGING_LEVELS == 2
        if (!MiSynchronizeSystemPde(MiAddressToPde(Address)))
#else
        if (!MiIsPdeForAddressValid(Address))
#endif
        {
            /* It's not disabled if it's not present */
            return FALSE;
        }
    }
    else
    {
        ASSERT(Process != NULL);
        ASSERT(Process == PsGetCurrentProcess());

        MiLockProcessWorkingSetShared(Process, PsGetCurrentThread());

        if (!MiIsPageTablePresent(Address))
        {
            /* It can't be disabled if there is no PDE */
            MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
            return FALSE;
        }

        MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);
    }

    PointerPte = MiAddressToPte(Address);
    Ret = !PointerPte->u.Hard.Valid
        && !FlagOn(PointerPte->u.Long, 0x800)
        && (PointerPte->u.Hard.PageFrameNumber != 0);

    if (Address < MmSystemRangeStart)
        MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());

    return Ret;
}

BOOLEAN
NTAPI
MmIsPageSwapEntry(PEPROCESS Process, PVOID Address)
{
    BOOLEAN Ret;
    PMMPTE PointerPte;

    /* We never set swap entries for kernel addresses */
    if (Address >= MmSystemRangeStart)
    {
        ASSERT(Process == NULL);
        return FALSE;
    }

    ASSERT(Process != NULL);
    ASSERT(Process == PsGetCurrentProcess());

    MiLockProcessWorkingSetShared(Process, PsGetCurrentThread());

    if (!MiIsPageTablePresent(Address))
    {
        /* There can't be a swap entry if there is no PDE */
        MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
        return FALSE;
    }

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);
    Ret = !PointerPte->u.Hard.Valid && FlagOn(PointerPte->u.Long, 0x800);

    MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());

    return Ret;
}

VOID
NTAPI
MmGetPageFileMapping(PEPROCESS Process, PVOID Address, SWAPENTRY* SwapEntry)
{
    PMMPTE PointerPte;

    /* We never set swap entries for kernel addresses */
    if (Address >= MmSystemRangeStart)
    {
        ASSERT(Process == NULL);
        *SwapEntry = 0;
        return;
    }

    ASSERT(Process != NULL);
    ASSERT(Process == PsGetCurrentProcess());

    MiLockProcessWorkingSetShared(Process, PsGetCurrentThread());

    if (!MiIsPageTablePresent(Address))
    {
        /* There can't be a swap entry if there is no PDE */
        MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
        *SwapEntry = 0;
        return;
    }

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);
    if (!PointerPte->u.Hard.Valid && FlagOn(PointerPte->u.Long, 0x800))
        *SwapEntry = PointerPte->u.Long >> 1;
    else
        *SwapEntry = 0;

    MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
}

NTSTATUS
NTAPI
MmCreatePageFileMapping(PEPROCESS Process,
                        PVOID Address,
                        SWAPENTRY SwapEntry)
{
    PMMPTE PointerPte;
    ULONG_PTR Pte;

    /* This should not be called for kernel space anymore */
    ASSERT(Process != NULL);
    ASSERT(Address < MmSystemRangeStart);

    /* And we don't support creating for other process */
    ASSERT(Process == PsGetCurrentProcess());

    if (SwapEntry & ((ULONG_PTR)1 << (RTL_BITS_OF(SWAPENTRY) - 1)))
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    /* We are tinkering with the PDE here. Ensure it will be there */
    ASSERT(Process == PsGetCurrentProcess());
    MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);
    Pte = InterlockedExchangePte(PointerPte, SwapEntry << 1);
    if (Pte != 0)
    {
        KeBugCheckEx(MEMORY_MANAGEMENT, SwapEntry, (ULONG_PTR)Process, (ULONG_PTR)Address, 0);
    }

    /* This used to be a 0 PTE, now we need a valid PDE to keep it around */
    MiIncrementPageTableReferences(Address);
    MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    return STATUS_SUCCESS;
}


/* The cache bits of a PTE for a page whose PFN records how it is mapped */
static
VOID
MiSetPteCaching(
    _Inout_ PMMPTE Pte,
    _In_ MI_PFN_CACHE_ATTRIBUTE CacheAttribute)
{
    /* The encoding of the ARM3 mappings of the same page (MI_MAKE_PTE_*) */
    if (CacheAttribute == MiNonCached)
        MI_MAKE_PTE_NON_CACHED(Pte);
    else if (CacheAttribute == MiWriteCombined)
        MI_MAKE_PTE_WRITE_COMBINE(Pte);
    else
        MI_MAKE_PTE_CACHED(Pte);
}

NTSTATUS
NTAPI
MmCreateVirtualMappingUnsafeEx(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ ULONG flProtect,
    _In_ PFN_NUMBER Page,
    _In_ BOOLEAN IsPhysical)
{
    ULONG ProtectionMask;
    PMMPTE PointerPte;
    MMPTE TempPte;
    ULONG_PTR Pte;

    DPRINT("MmCreateVirtualMappingUnsafe(%p, %p, %lu, %x)\n",
           Process, Address, flProtect, Page);

    ASSERT(((ULONG_PTR)Address % PAGE_SIZE) == 0);

    ProtectionMask = MiMakeProtectionMask(flProtect);
    /* Caller must have checked ! */
    ASSERT(ProtectionMask != MM_INVALID_PROTECTION);
    ASSERT(ProtectionMask != MM_NOACCESS);
    ASSERT(ProtectionMask != MM_ZERO_ACCESS);

    /* Make sure our PDE is valid, and that everything is going fine */
    if (Process == NULL)
    {
        /* We don't support this in legacy Mm for kernel mappings */
        ASSERT(ProtectionMask != MM_WRITECOPY);
        ASSERT(ProtectionMask != MM_EXECUTE_WRITECOPY);

        if (Address < MmSystemRangeStart)
        {
            DPRINT1("NULL process given for user-mode mapping at %p\n", Address);
            KeBugCheck(MEMORY_MANAGEMENT);
        }
#if _MI_PAGING_LEVELS == 2
        if (!MiSynchronizeSystemPde(MiAddressToPde(Address)))
            MiFillSystemPageDirectory(Address, PAGE_SIZE);
#endif
    }
    else
    {
        if ((Address >= MmSystemRangeStart) || Add2Ptr(Address, PAGE_SIZE) >= MmSystemRangeStart)
        {
            DPRINT1("Process %p given for kernel-mode mapping at %p -- 1 page starting at %Ix\n",
                    Process, Address, Page);
            KeBugCheck(MEMORY_MANAGEMENT);
        }

        /* Only for current process !!! */
        ASSERT(Process == PsGetCurrentProcess());
        MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

        MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);
    }

    PointerPte = MiAddressToPte(Address);

    MI_MAKE_HARDWARE_PTE(&TempPte, PointerPte, ProtectionMask, Page);

    if (!IsPhysical)
    {
        PMMPFN Pfn1;
        KIRQL OldIrql;

        OldIrql = MiAcquirePfnLock();
        Pfn1 = &MmPfnDatabase[TempPte.u.Hard.PageFrameNumber];

        /* The first mapping of a RosMm page decides its caching type, later ones follow it */
        if (MI_IS_ROS_PFN(Pfn1))
        {
            if (Pfn1->u2.ShareCount == 0)
                Pfn1->u3.e1.CacheAttribute = MiCacheAttributeFromProtection(ProtectionMask);
            else if (Pfn1->u3.e1.CacheAttribute != MiNotMapped) /* defensive: RosMm pages start MiCached */
                MiSetPteCaching(&TempPte, Pfn1->u3.e1.CacheAttribute);
        }

        Pfn1->u2.ShareCount++;
        Pfn1->u3.e1.PageLocation = ActiveAndValid;
        MiReleasePfnLock(OldIrql);

        if (TempPte.u.Hard.CacheDisable)
            MiFlushReleasedSystemPtesBeforeUncachedMapping();
    }

    Pte = InterlockedExchangePte(PointerPte, TempPte.u.Long);
    /* There should not have been anything valid here */
    if (Pte != 0)
    {
        DPRINT1("Bad PTE %lx at %p for %p\n", Pte, PointerPte, Address);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    /* We don't need to flush the TLB here because it only caches valid translations
     * and we're moving this PTE from invalid to valid so it can't be cached right now */

    if (Address < MmSystemRangeStart)
    {
        /* Add PDE reference */
        MiIncrementPageTableReferences(Address);
        MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
    }

    return(STATUS_SUCCESS);
}

NTSTATUS
NTAPI
MmCreateVirtualMappingUnsafe(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ ULONG flProtect,
    _In_ PFN_NUMBER Page)
{
    return MmCreateVirtualMappingUnsafeEx(Process, Address, flProtect, Page, FALSE);
}

NTSTATUS
NTAPI
MmCreatePhysicalMapping(
    _Inout_opt_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ ULONG flProtect,
    _In_ PFN_NUMBER Page)
{
    return MmCreateVirtualMappingUnsafeEx(Process, Address, flProtect, Page, TRUE);
}

NTSTATUS
NTAPI
MmCreateVirtualMapping(PEPROCESS Process,
                       PVOID Address,
                       ULONG flProtect,
                       PFN_NUMBER Page)
{
    ASSERT((ULONG_PTR)Address % PAGE_SIZE == 0);
    if (!MmIsPageInUse(Page))
    {
        DPRINT1("Page %lx is not in use\n", Page);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    return MmCreateVirtualMappingUnsafe(Process, Address, flProtect, Page);
}

ULONG
NTAPI
MmGetPageProtect(PEPROCESS Process, PVOID Address)
{
    PMMPTE PointerPte;
    ULONG Protect;

    if (Address >= MmSystemRangeStart)
    {
        ASSERT(Process == NULL);

#if _MI_PAGING_LEVELS == 2
        if (!MiSynchronizeSystemPde(MiAddressToPde(Address)))
#else
        if (!MiIsPdeForAddressValid(Address))
#endif
        {
            return PAGE_NOACCESS;
        }
    }
    else
    {
        ASSERT(Address < MmSystemRangeStart);
        ASSERT(Process != NULL);

        ASSERT(Process == PsGetCurrentProcess());

        MiLockProcessWorkingSetShared(Process, PsGetCurrentThread());

        if (!MiIsPageTablePresent(Address))
        {
            /* It can't be present if there is no PDE */
            MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());
            return PAGE_NOACCESS;
        }

        MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);
    }

    PointerPte = MiAddressToPte(Address);

    if (!PointerPte->u.Flush.Valid)
    {
        Protect = PAGE_NOACCESS;
    }
    else
    {
        if (PointerPte->u.Flush.CopyOnWrite)
            Protect = PAGE_WRITECOPY;
        else if (PointerPte->u.Flush.Write)
            Protect = PAGE_READWRITE;
        else
            Protect = PAGE_READONLY;
#if _MI_PAGING_LEVELS >= 3
        /* PAE & AMD64 long mode support NoExecute bit */
        if (!PointerPte->u.Flush.NoExecute)
            Protect <<= 4;
#endif
        if (PointerPte->u.Flush.CacheDisable)
            Protect |= PAGE_NOCACHE;
        if (PointerPte->u.Flush.WriteThrough)
            Protect |= PAGE_WRITETHROUGH;
    }

    if (Address < MmSystemRangeStart)
        MiUnlockProcessWorkingSetShared(Process, PsGetCurrentThread());

    return(Protect);
}

/*
 * PhysicalView: the PTE maps a page through a \Device\PhysicalMemory view, which never records its
 * cache type in the PFN, so the requested cache bits are kept.
 * FlushList: the caller flushes the TB for the list; NULL flushes it here.
 */
static
VOID
MiSetPageProtect(PEPROCESS Process, PVOID Address, ULONG flProtect, BOOLEAN PhysicalView, PMM_TB_FLUSH_LIST FlushList)
{
    ULONG ProtectionMask;
    PMMPTE PointerPte;
    MMPTE TempPte, OldPte;
    PMMPFN Pfn1;

    DPRINT("MmSetPageProtect(Process %p  Address %p  flProtect %x)\n",
           Process, Address, flProtect);

    ASSERT(Process != NULL);
    ASSERT(Address < MmSystemRangeStart);

    ASSERT(Process == PsGetCurrentProcess());

    ProtectionMask = MiMakeProtectionMask(flProtect);
    /* Caller must have checked ! */
    ASSERT(ProtectionMask != MM_INVALID_PROTECTION);

    MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);

    /* Sanity check */
    ASSERT(PointerPte->u.Hard.Owner == 1);

    TempPte.u.Long = 0;
    TempPte.u.Hard.PageFrameNumber = PointerPte->u.Hard.PageFrameNumber;
    TempPte.u.Long |= MmProtectToPteMask[ProtectionMask];
    TempPte.u.Hard.Owner = 1;

    /* A RosMm page keeps the caching type its PFN records, as in MiFlushTbAndCapture.
       RosMm pages start MiCached, so the MiNotMapped test is defensive */
    Pfn1 = PhysicalView ? NULL : MiGetPfnEntry(TempPte.u.Hard.PageFrameNumber);
    if ((Pfn1 != NULL) && MI_IS_ROS_PFN(Pfn1) && (Pfn1->u3.e1.CacheAttribute != MiNotMapped))
        MiSetPteCaching(&TempPte, Pfn1->u3.e1.CacheAttribute);

    /* Only set valid bit if we have to */
    if ((ProtectionMask != MM_NOACCESS) && !FlagOn(ProtectionMask, MM_GUARDPAGE))
        TempPte.u.Hard.Valid = 1;

    /* Keep dirty & accessed bits */
    TempPte.u.Hard.Accessed = PointerPte->u.Hard.Accessed;
    TempPte.u.Hard.Dirty = PointerPte->u.Hard.Dirty;

    OldPte.u.Long = InterlockedExchangePte(PointerPte, TempPte.u.Long);

    // We should be able to bring a page back from PAGE_NOACCESS
    if (!OldPte.u.Hard.Valid && (FlagOn(OldPte.u.Long, 0x800) || (OldPte.u.Hard.PageFrameNumber == 0)))
    {
        DPRINT1("Invalid Pte %lx\n", OldPte.u.Long);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    if (OldPte.u.Long != TempPte.u.Long)
    {
        if (FlushList != NULL)
            MmAddToTbFlushList(FlushList, Address);
        else
            KeFlushSingleTb(Address, FALSE);
    }

    MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
}

VOID
NTAPI
MmSetPageProtect(PEPROCESS Process, PVOID Address, ULONG flProtect)
{
    MiSetPageProtect(Process, Address, flProtect, FALSE, NULL);
}

VOID
NTAPI
MmSetPageProtectDeferFlush(PEPROCESS Process, PVOID Address, ULONG flProtect, BOOLEAN PhysicalView, PMM_TB_FLUSH_LIST FlushList)
{
    MiSetPageProtect(Process, Address, flProtect, PhysicalView, FlushList);
}

VOID
NTAPI
MmSetDirtyBit(PEPROCESS Process, PVOID Address, BOOLEAN Bit)
{
    PMMPTE PointerPte;

    DPRINT("MmSetDirtyBit(Process %p  Address %p  Bit %x)\n",
           Process, Address, Bit);

    ASSERT(Process != NULL);
    ASSERT(Address < MmSystemRangeStart);

    ASSERT(Process == PsGetCurrentProcess());

    MiLockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());

    MiMakePdeExistAndMakeValid(MiAddressToPde(Address), Process, MM_NOIRQL);

    PointerPte = MiAddressToPte(Address);
    // We shouldnl't set dirty bit on non-mapped addresses
    if (!PointerPte->u.Hard.Valid && (FlagOn(PointerPte->u.Long, 0x800) || (PointerPte->u.Hard.PageFrameNumber == 0)))
    {
        DPRINT1("Invalid Pte %lx\n", PointerPte->u.Long);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    PointerPte->u.Hard.Dirty = !!Bit;

    if (!Bit)
        KeFlushSingleTb(Address, FALSE);

    MiUnlockProcessWorkingSetUnsafe(Process, PsGetCurrentThread());
}

CODE_SEG("INIT")
VOID
NTAPI
MmInitGlobalKernelPageDirectory(VOID)
{
    /* Nothing to do here */
}

#ifdef _M_IX86
BOOLEAN
Mmi386MakeKernelPageTableGlobal(PVOID Address)
{
    PMMPDE PointerPde = MiAddressToPde(Address);
    PMMPTE PointerPte = MiAddressToPte(Address);

    if (PointerPde->u.Hard.Valid == 0)
    {
        if (!MiSynchronizeSystemPde(PointerPde))
            return FALSE;
        return PointerPte->u.Hard.Valid != 0;
    }
    return FALSE;
}
#endif

/* EOF */
