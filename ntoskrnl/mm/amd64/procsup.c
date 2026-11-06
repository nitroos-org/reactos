/*
 * COPYRIGHT:       GPL, See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/mm/amd64/procsup.c
 * PURPOSE:         Low level memory management manipulation
 *
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 *                  ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

BOOLEAN
MiArchCreateProcessAddressSpace(
    _In_ PEPROCESS Process,
    _In_ PULONG_PTR DirectoryTableBase)
{
    KIRQL OldIrql;
    PFN_NUMBER TableBasePfn, HyperPfn, HyperPdPfn, HyperPtPfn;
    BOOLEAN ZeroHyperPd, ZeroHyperPt;
    PMMPTE SystemPte;
    MMPTE TempPte, PdePte;
    ULONG TableIndex;
    PMMPTE PageTablePointer;
    ULONG PageColor;

    /* Non-arch specific code-path allocated those for us */
    TableBasePfn = DirectoryTableBase[0] >> PAGE_SHIFT;
    HyperPfn = DirectoryTableBase[1] >> PAGE_SHIFT;

    /* Get a PTE to map the page directory */
    SystemPte = MiReserveSystemPtes(1, SystemPteSpace);
    if (!SystemPte)
        return FALSE;

    /* Lock PFN database */
    OldIrql = MiAcquirePfnLock();

    /* Fail the process instead of using page 0 when no page is free */
    if (MiGetUsablePageCount() < 2)
    {
        MiReleasePfnLock(OldIrql);
        MiReleaseSystemPtes(SystemPte, 1, SystemPteSpace);
        return FALSE;
    }

    /* Try getting zero pages, others are zeroed outside the PFN lock */
    PageColor = MI_GET_NEXT_PROCESS_COLOR(Process);
    HyperPdPfn = MiRemoveZeroPageSafe(PageColor);
    ZeroHyperPd = (HyperPdPfn == 0);
    if (ZeroHyperPd)
        HyperPdPfn = MiRemoveAnyPageGated(PageColor);
    PageColor = MI_GET_NEXT_PROCESS_COLOR(Process);
    HyperPtPfn = MiRemoveZeroPageSafe(PageColor);
    ZeroHyperPt = (HyperPtPfn == 0);
    if (ZeroHyperPt)
        HyperPtPfn = MiRemoveAnyPageGated(PageColor);
    MiReleasePfnLock(OldIrql);

    if (ZeroHyperPd) MiZeroPhysicalPage(HyperPdPfn);
    if (ZeroHyperPt) MiZeroPhysicalPage(HyperPtPfn);

    /* Get its address */
    PageTablePointer = MiPteToAddress(SystemPte);

    /* The PTE is remapped below with local flushes only, so stay on this
       processor: another one could keep a stale translation of it */
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    /* Build the PTE for the page directory and map it */
    MI_MAKE_HARDWARE_PTE_KERNEL(&PdePte, SystemPte, MM_READWRITE, TableBasePfn);
    MI_WRITE_VALID_PTE(SystemPte, PdePte);

    /* Copy the kernel mappings and zero out the rest */
    TableIndex = PXE_PER_PAGE / 2;
    RtlZeroMemory(PageTablePointer, TableIndex * sizeof(MMPTE));
    RtlCopyMemory(PageTablePointer + TableIndex,
                  MiAddressToPxe(0) + TableIndex,
                  PAGE_SIZE - TableIndex * sizeof(MMPTE));

    /* Sanity check */
    ASSERT(MiAddressToPxi(MmHyperSpaceEnd) >= TableIndex);

    /* Setup a PTE for the page directory mappings */
    TempPte = ValidKernelPteLocal;

    /* Update the self mapping of the PML4 */
    TableIndex = MiAddressToPxi((PVOID)PXE_SELFMAP);
    TempPte.u.Hard.PageFrameNumber = TableBasePfn;
    PageTablePointer[TableIndex] = TempPte;

    /* Write the PML4 entry for hyperspace */
    TableIndex = MiAddressToPxi((PVOID)HYPER_SPACE);
    TempPte.u.Hard.PageFrameNumber = HyperPfn;
    PageTablePointer[TableIndex] = TempPte;

    /* Map the hyperspace PDPT to the system PTE */
    PdePte.u.Hard.PageFrameNumber = HyperPfn;
    *SystemPte = PdePte;
    __invlpg(PageTablePointer);

    /* Write the hyperspace entry for the first PD */
    TempPte.u.Hard.PageFrameNumber = HyperPdPfn;
    PageTablePointer[0] = TempPte;

    /* Map the hyperspace PD to the system PTE */
    PdePte.u.Hard.PageFrameNumber = HyperPdPfn;
    *SystemPte = PdePte;
    __invlpg(PageTablePointer);

    /* Write the hyperspace entry for the first PT */
    TempPte.u.Hard.PageFrameNumber = HyperPtPfn;
    PageTablePointer[0] = TempPte;

    /* Map the hyperspace PT to the system PTE */
    PdePte.u.Hard.PageFrameNumber = HyperPtPfn;
    *SystemPte = PdePte;
    __invlpg(PageTablePointer);

    /* Write the hyperspace PTE for the working set list index */
    TempPte.u.Hard.PageFrameNumber = Process->WorkingSetPage;
    TableIndex = MiAddressToPti(MmWorkingSetList);
    PageTablePointer[TableIndex] = TempPte;

    KeLowerIrql(OldIrql);

    /* Release the system PTE */
    MiReleaseSystemPtes(SystemPte, 1, SystemPteSpace);

    return TRUE;
}
