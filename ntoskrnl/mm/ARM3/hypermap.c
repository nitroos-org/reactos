/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/hypermap.c
 * PURPOSE:         ARM Memory Manager Hyperspace Mapping Functionality
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

PMMPTE MmFirstReservedMappingPte, MmLastReservedMappingPte;
PMMPTE MiFirstReservedZeroingPte;
MMPTE HyperTemplatePte;
extern PKTHREAD MiZeroPageThread;

/* PRIVATE FUNCTIONS **********************************************************/

PVOID
NTAPI
MiMapPageInHyperSpace(IN PEPROCESS Process,
                      IN PFN_NUMBER Page,
                      IN PKIRQL OldIrql)
{
    MMPTE TempPte;
    PMMPTE PointerPte;
    PFN_NUMBER Offset;

    //
    // Never accept page 0 or non-physical pages
    //
    ASSERT(Page != 0);
    ASSERT(MiGetPfnEntry(Page) != NULL);

    //
    // Build the PTE
    //
    TempPte = ValidKernelPteLocal;
    TempPte.u.Hard.PageFrameNumber = Page;

    //
    // Pick the first hyperspace PTE
    //
    PointerPte = MmFirstReservedMappingPte;

    //
    // Acquire the hyperlock
    //
    ASSERT(Process == PsGetCurrentProcess());
    KeAcquireSpinLock(&Process->HyperSpaceLock, OldIrql);

    //
    // Now get the first free PTE
    //
    Offset = PFN_FROM_PTE(PointerPte);
    if (!Offset)
    {
        //
        // Reset the PTEs
        //
        Offset = MI_HYPERSPACE_PTES;
        KeFlushProcessTb();
    }

    //
    // Prepare the next PTE
    //
    PointerPte->u.Hard.PageFrameNumber = Offset - 1;

    //
    // Write the current PTE
    //
    PointerPte += Offset;
    MI_WRITE_VALID_PTE(PointerPte, TempPte);

    //
    // Return the address
    //
    return MiPteToAddress(PointerPte);
}

VOID
NTAPI
MiUnmapPageInHyperSpace(IN PEPROCESS Process,
                        IN PVOID Address,
                        IN KIRQL OldIrql)
{
    ASSERT(Process == PsGetCurrentProcess());

    //
    // Blow away the mapping
    //
    MiAddressToPte(Address)->u.Long = 0;

    //
    // Release the hyperlock
    //
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    KeReleaseSpinLock(&Process->HyperSpaceLock, OldIrql);
}

#if defined(_M_IX86) || defined(_M_AMD64)
#if defined(__GNUC__)
#define MiClflush(Address) __asm__ __volatile__("clflush %0" : "+m" (*(volatile UCHAR *)(Address)))
#else
#define MiClflush(Address) _mm_clflush((PVOID)(Address))
#endif

/* CLFLUSH line size, 0 without CLFLUSH, MAXULONG until the zero page thread reads it */
static ULONG MiZeroFlushLine = MAXULONG;

static
VOID
MiReadZeroFlushLine(VOID)
{
    INT Registers[4];

    /* CPUID 1: EDX bit 19 is CLFLUSH, EBX bits 8-15 its line size in 8-byte
       units; EDX bit 26 (SSE2) is needed for MFENCE */
    __cpuid(Registers, 1);
    if (!(Registers[3] & (1 << 19)) || !(Registers[3] & (1 << 26)))
        MiZeroFlushLine = 0;
    else if (((Registers[1] >> 8) & 0xFF) != 0)
        MiZeroFlushLine = ((Registers[1] >> 8) & 0xFF) * 8;
    else
        MiZeroFlushLine = 32;
}
#endif

PVOID
NTAPI
MiMapPagesInZeroSpace(IN PMMPFN Pfn1,
                      IN PFN_NUMBER NumberOfPages)
{
    MMPTE TempPte;
    PMMPTE PointerPte;
    PFN_NUMBER Offset, PageFrameIndex;

    //
    // Sanity checks
    //
    ASSERT(KeGetCurrentThread() == MiZeroPageThread);
#if defined(_M_IX86) || defined(_M_AMD64)
    /* The caller stays on this processor from the mapping to the unmapping */
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
#else
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
#endif
    ASSERT(NumberOfPages != 0);
    ASSERT(NumberOfPages <= MI_ZERO_PTES);

    //
    // Pick the first zeroing PTE
    //
    PointerPte = MiFirstReservedZeroingPte;

    //
    // Now get the first free PTE
    //
    Offset = PFN_FROM_PTE(PointerPte);
    if (NumberOfPages > Offset)
    {
        //
        // Reset the PTEs
        //
        Offset = MI_ZERO_PTES;
        PointerPte->u.Hard.PageFrameNumber = Offset;
#if !defined(_M_IX86) && !defined(_M_AMD64)
        KeFlushRangeTb(MiPteToAddress(PointerPte + 1), MI_ZERO_PTES, TRUE);
#endif
        /* On x86 and x64 no other processor is told: the window is used on one
           processor from its mapping to its unmapping, and that processor
           flushes it at both ends (below and in MiUnmapPagesInZeroSpace), so
           that no processor holds a translation of it that a later use could
           meet. An IPI to all processors per 32 pages stalled the others (disk
           completions, the lazy writer) for the 20 s the free memory of a
           large guest takes to zero. */
    }

    //
    // Prepare the next PTE
    //
    PointerPte->u.Hard.PageFrameNumber = Offset - NumberOfPages;

    /* Choose the correct PTE to use, and which template */
    PointerPte += (Offset + 1);
    TempPte = ValidKernelPte;

    /* Pages on the zeroed list may next be mapped uncached, so they must leave
       the zero page thread with no cached copy: through a cached mapping that
       takes CLFLUSH after the zeroing (MiUnmapPagesInZeroSpace), else the
       mapping is uncached */
#if defined(_M_IX86) || defined(_M_AMD64)
    if (MiZeroFlushLine == MAXULONG) MiReadZeroFlushLine();
    if (!MiZeroFlushLine)
#endif
    {
        /* Disable caching */
        MI_MAKE_PTE_NON_CACHED(&TempPte);
    }

    /* Make sure the list isn't empty and loop it */
    ASSERT(Pfn1 != (PVOID)LIST_HEAD);
    while (Pfn1 != (PVOID)LIST_HEAD)
    {
        /* Get the page index for this PFN */
        PageFrameIndex = MiGetPfnEntryIndex(Pfn1);

        //
        // Write the PFN
        //
        TempPte.u.Hard.PageFrameNumber = PageFrameIndex;

        //
        // Set the correct PTE to write to, and set its new value
        //
        PointerPte--;
        MI_WRITE_VALID_PTE(PointerPte, TempPte);

        /* Move to the next PFN */
        Pfn1 = (PMMPFN)Pfn1->u1.Flink;
    }

#if defined(_M_IX86) || defined(_M_AMD64)
    /* Drop what this processor may hold of the window (stale or speculative) */
    KxFlushRangeCurrentTb(MiPteToAddress(PointerPte), (ULONG)NumberOfPages);
#endif

    //
    // Return the address
    //
    return MiPteToAddress(PointerPte);
}

VOID
NTAPI
MiUnmapPagesInZeroSpace(IN PVOID VirtualAddress,
                        IN PFN_NUMBER NumberOfPages)
{
    PMMPTE PointerPte;

    //
    // Sanity checks
    //
    ASSERT(KeGetCurrentThread() == MiZeroPageThread);
#if defined(_M_IX86) || defined(_M_AMD64)
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
#else
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
#endif
    ASSERT (NumberOfPages != 0);
    ASSERT(NumberOfPages <= MI_ZERO_PTES);

    //
    // Get the first PTE for the mapped zero VA
    //
    PointerPte = MiAddressToPte(VirtualAddress);

#if defined(_M_IX86) || defined(_M_AMD64)
    /* Write the zeros back and drop them from every cache. The window turns
       uncached first, so that no line is refilled speculatively through it
       between its flush and the unmapping */
    if (MiZeroFlushLine)
    {
        PUCHAR Line, End = (PUCHAR)VirtualAddress + NumberOfPages * PAGE_SIZE;
        MMPTE TempPte;
        PFN_NUMBER i;

        for (i = 0; i < NumberOfPages; i++)
        {
            TempPte = PointerPte[i];
            MI_MAKE_PTE_NON_CACHED(&TempPte);
            MI_UPDATE_VALID_PTE(&PointerPte[i], TempPte);
        }
        KxFlushRangeCurrentTb(VirtualAddress, (ULONG)NumberOfPages);

        for (Line = VirtualAddress; Line < End; Line += MiZeroFlushLine)
            MiClflush(Line);
        _mm_mfence();
    }
#endif

    //
    // Blow away the mapped zero PTEs.
    // Note: no flush on other processors, see MiMapPagesInZeroSpace (x86, x64)
    //
    RtlZeroMemory(PointerPte, NumberOfPages * sizeof(MMPTE));

#if defined(_M_IX86) || defined(_M_AMD64)
    /* The zero page thread runs on one processor: drop its translations of the
       zeroed pages now, not at the next wrap */
    KxFlushRangeCurrentTb(VirtualAddress, (ULONG)NumberOfPages);
#endif
}

