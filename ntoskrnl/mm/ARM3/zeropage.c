/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/zeropage.c
 * PURPOSE:         ARM Memory Manager Zero Page Thread Support
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

KEVENT MmZeroingPageEvent;
PKTHREAD MiZeroPageThread;

/*
 * The thread keeps this many zeroed pages ready, no more: the allocator uses a
 * zeroed page when there is one and zeroes a free one itself when there is
 * none, so zeroing every free page ahead only touches memory nobody asked for
 * yet. In a virtual machine whose memory the host backs on first touch that
 * was the whole of the guest's RAM, written once after every boot: several
 * seconds of one processor in the first half minute, during which the
 * processes of the system ran 3 to 25 times slower. The target is a thirtieth
 * of the physical memory, from 32 MB to 256 MB.
 */
PFN_NUMBER MiZeroedPageTarget;
#define MI_ZERO_TARGET_MIN_PAGES    (32 * 1024 * 1024 / PAGE_SIZE)
#define MI_ZERO_TARGET_MAX_PAGES    (256 * 1024 * 1024 / PAGE_SIZE)

/*
 * Pages zeroed in one step. A step runs at DISPATCH_LEVEL on one processor, and
 * a thread readied on it meanwhile waits for the end of the step: 32 pages
 * (128 KB, with the cache flush of each line) took about 340 microseconds.
 */
#define MI_ZERO_STEP_PAGES          4
C_ASSERT(MI_ZERO_STEP_PAGES <= MI_ZERO_PTES);

/* PRIVATE FUNCTIONS **********************************************************/

VOID
NTAPI
MiFindInitializationCode(OUT PVOID *StartVa,
OUT PVOID *EndVa);

VOID
NTAPI
MiFreeInitializationCode(IN PVOID StartVa,
IN PVOID EndVa);

VOID
NTAPI
MmZeroPageThread(VOID)
{
    PKTHREAD Thread = KeGetCurrentThread();
    PVOID StartAddress, EndAddress;
    LARGE_INTEGER Timeout;

    ASSERT(MiZeroPageThread == NULL);
    MiZeroPageThread = Thread;

    /* Get the discardable sections to free them */
    MiFindInitializationCode(&StartAddress, &EndAddress);
    if (StartAddress) MiFreeInitializationCode(StartAddress, EndAddress);
    DPRINT("Free pages: %lx\n", MmAvailablePages);

    /* Boot is done with the free lists: from now on a freed page is the next one used (pfnlist.c) */
    {
        KIRQL Irql = MiAcquirePfnLock();
        MiFreeListLifo = TRUE;
        MiReleasePfnLock(Irql);
    }

    /* Set our priority to 0 */
    Thread->BasePriority = 0;
    KeSetPriorityThread(Thread, 0);

    /* How many zeroed pages to keep ready (see MiZeroedPageTarget) */
    MiZeroedPageTarget = min(max(MmNumberOfPhysicalPages / 32, MI_ZERO_TARGET_MIN_PAGES),
                             MI_ZERO_TARGET_MAX_PAGES);

    /* A top up that finds nothing to do waits for a freed page, or for a second */
    Timeout.QuadPart = -10 * 1000 * 1000;

    while (TRUE)
    {
        KIRQL OldIrql;

        OldIrql = MiAcquirePfnLock();

        while (TRUE)
        {
            ULONG PageCount = 0;
            PMMPFN Pfn1 = (PMMPFN)LIST_HEAD;
            PVOID ZeroAddress;
            PFN_NUMBER PageIndex, FreePage;
#if defined(_M_IX86) || defined(_M_AMD64)
            KIRQL ZeroIrql;
#endif

            while (PageCount < MI_ZERO_STEP_PAGES)
            {
                PMMPFN Pfn2;

                if (!MmFreePageListHead.Total)
                    break;

                /* Enough zeroed pages are ready */
                if (MmZeroedPageListHead.Total >= MiZeroedPageTarget)
                    break;

                PageIndex = MmFreePageListHead.Flink;
                ASSERT(PageIndex != LIST_HEAD);
                MI_SET_USAGE(MI_USAGE_ZERO_LOOP);
                MI_SET_PROCESS2("Kernel 0 Loop");
                FreePage = MiRemoveAnyPage(MI_GET_PAGE_COLOR(PageIndex));

                /* The first global free page should also be the first on its own list */
                if (FreePage != PageIndex)
                {
                    KeBugCheckEx(PFN_LIST_CORRUPT,
                                0x8F,
                                FreePage,
                                PageIndex,
                                0);
                }

                Pfn2 = MiGetPfnEntry(PageIndex);
                Pfn2->u1.Flink = (PFN_NUMBER)Pfn1;
                Pfn1 = Pfn2;
                PageCount++;
            }
            MiReleasePfnLock(OldIrql);

            if (PageCount == 0)
            {
                KeClearEvent(&MmZeroingPageEvent);
                break;
            }

#if defined(_M_IX86) || defined(_M_AMD64)
            /* Stay on this processor while the pages are mapped: their
               translations are flushed here, with no IPI to the others */
            KeRaiseIrql(DISPATCH_LEVEL, &ZeroIrql);
#endif
            ZeroAddress = MiMapPagesInZeroSpace(Pfn1, PageCount);
            ASSERT(ZeroAddress);
            KeZeroPages(ZeroAddress, PageCount * PAGE_SIZE);
            MiUnmapPagesInZeroSpace(ZeroAddress, PageCount);
#if defined(_M_IX86) || defined(_M_AMD64)
            KeLowerIrql(ZeroIrql);
#endif

            OldIrql = MiAcquirePfnLock();

            while (Pfn1 != (PMMPFN)LIST_HEAD)
            {
                PageIndex = MiGetPfnEntryIndex(Pfn1);
                Pfn1 = (PMMPFN)Pfn1->u1.Flink;
                MiInsertPageInList(&MmZeroedPageListHead, PageIndex);
            }
        }

        /* The PFN lock is not held here: wait for a freed page (the event is set only while
           fewer zeroed pages are ready than the target, see MiInsertPageInFreeList) or for
           a second, in case the zeroed pages were used up with no page freed since */
        KeWaitForSingleObject(&MmZeroingPageEvent,
                              WrFreePage,
                              KernelMode,
                              FALSE,
                              &Timeout);
    }
}

/* EOF */
