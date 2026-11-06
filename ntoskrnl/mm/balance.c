/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS kernel
 * PURPOSE:     kernel memory management functions
 * PROGRAMMERS: David Welch <welch@cwcom.net>
 *              Cameron Gutman <cameron.gutman@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#include "ARM3/miarm.h"


/* TYPES ********************************************************************/
typedef struct _MM_ALLOCATION_REQUEST
{
    PFN_NUMBER Page;
    LIST_ENTRY ListEntry;
    KEVENT Event;
}
MM_ALLOCATION_REQUEST, *PMM_ALLOCATION_REQUEST;
/* GLOBALS ******************************************************************/

MM_MEMORY_CONSUMER MiMemoryConsumers[MC_MAXIMUM];
static ULONG MiMinimumAvailablePages;
/*
 * Free pages the balancer works to keep (see MmInitializeBalancer). Reclaim used to start only
 * below MiMinimumAvailablePages (256 pages): cache views and file data then filled every free page
 * between two 2 s timer passes, the free list sat at 0, reclaim could only page out user pages one
 * at a time, and metadata pins (which cannot wait for pages) failed with STATUS_NO_MEMORY half way
 * through a file system operation.
 */
static ULONG MiLowWaterPages;
static ULONG MiMinimumPagesPerRun;
static CLIENT_ID MiBalancerThreadId;
static HANDLE MiBalancerThreadHandle = NULL;
static KEVENT MiBalancerEvent;
static KEVENT MiBalancerDoneEvent;
static KTIMER MiBalancerTimer;

static LONG PageOutThreadActive;

/* FUNCTIONS ****************************************************************/

CODE_SEG("INIT")
VOID
NTAPI
MmInitializeBalancer(ULONG NrAvailablePages, ULONG NrSystemPages)
{
    memset(MiMemoryConsumers, 0, sizeof(MiMemoryConsumers));

    /* Set up targets. */
    MiMinimumAvailablePages = 256;
    MiMinimumPagesPerRun = 256;
    /* 1/32 of the pages at start (8 MB at 256 MB, 32 MB from 1 GB), at least 4 MB */
    MiLowWaterPages = min(max(NrAvailablePages / 32, 1024), 8192);
    MiMemoryConsumers[MC_USER].PagesTarget = NrAvailablePages / 2;
}

CODE_SEG("INIT")
VOID
NTAPI
MmInitializeMemoryConsumer(
    ULONG Consumer,
    NTSTATUS (*Trim)(ULONG Target, ULONG Priority, PULONG NrFreed))
{
    MiMemoryConsumers[Consumer].Trim = Trim;
}

VOID
NTAPI
MiZeroPhysicalPage(
    IN PFN_NUMBER PageFrameIndex
);

NTSTATUS
NTAPI
MmReleasePageMemoryConsumer(ULONG Consumer, PFN_NUMBER Page)
{
    KIRQL OldIrql;

    if (Page == 0)
    {
        DPRINT1("Tried to release page zero.\n");
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    (void)InterlockedDecrementUL(&MiMemoryConsumers[Consumer].PagesUsed);

    OldIrql = MiAcquirePfnLock();

    MmDereferencePage(Page);

    MiReleasePfnLock(OldIrql);

    return(STATUS_SUCCESS);
}

ULONG
NTAPI
MiTrimMemoryConsumer(ULONG Consumer, ULONG InitialTarget)
{
    ULONG Target = InitialTarget;
    ULONG NrFreedPages = 0;
    NTSTATUS Status;
    /* UF-22: snapshot once; the compare and the subtract below must see the same value, or a
     * concurrent rise above the minimum underflows the unsigned subtraction into a giant target. */
    ULONG Available = MmAvailablePages;
    /* UF-22: same hazard on the consumer counter; a concurrent page release between the test and the
     * subtract would drop PagesUsed below the target and underflow it into a giant target. */
    ULONG PagesUsed = MiMemoryConsumers[Consumer].PagesUsed;

    /* Make sure we can trim this consumer */
    if (!MiMemoryConsumers[Consumer].Trim)
    {
        /* Return the unmodified initial target */
        return InitialTarget;
    }

    if (Available < MiMinimumAvailablePages)
    {
        /* Global page limit exceeded */
        Target = (ULONG)max(Target, MiMinimumAvailablePages - Available);
    }
    else if (PagesUsed > MiMemoryConsumers[Consumer].PagesTarget)
    {
        /* Consumer page limit exceeded */
        Target = max(Target, PagesUsed - MiMemoryConsumers[Consumer].PagesTarget);
    }

    if (Target)
    {
        /* Now swap the pages out */
        Status = MiMemoryConsumers[Consumer].Trim(Target, Available < MiMinimumAvailablePages, &NrFreedPages);

        DPRINT("Trimming consumer %lu: Freed %lu pages with a target of %lu pages\n", Consumer, NrFreedPages, Target);

        if (!NT_SUCCESS(Status))
        {
            KeBugCheck(MEMORY_MANAGEMENT);
        }
    }

    /* Return the page count needed to be freed to meet the initial target */
    return (InitialTarget > NrFreedPages) ? (InitialTarget - NrFreedPages) : 0;
}

NTSTATUS
MmTrimUserMemory(ULONG Target, ULONG Priority, PULONG NrFreedPages)
{
    PFN_NUMBER FirstPage, CurrentPage;
    NTSTATUS Status;

    (*NrFreedPages) = 0;

    DPRINT("MM BALANCER: %s\n", Priority ? "Paging out!" : "Removing access bit!");

    FirstPage = MmGetLRUFirstUserPage();
    CurrentPage = FirstPage;
    while (CurrentPage != 0 && Target > 0)
    {
        if (Priority)
        {
            Status = MmPageOutPhysicalAddress(CurrentPage);
            if (NT_SUCCESS(Status))
            {
                DPRINT("Succeeded\n");
                Target--;
                (*NrFreedPages)++;
                if (CurrentPage == FirstPage)
                {
                    FirstPage = 0;
                }
            }
        }
        else
        {
            /* When not paging-out agressively, just reset the accessed bit */
            PEPROCESS Process = NULL;
            PVOID Address = NULL;
            BOOLEAN Accessed = FALSE;

            /*
             * We have a lock-ordering problem here. We cant lock the PFN DB before the Process address space.
             * So we must use circonvoluted loops.
             * Well...
             */
            while (TRUE)
            {
                KAPC_STATE ApcState;
                KIRQL OldIrql = MiAcquirePfnLock();
                PMM_RMAP_ENTRY Entry = MmGetRmapListHeadPage(CurrentPage);
                while (Entry)
                {
                    if (RMAP_IS_SEGMENT(Entry->Address))
                    {
                        Entry = Entry->Next;
                        continue;
                    }

                    /* Check that we didn't treat this entry before */
                    if (Entry->Address < Address)
                    {
                        Entry = Entry->Next;
                        continue;
                    }

                    if ((Entry->Address == Address) && (Entry->Process <= Process))
                    {
                        Entry = Entry->Next;
                        continue;
                    }

                    break;
                }

                if (!Entry)
                {
                    MiReleasePfnLock(OldIrql);
                    break;
                }

                Process = Entry->Process;
                Address = Entry->Address;

                ObReferenceObject(Process);

                if (!ExAcquireRundownProtection(&Process->RundownProtect))
                {
                    ObDereferenceObject(Process);
                    MiReleasePfnLock(OldIrql);
                    continue;
                }

                MiReleasePfnLock(OldIrql);

                KeStackAttachProcess(&Process->Pcb, &ApcState);
                MiLockProcessWorkingSet(Process, PsGetCurrentThread());

                /* Be sure this is still valid. */
                if (MmIsAddressValid(Address))
                {
                    PMMPTE Pte = MiAddressToPte(Address);
                    Accessed = Accessed || Pte->u.Hard.Accessed;
                    Pte->u.Hard.Accessed = 0;

                    /* There is no need to invalidate, the balancer thread is never on a user process */
                    //KeInvalidateTlbEntry(Address);
                }

                MiUnlockProcessWorkingSet(Process, PsGetCurrentThread());

                KeUnstackDetachProcess(&ApcState);
                ExReleaseRundownProtection(&Process->RundownProtect);
                ObDereferenceObject(Process);
            }

            if (!Accessed)
            {
                /* Nobody accessed this page since the last time we check. Time to clean up */

                Status = MmPageOutPhysicalAddress(CurrentPage);
                if (NT_SUCCESS(Status))
                {
                    if (CurrentPage == FirstPage)
                    {
                        FirstPage = 0;
                    }
                }
                // DPRINT1("Paged-out one page: %s\n", NT_SUCCESS(Status) ? "Yes" : "No");
            }

            /* Done for this page. */
            Target--;
        }

        CurrentPage = MmGetLRUNextUserPage(CurrentPage, TRUE);
        if (FirstPage == 0)
        {
            FirstPage = CurrentPage;
        }
        else if (CurrentPage == FirstPage)
        {
            DPRINT1("We are back at the start, abort!\n");
            /* Leave through the common exit: it drops our reference on CurrentPage */
            break;
        }
    }

    if (CurrentPage)
    {
        KIRQL OldIrql = MiAcquirePfnLock();
        MmDereferencePage(CurrentPage);
        MiReleasePfnLock(OldIrql);
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
MmRebalanceMemoryConsumers(VOID)
{
    if (InterlockedCompareExchange(&PageOutThreadActive, 1, 0) == 0)
    {
        KeSetEvent(&MiBalancerEvent, IO_NO_INCREMENT, FALSE);
    }
}

BOOLEAN
NTAPI
MiThreadCanWaitForBalancer(
    _In_ BOOLEAN IgnoreWorkingSetLocks)
{
    PETHREAD Thread = PsGetCurrentThread();
    PMMSUPPORT KernelSpace = MmGetKernelAddressSpace();

    if (PsGetCurrentProcess()->AddressCreationLock.Owner == &Thread->Tcb)
        return FALSE;
    if (KernelSpace &&
        (CONTAINING_RECORD(KernelSpace, EPROCESS, Vm)->AddressCreationLock.Owner == &Thread->Tcb))
        return FALSE;
    if (!IgnoreWorkingSetLocks && MM_ANY_WS_LOCK_HELD(Thread))
        return FALSE;
    if (PsGetCurrentThreadId() == MiBalancerThreadId.UniqueThread)
        return FALSE;

    return TRUE;
}

BOOLEAN
NTAPI
MmRebalanceMemoryConsumersAndWait(VOID)
{
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    /*
     * A fault taken while this thread holds an address space lock (a page
     * table brought in by NtAllocateVirtualMemory, for example) must not
     * wait for a balancer pass, which may need that lock to page out; nor
     * can the balancer wait for itself when it faults while writing pages
     * back. Start it, give it a moment, and let the caller retry. This does
     * not guarantee progress: the balancer still blocks if it needs the
     * lock this thread keeps across the retries.
     */
    if (!MiThreadCanWaitForBalancer(FALSE))
    {
        LARGE_INTEGER Delay;

        Delay.QuadPart = -10 * 10000;
        MmRebalanceMemoryConsumers();
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        /* We could only spin: a lock this thread holds may be the very one the
         * balancer needs, so this makes no guaranteed progress. Report it so the
         * caller can bound the retries instead of livelocking forever behind that
         * lock (T16). */
        return FALSE;
    }

    KeResetEvent(&MiBalancerDoneEvent);
    MmRebalanceMemoryConsumers();
    KeWaitForSingleObject(&MiBalancerDoneEvent, Executive, KernelMode, FALSE, NULL);

    /* A real balancer pass ran: progress is possible, the caller may retry. */
    return TRUE;
}

NTSTATUS
NTAPI
MmRequestPageMemoryConsumer(ULONG Consumer, BOOLEAN CanWait,
                            PPFN_NUMBER AllocatedPage)
{
    PFN_NUMBER Page;
    ULONG Pace = 0, Dirty, Low, Range;
    static LONG Requests;
    static LARGE_INTEGER TinyTime = {{-1L, -1L}};

    /*
     * Pace the requests with one tick every Pace-th request (CORE-17624). While pages are short,
     * every hundredth, as this function always did. While dirty cache data exceeds a quarter of
     * the dirty page threshold, every hundredth at first and more often as it grows, up to every
     * fourth at three eighths, so that a writer cannot fill the cache views with dirty data
     * faster than the lazy writer cleans them. With free pages and a clean cache nothing waits.
     */
    if (MmAvailablePages < MiMinimumAvailablePages)
        Pace = 100;

    Dirty = CcTotalDirtyPages;
    Low = CcDirtyPageThreshold / 4;
    Range = max(CcDirtyPageThreshold / 8, 1);
    if (Dirty > Low)
        Pace = (Dirty - Low >= Range) ? 4 : 100 - (ULONG)((ULONGLONG)96 * (Dirty - Low) / Range);

    if ((Pace != 0) &&
        (PsGetCurrentThreadId() != MiBalancerThreadId.UniqueThread) &&
        (KeGetCurrentIrql() < DISPATCH_LEVEL) &&
        ((ULONG)InterlockedIncrement(&Requests) % Pace == 0))
    {
        KeDelayExecutionThread(KernelMode, FALSE, &TinyTime);
    }

    /*
     * Start reclaiming before the free list is empty: a pass trims clean cache views up to the
     * low-water mark (MiBalancerThread), which is cheap, instead of paging out user pages once
     * everything is gone. Asynchronous, the caller does not wait here.
     */
    if (MmAvailablePages < MiLowWaterPages)
        MmRebalanceMemoryConsumers();

    /*
     * Actually allocate the page.
     */
    Page = MmAllocPage(Consumer);
    if (Page == 0)
    {
        *AllocatedPage = 0;
        return STATUS_NO_MEMORY;
    }
    *AllocatedPage = Page;

    /* Update the target */
    InterlockedIncrementUL(&MiMemoryConsumers[Consumer].PagesUsed);

    return(STATUS_SUCCESS);
}

VOID
CcRosTrimCache(
    _In_ ULONG Target,
    _Out_ PULONG NrFreed);

VOID
NTAPI
MiBalancerThread(PVOID Unused)
{
    PVOID WaitObjects[2];
    NTSTATUS Status;

    WaitObjects[0] = &MiBalancerEvent;
    WaitObjects[1] = &MiBalancerTimer;

    while (TRUE)
    {
        KeSetEvent(&MiBalancerDoneEvent, IO_NO_INCREMENT, FALSE);
        Status = KeWaitForMultipleObjects(_countof(WaitObjects),
                                          WaitObjects,
                                          WaitAny,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          NULL,
                                          NULL);

        if (Status == STATUS_WAIT_0 || Status == STATUS_WAIT_1)
        {
            ULONG InitialTarget = 0;
            ULONG Target;
            ULONG NrFreedPages;

            do
            {
                ULONG OldTarget = InitialTarget;

                /* Trim each consumer */
                for (ULONG i = 0; i < MC_MAXIMUM; i++)
                {
                    InitialTarget = MiTrimMemoryConsumer(i, InitialTarget);
                }

                /* Trim cache */
                /* UF-22: snapshot MmAvailablePages once, then trim the cache only for the shortfall
                 * below the low-water mark. abs() of the unsigned difference evicted the whole clean cache
                 * every timer pass when memory was plentiful; reading MmAvailablePages twice (compare
                 * then subtract) could also race a concurrent change and underflow into a giant target. */
                ULONG Avail = MmAvailablePages;
                Target = max(InitialTarget, Avail < MiLowWaterPages ? MiLowWaterPages - Avail : 0);
                if (Target)
                {
                    CcRosTrimCache(Target, &NrFreedPages);
                    InitialTarget -= min(NrFreedPages, InitialTarget);
                }

                /* No pages left to swap! */
                if (InitialTarget != 0 &&
                    InitialTarget == OldTarget)
                {
                    /* Game over */
                    KeBugCheck(NO_PAGES_AVAILABLE);
                }
            }
            while (InitialTarget != 0);

            if (Status == STATUS_WAIT_0)
            {
                LONG Active = InterlockedExchange(&PageOutThreadActive, 0);
                ASSERT(Active == 1);
                DBG_UNREFERENCED_LOCAL_VARIABLE(Active);
            }
        }
        else
        {
            DPRINT1("KeWaitForMultipleObjects failed, status = %x\n", Status);
            KeBugCheck(MEMORY_MANAGEMENT);
        }
    }
}

CODE_SEG("INIT")
VOID
NTAPI
MiInitBalancerThread(VOID)
{
    KPRIORITY Priority;
    NTSTATUS Status;
    LARGE_INTEGER Timeout;

    KeInitializeEvent(&MiBalancerEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&MiBalancerDoneEvent, SynchronizationEvent, FALSE);
    KeInitializeTimerEx(&MiBalancerTimer, SynchronizationTimer);

    Timeout.QuadPart = -20000000; /* 2 sec */
    KeSetTimerEx(&MiBalancerTimer,
                 Timeout,
                 2000,         /* 2 sec */
                 NULL);

    Status = PsCreateSystemThread(&MiBalancerThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  NULL,
                                  &MiBalancerThreadId,
                                  MiBalancerThread,
                                  NULL);
    if (!NT_SUCCESS(Status))
    {
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    Priority = LOW_REALTIME_PRIORITY + 1;
    NtSetInformationThread(MiBalancerThreadHandle,
                           ThreadPriority,
                           &Priority,
                           sizeof(Priority));

}


/* EOF */
