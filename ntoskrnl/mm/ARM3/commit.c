/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     System-wide and per-process commit charge accounting
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

/*
 * Pages below the commit limit that only kernel-tier charges (pool, kernel
 * stack growth) may use, so that user requests fail before the kernel does.
 */
SIZE_T MiCommitReserve;

/* Boot-time memory charged at initialisation that may still be freed (loader data, INIT code) */
static volatile SIZE_T MiBootCommitCharge;

/*
 * Commitment that paging files can back: the copy-on-write views of the
 * legacy Mm, whose private pages MmPageOutPhysicalAddress writes to a paging
 * file. ARM3 has no working set trimming and no modified page writer for
 * private pages and paging file backed sections: what it commits is backed
 * by RAM alone. Windows never commits more than its backing store, and
 * without a paging file it limits commitment to RAM; a paging file that
 * the memory cannot be written to is no backing store for it. So the commit
 * limit counts paging file space only up to this much: committing ARM3
 * memory beyond RAM would only defer the failure from the allocation, which
 * can report it, to a page fault, which cannot (bugcheck 0x7A when a page
 * table page cannot be had for an address space operation).
 */
static volatile SIZE_T MiPageableCommittedPages;

/*
 * Part of RAM that commitments other than the kernel's leave to memory that
 * is not charged and must stay resident to run at all: image code and data,
 * mapped files, the cache, page tables. These are what the balancer can
 * reclaim; with all of RAM charged to memory that cannot be paged there is
 * nothing left to reclaim and the pages run out in a page fault.
 */
static SIZE_T MiResidentHeadroom;

/* PRIVATE FUNCTIONS **********************************************************/

static
VOID
MiUpdatePeakCommitment(
    _In_ SIZE_T TotalCommittedPages)
{
    SIZE_T PeakCommitment = MmPeakCommitment;

    while ((TotalCommittedPages > PeakCommitment) &&
           (InterlockedCompareExchangeSizeT(&MmPeakCommitment,
                                            TotalCommittedPages,
                                            PeakCommitment) != PeakCommitment))
    {
        PeakCommitment = MmPeakCommitment;
    }
}

/* What RAM can back, Headroom left over, plus what paging files can back */
static
SIZE_T
MiGetBackedCeiling(
    _In_ SIZE_T Headroom)
{
    SIZE_T Backed = MmNumberOfPhysicalPages + MiPageableCommittedPages;

    return (Backed > Headroom) ? (Backed - Headroom) : 0;
}

static
SIZE_T
MiGetCommitCeiling(
    _In_ SIZE_T Headroom)
{
    SIZE_T Limit = *(volatile SIZE_T *)&MmTotalCommitLimit;

    return min(Limit, MiGetBackedCeiling(Headroom));
}

/*
 * The commit limit: RAM less the resident headroom, plus the paging file
 * space that pageable commitment can use. User commitment is charged against
 * it (less the kernel reserve). Kernel charges may also use the headroom.
 * The system reports MiGetReportedCommitLimit() instead (RAM plus paging
 * files, as Windows does).
 */
SIZE_T
NTAPI
MiGetCommitLimit(VOID)
{
    return MiGetCommitCeiling(MiResidentHeadroom);
}

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeCommitLimit(VOID)
{
    SIZE_T Available, BootResident, RamPart;

    /*
     * The RAM part of the limit is all of physical memory, as Windows reports
     * it. What Mm cannot hand out any more at this point (the loader, the
     * kernel, the PFN database, initial nonpaged pool, a margin of 1024
     * pages) and was not charged already is resident for good: charge it now,
     * so that only the rest is left for commitments.
     */
    Available = MmAvailablePages;
    if (Available > 1024) Available -= 1024;
    BootResident = 0;
    if (MmNumberOfPhysicalPages > Available + MmTotalCommittedPages)
        BootResident = MmNumberOfPhysicalPages - Available - MmTotalCommittedPages;

    MmTotalCommitLimit = MmNumberOfPhysicalPages;
    MmTotalCommitLimitMaximum = MmNumberOfPhysicalPages;
    MiBootCommitCharge = BootResident;
    InterlockedExchangeAddSizeT(&MmTotalCommittedPages, BootResident);
    MiUpdatePeakCommitment(MmTotalCommittedPages);

    /* The reserve is a share of the memory commitments can actually have */
    RamPart = Available + MmTotalCommittedPages - BootResident;
    MiCommitReserve = RamPart / 64;
    if (MiCommitReserve < 1024) MiCommitReserve = 1024;
    if (MiCommitReserve > 8192) MiCommitReserve = 8192;

    /* An eighth of RAM, 16 MB to 1 GB, for what is resident but not charged */
    MiResidentHeadroom = MmNumberOfPhysicalPages / 8;
    if (MiResidentHeadroom < (16 * _1MB) / PAGE_SIZE) MiResidentHeadroom = (16 * _1MB) / PAGE_SIZE;
    if (MiResidentHeadroom > _1GB / PAGE_SIZE) MiResidentHeadroom = _1GB / PAGE_SIZE;

    DPRINT1("Commit limit %Iu pages (RAM), %Iu charged for boot-time memory, reserve %Iu pages, resident headroom %Iu pages\n",
            MmTotalCommitLimit, BootResident, MiCommitReserve, MiResidentHeadroom);
}

VOID
NTAPI
MiReturnBootCommit(
    _In_ SIZE_T Pages)
{
    SIZE_T Charged, Returned;

    /* Freed boot-time pages give back their part of the initial charge, never more */
    do
    {
        Charged = MiBootCommitCharge;
        Returned = min(Pages, Charged);
        if (Returned == 0)
            return;
    } while (InterlockedCompareExchangeSizeT(&MiBootCommitCharge, Charged - Returned, Charged) != Charged);

    MiReturnCommit(Returned);
}

BOOLEAN
NTAPI
MiChargeCommit(
    _In_ SIZE_T Pages,
    _In_ MI_COMMIT_TIER Tier)
{
    SIZE_T OldCommitted, NewCommitted, Ceiling, Headroom;

    if (Pages == 0)
        return TRUE;

    /*
     * Critical tier: the System process and critical processes (csrss, lsass,
     * winlogon...) do not give up the resident headroom. When an application
     * fills the cap, these must still be able to allocate, or the system dies
     * (bugcheck 0xF4 when a critical process cannot continue).
     */
    Headroom = MiResidentHeadroom;
    if ((Tier == MiCommitKernel) || MiIsCriticalProcess(PsGetCurrentProcess()))
        Headroom = 0;

    for (;;)
    {
        OldCommitted = *(volatile SIZE_T *)&MmTotalCommittedPages;
        NewCommitted = OldCommitted + Pages;
        if (NewCommitted < OldCommitted)
            return FALSE;

        /* Only pageable commitment may use the paging files beyond RAM */
        if (Tier == MiCommitUserPageable)
            Ceiling = *(volatile SIZE_T *)&MmTotalCommitLimit;
        else
            Ceiling = MiGetCommitCeiling(Headroom);
        if (Tier != MiCommitKernel)
            Ceiling = (Ceiling > MiCommitReserve) ? (Ceiling - MiCommitReserve) : 0;

        if (NewCommitted > Ceiling)
            return FALSE;

        if (InterlockedCompareExchangeSizeT(&MmTotalCommittedPages,
                                            NewCommitted,
                                            OldCommitted) == OldCommitted)
        {
            break;
        }
    }

    if (Tier == MiCommitUserPageable)
        InterlockedExchangeAddSizeT(&MiPageableCommittedPages, Pages);

    MiUpdatePeakCommitment(NewCommitted);
    return TRUE;
}

SIZE_T
NTAPI
MiGetPageableCommittedPages(VOID)
{
    return *(volatile SIZE_T *)&MiPageableCommittedPages;
}

BOOLEAN
NTAPI
MiIsCriticalProcess(
    _In_opt_ PEPROCESS Process)
{
    /* Before the first process exists, charges are the kernel's own */
    if ((Process == NULL) || (Process == PsIdleProcess) || (Process == PsInitialSystemProcess))
        return TRUE;

    return Process->BreakOnTermination != 0;
}

/* Return a charge taken with MiCommitUserPageable */
VOID
NTAPI
MiReturnPageableCommit(
    _In_ SIZE_T Pages)
{
    SIZE_T OldPageable;

    if (Pages == 0)
        return;

    OldPageable = InterlockedExchangeAddSizeT(&MiPageableCommittedPages, -(LONG_PTR)Pages);
    if (OldPageable < Pages)
    {
        DPRINT1("MiReturnPageableCommit: returning %Iu pages, only %Iu charged\n", Pages, OldPageable);
        ASSERT(FALSE);
        InterlockedExchangeAddSizeT(&MiPageableCommittedPages, Pages - OldPageable);
    }

    MiReturnCommit(Pages);
}

VOID
NTAPI
MiReturnCommit(
    _In_ SIZE_T Pages)
{
    SIZE_T OldCommitted;

    if (Pages == 0)
        return;

    OldCommitted = InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -(LONG_PTR)Pages);
    if (OldCommitted < Pages)
    {
        /* More was returned than charged: put the difference back */
        DPRINT1("MiReturnCommit: returning %Iu pages, only %Iu charged\n", Pages, OldCommitted);
        ASSERT(FALSE);
        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, Pages - OldCommitted);
    }
}

/*
 * A kernel-tier charge failed (pool, which returns NULL silently). Log it,
 * rate-limited to one line per 5 s plus a count of the suppressed ones, and
 * kick the paging file growth thread without waiting. Observability only: the
 * charge semantics are unchanged.
 */
VOID
NTAPI
MiReportKernelCommitFailure(
    _In_ SIZE_T Pages,
    _In_ PCSTR Site)
{
    static volatile LONG64 NextReport;
    static volatile LONG Suppressed;
    LONG64 Now, Next;
    SIZE_T Committed, Limit;

    Committed = MmTotalCommittedPages;
    Limit = MiGetCommitLimit();

    /* Room for this charge, were the limit raised; growth cannot raise it past RAM plus pageable commitment */
    if ((Committed + Pages > MmTotalCommitLimit) && (MmTotalCommitLimit < MiGetBackedCeiling(0)))
        MiRequestPagingFileGrowth(Committed + Pages - MmTotalCommitLimit);

    Now = (LONG64)KeQueryInterruptTime();
    Next = NextReport;
    if ((Now < Next) ||
        (InterlockedCompareExchange64(&NextReport, Now + 5 * 10000000LL, Next) != Next))
    {
        InterlockedIncrement(&Suppressed);
        return;
    }

    DPRINT1("MM: kernel commit charge failed at %s: %Iu pages, committed %Iu limit %Iu reserve %Iu (%ld similar suppressed)\n",
            Site, Pages, Committed, Limit, MiCommitReserve, InterlockedExchange(&Suppressed, 0));
}

BOOLEAN
NTAPI
MiWaitForCommitGrowth(
    _In_ SIZE_T Pages)
{
    SIZE_T Ceiling, Committed;

    /* Grow by what a user charge of this size lacks now, not by its size */
    Ceiling = MiGetCommitLimit();
    Ceiling = (Ceiling > MiCommitReserve) ? (Ceiling - MiCommitReserve) : 0;
    Committed = MmTotalCommittedPages;
    if (Committed + Pages <= Ceiling)
        return TRUE;

    /* RAM binds, not the paging files: growing them cannot make room for memory that cannot be paged */
    if (MmTotalCommitLimit >= MiGetBackedCeiling(MiResidentHeadroom))
        return FALSE;

    return MiWaitForPagingFileGrowth(Committed + Pages - Ceiling);
}

BOOLEAN
NTAPI
MiChargeCommitWithGrowth(
    _In_ SIZE_T Pages)
{
    ULONG Round;

    if (MiChargeCommit(Pages, MiCommitUser))
        return TRUE;

    /*
     * Growth means waiting for file I/O in another thread. A caller that
     * holds a guarded or fast mutex may hold a lock that I/O needs. Every
     * successful growth is followed by another attempt.
     */
    for (Round = 0; Round < 4; Round++)
    {
        if (KeAreAllApcsDisabled() || !MiWaitForCommitGrowth(Pages))
            break;

        if (MiChargeCommit(Pages, MiCommitUser))
            return TRUE;
    }

    return FALSE;
}

VOID
NTAPI
MiAddProcessCommit(
    _Inout_ PEPROCESS Process,
    _In_ SIZE_T Pages)
{
    SIZE_T NewCharge, Peak;

    if (Pages == 0)
        return;

    NewCharge = InterlockedExchangeAddSizeT(&Process->CommitCharge, Pages) + Pages;

    Peak = Process->CommitChargePeak;
    while ((NewCharge > Peak) &&
           (InterlockedCompareExchangeSizeT(&Process->CommitChargePeak, NewCharge, Peak) != Peak))
    {
        Peak = Process->CommitChargePeak;
    }
}

VOID
NTAPI
MiSubtractProcessCommit(
    _Inout_ PEPROCESS Process,
    _In_ SIZE_T Pages)
{
    SIZE_T OldCharge;

    if (Pages == 0)
        return;

    OldCharge = InterlockedExchangeAddSizeT(&Process->CommitCharge, -(LONG_PTR)Pages);
    if (OldCharge < Pages)
    {
        DPRINT1("MiSubtractProcessCommit: process %p returns %Iu pages, only %Iu charged\n",
                Process, Pages, OldCharge);
        ASSERT(FALSE);
        InterlockedExchangeAddSizeT(&Process->CommitCharge, Pages - OldCharge);
    }
}

VOID
NTAPI
MiReturnProcessCommit(
    _Inout_ PEPROCESS Process,
    _In_ SIZE_T Pages)
{
    MiSubtractProcessCommit(Process, Pages);
    MiReturnCommit(Pages);
}

/* EOF */
