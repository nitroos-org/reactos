/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/critical.c
 * PURPOSE:         Critical sections
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  Gunnar Dalsnes
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>
#include <reactos/verifier.h>

#define MAX_STATIC_CS_DEBUG_OBJECTS 64

static RTL_CRITICAL_SECTION RtlCriticalSectionLock;
static LIST_ENTRY RtlCriticalSectionList = {&RtlCriticalSectionList, &RtlCriticalSectionList};
static BOOLEAN RtlpCritSectInitialized = FALSE;
static RTL_CRITICAL_SECTION_DEBUG RtlpStaticDebugInfo[MAX_STATIC_CS_DEBUG_OBJECTS];
/* Claimed and released with interlocked operations: threads initialize and delete sections concurrently */
static LONG RtlpDebugInfoFreeList[MAX_STATIC_CS_DEBUG_OBJECTS];

LARGE_INTEGER RtlpTimeout;
BOOLEAN RtlpTimeoutDisable;
BOOLEAN RtlpCriticalSectionVerifier = FALSE;

extern BOOLEAN LdrpShutdownInProgress;
extern HANDLE LdrpShutdownThreadId;

/* FUNCTIONS *****************************************************************/

#define CRITSECT_HAS_DEBUG_INFO(CriticalSection) \
    (((CriticalSection)->DebugInfo != NULL) && \
     ((CriticalSection)->DebugInfo != LongToPtr(-1)))

/*
 * LockCount holds the state of the section as on Windows Server 2003 SP1
 * and later: bit 0 is set while the section is free, bit 1 is set while no
 * woken waiter is on its way back, and every waiting thread subtracts 4.
 * -1 is a free section nobody waits for, -2 an owned one (the owner's
 * recursion is in RecursionCount only); see RTLP_CS_* in rtlp.h.
 *
 * Leaving frees the section before it wakes a waiter, and the woken thread
 * competes for it with the running ones. Ownership is not handed to a
 * waiter that is not running yet: with that, the section stays owned for
 * the time a wake-up takes, every thread arriving meanwhile has to wait and
 * be woken in turn as well, and a section that many threads use stays in
 * that state (a lock convoy) until they stop using it.
 */

/* Take the section if it is free. TRUE when the caller now owns it. */
FORCEINLINE
BOOLEAN
RtlpTryTakeCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection)
{
    LONG Old = *(volatile LONG *)&CriticalSection->LockCount;
    LONG Previous;

    while (Old & RTLP_CS_FREE)
    {
        Previous = InterlockedCompareExchange(&CriticalSection->LockCount,
                                              Old - RTLP_CS_FREE,
                                              Old);
        if (Previous == Old)
            return TRUE;
        Old = Previous;
    }

    return FALSE;
}

/*++
 * RtlpCreateCriticalSectionSem
 *
 *     Checks if an Event has been created for the critical section.
 *
 * Params:
 *     None
 *
 * Returns:
 *     None. Raises an exception if the system call failed.
 *
 * Remarks:
 *     None
 *
 *--*/
_At_(CriticalSection->LockSemaphore, _Post_notnull_)
VOID
NTAPI
RtlpCreateCriticalSectionSem(PRTL_CRITICAL_SECTION CriticalSection)
{
    HANDLE hEvent = CriticalSection->LockSemaphore;
    HANDLE hNewEvent;
    NTSTATUS Status;

    /* Check if we have an event */
    if (!hEvent)
    {
        /* No, so create it */
        Status = NtCreateEvent(&hNewEvent,
                               EVENT_ALL_ACCESS,
                               NULL,
                               SynchronizationEvent,
                               FALSE);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to Create Event!\n");

            /*
             * Use INVALID_HANDLE_VALUE (-1) to signal that
             * the global keyed event must be used.
             */
            hNewEvent = INVALID_HANDLE_VALUE;
        }

        DPRINT("Created Event: %p\n", hNewEvent);

        /* Exchange the LockSemaphore field with the new handle, if it is still 0 */
        if (InterlockedCompareExchangePointer((PVOID*)&CriticalSection->LockSemaphore,
                                              (PVOID)hNewEvent,
                                               NULL) != NULL)
        {
            /* Someone else just created an event */
            if (hNewEvent != INVALID_HANDLE_VALUE)
            {
                DPRINT("Closing already created event: %p\n", hNewEvent);
                NtClose(hNewEvent);
            }
        }
    }

    return;
}

/*++
 * RtlpWaitForCriticalSection
 *
 *     Slow path of RtlEnterCriticalSection. Waits on an Event Object
 *     until a leaving thread wakes this one.
 *
 * Params:
 *     CriticalSection - Critical section to acquire.
 *
 * Returns:
 *     STATUS_SUCCESS, or raises an exception if a deadlock is occuring.
 *
 * Remarks:
 *     The caller is counted as a waiter in LockCount. Being woken does not
 *     give it the section: it tries to take it again (see
 *     RtlpEnterCriticalSectionContended).
 *
 *--*/
NTSTATUS
NTAPI
RtlpWaitForCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    NTSTATUS Status;
    EXCEPTION_RECORD ExceptionRecord;
    BOOLEAN LastChance = FALSE;

    /* Increase the Debug Entry count */
    DPRINT("Waiting on Critical Section Event: %p %p\n",
            CriticalSection,
            CriticalSection->LockSemaphore);

    if (CRITSECT_HAS_DEBUG_INFO(CriticalSection))
        CriticalSection->DebugInfo->EntryCount++;

    /* Do we have an Event yet? */
    if (!CriticalSection->LockSemaphore)
    {
        RtlpCreateCriticalSectionSem(CriticalSection);
    }

    for (;;)
    {
        /* Increase the number of times we've had contention */
        if (CRITSECT_HAS_DEBUG_INFO(CriticalSection))
            CriticalSection->DebugInfo->ContentionCount++;

        /* Check if allocating the event failed */
        if (CriticalSection->LockSemaphore == INVALID_HANDLE_VALUE)
        {
            /* Use the global keyed event (NULL as keyed event handle) */
            Status = NtWaitForKeyedEvent(NULL,
                                         CriticalSection,
                                         FALSE,
                                         (RtlpTimeoutDisable ? NULL : &RtlpTimeout));
        }
        else
        {
            /* Wait on the Event */
            Status = NtWaitForSingleObject(CriticalSection->LockSemaphore,
                                           FALSE,
                                           (RtlpTimeoutDisable ? NULL : &RtlpTimeout));
        }

        /* We have Timed out */
        if (Status == STATUS_TIMEOUT)
        {
            /* Is this the 2nd time we've timed out? */
            if (LastChance)
            {
                ERROR_DBGBREAK("Deadlock: 0x%p\n", CriticalSection);

                /* Yes it is, we are raising an exception */
                ExceptionRecord.ExceptionCode    = STATUS_POSSIBLE_DEADLOCK;
                ExceptionRecord.ExceptionFlags   = 0;
                ExceptionRecord.ExceptionRecord  = NULL;
                ExceptionRecord.ExceptionAddress = RtlRaiseException;
                ExceptionRecord.NumberParameters = 1;
                ExceptionRecord.ExceptionInformation[0] = (ULONG_PTR)CriticalSection;
                RtlRaiseException(&ExceptionRecord);
            }

            /* One more try */
            LastChance = TRUE;
        }
        else if (!NT_SUCCESS(Status))
        {
            /* The section is broken (e.g. an invalid event handle): waiting
               again would fail again, so raise the status as Windows does */
            DPRINT1("Waiting for critical section %p failed: 0x%08lx\n", CriticalSection, Status);
            RtlRaiseStatus(Status);
        }
        else
        {
            /* If we are here, everything went fine */
            return STATUS_SUCCESS;
        }
    }
}

/*++
 * RtlpUnWaitCriticalSection
 *
 *     Slow path of RtlLeaveCriticalSection. Fires an Event Object.
 *
 * Params:
 *     CriticalSection - Critical section to release.
 *
 * Returns:
 *     None. Raises an exception if the system call failed.
 *
 * Remarks:
 *     None
 *
 *--*/
VOID
NTAPI
RtlpUnWaitCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    NTSTATUS Status;

    /* Do we have an Event yet? */
    if (!CriticalSection->LockSemaphore)
    {
        RtlpCreateCriticalSectionSem(CriticalSection);
    }

    /* Signal the Event */
    DPRINT("Signaling Critical Section Event: %p, %p\n",
            CriticalSection,
            CriticalSection->LockSemaphore);

    /* Check if this critical section needs to use the keyed event */
    if (CriticalSection->LockSemaphore == INVALID_HANDLE_VALUE)
    {
        /* Release keyed event */
        Status = NtReleaseKeyedEvent(NULL, CriticalSection, FALSE, &RtlpTimeout);
    }
    else
    {
        /* Set the event */
        Status = NtSetEvent(CriticalSection->LockSemaphore, NULL);
    }

    if (!NT_SUCCESS(Status))
    {
        /* We've failed */
        DPRINT1("Signaling Failed for: %p, %p, 0x%08lx\n",
                CriticalSection,
                CriticalSection->LockSemaphore,
                Status);
        RtlRaiseStatus(Status);
    }
}

/*++
 * RtlpInitDeferredCriticalSection
 *
 *     Initializes the Critical Section implementation.
 *
 * Params:
 *     None
 *
 * Returns:
 *     None.
 *
 * Remarks:
 *     After this call, the Process Critical Section list is protected.
 *
 *--*/
VOID
NTAPI
RtlpInitDeferredCriticalSection(VOID)
{
    /* Initialize the CS Protecting the List */
    RtlInitializeCriticalSection(&RtlCriticalSectionLock);

    /* It's now safe to enter it */
    RtlpCritSectInitialized = TRUE;
}

/*++
 * RtlpAllocateDebugInfo
 *
 *     Finds or allocates memory for a Critical Section Debug Object
 *
 * Params:
 *     None
 *
 * Returns:
 *     A pointer to an empty Critical Section Debug Object.
 *
 * Remarks:
 *     For optimization purposes, the first 64 entries can be cached. From
 *     then on, future Critical Sections will allocate memory from the heap.
 *
 *--*/
PRTL_CRITICAL_SECTION_DEBUG
NTAPI
RtlpAllocateDebugInfo(VOID)
{
    ULONG i;

    /* Try to allocate from our buffer first */
    for (i = 0; i < MAX_STATIC_CS_DEBUG_OBJECTS; i++)
    {
        /* Claim the entry if it is free */
        if (!RtlpDebugInfoFreeList[i] &&
            !InterlockedCompareExchange(&RtlpDebugInfoFreeList[i], TRUE, FALSE))
        {
            DPRINT("Using entry: %lu. Buffer: %p\n", i, &RtlpStaticDebugInfo[i]);

            /* Use free entry found */
            return &RtlpStaticDebugInfo[i];
        }
    }

    /* We are out of static buffer, allocate dynamic */
    return RtlAllocateHeap(RtlGetProcessHeap(),
                           0,
                           sizeof(RTL_CRITICAL_SECTION_DEBUG));
}

/*++
 * RtlpFreeDebugInfo
 *
 *     Frees the memory for a Critical Section Debug Object
 *
 * Params:
 *     DebugInfo - Pointer to Critical Section Debug Object to free.
 *
 * Returns:
 *     None.
 *
 * Remarks:
 *     If the pointer is part of the static buffer, then the entry is made
 *     free again. If not, the object is de-allocated from the heap.
 *
 *--*/
VOID
NTAPI
RtlpFreeDebugInfo(PRTL_CRITICAL_SECTION_DEBUG DebugInfo)
{
    SIZE_T EntryId;

    /* Is it part of our cached entries? */
    if ((DebugInfo >= RtlpStaticDebugInfo) &&
        (DebugInfo <= &RtlpStaticDebugInfo[MAX_STATIC_CS_DEBUG_OBJECTS-1]))
    {
        /* Yes. zero it out */
        RtlZeroMemory(DebugInfo, sizeof(RTL_CRITICAL_SECTION_DEBUG));

        /* Mark as free */
        EntryId = (DebugInfo - RtlpStaticDebugInfo);
        DPRINT("Freeing from Buffer: %p. Entry: %Iu inside Process: %p\n",
               DebugInfo,
               EntryId,
               NtCurrentTeb()->ClientId.UniqueProcess);
        InterlockedExchange(&RtlpDebugInfoFreeList[EntryId], FALSE);

    }
    else if (!DebugInfo->Flags)
    {
        /* It's a dynamic one, so free from the heap */
        DPRINT("Freeing from Heap: %p inside Process: %p\n",
               DebugInfo,
               NtCurrentTeb()->ClientId.UniqueProcess);
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, DebugInfo);
    }
    else
    {
        /* HACK for Wine: stores a section name pointer in the Flags member */
        DPRINT("Assuming static: %p inside Process: %p\n",
               DebugInfo,
               NtCurrentTeb()->ClientId.UniqueProcess);
    }
}

/*++
 * RtlDeleteCriticalSection
 * @implemented NT4
 *
 *     Deletes a Critical Section
 *
 * Params:
 *     CriticalSection - Critical section to delete.
 *
 * Returns:
 *     STATUS_SUCCESS, or error value returned by NtClose.
 *
 * Remarks:
 *     The critical section members should not be read after this call.
 *
 *--*/
NTSTATUS
NTAPI
RtlDeleteCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("Deleting Critical Section: %p\n", CriticalSection);

    /* Close the Event Object Handle if it exists */
    if (CriticalSection->LockSemaphore)
    {
        /* In case NtClose fails, return the status */
        Status = NtClose(CriticalSection->LockSemaphore);
    }

    /* Protect List */
    RtlEnterCriticalSection(&RtlCriticalSectionLock);

    if (CRITSECT_HAS_DEBUG_INFO(CriticalSection))
    {
        /* Remove it from the list */
        RemoveEntryList(&CriticalSection->DebugInfo->ProcessLocksList);
#if 0
        /* HACK for Wine: We need to preserve Flags for RtlpFreeDebugInfo */
        RtlZeroMemory(CriticalSection->DebugInfo, sizeof(RTL_CRITICAL_SECTION_DEBUG));
#endif
    }

    /* Unprotect */
    RtlLeaveCriticalSection(&RtlCriticalSectionLock);

    if (CRITSECT_HAS_DEBUG_INFO(CriticalSection))
    {
        /* Free it */
        RtlpFreeDebugInfo(CriticalSection->DebugInfo);
    }

    /* Wipe it out */
    RtlZeroMemory(CriticalSection, sizeof(RTL_CRITICAL_SECTION));

    /* Return */
    return Status;
}

/*++
 * RtlSetCriticalSectionSpinCount
 * @implemented NT4
 *
 *     Sets the spin count for a critical section.
 *
 * Params:
 *     CriticalSection - Critical section to set the spin count for.
 *
 *     SpinCount - Spin count for the critical section.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     SpinCount is ignored on single-processor systems.
 *
 *--*/
ULONG
NTAPI
RtlSetCriticalSectionSpinCount(PRTL_CRITICAL_SECTION CriticalSection,
                               ULONG SpinCount)
{
    ULONG OldCount = (ULONG)CriticalSection->SpinCount;
    ULONG OsVersion = NtCurrentPeb()->OSMajorVersion << 8 |
                      NtCurrentPeb()->OSMinorVersion;

    if (OsVersion >= _WIN32_WINNT_WIN7)
    {
        /* Win7+: the flag bits stay, only the low 24 bits are the spin count */
        SpinCount &= ~RTL_CRITICAL_SECTION_ALL_FLAG_BITS;
        CriticalSection->SpinCount = ((NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0) |
                                     (OldCount & RTL_CRITICAL_SECTION_ALL_FLAG_BITS);
        return OldCount & ~RTL_CRITICAL_SECTION_ALL_FLAG_BITS;
    }

    /* Set to parameter if MP, or to 0 if this is Uniprocessor */
    CriticalSection->SpinCount = (NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0;
    return OldCount;
}

/*
 * Slow path of RtlEnterCriticalSection: another thread owns the section.
 * Returns once the calling thread owns it.
 */
static
VOID
RtlpEnterCriticalSectionContended(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection)
{
    ULONG_PTR Spin;
    LONG Old, New;
    BOOLEAN Woken = FALSE;

    /*
     * If we're shutting down the process, we're allowed to acquire any
     * critical sections by force (the loader lock in particular): its owner
     * is gone. The section stays owned, now by this thread, and is freed
     * when this thread leaves it.
     */
    if (LdrpShutdownInProgress &&
        LdrpShutdownThreadId == NtCurrentTeb()->RealClientId.UniqueThread)
    {
        DPRINT("Forcing ownership of critical section %p\n", CriticalSection);
        return;
    }

    /*
     * On a multiprocessor the owner is usually about to leave (short hold
     * times), so poll for the release for up to the section's spin count
     * before paying for a kernel wait and wake-up. The spin count is zero
     * on a uniprocessor.
     */
    Spin = CriticalSection->SpinCount & ~RTL_CRITICAL_SECTION_ALL_FLAG_BITS;
    while (Spin)
    {
        if ((*(volatile LONG *)&CriticalSection->LockCount & RTLP_CS_FREE) &&
            RtlpTryTakeCriticalSection(CriticalSection))
        {
            return;
        }
        YieldProcessor();
        Spin--;
    }

    for (;;)
    {
        /*
         * Take the section if it is free, else count this thread as a waiter.
         * A thread that was woken also sets the no-woken-waiter bit again, so
         * that the next leaving thread wakes another waiter.
         */
        Old = *(volatile LONG *)&CriticalSection->LockCount;
        if (Old & RTLP_CS_FREE)
            New = Old - RTLP_CS_FREE;
        else
            New = Old - RTLP_CS_WAITER;
        if (Woken)
            New += RTLP_CS_NOT_WOKEN;

        if (InterlockedCompareExchange(&CriticalSection->LockCount, New, Old) != Old)
            continue;

        if (Old & RTLP_CS_FREE)
            return;

        /* NOTE - CriticalSection->OwningThread can be NULL here because
                  changing this information is not serialized. This
                  happens when thread a acquires the lock and thread b
                  tries to acquire it as well but thread a hasn't had a
                  chance to set the OwningThread! So it's not an error
                  when OwningThread is NULL here! */

        /* Wait until a leaving thread wakes this one, then try again */
        RtlpWaitForCriticalSection(CriticalSection);
        Woken = TRUE;
    }
}

/*++
 * RtlEnterCriticalSection
 * @implemented NT4
 *
 *     Waits to gain ownership of the critical section.
 *
 * Params:
 *     CriticalSection - Critical section to wait for.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     Uses a fast-path unless contention happens.
 *
 *--*/
NTSTATUS
NTAPI
RtlEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    HANDLE Thread = (HANDLE)NtCurrentTeb()->ClientId.UniqueThread;

    /* Fast path: a free section is taken in one step */
    if (!RtlpTryTakeCriticalSection(CriticalSection))
    {
        /* Does this thread already own it? Only the owner ever stores its own id here. */
        if (Thread == CriticalSection->OwningThread)
        {
            /*
             * You own it, so you'll get it when you're done with it! No need
             * to use the interlocked functions for the recursion count as only
             * the thread who already owns the lock can modify this data.
             * LockCount does not count recursion.
             */
            CriticalSection->RecursionCount++;
            return STATUS_SUCCESS;
        }

        /* Somebody else owns it */
        RtlpEnterCriticalSectionContended(CriticalSection);
    }

    /*
     * Lock successful. Changing this information has not to be serialized
     * because only one thread at a time can actually change it (the one who
     * acquired the lock)!
     */
    CriticalSection->OwningThread = Thread;
    CriticalSection->RecursionCount = 1;
    NtCurrentTeb()->CountOfOwnedCriticalSections++;
    return STATUS_SUCCESS;
}

/*++
 * RtlInitializeCriticalSection
 * @implemented NT4
 *
 *     Initialises a new critical section.
 *
 * Params:
 *     CriticalSection - Critical section to initialise
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     Simply calls RtlInitializeCriticalSectionAndSpinCount
 *
 *--*/
NTSTATUS
NTAPI
RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    /* Call the Main Function */
    return RtlInitializeCriticalSectionAndSpinCount(CriticalSection, 0);
}

/*++
 * RtlInitializeCriticalSectionEx
 * @implemented NT6.0
 *
 *     Initialises a new critical section.
 *
 * Params:
 *     CriticalSection - Critical section to initialise
 *
 *     SpinCount - Spin count for the critical section.
 *
 *     Flags - Flags for initialization.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     SpinCount is ignored on single-processor systems.
 *
 *--*/
NTSTATUS
NTAPI
RtlInitializeCriticalSectionEx(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount,
    _In_ ULONG Flags)
{
    PRTL_CRITICAL_SECTION_DEBUG CritcalSectionDebugData;
    ULONG AllowedFlags;
    ULONG OsVersion;
    ULONG StoredFlags = 0;
    BOOLEAN IsWin7Plus, WantDebugInfo;

    /* Remove lower bits from flags */
    Flags &= RTL_CRITICAL_SECTION_ALL_FLAG_BITS;

    /* These flags generally allowed */
    AllowedFlags = RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO |
                   RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN |
                   RTL_CRITICAL_SECTION_FLAG_STATIC_INIT;

    /* Flags for Windows 7+ (CHECKME) */
    OsVersion = NtCurrentPeb()->OSMajorVersion << 8 |
                NtCurrentPeb()->OSMinorVersion;
    IsWin7Plus = (OsVersion >= _WIN32_WINNT_WIN7);
    if (IsWin7Plus)
    {
        AllowedFlags |= RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE |
                        RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO;
    }

    if (Flags & ~AllowedFlags)
    {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (SpinCount & RTL_CRITICAL_SECTION_ALL_FLAG_BITS)
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    /* First things first, set up the Object */
    DPRINT("Initializing Critical Section: %p\n", CriticalSection);
    CriticalSection->LockCount = -1;
    CriticalSection->RecursionCount = 0;
    CriticalSection->OwningThread = 0;
    CriticalSection->LockSemaphore = 0;

    /* Vista+: a zero spin count on an MP system selects the default dynamic spin count */
    if ((NtCurrentPeb()->NumberOfProcessors > 1) && (SpinCount == 0) &&
        (OsVersion >= _WIN32_WINNT_VISTA))
    {
        SpinCount = RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN | 2000;
    }

    /* Win7+: resource type, no-debug-info and dynamic-spin are kept in the spin count */
    if (IsWin7Plus)
    {
        StoredFlags = Flags & (RTL_CRITICAL_SECTION_FLAG_RESOURCE_TYPE |
                               RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO |
                               RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN);
    }
    CriticalSection->SpinCount = ((NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0) |
                                 StoredFlags;

    /*
     * Debug info is allocated unless suppressed, at every version. Real Win7+
     * defaults to none, but the Wine-derived code in this tree (msvcrt, wic,
     * strmbase...) dereferences cs.DebugInfo->Spare[0] after a plain
     * InitializeCriticalSection and would crash at load.
     */
    WantDebugInfo = !(Flags & RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO);

    if (!WantDebugInfo)
    {
        CriticalSection->DebugInfo = LongToPtr(-1);
    }
    else
    {
        /* Allocate the Debug Data */
        CritcalSectionDebugData = RtlpAllocateDebugInfo();
        DPRINT("Allocated Debug Data: %p inside Process: %p\n",
               CritcalSectionDebugData,
               NtCurrentTeb()->ClientId.UniqueProcess);

        if (!CritcalSectionDebugData)
        {
            /* This is bad! */
            DPRINT1("Couldn't allocate Debug Data for: %p\n", CriticalSection);
            return STATUS_NO_MEMORY;
        }

        /* Set it up (heap memory is not zeroed) */
        RtlZeroMemory(CritcalSectionDebugData, sizeof(*CritcalSectionDebugData));
        CritcalSectionDebugData->Type = RTL_CRITSECT_TYPE;
        CritcalSectionDebugData->ContentionCount = 0;
        CritcalSectionDebugData->EntryCount = 0;
        CritcalSectionDebugData->CriticalSection = CriticalSection;
        CritcalSectionDebugData->Flags = 0;
        CriticalSection->DebugInfo = CritcalSectionDebugData;

        /*
         * Add it to the List of Critical Sections owned by the process.
         * If we've initialized the Lock, then use it. If not, then probably
         * this is the lock initialization itself, so insert it directly.
         */
        if ((CriticalSection != &RtlCriticalSectionLock) && (RtlpCritSectInitialized))
        {
            DPRINT("Securely Inserting into ProcessLocks: %p, %p, %p\n",
                   &CritcalSectionDebugData->ProcessLocksList,
                   CriticalSection,
                   &RtlCriticalSectionList);

            /* Protect List */
            RtlEnterCriticalSection(&RtlCriticalSectionLock);

            /* Add this one */
            InsertTailList(&RtlCriticalSectionList, &CritcalSectionDebugData->ProcessLocksList);

            /* Unprotect */
            RtlLeaveCriticalSection(&RtlCriticalSectionLock);
        }
        else
        {
            DPRINT("Inserting into ProcessLocks: %p, %p, %p\n",
                   &CritcalSectionDebugData->ProcessLocksList,
                   CriticalSection,
                   &RtlCriticalSectionList);

            /* Add it directly */
            InsertTailList(&RtlCriticalSectionList, &CritcalSectionDebugData->ProcessLocksList);
        }
    }

    return STATUS_SUCCESS;
}

/*++
 * RtlInitializeCriticalSectionAndSpinCount
 * @implemented NT4
 *
 *     Initialises a new critical section.
 *
 * Params:
 *     CriticalSection - Critical section to initialise
 *
 *     SpinCount - Spin count for the critical section.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     SpinCount is ignored on single-processor systems.
 *
 *--*/
NTSTATUS
NTAPI
RtlInitializeCriticalSectionAndSpinCount(
    _Out_ PRTL_CRITICAL_SECTION CriticalSection,
    _In_ ULONG SpinCount)
{
    SpinCount &= ~RTL_CRITICAL_SECTION_ALL_FLAG_BITS;
    return RtlInitializeCriticalSectionEx(CriticalSection, SpinCount, 0);
}

/*++
 * RtlGetCriticalSectionRecursionCount
 * @implemented NT5.2 SP1
 *
 *     Retrieves the recursion count of a given critical section.
 *
 * Params:
 *     CriticalSection - Critical section to retrieve its recursion count.
 *
 * Returns:
 *     The recursion count.
 *
 * Remarks:
 *     We return the recursion count of the critical section if it is owned
 *     by the current thread, and otherwise we return zero.
 *
 *--*/
LONG
NTAPI
RtlGetCriticalSectionRecursionCount(PRTL_CRITICAL_SECTION CriticalSection)
{
    if (CriticalSection->OwningThread == NtCurrentTeb()->ClientId.UniqueThread)
    {
        /*
         * The critical section is owned by the current thread,
         * therefore retrieve its actual recursion count.
         */
        return CriticalSection->RecursionCount;
    }
    else
    {
        /*
         * It is not owned by the current thread, so
         * for this thread there is no recursion.
         */
        return 0;
    }
}

/*++
 * RtlLeaveCriticalSection
 * @implemented NT4
 *
 *     Releases a critical section and makes if available for new owners.
 *
 * Params:
 *     CriticalSection - Critical section to release.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     If another thread was waiting, the slow path is entered.
 *
 *--*/
NTSTATUS
NTAPI
RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
#if DBG
    HANDLE Thread = (HANDLE)NtCurrentTeb()->ClientId.UniqueThread;

    /*
     * In win this case isn't checked. However it's a valid check so it should
     * only be performed in debug builds!
     */
    if (Thread != CriticalSection->OwningThread)
    {
       DPRINT1("Releasing critical section not owned!\n");
       return STATUS_INVALID_PARAMETER;
    }
#endif

    /*
     * Decrease the Recursion Count. No need to do this atomically because only
     * the thread who holds the lock can call this function (unless the program
     * is totally screwed...
     */
    if (--CriticalSection->RecursionCount)
    {
        if (CriticalSection->RecursionCount < 0)
        {
            DPRINT1("CRITICAL SECTION MESS: Section %p is not acquired!\n", CriticalSection);
            return STATUS_UNSUCCESSFUL;
        }
        /* We still own it: LockCount does not count recursion */
    }
    else
    {
        LONG Old, New, Previous;
        BOOLEAN Wake;

        /*
         * Nobody owns us anymore. No need to do this atomically.
         * See comment above.
         */
        CriticalSection->OwningThread = 0;
        NtCurrentTeb()->CountOfOwnedCriticalSections--;

        /*
         * Free the section. If threads wait and none of them has been woken
         * yet, take one off the count of waiters and wake it: it competes for
         * the section when it runs. A woken thread that has not come back yet
         * is enough, it wakes no other.
         */
        Old = *(volatile LONG *)&CriticalSection->LockCount;
        for (;;)
        {
            Wake = (((ULONG)~Old >> 2) != 0) && (Old & RTLP_CS_NOT_WOKEN);
            New = Old + RTLP_CS_FREE;
            if (Wake)
                New += RTLP_CS_WAITER - RTLP_CS_NOT_WOKEN;

            Previous = InterlockedCompareExchange(&CriticalSection->LockCount, New, Old);
            if (Previous == Old)
                break;
            Old = Previous;
        }

        if (Wake)
        {
            RtlpUnWaitCriticalSection(CriticalSection);
        }
    }

    /* Sucessful! */
    return STATUS_SUCCESS;
}

/*++
 * RtlTryEnterCriticalSection
 * @implemented NT4
 *
 *     Attempts to gain ownership of the critical section without waiting.
 *
 * Params:
 *     CriticalSection - Critical section to attempt acquiring.
 *
 * Returns:
 *     TRUE if the critical section has been acquired, FALSE otherwise.
 *
 * Remarks:
 *     None
 *
 *--*/
LOGICAL
NTAPI
RtlTryEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    /* Try to take control */
    if (RtlpTryTakeCriticalSection(CriticalSection))
    {
        /* It's ours */
        CriticalSection->OwningThread = NtCurrentTeb()->ClientId.UniqueThread;
        CriticalSection->RecursionCount = 1;
        NtCurrentTeb()->CountOfOwnedCriticalSections++;
        return TRUE;
    }
    else if (CriticalSection->OwningThread == NtCurrentTeb()->ClientId.UniqueThread)
    {
        /* It's already ours; LockCount does not count recursion */
        CriticalSection->RecursionCount++;
        return TRUE;
    }

    /* It's not ours */
    return FALSE;
}

/**
 * @brief
 * RtlCheckForOrphanedCriticalSections
 *
 * Checks if the given thread owns any critical sections at the time
 * of its exit, and emits a debug message for each orphaned section found.
 *
 * @param[in] ThreadHandle
 * Handle to the thread to check.
 *
 * @return
 * Nothing
 *
 * @remarks
 * This function is typically called by the loader during thread exit.
 **/
VOID
NTAPI
RtlCheckForOrphanedCriticalSections(
    _In_ HANDLE ThreadHandle)
{
    THREAD_BASIC_INFORMATION ThreadInfo;
    NTSTATUS Status;
    PLIST_ENTRY ListEntry;

    /* Early exit if verifier is not active */
    if (!RtlpCriticalSectionVerifier)
        return;

    /* Get current thread ID first */
    if (ThreadHandle == NtCurrentThread())
    {
        /* Using current thread */
        ThreadInfo.ClientId.UniqueThread = NtCurrentTeb()->ClientId.UniqueThread;
    }
    else
    {
        /* Query thread info from the handle */
        Status = NtQueryInformationThread(
            ThreadHandle,
            ThreadBasicInformation,
            &ThreadInfo,
            sizeof(ThreadInfo),
            NULL);

        if (!NT_SUCCESS(Status))
            return;
    }

    /* Lock the critical section list */
    RtlEnterCriticalSection(&RtlCriticalSectionLock);

    /* Walk the global critical section list */
    ListEntry = RtlCriticalSectionList.Flink;
    while (ListEntry != &RtlCriticalSectionList)
    {
        PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
        PRTL_CRITICAL_SECTION CriticalSection;

        /* Get the debug info from the list entry */
        DebugInfo = CONTAINING_RECORD(
            ListEntry,
            RTL_CRITICAL_SECTION_DEBUG,
            ProcessLocksList);
        CriticalSection = DebugInfo->CriticalSection;

        /* Skip our own lock since we own it right now */
        if (CriticalSection == &RtlCriticalSectionLock)
        {
            ListEntry = ListEntry->Flink;
            continue;
        }

        /* Check if this critical section is owned by the target thread */
        if (CriticalSection &&
            CriticalSection->OwningThread == ThreadInfo.ClientId.UniqueThread)
        {
            /* Thread is exiting while owning a critical section! */
            VERIFIER_STOP(
                APPLICATION_VERIFIER_EXIT_THREAD_OWNS_LOCK,
                "Thread is exiting while owning a critical section",
                CriticalSection,
                "Critical section object",
                ThreadInfo.ClientId.UniqueThread,
                "Thread ID",
                DebugInfo,
                "Critical section debug info",
                NULL,
                NULL);
            /* TODO: Add stack trace information here (CORE-16870) */
        }

        ListEntry = ListEntry->Flink;
    }

    RtlLeaveCriticalSection(&RtlCriticalSectionLock);
}

LOGICAL
NTAPI
RtlIsCriticalSectionLocked(PRTL_CRITICAL_SECTION CriticalSection)
{
    return CriticalSection->RecursionCount != 0;
}

LOGICAL
NTAPI
RtlIsCriticalSectionLockedByThread(PRTL_CRITICAL_SECTION CriticalSection)
{
    return CriticalSection->OwningThread == NtCurrentTeb()->ClientId.UniqueThread &&
           CriticalSection->RecursionCount != 0;
}

VOID
NTAPI
RtlpNotOwnerCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    RtlRaiseStatus(STATUS_RESOURCE_NOT_OWNED);
}

/* EOF */
