/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS sysem libraries
 * PURPOSE:           Vectored Exception Handling
 * FILE:              lib/rtl/vectoreh.c
 * PROGRAMERS:        Thomas Weidenmueller
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>

/*
 * Every exception of every thread walks these lists, while handlers are added
 * and removed rarely. So the walk takes no lock and writes nothing that other
 * threads write too: threads that take exceptions at the same time do not
 * slow each other down.
 *
 * Adding and removing take RtlpVectoredHandlerLock exclusively. They change
 * the lists so that a walk in progress always follows valid Flink pointers:
 * an entry is complete before it is linked, and an unlinked entry keeps its
 * Flink. An unlinked entry is freed only once no walk can still be on it:
 * a walk counts itself in one of the counters of the current epoch until it
 * ends, handler calls included; removed entries wait on the pending list until
 * the epoch is switched, and then until no walk counted in the previous epoch
 * is left. So an entry is not freed while a walk is inside its handler, and a
 * second remove of it fails meanwhile, as before.
 *
 * A thread that leaves a handler without returning (it exits or unwinds past
 * the dispatcher) leaves its walk counted: entries removed after that are not
 * freed any more. That costs memory only; the old reference count lost the
 * entries such a walk held in the same way.
 *
 * Memory ordering: the code relies on the x86/x64 memory model (loads are not
 * reordered with other loads, stores not with other stores or with earlier
 * loads; only a store may pass a later load, and the interlocked operations,
 * which are full barriers, cover that). The walk reads the epoch and counts
 * itself in its counter before it reads Flink, and reads Removed before it
 * calls the handler; the remover writes Removed and the Flink pointers, and
 * only later reads the counters. A port to a weakly ordered CPU (ARM) needs
 * acquire loads for the Flink, Removed and epoch reads, release stores for
 * the Flink and Removed writes, and a full barrier between a walk counting
 * itself in and its first read of the list, and between the epoch switch and
 * the read of the counters in RtlpVehEpochDrained. The volatile qualifiers
 * here only keep the compiler from reordering or caching, they are not enough.
 */
RTL_SRWLOCK RtlpVectoredHandlerLock;
LIST_ENTRY RtlpVectoredExceptionList, RtlpVectoredContinueList;

typedef struct _RTL_VECTORED_HANDLER_ENTRY
{
    LIST_ENTRY ListEntry;
    PVECTORED_EXCEPTION_HANDLER VectoredHandler;
    volatile LONG Removed;                          /* Unlinked: no longer called */
    struct _RTL_VECTORED_HANDLER_ENTRY *NextFree;   /* Link on the pending and draining lists */
} RTL_VECTORED_HANDLER_ENTRY, *PRTL_VECTORED_HANDLER_ENTRY;

/* Walk counters, each on its own cache line; a thread uses the one of its thread id */
#define RTLP_VEH_WALK_SLOTS 16

typedef struct DECLSPEC_ALIGN(64) _RTLP_VEH_WALK_SLOT
{
    volatile LONG Walks;
    UCHAR Padding[64 - sizeof(LONG)];
} RTLP_VEH_WALK_SLOT;

static RTLP_VEH_WALK_SLOT RtlpVehWalkSlots[2][RTLP_VEH_WALK_SLOTS];
static volatile LONG RtlpVehEpoch;

/* Under the lock: entries removed since the last epoch switch, and those
   that wait for the walks of the epoch before it to end */
static PRTL_VECTORED_HANDLER_ENTRY RtlpVehPending, RtlpVehDraining;
static volatile LONG RtlpVehFreePending;

/* FUNCTIONS ***************************************************************/

VOID
NTAPI
RtlpInitializeVectoredExceptionHandling(VOID)
{
    /* Initialize our two lists and the common lock */
    RtlInitializeSRWLock(&RtlpVectoredHandlerLock);
    InitializeListHead(&RtlpVectoredExceptionList);
    InitializeListHead(&RtlpVectoredContinueList);
}

/* Counts a walk in the current epoch. Returns the counter to decrement when the walk ends. */
static
volatile LONG *
RtlpVehEnterWalk(VOID)
{
    ULONG Slot = (ULONG)(((ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread / 4) % RTLP_VEH_WALK_SLOTS);
    volatile LONG *Walks;
    LONG Epoch;

    for (;;)
    {
        Epoch = RtlpVehEpoch;
        Walks = &RtlpVehWalkSlots[Epoch][Slot].Walks;
        InterlockedIncrement(Walks);

        /* Counted before the epoch changed: the switch sees this walk.
           Otherwise count it in the new epoch. */
        if (RtlpVehEpoch == Epoch)
            return Walks;
        InterlockedDecrement(Walks);
    }
}

static
BOOLEAN
RtlpVehEpochDrained(
    _In_ LONG Epoch)
{
    ULONG i;

    for (i = 0; i < RTLP_VEH_WALK_SLOTS; i++)
    {
        if (RtlpVehWalkSlots[Epoch][i].Walks != 0)
            return FALSE;
    }
    return TRUE;
}

/* Called with the lock held exclusively. Returns the entries that no walk
   can be on any more, to be freed after the lock is released. */
static
PRTL_VECTORED_HANDLER_ENTRY
RtlpVehCollectFreeable(VOID)
{
    PRTL_VECTORED_HANDLER_ENTRY Free = NULL;
    LONG Epoch = RtlpVehEpoch;

    /* The draining entries were unlinked before the switch to the current
       epoch: only walks counted in the previous one can be on them */
    if (RtlpVehDraining && RtlpVehEpochDrained(Epoch ^ 1))
    {
        Free = RtlpVehDraining;
        RtlpVehDraining = NULL;
    }

    /* Then switch the epoch for the pending ones: walks that start from now
       on no longer find them */
    if (!RtlpVehDraining && RtlpVehPending)
    {
        RtlpVehDraining = RtlpVehPending;
        RtlpVehPending = NULL;
        InterlockedExchange(&RtlpVehEpoch, Epoch ^ 1);

        if (RtlpVehEpochDrained(Epoch))
        {
            PRTL_VECTORED_HANDLER_ENTRY Last = RtlpVehDraining;

            while (Last->NextFree)
                Last = Last->NextFree;
            Last->NextFree = Free;
            Free = RtlpVehDraining;
            RtlpVehDraining = NULL;
        }
    }

    RtlpVehFreePending = (RtlpVehPending != NULL) || (RtlpVehDraining != NULL);
    return Free;
}

static
VOID
RtlpVehFreeEntries(
    _In_opt_ PRTL_VECTORED_HANDLER_ENTRY Free)
{
    PRTL_VECTORED_HANDLER_ENTRY Next;

    while (Free)
    {
        Next = Free->NextFree;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Free);
        Free = Next;
    }
}

BOOLEAN
NTAPI
RtlpCallVectoredHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
                         IN PCONTEXT Context,
                         IN PLIST_ENTRY VectoredHandlerList)
{
    PLIST_ENTRY CurrentEntry;
    PRTL_VECTORED_HANDLER_ENTRY VectoredExceptionHandler;
    PVECTORED_EXCEPTION_HANDLER VectoredHandler;
    EXCEPTION_POINTERS ExceptionInfo;
    PRTL_VECTORED_HANDLER_ENTRY Free;
    volatile LONG *Walks;
    LONG HandlerReturn;

    /* Most processes have no handler on a list (no vectored continue handler
       at all). A handler that another thread adds at this moment is not
       ordered with this exception anyway. */
    if (IsListEmpty(VectoredHandlerList))
        return FALSE;

    /* Initialize this in case no one handles the exception */
    HandlerReturn = EXCEPTION_CONTINUE_SEARCH;

    /* Set up the data to pass to the handler */
    ExceptionInfo.ExceptionRecord = ExceptionRecord;
    ExceptionInfo.ContextRecord = Context;

    /* The entries this walk may come across stay allocated until it ends */
    Walks = RtlpVehEnterWalk();

    /* Loop entries */
    CurrentEntry = *(PLIST_ENTRY volatile *)&VectoredHandlerList->Flink;
    while (CurrentEntry != VectoredHandlerList)
    {
        /* Get the struct */
        VectoredExceptionHandler = CONTAINING_RECORD(CurrentEntry,
                                                     RTL_VECTORED_HANDLER_ENTRY,
                                                     ListEntry);

        /* A handler that was removed is not called any more */
        if (!VectoredExceptionHandler->Removed)
        {
            /*
             * Get the function pointer, decoding it so we will crash
             * if malicious code has altered it. That is, if something has
             * set VectoredHandler to a non-encoded pointer
             */
            VectoredHandler = RtlDecodePointer(VectoredExceptionHandler->VectoredHandler);

            /* Call the handler */
            HandlerReturn = VectoredHandler(&ExceptionInfo);

            /* Should we continue execution? */
            if (HandlerReturn == EXCEPTION_CONTINUE_EXECUTION)
            {
                /* Break out */
                break;
            }
        }

        /* Next entry. An entry that was unlinked meanwhile still leads on
           to the rest of the list. */
        CurrentEntry = *(PLIST_ENTRY volatile *)&CurrentEntry->Flink;
    }

    /* The walk is over */
    InterlockedDecrement(Walks);

    /* Free what was removed and is no longer used, if nobody is changing the
       lists right now (that one does it then) */
    if (RtlpVehFreePending && RtlTryAcquireSRWLockExclusive(&RtlpVectoredHandlerLock))
    {
        Free = RtlpVehCollectFreeable();
        RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);
        RtlpVehFreeEntries(Free);
    }

    /* Return whether to continue execution (ignored for continue handlers) */
    return (HandlerReturn == EXCEPTION_CONTINUE_EXECUTION) ? TRUE : FALSE;
}

PVOID
NTAPI
RtlpAddVectoredHandler(IN ULONG FirstHandler,
                       IN PVECTORED_EXCEPTION_HANDLER VectoredHandler,
                       IN PLIST_ENTRY VectoredHandlerList)
{
    PRTL_VECTORED_HANDLER_ENTRY VectoredHandlerEntry;
    PRTL_VECTORED_HANDLER_ENTRY Free;
    PLIST_ENTRY Previous, Next;

    /* Allocate our structure */
    VectoredHandlerEntry = RtlAllocateHeap(RtlGetProcessHeap(),
                                           0,
                                           sizeof(RTL_VECTORED_HANDLER_ENTRY));
    if (!VectoredHandlerEntry) return NULL;

    /* Set it up, encoding the pointer for security */
    VectoredHandlerEntry->VectoredHandler = RtlEncodePointer(VectoredHandler);
    VectoredHandlerEntry->Removed = FALSE;
    VectoredHandlerEntry->NextFree = NULL;

    /* Lock the list before modifying it */
    RtlAcquireSRWLockExclusive(&RtlpVectoredHandlerLock);

    /*
     * While holding the list lock, insert the handler
     * at beginning or end of list according to caller.
     * The entry is complete before a walk can reach it.
     */
    if (FirstHandler)
    {
        Previous = VectoredHandlerList;
        Next = VectoredHandlerList->Flink;
    }
    else
    {
        Previous = VectoredHandlerList->Blink;
        Next = VectoredHandlerList;
    }
    VectoredHandlerEntry->ListEntry.Flink = Next;
    VectoredHandlerEntry->ListEntry.Blink = Previous;
    Next->Blink = &VectoredHandlerEntry->ListEntry;
    InterlockedExchangePointer((PVOID *)&Previous->Flink, &VectoredHandlerEntry->ListEntry);

    /* Done with the list, free what was removed before if it is unused now */
    Free = RtlpVehCollectFreeable();
    RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);
    RtlpVehFreeEntries(Free);

    /* Return pointer to the structure as the handle */
    return VectoredHandlerEntry;
}

ULONG
NTAPI
RtlpRemoveVectoredHandler(IN PVOID VectoredHandlerHandle,
                          IN PLIST_ENTRY VectoredHandlerList)
{
    PLIST_ENTRY CurrentEntry;
    PRTL_VECTORED_HANDLER_ENTRY VectoredExceptionHandler;
    PRTL_VECTORED_HANDLER_ENTRY Free;
    BOOLEAN HandlerFound;

    /* Initialize this in case we don't find anything */
    HandlerFound = FALSE;

    /* Acquire list lock */
    RtlAcquireSRWLockExclusive(&RtlpVectoredHandlerLock);

    /* Loop the list */
    CurrentEntry = VectoredHandlerList->Flink;
    while (CurrentEntry != VectoredHandlerList)
    {
        /* Get the struct */
        VectoredExceptionHandler = CONTAINING_RECORD(CurrentEntry,
                                                     RTL_VECTORED_HANDLER_ENTRY,
                                                     ListEntry);

        /* Does it match? */
        if (VectoredExceptionHandler == VectoredHandlerHandle)
        {
            /*
             * Unlink it, keeping its Flink for a walk that is on it, and
             * free it once no walk can be on it any more. A walk that is
             * calling it right now finishes that call.
             */
            VectoredExceptionHandler->Removed = TRUE;
            CurrentEntry->Blink->Flink = CurrentEntry->Flink;
            CurrentEntry->Flink->Blink = CurrentEntry->Blink;
            VectoredExceptionHandler->NextFree = RtlpVehPending;
            RtlpVehPending = VectoredExceptionHandler;

            /* Found what we are looking for, stop searching */
            HandlerFound = TRUE;
            break;
        }

        /* Get the next entry */
        CurrentEntry = CurrentEntry->Flink;
    }

    /* Done with the list, let go of the lock and free what is unused */
    Free = RtlpVehCollectFreeable();
    RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);
    RtlpVehFreeEntries(Free);

    /* Return whether we found it */
    return (ULONG)HandlerFound;
}

BOOLEAN
NTAPI
RtlCallVectoredExceptionHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
                                 IN PCONTEXT Context)
{
    /* Call the shared routine */
    return RtlpCallVectoredHandlers(ExceptionRecord,
                                    Context,
                                    &RtlpVectoredExceptionList);
}

VOID
NTAPI
RtlCallVectoredContinueHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
                                IN PCONTEXT Context)
{
    /*
     * Call the shared routine (ignoring result,
     * execution always continues at this point)
     */
    (VOID)RtlpCallVectoredHandlers(ExceptionRecord,
                                   Context,
                                   &RtlpVectoredContinueList);
}

DECLSPEC_HOTPATCH
PVOID
NTAPI
RtlAddVectoredExceptionHandler(IN ULONG FirstHandler,
                               IN PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    /* Call the shared routine */
    return RtlpAddVectoredHandler(FirstHandler,
                                  VectoredHandler,
                                  &RtlpVectoredExceptionList);
}

DECLSPEC_HOTPATCH
PVOID
NTAPI
RtlAddVectoredContinueHandler(IN ULONG FirstHandler,
                              IN PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
    /* Call the shared routine */
    return RtlpAddVectoredHandler(FirstHandler,
                                  VectoredHandler,
                                  &RtlpVectoredContinueList);
}

//DECLSPEC_HOTPATCH
ULONG
NTAPI
RtlRemoveVectoredExceptionHandler(IN PVOID VectoredHandlerHandle)
{
    /* Call the shared routine */
    return RtlpRemoveVectoredHandler(VectoredHandlerHandle,
                                     &RtlpVectoredExceptionList);
}

//DECLSPEC_HOTPATCH
ULONG
NTAPI
RtlRemoveVectoredContinueHandler(IN PVOID VectoredHandlerHandle)
{
    /* Call the shared routine */
    return RtlpRemoveVectoredHandler(VectoredHandlerHandle,
                                     &RtlpVectoredContinueList);
}

/* EOF */
