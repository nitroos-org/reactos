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

/* Shared while the dispatcher walks a list, exclusive to change one: threads that take exceptions at the same time
   do not wait for each other */
RTL_SRWLOCK RtlpVectoredHandlerLock;
LIST_ENTRY RtlpVectoredExceptionList, RtlpVectoredContinueList;

typedef struct _RTL_VECTORED_HANDLER_ENTRY
{
    LIST_ENTRY ListEntry;
    PVECTORED_EXCEPTION_HANDLER VectoredHandler;
    LONG Refs;      /* The registration plus the walks that call it; the one that drops the last unlinks it */
    BOOLEAN Removed;/* Set under the exclusive lock by the one remove that counts; a removed entry is not called */
} RTL_VECTORED_HANDLER_ENTRY, *PRTL_VECTORED_HANDLER_ENTRY;

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

/* Takes a reference on an entry that is still registered. Call it with the lock held (shared or exclusive): Removed
   only changes under the exclusive lock, so an entry that was removed before the walk took the lock is never called,
   not even while a walk that started earlier is still inside its handler (then the entry only waits for that walk to
   drop the last reference and unlink it). */
static
BOOLEAN
RtlpReferenceVectoredHandler(
    _Inout_ PRTL_VECTORED_HANDLER_ENTRY Entry)
{
    if (Entry->Removed)
        return FALSE;

    /* The registration reference is still there, so the count cannot reach 0 under us */
    InterlockedIncrement(&Entry->Refs);
    return TRUE;
}

static
VOID
RtlpAcquireVectoredHandlerLock(
    _In_ BOOLEAN Exclusive)
{
    if (Exclusive)
        RtlAcquireSRWLockExclusive(&RtlpVectoredHandlerLock);
    else
        RtlAcquireSRWLockShared(&RtlpVectoredHandlerLock);
}

static
VOID
RtlpReleaseVectoredHandlerLock(
    _In_ BOOLEAN Exclusive)
{
    if (Exclusive)
        RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);
    else
        RtlReleaseSRWLockShared(&RtlpVectoredHandlerLock);
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
    LIST_ENTRY RemovedList;
    BOOLEAN Exclusive;
    LONG HandlerReturn;

    /* Most processes have no handler on a list (no vectored continue handler
       at all): do not take the lock that every exception of every thread
       would otherwise go through, as Windows does not. A handler that another
       thread adds at this moment is not ordered with this exception anyway. */
    if (IsListEmpty(VectoredHandlerList))
        return FALSE;

    /* Initialize this in case no one handles the exception */
    HandlerReturn = EXCEPTION_CONTINUE_SEARCH;
    InitializeListHead(&RemovedList);

    /* Set up the data to pass to the handler */
    ExceptionInfo.ExceptionRecord = ExceptionRecord;
    ExceptionInfo.ContextRecord = Context;

    /* Walk the list with the lock shared, it only changes when a handler is
       added or removed */
    Exclusive = FALSE;
    RtlpAcquireVectoredHandlerLock(Exclusive);

    /* Loop entries */
    CurrentEntry = VectoredHandlerList->Flink;
    while (CurrentEntry != VectoredHandlerList)
    {
        /* Get the struct */
        VectoredExceptionHandler = CONTAINING_RECORD(CurrentEntry,
                                                     RTL_VECTORED_HANDLER_ENTRY,
                                                     ListEntry);

        /* Reference it so it doesn't go away while we are using it. One that
           was removed is not called, also when it is still on the list
           because another walk is inside it. */
        if (!RtlpReferenceVectoredHandler(VectoredExceptionHandler))
        {
            CurrentEntry = CurrentEntry->Flink;
            continue;
        }

        /* Drop the lock before calling the handler */
        RtlpReleaseVectoredHandlerLock(Exclusive);

        /*
         * Get the function pointer, decoding it so we will crash
         * if malicious code has altered it. That is, if something has
         * set VectoredHandler to a non-encoded pointer
         */
        VectoredHandler = RtlDecodePointer(VectoredExceptionHandler->VectoredHandler);

        /* Call the handler */
        HandlerReturn = VectoredHandler(&ExceptionInfo);

        /* Handler called -- grab the lock to dereference. The entry stays
           linked while we hold a reference, so its link is still valid. */
        RtlpAcquireVectoredHandlerLock(Exclusive);

        /* Dereference and see if it got deleted */
        if (InterlockedDecrement(&VectoredExceptionHandler->Refs) == 0)
        {
            /* It did: unlink it with the lock exclusive, and walk the rest of
               the list that way, so the next link stays valid. It is freed
               after the walk, outside of the lock. */
            if (!Exclusive)
            {
                RtlpReleaseVectoredHandlerLock(Exclusive);
                Exclusive = TRUE;
                RtlpAcquireVectoredHandlerLock(Exclusive);
            }
            CurrentEntry = VectoredExceptionHandler->ListEntry.Flink;
            RemoveEntryList(&VectoredExceptionHandler->ListEntry);
            InsertTailList(&RemovedList, &VectoredExceptionHandler->ListEntry);
        }
        else
        {
            /* Continue searching the list */
            CurrentEntry = CurrentEntry->Flink;
        }

        /* Should we continue execution? */
        if (HandlerReturn == EXCEPTION_CONTINUE_EXECUTION)
        {
            /* Break out */
            break;
        }
    }

    /* Let go of the lock now */
    RtlpReleaseVectoredHandlerLock(Exclusive);

    /* Free what was removed */
    while (!IsListEmpty(&RemovedList))
    {
        CurrentEntry = RemoveHeadList(&RemovedList);
        RtlFreeHeap(RtlGetProcessHeap(),
                    0,
                    CONTAINING_RECORD(CurrentEntry, RTL_VECTORED_HANDLER_ENTRY, ListEntry));
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

    /* Allocate our structure */
    VectoredHandlerEntry = RtlAllocateHeap(RtlGetProcessHeap(),
                                           0,
                                           sizeof(RTL_VECTORED_HANDLER_ENTRY));
    if (!VectoredHandlerEntry) return NULL;

    /* Set it up, encoding the pointer for security */
    VectoredHandlerEntry->VectoredHandler = RtlEncodePointer(VectoredHandler);
    VectoredHandlerEntry->Refs = 1;
    VectoredHandlerEntry->Removed = FALSE;

    /* Lock the list before modifying it */
    RtlAcquireSRWLockExclusive(&RtlpVectoredHandlerLock);

    /*
     * While holding the list lock, insert the handler
     * at beginning or end of list according to caller.
     */
    if (FirstHandler)
    {
        InsertHeadList(VectoredHandlerList,
                       &VectoredHandlerEntry->ListEntry);
    }
    else
    {
        InsertTailList(VectoredHandlerList,
                       &VectoredHandlerEntry->ListEntry);
    }

    /* Done with the list, unlock it */
    RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);

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
    BOOLEAN HandlerRemoved;
    BOOLEAN HandlerFound;

    /* Initialize these in case we don't find anything */
    HandlerRemoved = FALSE;
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
             * Great, this means it is a valid entry.
             * However, it may be in use by the exception
             * dispatcher, so we have a ref count to respect.
             * If we can't remove it now then it will be done
             * right after it is not in use anymore.
             *
             * An entry that was removed already but is still on the list
             * (a walk is inside its handler) is not found: the registration
             * is gone, and the reference of that walk is not ours to drop.
             */
            if (VectoredExceptionHandler->Removed)
                break;

            /* From now on no walk starts the handler: the lock is exclusive */
            VectoredExceptionHandler->Removed = TRUE;

            if (InterlockedDecrement(&VectoredExceptionHandler->Refs) == 0)
            {
                /* Not in use, ok to remove and free */
                RemoveEntryList(&VectoredExceptionHandler->ListEntry);
                HandlerRemoved = TRUE;
            }

            /* Found what we are looking for, stop searching */
            HandlerFound = TRUE;
            break;
        }
        else
        {
            /* Get the next entry */
            CurrentEntry = CurrentEntry->Flink;
        }
    }

    /* Done with the list, let go of the lock */
    RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);

    /* Can we free what we found? */
    if (HandlerRemoved)
    {
        /* Do it */
        RtlFreeHeap(RtlGetProcessHeap(),
                    0,
                    VectoredExceptionHandler);
    }

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
