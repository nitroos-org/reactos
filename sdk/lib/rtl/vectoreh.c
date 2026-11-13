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
 * A walk that never ends would keep its epoch from draining, and so keep every
 * entry removed after it. A walk ends without returning when its handler does
 * not return: the thread exits (ExitThread, TerminateThread) or jumps or
 * unwinds past the dispatcher (longjmp, a C++ throw). So a thread counts its
 * walks in a slot of its own (TEB->ReservedForPerf holds the slot number + 1),
 * and its walks are dropped once they cannot go on:
 * - LdrShutdownThread drops the walks of the exiting thread (it may run in a
 *   handler: that walk does not come back) and frees its slot;
 * - when the thread walks again, it drops its earlier walks if the frame of
 *   the outermost of them is gone from the stack: the new walk starts at or
 *   above that frame, or a marker in that frame was overwritten. A frame that
 *   is still in use lies below everything its thread runs until it returns,
 *   and the walk never writes its marker again. When the outermost walk on a
 *   stack returns, the walks it contained have all returned or were left;
 * - when removed entries pile up behind an epoch that does not drain, an add
 *   or remove looks for slots of threads that no longer run (terminated
 *   without LdrShutdownThread; in a cloned process, the threads of the parent)
 *   and drops their walks: the owner's TEB is gone, or is another thread's
 *   (it does not hold the slot number).
 * What is left: a thread that left a walk and does not dispatch an exception
 * again keeps the entries removed meanwhile until it does or until it ends.
 * A thread whose walks are not all on the stack its TEB describes (fibers
 * switched inside a handler, code that runs on stacks of its own) keeps them
 * until they all return or the thread ends. A code that saves a frame of a
 * walk, runs other code at that place of the stack and puts the frame back
 * (stack copying coroutines) would break the frame rule. Threads beyond the
 * slots share hashed counters, whose walks are never dropped.
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
 * Slots are claimed and freed under the lock, so RtlpVehEpochDrained (under
 * the lock) sees every slot a walk can count itself in.
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

/* Walk counters of the threads without a slot, each on its own cache line;
   such a thread uses the one of its thread id */
#define RTLP_VEH_WALK_SLOTS 16

typedef struct DECLSPEC_ALIGN(64) _RTLP_VEH_WALK_SLOT
{
    volatile LONG Walks;
    UCHAR Padding[64 - sizeof(LONG)];
} RTLP_VEH_WALK_SLOT;

static RTLP_VEH_WALK_SLOT RtlpVehWalkSlots[2][RTLP_VEH_WALK_SLOTS];

/* Slots of the threads that walk, each on its own cache line. Only the owner
   writes its slot while it runs; claiming and freeing one takes the lock. */
#define RTLP_VEH_THREAD_SLOTS 64

typedef struct DECLSPEC_ALIGN(64) _RTLP_VEH_THREAD_SLOT
{
    volatile LONG Walks[2];     /* Walks of the owner not known to be over, per epoch */
    HANDLE Owner;               /* Thread id, NULL: free */
    PTEB Teb;                   /* Of the owner: freed when it ends */
    PVOID OuterFrame;           /* Marker of the outermost walk, NULL: no walk, or not known */
    PVOID OuterStack;           /* StackBase of the stack of that walk */
    ULONG_PTR OuterMarker;      /* Value of the marker */
    ULONG_PTR Sequence;         /* Makes the marker values differ */
} RTLP_VEH_THREAD_SLOT, *PRTLP_VEH_THREAD_SLOT;

static RTLP_VEH_THREAD_SLOT RtlpVehThreadSlots[RTLP_VEH_THREAD_SLOTS];
static LONG RtlpVehThreadSlotsUsed;     /* Under the lock: no slot at or above this was claimed */
static LONG RtlpVehThreadSlotsTaken;    /* Under the lock */

static volatile LONG RtlpVehEpoch;

/* Under the lock: entries removed since the last epoch switch, and those
   that wait for the walks of the epoch before it to end */
static PRTL_VECTORED_HANDLER_ENTRY RtlpVehPending, RtlpVehDraining;
static volatile LONG RtlpVehFreePending;

/* Under the lock: entries on both lists, and how many make an add or remove
   look for walks of threads that are gone */
#define RTLP_VEH_REAP_FIRST 64
static ULONG RtlpVehWaiting;
static ULONG RtlpVehReapAt = RTLP_VEH_REAP_FIRST;

/* The thread that holds the lock: an exception it takes meanwhile must not wait for the lock */
static HANDLE volatile RtlpVehLockOwner;

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

static
VOID
RtlpVehLock(VOID)
{
    RtlAcquireSRWLockExclusive(&RtlpVectoredHandlerLock);
    RtlpVehLockOwner = NtCurrentTeb()->ClientId.UniqueThread;
}

static
BOOLEAN
RtlpVehTryLock(VOID)
{
    if (!RtlTryAcquireSRWLockExclusive(&RtlpVectoredHandlerLock))
        return FALSE;
    RtlpVehLockOwner = NtCurrentTeb()->ClientId.UniqueThread;
    return TRUE;
}

static
VOID
RtlpVehUnlock(VOID)
{
    RtlpVehLockOwner = NULL;
    RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);
}

/* The slot of the current thread; claims one at its first walk. NULL: none
   (all taken, or this thread holds the lock: a later walk tries again). */
static
PRTLP_VEH_THREAD_SLOT
RtlpVehThreadSlot(
    _In_ PTEB Teb)
{
    HANDLE Self = Teb->ClientId.UniqueThread;
    ULONG_PTR Index = (ULONG_PTR)Teb->ReservedForPerf - 1;
    PRTLP_VEH_THREAD_SLOT Slot = NULL;
    ULONG i;

    /* A slot number that is not ours: one inherited from a thread of the
       parent of a cloned process, or none */
    if (Index < RTLP_VEH_THREAD_SLOTS && RtlpVehThreadSlots[Index].Owner == Self)
        return &RtlpVehThreadSlots[Index];

    if (RtlpVehThreadSlotsTaken >= RTLP_VEH_THREAD_SLOTS || RtlpVehLockOwner == Self)
        return NULL;

    /* Wait for the lock: a walk that counted in the shared counters would
       not be dropped. The holders only change the lists and slots, they wait
       for nothing else. */
    RtlpVehLock();

    for (i = 0; i < RTLP_VEH_THREAD_SLOTS; i++)
    {
        if (RtlpVehThreadSlots[i].Owner)
            continue;

        Slot = &RtlpVehThreadSlots[i];
        Slot->Teb = Teb;
        Slot->OuterFrame = NULL;
        Slot->Owner = Self;
        RtlpVehThreadSlotsTaken++;
        if ((LONG)i >= RtlpVehThreadSlotsUsed)
            RtlpVehThreadSlotsUsed = i + 1;
        Teb->ReservedForPerf = (PVOID)(ULONG_PTR)(i + 1);
        break;
    }

    RtlpVehUnlock();
    return Slot;
}

/* A walk of the slot's owner starts; Marker is a variable in the frame of the walk */
static
VOID
RtlpVehTrackWalk(
    _In_ PTEB Teb,
    _Inout_ PRTLP_VEH_THREAD_SLOT Slot,
    _Out_ volatile ULONG_PTR *Marker)
{
    PVOID Frame = (PVOID)Marker;
    PVOID StackBase = Teb->NtTib.StackBase;
    PVOID StackBottom = Teb->DeallocationStack ? Teb->DeallocationStack : Teb->NtTib.StackLimit;
    BOOLEAN OnStack = (Frame < StackBase) && (Frame >= StackBottom);

    if (Slot->Walks[0] || Slot->Walks[1])
    {
        /* Walks of this thread that did not return: nested ones, or left */
        if (!Slot->OuterFrame)
            return;

        if (!OnStack || Slot->OuterStack != StackBase)
        {
            /* Another stack: the place of the frames tells nothing any more */
            Slot->OuterFrame = NULL;
            return;
        }

        /* Nested in the outermost walk: its frame is above this one and
           intact (the outer frame lies between this one and the stack base,
           so it can be read) */
        if (Frame < Slot->OuterFrame &&
            *(volatile ULONG_PTR *)Slot->OuterFrame == Slot->OuterMarker)
        {
            return;
        }

        /* The frame of the outermost walk is gone, and with it the frames of
           the walks inside it: none of them comes back */
        Slot->Walks[0] = 0;
        Slot->Walks[1] = 0;
    }

    /* The outermost walk of the thread now */
    if (OnStack)
    {
        Slot->Sequence++;
        Slot->OuterMarker = (Slot->Sequence << 8) ^ (ULONG_PTR)Frame ^ (ULONG_PTR)Slot;
        *Marker = Slot->OuterMarker;
        Slot->OuterStack = StackBase;
        Slot->OuterFrame = Frame;
    }
    else
    {
        Slot->OuterFrame = NULL;
    }
}

/* Counts a walk in the current epoch. Returns the counter to decrement when the walk ends. */
static
volatile LONG *
RtlpVehEnterWalk(
    _Out_ volatile ULONG_PTR *Marker,
    _Out_ PRTLP_VEH_THREAD_SLOT *ThreadSlot)
{
    PTEB Teb = NtCurrentTeb();
    ULONG Hash = (ULONG)(((ULONG_PTR)Teb->ClientId.UniqueThread / 4) % RTLP_VEH_WALK_SLOTS);
    PRTLP_VEH_THREAD_SLOT Slot;
    volatile LONG *Walks;
    LONG Epoch;

    Slot = RtlpVehThreadSlot(Teb);
    if (Slot)
        RtlpVehTrackWalk(Teb, Slot, Marker);
    *ThreadSlot = Slot;

    for (;;)
    {
        Epoch = RtlpVehEpoch;
        Walks = Slot ? &Slot->Walks[Epoch] : &RtlpVehWalkSlots[Epoch][Hash].Walks;
        InterlockedIncrement(Walks);

        /* Counted before the epoch changed: the switch sees this walk.
           Otherwise count it in the new epoch. */
        if (RtlpVehEpoch == Epoch)
            return Walks;
        InterlockedDecrement(Walks);
    }
}

/* The walk returns */
static
VOID
RtlpVehLeaveWalk(
    _In_ volatile LONG *Walks,
    _In_opt_ PRTLP_VEH_THREAD_SLOT Slot,
    _In_ volatile ULONG_PTR *Marker)
{
    if (Slot && Slot->OuterFrame == (PVOID)Marker)
    {
        /* The outermost walk: those inside it returned or were left */
        Slot->OuterFrame = NULL;
        if (Slot->Walks[0])
            InterlockedExchange(&Slot->Walks[0], 0);
        if (Slot->Walks[1])
            InterlockedExchange(&Slot->Walks[1], 0);
    }
    else
    {
        InterlockedDecrement(Walks);
    }
}

/* Called with the lock held exclusively */
static
BOOLEAN
RtlpVehEpochDrained(
    _In_ LONG Epoch)
{
    LONG i;

    for (i = 0; i < RtlpVehThreadSlotsUsed; i++)
    {
        if (RtlpVehThreadSlots[i].Walks[Epoch] != 0)
            return FALSE;
    }
    for (i = 0; i < RTLP_VEH_WALK_SLOTS; i++)
    {
        if (RtlpVehWalkSlots[Epoch][i].Walks != 0)
            return FALSE;
    }
    return TRUE;
}

/* Called with the lock held exclusively: drops the walks of the slot and frees it */
static
VOID
RtlpVehReleaseSlot(
    _Inout_ PRTLP_VEH_THREAD_SLOT Slot)
{
    Slot->OuterFrame = NULL;
    InterlockedExchange(&Slot->Walks[0], 0);
    InterlockedExchange(&Slot->Walks[1], 0);
    InterlockedExchangePointer((PVOID *)&Slot->Owner, NULL);
    RtlpVehThreadSlotsTaken--;
}

/* Whether the thread that claimed a slot no longer runs; FALSE when that
   cannot be told. A thread's TEB is freed when it ends. A TEB at the same
   place belongs to another thread when it does not hold this slot's number:
   a new thread there may well have the same id, ids and TEBs are reused at
   once. The thread is not looked up by its id: opening a thread that is
   still being created breaks its creation. The reads cannot fault, as the
   TEB may go at any time. */
static
BOOLEAN
RtlpVehThreadGone(
    _In_ PRTLP_VEH_THREAD_SLOT Slot)
{
    MEMORY_BASIC_INFORMATION Info;
    CLIENT_ID ClientId;
    PVOID SlotNumber;
    NTSTATUS Status;

    Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  Slot->Teb,
                                  MemoryBasicInformation,
                                  &Info,
                                  sizeof(Info),
                                  NULL);
    if (!NT_SUCCESS(Status))
        return FALSE;
    if (Info.State != MEM_COMMIT)
        return TRUE;

    if (!NT_SUCCESS(NtReadVirtualMemory(NtCurrentProcess(),
                                        &Slot->Teb->ReservedForPerf,
                                        &SlotNumber,
                                        sizeof(SlotNumber),
                                        NULL)) ||
        !NT_SUCCESS(NtReadVirtualMemory(NtCurrentProcess(),
                                        &Slot->Teb->ClientId,
                                        &ClientId,
                                        sizeof(ClientId),
                                        NULL)))
    {
        return FALSE;
    }

    /* In a cloned process, the TEBs of the parent's threads have its id */
    return (SlotNumber != (PVOID)(ULONG_PTR)(Slot - RtlpVehThreadSlots + 1)) ||
           (ClientId.UniqueThread != Slot->Owner) ||
           (ClientId.UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess);
}

/* Called with the lock held exclusively: frees the slots of the threads that
   no longer run, dropping their walks */
static
VOID
RtlpVehReapThreadSlots(VOID)
{
    HANDLE Self = NtCurrentTeb()->ClientId.UniqueThread;
    PRTLP_VEH_THREAD_SLOT Slot;
    LONG i;

    for (i = 0; i < RtlpVehThreadSlotsUsed; i++)
    {
        Slot = &RtlpVehThreadSlots[i];
        if (Slot->Owner && Slot->Owner != Self && RtlpVehThreadGone(Slot))
            RtlpVehReleaseSlot(Slot);
    }
}

/* Called with the lock held exclusively. Returns the entries that no walk
   can be on any more, to be freed after the lock is released. MayReap: the
   caller may spend system calls on walks that do not end. */
static
PRTL_VECTORED_HANDLER_ENTRY
RtlpVehCollectFreeable(
    _In_ BOOLEAN MayReap)
{
    PRTL_VECTORED_HANDLER_ENTRY Free = NULL, Last;
    LONG Epoch = RtlpVehEpoch;

    /* Removed entries pile up behind a walk that does not end: drop the
       walks of threads that are gone. When that frees nothing, the next try
       waits for twice as many entries. */
    if (MayReap && RtlpVehDraining && RtlpVehWaiting >= RtlpVehReapAt)
    {
        RtlpVehReapThreadSlots();
        RtlpVehReapAt = RtlpVehWaiting * 2;
    }

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
            Last = RtlpVehDraining;
            while (Last->NextFree)
                Last = Last->NextFree;
            Last->NextFree = Free;
            Free = RtlpVehDraining;
            RtlpVehDraining = NULL;
        }
    }

    if (Free)
    {
        for (Last = Free; Last; Last = Last->NextFree)
            RtlpVehWaiting--;
        RtlpVehReapAt = RTLP_VEH_REAP_FIRST;
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

/* Called by LdrShutdownThread: the thread's walks are over, also one it
   exits from; its slot is free for another thread */
VOID
NTAPI
RtlpShutdownThreadVectoredHandlers(VOID)
{
    PTEB Teb = NtCurrentTeb();
    ULONG_PTR Index = (ULONG_PTR)Teb->ReservedForPerf - 1;
    PRTL_VECTORED_HANDLER_ENTRY Free;

    if (Index >= RTLP_VEH_THREAD_SLOTS)
        return;

    RtlpVehLock();
    if (RtlpVehThreadSlots[Index].Owner == Teb->ClientId.UniqueThread)
        RtlpVehReleaseSlot(&RtlpVehThreadSlots[Index]);
    Teb->ReservedForPerf = NULL;
    Free = RtlpVehCollectFreeable(FALSE);
    RtlpVehUnlock();
    RtlpVehFreeEntries(Free);
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
    PRTLP_VEH_THREAD_SLOT Slot;
    volatile ULONG_PTR Marker;
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
    Walks = RtlpVehEnterWalk(&Marker, &Slot);

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
    RtlpVehLeaveWalk(Walks, Slot, &Marker);

    /* Free what was removed and is no longer used, if nobody is changing the
       lists right now (that one does it then) */
    if (RtlpVehFreePending && RtlpVehTryLock())
    {
        Free = RtlpVehCollectFreeable(FALSE);
        RtlpVehUnlock();
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
    RtlpVehLock();

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
    Free = RtlpVehCollectFreeable(TRUE);
    RtlpVehUnlock();
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
    RtlpVehLock();

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
            RtlpVehWaiting++;

            /* Found what we are looking for, stop searching */
            HandlerFound = TRUE;
            break;
        }

        /* Get the next entry */
        CurrentEntry = CurrentEntry->Flink;
    }

    /* Done with the list, let go of the lock and free what is unused */
    Free = RtlpVehCollectFreeable(TRUE);
    RtlpVehUnlock();
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
