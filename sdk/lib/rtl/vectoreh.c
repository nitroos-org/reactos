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
 * slow each other down. Nothing on a walk, and nothing on a thread's exit,
 * waits for RtlpVectoredHandlerLock (a walk or an exit only tries it, to free
 * entries, and goes on when it is busy): the holder of the lock may be
 * suspended by the very thread that dispatches its first exception or exits.
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
 *   handler: that walk does not come back) and frees its slot, without the
 *   lock;
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
 * slots share hashed counters, whose walks are never dropped: with more than
 * RTLP_VEH_THREAD_SLOTS threads alive that dispatched an exception, the later
 * ones can still pin removed entries by a walk that does not return, as before
 * the slots (a slot is held for the life of its thread, and freed lazily when
 * its thread is terminated without LdrShutdownThread). The reaper takes the
 * TEB's ReservedForPerf as ours: other code that writes that field in a TEB
 * would make a live thread look gone, and its walks be dropped.
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
 *
 * Slots are claimed and freed without the lock, by compare-exchange on the
 * slot's Owner (a thread id; NULL: free; RTLP_VEH_SLOT_BUSY: being claimed,
 * freed, or looked at by the reaper):
 * - Claim: NULL -> BUSY; then Teb, OuterFrame and the slot number in the TEB
 *   are written; then the thread's slot count Used is raised (compare-
 *   exchange); only then Owner = thread id is stored. The stores before the
 *   publishing interlocked store cannot be seen after it (x86: stores are not
 *   reordered with each other, and the interlocked store is a barrier for the
 *   compiler too), so whoever reads a thread id in Owner and then reads Teb
 *   sees them, and the reaper never meets a half-claimed slot.
 * - Free (the owner at its exit, or the reaper, for a thread that is gone):
 *   thread id -> BUSY by compare-exchange, which only one of them wins; the
 *   winner clears the counters and OuterFrame, and then stores NULL. Nobody
 *   claims or walks in a BUSY slot, so a clear cannot erase the counts of a
 *   later owner. A walk of the owner that meets its own slot BUSY (only when
 *   the reaper took the slot of a recycled thread id by mistake, for a moment)
 *   counts in the hashed counters, that walk only.
 * - The reaper judges a slot from a snapshot of Owner, Teb and Generation and
 *   takes it BUSY only when the owner is gone; the owner of a live thread is
 *   never changed, so its walks always find their slot. The generation, bumped
 *   by every claim before the owner is published, tells a slot that was freed
 *   and claimed again by a thread with the same id (ids are reused at once):
 *   the thread id is put back then.
 * - RtlpVehEpochDrained: a walk counts itself (interlocked increment, a full
 *   barrier) in a slot after Used was raised to cover it, and then reads the
 *   epoch again. The remover switches the epoch (interlocked) and only then
 *   reads Used and the counters. If the walk's second read of the epoch still
 *   gave the old one, the switch comes later in the order of the interlocked
 *   operations, so the remover sees Used and the count; if it gave the new
 *   one, the walk undoes its count and goes on in the new epoch, which holds
 *   no entry that the switch moved to the draining list. A walk that counted
 *   in a slot beyond the Used the remover read started after the switch.
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
   writes its slot while it runs; claiming and freeing one is lock free. */
#define RTLP_VEH_THREAD_SLOTS 64
#define RTLP_VEH_SLOT_BUSY ((HANDLE)(LONG_PTR)-1)

typedef struct DECLSPEC_ALIGN(64) _RTLP_VEH_THREAD_SLOT
{
    volatile LONG Walks[2];     /* Walks of the owner not known to be over, per epoch */
    HANDLE volatile Owner;      /* Thread id, NULL: free, RTLP_VEH_SLOT_BUSY: changing hands */
    PTEB Teb;                   /* Of the owner: freed when it ends */
    volatile LONG Generation;   /* Counts the claims of the slot */
    PVOID OuterFrame;           /* Marker of the outermost walk, NULL: no walk, or not known */
    PVOID OuterStack;           /* StackBase of the stack of that walk */
    ULONG_PTR OuterMarker;      /* Value of the marker */
    ULONG_PTR Sequence;         /* Makes the marker values differ */
} RTLP_VEH_THREAD_SLOT, *PRTLP_VEH_THREAD_SLOT;

static RTLP_VEH_THREAD_SLOT RtlpVehThreadSlots[RTLP_VEH_THREAD_SLOTS];
static volatile LONG RtlpVehThreadSlotsUsed;    /* No slot at or above this was claimed (raised by compare-exchange) */
static volatile LONG RtlpVehThreadSlotsTaken;   /* Slots claimed, interlocked; only a hint to skip the search when all are taken */

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
}

static
BOOLEAN
RtlpVehTryLock(VOID)
{
    return RtlTryAcquireSRWLockExclusive(&RtlpVectoredHandlerLock);
}

static
VOID
RtlpVehUnlock(VOID)
{
    RtlReleaseSRWLockExclusive(&RtlpVectoredHandlerLock);
}

/* The slot of the current thread; claims one at its first walk, without
   waiting for anything. NULL: none (all taken, or the slot is being looked at
   by the reaper: the walk counts in the shared counters, a later walk tries
   again). */
static
PRTLP_VEH_THREAD_SLOT
RtlpVehThreadSlot(
    _In_ PTEB Teb)
{
    HANDLE Self = Teb->ClientId.UniqueThread;
    ULONG_PTR Index = (ULONG_PTR)Teb->ReservedForPerf - 1;
    PRTLP_VEH_THREAD_SLOT Slot;
    LONG Used;
    ULONG i;

    if (Index < RTLP_VEH_THREAD_SLOTS)
    {
        HANDLE Owner = RtlpVehThreadSlots[Index].Owner;

        if (Owner == Self)
            return &RtlpVehThreadSlots[Index];

        /* Ours, for the moment held by the reaper */
        if (Owner == RTLP_VEH_SLOT_BUSY)
            return NULL;
    }

    /* A slot number that is not ours: one inherited from a thread of the
       parent of a cloned process, or none */
    if (RtlpVehThreadSlotsTaken >= RTLP_VEH_THREAD_SLOTS)
        return NULL;

    for (i = 0; i < RTLP_VEH_THREAD_SLOTS; i++)
    {
        Slot = &RtlpVehThreadSlots[i];
        if (Slot->Owner ||
            InterlockedCompareExchangePointer((PVOID volatile *)&Slot->Owner, RTLP_VEH_SLOT_BUSY, NULL) != NULL)
        {
            continue;
        }

        /* Ours, and nobody looks at it: set it up, then publish it */
        Slot->Teb = Teb;
        Slot->OuterFrame = NULL;
        Teb->ReservedForPerf = (PVOID)(ULONG_PTR)(i + 1);
        InterlockedIncrement(&Slot->Generation);

        /* Raised before the first walk counts in the slot (see the header) */
        for (;;)
        {
            Used = RtlpVehThreadSlotsUsed;
            if (Used > (LONG)i ||
                InterlockedCompareExchange(&RtlpVehThreadSlotsUsed, i + 1, Used) == Used)
            {
                break;
            }
        }
        InterlockedIncrement(&RtlpVehThreadSlotsTaken);
        InterlockedExchangePointer((PVOID volatile *)&Slot->Owner, Self);
        return Slot;
    }

    return NULL;
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
    LONG i, Used;

    /* Read after the epoch was switched: see the header */
    Used = RtlpVehThreadSlotsUsed;
    for (i = 0; i < Used; i++)
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

/* The slot is BUSY and belongs to the caller: drops the walks of its owner
   and frees it */
static
VOID
RtlpVehFreeBusySlot(
    _Inout_ PRTLP_VEH_THREAD_SLOT Slot)
{
    Slot->OuterFrame = NULL;
    InterlockedExchange(&Slot->Walks[0], 0);
    InterlockedExchange(&Slot->Walks[1], 0);
    InterlockedDecrement(&RtlpVehThreadSlotsTaken);
    InterlockedExchangePointer((PVOID volatile *)&Slot->Owner, NULL);
}

/* Whether the thread that claimed a slot no longer runs; FALSE when that
   cannot be told. A thread's TEB is freed when it ends. A TEB at the same
   place belongs to another thread when it does not hold this slot's number:
   a new thread there may well have the same id, ids and TEBs are reused at
   once. The thread is not looked up by its id: opening a thread that is
   still being created breaks its creation. The reads cannot fault, as the
   TEB may go at any time. Teb and Owner are those of slot number Index. */
static
BOOLEAN
RtlpVehThreadGone(
    _In_ PTEB Teb,
    _In_ HANDLE Owner,
    _In_ LONG Index)
{
    MEMORY_BASIC_INFORMATION Info;
    CLIENT_ID ClientId;
    PVOID SlotNumber;
    NTSTATUS Status;

    Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  Teb,
                                  MemoryBasicInformation,
                                  &Info,
                                  sizeof(Info),
                                  NULL);
    if (!NT_SUCCESS(Status))
        return FALSE;
    if (Info.State != MEM_COMMIT)
        return TRUE;

    if (!NT_SUCCESS(NtReadVirtualMemory(NtCurrentProcess(),
                                        &Teb->ReservedForPerf,
                                        &SlotNumber,
                                        sizeof(SlotNumber),
                                        NULL)) ||
        !NT_SUCCESS(NtReadVirtualMemory(NtCurrentProcess(),
                                        &Teb->ClientId,
                                        &ClientId,
                                        sizeof(ClientId),
                                        NULL)))
    {
        return FALSE;
    }

    /* In a cloned process, the TEBs of the parent's threads have its id */
    return (SlotNumber != (PVOID)(ULONG_PTR)(Index + 1)) ||
           (ClientId.UniqueThread != Owner) ||
           (ClientId.UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess);
}

/* Called with the lock held exclusively (one reaper at a time): frees the
   slots of the threads that no longer run, dropping their walks. A slot is
   judged while its owner can still own it (the owner of a live thread is
   never touched: its walks must find the slot), from a snapshot of its owner,
   TEB and generation; only a slot judged gone is taken BUSY, and the snapshot
   must still hold then: a thread id that was freed and claimed again by a
   thread with the same id (ids are reused at once) is told by the generation,
   and the slot is given back. It is judged with 3 system calls even when it
   counts no walk: a free slot is what a later thread needs. */
static
VOID
RtlpVehReapThreadSlots(VOID)
{
    HANDLE Self = NtCurrentTeb()->ClientId.UniqueThread;
    PRTLP_VEH_THREAD_SLOT Slot;
    HANDLE Owner;
    LONG i, Used = RtlpVehThreadSlotsUsed, Generation;
    PTEB Teb;

    for (i = 0; i < Used; i++)
    {
        Slot = &RtlpVehThreadSlots[i];
        Owner = Slot->Owner;
        if (!Owner || Owner == RTLP_VEH_SLOT_BUSY || Owner == Self)
            continue;

        /* Teb and Generation were stored before the owner was published */
        Generation = Slot->Generation;
        Teb = Slot->Teb;
        if (!RtlpVehThreadGone(Teb, Owner, i))
            continue;

        if (InterlockedCompareExchangePointer((PVOID volatile *)&Slot->Owner, RTLP_VEH_SLOT_BUSY, Owner) != Owner)
            continue;
        if (Slot->Generation == Generation)
            RtlpVehFreeBusySlot(Slot);
        else
            InterlockedExchangePointer((PVOID volatile *)&Slot->Owner, Owner);
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
   exits from; its slot is free for another thread. Nothing here waits for the
   lock: the thread that holds it may be suspended by this one. Entries that
   cannot be freed now are freed by the next add, remove or walk. */
VOID
NTAPI
RtlpShutdownThreadVectoredHandlers(VOID)
{
    PTEB Teb = NtCurrentTeb();
    HANDLE Self = Teb->ClientId.UniqueThread;
    ULONG_PTR Index = (ULONG_PTR)Teb->ReservedForPerf - 1;
    PRTLP_VEH_THREAD_SLOT Slot;
    PRTL_VECTORED_HANDLER_ENTRY Free;
    HANDLE Owner;
    ULONG Spins;

    if (Index >= RTLP_VEH_THREAD_SLOTS)
        return;

    Slot = &RtlpVehThreadSlots[Index];
    for (Spins = 0; Spins < 1000; Spins++)
    {
        Owner = Slot->Owner;
        if (Owner == Self)
        {
            if (InterlockedCompareExchangePointer((PVOID volatile *)&Slot->Owner, RTLP_VEH_SLOT_BUSY, Self) == Self)
            {
                RtlpVehFreeBusySlot(Slot);
                break;
            }
        }
        else if (Owner == RTLP_VEH_SLOT_BUSY)
        {
            /* The reaper is looking at the slot: for a moment (it waits for nothing).
               Should it not be done soon, the slot stays with a TEB that no longer
               holds its number, and the next reaper frees it. */
            YieldProcessor();
        }
        else
        {
            break;
        }
    }
    Teb->ReservedForPerf = NULL;

    if (RtlpVehFreePending && RtlpVehTryLock())
    {
        Free = RtlpVehCollectFreeable(FALSE);
        RtlpVehUnlock();
        RtlpVehFreeEntries(Free);
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
