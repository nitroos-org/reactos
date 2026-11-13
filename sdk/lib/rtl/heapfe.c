/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/heapfe.c
 * PURPOSE:         RTL Heap front end: per-thread-slot cache of small freed blocks (user mode only)
 *
 * A serialized heap spends most of a multithreaded workload waiting for its own
 * lock. This front end lets small allocations and frees skip that lock, as the
 * low-fragmentation heap does on Windows (HeapQueryInformation reports it as
 * type 2, HeapSetInformation(HeapCompatibilityInformation, 2) turns it on).
 *
 * Design:
 *  - A freed small block is not given back to the heap. It stays a BUSY block
 *    of the heap proper (so neighbours never coalesce into it and the heap
 *    structure is untouched) and is pushed on a list of blocks of exactly its
 *    size, in the slot of the freeing thread. A later allocation of that size
 *    from a thread of the same slot pops it again, without taking the heap lock.
 *  - A slot is guarded by its own try-lock: a thread never waits for it, it falls
 *    back to the ordinary heap path. Threads are spread over the slots by id.
 *  - Blocks do not stay with the thread that freed them when it has more of a size class than it
 *    is likely to use: a batch of them moves to a shared list of the class, and a thread whose
 *    slot has none of a class takes a batch from there. This keeps the pattern of one thread
 *    allocating what others free (a producer and its workers) off the heap lock too. Shared lists
 *    have try-locks as well and a byte cap per class.
 *  - The cache is bounded (bytes per slot). Everything cached is returned to the
 *    heap, with coalescing, by RtlpHeapFeFlush: when the heap runs out of free
 *    space, and whenever someone locks the heap or walks it, so that HeapLock,
 *    HeapWalk and friends see the same blocks as without the front end. While a
 *    heap is locked by its user the front end is bypassed, so that the holder
 *    of the lock excludes every other allocation as documented.
 *  - A cached block carries a marker in the SmallTagIndex byte of its header
 *    (always zero for blocks the front end accepts), which lets HeapFree detect
 *    a double free, and HeapSize/HeapValidate treat the block as freed.
 *    The list link in the block is stored XORed with a per-heap secret.
 *  - Only heaps that could be contended are eligible: serialized, growable and
 *    without tail/free checking, validation or tags. Blocks with extra data or
 *    user flags, and requests with flags other than zeroing, take the old path.
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>
#include <heap.h>

#define NDEBUG
#include <debug.h>

/* DEFINITIONS **************************************************************/

#define HEAP_FE_SLOTS           64
#define HEAP_FE_SLOT_BUDGET     (512 * 1024)   /* cached bytes per slot */
#define HEAP_FE_SLOT_HIGH       24             /* blocks of a class in one slot above which a batch moves to the shared list */
#define HEAP_FE_BATCH           8              /* blocks moved at a time */
#define HEAP_FE_SHARED_CAP      (128 * 1024)   /* bytes on the shared list of a class */
#define HEAP_FE_FLUSH_SPINS     (1 << 20)      /* the flush waits this long for a slot or list that is in use */
#define HEAP_FE_MARK            0xCE

C_ASSERT(HEAP_FE_CLASSES == RTL_NUMBER_OF(((PHEAP_FE_ACT)0)->Live));
#define HEAP_FE_SIGNATURE       0x31454648  /* 'HFE1' */

typedef struct _HEAP_FE_SLOT
{
    volatile LONG Lock;
    ULONG Bytes;
    ULONG AllocHit;     /* statistics, for diagnostics only */
    ULONG AllocMiss;
    ULONG FreeCached;
    ULONG FreeSlow;
    UCHAR Pad[64 - 6 * sizeof(ULONG)];
    PHEAP_ENTRY Heads[HEAP_FE_CLASSES];
    USHORT Counts[HEAP_FE_CLASSES];     /* blocks on each list */
    UCHAR Misses[HEAP_FE_CLASSES];      /* requests the slot could not serve since the last refill */
    UCHAR Pad2[(64 - ((64 + sizeof(PHEAP_ENTRY) * HEAP_FE_CLASSES + sizeof(USHORT) * HEAP_FE_CLASSES + HEAP_FE_CLASSES) % 64)) % 64];
} HEAP_FE_SLOT, *PHEAP_FE_SLOT;

typedef struct _HEAP_FE_SHARED
{
    volatile LONG Lock;
    ULONG Bytes;
    PHEAP_ENTRY Head;
    UCHAR Pad[64 - 2 * sizeof(ULONG) - sizeof(PHEAP_ENTRY)];
} HEAP_FE_SHARED, *PHEAP_FE_SHARED;

typedef struct _HEAP_FE
{
    ULONG_PTR Cookie;
    volatile LONG Disabled;
    ULONG Signature;
    ULONG SlotCount;
    UCHAR Pad[64 - sizeof(ULONG_PTR) - 3 * sizeof(ULONG)];
    HEAP_FE_SHARED Shared[HEAP_FE_CLASSES];
    HEAP_FE_SLOT Slots[HEAP_FE_SLOTS];
} HEAP_FE, *PHEAP_FE;

C_ASSERT((sizeof(HEAP_FE_SLOT) % 64) == 0);
C_ASSERT(sizeof(HEAP_FE_SHARED) == 64);

/* PRIVATE FUNCTIONS ********************************************************/

FORCEINLINE
PHEAP_FE_SLOT
RtlpHeapFeSlot(PHEAP_FE Fe)
{
    ULONG_PTR Id = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;

    return &Fe->Slots[(Id >> 2) & (HEAP_FE_SLOTS - 1)];
}

FORCEINLINE
PHEAP_ENTRY
RtlpHeapFeNext(PHEAP_FE Fe, PHEAP_ENTRY Entry)
{
    PHEAP_ENTRY Next = (PHEAP_ENTRY)(*(PULONG_PTR)(Entry + 1) ^ Fe->Cookie);

    /* A link that is not a block address was overwritten after the free: drop the rest of the list */
    if ((ULONG_PTR)Next & (HEAP_ENTRY_SIZE - 1))
        return NULL;

    return Next;
}

/* Takes a front end lock for the flush, which holds the heap lock: waits for a holder that is running,
   gives up on one that does not let go (suspended, or preempted for long) */
static
BOOLEAN
RtlpHeapFeLockWait(volatile LONG *Lock)
{
    ULONG Spins;

    for (Spins = 0; Spins < HEAP_FE_FLUSH_SPINS; Spins++)
    {
        if (!*Lock && !InterlockedCompareExchange(Lock, 1, 0))
            return TRUE;
        YieldProcessor();
    }

    return FALSE;
}

/* PUBLIC FUNCTIONS *********************************************************/

static
BOOLEAN
RtlpHeapFeEligible(PHEAP Heap)
{
    if (RtlpGetMode() != UserMode)
        return FALSE;

    /* Not for heaps without a lock, fixed size ones, and the checking ones */
    if ((Heap->Flags & (HEAP_NO_SERIALIZE |
                        HEAP_TAIL_CHECKING_ENABLED |
                        HEAP_FREE_CHECKING_ENABLED |
                        HEAP_VALIDATE_ALL_ENABLED |
                        HEAP_VALIDATE_PARAMETERS_ENABLED |
                        HEAP_CAPTURE_STACK_BACKTRACES |
                        HEAP_CREATE_ENABLE_TRACING |
                        HEAP_FLAG_PAGE_ALLOCS)) ||
        !(Heap->Flags & HEAP_GROWABLE) ||
        (Heap->ForceFlags & (HEAP_NO_SERIALIZE | HEAP_FLAG_PAGE_ALLOCS)) ||
        Heap->PseudoTagEntries ||
        !Heap->LockVariable)
    {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
NTAPI
RtlpHeapFeEnable(PHEAP Heap)
{
    PHEAP_FE Fe = NULL;
    SIZE_T Size = sizeof(HEAP_FE);
    NTSTATUS Status;

    /* The caller holds the heap lock (or the heap is not shared yet) */
    if (Heap->FrontEndHeapType == HEAP_FRONTEND_CACHE)
        return TRUE;

    if (Heap->FrontEndHeapType != 0)
        return FALSE;

    if (!RtlpHeapFeEligible(Heap))
        return FALSE;

    Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                     (PVOID *)&Fe,
                                     0,
                                     &Size,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Fe->Signature = HEAP_FE_SIGNATURE;
    Fe->SlotCount = HEAP_FE_SLOTS;
    Fe->Cookie = (ULONG_PTR)__rdtsc() ^ ((ULONG_PTR)Fe << 8) ^
                 ((ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread << 20) ^
                 (ULONG_PTR)0x5bd1e995a3c6f1b7ULL;

    /* Publish the cache before the type: the type is what the fast paths test */
    Heap->FrontEndHeap = Fe;
    _ReadWriteBarrier();
    Heap->FrontEndHeapType = HEAP_FRONTEND_CACHE;

    /* Nothing is counted any more */
    if (Heap->FeAct)
    {
        PHEAP_FE_ACT Act = Heap->FeAct;

        Heap->FeAct = HEAP_FE_ACT_OFF;
        if (Act != HEAP_FE_ACT_OFF)
            RtlFreeHeap(Heap, HEAP_NO_SERIALIZE, Act);
    }
    return TRUE;
}

VOID
NTAPI
RtlpHeapFeDestroy(PHEAP Heap)
{
    PVOID Fe = Heap->FrontEndHeap;
    SIZE_T Size = 0;

    if (Heap->FrontEndHeapType != HEAP_FRONTEND_CACHE || !Fe)
        return;

    Heap->FrontEndHeapType = 0;
    Heap->FrontEndHeap = NULL;
    ZwFreeVirtualMemory(NtCurrentProcess(), &Fe, &Size, MEM_RELEASE);
}

/* Moves up to HEAP_FE_BATCH blocks of a class from a slot to the shared list of the class, when that
   has room and its lock is free. The caller holds the slot lock. */
static
VOID
RtlpHeapFeShare(PHEAP_FE Fe,
                PHEAP_FE_SLOT Slot,
                ULONG Class)
{
    PHEAP_FE_SHARED Shared = &Fe->Shared[Class];
    PHEAP_ENTRY First = NULL, Last = NULL, Entry;
    ULONG Count, Bytes = 0;

    if (Shared->Bytes >= HEAP_FE_SHARED_CAP ||
        Shared->Lock || InterlockedCompareExchange(&Shared->Lock, 1, 0))
    {
        return;
    }

    for (Count = 0; Count < HEAP_FE_BATCH && (Entry = Slot->Heads[Class]) != NULL; Count++)
    {
        Slot->Heads[Class] = RtlpHeapFeNext(Fe, Entry);
        Bytes += (ULONG)Entry->Size << HEAP_ENTRY_SHIFT;
        if (Last)
            *(PULONG_PTR)(Last + 1) = (ULONG_PTR)Entry ^ Fe->Cookie;
        else
            First = Entry;
        Last = Entry;
    }

    if (Last)
    {
        *(PULONG_PTR)(Last + 1) = (ULONG_PTR)Shared->Head ^ Fe->Cookie;
        Shared->Head = First;
        Shared->Bytes += Bytes;
        Slot->Bytes -= Bytes;
        Slot->Counts[Class] = (Slot->Counts[Class] > Count) ? Slot->Counts[Class] - Count : 0;
    }

    _ReadWriteBarrier();
    Shared->Lock = 0;
}

/* Takes a block of a class from its shared list, and a batch for the slot when the caller holds the
   slot lock (Slot != NULL). Neither lock is waited for. */
static
PHEAP_ENTRY
RtlpHeapFeTake(PHEAP_FE Fe,
               PHEAP_FE_SLOT Slot,
               ULONG Class)
{
    PHEAP_FE_SHARED Shared = &Fe->Shared[Class];
    PHEAP_ENTRY Entry, More;
    ULONG Count;

    if (!Shared->Head || Shared->Lock || InterlockedCompareExchange(&Shared->Lock, 1, 0))
        return NULL;

    Entry = Shared->Head;
    if (Entry)
    {
        Shared->Head = RtlpHeapFeNext(Fe, Entry);
        Shared->Bytes -= (ULONG)Entry->Size << HEAP_ENTRY_SHIFT;

        for (Count = 1; Slot && Count < HEAP_FE_BATCH && (More = Shared->Head) != NULL; Count++)
        {
            ULONG Bytes = (ULONG)More->Size << HEAP_ENTRY_SHIFT;

            Shared->Head = RtlpHeapFeNext(Fe, More);
            Shared->Bytes -= Bytes;
            *(PULONG_PTR)(More + 1) = (ULONG_PTR)Slot->Heads[Class] ^ Fe->Cookie;
            Slot->Heads[Class] = More;
            Slot->Counts[Class]++;
            Slot->Bytes += Bytes;
        }
    }

    _ReadWriteBarrier();
    Shared->Lock = 0;
    return Entry;
}

PHEAP_ENTRY
NTAPI
RtlpHeapFeAlloc(PHEAP Heap,
                SIZE_T Index,
                SIZE_T AllocationSize,
                SIZE_T Size)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;
    PHEAP_FE_SLOT Slot;
    PHEAP_ENTRY Entry = NULL;
    ULONG Class;

    if (Index >= HEAP_FE_UNITS || Fe->Disabled)
        return NULL;

    Class = HEAP_FE_CLASS_FOR_ALLOC((ULONG)Index);
    Slot = RtlpHeapFeSlot(Fe);

    if (Slot->Heads[Class] || Slot->Heads[Class + 1])
    {
        /* A busy slot (another thread of the same slot) is not waited for */
        if (Slot->Lock || InterlockedCompareExchange(&Slot->Lock, 1, 0))
            return NULL;

        Entry = Slot->Heads[Class];
        if (!Entry)
        {
            /* The next class is at most one step (64 bytes) bigger; the surplus fits UnusedBytes */
            Class++;
            Entry = Slot->Heads[Class];
        }
        if (Entry)
        {
            Slot->Heads[Class] = RtlpHeapFeNext(Fe, Entry);
            Slot->Bytes -= (ULONG)Entry->Size << HEAP_ENTRY_SHIFT;
            if (Slot->Counts[Class])
                Slot->Counts[Class]--;
        }

        _ReadWriteBarrier();
        Slot->Lock = 0;
    }
    else if (Fe->Shared[Class].Head)
    {
        /* What other threads freed: a batch for this slot, one block for this request */
        if (!Slot->Lock && !InterlockedCompareExchange(&Slot->Lock, 1, 0))
        {
            Entry = RtlpHeapFeTake(Fe, Slot, Class);
            _ReadWriteBarrier();
            Slot->Lock = 0;
        }
        else
        {
            Entry = RtlpHeapFeTake(Fe, NULL, Class);
        }
    }

    if (!Entry)
    {
        Slot->AllocMiss++;
        if (Slot->Misses[Class] != 0xFF)
            Slot->Misses[Class]++;
        return NULL;
    }

    Slot->AllocHit++;

    /* It is an in-use block again, with the size of this request */
    Entry->SmallTagIndex = 0;
    Entry->UnusedBytes = (UCHAR)(((ULONG)Entry->Size << HEAP_ENTRY_SHIFT) - Size);
    return Entry;
}

ULONG
NTAPI
RtlpHeapFeFree(PHEAP Heap,
               PHEAP_ENTRY Entry)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;
    PHEAP_FE_SLOT Slot;
    ULONG Bytes, Index, Class;

    /* Only a plain in-use block, possibly the last of its segment */
    if ((Entry->Flags & ~HEAP_ENTRY_LAST_ENTRY) != HEAP_ENTRY_BUSY)
        return HEAP_FE_NOT_HANDLED;

    if (Entry->SmallTagIndex == HEAP_FE_MARK)
        return HEAP_FE_INVALID;

    Index = Entry->Size;
    if (Index < 2 || Index >= HEAP_FE_UNITS || Entry->SmallTagIndex != 0 || Fe->Disabled)
        return HEAP_FE_NOT_HANDLED;

    Class = HEAP_FE_CLASS_FOR_FREE(Index);

    Slot = RtlpHeapFeSlot(Fe);
    Bytes = Index << HEAP_ENTRY_SHIFT;
    if (Slot->Lock || InterlockedCompareExchange(&Slot->Lock, 1, 0))
        return HEAP_FE_NOT_HANDLED;

    if (Slot->Bytes + Bytes > HEAP_FE_SLOT_BUDGET)
    {
        /* This thread frees more than it takes: the block goes to the shared list of its class,
           and only when that is full to the heap */
        PHEAP_FE_SHARED Shared = &Fe->Shared[Class];

        if (Shared->Bytes < HEAP_FE_SHARED_CAP &&
            !Shared->Lock && !InterlockedCompareExchange(&Shared->Lock, 1, 0))
        {
            *(PULONG_PTR)(Entry + 1) = (ULONG_PTR)Shared->Head ^ Fe->Cookie;
            Entry->SmallTagIndex = HEAP_FE_MARK;
            Shared->Head = Entry;
            Shared->Bytes += Bytes;
            _ReadWriteBarrier();
            Shared->Lock = 0;
            Slot->FreeCached++;
            Slot->Lock = 0;
            return HEAP_FE_CACHED;
        }

        Slot->FreeSlow++;
        _ReadWriteBarrier();
        Slot->Lock = 0;
        return HEAP_FE_NOT_HANDLED;
    }

    *(PULONG_PTR)(Entry + 1) = (ULONG_PTR)Slot->Heads[Class] ^ Fe->Cookie;
    Entry->SmallTagIndex = HEAP_FE_MARK;
    Slot->Heads[Class] = Entry;
    Slot->Bytes += Bytes;
    Slot->FreeCached++;
    /* A thread that keeps what it frees (the usual case) is not touched: only a slot that is more than half
       full and has many blocks of this class gives a batch away */
    if (++Slot->Counts[Class] > HEAP_FE_SLOT_HIGH && Slot->Bytes > HEAP_FE_SLOT_BUDGET / 2)
        RtlpHeapFeShare(Fe, Slot, Class);

    _ReadWriteBarrier();
    Slot->Lock = 0;
    return HEAP_FE_CACHED;
}

VOID
NTAPI
RtlpHeapFeCountAlloc(PHEAP Heap,
                     SIZE_T Index)
{
    PHEAP_FE_ACT Act = Heap->FeAct;
    BOOLEAN Activate = FALSE;
    ULONG Class;

    /* The caller holds the heap lock and the heap has no front end yet */
    if (Act == HEAP_FE_ACT_OFF)
        return;

    if (!Act)
    {
        /* First time: a heap that cannot have a front end does not count at all */
        if (!RtlpHeapFeEligible(Heap))
        {
            Heap->FeAct = HEAP_FE_ACT_OFF;
            return;
        }

        Act = RtlAllocateHeap(Heap, HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY, sizeof(*Act));
        if (!Act)
        {
            Heap->FeAct = HEAP_FE_ACT_OFF;
            return;
        }
        Heap->FeAct = Act;
    }

    if ((Index << HEAP_ENTRY_SHIFT) <= HEAP_FE_ACT_SMALL_BYTES)
    {
        Class = HEAP_FE_CLASS_FOR_ALLOC((ULONG)Index);
        if (Act->Live[Class] != 0xFF)
            Act->Live[Class]++;
        if (Act->Ops[Class] != 0xFFFF)
            Act->Ops[Class]++;
        Activate = (Act->Live[Class] >= HEAP_FE_ACT_LIVE) || (Act->Ops[Class] >= HEAP_FE_ACT_CHURN);
    }
    else if (Index <= Heap->VirtualMemoryThreshold)
    {
        Act->BigLive += Index << HEAP_ENTRY_SHIFT;
        Activate = Act->BigLive >= HEAP_FE_ACT_BIG_BYTES;
    }

    /* Enabling frees the counters; a heap that refuses is not asked again */
    if (Activate && !RtlpHeapFeEnable(Heap) && Heap->FrontEndHeapType == 0)
    {
        Heap->FeAct = HEAP_FE_ACT_OFF;
        RtlFreeHeap(Heap, HEAP_NO_SERIALIZE, Act);
    }
}

VOID
NTAPI
RtlpHeapFeCountFree(PHEAP Heap,
                    PHEAP_ENTRY Entry)
{
    PHEAP_FE_ACT Act = Heap->FeAct;
    SIZE_T Index = Entry->Size;
    ULONG Class;

    if (Act <= HEAP_FE_ACT_OFF)
        return;

    /* Only blocks the allocation counted (no extra data, no user flags) */
    if ((Entry->Flags & ~HEAP_ENTRY_LAST_ENTRY) != HEAP_ENTRY_BUSY)
        return;

    /* A block can be bigger than its request (the heap does not split off a remainder that is too
       small): count it under the class of the request, as the allocation did */
    if (((Index << HEAP_ENTRY_SHIFT) <= HEAP_FE_ACT_SMALL_BYTES + 256) &&
        (Index << HEAP_ENTRY_SHIFT) > Entry->UnusedBytes)
    {
        SIZE_T Payload = (Index << HEAP_ENTRY_SHIFT) - Entry->UnusedBytes;

        Index = ((Payload + Heap->AlignRound) & Heap->AlignMask) >> HEAP_ENTRY_SHIFT;
    }

    if ((Index << HEAP_ENTRY_SHIFT) <= HEAP_FE_ACT_SMALL_BYTES)
    {
        Class = HEAP_FE_CLASS_FOR_ALLOC((ULONG)Index);
        if (Act->Live[Class])
            Act->Live[Class]--;
    }
    else
    {
        SIZE_T Bytes = Index << HEAP_ENTRY_SHIFT;

        Act->BigLive = (Act->BigLive > Bytes) ? Act->BigLive - Bytes : 0;
    }
}

VOID
NTAPI
RtlpHeapFeRefill(PHEAP Heap,
                 PHEAP_ENTRY Served)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;
    PHEAP_FE_SLOT Slot;
    PHEAP_ENTRY Block[HEAP_FE_REFILL_MAX];
    ULONG Want, Got = 0, Class, i;
    SIZE_T Index = Served->Size, BlockBytes = Index << HEAP_ENTRY_SHIFT;

    /* The caller holds the heap lock and has just served Served, from the heap, to a thread whose
       slot had nothing of its size class. A thread that keeps missing gets a few more blocks of the
       class now, so that its next requests do not need the lock. Only the blocks the front end files
       under exactly one class: plain, of a class size. */
    /* Only while another thread waits for the heap lock: a thread alone gains nothing from taking blocks it may not use */
    if (Heap->LockVariable->CriticalSection.LockCount <= 0)
        return;

    if (Fe->Disabled || Index < 2 || Index >= HEAP_FE_UNITS ||
        (Served->Flags & ~HEAP_ENTRY_LAST_ENTRY) != HEAP_ENTRY_BUSY ||
        Index != RtlpHeapFeRoundIndex(Index))
    {
        return;
    }

    Class = HEAP_FE_CLASS_FOR_ALLOC((ULONG)Index);
    Slot = RtlpHeapFeSlot(Fe);
    if (Slot->Misses[Class] < HEAP_FE_REFILL_MISSES)
        return;

    Want = (ULONG)(HEAP_FE_REFILL_BYTES / BlockBytes);
    if (Want > HEAP_FE_REFILL_MAX)
        Want = HEAP_FE_REFILL_MAX;
    Slot->Misses[Class] = 0;
    if (!Want || Slot->Bytes + Want * BlockBytes > HEAP_FE_SLOT_BUDGET / 2)
        return;

    /* Not under the slot lock: serving a block may flush the front end, which waits for it */
    for (i = 0; i < Want; i++)
    {
        PHEAP_ENTRY Entry = RtlAllocateHeap(Heap, HEAP_NO_SERIALIZE, BlockBytes - sizeof(HEAP_ENTRY));

        if (!Entry)
            break;
        Block[Got++] = (PHEAP_ENTRY)Entry - 1;
    }
    if (!Got)
        return;

    if (Fe->Disabled || Slot->Lock || InterlockedCompareExchange(&Slot->Lock, 1, 0))
    {
        /* Give them back: the heap lock is ours */
        while (Got)
            RtlpFreeBlockLocked(Heap, Block[--Got]);
        return;
    }

    for (i = 0; i < Got; i++)
    {
        PHEAP_ENTRY Entry = Block[i];

        /* A block the heap served bigger than asked (it kept no remainder) files where it fits */
        Class = HEAP_FE_CLASS_FOR_FREE(Entry->Size);
        if (Entry->Size < 2 || Entry->Size >= HEAP_FE_UNITS ||
            (Entry->Flags & ~HEAP_ENTRY_LAST_ENTRY) != HEAP_ENTRY_BUSY ||
            Entry->SmallTagIndex != 0)
        {
            RtlpFreeBlockLocked(Heap, Entry);
            continue;
        }

        *(PULONG_PTR)(Entry + 1) = (ULONG_PTR)Slot->Heads[Class] ^ Fe->Cookie;
        Entry->SmallTagIndex = HEAP_FE_MARK;
        Slot->Heads[Class] = Entry;
        Slot->Counts[Class]++;
        Slot->Bytes += (ULONG)Entry->Size << HEAP_ENTRY_SHIFT;
        Slot->FreeCached++;
    }

    _ReadWriteBarrier();
    Slot->Lock = 0;
}

BOOLEAN
NTAPI
RtlpHeapFeIsCached(PHEAP_ENTRY Entry)
{
    return (Entry->Flags & HEAP_ENTRY_BUSY) && (Entry->SmallTagIndex == HEAP_FE_MARK);
}

ULONG
NTAPI
RtlpHeapFeFlush(PHEAP Heap)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;
    PHEAP_FE_SLOT Slot;
    PHEAP_ENTRY Entry, Next;
    ULONG Slots, Class, Count = 0;

    /* The caller holds the heap lock; slot holders never wait for it, so waiting here is safe */
    for (Slots = 0; Slots < HEAP_FE_SLOTS; Slots++)
    {
        Slot = &Fe->Slots[Slots];
        if (!Slot->Bytes && Slot->Lock == 0)
            continue;

        /* A holder that was suspended inside the slot (Office suspends all its threads) never lets go:
           the flush does not wait for it, the blocks of that slot stay parked */
        if (!RtlpHeapFeLockWait(&Slot->Lock))
            continue;

        for (Class = 0; Class < HEAP_FE_CLASSES; Class++)
        {
            Entry = Slot->Heads[Class];
            Slot->Heads[Class] = NULL;
            Slot->Counts[Class] = 0;
            while (Entry)
            {
                Next = RtlpHeapFeNext(Fe, Entry);
                Entry->SmallTagIndex = 0;
                RtlpFreeBlockLocked(Heap, Entry);
                Count++;
                Entry = Next;
            }
        }
        Slot->Bytes = 0;

        _ReadWriteBarrier();
        Slot->Lock = 0;
    }

    /* and what the threads left on the shared lists */
    for (Class = 0; Class < HEAP_FE_CLASSES; Class++)
    {
        PHEAP_FE_SHARED Shared = &Fe->Shared[Class];

        if (!Shared->Head && Shared->Lock == 0)
            continue;

        if (!RtlpHeapFeLockWait(&Shared->Lock))
            continue;

        Entry = Shared->Head;
        Shared->Head = NULL;
        Shared->Bytes = 0;

        _ReadWriteBarrier();
        Shared->Lock = 0;

        while (Entry)
        {
            Next = RtlpHeapFeNext(Fe, Entry);
            Entry->SmallTagIndex = 0;
            RtlpFreeBlockLocked(Heap, Entry);
            Count++;
            Entry = Next;
        }
    }

    return Count;
}

SIZE_T
NTAPI
RtlpHeapFeParked(PHEAP Heap)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;
    SIZE_T Total = 0;
    ULONG Slots;

    /* Racy by design: a size estimate to decide whether to give the blocks back */
    for (Slots = 0; Slots < Fe->SlotCount; Slots++)
        Total += Fe->Slots[Slots].Bytes;
    for (Slots = 0; Slots < HEAP_FE_CLASSES; Slots++)
        Total += Fe->Shared[Slots].Bytes;

    return Total;
}

ULONG
NTAPI
RtlpHeapFeLock(PHEAP Heap)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;

    if (Heap->FrontEndHeapType != HEAP_FRONTEND_CACHE)
        return 0;

    /* The heap lock is held: stop the cache from taking part, then give it back */
    InterlockedIncrement(&Fe->Disabled);
    return RtlpHeapFeFlush(Heap);
}

VOID
NTAPI
RtlpHeapFeUnlock(PHEAP Heap)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;

    if (Heap->FrontEndHeapType != HEAP_FRONTEND_CACHE)
        return;

    /* An unlock without a lock (a caller's bug) must not leave the front end out for good */
    if (Fe->Disabled > 0)
        InterlockedDecrement(&Fe->Disabled);
}
