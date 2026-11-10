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
#define HEAP_FE_MARK            0xCE
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
} HEAP_FE_SLOT, *PHEAP_FE_SLOT;

typedef struct _HEAP_FE
{
    ULONG_PTR Cookie;
    volatile LONG Disabled;
    ULONG Signature;
    ULONG SlotCount;
    UCHAR Pad[64 - sizeof(ULONG_PTR) - 3 * sizeof(ULONG)];
    HEAP_FE_SLOT Slots[HEAP_FE_SLOTS];
} HEAP_FE, *PHEAP_FE;

C_ASSERT((sizeof(HEAP_FE_SLOT) % 64) == 0);

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

/* PUBLIC FUNCTIONS *********************************************************/

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

PHEAP_ENTRY
NTAPI
RtlpHeapFeAlloc(PHEAP Heap,
                SIZE_T Index,
                SIZE_T AllocationSize,
                SIZE_T Size)
{
    PHEAP_FE Fe = Heap->FrontEndHeap;
    PHEAP_FE_SLOT Slot;
    PHEAP_ENTRY Entry;
    ULONG Class;

    if (Index >= HEAP_FE_UNITS || Fe->Disabled)
        return NULL;

    Class = HEAP_FE_CLASS_FOR_ALLOC((ULONG)Index);
    Slot = RtlpHeapFeSlot(Fe);

    /* Nothing of this class or the next one: let the heap serve it */
    if (!Slot->Heads[Class] && !Slot->Heads[Class + 1])
    {
        Slot->AllocMiss++;
        return NULL;
    }

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
    }

    _ReadWriteBarrier();
    Slot->Lock = 0;

    if (!Entry)
    {
        Slot->AllocMiss++;
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
    if (Slot->Bytes + Bytes > HEAP_FE_SLOT_BUDGET)
    {
        Slot->FreeSlow++;
        return HEAP_FE_NOT_HANDLED;
    }
    if (Slot->Lock || InterlockedCompareExchange(&Slot->Lock, 1, 0))
        return HEAP_FE_NOT_HANDLED;

    *(PULONG_PTR)(Entry + 1) = (ULONG_PTR)Slot->Heads[Class] ^ Fe->Cookie;
    Entry->SmallTagIndex = HEAP_FE_MARK;
    Slot->Heads[Class] = Entry;
    Slot->Bytes += Bytes;
    Slot->FreeCached++;

    _ReadWriteBarrier();
    Slot->Lock = 0;
    return HEAP_FE_CACHED;
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

        while (InterlockedCompareExchange(&Slot->Lock, 1, 0))
            YieldProcessor();

        for (Class = 0; Class < HEAP_FE_CLASSES; Class++)
        {
            Entry = Slot->Heads[Class];
            Slot->Heads[Class] = NULL;
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
