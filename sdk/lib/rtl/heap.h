/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS System Libraries
 * FILE:            lib/rtl/heap.h
 * PURPOSE:         Run-Time Libary Heap Manager header
 * PROGRAMMER:      Aleksey Bragin
 */

/* INCLUDES ******************************************************************/

#ifndef RTL_HEAP_H
#define RTL_HEAP_H

/* Core heap definitions */
#define HEAP_SEGMENTS 64

#define HEAP_ENTRY_SIZE ((ULONG)sizeof(HEAP_ENTRY))
#ifdef _WIN64
#define HEAP_ENTRY_SHIFT 4
#else
#define HEAP_ENTRY_SHIFT 3
#endif
#define HEAP_MAX_BLOCK_SIZE ((0x80000 - PAGE_SIZE) >> HEAP_ENTRY_SHIFT)

#define ARENA_INUSE_FILLER     0xBAADF00D
#define ARENA_FREE_FILLER      0xFEEEFEEE
#define HEAP_TAIL_FILL         0xab

// from ntifs.h, should go to another header!
#define HEAP_GLOBAL_TAG                 0x0800
#define HEAP_PSEUDO_TAG_FLAG            0x8000
#define HEAP_TAG_MASK                  (HEAP_MAXIMUM_TAG << HEAP_TAG_SHIFT)
#define HEAP_TAGS_MASK                 (HEAP_TAG_MASK ^ (0xFF << HEAP_TAG_SHIFT))

#define HEAP_EXTRA_FLAGS_MASK (HEAP_CAPTURE_STACK_BACKTRACES | \
                               HEAP_SETTABLE_USER_VALUE | \
                               HEAP_TAGS_MASK)

/* Heap entry flags */
#define HEAP_ENTRY_BUSY           0x01
#define HEAP_ENTRY_EXTRA_PRESENT  0x02
#define HEAP_ENTRY_FILL_PATTERN   0x04
#define HEAP_ENTRY_VIRTUAL_ALLOC  0x08
#define HEAP_ENTRY_LAST_ENTRY     0x10
#define HEAP_ENTRY_SETTABLE_FLAG1 0x20
#define HEAP_ENTRY_SETTABLE_FLAG2 0x40
#define HEAP_ENTRY_SETTABLE_FLAG3 0x80
#define HEAP_ENTRY_SETTABLE_FLAGS (HEAP_ENTRY_SETTABLE_FLAG1 | HEAP_ENTRY_SETTABLE_FLAG2 | HEAP_ENTRY_SETTABLE_FLAG3)

/* Signatures */
#define HEAP_SIGNATURE         0xeefeeff
#define HEAP_SEGMENT_SIGNATURE 0xffeeffee

/* Segment flags */
#define HEAP_USER_ALLOCATED    0x1

/* A handy inline to distinguis normal heap, special "debug heap" and special "page heap" */
FORCEINLINE BOOLEAN
RtlpHeapIsSpecial(ULONG Flags)
{
    if (Flags & HEAP_SKIP_VALIDATION_CHECKS) return FALSE;

    if (Flags & (HEAP_FLAG_PAGE_ALLOCS |
                 HEAP_VALIDATE_ALL_ENABLED |
                 HEAP_VALIDATE_PARAMETERS_ENABLED |
                 HEAP_CAPTURE_STACK_BACKTRACES |
                 HEAP_CREATE_ENABLE_TRACING))
    {
        /* This is a special heap */
        return TRUE;
    }

    /* No need for a special treatment */
    return FALSE;
}

/* Heap structures */
struct _HEAP_COMMON_ENTRY
{
#ifdef _WIN64
    PVOID PreviousBlockPrivateData;
#endif
    union
    {
        struct
        {
            USHORT Size;
            UCHAR Flags;
            UCHAR SmallTagIndex;
        };
        struct
        {
#ifndef _WIN64
            PVOID SubSegmentCode;
#else
            ULONG SubSegmentCodeDummy;
#endif
            USHORT PreviousSize;
            union
            {
                UCHAR SegmentOffset;
                UCHAR LFHFlags;
            };
            UCHAR UnusedBytes;
        };
        struct
        {
            USHORT FunctionIndex;
            USHORT ContextValue;
        };
        struct
        {
            ULONG InterceptorValue;
            USHORT UnusedBytesLength;
            UCHAR EntryOffset;
            UCHAR ExtendedBlockSignature;
        };
        struct
        {
            ULONG Code1;
            USHORT Code2;
            UCHAR Code3;
            UCHAR Code4;
        };
        ULONGLONG AgregateCode;
    };
};

typedef struct _HEAP_FREE_ENTRY
{
    struct _HEAP_COMMON_ENTRY;
    LIST_ENTRY FreeList;
}  HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY;

typedef struct _HEAP_ENTRY
{
    struct _HEAP_COMMON_ENTRY;
}  HEAP_ENTRY, *PHEAP_ENTRY;

#ifdef _WIN64
C_ASSERT(sizeof(HEAP_ENTRY) == 16);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, Size) == 8);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, Flags) == 10);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, PreviousSize) == 12);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, UnusedBytes) == 15);
#else
C_ASSERT(sizeof(HEAP_ENTRY) == 8);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, Size) == 0);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, Flags) == 2);
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, PreviousSize) == sizeof(PVOID));
C_ASSERT(FIELD_OFFSET(HEAP_ENTRY, UnusedBytes) == sizeof(PVOID) + 3);
#endif
C_ASSERT((1 << HEAP_ENTRY_SHIFT) == sizeof(HEAP_ENTRY));
C_ASSERT((2 << HEAP_ENTRY_SHIFT) == sizeof(HEAP_FREE_ENTRY));

typedef struct _HEAP_TAG_ENTRY
{
    ULONG Allocs;
    ULONG Frees;
    ULONG Size;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;

typedef struct _HEAP_PSEUDO_TAG_ENTRY
{
    ULONG Allocs;
    ULONG Frees;
    SIZE_T Size;
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;

typedef struct _HEAP_COUNTERS
{
    SIZE_T TotalMemoryReserved;
    SIZE_T TotalMemoryCommitted;
    SIZE_T TotalMemoryLargeUCR;
    SIZE_T TotalSizeInVirtualBlocks;
    ULONG TotalSegments;
    ULONG TotalUCRs;
    ULONG CommittOps;
    ULONG DeCommitOps;
    ULONG LockAcquires;
    ULONG LockCollisions;
    ULONG CommitRate;
    ULONG DecommittRate;
    ULONG CommitFailures;
    ULONG InBlockCommitFailures;
    ULONG CompactHeapCalls;
    ULONG CompactedUCRs;
    ULONG InBlockDeccommits;
    SIZE_T InBlockDeccomitSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;

typedef struct _HEAP_TUNING_PARAMETERS
{
    ULONG CommittThresholdShift;
    SIZE_T MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;

typedef struct _HEAP_LIST_LOOKUP
{
    struct _HEAP_LIST_LOOKUP *ExtendedLookup;
    ULONG ArraySize;
    ULONG ExtraItem;
    ULONG ItemCount;
    ULONG OutOfRangeItems;
    ULONG BaseIndex;
    PLIST_ENTRY ListHead;
    PULONG ListsInUseUlong;
    PLIST_ENTRY *ListHints;
} HEAP_LIST_LOOKUP, *PHEAP_LIST_LOOKUP;

#define HEAP_SEGMENT_MEMBERS                \
    HEAP_ENTRY Entry;                       \
    ULONG SegmentSignature;                 \
    ULONG SegmentFlags;                     \
    LIST_ENTRY SegmentListEntry;            \
    struct _HEAP *Heap;                     \
    PVOID BaseAddress;                      \
    ULONG NumberOfPages;                    \
    PHEAP_ENTRY FirstEntry;                 \
    PHEAP_ENTRY LastValidEntry;             \
    ULONG NumberOfUnCommittedPages;         \
    ULONG NumberOfUnCommittedRanges;        \
    USHORT SegmentAllocatorBackTraceIndex;  \
    USHORT Reserved;                        \
    LIST_ENTRY UCRSegmentList

typedef struct _HEAP
{
    HEAP_SEGMENT_MEMBERS;

    ULONG Flags;
    ULONG ForceFlags;
    ULONG CompatibilityFlags;
    ULONG EncodeFlagMask;
    HEAP_ENTRY Encoding;
    ULONG_PTR PointerKey;
    ULONG Interceptor;
    ULONG VirtualMemoryThreshold;
    ULONG Signature;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T TotalFreeSize;
    SIZE_T MaximumAllocationSize;
    USHORT ProcessHeapsListIndex;
    USHORT HeaderValidateLength;
    PVOID HeaderValidateCopy;
    USHORT NextAvailableTagIndex;
    USHORT MaximumTagIndex;
    PHEAP_TAG_ENTRY TagEntries;
    LIST_ENTRY UCRList;
    LIST_ENTRY UCRSegments; // FIXME: non-Vista
    ULONG_PTR AlignRound;
    ULONG_PTR AlignMask;
    LIST_ENTRY VirtualAllocdBlocks;
    LIST_ENTRY SegmentList;
    struct _HEAP_SEGMENT *Segments[HEAP_SEGMENTS]; //FIXME: non-Vista
    USHORT AllocatorBackTraceIndex;
    ULONG NonDedicatedListLength;
    PVOID BlocksIndex; // HEAP_LIST_LOOKUP
    PVOID UCRIndex;
    PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
    LIST_ENTRY FreeLists;
    PHEAP_LOCK LockVariable;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    PVOID FrontEndHeap;
    USHORT FrontHeapLockCount;
    UCHAR FrontEndHeapType;
    HEAP_COUNTERS Counters;
    HEAP_TUNING_PARAMETERS TuningParameters;
    RTL_BITMAP FreeHintBitmap;  // FIXME: non-Vista
    PLIST_ENTRY FreeHints[ANYSIZE_ARRAY]; // FIXME: non-Vista
} HEAP, *PHEAP;

typedef struct _HEAP_SEGMENT
{
    HEAP_SEGMENT_MEMBERS;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

typedef struct _HEAP_UCR_DESCRIPTOR
{
    LIST_ENTRY ListEntry;
    LIST_ENTRY SegmentEntry;
    PVOID Address;
    SIZE_T Size;
} HEAP_UCR_DESCRIPTOR, *PHEAP_UCR_DESCRIPTOR;

typedef struct _HEAP_UCR_SEGMENT
{
    LIST_ENTRY ListEntry;
    SIZE_T ReservedSize;
    SIZE_T CommittedSize;
} HEAP_UCR_SEGMENT, *PHEAP_UCR_SEGMENT;

typedef struct _HEAP_ENTRY_EXTRA
{
     union
     {
          struct
          {
               USHORT AllocatorBackTraceIndex;
               USHORT TagIndex;
               ULONG_PTR Settable;
          };
          UINT64 ZeroInit;
     };
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;

typedef HEAP_ENTRY_EXTRA HEAP_FREE_ENTRY_EXTRA, *PHEAP_FREE_ENTRY_EXTRA;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY
{
    LIST_ENTRY Entry;
    HEAP_ENTRY_EXTRA ExtraStuff;
    SIZE_T CommitSize;
    SIZE_T ReserveSize;
    HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;

/* Heap walking: the structures of a heap are read through a routine, which makes the walker serve this process and another one */
typedef
NTSTATUS
(NTAPI *PRTLP_HEAP_READ_ROUTINE)(
    _In_opt_ PVOID Context,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size);

/* Returns FALSE to end the walk */
typedef
BOOLEAN
(NTAPI *PRTLP_HEAP_WALK_CALLBACK)(
    _In_opt_ PVOID Context,
    _In_ PRTL_HEAP_WALK_ENTRY Entry);

/* Global variables */
extern RTL_CRITICAL_SECTION RtlpProcessHeapsListLock;
extern BOOLEAN RtlpPageHeapEnabled;

/* Functions declarations */

/* heap.c */
PHEAP_FREE_ENTRY NTAPI
RtlpCoalesceFreeBlocks (PHEAP Heap,
                        PHEAP_FREE_ENTRY FreeEntry,
                        PSIZE_T FreeSize,
                        BOOLEAN Remove);

PHEAP_ENTRY_EXTRA NTAPI
RtlpGetExtraStuffPointer(PHEAP_ENTRY HeapEntry);

BOOLEAN NTAPI
RtlpValidateHeap(PHEAP Heap, BOOLEAN ForceValidation);

BOOLEAN NTAPI
RtlpValidateHeapEntry(PHEAP Heap, PHEAP_ENTRY HeapEntry);

BOOLEAN NTAPI
RtlpValidateHeapHeaders(PHEAP Heap, BOOLEAN Recalculate);

/*
 * Reports every entry of the heap at HeapAddress. Without a read routine the heap is in this process
 * and is locked for the walk. With one it is read as it is, and the caller has to watch out for changes:
 * a chain of blocks that does not add up ends the walk with STATUS_INVALID_PARAMETER.
 */
NTSTATUS NTAPI
RtlpEnumerateHeap(_In_opt_ PRTLP_HEAP_READ_ROUTINE Read,
                  _In_opt_ PVOID ReadContext,
                  _In_ PVOID HeapAddress,
                  _In_ PRTLP_HEAP_WALK_CALLBACK Callback,
                  _In_opt_ PVOID CallbackContext,
                  _Out_opt_ PULONG HeapFlags);

/* heapfe.c: small-block front end of user-mode heaps (reported as the low-fragmentation heap, type 2) */
#define HEAP_FRONTEND_CACHE     2
#define HEAP_FE_NOT_HANDLED     0
#define HEAP_FE_CACHED          1
#define HEAP_FE_INVALID         2
/* Parked bytes (all slots) above which a heap that needs room gives them back before it grows */
#define HEAP_FE_FLUSH_LIMIT     (1024 * 1024)
/* A serialized heap that its own lock made wait this often gets the front end */
#define HEAP_FE_AUTO_THRESHOLD  16

/*
 * Size classes, in heap units (HEAP_ENTRY_SIZE bytes): exact up to HEAP_FE_EXACT, then one class
 * per HEAP_FE_STEP units (64 bytes). A freed block is filed under the largest class boundary it
 * reaches, a request looks in the smallest class boundary that covers it, so a block served is
 * never smaller than the request and is less than three steps (192 bytes) larger (HeapSize still reports the
 * requested size: the surplus is kept in UnusedBytes, which holds up to 255).
 */
#define HEAP_FE_MAX_BLOCK       4096    /* bytes, header included */
#define HEAP_FE_UNITS           (HEAP_FE_MAX_BLOCK >> HEAP_ENTRY_SHIFT)
#define HEAP_FE_EXACT           16
#ifdef _WIN64
#define HEAP_FE_STEP            4
#define HEAP_FE_CLASSES         80      /* >= 16 + (255 - 16) / 4 + 1, a multiple of 8 */
#else
#define HEAP_FE_STEP            8
#define HEAP_FE_CLASSES         80      /* >= 16 + (511 - 16) / 8 + 1, a multiple of 16 */
#endif

#define HEAP_FE_CLASS_FOR_ALLOC(Units) \
    (((Units) <= HEAP_FE_EXACT) ? (Units) : HEAP_FE_EXACT + (((Units) - HEAP_FE_EXACT + HEAP_FE_STEP - 1) / HEAP_FE_STEP))
#define HEAP_FE_CLASS_FOR_FREE(Units) \
    (((Units) <= HEAP_FE_EXACT) ? (Units) : HEAP_FE_EXACT + (((Units) - HEAP_FE_EXACT) / HEAP_FE_STEP))


/* The units of the block that serves a request of Index units: the boundary of its class, so that
   every block the heap hands out for a small request files under exactly the class a later request
   of the same class looks in (blocks of other sizes would pile up in classes nobody asks for) */
FORCEINLINE
SIZE_T
RtlpHeapFeRoundIndex(SIZE_T Index)
{
    return (Index <= HEAP_FE_EXACT) ? Index :
           HEAP_FE_EXACT + (((Index - HEAP_FE_EXACT + HEAP_FE_STEP - 1) / HEAP_FE_STEP) * HEAP_FE_STEP);
}

BOOLEAN NTAPI
RtlpHeapFeEnable(PHEAP Heap);

VOID NTAPI
RtlpHeapFeDestroy(PHEAP Heap);

PHEAP_ENTRY NTAPI
RtlpHeapFeAlloc(PHEAP Heap,
                SIZE_T Index,
                SIZE_T AllocationSize,
                SIZE_T Size);

ULONG NTAPI
RtlpHeapFeFree(PHEAP Heap,
               PHEAP_ENTRY Entry);

BOOLEAN NTAPI
RtlpHeapFeIsCached(PHEAP_ENTRY Entry);

ULONG NTAPI
RtlpHeapFeFlush(PHEAP Heap);

SIZE_T NTAPI
RtlpHeapFeParked(PHEAP Heap);

ULONG NTAPI
RtlpHeapFeLock(PHEAP Heap);

VOID NTAPI
RtlpHeapFeUnlock(PHEAP Heap);

/* heap.c: give an in-use block back to the heap proper (heap lock held) */
VOID NTAPI
RtlpFreeBlockLocked(PHEAP Heap,
                    PHEAP_ENTRY HeapEntry);

/* heapdbg.c */
NTSYSAPI
HANDLE NTAPI
RtlDebugCreateHeap(ULONG Flags,
                   PVOID Addr,
                   SIZE_T TotalSize,
                   SIZE_T CommitSize,
                   PVOID Lock,
                   PRTL_HEAP_PARAMETERS Parameters);

BOOLEAN NTAPI
RtlDebugDestroyHeap(HANDLE HeapPtr);

PVOID NTAPI
RtlDebugAllocateHeap(PVOID HeapPtr,
                     ULONG Flags,
                     SIZE_T Size);

PVOID NTAPI
RtlDebugReAllocateHeap(HANDLE HeapPtr,
                       ULONG Flags,
                       PVOID Ptr,
                       SIZE_T Size);

BOOLEAN NTAPI
RtlDebugFreeHeap(HANDLE HeapPtr,
                 ULONG Flags,
                 PVOID Ptr);

BOOLEAN NTAPI
RtlDebugGetUserInfoHeap(PVOID HeapHandle,
                        ULONG Flags,
                        PVOID BaseAddress,
                        PVOID *UserValue,
                        PULONG UserFlags);

BOOLEAN NTAPI
RtlDebugSetUserValueHeap(PVOID HeapHandle,
                         ULONG Flags,
                         PVOID BaseAddress,
                         PVOID UserValue);

BOOLEAN
NTAPI
RtlDebugSetUserFlagsHeap(PVOID HeapHandle,
                         ULONG Flags,
                         PVOID BaseAddress,
                         ULONG UserFlagsReset,
                         ULONG UserFlagsSet);

SIZE_T NTAPI
RtlDebugSizeHeap(HANDLE HeapPtr,
                 ULONG Flags,
                 PVOID Ptr);

/* heappage.c */

HANDLE NTAPI
RtlpPageHeapCreate(ULONG Flags,
                   PVOID Addr,
                   SIZE_T TotalSize,
                   SIZE_T CommitSize,
                   PVOID Lock,
                   PRTL_HEAP_PARAMETERS Parameters);

PVOID NTAPI
RtlpPageHeapDestroy(HANDLE HeapPtr);

PVOID NTAPI
RtlpPageHeapAllocate(IN PVOID HeapPtr,
                     IN ULONG Flags,
                     IN SIZE_T Size);

BOOLEAN NTAPI
RtlpPageHeapFree(HANDLE HeapPtr,
                 ULONG Flags,
                 PVOID Ptr);

PVOID NTAPI
RtlpPageHeapReAllocate(HANDLE HeapPtr,
                       ULONG Flags,
                       PVOID Ptr,
                       SIZE_T Size);

BOOLEAN NTAPI
RtlpPageHeapLock(HANDLE HeapPtr);

BOOLEAN NTAPI
RtlpPageHeapUnlock(HANDLE HeapPtr);

BOOLEAN NTAPI
RtlpPageHeapGetUserInfo(PVOID HeapHandle,
                        ULONG Flags,
                        PVOID BaseAddress,
                        PVOID *UserValue,
                        PULONG UserFlags);

BOOLEAN NTAPI
RtlpPageHeapSetUserValue(PVOID HeapHandle,
                         ULONG Flags,
                         PVOID BaseAddress,
                         PVOID UserValue);

BOOLEAN
NTAPI
RtlpPageHeapSetUserFlags(PVOID HeapHandle,
                         ULONG Flags,
                         PVOID BaseAddress,
                         ULONG UserFlagsReset,
                         ULONG UserFlagsSet);

BOOLEAN
NTAPI
RtlpDebugPageHeapValidate(PVOID HeapPtr,
                          ULONG Flags,
                          PVOID Block);

SIZE_T NTAPI
RtlpPageHeapSize(HANDLE HeapPtr,
                 ULONG Flags,
                 PVOID Ptr);

VOID
NTAPI
RtlpAddHeapToProcessList(PHEAP Heap);

VOID
NTAPI
RtlpRemoveHeapFromProcessList(PHEAP Heap);

VOID
NTAPI
RtlInitializeHeapManager(VOID);

#endif
