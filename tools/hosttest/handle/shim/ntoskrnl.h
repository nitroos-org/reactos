/*
 * PROJECT:     ReactOS host-native test harness (handle table)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Minimal type/primitive shims so the REAL ntoskrnl/ex/handle.c
 *              compiles with a host gcc. Picked up via -I before the tree,
 *              so handle.c's #include <ntoskrnl.h> resolves here.
 *
 * Model: one host pthread == one CPU. KeGetCurrentProcessorNumber() returns the
 * thread's CPU id; raising IRQL is a no-op (a thread is never preempted by a
 * "DPC" on its own CPU, so this harness cannot see IRQL/DPC reentrancy).
 * Struct layouts below are copies of sdk/include/ndk/extypes.h (XP-era
 * layout) and ntoskrnl/include/internal/ex.h; hostcheck in main verifies the
 * sizes the algorithm depends on.
 */
#ifndef HOSTTEST_NTOSKRNL_H
#define HOSTTEST_NTOSKRNL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>

#ifndef __x86_64__
#error host harness is 64-bit only (ULONG_PTR bitfield layout)
#endif
#define _WIN64 1

#define NTAPI
#define IN
#define OUT
#define OPTIONAL
#define VOID void
#define CODE_SEG(x)
#define PAGED_CODE()
#define FORCEINLINE static inline __attribute__((always_inline))
#define C_ASSERT(e) _Static_assert(e, #e)
#define FALSE 0
#define TRUE 1
#define NDEBUG_UNUSED

typedef void *PVOID;
typedef void *HANDLE, **PHANDLE;
typedef unsigned char UCHAR, BOOLEAN;
typedef unsigned short USHORT;
typedef uint32_t ULONG, *PULONG;
typedef int32_t LONG, *PLONG, NTSTATUS;
typedef uint64_t ULONG_PTR, SIZE_T;
typedef int64_t LONG_PTR;
typedef unsigned char KIRQL;
typedef wchar_t WCHAR;
#define LONG_MAX_UNUSED
#define NT_SUCCESS(s) ((s) >= 0)
#define STATUS_SUCCESS 0
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define ROS_PS_MAX_HANDLE_COUNT 0x1000000
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define TAG_OBJECT_TABLE 1
#define TAG_HANDLE_CPU_CACHE 2
#define ANYSIZE_ARRAY 1
#define ASSERT(e) do { if (!(e)) { fprintf(stderr, "ASSERT FAILED %s:%d: %s\n", __FILE__, __LINE__, #e); abort(); } } while (0)
#define DPRINT(...)
#define DPRINT1(...)
#define NDEBUG

typedef enum { NonPagedPool = 0, PagedPool = 1 } POOL_TYPE;

typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY;
static inline void InitializeListHead(LIST_ENTRY *h) { h->Flink = h->Blink = h; }
static inline void InsertTailList(LIST_ENTRY *h, LIST_ENTRY *e) { LIST_ENTRY *b = h->Blink; e->Flink = h; e->Blink = b; b->Flink = e; h->Blink = e; }
static inline void RemoveEntryList(LIST_ENTRY *e) { e->Blink->Flink = e->Flink; e->Flink->Blink = e->Blink; }

typedef struct _EPROCESS { HANDLE UniqueProcessId; } EPROCESS, *PEPROCESS;
typedef struct _KTHREAD { ULONG CombinedApcDisable; } KTHREAD, *PKTHREAD;
extern EPROCESS HostProcess;
extern KTHREAD HostThread;
#define PsGetCurrentProcess() (&HostProcess)
#define KeGetCurrentThread() (&HostThread)
#define KeGetCurrentIrql() APC_LEVEL

/* Push lock: Locked bit is set whenever held (exclusive or shared), as the real one. */
typedef struct _EX_PUSH_LOCK { volatile ULONG_PTR Value; } EX_PUSH_LOCK_RAW;
typedef struct _EX_PUSH_LOCK_S
{
    union {
        struct { ULONG_PTR Locked:1; ULONG_PTR Waiting:1; ULONG_PTR Waking:1; ULONG_PTR MultipleShared:1; ULONG_PTR Shared:60; };
        volatile ULONG_PTR Value;
    };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;
typedef struct _EX_PUSH_LOCK_WAIT_BLOCK { int dummy; } EX_PUSH_LOCK_WAIT_BLOCK;
#define PL_SHARED_ONE ((ULONG_PTR)16)
static inline void ExInitializePushLock(PEX_PUSH_LOCK l) { l->Value = 0; }
static inline void ExAcquirePushLockExclusive(PEX_PUSH_LOCK l)
{ for (;;) { if (__sync_bool_compare_and_swap(&l->Value, 0, 1)) return; sched_yield(); } }
static inline void ExReleasePushLockExclusive(PEX_PUSH_LOCK l) { __sync_lock_release(&l->Value); }
static inline void ExAcquirePushLockShared(PEX_PUSH_LOCK l)
{
    for (;;)
    {
        ULONG_PTR v = l->Value;
        /* free, or already held shared (Locked set, share count > 0) */
        if (v == 0 || (v & 1 && (v >> 4) != 0))
        {
            ULONG_PTR n = (v | 1) + PL_SHARED_ONE;
            if (__sync_bool_compare_and_swap(&l->Value, v, n)) return;
        }
        else sched_yield();
    }
}
static inline void ExReleasePushLockShared(PEX_PUSH_LOCK l)
{
    for (;;)
    {
        ULONG_PTR v = l->Value, n = v - PL_SHARED_ONE;
        if ((n >> 4) == 0) n = 0;
        if (__sync_bool_compare_and_swap(&l->Value, v, n)) return;
    }
}
static inline void ExWaitOnPushLock(PEX_PUSH_LOCK l) { ExAcquirePushLockExclusive(l); ExReleasePushLockExclusive(l); }
static inline void ExBlockPushLock(PEX_PUSH_LOCK l, EX_PUSH_LOCK_WAIT_BLOCK *w) { (void)l; (void)w; }
static inline void ExfUnblockPushLock(PEX_PUSH_LOCK l, EX_PUSH_LOCK_WAIT_BLOCK *w) { (void)l; (void)w; }
static inline void ExWaitForUnblockPushLock(PEX_PUSH_LOCK l, EX_PUSH_LOCK_WAIT_BLOCK *w) { (void)l; (void)w; sched_yield(); }

/* Interlocked */
#define InterlockedCompareExchange(p, x, c) __sync_val_compare_and_swap((p), (c), (x))
#define InterlockedCompareExchangePointer(p, x, c) __sync_val_compare_and_swap((p), (c), (x))
#define InterlockedIncrement(p) __sync_add_and_fetch((p), 1)
#define InterlockedDecrement(p) __sync_sub_and_fetch((p), 1)
#define InterlockedExchange(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedExchangeAdd(p, v) __sync_fetch_and_add((p), (v))
#define InterlockedOr(p, v) __sync_fetch_and_or((p), (v))
#define InterlockedExchangePointer(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)

#define RtlZeroMemory(d, n) memset((d), 0, (n))
#define RtlCopyMemory(d, s, n) memcpy((d), (s), (n))

/* Pool: plain heap; fault-injection hook lets tests exercise failure paths */
extern int HostPoolFailAfter; /* -1 = never; else fail when this many allocs remain */
PVOID ExAllocatePoolWithTag(POOL_TYPE t, SIZE_T n, ULONG tag);
void ExFreePoolWithTag(PVOID p, ULONG tag);
static inline NTSTATUS PsChargeProcessPagedPoolQuota(PEPROCESS p, SIZE_T n) { (void)p; (void)n; return STATUS_SUCCESS; }
static inline void PsReturnProcessPagedPoolQuota(PEPROCESS p, SIZE_T n) { (void)p; (void)n; }

/* CPU model */
extern ULONG KeNumberProcessors;
ULONG KeGetCurrentProcessorNumber(void);
static inline void KeEnterCriticalRegion(void) {}
static inline void KeLeaveCriticalRegion(void) {}
static inline KIRQL KeRaiseIrqlToDpcLevel(void) { return APC_LEVEL; }
static inline void KeLowerIrql(KIRQL i) { (void)i; }

/* Handle table types (copies of ndk/extypes.h + internal/ex.h) */
typedef struct _HANDLE_TABLE_ENTRY_INFO { ULONG AuditMask; } HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;
typedef struct _HANDLE_TABLE_ENTRY
{
    union { PVOID Object; ULONG_PTR ObAttributes; PHANDLE_TABLE_ENTRY_INFO InfoTable; ULONG_PTR Value; };
    union { ULONG GrantedAccess; struct { USHORT GrantedAccessIndex; USHORT CreatorBackTraceIndex; }; LONG NextFreeTableEntry; };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
typedef struct _HANDLE_TRACE_DEBUG_INFO HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;
typedef struct _HANDLE_TABLE
{
    ULONG_PTR TableCode;
    PEPROCESS QuotaProcess;
    PVOID UniqueProcessId;
    EX_PUSH_LOCK HandleTableLock[4];
    LIST_ENTRY HandleTableList;
    EX_PUSH_LOCK HandleContentionEvent;
    PHANDLE_TRACE_DEBUG_INFO DebugInfo;
    LONG ExtraInfoPages;
    ULONG FirstFree;
    ULONG LastFree;
    ULONG NextHandleNeedingPool;
    LONG HandleCount;
    union { ULONG Flags; UCHAR StrictFIFO:1; };
    PVOID PerCpuFreeCache;
    ULONG PerCpuFreeCacheCount;
} HANDLE_TABLE, *PHANDLE_TABLE;

#define HANDLE_LOW_BITS     (PAGE_SHIFT - 4)
#define HANDLE_HIGH_BITS    (PAGE_SHIFT - 3)
#define HANDLE_TAG_BITS     2
#define HANDLE_INDEX_BITS   (HANDLE_LOW_BITS + 2 * HANDLE_HIGH_BITS)
#define KERNEL_FLAG_BITS    (sizeof(ULONG_PTR) * 8 - HANDLE_INDEX_BITS - HANDLE_TAG_BITS)
typedef union _EXHANDLE
{
    struct { ULONG_PTR TagBits:HANDLE_TAG_BITS; ULONG_PTR Index:HANDLE_INDEX_BITS; ULONG_PTR KernelFlag:KERNEL_FLAG_BITS; };
    struct { ULONG_PTR TagBits2:HANDLE_TAG_BITS; ULONG_PTR LowIndex:HANDLE_LOW_BITS; ULONG_PTR MidIndex:HANDLE_HIGH_BITS; ULONG_PTR HighIndex:HANDLE_HIGH_BITS; ULONG_PTR KernelFlag2:KERNEL_FLAG_BITS; };
    HANDLE GenericHandleOverlay;
    ULONG_PTR Value;
    ULONG AsULONG;
} EXHANDLE, *PEXHANDLE;

#define EXHANDLE_TABLE_ENTRY_LOCK_BIT    1
#define FREE_HANDLE_MASK                -1
#define EX_HANDLE_CACHE_LINE        64
#define EX_HANDLE_CACHE_CAPACITY    ((EX_HANDLE_CACHE_LINE / sizeof(ULONG)) - 1)
#define EX_HANDLE_CACHE_REFILL_BATCH    8
#define EX_HANDLE_CACHE_FLUSH_BATCH     8
typedef struct _EX_HANDLE_CPU_CACHE { ULONG Count; ULONG Handles[EX_HANDLE_CACHE_CAPACITY]; } EX_HANDLE_CPU_CACHE, *PEX_HANDLE_CPU_CACHE;
C_ASSERT(sizeof(EX_HANDLE_CPU_CACHE) == EX_HANDLE_CACHE_LINE);
#define EX_HANDLE_CACHE_BASE(ht) \
    ((PEX_HANDLE_CPU_CACHE)(((ULONG_PTR)(ht)->PerCpuFreeCache + (EX_HANDLE_CACHE_LINE - 1)) & ~((ULONG_PTR)EX_HANDLE_CACHE_LINE - 1)))
#define EX_HANDLE_CACHE_SLOT(ht, cpu)   (&EX_HANDLE_CACHE_BASE(ht)[(cpu)])
#define LOW_LEVEL_ENTRIES   (PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
#define MID_LEVEL_ENTRIES   (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))
#define HIGH_LEVEL_ENTRIES  (ROS_PS_MAX_HANDLE_COUNT / (LOW_LEVEL_ENTRIES * MID_LEVEL_ENTRIES))
#define MAX_LOW_INDEX       LOW_LEVEL_ENTRIES
#define MAX_MID_INDEX       (MID_LEVEL_ENTRIES * LOW_LEVEL_ENTRIES)

typedef BOOLEAN (NTAPI *PEX_SWEEP_HANDLE_CALLBACK)(PHANDLE_TABLE_ENTRY, HANDLE, PVOID);
typedef BOOLEAN (NTAPI *PEX_DUPLICATE_HANDLE_CALLBACK)(PEPROCESS, PHANDLE_TABLE, PHANDLE_TABLE_ENTRY, PHANDLE_TABLE_ENTRY);
typedef BOOLEAN (NTAPI *PEX_CHANGE_HANDLE_CALLBACK)(PHANDLE_TABLE_ENTRY, ULONG_PTR);
typedef BOOLEAN (NTAPI *PEX_ENUM_HANDLE_CALLBACK)(PHANDLE_TABLE_ENTRY, HANDLE, PVOID);

/* Functions under test (defined by the real handle.c) */
PHANDLE_TABLE NTAPI ExCreateHandleTable(PEPROCESS Process);
HANDLE NTAPI ExCreateHandle(PHANDLE_TABLE t, PHANDLE_TABLE_ENTRY e);
BOOLEAN NTAPI ExDestroyHandle(PHANDLE_TABLE t, HANDLE h, PHANDLE_TABLE_ENTRY e);
VOID NTAPI ExDestroyHandleTable(PHANDLE_TABLE t, PVOID proc);
PHANDLE_TABLE_ENTRY NTAPI ExMapHandleToPointer(PHANDLE_TABLE t, HANDLE h);
VOID NTAPI ExUnlockHandleTableEntry(PHANDLE_TABLE t, PHANDLE_TABLE_ENTRY e);
PHANDLE_TABLE_ENTRY NTAPI ExpLookupHandleTableEntry(PHANDLE_TABLE t, EXHANDLE h);
PHANDLE_TABLE NTAPI ExpAllocateHandleTable(PEPROCESS Process, BOOLEAN NewTable);

#endif
