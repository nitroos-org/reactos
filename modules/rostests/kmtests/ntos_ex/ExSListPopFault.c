/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite: concurrent interlocked S-list pops of
 *              entries whose memory is freed (and unmapped) by the popper
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Pop reads the Next pointer of the first entry after it loaded the list
 * header. When another processor pops that entry in between and frees it,
 * and the memory gets unmapped, the read faults. That is not an error: the
 * header changed, so the pop must simply start over. Without that the system
 * stops with PAGE_FAULT_IN_NONPAGED_AREA inside the pop. The kernel has such
 * a list itself: the dead kernel stacks, popped at thread creation, freed
 * (and unmapped) by the exit of a thread that popped one before.
 *
 * The entries here are pages mapped into system space and unmapped when
 * freed. The consumers (every processor but 0) pop an entry, free it,
 * allocate a new one and push it, as fast as they can, and queue a DPC for
 * processor 0 each time. The popper on processor 0 pops and pushes back the
 * same entry in a tight loop, so most of its time is spent between the two
 * reads; the DPC stalls it there, as an interrupt (or a vm exit in a virtual
 * machine) does in real use, long enough for a consumer to pop and free the
 * entry the popper is about to read. The list keeps ENTRY_COUNT entries, so
 * the test also checks that none got lost.
 */

#define MAX_WORKERS     4
#define ENTRY_COUNT     8
#define ITERATIONS      100000
#define STALL_US        20

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _ENTRY
{
    SLIST_ENTRY Link;
    PMDL Mdl;
} ENTRY, *PENTRY;

static
PENTRY
AllocEntry(VOID)
{
    PHYSICAL_ADDRESS Low, High, Skip;
    PMDL Mdl;
    PENTRY Entry;

    Low.QuadPart = 0;
    High.QuadPart = -1;
    Skip.QuadPart = 0;
    Mdl = MmAllocatePagesForMdl(Low, High, Skip, PAGE_SIZE);
    if (!Mdl)
        return NULL;
    if (MmGetMdlByteCount(Mdl) < PAGE_SIZE)
        goto Fail;
    Entry = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!Entry)
        goto Fail;
    Entry->Mdl = Mdl;
    return Entry;

Fail:
    MmFreePagesFromMdl(Mdl);
    ExFreePool(Mdl);
    return NULL;
}

static
VOID
FreeEntry(
    _In_ PENTRY Entry)
{
    PMDL Mdl = Entry->Mdl;

    MmUnmapLockedPages(Entry, Mdl);
    MmFreePagesFromMdl(Mdl);
    ExFreePool(Mdl);
}

typedef struct _WORKER
{
    HANDLE Handle;
    ULONG Processor;
    ULONG Iterations;
    ULONG Failed;
} WORKER;

static SLIST_HEADER ListHead;
static WORKER Workers[MAX_WORKERS];
static volatile LONG Started;
static volatile LONG Go;
static volatile LONG Stop;
static volatile LONG ConsumersLeft;
static ULONG PopperIterations;
static volatile LONG StallCount;
static volatile LONG UnmappedCount;
static KDPC StallDpc;

static
VOID
NTAPI
StallDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    InterlockedIncrement(&StallCount);
    KeStallExecutionProcessor(STALL_US);
}

static
VOID
NTAPI
PopperThread(
    _In_ PVOID Context)
{
    PSLIST_ENTRY Entry;

    UNREFERENCED_PARAMETER(Context);
    KeSetSystemAffinityThread(1);
    InterlockedIncrement(&Started);
    while (!Go)
        YieldProcessor();

    while (!Stop)
    {
        Entry = InterlockedPopEntrySList(&ListHead);
        if (!Entry)
            continue;
        InterlockedPushEntrySList(&ListHead, Entry);
        PopperIterations++;
    }

    KeRevertToUserAffinityThread();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
NTAPI
WorkerThread(
    _In_ PVOID Context)
{
    WORKER *Worker = Context;
    PSLIST_ENTRY Entry;
    ULONG i;

    KeSetSystemAffinityThread((KAFFINITY)1 << Worker->Processor);
    InterlockedIncrement(&Started);
    while (!Go)
        YieldProcessor();

    for (i = 0; i < ITERATIONS; i++)
    {
        Entry = InterlockedPopEntrySList(&ListHead);
        if (!Entry)
            continue;
        FreeEntry((PENTRY)Entry);
        if (!MmIsAddressValid(Entry))
            InterlockedIncrement(&UnmappedCount);
        KeInsertQueueDpc(&StallDpc, NULL, NULL);

        Entry = &AllocEntry()->Link;
        if (!Entry)
        {
            Worker->Failed++;
            continue;
        }
        InterlockedPushEntrySList(&ListHead, Entry);
        Worker->Iterations++;
    }

    KeRevertToUserAffinityThread();
    InterlockedDecrement(&ConsumersLeft);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

START_TEST(ExSListPopFault)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    ULONG ConsumerCount = min(KeNumberProcessors, MAX_WORKERS + 1) - 1;
    ULONG i, Count = 0, Total = 0;
    PSLIST_ENTRY Entry;
    LARGE_INTEGER Timeout;
    HANDLE PopperHandle;

    if (skip(ConsumerCount >= 1, "Needs two processors\n"))
        return;

    InitializeSListHead(&ListHead);
    KeInitializeDpc(&StallDpc, StallDpcRoutine, NULL);
    KeSetTargetProcessorDpc(&StallDpc, 0);
    for (i = 0; i < ENTRY_COUNT; i++)
    {
        Entry = &AllocEntry()->Link;
        if (!Entry)
            break;
        InterlockedPushEntrySList(&ListHead, Entry);
    }
    ok_eq_ulong(i, (ULONG)ENTRY_COUNT);
    Started = 0;
    Go = 0;
    Stop = 0;
    PopperIterations = 0;
    StallCount = 0;
    UnmappedCount = 0;
    ConsumersLeft = (LONG)ConsumerCount;
    RtlZeroMemory(Workers, sizeof(Workers));

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(&PopperHandle, SYNCHRONIZE, &ObjectAttributes,
                                  NULL, NULL, PopperThread, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    for (i = 0; i < ConsumerCount; i++)
    {
        Workers[i].Processor = i + 1;
        InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = PsCreateSystemThread(&Workers[i].Handle, SYNCHRONIZE, &ObjectAttributes,
                                      NULL, NULL, WorkerThread, &Workers[i]);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            break;
    }
    ConsumersLeft -= (LONG)(ConsumerCount - i);
    ConsumerCount = i;

    Timeout.QuadPart = -10 * 1000 * 10;
    while (Started < (LONG)ConsumerCount + 1)
        KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

    Go = 1;

    for (i = 0; i < ConsumerCount; i++)
    {
        Status = ZwWaitForSingleObject(Workers[i].Handle, FALSE, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ZwClose(Workers[i].Handle);
        ok_eq_ulong(Workers[i].Failed, 0UL);
        Total += Workers[i].Iterations;
    }
    KeFlushQueuedDpcs();
    Stop = 1;
    Status = ZwWaitForSingleObject(PopperHandle, FALSE, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ZwClose(PopperHandle);

    /* Nothing got lost: the list still holds all its entries */
    while ((Entry = InterlockedPopEntrySList(&ListHead)) != NULL)
    {
        Count++;
        FreeEntry((PENTRY)Entry);
    }
    ok_eq_ulong(Count, (ULONG)ENTRY_COUNT);
    trace("%lu consumers, %lu replaced entries (%ld of them unmapped when freed), %lu popper iterations, %ld stalls\n",
          ConsumerCount, Total, UnmappedCount, PopperIterations, StallCount);
}
