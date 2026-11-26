/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            lib/drivers/chew/workqueue.c
 * PURPOSE:         Common Highlevel Executive Worker
 *
 * PROGRAMMERS:     arty (ayerkes@speakeasy.net)
 */

#include <wdm.h>

#include <chew.h>

#define FOURCC(w,x,y,z) (((w) << 24) | ((x) << 16) | ((y) << 8) | (z))
#define CHEW_TAG FOURCC('C','H','E','W')

PDEVICE_OBJECT WorkQueueDevice;
LIST_ENTRY     WorkQueue;
KSPIN_LOCK     WorkQueueLock;
KEVENT         WorkQueueClear;
PIO_WORKITEM   ReserveWorkItem;
LIST_ENTRY     ReserveQueue;
BOOLEAN        ReserveRunning;

typedef struct _WORK_ITEM
{
    LIST_ENTRY Entry;
    PIO_WORKITEM WorkItem;
    VOID (*Worker)(PVOID WorkerContext);
    PVOID WorkerContext;
} WORK_ITEM, *PWORK_ITEM;

NTSTATUS ChewInit(PDEVICE_OBJECT DeviceObject)
{
    WorkQueueDevice = DeviceObject;
    InitializeListHead(&WorkQueue);
    InitializeListHead(&ReserveQueue);
    KeInitializeSpinLock(&WorkQueueLock);
    KeInitializeEvent(&WorkQueueClear, NotificationEvent, TRUE);

    ReserveWorkItem = IoAllocateWorkItem(DeviceObject);
    return ReserveWorkItem ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

VOID ChewWaitIdle(VOID)
{
    KeWaitForSingleObject(&WorkQueueClear, Executive, KernelMode, FALSE, NULL);
}

VOID ChewShutdown(VOID)
{
    ChewWaitIdle();

    if (ReserveWorkItem)
    {
        IoFreeWorkItem(ReserveWorkItem);
        ReserveWorkItem = NULL;
    }
}

VOID NTAPI ChewWorkItem(PDEVICE_OBJECT DeviceObject, PVOID ChewItem)
{
    PWORK_ITEM WorkItem = ChewItem;
    KIRQL OldIrql;

    WorkItem->Worker(WorkItem->WorkerContext);

    IoFreeWorkItem(WorkItem->WorkItem);

    KeAcquireSpinLock(&WorkQueueLock, &OldIrql);
    RemoveEntryList(&WorkItem->Entry);

    if (IsListEmpty(&WorkQueue) && !ReserveRunning)
        KeSetEvent(&WorkQueueClear, 0, FALSE);

    KeReleaseSpinLock(&WorkQueueLock, OldIrql);

    ExFreePoolWithTag(WorkItem, CHEW_TAG);
}

static VOID NTAPI ChewReservedWorkItem(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PCHEW_RESERVED_ITEM Item;
    KIRQL OldIrql;

    for (;;)
    {
        KeAcquireSpinLock(&WorkQueueLock, &OldIrql);

        if (IsListEmpty(&ReserveQueue))
        {
            ReserveRunning = FALSE;
            if (IsListEmpty(&WorkQueue))
                KeSetEvent(&WorkQueueClear, 0, FALSE);
            KeReleaseSpinLock(&WorkQueueLock, OldIrql);
            return;
        }

        Item = CONTAINING_RECORD(RemoveHeadList(&ReserveQueue), CHEW_RESERVED_ITEM, Entry);
        KeReleaseSpinLock(&WorkQueueLock, OldIrql);

        /* The worker may free the item's storage */
        Item->Worker(Item->WorkerContext);
    }
}

VOID ChewQueueReserved(PCHEW_RESERVED_ITEM Item, VOID (*Worker)(PVOID), PVOID WorkerContext)
{
    KIRQL OldIrql;
    BOOLEAN Start;

    Item->Worker = Worker;
    Item->WorkerContext = WorkerContext;

    KeAcquireSpinLock(&WorkQueueLock, &OldIrql);
    InsertTailList(&ReserveQueue, &Item->Entry);
    Start = !ReserveRunning;
    ReserveRunning = TRUE;
    KeClearEvent(&WorkQueueClear);
    KeReleaseSpinLock(&WorkQueueLock, OldIrql);

    /* One run drains the queue; the work item is queued again only after that run ended */
    if (Start)
        IoQueueWorkItem(ReserveWorkItem, ChewReservedWorkItem, DelayedWorkQueue, NULL);
}

BOOLEAN ChewCreate(VOID (*Worker)(PVOID), PVOID WorkerContext)
{
    PWORK_ITEM Item;
    Item = ExAllocatePoolWithTag(NonPagedPool,
                                 sizeof(WORK_ITEM),
                                 CHEW_TAG);

    if (Item)
    {
        Item->WorkItem = IoAllocateWorkItem(WorkQueueDevice);
        if (!Item->WorkItem)
        {
            ExFreePool(Item);
            return FALSE;
        }

        Item->Worker = Worker;
        Item->WorkerContext = WorkerContext;
        ExInterlockedInsertTailList(&WorkQueue, &Item->Entry, &WorkQueueLock);
        KeClearEvent(&WorkQueueClear);
        IoQueueWorkItem(Item->WorkItem, ChewWorkItem, DelayedWorkQueue, Item);

        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/* Entries one run of a serial queue's work item handles before it lets other work items run */
#define CHEW_SERIAL_BATCH 64

static VOID NTAPI ChewSerialWorkItem(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PCHEW_SERIAL_QUEUE Queue = Context;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    ULONG Handled;

    for (Handled = 0; ; Handled++)
    {
        KeAcquireSpinLock(&Queue->Lock, &OldIrql);

        if (IsListEmpty(&Queue->List))
        {
            Queue->Running = FALSE;
            KeSetEvent(&Queue->Idle, IO_NO_INCREMENT, FALSE);
            KeReleaseSpinLock(&Queue->Lock, OldIrql);
            return;
        }

        if (Handled == CHEW_SERIAL_BATCH)
        {
            /* Still running: nobody else queues the work item, so the order is kept */
            KeReleaseSpinLock(&Queue->Lock, OldIrql);
            IoQueueWorkItem(Queue->WorkItem, ChewSerialWorkItem, DelayedWorkQueue, Queue);
            return;
        }

        Entry = RemoveHeadList(&Queue->List);
        Queue->Count--;
        KeReleaseSpinLock(&Queue->Lock, OldIrql);

        Queue->Worker(Entry);
    }
}

BOOLEAN ChewSerialInit(PCHEW_SERIAL_QUEUE Queue, VOID (*Worker)(PLIST_ENTRY Entry), ULONG Limit)
{
    Queue->WorkItem = IoAllocateWorkItem(WorkQueueDevice);
    if (!Queue->WorkItem)
        return FALSE;

    KeInitializeSpinLock(&Queue->Lock);
    InitializeListHead(&Queue->List);
    Queue->Worker = Worker;
    Queue->Count = 0;
    Queue->Limit = Limit;
    Queue->Inserted = 0;
    Queue->Running = FALSE;
    Queue->Closed = FALSE;
    KeInitializeEvent(&Queue->Idle, NotificationEvent, TRUE);

    return TRUE;
}

BOOLEAN ChewSerialInsert(PCHEW_SERIAL_QUEUE Queue, PLIST_ENTRY Entry)
{
    return ChewSerialInsertTicket(Queue, Entry, NULL);
}

BOOLEAN ChewSerialInsertTicket(PCHEW_SERIAL_QUEUE Queue, PLIST_ENTRY Entry, PULONG Ticket)
{
    KIRQL OldIrql;
    BOOLEAN Start = FALSE;

    KeAcquireSpinLock(&Queue->Lock, &OldIrql);

    if (Queue->Closed || Queue->Count >= Queue->Limit)
    {
        KeReleaseSpinLock(&Queue->Lock, OldIrql);
        return FALSE;
    }

    InsertTailList(&Queue->List, Entry);
    Queue->Count++;
    Queue->Inserted++;
    if (Ticket)
        *Ticket = Queue->Inserted;
    if (!Queue->Running)
    {
        Queue->Running = TRUE;
        KeClearEvent(&Queue->Idle);
        Start = TRUE;
    }

    KeReleaseSpinLock(&Queue->Lock, OldIrql);

    if (Start)
        IoQueueWorkItem(Queue->WorkItem, ChewSerialWorkItem, DelayedWorkQueue, Queue);

    return TRUE;
}

VOID ChewSerialRundown(PCHEW_SERIAL_QUEUE Queue)
{
    KIRQL OldIrql;

    if (!Queue->WorkItem)
        return;

    KeAcquireSpinLock(&Queue->Lock, &OldIrql);
    Queue->Closed = TRUE;
    KeReleaseSpinLock(&Queue->Lock, OldIrql);

    KeWaitForSingleObject(&Queue->Idle, Executive, KernelMode, FALSE, NULL);

    /* The worker sets Idle under the lock; once we hold the lock it has released it for good */
    KeAcquireSpinLock(&Queue->Lock, &OldIrql);
    ASSERT(!Queue->Running && IsListEmpty(&Queue->List));
    KeReleaseSpinLock(&Queue->Lock, OldIrql);

    IoFreeWorkItem(Queue->WorkItem);
    Queue->WorkItem = NULL;
}
