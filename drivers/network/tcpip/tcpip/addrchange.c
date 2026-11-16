/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/addrchange.c
 * PURPOSE:     IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST and IOCTL_IP_ROUTECHANGE_NOTIFY_REQUEST: pending
 *              requests that complete when the IPv4 address table or the route table changes
 */

#include "precomp.h"

/*
 * Requests wait in a cancel-safe queue. A change of the address table (an
 * address set or deleted, an interface registered or removed, a link going
 * up or down) completes every waiting request with STATUS_SUCCESS. A
 * request completes with STATUS_CANCELLED when the caller cancels it or
 * closes the last handle of its file object (see AddrChangeCleanup).
 */

/* What a waiting request looks at: the families of the changes it waits for (TCP_CHANGE_FAMILY_*), kept with the
 * request in the first driver context field */
#define IRP_FAMILIES(Irp) ((ULONG)(ULONG_PTR)(Irp)->Tail.Overlay.DriverContext[0])

/* Which waiting requests a removal looks for: those of one file object (NULL: any) that wait for one of Families */
typedef struct _CHANGE_PEEK
{
    PFILE_OBJECT FileObject;
    ULONG Families;
} CHANGE_PEEK, *PCHANGE_PEEK;

/* One queue for the address changes, one for the route changes */
typedef struct _CHANGE_QUEUE
{
    IO_CSQ Csq;
    LIST_ENTRY List;
    KSPIN_LOCK Lock;
} CHANGE_QUEUE;

static CHANGE_QUEUE AddrChangeQueue;
static CHANGE_QUEUE RouteChangeQueue;

#define QUEUE_OF(Csq) CONTAINING_RECORD((Csq), CHANGE_QUEUE, Csq)

static
VOID
NTAPI
ChangeCsqInsertIrp(PIO_CSQ Csq, PIRP Irp)
{
    InsertTailList(&QUEUE_OF(Csq)->List, &Irp->Tail.Overlay.ListEntry);
}

static
VOID
NTAPI
ChangeCsqRemoveIrp(PIO_CSQ Csq, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static
PIRP
NTAPI
ChangeCsqPeekNextIrp(PIO_CSQ Csq, PIRP Irp, PVOID PeekContext)
{
    PLIST_ENTRY Head = &QUEUE_OF(Csq)->List;
    PLIST_ENTRY Entry;
    PIRP Next;
    PCHANGE_PEEK Peek = PeekContext;

    Entry = Irp ? Irp->Tail.Overlay.ListEntry.Flink : Head->Flink;
    for (; Entry != Head; Entry = Entry->Flink)
    {
        Next = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        if (!Peek ||
            ((!Peek->FileObject || IoGetCurrentIrpStackLocation(Next)->FileObject == Peek->FileObject) &&
             (IRP_FAMILIES(Next) & Peek->Families)))
            return Next;
    }

    return NULL;
}

static
VOID
NTAPI
ChangeCsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql)
{
    KeAcquireSpinLock(&QUEUE_OF(Csq)->Lock, Irql);
}

static
VOID
NTAPI
ChangeCsqReleaseLock(PIO_CSQ Csq, KIRQL Irql)
{
    KeReleaseSpinLock(&QUEUE_OF(Csq)->Lock, Irql);
}

static
VOID
NTAPI
ChangeCsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static
VOID
ChangeQueueInitialize(CHANGE_QUEUE *Queue)
{
    InitializeListHead(&Queue->List);
    KeInitializeSpinLock(&Queue->Lock);
    IoCsqInitialize(&Queue->Csq,
                    ChangeCsqInsertIrp,
                    ChangeCsqRemoveIrp,
                    ChangeCsqPeekNextIrp,
                    ChangeCsqAcquireLock,
                    ChangeCsqReleaseLock,
                    ChangeCsqCompleteCanceledIrp);
}

VOID
AddrChangeInitialize(VOID)
{
    ChangeQueueInitialize(&AddrChangeQueue);
    ChangeQueueInitialize(&RouteChangeQueue);
}

/* Complete the waiting requests that wait for one of the families that changed; each one is told which of its
   families it was (when its output buffer holds that) */
static
VOID
ChangeQueueNotify(CHANGE_QUEUE *Queue, ULONG Families)
{
    PIRP Irp;
    CHANGE_PEEK Peek;
    ULONG Changed;
    PIO_STACK_LOCATION IrpSp;

    Peek.FileObject = NULL;
    Peek.Families = Families;
    while ((Irp = IoCsqRemoveNextIrp(&Queue->Csq, &Peek)) != NULL)
    {
        Changed = IRP_FAMILIES(Irp) & Families;
        IrpSp = IoGetCurrentIrpStackLocation(Irp);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        if (Irp->AssociatedIrp.SystemBuffer && IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG))
        {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = Changed;
            Irp->IoStatus.Information = sizeof(ULONG);
        }
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    }
}

/* The address table of these families (TCP_CHANGE_FAMILY_*) changed; callable at IRQL <= DISPATCH_LEVEL */
VOID
AddrChangeNotifyFamilies(ULONG Families)
{
    ChangeQueueNotify(&AddrChangeQueue, Families);
}

/* The route table of these families changed (a route added or removed); callable at IRQL <= DISPATCH_LEVEL */
VOID
RouteChangeNotifyFamilies(ULONG Families)
{
    ChangeQueueNotify(&RouteChangeQueue, Families);
}

/* The most requests one file object keeps waiting, in both queues together: the pool is not charged to anyone */
#define MAX_PENDING_PER_FILE 64

static
BOOLEAN
ChangeQueueIsFull(PIRP Irp)
{
    PFILE_OBJECT FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    CHANGE_QUEUE *Queues[2] = { &AddrChangeQueue, &RouteChangeQueue };
    ULONG Count = 0, i;
    KIRQL OldIrql;
    PLIST_ENTRY Entry;

    for (i = 0; i < 2; i++)
    {
        KeAcquireSpinLock(&Queues[i]->Lock, &OldIrql);
        for (Entry = Queues[i]->List.Flink; Entry != &Queues[i]->List; Entry = Entry->Flink)
        {
            PIRP Pending = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

            if (IoGetCurrentIrpStackLocation(Pending)->FileObject == FileObject)
                Count++;
        }
        KeReleaseSpinLock(&Queues[i]->Lock, OldIrql);
    }

    return Count >= MAX_PENDING_PER_FILE;
}

/* The families a request waits for: its input ULONG, IPv4 alone without one */
static
NTSTATUS
ChangeRequestFamilies(PIRP Irp, PULONG Families)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    *Families = TCP_CHANGE_FAMILY_IPV4;
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength != 0)
    {
        if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) || !Irp->AssociatedIrp.SystemBuffer)
            return STATUS_INVALID_PARAMETER;
        *Families = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        if (*Families == 0 || (*Families & ~(TCP_CHANGE_FAMILY_IPV4 | TCP_CHANGE_FAMILY_IPV6)))
            return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
ChangeQueueRequest(CHANGE_QUEUE *Queue, PIRP Irp)
{
    ULONG Families;
    NTSTATUS Status;

    Status = ChangeRequestFamilies(Irp, &Families);
    if (!NT_SUCCESS(Status))
        return Status;
    if (ChangeQueueIsFull(Irp))
        return STATUS_INSUFFICIENT_RESOURCES;

    /* A plain pend: the IRP is completed by the next change of one of its families */
    Irp->IoStatus.Information = 0;
    Irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)Families;
    IoCsqInsertIrp(&Queue->Csq, Irp, NULL);
    return STATUS_PENDING;
}

/* IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST: queue the request until the next change */
NTSTATUS
DispAddrChangeNotifyRequest(PIRP Irp)
{
    return ChangeQueueRequest(&AddrChangeQueue, Irp);
}

/* IOCTL_IP_ROUTECHANGE_NOTIFY_REQUEST: queue the request until the next route change */
NTSTATUS
DispRouteChangeNotifyRequest(PIRP Irp)
{
    return ChangeQueueRequest(&RouteChangeQueue, Irp);
}

/* Cancel the waiting requests of one file object, in both queues; returns how many */
static
ULONG
AddrChangeCancelFile(PFILE_OBJECT FileObject)
{
    PIRP Pending;
    ULONG Count = 0;
    CHANGE_QUEUE *Queues[2] = { &AddrChangeQueue, &RouteChangeQueue };
    ULONG i;
    CHANGE_PEEK Peek;

    Peek.FileObject = FileObject;
    Peek.Families = TCP_CHANGE_FAMILY_IPV4 | TCP_CHANGE_FAMILY_IPV6;
    for (i = 0; i < 2; i++)
    {
        while ((Pending = IoCsqRemoveNextIrp(&Queues[i]->Csq, &Peek)) != NULL)
        {
            Pending->IoStatus.Status = STATUS_CANCELLED;
            Pending->IoStatus.Information = 0;
            IoCompleteRequest(Pending, IO_NO_INCREMENT);
            Count++;
        }
    }

    return Count;
}

/* IOCTL_IP_ADDCHANGE_CANCEL_REQUEST: lets any thread cancel, which CancelIo cannot */
NTSTATUS
DispAddrChangeCancelRequest(PIRP Irp)
{
    Irp->IoStatus.Information = 0;
    AddrChangeCancelFile(IoGetCurrentIrpStackLocation(Irp)->FileObject);
    return STATUS_SUCCESS;
}

/* IRP_MJ_CLEANUP: the last handle of a file object closed; cancel its waiting requests */
NTSTATUS
NTAPI
TiDispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    AddrChangeCancelFile(IoGetCurrentIrpStackLocation(Irp)->FileObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
