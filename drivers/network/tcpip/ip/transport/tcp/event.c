/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        transport/tcp/event.c
 * PURPOSE:     Transmission Control Protocol
 * PROGRAMMERS: Cameron Gutman (cameron.gutman@reactos.org)
 */

#include "precomp.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/api.h"

#include <lwip_glue/lwip_glue.h>

extern NPAGED_LOOKASIDE_LIST TdiBucketLookasideList;

static
VOID
BucketCompletionWorker(PVOID Context)
{
    PTDI_BUCKET Bucket = (PTDI_BUCKET)Context;
    PTCP_COMPLETION_ROUTINE Complete;

    Complete = (PTCP_COMPLETION_ROUTINE)Bucket->Request.RequestNotifyObject;

    Complete(Bucket->Request.RequestContext, Bucket->Status, Bucket->Information);

    DereferenceObject(Bucket->AssociatedEndpoint);

    ExFreeToNPagedLookasideList(&TdiBucketLookasideList, Bucket);
}

/* Completions made under the lwIP core lock. The core lock is not recursive and a completion
 * routine (AFD) can start the next request at once, which takes the lock again, so the buckets wait
 * here (under the core lock) and sys_unlock_tcpip_core completes them once it has released the lock:
 * on the thread that made them, with no work item and no thread wake. */
static LIST_ENTRY DeferredCompletions;

/* Threads inside the receive worker (datalink/lan.c). It is one stage of a pipeline: what it
 * completes inline (AFD copies data to the reader and posts the next receive) delays the packets
 * behind it, which the same completions on other CPUs do not (HTTP download from the host:
 * 97 -> 68 MB/s with inline completion), so its completions go to work items */
static volatile LONG ReceiveWorkers;

/* Threads that declared themselves a lock-free context (the loopback worker). A completion runs inline
 * only on such a thread: a thread that is inside AFD or TDI (a send, a connect, a listen) holds the AFD
 * mutex of its socket, and AFD's completion of another socket takes that socket's mutex, so two threads
 * could wait for each other's. The worker holds nothing when it unlocks the core. */
#define INLINE_SLOTS 8
static PKTHREAD volatile InlineThreads[INLINE_SLOTS];

VOID TCPEnterInlineContext(VOID)
{
    ULONG i;
    PKTHREAD Me = KeGetCurrentThread();

    for (i = 0; i < INLINE_SLOTS; i++)
    {
        if (!InlineThreads[i] && InterlockedCompareExchangePointer((PVOID volatile *)&InlineThreads[i], Me, NULL) == NULL)
            return;
    }
}

VOID TCPLeaveInlineContext(VOID)
{
    ULONG i;
    PKTHREAD Me = KeGetCurrentThread();

    for (i = 0; i < INLINE_SLOTS; i++)
    {
        if (InlineThreads[i] == Me)
        {
            InterlockedExchangePointer((PVOID volatile *)&InlineThreads[i], NULL);
            return;
        }
    }
}

static BOOLEAN InInlineContext(VOID)
{
    ULONG i;
    PKTHREAD Me = KeGetCurrentThread();

    for (i = 0; i < INLINE_SLOTS; i++)
    {
        if (InlineThreads[i] == Me)
            return TRUE;
    }
    return FALSE;
}

VOID TCPEnterReceiveWorker(VOID) { InterlockedIncrement(&ReceiveWorkers); }
VOID TCPLeaveReceiveWorker(VOID) { InterlockedDecrement(&ReceiveWorkers); }

/* Stack a completion needs before it runs inline (the routine may start the next request, which
 * unlocks the core and completes more buckets on the same stack) */
#define TCP_COMPLETE_INLINE_STACK (KERNEL_STACK_SIZE / 2)

static KSPIN_LOCK BatchLock;
static LIST_ENTRY BatchList;

VOID
TCPInitDeferredCompletions(VOID)
{
    InitializeListHead(&DeferredCompletions);
    InitializeListHead(&BatchList);
    KeInitializeSpinLock(&BatchLock);
}

/* Under the core lock: takes the buckets that wait; FALSE if there are none */
BOOLEAN
TCPTakeDeferredCompletions(PLIST_ENTRY Taken)
{
    if (IsListEmpty(&DeferredCompletions))
        return FALSE;

    Taken->Flink = DeferredCompletions.Flink;
    Taken->Blink = DeferredCompletions.Blink;
    Taken->Flink->Blink = Taken;
    Taken->Blink->Flink = Taken;
    InitializeListHead(&DeferredCompletions);
    return TRUE;
}

static
VOID
QueueBucketCompletion(PTDI_BUCKET Bucket)
{
    if (!ChewCreate(BucketCompletionWorker, Bucket))
    {
        /* The bucket is off its queue, so a cancel cannot complete it */
        ChewQueueReserved(&Bucket->ReservedItem, BucketCompletionWorker, Bucket);
    }
}

/* Buckets that wait for a work item, which completes all that are queued while it runs: one thread
 * wake for a batch. (The reserved item of workqueue.c is one IO_WORKITEM queued again as soon as its
 * run ends; under this load it was queued again while the previous run had not returned, and the
 * queue stopped: a stress run of 16 threads hung. A work item of its own for each batch has no such window.) */
static KSPIN_LOCK BatchLock;
static LIST_ENTRY BatchList;
static BOOLEAN BatchQueued;

static
VOID
BatchWorker(PVOID Context)
{
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(Context);

    for (;;)
    {
        PTDI_BUCKET Bucket;

        KeAcquireSpinLock(&BatchLock, &OldIrql);
        if (IsListEmpty(&BatchList))
        {
            BatchQueued = FALSE;
            KeReleaseSpinLock(&BatchLock, OldIrql);
            return;
        }
        Bucket = CONTAINING_RECORD(RemoveHeadList(&BatchList), TDI_BUCKET, Entry);
        KeReleaseSpinLock(&BatchLock, OldIrql);

        BucketCompletionWorker(Bucket);
    }
}

static
VOID
QueueBatchedCompletion(PTDI_BUCKET Bucket)
{
    KIRQL OldIrql;
    BOOLEAN Start;

    KeAcquireSpinLock(&BatchLock, &OldIrql);
    InsertTailList(&BatchList, &Bucket->Entry);
    Start = !BatchQueued;
    BatchQueued = TRUE;
    KeReleaseSpinLock(&BatchLock, OldIrql);

    if (Start && !ChewCreate(BatchWorker, NULL))
    {
        /* No work item: what waits goes through the reserved item, which cannot fail */
        for (;;)
        {
            PTDI_BUCKET Waiting;

            KeAcquireSpinLock(&BatchLock, &OldIrql);
            if (IsListEmpty(&BatchList))
            {
                BatchQueued = FALSE;
                KeReleaseSpinLock(&BatchLock, OldIrql);
                break;
            }
            Waiting = CONTAINING_RECORD(RemoveHeadList(&BatchList), TDI_BUCKET, Entry);
            KeReleaseSpinLock(&BatchLock, OldIrql);
            ChewQueueReserved(&Waiting->ReservedItem, BucketCompletionWorker, Waiting);
        }
    }
}

/* With no lock held: completes the buckets taken by TCPTakeDeferredCompletions */
VOID
TCPRunDeferredCompletions(PLIST_ENTRY Taken, BOOLEAN TcpipThread)
{
    while (!IsListEmpty(Taken))
    {
        PTDI_BUCKET Bucket = CONTAINING_RECORD(RemoveHeadList(Taken), TDI_BUCKET, Entry);
        PCONNECTION_ENDPOINT Connection = Bucket->AssociatedEndpoint;

        if (!TcpipThread && !ReceiveWorkers && InInlineContext() &&
            KeGetCurrentIrql() == PASSIVE_LEVEL &&
            IoGetRemainingStackSize() >= TCP_COMPLETE_INLINE_STACK &&
            !ExIsResourceAcquiredExclusiveLite(&Connection->Resource))
        {
            /* The completion routine runs with the AFD mutex of its socket and can start a request that
             * unlocks the core again: what that completes goes to a work item, not inline */
            TCPLeaveInlineContext();
            BucketCompletionWorker(Bucket);
            TCPEnterInlineContext();
        }
        else
        {
            QueueBatchedCompletion(Bucket);
        }
    }
}

VOID
CompleteBucket(PCONNECTION_ENDPOINT Connection, PTDI_BUCKET Bucket, const BOOLEAN Synchronous)
{
    ReferenceObject(Connection);
    Bucket->AssociatedEndpoint = Connection;
    if (Synchronous)
    {
        BucketCompletionWorker(Bucket);
    }
    else if (sys_tcpip_core_locked())
    {
        /* The bucket is off its queue; its entry links it here until the core lock is released */
        InsertTailList(&DeferredCompletions, &Bucket->Entry);
    }
    else
    {
        QueueBucketCompletion(Bucket);
    }
}

VOID
FlushReceiveQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status)
{
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;

    ASSERT_TCPIP_OBJECT_LOCKED(Connection);

    while (!IsListEmpty(&Connection->ReceiveRequest))
    {
        Entry = RemoveHeadList(&Connection->ReceiveRequest);

        Bucket = CONTAINING_RECORD(Entry, TDI_BUCKET, Entry);

        Bucket->Information = 0;
        Bucket->Status = Status;

        CompleteBucket(Connection, Bucket, FALSE);
    }
}

VOID
FlushSendQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status)
{
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;

    ASSERT_TCPIP_OBJECT_LOCKED(Connection);

    while (!IsListEmpty(&Connection->SendRequest))
    {
        Entry = RemoveHeadList(&Connection->SendRequest);

        Bucket = CONTAINING_RECORD(Entry, TDI_BUCKET, Entry);

        Bucket->Information = 0;
        Bucket->Status = Status;

        CompleteBucket(Connection, Bucket, FALSE);
    }
}

VOID
FlushShutdownQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status)
{
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;

    ASSERT_TCPIP_OBJECT_LOCKED(Connection);

    while (!IsListEmpty(&Connection->ShutdownRequest))
    {
        Entry = RemoveHeadList(&Connection->ShutdownRequest);

        Bucket = CONTAINING_RECORD(Entry, TDI_BUCKET, Entry);

        Bucket->Information = 0;
        Bucket->Status = Status;

        CompleteBucket(Connection, Bucket, FALSE);
    }
}

VOID
FlushConnectQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status)
{
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;

    ASSERT_TCPIP_OBJECT_LOCKED(Connection);

    while (!IsListEmpty(&Connection->ConnectRequest))
    {
        Entry = RemoveHeadList(&Connection->ConnectRequest);
        Bucket = CONTAINING_RECORD( Entry, TDI_BUCKET, Entry );

        Bucket->Status = Status;
        Bucket->Information = 0;

        CompleteBucket(Connection, Bucket, FALSE);
    }
}

VOID
FlushListenQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status)
{
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;

    ASSERT_TCPIP_OBJECT_LOCKED(Connection);

    while (!IsListEmpty(&Connection->ListenRequest))
    {
        Entry = RemoveHeadList(&Connection->ListenRequest);
        Bucket = CONTAINING_RECORD( Entry, TDI_BUCKET, Entry );

        Bucket->Status = Status;
        Bucket->Information = 0;

        DereferenceObject(Bucket->AssociatedEndpoint);
        CompleteBucket(Connection, Bucket, FALSE);
    }
}

VOID
FlushAllQueues(PCONNECTION_ENDPOINT Connection, NTSTATUS Status)
{
    // flush receive queue
    FlushReceiveQueue(Connection, Status);

    /* We completed the reads successfully but we need to return failure now */
    if (Status == STATUS_SUCCESS)
    {
        Status = STATUS_FILE_CLOSED;
    }

    // flush listen queue
    FlushListenQueue(Connection, Status);

    // flush send queue
    FlushSendQueue(Connection, Status);

    // flush connect queue (a reset of a connect means it was refused)
    if (Status == STATUS_CONNECTION_RESET)
        FlushConnectQueue(Connection, STATUS_CONNECTION_REFUSED);
    else
        FlushConnectQueue(Connection, Status);

    // flush shutdown queue
    FlushShutdownQueue(Connection, Status);
}

VOID
TCPFinEventHandler(void *arg, const err_t err)
{
   PCONNECTION_ENDPOINT Connection = (PCONNECTION_ENDPOINT)arg, LastConnection;
   const NTSTATUS Status = TCPTranslateError(err);

   ASSERT(Connection->SocketContext == NULL);
   ASSERT(Connection->AddressFile);
   ASSERT(err != ERR_OK);

   LockObject(Connection);

   /* Complete all outstanding requests now */
   FlushAllQueues(Connection, Status);

   LockObject(Connection->AddressFile);

   /* Unlink this connection from the address file */
   if (Connection->AddressFile->Connection == Connection)
   {
       Connection->AddressFile->Connection = Connection->Next;
       DereferenceObject(Connection);
   }
   else if (Connection->AddressFile->Listener == Connection)
   {
       Connection->AddressFile->Listener = NULL;
       DereferenceObject(Connection);
   }
   else
   {
       LastConnection = Connection->AddressFile->Connection;
       while (LastConnection->Next != Connection && LastConnection->Next != NULL)
           LastConnection = LastConnection->Next;
       if (LastConnection->Next == Connection)
       {
           LastConnection->Next = Connection->Next;
           DereferenceObject(Connection);
       }
   }

   UnlockObject(Connection->AddressFile);

   /* Remove the address file from this connection */
   DereferenceObject(Connection->AddressFile);
   Connection->AddressFile = NULL;

   UnlockObject(Connection);
}

VOID
TCPAcceptEventHandler(void *arg, PTCP_PCB newpcb)
{
    PCONNECTION_ENDPOINT Connection = (PCONNECTION_ENDPOINT)arg;
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;
    PIRP Irp;
    NTSTATUS Status;

    LockObject(Connection);

    while (!IsListEmpty(&Connection->ListenRequest))
    {
        PIO_STACK_LOCATION IrpSp;

        Entry = RemoveHeadList(&Connection->ListenRequest);

        Bucket = CONTAINING_RECORD( Entry, TDI_BUCKET, Entry );

        Irp = Bucket->Request.RequestContext;
        IrpSp = IoGetCurrentIrpStackLocation( Irp );

        TI_DbgPrint(DEBUG_TCP,("[IP, TCPAcceptEventHandler] Getting the socket\n"));

        Status = TCPCheckPeerForAccept(newpcb,
                                       (PTDI_REQUEST_KERNEL)&IrpSp->Parameters);

        TI_DbgPrint(DEBUG_TCP,("Socket: Status: %x\n", Status));

        Bucket->Status = Status;
        Bucket->Information = 0;

        if (Status == STATUS_SUCCESS)
        {
            LockObject(Bucket->AssociatedEndpoint);

            /* sanity assert...this should never be in anything else but a CLOSED state */
            ASSERT( ((PTCP_PCB)Bucket->AssociatedEndpoint->SocketContext)->state == CLOSED );

            /*  free socket context created in FileOpenConnection, as we're using a new one */
            LibTCPClose(Bucket->AssociatedEndpoint, TRUE, FALSE);

            /* free previously created socket context (we don't use it, we use newpcb) */
            Bucket->AssociatedEndpoint->SocketContext = newpcb;

            /* The connection is filed under the listener binding, which has no concrete
               address for a wildcard listener: the local address is the one the SYN was
               sent to (a loopback alias, or one of several addresses of an interface) */
            Bucket->AssociatedEndpoint->ConnectAddress = newpcb->local_ip.addr;

            UnlockObject(Bucket->AssociatedEndpoint);

            LibTCPAccept(newpcb, (PTCP_PCB)Connection->SocketContext, Bucket->AssociatedEndpoint);
        }

        DereferenceObject(Bucket->AssociatedEndpoint);

        CompleteBucket(Connection, Bucket, FALSE);

        if (Status == STATUS_SUCCESS)
        {
            break;
        }
    }

    UnlockObject(Connection);
}

VOID
TCPSendEventHandler(void *arg, const u16_t space)
{
    PCONNECTION_ENDPOINT Connection = (PCONNECTION_ENDPOINT)arg;
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;
    PIRP Irp;
    NTSTATUS Status;
    PMDL Mdl;
    ULONG BytesSent;

    ReferenceObject(Connection);
    LockObject(Connection);

    while (!IsListEmpty(&Connection->SendRequest))
    {
        UINT SendLen = 0;
        PVOID SendBuffer = 0;

        Entry = RemoveHeadList(&Connection->SendRequest);

        UnlockObject(Connection);

        Bucket = CONTAINING_RECORD( Entry, TDI_BUCKET, Entry );

        Irp = Bucket->Request.RequestContext;
        Mdl = Irp->MdlAddress;

        TI_DbgPrint(DEBUG_TCP,
                    ("Getting the user buffer from %x\n", Mdl));

        NdisQueryBuffer( Mdl, &SendBuffer, &SendLen );

        TI_DbgPrint(DEBUG_TCP,
                    ("Writing %d bytes to %x\n", SendLen, SendBuffer));

        TI_DbgPrint(DEBUG_TCP, ("Connection: %x\n", Connection));
        TI_DbgPrint
        (DEBUG_TCP,
         ("Connection->SocketContext: %x\n",
          Connection->SocketContext));

        Status = TCPTranslateError(LibTCPSend(Connection,
                                              SendBuffer,
                                              SendLen, &BytesSent, TRUE, NULL));

        TI_DbgPrint(DEBUG_TCP,("TCP Bytes: %d\n", BytesSent));

        if( Status == STATUS_PENDING )
        {
            LockObject(Connection);

            /* A cancel that ran while the request was out of the queue did not find it */
            if (Irp->Cancel)
            {
                Bucket->Status = STATUS_CANCELLED;
                Bucket->Information = 0;
                CompleteBucket(Connection, Bucket, FALSE);
                continue;
            }

            InsertHeadList(&Connection->SendRequest, &Bucket->Entry);
            break;
        }
        else
        {
            TI_DbgPrint(DEBUG_TCP,
                        ("Completing Send request: %x %x\n",
                         Bucket->Request, Status));

            Bucket->Status = Status;
            Bucket->Information = (Bucket->Status == STATUS_SUCCESS) ? BytesSent : 0;

            CompleteBucket(Connection, Bucket, FALSE);
        }

        LockObject(Connection);
    }

    //  If we completed all outstanding send requests then finish all pending shutdown requests,
    //  cancel the timer and dereference the connection
    if (IsListEmpty(&Connection->SendRequest))
    {
        FlushShutdownQueue(Connection, STATUS_SUCCESS);

        if (KeCancelTimer(&Connection->DisconnectTimer))
        {
            DereferenceObject(Connection);
        }
    }

    UnlockObject(Connection);

    DereferenceObject(Connection);
}

VOID
TCPRecvEventHandler(void *arg)
{
    PCONNECTION_ENDPOINT Connection = (PCONNECTION_ENDPOINT)arg;
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;
    PIRP Irp;
    PMDL Mdl;
    UINT Received;
    UINT RecvLen;
    PUCHAR RecvBuffer;
    NTSTATUS Status;

    LockObject(Connection);

    while(!IsListEmpty(&Connection->ReceiveRequest))
    {
        Entry = RemoveHeadList(&Connection->ReceiveRequest);
        Bucket = CONTAINING_RECORD( Entry, TDI_BUCKET, Entry );

        Irp = Bucket->Request.RequestContext;
        Mdl = Irp->MdlAddress;

        NdisQueryBuffer( Mdl, &RecvBuffer, &RecvLen );

        Status = LibTCPGetDataFromConnectionQueue(Connection, RecvBuffer, RecvLen, &Received);
        if (Status == STATUS_PENDING)
        {
            InsertHeadList(&Connection->ReceiveRequest, &Bucket->Entry);
            break;
        }

        Bucket->Status = Status;
        Bucket->Information = Received;

        CompleteBucket(Connection, Bucket, FALSE);
    }
    UnlockObject(Connection);

    /* What the pending reads took makes room in the receive window */
    LibTCPReturnReceiveCredit(Connection);
}

VOID
TCPConnectEventHandler(void *arg, const err_t err)
{
    PCONNECTION_ENDPOINT Connection = (PCONNECTION_ENDPOINT)arg;
    PTDI_BUCKET Bucket;
    PLIST_ENTRY Entry;

    LockObject(Connection);

    while (!IsListEmpty(&Connection->ConnectRequest))
    {
        Entry = RemoveHeadList(&Connection->ConnectRequest);

        Bucket = CONTAINING_RECORD( Entry, TDI_BUCKET, Entry );

        Bucket->Status = TCPTranslateError(err);
        Bucket->Information = 0;

        CompleteBucket(Connection, Bucket, FALSE);
    }

    UnlockObject(Connection);
}
