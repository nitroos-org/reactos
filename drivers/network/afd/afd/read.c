/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/read.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"

/* After shutdown(SD_RECEIVE) only the receives that were pending are served: the buffer is refilled
 * for them alone (ForPending), when the data that arrived did not satisfy them all */
static VOID RefillSocketBufferEx( PAFD_FCB FCB, BOOLEAN ForPending )
{
    /* Make sure nothing's in flight first */
    if (FCB->ReceiveIrp.InFlightRequest) return;

    /* A receive that finished inside the call that started it waits for the loop of ReceiveComplete: it
     * refills when it has been handled, and only one can be waiting */
    if (FCB->RecvDeferred) return;

    /* Now ensure that receive is still allowed */
    if (FCB->TdiReceiveClosed) return;

    if (FCB->ReceiveShutdown && !ForPending) return;

    /* Check if the buffer is full */
    if (FCB->Recv.Content == FCB->Recv.Size)
    {
        /* If there are bytes used, we can solve this problem */
        if (FCB->Recv.BytesUsed != 0)
        {
            /* Reposition the unused portion to the beginning of the receive window */
            RtlMoveMemory(FCB->Recv.Window,
                          FCB->Recv.Window + FCB->Recv.BytesUsed,
                          FCB->Recv.Content - FCB->Recv.BytesUsed);

            FCB->Recv.Content -= FCB->Recv.BytesUsed;
            FCB->Recv.BytesUsed = 0;
        }
        else
        {
            /* No space in the buffer to receive */
            return;
        }
    }

    AFD_DbgPrint(MID_TRACE,("Replenishing buffer\n"));

    TdiReceive( &FCB->ReceiveIrp.InFlightRequest,
                FCB->Connection.Object,
                TDI_RECEIVE_NORMAL,
                FCB->Recv.Window + FCB->Recv.Content,
                FCB->Recv.Size - FCB->Recv.Content,
                ReceiveComplete,
                FCB );
}

static VOID RefillSocketBuffer( PAFD_FCB FCB )
{
    RefillSocketBufferEx( FCB, FALSE );
}

static VOID HandleReceiveComplete( PAFD_FCB FCB, NTSTATUS Status, ULONG_PTR Information )
{
    /* An aborted connection keeps its status; the transport flushing the receive changes nothing */
    if (FCB->ConnectionAborted)
        return;

    FCB->LastReceiveStatus = Status;

    /* We got closed while the receive was in progress */
    if (FCB->TdiReceiveClosed)
    {
        /* Data that arrives after shutdown(SD_RECEIVE) with no receive pending resets the connection,
           as on Windows; after the peer's end or a failure it is discarded */
        if (FCB->LocalReceiveShutdown && Status == STATUS_SUCCESS && Information != 0)
            AfdAbortConnection(FCB);
    }
    /* Receive successful */
    else if (Status == STATUS_SUCCESS)
    {
        FCB->Recv.Content += Information;
        ASSERT(FCB->Recv.Content <= FCB->Recv.Size);

        /* Check for graceful closure */
        if (Information == 0)
        {
            /* Receive is closed */
            FCB->TdiReceiveClosed = TRUE;
        }
        else
        {
            /* Issue another receive IRP to keep the buffer well stocked */
            RefillSocketBuffer(FCB);
        }
    }
    /* Receive failed with no data (unexpected closure) */
    else
    {
        /* A reset discards the data not read yet, as on Windows; other failures keep it */
        if (Status == STATUS_CONNECTION_RESET)
        {
            FCB->Recv.Content = 0;
            FCB->Recv.BytesUsed = 0;
        }
        FCB->TdiReceiveClosed = TRUE;
    }
}

static BOOLEAN CantReadMore( PAFD_FCB FCB ) {
    UINT BytesAvailable = FCB->Recv.Content - FCB->Recv.BytesUsed;

    return !BytesAvailable && FCB->TdiReceiveClosed;
}

static NTSTATUS TryToSatisfyRecvRequestFromBuffer( PAFD_FCB FCB,
                                                   PAFD_RECV_INFO RecvReq,
                                                   PUINT TotalBytesCopied ) {
    UINT i, BytesToCopy = 0, FcbBytesCopied = FCB->Recv.BytesUsed,
        BytesAvailable =
        FCB->Recv.Content - FCB->Recv.BytesUsed;
    PAFD_MAPBUF Map;
    *TotalBytesCopied = 0;


    AFD_DbgPrint(MID_TRACE,("Called, BytesAvailable = %u\n", BytesAvailable));

    if( CantReadMore(FCB) ) return STATUS_SUCCESS;
    if( !BytesAvailable ) return STATUS_PENDING;

    Map = (PAFD_MAPBUF)(RecvReq->BufferArray + RecvReq->BufferCount);

    AFD_DbgPrint(MID_TRACE,("Buffer Count: %u @ %p\n",
                            RecvReq->BufferCount,
                            RecvReq->BufferArray));
    for( i = 0;
         RecvReq->BufferArray &&
             BytesAvailable &&
             i < RecvReq->BufferCount;
         i++ ) {
        BytesToCopy =
            MIN( RecvReq->BufferArray[i].len, BytesAvailable );

        if( Map[i].Mdl ) {
            Map[i].BufferAddress = MmMapLockedPages( Map[i].Mdl, KernelMode );

            AFD_DbgPrint(MID_TRACE,("Buffer %u: %p:%u\n",
                                    i,
                                    Map[i].BufferAddress,
                                    BytesToCopy));

            RtlCopyMemory( Map[i].BufferAddress,
                           FCB->Recv.Window + FcbBytesCopied,
                           BytesToCopy );

            MmUnmapLockedPages( Map[i].BufferAddress, Map[i].Mdl );

            *TotalBytesCopied += BytesToCopy;
            FcbBytesCopied += BytesToCopy;
            BytesAvailable -= BytesToCopy;

            if (!(RecvReq->TdiFlags & TDI_RECEIVE_PEEK))
                FCB->Recv.BytesUsed += BytesToCopy;
        }
    }

    /* Issue another receive IRP to keep the buffer well stocked */
    RefillSocketBuffer(FCB);

    return STATUS_SUCCESS;
}

/* Completes the pending receives of a stream socket with STATUS_CONNECTION_ABORTED: its
 * connection is being aborted (closesocket with a zero linger time). The state lock is held. */
VOID AfdAbortPendingReceives( PAFD_FCB FCB ) {
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;
    PIO_STACK_LOCATION NextIrpSp;
    PAFD_RECV_INFO RecvReq;

    while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) {
        NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_RECV]);
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
        NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
        RecvReq = GetLockedData(NextIrp, NextIrpSp);

        UnlockBuffers( RecvReq->BufferArray, RecvReq->BufferCount, FALSE );
        NextIrp->IoStatus.Status = STATUS_CONNECTION_ABORTED;
        NextIrp->IoStatus.Information = 0;
        if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
        AfdClearCancelRoutine(NextIrp);
        IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
    }
}

/* shutdown(SD_RECEIVE) with receives pending leaves them pending, as on Windows: they complete with the data
 * that arrives later, with the end or the reset of the connection, or are cancelled. When none is left the
 * shutdown takes effect, as it does at once for a socket without a pending receive. The state lock is held. */
VOID AfdCompleteReceiveShutdown( PAFD_FCB FCB ) {
    if( !FCB->ReceiveShutdown || !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) return;

    FCB->ReceiveShutdown = FALSE;
    FCB->ShutdownBoth = FALSE;
    if( !FCB->TdiReceiveClosed ) {
        FCB->TdiReceiveClosed = TRUE;
        FCB->LocalReceiveShutdown = TRUE;
        FCB->LastReceiveStatus = STATUS_SUCCESS;
    }

    /* Discard what has not been read */
    FCB->Recv.Content = 0;
    FCB->Recv.BytesUsed = 0;
    FCB->PollState &= ~AFD_EVENT_RECEIVE;

    /* The receive in flight, if any, ends by itself and its data is discarded (see AfdDisconnect) */
    if( FCB->ReceiveIrp.InFlightRequest && (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) )
        IoCancelIrp( FCB->ReceiveIrp.InFlightRequest );
}

static NTSTATUS ReceiveActivity( PAFD_FCB FCB, PIRP Irp ) {
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;
    PIO_STACK_LOCATION NextIrpSp;
    PAFD_RECV_INFO RecvReq;
    UINT TotalBytesCopied = 0;
    NTSTATUS Status = STATUS_SUCCESS, RetStatus = STATUS_PENDING;

    AFD_DbgPrint(MID_TRACE,("%p %p\n", FCB, Irp));

    AFD_DbgPrint(MID_TRACE,("FCB %p Receive data waiting %u\n",
                            FCB, FCB->Recv.Content));

    /* An AcceptEx that received initial data leaves no receive in flight. Only for
     * completions: a receive completed inline would complete a request queued by
     * the caller behind its back */
    if (Irp == NULL && FCB->SharedData.State == SOCKET_STATE_CONNECTED)
        RefillSocketBuffer(FCB);

    if( CantReadMore( FCB ) ) {
        /* Success here means that we got an EOF.  Complete a pending read
         * with zero bytes if we haven't yet overread, then kill the others.
         */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_RECV]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            RecvReq = GetLockedData(NextIrp, NextIrpSp);

            AFD_DbgPrint(MID_TRACE,("Completing recv %p (%u)\n", NextIrp,
                                    TotalBytesCopied));
            UnlockBuffers( RecvReq->BufferArray,
                           RecvReq->BufferCount, FALSE );

            /* Unexpected disconnect by the remote host or graceful disconnect */
            Status = FCB->LastReceiveStatus;

            NextIrp->IoStatus.Status = Status;
            NextIrp->IoStatus.Information = 0;
            if( NextIrp == Irp ) RetStatus = Status;
            if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            AfdClearCancelRoutine(NextIrp);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }
    } else {
        /* Kick the user that receive would be possible now */
        /* XXX Not implemented yet */

        AFD_DbgPrint(MID_TRACE,("FCB %p Receive data waiting %u\n",
                                FCB, FCB->Recv.Content));
        /*OskitDumpBuffer( FCB->Recv.Window, FCB->Recv.Content );*/

        /* Try to clear some requests */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_RECV]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            RecvReq = GetLockedData(NextIrp, NextIrpSp);

            AFD_DbgPrint(MID_TRACE,("RecvReq @ %p\n", RecvReq));

            Status = TryToSatisfyRecvRequestFromBuffer
            ( FCB, RecvReq, &TotalBytesCopied );

            if( Status == STATUS_PENDING ) {
                AFD_DbgPrint(MID_TRACE,("Ran out of data for %p\n", NextIrp));
                InsertHeadList(&FCB->PendingIrpList[FUNCTION_RECV],
                               &NextIrp->Tail.Overlay.ListEntry);
                break;
            } else {
                AFD_DbgPrint(MID_TRACE,("Completing recv %p (%u)\n", NextIrp,
                                        TotalBytesCopied));
                UnlockBuffers( RecvReq->BufferArray,
                               RecvReq->BufferCount, FALSE );
                NextIrp->IoStatus.Status = Status;
                NextIrp->IoStatus.Information = TotalBytesCopied;
                if( NextIrp == Irp ) {
                    RetStatus = Status;
                }
                if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
                AfdClearCancelRoutine(NextIrp);
                IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
            }
        }
    }

    if( FCB->Recv.Content - FCB->Recv.BytesUsed &&
        IsListEmpty(&FCB->PendingIrpList[FUNCTION_RECV]) ) {
        FCB->PollState |= AFD_EVENT_RECEIVE;
        FCB->PollStatus[FD_READ_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }
    else if (!FCB->ConnectionAborted)
    {
        FCB->PollState &= ~AFD_EVENT_RECEIVE;
    }

    /* Signal FD_CLOSE if no buffered data remains and the socket can't receive any more */
    if (CantReadMore(FCB))
    {
        if (FCB->LastReceiveStatus == STATUS_SUCCESS)
        {
            FCB->PollState |= AFD_EVENT_DISCONNECT;
        }
        else
        {
            FCB->PollState |= AFD_EVENT_CLOSE;
        }
        FCB->PollStatus[FD_CLOSE_BIT] = FCB->LastReceiveStatus;
        PollReeval(FCB->DeviceExt, FCB->FileObject);
    }

    /* The receives that shutdown(SD_RECEIVE) kept and the data did not satisfy wait for more */
    if( FCB->ReceiveShutdown && !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) )
        RefillSocketBufferEx( FCB, TRUE );

    AfdCompleteReceiveShutdown( FCB );

    AFD_DbgPrint(MID_TRACE,("RetStatus for irp %p is %x\n", Irp, RetStatus));

    return RetStatus;
}

NTSTATUS NTAPI
AcceptExReceiveComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    PAFD_FCB FCB = (PAFD_FCB)Context;

    if (!SocketAcquireStateLock(FCB))
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->ReceiveIrp.InFlightRequest == Irp);
    ASSERT(FCB->AcceptIrp != NULL);
    FCB->ReceiveIrp.InFlightRequest = NULL;

    /* On a closed socket the AcceptEx request still completes with the receive's result */
    if (FCB->SharedData.State != SOCKET_STATE_CLOSED)
        FCB->SharedData.State = SOCKET_STATE_CONNECTED;

    /* Complete the AcceptEx IRP as the data has been received */
    MmUnlockPages((PMDL)FCB->AcceptIrp->Tail.Overlay.DriverContext[3]);
    IoFreeMdl((PMDL)FCB->AcceptIrp->Tail.Overlay.DriverContext[3]);
    FCB->AcceptIrp->IoStatus.Information = Irp->IoStatus.Information;
    FCB->AcceptIrp->IoStatus.Status = Irp->IoStatus.Status;
    if (FCB->AcceptIrp->MdlAddress)
        UnlockRequest(FCB->AcceptIrp, IoGetCurrentIrpStackLocation(FCB->AcceptIrp));
    AfdClearCancelRoutine(FCB->AcceptIrp);
    IoCompleteRequest(FCB->AcceptIrp, IO_NETWORK_INCREMENT);
    FCB->AcceptIrp = NULL;

    /* Continue receive activity */
    if (FCB->SharedData.State != SOCKET_STATE_CLOSED)
        ReceiveActivity(FCB, NULL);

    SocketStateUnlock(FCB);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ReceiveComplete
( PDEVICE_OBJECT DeviceObject,
  PIRP Irp,
  PVOID Context ) {
    PAFD_FCB FCB = (PAFD_FCB)Context;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;
    PAFD_RECV_INFO RecvReq;
    PIO_STACK_LOCATION NextIrpSp;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called\n"));

    if( !SocketAcquireStateLock( FCB ) )
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->ReceiveIrp.InFlightRequest == Irp);
    FCB->ReceiveIrp.InFlightRequest = NULL;

    if( FCB->SharedData.State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_RECV]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation(NextIrp);
            RecvReq = GetLockedData(NextIrp, NextIrpSp);
            NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
            NextIrp->IoStatus.Information = 0;
            UnlockBuffers(RecvReq->BufferArray, RecvReq->BufferCount, FALSE);
            if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            AfdClearCancelRoutine(NextIrp);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }
        SocketStateUnlock( FCB );
        return STATUS_FILE_CLOSED;
    } else if( FCB->SharedData.State == SOCKET_STATE_LISTENING ) {
        AFD_DbgPrint(MIN_TRACE,("!!! LISTENER GOT A RECEIVE COMPLETE !!!\n"));
        SocketStateUnlock( FCB );
        return STATUS_INVALID_PARAMETER;
    }

    if( FCB->RecvCompleteActive ) {
        /* The transport finished a receive inside the receive that an outer call of this routine starts
         * (it had data queued): leave it to that call, which loops. The refill of every 8K of a queue of
         * megabytes would otherwise nest, one transport call and one completion each, until the kernel
         * stack is gone */
        FCB->RecvDeferred = TRUE;
        FCB->RecvDeferredStatus = Irp->IoStatus.Status;
        FCB->RecvDeferredBytes = Irp->IoStatus.Information;
        SocketStateUnlock( FCB );
        return STATUS_SUCCESS;
    }

    FCB->RecvCompleteActive = TRUE;
    {
        NTSTATUS Status = Irp->IoStatus.Status;
        ULONG_PTR Bytes = Irp->IoStatus.Information;

        for(;;) {
            FCB->RecvDeferred = FALSE;
            HandleReceiveComplete( FCB, Status, Bytes );
            ReceiveActivity( FCB, NULL );
            if( !FCB->RecvDeferred )
                break;
            Status = FCB->RecvDeferredStatus;
            Bytes = FCB->RecvDeferredBytes;
        }
    }
    FCB->RecvCompleteActive = FALSE;

    SocketStateUnlock( FCB );

    return STATUS_SUCCESS;
}

static IO_WORKITEM_ROUTINE RelaunchPacketReceiveWorker;

/* Datagrams of no data that one datagram socket keeps waiting for a read */
#define AFD_MAX_QUEUED_EMPTY_DATAGRAMS 1024

/* Called with the socket state lock held */
static VOID
RelaunchPacketReceive(PAFD_FCB FCB)
{
    /* Nothing to do while a receive is in flight or about to be started, the
     * socket is closing or shut down for receiving, or the stored datagrams
     * still fill the receive window */
    if (FCB->ReceiveIrp.InFlightRequest ||
        FCB->RecvRelaunchQueued ||
        FCB->SharedData.State == SOCKET_STATE_CLOSED ||
        FCB->TdiReceiveClosed ||
        !FCB->AddressFile.Object ||
        FCB->Recv.Content >= FCB->Recv.Size)
    {
        return;
    }

    /* The receive IRP belongs to the thread that builds it and is cancelled
     * when that thread exits, so an application thread hands the start over
     * to a system worker thread. The work item is allocated at bind, so this
     * cannot fail */
    if (!PsIsSystemThread(PsGetCurrentThread()))
    {
        if (FCB->RecvRelaunchWorkItem)
        {
            FCB->RecvRelaunchQueued = TRUE;
            /* Keeps the FCB until the worker has run */
            ObReferenceObject(FCB->FileObject);
            IoQueueWorkItem(FCB->RecvRelaunchWorkItem,
                            RelaunchPacketReceiveWorker,
                            DelayedWorkQueue,
                            FCB);
        }
        return;
    }

    TdiReceiveDatagram(&FCB->ReceiveIrp.InFlightRequest,
                       FCB->AddressFile.Object,
                       0,
                       FCB->Recv.Window,
                       FCB->Recv.Size,
                       FCB->AddressFrom,
                       PacketSocketRecvComplete,
                       FCB);
}

static
VOID
NTAPI
RelaunchPacketReceiveWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PAFD_FCB FCB = Context;
    PFILE_OBJECT FileObject = FCB->FileObject;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (SocketAcquireStateLock(FCB))
    {
        FCB->RecvRelaunchQueued = FALSE;
        RelaunchPacketReceive(FCB);
        SocketStateUnlock(FCB);
    }

    ObDereferenceObject(FileObject);
}

/* Writes through a locked slot of the request (the slot has no MDL when the caller gave no pointer) */
static VOID
StoreToLockedBuffer(
    _In_ PAFD_MAPBUF Map,
    _In_ PVOID Data,
    _In_ ULONG Length)
{
    if( !Map->Mdl )
        return;

    Map->BufferAddress = MmGetSystemAddressForMdlSafe( Map->Mdl, NormalPagePriority );
    if( Map->BufferAddress )
        RtlCopyMemory( Map->BufferAddress, Data, MIN(Length, MmGetMdlByteCount(Map->Mdl)) );
}

/*
 * The control data of a received datagram for WSARecvMsg, as Windows hands it out: with
 * IP_PKTINFO enabled one message (level IPPROTO_IP, type IP_PKTINFO, an in_pktinfo with the
 * destination address and the interface index), laid out like the WSACMSGHDR of the caller
 * (the header is 12 bytes for a 32-bit process, 16 for a 64-bit one, and the data follows it).
 * The control length reports the full size of the message, the buffer receives as much of it
 * as it can take (a byte-wise cut for a 64-bit caller, as Windows does) and MSG_CTRUNC flags
 * the difference.
 * Without IP_PKTINFO there is no control data and nothing to truncate.
 *
 * Returns TRUE when the message is truncated (the receive then fails with WSAEMSGSIZE).
 */
static BOOLEAN
StoreMessageControl(
    _In_ PAFD_RECV_INFO_UDP RecvReq,
    _In_ PAFD_MAPBUF Map,
    _In_ PAFD_STORED_DATAGRAM DatagramRecv,
    _In_ BOOLEAN DatagramTruncated)
{
    PAFD_RECV_INFO_MSG Msg = (PAFD_RECV_INFO_MSG)RecvReq;
    PAFD_WSABUF Slots = RecvReq->BufferArray + RecvReq->BufferCount;
    UCHAR Cmsg[16 + sizeof(ULONG) * 2];
    ULONG HeaderSize = Msg->CmsgHdrSize;
    ULONG Total = 0, Capacity = Slots[EXTRA_LOCK_CONTROL].buf ? Slots[EXTRA_LOCK_CONTROL].len : 0;
    ULONG Flags = DatagramTruncated ? MSG_TRUNC : 0;

    if( (Msg->Options & AFD_RECV_MSG_PKTINFO) && DatagramRecv->PktInfo.Valid ) {
        ULONG Pos = 0;
        INT Level = IPPROTO_IP, Type = 19 /* IP_PKTINFO */;
        ULONG Addr = DatagramRecv->PktInfo.DstAddress, Index = DatagramRecv->PktInfo.IfIndex;

        Total = HeaderSize + sizeof(Addr) + sizeof(Index);
        ASSERT(Total <= sizeof(Cmsg));
        RtlZeroMemory(Cmsg, sizeof(Cmsg));
        /* cmsg_len is a SIZE_T, followed by two INT: cmsg_level and cmsg_type */
        RtlCopyMemory(Cmsg, &Total, sizeof(Total));
        Pos = HeaderSize - 2 * sizeof(INT);
        RtlCopyMemory(Cmsg + Pos, &Level, sizeof(Level));
        RtlCopyMemory(Cmsg + Pos + sizeof(INT), &Type, sizeof(Type));
        RtlCopyMemory(Cmsg + HeaderSize, &Addr, sizeof(Addr));
        RtlCopyMemory(Cmsg + HeaderSize + sizeof(Addr), &Index, sizeof(Index));

        if( Capacity < Total )
            Flags |= MSG_CTRUNC;

        /* A 64-bit process gets as many bytes as fit. A 32-bit one (whose messages the
         * 64-bit system converts) gets the header when that fits, and the data only whole. */
        if( HeaderSize == 12 && Capacity < Total )
            Capacity = (Capacity >= HeaderSize) ? HeaderSize : 0;
        StoreToLockedBuffer(&Map[RecvReq->BufferCount + EXTRA_LOCK_CONTROL], Cmsg, MIN(Capacity, Total));
    }

    StoreToLockedBuffer(&Map[RecvReq->BufferCount + EXTRA_LOCK_CONTROL_LENGTH], &Total, sizeof(Total));
    StoreToLockedBuffer(&Map[RecvReq->BufferCount + EXTRA_LOCK_MSG_FLAGS], &Flags, sizeof(Flags));

    return (Flags & MSG_CTRUNC) != 0;
}

static NTSTATUS NTAPI
SatisfyPacketRecvRequest( PAFD_FCB FCB, PIRP Irp,
                         PAFD_STORED_DATAGRAM DatagramRecv,
                         PUINT TotalBytesCopied ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
    PAFD_RECV_INFO RecvReq =
    GetLockedData(Irp, IrpSp);
    UINT BytesToCopy, BytesCopied = 0, BytesAvailable = DatagramRecv->Len;
    UINT AddrLen, i;
    PAFD_MAPBUF Map;
    BOOLEAN ExtraBuffers = CheckUnlockExtraBuffers(FCB, IrpSp);

    Map = (PAFD_MAPBUF)(RecvReq->BufferArray +
                        RecvReq->BufferCount +
                        (ExtraBuffers ? EXTRA_LOCK_BUFFERS : 0));

    /* LockBuffers puts the address and its length after the data buffers */
    if( ExtraBuffers &&
        Map[RecvReq->BufferCount].Mdl &&
        Map[RecvReq->BufferCount + 1].Mdl ) {
        PAFD_MAPBUF AddrMap = &Map[RecvReq->BufferCount];
        PAFD_MAPBUF AddrLenMap = &Map[RecvReq->BufferCount + 1];

        if( DatagramRecv->Address->TAAddressCount != 1 ) {
            AFD_DbgPrint
            (MIN_TRACE,
             ("Wierd address count %d\n",
              DatagramRecv->Address->TAAddressCount));
        }

        AddrLen = MIN(DatagramRecv->Address->Address->AddressLength +
                      sizeof(USHORT),
                      RecvReq->BufferArray[RecvReq->BufferCount].len);

        AFD_DbgPrint(MID_TRACE,("Copying %u bytes of address\n", AddrLen));

        AddrMap->BufferAddress = MmGetSystemAddressForMdlSafe( AddrMap->Mdl, NormalPagePriority );
        if( AddrMap->BufferAddress )
            RtlCopyMemory( AddrMap->BufferAddress,
                          &DatagramRecv->Address->Address->AddressType,
                          AddrLen );

        AddrLenMap->BufferAddress = MmGetSystemAddressForMdlSafe( AddrLenMap->Mdl, NormalPagePriority );
        if( AddrLenMap->BufferAddress )
            *((PINT)AddrLenMap->BufferAddress) = AddrLen;
    }

    /* Scatter the datagram over the data buffers in order */
    for( i = 0; i < RecvReq->BufferCount && BytesCopied < BytesAvailable; i++ ) {
        if( !Map[i].Mdl )
            continue;

        BytesToCopy = MIN( RecvReq->BufferArray[i].len,
                           BytesAvailable - BytesCopied );

        Map[i].BufferAddress = MmGetSystemAddressForMdlSafe( Map[i].Mdl, NormalPagePriority );

        AFD_DbgPrint(MID_TRACE,("Buffer %u: %p:%u\n",
                                i,
                                Map[i].BufferAddress,
                                BytesToCopy));

        if( Map[i].BufferAddress )
            RtlCopyMemory( Map[i].BufferAddress,
                          DatagramRecv->Buffer + BytesCopied,
                          BytesToCopy );

        BytesCopied += BytesToCopy;
    }

    *TotalBytesCopied = BytesCopied;

    if (*TotalBytesCopied == DatagramRecv->Len)
    {
        /* We copied the whole datagram */
        Status = Irp->IoStatus.Status = STATUS_SUCCESS;
    }
    else
    {
        /* We only copied part of the datagram */
        Status = Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
    }

    /* WSARecvMsg: the control data and the message flags */
    if( ExtraBuffers && (RecvReq->AfdFlags & AFD_RECV_MSG) ) {
        if( StoreMessageControl((PAFD_RECV_INFO_UDP)RecvReq, Map, DatagramRecv, Status == STATUS_BUFFER_OVERFLOW) )
            Status = Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
    }

    Irp->IoStatus.Information = *TotalBytesCopied;

    if (!(RecvReq->TdiFlags & TDI_RECEIVE_PEEK))
    {
        FCB->Recv.Content -= DatagramRecv->Len;
        ExFreePoolWithTag(DatagramRecv->Address, TAG_AFD_TRANSPORT_ADDRESS);
        ExFreePoolWithTag(DatagramRecv, TAG_AFD_STORED_DATAGRAM);

        /* The receive stops while the stored datagrams fill the window;
         * restart it now that there is room again */
        RelaunchPacketReceive(FCB);
    }

    AFD_DbgPrint(MID_TRACE,("Done\n"));

    return Status;
}

NTSTATUS NTAPI
AfdConnectedSocketReadData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                           PIO_STACK_LOCATION IrpSp, BOOLEAN Short) {
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_RECV_INFO RecvReq;
    UINT TotalBytesCopied = 0;
    PAFD_STORED_DATAGRAM DatagramRecv;
    PLIST_ENTRY ListEntry;
    KPROCESSOR_MODE LockMode;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Short);

    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    FCB->EventSelectDisabled &= ~AFD_EVENT_RECEIVE;

    if( !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
        FCB->SharedData.State != SOCKET_STATE_CONNECTED &&
        FCB->SharedData.State != SOCKET_STATE_CONNECTING ) {
        AFD_DbgPrint(MIN_TRACE,("Called recv on wrong kind of socket (s%x)\n",
                                FCB->SharedData.State));
        /* As a send on it: a stream socket that is not connected (fresh, bound, listening, after a
         * failed connect) is WSAENOTCONN on Windows (checked on Windows 10 22H2). Oracle Net reads
         * the socket after a refused connect (lsnrctl start) and was given WSAEINVAL */
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_CONNECTION,
                                       Irp, 0 );
    }

    if( !AfdRequestLengthValid( Irp, IrpSp, sizeof(AFD_RECV_INFO) ) )
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER,
                                       Irp, 0 );

    if( !(RecvReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) )
        return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY,
                                       Irp, 0 );

    AFD_DbgPrint(MID_TRACE,("Recv flags %x\n", RecvReq->AfdFlags));

    RecvReq->BufferArray = LockBuffers( RecvReq->BufferArray,
                                       RecvReq->BufferCount,
                                       NULL, NULL,
                                       TRUE, FALSE, LockMode, NULL );

    if( !RecvReq->BufferArray ) {
        return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION,
                                      Irp, 0 );
    }

    if( FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS )
    {
        if (!IsListEmpty(&FCB->DatagramList))
        {
            ListEntry = RemoveHeadList(&FCB->DatagramList);
            DatagramRecv = CONTAINING_RECORD(ListEntry, AFD_STORED_DATAGRAM, ListEntry);
            Status = SatisfyPacketRecvRequest(FCB, Irp, DatagramRecv,
                                              (PUINT)&Irp->IoStatus.Information);

            if (RecvReq->TdiFlags & TDI_RECEIVE_PEEK)
            {
                InsertHeadList(&FCB->DatagramList,
                               &DatagramRecv->ListEntry);
            }

            if (!IsListEmpty(&FCB->DatagramList))
            {
                FCB->PollState |= AFD_EVENT_RECEIVE;
                FCB->PollStatus[FD_READ_BIT] = STATUS_SUCCESS;
                PollReeval( FCB->DeviceExt, FCB->FileObject );
            }
            else
                FCB->PollState &= ~AFD_EVENT_RECEIVE;

            UnlockBuffers(RecvReq->BufferArray, RecvReq->BufferCount, FALSE);

            return UnlockAndMaybeComplete(FCB, Status, Irp, Irp->IoStatus.Information);
        }
        else if (!(RecvReq->AfdFlags & AFD_OVERLAPPED) &&
                ((RecvReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking)))
        {
            AFD_DbgPrint(MID_TRACE,("Nonblocking\n"));
            Status = STATUS_CANT_WAIT;
            FCB->PollState &= ~AFD_EVENT_RECEIVE;
            UnlockBuffers( RecvReq->BufferArray, RecvReq->BufferCount, FALSE );
            return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
        }
        else
        {
            FCB->PollState &= ~AFD_EVENT_RECEIVE;
            return LeaveIrpUntilLater( FCB, Irp, FUNCTION_RECV );
        }
    }

    Irp->IoStatus.Status = STATUS_PENDING;
    Irp->IoStatus.Information = 0;

    InsertTailList( &FCB->PendingIrpList[FUNCTION_RECV],
                    &Irp->Tail.Overlay.ListEntry );

    /************ From this point, the IRP is not ours ************/

    Status = ReceiveActivity( FCB, Irp );

    if( Status == STATUS_PENDING &&
        !(RecvReq->AfdFlags & AFD_OVERLAPPED) &&
        ((RecvReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking))) {
        AFD_DbgPrint(MID_TRACE,("Nonblocking\n"));
        Status = STATUS_CANT_WAIT;
        TotalBytesCopied = 0;
        RemoveEntryList( &Irp->Tail.Overlay.ListEntry );
        UnlockBuffers( RecvReq->BufferArray, RecvReq->BufferCount, FALSE );
        return UnlockAndMaybeComplete( FCB, Status, Irp,
                                       TotalBytesCopied );
    } else if( Status == STATUS_PENDING ) {
        AFD_DbgPrint(MID_TRACE,("Leaving read irp\n"));
        IoMarkIrpPending( Irp );
        /* A cancel that came before the routine was set found nothing to call */
        IoAcquireCancelSpinLock(&Irp->CancelIrql);
        if (!Irp->Cancel)
        {
            (void)IoSetCancelRoutine(Irp, AfdCancelHandler);
            IoReleaseCancelSpinLock(Irp->CancelIrql);
        }
        else
        {
            AfdCancelHandler(IoGetCurrentIrpStackLocation(Irp)->DeviceObject, Irp);
        }
    } else {
        AFD_DbgPrint(MID_TRACE,("Completed with status %x\n", Status));
    }

    SocketStateUnlock( FCB );
    return Status;
}

NTSTATUS NTAPI
PacketSocketRecvComplete(
        PDEVICE_OBJECT DeviceObject,
        PIRP Irp,
        PVOID Context ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PAFD_FCB FCB = Context;
    PIRP NextIrp;
    PIO_STACK_LOCATION NextIrpSp;
    PLIST_ENTRY ListEntry;
    PAFD_RECV_INFO RecvReq;
    PAFD_STORED_DATAGRAM DatagramRecv;
    UINT DGSize = Irp->IoStatus.Information + sizeof( AFD_STORED_DATAGRAM );
    PLIST_ENTRY NextIrpEntry, DatagramRecvEntry;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    if( !SocketAcquireStateLock( FCB ) )
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->ReceiveIrp.InFlightRequest == Irp);
    FCB->ReceiveIrp.InFlightRequest = NULL;

    if( FCB->SharedData.State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_RECV]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            RecvReq = GetLockedData(NextIrp, NextIrpSp);
            NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
            NextIrp->IoStatus.Information = 0;
            UnlockBuffers(RecvReq->BufferArray, RecvReq->BufferCount, CheckUnlockExtraBuffers(FCB, NextIrpSp));
            if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            AfdClearCancelRoutine(NextIrp);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }

        /* Free all items on the datagram list */
        while( !IsListEmpty( &FCB->DatagramList ) ) {
               DatagramRecvEntry = RemoveHeadList(&FCB->DatagramList);
               DatagramRecv = CONTAINING_RECORD(DatagramRecvEntry, AFD_STORED_DATAGRAM, ListEntry);
               ExFreePoolWithTag(DatagramRecv->Address, TAG_AFD_TRANSPORT_ADDRESS);
               ExFreePoolWithTag(DatagramRecv, TAG_AFD_STORED_DATAGRAM);
        }

        SocketStateUnlock( FCB );
        return STATUS_FILE_CLOSED;
    }

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
    {
        /* A datagram larger than the receive window arrives truncated with
         * STATUS_BUFFER_OVERFLOW: drop it and keep receiving. A cancel that
         * is not from a close or a shutdown comes from the exit of the thread
         * that owned the receive: start a new one */
        if (Irp->IoStatus.Status == STATUS_BUFFER_OVERFLOW ||
            Irp->IoStatus.Status == STATUS_CANCELLED)
        {
            RelaunchPacketReceive(FCB);
        }

        SocketStateUnlock(FCB);
        return Irp->IoStatus.Status;
    }

    if (FCB->TdiReceiveClosed)
    {
        SocketStateUnlock(FCB);
        return STATUS_FILE_CLOSED;
    }

    /* A datagram without data takes nothing from the receive window, but each one still costs a
     * non-paged allocation: past a number of waiting datagrams it is dropped, as one that does not
     * fit the window is. (Only an empty datagram needs the count; the others fill the window.) */
    if( Irp->IoStatus.Information == 0 )
    {
        UINT Waiting = 0;

        for( ListEntry = FCB->DatagramList.Flink;
             ListEntry != &FCB->DatagramList && Waiting < AFD_MAX_QUEUED_EMPTY_DATAGRAMS;
             ListEntry = ListEntry->Flink )
        {
            Waiting++;
        }

        if( Waiting >= AFD_MAX_QUEUED_EMPTY_DATAGRAMS )
        {
            RelaunchPacketReceive(FCB);
            SocketStateUnlock( FCB );
            return STATUS_SUCCESS;
        }
    }

    DatagramRecv = ExAllocatePoolWithTag(NonPagedPool,
                                         DGSize,
                                         TAG_AFD_STORED_DATAGRAM);

    if( DatagramRecv ) {
        DatagramRecv->Len = Irp->IoStatus.Information;
        RtlCopyMemory( DatagramRecv->Buffer, FCB->Recv.Window,
                       DatagramRecv->Len );
        AFD_DbgPrint(MID_TRACE,("Received (A %p)\n",
                                FCB->AddressFrom->RemoteAddress));
        DatagramRecv->Address =
            TaCopyTransportAddress( FCB->AddressFrom->RemoteAddress );

        /* What the transport reported besides the source (AddressFrom->Options),
         * for a WSARecvMsg that asks for IP_PKTINFO. The next datagram starts clean. */
        DatagramRecv->PktInfo = FCB->RecvPktInfo;
        RtlZeroMemory( &FCB->RecvPktInfo, sizeof(FCB->RecvPktInfo) );

        if( !DatagramRecv->Address ) Status = STATUS_NO_MEMORY;

    } else Status = STATUS_NO_MEMORY;

    if( !NT_SUCCESS( Status ) ) {

        if (DatagramRecv)
        {
            ExFreePoolWithTag(DatagramRecv, TAG_AFD_STORED_DATAGRAM);
        }

        /* The datagram is lost, but later ones can still be received */
        RelaunchPacketReceive(FCB);

        SocketStateUnlock( FCB );
        return Status;
    } else {
        FCB->Recv.Content += DatagramRecv->Len;
        InsertTailList( &FCB->DatagramList, &DatagramRecv->ListEntry );
    }

    /* Satisfy as many requests as we can */

    while( !IsListEmpty( &FCB->DatagramList ) &&
           !IsListEmpty( &FCB->PendingIrpList[FUNCTION_RECV] ) ) {
        AFD_DbgPrint(MID_TRACE,("Looping trying to satisfy request\n"));
        ListEntry = RemoveHeadList( &FCB->DatagramList );
        DatagramRecv = CONTAINING_RECORD( ListEntry, AFD_STORED_DATAGRAM,
                                          ListEntry );
        ListEntry = RemoveHeadList( &FCB->PendingIrpList[FUNCTION_RECV] );
        NextIrp = CONTAINING_RECORD( ListEntry, IRP, Tail.Overlay.ListEntry );
        NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
        RecvReq = GetLockedData(NextIrp, NextIrpSp);

        AFD_DbgPrint(MID_TRACE,("RecvReq: %p, DatagramRecv: %p\n",
                                RecvReq, DatagramRecv));

        AFD_DbgPrint(MID_TRACE,("Satisfying\n"));
        Status = SatisfyPacketRecvRequest
        ( FCB, NextIrp, DatagramRecv,
         (PUINT)&NextIrp->IoStatus.Information );

        if (RecvReq->TdiFlags & TDI_RECEIVE_PEEK)
        {
            InsertHeadList(&FCB->DatagramList,
                           &DatagramRecv->ListEntry);
        }

        AFD_DbgPrint(MID_TRACE,("Unlocking\n"));
        UnlockBuffers( RecvReq->BufferArray, RecvReq->BufferCount, CheckUnlockExtraBuffers(FCB, NextIrpSp) );
        if ( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );

        AFD_DbgPrint(MID_TRACE,("Completing\n"));
        AfdClearCancelRoutine(NextIrp);
        NextIrp->IoStatus.Status = Status;

        IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
    }

    if( !IsListEmpty( &FCB->DatagramList ) && IsListEmpty(&FCB->PendingIrpList[FUNCTION_RECV]) ) {
        AFD_DbgPrint(MID_TRACE,("Signalling\n"));
        FCB->PollState |= AFD_EVENT_RECEIVE;
        FCB->PollStatus[FD_READ_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    } else
        FCB->PollState &= ~AFD_EVENT_RECEIVE;

    /* The receive that was kept after shutdown(SD_RECEIVE) is served */
    AfdCompleteReceiveShutdown(FCB);

    /* Now relaunch the datagram request */
    RelaunchPacketReceive(FCB);

    SocketStateUnlock( FCB );

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
AfdPacketSocketReadData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                        PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_RECV_INFO_UDP RecvReq;
    PAFD_RECV_INFO_MSG Msg = NULL;
    PLIST_ENTRY ListEntry;
    PAFD_STORED_DATAGRAM DatagramRecv;
    KPROCESSOR_MODE LockMode;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    FCB->EventSelectDisabled &= ~AFD_EVENT_RECEIVE;

    /* Check that the socket is bound */
    if( FCB->SharedData.State != SOCKET_STATE_BOUND )
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid socket state\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    if (FCB->TdiReceiveClosed)
    {
        AFD_DbgPrint(MIN_TRACE,("Receive closed\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_FILE_CLOSED, Irp, 0);
    }

    if( !AfdRequestLengthValid( Irp, IrpSp, sizeof(AFD_RECV_INFO_UDP) ) )
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    if( !(RecvReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) )
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    AFD_DbgPrint(MID_TRACE,("Recv flags %x\n", RecvReq->AfdFlags));

    /* WSARecvMsg: the control data pointers follow the AFD_RECV_INFO_UDP. They
     * were copied with the request; the structure must hold them. */
    if( RecvReq->AfdFlags & AFD_RECV_MSG ) {
        PAFD_RECV_INFO_MSG MsgReq = (PAFD_RECV_INFO_MSG)RecvReq;

        if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_RECV_INFO_MSG) ||
            (MsgReq->CmsgHdrSize != 12 && MsgReq->CmsgHdrSize != 16) ) {
            return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
        }
        Msg = MsgReq;
    }

    RecvReq->BufferArray = LockBuffers( RecvReq->BufferArray,
                                        RecvReq->BufferCount,
                                        RecvReq->Address,
                                        RecvReq->AddressLength,
                                        TRUE, TRUE, LockMode, Msg );

    if( !RecvReq->BufferArray ) { /* access violation in userspace */
        return UnlockAndMaybeComplete(FCB, STATUS_ACCESS_VIOLATION, Irp, 0);
    }

    if (!IsListEmpty(&FCB->DatagramList))
    {
        ListEntry = RemoveHeadList(&FCB->DatagramList);
        DatagramRecv = CONTAINING_RECORD(ListEntry, AFD_STORED_DATAGRAM, ListEntry);
        Status = SatisfyPacketRecvRequest(FCB, Irp, DatagramRecv,
                                          (PUINT)&Irp->IoStatus.Information);

        if (RecvReq->TdiFlags & TDI_RECEIVE_PEEK)
        {
            InsertHeadList(&FCB->DatagramList,
                           &DatagramRecv->ListEntry);
        }

        if (!IsListEmpty(&FCB->DatagramList))
        {
            FCB->PollState |= AFD_EVENT_RECEIVE;
            FCB->PollStatus[FD_READ_BIT] = STATUS_SUCCESS;
            PollReeval( FCB->DeviceExt, FCB->FileObject );
        }
        else
            FCB->PollState &= ~AFD_EVENT_RECEIVE;

        UnlockBuffers(RecvReq->BufferArray, RecvReq->BufferCount, TRUE);

        return UnlockAndMaybeComplete(FCB, Status, Irp, Irp->IoStatus.Information);
    }
    else if (!(RecvReq->AfdFlags & AFD_OVERLAPPED) &&
            ((RecvReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking)))
    {
        AFD_DbgPrint(MID_TRACE,("Nonblocking\n"));
        Status = STATUS_CANT_WAIT;
        FCB->PollState &= ~AFD_EVENT_RECEIVE;
        UnlockBuffers( RecvReq->BufferArray, RecvReq->BufferCount, TRUE );
        return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
    }
    else
    {
        FCB->PollState &= ~AFD_EVENT_RECEIVE;
        return LeaveIrpUntilLater( FCB, Irp, FUNCTION_RECV );
    }
}
