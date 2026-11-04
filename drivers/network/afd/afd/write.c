/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/write.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"

/* Largest user-supplied TDI transport address we accept for a datagram send.
 * msafd caps its own buffer at 128 bytes; every supported address type fits. */
#define AFD_MAX_SEND_TA_LENGTH 256

/* Caller-supplied buffer lengths are summed without wrapping: an overflow
 * would let a huge request pass the SendLength > SpaceAvail check. */
static __inline UINT AfdSaturatedAdd(UINT Total, UINT Add)
{
    return (Add > MAXULONG - Total) ? MAXULONG : Total + Add;
}

/* Copy the caller's destination TRANSPORT_ADDRESS into kernel memory and check
 * it. The pointer inside the (already captured) request is a raw user pointer,
 * so it is probed and read under SEH; afterwards only Captured is used. The
 * captured block is guaranteed to hold the address type's full TDI length. */
static
NTSTATUS
AfdCaptureSendAddress(PIRP Irp,
                      PTDI_CONNECTION_INFORMATION Info,
                      PVOID CapturedBuf,
                      PTRANSPORT_ADDRESS *Captured)
{
    PTRANSPORT_ADDRESS Source = Info->RemoteAddress;
    ULONG Length = Info->RemoteAddressLength;
    PTRANSPORT_ADDRESS Ta = CapturedBuf;
    UINT TypeLength;
    NTSTATUS Status = STATUS_SUCCESS;

    *Captured = NULL;

    /* Must at least hold the TRANSPORT_ADDRESS header plus the TA_ADDRESS header */
    if (!Source ||
        Length < sizeof(ULONG) + 2 * sizeof(USHORT) ||
        Length > AFD_MAX_SEND_TA_LENGTH)
        return STATUS_INVALID_PARAMETER;

    _SEH2_TRY {
        if (Irp->RequestorMode == UserMode)
            ProbeForRead(Source, Length, 1);
        RtlCopyMemory(Ta, Source, Length);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        Status = STATUS_ACCESS_VIOLATION;
    } _SEH2_END;

    if (!NT_SUCCESS(Status))
        return Status;

    if (Ta->TAAddressCount < 1)
        return STATUS_INVALID_PARAMETER;

    /* TdiBuildConnectionInfo copies the by-type length out of the address */
    TypeLength = TaLengthOfTransportAddressByType(Ta->Address[0].AddressType);
    if (TypeLength == 0 || TypeLength > Length)
        return STATUS_INVALID_PARAMETER;

    *Captured = Ta;
    return STATUS_SUCCESS;
}

/* The state of a stream send request kept in its IRP while it is queued:
 * DriverContext[2]  the length of a send that AFD completes whole (AFD_SEND_WHOLE), 0 otherwise
 * DriverContext[3]  the bytes of the request in the send window that are not sent yet
 * IoStatus.Information  the bytes of the request copied into the window so far
 * A whole send stays queued, and is refilled from, until all of it is copied and sent. */
static __inline VOID AfdSetSendState(PIRP Irp, UINT Total, UINT InWindow)
{
    Irp->Tail.Overlay.DriverContext[2] = (PVOID)(ULONG_PTR)Total;
    Irp->Tail.Overlay.DriverContext[3] = (PVOID)(ULONG_PTR)InWindow;
}

/* The request still has bytes to copy into the window */
static __inline BOOLEAN AfdSendNeedsFill(PIRP Irp)
{
    ULONG_PTR Total = (ULONG_PTR)Irp->Tail.Overlay.DriverContext[2];

    if (Total != 0)
        return Irp->IoStatus.Information < Total;
    /* A request that is not whole is queued whole-or-partial once, with its window bytes recorded */
    return Irp->Tail.Overlay.DriverContext[3] == NULL;
}

/* Whether a queued whole send still has bytes to copy: later sends must not overtake it */
static BOOLEAN AfdSendQueueHasRemainder(PAFD_FCB FCB)
{
    PLIST_ENTRY Entry;

    for (Entry = FCB->PendingIrpList[FUNCTION_SEND].Flink;
         Entry != &FCB->PendingIrpList[FUNCTION_SEND];
         Entry = Entry->Flink)
    {
        PIRP Queued = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        if ((ULONG_PTR)Queued->Tail.Overlay.DriverContext[2] != 0 && AfdSendNeedsFill(Queued))
            return TRUE;
    }
    return FALSE;
}

static IO_COMPLETION_ROUTINE SendComplete;

/* What follows a send to the transport that sent Sent bytes of the window: completes the requests
 * whose bytes are all sent, refills the window and sends what is in it. The socket state lock is held */
static
VOID
AfdSendCompleted
( PAFD_FCB FCB,
  NTSTATUS Status,
  ULONG_PTR Sent ) {
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp = NULL;
    PIO_STACK_LOCATION NextIrpSp;
    PAFD_SEND_INFO SendReq = NULL;
    PAFD_MAPBUF Map;
    SIZE_T TotalBytesCopied = 0, TotalBytesProcessed = 0, SpaceAvail, i;
    UINT SendLength, BytesCopied;
    SIZE_T Skip;
    BOOLEAN FillFailed;

    /*
     * We need the IRPs of the stream between usermode and AFD. Those are
     * chained from FCB->PendingIrpList[FUNCTION_SEND] and you'll see them in
     * the code below as "NextIrp" ('cause they are the next usermode IRP to
     * be processed).
     */

    if( FCB->SharedData.State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            SendReq = GetLockedData(NextIrp, NextIrpSp);
            NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
            NextIrp->IoStatus.Information = 0;
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
            if( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            AfdClearCancelRoutine(NextIrp);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }

        RetryDisconnectCompletion(FCB);

        return;
    }

    if( !NT_SUCCESS(Status) ) {
        /* Complete all following send IRPs with error */

        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry =
                RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp =
                CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
            SendReq = GetLockedData(NextIrp, NextIrpSp);

            UnlockBuffers( SendReq->BufferArray,
                           SendReq->BufferCount,
                           FALSE );

            NextIrp->IoStatus.Status = Status;
            NextIrp->IoStatus.Information = 0;

            if ( NextIrp->MdlAddress ) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            AfdClearCancelRoutine(NextIrp);
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }

        RetryDisconnectCompletion(FCB);

        return;
    }

    RtlMoveMemory( FCB->Send.Window,
                   FCB->Send.Window + Sent,
                   FCB->Send.BytesUsed - Sent );

    TotalBytesProcessed = 0;
    SendLength = (UINT)Sent;
    while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) && SendLength > 0) {
        NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
        NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
        SendReq = GetLockedData(NextIrp, NextIrpSp);

        TotalBytesCopied = (ULONG_PTR)NextIrp->Tail.Overlay.DriverContext[3];
        ASSERT(TotalBytesCopied != 0);

        /* If we didn't get enough, keep waiting */
        if (TotalBytesCopied > SendLength)
        {
            /* Update the bytes left to send */
            TotalBytesCopied -= SendLength;
            NextIrp->Tail.Overlay.DriverContext[3] = (PVOID)TotalBytesCopied;

            /* Update the state variables */
            FCB->Send.BytesUsed -= SendLength;
            TotalBytesProcessed += SendLength;
            SendLength = 0;

            /* Pend the IRP */
            InsertHeadList(&FCB->PendingIrpList[FUNCTION_SEND],
                           &NextIrp->Tail.Overlay.ListEntry);
            break;
        }

        FCB->Send.BytesUsed -= TotalBytesCopied;
        TotalBytesProcessed += TotalBytesCopied;
        SendLength -= TotalBytesCopied;

        /* All that was copied is sent, but a whole send has more to copy: it stays queued
         * and is refilled below, nothing can have been sent beyond it */
        if (AfdSendNeedsFill(NextIrp) && NextIrp->Tail.Overlay.DriverContext[2] != NULL)
        {
            NextIrp->Tail.Overlay.DriverContext[3] = NULL;
            InsertHeadList(&FCB->PendingIrpList[FUNCTION_SEND],
                           &NextIrp->Tail.Overlay.ListEntry);
            break;
        }

        ASSERT(NextIrp->IoStatus.Information != 0);

        NextIrp->IoStatus.Status = Status;

        AfdClearCancelRoutine(NextIrp);

        UnlockBuffers( SendReq->BufferArray,
                       SendReq->BufferCount,
                       FALSE );

        if (NextIrp->MdlAddress) UnlockRequest(NextIrp, NextIrpSp);

        IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);
    }

    /* Bytes beyond the requests queued belong to a request that was cancelled with them in the window */
    if (SendLength != 0)
    {
        FCB->Send.BytesUsed -= SendLength;
        SendLength = 0;
    }

    /* Copy into the window from the request at the head of the queue if it has bytes left to copy */
    if (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND])) {
        NextIrpEntry = FCB->PendingIrpList[FUNCTION_SEND].Flink;
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
        NextIrpSp = IoGetCurrentIrpStackLocation( NextIrp );
        SendReq = GetLockedData(NextIrp, NextIrpSp);
        Map = (PAFD_MAPBUF)(SendReq->BufferArray + SendReq->BufferCount);

        if (AfdSendNeedsFill(NextIrp)) {
            BOOLEAN Whole = NextIrp->Tail.Overlay.DriverContext[2] != NULL;
            BOOLEAN Fill = TRUE;

            AFD_DbgPrint(MID_TRACE,("SendReq @ %p\n", SendReq));

            SpaceAvail = FCB->Send.Size - FCB->Send.BytesUsed;
            TotalBytesCopied = 0;
            FillFailed = FALSE;

            /* Count the total transfer size and what of it is left */
            SendLength = 0;
            for (i = 0; i < SendReq->BufferCount; i++)
            {
                SendLength = AfdSaturatedAdd(SendLength, SendReq->BufferArray[i].len);
            }
            Skip = NextIrp->IoStatus.Information;
            SendLength -= (UINT)Skip;

            /* Make sure we've got the space */
            if (SendLength > SpaceAvail)
            {
               /* Blocking sockets have to wait here, but a whole send takes what there is */
               if (!Whole && SendLength <= FCB->Send.Size &&
                   !((SendReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking)))
               {
                   FCB->PollState &= ~AFD_EVENT_SEND;

                   Fill = FALSE;
               }

               /* Check if we can send anything */
               if (SpaceAvail == 0)
               {
                   FCB->PollState &= ~AFD_EVENT_SEND;

                   /* We should never be non-overlapped and get to this point */
                   ASSERT(SendReq->AfdFlags & AFD_OVERLAPPED);

                   Fill = FALSE;
               }
            }

            if (Fill)
            {
                for( i = 0; SpaceAvail > 0 && i < SendReq->BufferCount; i++ ) {
                    /* Zero-length (or NULL) WSABUFs have no MDL: nothing to copy */
                    if (Map[i].Mdl == NULL || SendReq->BufferArray[i].len == 0)
                        continue;

                    /* Skip what an earlier refill copied */
                    if (Skip >= SendReq->BufferArray[i].len)
                    {
                        Skip -= SendReq->BufferArray[i].len;
                        continue;
                    }

                    BytesCopied = MIN(SendReq->BufferArray[i].len - (UINT)Skip, SpaceAvail);

                    Map[i].BufferAddress =
                       MmMapLockedPagesSpecifyCache( Map[i].Mdl, KernelMode, MmCached,
                                                     NULL, FALSE, NormalPagePriority );
                    if (Map[i].BufferAddress == NULL)
                    {
                        FillFailed = TRUE;
                        break;
                    }

                    RtlCopyMemory( FCB->Send.Window + FCB->Send.BytesUsed,
                                   (PUCHAR)Map[i].BufferAddress + Skip,
                                   BytesCopied );

                    MmUnmapLockedPages( Map[i].BufferAddress, Map[i].Mdl );

                    Skip = 0;
                    TotalBytesCopied += BytesCopied;
                    SpaceAvail -= BytesCopied;
                    FCB->Send.BytesUsed += BytesCopied;
                }

                NextIrp->IoStatus.Information += TotalBytesCopied;
                NextIrp->Tail.Overlay.DriverContext[3] =
                    (PVOID)((ULONG_PTR)NextIrp->Tail.Overlay.DriverContext[3] + TotalBytesCopied);

                if (FillFailed)
                {
                    /* Out of resources: a whole send ends with what it has copied */
                    if (Whole)
                        NextIrp->Tail.Overlay.DriverContext[2] = (PVOID)NextIrp->IoStatus.Information;

                    if (NextIrp->Tail.Overlay.DriverContext[3] == NULL)
                    {
                        /* Nothing of it is in the window, so no completion would ever come */
                        RemoveEntryList(&NextIrp->Tail.Overlay.ListEntry);
                        NextIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                        AfdClearCancelRoutine(NextIrp);
                        UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
                        if (NextIrp->MdlAddress) UnlockRequest(NextIrp, NextIrpSp);
                        IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);
                    }
                }
            }
        }
    }

    if (FCB->Send.Size - FCB->Send.BytesUsed != 0 && !FCB->SendClosed &&
        IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]))
    {
        FCB->PollState |= AFD_EVENT_SEND;
        FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }
    else
    {
        FCB->PollState &= ~AFD_EVENT_SEND;
    }


    /* Some data is still waiting */
    if( FCB->Send.BytesUsed )
    {
        Status = TdiSend( &FCB->SendIrp.InFlightRequest,
                          FCB->Connection.Object,
                          0,
                          FCB->Send.Window,
                          FCB->Send.BytesUsed,
                          SendComplete,
                          FCB );
    }
    else
    {
        /* Nothing is waiting so try to complete a pending disconnect */
        RetryDisconnectCompletion(FCB);
    }

}

static NTSTATUS NTAPI SendComplete
( PDEVICE_OBJECT DeviceObject,
  PIRP Irp,
  PVOID Context ) {
    NTSTATUS Status = Irp->IoStatus.Status;
    ULONG_PTR Sent = Irp->IoStatus.Information;
    PAFD_FCB FCB = (PAFD_FCB)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    /*
     * The Irp parameter passed in is the IRP of the stream between AFD and
     * TDI driver. It's not very useful to us.
     */

    AFD_DbgPrint(MID_TRACE,("Called, status %x, %u bytes used\n",
                            Irp->IoStatus.Status,
                            Irp->IoStatus.Information));

    if( !SocketAcquireStateLock( FCB ) )
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->SendIrp.InFlightRequest == Irp);
    FCB->SendIrp.InFlightRequest = NULL;
    /* Request is not in flight any longer */

    if( FCB->SendCompleteActive ) {
        /* The transport finished a send inside the send that an outer call of this routine makes
         * (a loopback connection does): leave it to that call, which loops, so that the stack does
         * not grow with every window of a large send */
        FCB->SendDeferred = TRUE;
        FCB->SendDeferredStatus = Status;
        FCB->SendDeferredBytes = Sent;
        SocketStateUnlock( FCB );
        return STATUS_SUCCESS;
    }

    FCB->SendCompleteActive = TRUE;
    for(;;) {
        FCB->SendDeferred = FALSE;
        AfdSendCompleted( FCB, Status, Sent );
        if( !FCB->SendDeferred )
            break;
        Status = FCB->SendDeferredStatus;
        Sent = FCB->SendDeferredBytes;
    }
    FCB->SendCompleteActive = FALSE;

    SocketStateUnlock( FCB );

    return STATUS_SUCCESS;
}

/* The datagram of a cancelled send request is still in flight: it must not
 * complete whichever request now happens to head the list */
VOID AfdOrphanDatagramSend( PAFD_FCB FCB, PIRP Irp ) {
    PLIST_ENTRY Entry;

    for( Entry = FCB->DatagramSendList.Flink;
         Entry != &FCB->DatagramSendList;
         Entry = Entry->Flink ) {
        PAFD_DGRAM_SEND_CONTEXT Ctx =
            CONTAINING_RECORD(Entry, AFD_DGRAM_SEND_CONTEXT, ListEntry);
        if( Ctx->UserIrp == Irp )
            Ctx->UserIrp = NULL;
    }
}

/* Cancels every datagram still in the transport, each once. The socket state
 * lock is held. A cancel may complete its datagram inside IoCancelIrp, which
 * unlinks the entry (the lock is recursive), so the walk restarts after each. */
VOID AfdCancelDatagramSends( PAFD_FCB FCB ) {
    for(;;) {
        PLIST_ENTRY Entry;
        PAFD_DGRAM_SEND_CONTEXT Ctx = NULL;

        for( Entry = FCB->DatagramSendList.Flink;
             Entry != &FCB->DatagramSendList;
             Entry = Entry->Flink ) {
            PAFD_DGRAM_SEND_CONTEXT This =
                CONTAINING_RECORD(Entry, AFD_DGRAM_SEND_CONTEXT, ListEntry);
            if( !This->CancelRequested && This->TransportIrp ) {
                Ctx = This;
                break;
            }
        }
        if( !Ctx )
            return;
        Ctx->CancelRequested = TRUE;
        IoCancelIrp( Ctx->TransportIrp );
    }
}

static BOOLEAN DgramSendIsTracked( PAFD_FCB FCB, PAFD_DGRAM_SEND_CONTEXT Ctx ) {
    PLIST_ENTRY Entry;

    for( Entry = FCB->DatagramSendList.Flink;
         Entry != &FCB->DatagramSendList;
         Entry = Entry->Flink )
        if( CONTAINING_RECORD(Entry, AFD_DGRAM_SEND_CONTEXT, ListEntry) == Ctx )
            return TRUE;
    return FALSE;
}

static BOOLEAN DgramSendRequestQueued( PAFD_FCB FCB, PIRP Irp ) {
    PLIST_ENTRY Entry;

    for( Entry = FCB->PendingIrpList[FUNCTION_SEND].Flink;
         Entry != &FCB->PendingIrpList[FUNCTION_SEND];
         Entry = Entry->Flink )
        if( CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry) == Irp )
            return TRUE;
    return FALSE;
}

static IO_COMPLETION_ROUTINE PacketSocketSendComplete;
static NTSTATUS NTAPI PacketSocketSendComplete
( PDEVICE_OBJECT DeviceObject,
  PIRP Irp,
  PVOID Context ) {
    PAFD_DGRAM_SEND_CONTEXT Ctx = (PAFD_DGRAM_SEND_CONTEXT)Context;
    PAFD_FCB FCB = Ctx->FCB;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;
    PAFD_SEND_INFO SendReq;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called, status %x, %u bytes used\n",
                            Irp->IoStatus.Status,
                            Irp->IoStatus.Information));

    if( !SocketAcquireStateLock( FCB ) )
        return STATUS_FILE_CLOSED;

    /* This datagram is done; the request it belongs to is the one recorded
     * when it was sent (NULL when that request was cancelled meanwhile) */
    NextIrp = Ctx->UserIrp;
    RemoveEntryList( &Ctx->ListEntry );
    ExFreePoolWithTag( Ctx, TAG_AFD_DGRAM_SEND );

    /* Only clear the slot if it still names this request: another datagram
     * send may have replaced it while this one was in flight */
    if (FCB->SendIrp.InFlightRequest == Irp)
        FCB->SendIrp.InFlightRequest = NULL;
    /* Request is not in flight any longer */

    if( FCB->SharedData.State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
            /* its datagram may still be in flight: drop the stale pointer */
            AfdOrphanDatagramSend(FCB, NextIrp);
            SendReq = GetLockedData(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));
            NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
            NextIrp->IoStatus.Information = 0;
            AfdClearCancelRoutine(NextIrp);
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
            UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
            IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }
        SocketStateUnlock( FCB );
        return STATUS_FILE_CLOSED;
    }

    /* The owning request may be gone (cancelled, or completed by another
     * path); other requests stay queued for their own datagrams */
    if( !NextIrp || !DgramSendRequestQueued( FCB, NextIrp ) ) {
        AFD_DbgPrint(MIN_TRACE,("Datagram send completed with no pending request\n"));
        SocketStateUnlock( FCB );
        return STATUS_SUCCESS;
    }

    RemoveEntryList(&NextIrp->Tail.Overlay.ListEntry);

    SendReq = GetLockedData(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));

    NextIrp->IoStatus.Status = Irp->IoStatus.Status;
    NextIrp->IoStatus.Information = Irp->IoStatus.Information;

    AfdClearCancelRoutine(NextIrp);

    UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);

    UnlockRequest(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));

    IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);

    FCB->PollState |= AFD_EVENT_SEND;
    FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
    PollReeval(FCB->DeviceExt, FCB->FileObject);

    SocketStateUnlock(FCB);

    return STATUS_SUCCESS;
}

/* Queue a datagram send request and hand its datagram to the transport,
 * recording which request the datagram completes. Returns FALSE, with the
 * request untouched, when the record cannot be allocated. Otherwise the
 * request is pending (or already completed) and the caller returns
 * STATUS_PENDING. The socket state lock is held. */
static BOOLEAN AfdQueueDatagramSend
( PAFD_FCB FCB, PIRP Irp, PAFD_SEND_INFO_UDP SendReq,
  PTDI_CONNECTION_INFORMATION TargetAddress ) {
    NTSTATUS Status;
    PIRP SavedInFlight;
    PAFD_DGRAM_SEND_CONTEXT Ctx;

    Ctx = ExAllocatePoolWithTag( NonPagedPool, sizeof(*Ctx), TAG_AFD_DGRAM_SEND );
    if( !Ctx )
        return FALSE;
    Ctx->FCB = FCB;
    Ctx->UserIrp = Irp;
    Ctx->TransportIrp = NULL;
    Ctx->CancelRequested = FALSE;

    FCB->PollState &= ~AFD_EVENT_SEND;

    Status = QueueUserModeIrp(FCB, Irp, FUNCTION_SEND);
    if (Status != STATUS_PENDING)
    {
        /* Cancelled before it could be queued: completed by the cancel handler */
        ExFreePoolWithTag( Ctx, TAG_AFD_DGRAM_SEND );
        return TRUE;
    }

    if (SendReq->BufferCount > 1)
    {
        AFD_DbgPrint(MIN_TRACE,("WARN: More than one buffer %ld\n", SendReq->BufferCount));
    }

    InsertTailList( &FCB->DatagramSendList, &Ctx->ListEntry );
    /* A failed hand-off must not erase an earlier datagram's slot */
    SavedInFlight = FCB->SendIrp.InFlightRequest;
    Status = TdiSendDatagram(&FCB->SendIrp.InFlightRequest,
                             FCB->AddressFile.Object,
                             SendReq->BufferArray[0].buf,
                             SendReq->BufferArray[0].len,
                             TargetAddress,
                             PacketSocketSendComplete,
                             Ctx);
    if (Status == STATUS_PENDING)
    {
        /* The completion needs the state lock, which this thread holds, so the
         * record is still listed unless the transport completed it inline */
        if (DgramSendIsTracked( FCB, Ctx ))
            Ctx->TransportIrp = FCB->SendIrp.InFlightRequest;
        return TRUE;
    }

    /* Not pending: normally the transport never took the datagram and the
     * completion routine did not run. If it did run, it consumed Ctx and
     * completed the request. */
    if (DgramSendIsTracked( FCB, Ctx ))
    {
        RemoveEntryList( &Ctx->ListEntry );
        ExFreePoolWithTag( Ctx, TAG_AFD_DGRAM_SEND );
        FCB->SendIrp.InFlightRequest = SavedInFlight;
    }
    else
        return TRUE;

    /* Earlier datagrams may still be queued: unlink this request, not the head */
    if (DgramSendRequestQueued( FCB, Irp ))
    {
        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = ((Status == STATUS_SUCCESS) ? SendReq->BufferArray[0].len : 0);
        AfdClearCancelRoutine(Irp);
        UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
        UnlockRequest(Irp, IoGetCurrentIrpStackLocation(Irp));
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
    }
    return TRUE;
}

NTSTATUS NTAPI
AfdConnectedSocketWriteData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                            PIO_STACK_LOCATION IrpSp, BOOLEAN Short) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_SEND_INFO SendReq;
    UINT TotalBytesCopied = 0, i, SpaceAvail = 0, BytesCopied, SendLength;
    BOOLEAN Whole;
    KPROCESSOR_MODE LockMode;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Short);

    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    /* A datagram socket signals FD_WRITE when it is bound or connected, not on each send */
    if( !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) )
        FCB->EventSelectDisabled &= ~AFD_EVENT_SEND;

    if( FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS )
    {
        PAFD_SEND_INFO_UDP SendReq;
        PTDI_CONNECTION_INFORMATION TargetAddress;

        /* Without a peer there is nothing to send to, bound or not */
        if( !FCB->RemoteAddress )
        {
            return UnlockAndMaybeComplete( FCB, STATUS_INVALID_CONNECTION, Irp, 0 );
        }

        /* Check that the socket is bound */
        if( FCB->SharedData.State != SOCKET_STATE_BOUND )
        {
            AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
            return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp,
                                           0 );
        }

        /* Connected datagram sends use only the leading AFD_SEND_INFO fields */
        if( !AfdRequestLengthValid( Irp, IrpSp, FIELD_OFFSET(AFD_SEND_INFO_UDP, TdiRequest) ) )
            return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

        if( !(SendReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) )
            return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );

        /* The datagram is taken from BufferArray[0] below */
        if( SendReq->BufferCount == 0 )
            return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

        /* Must lock buffers before handing off user data */
        SendReq->BufferArray = LockBuffers( SendReq->BufferArray,
                                            SendReq->BufferCount,
                                            NULL, NULL,
                                            FALSE, FALSE, LockMode, NULL );

        if( !SendReq->BufferArray ) {
            return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION,
                                           Irp, 0 );
        }

        Status = TdiBuildConnectionInfo( &TargetAddress, FCB->RemoteAddress );

        if( NT_SUCCESS(Status) ) {
            if (!AfdQueueDatagramSend(FCB, Irp, SendReq, TargetAddress)) {
                ExFreePoolWithTag(TargetAddress, TAG_AFD_TDI_CONNECTION_INFORMATION);
                UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
                return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );
            }

            ExFreePoolWithTag(TargetAddress, TAG_AFD_TDI_CONNECTION_INFORMATION);

            SocketStateUnlock(FCB);

            return STATUS_PENDING;
        }
        else
        {
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
            return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
        }
    }

    if (FCB->PollState & AFD_EVENT_CLOSE)
    {
        AFD_DbgPrint(MIN_TRACE,("Connection reset by remote peer\n"));

        /* This is an unexpected remote disconnect */
        return UnlockAndMaybeComplete(FCB, FCB->PollStatus[FD_CLOSE_BIT], Irp, 0);
    }

    if (FCB->PollState & AFD_EVENT_ABORT)
    {
        AFD_DbgPrint(MIN_TRACE,("Connection aborted\n"));

        /* This is an abortive socket closure on our side */
        return UnlockAndMaybeComplete(FCB, FCB->PollStatus[FD_CLOSE_BIT], Irp, 0);
    }

    if (FCB->SendClosed)
    {
        AFD_DbgPrint(MIN_TRACE,("No more sends\n"));

        /* This is a graceful send closure */
        return UnlockAndMaybeComplete(FCB, STATUS_FILE_CLOSED, Irp, 0);
    }

    if( !AfdRequestLengthValid( Irp, IrpSp, sizeof(AFD_SEND_INFO) ) )
        return UnlockAndMaybeComplete
            ( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

    if( !(SendReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) )
        return UnlockAndMaybeComplete
            ( FCB, STATUS_NO_MEMORY, Irp, 0 );

    if( SendReq->BufferCount == 0 )
        return UnlockAndMaybeComplete
            ( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

    SendReq->BufferArray = LockBuffers( SendReq->BufferArray,
                                        SendReq->BufferCount,
                                        NULL, NULL,
                                        FALSE, FALSE, LockMode, NULL );

    if( !SendReq->BufferArray ) {
        return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION,
                                       Irp, 0 );
    }

    AFD_DbgPrint(MID_TRACE,("Socket state %u\n", FCB->SharedData.State));

    if( FCB->SharedData.State != SOCKET_STATE_CONNECTED ) {
        AFD_DbgPrint(MID_TRACE,("Socket not connected\n"));
        UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_CONNECTION, Irp, 0 );
    }

    AFD_DbgPrint(MID_TRACE,("FCB->Send.BytesUsed = %u\n",
                            FCB->Send.BytesUsed));

    SpaceAvail = FCB->Send.Size - FCB->Send.BytesUsed;

    AFD_DbgPrint(MID_TRACE,("We can accept %u bytes\n",
                            SpaceAvail));

    /* Count the total transfer size */
    SendLength = 0;
    for (i = 0; i < SendReq->BufferCount; i++)
    {
        SendLength = AfdSaturatedAdd(SendLength, SendReq->BufferArray[i].len);
    }

    /* A stream send that the caller has no thread to continue (an event or a completion port) stays
     * queued until all of it is copied, as on Windows, also for a socket in non-blocking mode (msafd
     * asks for it only for an overlapped send, a plain send on such a socket takes what fits). The count
     * saturates only for a request AFD could not describe anyway */
    Whole = (SendReq->AfdFlags & AFD_SEND_WHOLE) &&
            (SendReq->AfdFlags & AFD_OVERLAPPED) &&
            SendLength != MAXULONG;

    /* An earlier whole send that is not copied yet goes first */
    if (SendLength != 0 && AfdSendQueueHasRemainder(FCB))
        SpaceAvail = 0;

    /* Make sure we've got the space */
    if (SendLength > SpaceAvail)
    {
        /* Blocking sockets have to wait here */
        if (SendLength <= FCB->Send.Size && !((SendReq->AfdFlags & AFD_IMMEDIATE) || (FCB->NonBlocking)))
        {
            FCB->PollState &= ~AFD_EVENT_SEND;
            Irp->IoStatus.Information = 0;
            AfdSetSendState(Irp, Whole ? SendLength : 0, 0);
            return LeaveIrpUntilLater(FCB, Irp, FUNCTION_SEND);
        }

        /* Check if we can send anything */
        if (SpaceAvail == 0)
        {
            FCB->PollState &= ~AFD_EVENT_SEND;

            /* Non-overlapped sockets will fail if we can send nothing */
            if (!(SendReq->AfdFlags & AFD_OVERLAPPED))
            {
                UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );
                return UnlockAndMaybeComplete( FCB, STATUS_CANT_WAIT, Irp, 0 );
            }
            else
            {
                /* Overlapped sockets just pend */
                Irp->IoStatus.Information = 0;
                AfdSetSendState(Irp, Whole ? SendLength : 0, 0);
                return LeaveIrpUntilLater(FCB, Irp, FUNCTION_SEND);
            }
        }
    }

    for ( i = 0; SpaceAvail > 0 && i < SendReq->BufferCount; i++ )
    {
        BytesCopied = MIN(SendReq->BufferArray[i].len, SpaceAvail);

        AFD_DbgPrint(MID_TRACE,("Copying Buffer %u, %p:%u to %p\n",
                                i,
                                SendReq->BufferArray[i].buf,
                                BytesCopied,
                                FCB->Send.Window + FCB->Send.BytesUsed));

        RtlCopyMemory(FCB->Send.Window + FCB->Send.BytesUsed,
                      SendReq->BufferArray[i].buf,
                      BytesCopied);

        TotalBytesCopied += BytesCopied;
        SpaceAvail -= BytesCopied;
        FCB->Send.BytesUsed += BytesCopied;
    }

    Irp->IoStatus.Information = TotalBytesCopied;

    if( TotalBytesCopied == 0 ) {
        AFD_DbgPrint(MID_TRACE,("Empty send\n"));
        UnlockBuffers( SendReq->BufferArray, SendReq->BufferCount, FALSE );
        return UnlockAndMaybeComplete
        ( FCB, STATUS_SUCCESS, Irp, TotalBytesCopied );
    }

    if (SpaceAvail)
    {
        FCB->PollState |= AFD_EVENT_SEND;
        FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }
    else
    {
        FCB->PollState &= ~AFD_EVENT_SEND;
    }

    /* We use the IRP tail for some temporary storage here */
    AfdSetSendState(Irp, Whole ? SendLength : 0, TotalBytesCopied);

    Status = QueueUserModeIrp(FCB, Irp, FUNCTION_SEND);
    if (Status == STATUS_PENDING && !FCB->SendIrp.InFlightRequest)
    {
        TdiSend(&FCB->SendIrp.InFlightRequest,
                FCB->Connection.Object,
                0,
                FCB->Send.Window,
                FCB->Send.BytesUsed,
                SendComplete,
                FCB);
    }

    SocketStateUnlock(FCB);

    return STATUS_PENDING;
}

NTSTATUS NTAPI
AfdPacketSocketWriteData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                         PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_SUCCESS;
    PTDI_CONNECTION_INFORMATION TargetAddress;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_SEND_INFO_UDP SendReq;
    KPROCESSOR_MODE LockMode;
    PTRANSPORT_ADDRESS RemoteAddress;
    ULONG_PTR RemoteAddressBuf[(AFD_MAX_SEND_TA_LENGTH + sizeof(ULONG_PTR) - 1) / sizeof(ULONG_PTR)];

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    /* A datagram socket signals FD_WRITE when it is bound or connected, not on each send */
    if( !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) )
        FCB->EventSelectDisabled &= ~AFD_EVENT_SEND;

    /* Check that the socket is bound */
    if( FCB->SharedData.State != SOCKET_STATE_BOUND &&
        FCB->SharedData.State != SOCKET_STATE_CREATED)
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid socket state\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    if (FCB->SendClosed)
    {
        AFD_DbgPrint(MIN_TRACE,("No more sends\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_FILE_CLOSED, Irp, 0);
    }

    if( !AfdRequestLengthValid( Irp, IrpSp, sizeof(AFD_SEND_INFO_UDP) ) )
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    if( !(SendReq = LockRequest( Irp, IrpSp, FALSE, &LockMode )) )
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    /* The datagram is taken from BufferArray[0] below */
    if( SendReq->BufferCount == 0 )
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    /* The destination is a user pointer: capture and validate it once, and use
     * only the kernel copy from here on */
    Status = AfdCaptureSendAddress(Irp, &SendReq->TdiConnection,
                                   RemoteAddressBuf, &RemoteAddress);
    if( !NT_SUCCESS(Status) )
        return UnlockAndMaybeComplete(FCB, Status, Irp, 0);

    if (FCB->SharedData.State == SOCKET_STATE_CREATED)
    {
        if (FCB->LocalAddress)
        {
            ExFreePoolWithTag(FCB->LocalAddress, TAG_AFD_TRANSPORT_ADDRESS);
        }

        FCB->LocalAddress =
        TaBuildNullTransportAddress( RemoteAddress->Address[0].AddressType );

        if( FCB->LocalAddress ) {
            /* The explicit bind path builds AddressFrom before warming the
             * socket; the implicit bind must do the same. WarmSocketForBind
             * pre-posts a receive datagram with FCB->AddressFrom, and tcpip
             * dereferences it (DGReceiveDatagram), so leaving it NULL here
             * bugchecks the transport from an unbound raw sendto (T134). */
            if( FCB->AddressFrom )
                Status = STATUS_SUCCESS; /* kept from an earlier failed attempt: rebuilding would leak it */
            else
                Status = TdiBuildConnectionInfo( &FCB->AddressFrom,
                                                 FCB->LocalAddress );

            if( NT_SUCCESS(Status) )
                Status = WarmSocketForBind( FCB, AFD_SHARE_WILDCARD );

            if( NT_SUCCESS(Status) )
                FCB->SharedData.State = SOCKET_STATE_BOUND;
            else
                return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
        } else
            return UnlockAndMaybeComplete
            ( FCB, STATUS_NO_MEMORY, Irp, 0 );
    }

    SendReq->BufferArray = LockBuffers( SendReq->BufferArray,
                                        SendReq->BufferCount,
                                        NULL, NULL,
                                        FALSE, FALSE, LockMode, NULL );

    if( !SendReq->BufferArray )
        return UnlockAndMaybeComplete( FCB, STATUS_ACCESS_VIOLATION,
                                       Irp, 0 );

    AFD_DbgPrint
        (MID_TRACE,("RemoteAddress #%d Type %u\n",
                    RemoteAddress->TAAddressCount,
                    RemoteAddress->Address[0].AddressType));

    Status = TdiBuildConnectionInfo( &TargetAddress, RemoteAddress );

    /* Check the size of the Address given ... */

    if( NT_SUCCESS(Status) ) {
        if (!AfdQueueDatagramSend(FCB, Irp, SendReq, TargetAddress)) {
            ExFreePoolWithTag(TargetAddress, TAG_AFD_TDI_CONNECTION_INFORMATION);
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
            return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );
        }

        ExFreePoolWithTag(TargetAddress, TAG_AFD_TDI_CONNECTION_INFORMATION);

        SocketStateUnlock(FCB);

        return STATUS_PENDING;
    }
    else
    {
        UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, FALSE);
        return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
    }
}
