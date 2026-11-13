/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/listen.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"
#include "ntdef.h"

/* An accept completes into a fresh stream socket only: not bound, connected,
 * listening or claimed by another accept, with no transport objects of its
 * own, and not the listener. Anything else would overwrite a live connection
 * and its in-flight receive. Windows fails such an AcceptEx with WSAEINVAL and
 * leaves the connection queued. Called with AcceptFcb's state lock held. */
static BOOLEAN AfdIsFreshAcceptSocket(PAFD_FCB ListenFcb, PAFD_FCB AcceptFcb)
{
    return AcceptFcb != ListenFcb &&
           AcceptFcb->SharedData.State == SOCKET_STATE_CREATED &&
           !(AcceptFcb->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
           !AcceptFcb->Connection.Object &&
           !AcceptFcb->AddressFile.Object;
}

static VOID ReleaseListenConnection(PAFD_FCB FCB);

/* Lock-free first look at a candidate accept socket, taken before its mutex
 * so that a socket that can never qualify is rejected without waiting on it.
 * The authoritative check is AfdIsFreshAcceptSocket under the lock. */
static BOOLEAN AfdMayBeFreshAcceptSocket(PAFD_FCB ListenFcb, PAFD_FCB AcceptFcb)
{
    return AcceptFcb != ListenFcb &&
           *(volatile ULONG *)&AcceptFcb->SharedData.State == SOCKET_STATE_CREATED;
}

/* Take the accept socket's lock while holding the listener's. Waiting here
 * could deadlock two listeners that accept into each other from two threads
 * (the wait is not alertable, so the threads could not even be killed), so the
 * lock is only tried: a socket that is busy is not a fresh, idle socket. */
static BOOLEAN AfdTryLockAcceptSocket(PAFD_FCB AcceptFcb)
{
    LARGE_INTEGER NoWait;

    NoWait.QuadPart = 0;
    return KeWaitForMutexObject(&AcceptFcb->Mutex, Executive, KernelMode,
                                FALSE, &NoWait) == STATUS_SUCCESS;
}

static NTSTATUS SatisfyAccept(PAFD_DEVICE_EXTENSION DeviceExt,
                              PIRP Irp,
                              PFILE_OBJECT NewFileObject,
                              PAFD_TDI_OBJECT_QELT Qelt,
                              BOOL SuperAccept)
{
    PAFD_FCB FCB = NewFileObject->FsContext;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceExt);

    /* SatisfySuperAccept completes the IRP itself */
    if (!SocketAcquireStateLock(FCB))
        return SuperAccept ? STATUS_FILE_CLOSED : LostSocket( Irp );

    /* Transfer the connection to the new socket, launch the opening read */
    AFD_DbgPrint(MID_TRACE,("Completing a real accept (FCB %p)\n", FCB));

    FCB->Connection = Qelt->Object;

    if (FCB->RemoteAddress)
    {
        ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);
    }

    FCB->RemoteAddress =
        TaCopyTransportAddress( Qelt->ConnInfo->RemoteAddress );

    if( !FCB->RemoteAddress )
        Status = STATUS_NO_MEMORY;
    else
        Status = MakeSocketIntoConnection(FCB, !SuperAccept);

    if (NT_SUCCESS(Status))
        Status = TdiBuildConnectionInfo(&FCB->ConnectCallInfo, FCB->RemoteAddress);

    if (NT_SUCCESS(Status))
        Status = TdiBuildConnectionInfo(&FCB->ConnectReturnInfo, FCB->RemoteAddress);

    /* A failure before the socket became a connection leaves it as it was, so
     * it can be used for another accept: the connection taken from the listener
     * is dropped (the peer sees it closed) rather than kept in FCB->Connection.
     * Once the socket is CONNECTED (receive started), the connection stays with
     * it and is consumed; the accept fails and the socket is closed by the caller. */
    if (!NT_SUCCESS(Status) && FCB->SharedData.State != SOCKET_STATE_CONNECTED)
        ReleaseListenConnection(FCB);

    if (SuperAccept)
    {
        SocketStateUnlock(FCB);
        return Status;
    }

    /* AfdAccept claimed the socket (CONNECTING); a failure before it became a
     * connection releases the claim, as SatisfySuperAccept does */
    if (!NT_SUCCESS(Status) && FCB->SharedData.State != SOCKET_STATE_CONNECTED)
        FCB->SharedData.State = SOCKET_STATE_CREATED;

    return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
}

static NTSTATUS SatisfyPreAccept( PIRP Irp, PAFD_TDI_OBJECT_QELT Qelt ) {
    PAFD_RECEIVED_ACCEPT_DATA ListenReceive =
        (PAFD_RECEIVED_ACCEPT_DATA)Irp->AssociatedIrp.SystemBuffer;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
    PTA_IP_ADDRESS IPAddr;
    /* METHOD_BUFFERED: the system buffer must hold both the address we copy and the
     * length we report back, else the I/O manager overruns the user buffer. */
    ULONG CopyLen = TaLengthOfTransportAddress( Qelt->ConnInfo->RemoteAddress );
    ULONG RequiredSize = FIELD_OFFSET(AFD_RECEIVED_ACCEPT_DATA, Address) +
                         (CopyLen > sizeof(TA_IP_ADDRESS) ? CopyLen : sizeof(TA_IP_ADDRESS));

    if( IrpSp->Parameters.DeviceIoControl.OutputBufferLength < RequiredSize ) {
        if (AfdRequestLocked(Irp)) UnlockRequest( Irp, IoGetCurrentIrpStackLocation( Irp ) );
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        AfdClearCancelRoutine( Irp );
        IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
        return STATUS_BUFFER_TOO_SMALL;
    }

    ListenReceive->SequenceNumber = Qelt->Seq;

    AFD_DbgPrint(MID_TRACE,("Giving SEQ %u to userland\n", Qelt->Seq));
    AFD_DbgPrint(MID_TRACE,("Socket Address (K) %p (U) %p\n",
                            &ListenReceive->Address,
                            Qelt->ConnInfo->RemoteAddress));

    TaCopyTransportAddressInPlace( &ListenReceive->Address,
                                   Qelt->ConnInfo->RemoteAddress );

    IPAddr = (PTA_IP_ADDRESS)&ListenReceive->Address;

    AFD_DbgPrint(MID_TRACE,("IPAddr->TAAddressCount %d\n",
                            IPAddr->TAAddressCount));
    AFD_DbgPrint(MID_TRACE,("IPAddr->Address[0].AddressType %u\n",
                            IPAddr->Address[0].AddressType));
    AFD_DbgPrint(MID_TRACE,("IPAddr->Address[0].AddressLength %u\n",
                            IPAddr->Address[0].AddressLength));
    AFD_DbgPrint(MID_TRACE,("IPAddr->Address[0].Address[0].sin_port %x\n",
                            IPAddr->Address[0].Address[0].sin_port));
    AFD_DbgPrint(MID_TRACE,("IPAddr->Address[0].Address[0].sin_addr %x\n",
                            IPAddr->Address[0].Address[0].in_addr));

    if (AfdRequestLocked(Irp)) UnlockRequest( Irp, IoGetCurrentIrpStackLocation( Irp ) );

    Irp->IoStatus.Information = ((PCHAR)&IPAddr[1]) - ((PCHAR)ListenReceive);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    AfdClearCancelRoutine(Irp);
    IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
    return STATUS_SUCCESS;
}

VOID FreeQueuedConnection(PAFD_TDI_OBJECT_QELT Qelt)
{
    if (Qelt->ConnInfo)
        ExFreePoolWithTag(Qelt->ConnInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
    ExFreePoolWithTag(Qelt, TAG_AFD_ACCEPT_QUEUE);
}

/* Release the AcceptEx output-buffer MDL kept in DriverContext[3], locked or not */
static VOID AfdFreeAcceptMdl(PIRP Irp)
{
    PMDL Mdl = (PMDL)Irp->Tail.Overlay.DriverContext[3];

    if (!Mdl)
        return;
    if (Mdl->MdlFlags & MDL_PAGES_LOCKED)
        MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    Irp->Tail.Overlay.DriverContext[3] = NULL;
}

static NTSTATUS SatisfySuperAccept(PAFD_FCB FCB, PIRP Irp, PAFD_TDI_OBJECT_QELT Qelt)
{
    PFILE_OBJECT NewFileObject = (PFILE_OBJECT)Irp->Tail.Overlay.DriverContext[2];
    PAFD_SUPER_ACCEPT_INFO AcceptInfo = (PAFD_SUPER_ACCEPT_INFO)Irp->Tail.Overlay.DriverContext[0]; /* LockRequest stores the request in index 0 */
    PAFD_FCB FCB2 = NewFileObject->FsContext;
    NTSTATUS Status;

    /* The accepted socket keeps the listener's SO_RCVBUF unless it has its own */
    if (!FCB2->RecvHint)
        FCB2->RecvHint = FCB->RecvHint;

    Status = SatisfyAccept(NULL, Irp, NewFileObject, Qelt, TRUE);

    /* The accept socket may be closed meanwhile; keep it referenced while FCB2 is used */
    Irp->Tail.Overlay.DriverContext[2] = NULL;
    if (!NT_SUCCESS(Status))
        goto end;

    BYTE *BufferPtr = MmGetSystemAddressForMdlSafe((PMDL)Irp->Tail.Overlay.DriverContext[3], NormalPagePriority);
    if (!BufferPtr)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    /* The initial data goes first, then the local and the remote address */
    PCHAR ReceiveData = (PCHAR)BufferPtr;

    /* Query TCPIP to find the local address of the socket */
    LONG RequestSize = (FIELD_OFFSET(TDI_ADDRESS_INFO, Address.Address[0].Address) + FCB->LocalAddress->Address[0].AddressLength);
    PTRANSPORT_ADDRESS RemoteAddress = (PTRANSPORT_ADDRESS)Qelt->ConnInfo->RemoteAddress;
    PTDI_ADDRESS_INFO Buffer = ExAllocatePoolWithTag(NonPagedPool, RequestSize, 'bufT');
    if (Buffer == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    PMDL Mdl = IoAllocateMdl(Buffer, RequestSize, FALSE, FALSE, NULL);
    if (Mdl == NULL)
    {
        ExFreePool(Buffer);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    _SEH2_TRY
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Nothing was locked and the MDL was never handed off: it is still ours */
        Status = _SEH2_GetExceptionCode();
        IoFreeMdl(Mdl);
        ExFreePool(Buffer);
        goto end;
    }
    _SEH2_END;

    /* TdiQueryInformation takes ownership of the locked MDL (see the note there):
     * the transport request unlocks and frees it, on success and on failure.
     * The query is synchronous, so Buffer is ours again when it returns. */
    Status = TdiQueryInformation(
        Qelt->Object.Object, TDI_QUERY_ADDRESS_INFO, Mdl);
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(Buffer);
        goto end;
    }

    /* The transport files the accepted connection under the listener's binding,
     * which has no concrete address when the listener is bound to the wildcard:
     * report the address of the interface the peer is reached through */
    if (Buffer->Address.TAAddressCount == 1 &&
        Buffer->Address.Address[0].AddressType == TDI_ADDRESS_TYPE_IP &&
        RemoteAddress->TAAddressCount == 1 &&
        RemoteAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP)
    {
        PTDI_ADDRESS_IP LocalIp = (PTDI_ADDRESS_IP)Buffer->Address.Address[0].Address;
        PTDI_ADDRESS_IP RemoteIp = (PTDI_ADDRESS_IP)RemoteAddress->Address[0].Address;
        ULONG Source;

        if (LocalIp->in_addr == 0 && RemoteIp->in_addr != 0 &&
            NT_SUCCESS(AfdQueryRouteSourceOn(Qelt->Object.Object, RemoteIp->in_addr, &Source)))
            LocalIp->in_addr = Source;
    }

    /* Each address area holds a sockaddr (the address type and the address) and
     * ends in a USHORT with its length; an area too small for that gets nothing */
    BufferPtr += AcceptInfo->ReceiveDataLength;
    if (AcceptInfo->LocalAddressLength >= sizeof(USHORT))
    {
        LONG LocalAddressLength = min(AcceptInfo->LocalAddressLength - sizeof(USHORT),
                                      sizeof(USHORT) + min(Buffer->Address.Address->AddressLength,
                                                           FCB->LocalAddress->Address[0].AddressLength));
        RtlCopyMemory(BufferPtr, &Buffer->Address.Address->AddressType, LocalAddressLength);
        *(USHORT *)(BufferPtr + AcceptInfo->LocalAddressLength - sizeof(USHORT)) = LocalAddressLength;
    }
    ExFreePool(Buffer);

    BufferPtr += AcceptInfo->LocalAddressLength;
    if (AcceptInfo->RemoteAddressLength >= sizeof(USHORT))
    {
        LONG RemoteAddressLength = min(AcceptInfo->RemoteAddressLength - sizeof(USHORT),
                                       sizeof(USHORT) + RemoteAddress->Address[0].AddressLength);
        RtlCopyMemory(BufferPtr, &RemoteAddress->Address[0].AddressType, RemoteAddressLength);
        *(USHORT *)(BufferPtr + AcceptInfo->RemoteAddressLength - sizeof(USHORT)) = RemoteAddressLength;
    }

    if (AcceptInfo->ReceiveDataLength)
    {
        /* Save this IRP so that it can be completed once the data is received */
        FCB2->AcceptIrp = Irp;

        Status = TdiReceive(&FCB2->ReceiveIrp.InFlightRequest,
                            FCB2->Connection.Object, TDI_RECEIVE_NORMAL,
                            ReceiveData,
                            AcceptInfo->ReceiveDataLength,
                            AcceptExReceiveComplete,
                            FCB2);

        /* The completion routine never runs for a receive that was not sent */
        if (Status != STATUS_PENDING)
        {
            FCB2->AcceptIrp = NULL;
            goto end;
        }

        if (Status == STATUS_PENDING)
            Status = STATUS_SUCCESS;
        /* See the end of this function */
        ObDereferenceObjectDeferDelete(NewFileObject);
        return Status;
    }
    else
    {
        /* Begin receive buffer */
        Status = TdiReceive(
            &FCB2->ReceiveIrp.InFlightRequest,
            FCB2->Connection.Object,
            TDI_RECEIVE_NORMAL,
            FCB2->Recv.Window,
            FCB2->Recv.Size,
            ReceiveComplete,
            FCB2);

        if (Status == STATUS_PENDING)
            Status = STATUS_SUCCESS;
    }

end:
    /* Complete the IRP, there is no data to receive */
    if (NT_SUCCESS(Status))
    {
        FCB2->SharedData.State = SOCKET_STATE_CONNECTED;
    }
    else
    {
        /* A socket made into a connection (windows allocated) keeps it and cannot accept again */
        if (FCB2->SharedData.State != SOCKET_STATE_CONNECTED)
            FCB2->SharedData.State = SOCKET_STATE_CREATED;
    }
    
    AfdFreeAcceptMdl(Irp);
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;
    if (AfdRequestLocked(Irp)) UnlockRequest( Irp, IoGetCurrentIrpStackLocation( Irp ) );
    AfdClearCancelRoutine(Irp);
    IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );

    /* This runs on a delayed worker or in a transport completion. If the
     * application closed the accepted socket, this is its last reference, and
     * its close waits for transport completions that may need this very
     * worker; the object manager's reaper runs that close instead */
    ObDereferenceObjectDeferDelete(NewFileObject);

    return STATUS_SUCCESS;
}

static IO_COMPLETION_ROUTINE ListenComplete;

/* Connections waiting for an accept count against the listen backlog */
static ULONG CountPendingConnections(PAFD_FCB FCB)
{
    PLIST_ENTRY Entry;
    ULONG Count = 0;

    for (Entry = FCB->PendingConnections.Flink;
         Entry != &FCB->PendingConnections;
         Entry = Entry->Flink)
        Count++;

    return Count;
}

static NTSTATUS IssueListen(PAFD_FCB FCB)
{
    NTSTATUS Status;
    ULONG Room;

    Status = TdiBuildNullConnectionInfoInPlace(FCB->ListenIrp.ConnectionCallInfo,
                                               FCB->LocalAddress->Address[0].AddressType);
    ASSERT(Status == STATUS_SUCCESS);

    Status = TdiBuildNullConnectionInfoInPlace(FCB->ListenIrp.ConnectionReturnInfo,
                                               FCB->LocalAddress->Address[0].AddressType);
    ASSERT(Status == STATUS_SUCCESS);

    /* The listen request states how many connections the queue has room for, so tcpip refuses the
       ones beyond it before it answers them, as Windows does */
    Room = CountPendingConnections(FCB);
    Room = Room < FCB->Backlog ? FCB->Backlog - Room : 1;

    Status = TdiListenEx( &FCB->ListenIrp.InFlightRequest,
                          FCB->Connection.Object,
                          &FCB->ListenIrp.ConnectionCallInfo,
                          &FCB->ListenIrp.ConnectionReturnInfo,
                          ListenComplete,
                          FCB,
                          (ULONG)min(Room, 0x7FFF) << 16 );

    if (Status == STATUS_PENDING)
        Status = STATUS_SUCCESS;

    return Status;
}

static NTSTATUS ListenAgain(PAFD_FCB FCB)
{
    NTSTATUS Status;

    /* Launch new accept socket */
    Status = WarmSocketForConnection( FCB );

    if (NT_SUCCESS(Status))
        Status = IssueListen(FCB);

    return Status;
}

static VOID ReleaseListenConnection(PAFD_FCB FCB)
{
    if (FCB->Connection.Object)
    {
        TdiDisassociateAddressFile(FCB->Connection.Object);
        ObDereferenceObject(FCB->Connection.Object);
        ZwClose(FCB->Connection.Handle);
        FCB->Connection.Object = NULL;
        FCB->Connection.Handle = INVALID_HANDLE_VALUE;
    }
}

VOID FreeListenConnectionInfo(PAFD_FCB FCB)
{
    if (FCB->ListenIrp.ConnectionReturnInfo)
    {
        ExFreePoolWithTag(FCB->ListenIrp.ConnectionReturnInfo,
                          TAG_AFD_TDI_CONNECTION_INFORMATION);

        FCB->ListenIrp.ConnectionReturnInfo = NULL;
    }

    if (FCB->ListenIrp.ConnectionCallInfo)
    {
        ExFreePoolWithTag(FCB->ListenIrp.ConnectionCallInfo,
                          TAG_AFD_TDI_CONNECTION_INFORMATION);

        FCB->ListenIrp.ConnectionCallInfo = NULL;
    }
}

#define AFD_RELISTEN_ATTEMPTS 5

static IO_WORKITEM_ROUTINE RelistenWorker;
static VOID NTAPI RelistenWorker(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PAFD_FCB FCB = Context;
    LARGE_INTEGER Delay;
    NTSTATUS Status;
    ULONG Attempt;

    UNREFERENCED_PARAMETER(DeviceObject);

    Delay.QuadPart = -100LL * 10000; /* 100 ms */

    SocketAcquireStateLock(FCB);

    if (FCB->ListenConnectionReady)
    {
        /* First listen: AfdListenSocket opened the connection and reports a failure, no retry */
        FCB->Relistening = TRUE;
        FCB->ListenStatus = STATUS_SUCCESS;
        Status = IssueListen(FCB);
        if (!NT_SUCCESS(Status))
            FCB->ListenStatus = Status;
        FCB->ListenConnectionReady = FALSE;
        FCB->Relistening = FALSE;
    }
    else
    {
        for (Attempt = 1; FCB->SharedData.State == SOCKET_STATE_LISTENING; Attempt++)
        {
            /* A full queue waits for an accept */
            if (CountPendingConnections(FCB) >= FCB->Backlog)
                break;

            /* A listen that fails before TdiListen returns is retried here, not queued again */
            FCB->Relistening = TRUE;
            ReleaseListenConnection(FCB);
            ListenAgain(FCB);
            FCB->Relistening = FALSE;

            if (FCB->ListenIrp.InFlightRequest)
                break;

            if (Attempt == AFD_RELISTEN_ATTEMPTS)
            {
                /* The socket is left without a listen, as it was before the retries */
                AFD_DbgPrint(MIN_TRACE,("Could not listen on %p\n", FCB));
                break;
            }

            /* Let a transient failure clear; closing the socket meanwhile ends the retries */
            SocketStateUnlock(FCB);
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            SocketAcquireStateLock(FCB);
        }
    }

    /* Set under the lock: AfdCloseSocket waits for the event, then for the lock */
    KeSetEvent(&FCB->RelistenIdle, IO_NO_INCREMENT, FALSE);
    SocketStateUnlock(FCB);
}

/* An accept made room in a full queue that stopped listening: listen again from a system thread */
static VOID ResumeListen(PAFD_FCB FCB)
{
    if (FCB->SharedData.State != SOCKET_STATE_LISTENING || FCB->ListenIrp.InFlightRequest ||
        FCB->Relistening || !KeReadStateEvent(&FCB->RelistenIdle) ||
        CountPendingConnections(FCB) >= FCB->Backlog)
    {
        return;
    }

    KeClearEvent(&FCB->RelistenIdle);
    IoQueueWorkItem(FCB->RelistenWorkItem, RelistenWorker, DelayedWorkQueue, FCB);
}

/* Hands queued connections to waiting AcceptEx requests from a system thread:
 * SatisfySuperAccept issues the accepted socket's first receive, and the I/O
 * manager cancels a request issued on a caller's thread when that thread exits */
static IO_WORKITEM_ROUTINE AcceptWorker;
static VOID NTAPI AcceptWorker(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    PAFD_FCB FCB = Context;
    PLIST_ENTRY Entry, PendingConn;
    PAFD_TDI_OBJECT_QELT Qelt;
    PIRP Irp;

    UNREFERENCED_PARAMETER(DeviceObject);

    SocketAcquireStateLock(FCB);

    if (FCB->SharedData.State == SOCKET_STATE_LISTENING)
    {
        Entry = FCB->PendingIrpList[FUNCTION_PREACCEPT].Flink;
        while (Entry != &FCB->PendingIrpList[FUNCTION_PREACCEPT] &&
               !IsListEmpty(&FCB->PendingConnections))
        {
            Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
            Entry = Entry->Flink;

            /* Skip waits for a connection, and leave a cancelled request to AfdCancelHandler */
            if (!Irp->Tail.Overlay.DriverContext[2] || !Irp->Tail.Overlay.DriverContext[3] || Irp->Cancel)
                continue;

            RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
            PendingConn = RemoveHeadList(&FCB->PendingConnections);
            Qelt = CONTAINING_RECORD(PendingConn, AFD_TDI_OBJECT_QELT, ListEntry);
            SatisfySuperAccept(FCB, Irp, Qelt);
            FreeQueuedConnection(Qelt);
        }

        ResumeListen(FCB);

        if (!IsListEmpty(&FCB->PendingConnections))
        {
            FCB->PollState |= AFD_EVENT_ACCEPT;
            FCB->PollStatus[FD_ACCEPT_BIT] = STATUS_SUCCESS;
            PollReeval(FCB->DeviceExt, FCB->FileObject);
        }
        else
        {
            FCB->PollState &= ~AFD_EVENT_ACCEPT;
        }
    }

    /* Set under the lock: AfdCloseSocket waits for the event, then for the lock */
    FCB->AcceptWorkQueued = FALSE;
    KeSetEvent(&FCB->AcceptWorkIdle, IO_NO_INCREMENT, FALSE);
    SocketStateUnlock(FCB);
}

static NTSTATUS NTAPI ListenComplete( PDEVICE_OBJECT DeviceObject,
                                      PIRP Irp,
                                      PVOID Context ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PAFD_FCB FCB = (PAFD_FCB)Context;
    PAFD_TDI_OBJECT_QELT Qelt;
    BOOLEAN Queued = FALSE;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) )
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->ListenIrp.InFlightRequest == Irp);
    FCB->ListenIrp.InFlightRequest = NULL;

    if( FCB->SharedData.State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_PREACCEPT] ) ) {
           NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_PREACCEPT]);
           NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
           NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
           NextIrp->IoStatus.Information = 0;
           if (AfdRequestLocked(NextIrp)) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
           AfdClearCancelRoutine(NextIrp);
           IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }

        FreeListenConnectionInfo(FCB);

        SocketStateUnlock( FCB );
        return STATUS_FILE_CLOSED;
    }

    AFD_DbgPrint(MID_TRACE,("Completing listen request.\n"));
    AFD_DbgPrint(MID_TRACE,("IoStatus was %x\n", Irp->IoStatus.Status));

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
    {
        /* The worker listens again and retries; no TDI call runs in this failure path */
        if (FCB->Relistening)
        {
            /* The worker issued this listen; record a failed first listen for AfdListenSocket */
            if (FCB->ListenConnectionReady)
                FCB->ListenStatus = Irp->IoStatus.Status;
        }
        else
        {
            KeClearEvent(&FCB->RelistenIdle);
            IoQueueWorkItem(FCB->RelistenWorkItem, RelistenWorker, DelayedWorkQueue, FCB);
        }

        SocketStateUnlock(FCB);
        return Irp->IoStatus.Status;
    }

    /* A full queue takes no more connections. Drop this one, which the peer
     * sees closed, and listen again: a listener that stopped listening would
     * have tcpip park the next connections beyond the backlog. */
    if (CountPendingConnections(FCB) >= FCB->Backlog)
        Qelt = NULL;
    else
        Qelt = ExAllocatePoolWithTag(NonPagedPool,
                                     sizeof(*Qelt),
                                     TAG_AFD_ACCEPT_QUEUE);

    if( !Qelt ) {
        Status = STATUS_NO_MEMORY;
    } else {
        UINT AddressType =
            FCB->LocalAddress->Address[0].AddressType;

        Qelt->Object = FCB->Connection;
        FCB->Connection.Object = NULL;
        FCB->Connection.Handle = INVALID_HANDLE_VALUE;
        Qelt->Seq = FCB->ConnSeq++;
        AFD_DbgPrint(MID_TRACE,("Address Type: %u (RA %p)\n",
                                AddressType,
                                FCB->ListenIrp.
                                ConnectionReturnInfo->RemoteAddress));

        Status = TdiBuildNullConnectionInfo( &Qelt->ConnInfo, AddressType );
        if( NT_SUCCESS(Status) ) {
            TaCopyTransportAddressInPlace
               ( Qelt->ConnInfo->RemoteAddress,
                 FCB->ListenIrp.ConnectionReturnInfo->RemoteAddress );
            InsertTailList( &FCB->PendingConnections, &Qelt->ListEntry );
            Queued = TRUE;
        } else {
            FCB->Connection = Qelt->Object;
            ExFreePoolWithTag(Qelt, TAG_AFD_ACCEPT_QUEUE);
        }
    }

    /* Satisfy a pre-accept request if one is available; a dropped connection
     * satisfies none, the queued ones were offered already */
    if( Queued &&
        !IsListEmpty( &FCB->PendingIrpList[FUNCTION_PREACCEPT] ) &&
        !IsListEmpty( &FCB->PendingConnections ) ) {
        PLIST_ENTRY PendingIrp  =
            RemoveHeadList( &FCB->PendingIrpList[FUNCTION_PREACCEPT] );
        PLIST_ENTRY PendingConn = FCB->PendingConnections.Flink;
        PIRP PendingIrpPtr = CONTAINING_RECORD(PendingIrp, IRP, Tail.Overlay.ListEntry);
        PAFD_TDI_OBJECT_QELT ConnectionData = CONTAINING_RECORD( PendingConn, AFD_TDI_OBJECT_QELT, ListEntry);
        if (PendingIrpPtr->Tail.Overlay.DriverContext[2] && PendingIrpPtr->Tail.Overlay.DriverContext[3])
        {
            RemoveEntryList(PendingConn);
            SatisfySuperAccept(FCB, PendingIrpPtr, ConnectionData);
            FreeQueuedConnection(ConnectionData);
        }
        else
        {
            SatisfyPreAccept(PendingIrpPtr, ConnectionData);
        }
    }

    /* Drop a connection that could not be queued for accept */
    ReleaseListenConnection(FCB);

    /* tcpip completes a listen from a worker thread, at PASSIVE_LEVEL, so listen again here. A full
     * queue does not listen: tcpip then refuses the connections the queue has no room for, and
     * the accept that makes room listens again */
    if (CountPendingConnections(FCB) >= FCB->Backlog)
        Status = STATUS_SUCCESS;
    else
        Status = ListenAgain(FCB);

    /* The worker retries a listen that could not be issued here */
    if (!NT_SUCCESS(Status) && !FCB->Relistening)
    {
        KeClearEvent(&FCB->RelistenIdle);
        IoQueueWorkItem(FCB->RelistenWorkItem, RelistenWorker, DelayedWorkQueue, FCB);
    }

    /* Trigger a select return if appropriate */
    if( !IsListEmpty( &FCB->PendingConnections ) ) {
        FCB->PollState |= AFD_EVENT_ACCEPT;
        FCB->PollStatus[FD_ACCEPT_BIT] = STATUS_SUCCESS;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    } else
        FCB->PollState &= ~AFD_EVENT_ACCEPT;

    SocketStateUnlock( FCB );

    return Status;
}

NTSTATUS AfdListenSocket( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                          PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_LISTEN_DATA ListenReq;

    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    if( !AfdRequestLengthValid( Irp, IrpSp, sizeof(AFD_LISTEN_DATA) ) )
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp,
                                       0 );

    if( !(ListenReq = LockRequest( Irp, IrpSp, FALSE, NULL )) )
        return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp,
                                       0 );

    if( FCB->SharedData.State != SOCKET_STATE_BOUND ) {
        Status = STATUS_INVALID_PARAMETER;
        AFD_DbgPrint(MIN_TRACE,("Could not listen an unbound socket\n"));
        return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
    }

    if (!FCB->RelistenWorkItem)
    {
        FCB->RelistenWorkItem = IoAllocateWorkItem(DeviceObject);
        if (!FCB->RelistenWorkItem)
            return UnlockAndMaybeComplete(FCB, STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
    }

    if (!FCB->AcceptWorkItem)
    {
        FCB->AcceptWorkItem = IoAllocateWorkItem(DeviceObject);
        if (!FCB->AcceptWorkItem)
            return UnlockAndMaybeComplete(FCB, STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
    }

    FCB->DelayedAccept = ListenReq->UseDelayedAcceptance;

    /* A backlog of 0 still queues one connection */
    FCB->Backlog = ListenReq->Backlog;
    if (FCB->Backlog == 0)
        FCB->Backlog = 1;
    else if (FCB->Backlog > AFD_MAX_BACKLOG)
        FCB->Backlog = AFD_MAX_BACKLOG;

    AFD_DbgPrint(MID_TRACE,("ADDRESSFILE: %p\n", FCB->AddressFile.Handle));

    /* A failed or cancelled connect left its endpoint on the bound socket */
    AfdCloseConnectionEndpoint( FCB );
    Status = WarmSocketForConnection( FCB );

    AFD_DbgPrint(MID_TRACE,("Status from warmsocket %x\n", Status));

    if( !NT_SUCCESS(Status) ) return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );

    Status = TdiBuildNullConnectionInfo
        ( &FCB->ListenIrp.ConnectionCallInfo,
          FCB->LocalAddress->Address[0].AddressType );

    if (!NT_SUCCESS(Status)) return UnlockAndMaybeComplete(FCB, Status, Irp, 0);

    Status = TdiBuildNullConnectionInfo
        ( &FCB->ListenIrp.ConnectionReturnInfo,
          FCB->LocalAddress->Address[0].AddressType );

    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(FCB->ListenIrp.ConnectionCallInfo,
                          TAG_AFD_TDI_CONNECTION_INFORMATION);

        FCB->ListenIrp.ConnectionCallInfo = NULL;
        return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
    }

    FCB->SharedData.State = SOCKET_STATE_LISTENING;

    /* Listen from a system thread: a listen queued to this thread is cancelled when it exits */
    FCB->ListenConnectionReady = TRUE;
    KeClearEvent(&FCB->RelistenIdle);
    IoQueueWorkItem(FCB->RelistenWorkItem, RelistenWorker, DelayedWorkQueue, FCB);
    SocketStateUnlock(FCB);
    KeWaitForSingleObject(&FCB->RelistenIdle, Executive, KernelMode, FALSE, NULL);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    /* A first listen that failed left nothing in flight that could queue the worker again */
    if (!NT_SUCCESS(FCB->ListenStatus))
    {
        /* The worker could not listen: report it and leave the socket bound */
        Status = FCB->ListenStatus;
        ReleaseListenConnection(FCB);
        FreeListenConnectionInfo(FCB);
        FCB->SharedData.State = SOCKET_STATE_BOUND;
    }

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));
    return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
}

NTSTATUS AfdWaitForListen( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                           PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called\n"));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    if( !IsListEmpty( &FCB->PendingConnections ) ) {
        PLIST_ENTRY PendingConn = FCB->PendingConnections.Flink;

        /* We have a pending connection ... complete this irp right away */
        Status = SatisfyPreAccept
            ( Irp,
              CONTAINING_RECORD
              ( PendingConn, AFD_TDI_OBJECT_QELT, ListEntry ) );

        AFD_DbgPrint(MID_TRACE,("Completed a wait for accept\n"));

        if ( !IsListEmpty( &FCB->PendingConnections ) )
        {
             FCB->PollState |= AFD_EVENT_ACCEPT;
             FCB->PollStatus[FD_ACCEPT_BIT] = STATUS_SUCCESS;
             PollReeval( FCB->DeviceExt, FCB->FileObject );
        } else
             FCB->PollState &= ~AFD_EVENT_ACCEPT;

        SocketStateUnlock( FCB );
        return Status;
    } else if (FCB->NonBlocking) {
        AFD_DbgPrint(MIN_TRACE,("No connection ready on a non-blocking socket\n"));

        return UnlockAndMaybeComplete(FCB, STATUS_CANT_WAIT, Irp, 0);
    } else {
        AFD_DbgPrint(MID_TRACE,("Holding\n"));

        return LeaveIrpUntilLater( FCB, Irp, FUNCTION_PREACCEPT );
    }
}

NTSTATUS AfdAccept( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                    PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_DEVICE_EXTENSION DeviceExt =
        (PAFD_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_ACCEPT_DATA AcceptData = Irp->AssociatedIrp.SystemBuffer;
    PLIST_ENTRY PendingConn;

    AFD_DbgPrint(MID_TRACE,("Called\n"));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    /* IOCTL_AFD_ACCEPT is METHOD_BUFFERED: a zero-length input leaves
     * SystemBuffer NULL and a short buffer would be a pool over-read, so
     * reject anything that cannot hold an AFD_ACCEPT_DATA before we touch it. */
    if( !AcceptData ||
        IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_ACCEPT_DATA) )
    {
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
    }

    FCB->EventSelectDisabled &= ~AFD_EVENT_ACCEPT;

    for( PendingConn = FCB->PendingConnections.Flink;
         PendingConn != &FCB->PendingConnections;
         PendingConn = PendingConn->Flink ) {
        PAFD_TDI_OBJECT_QELT PendingConnObj =
            CONTAINING_RECORD( PendingConn, AFD_TDI_OBJECT_QELT, ListEntry );

        AFD_DbgPrint(MID_TRACE,("Comparing Seq %u to Q %u\n",
                                AcceptData->SequenceNumber,
                                PendingConnObj->Seq));

        if( PendingConnObj->Seq == AcceptData->SequenceNumber ) {
            PFILE_OBJECT NewFileObject = NULL;
            PAFD_FCB NewFcb;

            /* A bad accept handle leaves the connection queued for a retry */
            /* Reference with the requestor mode so the handle is resolved
             * against the caller's own handle table and its granted access is
             * checked (KernelMode skipped both, letting a caller pass a handle
             * -- even a kernel handle -- it should not be able to). A socket is
             * opened with GENERIC_READ|GENERIC_WRITE, which the I/O manager has
             * already mapped to specific rights in the handle table. The check
             * compares raw granted bits, so a GENERIC_* mask can never be
             * satisfied (accept() failed with STATUS_ACCESS_DENIED, WSAEACCES):
             * require the specific data rights instead of FILE_ALL_ACCESS. */
            Status = ObReferenceObjectByHandle
                ( AcceptData->ListenHandle,
                  FILE_READ_DATA | FILE_WRITE_DATA,
                  *IoFileObjectType,
                  Irp->RequestorMode,
                  (PVOID *)&NewFileObject,
                  NULL );

            if( !NT_SUCCESS(Status) ) return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );

            /* Target must be an AFD socket, else FsContext is not an AFD_FCB */
            if( NewFileObject->DeviceObject != DeviceObject ) {
                ObDereferenceObject( NewFileObject );
                return UnlockAndMaybeComplete( FCB, STATUS_INVALID_HANDLE, Irp, 0 );
            }

            /* Only a fresh socket can take the connection (as in
             * AfdSuperAccept). A rejected one leaves the connection queued.
             * Claim the socket (CONNECTING) under its lock, so nothing binds,
             * connects or accepts into it before SatisfyAccept relocks it. The
             * listener itself is rejected too: its mutex is ours already. */
            NewFcb = NewFileObject->FsContext;
            if( !NewFcb || !AfdMayBeFreshAcceptSocket( FCB, NewFcb ) ) {
                AFD_DbgPrint(MIN_TRACE,("Accept socket is not a fresh socket\n"));
                ObDereferenceObject( NewFileObject );
                return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
            }

            /* Never wait for the second lock (see AfdTryLockAcceptSocket) */
            if( !AfdTryLockAcceptSocket( NewFcb ) ) {
                AFD_DbgPrint(MIN_TRACE,("Accept socket is busy\n"));
                ObDereferenceObject( NewFileObject );
                return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
            }

            /* The state may have changed before the lock was taken */
            if( !AfdIsFreshAcceptSocket( FCB, NewFcb ) ) {
                AFD_DbgPrint(MIN_TRACE,("Accept socket is not a fresh socket\n"));
                SocketStateUnlock( NewFcb );
                ObDereferenceObject( NewFileObject );
                return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
            }

            NewFcb->SharedData.State = SOCKET_STATE_CONNECTING;
            /* The accepted socket keeps the listener's SO_RCVBUF unless it has its own */
            if( !NewFcb->RecvHint )
                NewFcb->RecvHint = FCB->RecvHint;
            SocketStateUnlock( NewFcb );

            RemoveEntryList( PendingConn );

            ASSERT(NewFileObject != FileObject);
            ASSERT(NewFileObject->FsContext != FCB);

            /* We have a pending connection ... complete this irp right away */
            Status = SatisfyAccept( DeviceExt, Irp, NewFileObject, PendingConnObj, FALSE );

            ObDereferenceObject( NewFileObject );

            AFD_DbgPrint(MID_TRACE,("Completed a wait for accept\n"));

            FreeQueuedConnection(PendingConnObj);

            ResumeListen(FCB);

            if( !IsListEmpty( &FCB->PendingConnections ) )
            {
                FCB->PollState |= AFD_EVENT_ACCEPT;
                FCB->PollStatus[FD_ACCEPT_BIT] = STATUS_SUCCESS;
                PollReeval( FCB->DeviceExt, FCB->FileObject );
            } else
                FCB->PollState &= ~AFD_EVENT_ACCEPT;

            SocketStateUnlock( FCB );
            return Status;
        }
    }

    AFD_DbgPrint(MIN_TRACE,("No connection waiting\n"));

    return UnlockAndMaybeComplete( FCB, STATUS_UNSUCCESSFUL, Irp, 0 );
}

#define AFD_MIN_SUPER_ACCEPT_REMOTE_LENGTH 8

NTSTATUS AfdSuperAccept( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                    PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB Fcb = FileObject->FsContext;
    PAFD_SUPER_ACCEPT_INFO AcceptRequest;
    ULONG OutputLength;

    PFILE_OBJECT NewFileObject = NULL;

    AFD_DbgPrint(MID_TRACE,("Called\n"));

    if( !SocketAcquireStateLock( Fcb ) ) return LostSocket( Irp );

    if( !(AcceptRequest = LockRequest( Irp, IrpSp, FALSE, NULL )) )
        return UnlockAndMaybeComplete( Fcb, STATUS_NO_MEMORY, Irp,
                                       0 );

    /* The locked METHOD_NEITHER input must be large enough to hold the
     * request struct we are about to read, or it is a pool over-read. */
    if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_SUPER_ACCEPT_INFO) )
        return UnlockAndMaybeComplete( Fcb, STATUS_INVALID_PARAMETER, Irp, 0 );

    /* AcceptEx works on a listening socket only: a socket that is not listening (not
     * bound, bound, connected, closed) has no connections to hand out, and would pend a request
     * that nothing completes. Windows answers WSAEINVAL. */
    if( Fcb->SharedData.State != SOCKET_STATE_LISTENING )
        return UnlockAndMaybeComplete( Fcb, STATUS_INVALID_PARAMETER, Irp, 0 );

    Fcb->EventSelectDisabled &= ~AFD_EVENT_ACCEPT;

    /* The output buffer holds the initial data, the local and the remote address area */
    OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (AcceptRequest->ReceiveDataLength > OutputLength ||
        AcceptRequest->LocalAddressLength > OutputLength - AcceptRequest->ReceiveDataLength ||
        AcceptRequest->RemoteAddressLength > OutputLength - AcceptRequest->ReceiveDataLength -
                                             AcceptRequest->LocalAddressLength)
    {
        return UnlockAndMaybeComplete(Fcb, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    /* Windows answers an AcceptEx whose remote address area is shorter than 8 bytes
     * with WSAEFAULT instead of queueing it (measured on Windows 10, 32 and 64 bit;
     * the local area may be any length, even 0) */
    if (AcceptRequest->RemoteAddressLength < AFD_MIN_SUPER_ACCEPT_REMOTE_LENGTH)
        return UnlockAndMaybeComplete(Fcb, STATUS_INVALID_PARAMETER, Irp, 0);

    /* Allow the IRP to access UserBuffer later */
    Irp->Tail.Overlay.DriverContext[3] = IoAllocateMdl(Irp->UserBuffer, OutputLength, FALSE, FALSE, NULL);
    if (!Irp->Tail.Overlay.DriverContext[3])
        return UnlockAndMaybeComplete(Fcb, STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
    _SEH2_TRY
    {
        MmProbeAndLockPages((PMDL)Irp->Tail.Overlay.DriverContext[3], Irp->RequestorMode, IoWriteAccess);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
        /* The probe failed, so the pages are not locked, but the MDL is ours */
        AfdFreeAcceptMdl(Irp);
        return UnlockAndMaybeComplete(Fcb, Status, Irp, 0);
    }
    _SEH2_END;

    /* Validate that accepting socket is valid, and has not been bound or connected */
    /* User-supplied handle: resolve it in the caller's handle table under the
     * requestor mode (KernelMode skipped that check). Require only the access a
     * socket is actually opened with (specific rights; GENERIC_* is never
     * granted), not FILE_ALL_ACCESS. */
    Status = ObReferenceObjectByHandle(
        AcceptRequest->AcceptHandle, FILE_READ_DATA | FILE_WRITE_DATA, *IoFileObjectType, Irp->RequestorMode, (PVOID *)&NewFileObject, NULL);
    if (!NT_SUCCESS(Status))
    {
        /* The output pages were probed and locked above */
        AfdFreeAcceptMdl(Irp);
        return UnlockAndMaybeComplete(Fcb, Status, Irp, 0);
    }

    /* Target must be an AFD socket, else FsContext is not an AFD_FCB */
    if (NewFileObject->DeviceObject != DeviceObject)
    {
        ObDereferenceObject(NewFileObject);
        AfdFreeAcceptMdl(Irp);
        return UnlockAndMaybeComplete(Fcb, STATUS_INVALID_HANDLE, Irp, 0);
    }

    PAFD_FCB Fcb2 = NewFileObject->FsContext;

    /* Reject the listener itself and a socket that cannot qualify before
     * touching its lock; never wait for it while holding ours (deadlock when two
     * listeners accept into each other) */
    if (!Fcb2 || !AfdMayBeFreshAcceptSocket(Fcb, Fcb2) || !AfdTryLockAcceptSocket(Fcb2))
    {
        AfdFreeAcceptMdl(Irp);
        ObDereferenceObject(NewFileObject);
        return UnlockAndMaybeComplete(Fcb, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    /* Verify that the acceptor socket has not been already binded/connected or that it has been used by AcceptEx */
    if (!AfdIsFreshAcceptSocket(Fcb, Fcb2))
    {
        AfdFreeAcceptMdl(Irp);
        SocketStateUnlock(Fcb2);
        ObDereferenceObject(NewFileObject);
        return UnlockAndMaybeComplete(Fcb, STATUS_INVALID_PARAMETER, Irp, 0);
    }
    Fcb2->SharedData.State = SOCKET_STATE_CONNECTING;

    Irp->Tail.Overlay.DriverContext[2] = NewFileObject;
    
    /* Proceed later in SatisfyAcceptEx */
    SocketStateUnlock(Fcb2);

    Status = QueueUserModeIrp(Fcb, Irp, FUNCTION_PREACCEPT);

    /* Take a connection that is already waiting, the next one to arrive may never come */
    if (Status == STATUS_PENDING && !IsListEmpty(&Fcb->PendingConnections) &&
        Fcb->AcceptWorkItem && !Fcb->AcceptWorkQueued)
    {
        Fcb->AcceptWorkQueued = TRUE;
        KeClearEvent(&Fcb->AcceptWorkIdle);
        IoQueueWorkItem(Fcb->AcceptWorkItem, AcceptWorker, DelayedWorkQueue, Fcb);
    }

    SocketStateUnlock(Fcb);
    return Status;
}
