/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/connect.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"
#include <reactos/drivers/tdiext.h>

NTSTATUS
NTAPI
AfdGetConnectOptions(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                     PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (FCB->ConnectOptionsSize == 0)
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    ASSERT(FCB->ConnectOptions);

    if (FCB->FilledConnectOptions < BufferSize) BufferSize = FCB->FilledConnectOptions;

    /* METHOD_NEITHER: probe the caller's output and copy under SEH */
    Status = AfdCopyToUserOutput(Irp, IrpSp, FCB->ConnectOptions, BufferSize);

    return UnlockAndMaybeComplete(FCB, Status, Irp, NT_SUCCESS(Status) ? BufferSize : 0);
}

NTSTATUS
NTAPI
AfdSetConnectOptions(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                     PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PVOID ConnectOptions = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT ConnectOptionsSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!ConnectOptions)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (FCB->ConnectOptions)
    {
        ExFreePoolWithTag(FCB->ConnectOptions, TAG_AFD_CONNECT_OPTIONS);
        FCB->ConnectOptions = NULL;
        FCB->ConnectOptionsSize = 0;
        FCB->FilledConnectOptions = 0;
    }

    FCB->ConnectOptions = ExAllocatePoolWithTag(PagedPool,
                                                ConnectOptionsSize,
                                                TAG_AFD_CONNECT_OPTIONS);

    if (!FCB->ConnectOptions)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    RtlCopyMemory(FCB->ConnectOptions,
                  ConnectOptions,
                  ConnectOptionsSize);

    FCB->ConnectOptionsSize = ConnectOptionsSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

NTSTATUS
NTAPI
AfdSetConnectOptionsSize(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                         PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PUINT ConnectOptionsSize = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!ConnectOptionsSize)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (BufferSize < sizeof(UINT))
    {
        AFD_DbgPrint(MIN_TRACE,("Buffer too small\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_BUFFER_TOO_SMALL, Irp, 0);
    }

    if (FCB->ConnectOptions)
    {
        ExFreePoolWithTag(FCB->ConnectOptions, TAG_AFD_CONNECT_OPTIONS);
        FCB->ConnectOptionsSize = 0;
        FCB->FilledConnectOptions = 0;
    }

    FCB->ConnectOptions = ExAllocatePoolWithTag(PagedPool,
                                                *ConnectOptionsSize,
                                                TAG_AFD_CONNECT_OPTIONS);

    if (!FCB->ConnectOptions) return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    FCB->ConnectOptionsSize = *ConnectOptionsSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

NTSTATUS
NTAPI
AfdGetConnectData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                  PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (FCB->ConnectDataSize == 0)
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    ASSERT(FCB->ConnectData);

    if (FCB->FilledConnectData < BufferSize) BufferSize = FCB->FilledConnectData;

    /* METHOD_NEITHER: probe the caller's output and copy under SEH */
    Status = AfdCopyToUserOutput(Irp, IrpSp, FCB->ConnectData, BufferSize);

    return UnlockAndMaybeComplete(FCB, Status, Irp, NT_SUCCESS(Status) ? BufferSize : 0);
}

NTSTATUS
NTAPI
AfdSetConnectData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                  PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PVOID ConnectData = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT ConnectDataSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!ConnectData)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (FCB->ConnectData)
    {
        ExFreePoolWithTag(FCB->ConnectData, TAG_AFD_CONNECT_DATA);
        FCB->ConnectData = NULL;
        FCB->ConnectDataSize = 0;
        FCB->FilledConnectData = 0;
    }

    FCB->ConnectData = ExAllocatePoolWithTag(PagedPool,
                                             ConnectDataSize,
                                             TAG_AFD_CONNECT_DATA);

    if (!FCB->ConnectData) return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    RtlCopyMemory(FCB->ConnectData,
                  ConnectData,
                  ConnectDataSize);

    FCB->ConnectDataSize = ConnectDataSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

NTSTATUS
NTAPI
AfdSetConnectDataSize(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                      PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PUINT ConnectDataSize = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!ConnectDataSize)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (BufferSize < sizeof(UINT))
    {
        AFD_DbgPrint(MIN_TRACE,("Buffer too small\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_BUFFER_TOO_SMALL, Irp, 0);
    }

    if (FCB->ConnectData)
    {
        ExFreePoolWithTag(FCB->ConnectData, TAG_AFD_CONNECT_DATA);
        FCB->ConnectDataSize = 0;
        FCB->FilledConnectData = 0;
    }

    FCB->ConnectData = ExAllocatePoolWithTag(PagedPool,
                                             *ConnectDataSize,
                                             TAG_AFD_CONNECT_DATA);

    if (!FCB->ConnectData) return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    FCB->ConnectDataSize = *ConnectDataSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}


/* A failed or cancelled connect leaves its connection endpoint behind; the
   next connect opens a new one, so close the old one first. Called with the
   state lock held and no transport request on the connection */
VOID
AfdCloseConnectionEndpoint(PAFD_FCB FCB)
{
    ASSERT(!FCB->ConnectIrp.InFlightRequest);

    if (FCB->Connection.Object)
    {
        TdiDisassociateAddressFile(FCB->Connection.Object);
        ObDereferenceObject(FCB->Connection.Object);
        FCB->Connection.Object = NULL;
    }
    if (FCB->Connection.Handle != INVALID_HANDLE_VALUE)
    {
        ZwClose(FCB->Connection.Handle);
        FCB->Connection.Handle = INVALID_HANDLE_VALUE;
    }
}

NTSTATUS
WarmSocketForConnection(PAFD_FCB FCB) {
    NTSTATUS Status;

    if( !FCB->TdiDeviceName.Length || !FCB->TdiDeviceName.Buffer ) {
        AFD_DbgPrint(MIN_TRACE,("Null Device\n"));
        return STATUS_NO_SUCH_DEVICE;
    }

    Status = TdiOpenConnectionEndpointFile(&FCB->TdiDeviceName,
                                           &FCB->Connection.Handle,
                                           &FCB->Connection.Object );

    if( NT_SUCCESS(Status) ) {
        Status = TdiAssociateAddressFile( FCB->AddressFile.Handle,
                                          FCB->Connection.Object );
    }

    return Status;
}

NTSTATUS
MakeSocketIntoConnection(PAFD_FCB FCB, BOOL Receive) {
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT(!FCB->Recv.Window);
    ASSERT(!FCB->Send.Window);

    if (!FCB->Recv.Size)
    {
        Status = TdiQueryMaxDatagramLength(FCB->Connection.Object,
                                           &FCB->Recv.Size);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    if (!FCB->Send.Size)
    {
        Status = TdiQueryMaxDatagramLength(FCB->Connection.Object,
                                           &FCB->Send.Size);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    /* Allocate the receive area and start receiving */
    if (!FCB->Recv.Window)
    {
        FCB->Recv.NonPaged = FCB->Recv.Size <= AFD_NONPAGED_WINDOW_MAX;
        FCB->Recv.Window = ExAllocatePoolWithTag(FCB->Recv.NonPaged ? NonPagedPool : PagedPool,
                                                 FCB->Recv.Size,
                                                 TAG_AFD_DATA_BUFFER);

        if( !FCB->Recv.Window ) { FCB->Recv.NonPaged = FALSE; return STATUS_NO_MEMORY; }
    }

    /* The send window is allocated by the first send (AfdConnectedSocketWriteData): a 64 KB window
     * for every connected socket took 640 MB of paged pool for 5000 connections (i386 ran out) */

    FCB->SharedData.State = SOCKET_STATE_CONNECTED;
    FCB->SharedData.ConnectTime = 0; // Not used

    /* SO_RCVBUF set before the connection existed (or inherited from the listener) */
    AfdApplyReceiveHint(FCB);

    if (Receive)
    {
        Status = AfdTdiReceiveWindow( FCB, FCB->Recv.Window, FCB->Recv.Size );

        if( Status == STATUS_PENDING ) Status = STATUS_SUCCESS;
    }

   FCB->PollState |= AFD_EVENT_CONNECT | AFD_EVENT_SEND;
   FCB->PollStatus[FD_CONNECT_BIT] = STATUS_SUCCESS;
   FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
   PollReeval( FCB->DeviceExt, FCB->FileObject );

   return Status;
}

static IO_COMPLETION_ROUTINE StreamSocketConnectSendComplete;

static
NTSTATUS
NTAPI
StreamSocketConnectSendComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context)
{
    PAFD_FCB FCB = (PAFD_FCB)Context;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;

    if (!SocketAcquireStateLock(FCB))
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->SendIrp.InFlightRequest == Irp);
    FCB->SendIrp.InFlightRequest = NULL;

    while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECTEX]))
    {
        NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_CONNECTEX]);
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);

        AFD_DbgPrint(MID_TRACE,("Completing connectex %p\n", NextIrp));
        NextIrp->IoStatus.Status = Irp->IoStatus.Status;
        NextIrp->IoStatus.Information = Irp->IoStatus.Information;
        if (AfdRequestLocked(NextIrp))
            UnlockRequest(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));
        AfdClearCancelRoutine(NextIrp);
        IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);
    }

    if (FCB->OnConnectSendBuffer)
    {
        ExFreePoolWithTag(FCB->OnConnectSendBuffer, TAG_AFD_SUPER_CONNECT_BUFFER);
        FCB->OnConnectSendBuffer = NULL;
        FCB->OnConnectSendBufferSize = 0;
    }
    
    SocketStateUnlock(FCB);
    
    return STATUS_SUCCESS;
}

/* A queued ConnectEx was cancelled while its transport connect completed */
static BOOLEAN AfdConnectExCancelled(PAFD_FCB FCB)
{
    PLIST_ENTRY Entry;

    for (Entry = FCB->PendingIrpList[FUNCTION_CONNECTEX].Flink;
         Entry != &FCB->PendingIrpList[FUNCTION_CONNECTEX];
         Entry = Entry->Flink)
    {
        if (CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry)->Cancel)
            return TRUE;
    }
    return FALSE;
}

/* The ConnectEx initial-send buffer, on paths where no send owns it */
static VOID FreeConnectSendBuffer(PAFD_FCB FCB)
{
    if (FCB->OnConnectSendBuffer)
    {
        ExFreePoolWithTag(FCB->OnConnectSendBuffer, TAG_AFD_SUPER_CONNECT_BUFFER);
        FCB->OnConnectSendBuffer = NULL;
        FCB->OnConnectSendBufferSize = 0;
    }
}

static IO_COMPLETION_ROUTINE StreamSocketConnectComplete;
static
NTSTATUS
NTAPI
StreamSocketConnectComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                            PVOID Context) {
    NTSTATUS Status = Irp->IoStatus.Status;
    PAFD_FCB FCB = (PAFD_FCB)Context;
    PLIST_ENTRY NextIrpEntry;
    PIRP NextIrp;

    AFD_DbgPrint(MID_TRACE,("Called: FCB %p, FO %p\n",
                            Context, FCB->FileObject));

    /* I was wrong about this before as we can have pending writes to a not
     * yet connected socket */
    if( !SocketAcquireStateLock( FCB ) )
        return STATUS_FILE_CLOSED;

    AFD_DbgPrint(MID_TRACE,("Irp->IoStatus.Status = %x\n",
                            Irp->IoStatus.Status));

    ASSERT(FCB->ConnectIrp.InFlightRequest == Irp);
    FCB->ConnectIrp.InFlightRequest = NULL;

    if( FCB->SharedData.State == SOCKET_STATE_CLOSED ) {
        /* Cleanup our IRP queue because the FCB is being destroyed */
        while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_CONNECT] ) ) {
               NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_CONNECT]);
               NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
               NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
               NextIrp->IoStatus.Information = 0;
               if (AfdRequestLocked(NextIrp)) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
               AfdClearCancelRoutine(NextIrp);
               IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
        }
        while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECTEX]))
        {
               NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_CONNECTEX]);
               NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
               NextIrp->IoStatus.Status = STATUS_FILE_CLOSED;
               NextIrp->IoStatus.Information = Irp->IoStatus.Information;
               if (AfdRequestLocked(NextIrp))
                   UnlockRequest(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));
               AfdClearCancelRoutine(NextIrp);
               IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);
        }
        SocketStateUnlock( FCB );
        return STATUS_FILE_CLOSED;
    }

    if( !NT_SUCCESS(Irp->IoStatus.Status) ) {
        FCB->PollState |= AFD_EVENT_CONNECT_FAIL;
        FCB->PollStatus[FD_CONNECT_BIT] = Irp->IoStatus.Status;
        /* A blocking connect returns its error itself; only a non-blocking one leaves it for SO_ERROR */
        if (FCB->NonBlocking && !IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECT]))
            FCB->AsyncConnectStatus = Irp->IoStatus.Status;
        AFD_DbgPrint(MID_TRACE,("Going to bound state\n"));
        FCB->SharedData.State = SOCKET_STATE_BOUND;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }

    /* Succeed pending irps on the FUNCTION_CONNECT list */
    while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_CONNECT] ) ) {
        NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_CONNECT]);
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);
        AFD_DbgPrint(MID_TRACE,("Completing connect %p\n", NextIrp));
        NextIrp->IoStatus.Status = Status;
        NextIrp->IoStatus.Information = NT_SUCCESS(Status) ? ((ULONG_PTR)FCB->Connection.Handle) : 0;
        if (AfdRequestLocked(NextIrp)) UnlockRequest( NextIrp, IoGetCurrentIrpStackLocation( NextIrp ) );
        AfdClearCancelRoutine(NextIrp);
        IoCompleteRequest( NextIrp, IO_NETWORK_INCREMENT );
    }

    if( NT_SUCCESS(Status) ) {
        Status = MakeSocketIntoConnection(FCB, TRUE);

        if( !NT_SUCCESS(Status) ) {
            goto end;
        }

        /* The return info is built by TdiBuildConnectionInfo, which reports
           OptionsLength = sizeof(ULONG) with no Options buffer, and the
           transport does not fill it in: copy only what has a source */
        FCB->FilledConnectData = 0;
        if (FCB->ConnectReturnInfo && FCB->ConnectReturnInfo->UserData)
            FCB->FilledConnectData = MIN(FCB->ConnectReturnInfo->UserDataLength, FCB->ConnectDataSize);
        if (FCB->FilledConnectData)
        {
            RtlCopyMemory(FCB->ConnectData,
                          FCB->ConnectReturnInfo->UserData,
                          FCB->FilledConnectData);
        }

        FCB->FilledConnectOptions = 0;
        if (FCB->ConnectReturnInfo && FCB->ConnectReturnInfo->Options)
            FCB->FilledConnectOptions = MIN(FCB->ConnectReturnInfo->OptionsLength, FCB->ConnectOptionsSize);
        if (FCB->FilledConnectOptions)
        {
            RtlCopyMemory(FCB->ConnectOptions,
                          FCB->ConnectReturnInfo->Options,
                          FCB->FilledConnectOptions);
        }

        if( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_SEND] ) ) {
            NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_SEND]);
            NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP,
                                        Tail.Overlay.ListEntry);
            AFD_DbgPrint(MID_TRACE,("Launching send request %p\n", NextIrp));
            Status = AfdConnectedSocketWriteData
                ( DeviceObject,
                  NextIrp,
                  IoGetCurrentIrpStackLocation( NextIrp ),
                  FALSE );
        }

        if( Status == STATUS_PENDING )
            Status = STATUS_SUCCESS;

        if (FCB->OnConnectSendBuffer && AfdConnectExCancelled(FCB))
        {
            /* Its cancel routine is spent, so a stalled initial send could never be cancelled */
            Status = STATUS_CANCELLED;
            goto end;
        }

        if (FCB->OnConnectSendBuffer)
        {
            /* Issued with the lock held, so a close cannot pass its in-flight wait first */
            Status = TdiSend(&FCB->SendIrp.InFlightRequest,
                             FCB->Connection.Object,
                             AFD_OVERLAPPED,
                             FCB->OnConnectSendBuffer,
                             FCB->OnConnectSendBufferSize,
                             StreamSocketConnectSendComplete,
                             FCB);

            /* TdiSend failed before the transport got the request, so no completion frees the buffer */
            if (!NT_SUCCESS(Status) && FCB->OnConnectSendBuffer)
                goto end;

            SocketStateUnlock(FCB);
            return Status == STATUS_PENDING ? STATUS_SUCCESS : Status;
        }
    }

end:
    FreeConnectSendBuffer(FCB);
    while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECTEX]))
    {
        NextIrpEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_CONNECTEX]);
        NextIrp = CONTAINING_RECORD(NextIrpEntry, IRP, Tail.Overlay.ListEntry);

        AFD_DbgPrint(MID_TRACE,("Completing connectex %p\n", NextIrp));
        NextIrp->IoStatus.Status = Status;
        NextIrp->IoStatus.Information = 0;
        if (AfdRequestLocked(NextIrp))
            UnlockRequest(NextIrp, IoGetCurrentIrpStackLocation(NextIrp));
        AfdClearCancelRoutine(NextIrp);
        IoCompleteRequest(NextIrp, IO_NETWORK_INCREMENT);
    }
    SocketStateUnlock( FCB );

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));

    return Status;
}

/* Issue the transport connect for a connect request queued (pending) on
   Function. Called with the state lock held and the socket CONNECTING. */
static VOID
SubmitConnect(PAFD_FCB FCB, PIRP Irp, UINT Function)
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;

    Status = TdiConnect(&FCB->ConnectIrp.InFlightRequest,
                        FCB->Connection.Object,
                        FCB->ConnectCallInfo,
                        FCB->ConnectReturnInfo,
                        StreamSocketConnectComplete,
                        FCB);
    if (Status == STATUS_PENDING)
        return;

    /* If the transport completed the request inside TdiConnect (the state mutex
       is recursive), StreamSocketConnectComplete has run: it moved the socket out
       of CONNECTING or completed this request. tcpip itself always pends. */
    if (FCB->SharedData.State != SOCKET_STATE_CONNECTING)
        return;
    for (Entry = FCB->PendingIrpList[Function].Flink;
         Entry != &FCB->PendingIrpList[Function];
         Entry = Entry->Flink)
    {
        if (CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry) == Irp)
            break;
    }
    if (Entry == &FCB->PendingIrpList[Function])
        return;

    /* TdiConnect failed before the transport got the request */
    FCB->SharedData.State = SOCKET_STATE_BOUND;
    FCB->PollState |= AFD_EVENT_CONNECT_FAIL;
    FCB->PollStatus[FD_CONNECT_BIT] = Status;
    if (FCB->NonBlocking && Function == FUNCTION_CONNECT)
        FCB->AsyncConnectStatus = Status;
    PollReeval(FCB->DeviceExt, FCB->FileObject);
    FreeConnectSendBuffer(FCB);

    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    if (AfdRequestLocked(Irp))
        UnlockRequest(Irp, IoGetCurrentIrpStackLocation(Irp));
    AfdClearCancelRoutine(Irp);
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
}

/* Return the socket object for ths request only if it is a connected or
   stream type. */
NTSTATUS
NTAPI
AfdStreamSocketConnect(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                       PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_CONNECT_INFO ConnectReq;
    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );
    if( !(ConnectReq = LockRequest( Irp, IrpSp, FALSE, NULL )) )
        return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp,
                                       0 );

    /* ConnectReq is the captured user IOCTL buffer. Validate that the declared
     * RemoteAddress header is within the supplied input before we read its
     * AddressType/AddressLength or copy it, so nothing runs off the pool copy. */
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength <
            FIELD_OFFSET(AFD_CONNECT_INFO, RemoteAddress) + sizeof(ULONG) + 2 * sizeof(USHORT))
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

    /* An address of the unspecified family (it ends a datagram association) carries no data;
     * any other must be complete for its type */
    if (!(ConnectReq->RemoteAddress.TAAddressCount >= 1 &&
          ConnectReq->RemoteAddress.Address[0].AddressType == 0) &&
        !TaTransportAddressFits( &ConnectReq->RemoteAddress,
            IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_CONNECT_INFO, RemoteAddress)))
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

    AFD_DbgPrint(MID_TRACE,("Connect request:\n"));
#if 0
    OskitDumpBuffer
        ( (PCHAR)ConnectReq,
          IrpSp->Parameters.DeviceIoControl.InputBufferLength );
#endif

   if( FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS )
   {
        PTRANSPORT_ADDRESS NewAddress;

        /* An address of the unspecified family ends the association with the peer */
        if( ConnectReq->RemoteAddress.TAAddressCount >= 1 &&
            ConnectReq->RemoteAddress.Address[0].AddressType == 0 )
        {
            if( !FCB->RemoteAddress )
                return UnlockAndMaybeComplete( FCB, STATUS_PROTOCOL_NOT_SUPPORTED, Irp, 0 );

            ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);
            FCB->RemoteAddress = NULL;
            return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );
        }

        NewAddress =
            TaCopyTransportAddressBounded( &ConnectReq->RemoteAddress,
                IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_CONNECT_INFO, RemoteAddress) );

        if( !NewAddress )
            return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );

        if( NewAddress->TAAddressCount == 1 &&
            NewAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP &&
            NewAddress->Address[0].AddressLength >= TDI_ADDRESS_LENGTH_IP )
        {
            ULONG Peer = ((PTDI_ADDRESS_IP)NewAddress->Address[0].Address)->in_addr;
            ULONG Bound = 0, Source;

            if( FCB->LocalAddress &&
                FCB->LocalAddress->TAAddressCount == 1 &&
                FCB->LocalAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP &&
                FCB->LocalAddress->Address[0].AddressLength >= TDI_ADDRESS_LENGTH_IP )
                Bound = ((PTDI_ADDRESS_IP)FCB->LocalAddress->Address[0].Address)->in_addr;

            Status = STATUS_SUCCESS;
            if( Peer == 0 )
            {
                /* The unspecified address is no peer */
                Status = STATUS_INVALID_ADDRESS;
            }
            else if( Bound != 0 && FCB->AddressFile.Object &&
                     NT_SUCCESS(AfdQueryRouteSource(FCB, Peer, &Source)) )
            {
                /* A socket bound to the loopback address cannot reach a peer through
                 * another interface, nor one bound to another address a loopback peer */
                BOOLEAN BoundLoopback = (Bound & 0xFF) == 127;
                BOOLEAN SourceLoopback = (Source & 0xFF) == 127;
                /* Multicast, broadcast and link-local peers are accepted whatever the socket is bound to */
                BOOLEAN AnyBinding = (Peer & 0xF0) == 0xE0 || Peer == 0xFFFFFFFF ||
                                     (Peer & 0xFFFF) == 0xFEA9;

                if( BoundLoopback && !SourceLoopback && !AnyBinding )
                    Status = STATUS_NETWORK_UNREACHABLE;
                else if( !BoundLoopback && SourceLoopback )
                    Status = STATUS_INVALID_ADDRESS;
            }

            if( !NT_SUCCESS(Status) )
            {
                ExFreePoolWithTag(NewAddress, TAG_AFD_TRANSPORT_ADDRESS);
                return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
            }
        }

        if (FCB->RemoteAddress)
            ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);
        FCB->RemoteAddress = NewAddress;

        /* Every connect signals FD_CONNECT, and FD_WRITE again */
        FCB->PollState |= AFD_EVENT_CONNECT;
        FCB->PollStatus[FD_CONNECT_BIT] = STATUS_SUCCESS;
        FCB->EventSelectDisabled &= ~(AFD_EVENT_CONNECT | AFD_EVENT_SEND);
        PollReeval( FCB->DeviceExt, FCB->FileObject );

        return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );
   }

    switch(FCB->SharedData.State)
    {
    case SOCKET_STATE_CONNECTED:
        /* WSAEISCONN, as on Windows. Qt asks a non-blocking socket whether it
         * is connected by connecting it again and waits for this answer */
        Status = STATUS_CONNECTION_ACTIVE;
        break;

    case SOCKET_STATE_CONNECTING:
        /* WSAEINVAL while a ConnectEx connects, as on Windows */
        if (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECTEX]))
        {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        /* WSAEALREADY: a connect is in progress. It is not queued behind the
         * first one, which the caller keeps waiting for */
        Status = STATUS_CONNECTION_IN_USE;
        break;

    case SOCKET_STATE_CREATED:
        if (FCB->LocalAddress)
        {
            ExFreePoolWithTag(FCB->LocalAddress, TAG_AFD_TRANSPORT_ADDRESS);
        }

        FCB->LocalAddress =
            TaBuildNullTransportAddress( ConnectReq->RemoteAddress.Address[0].AddressType );

        if( FCB->LocalAddress ) {
            Status = WarmSocketForBind( FCB, AFD_SHARE_WILDCARD );

            if( NT_SUCCESS(Status) )
                FCB->SharedData.State = SOCKET_STATE_BOUND;
            else
                return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
        } else
            return UnlockAndMaybeComplete
                ( FCB, STATUS_NO_MEMORY, Irp, 0 );

    /* Drop through to SOCKET_STATE_BOUND */

    case SOCKET_STATE_BOUND:
        if (FCB->RemoteAddress)
        {
            ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);
        }

        FCB->RemoteAddress =
            TaCopyTransportAddressBounded( &ConnectReq->RemoteAddress,
                IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_CONNECT_INFO, RemoteAddress) );

        if( !FCB->RemoteAddress ) {
            Status = STATUS_NO_MEMORY;
            break;
        }

        AfdCloseConnectionEndpoint( FCB );
        Status = WarmSocketForConnection( FCB );

        if( !NT_SUCCESS(Status) )
            break;

        if (FCB->ConnectReturnInfo)
        {
            ExFreePoolWithTag(FCB->ConnectReturnInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
        }

        Status = TdiBuildConnectionInfo
            ( &FCB->ConnectReturnInfo,
              &ConnectReq->RemoteAddress );

        if( NT_SUCCESS(Status) )
        {
            if (FCB->ConnectCallInfo)
            {
                ExFreePoolWithTag(FCB->ConnectCallInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
            }

            Status = TdiBuildConnectionInfo(&FCB->ConnectCallInfo,
                                              &ConnectReq->RemoteAddress);
        }
        else break;


        if( NT_SUCCESS(Status) ) {
            FCB->ConnectCallInfo->UserData = FCB->ConnectData;
            FCB->ConnectCallInfo->UserDataLength = FCB->ConnectDataSize;
            FCB->ConnectCallInfo->Options = FCB->ConnectOptions;
            FCB->ConnectCallInfo->OptionsLength = FCB->ConnectOptionsSize;

            FCB->SharedData.State = SOCKET_STATE_CONNECTING;
            /* An earlier connect's failure does not belong to this one */
            FCB->PollState &= ~AFD_EVENT_CONNECT_FAIL;
            FCB->AsyncConnectStatus = STATUS_SUCCESS;

            AFD_DbgPrint(MID_TRACE,("Queueing IRP %p\n", Irp));
            Status = QueueUserModeIrp(FCB, Irp, FUNCTION_CONNECT);
            if (Status == STATUS_PENDING)
                SubmitConnect(FCB, Irp, FUNCTION_CONNECT);
            else
                FCB->SharedData.State = SOCKET_STATE_BOUND;

            SocketStateUnlock(FCB);

            return Status;
        }
        break;

    default:
        AFD_DbgPrint(MIN_TRACE,("Inappropriate socket state %u for connect\n",
                                FCB->SharedData.State));
        break;
    }

    return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
}

/* Return the socket object for ths request only if it is a connected or stream type. */
NTSTATUS
NTAPI
AfdStreamSocketSuperConnect(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_SUPER_CONNECT_INFO ConnectReq;
    KPROCESSOR_MODE LockMode;
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    AFD_DbgPrint(MID_TRACE,("Called on %p\n", FCB));

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB))
        return LostSocket(Irp);

    ConnectReq = LockRequest(Irp, IrpSp, FALSE, &LockMode);
    if (!ConnectReq)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    AFD_DbgPrint(MID_TRACE,("Connect request:\n"));
#if DBG
    OskitDumpBuffer((PCHAR)ConnectReq,
                    IrpSp->Parameters.DeviceIoControl.InputBufferLength);
#endif

    /* Validate that the declared RemoteAddress header fits in the captured user
     * input before we read or copy it (bounds the address copies below). */
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength <
            FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress) + sizeof(ULONG) + 2 * sizeof(USHORT))
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    if (!TaTransportAddressFits( &ConnectReq->RemoteAddress,
            IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress)))
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    if (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)
    {
        AFD_DbgPrint(MIN_TRACE,("Cannot call IOCTL_CONNECTEX on connectionless socket\n",
                                 FCB->SharedData.State));
         if (FCB->RemoteAddress)
         {
             ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);
         }

         FCB->RemoteAddress =
             TaCopyTransportAddressBounded(&ConnectReq->RemoteAddress,
                IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress));

         if(!FCB->RemoteAddress)
             Status = STATUS_NO_MEMORY;
         else
             Status = STATUS_SUCCESS;

         return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
    }

    /* The state is checked before the buffer is touched: a pending connect or
       initial send owns the buffer */
    switch (FCB->SharedData.State)
    {
    case SOCKET_STATE_CONNECTED:
        /* WSAEISCONN, as on Windows */
        return UnlockAndMaybeComplete(FCB, STATUS_CONNECTION_ACTIVE, Irp, 0);

    case SOCKET_STATE_CONNECTING:
        /* WSAEINVAL, as on Windows */
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    case SOCKET_STATE_BOUND:
        /* No request owns a buffer on a bound socket */
        FreeConnectSendBuffer(FCB);

        if (Irp->UserBuffer && BufferSize)
        {
            FCB->OnConnectSendBuffer = ExAllocatePoolWithTag(PagedPool,
                                                             BufferSize,
                                                             TAG_AFD_SUPER_CONNECT_BUFFER);
            if (!FCB->OnConnectSendBuffer)
                return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

            FCB->OnConnectSendBufferSize = BufferSize;
            Status = STATUS_SUCCESS;
            /* METHOD_NEITHER: the send buffer is the caller's raw pointer */
            _SEH2_TRY
            {
                if (Irp->RequestorMode != KernelMode)
                    ProbeForRead(Irp->UserBuffer, BufferSize, 1);
                RtlCopyMemory(FCB->OnConnectSendBuffer, Irp->UserBuffer, BufferSize);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            if (!NT_SUCCESS(Status))
            {
                FreeConnectSendBuffer(FCB);
                return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
            }
        }

        if (FCB->RemoteAddress)
        {
            ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);
        }

        FCB->RemoteAddress =
            TaCopyTransportAddressBounded(&ConnectReq->RemoteAddress,
                IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress));
        if (!FCB->RemoteAddress)
        {
            Status = STATUS_NO_MEMORY;
            break;
        }

        AfdCloseConnectionEndpoint(FCB);
        Status = WarmSocketForConnection(FCB);
        if (!NT_SUCCESS(Status))
            break;

        if (FCB->ConnectReturnInfo)
        {
            ExFreePoolWithTag(FCB->ConnectReturnInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
        }

        Status = TdiBuildConnectionInfo(&FCB->ConnectReturnInfo,
                                        &ConnectReq->RemoteAddress);
        if (!NT_SUCCESS(Status))
            break;

        if (FCB->ConnectCallInfo)
        {
            ExFreePoolWithTag(FCB->ConnectCallInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);
        }

        Status = TdiBuildConnectionInfo(&FCB->ConnectCallInfo,
                                        &ConnectReq->RemoteAddress);


        if (!NT_SUCCESS(Status))
            break;

        FCB->ConnectCallInfo->UserData = FCB->ConnectData ?  FCB->ConnectData : FCB->OnConnectSendBuffer;
        FCB->ConnectCallInfo->UserDataLength = FCB->ConnectData ?  FCB->ConnectDataSize : FCB->OnConnectSendBufferSize;
        FCB->ConnectCallInfo->Options = FCB->ConnectOptions;
        FCB->ConnectCallInfo->OptionsLength = FCB->ConnectOptionsSize;
        FCB->SharedData.State = SOCKET_STATE_CONNECTING;
        /* An earlier connect's failure does not belong to this one */
        FCB->PollState &= ~AFD_EVENT_CONNECT_FAIL;
        FCB->AsyncConnectStatus = STATUS_SUCCESS;

        AFD_DbgPrint(MID_TRACE,("Queueing IRP %p\n", Irp));
        Status = QueueUserModeIrp( FCB, Irp, FUNCTION_CONNECTEX );
        if (Status == STATUS_PENDING)
        {
            SubmitConnect(FCB, Irp, FUNCTION_CONNECTEX);
        }
        else
        {
            /* Cancelled before it was queued, and completed */
            FCB->SharedData.State = SOCKET_STATE_BOUND;
            FreeConnectSendBuffer(FCB);
        }

        SocketStateUnlock(FCB);

        return Status;

    default:
        AFD_DbgPrint(MIN_TRACE,("Inappropriate socket state %u for connect\n",
                                FCB->SharedData.State));
        break;
    }

    /* No connect request carries the buffer on these paths */
    FreeConnectSendBuffer(FCB);
    return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
}
