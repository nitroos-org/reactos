/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/info.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"
#include <reactos/drivers/tdiext.h>
#include <tdiinfo.h>

NTSTATUS NTAPI
AfdGetInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp,
            PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PAFD_INFO InfoReq = LockRequestSync(Irp, IrpSp, TRUE, NULL);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PLIST_ENTRY CurrentEntry;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called %p %x\n", InfoReq,
                            InfoReq ? InfoReq->InformationClass : 0));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    if (!InfoReq)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    /* The captured METHOD_NEITHER input is only as large as the user-supplied
     * InputBufferLength (lock.c). Reading/writing the AFD_INFO fields below with
     * a short buffer would run off the pool copy, so reject undersized input. */
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_INFO))
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    _SEH2_TRY {
        switch( InfoReq->InformationClass ) {
        case AFD_INFO_RECEIVE_WINDOW_SIZE:
            InfoReq->Information.Ulong = FCB->Recv.Size;
            break;

        case AFD_INFO_SEND_WINDOW_SIZE:
            InfoReq->Information.Ulong = FCB->Send.Size;
            AFD_DbgPrint(MID_TRACE,("Send window size %u\n", FCB->Send.Size));
            break;

        case AFD_INFO_GROUP_ID_TYPE:
            InfoReq->Information.LargeInteger.u.HighPart = FCB->GroupType;
            InfoReq->Information.LargeInteger.u.LowPart = FCB->GroupID;
            AFD_DbgPrint(MID_TRACE, ("Group ID: %u Group Type: %u\n", FCB->GroupID, FCB->GroupType));
            break;

        case AFD_INFO_BLOCKING_MODE:
            InfoReq->Information.Boolean = FCB->NonBlocking;
            break;

    case AFD_INFO_INLINING_MODE:
        InfoReq->Information.Boolean = FCB->OobInline;
        break;

    case AFD_INFO_RECEIVE_CONTENT_SIZE:
        InfoReq->Information.Ulong = FCB->Recv.Content - FCB->Recv.BytesUsed;
        /* A queued zero-length datagram counts as one byte, as on Windows */
        if (InfoReq->Information.Ulong == 0 &&
            (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
            !IsListEmpty(&FCB->DatagramList))
            InfoReq->Information.Ulong = 1;
        break;

    case AFD_INFO_CONNECT_ERROR:
        InfoReq->Information.Ulong = (ULONG)FCB->AsyncConnectStatus;
        break;

    case AFD_INFO_CONNECTION_ABORTED:
        InfoReq->Information.Ulong = FCB->ConnectionAborted;
        break;

        case AFD_INFO_SENDS_IN_PROGRESS:
            InfoReq->Information.Ulong = 0;

            /* Count the queued sends */
            CurrentEntry = FCB->PendingIrpList[FUNCTION_SEND].Flink;
            while (CurrentEntry != &FCB->PendingIrpList[FUNCTION_SEND])
            {
                 InfoReq->Information.Ulong++;
                 CurrentEntry = CurrentEntry->Flink;
            }

        /* This needs to count too because when this is dispatched
         * the user-mode IRP has already been completed and therefore
         * will NOT be in our pending IRP list. We count this as one send
         * outstanding although it could be multiple since we batch sends
         * when waiting for the in flight request to return, so this number
         * may not be accurate but it really doesn't matter that much since
         * it's more or less a zero/non-zero comparison to determine whether
         * we can shutdown the socket
         */
        if (FCB->SendIrp.InFlightRequest)
            InfoReq->Information.Ulong++;
        break;

        default:
            AFD_DbgPrint(MIN_TRACE,("Unknown info id %x\n",
                                    InfoReq->InformationClass));
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        AFD_DbgPrint(MIN_TRACE,("Exception executing GetInfo\n"));
        Status = STATUS_INVALID_PARAMETER;
    } _SEH2_END;

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));

    return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
}

/* Gives the transport the receive window SO_RCVBUF asked for (a stream socket with a connection object):
 * the transport announces at most that to the peer, and announces more as the data is read (tcpip.sys).
 * Without a hint the transport gets its default window.
 *
 * On Windows a socket whose application does not read takes about twice SO_RCVBUF from the sender (measured on
 * Windows 10 22H2: the buffer of AFD, which FIONREAD reports, and the receive window of TCP; 8K, 64K and 1M all
 * match). AFD's own buffer here is its small staging area (Recv.Size), so the window makes up the rest. */
NTSTATUS
AfdApplyReceiveHint(PAFD_FCB FCB)
{
    PFILE_OBJECT FileObject = FCB->Connection.Object;
    PDEVICE_OBJECT DeviceObject;
    PTCP_REQUEST_SET_INFORMATION_EX Request;
    ULONG RequestSize = FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer) + sizeof(ULONG);
    ULONG Window;
    IO_STATUS_BLOCK Iosb;
    KEVENT Event;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;

    if (!FileObject || (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS))
        return STATUS_SUCCESS;

    /* No hint: 0, the transport's default window (a connection starts with 64K, the most a SYN announces).
     * A hint above 1 GB is clamped by the transport anyway (4 MB) */
    Window = min(FCB->RecvHint, 0x40000000UL);
    if (Window > FCB->Recv.Size)
        Window = Window * 2 - FCB->Recv.Size;

    Request = ExAllocatePoolWithTag(NonPagedPool, RequestSize, TAG_AFD_DATA_BUFFER);
    if (!Request)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(Request, RequestSize);
    Request->ID.toi_class = INFO_CLASS_PROTOCOL;
    Request->ID.toi_type = INFO_TYPE_CONNECTION;
    Request->ID.toi_id = TCP_SOCKET_WINDOW;
    Request->BufferSize = sizeof(ULONG);
    RtlCopyMemory(Request->Buffer, &Window, sizeof(ULONG));

    DeviceObject = IoGetRelatedDeviceObject(FileObject);
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildDeviceIoControlRequest(IOCTL_TCP_SET_INFORMATION_EX,
                                        DeviceObject,
                                        Request,
                                        RequestSize,
                                        NULL,
                                        0,
                                        FALSE,
                                        &Event,
                                        &Iosb);
    if (!Irp)
    {
        ExFreePoolWithTag(Request, TAG_AFD_DATA_BUFFER);
        return STATUS_NO_MEMORY;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->FileObject = FileObject;

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Iosb.Status;
    }

    ExFreePoolWithTag(Request, TAG_AFD_DATA_BUFFER);
    return Status;
}

NTSTATUS NTAPI
AfdSetInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp,
            PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PAFD_INFO InfoReq = LockRequest(Irp, IrpSp, FALSE, NULL);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PCHAR NewBuffer;
    BOOLEAN NewNonPaged;
    PEPROCESS NewQuotaProcess;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!InfoReq)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    /* See AfdGetInfo: reject input too small to hold the AFD_INFO we read. */
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_INFO))
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    _SEH2_TRY {
        switch (InfoReq->InformationClass) {
            case AFD_INFO_BLOCKING_MODE:
                AFD_DbgPrint(MID_TRACE,("Blocking mode set to %u\n", InfoReq->Information.Boolean));
                FCB->NonBlocking = InfoReq->Information.Boolean;
                break;
            case AFD_INFO_INLINING_MODE:
                FCB->OobInline = InfoReq->Information.Boolean;
                break;
            case AFD_INFO_RECEIVE_WINDOW_HINT:
                /* SO_RCVBUF: kept in any socket state and given to the transport once there is a connection
                 * (at connect and accept, MakeSocketIntoConnection). AFD_INFO_RECEIVE_WINDOW_SIZE reports
                 * the size of AFD's own buffer and is not changed by it. */
                if (InfoReq->Information.Ulong == 0)
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                FCB->RecvHint = InfoReq->Information.Ulong;
                if (FCB->SharedData.State == SOCKET_STATE_CONNECTED)
                    Status = AfdApplyReceiveHint(FCB);
                break;
            case AFD_INFO_RECEIVE_WINDOW_SIZE:
                if (FCB->SharedData.State == SOCKET_STATE_CONNECTED ||
                    FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)
                {
                    /* FIXME: likely not right, check tcpip.sys for TDI_QUERY_MAX_DATAGRAM_INFO */
                    if (InfoReq->Information.Ulong > 0 && InfoReq->Information.Ulong < 0xFFFF &&
                        InfoReq->Information.Ulong != FCB->Recv.Size)
                    {
                        /* Once a transport object is attached, Recv.Window is
                         * handed to TDI by raw pointer (read.c RefillSocketBuffer
                         * / RelaunchPacketReceive) and such a request outlives
                         * the FCB state lock we hold here. Freeing/reallocating
                         * the window would then leave the in-flight request
                         * writing incoming data into freed pool (use-after-free).
                         * Match Windows (and the AFD window-size apitest): the
                         * size is advisory (SO_RCVBUF) once the socket is
                         * bound/connected, so report success without touching the
                         * live buffer. Resizing is still allowed before any
                         * transport is attached (e.g. a fresh datagram socket),
                         * where nothing can reference the buffer. */
                        if (FCB->Connection.Object || FCB->AddressFile.Object)
                        {
                            Status = STATUS_SUCCESS;
                            break;
                        }

                        NewBuffer = AfdAllocRecvWindow(FCB,
                                                       InfoReq->Information.Ulong,
                                                       &NewNonPaged,
                                                       &NewQuotaProcess);

                        if (NewBuffer)
                        {
                            if (FCB->Recv.Content > InfoReq->Information.Ulong)
                                FCB->Recv.Content = InfoReq->Information.Ulong;

                            /* Keep the read cursor within the (possibly shrunk)
                             * content so later Content - BytesUsed arithmetic
                             * (info.c AFD_INFO_RECEIVE_CONTENT_SIZE, read.c)
                             * cannot underflow into a huge length */
                            if (FCB->Recv.BytesUsed > FCB->Recv.Content)
                                FCB->Recv.BytesUsed = FCB->Recv.Content;

                            if (FCB->Recv.Window)
                            {
                                RtlCopyMemory(NewBuffer,
                                              FCB->Recv.Window,
                                              FCB->Recv.Content);

                                /* Frees with the size it was allocated and charged with */
                                AfdFreeRecvWindow(FCB->Recv.Window,
                                                  FCB->Recv.Size,
                                                  FCB->Recv.NonPaged,
                                                  FCB->Recv.QuotaProcess);
                            }

                            FCB->Recv.Size = InfoReq->Information.Ulong;
                            FCB->Recv.Window = NewBuffer;
                            FCB->Recv.NonPaged = NewNonPaged;
                            FCB->Recv.QuotaProcess = NewQuotaProcess;

                            Status = STATUS_SUCCESS;
                        }
                        else
                        {
                            Status = STATUS_NO_MEMORY;
                        }
                    }
                    else
                    {
                        Status = STATUS_SUCCESS;
                    }
                }
                else
                {
                    Status = STATUS_INVALID_PARAMETER;
                }
                break;
            case AFD_INFO_SEND_WINDOW_SIZE:
                if (FCB->SharedData.State == SOCKET_STATE_CONNECTED ||
                    FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)
                {
                    if (InfoReq->Information.Ulong > 0 && InfoReq->Information.Ulong < 0xFFFF &&
                        InfoReq->Information.Ulong != FCB->Send.Size)
                    {
                        /* As for the receive window above: once a transport is
                         * attached, TdiSend (write.c) may hold a raw pointer into
                         * Send.Window past the FCB lock, so freeing/reallocating
                         * it would be a use-after-free. Report success without
                         * resizing the live buffer, matching Windows. */
                        if (FCB->Connection.Object || FCB->AddressFile.Object)
                        {
                            Status = STATUS_SUCCESS;
                            break;
                        }

                        NewBuffer = ExAllocatePoolWithTag(PagedPool,
                                                          InfoReq->Information.Ulong,
                                                          TAG_AFD_DATA_BUFFER);

                        if (NewBuffer)
                        {
                            if (FCB->Send.BytesUsed > InfoReq->Information.Ulong)
                                FCB->Send.BytesUsed = InfoReq->Information.Ulong;

                            if (FCB->Send.Window)
                            {
                                RtlCopyMemory(NewBuffer,
                                              FCB->Send.Window,
                                              FCB->Send.BytesUsed);

                                ExFreePoolWithTag(FCB->Send.Window, TAG_AFD_DATA_BUFFER);
                            }

                            FCB->Send.Size = InfoReq->Information.Ulong;
                            FCB->Send.Window = NewBuffer;

                            Status = STATUS_SUCCESS;
                        }
                        else
                        {
                            Status = STATUS_NO_MEMORY;
                        }
                    }
                    else
                    {
                        Status = STATUS_SUCCESS;
                    }
                }
                else
                {
                    Status = STATUS_INVALID_PARAMETER;
                }
                break;
            default:
                AFD_DbgPrint(MIN_TRACE,("Unknown request %u\n", InfoReq->InformationClass));
                break;
        }
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        AFD_DbgPrint(MIN_TRACE,("Exception executing SetInfo\n"));
        Status = STATUS_INVALID_PARAMETER;
    } _SEH2_END;

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));

    return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
}

/* Runs a TDI query into a kernel buffer; the query takes ownership of the MDL */
static NTSTATUS
AfdQueryTransportBuffer(PFILE_OBJECT Object, LONG QueryType, PVOID Buffer, ULONG Size)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMDL Mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, NULL);

    if (Mdl == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    _SEH2_TRY {
        MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        Status = _SEH2_GetExceptionCode();
    } _SEH2_END;

    if (!NT_SUCCESS(Status))
    {
        IoFreeMdl(Mdl);
        return Status;
    }

    return TdiQueryInformation(Object, QueryType, Mdl);
}

/* The address of the interface a datagram from this socket to Destination (a
 * network-order IPv4 address) leaves from, asked of any object of the transport;
 * fails when there is no route */
NTSTATUS
AfdQueryRouteSourceOn(PFILE_OBJECT Object, ULONG Destination, PULONG Source)
{
    PTA_IP_ADDRESS Query;
    NTSTATUS Status;

    Query = ExAllocatePoolWithTag(NonPagedPool, 64, TAG_AFD_TRANSPORT_ADDRESS);
    if (Query == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Query, 64);

    Query->TAAddressCount = 1;
    Query->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    Query->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    Query->Address[0].Address[0].in_addr = Destination;

    Status = AfdQueryTransportBuffer(Object,
                                     TDI_QUERY_ROS_SOURCE_ADDRESS,
                                     Query,
                                     sizeof(TA_IP_ADDRESS));
    if (NT_SUCCESS(Status))
        *Source = Query->Address[0].Address[0].in_addr;

    ExFreePoolWithTag(Query, TAG_AFD_TRANSPORT_ADDRESS);
    return Status;
}

NTSTATUS
AfdQueryRouteSource(PAFD_FCB FCB, ULONG Destination, PULONG Source)
{
    return AfdQueryRouteSourceOn(FCB->AddressFile.Object, Destination, Source);
}

/* The local name of a connected socket whose transport object only knows the
 * wildcard address (a connected datagram socket, or the end of an accepted TCP
 * connection, which the transport files under the listener's binding): a socket
 * bound to the wildcard address reports the address of the interface its traffic
 * to the peer leaves from, as Windows does. QueryObject is the transport object to ask.
 * Called with the state lock held; completes the IRP. */
static NTSTATUS
AfdGetConnectedName(PAFD_FCB FCB, PFILE_OBJECT QueryObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    const ULONG InfoSize = FIELD_OFFSET(TDI_ADDRESS_INFO, Address.Address[0].Address) +
                           sizeof(TDI_ADDRESS_IP);
    PTDI_ADDRESS_INFO Info;
    PTDI_ADDRESS_IP Local, Remote;
    ULONG Source;
    NTSTATUS Status;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < InfoSize)
        return UnlockAndMaybeComplete(FCB, STATUS_BUFFER_TOO_SMALL, Irp, 0);

    Info = ExAllocatePoolWithTag(NonPagedPool, 64, TAG_AFD_TRANSPORT_ADDRESS);
    if (Info == NULL)
        return UnlockAndMaybeComplete(FCB, STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
    RtlZeroMemory(Info, 64);

    Status = AfdQueryTransportBuffer(QueryObject,
                                     TDI_QUERY_ADDRESS_INFO,
                                     Info,
                                     InfoSize);
    if (NT_SUCCESS(Status))
    {
        Local = (PTDI_ADDRESS_IP)Info->Address.Address[0].Address;
        Remote = (PTDI_ADDRESS_IP)FCB->RemoteAddress->Address[0].Address;

        if (Local->in_addr == 0 && Remote->in_addr != 0)
        {
            /* Without a route the socket stays on the wildcard address */
            if (NT_SUCCESS(AfdQueryRouteSourceOn(QueryObject, Remote->in_addr, &Source)))
                Local->in_addr = Source;
        }

        /* This is a METHOD_NEITHER IOCTL: probe the raw user pointer and copy under SEH */
        _SEH2_TRY {
            if (Irp->RequestorMode != KernelMode)
                ProbeForWrite(Irp->UserBuffer, InfoSize, sizeof(CHAR));
            RtlCopyMemory(Irp->UserBuffer, Info, InfoSize);
        } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
            Status = STATUS_INVALID_PARAMETER;
        } _SEH2_END;
    }

    ExFreePoolWithTag(Info, TAG_AFD_TRANSPORT_ADDRESS);

    return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
}

NTSTATUS NTAPI
AfdGetSockName( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PMDL Mdl = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);
    ASSERT(Irp->MdlAddress == NULL);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    if( FCB->AddressFile.Object == NULL && FCB->Connection.Object == NULL ) {
         return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
    }

    /* connect() on a datagram socket only records the peer */
    if( (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
        FCB->AddressFile.Object &&
        FCB->RemoteAddress &&
        FCB->RemoteAddress->TAAddressCount == 1 &&
        FCB->RemoteAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP &&
        FCB->RemoteAddress->Address[0].AddressLength >= TDI_ADDRESS_LENGTH_IP ) {
        return AfdGetConnectedName( FCB, FCB->AddressFile.Object, Irp, IrpSp );
    }

    /* An accepted TCP connection: the transport reports the listener's binding
     * for it, the wildcard address when the listener has no concrete one */
    if( !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
        FCB->SharedData.State == SOCKET_STATE_CONNECTED &&
        FCB->Connection.Object &&
        FCB->RemoteAddress &&
        FCB->RemoteAddress->TAAddressCount == 1 &&
        FCB->RemoteAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP &&
        FCB->RemoteAddress->Address[0].AddressLength >= TDI_ADDRESS_LENGTH_IP ) {
        return AfdGetConnectedName( FCB, FCB->Connection.Object, Irp, IrpSp );
    }

    Mdl = IoAllocateMdl( Irp->UserBuffer,
                         IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
                         FALSE,
                         FALSE,
                         NULL );

    if( Mdl != NULL ) {
        _SEH2_TRY {
            MmProbeAndLockPages( Mdl, Irp->RequestorMode, IoModifyAccess );
        } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
            AFD_DbgPrint(MIN_TRACE, ("MmProbeAndLockPages() failed.\n"));
            Status = _SEH2_GetExceptionCode();
        } _SEH2_END;

        if( NT_SUCCESS(Status) ) {
            /* TdiQueryInformation takes the locked MDL: the transport request
             * unlocks and frees it when it completes, whether the query
             * succeeds or fails. Freeing it here as well would put it on the
             * MDL lookaside list twice. */
            /* A refused or cancelled connect leaves its connection endpoint
             * behind with no address attached, but the socket keeps the
             * (possibly implicit) local binding of its address file, which
             * Windows reports. Ask the connection only while it is the live
             * one: connecting, connected, or with no address file to ask. */
            Status = TdiQueryInformation( (FCB->Connection.Object &&
                                           (FCB->SharedData.State == SOCKET_STATE_CONNECTED ||
                                            FCB->SharedData.State == SOCKET_STATE_CONNECTING ||
                                            FCB->AddressFile.Object == NULL))
                                            ? FCB->Connection.Object
                                            : FCB->AddressFile.Object,
                                          TDI_QUERY_ADDRESS_INFO,
                                          Mdl );
        } else {
            /* The probe failed: the MDL is not locked and was never handed off */
            IoFreeMdl(Mdl);
        }
    } else
        Status = STATUS_INSUFFICIENT_RESOURCES;

    return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
}

NTSTATUS NTAPI
AfdGetPeerName( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    if (FCB->RemoteAddress == NULL) {
        AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
    }

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= TaLengthOfTransportAddress(FCB->RemoteAddress))
    {
        /* This is a METHOD_NEITHER IOCTL, so Irp->UserBuffer is the raw,
         * unvalidated user output pointer. Probe it for the write (when the
         * request came from user mode) and copy under SEH so a bad or
         * concurrently-unmapped address cannot turn into a kernel-mode write to
         * an arbitrary address. */
        _SEH2_TRY {
            if (Irp->RequestorMode != KernelMode)
                ProbeForWrite(Irp->UserBuffer,
                              TaLengthOfTransportAddress(FCB->RemoteAddress),
                              sizeof(CHAR));
            RtlCopyMemory(Irp->UserBuffer, FCB->RemoteAddress, TaLengthOfTransportAddress(FCB->RemoteAddress));
            Status = STATUS_SUCCESS;
        } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
            AFD_DbgPrint(MIN_TRACE,("Exception writing peer name\n"));
            Status = STATUS_INVALID_PARAMETER;
        } _SEH2_END;
    }
    else
    {
        AFD_DbgPrint(MIN_TRACE,("Buffer too small\n"));
        Status = STATUS_BUFFER_TOO_SMALL;
    }

    return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
}
