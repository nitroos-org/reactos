/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/bind.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"

NTSTATUS WarmSocketForBind( PAFD_FCB FCB, ULONG ShareType ) {
    NTSTATUS Status;

    AFD_DbgPrint(MID_TRACE,("Called (AF %u)\n",
                            FCB->LocalAddress->Address[0].AddressType));

    if( !FCB->TdiDeviceName.Length || !FCB->TdiDeviceName.Buffer ) {
        AFD_DbgPrint(MIN_TRACE,("Null Device\n"));
        return STATUS_NO_SUCH_DEVICE;
    }
    if( !FCB->LocalAddress ) {
        AFD_DbgPrint(MIN_TRACE,("No local address\n"));
        return STATUS_INVALID_PARAMETER;
    }

    /* Used to restart the receive from a system thread (read.c). Allocated
     * before the address is opened, so that its failure leaves nothing open */
    if ((FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) && !FCB->RecvRelaunchWorkItem)
    {
        FCB->RecvRelaunchWorkItem = IoAllocateWorkItem(FCB->FileObject->DeviceObject);
        if (!FCB->RecvRelaunchWorkItem)
            return STATUS_NO_MEMORY;
    }

    Status = TdiOpenAddressFile(&FCB->TdiDeviceName,
                                FCB->LocalAddress,
                                ShareType,
                                &FCB->AddressFile.Handle,
                                &FCB->AddressFile.Object );
    if (!NT_SUCCESS(Status))
        return Status;

    if (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)
    {
        /* The receive reports the source address and, through the Options, the packet
         * information in AddressFrom. An implicit bind (connect) has not built it yet. */
        if (!FCB->AddressFrom)
            Status = TdiBuildConnectionInfo(&FCB->AddressFrom, FCB->LocalAddress);

        if (NT_SUCCESS(Status) && FCB->AddressFrom)
        {
            RtlZeroMemory(&FCB->RecvPktInfo, sizeof(FCB->RecvPktInfo));
            FCB->AddressFrom->Options = &FCB->RecvPktInfo;
            FCB->AddressFrom->OptionsLength = sizeof(FCB->RecvPktInfo);
        }

        if (NT_SUCCESS(Status) && !FCB->Recv.Size)
        {
            Status = TdiQueryMaxDatagramLength(FCB->AddressFile.Object,
                                               &FCB->Recv.Size);
        }

        if (NT_SUCCESS(Status) && !FCB->Recv.Window)
        {
            FCB->Recv.Window = ExAllocatePoolWithTag(PagedPool,
                                                     FCB->Recv.Size,
                                                     TAG_AFD_DATA_BUFFER);

            if (!FCB->Recv.Window)
                Status = STATUS_NO_MEMORY;
        }

        if (NT_SUCCESS(Status) && FCB->Recv.Content < FCB->Recv.Size)
        {
            Status = TdiReceiveDatagram(&FCB->ReceiveIrp.InFlightRequest,
                                        FCB->AddressFile.Object,
                                        0,
                                        FCB->Recv.Window,
                                        FCB->Recv.Size,
                                        FCB->AddressFrom,
                                        PacketSocketRecvComplete,
                                        FCB);

            /* We don't want to wait for this read to complete. */
            if( Status == STATUS_PENDING ) Status = STATUS_SUCCESS;
        }
    }

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));

    return Status;
}

NTSTATUS NTAPI
AfdBindSocket(PDEVICE_OBJECT DeviceObject, PIRP Irp,
              PIO_STACK_LOCATION IrpSp) {
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_BIND_DATA BindReq;
    HANDLE UserHandle = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called\n"));

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );
    if( !(BindReq = LockRequest( Irp, IrpSp, FALSE, NULL )) )
        return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY,
                                       Irp, 0 );
    
    if (FCB->SharedData.State != SOCKET_STATE_CREATED)
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    /* The address must be complete for its type, within what was supplied */
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < FIELD_OFFSET(AFD_BIND_DATA, Address) ||
        !TaTransportAddressFits( &BindReq->Address,
            IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_BIND_DATA, Address)))
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);

    if (FCB->LocalAddress)
    {
        ExFreePoolWithTag(FCB->LocalAddress, TAG_AFD_TRANSPORT_ADDRESS);
    }

    /* BindReq is the captured user IOCTL buffer; bound the copy to the bytes
     * actually supplied so a lying Address[0].AddressLength cannot over-read
     * adjacent pool into LocalAddress (which getsockname later returns). */
    FCB->LocalAddress =
        (IrpSp->Parameters.DeviceIoControl.InputBufferLength >= FIELD_OFFSET(AFD_BIND_DATA, Address))
            ? TaCopyTransportAddressBounded( &BindReq->Address,
                  IrpSp->Parameters.DeviceIoControl.InputBufferLength - FIELD_OFFSET(AFD_BIND_DATA, Address))
            : NULL;

    if( FCB->LocalAddress && !FCB->AddressFrom )
        Status = TdiBuildConnectionInfo( &FCB->AddressFrom,
                                         FCB->LocalAddress );

    if( NT_SUCCESS(Status) )
        Status = WarmSocketForBind( FCB, BindReq->ShareType );
    AFD_DbgPrint(MID_TRACE,("FCB->Flags %x\n", FCB->Flags));

    /* The transport has read the connect hint (AFD_TCP_CONNECT_HINT) from the padding of the address; getsockname
     * returns this address, which has to show zeros there as it always did */
    if (FCB->LocalAddress &&
        FCB->LocalAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP &&
        FCB->LocalAddress->Address[0].AddressLength >= TDI_ADDRESS_LENGTH_IP)
    {
        PTA_IP_ADDRESS LocalIp = (PTA_IP_ADDRESS)FCB->LocalAddress;

        RtlZeroMemory(LocalIp->Address[0].Address[0].sin_zero, sizeof(LocalIp->Address[0].Address[0].sin_zero));
    }

    if (NT_SUCCESS(Status))
    {
        Status = ObOpenObjectByPointer(FCB->AddressFile.Object,
                                       0,
                                       NULL,
                                       MAXIMUM_ALLOWED,
                                       *IoFileObjectType,
                                       Irp->RequestorMode,
                                       &UserHandle);
        if (NT_SUCCESS(Status))
        {
            FCB->SharedData.State = SOCKET_STATE_BOUND;

            /* A bound datagram socket signals FD_WRITE */
            if (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)
            {
                FCB->EventSelectDisabled &= ~AFD_EVENT_SEND;
                PollReeval( FCB->DeviceExt, FCB->FileObject );
            }
        }
    }

    /* MSAFD relies on us returning the address file handle in the IOSB */
    return UnlockAndMaybeComplete( FCB, Status, Irp,
                                   (ULONG_PTR)UserHandle);
}
