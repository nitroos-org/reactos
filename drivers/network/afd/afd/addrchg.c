/*
 * PROJECT:     NitroOS ancillary function driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Requests for the next change of the address list, kept pending in the driver
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * msafd (misc/addrchg.c) learns of an address change from the TCP/IP driver. A request of SIO_ADDRESS_LIST_CHANGE that
 * the caller made with an OVERLAPPED and no completion routine must complete through the completion port of the socket
 * the way every other overlapped request does, and only the driver that owns the socket's file object can do that.
 * IOCTL_AFD_ADDRCHANGE_WAIT therefore stays pending in the driver (the OVERLAPPED is its status block and context) and
 * IOCTL_AFD_ADDRCHANGE_COMPLETE completes the waiting requests of the socket. Closing the socket cancels them, so the
 * port gets the aborted request, as on Windows.
 */

#include "afd.h"

NTSTATUS AfdAddrChangeWait( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                            PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    return LeaveIrpUntilLater( FCB, Irp, FUNCTION_ADDRCHANGE );
}

NTSTATUS AfdAddrChangeComplete( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                                PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    NTSTATUS Result = STATUS_SUCCESS;
    PLIST_ENTRY Entry;
    PIRP Waiting;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(NTSTATUS) )
        Result = *(PNTSTATUS)Irp->AssociatedIrp.SystemBuffer;

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    while( !IsListEmpty( &FCB->PendingIrpList[FUNCTION_ADDRCHANGE] ) ) {
        Entry = RemoveHeadList( &FCB->PendingIrpList[FUNCTION_ADDRCHANGE] );
        Waiting = CONTAINING_RECORD( Entry, IRP, Tail.Overlay.ListEntry );

        Waiting->IoStatus.Status = Result;
        Waiting->IoStatus.Information = 0;
        AfdClearCancelRoutine( Waiting );
        IoCompleteRequest( Waiting, IO_NETWORK_INCREMENT );
    }

    return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );
}
