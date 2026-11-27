/*
 * PROJECT:     NitroOS ancillary function driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The request that stands for an overlapped TransmitFile or TransmitPackets of msafd
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * msafd (misc/transmit.c) does an overlapped TransmitFile in a worker thread with ordinary sends. The caller's
 * CancelIoEx(socket, &ov) looks for a request of the socket with that OVERLAPPED, and there was none: the transfer
 * went on until the socket was closed. The calling thread therefore makes a hold (IOCTL_AFD_TRANSMIT_HOLD) with its
 * OVERLAPPED as the status block and completion context and its event, before the worker starts; the hold stays
 * pending here until the worker completes it with the result of the transfer (IOCTL_AFD_TRANSMIT_COMPLETE): the
 * caller is told through its event and the completion port of the socket like for any other request, and the hold
 * is the calling thread's request (CancelIo of that thread finds it, the end of that thread cancels it).
 *
 * A cancel of the hold stops the transfer as Windows does (measured on Windows Server 2022: the request completes
 * with STATUS_CANCELLED and the bytes sent so far, a later send fails with WSAECONNABORTED and the peer gets a
 * reset): the connection is aborted, the worker's sends fail, and the worker completes the hold, which then reports
 * STATUS_CANCELLED. A hold is completed at once with STATUS_CANCELLED when nobody may wait for the worker (the thread
 * that made it is ending, or the socket is cleaned up).
 */

#include "afd.h"

/* Holds are kept on FCB->TransmitHolds; DriverContext[2] is the hold's number (FCB->TransmitHoldSequence, never 0),
 * DriverContext[3] is set once a cancel asked for the transfer to stop */
#define AfdHoldSequence(Irp) ((ULONG)(ULONG_PTR)(Irp)->Tail.Overlay.DriverContext[2])
#define AfdHoldCancelled(Irp) ((Irp)->Tail.Overlay.DriverContext[3] != NULL)

/* The hold with that number, if it is still queued. The cancel routine looks its hold up by number, not by address:
 * once the cancel lock is let go the hold may be completed and its IRP freed, and the same address may come back as
 * a new hold of the same socket, which has another number. The state lock is held */
static PIRP AfdFindHold( PAFD_FCB FCB, ULONG Sequence ) {
    PLIST_ENTRY Entry;
    PIRP Hold;

    for( Entry = FCB->TransmitHolds.Flink; Entry != &FCB->TransmitHolds; Entry = Entry->Flink ) {
        Hold = CONTAINING_RECORD( Entry, IRP, Tail.Overlay.ListEntry );
        if( AfdHoldSequence( Hold ) == Sequence )
            return Hold;
    }
    return NULL;
}

static DRIVER_CANCEL AfdTransmitHoldCancel;
static VOID NTAPI AfdTransmitHoldCancel( PDEVICE_OBJECT DeviceObject, PIRP Irp ) {
    /* As AfdCancelHandler: the socket comes from the IRP, and is kept while the cancel lock is let go */
    PFILE_OBJECT FileObject = Irp->Tail.Overlay.OriginalFileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    ULONG Sequence = AfdHoldSequence( Irp );
    KIRQL OldIrql;
    BOOLEAN Now;

    UNREFERENCED_PARAMETER(DeviceObject);

    ObReferenceObject( FileObject );
    IoReleaseCancelSpinLock( Irp->CancelIrql );

    /* Irp may be completed and gone from here on (AfdTransmitComplete, the cleanup): only the number is used */
    if( !SocketAcquireStateLock( FCB ) ) {
        ObDereferenceObject( FileObject );
        return;
    }

    Irp = AfdFindHold( FCB, Sequence );
    if( !Irp ) {
        /* Completed meanwhile */
        SocketStateUnlock( FCB );
        ObDereferenceObject( FileObject );
        return;
    }

    /* The thread that made the hold is ending (the end of its process, or of the thread: its I/O is cancelled, and
     * it waits for that), or the socket is cleaned up: nobody may wait for the worker. The transfer is stopped all
     * the same. (A cancel by another thread of the process runs here on the thread that made the hold, from a
     * kernel APC: the thread does not tell who cancelled) */
    Now = !Irp->Tail.Overlay.Thread || PsIsThreadTerminating( Irp->Tail.Overlay.Thread ) || FCB->CleanedUp;

    if( !Now ) {
        /* The caller stopped the transfer: the connection is aborted (the worker's sends fail with it) and the
         * worker completes the hold, as cancelled */
        Irp->Tail.Overlay.DriverContext[3] = (PVOID)1;
        AfdAbortConnection( FCB );

        /* Armed again, so that a later cancel still finds it: the end of the thread that made it (IoCancelThreadIo
         * waits for its requests, and the worker may never complete this one: the process is terminated, or the
         * worker is held up in a file read). That thread sets its terminated flag before it cancels its requests,
         * and IoCancelIrp takes the cancel lock: either the flag is seen here, or the cancel comes after the routine
         * is set */
        IoAcquireCancelSpinLock( &OldIrql );
        if( !PsIsThreadTerminating( Irp->Tail.Overlay.Thread ) ) {
            (void)IoSetCancelRoutine( Irp, AfdTransmitHoldCancel );
            IoReleaseCancelSpinLock( OldIrql );
            SocketStateUnlock( FCB );
            ObDereferenceObject( FileObject );
            return;
        }
        IoReleaseCancelSpinLock( OldIrql );
    }

    RemoveEntryList( &Irp->Tail.Overlay.ListEntry );
    if( !FCB->CleanedUp )
        AfdAbortConnection( FCB );
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    SocketStateUnlock( FCB );
    IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
    ObDereferenceObject( FileObject );
}

NTSTATUS AfdTransmitHold( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                          PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    /* A hold has no buffers: its completion reports the bytes of the transfer, and must copy nothing */
    if( IrpSp->Parameters.DeviceIoControl.InputBufferLength != 0 ||
        IrpSp->Parameters.DeviceIoControl.OutputBufferLength != 0 ||
        Irp->UserBuffer != NULL || Irp->MdlAddress != NULL ||
        (Irp->Flags & (IRP_BUFFERED_IO | IRP_INPUT_OPERATION)) ||
        Irp->RequestorMode != UserMode )
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

    /* Only a stream socket transmits; nobody would end a hold made after the cleanup */
    if( (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) || FCB->CleanedUp )
        return UnlockAndMaybeComplete( FCB, FCB->CleanedUp ? STATUS_CANCELLED : STATUS_INVALID_PARAMETER, Irp, 0 );

    if( ++FCB->TransmitHoldSequence == 0 )
        FCB->TransmitHoldSequence = 1;
    Irp->Tail.Overlay.DriverContext[2] = (PVOID)(ULONG_PTR)FCB->TransmitHoldSequence;
    Irp->Tail.Overlay.DriverContext[3] = NULL;
    InsertTailList( &FCB->TransmitHolds, &Irp->Tail.Overlay.ListEntry );

    IoAcquireCancelSpinLock( &Irp->CancelIrql );
    if( Irp->Cancel ) {
        /* Cancelled before the routine was set: it never started */
        IoReleaseCancelSpinLock( Irp->CancelIrql );
        RemoveEntryList( &Irp->Tail.Overlay.ListEntry );
        return UnlockAndMaybeComplete( FCB, STATUS_CANCELLED, Irp, 0 );
    }
    (void)IoSetCancelRoutine( Irp, AfdTransmitHoldCancel );
    IoReleaseCancelSpinLock( Irp->CancelIrql );

    IoMarkIrpPending( Irp );
    SocketStateUnlock( FCB );
    return STATUS_PENDING;
}

NTSTATUS AfdTransmitComplete( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                              PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    AFD_TRANSMIT_RESULT Result;
    PLIST_ENTRY Entry;
    PIRP Hold = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket( Irp );

    if( IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(Result) || !Irp->AssociatedIrp.SystemBuffer )
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );
    RtlCopyMemory( &Result, Irp->AssociatedIrp.SystemBuffer, sizeof(Result) );

    /* A request does not complete as pending */
    if( Result.Status == STATUS_PENDING || Result.Iosb == 0 )
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER, Irp, 0 );

    for( Entry = FCB->TransmitHolds.Flink; Entry != &FCB->TransmitHolds; Entry = Entry->Flink ) {
        PIRP Candidate = CONTAINING_RECORD( Entry, IRP, Tail.Overlay.ListEntry );

        if( (ULONG_PTR)Candidate->UserIosb == (ULONG_PTR)Result.Iosb ) {
            Hold = Candidate;
            break;
        }
    }

    /* Cancelled already (by its own worker, at its end, or by the cleanup) */
    if( !Hold )
        return UnlockAndMaybeComplete( FCB, STATUS_NOT_FOUND, Irp, 0 );

    RemoveEntryList( &Hold->Tail.Overlay.ListEntry );
    Hold->IoStatus.Status = AfdHoldCancelled( Hold ) ? STATUS_CANCELLED : (NTSTATUS)Result.Status;
    Hold->IoStatus.Information = (ULONG_PTR)Result.Information;
    AfdClearCancelRoutine( Hold );
    IoCompleteRequest( Hold, IO_NETWORK_INCREMENT );

    return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );
}

/* The cleanup of the socket: nobody can complete a hold any more (the worker holds a handle of its own, so the
 * cleanup comes after it, unless its process is ending). The state lock is held */
VOID AfdCompleteTransmitHolds( PAFD_FCB FCB ) {
    PLIST_ENTRY Entry;
    PIRP Hold;

    while( !IsListEmpty( &FCB->TransmitHolds ) ) {
        Entry = RemoveHeadList( &FCB->TransmitHolds );
        Hold = CONTAINING_RECORD( Entry, IRP, Tail.Overlay.ListEntry );
        Hold->IoStatus.Status = STATUS_CANCELLED;
        Hold->IoStatus.Information = 0;
        AfdClearCancelRoutine( Hold );
        IoCompleteRequest( Hold, IO_NETWORK_INCREMENT );
    }
}
