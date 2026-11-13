/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/lock.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"

/* Upper bound on the LockBuffers pool block: well above any legitimate WSABUF
 * scatter/gather while keeping the size math clear of a 32-bit wrap. */
#define AFD_MAX_WSA_BUFFER_SIZE (16 * 1024 * 1024)

/* Captures of at most this many bytes (the input of nearly every socket control request) are copied
 * into a lookaside block without locking the caller's pages: no MDL, no probe-and-lock, no system
 * mapping, no pool call. */
#define AFD_FAST_CAPTURE_MAX 1024

static NPAGED_LOOKASIDE_LIST AfdCaptureLookaside;

VOID AfdInitCapture(VOID)
{
    ExInitializeNPagedLookasideList(&AfdCaptureLookaside, NULL, NULL, 0,
                                    AFD_FAST_CAPTURE_MAX, TAG_AFD_DATA_BUFFER, 0);
}

VOID AfdFreeCapture(VOID)
{
    ExDeleteNPagedLookasideList(&AfdCaptureLookaside);
}

/* Fast capture of a small METHOD_NEITHER ioctl input. Output asks for the input buffer to be written back
 * at UnlockRequest: that is only possible without the locked pages when the request is completed by the
 * thread that issued it (Synchronous), so the caller says so. Returns NULL when the fast path does not
 * apply (Fallback TRUE) or the buffer is not accessible (Fallback FALSE). */
static PVOID AfdFastCapture(PIRP Irp, PIO_STACK_LOCATION IrpSp, BOOLEAN Output,
                            KPROCESSOR_MODE *LockMode, BOOLEAN *Fallback)
{
    ULONG Length = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    PVOID Copy;
    BOOLEAN Failed = FALSE;

    *Fallback = TRUE;

    if (Length > AFD_FAST_CAPTURE_MAX)
        return NULL;

    if (Output &&
        (KeGetCurrentIrql() > APC_LEVEL ||
         (Irp->RequestorMode != KernelMode && IoGetRequestorProcess(Irp) != PsGetCurrentProcess())))
        return NULL;

    Copy = ExAllocateFromNPagedLookasideList(&AfdCaptureLookaside);
    if (!Copy)
    {
        *Fallback = FALSE;
        return NULL;
    }

    _SEH2_TRY {
        if (Irp->RequestorMode != KernelMode)
        {
            ProbeForRead(UserBuffer, Length, sizeof(UCHAR));
            if (Output)
                ProbeForWrite(UserBuffer, Length, sizeof(UCHAR));
        }
        RtlCopyMemory(Copy, UserBuffer, Length);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        Failed = TRUE;
    } _SEH2_END;

    if (Failed)
    {
        AFD_DbgPrint(MIN_TRACE,("Failed to access the request buffer\n"));
        ExFreeToNPagedLookasideList(&AfdCaptureLookaside, Copy);
        *Fallback = FALSE;
        return NULL;
    }

    /* No MDL: DriverContext[0] marks the request as captured. [1] is the user address to write back to. */
    Irp->Tail.Overlay.DriverContext[0] = Copy;
    Irp->Tail.Overlay.DriverContext[1] = Output ? UserBuffer : NULL;

    if (LockMode != NULL)
        *LockMode = UserMode;

    *Fallback = FALSE;
    return Copy;
}

PVOID GetLockedData(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ASSERT(AfdRequestLocked(Irp));
    ASSERT(Irp->Tail.Overlay.DriverContext[0]);

    UNREFERENCED_PARAMETER(IrpSp);

    return Irp->Tail.Overlay.DriverContext[0];
}

/* Validate the size of a METHOD_NEITHER request before it is locked and copied.
 * For ioctls the input buffer must be present and at least MinLength bytes
 * (and never empty); for read/write the user buffer must be present whenever
 * a length is given. Callers that interpret the request as a structure pass
 * the size of the part they actually read. */
BOOLEAN AfdRequestLengthValid( PIRP Irp,
                               PIO_STACK_LOCATION IrpSp,
                               ULONG MinLength ) {
    switch (IrpSp->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
            if (MinLength == 0)
                MinLength = 1;
            return IrpSp->Parameters.DeviceIoControl.Type3InputBuffer != NULL &&
                   IrpSp->Parameters.DeviceIoControl.InputBufferLength >= MinLength;

        case IRP_MJ_READ:
            return Irp->UserBuffer != NULL || IrpSp->Parameters.Read.Length == 0;

        case IRP_MJ_WRITE:
            return Irp->UserBuffer != NULL || IrpSp->Parameters.Write.Length == 0;

        default:
            return FALSE;
    }
}

static PVOID AfdLockRequest( PIRP Irp,
                             PIO_STACK_LOCATION IrpSp,
                             BOOLEAN Output,
                             BOOLEAN Synchronous,
                             KPROCESSOR_MODE *LockMode) {
    BOOLEAN LockFailed = FALSE;

    ASSERT(!AfdRequestLocked(Irp));

    /* Backstop: a NULL or empty request buffer is never valid (ASSERTs vanish
     * in release builds). Callers check their structure's minimum size first. */
    if (!AfdRequestLengthValid(Irp, IrpSp, 1))
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid request buffer\n"));
        return NULL;
    }

    switch (IrpSp->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        {
            BOOLEAN Fallback;
            PVOID Fast;

            /* An input that is only read, or one written back by a request that completes in the
             * caller's own context, needs no locked pages */
            if (!Output || Synchronous)
            {
                Fast = AfdFastCapture(Irp, IrpSp, Output, LockMode, &Fallback);
                if (Fast || !Fallback)
                    return Fast;
            }
        }

            Irp->MdlAddress =
            IoAllocateMdl( IrpSp->Parameters.DeviceIoControl.Type3InputBuffer,
                          IrpSp->Parameters.DeviceIoControl.InputBufferLength,
                          FALSE,
                          FALSE,
                          NULL );
            if( Irp->MdlAddress ) {
                _SEH2_TRY {
                    MmProbeAndLockPages( Irp->MdlAddress, Irp->RequestorMode, IoModifyAccess );
                } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
                    LockFailed = TRUE;
                } _SEH2_END;

                if( LockFailed ) {
                    AFD_DbgPrint(MIN_TRACE,("Failed to lock pages\n"));
                    IoFreeMdl( Irp->MdlAddress );
                    Irp->MdlAddress = NULL;
                    return NULL;
                }

                /* The mapped address goes in index 1 */
                Irp->Tail.Overlay.DriverContext[1] = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                if (!Irp->Tail.Overlay.DriverContext[1])
                {
                    AFD_DbgPrint(MIN_TRACE,("Failed to get mapped address\n"));
                    MmUnlockPages(Irp->MdlAddress);
                    IoFreeMdl( Irp->MdlAddress );
                    Irp->MdlAddress = NULL;
                    return NULL;
                }

                /* The allocated address goes in index 0 */
                Irp->Tail.Overlay.DriverContext[0] = ExAllocatePoolWithTag(NonPagedPool,
                                                                           MmGetMdlByteCount(Irp->MdlAddress),
                                                                           TAG_AFD_DATA_BUFFER);

                if (!Irp->Tail.Overlay.DriverContext[0])
                {
                    AFD_DbgPrint(MIN_TRACE,("Failed to allocate memory\n"));
                    MmUnlockPages(Irp->MdlAddress);
                    IoFreeMdl( Irp->MdlAddress );
                    Irp->MdlAddress = NULL;
                    return NULL;
                }

                RtlCopyMemory(Irp->Tail.Overlay.DriverContext[0],
                              Irp->Tail.Overlay.DriverContext[1],
                              MmGetMdlByteCount(Irp->MdlAddress));

                /* If we don't want a copy back, we zero the mapped address pointer */
                if (!Output)
                {
                    Irp->Tail.Overlay.DriverContext[1] = NULL;
                }

                /* We're using a user-mode buffer directly */
                if (LockMode != NULL)
                {
                    *LockMode = UserMode;
                }
            }
            else return NULL;
            break;

        case IRP_MJ_READ:
        case IRP_MJ_WRITE:
            Irp->MdlAddress =
            IoAllocateMdl(Irp->UserBuffer,
                          (IrpSp->MajorFunction == IRP_MJ_READ) ?
                                IrpSp->Parameters.Read.Length : IrpSp->Parameters.Write.Length,
                          FALSE,
                          FALSE,
                          NULL );
            if( Irp->MdlAddress ) {
                PAFD_RECV_INFO AfdInfo;

                _SEH2_TRY {
                    MmProbeAndLockPages( Irp->MdlAddress, Irp->RequestorMode, IoModifyAccess );
                } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
                    LockFailed = TRUE;
                } _SEH2_END;

                if( LockFailed ) {
                    AFD_DbgPrint(MIN_TRACE,("Failed to lock pages\n"));
                    IoFreeMdl( Irp->MdlAddress );
                    Irp->MdlAddress = NULL;
                    return NULL;
                }

                /* We need to create the info struct that AFD expects for all send/recv requests */
                AfdInfo = ExAllocatePoolWithTag(NonPagedPool,
                                                sizeof(AFD_RECV_INFO) + sizeof(AFD_WSABUF),
                                                TAG_AFD_DATA_BUFFER);

                if (!AfdInfo)
                {
                    AFD_DbgPrint(MIN_TRACE,("Failed to allocate memory\n"));
                    MmUnlockPages(Irp->MdlAddress);
                    IoFreeMdl( Irp->MdlAddress );
                    Irp->MdlAddress = NULL;
                    return NULL;
                }

                /* We'll append the buffer array to this struct */
                AfdInfo->BufferArray = (PAFD_WSABUF)(AfdInfo + 1);
                AfdInfo->BufferCount = 1;

                /* Setup the default flags values */
                AfdInfo->AfdFlags = 0;
                AfdInfo->TdiFlags = 0;

                /* Now build the buffer array. A zero-length transfer has no
                 * pages to map; leave the buffer empty (LockBuffers skips it). */
                if (MmGetMdlByteCount(Irp->MdlAddress) != 0)
                {
                    AfdInfo->BufferArray[0].buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                    if (!AfdInfo->BufferArray[0].buf)
                    {
                        AFD_DbgPrint(MIN_TRACE,("Failed to get mapped address\n"));
                        ExFreePoolWithTag(AfdInfo, TAG_AFD_DATA_BUFFER);
                        MmUnlockPages(Irp->MdlAddress);
                        IoFreeMdl( Irp->MdlAddress );
                        Irp->MdlAddress = NULL;
                        return NULL;
                    }
                }
                else
                {
                    AfdInfo->BufferArray[0].buf = NULL;
                }
                AfdInfo->BufferArray[0].len = MmGetMdlByteCount(Irp->MdlAddress);

                /* Store the struct where AFD expects */
                Irp->Tail.Overlay.DriverContext[0] = AfdInfo;

                /* Don't copy anything out */
                Irp->Tail.Overlay.DriverContext[1] = NULL;

                /* We're using a placeholder buffer that we allocated */
                if (LockMode != NULL)
                {
                    *LockMode = KernelMode;
                }
            }
            else return NULL;
            break;

        default:
            ASSERT(FALSE);
            return NULL;
    }

    return GetLockedData(Irp, IrpSp);
}

/* Lock a method_neither request so it'll be available from DISPATCH_LEVEL */
PVOID LockRequest( PIRP Irp,
                   PIO_STACK_LOCATION IrpSp,
                   BOOLEAN Output,
                   KPROCESSOR_MODE *LockMode) {
    return AfdLockRequest(Irp, IrpSp, Output, FALSE, LockMode);
}

/* As LockRequest, for a request that is answered and completed by the thread that issued it, at
 * PASSIVE_LEVEL, before the dispatch routine returns: the output is written back to the caller's buffer
 * without ever locking it */
PVOID LockRequestSync( PIRP Irp,
                       PIO_STACK_LOCATION IrpSp,
                       BOOLEAN Output,
                       KPROCESSOR_MODE *LockMode) {
    return AfdLockRequest(Irp, IrpSp, Output, TRUE, LockMode);
}

VOID UnlockRequest( PIRP Irp, PIO_STACK_LOCATION IrpSp )
{
    ASSERT(AfdRequestLocked(Irp));
    ASSERT(Irp->Tail.Overlay.DriverContext[0]);

    /* Captured without an MDL (AfdFastCapture) */
    if (!Irp->MdlAddress)
    {
        PVOID Copy = Irp->Tail.Overlay.DriverContext[0];
        PVOID UserBuffer = Irp->Tail.Overlay.DriverContext[1];

        if (UserBuffer != NULL)
        {
            _SEH2_TRY {
                RtlCopyMemory(UserBuffer, Copy, IrpSp->Parameters.DeviceIoControl.InputBufferLength);
            } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
                AFD_DbgPrint(MIN_TRACE,("Exception writing the request buffer\n"));
            } _SEH2_END;
        }

        ExFreeToNPagedLookasideList(&AfdCaptureLookaside, Copy);
        Irp->Tail.Overlay.DriverContext[0] = NULL;
        Irp->Tail.Overlay.DriverContext[1] = NULL;
        return;
    }

    /* Check if we need to copy stuff back */
    if (Irp->Tail.Overlay.DriverContext[1] != NULL)
    {
        RtlCopyMemory(Irp->Tail.Overlay.DriverContext[1],
                      Irp->Tail.Overlay.DriverContext[0],
                      MmGetMdlByteCount(Irp->MdlAddress));
    }

    ExFreePoolWithTag(Irp->Tail.Overlay.DriverContext[0], TAG_AFD_DATA_BUFFER);
    MmUnlockPages( Irp->MdlAddress );
    IoFreeMdl( Irp->MdlAddress );
    Irp->MdlAddress = NULL;
    Irp->Tail.Overlay.DriverContext[0] = NULL;
    Irp->Tail.Overlay.DriverContext[1] = NULL;
}

/* Releases the pages that LockBuffers locked for the first Count slots before a later slot failed:
 * the caller gets no array back, so nothing else would ever unlock them */
static VOID AfdUnlockBufferRange( PAFD_MAPBUF MapBuf, UINT Count ) {
    UINT j;

    for( j = 0; j < Count; j++ ) {
        if( MapBuf[j].Mdl ) {
            MmUnlockPages( MapBuf[j].Mdl );
            IoFreeMdl( MapBuf[j].Mdl );
            MapBuf[j].Mdl = NULL;
        }
    }
}

/* Note: We add EXTRA_LOCK_BUFFERS extra buffers if LockAddress is true.  This allows
 * us to treat the address buffer (and, for WSARecvMsg, the control buffer, its
 * length and the message flags: Msg) as ordinary client buffers.  They're only
 * used for datagrams. */

PAFD_WSABUF LockBuffers( PAFD_WSABUF Buf, UINT Count,
                         PVOID AddressBuf, PINT AddressLen,
                         BOOLEAN Write, BOOLEAN LockAddress,
                         KPROCESSOR_MODE LockMode,
                         PAFD_RECV_INFO_MSG Msg) {
    UINT i;
    /* Copy the buffer array so we don't lose it */
    UINT Lock = LockAddress ? EXTRA_LOCK_BUFFERS : 0;
    /* Count is user-supplied: size the block in 64-bit and cap it so a large Count
     * cannot wrap the 32-bit product and undersize the pool block we then fill. */
    ULONGLONG Size64 = (ULONGLONG)(sizeof(AFD_WSABUF) + sizeof(AFD_MAPBUF)) *
                       ((ULONGLONG)Count + Lock);
    SIZE_T Size = (SIZE_T)Size64;
    PAFD_WSABUF NewBuf;
    BOOLEAN LockFailed = FALSE;
    PAFD_MAPBUF MapBuf;

    if( Size64 > AFD_MAX_WSA_BUFFER_SIZE )
        return NULL;
    NewBuf = ExAllocatePoolWithTag(PagedPool, Size, TAG_AFD_WSA_BUFFER);

    AFD_DbgPrint(MID_TRACE,("Called(%p)\n", NewBuf));

    if( NewBuf ) {
        RtlZeroMemory(NewBuf, Size);

        MapBuf = (PAFD_MAPBUF)(NewBuf + Count + Lock);

        _SEH2_TRY {
            /* Buf and AddressLen are user-supplied pointers for user-mode
             * requests. Probe them so a kernel-mode pointer is rejected rather
             * than read outright: SEH traps faults but not a valid kernel read,
             * which would otherwise be an information-disclosure oracle. Kernel
             * callers (LockMode == KernelMode) pass legitimate kernel buffers. */
            if( LockMode == UserMode ) {
                if( Count )
                    ProbeForRead( Buf, sizeof(AFD_WSABUF) * Count, 1 );
                if( LockAddress && AddressBuf && AddressLen )
                    ProbeForRead( AddressLen, sizeof(*AddressLen), 1 );
                if( LockAddress && Msg && Msg->ControlLength )
                    ProbeForRead( Msg->ControlLength, sizeof(*Msg->ControlLength), 1 );
            }
            RtlCopyMemory( NewBuf, Buf, sizeof(AFD_WSABUF) * Count );
            if( LockAddress ) {
                if (AddressBuf && AddressLen) {
                    NewBuf[Count].buf = AddressBuf;
                    NewBuf[Count].len = *AddressLen;
                    NewBuf[Count + 1].buf = (PVOID)AddressLen;
                    NewBuf[Count + 1].len = sizeof(*AddressLen);
                }
                if (Msg && Msg->ControlLength) {
                    /* The control buffer is locked for the size it was given. The
                     * length and the flags are written back (an unlocked slot,
                     * for an absent pointer, is skipped when writing). */
                    NewBuf[Count + EXTRA_LOCK_CONTROL_LENGTH].buf = (PVOID)Msg->ControlLength;
                    NewBuf[Count + EXTRA_LOCK_CONTROL_LENGTH].len = sizeof(*Msg->ControlLength);
                    if (Msg->ControlBuffer) {
                        NewBuf[Count + EXTRA_LOCK_CONTROL].buf = Msg->ControlBuffer;
                        NewBuf[Count + EXTRA_LOCK_CONTROL].len = *Msg->ControlLength;
                    }
                }
                if (Msg && Msg->MsgFlags) {
                    NewBuf[Count + EXTRA_LOCK_MSG_FLAGS].buf = (PVOID)Msg->MsgFlags;
                    NewBuf[Count + EXTRA_LOCK_MSG_FLAGS].len = sizeof(*Msg->MsgFlags);
                }
                Count += EXTRA_LOCK_BUFFERS;
            }
        } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
            AFD_DbgPrint(MIN_TRACE,("Access violation copying buffer info "
                                    "from userland (%p %p)\n",
                                    Buf, AddressLen));
            ExFreePoolWithTag(NewBuf, TAG_AFD_WSA_BUFFER);
            _SEH2_YIELD(return NULL);
        } _SEH2_END;

        for( i = 0; i < Count; i++ ) {
            AFD_DbgPrint(MID_TRACE,("Locking buffer %u (%p:%u)\n",
                                    i, NewBuf[i].buf, NewBuf[i].len));

            if( NewBuf[i].buf && NewBuf[i].len ) {
                ULONG LockLength = NewBuf[i].len;

                /* The control buffer length is the caller's (up to 4 GB); AFD never writes
                 * more than one IP_PKTINFO message (16 byte header + 8), so pin only that.
                 * The slot keeps the full length: it is the capacity for MSG_CTRUNC. */
                if( LockAddress && Msg && i == Count - EXTRA_LOCK_BUFFERS + EXTRA_LOCK_CONTROL )
                    LockLength = MIN(LockLength, AFD_MAX_CONTROL_LOCK);

                MapBuf[i].Mdl = IoAllocateMdl( NewBuf[i].buf,
                                               LockLength,
                                               FALSE,
                                               FALSE,
                                               NULL );
            } else {
                MapBuf[i].Mdl = NULL;
                continue;
            }

            AFD_DbgPrint(MID_TRACE,("NewMdl @ %p\n", MapBuf[i].Mdl));

            if( MapBuf[i].Mdl ) {
                AFD_DbgPrint(MID_TRACE,("Probe and lock pages\n"));
                _SEH2_TRY {
                    MmProbeAndLockPages( MapBuf[i].Mdl, LockMode,
                                         Write ? IoModifyAccess : IoReadAccess );
                } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
                    LockFailed = TRUE;
                } _SEH2_END;
                AFD_DbgPrint(MID_TRACE,("MmProbeAndLock finished\n"));

                if( LockFailed ) {
            AFD_DbgPrint(MIN_TRACE,("Failed to lock pages\n"));
                    IoFreeMdl( MapBuf[i].Mdl );
                    MapBuf[i].Mdl = NULL;
                    AfdUnlockBufferRange( MapBuf, i );
                    ExFreePoolWithTag(NewBuf, TAG_AFD_WSA_BUFFER);
                    return NULL;
                }
            } else {
                AfdUnlockBufferRange( MapBuf, i );
                ExFreePoolWithTag(NewBuf, TAG_AFD_WSA_BUFFER);
                return NULL;
            }
        }
    }

    AFD_DbgPrint(MID_TRACE,("Leaving %p\n", NewBuf));

    return NewBuf;
}

VOID UnlockBuffers( PAFD_WSABUF Buf, UINT Count, BOOL Address ) {
    UINT Lock = Address ? EXTRA_LOCK_BUFFERS : 0;
    PAFD_MAPBUF Map = (PAFD_MAPBUF)(Buf + Count + Lock);
    UINT i;

    if( !Buf ) return;

    for( i = 0; i < Count + Lock; i++ ) {
        if( Map[i].Mdl ) {
            MmUnlockPages( Map[i].Mdl );
            IoFreeMdl( Map[i].Mdl );
            Map[i].Mdl = NULL;
        }
    }

    ExFreePoolWithTag(Buf, TAG_AFD_WSA_BUFFER);
    Buf = NULL;
}

/* Produce a kernel-land handle array with handles replaced by object
 * pointers.  This will allow the system to do proper alerting.
 * Every handle must name a socket of this device */
NTSTATUS LockHandles( PAFD_HANDLE HandleArray, UINT HandleCount,
                      PDEVICE_OBJECT DeviceObject, KPROCESSOR_MODE AccessMode,
                      PAFD_HANDLE *LockedHandles ) {
    UINT i;
    NTSTATUS Status = STATUS_SUCCESS;
    PFILE_OBJECT FileObject;
    PAFD_HANDLE FileObjects;

    *LockedHandles = NULL;

    FileObjects = ExAllocatePoolZero(NonPagedPool,
                                     HandleCount * sizeof(AFD_HANDLE),
                                     TAG_AFD_POLL_HANDLE);
    if( !FileObjects ) return STATUS_NO_MEMORY;

    for( i = 0; i < HandleCount; i++ ) {
        FileObjects[i].Events = HandleArray[i].Events;

        Status = ObReferenceObjectByHandle( (HANDLE)HandleArray[i].Handle,
                                            0,
                                            *IoFileObjectType,
                                            AccessMode,
                                            (PVOID*)&FileObject,
                                            NULL );
        if( !NT_SUCCESS(Status) ) {
            AFD_DbgPrint(MIN_TRACE,("Failed to reference handle %u (0x%x)\n", i, Status));
            break;
        }

        if( FileObject->DeviceObject != DeviceObject || !FileObject->FsContext ) {
            AFD_DbgPrint(MIN_TRACE,("Handle %u is not a socket\n", i));
            ObDereferenceObject( FileObject );
            Status = STATUS_INVALID_HANDLE;
            break;
        }

        FileObjects[i].Handle = (SOCKET)FileObject;
    }

    if( !NT_SUCCESS(Status) ) {
        UnlockHandles( FileObjects, HandleCount );
        return Status;
    }

    *LockedHandles = FileObjects;
    return STATUS_SUCCESS;
}

VOID UnlockHandles( PAFD_HANDLE HandleArray, UINT HandleCount ) {
    UINT i;

    for( i = 0; i < HandleCount; i++ ) {
        if( HandleArray[i].Handle )
            ObDereferenceObject( (PVOID)HandleArray[i].Handle );
    }

    ExFreePoolWithTag(HandleArray, TAG_AFD_POLL_HANDLE);
    HandleArray = NULL;
}

BOOLEAN SocketAcquireStateLock( PAFD_FCB FCB ) {
    if( !FCB ) return FALSE;

    return !KeWaitForMutexObject(&FCB->Mutex,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

BOOLEAN AfdHasInFlightRequest( PAFD_FCB FCB ) {
    return FCB->ConnectIrp.InFlightRequest || FCB->ListenIrp.InFlightRequest ||
           FCB->ReceiveIrp.InFlightRequest || FCB->SendIrp.InFlightRequest ||
           FCB->DisconnectIrp.InFlightRequest ||
           !IsListEmpty(&FCB->DatagramSendList);
}

VOID SocketStateUnlock( PAFD_FCB FCB ) {
    /* Wakes AfdCloseSocket, which waits for the transport requests of a closed socket */
    if (FCB->SharedData.State == SOCKET_STATE_CLOSED)
        KeSetEvent(&FCB->InFlightIdle, IO_NO_INCREMENT, FALSE);
    KeReleaseMutex(&FCB->Mutex, FALSE);
}

VOID AfdClearCancelRoutine( PIRP Irp ) {
    KIRQL OldIrql;

    /* IoCancelIrp claimed the routine and checks the IRP is not completed under the cancel lock */
    if (!IoSetCancelRoutine(Irp, NULL) && Irp->Cancel) {
        IoAcquireCancelSpinLock(&OldIrql);
        IoReleaseCancelSpinLock(OldIrql);
    }
}

NTSTATUS NTAPI UnlockAndMaybeComplete
( PAFD_FCB FCB, NTSTATUS Status, PIRP Irp,
  UINT Information ) {
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    if ( AfdRequestLocked(Irp) ) UnlockRequest( Irp, IoGetCurrentIrpStackLocation( Irp ) );
    AfdClearCancelRoutine(Irp);
    SocketStateUnlock( FCB );
    IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
    return Status;
}


NTSTATUS LostSocket( PIRP Irp ) {
    NTSTATUS Status = STATUS_FILE_CLOSED;
    AFD_DbgPrint(MIN_TRACE,("Called.\n"));
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;
    if ( AfdRequestLocked(Irp) ) UnlockRequest( Irp, IoGetCurrentIrpStackLocation( Irp ) );
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return Status;
}

/* Copy Length bytes of Data to the output of a METHOD_NEITHER request.
 * Irp->UserBuffer is the caller's raw pointer: the I/O manager never checks it.
 * Probe the whole declared output for a write (user-mode requests), as
 * AfdGetContext does, and copy under SEH, so a kernel address or an unmapped or
 * read-only page fails the request with the exception code instead of
 * becoming a kernel-mode write. */
NTSTATUS AfdCopyToUserOutput(PIRP Irp, PIO_STACK_LOCATION IrpSp,
                             const VOID *Data, ULONG Length)
{
    ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT(Length <= OutputLength);

    _SEH2_TRY
    {
        if (Irp->RequestorMode != KernelMode && OutputLength != 0)
            ProbeForWrite(Irp->UserBuffer, OutputLength, sizeof(UCHAR));
        if (Length != 0)
            RtlCopyMemory(Irp->UserBuffer, Data, Length);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        AFD_DbgPrint(MIN_TRACE,("Exception writing the output buffer\n"));
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;
}

NTSTATUS QueueUserModeIrp(PAFD_FCB FCB, PIRP Irp, UINT Function)
{
    NTSTATUS Status;

    /* Add the IRP to the queue in all cases (so AfdCancelHandler will work properly) */
    InsertTailList( &FCB->PendingIrpList[Function],
                   &Irp->Tail.Overlay.ListEntry );

    /* Acquire the cancel spin lock and check the cancel bit */
    IoAcquireCancelSpinLock(&Irp->CancelIrql);
    if (!Irp->Cancel)
    {
        /* We are not cancelled; we're good to go so
         * set the cancel routine, release the cancel spin lock,
         * mark the IRP as pending, and
         * return STATUS_PENDING to the caller
         */
        (void)IoSetCancelRoutine(Irp, AfdCancelHandler);
        IoReleaseCancelSpinLock(Irp->CancelIrql);
        IoMarkIrpPending(Irp);
        Status = STATUS_PENDING;
    }
    else
    {
        /* We were already cancelled before we were able to register our cancel routine
         * so we are to call the cancel routine ourselves right here to cancel the IRP
         * (which handles all the stuff we do above) and return STATUS_CANCELLED to the caller
         */
        AfdCancelHandler(IoGetCurrentIrpStackLocation(Irp)->DeviceObject,
                         Irp);
        Status = STATUS_CANCELLED;
    }

    return Status;
}

NTSTATUS LeaveIrpUntilLater( PAFD_FCB FCB, PIRP Irp, UINT Function ) {
    NTSTATUS Status;

    Status = QueueUserModeIrp(FCB, Irp, Function);

    SocketStateUnlock( FCB );

    return Status;
}
