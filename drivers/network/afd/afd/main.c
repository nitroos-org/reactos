/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/main.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040630 Created
 *
 * Suggestions: Uniform naming (AfdXxx)
 */

/* INCLUDES */

#include "afd.h"
#include "wdm.h"

#if DBG

/* See debug.h for debug/trace constants */
//DWORD DebugTraceLevel = DEBUG_ULTRA;
DWORD DebugTraceLevel = MIN_TRACE;

#endif /* DBG */

/* FIXME: should depend on SystemSize */
ULONG AfdReceiveWindowSize = 0x2000;
ULONG AfdSendWindowSize = 0x2000;

void OskitDumpBuffer( PCHAR Data, UINT Len ) {
    unsigned int i;

    for( i = 0; i < Len; i++ ) {
        if( i && !(i & 0xf) ) DbgPrint( "\n" );
        if( !(i & 0xf) ) DbgPrint( "%p: ", (Data + i) );
        DbgPrint( " %02x", Data[i] & 0xff );
    }
    DbgPrint("\n");
}

/* FUNCTIONS */

NTSTATUS NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

NTSTATUS NTAPI
AfdGetDisconnectOptions(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                        PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (FCB->DisconnectOptionsSize == 0)
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    ASSERT(FCB->DisconnectOptions);

    if (FCB->FilledDisconnectOptions < BufferSize) BufferSize = FCB->FilledDisconnectOptions;

    /* METHOD_NEITHER: probe the caller's output and copy under SEH */
    Status = AfdCopyToUserOutput(Irp, IrpSp, FCB->DisconnectOptions, BufferSize);

    return UnlockAndMaybeComplete(FCB, Status, Irp, NT_SUCCESS(Status) ? BufferSize : 0);
}

NTSTATUS
NTAPI
AfdSetDisconnectOptions(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                        PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PVOID DisconnectOptions = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT DisconnectOptionsSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!DisconnectOptions)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (FCB->DisconnectOptions)
    {
        ExFreePoolWithTag(FCB->DisconnectOptions, TAG_AFD_DISCONNECT_OPTIONS);
        FCB->DisconnectOptions = NULL;
        FCB->DisconnectOptionsSize = 0;
        FCB->FilledDisconnectOptions = 0;
    }

    FCB->DisconnectOptions = ExAllocatePoolWithTag(PagedPool,
                                                   DisconnectOptionsSize,
                                                   TAG_AFD_DISCONNECT_OPTIONS);

    if (!FCB->DisconnectOptions)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    RtlCopyMemory(FCB->DisconnectOptions,
                  DisconnectOptions,
                  DisconnectOptionsSize);

    FCB->DisconnectOptionsSize = DisconnectOptionsSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

NTSTATUS
NTAPI
AfdSetDisconnectOptionsSize(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                      PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PUINT DisconnectOptionsSize = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!DisconnectOptionsSize)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (BufferSize < sizeof(UINT))
    {
        AFD_DbgPrint(MIN_TRACE,("Buffer too small\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_BUFFER_TOO_SMALL, Irp, 0);
    }

    if (FCB->DisconnectOptions)
    {
        ExFreePoolWithTag(FCB->DisconnectOptions, TAG_AFD_DISCONNECT_OPTIONS);
        FCB->DisconnectOptionsSize = 0;
        FCB->FilledDisconnectOptions = 0;
    }

    FCB->DisconnectOptions = ExAllocatePoolWithTag(PagedPool,
                                                   *DisconnectOptionsSize,
                                                   TAG_AFD_DISCONNECT_OPTIONS);

    if (!FCB->DisconnectOptions) return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    FCB->DisconnectOptionsSize = *DisconnectOptionsSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

NTSTATUS NTAPI
AfdGetDisconnectData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                  PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (FCB->DisconnectDataSize == 0)
    {
        AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
    }

    ASSERT(FCB->DisconnectData);

    if (FCB->FilledDisconnectData < BufferSize)
        BufferSize = FCB->FilledDisconnectData;

    /* METHOD_NEITHER: probe the caller's output and copy under SEH */
    Status = AfdCopyToUserOutput(Irp, IrpSp, FCB->DisconnectData, BufferSize);

    return UnlockAndMaybeComplete(FCB, Status, Irp, NT_SUCCESS(Status) ? BufferSize : 0);
}

NTSTATUS
NTAPI
AfdSetDisconnectData(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                     PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PVOID DisconnectData = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT DisconnectDataSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!DisconnectData)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (FCB->DisconnectData)
    {
        ExFreePoolWithTag(FCB->DisconnectData, TAG_AFD_DISCONNECT_DATA);
        FCB->DisconnectData = NULL;
        FCB->DisconnectDataSize = 0;
        FCB->FilledDisconnectData = 0;
    }

    FCB->DisconnectData = ExAllocatePoolWithTag(PagedPool,
                                                DisconnectDataSize,
                                                TAG_AFD_DISCONNECT_DATA);

    if (!FCB->DisconnectData)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    RtlCopyMemory(FCB->DisconnectData,
                  DisconnectData,
                  DisconnectDataSize);

    FCB->DisconnectDataSize = DisconnectDataSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

NTSTATUS
NTAPI
AfdSetDisconnectDataSize(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                      PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PUINT DisconnectDataSize = LockRequest(Irp, IrpSp, FALSE, NULL);
    UINT BufferSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!DisconnectDataSize)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    if (BufferSize < sizeof(UINT))
    {
        AFD_DbgPrint(MIN_TRACE,("Buffer too small\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_BUFFER_TOO_SMALL, Irp, 0);
    }

    if (FCB->DisconnectData)
    {
        ExFreePoolWithTag(FCB->DisconnectData, TAG_AFD_DISCONNECT_DATA);
        FCB->DisconnectDataSize = 0;
        FCB->FilledDisconnectData = 0;
    }

    FCB->DisconnectData = ExAllocatePoolWithTag(PagedPool,
                                                *DisconnectDataSize,
                                                TAG_AFD_DISCONNECT_DATA);

    if (!FCB->DisconnectData)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

    FCB->DisconnectDataSize = *DisconnectDataSize;

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

static NTSTATUS NTAPI
AfdGetTdiHandles(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PULONG HandleFlags;
    PAFD_TDI_HANDLE_DATA HandleData = Irp->UserBuffer;
    NTSTATUS Status;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    BOOLEAN Wow64 = IoIs32bitProcess(Irp);

    if (Wow64 && (!IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ||
                  IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) ||
                  IrpSp->Parameters.DeviceIoControl.OutputBufferLength < 2 * sizeof(ULONG)))
    {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }
#endif

    UNREFERENCED_PARAMETER(DeviceObject);

    HandleFlags = LockRequest(Irp, IrpSp, TRUE, NULL);
    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!HandleFlags)
        return UnlockAndMaybeComplete(FCB, STATUS_NO_MEMORY, Irp, 0);

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Wow64)
    {
        PULONG Handles32 = Irp->UserBuffer;
        Status = STATUS_SUCCESS;
        _SEH2_TRY
        {
            ProbeForWrite(Handles32, 2 * sizeof(ULONG), sizeof(ULONG));
            if (*HandleFlags & AFD_ADDRESS_HANDLE)
                Handles32[0] = HandleToUlong(FCB->AddressFile.Handle);
            if (*HandleFlags & AFD_CONNECTION_HANDLE)
                Handles32[1] = HandleToUlong(FCB->Connection.Handle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
        return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
    }
#endif

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) ||
        IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*HandleData))
    {
        AFD_DbgPrint(MIN_TRACE,("Buffer too small\n"));
        return UnlockAndMaybeComplete(FCB, STATUS_BUFFER_TOO_SMALL, Irp, 0);
    }

    /* METHOD_NEITHER: HandleData is the caller's raw output pointer. Probe it
     * for the write (user-mode requests) and write under SEH, as the WoW64
     * path above does, so it cannot become a kernel-mode write. */
    Status = STATUS_SUCCESS;
    _SEH2_TRY
    {
        if (Irp->RequestorMode != KernelMode)
            ProbeForWrite(HandleData, sizeof(*HandleData), sizeof(ULONG));

        if ((*HandleFlags) & AFD_ADDRESS_HANDLE)
            HandleData->TdiAddressHandle = FCB->AddressFile.Handle;

        if ((*HandleFlags) & AFD_CONNECTION_HANDLE)
            HandleData->TdiConnectionHandle = FCB->Connection.Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        AFD_DbgPrint(MIN_TRACE,("Exception writing the TDI handles\n"));
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
}

/*
 * The AFD create packet (the EA passed when opening \Device\Afd) has two
 * wire layouts and no version field to tell them apart:
 *
 *   NT5  (AFD_CREATE_PACKET)     - what ReactOS msafd.dll sends.
 *   NT6+ (AFD_CREATE_PACKET_NT6) - what Windows mswsock sends on Vista and
 *                                  later; it inserts AddressFamily, SocketType
 *                                  and Protocol (three DWORDs) ahead of
 *                                  SizeOfTransportName, shifting the transport
 *                                  name by 12 bytes.
 *
 * EndpointFlags and GroupID keep the same offset in both, so only the
 * transport name moves. We detect the layout from content: an AFD transport
 * name is always a "\Device\..." string, so a correctly located name begins
 * with L'\\' and its declared byte count fits the bytes after the header.
 * We switch to the NT6 layout only when it is self-consistent and the NT5
 * interpretation is not, so a genuine NT5 packet is parsed exactly as before.
 */
static
BOOLEAN
AfdCreatePacketNameConsistent(ULONG SizeOfTransportName,
                              const WCHAR *TransportName,
                              ULONG BytesAvailable)
{
    /* A non-empty, WCHAR-sized name that fits and looks like a device path. */
    if( SizeOfTransportName < sizeof(WCHAR) ||
        SizeOfTransportName > BytesAvailable ||
        (SizeOfTransportName % sizeof(WCHAR)) != 0 )
    {
        return FALSE;
    }

    return (TransportName[0] == L'\\');
}

static
BOOLEAN
AfdIsCreatePacketNt6(PAFD_CREATE_PACKET ConnectInfo, ULONG EaValueLength)
{
    PAFD_CREATE_PACKET_NT6 ConnectInfo6 = (PAFD_CREATE_PACKET_NT6)ConnectInfo;
    BOOLEAN Nt5Consistent, Nt6Consistent;

    /* Too small to even contain the larger NT6 header: cannot be NT6. */
    if( EaValueLength < FIELD_OFFSET(AFD_CREATE_PACKET_NT6, TransportName) )
        return FALSE;

    Nt5Consistent =
        EaValueLength >= FIELD_OFFSET(AFD_CREATE_PACKET, TransportName) &&
        AfdCreatePacketNameConsistent(ConnectInfo->SizeOfTransportName,
                                      ConnectInfo->TransportName,
                                      EaValueLength - FIELD_OFFSET(AFD_CREATE_PACKET, TransportName));

    Nt6Consistent =
        AfdCreatePacketNameConsistent(ConnectInfo6->SizeOfTransportName,
                                      ConnectInfo6->TransportName,
                                      EaValueLength - FIELD_OFFSET(AFD_CREATE_PACKET_NT6, TransportName));

    return (Nt6Consistent && !Nt5Consistent);
}

static NTSTATUS NTAPI
AfdCreateSocket(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp) {
    PAFD_FCB FCB;
    PFILE_OBJECT FileObject;
    PAFD_DEVICE_EXTENSION DeviceExt;
    PFILE_FULL_EA_INFORMATION EaInfo;
    PAFD_CREATE_PACKET ConnectInfo = NULL;
    //ULONG EaLength;
    PWCHAR EaInfoValue = NULL;
    PWCHAR TransportName = NULL;
    ULONG SizeOfTransportName = 0;
    //UINT Disposition;
    UINT i;
    NTSTATUS Status = STATUS_SUCCESS;

    AFD_DbgPrint(MID_TRACE,("AfdCreate(DeviceObject %p Irp %p)\n",
                            DeviceObject, Irp));

    DeviceExt = DeviceObject->DeviceExtension;
    FileObject = IrpSp->FileObject;
    FileObject->Flags |= FO_NAMED_PIPE;
    //Disposition = (IrpSp->Parameters.Create.Options >> 24) & 0xff;

    Irp->IoStatus.Information = 0;

    EaInfo = Irp->AssociatedIrp.SystemBuffer;

    if( EaInfo ) {
        ULONG HeaderSize = FIELD_OFFSET(AFD_CREATE_PACKET, TransportName);

        ConnectInfo = (PAFD_CREATE_PACKET)(EaInfo->EaName + EaInfo->EaNameLength + 1);

        //EaLength = sizeof(FILE_FULL_EA_INFORMATION) + EaInfo->EaNameLength + EaInfo->EaValueLength;

        /* Select the create-packet layout the caller used (see
         * AfdIsCreatePacketNt6) and read the transport name from its offset. */
        if( AfdIsCreatePacketNt6(ConnectInfo, EaInfo->EaValueLength) )
        {
            PAFD_CREATE_PACKET_NT6 ConnectInfo6 = (PAFD_CREATE_PACKET_NT6)ConnectInfo;

            HeaderSize = FIELD_OFFSET(AFD_CREATE_PACKET_NT6, TransportName);
            SizeOfTransportName = ConnectInfo6->SizeOfTransportName;
            TransportName = ConnectInfo6->TransportName;
        }
        else
        {
            SizeOfTransportName = ConnectInfo->SizeOfTransportName;
            TransportName = ConnectInfo->TransportName;
        }
        EaInfoValue = TransportName;

        /* The EA value must span the create-packet header and the transport
         * name it declares; without this, reading SizeOfTransportName and then
         * copying that many bytes from TransportName over-reads the EA pool
         * block (the declared name length is a DWORD, up to 64KB-1). */
        if( EaInfo->EaValueLength < HeaderSize ||
            SizeOfTransportName > EaInfo->EaValueLength - HeaderSize )
        {
            AFD_DbgPrint(MIN_TRACE,("Invalid AFD_CREATE_PACKET EA length\n"));
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            IoCompleteRequest( Irp, IO_NO_INCREMENT );
            return STATUS_INVALID_PARAMETER;
        }

        AFD_DbgPrint(MID_TRACE,("EaInfo: %p, EaInfoValue: %p\n",
                                EaInfo, EaInfoValue));
    }

    AFD_DbgPrint(MID_TRACE,("About to allocate the new FCB\n"));

    FCB = ExAllocatePoolWithTag(NonPagedPool, sizeof(AFD_FCB), TAG_AFD_FCB);
    if( FCB == NULL ) {
        Irp->IoStatus.Status = STATUS_NO_MEMORY;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NO_MEMORY;
    }

    AFD_DbgPrint(MID_TRACE,("Initializing the new FCB @ %p (FileObject %p Flags %x)\n",
                            FCB, FileObject, ConnectInfo ? ConnectInfo->EndpointFlags : 0));

    RtlZeroMemory( FCB, sizeof( *FCB ) );

    FCB->Flags = ConnectInfo ? ConnectInfo->EndpointFlags : 0;
    FCB->GroupID = ConnectInfo ? ConnectInfo->GroupID : 0;
    FCB->GroupType = 0; /* FIXME */
    FCB->SharedData.State = SOCKET_STATE_CREATED;
    FCB->FileObject = FileObject;
    FCB->DeviceExt = DeviceExt;
    FCB->AddressFile.Handle = INVALID_HANDLE_VALUE;
    FCB->Connection.Handle = INVALID_HANDLE_VALUE;
    FCB->Recv.Size = AfdReceiveWindowSize;
    FCB->Send.Size = AfdSendWindowSize;

    KeInitializeMutex( &FCB->Mutex, 0 );
    KeInitializeEvent( &FCB->RelistenIdle, NotificationEvent, TRUE );
    KeInitializeEvent( &FCB->AcceptWorkIdle, NotificationEvent, TRUE );
    KeInitializeEvent( &FCB->InFlightIdle, NotificationEvent, FALSE );

    for( i = 0; i < MAX_FUNCTIONS; i++ ) {
        InitializeListHead( &FCB->PendingIrpList[i] );
    }

    InitializeListHead( &FCB->DatagramList );
    InitializeListHead( &FCB->DatagramSendList );
    InitializeListHead( &FCB->PendingConnections );

    AFD_DbgPrint(MID_TRACE,("%p: Checking command channel\n", FCB));

    if( ConnectInfo ) {
        FCB->TdiDeviceName.Length = SizeOfTransportName;
        FCB->TdiDeviceName.MaximumLength = FCB->TdiDeviceName.Length;
        FCB->TdiDeviceName.Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                                          FCB->TdiDeviceName.Length,
                                                          TAG_AFD_TRANSPORT_ADDRESS);

        if( !FCB->TdiDeviceName.Buffer ) {
            ExFreePoolWithTag(FCB, TAG_AFD_FCB);
            AFD_DbgPrint(MID_TRACE,("Could not copy target string\n"));
            Irp->IoStatus.Status = STATUS_NO_MEMORY;
            IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
            return STATUS_NO_MEMORY;
        }

        RtlCopyMemory( FCB->TdiDeviceName.Buffer,
                       TransportName,
                       FCB->TdiDeviceName.Length );

        AFD_DbgPrint(MID_TRACE,("Success: %s %wZ\n",
                                EaInfo->EaName, &FCB->TdiDeviceName));
    } else {
        AFD_DbgPrint(MID_TRACE,("Success: Control connection\n"));
    }

    FileObject->FsContext = FCB;

    /* It seems that UDP sockets are writable from inception */
    if( FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS ) {
        AFD_DbgPrint(MID_TRACE,("Packet oriented socket\n"));

        /* A datagram socket is always sendable */
        FCB->PollState |= AFD_EVENT_SEND;
        FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
        /* but FD_WRITE is only signalled once the socket is bound */
        FCB->EventSelectDisabled |= AFD_EVENT_SEND;
        PollReeval( FCB->DeviceExt, FCB->FileObject );
    }

    if( !NT_SUCCESS(Status) ) {
        if (FCB->TdiDeviceName.Buffer)
        {
            ExFreePoolWithTag(FCB->TdiDeviceName.Buffer, TAG_AFD_TRANSPORT_ADDRESS);
        }
        ExFreePoolWithTag(FCB, TAG_AFD_FCB);
        FileObject->FsContext = NULL;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );

    return Status;
}

static NTSTATUS NTAPI
AfdCleanupSocket(PDEVICE_OBJECT DeviceObject, PIRP Irp,
                 PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PLIST_ENTRY CurrentEntry, NextEntry;
    UINT Function;
    PIRP CurrentIrp;

    UNREFERENCED_PARAMETER(DeviceObject);

    if( !SocketAcquireStateLock( FCB ) ) return LostSocket(Irp);

    for (Function = 0; Function < MAX_FUNCTIONS; Function++)
    {
        /* Closing a stream socket aborts its pending receives (STATUS_CONNECTION_ABORTED,
           as Windows does); every other request, and any receive of a datagram socket, is cancelled,
           and so is a receive that shutdown(SD_BOTH) left pending */
        FCB->AbortingReceives = (Function == FUNCTION_RECV) &&
                                !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
                                !FCB->ShutdownBoth;

        CurrentEntry = FCB->PendingIrpList[Function].Flink;
        while (CurrentEntry != &FCB->PendingIrpList[Function])
        {
           NextEntry = CurrentEntry->Flink;
           CurrentIrp = CONTAINING_RECORD(CurrentEntry, IRP, Tail.Overlay.ListEntry);

           /* The cancel routine will remove the IRP from the list */
           IoCancelIrp(CurrentIrp);

           CurrentEntry = NextEntry;
        }
    }
    FCB->AbortingReceives = FALSE;

    KillSelectsForFCB( FCB->DeviceExt, FileObject, FALSE );

    return UnlockAndMaybeComplete(FCB, STATUS_SUCCESS, Irp, 0);
}

/* Called with the state lock held. A cancel does not dequeue a request the
 * transport already took and completes from a work item, and a worker or a
 * completion may issue a request after the first cancel; their completions
 * still use the FCB. Every unlock of the closed socket wakes the wait */
static VOID
WaitForInFlightRequests(PAFD_FCB FCB, PAFD_IN_FLIGHT_REQUEST *InFlightRequest)
{
    UINT i;

    while (AfdHasInFlightRequest(FCB))
    {
        for (i = 0; i < IN_FLIGHT_REQUESTS; i++)
        {
            if (InFlightRequest[i]->InFlightRequest)
                IoCancelIrp(InFlightRequest[i]->InFlightRequest);
        }
        AfdCancelDatagramSends(FCB);

        if (!AfdHasInFlightRequest(FCB))
            break;

        /* Not SocketStateUnlock, which would wake this wait at once */
        KeClearEvent(&FCB->InFlightIdle);
        KeReleaseMutex(&FCB->Mutex, FALSE);
        KeWaitForSingleObject(&FCB->InFlightIdle, Executive, KernelMode, FALSE, NULL);
        SocketAcquireStateLock(FCB);
    }
}

static NTSTATUS NTAPI
AfdCloseSocket(PDEVICE_OBJECT DeviceObject, PIRP Irp,
               PIO_STACK_LOCATION IrpSp)
{
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    UINT i;
    PAFD_IN_FLIGHT_REQUEST InFlightRequest[IN_FLIGHT_REQUESTS];
    PAFD_TDI_OBJECT_QELT Qelt;
    PLIST_ENTRY QeltEntry;


    AFD_DbgPrint(MID_TRACE,("AfdClose(DeviceObject %p Irp %p)\n",
                            DeviceObject, Irp));

    if( !SocketAcquireStateLock( FCB ) ) return STATUS_FILE_CLOSED;

    FCB->SharedData.State = SOCKET_STATE_CLOSED;

    InFlightRequest[0] = &FCB->ListenIrp;
    InFlightRequest[1] = &FCB->ReceiveIrp;
    InFlightRequest[2] = &FCB->SendIrp;
    InFlightRequest[3] = &FCB->ConnectIrp;
    InFlightRequest[4] = &FCB->DisconnectIrp;

    /* Cancel our pending requests */
    for( i = 0; i < IN_FLIGHT_REQUESTS; i++ ) {
        if( InFlightRequest[i]->InFlightRequest ) {
            AFD_DbgPrint(MID_TRACE,("Cancelling in flight irp %u (%p)\n",
                                    i, InFlightRequest[i]->InFlightRequest));
            IoCancelIrp(InFlightRequest[i]->InFlightRequest);
        }
    }

    /* The slot above names only the last datagram sent */
    AfdCancelDatagramSends(FCB);

    KillSelectsForFCB( FCB->DeviceExt, FileObject, FALSE );

    ASSERT(IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECT]));
    ASSERT(IsListEmpty(&FCB->PendingIrpList[FUNCTION_CONNECTEX]));
    ASSERT(IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]));
    ASSERT(IsListEmpty(&FCB->PendingIrpList[FUNCTION_RECV]));
    ASSERT(IsListEmpty(&FCB->PendingIrpList[FUNCTION_PREACCEPT]));
    ASSERT(IsListEmpty(&FCB->PendingIrpList[FUNCTION_DISCONNECT]));

    while (!IsListEmpty(&FCB->PendingConnections))
    {
        QeltEntry = RemoveHeadList(&FCB->PendingConnections);
        Qelt = CONTAINING_RECORD(QeltEntry, AFD_TDI_OBJECT_QELT, ListEntry);

        /* We have to close all pending connections or the listen won't get closed */
        TdiDisassociateAddressFile(Qelt->Object.Object);
        ObDereferenceObject(Qelt->Object.Object);
        ZwClose(Qelt->Object.Handle);

        FreeQueuedConnection(Qelt);
    }

    SocketStateUnlock( FCB );

    /* No relisten is queued once the socket is closed; wait for one already queued */
    if (FCB->RelistenWorkItem)
        KeWaitForSingleObject(&FCB->RelistenIdle, Executive, KernelMode, FALSE, NULL);

    /* Likewise for the AcceptEx work item */
    if (FCB->AcceptWorkItem)
        KeWaitForSingleObject(&FCB->AcceptWorkIdle, Executive, KernelMode, FALSE, NULL);

    /* Taking the lock waits for the worker */
    SocketAcquireStateLock(FCB);
    WaitForInFlightRequests(FCB, InFlightRequest);
    FreeListenConnectionInfo(FCB);
    SocketStateUnlock(FCB);

    if (FCB->RelistenWorkItem)
        IoFreeWorkItem(FCB->RelistenWorkItem);

    if (FCB->AcceptWorkItem)
        IoFreeWorkItem(FCB->AcceptWorkItem);

    if( FCB->EventSelect )
        ObDereferenceObject( FCB->EventSelect );

    if (FCB->Context)
        ExFreePoolWithTag(FCB->Context, TAG_AFD_SOCKET_CONTEXT);

    if (FCB->Recv.Window)
        ExFreePoolWithTag(FCB->Recv.Window, TAG_AFD_DATA_BUFFER);

    if (FCB->RecvRelaunchWorkItem)
        IoFreeWorkItem(FCB->RecvRelaunchWorkItem);

    if (FCB->Send.Window)
        ExFreePoolWithTag(FCB->Send.Window, TAG_AFD_DATA_BUFFER);

    if (FCB->AddressFrom)
        ExFreePoolWithTag(FCB->AddressFrom, TAG_AFD_TDI_CONNECTION_INFORMATION);

    if (FCB->ConnectCallInfo)
        ExFreePoolWithTag(FCB->ConnectCallInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);

    if (FCB->ConnectReturnInfo)
        ExFreePoolWithTag(FCB->ConnectReturnInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);

    if (FCB->ConnectData)
        ExFreePoolWithTag(FCB->ConnectData, TAG_AFD_CONNECT_DATA);

    if (FCB->DisconnectData)
        ExFreePoolWithTag(FCB->DisconnectData, TAG_AFD_DISCONNECT_DATA);

    if (FCB->ConnectOptions)
        ExFreePoolWithTag(FCB->ConnectOptions, TAG_AFD_CONNECT_OPTIONS);

    if (FCB->DisconnectOptions)
        ExFreePoolWithTag(FCB->DisconnectOptions, TAG_AFD_DISCONNECT_OPTIONS);

    if (FCB->LocalAddress)
        ExFreePoolWithTag(FCB->LocalAddress, TAG_AFD_TRANSPORT_ADDRESS);

    if (FCB->RemoteAddress)
        ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);

    if (FCB->OnConnectSendBuffer)
        ExFreePoolWithTag(FCB->OnConnectSendBuffer, TAG_AFD_SUPER_CONNECT_BUFFER);

    if( FCB->Connection.Object )
    {
        TdiDisassociateAddressFile(FCB->Connection.Object);
        ObDereferenceObject(FCB->Connection.Object);
    }

    if( FCB->AddressFile.Object )
        ObDereferenceObject(FCB->AddressFile.Object);

    if( FCB->AddressFile.Handle != INVALID_HANDLE_VALUE )
    {
        if (ZwClose(FCB->AddressFile.Handle) == STATUS_INVALID_HANDLE)
        {
            DbgPrint("INVALID ADDRESS FILE HANDLE VALUE: %p %p\n", FCB->AddressFile.Handle, FCB->AddressFile.Object);
        }
    }

    if( FCB->Connection.Handle != INVALID_HANDLE_VALUE )
    {
        if (ZwClose(FCB->Connection.Handle) == STATUS_INVALID_HANDLE)
        {
            DbgPrint("INVALID CONNECTION HANDLE VALUE: %p %p\n", FCB->Connection.Handle, FCB->Connection.Object);
        }
    }

    if (FCB->TdiDeviceName.Buffer)
    {
        ExFreePoolWithTag(FCB->TdiDeviceName.Buffer, TAG_AFD_TRANSPORT_ADDRESS);
    }

    ExFreePoolWithTag(FCB, TAG_AFD_FCB);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    AFD_DbgPrint(MID_TRACE, ("Returning success.\n"));

    return STATUS_SUCCESS;
}

static IO_COMPLETION_ROUTINE DisconnectComplete;
static
NTSTATUS
NTAPI
DisconnectComplete(PDEVICE_OBJECT DeviceObject,
                   PIRP Irp,
                   PVOID Context)
{
    PAFD_FCB FCB = Context;
    PIRP CurrentIrp;
    PLIST_ENTRY CurrentEntry;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB))
        return STATUS_FILE_CLOSED;

    ASSERT(FCB->DisconnectIrp.InFlightRequest == Irp);
    FCB->DisconnectIrp.InFlightRequest = NULL;

    ASSERT(FCB->DisconnectPending);
    ASSERT((IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) && !FCB->SendIrp.InFlightRequest) ||
           (FCB->DisconnectFlags & TDI_DISCONNECT_ABORT));

    if (NT_SUCCESS(Irp->IoStatus.Status) && (FCB->DisconnectFlags & TDI_DISCONNECT_RELEASE))
    {
        /* The return info reports OptionsLength = sizeof(ULONG) with no
           Options buffer (TdiBuildConnectionInfo) and the transport does not
           fill it in: copy only what has a source */
        FCB->FilledDisconnectData = 0;
        if (FCB->ConnectReturnInfo && FCB->ConnectReturnInfo->UserData)
            FCB->FilledDisconnectData = MIN(FCB->DisconnectDataSize, FCB->ConnectReturnInfo->UserDataLength);
        if (FCB->FilledDisconnectData)
        {
            RtlCopyMemory(FCB->DisconnectData,
                          FCB->ConnectReturnInfo->UserData,
                          FCB->FilledDisconnectData);
        }

        FCB->FilledDisconnectOptions = 0;
        if (FCB->ConnectReturnInfo && FCB->ConnectReturnInfo->Options)
            FCB->FilledDisconnectOptions = MIN(FCB->DisconnectOptionsSize, FCB->ConnectReturnInfo->OptionsLength);
        if (FCB->FilledDisconnectOptions)
        {
            RtlCopyMemory(FCB->DisconnectOptions,
                          FCB->ConnectReturnInfo->Options,
                          FCB->FilledDisconnectOptions);
        }
    }

    FCB->DisconnectPending = FALSE;

    while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_DISCONNECT]))
    {
        CurrentEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_DISCONNECT]);
        CurrentIrp = CONTAINING_RECORD(CurrentEntry, IRP, Tail.Overlay.ListEntry);
        CurrentIrp->IoStatus.Status = FCB->ConnectionAborted ? STATUS_SUCCESS : Irp->IoStatus.Status;
        CurrentIrp->IoStatus.Information = 0;
        UnlockRequest(CurrentIrp, IoGetCurrentIrpStackLocation(CurrentIrp));
        AfdClearCancelRoutine(CurrentIrp);
        IoCompleteRequest(CurrentIrp, IO_NETWORK_INCREMENT );
    }

    if (FCB->ConnectionAborted)
    {
        /* The state was set when the connection was aborted (AfdAbortConnection) */
    }
    else if (!(FCB->DisconnectFlags & TDI_DISCONNECT_RELEASE))
    {
        /* Signal complete connection closure immediately */
        FCB->PollState |= AFD_EVENT_ABORT;
        FCB->PollStatus[FD_CLOSE_BIT] = Irp->IoStatus.Status;
        FCB->LastReceiveStatus = STATUS_FILE_CLOSED;
        PollReeval(FCB->DeviceExt, FCB->FileObject);
    }

    SocketStateUnlock(FCB);

    return Irp->IoStatus.Status;
}

static
NTSTATUS
DoDisconnect(PAFD_FCB FCB)
{
    NTSTATUS Status;

    ASSERT(FCB->DisconnectPending);
    ASSERT((IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) && !FCB->SendIrp.InFlightRequest) ||
           (FCB->DisconnectFlags & TDI_DISCONNECT_ABORT));

    if (FCB->DisconnectIrp.InFlightRequest)
    {
        return STATUS_PENDING;
    }

    FCB->ConnectCallInfo->UserData = FCB->DisconnectData;
    FCB->ConnectCallInfo->UserDataLength = FCB->DisconnectDataSize;
    FCB->ConnectCallInfo->Options = FCB->DisconnectOptions;
    FCB->ConnectCallInfo->OptionsLength = FCB->DisconnectOptionsSize;

    Status = TdiDisconnect(&FCB->DisconnectIrp.InFlightRequest,
                           FCB->Connection.Object,
                           &FCB->DisconnectTimeout,
                           FCB->DisconnectFlags,
                           DisconnectComplete,
                           FCB,
                           FCB->ConnectCallInfo,
                           FCB->ConnectReturnInfo);
    if (Status != STATUS_PENDING)
    {
        FCB->DisconnectPending = FALSE;
    }

    return Status;
}

VOID
RetryDisconnectCompletion(PAFD_FCB FCB)
{
    ASSERT(FCB->RemoteAddress);

    if (IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) && !FCB->SendIrp.InFlightRequest && FCB->DisconnectPending)
    {
        /* Sends are done; fire off a TDI_DISCONNECT request */
        DoDisconnect(FCB);
    }
}

/* The state of a connection that shutdown(SD_RECEIVE) reset because data was unread or arrived with no
 * receive pending: Windows fails every later operation of the socket with WSAECONNABORTED and reports
 * the socket readable and writable (the operations fail at once) and FD_CLOSE with the same error.
 * The state lock is held. */
static VOID
AfdMarkConnectionAborted(PAFD_FCB FCB, BOOLEAN Unread)
{
    FCB->ConnectionAborted = TRUE;
    FCB->ReceiveShutdown = FALSE;
    FCB->ShutdownBoth = FALSE;
    FCB->TdiReceiveClosed = TRUE;
    FCB->SendClosed = TRUE;
    FCB->Recv.Content = 0;
    FCB->Recv.BytesUsed = 0;
    FCB->LastReceiveStatus = STATUS_CONNECTION_ABORTED;
    FCB->PollState &= ~AFD_EVENT_RECEIVE;
    FCB->PollState |= AFD_EVENT_ABORT | AFD_EVENT_SEND;
    /* data that was queued still signals FD_READ, as on Windows (data that arrives later does not) */
    if (Unread)
    {
        FCB->PollState |= AFD_EVENT_RECEIVE;
        FCB->PollStatus[FD_READ_BIT] = STATUS_SUCCESS;
    }
    FCB->PollStatus[FD_CLOSE_BIT] = STATUS_CONNECTION_ABORTED;
    FCB->PollStatus[FD_WRITE_BIT] = STATUS_SUCCESS;
    PollReeval(FCB->DeviceExt, FCB->FileObject);
}

/* Aborts the connection of a stream socket whose receive direction was shut down by shutdown(SD_RECEIVE)
 * when data arrives: an RST goes to the peer and the socket fails as AfdMarkConnectionAborted says.
 * The state lock is held. */
VOID
AfdAbortConnection(PAFD_FCB FCB)
{
    if (FCB->ConnectionAborted ||
        (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) ||
        FCB->SharedData.State != SOCKET_STATE_CONNECTED ||
        !FCB->ConnectCallInfo ||
        !FCB->Connection.Object)
        return;

    AfdMarkConnectionAborted(FCB, FALSE);

    /* A graceful disconnect that the transport is working on ends by itself */
    if (FCB->DisconnectIrp.InFlightRequest)
        return;

    FCB->DisconnectFlags = TDI_DISCONNECT_ABORT;
    FCB->DisconnectTimeout.QuadPart = -1000000LL;
    FCB->DisconnectPending = TRUE;
    DoDisconnect(FCB);
}

static NTSTATUS NTAPI
AfdDisconnect(PDEVICE_OBJECT DeviceObject, PIRP Irp,
              PIO_STACK_LOCATION IrpSp) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    PAFD_DISCONNECT_INFO DisReq;
    NTSTATUS Status = STATUS_SUCCESS;
    USHORT Flags;
    PLIST_ENTRY CurrentEntry;
    PIRP CurrentIrp;
    BOOLEAN AbortConnection = FALSE;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);

    if (!AfdRequestLengthValid(Irp, IrpSp, sizeof(AFD_DISCONNECT_INFO)))
        return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER,
                                       Irp, 0 );

    if (!(DisReq = LockRequest(Irp, IrpSp, FALSE, NULL)))
        return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY,
                                       Irp, 0 );

    /* The connection is reset already (see AfdAbortConnection): a shutdown succeeds and does nothing */
    if (FCB->ConnectionAborted)
        return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );

    /* Send direction only */
    if ((DisReq->DisconnectType & AFD_DISCONNECT_SEND) &&
        !(DisReq->DisconnectType & AFD_DISCONNECT_RECV))
    {
        /* Perform a controlled disconnect */
        Flags = TDI_DISCONNECT_RELEASE;
    }
    /* Receive direction or both */
    else
    {
        if (!(DisReq->DisconnectType & AFD_DISCONNECT_ABORT) &&
            !IsListEmpty(&FCB->PendingIrpList[FUNCTION_RECV]))
        {
            /* Receives are pending: Windows leaves them pending (they complete with data that
               arrives later, with the end or the reset of the connection, with a cancel or at
               the close), and the shutdown takes effect when none is left */
            FCB->ReceiveShutdown = TRUE;
            FCB->ShutdownBoth = (DisReq->DisconnectType & AFD_DISCONNECT_SEND) != 0;
        }
        else
        {
            /* Unread data at shutdown(SD_RECEIVE) of a live stream connection resets it, as on Windows */
            AbortConnection = !(DisReq->DisconnectType & AFD_DISCONNECT_ABORT) &&
                              !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS) &&
                              FCB->SharedData.State == SOCKET_STATE_CONNECTED &&
                              FCB->ConnectCallInfo &&
                              !FCB->TdiReceiveClosed &&
                              FCB->Recv.Content != FCB->Recv.BytesUsed;

            /* Mark that we can't issue another receive request */
            FCB->TdiReceiveClosed = TRUE;
            if (!(DisReq->DisconnectType & AFD_DISCONNECT_ABORT))
                FCB->LocalReceiveShutdown = TRUE;

            /* An abortive close of a stream socket aborts the receives that are pending (the
               cancel of the transport's receive below would complete them as cancelled) */
            if ((DisReq->DisconnectType & AFD_DISCONNECT_ABORT) &&
                !(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS))
                AfdAbortPendingReceives(FCB);

            /* Try to cancel a pending TDI receive IRP if there was one in progress. Not the one of a
               stream socket that is not aborted: its cancel breaks the sends of the socket, and what
               it receives is discarded as the receive of a closed socket */
            if (FCB->ReceiveIrp.InFlightRequest &&
                ((DisReq->DisconnectType & AFD_DISCONNECT_ABORT) ||
                 (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)))
                IoCancelIrp(FCB->ReceiveIrp.InFlightRequest);

            /* Discard any pending data */
            FCB->Recv.Content = 0;
            FCB->Recv.BytesUsed = 0;

            /* Set a successful receive status to indicate a shutdown on overread */
            FCB->LastReceiveStatus = STATUS_SUCCESS;

            /* Clear the receive event */
            FCB->PollState &= ~AFD_EVENT_RECEIVE;

            if (AbortConnection)
                AfdMarkConnectionAborted(FCB, TRUE);
        }

        /* Receive direction only */
        if ((DisReq->DisconnectType & AFD_DISCONNECT_RECV) &&
            !(DisReq->DisconnectType & (AFD_DISCONNECT_SEND | AFD_DISCONNECT_ABORT)) &&
            !AbortConnection)
        {
            /* No need to tell the transport driver for receive direction only */
            return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );
        }
        else if (AbortConnection ||
                 (DisReq->DisconnectType & AFD_DISCONNECT_ABORT) ||
                 (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS))
        {
            /* Perform an abortive disconnect */
            Flags = TDI_DISCONNECT_ABORT;
        }
        else
        {
            /* Both directions: the send direction still closes gracefully */
            Flags = TDI_DISCONNECT_RELEASE;
        }
    }

    if (!(FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS))
    {
        if (!FCB->ConnectCallInfo)
        {
            AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
            return UnlockAndMaybeComplete( FCB, STATUS_INVALID_PARAMETER,
                                           Irp, 0 );
        }

        if (FCB->DisconnectPending)
        {
            if (FCB->DisconnectIrp.InFlightRequest)
            {
                IoCancelIrp(FCB->DisconnectIrp.InFlightRequest);
                ASSERT(!FCB->DisconnectIrp.InFlightRequest);
            }
            else
            {
                while (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_DISCONNECT]))
                {
                    CurrentEntry = RemoveHeadList(&FCB->PendingIrpList[FUNCTION_DISCONNECT]);
                    CurrentIrp = CONTAINING_RECORD(CurrentEntry, IRP, Tail.Overlay.ListEntry);
                    CurrentIrp->IoStatus.Status = STATUS_CANCELLED;
                    CurrentIrp->IoStatus.Information = 0;
                    UnlockRequest(CurrentIrp, IoGetCurrentIrpStackLocation(CurrentIrp));
                    AfdClearCancelRoutine(CurrentIrp);
                    IoCompleteRequest(CurrentIrp, IO_NETWORK_INCREMENT );
                }
            }
        }

        FCB->DisconnectFlags = Flags;
        FCB->DisconnectTimeout = DisReq->Timeout;
        FCB->DisconnectPending = TRUE;
        FCB->SendClosed = TRUE;
        FCB->PollState &= ~AFD_EVENT_SEND;
        /* a reset connection stays writable: the send fails at once */
        if (FCB->ConnectionAborted)
            FCB->PollState |= AFD_EVENT_SEND;

        /* A graceful shutdown while data is still waiting to be sent (the peer's window is closed, say) returns
         * at once, as on Windows: the end of the stream goes out after the data (RetryDisconnectCompletion,
         * when the transport has taken it all) and the request is not kept for it */
        if (!(FCB->DisconnectFlags & TDI_DISCONNECT_ABORT) &&
            (!IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) || FCB->SendIrp.InFlightRequest))
        {
            Status = STATUS_SUCCESS;
        }
        else
            Status = QueueUserModeIrp(FCB, Irp, FUNCTION_DISCONNECT);

        if (Status == STATUS_PENDING)
        {
            if ((IsListEmpty(&FCB->PendingIrpList[FUNCTION_SEND]) && !FCB->SendIrp.InFlightRequest) ||
                (FCB->DisconnectFlags & TDI_DISCONNECT_ABORT))
            {
                /* Go ahead and execute the disconnect because we're ready for it */
                Status = DoDisconnect(FCB);
            }

            if (Status != STATUS_PENDING)
                RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        }

        if (Status == STATUS_PENDING)
        {
            SocketStateUnlock(FCB);

            return Status;
        }
    }
    else
    {
        if (!(Flags & TDI_DISCONNECT_RELEASE))
        {
            if (!FCB->RemoteAddress)
            {
                AFD_DbgPrint(MIN_TRACE,("Invalid parameter\n"));
                return UnlockAndMaybeComplete(FCB, STATUS_INVALID_PARAMETER, Irp, 0);
            }

            ExFreePoolWithTag(FCB->RemoteAddress, TAG_AFD_TRANSPORT_ADDRESS);

            FCB->RemoteAddress = NULL;
        }

        FCB->PollState &= ~AFD_EVENT_SEND;
        FCB->SendClosed = TRUE;
    }

    return UnlockAndMaybeComplete( FCB, Status, Irp, 0 );
}

NTSTATUS
AfdQueryFsDeviceInfo(PDEVICE_OBJECT DeviceObject, PFILE_FS_DEVICE_INFORMATION Buffer, PULONG Length)
{
    if (*Length >= sizeof(FILE_FS_DEVICE_INFORMATION))
    {
        Buffer->Characteristics = 0;
        Buffer->DeviceType = FILE_DEVICE_NAMED_PIPE;

        *Length -= sizeof(FILE_FS_DEVICE_INFORMATION);

        return STATUS_SUCCESS;
    }
    else
    {
        ASSERT(*Length >= sizeof(FILE_FS_DEVICE_INFORMATION));
        return STATUS_INFO_LENGTH_MISMATCH;
    }
}

static NTSTATUS NTAPI
AfdQueryVolumeInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    FS_INFORMATION_CLASS InfoClass;
    PVOID Buffer;
    ULONG Length;
    NTSTATUS Status = STATUS_INVALID_INFO_CLASS;

    Buffer = Irp->AssociatedIrp.SystemBuffer;
    Length = IrpSp->Parameters.QueryVolume.Length;
    InfoClass = IrpSp->Parameters.QueryVolume.FsInformationClass;

    switch (InfoClass)
    {
    case FileFsDeviceInformation:
        Status = AfdQueryFsDeviceInfo(DeviceObject, Buffer, &Length);
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = IrpSp->Parameters.QueryVolume.Length - Length;
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    return Status;
}

static DRIVER_DISPATCH AfdDispatch;
static NTSTATUS NTAPI
AfdDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
#if DBG
    PFILE_OBJECT FileObject = IrpSp->FileObject;
#endif

    AFD_DbgPrint(MID_TRACE,("AfdDispatch: %u\n", IrpSp->MajorFunction));
    if( IrpSp->MajorFunction != IRP_MJ_CREATE) {
        AFD_DbgPrint(MID_TRACE,("FO %p, IrpSp->FO %p\n",
                                FileObject, IrpSp->FileObject));
        ASSERT(FileObject == IrpSp->FileObject);
    }

    Irp->IoStatus.Information = 0;

    switch(IrpSp->MajorFunction)
    {
        /* opening and closing handles to the device */
    case IRP_MJ_CREATE:
        /* Mostly borrowed from the named pipe file system */
        return AfdCreateSocket(DeviceObject, Irp, IrpSp);

    case IRP_MJ_CLOSE:
        /* Ditto the borrowing */
        return AfdCloseSocket(DeviceObject, Irp, IrpSp);

    case IRP_MJ_CLEANUP:
        return AfdCleanupSocket(DeviceObject, Irp, IrpSp);

    /* write data */
    case IRP_MJ_WRITE:
        return AfdConnectedSocketWriteData( DeviceObject, Irp, IrpSp, TRUE );

    /* read data */
    case IRP_MJ_READ:
        return AfdConnectedSocketReadData( DeviceObject, Irp, IrpSp, TRUE );

    /* query volume info */
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        return AfdQueryVolumeInformation(DeviceObject, Irp, IrpSp);

    case IRP_MJ_DEVICE_CONTROL:
    {
        switch( IrpSp->Parameters.DeviceIoControl.IoControlCode ) {
        case IOCTL_AFD_BIND:
            return AfdBindSocket( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_CONNECT:
            return AfdStreamSocketConnect( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_SUPER_CONNECT:
            return AfdStreamSocketSuperConnect(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_START_LISTEN:
            return AfdListenSocket( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_RECV:
            return AfdConnectedSocketReadData( DeviceObject, Irp, IrpSp,
                                               FALSE );

        case IOCTL_AFD_SELECT:
            return AfdSelect( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_EVENT_SELECT:
            return AfdEventSelect( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_ENUM_NETWORK_EVENTS:
            return AfdEnumEvents( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_RECV_DATAGRAM:
            return AfdPacketSocketReadData( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_SEND:
            return AfdConnectedSocketWriteData( DeviceObject, Irp, IrpSp,
                                                FALSE );

        case IOCTL_AFD_SEND_DATAGRAM:
            return AfdPacketSocketWriteData( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_GET_INFO:
            return AfdGetInfo( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_SET_INFO:
            return AfdSetInfo( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_GET_CONTEXT_SIZE:
            return AfdGetContextSize( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_GET_CONTEXT:
            return AfdGetContext( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_SET_CONTEXT:
            return AfdSetContext( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_WAIT_FOR_LISTEN:
            return AfdWaitForListen( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_ACCEPT:
            return AfdAccept( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_SUPER_ACCEPT:
            return AfdSuperAccept( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_DISCONNECT:
            return AfdDisconnect( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_GET_SOCK_NAME:
            return AfdGetSockName( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_GET_PEER_NAME:
            return AfdGetPeerName( DeviceObject, Irp, IrpSp );

        case IOCTL_AFD_GET_CONNECT_DATA:
            return AfdGetConnectData(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_CONNECT_DATA:
            return AfdSetConnectData(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_DISCONNECT_DATA:
            return AfdSetDisconnectData(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_GET_DISCONNECT_DATA:
            return AfdGetDisconnectData(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_CONNECT_DATA_SIZE:
            return AfdSetConnectDataSize(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_DISCONNECT_DATA_SIZE:
            return AfdSetDisconnectDataSize(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_CONNECT_OPTIONS:
            return AfdSetConnectOptions(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_DISCONNECT_OPTIONS:
            return AfdSetDisconnectOptions(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_GET_CONNECT_OPTIONS:
            return AfdGetConnectOptions(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_GET_DISCONNECT_OPTIONS:
            return AfdGetDisconnectOptions(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_CONNECT_OPTIONS_SIZE:
            return AfdSetConnectOptionsSize(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_SET_DISCONNECT_OPTIONS_SIZE:
            return AfdSetDisconnectOptionsSize(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_GET_TDI_HANDLES:
            return AfdGetTdiHandles(DeviceObject, Irp, IrpSp);

        case IOCTL_AFD_DEFER_ACCEPT:
            DbgPrint("IOCTL_AFD_DEFER_ACCEPT is UNIMPLEMENTED!\n");
            break;

        case IOCTL_AFD_GET_PENDING_CONNECT_DATA:
            DbgPrint("IOCTL_AFD_GET_PENDING_CONNECT_DATA is UNIMPLEMENTED!\n");
            break;

        case IOCTL_AFD_VALIDATE_GROUP:
            DbgPrint("IOCTL_AFD_VALIDATE_GROUP is UNIMPLEMENTED!\n");
            break;

        default:
            Status = STATUS_NOT_SUPPORTED;
            DbgPrint("Unknown IOCTL (0x%x)\n",
                     IrpSp->Parameters.DeviceIoControl.IoControlCode);
            break;
        }
        break;
    }

/* unsupported operations */
    default:
    {
        Status = STATUS_NOT_IMPLEMENTED;
        AFD_DbgPrint(MIN_TRACE,
                     ("Irp: Unknown Major code was %x\n",
                      IrpSp->MajorFunction));
        break;
    }
    }

    AFD_DbgPrint(MID_TRACE, ("Returning %x\n", Status));
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

BOOLEAN CheckUnlockExtraBuffers(PAFD_FCB FCB, PIO_STACK_LOCATION IrpSp)
{
    if (FCB->Flags & AFD_ENDPOINT_CONNECTIONLESS)
    {
        if (IrpSp->MajorFunction == IRP_MJ_READ || IrpSp->MajorFunction == IRP_MJ_WRITE)
        {
            /* read()/write() call - no extra buffers */
            return FALSE;
        }
        else if (IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
        {
            if (IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_RECV_DATAGRAM)
            {
                /* recvfrom() call - extra buffers */
                return TRUE;
            }
            else if (IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_RECV)
            {
                /* recv() call - no extra buffers */
                return FALSE;
            }
            else if (IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_SEND ||
                     IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_SEND_DATAGRAM)
            {
                /* send()/sendto() call - no extra buffers */
                return FALSE;
            }
            else
            {
                /* Unknown IOCTL */
                ASSERT(FALSE);
                return FALSE;
            }
        }
        else
        {
            /* Unknown IRP_MJ code */
            ASSERT(FALSE);
            return FALSE;
        }
    }
    else
    {
        /* Connection-oriented never has extra buffers */
        return FALSE;
    }
}

VOID
CleanupPendingIrp(PAFD_FCB FCB, PIRP Irp, PIO_STACK_LOCATION IrpSp, PAFD_ACTIVE_POLL Poll)
{
    PAFD_RECV_INFO RecvReq;
    PAFD_SEND_INFO SendReq;
    PAFD_POLL_INFO PollReq;

    if (IrpSp->MajorFunction == IRP_MJ_READ)
    {
        RecvReq = GetLockedData(Irp, IrpSp);
        UnlockBuffers(RecvReq->BufferArray, RecvReq->BufferCount, CheckUnlockExtraBuffers(FCB, IrpSp));
    }
    else if (IrpSp->MajorFunction == IRP_MJ_WRITE)
    {
        SendReq = GetLockedData(Irp, IrpSp);
        UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, CheckUnlockExtraBuffers(FCB, IrpSp));
    }
    else
    {
        ASSERT(IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);

        /* AFD_RECV_INFO_UDP starts like AFD_RECV_INFO */
        if (IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_RECV ||
            IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_RECV_DATAGRAM)
        {
            RecvReq = GetLockedData(Irp, IrpSp);
            UnlockBuffers(RecvReq->BufferArray, RecvReq->BufferCount, CheckUnlockExtraBuffers(FCB, IrpSp));
        }
        else if (IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_SEND ||
                 IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_SEND_DATAGRAM)
        {
            /* AFD_SEND_INFO_UDP starts like AFD_SEND_INFO */
            SendReq = GetLockedData(Irp, IrpSp);
            UnlockBuffers(SendReq->BufferArray, SendReq->BufferCount, CheckUnlockExtraBuffers(FCB, IrpSp));
        }
        else if (IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_AFD_SELECT)
        {
            ASSERT(Poll);

            PollReq = Irp->AssociatedIrp.SystemBuffer;
            ZeroEvents(PollReq->Handles, PollReq->HandleCount);
            SignalSocket(Poll, NULL, PollReq, STATUS_CANCELLED);
        }
    }
}

/* Irp is the only request on the connect and ConnectEx queues */
static
BOOLEAN
AfdIsOnlyConnectRequest(PAFD_FCB FCB, PIRP Irp)
{
    PLIST_ENTRY Connect = &FCB->PendingIrpList[FUNCTION_CONNECT];
    PLIST_ENTRY ConnectEx = &FCB->PendingIrpList[FUNCTION_CONNECTEX];
    PLIST_ENTRY Entry = &Irp->Tail.Overlay.ListEntry;

    if (Connect->Flink == Entry && Entry->Flink == Connect && IsListEmpty(ConnectEx))
        return TRUE;
    if (ConnectEx->Flink == Entry && Entry->Flink == ConnectEx && IsListEmpty(Connect))
        return TRUE;
    return FALSE;
}

static
BOOLEAN
AfdIsIrpQueued(PAFD_FCB FCB, PIRP Irp)
{
    PLIST_ENTRY CurrentEntry;
    ULONG Function;

    for (Function = 0; Function < MAX_FUNCTIONS; Function++)
    {
        for (CurrentEntry = FCB->PendingIrpList[Function].Flink;
             CurrentEntry != &FCB->PendingIrpList[Function];
             CurrentEntry = CurrentEntry->Flink)
        {
            if (CONTAINING_RECORD(CurrentEntry, IRP, Tail.Overlay.ListEntry) == Irp)
                return TRUE;
        }
    }

    return FALSE;
}

VOID
NTAPI
AfdCancelHandler(PDEVICE_OBJECT DeviceObject,
                 PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    /* Completion does not take the cancel lock and moves the current stack location,
       so the socket comes from the IRP itself */
    PFILE_OBJECT FileObject = Irp->Tail.Overlay.OriginalFileObject;
    PAFD_FCB FCB = FileObject->FsContext;
    ULONG Function, IoctlCode;
    PIRP CurrentIrp;
    PLIST_ENTRY CurrentEntry;
    PAFD_DEVICE_EXTENSION DeviceExt = DeviceObject->DeviceExtension;
    KIRQL OldIrql;
    PAFD_ACTIVE_POLL Poll;

    /* The IRP cannot complete while the cancel lock is held; keep the socket past that */
    ObReferenceObject(FileObject);
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    if (!SocketAcquireStateLock(FCB))
    {
        ObDereferenceObject(FileObject);
        return;
    }

    KeAcquireSpinLock(&DeviceExt->Lock, &OldIrql);
    for (CurrentEntry = DeviceExt->Polls.Flink;
         CurrentEntry != &DeviceExt->Polls;
         CurrentEntry = CurrentEntry->Flink)
    {
        Poll = CONTAINING_RECORD(CurrentEntry, AFD_ACTIVE_POLL, ListEntry);
        /* A completed IRP may be reused for a new request at the same address */
        if (Poll->Irp == Irp && Irp->Cancel)
        {
            CleanupPendingIrp(FCB, Irp, IoGetCurrentIrpStackLocation(Irp), Poll);
            KeReleaseSpinLock(&DeviceExt->Lock, OldIrql);
            SocketStateUnlock(FCB);
            ObDereferenceObject(FileObject);
            return;
        }
    }
    KeReleaseSpinLock(&DeviceExt->Lock, OldIrql);

    /* Only a cancelled IRP still queued under the socket lock is ours */
    if (!AfdIsIrpQueued(FCB, Irp) || !Irp->Cancel)
    {
        SocketStateUnlock(FCB);
        ObDereferenceObject(FileObject);
        return;
    }
    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
            IoctlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
            break;

        case IRP_MJ_READ:
            IoctlCode = IOCTL_AFD_RECV;
            break;

        case IRP_MJ_WRITE:
            IoctlCode = IOCTL_AFD_SEND;
            break;

        default:
            ASSERT(FALSE);
            SocketStateUnlock(FCB);
            ObDereferenceObject(FileObject);
            return;
    }

    switch (IoctlCode)
    {
        case IOCTL_AFD_RECV:
        case IOCTL_AFD_RECV_DATAGRAM:
            Function = FUNCTION_RECV;
            break;

        case IOCTL_AFD_SEND:
        case IOCTL_AFD_SEND_DATAGRAM:
            Function = FUNCTION_SEND;
            break;

        case IOCTL_AFD_CONNECT:
            Function = FUNCTION_CONNECT;
            break;

        case IOCTL_AFD_SUPER_CONNECT:
            Function = FUNCTION_CONNECTEX;
            break;

        case IOCTL_AFD_WAIT_FOR_LISTEN:
            Function = FUNCTION_PREACCEPT;
            break;

        case IOCTL_AFD_SUPER_ACCEPT:
            Function = FUNCTION_PREACCEPT;
            break;

        case IOCTL_AFD_DISCONNECT:
            Function = FUNCTION_DISCONNECT;
            break;

        default:
            ASSERT(FALSE);
            UnlockAndMaybeComplete(FCB, STATUS_CANCELLED, Irp, 0);
            ObDereferenceObject(FileObject);
            return;
    }

    CurrentEntry = FCB->PendingIrpList[Function].Flink;
    while (CurrentEntry != &FCB->PendingIrpList[Function])
    {
        CurrentIrp = CONTAINING_RECORD(CurrentEntry, IRP, Tail.Overlay.ListEntry);

        if (CurrentIrp == Irp)
        {
            /* The last connect request of a socket whose transport connect runs: stop the
               transport connect and leave this request queued. Its completion completes the
               request with the transport's result once the socket is bound or connected
               again, so the caller never sees a cancel while the socket still connects */
            if ((Function == FUNCTION_CONNECT || Function == FUNCTION_CONNECTEX) &&
                FCB->SharedData.State == SOCKET_STATE_CONNECTING &&
                FCB->ConnectIrp.InFlightRequest &&
                AfdIsOnlyConnectRequest(FCB, Irp))
            {
                IoCancelIrp(FCB->ConnectIrp.InFlightRequest);
                SocketStateUnlock(FCB);
                ObDereferenceObject(FileObject);
                return;
            }

            if (Function == FUNCTION_SEND)
                AfdOrphanDatagramSend(FCB, Irp);
            RemoveEntryList(CurrentEntry);
            CleanupPendingIrp(FCB, Irp, IrpSp, NULL);
            /* The last receive that shutdown(SD_RECEIVE) kept pending */
            if (Function == FUNCTION_RECV)
                AfdCompleteReceiveShutdown(FCB);
            if (Function == FUNCTION_PREACCEPT)
            {
                /* Unlock the acceptor socket so that it can be reused */
                PFILE_OBJECT NewFileObject = (PFILE_OBJECT)Irp->Tail.Overlay.DriverContext[2];
                if (NewFileObject)
                {
                    PAFD_FCB FCB2 = NewFileObject->FsContext;
                    FCB2->SharedData.State = SOCKET_STATE_CREATED;

                    /* With the listener locked, never close the accept socket here */
                    ObDereferenceObjectDeferDelete(NewFileObject);
                    Irp->Tail.Overlay.DriverContext[2] = NULL;
                }

                if (Irp->Tail.Overlay.DriverContext[3])
                {
                    MmUnlockPages((PMDL)Irp->Tail.Overlay.DriverContext[3]);
                    IoFreeMdl((PMDL)Irp->Tail.Overlay.DriverContext[3]);
                    Irp->Tail.Overlay.DriverContext[3] = NULL;
                }
            }
            /* The cancel comes from the cleanup of a stream socket: the connection is gone */
            UnlockAndMaybeComplete(FCB,
                                   (Function == FUNCTION_RECV && FCB->AbortingReceives) ?
                                       STATUS_CONNECTION_ABORTED : STATUS_CANCELLED,
                                   Irp, 0);
            ObDereferenceObject(FileObject);
            return;
        }
        else
        {
            CurrentEntry = CurrentEntry->Flink;
        }
    }

    SocketStateUnlock(FCB);
    ObDereferenceObject(FileObject);

    DbgPrint("WARNING!!! IRP cancellation race could lead to a process hang! (Function: %u)\n", Function);
}

static DRIVER_UNLOAD AfdUnload;
static VOID NTAPI
AfdUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING wstrDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Afd");
    PAFD_DEVICE_EXTENSION DeviceExt;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);
    /* register driver routines */
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AfdDispatch;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AfdDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = AfdDispatch;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = AfdDispatch;
    DriverObject->MajorFunction[IRP_MJ_READ] = AfdDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AfdDispatch;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = AfdDispatch;
    DriverObject->DriverUnload = AfdUnload;

    Status = IoCreateDevice(DriverObject,
                            sizeof(AFD_DEVICE_EXTENSION),
                            &wstrDeviceName,
                            FILE_DEVICE_NAMED_PIPE,
                            0,
                            FALSE,
                            &DeviceObject);

    /* failure */
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    DeviceExt = DeviceObject->DeviceExtension;
    KeInitializeSpinLock( &DeviceExt->Lock );
    InitializeListHead( &DeviceExt->Polls );

    AFD_DbgPrint(MID_TRACE,("Device created: object %p ext %p\n",
                            DeviceObject, DeviceExt));

    return Status;
}

/* EOF */
