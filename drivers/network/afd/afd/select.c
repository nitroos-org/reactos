/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/net/afd/afd/select.c
 * PURPOSE:          Ancillary functions driver
 * PROGRAMMER:       Art Yerkes (ayerkes@speakeasy.net)
 * UPDATE HISTORY:
 * 20040708 Created
 */

#include "afd.h"

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
typedef struct
{
    ULONG Handle, Events;
    NTSTATUS Status;
} AFD_HANDLE32;

typedef struct
{
    ULONG Event, PollEvents;
    NTSTATUS EventStatus[AFD_MAX_EVENTS];
} AFD_ENUM_NETWORK_EVENTS_INFO32;

typedef struct
{
    LARGE_INTEGER Timeout;
    ULONG HandleCount, Exclusive;
    AFD_HANDLE32 Handles[1];
} AFD_POLL_INFO32;

C_ASSERT(FIELD_OFFSET(AFD_POLL_INFO32, Handles) == 16);
C_ASSERT(sizeof(AFD_HANDLE32) == 12);

/* METHOD_BUFFERED keeps the native poll alive through timeout/cancellation.
 * Completion packs its result before the I/O manager copies it to the guest. */
static NTSTATUS
AfdCapturePoll32(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    AFD_POLL_INFO32 *From = Irp->AssociatedIrp.SystemBuffer;
    PAFD_POLL_INFO To;
    ULONG Count, i, Length;

    if (!From || IrpSp->Parameters.DeviceIoControl.InputBufferLength <
                 FIELD_OFFSET(AFD_POLL_INFO32, Handles))
        return STATUS_BUFFER_TOO_SMALL;
    Count = From->HandleCount;
    if (!Count || Count > (MAXULONG - FIELD_OFFSET(AFD_POLL_INFO, Handles)) / sizeof(AFD_HANDLE))
        return STATUS_INVALID_PARAMETER;
    Length = FIELD_OFFSET(AFD_POLL_INFO32, Handles) + Count * sizeof(AFD_HANDLE32);
    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < Length ||
        IrpSp->Parameters.DeviceIoControl.OutputBufferLength < Length)
        return STATUS_BUFFER_TOO_SMALL;
    To = ExAllocatePoolWithTag(NonPagedPool,
                              FIELD_OFFSET(AFD_POLL_INFO, Handles) + Count * sizeof(AFD_HANDLE),
                              TAG_AFD_DATA_BUFFER);
    if (!To) return STATUS_NO_MEMORY;
    To->Timeout = From->Timeout;
    To->HandleCount = Count;
    To->Exclusive = From->Exclusive;
    Irp->Tail.Overlay.DriverContext[3] = UlongToPtr(From->Exclusive);
    for (i = 0; i < Count; ++i)
    {
        To->Handles[i].Handle = (SOCKET)(LONG_PTR)(LONG)From->Handles[i].Handle;
        To->Handles[i].Events = From->Handles[i].Events;
        To->Handles[i].Status = From->Handles[i].Status;
    }
    ExFreePool(From);
    Irp->AssociatedIrp.SystemBuffer = To;
    return STATUS_SUCCESS;
}

static VOID
AfdCompletePoll32(PIRP Irp, PAFD_POLL_INFO From)
{
    AFD_POLL_INFO32 *To = (PVOID)From;
    ULONG Count = From->HandleCount, i;

    To->Exclusive = PtrToUlong(Irp->Tail.Overlay.DriverContext[3]);
    for (i = 0; i < Count; ++i)
    {
        AFD_HANDLE Handle = From->Handles[i];
        To->Handles[i].Handle = (ULONG)Handle.Handle;
        To->Handles[i].Events = Handle.Events;
        To->Handles[i].Status = Handle.Status;
    }
    Irp->IoStatus.Information = FIELD_OFFSET(AFD_POLL_INFO32, Handles) + Count * sizeof(AFD_HANDLE32);
}
#endif

static VOID PrintEvents( ULONG Events ) {
#if DBG
    char *events_list[] = { "AFD_EVENT_RECEIVE",
                            "AFD_EVENT_OOB_RECEIVE",
                            "AFD_EVENT_SEND",
                            "AFD_EVENT_DISCONNECT",
                            "AFD_EVENT_ABORT",
                            "AFD_EVENT_CLOSE",
                            "AFD_EVENT_CONNECT",
                            "AFD_EVENT_ACCEPT",
                            "AFD_EVENT_CONNECT_FAIL",
                            "AFD_EVENT_QOS",
                            "AFD_EVENT_GROUP_QOS",
                            NULL };
    int i;

    for( i = 0; events_list[i]; i++ )
        if( Events & (1 << i) ) AFD_DbgPrint(MID_TRACE,("%s ", events_list[i] ));
#endif
}

static VOID CopyBackStatus( PAFD_HANDLE HandleArray,
                            UINT HandleCount ) {
    UINT i;

    for( i = 0; i < HandleCount; i++ ) {
        HandleArray[i].Events = HandleArray[i].Status;
        HandleArray[i].Status = 0;
    }
}

VOID ZeroEvents( PAFD_HANDLE HandleArray,
                 UINT HandleCount ) {
    UINT i;

    for( i = 0; i < HandleCount; i++ ) {
        HandleArray[i].Status = 0;
        HandleArray[i].Events = 0;
    }
}


/* you must pass either Poll OR Irp */
VOID SignalSocket(
   PAFD_ACTIVE_POLL Poll OPTIONAL,
   PIRP _Irp OPTIONAL,
   PAFD_POLL_INFO PollReq,
   NTSTATUS Status
   )
{
    UINT i;
    PIRP Irp = _Irp ? _Irp : Poll->Irp;
    AFD_DbgPrint(MID_TRACE,("Called (Status %x)\n", Status));

    if (Poll)
    {
        RemoveEntryList( &Poll->ListEntry );
        /* A timeout DPC that already runs owns the poll and frees it */
        if (KeCancelTimer( &Poll->Timer ) || KeRemoveQueueDpc( &Poll->TimeoutDpc ))
            ExFreePoolWithTag(Poll, TAG_AFD_ACTIVE_POLL);
        else
            Poll->Irp = NULL;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information =
        FIELD_OFFSET(AFD_POLL_INFO, Handles) + sizeof(AFD_HANDLE) * PollReq->HandleCount;
    CopyBackStatus( PollReq->Handles,
                    PollReq->HandleCount );
    for( i = 0; i < PollReq->HandleCount; i++ ) {
        AFD_DbgPrint
            (MAX_TRACE,
             ("Handle(%x): Got %x,%x\n",
              PollReq->Handles[i].Handle,
              PollReq->Handles[i].Events,
              PollReq->Handles[i].Status));
    }
    UnlockHandles( AFD_HANDLES(Irp), PollReq->HandleCount );
    SET_AFD_HANDLES(Irp, NULL);
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (IoIs32bitProcess(Irp)) AfdCompletePoll32(Irp, PollReq);
#endif
    if (AfdRequestLocked(Irp)) UnlockRequest( Irp, IoGetCurrentIrpStackLocation( Irp ) );
    AFD_DbgPrint(MID_TRACE,("Completing\n"));
    AfdClearCancelRoutine(Irp);
    IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
    AFD_DbgPrint(MID_TRACE,("Done\n"));
}

static KDEFERRED_ROUTINE SelectTimeout;
static VOID NTAPI SelectTimeout( PKDPC Dpc,
                           PVOID DeferredContext,
                           PVOID SystemArgument1,
                           PVOID SystemArgument2 ) {
    PAFD_ACTIVE_POLL Poll = DeferredContext;
    PAFD_POLL_INFO PollReq;
    PIRP Irp;
    KIRQL OldIrql;
    PAFD_DEVICE_EXTENSION DeviceExt;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    AFD_DbgPrint(MID_TRACE,("Called\n"));

    DeviceExt = Poll->DeviceExt;

    KeAcquireSpinLock( &DeviceExt->Lock, &OldIrql );
    Irp = Poll->Irp;
    if (Irp)
    {
        PollReq = Irp->AssociatedIrp.SystemBuffer;
        ZeroEvents( PollReq->Handles, PollReq->HandleCount );
        SignalSocket( Poll, NULL, PollReq, STATUS_TIMEOUT );
    }
    ExFreePoolWithTag(Poll, TAG_AFD_ACTIVE_POLL);
    KeReleaseSpinLock( &DeviceExt->Lock, OldIrql );

    AFD_DbgPrint(MID_TRACE,("Timeout\n"));
}

VOID KillSelectsForFCB( PAFD_DEVICE_EXTENSION DeviceExt,
                        PFILE_OBJECT FileObject,
                        BOOLEAN OnlyExclusive ) {
    KIRQL OldIrql;
    PLIST_ENTRY ListEntry;
    PAFD_ACTIVE_POLL Poll;
    PIRP Irp;
    PAFD_POLL_INFO PollReq;
    PAFD_HANDLE HandleArray;
    UINT i;

    AFD_DbgPrint(MID_TRACE,("Killing selects that refer to %p\n", FileObject));

    KeAcquireSpinLock( &DeviceExt->Lock, &OldIrql );

    ListEntry = DeviceExt->Polls.Flink;
    while ( ListEntry != &DeviceExt->Polls ) {
        Poll = CONTAINING_RECORD(ListEntry, AFD_ACTIVE_POLL, ListEntry);
        ListEntry = ListEntry->Flink;
        Irp = Poll->Irp;
        PollReq = Irp->AssociatedIrp.SystemBuffer;
        HandleArray = AFD_HANDLES(Irp);

        for( i = 0; i < PollReq->HandleCount; i++ ) {
            AFD_DbgPrint(MAX_TRACE,("Req: %u, This %p\n",
                                    HandleArray[i].Handle, FileObject));
            if( (PVOID)HandleArray[i].Handle == FileObject &&
                (!OnlyExclusive || (OnlyExclusive && Poll->Exclusive)) ) {
                ZeroEvents( PollReq->Handles, PollReq->HandleCount );
                SignalSocket( Poll, NULL, PollReq, STATUS_CANCELLED );
                /* The poll and its request are gone */
                break;
            }
        }
    }

    KeReleaseSpinLock( &DeviceExt->Lock, OldIrql );

    AFD_DbgPrint(MID_TRACE,("Done\n"));
}

NTSTATUS NTAPI
AfdSelect( PDEVICE_OBJECT DeviceObject, PIRP Irp,
           PIO_STACK_LOCATION IrpSp ) {
    NTSTATUS Status = STATUS_NO_MEMORY;
    PAFD_FCB FCB;
    PFILE_OBJECT FileObject;
    PAFD_POLL_INFO PollReq = Irp->AssociatedIrp.SystemBuffer;
    PAFD_DEVICE_EXTENSION DeviceExt = DeviceObject->DeviceExtension;
    ULONG InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PAFD_HANDLE LockedHandles;
    KIRQL OldIrql;
    UINT i, Signalled = 0;
    BOOLEAN Exclusive, NoPoll = FALSE;

    SET_AFD_HANDLES(Irp, NULL);

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (IoIs32bitProcess(Irp))
    {
        /* Convert the 32-bit request in place and validate it in native layout */
        Status = AfdCapturePoll32(Irp, IrpSp);
        if (!NT_SUCCESS(Status))
        {
            Irp->IoStatus.Status = Status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
            return Status;
        }
        PollReq = Irp->AssociatedIrp.SystemBuffer;
    }
    else
#endif
    /* The reply is written over the request, so the output must hold the request */
    if( !PollReq ||
        InputLength < FIELD_OFFSET(AFD_POLL_INFO, Handles) ||
        OutputLength < InputLength ||
        PollReq->HandleCount == 0 ||
        PollReq->HandleCount > (InputLength - FIELD_OFFSET(AFD_POLL_INFO, Handles)) / sizeof(AFD_HANDLE) ) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
        return STATUS_INVALID_PARAMETER;
    }

    Exclusive = PollReq->Exclusive;

    AFD_DbgPrint(MID_TRACE,("Called (HandleCount %u Timeout %d)\n",
                            PollReq->HandleCount,
                            (INT)(PollReq->Timeout.QuadPart)));

    Status = LockHandles( PollReq->Handles, PollReq->HandleCount,
                          DeviceObject, Irp->RequestorMode, &LockedHandles );
    if( !NT_SUCCESS(Status) ) {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
        return Status;
    }
    SET_AFD_HANDLES(Irp, LockedHandles);

    if( Exclusive ) {
        for( i = 0; i < PollReq->HandleCount; i++ ) {
            KillSelectsForFCB( DeviceExt,
                               (PFILE_OBJECT)LockedHandles[i].Handle,
                               TRUE );
        }
    }

    KeAcquireSpinLock( &DeviceExt->Lock, &OldIrql );

    for( i = 0; i < PollReq->HandleCount; i++ ) {
        FileObject = (PFILE_OBJECT)LockedHandles[i].Handle;
        FCB = FileObject->FsContext;

        AFD_DbgPrint(MID_TRACE, ("AFD: Select Events: "));
        PrintEvents( PollReq->Handles[i].Events );
        AFD_DbgPrint(MID_TRACE,("\n"));

        PollReq->Handles[i].Status =
            PollReq->Handles[i].Events & FCB->PollState;
        if( PollReq->Handles[i].Status ) {
            AFD_DbgPrint(MID_TRACE,("Signalling %p with %x\n",
                                    FCB, FCB->PollState));
            Signalled++;
        }
    }

    if( Signalled ) {
        Status = STATUS_SUCCESS;
        Irp->IoStatus.Status = Status;
        SignalSocket( NULL, Irp, PollReq, Status );
    } else {

       PAFD_ACTIVE_POLL Poll = NULL;

       Poll = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(AFD_ACTIVE_POLL),
                                    TAG_AFD_ACTIVE_POLL);

       if (Poll){
          Poll->Irp = Irp;
          Poll->DeviceExt = DeviceExt;
          Poll->Exclusive = Exclusive;

          KeInitializeTimerEx( &Poll->Timer, NotificationTimer );

          KeInitializeDpc( (PRKDPC)&Poll->TimeoutDpc, SelectTimeout, Poll );

          InsertTailList( &DeviceExt->Polls, &Poll->ListEntry );

          KeSetTimer( &Poll->Timer, PollReq->Timeout, &Poll->TimeoutDpc );

          Status = STATUS_PENDING;
          IoMarkIrpPending( Irp );
          (void)IoSetCancelRoutine(Irp, AfdCancelHandler);

          /* A cancel that came before the routine was set found nothing to call */
          if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL))
              SignalSocket( Poll, NULL, PollReq, STATUS_CANCELLED );
       } else {
          Status = STATUS_NO_MEMORY;
          NoPoll = TRUE;
       }
    }

    KeReleaseSpinLock( &DeviceExt->Lock, OldIrql );

    /* No poll could be queued: release the references and complete the request */
    if( NoPoll ) {
        UnlockHandles( LockedHandles, PollReq->HandleCount );
        SET_AFD_HANDLES(Irp, NULL);
        Irp->IoStatus.Status = STATUS_NO_MEMORY;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest( Irp, IO_NETWORK_INCREMENT );
    }

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));

    return Status;
}

NTSTATUS NTAPI
AfdEventSelect( PDEVICE_OBJECT DeviceObject, PIRP Irp,
                PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    NTSTATUS Status = STATUS_NO_MEMORY;
    PAFD_EVENT_SELECT_INFO EventSelectInfo;
    HANDLE EventHandle;
    ULONG Events;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    BOOLEAN Guest = IoIs32bitProcess(Irp);
#endif
    PAFD_FCB FCB = FileObject->FsContext;

    UNREFERENCED_PARAMETER(DeviceObject);

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Guest && (!IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ||
                  IrpSp->Parameters.DeviceIoControl.InputBufferLength < 2 * sizeof(ULONG)))
    {
        if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);
        return UnlockAndMaybeComplete(FCB,
            IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ? STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_PARAMETER,
            Irp, 0);
    }
#endif
    EventSelectInfo = LockRequest(Irp, IrpSp, FALSE, NULL);
    if( !SocketAcquireStateLock( FCB ) ) {
        return LostSocket( Irp );
    }

    if ( !EventSelectInfo ) {
         return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp,
                                        0 );
    }
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Guest)
    {
        EventHandle = (HANDLE)(LONG_PTR)(LONG)((PULONG)EventSelectInfo)[0];
        Events = ((PULONG)EventSelectInfo)[1];
    }
    else
#endif
    {
        EventHandle = EventSelectInfo->EventObject;
        Events = EventSelectInfo->Events;
    }
    AFD_DbgPrint(MID_TRACE,("Called (Event %p Triggers %u)\n", EventHandle, Events));

    if( FCB->EventSelect ) ObDereferenceObject( FCB->EventSelect );
    FCB->EventSelect = NULL;

    if( EventHandle && Events ) {
        Status = ObReferenceObjectByHandle( EventHandle,
                                            EVENT_ALL_ACCESS,
                                            *ExEventObjectType,
                                            UserMode,
                                            (PVOID *)&FCB->EventSelect,
                                            NULL );

        if( !NT_SUCCESS(Status) )
        {
            AFD_DbgPrint(MIN_TRACE,("Failed reference event (0x%x)\n", Status));
            FCB->EventSelect = NULL;
        }
        else
            FCB->EventSelectTriggers = Events;
    } else {
        FCB->EventSelect = NULL;
        FCB->EventSelectTriggers = 0;
        Status = STATUS_SUCCESS;
    }

    if((FCB->EventSelect) &&
       (FCB->PollState & (FCB->EventSelectTriggers & ~FCB->EventSelectDisabled)))
    {
        AFD_DbgPrint(MID_TRACE,("Setting event %p\n", FCB->EventSelect));

        /* Set the application's event */
        KeSetEvent( FCB->EventSelect, IO_NETWORK_INCREMENT, FALSE );
    }

    AFD_DbgPrint(MID_TRACE,("Returning %x\n", Status));

    return UnlockAndMaybeComplete( FCB, Status, Irp,
                                   0 );
}

NTSTATUS NTAPI
AfdEnumEvents( PDEVICE_OBJECT DeviceObject, PIRP Irp,
               PIO_STACK_LOCATION IrpSp ) {
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PAFD_ENUM_NETWORK_EVENTS_INFO EnumReq;
    HANDLE EventHandle;
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    BOOLEAN Guest = IoIs32bitProcess(Irp);
#endif
    PAFD_FCB FCB = FileObject->FsContext;
    PKEVENT UserEvent;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    AFD_DbgPrint(MID_TRACE,("Called (FCB %p)\n", FCB));

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Guest && (!IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ||
                  IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_ENUM_NETWORK_EVENTS_INFO32)))
    {
        if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);
        return UnlockAndMaybeComplete(FCB,
            IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ? STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_PARAMETER,
            Irp, 0);
    }
#endif
    /* Native (non-WoW64) path: the output below writes PollEvents and the whole
     * EventStatus array into the captured buffer, whose size equals the user's
     * InputBufferLength (lock.c). Reject input too small to hold the structure,
     * otherwise those writes overrun the NonPagedPool copy. The 32-bit guest
     * path above validates against the 32-bit layout. */
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (!Guest)
#endif
    {
        if (!IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ||
            IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(AFD_ENUM_NETWORK_EVENTS_INFO))
        {
            if (!SocketAcquireStateLock(FCB)) return LostSocket(Irp);
            return UnlockAndMaybeComplete(FCB,
                IrpSp->Parameters.DeviceIoControl.Type3InputBuffer ? STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_PARAMETER,
                Irp, 0);
        }
    }
    EnumReq = LockRequest(Irp, IrpSp, TRUE, NULL);
    if( !SocketAcquireStateLock( FCB ) ) {
        return LostSocket( Irp );
    }

    if ( !EnumReq ) {
         return UnlockAndMaybeComplete( FCB, STATUS_NO_MEMORY, Irp, 0 );
    }

#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Guest)
        EventHandle = (HANDLE)(LONG_PTR)(LONG)((AFD_ENUM_NETWORK_EVENTS_INFO32 *)EnumReq)->Event;
    else
#endif
        EventHandle = EnumReq->Event;

    /* An event may optionally be provided for us to clear */
    if (EventHandle != NULL)
    {
        Status = ObReferenceObjectByHandle(EventHandle,
                                           EVENT_ALL_ACCESS,
                                           *ExEventObjectType,
                                           UserMode,
                                           (PVOID *)&UserEvent,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            AFD_DbgPrint(MIN_TRACE,("Unable to reference event %x\n", Status));
            return UnlockAndMaybeComplete(FCB, Status, Irp, 0);
        }

        /* Clear the event */
        KeClearEvent(UserEvent);
        ObDereferenceObject(UserEvent);
    }

    /* Copy the poll state, masking out disabled events */
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
    if (Guest)
    {
        AFD_ENUM_NETWORK_EVENTS_INFO32 *To = (PVOID)EnumReq;
        To->PollEvents = FCB->PollState & FCB->EventSelectTriggers & ~FCB->EventSelectDisabled;
        RtlCopyMemory(To->EventStatus, FCB->PollStatus, sizeof(To->EventStatus));
    }
    else
#endif
    {
        EnumReq->PollEvents = (FCB->PollState & FCB->EventSelectTriggers & ~FCB->EventSelectDisabled);
        RtlCopyMemory(EnumReq->EventStatus, FCB->PollStatus, sizeof(EnumReq->EventStatus));
    }

    /* Disable the events that triggered the select until the reenabling function is called */
    FCB->EventSelectDisabled |= (FCB->PollState & FCB->EventSelectTriggers);

    return UnlockAndMaybeComplete( FCB, STATUS_SUCCESS, Irp, 0 );
}

/* * * NOTE ALWAYS CALLED AT DISPATCH_LEVEL * * */
static BOOLEAN UpdatePollWithFCB( PAFD_ACTIVE_POLL Poll, PFILE_OBJECT FileObject ) {
    UINT i;
    PAFD_FCB FCB;
    UINT Signalled = 0;
    PAFD_POLL_INFO PollReq = Poll->Irp->AssociatedIrp.SystemBuffer;

    ASSERT( KeGetCurrentIrql() == DISPATCH_LEVEL );

    for( i = 0; i < PollReq->HandleCount; i++ ) {
        FileObject = (PFILE_OBJECT)AFD_HANDLES(Poll->Irp)[i].Handle;
        FCB = FileObject->FsContext;

        PollReq->Handles[i].Status = PollReq->Handles[i].Events & FCB->PollState;
        if( PollReq->Handles[i].Status ) {
            AFD_DbgPrint(MID_TRACE,("Signalling %p with %x\n",
                                    FCB, FCB->PollState));
            Signalled++;
        }
    }

    return Signalled ? 1 : 0;
}

VOID PollReeval( PAFD_DEVICE_EXTENSION DeviceExt, PFILE_OBJECT FileObject ) {
    PAFD_ACTIVE_POLL Poll = NULL;
    PLIST_ENTRY ThePollEnt = NULL;
    PAFD_FCB FCB;
    KIRQL OldIrql;
    PAFD_POLL_INFO PollReq;

    AFD_DbgPrint(MID_TRACE,("Called: DeviceExt %p FileObject %p\n",
                            DeviceExt, FileObject));

    KeAcquireSpinLock( &DeviceExt->Lock, &OldIrql );

    /* Take care of any event select signalling */
    FCB = (PAFD_FCB)FileObject->FsContext;

    if( !FCB ) {
        KeReleaseSpinLock( &DeviceExt->Lock, OldIrql );
        return;
    }

    /* Now signal normal select irps */
    ThePollEnt = DeviceExt->Polls.Flink;

    while( ThePollEnt != &DeviceExt->Polls ) {
        Poll = CONTAINING_RECORD( ThePollEnt, AFD_ACTIVE_POLL, ListEntry );
        PollReq = Poll->Irp->AssociatedIrp.SystemBuffer;
        AFD_DbgPrint(MID_TRACE,("Checking poll %p\n", Poll));

        if( UpdatePollWithFCB( Poll, FileObject ) ) {
            ThePollEnt = ThePollEnt->Flink;
            AFD_DbgPrint(MID_TRACE,("Signalling socket\n"));
            SignalSocket( Poll, NULL, PollReq, STATUS_SUCCESS );
        } else
            ThePollEnt = ThePollEnt->Flink;
    }

    KeReleaseSpinLock( &DeviceExt->Lock, OldIrql );

    if((FCB->EventSelect) &&
       (FCB->PollState & (FCB->EventSelectTriggers & ~FCB->EventSelectDisabled)))
    {
        AFD_DbgPrint(MID_TRACE,("Setting event %p\n", FCB->EventSelect));

        /* Set the application's event */
        KeSetEvent( FCB->EventSelect, IO_NETWORK_INCREMENT, FALSE );
    }

    AFD_DbgPrint(MID_TRACE,("Leaving\n"));
}
