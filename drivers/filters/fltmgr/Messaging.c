/*
* PROJECT:         Filesystem Filter Manager
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            drivers/filters/fltmgr/Messaging.c
* PURPOSE:         Contains the routines to handle the comms layer
* PROGRAMMERS:     Ged Murphy (gedmurphy@reactos.org)
*
* A mini-filter creates a server port with FltCreateCommunicationPort. A user mode program connects
* to it with FilterConnectCommunicationPort, which opens the device \FileSystem\Filters\FltMgrMsg with
* the connection request as extended attribute; the open file is the connection. Then:
*   FilterSendMessage       -> IOCTL_FILTER_SEND_MESSAGE -> the message callback of the server port
*   FltSendMessage          -> queued for the connection, handed to a FilterGetMessage
*                              (IOCTL_FILTER_GET_MESSAGE), answered with FilterReplyMessage
*                              (IOCTL_FILTER_REPLY_MESSAGE) if the sender waits for an answer
* The documentation is the Windows Driver Kit's for FltCreateCommunicationPort, FltSendMessage,
* FltCloseClientPort and fltuser.h. The format of the connection request is our own.
*/

/* INCLUDES ******************************************************************/

#include "fltmgr.h"
#include "fltmgrint.h"
#include "fltmgrproto.h"
#include <fltmgr_shared.h>

#define NDEBUG
#include <debug.h>


/* DATA *********************************************************************/

UNICODE_STRING CommsDeviceName = RTL_CONSTANT_STRING(L"\\FileSystem\\Filters\\FltMgrMsg");
PDEVICE_OBJECT CommsDeviceObject;

typedef struct _FLT_SERVER_PORT
{
    LIST_ENTRY Link;                /* FltpServerPorts, under FltpPortsLock */
    PFLT_FILTER Filter;
    PFLT_CONNECT_NOTIFY ConnectNotify;
    PFLT_DISCONNECT_NOTIFY DisconnectNotify;
    PFLT_MESSAGE_NOTIFY MessageNotify;
    PVOID Cookie;
    LONG MaxConnections;
    LONG NumberOfConnections;
    BOOLEAN Closed;
    LONG RefCount;                  /* the creator, and each connection */
    UNICODE_STRING Name;
    PSECURITY_DESCRIPTOR SecurityDescriptor;    /* who may connect (FLT_PORT_CONNECT) */

} FLT_SERVER_PORT, *PFLT_SERVER_PORT;

typedef struct _FLT_CONNECTION
{
    LIST_ENTRY FilterLink;          /* Filter->ConnectionList */
    PFLT_SERVER_PORT ServerPort;
    PFLT_FILTER Filter;
    PVOID Cookie;
    EX_RUNDOWN_REF MsgNotifRundownRef;  /* message callbacks in flight */
    KSPIN_LOCK Lock;
    LIST_ENTRY Queued;              /* messages for the client, not taken yet */
    LIST_ENTRY Waiting;             /* messages the client has, waiting for the reply */
    LIST_ENTRY GetIrps;             /* FilterGetMessage requests waiting for a message */
    ULONGLONG NextId;
    volatile LONG Disconnected;     /* set once, by whoever disconnects first; read under Lock when queuing */
    volatile LONG ClientPortClosed; /* the filter has let go of the port */
    volatile LONG RefCount;         /* the file object of the client, the filter's port */
    PKTHREAD DisconnectThread;      /* the thread doing the disconnect */
    KEVENT DisconnectDone;          /* set when the disconnect is over, DisconnectNotify included */

} FLT_CONNECTION, *PFLT_CONNECTION;

/*
 * A message of FltSendMessage, on the sender's stack. Data and ReplyBuffer are non-paged copies made by
 * FltSendMessage: they are written and read under Connection->Lock (a spin lock), the filter's own
 * buffers may be paged.
 */
typedef struct _FLT_MESSAGE
{
    LIST_ENTRY Link;
    ULONGLONG Id;
    PVOID Data;
    ULONG Length;
    PVOID ReplyBuffer;
    ULONG ReplyCapacity;
    ULONG ReplyLength;
    NTSTATUS Status;
    BOOLEAN WantsReply;
    BOOLEAN Linked;
    BOOLEAN Done;
    KEVENT Event;

} FLT_MESSAGE, *PFLT_MESSAGE;

static LIST_ENTRY FltpServerPorts = { &FltpServerPorts, &FltpServerPorts };
static FAST_MUTEX FltpPortsLock;

/* The only specific right of a port is FLT_PORT_CONNECT, which every generic right includes */
static GENERIC_MAPPING FltpPortMapping =
{
    STANDARD_RIGHTS_READ | FLT_PORT_CONNECT,
    STANDARD_RIGHTS_WRITE | FLT_PORT_CONNECT,
    STANDARD_RIGHTS_EXECUTE | FLT_PORT_CONNECT,
    FLT_PORT_ALL_ACCESS
};

static
VOID
DisconnectConnection(
    _In_ PFLT_CONNECTION Connection,
    _In_ BOOLEAN WaitForOther
);

static
VOID
CloseClientPortReference(
    _In_ PFLT_CONNECTION Connection,
    _In_ BOOLEAN WaitForOther
);


/* PRIVATE FUNCTIONS ******************************************************/

static
VOID
ReleaseServerPort(_In_ PFLT_SERVER_PORT Port)
{
    if (InterlockedDecrement(&Port->RefCount) == 0)
    {
        if (Port->SecurityDescriptor)
            SeDeassignSecurity(&Port->SecurityDescriptor);
        FltpFreeUnicodeString(&Port->Name);
        ExFreePoolWithTag(Port, FM_TAG_MESSAGE);
    }
}

static
VOID
ReleaseConnection(_In_ PFLT_CONNECTION Connection)
{
    if (InterlockedDecrement(&Connection->RefCount) == 0)
    {
        ReleaseServerPort(Connection->ServerPort);
        ExFreePoolWithTag(Connection, FM_TAG_MESSAGE);
    }
}

/* Gives a message to a request for one, if both are there. Lock held. */
static
PIRP
MatchMessage(_In_ PFLT_CONNECTION Connection,
             _Out_ PFLT_MESSAGE *Message)
{
    PLIST_ENTRY Entry;
    PFLT_MESSAGE Candidate;
    PIRP Irp;

    *Message = NULL;

    while (!IsListEmpty(&Connection->Queued) && !IsListEmpty(&Connection->GetIrps))
    {
        Candidate = CONTAINING_RECORD(Connection->Queued.Flink, FLT_MESSAGE, Link);
        Entry = Connection->GetIrps.Flink;
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        /* A request being cancelled isn't ours anymore */
        if (IoSetCancelRoutine(Irp, NULL) == NULL)
        {
            RemoveEntryList(Entry);
            InitializeListHead(Entry);
            continue;
        }

        RemoveEntryList(Entry);
        *Message = Candidate;
        return Irp;
    }

    return NULL;
}

/* Hands the message to the request, completing it. Called with the lock held; the IRP is completed after. */
static
NTSTATUS
DeliverMessage(_In_ PFLT_CONNECTION Connection,
               _In_ PFLT_MESSAGE Message,
               _In_ PIRP Irp,
               _Out_ PULONG_PTR Information)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Capacity = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PFILTER_MESSAGE_HEADER Header = Irp->AssociatedIrp.SystemBuffer;

    *Information = 0;

    if (Capacity < sizeof(*Header) + Message->Length)
        return STATUS_BUFFER_TOO_SMALL;

    Header->ReplyLength = Message->ReplyCapacity;
    Header->MessageId = Message->Id;
    RtlCopyMemory(Header + 1, Message->Data, Message->Length);
    *Information = sizeof(*Header) + Message->Length;

    /* Out of the queue. A message which wants an answer waits for it, the others are done */
    RemoveEntryList(&Message->Link);
    if (Message->WantsReply)
    {
        InsertTailList(&Connection->Waiting, &Message->Link);
    }
    else
    {
        InitializeListHead(&Message->Link);
        Message->Linked = FALSE;
        Message->Status = STATUS_SUCCESS;
        Message->Done = TRUE;
        KeSetEvent(&Message->Event, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_SUCCESS;
}

static
VOID
NTAPI
CancelGetMessage(_Inout_ PDEVICE_OBJECT DeviceObject,
                 _Inout_ PIRP Irp)
{
    PFLT_CONNECTION Connection = IoGetCurrentIrpStackLocation(Irp)->FileObject->FsContext2;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&Connection->Lock, &OldIrql);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    InitializeListHead(&Irp->Tail.Overlay.ListEntry);
    KeReleaseSpinLock(&Connection->Lock, OldIrql);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* Parses the connection request out of the extended attributes of the create */
static
NTSTATUS
ParseConnectRequest(_In_ PIRP Irp,
                    _Out_ PFLT_CONNECT_REQUEST *Request,
                    _Out_ PULONG ValueLength)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_FULL_EA_INFORMATION Ea = Irp->AssociatedIrp.SystemBuffer;
    ULONG Length = Stack->Parameters.Create.EaLength;
    ULONG Required;
    static const CHAR Name[] = FLT_CONNECT_EA_NAME;

    if (Ea == NULL || Length < FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName))
        return STATUS_INVALID_PARAMETER;

    Required = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + Ea->EaNameLength + 1 + Ea->EaValueLength;
    if (Required > Length ||
        Ea->EaNameLength != sizeof(Name) - 1 ||
        RtlCompareMemory(Ea->EaName, Name, sizeof(Name) - 1) != sizeof(Name) - 1 ||
        Ea->EaValueLength < sizeof(FLT_CONNECT_REQUEST))
    {
        return STATUS_INVALID_PARAMETER;
    }

    *Request = (PFLT_CONNECT_REQUEST)(Ea->EaName + Ea->EaNameLength + 1);
    *ValueLength = Ea->EaValueLength;

    if ((ULONG)sizeof(FLT_CONNECT_REQUEST) + (*Request)->NameLength + (*Request)->ContextSize > *ValueLength)
        return STATUS_INVALID_PARAMETER;

    return STATUS_SUCCESS;
}

/*
 * May the opener connect? The descriptor of the server port decides, checked for FLT_PORT_CONNECT
 * against the token the I/O manager captured for the open (impersonation included). An open from
 * kernel mode is not checked, unless the caller asked for it (OBJ_FORCE_ACCESS_CHECK).
 */
static
NTSTATUS
CheckConnectAccess(_In_ PFLT_SERVER_PORT Server,
                   _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PIO_SECURITY_CONTEXT SecurityContext = Stack->Parameters.Create.SecurityContext;
    KPROCESSOR_MODE AccessMode;
    PPRIVILEGE_SET Privileges = NULL;
    ACCESS_MASK Granted = 0;
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    BOOLEAN Allowed;

    AccessMode = (Stack->Flags & SL_FORCE_ACCESS_CHECK) ? UserMode : Irp->RequestorMode;
    if (AccessMode == KernelMode)
        return STATUS_SUCCESS;

    if (SecurityContext == NULL || SecurityContext->AccessState == NULL || Server->SecurityDescriptor == NULL)
        return STATUS_ACCESS_DENIED;

    SeLockSubjectContext(&SecurityContext->AccessState->SubjectSecurityContext);
    Allowed = SeAccessCheck(Server->SecurityDescriptor,
                            &SecurityContext->AccessState->SubjectSecurityContext,
                            TRUE,
                            FLT_PORT_CONNECT,
                            0,
                            &Privileges,
                            &FltpPortMapping,
                            AccessMode,
                            &Granted,
                            &Status);
    SeUnlockSubjectContext(&SecurityContext->AccessState->SubjectSecurityContext);

    if (Privileges)
        SeFreePrivileges(Privileges);

    if (!Allowed)
        return NT_SUCCESS(Status) ? STATUS_ACCESS_DENIED : Status;

    return STATUS_SUCCESS;
}

static
NTSTATUS
CreateConnection(_Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFLT_CONNECT_REQUEST Request;
    PFLT_SERVER_PORT Server = NULL;
    PFLT_FILTER Filter;
    PFLT_CONNECTION Connection;
    PLIST_ENTRY Entry;
    UNICODE_STRING PortName;
    ULONG ValueLength;
    BOOLEAN Inserted, Disconnected;
    NTSTATUS Status;

    Status = ParseConnectRequest(Irp, &Request, &ValueLength);
    if (!NT_SUCCESS(Status))
        return Status;

    PortName.Buffer = (PWCH)(Request + 1);
    PortName.Length = PortName.MaximumLength = Request->NameLength;

    /*
     * The server port of that name, which isn't being closed, of a filter which isn't being unloaded.
     * The filter is referenced until the connection is in its list (or refused): an unregister waits
     * for that, so it can't miss the connection, and ConnectNotify can't run in an unloaded image.
     * Under FltpPortsLock the port still holds its own filter reference, so the filter is there.
     */
    ExAcquireFastMutex(&FltpPortsLock);
    for (Entry = FltpServerPorts.Flink; Entry != &FltpServerPorts; Entry = Entry->Flink)
    {
        PFLT_SERVER_PORT Candidate = CONTAINING_RECORD(Entry, FLT_SERVER_PORT, Link);

        if (!Candidate->Closed && RtlEqualUnicodeString(&Candidate->Name, &PortName, TRUE))
        {
            if (!(Candidate->Filter->Base.Flags & FLT_OBFL_DRAINING) &&
                NT_SUCCESS(FltObjectReference(Candidate->Filter)))
            {
                Server = Candidate;
                InterlockedIncrement(&Server->RefCount);
            }
            break;
        }
    }
    ExReleaseFastMutex(&FltpPortsLock);

    if (Server == NULL)
        return STATUS_OBJECT_NAME_NOT_FOUND;
    Filter = Server->Filter;

    /* Nobody gets to the filter's callbacks without the right to connect */
    Status = CheckConnectAccess(Server, Irp);
    if (!NT_SUCCESS(Status))
    {
        ReleaseServerPort(Server);
        FltObjectDereference(Filter);
        return Status;
    }

    if (InterlockedIncrement(&Server->NumberOfConnections) > Server->MaxConnections)
    {
        InterlockedDecrement(&Server->NumberOfConnections);
        ReleaseServerPort(Server);
        FltObjectDereference(Filter);
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    Connection = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Connection), FM_TAG_MESSAGE);
    if (Connection == NULL)
    {
        InterlockedDecrement(&Server->NumberOfConnections);
        ReleaseServerPort(Server);
        FltObjectDereference(Filter);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Connection, sizeof(*Connection));
    Connection->ServerPort = Server;
    Connection->Filter = Server->Filter;
    Connection->RefCount = 1;
    Connection->NextId = 1;
    InitializeListHead(&Connection->FilterLink);
    InitializeListHead(&Connection->Queued);
    InitializeListHead(&Connection->Waiting);
    InitializeListHead(&Connection->GetIrps);
    KeInitializeSpinLock(&Connection->Lock);
    ExInitializeRundownProtection(&Connection->MsgNotifRundownRef);
    KeInitializeEvent(&Connection->DisconnectDone, NotificationEvent, FALSE);

    /* The filter is told, and may refuse. The port is the filter's too: it closes it when the client goes. */
    InterlockedIncrement(&Connection->RefCount);
    Stack->FileObject->FsContext2 = Connection;
    Status = Server->ConnectNotify((PFLT_PORT)Connection,
                                   Server->Cookie,
                                   Request->ContextSize ? (PUCHAR)(Request + 1) + Request->NameLength : NULL,
                                   Request->ContextSize,
                                   &Connection->Cookie);
    if (!NT_SUCCESS(Status))
    {
        /* Never connected: nothing to tell the filter, and no port to close */
        Stack->FileObject->FsContext2 = NULL;
        InterlockedDecrement(&Server->NumberOfConnections);
        Connection->Disconnected = TRUE;
        Connection->ClientPortClosed = TRUE;
        KeSetEvent(&Connection->DisconnectDone, IO_NO_INCREMENT, FALSE);
        ReleaseConnection(Connection);
        ReleaseConnection(Connection);
        FltObjectDereference(Filter);
        return Status;
    }

    /*
     * An unregister that started meanwhile has looked at the list already, or will after us: it sets
     * the draining flag before it takes the lock, so either we see the flag or it sees the connection.
     *
     * The filter may also have closed the port already (FltCloseClientPort from another thread, between
     * its ConnectNotify and here): that disconnect is over or under way, and it takes the connection
     * out of the list under this lock at its end. A connection which is disconnected when we look here
     * must not go into the list: nothing would take it out again, and it would be freed while listed.
     */
    ExAcquireFastMutex(&Filter->ConnectionList.mLock);
    Disconnected = Connection->Disconnected;
    Inserted = !(Filter->Base.Flags & FLT_OBFL_DRAINING) && !Disconnected;
    if (Inserted)
    {
        InsertTailList(&Filter->ConnectionList.mList, &Connection->FilterLink);
        Filter->ConnectionList.mCount++;
    }
    ExReleaseFastMutex(&Filter->ConnectionList.mLock);

    if (!Inserted)
    {
        /*
         * Connected, but the filter is going or has let go already: it is told (or a disconnect another
         * thread does is waited for, while our reference keeps the filter), the client gets no handle
         */
        Stack->FileObject->FsContext2 = NULL;
        CloseClientPortReference(Connection, TRUE);
        ReleaseConnection(Connection);
        FltObjectDereference(Filter);
        return Disconnected ? STATUS_PORT_DISCONNECTED : STATUS_FLT_DELETING_OBJECT;
    }

    FltObjectDereference(Filter);

    Irp->IoStatus.Information = FILE_OPENED;
    return STATUS_SUCCESS;
}

/*
 * The connection is over, from either side: the waiting ones are told, the filter is told once.
 * The connection itself stays as long as the filter has its port.
 *
 * When the filter is being unregistered (WaitForOther), coming second means waiting until the first
 * one is through, DisconnectNotify included: the unregister must not free the filter while another
 * thread (the client's cleanup) is still in its callbacks. The connection leaves the filter's list
 * last, so FltpDisconnectFilterPorts finds, and waits for, every disconnect still under way. The
 * other ones coming second (the client's cleanup, FltCloseClientPort, maybe from inside a callback
 * the first one waits for) don't wait. Nor does the thread doing the disconnect for itself.
 */
static
VOID
DisconnectConnection(_In_ PFLT_CONNECTION Connection,
                     _In_ BOOLEAN WaitForOther)
{
    LIST_ENTRY Irps;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    PFLT_SERVER_PORT Server = Connection->ServerPort;

    if (InterlockedExchange(&Connection->Disconnected, TRUE))
    {
        if (WaitForOther && Connection->DisconnectThread != KeGetCurrentThread())
            KeWaitForSingleObject(&Connection->DisconnectDone, Executive, KernelMode, FALSE, NULL);
        return;
    }
    Connection->DisconnectThread = KeGetCurrentThread();

    InitializeListHead(&Irps);

    KeAcquireSpinLock(&Connection->Lock, &OldIrql);

    /* The senders wake up and take their messages out of the lists */
    for (Entry = Connection->Queued.Flink; Entry != &Connection->Queued; Entry = Entry->Flink)
    {
        PFLT_MESSAGE Message = CONTAINING_RECORD(Entry, FLT_MESSAGE, Link);

        Message->Status = STATUS_PORT_DISCONNECTED;
        Message->Done = TRUE;
        KeSetEvent(&Message->Event, IO_NO_INCREMENT, FALSE);
    }
    for (Entry = Connection->Waiting.Flink; Entry != &Connection->Waiting; Entry = Entry->Flink)
    {
        PFLT_MESSAGE Message = CONTAINING_RECORD(Entry, FLT_MESSAGE, Link);

        Message->Status = STATUS_PORT_DISCONNECTED;
        Message->Done = TRUE;
        KeSetEvent(&Message->Event, IO_NO_INCREMENT, FALSE);
    }

    while (!IsListEmpty(&Connection->GetIrps))
    {
        PIRP Irp;

        Entry = RemoveHeadList(&Connection->GetIrps);
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        if (IoSetCancelRoutine(Irp, NULL) != NULL)
            InsertTailList(&Irps, Entry);
        else
            InitializeListHead(Entry);  /* the cancel routine completes it */
    }
    KeReleaseSpinLock(&Connection->Lock, OldIrql);

    while (!IsListEmpty(&Irps))
    {
        PIRP Irp = CONTAINING_RECORD(RemoveHeadList(&Irps), IRP, Tail.Overlay.ListEntry);

        Irp->IoStatus.Status = STATUS_PORT_DISCONNECTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    /* Callbacks for messages of the client, running at this moment */
    ExWaitForRundownProtectionRelease(&Connection->MsgNotifRundownRef);

    InterlockedDecrement(&Server->NumberOfConnections);
    if (Server->DisconnectNotify)
        Server->DisconnectNotify(Connection->Cookie);

    /* Done with the filter: an unregister waiting in FltpDisconnectFilterPorts may go on */
    ExAcquireFastMutex(&Connection->Filter->ConnectionList.mLock);
    if (!IsListEmpty(&Connection->FilterLink))
    {
        RemoveEntryList(&Connection->FilterLink);
        InitializeListHead(&Connection->FilterLink);
        Connection->Filter->ConnectionList.mCount--;
    }
    ExReleaseFastMutex(&Connection->Filter->ConnectionList.mLock);

    KeSetEvent(&Connection->DisconnectDone, IO_NO_INCREMENT, FALSE);
}

/* The filter lets go of its port to the client */
static
VOID
CloseClientPortReference(_In_ PFLT_CONNECTION Connection,
                         _In_ BOOLEAN WaitForOther)
{
    DisconnectConnection(Connection, WaitForOther);

    if (!InterlockedExchange(&Connection->ClientPortClosed, TRUE))
        ReleaseConnection(Connection);
}


/* EXPORTED FUNCTIONS ******************************************************/

_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
FLTAPI
FltCreateCommunicationPort(_In_ PFLT_FILTER Filter,
                           _Outptr_ PFLT_PORT *ServerPort,
                           _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                           _In_opt_ PVOID ServerPortCookie,
                           _In_ PFLT_CONNECT_NOTIFY ConnectNotifyCallback,
                           _In_ PFLT_DISCONNECT_NOTIFY DisconnectNotifyCallback,
                           _In_opt_ PFLT_MESSAGE_NOTIFY MessageNotifyCallback,
                           _In_ LONG MaxConnections)
{
    PFLT_SERVER_PORT Port;
    PLIST_ENTRY Entry;
    PSECURITY_DESCRIPTOR Explicit, Default = NULL;
    SECURITY_SUBJECT_CONTEXT Subject;
    NTSTATUS Status;

    PAGED_CODE();

    *ServerPort = NULL;

    /* The caller must allow at least one connection */
    if (MaxConnections <= 0 || ConnectNotifyCallback == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* The request must be for a kernel handle, with a name */
    if (!(ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE) ||
        ObjectAttributes->ObjectName == NULL ||
        ObjectAttributes->ObjectName->Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Get rundown protection on the target to stop the owner
     * from unloading whilst this port is open. It gets removed in
     * FltCloseCommunicationPort
     */
    Status = FltObjectReference(Filter);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Port = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Port), FM_TAG_MESSAGE);
    if (Port == NULL)
    {
        FltObjectDereference(Filter);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Port, sizeof(*Port));
    Port->RefCount = 1;
    Port->Filter = Filter;
    Port->ConnectNotify = ConnectNotifyCallback;
    Port->DisconnectNotify = DisconnectNotifyCallback;
    Port->MessageNotify = MessageNotifyCallback;
    Port->Cookie = ServerPortCookie;
    Port->MaxConnections = MaxConnections;

    Status = FltpReallocateUnicodeString(&Port->Name, ObjectAttributes->ObjectName->Length, FALSE);
    if (!NT_SUCCESS(Status))
    {
        FltObjectDereference(Filter);
        ExFreePoolWithTag(Port, FM_TAG_MESSAGE);
        return Status;
    }
    RtlCopyUnicodeString(&Port->Name, ObjectAttributes->ObjectName);

    /*
     * The descriptor the filter gave decides who may connect. Without one the port gets the default
     * of FltBuildDefaultSecurityDescriptor: the system and the administrators. What the given
     * descriptor leaves out (owner, group) comes from the creator, as for any other object.
     */
    Explicit = ObjectAttributes->SecurityDescriptor;
    if (Explicit == NULL)
    {
        Status = FltBuildDefaultSecurityDescriptor(&Default, FLT_PORT_ALL_ACCESS);
        Explicit = Default;
    }
    if (NT_SUCCESS(Status))
    {
        SeCaptureSubjectContext(&Subject);
        Status = SeAssignSecurity(NULL,
                                  Explicit,
                                  &Port->SecurityDescriptor,
                                  FALSE,
                                  &Subject,
                                  &FltpPortMapping,
                                  PagedPool);
        SeReleaseSubjectContext(&Subject);
    }
    if (Default)
        FltFreeSecurityDescriptor(Default);
    if (!NT_SUCCESS(Status))
    {
        Port->SecurityDescriptor = NULL;
        FltObjectDereference(Filter);
        ReleaseServerPort(Port);
        return Status;
    }

    ExAcquireFastMutex(&FltpPortsLock);
    for (Entry = FltpServerPorts.Flink; Entry != &FltpServerPorts; Entry = Entry->Flink)
    {
        PFLT_SERVER_PORT Other = CONTAINING_RECORD(Entry, FLT_SERVER_PORT, Link);

        if (RtlEqualUnicodeString(&Other->Name, &Port->Name, TRUE))
        {
            Status = STATUS_OBJECT_NAME_COLLISION;
            break;
        }
    }
    if (NT_SUCCESS(Status))
        InsertTailList(&FltpServerPorts, &Port->Link);
    ExReleaseFastMutex(&FltpPortsLock);

    if (!NT_SUCCESS(Status))
    {
        FltObjectDereference(Filter);
        ReleaseServerPort(Port);
        return Status;
    }

    /* The list of ports of the filter */
    ExAcquireFastMutex(&Filter->PortList.mLock);
    Filter->PortList.mCount++;
    ExReleaseFastMutex(&Filter->PortList.mLock);

    *ServerPort = (PFLT_PORT)Port;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FLTAPI
FltCloseCommunicationPort(_In_ PFLT_PORT ServerPort)
{
    PFLT_SERVER_PORT Port = (PFLT_SERVER_PORT)ServerPort;

    PAGED_CODE();

    /* No new clients. The ones there stay until they go or the filter does. */
    ExAcquireFastMutex(&FltpPortsLock);
    Port->Closed = TRUE;
    RemoveEntryList(&Port->Link);
    InitializeListHead(&Port->Link);
    ExReleaseFastMutex(&FltpPortsLock);

    ExAcquireFastMutex(&Port->Filter->PortList.mLock);
    Port->Filter->PortList.mCount--;
    ExReleaseFastMutex(&Port->Filter->PortList.mLock);

    /* The filter may unload now */
    FltObjectDereference(Port->Filter);
    ReleaseServerPort(Port);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FLTAPI
FltCloseClientPort(_In_ PFLT_FILTER Filter,
                   _Inout_ PFLT_PORT *ClientPort)
{
    PFLT_PORT Port;

    /* Protect against the port being used whilst we're closing it */
    FltAcquirePushLockExclusive(&Filter->PortLock);

    /* Store the port while we have the lock held */
    Port = *ClientPort;
    *ClientPort = NULL;

    /* Unlock the port */
    FltReleasePushLock(&Filter->PortLock);

    if (Port)
        CloseClientPortReference((PFLT_CONNECTION)Port, FALSE);
}

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
FLTAPI
FltSendMessage(_In_ PFLT_FILTER Filter,
               _In_ PFLT_PORT *ClientPort,
               _In_reads_bytes_(SenderBufferLength) PVOID SenderBuffer,
               _In_ ULONG SenderBufferLength,
               _Out_writes_bytes_opt_(*ReplyLength) PVOID ReplyBuffer,
               _Inout_opt_ PULONG ReplyLength,
               _In_opt_ PLARGE_INTEGER Timeout)
{
    PFLT_CONNECTION Connection;
    FLT_MESSAGE Message;
    KIRQL OldIrql;
    PIRP Irp;
    PFLT_MESSAGE Matched;
    ULONG_PTR Information = 0;
    ULONG ReplyCapacity;
    PUCHAR Copy = NULL;
    NTSTATUS Status, DeliverStatus = STATUS_SUCCESS;

    PAGED_CODE();

    if ((ReplyBuffer == NULL) != (ReplyLength == NULL))
        return STATUS_INVALID_PARAMETER;

    ReplyCapacity = ReplyBuffer ? *ReplyLength : 0;
    if (ReplyCapacity > MAXULONG - SenderBufferLength)
        return STATUS_INVALID_PARAMETER;

    /*
     * The message and the room for the answer are non-paged: the client side copies them under the
     * connection's spin lock. The filter's buffers may well be paged, they are only touched here.
     */
    if (SenderBufferLength + ReplyCapacity)
    {
        Copy = ExAllocatePoolWithTag(NonPagedPool, SenderBufferLength + ReplyCapacity, FM_TAG_MESSAGE);
        if (Copy == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        if (SenderBufferLength)
            RtlCopyMemory(Copy, SenderBuffer, SenderBufferLength);
    }

    RtlZeroMemory(&Message, sizeof(Message));
    Message.Data = Copy;
    Message.Length = SenderBufferLength;
    Message.WantsReply = (ReplyBuffer != NULL);
    Message.ReplyBuffer = Copy ? Copy + SenderBufferLength : NULL;
    Message.ReplyCapacity = ReplyCapacity;
    KeInitializeEvent(&Message.Event, NotificationEvent, FALSE);

    /* The pointer is the filter's own while it holds the lock */
    FltAcquirePushLockShared(&Filter->PortLock);
    Connection = (PFLT_CONNECTION)*ClientPort;
    if (Connection == NULL)
    {
        FltReleasePushLock(&Filter->PortLock);
        if (Copy) ExFreePoolWithTag(Copy, FM_TAG_MESSAGE);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * A disconnect sets the flag first and then wakes, under this lock, whatever is queued. So the
     * flag is read under the lock too: a message queued after the disconnect looked would never be
     * woken, and a sender without a timeout would wait for ever.
     */
    KeAcquireSpinLock(&Connection->Lock, &OldIrql);
    if (Connection->Disconnected)
    {
        KeReleaseSpinLock(&Connection->Lock, OldIrql);
        FltReleasePushLock(&Filter->PortLock);
        if (Copy) ExFreePoolWithTag(Copy, FM_TAG_MESSAGE);
        return STATUS_PORT_DISCONNECTED;
    }
    Message.Id = Connection->NextId++;
    InsertTailList(&Connection->Queued, &Message.Link);
    Message.Linked = TRUE;

    /* A request waiting for a message takes it right away */
    Irp = MatchMessage(Connection, &Matched);
    if (Irp)
        DeliverStatus = DeliverMessage(Connection, Matched, Irp, &Information);
    KeReleaseSpinLock(&Connection->Lock, OldIrql);

    if (Irp)
    {
        Irp->IoStatus.Status = DeliverStatus;
        Irp->IoStatus.Information = Information;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    /* Until a client has taken it, or answered it */
    Status = KeWaitForSingleObject(&Message.Event, Executive, KernelMode, FALSE, Timeout);

    KeAcquireSpinLock(&Connection->Lock, &OldIrql);
    if (Status == STATUS_TIMEOUT && !Message.Done)
        Message.Status = STATUS_TIMEOUT;
    if (Message.Linked)
        RemoveEntryList(&Message.Link);
    KeReleaseSpinLock(&Connection->Lock, OldIrql);

    FltReleasePushLock(&Filter->PortLock);

    /* Nobody can write the answer any more: it goes to the filter's buffer at the filter's IRQL */
    if (ReplyLength)
    {
        if (Message.ReplyLength)
            RtlCopyMemory(ReplyBuffer, Message.ReplyBuffer, Message.ReplyLength);
        *ReplyLength = Message.ReplyLength;
    }
    if (Copy)
        ExFreePoolWithTag(Copy, FM_TAG_MESSAGE);
    return Message.Status;
}

/* INTERNAL FUNCTIONS ******************************************************/

NTSTATUS
FltpMsgCreate(_In_ PDEVICE_OBJECT DeviceObject,
              _Inout_ PIRP Irp)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Information = 0;
    Status = CreateConnection(Irp);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static
NTSTATUS
HandleSendMessage(_In_ PFLT_CONNECTION Connection,
                  _Inout_ PIRP Irp,
                  _Out_ PULONG_PTR Information)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG InLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PFLT_SERVER_PORT Server = Connection->ServerPort;
    PVOID Input = NULL;
    ULONG Returned = 0;
    NTSTATUS Status;

    *Information = 0;

    if (Server->MessageNotify == NULL)
        return STATUS_INVALID_DEVICE_REQUEST;

    /* The buffer is shared by the message and the answer: the filter gets a copy of the message */
    if (InLength)
    {
        Input = ExAllocatePoolWithTag(NonPagedPool, InLength, FM_TAG_MESSAGE);
        if (Input == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(Input, Irp->AssociatedIrp.SystemBuffer, InLength);
    }

    if (!ExAcquireRundownProtection(&Connection->MsgNotifRundownRef))
    {
        if (Input) ExFreePoolWithTag(Input, FM_TAG_MESSAGE);
        return STATUS_PORT_DISCONNECTED;
    }

    Status = Server->MessageNotify(Connection->Cookie,
                                   Input,
                                   InLength,
                                   OutLength ? Irp->AssociatedIrp.SystemBuffer : NULL,
                                   OutLength,
                                   &Returned);
    ExReleaseRundownProtection(&Connection->MsgNotifRundownRef);

    if (Input) ExFreePoolWithTag(Input, FM_TAG_MESSAGE);

    if (Returned > OutLength)
        Returned = OutLength;
    *Information = Returned;
    return Status;
}

static
NTSTATUS
HandleGetMessage(_In_ PFLT_CONNECTION Connection,
                 _Inout_ PIRP Irp,
                 _Out_ PULONG_PTR Information)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    KIRQL OldIrql;
    PFLT_MESSAGE Message;
    NTSTATUS Status;

    *Information = 0;

    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FILTER_MESSAGE_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    KeAcquireSpinLock(&Connection->Lock, &OldIrql);
    if (Connection->Disconnected)
    {
        KeReleaseSpinLock(&Connection->Lock, OldIrql);
        return STATUS_PORT_DISCONNECTED;
    }

    if (!IsListEmpty(&Connection->Queued))
    {
        Message = CONTAINING_RECORD(Connection->Queued.Flink, FLT_MESSAGE, Link);
        Status = DeliverMessage(Connection, Message, Irp, Information);
        KeReleaseSpinLock(&Connection->Lock, OldIrql);
        return Status;
    }

    /* Nothing yet: the request waits */
    IoMarkIrpPending(Irp);
    InsertTailList(&Connection->GetIrps, &Irp->Tail.Overlay.ListEntry);
    IoSetCancelRoutine(Irp, CancelGetMessage);
    if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL) != NULL)
    {
        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        InitializeListHead(&Irp->Tail.Overlay.ListEntry);
        KeReleaseSpinLock(&Connection->Lock, OldIrql);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_PENDING;
    }
    KeReleaseSpinLock(&Connection->Lock, OldIrql);
    return STATUS_PENDING;
}

static
NTSTATUS
HandleReplyMessage(_In_ PFLT_CONNECTION Connection,
                   _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG InLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    PFILTER_REPLY_HEADER Header = Irp->AssociatedIrp.SystemBuffer;
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (InLength < sizeof(*Header))
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&Connection->Lock, &OldIrql);
    for (Entry = Connection->Waiting.Flink; Entry != &Connection->Waiting; Entry = Entry->Flink)
    {
        PFLT_MESSAGE Message = CONTAINING_RECORD(Entry, FLT_MESSAGE, Link);
        ULONG Data = InLength - sizeof(*Header);

        if (Message->Id != Header->MessageId)
            continue;

        /* What the sender has room for is what it gets */
        if (Data > Message->ReplyCapacity)
            Data = Message->ReplyCapacity;
        RtlCopyMemory(Message->ReplyBuffer, Header + 1, Data);
        Message->ReplyLength = Data;
        Message->Status = Header->Status;
        Message->Done = TRUE;
        RemoveEntryList(&Message->Link);
        InitializeListHead(&Message->Link);
        Message->Linked = FALSE;
        KeSetEvent(&Message->Event, IO_NO_INCREMENT, FALSE);
        Status = STATUS_SUCCESS;
        break;
    }
    KeReleaseSpinLock(&Connection->Lock, OldIrql);

    return Status;
}

NTSTATUS
FltpMsgDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                     _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PFLT_CONNECTION Connection = Stack->FileObject->FsContext2;
    ULONG_PTR Information = 0;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Connection == NULL)
    {
        Status = STATUS_INVALID_HANDLE;
    }
    else if (Connection->Disconnected)
    {
        Status = STATUS_PORT_DISCONNECTED;
    }
    else
    {
        switch (Stack->Parameters.DeviceIoControl.IoControlCode)
        {
            case IOCTL_FILTER_SEND_MESSAGE:
                Status = HandleSendMessage(Connection, Irp, &Information);
                break;

            case IOCTL_FILTER_GET_MESSAGE:
                Status = HandleGetMessage(Connection, Irp, &Information);
                if (Status == STATUS_PENDING)
                    return STATUS_PENDING;
                break;

            case IOCTL_FILTER_REPLY_MESSAGE:
                Status = HandleReplyMessage(Connection, Irp);
                break;

            default:
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NT_SUCCESS(Status) ? Information : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
FltpMsgDispatch(_In_ PDEVICE_OBJECT DeviceObject,
                _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION StackPtr;
    PFLT_CONNECTION Connection;
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    StackPtr = IoGetCurrentIrpStackLocation(Irp);
    Connection = StackPtr->FileObject ? StackPtr->FileObject->FsContext2 : NULL;

    switch (StackPtr->MajorFunction)
    {
        case IRP_MJ_CLEANUP:
            /* The last handle of the client is gone */
            if (Connection)
                DisconnectConnection(Connection, FALSE);
            break;

        case IRP_MJ_CLOSE:
            if (Connection)
            {
                StackPtr->FileObject->FsContext2 = NULL;
                ReleaseConnection(Connection);
            }
            break;

        case IRP_MJ_DEVICE_CONTROL:
            return FltpMsgDeviceControl(DeviceObject, Irp);

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/*
 * A filter goes away: whoever is still connected is disconnected. Called after the filter is marked
 * draining, so no connection joins the list any more; a disconnect another thread has started is
 * waited for (its DisconnectNotify included), and the connection is in the list until it is over.
 */
VOID
FltpDisconnectFilterPorts(_In_ PFLT_FILTER Filter)
{
    PFLT_CONNECTION Connection;
    PLIST_ENTRY Entry;

    for (;;)
    {
        Connection = NULL;

        ExAcquireFastMutex(&Filter->ConnectionList.mLock);
        for (Entry = Filter->ConnectionList.mList.Flink;
             Entry != &Filter->ConnectionList.mList;
             Entry = Entry->Flink)
        {
            Connection = CONTAINING_RECORD(Entry, FLT_CONNECTION, FilterLink);
            InterlockedIncrement(&Connection->RefCount);
            break;
        }
        ExReleaseFastMutex(&Filter->ConnectionList.mLock);

        if (Connection == NULL)
            break;

        CloseClientPortReference(Connection, TRUE);
        ReleaseConnection(Connection);
    }
}

NTSTATUS
FltpSetupCommunicationObjects(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymLinkName;
    NTSTATUS Status;

    ExInitializeFastMutex(&FltpPortsLock);

    /* Create the device object */
    Status = IoCreateDevice(DriverObject,
                            0,
                            &CommsDeviceName,
                            FILE_DEVICE_WPD,
                            0,
                            0,
                            &CommsDeviceObject);
    if (NT_SUCCESS(Status))
    {
        /* Setup a symbolic link for the device */
        RtlInitUnicodeString(&SymLinkName, L"\\DosDevices\\FltMgrMsg");
        Status = IoCreateSymbolicLink(&SymLinkName, &CommsDeviceName);
        if (NT_SUCCESS(Status))
        {
            ClearFlag(CommsDeviceObject->Flags, DO_DEVICE_INITIALIZING);
        }
        else
        {
            IoDeleteDevice(CommsDeviceObject);
            CommsDeviceObject = NULL;
        }
    }

    return Status;
}
