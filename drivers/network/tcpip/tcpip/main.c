/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/main.c
 * PURPOSE:     Driver entry point
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"
#include <igmp.h>

#include <ntifs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/obfuncs.h>

#include <dispatch.h>
#include <fileobjs.h>
#include <nitrofwk.h>

PDEVICE_OBJECT TCPDeviceObject   = NULL;
PDEVICE_OBJECT UDPDeviceObject   = NULL;
PDEVICE_OBJECT IPDeviceObject    = NULL;
PDEVICE_OBJECT RawIPDeviceObject = NULL;
NDIS_HANDLE GlobalPacketPool     = NULL;
NDIS_HANDLE GlobalBufferPool     = NULL;
KSPIN_LOCK EntityListLock;
TDIEntityInfo *EntityList        = NULL;
ULONG EntityCount                = 0;
ULONG EntityMax                  = 0;
PUCHAR EntityInstanceUsed        = NULL;
UDP_STATISTICS UDPStats;

/* Network timers */
KTIMER IPTimer;
KDPC IPTimeoutDpc;

VOID TiWriteErrorLog(
    PDRIVER_OBJECT DriverContext,
    NTSTATUS ErrorCode,
    ULONG UniqueErrorValue,
    NTSTATUS FinalStatus,
    PWSTR String,
    ULONG DumpDataCount,
    PULONG DumpData)
/*
 * FUNCTION: Writes an error log entry
 * ARGUMENTS:
 *     DriverContext    = Pointer to the driver or device object
 *     ErrorCode        = An error code to put in the log entry
 *     UniqueErrorValue = UniqueErrorValue in the error log packet
 *     FinalStatus      = FinalStatus in the error log packet
 *     String           = If not NULL, a pointer to a string to put in log
 *                        entry
 *     DumpDataCount    = Number of ULONGs of dump data
 *     DumpData         = Pointer to dump data for the log entry
 */
{
    PIO_ERROR_LOG_PACKET LogEntry;
    UCHAR EntrySize;
    ULONG StringSize;
    PUCHAR pString;
    static WCHAR DriverName[] = L"TCP/IP";

    EntrySize = sizeof(IO_ERROR_LOG_PACKET) +
        (DumpDataCount * sizeof(ULONG)) + sizeof(DriverName);

    if (String) {
        StringSize = (wcslen(String) * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
        EntrySize += (UCHAR)StringSize;
    }

    /* Fail if the required error log entry is too large */
    if (EntrySize > ERROR_LOG_MAXIMUM_SIZE)
        return;

    LogEntry = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(DriverContext, EntrySize);
    if (!LogEntry)
        return;

    LogEntry->MajorFunctionCode = -1;
    LogEntry->RetryCount        = -1;
    LogEntry->DumpDataSize      = (USHORT)(DumpDataCount * sizeof(ULONG));
    LogEntry->NumberOfStrings   = (String == NULL) ? 1 : 2;
    LogEntry->StringOffset      = sizeof(IO_ERROR_LOG_PACKET) + (DumpDataCount * sizeof(ULONG));
    LogEntry->EventCategory     = 0;
    LogEntry->ErrorCode         = ErrorCode;
    LogEntry->UniqueErrorValue  = UniqueErrorValue;
    LogEntry->FinalStatus       = FinalStatus;
    LogEntry->SequenceNumber    = -1;
    LogEntry->IoControlCode     = 0;

    if (DumpDataCount)
        RtlCopyMemory(LogEntry->DumpData, DumpData, DumpDataCount * sizeof(ULONG));

    pString = ((PUCHAR)LogEntry) + LogEntry->StringOffset;
    RtlCopyMemory(pString, DriverName, sizeof(DriverName));
    pString += sizeof(DriverName);

    if (String)
        RtlCopyMemory(pString, String, StringSize);

    IoWriteErrorLogEntry(LogEntry);
}

/*
 * Raw sockets. Windows (Windows Server 2022 and 10, evidence v6raw-20261116) lets Administrators, LocalSystem,
 * LocalService and NetworkService open raw sockets of any protocol; anybody else gets IPPROTO_ICMP and
 * IPPROTO_ICMPV6 ones only (in either family; WSAEACCES at socket() for the others), which send echo requests only
 * and may not set the header-include option. AFD refuses the socket itself (afd/main.c); this checks every address
 * opened on the raw devices, whoever opens it, against the opener's token (for AFD's open at bind: the
 * application's), and records the answer on the address file (RawPrivileged) for the send and the option.
 */
#define TI_IPPROTO_ICMPV6   58
static PSECURITY_DESCRIPTOR TiRawSD;

static
NTSTATUS
TiCreateRawSecurityDescriptor(VOID)
{
    PSID Sids[4];
    SECURITY_DESCRIPTOR AbsSD;
    ULONG DaclSize, RelSize = 0, i;
    PACL Dacl;
    NTSTATUS Status;

    Sids[0] = SeExports->SeAliasAdminsSid;
    Sids[1] = SeExports->SeLocalSystemSid;
    Sids[2] = SeExports->SeLocalServiceSid;
    Sids[3] = SeExports->SeNetworkServiceSid;

    DaclSize = sizeof(ACL);
    for (i = 0; i < RTL_NUMBER_OF(Sids); i++)
        DaclSize += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(Sids[i]);
    Dacl = ExAllocatePoolWithTag(PagedPool, DaclSize, DEVICE_OBJ_SECURITY_TAG);
    if (!Dacl)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = RtlCreateSecurityDescriptor(&AbsSD, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlCreateAcl(Dacl, DaclSize, ACL_REVISION);
    for (i = 0; NT_SUCCESS(Status) && i < RTL_NUMBER_OF(Sids); i++)
        Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, Sids[i]);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(&AbsSD, TRUE, Dacl, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlSetOwnerSecurityDescriptor(&AbsSD, SeExports->SeAliasAdminsSid, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlSetGroupSecurityDescriptor(&AbsSD, SeExports->SeLocalSystemSid, FALSE);
    if (NT_SUCCESS(Status))
    {
        Status = RtlAbsoluteToSelfRelativeSD(&AbsSD, NULL, &RelSize);
        if (Status == STATUS_BUFFER_TOO_SMALL)
        {
            TiRawSD = ExAllocatePoolWithTag(PagedPool, RelSize, DEVICE_OBJ_SECURITY_TAG);
            Status = TiRawSD ? RtlAbsoluteToSelfRelativeSD(&AbsSD, TiRawSD, &RelSize) : STATUS_INSUFFICIENT_RESOURCES;
            if (!NT_SUCCESS(Status) && TiRawSD)
            {
                ExFreePoolWithTag(TiRawSD, DEVICE_OBJ_SECURITY_TAG);
                TiRawSD = NULL;
            }
        }
        else if (NT_SUCCESS(Status))
        {
            Status = STATUS_UNSUCCESSFUL;
        }
    }
    ExFreePoolWithTag(Dacl, DEVICE_OBJ_SECURITY_TAG);
    return Status;
}

/* Whether the opener of this create may use any raw protocol. The token is always checked (an open from kernel
   mode for a user, AFD's, carries the user's subject context); no descriptor or no security context: no */
static
BOOLEAN
TiRawCallerPrivileged(
    _In_ PIO_STACK_LOCATION IrpSp)
{
    PIO_SECURITY_CONTEXT Sc = IrpSp->Parameters.Create.SecurityContext;
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    BOOLEAN Allowed;

    if (!TiRawSD || !Sc || !Sc->AccessState)
        return FALSE;

    SeLockSubjectContext(&Sc->AccessState->SubjectSecurityContext);
    Allowed = SeAccessCheck(TiRawSD, &Sc->AccessState->SubjectSecurityContext, TRUE, FILE_WRITE_DATA, 0, NULL,
                            IoGetFileObjectGenericMapping(), UserMode, &Granted, &AccessStatus);
    SeUnlockSubjectContext(&Sc->AccessState->SubjectSecurityContext);
    return Allowed;
}

/*
 * FUNCTION: Creates a file object
 * ARGUMENTS:
 *     DeviceObject = Pointer to a device object for this driver
 *     Irp          = Pointer to a I/O request packet
 * RETURNS:
 *     Status of the operation
 */

NTSTATUS TiCreateFileObject(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PFILE_FULL_EA_INFORMATION EaInfo;
    PTRANSPORT_CONTEXT Context;
    PIO_STACK_LOCATION IrpSp;
    PTA_IP_ADDRESS Address;
    TDI_REQUEST Request;
    PVOID ClientContext;
    NTSTATUS Status;
    ULONG Protocol;
    BOOLEAN RawPrivileged = TRUE;

    TI_DbgPrint(DEBUG_IRP, ("Called. DeviceObject is at (0x%X), IRP is at (0x%X).\n", DeviceObject, Irp));

    EaInfo = Irp->AssociatedIrp.SystemBuffer;

    /* Parameter check */
    /* No EA information means that we're opening for SET/QUERY_INFORMATION
    * style calls. */

    /* Allocate resources here. We release them again if something failed */
    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(TRANSPORT_CONTEXT),
                                    TRANS_CONTEXT_TAG);
    if (!Context)
    {
        TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Context->CancelIrps = FALSE;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp->FileObject->FsContext = Context;
    Request.RequestContext       = Irp;

    /* Branch to the right handler */
    if (EaInfo &&
        (EaInfo->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH) &&
        (RtlCompareMemory(&EaInfo->EaName, TdiTransportAddress,
        TDI_TRANSPORT_ADDRESS_LENGTH) == TDI_TRANSPORT_ADDRESS_LENGTH))
    {
        /* This is a request to open an address */


        /* XXX This should probably be done in IoCreateFile() */
        /* Parameter checks */

        Address = (PTA_IP_ADDRESS)(EaInfo->EaName + EaInfo->EaNameLength + 1); //0-term

        /* An IPv6 address (TA_IP6_ADDRESS, the whole of it within the EA value) is taken for TCP, UDP and raw IP
           (rawip6.c) while the stack has IPv6 on */
        if ((EaInfo->EaValueLength >= sizeof(TA_IP_ADDRESS)) &&
            (Address->TAAddressCount == 1) &&
            (Address->Address[0].AddressType == TDI_ADDRESS_TYPE_IP6))
        {
            if ((EaInfo->EaValueLength < sizeof(TA_IP6_ADDRESS)) ||
                (Address->Address[0].AddressLength < TDI_ADDRESS_LENGTH_IP6) ||
                (DeviceObject != TCPDeviceObject && DeviceObject != UDPDeviceObject &&
                 DeviceObject != RawIPDeviceObject) ||
                !TCPIpv6Enabled)
            {
                TI_DbgPrint(MIN_TRACE, ("IPv6 address refused (length %u, device %p).\n",
                                        EaInfo->EaValueLength, DeviceObject));
                ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
                return STATUS_INVALID_PARAMETER;
            }
        }
        else if ((EaInfo->EaValueLength < sizeof(TA_IP_ADDRESS)) ||
            (Address->TAAddressCount != 1) ||
            (Address->Address[0].AddressLength < TDI_ADDRESS_LENGTH_IP) ||
            (Address->Address[0].AddressType != TDI_ADDRESS_TYPE_IP))
        {
            TI_DbgPrint(MIN_TRACE, ("Parameters are invalid:\n"));
            TI_DbgPrint(MIN_TRACE, ("AddressCount: %d\n", Address->TAAddressCount));
            if( Address->TAAddressCount == 1 )
            {
                TI_DbgPrint(MIN_TRACE, ("AddressLength: %u\n",
                            Address->Address[0].AddressLength));
                TI_DbgPrint(MIN_TRACE, ("AddressType: %u\n",
                            Address->Address[0].AddressType));
            }

            ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        /* Open address file object */

        /* Protocol depends on device object so find the protocol */
        if (DeviceObject == TCPDeviceObject)
            Protocol = IPPROTO_TCP;
        else if (DeviceObject == UDPDeviceObject)
            Protocol = IPPROTO_UDP;
        else if (DeviceObject == IPDeviceObject)
            Protocol = IPPROTO_RAW;
        else if (DeviceObject == RawIPDeviceObject)
        {
            Status = TiGetProtocolNumber(&IrpSp->FileObject->FileName, &Protocol);
            if (!NT_SUCCESS(Status))
            {
                TI_DbgPrint(MIN_TRACE, ("Raw IP protocol number is invalid.\n"));
                ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
                return STATUS_INVALID_PARAMETER;
            }
        }
        else
        {
            TI_DbgPrint(MIN_TRACE, ("Invalid device object at (0x%X).\n", DeviceObject));
            ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        /* A raw address: any protocol for a privileged opener, ICMP and ICMPv6 for everybody */
        if (DeviceObject == RawIPDeviceObject || DeviceObject == IPDeviceObject)
        {
            RawPrivileged = TiRawCallerPrivileged(IrpSp);
            if (!RawPrivileged && Protocol != IPPROTO_ICMP && Protocol != TI_IPPROTO_ICMPV6)
            {
                TI_DbgPrint(MIN_TRACE, ("Raw protocol %u refused to an unprivileged opener.\n", Protocol));
                ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
                return STATUS_ACCESS_DENIED;
            }
        }

        Status = FileOpenAddress(&Request, Address, Protocol, IrpSp->Parameters.Create.ShareAccess, NULL);
        if (NT_SUCCESS(Status))
        {
            /* (the handle is not out yet: nothing sends on it before this is set) */
            ((PADDRESS_FILE)Request.Handle.AddressHandle)->RawPrivileged = RawPrivileged;
            TiRecordAddressFileOwner(IrpSp, Request.Handle.AddressHandle);
            IrpSp->FileObject->FsContext2 = (PVOID)TDI_TRANSPORT_ADDRESS_FILE;
            Context->Handle.AddressHandle = Request.Handle.AddressHandle;
        }

    }
    else if (EaInfo &&
            (EaInfo->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH) &&
            (RtlCompareMemory
            (&EaInfo->EaName, TdiConnectionContext,
            TDI_CONNECTION_CONTEXT_LENGTH) ==
            TDI_CONNECTION_CONTEXT_LENGTH))
    {
        /* This is a request to open a connection endpoint */

        /* Parameter checks */

        if (EaInfo->EaValueLength < sizeof(PVOID))
        {
            TI_DbgPrint(MIN_TRACE, ("Parameters are invalid.\n"));
            ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        /* Can only do connection oriented communication using TCP */

        if (DeviceObject != TCPDeviceObject)
        {
            TI_DbgPrint(MIN_TRACE, ("Bad device object.\n"));
            ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        ClientContext = *((PVOID*)(EaInfo->EaName + EaInfo->EaNameLength));

        /* Open connection endpoint file object */

        Status = FileOpenConnection(&Request, ClientContext);
        if (NT_SUCCESS(Status))
        {
            IrpSp->FileObject->FsContext2 = (PVOID)TDI_CONNECTION_FILE;
            Context->Handle.ConnectionContext = Request.Handle.ConnectionContext;
        }
    }
    else
    {
        /* This is a request to open a control connection */
        Status = FileOpenControlChannel(&Request);
        if (NT_SUCCESS(Status))
        {
            IrpSp->FileObject->FsContext2 = (PVOID)TDI_CONTROL_CHANNEL_FILE;
            Context->Handle.ControlChannel = Request.Handle.ControlChannel;
        }
    }

    if (!NT_SUCCESS(Status))
        ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);

    TI_DbgPrint(DEBUG_IRP, ("Leaving. Status = (0x%X).\n", Status));

    Irp->IoStatus.Status = Status;
    return Status;
}


/*
 * FUNCTION: Releases resources used by a file object
 * ARGUMENTS:
 *     DeviceObject = Pointer to a device object for this driver
 *     Irp          = Pointer to a I/O request packet
 * RETURNS:
 *     Status of the operation
 * NOTES:
 *     This function does not pend
 */
NTSTATUS TiCloseFileObject(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    PTRANSPORT_CONTEXT Context;
    TDI_REQUEST Request;
    NTSTATUS Status;

    IrpSp   = IoGetCurrentIrpStackLocation(Irp);
    Context = IrpSp->FileObject->FsContext;
    if (!Context)
    {
        TI_DbgPrint(MIN_TRACE, ("Parameters are invalid.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    switch ((ULONG_PTR)IrpSp->FileObject->FsContext2)
    {
        case TDI_TRANSPORT_ADDRESS_FILE:
            Request.Handle.AddressHandle = Context->Handle.AddressHandle;
            Status = FileCloseAddress(&Request);
            break;

        case TDI_CONNECTION_FILE:
            Request.Handle.ConnectionContext = Context->Handle.ConnectionContext;
            Status = FileCloseConnection(&Request);
            break;

        case TDI_CONTROL_CHANNEL_FILE:
            Request.Handle.ControlChannel = Context->Handle.ControlChannel;
            Status = FileCloseControlChannel(&Request);
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    if (NT_SUCCESS(Status))
        ExFreePoolWithTag(Context, TRANS_CONTEXT_TAG);

    Irp->IoStatus.Status = Status;

    return Irp->IoStatus.Status;
}


NTSTATUS NTAPI
TiDispatchOpenClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
/*
 * FUNCTION: Main dispath routine
 * ARGUMENTS:
 *     DeviceObject = Pointer to a device object for this driver
 *     Irp          = Pointer to a I/O request packet
 * RETURNS:
 *     Status of the operation
 */
{
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;

//  DbgPrint("Called. DeviceObject is at (0x%X), IRP is at (0x%X).\n", DeviceObject, Irp);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->MajorFunction) {
    /* Open an address file, connection endpoint, or control connection */
    case IRP_MJ_CREATE:
        Status = TiCreateFileObject(DeviceObject, Irp);
        break;

    /* Close an address file, connection endpoint, or control connection */
    case IRP_MJ_CLOSE:
        Status = TiCloseFileObject(DeviceObject, Irp);
        break;

     default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    //DbgPrint("Leaving. Status is (0x%X)\n", Status);

    return IRPFinish( Irp, Status );
}


NTSTATUS NTAPI
TiDispatchInternal(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
/*
 * FUNCTION: Internal IOCTL dispatch routine
 * ARGUMENTS:
 *     DeviceObject = Pointer to a device object for this driver
 *     Irp          = Pointer to a I/O request packet
 * RETURNS:
 *     Status of the operation
 */
{
    NTSTATUS Status;
    BOOLEAN Complete = TRUE;
    PIO_STACK_LOCATION IrpSp;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TI_DbgPrint(DEBUG_IRP, ("[TCPIP, TiDispatchInternal] Called. DeviceObject is at (0x%X), IRP is at (0x%X) MN (%d).\n",
        DeviceObject, Irp, IrpSp->MinorFunction));

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    switch (IrpSp->MinorFunction) {
    case TDI_RECEIVE:
        Status = DispTdiReceive(Irp);
        Complete = FALSE;
        break;

    case TDI_RECEIVE_DATAGRAM:
        Status = DispTdiReceiveDatagram(Irp);
        Complete = FALSE;
        break;

    case TDI_SEND:
        Status = DispTdiSend(Irp);
        Complete = FALSE; /* Completed in DispTdiSend */
        break;

    case TDI_SEND_DATAGRAM:
        Status = DispTdiSendDatagram(Irp);
        Complete = FALSE;
        break;

  case TDI_ACCEPT:
    Status = DispTdiAccept(Irp);
    break;

    case TDI_LISTEN:
        Status = DispTdiListen(Irp);
        Complete = FALSE;
        break;

    case TDI_CONNECT:
        Status = DispTdiConnect(Irp);
        Complete = FALSE; /* Completed by the TCP event handler */
        break;

    case TDI_DISCONNECT:
        Status = DispTdiDisconnect(Irp);
        Complete = FALSE;
        break;

    case TDI_ASSOCIATE_ADDRESS:
        Status = DispTdiAssociateAddress(Irp);
        break;

    case TDI_DISASSOCIATE_ADDRESS:
        Status = DispTdiDisassociateAddress(Irp);
        break;

    case TDI_QUERY_INFORMATION:
        Status = DispTdiQueryInformation(DeviceObject, Irp);
        break;

    case TDI_SET_INFORMATION:
        Status = DispTdiSetInformation(Irp);
        break;

    case TDI_SET_EVENT_HANDLER:
        Status = DispTdiSetEventHandler(Irp);
        break;

    case TDI_ACTION:
        Status = STATUS_SUCCESS;
        break;

    /* An unsupported IOCTL code was submitted */
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    TI_DbgPrint(DEBUG_IRP, ("[TCPIP, TiDispatchInternal] Leaving. Status = (0x%X).\n", Status));

    if( Complete )
        IRPFinish( Irp, Status );

    return Status;
}


/* Admin-only SD (System/Administrators/NetworkService). It is no longer applied
 * to a device; it is the reference SD used by TiCheckControlAccess() to gate
 * privileged control requests (route/ARP/IP address writes). */
static PSECURITY_DESCRIPTOR TiControlSD;

/**
 * @brief Gate privileged control requests (route/ARP/IP address writes).
 *
 * Opening the device is allowed for everyone (sockets), so privileged requests
 * must be authorized per request against the admin-only TiControlSD, using the
 * caller's effective (impersonation) token. Kernel-mode callers are trusted.
 */
static
NTSTATUS TiCheckControlAccess(
    _In_ PIRP Irp)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    ACCESS_MASK Granted;
    NTSTATUS AccessStatus;
    BOOLEAN Allowed;

    if (Irp->RequestorMode == KernelMode)
        return STATUS_SUCCESS;

    if (TiControlSD == NULL)
        return STATUS_ACCESS_DENIED;

    SeCaptureSubjectContext(&SubjectContext);
    SeLockSubjectContext(&SubjectContext);
    Allowed = SeAccessCheck(TiControlSD,
                            &SubjectContext,
                            TRUE,
                            FILE_WRITE_DATA,
                            0,
                            NULL,
                            IoGetFileObjectGenericMapping(),
                            UserMode,
                            &Granted,
                            &AccessStatus);
    SeUnlockSubjectContext(&SubjectContext);
    SeReleaseSubjectContext(&SubjectContext);

    return Allowed ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

/*
 * Socket options by entity id. IOCTL_TCP_SET_INFORMATION_EX / QUERY_INFORMATION_EX with INFO_TYPE_ADDRESS_OBJECT or
 * INFO_TYPE_CONNECTION name their socket by a TDI entity id, and the entity list is public (netstat, iphlpapi).
 * Sent on the socket's own address handle (the one AFD gives the application at bind, which the Winsock helper
 * uses), the request is about that socket and needs nothing more: holding the handle is the right to it. Sent on
 * any other handle (a control channel), the socket the id names must be the caller's: the request comes from the
 * process that opened the address, or from a token of the same user that is not restricted, or from an
 * administrator (LocalSystem, NetworkService: TiControlSD, as for routes and addresses). Anybody else may still read
 * the public tables, but not set or read the options of another user's socket (TTL, broadcast, don't-fragment,
 * multicast groups and options, TCP keepalive and nodelay).
 */

/* Records the user of the opener's token on a new address file. No security context or no memory: no owner, so only
 * the opening process and administrators pass TiCheckAddressFileAccess */
VOID
TiRecordAddressFileOwner(
    _In_ PIO_STACK_LOCATION IrpSp,
    _In_ PADDRESS_FILE AddrFile)
{
    PIO_SECURITY_CONTEXT Sc = IrpSp->Parameters.Create.SecurityContext;
    PTOKEN_USER User = NULL;
    PACCESS_TOKEN Token;
    PSID Sid;
    ULONG Length;

    if (!Sc || !Sc->AccessState)
        return;

    Token = SeQuerySubjectContextToken(&Sc->AccessState->SubjectSecurityContext);
    if (!Token || !NT_SUCCESS(SeQueryInformationToken(Token, TokenUser, (PVOID *)&User)) || !User)
        return;

    if (RtlValidSid(User->User.Sid))
    {
        Length = RtlLengthSid(User->User.Sid);
        Sid = ExAllocatePoolWithTag(NonPagedPool, Length, OWNER_SID_TAG);
        if (Sid && NT_SUCCESS(RtlCopySid(Length, Sid, User->User.Sid)))
            AddrFile->OwnerSid = Sid;
        else if (Sid)
            ExFreePoolWithTag(Sid, OWNER_SID_TAG);
    }

    ExFreePool(User);
}

/* Whether the sender of this request may set or read the options of AddrFile, which it named by entity id (see
 * above). Kernel-mode senders are trusted */
NTSTATUS
TiCheckAddressFileAccess(
    _In_ PIRP Irp,
    _In_ PADDRESS_FILE AddrFile)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PTOKEN_USER User = NULL;
    PACCESS_TOKEN Token;
    BOOLEAN SameUser = FALSE;

    if (Irp->RequestorMode == KernelMode)
        return STATUS_SUCCESS;

    /* The process that opened it (referenced while the address file is listed, so it is not another one) */
    if (AddrFile->FwCreator && AddrFile->FwCreator == (PVOID)PsGetCurrentProcess())
        return STATUS_SUCCESS;

    if (AddrFile->OwnerSid)
    {
        SeCaptureSubjectContext(&SubjectContext);
        Token = SeQuerySubjectContextToken(&SubjectContext);
        if (Token && !SeTokenIsRestricted(Token) &&
            NT_SUCCESS(SeQueryInformationToken(Token, TokenUser, (PVOID *)&User)) && User)
        {
            SameUser = RtlEqualSid(User->User.Sid, AddrFile->OwnerSid);
            ExFreePool(User);
        }
        SeReleaseSubjectContext(&SubjectContext);

        if (SameUser)
            return STATUS_SUCCESS;
    }

    return TiCheckControlAccess(Irp);
}

/**
 * @brief Dispatch routine for IRP_MJ_DEVICE_CONTROL requests
 *
 * @param[in] DeviceObject
 *   Pointer to a device object for this driver
 * @param[in] Irp
 *   Pointer to a I/O request packet
 *
 * @return
 *   Status of the operation
 */
NTSTATUS NTAPI
TiDispatch(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TI_DbgPrint(DEBUG_IRP, ("[TCPIP, TiDispatch] Called. IRP is at (0x%X).\n", Irp));

    Irp->IoStatus.Information = 0;

#if 0
    Status = TdiMapUserRequest(DeviceObject, Irp, IrpSp);
    if (NT_SUCCESS(Status))
    {
        TiDispatchInternal(DeviceObject, Irp);
        Status = STATUS_PENDING;
    }
    else
    {
#else
    if (TRUE) {
#endif
        /* See if this request is TCP/IP specific */
        switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
        {
            case IOCTL_TCP_QUERY_INFORMATION_EX:
                TI_DbgPrint(MIN_TRACE, ("TCP_QUERY_INFORMATION_EX\n"));
                Status = DispTdiQueryInformationEx(Irp, IrpSp);
                break;

            case IOCTL_TCP_SET_INFORMATION_EX:
                TI_DbgPrint(MIN_TRACE, ("TCP_SET_INFORMATION_EX\n"));
                /* Provider-class (ARP table / route) writes are privileged.
                 * Per-socket address-object/connection options are the
                 * socket's owner's (TiCheckAddressFileAccess, from info.c). */
                if (IrpSp->Parameters.DeviceIoControl.InputBufferLength <
                    FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                /* The option bytes the handlers read are the ones the caller supplied: BufferSize names
                 * them and must fit in the input */
                if (((PTCP_REQUEST_SET_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer)->BufferSize >
                    IrpSp->Parameters.DeviceIoControl.InputBufferLength -
                    FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (((PTCP_REQUEST_SET_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer)->ID.toi_type !=
                    INFO_TYPE_ADDRESS_OBJECT &&
                    ((PTCP_REQUEST_SET_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer)->ID.toi_type !=
                    INFO_TYPE_CONNECTION)
                {
                    Status = TiCheckControlAccess(Irp);
                    if (!NT_SUCCESS(Status))
                        break;
                }
                Status = DispTdiSetInformationEx(Irp, IrpSp);
                break;

            case IOCTL_SET_IP_ADDRESS:
                TI_DbgPrint(MIN_TRACE, ("SET_IP_ADDRESS\n"));
                Status = TiCheckControlAccess(Irp);
                if (NT_SUCCESS(Status))
                    Status = DispTdiSetIPAddress(Irp, IrpSp);
                break;

            case IOCTL_DELETE_IP_ADDRESS:
                TI_DbgPrint(MIN_TRACE, ("DELETE_IP_ADDRESS\n"));
                Status = TiCheckControlAccess(Irp);
                if (NT_SUCCESS(Status))
                    Status = DispTdiDeleteIPAddress(Irp, IrpSp);
                break;

            case IOCTL_IP6_ADDRESS_CONFIG:
                Status = TiCheckControlAccess(Irp);
                if (NT_SUCCESS(Status))
                    Status = DispAddressConfig6(Irp, IrpSp);
                break;

            case IOCTL_IP6_ROUTE_CONFIG:
                Status = TiCheckControlAccess(Irp);
                if (NT_SUCCESS(Status))
                    Status = DispRouteConfig6(Irp, IrpSp);
                break;

            case IOCTL_IP_INTERFACE_CONFIG:
                Status = TiCheckControlAccess(Irp);
                if (NT_SUCCESS(Status))
                    Status = DispInterfaceConfig(Irp, IrpSp);
                break;

            case IOCTL_IP6_SOLICIT:
                Status = DispSolicit6(Irp, IrpSp);
                break;

            case IOCTL_IP6_POLICY_RELOAD:
                Status = TiCheckControlAccess(Irp);
                if (NT_SUCCESS(Status))
                    Status = TCP6LoadPrefixPolicies();
                break;

            case IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST:
                TI_DbgPrint(MIN_TRACE, ("IP_ADDCHANGE_NOTIFY_REQUEST\n"));
                Status = DispAddrChangeNotifyRequest(Irp);
                break;

            case IOCTL_IP_ROUTECHANGE_NOTIFY_REQUEST:
                Status = DispRouteChangeNotifyRequest(Irp);
                break;

            case IOCTL_IP_ADDCHANGE_CANCEL_REQUEST:
                Status = DispAddrChangeCancelRequest(Irp);
                break;

            case IOCTL_QUERY_IP_HW_ADDRESS:
                TI_DbgPrint(MIN_TRACE, ("QUERY_IP_HW_ADDRESS\n"));
                Status = DispTdiQueryIpHwAddress(DeviceObject, Irp, IrpSp);
                break;

            case IOCTL_ICMP_ECHO_REQUEST:
                TI_DbgPrint(MIN_TRACE, ("ICMP_ECHO_REQUEST\n"));
                /* \Device\Ip6: an ICMPv6 echo (Icmp6SendEcho2) */
                if (Ip6DeviceObject && DeviceObject == Ip6DeviceObject)
                    Status = DispEchoRequest6(Irp, IrpSp);
                else
                    Status = DispEchoRequest(DeviceObject, Irp, IrpSp);
                break;

            default:
                TI_DbgPrint(MIN_TRACE, ("Unknown IOCTL 0x%X\n",
                    IrpSp->Parameters.DeviceIoControl.IoControlCode));
                Status = STATUS_NOT_IMPLEMENTED;
                break;
        }
    }

    TI_DbgPrint(DEBUG_IRP, ("[TCPIP, TiDispatch] Leaving. Status = (0x%X).\n", Status));

    return IRPFinish(Irp, Status);
}

/* WindowsDeviceAcl: the descriptor of \Device\Ip as Windows Server 2022 has it: System and Administrators FILE_ALL_ACCESS,
   Everyone WorldAccess, nobody else (no Network Service ACE). Without it: System, Administrators and Network Service
   FILE_ALL_ACCESS (the descriptor that the privileged control requests are checked against, and of \Device\Tcp).
   Specific rights, not GENERIC_ALL: the access check does not map generic rights inside an ACE (Windows does not). */
static
NTSTATUS TiCreateSecurityDescriptor(
    _In_ ACCESS_MASK WorldAccess,
    _In_ BOOLEAN WindowsDeviceAcl,
    _Out_ PSECURITY_DESCRIPTOR *SecurityDescriptor)
{
    NTSTATUS Status;
    SECURITY_DESCRIPTOR AbsSD;
    ULONG DaclSize, RelSDSize = 0;
    PSECURITY_DESCRIPTOR RelSD = NULL;
    PACL Dacl = NULL;

    /* Setup a SD */
    Status = RtlCreateSecurityDescriptor(&AbsSD,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to create the absolute SD (0x%X)\n", Status));
        goto Quit;
    }

    /* Setup a DACL */
    DaclSize = sizeof(ACL) +
               sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(SeExports->SeLocalSystemSid) +
               sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(SeExports->SeAliasAdminsSid) +
               sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(SeExports->SeNetworkServiceSid) +
               sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(SeExports->SeWorldSid);
    Dacl = ExAllocatePoolWithTag(PagedPool,
                                 DaclSize,
                                 DEVICE_OBJ_SECURITY_TAG);
    if (Dacl == NULL)
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to allocate buffer heap for a DACL\n"));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quit;
    }

    Status = RtlCreateAcl(Dacl,
                          DaclSize,
                          ACL_REVISION);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to create a DACL (0x%X)\n", Status));
        goto Quit;
    }

    /* Setup access */
    Status = RtlAddAccessAllowedAce(Dacl,
                                    ACL_REVISION,
                                    FILE_ALL_ACCESS,
                                    SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to add access allowed ACE for System SID (0x%X)\n", Status));
        goto Quit;
    }

    Status = RtlAddAccessAllowedAce(Dacl,
                                    ACL_REVISION,
                                    FILE_ALL_ACCESS,
                                    SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to add access allowed ACE for Admins SID (0x%X)\n", Status));
        goto Quit;
    }

    if (!WindowsDeviceAcl)
    {
        Status = RtlAddAccessAllowedAce(Dacl,
                                        ACL_REVISION,
                                        FILE_ALL_ACCESS,
                                        SeExports->SeNetworkServiceSid);
        if (!NT_SUCCESS(Status))
        {
            TI_DbgPrint(MIN_TRACE, ("Failed to add access allowed ACE for Network Service SID (0x%X)\n", Status));
            goto Quit;
        }
    }

    if (WorldAccess != 0)
    {
        /* Everyone may open the device and use sockets (create/bind/connect/
         * send/recv), as on Windows. Privileged control requests are checked
         * separately against TiControlSD. */
        Status = RtlAddAccessAllowedAce(Dacl,
                                        ACL_REVISION,
                                        WorldAccess,
                                        SeExports->SeWorldSid);
        if (!NT_SUCCESS(Status))
        {
            TI_DbgPrint(MIN_TRACE, ("Failed to add access allowed ACE for World SID (0x%X)\n", Status));
            goto Quit;
        }
    }

    /* Assign security data to SD */
    Status = RtlSetDaclSecurityDescriptor(&AbsSD,
                                          TRUE,
                                          Dacl,
                                          FALSE);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to set DACL to security descriptor (0x%X)\n", Status));
        goto Quit;
    }

    Status = RtlSetGroupSecurityDescriptor(&AbsSD,
                                           SeExports->SeLocalSystemSid,
                                           FALSE);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to set group to security descriptor (0x%X)\n", Status));
        goto Quit;
    }

    Status = RtlSetOwnerSecurityDescriptor(&AbsSD,
                                           SeExports->SeAliasAdminsSid,
                                           FALSE);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to set owner to security descriptor (0x%X)\n", Status));
        goto Quit;
    }

    /* Get the required buffer size for the self-relative SD */
    Status = RtlAbsoluteToSelfRelativeSD(&AbsSD,
                                         NULL,
                                         &RelSDSize);
    if (Status != STATUS_BUFFER_TOO_SMALL)
    {
        TI_DbgPrint(MIN_TRACE, ("Expected STATUS_BUFFER_TOO_SMALL but got something else (0x%X)\n", Status));
        goto Quit;
    }

    RelSD = ExAllocatePoolWithTag(PagedPool,
                                  RelSDSize,
                                  DEVICE_OBJ_SECURITY_TAG);
    if (RelSD == NULL)
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to allocate buffer heap for relative SD\n"));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Quit;
    }

    /* Convert it now */
    Status = RtlAbsoluteToSelfRelativeSD(&AbsSD,
                                         RelSD,
                                         &RelSDSize);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to convert absolute SD into a relative SD (0x%X)\n", Status));
        goto Quit;
    }

    /* Give the buffer to caller */
    *SecurityDescriptor = RelSD;

Quit:
    if (!NT_SUCCESS(Status))
    {
        if (RelSD != NULL)
        {
            ExFreePoolWithTag(RelSD, DEVICE_OBJ_SECURITY_TAG);
        }
    }

    if (Dacl != NULL)
    {
        ExFreePoolWithTag(Dacl, DEVICE_OBJ_SECURITY_TAG);
    }

    return Status;
}

static
NTSTATUS TiSetupTcpDeviceSD(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ACCESS_MASK WorldAccess,
    _In_ BOOLEAN WindowsDeviceAcl)
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR Sd;
    SECURITY_INFORMATION Info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    /* Obtain a security descriptor */
    Status = TiCreateSecurityDescriptor(WorldAccess, WindowsDeviceAcl, &Sd);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to create a security descriptor for the device object\n"));
        return Status;
    }

    /* Whack the new descriptor into the TCP device object */
    Status = ObSetSecurityObjectByPointer(DeviceObject,
                                          Info,
                                          Sd);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to set new security information to the device object\n"));
    }

    ExFreePoolWithTag(Sd, DEVICE_OBJ_SECURITY_TAG);
    return Status;
}

static
NTSTATUS TiSecurityStartup(
    VOID)
{
    NTSTATUS Status;

    /* Reference SD for privileged control requests */
    Status = TiCreateSecurityDescriptor(0, FALSE, &TiControlSD);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to create the control security descriptor\n"));
        return Status;
    }

    /* Who may open raw sockets of any protocol (without it nobody may: only ICMP and ICMPv6 ones) */
    Status = TiCreateRawSecurityDescriptor();
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to create the raw socket security descriptor\n"));
        return Status;
    }

    /* Set security data for the TCP and IP device objects */
    Status = TiSetupTcpDeviceSD(TCPDeviceObject, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FALSE);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to set security data for TCP device object\n"));
        return Status;
    }

    /* Windows grants Everyone read, write AND execute on the IP device (Device\Ip)
     * (0x1201bf): IcmpCreateFile() opens it with GENERIC_EXECUTE, which is how a
     * standard user can ping. */
    Status = TiSetupTcpDeviceSD(IPDeviceObject,
                                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE, TRUE);
    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(MIN_TRACE, ("Failed to set security data for IP device object\n"));
        return Status;
    }

    /* \Device\Ip6 as \Device\Ip: Icmp6CreateFile() opens it with GENERIC_EXECUTE (Windows Server 2022 has the same
     * descriptor on both). Two differences from Windows are left for the operator to decide: both devices lack the
     * restricted code ACE (S-1-5-12, read and execute) of Windows, and \Device\Tcp gives Everyone read and write where
     * Windows gives read and execute only (0x1200a0). */
    if (Ip6DeviceObject)
    {
        Status = TiSetupTcpDeviceSD(Ip6DeviceObject,
                                    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE, TRUE);
        if (!NT_SUCCESS(Status))
        {
            TI_DbgPrint(MIN_TRACE, ("Failed to set security data for IPv6 device object\n"));
            return Status;
        }
    }

    return STATUS_SUCCESS;
}


VOID NTAPI TiUnload(
  PDRIVER_OBJECT DriverObject)
/*
 * FUNCTION: Unloads the driver
 * ARGUMENTS:
 *     DriverObject = Pointer to driver object created by the system
 */
{
#if DBG
  KIRQL OldIrql;
#endif

    NitroFwUnload();

#if DBG
    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    if (!IsListEmpty(&AddressFileListHead)) {
        TI_DbgPrint(MIN_TRACE, ("[TCPIP, TiUnload] Called. Open address file objects exists.\n"));
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
#endif
    /* Cancel timer */
    KeCancelTimer(&IPTimer);

    if (TiControlSD)
    {
        ExFreePoolWithTag(TiControlSD, DEVICE_OBJ_SECURITY_TAG);
        TiControlSD = NULL;
    }
    if (TiRawSD)
    {
        ExFreePoolWithTag(TiRawSD, DEVICE_OBJ_SECURITY_TAG);
        TiRawSD = NULL;
    }

    /* Unregister loopback adapter */
    LoopUnregisterAdapter(NULL);

    /* Unregister protocol with NDIS */
    LANUnregisterProtocol();

    /* Shutdown transport level protocol subsystems */
    TCPShutdown();
    UDPShutdown();
    RawIPShutdown();
    ICMPShutdown();
    IGMPShutdown();
    AddrChangeShutdown();

    /* Shutdown network level protocol subsystem */
    IPShutdown();

    /* Free NDIS buffer descriptors */
    if (GlobalBufferPool)
        NdisFreeBufferPool(GlobalBufferPool);

    /* Free NDIS packet descriptors */
    if (GlobalPacketPool)
        NdisFreePacketPool(GlobalPacketPool);

    /* Release all device objects */

    if (TCPDeviceObject)
        IoDeleteDevice(TCPDeviceObject);

    if (UDPDeviceObject)
        IoDeleteDevice(UDPDeviceObject);

    if (RawIPDeviceObject)
        IoDeleteDevice(RawIPDeviceObject);

    if (Ip6DeviceObject)
        IoDeleteDevice(Ip6DeviceObject);

    if (IPDeviceObject) {
        ChewShutdown();
        IoDeleteDevice(IPDeviceObject);
    }

    if (EntityList)
        ExFreePoolWithTag(EntityList, TDI_ENTITY_TAG);

    if (EntityInstanceUsed)
        ExFreePoolWithTag(EntityInstanceUsed, TDI_ENTITY_TAG);

    TI_DbgPrint(MAX_TRACE, ("[TCPIP, TiUnload] Leaving.\n"));
}

NTSTATUS NTAPI
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
/*
 * FUNCTION: Main driver entry point
 * ARGUMENTS:
 *     DriverObject = Pointer to a driver object for this driver
 *     RegistryPath = Registry node for configuration parameters
 * RETURNS:
 *     Status of driver initialization
 */
{
    NTSTATUS Status;
    UNICODE_STRING strIpDeviceName = RTL_CONSTANT_STRING(DD_IP_DEVICE_NAME);
    UNICODE_STRING strRawDeviceName = RTL_CONSTANT_STRING(DD_RAWIP_DEVICE_NAME);
    UNICODE_STRING strUdpDeviceName = RTL_CONSTANT_STRING(DD_UDP_DEVICE_NAME);
    UNICODE_STRING strTcpDeviceName = RTL_CONSTANT_STRING(DD_TCP_DEVICE_NAME);
    UNICODE_STRING strNdisDeviceName = RTL_CONSTANT_STRING(TCPIP_PROTOCOL_NAME);
    NDIS_STATUS NdisStatus;
    LARGE_INTEGER DueTime;

    TI_DbgPrint(MAX_TRACE, ("[TCPIP, DriverEntry] Called\n"));

    /* TdiInitialize() ? */

    /* FIXME: Create symbolic links in Win32 namespace */

    /* Initialize our periodic timer and its associated DPC object. When the
        timer expires, the IPTimeout deferred procedure call (DPC) is queued */
    KeInitializeDpc(&IPTimeoutDpc, IPTimeoutDpcFn, NULL);
    KeInitializeTimer(&IPTimer);

    /* Create IP device object */
    Status = IoCreateDevice(DriverObject, 0, &strIpDeviceName,
        FILE_DEVICE_NETWORK, 0, FALSE, &IPDeviceObject);
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Failed to create IP device object. Status (0x%X).\n", Status));
        TiUnload(DriverObject);
        return Status;
    }

    Status = ChewInit( IPDeviceObject );
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Failed to initialize the work queue. Status (0x%X).\n", Status));
        TiUnload(DriverObject);
        return Status;
    }

    /* Create RawIP device object */
    Status = IoCreateDevice(DriverObject, 0, &strRawDeviceName,
        FILE_DEVICE_NETWORK, 0, FALSE, &RawIPDeviceObject);
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Failed to create RawIP device object. Status (0x%X).\n", Status));
        TiUnload(DriverObject);
        return Status;
    }

    /* Create UDP device object */
    Status = IoCreateDevice(DriverObject, 0, &strUdpDeviceName,
        FILE_DEVICE_NETWORK, 0, FALSE, &UDPDeviceObject);
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Failed to create UDP device object. Status (0x%X).\n", Status));
        TiUnload(DriverObject);
        return Status;
    }

    /* Create TCP device object */
    Status = IoCreateDevice(DriverObject, 0, &strTcpDeviceName,
        FILE_DEVICE_NETWORK, 0, FALSE, &TCPDeviceObject);
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Failed to create TCP device object. Status (0x%X).\n", Status));
        TiUnload(DriverObject);
        return Status;
    }

    /* Setup network layer and transport layer entities */
    KeInitializeSpinLock(&EntityListLock);
    /* AddEntity grows both as needed */
    EntityList = ExAllocatePoolWithTag(NonPagedPool,
                                       sizeof(TDIEntityInfo) * TDI_ENTITIES_INITIAL,
                                       TDI_ENTITY_TAG );
    EntityInstanceUsed = ExAllocatePoolWithTag(NonPagedPool,
                                               TDI_ENTITIES_INITIAL + 1,
                                               TDI_ENTITY_TAG );
    if (!EntityList || !EntityInstanceUsed) {
        TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
        TiUnload(DriverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    EntityCount = 0;
    EntityMax   = TDI_ENTITIES_INITIAL;

    /* Allocate NDIS packet descriptors */
    NdisAllocatePacketPoolEx(&NdisStatus, &GlobalPacketPool, 500, 1500, sizeof(PACKET_CONTEXT));
    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        TiUnload(DriverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Allocate NDIS buffer descriptors */
    NdisAllocateBufferPool(&NdisStatus, &GlobalBufferPool, 2000);
    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        TiUnload(DriverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Initialize address file list and protecting spin lock */
    InitializeListHead(&AddressFileListHead);
    {
        ULONG b;
        for (b = 0; b < ADDRESS_FILE_PORT_BUCKETS; b++)
            InitializeListHead(&AddressFilePortHash[b]);
    }
    KeInitializeSpinLock(&AddressFileListLock);

    /* Initialize connection endpoint list and protecting spin lock */
    InitializeListHead(&ConnectionEndpointListHead);
    KeInitializeSpinLock(&ConnectionEndpointListLock);

    /* Initialize interface list and protecting spin lock */
    InitializeListHead(&InterfaceListHead);
    KeInitializeSpinLock(&InterfaceListLock);

    /* Initialize network level protocol subsystem */
    IPStartup(RegistryPath);

    /* Initialize transport level protocol subsystems */
    Status = RawIPStartup();
    if( !NT_SUCCESS(Status) ) {
        TiUnload(DriverObject);
        return Status;
    }

    Status = UDPStartup();
    if( !NT_SUCCESS(Status) ) {
        TiUnload(DriverObject);
        return Status;
    }

    Status = TCPStartup();
    if( !NT_SUCCESS(Status) ) {
        TiUnload(DriverObject);
        return Status;
    }

    Status = ICMPStartup();
    if( !NT_SUCCESS(Status) ) {
        TiUnload(DriverObject);
        return Status;
    }

    Status = IGMPStartup();
    if( !NT_SUCCESS(Status) ) {
        TiUnload(DriverObject);
        return Status;
    }

    /* The ICMPv6 echo device (\Device\Ip6, Icmp6CreateFile) exists only with IPv6 on (TCPStartup read the switch);
       without it Icmp6CreateFile fails as before. Not having it is no reason to fail the driver */
    if (TCPIpv6Enabled)
    {
        UNICODE_STRING strIp6DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Ip6");

        if (!NT_SUCCESS(IoCreateDevice(DriverObject, 0, &strIp6DeviceName, FILE_DEVICE_NETWORK, 0, FALSE,
                                       &Ip6DeviceObject)))
            Ip6DeviceObject = NULL;
    }

    /* Initialize security */
    Status = TiSecurityStartup();
    if (!NT_SUCCESS(Status))
    {
        TiUnload(DriverObject);
        return Status;
    }

    /* Use direct I/O */
    IPDeviceObject->Flags    |= DO_DIRECT_IO;
    RawIPDeviceObject->Flags |= DO_DIRECT_IO;
    UDPDeviceObject->Flags   |= DO_DIRECT_IO;
    TCPDeviceObject->Flags   |= DO_DIRECT_IO;

    /* Initialize the driver object with this driver's entry points */
    DriverObject->MajorFunction[IRP_MJ_CREATE]  = TiDispatchOpenClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]   = TiDispatchOpenClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = TiDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = TiDispatchInternal;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TiDispatch;

    DriverObject->DriverUnload = TiUnload;

    /* NitroOS inbound filter (\\Device\\NitroFw); never fails the driver */
    NitroFwInitialize(DriverObject);

    AddrChangeInitialize();

    /* Open loopback adapter */
    Status = LoopRegisterAdapter(NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Failed to create loopback adapter. Status (0x%X).\n", Status));
        TiUnload(DriverObject);
        return Status;
    }

    /* Register protocol with NDIS */
    /* This used to be IP_DEVICE_NAME but the DDK says it has to match your entry in the SCM */
    Status = LANRegisterProtocol(&strNdisDeviceName);
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE,("Failed to register protocol with NDIS; status 0x%x\n", Status));
        TiWriteErrorLog(
        DriverObject,
        EVENT_TRANSPORT_REGISTER_FAILED,
        TI_ERROR_DRIVERENTRY,
        Status,
        NULL,
        0,
        NULL);
        TiUnload(DriverObject);
        return Status;
    }

    /* Start the periodic timer with an initial and periodic
        relative expiration time of IP_TIMEOUT milliseconds */
    DueTime.QuadPart = -(LONGLONG)IP_TIMEOUT * 10000;
    KeSetTimerEx(&IPTimer, DueTime, IP_TIMEOUT, &IPTimeoutDpc);

    TI_DbgPrint(MAX_TRACE, ("[TCPIP, DriverEntry] Finished\n"));


    return STATUS_SUCCESS;
}

VOID NTAPI
IPAddInterface(
    ULONG   Unknown0,
    ULONG   Unknown1,
    ULONG   Unknown2,
    ULONG   Unknown3,
    ULONG   Unknown4)
{
    UNIMPLEMENTED;
}


VOID NTAPI
IPDelInterface(
    ULONG   Unknown0)
{
    UNIMPLEMENTED;
}


VOID NTAPI
LookupRoute(
    ULONG   Unknown0,
    ULONG   Unknown1)
{
    UNIMPLEMENTED;
}

/* EOF */
