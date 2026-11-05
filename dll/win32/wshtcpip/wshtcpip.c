/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS WinSock Helper DLL for TCP/IP
 * FILE:        wshtcpip.c
 * PURPOSE:     DLL entry
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/09-2000 Created
 */
#include "wshtcpip.h"
#define NDEBUG
#include <debug.h>

BOOL
EXPORT
DllMain(HANDLE hInstDll,
        ULONG dwReason,
        PVOID Reserved)
{
    DPRINT("DllMain of wshtcpip.dll\n");

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        /* Don't need thread attach notifications
           so disable them to improve performance */
        DisableThreadLibraryCalls(hInstDll);
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


INT
EXPORT
WSHAddressToString(
    IN      LPSOCKADDR Address,
    IN      INT AddressLength,
    IN      LPWSAPROTOCOL_INFOW ProtocolInfo    OPTIONAL,
    OUT     LPWSTR AddressString,
    IN OUT  LPDWORD AddressStringLength)
{
    UNIMPLEMENTED;

    return NO_ERROR;
}


INT
EXPORT
WSHEnumProtocols(
    IN      LPINT lpiProtocols  OPTIONAL,
    IN      LPWSTR lpTransportKeyName,
    IN OUT  LPVOID lpProtocolBuffer,
    IN OUT  LPDWORD lpdwBufferLength)
{
    UNIMPLEMENTED;

    return NO_ERROR;
}


INT
EXPORT
WSHGetBroadcastSockaddr(
    IN  PVOID HelperDllSocketContext,
    OUT PSOCKADDR Sockaddr,
    OUT PINT SockaddrLength)
{
    INT Size = 2 * sizeof(UINT);

    if (*SockaddrLength < Size)
    {
        DPRINT1("Socket address length too small: %d\n", *SockaddrLength);
        return WSAEFAULT;
    }

    RtlZeroMemory(Sockaddr, *SockaddrLength);

    Sockaddr->sa_family = AF_INET;
    *((PUINT)Sockaddr->sa_data) = INADDR_BROADCAST;

    /* *SockaddrLength = Size; */

    return NO_ERROR;
}


INT
EXPORT
WSHGetProviderGuid(
    IN  LPWSTR ProviderName,
    OUT LPGUID ProviderGuid)
{
    UNIMPLEMENTED;

    return NO_ERROR;
}


/*
Document from OSR how WSHGetSockaddrType works
http://www.osronline.com/ddkx/network/37wshfun_5lyq.htm
*/

INT
EXPORT
WSHGetSockaddrType(
    IN  PSOCKADDR Sockaddr,
    IN  DWORD SockaddrLength,
    OUT PSOCKADDR_INFO SockaddrInfo)
{
    PSOCKADDR_IN ipv4 = (PSOCKADDR_IN)Sockaddr;

    if (!ipv4 || !SockaddrInfo || SockaddrLength < sizeof(SOCKADDR_IN) ||
        ipv4->sin_family != AF_INET)
    {
        DPRINT1("Invalid parameter: %x %x %d %u\n", ipv4, SockaddrInfo, SockaddrLength, (ipv4 ? ipv4->sin_family : 0));
        return WSAEINVAL;
    }

    switch (ntohl(ipv4->sin_addr.s_addr))
    {
      case INADDR_ANY:
           SockaddrInfo->AddressInfo = SockaddrAddressInfoWildcard;
           break;

      case INADDR_BROADCAST:
           SockaddrInfo->AddressInfo = SockaddrAddressInfoBroadcast;
           break;

      case INADDR_LOOPBACK:
           SockaddrInfo->AddressInfo = SockaddrAddressInfoLoopback;
           break;

      default:
           SockaddrInfo->AddressInfo = SockaddrAddressInfoNormal;
	   break;
    }

    if (ntohs(ipv4->sin_port) == 0)
 	SockaddrInfo->EndpointInfo = SockaddrEndpointInfoWildcard;
    else if (ntohs(ipv4->sin_port) < IPPORT_RESERVED)
	SockaddrInfo->EndpointInfo = SockaddrEndpointInfoReserved;
    else
        SockaddrInfo->EndpointInfo = SockaddrEndpointInfoNormal;

    return NO_ERROR;
}

/*
 * IP and UDP options that the TCP/IP driver has no interface for (or cannot read back) are kept with the
 * socket and answered from there, as Windows answers them (measured on Windows 10 22H2 for a datagram socket:
 * what was set is read back; an option that was not set reads as its default). IP_RECVECN and IP_ECN are the
 * same option (50). IP_MTU_DISCOVER takes 0 to 3, and IP_DONTFRAGMENT and IP_MTU_DISCOVER refuse to be
 * set once the other one is in use. The receive switches and the UDP options are refused on a stream socket.
 */
#define WSH_IP_RECVTOS          40
#define WSH_IP_RECVECN          50
#define WSH_IP_MTU_DISCOVER     71
#define WSH_UDP_SEND_MSG_SIZE   2
#define WSH_UDP_RECV_MAX_COALESCED_SIZE 3

#define WSH_SET_TTL     0x01
#define WSH_SET_TOS     0x02
#define WSH_SET_DF      0x04
#define WSH_SET_RECVTOS 0x08
#define WSH_SET_RECVECN 0x10
#define WSH_SET_MLOOP   0x20
#define WSH_SET_MTTL    0x40
#define WSH_SET_USENDSZ 0x80
#define WSH_SET_URECVSZ 0x100
#define WSH_SET_MTUD    0x200

/* Finds the kept value of an option; Boolean is TRUE when it is a switch, Default what an unset one reads */
static
PLONG
WshKeptOption(
    _In_ PSOCKET_CONTEXT Context,
    _In_ INT Level,
    _In_ INT OptionName,
    _Out_ PDWORD Bit,
    _Out_ PLONG Default,
    _Out_ PBOOLEAN Boolean)
{
    *Boolean = FALSE;
    *Default = 0;

    if (Level == IPPROTO_IP)
    {
        switch (OptionName)
        {
            case IP_TTL:            *Bit = WSH_SET_TTL; *Default = 128; return &Context->IpTtl;
            case IP_TOS:            *Bit = WSH_SET_TOS; return &Context->IpTos;
            case IP_DONTFRAGMENT:   *Bit = WSH_SET_DF; *Boolean = TRUE; return &Context->IpDontFragment;
            case WSH_IP_MTU_DISCOVER: *Bit = WSH_SET_MTUD; return &Context->IpMtuDiscover;
            case WSH_IP_RECVTOS:    *Bit = WSH_SET_RECVTOS; *Boolean = TRUE; return &Context->IpRecvTos;
            case WSH_IP_RECVECN:    *Bit = WSH_SET_RECVECN; *Boolean = TRUE; return &Context->IpRecvEcn;
            case IP_MULTICAST_LOOP: *Bit = WSH_SET_MLOOP; *Default = 1; *Boolean = TRUE; return &Context->IpMulticastLoop;
            case IP_MULTICAST_TTL:  *Bit = WSH_SET_MTTL; *Default = 1; return &Context->IpMulticastTtl;
            default: break;
        }
    }
    else if (Level == IPPROTO_UDP)
    {
        switch (OptionName)
        {
            case WSH_UDP_SEND_MSG_SIZE:           *Bit = WSH_SET_USENDSZ; return &Context->UdpSendMsgSize;
            case WSH_UDP_RECV_MAX_COALESCED_SIZE: *Bit = WSH_SET_URECVSZ; return &Context->UdpRecvMaxCoalescedSize;
            default: break;
        }
    }
    return NULL;
}

static
void
GetTdiTypeId(
    _In_ INT Level,
    _In_ INT OptionName,
    _Out_ PULONG TdiType,
    _Out_ PULONG TdiId)
{
    switch (Level)
    {
       case SOL_SOCKET:
          *TdiType = INFO_TYPE_CONNECTION;
          switch (OptionName)
          {
             case SO_KEEPALIVE:
                *TdiId = TCP_SOCKET_KEEPALIVE;
                return;
             default:
                break;
          }
          break;

       case IPPROTO_IP:
          *TdiType = INFO_TYPE_ADDRESS_OBJECT;
          switch (OptionName)
          {
             case IP_TTL:
                *TdiId = AO_OPTION_TTL;
                return;

             case IP_DONTFRAGMENT:
                 *TdiId = AO_OPTION_IP_DONTFRAGMENT;
                 return;

#if 0
             case IP_RECEIVE_BROADCAST:
                 *TdiId = AO_OPTION_BROADCAST;
                 return;
#endif

             case IP_HDRINCL:
                 *TdiId = AO_OPTION_IP_HDRINCL;
                 return;

             default:
                break;
          }
          break;

       case IPPROTO_TCP:
          *TdiType = INFO_TYPE_CONNECTION;
          switch (OptionName)
          {
             case TCP_NODELAY:
                 *TdiId = TCP_SOCKET_NODELAY;
                 return;
             default:
                 break;
          }

       default:
          break;
    }

    DPRINT1("Unknown level/option name: %d %d\n", Level, OptionName);
    *TdiType = 0;
    *TdiId = 0;
}

INT
EXPORT
WSHGetSocketInformation(
    IN  PVOID HelperDllSocketContext,
    IN  SOCKET SocketHandle,
    IN  HANDLE TdiAddressObjectHandle,
    IN  HANDLE TdiConnectionObjectHandle,
    IN  INT Level,
    IN  INT OptionName,
    OUT PCHAR OptionValue,
    OUT LPINT OptionLength)
{
    PSOCKET_CONTEXT Context = HelperDllSocketContext;
    PLONG Kept;
    DWORD Bit;
    LONG Default, Value;
    BOOLEAN Boolean;

    if (Context && (Level == IPPROTO_IP || Level == IPPROTO_UDP))
    {
        Kept = WshKeptOption(Context, Level, OptionName, &Bit, &Default, &Boolean);
        if (!Kept)
            goto Unknown;

        /* The datagram only options are invalid on a stream */
        if (Context->SocketType != SOCK_DGRAM && Context->SocketType != SOCK_RAW &&
            (Level == IPPROTO_UDP || OptionName == WSH_IP_RECVTOS || OptionName == WSH_IP_RECVECN))
            return WSAEINVAL;

        if (!OptionLength || !OptionValue || *OptionLength < (INT)sizeof(CHAR))
        {
            if (OptionLength) *OptionLength = sizeof(LONG);
            return WSAEFAULT;
        }

        Value = (Context->OptionsSet & Bit) ? *Kept : Default;
        if (*OptionLength >= (INT)sizeof(LONG))
        {
            *(PLONG)OptionValue = Value;
            *OptionLength = sizeof(LONG);
        }
        else
        {
            /* Less than four bytes: the low byte */
            *(PUCHAR)OptionValue = (UCHAR)Value;
            *OptionLength = sizeof(UCHAR);
        }
        return NO_ERROR;
    }

Unknown:
    DPRINT1("Get: Unknown level/option name: %d %d\n", Level, OptionName);

    /* Not an option of this protocol: IP says so, UDP finds the request invalid */
    if (OptionLength) *OptionLength = 0;

    return (Level == IPPROTO_UDP) ? WSAEINVAL : WSAENOPROTOOPT;
}


INT
EXPORT
WSHGetWildcardSockaddr(
    IN  PVOID HelperDllSocketContext,
    OUT PSOCKADDR Sockaddr,
    OUT PINT SockaddrLength)
{
    INT Size = 2 * sizeof(UINT);

    if (*SockaddrLength < Size)
    {
        DPRINT1("Socket address length too small: %d\n", *SockaddrLength);
        return WSAEFAULT;
    }

    RtlZeroMemory(Sockaddr, *SockaddrLength);

    Sockaddr->sa_family = AF_INET;
    *((PUINT)Sockaddr->sa_data) = INADDR_ANY;

    /* *SockaddrLength = Size; */

    return NO_ERROR;
}


DWORD
EXPORT
WSHGetWinsockMapping(
    OUT PWINSOCK_MAPPING Mapping,
    IN  DWORD MappingLength)
{
    DWORD Rows = 6;
    DWORD Columns = 3;
    DWORD Size = 2 * sizeof(DWORD) + Columns * Rows * sizeof(DWORD);

    if (MappingLength < Size)
    {
        DPRINT1("Mapping length too small: %d\n", MappingLength);
        return Size;
    }

    Mapping->Rows = Rows;
    Mapping->Columns = Columns;

    Mapping->Mapping[0].AddressFamily = AF_INET;
    Mapping->Mapping[0].SocketType = SOCK_STREAM;
    Mapping->Mapping[0].Protocol = 0;

    Mapping->Mapping[1].AddressFamily = AF_INET;
    Mapping->Mapping[1].SocketType = SOCK_STREAM;
    Mapping->Mapping[1].Protocol = IPPROTO_TCP;

    Mapping->Mapping[2].AddressFamily = AF_INET;
    Mapping->Mapping[2].SocketType = SOCK_DGRAM;
    Mapping->Mapping[2].Protocol = 0;

    Mapping->Mapping[3].AddressFamily = AF_INET;
    Mapping->Mapping[3].SocketType = SOCK_DGRAM;
    Mapping->Mapping[3].Protocol = IPPROTO_UDP;

    Mapping->Mapping[4].AddressFamily = AF_INET;
    Mapping->Mapping[4].SocketType = SOCK_RAW;
    Mapping->Mapping[4].Protocol = 0;

    Mapping->Mapping[5].AddressFamily = AF_INET;
    Mapping->Mapping[5].SocketType = SOCK_RAW;
    Mapping->Mapping[5].Protocol = IPPROTO_ICMP;

    return NO_ERROR;
}


INT
EXPORT
WSHGetWSAProtocolInfo(
    IN  LPWSTR ProviderName,
    OUT LPWSAPROTOCOL_INFOW *ProtocolInfo,
    OUT LPDWORD ProtocolInfoEntries)
{
    UNIMPLEMENTED;

    return NO_ERROR;
}


INT
EXPORT
WSHIoctl(
    IN  PVOID HelperDllSocketContext,
    IN  SOCKET SocketHandle,
    IN  HANDLE TdiAddressObjectHandle,
    IN  HANDLE TdiConnectionObjectHandle,
    IN  DWORD IoControlCode,
    IN  LPVOID InputBuffer,
    IN  DWORD InputBufferLength,
    IN  LPVOID OutputBuffer,
    IN  DWORD OutputBufferLength,
    OUT LPDWORD NumberOfBytesReturned,
    IN  LPWSAOVERLAPPED Overlapped,
    IN  LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine,
    OUT LPBOOL NeedsCompletion)
{
    INT res;
    PSOCKET_CONTEXT Context = HelperDllSocketContext;
    PTCP_REQUEST_SET_INFORMATION_EX Info;
    PQUEUED_REQUEST Queued, NextQueued;

    if (IoControlCode == SIO_GET_INTERFACE_LIST)
    {
        res = WSHIoctl_GetInterfaceList(
            OutputBuffer,
            OutputBufferLength,
            NumberOfBytesReturned,
            NeedsCompletion);
        return res;
    }
    else if (IoControlCode == SIO_KEEPALIVE_VALS)
    {
        if (!InputBuffer || InputBufferLength != sizeof(struct tcp_keepalive))
        {
            return WSAEINVAL;
        }

        Info = HeapAlloc(GetProcessHeap(), 0, sizeof(*Info) + InputBufferLength);
        if (!Info)
            return WSAENOBUFS;

        Info->ID.toi_entity.tei_entity = Context->AddrFileEntityType;
        Info->ID.toi_entity.tei_instance = Context->AddrFileInstance;
        Info->ID.toi_class = INFO_CLASS_PROTOCOL;
        Info->ID.toi_type = INFO_TYPE_CONNECTION;
        Info->ID.toi_id = TCP_SOCKET_KEEPALIVEVALS;
        Info->BufferSize = InputBufferLength;
        memcpy(Info->Buffer, InputBuffer, InputBufferLength);

        if (Context->SocketState == SocketStateCreated)
        {
            if (Context->RequestQueue)
            {
                Queued = Context->RequestQueue;
                while ((NextQueued = Queued->Next))
                {
                    Queued = NextQueued;
                }

                Queued->Next = HeapAlloc(GetProcessHeap(), 0, sizeof(QUEUED_REQUEST));
                if (!Queued->Next)
                {
                    HeapFree(GetProcessHeap(), 0, Info);
                    return WSAENOBUFS;
                }

                NextQueued = Queued->Next;
                NextQueued->Next = NULL;
                NextQueued->Info = Info;
            }
            else
            {
                Context->RequestQueue = HeapAlloc(GetProcessHeap(), 0, sizeof(QUEUED_REQUEST));
                if (!Context->RequestQueue)
                {
                    HeapFree(GetProcessHeap(), 0, Info);
                    return WSAENOBUFS;
                }

                Context->RequestQueue->Next = NULL;
                Context->RequestQueue->Info = Info;
            }

            return 0;
        }

        res = SendRequest(Info, sizeof(*Info) + Info->BufferSize, IOCTL_TCP_SET_INFORMATION_EX);

        HeapFree(GetProcessHeap(), 0, Info);
        return res;
    }

    UNIMPLEMENTED;

    DPRINT1("Ioctl: Unknown IOCTL code: %x\n", IoControlCode);

    return WSAEINVAL;
}


INT
EXPORT
WSHJoinLeaf(
    IN  PVOID HelperDllSocketContext,
    IN  SOCKET SocketHandle,
    IN  HANDLE TdiAddressObjectHandle,
    IN  HANDLE TdiConnectionObjectHandle,
    IN  PVOID LeafHelperDllSocketContext,
    IN  SOCKET LeafSocketHandle,
    IN  PSOCKADDR Sockaddr,
    IN  DWORD SockaddrLength,
    IN  LPWSABUF CallerData,
    IN  LPWSABUF CalleeData,
    IN  LPQOS SocketQOS,
    IN  LPQOS GroupQOS,
    IN  DWORD Flags)
{
    UNIMPLEMENTED;

    return NO_ERROR;
}

INT
SendRequest(
    IN PVOID Request,
    IN DWORD RequestSize,
    IN DWORD IOCTL)
{
    BOOLEAN Success;
    HANDLE TcpCC;
    DWORD BytesReturned;

    if (openTcpFile(&TcpCC, FILE_READ_DATA | FILE_WRITE_DATA) != STATUS_SUCCESS)
        return WSAEINVAL;

    Success = DeviceIoControl(TcpCC,
                              IOCTL,
                              Request,
                              RequestSize,
                              NULL,
                              0,
                              &BytesReturned,
                              NULL);

    closeTcpFile(TcpCC);

    DPRINT("DeviceIoControl: %ld\n", (Success ? NO_ERROR : GetLastError()));

    if (!Success)
        return WSAEINVAL;

    return NO_ERROR;
}

INT
EXPORT
WSHNotify(
    IN  PVOID HelperDllSocketContext,
    IN  SOCKET SocketHandle,
    IN  HANDLE TdiAddressObjectHandle,
    IN  HANDLE TdiConnectionObjectHandle,
    IN  DWORD NotifyEvent)
{
    PSOCKET_CONTEXT Context = HelperDllSocketContext;
    NTSTATUS Status;
    HANDLE TcpCC;
    TDIEntityID *EntityIDs;
    DWORD EntityCount, i;
    PQUEUED_REQUEST QueuedRequest, NextQueuedRequest;

    switch (NotifyEvent)
    {
        case WSH_NOTIFY_CLOSE:
            DPRINT("WSHNotify: WSH_NOTIFY_CLOSE\n");
            QueuedRequest = Context->RequestQueue;
            while (QueuedRequest)
            {
                NextQueuedRequest = QueuedRequest->Next;

                HeapFree(GetProcessHeap(), 0, QueuedRequest->Info);
                HeapFree(GetProcessHeap(), 0, QueuedRequest);

                QueuedRequest = NextQueuedRequest;
            }
            HeapFree(GetProcessHeap(), 0, HelperDllSocketContext);
            break;


        case WSH_NOTIFY_BIND:
            DPRINT("WSHNotify: WSH_NOTIFY_BIND\n");
            Status = openTcpFile(&TcpCC, FILE_READ_DATA);
            if (Status != STATUS_SUCCESS)
                return WSAEINVAL;

            Status = tdiGetEntityIDSet(TcpCC,
                                       &EntityIDs,
                                       &EntityCount);

            closeTcpFile(TcpCC);

            if (Status != STATUS_SUCCESS)
                return WSAEINVAL;

            for (i = 0; i < EntityCount; i++)
            {
                if (EntityIDs[i].tei_entity == CO_TL_ENTITY ||
                    EntityIDs[i].tei_entity == CL_TL_ENTITY ||
                    EntityIDs[i].tei_entity == ER_ENTITY)
                {
                    Context->AddrFileInstance = EntityIDs[i].tei_instance;
                    Context->AddrFileEntityType = EntityIDs[i].tei_entity;
                }
            }

            DPRINT("Instance: %lx Type: %lx\n", Context->AddrFileInstance, Context->AddrFileEntityType);

            tdiFreeThingSet(EntityIDs);

            Context->SocketState = SocketStateBound;

            QueuedRequest = Context->RequestQueue;
            while (QueuedRequest)
            {
                QueuedRequest->Info->ID.toi_entity.tei_entity = Context->AddrFileEntityType;
                QueuedRequest->Info->ID.toi_entity.tei_instance = Context->AddrFileInstance;

                SendRequest(QueuedRequest->Info,
                            sizeof(*QueuedRequest->Info) + QueuedRequest->Info->BufferSize,
                            IOCTL_TCP_SET_INFORMATION_EX);

                NextQueuedRequest = QueuedRequest->Next;

                HeapFree(GetProcessHeap(), 0, QueuedRequest->Info);
                HeapFree(GetProcessHeap(), 0, QueuedRequest);

                QueuedRequest = NextQueuedRequest;
            }
            Context->RequestQueue = NULL;
            break;

        default:
            DPRINT1("Unwanted notification received! (%ld)\n", NotifyEvent);
            break;
    }

    return NO_ERROR;
}


INT
EXPORT
WSHOpenSocket(
    IN OUT  PINT AddressFamily,
    IN OUT  PINT SocketType,
    IN OUT  PINT Protocol,
    OUT     PUNICODE_STRING TransportDeviceName,
    OUT     PVOID HelperDllSocketContext,
    OUT     PDWORD NotificationEvents)
/*
 * FUNCTION: Opens a socket
 */
{
    return WSHOpenSocket2(AddressFamily,
                          SocketType,
                          Protocol,
                          0,
                          0,
                          TransportDeviceName,
                          HelperDllSocketContext,
                          NotificationEvents);
}


INT
EXPORT
WSHOpenSocket2(
    OUT PINT AddressFamily,
    IN  OUT PINT SocketType,
    IN  OUT PINT Protocol,
    IN  GROUP Group,
    IN  DWORD Flags,
    OUT PUNICODE_STRING TransportDeviceName,
    OUT PVOID *HelperDllSocketContext,
    OUT PDWORD NotificationEvents)
/*
 * FUNCTION: Opens a socket
 * ARGUMENTS:
 *     AddressFamily          = Address of buffer with address family (updated)
 *     SocketType             = Address of buffer with type of socket (updated)
 *     Protocol               = Address of buffer with protocol number (updated)
 *     Group                  = Socket group
 *     Flags                  = Socket flags
 *     TransportDeviceName    = Address of buffer to place name of transport device
 *     HelperDllSocketContext = Address of buffer to place socket context pointer
 *     NotificationEvents     = Address of buffer to place flags for event notification
 * RETURNS:
 *     Status of operation
 * NOTES:
 *     Mapping tripple is returned in an canonicalized form
 */
{
    PSOCKET_CONTEXT Context;
    UNICODE_STRING String;
    UNICODE_STRING TcpDeviceName = RTL_CONSTANT_STRING(DD_TCP_DEVICE_NAME);
    UNICODE_STRING UdpDeviceName = RTL_CONSTANT_STRING(DD_UDP_DEVICE_NAME);
    UNICODE_STRING RawDeviceName = RTL_CONSTANT_STRING(DD_RAW_IP_DEVICE_NAME);

    DPRINT("WSHOpenSocket2 called\n");

    switch (*SocketType) {
    case SOCK_STREAM:
        String = TcpDeviceName;
        break;

    case SOCK_DGRAM:
        String = UdpDeviceName;
        break;

    case SOCK_RAW:
        if ((*Protocol < 0) || (*Protocol > 255))
          return WSAEINVAL;

        String = RawDeviceName;
        break;

    default:
        return WSAEINVAL;
    }

    RtlInitUnicodeString(TransportDeviceName, NULL);

    TransportDeviceName->MaximumLength = String.Length +        /* Transport device name */
                                         (4 * sizeof(WCHAR) +   /* Separator and protocol */
                                         sizeof(UNICODE_NULL)); /* Terminating null */

    TransportDeviceName->Buffer = HeapAlloc(
        GetProcessHeap(),
        0,
        TransportDeviceName->MaximumLength);

    if (!TransportDeviceName->Buffer)
        return WSAENOBUFS;

    /* Append the transport device name */
    RtlAppendUnicodeStringToString(TransportDeviceName, &String);

    if (*SocketType == SOCK_RAW) {
        /* Append a separator */
        TransportDeviceName->Buffer[TransportDeviceName->Length / sizeof(WCHAR)] = OBJ_NAME_PATH_SEPARATOR;
        TransportDeviceName->Length += sizeof(WCHAR);
        TransportDeviceName->Buffer[TransportDeviceName->Length / sizeof(WCHAR)] = UNICODE_NULL;

        /* Append the protocol number */
        String.Buffer = TransportDeviceName->Buffer + (TransportDeviceName->Length / sizeof(WCHAR));
        String.Length = 0;
        String.MaximumLength = TransportDeviceName->MaximumLength - TransportDeviceName->Length;

        RtlIntegerToUnicodeString((ULONG)*Protocol, 10, &String);

        TransportDeviceName->Length += String.Length;
    }

    /* Setup a socket context area */

    Context = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SOCKET_CONTEXT));
    if (!Context) {
        RtlFreeUnicodeString(TransportDeviceName);
        return WSAENOBUFS;
    }

    Context->AddressFamily = *AddressFamily;
    Context->SocketType    = *SocketType;
    Context->Protocol      = *Protocol;
    Context->Flags         = Flags;
    Context->SocketState   = SocketStateCreated;

    *HelperDllSocketContext = Context;
    *NotificationEvents = WSH_NOTIFY_CLOSE | WSH_NOTIFY_BIND;

    return NO_ERROR;
}

INT
EXPORT
WSHSetSocketInformation(
    IN  PVOID HelperDllSocketContext,
    IN  SOCKET SocketHandle,
    IN  HANDLE TdiAddressObjectHandle,
    IN  HANDLE TdiConnectionObjectHandle,
    IN  INT Level,
    IN  INT OptionName,
    IN  PCHAR OptionValue,
    IN  INT OptionLength)
{
    PSOCKET_CONTEXT Context = HelperDllSocketContext;
    ULONG TdiType, TdiId;
    INT Status;
    PTCP_REQUEST_SET_INFORMATION_EX Info;
    PQUEUED_REQUEST Queued, NextQueued;

    DPRINT("WSHSetSocketInformation\n");

    /* FIXME: We only handle address file object here */

    switch (Level)
    {
        case SOL_SOCKET:
            switch (OptionName)
            {
                case SO_DONTROUTE:
                    if (OptionLength < sizeof(BOOL))
                    {
                        return WSAEFAULT;
                    }
                    Context->DontRoute = *(BOOL*)OptionValue;
                    /* This is silently ignored on Windows */
                    return 0;

                case SO_KEEPALIVE:
                    if (OptionLength < sizeof(DWORD))
                    {
                        return WSAEFAULT;
                    }
                    break;

                default:
                    /* Invalid option */
                    DPRINT1("Set: Received unexpected SOL_SOCKET option %d\n", OptionName);
                    return WSAENOPROTOOPT;
            }
            break;

        case IPPROTO_IP:
            if (OptionName != IP_HDRINCL)
            {
                PLONG Kept;
                DWORD Bit;
                LONG Default, Value;
                BOOLEAN Boolean;

                Kept = WshKeptOption(Context, Level, OptionName, &Bit, &Default, &Boolean);
                if (Kept)
                {
                    if (!OptionValue || OptionLength < (INT)sizeof(CHAR))
                        return WSAEFAULT;

                    /* The receive switches are for datagrams */
                    if (Context->SocketType != SOCK_DGRAM && Context->SocketType != SOCK_RAW &&
                        (OptionName == WSH_IP_RECVTOS || OptionName == WSH_IP_RECVECN))
                        return WSAEINVAL;

                    Value = (OptionLength >= (INT)sizeof(LONG)) ? *(PLONG)OptionValue : *(PUCHAR)OptionValue;
                    if (Boolean)
                        Value = (Value != 0);

                    switch (OptionName)
                    {
                        case IP_TTL:
                            /* A byte; -1 changes nothing */
                            if (Value == -1)
                                return NO_ERROR;
                            /* fall through */
                        case IP_TOS:
                            if (Value < 0 || Value > 255)
                                return WSAEINVAL;
                            break;

                        case WSH_IP_MTU_DISCOVER:
                            if (Value < 0 || Value > 3)
                                return WSAEINVAL;
                            /* Not once IP_DONTFRAGMENT is in use */
                            if (Value != 0 && (Context->OptionsSet & WSH_SET_DF) && Context->IpDontFragment)
                                return WSAEINVAL;
                            break;

                        case IP_DONTFRAGMENT:
                            /* Not once IP_MTU_DISCOVER is in use */
                            if ((Context->OptionsSet & WSH_SET_MTUD) && Context->IpMtuDiscover)
                                return WSAEINVAL;
                            break;

                        default:
                            break;
                    }

                    *Kept = Value;
                    Context->OptionsSet |= Bit;

                    /* Only these two have an effect in the driver */
                    if (OptionName != IP_TTL && OptionName != IP_DONTFRAGMENT)
                        return NO_ERROR;
                }
            }

            switch (OptionName)
            {
                case IP_TTL:
                case IP_DONTFRAGMENT:
                case IP_HDRINCL:
                    /* Send these to TCPIP */
                    break;

                default:
                    /* Invalid option -- FIXME */
                    DPRINT1("Set: Received unsupported IPPROTO_IP option %d\n", OptionName);
                    return 0;
            }
            break;

        case IPPROTO_TCP:
            switch (OptionName)
            {
                case TCP_NODELAY:
                    if (OptionLength < sizeof(CHAR))
                    {
                        return WSAEFAULT;
                    }
                    break;

                default:
                    /* Invalid option */
                    DPRINT1("Set: Received unexpected IPPROTO_TCP option %d\n", OptionName);
                    return 0;
            }
            break;

        case IPPROTO_UDP:
        {
            PLONG Kept;
            DWORD Bit;
            LONG Default;
            BOOLEAN Boolean;

            Kept = WshKeptOption(Context, Level, OptionName, &Bit, &Default, &Boolean);
            if (!Kept)
            {
                DPRINT1("Set: Received unexpected IPPROTO_UDP option %d\n", OptionName);
                return 0;
            }
            /* Datagrams only, and a whole DWORD */
            if (Context->SocketType != SOCK_DGRAM && Context->SocketType != SOCK_RAW)
                return WSAEINVAL;
            if (!OptionValue || OptionLength < (INT)sizeof(LONG))
                return WSAEFAULT;
            *Kept = *(PLONG)OptionValue;
            Context->OptionsSet |= Bit;
            return NO_ERROR;
        }

        default:
            DPRINT1("Set: Received unexpected %d option %d\n", Level, OptionName);
            return 0;
    }

    /* If we get here, GetAddressOption must return something valid */
    GetTdiTypeId(Level, OptionName, &TdiType, &TdiId);
    ASSERT((TdiId != 0) && (TdiType != 0));

    Info = HeapAlloc(GetProcessHeap(), 0, sizeof(*Info) + OptionLength);
    if (!Info)
        return WSAENOBUFS;

    Info->ID.toi_entity.tei_entity = Context->AddrFileEntityType;
    Info->ID.toi_entity.tei_instance = Context->AddrFileInstance;
    Info->ID.toi_class = INFO_CLASS_PROTOCOL;
    Info->ID.toi_type = TdiType;
    Info->ID.toi_id = TdiId;
    Info->BufferSize = OptionLength;
    memcpy(Info->Buffer, OptionValue, OptionLength);

    if (Context->SocketState == SocketStateCreated)
    {
        if (Context->RequestQueue)
        {
            Queued = Context->RequestQueue;
            while ((NextQueued = Queued->Next))
            {
               Queued = NextQueued;
            }

            Queued->Next = HeapAlloc(GetProcessHeap(), 0, sizeof(QUEUED_REQUEST));
            if (!Queued->Next)
            {
                HeapFree(GetProcessHeap(), 0, Info);
                return WSAENOBUFS;
            }

            NextQueued = Queued->Next;
            NextQueued->Next = NULL;
            NextQueued->Info = Info;
        }
        else
        {
            Context->RequestQueue = HeapAlloc(GetProcessHeap(), 0, sizeof(QUEUED_REQUEST));
            if (!Context->RequestQueue)
            {
                HeapFree(GetProcessHeap(), 0, Info);
                return WSAENOBUFS;
            }

            Context->RequestQueue->Next = NULL;
            Context->RequestQueue->Info = Info;
        }

        return 0;
    }

    Status = SendRequest(Info, sizeof(*Info) + Info->BufferSize, IOCTL_TCP_SET_INFORMATION_EX);

    HeapFree(GetProcessHeap(), 0, Info);

    return Status;
}


INT
EXPORT
WSHStringToAddress(
    IN      LPWSTR AddressString,
    IN      DWORD AddressFamily,
    IN      LPWSAPROTOCOL_INFOW ProtocolInfo    OPTIONAL,
    OUT     LPSOCKADDR Address,
    IN OUT  LPDWORD AddressStringLength)
{
    UNIMPLEMENTED;

    return NO_ERROR;
}

/* EOF */
