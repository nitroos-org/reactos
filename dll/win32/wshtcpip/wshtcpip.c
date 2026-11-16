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

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif
#ifndef IPV6_UNICAST_HOPS
#define IPV6_UNICAST_HOPS 4
#endif
#ifndef IPV6_MULTICAST_HOPS
#define IPV6_MULTICAST_HOPS 10
#endif
#ifndef IPV6_MULTICAST_LOOP
#define IPV6_MULTICAST_LOOP 11
#endif
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#ifndef IPV6_MULTICAST_IF
#define IPV6_MULTICAST_IF 9
#endif
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP 12
#endif
#ifndef IPV6_DROP_MEMBERSHIP
#define IPV6_DROP_MEMBERSHIP 13
#endif
/* struct ipv6_mreq: the group (16 bytes), then the interface index */
#define WSH_IPV6_MREQ_LENGTH 20

/* The socket address of an AF_INET6 socket: SOCKADDR_IN6 with the scope id (what the stack expects) */
#define WSH_SOCKADDR_IN6_LENGTH 28
C_ASSERT(sizeof(SOCKADDR_IN6_LH) == WSH_SOCKADDR_IN6_LENGTH);

/* Not in every SDK header of this tree */
#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER   71
#endif

/*
 * An AF_INET6 socket is made only while the stack says it has IPv6 on (Tcpip\Parameters\Ipv6Enable, read by
 * tcpip.sys when it starts) and takes IPv6 addresses for its sockets (TCP_IPV6_STATE_SOCKETS of its
 * IP_IPV6_TABLE_ENTRY_ID answer): otherwise WSAEAFNOSUPPORT, what an IPv6 socket has always got here. The stack
 * is the only source: no registry value is read here. Its answer cannot change while the system runs, so a
 * definite one is kept for the process; a stack that cannot be asked counts as "no IPv6" and is asked again.
 */
static volatile LONG WshIpv6State; /* 0 not known yet, 1 on, 2 off */

static
BOOLEAN
WshIpv6Enabled(VOID)
{
    LONG State = WshIpv6State;
    HANDLE TcpFile;
    ULONG Flags;
    NTSTATUS Status;

    if (State != 0)
        return State == 1;

    if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
        return FALSE;
    Status = tdiQueryIpv6StackState(TcpFile, &Flags);
    closeTcpFile(TcpFile);
    /* a query that failed is not an answer: nothing is kept, the next socket asks again */
    if (!NT_SUCCESS(Status))
        return FALSE;

    State = ((Flags & TCP_IPV6_STATE_ON) && (Flags & TCP_IPV6_STATE_SOCKETS)) ? 1 : 2;
    InterlockedExchange(&WshIpv6State, State);
    return State == 1;
}

/*
 * Once the stack has IPv6 sockets, the socket types other than stream need their own flag of its answer: a datagram
 * socket TCP_IPV6_STATE_DATAGRAMS, a raw one TCP_IPV6_STATE_RAW (WSAEAFNOSUPPORT without it, as before the stack took
 * them). Kept for the process as WshIpv6Enabled keeps its answer; asked again while the stack cannot be asked.
 */
static volatile LONG WshIpv6TypeFlags = -1;

static
BOOLEAN
WshIpv6TypeEnabled(
    _In_ INT SocketType)
{
    LONG Flags = WshIpv6TypeFlags;
    HANDLE TcpFile;

    if (SocketType == SOCK_STREAM)
        return TRUE;

    if (Flags == -1)
    {
        if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
            return FALSE;
        Flags = (LONG)tdiGetIpv6StackState(TcpFile);
        closeTcpFile(TcpFile);
        if (Flags & TCP_IPV6_STATE_ON)
            InterlockedExchange(&WshIpv6TypeFlags, Flags);
    }

    if (SocketType == SOCK_DGRAM)
        return (Flags & TCP_IPV6_STATE_DATAGRAMS) != 0;
    return (Flags & TCP_IPV6_STATE_RAW) != 0;
}

/* IPv6 addresses: the unspecified one, ::1 and the IPv4 mapped ones */
static
BOOLEAN
WshIsV6Any(const UCHAR *Address)
{
    ULONG i;

    for (i = 0; i < 16; i++)
    {
        if (Address[i] != 0)
            return FALSE;
    }
    return TRUE;
}

static
BOOLEAN
WshIsV6Loopback(const UCHAR *Address)
{
    ULONG i;

    for (i = 0; i < 15; i++)
    {
        if (Address[i] != 0)
            return FALSE;
    }
    return Address[15] == 1;
}

static
BOOLEAN
WshIsV6V4Mapped(const UCHAR *Address)
{
    ULONG i;

    for (i = 0; i < 10; i++)
    {
        if (Address[i] != 0)
            return FALSE;
    }
    return Address[10] == 0xff && Address[11] == 0xff;
}

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
    PSOCKET_CONTEXT Context = HelperDllSocketContext;

    /* There is no broadcast address in IPv6 (VERIFY ON ORACLE: the error Windows gives) */
    if (Context && Context->AddressFamily == AF_INET6)
        return WSAEOPNOTSUPP;

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

    /* An IPv6 socket address: it has to be a whole SOCKADDR_IN6 (the scope id is part of it) */
    if (Sockaddr && SockaddrInfo && SockaddrLength >= sizeof(USHORT) && Sockaddr->sa_family == AF_INET6)
    {
        const SOCKADDR_IN6_LH *ipv6 = (const SOCKADDR_IN6_LH *)Sockaddr;
        const UCHAR *Address = (const UCHAR *)&ipv6->sin6_addr;
        USHORT Port = ntohs(ipv6->sin6_port);

        if (SockaddrLength < WSH_SOCKADDR_IN6_LENGTH)
        {
            DPRINT1("Invalid IPv6 socket address length: %u\n", SockaddrLength);
            return WSAEINVAL;
        }

        if (WshIsV6Any(Address))
            SockaddrInfo->AddressInfo = SockaddrAddressInfoWildcard;
        else if (WshIsV6Loopback(Address))
            SockaddrInfo->AddressInfo = SockaddrAddressInfoLoopback;
        else if (WshIsV6V4Mapped(Address))
        {
            /* An IPv4 address on an IPv6 socket: the kind of the IPv4 address (VERIFY ON ORACLE).
             * Broadcast is not a thing there, the socket option for it is IPv4 only. */
            ULONG V4 = ntohl(*(const UNALIGNED ULONG *)(Address + 12));

            if (V4 == INADDR_ANY)
                SockaddrInfo->AddressInfo = SockaddrAddressInfoWildcard;
            else if ((V4 >> 24) == 127)
                SockaddrInfo->AddressInfo = SockaddrAddressInfoLoopback;
            else
                SockaddrInfo->AddressInfo = SockaddrAddressInfoNormal;
        }
        else
            SockaddrInfo->AddressInfo = SockaddrAddressInfoNormal;

        if (Port == 0)
            SockaddrInfo->EndpointInfo = SockaddrEndpointInfoWildcard;
        else if (Port < IPPORT_RESERVED)
            SockaddrInfo->EndpointInfo = SockaddrEndpointInfoReserved;
        else
            SockaddrInfo->EndpointInfo = SockaddrEndpointInfoNormal;

        return NO_ERROR;
    }

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

/* The socket type an IPPROTO_IPV6 option needs, as Windows answers it: WSAEINVAL (get and set) otherwise */
static
BOOLEAN
WshIpv6OptionFitsType(
    _In_ PSOCKET_CONTEXT Context,
    _In_ INT OptionName)
{
    switch (OptionName)
    {
        case IPV6_HDRINCL:
            return Context->SocketType == SOCK_RAW;
        case IPV6_RECVTCLASS:
        case IPV6_RECVIF:
            return Context->SocketType == SOCK_DGRAM || Context->SocketType == SOCK_RAW;
        default:
            return TRUE;
    }
}

/*
 * Whether the caller may use the header-include option of a raw socket: Windows answers WSAEACCES at setsockopt to
 * anybody but Administrators, LocalSystem, LocalService and NetworkService (evidence v6raw-20261116). The stack
 * holds the rule for every request that reaches it (tcpip.sys, by the socket's opener); this gives the error at once
 * for a socket that is not bound yet (whose option waits for the bind).
 */
static
BOOLEAN
WshRawPrivileged(VOID)
{
    static const ULONG Rids[][2] = { { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS },
                                     { SECURITY_LOCAL_SYSTEM_RID, 0 },
                                     { SECURITY_LOCAL_SERVICE_RID, 0 },
                                     { SECURITY_NETWORK_SERVICE_RID, 0 } };
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    BOOL Member;
    PSID Sid;
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Rids); i++)
    {
        if (!AllocateAndInitializeSid(&Nt, Rids[i][1] ? 2 : 1, Rids[i][0], Rids[i][1], 0, 0, 0, 0, 0, 0, &Sid))
            continue;
        Member = FALSE;
        if (!CheckTokenMembership(NULL, Sid, &Member))
            Member = FALSE;
        FreeSid(Sid);
        if (Member)
            return TRUE;
    }
    return FALSE;
}

/* An interface index this machine has (IPV6_UNICAST_IF: WSAEINVAL for another, as on Windows) */
static
BOOLEAN
WshInterfaceExists(
    _In_ ULONG Index)
{
    typedef PCHAR (WINAPI *PIF_INDEXTONAME)(ULONG, PCHAR);
    static PIF_INDEXTONAME IndexToName;
    CHAR Name[260];

    if (!IndexToName)
    {
        HMODULE Iphlpapi = LoadLibraryW(L"iphlpapi.dll");

        if (Iphlpapi)
            IndexToName = (PIF_INDEXTONAME)GetProcAddress(Iphlpapi, "if_indextoname");
        if (!IndexToName)
            return TRUE;    /* cannot tell: taken */
    }
    return IndexToName(Index, Name) != NULL;
}

/*
 * The IPPROTO_IPV6 options of an AF_INET6 socket, kept with the socket (a datagram socket's hop limits, multicast
 * loop and interface also go to the stack; IPV6_V6ONLY and the others do not reach it): what was set reads back, an
 * option that was not set reads as its default. Windows 10 (oracle, datagram socket): IPV6_V6ONLY 1, unicast hops
 * 128, multicast hops 1, multicast loop 1, multicast interface 0, don't fragment 0 (IPV6_DONTFRAG: the stack does
 * not act on it yet).
 */
static
PLONG
WshKeptIpv6Option(
    _In_ PSOCKET_CONTEXT Context,
    _In_ INT OptionName,
    _Out_ PDWORD Bit,
    _Out_ PLONG Default,
    _Out_ PBOOLEAN Boolean)
{
    *Boolean = FALSE;
    *Default = 0;

    switch (OptionName)
    {
        case IPV6_V6ONLY:        *Bit = WSH_SET6_V6ONLY; *Default = 1; *Boolean = TRUE; return &Context->Ipv6V6Only;
        case IPV6_UNICAST_HOPS:  *Bit = WSH_SET6_UNIHOPS; *Default = 128; return &Context->Ipv6UnicastHops;
        case IPV6_MULTICAST_HOPS: *Bit = WSH_SET6_MCASTHOPS; *Default = 1; return &Context->Ipv6MulticastHops;
        case IPV6_MULTICAST_LOOP: *Bit = WSH_SET6_MCASTLOOP; *Default = 1; *Boolean = TRUE; return &Context->Ipv6MulticastLoop;
        case IPV6_DONTFRAG:      *Bit = WSH_SET6_DONTFRAG; *Boolean = TRUE; return &Context->Ipv6DontFragment;
        case IPV6_MULTICAST_IF:  *Bit = WSH_SET6_MCASTIF; return &Context->Ipv6MulticastIf;
        /* Windows Server 2022 and 10 (evidence v6raw-20261116): IPV6_HDRINCL a raw socket's (WSAEINVAL on
         * another), IPV6_RECVTCLASS and IPV6_RECVIF a datagram or raw socket's (WSAEINVAL on a stream), all off by
         * default and read back as 0 or 1; IPV6_UNICAST_IF an interface index (0 = none), IPV6_MTU_DISCOVER 0 to 3
         * (0, IP_PMTUDISC_NOT_SET, by default) on any socket. The stack takes IPV6_HDRINCL; the others are kept
         * with the socket (the control messages of the two receive switches are not delivered yet, the unicast
         * interface is not enforced yet: release notes) */
        case IPV6_HDRINCL:       *Bit = WSH_SET6_HDRINCL; *Boolean = TRUE; return &Context->Ipv6HdrIncl;
        case IPV6_RECVTCLASS:    *Bit = WSH_SET6_RECVTCLASS; *Boolean = TRUE; return &Context->Ipv6RecvTclass;
        case IPV6_RECVIF:        *Bit = WSH_SET6_RECVIF; *Boolean = TRUE; return &Context->Ipv6RecvIf;
        case IPV6_UNICAST_IF:    *Bit = WSH_SET6_UNICASTIF; return &Context->Ipv6UnicastIf;
        case IPV6_MTU_DISCOVER:  *Bit = WSH_SET6_MTUD; return &Context->Ipv6MtuDiscover;
        default: break;
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
          break;

       case IPPROTO_IPV6:
          /* What an IPv6 datagram socket hands to the stack (WSHSetSocketInformation) */
          *TdiType = INFO_TYPE_ADDRESS_OBJECT;
          switch (OptionName)
          {
             case IPV6_UNICAST_HOPS:    *TdiId = AO_OPTION_TTL; return;
             case IPV6_MULTICAST_HOPS:  *TdiId = AO_OPTION_MCASTTTL; return;
             case IPV6_MULTICAST_LOOP:  *TdiId = AO_OPTION_MCASTLOOP; return;
             case IPV6_MULTICAST_IF:    *TdiId = AO_OPTION_INDEX_MCASTIF; return;
             case IPV6_ADD_MEMBERSHIP:  *TdiId = AO_OPTION_INDEX_ADD_MCAST; return;
             case IPV6_DROP_MEMBERSHIP: *TdiId = AO_OPTION_INDEX_DEL_MCAST; return;
             case IPV6_HDRINCL:         *TdiId = AO_OPTION_IP_HDRINCL; return;
             default: break;
          }
          break;

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

    /* IPPROTO_IPV6 on an IPv6 socket (an IPv4 socket never gets here: msafd answers for it) */
    if (Context && Level == IPPROTO_IPV6 && Context->AddressFamily == AF_INET6)
    {
        Kept = WshKeptIpv6Option(Context, OptionName, &Bit, &Default, &Boolean);
        if (!Kept)
        {
            DPRINT1("Get: Unknown IPPROTO_IPV6 option: %d\n", OptionName);
            if (OptionLength) *OptionLength = 0;
            return WSAENOPROTOOPT;
        }
        if (!WshIpv6OptionFitsType(Context, OptionName))
        {
            if (OptionLength) *OptionLength = 0;
            return WSAEINVAL;
        }

        if (!OptionLength || !OptionValue || *OptionLength < (INT)sizeof(CHAR))
        {
            if (OptionLength) *OptionLength = sizeof(LONG);
            return WSAEFAULT;
        }

        Value = (Context->Ipv6OptionsSet & Bit) ? *Kept : Default;

        /* IPV6_V6ONLY as Windows 10 answers it (oracle probe, 32 and 64 bit): a stream socket wants a DWORD
         * (WSAEFAULT, length 0, for less), a datagram socket gives one byte */
        if (OptionName == IPV6_V6ONLY)
        {
            if (Context->SocketType == SOCK_STREAM)
            {
                if (*OptionLength < (INT)sizeof(LONG))
                {
                    *OptionLength = 0;
                    return WSAEFAULT;
                }
                *(PLONG)OptionValue = Value;
                *OptionLength = sizeof(LONG);
            }
            else
            {
                *(PUCHAR)OptionValue = (UCHAR)Value;
                *OptionLength = sizeof(UCHAR);
            }
            return NO_ERROR;
        }

        if (*OptionLength >= (INT)sizeof(LONG))
        {
            *(PLONG)OptionValue = Value;
            *OptionLength = sizeof(LONG);
        }
        else
        {
            *(PUCHAR)OptionValue = (UCHAR)Value;
            *OptionLength = sizeof(UCHAR);
        }
        return NO_ERROR;
    }

    /* IP_HDRINCL: a raw socket's, as set (0 by default); WSAEINVAL on another */
    if (Context && Level == IPPROTO_IP && OptionName == IP_HDRINCL)
    {
        if (Context->SocketType != SOCK_RAW)
        {
            if (OptionLength) *OptionLength = 0;
            return WSAEINVAL;
        }
        if (!OptionLength || !OptionValue || *OptionLength < (INT)sizeof(LONG))
        {
            if (OptionLength) *OptionLength = sizeof(LONG);
            return WSAEFAULT;
        }
        *(PLONG)OptionValue = Context->IpHdrIncl;
        *OptionLength = sizeof(LONG);
        return NO_ERROR;
    }

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
    PSOCKET_CONTEXT Context = HelperDllSocketContext;

    if (Context && Context->AddressFamily == AF_INET6)
    {
        /* [::]:0, a whole SOCKADDR_IN6; the length says how much there is */
        if (*SockaddrLength < WSH_SOCKADDR_IN6_LENGTH)
        {
            DPRINT1("Socket address length too small: %d\n", *SockaddrLength);
            return WSAEFAULT;
        }

        RtlZeroMemory(Sockaddr, WSH_SOCKADDR_IN6_LENGTH);
        Sockaddr->sa_family = AF_INET6;
        *SockaddrLength = WSH_SOCKADDR_IN6_LENGTH;
        return NO_ERROR;
    }

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
    BOOLEAN Handled;

    /* The multicast source filter ioctls (mcast.c) */
    res = WshMcastIoctl(Context, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength,
                        NumberOfBytesReturned, &Handled);
    if (Handled)
    {
        *NeedsCompletion = FALSE;
        return res;
    }

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

        res = SendRequest(TdiAddressObjectHandle, Info, sizeof(*Info) + Info->BufferSize, IOCTL_TCP_SET_INFORMATION_EX);

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

/* A socket option to the stack: on the socket's own address handle (AFD's, from bind; the stack takes the request
 * for that socket whatever entity it names), else on a control channel by the socket's entity id, which the stack
 * allows to the socket's own process and user only (tcpip main.c). NO_ERROR or the Win32 error;
 * ERROR_OPEN_FAILED when no control channel could be opened */
static
DWORD
WshSetInformationEx(
    _In_opt_ HANDLE AddressHandle,
    _In_ DWORD IOCTL,
    _In_ PVOID Request,
    _In_ DWORD RequestSize)
{
    HANDLE TcpCC;
    DWORD BytesReturned, Error;

    if (AddressHandle)
    {
        if (DeviceIoControl(AddressHandle, IOCTL, Request, RequestSize, NULL, 0, &BytesReturned, NULL))
            return NO_ERROR;
        Error = GetLastError();
        DPRINT("DeviceIoControl (address handle): %lu\n", Error);
        /* A handle that does not take the request: the control channel */
        if (Error != ERROR_ACCESS_DENIED && Error != ERROR_INVALID_HANDLE)
            return Error;
    }

    if (openTcpFile(&TcpCC, FILE_READ_DATA | FILE_WRITE_DATA) != STATUS_SUCCESS)
        return ERROR_OPEN_FAILED;

    if (DeviceIoControl(TcpCC, IOCTL, Request, RequestSize, NULL, 0, &BytesReturned, NULL))
        Error = NO_ERROR;
    else
        Error = GetLastError();

    closeTcpFile(TcpCC);

    DPRINT("DeviceIoControl: %lu\n", Error);

    return Error;
}

INT
SendRequest(
    IN HANDLE AddressHandle,
    IN PVOID Request,
    IN DWORD RequestSize,
    IN DWORD IOCTL)
{
    if (WshSetInformationEx(AddressHandle, IOCTL, Request, RequestSize) != NO_ERROR)
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
    INT Error;

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
            WshMcastFree(Context);
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

                SendRequest(TdiAddressObjectHandle,
                            QueuedRequest->Info,
                            sizeof(*QueuedRequest->Info) + QueuedRequest->Info->BufferSize,
                            IOCTL_TCP_SET_INFORMATION_EX);

                NextQueuedRequest = QueuedRequest->Next;

                HeapFree(GetProcessHeap(), 0, QueuedRequest->Info);
                HeapFree(GetProcessHeap(), 0, QueuedRequest);

                QueuedRequest = NextQueuedRequest;
            }
            Context->RequestQueue = NULL;

            /* The groups and filters the socket set before the bind (mcast.c): the stack's refusals fail the bind */
            Error = WshMcastBind(Context);
            if (Error != NO_ERROR)
                return Error;
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

    /* An IPv6 socket exists only while the stack takes IPv6 (see WshIpv6Enabled): until then it is the
     * WSAEAFNOSUPPORT an application has always got for AF_INET6 */
    if (*AddressFamily == AF_INET6 && !WshIpv6Enabled())
        return WSAEAFNOSUPPORT;
    if (*AddressFamily == AF_INET6 && !WshIpv6TypeEnabled(*SocketType))
        return WSAEAFNOSUPPORT;

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

    /* Multicast groups and source filters (mcast.c) */
    if (WshMcastIsOption(Level, OptionName))
    {
        BOOLEAN Handled;

        Status = WshMcastSetOption(Context, Level, OptionName, OptionValue, OptionLength, &Handled);
        if (Handled)
            return Status;
    }

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
            /* IP_HDRINCL: a raw socket's (WSAEINVAL on another), for a privileged caller only (WSAEACCES, as
             * Windows answers a standard user's ICMP socket); kept for getsockopt and given to the stack */
            if (OptionName == IP_HDRINCL)
            {
                if (Context->SocketType != SOCK_RAW)
                    return WSAEINVAL;
                if (!OptionValue || OptionLength < (INT)sizeof(CHAR))
                    return WSAEFAULT;
                if (!WshRawPrivileged())
                    return WSAEACCES;
                Context->IpHdrIncl = ((OptionLength >= (INT)sizeof(LONG)) ? *(PLONG)OptionValue
                                                                          : *(PUCHAR)OptionValue) != 0;
            }
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

        case IPPROTO_IPV6:
        {
            PLONG Kept;
            DWORD Bit;
            LONG Default, Value;
            BOOLEAN Boolean;

            /* An IPv4 socket has never had an answer here (see msafd for IPV6_V6ONLY): unchanged. Only
             * IPV6_V6ONLY is checked: Windows 10 (oracle) takes a DWORD of 0 or 1 on an AF_INET socket and
             * ignores it, and fails a request that is too short (one byte) with WSAEFAULT */
            if (Context->AddressFamily != AF_INET6)
            {
                if (OptionName == IPV6_V6ONLY)
                    return (!OptionValue || OptionLength < (INT)sizeof(DWORD)) ? WSAEFAULT : 0;
                DPRINT1("Set: Received unexpected %d option %d\n", Level, OptionName);
                return 0;
            }

            /* Joining and leaving a group (IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP) is mcast.c's */

            Kept = WshKeptIpv6Option(Context, OptionName, &Bit, &Default, &Boolean);
            if (!Kept)
            {
                DPRINT1("Set: Received unexpected IPPROTO_IPV6 option %d\n", OptionName);
                return WSAENOPROTOOPT;
            }
            if (!WshIpv6OptionFitsType(Context, OptionName))
                return WSAEINVAL;
            if (!OptionValue || OptionLength < (INT)sizeof(CHAR))
                return WSAEFAULT;
            if (OptionName == IPV6_HDRINCL && !WshRawPrivileged())
                return WSAEACCES;

            /* IPV6_V6ONLY goes to the stack with the bind (WSPBind): once bound it cannot change. WSAEINVAL, as
             * Windows 10 answers (oracle probe) */
            if (OptionName == IPV6_V6ONLY && Context->SocketState != SocketStateCreated)
                return WSAEINVAL;

            Value = (OptionLength >= (INT)sizeof(LONG)) ? *(PLONG)OptionValue : *(PUCHAR)OptionValue;
            if (Boolean)
                Value = (Value != 0);
            else if (OptionName == IPV6_UNICAST_IF)
            {
                /* An interface index in host order, 0 for none (Windows: WSAEINVAL for one that does not exist) */
                if (Value != 0 && (Value < 0 || !WshInterfaceExists((ULONG)Value)))
                    return WSAEINVAL;
            }
            else if (OptionName == IPV6_MTU_DISCOVER)
            {
                if (Value < 0 || Value > 3)
                    return WSAEINVAL;
            }
            else if (OptionName == IPV6_MULTICAST_IF)
            {
                /* An interface index: the stack takes it as unsigned, a negative one is no index (VERIFY ON
                 * ORACLE: the exact error) */
                if (Value < 0)
                    return WSAEINVAL;
            }
            else if (Value < -1 || Value > 255)
                return WSAEINVAL;
            /* -1 is the default hop limit: 128 unicast (what an unset one reads, oracle), 1 multicast (VERIFY ON
             * ORACLE: what reads back after -1) */
            if (Value == -1 && OptionName == IPV6_UNICAST_HOPS)
                Value = 128;
            else if (Value == -1 && OptionName == IPV6_MULTICAST_HOPS)
                Value = 1;

            *Kept = Value;
            Context->Ipv6OptionsSet |= Bit;

            /* The hop limits, the multicast loop and interface of a datagram socket reach the stack (as a LONG,
             * -1 = the default); a stream socket keeps them only, as before, and so does IPV6_DONTFRAG (the
             * stack does not act on it) */
            if (OptionName == IPV6_HDRINCL)
            {
                /* The raw socket's: the stack takes it (AO_OPTION_IP_HDRINCL) */
                OptionValue = (PCHAR)Kept;
                OptionLength = sizeof(LONG);
                break;
            }
            if (OptionName == IPV6_V6ONLY || OptionName == IPV6_DONTFRAG || OptionName == IPV6_RECVTCLASS ||
                OptionName == IPV6_RECVIF || OptionName == IPV6_UNICAST_IF || OptionName == IPV6_MTU_DISCOVER ||
                Context->SocketType != SOCK_DGRAM)
                return NO_ERROR;
            OptionValue = (PCHAR)Kept;
            OptionLength = sizeof(LONG);
            break;
        }

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

    Status = SendRequest(TdiAddressObjectHandle, Info, sizeof(*Info) + Info->BufferSize, IOCTL_TCP_SET_INFORMATION_EX);

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
