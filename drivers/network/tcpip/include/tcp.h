/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/tcp.h
 * PURPOSE:     Transmission Control Protocol definitions
 */

#pragma once

#include <ports.h>

typedef VOID
(*PTCP_COMPLETION_ROUTINE)( PVOID Context, NTSTATUS Status, ULONG Count );

/* TCPv4 header structure */
#include <pshpack1.h>
typedef struct TCPv4_HEADER {
  USHORT SourcePort;        /* Source port */
  USHORT DestinationPort;   /* Destination port */
  ULONG  SequenceNumber;    /* Sequence number */
  ULONG  AckNumber;         /* Acknowledgement number */
  UCHAR  DataOffset;        /* Data offset; 32-bit words (leftmost 4 bits) */
  UCHAR  Flags;             /* Control bits (rightmost 6 bits) */
  USHORT Window;            /* Maximum acceptable receive window */
  USHORT Checksum;          /* Checksum of segment */
  USHORT Urgent;            /* Pointer to urgent data */
} TCPv4_HEADER, *PTCPv4_HEADER;

#define TCPOPT_END_OF_LIST  0x0
#define TCPOPT_NO_OPERATION 0x1
#define TCPOPT_MAX_SEG_SIZE 0x2

#define TCPOPTLEN_MAX_SEG_SIZE  0x4

/* Data offset; 32-bit words (leftmost 4 bits); convert to bytes */
#define TCP_DATA_OFFSET(DataOffset)(((DataOffset) & 0xF0) >> (4-2))


/* TCPv4 pseudo header */
typedef struct TCPv4_PSEUDO_HEADER {
  ULONG SourceAddress;      /* Source address */
  ULONG DestinationAddress; /* Destination address */
  UCHAR Zero;               /* Reserved */
  UCHAR Protocol;           /* Protocol */
  USHORT TCPLength;         /* Size of TCP segment */
} TCPv4_PSEUDO_HEADER, *PTCPv4_PSEUDO_HEADER;
#include <poppack.h>

typedef struct _SLEEPING_THREAD {
    LIST_ENTRY Entry;
    PVOID SleepToken;
    KEVENT Event;
} SLEEPING_THREAD, *PSLEEPING_THREAD;

typedef struct _CLIENT_DATA {
    BOOLEAN Unlocked;
    KSPIN_LOCK Lock;
    KIRQL OldIrql;
} CLIENT_DATA, *PCLIENT_DATA;

/* Retransmission timeout constants */

/* Lower bound for retransmission timeout in TCP timer ticks */
#define TCP_MIN_RETRANSMISSION_TIMEOUT    1*1000          /* 1 tick */

/* Upper bound for retransmission timeout in TCP timer ticks */
#define TCP_MAX_RETRANSMISSION_TIMEOUT    1*60*1000       /* 1 tick */

/* Smoothing factor */
#define TCP_ALPHA_RETRANSMISSION_TIMEOUT(x)(((x)*8)/10)   /* 0.8 */

/* Delay variance factor */
#define TCP_BETA_RETRANSMISSION_TIMEOUT(x)(((x)*16)/10)   /* 1.6 */

#define SEL_CONNECT 1
#define SEL_FIN     2
#define SEL_RST     4
#define SEL_ABRT    8
#define SEL_READ    16
#define SEL_WRITE   32
#define SEL_ACCEPT  64
#define SEL_OOB     128
#define SEL_ERROR   256
#define SEL_FINOUT  512

#define	FREAD		0x0001
#define	FWRITE		0x0002

/* Datagram/segment send request flags */

#define SRF_URG   TCP_URG
#define SRF_ACK   TCP_ACK
#define SRF_PSH   TCP_PSH
#define SRF_RST   TCP_RST
#define SRF_SYN   TCP_SYN
#define SRF_FIN   TCP_FIN

extern LONG TCP_IPIdentification;
extern CLIENT_DATA ClientInfo;

/* accept.c */
NTSTATUS TCPCheckPeerForAccept(PVOID Context,
                               PTDI_REQUEST_KERNEL Request);
NTSTATUS TCPListen( PCONNECTION_ENDPOINT Connection, UINT Backlog );
BOOLEAN TCPAbortListenForSocket( PCONNECTION_ENDPOINT Listener,
			         PCONNECTION_ENDPOINT Connection,
			         PIRP Irp );
NTSTATUS TCPAccept
( PTDI_REQUEST Request,
  PCONNECTION_ENDPOINT Listener,
  PCONNECTION_ENDPOINT Connection,
  PTCP_COMPLETION_ROUTINE Complete,
  PVOID Context,
  ULONG Room );

/* tcp.c */
PCONNECTION_ENDPOINT TCPAllocateConnectionEndpoint( PVOID ClientContext );
VOID TCPFreeConnectionEndpoint( PCONNECTION_ENDPOINT Connection );

NTSTATUS TCPSocket( PCONNECTION_ENDPOINT Connection,
		    UINT Family, UINT Type, UINT Proto );

VOID HandleSignalledConnection(PCONNECTION_ENDPOINT Connection);

PTCP_SEGMENT TCPCreateSegment(
  PIP_PACKET IPPacket,
  PTCPv4_HEADER TCPHeader,
  ULONG SegmentLength);

VOID TCPFreeSegment(
  PTCP_SEGMENT Segment);

VOID TCPAddSegment(
  PCONNECTION_ENDPOINT Connection,
  PTCP_SEGMENT Segment,
  PULONG Acknowledged);

NTSTATUS TCPConnect(
  PCONNECTION_ENDPOINT Connection,
  PTDI_CONNECTION_INFORMATION ConnInfo,
  PTDI_CONNECTION_INFORMATION ReturnInfo,
  PTCP_COMPLETION_ROUTINE Complete,
  PVOID Context);

NTSTATUS TCPDisconnect(
  PCONNECTION_ENDPOINT Connection,
  UINT Flags,
  PLARGE_INTEGER Timeout,
  PTDI_CONNECTION_INFORMATION ConnInfo,
  PTDI_CONNECTION_INFORMATION ReturnInfo,
  PTCP_COMPLETION_ROUTINE Complete,
  PVOID Context);

NTSTATUS TCPReceiveData(
  PCONNECTION_ENDPOINT Connection,
  PNDIS_BUFFER Buffer,
  ULONG ReceiveLength,
  PULONG BytesReceived,
  ULONG ReceiveFlags,
  PTCP_COMPLETION_ROUTINE Complete,
  PVOID Context);

NTSTATUS TCPSendData(
  PCONNECTION_ENDPOINT Connection,
  PCHAR Buffer,
  ULONG DataSize,
  PULONG DataUsed,
  ULONG Flags,
  PTCP_COMPLETION_ROUTINE Complete,
  PVOID Context);

NTSTATUS TCPClose( PCONNECTION_ENDPOINT Connection );

NTSTATUS TCPTranslateError( const INT8 err );

/* The dynamic port range of Windows Vista and later (IANA) */
#define TCP_EPHEMERAL_FIRST 49152
#define TCP_EPHEMERAL_LAST  65535

UINT TCPAllocatePort( const UINT HintPort );

/* What AFD puts in the sin_zero of the null address it opens for the implicit bind of a connect, so that the port is chosen
   knowing the remote endpoint (a TIME-WAIT of another remote endpoint does not make a port unusable, as on Windows).
   Same layout in drivers/network/afd/afd/connect.c. */
#include <pshpack1.h>
typedef struct _TCP_CONNECT_HINT {
    ULONG  RemoteAddress;  /* network order */
    USHORT RemotePort;     /* network order */
    USHORT Magic;          /* TCP_CONNECT_HINT_MAGIC */
} TCP_CONNECT_HINT, *PTCP_CONNECT_HINT;
#include <poppack.h>
#define TCP_CONNECT_HINT_MAGIC 0xE9F1
#define TCP_PORT_TIME_WAIT ((UINT)-2)

UINT TCPAllocatePortForRemote( ULONG RemoteAddress, USHORT RemotePort );

BOOLEAN TCPReservePort( const UINT Port );

UINT TCPAllocateEphemeralPort( PPORT_IN_USE_ROUTINE InUse );

VOID TCPFreePort( const UINT Port );

/* The local or remote address of a connection as a TA_IP_ADDRESS, or a TA_IP6_ADDRESS for an IPv6 one; Length is
   the room at TransportAddress (STATUS_BUFFER_TOO_SMALL when the address does not fit) */
NTSTATUS TCPGetSockAddress
( PCONNECTION_ENDPOINT Connection,
  PTRANSPORT_ADDRESS TransportAddress,
  ULONG Length,
  BOOLEAN RemoteAddress );

/* What the Winsock provider puts in the sin6_flowinfo of the address it binds an IPv6 socket to when IPV6_V6ONLY is
   off (a dual stack socket); any other value is a socket with IPV6_V6ONLY on, the default. No flow information has
   the top bits set (RFC 8200: 8 bits of traffic class, 20 of flow label). AFD clears the field once the address is
   open. Same value as AFD_TCP_BIND6_DUAL_STACK in <afd/shared.h> */
#define TCP_BIND6_DUAL_STACK 0xF6D5A001UL

/* Whether an address file takes connections or datagrams of this IP version (IP_ADDRESS_V4 or IP_ADDRESS_V6):
   its own address, and IPv4 too for a dual stack socket bound to the unspecified IPv6 address */
BOOLEAN AddrFileTakesType( PADDRESS_FILE AddrFile, UCHAR Type );

NTSTATUS TCPStartup(
  VOID);

NTSTATUS TCPShutdown(
  VOID);

BOOLEAN TCPRemoveIRP( PCONNECTION_ENDPOINT Connection, PIRP Irp );

NTSTATUS TCPSetNoDelay(PCONNECTION_ENDPOINT Connection, BOOLEAN Set);

NTSTATUS TCPSetReceiveWindow(PCONNECTION_ENDPOINT Connection, ULONG Size);

NTSTATUS TCPSetKeepAlive(PCONNECTION_ENDPOINT Connection, BOOLEAN Set);

NTSTATUS TCPSetKeepAliveValues(PCONNECTION_ENDPOINT Connection, DWORD KeepAliveTime, DWORD KeepAliveInterval);

VOID
TCPUpdateInterfaceLinkStatus(PIP_INTERFACE IF);

/* IPv6 (ip/transport/tcp/if6.c), behind Tcpip\Parameters\Ipv6Enable */
extern BOOLEAN TCPIpv6Enabled;

VOID
TCPReadIpv6Switch(VOID);

VOID
TCPInterfaceInit6(PIP_INTERFACE IF);

VOID
TCPAddLoopbackAddress6(PIP_INTERFACE IF);

/* Stable random interface identifiers (ip/transport/tcp/iid6.c), behind Tcpip6\Parameters\RandomizeIdentifiers */
extern BOOLEAN TCP6RandomizeIdentifiers;

VOID
TCP6ReadIdentifierSettings(VOID);

struct netif;
BOOLEAN
TCP6SetStableLinkLocal(struct netif *netif);

VOID
TCPReceive6(PIP_INTERFACE IF, PIP_PACKET IPPacket);

/* The IP_IPV6_TABLE_ENTRY_ID answer; returns its size (what fits in Out is written) */
ULONG
TCPQueryIpv6Table(PVOID Out, ULONG OutSize);

/* The IP_IPV6_DNS_ENTRY_ID answer (rdnss6.c); same convention */
ULONG
TCPQueryIpv6Dns(PVOID Out, ULONG OutSize);

/* The IP_IPV6_ND_ENTRY_ID and IP_IPV6_STATS_ENTRY_ID answers (nd6info.c); same convention */
ULONG
TCPQueryIpv6Nd(PVOID Out, ULONG OutSize);

ULONG
TCPQueryIpv6Stats(PVOID Out, ULONG OutSize);

/* The IPv6 route table (route6.c): the IP_IPV6_ROUTE_ENTRY_ID answer (same convention), IOCTL_IP6_ROUTE_CONFIG,
   and the routes of an interface that goes (core lock held, before netif_remove) */
ULONG
TCPQueryIpv6Routes(PVOID Out, ULONG OutSize);

NTSTATUS
DispRouteConfig6(PIRP Irp, PIO_STACK_LOCATION IrpSp);

VOID
TCP6RemoveRoutesOfNetif(struct netif *netif);

/* The interface with this index that can have IPv6 routes and addresses, referenced (IPDereferenceInterface), or
   NULL; and whether a netif is still one of lwIP's (core lock held) */
PIP_INTERFACE
TCP6ReferenceInterface(ULONG IfIndex);

BOOLEAN
TCP6NetifRegistered(struct netif *netif);

/* Configured IPv6 addresses (addr6.c): IOCTL_IP6_ADDRESS_CONFIG; what was configured for the address in an lwIP
   address slot (FALSE: the stack formed it); the entries of an interface that goes; all of them under the core lock */
typedef struct _TCP6_ADDRESS_INFO
{
    UCHAR PrefixLength;
    UCHAR PrefixOrigin;     /* NL_PREFIX_ORIGIN */
    UCHAR SuffixOrigin;     /* NL_SUFFIX_ORIGIN */
    ULONG Flags;            /* TCP_IPV6_ADDRESS_ */
} TCP6_ADDRESS_INFO, *PTCP6_ADDRESS_INFO;

extern ULONG Addr6Count;

NTSTATUS
DispAddressConfig6(PIRP Irp, PIO_STACK_LOCATION IrpSp);

BOOLEAN
TCP6AddressInfo(struct netif *netif, signed char Slot, PTCP6_ADDRESS_INFO Info);

VOID
TCP6RemoveAddressesOfNetif(struct netif *netif);

/* The counters of the IPv6 path (nd6info.c): a datagram leaves through the IPv6 output callback (the opens of TCP
   connections are counted from lwip_glue/tcp.c, see lwip_glue.h) */
struct pbuf;

VOID
TCP6CountOutput(const struct pbuf *p);


/* A unicast IPv6 address of this machine (16 bytes, network order) that a socket may bind; *Zone gets the lwIP zone
   of a link-local one (0 otherwise) */
BOOLEAN
TCPFindLocalAddress6(const UCHAR *Address, ULONG ScopeId, PUCHAR Zone);

/* The lwIP zone of the interface with this index (IF->Index), 0 when there is none */
UCHAR
TCPZoneOfInterface6(ULONG IfIndex);

/* The interface index of an lwIP zone, 0 when there is none (CoreLocked: the caller holds the core lock) */
ULONG
TCPInterfaceOfZone6(UCHAR Zone, BOOLEAN CoreLocked);

/* The address of an address file as a TA_IP_ADDRESS or TA_IP6_ADDRESS (Length: the room at Address) */
NTSTATUS
TCPAddrFileTransportAddress(PADDRESS_FILE AddrFile, PTRANSPORT_ADDRESS Address, ULONG Length);

/* The local address of a connection of an IPv6 socket (connection locked) */
NTSTATUS
TCPGetLocalAddress6(PCONNECTION_ENDPOINT Connection, PADDRESS_FILE AddrFile, PTRANSPORT_ADDRESS Address, ULONG Length);

#if DBG || defined(TCPIP_IPV6_SELFTEST)
/* ip/transport/tcp/selftest6.c: runs with Tcpip\Parameters\Ipv6SelfTest set */
VOID
TCPStartIpv6SelfTest(VOID);

/* ICMPv6 messages from adapters, counted by if6.c for the self-test */
#define TCP6_RX_NS_MULTICAST  0   /* neighbour solicitations to a multicast (solicited-node) address */
#define TCP6_RX_NS_UNICAST    1
#define TCP6_RX_RA_MULTICAST  2   /* router advertisements to a multicast (all-nodes) address */
#define TCP6_RX_RA_UNICAST    3
#define TCP6_RX_ECHO_REQUEST  4
#define TCP6_RX_KINDS         5
extern volatile LONG TCP6ReceivedIcmp[TCP6_RX_KINDS];
#endif

VOID
TCPUpdateInterfaceIPInformation(PIP_INTERFACE IF);

VOID
FlushListenQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status);

VOID
FlushConnectQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status);

VOID
FlushReceiveQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status);

VOID
FlushSendQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status);

VOID
FlushShutdownQueue(PCONNECTION_ENDPOINT Connection, const NTSTATUS Status);

VOID
FlushAllQueues(PCONNECTION_ENDPOINT Connection, NTSTATUS Status);

VOID CompleteBucket(PCONNECTION_ENDPOINT Connection, PTDI_BUCKET Bucket, const BOOLEAN Synchronous);

/* Around the receive worker's input of a packet: its TDI completions go to work items */
/* Around work that holds no AFD or TDI lock (the loopback worker): its completions run inline */
VOID TCPEnterInlineContext(VOID);
VOID TCPLeaveInlineContext(VOID);
VOID TCPEnterReceiveWorker(VOID);
VOID TCPLeaveReceiveWorker(VOID);

void
LibTCPDumpPcb(PVOID SocketContext);

NTSTATUS TCPGetSocketStatus(PCONNECTION_ENDPOINT Connection, PULONG State);
/* The local and remote address (TA_IP_ADDRESS, or TA_IP6_ADDRESS for an IPv6 one; Length is the room at each) and
   the state (MIB_TCP_STATE_xxx) of a connection that has a socket, read together under the core lock. An error when it
   has none (not connected yet, or closed meanwhile). PASSIVE_LEVEL, the core lock not held */
NTSTATUS TCPGetConnectionEnds(PCONNECTION_ENDPOINT Connection, PTRANSPORT_ADDRESS Local, PTRANSPORT_ADDRESS Remote,
                              ULONG Length, PULONG State);
ULONG TCPEnumTimeWait(PTCP_TIMEWAIT_ROW Rows, ULONG MaxRows);
