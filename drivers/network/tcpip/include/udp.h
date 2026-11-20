/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        include/udp.h
 * PURPOSE:     User Datagram Protocol definitions
 */

#pragma once

#define UDP_STARTING_PORT 0x8000
#define UDP_DYNAMIC_PORTS 0x8000

/* UDPv4 header structure */
#include <pshpack1.h>
typedef struct UDP_HEADER {
  USHORT SourcePort; /* Source port */
  USHORT DestPort;   /* Destination port */
  USHORT Length;     /* Size of header and data */
  USHORT Checksum;   /* Checksum of datagram */
} UDP_HEADER, *PUDP_HEADER;

/* UDPv4 pseudo header */
typedef struct UDP_PSEUDO_HEADER {
  ULONG SourceAddress; /* Source address */
  ULONG DestAddress;   /* Destination address */
  UCHAR Zero;          /* Reserved */
  UCHAR Protocol;      /* Protocol */
  USHORT UDPLength;    /* Size of UDP datagram */
} UDP_PSEUDO_HEADER, *PUDP_PSEUDO_HEADER;
#include <poppack.h>

typedef struct UDP_STATISTICS {
  ULONG InputDatagrams;
  ULONG NumPorts;
  ULONG InputErrors;
  ULONG OutputDatagrams;
  ULONG NumAddresses;
} UDP_STATISTICS, *PUDP_STATISTICS;

extern UDP_STATISTICS UDPStats;

VOID UDPSend(
  PVOID Context,
  PDATAGRAM_SEND_REQUEST SendRequest);

NTSTATUS UDPSendDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed );

VOID UDPReceive(
    PIP_INTERFACE Interface,
    PIP_PACKET IPPacket);

/* An ICMP port unreachable for one of our UDP datagrams (icmp.c) */
VOID UDPPortUnreachable(
    PIP_PACKET IPPacket,
    PUCHAR Icmp,
    UINT Size);

NTSTATUS UDPStartup(
  VOID);

NTSTATUS UDPShutdown(
  VOID);
UINT UDPAllocatePort( UINT HintPort );
BOOLEAN UDPReservePort( UINT Port );
VOID UDPFreePort( UINT Port );

/* UDP over IPv6 (ip/transport/udp/udp6.c), with Tcpip\Parameters\Ipv6Enable on */
NTSTATUS UDPSendDatagram6(
    PADDRESS_FILE AddrFile,
    PTA_IP6_ADDRESS Remote,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed);

/* Hands the datagrams that IPv6 input or a looped multicast send left for the sockets to them. Called with no lock
   held (PASSIVE_LEVEL) after lwIP's core lock was released */
VOID UDP6DeliverDeferred(VOID);

/* IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP (Request: struct ipv6_mreq), a group's source filter
   (NITRO_AO_OPTION_MCAST_FILTER, nitrotdi.h) and the end of a socket's groups */
NTSTATUS UDP6SetMembership(PADDRESS_FILE AddrFile, BOOLEAN Join, const VOID *Request, UINT Length);
NTSTATUS UDP6SetFilter(PADDRESS_FILE AddrFile, ULONG IfIndex, const UCHAR *GroupAddress, UCHAR Mode, ULONG NumSources,
                       const UCHAR (*Sources)[16], BOOLEAN MustBeNew);
VOID UDP6LeaveAll(PADDRESS_FILE AddrFile);
/* IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP (Request: struct ip_mreq), an IPv4 group's source filter of a socket
   (NITRO_AO_OPTION_MCAST_FILTER), whether the socket takes a datagram to a group from a source by them (no filter
   for the group: it does, as before) and the end of a socket's IPv4 groups */
NTSTATUS UDP4SetMembership(PADDRESS_FILE AddrFile, BOOLEAN Join, const VOID *Request, UINT Length);
NTSTATUS UDP4SetFilter(PADDRESS_FILE AddrFile, ULONG IfIndex, ULONG Group, UCHAR Mode, ULONG NumSources,
                       const UCHAR (*Sources)[16], BOOLEAN MustBeNew);
BOOLEAN UDP4FilterAccepts(PADDRESS_FILE AddrFile, ULONG Group, ULONG Source, ULONG IfIndex);
VOID UDP4LeaveAll(PADDRESS_FILE AddrFile);
/* Whether some socket joined an IPv4 group (a hint without the core lock) */
BOOLEAN UDP4HasGroups(VOID);
VOID UDP6Startup(VOID);
/* The row of an IPv6 UDP socket (IP_UDP6_ROW_ENTRY_ID) */
VOID UDP6BuildRow(PADDRESS_FILE AddrFile, PUDP6_ROW_OWNER_PID Row);
/* Whether a UDP socket is bound to the IPv6 address (temp6.c: such a temporary address is in use). Takes
   AddressFileListLock, which the core lock may be held over */
BOOLEAN UDP6AddressInUse(const UCHAR *Address);

/* ICMPv6 echo (ip/network/echo6.c): \Device\Ip6, made only with IPv6 on */
extern PDEVICE_OBJECT Ip6DeviceObject;
NTSTATUS DispEchoRequest6(PIRP Irp, PIO_STACK_LOCATION IrpSp);
/* The firewall: an echo reply or an ICMPv6 error that answers one of our outstanding echo requests */
BOOLEAN Echo6ReplyExpected(const UCHAR *Src, const UCHAR *Icmp, ULONG Avail);
BOOLEAN Echo6ErrorRelated(const UCHAR *Icmp, ULONG Avail);

/* EOF */
