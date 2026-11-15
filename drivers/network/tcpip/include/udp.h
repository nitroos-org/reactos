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

/* IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP (Request: struct ipv6_mreq) and the end of a socket's groups */
NTSTATUS UDP6SetMembership(PADDRESS_FILE AddrFile, BOOLEAN Join, const VOID *Request, UINT Length);
VOID UDP6LeaveAll(PADDRESS_FILE AddrFile);
VOID UDP6Startup(VOID);
/* The row of an IPv6 UDP socket (IP_UDP6_ROW_ENTRY_ID) */
VOID UDP6BuildRow(PADDRESS_FILE AddrFile, PUDP6_ROW_OWNER_PID Row);

/* EOF */
