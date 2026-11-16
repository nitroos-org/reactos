/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The IPv6 neighbours, routes and counters of the stack (ipv6net.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef IPV6NET_H
#define IPV6NET_H

#include <wine/netioapi.h>

/* The neighbour cache and the on-link prefixes of the stack (IP_IPV6_ND_ENTRY_ID) */
typedef struct _IPV6_ND_STATE
{
    PVOID Memory;
    PTCP_IPV6_ND_HEADER Header;
    PTCP_IPV6_NEIGHBOR_ROW Neighbors;
    PTCP_IPV6_PREFIX_ROW Prefixes;
} IPV6_ND_STATE, *PIPV6_ND_STATE;

BOOL Ipv6GetNdFromFile(HANDLE TcpFile, PIPV6_ND_STATE State);
VOID Ipv6FreeNd(PIPV6_ND_STATE State);

/* The IPv6 neighbour rows, sorted by interface and address; the rows are one HeapAlloc block of the process heap.
   Off: NO_ERROR and no row */
DWORD Ipv6GetNeighborRows(PMIB_IPNET_ROW2 *Rows, ULONG *Count);
/* The IPv4 neighbours in the same layout (neighbor2.c) */
DWORD Ipv4GetNeighborRows(PMIB_IPNET_ROW2 *Rows, ULONG *Count);

/* The interface that owns this IPv6 address of this computer. FALSE too when IPv6 is off */
BOOL Ipv6FindOwner(const UCHAR *Address, DWORD Scope, PDWORD IfIndex);

/* The IPv6 route rows, sorted by prefix, length and interface; same convention */
DWORD Ipv6GetRouteRows(PMIB_IPFORWARD_ROW2 *Rows, ULONG *Count);
/* The metric of an IPv4 interface; 0 when it is not known (route2.c) */
DWORD Ipv4InterfaceMetric(DWORD IfIndex);
/* The IPv4 routes in the same layout (route2.c) */
DWORD Ipv4GetRouteRows(PMIB_IPFORWARD_ROW2 *Rows, ULONG *Count);

/* GetBestRoute2 for an IPv6 destination */
DWORD Ipv6BestRoute(const NET_LUID *InterfaceLuid, NET_IFINDEX InterfaceIndex, const SOCKADDR_INET *SourceAddress,
                    const SOCKADDR_INET *DestinationAddress, PMIB_IPFORWARD_ROW2 BestRoute,
                    SOCKADDR_INET *BestSourceAddress);

/* The statistics of the IPv6 path, filled in from the stack's counters. FALSE: IPv6 is off, nothing was written */
BOOL Ipv6GetIpStatistics(PMIB_IPSTATS Stats);
BOOL Ipv6GetTcpStatistics(PMIB_TCPSTATS Stats);
BOOL Ipv6GetIcmpStatistics(PMIB_ICMP_EX Stats);

/* IPv6 address configuration (config6.c), for Create/Delete/SetUnicastIpAddressEntry */
DWORD Ipv6CreateUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row);
DWORD Ipv6DeleteUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row);
DWORD Ipv6SetUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row);

/* The per-interface parameters of the stack (ipif.c: IP_INTERFACE_CONFIG_ENTRY_ID, IOCTL_IP_INTERFACE_CONFIG) */
typedef struct _IP_INTERFACE_CONFIG
{
    PVOID Memory;
    PTCP_IP_INTERFACE_ROW Rows;
    ULONG Count;
} IP_INTERFACE_CONFIG, *PIP_INTERFACE_CONFIG;

BOOL IpGetInterfaceConfig(PIP_INTERFACE_CONFIG Config);
VOID IpFreeInterfaceConfig(PIP_INTERFACE_CONFIG Config);
const TCP_IP_INTERFACE_ROW *IpFindInterfaceConfig(const IP_INTERFACE_CONFIG *Config, DWORD IfIndex);
DWORD IpSetInterfaceConfig(PTCP_IP_INTERFACE_REQUEST Request, ULONG Store);

#endif
