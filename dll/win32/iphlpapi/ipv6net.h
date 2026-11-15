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



#endif
