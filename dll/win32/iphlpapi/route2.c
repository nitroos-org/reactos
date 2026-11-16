/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetBestRoute2
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include <wine/netioapi.h>
#include "ipv6net.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/*
 * The route metric Windows gives on-link and host routes. The legacy route table of the stack here holds route
 * and interface cost as one number and the interface cost is not available, so routes with a gateway report
 * that number as it is.
 */
#define ON_LINK_METRIC 256

static BOOL if_index_to_luid(DWORD Index, PULONG Type, NET_LUID *Luid)
{
  Luid->Value = 0;
  return getInterfaceLuidByIndex(Index, Type, &Luid->Value);
}

/*
 * The interface that owns an address of this computer, or with Broadcast also the interface whose
 * subnet the address is the broadcast address of. With Constrained the given interface is the only
 * candidate. Addresses are in network byte order.
 */
static BOOL find_local_address(IPAddr Dest, BOOL Broadcast, BOOL Constrained, DWORD ConstrainedIndex, PDWORD Index)
{
  InterfaceIndexTable *Table;
  BOOL Found = FALSE;
  DWORD i;

  if (!Dest || Dest == INADDR_NONE || !(Table = getInterfaceIndexTable()))
    return FALSE;

  for (i = 0; i < Table->numIndexes && !Found; i++)
  {
    IPAddr Address = getInterfaceIPAddrByIndex(Table->indexes[i]);
    IPAddr Mask = getInterfaceMaskByIndex(Table->indexes[i]);

    if (Constrained && Table->indexes[i] != ConstrainedIndex)
      continue;
    if (!Address || Address == INADDR_NONE)
      continue;
    if (Dest == Address || (Broadcast && Mask && Mask != INADDR_NONE && Dest == (Address | ~Mask)))
    {
      *Index = Table->indexes[i];
      Found = TRUE;
    }
  }
  free(Table);
  return Found;
}

/* The interface of a limited broadcast that names none: the first with an address, a real one before the loopback. */
static BOOL find_broadcast_interface(PDWORD Index)
{
  InterfaceIndexTable *Table = getInterfaceIndexTable();
  BOOL Found = FALSE;
  ULONG Type;
  NET_LUID Luid;
  DWORD i, Loopback = 0;
  BOOL HaveLoopback = FALSE;

  if (!Table)
    return FALSE;

  for (i = 0; i < Table->numIndexes && !Found; i++)
  {
    IPAddr Address = getInterfaceIPAddrByIndex(Table->indexes[i]);

    if (!Address || Address == INADDR_NONE || !if_index_to_luid(Table->indexes[i], &Type, &Luid))
      continue;
    if (Type == IF_TYPE_SOFTWARE_LOOPBACK)
    {
      Loopback = Table->indexes[i];
      HaveLoopback = TRUE;
    }
    else
    {
      *Index = Table->indexes[i];
      Found = TRUE;
    }
  }
  if (!Found && HaveLoopback)
  {
    *Index = Loopback;
    Found = TRUE;
  }
  free(Table);
  return Found;
}

/*
 * The metric of an IPv4 interface (GetIpInterfaceEntry). The route table of the stack, like GetIpForwardTable on
 * Windows, shows the sum of the interface metric and the route metric; MIB_IPFORWARD_ROW2.Metric is the route's own
 * (a read of Windows Server 2022: a default route of a metric 25 interface is 25 in the one and 0 in the other, an
 * on-link route 281 and 256). 0 when the interface is not known.
 */
DWORD Ipv4InterfaceMetric(DWORD IfIndex)
{
  MIB_IPINTERFACE_ROW Interface;

  memset(&Interface, 0, sizeof(Interface));
  Interface.Family = AF_INET;
  Interface.InterfaceIndex = IfIndex;
  if (GetIpInterfaceEntry(&Interface) != NO_ERROR)
    return 0;
  return Interface.Metric;
}

/* The route metric of a route of the stack's table (the sum of the two), never below 0 */
static ULONG route_own_metric(ULONG Total, DWORD IfIndex)
{
  ULONG Interface = Ipv4InterfaceMetric(IfIndex);

  return Total > Interface ? Total - Interface : 0;
}

static ULONG mask_prefix_length(ULONG Mask)
{
  ULONG Length = 0;

  for (Mask = ntohl(Mask); Mask & 0x80000000; Mask <<= 1)
    Length++;
  return Length;
}

static BOOL fill_best_route(PMIB_IPFORWARD_ROW2 Row, SOCKADDR_INET *BestSource, DWORD IfIndex, IPAddr Dest,
                            ULONG PrefixLength, IPAddr NextHop, ULONG Metric, BOOLEAN Loopback, IPAddr Source)
{
  NET_LUID Luid;

  if (!if_index_to_luid(IfIndex, NULL, &Luid))
    return FALSE;

  memset(Row, 0, sizeof(*Row));
  Row->InterfaceLuid = Luid;
  Row->InterfaceIndex = IfIndex;
  Row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
  Row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = Dest;
  Row->DestinationPrefix.PrefixLength = PrefixLength;
  Row->NextHop.Ipv4.sin_family = AF_INET;
  Row->NextHop.Ipv4.sin_addr.s_addr = NextHop;
  /* the stack here keeps no route lifetime or age, so a route never expires and has no age */
  Row->ValidLifetime = Row->PreferredLifetime = 0xffffffff;
  Row->Metric = Metric;
  Row->Protocol = MIB_IPPROTO_NETMGMT;
  Row->Loopback = Loopback;
  Row->AutoconfigureAddress = TRUE;

  memset(BestSource, 0, sizeof(*BestSource));
  BestSource->Ipv4.sin_family = AF_INET;
  BestSource->Ipv4.sin_addr.s_addr = Source ? Source : getInterfaceIPAddrByIndex(IfIndex);
  return TRUE;
}

/******************************************************************
 *    GetBestRoute2 (IPHLPAPI.@)
 *
 * Find the route a packet to a destination takes, and the source address it carries.
 *
 * NOTES
 *  IPv6 destinations are routed from the routes Ipv6GetRouteRows builds (ipv6net.c); while the stack has
 *  IPv6 off every IPv6 destination has no route.
 *  The measured Windows behaviour is followed. A luid wins over an index, a zero luid
 *  or index is not a constraint, and a source address confines the route to the
 *  interface that owns it. A destination that is an address of this computer, or the
 *  broadcast address of one of its subnets, gets a host route over that interface.
 *  Windows also answers multicast and link-local destinations with an empty row and
 *  NO_ERROR; here they follow the routing table like any other address.
 */
DWORD WINAPI GetBestRoute2(NET_LUID *InterfaceLuid, NET_IFINDEX InterfaceIndex,
                           const SOCKADDR_INET *SourceAddress, const SOCKADDR_INET *DestinationAddress,
                           ULONG AddressSortOptions, PMIB_IPFORWARD_ROW2 BestRoute,
                           SOCKADDR_INET *BestSourceAddress)
{
  DWORD IfIndex = 0, SourceIf, OwnerIf, Matched = 0, i;
  ULONG Type = 0, MatchedLength = 0;
  IPAddr Dest, Source = 0;
  RouteTable *Table;
  BOOL Constrained = FALSE, Found = FALSE, Filled, Local;
  NET_LUID Luid;

  TRACE("(%p, %lu, %p, %p, 0x%lx, %p, %p)\n", InterfaceLuid, InterfaceIndex, SourceAddress,
        DestinationAddress, AddressSortOptions, BestRoute, BestSourceAddress);

  if (!DestinationAddress || !BestRoute || !BestSourceAddress)
    return ERROR_INVALID_PARAMETER;
  if (DestinationAddress->si_family != AF_INET && DestinationAddress->si_family != AF_INET6)
    return ERROR_INVALID_PARAMETER;

  if (DestinationAddress->si_family == AF_INET6)
    return Ipv6BestRoute(InterfaceLuid, InterfaceIndex, SourceAddress, DestinationAddress, BestRoute,
                         BestSourceAddress);

  if (InterfaceLuid && InterfaceLuid->Value)
  {
    if (!getInterfaceIndexByLuid(InterfaceLuid->Value, &IfIndex))
      return ERROR_NOT_FOUND;
    Constrained = TRUE;
  }
  else if (InterfaceIndex)
  {
    IfIndex = InterfaceIndex;
    if (!if_index_to_luid(IfIndex, NULL, &Luid))
      return ERROR_FILE_NOT_FOUND;
    Constrained = TRUE;
  }

  if (SourceAddress && SourceAddress->si_family == AF_INET && SourceAddress->Ipv4.sin_addr.s_addr)
  {
    Source = SourceAddress->Ipv4.sin_addr.s_addr;
    if (!find_local_address(Source, FALSE, FALSE, 0, &SourceIf))
      return ERROR_NOT_FOUND;
    if (Constrained && SourceIf != IfIndex)
      return ERROR_NETWORK_UNREACHABLE;
    IfIndex = SourceIf;
    Constrained = TRUE;
  }

  Dest = DestinationAddress->Ipv4.sin_addr.s_addr;

  /* an address or broadcast of the interface asked for is found first, then any other's */
  Local = Constrained && find_local_address(Dest, TRUE, TRUE, IfIndex, &OwnerIf);
  if (!Local)
    Local = find_local_address(Dest, TRUE, FALSE, 0, &OwnerIf);
  if (!Local && Dest == INADDR_NONE)
  {
    /* the limited broadcast goes out over the interface asked for, else over the first one with an address */
    if (Constrained)
    {
      OwnerIf = IfIndex;
      Local = TRUE;
    }
    else
      Local = find_broadcast_interface(&OwnerIf);
  }

  if (Local)
  {
    if (Constrained && OwnerIf != IfIndex)
    {
      /* the 127.0.0.0/8 addresses exist on the loopback interface alone */
      if (if_index_to_luid(IfIndex, &Type, &Luid) && (Dest & 0xff) == 127 && Type != IF_TYPE_SOFTWARE_LOOPBACK)
        return ERROR_INVALID_PARAMETER;
      return ERROR_NETWORK_UNREACHABLE;
    }
    Filled = fill_best_route(BestRoute, BestSourceAddress, OwnerIf, Dest, 32, 0, ON_LINK_METRIC, TRUE,
                             Source ? Source : getInterfaceIPAddrByIndex(OwnerIf));
    return Filled ? NO_ERROR : ERROR_NOT_FOUND;
  }

  Table = getRouteTable();
  if (!Table)
    return ERROR_OUTOFMEMORY;

  /* the longest matching prefix wins, then the lowest metric */
  for (i = 0; i < Table->numRoutes; i++)
  {
    RouteEntry *Route = &Table->routes[i];
    ULONG Length = mask_prefix_length(Route->mask);

    if ((Dest & Route->mask) != (Route->dest & Route->mask))
      continue;
    if (Constrained && Route->ifIndex != IfIndex)
      continue;
    if (!Found || Length > MatchedLength || (Length == MatchedLength && Route->metric < Table->routes[Matched].metric))
    {
      Found = TRUE;
      Matched = i;
      MatchedLength = Length;
    }
  }

  Filled = FALSE;
  if (Found)
  {
    RouteEntry *Route = &Table->routes[Matched];
    IPAddr Own = getInterfaceIPAddrByIndex(Route->ifIndex);
    BOOL OnLink = !Route->gateway || Route->gateway == Own;

    /* a gateway that is the interface address, or none, means the destination is on the link */
    Filled = fill_best_route(BestRoute, BestSourceAddress, Route->ifIndex, Route->dest & Route->mask, MatchedLength,
                             OnLink ? 0 : Route->gateway,
                             OnLink ? ON_LINK_METRIC : route_own_metric(Route->metric, Route->ifIndex), FALSE, Source);
  }
  HeapFree(GetProcessHeap(), 0, Table);

  if (!Found)
    return ERROR_NETWORK_UNREACHABLE;
  return Filled ? NO_ERROR : ERROR_NOT_FOUND;
}

/******************************************************************
 *    GetBestInterfaceEx (IPHLPAPI.@)
 *
 * Find the interface a packet to a destination leaves by.
 *
 * NOTES
 *  The measured Windows behaviour is followed, on top of the route lookup of GetBestRoute2:
 *  0.0.0.0/8 (but the unspecified address) and the class E range (but the limited broadcast)
 *  have no route, the default route is not taken for a link-local destination (which then
 *  succeeds with interface 0), and so does 224.0.0.1, a group every host has joined. Windows
 *  gives interface 0 to the other groups this computer joined too; the stack here lists none.
 *  The limited broadcast takes the interface GetBestRoute2 gives it; Windows takes the lowest
 *  metric of its 255.255.255.255 routes, which the stack here does not have.
 *  IPv6 destinations take the interface of their GetBestRoute2 route.
 */
DWORD WINAPI GetBestInterfaceEx(struct sockaddr *pDestAddr, PDWORD pdwBestIfIndex)
{
  SOCKADDR_INET Dest, Source;
  MIB_IPFORWARD_ROW2 Row;
  ULONG Host = 0;
  DWORD Result;

  TRACE("(%p, %p)\n", pDestAddr, pdwBestIfIndex);

  if (!pDestAddr || !pdwBestIfIndex)
    return ERROR_INVALID_PARAMETER;

  memset(&Dest, 0, sizeof(Dest));
  if (pDestAddr->sa_family == AF_INET)
  {
    Dest.Ipv4.sin_family = AF_INET;
    Dest.Ipv4.sin_addr = ((SOCKADDR_IN *)pDestAddr)->sin_addr;
    Host = ntohl(Dest.Ipv4.sin_addr.s_addr);

    if (Host && !(Host >> 24))
      return ERROR_NETWORK_UNREACHABLE;
    if ((Host >> 28) == 0xf && Host != 0xffffffff)
      return ERROR_NETWORK_UNREACHABLE;
    if (Host == 0xe0000001)
    {
      *pdwBestIfIndex = 0;
      return NO_ERROR;
    }
  }
  else if (pDestAddr->sa_family == AF_INET6)
    Dest.Ipv6 = *(SOCKADDR_IN6 *)pDestAddr;
  else
    return ERROR_INVALID_PARAMETER;

  Result = GetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
  if ((Host >> 16) == 0xa9fe && (Result == ERROR_NETWORK_UNREACHABLE ||
                                 (Result == NO_ERROR && !Row.DestinationPrefix.PrefixLength)))
  {
    *pdwBestIfIndex = 0;
    return NO_ERROR;
  }
  if (Result != NO_ERROR)
    return Result;

  *pdwBestIfIndex = Row.InterfaceIndex;
  return NO_ERROR;
}

static UINT8 mask_length_of(DWORD Mask)
{
  DWORD Host = ntohl(Mask);
  UINT8 Length = 0;

  for (; Host & 0x80000000UL; Host <<= 1)
    Length++;
  return Length;
}

/* The IPv4 routing table as MIB_IPFORWARD_ROW2 rows (an empty one is NO_ERROR and no row) */
DWORD Ipv4GetRouteRows(PMIB_IPFORWARD_ROW2 *Rows, ULONG *Count)
{
  PMIB_IPFORWARDTABLE Table = NULL;
  PMIB_IPFORWARD_ROW2 Out;
  ULONG Size = 0, Tries, i;
  DWORD Result = ERROR_INSUFFICIENT_BUFFER;
  DWORD LastIndex = 0xffffffff;
  ULONG64 LastLuid = 0;
  ULONG LastMetric = 0;

  *Rows = NULL;
  *Count = 0;
  for (Tries = 0; Tries < 3 && Result == ERROR_INSUFFICIENT_BUFFER; Tries++)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    Table = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Size && !Table)
      return ERROR_NOT_ENOUGH_MEMORY;
    Result = GetIpForwardTable(Table, &Size, FALSE);
  }
  if (Result == ERROR_NO_DATA)
  {
    /* no routes at all */
    HeapFree(GetProcessHeap(), 0, Table);
    *Rows = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Out));
    return *Rows ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
  }
  if (Result != NO_ERROR)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return Result;
  }

  Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)(Table->dwNumEntries + 1) * sizeof(*Out));
  if (!Out)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  for (i = 0; i < Table->dwNumEntries; i++)
  {
    const MIB_IPFORWARDROW *Row = &Table->table[i];
    PMIB_IPFORWARD_ROW2 New = &Out[i];

    if (Row->dwForwardIfIndex != LastIndex)
    {
      LastIndex = Row->dwForwardIfIndex;
      if (!getInterfaceLuidByIndex(LastIndex, NULL, &LastLuid))
        LastLuid = 0;
      LastMetric = Ipv4InterfaceMetric(LastIndex);
    }
    New->InterfaceLuid.Value = LastLuid;
    New->InterfaceIndex = Row->dwForwardIfIndex;
    New->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    New->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = Row->dwForwardDest;
    New->DestinationPrefix.PrefixLength = mask_length_of(Row->dwForwardMask);
    New->NextHop.Ipv4.sin_family = AF_INET;
    New->NextHop.Ipv4.sin_addr.s_addr = Row->dwForwardNextHop;
    New->ValidLifetime = 0xffffffff;
    New->PreferredLifetime = 0xffffffff;
    New->Metric = Row->dwForwardMetric1 > LastMetric ? Row->dwForwardMetric1 - LastMetric : 0;
    New->Protocol = Row->dwForwardProto;
    New->Age = Row->dwForwardAge;
  }
  *Count = Table->dwNumEntries;
  *Rows = Out;
  HeapFree(GetProcessHeap(), 0, Table);
  return NO_ERROR;
}

/******************************************************************
 *    GetIpForwardTable2 (IPHLPAPI.@)
 *
 * The routes of the stack: the IPv4 routing table, then the IPv6 routes (Ipv6GetRouteRows). The rows of an
 * address family that is not asked for are left out. FreeMibTable frees the table.
 */
DWORD WINAPI GetIpForwardTable2(ADDRESS_FAMILY Family, PMIB_IPFORWARD_TABLE2 *Table)
{
  PMIB_IPFORWARD_ROW2 Rows4 = NULL, Rows6 = NULL;
  ULONG Count4 = 0, Count6 = 0;
  PMIB_IPFORWARD_TABLE2 Out;
  DWORD Result;

  TRACE("(%u, %p)\n", Family, Table);

  if (!Table || (Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;
  *Table = NULL;

  if (Family != AF_INET6)
  {
    Result = Ipv4GetRouteRows(&Rows4, &Count4);
    if (Result != NO_ERROR)
      return Result;
  }
  if (Family != AF_INET)
  {
    Result = Ipv6GetRouteRows(&Rows6, &Count6);
    if (Result != NO_ERROR)
    {
      HeapFree(GetProcessHeap(), 0, Rows4);
      return Result;
    }
  }

  Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  FIELD_OFFSET(MIB_IPFORWARD_TABLE2, Table) + (SIZE_T)(Count4 + Count6 + 1) * sizeof(MIB_IPFORWARD_ROW2));
  if (Out)
  {
    if (Count4)
      memcpy(Out->Table, Rows4, (SIZE_T)Count4 * sizeof(MIB_IPFORWARD_ROW2));
    if (Count6)
      memcpy(Out->Table + Count4, Rows6, (SIZE_T)Count6 * sizeof(MIB_IPFORWARD_ROW2));
    Out->NumEntries = Count4 + Count6;
    *Table = Out;
  }
  HeapFree(GetProcessHeap(), 0, Rows4);
  HeapFree(GetProcessHeap(), 0, Rows6);
  return Out ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}
