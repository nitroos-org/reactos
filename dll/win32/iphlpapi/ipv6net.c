/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 neighbours, routes, best route and statistics from the stack's IPv6 state
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include "ipv6net.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/*
 * The stack keeps no routing table for IPv6, so the one Windows reports is built from what it has: the
 * addresses of the interfaces (a host route for each, ::1/128 on the loopback interface), the link-local prefix
 * of each interface that has such an address, the multicast prefix of every interface, the on-link prefixes and
 * the default routers router advertisements gave. The layout follows what Windows 10 reports for the first
 * three (oracle probe: protocol Local, metric 256, Loopback set on the host routes, ff00::/8 of origin well known,
 * sorted by prefix, length and interface); the rows from router advertisements are NetMgmt routes of origin
 * RouterAdvertisement with the metric of a medium preference router, which that probe could not show (its network
 * sends no advertisement). The neighbour cache is the stack's; the multicast groups the stack receives
 * on an Ethernet interface (the all-nodes group and the solicited-node group of each address) are Permanent
 * entries with their Ethernet address, as Windows lists them.
 */

#define ROUTE_METRIC            256
#define PROTOCOL_LOCAL          2
#define PROTOCOL_NETMGMT        3
#define ORIGIN_MANUAL           0
#define ORIGIN_WELLKNOWN        1
#define ORIGIN_ROUTERADV        3

#define DAD_TENTATIVE           1
#define DAD_DUPLICATE           2
#define DAD_DEPRECATED          3
#define DAD_PREFERRED           4

/* NL_NEIGHBOR_STATE */
#define NEIGHBOR_PERMANENT      6

/* ---- the stack's answers ---- */

BOOL Ipv6GetNdFromFile(HANDLE TcpFile, PIPV6_ND_STATE State)
{
  PVOID Blob = NULL;
  DWORD Size = 0;
  PTCP_IPV6_ND_HEADER Header;
  SIZE_T Needed;
  NTSTATUS Status;

  RtlZeroMemory(State, sizeof(*State));

  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_IPV6_ND_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  Header = Blob;
  if (Size < sizeof(*Header) || !Header->Enabled)
    goto Off;
  if (Header->NeighborCount > 0xFFFF || Header->PrefixCount > 0xFFFF)
    goto Off;
  Needed = (SIZE_T)sizeof(*Header) + (SIZE_T)Header->NeighborCount * sizeof(TCP_IPV6_NEIGHBOR_ROW) +
           (SIZE_T)Header->PrefixCount * sizeof(TCP_IPV6_PREFIX_ROW);
  if (Needed > Size)
    goto Off;

  State->Memory = Blob;
  State->Header = Header;
  State->Neighbors = (PTCP_IPV6_NEIGHBOR_ROW)(Header + 1);
  State->Prefixes = (PTCP_IPV6_PREFIX_ROW)(State->Neighbors + Header->NeighborCount);
  return TRUE;

Off:
  tdiFreeThingSet(Blob);
  return FALSE;
}

VOID Ipv6FreeNd(PIPV6_ND_STATE State)
{
  if (State->Memory)
    tdiFreeThingSet(State->Memory);
  RtlZeroMemory(State, sizeof(*State));
}

/* The route table of the stack (IP_IPV6_ROUTE_ENTRY_ID): the configured routes and those router advertisements gave */
typedef struct _IPV6_ROUTE_STATE
{
  PVOID Memory;
  PTCP_IPV6_ROUTE_HEADER Header;
  PTCP_IPV6_ROUTE_ROW Rows;
} IPV6_ROUTE_STATE;

static BOOL get_routes_from_file(HANDLE TcpFile, IPV6_ROUTE_STATE *State)
{
  PVOID Blob = NULL;
  DWORD Size = 0;
  PTCP_IPV6_ROUTE_HEADER Header;
  NTSTATUS Status;

  memset(State, 0, sizeof(*State));
  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_IPV6_ROUTE_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  Header = Blob;
  if (Size < sizeof(*Header) || !Header->Enabled || Header->Count > 0xFFFF ||
      (SIZE_T)sizeof(*Header) + (SIZE_T)Header->Count * sizeof(TCP_IPV6_ROUTE_ROW) > Size)
  {
    tdiFreeThingSet(Blob);
    return FALSE;
  }
  State->Memory = Blob;
  State->Header = Header;
  State->Rows = (PTCP_IPV6_ROUTE_ROW)(Header + 1);
  return TRUE;
}

/* Everything the tables below are built from, taken together. FALSE: IPv6 is off (nothing to free) */
typedef struct _IPV6_ALL
{
  IPV6_STATE State;
  IPV6_ND_STATE Nd;
  IPV6_DNS_STATE Dns;
  IPV6_ROUTE_STATE Routes;
} IPV6_ALL;

static BOOL get_all(IPV6_ALL *All)
{
  HANDLE TcpFile;
  BOOL On;

  memset(All, 0, sizeof(*All));
  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;

  On = Ipv6GetStateFromFile(TcpFile, &All->State);
  if (On)
  {
    /* a stack without these queries has neither neighbours nor prefixes nor routers to show */
    Ipv6GetNdFromFile(TcpFile, &All->Nd);
    Ipv6GetDnsFromFile(TcpFile, &All->Dns);
    get_routes_from_file(TcpFile, &All->Routes);
  }
  closeTcpFile(TcpFile);
  return On;
}

static void free_all(IPV6_ALL *All)
{
  Ipv6FreeState(&All->State);
  Ipv6FreeNd(&All->Nd);
  Ipv6FreeDns(&All->Dns);
  if (All->Routes.Memory)
    tdiFreeThingSet(All->Routes.Memory);
  memset(&All->Routes, 0, sizeof(All->Routes));
}

static BOOL is_link_local(const UCHAR *Address)
{
  return Address[0] == 0xfe && (Address[1] & 0xc0) == 0x80;
}

static BOOL if_luid(DWORD Index, NET_LUID *Luid)
{
  Luid->Value = 0;
  return getInterfaceLuidByIndex(Index, NULL, &Luid->Value);
}

static void set_v6(SOCKADDR_INET *Out, const UCHAR *Address, ULONG Scope)
{
  memset(Out, 0, sizeof(*Out));
  Out->Ipv6.sin6_family = AF_INET6;
  if (Address)
    memcpy(&Out->Ipv6.sin6_addr, Address, 16);
  Out->Ipv6.sin6_scope_id = Scope;
}

/* ---- neighbours ---- */

typedef struct _NEIGHBOR_LIST
{
  PMIB_IPNET_ROW2 Rows;
  ULONG Count, Max;
  BOOL Failed;
} NEIGHBOR_LIST;

static PMIB_IPNET_ROW2 add_neighbor(NEIGHBOR_LIST *List, DWORD IfIndex, const UCHAR *Address, ULONG State)
{
  PMIB_IPNET_ROW2 Row;
  NET_LUID Luid;

  if (List->Failed || !if_luid(IfIndex, &Luid))
    return NULL;
  if (List->Count == List->Max)
  {
    ULONG Max = List->Max ? List->Max * 2 : 16;
    PMIB_IPNET_ROW2 New = List->Rows ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, List->Rows, Max * sizeof(*New))
                                     : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Max * sizeof(*New));

    if (!New)
    {
      List->Failed = TRUE;
      return NULL;
    }
    List->Rows = New;
    List->Max = Max;
  }

  Row = &List->Rows[List->Count++];
  memset(Row, 0, sizeof(*Row));
  set_v6(&Row->Address, Address, 0);
  Row->InterfaceIndex = IfIndex;
  Row->InterfaceLuid = Luid;
  Row->State = State;
  return Row;
}

static int __cdecl compare_neighbors(const void *A, const void *B)
{
  const MIB_IPNET_ROW2 *X = A, *Y = B;

  if (X->InterfaceIndex != Y->InterfaceIndex)
    return X->InterfaceIndex < Y->InterfaceIndex ? -1 : 1;
  return memcmp(&X->Address.Ipv6.sin6_addr, &Y->Address.Ipv6.sin6_addr, 16);
}

/* The solicited-node group of an address, and its Ethernet address (RFC 4291 2.7.1, RFC 2464 7) */
static void solicited_node(const UCHAR *Address, UCHAR *Group, UCHAR *Mac)
{
  memset(Group, 0, 16);
  Group[0] = 0xff;
  Group[1] = 0x02;
  Group[11] = 0x01;
  Group[12] = 0xff;
  memcpy(Group + 13, Address + 13, 3);
  Mac[0] = Mac[1] = 0x33;
  memcpy(Mac + 2, Group + 12, 4);
}

static void add_group(NEIGHBOR_LIST *List, DWORD IfIndex, const UCHAR *Group, const UCHAR *Mac)
{
  ULONG i;
  PMIB_IPNET_ROW2 Row;

  for (i = 0; i < List->Count; i++)
    if (List->Rows[i].InterfaceIndex == IfIndex && !memcmp(&List->Rows[i].Address.Ipv6.sin6_addr, Group, 16))
      return;
  Row = add_neighbor(List, IfIndex, Group, NEIGHBOR_PERMANENT);
  if (!Row)
    return;
  memcpy(Row->PhysicalAddress, Mac, 6);
  Row->PhysicalAddressLength = 6;
}

DWORD Ipv6GetNeighborRows(PMIB_IPNET_ROW2 *Rows, ULONG *Count)
{
  IPV6_ALL All;
  NEIGHBOR_LIST List = { NULL, 0, 0, FALSE };
  ULONG i;

  *Rows = NULL;
  *Count = 0;
  if (!get_all(&All))
    return NO_ERROR;

  for (i = 0; All.Nd.Header && i < All.Nd.Header->NeighborCount; i++)
  {
    const TCP_IPV6_NEIGHBOR_ROW *Source = &All.Nd.Neighbors[i];
    PMIB_IPNET_ROW2 Row = add_neighbor(&List, Source->IfIndex, Source->Address, Source->State);
    ULONG Length = Source->LinkLength;

    if (!Row)
      continue;
    if (Length > sizeof(Source->LinkAddress))
      Length = sizeof(Source->LinkAddress);
    memcpy(Row->PhysicalAddress, Source->LinkAddress, Length);
    Row->PhysicalAddressLength = Length;
    Row->Flags = (Source->Flags & TCP_IPV6_NEIGHBOR_ROUTER) ? 1 : 0;
    Row->ReachabilityTime.LastReachable = (Source->State == 5) ? GetTickCount() : 0;
  }

  /* the groups an Ethernet interface receives: all nodes, and the solicited-node group of each address */
  for (i = 0; i < All.State.Header->InterfaceCount; i++)
  {
    const TCP_IPV6_INTERFACE_ROW *If = &All.State.Interfaces[i];
    static const UCHAR AllNodes[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    static const UCHAR AllNodesMac[6] = { 0x33, 0x33, 0, 0, 0, 1 };
    ULONG j;

    if (!(If->Flags & TCP_IPV6_IF_ENABLED) || (If->Flags & TCP_IPV6_IF_LOOPBACK))
      continue;
    add_group(&List, If->IfIndex, AllNodes, AllNodesMac);
    for (j = 0; j < All.State.Header->AddressCount; j++)
    {
      const TCP_IPV6_ADDRESS_ROW *Address = &All.State.Addresses[j];
      UCHAR Group[16], Mac[6];

      if (Address->IfIndex != If->IfIndex || Address->DadState == DAD_DUPLICATE)
        continue;
      solicited_node(Address->Address, Group, Mac);
      add_group(&List, If->IfIndex, Group, Mac);
    }
  }
  free_all(&All);

  if (List.Failed)
  {
    HeapFree(GetProcessHeap(), 0, List.Rows);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  if (List.Count > 1)
    qsort(List.Rows, List.Count, sizeof(*List.Rows), compare_neighbors);
  *Rows = List.Rows;
  *Count = List.Count;
  return NO_ERROR;
}

/* ---- the owner of an address ---- */

BOOL Ipv6FindOwner(const UCHAR *Address, DWORD Scope, PDWORD IfIndex)
{
  IPV6_STATE State;
  BOOL Found = FALSE;
  ULONG i;

  if (!Ipv6GetState(&State))
    return FALSE;
  for (i = 0; i < State.Header->AddressCount && !Found; i++)
  {
    const TCP_IPV6_ADDRESS_ROW *Row = &State.Addresses[i];

    if (memcmp(Row->Address, Address, 16))
      continue;
    /* a link-local address is the same on every interface; the zone tells which one */
    if (is_link_local(Address) && Scope && Row->IfIndex != Scope)
      continue;
    *IfIndex = Row->IfIndex;
    Found = TRUE;
  }
  Ipv6FreeState(&State);
  return Found;
}

static BOOL is_any(const UCHAR *Address)
{
  static const UCHAR Zero[16];

  return !memcmp(Address, Zero, 16);
}

static BOOL is_loopback_address(const UCHAR *Address)
{
  static const UCHAR Loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

  return !memcmp(Address, Loopback, 16);
}

static BOOL is_v4_mapped(const UCHAR *Address)
{
  static const UCHAR Prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

  return !memcmp(Address, Prefix, 12);
}

static BOOL usable_state(ULONG DadState)
{
  return DadState == DAD_PREFERRED || DadState == DAD_DEPRECATED;
}

/* ---- routes ---- */

typedef struct _ROUTE_LIST
{
  PMIB_IPFORWARD_ROW2 Rows;
  ULONG Count, Max;
  BOOL Failed;
} ROUTE_LIST;

static PMIB_IPFORWARD_ROW2 add_route(ROUTE_LIST *List, DWORD IfIndex, const UCHAR *Prefix, ULONG Length,
                                     const UCHAR *Gateway, ULONG Origin, BOOLEAN Loopback, ULONG Lifetime)
{
  PMIB_IPFORWARD_ROW2 Row;
  NET_LUID Luid;

  if (List->Failed || !if_luid(IfIndex, &Luid))
    return NULL;
  if (List->Count == List->Max)
  {
    ULONG Max = List->Max ? List->Max * 2 : 16;
    PMIB_IPFORWARD_ROW2 New = List->Rows ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, List->Rows, Max * sizeof(*New))
                                         : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Max * sizeof(*New));

    if (!New)
    {
      List->Failed = TRUE;
      return NULL;
    }
    List->Rows = New;
    List->Max = Max;
  }

  Row = &List->Rows[List->Count++];
  memset(Row, 0, sizeof(*Row));
  Row->InterfaceLuid = Luid;
  Row->InterfaceIndex = IfIndex;
  set_v6(&Row->DestinationPrefix.Prefix, Prefix, 0);
  Row->DestinationPrefix.PrefixLength = Length;
  set_v6(&Row->NextHop, Gateway, (Gateway && is_link_local(Gateway)) ? IfIndex : 0);
  /* the stack keeps the lifetime of the route it learnt, a route of its own lasts */
  Row->ValidLifetime = Row->PreferredLifetime = Lifetime;
  Row->Metric = ROUTE_METRIC;
  Row->Protocol = (Origin == ORIGIN_ROUTERADV) ? PROTOCOL_NETMGMT : PROTOCOL_LOCAL;
  Row->Loopback = Loopback;
  Row->AutoconfigureAddress = TRUE;
  Row->Origin = Origin;
  return Row;
}

static int __cdecl compare_routes(const void *A, const void *B)
{
  const MIB_IPFORWARD_ROW2 *X = A, *Y = B;
  int Order = memcmp(&X->DestinationPrefix.Prefix.Ipv6.sin6_addr, &Y->DestinationPrefix.Prefix.Ipv6.sin6_addr, 16);

  if (Order)
    return Order;
  if (X->DestinationPrefix.PrefixLength != Y->DestinationPrefix.PrefixLength)
    return X->DestinationPrefix.PrefixLength < Y->DestinationPrefix.PrefixLength ? -1 : 1;
  if (X->InterfaceIndex != Y->InterfaceIndex)
    return X->InterfaceIndex < Y->InterfaceIndex ? -1 : 1;
  return 0;
}

static DWORD build_routes(const IPV6_ALL *All, PMIB_IPFORWARD_ROW2 *Rows, ULONG *Count)
{
  static const UCHAR LinkLocalPrefix[16] = { 0xfe, 0x80 };
  static const UCHAR MulticastPrefix[16] = { 0xff };
  static const UCHAR Any[16];
  ROUTE_LIST List = { NULL, 0, 0, FALSE };
  ULONG i, j;

  for (i = 0; i < All->State.Header->InterfaceCount; i++)
  {
    const TCP_IPV6_INTERFACE_ROW *If = &All->State.Interfaces[i];
    BOOL Loopback = (If->Flags & TCP_IPV6_IF_LOOPBACK) != 0, HaveLinkLocal = FALSE;

    if (!(If->Flags & TCP_IPV6_IF_ENABLED))
      continue;

    for (j = 0; j < All->State.Header->AddressCount; j++)
    {
      const TCP_IPV6_ADDRESS_ROW *Address = &All->State.Addresses[j];

      if (Address->IfIndex != If->IfIndex || Address->DadState == DAD_DUPLICATE)
        continue;
      if (is_link_local(Address->Address))
        HaveLinkLocal = TRUE;
      /* a host route for each address that works; the loopback interface has ::1 */
      if (usable_state(Address->DadState) && (!Loopback || is_loopback_address(Address->Address)))
        add_route(&List, If->IfIndex, Address->Address, 128, NULL, ORIGIN_MANUAL, TRUE, 0xffffffff);
    }
    if (!Loopback && HaveLinkLocal)
      add_route(&List, If->IfIndex, LinkLocalPrefix, 64, NULL, ORIGIN_MANUAL, FALSE, 0xffffffff);
    add_route(&List, If->IfIndex, MulticastPrefix, 8, NULL, ORIGIN_WELLKNOWN, FALSE, 0xffffffff);
  }

  /* the stack's route table: the configured routes, and the on-link prefixes and default routers router
     advertisements gave (the same rows as from the neighbour discovery and DNS tables below, which a stack without
     the route table query still answers) */
  for (i = 0; All->Routes.Header && i < All->Routes.Header->Count; i++)
  {
    const TCP_IPV6_ROUTE_ROW *Route = &All->Routes.Rows[i];
    PMIB_IPFORWARD_ROW2 Row;

    if (!Ipv6FindInterface(&All->State, Route->IfIndex))
      continue;
    Row = add_route(&List, Route->IfIndex, Route->Prefix, Route->PrefixLength,
                    is_any(Route->NextHop) ? NULL : Route->NextHop, Route->Origin, FALSE, Route->ValidLifetime);
    if (!Row)
      continue;
    /* the metric of a route of an advertisement is the one of its preference (medium: the usual 256) */
    if (Route->Flags & TCP_IPV6_ROUTE_FROM_RA)
    {
      Row->Metric = Route->Metric;
      continue;
    }
    /* a configured route: what was asked for it */
    Row->PreferredLifetime = Route->PreferredLifetime;
    Row->Metric = Route->Metric;
    Row->Protocol = Route->Protocol;
    Row->Publish = (Route->Flags & TCP_IPV6_ROUTE_PUBLISH) != 0;
    Row->Immortal = (Route->Flags & TCP_IPV6_ROUTE_IMMORTAL) != 0;
    Row->AutoconfigureAddress = (Route->Flags & TCP_IPV6_ROUTE_NO_AUTOCONFIGURE) == 0;
    Row->Age = Route->Age;
  }

  for (i = 0; !All->Routes.Header && All->Nd.Header && i < All->Nd.Header->PrefixCount; i++)
  {
    const TCP_IPV6_PREFIX_ROW *Prefix = &All->Nd.Prefixes[i];

    if (Ipv6FindInterface(&All->State, Prefix->IfIndex))
      add_route(&List, Prefix->IfIndex, Prefix->Prefix, Prefix->PrefixLength, NULL, ORIGIN_ROUTERADV, FALSE,
                Prefix->Lifetime);
  }
  for (i = 0; !All->Routes.Header && All->Dns.Header && i < All->Dns.Header->Count; i++)
  {
    const TCP_IPV6_DNS_ROW *Router = &All->Dns.Rows[i];

    if (Router->Kind == TCP_IPV6_DNS_ROUTER && Ipv6FindInterface(&All->State, Router->IfIndex))
      add_route(&List, Router->IfIndex, Any, 0, Router->Address, ORIGIN_ROUTERADV, FALSE, Router->Lifetime);
  }

  if (List.Failed)
  {
    HeapFree(GetProcessHeap(), 0, List.Rows);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  if (List.Count > 1)
    qsort(List.Rows, List.Count, sizeof(*List.Rows), compare_routes);
  *Rows = List.Rows;
  *Count = List.Count;
  return NO_ERROR;
}

DWORD Ipv6GetRouteRows(PMIB_IPFORWARD_ROW2 *Rows, ULONG *Count)
{
  IPV6_ALL All;
  DWORD Result;

  *Rows = NULL;
  *Count = 0;
  if (!get_all(&All))
    return NO_ERROR;
  Result = build_routes(&All, Rows, Count);
  free_all(&All);
  return Result;
}

/* ---- the best route ---- */

/* The number of leading bits two addresses share */
static ULONG common_bits(const UCHAR *A, const UCHAR *B)
{
  ULONG Bits = 0, i;
  UCHAR Diff;

  for (i = 0; i < 16 && A[i] == B[i]; i++)
    Bits += 8;
  if (i == 16)
    return Bits;
  for (Diff = A[i] ^ B[i]; !(Diff & 0x80); Diff <<= 1)
    Bits++;
  return Bits;
}

/* A temporary address (RFC 8981): the stack reports its suffix origin as IpSuffixOriginRandom */
static int is_temporary(const TCP_IPV6_ADDRESS_ROW *Row)
{
  return Row->SuffixOrigin == IpSuffixOriginRandom ? 1 : 0;
}

/* The address a packet to Dest leaves with over interface IfIndex */
static void pick_source(const IPV6_ALL *All, DWORD IfIndex, const UCHAR *Dest, SOCKADDR_INET *Source)
{
  const TCP_IPV6_ADDRESS_ROW *LinkLocal = NULL, *Global = NULL, *Loopback = NULL, *Own = NULL;
  const TCP_IPV6_ADDRESS_ROW *Chosen;
  ULONG i;

  for (i = 0; i < All->State.Header->AddressCount; i++)
  {
    const TCP_IPV6_ADDRESS_ROW *Row = &All->State.Addresses[i];

    if (Row->IfIndex != IfIndex || !usable_state(Row->DadState))
      continue;
    if (!memcmp(Row->Address, Dest, 16))
      Own = Row;
    /* an address configured with skip-as-source is not chosen (only bound to) */
    if (Row->Flags & TCP_IPV6_ADDRESS_SKIP_AS_SOURCE)
      continue;
    if (is_loopback_address(Row->Address))
      Loopback = Row;
    else if (is_link_local(Row->Address))
    {
      if (!LinkLocal)
        LinkLocal = Row;
    }
    /* a preferred address before a deprecated one, a temporary one (suffix origin Random) before a public one,
       then the longest prefix in common with the destination (RFC 6724 rules 3, 7 and 8, as the stack chooses) */
    else if (!Global || (Global->DadState != DAD_PREFERRED && Row->DadState == DAD_PREFERRED) ||
             (Global->DadState == Row->DadState &&
              (is_temporary(Row) > is_temporary(Global) ||
               (is_temporary(Row) == is_temporary(Global) &&
                common_bits(Row->Address, Dest) > common_bits(Global->Address, Dest)))))
      Global = Row;
  }

  if (Own)
    Chosen = Own;
  else if (Loopback)
    Chosen = Loopback;
  else if (Dest[0] == 0xff || is_link_local(Dest))
    Chosen = LinkLocal ? LinkLocal : Global;
  else
    Chosen = Global ? Global : LinkLocal;

  if (!Chosen)
  {
    set_v6(Source, NULL, 0);
    return;
  }
  set_v6(Source, Chosen->Address, is_link_local(Chosen->Address) ? IfIndex : 0);
}

static void empty_route(PMIB_IPFORWARD_ROW2 Route)
{
  memset(Route, 0, sizeof(*Route));
  set_v6(&Route->DestinationPrefix.Prefix, NULL, 0);
  set_v6(&Route->NextHop, NULL, 0);
}

static BOOL prefix_covers(const UCHAR *Prefix, ULONG Length, const UCHAR *Address)
{
  ULONG Bytes = Length / 8, Bits = Length % 8;

  if (Bytes && memcmp(Prefix, Address, Bytes))
    return FALSE;
  if (Bits && ((Prefix[Bytes] ^ Address[Bytes]) & (0xff << (8 - Bits)) & 0xff))
    return FALSE;
  return TRUE;
}

/* A v4-mapped destination is routed as the IPv4 address, the answer is in v4-mapped form */
static void map_v4(SOCKADDR_INET *Out, const SOCKADDR_INET *In)
{
  UCHAR Mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

  memcpy(Mapped + 12, &In->Ipv4.sin_addr, 4);
  set_v6(Out, Mapped, 0);
}

static DWORD best_route_v4_mapped(const NET_LUID *Luid, NET_IFINDEX IfIndex, const SOCKADDR_INET *Source,
                                  const SOCKADDR_INET *Dest, PMIB_IPFORWARD_ROW2 Route, SOCKADDR_INET *BestSource)
{
  SOCKADDR_INET Dest4, Source4, Best4;
  MIB_IPFORWARD_ROW2 Route4;
  DWORD Result;

  memset(&Dest4, 0, sizeof(Dest4));
  Dest4.Ipv4.sin_family = AF_INET;
  memcpy(&Dest4.Ipv4.sin_addr, Dest->Ipv6.sin6_addr.u.Byte + 12, 4);
  if (Source && Source->si_family == AF_INET6 && !is_any(Source->Ipv6.sin6_addr.u.Byte))
  {
    if (!is_v4_mapped(Source->Ipv6.sin6_addr.u.Byte))
      return ERROR_NOT_FOUND;
    memset(&Source4, 0, sizeof(Source4));
    Source4.Ipv4.sin_family = AF_INET;
    memcpy(&Source4.Ipv4.sin_addr, Source->Ipv6.sin6_addr.u.Byte + 12, 4);
    Source = &Source4;
  }
  else
    Source = NULL;

  Result = GetBestRoute2((NET_LUID *)Luid, IfIndex, Source, &Dest4, 0, &Route4, &Best4);
  if (Result != NO_ERROR)
    return Result;

  *Route = Route4;
  map_v4(&Route->DestinationPrefix.Prefix, &Route4.DestinationPrefix.Prefix);
  Route->DestinationPrefix.PrefixLength = Route4.DestinationPrefix.PrefixLength + 96;
  map_v4(&Route->NextHop, &Route4.NextHop);
  map_v4(BestSource, &Best4);
  return NO_ERROR;
}

DWORD Ipv6BestRoute(const NET_LUID *InterfaceLuid, NET_IFINDEX InterfaceIndex, const SOCKADDR_INET *SourceAddress,
                    const SOCKADDR_INET *DestinationAddress, PMIB_IPFORWARD_ROW2 BestRoute,
                    SOCKADDR_INET *BestSourceAddress)
{
  const UCHAR *Dest = DestinationAddress->Ipv6.sin6_addr.u.Byte;
  IPV6_ALL All;
  DWORD Index = 0, Owner, Result;
  BOOL Constrained = FALSE, ScopedByDest = FALSE, Found = FALSE;
  ULONG i, Best = 0;
  PMIB_IPFORWARD_ROW2 Rows = NULL;
  ULONG Count = 0;
  NET_LUID Luid;

  /* the unspecified address has no route, with or without IPv6 */
  if (is_any(Dest))
    return ERROR_NOT_FOUND;

  if (!get_all(&All))
  {
    /* IPv6 is off: no IPv6 destination can be reached */
    return ERROR_NETWORK_UNREACHABLE;
  }

  if (is_v4_mapped(Dest))
  {
    free_all(&All);
    return best_route_v4_mapped(InterfaceLuid, InterfaceIndex, SourceAddress, DestinationAddress, BestRoute,
                                BestSourceAddress);
  }

  if (InterfaceLuid && InterfaceLuid->Value)
  {
    if (!getInterfaceIndexByLuid(InterfaceLuid->Value, &Index))
    {
      free_all(&All);
      return ERROR_NOT_FOUND;
    }
    Constrained = TRUE;
  }
  else if (InterfaceIndex)
  {
    if (!if_luid(InterfaceIndex, &Luid))
    {
      free_all(&All);
      return ERROR_FILE_NOT_FOUND;
    }
    Index = InterfaceIndex;
    Constrained = TRUE;
  }

  if (SourceAddress && SourceAddress->si_family == AF_INET6 && !is_any(SourceAddress->Ipv6.sin6_addr.u.Byte))
  {
    if (!Ipv6FindOwner(SourceAddress->Ipv6.sin6_addr.u.Byte, SourceAddress->Ipv6.sin6_scope_id, &Owner))
    {
      free_all(&All);
      return ERROR_NOT_FOUND;
    }
    if (Constrained && Owner != Index)
    {
      free_all(&All);
      return ERROR_NETWORK_UNREACHABLE;
    }
    Index = Owner;
    Constrained = TRUE;
  }

  /* a link-local destination names its link in the scope id */
  if (!Constrained && DestinationAddress->Ipv6.sin6_scope_id && (is_link_local(Dest) || (Dest[0] == 0xff && (Dest[1] & 0x0f) == 2)))
  {
    Index = DestinationAddress->Ipv6.sin6_scope_id;
    Constrained = TRUE;
    ScopedByDest = TRUE;
  }

  /* A multicast destination without an interface has no route of its own: the row is empty and the source is
     the link-local address of the interface a packet would leave over (measured) */
  if (!Constrained && Dest[0] == 0xff)
  {
    BOOL Have = FALSE;

    empty_route(BestRoute);
    for (i = 0; i < All.State.Header->InterfaceCount && !Have; i++)
    {
      const TCP_IPV6_INTERFACE_ROW *If = &All.State.Interfaces[i];

      if ((If->Flags & TCP_IPV6_IF_ENABLED) && !(If->Flags & TCP_IPV6_IF_LOOPBACK))
      {
        pick_source(&All, If->IfIndex, Dest, BestSourceAddress);
        Have = !is_any(BestSourceAddress->Ipv6.sin6_addr.u.Byte);
      }
    }
    free_all(&All);
    if (!Have)
      return ERROR_NETWORK_UNREACHABLE;
    return NO_ERROR;
  }

  Result = build_routes(&All, &Rows, &Count);
  if (Result != NO_ERROR)
  {
    free_all(&All);
    return Result;
  }

  /* the longest matching prefix wins, then the lowest metric, then the lowest interface */
  for (i = 0; i < Count; i++)
  {
    const MIB_IPFORWARD_ROW2 *Route = &Rows[i];
    ULONG Length = Route->DestinationPrefix.PrefixLength;

    if (!prefix_covers(Route->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, Length, Dest))
      continue;
    if (Constrained && Route->InterfaceIndex != Index)
      continue;
    if (!Found || Length > Rows[Best].DestinationPrefix.PrefixLength ||
        (Length == Rows[Best].DestinationPrefix.PrefixLength && Route->Metric < Rows[Best].Metric))
    {
      Found = TRUE;
      Best = i;
    }
  }

  if (Found)
  {
    *BestRoute = Rows[Best];
    pick_source(&All, Rows[Best].InterfaceIndex, Dest, BestSourceAddress);
    Result = NO_ERROR;
  }
  else if (ScopedByDest || !Constrained)
    Result = ERROR_NETWORK_UNREACHABLE;
  else if (is_link_local(Dest) || Dest[0] == 0xff)
  {
    /* a link-local or multicast destination over an interface without a route for it: an empty row and the
       address of that interface (measured over the loopback interface) */
    empty_route(BestRoute);
    pick_source(&All, Index, Dest, BestSourceAddress);
    Result = NO_ERROR;
  }
  else
    Result = ERROR_INVALID_NETNAME;

  HeapFree(GetProcessHeap(), 0, Rows);
  free_all(&All);
  return Result;
}

static BOOL get_stats_from_file(HANDLE TcpFile, PTCP_IPV6_STATS Stats)
{
  PVOID Blob = NULL;
  DWORD Size = 0;
  BOOL Result = FALSE;
  NTSTATUS Status;

  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_IPV6_STATS_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  if (Size >= sizeof(*Stats) && ((PTCP_IPV6_STATS)Blob)->Enabled)
  {
    memcpy(Stats, Blob, sizeof(*Stats));
    Result = TRUE;
  }
  tdiFreeThingSet(Blob);
  return Result;
}

/* ---- statistics ---- */

BOOL Ipv6GetIpStatistics(PMIB_IPSTATS Stats)
{
  HANDLE TcpFile;
  TCP_IPV6_STATS Counters;
  IPV6_ALL All;
  PMIB_IPFORWARD_ROW2 Routes = NULL;
  ULONG Routed = 0, i;
  BOOL Result;

  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;
  Result = get_stats_from_file(TcpFile, &Counters);
  closeTcpFile(TcpFile);
  if (!Result || !get_all(&All))
    return FALSE;

  memset(Stats, 0, sizeof(*Stats));
  /* not forwarding (2), the hop limit of the stack, the reassembly timeout of lwIP's IPv6 layer (seconds) */
  Stats->dwForwarding = MIB_IP_NOT_FORWARDING;
  Stats->dwDefaultTTL = 128;
  Stats->dwReasmTimeout = 60;
  Stats->dwInReceives = Counters.IpInReceives;
  Stats->dwInDelivers = Counters.IpInDelivers;
  Stats->dwOutRequests = Counters.IpOutRequests;
  for (i = 0; i < All.State.Header->InterfaceCount; i++)
    if (All.State.Interfaces[i].Flags & TCP_IPV6_IF_ENABLED)
      Stats->dwNumIf++;
  Stats->dwNumAddr = All.State.Header->AddressCount;
  if (build_routes(&All, &Routes, &Routed) == NO_ERROR)
    Stats->dwNumRoutes = Routed;
  HeapFree(GetProcessHeap(), 0, Routes);
  free_all(&All);
  return TRUE;
}

BOOL Ipv6GetTcpStatistics(PMIB_TCPSTATS Stats)
{
  HANDLE TcpFile;
  TCP_IPV6_STATS Counters;
  PMIB_TCP6TABLE_OWNER_PID Table;
  ULONG i;
  BOOL Result;

  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;
  Result = get_stats_from_file(TcpFile, &Counters);
  if (Result)
  {
    /* the retransmission timer parameters are the stack's, whichever address family */
    memset(Stats, 0, sizeof(*Stats));
    if (getTCPStats(TcpFile, Stats) != NO_ERROR)
      memset(Stats, 0, sizeof(*Stats));
  }
  closeTcpFile(TcpFile);
  if (!Result)
    return FALSE;

  Stats->dwActiveOpens = Counters.TcpActiveOpens;
  Stats->dwPassiveOpens = Counters.TcpPassiveOpens;
  Stats->dwAttemptFails = 0;
  Stats->dwEstabResets = 0;
  Stats->dwCurrEstab = 0;
  Stats->dwInSegs = Counters.TcpInSegs;
  Stats->dwOutSegs = Counters.TcpOutSegs;
  Stats->dwRetransSegs = 0;
  Stats->dwInErrs = 0;
  Stats->dwOutRsts = 0;
  Stats->dwNumConns = 0;

  Table = getTcp6Table();
  if (Table)
  {
    for (i = 0; i < Table->dwNumEntries; i++)
    {
      Stats->dwNumConns++;
      if (Table->table[i].dwState == MIB_TCP_STATE_ESTAB || Table->table[i].dwState == MIB_TCP_STATE_CLOSE_WAIT)
        Stats->dwCurrEstab++;
    }
    HeapFree(GetProcessHeap(), 0, Table);
  }
  return TRUE;
}

BOOL Ipv6GetIcmpStatistics(PMIB_ICMP_EX Stats)
{
  HANDLE TcpFile;
  TCP_IPV6_STATS Counters;
  BOOL Result;
  ULONG i;

  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;
  Result = get_stats_from_file(TcpFile, &Counters);
  closeTcpFile(TcpFile);
  if (!Result)
    return FALSE;

  memset(Stats, 0, sizeof(*Stats));
  Stats->icmpInStats.dwMsgs = Counters.IcmpInMsgs;
  Stats->icmpOutStats.dwMsgs = Counters.IcmpOutMsgs;
  for (i = 0; i < 256; i++)
  {
    Stats->icmpInStats.rgdwTypeCount[i] = Counters.IcmpIn[i];
    Stats->icmpOutStats.rgdwTypeCount[i] = Counters.IcmpOut[i];
  }
  return TRUE;
}
