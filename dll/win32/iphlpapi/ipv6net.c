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

/* Everything the tables below are built from, taken together. FALSE: IPv6 is off (nothing to free) */
typedef struct _IPV6_ALL
{
  IPV6_STATE State;
  IPV6_ND_STATE Nd;
  IPV6_DNS_STATE Dns;
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
  }
  closeTcpFile(TcpFile);
  return On;
}

static void free_all(IPV6_ALL *All)
{
  Ipv6FreeState(&All->State);
  Ipv6FreeNd(&All->Nd);
  Ipv6FreeDns(&All->Dns);
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


