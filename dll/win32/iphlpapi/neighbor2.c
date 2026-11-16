/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetIpNetEntry2, ResolveIpNetEntry2 and the thread compartment calls
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include <wine/netioapi.h>
#include "ipv6net.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/* The compartment every interface lives in; the stack here has no other. */
#define PRIMARY_COMPARTMENT 1

#define LOOPBACK_LUID 0x0018000000000000ULL

/*
 * The measured Windows 10 behaviour: a thread starts in compartment 1, and compartment 1 and 0 are accepted
 * by the setter (0 leaves the thread where it is), any other id does not exist.
 */
NET_IF_COMPARTMENT_ID WINAPI GetCurrentThreadCompartmentId(void)
{
  return PRIMARY_COMPARTMENT;
}

DWORD WINAPI SetCurrentThreadCompartmentId(NET_IF_COMPARTMENT_ID CompartmentId)
{
  TRACE("(%lu)\n", CompartmentId);

  if (CompartmentId == PRIMARY_COMPARTMENT || CompartmentId == 0)
    return NO_ERROR;
  return ERROR_NOT_FOUND;
}

/*
 * The interface a row names. A luid wins over an index, a zero luid or index is not a constraint; an unknown luid
 * is ERROR_NOT_FOUND and an unknown index ERROR_FILE_NOT_FOUND, as in GetBestRoute2. *Constrained says whether
 * the row named one.
 */
static DWORD row_interface(const MIB_IPNET_ROW2 *Row, PDWORD Index, PBOOL Constrained)
{
  ULONG64 Luid;

  *Index = 0;
  *Constrained = FALSE;
  if (Row->InterfaceLuid.Value)
  {
    if (!getInterfaceIndexByLuid(Row->InterfaceLuid.Value, Index))
      return ERROR_NOT_FOUND;
    *Constrained = TRUE;
  }
  else if (Row->InterfaceIndex)
  {
    if (!getInterfaceLuidByIndex(Row->InterfaceIndex, NULL, &Luid))
      return ERROR_FILE_NOT_FOUND;
    *Index = Row->InterfaceIndex;
    *Constrained = TRUE;
  }
  return NO_ERROR;
}

static BOOL set_interface(PMIB_IPNET_ROW2 Row, DWORD Index)
{
  ULONG64 Luid;

  if (!getInterfaceLuidByIndex(Index, NULL, &Luid))
    return FALSE;
  Row->InterfaceIndex = Index;
  Row->InterfaceLuid.Value = Luid;
  return TRUE;
}

static void set_neighbor(PMIB_IPNET_ROW2 Row, NL_NEIGHBOR_STATE State, const BYTE *Address, ULONG Length)
{
  memset(Row->PhysicalAddress, 0, sizeof(Row->PhysicalAddress));
  if (Length > sizeof(Row->PhysicalAddress))
    Length = sizeof(Row->PhysicalAddress);
  memcpy(Row->PhysicalAddress, Address, Length);
  Row->PhysicalAddressLength = Length;
  Row->State = State;
  Row->Flags = 0;
  Row->ReachabilityTime.LastReachable = (State == NlnsPermanent) ? 0 : GetTickCount();
}

static BOOL valid_family(const MIB_IPNET_ROW2 *Row)
{
  return Row->Address.si_family == AF_INET || Row->Address.si_family == AF_INET6;
}

static BOOL is_v6_loopback(const MIB_IPNET_ROW2 *Row)
{
  static const IN6_ADDR Loopback = { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };

  return Row->Address.si_family == AF_INET6 && !memcmp(&Row->Address.Ipv6.sin6_addr, &Loopback, sizeof(Loopback));
}

/******************************************************************
 *    GetIpNetEntry2 (IPHLPAPI.@)
 *
 * Look up one neighbor in the cache.
 *
 * NOTES
 *  An IPv4 neighbor comes from the ARP table; a dynamic entry is reported Reachable and a static one Permanent.
 *  An IPv6 neighbor is one of the neighbour cache of the stack (Ipv6GetNeighborRows), found by address and, when the
 *  row names one, by interface. The Windows entries that need no
 *  ARP exchange (the limited broadcast, Permanent with the all-ones address) are not reported. The row is
 *  left alone when nothing is found; without an interface in it, the interface of the entry is filled in.
 */
DWORD WINAPI GetIpNetEntry2(PMIB_IPNET_ROW2 Row)
{
  PMIB_IPNETTABLE Table = NULL;
  ULONG Size = 0, Tries;
  DWORD Error = ERROR_INSUFFICIENT_BUFFER, Index, i;
  BOOL Constrained;

  TRACE("(%p)\n", Row);

  if (!Row || !valid_family(Row))
    return ERROR_INVALID_PARAMETER;

  Error = row_interface(Row, &Index, &Constrained);
  if (Error != NO_ERROR)
    return Error;

  if (Row->Address.si_family == AF_INET6)
  {
    PMIB_IPNET_ROW2 Rows;
    ULONG Count, k;

    Error = Ipv6GetNeighborRows(&Rows, &Count);
    if (Error != NO_ERROR)
      return Error;
    Error = ERROR_NOT_FOUND;
    for (k = 0; k < Count; k++)
    {
      const MIB_IPNET_ROW2 *Entry = &Rows[k];

      if (memcmp(&Entry->Address.Ipv6.sin6_addr, &Row->Address.Ipv6.sin6_addr, 16))
        continue;
      if (Constrained && Entry->InterfaceIndex != Index)
        continue;
      Row->InterfaceIndex = Entry->InterfaceIndex;
      Row->InterfaceLuid = Entry->InterfaceLuid;
      memcpy(Row->PhysicalAddress, Entry->PhysicalAddress, sizeof(Row->PhysicalAddress));
      Row->PhysicalAddressLength = Entry->PhysicalAddressLength;
      Row->State = Entry->State;
      Row->Flags = Entry->Flags;
      Row->ReachabilityTime = Entry->ReachabilityTime;
      Error = NO_ERROR;
      break;
    }
    HeapFree(GetProcessHeap(), 0, Rows);
    return Error;
  }

  Error = ERROR_INSUFFICIENT_BUFFER;
  for (Tries = 0; Tries < 5 && Error == ERROR_INSUFFICIENT_BUFFER; Tries++)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    Table = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Size && !Table)
      return ERROR_OUTOFMEMORY;
    Error = GetIpNetTable(Table, &Size, FALSE);
  }
  if (Error != NO_ERROR)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return Error == ERROR_NO_DATA ? ERROR_NOT_FOUND : Error;
  }

  Error = ERROR_NOT_FOUND;
  for (i = 0; i < Table->dwNumEntries; i++)
  {
    PMIB_IPNETROW Entry = &Table->table[i];

    if (Entry->dwAddr != Row->Address.Ipv4.sin_addr.s_addr)
      continue;
    if (Constrained && Entry->dwIndex != Index)
      continue;
    if (Entry->dwType != MIB_IPNET_TYPE_DYNAMIC && Entry->dwType != MIB_IPNET_TYPE_STATIC)
      continue;
    if (!set_interface(Row, Entry->dwIndex))
      continue;

    set_neighbor(Row, Entry->dwType == MIB_IPNET_TYPE_STATIC ? NlnsPermanent : NlnsReachable, Entry->bPhysAddr,
                 Entry->dwPhysAddrLen);
    Error = NO_ERROR;
    break;
  }
  HeapFree(GetProcessHeap(), 0, Table);
  return Error;
}

/* The interface that owns an IPv4 address of this computer. */
static BOOL find_owner(IPAddr Address, PDWORD Index)
{
  InterfaceIndexTable *Table = getInterfaceIndexTable();
  BOOL Found = FALSE;
  DWORD i;

  if (!Table)
    return FALSE;
  for (i = 0; i < Table->numIndexes && !Found; i++)
  {
    if (getInterfaceIPAddrByIndex(Table->indexes[i]) == Address)
    {
      *Index = Table->indexes[i];
      Found = TRUE;
    }
  }
  free(Table);
  return Found;
}

/* The first neighbour of the cache with this address (on the interface, when there is one) that has a link address */
static BOOL find_cached_v6(const UCHAR *Address, DWORD Index, BOOL Constrained, PMIB_IPNET_ROW2 Found)
{
  PMIB_IPNET_ROW2 Rows;
  ULONG Count, k;
  BOOL Result = FALSE;

  if (Ipv6GetNeighborRows(&Rows, &Count) != NO_ERROR)
    return FALSE;
  for (k = 0; k < Count && !Result; k++)
  {
    if (memcmp(&Rows[k].Address.Ipv6.sin6_addr, Address, 16))
      continue;
    if (Constrained && Rows[k].InterfaceIndex != Index)
      continue;
    if (Rows[k].State <= NlnsIncomplete)
      continue;
    *Found = Rows[k];
    Result = TRUE;
  }
  HeapFree(GetProcessHeap(), 0, Rows);
  return Result;
}

/*
 * Neighbour solicitations for the address on the interface: all that Windows puts on the wire for ResolveIpNetEntry2
 * (a read of the packets of Windows Server 2022: one solicitation to the solicited-node group of the address, again
 * once a second up to three times while nothing answers; no datagram of any protocol). The stack asks for it with
 * IOCTL_IP6_SOLICIT, which any caller may; FALSE: it could not (no such interface, link down, IPv6 off).
 */
static BOOL solicit_v6(const UCHAR *Address, DWORD Index)
{
  TCP_IPV6_SOLICIT_REQUEST Request;
  HANDLE TcpFile;
  IO_STATUS_BLOCK Iosb;
  NTSTATUS Status;

  Request.IfIndex = Index;
  memcpy(Request.Address, Address, 16);
  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;
  Status = NtDeviceIoControlFile(TcpFile, NULL, NULL, NULL, &Iosb, IOCTL_IP6_SOLICIT, &Request, sizeof(Request),
                                 NULL, 0);
  closeTcpFile(TcpFile);
  return NT_SUCCESS(Status);
}

/*
 * ResolveIpNetEntry2 for an IPv6 address: ::1 resolves on the loopback interface, Permanent and without a link
 * address; an address of this computer to the link address of its interface, Permanent; a neighbour in the cache to
 * its entry. Any other on-link address is asked for by neighbour solicitations (up to three seconds, the stack asks
 * three times); everything else, an address the routes do not show on a link included, is ERROR_BAD_NET_NAME as before
 * there was an IPv6 stack. The unspecified address is ERROR_INVALID_PARAMETER.
 */
static DWORD resolve_v6(PMIB_IPNET_ROW2 Row, DWORD Index, BOOL Constrained)
{
  const UCHAR *Address = Row->Address.Ipv6.sin6_addr.u.Byte;
  static const UCHAR Zero[16];
  DWORD Own, Mode, Tries;
  BOOL Have, Asked;
  MIB_IPNET_ROW2 Found;
  ULONG Length;
  BYTE Link[MAX_INTERFACE_PHYSADDR];
  SOCKADDR_INET Best, BestSource;
  MIB_IPFORWARD_ROW2 Route;
  IPV6_STATE State;


  /* without IPv6 only ::1 resolves, to the loopback interface; everything else is ERROR_BAD_NET_NAME */
  if (!Ipv6GetState(&State))
  {
    if (!is_v6_loopback(Row) || !getInterfaceIndexByLuid(LOOPBACK_LUID, &Index) || !set_interface(Row, Index))
      return ERROR_BAD_NET_NAME;
    set_neighbor(Row, NlnsPermanent, NULL, 0);
    return NO_ERROR;
  }
  Ipv6FreeState(&State);

  if (!memcmp(Address, Zero, 16))
    return ERROR_INVALID_PARAMETER;

  if (is_v6_loopback(Row))
  {
    if (!getInterfaceIndexByLuid(LOOPBACK_LUID, &Index) || !set_interface(Row, Index))
      return ERROR_BAD_NET_NAME;
    set_neighbor(Row, NlnsPermanent, NULL, 0);
    return NO_ERROR;
  }

  if (Ipv6FindOwner(Address, Row->Address.Ipv6.sin6_scope_id, &Own) && (!Constrained || Own == Index))
  {
    Length = sizeof(Link);
    if (getInterfacePhysicalByIndex(Own, &Length, Link, &Mode) == NO_ERROR && set_interface(Row, Own))
    {
      set_neighbor(Row, NlnsPermanent, Link, Length);
      return NO_ERROR;
    }
  }

  if (!Constrained)
  {
    memset(&Best, 0, sizeof(Best));
    Best.Ipv6 = Row->Address.Ipv6;
    if (GetBestRoute2(NULL, 0, NULL, &Best, 0, &Route, &BestSource) != NO_ERROR)
      return ERROR_BAD_NET_NAME;
    /* only a destination the route shows on a link is a neighbour (a gateway is not what is asked for) */
    if (!Route.InterfaceIndex || Route.DestinationPrefix.PrefixLength == 0 || Address[0] == 0xff)
      return ERROR_BAD_NET_NAME;
    Index = Route.InterfaceIndex;
  }

  /* Windows asks for the address whether it knows it or not (one solicitation, answered in milliseconds) */
  Have = find_cached_v6(Address, Index, TRUE, &Found);
  Asked = solicit_v6(Address, Row->Address.Ipv6.sin6_scope_id ? Row->Address.Ipv6.sin6_scope_id : Index);
  if (!Have && Asked)
  {
    for (Tries = 0; Tries < 30 && !Have; Tries++)
    {
      Sleep(100);
      Have = find_cached_v6(Address, Index, TRUE, &Found);
    }
  }
  if (!Have)
    return ERROR_BAD_NET_NAME;

  Row->InterfaceIndex = Found.InterfaceIndex;
  Row->InterfaceLuid = Found.InterfaceLuid;
  memcpy(Row->PhysicalAddress, Found.PhysicalAddress, sizeof(Row->PhysicalAddress));
  Row->PhysicalAddressLength = Found.PhysicalAddressLength;
  Row->State = Found.State;
  Row->Flags = Found.Flags;
  Row->ReachabilityTime = Found.ReachabilityTime;
  return NO_ERROR;
}

/******************************************************************
 *    ResolveIpNetEntry2 (IPHLPAPI.@)
 *
 * Resolve a neighbor, sending an ARP request when it is not cached.
 *
 * NOTES
 *  The measured Windows behaviour is followed for the cases below. A loopback address (or ::1) resolves on the
 *  loopback interface, Permanent and without a link address; an address of this computer resolves to the link
 *  address of its interface, Permanent. The ARP failure is ERROR_BAD_NET_NAME, as is any IPv6 address but ::1
 *  (there is no IPv6 stack). 0.0.0.0 is ERROR_INVALID_PARAMETER. Windows also answers the limited broadcast
 *  and multicast addresses with the link address of the interface; here they are ARPed for and fail. A
 *  SourceAddress that is not an address of the interface is ignored. Without an interface in the row the
 *  route to the address picks one; an address without a route is ERROR_BAD_NET_NAME.
 */
DWORD WINAPI ResolveIpNetEntry2(PMIB_IPNET_ROW2 Row, const SOCKADDR_INET *SourceAddress)
{
  DWORD Error, Index, Mode, Own = 0;
  BOOL Constrained;
  IPAddr Dest, Source = 0;
  ULONG Hw[2], HwLen;
  BYTE Link[MAX_INTERFACE_PHYSADDR];

  TRACE("(%p, %p)\n", Row, SourceAddress);

  if (!Row || !valid_family(Row))
    return ERROR_INVALID_PARAMETER;

  Error = row_interface(Row, &Index, &Constrained);
  if (Error != NO_ERROR)
    return Error;

  if (Row->Address.si_family == AF_INET6)
    return resolve_v6(Row, Index, Constrained);

  Dest = Row->Address.Ipv4.sin_addr.s_addr;
  if (!Dest)
    return ERROR_INVALID_PARAMETER;

  /* 127.0.0.0/8 lives on the loopback interface alone */
  if ((Dest & 0xff) == 127)
  {
    if (!getInterfaceIndexByLuid(LOOPBACK_LUID, &Index) || !set_interface(Row, Index))
      return ERROR_BAD_NET_NAME;
    set_neighbor(Row, NlnsPermanent, NULL, 0);
    return NO_ERROR;
  }

  /* an address of this computer is its own neighbor */
  if (find_owner(Dest, &Own) && (!Constrained || Own == Index))
  {
    ULONG Length = sizeof(Link);

    if (getInterfacePhysicalByIndex(Own, &Length, Link, &Mode) == NO_ERROR && set_interface(Row, Own))
    {
      set_neighbor(Row, NlnsPermanent, Link, Length);
      return NO_ERROR;
    }
  }

  if (!Constrained)
  {
    SOCKADDR_INET Best, BestSource;
    MIB_IPFORWARD_ROW2 Route;

    memset(&Best, 0, sizeof(Best));
    Best.Ipv4.sin_family = AF_INET;
    Best.Ipv4.sin_addr.s_addr = Dest;
    if (GetBestRoute2(NULL, 0, NULL, &Best, 0, &Route, &BestSource) != NO_ERROR)
      return ERROR_BAD_NET_NAME;
    Index = Route.InterfaceIndex;
  }

  /* the ARP request leaves with an address of the interface; one the caller names must be it */
  Source = getInterfaceIPAddrByIndex(Index);
  if (SourceAddress && SourceAddress->si_family == AF_INET && SourceAddress->Ipv4.sin_addr.s_addr &&
      SourceAddress->Ipv4.sin_addr.s_addr == Source)
    Source = SourceAddress->Ipv4.sin_addr.s_addr;
  if (!Source || Source == INADDR_NONE)
    return ERROR_BAD_NET_NAME;

  memset(Hw, 0, sizeof(Hw));
  HwLen = 6;
  if (SendARP(Dest, Source, Hw, &HwLen) != NO_ERROR || !HwLen || HwLen > sizeof(Hw) || !set_interface(Row, Index))
    return ERROR_BAD_NET_NAME;

  set_neighbor(Row, NlnsReachable, (const BYTE *)Hw, HwLen);
  return NO_ERROR;
}

/* The IPv4 neighbours (the ARP table: dynamic entries are Reachable, static ones Permanent) as MIB_IPNET_ROW2 rows */
DWORD Ipv4GetNeighborRows(PMIB_IPNET_ROW2 *Rows, ULONG *Count)
{
  PMIB_IPNETTABLE Table = NULL;
  PMIB_IPNET_ROW2 Out;
  ULONG Size = 0, Tries, i, Used = 0;
  DWORD Error = ERROR_INSUFFICIENT_BUFFER;

  *Rows = NULL;
  *Count = 0;
  for (Tries = 0; Tries < 5 && Error == ERROR_INSUFFICIENT_BUFFER; Tries++)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    Table = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Size && !Table)
      return ERROR_OUTOFMEMORY;
    Error = GetIpNetTable(Table, &Size, FALSE);
  }
  if (Error == ERROR_NO_DATA)
  {
    /* an empty cache */
    HeapFree(GetProcessHeap(), 0, Table);
    Table = NULL;
    Error = NO_ERROR;
  }
  if (Error != NO_ERROR)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return Error;
  }

  Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)((Table ? Table->dwNumEntries : 0) + 1) * sizeof(*Out));
  if (!Out)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return ERROR_OUTOFMEMORY;
  }
  for (i = 0; Table && i < Table->dwNumEntries; i++)
  {
    PMIB_IPNETROW Entry = &Table->table[i];
    PMIB_IPNET_ROW2 Row = &Out[Used];

    if (Entry->dwType != MIB_IPNET_TYPE_DYNAMIC && Entry->dwType != MIB_IPNET_TYPE_STATIC)
      continue;
    if (!set_interface(Row, Entry->dwIndex))
      continue;
    Row->Address.Ipv4.sin_family = AF_INET;
    Row->Address.Ipv4.sin_addr.s_addr = Entry->dwAddr;
    set_neighbor(Row, Entry->dwType == MIB_IPNET_TYPE_STATIC ? NlnsPermanent : NlnsReachable, Entry->bPhysAddr,
                 Entry->dwPhysAddrLen);
    Used++;
  }
  HeapFree(GetProcessHeap(), 0, Table);
  *Rows = Out;
  *Count = Used;
  return NO_ERROR;
}

/******************************************************************
 *    GetIpNetTable2 (IPHLPAPI.@)
 *
 * The neighbours of the stack: the IPv4 ones (the ARP table), then the IPv6 ones (the neighbour cache and the
 * multicast groups it receives, Ipv6GetNeighborRows). The rows of an address family that is not asked for are left
 * out. FreeMibTable frees the table.
 */
DWORD WINAPI GetIpNetTable2(ADDRESS_FAMILY Family, PMIB_IPNET_TABLE2 *Table)
{
  PMIB_IPNET_ROW2 Rows4 = NULL, Rows6 = NULL;
  ULONG Count4 = 0, Count6 = 0;
  PMIB_IPNET_TABLE2 Out;
  DWORD Error;

  TRACE("(%u, %p)\n", Family, Table);

  if (!Table || (Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;
  *Table = NULL;

  if (Family != AF_INET6)
  {
    Error = Ipv4GetNeighborRows(&Rows4, &Count4);
    if (Error != NO_ERROR)
      return Error;
  }
  if (Family != AF_INET)
  {
    Error = Ipv6GetNeighborRows(&Rows6, &Count6);
    if (Error != NO_ERROR)
    {
      HeapFree(GetProcessHeap(), 0, Rows4);
      return Error;
    }
  }

  Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                  FIELD_OFFSET(MIB_IPNET_TABLE2, Table) + (SIZE_T)(Count4 + Count6 + 1) * sizeof(MIB_IPNET_ROW2));
  if (Out)
  {
    if (Count4)
      memcpy(Out->Table, Rows4, (SIZE_T)Count4 * sizeof(MIB_IPNET_ROW2));
    if (Count6)
      memcpy(Out->Table + Count4, Rows6, (SIZE_T)Count6 * sizeof(MIB_IPNET_ROW2));
    Out->NumEntries = Count4 + Count6;
    *Table = Out;
  }
  HeapFree(GetProcessHeap(), 0, Rows4);
  HeapFree(GetProcessHeap(), 0, Rows6);
  return Out ? NO_ERROR : ERROR_OUTOFMEMORY;
}
