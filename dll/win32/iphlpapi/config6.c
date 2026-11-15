/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 address and route configuration: Create/Set/DeleteUnicastIpAddressEntry for AF_INET6,
 *              InitializeIpForwardEntry, Create/Set/Delete/GetIpForwardEntry2
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * tcpip.sys configures IPv6 addresses and routes through two private requests (IOCTL_IP6_ADDRESS_CONFIG,
 * IOCTL_IP6_ROUTE_CONFIG, administrators only). What these functions add lives in the active store, as the
 * documentation of the functions says of their entries (gone when the computer restarts or the interface goes);
 * the persistent store is reached through the requests alone. An IPv4 route goes to the IPv4 route table of the
 * stack (CreateIpForwardEntry and the others).
 *
 * Arguments are checked as the documentation and a read-only probe of Windows 10 22H2 say (only rows that cannot be
 * added were given to it): a NULL row or a row without an address family is ERROR_INVALID_PARAMETER; then the
 * interface is looked for (an unknown luid ERROR_NOT_FOUND, an unknown index ERROR_FILE_NOT_FOUND), before the prefix
 * length and the family of the next hop are checked (ERROR_INVALID_PARAMETER).
 */

#include "iphlpapi_private.h"
#include <wine/netioapi.h>
#include "ipv6net.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

#define INFINITE_LIFETIME   0xffffffff

static DWORD status_to_error(NTSTATUS Status)
{
  switch (Status)
  {
    case STATUS_SUCCESS:                return NO_ERROR;
    case STATUS_INVALID_PARAMETER:      return ERROR_INVALID_PARAMETER;
    case STATUS_NOT_FOUND:              return ERROR_NOT_FOUND;
    case STATUS_OBJECT_NAME_COLLISION:  return ERROR_OBJECT_ALREADY_EXISTS;
    case STATUS_ACCESS_DENIED:          return ERROR_ACCESS_DENIED;
    case STATUS_NOT_SUPPORTED:          return ERROR_NOT_SUPPORTED;
    case STATUS_INSUFFICIENT_RESOURCES: return ERROR_NOT_ENOUGH_MEMORY;
    default:                            return RtlNtStatusToDosError(Status);
  }
}

static NTSTATUS send_request(ULONG Code, PVOID Request, ULONG Size)
{
  HANDLE TcpFile;
  IO_STATUS_BLOCK Iosb;
  NTSTATUS Status;

  Status = openTcpFile(&TcpFile, FILE_READ_DATA | FILE_WRITE_DATA);
  if (!NT_SUCCESS(Status))
    return Status;
  Status = NtDeviceIoControlFile(TcpFile, NULL, NULL, NULL, &Iosb, Code, Request, Size, NULL, 0);
  closeTcpFile(TcpFile);
  return Status;
}

/*
 * The interface a row names: the luid wins over the index (documentation). An unknown luid is ERROR_NOT_FOUND, an
 * unknown index ERROR_FILE_NOT_FOUND, neither one given ERROR_INVALID_PARAMETER (as GetUnicastIpAddressEntry and the
 * other row functions of this DLL answer).
 */
static DWORD row_interface(const NET_LUID *Luid, NET_IFINDEX Index, PDWORD IfIndex)
{
  ULONG64 Found;

  if (Luid->Value)
    return getInterfaceIndexByLuid(Luid->Value, IfIndex) ? NO_ERROR : ERROR_NOT_FOUND;
  if (!Index)
    return ERROR_INVALID_PARAMETER;
  if (!getInterfaceLuidByIndex(Index, NULL, &Found))
    return ERROR_FILE_NOT_FOUND;
  *IfIndex = Index;
  return NO_ERROR;
}

/* ---- unicast addresses (netio.c calls these for AF_INET6) ---- */

static DWORD unicast_request(ULONG Operation, const MIB_UNICASTIPADDRESS_ROW *Row, ULONG PrefixLength,
                             ULONG PrefixOrigin, ULONG SuffixOrigin)
{
  TCP_IPV6_ADDRESS_REQUEST Request;
  DWORD IfIndex = 0, Error;

  Error = row_interface(&Row->InterfaceLuid, Row->InterfaceIndex, &IfIndex);
  if (Error != NO_ERROR)
    return Error;

  memset(&Request, 0, sizeof(Request));
  Request.Operation = Operation;
  Request.Store = TCP_IPV6_STORE_ACTIVE;
  Request.IfIndex = IfIndex;
  memcpy(Request.Address, &Row->Address.Ipv6.sin6_addr, 16);
  Request.PrefixLength = PrefixLength;
  Request.ValidLifetime = Row->ValidLifetime;
  Request.PreferredLifetime = Row->PreferredLifetime;
  Request.PrefixOrigin = PrefixOrigin;
  Request.SuffixOrigin = SuffixOrigin;
  Request.Flags = Row->SkipAsSource ? TCP_IPV6_ADDRESS_SKIP_AS_SOURCE : 0;
  return status_to_error(send_request(IOCTL_IP6_ADDRESS_CONFIG, &Request, sizeof(Request)));
}

/* An origin of the row, or what it becomes when the row leaves it to the stack (Unchanged, Other) */
static ULONG origin_or(ULONG Origin, ULONG Default)
{
  return (Origin == IpPrefixOriginOther || Origin == IpPrefixOriginUnchanged) ? Default : Origin;
}

DWORD Ipv6CreateUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  ULONG Length = Row->OnLinkPrefixLength;
  DWORD IfIndex, Error;

  /* the interface first (probe: a length of 129 over an unknown interface is ERROR_FILE_NOT_FOUND) */
  Error = row_interface(&Row->InterfaceLuid, Row->InterfaceIndex, &IfIndex);
  if (Error != NO_ERROR)
    return Error;
  /* 255 (InitializeUnicastIpAddressEntry) leaves the length to the stack: /64, the length of an IPv6 subnet */
  if (Length == 255)
    Length = 64;
  else if (Length > 128)
    return ERROR_INVALID_PARAMETER;
  if (Row->ValidLifetime == 0 || Row->PreferredLifetime > Row->ValidLifetime)
    return ERROR_INVALID_PARAMETER;

  return unicast_request(TCP_IPV6_CONFIG_CREATE, Row, Length, origin_or(Row->PrefixOrigin, IpPrefixOriginManual),
                         origin_or(Row->SuffixOrigin, IpSuffixOriginManual));
}

DWORD Ipv6DeleteUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  return unicast_request(TCP_IPV6_CONFIG_DELETE, Row, 0, 0, 0);
}

DWORD Ipv6SetUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  MIB_UNICASTIPADDRESS_ROW Current;
  ULONG Length = Row->OnLinkPrefixLength;
  DWORD Error;

  /* what the row leaves unchanged (an Unchanged origin, a length of 255) stays what the address has */
  Current = *Row;
  Error = GetUnicastIpAddressEntry(&Current);
  if (Error != NO_ERROR)
    return Error;
  if (Length == 255)
    Length = Current.OnLinkPrefixLength;
  else if (Length > 128)
    return ERROR_INVALID_PARAMETER;
  if (Row->ValidLifetime == 0 || Row->PreferredLifetime > Row->ValidLifetime)
    return ERROR_INVALID_PARAMETER;

  return unicast_request(TCP_IPV6_CONFIG_SET, Row, Length,
                         Row->PrefixOrigin == IpPrefixOriginUnchanged ? Current.PrefixOrigin : Row->PrefixOrigin,
                         Row->SuffixOrigin == IpSuffixOriginUnchanged ? Current.SuffixOrigin : Row->SuffixOrigin);
}

/* ---- routes ---- */

VOID WINAPI InitializeIpForwardEntry(PMIB_IPFORWARD_ROW2 Row)
{
  if (!Row)
    return;

  /* Windows 10 22H2 (probe): no prefix, next hop or interface, infinite lifetimes; the site prefix length, the
     metric, the protocol and the four flags "not given" (all bits set); age 0, origin Manual */
  memset(Row, 0, sizeof(*Row));
  Row->SitePrefixLength = 255;
  Row->ValidLifetime = INFINITE_LIFETIME;
  Row->PreferredLifetime = INFINITE_LIFETIME;
  Row->Metric = (ULONG)-1;
  Row->Protocol = (NL_ROUTE_PROTOCOL)-1;
  Row->Loopback = 255;
  Row->AutoconfigureAddress = 255;
  Row->Publish = 255;
  Row->Immortal = 255;
  Row->Origin = NlroManual;
}

static BOOL is_zero(const void *Address, SIZE_T Length)
{
  const UCHAR *Byte = Address;

  while (Length--)
    if (*Byte++)
      return FALSE;
  return TRUE;
}

/* The checks every route row passes; *Family is the family of the route */
static DWORD check_route_row(const MIB_IPFORWARD_ROW2 *Row, ADDRESS_FAMILY *Family, PDWORD IfIndex)
{
  ADDRESS_FAMILY Dest, Hop;
  DWORD Error;

  if (!Row)
    return ERROR_INVALID_PARAMETER;
  Dest = Row->DestinationPrefix.Prefix.si_family;
  Hop = Row->NextHop.si_family;
  if (Dest != AF_INET && Dest != AF_INET6)
    return ERROR_INVALID_PARAMETER;

  /* the interface before the rest (probe: an IPv4 next hop or a length of 129 over an unknown interface is
     ERROR_FILE_NOT_FOUND) */
  Error = row_interface(&Row->InterfaceLuid, Row->InterfaceIndex, IfIndex);
  if (Error != NO_ERROR)
    return Error;

  /* the next hop is of the family of the destination (or left unspecified: on-link) */
  if (Hop != Dest && Hop != AF_UNSPEC)
    return ERROR_INVALID_PARAMETER;
  if (Row->DestinationPrefix.PrefixLength > (Dest == AF_INET ? 32 : 128))
    return ERROR_INVALID_PARAMETER;
  *Family = Dest;
  return NO_ERROR;
}

/* The metric the stack takes: -1 (InitializeIpForwardEntry: not given) is the route metric Windows gives a route
   by default, 256 */
static ULONG route_metric(ULONG Metric)
{
  return Metric == (ULONG)-1 ? 256 : Metric;
}

/* A flag of the row, or its default when the row does not give it (255, InitializeIpForwardEntry) */
static BOOLEAN route_flag(BOOLEAN Flag, BOOLEAN Default)
{
  return Flag == 255 ? Default : (Flag != FALSE);
}

static DWORD route_request6(ULONG Operation, const MIB_IPFORWARD_ROW2 *Row, DWORD IfIndex)
{
  TCP_IPV6_ROUTE_REQUEST Request;

  memset(&Request, 0, sizeof(Request));
  Request.Operation = Operation;
  Request.Store = TCP_IPV6_STORE_ACTIVE;
  Request.IfIndex = IfIndex;
  memcpy(Request.Prefix, &Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, 16);
  Request.PrefixLength = Row->DestinationPrefix.PrefixLength;
  if (Row->NextHop.si_family == AF_INET6)
    memcpy(Request.NextHop, &Row->NextHop.Ipv6.sin6_addr, 16);
  Request.Metric = route_metric(Row->Metric);
  Request.ValidLifetime = Row->ValidLifetime;
  Request.PreferredLifetime = Row->PreferredLifetime;
  Request.Origin = Row->Origin;
  /* a route the protocol of which is not given is one of network management, as CreateIpForwardEntry makes */
  Request.Protocol = Row->Protocol == (NL_ROUTE_PROTOCOL)-1 ? MIB_IPPROTO_NETMGMT : Row->Protocol;
  Request.Flags = (route_flag(Row->Publish, FALSE) ? TCP_IPV6_ROUTE_PUBLISH : 0) |
                  (route_flag(Row->Immortal, FALSE) ? TCP_IPV6_ROUTE_IMMORTAL : 0);
  return status_to_error(send_request(IOCTL_IP6_ROUTE_CONFIG, &Request, sizeof(Request)));
}

/* An IPv4 route in the layout of the IPv4 route table */
static void legacy_row(const MIB_IPFORWARD_ROW2 *Row, DWORD IfIndex, PMIB_IPFORWARDROW Out)
{
  ULONG Mask = 0;

  memset(Out, 0, sizeof(*Out));
  ConvertLengthToIpv4Mask(Row->DestinationPrefix.PrefixLength, &Mask);
  Out->dwForwardDest = Row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr & Mask;
  Out->dwForwardMask = Mask;
  Out->dwForwardNextHop = Row->NextHop.si_family == AF_INET ? Row->NextHop.Ipv4.sin_addr.s_addr : 0;
  Out->dwForwardIfIndex = IfIndex;
  Out->dwForwardType = Out->dwForwardNextHop ? MIB_IPROUTE_TYPE_INDIRECT : MIB_IPROUTE_TYPE_DIRECT;
  Out->dwForwardProto = MIB_IPPROTO_NETMGMT;
  Out->dwForwardMetric1 = route_metric(Row->Metric);
  Out->dwForwardMetric2 = Out->dwForwardMetric3 = Out->dwForwardMetric4 = Out->dwForwardMetric5 = (DWORD)-1;
}

static DWORD route_lifetimes_ok(const MIB_IPFORWARD_ROW2 *Row)
{
  if (Row->ValidLifetime == 0 || Row->PreferredLifetime > Row->ValidLifetime)
    return ERROR_INVALID_PARAMETER;
  return NO_ERROR;
}

DWORD WINAPI CreateIpForwardEntry2(const MIB_IPFORWARD_ROW2 *Row)
{
  ADDRESS_FAMILY Family;
  MIB_IPFORWARDROW Legacy;
  DWORD IfIndex = 0, Error;

  TRACE("(%p)\n", Row);

  Error = check_route_row(Row, &Family, &IfIndex);
  if (Error == NO_ERROR)
    Error = route_lifetimes_ok(Row);
  if (Error != NO_ERROR)
    return Error;

  if (Family == AF_INET6)
    return route_request6(TCP_IPV6_CONFIG_CREATE, Row, IfIndex);

  legacy_row(Row, IfIndex, &Legacy);
  return CreateIpForwardEntry(&Legacy);
}

DWORD WINAPI SetIpForwardEntry2(const MIB_IPFORWARD_ROW2 *Row)
{
  ADDRESS_FAMILY Family;
  MIB_IPFORWARDROW Legacy;
  DWORD IfIndex = 0, Error;

  TRACE("(%p)\n", Row);

  Error = check_route_row(Row, &Family, &IfIndex);
  if (Error == NO_ERROR)
    Error = route_lifetimes_ok(Row);
  if (Error != NO_ERROR)
    return Error;

  if (Family == AF_INET6)
  {
    MIB_IPFORWARD_ROW2 Change = *Row, Current = *Row;

    /* what the row does not give stays what the route has */
    Error = GetIpForwardEntry2(&Current);
    if (Error != NO_ERROR)
      return Error;
    if (Change.Metric == (ULONG)-1)
      Change.Metric = Current.Metric;
    if (Change.Protocol == (NL_ROUTE_PROTOCOL)-1)
      Change.Protocol = Current.Protocol;
    if (Change.Publish == 255)
      Change.Publish = Current.Publish;
    if (Change.Immortal == 255)
      Change.Immortal = Current.Immortal;
    return route_request6(TCP_IPV6_CONFIG_SET, &Change, IfIndex);
  }

  legacy_row(Row, IfIndex, &Legacy);
  return SetIpForwardEntry(&Legacy);
}

DWORD WINAPI DeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2 *Row)
{
  ADDRESS_FAMILY Family;
  MIB_IPFORWARDROW Legacy;
  DWORD IfIndex = 0, Error;

  TRACE("(%p)\n", Row);

  Error = check_route_row(Row, &Family, &IfIndex);
  if (Error != NO_ERROR)
    return Error;

  if (Family == AF_INET6)
    return route_request6(TCP_IPV6_CONFIG_DELETE, Row, IfIndex);

  legacy_row(Row, IfIndex, &Legacy);
  return DeleteIpForwardEntry(&Legacy);
}

static BOOL same_prefix(const SOCKADDR_INET *A, const SOCKADDR_INET *B)
{
  if (A->si_family != B->si_family)
    return FALSE;
  if (A->si_family == AF_INET)
    return A->Ipv4.sin_addr.s_addr == B->Ipv4.sin_addr.s_addr;
  return !memcmp(&A->Ipv6.sin6_addr, &B->Ipv6.sin6_addr, 16);
}

/* An unspecified next hop of the row matches an on-link route */
static BOOL same_next_hop(const SOCKADDR_INET *Row, const SOCKADDR_INET *Route)
{
  if (Row->si_family == AF_UNSPEC || (Row->si_family == AF_INET && !Row->Ipv4.sin_addr.s_addr) ||
      (Row->si_family == AF_INET6 && is_zero(&Row->Ipv6.sin6_addr, 16)))
  {
    return (Route->si_family == AF_INET && !Route->Ipv4.sin_addr.s_addr) ||
           (Route->si_family == AF_INET6 && is_zero(&Route->Ipv6.sin6_addr, 16));
  }
  return same_prefix(Row, Route);
}

DWORD WINAPI GetIpForwardEntry2(PMIB_IPFORWARD_ROW2 Row)
{
  ADDRESS_FAMILY Family;
  PMIB_IPFORWARD_ROW2 Rows = NULL;
  ULONG Count = 0, i;
  DWORD IfIndex = 0, Error;

  TRACE("(%p)\n", Row);

  Error = check_route_row(Row, &Family, &IfIndex);
  if (Error != NO_ERROR)
    return Error;

  Error = Family == AF_INET6 ? Ipv6GetRouteRows(&Rows, &Count) : Ipv4GetRouteRows(&Rows, &Count);
  if (Error != NO_ERROR)
    return Error;

  Error = ERROR_NOT_FOUND;
  for (i = 0; i < Count; i++)
  {
    if (Rows[i].InterfaceIndex == IfIndex &&
        Rows[i].DestinationPrefix.PrefixLength == Row->DestinationPrefix.PrefixLength &&
        same_prefix(&Rows[i].DestinationPrefix.Prefix, &Row->DestinationPrefix.Prefix) &&
        same_next_hop(&Row->NextHop, &Rows[i].NextHop))
    {
      *Row = Rows[i];
      Error = NO_ERROR;
      break;
    }
  }
  HeapFree(GetProcessHeap(), 0, Rows);
  return Error;
}
