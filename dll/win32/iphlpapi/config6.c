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
#include <iphlpapi_nitro.h>

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

static DWORD unicast_request(ULONG Operation, ULONG Store, const MIB_UNICASTIPADDRESS_ROW *Row, ULONG PrefixLength,
                             ULONG PrefixOrigin, ULONG SuffixOrigin)
{
  TCP_IPV6_ADDRESS_REQUEST Request;
  DWORD IfIndex = 0, Error;

  Error = row_interface(&Row->InterfaceLuid, Row->InterfaceIndex, &IfIndex);
  if (Error != NO_ERROR)
    return Error;

  memset(&Request, 0, sizeof(Request));
  Request.Operation = Operation;
  Request.Store = Store;
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

static DWORD create_address(const MIB_UNICASTIPADDRESS_ROW *Row, ULONG Store)
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

  return unicast_request(TCP_IPV6_CONFIG_CREATE, Store, Row, Length, origin_or(Row->PrefixOrigin, IpPrefixOriginManual),
                         origin_or(Row->SuffixOrigin, IpSuffixOriginManual));
}

static DWORD set_address(const MIB_UNICASTIPADDRESS_ROW *Row, ULONG Store)
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

  return unicast_request(TCP_IPV6_CONFIG_SET, Store, Row, Length,
                         Row->PrefixOrigin == IpPrefixOriginUnchanged ? Current.PrefixOrigin : Row->PrefixOrigin,
                         Row->SuffixOrigin == IpSuffixOriginUnchanged ? Current.SuffixOrigin : Row->SuffixOrigin);
}

DWORD Ipv6CreateUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  return create_address(Row, TCP_IPV6_STORE_ACTIVE);
}

DWORD Ipv6DeleteUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  return unicast_request(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, Row, 0, 0, 0);
}

DWORD Ipv6SetUnicastAddress(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  return set_address(Row, TCP_IPV6_STORE_ACTIVE);
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

static DWORD route_request6(ULONG Operation, ULONG Store, const MIB_IPFORWARD_ROW2 *Row, DWORD IfIndex)
{
  TCP_IPV6_ROUTE_REQUEST Request;

  memset(&Request, 0, sizeof(Request));
  Request.Operation = Operation;
  Request.Store = Store;
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
  /* the table of the stack holds the sum of the interface metric and the route metric (route2.c) */
  Out->dwForwardMetric1 = route_metric(Row->Metric) + Ipv4InterfaceMetric(IfIndex);
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
    return route_request6(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_ACTIVE, Row, IfIndex);

  legacy_row(Row, IfIndex, &Legacy);
  return CreateIpForwardEntry(&Legacy);
}

/* A change of an IPv6 route: what the row does not give stays what the route has */
static DWORD set_route6(const MIB_IPFORWARD_ROW2 *Row, DWORD IfIndex, ULONG Store)
{
  MIB_IPFORWARD_ROW2 Change = *Row, Current = *Row;
  DWORD Error;

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
  return route_request6(TCP_IPV6_CONFIG_SET, Store, &Change, IfIndex);
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
    return set_route6(Row, IfIndex, TCP_IPV6_STORE_ACTIVE);

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
    return route_request6(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, Row, IfIndex);

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

/* ---- the persistent store: what route.exe and netsh configure (NitroConfigureIpv6*) ----
 *
 * The stack writes the persistent store itself when a request names it (persist6.c): the records are the request
 * layout in the PersistentAddresses and PersistentRoutes values of Tcpip6\Parameters\Interfaces\<adapter GUID>
 * (the same place and format New-NetRoute and New-NetIPAddress with -PolicyStore PersistentStore use). User mode
 * only reads them, and puts one back after the removal from the active store alone, which the stack takes out of
 * both stores.
 */

#define PERSIST_ADDRESSES   L"PersistentAddresses"
#define PERSIST_ROUTES      L"PersistentRoutes"
#define PERSIST_MAX_VALUE   0x10000
#define ADDRESS_KEY_FROM    12      /* the address of a TCP_IPV6_ADDRESS_REQUEST */
#define ADDRESS_KEY_TO      28
#define ROUTE_KEY_FROM      12      /* the prefix, its length and the next hop of a TCP_IPV6_ROUTE_REQUEST */
#define ROUTE_KEY_TO        48

static const WCHAR Interfaces6Key[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\";

/* The registry path of the adapter of an interface: the name the stack gives an interface is its GUID text */
static BOOL adapter_key_path(DWORD IfIndex, WCHAR *Path, SIZE_T Count)
{
  const char *Name = getInterfaceNameByIndex(IfIndex);
  SIZE_T Prefix = wcslen(Interfaces6Key), Length, i;

  if (!Name)
    return FALSE;
  Length = strlen(Name);
  if (Length == 0 || Prefix + Length + 1 > Count)
  {
    consumeInterfaceName(Name);
    return FALSE;
  }
  wcscpy(Path, Interfaces6Key);
  for (i = 0; i < Length; i++)
    Path[Prefix + i] = (UCHAR)Name[i];
  Path[Prefix + Length] = 0;
  consumeInterfaceName(Name);
  return TRUE;
}

/* The records of a value of a key (a HeapAlloc block, the caller frees it), *Count of them; none: NULL and 0.
   *Unread (optional): a value of the right form is there but could not be read (no memory, or it grew between the
   two queries because the stack wrote it): NULL and 0 then do not mean "no record" */
static PUCHAR read_records(const WCHAR *Path, const WCHAR *Value, ULONG Size, PULONG Count, PBOOL Unread)
{
  HKEY Key;
  DWORD Type, Bytes = 0;
  PUCHAR Data = NULL;

  *Count = 0;
  if (Unread)
    *Unread = FALSE;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
    return NULL;

  if (RegQueryValueExW(Key, Value, NULL, &Type, NULL, &Bytes) == ERROR_SUCCESS && Type == REG_BINARY &&
      Bytes != 0 && Bytes <= PERSIST_MAX_VALUE && Bytes % Size == 0)
  {
    Data = HeapAlloc(GetProcessHeap(), 0, Bytes);
    if (Data && RegQueryValueExW(Key, Value, NULL, &Type, Data, &Bytes) == ERROR_SUCCESS && Type == REG_BINARY &&
        Bytes != 0 && Bytes % Size == 0)
    {
      *Count = Bytes / Size;
    }
    else
    {
      HeapFree(GetProcessHeap(), 0, Data);
      Data = NULL;
      if (Unread)
        *Unread = TRUE;
    }
  }
  RegCloseKey(Key);
  return Data;
}

/* The record of the value that has the key bytes [From, To) of Key, or NULL (points into Records) */
static PUCHAR find_record(PUCHAR Records, ULONG Count, ULONG Size, const UCHAR *Key, ULONG From, ULONG To)
{
  ULONG i;

  for (i = 0; Records && i < Count; i++)
  {
    if (!memcmp(Records + i * Size + From, Key + From, To - From))
      return Records + i * Size;
  }
  return NULL;
}

/* The persistent record with the key of Key, copied to Out (Size bytes): *Found if there is one. An error: the
   store could not be read, so it is not known whether there is one */
static DWORD saved_record(DWORD IfIndex, const WCHAR *Value, ULONG Size, const UCHAR *Key, ULONG From, ULONG To,
                          UCHAR *Out, PBOOL Found)
{
  WCHAR Path[160];
  ULONG Count;
  PUCHAR Records, Record;
  BOOL Unread;

  *Found = FALSE;
  if (!adapter_key_path(IfIndex, Path, ARRAYSIZE(Path)))
    return NO_ERROR;
  Records = read_records(Path, Value, Size, &Count, &Unread);
  if (Unread)
    return ERROR_NOT_ENOUGH_MEMORY;
  Record = find_record(Records, Count, Size, Key, From, To);
  if (Record)
  {
    memcpy(Out, Record, Size);
    *Found = TRUE;
  }
  HeapFree(GetProcessHeap(), 0, Records);
  return NO_ERROR;
}

/* Puts Record back into the value of the adapter of IfIndex (the stack removed it with the active entry). An error:
   the record is not back (the value is left as it was rather than written without the records it could not read) */
static DWORD put_record(DWORD IfIndex, const WCHAR *Value, ULONG Size, const UCHAR *Record, ULONG From, ULONG To)
{
  WCHAR Path[160];
  ULONG Count, i, Kept = 0;
  PUCHAR Records, All;
  HKEY Key;
  BOOL Unread;
  DWORD Error;

  if (!adapter_key_path(IfIndex, Path, ARRAYSIZE(Path)))
    return ERROR_NOT_FOUND;
  Records = read_records(Path, Value, Size, &Count, &Unread);
  if (Unread)
    return ERROR_NOT_ENOUGH_MEMORY;
  All = HeapAlloc(GetProcessHeap(), 0, (Count + 1) * Size);
  if (!All)
  {
    HeapFree(GetProcessHeap(), 0, Records);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  for (i = 0; i < Count; i++)
  {
    if (memcmp(Records + i * Size + From, Record + From, To - From))
      memcpy(All + Kept++ * Size, Records + i * Size, Size);
  }
  memcpy(All + Kept++ * Size, Record, Size);
  Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &Key,
                          NULL);
  if (Error == ERROR_SUCCESS)
  {
    Error = RegSetValueExW(Key, Value, 0, REG_BINARY, All, Kept * Size);
    RegCloseKey(Key);
  }
  HeapFree(GetProcessHeap(), 0, All);
  HeapFree(GetProcessHeap(), 0, Records);
  return Error;
}

/* The bits after the prefix length name nothing: the stack clears them before it keeps a route */
static void mask_prefix(UCHAR *Address, ULONG Length)
{
  ULONG i;

  for (i = 0; i < 16; i++)
  {
    LONG Bits = (LONG)Length - (LONG)i * 8;

    if (Bits >= 8)
      continue;
    Address[i] = Bits <= 0 ? 0 : (UCHAR)(Address[i] & (0xff << (8 - Bits)));
  }
}

static void route_key(const MIB_IPFORWARD_ROW2 *Row, TCP_IPV6_ROUTE_REQUEST *Key)
{
  memset(Key, 0, sizeof(*Key));
  memcpy(Key->Prefix, &Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, 16);
  mask_prefix(Key->Prefix, Row->DestinationPrefix.PrefixLength);
  Key->PrefixLength = Row->DestinationPrefix.PrefixLength;
  if (Row->NextHop.si_family == AF_INET6)
    memcpy(Key->NextHop, &Row->NextHop.Ipv6.sin6_addr, 16);
}

DWORD WINAPI NitroConfigureIpv6Route(ULONG Operation, BOOL Persistent, const MIB_IPFORWARD_ROW2 *Row)
{
  ADDRESS_FAMILY Family;
  ULONG Store = Persistent ? TCP_IPV6_STORE_PERSISTENT : TCP_IPV6_STORE_ACTIVE;
  TCP_IPV6_ROUTE_REQUEST Key, Saved;
  BOOL Kept;
  DWORD IfIndex = 0, Error;

  TRACE("(%lu, %d, %p)\n", Operation, Persistent, Row);

  if (Operation < TCP_IPV6_CONFIG_CREATE || Operation > TCP_IPV6_CONFIG_DELETE)
    return ERROR_INVALID_PARAMETER;
  Error = check_route_row(Row, &Family, &IfIndex);
  if (Error == NO_ERROR && Operation != TCP_IPV6_CONFIG_DELETE)
    Error = route_lifetimes_ok(Row);
  if (Error != NO_ERROR)
    return Error;
  if (Family != AF_INET6)
    return ERROR_INVALID_PARAMETER;

  if (Operation == TCP_IPV6_CONFIG_CREATE)
    return route_request6(Operation, Store, Row, IfIndex);
  if (Operation == TCP_IPV6_CONFIG_SET)
    return set_route6(Row, IfIndex, Store);

  /* the stack's removal takes the route out of both stores: one of the active store alone keeps the record */
  if (Persistent)
    return route_request6(Operation, Store, Row, IfIndex);
  route_key(Row, &Key);
  /* a store that cannot be read stops the removal: going on would lose the record */
  Error = saved_record(IfIndex, PERSIST_ROUTES, sizeof(Saved), (const UCHAR *)&Key, ROUTE_KEY_FROM, ROUTE_KEY_TO,
                       (UCHAR *)&Saved, &Kept);
  if (Error != NO_ERROR)
    return Error;
  Error = route_request6(Operation, Store, Row, IfIndex);
  if (Kept && Error == NO_ERROR)
    Error = put_record(IfIndex, PERSIST_ROUTES, sizeof(Saved), (const UCHAR *)&Saved, ROUTE_KEY_FROM, ROUTE_KEY_TO);
  return Error;
}

DWORD WINAPI NitroConfigureIpv6Address(ULONG Operation, BOOL Persistent, const MIB_UNICASTIPADDRESS_ROW *Row)
{
  ULONG Store = Persistent ? TCP_IPV6_STORE_PERSISTENT : TCP_IPV6_STORE_ACTIVE;
  TCP_IPV6_ADDRESS_REQUEST Key, Saved;
  BOOL Kept;
  DWORD IfIndex = 0, Error;

  TRACE("(%lu, %d, %p)\n", Operation, Persistent, Row);

  if (!Row || Row->Address.si_family != AF_INET6)
    return ERROR_INVALID_PARAMETER;
  if (Operation == TCP_IPV6_CONFIG_CREATE)
    return create_address(Row, Store);
  if (Operation == TCP_IPV6_CONFIG_SET)
    return set_address(Row, Store);
  if (Operation != TCP_IPV6_CONFIG_DELETE)
    return ERROR_INVALID_PARAMETER;

  if (Persistent)
    return unicast_request(Operation, Store, Row, 0, 0, 0);

  Error = row_interface(&Row->InterfaceLuid, Row->InterfaceIndex, &IfIndex);
  if (Error != NO_ERROR)
    return Error;
  memset(&Key, 0, sizeof(Key));
  memcpy(Key.Address, &Row->Address.Ipv6.sin6_addr, 16);
  Error = saved_record(IfIndex, PERSIST_ADDRESSES, sizeof(Saved), (const UCHAR *)&Key, ADDRESS_KEY_FROM,
                       ADDRESS_KEY_TO, (UCHAR *)&Saved, &Kept);
  if (Error != NO_ERROR)
    return Error;
  Error = unicast_request(Operation, Store, Row, 0, 0, 0);
  if (Kept && Error == NO_ERROR)
    Error = put_record(IfIndex, PERSIST_ADDRESSES, sizeof(Saved), (const UCHAR *)&Saved, ADDRESS_KEY_FROM,
                       ADDRESS_KEY_TO);
  return Error;
}

DWORD WINAPI NitroGetPersistentIpv6Routes(PMIB_IPFORWARD_TABLE2 *Table)
{
  HKEY Root;
  PMIB_IPFORWARD_TABLE2 Result = NULL;
  ULONG Capacity = 0, Used = 0, Index = 0;
  WCHAR Name[80], Path[160];
  DWORD NameLength, Error = NO_ERROR;
  const SIZE_T Header = FIELD_OFFSET(MIB_IPFORWARD_TABLE2, Table);

  TRACE("(%p)\n", Table);

  if (!Table)
    return ERROR_INVALID_PARAMETER;
  *Table = NULL;

  Result = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Header + sizeof(MIB_IPFORWARD_ROW2));
  if (!Result)
    return ERROR_NOT_ENOUGH_MEMORY;
  Capacity = 1;

  /* the key of the interfaces is not there until something is configured: no persistent route */
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Interfaces6Key, 0, KEY_ENUMERATE_SUB_KEYS, &Root) != ERROR_SUCCESS)
  {
    *Table = Result;
    return NO_ERROR;
  }

  for (;; Index++)
  {
    PTCP_IPV6_ROUTE_REQUEST Records;
    ULONG Count, i;
    char Narrow[80];
    DWORD IfIndex;
    ULONG64 Luid = 0;
    SIZE_T Length, j;

    NameLength = ARRAYSIZE(Name);
    if (RegEnumKeyExW(Root, Index, Name, &NameLength, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
      break;
    Length = wcslen(Interfaces6Key);
    if (NameLength == 0 || NameLength >= ARRAYSIZE(Narrow) || Length + NameLength + 1 > ARRAYSIZE(Path))
      continue;
    wcscpy(Path, Interfaces6Key);
    wcscpy(Path + Length, Name);
    for (j = 0; j <= NameLength; j++)
      Narrow[j] = Name[j] > 0x7f ? '?' : (char)Name[j];

    /* the adapter of the key: gone (removed) adapters have no interface, their routes are not shown */
    if (getInterfaceIndexByName(Narrow, &IfIndex) != NO_ERROR)
      continue;
    getInterfaceLuidByIndex(IfIndex, NULL, &Luid);

    Records = (PTCP_IPV6_ROUTE_REQUEST)read_records(Path, PERSIST_ROUTES, sizeof(*Records), &Count, NULL);
    for (i = 0; Records && i < Count; i++)
    {
      PMIB_IPFORWARD_ROW2 Row;

      if (Used == Capacity)
      {
        PMIB_IPFORWARD_TABLE2 Bigger = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Result,
                                                   Header + (Capacity * 2) * sizeof(MIB_IPFORWARD_ROW2));
        if (!Bigger)
        {
          Error = ERROR_NOT_ENOUGH_MEMORY;
          break;
        }
        Result = Bigger;
        Capacity *= 2;
      }

      Row = &Result->Table[Used++];
      InitializeIpForwardEntry(Row);
      Row->InterfaceLuid.Value = Luid;
      Row->InterfaceIndex = IfIndex;
      Row->DestinationPrefix.Prefix.si_family = AF_INET6;
      memcpy(&Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, Records[i].Prefix, 16);
      Row->DestinationPrefix.PrefixLength = (UINT8)Records[i].PrefixLength;
      Row->NextHop.si_family = AF_INET6;
      memcpy(&Row->NextHop.Ipv6.sin6_addr, Records[i].NextHop, 16);
      Row->Metric = Records[i].Metric;
      Row->ValidLifetime = Records[i].ValidLifetime;
      Row->PreferredLifetime = Records[i].PreferredLifetime;
      Row->Origin = Records[i].Origin;
      Row->Protocol = Records[i].Protocol;
      Row->Publish = (Records[i].Flags & TCP_IPV6_ROUTE_PUBLISH) != 0;
      Row->Immortal = (Records[i].Flags & TCP_IPV6_ROUTE_IMMORTAL) != 0;
      Row->Loopback = FALSE;
      Row->AutoconfigureAddress = FALSE;
    }
    HeapFree(GetProcessHeap(), 0, Records);
    if (Error != NO_ERROR)
      break;
  }
  RegCloseKey(Root);

  if (Error != NO_ERROR)
  {
    HeapFree(GetProcessHeap(), 0, Result);
    return Error;
  }
  Result->NumEntries = Used;
  *Table = Result;
  return NO_ERROR;
}
