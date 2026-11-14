/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The Vista interface and address tables (NETIO): GetIfTable2, GetIpInterfaceTable,
 *              GetUnicastIpAddressTable, GetAnycastIpAddressTable, the interface name and luid conversions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include <strsafe.h>
#include <wine/netioapi.h>

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/*
 * The tables are built from what the legacy queries give: GetIfTable for the interfaces, GetAdaptersAddresses for
 * their alias and description, GetIpAddrTable for the IPv4 addresses. IPv6 is in the tables only while the stack
 * has it on (Tcpip\Parameters\Ipv6Enable, see ipv6state.c): the IPv6 tables are empty and no interface is an IPv6
 * interface otherwise. What the stack cannot tell is filled in like Windows 10 does for an Ethernet adapter and
 * the loopback interface; the constants below were read from a Windows 10 22H2 system.
 */

#define NDIS_MEDIUM_LOOPBACK 17
#define LOOPBACK_ALIAS      L"Loopback Pseudo-Interface 1"
#define LOOPBACK_DESCR      L"Software Loopback Interface 1"
#define LOOPBACK_SPEED      1073741824ULL
#define LOOPBACK_ROW2_MTU   1500
#define LOOPBACK_IP_MTU     0xffffffffUL
#define LOOPBACK_METRIC     75

/* The loopback interface of the stack has no guid; this one is made up and the same on every system. */
static const GUID LoopbackGuid = { 0x6a6f6783, 0xd2ea, 0x11f1, { 0x9f, 0x53, 0x80, 0x6e, 0x6f, 0x6e, 0x69, 0x63 } };

typedef struct _NETIO_IF
{
  DWORD Index;
  ULONG Type;
  ULONG64 Luid;
  GUID Guid;
  BOOL Loopback;
  BOOL Connected;
  BOOL Dhcp;
  DWORD LeaseTerminates;                /* seconds since 1970, 0 when unknown */
  DWORD ManualMetric;                   /* Tcpip\Parameters\Interfaces\{guid}\InterfaceMetric, 0 = automatic */
  WCHAR Alias[IF_MAX_STRING_SIZE + 1];
  WCHAR Description[IF_MAX_STRING_SIZE + 1];
  MIB_IFROW Row;
} NETIO_IF;

static void *alloc_zeroed(SIZE_T Size)
{
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

/* Every table this DLL hands out comes from the process heap. */
VOID WINAPI FreeMibTable(PVOID Memory)
{
  TRACE("(%p)\n", Memory);
  if (Memory)
    HeapFree(GetProcessHeap(), 0, Memory);
}

static BOOL parse_guid(const BYTE *Text, DWORD Length, GUID *Guid)
{
  WCHAR Wide[48];
  UNICODE_STRING String;
  DWORD i;

  if (Length != 38)
    return FALSE;
  for (i = 0; i < Length; i++)
    Wide[i] = Text[i];
  Wide[Length] = 0;
  RtlInitUnicodeString(&String, Wide);
  return NT_SUCCESS(RtlGUIDFromString(&String, Guid));
}

static void read_dhcp_state(NETIO_IF *If)
{
  WCHAR Key[160];
  HKEY Handle;
  DWORD Size, Type, Value;
  int i;

  for (i = 0; i < 38; i++)
    Key[i] = If->Row.bDescr[i];
  Key[38] = 0;

  {
    static const WCHAR Prefix[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
    WCHAR Path[160];
    wcscpy(Path, Prefix);
    wcscat(Path, Key);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &Handle) != ERROR_SUCCESS)
      return;
  }

  Size = sizeof(Value);
  if (RegQueryValueExW(Handle, L"EnableDHCP", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
      Type == REG_DWORD && Value == 1)
  {
    If->Dhcp = TRUE;
    Size = sizeof(Value);
    if (RegQueryValueExW(Handle, L"LeaseTerminatesTime", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD)
      If->LeaseTerminates = Value;
  }

  /* a metric set by hand (netsh, Set-NetIPInterface, the adapter's advanced TCP/IP page); the stack reads the same value
     at bind time. 0 or no value = the automatic metric, and the stack takes at most 9999. */
  Size = sizeof(Value);
  if (RegQueryValueExW(Handle, L"InterfaceMetric", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
      Type == REG_DWORD && Value != 0)
    If->ManualMetric = min(Value, 9999);
  RegCloseKey(Handle);
}

/* The alias and description of the adapters, as GetAdaptersAddresses finds them. */
static void read_names(NETIO_IF *List, ULONG Count)
{
  PIP_ADAPTER_ADDRESSES Buffer = NULL, Adapter;
  ULONG Size = 0, Tries, i, Result = ERROR_BUFFER_OVERFLOW;
  ULONG Flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

  for (Tries = 0; Tries < 3 && Result == ERROR_BUFFER_OVERFLOW; Tries++)
  {
    HeapFree(GetProcessHeap(), 0, Buffer);
    Buffer = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Size && !Buffer)
      return;
    Result = GetAdaptersAddresses(AF_INET, Flags, NULL, Buffer, &Size);
  }

  for (i = 0; Result == ERROR_SUCCESS && i < Count; i++)
  {
    for (Adapter = Buffer; Adapter; Adapter = Adapter->Next)
    {
      if (Adapter->IfIndex != List[i].Index)
        continue;
      if (Adapter->FriendlyName)
        StringCchCopyNW(List[i].Alias, ARRAYSIZE(List[i].Alias), Adapter->FriendlyName, IF_MAX_STRING_SIZE);
      if (Adapter->Description)
        StringCchCopyNW(List[i].Description, ARRAYSIZE(List[i].Description), Adapter->Description, IF_MAX_STRING_SIZE);
      break;
    }
  }
  HeapFree(GetProcessHeap(), 0, Buffer);
}

/* All the interfaces of the stack, by index. Free the list with the process heap. */
static DWORD collect_interfaces(NETIO_IF **Out, ULONG *Count)
{
  PMIB_IFTABLE Table = NULL;
  NETIO_IF *List;
  ULONG Size = 0, Tries, i;
  DWORD Result = ERROR_INSUFFICIENT_BUFFER;

  for (Tries = 0; Tries < 3 && Result == ERROR_INSUFFICIENT_BUFFER; Tries++)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    Table = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Size && !Table)
      return ERROR_NOT_ENOUGH_MEMORY;
    Result = GetIfTable(Table, &Size, FALSE);
  }
  if (Result != NO_ERROR)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return Result == ERROR_NO_DATA ? ERROR_NOT_FOUND : Result;
  }

  List = alloc_zeroed((SIZE_T)Table->dwNumEntries * sizeof(*List) + 1);
  if (!List)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  for (i = 0; i < Table->dwNumEntries; i++)
  {
    NETIO_IF *If = &List[i];

    If->Row = Table->table[i];
    If->Index = If->Row.dwIndex;
    If->Type = If->Row.dwType;
    If->Luid = makeInterfaceLuid(If->Index, If->Type);
    If->Loopback = (If->Type == IF_TYPE_SOFTWARE_LOOPBACK);
    /* the same test as the OperStatus of GetAdaptersAddresses */
    If->Connected = (If->Row.dwOperStatus >= IF_OPER_STATUS_CONNECTING);

    if (If->Loopback)
    {
      If->Guid = LoopbackGuid;
    }
    else
    {
      if (!parse_guid(If->Row.bDescr, If->Row.dwDescrLen, &If->Guid))
        If->Guid.Data1 = If->Index;
      read_dhcp_state(If);
    }
  }
  *Count = Table->dwNumEntries;
  HeapFree(GetProcessHeap(), 0, Table);

  read_names(List, *Count);
  for (i = 0; i < *Count; i++)
  {
    NETIO_IF *If = &List[i];

    if (If->Loopback)
    {
      StringCchCopyW(If->Alias, ARRAYSIZE(If->Alias), LOOPBACK_ALIAS);
      StringCchCopyW(If->Description, ARRAYSIZE(If->Description), LOOPBACK_DESCR);
    }
    else if (!If->Alias[0])
    {
      StringCchCopyW(If->Alias, ARRAYSIZE(If->Alias), L"Ethernet");
    }
  }

  *Out = List;
  return NO_ERROR;
}

static NETIO_IF *find_by_luid(NETIO_IF *List, ULONG Count, ULONG64 Luid)
{
  ULONG i;

  for (i = 0; Luid && i < Count; i++)
    if (List[i].Luid == Luid)
      return &List[i];
  return NULL;
}

static NETIO_IF *find_by_index(NETIO_IF *List, ULONG Count, DWORD Index)
{
  ULONG i;

  for (i = 0; i < Count; i++)
    if (List[i].Index == Index)
      return &List[i];
  return NULL;
}

/*
 * The interface a row names. The luid wins over the index when both are given. Windows tells an unknown
 * index (ERROR_FILE_NOT_FOUND) from an unknown luid (ERROR_NOT_FOUND) for the IP rows.
 */
static NETIO_IF *find_row_interface(NETIO_IF *List, ULONG Count, ULONG64 Luid, DWORD Index, DWORD *Error)
{
  NETIO_IF *If;

  if (Luid)
  {
    If = find_by_luid(List, Count, Luid);
    *Error = If ? NO_ERROR : ERROR_NOT_FOUND;
    return If;
  }
  /* the loopback interface of the stack has index 0, which Windows reads as no index */
  If = Index ? find_by_index(List, Count, Index) : NULL;
  *Error = If ? NO_ERROR : (Index ? ERROR_FILE_NOT_FOUND : ERROR_INVALID_PARAMETER);
  return If;
}

/* ---- MIB_IF_ROW2 ---- */

/* The automatic interface metric of Windows for a link speed in bits per second. */
static ULONG automatic_metric(ULONG64 Speed)
{
  if (Speed > 200000000ULL)
    return 15;
  if (Speed > 80000000ULL)
    return 20;
  if (Speed > 20000000ULL)
    return 25;
  if (Speed > 4000000ULL)
    return 30;
  return 40;
}

static void fill_if_row2(const NETIO_IF *If, PMIB_IF_ROW2 Out, BOOL Statistics)
{
  const MIB_IFROW *Row = &If->Row;
  ULONG Length = min(Row->dwPhysAddrLen, IF_MAX_PHYS_ADDRESS_LENGTH);

  memset(Out, 0, sizeof(*Out));
  Out->InterfaceLuid.Value = If->Luid;
  Out->InterfaceIndex = If->Index;
  Out->InterfaceGuid = If->Guid;
  StringCchCopyW(Out->Alias, ARRAYSIZE(Out->Alias), If->Alias);
  StringCchCopyW(Out->Description, ARRAYSIZE(Out->Description), If->Description);
  Out->PhysicalAddressLength = Length;
  memcpy(Out->PhysicalAddress, Row->bPhysAddr, Length);
  memcpy(Out->PermanentPhysicalAddress, Row->bPhysAddr, Length);
  Out->Mtu = If->Loopback ? LOOPBACK_ROW2_MTU : Row->dwMtu;
  Out->Type = If->Type;
  Out->TunnelType = 0; /* TUNNEL_TYPE_NONE */
  Out->MediaType = If->Loopback ? NDIS_MEDIUM_LOOPBACK : NdisMedium802_3;
  Out->PhysicalMediumType = NdisPhysicalMediumUnspecified;
  Out->AccessType = If->Loopback ? NET_IF_ACCESS_LOOPBACK : NET_IF_ACCESS_BROADCAST;
  Out->DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
  Out->InterfaceAndOperStatusFlags.HardwareInterface = !If->Loopback;
  Out->InterfaceAndOperStatusFlags.ConnectorPresent = !If->Loopback;
  Out->InterfaceAndOperStatusFlags.NotMediaConnected = !If->Connected;
  Out->OperStatus = If->Connected ? IfOperStatusUp : IfOperStatusDown;
  Out->AdminStatus = (Row->dwAdminStatus == MIB_IF_ADMIN_STATUS_DOWN) ? NET_IF_ADMIN_STATUS_DOWN : NET_IF_ADMIN_STATUS_UP;
  Out->MediaConnectState = If->Connected ? MediaConnectStateConnected : MediaConnectStateDisconnected;
  Out->ConnectionType = NET_IF_CONNECTION_DEDICATED;
  Out->TransmitLinkSpeed = If->Loopback ? LOOPBACK_SPEED : Row->dwSpeed;
  Out->ReceiveLinkSpeed = Out->TransmitLinkSpeed;

  if (Statistics)
  {
    Out->InOctets = Row->dwInOctets;
    Out->InUcastPkts = Row->dwInUcastPkts;
    Out->InNUcastPkts = Row->dwInNUcastPkts;
    Out->InDiscards = Row->dwInDiscards;
    Out->InErrors = Row->dwInErrors;
    Out->InUnknownProtos = Row->dwInUnknownProtos;
    Out->OutOctets = Row->dwOutOctets;
    Out->OutUcastPkts = Row->dwOutUcastPkts;
    Out->OutNUcastPkts = Row->dwOutNUcastPkts;
    Out->OutDiscards = Row->dwOutDiscards;
    Out->OutErrors = Row->dwOutErrors;
    Out->OutQLen = Row->dwOutQLen;
  }
}

static DWORD get_if_table2(ULONG Level, PMIB_IF_TABLE2 *Table)
{
  NETIO_IF *List;
  PMIB_IF_TABLE2 Out;
  ULONG Count, i;
  DWORD Result;

  if (!Table || Level > 2)
    return ERROR_INVALID_PARAMETER;

  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
  {
    *Table = NULL;
    return Result;
  }

  Out = alloc_zeroed(FIELD_OFFSET(MIB_IF_TABLE2, Table) + (SIZE_T)(Count ? Count : 1) * sizeof(MIB_IF_ROW2));
  if (!Out)
  {
    HeapFree(GetProcessHeap(), 0, List);
    *Table = NULL;
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  Out->NumEntries = Count;
  for (i = 0; i < Count; i++)
    fill_if_row2(&List[i], &Out->Table[i], Level != 2);

  HeapFree(GetProcessHeap(), 0, List);
  *Table = Out;
  return NO_ERROR;
}

DWORD WINAPI GetIfTable2(PMIB_IF_TABLE2 *Table)
{
  return get_if_table2(0, Table);
}

DWORD WINAPI GetIfTable2Ex(MIB_IF_TABLE_LEVEL Level, PMIB_IF_TABLE2 *Table)
{
  return get_if_table2(Level, Table);
}

static DWORD get_if_entry2(ULONG Level, PMIB_IF_ROW2 Row)
{
  NETIO_IF *List, *If;
  ULONG Count;
  DWORD Result;

  if (!Row || Level > 2 || (!Row->InterfaceLuid.Value && !Row->InterfaceIndex))
    return ERROR_INVALID_PARAMETER;

  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;

  if (Row->InterfaceLuid.Value)
    If = find_by_luid(List, Count, Row->InterfaceLuid.Value);
  else
    If = find_by_index(List, Count, Row->InterfaceIndex);

  if (If)
    fill_if_row2(If, Row, Level != 2);
  HeapFree(GetProcessHeap(), 0, List);
  return If ? NO_ERROR : ERROR_FILE_NOT_FOUND;
}

DWORD WINAPI GetIfEntry2(PMIB_IF_ROW2 Row)
{
  return get_if_entry2(0, Row);
}

DWORD WINAPI GetIfEntry2Ex(MIB_IF_TABLE_LEVEL Level, PMIB_IF_ROW2 Row)
{
  return get_if_entry2(Level, Row);
}

/* ---- MIB_IPINTERFACE_ROW ---- */

VOID WINAPI InitializeIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row)
{
  if (!Row)
    return;

  memset(Row, 0xff, sizeof(*Row));
  Row->Family = AF_UNSPEC;
  Row->InterfaceLuid.Value = 0;
  Row->InterfaceIndex = 0;
  Row->BaseReachableTime = 0;
  Row->RetransmitTime = 0;
  Row->PathMtuDiscoveryTimeout = 0;
  Row->NlMtu = 0;
}

static void fill_ip_interface(const NETIO_IF *If, ADDRESS_FAMILY Family, PMIB_IPINTERFACE_ROW Out)
{
  ULONG i;

  memset(Out, 0, sizeof(*Out));
  Out->Family = Family;
  Out->InterfaceLuid.Value = If->Luid;
  Out->InterfaceIndex = If->Index;
  Out->UseAutomaticMetric = TRUE;
  Out->ManagedAddressConfigurationSupported = (Family == AF_INET);
  Out->OtherStatefulConfigurationSupported = (Family == AF_INET);
  Out->RouterDiscoveryBehavior = (Family == AF_INET) ? RouterDiscoveryDhcp : RouterDiscoveryEnabled;
  /* Windows 10 (measured): IPv4 link-local addresses are delayed (6.5 s), IPv6 ones are always on */
  Out->LinkLocalAddressBehavior = (Family == AF_INET) ? LinkLocalDelayed : LinkLocalAlwaysOn;
  Out->LinkLocalAddressTimeout = (Family == AF_INET) ? 6500 : 0;
  Out->BaseReachableTime = 30000;
  Out->RetransmitTime = 1000;
  Out->PathMtuDiscoveryTimeout = 600000;
  Out->MinRouterAdvertisementInterval = 200;
  Out->MaxRouterAdvertisementInterval = 600;
  Out->SitePrefixLength = 64;
  Out->ReachableTime = 30000;
  Out->Connected = If->Connected;

  for (i = 0; i < ScopeLevelCount; i++)
    Out->ZoneIndices[i] = (i < 4) ? If->Index : 1;
  Out->ZoneIndices[14] = 0;

  if (If->Loopback)
  {
    Out->NlMtu = LOOPBACK_IP_MTU;
    Out->Metric = LOOPBACK_METRIC;
  }
  else
  {
    Out->NlMtu = If->Row.dwMtu;
    if (If->ManualMetric)
    {
      Out->UseAutomaticMetric = FALSE;
      Out->Metric = If->ManualMetric;
    }
    else
      Out->Metric = automatic_metric(If->Row.dwSpeed);
    Out->UseNeighborUnreachabilityDetection = TRUE;
    Out->SupportsNeighborDiscovery = TRUE;
    Out->SupportsRouterDiscovery = TRUE;
    Out->DadTransmits = (Family == AF_INET) ? 3 : 1;
  }
}

DWORD WINAPI GetIpInterfaceTable(ADDRESS_FAMILY Family, PMIB_IPINTERFACE_TABLE *Table)
{
  NETIO_IF *List;
  IPV6_STATE V6;
  PMIB_IPINTERFACE_TABLE Out;
  ULONG Count = 0, i, Rows4, Rows6 = 0, Next = 0;
  DWORD Result;

  if (!Table || (Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;

  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
  {
    *Table = NULL;
    return Result;
  }

  /* every interface is an IPv4 interface; an IPv6 one only where the stack has IPv6 on */
  Rows4 = (Family == AF_INET6) ? 0 : Count;
  Ipv6GetState(&V6);
  if (Family != AF_INET)
    for (i = 0; i < Count; i++)
      if (Ipv6FindInterface(&V6, List[i].Index))
        Rows6++;

  Out = alloc_zeroed(FIELD_OFFSET(MIB_IPINTERFACE_TABLE, Table) +
                     (SIZE_T)((Rows4 + Rows6) ? (Rows4 + Rows6) : 1) * sizeof(MIB_IPINTERFACE_ROW));
  if (!Out)
  {
    Ipv6FreeState(&V6);
    HeapFree(GetProcessHeap(), 0, List);
    *Table = NULL;
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  for (i = 0; i < Rows4; i++)
    fill_ip_interface(&List[i], AF_INET, &Out->Table[Next++]);
  for (i = 0; Rows6 && i < Count; i++)
    if (Ipv6FindInterface(&V6, List[i].Index))
      fill_ip_interface(&List[i], AF_INET6, &Out->Table[Next++]);
  Out->NumEntries = Next;

  Ipv6FreeState(&V6);
  HeapFree(GetProcessHeap(), 0, List);
  *Table = Out;
  return NO_ERROR;
}

DWORD WINAPI GetIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row)
{
  NETIO_IF *List, *If;
  ULONG Count;
  DWORD Result, Error;

  if (!Row || (Row->Family != AF_INET && Row->Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;

  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;

  If = find_row_interface(List, Count, Row->InterfaceLuid.Value, Row->InterfaceIndex, &Error);
  if (If && Row->Family == AF_INET6)
  {
    IPV6_STATE V6;

    /* an IPv6 interface is one the stack has IPv6 on (none while it is off) */
    Ipv6GetState(&V6);
    if (!Ipv6FindInterface(&V6, If->Index))
    {
      If = NULL;
      Error = ERROR_NOT_FOUND;
    }
    Ipv6FreeState(&V6);
  }
  if (If)
  {
    ADDRESS_FAMILY Family = Row->Family;

    fill_ip_interface(If, Family, Row);
  }
  HeapFree(GetProcessHeap(), 0, List);
  return If ? NO_ERROR : Error;
}

/* ---- MIB_UNICASTIPADDRESS_ROW ---- */

static BOOL get_address_table(PMIB_IPADDRTABLE *Out)
{
  PMIB_IPADDRTABLE Table = NULL;
  ULONG Size = 0, Tries;
  DWORD Result = ERROR_INSUFFICIENT_BUFFER;

  for (Tries = 0; Tries < 3 && Result == ERROR_INSUFFICIENT_BUFFER; Tries++)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    Table = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
    if (Size && !Table)
      return FALSE;
    Result = GetIpAddrTable(Table, &Size, FALSE);
  }
  if (Result != NO_ERROR)
  {
    HeapFree(GetProcessHeap(), 0, Table);
    return FALSE;
  }
  *Out = Table;
  return TRUE;
}

static UINT8 mask_to_prefix_length(DWORD Mask)
{
  DWORD Host = ntohl(Mask);
  UINT8 Length = 0;

  while (Host & 0x80000000UL)
  {
    Length++;
    Host <<= 1;
  }
  return Length;
}

static LONGLONG boot_time_filetime(void)
{
  FILETIME Now;
  ULARGE_INTEGER Value;

  GetSystemTimeAsFileTime(&Now);
  Value.LowPart = Now.dwLowDateTime;
  Value.HighPart = Now.dwHighDateTime;
  return (LONGLONG)Value.QuadPart - (LONGLONG)GetTickCount() * 10000;
}

static void fill_unicast_row(const NETIO_IF *If, const MIB_IPADDRROW *Address, PMIB_UNICASTIPADDRESS_ROW Out)
{
  memset(Out, 0, sizeof(*Out));
  Out->Address.Ipv4.sin_family = AF_INET;
  Out->Address.Ipv4.sin_addr.s_addr = Address->dwAddr;
  Out->InterfaceLuid.Value = If->Luid;
  Out->InterfaceIndex = If->Index;
  Out->OnLinkPrefixLength = mask_to_prefix_length(Address->dwMask);
  Out->DadState = IpDadStatePreferred;
  Out->ValidLifetime = 0xffffffff;
  Out->PreferredLifetime = 0xffffffff;
  Out->CreationTimeStamp.QuadPart = boot_time_filetime();

  if (If->Loopback)
  {
    Out->PrefixOrigin = IpPrefixOriginWellKnown;
    Out->SuffixOrigin = IpSuffixOriginWellKnown;
  }
  else if (If->Dhcp)
  {
    FILETIME Now;
    ULARGE_INTEGER Value;
    ULONGLONG Seconds;

    Out->PrefixOrigin = IpPrefixOriginDhcp;
    Out->SuffixOrigin = IpSuffixOriginDhcp;
    GetSystemTimeAsFileTime(&Now);
    Value.LowPart = Now.dwLowDateTime;
    Value.HighPart = Now.dwHighDateTime;
    Seconds = (Value.QuadPart - 116444736000000000ULL) / 10000000ULL;
    if (If->LeaseTerminates)
    {
      Out->ValidLifetime = If->LeaseTerminates > Seconds ? (ULONG)(If->LeaseTerminates - Seconds) : 0;
      Out->PreferredLifetime = Out->ValidLifetime;
    }
  }
  else
  {
    Out->PrefixOrigin = IpPrefixOriginManual;
    Out->SuffixOrigin = IpSuffixOriginManual;
  }
}

/* An IPv6 address of the stack. The zone of a link-local address is its interface (Windows 10 measured: the scope
   id of the address and of the row are the interface index, 0 for ::1) */
static void fill_unicast_row6(const NETIO_IF *If, const TCP_IPV6_ADDRESS_ROW *Address, PMIB_UNICASTIPADDRESS_ROW Out)
{
  BOOL LinkLocal = Address->Address[0] == 0xFE && (Address->Address[1] & 0xC0) == 0x80;

  memset(Out, 0, sizeof(*Out));
  Out->Address.Ipv6.sin6_family = AF_INET6;
  memcpy(&Out->Address.Ipv6.sin6_addr, Address->Address, 16);
  if (LinkLocal)
  {
    Out->Address.Ipv6.sin6_scope_id = If->Index;
    Out->ScopeId.Value = If->Index;
  }
  Out->InterfaceLuid.Value = If->Luid;
  Out->InterfaceIndex = If->Index;
  Out->PrefixOrigin = Address->PrefixOrigin;
  Out->SuffixOrigin = Address->SuffixOrigin;
  Out->ValidLifetime = Address->ValidLifetime;
  Out->PreferredLifetime = Address->PreferredLifetime;
  Out->OnLinkPrefixLength = (UINT8)Address->PrefixLength;
  Out->DadState = Address->DadState;
  Out->CreationTimeStamp.QuadPart = boot_time_filetime();
}

DWORD WINAPI GetUnicastIpAddressTable(ADDRESS_FAMILY Family, PMIB_UNICASTIPADDRESS_TABLE *Table)
{
  NETIO_IF *List;
  PMIB_IPADDRTABLE Addresses = NULL;
  PMIB_UNICASTIPADDRESS_TABLE Out;
  IPV6_STATE V6 = { 0 };
  ULONG Count = 0, i, j, Rows = 0, Next = 0;
  DWORD Result;

  if (!Table || (Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;

  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
  {
    *Table = NULL;
    return Result;
  }
  if (Family != AF_INET6 && !get_address_table(&Addresses))
    Addresses = NULL;

  if (Addresses)
    for (j = 0; j < Addresses->dwNumEntries; j++)
      if (Addresses->table[j].dwAddr && find_by_index(List, Count, Addresses->table[j].dwIndex))
        Rows++;

  /* the IPv6 addresses the stack has (none while IPv6 is off), after the IPv4 ones as Windows 10 lists them */
  if (Family != AF_INET && Ipv6GetState(&V6))
    for (j = 0; j < V6.Header->AddressCount; j++)
      if (find_by_index(List, Count, V6.Addresses[j].IfIndex))
        Rows++;

  Out = alloc_zeroed(FIELD_OFFSET(MIB_UNICASTIPADDRESS_TABLE, Table) + (SIZE_T)(Rows ? Rows : 1) * sizeof(MIB_UNICASTIPADDRESS_ROW));
  if (!Out)
  {
    Ipv6FreeState(&V6);
    HeapFree(GetProcessHeap(), 0, Addresses);
    HeapFree(GetProcessHeap(), 0, List);
    *Table = NULL;
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  /* by interface, in the order of the interfaces */
  for (i = 0; Addresses && i < Count; i++)
    for (j = 0; j < Addresses->dwNumEntries; j++)
      if (Addresses->table[j].dwAddr && Addresses->table[j].dwIndex == List[i].Index)
        fill_unicast_row(&List[i], &Addresses->table[j], &Out->Table[Next++]);
  for (i = 0; V6.Header && i < Count; i++)
    for (j = 0; j < V6.Header->AddressCount; j++)
      if (V6.Addresses[j].IfIndex == List[i].Index)
        fill_unicast_row6(&List[i], &V6.Addresses[j], &Out->Table[Next++]);
  Out->NumEntries = Next;

  Ipv6FreeState(&V6);
  HeapFree(GetProcessHeap(), 0, Addresses);
  HeapFree(GetProcessHeap(), 0, List);
  *Table = Out;
  return NO_ERROR;
}

/*
 * The stack has no anycast addresses and Windows 10 returns an empty table, with NO_ERROR, on a system that has
 * none (the same arguments are rejected as for GetUnicastIpAddressTable). Java's net.dll delay-loads it.
 */
DWORD WINAPI GetAnycastIpAddressTable(ADDRESS_FAMILY Family, PMIB_ANYCASTIPADDRESS_TABLE *Table)
{
  PMIB_ANYCASTIPADDRESS_TABLE Out;

  TRACE("(%u, %p)\n", Family, Table);

  if (!Table || (Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;

  Out = alloc_zeroed(sizeof(*Out));
  if (!Out)
  {
    *Table = NULL;
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  *Table = Out;
  return NO_ERROR;
}

DWORD WINAPI GetUnicastIpAddressEntry(PMIB_UNICASTIPADDRESS_ROW Row)
{
  NETIO_IF *List, *If;
  PMIB_IPADDRTABLE Addresses;
  ULONG Count, j;
  DWORD Result, Error;
  BOOL Found = FALSE;

  if (!Row || (Row->Address.si_family != AF_INET && Row->Address.si_family != AF_INET6))
    return ERROR_INVALID_PARAMETER;

  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;

  /* Windows needs the interface: an address alone is not enough */
  If = find_row_interface(List, Count, Row->InterfaceLuid.Value, Row->InterfaceIndex, &Error);
  if (!If)
  {
    if (Error == ERROR_INVALID_PARAMETER)
      Error = ERROR_FILE_NOT_FOUND;
  }
  else
  {
    Error = ERROR_NOT_FOUND;
    if (Row->Address.si_family == AF_INET && get_address_table(&Addresses))
    {
      for (j = 0; j < Addresses->dwNumEntries && !Found; j++)
      {
        if (Addresses->table[j].dwIndex == If->Index && Addresses->table[j].dwAddr &&
            Addresses->table[j].dwAddr == Row->Address.Ipv4.sin_addr.s_addr)
        {
          fill_unicast_row(If, &Addresses->table[j], Row);
          Found = TRUE;
        }
      }
      HeapFree(GetProcessHeap(), 0, Addresses);
    }
    else if (Row->Address.si_family == AF_INET6)
    {
      IPV6_STATE V6;

      /* an IPv6 address the stack has on this interface (none while IPv6 is off) */
      if (Ipv6GetState(&V6))
      {
        for (j = 0; j < V6.Header->AddressCount && !Found; j++)
        {
          if (V6.Addresses[j].IfIndex == If->Index &&
              !memcmp(V6.Addresses[j].Address, &Row->Address.Ipv6.sin6_addr, 16))
          {
            fill_unicast_row6(If, &V6.Addresses[j], Row);
            Found = TRUE;
          }
        }
        Ipv6FreeState(&V6);
      }
    }
  }
  HeapFree(GetProcessHeap(), 0, List);
  return Found ? NO_ERROR : Error;
}

VOID WINAPI InitializeUnicastIpAddressEntry(PMIB_UNICASTIPADDRESS_ROW Row)
{
  if (!Row)
    return;

  /* UNVERIFIED against Windows: the oracle probe of the oraxe2 lane returned no output */
  memset(Row, 0, sizeof(*Row));
  Row->OnLinkPrefixLength = 255;
  Row->ValidLifetime = 0xffffffff;
  Row->PreferredLifetime = 0xffffffff;
}

/* The IPv4 address of the interface the row names, or the error to return. The stack keeps one IPv4 address
   per interface, and its NTE context (DeleteIPAddress) is the index of the interface. */
static DWORD unicast_row_interface(const MIB_UNICASTIPADDRESS_ROW *Row, DWORD *Index, DWORD *Current)
{
  NETIO_IF *List, *If;
  PMIB_IPADDRTABLE Addresses;
  ULONG Count, j;
  DWORD Result, Error;

  *Current = 0;
  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;

  If = find_row_interface(List, Count, Row->InterfaceLuid.Value, Row->InterfaceIndex, &Error);
  if (If)
  {
    *Index = If->Index;
    if (get_address_table(&Addresses))
    {
      for (j = 0; j < Addresses->dwNumEntries; j++)
        if (Addresses->table[j].dwIndex == If->Index && Addresses->table[j].dwAddr)
          *Current = Addresses->table[j].dwAddr;
      HeapFree(GetProcessHeap(), 0, Addresses);
    }
  }
  HeapFree(GetProcessHeap(), 0, List);
  return Error;
}

DWORD WINAPI CreateUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  DWORD Index = 0, Current, Error, Context, Instance;
  ULONG Mask;

  if (!Row || (Row->Address.si_family != AF_INET && Row->Address.si_family != AF_INET6))
    return ERROR_INVALID_PARAMETER;
  if (Row->Address.si_family == AF_INET6)
    return ERROR_NOT_SUPPORTED;
  if (!Row->Address.Ipv4.sin_addr.s_addr || Row->OnLinkPrefixLength > 32)
    return ERROR_INVALID_PARAMETER;

  Error = unicast_row_interface(Row, &Index, &Current);
  if (Error != NO_ERROR)
    return Error;
  if (Current == Row->Address.Ipv4.sin_addr.s_addr)
    return ERROR_OBJECT_ALREADY_EXISTS;
  /* a second address on an interface would replace the first in this stack */
  if (Current)
    return ERROR_NOT_SUPPORTED;

  ConvertLengthToIpv4Mask(Row->OnLinkPrefixLength, &Mask);
  return AddIPAddress(Row->Address.Ipv4.sin_addr.s_addr, Mask, Index, &Context, &Instance);
}

DWORD WINAPI DeleteUnicastIpAddressEntry(const MIB_UNICASTIPADDRESS_ROW *Row)
{
  DWORD Index = 0, Current, Error;

  if (!Row || (Row->Address.si_family != AF_INET && Row->Address.si_family != AF_INET6))
    return ERROR_INVALID_PARAMETER;
  if (Row->Address.si_family == AF_INET6)
    return ERROR_NOT_FOUND;

  Error = unicast_row_interface(Row, &Index, &Current);
  if (Error != NO_ERROR)
    return Error;
  if (!Row->Address.Ipv4.sin_addr.s_addr || Current != Row->Address.Ipv4.sin_addr.s_addr)
    return ERROR_NOT_FOUND;

  return DeleteIPAddress(Index);
}

/* ---- interface names and luids ---- */

static const struct { ULONG Type; const char *Name; } TypeNames[] =
{
  { IF_TYPE_ETHERNET_CSMACD, "ethernet" },
  { IF_TYPE_ISO88025_TOKENRING, "iso88025_tokenring" },
  { IF_TYPE_PPP, "ppp" },
  { IF_TYPE_SOFTWARE_LOOPBACK, "loopback" },
  { IF_TYPE_ATM, "atm" },
  { IF_TYPE_IEEE80211, "wireless" },
  { 131 /* IF_TYPE_TUNNEL */, "tunnel" },
  { 144 /* IF_TYPE_IEEE1394 */, "ieee1394" },
};

/* "ethernet_32769": the type name and the network index of the luid */
static void luid_to_name(ULONG64 Luid, char *Name, size_t Size)
{
  ULONG Type = (ULONG)(Luid >> 48);
  ULONG Number = (ULONG)((Luid >> 24) & 0xffffff);
  const char *Text = "other";
  size_t i;

  for (i = 0; i < ARRAYSIZE(TypeNames); i++)
    if (TypeNames[i].Type == Type)
      Text = TypeNames[i].Name;
  snprintf(Name, Size, "%s_%lu", Text, Number);
}

static BOOL name_to_luid(const char *Name, ULONG64 *Luid)
{
  const char *Underscore = strrchr(Name, '_');
  const char *Digits;
  size_t i, Length;
  ULONG64 Number = 0;

  if (!Underscore || Underscore == Name)
    return FALSE;
  Digits = Underscore + 1;
  if (!*Digits)
    return FALSE;
  for (; *Digits; Digits++)
  {
    if (*Digits < '0' || *Digits > '9')
      return FALSE;
    Number = Number * 10 + (*Digits - '0');
    if (Number > 0xffffff)
      return FALSE;
  }

  Length = Underscore - Name;
  for (i = 0; i < ARRAYSIZE(TypeNames); i++)
  {
    if (strlen(TypeNames[i].Name) == Length && !_strnicmp(Name, TypeNames[i].Name, Length))
    {
      *Luid = ((ULONG64)TypeNames[i].Type << 48) | (Number << 24);
      return TRUE;
    }
  }
  return FALSE;
}

DWORD WINAPI ConvertInterfaceIndexToLuid(NET_IFINDEX Index, PNET_LUID Luid)
{
  ULONG Type;

  if (!Luid)
    return ERROR_INVALID_PARAMETER;
  Luid->Value = 0;
  if (!Index)
    return ERROR_FILE_NOT_FOUND;
  return getInterfaceLuidByIndex(Index, &Type, &Luid->Value) ? NO_ERROR : ERROR_FILE_NOT_FOUND;
}

DWORD WINAPI ConvertInterfaceLuidToIndex(const NET_LUID *Luid, PNET_IFINDEX Index)
{
  DWORD Value = 0;

  if (!Luid || !Index)
    return ERROR_INVALID_PARAMETER;
  *Index = 0;
  if (!getInterfaceIndexByLuid(Luid->Value, &Value))
    return ERROR_FILE_NOT_FOUND;
  *Index = Value;
  return NO_ERROR;
}

DWORD WINAPI ConvertInterfaceLuidToNameA(const NET_LUID *Luid, PSTR Name, SIZE_T Length)
{
  char Text[64];

  if (!Luid || !Name)
    return ERROR_INVALID_PARAMETER;
  luid_to_name(Luid->Value, Text, sizeof(Text));
  if (Length < strlen(Text) + 1)
    return ERROR_NOT_ENOUGH_MEMORY;
  strcpy(Name, Text);
  return NO_ERROR;
}

DWORD WINAPI ConvertInterfaceLuidToNameW(const NET_LUID *Luid, PWSTR Name, SIZE_T Length)
{
  char Text[64];
  size_t i, Needed;

  if (!Luid || !Name)
    return ERROR_INVALID_PARAMETER;
  luid_to_name(Luid->Value, Text, sizeof(Text));
  Needed = strlen(Text) + 1;
  if (Length < Needed)
    return ERROR_NOT_ENOUGH_MEMORY;
  for (i = 0; i < Needed; i++)
    Name[i] = (UCHAR)Text[i];
  return NO_ERROR;
}

DWORD WINAPI ConvertInterfaceNameToLuidA(const char *Name, PNET_LUID Luid)
{
  ULONG64 Value;
  DWORD Index;

  if (!Name || !Luid)
    return ERROR_INVALID_PARAMETER;
  Luid->Value = 0;
  if (!name_to_luid(Name, &Value))
    return ERROR_INVALID_NAME;
  if (!getInterfaceIndexByLuid(Value, &Index))
    return ERROR_FILE_NOT_FOUND;
  Luid->Value = Value;
  return NO_ERROR;
}

DWORD WINAPI ConvertInterfaceNameToLuidW(const WCHAR *Name, PNET_LUID Luid)
{
  char Text[64];
  size_t i;

  if (!Name || !Luid)
    return ERROR_INVALID_PARAMETER;
  for (i = 0; Name[i]; i++)
  {
    if (i >= sizeof(Text) - 1 || Name[i] > 0x7f)
    {
      Luid->Value = 0;
      return ERROR_INVALID_NAME;
    }
    Text[i] = (char)Name[i];
  }
  Text[i] = 0;
  return ConvertInterfaceNameToLuidA(Text, Luid);
}

DWORD WINAPI ConvertInterfaceLuidToAlias(const NET_LUID *Luid, PWSTR Alias, SIZE_T Length)
{
  NETIO_IF *List, *If;
  ULONG Count;
  DWORD Result;

  if (!Luid || !Alias)
    return ERROR_INVALID_PARAMETER;
  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;
  If = find_by_luid(List, Count, Luid->Value);
  if (!If)
    Result = ERROR_FILE_NOT_FOUND;
  else if (Length < wcslen(If->Alias) + 1)
    Result = ERROR_NOT_ENOUGH_MEMORY;
  else
  {
    wcscpy(Alias, If->Alias);
    Result = NO_ERROR;
  }
  HeapFree(GetProcessHeap(), 0, List);
  return Result;
}

DWORD WINAPI ConvertInterfaceAliasToLuid(const WCHAR *Alias, PNET_LUID Luid)
{
  NETIO_IF *List;
  ULONG Count, i;
  DWORD Result;

  if (!Alias || !Luid)
    return ERROR_INVALID_PARAMETER;
  Luid->Value = 0;
  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;
  Result = ERROR_INVALID_PARAMETER;
  for (i = 0; i < Count; i++)
  {
    if (!_wcsicmp(List[i].Alias, Alias))
    {
      Luid->Value = List[i].Luid;
      Result = NO_ERROR;
      break;
    }
  }
  HeapFree(GetProcessHeap(), 0, List);
  return Result;
}

DWORD WINAPI ConvertInterfaceLuidToGuid(const NET_LUID *Luid, GUID *Guid)
{
  NETIO_IF *List, *If;
  ULONG Count;
  DWORD Result;

  if (!Luid || !Guid)
    return ERROR_INVALID_PARAMETER;
  memset(Guid, 0, sizeof(*Guid));
  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;
  If = find_by_luid(List, Count, Luid->Value);
  if (If)
    *Guid = If->Guid;
  HeapFree(GetProcessHeap(), 0, List);
  return If ? NO_ERROR : ERROR_FILE_NOT_FOUND;
}

DWORD WINAPI ConvertInterfaceGuidToLuid(const GUID *Guid, PNET_LUID Luid)
{
  NETIO_IF *List;
  ULONG Count, i;
  DWORD Result;

  if (!Guid || !Luid)
    return ERROR_INVALID_PARAMETER;
  Luid->Value = 0;
  Result = collect_interfaces(&List, &Count);
  if (Result != NO_ERROR)
    return Result;
  Result = ERROR_FILE_NOT_FOUND;
  for (i = 0; i < Count; i++)
  {
    if (!memcmp(&List[i].Guid, Guid, sizeof(*Guid)))
    {
      Luid->Value = List[i].Luid;
      Result = NO_ERROR;
      break;
    }
  }
  HeapFree(GetProcessHeap(), 0, List);
  return Result;
}

PCHAR WINAPI if_indextoname(NET_IFINDEX Index, PCHAR Name)
{
  ULONG Type;
  ULONG64 Luid;

  if (!Name || !Index || !getInterfaceLuidByIndex(Index, &Type, &Luid))
    return NULL;
  luid_to_name(Luid, Name, IF_MAX_STRING_SIZE);
  return Name;
}

NET_IFINDEX WINAPI if_nametoindex(PCSTR Name)
{
  ULONG64 Luid;
  DWORD Index;

  if (!Name || !name_to_luid(Name, &Luid) || !getInterfaceIndexByLuid(Luid, &Index))
    return 0;
  return Index;
}
