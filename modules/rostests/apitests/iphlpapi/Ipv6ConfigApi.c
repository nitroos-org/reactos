/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The IPv6 configuration functions of the IP Helper: Create/Set/DeleteUnicastIpAddressEntry for an IPv6
 *              address, InitializeIpForwardEntry and Create/Set/Get/DeleteIpForwardEntry2 for IPv6 (and an IPv4
 *              route). The defaults and the answers to rows that cannot be added were probed on Windows 10 22H2
 *              (read-only: no row was added there): a NULL row or one without a family is ERROR_INVALID_PARAMETER,
 *              then the interface is looked for (unknown luid ERROR_NOT_FOUND, unknown index ERROR_FILE_NOT_FOUND),
 *              then the prefix length and the next hop are checked. The rest follows the documentation.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"

/* MIB_UNICASTIPADDRESS_ROW */
typedef struct
{
    SOCKADDR_INET Address;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    ULONG PrefixOrigin;
    ULONG SuffixOrigin;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    UINT8 OnLinkPrefixLength;
    BOOLEAN SkipAsSource;
    ULONG DadState;
    SCOPE_ID ScopeId;
    LARGE_INTEGER CreationTimeStamp;
} UNICAST_ROW6;

typedef struct
{
    ULONG NumEntries;
    UNICAST_ROW6 Table[1];
} UNICAST_TABLE6;

typedef DWORD (WINAPI *PFN_ROW)(PVOID);
typedef VOID (WINAPI *PFN_INIT)(PVOID);

static PFN_GET_TABLE pGetUnicastIpAddressTable, pGetIpForwardTable2;
static PFN_FREE_TABLE pFreeMibTable;
static PFN_ROW pCreateUnicastIpAddressEntry, pDeleteUnicastIpAddressEntry, pSetUnicastIpAddressEntry,
               pGetUnicastIpAddressEntry;
static PFN_ROW pCreateIpForwardEntry2, pDeleteIpForwardEntry2, pSetIpForwardEntry2, pGetIpForwardEntry2;
static PFN_INIT pInitializeUnicastIpAddressEntry, pInitializeIpForwardEntry;

#define ORIGIN_MANUAL   1
#define UNKNOWN_INDEX   0x7ffffff0
#define UNKNOWN_LUID    0x0006000000fff000ULL

static ULONG EthernetIndex(void)
{
    UNICAST_TABLE6 *Table = NULL;
    ULONG i, Index = 0;

    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return 0;
    for (i = 0; i < Table->NumEntries && !Index; i++)
    {
        if (Ipv6IsLinkLocal(Table->Table[i].Address.Ipv6.sin6_addr.u.Byte) &&
            (Table->Table[i].InterfaceLuid.Value >> 48) != 24)
            Index = Table->Table[i].InterfaceIndex;
    }
    pFreeMibTable(Table);
    return Index;
}

/* Any interface that is not the loopback interface (IPv6 off: by its IPv4 address) */
static ULONG AnyIndex(void)
{
    UNICAST_TABLE6 *Table = NULL;
    ULONG i, Index = 0;

    if (pGetUnicastIpAddressTable(AF_UNSPEC, (PVOID *)&Table) != NO_ERROR || !Table)
        return 0;
    for (i = 0; i < Table->NumEntries && !Index; i++)
    {
        if ((Table->Table[i].InterfaceLuid.Value >> 48) != 24)
            Index = Table->Table[i].InterfaceIndex;
    }
    pFreeMibTable(Table);
    return Index;
}

static void TestInitialize(void)
{
    ROUTE_ROW6 Route;
    UNICAST_ROW6 Row;

    memset(&Row, 0xaa, sizeof(Row));
    pInitializeUnicastIpAddressEntry(&Row);
    ok(Row.Address.si_family == AF_UNSPEC && Row.InterfaceIndex == 0 && Row.InterfaceLuid.Value == 0, "address\n");
    ok(Row.PrefixOrigin == 16 && Row.SuffixOrigin == 16, "origins %lu %lu\n", Row.PrefixOrigin, Row.SuffixOrigin);
    ok(Row.ValidLifetime == 0xffffffff && Row.PreferredLifetime == 0xffffffff, "lifetimes\n");
    ok(Row.OnLinkPrefixLength == 255 && Row.SkipAsSource == FALSE, "length %u skip %u\n", Row.OnLinkPrefixLength,
       Row.SkipAsSource);
    ok(Row.DadState == 0 && Row.ScopeId.Value == 0 && Row.CreationTimeStamp.QuadPart == 0, "dad %lu\n", Row.DadState);

    memset(&Route, 0xaa, sizeof(Route));
    pInitializeIpForwardEntry(&Route);
    ok(Route.InterfaceLuid.Value == 0 && Route.InterfaceIndex == 0, "interface\n");
    ok(Route.DestinationPrefix.Prefix.si_family == AF_UNSPEC && Route.DestinationPrefix.PrefixLength == 0,
       "destination %u /%u\n", Route.DestinationPrefix.Prefix.si_family, Route.DestinationPrefix.PrefixLength);
    ok(Route.NextHop.si_family == AF_UNSPEC, "next hop %u\n", Route.NextHop.si_family);
    ok(Route.SitePrefixLength == 255, "site prefix length %u\n", Route.SitePrefixLength);
    ok(Route.ValidLifetime == 0xffffffff && Route.PreferredLifetime == 0xffffffff, "lifetimes %lx %lx\n",
       Route.ValidLifetime, Route.PreferredLifetime);
    ok(Route.Metric == 0xffffffff, "metric %lx\n", Route.Metric);
    ok(Route.Protocol == 0xffffffff, "protocol %lx\n", Route.Protocol);
    ok(Route.Loopback == 255 && Route.AutoconfigureAddress == 255 && Route.Publish == 255 &&
       Route.Immortal == 255, "flags %u %u %u %u\n", Route.Loopback, Route.AutoconfigureAddress, Route.Publish,
       Route.Immortal);
    ok(Route.Origin == 0 && Route.Age == 0, "origin %lu age %lu\n", Route.Origin, Route.Age);
    pInitializeIpForwardEntry(NULL);
}

static void InitRoute(ROUTE_ROW6 *Route, ULONG IfIndex, const char *Prefix, UINT8 Length, const char *NextHop)
{
    pInitializeIpForwardEntry(Route);
    Route->InterfaceIndex = IfIndex;
    Ipv6Parse(&Route->DestinationPrefix.Prefix, Prefix, 0);
    Route->DestinationPrefix.PrefixLength = Length;
    if (NextHop)
        Ipv6Parse(&Route->NextHop, NextHop, 0);
}

static void TestRouteInvalid(ULONG IfIndex)
{
    ROUTE_ROW6 Route;
    DWORD Error;

    ok(pCreateIpForwardEntry2(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");
    ok(pDeleteIpForwardEntry2(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");
    ok(pSetIpForwardEntry2(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");
    ok(pGetIpForwardEntry2(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");

    InitRoute(&Route, IfIndex, "2001:db8:9c::", 129, "fe80::9c");
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_INVALID_PARAMETER, "prefix length 129: %lu\n", Error);
    Route.InterfaceIndex = UNKNOWN_INDEX;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_FILE_NOT_FOUND, "prefix length 129, unknown interface: %lu\n", Error);
    Route.DestinationPrefix.PrefixLength = 48;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_FILE_NOT_FOUND, "unknown interface: %lu\n", Error);
    Route.InterfaceIndex = 0;
    Route.InterfaceLuid.Value = UNKNOWN_LUID;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "unknown luid: %lu\n", Error);
    Route.InterfaceLuid.Value = 0;
    Route.InterfaceIndex = UNKNOWN_INDEX;
    Route.NextHop.si_family = AF_INET;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_FILE_NOT_FOUND, "IPv4 next hop, unknown interface: %lu\n", Error);
    Route.InterfaceIndex = IfIndex;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_INVALID_PARAMETER, "IPv4 next hop: %lu\n", Error);
    Route.InterfaceIndex = UNKNOWN_INDEX;
    Route.NextHop.si_family = AF_INET6;
    Route.DestinationPrefix.Prefix.si_family = AF_UNSPEC;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_INVALID_PARAMETER, "no family, unknown interface: %lu\n", Error);

    InitRoute(&Route, IfIndex, "2001:db8:9c::", 48, "fe80::9c");
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "delete of a route that is not there: %lu\n", Error);
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "change of a route that is not there: %lu\n", Error);
    Error = pGetIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "get of a route that is not there: %lu\n", Error);
}

static void TestRoute(ULONG IfIndex)
{
    ROUTE_ROW6 Route, Got;
    DWORD Error;

    InitRoute(&Route, IfIndex, "2001:db8:9c::", 48, "fe80::9c");
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "create: %lu\n", Error);
    if (Error != NO_ERROR)
        return;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_OBJECT_ALREADY_EXISTS, "create again: %lu\n", Error);

    InitRoute(&Got, IfIndex, "2001:db8:9c::", 48, "fe80::9c");
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == NO_ERROR, "get: %lu\n", Error);
    ok(Got.Metric == 256, "metric %lu\n", Got.Metric);
    ok(Got.Protocol == 3 && Got.Origin == 0, "protocol %lu origin %lu\n", Got.Protocol, Got.Origin);
    ok(Got.InterfaceLuid.Value != 0, "no luid\n");

    /* by luid, a new metric */
    Route.InterfaceIndex = 0;
    Route.InterfaceLuid = Got.InterfaceLuid;
    Route.Metric = 42;
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "set: %lu\n", Error);
    InitRoute(&Got, IfIndex, "2001:db8:9c::", 48, "fe80::9c");
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == NO_ERROR && Got.Metric == 42, "get after the change: %lu metric %lu\n", Error, Got.Metric);

    /* a row that gives no metric leaves it as it is */
    Route.Metric = 0xffffffff;
    Route.ValidLifetime = 7200;
    Route.PreferredLifetime = 3600;
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "set without a metric: %lu\n", Error);
    InitRoute(&Got, IfIndex, "2001:db8:9c::", 48, "fe80::9c");
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == NO_ERROR && Got.Metric == 42 && Got.ValidLifetime <= 7200 && Got.ValidLifetime > 7000,
       "get: %lu metric %lu valid %lu\n", Error, Got.Metric, Got.ValidLifetime);

    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "delete: %lu\n", Error);
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "delete again: %lu\n", Error);
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == ERROR_NOT_FOUND, "get after the delete: %lu\n", Error);

    /* an on-link route (no next hop) */
    InitRoute(&Route, IfIndex, "2001:db8:9d::", 64, NULL);
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "create on-link: %lu\n", Error);
    InitRoute(&Got, IfIndex, "2001:db8:9d::", 64, NULL);
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == NO_ERROR && Got.NextHop.si_family == AF_INET6 && Ipv6IsZero(Got.NextHop.Ipv6.sin6_addr.u.Byte),
       "get on-link: %lu\n", Error);
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "delete on-link: %lu\n", Error);
}

/* An IPv4 route through the IPv4 default gateway (when there is one) */
static void TestRoute4(void)
{
    ROUTE_TABLE6 *Table = NULL;
    ROUTE_ROW6 Route, Got;
    ULONG i, Gateway = 0, IfIndex = 0;
    DWORD Error;

    if (pGetIpForwardTable2(AF_INET, (PVOID *)&Table) != NO_ERROR || !Table)
        return;
    for (i = 0; i < Table->NumEntries && !Gateway; i++)
    {
        if (Table->Table[i].DestinationPrefix.PrefixLength == 0 && Table->Table[i].NextHop.Ipv4.sin_addr.s_addr)
        {
            Gateway = Table->Table[i].NextHop.Ipv4.sin_addr.s_addr;
            IfIndex = Table->Table[i].InterfaceIndex;
        }
    }
    pFreeMibTable(Table);
    if (!Gateway)
    {
        skip("no IPv4 default gateway\n");
        return;
    }

    pInitializeIpForwardEntry(&Route);
    Route.InterfaceIndex = IfIndex;
    Route.DestinationPrefix.Prefix.si_family = AF_INET;
    Route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = inet_addr("198.51.100.0");
    Route.DestinationPrefix.PrefixLength = 24;
    Route.NextHop.si_family = AF_INET;
    Route.NextHop.Ipv4.sin_addr.s_addr = Gateway;
    Route.Metric = 30;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "create IPv4: %lu\n", Error);
    Got = Route;
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == NO_ERROR, "get IPv4: %lu\n", Error);
    Route.DestinationPrefix.PrefixLength = 33;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == ERROR_INVALID_PARAMETER, "IPv4 prefix length 33: %lu\n", Error);
    Route.DestinationPrefix.PrefixLength = 24;
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "delete IPv4: %lu\n", Error);
    Got = Route;
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == ERROR_NOT_FOUND, "get IPv4 after the delete: %lu\n", Error);
}

static void InitAddress(UNICAST_ROW6 *Row, ULONG IfIndex, const char *Address)
{
    pInitializeUnicastIpAddressEntry(Row);
    Row->InterfaceIndex = IfIndex;
    Ipv6Parse(&Row->Address, Address, 0);
}

static void TestAddressInvalid(ULONG IfIndex)
{
    UNICAST_ROW6 Row;
    DWORD Error;

    InitAddress(&Row, IfIndex, "2001:db8:9b::7");
    Row.OnLinkPrefixLength = 129;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "prefix length 129: %lu\n", Error);
    Row.InterfaceIndex = UNKNOWN_INDEX;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "prefix length 129, unknown interface: %lu\n", Error);
    Row.OnLinkPrefixLength = 64;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "unknown interface: %lu\n", Error);
    Row.OnLinkPrefixLength = 255;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "length 255, unknown interface: %lu\n", Error);
    Row.InterfaceIndex = 0;
    Row.InterfaceLuid.Value = UNKNOWN_LUID;
    Row.OnLinkPrefixLength = 64;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "unknown luid: %lu\n", Error);
    Row.InterfaceLuid.Value = 0;
    Row.InterfaceIndex = UNKNOWN_INDEX;
    Row.Address.si_family = AF_UNSPEC;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "no family, unknown interface: %lu\n", Error);
    ok(pCreateUnicastIpAddressEntry(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");

    InitAddress(&Row, IfIndex, "2001:db8:9b::7");
    Error = pDeleteUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "delete of an address that is not there: %lu\n", Error);
    Error = pSetUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "change of an address that is not there: %lu\n", Error);
    ok(pSetUnicastIpAddressEntry(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");
    Row.Address.si_family = AF_INET;
    Error = pSetUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_NOT_SUPPORTED, "IPv4 change: %lu\n", Error);
}

static void TestAddress(ULONG IfIndex)
{
    UNICAST_ROW6 Row, Got;
    DWORD Error;

    InitAddress(&Row, IfIndex, "2001:db8:9b::7");
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "create: %lu\n", Error);
    if (Error != NO_ERROR)
        return;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_OBJECT_ALREADY_EXISTS, "create again: %lu\n", Error);

    InitAddress(&Got, IfIndex, "2001:db8:9b::7");
    Error = pGetUnicastIpAddressEntry(&Got);
    ok(Error == NO_ERROR, "get: %lu\n", Error);
    ok(Got.OnLinkPrefixLength == 64, "prefix length %u\n", Got.OnLinkPrefixLength);
    ok(Got.PrefixOrigin == ORIGIN_MANUAL && Got.SuffixOrigin == ORIGIN_MANUAL, "origins %lu %lu\n",
       Got.PrefixOrigin, Got.SuffixOrigin);
    ok(Got.ValidLifetime == 0xffffffff, "valid lifetime %lx\n", Got.ValidLifetime);

    /* a change: skip-as-source, the prefix length and origins left as they are */
    Row.SkipAsSource = TRUE;
    Row.OnLinkPrefixLength = 255;
    Row.PrefixOrigin = 16;      /* IpPrefixOriginUnchanged */
    Row.SuffixOrigin = 16;      /* IpSuffixOriginUnchanged */
    Error = pSetUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "set: %lu\n", Error);
    InitAddress(&Got, IfIndex, "2001:db8:9b::7");
    Error = pGetUnicastIpAddressEntry(&Got);
    ok(Error == NO_ERROR && Got.SkipAsSource, "get after the change: %lu skip %u\n", Error, Got.SkipAsSource);
    ok(Got.OnLinkPrefixLength == 64 && Got.PrefixOrigin == ORIGIN_MANUAL, "length %u origin %lu\n",
       Got.OnLinkPrefixLength, Got.PrefixOrigin);

    Error = pDeleteUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "delete: %lu\n", Error);
    Error = pDeleteUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "delete again: %lu\n", Error);
    Error = pGetUnicastIpAddressEntry(&Got);
    ok(Error == ERROR_NOT_FOUND, "get after the delete: %lu\n", Error);
}

START_TEST(Ipv6ConfigApi)
{
    WSADATA Data;
    ULONG IfIndex;

    pGetUnicastIpAddressTable = (PFN_GET_TABLE)Ipv6Proc("GetUnicastIpAddressTable");
    pGetIpForwardTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpForwardTable2");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    pCreateUnicastIpAddressEntry = (PFN_ROW)Ipv6Proc("CreateUnicastIpAddressEntry");
    pDeleteUnicastIpAddressEntry = (PFN_ROW)Ipv6Proc("DeleteUnicastIpAddressEntry");
    pSetUnicastIpAddressEntry = (PFN_ROW)Ipv6Proc("SetUnicastIpAddressEntry");
    pGetUnicastIpAddressEntry = (PFN_ROW)Ipv6Proc("GetUnicastIpAddressEntry");
    pCreateIpForwardEntry2 = (PFN_ROW)Ipv6Proc("CreateIpForwardEntry2");
    pDeleteIpForwardEntry2 = (PFN_ROW)Ipv6Proc("DeleteIpForwardEntry2");
    pSetIpForwardEntry2 = (PFN_ROW)Ipv6Proc("SetIpForwardEntry2");
    pGetIpForwardEntry2 = (PFN_ROW)Ipv6Proc("GetIpForwardEntry2");
    pInitializeUnicastIpAddressEntry = (PFN_INIT)Ipv6Proc("InitializeUnicastIpAddressEntry");
    pInitializeIpForwardEntry = (PFN_INIT)Ipv6Proc("InitializeIpForwardEntry");
    if (!pGetUnicastIpAddressTable || !pGetIpForwardTable2 || !pFreeMibTable || !pCreateUnicastIpAddressEntry ||
        !pDeleteUnicastIpAddressEntry || !pSetUnicastIpAddressEntry || !pGetUnicastIpAddressEntry ||
        !pCreateIpForwardEntry2 || !pDeleteIpForwardEntry2 || !pSetIpForwardEntry2 || !pGetIpForwardEntry2 ||
        !pInitializeUnicastIpAddressEntry || !pInitializeIpForwardEntry)
    {
        skip("the IP Helper configuration functions are missing\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Data);

    TestInitialize();
    TestRoute4();

    if (!Ipv6SocketsWork())
    {
        UNICAST_ROW6 Row;
        ROUTE_ROW6 Route;
        DWORD Error;

        IfIndex = AnyIndex();
        if (!IfIndex)
        {
            skip("no interface\n");
            WSACleanup();
            return;
        }
        /* no IPv6 stack: an IPv6 row is not supported (documentation) */
        InitAddress(&Row, IfIndex, "2001:db8:9b::7");
        Error = pCreateUnicastIpAddressEntry(&Row);
        ok(Error == ERROR_NOT_SUPPORTED, "IPv6 off, address: %lu\n", Error);
        InitRoute(&Route, IfIndex, "2001:db8:9c::", 48, "fe80::9c");
        Error = pCreateIpForwardEntry2(&Route);
        ok(Error == ERROR_NOT_SUPPORTED, "IPv6 off, route: %lu\n", Error);
        WSACleanup();
        return;
    }

    IfIndex = EthernetIndex();
    if (!IfIndex)
    {
        skip("no Ethernet interface with IPv6\n");
        WSACleanup();
        return;
    }
    TestRouteInvalid(IfIndex);
    TestRoute(IfIndex);
    TestAddressInvalid(IfIndex);
    TestAddress(IfIndex);
    WSACleanup();
}
