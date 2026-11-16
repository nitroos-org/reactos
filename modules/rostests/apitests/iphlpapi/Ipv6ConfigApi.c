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
    /* InitializeUnicastIpAddressEntry leaves the length at 255: Windows makes a /128 of it */
    ok(Got.OnLinkPrefixLength == 128, "prefix length %u\n", Got.OnLinkPrefixLength);
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
    ok(Got.OnLinkPrefixLength == 128 && Got.PrefixOrigin == ORIGIN_MANUAL, "length %u origin %lu\n",
       Got.OnLinkPrefixLength, Got.PrefixOrigin);

    Error = pDeleteUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "delete: %lu\n", Error);
    Error = pDeleteUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "delete again: %lu\n", Error);
    Error = pGetUnicastIpAddressEntry(&Got);
    ok(Error == ERROR_NOT_FOUND, "get after the delete: %lu\n", Error);
}

/*
 * The checks of the fields of an address row and a route row. The answers were measured on Windows Server 2022
 * (a throwaway VM; the rows were added and removed again): an origin is a 4-bit value (16, Unchanged, for both
 * origins or none) and a change never changes the origins; SkipAsSource 255 is "not given"; a length of 255 is a
 * /128 on a creation; a metric has 31 bits; Publish and Immortal are true for 1 only; Origin and Loopback are
 * ignored; a site prefix length longer than the route's prefix is refused (0 and 255 are taken; the lengths between
 * were not measured: taken here, as the field's documentation has them legal); a prefix with bits after its length
 * is refused; a preferred lifetime
 * over the valid one is refused.
 */
#define E_INVALID   ERROR_INVALID_PARAMETER

/* What an origin reads back as: 8..15 sit in a signed 4-bit field */
static ULONG StoredOrigin(ULONG Origin)
{
    return (Origin >= 8 && Origin <= 15) ? (Origin | 0xfffffff0) : Origin;
}

static void TestAddressFields(ULONG IfIndex)
{
    static const struct { ULONG Prefix, Suffix; DWORD Error; } Pairs[] =
    {
        { 16, 16, NO_ERROR }, { 1, 16, E_INVALID }, { 16, 1, E_INVALID }, { 0, 16, E_INVALID }, { 0xffffffff, 16, E_INVALID },
        { 17, 17, E_INVALID }, { 100, 1, E_INVALID }, { 1, 100, E_INVALID }, { 17, 1, E_INVALID }, { 1, 17, E_INVALID },
        { 4, 5, E_INVALID }, { 1, 5, NO_ERROR }, { 0, 0, NO_ERROR }, { 3, 3, NO_ERROR }, { 4, 4, NO_ERROR },
        { 5, 5, NO_ERROR }, { 15, 1, NO_ERROR }, { 1, 15, NO_ERROR }, { 8, 9, NO_ERROR }, { 0xffffffff, 1, NO_ERROR },
        { 1, 0xffffffff, NO_ERROR }, { 7, 6, NO_ERROR },
    };
    UNICAST_ROW6 Row, Got;
    DWORD Error;
    ULONG i;
    int k;

    for (i = 0; i < sizeof(Pairs) / sizeof(Pairs[0]); i++)
    {
        InitAddress(&Row, IfIndex, "2001:db8:9b::20");
        Row.PrefixOrigin = Pairs[i].Prefix;
        Row.SuffixOrigin = Pairs[i].Suffix;
        Error = pCreateUnicastIpAddressEntry(&Row);
        ok(Error == Pairs[i].Error, "create, origins %lu/%lu: %lu\n", Pairs[i].Prefix, Pairs[i].Suffix, Error);
        if (Error != NO_ERROR)
            continue;
        InitAddress(&Got, IfIndex, "2001:db8:9b::20");
        Error = pGetUnicastIpAddressEntry(&Got);
        ok(Error == NO_ERROR, "get: %lu\n", Error);
        if (Pairs[i].Prefix == 16)
            ok(Got.PrefixOrigin == ORIGIN_MANUAL && Got.SuffixOrigin == ORIGIN_MANUAL, "unchanged origins read %lu/%lu\n",
               Got.PrefixOrigin, Got.SuffixOrigin);
        else
            /* a suffix origin of -1 makes the prefix origin read -1 too (measured on Windows) */
            ok(Got.PrefixOrigin == (Pairs[i].Suffix == 0xffffffff ? 0xffffffff : StoredOrigin(Pairs[i].Prefix)) &&
               Got.SuffixOrigin == StoredOrigin(Pairs[i].Suffix),
               "origins %lu/%lu read %lx/%lx\n", Pairs[i].Prefix, Pairs[i].Suffix, Got.PrefixOrigin, Got.SuffixOrigin);
        Error = pDeleteUnicastIpAddressEntry(&Row);
        ok(Error == NO_ERROR, "delete: %lu\n", Error);
    }

    /* a change is checked like a creation, and changes no origin */
    InitAddress(&Row, IfIndex, "2001:db8:9b::21");
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "create: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        for (i = 0; i < sizeof(Pairs) / sizeof(Pairs[0]); i++)
        {
            InitAddress(&Row, IfIndex, "2001:db8:9b::21");
            Row.PrefixOrigin = Pairs[i].Prefix;
            Row.SuffixOrigin = Pairs[i].Suffix;
            Error = pSetUnicastIpAddressEntry(&Row);
            ok(Error == Pairs[i].Error, "set, origins %lu/%lu: %lu\n", Pairs[i].Prefix, Pairs[i].Suffix, Error);
        }
        InitAddress(&Got, IfIndex, "2001:db8:9b::21");
        Error = pGetUnicastIpAddressEntry(&Got);
        ok(Error == NO_ERROR && Got.PrefixOrigin == ORIGIN_MANUAL && Got.SuffixOrigin == ORIGIN_MANUAL,
           "origins after the changes: %lu %lu/%lu\n", Error, Got.PrefixOrigin, Got.SuffixOrigin);
        pDeleteUnicastIpAddressEntry(&Row);
    }

    /* SkipAsSource: 255 is not given (false when creating, unchanged when changing), the others are true */
    for (k = 0; k < 2; k++)
    {
        static const UCHAR Skip[] = { 255, 2 };

        InitAddress(&Row, IfIndex, "2001:db8:9b::22");
        Row.SkipAsSource = Skip[k];
        Error = pCreateUnicastIpAddressEntry(&Row);
        ok(Error == NO_ERROR, "create, skip %u: %lu\n", Skip[k], Error);
        InitAddress(&Got, IfIndex, "2001:db8:9b::22");
        Error = pGetUnicastIpAddressEntry(&Got);
        ok(Error == NO_ERROR && Got.SkipAsSource == (k == 1), "skip %u created as %u\n", Skip[k], Got.SkipAsSource);
        if (k == 1)
        {
            Row.SkipAsSource = 255;
            Error = pSetUnicastIpAddressEntry(&Row);
            InitAddress(&Got, IfIndex, "2001:db8:9b::22");
            ok(Error == NO_ERROR && pGetUnicastIpAddressEntry(&Got) == NO_ERROR && Got.SkipAsSource,
               "skip 255 on a change: %lu\n", Error);
            Row.SkipAsSource = 0;
            Error = pSetUnicastIpAddressEntry(&Row);
            InitAddress(&Got, IfIndex, "2001:db8:9b::22");
            ok(Error == NO_ERROR && pGetUnicastIpAddressEntry(&Got) == NO_ERROR && !Got.SkipAsSource,
               "skip 0 on a change: %lu\n", Error);
            Row.SkipAsSource = 2;
            Error = pSetUnicastIpAddressEntry(&Row);
            InitAddress(&Got, IfIndex, "2001:db8:9b::22");
            ok(Error == NO_ERROR && pGetUnicastIpAddressEntry(&Got) == NO_ERROR && Got.SkipAsSource == TRUE,
               "skip 2 on a change: %lu\n", Error);
        }
        pDeleteUnicastIpAddressEntry(&Row);
    }

    /* the prefix length: 255 on a change is the length the address has */
    InitAddress(&Row, IfIndex, "2001:db8:9b::23");
    Row.OnLinkPrefixLength = 100;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "create /100: %lu\n", Error);
    Row.OnLinkPrefixLength = 255;
    Error = pSetUnicastIpAddressEntry(&Row);
    InitAddress(&Got, IfIndex, "2001:db8:9b::23");
    ok(Error == NO_ERROR && pGetUnicastIpAddressEntry(&Got) == NO_ERROR && Got.OnLinkPrefixLength == 100,
       "length 255 on a change: %lu /%u\n", Error, Got.OnLinkPrefixLength);
    Row.OnLinkPrefixLength = 129;
    Error = pSetUnicastIpAddressEntry(&Row);
    ok(Error == E_INVALID, "length 129 on a change: %lu\n", Error);
    pDeleteUnicastIpAddressEntry(&Row);

    /* lifetimes */
    InitAddress(&Row, IfIndex, "2001:db8:9b::24");
    Row.ValidLifetime = 100;
    Row.PreferredLifetime = 101;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == E_INVALID, "preferred over valid: %lu\n", Error);
    Row.ValidLifetime = 0;
    Row.PreferredLifetime = 1;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == E_INVALID, "valid 0, preferred 1: %lu\n", Error);
    Row.ValidLifetime = 100;
    Row.PreferredLifetime = 100;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "valid 100, preferred 100: %lu\n", Error);
    pDeleteUnicastIpAddressEntry(&Row);

    /* a valid lifetime of 0 (with a preferred one of 0) is taken, and the address is gone a moment later */
    Row.ValidLifetime = 0;
    Row.PreferredLifetime = 0;
    Error = pCreateUnicastIpAddressEntry(&Row);
    ok(Error == NO_ERROR, "valid 0, preferred 0: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        for (k = 0; k < 12; k++)
        {
            Sleep(500);
            InitAddress(&Got, IfIndex, "2001:db8:9b::24");
            if (pGetUnicastIpAddressEntry(&Got) == ERROR_NOT_FOUND)
                break;
        }
        ok(k < 12, "an address with a valid lifetime of 0 is still there after 6 s\n");
        pDeleteUnicastIpAddressEntry(&Row);
    }
}

static void InitFieldRoute(ROUTE_ROW6 *Route, ULONG IfIndex)
{
    InitRoute(Route, IfIndex, "2001:db8:9e::", 48, NULL);
}

static void TestRouteFields(ULONG IfIndex)
{
    static const struct { ULONG Metric; DWORD Error; ULONG Read; } Metrics[] =
    {
        { 0, NO_ERROR, 0 }, { 1, NO_ERROR, 1 }, { 9999, NO_ERROR, 9999 }, { 10000, NO_ERROR, 10000 },
        { 0x7fffffff, NO_ERROR, 0x7fffffff }, { 0x80000000, E_INVALID, 0 }, { 0xfffffffe, E_INVALID, 0 },
        { 0xffffffff, NO_ERROR, 256 },
    };
    static const struct { ULONG Protocol, Read; } Protocols[] =
    {
        { 0, 0 }, { 1, 1 }, { 2, 2 }, { 3, 3 }, { 14, 14 }, { 100, 100 }, { 10002, 10002 }, { 0x7fffffff, 0x7fffffff },
        { 0xffffffff, 3 },
    };
    static const UCHAR Flags[] = { 0, 1, 2, 255 };
    /* the route is a /48: refused (measured), then taken (0 and 255 measured, 1 and 48 not: VERIFY ON ORACLE) */
    static const UCHAR Sites[] = { 49, 64, 128, 129, 254 };
    static const UCHAR SitesTaken[] = { 0, 1, 48, 255 };
    ROUTE_ROW6 Route, Got;
    DWORD Error;
    ULONG i;
    int k;

    for (i = 0; i < sizeof(Metrics) / sizeof(Metrics[0]); i++)
    {
        InitFieldRoute(&Route, IfIndex);
        Route.Metric = Metrics[i].Metric;
        Error = pCreateIpForwardEntry2(&Route);
        ok(Error == Metrics[i].Error, "metric %lx: %lu\n", Metrics[i].Metric, Error);
        if (Error == NO_ERROR)
        {
            InitFieldRoute(&Got, IfIndex);
            ok(pGetIpForwardEntry2(&Got) == NO_ERROR && Got.Metric == Metrics[i].Read, "metric %lx read %lu\n",
               Metrics[i].Metric, Got.Metric);
            pDeleteIpForwardEntry2(&Route);
        }
    }
    /* a change: the same limit */
    InitFieldRoute(&Route, IfIndex);
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "create: %lu\n", Error);
    Route.Metric = 0x80000000;
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "change to metric 0x80000000: %lu\n", Error);
    Route.Metric = 0x7fffffff;
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "change to metric 0x7fffffff: %lu\n", Error);
    pDeleteIpForwardEntry2(&Route);

    for (i = 0; i < sizeof(Protocols) / sizeof(Protocols[0]); i++)
    {
        InitFieldRoute(&Route, IfIndex);
        Route.Protocol = Protocols[i].Protocol;
        Error = pCreateIpForwardEntry2(&Route);
        ok(Error == NO_ERROR, "protocol %lx: %lu\n", Protocols[i].Protocol, Error);
        InitFieldRoute(&Got, IfIndex);
        ok(pGetIpForwardEntry2(&Got) == NO_ERROR && Got.Protocol == Protocols[i].Read, "protocol %lx read %lu\n",
           Protocols[i].Protocol, Got.Protocol);
        pDeleteIpForwardEntry2(&Route);
    }

    /* origin and loopback are ignored (read back as 0); the flags: Publish and Immortal are true for 1 only,
       AutoconfigureAddress is true for 1 and 255 (not given) */
    for (k = 0; k < 4; k++)
    {
        InitFieldRoute(&Route, IfIndex);
        Route.Origin = k == 3 ? 100 : k;
        Route.Loopback = Flags[k];
        Route.Publish = Flags[k];
        Route.Immortal = Flags[k];
        Route.AutoconfigureAddress = Flags[k];
        Error = pCreateIpForwardEntry2(&Route);
        ok(Error == NO_ERROR, "flags %u: %lu\n", Flags[k], Error);
        InitFieldRoute(&Got, IfIndex);
        ok(pGetIpForwardEntry2(&Got) == NO_ERROR, "get\n");
        ok(Got.Origin == 0 && Got.Loopback == 0, "origin %lu loopback %u\n", Got.Origin, Got.Loopback);
        ok(Got.Publish == (Flags[k] == 1) && Got.Immortal == (Flags[k] == 1), "flags %u read publish %u immortal %u\n",
           Flags[k], Got.Publish, Got.Immortal);
        ok(Got.AutoconfigureAddress == (Flags[k] == 1 || Flags[k] == 255), "flags %u read autoconfigure %u\n",
           Flags[k], Got.AutoconfigureAddress);
        pDeleteIpForwardEntry2(&Route);
    }

    /* a site prefix length longer than the route's prefix is refused; the others are taken and read back as 0 */
    for (i = 0; i < sizeof(Sites) / sizeof(Sites[0]); i++)
    {
        InitFieldRoute(&Route, IfIndex);
        Route.SitePrefixLength = Sites[i];
        Error = pCreateIpForwardEntry2(&Route);
        ok(Error == E_INVALID, "site prefix length %u: %lu\n", Sites[i], Error);
        if (Error == NO_ERROR)
            pDeleteIpForwardEntry2(&Route);
    }
    for (i = 0; i < sizeof(SitesTaken) / sizeof(SitesTaken[0]); i++)
    {
        InitFieldRoute(&Route, IfIndex);
        Route.SitePrefixLength = SitesTaken[i];
        Error = pCreateIpForwardEntry2(&Route);
        ok(Error == NO_ERROR, "site prefix length %u: %lu\n", SitesTaken[i], Error);
        if (Error != NO_ERROR)
            continue;
        InitFieldRoute(&Got, IfIndex);
        ok(pGetIpForwardEntry2(&Got) == NO_ERROR, "get\n");
        ok(Got.SitePrefixLength == 0, "site prefix length %u reads %u\n", SitesTaken[i], Got.SitePrefixLength);
        pDeleteIpForwardEntry2(&Route);
    }
    InitFieldRoute(&Route, IfIndex);
    Route.SitePrefixLength = 0;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "site prefix length 0: %lu\n", Error);
    Route.SitePrefixLength = 64;
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "change to site prefix length 64: %lu\n", Error);
    Route.SitePrefixLength = 32;
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "change to site prefix length 32: %lu\n", Error);
    pDeleteIpForwardEntry2(&Route);

    /* lifetimes: a valid lifetime of 0 is taken (the route lasts) */
    InitFieldRoute(&Route, IfIndex);
    Route.ValidLifetime = 100;
    Route.PreferredLifetime = 101;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "preferred over valid: %lu\n", Error);
    Route.ValidLifetime = 0;
    Route.PreferredLifetime = 1;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "valid 0, preferred 1: %lu\n", Error);
    Route.PreferredLifetime = 0;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == NO_ERROR, "valid 0, preferred 0: %lu\n", Error);
    Sleep(2500);
    InitFieldRoute(&Got, IfIndex);
    Error = pGetIpForwardEntry2(&Got);
    ok(Error == NO_ERROR, "a route with a valid lifetime of 0 is gone: %lu\n", Error);
    pDeleteIpForwardEntry2(&Route);

    /* bits after the prefix length: creation, change and removal refuse them, a lookup finds nothing */
    InitRoute(&Route, IfIndex, "2001:db8:9e::1", 48, NULL);
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "create with host bits: %lu\n", Error);
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "change with host bits: %lu\n", Error);
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "removal with host bits: %lu\n", Error);
    Error = pGetIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "lookup with host bits: %lu\n", Error);
    InitFieldRoute(&Got, IfIndex);
    Error = pCreateIpForwardEntry2(&Got);
    ok(Error == NO_ERROR, "create: %lu\n", Error);
    InitRoute(&Route, IfIndex, "2001:db8:9e::1", 48, NULL);
    Error = pGetIpForwardEntry2(&Route);
    ok(Error == ERROR_NOT_FOUND, "lookup of the route with host bits: %lu\n", Error);
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "change of the route with host bits: %lu\n", Error);
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "removal of the route with host bits: %lu\n", Error);
    Error = pDeleteIpForwardEntry2(&Got);
    ok(Error == NO_ERROR, "delete: %lu\n", Error);

    /* the same checks for an IPv4 row (all of them come before the stack is asked) */
    InitFieldRoute(&Route, IfIndex);
    Route.DestinationPrefix.Prefix.si_family = AF_INET;
    Route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = inet_addr("198.51.100.1");
    Route.DestinationPrefix.PrefixLength = 24;
    Route.NextHop.si_family = AF_UNSPEC;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "IPv4 create with host bits: %lu\n", Error);
    Error = pSetIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "IPv4 change with host bits: %lu\n", Error);
    Error = pDeleteIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "IPv4 removal with host bits: %lu\n", Error);
    Route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = inet_addr("198.51.100.0");
    Route.Metric = 0x80000000;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "IPv4 metric 0x80000000: %lu\n", Error);
    Route.Metric = 0xffffffff;
    Route.SitePrefixLength = 64;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "IPv4 site prefix length 64: %lu\n", Error);
    Route.SitePrefixLength = 255;
    Route.ValidLifetime = 100;
    Route.PreferredLifetime = 101;
    Error = pCreateIpForwardEntry2(&Route);
    ok(Error == E_INVALID, "IPv4 preferred over valid: %lu\n", Error);
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
    TestAddressFields(IfIndex);
    TestRouteFields(IfIndex);
    WSACleanup();
}
