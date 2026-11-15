/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetIpForwardTable2, GetBestRoute2 and GetBestInterfaceEx for IPv6. The expected rows and answers were
 *              probed on Windows 10 22H2 (::1/128 on the loopback interface with Loopback set, fe80::/64 and a /128
 *              host route per address, ff00::/8 per interface, protocol Local, metric 256, sorted by prefix, length and
 *              interface; the unspecified address not found, a link-local destination in the scope of the loopback
 *              interface unreachable, a multicast destination without an interface an empty row, a global destination
 *              over the loopback interface ERROR_INVALID_NETNAME). Router advertisement routes (the default route and the
 *              on-link prefixes) are NetMgmt routes this stack adds; its network had none there. Without IPv6 the table
 *              is empty and no IPv6 destination has a route.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"

static PFN_GET_TABLE pGetIpForwardTable2;
static PFN_FREE_TABLE pFreeMibTable;
static PFN_BEST_ROUTE pGetBestRoute2;
static DWORD (WINAPI *pGetBestInterfaceEx)(struct sockaddr *, PDWORD);

static ULONG LoopbackIndex;

static ROUTE_TABLE6 *GetTable(USHORT Family)
{
    ROUTE_TABLE6 *Table = NULL;
    DWORD Error = pGetIpForwardTable2(Family, (PVOID *)&Table);

    ok(Error == NO_ERROR, "GetIpForwardTable2(%u): %lu\n", Family, Error);
    ok(Error != NO_ERROR || Table != NULL, "GetIpForwardTable2(%u): no table\n", Family);
    return Error == NO_ERROR ? Table : NULL;
}

static BOOL IsLoopbackAddress(const UCHAR *A)
{
    int i;

    for (i = 0; i < 15; i++)
        if (A[i])
            return FALSE;
    return A[15] == 1;
}

static void TestFamilies(void)
{
    ROUTE_TABLE6 *V4, *V6, *All;
    ULONG i;
    DWORD Error;
    ROUTE_TABLE6 *Table = (ROUTE_TABLE6 *)(ULONG_PTR)0x12345678;

    Error = pGetIpForwardTable2(AF_INET6, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "no table pointer: %lu\n", Error);
    Error = pGetIpForwardTable2(99, (PVOID *)&Table);
    ok(Error == ERROR_INVALID_PARAMETER, "family 99: %lu\n", Error);

    V4 = GetTable(AF_INET);
    V6 = GetTable(AF_INET6);
    All = GetTable(AF_UNSPEC);
    if (!V4 || !V6 || !All)
        return;
    ok(All->NumEntries == V4->NumEntries + V6->NumEntries, "AF_UNSPEC: %lu rows, IPv4 %lu, IPv6 %lu\n", All->NumEntries,
       V4->NumEntries, V6->NumEntries);
    for (i = 0; i < V4->NumEntries; i++)
        ok(V4->Table[i].DestinationPrefix.Prefix.si_family == AF_INET, "IPv4 table: row %lu has family %u\n", i,
           V4->Table[i].DestinationPrefix.Prefix.si_family);
    for (i = 0; i < All->NumEntries; i++)
        ok((i < V4->NumEntries) == (All->Table[i].DestinationPrefix.Prefix.si_family == AF_INET),
           "AF_UNSPEC: row %lu has family %u\n", i, All->Table[i].DestinationPrefix.Prefix.si_family);
    pFreeMibTable(V4);
    pFreeMibTable(V6);
    pFreeMibTable(All);
}

static void TestRoutes(const ROUTE_TABLE6 *Table)
{
    ULONG i, j;
    BOOL Loopback = FALSE;

    for (i = 0; i < Table->NumEntries; i++)
    {
        const ROUTE_ROW6 *Row = &Table->Table[i];
        const UCHAR *Prefix = Row->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte;
        ULONG Length = Row->DestinationPrefix.PrefixLength;
        BOOL HostBitsClear = TRUE;

        ok(Row->DestinationPrefix.Prefix.si_family == AF_INET6, "row %lu: family %u\n", i,
           Row->DestinationPrefix.Prefix.si_family);
        ok(Row->NextHop.si_family == AF_INET6, "row %lu: next hop family %u\n", i, Row->NextHop.si_family);
        ok(Row->InterfaceIndex != 0 && Row->InterfaceLuid.Value != 0, "row %lu: no interface\n", i);
        ok(Length <= 128, "row %lu: prefix length %lu\n", i, Length);
        for (j = Length; j < 128; j++)
            if (Prefix[j / 8] & (0x80 >> (j % 8)))
                HostBitsClear = FALSE;
        ok(HostBitsClear, "row %lu: bits past the prefix length\n", i);
        ok(Row->Metric == 256, "row %lu: metric %lu\n", i, Row->Metric);
        if (i)
        {
            const ROUTE_ROW6 *Before = &Table->Table[i - 1];
            int Order = memcmp(Before->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, Prefix, 16);

            ok(Order < 0 || (Order == 0 && (Before->DestinationPrefix.PrefixLength < Length ||
                                            (Before->DestinationPrefix.PrefixLength == Length &&
                                             Before->InterfaceIndex <= Row->InterfaceIndex))),
               "rows %lu and %lu are not sorted by prefix, length and interface\n", i - 1, i);
        }

        if (Length == 128 && Row->InterfaceLuid.Value == LOOPBACK6_LUID)
        {
            /* ::1 */
            Loopback = TRUE;
            LoopbackIndex = Row->InterfaceIndex;
            ok(IsLoopbackAddress(Prefix) && Row->Loopback, "loopback host route %lu\n", i);
            ok(Row->Protocol == 2, "::1/128 protocol %lu\n", Row->Protocol);
        }
        if (Length == 128)
        {
            ok(Row->Loopback, "row %lu: a host route without Loopback\n", i);
            ok(Ipv6IsZero(Row->NextHop.Ipv6.sin6_addr.u.Byte), "row %lu: host route with a next hop\n", i);
        }
        if (Length == 8 && Prefix[0] == 0xff)
        {
            ok(Row->Origin == 1 && Row->Protocol == 2 && !Row->Loopback, "ff00::/8 row %lu: origin %lu protocol %lu\n", i,
               Row->Origin, Row->Protocol);
        }
        if (Length == 64 && Ipv6IsLinkLocal(Prefix))
        {
            ok(Row->Protocol == 2 && !Row->Loopback && Ipv6IsZero(Row->NextHop.Ipv6.sin6_addr.u.Byte),
               "fe80::/64 row %lu\n", i);
        }
        if (Length == 0)
        {
            /* the default route of a router advertisement: a link-local next hop in the scope of its interface */
            ok(Ipv6IsLinkLocal(Row->NextHop.Ipv6.sin6_addr.u.Byte) &&
               Row->NextHop.Ipv6.sin6_scope_id == Row->InterfaceIndex, "default route %lu: next hop\n", i);
            ok(Row->Protocol == 3 && Row->Origin == 3, "default route %lu: protocol %lu origin %lu\n", i, Row->Protocol,
               Row->Origin);
        }
    }
    ok(Loopback, "no ::1/128 route\n");

    /* every interface that has a route has the multicast prefix */
    for (i = 0; i < Table->NumEntries; i++)
    {
        BOOL Have = FALSE;

        for (j = 0; j < Table->NumEntries && !Have; j++)
            Have = Table->Table[j].InterfaceIndex == Table->Table[i].InterfaceIndex &&
                   Table->Table[j].DestinationPrefix.PrefixLength == 8 &&
                   Table->Table[j].DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte[0] == 0xff;
        ok(Have, "interface %lu has no ff00::/8 route\n", Table->Table[i].InterfaceIndex);
    }
}

static void Dest(SOCKADDR_INET *Address, const char *Text, ULONG Scope)
{
    Ipv6Parse(Address, Text, Scope);
}

static void TestBestRoute(const ROUTE_TABLE6 *Table, BOOL On)
{
    SOCKADDR_INET Address, Source;
    ROUTE_ROW6 Row;
    NET_LUID Luid;
    DWORD Error;
    ULONG i;
    const ROUTE_ROW6 *Link = NULL, *Default = NULL;
    BOOL Global = FALSE;

    Dest(&Address, "::1", 0);
    memset(&Row, 0xcc, sizeof(Row));
    Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
    if (!On)
    {
        ok(Error == ERROR_NETWORK_UNREACHABLE, "::1 without IPv6: %lu\n", Error);
        Dest(&Address, "2001:db8::1", 0);
        Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
        ok(Error == ERROR_NETWORK_UNREACHABLE, "2001:db8::1 without IPv6: %lu\n", Error);
        return;
    }
    ok(Error == NO_ERROR, "::1: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        ok(Row.DestinationPrefix.PrefixLength == 128 && Row.InterfaceLuid.Value == LOOPBACK6_LUID && Row.Loopback &&
           Row.Metric == 256 && Row.Protocol == 2, "::1: route\n");
        ok(Source.si_family == AF_INET6 &&
           IsLoopbackAddress(Source.Ipv6.sin6_addr.u.Byte), "::1: source\n");
    }

    Dest(&Address, "::", 0);
    Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
    ok(Error == ERROR_NOT_FOUND, ":: : %lu\n", Error);

    /* the routes of the table the answers depend on */
    for (i = 0; i < Table->NumEntries; i++)
    {
        const ROUTE_ROW6 *R = &Table->Table[i];

        if (R->DestinationPrefix.PrefixLength == 64 && Ipv6IsLinkLocal(R->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte))
            Link = R;
        if (R->DestinationPrefix.PrefixLength == 0)
            Default = R;
        if (R->DestinationPrefix.PrefixLength == 128 && R->InterfaceLuid.Value != LOOPBACK6_LUID &&
            !Ipv6IsLinkLocal(R->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte))
            Global = TRUE;
    }

    /* a link-local destination goes over the interface that has the link-local prefix */
    if (Link)
    {
        Dest(&Address, "fe80::1", 0);
        memset(&Row, 0xcc, sizeof(Row));
        Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
        ok(Error == NO_ERROR, "fe80::1: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            ok(Row.InterfaceIndex == Link->InterfaceIndex && Row.DestinationPrefix.PrefixLength == 64,
               "fe80::1: interface %lu, prefix length %u\n", Row.InterfaceIndex, Row.DestinationPrefix.PrefixLength);
            ok(Ipv6IsLinkLocal(Source.Ipv6.sin6_addr.u.Byte) && Source.Ipv6.sin6_scope_id == Link->InterfaceIndex,
               "fe80::1: source scope %lu\n", Source.Ipv6.sin6_scope_id);
        }

        /* the scope id names the interface: the loopback interface has no link-local prefix */
        Dest(&Address, "fe80::2", LoopbackIndex);
        Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
        ok(Error == ERROR_NETWORK_UNREACHABLE, "fe80::2%%%lu: %lu\n", LoopbackIndex, Error);
        Dest(&Address, "fe80::2", Link->InterfaceIndex);
        Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
        ok(Error == NO_ERROR && Row.InterfaceIndex == Link->InterfaceIndex, "fe80::2%%%lu: %lu\n", Link->InterfaceIndex,
           Error);

        /* a multicast destination without an interface: an empty row and the link-local source */
        Dest(&Address, "ff02::1", 0);
        memset(&Row, 0xcc, sizeof(Row));
        Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
        ok(Error == NO_ERROR, "ff02::1: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            ok(Row.InterfaceIndex == 0 && Row.DestinationPrefix.PrefixLength == 0 && Row.Metric == 0 && Row.Protocol == 0,
               "ff02::1: row is not empty\n");
            ok(Ipv6IsLinkLocal(Source.Ipv6.sin6_addr.u.Byte) && Source.Ipv6.sin6_scope_id == Link->InterfaceIndex,
               "ff02::1: source\n");
        }
    }

    /* over the loopback interface */
    Dest(&Address, "ff02::1", 0);
    memset(&Row, 0xcc, sizeof(Row));
    Error = pGetBestRoute2(NULL, LoopbackIndex, NULL, &Address, 0, &Row, &Source);
    ok(Error == NO_ERROR && Row.InterfaceIndex == LoopbackIndex && Row.DestinationPrefix.PrefixLength == 8,
       "ff02::1 over the loopback interface: %lu\n", Error);
    Dest(&Address, "2001:db8::1", 0);
    Error = pGetBestRoute2(NULL, LoopbackIndex, NULL, &Address, 0, &Row, &Source);
    ok(Error == ERROR_INVALID_NETNAME, "2001:db8::1 over the loopback interface: %lu\n", Error);
    Luid.Value = LOOPBACK6_LUID;
    Dest(&Address, "::1", 0);
    Error = pGetBestRoute2(&Luid, 0, NULL, &Address, 0, &Row, &Source);
    ok(Error == NO_ERROR && Row.InterfaceIndex == LoopbackIndex, "::1 over the loopback luid: %lu\n", Error);

    /* arguments naming something that is not there */
    Error = pGetBestRoute2(NULL, 99999, NULL, &Address, 0, &Row, &Source);
    ok(Error == ERROR_FILE_NOT_FOUND, "unknown interface index: %lu\n", Error);
    Luid.Value = 0x0123456789ULL << 24;
    Error = pGetBestRoute2(&Luid, 0, NULL, &Address, 0, &Row, &Source);
    ok(Error == ERROR_NOT_FOUND, "unknown luid: %lu\n", Error);
    Dest(&Source, "2001:db8::2", 0);
    Dest(&Address, "2001:db8::1", 0);
    Error = pGetBestRoute2(NULL, 0, &Source, &Address, 0, &Row, &Source);
    ok(Error == ERROR_NOT_FOUND, "a source that is not an address of this computer: %lu\n", Error);

    /* a global destination follows the default route, and has none without one */
    memset(&Row, 0xcc, sizeof(Row));
    Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
    if (Default)
    {
        ok(Error == NO_ERROR, "2001:db8::1 with a default route: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            ok(Row.DestinationPrefix.PrefixLength == 0 && Row.InterfaceIndex == Default->InterfaceIndex &&
               !memcmp(Row.NextHop.Ipv6.sin6_addr.u.Byte, Default->NextHop.Ipv6.sin6_addr.u.Byte, 16),
               "2001:db8::1: route\n");
            ok(Global == (Ipv6IsLinkLocal(Source.Ipv6.sin6_addr.u.Byte) == FALSE),
               "2001:db8::1: source %s with %s global address\n",
               Ipv6IsLinkLocal(Source.Ipv6.sin6_addr.u.Byte) ? "link-local" : "global", Global ? "a" : "no");
        }
    }
    else
        ok(Error == ERROR_NETWORK_UNREACHABLE, "2001:db8::1 without a default route: %lu\n", Error);

    /* an IPv4 address in IPv6 form is routed as the IPv4 address */
    Dest(&Address, "::ffff:127.0.0.1", 0);
    memset(&Row, 0xcc, sizeof(Row));
    Error = pGetBestRoute2(NULL, 0, NULL, &Address, 0, &Row, &Source);
    ok(Error == NO_ERROR && Row.InterfaceIndex == LoopbackIndex && Row.DestinationPrefix.PrefixLength >= 96,
       "::ffff:127.0.0.1: %lu\n", Error);

}

static void TestBestInterface(const ROUTE_TABLE6 *Table, BOOL On)
{
    SOCKADDR_IN6 Address;
    DWORD Index, Error;
    ULONG i;
    BOOL Default = FALSE;

    for (i = 0; i < Table->NumEntries; i++)
        if (Table->Table[i].DestinationPrefix.PrefixLength == 0)
            Default = TRUE;

    memset(&Address, 0, sizeof(Address));
    Address.sin6_family = AF_INET6;
    Address.sin6_addr.u.Byte[15] = 1;
    Index = 0xdead;
    Error = pGetBestInterfaceEx((struct sockaddr *)&Address, &Index);
    if (!On)
    {
        ok(Error == ERROR_NETWORK_UNREACHABLE, "::1 without IPv6: %lu\n", Error);
        return;
    }
    ok(Error == NO_ERROR && Index == LoopbackIndex, "::1: %lu, interface %lu\n", Error, Index);

    memset(&Address.sin6_addr, 0, sizeof(Address.sin6_addr));
    Address.sin6_addr.u.Byte[0] = 0x20;
    Address.sin6_addr.u.Byte[1] = 0x01;
    Address.sin6_addr.u.Byte[2] = 0x0d;
    Address.sin6_addr.u.Byte[3] = 0xb8;
    Address.sin6_addr.u.Byte[15] = 1;
    Index = 0xdead;
    Error = pGetBestInterfaceEx((struct sockaddr *)&Address, &Index);
    if (Default)
        ok(Error == NO_ERROR && Index != 0xdead && Index != 0 && Index != LoopbackIndex, "2001:db8::1: %lu, interface %lu\n",
           Error, Index);
    else
        ok(Error == ERROR_NETWORK_UNREACHABLE && Index == 0xdead, "2001:db8::1 without a default route: %lu, interface %lu\n",
           Error, Index);
}

START_TEST(IpForwardTable6)
{
    WSADATA Wsa;
    ROUTE_TABLE6 *V6;
    BOOL On;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    pGetIpForwardTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpForwardTable2");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    pGetBestRoute2 = (PFN_BEST_ROUTE)Ipv6Proc("GetBestRoute2");
    pGetBestInterfaceEx = (PVOID)Ipv6Proc("GetBestInterfaceEx");
    if (!pGetIpForwardTable2 || !pFreeMibTable || !pGetBestRoute2 || !pGetBestInterfaceEx)
    {
        skip("The route functions are not available\n");
        return;
    }

    On = Ipv6SocketsWork();
    TestFamilies();

    V6 = GetTable(AF_INET6);
    if (!V6)
        return;
    if (On)
        TestRoutes(V6);
    else
        ok(V6->NumEntries == 0, "IPv6 is off: %lu rows\n", V6->NumEntries);
    TestBestRoute(V6, On);
    TestBestInterface(V6, On);
    pFreeMibTable(V6);
}
