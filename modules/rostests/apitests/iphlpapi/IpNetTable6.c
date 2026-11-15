/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetIpNetTable2, GetIpNetEntry2 and ResolveIpNetEntry2 for IPv6: the table lists the neighbours of the
 *              stack's cache and the multicast groups it receives as Windows 10 does (oracle probe: the Permanent
 *              33-33-... entries, Stale/Reachable neighbours with their Ethernet address, rows sorted by interface and
 *              address), without IPv6 the table is empty
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"

static PFN_GET_TABLE pGetIpNetTable2;
static PFN_FREE_TABLE pFreeMibTable;
static PFN_GET_NEIGH pGetIpNetEntry2;
static PFN_RESOLVE pResolveIpNetEntry2;
static PFN_GET_TABLE pGetIpForwardTable2;

static void TestArguments(void)
{
    NEIGH_TABLE6 *Table = (NEIGH_TABLE6 *)(ULONG_PTR)0x12345678;
    DWORD Error;

    Error = pGetIpNetTable2(AF_INET6, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "no table pointer: %lu\n", Error);
    Error = pGetIpNetTable2(99, (PVOID *)&Table);
    ok(Error == ERROR_INVALID_PARAMETER, "family 99: %lu\n", Error);
    ok(Table == (NEIGH_TABLE6 *)(ULONG_PTR)0x12345678, "family 99: table written\n");
}

static NEIGH_TABLE6 *GetTable(USHORT Family)
{
    NEIGH_TABLE6 *Table = NULL;
    DWORD Error = pGetIpNetTable2(Family, (PVOID *)&Table);

    ok(Error == NO_ERROR, "GetIpNetTable2(%u): %lu\n", Family, Error);
    ok(Error != NO_ERROR || Table != NULL, "GetIpNetTable2(%u): no table\n", Family);
    return Error == NO_ERROR ? Table : NULL;
}

static void TestFamilies(void)
{
    NEIGH_TABLE6 *V4, *V6, *All;
    ULONG i, Tries;

    /* the cache moves while this runs: look again until the three agree */
    for (Tries = 0; Tries < 5; Tries++)
    {
        V4 = GetTable(AF_INET);
        V6 = GetTable(AF_INET6);
        All = GetTable(AF_UNSPEC);
        if (!V4 || !V6 || !All || All->NumEntries == V4->NumEntries + V6->NumEntries)
            break;
        pFreeMibTable(V4);
        pFreeMibTable(V6);
        pFreeMibTable(All);
    }
    if (!V4 || !V6 || !All)
        return;

    ok(All->NumEntries == V4->NumEntries + V6->NumEntries, "AF_UNSPEC: %lu rows, IPv4 %lu, IPv6 %lu\n", All->NumEntries,
       V4->NumEntries, V6->NumEntries);
    for (i = 0; i < V4->NumEntries; i++)
        ok(V4->Table[i].Address.si_family == AF_INET, "IPv4 table: row %lu has family %u\n", i,
           V4->Table[i].Address.si_family);
    for (i = 0; i < V6->NumEntries; i++)
        ok(V6->Table[i].Address.si_family == AF_INET6, "IPv6 table: row %lu has family %u\n", i,
           V6->Table[i].Address.si_family);
    /* the IPv4 rows come first, then the IPv6 ones */
    for (i = 0; i < All->NumEntries; i++)
        ok((i < V4->NumEntries) == (All->Table[i].Address.si_family == AF_INET), "AF_UNSPEC: row %lu has family %u\n", i,
           All->Table[i].Address.si_family);

    pFreeMibTable(V4);
    pFreeMibTable(V6);
    pFreeMibTable(All);
}

static BOOL IsAllNodes(const UCHAR *A)
{
    int i;

    for (i = 2; i < 15; i++)
        if (A[i])
            return FALSE;
    return A[0] == 0xff && A[1] == 0x02 && A[15] == 1;
}

static void TestRows(const NEIGH_TABLE6 *Table)
{
    ULONG i, j;

    for (i = 0; i < Table->NumEntries; i++)
    {
        const NEIGH_ROW6 *Row = &Table->Table[i];
        const UCHAR *Address = Row->Address.Ipv6.sin6_addr.u.Byte;
        BOOL Multicast = Address[0] == 0xff;

        ok(Row->InterfaceIndex != 0, "row %lu: no interface\n", i);
        ok(Row->InterfaceLuid.Value != 0, "row %lu: no luid\n", i);
        ok(Row->State >= NLNS_INCOMPLETE && Row->State <= NLNS_PERMANENT, "row %lu: state %lu\n", i, Row->State);
        ok(Row->PhysicalAddressLength <= sizeof(Row->PhysicalAddress), "row %lu: link address length %lu\n", i,
           Row->PhysicalAddressLength);
        ok(Multicast == (Row->State == NLNS_PERMANENT), "row %lu: state %lu for a %s address\n", i, Row->State,
           Multicast ? "multicast" : "unicast");
        if (i)
        {
            const NEIGH_ROW6 *Before = &Table->Table[i - 1];

            ok(Before->InterfaceIndex < Row->InterfaceIndex ||
               (Before->InterfaceIndex == Row->InterfaceIndex &&
                memcmp(&Before->Address.Ipv6.sin6_addr, &Row->Address.Ipv6.sin6_addr, 16) <= 0),
               "rows %lu and %lu are not sorted by interface and address\n", i - 1, i);
        }
        if (Row->State == NLNS_INCOMPLETE)
            continue;

        if (Multicast && Row->PhysicalAddressLength == 6)
        {
            /* RFC 2464 7: 33:33 and the last 32 bits of the group */
            ok(Row->PhysicalAddress[0] == 0x33 && Row->PhysicalAddress[1] == 0x33 &&
               !memcmp(&Row->PhysicalAddress[2], &Address[12], 4),
               "row %lu: group address maps to %02x-%02x-%02x-%02x-%02x-%02x\n", i, Row->PhysicalAddress[0],
               Row->PhysicalAddress[1], Row->PhysicalAddress[2], Row->PhysicalAddress[3], Row->PhysicalAddress[4],
               Row->PhysicalAddress[5]);
        }
        if (!Multicast)
            ok(Row->PhysicalAddressLength == 6, "row %lu: unicast neighbour with a %lu byte link address\n", i,
               Row->PhysicalAddressLength);

        /* an interface with an Ethernet address receives the all-nodes group */
        if (Row->PhysicalAddressLength == 6)
        {
            BOOL Have = FALSE;

            for (j = 0; j < Table->NumEntries && !Have; j++)
                Have = Table->Table[j].InterfaceIndex == Row->InterfaceIndex &&
                       IsAllNodes(Table->Table[j].Address.Ipv6.sin6_addr.u.Byte);
            ok(Have, "row %lu: interface %lu has no ff02::1 entry\n", i, Row->InterfaceIndex);
        }
    }
}

/* GetIpNetEntry2 finds each row of the table by address and interface, with the same link address */
static void TestEntries(const NEIGH_TABLE6 *Table)
{
    ULONG i;
    SOCKADDR_INET Missing;
    NEIGH_ROW6 Row;
    DWORD Error;

    for (i = 0; i < Table->NumEntries; i++)
    {
        const NEIGH_ROW6 *Source = &Table->Table[i];

        if (Source->State == NLNS_INCOMPLETE)
            continue;
        memset(&Row, 0, sizeof(Row));
        Row.Address = Source->Address;
        Row.InterfaceIndex = Source->InterfaceIndex;
        Error = pGetIpNetEntry2(&Row);
        ok(Error == NO_ERROR, "GetIpNetEntry2 for row %lu: %lu\n", i, Error);
        if (Error != NO_ERROR)
            continue;
        ok(Row.InterfaceLuid.Value == Source->InterfaceLuid.Value, "row %lu: luid\n", i);
        ok(Row.PhysicalAddressLength == Source->PhysicalAddressLength &&
           !memcmp(Row.PhysicalAddress, Source->PhysicalAddress, Source->PhysicalAddressLength),
           "row %lu: link address\n", i);
        ok(Row.State >= NLNS_INCOMPLETE && Row.State <= NLNS_PERMANENT, "row %lu: state %lu\n", i, Row.State);
    }

    /* an address nobody has */
    Ipv6Parse(&Missing, "fe80::dead:beef:1234:5678", 0);
    memset(&Row, 0, sizeof(Row));
    Row.Address = Missing;
    Error = pGetIpNetEntry2(&Row);
    ok(Error == ERROR_NOT_FOUND || (Error == NO_ERROR && Row.State <= NLNS_INCOMPLETE), "unknown neighbour: %lu\n", Error);
}

/* ResolveIpNetEntry2: the unspecified address, an address of this computer, a router the stack knows */
static void TestResolve(const NEIGH_TABLE6 *Table)
{
    ULONG i;
    NEIGH_ROW6 Row;
    SOCKADDR_INET Any;
    UCHAR Physical[8];
    ULONG Length;
    DWORD Error;
    ROUTE_TABLE6 *Routes = NULL;
    BOOL Ethernet = FALSE;

    Ipv6Parse(&Any, "::", 0);
    memset(&Row, 0, sizeof(Row));
    Row.Address = Any;
    Error = pResolveIpNetEntry2(&Row, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "resolve ::: %lu\n", Error);

    /* a neighbour already in the cache resolves to its link address */
    for (i = 0; i < Table->NumEntries; i++)
    {
        const NEIGH_ROW6 *Source = &Table->Table[i];

        if (Source->State == NLNS_PERMANENT || Source->State == NLNS_INCOMPLETE || Source->PhysicalAddressLength != 6)
            continue;
        Ethernet = TRUE;
        memset(&Row, 0, sizeof(Row));
        Row.Address = Source->Address;
        Row.InterfaceIndex = Source->InterfaceIndex;
        Error = pResolveIpNetEntry2(&Row, NULL);
        ok(Error == NO_ERROR, "resolve a cached neighbour: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            ok(Row.PhysicalAddressLength == 6 && !memcmp(Row.PhysicalAddress, Source->PhysicalAddress, 6),
               "resolved link address\n");
            ok(Row.State > NLNS_INCOMPLETE && Row.State != NLNS_PERMANENT, "resolved state %lu\n", Row.State);
        }
        break;
    }

    /* an address of this computer: Permanent, with the link address of its interface */
    if (pGetIpForwardTable2 && pGetIpForwardTable2(AF_INET6, (PVOID *)&Routes) == NO_ERROR && Routes)
    {
        for (i = 0; i < Routes->NumEntries; i++)
        {
            const ROUTE_ROW6 *Route = &Routes->Table[i];

            if (!Route->Loopback || Route->DestinationPrefix.PrefixLength != 128 ||
                Route->InterfaceLuid.Value == LOOPBACK6_LUID)
                continue;
            if (!Ipv6AdapterPhysical(Route->InterfaceIndex, Physical, &Length))
                continue;
            Ethernet = TRUE;
            memset(&Row, 0, sizeof(Row));
            Row.Address = Route->DestinationPrefix.Prefix;
            Row.InterfaceIndex = Route->InterfaceIndex;
            Error = pResolveIpNetEntry2(&Row, NULL);
            ok(Error == NO_ERROR, "resolve an own address: %lu\n", Error);
            if (Error == NO_ERROR)
            {
                ok(Row.State == NLNS_PERMANENT, "own address state %lu\n", Row.State);
                ok(Row.PhysicalAddressLength == Length && !memcmp(Row.PhysicalAddress, Physical, Length),
                   "own address link address\n");
            }
            break;
        }

        /* an address on the link nobody answers for: asked three times, then it is not there */
        if (Ethernet)
        {
            for (i = 0; i < Routes->NumEntries; i++)
            {
                const ROUTE_ROW6 *Route = &Routes->Table[i];

                if (Route->DestinationPrefix.PrefixLength != 64 || !Ipv6IsLinkLocal(Route->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte))
                    continue;
                memset(&Row, 0, sizeof(Row));
                Ipv6Parse(&Row.Address, "fe80::1234:5678:9abc:def0", Route->InterfaceIndex);
                Row.InterfaceIndex = Route->InterfaceIndex;
                Error = pResolveIpNetEntry2(&Row, NULL);
                ok(Error == ERROR_BAD_NET_NAME, "resolve a missing neighbour: %lu\n", Error);
                break;
            }
        }
        pFreeMibTable(Routes);
    }
    if (!Ethernet)
        skip("no IPv6 neighbour or address on an Ethernet interface to resolve\n");
}

START_TEST(IpNetTable6)
{
    WSADATA Wsa;
    NEIGH_TABLE6 *V6;
    BOOL On;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    pGetIpNetTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpNetTable2");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    pGetIpNetEntry2 = (PFN_GET_NEIGH)Ipv6Proc("GetIpNetEntry2");
    pResolveIpNetEntry2 = (PFN_RESOLVE)Ipv6Proc("ResolveIpNetEntry2");
    pGetIpForwardTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpForwardTable2");
    if (!pGetIpNetTable2 || !pFreeMibTable || !pGetIpNetEntry2 || !pResolveIpNetEntry2)
    {
        skip("The neighbour functions are not available\n");
        return;
    }

    On = Ipv6SocketsWork();
    TestArguments();
    TestFamilies();

    V6 = GetTable(AF_INET6);
    if (!V6)
        return;
    if (!On)
    {
        /* Without IPv6 there is nothing to list */
        ok(V6->NumEntries == 0, "IPv6 is off: %lu rows\n", V6->NumEntries);
        pFreeMibTable(V6);
        return;
    }

    TestRows(V6);
    TestEntries(V6);
    TestResolve(V6);
    pFreeMibTable(V6);
}
