/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for GetBestRoute2
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

/* The rows of the Windows SDK, under private names: the headers of this tree do not declare them. */
typedef struct
{
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    struct { SOCKADDR_INET Prefix; UINT8 PrefixLength; } DestinationPrefix;
    SOCKADDR_INET NextHop;
    UCHAR SitePrefixLength;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    ULONG Metric;
    ULONG Protocol;
    BOOLEAN Loopback;
    BOOLEAN AutoconfigureAddress;
    BOOLEAN Publish;
    BOOLEAN Immortal;
    ULONG Age;
    ULONG Origin;
} ROUTE_ROW2;

typedef struct
{
    ULONG NumEntries;
    ROUTE_ROW2 Table[1];
} ROUTE_TABLE2;

typedef DWORD (WINAPI *PGET_BEST_ROUTE2)(NET_LUID *, ULONG, const SOCKADDR_INET *, const SOCKADDR_INET *,
                                         ULONG, ROUTE_ROW2 *, SOCKADDR_INET *);
typedef DWORD (WINAPI *PGET_IP_FORWARD_TABLE2)(USHORT, ROUTE_TABLE2 **);
typedef VOID (WINAPI *PFREE_MIB_TABLE)(PVOID);

#define IF_TYPE_LOOPBACK 24
#define MIB_PROTO_LOCAL 2
#define MIB_PROTO_NETMGMT 3
#define ON_LINK_METRIC 256
#define MAX_LOCAL_ADDRESSES 256

static PGET_BEST_ROUTE2 pGetBestRoute2;
static ULONG LoopbackIndex, AdapterIndex, AdapterAddress, AdapterMask, Gateway;
static ULONGLONG LoopbackLuid, AdapterLuid;
static BOOL HaveLoopbackLuid, HaveAdapterLuid;
static ULONG LocalAddresses[MAX_LOCAL_ADDRESSES], NumLocalAddresses;
static BOOL HaveLoopback, HaveAdapter, AddressesTruncated;
/* 1: the default route of the adapter is the only route of the adapter that covers 8.8.8.8, 0: none covers it, -1: unclear */
static int DefaultRouteOnly;

static void MakeV4(SOCKADDR_INET *Address, ULONG Ip)
{
    memset(Address, 0, sizeof(*Address));
    Address->Ipv4.sin_family = AF_INET;
    Address->Ipv4.sin_addr.s_addr = Ip;
}

static void MakeV6(SOCKADDR_INET *Address, USHORT First, USHORT Last)
{
    memset(Address, 0, sizeof(*Address));
    Address->Ipv6.sin6_family = AF_INET6;
    Address->Ipv6.sin6_addr.u.Word[0] = htons(First);
    Address->Ipv6.sin6_addr.u.Word[7] = htons(Last);
}

static BOOL PrefixCovers(const UCHAR *Prefix, UINT8 Length, const UCHAR *Address)
{
    UINT8 i;

    for (i = 0; i < Length && i < 128; i++)
    {
        if (((Prefix[i / 8] ^ Address[i / 8]) >> (7 - i % 8)) & 1)
            return FALSE;
    }
    return TRUE;
}

static BOOL IsLocalAddress(ULONG Ip)
{
    ULONG i;

    for (i = 0; i < NumLocalAddresses; i++)
    {
        if (LocalAddresses[i] == Ip)
            return TRUE;
    }
    return FALSE;
}

static void FindEnvironment(void)
{
    ULONG Size = 0, i, Covering = 0, Defaults = 0, BestMetric = 0xffffffff;
    IP_ADAPTER_ADDRESSES *Adapters, *Adapter;
    MIB_IPADDRTABLE *Addresses;
    MIB_IPFORWARDTABLE *Routes;
    ULONG Flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG Google = htonl(0x08080808);

    GetAdaptersAddresses(AF_UNSPEC, Flags, NULL, NULL, &Size);
    Adapters = malloc(Size);
    if (Adapters && GetAdaptersAddresses(AF_UNSPEC, Flags, NULL, Adapters, &Size) == NO_ERROR)
    {
        for (Adapter = Adapters; Adapter; Adapter = Adapter->Next)
        {
            IP_ADAPTER_UNICAST_ADDRESS *Unicast;

            for (Unicast = Adapter->FirstUnicastAddress; Unicast; Unicast = Unicast->Next)
            {
                ULONG Ip;

                if (Unicast->Address.lpSockaddr->sa_family != AF_INET)
                    continue;
                Ip = ((struct sockaddr_in *)Unicast->Address.lpSockaddr)->sin_addr.s_addr;
                if (NumLocalAddresses < MAX_LOCAL_ADDRESSES)
                    LocalAddresses[NumLocalAddresses++] = Ip;
                else
                    AddressesTruncated = TRUE;

                if (Adapter->IfType == IF_TYPE_LOOPBACK && !HaveLoopback)
                {
                    LoopbackIndex = Adapter->IfIndex;
                    HaveLoopback = TRUE;
                    HaveLoopbackLuid = Adapter->Length >= sizeof(IP_ADAPTER_ADDRESSES_LH);
                    if (HaveLoopbackLuid)
                        LoopbackLuid = ((IP_ADAPTER_ADDRESSES_LH *)Adapter)->Luid.Value;
                }
                else if (Adapter->IfType != IF_TYPE_LOOPBACK && !HaveAdapter && Ip != 0)
                {
                    AdapterIndex = Adapter->IfIndex;
                    AdapterAddress = Ip;
                    HaveAdapter = TRUE;
                    HaveAdapterLuid = Adapter->Length >= sizeof(IP_ADAPTER_ADDRESSES_LH);
                    if (HaveAdapterLuid)
                        AdapterLuid = ((IP_ADAPTER_ADDRESSES_LH *)Adapter)->Luid.Value;
                }
            }
        }
    }
    free(Adapters);
    if (!HaveAdapter)
        return;

    Size = 0;
    GetIpAddrTable(NULL, &Size, FALSE);
    Addresses = malloc(Size);
    if (Addresses && GetIpAddrTable(Addresses, &Size, FALSE) == NO_ERROR)
    {
        for (i = 0; i < Addresses->dwNumEntries; i++)
        {
            if (Addresses->table[i].dwAddr == AdapterAddress)
                AdapterMask = Addresses->table[i].dwMask;
        }
    }
    free(Addresses);

    Size = 0;
    GetIpForwardTable(NULL, &Size, FALSE);
    Routes = malloc(Size);
    if (Routes && GetIpForwardTable(Routes, &Size, FALSE) == NO_ERROR)
    {
        for (i = 0; i < Routes->dwNumEntries; i++)
        {
            MIB_IPFORWARDROW *Route = &Routes->table[i];

            if (Route->dwForwardIfIndex != AdapterIndex ||
                (Google & Route->dwForwardMask) != (Route->dwForwardDest & Route->dwForwardMask))
                continue;
            Covering++;
            if (Route->dwForwardDest == 0 && Route->dwForwardMask == 0)
            {
                Defaults++;
                if (Route->dwForwardMetric1 < BestMetric)
                {
                    BestMetric = Route->dwForwardMetric1;
                    Gateway = Route->dwForwardNextHop;
                }
            }
        }
        DefaultRouteOnly = Covering == 0 ? 0 : (Covering == 1 && Defaults == 1) ? 1 : -1;
    }
    else
        DefaultRouteOnly = -1;
    free(Routes);
}

static void CheckRow(const char *Name, const ROUTE_ROW2 *Row, const SOCKADDR_INET *Source, ULONG Index,
                     ULONG Type, ULONG PrefixAddress, ULONG PrefixLength, ULONG NextHop, ULONG SourceIp)
{
    ok(Row->InterfaceIndex == Index, "%s: interface index %lu, expected %lu\n", Name, Row->InterfaceIndex, Index);
    ok(Row->InterfaceLuid.Info.IfType == Type, "%s: luid type %u, expected %lu\n", Name,
       Row->InterfaceLuid.Info.IfType, Type);
    ok(Row->DestinationPrefix.Prefix.si_family == AF_INET, "%s: prefix family %u\n", Name,
       Row->DestinationPrefix.Prefix.si_family);
    ok(Row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr == PrefixAddress, "%s: prefix %08lx, expected %08lx\n", Name,
       Row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr, PrefixAddress);
    ok(Row->DestinationPrefix.PrefixLength == PrefixLength, "%s: prefix length %u, expected %lu\n", Name,
       Row->DestinationPrefix.PrefixLength, PrefixLength);
    ok(Row->NextHop.si_family == AF_INET, "%s: next hop family %u\n", Name, Row->NextHop.si_family);
    ok(Row->NextHop.Ipv4.sin_addr.s_addr == NextHop, "%s: next hop %08lx, expected %08lx\n", Name,
       Row->NextHop.Ipv4.sin_addr.s_addr, NextHop);
    /* Windows 7 reports every route as network management, Windows 10 the on-link ones as local */
    ok(Row->Protocol == MIB_PROTO_LOCAL || Row->Protocol == MIB_PROTO_NETMGMT, "%s: protocol %lu\n", Name, Row->Protocol);
    ok(Source->si_family == AF_INET, "%s: source family %u\n", Name, Source->si_family);
    ok(Source->Ipv4.sin_addr.s_addr == SourceIp, "%s: source %08lx, expected %08lx\n", Name,
       Source->Ipv4.sin_addr.s_addr, SourceIp);
}

static void TestArguments(void)
{
    SOCKADDR_INET Dest, Source;
    ROUTE_ROW2 Row;
    DWORD Error;

    MakeV4(&Dest, htonl(INADDR_LOOPBACK));
    Error = pGetBestRoute2(NULL, 0, NULL, NULL, 0, &Row, &Source);
    ok(Error == ERROR_INVALID_PARAMETER, "no destination: %lu\n", Error);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, NULL, &Source);
    ok(Error == ERROR_INVALID_PARAMETER, "no route row: %lu\n", Error);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "no source row: %lu\n", Error);

    memset(&Dest, 0, sizeof(Dest));
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == ERROR_INVALID_PARAMETER, "family 0: %lu\n", Error);
    Dest.si_family = 99;
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == ERROR_INVALID_PARAMETER, "family 99: %lu\n", Error);

    MakeV6(&Dest, 0x2001, 1);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, NULL, &Source);
    ok(Error == ERROR_INVALID_PARAMETER, "IPv6, no route row: %lu\n", Error);
}

static void TestLoopback(void)
{
    SOCKADDR_INET Dest, Source;
    ROUTE_ROW2 Row;
    DWORD Error;

    if (!HaveLoopback)
    {
        skip("No loopback interface\n");
        return;
    }

    memset(&Row, 0xcc, sizeof(Row));
    MakeV4(&Dest, htonl(INADDR_LOOPBACK));
    Dest.Ipv4.sin_port = htons(80);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == NO_ERROR, "127.0.0.1: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        CheckRow("127.0.0.1", &Row, &Source, LoopbackIndex, IF_TYPE_LOOPBACK, htonl(INADDR_LOOPBACK), 32, 0,
                 htonl(INADDR_LOOPBACK));
        ok(Row.Loopback, "127.0.0.1: not a loopback route\n");
        ok(Row.Metric == ON_LINK_METRIC, "127.0.0.1: metric %lu\n", Row.Metric);
        ok(!HaveLoopbackLuid || Row.InterfaceLuid.Value == LoopbackLuid, "127.0.0.1: luid 0x%I64x, adapter luid 0x%I64x\n",
           (ULONGLONG)Row.InterfaceLuid.Value, LoopbackLuid);
    }

    memset(&Row, 0xcc, sizeof(Row));
    MakeV4(&Dest, htonl(0x7f010203));
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == NO_ERROR, "127.1.2.3: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        CheckRow("127.1.2.3", &Row, &Source, LoopbackIndex, IF_TYPE_LOOPBACK, htonl(0x7f000000), 8, 0,
                 htonl(INADDR_LOOPBACK));
        ok(!Row.Loopback, "127.1.2.3: a loopback route\n");
    }

    /* the loopback address is not reachable over a network adapter */
    if (HaveAdapter)
    {
        MakeV4(&Dest, htonl(INADDR_LOOPBACK));
        Error = pGetBestRoute2(NULL, AdapterIndex, NULL, &Dest, 0, &Row, &Source);
        ok(Error == ERROR_INVALID_PARAMETER, "127.0.0.1 over the adapter: %lu\n", Error);
    }
}

static void TestLocalDestinations(void)
{
    SOCKADDR_INET Dest, Source;
    ROUTE_ROW2 Row;
    ULONG Broadcast;
    DWORD Error;

    /* an address of this computer gets a host route over its interface */
    memset(&Row, 0xcc, sizeof(Row));
    MakeV4(&Dest, AdapterAddress);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == NO_ERROR, "own address: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        CheckRow("own address", &Row, &Source, AdapterIndex, Row.InterfaceLuid.Info.IfType, AdapterAddress, 32, 0,
                 AdapterAddress);
        ok(Row.Loopback, "own address: not a loopback route\n");
        ok(Row.InterfaceLuid.Info.IfType != IF_TYPE_LOOPBACK, "own address: loopback luid\n");
        ok(!HaveAdapterLuid || Row.InterfaceLuid.Value == AdapterLuid, "own address: luid 0x%I64x, adapter luid 0x%I64x\n",
           (ULONGLONG)Row.InterfaceLuid.Value, AdapterLuid);
        ok(Row.Metric == ON_LINK_METRIC, "own address: metric %lu\n", Row.Metric);
    }

    /* so does the broadcast address of its subnet, and the limited broadcast over a given interface */
    if (AdapterMask != 0 && AdapterMask != INADDR_NONE)
    {
        Broadcast = AdapterAddress | ~AdapterMask;
        MakeV4(&Dest, Broadcast);
        memset(&Row, 0xcc, sizeof(Row));
        Error = pGetBestRoute2(NULL, AdapterIndex, NULL, &Dest, 0, &Row, &Source);
        ok(Error == NO_ERROR, "subnet broadcast: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            CheckRow("subnet broadcast", &Row, &Source, AdapterIndex, Row.InterfaceLuid.Info.IfType, Broadcast, 32, 0,
                     AdapterAddress);
            ok(Row.Loopback, "subnet broadcast: not a loopback route\n");
        }
    }
    else
        skip("No subnet mask for the adapter\n");

    MakeV4(&Dest, INADDR_NONE);
    memset(&Row, 0xcc, sizeof(Row));
    Error = pGetBestRoute2(NULL, AdapterIndex, NULL, &Dest, 0, &Row, &Source);
    ok(Error == NO_ERROR, "limited broadcast: %lu\n", Error);
    if (Error == NO_ERROR)
        CheckRow("limited broadcast", &Row, &Source, AdapterIndex, Row.InterfaceLuid.Info.IfType, INADDR_NONE, 32, 0,
                 AdapterAddress);
}

static void TestInterfaceAndSource(void)
{
    SOCKADDR_INET Dest, SrcAddr, Source;
    MIB_IFROW IfRow;
    NET_LUID Luid;
    ROUTE_ROW2 Row, Row2;
    ULONG Unknown, UnknownIp;
    DWORD Error;

    MakeV4(&Dest, AdapterAddress);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    if (Error != NO_ERROR)
    {
        skip("No route to the adapter address\n");
        return;
    }

    /* the luid it returns is accepted as the interface, and beats the index */
    Luid = Row.InterfaceLuid;
    Error = pGetBestRoute2(&Luid, 0, NULL, &Dest, 0, &Row2, &Source);
    ok(Error == NO_ERROR, "own address by luid: %lu\n", Error);
    ok(Error != NO_ERROR || Row2.InterfaceIndex == AdapterIndex, "own address by luid: index %lu\n", Row2.InterfaceIndex);

    for (Unknown = 9999; Unknown < 20000; Unknown++)
    {
        memset(&IfRow, 0, sizeof(IfRow));
        IfRow.dwIndex = Unknown;
        if (GetIfEntry(&IfRow) != NO_ERROR)
            break;
    }
    Error = pGetBestRoute2(&Luid, Unknown, NULL, &Dest, 0, &Row2, &Source);
    ok(Error == NO_ERROR, "luid and an unknown index: %lu\n", Error);

    /* an unknown luid, an unknown index, and a source address that is nobody's */
    memset(&Luid, 0, sizeof(Luid));
    Luid.Value = 0x123456789abcdefULL;
    Error = pGetBestRoute2(&Luid, 0, NULL, &Dest, 0, &Row2, &Source);
    ok(Error == ERROR_NOT_FOUND, "unknown luid: %lu\n", Error);
    Luid.Value = 0;
    Error = pGetBestRoute2(&Luid, 0, NULL, &Dest, 0, &Row2, &Source);
    ok(Error == NO_ERROR, "zero luid: %lu\n", Error);
    Error = pGetBestRoute2(NULL, Unknown, NULL, &Dest, 0, &Row2, &Source);
    ok(Error == ERROR_FILE_NOT_FOUND, "unknown index: %lu\n", Error);

    UnknownIp = htonl(0xc000024d);
    while (IsLocalAddress(UnknownIp))
        UnknownIp = htonl(ntohl(UnknownIp) + 1);
    MakeV4(&SrcAddr, UnknownIp);
    Error = pGetBestRoute2(NULL, 0, &SrcAddr, &Dest, 0, &Row2, &Source);
    if (!AddressesTruncated)
        ok(Error == ERROR_NOT_FOUND, "foreign source address: %lu\n", Error);
    MakeV4(&SrcAddr, 0);
    Error = pGetBestRoute2(NULL, 0, &SrcAddr, &Dest, 0, &Row2, &Source);
    ok(Error == NO_ERROR, "zero source address: %lu\n", Error);
}

static void TestDefaultRoute(void)
{
    SOCKADDR_INET Dest, SrcAddr, Source;
    ROUTE_ROW2 Row;
    DWORD Error;

    /* a destination off the link, over the adapter, follows its default route */
    MakeV4(&Dest, htonl(0x08080808));
    memset(&Row, 0xcc, sizeof(Row));
    Error = pGetBestRoute2(NULL, AdapterIndex, NULL, &Dest, 0, &Row, &Source);
    if (DefaultRouteOnly == 1)
    {
        ok(Error == NO_ERROR, "8.8.8.8: %lu\n", Error);
        if (Error == NO_ERROR)
            CheckRow("8.8.8.8", &Row, &Source, AdapterIndex, Row.InterfaceLuid.Info.IfType, 0, 0, Gateway, AdapterAddress);

        MakeV4(&SrcAddr, AdapterAddress);
        Error = pGetBestRoute2(NULL, 0, &SrcAddr, &Dest, 0, &Row, &Source);
        ok(Error == NO_ERROR, "8.8.8.8 from the adapter address: %lu\n", Error);
        ok(Error != NO_ERROR || Source.Ipv4.sin_addr.s_addr == AdapterAddress, "source %08lx\n",
           Source.Ipv4.sin_addr.s_addr);

        /* the loopback address as the source confines the route to the loopback interface */
        MakeV4(&SrcAddr, htonl(INADDR_LOOPBACK));
        Error = pGetBestRoute2(NULL, 0, &SrcAddr, &Dest, 0, &Row, &Source);
        ok(Error == ERROR_NETWORK_UNREACHABLE, "8.8.8.8 from 127.0.0.1: %lu\n", Error);
    }
    else if (DefaultRouteOnly == 0)
    {
        ok(Error == ERROR_NETWORK_UNREACHABLE, "8.8.8.8 without a route: %lu\n", Error);
    }
    else
    {
        skip("The routes of the adapter do not give a clear answer for 8.8.8.8\n");
    }
}

static void TestIpv6(void)
{
    HMODULE hIphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    PGET_IP_FORWARD_TABLE2 pGetIpForwardTable2 = (PGET_IP_FORWARD_TABLE2)GetProcAddress(hIphlpapi, "GetIpForwardTable2");
    PFREE_MIB_TABLE pFreeMibTable = (PFREE_MIB_TABLE)GetProcAddress(hIphlpapi, "FreeMibTable");
    SOCKADDR_INET Dest, Source;
    ROUTE_ROW2 Row;
    ROUTE_TABLE2 *Table = NULL;
    BOOL Routed = FALSE;
    DWORD Error;
    ULONG i;

    MakeV6(&Dest, 0, 0);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == ERROR_NOT_FOUND, "::: %lu\n", Error);

    if (is_reactos())
    {
        /* ::1 has a route over the loopback interface while the stack has IPv6 (IpForwardTable6 tests it in detail) */
        SOCKET Probe = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        BOOL HaveV6 = Probe != INVALID_SOCKET;

        if (HaveV6)
            closesocket(Probe);
        MakeV6(&Dest, 0, 1);
        Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
        ok(Error == (HaveV6 ? NO_ERROR : ERROR_NETWORK_UNREACHABLE), "::1: %lu\n", Error);
    }

    MakeV6(&Dest, 0x2001, 1);
    /* Without an IPv6 route that covers a global address it has no route; ReactOS has no IPv6 at all. */
    if (pGetIpForwardTable2)
    {
        Error = pGetIpForwardTable2(AF_INET6, &Table);
        if (Error == NO_ERROR && Table)
        {
            for (i = 0; i < Table->NumEntries; i++)
            {
                const ROUTE_ROW2 *Route = &Table->Table[i];

                if (PrefixCovers(Route->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
                                 Route->DestinationPrefix.PrefixLength, Dest.Ipv6.sin6_addr.u.Byte))
                    Routed = TRUE;
            }
            if (pFreeMibTable)
                pFreeMibTable(Table);
        }
        else if (!is_reactos())
        {
            skip("The IPv6 routes cannot be enumerated\n");
            return;
        }
    }
    if (Routed)
    {
        skip("The computer has an IPv6 route that covers 2001::1\n");
        return;
    }

    MakeV6(&Dest, 0x2001, 1);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Row, &Source);
    ok(Error == ERROR_NETWORK_UNREACHABLE, "2001::1: %lu\n", Error);
}

START_TEST(GetBestRoute2)
{
    HMODULE hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    WSADATA Wsa;

    pGetBestRoute2 = (PGET_BEST_ROUTE2)GetProcAddress(hIphlpapi, "GetBestRoute2");
    if (!pGetBestRoute2 && (!is_reactos() || !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64")))
    {
        skip("No NT 6 exports\n");
        return;
    }
    ok(pGetBestRoute2 != NULL, "GetBestRoute2 is not exported\n");
    if (!pGetBestRoute2)
        return;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    FindEnvironment();
    TestArguments();
    TestLoopback();
    TestIpv6();
    if (!HaveAdapter)
    {
        skip("No network adapter with an IPv4 address\n");
    }
    else
    {
        TestLocalDestinations();
        TestInterfaceAndSource();
        TestDefaultRoute();
    }
    WSACleanup();
}
