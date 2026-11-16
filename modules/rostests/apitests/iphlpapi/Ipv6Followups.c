/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What a read of Windows Server 2022 showed about the IPv6 IP Helper functions and these tests keep:
 *              - ResolveIpNetEntry2 for IPv6 puts neighbour solicitations on the wire (the ICMPv6 solicitation counter
 *                moves), also for a neighbour that is cached, and nothing else (a capture of the wire shows that: the
 *                counters of the stack cannot); IOCTL_IP6_SOLICIT is the private request behind it
 *              - NotifyAddrChange, NotifyRouteChange and SIO_ADDRESS_LIST_CHANGE on an AF_INET socket do not wake for
 *                an IPv6 change, SIO_ADDRESS_LIST_CHANGE on an AF_INET6 socket does not wake for an IPv4 one
 *              - the unicast IPv6 neighbours of an interface that is not up are not listed
 *              - GetExtendedTcpTable(AF_INET6) and GetTcp6Table are sorted
 *              - MIB_IPFORWARD_ROW2.Metric of an IPv4 route is the metric of the route table less the interface metric
 *                (Windows: a default route of a metric 25 interface is 25 in GetIpForwardTable, 0 in the row; the
 *                routes the stack makes carry a metric below the interface's, which is 0 in the row), and a route made
 *                with a metric reads back with it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"
#include <tcpmib.h>
#include <tcpioctl.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

#ifndef SIO_ADDRESS_LIST_CHANGE
#define SIO_ADDRESS_LIST_CHANGE _WSAIO(IOC_WS2, 23)
#endif

static PFN_GET_TABLE pGetIpForwardTable2, pGetIpNetTable2, pGetUnicastIpAddressTable;
static PFN_FREE_TABLE pFreeMibTable;
static PFN_RESOLVE pResolveIpNetEntry2;
static DWORD (WINAPI *pGetIcmpStatisticsEx)(PMIB_ICMP_EX, DWORD);
static DWORD (WINAPI *pGetIpInterfaceEntry)(PVOID);
static void (WINAPI *pInitializeIpForwardEntry)(PVOID);
static DWORD (WINAPI *pCreateIpForwardEntry2)(PVOID);
static DWORD (WINAPI *pDeleteIpForwardEntry2)(PVOID);
static DWORD (WINAPI *pGetIpForwardEntry2)(PVOID);

/* MIB_UNICASTIPADDRESS_ROW and its table */
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

/* MIB_IPINTERFACE_ROW, to its Metric */
typedef struct
{
    USHORT Family;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    ULONG MaxReassemblySize;
    ULONGLONG InterfaceIdentifier;
    ULONG MinRouterAdvertisementInterval;
    ULONG MaxRouterAdvertisementInterval;
    BOOLEAN AdvertisingEnabled;
    BOOLEAN ForwardingEnabled;
    BOOLEAN WeakHostSend;
    BOOLEAN WeakHostReceive;
    BOOLEAN UseAutomaticMetric;
    BOOLEAN UseNeighborUnreachabilityDetection;
    BOOLEAN ManagedAddressConfigurationSupported;
    BOOLEAN OtherStatefulConfigurationSupported;
    BOOLEAN AdvertiseDefaultRoute;
    ULONG RouterDiscoveryBehavior;
    ULONG DadTransmits;
    ULONG BaseReachableTime;
    ULONG RetransmitTime;
    ULONG PathMtuDiscoveryTimeout;
    ULONG LinkLocalAddressBehavior;
    ULONG LinkLocalAddressTimeout;
    ULONG ZoneIndices[16];
    ULONG SitePrefixLength;
    ULONG Metric;
    ULONG NlMtu;
    BOOLEAN Connected;
    BOOLEAN SupportsWakeUpPatterns;
    BOOLEAN SupportsNeighborDiscovery;
    BOOLEAN SupportsRouterDiscovery;
    ULONG ReachableTime;
    UCHAR TransmitOffload;
    UCHAR ReceiveOffload;
    BOOLEAN DisableDefaultRoutes;
} IPIF_ROW;

#define DAD_PREFERRED   4
#define ORIGIN_MANUAL   1

static NTSTATUS SendRequest(ULONG Code, PVOID Request, ULONG Size)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Device;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    /* read access only: neither IOCTL_IP6_SOLICIT nor a notification needs more */
    Status = NtCreateFile(&Device, GENERIC_READ | SYNCHRONIZE, &Attributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, Code, Request, Size, NULL, 0);
    NtClose(Device);
    return Status;
}

static NTSTATUS AddressRequest(ULONG Operation, ULONG IfIndex, const char *Address, ULONG Length)
{
    TCP_IPV6_ADDRESS_REQUEST Request;
    SOCKADDR_INET Parsed;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Device;
    NTSTATUS Status;

    memset(&Request, 0, sizeof(Request));
    Request.Operation = Operation;
    Request.Store = TCP_IPV6_STORE_ACTIVE;
    Request.IfIndex = IfIndex;
    Ipv6Parse(&Parsed, Address, 0);
    memcpy(Request.Address, &Parsed.Ipv6.sin6_addr, 16);
    Request.PrefixLength = Length;
    Request.ValidLifetime = 600;
    Request.PreferredLifetime = 300;
    Request.PrefixOrigin = ORIGIN_MANUAL;
    Request.SuffixOrigin = ORIGIN_MANUAL;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&Device, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, IOCTL_IP6_ADDRESS_CONFIG, &Request,
                                   sizeof(Request), NULL, 0);
    NtClose(Device);
    return Status;
}

/* The first interface with a link-local IPv6 address that is not the loopback interface (0: none) */
static ULONG EthernetIndex(void)
{
    UNICAST_TABLE6 *Table = NULL;
    ULONG i, Index = 0;

    if (!pGetUnicastIpAddressTable || pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
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

static BOOL IsUp(ULONG IfIndex)
{
    ULONG Size = 0;
    PIP_ADAPTER_ADDRESSES Adapters, A;
    BOOL Up = FALSE;

    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL,
                         NULL, &Size);
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    if (Adapters && GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                         GAA_FLAG_SKIP_DNS_SERVER, NULL, Adapters, &Size) == NO_ERROR)
    {
        for (A = Adapters; A; A = A->Next)
            if (A->IfIndex == IfIndex || A->Ipv6IfIndex == IfIndex)
                Up = (A->OperStatus == IfOperStatusUp);
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Up;
}

static BOOL FindNeighbour(const SOCKADDR_INET *Address, ULONG IfIndex, ULONG *State)
{
    NEIGH_TABLE6 *Table = NULL;
    ULONG i;
    BOOL Found = FALSE;

    if (pGetIpNetTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries && !Found; i++)
    {
        if (Table->Table[i].InterfaceIndex == IfIndex &&
            !memcmp(&Table->Table[i].Address.Ipv6.sin6_addr, &Address->Ipv6.sin6_addr, 16))
        {
            *State = Table->Table[i].State;
            Found = TRUE;
        }
    }
    pFreeMibTable(Table);
    return Found;
}

static DWORD NeighbourSolicitations(void)
{
    MIB_ICMP_EX Icmp;

    memset(&Icmp, 0, sizeof(Icmp));
    if (pGetIcmpStatisticsEx(&Icmp, AF_INET6) != NO_ERROR)
        return 0;
    return Icmp.icmpOutStats.rgdwTypeCount[135];
}

/* IOCTL_IP6_SOLICIT: a request that is wrong fails, a good one starts neighbour discovery and nothing else */
static void TestSolicitRequest(ULONG Index, BOOL On)
{
    TCP_IPV6_SOLICIT_REQUEST Request;
    SOCKADDR_INET Target;
    NTSTATUS Status;
    ULONG State = 0, i;
    BOOL Seen = FALSE, Gone = FALSE;

    memset(&Request, 0, sizeof(Request));
    Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request) - 1);
    ok(Status == STATUS_INVALID_PARAMETER, "a short request: 0x%lx\n", Status);

    if (!On)
    {
        Request.IfIndex = 1;
        Request.Address[0] = 0xfe;
        Request.Address[1] = 0x80;
        Request.Address[15] = 5;
        Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
        ok(Status == STATUS_NOT_SUPPORTED, "IPv6 off: 0x%lx\n", Status);
        return;
    }

    /* the unspecified address, a multicast address and the loopback address are no neighbours */
    Request.IfIndex = Index;
    Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
    ok(Status == STATUS_INVALID_PARAMETER, "the unspecified address: 0x%lx\n", Status);
    Request.Address[0] = 0xff;
    Request.Address[1] = 0x02;
    Request.Address[15] = 1;
    Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
    ok(Status == STATUS_INVALID_PARAMETER, "a multicast address: 0x%lx\n", Status);
    memset(Request.Address, 0, 16);
    Request.Address[15] = 1;
    Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
    ok(Status == STATUS_INVALID_PARAMETER, "the loopback address: 0x%lx\n", Status);

    /* an interface that is not there */
    Ipv6Parse(&Target, "fe80::6c0b:2:3:4", 0);
    memcpy(Request.Address, &Target.Ipv6.sin6_addr, 16);
    Request.IfIndex = 0x7ffffff0;
    Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
    ok(Status == STATUS_NOT_FOUND, "an unknown interface: 0x%lx\n", Status);

    /* a good one: an incomplete neighbour appears, and is gone when nobody answered (three solicitations a second apart) */
    Request.IfIndex = Index;
    if (!IsUp(Index))
    {
        skip("The interface is not up\n");
        return;
    }
    Target.Ipv6.sin6_scope_id = Index;
    Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
    ok(Status == STATUS_SUCCESS, "a solicit request: 0x%lx\n", Status);
    for (i = 0; i < 20 && !Seen; i++)
    {
        Seen = FindNeighbour(&Target, Index, &State);
        if (!Seen)
            Sleep(50);
    }
    ok(Seen && State == NLNS_INCOMPLETE, "the neighbour asked for: seen %d, state %lu\n", Seen, State);
    for (i = 0; i < 60 && !Gone; i++)
    {
        Sleep(100);
        Gone = !FindNeighbour(&Target, Index, &State);
    }
    ok(Gone, "an unanswered neighbour is dropped after the solicitations\n");
}

/* IOCTL_IP6_SOLICIT in a loop does not flood the link: an address being asked for is not asked again, and a cached
 * neighbour is asked for at most 16 times a second (the stack's bound) */
static void TestSolicitBound(ULONG Index)
{
    TCP_IPV6_SOLICIT_REQUEST Request;
    SOCKADDR_INET Target;
    NEIGH_TABLE6 *Table = NULL;
    DWORD Before, After, Start;
    NTSTATUS Status;
    ULONG i, Failed;

    if (!IsUp(Index))
    {
        skip("The interface is not up\n");
        return;
    }

    /* an address nobody answers: the first request makes an incomplete entry, the others leave it to the timer */
    Ipv6Parse(&Target, "fe80::6c0b:8:9:a", 0);
    memset(&Request, 0, sizeof(Request));
    Request.IfIndex = Index;
    memcpy(Request.Address, &Target.Ipv6.sin6_addr, 16);
    Before = NeighbourSolicitations();
    for (i = 0, Failed = 0; i < 200; i++)
        if (!NT_SUCCESS(SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request))))
            Failed++;
    After = NeighbourSolicitations();
    ok(Failed == 0, "%lu of 200 solicit requests failed\n", Failed);
    ok(After - Before <= 3, "%lu neighbour solicitations for 200 requests for one address being asked for\n",
       After - Before);

    /* a cached neighbour */
    if (pGetIpNetTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const NEIGH_ROW6 *Source = &Table->Table[i];

        if (Source->InterfaceIndex == Index && Source->State >= NLNS_STALE && Source->State != NLNS_PERMANENT &&
            Source->PhysicalAddressLength == 6)
        {
            memcpy(Request.Address, &Source->Address.Ipv6.sin6_addr, 16);
            break;
        }
    }
    if (i == Table->NumEntries)
    {
        pFreeMibTable(Table);
        skip("No cached neighbour\n");
        return;
    }
    pFreeMibTable(Table);
    Sleep(1100);
    Start = GetTickCount();
    Before = NeighbourSolicitations();
    for (i = 0, Failed = 0; i < 500; i++)
    {
        Status = SendRequest(IOCTL_IP6_SOLICIT, &Request, sizeof(Request));
        if (!NT_SUCCESS(Status))
            Failed++;
    }
    After = NeighbourSolicitations();
    ok(Failed == 0, "%lu of 500 solicit requests for a cached neighbour failed\n", Failed);
    /* 16 in every second the loop touched, and a few the stack sends by itself (probes of other neighbours) */
    ok(After - Before >= 1 && After - Before <= 16 * ((GetTickCount() - Start) / 1000 + 2) + 4,
       "%lu neighbour solicitations for 500 requests in %lu ms\n", After - Before, GetTickCount() - Start);
}

/* ResolveIpNetEntry2: solicitations only, for an unknown neighbour and for a cached one */
static void TestResolveWire(ULONG Index)
{
    NEIGH_ROW6 Row;
    SOCKADDR_INET Target;
    NEIGH_TABLE6 *Table = NULL;
    DWORD Before, After, Error;
    ULONG i;

    if (!IsUp(Index))
    {
        skip("The interface is not up\n");
        return;
    }

    /* nobody answers: Windows asked three times a second apart (a capture) */
    Ipv6Parse(&Target, "fe80::6c0b:5:6:7", Index);
    memset(&Row, 0, sizeof(Row));
    Row.Address = Target;
    Row.InterfaceIndex = Index;
    Before = NeighbourSolicitations();
    Error = pResolveIpNetEntry2(&Row, NULL);
    ok(Error == ERROR_BAD_NET_NAME, "resolve a missing neighbour: %lu\n", Error);
    After = NeighbourSolicitations();
    /* the stack asks three times; the counter also counts what it sends for other neighbours in these three seconds
       (a probe of the router), which a slow Debug build lets in */
    ok(After - Before >= 1 && After - Before <= 6, "%lu neighbour solicitations for a missing neighbour\n", After - Before);

    /* a cached neighbour: resolved, and asked for once more */
    if (pGetIpNetTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const NEIGH_ROW6 *Source = &Table->Table[i];

        if (Source->InterfaceIndex != Index || Source->State < NLNS_STALE || Source->State == NLNS_PERMANENT ||
            Source->PhysicalAddressLength != 6)
            continue;
        memset(&Row, 0, sizeof(Row));
        Row.Address = Source->Address;
        Row.InterfaceIndex = Index;
        Before = NeighbourSolicitations();
            Error = pResolveIpNetEntry2(&Row, NULL);
        Sleep(200);
        After = NeighbourSolicitations();
            ok(Error == NO_ERROR, "resolve a cached neighbour: %lu\n", Error);
        ok(After - Before >= 1, "no neighbour solicitation for a cached neighbour\n");
        break;
    }
    pFreeMibTable(Table);
}

/* The unicast neighbours of an interface that is not up are not listed */
static void TestNeighboursOfDownInterfaces(void)
{
    NEIGH_TABLE6 *Table = NULL;
    ULONG i;

    if (pGetIpNetTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const NEIGH_ROW6 *Row = &Table->Table[i];

        if (Row->Address.Ipv6.sin6_addr.u.Byte[0] == 0xff || Row->State == NLNS_PERMANENT)
            continue;
        ok(IsUp(Row->InterfaceIndex), "a neighbour on interface %lu, which is not up\n", Row->InterfaceIndex);
    }
    pFreeMibTable(Table);
}

/* The order of the IPv6 TCP tables: local address, scope, port, remote address, scope, port */
static int Compare16(const void *A, const void *B)
{
    return memcmp(A, B, 16);
}

static void TestTcp6Sort(void)
{
    SOCKET Sockets[6];
    ULONG i, Count = 0;
    SOCKADDR_IN6 Address;
    static const USHORT Ports[] = { 40001, 61003, 1500, 32768, 65000, 10 };
    DWORD Size = 0, Error;
    PMIB_TCP6TABLE_OWNER_PID Table;
    PMIB_TCP6TABLE Legacy = NULL;
    DWORD (WINAPI *pGetTcp6Table)(PMIB_TCP6TABLE, PULONG, BOOL);

    for (i = 0; i < 6; i++)
    {
        Sockets[i] = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (Sockets[i] == INVALID_SOCKET)
            continue;
        memset(&Address, 0, sizeof(Address));
        Address.sin6_family = AF_INET6;
        Address.sin6_addr.u.Byte[15] = 1;   /* ::1 */
        Address.sin6_port = htons(Ports[i]);
        if (bind(Sockets[i], (struct sockaddr *)&Address, sizeof(Address)) == 0 && listen(Sockets[i], 1) == 0)
            Count++;
    }
    if (Count < 2)
    {
        skip("IPv6 listeners could not be made\n");
        goto done;
    }

    GetExtendedTcpTable(NULL, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    Size += 8192;
    Table = HeapAlloc(GetProcessHeap(), 0, Size);
    Error = GetExtendedTcpTable(Table, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    ok(Error == NO_ERROR, "GetExtendedTcpTable(AF_INET6): %lu\n", Error);
    if (Error == NO_ERROR)
    {
        ULONG Seen = 0;

        for (i = 0; i < Table->dwNumEntries; i++)
        {
            const MIB_TCP6ROW_OWNER_PID *A = &Table->table[i], *B = &Table->table[i + 1];
            int Order;

            if (A->dwOwningPid == GetCurrentProcessId())
                Seen++;
            if (i + 1 == Table->dwNumEntries)
                break;
            Order = Compare16(A->ucLocalAddr, B->ucLocalAddr);
            if (Order == 0 && A->dwLocalScopeId != B->dwLocalScopeId)
                Order = A->dwLocalScopeId < B->dwLocalScopeId ? -1 : 1;
            if (Order == 0 && A->dwLocalPort != B->dwLocalPort)
                Order = A->dwLocalPort < B->dwLocalPort ? -1 : 1;
            ok(Order <= 0, "rows %lu and %lu are not in order (local address, scope, port)\n", i, i + 1);
        }
        ok(Seen >= Count, "%lu of the %lu listeners in the table\n", Seen, Count);
    }
    HeapFree(GetProcessHeap(), 0, Table);

    pGetTcp6Table = (void *)Ipv6Proc("GetTcp6Table");
    if (pGetTcp6Table)
    {
        Size = 0;
        pGetTcp6Table(NULL, &Size, TRUE);
        Size += 8192;
        Legacy = HeapAlloc(GetProcessHeap(), 0, Size);
        Error = pGetTcp6Table(Legacy, &Size, TRUE);
        ok(Error == NO_ERROR, "GetTcp6Table: %lu\n", Error);
        for (i = 0; Error == NO_ERROR && i + 1 < Legacy->dwNumEntries; i++)
        {
            const MIB_TCP6ROW *A = &Legacy->table[i], *B = &Legacy->table[i + 1];
            int Order = Compare16(&A->LocalAddr, &B->LocalAddr);

            if (Order == 0 && A->dwLocalScopeId != B->dwLocalScopeId)
                Order = A->dwLocalScopeId < B->dwLocalScopeId ? -1 : 1;
            if (Order == 0 && A->dwLocalPort != B->dwLocalPort)
                Order = A->dwLocalPort < B->dwLocalPort ? -1 : 1;
            ok(Order <= 0, "GetTcp6Table rows %lu and %lu are not in order\n", i, i + 1);
        }
        HeapFree(GetProcessHeap(), 0, Legacy);
    }

done:
    for (i = 0; i < 6; i++)
        if (Sockets[i] != INVALID_SOCKET)
            closesocket(Sockets[i]);
}

/* IPv4 route rows: the metric of the row is what GetIpForwardTable says less the metric of the interface */
static void TestRouteMetric(void)
{
    ROUTE_TABLE6 *Table = NULL;
    PMIB_IPFORWARDTABLE Legacy;
    ULONG Size = 0, i, j, Compared = 0;

    if (pGetIpForwardTable2(AF_INET, (PVOID *)&Table) != NO_ERROR || !Table)
    {
        skip("GetIpForwardTable2 failed\n");
        return;
    }
    GetIpForwardTable(NULL, &Size, FALSE);
    Legacy = HeapAlloc(GetProcessHeap(), 0, Size + 4096);
    if (Legacy && GetIpForwardTable(Legacy, &Size, FALSE) == NO_ERROR)
    {
        for (i = 0; i < Table->NumEntries; i++)
        {
            const ROUTE_ROW6 *Row = &Table->Table[i];
            IPIF_ROW Interface;

            memset(&Interface, 0, sizeof(Interface));
            Interface.Family = AF_INET;
            Interface.InterfaceIndex = Row->InterfaceIndex;
            if (pGetIpInterfaceEntry(&Interface) != NO_ERROR)
                continue;
            for (j = 0; j < Legacy->dwNumEntries; j++)
            {
                const MIB_IPFORWARDROW *Old = &Legacy->table[j];
                ULONG Mask = 0;

                Mask = Row->DestinationPrefix.PrefixLength ? htonl(0xffffffffUL << (32 - Row->DestinationPrefix.PrefixLength)) : 0;
                if (Old->dwForwardIfIndex != Row->InterfaceIndex ||
                    Old->dwForwardDest != Row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr ||
                    Old->dwForwardMask != Mask || Old->dwForwardNextHop != Row->NextHop.Ipv4.sin_addr.s_addr)
                    continue;
                Compared++;
                ok(Row->Metric == (Old->dwForwardMetric1 > Interface.Metric ? Old->dwForwardMetric1 - Interface.Metric : 0),
                   "route %lx/%u via %lx: legacy metric %lu, row metric %lu, interface metric %lu\n",
                   (ULONG)Old->dwForwardDest, Row->DestinationPrefix.PrefixLength, (ULONG)Old->dwForwardNextHop,
                   Old->dwForwardMetric1, Row->Metric, Interface.Metric);
                break;
            }
        }
    }
    ok(Compared > 0, "no route compared\n");
    HeapFree(GetProcessHeap(), 0, Legacy);
    pFreeMibTable(Table);
}

/* A route made with a metric reads back with that metric */
static void TestRouteMetricRoundTrip(void)
{
    ROUTE_ROW6 Row, Read;
    ROUTE_TABLE6 *Table = NULL;
    ULONG i, Index = 0;
    DWORD Error;

    if (!pCreateIpForwardEntry2 || !pDeleteIpForwardEntry2 || !pInitializeIpForwardEntry || !pGetIpForwardEntry2)
    {
        skip("The route functions are not available\n");
        return;
    }
    if (pGetIpForwardTable2(AF_INET, (PVOID *)&Table) != NO_ERROR || !Table)
        return;
    for (i = 0; i < Table->NumEntries && !Index; i++)
        if (Table->Table[i].InterfaceLuid.Value != LOOPBACK6_LUID && Table->Table[i].DestinationPrefix.PrefixLength == 24)
            Index = Table->Table[i].InterfaceIndex;
    pFreeMibTable(Table);
    if (!Index)
    {
        skip("no interface with an IPv4 prefix route\n");
        return;
    }

    pInitializeIpForwardEntry(&Row);
    Row.InterfaceIndex = Index;
    Row.DestinationPrefix.Prefix.si_family = AF_INET;
    Row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = inet_addr("198.51.100.0");
    Row.DestinationPrefix.PrefixLength = 24;
    Row.NextHop.si_family = AF_INET;
    Row.Metric = 333;
    Error = pCreateIpForwardEntry2(&Row);
    ok(Error == NO_ERROR || Error == ERROR_NOT_SUPPORTED, "CreateIpForwardEntry2: %lu\n", Error);
    if (Error != NO_ERROR)
        return;

    Read = Row;
    Read.Metric = 0;
    Error = pGetIpForwardEntry2(&Read);
    ok(Error == NO_ERROR, "GetIpForwardEntry2: %lu\n", Error);
    if (Error == NO_ERROR)
        ok(Read.Metric == 333, "metric read back %lu\n", Read.Metric);
    Error = pDeleteIpForwardEntry2(&Row);
    ok(Error == NO_ERROR, "DeleteIpForwardEntry2: %lu\n", Error);
}

typedef struct
{
    HANDLE Address, Route, Socket4, Socket6;
} WAITERS;

static WAITERS W;
static OVERLAPPED OAddr, ORoute, OSock4, OSock6;
static SOCKET S4, S6;

/* The request of dnsapi's IPv6 name server cache: both families on an asynchronous handle of its own, which is told
 * the family that changed */
static HANDLE BothFile, BothEvent;
static IO_STATUS_BLOCK BothIosb;
static ULONG BothChanged;

static void ArmBoth(void)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    ULONG Families = TCP_CHANGE_FAMILY_IPV4 | TCP_CHANGE_FAMILY_IPV6;
    NTSTATUS Status;

    if (!BothFile)
    {
        InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(&BothFile, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
        ok(NT_SUCCESS(Status), "\\Device\\Tcp: 0x%lx\n", Status);
        if (!NT_SUCCESS(Status))
        {
            BothFile = NULL;
            return;
        }
    }
    ResetEvent(BothEvent);
    BothChanged = 0;
    BothIosb.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(BothFile, BothEvent, NULL, NULL, &BothIosb, IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST,
                                   &Families, sizeof(Families), &BothChanged, sizeof(BothChanged));
    ok(Status == STATUS_PENDING, "a request for both families: 0x%lx\n", Status);
}

/* The request for both families woke for Family alone and said so */
static void CheckBoth(ULONG Family, const char *What)
{
    BOOL Woke = BothFile && WaitForSingleObject(BothEvent, 0) == WAIT_OBJECT_0;

    ok(Woke, "a request for both families does not wake for %s\n", What);
    if (Woke)
        ok(BothIosb.Status == STATUS_SUCCESS && BothIosb.Information == sizeof(ULONG) && BothChanged == Family,
           "%s: status 0x%lx, %lu bytes, families %lu\n", What, BothIosb.Status, (ULONG)BothIosb.Information,
           BothChanged);
}

static void Arm(void)
{
    DWORD Bytes;

    ArmBoth();
    ResetEvent(OAddr.hEvent);
    ResetEvent(ORoute.hEvent);
    ResetEvent(OSock4.hEvent);
    ResetEvent(OSock6.hEvent);
    memset(&OAddr.Internal, 0, 2 * sizeof(ULONG_PTR));
    NotifyAddrChange(&W.Address, &OAddr);
    NotifyRouteChange(&W.Route, &ORoute);
    WSAIoctl(S4, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Bytes, &OSock4, NULL);
    WSAIoctl(S6, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Bytes, &OSock6, NULL);
}

static void Disarm(void)
{
    IO_STATUS_BLOCK Iosb;

    if (BothFile)
        NtDeviceIoControlFile(BothFile, NULL, NULL, NULL, &Iosb, IOCTL_IP_ADDCHANGE_CANCEL_REQUEST, NULL, 0, NULL, 0);
    CancelIPChangeNotify(&OAddr);
    CancelIPChangeNotify(&ORoute);
    CancelIo((HANDLE)S4);
    CancelIo((HANDLE)S6);
    Sleep(300);
}

static BOOL Signalled(const OVERLAPPED *O)
{
    return WaitForSingleObject(O->hEvent, 0) == WAIT_OBJECT_0;
}

/* An IPv6 address comes: only the AF_INET6 socket wakes. An IPv4 address comes: the legacy waiters and the AF_INET
 * socket wake, the AF_INET6 socket does not */
static void TestNotifyFamilies(ULONG Index)
{
    NTSTATUS Status;
    DWORD Error, Tries;
    ULONG Context = 0, Instance = 0;
    DWORD V4Index = 0;
    ULONG Size = 0;
    PIP_ADAPTER_INFO Adapters, A;

    if (!is_reactos())
    {
        skip("Changing an address of the computer is not tried on Windows\n");
        return;
    }
    S4 = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    S6 = WSASocketW(AF_INET6, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    OAddr.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ORoute.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    OSock4.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    OSock6.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    BothEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    Arm();
    Sleep(300);
    ok(!Signalled(&OAddr) && !Signalled(&ORoute) && !Signalled(&OSock4) && !Signalled(&OSock6), "a wake without a change\n");

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, Index, "fd00:6c0b:2::77", 64);
    ok(Status == STATUS_SUCCESS, "the IPv6 address: 0x%lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        for (Tries = 0; Tries < 30 && !Signalled(&OSock6); Tries++)
            Sleep(100);
        Sleep(500);
        ok(Signalled(&OSock6), "an AF_INET6 socket does not wake for an IPv6 address\n");
        ok(!Signalled(&OSock4), "an AF_INET socket wakes for an IPv6 address\n");
        ok(!Signalled(&OAddr), "NotifyAddrChange wakes for an IPv6 address\n");
        ok(!Signalled(&ORoute), "NotifyRouteChange wakes for an IPv6 address\n");
        CheckBoth(TCP_CHANGE_FAMILY_IPV6, "an IPv6 address");
        AddressRequest(TCP_IPV6_CONFIG_DELETE, Index, "fd00:6c0b:2::77", 64);
        Sleep(500);
    }
    Disarm();

    GetAdaptersInfo(NULL, &Size);
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    if (Adapters && GetAdaptersInfo(Adapters, &Size) == NO_ERROR)
        for (A = Adapters; A && !V4Index; A = A->Next)
            if (A->Type != MIB_IF_TYPE_LOOPBACK && strcmp(A->IpAddressList.IpAddress.String, "0.0.0.0"))
                V4Index = A->Index;
    HeapFree(GetProcessHeap(), 0, Adapters);
    if (!V4Index)
    {
        skip("No adapter with an IPv4 address\n");
        return;
    }

    Arm();
    Sleep(300);
    Error = AddIPAddress(inet_addr("192.0.2.79"), inet_addr("255.255.255.0"), V4Index, &Context, &Instance);
    ok(Error == NO_ERROR, "AddIPAddress: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        for (Tries = 0; Tries < 30 && !Signalled(&OAddr); Tries++)
            Sleep(100);
        Sleep(500);
        ok(Signalled(&OAddr), "NotifyAddrChange does not wake for an IPv4 address\n");
        ok(Signalled(&OSock4), "an AF_INET socket does not wake for an IPv4 address\n");
        ok(Signalled(&ORoute), "NotifyRouteChange does not wake for the route of an IPv4 address\n");
        ok(!Signalled(&OSock6), "an AF_INET6 socket wakes for an IPv4 address\n");
        CheckBoth(TCP_CHANGE_FAMILY_IPV4, "an IPv4 address");
        DeleteIPAddress(Context);
        Sleep(500);
    }
    Disarm();
    CloseHandle(OAddr.hEvent);
    CloseHandle(ORoute.hEvent);
    CloseHandle(OSock4.hEvent);
    CloseHandle(OSock6.hEvent);
    if (BothFile)
        NtClose(BothFile);
    BothFile = NULL;
    CloseHandle(BothEvent);
    closesocket(S4);
    closesocket(S6);
}

START_TEST(Ipv6Followups)
{
    WSADATA Wsa;
    HMODULE Module;
    BOOL On;
    ULONG Index;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    Module = LoadLibraryW(L"iphlpapi.dll");
    pGetIpForwardTable2 = (PFN_GET_TABLE)GetProcAddress(Module, "GetIpForwardTable2");
    pGetIpNetTable2 = (PFN_GET_TABLE)GetProcAddress(Module, "GetIpNetTable2");
    pGetUnicastIpAddressTable = (PFN_GET_TABLE)GetProcAddress(Module, "GetUnicastIpAddressTable");
    pFreeMibTable = (PFN_FREE_TABLE)GetProcAddress(Module, "FreeMibTable");
    pResolveIpNetEntry2 = (PFN_RESOLVE)GetProcAddress(Module, "ResolveIpNetEntry2");
    pGetIcmpStatisticsEx = (void *)GetProcAddress(Module, "GetIcmpStatisticsEx");
    pGetIpInterfaceEntry = (void *)GetProcAddress(Module, "GetIpInterfaceEntry");
    pInitializeIpForwardEntry = (void *)GetProcAddress(Module, "InitializeIpForwardEntry");
    pCreateIpForwardEntry2 = (void *)GetProcAddress(Module, "CreateIpForwardEntry2");
    pDeleteIpForwardEntry2 = (void *)GetProcAddress(Module, "DeleteIpForwardEntry2");
    pGetIpForwardEntry2 = (void *)GetProcAddress(Module, "GetIpForwardEntry2");
    if (!pGetIpForwardTable2 || !pGetIpNetTable2 || !pFreeMibTable || !pResolveIpNetEntry2 || !pGetIcmpStatisticsEx ||
        !pGetIpInterfaceEntry)
    {
        skip("The IP Helper functions are not available\n");
        return;
    }

    On = Ipv6SocketsWork();
    Index = EthernetIndex();

    if (is_reactos())
        TestSolicitRequest(Index, On);
    if (On && Index)
    {
        TestResolveWire(Index);
        if (is_reactos())
            TestSolicitBound(Index);
        TestNeighboursOfDownInterfaces();
        TestNotifyFamilies(Index);
    }
    else
        skip("No IPv6 interface with a link-local address\n");
    if (On)
        TestTcp6Sort();
    TestRouteMetric();
    if (is_reactos())
        TestRouteMetricRoundTrip();
}
