/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The IPv6 route table of tcpip.sys (IOCTL_IP6_ROUTE_CONFIG, a private request of this stack): a configured
 *              route is listed by GetIpForwardTable2, chosen by GetBestRoute2 and by the stack itself (a datagram to
 *              its prefix makes a neighbour entry for its next hop, or for the destination of an on-link route),
 *              announced by NotifyRouteChange2, changed, removed, and gone when its lifetime ends. Invalid requests
 *              fail without a change. Without IPv6 the request is not supported.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"
#include <tcpioctl.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

static PFN_GET_TABLE pGetIpForwardTable2, pGetIpNetTable2, pGetUnicastIpAddressTable;
static PFN_FREE_TABLE pFreeMibTable;
static PFN_BEST_ROUTE pGetBestRoute2;
static DWORD (WINAPI *pNotifyRouteChange2)(USHORT, PVOID, PVOID, BOOLEAN, HANDLE *);
static DWORD (WINAPI *pCancelMibChangeNotify2)(HANDLE);

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

static NTSTATUS SendRequest(ULONG Code, PVOID Request, ULONG Size)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Device;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&Device, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, Code, Request, Size, NULL, 0);
    NtClose(Device);
    return Status;
}

static NTSTATUS RouteRequest(ULONG Operation, ULONG IfIndex, const char *Prefix, ULONG Length, const char *NextHop,
                             ULONG Metric, ULONG Valid, ULONG Preferred)
{
    TCP_IPV6_ROUTE_REQUEST Request;
    SOCKADDR_INET Address;

    memset(&Request, 0, sizeof(Request));
    Request.Operation = Operation;
    Request.Store = TCP_IPV6_STORE_ACTIVE;
    Request.IfIndex = IfIndex;
    Ipv6Parse(&Address, Prefix, 0);
    memcpy(Request.Prefix, &Address.Ipv6.sin6_addr, 16);
    Request.PrefixLength = Length;
    if (NextHop)
    {
        Ipv6Parse(&Address, NextHop, 0);
        memcpy(Request.NextHop, &Address.Ipv6.sin6_addr, 16);
    }
    Request.Metric = Metric;
    Request.ValidLifetime = Valid;
    Request.PreferredLifetime = Preferred;
    Request.Origin = 0;     /* NlroManual */
    Request.Protocol = 3;   /* MIB_IPPROTO_NETMGMT */
    return SendRequest(IOCTL_IP6_ROUTE_CONFIG, &Request, sizeof(Request));
}

static ULONG LoopbackIndex;

/* The first interface with a link-local address that is not the loopback interface (0: none); LoopbackIndex gets
   the interface of ::1 */
static ULONG EthernetIndex(void)
{
    static const UCHAR Loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    UNICAST_TABLE6 *Table = NULL;
    ULONG i, Index = 0;

    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return 0;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const UCHAR *A = Table->Table[i].Address.Ipv6.sin6_addr.u.Byte;

        if (!Index && Ipv6IsLinkLocal(A) && (Table->Table[i].InterfaceLuid.Value >> 48) != 24)
            Index = Table->Table[i].InterfaceIndex;
        if (!memcmp(A, Loopback, sizeof(Loopback)))
            LoopbackIndex = Table->Table[i].InterfaceIndex;
    }
    pFreeMibTable(Table);
    return Index;
}

static BOOL SameAddress(const SOCKADDR_INET *A, const char *Text)
{
    SOCKADDR_INET B;

    Ipv6Parse(&B, Text, 0);
    return A->si_family == AF_INET6 && !memcmp(&A->Ipv6.sin6_addr, &B.Ipv6.sin6_addr, 16);
}

/* The row of the table for prefix/length over IfIndex (a copy), FALSE: none */
static BOOL FindRoute(ULONG IfIndex, const char *Prefix, ULONG Length, ROUTE_ROW6 *Out)
{
    ROUTE_TABLE6 *Table = NULL;
    ULONG i;
    BOOL Found = FALSE;

    if (pGetIpForwardTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries && !Found; i++)
    {
        if (Table->Table[i].InterfaceIndex == IfIndex && Table->Table[i].DestinationPrefix.PrefixLength == Length &&
            SameAddress(&Table->Table[i].DestinationPrefix.Prefix, Prefix))
        {
            *Out = Table->Table[i];
            Found = TRUE;
        }
    }
    pFreeMibTable(Table);
    return Found;
}

/* Whether the neighbour cache has an entry for Address on IfIndex */
static BOOL HasNeighbor(ULONG IfIndex, const char *Address)
{
    NEIGH_TABLE6 *Table = NULL;
    ULONG i;
    BOOL Found = FALSE;

    if (pGetIpNetTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries && !Found; i++)
        Found = Table->Table[i].InterfaceIndex == IfIndex && SameAddress(&Table->Table[i].Address, Address);
    pFreeMibTable(Table);
    return Found;
}

/* One UDP datagram to Address (port 9): the stack routes it */
static void SendTo(const char *Address)
{
    SOCKET Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    SOCKADDR_INET To;

    ok(Socket != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET)
        return;
    Ipv6Parse(&To, Address, 0);
    To.Ipv6.sin6_port = htons(9);
    sendto(Socket, "x", 1, 0, (struct sockaddr *)&To.Ipv6, sizeof(To.Ipv6));
    closesocket(Socket);
}

static BOOL WaitNeighbor(ULONG IfIndex, const char *Address)
{
    int i;

    for (i = 0; i < 20; i++)
    {
        if (HasNeighbor(IfIndex, Address))
            return TRUE;
        Sleep(100);
    }
    return FALSE;
}

static LONG Added, Deleted, Changed;

static VOID WINAPI RouteCallback(PVOID Context, ROUTE_ROW6 *Row, ULONG Type)
{
    UNREFERENCED_PARAMETER(Context);

    if (!Row || Row->DestinationPrefix.PrefixLength != 48 ||
        !SameAddress(&Row->DestinationPrefix.Prefix, "2001:db8:77::"))
        return;
    if (Type == 1)          /* MibAddInstance */
        InterlockedIncrement(&Added);
    else if (Type == 2)     /* MibDeleteInstance */
        InterlockedIncrement(&Deleted);
    else if (Type == 0)     /* MibParameterNotification */
        InterlockedIncrement(&Changed);
}

static BOOL WaitCount(volatile LONG *Count, LONG Want)
{
    int i;

    for (i = 0; i < 50 && *Count < Want; i++)
        Sleep(100);
    return *Count >= Want;
}

static void TestInvalid(ULONG IfIndex)
{
    NTSTATUS Status;
    TCP_IPV6_ROUTE_REQUEST Request;

    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77::", 129, "fe80::77", 10, ~0UL, ~0UL);
    ok(Status == STATUS_INVALID_PARAMETER, "prefix length 129: %lx\n", Status);
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, 0x7ffffff0, "2001:db8:77::", 48, "fe80::77", 10, ~0UL, ~0UL);
    ok(Status == STATUS_NOT_FOUND, "unknown interface: %lx\n", Status);
    if (LoopbackIndex)
    {
        Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, LoopbackIndex, "2001:db8:77::", 48, "fe80::77", 10, ~0UL, ~0UL);
        ok(Status == STATUS_NOT_FOUND, "loopback interface: %lx\n", Status);
    }
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77::", 48, "ff02::1", 10, ~0UL, ~0UL);
    ok(Status == STATUS_INVALID_PARAMETER, "multicast next hop: %lx\n", Status);
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77::", 48, "fe80::77", 10, 100, 200);
    ok(Status == STATUS_INVALID_PARAMETER, "preferred lifetime over the valid one: %lx\n", Status);
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77::", 48, "fe80::77", 10, 0, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "valid lifetime 0: %lx\n", Status);
    Status = RouteRequest(9, IfIndex, "2001:db8:77::", 48, "fe80::77", 10, ~0UL, ~0UL);
    ok(Status == STATUS_INVALID_PARAMETER, "operation 9: %lx\n", Status);
    Status = RouteRequest(TCP_IPV6_CONFIG_SET, IfIndex, "2001:db8:77::", 48, "fe80::77", 10, ~0UL, ~0UL);
    ok(Status == STATUS_NOT_FOUND, "change of a route that is not there: %lx\n", Status);
    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:77::", 48, "fe80::77", 10, ~0UL, ~0UL);
    ok(Status == STATUS_NOT_FOUND, "removal of a route that is not there: %lx\n", Status);

    /* a request that is too short */
    memset(&Request, 0, sizeof(Request));
    Status = SendRequest(IOCTL_IP6_ROUTE_CONFIG, &Request, sizeof(Request) - 1);
    ok(Status == STATUS_INVALID_PARAMETER, "short request: %lx\n", Status);
    Status = SendRequest(IOCTL_IP6_ROUTE_CONFIG, NULL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "no request: %lx\n", Status);
}

static void TestRoute(ULONG IfIndex)
{
    ROUTE_ROW6 Row, Best;
    SOCKADDR_INET Dest, Source;
    HANDLE Handle = NULL;
    NTSTATUS Status;
    DWORD Error;

    Error = pNotifyRouteChange2(AF_INET6, RouteCallback, NULL, FALSE, &Handle);
    ok(Error == NO_ERROR, "NotifyRouteChange2: %lu\n", Error);

    /* a route to 2001:db8:77::/48 through a router on the link */
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77::", 48, "fe80::77", 7, ~0UL, ~0UL);
    ok(Status == STATUS_SUCCESS, "create: %lx\n", Status);
    if (!NT_SUCCESS(Status))
        goto Out;
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77::", 48, "fe80::77", 7, ~0UL, ~0UL);
    ok(Status == STATUS_OBJECT_NAME_COLLISION, "create again: %lx\n", Status);
    if (Handle)
        ok(WaitCount(&Added, 1), "no add notification\n");

    ok(FindRoute(IfIndex, "2001:db8:77::", 48, &Row), "route not listed\n");
    ok(SameAddress(&Row.NextHop, "fe80::77"), "next hop\n");
    ok(Row.NextHop.Ipv6.sin6_scope_id == IfIndex, "next hop scope %lu\n", Row.NextHop.Ipv6.sin6_scope_id);
    ok(Row.Metric == 7, "metric %lu\n", Row.Metric);
    ok(Row.Protocol == 3, "protocol %lu\n", Row.Protocol);
    ok(Row.Origin == 0, "origin %lu\n", Row.Origin);
    ok(Row.ValidLifetime == 0xffffffff && Row.PreferredLifetime == 0xffffffff, "lifetimes %lu %lu\n",
       Row.ValidLifetime, Row.PreferredLifetime);
    ok(!Row.Loopback, "loopback\n");

    /* GetBestRoute2 takes it for its prefix (the longest one) */
    Ipv6Parse(&Dest, "2001:db8:77::1234", 0);
    memset(&Best, 0, sizeof(Best));
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Best, &Source);
    ok(Error == NO_ERROR, "GetBestRoute2: %lu\n", Error);
    ok(Error != NO_ERROR || (Best.DestinationPrefix.PrefixLength == 48 && Best.InterfaceIndex == IfIndex &&
       SameAddress(&Best.NextHop, "fe80::77")), "best route /%u over %lu\n", Best.DestinationPrefix.PrefixLength,
       Best.InterfaceIndex);

    /* and the stack: a datagram to the prefix goes to the router, which it looks for */
    SendTo("2001:db8:77::1234");
    ok(WaitNeighbor(IfIndex, "fe80::77"), "no neighbour entry for the next hop\n");

    /* a change */
    Status = RouteRequest(TCP_IPV6_CONFIG_SET, IfIndex, "2001:db8:77::", 48, "fe80::77", 9, 3600, 1800);
    ok(Status == STATUS_SUCCESS, "set: %lx\n", Status);
    ok(FindRoute(IfIndex, "2001:db8:77::", 48, &Row), "route not listed after the change\n");
    ok(Row.Metric == 9, "metric %lu\n", Row.Metric);
    ok(Row.ValidLifetime <= 3600 && Row.ValidLifetime >= 3590, "valid lifetime %lu\n", Row.ValidLifetime);
    ok(Row.PreferredLifetime <= 1800 && Row.PreferredLifetime >= 1790, "preferred lifetime %lu\n",
       Row.PreferredLifetime);

    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:77::", 48, "fe80::77", 0, 0, 0);
    ok(Status == STATUS_SUCCESS, "delete: %lx\n", Status);
    ok(!FindRoute(IfIndex, "2001:db8:77::", 48, &Row), "route still listed\n");
    if (Handle)
        ok(WaitCount(&Deleted, 1), "no delete notification (%ld)\n", Deleted);

    /* an on-link route: the destination itself is looked for on the link */
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:78::", 64, NULL, 5, ~0UL, ~0UL);
    ok(Status == STATUS_SUCCESS, "create on-link: %lx\n", Status);
    ok(FindRoute(IfIndex, "2001:db8:78::", 64, &Row), "on-link route not listed\n");
    ok(Row.NextHop.si_family == AF_INET6 && Ipv6IsZero(Row.NextHop.Ipv6.sin6_addr.u.Byte), "on-link next hop\n");
    SendTo("2001:db8:78::99");
    ok(WaitNeighbor(IfIndex, "2001:db8:78::99"), "no neighbour entry for the on-link destination\n");
    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:78::", 64, NULL, 0, 0, 0);
    ok(Status == STATUS_SUCCESS, "delete on-link: %lx\n", Status);

    /* the bits after the prefix length do not count: the route is 2001:db8:77::/48 */
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:77:1::5", 48, "fe80::77", 7, 3, 3);
    ok(Status == STATUS_SUCCESS, "create with host bits: %lx\n", Status);
    ok(FindRoute(IfIndex, "2001:db8:77::", 48, &Row), "masked route not listed\n");
    ok(Row.ValidLifetime <= 3, "valid lifetime %lu\n", Row.ValidLifetime);
    if (Handle)
        ok(WaitCount(&Added, 2), "no add notification for the short route\n");

    /* its lifetime ends: it goes, with a notification */
    Sleep(5000);
    ok(!FindRoute(IfIndex, "2001:db8:77::", 48, &Row), "route still listed after its lifetime\n");
    if (Handle)
        ok(WaitCount(&Deleted, 2), "no delete notification at the end of the lifetime (%ld)\n", Deleted);
    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:77::", 48, "fe80::77", 0, 0, 0);
    ok(Status == STATUS_NOT_FOUND, "delete after the lifetime: %lx\n", Status);

Out:
    if (Handle)
        pCancelMibChangeNotify2(Handle);
}

START_TEST(Ipv6RouteConfig)
{
    WSADATA Data;
    ULONG IfIndex;
    NTSTATUS Status;

    pGetIpForwardTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpForwardTable2");
    pGetIpNetTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpNetTable2");
    pGetUnicastIpAddressTable = (PFN_GET_TABLE)Ipv6Proc("GetUnicastIpAddressTable");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    pGetBestRoute2 = (PFN_BEST_ROUTE)Ipv6Proc("GetBestRoute2");
    pNotifyRouteChange2 = (PVOID)Ipv6Proc("NotifyRouteChange2");
    pCancelMibChangeNotify2 = (PVOID)Ipv6Proc("CancelMibChangeNotify2");
    if (!pGetIpForwardTable2 || !pGetIpNetTable2 || !pGetUnicastIpAddressTable || !pFreeMibTable || !pGetBestRoute2 ||
        !pNotifyRouteChange2 || !pCancelMibChangeNotify2)
    {
        skip("the IP Helper functions are missing\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Data);

    if (!Ipv6SocketsWork())
    {
        /* IPv6 is off: there is no IPv6 route to configure */
        Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, 2, "2001:db8:77::", 48, "fe80::77", 10, ~0UL, ~0UL);
        ok(Status == STATUS_NOT_SUPPORTED, "IPv6 off: %lx\n", Status);
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

    TestInvalid(IfIndex);
    TestRoute(IfIndex);
    WSACleanup();
}
