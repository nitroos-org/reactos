/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for GetBestInterfaceEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>

#define UNSET 0xdeadbeef

typedef DWORD (WINAPI *PGET_BEST_INTERFACE_EX)(struct sockaddr *, PDWORD);

static PGET_BEST_INTERFACE_EX pGetBestInterfaceEx;
static ULONG LoopbackIndex, AdapterIndex, AdapterAddress, AdapterMask;
static BOOL HaveLoopback, HaveAdapter;
static MIB_IPFORWARDTABLE *Routes;

static void MakeV4(SOCKADDR_IN *Address, ULONG Ip)
{
    memset(Address, 0, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = Ip;
}

static void FindEnvironment(void)
{
    MIB_IPADDRTABLE *Addresses;
    ULONG Size = 0, i;

    GetIpAddrTable(NULL, &Size, FALSE);
    Addresses = malloc(Size);
    if (Addresses && GetIpAddrTable(Addresses, &Size, FALSE) == NO_ERROR)
    {
        for (i = 0; i < Addresses->dwNumEntries; i++)
        {
            const MIB_IPADDRROW *Row = &Addresses->table[i];

            if (Row->dwAddr == htonl(INADDR_LOOPBACK))
            {
                LoopbackIndex = Row->dwIndex;
                HaveLoopback = TRUE;
            }
            else if (!HaveAdapter && Row->dwAddr && Row->dwMask && Row->dwMask != INADDR_NONE &&
                     (ntohl(Row->dwAddr) >> 24) != 127 && (ntohl(Row->dwAddr) >> 16) != 0xa9fe)
            {
                AdapterIndex = Row->dwIndex;
                AdapterAddress = Row->dwAddr;
                AdapterMask = Row->dwMask;
                HaveAdapter = TRUE;
            }
        }
    }
    free(Addresses);

    Size = 0;
    GetIpForwardTable(NULL, &Size, FALSE);
    Routes = malloc(Size);
    if (Routes && GetIpForwardTable(Routes, &Size, FALSE) != NO_ERROR)
    {
        free(Routes);
        Routes = NULL;
    }
}

/* The interface of the best route for the address: the longest prefix, then the lowest metric; not a tie. */
static BOOL RouteIndex(ULONG Ip, PULONG Index)
{
    ULONG i, BestMask = 0, BestMetric = 0;
    BOOL Found = FALSE, Tie = FALSE;

    for (i = 0; Routes && i < Routes->dwNumEntries; i++)
    {
        const MIB_IPFORWARDROW *Route = &Routes->table[i];
        ULONG Mask = ntohl(Route->dwForwardMask);

        if ((Ip & Route->dwForwardMask) != (Route->dwForwardDest & Route->dwForwardMask))
            continue;
        if (Found && Mask == BestMask && Route->dwForwardMetric1 == BestMetric)
        {
            Tie |= Route->dwForwardIfIndex != *Index;
        }
        else if (!Found || Mask > BestMask || (Mask == BestMask && Route->dwForwardMetric1 < BestMetric))
        {
            Found = TRUE;
            Tie = FALSE;
            BestMask = Mask;
            BestMetric = Route->dwForwardMetric1;
            *Index = Route->dwForwardIfIndex;
        }
    }
    return Found && !Tie;
}

/* The number of routes other than a default route that cover the address. */
static ULONG SpecificRoutes(ULONG Ip)
{
    ULONG i, Count = 0;

    for (i = 0; Routes && i < Routes->dwNumEntries; i++)
    {
        const MIB_IPFORWARDROW *Route = &Routes->table[i];

        if (Route->dwForwardMask && (Ip & Route->dwForwardMask) == (Route->dwForwardDest & Route->dwForwardMask))
            Count++;
    }
    return Count;
}

static void Expect(const char *Name, struct sockaddr *Dest, DWORD ExpectedError, DWORD ExpectedIndex)
{
    DWORD Index = UNSET, Error;

    Error = pGetBestInterfaceEx(Dest, &Index);
    ok(Error == ExpectedError, "%s: error %lu, expected %lu\n", Name, Error, ExpectedError);
    if (ExpectedError == NO_ERROR)
        ok(Index == ExpectedIndex, "%s: interface %lu, expected %lu\n", Name, Index, ExpectedIndex);
    else
        ok(Index == UNSET, "%s: interface written as %lu\n", Name, Index);
}

static void TestArguments(void)
{
    SOCKADDR_IN Dest;
    DWORD Index = UNSET, Error;
    USHORT Families[] = { AF_UNSPEC, AF_UNIX, AF_NETBIOS, 0x1234 };
    char Name[32];
    ULONG i;

    MakeV4(&Dest, htonl(0x08080808));
    Error = pGetBestInterfaceEx(NULL, &Index);
    ok(Error == ERROR_INVALID_PARAMETER, "no destination: %lu\n", Error);
    ok(Index == UNSET, "no destination: interface written as %lu\n", Index);
    Error = pGetBestInterfaceEx((struct sockaddr *)&Dest, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "no output: %lu\n", Error);
    Error = pGetBestInterfaceEx(NULL, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "no destination, no output: %lu\n", Error);

    for (i = 0; i < ARRAYSIZE(Families); i++)
    {
        MakeV4(&Dest, htonl(0x08080808));
        Dest.sin_family = Families[i];
        sprintf(Name, "family %u", Families[i]);
        Expect(Name, (struct sockaddr *)&Dest, ERROR_INVALID_PARAMETER, 0);
    }
}

static void TestLoopback(void)
{
    SOCKADDR_IN Dest;

    if (!HaveLoopback)
    {
        skip("No loopback address\n");
        return;
    }

    MakeV4(&Dest, htonl(INADDR_LOOPBACK));
    Expect("127.0.0.1", (struct sockaddr *)&Dest, NO_ERROR, LoopbackIndex);
    MakeV4(&Dest, htonl(0x7f010203));
    Expect("127.1.2.3", (struct sockaddr *)&Dest, NO_ERROR, LoopbackIndex);
    MakeV4(&Dest, htonl(0x7fffffff));
    Expect("127.255.255.255", (struct sockaddr *)&Dest, NO_ERROR, LoopbackIndex);
}

static void TestAdapter(void)
{
    SOCKADDR_IN Dest;

    MakeV4(&Dest, AdapterAddress);
    Expect("own address", (struct sockaddr *)&Dest, NO_ERROR, AdapterIndex);

    /* the port and the unused bytes do not matter */
    Dest.sin_port = htons(80);
    memset(Dest.sin_zero, 0xaa, sizeof(Dest.sin_zero));
    Expect("own address with a port", (struct sockaddr *)&Dest, NO_ERROR, AdapterIndex);
}

static void ExpectRouted(const char *Name, ULONG Ip, USHORT Port)
{
    SOCKADDR_IN Dest;
    ULONG Index;

    if (!RouteIndex(Ip, &Index))
    {
        skip("%s: the routing table has no route, or two equal ones\n", Name);
        return;
    }
    MakeV4(&Dest, Ip);
    Dest.sin_port = Port;
    Expect(Name, (struct sockaddr *)&Dest, NO_ERROR, Index);
}

static void ExpectUnrouted(const char *Name, ULONG Ip)
{
    SOCKADDR_IN Dest;

    if (SpecificRoutes(Ip))
    {
        skip("%s: a route more specific than the default covers it\n", Name);
        return;
    }
    MakeV4(&Dest, Ip);
    Expect(Name, (struct sockaddr *)&Dest, NO_ERROR, 0);
}

static void TestRoutes(void)
{
    SOCKADDR_IN Dest;
    DWORD Index = UNSET, Error;

    /* the unspecified address, and addresses off the link, follow the best route; so does the adapter's subnet */
    ExpectRouted("0.0.0.0", 0, 0);
    ExpectRouted("8.8.8.8", htonl(0x08080808), 0);
    ExpectRouted("1.2.3.4 with a port", htonl(0x01020304), htons(53));
    ExpectRouted("subnet address", AdapterAddress & AdapterMask, 0);
    ExpectRouted("subnet broadcast", AdapterAddress | ~AdapterMask, 0);
    ExpectRouted("169.253.255.255", htonl(0xa9fdffff), 0);
    ExpectRouted("169.255.0.1", htonl(0xa9ff0001), 0);

    /* a link-local destination does not take the default route, and answers with no interface */
    ExpectUnrouted("169.254.1.1", htonl(0xa9fe0101));
    ExpectUnrouted("169.254.0.0", htonl(0xa9fe0000));
    ExpectUnrouted("169.254.255.255", htonl(0xa9feffff));

    /* the limited broadcast has an interface */
    MakeV4(&Dest, INADDR_NONE);
    Error = pGetBestInterfaceEx((struct sockaddr *)&Dest, &Index);
    ok(Error == NO_ERROR, "255.255.255.255: error %lu\n", Error);
    ok(Error != NO_ERROR || Index != UNSET, "255.255.255.255: no interface\n");
}

static void TestReservedRanges(void)
{
    SOCKADDR_IN Dest;
    static const ULONG Unreachable[] = { 0x00000001, 0x000000ff, 0x00ffffff, 0xf0000000, 0xf0000001, 0xf8000000,
                                         0xffffff00, 0xfffffffe };
    char Name[32];
    ULONG i;

    /* no route, whatever the routing table says: 0.0.0.0/8 but the unspecified address, and class E */
    for (i = 0; i < ARRAYSIZE(Unreachable); i++)
    {
        MakeV4(&Dest, htonl(Unreachable[i]));
        sprintf(Name, "%lu.%lu.%lu.%lu", Unreachable[i] >> 24, (Unreachable[i] >> 16) & 255, (Unreachable[i] >> 8) & 255,
                Unreachable[i] & 255);
        Expect(Name, (struct sockaddr *)&Dest, ERROR_NETWORK_UNREACHABLE, 0);
    }

    /* every computer joins the all-hosts group, which has no interface */
    MakeV4(&Dest, htonl(0xe0000001));
    Expect("224.0.0.1", (struct sockaddr *)&Dest, NO_ERROR, 0);
}

static void TestIpv6(void)
{
    SOCKADDR_IN6 Dest;
    DWORD Index = UNSET, Error;

    /*
     * Without an IPv6 stack, and on Windows with IPv6 and no IPv6 default or global route (also with IPv6
     * disabled), the unspecified address is not found and a global one has no route.
     */
    memset(&Dest, 0, sizeof(Dest));
    Dest.sin6_family = AF_INET6;
    Error = pGetBestInterfaceEx((struct sockaddr *)&Dest, &Index);
    ok(Error == ERROR_NOT_FOUND || (!is_reactos() && Error == NO_ERROR), "::: error %lu\n", Error);
    ok(Error == NO_ERROR || Index == UNSET, "::: interface written as %lu\n", Index);

    Index = UNSET;
    Dest.sin6_addr.u.Word[0] = htons(0x2001);
    Dest.sin6_addr.u.Word[7] = htons(1);
    Error = pGetBestInterfaceEx((struct sockaddr *)&Dest, &Index);
    /* a router advertisement can give the stack an IPv6 default route (IpForwardTable6 tests the routes) */
    ok(Error == ERROR_NETWORK_UNREACHABLE || Error == NO_ERROR, "2001::1: error %lu\n", Error);
    ok(Error == NO_ERROR || Index == UNSET, "2001::1: interface written as %lu\n", Index);
}

START_TEST(GetBestInterfaceEx)
{
    HMODULE hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    WSADATA Wsa;

    pGetBestInterfaceEx = (PGET_BEST_INTERFACE_EX)GetProcAddress(hIphlpapi, "GetBestInterfaceEx");
    ok(pGetBestInterfaceEx != NULL, "GetBestInterfaceEx is not exported\n");
    if (!pGetBestInterfaceEx)
        return;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    FindEnvironment();
    TestArguments();
    TestLoopback();
    TestReservedRanges();
    TestIpv6();
    if (!HaveAdapter)
    {
        skip("No network adapter with an IPv4 address\n");
    }
    else
    {
        TestAdapter();
        TestRoutes();
    }
    free(Routes);
    WSACleanup();
}
