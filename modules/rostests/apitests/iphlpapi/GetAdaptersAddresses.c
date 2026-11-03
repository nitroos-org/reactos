/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the Windows Vista fields of GetAdaptersAddresses
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

#define LOOPBACK_LUID 0x0018000000000000ULL
#define MAX_ADAPTERS 64

static IP_ADAPTER_ADDRESSES_LH *GetAdapters(ULONG Flags)
{
    IP_ADAPTER_ADDRESSES_LH *Adapters = NULL;
    ULONG Size = 0, Tries;
    DWORD Error = ERROR_BUFFER_OVERFLOW;

    for (Tries = 0; Tries < 5 && Error == ERROR_BUFFER_OVERFLOW; Tries++)
    {
        free(Adapters);
        Adapters = Size ? malloc(Size) : NULL;
        Error = GetAdaptersAddresses(AF_UNSPEC, Flags, NULL, (PIP_ADAPTER_ADDRESSES)Adapters, &Size);
    }
    ok(Error == NO_ERROR, "GetAdaptersAddresses: %lu\n", Error);
    if (Error != NO_ERROR)
    {
        free(Adapters);
        return NULL;
    }
    return Adapters;
}

static void TestAdapters(void)
{
    ULONG Flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    IP_ADAPTER_ADDRESSES_LH *Adapters, *Other, *A, *B;
    ULONG Count = 0, Loopbacks = 0;
    MIB_IFROW IfRow;
    DWORD Error;

    Adapters = GetAdapters(Flags);
    if (!Adapters)
        return;

    for (A = Adapters; A; A = A->Next)
    {
        Count++;
        ok(A->Length >= sizeof(IP_ADAPTER_ADDRESSES_LH), "adapter %lu: Length %lu, expected at least %lu\n", A->IfIndex,
           A->Length, (ULONG)sizeof(IP_ADAPTER_ADDRESSES_LH));
        if (A->Length < sizeof(IP_ADAPTER_ADDRESSES_LH))
            continue;

        ok(A->Luid.Value != 0, "adapter %lu: no luid\n", A->IfIndex);

        /* the stack is IPv4: .NET GetIPv4Properties throws NetworkInformationException (WSAEPROTONOSUPPORT)
         * for an adapter without this flag */
        ok((A->Flags & IP_ADAPTER_IPV4_ENABLED) != 0, "adapter %lu: Flags 0x%lx lack IP_ADAPTER_IPV4_ENABLED\n",
           A->IfIndex, A->Flags);
        ok(A->Ipv6IfIndex == 0 || (A->Flags & IP_ADAPTER_IPV6_ENABLED), "adapter %lu: Ipv6IfIndex %lu but Flags 0x%lx\n",
           A->IfIndex, A->Ipv6IfIndex, A->Flags);
        ok(A->Luid.Info.IfType == A->IfType, "adapter %lu: luid type %u, adapter type %lu\n", A->IfIndex,
           A->Luid.Info.IfType, A->IfType);
        ok(A->Luid.Info.Reserved == 0, "adapter %lu: luid reserved bits 0x%lx\n", A->IfIndex,
           (ULONG)A->Luid.Info.Reserved);
        for (B = Adapters; B != A; B = B->Next)
        {
            if (B->Length >= sizeof(IP_ADAPTER_ADDRESSES_LH))
                ok(B->Luid.Value != A->Luid.Value, "adapters %lu and %lu share the luid 0x%I64x\n", B->IfIndex,
                   A->IfIndex, (ULONGLONG)A->Luid.Value);
        }

        memset(&IfRow, 0, sizeof(IfRow));
        IfRow.dwIndex = A->IfIndex;
        Error = GetIfEntry(&IfRow);
        ok(Error == NO_ERROR, "adapter %lu: GetIfEntry %lu\n", A->IfIndex, Error);
        ok(Error != NO_ERROR || IfRow.dwType == A->IfType, "adapter %lu: GetIfEntry type %lu, adapter type %lu\n",
           A->IfIndex, IfRow.dwType, A->IfType);

        if (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            Loopbacks++;
            ok(A->Luid.Value == LOOPBACK_LUID, "loopback: luid 0x%I64x\n", (ULONGLONG)A->Luid.Value);
            ok(A->IfIndex == 1, "loopback: index %lu\n", A->IfIndex);
        }
    }
    ok(Count != 0, "no adapters\n");
    ok(Loopbacks == 1, "%lu loopback adapters\n", Loopbacks);

    /* the luid belongs to the interface, not to what was asked for */
    Other = GetAdapters(GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_FRIENDLY_NAME);
    for (A = Adapters; Other && A; A = A->Next)
    {
        for (B = Other; B && B->IfIndex != A->IfIndex; B = B->Next)
            ;
        ok(B != NULL, "adapter %lu is missing with other flags\n", A->IfIndex);
        if (B && A->Length >= sizeof(IP_ADAPTER_ADDRESSES_LH) && B->Length >= sizeof(IP_ADAPTER_ADDRESSES_LH))
            ok(B->Luid.Value == A->Luid.Value, "adapter %lu: luid 0x%I64x, with other flags 0x%I64x\n", A->IfIndex,
               (ULONGLONG)A->Luid.Value, (ULONGLONG)B->Luid.Value);
    }
    free(Other);
    free(Adapters);
}

static void TestLoopbackIndex(void)
{
    IP_ADAPTER_ADDRESSES_LH *Adapters, *A;
    MIB_IPADDRTABLE *Addresses;
    ULONG Size = 0, i, Index = 0;
    BOOL Have = FALSE;

    GetIpAddrTable(NULL, &Size, FALSE);
    Addresses = malloc(Size);
    if (!Addresses || GetIpAddrTable(Addresses, &Size, FALSE) != NO_ERROR)
    {
        free(Addresses);
        skip("No address table\n");
        return;
    }
    for (i = 0; i < Addresses->dwNumEntries; i++)
    {
        if (Addresses->table[i].dwAddr == htonl(INADDR_LOOPBACK))
        {
            Index = Addresses->table[i].dwIndex;
            Have = TRUE;
        }
    }
    free(Addresses);
    if (!Have)
    {
        skip("No loopback address\n");
        return;
    }

    /* the interface that owns 127.0.0.1 is the loopback interface of GetAdaptersAddresses */
    Adapters = GetAdapters(GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER);
    for (A = Adapters; A; A = A->Next)
    {
        if (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            ok(A->IfIndex == Index, "loopback adapter index %lu, 127.0.0.1 is on interface %lu\n", A->IfIndex, Index);
    }
    free(Adapters);
}

static BOOL HasGateway(const IP_ADAPTER_ADDRESSES_LH *Adapter, ULONG Address)
{
    const IP_ADAPTER_GATEWAY_ADDRESS_LH *Gateway;

    for (Gateway = Adapter->FirstGatewayAddress; Gateway; Gateway = Gateway->Next)
    {
        if (Gateway->Address.lpSockaddr && Gateway->Address.lpSockaddr->sa_family == AF_INET &&
            ((SOCKADDR_IN *)Gateway->Address.lpSockaddr)->sin_addr.S_un.S_addr == Address)
            return TRUE;
    }
    return FALSE;
}

static void TestGatewayList(ULONG Flags, const MIB_IPFORWARDTABLE *Routes)
{
    IP_ADAPTER_ADDRESSES_LH *Adapters, *A;
    IP_ADAPTER_GATEWAY_ADDRESS_LH *G, *H;
    ULONG i;

    Adapters = GetAdapters(Flags);
    if (!Adapters)
        return;

    for (A = Adapters; A; A = A->Next)
    {
        ULONG Count = 0;

        for (G = A->FirstGatewayAddress; G; G = G->Next)
        {
            Count++;
            ok(G->Length >= sizeof(IP_ADAPTER_GATEWAY_ADDRESS_LH), "flags 0x%lx, adapter %lu: gateway Length %lu\n",
               Flags, A->IfIndex, G->Length);
            ok(G->Address.lpSockaddr != NULL, "flags 0x%lx, adapter %lu: gateway without address\n", Flags,
               A->IfIndex);
            if (!G->Address.lpSockaddr)
                continue;

            ok(A->IfType != IF_TYPE_SOFTWARE_LOOPBACK, "flags 0x%lx: the loopback adapter has a gateway\n", Flags);
            if (G->Address.lpSockaddr->sa_family != AF_INET)
                continue;

            ok(G->Address.iSockaddrLength == sizeof(SOCKADDR_IN), "flags 0x%lx, adapter %lu: gateway address length %d\n",
               Flags, A->IfIndex, G->Address.iSockaddrLength);
            ok(((SOCKADDR_IN *)G->Address.lpSockaddr)->sin_port == 0, "flags 0x%lx, adapter %lu: gateway port %u\n",
               Flags, A->IfIndex, ((SOCKADDR_IN *)G->Address.lpSockaddr)->sin_port);
            ok(((SOCKADDR_IN *)G->Address.lpSockaddr)->sin_addr.S_un.S_addr != 0, "flags 0x%lx, adapter %lu: gateway 0.0.0.0\n",
               Flags, A->IfIndex);

            /* the gateways of an adapter are all different */
            for (H = A->FirstGatewayAddress; H != G; H = H->Next)
            {
                ok(H->Address.lpSockaddr->sa_family != AF_INET ||
                   ((SOCKADDR_IN *)H->Address.lpSockaddr)->sin_addr.S_un.S_addr !=
                   ((SOCKADDR_IN *)G->Address.lpSockaddr)->sin_addr.S_un.S_addr,
                   "flags 0x%lx, adapter %lu: gateway listed twice\n", Flags, A->IfIndex);
            }

            /* ... and each is the next hop of a default route of the interface */
            for (i = 0; i < Routes->dwNumEntries; i++)
            {
                if (Routes->table[i].dwForwardDest == 0 && Routes->table[i].dwForwardMask == 0 &&
                    Routes->table[i].dwForwardIfIndex == A->IfIndex &&
                    Routes->table[i].dwForwardNextHop == ((SOCKADDR_IN *)G->Address.lpSockaddr)->sin_addr.S_un.S_addr)
                    break;
            }
            ok(i < Routes->dwNumEntries, "flags 0x%lx, adapter %lu: gateway %s is no default route\n", Flags,
               A->IfIndex, inet_ntoa(((SOCKADDR_IN *)G->Address.lpSockaddr)->sin_addr));
        }

        if (!(Flags & GAA_FLAG_INCLUDE_GATEWAYS))
        {
            ok(Count == 0, "flags 0x%lx, adapter %lu: %lu gateways without GAA_FLAG_INCLUDE_GATEWAYS\n", Flags,
               A->IfIndex, Count);
            continue;
        }

        /* every default route that leaves through a router is a gateway of its interface */
        for (i = 0; i < Routes->dwNumEntries; i++)
        {
            const MIB_IPFORWARDROW *Route = &Routes->table[i];

            if (Route->dwForwardDest != 0 || Route->dwForwardMask != 0 || Route->dwForwardNextHop == 0 ||
                Route->dwForwardIfIndex != A->IfIndex)
                continue;
            ok(HasGateway(A, Route->dwForwardNextHop), "flags 0x%lx, adapter %lu: no gateway for the default route via %s\n",
               Flags, A->IfIndex, inet_ntoa(*(struct in_addr *)&Route->dwForwardNextHop));
        }
    }
    free(Adapters);
}

static void TestGateways(void)
{
    MIB_IPFORWARDTABLE *Routes;
    IP_ADAPTER_INFO *Info = NULL, *I;
    IP_ADAPTER_ADDRESSES_LH *Adapters, *A;
    ULONG Size = 0, i, Defaults = 0;
    DWORD Error;

    GetIpForwardTable(NULL, &Size, FALSE);
    Routes = malloc(Size);
    if (!Routes || GetIpForwardTable(Routes, &Size, FALSE) != NO_ERROR)
    {
        free(Routes);
        skip("No route table\n");
        return;
    }
    for (i = 0; i < Routes->dwNumEntries; i++)
    {
        if (Routes->table[i].dwForwardDest == 0 && Routes->table[i].dwForwardMask == 0 &&
            Routes->table[i].dwForwardNextHop != 0)
            Defaults++;
    }

    TestGatewayList(0, Routes);
    TestGatewayList(GAA_FLAG_INCLUDE_GATEWAYS, Routes);
    TestGatewayList(GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
                    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, Routes);
    TestGatewayList(GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_WINS_INFO |
                    GAA_FLAG_INCLUDE_ALL_INTERFACES, Routes);

    if (!Defaults)
    {
        free(Routes);
        skip("No default route\n");
        return;
    }

    /* the first gateway is the one of GetAdaptersInfo */
    Size = 0;
    Error = GetAdaptersInfo(NULL, &Size);
    if (Error == ERROR_BUFFER_OVERFLOW)
    {
        Info = malloc(Size);
        Error = Info ? GetAdaptersInfo(Info, &Size) : ERROR_OUTOFMEMORY;
    }
    Adapters = GetAdapters(GAA_FLAG_INCLUDE_GATEWAYS);
    for (I = Error == NO_ERROR ? Info : NULL; I && Adapters; I = I->Next)
    {
        for (A = Adapters; A && strcmp(A->AdapterName, I->AdapterName); A = A->Next)
            ;
        if (!A || I->GatewayList.IpAddress.String[0] == '0' || !I->GatewayList.IpAddress.String[0])
            continue;
        ok(A->FirstGatewayAddress != NULL &&
           A->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET &&
           !strcmp(inet_ntoa(((SOCKADDR_IN *)A->FirstGatewayAddress->Address.lpSockaddr)->sin_addr),
                   I->GatewayList.IpAddress.String),
           "adapter %s: GetAdaptersInfo gateway %s, GetAdaptersAddresses %s\n", I->AdapterName,
           I->GatewayList.IpAddress.String,
           A->FirstGatewayAddress ? "another one" : "none");
    }
    free(Adapters);
    free(Info);
    free(Routes);
}

/* The number of leading one bits of a mask in host order */
static ULONG PrefixOfMask(ULONG Mask)
{
    ULONG Bits = 0;

    while (Bits < 32 && (Mask & (0x80000000UL >> Bits)))
        Bits++;
    return Bits;
}

/* The fields .NET reads: OnLinkPrefixLength gives UnicastIPAddressInformation.IPv4Mask / PrefixLength, Mtu and
 * the speeds give the interface properties, the flags tell which interface properties exist */
static void TestPrefixMtuFlags(void)
{
    IP_ADAPTER_ADDRESSES_LH *Adapters, *A;
    IP_ADAPTER_UNICAST_ADDRESS_LH *U;
    MIB_IPADDRTABLE *Addresses;
    ULONG Size = 0, i;

    GetIpAddrTable(NULL, &Size, FALSE);
    Addresses = malloc(Size);
    if (!Addresses || GetIpAddrTable(Addresses, &Size, FALSE) != NO_ERROR)
    {
        free(Addresses);
        skip("No address table\n");
        return;
    }

    Adapters = GetAdapters(GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER);
    for (A = Adapters; A; A = A->Next)
    {
        if (A->Length < sizeof(IP_ADAPTER_ADDRESSES_LH))
            continue;

        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            ULONG Address, Expected = 0;
            BOOL Found = FALSE;

            if (!U->Address.lpSockaddr || U->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            Address = ((SOCKADDR_IN *)U->Address.lpSockaddr)->sin_addr.S_un.S_addr;

            for (i = 0; i < Addresses->dwNumEntries; i++)
            {
                if (Addresses->table[i].dwAddr == Address && Addresses->table[i].dwIndex == A->IfIndex)
                {
                    Found = TRUE;
                    Expected = PrefixOfMask(ntohl(Addresses->table[i].dwMask));
                }
            }
            if (!Found)
                continue;

            /* Windows 10: 24 for the Ethernet address of a /24, 8 for 127.0.0.1 (read as 0 by .NET: mask 0.0.0.0) */
            ok(Expected != 0, "adapter %lu: the address table has no mask for %s\n", A->IfIndex,
               inet_ntoa(((SOCKADDR_IN *)U->Address.lpSockaddr)->sin_addr));
            ok(U->OnLinkPrefixLength == Expected, "adapter %lu, %s: OnLinkPrefixLength %u, the mask of GetIpAddrTable has %lu bits\n",
               A->IfIndex, inet_ntoa(((SOCKADDR_IN *)U->Address.lpSockaddr)->sin_addr), U->OnLinkPrefixLength, Expected);
            if (Address == htonl(INADDR_LOOPBACK))
                ok(U->OnLinkPrefixLength == 8, "loopback: OnLinkPrefixLength %u\n", U->OnLinkPrefixLength);
        }

        if (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            /* Windows 10 measured: Flags 0x181 (IPv6 enabled, IPv4 enabled, DDNS), Mtu 4294967295, 1 Gbit/s */
            ok((A->Flags & IP_ADAPTER_DDNS_ENABLED) != 0, "loopback: Flags 0x%lx lack IP_ADAPTER_DDNS_ENABLED\n", A->Flags);
            ok(A->Mtu == 0xFFFFFFFFUL, "loopback: Mtu %lu\n", A->Mtu);
            ok(A->TransmitLinkSpeed == 1073741824ULL, "loopback: TransmitLinkSpeed %I64u\n", (ULONGLONG)A->TransmitLinkSpeed);
            ok(A->ReceiveLinkSpeed == 1073741824ULL, "loopback: ReceiveLinkSpeed %I64u\n", (ULONGLONG)A->ReceiveLinkSpeed);
        }
        else if (A->OperStatus == IfOperStatusUp)
        {
            ok(A->Mtu != 0 && A->Mtu != 0xFFFFFFFFUL, "adapter %lu: Mtu %lu\n", A->IfIndex, A->Mtu);
            ok(A->TransmitLinkSpeed != 0 && A->ReceiveLinkSpeed != 0, "adapter %lu: link speed %I64u / %I64u\n", A->IfIndex,
               (ULONGLONG)A->TransmitLinkSpeed, (ULONGLONG)A->ReceiveLinkSpeed);
        }
    }
    free(Adapters);

    /* the mask of GetAdaptersInfo agrees with the prefix of the same address */
    {
        IP_ADAPTER_INFO *Info = NULL, *I;
        IP_ADDR_STRING *Ip;

        Size = 0;
        if (GetAdaptersInfo(NULL, &Size) == ERROR_BUFFER_OVERFLOW && (Info = malloc(Size)) != NULL &&
            GetAdaptersInfo(Info, &Size) == NO_ERROR)
        {
            Adapters = GetAdapters(GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER);
            for (I = Info; I; I = I->Next)
            {
                for (A = Adapters; A && strcmp(A->AdapterName, I->AdapterName); A = A->Next)
                    ;
                for (Ip = &I->IpAddressList; A && Ip; Ip = Ip->Next)
                {
                    ULONG Mask = inet_addr(Ip->IpMask.String), Addr = inet_addr(Ip->IpAddress.String);

                    if (Mask == INADDR_NONE || Addr == 0)
                        continue;
                    for (U = A->FirstUnicastAddress; U; U = U->Next)
                    {
                        if (U->Address.lpSockaddr && U->Address.lpSockaddr->sa_family == AF_INET &&
                            ((SOCKADDR_IN *)U->Address.lpSockaddr)->sin_addr.S_un.S_addr == Addr)
                            ok(U->OnLinkPrefixLength == PrefixOfMask(ntohl(Mask)),
                               "%s: OnLinkPrefixLength %u, GetAdaptersInfo mask %s\n", Ip->IpAddress.String,
                               U->OnLinkPrefixLength, Ip->IpMask.String);
                    }
                }
            }
            free(Adapters);
        }
        free(Info);
    }
    free(Addresses);
}

START_TEST(GetAdaptersAddresses)
{
    WSADATA Wsa;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    TestAdapters();
    TestLoopbackIndex();
    TestGateways();
    TestPrefixMtuFlags();
    WSACleanup();
}
