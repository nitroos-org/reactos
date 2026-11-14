/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What iphlpapi reports about IPv6: nothing while the stack has IPv6 off (the answers of a system
 *              without IPv6), and with Tcpip\Parameters\Ipv6Enable set the addresses, flags and interface rows
 *              the way a Windows 10 22H2 system reports them for the loopback interface and an Ethernet adapter
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

/* The rows of the Windows SDK, under private names: the headers of this tree do not declare them. */
typedef struct
{
    SOCKADDR_INET Address;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    ULONG PrefixOrigin;
    ULONG SuffixOrigin;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    UCHAR OnLinkPrefixLength;
    BOOLEAN SkipAsSource;
    ULONG DadState;
    ULONG ScopeId;
    LARGE_INTEGER CreationTimeStamp;
} UNICAST_ROW;

typedef struct
{
    ULONG NumEntries;
    UNICAST_ROW Table[1];
} UNICAST_TABLE;

typedef struct
{
    USHORT Family;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    ULONG MaxReassemblySize;
    ULONG64 InterfaceIdentifier;
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

typedef struct
{
    ULONG NumEntries;
    IPIF_ROW Table[1];
} IPIF_TABLE;

typedef DWORD (WINAPI *PGET_UNICAST_TABLE)(USHORT, UNICAST_TABLE **);
typedef DWORD (WINAPI *PGET_UNICAST_ENTRY)(UNICAST_ROW *);
typedef DWORD (WINAPI *PGET_IPIF_TABLE)(USHORT, IPIF_TABLE **);
typedef DWORD (WINAPI *PGET_IPIF_ENTRY)(IPIF_ROW *);
typedef VOID (WINAPI *PFREE_MIB_TABLE)(PVOID);

static PGET_UNICAST_TABLE pGetUnicastIpAddressTable;
static PGET_UNICAST_ENTRY pGetUnicastIpAddressEntry;
static PGET_IPIF_TABLE pGetIpInterfaceTable;
static PGET_IPIF_ENTRY pGetIpInterfaceEntry;
static PFREE_MIB_TABLE pFreeMibTable;

/* NL_DAD_STATE, NL_PREFIX_ORIGIN, NL_SUFFIX_ORIGIN, NL_LINK_LOCAL_ADDRESS_BEHAVIOR, NL_ROUTER_DISCOVERY_BEHAVIOR */
#define DAD_TENTATIVE   1
#define DAD_DEPRECATED  3
#define DAD_PREFERRED   4
#define PREFIX_WELLKNOWN 2
#define SUFFIX_WELLKNOWN 2
#define SUFFIX_LINKLAYER 4
#define LINKLOCAL_ALWAYS_ON 2
#define ROUTER_DISCOVERY_ENABLED 1

#define IPV6_ENABLED_FLAG 0x100
#define IPV4_ENABLED_FLAG 0x80

static BOOL Ipv6On;

/* The switch the stack was started with is what Tcpip\Parameters\Ipv6Enable says at boot; the test reads the same
   value (it is not changed while the system runs) */
static BOOL ReadSwitch(void)
{
    HKEY Key;
    DWORD Value = 0, Size = sizeof(Value), Type = 0;
    BOOL On = FALSE;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 0, KEY_READ, &Key) ==
        ERROR_SUCCESS)
    {
        if (RegQueryValueExA(Key, "Ipv6Enable", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Value != 0)
            On = TRUE;
        RegCloseKey(Key);
    }
    return On;
}

static BOOL IsLinkLocal(const SOCKADDR_IN6 *A)
{
    return A->sin6_addr.s6_addr[0] == 0xFE && (A->sin6_addr.s6_addr[1] & 0xC0) == 0x80;
}

static BOOL IsLoopback6(const SOCKADDR_IN6 *A)
{
    static const UCHAR Loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    return !memcmp(&A->sin6_addr, Loopback, 16);
}

static IP_ADAPTER_ADDRESSES *GetAdapters(ULONG Family, ULONG Flags, DWORD *Result)
{
    IP_ADAPTER_ADDRESSES *Buffer = NULL;
    ULONG Size = 0, Try;

    *Result = ERROR_BUFFER_OVERFLOW;
    for (Try = 0; Try < 4 && *Result == ERROR_BUFFER_OVERFLOW; Try++)
    {
        free(Buffer);
        Buffer = Size ? malloc(Size) : NULL;
        if (Size && !Buffer)
            return NULL;
        *Result = GetAdaptersAddresses(Family, Flags, NULL, Buffer, &Size);
    }
    if (*Result != NO_ERROR)
    {
        free(Buffer);
        return NULL;
    }
    return Buffer;
}

static ULONG CountFamily(const IP_ADAPTER_ADDRESSES *A, int Family)
{
    const IP_ADAPTER_UNICAST_ADDRESS *U;
    ULONG Count = 0;

    for (U = A->FirstUnicastAddress; U; U = U->Next)
        if (U->Address.lpSockaddr && U->Address.lpSockaddr->sa_family == Family)
            Count++;
    return Count;
}

/* DAD takes about a second and a half: wait until the addresses of the interfaces have left tentative */
static void WaitForDad(void)
{
    ULONG Try;

    for (Try = 0; Try < 30; Try++)
    {
        UNICAST_TABLE *Table = NULL;
        ULONG i, Tentative = 0;

        if (pGetUnicastIpAddressTable(AF_INET6, &Table) != NO_ERROR || !Table)
            return;
        for (i = 0; i < Table->NumEntries; i++)
            if (Table->Table[i].DadState == DAD_TENTATIVE)
                Tentative++;
        pFreeMibTable(Table);
        if (!Tentative)
            return;
        Sleep(500);
    }
}

static void TestOff(void)
{
    IP_ADAPTER_ADDRESSES *Adapters, *A;
    UNICAST_TABLE *Table = (UNICAST_TABLE *)(ULONG_PTR)0x12345678;
    IPIF_TABLE *IfTable = (IPIF_TABLE *)(ULONG_PTR)0x12345678;
    IPIF_ROW Row;
    DWORD Result, Error;
    ULONG i;

    /* Family IPv6 has nothing to say, and the other families list IPv4 only */
    Adapters = GetAdapters(AF_INET6, 0, &Result);
    ok(Result == ERROR_NO_DATA, "GetAdaptersAddresses(AF_INET6): %lu\n", Result);
    ok(Adapters == NULL, "GetAdaptersAddresses(AF_INET6): adapters\n");

    for (i = 0; i < 2; i++)
    {
        Adapters = GetAdapters(i ? AF_INET : AF_UNSPEC, 0, &Result);
        ok(Result == NO_ERROR, "GetAdaptersAddresses(%lu): %lu\n", i ? (ULONG)AF_INET : (ULONG)AF_UNSPEC, Result);
        for (A = Adapters; A; A = A->Next)
        {
            ok(!(A->Flags & IPV6_ENABLED_FLAG), "adapter %lu: flags 0x%lx\n", A->IfIndex, A->Flags);
            ok(A->Ipv6IfIndex == 0, "adapter %lu: Ipv6IfIndex %lu\n", A->IfIndex, A->Ipv6IfIndex);
            ok(CountFamily(A, AF_INET6) == 0, "adapter %lu: IPv6 addresses\n", A->IfIndex);
        }
        free(Adapters);
    }

    Error = pGetUnicastIpAddressTable(AF_INET6, &Table);
    ok(Error == NO_ERROR, "GetUnicastIpAddressTable(AF_INET6): %lu\n", Error);
    ok(Table && Table != (UNICAST_TABLE *)(ULONG_PTR)0x12345678 && Table->NumEntries == 0,
       "GetUnicastIpAddressTable(AF_INET6): %lu rows\n", Table ? Table->NumEntries : 0xdead);
    if (Table && Table != (UNICAST_TABLE *)(ULONG_PTR)0x12345678)
        pFreeMibTable(Table);

    Table = NULL;
    Error = pGetUnicastIpAddressTable(AF_UNSPEC, &Table);
    ok(Error == NO_ERROR && Table, "GetUnicastIpAddressTable(AF_UNSPEC): %lu\n", Error);
    for (i = 0; Table && i < Table->NumEntries; i++)
        ok(Table->Table[i].Address.si_family == AF_INET, "row %lu: family %u\n", i, Table->Table[i].Address.si_family);
    if (Table)
        pFreeMibTable(Table);

    Error = pGetIpInterfaceTable(AF_INET6, &IfTable);
    ok(Error == NO_ERROR, "GetIpInterfaceTable(AF_INET6): %lu\n", Error);
    ok(IfTable && IfTable != (IPIF_TABLE *)(ULONG_PTR)0x12345678 && IfTable->NumEntries == 0,
       "GetIpInterfaceTable(AF_INET6): %lu rows\n", IfTable ? IfTable->NumEntries : 0xdead);
    if (IfTable && IfTable != (IPIF_TABLE *)(ULONG_PTR)0x12345678)
        pFreeMibTable(IfTable);

    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET6;
    Row.InterfaceIndex = 1;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "GetIpInterfaceEntry(AF_INET6, loopback): %lu\n", Error);
}

static void CheckLoopbackRow(const UNICAST_ROW *R)
{
    ok(R->Address.Ipv6.sin6_scope_id == 0, "::1: sin6_scope_id %lu\n", R->Address.Ipv6.sin6_scope_id);
    ok(R->ScopeId == 0, "::1: ScopeId %lu\n", R->ScopeId);
    ok(R->OnLinkPrefixLength == 128, "::1: prefix length %u\n", R->OnLinkPrefixLength);
    ok(R->PrefixOrigin == PREFIX_WELLKNOWN, "::1: PrefixOrigin %lu\n", R->PrefixOrigin);
    ok(R->SuffixOrigin == SUFFIX_WELLKNOWN, "::1: SuffixOrigin %lu\n", R->SuffixOrigin);
    ok(R->DadState == DAD_PREFERRED, "::1: DadState %lu\n", R->DadState);
    ok(R->ValidLifetime == 0xFFFFFFFF && R->PreferredLifetime == 0xFFFFFFFF, "::1: lifetimes %lu/%lu\n",
       R->ValidLifetime, R->PreferredLifetime);
    ok(R->SkipAsSource == 0, "::1: SkipAsSource\n");
}

static void CheckLinkLocalRow(const UNICAST_ROW *R)
{
    ok(R->Address.Ipv6.sin6_scope_id == R->InterfaceIndex, "fe80: sin6_scope_id %lu, interface %lu\n",
       R->Address.Ipv6.sin6_scope_id, R->InterfaceIndex);
    ok(R->ScopeId == R->InterfaceIndex, "fe80: ScopeId %lu, interface %lu\n", R->ScopeId, R->InterfaceIndex);
    ok(R->OnLinkPrefixLength == 64, "fe80: prefix length %u\n", R->OnLinkPrefixLength);
    ok(R->PrefixOrigin == PREFIX_WELLKNOWN, "fe80: PrefixOrigin %lu\n", R->PrefixOrigin);
    ok(R->SuffixOrigin == SUFFIX_LINKLAYER, "fe80: SuffixOrigin %lu\n", R->SuffixOrigin);
    ok(R->DadState == DAD_PREFERRED || R->DadState == DAD_DEPRECATED, "fe80: DadState %lu\n", R->DadState);
    ok(R->ValidLifetime == 0xFFFFFFFF && R->PreferredLifetime == 0xFFFFFFFF, "fe80: lifetimes %lu/%lu\n",
       R->ValidLifetime, R->PreferredLifetime);
}

static void TestOn(void)
{
    IP_ADAPTER_ADDRESSES *All, *V6, *V4, *A, *B;
    UNICAST_TABLE *Table = NULL, *Table6 = NULL, *Table4 = NULL;
    IPIF_TABLE *IfTable = NULL;
    ULONG i, k, LoopbackV6 = 0, LinkLocals = 0, V6Adapters = 0;
    DWORD Error, Result;

    WaitForDad();

    All = GetAdapters(AF_UNSPEC, 0, &Result);
    ok(Result == NO_ERROR && All, "GetAdaptersAddresses(AF_UNSPEC): %lu\n", Result);
    V6 = GetAdapters(AF_INET6, 0, &Result);
    ok(Result == NO_ERROR && V6, "GetAdaptersAddresses(AF_INET6): %lu\n", Result);
    V4 = GetAdapters(AF_INET, 0, &Result);
    ok(Result == NO_ERROR && V4, "GetAdaptersAddresses(AF_INET): %lu\n", Result);
    if (!All || !V6 || !V4)
        goto Done;

    /* The flags and the interface index of IPv6 do not depend on the family that was asked for */
    for (A = V4; A; A = A->Next)
    {
        for (B = All; B && B->IfIndex != A->IfIndex; B = B->Next)
            ;
        ok(B != NULL, "adapter %lu is missing from AF_UNSPEC\n", A->IfIndex);
        if (B)
        {
            ok(A->Flags == B->Flags, "adapter %lu: flags 0x%lx / 0x%lx\n", A->IfIndex, A->Flags, B->Flags);
            ok(A->Ipv6IfIndex == B->Ipv6IfIndex, "adapter %lu: Ipv6IfIndex %lu / %lu\n", A->IfIndex,
               A->Ipv6IfIndex, B->Ipv6IfIndex);
        }
        ok(CountFamily(A, AF_INET6) == 0, "adapter %lu: AF_INET lists IPv6 addresses\n", A->IfIndex);
    }

    V6Adapters = 0;
    for (A = All; A; A = A->Next)
    {
        const IP_ADAPTER_UNICAST_ADDRESS *U;
        BOOL SeenV4 = FALSE;
        BOOL Loopback = (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

        ok((A->Flags & IPV4_ENABLED_FLAG) != 0, "adapter %lu: flags 0x%lx lack IPv4\n", A->IfIndex, A->Flags);
        if (!(A->Flags & IPV6_ENABLED_FLAG))
        {
            ok(A->Ipv6IfIndex == 0, "adapter %lu: Ipv6IfIndex %lu without the flag\n", A->IfIndex, A->Ipv6IfIndex);
            ok(CountFamily(A, AF_INET6) == 0, "adapter %lu: IPv6 addresses without the flag\n", A->IfIndex);
            continue;
        }
        V6Adapters++;
        ok(A->Ipv6IfIndex == A->IfIndex, "adapter %lu: Ipv6IfIndex %lu\n", A->IfIndex, A->Ipv6IfIndex);

        /* Windows 10: the interface index for the interface and link scopes, 1 for the wider ones, 0 for the
           unused level 14 */
        for (i = 0; i < 16; i++)
        {
            ULONG Expected = (i < 4) ? A->IfIndex : (i == 14 ? 0 : 1);
            ok(A->ZoneIndices[i] == Expected, "adapter %lu: ZoneIndices[%lu] = %lu\n", A->IfIndex, i,
               A->ZoneIndices[i]);
        }

        /* the IPv6 addresses come first, then the IPv4 ones */
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            int Family = U->Address.lpSockaddr ? U->Address.lpSockaddr->sa_family : 0;

            if (Family == AF_INET)
                SeenV4 = TRUE;
            else if (Family == AF_INET6)
            {
                const SOCKADDR_IN6 *S = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;

                ok(!SeenV4, "adapter %lu: an IPv6 address after an IPv4 one\n", A->IfIndex);
                ok(U->Address.iSockaddrLength == sizeof(SOCKADDR_IN6), "adapter %lu: sockaddr length %d\n",
                   A->IfIndex, U->Address.iSockaddrLength);
                ok(U->Length >= sizeof(IP_ADAPTER_UNICAST_ADDRESS), "adapter %lu: Length %lu\n", A->IfIndex,
                   U->Length);
                ok(S->sin6_port == 0 && S->sin6_flowinfo == 0, "adapter %lu: port/flow\n", A->IfIndex);
                if (Loopback)
                {
                    ok(IsLoopback6(S), "loopback adapter has an IPv6 address that is not ::1\n");
                    LoopbackV6++;
                    ok(U->OnLinkPrefixLength == 128, "::1: prefix %u\n", U->OnLinkPrefixLength);
                    ok(U->PrefixOrigin == PREFIX_WELLKNOWN && U->SuffixOrigin == SUFFIX_WELLKNOWN,
                       "::1: origins %d/%d\n", U->PrefixOrigin, U->SuffixOrigin);
                    ok(U->DadState == DAD_PREFERRED, "::1: DadState %d\n", U->DadState);
                    ok(S->sin6_scope_id == 0, "::1: scope %lu\n", S->sin6_scope_id);
                }
                else if (IsLinkLocal(S))
                {
                    LinkLocals++;
                    ok(S->sin6_scope_id == A->IfIndex, "fe80: scope %lu, adapter %lu\n", S->sin6_scope_id, A->IfIndex);
                    ok(U->OnLinkPrefixLength == 64, "fe80: prefix %u\n", U->OnLinkPrefixLength);
                    ok(U->PrefixOrigin == PREFIX_WELLKNOWN && U->SuffixOrigin == SUFFIX_LINKLAYER,
                       "fe80: origins %d/%d\n", U->PrefixOrigin, U->SuffixOrigin);
                    ok(U->DadState == DAD_PREFERRED || U->DadState == DAD_DEPRECATED, "fe80: DadState %d\n",
                       U->DadState);
                    ok(U->ValidLifetime == 0xFFFFFFFF && U->PreferredLifetime == 0xFFFFFFFF, "fe80: lifetimes\n");
                    ok(U->Flags == 0, "fe80: Flags 0x%lx\n", U->Flags);
                }
            }
        }
    }
    ok(V6Adapters != 0, "no adapter has IPv6\n");
    ok(LoopbackV6 == 1, "%lu ::1 addresses on the loopback interface\n", LoopbackV6);

    /* Family IPv6 lists the IPv6 addresses and no IPv4 one, no IPv4 name server */
    for (A = V6; A; A = A->Next)
    {
        const IP_ADAPTER_DNS_SERVER_ADDRESS *D;

        ok(CountFamily(A, AF_INET) == 0, "adapter %lu: AF_INET6 lists IPv4 addresses\n", A->IfIndex);
        for (D = A->FirstDnsServerAddress; D; D = D->Next)
            ok(D->Address.lpSockaddr && D->Address.lpSockaddr->sa_family == AF_INET6,
               "adapter %lu: AF_INET6 lists an IPv4 name server\n", A->IfIndex);
    }

    /* The table of unicast addresses: the IPv4 rows first, then the IPv6 ones, as GetAdaptersAddresses has them */
    Error = pGetUnicastIpAddressTable(AF_UNSPEC, &Table);
    ok(Error == NO_ERROR && Table, "GetUnicastIpAddressTable(AF_UNSPEC): %lu\n", Error);
    Error = pGetUnicastIpAddressTable(AF_INET6, &Table6);
    ok(Error == NO_ERROR && Table6, "GetUnicastIpAddressTable(AF_INET6): %lu\n", Error);
    Error = pGetUnicastIpAddressTable(AF_INET, &Table4);
    ok(Error == NO_ERROR && Table4, "GetUnicastIpAddressTable(AF_INET): %lu\n", Error);
    if (Table && Table6 && Table4)
    {
        BOOL SeenV6 = FALSE;
        ULONG Rows6 = 0, Loop = 0, Link = 0;

        ok(Table->NumEntries == Table4->NumEntries + Table6->NumEntries, "rows %lu, IPv4 %lu, IPv6 %lu\n",
           Table->NumEntries, Table4->NumEntries, Table6->NumEntries);
        for (i = 0; i < Table->NumEntries; i++)
        {
            if (Table->Table[i].Address.si_family == AF_INET6)
                SeenV6 = TRUE;
            else
                ok(!SeenV6, "row %lu: an IPv4 row after an IPv6 one\n", i);
        }
        for (i = 0; i < Table6->NumEntries; i++)
        {
            const UNICAST_ROW *R = &Table6->Table[i];

            ok(R->Address.si_family == AF_INET6, "IPv6 table: row %lu has family %u\n", i, R->Address.si_family);
            ok(R->InterfaceLuid.Value != 0 && R->InterfaceIndex != 0, "row %lu: no interface\n", i);
            Rows6++;
            if (IsLoopback6(&R->Address.Ipv6))
            {
                Loop++;
                CheckLoopbackRow(R);
            }
            else if (IsLinkLocal(&R->Address.Ipv6))
            {
                Link++;
                CheckLinkLocalRow(R);
            }

            /* the same address is in the adapter list, on the same interface */
            for (A = All; A; A = A->Next)
            {
                const IP_ADAPTER_UNICAST_ADDRESS *U;
                BOOL Found = FALSE;

                if (A->IfIndex != R->InterfaceIndex)
                    continue;
                for (U = A->FirstUnicastAddress; U && !Found; U = U->Next)
                    if (U->Address.lpSockaddr && U->Address.lpSockaddr->sa_family == AF_INET6 &&
                        !memcmp(&((SOCKADDR_IN6 *)U->Address.lpSockaddr)->sin6_addr, &R->Address.Ipv6.sin6_addr, 16))
                        Found = TRUE;
                ok(Found, "row %lu: not in the list of adapter %lu\n", i, A->IfIndex);
            }

            /* the entry getter agrees */
            if (pGetUnicastIpAddressEntry)
            {
                UNICAST_ROW One;

                memset(&One, 0, sizeof(One));
                One.Address = R->Address;
                One.InterfaceIndex = R->InterfaceIndex;
                Error = pGetUnicastIpAddressEntry(&One);
                ok(Error == NO_ERROR, "GetUnicastIpAddressEntry(row %lu): %lu\n", i, Error);
                if (Error == NO_ERROR)
                {
                    ok(One.InterfaceLuid.Value == R->InterfaceLuid.Value, "entry %lu: luid\n", i);
                    ok(One.PrefixOrigin == R->PrefixOrigin && One.SuffixOrigin == R->SuffixOrigin &&
                       One.OnLinkPrefixLength == R->OnLinkPrefixLength, "entry %lu: origins or prefix\n", i);
                }
            }
        }
        ok(Loop == 1, "%lu ::1 rows\n", Loop);
        ok(Link == LinkLocals, "%lu link-local rows, %lu in the adapter lists\n", Link, LinkLocals);
        ok(Rows6 == Table6->NumEntries, "rows\n");
    }

    /* A made-up address is not there */
    if (pGetUnicastIpAddressEntry && Table6 && Table6->NumEntries)
    {
        UNICAST_ROW One;

        memset(&One, 0, sizeof(One));
        One.Address.si_family = AF_INET6;
        One.Address.Ipv6.sin6_addr.s6_addr[0] = 0x20;
        One.Address.Ipv6.sin6_addr.s6_addr[1] = 0x01;
        One.Address.Ipv6.sin6_addr.s6_addr[15] = 0x77;
        One.InterfaceIndex = Table6->Table[0].InterfaceIndex;
        Error = pGetUnicastIpAddressEntry(&One);
        ok(Error == ERROR_NOT_FOUND, "GetUnicastIpAddressEntry(unknown address): %lu\n", Error);
    }

    /* The interface rows: IPv6 interfaces are the ones the adapters flag */
    Error = pGetIpInterfaceTable(AF_INET6, &IfTable);
    ok(Error == NO_ERROR && IfTable, "GetIpInterfaceTable(AF_INET6): %lu\n", Error);
    if (IfTable)
    {
        ok(IfTable->NumEntries == V6Adapters, "%lu IPv6 interfaces, %lu adapters with the flag\n", IfTable->NumEntries,
           V6Adapters);
        for (i = 0; i < IfTable->NumEntries; i++)
        {
            IPIF_ROW One;
            const IPIF_ROW *R = &IfTable->Table[i];
            BOOL Loopback = FALSE;

            ok(R->Family == AF_INET6, "interface row %lu: family %u\n", i, R->Family);
            for (A = All; A; A = A->Next)
                if (A->IfIndex == R->InterfaceIndex)
                {
                    Loopback = (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
                    ok(A->Flags & IPV6_ENABLED_FLAG, "interface %lu is not flagged\n", A->IfIndex);
                }

            memset(&One, 0, sizeof(One));
            One.Family = AF_INET6;
            One.InterfaceIndex = R->InterfaceIndex;
            Error = pGetIpInterfaceEntry(&One);
            ok(Error == NO_ERROR, "GetIpInterfaceEntry(AF_INET6, %lu): %lu\n", R->InterfaceIndex, Error);
            if (Error != NO_ERROR)
                continue;

            /* what Windows 10 reports for an IPv6 interface */
            ok(One.RouterDiscoveryBehavior == ROUTER_DISCOVERY_ENABLED, "%lu: RouterDiscoveryBehavior %lu\n",
               One.InterfaceIndex, One.RouterDiscoveryBehavior);
            ok(One.LinkLocalAddressBehavior == LINKLOCAL_ALWAYS_ON, "%lu: LinkLocalAddressBehavior %lu\n",
               One.InterfaceIndex, One.LinkLocalAddressBehavior);
            ok(One.LinkLocalAddressTimeout == 0, "%lu: LinkLocalAddressTimeout %lu\n", One.InterfaceIndex,
               One.LinkLocalAddressTimeout);
            ok(!One.ManagedAddressConfigurationSupported && !One.OtherStatefulConfigurationSupported,
               "%lu: stateful configuration\n", One.InterfaceIndex);
            ok(One.UseAutomaticMetric, "%lu: UseAutomaticMetric\n", One.InterfaceIndex);
            ok(One.BaseReachableTime == 30000 && One.RetransmitTime == 1000, "%lu: reachable times %lu/%lu\n",
               One.InterfaceIndex, One.BaseReachableTime, One.RetransmitTime);
            ok(One.PathMtuDiscoveryTimeout == 600000, "%lu: PathMtuDiscoveryTimeout %lu\n", One.InterfaceIndex,
               One.PathMtuDiscoveryTimeout);
            ok(One.MinRouterAdvertisementInterval == 200 && One.MaxRouterAdvertisementInterval == 600,
               "%lu: advertisement intervals\n", One.InterfaceIndex);
            ok(One.Connected, "%lu: not connected\n", One.InterfaceIndex);
            for (k = 0; k < 16; k++)
            {
                ULONG Expected = (k < 4) ? One.InterfaceIndex : (k == 14 ? 0 : 1);
                ok(One.ZoneIndices[k] == Expected, "%lu: ZoneIndices[%lu] = %lu\n", One.InterfaceIndex, k,
                   One.ZoneIndices[k]);
            }
            if (Loopback)
            {
                ok(One.NlMtu == 0xFFFFFFFF, "loopback: NlMtu %lu\n", One.NlMtu);
                ok(!One.UseNeighborUnreachabilityDetection && !One.SupportsNeighborDiscovery &&
                   !One.SupportsRouterDiscovery, "loopback: neighbour discovery flags\n");
                ok(One.DadTransmits == 0, "loopback: DadTransmits %lu\n", One.DadTransmits);
                ok(One.Metric == 75, "loopback: Metric %lu\n", One.Metric);
            }
            else
            {
                ok(One.UseNeighborUnreachabilityDetection && One.SupportsNeighborDiscovery &&
                   One.SupportsRouterDiscovery, "%lu: neighbour discovery flags\n", One.InterfaceIndex);
                ok(One.DadTransmits == 1, "%lu: DadTransmits %lu\n", One.InterfaceIndex, One.DadTransmits);
            }

            /* the same interface answers the IPv4 query too */
            One.Family = AF_INET;
            Error = pGetIpInterfaceEntry(&One);
            ok(Error == NO_ERROR, "GetIpInterfaceEntry(AF_INET, %lu): %lu\n", R->InterfaceIndex, Error);
        }
    }

    /* The IPv4 interface table is still there, and AF_UNSPEC has both */
    {
        IPIF_TABLE *T4 = NULL, *TU = NULL;

        Error = pGetIpInterfaceTable(AF_INET, &T4);
        ok(Error == NO_ERROR && T4, "GetIpInterfaceTable(AF_INET): %lu\n", Error);
        Error = pGetIpInterfaceTable(AF_UNSPEC, &TU);
        ok(Error == NO_ERROR && TU, "GetIpInterfaceTable(AF_UNSPEC): %lu\n", Error);
        if (T4 && TU && IfTable)
            ok(TU->NumEntries == T4->NumEntries + IfTable->NumEntries, "interface rows %lu, IPv4 %lu, IPv6 %lu\n",
               TU->NumEntries, T4->NumEntries, IfTable->NumEntries);
        if (T4)
            pFreeMibTable(T4);
        if (TU)
            pFreeMibTable(TU);
    }

    /* GetAdaptersInfo stays IPv4 only */
    {
        IP_ADAPTER_INFO *Info = NULL;
        ULONG Size = 0;

        Error = GetAdaptersInfo(NULL, &Size);
        ok(Error == ERROR_BUFFER_OVERFLOW || Error == ERROR_NO_DATA, "GetAdaptersInfo size: %lu\n", Error);
        if (Error == ERROR_BUFFER_OVERFLOW)
        {
            Info = malloc(Size);
            Error = GetAdaptersInfo(Info, &Size);
            ok(Error == NO_ERROR, "GetAdaptersInfo: %lu\n", Error);
            if (Error == NO_ERROR)
            {
                IP_ADAPTER_INFO *I;

                for (I = Info; I; I = I->Next)
                    ok(strchr(I->IpAddressList.IpAddress.String, ':') == NULL, "GetAdaptersInfo: IPv6 address '%s'\n",
                       I->IpAddressList.IpAddress.String);
            }
            free(Info);
        }
    }

Done:
    if (Table)
        pFreeMibTable(Table);
    if (Table6)
        pFreeMibTable(Table6);
    if (Table4)
        pFreeMibTable(Table4);
    if (IfTable)
        pFreeMibTable(IfTable);
    free(All);
    free(V6);
    free(V4);
}

START_TEST(Ipv6Reporting)
{
    HMODULE hIphlpapi = GetModuleHandleA("iphlpapi.dll");

    if (!hIphlpapi)
        hIphlpapi = LoadLibraryA("iphlpapi.dll");
    pGetUnicastIpAddressTable = (PGET_UNICAST_TABLE)GetProcAddress(hIphlpapi, "GetUnicastIpAddressTable");
    pGetUnicastIpAddressEntry = (PGET_UNICAST_ENTRY)GetProcAddress(hIphlpapi, "GetUnicastIpAddressEntry");
    pGetIpInterfaceTable = (PGET_IPIF_TABLE)GetProcAddress(hIphlpapi, "GetIpInterfaceTable");
    pGetIpInterfaceEntry = (PGET_IPIF_ENTRY)GetProcAddress(hIphlpapi, "GetIpInterfaceEntry");
    pFreeMibTable = (PFREE_MIB_TABLE)GetProcAddress(hIphlpapi, "FreeMibTable");

    if (!pGetUnicastIpAddressTable || !pGetIpInterfaceTable || !pGetIpInterfaceEntry || !pFreeMibTable)
    {
        skip("The Vista IP Helper tables are not available\n");
        return;
    }

    Ipv6On = ReadSwitch();
    trace("Ipv6Enable is %s\n", Ipv6On ? "on" : "off");
    if (Ipv6On)
        TestOn();
    else
        TestOff();
}
