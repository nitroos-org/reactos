/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 temporary addresses (RFC 8981). With the default (Tcpip6\Parameters\UseTemporaryAddresses absent
 *              or not 0) every prefix a router advertises for stateless autoconfiguration gets, next to its public
 *              address, a temporary address with a random identifier: GetAdaptersAddresses and
 *              GetUnicastIpAddressTable report it with PrefixOrigin RouterAdvertisement and SuffixOrigin Random
 *              (Get-NetIPAddress SuffixOrigin Random, ipconfig "Temporary IPv6 Address"), one of them preferred,
 *              its lifetimes those of the prefix within MaxValidLifetime / MaxPreferredLifetime (Windows 10 22H2
 *              defaults: 7 days / 1 day, oracle), counting down; outgoing connections take it as their source
 *              (RFC 6724 rule 7: GetBestRoute2, and a TCP connection when a host answers). With a short
 *              MaxPreferredLifetime (at most 120 s in the registry, a test setting) a new one replaces it and the old
 *              one stays, deprecated. With UseTemporaryAddresses = 0 there is none. Without a router advertisement
 *              that forms an address (no router, no network adapter, IPv6 off) the checks are skipped.
 *              Optional: IPV6TEMP_PEER and IPV6TEMP_PORT (environment) name a TCP server to connect to.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdlib.h>

/* The rows of the Windows SDK, under private names: the headers of this tree do not declare them */
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

typedef DWORD (WINAPI *PGET_UNICAST_TABLE)(USHORT, UNICAST_TABLE **);
typedef DWORD (WINAPI *PGET_BEST_ROUTE2)(NET_LUID *, ULONG, const SOCKADDR_INET *, const SOCKADDR_INET *,
                                         ULONG, ROUTE_ROW2 *, SOCKADDR_INET *);
typedef VOID (WINAPI *PFREE_MIB_TABLE)(PVOID);

static PGET_UNICAST_TABLE pGetUnicastIpAddressTable;
static PGET_BEST_ROUTE2 pGetBestRoute2;
static PFREE_MIB_TABLE pFreeMibTable;

#define PARAMETERS_KEY  L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"

typedef struct _SETTINGS
{
    DWORD Use, MaxValid, MaxPreferred, Regenerate, MaxRandom;
} SETTINGS;

static DWORD ReadValue(HKEY Key, PCWSTR Name, DWORD Default)
{
    DWORD Value, Size = sizeof(Value), Type = 0;

    if (!Key || RegQueryValueExW(Key, Name, NULL, &Type, (BYTE *)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD || Size != sizeof(Value))
        return Default;
    return Value;
}

static void ReadSettings(SETTINGS *S)
{
    HKEY Key = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        Key = NULL;
    S->Use = ReadValue(Key, L"UseTemporaryAddresses", 1);
    S->MaxValid = ReadValue(Key, L"MaxValidLifetime", 7 * 24 * 3600);
    S->MaxPreferred = ReadValue(Key, L"MaxPreferredLifetime", 24 * 3600);
    S->Regenerate = ReadValue(Key, L"RegenerateTime", 5);
    S->MaxRandom = ReadValue(Key, L"MaxRandomTime", 600);
    if (Key)
        RegCloseKey(Key);
    if (S->MaxPreferred > S->MaxValid)
        S->MaxPreferred = S->MaxValid;
}

static BOOL IsLinkLocal(const BYTE *A)
{
    return A[0] == 0xfe && (A[1] & 0xc0) == 0x80;
}

static IP_ADAPTER_ADDRESSES *GetList(void)
{
    IP_ADAPTER_ADDRESSES *List;
    ULONG Size = 64 * 1024, Error;

    List = HeapAlloc(GetProcessHeap(), 0, Size);
    Error = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                 NULL, List, &Size);
    ok(Error == ERROR_SUCCESS || Error == ERROR_NO_DATA, "GetAdaptersAddresses error %lu\n", Error);
    if (Error != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, List);
        return NULL;
    }
    return List;
}

/* An address an Ethernet adapter got from a router advertisement: the public one (suffix not Random) */
typedef struct _FOUND
{
    DWORD IfIndex;
    BYTE Public[16];
    ULONG PublicValid, PublicPreferred;
    DWORD PublicDad;
    ULONG Temporary, PreferredTemporary;
    BYTE Preferred[16];             /* the preferred temporary address */
    ULONG Valid, PreferredLife;     /* its lifetimes */
    ULONG PrefixOrigin, SuffixOrigin, PrefixLength;
    ULONG Deprecated;               /* deprecated temporary addresses of the prefix */
    BYTE Old[16];                   /* one of them */
    ULONG Random;                   /* addresses with suffix origin Random anywhere */
} FOUND;

/* The first public SLAAC address of an Ethernet adapter and the temporary addresses of its prefix. Prefix: the
   prefix to look at (NULL: the first one found) */
static BOOL Scan(FOUND *F, const BYTE *Prefix)
{
    IP_ADAPTER_ADDRESSES *List = GetList(), *A;
    IP_ADAPTER_UNICAST_ADDRESS *U;
    BOOL Have = FALSE;
    BYTE Want[8];

    /* Prefix may point into *F */
    if (Prefix)
    {
        memcpy(Want, Prefix, 8);
        Prefix = Want;
    }
    memset(F, 0, sizeof(*F));
    for (A = List; A; A = A->Next)
    {
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            const SOCKADDR_IN6 *S = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;

            if (S->sin6_family == AF_INET6 && U->SuffixOrigin == IpSuffixOriginRandom)
                F->Random++;
        }
        if (Have || A->IfType != IF_TYPE_ETHERNET_CSMACD || A->PhysicalAddressLength != 6)
            continue;
        for (U = A->FirstUnicastAddress; U && !Have; U = U->Next)
        {
            const SOCKADDR_IN6 *S = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;

            if (S->sin6_family != AF_INET6 || IsLinkLocal(S->sin6_addr.s6_addr) ||
                U->PrefixOrigin != IpPrefixOriginRouterAdvertisement || U->SuffixOrigin == IpSuffixOriginRandom ||
                (Prefix && memcmp(S->sin6_addr.s6_addr, Prefix, 8)))
                continue;
            Have = TRUE;
            F->IfIndex = A->IfIndex;
            memcpy(F->Public, S->sin6_addr.s6_addr, 16);
            F->PublicValid = U->ValidLifetime;
            F->PublicPreferred = U->PreferredLifetime;
            F->PublicDad = U->DadState;
        }
        if (!Have)
            continue;
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            const SOCKADDR_IN6 *S = (const SOCKADDR_IN6 *)U->Address.lpSockaddr;

            if (S->sin6_family != AF_INET6 || U->SuffixOrigin != IpSuffixOriginRandom ||
                memcmp(S->sin6_addr.s6_addr, F->Public, 8))
                continue;
            F->Temporary++;
            if (U->DadState == IpDadStatePreferred)
            {
                F->PreferredTemporary++;
                memcpy(F->Preferred, S->sin6_addr.s6_addr, 16);
                F->Valid = U->ValidLifetime;
                F->PreferredLife = U->PreferredLifetime;
                F->PrefixOrigin = U->PrefixOrigin;
                F->SuffixOrigin = U->SuffixOrigin;
                F->PrefixLength = U->OnLinkPrefixLength;
            }
            else if (U->DadState == IpDadStateDeprecated)
            {
                F->Deprecated++;
                memcpy(F->Old, S->sin6_addr.s6_addr, 16);
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, List);
    return Have;
}

static void Text(const BYTE *A, char *Out, size_t Size)
{
    SOCKADDR_IN6 S;
    DWORD Length = (DWORD)Size;

    memset(&S, 0, sizeof(S));
    S.sin6_family = AF_INET6;
    memcpy(S.sin6_addr.s6_addr, A, 16);
    if (WSAAddressToStringA((SOCKADDR *)&S, sizeof(S), NULL, Out, &Length))
        strcpy(Out, "?");
}

/* GetUnicastIpAddressTable has the address with the same origins */
static void CheckTableRow(const BYTE *Address)
{
    UNICAST_TABLE *Table = NULL;
    ULONG i;
    BOOL Found = FALSE;
    DWORD Error;

    if (!pGetUnicastIpAddressTable || !pFreeMibTable)
    {
        skip("no GetUnicastIpAddressTable\n");
        return;
    }
    Error = pGetUnicastIpAddressTable(AF_INET6, &Table);
    ok(Error == NO_ERROR, "GetUnicastIpAddressTable error %lu\n", Error);
    if (Error != NO_ERROR || !Table)
        return;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const UNICAST_ROW *R = &Table->Table[i];

        if (memcmp(R->Address.Ipv6.sin6_addr.s6_addr, Address, 16))
            continue;
        Found = TRUE;
        ok(R->PrefixOrigin == IpPrefixOriginRouterAdvertisement, "table: PrefixOrigin %d\n", R->PrefixOrigin);
        ok(R->SuffixOrigin == IpSuffixOriginRandom, "table: SuffixOrigin %d\n", R->SuffixOrigin);
        ok(R->OnLinkPrefixLength == 64, "table: prefix length %u\n", R->OnLinkPrefixLength);
        ok(R->DadState == IpDadStatePreferred, "table: DadState %d\n", R->DadState);
        ok(!R->SkipAsSource, "table: SkipAsSource\n");
    }
    ok(Found, "the temporary address is not in GetUnicastIpAddressTable\n");
    pFreeMibTable(Table);
}

/* The source the stack takes for a destination in the prefix (GetBestRoute2) */
static BOOL BestSource(DWORD IfIndex, const BYTE *Prefix, BYTE Source[16])
{
    SOCKADDR_INET Dest, Best;
    ROUTE_ROW2 Route;
    DWORD Error;

    if (!pGetBestRoute2)
        return FALSE;

    memset(&Dest, 0, sizeof(Dest));
    Dest.Ipv6.sin6_family = AF_INET6;
    memcpy(Dest.Ipv6.sin6_addr.s6_addr, Prefix, 8);
    Dest.Ipv6.sin6_addr.s6_addr[15] = 0x99;
    Dest.Ipv6.sin6_addr.s6_addr[14] = 0x77;
    memset(&Best, 0, sizeof(Best));
    Error = pGetBestRoute2(NULL, IfIndex, NULL, &Dest, 0, &Route, &Best);
    ok(Error == NO_ERROR, "GetBestRoute2 error %lu\n", Error);
    if (Error != NO_ERROR || Best.si_family != AF_INET6)
        return FALSE;
    memcpy(Source, Best.Ipv6.sin6_addr.s6_addr, 16);
    return TRUE;
}

/* A TCP connection to Peer (text) port Port: its local address. FALSE: no connection within 5 s */
static BOOL ConnectSource(const char *Peer, const char *Port, BYTE Source[16])
{
    ADDRINFOA Hints, *Info = NULL;
    SOCKET s;
    SOCKADDR_IN6 Local;
    int Length = sizeof(Local), Error;
    u_long NonBlocking = 1;
    fd_set Write, Except;
    struct timeval Timeout = { 5, 0 };
    BOOL Connected = FALSE;

    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = AF_INET6;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(Peer, Port, &Hints, &Info) || !Info)
        return FALSE;
    s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET)
    {
        ioctlsocket(s, FIONBIO, &NonBlocking);
        Error = connect(s, Info->ai_addr, (int)Info->ai_addrlen);
        if (Error == 0 || WSAGetLastError() == WSAEWOULDBLOCK)
        {
            FD_ZERO(&Write);
            FD_ZERO(&Except);
            FD_SET(s, &Write);
            FD_SET(s, &Except);
            if (select(0, NULL, &Write, &Except, &Timeout) > 0 && FD_ISSET(s, &Write))
                Connected = getsockname(s, (SOCKADDR *)&Local, &Length) == 0 && Local.sin6_family == AF_INET6;
        }
        closesocket(s);
    }
    freeaddrinfo(Info);
    if (Connected)
        memcpy(Source, Local.sin6_addr.s6_addr, 16);
    return Connected;
}

START_TEST(Ipv6Temporary)
{
    SETTINGS S;
    FOUND F, G;
    WSADATA Wsa;
    BYTE Source[16];
    char T1[64], T2[64];
    ULONG Try, MaxPreferred;
    BOOL Have = FALSE, Short;
    const char *Peer, *Port;

    HMODULE Iphlpapi = GetModuleHandleW(L"iphlpapi.dll");

    pGetUnicastIpAddressTable = (PGET_UNICAST_TABLE)GetProcAddress(Iphlpapi, "GetUnicastIpAddressTable");
    pGetBestRoute2 = (PGET_BEST_ROUTE2)GetProcAddress(Iphlpapi, "GetBestRoute2");
    pFreeMibTable = (PFREE_MIB_TABLE)GetProcAddress(Iphlpapi, "FreeMibTable");
    WSAStartup(MAKEWORD(2, 2), &Wsa);
    ReadSettings(&S);
    Short = S.MaxPreferred <= 120;
    trace("UseTemporaryAddresses %lu, MaxValidLifetime %lu, MaxPreferredLifetime %lu, RegenerateTime %lu, MaxRandomTime %lu\n",
          S.Use, S.MaxValid, S.MaxPreferred, S.Regenerate, S.MaxRandom);

    /* a router advertisement may take a while (QEMU's user network answers the router solicitation) */
    for (Try = 0; Try < 30 && !(Have = Scan(&F, NULL)); Try++)
        Sleep(1000);
    if (!Have)
    {
        skip("no address from a router advertisement on an Ethernet adapter within 30 s (no router, no adapter or IPv6 off)\n");
        ok(F.Random == 0, "%lu temporary addresses without a public one\n", F.Random);
        WSACleanup();
        return;
    }
    Text(F.Public, T1, sizeof(T1));
    trace("adapter %lu public %s valid %lu preferred %lu dad %lu\n", F.IfIndex, T1, F.PublicValid, F.PublicPreferred,
          F.PublicDad);

    Peer = getenv("IPV6TEMP_PEER");
    Port = getenv("IPV6TEMP_PORT");
    if (!Port || !*Port)
        Port = "22";

    if (!S.Use)
    {
        Sleep(3000);
        Scan(&F, F.Public);
        ok(F.Random == 0, "UseTemporaryAddresses = 0: %lu addresses with suffix origin Random\n", F.Random);
        /* the public address is the source */
        if (Peer && *Peer && ConnectSource(Peer, Port, Source))
        {
            Text(Source, T2, sizeof(T2));
            trace("TCP to %s: local address %s\n", Peer, T2);
            ok(!memcmp(Source, F.Public, 16), "TCP to %s: local address %s, want the public %s\n", Peer, T2, T1);
        }
        WSACleanup();
        return;
    }

    /* one preferred temporary address for the prefix (after its DAD) */
    for (Try = 0; Try < 20; Try++)
    {
        Scan(&F, F.Public);
        if (F.PreferredTemporary)
            break;
        Sleep(500);
    }
    ok(F.PreferredTemporary == 1, "%lu preferred temporary addresses for the prefix (of %lu), want 1\n",
       F.PreferredTemporary, F.Temporary);
    if (!F.PreferredTemporary)
    {
        if (Peer && *Peer && ConnectSource(Peer, Port, Source))
        {
            Text(Source, T2, sizeof(T2));
            trace("TCP to %s: local address %s\n", Peer, T2);
        }
        WSACleanup();
        return;
    }
    Text(F.Preferred, T2, sizeof(T2));
    trace("temporary %s valid %lu preferred %lu origins %lu/%lu /%lu; %lu deprecated\n", T2, F.Valid, F.PreferredLife,
          F.PrefixOrigin, F.SuffixOrigin, F.PrefixLength, F.Deprecated);
    ok(memcmp(F.Preferred + 8, F.Public + 8, 8) != 0, "the temporary identifier is the public one\n");
    ok(F.PrefixOrigin == IpPrefixOriginRouterAdvertisement, "PrefixOrigin %lu, want RouterAdvertisement\n", F.PrefixOrigin);
    ok(F.SuffixOrigin == IpSuffixOriginRandom, "SuffixOrigin %lu, want Random\n", F.SuffixOrigin);
    ok(F.PrefixLength == 64, "OnLinkPrefixLength %lu\n", F.PrefixLength);
    /* RFC 8981 3.4: within the temporary maximums and the prefix's own lifetimes */
    ok(F.Valid <= S.MaxValid && F.Valid <= F.PublicValid + 1, "valid lifetime %lu: over min(%lu, %lu)\n", F.Valid,
       S.MaxValid, F.PublicValid);
    ok(F.PreferredLife <= S.MaxPreferred && F.PreferredLife <= F.PublicPreferred + 1 && F.PreferredLife <= F.Valid,
       "preferred lifetime %lu: over min(%lu, %lu, valid)\n", F.PreferredLife, S.MaxPreferred, F.PublicPreferred);
    ok(F.PreferredLife > 0 && F.Valid > 0, "lifetimes %lu/%lu\n", F.Valid, F.PreferredLife);
    CheckTableRow(F.Preferred);

    /* the lifetimes count down (unless a router advertisement raised the prefix's meanwhile) */
    Sleep(3000);
    Scan(&G, F.Public);
    if (G.PreferredTemporary && !memcmp(G.Preferred, F.Preferred, 16) && G.PublicPreferred <= F.PublicPreferred)
    {
        ok(G.Valid < F.Valid && G.Valid + 6 >= F.Valid, "valid lifetime %lu then %lu after 3 s\n", F.Valid, G.Valid);
        ok(G.PreferredLife < F.PreferredLife && G.PreferredLife + 6 >= F.PreferredLife,
           "preferred lifetime %lu then %lu after 3 s\n", F.PreferredLife, G.PreferredLife);
    }
    else
        trace("lifetimes not compared: the prefix was advertised again or the address changed\n");

    /* outgoing: the temporary address is the source (rule 7) */
    if (BestSource(F.IfIndex, F.Public, Source))
    {
        Text(Source, T1, sizeof(T1));
        ok(!memcmp(Source, F.Preferred, 16), "GetBestRoute2 source %s, want the temporary %s\n", T1, T2);
    }
    if (Peer && *Peer)
    {
        if (ConnectSource(Peer, Port, Source))
        {
            Text(Source, T1, sizeof(T1));
            trace("TCP to %s: local address %s\n", Peer, T1);
            ok(!memcmp(Source, F.Preferred, 16), "TCP to %s: local address %s, want the temporary %s\n", Peer, T1, T2);
        }
        else
            skip("no TCP connection to %s\n", Peer);
    }

    if (!Short)
    {
        WSACleanup();
        return;
    }

    /* short lifetimes (a test setting): a new one before this one is deprecated, the old one stays deprecated */
    MaxPreferred = S.MaxPreferred;
    trace("waiting up to %lu s for the next temporary address\n", MaxPreferred + 20);
    for (Try = 0; Try < MaxPreferred + 20; Try++)
    {
        Scan(&G, F.Public);
        if (G.PreferredTemporary == 1 && memcmp(G.Preferred, F.Preferred, 16) && G.Deprecated)
            break;
        Sleep(1000);
    }
    Text(G.Preferred, T1, sizeof(T1));
    ok(G.PreferredTemporary == 1 && memcmp(G.Preferred, F.Preferred, 16) != 0,
       "no new preferred temporary address after %lu s (%lu preferred, now %s)\n", Try, G.PreferredTemporary, T1);
    ok(G.Deprecated >= 1, "the old temporary address is not listed as deprecated (%lu temporary)\n", G.Temporary);
    if (G.Deprecated && S.MaxValid > MaxPreferred + Try + 5)
    {
        Text(G.Old, T2, sizeof(T2));
        trace("deprecated: %s\n", T2);
    }
    trace("after %lu s: %lu temporary, %lu deprecated, new %s\n", Try, G.Temporary, G.Deprecated, T1);
    if (G.PreferredTemporary == 1 && BestSource(G.IfIndex, G.Public, Source))
    {
        Text(Source, T2, sizeof(T2));
        ok(!memcmp(Source, G.Preferred, 16), "GetBestRoute2 source %s, want the new temporary %s\n", T2, T1);
    }
    if (Peer && *Peer && G.PreferredTemporary == 1 && ConnectSource(Peer, Port, Source))
    {
        Text(Source, T2, sizeof(T2));
        trace("TCP to %s after the change: local address %s\n", Peer, T2);
        ok(!memcmp(Source, G.Preferred, 16), "TCP to %s after the change: local address %s, want %s\n", Peer, T2, T1);
    }
    WSACleanup();
}
