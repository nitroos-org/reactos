/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What the IPv6 IP Helper tests share: the rows of the Windows SDK under private names (the headers
 *              of this tree do not declare them) and a few helpers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef IPV6COMMON_H
#define IPV6COMMON_H

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

/* MIB_IPNET_ROW2 and MIB_IPNET_TABLE2 */
typedef struct
{
    SOCKADDR_INET Address;
    ULONG InterfaceIndex;
    NET_LUID InterfaceLuid;
    UCHAR PhysicalAddress[32];
    ULONG PhysicalAddressLength;
    ULONG State;
    UCHAR Flags;
    ULONG ReachabilityTime;
} NEIGH_ROW6;

typedef struct
{
    ULONG NumEntries;
    NEIGH_ROW6 Table[1];
} NEIGH_TABLE6;

/* MIB_IPFORWARD_ROW2 and MIB_IPFORWARD_TABLE2 */
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
} ROUTE_ROW6;

typedef struct
{
    ULONG NumEntries;
    ROUTE_ROW6 Table[1];
} ROUTE_TABLE6;

typedef DWORD (WINAPI *PFN_GET_TABLE)(USHORT, PVOID *);
typedef VOID (WINAPI *PFN_FREE_TABLE)(PVOID);
typedef DWORD (WINAPI *PFN_GET_NEIGH)(NEIGH_ROW6 *);
typedef DWORD (WINAPI *PFN_RESOLVE)(NEIGH_ROW6 *, const SOCKADDR_INET *);
typedef DWORD (WINAPI *PFN_BEST_ROUTE)(NET_LUID *, ULONG, const SOCKADDR_INET *, const SOCKADDR_INET *, ULONG,
                                       ROUTE_ROW6 *, SOCKADDR_INET *);

#define NLNS_INCOMPLETE 1
#define NLNS_PROBE      2
#define NLNS_DELAY      3
#define NLNS_STALE      4
#define NLNS_REACHABLE  5
#define NLNS_PERMANENT  6

#define LOOPBACK6_LUID  0x0018000000000000ULL

static __inline FARPROC Ipv6Proc(const char *Name)
{
    HMODULE Module = LoadLibraryW(L"iphlpapi.dll");

    return Module ? GetProcAddress(Module, Name) : NULL;
}

/* IPv6 sockets can be made: the stack says IPv6 is on (and Windows has it installed) */
static __inline BOOL Ipv6SocketsWork(void)
{
    SOCKET Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (Socket == INVALID_SOCKET)
        return FALSE;
    closesocket(Socket);
    return TRUE;
}

/* Not WSAStringToAddress: that needs the IPv6 entries of the Winsock catalog, which a stack without IPv6 does not have */
static __inline void Ipv6Parse(SOCKADDR_INET *Address, const char *Text, ULONG Scope)
{
    typedef LONG (NTAPI *PFN_STRING_TO_ADDRESS)(PCSTR, PCSTR *, PVOID);
    PFN_STRING_TO_ADDRESS pParse = (PFN_STRING_TO_ADDRESS)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                                         "RtlIpv6StringToAddressA");
    PCSTR End;

    memset(Address, 0, sizeof(*Address));
    if (!pParse || pParse(Text, &End, &Address->Ipv6.sin6_addr) != 0)
    {
        memset(Address, 0, sizeof(*Address));
        return;
    }
    Address->Ipv6.sin6_family = AF_INET6;
    Address->Ipv6.sin6_scope_id = Scope;
}

static __inline BOOL Ipv6IsZero(const UCHAR *Address)
{
    int i;

    for (i = 0; i < 16; i++)
        if (Address[i])
            return FALSE;
    return TRUE;
}

static __inline BOOL Ipv6IsLinkLocal(const UCHAR *Address)
{
    return Address[0] == 0xfe && (Address[1] & 0xc0) == 0x80;
}

/* The physical address of the adapter with this interface index (FALSE: none) */
static __inline BOOL Ipv6AdapterPhysical(ULONG IfIndex, UCHAR *Address, ULONG *Length)
{
    ULONG Size = 0;
    PIP_ADAPTER_ADDRESSES Adapters, A;
    BOOL Found = FALSE;

    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL,
                         NULL, &Size);
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    if (!Adapters)
        return FALSE;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             NULL, Adapters, &Size) == NO_ERROR)
    {
        for (A = Adapters; A && !Found; A = A->Next)
        {
            if (A->IfIndex != IfIndex && A->Ipv6IfIndex != IfIndex)
                continue;
            *Length = A->PhysicalAddressLength;
            memcpy(Address, A->PhysicalAddress, A->PhysicalAddressLength);
            Found = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Found;
}

#endif
