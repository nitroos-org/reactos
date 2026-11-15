/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateSortedAddressPairs on this machine (loopback and own-address destinations, so the answer does
 *              not depend on the network) and the registry-backed prefix policy table
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>

/* Not declared by the headers of this tree */
typedef DWORD (WINAPI *PCREATE_SORTED_ADDRESS_PAIRS)(const PSOCKADDR_IN6, ULONG, const PSOCKADDR_IN6, ULONG, ULONG,
                                                     PSOCKADDR_IN6_PAIR *, ULONG *);
typedef VOID (WINAPI *PFREE_MIB_TABLE)(PVOID);

static PCREATE_SORTED_ADDRESS_PAIRS pCreate;
static PFREE_MIB_TABLE pFree;

static void Mapped(SOCKADDR_IN6 *Out, UCHAR A, UCHAR B, UCHAR C, UCHAR D)
{
    memset(Out, 0, sizeof(*Out));
    Out->sin6_family = AF_INET6;
    Out->sin6_addr.u.Byte[10] = Out->sin6_addr.u.Byte[11] = 0xff;
    Out->sin6_addr.u.Byte[12] = A;
    Out->sin6_addr.u.Byte[13] = B;
    Out->sin6_addr.u.Byte[14] = C;
    Out->sin6_addr.u.Byte[15] = D;
}

static void Loop6(SOCKADDR_IN6 *Out)
{
    memset(Out, 0, sizeof(*Out));
    Out->sin6_family = AF_INET6;
    Out->sin6_addr.u.Byte[15] = 1;
}

static BOOL IsMappedAddr(const SOCKADDR_IN6 *A)
{
    static const UCHAR Prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    return !memcmp(A->sin6_addr.u.Byte, Prefix, 12);
}

/* "::1" or the IPv4 address, for messages */
static void Text(const SOCKADDR_IN6 *A, char *Out)
{
    if (IsMappedAddr(A))
        sprintf(Out, "%u.%u.%u.%u", A->sin6_addr.u.Byte[12], A->sin6_addr.u.Byte[13], A->sin6_addr.u.Byte[14],
                A->sin6_addr.u.Byte[15]);
    else
        sprintf(Out, "v6 last byte %u", A->sin6_addr.u.Byte[15]);
}

static void TestParameters(void)
{
    SOCKADDR_IN6 Dest[2], Source;
    PSOCKADDR_IN6_PAIR Pairs = (PSOCKADDR_IN6_PAIR)0x1234;
    ULONG Count = 77;
    DWORD Error;

    Mapped(&Dest[0], 127, 0, 0, 1);
    Mapped(&Source, 127, 0, 0, 1);

    Error = pCreate(NULL, 0, Dest, 1, 0, &Pairs, &Count);
    ok(Error == NO_ERROR, "one destination: %lu\n", Error);
    ok(Count == 1 && Pairs, "one destination: count %lu pairs %p\n", Count, Pairs);
    if (Pairs)
        pFree(Pairs);

    /* the Windows 10 oracle rejects a source list, also of one address */
    Pairs = (PSOCKADDR_IN6_PAIR)0x1234;
    Count = 77;
    Error = pCreate(&Source, 1, Dest, 1, 0, &Pairs, &Count);
    ok(Error == ERROR_INVALID_PARAMETER, "source list: %lu\n", Error);
    ok(Pairs == (PSOCKADDR_IN6_PAIR)0x1234 && Count == 77, "outputs after a failure: %p %lu\n", Pairs, Count);
    ok(pCreate(&Source, 0, Dest, 1, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "source list, count 0\n");
    ok(pCreate(NULL, 1, Dest, 1, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "source count only\n");
    ok(pCreate(NULL, 0, NULL, 1, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "no destinations\n");
    ok(pCreate(NULL, 0, Dest, 0, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "destination count 0\n");
    ok(pCreate(NULL, 0, Dest, 1, 1, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "options 1\n");
    ok(pCreate(NULL, 0, Dest, 1, 0, NULL, &Count) == ERROR_INVALID_PARAMETER, "no output list\n");
    ok(pCreate(NULL, 0, Dest, 1, 0, &Pairs, NULL) == ERROR_INVALID_PARAMETER, "no output count\n");

    Dest[1] = Dest[0];
    Dest[1].sin6_family = AF_INET;
    ok(pCreate(NULL, 0, Dest, 2, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "AF_INET entry\n");

    /* the documented limit is 500 destinations: 500 are sorted, 501 and absurd counts are rejected before the list
       is read (the outputs stay as they were) */
    {
        SOCKADDR_IN6 *Many = HeapAlloc(GetProcessHeap(), 0, 501 * sizeof(*Many));
        ULONG i;

        ok(Many != NULL, "no memory\n");
        if (Many)
        {
            for (i = 0; i < 501; i++)
                Mapped(&Many[i], 127, 0, (UCHAR)(i >> 8), (UCHAR)(i + 1));
            Pairs = NULL;
            Count = 0;
            Error = pCreate(NULL, 0, Many, 500, 0, &Pairs, &Count);
            ok(Error == NO_ERROR, "500 destinations: %lu\n", Error);
            ok(Count >= 1 && Count <= 500 && Pairs != NULL, "500 destinations: count %lu pairs %p\n", Count, Pairs);
            if (Error == NO_ERROR && Pairs)
                pFree(Pairs);
            Pairs = (PSOCKADDR_IN6_PAIR)0x1234;
            Count = 77;
            ok(pCreate(NULL, 0, Many, 501, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "501 destinations\n");
            ok(pCreate(NULL, 0, Many, 0x7fffffff, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "count 0x7fffffff\n");
            ok(pCreate(NULL, 0, Many, 0xffffffff, 0, &Pairs, &Count) == ERROR_INVALID_PARAMETER, "count 0xffffffff\n");
            ok(Pairs == (PSOCKADDR_IN6_PAIR)0x1234 && Count == 77, "outputs after a rejected count: %p %lu\n", Pairs, Count);
            HeapFree(GetProcessHeap(), 0, Many);
        }
    }
}

/* the first Wanted pairs must be these destinations, each with this source */
static BOOL Sorted(const char *Label, SOCKADDR_IN6 *Dest, ULONG N, const SOCKADDR_IN6 *Expect, ULONG Wanted)
{
    PSOCKADDR_IN6_PAIR Pairs = NULL;
    ULONG Count = 0, i;
    DWORD Error;
    BOOL Good = TRUE;

    Error = pCreate(NULL, 0, Dest, N, 0, &Pairs, &Count);
    ok(Error == NO_ERROR, "%s: error %lu\n", Label, Error);
    if (Error != NO_ERROR)
        return FALSE;
    ok(Count == Wanted, "%s: %lu pairs, expected %lu\n", Label, Count, Wanted);
    for (i = 0; i < Count && i < Wanted; i++)
    {
        char A[64], B[64];

        if (!Pairs[i].DestinationAddress || !Pairs[i].SourceAddress)
        {
            ok(0, "%s: pair %lu has a NULL address\n", Label, i);
            Good = FALSE;
            continue;
        }
        Text(Pairs[i].DestinationAddress, A);
        Text(&Expect[i], B);
        ok(!memcmp(&Pairs[i].DestinationAddress->sin6_addr, &Expect[i].sin6_addr, 16), "%s: pair %lu is %s, expected %s\n",
           Label, i, A, B);
        ok(Pairs[i].SourceAddress->sin6_family == AF_INET6, "%s: pair %lu source family %d\n", Label, i,
           Pairs[i].SourceAddress->sin6_family);
        /* a source is of the family of its destination */
        ok(IsMappedAddr(Pairs[i].SourceAddress) == IsMappedAddr(Pairs[i].DestinationAddress),
           "%s: pair %lu mixes the families\n", Label, i);
    }
    if (Pairs)
        pFree(Pairs);
    return Good;
}

static BOOL FirstAdapterAddress(SOCKADDR_IN6 *Out)
{
    ULONG Size = 0, i;
    PMIB_IPADDRTABLE Table;
    BOOL Found = FALSE;

    GetIpAddrTable(NULL, &Size, FALSE);
    Table = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Table)
        return FALSE;
    if (GetIpAddrTable(Table, &Size, FALSE) == NO_ERROR)
    {
        for (i = 0; i < Table->dwNumEntries; i++)
        {
            DWORD Address = Table->table[i].dwAddr;
            UCHAR *B = (UCHAR *)&Address;

            if (Address && B[0] != 127 && !(B[0] == 169 && B[1] == 254))
            {
                Mapped(Out, B[0], B[1], B[2], B[3]);
                Found = TRUE;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Table);
    return Found;
}

static BOOL Ipv6On;

static void TestOrder(void)
{
    SOCKADDR_IN6 D[4], E[4], Own;
    PSOCKADDR_IN6_PAIR Pairs = NULL;
    ULONG Count = 0;

    /* IPv6 on: ::1 can be reached and is its own source (with IPv6 off nothing is reachable, and the pair has no source) */
    Loop6(&D[0]);
    if (pCreate(NULL, 0, D, 1, 0, &Pairs, &Count) == NO_ERROR && Count == 1 &&
        !memcmp(&Pairs[0].SourceAddress->sin6_addr, &D[0].sin6_addr, 16))
        Ipv6On = TRUE;
    if (Pairs)
        pFree(Pairs);
    if (!Ipv6On)
        skip("IPv6 is off: no ::1\n");

    /* 127.0.0.1 and ::1: ::1 has the higher precedence (50) whatever the order given */
    Mapped(&D[0], 127, 0, 0, 1);
    Loop6(&D[1]);
    if (Ipv6On)
    {
        E[0] = D[1];
        E[1] = D[0];
        Sorted("::1 before 127.0.0.1", D, 2, E, 2);
        D[0] = E[0];
        D[1] = E[1];
        Sorted("::1 before 127.0.0.1 (given sorted)", D, 2, E, 2);
    }

    /* 127.0.0.2 is not an address of the host: after 127.0.0.1 whatever the order given; the source is 127.0.0.1 */
    Mapped(&D[0], 127, 0, 0, 2);
    Mapped(&D[1], 127, 0, 0, 1);
    E[0] = D[1];
    E[1] = D[0];
    if (Sorted("127.0.0.1 before 127.0.0.2", D, 2, E, 2))
    {
        ULONG n = 0;

        pCreate(NULL, 0, D, 2, 0, &Pairs, &n);
        if (Pairs && n == 2)
            ok(Pairs[1].SourceAddress->sin6_addr.u.Byte[15] == 1 && Pairs[1].SourceAddress->sin6_addr.u.Byte[12] == 127,
               "the source of 127.0.0.2 is not 127.0.0.1\n");
        if (Pairs)
            pFree(Pairs);
    }

    /* equal destinations keep the order they were given */
    Mapped(&D[0], 127, 0, 0, 3);
    Mapped(&D[1], 127, 0, 0, 2);
    Mapped(&D[2], 127, 0, 0, 4);
    Sorted("stable", D, 3, D, 3);
    E[0] = D[2];
    E[1] = D[1];
    E[2] = D[0];
    Sorted("stable (reversed)", E, 3, E, 3);

    /* the host's own address before the loopback one, and the source is the address itself */
    if (FirstAdapterAddress(&Own))
    {
        Mapped(&D[0], 127, 0, 0, 1);
        D[1] = Own;
        E[0] = Own;
        E[1] = D[0];
        Sorted("own address before 127.0.0.1", D, 2, E, 2);
        if (pCreate(NULL, 0, &Own, 1, 0, &Pairs, &Count) == NO_ERROR && Count == 1)
            ok(!memcmp(&Pairs[0].SourceAddress->sin6_addr, &Own.sin6_addr, 16), "the source of an own address is itself\n");
        if (Pairs)
            pFree(Pairs);
    }
    else
        skip("no IPv4 address on an adapter\n");

    /* a destination list is not changed: the caller's array keeps its order */
    Mapped(&D[0], 127, 0, 0, 2);
    Mapped(&D[1], 127, 0, 0, 1);
    pCreate(NULL, 0, D, 2, 0, &Pairs, &Count);
    ok(D[0].sin6_addr.u.Byte[15] == 2 && D[1].sin6_addr.u.Byte[15] == 1, "the input list was changed\n");
    if (Pairs)
        pFree(Pairs);
}

/* whatever the network: a list comes back (the reachable destinations, or all of them when none can be reached) */
static void TestAlwaysAList(void)
{
    SOCKADDR_IN6 D[2];
    PSOCKADDR_IN6_PAIR Pairs = NULL;
    ULONG Count = 0, i;
    DWORD Error;

    Mapped(&D[0], 198, 51, 100, 1);
    memset(&D[1], 0, sizeof(D[1]));
    D[1].sin6_family = AF_INET6;
    D[1].sin6_addr.u.Byte[0] = 0x20;
    D[1].sin6_addr.u.Byte[1] = 0x01;
    D[1].sin6_addr.u.Byte[2] = 0x0d;
    D[1].sin6_addr.u.Byte[3] = 0xb8;
    D[1].sin6_addr.u.Byte[15] = 1;
    Error = pCreate(NULL, 0, D, 2, 0, &Pairs, &Count);
    ok(Error == NO_ERROR, "documentation addresses: %lu\n", Error);
    ok(Pairs != NULL && Count >= 1 && Count <= 2, "documentation addresses: %p, %lu pairs\n", Pairs, Count);
    for (i = 0; Pairs && i < Count; i++)
        ok(Pairs[i].SourceAddress && Pairs[i].DestinationAddress, "pair %lu has a NULL address\n", i);
    if (Pairs)
        pFree(Pairs);
}

#define KEY L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"

/* HKLM\...\Tcpip6\Parameters\PrefixPolicies replaces the table: IPv4 preferred over ::1 */
static void TestRegistryPolicy(void)
{
    HKEY Key;
    DWORD Disposition, Type = 0, Size = 0, Error;
    PBYTE Saved = NULL;
    BOOL Had = FALSE;
    SOCKADDR_IN6 D[2], E[2];
    static const WCHAR Prefer4[] = L"::1/128 50 0\0::ffff:0:0/96 60 4\0::/0 40 1\0";

    if (!Ipv6On)
    {
        skip("IPv6 is off\n");
        return;
    }
    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, KEY, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &Key, &Disposition);
    if (Error != ERROR_SUCCESS)
    {
        skip("cannot open the Tcpip6 Parameters key (%lu)\n", Error);
        return;
    }
    if (RegQueryValueExW(Key, L"PrefixPolicies", NULL, &Type, NULL, &Size) == ERROR_SUCCESS)
    {
        Saved = HeapAlloc(GetProcessHeap(), 0, Size);
        if (Saved && RegQueryValueExW(Key, L"PrefixPolicies", NULL, &Type, Saved, &Size) == ERROR_SUCCESS)
            Had = TRUE;
    }

    Mapped(&D[0], 127, 0, 0, 1);
    Loop6(&D[1]);
    E[0] = D[1];
    E[1] = D[0];
    RegDeleteValueW(Key, L"PrefixPolicies");
    Sorted("default table", D, 2, E, 2);

    Error = RegSetValueExW(Key, L"PrefixPolicies", 0, REG_MULTI_SZ, (const BYTE *)Prefer4, sizeof(Prefer4) + sizeof(WCHAR));
    ok(Error == ERROR_SUCCESS, "set value: %lu\n", Error);
    E[0] = D[0];
    E[1] = D[1];
    Sorted("IPv4 first by the table", D, 2, E, 2);

    /* a value without a valid line leaves the defaults */
    Error = RegSetValueExW(Key, L"PrefixPolicies", 0, REG_MULTI_SZ, (const BYTE *)L"garbage\0\0", 18);
    ok(Error == ERROR_SUCCESS, "set bad value: %lu\n", Error);
    E[0] = D[1];
    E[1] = D[0];
    Sorted("invalid table is ignored", D, 2, E, 2);

    if (Had)
        RegSetValueExW(Key, L"PrefixPolicies", 0, Type, Saved, Size);
    else
        RegDeleteValueW(Key, L"PrefixPolicies");
    Sorted("table restored", D, 2, E, 2);
    HeapFree(GetProcessHeap(), 0, Saved);
    RegCloseKey(Key);
    if (Disposition == REG_CREATED_NEW_KEY)
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, KEY);
}

START_TEST(CreateSortedAddressPairs)
{
    HMODULE Module = LoadLibraryW(L"iphlpapi.dll");

    pCreate = (PCREATE_SORTED_ADDRESS_PAIRS)GetProcAddress(Module, "CreateSortedAddressPairs");
    pFree = (PFREE_MIB_TABLE)GetProcAddress(Module, "FreeMibTable");
    if (!pCreate || !pFree)
    {
        skip("CreateSortedAddressPairs is not exported\n");
        return;
    }

    TestParameters();
    TestOrder();
    TestAlwaysAList();
    TestRegistryPolicy();
}
