/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Configured IPv6 addresses of tcpip.sys (IOCTL_IP6_ADDRESS_CONFIG, a private request of this stack): a
 *              created address is tentative, then preferred once duplicate address detection passed (nobody on the
 *              test link has it); it is listed by GetUnicastIpAddressTable with what was asked for it, announced by
 *              NotifyUnicastIpAddressChange, gives its on-link prefix to the route table, is the source the stack and
 *              GetBestRoute2 choose for its prefix (not with skip-as-source), can be bound; it changes, goes when its
 *              valid lifetime ends, and is removed. Invalid requests fail without a change, the address slots of an
 *              interface run out. Without IPv6 the request is not supported.
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
static DWORD (WINAPI *pNotifyUnicastIpAddressChange)(USHORT, PVOID, PVOID, BOOLEAN, HANDLE *);
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

#define DAD_TENTATIVE   1
#define DAD_DEPRECATED  3
#define DAD_PREFERRED   4
#define ORIGIN_MANUAL   1

static ULONG LoopbackIndex;

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

static NTSTATUS AddressRequest(ULONG Operation, ULONG IfIndex, const char *Address, ULONG Length, ULONG Valid,
                               ULONG Preferred, ULONG Flags)
{
    TCP_IPV6_ADDRESS_REQUEST Request;
    SOCKADDR_INET Parsed;

    memset(&Request, 0, sizeof(Request));
    Request.Operation = Operation;
    Request.Store = TCP_IPV6_STORE_ACTIVE;
    Request.IfIndex = IfIndex;
    Ipv6Parse(&Parsed, Address, 0);
    memcpy(Request.Address, &Parsed.Ipv6.sin6_addr, 16);
    Request.PrefixLength = Length;
    Request.ValidLifetime = Valid;
    Request.PreferredLifetime = Preferred;
    Request.PrefixOrigin = ORIGIN_MANUAL;
    Request.SuffixOrigin = ORIGIN_MANUAL;
    Request.Flags = Flags;
    return SendRequest(IOCTL_IP6_ADDRESS_CONFIG, &Request, sizeof(Request));
}

static BOOL SameAddress(const SOCKADDR_INET *A, const char *Text)
{
    SOCKADDR_INET B;

    Ipv6Parse(&B, Text, 0);
    return A->si_family == AF_INET6 && !memcmp(&A->Ipv6.sin6_addr, &B.Ipv6.sin6_addr, 16);
}

/* The first interface with a link-local address that is not the loopback interface (0: none) */
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

static BOOL FindAddress(ULONG IfIndex, const char *Address, UNICAST_ROW6 *Out)
{
    UNICAST_TABLE6 *Table = NULL;
    ULONG i;
    BOOL Found = FALSE;

    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries && !Found; i++)
    {
        if (Table->Table[i].InterfaceIndex == IfIndex && SameAddress(&Table->Table[i].Address, Address))
        {
            *Out = Table->Table[i];
            Found = TRUE;
        }
    }
    pFreeMibTable(Table);
    return Found;
}

#define ORIGIN_RANDOM   5

/* Whether the interface has a preferred temporary address (SuffixOrigin Random, RFC 8981), and whether Source is one */
/* A global address of the default policy table's label 1 (::/0): not link-local, site-local, unique local, 6to4,
   Teredo (2001::/32) or 3ffe::/16, so RFC 6724 rules 2 and 6 rank it as they rank 2001:db8:99::5 */
static BOOL GlobalLabelOne(const UCHAR *A)
{
    if (A[0] == 0xfe && ((A[1] & 0xc0) == 0x80 || (A[1] & 0xc0) == 0xc0))
        return FALSE;
    if ((A[0] & 0xfe) == 0xfc)
        return FALSE;
    if (A[0] == 0x20 && A[1] == 0x02)
        return FALSE;
    if (A[0] == 0x20 && A[1] == 0x01 && A[2] == 0 && A[3] == 0)
        return FALSE;
    if (A[0] == 0x3f && A[1] == 0xfe)
        return FALSE;
    return TRUE;
}

/* A preferred temporary address of the interface that competes with the configured one for a destination in its
   prefix: of the same scope and label, so only rule 7 tells them apart (a temporary address of a site-local SLAAC
   prefix, as QEMU's user network gives, loses at rule 2, one of another label at rule 6) */
static BOOL HasTemporary(ULONG IfIndex, const SOCKADDR_INET *Source, BOOL *SourceIsTemporary)
{
    UNICAST_TABLE6 *Table = NULL;
    ULONG i;
    BOOL Has = FALSE;

    *SourceIsTemporary = FALSE;
    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const UNICAST_ROW6 *Row = &Table->Table[i];

        if (Row->InterfaceIndex != IfIndex || Row->SuffixOrigin != ORIGIN_RANDOM || Row->DadState != DAD_PREFERRED ||
            !GlobalLabelOne(Row->Address.Ipv6.sin6_addr.u.Byte))
            continue;
        Has = TRUE;
        if (Source->si_family == AF_INET6 && !memcmp(&Source->Ipv6.sin6_addr, &Row->Address.Ipv6.sin6_addr, 16))
            *SourceIsTemporary = TRUE;
    }
    pFreeMibTable(Table);
    return Has;
}

static BOOL WaitState(ULONG IfIndex, const char *Address, ULONG State, UNICAST_ROW6 *Out)
{
    int i;

    for (i = 0; i < 100; i++)
    {
        if (FindAddress(IfIndex, Address, Out) && Out->DadState == State)
            return TRUE;
        Sleep(100);
    }
    return FALSE;
}

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

static LONG Added, Deleted;

static VOID WINAPI AddressCallback(PVOID Context, UNICAST_ROW6 *Row, ULONG Type)
{
    UNREFERENCED_PARAMETER(Context);

    if (!Row || !SameAddress(&Row->Address, "2001:db8:99::5"))
        return;
    if (Type == 1)          /* MibAddInstance */
        InterlockedIncrement(&Added);
    else if (Type == 2)     /* MibDeleteInstance */
        InterlockedIncrement(&Deleted);
}

static BOOL WaitCount(volatile LONG *Count, LONG Want)
{
    int i;

    for (i = 0; i < 50 && *Count < Want; i++)
        Sleep(100);
    return *Count >= Want;
}

/* A creation of 2001:db8:99::8 with these origins (the stack reports them to user mode as they are) */
static NTSTATUS OriginsRequest(ULONG IfIndex, ULONG Prefix, ULONG Suffix)
{
    TCP_IPV6_ADDRESS_REQUEST Request;
    SOCKADDR_INET Parsed;

    memset(&Request, 0, sizeof(Request));
    Request.Operation = TCP_IPV6_CONFIG_CREATE;
    Request.Store = TCP_IPV6_STORE_ACTIVE;
    Request.IfIndex = IfIndex;
    Ipv6Parse(&Parsed, "2001:db8:99::8", 0);
    memcpy(Request.Address, &Parsed.Ipv6.sin6_addr, 16);
    Request.PrefixLength = 64;
    Request.ValidLifetime = Request.PreferredLifetime = ~0UL;
    Request.PrefixOrigin = Prefix;
    Request.SuffixOrigin = Suffix;
    return SendRequest(IOCTL_IP6_ADDRESS_CONFIG, &Request, sizeof(Request));
}

static void TestOriginsAndFlags(ULONG IfIndex)
{
    static const struct { ULONG Prefix, Suffix; NTSTATUS Status; } Origins[] =
    {
        { 16, 1, STATUS_INVALID_PARAMETER }, { 1, 16, STATUS_INVALID_PARAMETER }, { 16, 16, STATUS_INVALID_PARAMETER },
        { 17, 1, STATUS_INVALID_PARAMETER }, { 1, 100, STATUS_INVALID_PARAMETER },
        { 0xfffffff7, 1, STATUS_INVALID_PARAMETER }, { 1, 0x10000, STATUS_INVALID_PARAMETER },
        { 0, 0, STATUS_SUCCESS }, { 15, 1, STATUS_SUCCESS }, { 1, 0xfffffff8, STATUS_SUCCESS },
        { 0xffffffff, 0xffffffff, STATUS_SUCCESS },
    };
    NTSTATUS Status;
    ULONG i;

    for (i = 0; i < sizeof(Origins) / sizeof(Origins[0]); i++)
    {
        Status = OriginsRequest(IfIndex, Origins[i].Prefix, Origins[i].Suffix);
        ok(Status == Origins[i].Status, "origins %lx/%lx: %lx\n", Origins[i].Prefix, Origins[i].Suffix, Status);
        if (NT_SUCCESS(Status))
            AddressRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:99::8", 64, 0, 0, 0);
    }
    /* flags the request does not know (the other bits are the row's) */
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::8", 64, ~0UL, ~0UL, 0x2);
    ok(Status == STATUS_INVALID_PARAMETER, "flag 2: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::8", 64, ~0UL, ~0UL, 0x80);
    ok(Status == STATUS_INVALID_PARAMETER, "flag 0x80: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::8", 64, ~0UL, ~0UL, 0x1);
    ok(Status == STATUS_SUCCESS, "skip as source: %lx\n", Status);
    AddressRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:99::8", 64, 0, 0, 0);
}

static void TestInvalid(ULONG IfIndex)
{
    TCP_IPV6_ADDRESS_REQUEST Request;
    NTSTATUS Status;

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "ff02::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "multicast: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "::", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "unspecified: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "::1", 128, ~0UL, ~0UL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "loopback: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "::ffff:192.0.2.5", 96, ~0UL, ~0UL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "v4-mapped: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::5", 129, ~0UL, ~0UL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "prefix length 129: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::5", 64, 0, 0, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "valid lifetime 0: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::5", 64, 100, 200, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "preferred over valid: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, 0x7ffffff0, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_NOT_FOUND, "unknown interface: %lx\n", Status);
    if (LoopbackIndex)
    {
        Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, LoopbackIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
        ok(Status == STATUS_NOT_FOUND, "loopback interface: %lx\n", Status);
    }
    Status = AddressRequest(7, IfIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "operation 7: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_SET, IfIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_NOT_FOUND, "change of an address that is not there: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_NOT_FOUND, "removal of an address that is not there: %lx\n", Status);

    memset(&Request, 0, sizeof(Request));
    Status = SendRequest(IOCTL_IP6_ADDRESS_CONFIG, &Request, sizeof(Request) - 1);
    ok(Status == STATUS_INVALID_PARAMETER, "short request: %lx\n", Status);
}

/* The source GetBestRoute2 answers for the multicast address Text */
static void TestMulticastSource(ULONG IfIndex, const char *Text)
{
    SOCKADDR_INET Dest, Source;
    ROUTE_ROW6 Route;
    SOCKET Socket;
    DWORD Error;
    BOOL Link, Site;

    Ipv6Parse(&Dest, Text, IfIndex);
    Dest.Ipv6.sin6_port = htons(9);
    Error = pGetBestRoute2(NULL, IfIndex, NULL, &Dest, 0, &Route, &Source);
    ok(Error == NO_ERROR, "%s: GetBestRoute2: %lu\n", Text, Error);
    if (Error != NO_ERROR)
        return;

    /* the link-local address for a link-scope destination, an address of at least the scope for a larger one (the
       global address 2001:db8:99::5 and the site-local SLAAC address are there as well as the link-local one) */
    Link = Source.Ipv6.sin6_addr.u.Byte[0] == 0xfe && (Source.Ipv6.sin6_addr.u.Byte[1] & 0xc0) == 0x80;
    Site = Source.Ipv6.sin6_addr.u.Byte[0] == 0xfe && (Source.Ipv6.sin6_addr.u.Byte[1] & 0xc0) == 0xc0;
    if (Dest.Ipv6.sin6_addr.u.Byte[1] <= 0x02)
        ok(Link, "%s: source is not link-local\n", Text);
    else if (Dest.Ipv6.sin6_addr.u.Byte[1] == 0x05)
        ok(!Link, "%s: source is link-local\n", Text);
    else
        ok(!Link && !Site, "%s: source is not of global scope\n", Text);

    /* a datagram goes out with the same choice (the stack's source is not visible here: a socket connected to a
       multicast address stays unbound; the wire shows it in the lane's bed) */
    Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    ok(Socket != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
    if (Socket != INVALID_SOCKET)
    {
        ok(sendto(Socket, "x", 1, 0, (struct sockaddr *)&Dest.Ipv6, sizeof(Dest.Ipv6)) == 1, "%s: sendto: %d\n", Text,
           WSAGetLastError());
        closesocket(Socket);
    }
}

static void TestAddress(ULONG IfIndex)
{
    UNICAST_ROW6 Row;
    ROUTE_ROW6 Route;
    SOCKADDR_INET Dest, Source, Bind;
    HANDLE Handle = NULL;
    NTSTATUS Status;
    DWORD Error;
    SOCKET Socket;

    Error = pNotifyUnicastIpAddressChange(AF_INET6, AddressCallback, NULL, FALSE, &Handle);
    ok(Error == NO_ERROR, "NotifyUnicastIpAddressChange: %lu\n", Error);

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_SUCCESS, "create: %lx\n", Status);
    if (!NT_SUCCESS(Status))
        goto Out;
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_OBJECT_NAME_COLLISION, "create again: %lx\n", Status);

    ok(FindAddress(IfIndex, "2001:db8:99::5", &Row), "address not listed\n");
    ok(Row.DadState == DAD_TENTATIVE || Row.DadState == DAD_PREFERRED, "first state %lu\n", Row.DadState);
    ok(WaitState(IfIndex, "2001:db8:99::5", DAD_PREFERRED, &Row), "not preferred: state %lu\n", Row.DadState);
    ok(Row.OnLinkPrefixLength == 64, "prefix length %u\n", Row.OnLinkPrefixLength);
    ok(Row.PrefixOrigin == ORIGIN_MANUAL && Row.SuffixOrigin == ORIGIN_MANUAL, "origins %lu %lu\n",
       Row.PrefixOrigin, Row.SuffixOrigin);
    ok(Row.ValidLifetime == 0xffffffff && Row.PreferredLifetime == 0xffffffff, "lifetimes %lu %lu\n",
       Row.ValidLifetime, Row.PreferredLifetime);
    ok(!Row.SkipAsSource, "skip as source\n");
    ok(Row.Address.Ipv6.sin6_scope_id == 0, "scope %lu\n", Row.Address.Ipv6.sin6_scope_id);
    if (Handle)
        ok(WaitCount(&Added, 1), "no add notification\n");

    /* its on-link prefix and its host route */
    ok(FindRoute(IfIndex, "2001:db8:99::", 64, &Route), "no on-link prefix route\n");
    ok(Route.Protocol == 2 && Route.Origin == 0 && Ipv6IsZero(Route.NextHop.Ipv6.sin6_addr.u.Byte),
       "on-link route protocol %lu origin %lu\n", Route.Protocol, Route.Origin);
    ok(FindRoute(IfIndex, "2001:db8:99::5", 128, &Route) && Route.Loopback, "no host route\n");

    /* the source of its prefix */
    Ipv6Parse(&Dest, "2001:db8:99::77", 0);
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Route, &Source);
    ok(Error == NO_ERROR, "GetBestRoute2: %lu\n", Error);
    ok(Error != NO_ERROR || (Route.InterfaceIndex == IfIndex && Route.DestinationPrefix.PrefixLength == 64),
       "best route /%u over %lu\n", Route.DestinationPrefix.PrefixLength, Route.InterfaceIndex);
    if (Error == NO_ERROR)
    {
        BOOL IsTemporary, Has = HasTemporary(IfIndex, &Source, &IsTemporary);

        /* RFC 6724 5: rule 7 (a temporary address, of the SLAAC prefix when the interface has one) comes before rule 8
           (the longest common prefix with the destination), so with a temporary address of the same scope and label
           (rules 2 and 6 come first) the source is that one */
        if (Has)
            ok(IsTemporary, "source is not the temporary address\n");
        else
            ok(SameAddress(&Source, "2001:db8:99::5"), "source is not the address\n");
    }

    /* a multicast destination: ff01/ff02 take the link-local address (rule 2), ff05 and ff0e the address of their
       scope, and the stack answers the same as GetBestRoute2 (global address and link-local address present) */
    TestMulticastSource(IfIndex, "ff01::1");
    TestMulticastSource(IfIndex, "ff02::1");
    TestMulticastSource(IfIndex, "ff05::1:3");
    TestMulticastSource(IfIndex, "ff0e::1");

    /* it can be bound, and a datagram from it to its prefix is sent on the link */
    Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    ok(Socket != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
    if (Socket != INVALID_SOCKET)
    {
        int i;

        Ipv6Parse(&Bind, "2001:db8:99::5", 0);
        ok(bind(Socket, (struct sockaddr *)&Bind.Ipv6, sizeof(Bind.Ipv6)) == 0, "bind: %d\n", WSAGetLastError());
        Dest.Ipv6.sin6_port = htons(9);
        sendto(Socket, "x", 1, 0, (struct sockaddr *)&Dest.Ipv6, sizeof(Dest.Ipv6));
        for (i = 0; i < 20 && !HasNeighbor(IfIndex, "2001:db8:99::77"); i++)
            Sleep(100);
        ok(i < 20, "no neighbour entry for the destination on the link\n");
        closesocket(Socket);
    }

    /* a change: skip-as-source, a /48 */
    Status = AddressRequest(TCP_IPV6_CONFIG_SET, IfIndex, "2001:db8:99::5", 48, ~0UL, ~0UL,
                            TCP_IPV6_ADDRESS_SKIP_AS_SOURCE);
    ok(Status == STATUS_SUCCESS, "set: %lx\n", Status);
    ok(FindAddress(IfIndex, "2001:db8:99::5", &Row), "address not listed after the change\n");
    ok(Row.SkipAsSource, "not skip-as-source\n");
    ok(Row.OnLinkPrefixLength == 48, "prefix length %u\n", Row.OnLinkPrefixLength);
    ok(Row.DadState == DAD_PREFERRED, "state %lu\n", Row.DadState);
    ok(FindRoute(IfIndex, "2001:db8:99::", 48, &Route), "no /48 on-link route\n");
    ok(!FindRoute(IfIndex, "2001:db8:99::", 64, &Route), "the /64 on-link route stayed\n");
    Error = pGetBestRoute2(NULL, 0, NULL, &Dest, 0, &Route, &Source);
    ok(Error == NO_ERROR, "GetBestRoute2: %lu\n", Error);
    ok(Error != NO_ERROR || !SameAddress(&Source, "2001:db8:99::5"), "source is the skip-as-source address\n");

    /* a deprecated one: preferred lifetime 0 */
    Status = AddressRequest(TCP_IPV6_CONFIG_SET, IfIndex, "2001:db8:99::5", 64, 600, 0, 0);
    ok(Status == STATUS_SUCCESS, "set deprecated: %lx\n", Status);
    ok(FindAddress(IfIndex, "2001:db8:99::5", &Row) && Row.DadState == DAD_DEPRECATED, "state %lu\n", Row.DadState);
    ok(Row.ValidLifetime <= 600 && Row.ValidLifetime >= 590, "valid lifetime %lu\n", Row.ValidLifetime);

    /* the end of its valid lifetime removes it */
    Status = AddressRequest(TCP_IPV6_CONFIG_SET, IfIndex, "2001:db8:99::5", 64, 3, 3, 0);
    ok(Status == STATUS_SUCCESS, "set short: %lx\n", Status);
    Sleep(5000);
    ok(!FindAddress(IfIndex, "2001:db8:99::5", &Row), "address still listed after its lifetime\n");
    ok(!FindRoute(IfIndex, "2001:db8:99::", 64, &Route), "on-link route still listed after the address went\n");
    if (Handle)
        ok(WaitCount(&Deleted, 1), "no delete notification\n");
    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:99::5", 64, 0, 0, 0);
    ok(Status == STATUS_NOT_FOUND, "delete after the lifetime: %lx\n", Status);

    /* created and removed */
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
    ok(Status == STATUS_SUCCESS, "create again: %lx\n", Status);
    /* the notification compares tables: an address that came and went before it looked is no change */
    if (Handle)
        ok(WaitCount(&Added, 2), "no add notification\n");
    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, "2001:db8:99::5", 0, 0, 0, 0);
    ok(Status == STATUS_SUCCESS, "delete: %lx\n", Status);
    ok(!FindAddress(IfIndex, "2001:db8:99::5", &Row), "address still listed\n");
    if (Handle)
        ok(WaitCount(&Deleted, 2), "no delete notification\n");

Out:
    if (Handle)
        pCancelMibChangeNotify2(Handle);
}

/* The address slots of an interface run out; nothing stays */
static void TestSlots(ULONG IfIndex)
{
    char Text[64];
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Made = 0, i;
    UNICAST_ROW6 Row;

    for (i = 0; i < 40 && NT_SUCCESS(Status); i++)
    {
        sprintf(Text, "2001:db8:9a::%lu", i + 1);
        Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, IfIndex, Text, 64, ~0UL, ~0UL, 0);
        if (NT_SUCCESS(Status))
            Made++;
    }
    ok(Status == STATUS_INSUFFICIENT_RESOURCES, "last create: %lx\n", Status);
    ok(Made >= 4 && Made <= 15, "%lu addresses made\n", Made);
    for (i = 0; i < Made; i++)
    {
        sprintf(Text, "2001:db8:9a::%lu", i + 1);
        Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, IfIndex, Text, 64, 0, 0, 0);
        ok(Status == STATUS_SUCCESS, "delete %s: %lx\n", Text, Status);
        ok(!FindAddress(IfIndex, Text, &Row), "%s still listed\n", Text);
    }
}

START_TEST(Ipv6AddressConfig)
{
    WSADATA Data;
    ULONG IfIndex;
    NTSTATUS Status;

    pGetIpForwardTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpForwardTable2");
    pGetIpNetTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpNetTable2");
    pGetUnicastIpAddressTable = (PFN_GET_TABLE)Ipv6Proc("GetUnicastIpAddressTable");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    pGetBestRoute2 = (PFN_BEST_ROUTE)Ipv6Proc("GetBestRoute2");
    pNotifyUnicastIpAddressChange = (PVOID)Ipv6Proc("NotifyUnicastIpAddressChange");
    pCancelMibChangeNotify2 = (PVOID)Ipv6Proc("CancelMibChangeNotify2");
    if (!pGetIpForwardTable2 || !pGetIpNetTable2 || !pGetUnicastIpAddressTable || !pFreeMibTable || !pGetBestRoute2 ||
        !pNotifyUnicastIpAddressChange || !pCancelMibChangeNotify2)
    {
        skip("the IP Helper functions are missing\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Data);

    if (!Ipv6SocketsWork())
    {
        Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, 2, "2001:db8:99::5", 64, ~0UL, ~0UL, 0);
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
    TestOriginsAndFlags(IfIndex);
    TestAddress(IfIndex);
    TestSlots(IfIndex);
    WSACleanup();
}
