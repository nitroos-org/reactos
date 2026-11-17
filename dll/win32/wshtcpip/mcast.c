/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Multicast groups and source filters of a datagram socket (RFC 3678 as Windows has it)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The protocol-independent options MCAST_JOIN_GROUP, MCAST_LEAVE_GROUP, MCAST_BLOCK_SOURCE, MCAST_UNBLOCK_SOURCE,
 * MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP (struct group_req / group_source_req), the IPv4 ones
 * IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP, IP_BLOCK_SOURCE,
 * IP_UNBLOCK_SOURCE (struct ip_mreq / ip_mreq_source), IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP (struct
 * ipv6_mreq), and the ioctls SIOCSMSFILTER / SIOCGMSFILTER (struct group_filter, both families) and
 * SIO_SET_MULTICAST_FILTER / SIO_GET_MULTICAST_FILTER (struct ip_msfilter, IPv4).
 *
 * The socket's groups are kept here (each with its interface, filter mode and source list): the socket API's
 * rules and answers are applied to them, and after every change the group's whole filter goes to the stack
 * (NITRO_AO_OPTION_MCAST_FILTER, nitrotdi.h), which filters what the socket receives and reports the merged
 * filter of all sockets with MLD (IPv6). Before the bind the groups stay in the table (an unbound socket joins and
 * reads its filters back, as on Windows) and go to the stack at the bind (WshMcastBind), one request per group, where
 * a refusal fails the bind. A group's interface is fixed at its join: a request without one is for the socket's join
 * of the group wherever it landed (as the stack finds it), an IPv4 join without one is on every adapter. The answers are those of Windows Server 2022
 * (64 and 32 bit identical; evidence v6mld2-20261116):
 *   - join twice WSAEINVAL; leave of a group not joined WSAEADDRNOTAVAIL; block / unblock / source leave on a group
 *     not joined WSAEINVAL;
 *   - a source join on an any-source group, a block on a source-specific one, a group join on a source-specific
 *     one: WSAEINVAL; a source joined or blocked twice WSAEADDRINUSE; a source left or unblocked that is not there
 *     WSAEADDRNOTAVAIL; the last source left leaves the group; MCAST_LEAVE_GROUP / IP_DROP_MEMBERSHIP /
 *     IPV6_DROP_MEMBERSHIP leave a source-specific group too;
 *   - a group that is no multicast address, of the other family, or of family 0, a source that is multicast or
 *     unspecified, an interface that does not exist: WSAEADDRNOTAVAIL; a short request (or none) WSAEFAULT; a
 *     stream socket WSAEINVAL (a raw socket takes IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP); an IPv6 join with interface 0
 *     is on the default interface (found with its index too);
 *   - an AF_INET socket takes the options at IPPROTO_IP and (for IPv4 groups) at IPPROTO_IPV6; an AF_INET6 socket
 *     takes IPv6 groups at IPPROTO_IPV6 and, when it is dual stack (IPV6_V6ONLY off), IPv4 groups at IPPROTO_IP;
 *     IPPROTO_IP on an IPv6-only socket WSAEINVAL;
 *   - the ioctls: a short input WSAEINVAL, no output buffer WSAEFAULT, room for fewer sources than the filter has
 *     WSAEFAULT, a group not joined WSAEINVAL, duplicate sources in a filter WSAEADDRINUSE; a filter of INCLUDE with
 *     no source leaves the group; the answer is as long as the filter (GROUP_FILTER_SIZE / IP_MSFILTER_SIZE);
 *     SIO_*_MULTICAST_FILTER on an AF_INET6 socket WSAEINVAL;
 *   - the options are not readable (getsockopt WSAENOPROTOOPT, the generic answer).
 * Differences (release notes): at most NITRO_MCAST_MAX_SOURCES sources per group and 20 groups per socket (Windows
 * took 1100 and 300 without an error); a source of the other family is taken as Windows takes it, but which source
 * Windows then filters is not known (here: the IPv4-mapped form, or the last four bytes).
 */

#include "wshtcpip.h"
#include <iphlpapi.h>
#include <nitrotdi.h>

#define NDEBUG
#include <debug.h>

#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP            41
#define MCAST_LEAVE_GROUP           42
#define MCAST_BLOCK_SOURCE          43
#define MCAST_UNBLOCK_SOURCE        44
#define MCAST_JOIN_SOURCE_GROUP     45
#define MCAST_LEAVE_SOURCE_GROUP    46
#endif
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP 12
#define IPV6_DROP_MEMBERSHIP 13
#endif
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

C_ASSERT(MCAST_INCLUDE == NITRO_MCAST_INCLUDE && MCAST_EXCLUDE == NITRO_MCAST_EXCLUDE);

typedef struct _WSH_MCAST {
    struct _WSH_MCAST *Next;
    UCHAR Family;               /* NITRO_MCAST_FAMILY_IP / _IP6 */
    UCHAR Mode;                 /* MCAST_INCLUDE / MCAST_EXCLUDE */
    UCHAR Group[16];
    ULONG Given;                /* the interface the join named (0: none; the lookups follow the stack's: a request
                                   without an interface is for the socket's join of the group, wherever it landed) */
    ULONG IfIndex;              /* what the stack was given at the join: the same, or for IPv6 the default interface
                                   then (0: the stack's choice); kept, never resolved again */
    ULONG NumSources;
    UCHAR (*Sources)[16];
} WSH_MCAST, *PWSH_MCAST;

/* The operations the options and ioctls come to */
typedef enum _WSH_MCAST_OP {
    McastJoin,                  /* MCAST_JOIN_GROUP, IP_ADD_MEMBERSHIP, IPV6_ADD_MEMBERSHIP */
    McastLeave,                 /* MCAST_LEAVE_GROUP, IP_DROP_MEMBERSHIP, IPV6_DROP_MEMBERSHIP */
    McastBlock,
    McastUnblock,
    McastJoinSource,
    McastLeaveSource
} WSH_MCAST_OP;

typedef ULONG (WINAPI *PGET_ADAPTERS_ADDRESSES)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
typedef PCHAR (WINAPI *PIF_INDEXTONAME)(ULONG, PCHAR);

static PGET_ADAPTERS_ADDRESSES WshGetAdaptersAddresses;
static PIF_INDEXTONAME WshIfIndexToName;

static
BOOLEAN
WshMcastIphlpapi(VOID)
{
    HMODULE Iphlpapi;

    if (WshGetAdaptersAddresses && WshIfIndexToName)
        return TRUE;
    Iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (!Iphlpapi)
        return FALSE;
    WshIfIndexToName = (PIF_INDEXTONAME)GetProcAddress(Iphlpapi, "if_indextoname");
    WshGetAdaptersAddresses = (PGET_ADAPTERS_ADDRESSES)GetProcAddress(Iphlpapi, "GetAdaptersAddresses");
    return WshGetAdaptersAddresses && WshIfIndexToName;
}

/* The adapters (caller frees with HeapFree), or NULL */
static
PIP_ADAPTER_ADDRESSES
WshMcastAdapters(VOID)
{
    ULONG Size = 16 * 1024, Error, Try;
    PIP_ADAPTER_ADDRESSES Adapters;

    if (!WshMcastIphlpapi())
        return NULL;
    for (Try = 0; Try < 3; Try++)
    {
        Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Adapters)
            return NULL;
        Error = WshGetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                        GAA_FLAG_SKIP_DNS_SERVER, NULL, Adapters, &Size);
        if (Error == NO_ERROR)
            return Adapters;
        HeapFree(GetProcessHeap(), 0, Adapters);
        if (Error != ERROR_BUFFER_OVERFLOW)
            return NULL;
    }
    return NULL;
}

/* The default interface of a group: the first adapter that is up and has the family (VERIFY ON ORACLE: Windows
 * takes the interface of the route to the group; the stack's own choice, Udp6DefaultMulticastNetif, prefers its
 * default interface). 0: none, the stack chooses */
static
ULONG
WshMcastDefaultInterface(UCHAR Family)
{
    PIP_ADAPTER_ADDRESSES Adapters = WshMcastAdapters(), A;
    ULONG Index = 0;

    for (A = Adapters; A && !Index; A = A->Next)
    {
        if (A->IfType == IF_TYPE_SOFTWARE_LOOPBACK || A->OperStatus != IfOperStatusUp)
            continue;
        Index = (Family == NITRO_MCAST_FAMILY_IP6) ? A->Ipv6IfIndex : A->IfIndex;
    }
    if (Adapters)
        HeapFree(GetProcessHeap(), 0, Adapters);
    return Index;
}

/* An interface index as given: FALSE when the machine has no such interface. 0 stays 0 (none given): the default
 * interface is looked up only when a group is joined (WshMcastJoinIndex), never to find or leave one */
static
BOOLEAN
WshMcastResolveIndex(UCHAR Family, ULONG Given, PULONG Index)
{
    CHAR Name[260];

    UNREFERENCED_PARAMETER(Family);
    if (Given != 0 && WshMcastIphlpapi() && !WshIfIndexToName(Given, Name))
        return FALSE;
    *Index = Given;
    return TRUE;
}

/* The interface the stack is given for a new join: the one named; for IPv6 without one the default interface (0: the
 * stack chooses); for IPv4 without one none, which the stack takes as every adapter */
static
ULONG
WshMcastJoinIndex(UCHAR Family, ULONG Given)
{
    if (Given || Family != NITRO_MCAST_FAMILY_IP6)
        return Given;
    return WshMcastDefaultInterface(Family);
}

/* An IPv4 interface as struct ip_mreq names it: 0.0.0.0 none, 0.0.0.0/8 an interface index, else an
 * address of this machine (FALSE: none has it) */
static
BOOLEAN
WshMcastResolveAddress(IN_ADDR Interface, PULONG Index)
{
    PIP_ADAPTER_ADDRESSES Adapters, A;
    PIP_ADAPTER_UNICAST_ADDRESS U;
    ULONG Host = ntohl(Interface.s_addr);

    if (Host < 0x01000000)
        return WshMcastResolveIndex(NITRO_MCAST_FAMILY_IP, Host, Index);

    Adapters = WshMcastAdapters();
    for (A = Adapters; A; A = A->Next)
    {
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            if (U->Address.lpSockaddr && U->Address.lpSockaddr->sa_family == AF_INET &&
                ((PSOCKADDR_IN)U->Address.lpSockaddr)->sin_addr.s_addr == Interface.s_addr)
            {
                *Index = A->IfIndex;
                HeapFree(GetProcessHeap(), 0, Adapters);
                return TRUE;
            }
        }
    }
    if (Adapters)
        HeapFree(GetProcessHeap(), 0, Adapters);
    return FALSE;
}

/* A group address of the family: multicast (FALSE: WSAEADDRNOTAVAIL) */
static
BOOLEAN
WshMcastIsGroup(UCHAR Family, const UCHAR *Address)
{
    return (Family == NITRO_MCAST_FAMILY_IP) ? ((Address[0] & 0xF0) == 0xE0) : (Address[0] == 0xFF);
}

/* A source address: neither multicast nor unspecified */
static
BOOLEAN
WshMcastIsSource(UCHAR Family, const UCHAR *Address)
{
    ULONG i;

    if (Family == NITRO_MCAST_FAMILY_IP)
        return (Address[0] & 0xF0) != 0xE0 && (Address[0] | Address[1] | Address[2] | Address[3]) != 0;
    if (Address[0] == 0xFF)
        return FALSE;
    for (i = 0; i < 16; i++)
    {
        if (Address[i])
            return TRUE;
    }
    return FALSE;
}

/* The group of a socket address (sockaddr_in / sockaddr_in6) of the family the request is for: FALSE when it is of
 * another family */
static
BOOLEAN
WshMcastGroupOf(UCHAR Family, const SOCKADDR_STORAGE *Address, UCHAR *Group)
{
    RtlZeroMemory(Group, 16);
    if (Family == NITRO_MCAST_FAMILY_IP && Address->ss_family == AF_INET)
    {
        RtlCopyMemory(Group, &((const SOCKADDR_IN *)Address)->sin_addr, 4);
        return TRUE;
    }
    if (Family == NITRO_MCAST_FAMILY_IP6 && Address->ss_family == AF_INET6)
    {
        RtlCopyMemory(Group, &((const SOCKADDR_IN6 *)Address)->sin6_addr, 16);
        return TRUE;
    }
    return FALSE;
}

/* A source of a socket address: Windows takes one of the other family too (see the header) */
static
VOID
WshMcastSourceOf(UCHAR Family, const SOCKADDR_STORAGE *Address, UCHAR *Source)
{
    RtlZeroMemory(Source, 16);
    if (Address->ss_family == AF_INET)
    {
        const UCHAR *V4 = (const UCHAR *)&((const SOCKADDR_IN *)Address)->sin_addr;

        if (Family == NITRO_MCAST_FAMILY_IP)
        {
            RtlCopyMemory(Source, V4, 4);
        }
        else
        {
            Source[10] = Source[11] = 0xFF;
            RtlCopyMemory(&Source[12], V4, 4);
        }
    }
    else if (Address->ss_family == AF_INET6)
    {
        const UCHAR *V6 = (const UCHAR *)&((const SOCKADDR_IN6 *)Address)->sin6_addr;

        if (Family == NITRO_MCAST_FAMILY_IP6)
            RtlCopyMemory(Source, V6, 16);
        else
            RtlCopyMemory(Source, &V6[12], 4);
    }
}

static
PWSH_MCAST
WshMcastFind(PSOCKET_CONTEXT Context, UCHAR Family, const UCHAR *Group, ULONG Given)
{
    PWSH_MCAST M, Any = NULL;

    /* The socket's join of the group, as the stack finds it: with no interface given, the one made without one, else
       the socket's join of the group wherever it landed (the default interface may have changed since); an interface
       given is the join's, or (IPv4: a join without one is on every adapter) matches it */
    for (M = Context->Mcast; M; M = M->Next)
    {
        if (M->Family != Family || !RtlEqualMemory(M->Group, Group, 16))
            continue;
        if (Given == 0)
        {
            if (M->Given == 0)
                return M;
            if (!Any)
                Any = M;
        }
        else if (M->IfIndex == Given || (Family == NITRO_MCAST_FAMILY_IP && M->IfIndex == 0))
        {
            return M;
        }
    }
    return Any;
}

/* The socket's groups of a family */
static
ULONG
WshMcastCount(PSOCKET_CONTEXT Context, UCHAR Family)
{
    PWSH_MCAST M;
    ULONG Count = 0;

    for (M = Context->Mcast; M; M = M->Next)
    {
        if (M->Family == Family)
            Count++;
    }
    return Count;
}

static
LONG
WshMcastFindSource(const UCHAR (*Sources)[16], ULONG Count, const UCHAR *Source)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        if (RtlEqualMemory(Sources[i], Source, 16))
            return (LONG)i;
    }
    return -1;
}

/* A filter request to the stack, on the socket's own address handle (WshSetInformationEx: the stack takes it for that
 * socket whatever entity it names; a control channel only without one), and the stack's answer as the socket API
 * answers (STATUS_INVALID_PARAMETER: the group is joined already, WSAEINVAL; the rest - no such interface, not a
 * member, no room - WSAEADDRNOTAVAIL, the answer the stack gave IPV6_ADD_MEMBERSHIP before) */
static
INT
WshMcastSend(PSOCKET_CONTEXT Context, HANDLE AddressHandle, PNITRO_MCAST_FILTER Filter, ULONG Size)
{
    PTCP_REQUEST_SET_INFORMATION_EX Info;
    DWORD Status;
    INT Error = NO_ERROR;

    /* An unbound socket has no address object in the stack yet: its groups wait in the socket's table (one entry
       per group, so the wait is bounded) and WshMcastBind hands them over at the bind */
    if (Context->SocketState == SocketStateCreated)
        return NO_ERROR;

    Info = HeapAlloc(GetProcessHeap(), 0, FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer) + Size);
    if (!Info)
        return WSAENOBUFS;
    Info->ID.toi_entity.tei_entity = Context->AddrFileEntityType;
    Info->ID.toi_entity.tei_instance = Context->AddrFileInstance;
    Info->ID.toi_class = INFO_CLASS_PROTOCOL;
    Info->ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;
    Info->ID.toi_id = NITRO_AO_OPTION_MCAST_FILTER;
    Info->BufferSize = Size;
    RtlCopyMemory(Info->Buffer, Filter, Size);

    Status = WshSetInformationEx(AddressHandle, IOCTL_TCP_SET_INFORMATION_EX, Info,
                                 FIELD_OFFSET(TCP_REQUEST_SET_INFORMATION_EX, Buffer) + Size);
    if (Status == ERROR_OPEN_FAILED)
        Error = WSAENOBUFS;
    else if (Status == ERROR_INVALID_PARAMETER)
        Error = WSAEINVAL;
    else if (Status != NO_ERROR)
        Error = WSAEADDRNOTAVAIL;
    HeapFree(GetProcessHeap(), 0, Info);
    return Error;
}

/*
 * The new filter of a group (Entry: the socket's group, or NULL for a new one on the interface Given names): to the
 * stack (after the bind when the socket is not bound yet), then kept. INCLUDE with no source leaves the group. A
 * group's interface is fixed when it is joined (the stack is given that index for every later change, never the
 * default interface of the day). Sources: NumSources of 16 bytes (copied)
 */
static
INT
WshMcastCommit(PSOCKET_CONTEXT Context, HANDLE AddressHandle, PWSH_MCAST Entry, UCHAR Family, const UCHAR *Group,
               ULONG Given, UCHAR Mode, const UCHAR (*Sources)[16], ULONG NumSources)
{
    BOOLEAN Leave = (Mode == MCAST_INCLUDE && NumSources == 0);
    PNITRO_MCAST_FILTER Filter;
    UCHAR (*Copy)[16] = NULL;
    PWSH_MCAST New = NULL, *Link;
    ULONG Size, IfIndex;
    INT Error;

    if (Leave && !Entry)
        return NO_ERROR;
    if (NumSources > NITRO_MCAST_MAX_SOURCES)
        return WSAENOBUFS;
    /* The socket's limit, as the stack answers one past it (also before the bind, where nothing else would) */
    if (!Entry && WshMcastCount(Context, Family) >= NITRO_MCAST_MAX_GROUPS)
        return WSAEADDRNOTAVAIL;
    IfIndex = Entry ? Entry->IfIndex : WshMcastJoinIndex(Family, Given);

    Size = NITRO_MCAST_FILTER_SIZE(NumSources);
    Filter = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!Filter)
        return WSAENOBUFS;
    if (NumSources)
    {
        Copy = HeapAlloc(GetProcessHeap(), 0, NumSources * 16);
        if (!Copy)
        {
            HeapFree(GetProcessHeap(), 0, Filter);
            return WSAENOBUFS;
        }
        RtlCopyMemory(Copy, Sources, NumSources * 16);
    }
    if (!Entry)
    {
        New = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*New));
        if (!New)
        {
            if (Copy)
                HeapFree(GetProcessHeap(), 0, Copy);
            HeapFree(GetProcessHeap(), 0, Filter);
            return WSAENOBUFS;
        }
    }

    Filter->InterfaceIndex = IfIndex;
    Filter->Family = Family;
    Filter->Mode = Mode;
    Filter->Flags = Entry ? 0 : NITRO_MCAST_FILTER_NEW;
    RtlCopyMemory(Filter->Group, Group, 16);
    Filter->NumSources = NumSources;
    if (NumSources)
        RtlCopyMemory(Filter->Sources, Sources, NumSources * 16);
    Error = WshMcastSend(Context, AddressHandle, Filter, Size);
    HeapFree(GetProcessHeap(), 0, Filter);
    if (Error != NO_ERROR)
    {
        if (Copy)
            HeapFree(GetProcessHeap(), 0, Copy);
        if (New)
            HeapFree(GetProcessHeap(), 0, New);
        return Error;
    }

    if (Leave)
    {
        for (Link = &Context->Mcast; *Link != Entry; Link = &(*Link)->Next)
            ;
        *Link = Entry->Next;
        if (Entry->Sources)
            HeapFree(GetProcessHeap(), 0, Entry->Sources);
        HeapFree(GetProcessHeap(), 0, Entry);
        return NO_ERROR;
    }
    if (New)
    {
        New->Family = Family;
        RtlCopyMemory(New->Group, Group, 16);
        New->Given = Given;
        New->IfIndex = IfIndex;
        New->Next = Context->Mcast;
        Context->Mcast = New;
        Entry = New;
    }
    else if (Entry->Sources)
    {
        HeapFree(GetProcessHeap(), 0, Entry->Sources);
    }
    Entry->Mode = Mode;
    Entry->NumSources = NumSources;
    Entry->Sources = Copy;
    return NO_ERROR;
}

/* One option's operation on the socket's group (the request already checked) */
static
INT
WshMcastOperate(PSOCKET_CONTEXT Context, HANDLE AddressHandle, WSH_MCAST_OP Op, UCHAR Family, const UCHAR *Group,
                ULONG Given, const UCHAR *Source)
{
    PWSH_MCAST Entry = WshMcastFind(Context, Family, Group, Given);
    UCHAR (*List)[16];
    LONG At;
    INT Error;

    switch (Op)
    {
        case McastJoin:
            if (Entry)
                return WSAEINVAL;
            return WshMcastCommit(Context, AddressHandle,NULL, Family, Group, Given, MCAST_EXCLUDE, NULL, 0);

        case McastLeave:
            if (!Entry)
                return WSAEADDRNOTAVAIL;
            return WshMcastCommit(Context, AddressHandle,Entry, Family, Group, Given, MCAST_INCLUDE, NULL, 0);

        case McastJoinSource:
            if (!Entry)
                return WshMcastCommit(Context, AddressHandle,NULL, Family, Group, Given, MCAST_INCLUDE, (const UCHAR (*)[16])Source, 1);
            /* fall through */
        case McastBlock:
            if (!Entry || Entry->Mode != ((Op == McastBlock) ? MCAST_EXCLUDE : MCAST_INCLUDE))
                return WSAEINVAL;
            if (WshMcastFindSource((const UCHAR (*)[16])Entry->Sources, Entry->NumSources, Source) >= 0)
                return WSAEADDRINUSE;
            List = HeapAlloc(GetProcessHeap(), 0, (Entry->NumSources + 1) * 16);
            if (!List)
                return WSAENOBUFS;
            if (Entry->NumSources)
                RtlCopyMemory(List, Entry->Sources, Entry->NumSources * 16);
            RtlCopyMemory(List[Entry->NumSources], Source, 16);
            Error = WshMcastCommit(Context, AddressHandle,Entry, Family, Group, Given, Entry->Mode, (const UCHAR (*)[16])List,
                                   Entry->NumSources + 1);
            HeapFree(GetProcessHeap(), 0, List);
            return Error;

        case McastUnblock:
        case McastLeaveSource:
            if (!Entry || Entry->Mode != ((Op == McastUnblock) ? MCAST_EXCLUDE : MCAST_INCLUDE))
                return WSAEINVAL;
            At = WshMcastFindSource((const UCHAR (*)[16])Entry->Sources, Entry->NumSources, Source);
            if (At < 0)
                return WSAEADDRNOTAVAIL;
            List = HeapAlloc(GetProcessHeap(), 0, Entry->NumSources * 16);
            if (!List)
                return WSAENOBUFS;
            RtlCopyMemory(List, Entry->Sources, Entry->NumSources * 16);
            RtlMoveMemory(List[At], List[At + 1], (Entry->NumSources - At - 1) * 16);
            /* the last source of a source-specific group: the group is left */
            Error = WshMcastCommit(Context, AddressHandle,Entry, Family, Group, Given, Entry->Mode, (const UCHAR (*)[16])List,
                                   Entry->NumSources - 1);
            HeapFree(GetProcessHeap(), 0, List);
            return Error;
    }
    return WSAEINVAL;
}

/* Whether a dual stack IPv6 socket (IPV6_V6ONLY off: it takes IPv4 groups at IPPROTO_IP) */
static
BOOLEAN
WshMcastDualStack(PSOCKET_CONTEXT Context)
{
    return Context->AddressFamily == AF_INET6 && (Context->Ipv6OptionsSet & WSH_SET6_V6ONLY) &&
           !Context->Ipv6V6Only;
}

/* Whether Level/OptionName is one of the options here */
BOOLEAN
WshMcastIsOption(INT Level, INT OptionName)
{
    if (OptionName >= MCAST_JOIN_GROUP && OptionName <= MCAST_LEAVE_SOURCE_GROUP)
        return Level == IPPROTO_IP || Level == IPPROTO_IPV6;
    if (Level == IPPROTO_IP)
        return OptionName == IP_ADD_MEMBERSHIP || OptionName == IP_DROP_MEMBERSHIP ||
               OptionName == IP_ADD_SOURCE_MEMBERSHIP || OptionName == IP_DROP_SOURCE_MEMBERSHIP ||
               OptionName == IP_BLOCK_SOURCE || OptionName == IP_UNBLOCK_SOURCE;
    if (Level == IPPROTO_IPV6)
        return OptionName == IPV6_ADD_MEMBERSHIP || OptionName == IPV6_DROP_MEMBERSHIP;
    return FALSE;
}

/*
 * setsockopt of an option WshMcastIsOption names. IPV6_ADD/DROP_MEMBERSHIP on an AF_INET socket are not taken
 * here (*Handled FALSE: the caller answers as before)
 */
INT
WshMcastSetOption(PSOCKET_CONTEXT Context, HANDLE AddressHandle, INT Level, INT OptionName, PCHAR OptionValue,
                  INT OptionLength, PBOOLEAN Handled)
{
    WSH_MCAST_OP Op;
    UCHAR Family, Group[16], Source[16];
    ULONG IfIndex, Given;
    BOOLEAN HasSource = FALSE;

    *Handled = TRUE;

    if (Level == IPPROTO_IPV6 && (OptionName == IPV6_ADD_MEMBERSHIP || OptionName == IPV6_DROP_MEMBERSHIP) &&
        Context->AddressFamily != AF_INET6)
    {
        *Handled = FALSE;
        return NO_ERROR;
    }

    /* The level an option is taken at (see the header): IPPROTO_IP on an IPv6-only socket is not */
    if (Level == IPPROTO_IP && Context->AddressFamily == AF_INET6 && !WshMcastDualStack(Context))
        return WSAEINVAL;
    /* A raw socket joins and leaves an IPv4 group too (IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP: the adapter passes the
       group's frames, as for a datagram socket); the other options are a datagram socket's */
    if (Context->SocketType != SOCK_DGRAM &&
        !(Context->SocketType == SOCK_RAW && Level == IPPROTO_IP &&
          (OptionName == IP_ADD_MEMBERSHIP || OptionName == IP_DROP_MEMBERSHIP)))
        return WSAEINVAL;
    Family = (Context->AddressFamily == AF_INET6 && Level == IPPROTO_IPV6) ? NITRO_MCAST_FAMILY_IP6 : NITRO_MCAST_FAMILY_IP;

    if (OptionName >= MCAST_JOIN_GROUP && OptionName <= MCAST_LEAVE_SOURCE_GROUP)
    {
        static const WSH_MCAST_OP Ops[] = { McastJoin, McastLeave, McastBlock, McastUnblock, McastJoinSource,
                                            McastLeaveSource };
        const SOCKADDR_STORAGE *GroupAddress;

        Op = Ops[OptionName - MCAST_JOIN_GROUP];
        HasSource = (Op != McastJoin && Op != McastLeave);
        if (!OptionValue || OptionLength < (INT)(HasSource ? sizeof(GROUP_SOURCE_REQ) : sizeof(GROUP_REQ)))
            return WSAEFAULT;
        if (HasSource)
        {
            const GROUP_SOURCE_REQ *R = (const GROUP_SOURCE_REQ *)OptionValue;

            Given = R->gsr_interface;
            GroupAddress = &R->gsr_group;
            WshMcastSourceOf(Family, &R->gsr_source, Source);
        }
        else
        {
            const GROUP_REQ *R = (const GROUP_REQ *)OptionValue;

            Given = R->gr_interface;
            GroupAddress = &R->gr_group;
        }
        if (!WshMcastGroupOf(Family, GroupAddress, Group) || !WshMcastIsGroup(Family, Group))
            return WSAEADDRNOTAVAIL;
        if (HasSource && !WshMcastIsSource(Family, Source))
            return WSAEADDRNOTAVAIL;
        if (!WshMcastResolveIndex(Family, Given, &IfIndex))
            return WSAEADDRNOTAVAIL;
    }
    else if (Level == IPPROTO_IPV6)
    {
        /* struct ipv6_mreq: the group, then the interface index */
        if (!OptionValue || OptionLength < (INT)sizeof(IPV6_MREQ))
            return WSAEFAULT;
        Op = (OptionName == IPV6_ADD_MEMBERSHIP) ? McastJoin : McastLeave;
        RtlCopyMemory(Group, &((const IPV6_MREQ *)OptionValue)->ipv6mr_multiaddr, 16);
        if (!WshMcastIsGroup(Family, Group))
            return WSAEADDRNOTAVAIL;
        if (!WshMcastResolveIndex(Family, ((const IPV6_MREQ *)OptionValue)->ipv6mr_interface, &IfIndex))
            return WSAEADDRNOTAVAIL;
    }
    else
    {
        IN_ADDR Interface;

        RtlZeroMemory(Group, sizeof(Group));
        if (OptionName == IP_ADD_MEMBERSHIP || OptionName == IP_DROP_MEMBERSHIP)
        {
            if (!OptionValue || OptionLength < (INT)sizeof(IP_MREQ))
                return WSAEFAULT;
            Op = (OptionName == IP_ADD_MEMBERSHIP) ? McastJoin : McastLeave;
            RtlCopyMemory(Group, &((const IP_MREQ *)OptionValue)->imr_multiaddr, 4);
            Interface = ((const IP_MREQ *)OptionValue)->imr_interface;
        }
        else
        {
            const IP_MREQ_SOURCE *R = (const IP_MREQ_SOURCE *)OptionValue;

            if (!OptionValue || OptionLength < (INT)sizeof(IP_MREQ_SOURCE))
                return WSAEFAULT;
            Op = (OptionName == IP_ADD_SOURCE_MEMBERSHIP) ? McastJoinSource :
                 (OptionName == IP_DROP_SOURCE_MEMBERSHIP) ? McastLeaveSource :
                 (OptionName == IP_BLOCK_SOURCE) ? McastBlock : McastUnblock;
            RtlCopyMemory(Group, &R->imr_multiaddr, 4);
            RtlZeroMemory(Source, sizeof(Source));
            RtlCopyMemory(Source, &R->imr_sourceaddr, 4);
            Interface = R->imr_interface;
            HasSource = TRUE;
        }
        if (!WshMcastIsGroup(Family, Group))
            return WSAEADDRNOTAVAIL;
        if (HasSource && !WshMcastIsSource(Family, Source))
            return WSAEADDRNOTAVAIL;
        if (!WshMcastResolveAddress(Interface, &IfIndex))
            return WSAEADDRNOTAVAIL;
    }

    return WshMcastOperate(Context, AddressHandle, Op, Family, Group, IfIndex, HasSource ? Source : NULL);
}

/* Duplicate sources in a filter (WSAEADDRINUSE) */
static
BOOLEAN
WshMcastHasDuplicate(const UCHAR (*Sources)[16], ULONG Count)
{
    ULONG i;

    for (i = 1; i < Count; i++)
    {
        if (WshMcastFindSource(Sources, i, Sources[i]) >= 0)
            return TRUE;
    }
    return FALSE;
}

/* A whole filter set by an ioctl: the group and sources already converted */
static
INT
WshMcastSetFilter(PSOCKET_CONTEXT Context, HANDLE AddressHandle, UCHAR Family, const UCHAR *Group, ULONG Given,
                  ULONG Mode, const UCHAR (*Sources)[16], ULONG NumSources)
{
    PWSH_MCAST Entry = WshMcastFind(Context, Family, Group, Given);
    ULONG i;

    for (i = 0; i < NumSources; i++)
    {
        if (!WshMcastIsSource(Family, Sources[i]))
            return WSAEADDRNOTAVAIL;
    }
    if (WshMcastHasDuplicate(Sources, NumSources))
        return WSAEADDRINUSE;
    /* Windows takes any mode that is not MCAST_INCLUDE (2 included) as MCAST_EXCLUDE (VERIFY ON ORACLE what it does
       with it) */
    return WshMcastCommit(Context, AddressHandle, Entry, Family, Group, Given,
                          Mode == MCAST_INCLUDE ? MCAST_INCLUDE : MCAST_EXCLUDE, Sources, NumSources);
}

/*
 * WSAIoctl of SIOCSMSFILTER, SIOCGMSFILTER, SIO_SET_MULTICAST_FILTER, SIO_GET_MULTICAST_FILTER (*Handled FALSE for
 * any other code)
 */
INT
WshMcastIoctl(PSOCKET_CONTEXT Context, HANDLE AddressHandle, DWORD Code, PVOID InputBuffer, DWORD InputBufferLength,
              PVOID OutputBuffer, DWORD OutputBufferLength, LPDWORD Returned, PBOOLEAN Handled)
{
    BOOLEAN Set, V4;
    UCHAR Family, Group[16];
    ULONG IfIndex, Mode, NumSources, i, Needed;
    UCHAR (*Sources)[16] = NULL;
    PWSH_MCAST Entry;
    INT Error;

    if (Code == SIOCSMSFILTER || Code == SIOCGMSFILTER)
        V4 = FALSE;
    else if (Code == SIO_SET_MULTICAST_FILTER || Code == SIO_GET_MULTICAST_FILTER)
        V4 = TRUE;
    else
    {
        *Handled = FALSE;
        return NO_ERROR;
    }
    *Handled = TRUE;
    *Returned = 0;
    Set = (Code == SIOCSMSFILTER || Code == SIO_SET_MULTICAST_FILTER);

    if (Context->SocketType != SOCK_DGRAM)
        return WSAEINVAL;
    if (V4 && Context->AddressFamily != AF_INET)
        return WSAEINVAL;
    if (!InputBuffer)
        return WSAEFAULT;
    if (!Set && !OutputBuffer)
        return WSAEFAULT;
    Family = (Context->AddressFamily == AF_INET6) ? NITRO_MCAST_FAMILY_IP6 : NITRO_MCAST_FAMILY_IP;

    if (V4)
    {
        const IP_MSFILTER *F = InputBuffer;

        if (InputBufferLength < IP_MSFILTER_SIZE(0))
            return WSAEINVAL;
        NumSources = F->imsf_numsrc;
        if (Set && (NumSources > NITRO_MCAST_MAX_SOURCES || InputBufferLength < IP_MSFILTER_SIZE(NumSources)))
            return WSAEINVAL;
        RtlZeroMemory(Group, sizeof(Group));
        RtlCopyMemory(Group, &F->imsf_multiaddr, 4);
        if (!WshMcastIsGroup(Family, Group) || !WshMcastResolveAddress(F->imsf_interface, &IfIndex))
            return WSAEADDRNOTAVAIL;
        Mode = F->imsf_fmode;
        if (Set && NumSources)
        {
            Sources = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumSources * 16);
            if (!Sources)
                return WSAENOBUFS;
            for (i = 0; i < NumSources; i++)
                RtlCopyMemory(Sources[i], &F->imsf_slist[i], 4);
        }
    }
    else
    {
        const GROUP_FILTER *F = InputBuffer;

        if (InputBufferLength < GROUP_FILTER_SIZE(0))
            return WSAEINVAL;
        NumSources = F->gf_numsrc;
        if (Set && (NumSources > NITRO_MCAST_MAX_SOURCES || InputBufferLength < GROUP_FILTER_SIZE(NumSources)))
            return WSAEINVAL;
        /* an AF_INET6 socket's filters are of IPv6 groups: reading one of an IPv4 group WSAEINVAL (a dual stack
           socket that joined it), setting one WSAEADDRNOTAVAIL, as Windows answers */
        if (!Set && Family == NITRO_MCAST_FAMILY_IP6 && F->gf_group.ss_family == AF_INET)
            return WSAEINVAL;
        if (!WshMcastGroupOf(Family, &F->gf_group, Group) || !WshMcastIsGroup(Family, Group) ||
            !WshMcastResolveIndex(Family, F->gf_interface, &IfIndex))
            return WSAEADDRNOTAVAIL;
        Mode = F->gf_fmode;
        if (Set && NumSources)
        {
            Sources = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumSources * 16);
            if (!Sources)
                return WSAENOBUFS;
            for (i = 0; i < NumSources; i++)
                WshMcastSourceOf(Family, &F->gf_slist[i], Sources[i]);
        }
    }

    if (Set)
    {
        Error = WshMcastSetFilter(Context, AddressHandle, Family, Group, IfIndex, Mode, (const UCHAR (*)[16])Sources,
                                  NumSources);
        if (Sources)
            HeapFree(GetProcessHeap(), 0, Sources);
        return Error;
    }

    /* The filter as it is: the caller's buffer must hold all its sources (NumSources says how many it has room for) */
    Entry = WshMcastFind(Context, Family, Group, IfIndex);
    if (!Entry)
        return WSAEINVAL;
    Needed = V4 ? IP_MSFILTER_SIZE(Entry->NumSources) : GROUP_FILTER_SIZE(Entry->NumSources);
    if (NumSources < Entry->NumSources || OutputBufferLength < Needed)
        return WSAEFAULT;
    if (V4)
    {
        IP_MSFILTER *Out = OutputBuffer;

        RtlCopyMemory(&Out->imsf_multiaddr, Group, 4);
        Out->imsf_interface = ((const IP_MSFILTER *)InputBuffer)->imsf_interface;
        Out->imsf_fmode = Entry->Mode;
        Out->imsf_numsrc = Entry->NumSources;
        for (i = 0; i < Entry->NumSources; i++)
            RtlCopyMemory(&Out->imsf_slist[i], Entry->Sources[i], 4);
    }
    else
    {
        GROUP_FILTER *Out = OutputBuffer;
        SOCKADDR_STORAGE GroupAddress = ((const GROUP_FILTER *)InputBuffer)->gf_group;
        ULONG Interface = ((const GROUP_FILTER *)InputBuffer)->gf_interface;

        RtlZeroMemory(Out, Needed);
        Out->gf_interface = Interface;
        Out->gf_group = GroupAddress;
        Out->gf_fmode = Entry->Mode;
        Out->gf_numsrc = Entry->NumSources;
        for (i = 0; i < Entry->NumSources; i++)
        {
            if (Family == NITRO_MCAST_FAMILY_IP)
            {
                PSOCKADDR_IN A = (PSOCKADDR_IN)&Out->gf_slist[i];

                A->sin_family = AF_INET;
                RtlCopyMemory(&A->sin_addr, Entry->Sources[i], 4);
            }
            else
            {
                PSOCKADDR_IN6 A = (PSOCKADDR_IN6)&Out->gf_slist[i];

                A->sin6_family = AF_INET6;
                RtlCopyMemory(&A->sin6_addr, Entry->Sources[i], 16);
            }
        }
    }
    *Returned = Needed;
    return NO_ERROR;
}

/*
 * The bind (WSHNotify, the address object exists now): the groups the socket joined before it, one filter each, go to
 * the stack. A group the stack refuses (its limits, an interface that went away) is dropped from the socket's table,
 * so no later answer says it is joined, and the first refusal fails the bind with the answer the join would have had
 */
INT
WshMcastBind(PSOCKET_CONTEXT Context, HANDLE AddressHandle)
{
    PWSH_MCAST M, Next, Reversed = NULL, *Link;
    PNITRO_MCAST_FILTER Filter;
    INT First = NO_ERROR, Error;
    ULONG Size;

    /* The table has the newest group first: the groups go in the order they were joined, so a limit refuses the later
       ones */
    for (M = Context->Mcast; M; M = Next)
    {
        Next = M->Next;
        M->Next = Reversed;
        Reversed = M;
    }
    Context->Mcast = Reversed;

    for (Link = &Context->Mcast; (M = *Link) != NULL; )
    {
        Size = NITRO_MCAST_FILTER_SIZE(M->NumSources);
        Filter = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        if (!Filter)
        {
            Error = WSAENOBUFS;
        }
        else
        {
            Filter->InterfaceIndex = M->IfIndex;
            Filter->Family = M->Family;
            Filter->Mode = M->Mode;
            Filter->Flags = NITRO_MCAST_FILTER_NEW;
            RtlCopyMemory(Filter->Group, M->Group, 16);
            Filter->NumSources = M->NumSources;
            if (M->NumSources)
                RtlCopyMemory(Filter->Sources, M->Sources, M->NumSources * 16);
            Error = WshMcastSend(Context, AddressHandle, Filter, Size);
            HeapFree(GetProcessHeap(), 0, Filter);
        }
        if (Error == NO_ERROR)
        {
            Link = &M->Next;
            continue;
        }
        if (First == NO_ERROR)
            First = Error;
        *Link = M->Next;
        if (M->Sources)
            HeapFree(GetProcessHeap(), 0, M->Sources);
        HeapFree(GetProcessHeap(), 0, M);
    }
    return First;
}

/* The socket is closed: its groups go with it (the stack leaves them when the address object goes) */
VOID
WshMcastFree(PSOCKET_CONTEXT Context)
{
    PWSH_MCAST M, Next;

    for (M = Context->Mcast; M; M = Next)
    {
        Next = M->Next;
        if (M->Sources)
            HeapFree(GetProcessHeap(), 0, M->Sources);
        HeapFree(GetProcessHeap(), 0, M);
    }
    Context->Mcast = NULL;
}
