/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IPv6 neighbour cache, on-link prefixes and counters for user mode (iphlpapi)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * IP_IPV6_ND_ENTRY_ID hands out lwIP's neighbour cache and its on-link prefix list (tcpioctl.h).
 */
/*
 * IP_IPV6_STATS_ENTRY_ID hands out the counters kept here. They are bumped from the places every IPv6 datagram
 * passes: the start of ip6_input (LWIP_HOOK_IP6_INPUT), the upper layer dispatch of ip6_input
 * (LWIP_HOOK_IP6_NEXTH_INPUT) and the output callback of the IPv6 interface (TCPSendData6Callback). All of them run
 * with the lwIP core lock held and use interlocked operations, as the query does not take that lock for the counters.
 */

#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/priv/nd6_priv.h"

/* NL_NEIGHBOR_STATE */
#define ND6INFO_INCOMPLETE  1
#define ND6INFO_PROBE       2
#define ND6INFO_DELAY       3
#define ND6INFO_STALE       4
#define ND6INFO_REACHABLE   5

static
ULONG
Nd6InfoInterfaceIndex(const struct netif *netif)
{
    return (netif && netif->state) ? ((PIP_INTERFACE)netif->state)->Index : 0;
}

/* The IP_IPV6_ND_ENTRY_ID answer: TCP_IPV6_ND_HEADER, the neighbour rows, the prefix rows. Returns the size of
 * the whole answer; what fits in Out (OutSize bytes) is written, so a caller whose buffer is too small gets the
 * size and asks again. Off: the header alone, with Enabled 0. PASSIVE_LEVEL */
ULONG
TCPQueryIpv6Nd(PVOID Out, ULONG OutSize)
{
    PTCP_IPV6_ND_HEADER Header = Out;
    PTCP_IPV6_NEIGHBOR_ROW Neighbors = (PTCP_IPV6_NEIGHBOR_ROW)(Header + 1);
    PTCP_IPV6_PREFIX_ROW Prefixes;
    ULONG NeighborCount = 0, PrefixCount = 0, i, Size;
    BOOLEAN Fits = (Out != NULL && OutSize >= sizeof(*Header));
    ULONG PrefixBase;

    if (!TCPIpv6Enabled)
    {
        if (Fits)
            RtlZeroMemory(Header, sizeof(*Header));
        return sizeof(*Header);
    }

    LOCK_TCPIP_CORE();

    /* The rows are counted first: the prefix rows start after the last neighbour row */
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++)
    {
        const struct nd6_neighbor_cache_entry *Entry = &neighbor_cache[i];

        if (Entry->state == ND6_NO_ENTRY || Entry->netif == NULL || !Nd6InfoInterfaceIndex(Entry->netif))
            continue;
        NeighborCount++;
    }
    PrefixBase = sizeof(*Header) + NeighborCount * sizeof(*Neighbors);
    Prefixes = (PTCP_IPV6_PREFIX_ROW)((PUCHAR)Out + PrefixBase);

    NeighborCount = 0;
    for (i = 0; i < LWIP_ND6_NUM_NEIGHBORS; i++)
    {
        const struct nd6_neighbor_cache_entry *Entry = &neighbor_cache[i];
        PTCP_IPV6_NEIGHBOR_ROW Row;
        ULONG IfIndex = Nd6InfoInterfaceIndex(Entry->netif), Length;

        if (Entry->state == ND6_NO_ENTRY || Entry->netif == NULL || !IfIndex)
            continue;

        if (Fits && OutSize >= sizeof(*Header) + (NeighborCount + 1) * sizeof(*Row))
        {
            Row = &Neighbors[NeighborCount];
            RtlZeroMemory(Row, sizeof(*Row));
            Row->IfIndex = IfIndex;
            RtlCopyMemory(Row->Address, Entry->next_hop_address.addr, 16);
            switch (Entry->state)
            {
                case ND6_INCOMPLETE: Row->State = ND6INFO_INCOMPLETE; break;
                case ND6_REACHABLE:  Row->State = ND6INFO_REACHABLE; break;
                case ND6_STALE:      Row->State = ND6INFO_STALE; break;
                case ND6_DELAY:      Row->State = ND6INFO_DELAY; break;
                default:             Row->State = ND6INFO_PROBE; break;
            }
            Row->Flags = Entry->isrouter ? TCP_IPV6_NEIGHBOR_ROUTER : 0;
            if (Entry->state != ND6_INCOMPLETE)
            {
                Length = Entry->netif->hwaddr_len;
                if (Length > sizeof(Row->LinkAddress))
                    Length = sizeof(Row->LinkAddress);
                Row->LinkLength = Length;
                RtlCopyMemory(Row->LinkAddress, Entry->lladdr, Length);
            }
        }
        NeighborCount++;
    }

    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++)
    {
        const struct nd6_prefix_list_entry *Entry = &prefix_list[i];
        PTCP_IPV6_PREFIX_ROW Row;
        ULONG IfIndex;

        if (Entry->netif == NULL || Entry->invalidation_timer == 0 || !netif_is_up(Entry->netif))
            continue;
        IfIndex = Nd6InfoInterfaceIndex(Entry->netif);
        if (!IfIndex)
            continue;

        if (Fits && OutSize >= PrefixBase + (PrefixCount + 1) * sizeof(*Row))
        {
            Row = &Prefixes[PrefixCount];
            RtlZeroMemory(Row, sizeof(*Row));
            Row->IfIndex = IfIndex;
            RtlCopyMemory(Row->Prefix, Entry->prefix.addr, 16);
            /* lwIP takes on-link prefixes of length 64 only (nd6.c) */
            Row->PrefixLength = 64;
            /* a lifetime of 0xFFFFFFFF seconds from the advertisement is infinite */
            Row->Lifetime = Entry->invalidation_timer;
        }
        PrefixCount++;
    }

    if (Fits)
    {
        Header->Enabled = 1;
        Header->NeighborCount = NeighborCount;
        Header->PrefixCount = PrefixCount;
    }
    UNLOCK_TCPIP_CORE();

    Size = PrefixBase + PrefixCount * sizeof(TCP_IPV6_PREFIX_ROW);
    return Size;
}

static volatile LONG Ip6InReceives;
static volatile LONG Ip6InDelivers;
static volatile LONG Ip6OutRequests;
static volatile LONG Tcp6InSegs;
static volatile LONG Tcp6OutSegs;
static volatile LONG Tcp6ActiveOpens;
static volatile LONG Tcp6PassiveOpens;
static volatile LONG Icmp6InMsgs;
static volatile LONG Icmp6OutMsgs;
static volatile LONG Icmp6In[256];
static volatile LONG Icmp6Out[256];

/* The next header of the datagram and, for ICMPv6 that follows the fixed header directly, its type (-1: none) */
static
VOID
Nd6InfoClassify(const struct pbuf *p, UCHAR *NextHeader, int *IcmpType)
{
    UCHAR Type;

    *NextHeader = 0;
    *IcmpType = -1;
    if (!p)
        return;
    if (p->len >= 41)
    {
        /* the usual case: the header and the first bytes behind it are in the first buffer */
        const UCHAR *Datagram = p->payload;

        *NextHeader = Datagram[6];
        if (*NextHeader == IP6_NEXTH_ICMP6)
            *IcmpType = Datagram[40];
        return;
    }
    if (pbuf_copy_partial(p, NextHeader, 1, 6) != 1)
        return;
    if (*NextHeader == IP6_NEXTH_ICMP6 && pbuf_copy_partial(p, &Type, 1, 40) == 1)
        *IcmpType = Type;
}

/* LWIP_HOOK_IP6_INPUT: a datagram enters the IPv6 layer. Never takes it */
int
LibIp6CountInput(struct pbuf *p, struct netif *inp)
{
    UCHAR NextHeader;
    int Type;

    UNREFERENCED_PARAMETER(inp);

    InterlockedIncrement(&Ip6InReceives);
    Nd6InfoClassify(p, &NextHeader, &Type);
    if (Type >= 0)
    {
        InterlockedIncrement(&Icmp6InMsgs);
        InterlockedIncrement(&Icmp6In[Type]);
    }
    return 0;
}

/* LWIP_HOOK_IP6_NEXTH_INPUT, before the transports: a datagram reached its upper layer protocol */
void
LibIp6CountDelivered(struct pbuf *p, struct netif *inp, u8_t nexth)
{
    UNREFERENCED_PARAMETER(p);
    UNREFERENCED_PARAMETER(inp);

    InterlockedIncrement(&Ip6InDelivers);
    if (nexth == IP6_NEXTH_TCP)
        InterlockedIncrement(&Tcp6InSegs);
}

/* A datagram goes out through the IPv6 interface's output callback (if6.c) */
VOID
TCP6CountOutput(const struct pbuf *p)
{
    UCHAR NextHeader;
    int Type;

    InterlockedIncrement(&Ip6OutRequests);
    Nd6InfoClassify(p, &NextHeader, &Type);
    if (NextHeader == IP6_NEXTH_TCP)
        InterlockedIncrement(&Tcp6OutSegs);
    if (Type >= 0)
    {
        InterlockedIncrement(&Icmp6OutMsgs);
        InterlockedIncrement(&Icmp6Out[Type]);
    }
}

VOID
TCP6CountActiveOpen(VOID)
{
    InterlockedIncrement(&Tcp6ActiveOpens);
}

VOID
TCP6CountPassiveOpen(VOID)
{
    InterlockedIncrement(&Tcp6PassiveOpens);
}

/* The IP_IPV6_STATS_ENTRY_ID answer: one TCP_IPV6_STATS. Returns its size; it is written when OutSize holds it */
ULONG
TCPQueryIpv6Stats(PVOID Out, ULONG OutSize)
{
    PTCP_IPV6_STATS Stats = Out;
    ULONG i;

    if (Out == NULL || OutSize < sizeof(*Stats))
        return sizeof(*Stats);

    RtlZeroMemory(Stats, sizeof(*Stats));
    if (!TCPIpv6Enabled)
        return sizeof(*Stats);

    Stats->Enabled = 1;
    Stats->IpInReceives = (ULONG)Ip6InReceives;
    Stats->IpInDelivers = (ULONG)Ip6InDelivers;
    Stats->IpOutRequests = (ULONG)Ip6OutRequests;
    Stats->TcpInSegs = (ULONG)Tcp6InSegs;
    Stats->TcpOutSegs = (ULONG)Tcp6OutSegs;
    Stats->TcpActiveOpens = (ULONG)Tcp6ActiveOpens;
    Stats->TcpPassiveOpens = (ULONG)Tcp6PassiveOpens;
    Stats->IcmpInMsgs = (ULONG)Icmp6InMsgs;
    Stats->IcmpOutMsgs = (ULONG)Icmp6OutMsgs;
    for (i = 0; i < 256; i++)
    {
        Stats->IcmpIn[i] = (ULONG)Icmp6In[i];
        Stats->IcmpOut[i] = (ULONG)Icmp6Out[i];
    }
    return sizeof(*Stats);
}


