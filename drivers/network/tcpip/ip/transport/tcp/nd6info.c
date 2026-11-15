/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IPv6 neighbour cache, on-link prefixes and counters for user mode (iphlpapi)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * IP_IPV6_ND_ENTRY_ID hands out lwIP's neighbour cache and its on-link prefix list (tcpioctl.h).
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


