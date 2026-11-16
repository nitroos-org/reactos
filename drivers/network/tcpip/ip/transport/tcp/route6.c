/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The IPv6 route table: configured routes beside what router advertisements give
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * lwIP routes IPv6 by its neighbour discovery state alone: the on-link prefixes and default routers router
 * advertisements gave (nd6.c), and the /64 of a static address. This file adds the routes an administrator
 * configures (IOCTL_IP6_ROUTE_CONFIG: prefix and length, next hop or on-link, interface, metric, lifetimes, origin,
 * protocol) and makes one table of them, the on-link prefixes of configured addresses (addr6.c) and the router
 * advertisement routes:
 *
 * - the stack routes by it: lwIP asks LibIp6Route (LWIP_HOOK_IP6_ROUTE) for the interface of a destination that has
 *   no zone, and LibNd6GetGw (LWIP_HOOK_ND6_GET_GW) for the next hop of a destination that is not on-link by lwIP's
 *   own rules. The longest prefix wins, then the lowest metric, then a configured route over a router advertisement
 *   one. When a router advertisement route wins (or nothing does) the hooks answer nothing and lwIP's own rules
 *   choose, as they did before this table existed: with no configured route the hooks return at once, and the
 *   behaviour is exactly the old one;
 * - user mode reads it (IP_IPV6_ROUTE_ENTRY_ID: GetIpForwardTable2, GetBestRoute2 in iphlpapi), the router
 *   advertisement rows with the values iphlpapi showed for them before;
 * - every change completes the pending route change requests (NotifyRouteChange2), and empties lwIP's destination
 *   cache, which keeps the next hop of each destination it has seen.
 *
 * All of it is under lwIP's core lock, as the hooks run with it held. Lifetimes run on the interrupt time; a
 * configured route whose valid lifetime ends is removed by the ND timer (LWIP_HOOK_ND6_TMR, once a second). The
 * routes of an interface go with it (TCP6RemoveRoutesOfNetif). A route configured with TCP_IPV6_STORE_PERSISTENT
 * is written to the persistent store too (persist6.c) and comes back whenever the adapter starts.
 */

#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include <lwip_hooks.h>
#include "lwip/priv/nd6_priv.h"

/* Configured routes, over all interfaces */
#define ROUTE6_MAX              256
/* The metric of the routes router advertisements give, as iphlpapi reports them (medium preference; high and low
   preference add the offsets below: a lower metric wins) */
#define ROUTE6_RA_METRIC        256
#define ROUTE6_RA_METRIC_HIGH   128
#define ROUTE6_RA_METRIC_LOW    512
/* Routes of route information options (RFC 4191) kept at most: a router that sends them all the time replaces its
   own, and the oldest goes first, so an advertisement cannot fill the table the configured routes live in */
#define ROUTE6_RA_MAX           32
/* NL_ROUTE_ORIGIN and NL_ROUTE_PROTOCOL values of router advertisement routes, and of the on-link prefix of a
   configured address (a route of the stack, as the host routes are) */
#define ROUTE6_ORIGIN_MANUAL    0
#define ROUTE6_ORIGIN_RA        3
#define ROUTE6_PROTOCOL_LOCAL   2
#define ROUTE6_PROTOCOL_NETMGMT 3
#define ROUTE6_INFINITE         0xFFFFFFFF

typedef struct _ROUTE6_ENTRY
{
    struct netif *Netif;        /* NULL: a free entry */
    ULONG IfIndex;
    ip6_addr_t Prefix;          /* no zone, the bits after PrefixLength zero */
    UCHAR PrefixLength;
    BOOLEAN OnLink;             /* no next hop */
    ip6_addr_t NextHop;         /* a link-local one has the zone of Netif */
    ULONG Metric;
    ULONG Origin;
    ULONG Protocol;
    ULONG Flags;                /* TCP_IPV6_ROUTE_ */
    ULONG ValidLifetime;        /* as configured at Created */
    ULONG PreferredLifetime;
    ULONGLONG Created;          /* seconds of interrupt time */
} ROUTE6_ENTRY, *PROUTE6_ENTRY;

/* The answer goes through a pool block that info.c caps at 64 KB: the largest one stays below */
C_ASSERT(sizeof(TCP_IPV6_ROUTE_HEADER) +
         (ROUTE6_MAX + LWIP_ND6_NUM_PREFIXES + LWIP_ND6_NUM_ROUTERS) * sizeof(TCP_IPV6_ROUTE_ROW) < 0x10000);

static ROUTE6_ENTRY Route6Table[ROUTE6_MAX];
/* Entries in use: with none, the hooks leave everything to lwIP */
static ULONG Route6Count;

/* What a lookup found */
typedef struct _ROUTE6_MATCH
{
    BOOLEAN Found;
    BOOLEAN FromRa;
    UCHAR Length;
    ULONG Metric;
    struct netif *Netif;
    const ip6_addr_t *NextHop;  /* NULL: on-link */
} ROUTE6_MATCH, *PROUTE6_MATCH;

/* The metric of a route of an advertisement with this preference (RFC 4191 2.1: the two bits 01 high, 00 medium, 11
   low, 10 reserved and treated as medium). The values are our own choice: only their order is fixed by the RFC */
static
ULONG
Route6PreferenceMetric(UCHAR Preference)
{
    switch (Preference & 3)
    {
        case 1:
            return ROUTE6_RA_METRIC_HIGH;
        case 3:
            return ROUTE6_RA_METRIC_LOW;
        default:
            return ROUTE6_RA_METRIC;
    }
}

static
ULONGLONG
Route6Seconds(VOID)
{
    return KeQueryInterruptTime() / 10000000ULL;
}

/* Seconds left of a lifetime given at Created; ROUTE6_INFINITE stays */
static
ULONG
Route6Left(ULONG Lifetime, ULONGLONG Created, ULONGLONG Now)
{
    ULONGLONG Passed = Now - Created;

    if (Lifetime == ROUTE6_INFINITE)
        return ROUTE6_INFINITE;
    return Passed >= Lifetime ? 0 : (ULONG)(Lifetime - Passed);
}

/* Whether the first Length bits of Address are those of Prefix */
static
BOOLEAN
Route6Covers(const ip6_addr_t *Prefix, UCHAR Length, const ip6_addr_t *Address)
{
    const UCHAR *P = (const UCHAR *)Prefix->addr, *A = (const UCHAR *)Address->addr;
    UCHAR Bytes = Length / 8, Bits = Length % 8;

    if (Bytes && RtlCompareMemory(P, A, Bytes) != Bytes)
        return FALSE;
    if (Bits && ((P[Bytes] ^ A[Bytes]) & (UCHAR)(0xFF << (8 - Bits))))
        return FALSE;
    return TRUE;
}

/* Clears the bits of Prefix after the first Length */
static
VOID
Route6Mask(ip6_addr_t *Prefix, UCHAR Length)
{
    UCHAR *P = (UCHAR *)Prefix->addr;
    UCHAR i;

    for (i = Length / 8; i < 16; i++)
    {
        if (i == Length / 8 && (Length % 8))
            P[i] &= (UCHAR)(0xFF << (8 - Length % 8));
        else
            P[i] = 0;
    }
}

static
ULONG
Route6IfIndex(const struct netif *netif)
{
    return (netif && netif->state) ? ((PIP_INTERFACE)netif->state)->Index : 0;
}

static
BOOLEAN
Route6NetifUsable(struct netif *netif)
{
    return netif != NULL && netif_is_up(netif) && netif_is_link_up(netif);
}

static
VOID
Route6Consider(PROUTE6_MATCH Best, struct netif *netif, UCHAR Length, ULONG Metric, const ip6_addr_t *NextHop,
               BOOLEAN FromRa)
{
    /* the route metric and the interface metric (set by hand or automatic) are added, as on Windows; a route metric
       near the top of the range (it is not limited) stays the highest instead of wrapping to a low one */
    ULONG IfMetric = TCP6InterfaceMetric(netif);

    Metric = (Metric > MAXULONG - IfMetric) ? MAXULONG : Metric + IfMetric;

    if (Best->Found)
    {
        if (Length < Best->Length)
            return;
        if (Length == Best->Length)
        {
            if (Metric > Best->Metric)
                return;
            /* the same length and metric: a configured route before one of a router advertisement, else the
               first one */
            if (Metric == Best->Metric && (FromRa || !Best->FromRa))
                return;
        }
    }

    Best->Found = TRUE;
    Best->FromRa = FromRa;
    Best->Length = Length;
    Best->Metric = Metric;
    Best->Netif = netif;
    Best->NextHop = NextHop;
}

/* The on-link prefix the configured address in a slot gives: FALSE for none (the address was formed by the
   stack, is duplicated, is link-local: fe80::/64 is on-link anyway, or has a /128) (core lock held) */
static
BOOLEAN
Route6AddressPrefix(struct netif *netif, s8_t Slot, ip6_addr_t *Prefix, PUCHAR Length)
{
    TCP6_ADDRESS_INFO Info;
    const ip6_addr_t *Address;

    if (!TCP6AddressInfo(netif, Slot, &Info) || ip6_addr_isduplicated(netif_ip6_addr_state(netif, Slot)))
        return FALSE;
    Address = netif_ip6_addr(netif, Slot);
    if (ip6_addr_islinklocal(Address) || Info.PrefixLength >= 128)
        return FALSE;

    ip6_addr_set(Prefix, Address);
    ip6_addr_clear_zone(Prefix);
    Route6Mask(Prefix, Info.PrefixLength);
    *Length = Info.PrefixLength;
    return TRUE;
}

/* Whether an earlier slot of netif gives the same on-link prefix (core lock held) */
static
BOOLEAN
Route6AddressPrefixSeen(struct netif *netif, s8_t Slot, const ip6_addr_t *Prefix, UCHAR Length)
{
    ip6_addr_t Other;
    UCHAR OtherLength;
    s8_t i;

    for (i = 0; i < Slot; i++)
    {
        if (Route6AddressPrefix(netif, i, &Other, &OtherLength) && OtherLength == Length &&
            ip6_addr_zoneless_eq(&Other, Prefix))
            return TRUE;
    }
    return FALSE;
}

/* The best route to Dest (no zone), over any interface or only over Only (core lock held) */
static
BOOLEAN
Route6Find(const ip6_addr_t *Dest, struct netif *Only, PROUTE6_MATCH Best)
{
    ULONGLONG Now = Route6Seconds();
    ULONG i, Seen;

    RtlZeroMemory(Best, sizeof(*Best));

    for (i = 0, Seen = 0; i < ROUTE6_MAX && Seen < Route6Count; i++)
    {
        PROUTE6_ENTRY Entry = &Route6Table[i];

        if (!Entry->Netif)
            continue;
        Seen++;
        if ((Only && Entry->Netif != Only) || !Route6NetifUsable(Entry->Netif))
            continue;
        if (!Route6Left(Entry->ValidLifetime, Entry->Created, Now))
            continue;
        if (!Route6Covers(&Entry->Prefix, Entry->PrefixLength, Dest))
            continue;
        Route6Consider(Best, Entry->Netif, Entry->PrefixLength, Entry->Metric,
                       Entry->OnLink ? NULL : &Entry->NextHop, FALSE);
    }

    /* the on-link prefixes of configured addresses */
    if (Addr6Count)
    {
        struct netif *netif;
        ip6_addr_t Prefix;
        UCHAR Length;
        s8_t Slot;

        NETIF_FOREACH(netif)
        {
            if ((Only && netif != Only) || !Route6NetifUsable(netif))
                continue;
            for (Slot = 0; Slot < LWIP_IPV6_NUM_ADDRESSES; Slot++)
            {
                if (Route6AddressPrefix(netif, Slot, &Prefix, &Length) && Route6Covers(&Prefix, Length, Dest))
                    Route6Consider(Best, netif, Length, ROUTE6_RA_METRIC, NULL, FALSE);
            }
        }
    }

    /* lwIP's on-link prefixes are /64 (nd6.c) */
    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++)
    {
        struct netif *netif = prefix_list[i].netif;

        if (!netif || prefix_list[i].invalidation_timer == 0 || (Only && netif != Only) || !Route6NetifUsable(netif))
            continue;
        if (!Route6Covers(&prefix_list[i].prefix, 64, Dest))
            continue;
        Route6Consider(Best, netif, 64, ROUTE6_RA_METRIC, NULL, TRUE);
    }

    for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++)
    {
        struct nd6_neighbor_cache_entry *Neighbor = default_router_list[i].neighbor_entry;

        if (!Neighbor || default_router_list[i].invalidation_timer == 0 || !Neighbor->netif)
            continue;
        if ((Only && Neighbor->netif != Only) || !Route6NetifUsable(Neighbor->netif))
            continue;
        Route6Consider(Best, Neighbor->netif, 0, Route6PreferenceMetric((UCHAR)(default_router_list[i].flags >> 3)),
                       &Neighbor->next_hop_address, TRUE);
    }

    return Best->Found;
}

/* Whether Address is an address of one of our interfaces (core lock held) */
static
BOOLEAN
Route6IsOwnAddress(const ip6_addr_t *Address)
{
    struct netif *netif;
    s8_t i;

    NETIF_FOREACH(netif)
    {
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)) &&
                ip6_addr_zoneless_eq(netif_ip6_addr(netif, i), Address))
                return TRUE;
        }
    }
    return FALSE;
}

/* Whether there is anything of ours to route by: without it, the hooks leave everything to lwIP (core lock held) */
static
BOOLEAN
Route6Active(VOID)
{
    return Route6Count != 0 || Addr6Count != 0;
}

/* LWIP_HOOK_IP6_ROUTE (core lock held): the interface for a destination without a zone, when a configured route is
   the best one; NULL lets lwIP choose (a router advertisement route won, or nothing matched, or the destination is
   an address of ours) */
struct netif *
LibIp6Route(const ip6_addr_t *src, const ip6_addr_t *dest)
{
    ROUTE6_MATCH Best;

    UNREFERENCED_PARAMETER(src);

    if (!Route6Active() || Route6IsOwnAddress(dest))
        return NULL;
    if (!Route6Find(dest, NULL, &Best) || Best.FromRa)
        return NULL;
    return Best.Netif;
}

/* LWIP_HOOK_ND6_GET_GW (core lock held): the next hop of a destination lwIP does not see on-link, over netif: the
   next hop of the configured route that is the best one there, or the destination itself for an on-link one; NULL
   lets lwIP pick one of its default routers */
const ip6_addr_t *
LibNd6GetGw(struct netif *netif, const ip6_addr_t *dest)
{
    ROUTE6_MATCH Best;

    if (!Route6Active())
        return NULL;
    if (!Route6Find(dest, netif, &Best) || Best.FromRa)
        return NULL;
    return Best.NextHop ? Best.NextHop : dest;
}

/* The routes changed (core lock held): lwIP's destination cache keeps a next hop for each destination it has seen,
   which has to be found again */
static
VOID
Route6Changed(VOID)
{
    nd6_clear_destination_cache();
}

/* LWIP_HOOK_ND6_TMR (core lock held, once a second): configured routes whose valid lifetime ended go */
void
LibNd6Timer(void)
{
    ULONGLONG Now;
    BOOLEAN Changed = FALSE;
    ULONG i;

    if (!Route6Count)
        return;

    Now = Route6Seconds();
    for (i = 0; i < ROUTE6_MAX; i++)
    {
        PROUTE6_ENTRY Entry = &Route6Table[i];

        if (!Entry->Netif || Route6Left(Entry->ValidLifetime, Entry->Created, Now))
            continue;
        RtlZeroMemory(Entry, sizeof(*Entry));
        Route6Count--;
        Changed = TRUE;
    }

    if (Changed)
    {
        Route6Changed();
        RouteChangeNotify();
    }
}

static PROUTE6_ENTRY Route6Lookup(struct netif *netif, const ip6_addr_t *Prefix, UCHAR Length, BOOLEAN OnLink,
                                  const ip6_addr_t *NextHop);

/* LWIP_HOOK_ND6_ROUTE_INFO (core lock held): a route information option (RFC 4191 2.3) of a router advertisement
   that passed lwIP's checks: Prefix (16 bytes, the bits after Length are ignored) is reachable through Router, with
   the metric of Preference (the 2-bit field), for Lifetime seconds (0xFFFFFFFF: infinite; 0 removes the route). The
   route is an entry of the table like a configured one (the stack routes by it) with the origin router advertisement.
   A route a program configured for the same prefix and router stays as it is. At most ROUTE6_RA_MAX such routes: a new
   one replaces the oldest when they are all there. A refresh with the same preference only moves the lifetime. */
void
LibNd6RouteInfo(struct netif *netif, const ip6_addr_t *Router, const u8_t *PrefixBytes, u8_t Length, u8_t Preference,
                u32_t Lifetime)
{
    ip6_addr_t Prefix, NextHop;
    PROUTE6_ENTRY Entry;
    ULONG IfIndex = Route6IfIndex(netif), i, RaCount = 0, Oldest = ROUTE6_MAX;
    ULONG Metric = Route6PreferenceMetric(Preference);
    BOOLEAN Changed = FALSE;

    if (!IfIndex || Length > 128 || ip6_addr_isany(Router) || !ip6_addr_islinklocal(Router))
        return;

    RtlZeroMemory(&Prefix, sizeof(Prefix));
    RtlCopyMemory(Prefix.addr, PrefixBytes, 16);
    Route6Mask(&Prefix, Length);
    /* a destination that is no global or unique local unicast prefix: link-local and multicast are not routed by
       an advertisement */
    if (ip6_addr_islinklocal(&Prefix) || ip6_addr_ismulticast(&Prefix) || ip6_addr_isloopback(&Prefix))
        return;

    NextHop = *Router;
    ip6_addr_assign_zone(&NextHop, IP6_UNICAST, netif);

    Entry = Route6Lookup(netif, &Prefix, Length, FALSE, &NextHop);
    if (Entry && !(Entry->Flags & TCP_IPV6_ROUTE_FROM_RA))
        return;                         /* configured: left as it is */

    if (Lifetime == 0)
    {
        if (Entry)
        {
            RtlZeroMemory(Entry, sizeof(*Entry));
            Route6Count--;
            Route6Changed();
            RouteChangeNotify();
        }
        return;
    }

    if (!Entry)
    {
        for (i = 0; i < ROUTE6_MAX; i++)
        {
            PROUTE6_ENTRY Other = &Route6Table[i];

            if (Other->Netif && (Other->Flags & TCP_IPV6_ROUTE_FROM_RA))
            {
                RaCount++;
                if (Oldest == ROUTE6_MAX || Other->Created < Route6Table[Oldest].Created)
                    Oldest = i;
            }
        }
        if (RaCount >= ROUTE6_RA_MAX && Oldest < ROUTE6_MAX)
        {
            RtlZeroMemory(&Route6Table[Oldest], sizeof(Route6Table[Oldest]));
            Route6Count--;
        }
        for (i = 0; i < ROUTE6_MAX && Route6Table[i].Netif; i++)
            ;
        if (i == ROUTE6_MAX)
            return;                     /* the table is full of configured routes */
        Entry = &Route6Table[i];
        RtlZeroMemory(Entry, sizeof(*Entry));
        Entry->Netif = netif;
        Entry->IfIndex = IfIndex;
        Entry->Prefix = Prefix;
        Entry->PrefixLength = Length;
        Entry->OnLink = FALSE;
        Entry->NextHop = NextHop;
        Route6Count++;
        Changed = TRUE;
    }
    else if (Entry->Metric != Metric)
        Changed = TRUE;

    Entry->Metric = Metric;
    Entry->Origin = ROUTE6_ORIGIN_RA;
    Entry->Protocol = ROUTE6_PROTOCOL_NETMGMT;
    Entry->Flags = TCP_IPV6_ROUTE_FROM_RA;
    Entry->ValidLifetime = Lifetime;
    Entry->PreferredLifetime = Lifetime;
    Entry->Created = Route6Seconds();

    if (Changed)
    {
        Route6Changed();
        RouteChangeNotify();
    }
}

/* The interface goes (core lock held, before netif_remove): its configured routes go with it, and what was kept for
   its configured addresses and what its router advertisements told (ra6.c) */
VOID
TCP6RemoveRoutesOfNetif(struct netif *netif)
{
    BOOLEAN Changed = FALSE;
    ULONG i;

    TCP6RemoveAddressesOfNetif(netif);
    TCP6RemoveRaOfNetif(netif);

    for (i = 0; i < ROUTE6_MAX && Route6Count; i++)
    {
        if (Route6Table[i].Netif != netif)
            continue;
        RtlZeroMemory(&Route6Table[i], sizeof(Route6Table[i]));
        Route6Count--;
        Changed = TRUE;
    }

    if (Changed)
    {
        Route6Changed();
        RouteChangeNotify();
    }
}

/* The next row of an answer: in Out while it fits, else a scratch row that is thrown away (the size still counts it) */
static
PTCP_IPV6_ROUTE_ROW
Route6NextRow(PTCP_IPV6_ROUTE_ROW Rows, BOOLEAN Fits, ULONG OutSize, PULONG Count, PTCP_IPV6_ROUTE_ROW Scratch)
{
    PTCP_IPV6_ROUTE_ROW Row = Scratch;

    if (Fits && OutSize >= sizeof(TCP_IPV6_ROUTE_HEADER) + (*Count + 1) * sizeof(*Row))
        Row = &Rows[*Count];
    RtlZeroMemory(Row, sizeof(*Row));
    (*Count)++;
    return Row;
}

/* The IP_IPV6_ROUTE_ENTRY_ID answer: TCP_IPV6_ROUTE_HEADER, then the rows. Returns the size of the whole answer;
 * what fits in Out (OutSize bytes) is written, so a caller whose buffer is too small gets the size and asks again.
 * Off: the header alone, with Enabled 0. PASSIVE_LEVEL */
ULONG
TCPQueryIpv6Routes(PVOID Out, ULONG OutSize)
{
    PTCP_IPV6_ROUTE_HEADER Header = Out;
    PTCP_IPV6_ROUTE_ROW Rows = (PTCP_IPV6_ROUTE_ROW)(Header + 1);
    BOOLEAN Fits = (Out != NULL && OutSize >= sizeof(*Header));
    ULONG Count = 0, i, Seen;
    ULONGLONG Now;

    TCP_IPV6_ROUTE_ROW Scratch;
    PTCP_IPV6_ROUTE_ROW Row;

    if (!TCPIpv6Enabled)
    {
        if (Fits)
            RtlZeroMemory(Header, sizeof(*Header));
        return sizeof(*Header);
    }

    LOCK_TCPIP_CORE();
    Now = Route6Seconds();

    for (i = 0, Seen = 0; i < ROUTE6_MAX && Seen < Route6Count; i++)
    {
        PROUTE6_ENTRY Entry = &Route6Table[i];
        ULONG Valid;

        if (!Entry->Netif)
            continue;
        Seen++;
        Valid = Route6Left(Entry->ValidLifetime, Entry->Created, Now);
        if (!Valid)
            continue;

        Row = Route6NextRow(Rows, Fits, OutSize, &Count, &Scratch);
        Row->IfIndex = Entry->IfIndex;
        RtlCopyMemory(Row->Prefix, Entry->Prefix.addr, 16);
        Row->PrefixLength = Entry->PrefixLength;
        if (!Entry->OnLink)
            RtlCopyMemory(Row->NextHop, Entry->NextHop.addr, 16);
        Row->Metric = Entry->Metric;
        Row->ValidLifetime = Valid;
        Row->PreferredLifetime = min(Route6Left(Entry->PreferredLifetime, Entry->Created, Now), Valid);
        Row->Origin = Entry->Origin;
        Row->Protocol = Entry->Protocol;
        Row->Flags = Entry->Flags;
        Row->Age = (ULONG)min(Now - Entry->Created, 0xFFFFFFFFULL);
    }

    /* The on-link prefixes of configured addresses (one row for a prefix two of them share) */
    if (Addr6Count)
    {
        struct netif *netif;
        ip6_addr_t Prefix;
        UCHAR Length;
        s8_t Slot;

        NETIF_FOREACH(netif)
        {
            ULONG IfIndex = Route6IfIndex(netif);

            if (!IfIndex)
                continue;
            for (Slot = 0; Slot < LWIP_IPV6_NUM_ADDRESSES; Slot++)
            {
                u32_t Valid, Preferred;

                if (!Route6AddressPrefix(netif, Slot, &Prefix, &Length) ||
                    Route6AddressPrefixSeen(netif, Slot, &Prefix, Length))
                    continue;
                Valid = netif_ip6_addr_valid_life(netif, Slot);
                Preferred = netif_ip6_addr_pref_life(netif, Slot);

                Row = Route6NextRow(Rows, Fits, OutSize, &Count, &Scratch);
                Row->IfIndex = IfIndex;
                RtlCopyMemory(Row->Prefix, Prefix.addr, 16);
                Row->PrefixLength = Length;
                Row->Metric = ROUTE6_RA_METRIC;
                Row->ValidLifetime = ip6_addr_life_isinfinite(Valid) ? ROUTE6_INFINITE : Valid;
                Row->PreferredLifetime = ip6_addr_life_isinfinite(Preferred) ? ROUTE6_INFINITE : Preferred;
                Row->Origin = ROUTE6_ORIGIN_MANUAL;
                Row->Protocol = ROUTE6_PROTOCOL_LOCAL;
                Row->Flags = TCP_IPV6_ROUTE_FROM_ADDRESS;
            }
        }
    }

    /* What router advertisements gave, as the neighbour discovery and DNS tables hand it out (nd6info.c,
       rdnss6.c): the on-link prefixes, then the default routers */
    for (i = 0; i < LWIP_ND6_NUM_PREFIXES; i++)
    {
        const struct nd6_prefix_list_entry *Entry = &prefix_list[i];
        ULONG IfIndex;

        if (Entry->netif == NULL || Entry->invalidation_timer == 0 || !netif_is_up(Entry->netif))
            continue;
        IfIndex = Route6IfIndex(Entry->netif);
        if (!IfIndex)
            continue;

        Row = Route6NextRow(Rows, Fits, OutSize, &Count, &Scratch);
        Row->IfIndex = IfIndex;
        RtlCopyMemory(Row->Prefix, Entry->prefix.addr, 16);
        Row->PrefixLength = 64;
        Row->Metric = ROUTE6_RA_METRIC;
        Row->ValidLifetime = Row->PreferredLifetime = Entry->invalidation_timer;
        Row->Origin = ROUTE6_ORIGIN_RA;
        Row->Protocol = ROUTE6_PROTOCOL_NETMGMT;
        Row->Flags = TCP_IPV6_ROUTE_FROM_RA;
    }

    for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++)
    {
        struct nd6_neighbor_cache_entry *Neighbor = default_router_list[i].neighbor_entry;
        ULONG IfIndex;

        if (Neighbor == NULL || default_router_list[i].invalidation_timer == 0 || Neighbor->netif == NULL)
            continue;
        IfIndex = Route6IfIndex(Neighbor->netif);
        if (!IfIndex || !netif_is_up(Neighbor->netif))
            continue;

        Row = Route6NextRow(Rows, Fits, OutSize, &Count, &Scratch);
        Row->IfIndex = IfIndex;
        Row->PrefixLength = 0;
        RtlCopyMemory(Row->NextHop, Neighbor->next_hop_address.addr, 16);
        Row->Metric = Route6PreferenceMetric((UCHAR)(default_router_list[i].flags >> 3));
        Row->ValidLifetime = Row->PreferredLifetime = default_router_list[i].invalidation_timer;
        Row->Origin = ROUTE6_ORIGIN_RA;
        Row->Protocol = ROUTE6_PROTOCOL_NETMGMT;
        Row->Flags = TCP_IPV6_ROUTE_FROM_RA;
    }

    if (Fits)
    {
        Header->Enabled = 1;
        Header->Count = Count;
    }
    UNLOCK_TCPIP_CORE();

    return sizeof(*Header) + Count * sizeof(TCP_IPV6_ROUTE_ROW);
}

/* The interface with this index that can have IPv6 routes and addresses (an Ethernet one, not the loopback
   interface), referenced, or NULL */
PIP_INTERFACE
TCP6ReferenceInterface(ULONG IfIndex)
{
    PIP_INTERFACE Found = NULL;
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    ForEachInterface(CurrentIF) {
        if (CurrentIF->Index == IfIndex)
        {
            if (CurrentIF != Loopback && CurrentIF->TCPContext && CurrentIF->AddressLength == 6)
            {
                IPReferenceInterface(CurrentIF);
                Found = CurrentIF;
            }
            break;
        }
    } EndFor(CurrentIF);
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return Found;
}

/* Whether netif is still one of lwIP's interfaces (core lock held): an interface that went has its routes and
   addresses removed already, nothing may be added to it */
BOOLEAN
TCP6NetifRegistered(struct netif *netif)
{
    struct netif *Current;

    NETIF_FOREACH(Current)
    {
        if (Current == netif)
            return TRUE;
    }
    return FALSE;
}

static
PROUTE6_ENTRY
Route6Lookup(struct netif *netif, const ip6_addr_t *Prefix, UCHAR Length, BOOLEAN OnLink, const ip6_addr_t *NextHop)
{
    ULONG i;

    for (i = 0; i < ROUTE6_MAX; i++)
    {
        PROUTE6_ENTRY Entry = &Route6Table[i];

        if (Entry->Netif != netif || Entry->PrefixLength != Length || Entry->OnLink != OnLink)
            continue;
        if (!ip6_addr_zoneless_eq(&Entry->Prefix, Prefix))
            continue;
        if (!OnLink && !ip6_addr_zoneless_eq(&Entry->NextHop, NextHop))
            continue;
        return Entry;
    }
    return NULL;
}

/* A route request, checked: the prefix (masked) and next hop it names. Returns STATUS_SUCCESS or the reason */
static
NTSTATUS
Route6CheckRequest(const TCP_IPV6_ROUTE_REQUEST *Request, ip6_addr_t *Prefix, ip6_addr_t *NextHop, PBOOLEAN OnLink)
{
    if (Request->Operation < TCP_IPV6_CONFIG_CREATE || Request->Operation > TCP_IPV6_CONFIG_DELETE)
        return STATUS_INVALID_PARAMETER;
    if (Request->Store != TCP_IPV6_STORE_ACTIVE && Request->Store != TCP_IPV6_STORE_PERSISTENT)
        return STATUS_INVALID_PARAMETER;
    if (Request->PrefixLength > 128)
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(Prefix->addr, Request->Prefix, 16);
    ip6_addr_clear_zone(Prefix);
    /* the bits after the prefix length name nothing (Windows is not asked whether it refuses them: it is not more
       lenient to take them) */
    Route6Mask(Prefix, (UCHAR)Request->PrefixLength);

    RtlCopyMemory(NextHop->addr, Request->NextHop, 16);
    ip6_addr_clear_zone(NextHop);
    *OnLink = ip6_addr_isany(NextHop);
    if (!*OnLink && (ip6_addr_ismulticast(NextHop) || ip6_addr_isloopback(NextHop)))
        return STATUS_INVALID_PARAMETER;

    if (Request->Operation != TCP_IPV6_CONFIG_DELETE)
    {
        if (Request->ValidLifetime == 0 || Request->PreferredLifetime > Request->ValidLifetime)
            return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* Creates, changes or removes a route over netif (core lock held). Persistent: the route is in the persistent store
   too (a change keeps that); *WasPersistent: it was before */
static
NTSTATUS
Route6ConfigureLocked(struct netif *netif, ULONG IfIndex, const TCP_IPV6_ROUTE_REQUEST *Request,
                      const ip6_addr_t *Prefix, const ip6_addr_t *Hop, BOOLEAN OnLink, BOOLEAN Persistent,
                      PBOOLEAN WasPersistent)
{
    ip6_addr_t NextHop = *Hop;
    PROUTE6_ENTRY Entry;
    NTSTATUS Status;
    ULONG i;

    if (!OnLink && ip6_addr_islinklocal(&NextHop))
        ip6_addr_assign_zone(&NextHop, IP6_UNICAST, netif);

    Entry = Route6Lookup(netif, Prefix, (UCHAR)Request->PrefixLength, OnLink, &NextHop);
    *WasPersistent = Entry && (Entry->Flags & TCP_IPV6_ROUTE_PERSISTENT);
    Persistent = Persistent || *WasPersistent;

    switch (Request->Operation)
    {
        case TCP_IPV6_CONFIG_CREATE:
            if (Entry)
                return STATUS_OBJECT_NAME_COLLISION;
            for (i = 0; i < ROUTE6_MAX && Route6Table[i].Netif; i++)
                ;
            if (i == ROUTE6_MAX)
                return STATUS_INSUFFICIENT_RESOURCES;
            Entry = &Route6Table[i];
            RtlZeroMemory(Entry, sizeof(*Entry));
            Entry->Netif = netif;
            Entry->IfIndex = IfIndex;
            Entry->Prefix = *Prefix;
            Entry->PrefixLength = (UCHAR)Request->PrefixLength;
            Entry->OnLink = OnLink;
            if (!OnLink)
                Entry->NextHop = NextHop;
            Route6Count++;
            /* the rest as for a change */
            /* fall through */
        case TCP_IPV6_CONFIG_SET:
            if (!Entry)
                return STATUS_NOT_FOUND;
            Entry->Metric = Request->Metric;
            Entry->Origin = Request->Origin;
            Entry->Protocol = Request->Protocol;
            Entry->Flags = (Request->Flags & (TCP_IPV6_ROUTE_PUBLISH | TCP_IPV6_ROUTE_IMMORTAL)) |
                           (Persistent ? TCP_IPV6_ROUTE_PERSISTENT : 0);
            Entry->ValidLifetime = Request->ValidLifetime;
            Entry->PreferredLifetime = Request->PreferredLifetime;
            Entry->Created = Route6Seconds();
            Status = STATUS_SUCCESS;
            break;

        case TCP_IPV6_CONFIG_DELETE:
            if (!Entry)
                return STATUS_NOT_FOUND;
            RtlZeroMemory(Entry, sizeof(*Entry));
            Route6Count--;
            Status = STATUS_SUCCESS;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    Route6Changed();
    return Status;
}

/* A persistent record (persist6.c), with the adapter's start (core lock held): the route is added unless it is
   there. STATUS_SUCCESS: added */
NTSTATUS
TCP6ApplyRouteLocked(PIP_INTERFACE IF, struct netif *netif, const TCP_IPV6_ROUTE_REQUEST *Record)
{
    TCP_IPV6_ROUTE_REQUEST Request = *Record;
    ip6_addr_t Prefix, NextHop;
    BOOLEAN OnLink, WasPersistent;
    NTSTATUS Status;

    Request.Operation = TCP_IPV6_CONFIG_CREATE;
    Request.Store = TCP_IPV6_STORE_PERSISTENT;
    Status = Route6CheckRequest(&Request, &Prefix, &NextHop, &OnLink);
    if (!NT_SUCCESS(Status))
        return Status;
    return Route6ConfigureLocked(netif, IF->Index, &Request, &Prefix, &NextHop, OnLink, TRUE, &WasPersistent);
}

/* IOCTL_IP6_ROUTE_CONFIG (the caller is an administrator: TiDispatch checked) */
NTSTATUS
DispRouteConfig6(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    TCP_IPV6_ROUTE_REQUEST Request, Undo;
    PIP_INTERFACE IF;
    struct netif *netif;
    ip6_addr_t Prefix, NextHop;
    BOOLEAN OnLink, Persistent, WasPersistent = FALSE, Found;
    NTSTATUS Status, StoreStatus;

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(Request) || !Irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&Request, Irp->AssociatedIrp.SystemBuffer, sizeof(Request));

    if (!TCPIpv6Enabled)
        return STATUS_NOT_SUPPORTED;

    Status = Route6CheckRequest(&Request, &Prefix, &NextHop, &OnLink);
    if (!NT_SUCCESS(Status))
        return Status;
    Persistent = (Request.Store == TCP_IPV6_STORE_PERSISTENT);
    /* the record of the persistent store names the route as the table does: the prefix without its host bits */
    RtlCopyMemory(Request.Prefix, Prefix.addr, 16);

    IF = TCP6ReferenceInterface(Request.IfIndex);
    if (!IF)
        return STATUS_NOT_FOUND;
    netif = IF->TCPContext;

    /* DisabledComponents: only the loopback interface has IPv6 */
    if (!TCPIpv6Links && IF != Loopback)
    {
        IPDereferenceInterface(IF);
        return STATUS_NOT_SUPPORTED;
    }

    LOCK_TCPIP_CORE();
    if (TCP6NetifRegistered(netif))
        Status = Route6ConfigureLocked(netif, IF->Index, &Request, &Prefix, &NextHop, OnLink, Persistent,
                                       &WasPersistent);
    else
        Status = STATUS_NOT_FOUND;
    UNLOCK_TCPIP_CORE();

    /* the persistent store: a removal takes the route out of both stores, a creation or change of a persistent
       route writes it */
    if (Request.Operation == TCP_IPV6_CONFIG_DELETE)
    {
        StoreStatus = TCP6PersistRoute(IF, &Request, TRUE, &Found);
        if (Status == STATUS_NOT_FOUND && NT_SUCCESS(StoreStatus) && Found)
            Status = STATUS_SUCCESS;
        else if (NT_SUCCESS(Status) && !NT_SUCCESS(StoreStatus))
            Status = StoreStatus;
    }
    else if (NT_SUCCESS(Status) && (Persistent || WasPersistent))
    {
        StoreStatus = TCP6PersistRoute(IF, &Request, FALSE, &Found);
        if (!NT_SUCCESS(StoreStatus))
        {
            if (Request.Operation == TCP_IPV6_CONFIG_CREATE)
            {
                Undo = Request;
                Undo.Operation = TCP_IPV6_CONFIG_DELETE;
                LOCK_TCPIP_CORE();
                if (TCP6NetifRegistered(netif))
                    Route6ConfigureLocked(netif, IF->Index, &Undo, &Prefix, &NextHop, OnLink, FALSE, &WasPersistent);
                UNLOCK_TCPIP_CORE();
            }
            Status = StoreStatus;
        }
    }
    IPDereferenceInterface(IF);

    if (NT_SUCCESS(Status))
        RouteChangeNotify();
    return Status;
}
