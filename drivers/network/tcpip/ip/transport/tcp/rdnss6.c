/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IPv6 DNS servers of router advertisements (RFC 8106) and the default routers, for user mode
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The resolver lives in user mode (dnsapi); the stack only has to remember what router advertisements tell it.
 * lwIP calls LibTCPRdnss6Input (LWIP_HOOK_ND6_RDNSS) for every address of an RDNSS option, with the core lock
 * held; IP_IPV6_DNS_ENTRY_ID (tcpioctl.h) hands the list, with the default routers of the stack, to iphlpapi.
 * Only router advertisements that passed lwIP's checks (RFC 4861 6.1.2: link-local source, hop limit 255) get
 * here, and nothing is stored while IPv6 is off (no advertisement is processed then).
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

/* All interfaces together: a few servers per advertisement, and a neighbour that sends them all the time
   replaces its own entries first */
#define RDNSS6_MAX_SERVERS      16
/* sys_now() is in milliseconds and wraps: lifetimes are held to what a signed difference can carry (24 days);
   0xFFFFFFFF stays infinite */
#define RDNSS6_MAX_LIFETIME     2000000UL

typedef struct _RDNSS6_ENTRY
{
    BOOLEAN InUse;
    BOOLEAN Infinite;
    ULONG IfIndex;
    UCHAR Address[16];
    u32_t Expire;           /* sys_now() */
} RDNSS6_ENTRY;

/* Guarded by the lwIP core lock */
static RDNSS6_ENTRY Rdnss6Table[RDNSS6_MAX_SERVERS];
static ULONG Rdnss6Next;

static
ULONG
Rdnss6InterfaceIndex(const struct netif *netif)
{
    return (netif && netif->state) ? ((PIP_INTERFACE)netif->state)->Index : 0;
}

/* Seconds left of an entry, 0 when it ran out; 0xFFFFFFFF for an infinite one */
static
ULONG
Rdnss6Remaining(const RDNSS6_ENTRY *Entry, u32_t Now)
{
    LONG Left;

    if (Entry->Infinite)
        return 0xFFFFFFFF;
    Left = (LONG)(Entry->Expire - Now);
    return Left > 0 ? (ULONG)((Left + 999) / 1000) : 0;
}

/* LWIP_HOOK_ND6_RDNSS: one address of a router advertisement's RDNSS option; core lock held. Lifetime 0
   removes the server (RFC 8106 5.1) */
void
LibTCPRdnss6Input(struct netif *netif, const ip6_addr_t *addr, u32_t lifetime)
{
    ULONG IfIndex = Rdnss6InterfaceIndex(netif), i, Slot = RDNSS6_MAX_SERVERS;
    u32_t Now = sys_now();
    UCHAR Raw[16];

    if (!IfIndex || ip6_addr_isany(addr) || ip6_addr_ismulticast(addr) || ip6_addr_isloopback(addr))
        return;

    RtlCopyMemory(Raw, addr->addr, sizeof(Raw));

    /* the server is already there, or the first free (or run out) slot */
    for (i = 0; i < RDNSS6_MAX_SERVERS; i++)
    {
        RDNSS6_ENTRY *Entry = &Rdnss6Table[i];

        if (Entry->InUse && Entry->IfIndex == IfIndex && (RtlCompareMemory(Entry->Address, Raw, sizeof(Raw)) == sizeof(Raw)))
        {
            Slot = i;
            break;
        }
        if (Slot == RDNSS6_MAX_SERVERS && (!Entry->InUse || Rdnss6Remaining(Entry, Now) == 0))
            Slot = i;
    }

    if (lifetime == 0)
    {
        if (Slot < RDNSS6_MAX_SERVERS && Rdnss6Table[Slot].InUse && Rdnss6Table[Slot].IfIndex == IfIndex &&
            (RtlCompareMemory(Rdnss6Table[Slot].Address, Raw, sizeof(Raw)) == sizeof(Raw)))
            Rdnss6Table[Slot].InUse = FALSE;
        return;
    }

    if (Slot == RDNSS6_MAX_SERVERS)
    {
        /* full of live servers: the oldest slot in turn */
        Slot = Rdnss6Next++ % RDNSS6_MAX_SERVERS;
    }

    Rdnss6Table[Slot].InUse = TRUE;
    Rdnss6Table[Slot].IfIndex = IfIndex;
    RtlCopyMemory(Rdnss6Table[Slot].Address, Raw, sizeof(Raw));
    Rdnss6Table[Slot].Infinite = (lifetime == 0xFFFFFFFF);
    if (!Rdnss6Table[Slot].Infinite)
        Rdnss6Table[Slot].Expire = Now + min(lifetime, RDNSS6_MAX_LIFETIME) * 1000;
}

/* True when an interface with this index is still there; core lock held */
static
BOOLEAN
Rdnss6InterfaceExists(ULONG IfIndex)
{
    struct netif *netif;

    NETIF_FOREACH(netif)
    {
        if (Rdnss6InterfaceIndex(netif) == IfIndex)
            return TRUE;
    }
    return FALSE;
}

/* The IP_IPV6_DNS_ENTRY_ID answer: TCP_IPV6_DNS_HEADER and its rows (the DNS servers of router advertisements,
 * then the default routers). Returns the size of the whole answer; what fits in Out (OutSize bytes) is
 * written, so a caller whose buffer is too small gets the size and asks again. Off: the header alone, with
 * Enabled 0. PASSIVE_LEVEL */
ULONG
TCPQueryIpv6Dns(PVOID Out, ULONG OutSize)
{
    PTCP_IPV6_DNS_HEADER Header = Out;
    PTCP_IPV6_DNS_ROW Rows = (PTCP_IPV6_DNS_ROW)(Header + 1);
    ULONG Count = 0, i;
    u32_t Now;
    BOOLEAN Fits = (Out != NULL && OutSize >= sizeof(*Header));

    if (!TCPIpv6Enabled)
    {
        if (Fits)
            RtlZeroMemory(Header, sizeof(*Header));
        return sizeof(*Header);
    }

#define ADD_ROW(_If, _Kind, _Addr, _Life)                                                       \
    do {                                                                                        \
        if (Fits && OutSize >= sizeof(*Header) + (Count + 1) * sizeof(*Rows))                   \
        {                                                                                       \
            Rows[Count].IfIndex = (_If);                                                        \
            Rows[Count].Kind = (_Kind);                                                         \
            RtlCopyMemory(Rows[Count].Address, (_Addr), 16);                                    \
            Rows[Count].Lifetime = (_Life);                                                     \
        }                                                                                       \
        Count++;                                                                                \
    } while (0)

    LOCK_TCPIP_CORE();
    Now = sys_now();

    for (i = 0; i < RDNSS6_MAX_SERVERS; i++)
    {
        RDNSS6_ENTRY *Entry = &Rdnss6Table[i];
        ULONG Left;

        if (!Entry->InUse)
            continue;
        Left = Rdnss6Remaining(Entry, Now);
        if (Left == 0 || !Rdnss6InterfaceExists(Entry->IfIndex))
        {
            Entry->InUse = FALSE;
            continue;
        }
        ADD_ROW(Entry->IfIndex, TCP_IPV6_DNS_SERVER, Entry->Address, Left);
    }

    for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++)
    {
        struct nd6_neighbor_cache_entry *Neighbor = default_router_list[i].neighbor_entry;
        ULONG IfIndex;

        if (Neighbor == NULL || default_router_list[i].invalidation_timer == 0 || Neighbor->netif == NULL)
            continue;
        IfIndex = Rdnss6InterfaceIndex(Neighbor->netif);
        if (!IfIndex || !netif_is_up(Neighbor->netif))
            continue;
        ADD_ROW(IfIndex, TCP_IPV6_DNS_ROUTER, Neighbor->next_hop_address.addr,
                default_router_list[i].invalidation_timer);
    }

    if (Fits)
    {
        Header->Enabled = 1;
        Header->Count = Count;
    }
    UNLOCK_TCPIP_CORE();

#undef ADD_ROW

    return sizeof(*Header) + Count * sizeof(*Rows);
}
