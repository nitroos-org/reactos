/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What router advertisements tell besides prefixes, DNS servers and routers: DNS search lists
 *              (RFC 8106), the M and O flags, the current hop limit (RFC 4861 4.2)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Like rdnss6.c: lwIP calls the hooks below (lwipopts.h) with the core lock held, only for router advertisements
 * that passed its checks (link-local source, hop limit 255); nothing is stored while IPv6 is off.
 *
 * - LibTCPDnssl6Input reads one DNSSL option from the packet and keeps its domain names with their lifetime
 *   (RA6_MAX_SUFFIXES over all interfaces; when they are all in use the interface that holds the most gives one up,
 *   its least recently refreshed, so an interface that sends names all the time replaces its own first and cannot
 *   push out those of the others; it is the interface, not the router, because an interface's search list is one
 *   list whoever sent a name and the stored name carries no sender); IP_IPV6_RA_ENTRY_ID hands them to iphlpapi (GetAdaptersAddresses FirstDnsSuffix, the resolver's
 *   search list, ipconfig /all). The option comes from the network: every length is checked here, and a name is
 *   kept only when it is made of letters, digits, '-' and '_' (what a host name or a punycode label has).
 * - LibNd6RaHeader keeps the M and O flags and the current hop limit of an interface, in its IP_INTERFACE. The
 *   flags are exported in the rows of the IPv6 table (TCP_IPV6_INTERFACE_ROW; GetIpInterfaceEntry), a change of
 *   them completes the interface change requests. A hop limit of 0 (unspecified, RFC 4861 4.2) leaves the one
 *   before. LibIp6HopLimit gives it to datagrams whose sender did not choose one.
 */

#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/prot/nd6.h"
#include "lwip/priv/nd6_priv.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include <lwip_hooks.h>

/* All interfaces together */
#define RA6_MAX_SUFFIXES        16
/* A name of the DNS is at most 255 octets in the label encoding: 253 characters without the final dot */
#define RA6_NAME_MAX            253
/* The most an option can hold: 255 units of 8 bytes */
#define RA6_OPTION_MAX          (255 * 8)

typedef struct _RA6_SUFFIX
{
    BOOLEAN InUse;
    BOOLEAN Infinite;
    ULONG IfIndex;
    ULONGLONG Expire;           /* Ra6Now() */
    ULONGLONG Seq;              /* Ra6Sequence when stored or last refreshed: the smallest is the oldest */
    CHAR Name[RA6_NAME_MAX + 1];
} RA6_SUFFIX;

/* Guarded by the lwIP core lock */
static RA6_SUFFIX Ra6Suffixes[RA6_MAX_SUFFIXES];
static ULONGLONG Ra6Sequence;
/* The option as read from the packet (core lock: one reader at a time) */
static UCHAR Ra6Option[RA6_OPTION_MAX];

static
ULONG
Ra6InterfaceIndex(const struct netif *netif)
{
    return (netif && netif->state) ? ((PIP_INTERFACE)netif->state)->Index : 0;
}

/* Monotonic milliseconds since boot */
static
ULONGLONG
Ra6Now(VOID)
{
    return KeQueryInterruptTime() / 10000;
}

static
ULONG
Ra6Remaining(const RA6_SUFFIX *Entry, ULONGLONG Now)
{
    if (Entry->Infinite)
        return 0xFFFFFFFF;
    if (Entry->Expire <= Now)
        return 0;
    return (ULONG)min((Entry->Expire - Now + 999) / 1000, 0xFFFFFFFEUL);
}

static
BOOLEAN
Ra6NameCharacter(UCHAR c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static
BOOLEAN
Ra6SameName(const CHAR *A, const CHAR *B)
{
    return _stricmp(A, B) == 0;
}

/* All entries are in use: the one that gives way to a name of interface IfIndex. The interface that holds the most
   entries loses its least recently refreshed (on a tie the one the name is for: it replaces its own); core lock held */
static
ULONG
Ra6Victim(ULONG IfIndex)
{
    ULONG i, j, Best = 0, BestCount = 0, BestIf = 0, Victim = RA6_MAX_SUFFIXES;

    for (i = 0; i < RA6_MAX_SUFFIXES; i++)
    {
        ULONG Count = 0;

        for (j = 0; j < RA6_MAX_SUFFIXES; j++)
        {
            if (Ra6Suffixes[j].InUse && Ra6Suffixes[j].IfIndex == Ra6Suffixes[i].IfIndex)
                Count++;
        }
        if (Count > BestCount || (Count == BestCount && Ra6Suffixes[i].IfIndex == IfIndex))
        {
            Best = i;
            BestCount = Count;
            BestIf = Ra6Suffixes[i].IfIndex;
        }
    }

    for (i = 0; i < RA6_MAX_SUFFIXES; i++)
    {
        if (Ra6Suffixes[i].InUse && Ra6Suffixes[i].IfIndex == BestIf &&
            (Victim == RA6_MAX_SUFFIXES || Ra6Suffixes[i].Seq < Ra6Suffixes[Victim].Seq))
            Victim = i;
    }
    return Victim == RA6_MAX_SUFFIXES ? Best : Victim;
}

/* One domain name of the list, in the dotted form, for the interface: stores it, or removes it for a lifetime of 0
   (RFC 8106 5.2); core lock held */
static
VOID
Ra6SetSuffix(ULONG IfIndex, const CHAR *Name, ULONG Lifetime)
{
    ULONGLONG Now = Ra6Now();
    ULONG i, Slot = RA6_MAX_SUFFIXES;

    for (i = 0; i < RA6_MAX_SUFFIXES; i++)
    {
        RA6_SUFFIX *Entry = &Ra6Suffixes[i];

        if (Entry->InUse && Entry->IfIndex == IfIndex && Ra6SameName(Entry->Name, Name))
        {
            Slot = i;
            break;
        }
        if (Slot == RA6_MAX_SUFFIXES && (!Entry->InUse || Ra6Remaining(Entry, Now) == 0))
            Slot = i;
    }

    if (Lifetime == 0)
    {
        if (Slot < RA6_MAX_SUFFIXES && Ra6Suffixes[Slot].InUse && Ra6Suffixes[Slot].IfIndex == IfIndex &&
            Ra6SameName(Ra6Suffixes[Slot].Name, Name))
            Ra6Suffixes[Slot].InUse = FALSE;
        return;
    }

    if (Slot == RA6_MAX_SUFFIXES)
        Slot = Ra6Victim(IfIndex);

    Ra6Suffixes[Slot].Seq = ++Ra6Sequence;
    Ra6Suffixes[Slot].InUse = TRUE;
    Ra6Suffixes[Slot].IfIndex = IfIndex;
    RtlCopyMemory(Ra6Suffixes[Slot].Name, Name, strlen(Name) + 1);
    Ra6Suffixes[Slot].Infinite = (Lifetime == 0xFFFFFFFF);
    if (!Ra6Suffixes[Slot].Infinite)
        Ra6Suffixes[Slot].Expire = Now + (ULONGLONG)Lifetime * 1000;
}

/*
 * The names of a DNSSL option body (Data, Length bytes after the 8 of the base): each is labels (a length of 1 to 63,
 * then that many characters) ended by a zero length; a zero where a name starts is padding and ends the list (RFC
 * 8106 5.2). A name is cut off by the end of the option, longer than 253 characters, has a label of 0 or more than 63
 * characters (compression is not allowed in the option: a length above 63 is not a label), or a character
 * outside letters, digits, '-', '_' is skipped, and so is everything after a cut-off one (there is no way to find the
 * next name). Calls Ra6SetSuffix for each good one. Returns how many names it took.
 */
ULONG
Ra6ParseNames(ULONG IfIndex, const UCHAR *Data, ULONG Length, ULONG Lifetime)
{
    ULONG Pos = 0, Taken = 0;

    while (Pos < Length && Data[Pos] != 0)
    {
        CHAR Name[RA6_NAME_MAX + 1];
        ULONG Used = 0;
        BOOLEAN Good = TRUE;

        /* one name */
        for (;;)
        {
            ULONG Label, k;

            if (Pos >= Length)
                return Taken;               /* no terminating zero length: the name is cut off */
            Label = Data[Pos++];
            if (Label == 0)
                break;
            if (Label > 63 || Pos + Label > Length)
                return Taken;               /* not a label (compression), or cut off: stop here */
            if (Good)
            {
                if (Used + (Used ? 1 : 0) + Label > RA6_NAME_MAX)
                    Good = FALSE;
                else
                {
                    if (Used)
                        Name[Used++] = '.';
                    for (k = 0; k < Label; k++)
                    {
                        if (!Ra6NameCharacter(Data[Pos + k]))
                            Good = FALSE;
                        Name[Used + k] = (CHAR)Data[Pos + k];
                    }
                    Used += Label;
                }
            }
            Pos += Label;
        }

        if (Good && Used)
        {
            Name[Used] = '\0';
            Ra6SetSuffix(IfIndex, Name, Lifetime);
            Taken++;
        }
    }
    return Taken;
}

/* LWIP_HOOK_ND6_DNSSL: a DNS search list option at Offset of the packet, Length bytes in all (a multiple of 8, at
   least 8, inside the packet: nd6.c checked); core lock held */
void
LibTCPDnssl6Input(struct netif *netif, struct pbuf *p, u16_t Offset, u16_t Length)
{
    ULONG IfIndex = Ra6InterfaceIndex(netif);
    ULONG Lifetime;

    if (!IfIndex || Length < SIZEOF_DNSSL_OPTION_BASE || Length > sizeof(Ra6Option))
        return;
    if (pbuf_copy_partial(p, Ra6Option, Length, Offset) != Length)
        return;

    /* type, length, 2 reserved, then the lifetime (network order) */
    Lifetime = ((ULONG)Ra6Option[4] << 24) | ((ULONG)Ra6Option[5] << 16) | ((ULONG)Ra6Option[6] << 8) | Ra6Option[7];
    Ra6ParseNames(IfIndex, Ra6Option + SIZEOF_DNSSL_OPTION_BASE, Length - SIZEOF_DNSSL_OPTION_BASE, Lifetime);
}

/* LWIP_HOOK_ND6_RA_HEADER: the header of a router advertisement that passed the checks; core lock held. The flags of
   an interface are those of this advertisement and of every default router of the interface that is still valid (their
   last advertisement): with two routers that disagree the flags stay set, and do not follow whichever advertisement
   came last. The current hop limit is the last non-zero one (RFC 4861 6.3.4) */
void
LibNd6RaHeader(struct netif *netif, u8_t CurHopLimit, u8_t Flags)
{
    PIP_INTERFACE IF;
    UCHAR RaFlags = 0;
    ULONG i;
    u8_t All = Flags;

    if (!netif || !netif->state)
        return;
    IF = netif->state;

    for (i = 0; i < LWIP_ND6_NUM_ROUTERS; i++)
    {
        struct nd6_neighbor_cache_entry *Neighbor = default_router_list[i].neighbor_entry;

        if (Neighbor && Neighbor->netif == netif && default_router_list[i].invalidation_timer > 0)
            All |= default_router_list[i].flags;
    }

    if (All & ND6_RA_FLAG_MANAGED_ADDR_CONFIG)
        RaFlags |= TCP_IPV6_IF_RA_MANAGED;
    if (All & ND6_RA_FLAG_OTHER_CONFIG)
        RaFlags |= TCP_IPV6_IF_RA_OTHER;

    /* 0: unspecified by this router, what was before stays */
    if (CurHopLimit)
        IF->Ra6HopLimit = CurHopLimit;

    if (IF->Ra6Flags != RaFlags)
    {
        IF->Ra6Flags = RaFlags;
        /* the interface's M and O flags are part of what NotifyIpInterfaceChange compares; a DHCPv6 client
           watches them */
        AddrChangeNotify6();
    }
}

/* LWIP_HOOK_IP6_HOP_LIMIT (ip6_output_if_src, core lock held): the hop limit a datagram goes out with.
   IP_DEFAULT_TTL is what the stack gives a socket whose owner did not set IP_TTL / IPV6_UNICAST_HOPS: it becomes the
   router's current hop limit of the interface when there is one (a socket that set exactly the default cannot be told
   apart; the loss is the same value). Anything else, and everything that is not IPv6 data, stays */
u8_t
LibIp6HopLimit(struct netif *netif, u8_t Hl)
{
    PIP_INTERFACE IF;

    if (Hl != IP_DEFAULT_TTL || !netif || !netif->state)
        return Hl;
    IF = netif->state;
    return IF->Ra6HopLimit ? IF->Ra6HopLimit : Hl;
}

/* The interface goes (core lock held, before netif_remove): its search domains go with it */
VOID
TCP6RemoveRaOfNetif(struct netif *netif)
{
    ULONG IfIndex = Ra6InterfaceIndex(netif), i;

    if (!IfIndex)
        return;
    for (i = 0; i < RA6_MAX_SUFFIXES; i++)
    {
        if (Ra6Suffixes[i].InUse && Ra6Suffixes[i].IfIndex == IfIndex)
            Ra6Suffixes[i].InUse = FALSE;
    }
}

/* True when an interface with this index is still there; core lock held */
static
BOOLEAN
Ra6InterfaceExists(ULONG IfIndex)
{
    struct netif *netif;

    NETIF_FOREACH(netif)
    {
        if (Ra6InterfaceIndex(netif) == IfIndex)
            return TRUE;
    }
    return FALSE;
}

/* The IP_IPV6_RA_ENTRY_ID answer: TCP_IPV6_RA_HEADER and its rows (the search domains of router advertisements).
 * Returns the size of the whole answer; what fits in Out (OutSize bytes) is written, so a caller whose buffer is too
 * small gets the size and asks again. Off: the header alone, with Enabled 0. PASSIVE_LEVEL */
ULONG
TCPQueryIpv6Ra(PVOID Out, ULONG OutSize)
{
    PTCP_IPV6_RA_HEADER Header = Out;
    PTCP_IPV6_RA_ROW Rows = (PTCP_IPV6_RA_ROW)(Header + 1);
    ULONG Count = 0, i;
    ULONGLONG Now;
    BOOLEAN Fits = (Out != NULL && OutSize >= sizeof(*Header));

    if (!TCPIpv6Enabled)
    {
        if (Fits)
            RtlZeroMemory(Header, sizeof(*Header));
        return sizeof(*Header);
    }

    LOCK_TCPIP_CORE();
    Now = Ra6Now();

    for (i = 0; i < RA6_MAX_SUFFIXES; i++)
    {
        RA6_SUFFIX *Entry = &Ra6Suffixes[i];
        ULONG Left;

        if (!Entry->InUse)
            continue;
        Left = Ra6Remaining(Entry, Now);
        if (Left == 0 || !Ra6InterfaceExists(Entry->IfIndex))
        {
            Entry->InUse = FALSE;
            continue;
        }
        if (Fits && OutSize >= sizeof(*Header) + (Count + 1) * sizeof(*Rows))
        {
            RtlZeroMemory(&Rows[Count], sizeof(Rows[Count]));
            Rows[Count].IfIndex = Entry->IfIndex;
            Rows[Count].Lifetime = Left;
            RtlCopyMemory(Rows[Count].Name, Entry->Name, strlen(Entry->Name) + 1);
        }
        Count++;
    }

    if (Fits)
    {
        Header->Enabled = 1;
        Header->Count = Count;
    }
    UNLOCK_TCPIP_CORE();

    return sizeof(*Header) + Count * sizeof(*Rows);
}
