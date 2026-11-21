/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     UDP over IPv6: datagram sockets on lwIP's IPv6 layer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * An IPv6 UDP socket is an address file of our datagram layer (datagram.c: the receive queue, the TDI events,
 * AFD's receives) with an IPv6 address; lwIP is its network layer (routing, source address selection, neighbour
 * discovery, fragmentation and reassembly), as it is for IPv6 TCP. Our own IP layer stays IPv4.
 *
 * Send (UDPSendDatagram6): the UDP header and the RFC 8200 8.1 checksum (pseudo header with the source lwIP
 * selects) are built here, then ip6_output_if. A datagram to a multicast group goes out on the socket's
 * IPV6_MULTICAST_IF or the default interface with the multicast hop limit, and with IPV6_MULTICAST_LOOP (on by
 * default) a copy goes to this machine's members of the group (the loopback interface loops it itself).
 *
 * Receive (LibIp6NexthInput, lwIP's ip6_input after reassembly and the extension headers, core lock held): the
 * datagram is checked (length, a checksum is mandatory over IPv6) and copied to a queue; the queue is handed to the
 * sockets once the core lock is released (UDP6DeliverDeferred). The sockets' receive completions run AFD code that
 * may send, which takes the core lock again: they must not run under it. A datagram for a port no IPv6 socket has
 * is answered with an ICMPv6 port unreachable (RFC 4443 3.1; lwIP rate limits its errors), unless it went to a
 * multicast group.
 *
 * Multicast groups (IPV6_ADD_MEMBERSHIP, MCAST_JOIN_GROUP, MCAST_JOIN_SOURCE_GROUP, source filters): per socket
 * (up to UDP6_SOCKET_GROUPS), each with its filter (RFC 3678: INCLUDE these sources, or EXCLUDE these; the Winsock
 * helper keeps the socket API's rules and hands the stack a group's whole filter, UDP6SetFilter), and per interface
 * the list of the sockets' joins. The filters of every socket in a group on an interface are merged (RFC 3810
 * 4.2; one walk of that list under the core lock, over sorted source lists, with bounded work: Udp6UpdateMld) into
 * the filter MLD reports (mld6.c, MLDv2 with source lists, RFC 3810; MLDv1 while an MLDv1 querier is on
 * the link): ip6_input takes the group while any socket listens to it, and a switch or router that snoops MLD
 * forwards it (and, with MLDv2, only the sources asked for). The group also goes in the adapter's multicast list
 * (if6.c, TCP6UpdateMulticast). A socket receives a group's datagram only if it joined the group on the interface
 * the datagram arrived on and its filter takes the source. Windows Server 2022 (peer capture 2026-11-16) reports
 * with MLDv2 and falls back to MLDv1 with an MLDv1 querier, as here.
 */

#include "precomp.h"

#include <nitrofwk.h>
#include <nitrotdi.h>
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/icmp6.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/mld6.h"

/* ntifs.h has it; this driver includes ntddk.h only (an implicit declaration would return an int, not a BOOLEAN) */
NTKERNELAPI
BOOLEAN
NTAPI
PsIsSystemThread(
    _In_ PETHREAD Thread);

/* ntifs.h has it too */
NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG Seed);

/* rawip6.c */
BOOLEAN RawIp6Input(struct pbuf *p, struct netif *inp, u8_t nexth);
VOID RawIp6DeliverDeferred(VOID);
BOOLEAN RawIp6HasDeferred(VOID);
BOOLEAN Ip6IsLocalAddress(const ip6_addr_t *Address);
err_t Ip6SendFragmented(struct pbuf *p, const ip6_addr_t *Source, const ip6_addr_t *Dest, u8_t Hops, u8_t TClass,
                        u8_t Protocol, struct netif *netif);

/* echo6.c */
int Echo6Input(struct pbuf *p, struct netif *inp);
VOID Echo6CompleteDone(VOID);
VOID Echo6Startup(VOID);

#define UDP6_TAG                'U6pT'
#define UDP6_SOCKET_GROUPS      NITRO_MCAST_MAX_GROUPS  /* IP_MAX_MEMBERSHIPS (Windows takes at least 300: release notes) */
#define UDP6_MACHINE_GROUPS     128
/* The sources of a group's merged filter MLD is told (MLD6_MAX_SOURCES); beyond them EXCLUDE with none */
#define UDP6_MLD_SOURCES        256
/* Table entries one process can take: a group joined by sockets of other processes costs a joiner nothing (it
   shares the entry), a new one is charged to the process that joined it first, so no process can fill the table
   for everybody (Windows limits a socket, not the machine) */
#define UDP6_PROCESS_GROUPS     32
/* Datagrams waiting for UDP6DeliverDeferred: beyond these the newest are dropped */
#define UDP6_DEFERRED_MAX       4096
#define UDP6_DEFERRED_MAX_BYTES (16 * 1024 * 1024)
/* The largest UDP payload over IPv6: 65535 - 8 = 65527 bytes, as Windows (oracle; WSAEMSGSIZE beyond). lwIP keeps
   a datagram with its IPv6 header in buffers of 16-bit length, so one of more than 65535 - 40 - 8 = 65487 bytes goes
   out as fragments built here (Ip6SendFragmented, rawip6.c). lwIP's reassembly cannot hold such a datagram either,
   so this machine receives at most 65487 bytes: a larger datagram to one of its own addresses is refused at the
   send (WSAEMSGSIZE) rather than lost (release notes, ipv6-notes.md) */
#define UDP6_MAX_PAYLOAD        (0xFFFF - sizeof(UDP_HEADER))
#define UDP6_MAX_LWIP_PAYLOAD   (0xFFFF - 40 - sizeof(UDP_HEADER))

typedef struct _UDP6_GROUP {
    UCHAR Group[16];
    UCHAR Zone;                 /* lwIP's netif index of the interface */
} UDP6_GROUP, *PUDP6_GROUP;

/* A socket's group and its source filter (one allocation per join). The sources are written under the socket's object
   lock AND the core lock: delivery reads them under the object lock, the MLD merge (Udp6UpdateMld) under the core lock.
   They are sorted and have no duplicates (delivery searches them, the merge walks them) */
typedef struct _UDP6_MEMBER {
    LIST_ENTRY GroupLink;       /* in the members of the machine's entry of the group (core lock) */
    UDP6_GROUP Group;
    UCHAR Mode;                 /* NITRO_MCAST_INCLUDE / NITRO_MCAST_EXCLUDE */
    ULONG NumSources;
    UCHAR (*Sources)[16];       /* UDP6_TAG */
} UDP6_MEMBER, *PUDP6_MEMBER;

typedef struct _UDP6_MEMBERSHIPS {
    ULONG Count;
    PUDP6_MEMBER Groups[UDP6_SOCKET_GROUPS];
} UDP6_MEMBERSHIPS, *PUDP6_MEMBERSHIPS;

/* The groups some socket joined, per interface (core lock) */
typedef struct _UDP6_MACHINE_GROUP {
    UDP6_GROUP Group;
    ULONG Sockets;
    HANDLE Owner;               /* the process that took the entry (it stays charged until the entry is free) */
    LIST_ENTRY Members;         /* the UDP6_MEMBERs, Sockets of them: the merge walks these, not every socket */
} UDP6_MACHINE_GROUP, *PUDP6_MACHINE_GROUP;

static UDP6_MACHINE_GROUP Udp6Groups[UDP6_MACHINE_GROUPS];

typedef struct _UDP6_DEFERRED {
    LIST_ENTRY ListEntry;
    UCHAR Src[16];
    UCHAR Dst[16];
    USHORT SrcPort;             /* network order */
    USHORT DstPort;
    UCHAR Zone;                 /* the interface it arrived on (multicast membership) */
    BOOLEAN Multicast;
    BOOLEAN Unreachable;        /* no datagram: an ICMPv6 port unreachable for the socket on Src:SrcPort */
    DG_RX_INFO6 Info;
    UINT Length;
    UCHAR Data[ANYSIZE_ARRAY];
} UDP6_DEFERRED, *PUDP6_DEFERRED;

static LIST_ENTRY Udp6Deferred = { &Udp6Deferred, &Udp6Deferred };
static KSPIN_LOCK Udp6DeferredLock;
static LONG Udp6DeferredCount;
static LONG Udp6DeferredBytes;

/* Datagrams dropped: malformed (length, checksum), no room in the queue, no memory */
volatile LONG UDP6ReceiveDropped;
volatile LONG UDP6PortUnreachable;

/* The interface of an interface index (IF->Index), or NULL (core lock held; echo6.c too) */
struct netif *
Udp6NetifOfIndex(ULONG IfIndex)
{
    struct netif *netif;

    NETIF_FOREACH(netif)
    {
        PIP_INTERFACE IF = netif->state;

        if (IF && IF->Index == IfIndex && netif_is_up(netif))
            return netif;
    }
    return NULL;
}

static
BOOLEAN
Udp6NetifHasAddress(struct netif *netif)
{
    s8_t i;

    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)))
            return TRUE;
    }
    return FALSE;
}

/* No route only because the link of the interface that would carry the datagram is down (core lock held): Windows
 * keeps its routes over a media disconnect and drops a datagram sent meanwhile without an error (Windows Server 2022:
 * UDP sendto over IPv4 and IPv6 during link drops of 1 to 120 s returned no error). lwIP routes nothing over an
 * interface without link, so this is TRUE when an interface that is up but has lost its link has an address that is
 * not link-local (it had the routes for such a destination), or any address for a link-local destination */
static BOOLEAN
Udp6OnlyLinkDown(const ip6_addr_t *Dest)
{
    struct netif *netif;
    s8_t i;

    if (ip6_addr_isloopback(Dest) || ip6_addr_ismulticast(Dest))
        return FALSE;
    NETIF_FOREACH(netif)
    {
        if (!netif_is_up(netif) || netif_is_link_up(netif) || (Loopback && netif == Loopback->TCPContext))
            continue;
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
                (ip6_addr_islinklocal(Dest) || !ip6_addr_islinklocal(netif_ip6_addr(netif, i))))
                return TRUE;
        }
    }
    return FALSE;
}

/* lwIP's route to Dest (core lock held; echo6.c too). lwIP falls back to its default interface when it has no route,
 * which is the loopback interface on a machine without an IPv6 adapter: that is no route, except for ::1 (Windows
 * answers no route: WSAENETUNREACH / ERROR_NETWORK_UNREACHABLE, oracle for the echo) */
struct netif *
Udp6Route(const ip6_addr_t *Src, const ip6_addr_t *Dest)
{
    struct netif *netif = ip6_route(Src, Dest);

    if (netif && Loopback && netif == Loopback->TCPContext && !ip6_addr_isloopback(Dest))
        return NULL;
    return netif;
}

/* The interface of a multicast datagram or group without an interface index: lwIP's default one when it is up
 * with an IPv6 address, else the first adapter that is, else the loopback interface (core lock held). VERIFY ON
 * ORACLE: Windows takes the interface of the route to the group. echo6.c too */
struct netif *
Udp6DefaultMulticastNetif(VOID)
{
    struct netif *netif;
    struct netif *LoopNetif = Loopback ? Loopback->TCPContext : NULL;

    if (netif_default && netif_default != LoopNetif && netif_is_up(netif_default) &&
        Udp6NetifHasAddress(netif_default))
        return netif_default;

    NETIF_FOREACH(netif)
    {
        if (netif != LoopNetif && netif->state && netif_is_up(netif) && Udp6NetifHasAddress(netif))
            return netif;
    }

    /* An adapter that is up but whose link-local address has not passed duplicate address detection yet is still
       the interface of a group (a join made in the first second after the adapter came up would otherwise land
       on the loopback interface, where a later leave without an interface does not find it). Not while IPv6 is off
       on the adapters (Ipv6Enable = 0, DisabledComponents 0x10): no adapter ever gets an address or sends IPv6 then,
       and the group belongs to the loopback interface */
    if (TCPIpv6Links)
    {
        NETIF_FOREACH(netif)
        {
            if (netif != LoopNetif && netif->state && netif_is_up(netif) && (netif->flags & NETIF_FLAG_LINK_UP))
                return netif;
        }
    }

    return (LoopNetif && netif_is_up(LoopNetif)) ? LoopNetif : NULL;
}

/* ------------------------------------------------------------------------------------------------
 * Receive
 * ---------------------------------------------------------------------------------------------- */

/* A socket that would take a unicast datagram to Dst:Port (AddressFileListLock; no reference is taken) */
static
BOOLEAN
Udp6HasReceiver(const UCHAR *Dst, USHORT Port)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;
    IP_ADDRESS Address;

    Address.Type = IP_ADDRESS_V6;
    RtlCopyMemory(Address.Address.IPv6Address, Dst, 16);

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        PADDRESS_FILE AddrFile = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);

        if (AddrFile->Protocol == IPPROTO_UDP && AddrFile->Port == Port && !AddrFile->PortReleased &&
            AddrFile->Address.Type == IP_ADDRESS_V6 &&
            (AddrIsUnspecified(&AddrFile->Address) || AddrIsEqual(&AddrFile->Address, &Address)))
        {
            Found = TRUE;
            break;
        }
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

    return Found;
}

static
VOID
Udp6Defer(PUDP6_DEFERRED D)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&Udp6DeferredLock, &OldIrql);
    if (Udp6DeferredCount >= UDP6_DEFERRED_MAX || Udp6DeferredBytes + (LONG)D->Length > UDP6_DEFERRED_MAX_BYTES)
    {
        KeReleaseSpinLock(&Udp6DeferredLock, OldIrql);
        InterlockedIncrement(&UDP6ReceiveDropped);
        ExFreePoolWithTag(D, UDP6_TAG);
        return;
    }
    InsertTailList(&Udp6Deferred, &D->ListEntry);
    Udp6DeferredCount++;
    Udp6DeferredBytes += D->Length;
    KeReleaseSpinLock(&Udp6DeferredLock, OldIrql);
}

static
PUDP6_DEFERRED
Udp6AllocateDeferred(UINT Length)
{
    PUDP6_DEFERRED D;

    D = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(UDP6_DEFERRED, Data[Length ? Length : 1]), UDP6_TAG);
    if (!D)
    {
        InterlockedIncrement(&UDP6ReceiveDropped);
        return NULL;
    }
    RtlZeroMemory(D, FIELD_OFFSET(UDP6_DEFERRED, Data));
    D->Length = Length;
    return D;
}

/*
 * An ICMPv6 destination unreachable, port unreachable (RFC 4443 3.1, code 4) whose invoking packet is a UDP datagram
 * we sent: the socket that sent it is told (DGReportPortUnreachable, from UDP6DeliverDeferred: not under the core
 * lock). p at the ICMPv6 header, core lock held, not freed here. The invoking packet must start with its UDP
 * header right after the IPv6 header (extension headers are not followed) and come from one of our addresses
 */
static
VOID
Udp6IcmpInput(struct pbuf *p)
{
    UCHAR Msg[8 + 40 + 8];
    PUDP6_DEFERRED D;
    ip6_addr_t Inner;

    if (p->tot_len < sizeof(Msg) || pbuf_copy_partial(p, Msg, sizeof(Msg), 0) != sizeof(Msg))
        return;
    if (Msg[0] != ICMP6_TYPE_DUR || Msg[1] != ICMP6_DUR_PORT || (Msg[8] >> 4) != 6 || Msg[8 + 6] != IP6_NEXTH_UDP)
        return;
    if (ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->tot_len, ip6_current_src_addr(), ip6_current_dest_addr()) != 0)
        return;

    /* The invoking packet's source is ours (the destination of this message) */
    RtlCopyMemory(Inner.addr, &Msg[8 + 8], 16);
    ip6_addr_clear_zone(&Inner);
    if (!ip6_addr_zoneless_eq(&Inner, ip6_current_dest_addr()) && !ip6_addr_isloopback(&Inner))
        return;

    D = Udp6AllocateDeferred(0);
    if (!D)
        return;
    D->Unreachable = TRUE;
    RtlCopyMemory(D->Src, &Msg[8 + 8], 16);
    RtlCopyMemory(D->Dst, &Msg[8 + 24], 16);
    RtlCopyMemory(&D->SrcPort, &Msg[8 + 40], sizeof(USHORT));
    RtlCopyMemory(&D->DstPort, &Msg[8 + 42], sizeof(USHORT));
    Udp6Defer(D);
}

/*
 * NitroOS hook LWIP_HOOK_IP6_NEXTH_INPUT (lwipopts.h): ip6_input hands over the payload of a datagram for us after
 * its extension headers and reassembly, p at the transport header, core lock held. Returns 1 when it took p (it is
 * freed here), 0 to let lwIP go on (any other protocol).
 */
int
LibIp6NexthInput(struct pbuf *p, struct netif *inp, u8_t nexth)
{
    UDP_HEADER Header;
    UINT Length;
    PUDP6_DEFERRED D;
    const ip6_addr_t *Src, *Dst;
    PIP_INTERFACE IF = inp ? inp->state : NULL;

    if (!TCPIpv6Enabled)
        return 0;
    /* ICMPv6: a copy for the raw ICMPv6 sockets, a port unreachable for the UDP socket that sent the datagram,
       the answers to our echo requests (echo6.c) */
    if (nexth == IP6_NEXTH_ICMP6)
    {
        RawIp6Input(p, inp, nexth);
        Udp6IcmpInput(p);
        return Echo6Input(p, inp);
    }
    if (nexth != IP6_NEXTH_UDP)
    {
        /* Another protocol: to the raw sockets of it, if there are any (lwIP answers the others with a parameter
           problem, and takes TCP itself) */
        if (nexth != IP6_NEXTH_TCP && RawIp6Input(p, inp, nexth))
        {
            pbuf_free(p);
            return 1;
        }
        return 0;
    }

    Src = ip6_current_src_addr();
    Dst = ip6_current_dest_addr();

    /* The UDP length counts the header; the datagram must hold it all (frame padding beyond it is cut). A zero
       length (a jumbogram, RFC 2675) is not supported. The checksum is mandatory (RFC 8200 8.1) */
    if (p->tot_len < sizeof(Header) || pbuf_copy_partial(p, &Header, sizeof(Header), 0) != sizeof(Header))
        goto Drop;
    Length = WN2H(Header.Length);
    if (Length < sizeof(Header) || Length > p->tot_len || Header.Checksum == 0)
        goto Drop;
    if (Length < p->tot_len)
        pbuf_realloc(p, (u16_t)Length);
    if (ip6_chksum_pseudo(p, IP6_NEXTH_UDP, p->tot_len, Src, Dst) != 0)
        goto Drop;

    if (!ip6_addr_ismulticast(Dst) && !Udp6HasReceiver((const UCHAR *)Dst->addr, Header.DestPort))
    {
        /* RFC 4443 3.1: port unreachable, lwIP's ICMPv6 error path (rate limited) with the datagram as it came */
        InterlockedIncrement(&UDP6PortUnreachable);
        if (pbuf_add_header_force(p, ip_current_header_tot_len()) == 0)
            icmp6_dest_unreach(p, ICMP6_DUR_PORT);
        pbuf_free(p);
        return 1;
    }

    D = Udp6AllocateDeferred(Length - sizeof(Header));
    if (!D)
    {
        pbuf_free(p);
        return 1;
    }
    RtlCopyMemory(D->Src, Src->addr, 16);
    RtlCopyMemory(D->Dst, Dst->addr, 16);
    D->SrcPort = Header.SourcePort;
    D->DstPort = Header.DestPort;
    D->Multicast = ip6_addr_ismulticast(Dst) ? TRUE : FALSE;
    D->Zone = (UCHAR)netif_get_index(inp);
    D->Info.IfIndex = IF ? IF->Index : 0;
    /* A link-local source is named with the interface it is on (sin6_scope_id), as on Windows */
    D->Info.SrcScopeId = (ip6_addr_islinklocal(Src) && IF) ? IF->Index : 0;
    D->Info.HopLimit = IP6H_HOPLIM(ip6_current_header());
    if (D->Length && pbuf_copy_partial(p, D->Data, (u16_t)D->Length, sizeof(Header)) != D->Length)
    {
        ExFreePoolWithTag(D, UDP6_TAG);
        InterlockedIncrement(&UDP6ReceiveDropped);
        pbuf_free(p);
        return 1;
    }
    pbuf_free(p);

    Udp6Defer(D);
    return 1;

Drop:
    InterlockedIncrement(&UDP6ReceiveDropped);
    pbuf_free(p);
    return 1;
}

/* The order of two sources (bytewise: no memcmp in the kernel build) */
static
LONG
Udp6CompareSource(const UCHAR *A, const UCHAR *B)
{
    ULONG i;

    for (i = 0; i < 16; i++)
    {
        if (A[i] != B[i])
            return A[i] < B[i] ? -1 : 1;
    }
    return 0;
}

/* Whether Source is in a sorted list */
static
BOOLEAN
Udp6HasSource(const UCHAR (*Sources)[16], ULONG Count, const UCHAR *Source)
{
    ULONG Low = 0, High = Count;

    while (Low < High)
    {
        ULONG Mid = Low + (High - Low) / 2;
        LONG Order = Udp6CompareSource(Sources[Mid], Source);

        if (Order == 0)
            return TRUE;
        if (Order < 0)
            Low = Mid + 1;
        else
            High = Mid;
    }
    return FALSE;
}

/* A list of sources sorted and without duplicates; returns how many are left */
static
ULONG
Udp6SortSources(UCHAR (*Sources)[16], ULONG Count)
{
    ULONG Gap, i, j, Kept;
    UCHAR Value[16];

    for (Gap = Count / 2; Gap; Gap /= 2)
    {
        for (i = Gap; i < Count; i++)
        {
            RtlCopyMemory(Value, Sources[i], 16);
            for (j = i; j >= Gap && Udp6CompareSource(Sources[j - Gap], Value) > 0; j -= Gap)
                RtlCopyMemory(Sources[j], Sources[j - Gap], 16);
            RtlCopyMemory(Sources[j], Value, 16);
        }
    }
    for (i = Kept = 0; i < Count; i++)
    {
        if (!Kept || Udp6CompareSource(Sources[Kept - 1], Sources[i]) != 0)
        {
            if (Kept != i)
                RtlCopyMemory(Sources[Kept], Sources[i], 16);
            Kept++;
        }
    }
    return Kept;
}

/* Joined Group on Zone with a filter that takes Source (the socket's object lock held) */
static
BOOLEAN
Udp6IsMember(PADDRESS_FILE AddrFile, const UCHAR *Group, UCHAR Zone, const UCHAR *Source)
{
    PUDP6_MEMBERSHIPS M = AddrFile->Groups6;
    ULONG i;

    if (!M)
        return FALSE;
    for (i = 0; i < M->Count; i++)
    {
        PUDP6_MEMBER Member = M->Groups[i];

        if (Member->Group.Zone == Zone && RtlCompareMemory(Member->Group.Group, Group, 16) == 16)
        {
            BOOLEAN Listed = Udp6HasSource((const UCHAR (*)[16])Member->Sources, Member->NumSources, Source);

            return (Member->Mode == NITRO_MCAST_INCLUDE) ? Listed : !Listed;
        }
    }
    return FALSE;
}

static
VOID
Udp6Deliver(PUDP6_DEFERRED D)
{
    AF_SEARCH SearchContext;
    IP_ADDRESS Src, Dst;
    IP_PACKET Packet;
    PADDRESS_FILE AddrFile, Best = NULL;

    Src.Type = IP_ADDRESS_V6;
    RtlCopyMemory(Src.Address.IPv6Address, D->Src, 16);
    Dst.Type = IP_ADDRESS_V6;
    RtlCopyMemory(Dst.Address.IPv6Address, D->Dst, 16);

    /* A port unreachable: the socket on the datagram's source address and port that would receive there (the one
       bound to the address itself rather than the wildcard, the latest bound among equals) */
    if (D->Unreachable)
    {
        for (AddrFile = AddrSearchFirst(&Src, D->SrcPort, IPPROTO_UDP, &SearchContext);
             AddrFile != NULL;
             AddrFile = AddrSearchNext(&SearchContext))
        {
            if (AddrFile->Address.Type == IP_ADDRESS_V6 &&
                (!Best || !AddrIsUnspecified(&AddrFile->Address) || AddrIsUnspecified(&Best->Address)))
            {
                if (Best)
                    DereferenceObject(Best);
                Best = AddrFile;
            }
            else
            {
                DereferenceObject(AddrFile);
            }
        }
        if (Best)
        {
            DGReportPortUnreachable(Best);
            DereferenceObject(Best);
        }
        return;
    }

    /* DGDeliverData reads the payload at Data (IPPacket->Header for raw IP only) */
    RtlZeroMemory(&Packet, sizeof(Packet));
    Packet.Type = IP_ADDRESS_V6;
    Packet.Header = D->Data;
    Packet.Data = D->Data;
    Packet.HeaderSize = 0;
    Packet.TotalSize = D->Length;
    Packet.SrcAddr = Src;
    Packet.DstAddr = Dst;

    /* A group's datagram goes to every socket on the port that joined it on that interface; a unicast one to a
       single socket, as for IPv4 (udp.c): the one bound to the address itself rather than the wildcard, the latest
       bound among equals */
    for (AddrFile = AddrSearchFirst(&Dst, D->DstPort, IPPROTO_UDP, &SearchContext);
         AddrFile != NULL;
         AddrFile = AddrSearchNext(&SearchContext))
    {
        if (D->Multicast)
        {
            BOOLEAN Member;

            LockObject(AddrFile);
            Member = Udp6IsMember(AddrFile, D->Dst, D->Zone, D->Src);
            UnlockObject(AddrFile);
            if (Member)
                DGDeliverDataEx(NULL, AddrFile, &Src, &Dst, D->SrcPort, D->DstPort, &Packet, D->Length, &D->Info);
            DereferenceObject(AddrFile);
        }
        else if (!Best || !AddrIsUnspecified(&AddrFile->Address) || AddrIsUnspecified(&Best->Address))
        {
            if (Best)
                DereferenceObject(Best);
            Best = AddrFile;
        }
        else
        {
            DereferenceObject(AddrFile);
        }
    }

    if (Best)
    {
        DGDeliverDataEx(NULL, Best, &Src, &Dst, D->SrcPort, D->DstPort, &Packet, D->Length, &D->Info);
        DereferenceObject(Best);
    }
}

VOID
UDP6DeliverDeferred(VOID)
{
    PLIST_ENTRY Entry;
    PUDP6_DEFERRED D;
    KIRQL OldIrql;

    /* The echo requests the input answered (echo6.c) */
    Echo6CompleteDone();

    /* The raw IPv6 sockets' packets (rawip6.c) */
    RawIp6DeliverDeferred();

    /* Cheap when there is nothing: every IPv6 input calls this */
    if (IsListEmpty(&Udp6Deferred))
        return;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT(!sys_tcpip_core_locked());

    for (;;)
    {
        KeAcquireSpinLock(&Udp6DeferredLock, &OldIrql);
        if (IsListEmpty(&Udp6Deferred))
        {
            KeReleaseSpinLock(&Udp6DeferredLock, OldIrql);
            break;
        }
        Entry = RemoveHeadList(&Udp6Deferred);
        D = CONTAINING_RECORD(Entry, UDP6_DEFERRED, ListEntry);
        Udp6DeferredCount--;
        Udp6DeferredBytes -= D->Length;
        KeReleaseSpinLock(&Udp6DeferredLock, OldIrql);

        Udp6Deliver(D);
        ExFreePoolWithTag(D, UDP6_TAG);
    }
}

/* The sender's thread is an application thread. AFD re-posts a datagram socket's receive inline only on a system
 * thread; from an application thread it hands the re-post to a work item, and a datagram delivered to the socket
 * before that ran finds no receive posted and is lost (a multicast sender that is also a member: the next send's
 * looped copy). So what an application thread leaves in the queue is delivered from a work item, which is a
 * system thread. One work item at a time; the item takes a reference on the device object while it is queued */
static volatile LONG Udp6WorkQueued;

static
VOID
NTAPI
Udp6DeliveryWorker(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Cleared first: a datagram queued after this point queues the next item */
    InterlockedExchange(&Udp6WorkQueued, 0);
    UDP6DeliverDeferred();
    IoFreeWorkItem((PIO_WORKITEM)Context);
}

/* Delivers the queue from a system thread: now when this is one, else from a work item (inline when there is
   no memory for one: the datagram may then be lost as before, never more than that). rawip6.c too */
VOID
Udp6DeliverFromSystemThread(VOID)
{
    PIO_WORKITEM Item;

    if (IsListEmpty(&Udp6Deferred) && !RawIp6HasDeferred())
        return;
    if (PsIsSystemThread(PsGetCurrentThread()))
    {
        UDP6DeliverDeferred();
        return;
    }
    if (InterlockedCompareExchange(&Udp6WorkQueued, 1, 0) != 0)
        return;     /* an item is queued or running: it drains the queue and a later datagram queues the next */

    Item = TCPDeviceObject ? IoAllocateWorkItem(TCPDeviceObject) : NULL;
    if (!Item)
    {
        InterlockedExchange(&Udp6WorkQueued, 0);
        UDP6DeliverDeferred();
        return;
    }
    IoQueueWorkItem(Item, Udp6DeliveryWorker, CriticalWorkQueue, Item);
}

/* ------------------------------------------------------------------------------------------------
 * Send
 * ---------------------------------------------------------------------------------------------- */

NTSTATUS
UDPSendDatagram6(
    PADDRESS_FILE AddrFile,
    PTA_IP6_ADDRESS Remote,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed)
{
    UCHAR RemoteBytes[16];
    USHORT RemotePort, LocalPort;
    ULONG ScopeId, McastIf;
    IP_ADDRESS Local, RemoteIp;
    UCHAR Zone, Hops, McastHops;
    BOOLEAN McastLoop, Multicast;
    ip6_addr_t Dest, Source;
    const ip_addr_t *Selected;
    struct netif *netif = NULL;
    struct netif *LoopNetif;
    struct pbuf *p, *Data;
    PUDP_HEADER Header;
    PUDP6_DEFERRED Copy = NULL;
    err_t Result;
    NTSTATUS Status = STATUS_SUCCESS;

    /* The caller checked that the whole TA_IP6_ADDRESS is there; its fields may be unaligned */
    RtlCopyMemory(RemoteBytes, Remote->Address[0].Address[0].sin6_addr, sizeof(RemoteBytes));
    RtlCopyMemory(&RemotePort, &Remote->Address[0].Address[0].sin6_port, sizeof(RemotePort));
    RtlCopyMemory(&ScopeId, &Remote->Address[0].Address[0].sin6_scope_id, sizeof(ScopeId));

    if (!TCPIpv6Enabled)
        return STATUS_INVALID_ADDRESS;
    /* WSAEMSGSIZE beyond UDP6_MAX_PAYLOAD (Windows beyond 65527 bytes, oracle) */
    if (DataSize > UDP6_MAX_PAYLOAD)
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(Dest.addr, RemoteBytes, sizeof(Dest.addr));
    ip6_addr_clear_zone(&Dest);
    /* No datagram to :: (VERIFY ON ORACLE: Windows answers WSAEADDRNOTAVAIL for the unspecified address) */
    if (ip6_addr_isany(&Dest))
        return STATUS_INVALID_ADDRESS;
    Multicast = ip6_addr_ismulticast(&Dest) ? TRUE : FALSE;

    LockObject(AddrFile);
    Local = AddrFile->Address;
    LocalPort = AddrFile->Port;
    Zone = AddrFile->Zone6;
    Hops = AddrFile->TTL;
    McastHops = AddrFile->McastHops;
    McastLoop = AddrFile->McastLoop;
    McastIf = AddrFile->McastIf;
    UnlockObject(AddrFile);

    /* A socket bound to ::ffff:a.b.c.d sends IPv4 only */
    if (Local.Type != IP_ADDRESS_V6)
        return STATUS_INVALID_ADDRESS;

    RemoteIp.Type = IP_ADDRESS_V6;
    RtlCopyMemory(RemoteIp.Address.IPv6Address, RemoteBytes, sizeof(RemoteBytes));

    /* A multicast datagram this machine's members get too (the loopback interface loops its own) */
    if (Multicast && McastLoop)
    {
        Copy = Udp6AllocateDeferred(DataSize);
        if (Copy && DataSize)
            RtlCopyMemory(Copy->Data, BufferData, DataSize);
    }

    LOCK_TCPIP_CORE();

    /* lwIP's buffers are taken and given back under the core lock, as everywhere else in this driver. The UDP
       header has a buffer of its own with room for the IPv6 and link headers in front, the data one without:
       a single buffer could not hold 65527 bytes of data and the headers within lwIP's 16-bit lengths */
    p = pbuf_alloc(PBUF_IP, sizeof(UDP_HEADER), PBUF_RAM);
    Data = DataSize ? pbuf_alloc(PBUF_RAW, (u16_t)DataSize, PBUF_RAM) : NULL;
    if (!p || (DataSize && (!Data || pbuf_take(Data, BufferData, (u16_t)DataSize) != ERR_OK)))
    {
        if (p)
            pbuf_free(p);
        if (Data)
            pbuf_free(Data);
        UNLOCK_TCPIP_CORE();
        if (Copy)
            ExFreePoolWithTag(Copy, UDP6_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (Data)
        pbuf_cat(p, Data);

    LoopNetif = Loopback ? Loopback->TCPContext : NULL;

    /* The interface: a scoped destination's from its scope id (link-local and the multicast scopes below global
       need one, RFC 4007 6), a multicast one's from IPV6_MULTICAST_IF, else the route */
    if (Multicast)
    {
        netif = McastIf ? Udp6NetifOfIndex(McastIf) : (ScopeId ? Udp6NetifOfIndex(ScopeId) : NULL);
        if (!netif && !McastIf && !ScopeId)
            netif = Udp6DefaultMulticastNetif();
        if (netif)
            ip6_addr_assign_zone(&Dest, IP6_MULTICAST, netif);
    }
    else if (ip6_addr_islinklocal(&Dest))
    {
        if (ScopeId)
            netif = Udp6NetifOfIndex(ScopeId);
        else if (Zone != IP6_NO_ZONE)
            netif = netif_get_by_index(Zone);
        else
            netif = TCP6DefaultLinkLocalNetif();   /* no scope id: the adapter of the lowest metric (Windows) */
        if (netif)
            ip6_addr_assign_zone(&Dest, IP6_UNICAST, netif);
    }

    /* The source: the bound address, else what lwIP selects for the destination (RFC 6724 as lwIP does it) */
    if (!AddrIsUnspecified(&Local))
    {
        RtlCopyMemory(Source.addr, Local.Address.IPv6Address, sizeof(Source.addr));
        ip6_addr_clear_zone(&Source);
        if (Zone != IP6_NO_ZONE)
            ip6_addr_set_zone(&Source, Zone);
        if (!netif)
            netif = Udp6Route(&Source, &Dest);
    }
    else
    {
        if (!netif && !(ip6_addr_islinklocal(&Dest) || ip6_addr_ismulticast(&Dest)))
            netif = Udp6Route(IP6_ADDR_ANY6, &Dest);
        Selected = netif ? ip6_select_source_address(netif, &Dest) : NULL;
        if (!Selected)
        {
            /* the link is down: sent and lost, as on Windows (Udp6OnlyLinkDown) */
            NTSTATUS Lost = Udp6OnlyLinkDown(&Dest) ? STATUS_SUCCESS : STATUS_NETWORK_UNREACHABLE;

            pbuf_free(p);
            UNLOCK_TCPIP_CORE();
            if (Copy)
                ExFreePoolWithTag(Copy, UDP6_TAG);
            if (NT_SUCCESS(Lost))
                *DataUsed = DataSize;
            return Lost;
        }
        ip6_addr_copy(Source, *ip_2_ip6(Selected));
    }

    if (!netif)
    {
        NTSTATUS Lost = Udp6OnlyLinkDown(&Dest) ? STATUS_SUCCESS : STATUS_NETWORK_UNREACHABLE;

        pbuf_free(p);
        UNLOCK_TCPIP_CORE();
        if (Copy)
            ExFreePoolWithTag(Copy, UDP6_TAG);
        if (NT_SUCCESS(Lost))
            *DataUsed = DataSize;
        return Lost;
    }

    Header = (PUDP_HEADER)p->payload;
    Header->SourcePort = LocalPort;
    Header->DestPort = RemotePort;
    Header->Length = WH2N((USHORT)(sizeof(UDP_HEADER) + DataSize));
    Header->Checksum = 0;
    Header->Checksum = ip6_chksum_pseudo(p, IP6_NEXTH_UDP, p->tot_len, &Source, &Dest);
    /* 0 is sent as all ones (RFC 8200 8.1) */
    if (Header->Checksum == 0)
        Header->Checksum = 0xFFFF;

    /* Replies to this datagram pass the inbound filter */
    NITROFW_NOTE_UDP_SEND(LocalPort, &RemoteIp, RemotePort, Multicast);

    /* More than lwIP can hold with the IPv6 header goes out in fragments built here; to this machine it would not be
       reassembled (UDP6_MAX_PAYLOAD) */
    if (DataSize > UDP6_MAX_LWIP_PAYLOAD && (netif == LoopNetif || Ip6IsLocalAddress(&Dest)))
        Result = ERR_VAL;
    else
        Result = Ip6SendFragmented(p, &Source, &Dest, Multicast ? McastHops : Hops, 0, IP6_NEXTH_UDP, netif);
    /* an interface without link has no route lwIP uses: lost without an error, as on Windows (Udp6OnlyLinkDown) */
    if (Result == ERR_RTE && !netif_is_link_up(netif))
        Result = ERR_OK;

    /* Only a datagram that was sent (or is kept for neighbour discovery, which counts as sent) reaches the members
       here: nobody sees one whose sendto fails */
    if (Copy)
    {
        if (netif != LoopNetif && (Result == ERR_OK || Result == ERR_INPROGRESS))
        {
            PIP_INTERFACE IF = netif->state;

            RtlCopyMemory(Copy->Src, Source.addr, 16);
            RtlCopyMemory(Copy->Dst, RemoteBytes, 16);
            Copy->SrcPort = LocalPort;
            Copy->DstPort = RemotePort;
            Copy->Multicast = TRUE;
            Copy->Zone = (UCHAR)netif_get_index(netif);
            Copy->Info.IfIndex = IF ? IF->Index : 0;
            Copy->Info.SrcScopeId = (ip6_addr_islinklocal(&Source) && IF) ? IF->Index : 0;
            Copy->Info.HopLimit = McastHops;
            Udp6Defer(Copy);
        }
        else
        {
            ExFreePoolWithTag(Copy, UDP6_TAG);
        }
    }

    pbuf_free(p);
    UNLOCK_TCPIP_CORE();

    /* A datagram lwIP keeps for neighbour discovery counts as sent, as an IPv4 one waiting for ARP */
    if (Result == ERR_VAL)
        Status = STATUS_BUFFER_TOO_SMALL;
    else if (Result != ERR_OK && Result != ERR_INPROGRESS)
        Status = (Result == ERR_MEM || Result == ERR_BUF) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_NETWORK_UNREACHABLE;

    /* The looped copy, and anything the send put on the queue meanwhile */
    Udp6DeliverFromSystemThread();

    if (NT_SUCCESS(Status))
        *DataUsed = DataSize;
    return Status;
}

/* ------------------------------------------------------------------------------------------------
 * Multicast groups
 * ---------------------------------------------------------------------------------------------- */

/* NitroOS hook LWIP_HOOK_IP6_MCAST_ACCEPT (lwipopts.h, used only with LWIP_IPV6_MLD 0): ip6_input takes a
 * datagram to Dest on inp, a group that is neither all-nodes nor solicited-node, when a socket joined it there
 * (core lock held) */
int
LibIp6McastAccept(struct netif *inp, const ip6_addr_t *Dest)
{
    UCHAR Zone = (UCHAR)netif_get_index(inp);
    ULONG i;

    for (i = 0; i < UDP6_MACHINE_GROUPS; i++)
    {
        if (Udp6Groups[i].Sockets && Udp6Groups[i].Group.Zone == Zone &&
            RtlCompareMemory(Udp6Groups[i].Group.Group, Dest->addr, 16) == 16)
            return 1;
    }
    return 0;
}

/* The link layer addresses of the groups sockets joined on netif (RFC 2464 7), added to the adapter's list
 * (if6.c, core lock held). *Count becomes Max + 1 when they do not all fit */
VOID
UDP6AddMulticastList(struct netif *netif, PUCHAR List, PUINT Count, UINT Max)
{
    UCHAR Zone = (UCHAR)netif_get_index(netif);
    ULONG i, j, k;

    for (i = 0; i < UDP6_MACHINE_GROUPS && *Count <= Max; i++)
    {
        UCHAR Mac[6];

        if (!Udp6Groups[i].Sockets || Udp6Groups[i].Group.Zone != Zone)
            continue;

        Mac[0] = 0x33;
        Mac[1] = 0x33;
        RtlCopyMemory(&Mac[2], &Udp6Groups[i].Group.Group[12], 4);

        for (j = 0; j < *Count; j++)
        {
            for (k = 0; k < 6 && List[j * 6 + k] == Mac[k]; k++)
                ;
            if (k == 6)
                break;
        }
        if (j < *Count)
            continue;
        if (*Count == Max)
        {
            *Count = Max + 1;
            break;
        }
        RtlCopyMemory(&List[*Count * 6], Mac, 6);
        (*Count)++;
    }
}

/* if6.c: sets the adapter's multicast list again (core lock held) */
VOID TCP6UpdateMulticastList(struct netif *netif);

#if LWIP_IPV6_MLD
/* LWIP_HOOK MLD6_RAND (lwipopts.h): the random part of an MLD report delay (core lock held) */
u32_t
LibMld6Random(VOID)
{
    static ULONG Seed;

    if (!Seed)
        Seed = (ULONG)KeQueryPerformanceCounter(NULL).QuadPart | 1;
    return RtlRandomEx(&Seed);
}
C_ASSERT(NITRO_MCAST_INCLUDE == MLD6_FMODE_INCLUDE && NITRO_MCAST_EXCLUDE == MLD6_FMODE_EXCLUDE);
C_ASSERT(UDP6_MLD_SOURCES == MLD6_MAX_SOURCES);
#endif /* LWIP_IPV6_MLD */

/* The machine's entry of a group on an interface, or NULL when no socket is in it (core lock held) */
static
PUDP6_MACHINE_GROUP
Udp6FindGroup(const UDP6_GROUP *Group)
{
    ULONG i;

    for (i = 0; i < UDP6_MACHINE_GROUPS; i++)
    {
        if (Udp6Groups[i].Sockets && Udp6Groups[i].Group.Zone == Group->Zone &&
            RtlCompareMemory(Udp6Groups[i].Group.Group, Group->Group, 16) == 16)
            return &Udp6Groups[i];
    }
    return NULL;
}

/* The work one merge may do, in list elements stepped over: what a handful of sockets with full lists cost, and
   what no number of sockets can make more. Beyond it the merge reports EXCLUDE with no source (more traffic, never
   less; the sockets' own filters still decide what they receive) */
#define UDP6_MLD_WORK           16384

/* The merge's lists (core lock) */
static UCHAR Udp6MldList[2][UDP6_MLD_SOURCES][16];

/* List of Count sorted sources becomes its intersection with the sorted Other (Keep) or its difference from it
   (!Keep), in place; *Work counts the steps. Returns the new count */
static
ULONG
Udp6MergeSources(UCHAR (*List)[16], ULONG Count, const UCHAR (*Other)[16], ULONG OtherCount, BOOLEAN Keep,
                 PULONG Work)
{
    ULONG i = 0, j = 0, Kept = 0;

    *Work += Count + OtherCount;
    while (i < Count)
    {
        LONG Order = (j < OtherCount) ? Udp6CompareSource(List[i], Other[j]) : -1;

        if (Order > 0)
        {
            j++;
            continue;
        }
        if ((Order == 0) == Keep)
        {
            if (Kept != i)
                RtlCopyMemory(List[Kept], List[i], 16);
            Kept++;
        }
        if (Order == 0)
            j++;
        i++;
    }
    return Kept;
}

/* The merge of the sorted lists A and B (the union) into Out, which has room for UDP6_MLD_SOURCES; *Work counts the
   steps. Returns the count, or more than UDP6_MLD_SOURCES when it does not fit */
static
ULONG
Udp6UnionSources(UCHAR (*Out)[16], const UCHAR (*A)[16], ULONG ACount, const UCHAR (*B)[16], ULONG BCount, PULONG Work)
{
    ULONG i = 0, j = 0, Count = 0;

    *Work += ACount + BCount;
    while (i < ACount || j < BCount)
    {
        LONG Order = (i == ACount) ? 1 : (j == BCount) ? -1 : Udp6CompareSource(A[i], B[j]);
        const UCHAR *Next = (Order <= 0) ? A[i] : B[j];

        if (Count == UDP6_MLD_SOURCES)
            return UDP6_MLD_SOURCES + 1;
        RtlCopyMemory(Out[Count++], Next, 16);
        if (Order <= 0)
            i++;
        if (Order >= 0)
            j++;
    }
    return Count;
}

/* The filters of every socket's join of Group merged (RFC 3810 4.2): EXCLUDE when any socket excludes, with the
 * sources every excluding socket excludes and no including socket includes; else INCLUDE with every source some
 * socket includes (none: nobody listens). MLD reports it (mld6.c). Core lock held, so no socket's filter changes
 * meanwhile (they change under the core lock). The members are the entry's own list (no walk over every socket, no
 * other lock), the lists are sorted, and the work is bounded (UDP6_MLD_WORK): the starting point of the intersection
 * is the smallest excluding list, so it never exceeds it. More sources than MLD reports, or more work than the bound:
 * EXCLUDE with none (more traffic, never less) */
static
err_t
Udp6UpdateMld(struct netif *netif, const UDP6_GROUP *Group)
{
    PUDP6_MACHINE_GROUP Machine = Udp6FindGroup(Group);
    PLIST_ENTRY Entry;
    PUDP6_MEMBER Smallest = NULL;
    ULONG Excluders = 0, Included = 0, Count = 0, Work = 0, Bound = 0, Current = 0;
    UCHAR (*List)[16] = NULL;
    UCHAR Mode;
    ip6_addr_t Address;
    err_t Err;

    for (Entry = Machine ? Machine->Members.Flink : NULL; Machine && Entry != &Machine->Members; Entry = Entry->Flink)
    {
        PUDP6_MEMBER Member = CONTAINING_RECORD(Entry, UDP6_MEMBER, GroupLink);

        if (Member->Mode == NITRO_MCAST_EXCLUDE)
        {
            if (!Smallest || Member->NumSources < Smallest->NumSources)
                Smallest = Member;
            Excluders++;
        }
        else
        {
            Included += Member->NumSources;
        }
    }

    Mode = Excluders ? NITRO_MCAST_EXCLUDE : NITRO_MCAST_INCLUDE;
    Bound = Excluders ? Smallest->NumSources : Included;
    if (Bound > UDP6_MLD_SOURCES)
    {
        Mode = NITRO_MCAST_EXCLUDE;
        Bound = 0;
    }

    if (Bound)
    {
        if (Excluders)
        {
            /* the intersection of the excluded sources, starting from the smallest list ... */
            List = Udp6MldList[0];
            Count = Smallest->NumSources;
            RtlCopyMemory(List, Smallest->Sources, Count * 16);
            for (Entry = Machine->Members.Flink; Entry != &Machine->Members && Count && Work <= UDP6_MLD_WORK;
                 Entry = Entry->Flink)
            {
                PUDP6_MEMBER Member = CONTAINING_RECORD(Entry, UDP6_MEMBER, GroupLink);

                if (Member != Smallest && Member->Mode == NITRO_MCAST_EXCLUDE)
                    Count = Udp6MergeSources(List, Count, (const UCHAR (*)[16])Member->Sources, Member->NumSources,
                                             TRUE, &Work);
            }
            /* ... less every included one */
            for (Entry = Machine->Members.Flink; Entry != &Machine->Members && Count && Work <= UDP6_MLD_WORK;
                 Entry = Entry->Flink)
            {
                PUDP6_MEMBER Member = CONTAINING_RECORD(Entry, UDP6_MEMBER, GroupLink);

                if (Member->Mode == NITRO_MCAST_INCLUDE)
                    Count = Udp6MergeSources(List, Count, (const UCHAR (*)[16])Member->Sources, Member->NumSources,
                                             FALSE, &Work);
            }
        }
        else
        {
            /* the union of the included sources */
            for (Entry = Machine->Members.Flink; Entry != &Machine->Members && Count <= UDP6_MLD_SOURCES &&
                                                 Work <= UDP6_MLD_WORK; Entry = Entry->Flink)
            {
                PUDP6_MEMBER Member = CONTAINING_RECORD(Entry, UDP6_MEMBER, GroupLink);

                Count = Udp6UnionSources(Udp6MldList[1 - Current], (const UCHAR (*)[16])Udp6MldList[Current], Count,
                                         (const UCHAR (*)[16])Member->Sources, Member->NumSources, &Work);
                Current = 1 - Current;
            }
            List = Udp6MldList[Current];
        }
        if (Work > UDP6_MLD_WORK || Count > UDP6_MLD_SOURCES)
        {
            Mode = NITRO_MCAST_EXCLUDE;
            Count = 0;
        }
    }

    if (!Count)
        List = NULL;

#if LWIP_IPV6_MLD
    RtlCopyMemory(Address.addr, Group->Group, 16);
    ip6_addr_clear_zone(&Address);
    Err = mld6_set_filter_netif(netif, &Address, Mode, (const u8_t (*)[16])List, (u16_t)Count);
    if (Err != ERR_OK && Count)
    {
        /* No memory for MLD's copy of the sources: the coarse filter, which needs none (more traffic, never less;
           keeping the old report could keep a source the sockets now listen to out) */
        Err = mld6_set_filter_netif(netif, &Address, NITRO_MCAST_EXCLUDE, NULL, 0);
    }
#else
    UNREFERENCED_PARAMETER(netif);
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Mode);
    Err = ERR_OK;
#endif
    return Err;
}


#if LWIP_IPV6_MLD
/* lwIP's interface events for MLD (core lock held) */
static
void
Udp6MldNetifEvent(struct netif *netif, netif_nsc_reason_t Reason, const netif_ext_callback_args_t *Args)
{
    ULONG i;

    /* An interface was added, with its final index: the groups sockets hold for that index are joined in MLD
       there, as the accept hook took them without MLD */
    if (Reason & LWIP_NSC_NETIF_ADDED)
    {
        UCHAR Zone = (UCHAR)netif_get_index(netif);

        for (i = 0; i < UDP6_MACHINE_GROUPS; i++)
        {
            if (Udp6Groups[i].Sockets && Udp6Groups[i].Group.Zone == Zone)
                Udp6UpdateMld(netif, &Udp6Groups[i].Group);
        }
    }

    /* The link-local address passed duplicate address detection: the reports sent so far had no source address
       (::, RFC 3590 4), which a snooping switch may ignore; every group is reported again from the link-local
       address (within half a second) */
    if ((Reason & LWIP_NSC_IPV6_ADDR_STATE_CHANGED) && Args && (netif->flags & NETIF_FLAG_MLD6) &&
        Args->ipv6_addr_state_changed.addr_index == 0 &&
        !ip6_addr_isvalid(Args->ipv6_addr_state_changed.old_state) &&
        ip6_addr_isvalid(netif_ip6_addr_state(netif, 0)))
    {
        mld6_report_groups(netif);
    }
}

static netif_ext_callback_t Udp6MldCallback;
static BOOLEAN Udp6MldCallbackAdded;

/* if6.c, with IPv6 on, as each interface is set up (core lock held): MLD's interface events from now on */
VOID
UDP6MldStart(VOID)
{
    if (!Udp6MldCallbackAdded)
    {
        netif_add_ext_callback(&Udp6MldCallback, Udp6MldNetifEvent);
        Udp6MldCallbackAdded = TRUE;
    }
}
#endif /* LWIP_IPV6_MLD */

/* One socket more or less in Group on its interface (core lock held): the machine's table of groups and the adapter's
 * multicast list (MLD follows the filters, Udp6UpdateMld). FALSE: no room for another group, in the table or in
 * Process's share of it */
static
BOOLEAN
Udp6CountMember(const UDP6_GROUP *Group, BOOLEAN Join, HANDLE Process)
{
    ULONG i, Free = UDP6_MACHINE_GROUPS, Taken = 0;
    struct netif *netif;

    for (i = 0; i < UDP6_MACHINE_GROUPS; i++)
    {
        if (!Udp6Groups[i].Sockets)
        {
            if (Free == UDP6_MACHINE_GROUPS)
                Free = i;
            continue;
        }
        if (Join && Udp6Groups[i].Owner == Process)
            Taken++;
        if (Udp6Groups[i].Group.Zone == Group->Zone &&
            RtlCompareMemory(Udp6Groups[i].Group.Group, Group->Group, 16) == 16)
            break;
    }

    if (i < UDP6_MACHINE_GROUPS)
    {
        if (Join)
        {
            Udp6Groups[i].Sockets++;
            return TRUE;
        }
        if (--Udp6Groups[i].Sockets != 0)
            return TRUE;
    }
    else
    {
        if (!Join)
            return TRUE;
        if (Free == UDP6_MACHINE_GROUPS || Taken >= UDP6_PROCESS_GROUPS)
            return FALSE;
        Udp6Groups[Free].Group = *Group;
        Udp6Groups[Free].Sockets = 1;
        Udp6Groups[Free].Owner = Process;
        InitializeListHead(&Udp6Groups[Free].Members);
    }

    /* The first socket in the group, or the last one gone: the adapter's list changes */
    netif = netif_get_by_index(Group->Zone);
    if (netif)
        TCP6UpdateMulticastList(netif);
    return TRUE;
}

/*
 * A socket's filter for one group (NITRO_AO_OPTION_MCAST_FILTER, nitrotdi.h; and IPV6_ADD/DROP_MEMBERSHIP):
 * Mode with NumSources sources of 16 bytes; INCLUDE with none leaves the group. IfIndex 0 is the stack's choice:
 * the interface the socket has the group on (for a change or a leave), else the default multicast interface.
 * MustBeNew: STATUS_INVALID_PARAMETER when the socket has the group already (IPV6_ADD_MEMBERSHIP twice).
 */
NTSTATUS
UDP6SetFilter(PADDRESS_FILE AddrFile, ULONG IfIndex, const UCHAR *GroupAddress, UCHAR Mode, ULONG NumSources,
              const UCHAR (*Sources)[16], BOOLEAN MustBeNew)
{
    UDP6_GROUP Group;
    ULONG i;
    struct netif *netif;
    BOOLEAN Resolved = FALSE, Leave = (Mode == NITRO_MCAST_INCLUDE && NumSources == 0);
    PUDP6_MEMBERSHIPS M, New = NULL;
    PUDP6_MEMBER NewMember = NULL, Gone = NULL, Member;
    PUDP6_MACHINE_GROUP Machine;
    UCHAR (*Copy)[16] = NULL, (*Old)[16] = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!TCPIpv6Enabled || Mode > NITRO_MCAST_EXCLUDE)
        return STATUS_INVALID_PARAMETER;
    if (GroupAddress[0] != 0xFF)
        return STATUS_INVALID_ADDRESS;
    if (NumSources > NITRO_MCAST_MAX_SOURCES)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(&Group, sizeof(Group));
    RtlCopyMemory(Group.Group, GroupAddress, 16);

    if (!Leave)
    {
        New = ExAllocatePoolWithTag(NonPagedPool, sizeof(*New), UDP6_TAG);
        NewMember = ExAllocatePoolWithTag(NonPagedPool, sizeof(*NewMember), UDP6_TAG);
        if (NumSources)
            Copy = ExAllocatePoolWithTag(NonPagedPool, NumSources * 16, UDP6_TAG);
        if (!New || !NewMember || (NumSources && !Copy))
        {
            if (New)
                ExFreePoolWithTag(New, UDP6_TAG);
            if (NewMember)
                ExFreePoolWithTag(NewMember, UDP6_TAG);
            if (Copy)
                ExFreePoolWithTag(Copy, UDP6_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(New, sizeof(*New));
        RtlZeroMemory(NewMember, sizeof(*NewMember));
        if (NumSources)
        {
            /* sorted, no duplicates (before any lock): delivery searches the list, the MLD merge walks it */
            RtlCopyMemory(Copy, Sources, NumSources * 16);
            NumSources = Udp6SortSources(Copy, NumSources);
        }
    }

    LockObject(AddrFile);
    LOCK_TCPIP_CORE();

    /* The socket's last handle is closed (FileCloseAddress, under the object lock): its groups are left now or
       already (UDP6LeaveAll), so nothing may join again. A request that referenced the address object by its entity
       before the close would otherwise link a member nobody leaves: the group stays joined and charged until reboot */
    if (AddrFile->PortReleased && !Leave)
    {
        Status = STATUS_INVALID_ADDRESS;
        goto Done;
    }

    netif = IfIndex ? Udp6NetifOfIndex(IfIndex) : Udp6DefaultMulticastNetif();
    if (netif)
    {
        Group.Zone = (UCHAR)netif_get_index(netif);
        Resolved = TRUE;
    }
    if (!MustBeNew && !IfIndex && AddrFile->Groups6)
    {
        /* Without an interface, a change or a leave is for the socket's join of the group, on whichever interface
           the join landed: the default one may have changed since (an adapter that got its address, or went away) */
        BOOLEAN Found = FALSE;
        UCHAR Zone = 0;

        M = AddrFile->Groups6;
        for (i = 0; i < M->Count; i++)
        {
            if (RtlCompareMemory(M->Groups[i]->Group.Group, Group.Group, 16) == 16 &&
                (!Found || (Resolved && M->Groups[i]->Group.Zone == Group.Zone)))
            {
                Found = TRUE;
                Zone = M->Groups[i]->Group.Zone;
            }
        }
        if (Found)
        {
            Group.Zone = Zone;
            Resolved = TRUE;
        }
    }
    if (!Resolved)
    {
        Status = STATUS_INVALID_ADDRESS;
        goto Done;
    }
    netif = netif_get_by_index(Group.Zone);

    if (!AddrFile->Groups6 && New)
    {
        AddrFile->Groups6 = New;
        New = NULL;
    }
    M = AddrFile->Groups6;

    for (i = 0; M && i < M->Count; i++)
    {
        if (M->Groups[i]->Group.Zone == Group.Zone && RtlCompareMemory(M->Groups[i]->Group.Group, Group.Group, 16) == 16)
            break;
    }

    if (!M || i == M->Count)
    {
        /* A new group: the socket's limit, the machine's table, and MLD's memory (Windows Server 2022 took 300
           groups on one socket without an error: release notes) */
        if (Leave)
        {
            Status = STATUS_INVALID_ADDRESS;
        }
        else if (M->Count == UDP6_SOCKET_GROUPS || !Udp6CountMember(&Group, TRUE, AddrFile->ProcessId))
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            Member = NewMember;
            Member->Group = Group;
            Member->Mode = Mode;
            Member->NumSources = NumSources;
            Member->Sources = Copy;
            Machine = Udp6FindGroup(&Group);
            InsertTailList(&Machine->Members, &Member->GroupLink);
            M->Groups[M->Count++] = Member;
            NewMember = NULL;
            Copy = NULL;
            if (netif && Udp6UpdateMld(netif, &Group) != ERR_OK)
            {
                /* without MLD ip6_input would not take the group's datagrams */
                M->Count--;
                RemoveEntryList(&Member->GroupLink);
                NewMember = Member;
                Copy = Member->Sources;
                Udp6CountMember(&Group, FALSE, NULL);
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }
    else if (MustBeNew)
    {
        /* a second join: WSAEINVAL through the helper (oracle) */
        Status = STATUS_INVALID_PARAMETER;
    }
    else if (Leave)
    {
        Member = M->Groups[i];
        M->Groups[i] = M->Groups[--M->Count];
        RemoveEntryList(&Member->GroupLink);
        Old = Member->Sources;
        Gone = Member;
        Udp6CountMember(&Group, FALSE, NULL);
        if (netif)
            Udp6UpdateMld(netif, &Group);
    }
    else
    {
        Member = M->Groups[i];
        Old = Member->Sources;
        Member->Mode = Mode;
        Member->NumSources = NumSources;
        Member->Sources = Copy;
        Copy = NULL;
        /* without memory for MLD's copy the group is reported as EXCLUDE with none (Udp6UpdateMld); the socket's own
           filter is in force either way */
        if (netif)
            Udp6UpdateMld(netif, &Group);
    }

Done:
    UNLOCK_TCPIP_CORE();
    UnlockObject(AddrFile);

    if (New)
        ExFreePoolWithTag(New, UDP6_TAG);
    if (NewMember)
        ExFreePoolWithTag(NewMember, UDP6_TAG);
    if (Gone && Gone != NewMember)
        ExFreePoolWithTag(Gone, UDP6_TAG);
    if (Copy)
        ExFreePoolWithTag(Copy, UDP6_TAG);
    if (Old)
        ExFreePoolWithTag(Old, UDP6_TAG);
    return Status;
}

/* IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP as the stack had them before the source filters (AO_OPTION_INDEX_ADD_MCAST
 * and _DEL_; struct ipv6_mreq: the group, the interface index, 0 for the stack's choice): a join is EXCLUDE with no
 * source, a leave INCLUDE with none */
NTSTATUS
UDP6SetMembership(PADDRESS_FILE AddrFile, BOOLEAN Join, const VOID *Request, UINT Length)
{
    ULONG IfIndex;

    if (Length < 20 || !TCPIpv6Enabled)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&IfIndex, (const UCHAR *)Request + 16, sizeof(IfIndex));
    return UDP6SetFilter(AddrFile, IfIndex, Request, Join ? NITRO_MCAST_EXCLUDE : NITRO_MCAST_INCLUDE, 0, NULL, Join);
}

VOID
UDP6LeaveAll(PADDRESS_FILE AddrFile)
{
    PUDP6_MEMBERSHIPS M;
    ULONG i;

    LockObject(AddrFile);
    LOCK_TCPIP_CORE();
    M = AddrFile->Groups6;
    AddrFile->Groups6 = NULL;
    for (i = 0; M && i < M->Count; i++)
    {
        struct netif *netif;
        PUDP6_MEMBER Member = M->Groups[i];

        RemoveEntryList(&Member->GroupLink);
        Udp6CountMember(&Member->Group, FALSE, NULL);
        netif = netif_get_by_index(Member->Group.Zone);
        if (netif)
            Udp6UpdateMld(netif, &Member->Group);
    }
    UNLOCK_TCPIP_CORE();
    UnlockObject(AddrFile);

    if (M)
    {
        for (i = 0; i < M->Count; i++)
        {
            if (M->Groups[i]->Sources)
                ExFreePoolWithTag(M->Groups[i]->Sources, UDP6_TAG);
            ExFreePoolWithTag(M->Groups[i], UDP6_TAG);
        }
        ExFreePoolWithTag(M, UDP6_TAG);
    }
}

/* Whether a UDP socket is bound to Address (16 bytes). The core lock may be held (as in Udp6HasReceiver: the order is
   core lock, then AddressFileListLock) */
BOOLEAN
UDP6AddressInUse(const UCHAR *Address)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;
    IP_ADDRESS Wanted;

    Wanted.Type = IP_ADDRESS_V6;
    RtlCopyMemory(Wanted.Address.IPv6Address, Address, 16);

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        PADDRESS_FILE AddrFile = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);

        if (AddrFile->Protocol == IPPROTO_UDP && !AddrFile->PortReleased && AddrFile->Address.Type == IP_ADDRESS_V6 &&
            AddrIsEqual(&AddrFile->Address, &Wanted))
        {
            Found = TRUE;
            break;
        }
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

    return Found;
}

/* The row of an IPv6 UDP socket for the IPv6 UDP table (ninfo.c) */
VOID
UDP6BuildRow(PADDRESS_FILE AddrFile, PUDP6_ROW_OWNER_PID Row)
{
    RtlZeroMemory(Row, sizeof(*Row));
    if (AddrFile->Address.Type == IP_ADDRESS_V6)
    {
        RtlCopyMemory(Row->LocalAddr, AddrFile->Address.Address.IPv6Address, 16);
        if (AddrFile->Zone6 != IP6_NO_ZONE)
            Row->LocalScopeId = TCPInterfaceOfZone6(AddrFile->Zone6, FALSE);
    }
    else
    {
        Row->LocalAddr[10] = 0xFF;
        Row->LocalAddr[11] = 0xFF;
        RtlCopyMemory(&Row->LocalAddr[12], &AddrFile->Address.Address.IPv4Address, sizeof(ULONG));
    }
    Row->LocalPort = AddrFile->Port;
    Row->OwningPid = HandleToUlong(AddrFile->ProcessId);
}

VOID
UDP6Startup(VOID)
{
    KeInitializeSpinLock(&Udp6DeferredLock);
    Echo6Startup();
}
