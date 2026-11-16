/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Raw IPv6 sockets (AF_INET6, SOCK_RAW) on lwIP's IPv6 layer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A raw IPv6 socket is an address file of the raw IP device (\Device\RawIp\<protocol>) with an IPv6 address. Its
 * datagrams are the payload of IPv6 packets of that next header; lwIP is the network layer (route, source address,
 * neighbour discovery, fragmentation and reassembly), as for IPv6 UDP (udp6.c).
 *
 * What Windows does (Windows Server 2022 and Windows 10 22H2, evidence v6raw-20261116):
 * - Who: Administrators, LocalSystem, LocalService and NetworkService open any protocol; everybody else only
 *   IPPROTO_ICMP and IPPROTO_ICMPV6 (WSAEACCES at socket() for the others; AFD and TiCreateFileObject check it).
 *   Such an unprivileged socket sends only an echo request of its own family of at least 8 bytes (anything else
 *   is WSAEACCES at sendto) and may not set the header-include option (WSAEACCES).
 * - Receive: the payload after the IPv6 header and its extension headers (never the IPv6 header, whatever
 *   IPV6_HDRINCL says), from every packet of the protocol to an address the socket is bound to (or :: ), a copy
 *   per socket. An ICMPv6 socket gets the echo replies and the other ICMPv6 messages, but not the echo requests
 *   the stack itself answers (measured on the loopback address).
 * - Send: the stack computes the ICMPv6 checksum of an ICMPv6 socket (a wrong one in the data is replaced); up to
 *   65535 bytes (65536: WSAEMSGSIZE). With IPV6_HDRINCL (administrators) the data starts with the IPv6 header.
 *
 * Receive (RawIp6Input, from LibIp6NexthInput: lwIP's ip6_input after reassembly and the extension headers, core
 * lock held): with a raw IPv6 socket open, the payload is copied to a queue that RawIp6DeliverDeferred hands to the
 * sockets once the core lock is released (UDP6DeliverDeferred calls it), as udp6.c does for datagrams.
 */

#include "precomp.h"

#include <nitrofwk.h>
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/prot/ip6.h"
#include "lwip/nd6.h"
#include "lwip/icmp6.h"

#define RAW6_TAG                'R6pT'
/* The largest datagram a raw IPv6 socket sends (Windows: 65535, WSAEMSGSIZE beyond). lwIP keeps a packet with its
   IPv6 header in buffers of 16-bit length, so more than 65535 - 40 bytes of payload go out as fragments built here
   (Ip6SendFragmented) */
#define RAW6_MAX_PAYLOAD        0xFFFF
/* Waiting for RawIp6DeliverDeferred: beyond these the newest are dropped */
#define RAW6_DEFERRED_MAX       1024
#define RAW6_DEFERRED_MAX_BYTES (4 * 1024 * 1024)

/* udp6.c */
VOID Udp6DeliverFromSystemThread(VOID);
struct netif *Udp6NetifOfIndex(ULONG IfIndex);
struct netif *Udp6Route(const ip6_addr_t *Src, const ip6_addr_t *Dest);
struct netif *Udp6DefaultMulticastNetif(VOID);

typedef struct _RAW6_DEFERRED {
    LIST_ENTRY ListEntry;
    UCHAR Src[16];
    UCHAR Dst[16];
    UCHAR Protocol;
    DG_RX_INFO6 Info;
    UINT Length;
    UCHAR Data[ANYSIZE_ARRAY];
} RAW6_DEFERRED, *PRAW6_DEFERRED;

static LIST_ENTRY Raw6Deferred = { &Raw6Deferred, &Raw6Deferred };
static KSPIN_LOCK Raw6DeferredLock;
static LONG Raw6DeferredCount;
static LONG Raw6DeferredBytes;

/* Raw IPv6 address files that exist (FileOpenAddress / AddrFileFree): no copy is made while there is none */
volatile LONG RawIp6Sockets;
volatile LONG RawIp6Dropped;

BOOLEAN
RawIp6IsRawFile(PADDRESS_FILE AddrFile)
{
    return AddrFile->Family == TDI_ADDRESS_TYPE_IP6 &&
           AddrFile->Protocol != IPPROTO_TCP && AddrFile->Protocol != IPPROTO_UDP;
}

/* ------------------------------------------------------------------------------------------------
 * Receive
 * ---------------------------------------------------------------------------------------------- */

/* A raw IPv6 socket of Protocol (AddressFileListLock; no reference is taken) */
static
BOOLEAN
RawIp6HasSocket(UCHAR Protocol)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    BOOLEAN Found = FALSE;

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead; Entry = Entry->Flink)
    {
        PADDRESS_FILE AddrFile = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);

        if (AddrFile->Protocol == Protocol && RawIp6IsRawFile(AddrFile) && !AddrFile->PortReleased)
        {
            Found = TRUE;
            break;
        }
    }
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);

    return Found;
}

/*
 * From LibIp6NexthInput (udp6.c), core lock held, p at the payload after the extension headers (not freed here).
 * Returns TRUE when a raw socket of the protocol exists and got (or was offered) a copy.
 */
BOOLEAN
RawIp6Input(struct pbuf *p, struct netif *inp, u8_t nexth)
{
    PRAW6_DEFERRED D;
    PIP_INTERFACE IF = inp ? inp->state : NULL;
    const ip6_addr_t *Src = ip6_current_src_addr();
    const ip6_addr_t *Dst = ip6_current_dest_addr();
    KIRQL OldIrql;
    UCHAR Type;

    if (!RawIp6Sockets || p->tot_len == 0)
        return FALSE;

    /* The echo requests the stack answers are not given to ICMPv6 sockets (Windows, on the loopback address) */
    if (nexth == IP6_NEXTH_ICMP6 && pbuf_copy_partial(p, &Type, 1, 0) == 1 && Type == ICMP6_TYPE_EREQ)
        return FALSE;

    if (!RawIp6HasSocket(nexth))
        return FALSE;

    D = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(RAW6_DEFERRED, Data[p->tot_len]), RAW6_TAG);
    if (!D)
    {
        InterlockedIncrement(&RawIp6Dropped);
        return TRUE;
    }
    RtlZeroMemory(D, FIELD_OFFSET(RAW6_DEFERRED, Data));
    RtlCopyMemory(D->Src, Src->addr, 16);
    RtlCopyMemory(D->Dst, Dst->addr, 16);
    D->Protocol = nexth;
    D->Info.IfIndex = IF ? IF->Index : 0;
    D->Info.SrcScopeId = (ip6_addr_islinklocal(Src) && IF) ? IF->Index : 0;
    D->Info.HopLimit = IP6H_HOPLIM(ip6_current_header());
    D->Length = p->tot_len;
    if (pbuf_copy_partial(p, D->Data, p->tot_len, 0) != p->tot_len)
    {
        ExFreePoolWithTag(D, RAW6_TAG);
        InterlockedIncrement(&RawIp6Dropped);
        return TRUE;
    }

    KeAcquireSpinLock(&Raw6DeferredLock, &OldIrql);
    if (Raw6DeferredCount >= RAW6_DEFERRED_MAX || Raw6DeferredBytes + (LONG)D->Length > RAW6_DEFERRED_MAX_BYTES)
    {
        KeReleaseSpinLock(&Raw6DeferredLock, OldIrql);
        ExFreePoolWithTag(D, RAW6_TAG);
        InterlockedIncrement(&RawIp6Dropped);
        return TRUE;
    }
    InsertTailList(&Raw6Deferred, &D->ListEntry);
    Raw6DeferredCount++;
    Raw6DeferredBytes += D->Length;
    KeReleaseSpinLock(&Raw6DeferredLock, OldIrql);
    return TRUE;
}

static
VOID
RawIp6Deliver(PRAW6_DEFERRED D)
{
    AF_SEARCH SearchContext;
    IP_ADDRESS Src, Dst;
    IP_PACKET Packet;
    PADDRESS_FILE AddrFile;

    Src.Type = IP_ADDRESS_V6;
    RtlCopyMemory(Src.Address.IPv6Address, D->Src, 16);
    Dst.Type = IP_ADDRESS_V6;
    RtlCopyMemory(Dst.Address.IPv6Address, D->Dst, 16);

    /* The payload without any header: DGDeliverNow takes Data (and HeaderSize 0) whatever HeaderIncl says */
    RtlZeroMemory(&Packet, sizeof(Packet));
    Packet.Type = IP_ADDRESS_V6;
    Packet.Header = D->Data;
    Packet.Data = D->Data;
    Packet.HeaderSize = 0;
    Packet.TotalSize = D->Length;
    Packet.SrcAddr = Src;
    Packet.DstAddr = Dst;

    /* Every raw IPv6 socket of the protocol bound to the destination or to :: gets a copy */
    for (AddrFile = AddrSearchFirst(&Dst, 0, D->Protocol, &SearchContext);
         AddrFile != NULL;
         AddrFile = AddrSearchNext(&SearchContext))
    {
        if (RawIp6IsRawFile(AddrFile))
            DGDeliverDataEx(NULL, AddrFile, &Src, &Dst, 0, 0, &Packet, D->Length, &D->Info);
        DereferenceObject(AddrFile);
    }
}

/* Called from UDP6DeliverDeferred: no lock held, PASSIVE_LEVEL */
VOID
RawIp6DeliverDeferred(VOID)
{
    PLIST_ENTRY Entry;
    PRAW6_DEFERRED D;
    KIRQL OldIrql;

    if (IsListEmpty(&Raw6Deferred))
        return;

    for (;;)
    {
        KeAcquireSpinLock(&Raw6DeferredLock, &OldIrql);
        if (IsListEmpty(&Raw6Deferred))
        {
            KeReleaseSpinLock(&Raw6DeferredLock, OldIrql);
            break;
        }
        Entry = RemoveHeadList(&Raw6Deferred);
        D = CONTAINING_RECORD(Entry, RAW6_DEFERRED, ListEntry);
        Raw6DeferredCount--;
        Raw6DeferredBytes -= D->Length;
        KeReleaseSpinLock(&Raw6DeferredLock, OldIrql);

        RawIp6Deliver(D);
        ExFreePoolWithTag(D, RAW6_TAG);
    }
}

BOOLEAN
RawIp6HasDeferred(VOID)
{
    return !IsListEmpty(&Raw6Deferred);
}

VOID
RawIp6Startup(VOID)
{
    KeInitializeSpinLock(&Raw6DeferredLock);
}

/* ------------------------------------------------------------------------------------------------
 * Send
 * ---------------------------------------------------------------------------------------------- */

/* Is Address one of this machine's IPv6 addresses (core lock held; udp6.c too) */
BOOLEAN
Ip6IsLocalAddress(const ip6_addr_t *Address)
{
    struct netif *netif;
    s8_t i;

    if (ip6_addr_isloopback(Address))
        return TRUE;
    NETIF_FOREACH(netif)
    {
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
                ip6_addr_zoneless_eq(netif_ip6_addr(netif, i), Address))
                return TRUE;
        }
    }
    return FALSE;
}

/*
 * One IPv6 packet of Protocol with Payload (core lock held; p is not freed here). lwIP fragments what does not fit
 * the path MTU; a payload that lwIP cannot hold with its IPv6 header in a 16-bit length (more than 65495 bytes)
 * goes out as fragments built here (RFC 8200 4.5: offsets in 8-byte units, one identification, the fragment header
 * right after the IPv6 header, every fragment a multiple of 8 bytes except the last).
 */
err_t
Ip6SendFragmented(struct pbuf *p, const ip6_addr_t *Source, const ip6_addr_t *Dest, u8_t Hops, u8_t TClass,
                  u8_t Protocol, struct netif *netif)
{
    static ULONG Identification;
    struct ip6_frag_hdr *Frag;
    struct pbuf *f;
    ULONG Id, Offset, Total = p->tot_len, Chunk;
    u16_t Mtu;
    err_t Result = ERR_OK;

    if (Total + IP6_HLEN <= 0xFFFF)
        return ip6_output_if(p, Source, Dest, Hops, TClass, Protocol, netif);

    /* The fragmentable part per fragment: what fits the link MTU after the IPv6 and fragment headers */
    Mtu = nd6_get_destination_mtu(Dest, netif);
    if (Mtu < 1280)
        Mtu = 1280;
    Chunk = (Mtu - IP6_HLEN - IP6_FRAG_HLEN) & ~7UL;
    if (!Identification)
        Identification = (ULONG)KeQueryPerformanceCounter(NULL).LowPart | 1;
    Id = (ULONG)InterlockedIncrement((PLONG)&Identification);

    for (Offset = 0; Offset < Total && Result == ERR_OK; Offset += Chunk)
    {
        ULONG Length = min(Chunk, Total - Offset);
        BOOLEAN More = (Offset + Length < Total);

        f = pbuf_alloc(PBUF_IP, (u16_t)(IP6_FRAG_HLEN + Length), PBUF_RAM);
        if (!f)
            return ERR_MEM;
        Frag = (struct ip6_frag_hdr *)f->payload;
        Frag->_nexth = Protocol;
        Frag->reserved = 0;
        Frag->_fragment_offset = lwip_htons((u16_t)(Offset | (More ? IP6_FRAG_MORE_FLAG : 0)));
        Frag->_identification = lwip_htonl(Id);
        if (pbuf_copy_partial(p, (u8_t *)f->payload + IP6_FRAG_HLEN, (u16_t)Length, (u16_t)Offset) != Length)
        {
            pbuf_free(f);
            return ERR_BUF;
        }
        Result = ip6_output_if(f, Source, Dest, Hops, TClass, IP6_NEXTH_FRAGMENT, netif);
        pbuf_free(f);
    }
    return Result;
}

/* An unprivileged raw socket (an ICMP or ICMPv6 one of a standard user) sends echo requests of its own family
   only, 8 bytes at least (Windows: WSAEACCES at sendto for anything else) */
static
BOOLEAN
RawIp6UnprivilegedMaySend(PADDRESS_FILE AddrFile, PCHAR Data, ULONG Size)
{
    UCHAR Type;

    if (AddrFile->RawPrivileged)
        return TRUE;
    if (AddrFile->Protocol != IP6_NEXTH_ICMP6 || Size < 8)
        return FALSE;
    /* (the send's buffer is the system mapping of its locked MDL, DispTdiSendDatagram) */
    Type = *(PUCHAR)Data;
    return Type == ICMP6_TYPE_EREQ;
}

NTSTATUS
RawIPSendDatagram6(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed)
{
    PTA_IP6_ADDRESS Remote = (PTA_IP6_ADDRESS)ConnInfo->RemoteAddress;
    UCHAR RemoteBytes[16];
    ULONG ScopeId, McastIf;
    IP_ADDRESS Local, RemoteIp;
    UCHAR Zone, Hops, McastHops, Protocol, TClass = 0;
    BOOLEAN Multicast, HeaderIncl;
    ip6_addr_t Dest, Source;
    const ip_addr_t *Selected;
    struct netif *netif = NULL;
    struct pbuf *p, *Data;
    PCHAR Payload = BufferData;
    ULONG PayloadSize = DataSize;
    err_t Result;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!TCPIpv6Enabled)
        return STATUS_INVALID_ADDRESS;
    if (!ConnInfo || !Remote || ConnInfo->RemoteAddressLength < sizeof(TA_IP6_ADDRESS) ||
        Remote->TAAddressCount != 1 || Remote->Address[0].AddressType != TDI_ADDRESS_TYPE_IP6 ||
        Remote->Address[0].AddressLength < TDI_ADDRESS_LENGTH_IP6)
        return STATUS_INVALID_ADDRESS;

    /* The caller checked that the whole TA_IP6_ADDRESS is there; its fields may be unaligned */
    RtlCopyMemory(RemoteBytes, Remote->Address[0].Address[0].sin6_addr, sizeof(RemoteBytes));
    RtlCopyMemory(&ScopeId, &Remote->Address[0].Address[0].sin6_scope_id, sizeof(ScopeId));

    if (DataSize > RAW6_MAX_PAYLOAD)
        return STATUS_BUFFER_TOO_SMALL;
    if (!RawIp6UnprivilegedMaySend(AddrFile, BufferData, DataSize))
        return STATUS_ACCESS_DENIED;

    LockObject(AddrFile);
    Local = AddrFile->Address;
    Zone = AddrFile->Zone6;
    Hops = AddrFile->TTL;
    McastHops = AddrFile->McastHops;
    McastIf = AddrFile->McastIf;
    Protocol = (UCHAR)AddrFile->Protocol;
    HeaderIncl = AddrFile->HeaderIncl6;
    UnlockObject(AddrFile);

    RtlCopyMemory(Dest.addr, RemoteBytes, sizeof(Dest.addr));
    ip6_addr_clear_zone(&Dest);
    RtlZeroMemory(&Source, sizeof(Source));

    /* IPV6_HDRINCL: the data is the IPv6 header and its payload. The destination, next header, hop limit and
       traffic class come from the header; the source must be :: or an address of this machine (no packet is sent
       in another host's name) and the payload length must be what follows the header */
    if (HeaderIncl)
    {
        UCHAR Header[IP6_HLEN];

        if (DataSize < IP6_HLEN)
            return STATUS_INVALID_PARAMETER;
        RtlCopyMemory(Header, BufferData, IP6_HLEN);
        if ((Header[0] >> 4) != 6 || (ULONG)((Header[4] << 8) | Header[5]) != DataSize - IP6_HLEN)
            return STATUS_INVALID_PARAMETER;
        TClass = (UCHAR)(((Header[0] & 0x0F) << 4) | (Header[1] >> 4));
        Protocol = Header[6];
        Hops = Header[7];
        RtlCopyMemory(Source.addr, &Header[8], 16);
        RtlCopyMemory(Dest.addr, &Header[24], 16);
        ip6_addr_clear_zone(&Source);
        ip6_addr_clear_zone(&Dest);
        Payload = BufferData + IP6_HLEN;
        PayloadSize = DataSize - IP6_HLEN;
    }

    if (ip6_addr_isany(&Dest))
        return STATUS_INVALID_ADDRESS;
    Multicast = ip6_addr_ismulticast(&Dest) ? TRUE : FALSE;

    /* A socket bound to ::ffff:a.b.c.d has no IPv6 (raw sockets are never dual stack) */
    if (Local.Type != IP_ADDRESS_V6)
        return STATUS_INVALID_ADDRESS;

    RemoteIp.Type = IP_ADDRESS_V6;
    RtlCopyMemory(RemoteIp.Address.IPv6Address, Dest.addr, sizeof(Dest.addr));

    LOCK_TCPIP_CORE();

    /* The data in a buffer of its own, the headers' room in another in front of it (lwIP's 16-bit lengths: one
       buffer could not hold 65535 bytes and the room), as udp6.c does */
    p = pbuf_alloc(PBUF_IP, 0, PBUF_RAM);
    Data = PayloadSize ? pbuf_alloc(PBUF_RAW, (u16_t)PayloadSize, PBUF_RAM) : NULL;
    if (!p || (PayloadSize && !Data))
    {
        if (p)
            pbuf_free(p);
        if (Data)
            pbuf_free(Data);
        UNLOCK_TCPIP_CORE();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (Data)
    {
        pbuf_take(Data, Payload, (u16_t)PayloadSize);
        pbuf_cat(p, Data);
    }

    /* The interface: as for a UDP datagram (udp6.c) */
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
        if (netif)
            ip6_addr_assign_zone(&Dest, IP6_UNICAST, netif);
    }

    /* The source: the header's (IPV6_HDRINCL), else the bound address, else what lwIP selects */
    if (HeaderIncl && !ip6_addr_isany(&Source))
    {
        if (!Ip6IsLocalAddress(&Source))
        {
            pbuf_free(p);
            UNLOCK_TCPIP_CORE();
            return STATUS_INVALID_ADDRESS;
        }
        if (!netif)
            netif = Udp6Route(&Source, &Dest);
        if (netif && ip6_addr_islinklocal(&Source))
            ip6_addr_assign_zone(&Source, IP6_UNICAST, netif);
    }
    else if (!AddrIsUnspecified(&Local))
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
            pbuf_free(p);
            UNLOCK_TCPIP_CORE();
            return STATUS_NETWORK_UNREACHABLE;
        }
        ip6_addr_copy(Source, *ip_2_ip6(Selected));
    }

    if (!netif)
    {
        pbuf_free(p);
        UNLOCK_TCPIP_CORE();
        return STATUS_NETWORK_UNREACHABLE;
    }

    /* lwIP's reassembly cannot hold more than 65495 bytes of payload: to this machine that is the limit (a larger
       packet would be lost on the way in), WSAEMSGSIZE as beyond 65535 */
    if (PayloadSize > (ULONG)(0xFFFF - IP6_HLEN) &&
        ((Loopback && netif == Loopback->TCPContext) || Ip6IsLocalAddress(&Dest)))
    {
        pbuf_free(p);
        UNLOCK_TCPIP_CORE();
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* ICMPv6: the stack computes the checksum (RFC 3542 3.1; Windows replaces a wrong one), when the data holds it */
    if (Protocol == IP6_NEXTH_ICMP6 && p->tot_len >= 4)
    {
        u16_t Zero = 0, Sum;

        pbuf_take_at(p, &Zero, sizeof(Zero), 2);
        Sum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->tot_len, &Source, &Dest);
        pbuf_take_at(p, &Sum, sizeof(Sum), 2);
    }

    /* The replies to an echo request pass the inbound filter */
    if (Protocol == IP6_NEXTH_ICMP6 && Data && Data->len >= 8)
        NITROFW_NOTE_ICMP_SEND(&RemoteIp, (PUCHAR)Data->payload, Data->len);

    Result = Ip6SendFragmented(p, &Source, &Dest, Multicast ? McastHops : Hops, TClass, Protocol, netif);

    pbuf_free(p);
    UNLOCK_TCPIP_CORE();

    /* A packet lwIP keeps for neighbour discovery counts as sent */
    if (Result != ERR_OK && Result != ERR_INPROGRESS)
        Status = (Result == ERR_MEM || Result == ERR_BUF) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_NETWORK_UNREACHABLE;

    /* What the send put on the queues (a packet to this machine is taken by ip6_input at once), from a system
       thread (udp6.c: AFD re-posts a receive inline only there) */
    Udp6DeliverFromSystemThread();

    if (NT_SUCCESS(Status))
        *DataUsed = DataSize;
    return Status;
}
