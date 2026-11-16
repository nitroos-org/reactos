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
 * Multicast groups (IPV6_ADD_MEMBERSHIP): per socket (up to UDP6_SOCKET_GROUPS), and per interface a count of
 * the sockets that joined. The first socket in a group joins it in lwIP's MLD on that interface (mld6.c, MLDv1,
 * RFC 2710): ip6_input then takes the group, and MLD reports it to the link (at once, again within half a second,
 * and in answer to each query), so a switch that snoops MLD forwards it; the last socket leaving sends the done
 * message. The group also goes in the adapter's multicast list (if6.c, TCP6UpdateMulticast). A socket receives a
 * group's datagram only if it joined the group on the interface the datagram arrived on (VERIFY ON ORACLE).
 * Windows reports with MLDv2 (RFC 3810, VERIFY on a capture); MLDv1 is what lwIP has, and an MLDv2 router or
 * snooping switch falls back to it for the link (RFC 3810 8).
 */

#include "precomp.h"

#include <nitrofwk.h>
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

/* echo6.c */
int Echo6Input(struct pbuf *p, struct netif *inp);
VOID Echo6CompleteDone(VOID);
VOID Echo6Startup(VOID);

#define UDP6_TAG                'U6pT'
#define UDP6_SOCKET_GROUPS      20      /* IP_MAX_MEMBERSHIPS */
#define UDP6_MACHINE_GROUPS     128
/* Table entries one process can take: a group joined by sockets of other processes costs a joiner nothing (it
   shares the entry), a new one is charged to the process that joined it first, so no process can fill the table
   for everybody (Windows limits a socket, not the machine) */
#define UDP6_PROCESS_GROUPS     32
/* Datagrams waiting for UDP6DeliverDeferred: beyond these the newest are dropped */
#define UDP6_DEFERRED_MAX       4096
#define UDP6_DEFERRED_MAX_BYTES (16 * 1024 * 1024)
/* The largest UDP payload this stack sends over IPv6: lwIP keeps a datagram with its IPv6 header in buffers of
   16-bit length, so 65535 - 40 - 8 = 65487 bytes, where Windows sends 65535 - 8 = 65527 (oracle). A larger one is
   WSAEMSGSIZE, as Windows answers beyond 65527 */
#define UDP6_MAX_PAYLOAD        (0xFFFF - 40 - sizeof(UDP_HEADER))

typedef struct _UDP6_GROUP {
    UCHAR Group[16];
    UCHAR Zone;                 /* lwIP's netif index of the interface */
} UDP6_GROUP, *PUDP6_GROUP;

typedef struct _UDP6_MEMBERSHIPS {
    ULONG Count;
    UDP6_GROUP Groups[UDP6_SOCKET_GROUPS];
} UDP6_MEMBERSHIPS, *PUDP6_MEMBERSHIPS;

/* The groups some socket joined, per interface (core lock) */
typedef struct _UDP6_MACHINE_GROUP {
    UDP6_GROUP Group;
    ULONG Sockets;
    HANDLE Owner;               /* the process that took the entry (it stays charged until the entry is free) */
} UDP6_MACHINE_GROUP;

static UDP6_MACHINE_GROUP Udp6Groups[UDP6_MACHINE_GROUPS];

typedef struct _UDP6_DEFERRED {
    LIST_ENTRY ListEntry;
    UCHAR Src[16];
    UCHAR Dst[16];
    USHORT SrcPort;             /* network order */
    USHORT DstPort;
    UCHAR Zone;                 /* the interface it arrived on (multicast membership) */
    BOOLEAN Multicast;
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
    /* ICMPv6: the answers to our echo requests (echo6.c) */
    if (nexth == IP6_NEXTH_ICMP6)
        return Echo6Input(p, inp);
    if (nexth != IP6_NEXTH_UDP)
        return 0;

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

/* Joined Group on Zone (the socket's object lock held) */
static
BOOLEAN
Udp6IsMember(PADDRESS_FILE AddrFile, const UCHAR *Group, UCHAR Zone)
{
    PUDP6_MEMBERSHIPS M = AddrFile->Groups6;
    ULONG i;

    if (!M)
        return FALSE;
    for (i = 0; i < M->Count; i++)
    {
        if (M->Groups[i].Zone == Zone && RtlCompareMemory(M->Groups[i].Group, Group, 16) == 16)
            return TRUE;
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
            Member = Udp6IsMember(AddrFile, D->Dst, D->Zone);
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
   no memory for one: the datagram may then be lost as before, never more than that) */
static
VOID
Udp6DeliverFromSystemThread(VOID)
{
    PIO_WORKITEM Item;

    if (IsListEmpty(&Udp6Deferred))
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
            pbuf_free(p);
            UNLOCK_TCPIP_CORE();
            if (Copy)
                ExFreePoolWithTag(Copy, UDP6_TAG);
            return STATUS_NETWORK_UNREACHABLE;
        }
        ip6_addr_copy(Source, *ip_2_ip6(Selected));
    }

    if (!netif)
    {
        pbuf_free(p);
        UNLOCK_TCPIP_CORE();
        if (Copy)
            ExFreePoolWithTag(Copy, UDP6_TAG);
        return STATUS_NETWORK_UNREACHABLE;
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

    Result = ip6_output_if(p, &Source, &Dest, Multicast ? McastHops : Hops, 0, IP6_NEXTH_UDP, netif);

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
    if (Result != ERR_OK && Result != ERR_INPROGRESS)
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

/* Group in lwIP's MLD on netif: joined for the first socket, left after the last (core lock held) */
static
err_t
Udp6Mld(struct netif *netif, const UDP6_GROUP *Group, BOOLEAN Join)
{
    ip6_addr_t Address;

    RtlCopyMemory(Address.addr, Group->Group, 16);
    ip6_addr_clear_zone(&Address);
    return Join ? mld6_joingroup_netif(netif, &Address) : mld6_leavegroup_netif(netif, &Address);
}

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
                Udp6Mld(netif, &Udp6Groups[i].Group, TRUE);
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

/* One socket more or less in Group on its interface (core lock held). FALSE: no room for another group, in the
 * table or in Process's share of it */
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
#if LWIP_IPV6_MLD
        /* MLD takes the group first: without it ip6_input would not take the group's datagrams */
        netif = netif_get_by_index(Group->Zone);
        if (netif && Udp6Mld(netif, Group, TRUE) != ERR_OK)
            return FALSE;
#endif
        Udp6Groups[Free].Group = *Group;
        Udp6Groups[Free].Sockets = 1;
        Udp6Groups[Free].Owner = Process;
    }

    /* The first socket in the group, or the last one gone: the adapter's list changes (and MLD leaves the group
       after the last one) */
    netif = netif_get_by_index(Group->Zone);
    if (netif)
    {
#if LWIP_IPV6_MLD
        if (!Join)
            Udp6Mld(netif, Group, FALSE);
#endif
        TCP6UpdateMulticastList(netif);
    }
    return TRUE;
}

NTSTATUS
UDP6SetMembership(PADDRESS_FILE AddrFile, BOOLEAN Join, const VOID *Request, UINT Length)
{
    UDP6_GROUP Group;
    ULONG IfIndex, i;
    struct netif *netif;
    BOOLEAN Resolved = FALSE;
    PUDP6_MEMBERSHIPS M, New = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    /* struct ipv6_mreq: the group, the interface index (0: the stack's choice) */
    if (Length < 20 || !TCPIpv6Enabled)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(Group.Group, Request, 16);
    RtlCopyMemory(&IfIndex, (const UCHAR *)Request + 16, sizeof(IfIndex));
    if (Group.Group[0] != 0xFF)
        return STATUS_INVALID_ADDRESS;

    if (Join)
    {
        New = ExAllocatePoolWithTag(NonPagedPool, sizeof(*New), UDP6_TAG);
        if (!New)
            return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(New, sizeof(*New));
    }

    LockObject(AddrFile);
    LOCK_TCPIP_CORE();

    netif = IfIndex ? Udp6NetifOfIndex(IfIndex) : Udp6DefaultMulticastNetif();
    if (netif)
    {
        Group.Zone = (UCHAR)netif_get_index(netif);
        Resolved = TRUE;
    }
    if (!Join && !IfIndex && AddrFile->Groups6)
    {
        /* A leave without an interface ends the socket's join of the group, on whichever interface the join
           landed: the default one may have changed since (an adapter that got its address, or went away) */
        BOOLEAN Found = FALSE;
        UCHAR Zone = 0;

        M = AddrFile->Groups6;
        for (i = 0; i < M->Count; i++)
        {
            if (RtlCompareMemory(M->Groups[i].Group, Group.Group, 16) == 16 &&
                (!Found || (Resolved && M->Groups[i].Zone == Group.Zone)))
            {
                Found = TRUE;
                Zone = M->Groups[i].Zone;
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

    if (!AddrFile->Groups6 && Join)
    {
        AddrFile->Groups6 = New;
        New = NULL;
    }
    M = AddrFile->Groups6;

    for (i = 0; M && i < M->Count; i++)
    {
        if (M->Groups[i].Zone == Group.Zone && RtlCompareMemory(M->Groups[i].Group, Group.Group, 16) == 16)
            break;
    }

    if (Join)
    {
        /* A second join: WSAEINVAL through the helper (oracle); one past the limit: VERIFY ON ORACLE */
        if (i < M->Count)
            Status = STATUS_INVALID_PARAMETER;
        else if (M->Count == UDP6_SOCKET_GROUPS || !Udp6CountMember(&Group, TRUE, AddrFile->ProcessId))
            Status = STATUS_INSUFFICIENT_RESOURCES;
        else
            M->Groups[M->Count++] = Group;
    }
    else
    {
        if (!M || i == M->Count)
        {
            Status = STATUS_INVALID_ADDRESS;
        }
        else
        {
            M->Groups[i] = M->Groups[--M->Count];
            Udp6CountMember(&Group, FALSE, NULL);
        }
    }

Done:
    UNLOCK_TCPIP_CORE();
    UnlockObject(AddrFile);

    if (New)
        ExFreePoolWithTag(New, UDP6_TAG);
    return Status;
}

VOID
UDP6LeaveAll(PADDRESS_FILE AddrFile)
{
    PUDP6_MEMBERSHIPS M;
    ULONG i;

    LockObject(AddrFile);
    M = AddrFile->Groups6;
    AddrFile->Groups6 = NULL;
    if (M && M->Count)
    {
        LOCK_TCPIP_CORE();
        for (i = 0; i < M->Count; i++)
            Udp6CountMember(&M->Groups[i], FALSE, NULL);
        UNLOCK_TCPIP_CORE();
    }
    UnlockObject(AddrFile);

    if (M)
        ExFreePoolWithTag(M, UDP6_TAG);
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
