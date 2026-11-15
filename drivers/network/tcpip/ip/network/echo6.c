/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ICMPv6 echo for Icmp6SendEcho2 (\Device\Ip6, IOCTL_ICMP_ECHO_REQUEST)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * iphlpapi's Icmp6SendEcho2 opens \Device\Ip6 (made only with Tcpip\Parameters\Ipv6Enable on) and asks for one
 * echo: ICMPV6_ECHO_REQUEST and the data in, ICMPV6_ECHO_REPLY and the reply's data out. The request is an ICMPv6
 * echo request (RFC 4443 4.1) sent through lwIP's IPv6 (route, source selection, neighbour discovery) with an
 * identifier and sequence number of its own. The answer is taken from ip6_input (LibIp6NexthInput, core lock held):
 * the echo reply with that identifier and sequence from the address asked, or an ICMPv6 error whose invoking packet
 * is the request (destination unreachable, packet too big, time exceeded, parameter problem). The request is then
 * completed once the core lock is released (Echo6CompleteDone, from the same places as the UDP deliveries), by its
 * timer (IP_REQ_TIMED_OUT, STATUS_TIMEOUT as the IPv4 echo), or by its cancellation. Three parties may finish a
 * request; the first one to change its state does, under Echo6Lock. A reference for the timer's DPC and one for the
 * request keep the record until both are gone.
 *
 * The firewall passes an echo reply or an error only while it answers an outstanding request (Echo6ReplyExpected,
 * Echo6ErrorRelated), as IPv4 does with FwIcmpReplyExpected.
 */

#include "precomp.h"

#include <psdk/ipexport.h>
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"

#define ECHO6_TAG               'E6pT'
#define ECHO6_PENDING           0
#define ECHO6_ANSWERED          1
#define ECHO6_TIMED_OUT         2
#define ECHO6_CANCELLED         3
/* Status of a request that could not be sent for want of a route */
#define ECHO6_NO_ROUTE          0xFFFFFFFF
/* The largest echo data lwIP sends in one datagram (its 16-bit length holds the IPv6 and ICMPv6 headers too) */
#define ECHO6_MAX_DATA          (0xFFFF - 40 - 8)
#define ECHO6_MAX_ROOM          0x10000

typedef struct _ECHO6 {
    LIST_ENTRY Entry;           /* Echo6Pending, then Echo6Done */
    LONG Refs;
    LONG State;
    PIRP Irp;
    USHORT Ident;               /* as in the packet */
    USHORT Seq;
    UCHAR Dst[16];
    ULONGLONG Start;
    KTIMER Timer;
    KDPC Dpc;
    ULONG Status;               /* IP_xxx */
    UCHAR From[16];
    ULONG FromScope;
    ULONG Room;                 /* reply data the caller's buffer takes */
    ULONG DataLen;
    UCHAR Data[ANYSIZE_ARRAY];
} ECHO6, *PECHO6;

static LIST_ENTRY Echo6Pending = { &Echo6Pending, &Echo6Pending };
static LIST_ENTRY Echo6Done = { &Echo6Done, &Echo6Done };
static KSPIN_LOCK Echo6Lock;
static volatile LONG Echo6Counter;

PDEVICE_OBJECT Ip6DeviceObject = NULL;

/* udp6.c */
struct netif *Udp6NetifOfIndex(ULONG IfIndex);
struct netif *Udp6DefaultMulticastNetif(VOID);
struct netif *Udp6Route(const ip6_addr_t *Src, const ip6_addr_t *Dest);

static
VOID
Echo6Release(PECHO6 E)
{
    if (InterlockedDecrement(&E->Refs) == 0)
        ExFreePoolWithTag(E, ECHO6_TAG);
}

/* Writes the answer to the caller's buffer and completes the request (no lock held; any IRQL up to DISPATCH) */
static
VOID
Echo6Complete(PECHO6 E)
{
    PIRP Irp = E->Irp;
    PICMPV6_ECHO_REPLY Reply = Irp->AssociatedIrp.SystemBuffer;
    KIRQL OldIrql;

    IoAcquireCancelSpinLock(&OldIrql);
    IoSetCancelRoutine(Irp, NULL);
    IoReleaseCancelSpinLock(OldIrql);

    RtlZeroMemory(Reply, sizeof(*Reply));
    if (E->State == ECHO6_CANCELLED)
    {
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
    }
    else if (E->Status == ECHO6_NO_ROUTE)
    {
        /* No route: the request fails (Windows 10: ERROR_NETWORK_UNREACHABLE, the reply untouched; oracle) */
        Irp->IoStatus.Status = STATUS_NETWORK_UNREACHABLE;
        Irp->IoStatus.Information = 0;
    }
    else if (E->State == ECHO6_TIMED_OUT)
    {
        Reply->Status = IP_REQ_TIMED_OUT;
        Irp->IoStatus.Status = STATUS_TIMEOUT;
        Irp->IoStatus.Information = sizeof(*Reply);
    }
    else
    {
        RtlCopyMemory(Reply->Address.sin6_addr, E->From, sizeof(E->From));
        Reply->Address.sin6_scope_id = E->FromScope;
        Reply->Status = E->Status;
        Reply->RoundTripTime = (ULONG)((KeQueryInterruptTime() - E->Start) / 10000);
        if (E->DataLen)
            RtlCopyMemory(Reply + 1, E->Data, E->DataLen);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = sizeof(*Reply) + E->DataLen;
    }
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    /* The timer's reference goes with the timer when it had not fired yet; else its DPC drops it */
    if (KeCancelTimer(&E->Timer))
        Echo6Release(E);
    Echo6Release(E);
}

static
VOID
NTAPI
Echo6Timeout(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PECHO6 E = Context;
    BOOLEAN Won = FALSE;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    KeAcquireSpinLockAtDpcLevel(&Echo6Lock);
    if (E->State == ECHO6_PENDING)
    {
        E->State = ECHO6_TIMED_OUT;
        RemoveEntryList(&E->Entry);
        Won = TRUE;
    }
    KeReleaseSpinLockFromDpcLevel(&Echo6Lock);

    if (Won)
    {
        /* Echo6Complete's KeCancelTimer finds the timer gone: the reference of this DPC is dropped below */
        Echo6Complete(E);
    }
    Echo6Release(E);
}

static
VOID
NTAPI
Echo6Cancel(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PECHO6 E = Irp->Tail.Overlay.DriverContext[0];
    BOOLEAN Won = FALSE;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(DeviceObject);
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    if (E->State == ECHO6_PENDING)
    {
        E->State = ECHO6_CANCELLED;
        RemoveEntryList(&E->Entry);
        Won = TRUE;
    }
    KeReleaseSpinLock(&Echo6Lock, OldIrql);

    if (Won)
        Echo6Complete(E);
}

/* The outstanding request with this identifier and sequence (as in the packet) to Peer (Echo6Lock held) */
static
PECHO6
Echo6Find(const UCHAR *Peer, USHORT Ident, USHORT Seq)
{
    PLIST_ENTRY Entry;

    for (Entry = Echo6Pending.Flink; Entry != &Echo6Pending; Entry = Entry->Flink)
    {
        PECHO6 E = CONTAINING_RECORD(Entry, ECHO6, Entry);

        if (E->Ident == Ident && E->Seq == Seq &&
            (!Peer || E->Dst[0] == 0xFF || RtlCompareMemory(E->Dst, Peer, 16) == 16))
            return E;
    }
    return NULL;
}

/* The firewall (nitrofw.c): an echo reply from Src (Icmp: the ICMPv6 message, Avail bytes of it) answers one of our
   outstanding requests */
BOOLEAN
Echo6ReplyExpected(const UCHAR *Src, const UCHAR *Icmp, ULONG Avail)
{
    BOOLEAN Found;
    KIRQL OldIrql;
    USHORT Ident, Seq;

    if (Avail < 8 || IsListEmpty(&Echo6Pending))
        return FALSE;
    RtlCopyMemory(&Ident, Icmp + 4, sizeof(Ident));
    RtlCopyMemory(&Seq, Icmp + 6, sizeof(Seq));

    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    Found = (Echo6Find(Src, Ident, Seq) != NULL);
    KeReleaseSpinLock(&Echo6Lock, OldIrql);
    return Found;
}

/* The invoking packet of an ICMPv6 error (Icmp, Avail bytes) is one of our outstanding echo requests: its IPv6
   header without extension headers, then the echo request. Returns the request's destination in *Dst (16 bytes) */
static
BOOLEAN
Echo6Invoking(const UCHAR *Icmp, ULONG Avail, USHORT *Ident, USHORT *Seq)
{
    if (Avail < 8 + 40 + 8 || Icmp[8 + 6] != 58 || Icmp[8 + 40] != 128)
        return FALSE;
    RtlCopyMemory(Ident, Icmp + 8 + 40 + 4, sizeof(*Ident));
    RtlCopyMemory(Seq, Icmp + 8 + 40 + 6, sizeof(*Seq));
    return TRUE;
}

BOOLEAN
Echo6ErrorRelated(const UCHAR *Icmp, ULONG Avail)
{
    BOOLEAN Found;
    KIRQL OldIrql;
    USHORT Ident, Seq;

    if (IsListEmpty(&Echo6Pending) || !Echo6Invoking(Icmp, Avail, &Ident, &Seq))
        return FALSE;

    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    /* the invoking packet's destination is the request's */
    Found = (Echo6Find(Icmp + 8 + 24, Ident, Seq) != NULL);
    KeReleaseSpinLock(&Echo6Lock, OldIrql);
    return Found;
}

static
ULONG
Echo6ErrorStatus(UCHAR Type, UCHAR Code)
{
    switch (Type)
    {
        case 1:
            /* destination unreachable: no route, prohibited, beyond scope, address, port */
            switch (Code)
            {
                case 0: return IP_DEST_NET_UNREACHABLE;
                case 1: return IP_DEST_PROT_UNREACHABLE; /* 11004, IP_DEST_PROHIBITED for IPv6 */
                case 4: return IP_DEST_PORT_UNREACHABLE;
                default: return IP_DEST_HOST_UNREACHABLE;
            }
        case 2: return IP_PACKET_TOO_BIG;
        case 3: return (Code == 0) ? IP_TTL_EXPIRED_TRANSIT : IP_TTL_EXPIRED_REASSEM;
        default: return IP_PARAM_PROBLEM;
    }
}

/* From LibIp6NexthInput (udp6.c), core lock held, p at the ICMPv6 header: 1 when p was an answer to one of our
   requests and was taken (freed), 0 to let lwIP go on (also after taking note of an error, which lwIP still sees) */
int
Echo6Input(struct pbuf *p, struct netif *inp)
{
    UCHAR Head[8 + 40 + 8];
    const ip6_addr_t *Src = ip6_current_src_addr();
    PIP_INTERFACE IF = inp ? inp->state : NULL;
    USHORT Ident, Seq;
    PECHO6 E;
    UINT Have;
    BOOLEAN Reply;

    if (IsListEmpty(&Echo6Pending) || p->tot_len < 8)
        return 0;

    Have = pbuf_copy_partial(p, Head, (u16_t)min(p->tot_len, sizeof(Head)), 0);
    if (Have < 8)
        return 0;

    if (Head[0] == 129)
    {
        /* lwIP has not checked the checksum yet: what is taken here must be whole */
        if (ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->tot_len, Src, ip6_current_dest_addr()) != 0)
            return 0;
        RtlCopyMemory(&Ident, Head + 4, sizeof(Ident));
        RtlCopyMemory(&Seq, Head + 6, sizeof(Seq));
        Reply = TRUE;
    }
    else if (Head[0] >= 1 && Head[0] <= 4)
    {
        if (!Echo6Invoking(Head, Have, &Ident, &Seq))
            return 0;
        Reply = FALSE;
    }
    else
    {
        return 0;
    }

    {
        KIRQL OldIrql;

        KeAcquireSpinLock(&Echo6Lock, &OldIrql);
        E = Echo6Find(Reply ? (const UCHAR *)Src->addr : Head + 8 + 24, Ident, Seq);
        if (E)
        {
            E->State = ECHO6_ANSWERED;
            RemoveEntryList(&E->Entry);
            RtlCopyMemory(E->From, Src->addr, 16);
            E->FromScope = (ip6_addr_islinklocal(Src) && IF) ? IF->Index : 0;
            if (Reply)
            {
                E->Status = IP_SUCCESS;
                E->DataLen = min(E->Room, (ULONG)p->tot_len - 8);
                if (E->DataLen)
                    pbuf_copy_partial(p, E->Data, (u16_t)E->DataLen, 8);
            }
            else
            {
                E->Status = Echo6ErrorStatus(Head[0], Head[1]);
                E->DataLen = 0;
            }
            InsertTailList(&Echo6Done, &E->Entry);
        }
        KeReleaseSpinLock(&Echo6Lock, OldIrql);
    }

    if (!E || !Reply)
        return 0;
    pbuf_free(p);
    return 1;
}

/* Completes the requests Echo6Input answered (no lock held, PASSIVE_LEVEL) */
VOID
Echo6CompleteDone(VOID)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;

    if (IsListEmpty(&Echo6Done))
        return;

    for (;;)
    {
        KeAcquireSpinLock(&Echo6Lock, &OldIrql);
        if (IsListEmpty(&Echo6Done))
        {
            KeReleaseSpinLock(&Echo6Lock, OldIrql);
            break;
        }
        Entry = RemoveHeadList(&Echo6Done);
        KeReleaseSpinLock(&Echo6Lock, OldIrql);

        Echo6Complete(CONTAINING_RECORD(Entry, ECHO6, Entry));
    }
}

/* IOCTL_ICMP_ECHO_REQUEST on \Device\Ip6 (PASSIVE_LEVEL). Returns STATUS_PENDING once the request is outstanding */
NTSTATUS
DispEchoRequest6(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PICMPV6_ECHO_REQUEST In = Irp->AssociatedIrp.SystemBuffer;
    ICMPV6_ECHO_REQUEST Req;
    ULONG DataSize, Room, Counter, Timeout;
    UCHAR Src6[16], Zone = IP6_NO_ZONE;
    BOOLEAN HasSource = FALSE;
    ip6_addr_t Dest, Source;
    const ip_addr_t *Selected;
    struct netif *netif = NULL;
    struct pbuf *p = NULL, *Data = NULL;
    PUCHAR Icmp;
    PECHO6 E;
    LARGE_INTEGER Due;
    KIRQL OldIrql;
    err_t Result = ERR_RTE;
    ULONG i;

    if (!TCPIpv6Enabled)
        return STATUS_INVALID_DEVICE_REQUEST;
    if (!In || InLen < sizeof(Req) || OutLen < sizeof(ICMPV6_ECHO_REPLY))
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&Req, In, sizeof(Req));
    DataSize = InLen - sizeof(Req);
    if (DataSize > ECHO6_MAX_DATA)
        return STATUS_INVALID_PARAMETER;
    Room = min(OutLen - sizeof(ICMPV6_ECHO_REPLY), ECHO6_MAX_ROOM);

    /* A source the caller names must be one of our addresses */
    RtlCopyMemory(Src6, Req.SourceAddress.sin6_addr, sizeof(Src6));
    for (i = 0; i < 16 && Src6[i] == 0; i++)
        ;
    if (i < 16)
    {
        if (!TCPFindLocalAddress6(Src6, Req.SourceAddress.sin6_scope_id, &Zone))
            return STATUS_INVALID_ADDRESS;
        HasSource = TRUE;
    }

    E = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(ECHO6, Data[Room ? Room : 1]), ECHO6_TAG);
    if (!E)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(E, FIELD_OFFSET(ECHO6, Data));
    E->Refs = 2;    /* the request and the timer */
    E->State = ECHO6_PENDING;
    E->Irp = Irp;
    E->Room = Room;
    Counter = (ULONG)InterlockedIncrement(&Echo6Counter);
    E->Ident = (USHORT)(0x4E36 ^ (Counter >> 16));
    E->Seq = (USHORT)Counter;
    RtlCopyMemory(E->Dst, Req.DestinationAddress.sin6_addr, sizeof(E->Dst));
    KeInitializeTimer(&E->Timer);
    KeInitializeDpc(&E->Dpc, Echo6Timeout, E);
    Irp->Tail.Overlay.DriverContext[0] = E;

    /* Outstanding from here on: the timer, the cancel routine and the list may each finish it */
    IoMarkIrpPending(Irp);
    Timeout = Req.Timeout ? Req.Timeout : 1;
    if (Timeout > 0x7FFFFFFF / 10000)
        Timeout = 0x7FFFFFFF / 10000;
    Due.QuadPart = -(LONGLONG)Timeout * 10000;
    E->Start = KeQueryInterruptTime();
    KeSetTimer(&E->Timer, Due, &E->Dpc);

    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    InsertTailList(&Echo6Pending, &E->Entry);
    KeReleaseSpinLock(&Echo6Lock, OldIrql);

    IoAcquireCancelSpinLock(&OldIrql);
    IoSetCancelRoutine(Irp, Echo6Cancel);
    if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL))
    {
        IoReleaseCancelSpinLock(OldIrql);
        KeAcquireSpinLock(&Echo6Lock, &OldIrql);
        if (E->State == ECHO6_PENDING)
        {
            E->State = ECHO6_CANCELLED;
            RemoveEntryList(&E->Entry);
            KeReleaseSpinLock(&Echo6Lock, OldIrql);
            Echo6Complete(E);
        }
        else
        {
            KeReleaseSpinLock(&Echo6Lock, OldIrql);
        }
        return STATUS_PENDING;
    }
    IoReleaseCancelSpinLock(OldIrql);

    LOCK_TCPIP_CORE();

    p = pbuf_alloc(PBUF_IP, 8, PBUF_RAM);
    Data = DataSize ? pbuf_alloc(PBUF_RAW, (u16_t)DataSize, PBUF_RAM) : NULL;
    if (p && (!DataSize || (Data && pbuf_take(Data, In + 1, (u16_t)DataSize) == ERR_OK)))
    {
        if (Data)
        {
            pbuf_cat(p, Data);
            Data = NULL;
        }

        RtlCopyMemory(Dest.addr, E->Dst, sizeof(Dest.addr));
        ip6_addr_clear_zone(&Dest);
        if (ip6_addr_ismulticast(&Dest))
        {
            netif = Req.DestinationAddress.sin6_scope_id ? Udp6NetifOfIndex(Req.DestinationAddress.sin6_scope_id) :
                                                           Udp6DefaultMulticastNetif();
            if (netif)
                ip6_addr_assign_zone(&Dest, IP6_MULTICAST, netif);
        }
        else if (ip6_addr_islinklocal(&Dest))
        {
            netif = Req.DestinationAddress.sin6_scope_id ? Udp6NetifOfIndex(Req.DestinationAddress.sin6_scope_id) :
                    (Zone != IP6_NO_ZONE ? netif_get_by_index(Zone) : NULL);
            if (netif)
                ip6_addr_assign_zone(&Dest, IP6_UNICAST, netif);
        }

        if (HasSource)
        {
            RtlCopyMemory(Source.addr, Src6, sizeof(Source.addr));
            ip6_addr_clear_zone(&Source);
            if (Zone != IP6_NO_ZONE)
                ip6_addr_set_zone(&Source, Zone);
            if (!netif)
                netif = Udp6Route(&Source, &Dest);
        }
        else
        {
            if (!netif && !ip6_addr_isany(&Dest) && !ip6_addr_islinklocal(&Dest))
                netif = Udp6Route(IP6_ADDR_ANY6, &Dest);
            Selected = netif ? ip6_select_source_address(netif, &Dest) : NULL;
            if (Selected)
                ip6_addr_copy(Source, *ip_2_ip6(Selected));
            else
                netif = NULL;
        }

        if (netif && !ip6_addr_isany(&Dest))
        {
            Icmp = p->payload;
            Icmp[0] = 128;
            Icmp[1] = 0;
            Icmp[2] = Icmp[3] = 0;
            RtlCopyMemory(Icmp + 4, &E->Ident, sizeof(E->Ident));
            RtlCopyMemory(Icmp + 6, &E->Seq, sizeof(E->Seq));
            *(u16_t *)(Icmp + 2) = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->tot_len, &Source, &Dest);
            Result = ip6_output_if(p, &Source, &Dest, Req.Ttl ? (u8_t)min(Req.Ttl, 255) : 128, 0,
                                   IP6_NEXTH_ICMP6, netif);
        }
    }
    else
    {
        Result = ERR_MEM;
    }
    if (p)
        pbuf_free(p);
    if (Data)
        pbuf_free(Data);
    UNLOCK_TCPIP_CORE();

    /* Not sent (no route, no memory): answered now. One that waits for neighbour discovery is outstanding */
    if (Result != ERR_OK && Result != ERR_INPROGRESS)
    {
        KeAcquireSpinLock(&Echo6Lock, &OldIrql);
        if (E->State == ECHO6_PENDING)
        {
            E->State = ECHO6_ANSWERED;
            E->Status = (Result == ERR_MEM || Result == ERR_BUF) ? IP_NO_RESOURCES : ECHO6_NO_ROUTE;
            RemoveEntryList(&E->Entry);
            InsertTailList(&Echo6Done, &E->Entry);
        }
        KeReleaseSpinLock(&Echo6Lock, OldIrql);
    }

    /* Anything the send answered at once (loopback answers come later, from the loopback worker) */
    Echo6CompleteDone();
    return STATUS_PENDING;
}

VOID
Echo6Startup(VOID)
{
    KeInitializeSpinLock(&Echo6Lock);
}
