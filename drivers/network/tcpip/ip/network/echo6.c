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
/* Listed (so that it counts against the caps) but the IRP is not yet pending and the timer not set: nothing
   answers it, finishes it or finds it yet */
#define ECHO6_NEW               4
/* Status of a request that could not be sent for want of a route */
#define ECHO6_NO_ROUTE          0xFFFFFFFF
/* The largest echo data lwIP sends in one datagram (its 16-bit length holds the IPv6 and ICMPv6 headers too) */
#define ECHO6_MAX_DATA          (0xFFFF - 40 - 8)
#define ECHO6_MAX_ROOM          0x10000
/* Outstanding requests: the record of each pins up to ECHO6_MAX_ROOM bytes of reply room and lives until the
   answer, the timeout or the cancel. A process gets 512 at once, the system 4096 (the most one user can pin is
   then 512 records, and all together at most 4096 * 64 KB when every request asks for 64 KB of data; an
   ordinary caller has a handful). The one that goes over gets STATUS_INSUFFICIENT_RESOURCES, as for want of
   memory. Windows' limits are not known (VERIFY ON ORACLE if it ever matters) */
#define ECHO6_MAX_PER_PROCESS   512
#define ECHO6_MAX_SYSTEM        4096
/* The requests wait in hash buckets of their sequence number, which counts up: an inbound ICMPv6 packet looks at
   one bucket (a handful of records at the caps), not at every outstanding request */
#define ECHO6_BUCKETS           64

typedef struct _ECHO6 {
    LIST_ENTRY Entry;           /* Echo6Pending, then Echo6Done */
    LONG Refs;
    LONG State;
    PIRP Irp;
    USHORT Ident;               /* as in the packet */
    USHORT Seq;
    UCHAR Dst[16];
    ULONGLONG Start;
    PEPROCESS Process;          /* the requestor: only compared, never dereferenced */
    KTIMER Timer;
    KDPC Dpc;
    ULONG Status;               /* IP_xxx */
    UCHAR From[16];
    ULONG FromScope;
    ULONG Room;                 /* reply data the caller's buffer takes */
    ULONG DataLen;
    UCHAR Data[ANYSIZE_ARRAY];
} ECHO6, *PECHO6;

static LIST_ENTRY Echo6Pending[ECHO6_BUCKETS];
static volatile LONG Echo6Count;        /* the requests on Echo6Pending, changed under Echo6Lock */
static LIST_ENTRY Echo6Done = { &Echo6Done, &Echo6Done };
static KSPIN_LOCK Echo6Lock;
static volatile LONG Echo6Counter;

PDEVICE_OBJECT Ip6DeviceObject = NULL;

/* udp6.c */
struct netif *Udp6NetifOfIndex(ULONG IfIndex);
struct netif *Udp6DefaultMulticastNetif(VOID);
struct netif *Udp6Route(const ip6_addr_t *Src, const ip6_addr_t *Dest);

#define ECHO6_BUCKET(Seq)       (&Echo6Pending[(USHORT)(Seq) % ECHO6_BUCKETS])

/* Takes a request off the pending buckets (Echo6Lock held; it is on them) */
static
VOID
Echo6Unlink(PECHO6 E)
{
    RemoveEntryList(&E->Entry);
    InterlockedDecrement(&Echo6Count);
}

/* Puts a new request on the pending buckets unless the system or its process has too many (Echo6Lock held) */
static
BOOLEAN
Echo6Insert(PECHO6 E)
{
    if (Echo6Count >= ECHO6_MAX_SYSTEM)
        return FALSE;

    /* The count of a process is looked for only when it could be over the cap */
    if (Echo6Count >= ECHO6_MAX_PER_PROCESS)
    {
        ULONG Mine = 0, i;
        PLIST_ENTRY Entry;

        for (i = 0; i < ECHO6_BUCKETS; i++)
        {
            for (Entry = Echo6Pending[i].Flink; Entry != &Echo6Pending[i]; Entry = Entry->Flink)
            {
                if (CONTAINING_RECORD(Entry, ECHO6, Entry)->Process == E->Process)
                    Mine++;
            }
        }
        if (Mine >= ECHO6_MAX_PER_PROCESS)
            return FALSE;
    }

    InsertTailList(ECHO6_BUCKET(E->Seq), &E->Entry);
    InterlockedIncrement(&Echo6Count);
    return TRUE;
}

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
        Echo6Unlink(E);
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

    /* A reference first, while the cancel spin lock is held: the request's own reference is dropped only by
       Echo6Complete, which takes the cancel spin lock before it can get that far. Once the lock is released a
       completion on another processor may run to the end and free the record under this routine */
    InterlockedIncrement(&E->Refs);
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    if (E->State == ECHO6_PENDING)
    {
        E->State = ECHO6_CANCELLED;
        Echo6Unlink(E);
        Won = TRUE;
    }
    KeReleaseSpinLock(&Echo6Lock, OldIrql);

    if (Won)
        Echo6Complete(E);
    Echo6Release(E);
}

/* The outstanding request with this identifier and sequence (as in the packet) to Peer (Echo6Lock held) */
static
PECHO6
Echo6Find(const UCHAR *Peer, USHORT Ident, USHORT Seq)
{
    PLIST_ENTRY Head = ECHO6_BUCKET(Seq), Entry;

    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        PECHO6 E = CONTAINING_RECORD(Entry, ECHO6, Entry);

        if (E->State == ECHO6_PENDING && E->Ident == Ident && E->Seq == Seq &&
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

    if (Avail < 8 || Echo6Count == 0)
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

    if (Echo6Count == 0 || !Echo6Invoking(Icmp, Avail, &Ident, &Seq))
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

    if (Echo6Count == 0 || p->tot_len < 8)
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
        /* The same for an error: it completes the request before lwIP looks at it */
        if (ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->tot_len, Src, ip6_current_dest_addr()) != 0)
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
            Echo6Unlink(E);
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
    BOOLEAN HasSource = FALSE, Inserted;
    ip6_addr_t Dest, Source;
    const ip_addr_t *Selected;
    struct netif *netif = NULL;
    struct pbuf *p = NULL, *Data = NULL;
    PUCHAR Icmp;
    PECHO6 E;
    PUCHAR Payload = NULL;
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
    /* A reply carries the data of its request back: no more room is kept than that (a request with no data
       keeps none; an error answer has none either) */
    Room = min(min(OutLen - sizeof(ICMPV6_ECHO_REPLY), ECHO6_MAX_ROOM), DataSize);

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

    /* The echo data is taken from the caller's system buffer now: once the request is outstanding it can be
       completed at any moment (a timer of a millisecond, a cancel) and the buffer is then the I/O manager's */
    if (DataSize)
    {
        Payload = ExAllocatePoolWithTag(NonPagedPool, DataSize, ECHO6_TAG);
        if (!Payload)
            return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(Payload, In + 1, DataSize);
    }

    E = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(ECHO6, Data[Room ? Room : 1]), ECHO6_TAG);
    if (!E)
    {
        if (Payload)
            ExFreePoolWithTag(Payload, ECHO6_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(E, FIELD_OFFSET(ECHO6, Data));
    /* The request, the timer, and this routine until it returns: the request may be completed (timer, cancel,
       answer) and the record freed while this routine still reads and updates it */
    E->Refs = 3;
    E->State = ECHO6_NEW;
    E->Irp = Irp;
    E->Process = IoGetCurrentProcess();
    E->Room = Room;
    Counter = (ULONG)InterlockedIncrement(&Echo6Counter);
    E->Ident = (USHORT)(0x4E36 ^ (Counter >> 16));
    E->Seq = (USHORT)Counter;
    RtlCopyMemory(E->Dst, Req.DestinationAddress.sin6_addr, sizeof(E->Dst));
    KeInitializeTimer(&E->Timer);
    KeInitializeDpc(&E->Dpc, Echo6Timeout, E);
    Irp->Tail.Overlay.DriverContext[0] = E;

    /* Too many outstanding (this process, or all together): refused before anything is published */
    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    Inserted = Echo6Insert(E);
    KeReleaseSpinLock(&Echo6Lock, OldIrql);
    if (!Inserted)
    {
        if (Payload)
            ExFreePoolWithTag(Payload, ECHO6_TAG);
        ExFreePoolWithTag(E, ECHO6_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Outstanding from here on: the timer, the cancel routine and the list may each finish it */
    IoMarkIrpPending(Irp);
    Timeout = Req.Timeout ? Req.Timeout : 1;
    if (Timeout > 0x7FFFFFFF / 10000)
        Timeout = 0x7FFFFFFF / 10000;
    Due.QuadPart = -(LONGLONG)Timeout * 10000;
    E->Start = KeQueryInterruptTime();

    /* Findable and finishable from here; the timer last, so that its DPC finds the request PENDING */
    KeAcquireSpinLock(&Echo6Lock, &OldIrql);
    E->State = ECHO6_PENDING;
    KeReleaseSpinLock(&Echo6Lock, OldIrql);
    KeSetTimer(&E->Timer, Due, &E->Dpc);

    IoAcquireCancelSpinLock(&OldIrql);
    IoSetCancelRoutine(Irp, Echo6Cancel);
    if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL))
    {
        IoReleaseCancelSpinLock(OldIrql);
        KeAcquireSpinLock(&Echo6Lock, &OldIrql);
        if (E->State == ECHO6_PENDING)
        {
            E->State = ECHO6_CANCELLED;
            Echo6Unlink(E);
            KeReleaseSpinLock(&Echo6Lock, OldIrql);
            Echo6Complete(E);
        }
        else
        {
            KeReleaseSpinLock(&Echo6Lock, OldIrql);
        }
        if (Payload)
            ExFreePoolWithTag(Payload, ECHO6_TAG);
        Echo6Release(E);
        return STATUS_PENDING;
    }
    IoReleaseCancelSpinLock(OldIrql);

    LOCK_TCPIP_CORE();

    p = pbuf_alloc(PBUF_IP, 8, PBUF_RAM);
    Data = DataSize ? pbuf_alloc(PBUF_RAW, (u16_t)DataSize, PBUF_RAM) : NULL;
    if (p && (!DataSize || (Data && pbuf_take(Data, Payload, (u16_t)DataSize) == ERR_OK)))
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
            Echo6Unlink(E);
            InsertTailList(&Echo6Done, &E->Entry);
        }
        KeReleaseSpinLock(&Echo6Lock, OldIrql);
    }

    /* Anything the send answered at once (loopback answers come later, from the loopback worker) */
    Echo6CompleteDone();
    if (Payload)
        ExFreePoolWithTag(Payload, ECHO6_TAG);
    Echo6Release(E);
    return STATUS_PENDING;
}

VOID
Echo6Startup(VOID)
{
    ULONG i;

    for (i = 0; i < ECHO6_BUCKETS; i++)
        InitializeListHead(&Echo6Pending[i]);
    KeInitializeSpinLock(&Echo6Lock);
}
