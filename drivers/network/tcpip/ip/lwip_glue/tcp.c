#include <debug.h>
#include <lwip/tcpip.h>

#include "lwip_glue.h"

/* tcp_process_refused_data hands over data held while a connection waited to be accepted */
#include <lwip/priv/tcp_priv.h>
#include <lwip/inet_chksum.h>
#include <lwip_hooks.h>

static const char * const tcp_state_str[] = {
  "CLOSED",
  "LISTEN",
  "SYN_SENT",
  "SYN_RCVD",
  "ESTABLISHED",
  "FIN_WAIT_1",
  "FIN_WAIT_2",
  "CLOSE_WAIT",
  "CLOSING",
  "LAST_ACK",
  "TIME_WAIT"
};

/* The way that lwIP does multi-threading is really not ideal for our purposes but
 * we best go along with it unless we want another unstable TCP library. lwIP uses
 * a thread called the "tcpip thread" which is the only one allowed to call raw API
 * functions. Since this is the case, for each of our LibTCP* functions, we queue a request
 * for a callback to "tcpip thread" which calls our LibTCP*Callback functions. Yes, this is
 * a lot of unnecessary thread swapping and it could definitely be faster, but I don't want
 * to going messing around in lwIP because I have no desire to create another mess like oskittcp
 *
 * lwIP's core locking (LOCK_TCPIP_CORE) lets any thread call the raw API while it holds the core
 * lock, as the tcpip thread does while it runs these callbacks. Sends and received packets use it
 * to stay on their own threads; the other requests still go through the tcpip thread. */

extern KEVENT TerminationEvent;
extern NPAGED_LOOKASIDE_LIST MessageLookasideList;
extern NPAGED_LOOKASIDE_LIST QueueEntryLookasideList;

/* Required for ERR_T to NTSTATUS translation in receive error handling */
NTSTATUS TCPTranslateError(const err_t err);

void
LibTCPDumpPcb(PVOID SocketContext)
{
    struct tcp_pcb *pcb = (struct tcp_pcb*)SocketContext;
    unsigned int addr = lwip_ntohl(pcb->remote_ip.addr);

    DbgPrint("\tState: %s\n", tcp_state_str[pcb->state]);
    DbgPrint("\tRemote: (%d.%d.%d.%d, %d)\n",
    (addr >> 24) & 0xFF,
    (addr >> 16) & 0xFF,
    (addr >> 8) & 0xFF,
    addr & 0xFF,
    pcb->remote_port);
}

static
void
LibTCPEmptyQueue(PCONNECTION_ENDPOINT Connection)
{
    PLIST_ENTRY Entry;
    PQUEUE_ENTRY qp = NULL;

    ReferenceObject(Connection);

    while (!IsListEmpty(&Connection->PacketQueue))
    {
        Entry = RemoveHeadList(&Connection->PacketQueue);
        qp = CONTAINING_RECORD(Entry, QUEUE_ENTRY, ListEntry);

        /* We're in the tcpip thread here so this is safe */
        pbuf_free(qp->p);

        ExFreeToNPagedLookasideList(&QueueEntryLookasideList, qp);
    }

    DereferenceObject(Connection);
}

err_t LibTCPEnqueuePacket(PCONNECTION_ENDPOINT Connection, struct pbuf *p, ULONG PreCredit)
{
    PQUEUE_ENTRY qp;

    qp = (PQUEUE_ENTRY)ExAllocateFromNPagedLookasideList(&QueueEntryLookasideList);
    if (!qp)
        return ERR_MEM;

    qp->p = p;
    qp->Offset = 0;

    LockObject(Connection);
    InsertTailList(&Connection->PacketQueue, &qp->ListEntry);
    Connection->RecvQueued += p->tot_len;
    Connection->PreCredited += PreCredit;
    UnlockObject(Connection);

    return ERR_OK;
}

PQUEUE_ENTRY LibTCPDequeuePacket(PCONNECTION_ENDPOINT Connection)
{
    PLIST_ENTRY Entry;
    PQUEUE_ENTRY qp = NULL;

    if (IsListEmpty(&Connection->PacketQueue)) return NULL;

    Entry = RemoveHeadList(&Connection->PacketQueue);

    qp = CONTAINING_RECORD(Entry, QUEUE_ENTRY, ListEntry);

    return qp;
}

NTSTATUS LibTCPGetDataFromConnectionQueue(PCONNECTION_ENDPOINT Connection, PUCHAR RecvBuffer, UINT RecvLen, UINT *Received)
{
    PQUEUE_ENTRY qp;
    struct pbuf* p;
    NTSTATUS Status;
    UINT ReadLength, PayloadLength, Offset, Copied;

    (*Received) = 0;

    LockObject(Connection);

    if (!IsListEmpty(&Connection->PacketQueue))
    {
        while ((qp = LibTCPDequeuePacket(Connection)) != NULL)
        {
            p = qp->p;

            /* Calculate the payload length first */
            PayloadLength = p->tot_len;
            PayloadLength -= qp->Offset;
            Offset = qp->Offset;

            /* Check if we're reading the whole buffer */
            ReadLength = MIN(PayloadLength, RecvLen);
            ASSERT(ReadLength != 0);
            if (ReadLength != PayloadLength)
            {
                /* Save this one for later */
                qp->Offset += ReadLength;
                InsertHeadList(&Connection->PacketQueue, &qp->ListEntry);
                qp = NULL;
            }

            Copied = pbuf_copy_partial(p, RecvBuffer, ReadLength, Offset);
            ASSERT(Copied == ReadLength);

            /* Update trackers */
            RecvLen -= ReadLength;
            RecvBuffer += ReadLength;
            (*Received) += ReadLength;
            /* what was acknowledged on arrival (PreCredited) is not credited again */
            {
                ULONG Pre = min(ReadLength, Connection->PreCredited);

                Connection->PreCredited -= Pre;
                Connection->RecvCredit += ReadLength - Pre;
            }
            Connection->RecvQueued -= (Connection->RecvQueued < ReadLength) ? Connection->RecvQueued : ReadLength;
            Connection->Consumed += ReadLength;

            if (qp != NULL)
            {
                /* lwIP's memory functions may be called from any thread (SYS_LIGHTWEIGHT_PROT);
                 * the segment is ours since the receive callback took it */
                pbuf_free(qp->p);

                ExFreeToNPagedLookasideList(&QueueEntryLookasideList, qp);
            }
            else
            {
                /* If we get here, it means we've filled the buffer */
                ASSERT(RecvLen == 0);
            }

            ASSERT((*Received) != 0);
            Status = STATUS_SUCCESS;

            if (!RecvLen)
                break;
        }
    }
    else
    {
        if (Connection->ReceiveShutdown)
            Status = Connection->ReceiveShutdownStatus;
        else
            Status = STATUS_PENDING;
    }

    UnlockObject(Connection);

    return Status;
}

/* The receive window. It shrinks as segments arrive and grows again with tcp_recved(), which is called
 * for the bytes the owner has read (RecvCredit, counted when the queue is read), not for those that
 * arrived: an owner that stops reading closes the window and the sender stalls once its share of the
 * buffer is full. The window of a connection is at most tcp_pcb.rcv_wnd_max, set from SO_RCVBUF. */

/* A connection starts with 64K (TCP_WND_DEFAULT: all its SYN can announce, and a peer may use all of it), and
 * a window is not taken back once announced: the smallest window is that, whatever SO_RCVBUF asks for */
#define LIBTCP_MIN_WINDOW TCP_WND_DEFAULT

/* The window of a connection whose owner set no SO_RCVBUF: 2 MB. Windows takes about that from a sender
 * while the application does not read, although SO_RCVBUF reads 64K (measured on Windows 10 22H2) */
#define LIBTCP_DEFAULT_WINDOW 0x200000

/* What a peer without window scaling may have queued before its window closes */
#define LIBTCP_NOWS_QUEUE 0x4000000

/* Opens the receive window by Bytes (as far as the connection's largest window allows) and announces it
 * once: tcp_recved() announces after each call, so a long run of calls is a burst of window updates. The core
 * lock is held */
static
VOID
LibTCPOpenWindow(PCONNECTION_ENDPOINT Connection, PTCP_PCB pcb, ULONG Bytes)
{
    tcpwnd_size_t Room = TCP_WND_MAX(pcb) - pcb->rcv_wnd;

    if (pcb->rcv_wnd > TCP_WND_MAX(pcb))
        Room = 0;

    pcb->rcv_wnd += (tcpwnd_size_t)min(Bytes, Room);

    /* tcp_recved() would send a window update whenever the window has opened by a few segments. With a
     * large window the peer has room and the packet is waste (each one costs a guest exit: 20% of the speed
     * of a download); the update goes out on the next acknowledgement. It is sent when what the peer was told
     * is less than half of the largest window, the window being nearly shut or small */
    {
        tcpwnd_size_t Max = TCP_WND_MAX(pcb);
        u32_t Inflation = tcp_update_rcv_ann_wnd(pcb);
        u32_t Left = TCP_SEQ_GT(pcb->rcv_ann_right_edge, pcb->rcv_nxt) ? pcb->rcv_ann_right_edge - pcb->rcv_nxt : 0;

        if (Inflation >= LWIP_MIN(TCP_WND_UPDATE_THRESHOLD, Max / 2) && Left < Max / 2)
        {
            tcp_ack_now(pcb);
            tcp_output(pcb);
        }
    }

    Connection->RecvWndNow = pcb->rcv_wnd;
    Connection->RecvWndMax = TCP_WND_MAX(pcb);
}

/* The core lock is held */
static
VOID
LibTCPReturnCreditLocked(PCONNECTION_ENDPOINT Connection)
{
    PTCP_PCB pcb;
    ULONG Credit;

    LockObject(Connection);
    pcb = Connection->SocketContext;
    Credit = Connection->RecvCredit;
    Connection->RecvCredit = 0;
    UnlockObject(Connection);

    /* No PCB: the connection is over, nothing is announced any more */
    if (!pcb || !Credit)
        return;

    LibTCPOpenWindow(Connection, pcb, Credit);
}

static
void
LibTCPReturnCreditCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    PCONNECTION_ENDPOINT Connection = msg->Input.Socket.Arg;

    LibTCPReturnCreditLocked(Connection);

    DereferenceObject(Connection);
    ExFreeToNPagedLookasideList(&MessageLookasideList, msg);
}

/* Gives lwIP the window of the bytes read from the queue. Called after the object lock is released,
 * from any thread that reads the queue (on the tcpip thread the core lock is already held) */
VOID
LibTCPReturnReceiveCredit(PCONNECTION_ENDPOINT Connection)
{
    struct lwip_callback_msg *msg;

    if (!Connection->RecvCredit)
        return;

    /* A reader that takes the core lock while the segments of a burst arrive waits for the receive worker,
     * which holds it for every one of them: the reader stalls for tens of milliseconds to a second, and with
     * it the window (a 200 MB download to a file ran 25% slower than before the window closed). While the
     * window is mostly open the credit waits for the next segment, which returns it under the lock the worker
     * has anyway; a window that is half shut or less is reopened by the reader. At the close of the connection
     * what is left is returned (LibTCPCloseCallback, LibTCPShutdownCallback). */
    if (!sys_tcpip_core_locked() && Connection->RecvWndMax && Connection->RecvWndNow > Connection->RecvWndMax / 2)
        return;

    if (sys_tcpip_core_locked())
    {
        LibTCPReturnCreditLocked(Connection);
    }
    else if (KeGetCurrentIrql() <= APC_LEVEL)
    {
        LOCK_TCPIP_CORE();
        LibTCPReturnCreditLocked(Connection);
        UNLOCK_TCPIP_CORE();
    }
    else
    {
        /* Too high for the core lock: the tcpip thread does it */
        msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
        if (!msg)
            return; /* the credit stays and goes out with the next read */

        ReferenceObject(Connection);
        msg->Input.Socket.Arg = Connection;
        if (tcpip_callback_with_block(LibTCPReturnCreditCallback, msg, 0) != ERR_OK)
        {
            DereferenceObject(Connection);
            ExFreeToNPagedLookasideList(&MessageLookasideList, msg);
        }
    }
}

/* Sets the largest receive window of an established connection (SO_RCVBUF, 0 for the default); PASSIVE_LEVEL.
 * A larger window is announced at once. A smaller one (a later SO_RCVBUF below an earlier one) cuts the window
 * left now to it; what the peer sent inside the old window and is still on its way is then dropped and sent
 * again */
NTSTATUS
LibTCPSetReceiveWindow(PCONNECTION_ENDPOINT Connection, ULONG Size)
{
    PTCP_PCB pcb;
    tcpwnd_size_t Old, New;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOLEAN Locked = sys_tcpip_core_locked();

    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_UNSUCCESSFUL;

    Connection->AutoTune = (Size == 0);
    if (Size == 0)
        Size = LIBTCP_DEFAULT_WINDOW;
    else if (Size < LIBTCP_MIN_WINDOW)
        Size = LIBTCP_MIN_WINDOW;
    if (Size > TCP_WND)
        Size = TCP_WND;

    if (!Locked)
        LOCK_TCPIP_CORE();

    LockObject(Connection);
    pcb = Connection->SocketContext;
    UnlockObject(Connection);

    if (pcb && pcb->state != LISTEN)
    {
        /* What the peer can use: without window scaling the window stays below 64K whatever the limit */
        Old = TCP_WND_MAX(pcb);
        pcb->rcv_wnd_max = Size;
        New = TCP_WND_MAX(pcb);

        if (New > Old)
        {
            LibTCPOpenWindow(Connection, pcb, New - Old);
        }
        else if (New < Old && pcb->rcv_wnd > New)
        {
            pcb->rcv_wnd = New;
        }

        Status = STATUS_SUCCESS;
    }

    if (!Locked)
        UNLOCK_TCPIP_CORE();

    return Status;
}

static
BOOLEAN
WaitForEventSafely(PRKEVENT Event)
{
    PVOID WaitObjects[] = {Event, &TerminationEvent};

    if (KeWaitForMultipleObjects(2,
                                 WaitObjects,
                                 WaitAny,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL,
                                 NULL) == STATUS_WAIT_0)
    {
        /* Signalled by the caller's event */
        return TRUE;
    }
    else /* if KeWaitForMultipleObjects() == STATUS_WAIT_1 */
    {
        /* Signalled by our termination event */
        return FALSE;
    }
}

static
err_t
InternalSendEventHandler(void *arg, PTCP_PCB pcb, const u16_t space)
{
    /* Make sure the socket didn't get closed */
    if (!arg) return ERR_OK;

    TCPSendEventHandler(arg, space);

    return ERR_OK;
}

static
err_t
InternalRecvEventHandler(void *arg, PTCP_PCB pcb, struct pbuf *p, const err_t err)
{
    PCONNECTION_ENDPOINT Connection = arg;

    /* Make sure the socket didn't get closed */
    if (!arg)
    {
        if (p)
            pbuf_free(p);

        return ERR_OK;
    }

    if (p)
    {
        /* On lookaside exhaustion let lwIP keep the pbuf and retry later
         * instead of dereferencing a NULL queue entry */
        {
            /* Without window scaling the peer'"'"'s window is 64K and the window closes at every stall of the reader
             * (a file write of 0.3 s): the data is acknowledged on arrival, as it was before the window closed,
             * while at most LIBTCP_NOWS_QUEUE are queued */
            ULONG Length = p->tot_len;
            ULONG Pre = (!(pcb->flags & TF_WND_SCALE) && Connection->RecvQueued < LIBTCP_NOWS_QUEUE) ? Length : 0;

            if (LibTCPEnqueuePacket(Connection, p, Pre) != ERR_OK)
                return ERR_MEM;

            if (Pre)
                LibTCPOpenWindow(Connection, pcb, Pre);
        }

        /* A peer on this machine gets every segment acknowledged at once. lwIP acknowledges every second
         * segment and the odd one after a timer tick; the sender's Nagle rule holds the short last segment of a
         * write back until everything before it is acknowledged, so a program that waits for its data before
         * it writes more (one 8K write is five full segments and a short one) waits a tick per write: 2 MB/s
         * for a loopback loop that does 50 MB/s when the window update of every segment used to acknowledge
         * it. Where the round trip costs nothing the extra packet is free */
        if (ip4_addr_isloopback(&pcb->remote_ip) || ip4_addr_cmp(&pcb->remote_ip, &pcb->local_ip))
            tcp_ack_now(pcb);

        /* Autotuning, as Windows does (the same default socket took 2.7 MB from a sender that did not read and
         * 6.9 MB after it had read 64 MB): when the window shuts while the owner reads, the owner is slower
         * than the peer for a while (a download written to a file stalls for 0.3 to 1.7 s at a time), and the
         * window doubles, up to TCP_WND (32 MB). Before the window shut, such stalls were hidden by a queue
         * without limit: a 200 MB download ran 30% slower with a 2 MB window and as fast as before with a
         * 32 MB one. An owner that does not read gets no more. A SO_RCVBUF is kept as asked, as on Windows. */
        if (Connection->AutoTune && (pcb->flags & TF_WND_SCALE) && pcb->rcv_wnd < 2 * TCP_MSS &&
            Connection->Consumed != Connection->AutoSeen && pcb->rcv_wnd_max < TCP_WND)
        {
            ULONG Old = pcb->rcv_wnd_max;

            Connection->AutoSeen = Connection->Consumed;
            pcb->rcv_wnd_max = min(Old * 2, (ULONG)TCP_WND);
            LibTCPOpenWindow(Connection, pcb, pcb->rcv_wnd_max - Old);
        }

        Connection->RecvWndNow = pcb->rcv_wnd;
        Connection->RecvWndMax = TCP_WND_MAX(pcb);

        /* The window is given back as the data is read (LibTCPReturnReceiveCredit), not now:
         * a reader that stops reading closes the window, as on Windows */
        TCPRecvEventHandler(arg);
    }
    else if (err == ERR_OK)
    {
        /* Complete pending reads with 0 bytes to indicate a graceful closure,
         * but note that send is still possible in this state so we don't close the
         * whole socket here (by calling tcp_close()) as that would violate TCP specs
         */
        Connection->ReceiveShutdown = TRUE;
        Connection->ReceiveShutdownStatus = STATUS_SUCCESS;

        /* If we already did a send shutdown, we're in TIME_WAIT so we can't use this PCB anymore */
        if (Connection->SendShutdown)
        {
            Connection->SocketContext = NULL;
            tcp_arg(pcb, NULL);
        }

        /* Indicate the graceful close event */
        TCPRecvEventHandler(arg);

        /* If the PCB is gone, clean up the connection */
        if (Connection->SendShutdown)
        {
            TCPFinEventHandler(Connection, ERR_CLSD);
        }
    }

    return ERR_OK;
}

/* A SYN whose sequence number is above everything the previous connection on its 4-tuple received may
 * reopen that connection from TIME-WAIT (the sequence-number rule of RFC 6191), when the new initial
 * sequence number is above everything the old connection sent (RFC 1122 4.2.2.13). lwIP answers such a
 * SYN with an ACK (or a reset, inside the old receive window) for the whole of TIME-WAIT
 * (2 * TCP_MSL), so a client that reuses its port within that time cannot connect. The timestamp rule
 * of RFC 6191 is not used: lwIP does not reject old segments by their timestamps (PAWS), so only the
 * sequence numbers keep the two connections apart */

/* What an ended TIME-WAIT still protects until the new connection is accepted or the time it had left
   has passed: no SYN at or below the old receive sequence gets through, and no open of the 4-tuple
   starts below the old send sequence, even after an attempt to open the new connection fails */
typedef struct _TIME_WAIT_REOPEN
{
    LIST_ENTRY ListEntry;
    ip4_addr_t LocalIp;
    ip4_addr_t RemoteIp;
    u16_t LocalPort;
    u16_t RemotePort;
    u32_t RcvNxt;
    u32_t IssFloor;
    /* Interrupt time: tcp_ticks stops when lwIP has no active or TIME-WAIT PCB, and the system time
       can be set */
    ULONGLONG Expires;
} TIME_WAIT_REOPEN, *PTIME_WAIT_REOPEN;

/* Beyond this, a SYN finds the TIME-WAIT as before */
#define MAX_TIME_WAIT_REOPENS 4096

static LIST_ENTRY TimeWaitReopens = { &TimeWaitReopens, &TimeWaitReopens };
static ULONG TimeWaitReopenCount;

static
VOID
LibTCPFreeReopen(PTIME_WAIT_REOPEN Reopen)
{
    RemoveEntryList(&Reopen->ListEntry);
    TimeWaitReopenCount--;
    ExFreePoolWithTag(Reopen, LWIP_REOPEN_TAG);
}

/* The record of a 4-tuple; frees the records whose time has passed */
static
PTIME_WAIT_REOPEN
LibTCPFindReopen(const ip4_addr_t *LocalIp, u16_t LocalPort, const ip4_addr_t *RemoteIp, u16_t RemotePort)
{
    PLIST_ENTRY Entry, Next;
    PTIME_WAIT_REOPEN Reopen, Found = NULL;
    ULONGLONG Now = KeQueryInterruptTime();

    for (Entry = TimeWaitReopens.Flink; Entry != &TimeWaitReopens; Entry = Next)
    {
        Next = Entry->Flink;
        Reopen = CONTAINING_RECORD(Entry, TIME_WAIT_REOPEN, ListEntry);
        if (Now >= Reopen->Expires)
        {
            LibTCPFreeReopen(Reopen);
            continue;
        }
        if (!Found && Reopen->LocalPort == LocalPort && Reopen->RemotePort == RemotePort &&
            ip4_addr_eq(&Reopen->LocalIp, LocalIp) && ip4_addr_eq(&Reopen->RemoteIp, RemoteIp))
        {
            Found = Reopen;
        }
    }
    return Found;
}

/* Called by LibIPShutdown once lwIP has stopped */
VOID
LibTCPFreeTimeWaitReopens(VOID)
{
    while (!IsListEmpty(&TimeWaitReopens))
        LibTCPFreeReopen(CONTAINING_RECORD(TimeWaitReopens.Flink, TIME_WAIT_REOPEN, ListEntry));
}

static
u16_t
LibTCPSegmentChecksum(const ip4_addr_t *Src, const ip4_addr_t *Dest, const void *Segment, u16_t Length)
{
    /* inet_chksum returns the complement of the sum */
    u32_t Sum = (u16_t)~inet_chksum(Segment, Length);

    Sum += (ip4_addr_get_u32(Src) & 0xFFFF) + (ip4_addr_get_u32(Src) >> 16);
    Sum += (ip4_addr_get_u32(Dest) & 0xFFFF) + (ip4_addr_get_u32(Dest) >> 16);
    Sum += lwip_htons(IP_PROTO_TCP) + lwip_htons(Length);
    Sum = FOLD_U32T(Sum);
    Sum = FOLD_U32T(Sum);
    return (u16_t)~Sum;
}

/* Whether the listener that tcp_input would choose can take a new connection */
static
BOOLEAN
LibTCPListenerHasRoom(const ip4_addr_t *Dest, u16_t Port, struct netif *inp)
{
    struct tcp_pcb_listen *lpcb, *Any = NULL;

    for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next)
    {
        if ((lpcb->netif_idx != NETIF_NO_INDEX && lpcb->netif_idx != netif_get_index(inp)) ||
            lpcb->local_port != Port)
        {
            continue;
        }
        if (ip_addr_isany(&lpcb->local_ip))
            Any = lpcb;
        else if (IP_IS_V4_VAL(lpcb->local_ip) && ip4_addr_eq(ip_2_ip4(&lpcb->local_ip), Dest))
            break;
    }
    if (!lpcb)
        lpcb = Any;
    if (!lpcb)
        return FALSE;
#if TCP_LISTEN_BACKLOG
    return lpcb->accepts_pending < lpcb->backlog;
#else
    return TRUE;
#endif
}

/* LWIP_HOOK_IP4_INPUT: runs under the core lock before lwIP looks at the packet; consumes only a SYN
   that an ended TIME-WAIT still refuses */
int
LibTCPReopenTimeWait(struct pbuf *p, struct netif *inp)
{
    const struct ip_hdr *IpHeader = p->payload;
    const struct tcp_hdr *TcpHeader;
    struct tcp_pcb *pcb;
    PTIME_WAIT_REOPEN Reopen;
    ip4_addr_t Src, Dest;
    u16_t IpHeaderLength, IpLength, TcpHeaderLength, SrcPort, DestPort;
    u32_t SeqNo, Age;
    ULONGLONG Expires;
    u8_t Flags;

    /* Only an unfragmented SYN that the first buffer holds whole */
    if (p->len < IP_HLEN || IPH_V(IpHeader) != 4 || IPH_PROTO(IpHeader) != IP_PROTO_TCP ||
        (IPH_OFFSET(IpHeader) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0)
    {
        return 0;
    }
    IpHeaderLength = IPH_HL_BYTES(IpHeader);
    IpLength = lwip_ntohs(IPH_LEN(IpHeader));
    if (IpHeaderLength < IP_HLEN || IpLength > p->len || IpLength < IpHeaderLength + TCP_HLEN)
        return 0;
    TcpHeader = (const struct tcp_hdr *)((const u8_t *)IpHeader + IpHeaderLength);
    TcpHeaderLength = TCPH_HDRLEN_BYTES(TcpHeader);
    Flags = TCPH_FLAGS(TcpHeader);
    /* Every segment that tcp_listen_input takes for a SYN */
    if (!(Flags & TCP_SYN) || (Flags & (TCP_RST | TCP_ACK)) ||
        TcpHeaderLength < TCP_HLEN || TcpHeaderLength > IpLength - IpHeaderLength)
    {
        return 0;
    }

    ip4_addr_copy(Src, IpHeader->src);
    ip4_addr_copy(Dest, IpHeader->dest);
    SrcPort = lwip_ntohs(TcpHeader->src);
    DestPort = lwip_ntohs(TcpHeader->dest);
    SeqNo = lwip_ntohl(TcpHeader->seqno);
    Reopen = LibTCPFindReopen(&Dest, DestPort, &Src, SrcPort);

    /* The same match as tcp_input's */
    for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next)
    {
        if (pcb->netif_idx != NETIF_NO_INDEX && pcb->netif_idx != netif_get_index(inp))
            continue;
        if (pcb->remote_port == SrcPort && pcb->local_port == DestPort &&
            IP_IS_V4_VAL(pcb->remote_ip) && ip4_addr_eq(ip_2_ip4(&pcb->remote_ip), &Src) &&
            ip4_addr_eq(ip_2_ip4(&pcb->local_ip), &Dest))
        {
            break;
        }
    }
    if (!pcb)
    {
        /* RFC 6191 drops a SYN that may not reopen the connection */
        if (Reopen && !TCP_SEQ_GT(SeqNo, Reopen->RcvNxt))
        {
            pbuf_free(p);
            return 1;
        }
        return 0;
    }

    /* Only a plain SYN that ip4_input delivers on this interface (to its address, from a unicast
       source), above the old receive sequences (this TIME-WAIT's and an older record's), ends a
       TIME-WAIT */
    if (Flags != TCP_SYN || !netif_is_up(inp) ||
        (!ip4_addr_eq(&Dest, netif_ip4_addr(inp)) &&
         !(ip4_addr_isloopback(&Dest) && ip4_addr_isloopback(netif_ip4_addr(inp)))) ||
        ip4_addr_isbroadcast(&Src, inp) || ip4_addr_ismulticast(&Src) ||
        !TCP_SEQ_GT(SeqNo, pcb->rcv_nxt) || (Reopen && !TCP_SEQ_GT(SeqNo, Reopen->RcvNxt)))
    {
        return 0;
    }

    /* Only a segment lwIP would accept may end the TIME-WAIT */
#if CHECKSUM_CHECK_IP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP)
    {
        if (inet_chksum(IpHeader, IpHeaderLength) != 0)
            return 0;
    }
#endif
#if CHECKSUM_CHECK_TCP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP)
    {
        if (LibTCPSegmentChecksum(&Src, &Dest, TcpHeader, IpLength - IpHeaderLength) != 0)
            return 0;
    }
#endif

    /* Without a listener that takes the SYN, the TIME-WAIT stays and answers it as before */
    if (!LibTCPListenerHasRoom(&Dest, DestPort, inp))
        return 0;

    /* The time the TIME-WAIT has left, rounded up: tcp_slowtmr ends it once its age in ticks is above
       2 * TCP_MSL / TCP_SLOW_INTERVAL; interrupt time counts 100 ns units */
    Age = (u32_t)(tcp_ticks - pcb->tmr);
    if (Age > 2 * TCP_MSL / TCP_SLOW_INTERVAL)
        Age = 2 * TCP_MSL / TCP_SLOW_INTERVAL;
    Expires = KeQueryInterruptTime() +
              (ULONGLONG)(2 * TCP_MSL / TCP_SLOW_INTERVAL + 1 - Age) * TCP_SLOW_INTERVAL * 10000;
    if (!Reopen)
    {
        if (TimeWaitReopenCount >= MAX_TIME_WAIT_REOPENS)
            return 0;
        Reopen = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Reopen), LWIP_REOPEN_TAG);
        if (!Reopen)
            return 0;
        Reopen->LocalIp = Dest;
        Reopen->RemoteIp = Src;
        Reopen->LocalPort = DestPort;
        Reopen->RemotePort = SrcPort;
        Reopen->RcvNxt = pcb->rcv_nxt;
        Reopen->IssFloor = pcb->snd_nxt;
        Reopen->Expires = Expires;
        InsertTailList(&TimeWaitReopens, &Reopen->ListEntry);
        TimeWaitReopenCount++;
    }
    else
    {
        /* An older record keeps whichever limits are higher */
        if (TCP_SEQ_GT(pcb->rcv_nxt, Reopen->RcvNxt))
            Reopen->RcvNxt = pcb->rcv_nxt;
        if (TCP_SEQ_GT(pcb->snd_nxt, Reopen->IssFloor))
            Reopen->IssFloor = pcb->snd_nxt;
        if (Expires > Reopen->Expires)
            Reopen->Expires = Expires;
    }

    /* What lwIP does when the TIME-WAIT ends; the glue let go of the PCB when it entered TIME-WAIT.
       tcp_input then finds no PCB for the 4-tuple and gives the SYN to the listener; the record keeps
       the rest */
    tcp_pcb_remove(&tcp_tw_pcbs, pcb);
    tcp_free(pcb);
    return 0;
}

/* LWIP_HOOK_TCP_ISN: lwIP's own generator, raised for an open of a reopened 4-tuple */
u32_t
LibTCPNextIss(const ip_addr_t *LocalIp, u16_t LocalPort, const ip_addr_t *RemoteIp, u16_t RemotePort)
{
    static u32_t Iss = 6510;
    PTIME_WAIT_REOPEN Reopen;
    u32_t Next, Floor;

    Iss += tcp_ticks;
    Next = Iss;
    if (IP_IS_V4(LocalIp) && IP_IS_V4(RemoteIp))
    {
        Reopen = LibTCPFindReopen(ip_2_ip4(LocalIp), LocalPort, ip_2_ip4(RemoteIp), RemotePort);
        if (Reopen)
        {
            /* tcp_connect, which never runs while a packet is processed, sends its SYN at ISS - 1 */
            Floor = Reopen->IssFloor + (ip_current_input_netif() == NULL ? 1 : 0);
            if (TCP_SEQ_LT(Next, Floor))
                Next = Floor;
        }
    }
    return Next;
}

/* An established connection that no listen request has taken yet */
typedef struct _PENDING_ACCEPT
{
    LIST_ENTRY ListEntry;
    PCONNECTION_ENDPOINT Listener;
    PTCP_PCB Pcb;
    BOOLEAN PeerClosed;
} PENDING_ACCEPT, *PPENDING_ACCEPT;

/* Bounds the connections a listener keeps waiting, like the lwIP backlog */
#define MAX_PENDING_ACCEPTS 255

static
err_t
InternalPendingRecvEventHandler(void *arg, PTCP_PCB pcb, struct pbuf *p, const err_t err)
{
    PPENDING_ACCEPT Pending = arg;

    /* Refusing the data makes lwIP keep it until the connection is accepted */
    if (p)
        return ERR_MEM;

    if (Pending && err == ERR_OK)
        Pending->PeerClosed = TRUE;

    return ERR_OK;
}

static
void
InternalPendingErrorEventHandler(void *arg, const err_t err)
{
    PPENDING_ACCEPT Pending = arg;
    PCONNECTION_ENDPOINT Listener;

    /* lwIP already freed the PCB */
    if (!Pending)
        return;

    Listener = Pending->Listener;
    RemoveEntryList(&Pending->ListEntry);
    Listener->PendingAcceptCount--;
    ExFreePoolWithTag(Pending, LWIP_ACCEPT_TAG);
    DereferenceObject(Listener);
}

static void LibTCPClaimPendingAcceptCallback(void *arg);

static
VOID
LibTCPPostClaim(PCONNECTION_ENDPOINT Listener, u8_t Block)
{
    struct lwip_callback_msg *msg;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (!msg)
        return;

    ReferenceObject(Listener);
    msg->Input.Socket.Arg = Listener;
    if (tcpip_callback_with_block(LibTCPClaimPendingAcceptCallback, msg, Block) != ERR_OK)
    {
        DereferenceObject(Listener);
        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);
    }
}

static
BOOLEAN
LibTCPQueuePendingAccept(PCONNECTION_ENDPOINT Listener, PTCP_PCB pcb)
{
    PPENDING_ACCEPT Pending;

    if (Listener->PendingAcceptCount >= MAX_PENDING_ACCEPTS)
        return FALSE;

    Pending = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Pending), LWIP_ACCEPT_TAG);
    if (!Pending)
        return FALSE;

    /* Each pending connection keeps its listener */
    ReferenceObject(Listener);
    Pending->Listener = Listener;
    Pending->Pcb = pcb;
    Pending->PeerClosed = FALSE;
    InsertTailList(&Listener->PendingAccepts, &Pending->ListEntry);
    Listener->PendingAcceptCount++;

    tcp_arg(pcb, Pending);
    tcp_recv(pcb, InternalPendingRecvEventHandler);
    tcp_err(pcb, InternalPendingErrorEventHandler);
    tcp_sent(pcb, NULL);

    return TRUE;
}

/* This function MUST return an error value that is not ERR_ABRT or ERR_OK if the connection
 * is not accepted to avoid leaking the new PCB */
static
err_t
InternalAcceptConnection(void *arg, PTCP_PCB newpcb, const err_t err)
{
    /* Make sure the socket didn't get closed */
    if (!arg)
        return ERR_CLSD;

    /* lwIP reports a failed PCB allocation through this callback too */
    if (!newpcb || err != ERR_OK)
        return ERR_VAL;

    /* lwIP gave the new PCB the listener's argument; only LibTCPAccept may set it */
    tcp_arg(newpcb, NULL);

    /* Older connections are served first; the lwIP thread must not wait on its own queue */
    if (!IsListEmpty(&((PCONNECTION_ENDPOINT)arg)->PendingAccepts))
    {
        if (!LibTCPQueuePendingAccept(arg, newpcb))
            return ERR_CLSD;
        LibTCPPostClaim(arg, 0);
        return ERR_OK;
    }

    TCPAcceptEventHandler(arg, newpcb);

    /* Set in LibTCPAccept (called from TCPAcceptEventHandler) */
    if (newpcb->callback_arg)
        return ERR_OK;

    /* No listen request was queued, keep the connection until the next one comes */
    if (LibTCPQueuePendingAccept(arg, newpcb))
        return ERR_OK;

    return ERR_CLSD;
}

/* Once a reopened connection is accepted, its ended TIME-WAIT has nothing left to protect */
static
err_t
InternalAcceptEventHandler(void *arg, PTCP_PCB newpcb, const err_t err)
{
    PTIME_WAIT_REOPEN Reopen;
    ip4_addr_t LocalIp, RemoteIp;
    u16_t LocalPort = 0, RemotePort = 0;
    err_t Result;

    if (newpcb && err == ERR_OK)
    {
        ip4_addr_copy(LocalIp, *ip_2_ip4(&newpcb->local_ip));
        ip4_addr_copy(RemoteIp, *ip_2_ip4(&newpcb->remote_ip));
        LocalPort = newpcb->local_port;
        RemotePort = newpcb->remote_port;
    }

    Result = InternalAcceptConnection(arg, newpcb, err);

    if (Result == ERR_OK && LocalPort)
    {
        Reopen = LibTCPFindReopen(&LocalIp, LocalPort, &RemoteIp, RemotePort);
        if (Reopen)
            LibTCPFreeReopen(Reopen);
    }
    return Result;
}

static
void
LibTCPClaimPendingAcceptCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    PCONNECTION_ENDPOINT Listener = msg->Input.Socket.Arg;
    PPENDING_ACCEPT Pending;
    PTCP_PCB pcb;
    BOOLEAN PeerClosed;

    /* A closed listener has already aborted its pending connections */
    while (Listener->SocketContext && !IsListEmpty(&Listener->PendingAccepts))
    {
        Pending = CONTAINING_RECORD(Listener->PendingAccepts.Flink, PENDING_ACCEPT, ListEntry);
        pcb = Pending->Pcb;

        tcp_arg(pcb, NULL);
        TCPAcceptEventHandler(Listener, pcb);
        if (!pcb->callback_arg)
        {
            /* No listen request took it, keep it waiting */
            tcp_arg(pcb, Pending);
            break;
        }

        RemoveEntryList(&Pending->ListEntry);
        Listener->PendingAcceptCount--;
        PeerClosed = Pending->PeerClosed;
        ExFreePoolWithTag(Pending, LWIP_ACCEPT_TAG);
        DereferenceObject(Listener);

        /* Hand over what arrived while the connection waited */
        if (pcb->refused_data)
            tcp_process_refused_data(pcb);
        else if (PeerClosed)
            InternalRecvEventHandler(pcb->callback_arg, pcb, NULL, ERR_OK);
    }

    DereferenceObject(Listener);
    ExFreeToNPagedLookasideList(&MessageLookasideList, msg);
}

VOID
LibTCPClaimPendingAccept(PCONNECTION_ENDPOINT Listener)
{
    /* Not waited for: the caller may hold locks the accept path takes */
    LibTCPPostClaim(Listener, 1);
}

/* Runs on the lwIP thread when the listener closes */
static
void
LibTCPAbortPendingAccepts(PCONNECTION_ENDPOINT Listener)
{
    PPENDING_ACCEPT Pending;

    while (!IsListEmpty(&Listener->PendingAccepts))
    {
        Pending = CONTAINING_RECORD(RemoveHeadList(&Listener->PendingAccepts), PENDING_ACCEPT, ListEntry);
        tcp_arg(Pending->Pcb, NULL);
        tcp_abort(Pending->Pcb);
        ExFreePoolWithTag(Pending, LWIP_ACCEPT_TAG);
        DereferenceObject(Listener);
    }
    Listener->PendingAcceptCount = 0;
}

static
err_t
InternalConnectEventHandler(void *arg, PTCP_PCB pcb, const err_t err)
{
    /* Make sure the socket didn't get closed */
    if (!arg)
        return ERR_OK;

    TCPConnectEventHandler(arg, err);

    return ERR_OK;
}

static
void
InternalErrorEventHandler(void *arg, const err_t err)
{
    PCONNECTION_ENDPOINT Connection = arg;

    /* Make sure the socket didn't get closed */
    if (!arg || Connection->SocketContext == NULL) return;

    /* The PCB is dead now */
    Connection->SocketContext = NULL;

    /* A reader that finds the queue empty must also find the failure: a reset
       discards what was received and not read yet, as on Windows */
    LockObject(Connection);
    if (err == ERR_RST)
        LibTCPEmptyQueue(Connection);
    Connection->ReceiveShutdown = TRUE;
    Connection->ReceiveShutdownStatus = TCPTranslateError(err);
    UnlockObject(Connection);

    /* Give them one shot to receive the remaining data */
    TCPRecvEventHandler(Connection);

    /* Terminate the connection */
    TCPFinEventHandler(Connection, err);
}

static
void
LibTCPSocketCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;

    ASSERT(msg);

    msg->Output.Socket.NewPcb = tcp_new();

    if (msg->Output.Socket.NewPcb)
    {
        tcp_arg(msg->Output.Socket.NewPcb, msg->Input.Socket.Arg);
        tcp_err(msg->Output.Socket.NewPcb, InternalErrorEventHandler);
    }

    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

struct tcp_pcb *
LibTCPSocket(void *arg)
{
    struct lwip_callback_msg *msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    struct tcp_pcb *ret;

    if (msg)
    {
        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);
        msg->Input.Socket.Arg = arg;

        tcpip_callback_with_block(LibTCPSocketCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
            ret = msg->Output.Socket.NewPcb;
        else
            ret = NULL;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

        return ret;
    }

    return NULL;
}

static
void
LibTCPFreeSocketCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;

    ASSERT(msg);

    /* Calling tcp_close will free it */
    tcp_close(msg->Input.FreeSocket.pcb);

    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

void LibTCPFreeSocket(PTCP_PCB pcb)
{
    struct lwip_callback_msg msg;

    KeInitializeEvent(&msg.Event, NotificationEvent, FALSE);
    msg.Input.FreeSocket.pcb = pcb;

    tcpip_callback_with_block(LibTCPFreeSocketCallback, &msg, 1);

    WaitForEventSafely(&msg.Event);
}


/* Local ports any PCB uses, TIME-WAIT included; rebuilt for each ephemeral
   allocation and only touched with the core lock held */
static ULONG LibTCPUsedPorts[65536 / 32];

/* Called with the core lock held (and the port lock): is this port (host order) marked? */
static
BOOLEAN
LibTCPLocalPortUsed(ULONG Port)
{
    return (LibTCPUsedPorts[(Port & 0xFFFF) / 32] & (1UL << (Port % 32))) != 0;
}

/* Called with the core lock held: one pass over the PCB lists marks every used
   port, so that the search in the port bitmap only tests bits */
static
UINT
LibTCPAllocateEphemeralPortLocked(VOID)
{
    struct tcp_pcb *pcb;
    u8_t i;

    RtlZeroMemory(LibTCPUsedPorts, sizeof(LibTCPUsedPorts));
    for (i = 0; i < NUM_TCP_PCB_LISTS; i++)
    {
        for (pcb = *tcp_pcb_lists[i]; pcb != NULL; pcb = pcb->next)
            LibTCPUsedPorts[pcb->local_port / 32] |= 1UL << (pcb->local_port % 32);
    }

    return TCPAllocateEphemeralPort(LibTCPLocalPortUsed);
}

/* Every ephemeral TCP port comes from the port bitmap, which address files
   share; like lwIP's own allocator it skips ports a PCB still uses. Returns
   the port in network order, or (UINT)-1 if the range is exhausted */
UINT
LibTCPAllocateEphemeralPort(VOID)
{
    UINT Port;

    LOCK_TCPIP_CORE();
    Port = LibTCPAllocateEphemeralPortLocked();
    UNLOCK_TCPIP_CORE();

    return Port;
}

static
void
LibTCPBindCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    PTCP_PCB pcb = msg->Input.Bind.Connection->SocketContext;
    UINT Port = msg->Input.Bind.Port;

    ASSERT(msg);

    if (!msg->Input.Bind.Connection->SocketContext)
    {
        msg->Output.Bind.Error = ERR_CLSD;
        goto done;
    }

    /* We're guaranteed that the local address is valid to bind at this point */
    pcb->so_options |= SOF_REUSEADDR;

    if (!Port)
    {
        /* lwIP would pick a port the bitmap may have given to an address file */
        Port = LibTCPAllocateEphemeralPortLocked();
        if (Port == (UINT)-1)
        {
            /* Every ephemeral port is taken: WSAENOBUFS, as on Windows */
            msg->Output.Bind.Error = ERR_MEM;
            goto done;
        }
    }

    msg->Output.Bind.Error = tcp_bind(pcb,
                                      msg->Input.Bind.IpAddress,
                                      lwip_ntohs((u16_t)Port));

    if (!msg->Input.Bind.Port)
    {
        if (msg->Output.Bind.Error == ERR_OK)
            msg->Output.Bind.Port = (u16_t)Port;
        else
            TCPFreePort(Port);
    }

done:
    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

/* Port 0 binds an ephemeral port, which stays reserved in the port bitmap;
   it is returned in *BoundPort (network order) */
err_t
LibTCPBind(PCONNECTION_ENDPOINT Connection, ip4_addr_t *const ipaddr, const u16_t port, u16_t *const BoundPort)
{
    struct lwip_callback_msg *msg;
    err_t ret;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (msg)
    {
        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);
        msg->Input.Bind.Connection = Connection;
        msg->Input.Bind.IpAddress = ipaddr;
        msg->Input.Bind.Port = port;
        msg->Output.Bind.Port = port;

        tcpip_callback_with_block(LibTCPBindCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
            ret = msg->Output.Bind.Error;
        else
            ret = ERR_CLSD;

        if (ret == ERR_OK && BoundPort)
            *BoundPort = msg->Output.Bind.Port;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

        return ret;
    }

    return ERR_MEM;
}

static
void
LibTCPListenCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;

    ASSERT(msg);

    if (!msg->Input.Listen.Connection->SocketContext)
    {
        msg->Output.Listen.NewPcb = NULL;
        goto done;
    }

    msg->Output.Listen.NewPcb = tcp_listen_with_backlog((PTCP_PCB)msg->Input.Listen.Connection->SocketContext, msg->Input.Listen.Backlog);

    if (msg->Output.Listen.NewPcb)
    {
        tcp_accept(msg->Output.Listen.NewPcb, InternalAcceptEventHandler);
    }

done:
    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

PTCP_PCB
LibTCPListen(PCONNECTION_ENDPOINT Connection, UINT Backlog)
{
    struct lwip_callback_msg *msg;
    PTCP_PCB ret;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (msg)
    {
        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);
        msg->Input.Listen.Connection = Connection;
        /* lwIP keeps the backlog in a u8_t, a plain cast turned 1024 into 0 */
        msg->Input.Listen.Backlog = (u8_t)min(Backlog, 0xFF);

        tcpip_callback_with_block(LibTCPListenCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
            ret = msg->Output.Listen.NewPcb;
        else
            ret = NULL;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

        return ret;
    }

    return NULL;
}

/* Called with the core lock held */
static
err_t
LibTCPSendLocked(PCONNECTION_ENDPOINT Connection, void *Data, u16_t DataLength, PTDI_BUCKET Bucket, u32_t *Information)
{
    PTCP_PCB pcb = Connection->SocketContext;
    ULONG SendLength;
    UCHAR SendFlags;
    err_t Error;

    ASSERT(sys_tcpip_core_locked());

    if (!pcb || Connection->SendShutdown)
        return ERR_CLSD;

    SendFlags = TCP_WRITE_FLAG_COPY;
    SendLength = DataLength;
    if (tcp_sndbuf(pcb) == 0)
    {
        /* No buffer space so return pending */
        Error = ERR_INPROGRESS;
    }
    else
    {
        if (tcp_sndbuf(pcb) < SendLength)
        {
            /* We've got some room so let's send what we can */
            SendLength = tcp_sndbuf(pcb);

            /* Don't set the push flag */
            SendFlags |= TCP_WRITE_FLAG_MORE;
        }

        Error = tcp_write(pcb, Data, SendLength, SendFlags);
        if (Error == ERR_OK)
        {
            /* Queued successfully so try to send it */
            tcp_output(pcb);
            *Information = SendLength;
        }
        else if (Error == ERR_MEM)
        {
            /* The queue is too long */
            Error = ERR_INPROGRESS;
        }
    }

    /* Sent events are delivered under the core lock, so the request is in the queue
     * before the next one can look for it */
    if (Error == ERR_INPROGRESS && Bucket)
    {
        LockObject(Connection);
        InsertTailList(&Connection->SendRequest, &Bucket->Entry);
        UnlockObject(Connection);
    }

    return Error;
}

static
void
LibTCPSendCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;

    ASSERT(msg);

    msg->Output.Send.Error = LibTCPSendLocked(msg->Input.Send.Connection,
                                              msg->Input.Send.Data,
                                              msg->Input.Send.DataLength,
                                              msg->Input.Send.Bucket,
                                              &msg->Output.Send.Information);

    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

/* Stack a sender must have left to run lwIP's output path on its own thread */
#define LIBTCP_SEND_INLINE_STACK (KERNEL_STACK_SIZE / 2)

/* Bucket, if not NULL, is queued as a waiting send request if the data cannot be sent now */
err_t
LibTCPSend(PCONNECTION_ENDPOINT Connection, void *const dataptr, const u16_t len, ULONG *sent, const int safe, PTDI_BUCKET Bucket)
{
    err_t ret;
    u32_t Information = 0;
    struct lwip_callback_msg *msg;

    if (safe)
    {
        /* From a sent event: the core lock is already held */
        ret = LibTCPSendLocked(Connection, dataptr, len, Bucket, &Information);
    }
    else if (IoGetRemainingStackSize() >= LIBTCP_SEND_INLINE_STACK)
    {
        /* Send on the caller's thread rather than switching to the tcpip thread and back */
        LOCK_TCPIP_CORE();
        ret = LibTCPSendLocked(Connection, dataptr, len, Bucket, &Information);
        UNLOCK_TCPIP_CORE();
    }
    else
    {
        msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
        if (!msg)
            return ERR_MEM;

        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);
        msg->Input.Send.Connection = Connection;
        msg->Input.Send.Data = dataptr;
        msg->Input.Send.DataLength = len;
        msg->Input.Send.Bucket = Bucket;

        tcpip_callback_with_block(LibTCPSendCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
        {
            ret = msg->Output.Send.Error;
            Information = msg->Output.Send.Information;
        }
        else
            ret = ERR_CLSD;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);
    }

    if (ret == ERR_OK)
        *sent = Information;
    else
        *sent = 0;

    return ret;
}

static
void
LibTCPConnectCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    err_t Error;

    ASSERT(arg);

    if (!msg->Input.Connect.Connection->SocketContext)
    {
        msg->Output.Connect.Error = ERR_CLSD;
        goto done;
    }

    tcp_recv((PTCP_PCB)msg->Input.Connect.Connection->SocketContext, InternalRecvEventHandler);
    tcp_sent((PTCP_PCB)msg->Input.Connect.Connection->SocketContext, InternalSendEventHandler);

    Error = tcp_connect((PTCP_PCB)msg->Input.Connect.Connection->SocketContext,
                        msg->Input.Connect.IpAddress, lwip_ntohs(msg->Input.Connect.Port),
                        InternalConnectEventHandler);

    msg->Output.Connect.Error = Error == ERR_OK ? ERR_INPROGRESS : Error;

done:
    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

err_t
LibTCPConnect(PCONNECTION_ENDPOINT Connection, ip_addr_t *const ipaddr, const u16_t port)
{
    struct lwip_callback_msg *msg;
    err_t ret;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (msg)
    {
        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);
        msg->Input.Connect.Connection = Connection;
        msg->Input.Connect.IpAddress = ipaddr;
        msg->Input.Connect.Port = port;

        tcpip_callback_with_block(LibTCPConnectCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
        {
            ret = msg->Output.Connect.Error;
        }
        else
            ret = ERR_CLSD;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

        return ret;
    }

    return ERR_MEM;
}

static
void
LibTCPShutdownCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    PTCP_PCB pcb = msg->Input.Shutdown.Connection->SocketContext;

    if (!msg->Input.Shutdown.Connection->SocketContext)
    {
        msg->Output.Shutdown.Error = ERR_CLSD;
        goto done;
    }

    LibTCPReturnCreditLocked(msg->Input.Shutdown.Connection);

    /* LwIP makes the (questionable) assumption that SHUTDOWN_RDWR is equivalent to tcp_close().
     * This assumption holds even if the shutdown calls are done separately (even through multiple
     * WinSock shutdown() calls). This assumption means that lwIP has the right to deallocate our
     * PCB without telling us if we shutdown TX and RX. To avoid these problems, we'll clear the
     * socket context if we have called shutdown for TX and RX.
     */
    if (msg->Input.Shutdown.shut_rx != msg->Input.Shutdown.shut_tx) {
        if (msg->Input.Shutdown.shut_rx) {
            msg->Output.Shutdown.Error = tcp_shutdown(pcb, TRUE, FALSE);
        }
        if (msg->Input.Shutdown.shut_tx) {
            msg->Output.Shutdown.Error = tcp_shutdown(pcb, FALSE, TRUE);
        }
    }
    else if (msg->Input.Shutdown.shut_rx) {
        /* We received both RX and TX requests, which seems to mean closing connection from TDI.
         * So call tcp_close, otherwise we risk to be put in TCP_WAIT_* states, which makes further
         * attempts to close the socket to fail in this state.
         *
         * tcp_close frees the PCB on success, so detach the socket context and the
         * callback argument before the call (mirroring LibTCPCloseCallback) and restore
         * them if the close fails and the PCB survives. Clearing SocketContext also stops
         * the epilogue below from touching the freed PCB.
         */
        msg->Input.Shutdown.Connection->SocketContext = NULL;
        tcp_arg(pcb, NULL);
        msg->Output.Shutdown.Error = tcp_close(pcb);
        if (msg->Output.Shutdown.Error)
        {
            msg->Input.Shutdown.Connection->SocketContext = pcb;
            tcp_arg(pcb, msg->Input.Shutdown.Connection);
        }
    }
    else {
        /* This case shouldn't happen */
        DbgPrint("Requested socket shutdown(0, 0) !\n");
    }

    if (!msg->Output.Shutdown.Error)
    {
        if (msg->Input.Shutdown.shut_rx)
        {
            msg->Input.Shutdown.Connection->ReceiveShutdown = TRUE;
            msg->Input.Shutdown.Connection->ReceiveShutdownStatus = STATUS_FILE_CLOSED;
        }

        if (msg->Input.Shutdown.shut_tx)
            msg->Input.Shutdown.Connection->SendShutdown = TRUE;

        if (msg->Input.Shutdown.Connection->ReceiveShutdown &&
            msg->Input.Shutdown.Connection->SendShutdown)
        {
            /* The PCB is not ours anymore. If the tcp_close path above already
             * detached and freed it, SocketContext is NULL and the PCB must not
             * be touched; only detach here when it is still alive (the
             * tcp_shutdown path).
             */
            if (msg->Input.Shutdown.Connection->SocketContext)
            {
                msg->Input.Shutdown.Connection->SocketContext = NULL;
                tcp_arg(pcb, NULL);
            }
            TCPFinEventHandler(msg->Input.Shutdown.Connection, ERR_CLSD);
        }
    }

done:
    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

err_t
LibTCPShutdown(PCONNECTION_ENDPOINT Connection, const int shut_rx, const int shut_tx)
{
    struct lwip_callback_msg *msg;
    err_t ret;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (msg)
    {
        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);

        msg->Input.Shutdown.Connection = Connection;
        msg->Input.Shutdown.shut_rx = shut_rx;
        msg->Input.Shutdown.shut_tx = shut_tx;

        tcpip_callback_with_block(LibTCPShutdownCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
            ret = msg->Output.Shutdown.Error;
        else
            ret = ERR_CLSD;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

        return ret;
    }

    return ERR_MEM;
}

static
void
LibTCPAbortCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    PCONNECTION_ENDPOINT Connection = msg->Input.Shutdown.Connection;
    PTCP_PCB pcb = Connection->SocketContext;

    if (!pcb)
    {
        msg->Output.Shutdown.Error = ERR_CLSD;
        KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
        return;
    }

    /* A listening PCB has no peer to reset */
    if (pcb->state == LISTEN)
    {
        msg->Input.Shutdown.shut_rx = 1;
        msg->Input.Shutdown.shut_tx = 1;
        LibTCPShutdownCallback(msg);
        return;
    }

    /* The PCB is not ours anymore; tcp_abort frees it after it sends a reset.
     * Hold the connection lock so readers of SocketContext under it are done. */
    LockObject(Connection);
    Connection->SocketContext = NULL;
    tcp_arg(pcb, NULL);
    tcp_abort(pcb);

    Connection->ReceiveShutdown = TRUE;
    Connection->ReceiveShutdownStatus = STATUS_FILE_CLOSED;
    Connection->SendShutdown = TRUE;
    UnlockObject(Connection);

    msg->Output.Shutdown.Error = ERR_OK;
    TCPFinEventHandler(Connection, ERR_CLSD);

    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

err_t
LibTCPAbort(PCONNECTION_ENDPOINT Connection)
{
    struct lwip_callback_msg *msg;
    err_t ret;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (!msg)
        return ERR_MEM;

    KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);
    msg->Input.Shutdown.Connection = Connection;

    if (tcpip_callback_with_block(LibTCPAbortCallback, msg, 1) != ERR_OK)
        ret = ERR_MEM;
    else if (WaitForEventSafely(&msg->Event))
        ret = msg->Output.Shutdown.Error;
    else
        ret = ERR_CLSD;

    ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

    return ret;
}

static
void
LibTCPCloseCallback(void *arg)
{
    struct lwip_callback_msg *msg = arg;
    PTCP_PCB pcb = msg->Input.Close.Connection->SocketContext;

    /* Empty the queue even if we're already "closed" */
    LibTCPEmptyQueue(msg->Input.Close.Connection);
    LibTCPAbortPendingAccepts(msg->Input.Close.Connection);

    /* Check if we've already been closed */
    if (msg->Input.Close.Connection->Closing)
    {
        msg->Output.Close.Error = ERR_OK;
        goto done;
    }

    /* Enter "closing" mode if we're doing a normal close */
    if (msg->Input.Close.Callback)
        msg->Input.Close.Connection->Closing = TRUE;

    /* Check if the PCB was already "closed" but the client doesn't know it yet */
    if (!msg->Input.Close.Connection->SocketContext)
    {
        msg->Output.Close.Error = ERR_OK;
        goto done;
    }

    /* What the owner read and lwIP was not told yet: without it the close sees unread data and resets */
    LibTCPReturnCreditLocked(msg->Input.Close.Connection);

    /* Clear the PCB pointer and stop callbacks */
    msg->Input.Close.Connection->SocketContext = NULL;
    tcp_arg(pcb, NULL);

    /* This may generate additional callbacks but we don't care,
     * because they're too inconsistent to rely on */
    msg->Output.Close.Error = tcp_close(pcb);

    if (msg->Output.Close.Error)
    {
        /* Restore the PCB pointer */
        msg->Input.Close.Connection->SocketContext = pcb;
        msg->Input.Close.Connection->Closing = FALSE;
    }
    else if (msg->Input.Close.Callback)
    {
        TCPFinEventHandler(msg->Input.Close.Connection, ERR_CLSD);
    }

done:
    KeSetEvent(&msg->Event, IO_NO_INCREMENT, FALSE);
}

err_t
LibTCPClose(PCONNECTION_ENDPOINT Connection, const int safe, const int callback)
{
    err_t ret;
    struct lwip_callback_msg *msg;

    msg = ExAllocateFromNPagedLookasideList(&MessageLookasideList);
    if (msg)
    {
        KeInitializeEvent(&msg->Event, NotificationEvent, FALSE);

        msg->Input.Close.Connection = Connection;
        msg->Input.Close.Callback = callback;

        if (safe)
            LibTCPCloseCallback(msg);
        else
            tcpip_callback_with_block(LibTCPCloseCallback, msg, 1);

        if (WaitForEventSafely(&msg->Event))
            ret = msg->Output.Close.Error;
        else
            ret = ERR_CLSD;

        ExFreeToNPagedLookasideList(&MessageLookasideList, msg);

        return ret;
    }

    return ERR_MEM;
}

void
LibTCPAccept(PTCP_PCB pcb, struct tcp_pcb *listen_pcb, void *arg)
{
    ASSERT(arg);

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, InternalRecvEventHandler);
    tcp_sent(pcb, InternalSendEventHandler);
    tcp_err(pcb, InternalErrorEventHandler);
    tcp_arg(pcb, arg);

    tcp_accepted(listen_pcb);
}

err_t
LibTCPGetHostName(PTCP_PCB pcb, ip_addr_t *const ipaddr, u16_t *const port)
{
    if (!pcb)
        return ERR_CLSD;

    *ipaddr = pcb->local_ip;
    /* lwIP keeps ports in host order, our callers want network order */
    *port = lwip_htons(pcb->local_port);

    return ERR_OK;
}

err_t
LibTCPGetPeerName(PTCP_PCB pcb, ip_addr_t * const ipaddr, u16_t * const port)
{
    if (!pcb)
        return ERR_CLSD;

    *ipaddr = pcb->remote_ip;
    *port = lwip_htons(pcb->remote_port);

    return ERR_OK;
}

void
LibTCPSetNoDelay(
    PTCP_PCB pcb,
    BOOLEAN Set)
{
    if (Set)
        pcb->flags |= TF_NODELAY;
    else
        pcb->flags &= ~TF_NODELAY;
}

void
LibTCPSetKeepAlive(
    PTCP_PCB pcb,
    BOOLEAN Set)
{
    if (Set)
        pcb->so_options |= SOF_KEEPALIVE;
    else
        pcb->so_options &= ~SOF_KEEPALIVE;
}

void
LibTcpSetKeepAliveValues(
    PTCP_PCB pcb,
    u32_t KeepAliveTime,
    u32_t KeepAliveInterval
)
{
    pcb->keep_idle = KeepAliveTime;
    pcb->keep_intvl = KeepAliveInterval;
    pcb->keep_cnt = 10;
}

void
LibTCPGetSocketStatus(
    PTCP_PCB pcb,
    PULONG State)
{
    /* Translate state from enum tcp_state -> MIB_TCP_STATE */
    *State = pcb->state + 1;
}
