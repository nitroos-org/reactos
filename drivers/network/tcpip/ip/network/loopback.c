/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        datalink/loopback.c
 * PURPOSE:     Loopback adapter
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

PIP_INTERFACE Loopback = NULL;

/* Looped TCP segments and UDP datagrams are received one at a time, in the order they were sent */
static CHEW_SERIAL_QUEUE LoopQueue;

#define LOOP_QUEUE_LIMIT 1024

/* TCP fast path (on from the registration of the adapter to its removal): a TCP datagram lwIP sends to the loopback netif is copied
   once into a pbuf and goes on LoopQueue as it is. The worker gives it to lwIP, without the two NDIS
   packets, the neighbour queue, the IP layer's receive path and the two further copies of the other
   path. Everything the IP layer would do on the way is nothing for loopback: the firewall passes it by
   interface, loopback has no counters, and lwIP checks the header it built itself. Same queue, same
   worker, so the order of looped segments and datagrams does not change. Other protocols (UDP, ICMP)
   take the NDIS path of LoopTransmit */

BOOLEAN LoopFastPath = FALSE;

/* Pbuf is NULL for an IP packet of the NDIS path; a fast-path item ends before IPPacket */
typedef struct _LOOP_ITEM
{
  LIST_ENTRY ListEntry;
  struct pbuf *Pbuf;
  IP_PACKET IPPacket;
} LOOP_ITEM, *PLOOP_ITEM;

static NPAGED_LOOKASIDE_LIST LoopPbufItems;
static BOOLEAN LoopPbufItemsReady;
static volatile BOOLEAN LoopClosing;

/* Sends whose completion waits for the worker. A TCP send that asks for it (TCP_SEND_DELIVERED: the last send of a
 * TransmitFile) to a peer on this machine completes when the worker has handed its segments to the peer's
 * connection, so that the data is in the peer's queue when the sender goes on (on Windows it is; here the worker
 * runs a moment after the sender queued the segments). Every entry the worker finishes counts in LoopHandled; a
 * send holds the ticket of its last segment and completes when LoopHandled has reached it. The sender does not
 * wait: its request stays pending and the worker completes it, so no thread holds a lock another needs while it
 * waits, and no processor spins. Tickets wrap: they are compared as differences.
 * Plain sends do not wait: a request that comes back after the worker's round trip made a loopback echo three times
 * slower (39 to 130 microseconds a round trip) and bulk sends 18% slower, measured on pinned vCPUs */
static KSPIN_LOCK LoopWaitLock;
static LIST_ENTRY LoopWaiters;
static volatile LONG LoopWaiterCount;
static volatile LONG LoopHandled;

/* Under the core lock, written by LoopTransmitPbuf only */
ULONG LoopCoreSeq;
ULONG LoopCoreTicket;

BOOLEAN LoopDeferCompletion(
  PTDI_BUCKET Bucket,
  ULONG Ticket)
{
  KIRQL OldIrql;
  BOOLEAN Taken = TRUE;

  Bucket->LoopTicket = Ticket;

  /* The count, the entry and the check are one step under the lock: the worker counts an entry done first and
     looks at the waiters after, so either this check sees it or the worker sees the entry */
  KeAcquireSpinLock(&LoopWaitLock, &OldIrql);
  InsertTailList(&LoopWaiters, &Bucket->Entry);
  InterlockedIncrement(&LoopWaiterCount);
  if ((LONG)((ULONG)LoopHandled - Ticket) >= 0)
  {
    RemoveEntryList(&Bucket->Entry);
    InterlockedDecrement(&LoopWaiterCount);
    Taken = FALSE;
  }
  KeReleaseSpinLock(&LoopWaitLock, OldIrql);

  return Taken;
}

/* On the worker, with no lock held, after an entry is done: completes the sends whose segments are all done */
static VOID LoopCompleteWaiters(VOID)
{
  KIRQL OldIrql;
  LIST_ENTRY Done;
  PLIST_ENTRY Entry, Next;

  if (LoopWaiterCount == 0)
    return;

  InitializeListHead(&Done);
  KeAcquireSpinLock(&LoopWaitLock, &OldIrql);
  for (Entry = LoopWaiters.Flink; Entry != &LoopWaiters; Entry = Next)
  {
    PTDI_BUCKET Bucket = CONTAINING_RECORD(Entry, TDI_BUCKET, Entry);

    Next = Entry->Flink;
    if ((LONG)((ULONG)LoopHandled - Bucket->LoopTicket) >= 0)
    {
      RemoveEntryList(Entry);
      InterlockedDecrement(&LoopWaiterCount);
      InsertTailList(&Done, Entry);
    }
  }
  KeReleaseSpinLock(&LoopWaitLock, OldIrql);

  /* Inline on this thread, which holds nothing (it is in the inline context); a work item otherwise */
  TCPRunDeferredCompletions(&Done, FALSE);
}

VOID LoopPassiveWorkItem(
  PVOID Context)
{
  PLOOP_ITEM Item = Context;

  /* IPReceive() takes care of the NDIS packet */
  IPReceive(Loopback, &Item->IPPacket);

  ExFreePool(Item);
}

/* On the worker: a fast-path datagram enters lwIP as LibIPInsertPacket would put it there */
static VOID LoopInputPbuf(
  PLOOP_ITEM Item)
{
  struct pbuf *p = Item->Pbuf;
  struct netif *netif = Loopback ? Loopback->TCPContext : NULL;

  ExFreeToNPagedLookasideList(&LoopPbufItems, Item);

  if (LoopClosing || !netif || netif->input(p, netif) != ERR_OK)
    pbuf_free(p);
}

VOID LoopPassiveWorker(
  PLIST_ENTRY Entry)
{
  PLOOP_ITEM Item = CONTAINING_RECORD(Entry, LOOP_ITEM, ListEntry);

  /* Holds no lock: the TDI completions the segment causes run on this thread (CompleteBucket) */
  BOOLEAN Pbuf = (Item->Pbuf != NULL);

  TCPEnterInlineContext();
  if (Pbuf)
    LoopInputPbuf(Item);
  else
    LoopPassiveWorkItem(Item);

  /* The segment is with the peer's connection: the sends that waited for it are done */
  InterlockedIncrement(&LoopHandled);
  LoopCompleteWaiters();
  TCPLeaveInlineContext();

  /* An IPv6 datagram (::1) may have left UDP datagrams for the sockets (udp6.c) */
  if (Pbuf)
    UDP6DeliverDeferred();
}

BOOLEAN LoopTransmitPbuf(
  struct pbuf *p)
/*
 * FUNCTION: Loops a TCP datagram from lwIP back to lwIP (the fast path)
 * ARGUMENTS:
 *   p = The complete datagram, IP header first; it stays the caller's
 * RETURNS:
 *   FALSE if the copy could not be allocated (the caller tries again later),
 *   TRUE when it is queued, or dropped as LoopTransmit drops a packet when
 *   the queue is full
 * NOTES:
 *   Under the lwIP core lock (lwIP's output). lwIP keeps p for retransmission
 *   and ip4_input moves the payload of what it is given, so it gets a copy
 */
{
  struct pbuf *q;
  PLOOP_ITEM Item;
  ULONG Ticket;

  q = pbuf_clone(PBUF_RAW, PBUF_RAM, p);
  if (!q)
    return FALSE;

  Item = ExAllocateFromNPagedLookasideList(&LoopPbufItems);
  if (!Item)
  {
    pbuf_free(q);
    return TRUE;
  }

  Item->Pbuf = q;
  if (!ChewSerialInsertTicket(&LoopQueue, &Item->ListEntry, &Ticket))
  {
    pbuf_free(q);
    ExFreeToNPagedLookasideList(&LoopPbufItems, Item);
  }
  else
  {
    /* Whoever sent this datagram can wait for its ticket (the core lock is held) */
    LoopCoreTicket = Ticket;
    LoopCoreSeq++;
  }

  return TRUE;
}

BOOLEAN LoopDataFollows(
  const struct tcp_pcb *pcb)
/*
 * FUNCTION: Tells whether the segment that the worker takes next is data of the connection of pcb
 * NOTES:
 *   Looks at the head of the queue only (a fast-path item holds a contiguous copy of the datagram)
 */
{
  KIRQL OldIrql;
  PLIST_ENTRY Entry;
  PLOOP_ITEM Item;
  const UCHAR *Ip;
  UINT IpLen, TcpLen, Total;
  BOOLEAN Follows = FALSE;

  /* The datagrams compared below are IPv4 ones */
  if (!IP_IS_V4_VAL(pcb->remote_ip) || !IP_IS_V4_VAL(pcb->local_ip))
    return FALSE;

  KeAcquireSpinLock(&LoopQueue.Lock, &OldIrql);
  Entry = LoopQueue.List.Flink;
  if (Entry != &LoopQueue.List)
  {
    Item = CONTAINING_RECORD(Entry, LOOP_ITEM, ListEntry);
    if (Item->Pbuf && Item->Pbuf->len == Item->Pbuf->tot_len && Item->Pbuf->len >= sizeof(IPv4_HEADER) + 20)
    {
      Ip = Item->Pbuf->payload;
      IpLen = (Ip[0] & 0x0F) * 4;
      Total = (Ip[2] << 8) | Ip[3];
      if ((Ip[0] & 0xF0) == 0x40 && Ip[9] == IPPROTO_TCP && IpLen >= 20 && Total <= Item->Pbuf->len &&
          Total >= IpLen + 20)
      {
        const UCHAR *Tcp = Ip + IpLen;

        TcpLen = (Tcp[12] >> 4) * 4;
        /* From the peer to this PCB, with data and no SYN, FIN or RST */
        Follows = Total > IpLen + TcpLen &&
                  !(Tcp[13] & 0x07) &&
                  RtlCompareMemory(Ip + 12, &ip_2_ip4(&pcb->remote_ip)->addr, 4) == 4 &&
                  RtlCompareMemory(Ip + 16, &ip_2_ip4(&pcb->local_ip)->addr, 4) == 4 &&
                  Tcp[0] == (UCHAR)(pcb->remote_port >> 8) && Tcp[1] == (UCHAR)pcb->remote_port &&
                  Tcp[2] == (UCHAR)(pcb->local_port >> 8) && Tcp[3] == (UCHAR)pcb->local_port;
      }
    }
  }
  KeReleaseSpinLock(&LoopQueue.Lock, OldIrql);

  return Follows;
}

VOID LoopTransmit(
  PVOID Context,
  PNDIS_PACKET NdisPacket,
  UINT Offset,
  PVOID LinkAddress,
  USHORT Type)
/*
 * FUNCTION: Transmits a packet
 * ARGUMENTS:
 *   Context     = Pointer to context information (NULL)
 *   NdisPacket  = Pointer to NDIS packet to send
 *   Offset      = Offset in packet where packet data starts
 *   LinkAddress = Pointer to link address
 *   Type        = LAN protocol type
 */
{
    PCHAR PacketBuffer;
    UINT PacketLength;
    PNDIS_PACKET XmitPacket;
    NDIS_STATUS NdisStatus;
    PLOOP_ITEM Item;
    BOOLEAN Queued;

    ASSERT_KM_POINTER(NdisPacket);
    ASSERT_KM_POINTER(PC(NdisPacket));
    ASSERT_KM_POINTER(PC(NdisPacket)->DLComplete);

    if (Type != LAN_PROTO_IPv4)
    {
        TI_DbgPrint(MAX_TRACE, ("Received unsupported protocol %u\n", Type));
        PC(NdisPacket)->DLComplete(PC(NdisPacket)->Context, NdisPacket, NDIS_STATUS_NOT_SUPPORTED);
        return;
    }

    TI_DbgPrint(MAX_TRACE, ("Called (NdisPacket = %x)\n", NdisPacket));

    GetDataPtr( NdisPacket, 0, &PacketBuffer, &PacketLength );

    NdisStatus = AllocatePacketWithBuffer
        ( &XmitPacket, PacketBuffer, PacketLength );

    if( NT_SUCCESS(NdisStatus) ) {
        Item = ExAllocatePool(NonPagedPool, sizeof(LOOP_ITEM));
        if (Item)
        {
            Item->Pbuf = NULL;
            IPInitializePacket(&Item->IPPacket, 0);

            Item->IPPacket.NdisPacket = XmitPacket;

            GetDataPtr(Item->IPPacket.NdisPacket,
                       0,
                       (PCHAR*)&Item->IPPacket.Header,
                       &Item->IPPacket.TotalSize);

            Item->IPPacket.MappedHeader = TRUE;

            /* TCP in order, and UDP in order too: AFD keeps one datagram receive posted per
               socket and posts the next one only when the previous completed, so two
               datagrams delivered at the same time find no receive request and the second
               is dropped. Everything else in a work item of its own */
            if (PacketLength >= 10 && (PacketBuffer[0] & 0xF0) == 0x40 &&
                (PacketBuffer[9] == IPPROTO_TCP || PacketBuffer[9] == IPPROTO_UDP))
                Queued = ChewSerialInsert(&LoopQueue, &Item->ListEntry);
            else
                Queued = ChewCreate(LoopPassiveWorkItem, Item);

            if (!Queued)
            {
                Item->IPPacket.Free(&Item->IPPacket);
                ExFreePool(Item);
                NdisStatus = NDIS_STATUS_RESOURCES;
            }
        }
        else
        {
            FreeNdisPacket(XmitPacket);
            NdisStatus = NDIS_STATUS_RESOURCES;
        }
    }

    (PC(NdisPacket)->DLComplete)
        ( PC(NdisPacket)->Context, NdisPacket, NdisStatus );
}

NDIS_STATUS LoopRegisterAdapter(
  PNDIS_STRING AdapterName,
  PLAN_ADAPTER *Adapter)
/*
 * FUNCTION: Registers loopback adapter with the network layer
 * ARGUMENTS:
 *   AdapterName = Unused
 *   Adapter     = Unused
 * RETURNS:
 *   Status of operation
 */
{
  LLIP_BIND_INFO BindInfo;

  TI_DbgPrint(MID_TRACE, ("Called.\n"));

  if (!ChewSerialInit(&LoopQueue, LoopPassiveWorker, LOOP_QUEUE_LIMIT))
    return NDIS_STATUS_RESOURCES;

  KeInitializeSpinLock(&LoopWaitLock);
  InitializeListHead(&LoopWaiters);
  LoopWaiterCount = 0;
  LoopHandled = 0;

  ExInitializeNPagedLookasideList(&LoopPbufItems, NULL, NULL, 0,
                                  FIELD_OFFSET(LOOP_ITEM, IPPacket), 'pLoL', 0);
  LoopPbufItemsReady = TRUE;
  LoopClosing = FALSE;

  /* Bind the adapter to network (IP) layer */
  BindInfo.Context = NULL;
  BindInfo.HeaderSize = 0;
  BindInfo.MinFrameSize = 0;
  BindInfo.Address = NULL;
  BindInfo.AddressLength = 0;
  BindInfo.Transmit = LoopTransmit;
  BindInfo.Release = NULL;
  BindInfo.SetMulticast = NULL;

  Loopback = IPCreateInterface(&BindInfo);
  if (!Loopback) {
    ChewSerialRundown(&LoopQueue);
    ExDeleteNPagedLookasideList(&LoopPbufItems);
    LoopPbufItemsReady = FALSE;
    return NDIS_STATUS_RESOURCES;
  }

  Loopback->MTU = 16384;

  Loopback->Name.Buffer = L"Loopback";
  Loopback->Name.MaximumLength = Loopback->Name.Length =
      (USHORT)wcslen(Loopback->Name.Buffer) * sizeof(WCHAR);

  AddrInitIPv4(&Loopback->Unicast, LOOPBACK_ADDRESS_IPv4);
  AddrInitIPv4(&Loopback->Netmask, LOOPBACK_ADDRMASK_IPv4);
  AddrInitIPv4(&Loopback->Broadcast, LOOPBACK_BCASTADDR_IPv4);

  IPRegisterInterface(Loopback);

  IPAddInterfaceRoute(Loopback);

  /* ::1, when IPv6 is on */
  TCPAddLoopbackAddress6(Loopback);

  /* Last: the fast path needs the interface's netif */
  LoopFastPath = TRUE;
  DbgPrint("TCPIP: loopback fast path on\n");

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS LoopUnregisterAdapter(
  PLAN_ADAPTER Adapter)
/*
 * FUNCTION: Unregisters loopback adapter with the network layer
 * ARGUMENTS:
 *   Adapter = Unused
 * RETURNS:
 *   Status of operation
 * NOTES:
 *   Does not care wether we have registered loopback adapter
 */
{
  TI_DbgPrint(MID_TRACE, ("Called.\n"));

  if (Loopback != NULL)
    {
      /* A fast-path datagram queued from now on is freed by the worker, or refused by the closed queue */
      LoopFastPath = FALSE;
      LoopClosing = TRUE;

      IPUnregisterInterface(Loopback);
      ChewSerialRundown(&LoopQueue);
      /* The worker has done everything that was queued, and completed the sends that waited for it */
      ASSERT(LoopWaiterCount == 0);
      if (LoopPbufItemsReady)
      {
        ExDeleteNPagedLookasideList(&LoopPbufItems);
        LoopPbufItemsReady = FALSE;
      }
      IPDestroyInterface(Loopback);
      Loopback = NULL;
    }

  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));

  return NDIS_STATUS_SUCCESS;
}
