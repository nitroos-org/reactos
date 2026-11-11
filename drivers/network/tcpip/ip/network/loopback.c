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

/* TCP fast path (Tcpip\Parameters NitroLoopbackFastPath, REG_DWORD, read when the adapter registers;
   absent = LOOP_FAST_PATH_DEFAULT, 0 = off): a TCP datagram lwIP sends to the loopback netif is copied
   once into a pbuf and goes on LoopQueue as it is. The worker gives it to lwIP, without the two NDIS
   packets, the neighbour queue, the IP layer's receive path and the two further copies of the other
   path. Everything the IP layer would do on the way is nothing for loopback: the firewall passes it by
   interface, loopback has no counters, and lwIP checks the header it built itself. Same queue, same
   worker, so the order of looped segments and datagrams does not change */
#define LOOP_FAST_PATH_DEFAULT 1
#define LOOP_FAST_PATH_VALUE L"NitroLoopbackFastPath"

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
  TCPEnterInlineContext();
  if (Item->Pbuf)
    LoopInputPbuf(Item);
  else
    LoopPassiveWorkItem(Item);
  TCPLeaveInlineContext();
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
  if (!ChewSerialInsert(&LoopQueue, &Item->ListEntry))
  {
    pbuf_free(q);
    ExFreeToNPagedLookasideList(&LoopPbufItems, Item);
  }

  return TRUE;
}

static BOOLEAN LoopReadFastPathSwitch(VOID)
{
  UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters");
  UNICODE_STRING ValueName = RTL_CONSTANT_STRING(LOOP_FAST_PATH_VALUE);
  OBJECT_ATTRIBUTES Attributes;
  UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
  PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
  HANDLE Key;
  ULONG Length;
  NTSTATUS Status;
  BOOLEAN Enabled = LOOP_FAST_PATH_DEFAULT;

  InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
  if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
    return Enabled;

  Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
  if (NT_SUCCESS(Status) && Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
    Enabled = (*(PULONG)Info->Data != 0);

  ZwClose(Key);
  return Enabled;
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

  /* Last: the fast path needs the interface's netif */
  LoopFastPath = LoopReadFastPathSwitch();
  DbgPrint("TCPIP: loopback fast path %s\n", LoopFastPath ? "on" : "off");

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
