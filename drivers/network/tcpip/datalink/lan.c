/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        datalink/lan.c
 * PURPOSE:     Local Area Network media routines
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

#include <ntifs.h>
#include <receive.h>
#include <wait.h>
#include <reactos/nitrofw.h>
#include "fwiftype.h"

UINT TransferDataCalled = 0;
UINT TransferDataCompleteCalled = 0;

#define CCS_ROOT L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet"
#define TCPIP_GUID L"{4D36E972-E325-11CE-BFC1-08002BE10318}"

/* TCP segments that may wait in an adapter's receive queue */
#define LAN_RECEIVE_QUEUE_LIMIT 1024

/* Miniport packets among them; later segments are copied so the miniport's
   receive buffers do not run out while the worker is busy */
#define LAN_MAX_HELD_PACKETS 32

/* Frames other than TCP segments each get a work item of their own: a flood of them must not queue
   work (and hold the miniport's packets) without end. Past this many in flight a frame is dropped,
   as a full receive queue of a network card drops it */
#define LAN_MAX_PENDING_FRAMES 512

/* One NDIS request and its own completion. NDIS completes a pending request
   through ProtocolRequestComplete with that request, so the waiter is found
   from it: several requests can be pending on one adapter at a time. */
typedef struct _LAN_REQUEST {
    NDIS_REQUEST Request;
    KEVENT Event;
    NDIS_STATUS Status;
} LAN_REQUEST, *PLAN_REQUEST;

typedef struct _LAN_WQ_ITEM {
    LIST_ENTRY ListEntry;
    PNDIS_PACKET Packet;
    PLAN_ADAPTER Adapter;
    UINT BytesTransferred;
    BOOLEAN LegacyReceive;
    BOOLEAN Held;
    BOOLEAN FromOwnLink;    /* Frame is one our own send path looped back (LanLoopTagged), taken at indication */
} LAN_WQ_ITEM, *PLAN_WQ_ITEM;

typedef struct _RECONFIGURE_CONTEXT {
    ULONG State;
    PLAN_ADAPTER Adapter;
} RECONFIGURE_CONTEXT, *PRECONFIGURE_CONTEXT;

NDIS_HANDLE NdisProtocolHandle = (NDIS_HANDLE)NULL;
BOOLEAN ProtocolRegistered     = FALSE;
/* Adapters an IP interface owns (BindAdapter) that its last reference has not freed yet */
static volatile LONG LanAdaptersOwned = 0;
LIST_ENTRY AdapterListHead;
KSPIN_LOCK AdapterListLock;

NDIS_STATUS NDISCall(
    PLAN_ADAPTER Adapter,
    NDIS_REQUEST_TYPE Type,
    NDIS_OID OID,
    PVOID Buffer,
    UINT Length)
/*
 * FUNCTION: Send a request to NDIS
 * ARGUMENTS:
 *     Adapter     = Pointer to a LAN_ADAPTER structure
 *     Type        = Type of request (Set or Query)
 *     OID         = Value to be set/queried for
 *     Buffer      = Pointer to a buffer to use
 *     Length      = Number of bytes in Buffer
 * RETURNS:
 *     Status of operation
 */
{
    LAN_REQUEST Request;
    NDIS_STATUS NdisStatus;

    RtlZeroMemory(&Request.Request, sizeof(Request.Request));
    KeInitializeEvent(&Request.Event, NotificationEvent, FALSE);
    Request.Request.RequestType = Type;
    if (Type == NdisRequestSetInformation) {
        Request.Request.DATA.SET_INFORMATION.Oid                     = OID;
        Request.Request.DATA.SET_INFORMATION.InformationBuffer       = Buffer;
        Request.Request.DATA.SET_INFORMATION.InformationBufferLength = Length;
    } else {
        Request.Request.DATA.QUERY_INFORMATION.Oid                     = OID;
        Request.Request.DATA.QUERY_INFORMATION.InformationBuffer       = Buffer;
        Request.Request.DATA.QUERY_INFORMATION.InformationBufferLength = Length;
    }

    if (!Adapter->NdisHandle) {
        /* Closed: LANUnregisterAdapter runs */
        NdisStatus = NDIS_STATUS_CLOSING;
    } else if (Adapter->State != LAN_STATE_RESETTING) {
        NdisRequest(&NdisStatus, Adapter->NdisHandle, &Request.Request);
    } else {
        NdisStatus = NDIS_STATUS_NOT_ACCEPTED;
    }

    /* Wait for NDIS to complete this request: the request and the buffer
       belong to this frame until then */
    if (NdisStatus == NDIS_STATUS_PENDING) {
        KeWaitForSingleObject(&Request.Event,
                              UserRequest,
                              KernelMode,
                              FALSE,
                              NULL);
        NdisStatus = Request.Status;
    }

    return NdisStatus;
}

/* Frames the host sends to its own address.
   NDIS loops those back up from inside NdisSend (the miniport has NO_LOOPBACK set, or loops them itself),
   on the CPU that sends, before NdisSend returns. LANTransmit tags that window: LanLoopAdapter[cpu] holds
   the adapter while a frame addressed to the adapter's own MAC is inside NdisSend (IRQL is DISPATCH_LEVEL
   there: LANTransmit holds the adapter lock, so no wire frame can be indicated on this CPU meanwhile). The
   receive handlers read the tag at indication time. The frame's source MAC is deliberately not what
   decides it: a peer on the wire can put our MAC and our IP on a frame, and that frame must be filtered like
   any other inbound one. The inbound filter passes only tagged frames as local traffic. */
static PVOID volatile LanLoopAdapter[MAXIMUM_PROCESSORS];

static BOOLEAN
LanDestIsOwn(PLAN_ADAPTER Adapter, PETH_HEADER Header)
{
    return RtlCompareMemory(Header->DstAddr, Adapter->HWAddress, IEEE_802_ADDR_LENGTH) == IEEE_802_ADDR_LENGTH;
}

/* True while the calling CPU is inside NdisSend of a frame to this adapter's own MAC: the frame being
   indicated now is that frame, looped back. Cheap sanity check on top: it must also carry our MAC as source
   (LANTransmit puts it there). */
static BOOLEAN
LanLoopTagged(PLAN_ADAPTER Adapter, PVOID HeaderBuffer, ULONG HeaderBufferSize)
{
    KIRQL OldIrql;
    ULONG Cpu;
    BOOLEAN Tagged;

    if (Adapter->Media != NdisMedium802_3 || HeaderBufferSize < sizeof(ETH_HEADER) ||
        Adapter->HWAddressLength != IEEE_802_ADDR_LENGTH)
        return FALSE;

    /* the CPU number must not change while it is read */
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    Cpu = KeGetCurrentProcessorNumber();
    Tagged = Cpu < MAXIMUM_PROCESSORS && LanLoopAdapter[Cpu] == (PVOID)Adapter;
    KeLowerIrql(OldIrql);

    return Tagged &&
           RtlCompareMemory(((PETH_HEADER)HeaderBuffer)->SrcAddr, Adapter->HWAddress, IEEE_802_ADDR_LENGTH) == IEEE_802_ADDR_LENGTH;
}

static BOOLEAN
LanNdisPacketLoopTagged(PLAN_ADAPTER Adapter, PNDIS_PACKET NdisPacket)
{
    UCHAR Header[sizeof(ETH_HEADER)];

    if (Adapter->Media != NdisMedium802_3 ||
        CopyPacketToBuffer((PCHAR)Header, NdisPacket, 0, sizeof(Header)) != sizeof(Header))
        return FALSE;
    return LanLoopTagged(Adapter, Header, sizeof(Header));
}

/* Used by legacy ProtocolReceive for packet type */
NDIS_STATUS
GetPacketTypeFromHeaderBuffer(PLAN_ADAPTER Adapter,
                              PVOID HeaderBuffer,
                              ULONG HeaderBufferSize,
                              PULONG PacketType,
                              PBOOLEAN NonUnicast)
{
    PETH_HEADER EthHeader = HeaderBuffer;

    if (HeaderBufferSize < Adapter->HeaderSize)
    {
        TI_DbgPrint(DEBUG_DATALINK, ("Runt frame (size %d).\n", HeaderBufferSize));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    switch (Adapter->Media)
    {
        case NdisMedium802_3:
            /* Ethernet and IEEE 802.3 frames can be distinguished by
               looking at the IEEE 802.3 length field. This field is
               less than or equal to 1500 for a valid IEEE 802.3 frame
               and larger than 1500 is it's a valid EtherType value.
               See RFC 1122, section 2.3.3 for more information */

            *PacketType = EthHeader->EType;
            /* the group bit of the destination: broadcast and multicast frames */
            if (NonUnicast)
                *NonUnicast = (EthHeader->DstAddr[0] & BCAST_ETH_MASK) != 0;
            break;

        default:
            TI_DbgPrint(MIN_TRACE, ("Unsupported media.\n"));

            /* FIXME: Support other medias */
            return NDIS_STATUS_NOT_ACCEPTED;
    }

    TI_DbgPrint(DEBUG_DATALINK, ("EtherType (0x%X).\n", *PacketType));

    return NDIS_STATUS_SUCCESS;
}

/* Used by ProtocolReceivePacket for packet type */
NDIS_STATUS
GetPacketTypeFromNdisPacket(PLAN_ADAPTER Adapter,
                            PNDIS_PACKET NdisPacket,
                            PULONG PacketType,
                            PBOOLEAN NonUnicast)
{
    PVOID HeaderBuffer;
    ULONG BytesCopied;
    NDIS_STATUS Status;

    HeaderBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                         Adapter->HeaderSize,
                                         HEADER_TAG);
    if (!HeaderBuffer)
        return NDIS_STATUS_RESOURCES;

    /* Copy the media header */
    BytesCopied = CopyPacketToBuffer(HeaderBuffer,
                                     NdisPacket,
                                     0,
                                     Adapter->HeaderSize);
    if (BytesCopied != Adapter->HeaderSize)
    {
        /* Runt frame */
        ExFreePoolWithTag(HeaderBuffer, HEADER_TAG);
        TI_DbgPrint(DEBUG_DATALINK, ("Runt frame (size %d).\n", BytesCopied));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    Status = GetPacketTypeFromHeaderBuffer(Adapter,
                                           HeaderBuffer,
                                           BytesCopied,
                                           PacketType,
                                           NonUnicast);

    ExFreePoolWithTag(HeaderBuffer, HEADER_TAG);

    return Status;
}


VOID FreeAdapter(
    PLAN_ADAPTER Adapter)
/*
 * FUNCTION: Frees memory for a LAN_ADAPTER structure
 * ARGUMENTS:
 *     Adapter = Pointer to LAN_ADAPTER structure to free
 */
{
    ChewSerialRundown(&Adapter->ReceiveQueue);

    ExFreePoolWithTag(Adapter, LAN_ADAPTER_TAG);
}

/* The IP interface's release routine: the adapter goes with the interface's last reference
   (at <= DISPATCH_LEVEL). The binding is closed and the receive queue run down by then */
static VOID LanReleaseAdapter(
    PVOID Context)
{
    PLAN_ADAPTER Adapter = Context;

    ASSERT(!Adapter->NdisHandle && !Adapter->ReceiveQueue.WorkItem);

    ExFreePoolWithTag(Adapter, LAN_ADAPTER_TAG);

    /* LANUnregisterProtocol waits for this */
    InterlockedDecrement(&LanAdaptersOwned);
}


VOID UnbindAdapter(
    PLAN_ADAPTER Adapter);

/*
 * FUNCTION: Gives up an adapter whose NdisOpenAdapter succeeded but which is not registered after all
 * NOTES:
 *     Torn down as LANUnregisterAdapter does it, minus the adapter list (it is not on it yet):
 *     - the binding is closed first: NDIS keeps calling the binding's context (status and receive
 *       indications) until then, and the freed LAN_ADAPTER's memory is soon some other driver's (it
 *       was ndisuio's context, which a status indication then overwrote)
 *     - a reconfiguration BindAdapter's media indication queued (ReconfigureAdapterWorker holds the
 *       adapter) ends first, and the received frames still queued are delivered, before the adapter
 *       is freed; the IP interface BindAdapter registered goes after them (UnbindAdapter)
 */
static
VOID DenyOpenAdapter(
    PLAN_ADAPTER Adapter)
{
    NDIS_STATUS NdisStatus;
    NDIS_HANDLE NdisHandle;
    LARGE_INTEGER Delay;
    BOOLEAN Queued;
    KIRQL OldIrql;

    Delay.QuadPart = -100000;
    TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
    Adapter->Unbinding = TRUE;
    TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
    for (;;) {
        TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
        Queued = Adapter->ReconfigureQueued;
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
        if (!Queued)
            break;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    TcpipAcquireSpinLock(&Adapter->Lock, &OldIrql);
    NdisHandle = Adapter->NdisHandle;
    Adapter->NdisHandle = NULL;
    TcpipReleaseSpinLock(&Adapter->Lock, OldIrql);
    if (NdisHandle) {
        NdisCloseAdapter(&NdisStatus, NdisHandle);
        if (NdisStatus == NDIS_STATUS_PENDING)
            TcpipWaitForSingleObject(&Adapter->Event,
                                     UserRequest,
                                     KernelMode,
                                     FALSE,
                                     NULL);
    }

    ChewSerialRundown(&Adapter->ReceiveQueue);
    while (Adapter->ReceiveWorkItems != 0)
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    if (Adapter->Context) {
        /* The interface frees the adapter with its last reference */
        UnbindAdapter(Adapter);
    } else {
        FreeAdapter(Adapter);
    }
}


ULONG LANGetFwIfType(PIP_INTERFACE Interface)
{
    if (!Interface || !Interface->Context || Interface == Loopback)
        return NITROFW_IFTYPE_LAN;
    return ((PLAN_ADAPTER)Interface->Context)->FwIfType;
}

NTSTATUS TcpipLanGetDwordOid
( PIP_INTERFACE Interface,
  NDIS_OID Oid,
  PULONG Result ) {
    /* Get maximum frame size */
    if( Interface->Context ) {
        return NDISCall((PLAN_ADAPTER)Interface->Context,
                        NdisRequestQueryInformation,
                        Oid,
                        Result,
                        sizeof(ULONG));
    } else switch( Oid ) { /* Loopback Case */
    case OID_GEN_HARDWARE_STATUS:
        *Result = NdisHardwareStatusReady;
        return STATUS_SUCCESS;
    case OID_GEN_MEDIA_CONNECT_STATUS:
        *Result = NdisMediaStateConnected;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}


VOID NTAPI ProtocolOpenAdapterComplete(
    NDIS_HANDLE BindingContext,
    NDIS_STATUS Status,
    NDIS_STATUS OpenErrorStatus)
/*
 * FUNCTION: Called by NDIS to complete opening of an adapter
 * ARGUMENTS:
 *     BindingContext  = Pointer to a device context (LAN_ADAPTER)
 *     Status          = Status of the operation
 *     OpenErrorStatus = Additional status information
 */
{
    PLAN_ADAPTER Adapter = (PLAN_ADAPTER)BindingContext;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    Adapter->NdisStatus = Status;

    KeSetEvent(&Adapter->Event, 0, FALSE);
}


VOID NTAPI ProtocolCloseAdapterComplete(
    NDIS_HANDLE BindingContext,
    NDIS_STATUS Status)
/*
 * FUNCTION: Called by NDIS to complete closing an adapter
 * ARGUMENTS:
 *     BindingContext = Pointer to a device context (LAN_ADAPTER)
 *     Status         = Status of the operation
 */
{
    PLAN_ADAPTER Adapter = (PLAN_ADAPTER)BindingContext;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    Adapter->NdisStatus = Status;

    KeSetEvent(&Adapter->Event, 0, FALSE);
}


VOID NTAPI ProtocolResetComplete(
    NDIS_HANDLE BindingContext,
    NDIS_STATUS Status)
/*
 * FUNCTION: Called by NDIS to complete resetting an adapter
 * ARGUMENTS:
 *     BindingContext = Pointer to a device context (LAN_ADAPTER)
 *     Status         = Status of the operation
 */
{
    PLAN_ADAPTER Adapter = (PLAN_ADAPTER)BindingContext;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    Adapter->NdisStatus = Status;

    KeSetEvent(&Adapter->Event, 0, FALSE);
}


VOID NTAPI ProtocolRequestComplete(
    NDIS_HANDLE BindingContext,
    PNDIS_REQUEST NdisRequest,
    NDIS_STATUS Status)
/*
 * FUNCTION: Called by NDIS to complete a request
 * ARGUMENTS:
 *     BindingContext = Pointer to a device context (LAN_ADAPTER)
 *     NdisRequest    = Pointer to an object describing the request
 *     Status         = Status of the operation
 */
{
    PLAN_REQUEST Request = CONTAINING_RECORD(NdisRequest, LAN_REQUEST, Request);

    UNREFERENCED_PARAMETER(BindingContext);

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    /* Save the status of this request and wake the one waiting for it */
    Request->Status = Status;

    KeSetEvent(&Request->Event, IO_NO_INCREMENT, FALSE);
}


VOID NTAPI ProtocolSendComplete(
    NDIS_HANDLE BindingContext,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status)
/*
 * FUNCTION: Called by NDIS to complete sending process
 * ARGUMENTS:
 *     BindingContext = Pointer to a device context (LAN_ADAPTER)
 *     Packet         = Pointer to a packet descriptor
 *     Status         = Status of the operation
 */
{
    FreeNdisPacket(Packet);
}

static VOID LanReceivePacket(
    PLAN_ADAPTER Adapter,
    PNDIS_PACKET Packet,
    UINT BytesTransferred,
    BOOLEAN LegacyReceive,
    BOOLEAN FromOwnLink);

/* The bytes in the buffers of a packet a miniport lent us, counted from the buffer chain.
   NdisQueryPacketLength returns the length cached in the packet from its first query, and a
   miniport that resizes a recycled receive buffer for each frame (NdisAdjustBufferLength)
   without NdisRecalculatePacketCounts leaves the cache at the length of the first frame the
   packet carried. Frames longer than that then failed the length check of IPv4Receive: a
   lending dc21x4 lost the data segments that followed a short frame in its buffer and the TCP
   window collapsed until the sender retransmitted (0.03 MB/s on QEMU user networking) */
static UINT LanLentPacketLength(PNDIS_PACKET Packet) {
    PNDIS_BUFFER Buffer;
    UINT Length = 0;

    NdisQueryPacket(Packet, NULL, NULL, &Buffer, NULL);
    while (Buffer) {
        Length += MmGetMdlByteCount(Buffer);
        NdisGetNextBuffer(Buffer, &Buffer);
    }

    return Length;
}

static VOID LanReceiveItem( PLAN_WQ_ITEM WorkItem ) {
    PNDIS_PACKET Packet;
    PLAN_ADAPTER Adapter;
    UINT BytesTransferred;
    BOOLEAN LegacyReceive, Held, FromOwnLink;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    Packet = WorkItem->Packet;
    Adapter = WorkItem->Adapter;
    BytesTransferred = WorkItem->BytesTransferred;
    LegacyReceive = WorkItem->LegacyReceive;
    Held = WorkItem->Held;
    FromOwnLink = WorkItem->FromOwnLink;

    ExFreePoolWithTag(WorkItem, WQ_CONTEXT_TAG);

    LanReceivePacket(Adapter, Packet, BytesTransferred, LegacyReceive, FromOwnLink);

    /* The miniport's packet has left the queue */
    if (Held)
        InterlockedDecrement(&Adapter->HeldPackets);
}

static VOID LanReceiveWorker( PLIST_ENTRY Entry ) {
    LanReceiveItem(CONTAINING_RECORD(Entry, LAN_WQ_ITEM, ListEntry));
}

static VOID LanReceiveWorkItem( PVOID Context ) {
    PLAN_ADAPTER Adapter = ((PLAN_WQ_ITEM)Context)->Adapter;

    LanReceiveItem(Context);

    /* LANUnregisterAdapter waits for this */
    InterlockedDecrement(&Adapter->ReceiveWorkItems);
}

/* The unicast and the other (broadcast, multicast) frames are counted apart, as MIB-II ifInUcastPkts and
   ifInNUcastPkts: GetIfEntry and the .NET interface statistics read them */
static VOID LanCountReceivedFrame(
    PLAN_ADAPTER Adapter,
    BOOLEAN NonUnicast) {
    PIP_INTERFACE Interface = Adapter->Context;

    if (!Interface)
        return;

    if (NonUnicast)
        InterlockedIncrement((PLONG)&Interface->Stats.InNUnicast);
    else
        InterlockedIncrement((PLONG)&Interface->Stats.InUnicast);
}

static VOID LanReceivePacket(
    PLAN_ADAPTER Adapter,
    PNDIS_PACKET Packet,
    UINT BytesTransferred,
    BOOLEAN LegacyReceive,
    BOOLEAN FromOwnLink) {
    ULONG PacketType;
    BOOLEAN NonUnicast = FALSE;
    IP_PACKET IPPacket;
    PIP_INTERFACE Interface;

    Interface = Adapter->Context;

    IPInitializePacket(&IPPacket, 0);

    IPPacket.NdisPacket = Packet;
    IPPacket.ReturnPacket = !LegacyReceive;

    if (LegacyReceive)
    {
        /* Packet type is precomputed */
        PacketType = PC(IPPacket.NdisPacket)->PacketType;
        IPPacket.FromOwnLink = PC(IPPacket.NdisPacket)->FromOwnLink;

        /* Data is at position 0 */
        IPPacket.Position = 0;

        /* Packet size is determined by bytes transferred */
        IPPacket.TotalSize = BytesTransferred;
    }
    else
    {
        /* Determine packet type from media header */
        if (GetPacketTypeFromNdisPacket(Adapter,
                                        IPPacket.NdisPacket,
                                        &PacketType,
                                        &NonUnicast) != NDIS_STATUS_SUCCESS)
        {
            /* Bad packet */
            IPPacket.Free(&IPPacket);
            return;
        }

        /* A legacy receive was counted by ProtocolReceive or LanSubmitReceiveCopy, which had the header */
        LanCountReceivedFrame(Adapter, NonUnicast);
        IPPacket.FromOwnLink = FromOwnLink;

        /* Data is at the end of the media header */
        IPPacket.Position = Adapter->HeaderSize;

        /* Calculate packet size (excluding media header) */
        IPPacket.TotalSize = LanLentPacketLength(IPPacket.NdisPacket);
    }

    TI_DbgPrint
	(DEBUG_DATALINK,
	 ("Ether Type = %x Total = %d\n",
	  PacketType, IPPacket.TotalSize));

    /* Update interface stats */
    Interface->Stats.InBytes += IPPacket.TotalSize + Adapter->HeaderSize;

    /* NDIS packet is freed in all of these cases */
    switch (PacketType) {
        case ETYPE_IPv4:
        case ETYPE_IPv6:
            TI_DbgPrint(MID_TRACE,("Received IP Packet\n"));
            /* The receive worker hands TDI completions to other threads (see CompleteBucket) */
            TCPEnterReceiveWorker();
            IPReceive(Adapter->Context, &IPPacket);
            TCPLeaveReceiveWorker();
            break;
        case ETYPE_ARP:
            TI_DbgPrint(MID_TRACE,("Received ARP Packet\n"));
            ARPReceive(Adapter->Context, &IPPacket);
            break;
        default:
            IPPacket.Free(&IPPacket);
            break;
    }
}

/* An IPv4 TCP segment; the packet is a frame, or the data after the frame's
   media header (LegacyReceive) */
static BOOLEAN LanIsTcpPacket(
    PLAN_ADAPTER Adapter,
    PNDIS_PACKET Packet,
    BOOLEAN LegacyReceive) {
    UCHAR Header[sizeof(ETH_HEADER) + 10];
    UINT Offset = 0;

    if (LegacyReceive) {
        if (PC(Packet)->PacketType != ETYPE_IPv4 ||
            CopyPacketToBuffer((PCHAR)Header, Packet, 0, 10) != 10)
            return FALSE;
    } else {
        if (Adapter->Media != NdisMedium802_3 ||
            CopyPacketToBuffer((PCHAR)Header, Packet, 0, sizeof(Header)) != sizeof(Header) ||
            ((PETH_HEADER)Header)->EType != ETYPE_IPv4)
            return FALSE;
        Offset = sizeof(ETH_HEADER);
    }

    /* Version 4, protocol TCP */
    return (Header[Offset] >> 4) == 4 && Header[Offset + 9] == IPPROTO_TCP;
}

/* Returns FALSE if the packet was not queued; the caller still owns it then.
   Tcp is LanIsTcpPacket's answer for the packet */
BOOLEAN LanSubmitReceiveWork(
    NDIS_HANDLE BindingContext,
    PNDIS_PACKET Packet,
    UINT BytesTransferred,
    BOOLEAN LegacyReceive,
    BOOLEAN Tcp,
    BOOLEAN FromOwnLink) {
    PLAN_WQ_ITEM WQItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(LAN_WQ_ITEM),
                                                WQ_CONTEXT_TAG);
    PLAN_ADAPTER Adapter = (PLAN_ADAPTER)BindingContext;
    BOOLEAN Queued;

    TI_DbgPrint(DEBUG_DATALINK,("called\n"));

    if (!WQItem) return FALSE;

    WQItem->Packet = Packet;
    WQItem->Adapter = Adapter;
    WQItem->BytesTransferred = BytesTransferred;
    WQItem->LegacyReceive = LegacyReceive;
    WQItem->Held = Tcp && !LegacyReceive;
    WQItem->FromOwnLink = FromOwnLink;

    /* TCP segments go through one worker per adapter, so they reach TCP in the order
       they were indicated. Other frames keep a work item each: nothing they wait for
       (an ARP reply, a socket's lock) can hold up TCP or each other */
    if (Tcp) {
        Queued = ChewSerialInsert(&Adapter->ReceiveQueue, &WQItem->ListEntry);
    } else {
        if (InterlockedIncrement(&Adapter->ReceiveWorkItems) > LAN_MAX_PENDING_FRAMES) {
            Queued = FALSE;
        } else {
            Queued = ChewCreate(LanReceiveWorkItem, WQItem);
        }
        if (!Queued)
            InterlockedDecrement(&Adapter->ReceiveWorkItems);
    }

    if (!Queued) {
        ExFreePoolWithTag(WQItem, WQ_CONTEXT_TAG);
        return FALSE;
    }

    return TRUE;
}

VOID NTAPI ProtocolTransferDataComplete(
    NDIS_HANDLE BindingContext,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status,
    UINT BytesTransferred)
/*
 * FUNCTION: Called by NDIS to complete reception of data
 * ARGUMENTS:
 *     BindingContext   = Pointer to a device context (LAN_ADAPTER)
 *     Packet           = Pointer to a packet descriptor
 *     Status           = Status of the operation
 *     BytesTransferred = Number of bytes transferred
 * NOTES:
 *     If the packet was successfully received, determine the protocol
 *     type and pass it to the correct receive handler
 */
{
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    TI_DbgPrint(DEBUG_DATALINK,("called\n"));

    TransferDataCompleteCalled++;
    ASSERT(TransferDataCompleteCalled <= TransferDataCalled);

    /* The packet is ours (ProtocolReceive allocated it for the transfer): a failed transfer,
       such as one that NDIS fails at the halt of the miniport, frees it too */
    if( Status != NDIS_STATUS_SUCCESS ) {
        FreeNdisPacket(Packet);
        return;
    }

    if (!LanSubmitReceiveWork(BindingContext,
                              Packet,
                              BytesTransferred,
                              TRUE,
                              LanIsTcpPacket(BindingContext, Packet, TRUE),
                              FALSE /* unused: the tag was kept in the packet context */))
        FreeNdisPacket(Packet);
}

/* Queues a copy of a miniport's TCP segment, as ProtocolReceive does */
static VOID LanSubmitReceiveCopy(
    PLAN_ADAPTER Adapter,
    PNDIS_PACKET NdisPacket) {
    PNDIS_PACKET Copy;
    ULONG PacketType;
    BOOLEAN NonUnicast = FALSE;
    UINT Length, Size;
    PCHAR Data;

    Length = LanLentPacketLength(NdisPacket);
    if (Length <= Adapter->HeaderSize ||
        GetPacketTypeFromNdisPacket(Adapter, NdisPacket, &PacketType, &NonUnicast) != NDIS_STATUS_SUCCESS)
        return;

    Length -= Adapter->HeaderSize;
    if (AllocatePacketWithBuffer(&Copy, NULL, Length) != NDIS_STATUS_SUCCESS)
        return;

    GetDataPtr(Copy, 0, &Data, &Size);
    CopyPacketToBuffer(Data, NdisPacket, Adapter->HeaderSize, Length);
    PC(Copy)->PacketType = PacketType;
    PC(Copy)->FromOwnLink = LanNdisPacketLoopTagged(Adapter, NdisPacket);

    LanCountReceivedFrame(Adapter, NonUnicast);

    if (!LanSubmitReceiveWork(Adapter, Copy, Length, TRUE, TRUE, FALSE))
        FreeNdisPacket(Copy);
}

INT NTAPI ProtocolReceivePacket(
    NDIS_HANDLE BindingContext,
    PNDIS_PACKET NdisPacket)
{
    PLAN_ADAPTER Adapter = BindingContext;
    BOOLEAN Tcp, FromOwnLink;

    if (Adapter->State != LAN_STATE_STARTED) {
        TI_DbgPrint(DEBUG_DATALINK, ("Adapter is stopped.\n"));
        return 0;
    }

    Tcp = LanIsTcpPacket(Adapter, NdisPacket, FALSE);
    FromOwnLink = LanNdisPacketLoopTagged(Adapter, NdisPacket);   /* only valid here, inside the indication */

    if (Tcp && InterlockedIncrement(&Adapter->HeldPackets) > LAN_MAX_HELD_PACKETS) {
        InterlockedDecrement(&Adapter->HeldPackets);
        LanSubmitReceiveCopy(Adapter, NdisPacket);
        return 0;
    }

    if (!LanSubmitReceiveWork(BindingContext,
                              NdisPacket,
                              0, /* Unused */
                              FALSE,
                              Tcp,
                              FromOwnLink)) {
        if (Tcp)
            InterlockedDecrement(&Adapter->HeldPackets);
        return 0;
    }

    /* Hold 1 reference on this packet */
    return 1;
}

NDIS_STATUS NTAPI ProtocolReceive(
    NDIS_HANDLE BindingContext,
    NDIS_HANDLE MacReceiveContext,
    PVOID HeaderBuffer,
    UINT HeaderBufferSize,
    PVOID LookaheadBuffer,
    UINT LookaheadBufferSize,
    UINT PacketSize)
/*
 * FUNCTION: Called by NDIS when a packet has been received on the physical link
 * ARGUMENTS:
 *     BindingContext      = Pointer to a device context (LAN_ADAPTER)
 *     MacReceiveContext   = Handle used by underlying NIC driver
 *     HeaderBuffer        = Pointer to a buffer containing the packet header
 *     HeaderBufferSize    = Number of bytes in HeaderBuffer
 *     LookaheadBuffer     = Pointer to a buffer containing buffered packet data
 *     LookaheadBufferSize = Size of LookaheadBuffer. May be less than asked for
 *     PacketSize          = Overall size of the packet (not including header)
 * RETURNS:
 *     Status of operation
 */
{
    ULONG PacketType;
    BOOLEAN NonUnicast = FALSE;
    UINT BytesTransferred;
    PCHAR BufferData;
    NDIS_STATUS NdisStatus;
    PNDIS_PACKET NdisPacket;
    PLAN_ADAPTER Adapter = (PLAN_ADAPTER)BindingContext;

    TI_DbgPrint(DEBUG_DATALINK, ("Called. (packetsize %d)\n",PacketSize));

    if (Adapter->State != LAN_STATE_STARTED) {
        TI_DbgPrint(DEBUG_DATALINK, ("Adapter is stopped.\n"));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    if (HeaderBufferSize < Adapter->HeaderSize) {
        TI_DbgPrint(DEBUG_DATALINK, ("Runt frame received.\n"));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    NdisStatus = GetPacketTypeFromHeaderBuffer(Adapter,
                                               HeaderBuffer,
                                               HeaderBufferSize,
                                               &PacketType,
                                               &NonUnicast);
    if (NdisStatus != NDIS_STATUS_SUCCESS)
        return NDIS_STATUS_NOT_ACCEPTED;

    LanCountReceivedFrame(Adapter, NonUnicast);

    TI_DbgPrint(DEBUG_DATALINK, ("Adapter: %x (MTU %d)\n",
				 Adapter, Adapter->MTU));

    /* Get a transfer data packet */
    NdisStatus = AllocatePacketWithBuffer( &NdisPacket, NULL,
                                           PacketSize );
    if( NdisStatus != NDIS_STATUS_SUCCESS ) {
	return NDIS_STATUS_NOT_ACCEPTED;
    }

    PC(NdisPacket)->PacketType = PacketType;
    PC(NdisPacket)->FromOwnLink = LanLoopTagged(Adapter, HeaderBuffer, HeaderBufferSize);

    TI_DbgPrint(DEBUG_DATALINK, ("pretransfer LookaheadBufferSize %d packsize %d\n",LookaheadBufferSize,PacketSize));

    GetDataPtr( NdisPacket, 0, &BufferData, &PacketSize );

    TransferDataCalled++;

    if (LookaheadBufferSize == PacketSize)
    {
        /* Optimized code path for packets that are fully contained in
         * the lookahead buffer. */
        NdisCopyLookaheadData(BufferData,
                              LookaheadBuffer,
                              LookaheadBufferSize,
                              Adapter->MacOptions);
        /* The whole packet was copied from the lookahead buffer */
        BytesTransferred = PacketSize;
    }
    else
    {
        NdisTransferData(&NdisStatus, Adapter->NdisHandle,
                         MacReceiveContext, 0, PacketSize,
			 NdisPacket, &BytesTransferred);
    }
    TI_DbgPrint(DEBUG_DATALINK, ("Calling complete\n"));

    /* Complete with the count actually transferred, not the requested size, so a
       short synchronous transfer does not advertise an uninitialized tail. */
    if (NdisStatus != NDIS_STATUS_PENDING)
	ProtocolTransferDataComplete(BindingContext,
				     NdisPacket,
				     NdisStatus,
				     BytesTransferred);

    TI_DbgPrint(DEBUG_DATALINK, ("leaving\n"));

    return NDIS_STATUS_SUCCESS;
}


VOID NTAPI ProtocolReceiveComplete(
    NDIS_HANDLE BindingContext)
/*
 * FUNCTION: Called by NDIS when we're done receiving data
 * ARGUMENTS:
 *     BindingContext = Pointer to a device context (LAN_ADAPTER)
 */
{
    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));
}

BOOLEAN ReadIpConfiguration(PIP_INTERFACE Interface)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ParameterHandle;
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
    ULONG KeyValueInfoLength;
    WCHAR Buffer[150];
    UNICODE_STRING IPAddress = RTL_CONSTANT_STRING(L"IPAddress");
    UNICODE_STRING Netmask = RTL_CONSTANT_STRING(L"SubnetMask");
    UNICODE_STRING Gateway = RTL_CONSTANT_STRING(L"DefaultGateway");
    UNICODE_STRING EnableDhcp = RTL_CONSTANT_STRING(L"EnableDHCP");
    UNICODE_STRING InterfaceMetric = RTL_CONSTANT_STRING(L"InterfaceMetric");
    UNICODE_STRING Prefix = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\");
    UNICODE_STRING TcpipRegistryPath;
    UNICODE_STRING RegistryDataU;
    ANSI_STRING RegistryDataA;
    ULONG Unused;
    NTSTATUS Status;
    IP_ADDRESS DefaultMask, Router;

    AddrInitIPv4(&DefaultMask, 0);

    TcpipRegistryPath.MaximumLength = sizeof(WCHAR) * 150;
    TcpipRegistryPath.Length = 0;
    TcpipRegistryPath.Buffer = Buffer;

    /* Build the registry path */
    RtlAppendUnicodeStringToString(&TcpipRegistryPath, &Prefix);
    RtlAppendUnicodeStringToString(&TcpipRegistryPath, &Interface->Name);

    InitializeObjectAttributes(&ObjectAttributes,
                               &TcpipRegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               0,
                               NULL);

    /* Open a handle to the adapter parameters */
    Status = ZwOpenKey(&ParameterHandle, KEY_READ, &ObjectAttributes);

    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }
    else
    {
        KeyValueInfoLength = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + 16 * sizeof(WCHAR);
        KeyValueInfo = ExAllocatePoolWithTag(PagedPool,
                                             KeyValueInfoLength,
                                             KEY_VALUE_TAG);
        if (!KeyValueInfo)
        {
            ZwClose(ParameterHandle);
            return FALSE;
        }

        /* Read the InterfaceMetric value */
        Interface->Metric = 0;
        Status = ZwQueryValueKey(ParameterHandle,
                                 &InterfaceMetric,
                                 KeyValuePartialInformation,
                                 KeyValueInfo,
                                 KeyValueInfoLength,
                                 &Unused);
        if (NT_SUCCESS(Status) && KeyValueInfo->DataLength == sizeof(ULONG))
        {
            Interface->Metric = (UINT)*(PULONG)KeyValueInfo->Data;
            if (Interface->Metric > 9999)
                Interface->Metric = 9999;
        }

        /* Read the EnableDHCP entry */
        Status = ZwQueryValueKey(ParameterHandle,
                                 &EnableDhcp,
                                 KeyValuePartialInformation,
                                 KeyValueInfo,
                                 KeyValueInfoLength,
                                 &Unused);
        if (NT_SUCCESS(Status) && KeyValueInfo->DataLength == sizeof(ULONG) && (*(PULONG)KeyValueInfo->Data) == 0)
        {
            RegistryDataU.MaximumLength = KeyValueInfoLength - FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
            RegistryDataU.Buffer = (PWCHAR)KeyValueInfo->Data;

            /* Read the IP address */
            Status = ZwQueryValueKey(ParameterHandle,
                                     &IPAddress,
                                     KeyValuePartialInformation,
                                     KeyValueInfo,
                                     KeyValueInfoLength,
                                     &Unused);
            if (NT_SUCCESS(Status))
            {
                RegistryDataU.Length = KeyValueInfo->DataLength;

                Status = RtlUnicodeStringToAnsiString(&RegistryDataA,
                                                      &RegistryDataU,
                                                      TRUE);
                if (NT_SUCCESS(Status))
                {
                    AddrInitIPv4(&Interface->Unicast,
                                 inet_addr(RegistryDataA.Buffer));
                    RtlFreeAnsiString(&RegistryDataA);
                }
            }

            Status = ZwQueryValueKey(ParameterHandle,
                                     &Netmask,
                                     KeyValuePartialInformation,
                                     KeyValueInfo,
                                     KeyValueInfoLength,
                                     &Unused);
            if (NT_SUCCESS(Status))
            {
                RegistryDataU.Length = KeyValueInfo->DataLength;

                Status = RtlUnicodeStringToAnsiString(&RegistryDataA,
                                                      &RegistryDataU,
                                                      TRUE);
                if (NT_SUCCESS(Status))
                {
                    AddrInitIPv4(&Interface->Netmask,
                                 inet_addr(RegistryDataA.Buffer));
                    RtlFreeAnsiString(&RegistryDataA);
                }
            }

            /* We have to wait until both IP address and subnet mask
             * are read to add the interface route, but we must do it
             * before we add the default gateway */
            if (!AddrIsUnspecified(&Interface->Unicast) &&
                !AddrIsUnspecified(&Interface->Netmask))
                IPAddInterfaceRoute(Interface);

            /* Read default gateway info */
            Status = ZwQueryValueKey(ParameterHandle,
                                     &Gateway,
                                     KeyValuePartialInformation,
                                     KeyValueInfo,
                                     KeyValueInfoLength,
                                     &Unused);
            if (NT_SUCCESS(Status))
            {
                RegistryDataU.Length = KeyValueInfo->DataLength;

                Status = RtlUnicodeStringToAnsiString(&RegistryDataA,
                                                      &RegistryDataU,
                                                      TRUE);
                if (NT_SUCCESS(Status))
                {
                    AddrInitIPv4(&Router, inet_addr(RegistryDataA.Buffer));

                    if (!AddrIsUnspecified(&Router))
                        RouterCreateRoute(&DefaultMask, &DefaultMask, &Router, Interface);

                    RtlFreeAnsiString(&RegistryDataA);
                }
            }
        }

        ExFreePoolWithTag(KeyValueInfo, KEY_VALUE_TAG);
        ZwClose(ParameterHandle);
    }

    return TRUE;
}

BOOLEAN ReconfigureAdapter(PRECONFIGURE_CONTEXT Context)
{
    PLAN_ADAPTER Adapter = Context->Adapter;
    PIP_INTERFACE Interface = Adapter->Context;
    NDIS_STATUS NdisStatus;
    IP_ADDRESS DefaultMask;

    /* Initialize the default unspecified address (0.0.0.0) */
    AddrInitIPv4(&DefaultMask, 0);
    if (Context->State == LAN_STATE_STARTED &&
        !Context->Adapter->CompletingReset)
    {
        /* Read the IP configuration */
        ReadIpConfiguration(Interface);

        /* Compute the broadcast address */
        Interface->Broadcast.Type = IP_ADDRESS_V4;
        Interface->Broadcast.Address.IPv4Address = Interface->Unicast.Address.IPv4Address |
                                                  ~Interface->Netmask.Address.IPv4Address;
    }
    else if (!Context->Adapter->CompletingReset)
    {
        /* Clear IP configuration */
        Interface->Unicast = DefaultMask;
        Interface->Netmask = DefaultMask;
        Interface->Broadcast = DefaultMask;

        /* Remove all interface routes */
        RouterRemoveRoutesForInterface(Interface);

        /* Destroy all cached neighbors */
        NBDestroyNeighborsForInterface(Interface);
    }

    Context->Adapter->CompletingReset = FALSE;

    if (Context->State == LAN_STATE_STARTED)
    {
        /* Get maximum link speed */
        NdisStatus = NDISCall(Adapter,
                              NdisRequestQueryInformation,
                              OID_GEN_LINK_SPEED,
                              &Interface->Speed,
                              sizeof(Interface->Speed));

        if (!NT_SUCCESS(NdisStatus))
            Interface->Speed = IP_DEFAULT_LINK_SPEED;

        Adapter->Speed = Interface->Speed * 100L;

        /* Get maximum frame size */
        NdisStatus = NDISCall(Adapter,
                              NdisRequestQueryInformation,
                              OID_GEN_MAXIMUM_FRAME_SIZE,
                              &Adapter->MTU,
                              sizeof(Adapter->MTU));
        if (NdisStatus != NDIS_STATUS_SUCCESS)
            return FALSE;

        Interface->MTU = Adapter->MTU;

        /* Get maximum packet size */
        NdisStatus = NDISCall(Adapter,
                              NdisRequestQueryInformation,
                              OID_GEN_MAXIMUM_TOTAL_SIZE,
                              &Adapter->MaxPacketSize,
                              sizeof(Adapter->MaxPacketSize));
        if (NdisStatus != NDIS_STATUS_SUCCESS)
            return FALSE;
    }

    Adapter->State = Context->State;

    /* Update the IP and link status information cached in TCP */
    TCPUpdateInterfaceIPInformation(Interface);
    TCPUpdateInterfaceLinkStatus(Interface);

    return TRUE;
}

VOID ReconfigureAdapterWorker(PVOID Context)
{
    PLAN_ADAPTER Adapter = Context;
    RECONFIGURE_CONTEXT ReconfigureContext;
    BOOLEAN ResetEnd, Success;
    ULONG Requests;
    KIRQL OldIrql;

    ReconfigureContext.Adapter = Adapter;

    /* Apply the latest requested state until no new request came in meanwhile */
    TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
    for (;;)
    {
        Requests = Adapter->ReconfigureRequests;
        ReconfigureContext.State = Adapter->QueuedState;
        ResetEnd = Adapter->QueuedResetEnd;
        Adapter->QueuedResetEnd = FALSE;
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);

        /*
         * A link that went down and came back before this pass needs nothing.
         * After a reset, only the link information of the restored state is
         * read again; a media change since then needs a full reconfiguration.
         */
        Success = TRUE;
        if (ResetEnd || ReconfigureContext.State != Adapter->State)
        {
            Adapter->CompletingReset = (ReconfigureContext.State == Adapter->State);
            Success = ReconfigureAdapter(&ReconfigureContext);
            /* the link went up or down: the usable addresses changed */
            AddrChangeNotify();
        }

        TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
        if (Requests == Adapter->ReconfigureRequests)
        {
            /* Let the next indication retry a reconfiguration that failed */
            if (!Success)
                Adapter->QueuedState = LAN_STATE_OPENING;
            Adapter->ReconfigureQueued = FALSE;
            break;
        }
    }
    TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
}

VOID NTAPI ProtocolStatus(
    NDIS_HANDLE BindingContext,
    NDIS_STATUS GeneralStatus,
    PVOID StatusBuffer,
    UINT StatusBufferSize)
/*
 * FUNCTION: Called by NDIS when the underlying driver has changed state
 * ARGUMENTS:
 *     BindingContext   = Pointer to a device context (LAN_ADAPTER)
 *     GeneralStatus    = A general status code
 *     StatusBuffer     = Pointer to a buffer with medium-specific data
 *     StatusBufferSize = Number of bytes in StatusBuffer
 */
{
    PLAN_ADAPTER Adapter = BindingContext;
    UCHAR State = LAN_STATE_OPENING;
    BOOLEAN ResetEnd = FALSE, QueueWorker = FALSE;
    KIRQL OldIrql;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    /* Ignore the status indication if we have no context yet. We'll get another later */
    if (!Adapter->Context)
        return;

    /*
     * NDIS calls this with the miniport lock held, and LANTransmit calls
     * NdisSend with Adapter->Lock held, so only the reconfiguration lock is
     * taken here.
     */
    switch(GeneralStatus)
    {
        case NDIS_STATUS_MEDIA_CONNECT:
            DbgPrint("NDIS_STATUS_MEDIA_CONNECT\n");
            State = LAN_STATE_STARTED;
            break;

        case NDIS_STATUS_MEDIA_DISCONNECT:
            DbgPrint("NDIS_STATUS_MEDIA_DISCONNECT\n");
            State = LAN_STATE_STOPPED;
            break;

        case NDIS_STATUS_RESET_START:
            Adapter->OldState = Adapter->State;
            Adapter->State = LAN_STATE_RESETTING;
            /* Nothing else to do here */
            return;

        case NDIS_STATUS_RESET_END:
            /*
             * The adapter takes requests again: go back to the state applied
             * before the reset at once, so that the worker can query it. A
             * media change requested meanwhile stays requested.
             */
            Adapter->State = Adapter->OldState;
            ResetEnd = TRUE;
            break;

        default:
            DbgPrint("Unhandled status: %x", GeneralStatus);
            return;
    }

    /*
     * One worker per adapter applies the latest request. A media change is
     * compared with the last request, not with the state applied so far, so
     * that a quick disconnect and reconnect does not leave the adapter
     * stopped.
     */
    TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
    if (Adapter->Unbinding)
    {
        /* The adapter goes away: LANUnregisterAdapter waits for the worker that runs, none starts */
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
        return;
    }
    if (ResetEnd)
    {
        /* Never filtered: the worker reads the link information again */
        Adapter->QueuedResetEnd = TRUE;
        if (Adapter->QueuedState == LAN_STATE_OPENING)
            Adapter->QueuedState = Adapter->OldState;
    }
    else if (State == Adapter->QueuedState)
    {
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
        return;
    }
    else
    {
        Adapter->QueuedState = State;
    }
    Adapter->ReconfigureRequests++;
    if (!Adapter->ReconfigureQueued)
    {
        Adapter->ReconfigureQueued = TRUE;
        QueueWorker = TRUE;
    }
    TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);

    if (QueueWorker && !ChewCreate(ReconfigureAdapterWorker, Adapter))
    {
        /* Do not filter the next indication against a request that was lost */
        TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
        Adapter->ReconfigureQueued = FALSE;
        Adapter->QueuedResetEnd = FALSE;
        Adapter->QueuedState = LAN_STATE_OPENING;
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
    }
}

VOID NTAPI ProtocolStatusComplete(NDIS_HANDLE NdisBindingContext)
/*
 * FUNCTION: Called by NDIS when a status-change has occurred
 * ARGUMENTS:
 *     BindingContext = Pointer to a device context (LAN_ADAPTER)
 */
{
    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));
}

NDIS_STATUS NTAPI
ProtocolPnPEvent(
    NDIS_HANDLE NdisBindingContext,
    PNET_PNP_EVENT PnPEvent)
{
    switch(PnPEvent->NetEvent)
    {
      case NetEventSetPower:
         DbgPrint("Device transitioned to power state %ld\n", PnPEvent->Buffer);
         return NDIS_STATUS_SUCCESS;

      case NetEventQueryPower:
         DbgPrint("Device wants to go into power state %ld\n", PnPEvent->Buffer);
         return NDIS_STATUS_SUCCESS;

      case NetEventQueryRemoveDevice:
         DbgPrint("Device is about to be removed\n");
         return NDIS_STATUS_SUCCESS;

      case NetEventCancelRemoveDevice:
         DbgPrint("Device removal cancelled\n");
         return NDIS_STATUS_SUCCESS;

      default:
         DbgPrint("Unhandled event type: %ld\n", PnPEvent->NetEvent);
         return NDIS_STATUS_SUCCESS;
    }
}

VOID NTAPI ProtocolBindAdapter(
    OUT PNDIS_STATUS   Status,
    IN  NDIS_HANDLE    BindContext,
    IN  PNDIS_STRING   DeviceName,
    IN  PVOID          SystemSpecific1,
    IN  PVOID          SystemSpecific2)
/*
 * FUNCTION: Called by NDIS during NdisRegisterProtocol to set up initial
 *           bindings, and periodically thereafter as new adapters come online
 * ARGUMENTS:
 *     Status: Return value to NDIS
 *     BindContext: Handle provided by NDIS to track pending binding operations
 *     DeviceName: Name of the miniport device to bind to
 *     SystemSpecific1: Pointer to a registry path with protocol-specific configuration information
 *     SystemSpecific2: Unused & must not be touched
 */
{
    TI_DbgPrint(DEBUG_DATALINK, ("Called with registry path %wZ for %wZ\n", SystemSpecific1, DeviceName));
    *Status = LANRegisterAdapter(DeviceName, SystemSpecific1);
}


VOID LANTransmit(
    PVOID Context,
    PNDIS_PACKET NdisPacket,
    UINT Offset,
    PVOID LinkAddress,
    USHORT Type)
/*
 * FUNCTION: Transmits a packet
 * ARGUMENTS:
 *     Context     = Pointer to context information (LAN_ADAPTER)
 *     NdisPacket  = Pointer to NDIS packet to send
 *     Offset      = Offset in packet where data starts
 *     LinkAddress = Pointer to link address of destination (NULL = broadcast)
 *     Type        = LAN protocol type (LAN_PROTO_*)
 */
{
    NDIS_STATUS NdisStatus;
    PETH_HEADER EHeader;
    PCHAR Data, OldData;
    UINT Size, OldSize;
    PLAN_ADAPTER Adapter = (PLAN_ADAPTER)Context;
    KIRQL OldIrql;
    PNDIS_PACKET XmitPacket;
    PIP_INTERFACE Interface = Adapter->Context;

    TI_DbgPrint(DEBUG_DATALINK,
		("Called( NdisPacket %x, Offset %d, Adapter %x )\n",
		 NdisPacket, Offset, Adapter));

    if (Adapter->State != LAN_STATE_STARTED) {
        (*PC(NdisPacket)->DLComplete)(PC(NdisPacket)->Context, NdisPacket, NDIS_STATUS_NOT_ACCEPTED);
        return;
    }

    TI_DbgPrint(DEBUG_DATALINK,
		("Adapter Address [%02x %02x %02x %02x %02x %02x]\n",
		 Adapter->HWAddress[0] & 0xff,
		 Adapter->HWAddress[1] & 0xff,
		 Adapter->HWAddress[2] & 0xff,
		 Adapter->HWAddress[3] & 0xff,
		 Adapter->HWAddress[4] & 0xff,
		 Adapter->HWAddress[5] & 0xff));

    GetDataPtr( NdisPacket, 0, &OldData, &OldSize );

    NdisStatus = AllocatePacketWithBuffer(&XmitPacket, NULL, OldSize + Adapter->HeaderSize);
    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        (*PC(NdisPacket)->DLComplete)(PC(NdisPacket)->Context, NdisPacket, NDIS_STATUS_RESOURCES);
        return;
    }

    GetDataPtr(XmitPacket, 0, &Data, &Size);

    RtlCopyMemory(Data + Adapter->HeaderSize, OldData, OldSize);

    (*PC(NdisPacket)->DLComplete)(PC(NdisPacket)->Context, NdisPacket, NDIS_STATUS_SUCCESS);

    switch (Adapter->Media) {
        case NdisMedium802_3:
            EHeader = (PETH_HEADER)Data;

            if (LinkAddress) {
                /* Unicast address */
                RtlCopyMemory(EHeader->DstAddr, LinkAddress, IEEE_802_ADDR_LENGTH);
            } else {
                /* Broadcast address */
                RtlFillMemory(EHeader->DstAddr, IEEE_802_ADDR_LENGTH, 0xFF);
            }

            RtlCopyMemory(EHeader->SrcAddr, Adapter->HWAddress, IEEE_802_ADDR_LENGTH);

            switch (Type) {
                case LAN_PROTO_IPv4:
                    EHeader->EType = ETYPE_IPv4;
                    break;
                case LAN_PROTO_ARP:
                    EHeader->EType = ETYPE_ARP;
                    break;
                case LAN_PROTO_IPv6:
                    EHeader->EType = ETYPE_IPv6;
                    break;
                default:
                    ASSERT(FALSE);
                    return;
            }
            break;

        default:
            /* FIXME: Support other medias */
            break;
    }

	TI_DbgPrint( MID_TRACE, ("LinkAddress: %x\n", LinkAddress));
	if( LinkAddress ) {
	    TI_DbgPrint
		( MID_TRACE,
		  ("Link Address [%02x %02x %02x %02x %02x %02x]\n",
		   ((PCHAR)LinkAddress)[0] & 0xff,
		   ((PCHAR)LinkAddress)[1] & 0xff,
		   ((PCHAR)LinkAddress)[2] & 0xff,
		   ((PCHAR)LinkAddress)[3] & 0xff,
		   ((PCHAR)LinkAddress)[4] & 0xff,
		   ((PCHAR)LinkAddress)[5] & 0xff));
	}

    /* Update interface stats: the frames to a broadcast or multicast address are counted apart from the
       unicast ones, as MIB-II ifOutUcastPkts and ifOutNUcastPkts */
    Interface->Stats.OutBytes += Size;
    if (!LinkAddress || (((PUCHAR)LinkAddress)[0] & BCAST_ETH_MASK))
        InterlockedIncrement((PLONG)&Interface->Stats.OutNUnicast);
    else
        InterlockedIncrement((PLONG)&Interface->Stats.OutUnicast);

	TcpipAcquireSpinLock( &Adapter->Lock, &OldIrql );
	TI_DbgPrint(MID_TRACE, ("NdisSend\n"));
	/* LANUnregisterAdapter closes the binding under the lock */
	if (Adapter->NdisHandle) {
	    /* NDIS loops a frame to our own MAC back up from inside this call: tag that window (see LanLoopAdapter).
	       The lock is held, so this is DISPATCH_LEVEL and the CPU number is stable */
	    PVOID PrevTag = NULL;
	    ULONG Cpu = KeGetCurrentProcessorNumber();
	    BOOLEAN Tag = Adapter->Media == NdisMedium802_3 && Cpu < MAXIMUM_PROCESSORS &&
	                  LanDestIsOwn(Adapter, (PETH_HEADER)Data);

	    if (Tag) {
	        PrevTag = LanLoopAdapter[Cpu];
	        LanLoopAdapter[Cpu] = Adapter;
	    }
	    NdisSend(&NdisStatus, Adapter->NdisHandle, XmitPacket);
	    if (Tag)
	        LanLoopAdapter[Cpu] = PrevTag;
	} else
	    NdisStatus = NDIS_STATUS_CLOSING;
	TI_DbgPrint(MID_TRACE, ("NdisSend %s\n",
				NdisStatus == NDIS_STATUS_PENDING ?
				"Pending" : "Complete"));
	TcpipReleaseSpinLock( &Adapter->Lock, OldIrql );

	/* I had a talk with vizzini: these really ought to be here.
	 * we're supposed to see these completed by ndis *only* when
	 * status_pending is returned.  Note that this is different from
	 * the situation with IRPs. */
        if (NdisStatus != NDIS_STATUS_PENDING)
            ProtocolSendComplete((NDIS_HANDLE)Context, XmitPacket, NdisStatus);
}

static NTSTATUS
OpenRegistryKey( PNDIS_STRING RegistryPath, PHANDLE RegHandle ) {
    OBJECT_ATTRIBUTES Attributes;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenKey(RegHandle, KEY_ALL_ACCESS, &Attributes);
    return Status;
}

static NTSTATUS ReadStringFromRegistry( HANDLE RegHandle,
					PWCHAR RegistryValue,
					PUNICODE_STRING String ) {
    UNICODE_STRING ValueName;
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;
    ULONG ResultLength;
    UCHAR buf[1024];
    PKEY_VALUE_PARTIAL_INFORMATION Information = (PKEY_VALUE_PARTIAL_INFORMATION)buf;

    RtlInitUnicodeString(&ValueName, RegistryValue);
    Status =
	ZwQueryValueKey(RegHandle,
			&ValueName,
			KeyValuePartialInformation,
			Information,
			sizeof(buf),
			&ResultLength);

    if (!NT_SUCCESS(Status))
	return Status;
    /* IP address is stored as a REG_MULTI_SZ - we only pay attention to the first one though */
    TI_DbgPrint(MIN_TRACE, ("Information DataLength: 0x%x\n", Information->DataLength));

    UnicodeString.Buffer = (PWCHAR)&Information->Data;
    UnicodeString.Length = Information->DataLength - sizeof(WCHAR);
    UnicodeString.MaximumLength = Information->DataLength;

    String->Buffer =
	(PWCHAR)ExAllocatePoolWithTag( NonPagedPool,
				UnicodeString.MaximumLength + sizeof(WCHAR), REG_STR_TAG );

    if( !String->Buffer ) return STATUS_NO_MEMORY;

    String->MaximumLength = UnicodeString.MaximumLength;
    RtlCopyUnicodeString( String, &UnicodeString );

    return STATUS_SUCCESS;
}

/*
 * Utility to copy and append two unicode strings.
 *
 * IN OUT PUNICODE_STRING ResultFirst -> First string and result
 * IN     PUNICODE_STRING Second      -> Second string to append
 * IN     BOOL            Deallocate  -> TRUE: Deallocate First string before
 *                                       overwriting.
 *
 * Returns NTSTATUS.
 */

NTSTATUS NTAPI AppendUnicodeString(PUNICODE_STRING ResultFirst,
				   PUNICODE_STRING Second,
				   BOOLEAN Deallocate) {
    NTSTATUS Status;
    UNICODE_STRING Ustr = *ResultFirst;
    PWSTR new_string = ExAllocatePoolWithTag
        (PagedPool,
         (ResultFirst->Length + Second->Length + sizeof(WCHAR)), TEMP_STRING_TAG);
    if( !new_string ) {
	return STATUS_NO_MEMORY;
    }
    memcpy( new_string, ResultFirst->Buffer, ResultFirst->Length );
    memcpy( new_string + ResultFirst->Length / sizeof(WCHAR),
	    Second->Buffer, Second->Length );
    if( Deallocate ) RtlFreeUnicodeString(ResultFirst);
    ResultFirst->Length = Ustr.Length + Second->Length;
    ResultFirst->MaximumLength = ResultFirst->Length;
    new_string[ResultFirst->Length / sizeof(WCHAR)] = 0;
    Status = RtlCreateUnicodeString(ResultFirst,new_string) ?
	STATUS_SUCCESS : STATUS_NO_MEMORY;
    ExFreePoolWithTag(new_string, TEMP_STRING_TAG);
    return Status;
}

static NTSTATUS CheckForDeviceDesc( PUNICODE_STRING EnumKeyName,
                                    PUNICODE_STRING TargetKeyName,
                                    PUNICODE_STRING Name,
                                    PUNICODE_STRING DeviceDesc ) {
    UNICODE_STRING RootDevice = { 0, 0, NULL }, LinkageKeyName = { 0, 0, NULL };
    UNICODE_STRING DescKeyName = { 0, 0, NULL }, Linkage = { 0, 0, NULL };
    UNICODE_STRING BackSlash = { 0, 0, NULL };
    HANDLE DescKey = NULL, LinkageKey = NULL;
    NTSTATUS Status;

    TI_DbgPrint(DEBUG_DATALINK,("EnumKeyName %wZ\n", EnumKeyName));

    RtlInitUnicodeString(&BackSlash, L"\\");
    RtlInitUnicodeString(&Linkage, L"\\Linkage");

    RtlInitUnicodeString(&DescKeyName, L"");
    AppendUnicodeString( &DescKeyName, EnumKeyName, FALSE );
    AppendUnicodeString( &DescKeyName, &BackSlash, TRUE );
    AppendUnicodeString( &DescKeyName, TargetKeyName, TRUE );

    RtlInitUnicodeString(&LinkageKeyName, L"");
    AppendUnicodeString( &LinkageKeyName, &DescKeyName, FALSE );
    AppendUnicodeString( &LinkageKeyName, &Linkage, TRUE );

    Status = OpenRegistryKey( &LinkageKeyName, &LinkageKey );
    if( !NT_SUCCESS(Status) ) goto cleanup;

    Status = ReadStringFromRegistry( LinkageKey, L"RootDevice", &RootDevice );
    if( !NT_SUCCESS(Status) ) goto cleanup;

    if( RtlCompareUnicodeString( &RootDevice, Name, TRUE ) == 0 ) {
        Status = OpenRegistryKey( &DescKeyName, &DescKey );
        if( !NT_SUCCESS(Status) ) goto cleanup;

        Status = ReadStringFromRegistry( DescKey, L"DriverDesc", DeviceDesc );
        if( !NT_SUCCESS(Status) ) goto cleanup;

        TI_DbgPrint(DEBUG_DATALINK,("ADAPTER DESC: %wZ\n", DeviceDesc));
    } else Status = STATUS_UNSUCCESSFUL;

cleanup:
    RtlFreeUnicodeString( &RootDevice );
    RtlFreeUnicodeString( &LinkageKeyName );
    RtlFreeUnicodeString( &DescKeyName );
    if( LinkageKey ) ZwClose( LinkageKey );
    if( DescKey ) ZwClose( DescKey );

    TI_DbgPrint(DEBUG_DATALINK,("Returning %x\n", Status));

    return Status;
}

static NTSTATUS FindDeviceDescForAdapter( PUNICODE_STRING Name,
                                          PUNICODE_STRING DeviceDesc ) {
    UNICODE_STRING EnumKeyName, TargetKeyName;
    HANDLE EnumKey;
    NTSTATUS Status;
    ULONG i;
    KEY_BASIC_INFORMATION *Kbio =
        ExAllocatePoolWithTag(NonPagedPool, sizeof(KEY_BASIC_INFORMATION), KBIO_TAG);
    ULONG KbioLength = sizeof(KEY_BASIC_INFORMATION), ResultLength;

    RtlInitUnicodeString( DeviceDesc, NULL );

    if( !Kbio ) return STATUS_INSUFFICIENT_RESOURCES;

    RtlInitUnicodeString
        (&EnumKeyName, CCS_ROOT L"\\Control\\Class\\" TCPIP_GUID);

    Status = OpenRegistryKey( &EnumKeyName, &EnumKey );

    if( !NT_SUCCESS(Status) ) {
        TI_DbgPrint(DEBUG_DATALINK,("Couldn't open Enum key %wZ: %x\n",
                                    &EnumKeyName, Status));
        ExFreePoolWithTag( Kbio, KBIO_TAG );
        return Status;
    }

    for( i = 0; NT_SUCCESS(Status); i++ ) {
        Status = ZwEnumerateKey( EnumKey, i, KeyBasicInformation,
                                 Kbio, KbioLength, &ResultLength );

        if( Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW ) {
            ExFreePoolWithTag( Kbio, KBIO_TAG );
            KbioLength = ResultLength;
            Kbio = ExAllocatePoolWithTag( NonPagedPool, KbioLength, KBIO_TAG );
            if( !Kbio ) {
                TI_DbgPrint(DEBUG_DATALINK,("Failed to allocate memory\n"));
                ZwClose( EnumKey );
                return STATUS_NO_MEMORY;
            }

            Status = ZwEnumerateKey( EnumKey, i, KeyBasicInformation,
                                     Kbio, KbioLength, &ResultLength );

            if( !NT_SUCCESS(Status) ) {
                TI_DbgPrint(DEBUG_DATALINK,("Couldn't enum key child %d\n", i));
                ZwClose( EnumKey );
                ExFreePoolWithTag( Kbio, KBIO_TAG );
                return Status;
            }
        }

        if( NT_SUCCESS(Status) ) {
            TargetKeyName.Length = TargetKeyName.MaximumLength =
                Kbio->NameLength;
            TargetKeyName.Buffer = Kbio->Name;

            Status = CheckForDeviceDesc
                ( &EnumKeyName, &TargetKeyName, Name, DeviceDesc );
            if( NT_SUCCESS(Status) ) {
                ZwClose( EnumKey );
                ExFreePoolWithTag( Kbio, KBIO_TAG );
                return Status;
            } else Status = STATUS_SUCCESS;
        }
    }

    ZwClose( EnumKey );
    ExFreePoolWithTag( Kbio, KBIO_TAG );
    return STATUS_UNSUCCESSFUL;
}

VOID GetName( PUNICODE_STRING RegistryKey,
              PUNICODE_STRING OutName ) {
    PWCHAR Ptr;
    UNICODE_STRING PartialRegistryKey;

    PartialRegistryKey.Buffer =
        RegistryKey->Buffer + wcslen(CCS_ROOT L"\\Services\\");
    Ptr = PartialRegistryKey.Buffer;

    while( *Ptr != L'\\' &&
           ((PCHAR)Ptr) < ((PCHAR)RegistryKey->Buffer) + RegistryKey->Length )
        Ptr++;

    PartialRegistryKey.Length = PartialRegistryKey.MaximumLength =
        (Ptr - PartialRegistryKey.Buffer) * sizeof(WCHAR);

    RtlInitUnicodeString( OutName, L"" );
    AppendUnicodeString( OutName, &PartialRegistryKey, FALSE );
}

BOOLEAN BindAdapter(
    PLAN_ADAPTER Adapter,
    PNDIS_STRING RegistryPath)
/*
 * FUNCTION: Binds a LAN adapter to IP layer
 * ARGUMENTS:
 *     Adapter = Pointer to LAN_ADAPTER structure
 * NOTES:
 *    We set the lookahead buffer size, set the packet filter and
 *    bind the adapter to IP layer
 */
{
    PIP_INTERFACE IF;
    NDIS_STATUS NdisStatus;
    LLIP_BIND_INFO BindInfo;
    ULONG Lookahead = LOOKAHEAD_SIZE;
    NTSTATUS Status;
    NDIS_MEDIA_STATE MediaState;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    Adapter->State = LAN_STATE_OPENING;

    NdisStatus = NDISCall(Adapter,
                          NdisRequestSetInformation,
                          OID_GEN_CURRENT_LOOKAHEAD,
                          &Lookahead,
                          sizeof(ULONG));
    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        TI_DbgPrint(DEBUG_DATALINK, ("Could not set lookahead buffer size (0x%X).\n", NdisStatus));
        return FALSE;
    }

    /* Bind the adapter to IP layer */
    BindInfo.Context       = Adapter;
    BindInfo.HeaderSize    = Adapter->HeaderSize;
    BindInfo.MinFrameSize  = Adapter->MinFrameSize;
    BindInfo.Address       = (PUCHAR)&Adapter->HWAddress;
    BindInfo.AddressLength = Adapter->HWAddressLength;
    BindInfo.Transmit      = LANTransmit;
    BindInfo.Release       = LanReleaseAdapter;

    IF = IPCreateInterface(&BindInfo);

    if (!IF) {
        TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
        return FALSE;
    }

    /* The interface owns the adapter from now on: on a failure below, DenyOpenAdapter
       removes the interface (UnbindAdapter), and the adapter goes with its last reference */
    Adapter->Context = IF;
    InterlockedIncrement(&LanAdaptersOwned);

    /*
     * Query per-adapter configuration from the registry
     * In case anyone is curious:  there *is* an Ndis configuration api
     * for this sort of thing, but it doesn't really support things like
     * REG_MULTI_SZ very well, and there is a note in the DDK that says that
     * protocol drivers developed for win2k and above just use the native
     * services (ZwOpenKey, etc).
     */

    GetName( RegistryPath, &IF->Name );

    Status = FindDeviceDescForAdapter( &IF->Name, &IF->Description );
    if (!NT_SUCCESS(Status)) {
        /* No Linkage\RootDevice for it in the network class key: DenyOpenAdapter removes
           the interface (never registered, so IPUnregisterInterface is a no-op on it) */
        DbgPrint("TCPIP: no device description for %wZ (0x%lx), not binding to it\n", &IF->Name, Status);
        return FALSE;
    }

    TI_DbgPrint(DEBUG_DATALINK,("Adapter Description: %wZ\n",
                &IF->Description));

    /* Register interface with IP layer */
    IPRegisterInterface(IF);

    /* Get the media state */
    NdisStatus = NDISCall(Adapter,
                          NdisRequestQueryInformation,
                          OID_GEN_MEDIA_CONNECT_STATUS,
                          &MediaState,
                          sizeof(MediaState));
    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        TI_DbgPrint(DEBUG_DATALINK, ("Could not query media status (0x%X).\n", NdisStatus));
        /* The interface stays registered: DenyOpenAdapter removes it (UnbindAdapter) once the
           reconfiguration the media indication queued is done with it */
        return FALSE;
    }

    /* Indicate the current media state */
    ProtocolStatus(Adapter,
                   (MediaState == NdisMediaStateConnected) ? NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT,
                   NULL, 0);

    /* Set packet filter so we can send and receive packets */
    NdisStatus = NDISCall(Adapter,
                          NdisRequestSetInformation,
                          OID_GEN_CURRENT_PACKET_FILTER,
                          &Adapter->PacketFilter,
                          sizeof(UINT));

    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        TI_DbgPrint(DEBUG_DATALINK, ("Could not set packet filter (0x%X).\n", NdisStatus));
        /* The interface stays registered: DenyOpenAdapter removes it (UnbindAdapter) once the
           reconfiguration the media indication queued is done with it */
        return FALSE;
    }

    return TRUE;
}


VOID UnbindAdapter(
    PLAN_ADAPTER Adapter)
/*
 * FUNCTION: Unbinds a LAN adapter from IP layer
 * ARGUMENTS:
 *     Adapter = Pointer to LAN_ADAPTER structure
 */
{
    PIP_INTERFACE IF = Adapter->Context;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    /* BindAdapter registered the interface whatever the media state: a disconnected
       adapter's interface must go as well, with every route and neighbor on it.
       Adapter->Context keeps pointing to it: the interface frees the adapter, so a sender
       still holding a neighbour of the interface reaches a valid adapter (LANTransmit fails
       on the closed binding) */
    if (IF) {
        /* Off the interface list, and no neighbour or route is added to it any more */
        IPUnregisterInterface(IF);

        /* The routes drop their neighbours; the neighbours leave the cache */
        RouterRemoveRoutesForInterface(IF);
        NBDestroyNeighborsForInterface(IF);

        /* Drops the reference of the binding: interface and adapter go when the last
           neighbour or caller still using them lets go */
        IPDestroyInterface(IF);
    }
}


NDIS_STATUS LANRegisterAdapter(
    PNDIS_STRING AdapterName,
    PNDIS_STRING RegistryPath)
/*
 * FUNCTION: Registers protocol with an NDIS adapter
 * ARGUMENTS:
 *     AdapterName = Pointer to string with name of adapter to register
 *     Adapter     = Address of pointer to a LAN_ADAPTER structure
 * RETURNS:
 *     Status of operation
 */
{
    PLAN_ADAPTER IF;
    NDIS_STATUS NdisStatus;
    NDIS_STATUS OpenStatus;
    UINT MediaIndex;
    NDIS_MEDIUM MediaArray[MAX_MEDIA];
    UINT AddressOID;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    IF = ExAllocatePoolWithTag(NonPagedPool, sizeof(LAN_ADAPTER), LAN_ADAPTER_TAG);
    if (!IF) {
        TI_DbgPrint(MIN_TRACE, ("Insufficient resources.\n"));
        return NDIS_STATUS_RESOURCES;
    }

    RtlZeroMemory(IF, sizeof(LAN_ADAPTER));

    if (!ChewSerialInit(&IF->ReceiveQueue, LanReceiveWorker, LAN_RECEIVE_QUEUE_LIMIT)) {
        ExFreePoolWithTag(IF, LAN_ADAPTER_TAG);
        return NDIS_STATUS_RESOURCES;
    }

    /* Put adapter in stopped state */
    IF->State = LAN_STATE_STOPPED;

    /* Initialize protecting spin lock */
    KeInitializeSpinLock(&IF->Lock);
    KeInitializeSpinLock(&IF->ReconfigureLock);

    KeInitializeEvent(&IF->Event, SynchronizationEvent, FALSE);

    /* Initialize array with media IDs we support */
    MediaArray[MEDIA_ETH] = NdisMedium802_3;

    TI_DbgPrint(DEBUG_DATALINK,("opening adapter %wZ\n", AdapterName));
    /* Open the adapter. */
    NdisOpenAdapter(&NdisStatus,
                    &OpenStatus,
                    &IF->NdisHandle,
                    &MediaIndex,
                    MediaArray,
                    MAX_MEDIA,
                    NdisProtocolHandle,
                    IF,
                    AdapterName,
                    0,
                    NULL);

    /* Wait until the adapter is opened */
    if (NdisStatus == NDIS_STATUS_PENDING)
        KeWaitForSingleObject(&IF->Event, UserRequest, KernelMode, FALSE, NULL);
    else if (NdisStatus != NDIS_STATUS_SUCCESS) {
	TI_DbgPrint(DEBUG_DATALINK,("denying adapter %wZ\n", AdapterName));
	FreeAdapter(IF);
        return NdisStatus;
    }

    IF->Media = MediaArray[MediaIndex];

    /* Fill LAN_ADAPTER structure with some adapter specific information */
    switch (IF->Media) {
    case NdisMedium802_3:
        IF->HWAddressLength = IEEE_802_ADDR_LENGTH;
        IF->BCastMask       = BCAST_ETH_MASK;
        IF->BCastCheck      = BCAST_ETH_CHECK;
        IF->BCastOffset     = BCAST_ETH_OFFSET;
        IF->HeaderSize      = sizeof(ETH_HEADER);
        IF->MinFrameSize    = 60;
        AddressOID          = OID_802_3_CURRENT_ADDRESS;
        IF->PacketFilter    =
            NDIS_PACKET_TYPE_BROADCAST |
            NDIS_PACKET_TYPE_DIRECTED  |
            NDIS_PACKET_TYPE_MULTICAST;
        break;

    default:
        /* Unsupported media */
        TI_DbgPrint(MIN_TRACE, ("Unsupported media.\n"));
        DenyOpenAdapter(IF);
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    /* Interface type for the inbound filter's rule conditions (a miniport that does not answer is a LAN adapter) */
    {
        ULONG Physical = 0;
        if (NDISCall(IF, NdisRequestQueryInformation, OID_GEN_PHYSICAL_MEDIUM, &Physical, sizeof(Physical)) != NDIS_STATUS_SUCCESS)
            Physical = 0;
        IF->FwIfType = FwIfTypeFromMedium((ULONG)IF->Media, Physical);
    }

    /* Get maximum number of packets we can pass to NdisSend(Packets) at one time */
    NdisStatus = NDISCall(IF,
                          NdisRequestQueryInformation,
                          OID_GEN_MAXIMUM_SEND_PACKETS,
                          &IF->MaxSendPackets,
                          sizeof(UINT));
    if (NdisStatus != NDIS_STATUS_SUCCESS)
        /* Legacy NIC drivers may not support this query, if it fails we
           assume it can send at least one packet per call to NdisSend(Packets) */
        IF->MaxSendPackets = 1;

    /* Get current hardware address */
    NdisStatus = NDISCall(IF,
                          NdisRequestQueryInformation,
                          AddressOID,
                          &IF->HWAddress,
                          IF->HWAddressLength);
    if (NdisStatus != NDIS_STATUS_SUCCESS) {
        TI_DbgPrint(MIN_TRACE, ("Query for current hardware address failed.\n"));
        DenyOpenAdapter(IF);
        return NdisStatus;
    }

    /* Bind adapter to IP layer */
    if( !BindAdapter(IF, RegistryPath) ) {
	TI_DbgPrint(DEBUG_DATALINK,("denying adapter %wZ (BindAdapter)\n", AdapterName));
	DenyOpenAdapter(IF);
	return NDIS_STATUS_NOT_ACCEPTED;
    }

    /* Add adapter to the adapter list */
    ExInterlockedInsertTailList(&AdapterListHead,
                                &IF->ListEntry,
                                &AdapterListLock);

    TI_DbgPrint(DEBUG_DATALINK, ("Leaving.\n"));

    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS LANUnregisterAdapter(
    PLAN_ADAPTER Adapter)
/*
 * FUNCTION: Unregisters protocol with NDIS adapter
 * ARGUMENTS:
 *     Adapter = Pointer to a LAN_ADAPTER structure
 * RETURNS:
 *     Status of operation
 */
{
    KIRQL OldIrql;
    NDIS_HANDLE NdisHandle;
    NDIS_STATUS NdisStatus = NDIS_STATUS_SUCCESS;
    LARGE_INTEGER Delay;
    BOOLEAN Queued;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    /* Unlink the adapter from the list */
    TcpipAcquireSpinLock(&AdapterListLock, &OldIrql);
    RemoveEntryList(&Adapter->ListEntry);
    TcpipReleaseSpinLock(&AdapterListLock, OldIrql);

    /* No reconfiguration starts any more; the one that runs uses the binding and the
       interface, so it ends first (its NDIS requests fail at once on an adapter that
       NDIS is removing) */
    Delay.QuadPart = -100000;
    TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
    Adapter->Unbinding = TRUE;
    TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
    for (;;) {
        TcpipAcquireSpinLock(&Adapter->ReconfigureLock, &OldIrql);
        Queued = Adapter->ReconfigureQueued;
        TcpipReleaseSpinLock(&Adapter->ReconfigureLock, OldIrql);
        if (!Queued)
            break;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    /* Close the binding first: NDIS completes our sends and requests on it and
       indicates nothing more, so no received frame is queued after this */
    TcpipAcquireSpinLock(&Adapter->Lock, &OldIrql);
    /* LANTransmit refuses packets from now on, instead of reporting them sent */
    Adapter->State = LAN_STATE_STOPPED;
    NdisHandle = Adapter->NdisHandle;
    if (NdisHandle) {
        Adapter->NdisHandle = NULL;
        TcpipReleaseSpinLock(&Adapter->Lock, OldIrql);

        NdisCloseAdapter(&NdisStatus, NdisHandle);
        if (NdisStatus == NDIS_STATUS_PENDING) {
            TcpipWaitForSingleObject(&Adapter->Event,
                                     UserRequest,
                                     KernelMode,
                                     FALSE,
                                     NULL);
            NdisStatus = Adapter->NdisStatus;
        }
    } else
        TcpipReleaseSpinLock(&Adapter->Lock, OldIrql);

    /* The received frames still queued use the adapter and the IP interface: deliver
       them (what they send fails on the closed binding) before both go away */
    ChewSerialRundown(&Adapter->ReceiveQueue);
    while (Adapter->ReceiveWorkItems != 0)
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    /* Unbind adapter from IP layer; the interface frees the adapter with its last reference */
    if (Adapter->Context) {
        UnbindAdapter(Adapter);
    } else {
        FreeAdapter(Adapter);
    }

    return NdisStatus;
}

VOID
NTAPI
LANUnregisterProtocol(VOID)
/*
 * FUNCTION: Unregisters this protocol driver with NDIS
 * NOTES: Does not care wether we are already registered
 */
{
    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    if (ProtocolRegistered) {
        NDIS_STATUS NdisStatus;
        PLAN_ADAPTER Current;
        KIRQL OldIrql;

        /* Unregister every adapter; that waits, so not under the list lock */
        for (;;) {
            TcpipAcquireSpinLock(&AdapterListLock, &OldIrql);
            if (IsListEmpty(&AdapterListHead)) {
                TcpipReleaseSpinLock(&AdapterListLock, OldIrql);
                break;
            }
            Current = CONTAINING_RECORD(AdapterListHead.Flink, LAN_ADAPTER, ListEntry);
            TcpipReleaseSpinLock(&AdapterListLock, OldIrql);

            LANUnregisterAdapter(Current);
        }

        /* An interface outlives its unbinding while something still references it (an NCE
           held by a sender, a WaitForHwAddress work item for up to 10 seconds): its last
           reference frees the adapter (LanReleaseAdapter), which must happen before the
           driver goes */
        {
            LARGE_INTEGER Delay;
            ULONG Waited = 0;

            Delay.QuadPart = -100000; /* 10 ms */
            while (LanAdaptersOwned != 0) {
                if ((++Waited % 1000) == 0)
                    DbgPrint("TCPIP: unload waits for %ld adapters still referenced\n", LanAdaptersOwned);
                KeDelayExecutionThread(KernelMode, FALSE, &Delay);
            }
        }

        NdisDeregisterProtocol(&NdisStatus, NdisProtocolHandle);
        ProtocolRegistered = FALSE;
    }
}

VOID
NTAPI
ProtocolUnbindAdapter(
    PNDIS_STATUS Status,
    NDIS_HANDLE ProtocolBindingContext,
    NDIS_HANDLE UnbindContext)
{
    /* We don't pend any unbinding so we can just ignore UnbindContext */
    *Status = LANUnregisterAdapter((PLAN_ADAPTER)ProtocolBindingContext);
}

NTSTATUS LANRegisterProtocol(
    PNDIS_STRING Name)
/*
 * FUNCTION: Registers this protocol driver with NDIS
 * ARGUMENTS:
 *     Name = Name of this protocol driver
 * RETURNS:
 *     Status of operation
 */
{
    NDIS_STATUS NdisStatus;
    NDIS_PROTOCOL_CHARACTERISTICS ProtChars;

    TI_DbgPrint(DEBUG_DATALINK, ("Called.\n"));

    InitializeListHead(&AdapterListHead);
    KeInitializeSpinLock(&AdapterListLock);

    /* Set up protocol characteristics */
    RtlZeroMemory(&ProtChars, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
    ProtChars.MajorNdisVersion               = NDIS_VERSION_MAJOR;
    ProtChars.MinorNdisVersion               = NDIS_VERSION_MINOR;
    ProtChars.Name.Length                    = Name->Length;
    ProtChars.Name.Buffer                    = Name->Buffer;
    ProtChars.Name.MaximumLength             = Name->MaximumLength;
    ProtChars.OpenAdapterCompleteHandler     = ProtocolOpenAdapterComplete;
    ProtChars.CloseAdapterCompleteHandler    = ProtocolCloseAdapterComplete;
    ProtChars.ResetCompleteHandler           = ProtocolResetComplete;
    ProtChars.RequestCompleteHandler         = ProtocolRequestComplete;
    ProtChars.SendCompleteHandler            = ProtocolSendComplete;
    ProtChars.TransferDataCompleteHandler    = ProtocolTransferDataComplete;
    ProtChars.ReceivePacketHandler           = ProtocolReceivePacket;
    ProtChars.ReceiveHandler                 = ProtocolReceive;
    ProtChars.ReceiveCompleteHandler         = ProtocolReceiveComplete;
    ProtChars.StatusHandler                  = ProtocolStatus;
    ProtChars.StatusCompleteHandler          = ProtocolStatusComplete;
    ProtChars.BindAdapterHandler             = ProtocolBindAdapter;
    ProtChars.PnPEventHandler                = ProtocolPnPEvent;
    ProtChars.UnbindAdapterHandler           = ProtocolUnbindAdapter;
    ProtChars.UnloadHandler                  = LANUnregisterProtocol;

    /* Try to register protocol */
    NdisRegisterProtocol(&NdisStatus,
                         &NdisProtocolHandle,
                         &ProtChars,
                         sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
    if (NdisStatus != NDIS_STATUS_SUCCESS)
    {
        TI_DbgPrint(DEBUG_DATALINK, ("NdisRegisterProtocol failed, status 0x%x\n", NdisStatus));
        return (NTSTATUS)NdisStatus;
    }

    ProtocolRegistered = TRUE;

    return STATUS_SUCCESS;
}

/* EOF */
