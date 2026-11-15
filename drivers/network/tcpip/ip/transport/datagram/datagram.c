/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        transport/datagram/datagram.c
 * PURPOSE:     Routines for sending and receiving datagrams
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

BOOLEAN DGRemoveIRP(
    PADDRESS_FILE AddrFile,
    PIRP Irp)
{
    PLIST_ENTRY ListEntry;
    PDATAGRAM_RECEIVE_REQUEST ReceiveRequest;
    BOOLEAN Found = FALSE;

    TI_DbgPrint(MAX_TRACE, ("Called (Cancel IRP %08x for file %08x).\n",
                            Irp, AddrFile));

    LockObject(AddrFile);

    for( ListEntry = AddrFile->ReceiveQueue.Flink;
         ListEntry != &AddrFile->ReceiveQueue;
         ListEntry = ListEntry->Flink )
    {
        ReceiveRequest = CONTAINING_RECORD
            (ListEntry, DATAGRAM_RECEIVE_REQUEST, ListEntry);

        TI_DbgPrint(MAX_TRACE, ("Request: %08x?\n", ReceiveRequest));

        if (ReceiveRequest->Irp == Irp)
        {
            RemoveEntryList(&ReceiveRequest->ListEntry);
            ExFreePoolWithTag(ReceiveRequest, DATAGRAM_RECV_TAG);
            Found = TRUE;
            break;
        }
    }

    UnlockObject(AddrFile);

    TI_DbgPrint(MAX_TRACE, ("Done.\n"));

    return Found;
}

/*
 * What a receive reports besides the source address, through the Options of the connection
 * information it was posted with (AFD points them at a structure of this layout,
 * AFD_RECV_PKTINFO in drivers/network/afd/include/afd.h): the datagram's destination
 * address and the index of the interface that owns it, for IP_PKTINFO.
 */
#define DG_PKTINFO_V4 0x1   /* DstAddress: an IPv4 datagram */
#define DG_PKTINFO_V6 0x2   /* DstAddress6 and HopLimit: an IPv6 datagram (IPV6_PKTINFO, IPV6_HOPLIMIT) */
typedef struct _DG_RECV_PKTINFO {
    ULONG Valid;
    ULONG DstAddress;
    ULONG IfIndex;
    UCHAR DstAddress6[16];
    ULONG HopLimit;
} DG_RECV_PKTINFO, *PDG_RECV_PKTINFO;

/* The source of a datagram as the receive of an IPv6 socket reports it: a TA_IP6_ADDRESS, an IPv4 source (a dual
 * stack socket) as ::ffff:a.b.c.d. Ta has Length bytes (the receive's own buffer); nothing is written to a smaller
 * one */
static
VOID
DGBuildSource6(
    PTRANSPORT_ADDRESS Ta,
    ULONG Length,
    PIP_ADDRESS SrcAddress,
    USHORT SrcPort,
    ULONG ScopeId)
{
    PTA_IP6_ADDRESS Ta6 = (PTA_IP6_ADDRESS)Ta;
    UCHAR Bytes[16];
    ULONG Zero = 0;

    if (Length < sizeof(TA_IP6_ADDRESS))
        return;

    RtlZeroMemory(Bytes, sizeof(Bytes));
    if (SrcAddress->Type == IP_ADDRESS_V6)
    {
        RtlCopyMemory(Bytes, SrcAddress->Address.IPv6Address, sizeof(Bytes));
    }
    else
    {
        Bytes[10] = 0xFF;
        Bytes[11] = 0xFF;
        RtlCopyMemory(&Bytes[12], &SrcAddress->Address.IPv4Address, sizeof(ULONG));
        ScopeId = 0;
    }

    Ta6->TAAddressCount = 1;
    Ta6->Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;
    Ta6->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6;
    RtlCopyMemory(&Ta6->Address[0].Address[0].sin6_port, &SrcPort, sizeof(SrcPort));
    RtlCopyMemory(&Ta6->Address[0].Address[0].sin6_flowinfo, &Zero, sizeof(Zero));
    RtlCopyMemory(Ta6->Address[0].Address[0].sin6_addr, Bytes, sizeof(Bytes));
    RtlCopyMemory(&Ta6->Address[0].Address[0].sin6_scope_id, &ScopeId, sizeof(ScopeId));
}

VOID
DGDeliverData(
    PIP_INTERFACE Interface,
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS SrcAddress,
    PIP_ADDRESS DstAddress,
    USHORT SrcPort,
    USHORT DstPort,
    PIP_PACKET IPPacket,
    UINT DataSize)
{
    DGDeliverDataEx(Interface, AddrFile, SrcAddress, DstAddress, SrcPort, DstPort, IPPacket, DataSize, NULL);
}

/* TRUE: a receive took the datagram or the receive handler saw it; FALSE: nothing took it */
static
BOOLEAN
DGDeliverNow(
    PIP_INTERFACE Interface,
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS SrcAddress,
    PIP_ADDRESS DstAddress,
    USHORT SrcPort,
    USHORT DstPort,
    PIP_PACKET IPPacket,
    UINT DataSize,
    PDG_RX_INFO6 Info6)
/*
 * FUNCTION: Delivers datagram data to a user
 * ARGUMENTS:
 *     AddrFile = Address file to deliver data to
 *     Address  = Remote address the packet came from
 *     IPPacket = Pointer to IP packet to deliver
 *     DataSize = Number of bytes in data area
 *                (incl. IP header for raw IP file objects)
 * NOTES:
 *     If there is a receive request, then we copy the data to the
 *     buffer supplied by the user and complete the receive request.
 *     If no suitable receive request exists, then we call the event
 *     handler if it exists, otherwise we drop the packet.
 */
{
    LONG AddressLength;
    PVOID SourceAddress;
    ULONG BytesTaken;
    NTSTATUS Status;
    PVOID DataBuffer;
    BOOLEAN Delivered = FALSE;

    TI_DbgPrint(MIN_TRACE, ("Called.\n"));

    LockObject(AddrFile);

    if (AddrFile->Protocol == IPPROTO_UDP)
    {
        DataBuffer = IPPacket->Data;
    }
    else if (AddrFile->HeaderIncl)
    {
        DataBuffer = IPPacket->Header;
    }
    else
    {
        DataBuffer = IPPacket->Data;
        DataSize -= IPPacket->HeaderSize;
    }

    if (!IsListEmpty(&AddrFile->ReceiveQueue))
    {
        PLIST_ENTRY CurrentEntry;
        PDATAGRAM_RECEIVE_REQUEST Current = NULL;
        PTA_IP_ADDRESS RTAIPAddress;
        PIP_INTERFACE OwnerIF = NULL;

        /* A receive is posted: the datagram is its (or, when none takes it, dropped) */
        Delivered = TRUE;

        TI_DbgPrint(MAX_TRACE, ("There is a receive request.\n"));

        /* Search receive request list to find a match */
        CurrentEntry = AddrFile->ReceiveQueue.Flink;
        while (CurrentEntry != &AddrFile->ReceiveQueue)
        {
            Current = CONTAINING_RECORD(CurrentEntry, DATAGRAM_RECEIVE_REQUEST, ListEntry);
            CurrentEntry = CurrentEntry->Flink;
            /* (the wildcard test first: an IPv4 datagram of a dual stack socket has another address type; an
               IPv6 group's datagram reaches the members whatever they are bound to, udp6.c decided that) */
            if (DstPort == AddrFile->Port &&
               (AddrIsUnspecified(&AddrFile->Address) ||
                (DstAddress->Type == IP_ADDRESS_V6 && ((PUCHAR)DstAddress->Address.IPv6Address)[0] == 0xFF) ||
                AddrIsEqual(DstAddress, &AddrFile->Address) ||
                AddrIsUnspecified(DstAddress)))
            {

                /* Remove the request from the queue */
                RemoveEntryList(&Current->ListEntry);
                InterlockedIncrement(&AddrFile->Completing);

                TI_DbgPrint(MAX_TRACE, ("Suitable receive request found.\n"));

                TI_DbgPrint(MAX_TRACE,
                           ("Target Buffer: %x, Source Buffer: %x, Size %d\n",
                            Current->Buffer, DataBuffer, DataSize));

                /* Copy the data into buffer provided by the user */
                RtlCopyMemory(Current->Buffer,
                     DataBuffer,
                     MIN(Current->BufferSize, DataSize));

                /* The caller may not want the source address (no return info
                 * or no address buffer): skip it then. */
                RTAIPAddress = NULL;
                if (Current->ReturnInfo && Current->ReturnInfo->RemoteAddress)
                    RTAIPAddress = (PTA_IP_ADDRESS)Current->ReturnInfo->RemoteAddress;

                if (RTAIPAddress && AddrFile->Family == TDI_ADDRESS_TYPE_IP6)
                {
                    /* An IPv6 socket: AFD sized the buffer from its local address, a TA_IP6_ADDRESS */
                    DGBuildSource6((PTRANSPORT_ADDRESS)RTAIPAddress, Current->ReturnInfo->RemoteAddressLength,
                                   SrcAddress, SrcPort, Info6 ? Info6->SrcScopeId : 0);
                }
                else if (RTAIPAddress)
                {
                    RTAIPAddress->TAAddressCount = 1;
                    RTAIPAddress->Address->AddressType = TDI_ADDRESS_TYPE_IP;
                    RTAIPAddress->Address->AddressLength = TDI_ADDRESS_LENGTH_IP;
                    RTAIPAddress->Address->Address->sin_port = SrcPort;
                    RTAIPAddress->Address->Address->in_addr = SrcAddress->Address.IPv4Address;
                    RtlZeroMemory(RTAIPAddress->Address->Address->sin_zero, 8);
                }

                if (Current->ReturnInfo &&
                    Current->ReturnInfo->Options &&
                    Current->ReturnInfo->OptionsLength == sizeof(DG_RECV_PKTINFO) &&
                    DstAddress->Type == IP_ADDRESS_V4)
                {
                    PDG_RECV_PKTINFO PktInfo = Current->ReturnInfo->Options;

                    /* The interface to report for IP_PKTINFO: the one that owns the destination
                     * address (a datagram to a local address of an adapter arrives over the
                     * loopback interface, but is reported on the adapter, as on Windows), else
                     * the one it arrived on. Only looked up for a receive that asked for it;
                     * the interface list lock nests inside the address file lock. */
                    OwnerIF = AddrLocateInterface(DstAddress);
                    if (OwnerIF)
                        PktInfo->IfIndex = OwnerIF->Index;
                    else if (Interface)
                        PktInfo->IfIndex = Interface->Index;
                    else
                        PktInfo->IfIndex = 0;

                    PktInfo->DstAddress = DstAddress->Address.IPv4Address;
                    PktInfo->Valid = DG_PKTINFO_V4;
                }
                else if (Current->ReturnInfo &&
                         Current->ReturnInfo->Options &&
                         Current->ReturnInfo->OptionsLength == sizeof(DG_RECV_PKTINFO) &&
                         DstAddress->Type == IP_ADDRESS_V6 && Info6)
                {
                    PDG_RECV_PKTINFO PktInfo = Current->ReturnInfo->Options;

                    /* The interface the datagram arrived on (udp6.c) and its hop limit */
                    RtlCopyMemory(PktInfo->DstAddress6, DstAddress->Address.IPv6Address, sizeof(PktInfo->DstAddress6));
                    PktInfo->IfIndex = Info6->IfIndex;
                    PktInfo->HopLimit = Info6->HopLimit;
                    PktInfo->DstAddress = 0;
                    PktInfo->Valid = DG_PKTINFO_V6;
                }

                TI_DbgPrint(MAX_TRACE, ("(A: %08x) Addr %08x Port %04x\n",
                            RTAIPAddress,
                            SrcAddress->Address.IPv4Address, SrcPort));

                ReferenceObject(AddrFile);
                UnlockObject(AddrFile);

                /* Dropped outside the address file lock: the last reference frees the interface */
                if (OwnerIF)
                {
                    IPDereferenceInterface(OwnerIF);
                    OwnerIF = NULL;
                }

                /* Complete the receive request */
                if (Current->BufferSize < DataSize)
                    Current->Complete(Current->Context, STATUS_BUFFER_OVERFLOW, Current->BufferSize);
                else
                    Current->Complete(Current->Context, STATUS_SUCCESS, DataSize);

                LockObject(AddrFile);
                InterlockedDecrement(&AddrFile->Completing);
                DereferenceObject(AddrFile);

                /* A datagram is delivered to one receive. The lock was dropped for the
                   completion: the entry saved before it may have been cancelled and freed
                   since, so the walk does not continue */
                Delivered = TRUE;
                break;
            }
        }

        UnlockObject(AddrFile);
    }
    else if (AddrFile->RegisteredReceiveDatagramHandler)
    {
        PTDI_IND_RECEIVE_DATAGRAM ReceiveHandler = AddrFile->ReceiveDatagramHandler;
        PVOID HandlerContext = AddrFile->ReceiveDatagramHandlerContext;
        PVOID OptionsData = NULL;
        INT32 OptionsSize = 0;

        TI_DbgPrint(MAX_TRACE, ("Calling receive event handler.\n"));

        if (SrcAddress->Type == IP_ADDRESS_V4)
        {
            AddressLength = sizeof(IPv4_RAW_ADDRESS);
            SourceAddress = &SrcAddress->Address.IPv4Address;
            OptionsSize = IPPacket->HeaderSize - sizeof(IPv4_HEADER);
            if (OptionsSize > 0)
            {
                OptionsData = (PUCHAR)IPPacket->Header + sizeof(IPv4_HEADER);
            }
        }
        else /* (Address->Type == IP_ADDRESS_V6) */
        {
            AddressLength = sizeof(IPv6_RAW_ADDRESS);
            SourceAddress = SrcAddress->Address.IPv6Address;
        }

        ReferenceObject(AddrFile);
        /* Counted under the lock the handler was read under: whoever clears the handler
           and then owns its context waits for the count to drop before freeing it */
        InterlockedIncrement(&AddrFile->ReceiveHandlersActive);
        UnlockObject(AddrFile);

        TI_DbgPrint(MIN_TRACE, ("OptionsSize %d DataSize: %u\n", OptionsSize, DataSize));

        Status = (*ReceiveHandler)(HandlerContext,
            AddressLength,
            SourceAddress,
            OptionsSize,
            OptionsData,
            TDI_RECEIVE_ENTIRE_MESSAGE,
            DataSize,
            DataSize,
            &BytesTaken,
            DataBuffer,
            NULL);

        if (STATUS_SUCCESS != Status)
            TI_DbgPrint(MAX_TRACE, ("receive handler signaled failure with Status 0x%x\n", Status));

        InterlockedDecrement(&AddrFile->ReceiveHandlersActive);
        DereferenceObject(AddrFile);
        Delivered = TRUE;
    }
    else
    {
        UnlockObject(AddrFile);
        TI_DbgPrint(MAX_TRACE, ("No receive for the datagram.\n"));
    }

    TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));
    return Delivered;
}

/* A UDP datagram nobody could take at that moment. A datagram socket has one receive posted at a time: its owner
   (AFD) posts the next from inside the completion of the last one. Frames of an adapter are handled by one work
   item each, so a datagram that comes while another is being completed found no receive and was dropped (two
   group datagrams a few microseconds apart: 120-141 of 145 received on amd64). Such a datagram waits, while a
   completion is in progress on the socket, and the thread that completes it hands it on when the completion
   returns: to the receive posted by then, or it is dropped as before (no receive is posted when the owner's
   window is full, which keeps a full window dropping exactly what it did). */
#define DG_PENDING_MAX          128
#define DG_PENDING_MAX_BYTES    (256 * 1024)

typedef struct _DG_PENDING {
    LIST_ENTRY ListEntry;       /* first: the list is freed as pool blocks */
    IP_ADDRESS Src, Dst;
    USHORT SrcPort, DstPort;
    BOOLEAN HasInfo6;
    DG_RX_INFO6 Info6;
    UINT Size;
    UCHAR Data[1];
} DG_PENDING, *PDG_PENDING;

/* Hands the waiting datagrams to the receives posted, in order (the object lock is not held by the caller). Only
   one thread does it per socket at a time: a receive posted from a completion that runs here is served by the
   loop. With no receive posted and no completion in progress the waiting datagrams are dropped; while one is in
   progress, its thread comes back here */
static
VOID
DGFlushPending(PADDRESS_FILE AddrFile)
{
    PDG_PENDING P;
    IP_PACKET Packet;

    LockObject(AddrFile);
    if (AddrFile->PendingBusy)
    {
        UnlockObject(AddrFile);
        return;
    }
    AddrFile->PendingBusy = TRUE;

    while (!IsListEmpty(&AddrFile->PendingDatagrams))
    {
        if (IsListEmpty(&AddrFile->ReceiveQueue))
        {
            if (AddrFile->Completing == 0)
            {
                while (!IsListEmpty(&AddrFile->PendingDatagrams))
                    ExFreePoolWithTag(RemoveHeadList(&AddrFile->PendingDatagrams), DATAGRAM_PEND_TAG);
                AddrFile->PendingCount = 0;
                AddrFile->PendingBytes = 0;
            }
            break;
        }
        P = CONTAINING_RECORD(AddrFile->PendingDatagrams.Flink, DG_PENDING, ListEntry);
        RemoveEntryList(&P->ListEntry);
        AddrFile->PendingCount--;
        AddrFile->PendingBytes -= P->Size;
        UnlockObject(AddrFile);

        RtlZeroMemory(&Packet, sizeof(Packet));
        Packet.Type = P->Src.Type;
        Packet.Header = P->Data;
        Packet.Data = P->Data;
        Packet.TotalSize = P->Size;
        Packet.SrcAddr = P->Src;
        Packet.DstAddr = P->Dst;

        /* (a receive cancelled meanwhile drops it) */
        DGDeliverNow(NULL, AddrFile, &P->Src, &P->Dst, P->SrcPort, P->DstPort, &Packet, P->Size,
                     P->HasInfo6 ? &P->Info6 : NULL);
        ExFreePoolWithTag(P, DATAGRAM_PEND_TAG);
        LockObject(AddrFile);
    }

    AddrFile->PendingBusy = FALSE;
    UnlockObject(AddrFile);
}

/* Keeps a datagram until the completion in progress returns. FALSE: none is in progress (the caller drops it, or
   looks for a receive again); TRUE: it is kept, or dropped for want of room */
static
BOOLEAN
DGKeepPending(
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS SrcAddress,
    PIP_ADDRESS DstAddress,
    USHORT SrcPort,
    USHORT DstPort,
    PIP_PACKET IPPacket,
    UINT DataSize,
    PDG_RX_INFO6 Info6)
{
    PDG_PENDING P;

    /* Cheap when no completion is in progress: a socket whose window is full drops every datagram here */
    if (AddrFile->Completing == 0)
        return FALSE;

    P = ExAllocatePoolWithTag(NonPagedPool, FIELD_OFFSET(DG_PENDING, Data) + DataSize, DATAGRAM_PEND_TAG);
    if (!P)
        return TRUE;
    P->Src = *SrcAddress;
    P->Dst = *DstAddress;
    P->SrcPort = SrcPort;
    P->DstPort = DstPort;
    P->HasInfo6 = Info6 != NULL;
    if (Info6)
        P->Info6 = *Info6;
    P->Size = DataSize;
    RtlCopyMemory(P->Data, IPPacket->Data, DataSize);

    /* Under the lock the completion takes to end: it sees this datagram, or this sees it ended */
    LockObject(AddrFile);
    if (AddrFile->Completing == 0)
    {
        UnlockObject(AddrFile);
        ExFreePoolWithTag(P, DATAGRAM_PEND_TAG);
        return FALSE;
    }
    if (AddrFile->PendingCount >= DG_PENDING_MAX || AddrFile->PendingBytes + DataSize > DG_PENDING_MAX_BYTES)
    {
        UnlockObject(AddrFile);
        ExFreePoolWithTag(P, DATAGRAM_PEND_TAG);
        return TRUE;
    }
    InsertTailList(&AddrFile->PendingDatagrams, &P->ListEntry);
    AddrFile->PendingCount++;
    AddrFile->PendingBytes += DataSize;
    UnlockObject(AddrFile);
    return TRUE;
}

VOID
DGDeliverDataEx(
    PIP_INTERFACE Interface,
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS SrcAddress,
    PIP_ADDRESS DstAddress,
    USHORT SrcPort,
    USHORT DstPort,
    PIP_PACKET IPPacket,
    UINT DataSize,
    PDG_RX_INFO6 Info6)
{
    if (AddrFile->Protocol != IPPROTO_UDP)
    {
        DGDeliverNow(Interface, AddrFile, SrcAddress, DstAddress, SrcPort, DstPort, IPPacket, DataSize, Info6);
        return;
    }

    /* The datagrams that wait come first */
    if (!IsListEmpty(&AddrFile->PendingDatagrams))
        DGFlushPending(AddrFile);

    if (!DGDeliverNow(Interface, AddrFile, SrcAddress, DstAddress, SrcPort, DstPort, IPPacket, DataSize, Info6))
    {
        if (!DGKeepPending(AddrFile, SrcAddress, DstAddress, SrcPort, DstPort, IPPacket, DataSize, Info6))
        {
            /* No completion in progress: the receive may have been posted since the look above */
            if (!DGDeliverNow(Interface, AddrFile, SrcAddress, DstAddress, SrcPort, DstPort, IPPacket, DataSize,
                              Info6))
                TI_DbgPrint(MAX_TRACE, ("Discarding datagram.\n"));
        }
    }

    /* The completion that ended is the one that hands on what came during it */
    if (!IsListEmpty(&AddrFile->PendingDatagrams))
        DGFlushPending(AddrFile);
}

VOID DGReceiveComplete(PVOID Context, NTSTATUS Status, ULONG Count) {
    PDATAGRAM_RECEIVE_REQUEST ReceiveRequest =
	(PDATAGRAM_RECEIVE_REQUEST)Context;
    TI_DbgPrint(MAX_TRACE,("Called (%08x:%08x)\n", Status, Count));
    ReceiveRequest->UserComplete( ReceiveRequest->UserContext, Status, Count );
    ExFreePoolWithTag( ReceiveRequest, DATAGRAM_RECV_TAG );
    TI_DbgPrint(MAX_TRACE,("Done\n"));
}

NTSTATUS DGReceiveDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR BufferData,
    ULONG ReceiveLength,
    ULONG ReceiveFlags,
    PTDI_CONNECTION_INFORMATION ReturnInfo,
    PULONG BytesReceived,
    PDATAGRAM_COMPLETION_ROUTINE Complete,
    PVOID Context,
    PIRP Irp)
/*
 * FUNCTION: Attempts to receive an DG datagram from a remote address
 * ARGUMENTS:
 *     Request       = Pointer to TDI request
 *     ConnInfo      = Pointer to connection information
 *     Buffer        = Pointer to NDIS buffer chain to store received data
 *     ReceiveLength = Maximum size to use of buffer, 0 if all can be used
 *     ReceiveFlags  = Receive flags (None, Normal, Peek)
 *     ReturnInfo    = Pointer to structure for return information
 *     BytesReceive  = Pointer to structure for number of bytes received
 * RETURNS:
 *     Status of operation
 * NOTES:
 *     This is the high level interface for receiving DG datagrams
 */
{
    NTSTATUS Status;
    PDATAGRAM_RECEIVE_REQUEST ReceiveRequest;

    TI_DbgPrint(MAX_TRACE, ("Called.\n"));

    LockObject(AddrFile);

    ReceiveRequest = ExAllocatePoolWithTag(NonPagedPool, sizeof(DATAGRAM_RECEIVE_REQUEST),
                                           DATAGRAM_RECV_TAG);
    if (ReceiveRequest)
    {
	/* Initialize a receive request */

	/* Extract the remote address filter from the request (if any).
	 * A NULL ConnInfo means "no filter": guard it so a caller that posts a
	 * receive datagram without connection information cannot NULL-deref the
	 * transport (T134: an unbound raw AFD sendto reached here with NULL). */
	if ((ConnInfo != NULL) &&
	    (ConnInfo->RemoteAddressLength != 0) &&
	    (ConnInfo->RemoteAddress))
        {
	    Status = AddrGetAddress(ConnInfo->RemoteAddress,
				    &ReceiveRequest->RemoteAddress,
				    &ReceiveRequest->RemotePort);
	    if (!NT_SUCCESS(Status))
            {
		ExFreePoolWithTag(ReceiveRequest, DATAGRAM_RECV_TAG);
	        UnlockObject(AddrFile);
		return Status;
            }
	}
	else
        {
	    ReceiveRequest->RemotePort = 0;
	    AddrInitIPv4(&ReceiveRequest->RemoteAddress, 0);
        }

	IoMarkIrpPending(Irp);

	ReceiveRequest->ReturnInfo = ReturnInfo;
	ReceiveRequest->Buffer = BufferData;
	ReceiveRequest->BufferSize = ReceiveLength;
	ReceiveRequest->UserComplete = Complete;
	ReceiveRequest->UserContext = Context;
	ReceiveRequest->Complete =
		(PDATAGRAM_COMPLETION_ROUTINE)DGReceiveComplete;
	ReceiveRequest->Context = ReceiveRequest;
        ReceiveRequest->AddressFile = AddrFile;
        ReceiveRequest->Irp = Irp;

	/* Queue receive request */
	InsertTailList(&AddrFile->ReceiveQueue, &ReceiveRequest->ListEntry);

	TI_DbgPrint(MAX_TRACE, ("Leaving (pending %08x).\n", ReceiveRequest));

	UnlockObject(AddrFile);

	return STATUS_PENDING;
    }
    else
    {
	UnlockObject(AddrFile);
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    TI_DbgPrint(MAX_TRACE, ("Leaving with errors (0x%X).\n", Status));

    return Status;
}
