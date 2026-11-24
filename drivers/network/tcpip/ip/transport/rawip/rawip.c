/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        transport/rawip/rawip.c
 * PURPOSE:     User Datagram Protocol routines
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"
#include <icmp.h>
#include <nitrofwk.h>

NTSTATUS AddGenericHeaderIPv4(
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS RemoteAddress,
    USHORT RemotePort,
    PIP_ADDRESS LocalAddress,
    USHORT LocalPort,
    PIP_PACKET IPPacket,
    UINT DataLength,
    UINT Protocol,
    UINT ExtraLength,
    PVOID *NextHeader )
/*
 * FUNCTION: Adds an IPv4 and RawIp header to an IP packet
 * ARGUMENTS:
 *     SendRequest  = Pointer to send request
 *     LocalAddress = Pointer to our local address
 *     LocalPort    = The port we send this datagram from
 *     IPPacket     = Pointer to IP packet
 * RETURNS:
 *     Status of operation
 */
{
    PIPv4_HEADER IPHeader;
    ULONG BufferSize;

    TI_DbgPrint(MID_TRACE, ("Packet: %x NdisPacket %x\n",
			    IPPacket, IPPacket->NdisPacket));

    BufferSize = sizeof(IPv4_HEADER) + ExtraLength;

    GetDataPtr( IPPacket->NdisPacket,
		0,
		(PCHAR *)&IPPacket->Header,
		&IPPacket->TotalSize );
    IPPacket->MappedHeader = TRUE;

    IPPacket->HeaderSize = sizeof(IPv4_HEADER);

    TI_DbgPrint(MAX_TRACE, ("Allocated %d bytes for headers at 0x%X.\n",
			    BufferSize, IPPacket->Header));
    TI_DbgPrint(MAX_TRACE, ("Packet total length %d\n", IPPacket->TotalSize));

    /* Build IPv4 header */
    IPHeader = (PIPv4_HEADER)IPPacket->Header;
    /* Version = 4, Length = 5 DWORDs */
    IPHeader->VerIHL = 0x45;
    /* Normal Type-of-Service */
    IPHeader->Tos = 0;
    /* Length of header and data */
    IPHeader->TotalLength = WH2N((USHORT)IPPacket->TotalSize);
    /* Identification */
    IPHeader->Id = (USHORT)Random();
    /* One fragment at offset 0 */
    IPHeader->FlagsFragOfs = 0;
    /* Time-to-Live */
    IPHeader->Ttl = AddrFile->TTL;
    /* Protocol */
    IPHeader->Protocol = Protocol;
    /* Checksum is 0 (for later calculation of this) */
    IPHeader->Checksum = 0;
    /* Source address */
    IPHeader->SrcAddr = LocalAddress->Address.IPv4Address;
    /* Destination address. FIXME: IPv4 only */
    IPHeader->DstAddr = RemoteAddress->Address.IPv4Address;

    /* Build RawIp header */
    *NextHeader = (((PCHAR)IPHeader) + sizeof(IPv4_HEADER));
    IPPacket->Data = ((PCHAR)*NextHeader) + ExtraLength;

    return STATUS_SUCCESS;
}


NTSTATUS BuildRawIpPacket(
    PADDRESS_FILE AddrFile,
    PIP_PACKET Packet,
    PIP_ADDRESS RemoteAddress,
    USHORT RemotePort,
    PIP_ADDRESS LocalAddress,
    USHORT LocalPort,
    PCHAR DataBuffer,
    UINT DataLen )
/*
 * FUNCTION: Builds an RawIp packet
 * ARGUMENTS:
 *     Context      = Pointer to context information (DATAGRAM_SEND_REQUEST)
 *     LocalAddress = Pointer to our local address
 *     LocalPort    = The port we send this datagram from
 *     IPPacket     = Address of pointer to IP packet
 * RETURNS:
 *     Status of operation
 */
{
    NTSTATUS Status;
    PCHAR Payload;

    TI_DbgPrint(MAX_TRACE, ("Called.\n"));

    /* FIXME: Assumes IPv4 */
    IPInitializePacket(Packet, IP_ADDRESS_V4);

    Packet->TotalSize = sizeof(IPv4_HEADER) + DataLen;

    /* Prepare packet */
    Status = AllocatePacketWithBuffer( &Packet->NdisPacket,
				       NULL,
				       Packet->TotalSize );

    if( !NT_SUCCESS(Status) ) return Status;

    TI_DbgPrint(MID_TRACE, ("Allocated packet: %x\n", Packet->NdisPacket));
    TI_DbgPrint(MID_TRACE, ("Local Addr : %s\n", A2S(LocalAddress)));
    TI_DbgPrint(MID_TRACE, ("Remote Addr: %s\n", A2S(RemoteAddress)));

    switch (RemoteAddress->Type) {
    case IP_ADDRESS_V4:
	Status = AddGenericHeaderIPv4
            (AddrFile, RemoteAddress, RemotePort,
             LocalAddress, LocalPort, Packet, DataLen,
             AddrFile->Protocol,
             0, (PVOID *)&Payload );
	break;
    case IP_ADDRESS_V6:
	/* FIXME: Support IPv6 */
        Status = STATUS_UNSUCCESSFUL;
	TI_DbgPrint(MIN_TRACE, ("IPv6 RawIp datagrams are not supported.\n"));
        break;

    default:
	Status = STATUS_UNSUCCESSFUL;
        TI_DbgPrint(MIN_TRACE, ("Bad Address Type %d\n", RemoteAddress->Type));
	break;
    }

    if( !NT_SUCCESS(Status) ) {
        TI_DbgPrint(MIN_TRACE, ("Cannot add header. Status = (0x%X)\n",
                                Status));
        Packet->Free(Packet);
        return Status;
    }

    TI_DbgPrint(MID_TRACE, ("Copying data (hdr %x data %x (%d))\n",
			    Packet->Header, Packet->Data,
			    (PCHAR)Packet->Data - (PCHAR)Packet->Header));

    if (DataLen)
        RtlCopyMemory( Packet->Data, DataBuffer, DataLen );

    Packet->Flags |= IP_PACKET_FLAG_RAW;

    TI_DbgPrint(MID_TRACE, ("Displaying packet\n"));

    DISPLAY_IP_PACKET(Packet);

    TI_DbgPrint(MID_TRACE, ("Leaving\n"));

    return STATUS_SUCCESS;
}

/* An unprivileged raw socket (an ICMP socket of a standard user, AddrFile->RawPrivileged clear) sends echo requests
   of at least 8 bytes only: anything else is WSAEACCES at sendto on Windows (Windows Server 2022 and 10, evidence
   v6raw-20261116) */
BOOLEAN
RawIpUnprivilegedMaySend(PADDRESS_FILE AddrFile, PCHAR Data, ULONG Size)
{
    UCHAR Type;

    if (AddrFile->RawPrivileged)
        return TRUE;
    if (AddrFile->Protocol != IPPROTO_ICMP || Size < 8)
        return FALSE;
    /* (the send's buffer is the system mapping of its locked MDL, DispTdiSendDatagram) */
    Type = *(PUCHAR)Data;
    return Type == 8;   /* ICMP echo request */
}

/*
 * An echo request to a neighbour whose link address is not known yet does not make its sender wait for the resolution
 * (IPSendDatagram does, and gave up with ERROR_HOST_UNREACHABLE after the resolution failed, whatever time limit the
 * request had). It waits on the neighbour like a TCP segment does, and the request runs on its own time limit
 * (IP_REQ_TIMED_OUT). When the resolution fails first, the sender gets what Windows gives it (measured on Windows
 * Server 2022, IPv4 and IPv6): a reply with the status IP_DEST_HOST_UNREACHABLE from the address of its own interface,
 * which is an ICMP "host unreachable" message made here and delivered to the ICMP address files like one from a
 * router. The message is delivered from a work item: the neighbour completes the packet at DISPATCH_LEVEL under its
 * bucket lock (which the address file locks are taken before elsewhere), and the receive handler of an echo request
 * needs PASSIVE_LEVEL.
 */
#define RAW_ECHO_QUOTE_MAX (60 + 8)

typedef struct _RAW_ECHO_FAILURE
{
    WORK_QUEUE_ITEM WorkItem;
    PIP_INTERFACE Interface;        /* referenced */
    IP_ADDRESS Local;
    UINT QuoteSize;
    UCHAR Quote[RAW_ECHO_QUOTE_MAX];    /* the IP header of the request and the first 8 bytes of its ICMP message */
} RAW_ECHO_FAILURE, *PRAW_ECHO_FAILURE;

static
VOID
NTAPI
RawIpEchoFailureWorker(PVOID Context)
{
    PRAW_ECHO_FAILURE Failure = Context;
    UCHAR Buffer[8 + RAW_ECHO_QUOTE_MAX];
    ADDRESS_FILE FakeAddrFile;
    IP_PACKET NewPacket;
    UINT Size = 8 + Failure->QuoteSize;

    RtlZeroMemory(Buffer, 8);
    Buffer[0] = ICMP_TYPE_DEST_UNREACH;
    Buffer[1] = ICMP_CODE_DU_HOST_UNREACH;
    RtlCopyMemory(Buffer + 8, Failure->Quote, Failure->QuoteSize);

    RtlZeroMemory(&FakeAddrFile, sizeof(FakeAddrFile));
    FakeAddrFile.Protocol = IPPROTO_ICMP;
    FakeAddrFile.TTL = 128;

    if (NT_SUCCESS(BuildRawIpPacket(&FakeAddrFile, &NewPacket, &Failure->Local, 0, &Failure->Local, 0,
                                    (PCHAR)Buffer, Size)))
    {
        ((PICMP_HEADER)NewPacket.Data)->Checksum = 0;
        ((PICMP_HEADER)NewPacket.Data)->Checksum = (USHORT)IPv4Checksum(NewPacket.Data, Size, 0);
        /* a received packet carries its addresses (BuildRawIpPacket fills the header only) */
        NewPacket.SrcAddr = Failure->Local;
        NewPacket.DstAddr = Failure->Local;
        RawIpReceive(Failure->Interface, &NewPacket);
        NewPacket.Free(&NewPacket);
    }

    IPDereferenceInterface(Failure->Interface);
    ExFreePoolWithTag(Failure, OUT_DATA_TAG);
}

/* Called by the neighbour cache (at DISPATCH_LEVEL, under a bucket lock) when the packet has left or the neighbour
   could not be resolved */
static
VOID
RawIpEchoComplete(PVOID Context, PNDIS_PACKET NdisPacket, NDIS_STATUS NdisStatus)
{
    PRAW_ECHO_FAILURE Failure = Context;

    FreeNdisPacket(NdisPacket);
    if (NdisStatus == NDIS_STATUS_HOST_UNREACHABLE)
    {
        ExInitializeWorkItem(&Failure->WorkItem, RawIpEchoFailureWorker, Failure);
        ExQueueWorkItem(&Failure->WorkItem, DelayedWorkQueue);
        return;
    }
    IPDereferenceInterface(Failure->Interface);
    ExFreePoolWithTag(Failure, OUT_DATA_TAG);
}

/* Queues the datagram (one fragment, within the interface's MTU) on its neighbour and returns at once. Takes the packet */
static
NTSTATUS
RawIpQueueEchoOnNeighbour(PIP_PACKET Packet, PNEIGHBOR_CACHE_ENTRY NCE, PIP_ADDRESS Local)
{
    PRAW_ECHO_FAILURE Failure;
    PNDIS_PACKET NdisPacket;
    PIPv4_HEADER Header;
    PCHAR Data;
    UINT InSize;
    NDIS_STATUS NdisStatus;

    if (Packet->HeaderSize < sizeof(IPv4_HEADER) || Packet->HeaderSize > 60 ||
        Packet->TotalSize < Packet->HeaderSize + 8)
    {
        Packet->Free(Packet);
        return STATUS_INVALID_PARAMETER;
    }

    Failure = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Failure), OUT_DATA_TAG);
    if (!Failure)
    {
        Packet->Free(Packet);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Failure->Interface = NCE->Interface;
    Failure->Local = *Local;
    Failure->QuoteSize = Packet->HeaderSize + 8;
    RtlCopyMemory(Failure->Quote, Packet->Header, Packet->HeaderSize);
    RtlCopyMemory(Failure->Quote + Packet->HeaderSize, (PUCHAR)Packet->Header + Packet->HeaderSize, 8);

    NdisStatus = AllocatePacketWithBuffer(&NdisPacket, NULL, Packet->TotalSize);
    if (!NT_SUCCESS(NdisStatus))
    {
        ExFreePoolWithTag(Failure, OUT_DATA_TAG);
        Packet->Free(Packet);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    GetDataPtr(NdisPacket, 0, &Data, &InSize);
    RtlCopyMemory(Data, Packet->Header, Packet->TotalSize);
    Header = (PIPv4_HEADER)Data;
    Header->FlagsFragOfs = 0;
    Header->TotalLength = WH2N((USHORT)Packet->TotalSize);
    Header->Checksum = 0;
    Header->Checksum = (USHORT)IPv4Checksum(Header, Packet->HeaderSize, 0);
    Packet->Free(Packet);

    IPReferenceInterface(NCE->Interface);
    if (!NBQueuePacket(NCE, NdisPacket, RawIpEchoComplete, Failure))
    {
        IPDereferenceInterface(NCE->Interface);
        FreeNdisPacket(NdisPacket);
        ExFreePoolWithTag(Failure, OUT_DATA_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}

NTSTATUS RawIPSendDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed )
/*
 * FUNCTION: Sends an RawIp datagram to a remote address
 * ARGUMENTS:
 *     Request   = Pointer to TDI request
 *     ConnInfo  = Pointer to connection information
 *     Buffer    = Pointer to NDIS buffer with data
 *     DataSize  = Size in bytes of data to be sent
 * RETURNS:
 *     Status of operation
 */
{
    IP_PACKET Packet;
    PTA_IP_ADDRESS RemoteAddressTa = (PTA_IP_ADDRESS)ConnInfo->RemoteAddress;
    IP_ADDRESS RemoteAddress,  LocalAddress;
    USHORT RemotePort;
    NTSTATUS Status;
    PNEIGHBOR_CACHE_ENTRY NCE;
    BOOLEAN Multicast;

    if (!RawIpUnprivilegedMaySend(AddrFile, BufferData, DataSize))
        return STATUS_ACCESS_DENIED;

    LockObject(AddrFile);

    TI_DbgPrint(MID_TRACE,("Sending Datagram(%x %x %x %d)\n",
			   AddrFile, ConnInfo, BufferData, DataSize));
    TI_DbgPrint(MID_TRACE,("RemoteAddressTa: %x\n", RemoteAddressTa));

    switch( RemoteAddressTa->Address[0].AddressType ) {
        case TDI_ADDRESS_TYPE_IP:
            RemoteAddress.Type = IP_ADDRESS_V4;
            RemoteAddress.Address.IPv4Address =
            RemoteAddressTa->Address[0].Address[0].in_addr;
            RemotePort = RemoteAddressTa->Address[0].Address[0].sin_port;
            break;

        default:
            UnlockObject(AddrFile);
            return STATUS_UNSUCCESSFUL;
    }

    TI_DbgPrint(MID_TRACE,("About to get route to destination\n"));

    LocalAddress = AddrFile->Address;
    Multicast = IPV4_IS_MULTICAST(RemoteAddress.Address.IPv4Address);
    if (Multicast)
    {
        /* A group: its Ethernet address on the chosen interface (udp.c does the same), never a router */
        if (!(NCE = RouteGetMulticastNeighbor(&RemoteAddress, AddrFile->McastIf, &LocalAddress))) {
            UnlockObject(AddrFile);
            return AddrFile->McastIf ? STATUS_INVALID_ADDRESS : STATUS_NETWORK_UNREACHABLE;
        }
        if (AddrIsUnspecified(&LocalAddress))
        {
            LocalAddress = NCE->Interface->Unicast;
            LocalAddress.Address.IPv4Address = IFSelectSourceAddress(NCE->Interface,
                                                                     RemoteAddress.Address.IPv4Address);
        }
    }
    else if (AddrIsUnspecified(&LocalAddress))
    {
        /* If the local address is unspecified (0),
         * then use the unicast address of the
         * interface we're sending over
         */
        if(!(NCE = RouteGetRouteToDestination( &RemoteAddress ))) {
            UnlockObject(AddrFile);
            return STATUS_NETWORK_UNREACHABLE;
        }

        LocalAddress = NCE->Interface->Unicast;
        LocalAddress.Address.IPv4Address = IFSelectSourceAddress(NCE->Interface, RemoteAddress.Address.IPv4Address);
    }
    else
    {
        if(!(NCE = NBLocateNeighbor( &LocalAddress, NULL ))) {
            UnlockObject(AddrFile);
            return STATUS_INVALID_PARAMETER;
        }
    }

    Status = BuildRawIpPacket( AddrFile,
                               &Packet,
                               &RemoteAddress,
                               RemotePort,
                               &LocalAddress,
                               AddrFile->Port,
                               BufferData,
                               DataSize );

    /* A group's datagram has the multicast TTL (IP_MULTICAST_TTL); 0 sends nothing on the wire */
    if (NT_SUCCESS(Status) && Multicast)
        ((PIPv4_HEADER)Packet.Header)->Ttl = AddrFile->McastHops;

    UnlockObject(AddrFile);

    if( !NT_SUCCESS(Status) )
    {
        NBDereferenceNeighbor(NCE);
        return Status;
    }

    if (Multicast && ((PIPv4_HEADER)Packet.Header)->Ttl == 0)
    {
        Packet.Free(&Packet);
        NBDereferenceNeighbor(NCE);
        *DataUsed = DataSize;
        return STATUS_SUCCESS;
    }

    TI_DbgPrint(MID_TRACE,("About to send datagram\n"));

    /* the inbound filter lets the reply to this ICMP request through */
    if (AddrFile->Protocol == IPPROTO_ICMP)
        NITROFW_NOTE_ICMP_SEND(&RemoteAddress, (PUCHAR)BufferData, DataSize);

    /* an echo request to a neighbour that is not resolved yet is queued on it, not waited for */
    if (AddrFile->Protocol == IPPROTO_ICMP && !Multicast && DataSize >= 8 && *(PUCHAR)BufferData == ICMP_TYPE_ECHO_REQUEST &&
        (NCE->State & NUD_INCOMPLETE) && NCE->Interface->MTU != 0 && Packet.TotalSize <= NCE->Interface->MTU)
        Status = RawIpQueueEchoOnNeighbour(&Packet, NCE, &LocalAddress);
    else
        Status = IPSendDatagram(&Packet, NCE);
    NBDereferenceNeighbor(NCE);
    if (!NT_SUCCESS(Status))
        return Status;

    *DataUsed = DataSize;

    TI_DbgPrint(MID_TRACE,("Leaving\n"));

    return STATUS_SUCCESS;
}


VOID RawIpReceive(PIP_INTERFACE Interface, PIP_PACKET IPPacket)
/*
 * FUNCTION: Receives and queues a RawIp datagram
 * ARGUMENTS:
 *     NTE      = Pointer to net table entry which the packet was received on
*     IPPacket = Pointer to an IP packet that was received
* NOTES:
*     This is the low level interface for receiving RawIp datagrams. It strips
*     the RawIp header from a packet and delivers the data to anyone that wants it
*/
{
  AF_SEARCH SearchContext;
  PIPv4_HEADER IPv4Header;
  PADDRESS_FILE AddrFile;
  PIP_ADDRESS DstAddress, SrcAddress;
  UINT DataSize;

  TI_DbgPrint(MAX_TRACE, ("Called.\n"));

  switch (IPPacket->Type) {
  /* IPv4 packet */
  case IP_ADDRESS_V4:
    IPv4Header = IPPacket->Header;
    DstAddress = &IPPacket->DstAddr;
    SrcAddress = &IPPacket->SrcAddr;
    DataSize = IPPacket->TotalSize;
    break;

  /* IPv6 packet */
  case IP_ADDRESS_V6:
    TI_DbgPrint(MIN_TRACE, ("Discarded IPv6 datagram (%i bytes).\n", IPPacket->TotalSize));

    /* FIXME: IPv6 is not supported */
    return;

  default:
    return;
  }

  /* Locate a receive request on destination address file object
     and deliver the packet if one is found. If there is no receive
     request on the address file object, call the associated receive
     handler. If no receive handler is registered, drop the packet */

  AddrFile = AddrSearchFirst(DstAddress,
                             0,
                             IPv4Header->Protocol,
                             &SearchContext);
  if (AddrFile) {
    do {
      DGDeliverData(Interface,
		    AddrFile,
		    SrcAddress,
                    DstAddress,
                    0,
                    0,
                    IPPacket,
                    DataSize);
      DereferenceObject(AddrFile);
    } while ((AddrFile = AddrSearchNext(&SearchContext)) != NULL);
  } else {
    /* There are no open address files that will take this datagram */
    /* FIXME: IPv4 only */
    TI_DbgPrint(MID_TRACE, ("Cannot deliver IPv4 raw datagram to address (0x%X).\n",
                            DN2H(DstAddress->Address.IPv4Address)));

    /* FIXME: Send ICMP reply */
  }
  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));
}


NTSTATUS RawIPStartup(VOID)
/*
 * FUNCTION: Initializes the UDP subsystem
 * RETURNS:
 *     Status of operation
 */
{
  RtlZeroMemory(&UDPStats, sizeof(UDP_STATISTICS));

  /* Register this protocol with IP layer */
  IPRegisterProtocol(IPPROTO_RAW, RawIpReceive);

  RawIp6Startup();

  return STATUS_SUCCESS;
}


NTSTATUS RawIPShutdown(VOID)
/*
 * FUNCTION: Shuts down the UDP subsystem
 * RETURNS:
 *     Status of operation
 */
{
  /* Deregister this protocol with IP layer */
  IPRegisterProtocol(IPPROTO_RAW, NULL);

  return STATUS_SUCCESS;
}

/* EOF */
