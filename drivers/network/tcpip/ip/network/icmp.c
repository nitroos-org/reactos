/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        network/icmp.c
 * PURPOSE:     Internet Control Message Protocol routines
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

#include <icmp.h>

NTSTATUS ICMPStartup()
{
    IPRegisterProtocol(IPPROTO_ICMP, ICMPReceive);

    return STATUS_SUCCESS;
}

NTSTATUS ICMPShutdown()
{
    IPRegisterProtocol(IPPROTO_ICMP, NULL);

    return STATUS_SUCCESS;
}

NTSTATUS ICMPSendDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed )
/*
 * FUNCTION: Sends an ICMP datagram to a remote address
 * ARGUMENTS:
 *     Request   = Pointer to TDI request
 *     ConnInfo  = Pointer to connection information
 *     Buffer    = Pointer to NDIS buffer with data
 *     DataSize  = Size in bytes of data to be sent
 * RETURNS:
 *     Status of operation
 */
{
    TI_DbgPrint(DEBUG_ICMP, ("Sending ICMP datagram (0x%x)\n", AddrFile));

    /* just forward the call to RawIP handler */
    return RawIPSendDatagram(AddrFile, ConnInfo, BufferData, DataSize, DataUsed);
}


VOID ICMPReceive(
    PIP_INTERFACE Interface,
    PIP_PACKET IPPacket)
/*
 * FUNCTION: Receives an ICMP packet
 * ARGUMENTS:
 *     NTE      = Pointer to net table entry which the packet was received on
 *     IPPacket = Pointer to an IP packet that was received
 */
{
    PICMP_HEADER ICMPHeader = (PICMP_HEADER)IPPacket->Data;
    UINT32 DataSize = IPPacket->TotalSize - IPPacket->HeaderSize;

    TI_DbgPrint(DEBUG_ICMP, ("ICMPReceive: Size (%d) HeaderSize (%d) Type (%d) Code (%d) Checksum (0x%x)\n",
        IPPacket->TotalSize, IPPacket->HeaderSize, ICMPHeader->Type, ICMPHeader->Code, ICMPHeader->Checksum));

    /* Discard too short packets */
    if (DataSize < sizeof(ICMP_HEADER))
    {
        TI_DbgPrint(DEBUG_ICMP, ("Packet doesn't fit ICMP header. Discarded\n"));
        return;
    }

    /* Discard packets with bad checksum */
    if (!IPv4CorrectChecksum(IPPacket->Data, DataSize))
    {
        TI_DbgPrint(DEBUG_ICMP, ("Bad ICMP checksum. Packet discarded\n"));
        return;
    }

    RawIpReceive(Interface, IPPacket);

    if (ICMPHeader->Type == ICMP_TYPE_ECHO_REQUEST)
    {
        ICMPReply(Interface, IPPacket, ICMP_TYPE_ECHO_REPLY, 0);
    }
    else if (ICMPHeader->Type == ICMP_TYPE_DEST_UNREACH && ICMPHeader->Code == ICMP_CODE_DU_PORT_UNREACH)
    {
        /* The UDP socket that sent the datagram fails its next receive (WSAECONNRESET) */
        UDPPortUnreachable(IPPacket, (PUCHAR)IPPacket->Data, DataSize);
    }
}

/*
 * A UDP datagram for a port nobody has: ICMP destination unreachable, port unreachable (RFC 1122 4.1.3.1, RFC 792),
 * with the datagram's IP header and the first 8 bytes of its data (the UDP header), from the address it was sent
 * to. Not for a datagram to a broadcast or multicast address or from an address that is not a unicast one
 * (RFC 1122 3.2.2), and at most ICMP_UNREACH_PER_SECOND a second (RFC 1812 4.3.2.8). Windows answers so, which is
 * what makes the sender's next receive fail with WSAECONNRESET (evidence v6raw-20261116).
 */
#define ICMP_UNREACH_PER_SECOND 200

VOID ICMPPortUnreachable(
    PIP_INTERFACE Interface,
    PIP_PACKET IPPacket,
    PVOID TransportHeader)
{
    static LONG Sent;
    static LONGLONG Window;
    UCHAR Buffer[8 + 60 + 8];
    UINT Size, HeaderSize = IPPacket->HeaderSize;
    LARGE_INTEGER Now;
    IP_PACKET NewPacket;
    ADDRESS_FILE FakeAddrFile;
    PNEIGHBOR_CACHE_ENTRY NCE;
    IP_ADDRESS ReplySource;
    ULONG Src, Dst;

    if (IPPacket->Type != IP_ADDRESS_V4 || HeaderSize < sizeof(IPv4_HEADER) || HeaderSize > 60)
        return;
    Src = IPPacket->SrcAddr.Address.IPv4Address;
    Dst = IPPacket->DstAddr.Address.IPv4Address;
    if (Src == 0 || Src == 0xFFFFFFFF || (Src & 0xF0) == 0xE0 || Dst == 0xFFFFFFFF || (Dst & 0xF0) == 0xE0)
        return;
    AddrInitIPv4(&ReplySource, 0);
    if (AddrIsBroadcastMatch(&ReplySource, &IPPacket->DstAddr) || AddrIsBroadcastMatch(&ReplySource, &IPPacket->SrcAddr))
        return;

    KeQuerySystemTime(&Now);
    if (Now.QuadPart - Window >= 10000000LL)
    {
        Window = Now.QuadPart;
        Sent = 0;
    }
    if (InterlockedIncrement(&Sent) > ICMP_UNREACH_PER_SECOND)
        return;

    NCE = RouteGetRouteToDestination(&IPPacket->SrcAddr);
    if (!NCE)
        return;

    Size = 8 + HeaderSize + 8;
    RtlZeroMemory(Buffer, 8);
    Buffer[0] = ICMP_TYPE_DEST_UNREACH;
    Buffer[1] = ICMP_CODE_DU_PORT_UNREACH;
    RtlCopyMemory(Buffer + 8, IPPacket->Header, HeaderSize);
    RtlCopyMemory(Buffer + 8 + HeaderSize, TransportHeader, 8);

    RtlZeroMemory(&FakeAddrFile, sizeof(FakeAddrFile));
    FakeAddrFile.Protocol = IPPROTO_ICMP;
    FakeAddrFile.TTL = 128;

    /* From the address the datagram went to when it is ours, else from the interface */
    ReplySource = Interface->Unicast;
    if (IFIsNteIPv4Address(Interface, Dst) || AddrIsEqual(&Interface->Unicast, &IPPacket->DstAddr) ||
        (Dst & 0xFF) == 0x7F)
        ReplySource = IPPacket->DstAddr;

    if (!NT_SUCCESS(BuildRawIpPacket(&FakeAddrFile, &NewPacket, &IPPacket->SrcAddr, 0, &ReplySource, 0,
                                     (PCHAR)Buffer, Size)))
    {
        NBDereferenceNeighbor(NCE);
        return;
    }
    ((PICMP_HEADER)NewPacket.Data)->Checksum = 0;
    ((PICMP_HEADER)NewPacket.Data)->Checksum = (USHORT)IPv4Checksum(NewPacket.Data, Size, 0);

    IPSendDatagram(&NewPacket, NCE);
    NBDereferenceNeighbor(NCE);
}

VOID ICMPReply(
    PIP_INTERFACE Interface,
    PIP_PACKET IPPacket,
    UCHAR Type,
    UCHAR Code)
/*
 * FUNCTION: Transmits an ICMP packet in response to an incoming packet
 * ARGUMENTS:
 *     NTE      = Pointer to net table entry to use
 *     IPPacket = Pointer to IP packet that was received
 *     Type     = ICMP message type
 *     Code     = ICMP message code
 * NOTES:
 *     We have received a packet from someone and is unable to
 *     process it due to error(s) in the packet or we have run out
 *     of resources. We transmit an ICMP message to the host to
 *     notify him of the problem
 */
{
    UINT DataSize;
    IP_PACKET NewPacket;
    ADDRESS_FILE FakeAddrFile;
    PNEIGHBOR_CACHE_ENTRY NCE;
    IP_ADDRESS ReplySource;

    TI_DbgPrint(DEBUG_ICMP, ("Called. Type (%d)  Code (%d).\n", Type, Code));

    DataSize = IPPacket->TotalSize - IPPacket->HeaderSize;

    /* First check if we have a route to sender */
    NCE = RouteGetRouteToDestination(&IPPacket->SrcAddr);
    if (!NCE)
    {
        return;
    }

    /* This is the only data needed to generate a packet */
    FakeAddrFile.Protocol = IPPROTO_ICMP;
    FakeAddrFile.TTL = 128;

    /* An additional address of the interface answers from itself, not from the primary address */
    ReplySource = Interface->Unicast;
    if (IPPacket->DstAddr.Type == IP_ADDRESS_V4 &&
        IFIsNteIPv4Address(Interface, IPPacket->DstAddr.Address.IPv4Address))
        ReplySource = IPPacket->DstAddr;

    if (!NT_SUCCESS(BuildRawIpPacket(
        &FakeAddrFile, &NewPacket, &IPPacket->SrcAddr, 0, &ReplySource, 0, IPPacket->Data, DataSize)))
    {
        NBDereferenceNeighbor(NCE);
        return;
    }

    ((PICMP_HEADER)NewPacket.Data)->Type     = Type;
    ((PICMP_HEADER)NewPacket.Data)->Code     = Code;
    ((PICMP_HEADER)NewPacket.Data)->Checksum = 0;
    ((PICMP_HEADER)NewPacket.Data)->Checksum = (USHORT)IPv4Checksum(NewPacket.Data, DataSize, 0);

    IPSendDatagram(&NewPacket, NCE);
    NBDereferenceNeighbor(NCE);
}

/* EOF */
