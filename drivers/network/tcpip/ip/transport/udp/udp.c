/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        transport/udp/udp.c
 * PURPOSE:     User Datagram Protocol routines
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"
#include <nitrofwk.h>
#include <icmp.h>
#include <nitrotdi.h>
#include "lwip/netif.h"
#include "lwip/tcpip.h"

/* if6.c: sets an adapter's multicast list again (core lock held) */
VOID TCP6UpdateMulticastList(struct netif *netif);

BOOLEAN UDPInitialized = FALSE;
PORT_SET UDPPorts;

NTSTATUS AddUDPHeaderIPv4(
    PADDRESS_FILE AddrFile,
    PIP_ADDRESS RemoteAddress,
    USHORT RemotePort,
    PIP_ADDRESS LocalAddress,
    USHORT LocalPort,
    PIP_PACKET IPPacket,
    PVOID Data,
    UINT DataLength)
/*
 * FUNCTION: Adds an IPv4 and UDP header to an IP packet
 * ARGUMENTS:
 *     SendRequest  = Pointer to send request
 *     LocalAddress = Pointer to our local address
 *     LocalPort    = The port we send this datagram from
 *     IPPacket     = Pointer to IP packet
 * RETURNS:
 *     Status of operation
 */
{
    PUDP_HEADER UDPHeader;
    NTSTATUS Status;

    TI_DbgPrint(MID_TRACE, ("Packet: %x NdisPacket %x\n",
			    IPPacket, IPPacket->NdisPacket));

    Status = AddGenericHeaderIPv4
        ( AddrFile, RemoteAddress, RemotePort,
          LocalAddress, LocalPort,
          IPPacket, DataLength, IPPROTO_UDP,
          sizeof(UDP_HEADER), (PVOID *)&UDPHeader );

    if (!NT_SUCCESS(Status))
        return Status;

    /* Port values are already big-endian values */
    UDPHeader->SourcePort = LocalPort;
    UDPHeader->DestPort   = RemotePort;
    UDPHeader->Checksum   = 0;
    /* Length of UDP header and data */
    UDPHeader->Length     = WH2N(DataLength + sizeof(UDP_HEADER));

    TI_DbgPrint(MID_TRACE, ("Copying data (hdr %x data %x (%d))\n",
			    IPPacket->Header, IPPacket->Data,
			    (PCHAR)IPPacket->Data - (PCHAR)IPPacket->Header));

    if (DataLength)
        RtlCopyMemory(IPPacket->Data, Data, DataLength);

    UDPHeader->Checksum = UDPv4ChecksumCalculate((PIPv4_HEADER)IPPacket->Header,
                                                 (PUCHAR)UDPHeader,
                                                 DataLength + sizeof(UDP_HEADER));
    UDPHeader->Checksum = WH2N(UDPHeader->Checksum);

    TI_DbgPrint(MID_TRACE, ("Packet: %d ip %d udp %d payload\n",
			    (PCHAR)UDPHeader - (PCHAR)IPPacket->Header,
			    (PCHAR)IPPacket->Data - (PCHAR)UDPHeader,
			    DataLength));

    return STATUS_SUCCESS;
}


NTSTATUS BuildUDPPacket(
    PADDRESS_FILE AddrFile,
    PIP_PACKET Packet,
    PIP_ADDRESS RemoteAddress,
    USHORT RemotePort,
    PIP_ADDRESS LocalAddress,
    USHORT LocalPort,
    PCHAR DataBuffer,
    UINT DataLen )
/*
 * FUNCTION: Builds an UDP packet
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

    TI_DbgPrint(MAX_TRACE, ("Called.\n"));

    /* FIXME: Assumes IPv4 */
    IPInitializePacket(Packet, IP_ADDRESS_V4);

    Packet->TotalSize = sizeof(IPv4_HEADER) + sizeof(UDP_HEADER) + DataLen;

    /* Prepare packet */
    Status = AllocatePacketWithBuffer(&Packet->NdisPacket,
                                      NULL,
                                      Packet->TotalSize );

    if( !NT_SUCCESS(Status) )
    {
        Packet->Free(Packet);
        return Status;
    }

    TI_DbgPrint(MID_TRACE, ("Allocated packet: %x\n", Packet->NdisPacket));
    TI_DbgPrint(MID_TRACE, ("Local Addr : %s\n", A2S(LocalAddress)));
    TI_DbgPrint(MID_TRACE, ("Remote Addr: %s\n", A2S(RemoteAddress)));

    switch (RemoteAddress->Type) {
        case IP_ADDRESS_V4:
            Status = AddUDPHeaderIPv4(AddrFile, RemoteAddress, RemotePort,
                                      LocalAddress, LocalPort, Packet, DataBuffer, DataLen);
            break;
        case IP_ADDRESS_V6:
            /* FIXME: Support IPv6 */
            TI_DbgPrint(MIN_TRACE, ("IPv6 UDP datagrams are not supported.\n"));
        default:
            Status = STATUS_UNSUCCESSFUL;
            break;
    }
    if (!NT_SUCCESS(Status)) {
        TI_DbgPrint(MIN_TRACE, ("Cannot add UDP header. Status = (0x%X)\n",
                                Status));
        Packet->Free(Packet);
        return Status;
    }

    TI_DbgPrint(MID_TRACE, ("Displaying packet\n"));

    DISPLAY_IP_PACKET(Packet);

    TI_DbgPrint(MID_TRACE, ("Leaving\n"));

    return STATUS_SUCCESS;
}

/**
 * @brief
 * Checks whether an address is the limited broadcast address or the
 * directed broadcast address of a non-loopback interface.
 *
 * @param[in] Address
 * Destination address to check.
 *
 * @return
 * TRUE if the address is a broadcast address, FALSE otherwise.
 */
static
BOOLEAN
UDPIsBroadcastAddress(
    _In_ PIP_ADDRESS Address)
{
    BOOLEAN IsBroadcast = FALSE;
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    if (Address->Type != IP_ADDRESS_V4)
        return FALSE;

    if (Address->Address.IPv4Address == 0xFFFFFFFF)
        return TRUE;

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);

    ForEachInterface(CurrentIF) {
        if (CurrentIF != Loopback && AddrIsEqual(&CurrentIF->Broadcast, Address))
        {
            IsBroadcast = TRUE;
            break;
        }
    } EndFor(CurrentIF);

    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return IsBroadcast;
}

NTSTATUS UDPSendDatagram(
    PADDRESS_FILE AddrFile,
    PTDI_CONNECTION_INFORMATION ConnInfo,
    PCHAR BufferData,
    ULONG DataSize,
    PULONG DataUsed )
/*
 * FUNCTION: Sends an UDP datagram to a remote address
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
    IP_ADDRESS RemoteAddress;
    IP_ADDRESS LocalAddress;
    USHORT RemotePort;
    NTSTATUS Status;
    PNEIGHBOR_CACHE_ENTRY NCE;
    IP_PACKET LoopPacket;
    PNEIGHBOR_CACHE_ENTRY LoopNCE = NULL;

    LockObject(AddrFile);

    TI_DbgPrint(MID_TRACE,("Sending Datagram(%x %x %x %d)\n",
						   AddrFile, ConnInfo, BufferData, DataSize));
    TI_DbgPrint(MID_TRACE,("RemoteAddressTa: %x\n", RemoteAddressTa));

    switch( RemoteAddressTa->Address[0].AddressType ) {
    case TDI_ADDRESS_TYPE_IP:
		/* An IPv6 socket sends to IPv4 only through ::ffff:a.b.c.d */
		if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6)
		{
			UnlockObject(AddrFile);
			return STATUS_INVALID_ADDRESS;
		}
		RemoteAddress.Type = IP_ADDRESS_V4;
		RemoteAddress.Address.IPv4Address =
			RemoteAddressTa->Address[0].Address[0].in_addr;
		RemotePort = RemoteAddressTa->Address[0].Address[0].sin_port;
		break;

    case TDI_ADDRESS_TYPE_IP6:
    {
		/* An IPv6 socket's datagram (the whole TA_IP6_ADDRESS within what the client gave): an IPv6
		   destination goes to lwIP's IPv6 (udp6.c); ::ffff:a.b.c.d of a dual stack socket that is not bound
		   to an IPv6 address is an IPv4 datagram (VERIFY ON ORACLE: the error of a V6ONLY socket) */
		PTA_IP6_ADDRESS Remote6 = (PTA_IP6_ADDRESS)RemoteAddressTa;
		UCHAR Bytes[16];
		ULONG i;

		if (AddrFile->Family != TDI_ADDRESS_TYPE_IP6 ||
		    ConnInfo->RemoteAddressLength < sizeof(TA_IP6_ADDRESS) ||
		    Remote6->Address[0].AddressLength < TDI_ADDRESS_LENGTH_IP6)
		{
			UnlockObject(AddrFile);
			return (AddrFile->Family == TDI_ADDRESS_TYPE_IP6) ? STATUS_INVALID_ADDRESS : STATUS_UNSUCCESSFUL;
		}

		RtlCopyMemory(Bytes, Remote6->Address[0].Address[0].sin6_addr, sizeof(Bytes));
		for (i = 0; i < 10 && Bytes[i] == 0; i++)
			;
		if (i < 10 || Bytes[10] != 0xFF || Bytes[11] != 0xFF)
		{
			UnlockObject(AddrFile);
			return UDPSendDatagram6(AddrFile, Remote6, BufferData, DataSize, DataUsed);
		}

		if (!AddrFile->DualStack ||
		    (AddrFile->Address.Type == IP_ADDRESS_V6 && !AddrIsUnspecified(&AddrFile->Address)))
		{
			UnlockObject(AddrFile);
			return STATUS_INVALID_ADDRESS;
		}
		RemoteAddress.Type = IP_ADDRESS_V4;
		RtlCopyMemory(&RemoteAddress.Address.IPv4Address, &Bytes[12], sizeof(ULONG));
		RtlCopyMemory(&RemotePort, &Remote6->Address[0].Address[0].sin6_port, sizeof(RemotePort));
		break;
    }

    default:
		UnlockObject(AddrFile);
		return STATUS_UNSUCCESSFUL;
    }

    LocalAddress = AddrFile->Address;
    if (AddrIsUnspecified(&LocalAddress))
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

        /* A DHCP client without a leased address (BOOTREQUEST, ciaddr 0: DISCOVER, the REQUEST of the selecting and
           init-reboot states, DECLINE) sends from 0.0.0.0, also while the adapter holds an automatic private address
           (RFC 2131 4.1; Windows does, measured on its peer); the address of the interface would make a server with
           reverse-path filtering drop it. A REBIND/RENEW carries ciaddr and keeps the address of the interface. */
        if (RemoteAddress.Address.IPv4Address == 0xFFFFFFFF &&
            AddrFile->Port == WH2N(68) && RemotePort == WH2N(67) &&
            DataSize >= 240 && BufferData[0] == 1 &&
            BufferData[12] == 0 && BufferData[13] == 0 && BufferData[14] == 0 && BufferData[15] == 0)
        {
            LocalAddress.Address.IPv4Address = 0;
        }
    }
    else
    {
        if(!(NCE = NBLocateNeighbor( &LocalAddress, NULL ))) {
            UnlockObject(AddrFile);
            return STATUS_INVALID_PARAMETER;
        }
    }

    Status = BuildUDPPacket( AddrFile,
							 &Packet,
							 &RemoteAddress,
							 RemotePort,
							 &LocalAddress,
							 AddrFile->Port,
							 BufferData,
							 DataSize );

    if (!NT_SUCCESS(Status))
    {
        UnlockObject(AddrFile);
        NBDereferenceNeighbor(NCE);
        return Status;
    }

    /* NDIS does not loop broadcasts back to the sender, so deliver a local copy */
    if (Loopback != NULL &&
        NCE->Interface != Loopback &&
        UDPIsBroadcastAddress(&RemoteAddress))
    {
        LoopNCE = NBLocateNeighbor(&Loopback->Unicast, Loopback);
        if (LoopNCE != NULL &&
            !NT_SUCCESS(BuildUDPPacket(AddrFile,
                                       &LoopPacket,
                                       &RemoteAddress,
                                       RemotePort,
                                       &LocalAddress,
                                       AddrFile->Port,
                                       BufferData,
                                       DataSize)))
        {
            NBDereferenceNeighbor(LoopNCE);
            LoopNCE = NULL;
        }
    }

    /* the inbound filter lets this peer's replies through */
    NITROFW_NOTE_UDP_SEND(AddrFile->Port, &RemoteAddress, RemotePort, UDPIsBroadcastAddress(&RemoteAddress));

    UnlockObject(AddrFile);

    Status = IPSendDatagram(&Packet, NCE);
    NBDereferenceNeighbor(NCE);

    if (LoopNCE != NULL)
    {
        IPSendDatagram(&LoopPacket, LoopNCE);
        NBDereferenceNeighbor(LoopNCE);
    }

    if (!NT_SUCCESS(Status))
        return Status;

    *DataUsed = DataSize;

    return STATUS_SUCCESS;
}


/*
 * IPv4 multicast groups (IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP, struct ip_mreq). As on Windows, a join puts the
 * group in the adapter's multicast list (RFC 1112 6.4: 01:00:5e and the low 23 bits of the group), next to IPv6's
 * groups (if6.c, UDP4AddMulticastList); an adapter that filters multicast frames by its list passes none of the
 * group otherwise. That holds with IPv6 on the adapters and without it (DisabledComponents, Ipv6Enable = 0).
 * A socket's filter for a group (IP_ADD_SOURCE_MEMBERSHIP, MCAST_JOIN_SOURCE_GROUP, MCAST_BLOCK_SOURCE,
 * SIO_SET_MULTICAST_FILTER and the others: the Winsock helper keeps the socket API's rules and hands the stack the
 * group's whole filter, NITRO_AO_OPTION_MCAST_FILTER, nitrotdi.h) is kept on the same table: Mode with the
 * sources. Delivery: a multicast datagram the adapter passes reaches every socket bound to its port (no per-socket
 * membership); a socket with a filter for the group takes it only from a source the filter allows (INCLUDE: listed,
 * EXCLUDE: not listed). The stack sends no IGMP (a snooping switch does not forward the groups).
 * A socket's joins are changed under its object lock and the core lock; delivery reads them under the former, the
 * adapter list under the latter.
 */
#define UDP4_TAG            'M4pU'
#define UDP4_SOCKET_GROUPS  NITRO_MCAST_MAX_GROUPS      /* IP_MAX_MEMBERSHIPS */

typedef struct _UDP4_GROUP {
    ULONG Group;                /* network order */
    ULONG IfIndex;              /* 0: no interface given, every adapter */
    UCHAR Mode;                 /* NITRO_MCAST_INCLUDE / NITRO_MCAST_EXCLUDE (a plain join: EXCLUDE with no source) */
    ULONG NumSources;
    PULONG Sources;             /* sorted, no duplicates, network order; UDP4_TAG */
} UDP4_GROUP, *PUDP4_GROUP;

typedef struct _UDP4_MEMBERSHIPS {
    ULONG Count;
    UDP4_GROUP Groups[UDP4_SOCKET_GROUPS];
} UDP4_MEMBERSHIPS, *PUDP4_MEMBERSHIPS;

/* The joins of all sockets together (core lock) */
static ULONG Udp4Joins;

/* Whether a socket's join of a group on an interface and another one on IfIndex are the same: the same
   interface, or one of them without */
#define UDP4_SAME_INTERFACE(A, B) (!(A) || !(B) || (A) == (B))

/* The adapters' lists of interface IfIndex (0: every one) are set again (core lock held) */
static
VOID
Udp4GroupsChanged(ULONG IfIndex)
{
    struct netif *netif;

    NETIF_FOREACH(netif)
    {
        PIP_INTERFACE IF = netif->state;

        if (IF && (!IfIndex || IF->Index == IfIndex))
            TCP6UpdateMulticastList(netif);
    }
}

/* Whether an interface has index IfIndex (core lock held) */
static
BOOLEAN
Udp4InterfaceExists(ULONG IfIndex)
{
    struct netif *netif;

    NETIF_FOREACH(netif)
    {
        PIP_INTERFACE IF = netif->state;

        if (IF && IF->Index == IfIndex)
            return TRUE;
    }
    return FALSE;
}

/* Whether some socket joined an IPv4 group (core lock held) */
BOOLEAN
UDP4HasGroups(VOID)
{
    return Udp4Joins != 0;
}

/* The Ethernet addresses of the IPv4 groups sockets joined on interface IfIndex or without an interface, added to
 * its adapter's list (if6.c, core lock held). *Count becomes Max + 1 when they do not all fit */
VOID
UDP4AddMulticastList(ULONG IfIndex, PUCHAR List, PUINT Count, UINT Max)
{
    PLIST_ENTRY Entry;
    KIRQL OldIrql;
    ULONG i, j, k;

    if (!Udp4Joins)
        return;

    TcpipAcquireSpinLock(&AddressFileListLock, &OldIrql);
    for (Entry = AddressFileListHead.Flink; Entry != &AddressFileListHead && *Count <= Max; Entry = Entry->Flink)
    {
        PADDRESS_FILE AddrFile = CONTAINING_RECORD(Entry, ADDRESS_FILE, ListEntry);
        PUDP4_MEMBERSHIPS M = AddrFile->Groups4;

        for (i = 0; M && i < M->Count && *Count <= Max; i++)
        {
            const UCHAR *G = (const UCHAR *)&M->Groups[i].Group;
            UCHAR Mac[6];

            if (M->Groups[i].IfIndex && M->Groups[i].IfIndex != IfIndex)
                continue;

            Mac[0] = 0x01; Mac[1] = 0x00; Mac[2] = 0x5E;
            Mac[3] = G[1] & 0x7F; Mac[4] = G[2]; Mac[5] = G[3];

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
    TcpipReleaseSpinLock(&AddressFileListLock, OldIrql);
}

/* The sources of a filter sorted (so delivery can search them) and without duplicates; returns how many are left */
static
ULONG
Udp4SortSources(PULONG Sources, ULONG Count)
{
    ULONG Gap, i, j, Value, Kept;

    for (Gap = Count / 2; Gap; Gap /= 2)
    {
        for (i = Gap; i < Count; i++)
        {
            Value = Sources[i];
            for (j = i; j >= Gap && Sources[j - Gap] > Value; j -= Gap)
                Sources[j] = Sources[j - Gap];
            Sources[j] = Value;
        }
    }
    for (i = Kept = 0; i < Count; i++)
    {
        if (!Kept || Sources[Kept - 1] != Sources[i])
            Sources[Kept++] = Sources[i];
    }
    return Kept;
}

/*
 * A socket's filter for one IPv4 group, set as a whole (the group is joined by the first one): Mode with NumSources
 * sources, sorted, owned from here on (Copy, UDP4_TAG; freed when it fails or is replaced). INCLUDE with none leaves
 * the group. MustBeNew: STATUS_INVALID_PARAMETER when the socket has the group already (a second join). CheckIfIndex:
 * the interface (given as an index) must exist (the stack's own joins; the Winsock helper's requests are checked there)
 */
static
NTSTATUS
Udp4Apply(PADDRESS_FILE AddrFile, ULONG IfIndex, ULONG Group, UCHAR Mode, ULONG NumSources, PULONG Copy,
          BOOLEAN MustBeNew, BOOLEAN CheckIfIndex)
{
    PUDP4_MEMBERSHIPS M, New = NULL;
    PULONG Old = NULL;
    BOOLEAN Leave = (Mode == NITRO_MCAST_INCLUDE && NumSources == 0);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    if (!Leave)
    {
        New = ExAllocatePoolWithTag(NonPagedPool, sizeof(*New), UDP4_TAG);
        if (!New)
        {
            if (Copy)
                ExFreePoolWithTag(Copy, UDP4_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(New, sizeof(*New));
    }

    LockObject(AddrFile);
    LOCK_TCPIP_CORE();

    if (CheckIfIndex && IfIndex && !Udp4InterfaceExists(IfIndex))
    {
        Status = STATUS_INVALID_ADDRESS;
        goto Done;
    }

    if (!AddrFile->Groups4 && New)
    {
        AddrFile->Groups4 = New;
        New = NULL;
    }
    M = AddrFile->Groups4;

    /* the socket's filter of the group: on that interface, or (no interface given) on any */
    for (i = 0; M && i < M->Count; i++)
    {
        if (M->Groups[i].Group == Group && UDP4_SAME_INTERFACE(M->Groups[i].IfIndex, IfIndex))
            break;
    }

    if (!M || i == M->Count)
    {
        /* A new group: a leave of one the socket is not in is WSAEADDRNOTAVAIL, one past the limit as well */
        if (Leave)
        {
            Status = STATUS_INVALID_ADDRESS;
        }
        else if (M->Count == UDP4_SOCKET_GROUPS)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            M->Groups[M->Count].Group = Group;
            M->Groups[M->Count].IfIndex = IfIndex;
            M->Groups[M->Count].Mode = Mode;
            M->Groups[M->Count].NumSources = NumSources;
            M->Groups[M->Count].Sources = Copy;
            Copy = NULL;
            M->Count++;
            Udp4Joins++;
            Udp4GroupsChanged(IfIndex);
        }
    }
    else if (MustBeNew)
    {
        /* A second join: WSAEINVAL through the helper */
        Status = STATUS_INVALID_PARAMETER;
    }
    else if (Leave)
    {
        Old = M->Groups[i].Sources;
        IfIndex = M->Groups[i].IfIndex;
        M->Groups[i] = M->Groups[--M->Count];
        Udp4Joins--;
        Udp4GroupsChanged(IfIndex);
    }
    else
    {
        Old = M->Groups[i].Sources;
        M->Groups[i].Mode = Mode;
        M->Groups[i].NumSources = NumSources;
        M->Groups[i].Sources = Copy;
        Copy = NULL;
    }

Done:
    UNLOCK_TCPIP_CORE();
    UnlockObject(AddrFile);

    if (New)
        ExFreePoolWithTag(New, UDP4_TAG);
    if (Copy)
        ExFreePoolWithTag(Copy, UDP4_TAG);
    if (Old)
        ExFreePoolWithTag(Old, UDP4_TAG);
    return Status;
}

/* A group's whole source filter (NITRO_AO_OPTION_MCAST_FILTER): the Winsock helper's requests; IfIndex 0 is no
   interface given (every adapter) */
NTSTATUS
UDP4SetFilter(PADDRESS_FILE AddrFile, ULONG IfIndex, ULONG Group, UCHAR Mode, ULONG NumSources,
              const UCHAR (*Sources)[16], BOOLEAN MustBeNew)
{
    PULONG Copy = NULL;
    ULONG i;

    if (Mode > NITRO_MCAST_EXCLUDE)
        return STATUS_INVALID_PARAMETER;
    if ((Group & 0xF0) != 0xE0)
        return STATUS_INVALID_ADDRESS;
    if (NumSources > NITRO_MCAST_MAX_SOURCES)
        return STATUS_INSUFFICIENT_RESOURCES;
    if (NumSources)
    {
        Copy = ExAllocatePoolWithTag(NonPagedPool, NumSources * sizeof(ULONG), UDP4_TAG);
        if (!Copy)
            return STATUS_INSUFFICIENT_RESOURCES;
        for (i = 0; i < NumSources; i++)
            RtlCopyMemory(&Copy[i], Sources[i], sizeof(ULONG));
        NumSources = Udp4SortSources(Copy, NumSources);
    }
    return Udp4Apply(AddrFile, IfIndex, Group, Mode, NumSources, Copy, MustBeNew, FALSE);
}

/* IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP as the stack had them before the source filters (AO_OPTION_ADD_MCAST and
 * _DEL_; struct ip_mreq): a join is EXCLUDE with no source (any source), a leave INCLUDE with none */
NTSTATUS
UDP4SetMembership(PADDRESS_FILE AddrFile, BOOLEAN Join, const VOID *Request, UINT Length)
{
    ULONG Group, Interface, IfIndex = 0;

    /* struct ip_mreq: the group, then the interface: 0.0.0.0 for none, an address of it, or its index as 0.0.0.x
       (network order) */
    if (Length < 2 * sizeof(ULONG))
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&Group, Request, sizeof(Group));
    RtlCopyMemory(&Interface, (const UCHAR *)Request + sizeof(Group), sizeof(Interface));
    if ((Group & 0xF0) != 0xE0)
        return STATUS_INVALID_ADDRESS;

    if (Interface && (Interface & 0xFF))
    {
        IP_ADDRESS Address;
        PIP_INTERFACE IF;

        AddrInitIPv4(&Address, Interface);
        IF = AddrLocateInterface(&Address);
        if (!IF)
            return STATUS_INVALID_ADDRESS;
        IfIndex = IF->Index;
        IPDereferenceInterface(IF);
    }
    else if (Interface)
    {
        IfIndex = RtlUlongByteSwap(Interface);
    }

    return Udp4Apply(AddrFile, IfIndex, Group, Join ? NITRO_MCAST_EXCLUDE : NITRO_MCAST_INCLUDE, 0, NULL, Join,
                     Interface && !(Interface & 0xFF));
}

/* Whether the socket takes a datagram to Group from Source that came in on IfIndex: no filter of the socket for the
   group (it did before filters: no per-socket membership), or one that takes the source (INCLUDE: listed,
   EXCLUDE: not listed). The sources are sorted. Takes the socket's object lock */
BOOLEAN
UDP4FilterAccepts(PADDRESS_FILE AddrFile, ULONG Group, ULONG Source, ULONG IfIndex)
{
    PUDP4_MEMBERSHIPS M;
    BOOLEAN Filtered = FALSE, Accept = FALSE;
    ULONG i;

    if (!AddrFile->Groups4)
        return TRUE;
    LockObject(AddrFile);
    M = AddrFile->Groups4;
    for (i = 0; M && i < M->Count && !Accept; i++)
    {
        PUDP4_GROUP G = &M->Groups[i];
        ULONG Low = 0, High = G->NumSources;
        BOOLEAN Listed = FALSE;

        if (G->Group != Group || (G->IfIndex && G->IfIndex != IfIndex))
            continue;
        Filtered = TRUE;
        while (Low < High)
        {
            ULONG Mid = Low + (High - Low) / 2;

            if (G->Sources[Mid] == Source)
            {
                Listed = TRUE;
                break;
            }
            if (G->Sources[Mid] < Source)
                Low = Mid + 1;
            else
                High = Mid;
        }
        Accept = (G->Mode == NITRO_MCAST_INCLUDE) ? Listed : !Listed;
    }
    UnlockObject(AddrFile);
    return Accept || !Filtered;
}

VOID
UDP4LeaveAll(PADDRESS_FILE AddrFile)
{
    PUDP4_MEMBERSHIPS M;
    ULONG i;

    LockObject(AddrFile);
    LOCK_TCPIP_CORE();
    M = AddrFile->Groups4;
    AddrFile->Groups4 = NULL;
    if (M && M->Count)
    {
        Udp4Joins -= M->Count;
        Udp4GroupsChanged(0);
    }
    UNLOCK_TCPIP_CORE();
    UnlockObject(AddrFile);

    if (M)
    {
        for (i = 0; i < M->Count; i++)
        {
            if (M->Groups[i].Sources)
                ExFreePoolWithTag(M->Groups[i].Sources, UDP4_TAG);
        }
        ExFreePoolWithTag(M, UDP4_TAG);
    }
}

VOID UDPReceive(PIP_INTERFACE Interface, PIP_PACKET IPPacket)
/*
 * FUNCTION: Receives and queues a UDP datagram
 * ARGUMENTS:
 *     NTE      = Pointer to net table entry which the packet was received on
*     IPPacket = Pointer to an IP packet that was received
* NOTES:
*     This is the low level interface for receiving UDP datagrams. It strips
*     the UDP header from a packet and delivers the data to anyone that wants it
*/
{
  AF_SEARCH SearchContext;
  PIPv4_HEADER IPv4Header;
  PADDRESS_FILE AddrFile;
  PUDP_HEADER UDPHeader;
  PIP_ADDRESS DstAddress, SrcAddress;
  UINT DataSize, i;

  TI_DbgPrint(MAX_TRACE, ("Called.\n"));

  switch (IPPacket->Type) {
  /* IPv4 packet */
  case IP_ADDRESS_V4:
    IPv4Header = IPPacket->Header;
    DstAddress = &IPPacket->DstAddr;
    SrcAddress = &IPPacket->SrcAddr;
    break;

  /* IPv6 packet */
  case IP_ADDRESS_V6:
    TI_DbgPrint(MIN_TRACE, ("Discarded IPv6 UDP datagram (%i bytes).\n", IPPacket->TotalSize));

    /* FIXME: IPv6 is not supported */
    return;

  default:
    return;
  }

  UDPHeader = (PUDP_HEADER)IPPacket->Data;

  /* The datagram must be large enough to hold a UDP header before any UDP field
     is read; a shorter reassembled datagram would make the reads below run past
     the allocation (remote out-of-bounds read). */
  if (IPPacket->TotalSize < IPPacket->HeaderSize + sizeof(UDP_HEADER)) {
    TI_DbgPrint(MIN_TRACE, ("Truncated UDP datagram received.\n"));
    return;
  }

  /* Sanity checks. Validate the declared UDP length against the reassembled
     datagram BEFORE checksumming: the checksum covers UDPHeader->Length octets
     from the UDP header, so an oversized length would read past the datagram
     buffer (remote out-of-bounds read). */
  i = WH2N(UDPHeader->Length);
  if ((i < sizeof(UDP_HEADER)) || (i > IPPacket->TotalSize - IPPacket->HeaderSize)) {
    /* Incorrect or damaged packet received, discard it */
    TI_DbgPrint(MIN_TRACE, ("Incorrect or damaged UDP packet received.\n"));
    return;
  }

  DataSize = i - sizeof(UDP_HEADER);

  /* Calculate and validate UDP checksum (bounded by the validated length) */
  i = UDPv4ChecksumCalculate(IPv4Header,
                             (PUCHAR)UDPHeader,
                             WH2N(UDPHeader->Length));
  if (i != DH2N(0x0000FFFF) && UDPHeader->Checksum != 0)
  {
      TI_DbgPrint(MIN_TRACE, ("Bad checksum on packet received.\n"));
      return;
  }

  /* Go to UDP data area */
  IPPacket->Data = (PVOID)((ULONG_PTR)IPPacket->Data + sizeof(UDP_HEADER));

  /* Locate a receive request on destination address file object
     and deliver the packet if one is found. If there is no receive
     request on the address file object, call the associated receive
     handler. If no receive handler is registered, drop the packet */

  AddrFile = AddrSearchFirst(DstAddress,
                             UDPHeader->DestPort,
                             IPPROTO_UDP,
                             &SearchContext);
  if (AddrFile) {
    /* Broadcast and multicast datagrams reach every socket bound to the port. A unicast one
       reaches a single socket, as on Windows where several may share a port: the one bound
       to the destination address itself rather than the wildcard, the latest bound among
       equals (the list is in order of opening) */
    BOOLEAN ToAll = FALSE;
    PADDRESS_FILE Best = NULL;

    if (DstAddress->Type == IP_ADDRESS_V4)
    {
      ULONG Dst = DstAddress->Address.IPv4Address;
      IP_ADDRESS Unspecified;

      RtlZeroMemory(&Unspecified, sizeof(Unspecified));
      Unspecified.Type = IP_ADDRESS_V4;
      ToAll = (Dst == 0xFFFFFFFF) || ((Dst & 0xF0) == 0xE0) ||
              AddrIsBroadcastMatch(&Unspecified, DstAddress);
    }

    do {
      if (ToAll && (DstAddress->Address.IPv4Address & 0xF0) == 0xE0 && SrcAddress->Type == IP_ADDRESS_V4 &&
          !UDP4FilterAccepts(AddrFile, DstAddress->Address.IPv4Address, SrcAddress->Address.IPv4Address,
                             Interface ? Interface->Index : 0))
      {
        /* the socket's source filter for the group does not take this source */
        DereferenceObject(AddrFile);
      }
      else if (ToAll)
      {
        DGDeliverData(Interface,
                      AddrFile,
                      SrcAddress,
                      DstAddress,
                      UDPHeader->SourcePort,
                      UDPHeader->DestPort,
                      IPPacket,
                      DataSize);
        DereferenceObject(AddrFile);
      }
      else if (!Best ||
               !AddrIsUnspecified(&AddrFile->Address) ||
               AddrIsUnspecified(&Best->Address))
      {
        if (Best)
          DereferenceObject(Best);
        Best = AddrFile;
      }
      else
      {
        DereferenceObject(AddrFile);
      }
    } while ((AddrFile = AddrSearchNext(&SearchContext)) != NULL);

    if (Best)
    {
      DGDeliverData(Interface,
                    Best,
                    SrcAddress,
                    DstAddress,
                    UDPHeader->SourcePort,
                    UDPHeader->DestPort,
                    IPPacket,
                    DataSize);
      DereferenceObject(Best);
    }
  } else {
    /* There are no open address files that will take this datagram: port unreachable (not for a broadcast
       or multicast one, ICMPPortUnreachable decides) */
    TI_DbgPrint(MID_TRACE, ("Cannot deliver IPv4 UDP datagram to address (0x%X).\n",
      DN2H(DstAddress->Address.IPv4Address)));

    ICMPPortUnreachable(Interface, IPPacket, UDPHeader);
  }
  TI_DbgPrint(MAX_TRACE, ("Leaving.\n"));
}


/*
 * An ICMP port unreachable (icmp.c) whose invoking datagram is UDP from one of our addresses: the socket that sent it
 * (the one that would receive on its address and port) fails its next receive (DGReportPortUnreachable). Icmp: the
 * ICMP message (checksum checked), Size bytes.
 */
VOID UDPPortUnreachable(
    PIP_PACKET IPPacket,
    PUCHAR Icmp,
    UINT Size)
{
    PIPv4_HEADER Inner;
    UINT InnerLength;
    USHORT LocalPort;
    IP_ADDRESS Local;
    AF_SEARCH SearchContext;
    PADDRESS_FILE AddrFile, Best = NULL;

    if (Size < 8 + sizeof(IPv4_HEADER) + 8)
        return;
    Inner = (PIPv4_HEADER)(Icmp + 8);
    InnerLength = (Inner->VerIHL & 0x0F) * 4;
    if ((Inner->VerIHL >> 4) != 4 || InnerLength < sizeof(IPv4_HEADER) || Size < 8 + InnerLength + 8 ||
        Inner->Protocol != IPPROTO_UDP)
        return;
    /* The datagram came from the address this message went to */
    if (IPPacket->DstAddr.Type != IP_ADDRESS_V4 || Inner->SrcAddr != IPPacket->DstAddr.Address.IPv4Address)
        return;

    AddrInitIPv4(&Local, Inner->SrcAddr);
    RtlCopyMemory(&LocalPort, Icmp + 8 + InnerLength, sizeof(LocalPort));

    for (AddrFile = AddrSearchFirst(&Local, LocalPort, IPPROTO_UDP, &SearchContext);
         AddrFile != NULL;
         AddrFile = AddrSearchNext(&SearchContext))
    {
        if (!Best || !AddrIsUnspecified(&AddrFile->Address) || AddrIsUnspecified(&Best->Address))
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
        DGReportPortUnreachable(Best);
        DereferenceObject(Best);
    }
}

NTSTATUS UDPStartup(
  VOID)
/*
 * FUNCTION: Initializes the UDP subsystem
 * RETURNS:
 *     Status of operation
 */
{
  NTSTATUS Status;

  RtlZeroMemory(&UDPStats, sizeof(UDP_STATISTICS));

  Status = PortsStartup( &UDPPorts, 1, UDP_STARTING_PORT + UDP_DYNAMIC_PORTS );

  if( !NT_SUCCESS(Status) ) return Status;

  /* Register this protocol with IP layer */
  IPRegisterProtocol(IPPROTO_UDP, UDPReceive);

  UDP6Startup();

  UDPInitialized = TRUE;

  return STATUS_SUCCESS;
}


NTSTATUS UDPShutdown(
  VOID)
/*
 * FUNCTION: Shuts down the UDP subsystem
 * RETURNS:
 *     Status of operation
 */
{
  if (!UDPInitialized)
      return STATUS_SUCCESS;

  PortsShutdown( &UDPPorts );

  /* Deregister this protocol with IP layer */
  IPRegisterProtocol(IPPROTO_UDP, NULL);

  UDPInitialized = FALSE;

  return STATUS_SUCCESS;
}

UINT UDPAllocatePort( UINT HintPort ) {
    if( HintPort ) {
        if( AllocatePort( &UDPPorts, HintPort ) ) return HintPort;
        else return (UINT)-1;
    } else return AllocatePortFromRange
               ( &UDPPorts, UDP_STARTING_PORT,
                 UDP_STARTING_PORT + UDP_DYNAMIC_PORTS - 1 );
}

BOOLEAN UDPReservePort( UINT Port ) {
    return ReservePort( &UDPPorts, Port );
}

VOID UDPFreePort( UINT Port ) {
    DeallocatePort( &UDPPorts, Port );
}

/* EOF */
