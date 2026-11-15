/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        tcpip/ninfo.c
 * PURPOSE:     Network information
 * PROGRAMMERS: Art Yerkes
 * REVISIONS:
 *   CSH 01/08-2000 Created
 */

#include "precomp.h"

#define IP_ROUTE_TYPE_ADD 3
#define IP_ROUTE_TYPE_DEL 2

/* Get IPRouteEntry s for each of the routes in the system */
TDI_STATUS InfoTdiQueryGetRouteTable( PIP_INTERFACE IF, PNDIS_BUFFER Buffer, PUINT BufferSize ) {
    TDI_STATUS Status;
    UINT RtCount = CountFIBs(IF);
    UINT Size = sizeof( IPROUTE_ENTRY ) * RtCount;
    PFIB_ENTRY RCache, RCacheCur;
    PIPROUTE_ENTRY RouteEntries, RtCurrent;

    TI_DbgPrint(DEBUG_INFO, ("Called, routes = %d\n",
			    RtCount));

    if (RtCount == 0)
        return InfoCopyOut(NULL, 0, NULL, BufferSize);

    RouteEntries = ExAllocatePoolWithTag( NonPagedPool, Size, ROUTE_ENTRY_TAG );
    RtCurrent = RouteEntries;

    RCache = ExAllocatePoolWithTag( NonPagedPool, sizeof( FIB_ENTRY ) * RtCount, FIB_TAG );
    RCacheCur = RCache;

    if( !RCache || !RouteEntries ) {
	if( RCache ) ExFreePoolWithTag( RCache, FIB_TAG );
	if( RouteEntries ) ExFreePoolWithTag( RouteEntries, ROUTE_ENTRY_TAG );
	return TDI_NO_RESOURCES;
    }

    RtlZeroMemory( RouteEntries, Size );

    /* Each copy references its router's NCE; the FIB may have changed since the count */
    RtCount = CopyFIBs( IF, RCache, RtCount );
    Size = sizeof( IPROUTE_ENTRY ) * RtCount;

    while( RtCurrent < RouteEntries + RtCount ) {
	ASSERT(RCacheCur->Router);

	RtlCopyMemory( &RtCurrent->Dest,
		       &RCacheCur->NetworkAddress.Address,
		       sizeof(RtCurrent->Dest) );
	RtlCopyMemory( &RtCurrent->Mask,
		       &RCacheCur->Netmask.Address,
		       sizeof(RtCurrent->Mask) );
	RtlCopyMemory( &RtCurrent->Gw,
		       &RCacheCur->Router->Address.Address,
		       sizeof(RtCurrent->Gw) );

	RtCurrent->Metric1 = RCacheCur->Metric;
	RtCurrent->Type = TDI_ADDRESS_TYPE_IP;

	TI_DbgPrint
	    (DEBUG_INFO,
	     ("%d: NA %08x NM %08x GW %08x MT %x\n",
	      RtCurrent - RouteEntries,
	      RtCurrent->Dest,
	      RtCurrent->Mask,
	      RtCurrent->Gw,
	      RtCurrent->Metric1 ));

	/* The interface index, as in IFEntry.if_index and IPAddrEntry.iae_index (the entity
	   instance numbers an interface from 0, and its index no longer does) */
	RtCurrent->Index = IF->Index;

	NBDereferenceNeighbor(RCacheCur->Router);

	RtCurrent++; RCacheCur++;
    }

    Status = InfoCopyOut( (PCHAR)RouteEntries, Size, Buffer, BufferSize );

    ExFreePoolWithTag( RouteEntries, ROUTE_ENTRY_TAG );
    ExFreePoolWithTag( RCache, FIB_TAG );

    TI_DbgPrint(DEBUG_INFO, ("Returning %08x\n", Status));

    return Status;
}

TDI_STATUS InfoTdiQueryGetAddrTable(TDIEntityID ID,
				    PNDIS_BUFFER Buffer,
				    PUINT BufferSize)
{
    KIRQL OldIrql;
    PIPADDR_ENTRY IPEntry;
    PIP_INTERFACE CurrentIF;
    PIP_NTE Ntes;
    UINT i, NteCount, Count;
    TDI_STATUS Status;

    TI_DbgPrint(DEBUG_INFO, ("Called.\n"));


    TcpipAcquireSpinLock(&EntityListLock, &OldIrql);

    for (i = 0; i < EntityCount; i++)
    {
        if (EntityList[i].tei_entity == ID.tei_entity &&
            EntityList[i].tei_instance == ID.tei_instance)
            break;
    }

    if (i == EntityCount)
    {
        TcpipReleaseSpinLock(&EntityListLock, OldIrql);
        return TDI_INVALID_PARAMETER;
    }

    /* The primary address, then the additional ones (AddIPAddress beside it) */
    IPEntry = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(IPADDR_ENTRY) * (1 + IP_MAX_NTE) + sizeof(IP_NTE) * IP_MAX_NTE,
                                    IP_ADDRESS_TAG);
    if (!IPEntry)
    {
        TcpipReleaseSpinLock(&EntityListLock, OldIrql);
        return TDI_NO_RESOURCES;
    }
    Ntes = (PIP_NTE)&IPEntry[1 + IP_MAX_NTE];

    CurrentIF = EntityList[i].context;

    RtlZeroMemory(IPEntry, sizeof(IPADDR_ENTRY) * (1 + IP_MAX_NTE));
    IPEntry[0].Index = CurrentIF->Index;
    IPEntry[0].Context = (USHORT)CurrentIF->Index;
    GetInterfaceIPv4Address(CurrentIF,
			    ADE_UNICAST,
			    &IPEntry[0].Addr);
    GetInterfaceIPv4Address(CurrentIF,
			    ADE_ADDRMASK,
			    &IPEntry[0].Mask);
    GetInterfaceIPv4Address(CurrentIF,
			    ADE_BROADCAST,
			    &IPEntry[0].BcastAddr);

    NteCount = IFCopyNtes(CurrentIF, Ntes, IP_MAX_NTE);
    for (Count = 0; Count < NteCount; Count++)
    {
        IPEntry[1 + Count] = IPEntry[0];
        IPEntry[1 + Count].Addr = Ntes[Count].Address;
        IPEntry[1 + Count].Mask = Ntes[Count].Netmask;
        IPEntry[1 + Count].BcastAddr = Ntes[Count].Address | ~Ntes[Count].Netmask;
        IPEntry[1 + Count].Context = Ntes[Count].Context;
    }

    TcpipReleaseSpinLock(&EntityListLock, OldIrql);

    Status = InfoCopyOut((PCHAR)IPEntry, sizeof(IPADDR_ENTRY) * (1 + NteCount),
                         Buffer, BufferSize);

    ExFreePoolWithTag(IPEntry, IP_ADDRESS_TAG);

    return Status;
}

TDI_STATUS InfoTdiQueryGetIPSnmpInfo( TDIEntityID ID,
                                      PIP_INTERFACE IF,
				      PNDIS_BUFFER Buffer,
				      PUINT BufferSize ) {
    IPSNMPInfo SnmpInfo;
    UINT IfCount = CountInterfaces();
    UINT RouteCount = CountFIBs(IF);
    TDI_STATUS Status = TDI_INVALID_REQUEST;

    TI_DbgPrint(DEBUG_INFO, ("Called.\n"));

    RtlZeroMemory(&SnmpInfo, sizeof(SnmpInfo));

    SnmpInfo.ipsi_numif = IfCount;
    SnmpInfo.ipsi_numaddr = 1 + IFCountNtes(IF);
    SnmpInfo.ipsi_numroutes = RouteCount;

    Status = InfoCopyOut( (PCHAR)&SnmpInfo, sizeof(SnmpInfo),
			  Buffer, BufferSize );

    TI_DbgPrint(DEBUG_INFO, ("Returning %08x\n", Status));

    return Status;
}

/* The connection endpoints of an address file (the listener's accepted connections hang on its address file, as
 * do the connection of a client socket), each referenced: *Count of them in the returned array. The caller
 * dereferences each and frees the array with ExFreePoolWithTag(TDI_ENTITY_TAG). NULL, *Count 0 when there is none
 * (or no memory: *NoMemory) */
#define TCP_ROW_MAX_CONNECTIONS 65536

static
PCONNECTION_ENDPOINT *
InfoReferenceConnections(PADDRESS_FILE AddrFile, PULONG Count, PBOOLEAN NoMemory)
{
    PCONNECTION_ENDPOINT Connection, *Array = NULL;
    ULONG Total = 0, Taken = 0;

    *Count = 0;
    *NoMemory = FALSE;

    LockObject(AddrFile);
    for (Connection = AddrFile->Connection; Connection && Total < TCP_ROW_MAX_CONNECTIONS; Connection = Connection->Next)
        Total++;

    if (Total)
    {
        Array = ExAllocatePoolWithTag(NonPagedPool, Total * sizeof(*Array), TDI_ENTITY_TAG);
        if (Array)
        {
            /* The chain cannot change while the address file is locked: Taken equals Total */
            for (Connection = AddrFile->Connection; Connection && Taken < Total; Connection = Connection->Next)
            {
                ReferenceObject(Connection);
                Array[Taken++] = Connection;
            }
        }
        else
        {
            *NoMemory = TRUE;
        }
    }
    UnlockObject(AddrFile);

    *Count = Taken;
    return Array;
}

static
VOID
InfoDereferenceConnections(PCONNECTION_ENDPOINT *Array, ULONG Count)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        DereferenceObject(Array[i]);
    if (Array)
        ExFreePoolWithTag(Array, TDI_ENTITY_TAG);
}

TDI_STATUS InfoTdiQueryGetConnectionTcpTable(PADDRESS_FILE AddrFile,
				    PNDIS_BUFFER Buffer,
				    PUINT BufferSize,
                    TDI_TCPUDP_CLASS_INFO Class)
{
    SIZE_T Size;
    MIB_TCPROW_OWNER_MODULE TcpRow;
    PCONNECTION_ENDPOINT *Connections;
    ULONG ConnectionCount, Count = 0, i;
    BOOLEAN NoMemory;
    PUCHAR Rows;
    TDI_STATUS Status;

    TI_DbgPrint(DEBUG_INFO, ("Called.\n"));

    if (Class == TcpUdpClassOwnerPid)
    {
        Size = sizeof(MIB_TCPROW_OWNER_PID);
    }
    else if (Class == TcpUdpClassOwner)
    {
        Size = sizeof(MIB_TCPROW_OWNER_MODULE);
    }
    else
    {
        Size = sizeof(MIB_TCPROW);
    }

    /* An IPv6 socket (a dual stack one too) is no row of the IPv4 table: skipped, as a closing one is */
    if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6)
        return TDI_INVALID_REQUEST;

    /* One row for the listener (if the address file listens) and one for each connection of the address file
       that has a socket: the accepted ends of a listener are among them */
    Connections = InfoReferenceConnections(AddrFile, &ConnectionCount, &NoMemory);
    if (NoMemory)
        return TDI_NO_RESOURCES;

    Rows = ExAllocatePoolWithTag(NonPagedPool, (ConnectionCount + 1) * Size, TDI_ENTITY_TAG);
    if (!Rows)
    {
        InfoDereferenceConnections(Connections, ConnectionCount);
        return TDI_NO_RESOURCES;
    }

    if (AddrFile->Listener != NULL)
    {
        /* The listener's own address file is this one (a listener is made on the address file it listens on) */
        RtlZeroMemory(&TcpRow, sizeof(TcpRow));
        TcpRow.dwOwningPid = HandleToUlong(AddrFile->ProcessId);
        TcpRow.liCreateTimestamp = AddrFile->CreationTime;
        TcpRow.dwState = MIB_TCP_STATE_LISTEN;
        TcpRow.dwLocalAddr = AddrFile->Address.Address.IPv4Address;
        TcpRow.dwLocalPort = AddrFile->Port;
        TcpRow.dwRemoteAddr = AddrFile->Address.Address.IPv4Address;
        TcpRow.dwRemotePort = AddrFile->Port;
        if (Class == TcpUdpClassOwner)
            TcpRow.OwningModuleInfo[0] = (ULONG_PTR)AddrFile->SubProcessTag;
        RtlCopyMemory(Rows + Count * Size, &TcpRow, Size);
        Count++;
    }

    for (i = 0; i < ConnectionCount; i++)
    {
        TA_IP_ADDRESS Local, Remote;
        ULONG State;

        /* Fails if the connection has no socket (yet) or was closed meanwhile; no row then */
        if (!NT_SUCCESS(TCPGetConnectionEnds(Connections[i], (PTRANSPORT_ADDRESS)&Local,
                                             (PTRANSPORT_ADDRESS)&Remote, sizeof(Local), &State)))
            continue;

        ASSERT(Local.TAAddressCount >= 1);
        ASSERT(Local.Address[0].AddressLength == TDI_ADDRESS_LENGTH_IP);
        RtlZeroMemory(&TcpRow, sizeof(TcpRow));
        TcpRow.dwOwningPid = HandleToUlong(AddrFile->ProcessId);
        TcpRow.liCreateTimestamp = AddrFile->CreationTime;
        TcpRow.dwState = State;
        TcpRow.dwLocalAddr = Local.Address[0].Address[0].in_addr;
        TcpRow.dwLocalPort = Local.Address[0].Address[0].sin_port;
        TcpRow.dwRemoteAddr = Remote.Address[0].Address[0].in_addr;
        TcpRow.dwRemotePort = Remote.Address[0].Address[0].sin_port;
        if (Class == TcpUdpClassOwner)
            TcpRow.OwningModuleInfo[0] = (ULONG_PTR)AddrFile->SubProcessTag;
        RtlCopyMemory(Rows + Count * Size, &TcpRow, Size);
        Count++;
    }

    InfoDereferenceConnections(Connections, ConnectionCount);

    if (Count == 0)
        Status = TDI_INVALID_REQUEST;
    else
        Status = InfoCopyOut((PCHAR)Rows, Count * Size, Buffer, BufferSize);
    ExFreePoolWithTag(Rows, TDI_ENTITY_TAG);

    TI_DbgPrint(DEBUG_INFO, ("Returning %08x\n", Status));

    return Status;
}

/* The address, scope id and port (network order) of a TA_IP6_ADDRESS, or of a TA_IP_ADDRESS as ::ffff:a.b.c.d;
   Ta was built by this driver (TCPBuildTransportAddress), Length bytes of it valid */
static VOID Tcp6RowAddress(PTRANSPORT_ADDRESS Ta, ULONG Length, PUCHAR Address, PULONG ScopeId, PULONG Port)
{
    RtlZeroMemory(Address, 16);
    *ScopeId = 0;
    *Port = 0;

    if (Length >= sizeof(TA_IP6_ADDRESS) && Ta->Address[0].AddressType == TDI_ADDRESS_TYPE_IP6)
    {
        PTDI_ADDRESS_IP6 Ip6 = (PTDI_ADDRESS_IP6)Ta->Address[0].Address;
        USHORT PortN;

        RtlCopyMemory(Address, Ip6->sin6_addr, 16);
        RtlCopyMemory(ScopeId, &Ip6->sin6_scope_id, sizeof(*ScopeId));
        RtlCopyMemory(&PortN, &Ip6->sin6_port, sizeof(PortN));
        *Port = PortN;
    }
    else if (Length >= sizeof(TA_IP_ADDRESS) && Ta->Address[0].AddressType == TDI_ADDRESS_TYPE_IP)
    {
        PTDI_ADDRESS_IP Ip = (PTDI_ADDRESS_IP)Ta->Address[0].Address;

        Address[10] = 0xFF;
        Address[11] = 0xFF;
        RtlCopyMemory(&Address[12], &Ip->in_addr, sizeof(ULONG));
        *Port = Ip->sin_port;
    }
}

/* The row of an IPv6 UDP socket (IP_UDP6_ROW_ENTRY_ID); an IPv4 socket has none (refused, so that the caller skips
 * it) */
TDI_STATUS InfoTdiQueryGetConnectionUdp6Row(PADDRESS_FILE AddrFile,
                                            PNDIS_BUFFER Buffer,
                                            PUINT BufferSize)
{
    UDP6_ROW_OWNER_PID Row;

    if (AddrFile->Family != TDI_ADDRESS_TYPE_IP6 || AddrFile->Protocol != IPPROTO_UDP || AddrFile->PortReleased)
        return TDI_INVALID_REQUEST;

    UDP6BuildRow(AddrFile, &Row);
    return InfoCopyOut((PCHAR)&Row, sizeof(Row), Buffer, BufferSize);
}

/* The rows of an IPv6 TCP socket's address file (IP_TCP6_ROW_ENTRY_ID): its listener, and each of its connections
 * (the accepted ends of a listener hang on its address file). An IPv4 socket has none (refused, so that the
 * caller skips it, as a closing socket is skipped). The answer is one row after the other; its size is the number
 * of rows asked for, and a caller that wants them all asks for the size first */
TDI_STATUS InfoTdiQueryGetConnectionTcp6Row(PADDRESS_FILE AddrFile,
                                            PNDIS_BUFFER Buffer,
                                            PUINT BufferSize)
{
    PTCP6_ROW_OWNER_PID Rows;
    PCONNECTION_ENDPOINT *Connections;
    ULONG ConnectionCount, Count = 0, i;
    BOOLEAN NoMemory;
    TDI_STATUS Status;

    if (AddrFile->Family != TDI_ADDRESS_TYPE_IP6)
        return TDI_INVALID_REQUEST;

    Connections = InfoReferenceConnections(AddrFile, &ConnectionCount, &NoMemory);
    if (NoMemory)
        return TDI_NO_RESOURCES;

    Rows = ExAllocatePoolWithTag(NonPagedPool, (ConnectionCount + 1) * sizeof(*Rows), TDI_ENTITY_TAG);
    if (!Rows)
    {
        InfoDereferenceConnections(Connections, ConnectionCount);
        return TDI_NO_RESOURCES;
    }

    if (AddrFile->Listener != NULL)
    {
        TA_IP6_ADDRESS EndPoint;

        if (NT_SUCCESS(TCPAddrFileTransportAddress(AddrFile, (PTRANSPORT_ADDRESS)&EndPoint, sizeof(EndPoint))))
        {
            RtlZeroMemory(&Rows[Count], sizeof(*Rows));
            Rows[Count].OwningPid = HandleToUlong(AddrFile->ProcessId);
            Tcp6RowAddress((PTRANSPORT_ADDRESS)&EndPoint, sizeof(EndPoint), Rows[Count].LocalAddr,
                           &Rows[Count].LocalScopeId, &Rows[Count].LocalPort);
            Rows[Count].State = MIB_TCP_STATE_LISTEN;
            Count++;
        }
    }

    for (i = 0; i < ConnectionCount; i++)
    {
        TA_IP6_ADDRESS Local, Remote;
        PTCP6_ROW_OWNER_PID Row = &Rows[Count];
        ULONG State;

        /* Fails if the connection has no socket (yet) or was closed meanwhile; no row then */
        if (!NT_SUCCESS(TCPGetConnectionEnds(Connections[i], (PTRANSPORT_ADDRESS)&Local,
                                             (PTRANSPORT_ADDRESS)&Remote, sizeof(Local), &State)))
            continue;

        RtlZeroMemory(Row, sizeof(*Row));
        Row->OwningPid = HandleToUlong(AddrFile->ProcessId);
        Tcp6RowAddress((PTRANSPORT_ADDRESS)&Local, sizeof(Local), Row->LocalAddr, &Row->LocalScopeId, &Row->LocalPort);
        Tcp6RowAddress((PTRANSPORT_ADDRESS)&Remote, sizeof(Remote), Row->RemoteAddr, &Row->RemoteScopeId,
                       &Row->RemotePort);
        Row->State = State;
        Count++;
    }

    InfoDereferenceConnections(Connections, ConnectionCount);

    if (Count == 0)
        Status = TDI_INVALID_REQUEST;
    else
        Status = InfoCopyOut((PCHAR)Rows, Count * sizeof(*Rows), Buffer, BufferSize);
    ExFreePoolWithTag(Rows, TDI_ENTITY_TAG);
    return Status;
}

TDI_STATUS InfoTdiQueryGetConnectionUdpTable(PADDRESS_FILE AddrFile,
				    PNDIS_BUFFER Buffer,
				    PUINT BufferSize,
				    TDI_TCPUDP_CLASS_INFO Class)
{
    SIZE_T Size;
    MIB_UDPROW_OWNER_MODULE UdpRow;
    TDI_STATUS Status = TDI_INVALID_REQUEST;

    TI_DbgPrint(DEBUG_INFO, ("Called.\n"));

    if (Class == TcpUdpClassOwnerPid)
    {
        Size = sizeof(MIB_UDPROW_OWNER_PID);
    }
    else if (Class == TcpUdpClassOwner)
    {
        Size = sizeof(MIB_UDPROW_OWNER_MODULE);
    }
    else
    {
        Size = sizeof(MIB_UDPROW);
    }

    /* An IPv6 socket (a dual stack one too) is a row of the IPv6 table (IP_UDP6_ROW_ENTRY_ID), not of this one */
    if (AddrFile->Family == TDI_ADDRESS_TYPE_IP6)
        return TDI_INVALID_REQUEST;

    UdpRow.dwLocalAddr = AddrFile->Address.Address.IPv4Address;
    UdpRow.dwLocalPort = AddrFile->Port;
    UdpRow.dwOwningPid = HandleToUlong(AddrFile->ProcessId);
    UdpRow.liCreateTimestamp = AddrFile->CreationTime;
    UdpRow.dwFlags = 0; /* FIXME */
    if (Class == TcpUdpClassOwner)
    {
        RtlZeroMemory(&UdpRow.OwningModuleInfo[0], sizeof(UdpRow.OwningModuleInfo));
        UdpRow.OwningModuleInfo[0] = (ULONG_PTR)AddrFile->SubProcessTag;
    }

    Status = InfoCopyOut( (PCHAR)&UdpRow,
			  Size, Buffer, BufferSize );

    TI_DbgPrint(DEBUG_INFO, ("Returning %08x\n", Status));

    return Status;
}

TDI_STATUS InfoTdiSetRoute(PIP_INTERFACE IF, PVOID Buffer, UINT BufferSize)
{
    IP_ADDRESS Address, Netmask, Router;
    PIPROUTE_ENTRY Route = Buffer;

    if (!Buffer || BufferSize < sizeof(IPROUTE_ENTRY))
        return TDI_INVALID_PARAMETER;

    AddrInitIPv4( &Address, Route->Dest );
    AddrInitIPv4( &Netmask, Route->Mask );
    AddrInitIPv4( &Router,  Route->Gw );

    if (IF == Loopback)
    {
        DbgPrint("Failing attempt to add route to loopback adapter\n");
        return TDI_INVALID_PARAMETER;
    }

    if( Route->Type == IP_ROUTE_TYPE_ADD ) { /* Add the route */
        TI_DbgPrint(DEBUG_INFO,("Adding route (%s)\n", A2S(&Address)));
        /* an interface metric set by hand (SetIpInterfaceEntry, the registry) stays; otherwise the route's is used */
        IF->Metric = IF->Ip4MetricConfig ? IF->Ip4MetricConfig : Route->Metric1;
	if (!RouterCreateRoute(&Address, &Netmask, &Router, IF))
	    return TDI_NO_RESOURCES;

        return TDI_SUCCESS;
     } else if( Route->Type == IP_ROUTE_TYPE_DEL ) {
	TI_DbgPrint(DEBUG_INFO,("Removing route (%s)\n", A2S(&Address)));
	if (NT_SUCCESS(RouterRemoveRoute( &Address, &Router )))
            return TDI_SUCCESS;
        else
            return TDI_INVALID_PARAMETER;
     }

     return TDI_INVALID_REQUEST;
}
