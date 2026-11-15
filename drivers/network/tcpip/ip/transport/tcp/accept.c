/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS TCP/IP protocol driver
 * FILE:        transport/tcp/accept.c
 * PURPOSE:     Transmission Control Protocol Listen/Accept code
 * PROGRAMMERS: Art Yerkes (arty@users.sf.net)
 * REVISIONS:
 *   arty 12/21/2004 Created
 */

#include "precomp.h"

#include <lwip_glue/lwip_glue.h>

extern NPAGED_LOOKASIDE_LIST TdiBucketLookasideList;

NTSTATUS TCPCheckPeerForAccept(PVOID Context,
                               PTDI_REQUEST_KERNEL Request)
{
    struct tcp_pcb *newpcb = (struct tcp_pcb*)Context;
    NTSTATUS Status;
    PTDI_CONNECTION_INFORMATION WhoIsConnecting;
    PTA_IP_ADDRESS RemoteAddress;
    ip_addr_t ipaddr;
    u16_t Port;

    if (Request->RequestFlags & TDI_QUERY_ACCEPT)
        DbgPrint("TDI_QUERY_ACCEPT NOT SUPPORTED!!!\n");

    WhoIsConnecting = (PTDI_CONNECTION_INFORMATION)Request->ReturnConnectionInformation;
    RemoteAddress = (PTA_IP_ADDRESS)WhoIsConnecting->RemoteAddress;

    /* An IPv6 peer (of an IPv6 listener): a TA_IP6_ADDRESS, in the room the listener's owner gave for it */
    if (newpcb && IP_IS_V6_VAL(newpcb->remote_ip))
    {
        Status = TCPTranslateError(LibTCPGetPeerName(newpcb, &ipaddr, &Port));
        if (!NT_SUCCESS(Status))
            return Status;
        return TCPBuildTransportAddress(&ipaddr, Port, (PTRANSPORT_ADDRESS)RemoteAddress,
                                        WhoIsConnecting->RemoteAddressLength, TRUE);
    }

    RemoteAddress->TAAddressCount = 1;
    RemoteAddress->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    RemoteAddress->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

    Status = TCPTranslateError(LibTCPGetPeerName(newpcb,
                                                 &ipaddr,
                                                 &RemoteAddress->Address[0].Address[0].sin_port));

    RemoteAddress->Address[0].Address[0].in_addr = ip4_addr_get_u32(ip_2_ip4(&ipaddr));

    return Status;
}

/* This listen is on a socket we keep as internal.  That socket has the same
 * lifetime as the address file */
NTSTATUS TCPListen(PCONNECTION_ENDPOINT Connection, UINT Backlog)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ip_addr_t AddressToBind;
    PADDRESS_FILE AddrFile;
    u16_t BoundPort;

    ASSERT(Connection);

    LockObject(Connection);

    ASSERT_KM_POINTER(Connection->AddressFile);

    TI_DbgPrint(DEBUG_TCP,("[IP, TCPListen] Called\n"));

    TI_DbgPrint(DEBUG_TCP, ("Connection->SocketContext %x\n",
        Connection->SocketContext));

    AddrFile = Connection->AddressFile;
    if (AddrFile->Address.Type == IP_ADDRESS_V6 && AddrFile->DualStack && AddrIsUnspecified(&AddrFile->Address))
    {
        /* A dual stack socket on the unspecified address: one listener for both versions */
        ip_addr_copy(AddressToBind, *IP_ANY_TYPE);
    }
    else if (AddrFile->Address.Type == IP_ADDRESS_V6)
    {
        ip_addr_set_zero_ip6(&AddressToBind);
        RtlCopyMemory(ip_2_ip6(&AddressToBind)->addr, AddrFile->Address.Address.IPv6Address, 16);
        ip6_addr_set_zone(ip_2_ip6(&AddressToBind), AddrFile->Zone6);
    }
    else
    {
        /* IPv4, and the IPv4 address of a dual stack socket bound to ::ffff:a.b.c.d */
        ip_addr_set_ip4_u32_val(AddressToBind, AddrFile->Address.Address.IPv4Address);
    }

    Status = TCPTranslateError(LibTCPBind(Connection,
                                          &AddressToBind,
                                          Connection->AddressFile->Port,
                                          &BoundPort));

    /* Check if we had an unspecified port */
    if (NT_SUCCESS(Status) && !Connection->AddressFile->Port)
    {
        /* LibTCPBind reserved an ephemeral port in the port bitmap */
        Connection->AddressFile->Port = BoundPort;
    }

    if (NT_SUCCESS(Status))
    {
        Connection->SocketContext = LibTCPListen(Connection, Backlog);
        if (!Connection->SocketContext)
            Status = STATUS_UNSUCCESSFUL;
    }

    UnlockObject(Connection);

    TI_DbgPrint(DEBUG_TCP,("[IP, TCPListen] Leaving. Status = %x\n", Status));

    return Status;
}

BOOLEAN TCPAbortListenForSocket
(   PCONNECTION_ENDPOINT Listener,
    PCONNECTION_ENDPOINT Connection,
    PIRP Irp)
{
    PLIST_ENTRY ListEntry;
    PTDI_BUCKET Bucket;
    BOOLEAN Found = FALSE;

    LockObject(Listener);

    ListEntry = Listener->ListenRequest.Flink;
    while (ListEntry != &Listener->ListenRequest)
    {
        Bucket = CONTAINING_RECORD(ListEntry, TDI_BUCKET, Entry);

        if (Bucket->AssociatedEndpoint == Connection &&
            Bucket->Request.RequestContext == Irp)
        {
            DereferenceObject(Bucket->AssociatedEndpoint);
            RemoveEntryList( &Bucket->Entry );
            ExFreeToNPagedLookasideList(&TdiBucketLookasideList, Bucket);
            Found = TRUE;
            break;
        }

        ListEntry = ListEntry->Flink;
    }

    UnlockObject(Listener);

    return Found;
}

NTSTATUS TCPAccept ( PTDI_REQUEST Request,
                     PCONNECTION_ENDPOINT Listener,
                     PCONNECTION_ENDPOINT Connection,
                     PTCP_COMPLETION_ROUTINE Complete,
                     PVOID Context,
                     ULONG Room )
{
    NTSTATUS Status;
    PTDI_BUCKET Bucket;

    LockObject(Listener);

    Bucket = ExAllocateFromNPagedLookasideList(&TdiBucketLookasideList);

    if (Bucket)
    {
        Bucket->AssociatedEndpoint = Connection;
        ReferenceObject(Bucket->AssociatedEndpoint);

        Bucket->Request.RequestNotifyObject = Complete;
        Bucket->Request.RequestContext = Context;
        InsertTailList( &Listener->ListenRequest, &Bucket->Entry );
        Status = STATUS_PENDING;

        /* The owner states how many more connections it has room for. Stated with the request, under
           the lock that hands connections to it: one handed over to this request is then counted
           against the room (LibTCPAccept), not lost when the lwIP thread applies the room */
        if (Room)
            InterlockedExchange(&Listener->ListenRoom, (LONG)Room + 1);
    }
    else
        Status = STATUS_NO_MEMORY;

    UnlockObject(Listener);

    /* A connection may have been established while no listen request was queued */
    if (Status == STATUS_PENDING)
        LibTCPClaimPendingAccept(Listener);

    return Status;
}
