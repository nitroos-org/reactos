
#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/netifapi.h"
#include "lwip/ip.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include <ipifcons.h>

/* TCP segments that may wait for an unresolved neighbour: on one, and in all */
#define TCP_UNRESOLVED_PER_NEIGHBOR 16
#define TCP_UNRESOLVED_TOTAL        256

static LONG TCPUnresolvedSegments;

/* Context is non-NULL for a segment counted in TCPUnresolvedSegments */
static
VOID
TCPSendDataComplete(PVOID Context, PNDIS_PACKET NdisPacket, NDIS_STATUS NdisStatus)
{
    if (Context)
        InterlockedDecrement(&TCPUnresolvedSegments);

    FreeNdisPacket(NdisPacket);
}

err_t
TCPSendDataCallback(struct netif *netif, struct pbuf *p, const ip4_addr_t *dest)
{
    NDIS_STATUS NdisStatus;
    PNEIGHBOR_CACHE_ENTRY NCE;
    IP_PACKET Packet;
    IP_ADDRESS RemoteAddress, LocalAddress;
    PIPv4_HEADER Header;
    ULONG Length;
    ULONG TotalLength;
    BOOLEAN Unresolved;

    /* The caller frees the pbuf struct */

    if (((*(u8_t*)p->payload) & 0xF0) == 0x40)
    {
        Header = p->payload;

        LocalAddress.Type = IP_ADDRESS_V4;
        LocalAddress.Address.IPv4Address = Header->SrcAddr;

        RemoteAddress.Type = IP_ADDRESS_V4;
        RemoteAddress.Address.IPv4Address = Header->DstAddr;
    }
    else
    {
        return ERR_IF;
    }

    /* A whole TCP datagram to the loopback netif goes straight to the loopback queue (loopback.c).
     * Fragments take the IP layer's path, which reassembles them */
    if (LoopFastPath && netif->state == Loopback && Header->Protocol == IPPROTO_TCP &&
        p->len >= sizeof(IPv4_HEADER) && p->tot_len <= netif->mtu &&
        !(WN2H(Header->FlagsFragOfs) & (IPv4_MF_MASK | IPv4_FRAGOFS_MASK)))
    {
        return LoopTransmitPbuf(p) ? ERR_OK : ERR_MEM;
    }

    IPInitializePacket(&Packet, LocalAddress.Type);

    if (!(NCE = RouteGetRouteToDestination(&RemoteAddress)))
    {
        return ERR_RTE;
    }

    NdisStatus = AllocatePacketWithBuffer(&Packet.NdisPacket, NULL, p->tot_len);
    if (NdisStatus != NDIS_STATUS_SUCCESS)
    {
        NBDereferenceNeighbor(NCE);
        return ERR_MEM;
    }

    GetDataPtr(Packet.NdisPacket, 0, (PCHAR*)&Packet.Header, &Packet.TotalSize);
    Packet.MappedHeader = TRUE;

    ASSERT(Packet.TotalSize == p->tot_len);

    TotalLength = p->tot_len;
    Length = 0;
    while (Length < TotalLength)
    {
        ASSERT(p->len <= TotalLength - Length);
        ASSERT(p->tot_len == TotalLength - Length);
        RtlCopyMemory((PCHAR)Packet.Header + Length, p->payload, p->len);
        Length += p->len;
        p = p->next;
    }
    ASSERT(Length == TotalLength);

    Packet.HeaderSize = sizeof(IPv4_HEADER);
    Packet.TotalSize = TotalLength;
    Packet.SrcAddr = LocalAddress;
    Packet.DstAddr = RemoteAddress;

    /* lwIP's output runs under the core lock, and IPSendDatagram waits until the packet has
     * left, which includes resolving the neighbour's address: a neighbour that does not answer
     * held the lock for seconds. lwIP builds a complete datagram and fragments it to its
     * interface's MTU, so queue it on the neighbour as it is and free it when it has left.
     * Segments to unresolved neighbours (such as resets to spoofed sources) are limited, so
     * they cannot take the packet pool from other traffic */
    if (TotalLength <= NCE->Interface->MTU)
    {
        Unresolved = (NCE->State & NUD_INCOMPLETE) != 0;

        if (Unresolved && InterlockedIncrement(&TCPUnresolvedSegments) > TCP_UNRESOLVED_TOTAL)
        {
            InterlockedDecrement(&TCPUnresolvedSegments);
            FreeNdisPacket(Packet.NdisPacket);
            NBDereferenceNeighbor(NCE);
            return ERR_MEM;
        }

        /* The packet waits on the NCE without a reference of its own: the NCE completes
           whatever is queued on it when it leaves the cache, or with its last reference */
        if (!NBQueuePacketLimited(NCE, Packet.NdisPacket, TCPSendDataComplete,
                                  Unresolved ? &TCPUnresolvedSegments : NULL,
                                  TCP_UNRESOLVED_PER_NEIGHBOR))
        {
            if (Unresolved)
                InterlockedDecrement(&TCPUnresolvedSegments);
            FreeNdisPacket(Packet.NdisPacket);
            NBDereferenceNeighbor(NCE);
            return ERR_MEM;
        }

        NBDereferenceNeighbor(NCE);
        return ERR_OK;
    }

    /* IPSendDatagram fragments it and waits for each fragment, which for an unresolved
     * neighbour means waiting for resolution under the core lock: let lwIP try again later */
    if (NCE->State & NUD_INCOMPLETE)
    {
        FreeNdisPacket(Packet.NdisPacket);
        NBDereferenceNeighbor(NCE);
        return ERR_MEM;
    }

    NdisStatus = IPSendDatagram(&Packet, NCE);
    NBDereferenceNeighbor(NCE);
    if (!NT_SUCCESS(NdisStatus))
        return ERR_RTE;

    return 0;
}

VOID
TCPUpdateInterfaceLinkStatus(PIP_INTERFACE IF)
{
    ULONG OperationalStatus;

    GetInterfaceConnectionStatus(IF, &OperationalStatus);

    if (OperationalStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
        netif_set_link_up(IF->TCPContext);
    else
        netif_set_link_down(IF->TCPContext);
}

err_t
TCPInterfaceInit(struct netif *netif)
{
    PIP_INTERFACE IF = netif->state;

    netif->hwaddr_len = IF->AddressLength;
    RtlCopyMemory(netif->hwaddr, IF->Address, netif->hwaddr_len);

    netif->output = TCPSendDataCallback;
    netif->mtu = IF->MTU;

    netif->name[0] = 'e';
    netif->name[1] = 'n';

    netif->flags |= NETIF_FLAG_BROADCAST;

    TCPUpdateInterfaceLinkStatus(IF);

    TCPUpdateInterfaceIPInformation(IF);

    return 0;
}

VOID
TCPRegisterInterface(PIP_INTERFACE IF)
{
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gw;

    gw.addr = 0;
    ipaddr.addr = 0;
    netmask.addr = 0;

    IF->TCPContext = netif_add(IF->TCPContext,
                               &ipaddr,
                               &netmask,
                               &gw,
                               IF,
                               TCPInterfaceInit,
                               tcpip_input);
}

VOID
TCPUnregisterInterface(PIP_INTERFACE IF)
{
    netif_remove(IF->TCPContext);
}

VOID
TCPUpdateInterfaceIPInformation(PIP_INTERFACE IF)
{
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gw;

    gw.addr = 0;

    /* The netif is created before the interface knows its MTU; lwIP limits its segments and
     * fragments its datagrams to this value, and skips both while it is 0 */
    ((struct netif *)IF->TCPContext)->mtu = (u16_t)min(IF->MTU, 0xFFFF);

    GetInterfaceIPv4Address(IF,
                            ADE_UNICAST,
                            (PULONG)&ipaddr.addr);

    GetInterfaceIPv4Address(IF,
                            ADE_ADDRMASK,
                            (PULONG)&netmask.addr);

    netif_set_addr(IF->TCPContext, &ipaddr, &netmask, &gw);

    if (ipaddr.addr != 0)
    {
        netif_set_up(IF->TCPContext);
        netif_set_default(IF->TCPContext);
    }
    else
    {
        netif_set_down(IF->TCPContext);
    }
}
