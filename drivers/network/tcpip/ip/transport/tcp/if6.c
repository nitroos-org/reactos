/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IPv6 on lwIP's interfaces: the switch, the addresses, sending and receiving
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * IPv6 is lwIP's (ND, DAD, ICMPv6, fragments, TCP); our IP layer stays IPv4 and is not on the IPv6 path.
 * A received IPv6 frame goes from the adapter straight into lwIP (TCPReceive6), and lwIP's IPv6 datagrams
 * leave through TCPSendData6Callback: to the adapter with the Ethernet address lwIP's neighbour discovery
 * found, or for ::1 through the loopback queue. The behaviour follows RFC 8200, 4861 and 4862 as lwIP
 * implements them.
 *
 * Off by default: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Ipv6Enable (REG_DWORD, read once
 * at startup, non-zero = on). Off, no interface has an IPv6 address, nothing IPv6 is sent, and a received
 * IPv6 frame is dropped as before.
 *
 * There is no IPv6 socket yet (no TDI address type, no Winsock helper): nothing outside this driver can
 * create an IPv6 connection or listener. Until the firewall filters IPv6, a connection request (SYN) to an
 * IPv6 listener is taken only from this machine (the loopback queue, or a frame the adapter looped back
 * from our own send), never from the wire (LibTCPListenerInput6).
 */

#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"

#define TCP6_SWITCH_VALUE L"Ipv6Enable"

BOOLEAN TCPIpv6Enabled = FALSE;

/* Set while a datagram from one of our adapters, that the adapter looped back from our own send, is in
   ip6_input (core lock held) */
static BOOLEAN TCP6InputFromOwnLink;

/* Received IPv6 frames that were not handed to lwIP because they were shorter than their header says,
   or could not be copied; and connection requests to an IPv6 listener refused because they came from
   the wire */
volatile LONG TCP6ReceiveDropped;
volatile LONG TCP6ListenerRefused;

#if DBG || defined(TCPIP_IPV6_SELFTEST)
/* For the self-test (selftest6.c): ICMPv6 messages received, by kind (TCP6_RX_*) */
volatile LONG TCP6ReceivedIcmp[TCP6_RX_KINDS];

/* Tcpip\Parameters\Ipv6SelfTestMulticastOverflow (REG_DWORD, test runs only): ask for more multicast groups
   than the link layer takes as a list, so that its all-multicast fallback runs */
static BOOLEAN TCP6TestMulticastOverflow;

static
VOID
TCP6CountReceived(const UCHAR *Datagram, UINT Length)
{
    const UCHAR *Destination = Datagram + 24;
    UCHAR Type;

    /* ICMPv6 right after the fixed header only (what neighbour discovery and echo use) */
    if (Length < 41 || Datagram[6] != 58)
        return;
    Type = Datagram[40];
    if (Type == 135)
        InterlockedIncrement(&TCP6ReceivedIcmp[Destination[0] == 0xff ? TCP6_RX_NS_MULTICAST : TCP6_RX_NS_UNICAST]);
    else if (Type == 134)
        InterlockedIncrement(&TCP6ReceivedIcmp[Destination[0] == 0xff ? TCP6_RX_RA_MULTICAST : TCP6_RX_RA_UNICAST]);
    else if (Type == 128)
        InterlockedIncrement(&TCP6ReceivedIcmp[TCP6_RX_ECHO_REQUEST]);
}
#endif

VOID
TCPReadIpv6Switch(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters");
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(TCP6_SWITCH_VALUE);
    OBJECT_ATTRIBUTES Attributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length;
    NTSTATUS Status;

    TCPIpv6Enabled = FALSE;

    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
        return;

    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Status) && Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
        TCPIpv6Enabled = (*(PULONG)Info->Data != 0);

    ZwClose(Key);

    if (TCPIpv6Enabled)
        DbgPrint("TCPIP: IPv6 on (Ipv6Enable)\n");

#if DBG || defined(TCPIP_IPV6_SELFTEST)
    {
        UNICODE_STRING TestName = RTL_CONSTANT_STRING(L"Ipv6SelfTestMulticastOverflow");

        if (TCPIpv6Enabled && NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
        {
            Status = ZwQueryValueKey(Key, &TestName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
            if (NT_SUCCESS(Status) && Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
                TCP6TestMulticastOverflow = (*(PULONG)Info->Data != 0);
            ZwClose(Key);
        }
    }
#endif
}

/* The link layer multicast groups an Ethernet interface must receive (core lock held): the all-nodes group
 * (router advertisements, RFC 4861 4.2) and the solicited-node group of each of its addresses, tentative ones
 * included (neighbour solicitations, and duplicate address detection: RFC 4861 4.3, RFC 4862 5.4), mapped to
 * Ethernet addresses as RFC 2464 7 says (33:33 and the last 32 bits). lwIP's addresses on one interface share
 * their interface identifier (link-local and SLAAC), so this is usually two addresses. No MLD (lwipopts.h):
 * the groups are not reported to the link */
static
VOID
TCP6UpdateMulticast(struct netif *netif)
{
    PIP_INTERFACE IF = netif->state;
    UCHAR List[LL_MULTICAST_MAX * 6];
    UINT Count = 0, i, j;
    s8_t Index;

    if (!TCPIpv6Enabled || !IF || IF == Loopback || !IF->SetMulticast || IF->AddressLength != 6)
        return;

    RtlZeroMemory(List, sizeof(List));

    /* ff02::1 */
    List[0] = 0x33; List[1] = 0x33; List[2] = 0x00; List[3] = 0x00; List[4] = 0x00; List[5] = 0x01;
    Count = 1;

    for (Index = 0; Index < LWIP_IPV6_NUM_ADDRESSES; Index++)
    {
        const u8_t *Address;
        UCHAR Group[6];

        if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, Index)) ||
            ip6_addr_isduplicated(netif_ip6_addr_state(netif, Index)))
            continue;

        /* ff02::1:ffXX:XXXX, XX:XXXX the last 24 bits of the address */
        Address = (const u8_t *)netif_ip6_addr(netif, Index)->addr;
        Group[0] = 0x33; Group[1] = 0x33; Group[2] = 0xff;
        Group[3] = Address[13]; Group[4] = Address[14]; Group[5] = Address[15];

        for (i = 0; i < Count; i++)
        {
            for (j = 0; j < 6 && List[i * 6 + j] == Group[j]; j++)
                ;
            if (j == 6)
                break;
        }
        if (i < Count)
            continue;
        if (Count == LL_MULTICAST_MAX)
        {
            /* More than the link layer takes as a list: it receives all multicast instead */
            Count = LL_MULTICAST_MAX + 1;
            break;
        }
        RtlCopyMemory(&List[Count * 6], Group, 6);
        Count++;
    }

#if DBG || defined(TCPIP_IPV6_SELFTEST)
    if (TCP6TestMulticastOverflow)
        Count = LL_MULTICAST_MAX + 1;
#endif

    IF->SetMulticast(IF->Context, List, Count);
}

/* lwIP's interface events (core lock held): an address set, removed, or changing state */
static
void
TCP6NetifEvent(struct netif *netif, netif_nsc_reason_t Reason, const netif_ext_callback_args_t *Args)
{
    UNREFERENCED_PARAMETER(Args);

    if (Reason & (LWIP_NSC_IPV6_SET | LWIP_NSC_IPV6_ADDR_STATE_CHANGED))
        TCP6UpdateMulticast(netif);
}

static netif_ext_callback_t TCP6NetifCallback;
static BOOLEAN TCP6NetifCallbackAdded;

/* Called with the core lock held, from TCPInterfaceInit: the addresses an interface starts with */
VOID
TCPInterfaceInit6(PIP_INTERFACE IF)
{
    struct netif *netif = IF->TCPContext;

    if (!TCPIpv6Enabled)
        return;

    /* Address changes from now on keep the interface's multicast reception in step (the first interface
       registers it, under the core lock as the others) */
    if (!TCP6NetifCallbackAdded)
    {
        netif_add_ext_callback(&TCP6NetifCallback, TCP6NetifEvent);
        TCP6NetifCallbackAdded = TRUE;
    }

    /* An Ethernet interface gets its link-local address from its MAC (modified EUI-64, RFC 4291 2.5.1).
       It stays tentative until lwIP's duplicate address detection (RFC 4862 5.4) passes, which runs once
       the interface is up with its link */
    if (IF->AddressLength == 6 && netif->hwaddr_len == 6)
        netif_create_ip6_linklocal_address(netif, 1);
}

/* The loopback interface gets ::1 when it registers (it is not the global Loopback during netif_add) */
VOID
TCPAddLoopbackAddress6(PIP_INTERFACE IF)
{
    struct netif *netif = IF->TCPContext;
    ip6_addr_t Address;

    if (!TCPIpv6Enabled || !netif)
        return;

    ip6_addr_set_loopback(&Address);

    LOCK_TCPIP_CORE();
    /* ::1 needs no DAD: it is never on a link */
    netif_ip6_addr_set(netif, 0, &Address);
    netif_ip6_addr_set_state(netif, 0, IP6_ADDR_PREFERRED);
    UNLOCK_TCPIP_CORE();
}

/* Whether Address is one of the IPv6 addresses of netif (core lock held) */
static
BOOLEAN
TCP6IsOwnAddress(struct netif *netif, const ip6_addr_t *Address)
{
    s8_t i;

    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
            ip6_addr_zoneless_eq(netif_ip6_addr(netif, i), Address))
            return TRUE;
    }

    return FALSE;
}

static
VOID
TCPSendData6Complete(PVOID Context, PNDIS_PACKET NdisPacket, NDIS_STATUS NdisStatus)
{
    FreeNdisPacket(NdisPacket);
}

/* netif->output_ip6 (core lock held): an IPv6 datagram lwIP built, to Dest; the caller frees p.
 * This is what lwIP's ethip6_output does, except that the adapter (LANTransmit) builds the Ethernet header */
err_t
TCPSendData6Callback(struct netif *netif, struct pbuf *p, const ip6_addr_t *Dest)
{
    PIP_INTERFACE IF = netif->state;
    PNDIS_PACKET NdisPacket;
    PCHAR Data;
    UINT Size;
    UCHAR Mac[6];
    const u8_t *Hw = NULL;
    err_t Result;

    if (!TCPIpv6Enabled || !IF)
        return ERR_IF;

    /* ::1: the loopback queue gives a copy back to lwIP on its worker (LoopInputPbuf) */
    if (IF == Loopback)
        return LoopTransmitPbuf(p) ? ERR_OK : ERR_MEM;

    if (IF->AddressLength != 6 || !IF->Transmit || p->tot_len > IF->MTU)
        return ERR_IF;

    if (ip6_addr_ismulticast(Dest))
    {
        /* RFC 2464 7: 33:33 and the last 32 bits of the group */
        Mac[0] = 0x33;
        Mac[1] = 0x33;
        RtlCopyMemory(&Mac[2], &Dest->addr[3], 4);
    }
    else if (TCP6IsOwnAddress(netif, Dest))
    {
        /* To ourselves: the frame to our own MAC is looped back by NDIS inside the send, tagged as ours
           (LanLoopTagged), as an IPv4 datagram to the interface's own address is */
        RtlCopyMemory(Mac, IF->Address, 6);
    }
    else
    {
        /* The neighbour's link address, or nd6 keeps the datagram (a bounded queue) and sends it through
           this callback again once the neighbour answers */
        Result = nd6_get_next_hop_addr_or_queue(netif, p, Dest, &Hw);
        if (Result != ERR_OK)
            return Result;
        if (!Hw)
            return ERR_OK;
        RtlCopyMemory(Mac, Hw, 6);
    }

    if (AllocatePacketWithBuffer(&NdisPacket, NULL, p->tot_len) != NDIS_STATUS_SUCCESS)
        return ERR_MEM;

    GetDataPtr(NdisPacket, 0, &Data, &Size);
    if (Size < p->tot_len || pbuf_copy_partial(p, Data, p->tot_len, 0) != p->tot_len)
    {
        FreeNdisPacket(NdisPacket);
        return ERR_MEM;
    }

    PC(NdisPacket)->DLComplete = TCPSendData6Complete;
    PC(NdisPacket)->Context = NULL;

    /* Copies the frame (and the link address) before it returns, and completes NdisPacket */
    IF->Transmit(IF->Context, NdisPacket, 0, Mac, LAN_PROTO_IPv6);

    return ERR_OK;
}

/* Hands a complete IPv6 datagram (Length bytes, already bounded by the caller) to lwIP on netif */
VOID
TCPInput6(PIP_INTERFACE IF, struct pbuf *p, BOOLEAN FromOwnLink)
{
    struct netif *netif = IF->TCPContext;

    LOCK_TCPIP_CORE();
    /* Once its interface is removed (netif_remove takes it down) a late frame has nowhere to go */
    if (netif && netif_is_up(netif))
    {
        TCP6InputFromOwnLink = FromOwnLink;
        ip_input(p, netif);
        TCP6InputFromOwnLink = FALSE;
    }
    else
    {
        pbuf_free(p);
    }
    UNLOCK_TCPIP_CORE();
}

/* An IPv6 frame from an adapter (IPReceive, on the adapter's receive worker, PASSIVE_LEVEL). The caller
 * frees the packet */
VOID
TCPReceive6(PIP_INTERFACE IF, PIP_PACKET IPPacket)
{
    UCHAR Header[40];
    UINT Available, PayloadLength, Total;
    struct pbuf *p;

    if (!TCPIpv6Enabled || !IF->TCPContext || IF == Loopback)
        return;

    /* What the adapter delivered after the media header; the datagram must fit in it, whatever its
       header says */
    Available = IPPacket->TotalSize > IPPacket->Position ? IPPacket->TotalSize - IPPacket->Position : 0;
    if (Available < sizeof(Header) ||
        CopyPacketToBuffer((PCHAR)Header, IPPacket->NdisPacket, IPPacket->Position, sizeof(Header)) != sizeof(Header) ||
        (Header[0] >> 4) != 6)
    {
        InterlockedIncrement(&TCP6ReceiveDropped);
        return;
    }

    /* The payload length (RFC 8200 3) counts what follows the fixed header. Frame padding after it is not
       passed on; a datagram longer than the frame, or than a pbuf can hold, is dropped. A jumbogram (length
       0 with a hop-by-hop option) is not supported and is passed as the empty datagram its header says */
    PayloadLength = ((UINT)Header[4] << 8) | Header[5];
    Total = sizeof(Header) + PayloadLength;
    if (Total > Available || Total > 0xFFFF)
    {
        InterlockedIncrement(&TCP6ReceiveDropped);
        return;
    }

    p = pbuf_alloc(PBUF_RAW, (u16_t)Total, PBUF_RAM);
    if (!p)
    {
        InterlockedIncrement(&TCP6ReceiveDropped);
        return;
    }

    /* PBUF_RAM is one contiguous buffer */
    if (p->len != Total ||
        CopyPacketToBuffer((PCHAR)p->payload, IPPacket->NdisPacket, IPPacket->Position, Total) != Total)
    {
        pbuf_free(p);
        InterlockedIncrement(&TCP6ReceiveDropped);
        return;
    }

#if DBG || defined(TCPIP_IPV6_SELFTEST)
    TCP6CountReceived(p->payload, Total);
#endif

    TCPInput6(IF, p, IPPacket->FromOwnLink);
}

/* LWIP_HOOK_TCP_INPACKET_PCB for a segment to an IPv6 listener (core lock held, inside ip6_input): ERR_OK
 * lets lwIP take it, anything else drops it without an answer. Taken only from this machine: the loopback
 * interface (::1), or a frame that our own send looped back. A segment from the wire is dropped as the
 * firewall drops an unsolicited one, until the firewall knows IPv6 */
err_t
LibTCPListenerInput6(void)
{
    const struct netif *inp = ip_current_input_netif();

    if ((Loopback && inp == Loopback->TCPContext) || TCP6InputFromOwnLink)
        return ERR_OK;

    InterlockedIncrement(&TCP6ListenerRefused);
    return ERR_ABRT;
}
