/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Per-interface parameters of IPv4 and IPv6 (IOCTL_IP_INTERFACE_CONFIG, SetIpInterfaceEntry)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * What an administrator can set per interface and family, in force at once (the active store) and, with
 * TCP_IPV6_STORE_PERSISTENT, written under the adapter's key and read again whenever the adapter starts
 * (persist6.c: TCP6PersistInterface, TCP6ReadInterfaceParams):
 *
 *   MTU                IPv4 576..link MTU, IPv6 1280..link MTU. IP_INTERFACE::Ip4MtuConfig / Ip6MtuConfig; the
 *                      stack's MTU of the family (IP_INTERFACE::MTU, lwIP's netif->mtu and mtu6) follows, so new TCP
 *                      connections and datagrams use it (a router advertisement may lower the IPv6 one further)
 *   metric             1..9999, 0 automatic. IPv4: IP_INTERFACE::Metric (the IPv4 routes of the interface take it at
 *                      once); IPv6: added to the metric of every route when the route table chooses a route
 *                      (TCP6InterfaceMetric). The automatic one is Windows' table by link speed
 *   router discovery   IPv6: enabled, disabled (router advertisements of the interface are dropped, no router
 *                      solicitations), controlled by DHCP (kept and reported; it behaves as enabled). Addresses and
 *                      routes learned before stay until their lifetimes end
 *   DAD transmits      IPv6: 0..7 probes per address (0: the address is usable at the next timer tick)
 *   forwarding         the stack does not forward: only "off" exists, a request to switch it on is refused
 *
 * IPv4 router discovery and DAD transmits have no knob in this stack: a request to change them is refused
 * (STATUS_NOT_SUPPORTED). All checks run before anything is written or applied.
 */

#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include <lwip_hooks.h>

#define IFCFG_MAX_INTERFACES    64
#define IFCFG_MTU4_MIN          576
#define IFCFG_MTU6_MIN          1280
#define IFCFG_METRIC_MAX        9999
#define IFCFG_DAD_MAX           7

/* The values of NL_ROUTER_DISCOVERY_BEHAVIOR and what IP_INTERFACE::Ip6RouterDiscovery holds (0 = the default) */
#define IFCFG_RD_DISABLED       0
#define IFCFG_RD_ENABLED        1
#define IFCFG_RD_DHCP           2

static
UCHAR
IfcfgRdToInternal(ULONG Behavior)
{
    switch (Behavior)
    {
        case IFCFG_RD_DISABLED: return 1;
        case IFCFG_RD_DHCP:     return 2;
        default:                return 0;
    }
}

static
ULONG
IfcfgRdFromInternal(UCHAR Internal)
{
    switch (Internal)
    {
        case 1:  return IFCFG_RD_DISABLED;
        case 2:  return IFCFG_RD_DHCP;
        default: return IFCFG_RD_ENABLED;
    }
}

/* The automatic interface metric of Windows for a link speed (the same table iphlpapi reports) */
static
ULONG
IfcfgAutomaticMetric(PIP_INTERFACE IF)
{
    return RouterAutomaticMetric((ULONGLONG)IF->Speed * 100);   /* 100 bit/s units */
}

/* What the route table adds to a route's metric for the interface of netif (core lock held) */
ULONG
TCP6InterfaceMetric(struct netif *netif)
{
    PIP_INTERFACE IF = netif ? netif->state : NULL;

    if (!IF || IF == Loopback || IF->AddressLength != 6)
        return 0;
    return IF->Ip6Metric ? IF->Ip6Metric : IfcfgAutomaticMetric(IF);
}

/* The interface an IPv6 link-local destination without a scope id goes out on (core lock held). Measured on Windows
 * Server 2022 (ping, connect, sendto, one and two adapters; the name resolver leaves the scope id 0): the stack
 * takes the on-link fe80::/64 route of the lowest interface metric, so the adapter that is up with an address and
 * the lowest metric (the lowest interface index decides a tie here), the same one for every protocol; no adapter that can
 * carry it: no route (NULL). Windows also moves on to the next interface after neighbour discovery failed on the
 * first, which is not done here. The loopback interface is never chosen */
struct netif *
TCP6DefaultLinkLocalNetif(VOID)
{
    struct netif *netif, *Best = NULL;
    ULONG BestMetric = 0;
    s8_t i;

    NETIF_FOREACH(netif)
    {
        PIP_INTERFACE IF = netif->state;
        BOOLEAN HasAddress = FALSE;
        ULONG Metric;

        if (!IF || IF == Loopback || !netif_is_up(netif) || !(netif->flags & NETIF_FLAG_LINK_UP))
            continue;
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)))
            {
                HasAddress = TRUE;
                break;
            }
        }
        if (!HasAddress)
            continue;

        Metric = TCP6InterfaceMetric(netif);
        /* the lowest metric; a tie: the lowest interface index (the netif list is newest first) */
        if (!Best || Metric < BestMetric ||
            (Metric == BestMetric && IF->Index < ((PIP_INTERFACE)Best->state)->Index))
        {
            Best = netif;
            BestMetric = Metric;
        }
    }

    return Best;
}

/* The lwIP zone of TCP6DefaultLinkLocalNetif, IP6_NO_ZONE when there is none. PASSIVE_LEVEL */
UCHAR
TCP6DefaultLinkLocalZone(VOID)
{
    struct netif *netif;
    UCHAR Zone = IP6_NO_ZONE;

    if (!TCPIpv6Enabled)
        return IP6_NO_ZONE;

    LOCK_TCPIP_CORE();
    netif = TCP6DefaultLinkLocalNetif();
    if (netif)
        Zone = (UCHAR)netif_get_index(netif);
    UNLOCK_TCPIP_CORE();

    return Zone;
}

/* lwIP hook: router advertisements and solicitations of an interface whose router discovery is disabled */
int
LibNd6RaAccept(struct netif *netif)
{
    PIP_INTERFACE IF = netif ? netif->state : NULL;

    return !(IF && IF->Ip6RouterDiscovery == 1);
}

/* lwIP hook: the number of DAD probes of an interface */
u8_t
LibNd6DadAttempts(struct netif *netif)
{
    PIP_INTERFACE IF = netif ? netif->state : NULL;

    if (IF && IF->Ip6DadSet)
        return IF->Ip6DadTransmits;
    return LWIP_IPV6_DUP_DETECT_ATTEMPTS;
}

/* The interface with this index that has an adapter (referenced) */
static
PIP_INTERFACE
IfcfgReference(ULONG IfIndex)
{
    PIP_INTERFACE Found = NULL;
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    ForEachInterface(CurrentIF) {
        if (CurrentIF->Index == IfIndex)
        {
            if (CurrentIF != Loopback && CurrentIF->TCPContext && CurrentIF->AddressLength == 6)
            {
                IPReferenceInterface(CurrentIF);
                Found = CurrentIF;
            }
            break;
        }
    } EndFor(CurrentIF);
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    return Found;
}

/* The IP_INTERFACE_CONFIG_ENTRY_ID answer: TCP_IP_INTERFACE_HEADER, then the rows. Returns the size of the whole
   answer; what fits in Out (OutSize bytes) is written, so a caller whose buffer is too small gets the size and
   asks again. PASSIVE_LEVEL */
ULONG
TCPQueryIpInterfaces(PVOID Out, ULONG OutSize)
{
    PTCP_IP_INTERFACE_HEADER Header = Out;
    PTCP_IP_INTERFACE_ROW Rows = (PTCP_IP_INTERFACE_ROW)(Header + 1);
    ULONG Count = 0, Capacity = 0;
    KIRQL OldIrql;
    IF_LIST_ITER(CurrentIF);

    if (Out && OutSize >= sizeof(*Header))
        Capacity = (OutSize - sizeof(*Header)) / sizeof(*Rows);

    TcpipAcquireSpinLock(&InterfaceListLock, &OldIrql);
    ForEachInterface(CurrentIF) {
        struct netif *netif = CurrentIF->TCPContext;

        if (!netif)
            continue;
        if (Count < Capacity)
        {
            PTCP_IP_INTERFACE_ROW Row = &Rows[Count];
            BOOLEAN IsLoopback = (CurrentIF == Loopback);

            RtlZeroMemory(Row, sizeof(*Row));
            Row->IfIndex = CurrentIF->Index;
            Row->Ip4Mtu = CurrentIF->MTU;
            Row->Ip4Metric = CurrentIF->Ip4MetricConfig;
            Row->LinkSpeed = CurrentIF->Speed;
            if (IsLoopback)
                Row->Flags |= TCP_IPIF_ROW_LOOPBACK;
            /* DisabledComponents (TCPIpv6Links FALSE): IPv6 is on the loopback interface only */
            if (TCPIpv6Enabled &&
                (IsLoopback || (TCPIpv6Links && CurrentIF->AddressLength == 6 && netif->hwaddr_len == 6)))
            {
                Row->Flags |= TCP_IPIF_ROW_IP6;
                Row->Ip6Mtu = IsLoopback ? 0xFFFFFFFF : netif->mtu6;
                Row->Ip6Metric = CurrentIF->Ip6Metric;
                Row->Ip6RouterDiscovery = IfcfgRdFromInternal(CurrentIF->Ip6RouterDiscovery);
                Row->Ip6DadTransmits = IsLoopback ? 0 : LibNd6DadAttempts(netif);
            }
        }
        Count++;
    } EndFor(CurrentIF);
    TcpipReleaseSpinLock(&InterfaceListLock, OldIrql);

    if (Out && OutSize >= sizeof(*Header))
        Header->Count = min(Count, Capacity);
    return sizeof(*Header) + Count * sizeof(*Rows);
}

/* The adapter of IF started (PASSIVE_LEVEL, from TCP6ApplyPersistent): the persistent IPv6 parameters replace what
   was in force (a change of the active store only lasts until the adapter starts again, as the IPv4 metric of the
   registry always did) */
VOID
TCP6ApplyInterfaceParams(PIP_INTERFACE IF)
{
    ULONG Mtu = 0, Metric = 0, RouterDiscovery = 0xFFFFFFFF, Dad = 0xFFFFFFFF;
    struct netif *netif = IF->TCPContext;

    TCP6ReadInterfaceParams(IF, &Mtu, &Metric, &RouterDiscovery, &Dad);

    IF->Ip6MtuConfig = (Mtu >= IFCFG_MTU6_MIN && Mtu <= 0xFFFF) ? Mtu : 0;
    IF->Ip6Metric = (Metric <= IFCFG_METRIC_MAX) ? Metric : 0;
    IF->Ip6RouterDiscovery = (RouterDiscovery <= IFCFG_RD_DHCP) ? IfcfgRdToInternal(RouterDiscovery) : 0;
    if (Dad <= IFCFG_DAD_MAX)
    {
        IF->Ip6DadSet = TRUE;
        IF->Ip6DadTransmits = (UCHAR)Dad;
    }
    else
    {
        IF->Ip6DadSet = FALSE;
        IF->Ip6DadTransmits = 0;
    }

    if (IF->Ip6RouterDiscovery == 1 && netif)
    {
        LOCK_TCPIP_CORE();
        if (TCP6NetifRegistered(netif))
            netif->rs_count = 0;
        UNLOCK_TCPIP_CORE();
    }
}

/* A request on an interface the caller holds a reference to (PASSIVE_LEVEL, no lock held): checked, written to the
   persistent store when it asks for that, applied */
NTSTATUS
TCP6InterfaceConfigure(PIP_INTERFACE IF, const TCP_IP_INTERFACE_REQUEST *Asked)
{
    TCP_IP_INTERFACE_REQUEST Request = *Asked;
    struct netif *netif = IF->TCPContext;
    BOOLEAN V6, Persistent, WasDisabled;
    NTSTATUS Status;

    if ((Request.Family != TCP_IPIF_IPV4 && Request.Family != TCP_IPIF_IPV6) ||
        (Request.Store != TCP_IPV6_STORE_ACTIVE && Request.Store != TCP_IPV6_STORE_PERSISTENT) ||
        Request.Fields == 0 || (Request.Fields & ~(ULONG)(TCP_IPIF_SET_MTU | TCP_IPIF_SET_METRIC |
                                                          TCP_IPIF_SET_ROUTER_DISCOVERY | TCP_IPIF_SET_DAD_TRANSMITS |
                                                          TCP_IPIF_SET_FORWARDING)))
        return STATUS_INVALID_PARAMETER;
    V6 = (Request.Family == TCP_IPIF_IPV6);
    Persistent = (Request.Store == TCP_IPV6_STORE_PERSISTENT);

    /* the interfaces here are not the loopback one: with DisabledComponents they have no IPv6 (as DispRouteConfig6) */
    if (V6 && (!TCPIpv6Enabled || !TCPIpv6Links))
        return STATUS_NOT_SUPPORTED;

    /* everything is checked before anything changes: wrong values first, then what the stack cannot do */
    Status = STATUS_SUCCESS;
    if (Request.Fields & TCP_IPIF_SET_MTU)
    {
        ULONG Link = IF->LinkMtu ? IF->LinkMtu : IF->MTU;

        if (Request.Mtu < (V6 ? IFCFG_MTU6_MIN : IFCFG_MTU4_MIN) || Request.Mtu > Link || Request.Mtu > 0xFFFF)
            Status = STATUS_INVALID_PARAMETER;
    }
    if ((Request.Fields & TCP_IPIF_SET_METRIC) && Request.Metric > IFCFG_METRIC_MAX)
        Status = STATUS_INVALID_PARAMETER;
    if ((Request.Fields & TCP_IPIF_SET_ROUTER_DISCOVERY) && Request.RouterDiscovery > IFCFG_RD_DHCP)
        Status = STATUS_INVALID_PARAMETER;
    if ((Request.Fields & TCP_IPIF_SET_DAD_TRANSMITS) && V6 && Request.DadTransmits > IFCFG_DAD_MAX)
        Status = STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(Status))
    {
        if (((Request.Fields & TCP_IPIF_SET_FORWARDING) && Request.Forwarding) ||
            (!V6 && (Request.Fields & (TCP_IPIF_SET_ROUTER_DISCOVERY | TCP_IPIF_SET_DAD_TRANSMITS))))
            Status = STATUS_NOT_SUPPORTED;
    }
    if (!NT_SUCCESS(Status))
        return Status;

    /* the persistent store first: a value it does not take changes nothing */
    if (Persistent)
    {
        Status = TCP6PersistInterface(IF, &Request);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    if (V6)
    {
        WasDisabled = (IF->Ip6RouterDiscovery == 1);
        if (Request.Fields & TCP_IPIF_SET_MTU)
            IF->Ip6MtuConfig = Request.Mtu;
        if (Request.Fields & TCP_IPIF_SET_METRIC)
            IF->Ip6Metric = Request.Metric;
        if (Request.Fields & TCP_IPIF_SET_DAD_TRANSMITS)
        {
            IF->Ip6DadTransmits = (UCHAR)Request.DadTransmits;
            IF->Ip6DadSet = TRUE;
        }
        if (Request.Fields & TCP_IPIF_SET_ROUTER_DISCOVERY)
        {
            IF->Ip6RouterDiscovery = IfcfgRdToInternal(Request.RouterDiscovery);

            LOCK_TCPIP_CORE();
            if (TCP6NetifRegistered(netif))
            {
                /* off: no more solicitations; on again: solicit as the interface does when its link comes up */
                if (IF->Ip6RouterDiscovery == 1)
                    netif->rs_count = 0;
                else if (WasDisabled)
                    netif->rs_count = LWIP_ND6_MAX_MULTICAST_SOLICIT;
            }
            UNLOCK_TCPIP_CORE();
        }
        if (Request.Fields & TCP_IPIF_SET_MTU)
            TCPUpdateInterfaceIPInformation(IF);
        if (Request.Fields & TCP_IPIF_SET_METRIC)
            RouteChangeNotify6();
    }
    else
    {
        if (Request.Fields & TCP_IPIF_SET_MTU)
        {
            IF->Ip4MtuConfig = Request.Mtu;
            IF->MTU = IFEffectiveIp4Mtu(IF);
            TCPUpdateInterfaceIPInformation(IF);
        }
        if (Request.Fields & TCP_IPIF_SET_METRIC)
        {
            IF->Ip4MetricConfig = Request.Metric;
            IF->Metric = Request.Metric;
            RouterUpdateMetricsForInterface(IF);
        }
    }

    /* the interface table changed (user mode compares it for NotifyIpInterfaceChange) */
    AddrChangeNotifyFamilies(V6 ? TCP_CHANGE_FAMILY_IPV6 : TCP_CHANGE_FAMILY_IPV4);
    return STATUS_SUCCESS;
}

/* IOCTL_IP_INTERFACE_CONFIG (the caller is an administrator: TiDispatch checked) */
NTSTATUS
DispInterfaceConfig(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    TCP_IP_INTERFACE_REQUEST Request;
    PIP_INTERFACE IF;
    NTSTATUS Status;

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(Request) || !Irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&Request, Irp->AssociatedIrp.SystemBuffer, sizeof(Request));

    IF = IfcfgReference(Request.IfIndex);
    if (!IF)
        return STATUS_NOT_FOUND;
    Status = TCP6InterfaceConfigure(IF, &Request);
    IPDereferenceInterface(IF);
    return Status;
}
