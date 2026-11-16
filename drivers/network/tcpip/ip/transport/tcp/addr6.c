/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Configured IPv6 unicast addresses (IOCTL_IP6_ADDRESS_CONFIG)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * lwIP forms the addresses of an interface itself (the link-local one, SLAAC); an administrator adds, changes
 * and removes others here: prefix length, valid and preferred lifetimes, prefix and suffix origin (as reported),
 * skip-as-source. The address goes into a free address slot of lwIP's interface, tentative: lwIP's duplicate
 * address detection (RFC 4862 5.4) runs for it as for its own, and a duplicate stays duplicated (no new identifier,
 * as for a manual address in RFC 4862 5.4.5). Its lifetimes are not lwIP's "static" (0, which lwIP takes for an
 * implied /64): an infinite one is IP6_ADDR_LIFE_INFINITE, so the on-link prefix is the configured one, through the
 * route table (route6.c), and lwIP leaves the address alone when a router advertises its prefix (the NitroOS check
 * LWIP_HOOK_ND6_ADDR_CONFIGURED in nd6.c).
 *
 * What lwIP does not keep (prefix length, origins, skip-as-source) is kept here, per interface and address slot,
 * with the address: an entry counts only while the slot still holds that address, so an address lwIP removed (its
 * valid lifetime ended) leaves nothing behind that could apply to another one. The address change goes to user mode
 * through lwIP's interface events (if6.c: NotifyUnicastIpAddressChange, NotifyIpInterfaceChange and
 * NotifyRouteChange2). Everything here is under lwIP's core lock, but the persistent store (persist6.c): an address
 * configured with TCP_IPV6_STORE_PERSISTENT is written there and comes back whenever the adapter starts.
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

/* Configured addresses, over all interfaces (at most LWIP_IPV6_NUM_ADDRESSES - 1 per interface): ADDR6_MAX of them */
#define ADDR6_INFINITE          0xFFFFFFFF

typedef struct _ADDR6_ENTRY
{
    struct netif *Netif;        /* NULL: a free entry */
    s8_t Slot;
    ip6_addr_t Address;
    TCP6_ADDRESS_INFO Info;
} ADDR6_ENTRY, *PADDR6_ENTRY;

static ADDR6_ENTRY Addr6Table[ADDR6_MAX];
/* Entries in use. One whose slot changed meanwhile (the address expired, or the stack formed another one there) is
   stale until the next sweep (TCP6SweepAddresses, once a second), so the count is the live entries to within a second:
   the lookups that run per datagram while any address is configured scan no more than that */
ULONG Addr6Count;

/* The entry of a slot, if the slot still holds its address (core lock held) */
static
PADDR6_ENTRY
Addr6Find(struct netif *netif, s8_t Slot)
{
    ULONG i, Seen;

    for (i = 0, Seen = 0; i < ADDR6_MAX && Seen < Addr6Count; i++)
    {
        PADDR6_ENTRY Entry = &Addr6Table[i];

        if (!Entry->Netif)
            continue;
        Seen++;
        if (Entry->Netif != netif || Entry->Slot != Slot)
            continue;
        if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, Slot)) ||
            !ip6_addr_eq(&Entry->Address, netif_ip6_addr(netif, Slot)))
            return NULL;
        return Entry;
    }
    return NULL;
}

static
VOID
Addr6Free(PADDR6_ENTRY Entry)
{
    RtlZeroMemory(Entry, sizeof(*Entry));
    Addr6Count--;
}

/* The entries whose slot no longer holds their address go (core lock held) */
VOID
TCP6SweepAddresses(VOID)
{
    ULONG i;

    for (i = 0; i < ADDR6_MAX && Addr6Count; i++)
    {
        PADDR6_ENTRY Entry = &Addr6Table[i];

        if (!Entry->Netif)
            continue;
        if (ip6_addr_isinvalid(netif_ip6_addr_state(Entry->Netif, Entry->Slot)) ||
            !ip6_addr_eq(&Entry->Address, netif_ip6_addr(Entry->Netif, Entry->Slot)))
            Addr6Free(Entry);
    }
}

/* What was configured for the address in a slot; FALSE: the stack formed it (core lock held) */
BOOLEAN
TCP6AddressInfo(struct netif *netif, signed char Slot, PTCP6_ADDRESS_INFO Info)
{
    PADDR6_ENTRY Entry;

    if (!Addr6Count)
        return FALSE;
    Entry = Addr6Find(netif, Slot);
    if (!Entry)
        return FALSE;
    if (Info)
        *Info = Entry->Info;
    return TRUE;
}

/* LWIP_HOOK_ND6_ADDR_CONFIGURED (core lock held): router advertisements and duplicate address detection of the
   link-local address leave a configured address alone */
int
LibNd6AddrConfigured(struct netif *netif, s8_t Slot)
{
    return TCP6AddressInfo(netif, Slot, NULL);
}

/* LWIP_HOOK_IP6_SKIP_SOURCE (core lock held): a configured address marked skip-as-source is not chosen as the
   source of a datagram */
int
LibIp6SkipSource(struct netif *netif, s8_t Slot)
{
    TCP6_ADDRESS_INFO Info;

    return TCP6AddressInfo(netif, Slot, &Info) && (Info.Flags & TCP_IPV6_ADDRESS_SKIP_AS_SOURCE);
}

/* The interface goes (core lock held): its entries go */
VOID
TCP6RemoveAddressesOfNetif(struct netif *netif)
{
    ULONG i;

    TCP6DuplicateClear(netif);
    TCP6RemoveTemporaryOfNetif(netif);
    for (i = 0; i < ADDR6_MAX && Addr6Count; i++)
    {
        if (Addr6Table[i].Netif == netif)
            Addr6Free(&Addr6Table[i]);
    }
}

/* The slot of Address on netif, -1 if it has none (core lock held) */
static
s8_t
Addr6SlotOf(struct netif *netif, const ip6_addr_t *Address)
{
    s8_t i;

    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)) &&
            ip6_addr_zoneless_eq(netif_ip6_addr(netif, i), Address))
            return i;
    }
    return -1;
}

static
VOID
Addr6SetLifetimes(struct netif *netif, s8_t Slot, ULONG Valid, ULONG Preferred)
{
    /* never 0 (lwIP's "static"): the request was checked for a valid lifetime of at least 1 */
    netif_ip6_addr_set_valid_life(netif, Slot, Valid == ADDR6_INFINITE ? IP6_ADDR_LIFE_INFINITE : Valid);
    netif_ip6_addr_set_pref_life(netif, Slot, Preferred == ADDR6_INFINITE ? IP6_ADDR_LIFE_INFINITE : Preferred);
}

/* An origin value the stack keeps: 0..15 as asked, or what the field reads back for 8..15 (Windows keeps the value
   in a signed 4-bit field: 0xFFFFFFF8..0xFFFFFFFF) */
static
BOOLEAN
Addr6OriginValid(ULONG Origin)
{
    return Origin <= 15 || Origin >= 0xFFFFFFF8;
}

static
NTSTATUS
Addr6CheckRequest(const TCP_IPV6_ADDRESS_REQUEST *Request, ip6_addr_t *Address)
{
    if (Request->Operation < TCP_IPV6_CONFIG_CREATE || Request->Operation > TCP_IPV6_CONFIG_DELETE)
        return STATUS_INVALID_PARAMETER;
    if (Request->Store != TCP_IPV6_STORE_ACTIVE && Request->Store != TCP_IPV6_STORE_PERSISTENT)
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(Address->addr, Request->Address, 16);
    ip6_addr_clear_zone(Address);
    if (ip6_addr_isany(Address) || ip6_addr_ismulticast(Address) || ip6_addr_isloopback(Address) ||
        ip6_addr_isipv4mappedipv6(Address))
        return STATUS_INVALID_PARAMETER;

    if (Request->Operation != TCP_IPV6_CONFIG_DELETE)
    {
        if (Request->PrefixLength > 128)
            return STATUS_INVALID_PARAMETER;
        if (Request->ValidLifetime == 0 || Request->PreferredLifetime > Request->ValidLifetime)
            return STATUS_INVALID_PARAMETER;
        /* the origins are reported to user mode as they are: only values of the NL_PREFIX_ORIGIN and
           NL_SUFFIX_ORIGIN fields (a signed 4-bit field: 0..7, and -8..-1 as ULONG) and no unknown flag */
        if (!Addr6OriginValid(Request->PrefixOrigin) || !Addr6OriginValid(Request->SuffixOrigin) ||
            (Request->Flags & ~TCP_IPV6_ADDRESS_SKIP_AS_SOURCE))
            return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* Creates, changes or removes an address of netif (core lock held). Persistent: the entry is in the persistent
   store too (a change keeps that); *WasPersistent: it was before */
static
NTSTATUS
Addr6ConfigureLocked(struct netif *netif, const TCP_IPV6_ADDRESS_REQUEST *Request, const ip6_addr_t *Wanted,
                     BOOLEAN Persistent, PBOOLEAN WasPersistent)
{
    ip6_addr_t Address = *Wanted;
    PADDR6_ENTRY Entry = NULL;
    s8_t Slot;
    ULONG i;

    if (ip6_addr_islinklocal(&Address))
        ip6_addr_assign_zone(&Address, IP6_UNICAST, netif);

    Slot = Addr6SlotOf(netif, &Address);
    if (Slot >= 0)
        Entry = Addr6Find(netif, Slot);
    *WasPersistent = Entry && (Entry->Info.Flags & TCP_IPV6_ADDRESS_PERSISTENT);
    Persistent = Persistent || *WasPersistent;

    switch (Request->Operation)
    {
        case TCP_IPV6_CONFIG_CREATE:
            if (Slot >= 0)
                return STATUS_OBJECT_NAME_COLLISION;

            /* slot 0 is the link-local address lwIP forms (SLAAC takes its identifier from it): a configured
               link-local address goes there only while it is free */
            for (;;)
            {
                for (Slot = 1; Slot < LWIP_IPV6_NUM_ADDRESSES; Slot++)
                {
                    if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, Slot)))
                        break;
                }
                /* a temporary address (temp6.c) gives way to a configured or DHCPv6 address */
                if (Slot == LWIP_IPV6_NUM_ADDRESSES && TCP6TemporaryMakeRoom(netif))
                    continue;
                break;
            }
            if (Slot == LWIP_IPV6_NUM_ADDRESSES && ip6_addr_islinklocal(&Address) &&
                ip6_addr_isinvalid(netif_ip6_addr_state(netif, 0)))
                Slot = 0;
            if (Slot == LWIP_IPV6_NUM_ADDRESSES)
                return STATUS_INSUFFICIENT_RESOURCES;

            for (i = 0; i < ADDR6_MAX && Addr6Table[i].Netif; i++)
                ;
            if (i == ADDR6_MAX)
            {
                /* stale entries hold room: drop them and look again */
                for (i = 0; i < ADDR6_MAX; i++)
                {
                    if (Addr6Table[i].Netif && !Addr6Find(Addr6Table[i].Netif, Addr6Table[i].Slot))
                        Addr6Free(&Addr6Table[i]);
                }
                for (i = 0; i < ADDR6_MAX && Addr6Table[i].Netif; i++)
                    ;
                if (i == ADDR6_MAX)
                    return STATUS_INSUFFICIENT_RESOURCES;
            }
            /* an old entry of this slot (its address went meanwhile) gives way */
            {
                ULONG j;

                for (j = 0; j < ADDR6_MAX; j++)
                {
                    if (Addr6Table[j].Netif == netif && Addr6Table[j].Slot == Slot)
                        Addr6Free(&Addr6Table[j]);
                }
            }

            Entry = &Addr6Table[i];
            Entry->Netif = netif;
            Entry->Slot = Slot;
            Entry->Address = Address;
            Entry->Info.PrefixLength = (UCHAR)Request->PrefixLength;
            Entry->Info.PrefixOrigin = Request->PrefixOrigin;
            Entry->Info.SuffixOrigin = Request->SuffixOrigin;
            Entry->Info.Flags = (Request->Flags & TCP_IPV6_ADDRESS_SKIP_AS_SOURCE) | TCP_IPV6_ADDRESS_CONFIGURED |
                                (Persistent ? TCP_IPV6_ADDRESS_PERSISTENT : 0);
            Addr6Count++;

            netif_ip6_addr_set(netif, Slot, &Address);
            Addr6SetLifetimes(netif, Slot, Request->ValidLifetime, Request->PreferredLifetime);
            /* duplicate address detection runs for it from the next ND timer tick (lwIP: once the interface is up
               with its link); the interface event tells user mode */
            netif_ip6_addr_set_state(netif, Slot, IP6_ADDR_TENTATIVE);
            break;

        case TCP_IPV6_CONFIG_SET:
            if (Slot < 0)
                return STATUS_NOT_FOUND;
            if (!Entry)
            {
                /* an address the stack formed: from now on it is a configured one */
                for (i = 0; i < ADDR6_MAX && Addr6Table[i].Netif; i++)
                    ;
                if (i == ADDR6_MAX)
                    return STATUS_INSUFFICIENT_RESOURCES;
                Entry = &Addr6Table[i];
                Entry->Netif = netif;
                Entry->Slot = Slot;
                Entry->Address = *netif_ip6_addr(netif, Slot);
                Addr6Count++;
            }
            Entry->Info.PrefixLength = (UCHAR)Request->PrefixLength;
            Entry->Info.PrefixOrigin = Request->PrefixOrigin;
            Entry->Info.SuffixOrigin = Request->SuffixOrigin;
            Entry->Info.Flags = (Request->Flags & TCP_IPV6_ADDRESS_SKIP_AS_SOURCE) | TCP_IPV6_ADDRESS_CONFIGURED |
                                (Persistent ? TCP_IPV6_ADDRESS_PERSISTENT : 0);
            Addr6SetLifetimes(netif, Slot, Request->ValidLifetime, Request->PreferredLifetime);
            /* the preferred lifetime decides between preferred and deprecated (DAD is not run again) */
            if (ip6_addr_isvalid(netif_ip6_addr_state(netif, Slot)))
                netif_ip6_addr_set_state(netif, Slot, Request->PreferredLifetime ? IP6_ADDR_PREFERRED :
                                                                                   IP6_ADDR_DEPRECATED);
            break;

        case TCP_IPV6_CONFIG_DELETE:
            if (Slot < 0)
            {
                /* an address DAD found in use that was replaced by a new identifier (iid6.c) is still listed as a
                   duplicate: deleting it takes it off the list */
                if (TCP6DuplicateRemove(netif, &Address))
                {
                    AddrChangeNotify();
                    return STATUS_SUCCESS;
                }
                return STATUS_NOT_FOUND;
            }
            if (Entry)
                Addr6Free(Entry);
            netif_ip6_addr_set_valid_life(netif, Slot, 0);
            netif_ip6_addr_set_pref_life(netif, Slot, 0);
            /* connections bound to it are aborted by lwIP (netif_ip6_addr_set_state) */
            netif_ip6_addr_set_state(netif, Slot, IP6_ADDR_INVALID);
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    /* the on-link prefix and the source addresses changed: every destination finds its route again */
    nd6_clear_destination_cache();
    return STATUS_SUCCESS;
}

/* A persistent record (persist6.c), with the adapter's start (core lock held): the address is added unless it is
   there. STATUS_SUCCESS: added */
NTSTATUS
TCP6ApplyAddressLocked(struct netif *netif, const TCP_IPV6_ADDRESS_REQUEST *Record)
{
    TCP_IPV6_ADDRESS_REQUEST Request = *Record;
    ip6_addr_t Address;
    BOOLEAN WasPersistent;
    NTSTATUS Status;

    Request.Operation = TCP_IPV6_CONFIG_CREATE;
    Request.Store = TCP_IPV6_STORE_PERSISTENT;
    Status = Addr6CheckRequest(&Request, &Address);
    if (!NT_SUCCESS(Status))
        return Status;
    return Addr6ConfigureLocked(netif, &Request, &Address, TRUE, &WasPersistent);
}

/* IOCTL_IP6_ADDRESS_CONFIG (the caller is an administrator: TiDispatch checked) */
NTSTATUS
DispAddressConfig6(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    TCP_IPV6_ADDRESS_REQUEST Request, Undo;
    PIP_INTERFACE IF;
    struct netif *netif;
    ip6_addr_t Address;
    BOOLEAN Persistent, WasPersistent = FALSE, Found;
    NTSTATUS Status, StoreStatus;

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(Request) || !Irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&Request, Irp->AssociatedIrp.SystemBuffer, sizeof(Request));

    if (!TCPIpv6Enabled)
        return STATUS_NOT_SUPPORTED;

    Status = Addr6CheckRequest(&Request, &Address);
    if (!NT_SUCCESS(Status))
        return Status;
    Persistent = (Request.Store == TCP_IPV6_STORE_PERSISTENT);

    IF = TCP6ReferenceInterface(Request.IfIndex);
    if (!IF)
        return STATUS_NOT_FOUND;
    netif = IF->TCPContext;

    /* DisabledComponents: only the loopback interface has IPv6 */
    if (!TCPIpv6Links && IF != Loopback)
    {
        IPDereferenceInterface(IF);
        return STATUS_NOT_SUPPORTED;
    }

    /* from the change of the active table to the write of the record: one request at a time, so a creation racing a
       removal of the same address leaves the store in step with the table */
    TCP6ConfigLock();
    LOCK_TCPIP_CORE();
    if (TCP6NetifRegistered(netif))
        Status = Addr6ConfigureLocked(netif, &Request, &Address, Persistent, &WasPersistent);
    else
        Status = STATUS_NOT_FOUND;
    UNLOCK_TCPIP_CORE();

    /* the persistent store: a removal takes the address out of both stores (also one the active store no longer
       has), a creation or change of a persistent address writes it */
    if (Request.Operation == TCP_IPV6_CONFIG_DELETE)
    {
        StoreStatus = TCP6PersistAddress(IF, &Request, TRUE, &Found);
        if (Status == STATUS_NOT_FOUND && NT_SUCCESS(StoreStatus) && Found)
            Status = STATUS_SUCCESS;
        else if (NT_SUCCESS(Status) && !NT_SUCCESS(StoreStatus))
            Status = StoreStatus;
    }
    else if (NT_SUCCESS(Status) && (Persistent || WasPersistent))
    {
        StoreStatus = TCP6PersistAddress(IF, &Request, FALSE, &Found);
        if (!NT_SUCCESS(StoreStatus))
        {
            /* a creation the store did not take is undone */
            if (Request.Operation == TCP_IPV6_CONFIG_CREATE)
            {
                Undo = Request;
                Undo.Operation = TCP_IPV6_CONFIG_DELETE;
                LOCK_TCPIP_CORE();
                if (TCP6NetifRegistered(netif))
                    Addr6ConfigureLocked(netif, &Undo, &Address, FALSE, &WasPersistent);
                UNLOCK_TCPIP_CORE();
            }
            Status = StoreStatus;
        }
    }
    TCP6ConfigUnlock();
    IPDereferenceInterface(IF);

    /* a change without a state change made no interface event: the prefix length, origins or lifetimes are new */
    if (NT_SUCCESS(Status) && Request.Operation == TCP_IPV6_CONFIG_SET)
    {
        AddrChangeNotify();
        RouteChangeNotify();
    }
    return Status;
}
