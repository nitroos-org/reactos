/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IPv6 temporary addresses (RFC 8981) for stateless autoconfiguration
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Next to the stable address that stateless autoconfiguration forms for a prefix (iid6.c: the same address on the
 * same network every time), every SLAAC prefix gets a temporary address with a random identifier, RFC 8981, as
 * Windows does by default (netsh interface ipv6 show privacy: "Use Temporary Addresses: enabled"). Outgoing
 * connections prefer it (source address selection rule 7, RFC 6724 5: LWIP_HOOK_IP6_SOURCE_TEMPORARY in ip6.c),
 * so what a remote host sees changes once a day; incoming connections to the stable address work as before.
 *
 * Settings (Tcpip6\Parameters, REG_DWORD, read once at start; the names are those of Get-NetIPv6Protocol, the
 * defaults those of Windows, oracle 2026-11-16: netsh interface ipv6 show privacy):
 *   UseTemporaryAddresses   0 = no temporary addresses; absent or other = on
 *   MaxValidLifetime        seconds, 604800 (7 days): TEMP_VALID_LIFETIME
 *   MaxPreferredLifetime    seconds, 86400 (1 day): TEMP_PREFERRED_LIFETIME
 *   RegenerateTime          seconds, 5: REGEN_ADVANCE, a new address this long before the current one is deprecated
 *   MaxRandomTime           seconds, 600: the bound of the desynchronisation time (DESYNC_FACTOR), drawn once per start
 *                           as Windows does ("Random Time"), and at most 2/5 of MaxPreferredLifetime (RFC 8981 3.8)
 *   MaxDadAttempts          3: TEMP_IDGEN_RETRIES, new identifiers after DAD found one in use
 *
 * An address is made for a prefix while the stable (public) address lwIP formed for it is preferred, its lifetimes
 * are those of the public address (what the router advertises, after RFC 4862 5.5.3 e) but at most MaxValidLifetime
 * and MaxPreferredLifetime - desync from its creation (RFC 8981 3.4), and a new one is made RegenerateTime before the
 * newest one of the prefix stops being preferred (3.5): the old one stays, deprecated (connections that use it go on)
 * until its valid lifetime ends, when lwIP removes it. Everything runs from lwIP's neighbour discovery timer
 * (LWIP_HOOK_ND6_TMR, once a second): no timer of its own. An address whose DAD fails gets a new random identifier,
 * MaxDadAttempts times; then it stays duplicated (listed so) until its valid lifetime ends, and no other temporary
 * address is made for that prefix meanwhile (RFC 8981 3.4: stop on repeated collisions).
 *
 * The addresses live in lwIP's address slots (LWIP_IPV6_NUM_ADDRESSES); this file keeps which slot holds a temporary
 * address. lwIP's prefix processing leaves them alone (LWIP_HOOK_ND6_ADDR_CONFIGURED): they are not the address
 * nd6_process_autoconfig_prefix updates. When no slot is free for a new one, or only one is (it stays for the stable
 * address of a new prefix), the deprecated temporary address with the least valid lifetime left that no TCP
 * connection or listener uses gives way. There is no other limit of their number (Windows has no setting for it).
 *
 * The identifier: TCP6RandomIdentifier (iid6.c), RDRAND when the processor has it, under a per-start key; never
 * the system random number generator (SEC-system-rng-not-cryptographic), never a reserved identifier (RFC 5453),
 * never one an address of the interface has.
 *
 * Reported (if6.c): PrefixOrigin RouterAdvertisement, SuffixOrigin Random (Get-NetIPAddress SuffixOrigin Random,
 * ipconfig "Temporary IPv6 Address"). Core lock held for everything here but the settings.
 */

#include "precomp.h"

#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcp_priv.h"
#include <lwip_hooks.h>

#define TEMP6_PARAMETERS    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
/* Temporary addresses, over all interfaces */
#define TEMP6_MAX           64

BOOLEAN TCP6UseTemporaryAddresses;
ULONG TCP6TempMaxValid = 7 * 24 * 3600;
ULONG TCP6TempMaxPreferred = 24 * 3600;
ULONG TCP6TempRegenerate = 5;
ULONG TCP6TempMaxRandom = 10 * 60;
ULONG TCP6TempMaxDad = 3;
/* DESYNC_FACTOR of this start */
ULONG TCP6TempDesync;

typedef struct _TEMP6_ENTRY
{
    struct netif *Netif;        /* NULL: a free entry */
    s8_t Slot;
    UCHAR Retries;              /* new identifiers after DAD conflicts */
    ip6_addr_t Address;
    ULONG Created;              /* Temp6Ticks when it was made */
} TEMP6_ENTRY, *PTEMP6_ENTRY;

static TEMP6_ENTRY Temp6Table[TEMP6_MAX];
static ULONG Temp6Count;
/* Seconds, counted by the neighbour discovery timer (the clock of lwIP's lifetimes) */
static ULONG Temp6Ticks;
/* Per lwIP interface number: the slots that hold a temporary address (a quick no for source selection) */
static UCHAR Temp6Mask[256];
static BOOLEAN Temp6NoSlotLogged;

C_ASSERT(LWIP_IPV6_NUM_ADDRESSES <= 8);

static
ULONG
Temp6ReadValue(HANDLE Key, PCWSTR Name, ULONG Default, PBOOLEAN Present)
{
    UNICODE_STRING ValueName;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length;

    if (Present)
        *Present = FALSE;
    if (!Key)
        return Default;
    RtlInitUnicodeString(&ValueName, Name);
    if (NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
        Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
    {
        if (Present)
            *Present = TRUE;
        return *(PULONG)Info->Data;
    }
    return Default;
}

/* TCP6ReadIdentifierSettings, with IPv6 on, before any interface registers (PASSIVE_LEVEL). TRUE: temporary
   addresses are on (the caller makes the key of TCP6RandomIdentifier, then calls TCP6TemporaryStart) */
BOOLEAN
TCP6ReadTemporarySettings(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(TEMP6_PARAMETERS);
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Key = NULL;
    BOOLEAN Present;

    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
        Key = NULL;

    TCP6UseTemporaryAddresses = Temp6ReadValue(Key, L"UseTemporaryAddresses", 1, &Present) != 0;
    TCP6TempMaxValid = Temp6ReadValue(Key, L"MaxValidLifetime", TCP6TempMaxValid, NULL);
    TCP6TempMaxPreferred = Temp6ReadValue(Key, L"MaxPreferredLifetime", TCP6TempMaxPreferred, NULL);
    TCP6TempRegenerate = Temp6ReadValue(Key, L"RegenerateTime", TCP6TempRegenerate, NULL);
    TCP6TempMaxRandom = Temp6ReadValue(Key, L"MaxRandomTime", TCP6TempMaxRandom, NULL);
    TCP6TempMaxDad = Temp6ReadValue(Key, L"MaxDadAttempts", TCP6TempMaxDad, NULL);
    if (Key)
        ZwClose(Key);

    if (!TCP6UseTemporaryAddresses)
    {
        DbgPrint("TCPIP: no IPv6 temporary addresses (UseTemporaryAddresses = 0)\n");
        return FALSE;
    }

    /* what does not fit together is made to fit: an address is valid at least as long as it is preferred, and
       lives long enough for its DAD and a successor (RFC 8981 3.8) */
    if (TCP6TempMaxValid < 2)
        TCP6TempMaxValid = 2;
    if (TCP6TempMaxPreferred > TCP6TempMaxValid)
        TCP6TempMaxPreferred = TCP6TempMaxValid;
    if (TCP6TempMaxDad > 10)
        TCP6TempMaxDad = 10;
    if (TCP6TempRegenerate >= TCP6TempMaxPreferred)
        TCP6TempRegenerate = TCP6TempMaxPreferred / 2;
    return TRUE;
}

/* After TCP6ReadTemporarySettings said yes and the identifier key exists: the desynchronisation time of this start */
VOID
TCP6TemporaryStart(VOID)
{
    UCHAR Random[8];
    ULONG Bound = TCP6TempMaxRandom;

    /* RFC 8981 3.8: MAX_DESYNC_FACTOR is 2/5 of TEMP_PREFERRED_LIFETIME, and the preferred lifetime of an address
       stays above REGEN_ADVANCE */
    if (Bound > TCP6TempMaxPreferred / 5 * 2)
        Bound = TCP6TempMaxPreferred / 5 * 2;
    if (Bound + TCP6TempRegenerate >= TCP6TempMaxPreferred)
        Bound = (TCP6TempMaxPreferred > TCP6TempRegenerate + 1) ? TCP6TempMaxPreferred - TCP6TempRegenerate - 1 : 0;
    TCP6RandomIdentifier(Random);
    TCP6TempDesync = Bound ? (ULONG)(*(ULONGLONG UNALIGNED *)Random % ((ULONGLONG)Bound + 1)) : 0;

    DbgPrint("TCPIP: IPv6 temporary addresses: valid %lus, preferred %lus, regenerate %lus, random time %lus of %lus, "
             "%lu new identifiers on DAD conflict\n", TCP6TempMaxValid, TCP6TempMaxPreferred, TCP6TempRegenerate,
             TCP6TempDesync, TCP6TempMaxRandom, TCP6TempMaxDad);
}

/* The entry of a slot, if it still holds its temporary address. One an administrator changed (addr6.c: from then on
   a configured address) is no longer one */
static
PTEMP6_ENTRY
Temp6Find(struct netif *netif, s8_t Slot)
{
    ULONG i, Seen;

    if (!(Temp6Mask[netif->num] & (1 << Slot)))
        return NULL;
    if (Addr6Count && TCP6AddressInfo(netif, Slot, NULL))
        return NULL;
    for (i = 0, Seen = 0; i < TEMP6_MAX && Seen < Temp6Count; i++)
    {
        PTEMP6_ENTRY Entry = &Temp6Table[i];

        if (!Entry->Netif)
            continue;
        Seen++;
        if (Entry->Netif != netif || Entry->Slot != Slot)
            continue;
        if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, Slot)) ||
            !ip6_addr_zoneless_eq(&Entry->Address, netif_ip6_addr(netif, Slot)))
            return NULL;
        return Entry;
    }
    return NULL;
}

static
VOID
Temp6Free(PTEMP6_ENTRY Entry)
{
    Temp6Mask[Entry->Netif->num] &= ~(1 << Entry->Slot);
    RtlZeroMemory(Entry, sizeof(*Entry));
    Temp6Count--;
}

/* Whether the slot holds a temporary address (if6.c reports it so) */
BOOLEAN
TCP6TemporarySlot(struct netif *netif, signed char Slot)
{
    return Temp6Count && Temp6Find(netif, Slot) != NULL;
}

/* LWIP_HOOK_IP6_SOURCE_TEMPORARY (ip6.c, source address selection): 1 = the candidate is a temporary address,
   preferred over a public one by rule 7 */
int
LibIp6SourceTemporary(struct netif *netif, s8_t Slot)
{
    return Temp6Count && (Temp6Mask[netif->num] & (1 << Slot)) && Temp6Find(netif, Slot) != NULL;
}

/* Part of LWIP_HOOK_ND6_ADDR_CONFIGURED: lwIP's prefix processing and the link-local DAD failure leave a temporary
   address alone (it is not the address it formed for the prefix, nor derived from the link-local one) */
int
LibNd6AddrTemporary(struct netif *netif, s8_t Slot)
{
    return TCP6TemporarySlot(netif, Slot);
}

/* The interface goes */
VOID
TCP6RemoveTemporaryOfNetif(struct netif *netif)
{
    ULONG i;

    for (i = 0; i < TEMP6_MAX && Temp6Count; i++)
    {
        if (Temp6Table[i].Netif == netif)
            Temp6Free(&Temp6Table[i]);
    }
    Temp6Mask[netif->num] = 0;
}

/* Drops entries whose slot no longer holds their address (lwIP removed it at the end of its valid lifetime, or it
   was deleted) or holds it as a configured address (an administrator changed it) */
static
VOID
Temp6Prune(VOID)
{
    ULONG i;

    for (i = 0; i < TEMP6_MAX && Temp6Count; i++)
    {
        PTEMP6_ENTRY Entry = &Temp6Table[i];

        if (!Entry->Netif)
            continue;
        if (ip6_addr_isinvalid(netif_ip6_addr_state(Entry->Netif, Entry->Slot)) ||
            !ip6_addr_zoneless_eq(&Entry->Address, netif_ip6_addr(Entry->Netif, Entry->Slot)) ||
            (Addr6Count && TCP6AddressInfo(Entry->Netif, Entry->Slot, NULL)))
            Temp6Free(Entry);
    }
}

/* Whether Address is the local address of a TCP connection or listener */
static
BOOLEAN
Temp6InUse(const ip6_addr_t *Address)
{
    struct tcp_pcb *pcb;
    struct tcp_pcb_listen *lpcb;

    for (pcb = tcp_active_pcbs; pcb; pcb = pcb->next)
    {
        if (IP_IS_V6_VAL(pcb->local_ip) && ip6_addr_zoneless_eq(ip_2_ip6(&pcb->local_ip), Address))
            return TRUE;
    }
    for (pcb = tcp_bound_pcbs; pcb; pcb = pcb->next)
    {
        if (IP_IS_V6_VAL(pcb->local_ip) && ip6_addr_zoneless_eq(ip_2_ip6(&pcb->local_ip), Address))
            return TRUE;
    }
    for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb; lpcb = lpcb->next)
    {
        if (IP_IS_V6_VAL(lpcb->local_ip) && ip6_addr_zoneless_eq(ip_2_ip6(&lpcb->local_ip), Address))
            return TRUE;
    }
    return FALSE;
}

/* A free slot of netif (not slot 0, the link-local one), -1 if none; *Free: how many there are */
static
s8_t
Temp6FreeSlot(struct netif *netif, PULONG Free)
{
    s8_t i, First = -1;

    *Free = 0;
    for (i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)))
        {
            if (First < 0)
                First = i;
            (*Free)++;
        }
    }
    return First;
}

/* Makes room: the deprecated temporary address of netif with the least valid lifetime left that no TCP connection
   or listener uses goes. FALSE: there is none */
static
BOOLEAN
Temp6Evict(struct netif *netif)
{
    PTEMP6_ENTRY Best = NULL;
    u32_t BestLife = 0;
    ULONG i;

    for (i = 0; i < TEMP6_MAX; i++)
    {
        PTEMP6_ENTRY Entry = &Temp6Table[i];
        u32_t Life;

        if (Entry->Netif != netif || !ip6_addr_isdeprecated(netif_ip6_addr_state(netif, Entry->Slot)))
            continue;
        Life = netif_ip6_addr_valid_life(netif, Entry->Slot);
        if (Best && Life >= BestLife)
            continue;
        if (Temp6InUse(&Entry->Address))
            continue;
        Best = Entry;
        BestLife = Life;
    }
    if (!Best)
        return FALSE;

    {
        s8_t Slot = Best->Slot;

        Temp6Free(Best);
        netif_ip6_addr_set_valid_life(netif, Slot, 0);
        netif_ip6_addr_set_pref_life(netif, Slot, 0);
        netif_ip6_addr_set_state(netif, Slot, IP6_ADDR_INVALID);
    }
    return TRUE;
}

/* A random identifier for Prefix that is not reserved and that no address of netif has (Address, zoned). FALSE:
   none found (not in this universe) */
static
BOOLEAN
Temp6NewAddress(struct netif *netif, const ip6_addr_t *Prefix, ip6_addr_t *Address)
{
    ULONG Try;
    s8_t i;

    for (Try = 0; Try < 16; Try++)
    {
        UCHAR Iid[8];

        TCP6RandomIdentifier(Iid);
        if (TCP6ReservedIdentifier(Iid))
            continue;
        Address->addr[0] = Prefix->addr[0];
        Address->addr[1] = Prefix->addr[1];
        RtlCopyMemory(&Address->addr[2], Iid, 8);
        ip6_addr_clear_zone(Address);
        ip6_addr_assign_zone(Address, IP6_UNICAST, netif);
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)) &&
                ip6_addr_zoneless_eq(netif_ip6_addr(netif, i), Address))
                break;
        }
        if (i == LWIP_IPV6_NUM_ADDRESSES)
            return TRUE;
    }
    return FALSE;
}

static
ULONG
Temp6Min(ULONG a, ULONG b)
{
    return a < b ? a : b;
}

/* The lifetimes a temporary address made at Created may have now, given the public address's (RFC 8981 3.4) */
static
VOID
Temp6Lifetimes(ULONG Created, u32_t PublicValid, u32_t PublicPreferred, u32_t *Valid, u32_t *Preferred)
{
    ULONG Age = Temp6Ticks - Created;
    ULONG MaxPreferred = TCP6TempMaxPreferred - TCP6TempDesync;

    *Valid = Temp6Min(PublicValid, TCP6TempMaxValid > Age ? TCP6TempMaxValid - Age : 0);
    *Preferred = Temp6Min(PublicPreferred, MaxPreferred > Age ? MaxPreferred - Age : 0);
    if (*Preferred > *Valid)
        *Preferred = *Valid;
}

/* A new temporary address for the prefix of the public address in slot Public. FALSE: none made */
static
BOOLEAN
Temp6Create(struct netif *netif, s8_t Public)
{
    PTEMP6_ENTRY Entry = NULL;
    ip6_addr_t Address;
    u32_t Valid, Preferred;
    ULONG Free, i;
    s8_t Slot;

    Temp6Lifetimes(Temp6Ticks, netif_ip6_addr_valid_life(netif, Public), netif_ip6_addr_pref_life(netif, Public),
                   &Valid, &Preferred);
    /* RFC 8981 3.4 step 6: not worth it when it would be deprecated before a successor could be made */
    if (Preferred <= TCP6TempRegenerate || Valid < 2)
        return FALSE;

    /* one slot stays free for the stable address of a new prefix while a deprecated temporary address can give way */
    Slot = Temp6FreeSlot(netif, &Free);
    if (Free < 2 && Temp6Evict(netif))
        Slot = Temp6FreeSlot(netif, &Free);
    if (Slot < 0)
    {
        if (!Temp6NoSlotLogged)
            DbgPrint("TCPIP: no IPv6 address slot for a temporary address on interface %u\n", (UINT)netif->num);
        Temp6NoSlotLogged = TRUE;
        return FALSE;
    }

    for (i = 0; i < TEMP6_MAX && Temp6Table[i].Netif; i++)
        ;
    if (i == TEMP6_MAX)
        return FALSE;
    Entry = &Temp6Table[i];

    if (!Temp6NewAddress(netif, netif_ip6_addr(netif, Public), &Address))
        return FALSE;

    Entry->Netif = netif;
    Entry->Slot = Slot;
    Entry->Retries = 0;
    Entry->Address = Address;
    Entry->Created = Temp6Ticks;
    Temp6Count++;
    Temp6Mask[netif->num] |= (UCHAR)(1 << Slot);

    netif_ip6_addr_set(netif, Slot, &Address);
    netif_ip6_addr_set_valid_life(netif, Slot, Valid);
    netif_ip6_addr_set_pref_life(netif, Slot, Preferred);
    /* DAD from the next ND timer tick; the interface event tells user mode */
    netif_ip6_addr_set_state(netif, Slot, IP6_ADDR_TENTATIVE);
    Temp6NoSlotLogged = FALSE;
    return TRUE;
}

/* Whether slot i of netif holds a public address that stateless autoconfiguration formed for a prefix (not the
   link-local one, not configured, not temporary) */
static
BOOLEAN
Temp6IsPublic(struct netif *netif, s8_t i)
{
    const ip6_addr_t *Address = netif_ip6_addr(netif, i);

    return i > 0 && !ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)) && !netif_ip6_addr_isstatic(netif, i) &&
           !ip6_addr_islinklocal(Address) && !TCP6AddressInfo(netif, i, NULL) && !TCP6TemporarySlot(netif, i);
}

/* One prefix (the public address in slot Public): lifetimes of its temporary addresses, and a new one when none of
   them is tentative or preferred for longer than RegenerateTime */
static
VOID
Temp6DoPrefix(struct netif *netif, s8_t Public)
{
    const ip6_addr_t *Prefix = netif_ip6_addr(netif, Public);
    u8_t PublicState = netif_ip6_addr_state(netif, Public);
    u32_t PublicValid = netif_ip6_addr_valid_life(netif, Public), PublicPreferred = netif_ip6_addr_pref_life(netif, Public);
    BOOLEAN Current = FALSE;
    ULONG i;

    /* a duplicated public address is no prefix of ours: its temporary addresses run down on their own lifetimes */
    if (ip6_addr_isduplicated(PublicState))
        return;
    /* a deprecated one (what the router said): its temporary addresses follow (below) */
    if (ip6_addr_isdeprecated(PublicState))
        PublicPreferred = 0;

    for (i = 0; i < TEMP6_MAX; i++)
    {
        PTEMP6_ENTRY Entry = &Temp6Table[i];
        u8_t State;
        u32_t Valid, Preferred;

        if (Entry->Netif != netif || !ip6_addr_net_zoneless_eq(&Entry->Address, Prefix))
            continue;
        State = netif_ip6_addr_state(netif, Entry->Slot);

        /* a duplicated one stops new ones for the prefix until it goes (RFC 8981 3.4) */
        if (ip6_addr_isduplicated(State))
        {
            Current = TRUE;
            continue;
        }

        Temp6Lifetimes(Entry->Created, PublicValid, PublicPreferred, &Valid, &Preferred);
        /* never 0 (lwIP's "static"): lwIP removes it at its next tick */
        if (Valid == 0)
            Valid = 1;
        netif_ip6_addr_set_valid_life(netif, Entry->Slot, Valid);
        netif_ip6_addr_set_pref_life(netif, Entry->Slot, Preferred);
        if (ip6_addr_ispreferred(State) && Preferred == 0)
            netif_ip6_addr_set_state(netif, Entry->Slot, IP6_ADDR_DEPRECATED);
        else if (ip6_addr_isdeprecated(State) && Preferred > 0)
            netif_ip6_addr_set_state(netif, Entry->Slot, IP6_ADDR_PREFERRED);

        if (ip6_addr_istentative(State) || (Preferred > TCP6TempRegenerate))
            Current = TRUE;
    }

    if (!Current && !ip6_addr_isdeprecated(PublicState) && PublicPreferred > TCP6TempRegenerate)
        Temp6Create(netif, Public);
}

/* Part of LWIP_HOOK_ND6_TMR (once a second, after lwIP counted the lifetimes down) */
void
LibNd6TemporaryTimer(void)
{
    struct netif *netif;
    s8_t i;

    if (!TCP6UseTemporaryAddresses || !TCPIpv6Enabled)
        return;
    Temp6Ticks++;
    if (Temp6Count)
        Temp6Prune();

    NETIF_FOREACH(netif)
    {
        if (!netif->ip6_autoconfig_enabled || netif->hwaddr_len != 6)
            continue;
        for (i = 1; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (Temp6IsPublic(netif, i))
                Temp6DoPrefix(netif, i);
        }
    }
}

/* LWIP_HOOK_ND6_DAD_FAILED for a temporary address (iid6.c asks first). TRUE: it was one, *Result is the hook's
   answer: 1 = a new random identifier, DAD starts again; 0 = no new identifier left, lwIP marks it duplicated */
BOOLEAN
TCP6TemporaryDadFailed(struct netif *netif, s8_t Index, int *Result)
{
    PTEMP6_ENTRY Entry;
    ip6_addr_t Address, Prefix;

    if (!Temp6Count)
        return FALSE;
    Entry = Temp6Find(netif, Index);
    if (!Entry)
        return FALSE;

    *Result = 0;
    if (!ip6_addr_istentative(netif_ip6_addr_state(netif, Index)))
        return TRUE;
    if (Entry->Retries >= TCP6TempMaxDad)
    {
        DbgPrint("TCPIP: IPv6 temporary address %d of interface %u is a duplicate after %u new identifiers: no more "
                 "temporary addresses for its prefix while it lasts\n", (int)Index, (UINT)netif->num,
                 (UINT)TCP6TempMaxDad);
        return TRUE;
    }
    IP6_ADDR(&Prefix, Entry->Address.addr[0], Entry->Address.addr[1], 0, 0);
    if (!Temp6NewAddress(netif, &Prefix, &Address))
        return TRUE;

    Entry->Retries++;
    DbgPrint("TCPIP: IPv6 temporary address %d of interface %u is a duplicate, new identifier (%u)\n", (int)Index,
             (UINT)netif->num, (UINT)Entry->Retries);
    /* as in iid6.c: the state first (MLD leaves the old address's group), then the address */
    netif_ip6_addr_set_state(netif, Index, IP6_ADDR_TENTATIVE);
    netif_ip6_addr_set(netif, Index, &Address);
    Entry->Address = Address;
    *Result = 1;
    return TRUE;
}

/* For the self-test (selftest6.c): the temporary address in Slot is made Seconds older (its lifetimes follow at the
   next timer tick). FALSE: the slot holds none */
BOOLEAN
TCP6TemporaryAge(struct netif *netif, signed char Slot, ULONG Seconds)
{
    PTEMP6_ENTRY Entry = Temp6Count ? Temp6Find(netif, Slot) : NULL;

    if (!Entry)
        return FALSE;
    Entry->Created -= Seconds;
    return TRUE;
}
