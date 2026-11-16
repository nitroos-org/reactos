/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IPv6 source address selection (RFC 6724 section 5) with the prefix policy table
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Every source address lwIP chooses (TCP connect, UDP datagrams connected or not, echo requests, ICMPv6 errors)
 * comes from ip6_select_source_address, which the NitroOS hook LWIP_HOOK_IP6_SELECT_SOURCE sends here. The rules
 * themselves are AddrSortSelectSource of sdk/lib/addrsel, the same function iphlpapi's GetBestRoute2 and
 * CreateSortedAddressPairs (and through them getaddrinfo) use, with the same prefix policy table: rules 1, 2, 3, 6
 * (label), 7 (temporary addresses, temp6.c) and 8 (longest matching prefix up to the /64 of the source), and no
 * link-local source for a unicast destination beyond the link.
 *
 * The table: Tcpip6\Parameters\PrefixPolicies (and its ActiveState subkey, DisabledComponents 0x20, Tcpip\Parameters\
 * Ipv6Enable = 0), as user mode
 * reads it (addrsel.h); read at start and on IOCTL_IP6_POLICY_RELOAD, which NitroSetPrefixPolicies sends after
 * each change. Without a value the Windows default table. Selection runs under lwIP's core lock, which also guards
 * the table.
 */

#include "precomp.h"

#include "lwip/ip.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include <lwip_hooks.h>
#include <addrsel.h>

#define POLICY6_TAG         'lP6T'
#define POLICY6_PARAMETERS  L"\\Registry\\Machine\\" ADDRSEL_PARAMETERS_KEY

/* the table in force (core lock); Count 0 until the first load: the defaults are put in on first use */
static ADDRSORT_POLICY_TABLE Policy6Table;

/* PrefixPolicies of Key into Table when it has at least one valid line */
static
VOID
Policy6ReadValue(HANDLE Key, PADDRSORT_POLICY_TABLE Table, PKEY_VALUE_PARTIAL_INFORMATION Info, ULONG InfoSize)
{
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(ADDRSEL_POLICY_VALUE);
    ULONG Length, Chars;
    PWCHAR Text;

    /* one WCHAR of the buffer stays free for the terminator put after the data */
    if (!NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, InfoSize - sizeof(WCHAR),
                                    &Length)) ||
        Info->Type != REG_MULTI_SZ)
        return;
    Text = (PWCHAR)Info->Data;
    Chars = Info->DataLength / sizeof(WCHAR);
    Text[Chars] = UNICODE_NULL;
    AddrSortParsePolicy(Text, Chars + 1, Table);
}

/* IOCTL_IP6_POLICY_RELOAD and the start (PASSIVE_LEVEL, no lock held) */
NTSTATUS
TCP6LoadPrefixPolicies(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(POLICY6_PARAMETERS);
    UNICODE_STRING ActiveName = RTL_CONSTANT_STRING(ADDRSEL_ACTIVE_STATE_KEY);
    UNICODE_STRING ComponentsName = RTL_CONSTANT_STRING(L"DisabledComponents");
    UNICODE_STRING SwitchKeyName =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters");
    UNICODE_STRING SwitchName = RTL_CONSTANT_STRING(L"Ipv6Enable");
    OBJECT_ATTRIBUTES Attributes;
    PADDRSORT_POLICY_TABLE Table;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG InfoSize, Length;
    HANDLE Key = NULL, Active = NULL;

    PAGED_CODE();

    InfoSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + ADDRSEL_POLICY_BUFFER_CHARS * sizeof(WCHAR);
    Table = ExAllocatePoolWithTag(PagedPool, sizeof(*Table), POLICY6_TAG);
    Info = ExAllocatePoolWithTag(PagedPool, InfoSize, POLICY6_TAG);
    if (!Table || !Info)
    {
        if (Table)
            ExFreePoolWithTag(Table, POLICY6_TAG);
        if (Info)
            ExFreePoolWithTag(Info, POLICY6_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AddrSortDefaultPolicy(Table);
    /* Tcpip\Parameters\Ipv6Enable = 0 (a REG_DWORD of 0) is DisabledComponents 0xFF, which includes 0x20: prefer
       IPv4, as user mode reads it (iphlpapi sortpairs.c) */
    InitializeObjectAttributes(&Attributes, &SwitchKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
    {
        if (NT_SUCCESS(ZwQueryValueKey(Key, &SwitchName, KeyValuePartialInformation, Info, InfoSize, &Length)) &&
            Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG) && *(PULONG)Info->Data == 0)
            AddrSortPreferIpv4(Table);
        ZwClose(Key);
        Key = NULL;
    }
    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
    {
        /* DisabledComponents bit 0x20: prefer IPv4 (a PrefixPolicies value below still replaces the whole table) */
        if (NT_SUCCESS(ZwQueryValueKey(Key, &ComponentsName, KeyValuePartialInformation, Info, InfoSize, &Length)) &&
            Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG) && (*(PULONG)Info->Data & 0x20))
            AddrSortPreferIpv4(Table);
        Policy6ReadValue(Key, Table, Info, InfoSize);
        /* the volatile table of "store=active" wins while it exists */
        InitializeObjectAttributes(&Attributes, &ActiveName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, Key, NULL);
        if (NT_SUCCESS(ZwOpenKey(&Active, KEY_QUERY_VALUE, &Attributes)))
        {
            Policy6ReadValue(Active, Table, Info, InfoSize);
            ZwClose(Active);
        }
        ZwClose(Key);
    }

    LOCK_TCPIP_CORE();
    RtlCopyMemory(&Policy6Table, Table, sizeof(Policy6Table));
    UNLOCK_TCPIP_CORE();

    ExFreePoolWithTag(Info, POLICY6_TAG);
    ExFreePoolWithTag(Table, POLICY6_TAG);
    return STATUS_SUCCESS;
}

/* LWIP_HOOK_IP6_SELECT_SOURCE (ip6.c, core lock held): the source address for dest over netif, NULL for none */
const ip_addr_t *
LibIp6SelectSource(struct netif *netif, const ip6_addr_t *dest)
{
    ADDRSEL_CANDIDATE Candidates[LWIP_IPV6_NUM_ADDRESSES];
    s8_t Slots[LWIP_IPV6_NUM_ADDRESSES];
    ULONG Count = 0;
    LONG Best;
    s8_t i;

    if (!Policy6Table.Count)
        AddrSortDefaultPolicy(&Policy6Table);

    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        u8_t State = netif_ip6_addr_state(netif, i);

        /* preferred and deprecated addresses; tentative and duplicate ones are no source */
        if (!ip6_addr_isvalid(State))
            continue;
        RtlCopyMemory(Candidates[Count].Address, netif_ip6_addr(netif, i)->addr, 16);
        Candidates[Count].Deprecated = ip6_addr_ispreferred(State) ? FALSE : TRUE;
        Candidates[Count].Temporary = LibIp6SourceTemporary(netif, i) ? TRUE : FALSE;
        Candidates[Count].SkipAsSource = LibIp6SkipSource(netif, i) ? TRUE : FALSE;
        Slots[Count++] = i;
    }

    /* lwIP keeps addresses in network byte order: the 16 bytes as on the wire, as the rules want them */
    Best = AddrSortSelectSource(&Policy6Table, Candidates, Count, (const UCHAR *)dest->addr);
    return Best < 0 ? NULL : netif_ip_addr6(netif, Slots[Best]);
}
