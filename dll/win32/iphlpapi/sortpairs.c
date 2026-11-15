/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateSortedAddressPairs: the environment of the address ordering (addrsort.c) from the stack
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include "addrsort.h"
#include <wine/netioapi.h>

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

#define TCP6_PARAMETERS_KEY     L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
#define PREFIX_POLICIES_VALUE   L"PrefixPolicies"
#define MAX_SORT_ADDRESSES      0x10000

/*
 * The prefix policy table is the Windows default one. HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters,
 * value PrefixPolicies (REG_MULTI_SZ, one "prefix/length precedence label" per string, e.g. "fc00::/7 3 13")
 * replaces the whole table when it holds at least one valid line; netsh can write it. Windows keeps its table in
 * the NSI store, which is not documented, so there is no Windows location to follow. It is read on every call
 * (a few microseconds), so a change applies to the next sort.
 */
static
VOID
LoadPolicy(PADDRSORT_POLICY_TABLE Table)
{
    HKEY Key;
    WCHAR Buffer[2048];
    DWORD Type, Size = sizeof(Buffer) - sizeof(WCHAR);

    AddrSortDefaultPolicy(Table);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TCP6_PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return;
    if (RegQueryValueExW(Key, PREFIX_POLICIES_VALUE, NULL, &Type, (LPBYTE)Buffer, &Size) == ERROR_SUCCESS &&
        Type == REG_MULTI_SZ)
    {
        Buffer[Size / sizeof(WCHAR)] = 0;
        AddrSortParsePolicy(Buffer, Size / sizeof(WCHAR) + 1, Table);
    }
    RegCloseKey(Key);
}

typedef struct _SORT_CONTEXT
{
    const ADDRSORT_LOCAL *Local;
    ULONG LocalCount;
} SORT_CONTEXT;

static
BOOL
RouteLookup(PVOID Context, const UCHAR *Dest, ULONG Scope, ULONG *IfIndex)
{
    SORT_CONTEXT *Ctx = Context;
    SOCKADDR_INET Destination, Source;
    MIB_IPFORWARD_ROW2 Route;
    ULONG i;
    static const UCHAR MappedPrefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    memset(&Destination, 0, sizeof(Destination));
    if (!memcmp(Dest, MappedPrefix, sizeof(MappedPrefix)))
    {
        Destination.Ipv4.sin_family = AF_INET;
        memcpy(&Destination.Ipv4.sin_addr, Dest + 12, 4);
    }
    else
    {
        Destination.Ipv6.sin6_family = AF_INET6;
        memcpy(&Destination.Ipv6.sin6_addr, Dest, 16);
        Destination.Ipv6.sin6_scope_id = Scope;
    }

    memset(&Route, 0, sizeof(Route));
    memset(&Source, 0, sizeof(Source));
    if (GetBestRoute2(NULL, 0, NULL, &Destination, 0, &Route, &Source) != NO_ERROR)
        return FALSE;
    *IfIndex = Route.InterfaceIndex;

    /* a route row without an interface (multicast): the interface of the source address */
    if (!*IfIndex)
    {
        UCHAR Wanted[16];

        if (Source.si_family == AF_INET6)
            memcpy(Wanted, &Source.Ipv6.sin6_addr, 16);
        else
        {
            memcpy(Wanted, MappedPrefix, sizeof(MappedPrefix));
            memcpy(Wanted + 12, &Source.Ipv4.sin_addr, 4);
        }
        for (i = 0; i < Ctx->LocalCount; i++)
            if (!memcmp(Ctx->Local[i].Address, Wanted, 16))
            {
                *IfIndex = Ctx->Local[i].IfIndex;
                break;
            }
        if (!*IfIndex)
            return FALSE;
    }
    return TRUE;
}

static
PADDRSORT_LOCAL
CollectLocal(PULONG Count)
{
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;
    PADDRSORT_LOCAL Local;
    ULONG i, Used = 0;

    *Count = 0;
    if (GetUnicastIpAddressTable(AF_UNSPEC, &Table) != NO_ERROR || !Table)
        return NULL;
    Local = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Table->NumEntries + 1) * sizeof(*Local));
    if (!Local)
    {
        FreeMibTable(Table);
        return NULL;
    }

    for (i = 0; i < Table->NumEntries; i++)
    {
        const MIB_UNICASTIPADDRESS_ROW *Row = &Table->Table[i];
        PADDRSORT_LOCAL L = &Local[Used];

        /* NL_DAD_STATE: 3 deprecated, 4 preferred; tentative and duplicate addresses are no source */
        if (Row->DadState != 3 && Row->DadState != 4)
            continue;
        if (Row->Address.si_family == AF_INET6)
            memcpy(L->Address, &Row->Address.Ipv6.sin6_addr, 16);
        else if (Row->Address.si_family == AF_INET)
        {
            L->Address[10] = L->Address[11] = 0xff;
            memcpy(L->Address + 12, &Row->Address.Ipv4.sin_addr, 4);
        }
        else
            continue;
        L->IfIndex = Row->InterfaceIndex;
        L->Deprecated = Row->DadState == 3 || Row->PreferredLifetime == 0;
        /* NL_SUFFIX_ORIGIN_RANDOM: the temporary (privacy) addresses */
        L->Temporary = Row->SuffixOrigin == 5;
        L->Loopback = (Row->Address.si_family == AF_INET6) ?
                      (L->Address[15] == 1 && !memcmp(L->Address, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 15)) :
                      (L->Address[12] == 127);
        Used++;
    }
    FreeMibTable(Table);
    *Count = Used;
    return Local;
}

/*
 * CreateSortedAddressPairs (IPHLPAPI.@)
 *
 * The destinations in the order a connection should try them, each with the source address it would use
 * (RFC 6724 with the Windows prefix policy table). IPv4 destinations are given as IPv4-mapped IPv6 addresses.
 * The destination list is the only one that is accepted: a source list is rejected with ERROR_INVALID_PARAMETER
 * (the Windows 10 oracle does the same, also for a list of one address). A destination that cannot be reached
 * (no route, no source address of its kind) is left out, as on Windows, unless none can be reached: then all come
 * back as given. The result is one block: the pairs, then the addresses they point to; FreeMibTable frees it.
 */
DWORD WINAPI
CreateSortedAddressPairs(const PSOCKADDR_IN6 SourceAddressList,
                         ULONG SourceAddressCount,
                         const PSOCKADDR_IN6 DestinationAddressList,
                         ULONG DestinationAddressCount,
                         ULONG AddressSortOptions,
                         PSOCKADDR_IN6_PAIR *SortedAddressPairList,
                         ULONG *SortedAddressPairCount)
{
    ADDRSORT_POLICY_TABLE Policy;
    ADDRSORT_ENV Env;
    SORT_CONTEXT Context;
    PADDRSORT_ENTRY Entries;
    PADDRSORT_LOCAL Local;
    PSOCKADDR_IN6_PAIR Pairs;
    PSOCKADDR_IN6 Addresses;
    ULONG LocalCount, i, Out, Reachable = 0;

    TRACE("(%p, %lu, %p, %lu, 0x%lx, %p, %p)\n", SourceAddressList, SourceAddressCount, DestinationAddressList,
          DestinationAddressCount, AddressSortOptions, SortedAddressPairList, SortedAddressPairCount);

    /* the outputs are not touched when the arguments are rejected (the Wine test, which Windows passes) */
    if (SourceAddressList || SourceAddressCount || !DestinationAddressList || !DestinationAddressCount ||
        DestinationAddressCount > MAX_SORT_ADDRESSES || AddressSortOptions || !SortedAddressPairList ||
        !SortedAddressPairCount)
        return ERROR_INVALID_PARAMETER;
    for (i = 0; i < DestinationAddressCount; i++)
        if (DestinationAddressList[i].sin6_family != AF_INET6)
            return ERROR_INVALID_PARAMETER;

    Entries = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DestinationAddressCount * sizeof(*Entries));
    if (!Entries)
        return ERROR_NOT_ENOUGH_MEMORY;
    Local = CollectLocal(&LocalCount);

    LoadPolicy(&Policy);
    Context.Local = Local;
    Context.LocalCount = LocalCount;
    Env.Policy = &Policy;
    Env.Local = Local;
    Env.LocalCount = LocalCount;
    Env.Route = RouteLookup;
    Env.Context = &Context;

    for (i = 0; i < DestinationAddressCount; i++)
    {
        memcpy(Entries[i].Address, &DestinationAddressList[i].sin6_addr, 16);
        Entries[i].Scope = DestinationAddressList[i].sin6_scope_id;
    }
    AddrSortOrder(&Env, Entries, DestinationAddressCount);
    HeapFree(GetProcessHeap(), 0, Local);

    for (i = 0; i < DestinationAddressCount; i++)
        if (Entries[i].Reachable)
            Reachable++;

    /*
     * Nothing can be reached (no network at all): the destinations come back in the order they were given, each
     * with the unspecified address as its source, so that the caller finds a list and its own connect fails with
     * the real error. The Windows 10 oracle was only asked with reachable destinations among them.
     */
    Out = Reachable ? Reachable : DestinationAddressCount;
    Pairs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Out * (sizeof(*Pairs) + 2 * sizeof(SOCKADDR_IN6)));
    if (!Pairs)
    {
        HeapFree(GetProcessHeap(), 0, Entries);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    Addresses = (PSOCKADDR_IN6)(Pairs + Out);
    for (i = 0; i < Out; i++)
    {
        /* the reachable ones come first */
        const ADDRSORT_ENTRY *E = &Entries[i];
        PSOCKADDR_IN6 Source = &Addresses[i * 2], Dest = &Addresses[i * 2 + 1];

        *Dest = DestinationAddressList[E->Original];
        Source->sin6_family = AF_INET6;
        memcpy(&Source->sin6_addr, E->Source, 16);
        Source->sin6_scope_id = E->SourceScope;
        Pairs[i].SourceAddress = Source;
        Pairs[i].DestinationAddress = Dest;
    }
    *SortedAddressPairList = Pairs;
    *SortedAddressPairCount = Out;

    HeapFree(GetProcessHeap(), 0, Entries);
    return NO_ERROR;
}
