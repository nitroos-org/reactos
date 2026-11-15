/*
 * PROJECT:    ReactOS IF Monitor DLL
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    IPv6 context functions (netsh interface ipv6 show ...)
 * COPYRIGHT:  Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <ws2tcpip.h>
#include <wine/netioapi.h>
#include <guiddef.h>

#define NDEBUG
#include <debug.h>

#include "guid.h"
#include "resource.h"

/*
 * Only the show commands exist here. The add, set and delete commands need the configuration API of the stack
 * (CreateUnicastIpAddressEntry, CreateIpForwardEntry2 for IPv6): they get their own CMD_GROUP_ENTRY next to
 * Ipv6ShowCommands when that API is there, and nothing in this file has to change for them. The show commands
 * take the optional "interface=<name or index>" (and accept "level=" and "store=", which change nothing
 * about what the stack can tell).
 */

#define IPV6_PARAMETERS_KEY  L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
#define IPV6_INTERFACES_KEY  L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\"
#define INFINITE_LIFETIME    0xffffffff

static FN_HANDLE_CMD Ipv6ShowAddresses;
static FN_HANDLE_CMD Ipv6ShowInterfaces;
static FN_HANDLE_CMD Ipv6ShowRoute;
static FN_HANDLE_CMD Ipv6ShowNeighbors;
static FN_HANDLE_CMD Ipv6ShowDnsServers;
static FN_HANDLE_CMD Ipv6ShowJoins;
static FN_HANDLE_CMD Ipv6ShowDestinationCache;
static FN_HANDLE_CMD Ipv6ShowGlobal;
static FN_HANDLE_CMD Ipv6ShowPrivacy;
static FN_HANDLE_CMD Ipv6ShowPrefixPolicies;

static
CMD_ENTRY
Ipv6ShowCommands[] =
{
    {L"addresses", Ipv6ShowAddresses, IDS_HLP_IPV6_SHOW_ADDRESSES, IDS_HLP_IPV6_SHOW_ADDRESSES_EX, 0},
    {L"destinationcache", Ipv6ShowDestinationCache, IDS_HLP_IPV6_SHOW_DESTINATIONCACHE, IDS_HLP_IPV6_SHOW_DESTINATIONCACHE_EX, 0},
    {L"dnsservers", Ipv6ShowDnsServers, IDS_HLP_IPV6_SHOW_DNSSERVERS, IDS_HLP_IPV6_SHOW_DNSSERVERS_EX, 0},
    {L"global", Ipv6ShowGlobal, IDS_HLP_IPV6_SHOW_GLOBAL, IDS_HLP_IPV6_SHOW_GLOBAL_EX, 0},
    {L"interfaces", Ipv6ShowInterfaces, IDS_HLP_IPV6_SHOW_INTERFACES, IDS_HLP_IPV6_SHOW_INTERFACES_EX, 0},
    {L"joins", Ipv6ShowJoins, IDS_HLP_IPV6_SHOW_JOINS, IDS_HLP_IPV6_SHOW_JOINS_EX, 0},
    {L"neighbors", Ipv6ShowNeighbors, IDS_HLP_IPV6_SHOW_NEIGHBORS, IDS_HLP_IPV6_SHOW_NEIGHBORS_EX, 0},
    {L"prefixpolicies", Ipv6ShowPrefixPolicies, IDS_HLP_IPV6_SHOW_PREFIXPOLICIES, IDS_HLP_IPV6_SHOW_PREFIXPOLICIES_EX, 0},
    {L"privacy", Ipv6ShowPrivacy, IDS_HLP_IPV6_SHOW_PRIVACY, IDS_HLP_IPV6_SHOW_PRIVACY_EX, 0},
    {L"route", Ipv6ShowRoute, IDS_HLP_IPV6_SHOW_ROUTE, IDS_HLP_IPV6_SHOW_ROUTE_EX, 0},
};

static
CMD_GROUP_ENTRY
Ipv6Groups[] =
{
    {L"show", IDS_HLP_IPV6_SHOW, sizeof(Ipv6ShowCommands) / sizeof(CMD_ENTRY), 0, Ipv6ShowCommands, NULL},
};


/* Stack queries ************************************************************/

typedef struct _IPV6_IF
{
    ULONG Index;
    ULONG Metric;
    ULONG Mtu;
    BOOLEAN Connected;
    WCHAR Name[IF_MAX_STRING_SIZE + 1];
} IPV6_IF, *PIPV6_IF;

static
int
CompareInterfaces(
    const void *p1,
    const void *p2)
{
    const IPV6_IF *i1 = p1, *i2 = p2;

    if (i1->Index == i2->Index)
        return 0;
    return (i1->Index < i2->Index) ? -1 : 1;
}

/*
 * The interfaces that have IPv6 (the interface table of the family), ascending by index. With IPv6 off the table
 * is empty: every command then prints nothing, as for a system without IPv6.
 */
static
DWORD
LoadInterfaces(
    _Out_ PIPV6_IF *ppList,
    _Out_ PULONG pCount)
{
    PMIB_IPINTERFACE_TABLE Table = NULL;
    PIPV6_IF List = NULL;
    ULONG i;

    *ppList = NULL;
    *pCount = 0;

    if (GetIpInterfaceTable(AF_INET6, &Table) != NO_ERROR || Table == NULL)
        return ERROR_SUCCESS;

    if (Table->NumEntries != 0)
    {
        List = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Table->NumEntries * sizeof(IPV6_IF));
        if (List == NULL)
        {
            FreeMibTable(Table);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    for (i = 0; i < Table->NumEntries; i++)
    {
        MIB_IF_ROW2 IfRow;

        List[i].Index = Table->Table[i].InterfaceIndex;
        List[i].Metric = Table->Table[i].Metric;
        List[i].Mtu = Table->Table[i].NlMtu;
        List[i].Connected = Table->Table[i].Connected;

        ZeroMemory(&IfRow, sizeof(IfRow));
        IfRow.InterfaceIndex = Table->Table[i].InterfaceIndex;
        if (GetIfEntry2(&IfRow) == NO_ERROR && IfRow.Alias[0] != UNICODE_NULL)
            StringCchCopyW(List[i].Name, ARRAYSIZE(List[i].Name), IfRow.Alias);
        else
            StringCchPrintfW(List[i].Name, ARRAYSIZE(List[i].Name), L"Interface %lu", List[i].Index);
    }

    *pCount = Table->NumEntries;
    FreeMibTable(Table);
    qsort(List, *pCount, sizeof(IPV6_IF), CompareInterfaces);
    *ppList = List;
    return ERROR_SUCCESS;
}

static
VOID
FreeInterfaces(
    _In_opt_ PIPV6_IF List)
{
    if (List)
        HeapFree(GetProcessHeap(), 0, List);
}

static
PIPV6_IF
FindInterface(
    _In_ PIPV6_IF List,
    _In_ ULONG Count,
    _In_ ULONG Index)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        if (List[i].Index == Index)
            return &List[i];
    }
    return NULL;
}

/* "interface=<name or index>", "level=" and "store=" (ignored), or a bare interface name or index */
static
DWORD
ParseShowArguments(
    _In_ LPWSTR *argv,
    _In_ DWORD dwCurrentIndex,
    _In_ DWORD dwArgCount,
    _Out_ PCWSTR *ppInterface)
{
    DWORD i;
    PCWSTR Eq;
    SIZE_T Length;

    *ppInterface = NULL;
    for (i = dwCurrentIndex; i < dwArgCount; i++)
    {
        Eq = wcschr(argv[i], L'=');
        if (Eq == NULL)
        {
            if (*ppInterface != NULL)
                return ERROR_INVALID_SYNTAX;
            *ppInterface = argv[i];
            continue;
        }

        Length = Eq - argv[i];
        if (Length == 9 && _wcsnicmp(argv[i], L"interface", 9) == 0)
            *ppInterface = Eq + 1;
        else if (!((Length == 5 && _wcsnicmp(argv[i], L"level", 5) == 0) ||
                   (Length == 5 && _wcsnicmp(argv[i], L"store", 5) == 0)))
            return ERROR_INVALID_SYNTAX;
    }
    return ERROR_SUCCESS;
}

/* Does the interface pass the filter? A filter that is a number selects the index, else it is the name. */
static
BOOL
MatchesFilter(
    _In_ const IPV6_IF *If,
    _In_opt_ PCWSTR Filter)
{
    PWSTR End;
    ULONG Value;

    if (Filter == NULL || *Filter == UNICODE_NULL)
        return TRUE;

    Value = wcstoul(Filter, &End, 10);
    if (*End == UNICODE_NULL)
        return Value == If->Index;
    return _wcsicmp(Filter, If->Name) == 0;
}

static
BOOL
FilterMatchesAny(
    _In_ PIPV6_IF List,
    _In_ ULONG Count,
    _In_opt_ PCWSTR Filter)
{
    ULONG i;

    if (Filter == NULL || *Filter == UNICODE_NULL)
        return TRUE;

    for (i = 0; i < Count; i++)
    {
        if (MatchesFilter(&List[i], Filter))
            return TRUE;
    }
    return FALSE;
}

static
VOID
FormatAddress(
    _Out_writes_(64) PWSTR Buffer,
    _In_ const IN6_ADDR *Address)
{
    RtlIpv6AddressToStringW(Address, Buffer);
}

static
SIZE_T
FormatUnit(
    _Out_writes_(Size) PWSTR Buffer,
    _In_ SIZE_T Size,
    _In_ PCWSTR Format,
    _In_ ULONG Value)
{
    if (FAILED(StringCchPrintfW(Buffer, Size, Format, Value)))
    {
        Buffer[0] = UNICODE_NULL;
        return 0;
    }
    return wcslen(Buffer);
}

/* 7d, 23h59m58s, 5s, 0s: the units that are zero are left out */
static
VOID
FormatDuration(
    _Out_writes_(32) PWSTR Buffer,
    _In_ ULONG Seconds)
{
    ULONG Days, Hours, Minutes;
    SIZE_T Used = 0;

    if (Seconds == INFINITE_LIFETIME)
    {
        wcscpy(Buffer, L"infinite");
        return;
    }

    Days = Seconds / 86400;
    Hours = (Seconds % 86400) / 3600;
    Minutes = (Seconds % 3600) / 60;
    Seconds %= 60;

    Buffer[0] = UNICODE_NULL;
    if (Days)
        Used += FormatUnit(Buffer + Used, 32 - Used, L"%lud", Days);
    if (Hours)
        Used += FormatUnit(Buffer + Used, 32 - Used, L"%luh", Hours);
    if (Minutes)
        Used += FormatUnit(Buffer + Used, 32 - Used, L"%lum", Minutes);
    if (Seconds || Used == 0)
        FormatUnit(Buffer + Used, 32 - Used, L"%lus", Seconds);
}

static
BOOL
IsLoopbackAddress(
    _In_ const IN6_ADDR *Address)
{
    static const UCHAR Loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    return memcmp(Address, Loopback, sizeof(Loopback)) == 0;
}

static
BOOL
IsUnspecified(
    _In_ const IN6_ADDR *Address)
{
    static const IN6_ADDR Zero = {{{0}}};

    return memcmp(Address, &Zero, sizeof(Zero)) == 0;
}


/* show addresses ***********************************************************/

static
PCWSTR
AddressType(
    _In_ const MIB_UNICASTIPADDRESS_ROW *Row)
{
    const IN6_ADDR *Address = &Row->Address.Ipv6.sin6_addr;

    if (Row->PrefixOrigin == IpPrefixOriginManual)
        return L"Manual";
    if (Row->PrefixOrigin == IpPrefixOriginDhcp)
        return L"Dhcp";
    if (Address->u.Byte[0] == 0xfe && (Address->u.Byte[1] & 0xc0) == 0x80)
        return L"Other";
    if (Row->PrefixOrigin == IpPrefixOriginWellKnown || Row->PrefixOrigin == IpPrefixOriginOther)
        return L"Other";
    return L"Public";
}

static
PCWSTR
DadStateName(
    _In_ NL_DAD_STATE State)
{
    switch (State)
    {
        case IpDadStateTentative:  return L"Tentative";
        case IpDadStateDuplicate:  return L"Duplicate";
        case IpDadStateDeprecated: return L"Deprecated";
        case IpDadStatePreferred:  return L"Preferred";
        default:                   return L"Invalid";
    }
}

static
DWORD
WINAPI
Ipv6ShowAddresses(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;
    PCWSTR Filter;
    ULONG Count, i, j;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    if (GetUnicastIpAddressTable(AF_INET6, &Table) != NO_ERROR)
        Table = NULL;

    for (i = 0; i < Count; i++)
    {
        BOOL Header = FALSE;

        if (!MatchesFilter(&List[i], Filter) || Table == NULL)
            continue;

        for (j = 0; j < Table->NumEntries; j++)
        {
            const MIB_UNICASTIPADDRESS_ROW *Row = &Table->Table[j];
            WCHAR Address[80], Valid[32], Preferred[32];
            SIZE_T Length;

            if (Row->InterfaceIndex != List[i].Index || Row->Address.si_family != AF_INET6)
                continue;

            if (!Header)
            {
                PrintMessage(L"\nInterface %lu: %s\n\n", List[i].Index, List[i].Name);
                PrintMessage(L"Addr Type  DAD State   Valid Life Pref. Life Address\n");
                PrintMessage(L"---------  ----------- ---------- ---------- ------------------------\n");
                Header = TRUE;
            }

            FormatAddress(Address, &Row->Address.Ipv6.sin6_addr);
            Length = wcslen(Address);
            if (Row->Address.Ipv6.sin6_scope_id != 0)
                StringCchPrintfW(Address + Length, ARRAYSIZE(Address) - Length, L"%%%lu", (ULONG)Row->Address.Ipv6.sin6_scope_id);
            FormatDuration(Valid, Row->ValidLifetime);
            FormatDuration(Preferred, Row->PreferredLifetime);

            PrintMessage(L"%-9s  %-11s %10s %10s %s\n",
                         AddressType(Row), DadStateName(Row->DadState), Valid, Preferred, Address);
        }

        if (Header)
            PrintMessage(L"\n");
    }

    if (Table)
        FreeMibTable(Table);
    FreeInterfaces(List);
    return ERROR_SUCCESS;
}


/* show interfaces **********************************************************/

static
DWORD
WINAPI
Ipv6ShowInterfaces(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PCWSTR Filter;
    ULONG Count, i;
    BOOL Header = FALSE;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < Count; i++)
    {
        if (!MatchesFilter(&List[i], Filter))
            continue;

        if (!Header)
        {
            PrintMessage(L"\nIdx     Met         MTU          State                Name\n");
            PrintMessage(L"---  ----------  ----------  ------------  ---------------------------\n");
            Header = TRUE;
        }

        PrintMessage(L"%3lu  %10lu  %10lu  %-12s  %s\n",
                     List[i].Index, List[i].Metric, List[i].Mtu,
                     List[i].Connected ? L"connected" : L"disconnected", List[i].Name);
    }

    if (Header)
        PrintMessage(L"\n");

    FreeInterfaces(List);
    return ERROR_SUCCESS;
}


/* show route ***************************************************************/

static
PCWSTR
RouteType(
    _In_ const MIB_IPFORWARD_ROW2 *Row)
{
    /* the stack's own routes (connected prefixes, multicast) are protocol "local": Windows lists those as System,
       and only what a management tool added as Manual */
    switch (Row->Origin)
    {
        case NlroManual:    return (Row->Protocol == 2 /* MIB_IPPROTO_LOCAL */) ? L"System" : L"Manual";
        case NlroDHCP:      return L"Dhcp";
        case NlroRouterAdvertisement: return L"Autoconf";
        default:            return L"System";
    }
}

static
int
CompareRoutes(
    const void *p1,
    const void *p2)
{
    const MIB_IPFORWARD_ROW2 *r1 = *(const MIB_IPFORWARD_ROW2 **)p1;
    const MIB_IPFORWARD_ROW2 *r2 = *(const MIB_IPFORWARD_ROW2 **)p2;
    int Cmp;

    Cmp = memcmp(&r1->DestinationPrefix.Prefix.Ipv6.sin6_addr,
                 &r2->DestinationPrefix.Prefix.Ipv6.sin6_addr, sizeof(IN6_ADDR));
    if (Cmp != 0)
        return Cmp;
    if (r1->DestinationPrefix.PrefixLength != r2->DestinationPrefix.PrefixLength)
        return (r1->DestinationPrefix.PrefixLength < r2->DestinationPrefix.PrefixLength) ? -1 : 1;
    if (r1->InterfaceIndex != r2->InterfaceIndex)
        return (r1->InterfaceIndex < r2->InterfaceIndex) ? -1 : 1;
    return 0;
}

static
DWORD
WINAPI
Ipv6ShowRoute(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PMIB_IPFORWARD_TABLE2 Table = NULL;
    const MIB_IPFORWARD_ROW2 **Rows = NULL;
    PCWSTR Filter;
    ULONG Count, RowCount = 0, i;
    BOOL Header = FALSE;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    if (Count != 0 && GetIpForwardTable2(AF_INET6, &Table) == NO_ERROR && Table != NULL && Table->NumEntries != 0)
        Rows = HeapAlloc(GetProcessHeap(), 0, Table->NumEntries * sizeof(PVOID));

    if (Rows != NULL)
    {
        for (i = 0; i < Table->NumEntries; i++)
        {
            PIPV6_IF If = FindInterface(List, Count, Table->Table[i].InterfaceIndex);

            if (If != NULL && MatchesFilter(If, Filter) && Table->Table[i].DestinationPrefix.Prefix.si_family == AF_INET6)
                Rows[RowCount++] = &Table->Table[i];
        }
        qsort(Rows, RowCount, sizeof(PVOID), CompareRoutes);
    }

    for (i = 0; i < RowCount; i++)
    {
        const MIB_IPFORWARD_ROW2 *Row = Rows[i];
        PIPV6_IF If = FindInterface(List, Count, Row->InterfaceIndex);
        WCHAR Address[80], Prefix[96], Gateway[80];

        if (!Header)
        {
            PrintMessage(L"\nPublish  Type      Met  Prefix                    Idx  Gateway/Interface Name\n");
            PrintMessage(L"-------  --------  ---  ------------------------  ---  ------------------------\n");
            Header = TRUE;
        }

        FormatAddress(Address, &Row->DestinationPrefix.Prefix.Ipv6.sin6_addr);
        StringCchPrintfW(Prefix, ARRAYSIZE(Prefix), L"%s/%u", Address, (UINT)Row->DestinationPrefix.PrefixLength);

        if (Row->NextHop.si_family == AF_INET6 && !IsUnspecified(&Row->NextHop.Ipv6.sin6_addr))
            FormatAddress(Gateway, &Row->NextHop.Ipv6.sin6_addr);
        else
            StringCchCopyW(Gateway, ARRAYSIZE(Gateway), If->Name);

        PrintMessage(L"%-7s  %-8s  %3lu  %-24s  %3lu  %s\n",
                     Row->Publish ? L"Yes" : L"No", RouteType(Row), Row->Metric,
                     Prefix, Row->InterfaceIndex, Gateway);
    }

    if (Header)
        PrintMessage(L"\n");

    if (Rows)
        HeapFree(GetProcessHeap(), 0, Rows);
    if (Table)
        FreeMibTable(Table);
    FreeInterfaces(List);
    return ERROR_SUCCESS;
}


/* show neighbors, joins, destinationcache **********************************/

static
PCWSTR
NeighborState(
    _In_ NL_NEIGHBOR_STATE State)
{
    switch (State)
    {
        case NlnsIncomplete: return L"Incomplete";
        case NlnsProbe:      return L"Probe";
        case NlnsDelay:      return L"Delay";
        case NlnsStale:      return L"Stale";
        case NlnsReachable:  return L"Reachable";
        case NlnsPermanent:  return L"Permanent";
        default:             return L"Unreachable";
    }
}

static
DWORD
WINAPI
Ipv6ShowNeighbors(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PMIB_IPNET_TABLE2 Table = NULL;
    PCWSTR Filter;
    ULONG Count, i, j;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    if (Count != 0 && GetIpNetTable2(AF_INET6, &Table) != NO_ERROR)
        Table = NULL;

    for (i = 0; i < Count; i++)
    {
        if (!MatchesFilter(&List[i], Filter))
            continue;

        PrintMessage(L"\nInterface %lu: %s\n\n\n", List[i].Index, List[i].Name);
        PrintMessage(L"Internet Address                              Physical Address   Type\n");
        PrintMessage(L"--------------------------------------------  -----------------  -----------\n");

        for (j = 0; Table != NULL && j < Table->NumEntries; j++)
        {
            const MIB_IPNET_ROW2 *Row = &Table->Table[j];
            WCHAR Address[80], Physical[24];

            if (Row->InterfaceIndex != List[i].Index || Row->Address.si_family != AF_INET6)
                continue;

            FormatAddress(Address, &Row->Address.Ipv6.sin6_addr);
            Physical[0] = UNICODE_NULL;
            if (Row->PhysicalAddressLength == 6)
            {
                StringCchPrintfW(Physical, ARRAYSIZE(Physical), L"%02x-%02x-%02x-%02x-%02x-%02x",
                         Row->PhysicalAddress[0], Row->PhysicalAddress[1], Row->PhysicalAddress[2],
                         Row->PhysicalAddress[3], Row->PhysicalAddress[4], Row->PhysicalAddress[5]);
            }
            else if (Row->State == NlnsUnreachable || Row->State == NlnsIncomplete)
            {
                wcscpy(Physical, L"00-00-00-00-00-00");
            }

            PrintMessage(L"%-44s  %-17s  %s \n", Address, Physical, NeighborState(Row->State));
        }
    }

    if (Count != 0)
        PrintMessage(L"\n");

    if (Table)
        FreeMibTable(Table);
    FreeInterfaces(List);
    return ERROR_SUCCESS;
}

/*
 * The stack has no query for the groups a host has joined: what is listed is what IPv6 requires of every
 * interface that has addresses (RFC 4291 section 2.8: the interface-local and link-local all-nodes groups and
 * the solicited-node group of each unicast address, which the stack joins and reports for). Groups that
 * sockets joined are not listed until the stack exposes them.
 */
static
DWORD
WINAPI
Ipv6ShowJoins(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;
    PCWSTR Filter;
    ULONG Count, i, j;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    if (Count != 0 && GetUnicastIpAddressTable(AF_INET6, &Table) != NO_ERROR)
        Table = NULL;

    for (i = 0; i < Count; i++)
    {
        BOOL AnyAddress = FALSE;

        if (!MatchesFilter(&List[i], Filter))
            continue;

        PrintMessage(L"\nInterface %lu: %s\n\n", List[i].Index, List[i].Name);
        PrintMessage(L"Scope       References  Last  Address\n");
        PrintMessage(L"----------  ----------  ----  ---------------------------------\n");

        for (j = 0; Table != NULL && j < Table->NumEntries; j++)
        {
            const MIB_UNICASTIPADDRESS_ROW *Row = &Table->Table[j];

            if (Row->InterfaceIndex != List[i].Index || Row->Address.si_family != AF_INET6)
                continue;
            /* the loopback interface joins nothing the stack could tell of: it lists none */
            if (IsLoopbackAddress(&Row->Address.Ipv6.sin6_addr))
            {
                AnyAddress = FALSE;
                break;
            }
            AnyAddress = TRUE;
        }

        if (!AnyAddress)
            continue;

        PrintMessage(L"%-10u  %10u  %-4s  %s\n", 0, 0, L"Yes", L"ff01::1");
        PrintMessage(L"%-10u  %10u  %-4s  %s\n", 0, 0, L"Yes", L"ff02::1");
        for (j = 0; j < Table->NumEntries; j++)
        {
            const MIB_UNICASTIPADDRESS_ROW *Row = &Table->Table[j];
            const UCHAR *a = Row->Address.Ipv6.sin6_addr.u.Byte;
            ULONG k;
            BOOL Seen = FALSE;

            if (Row->InterfaceIndex != List[i].Index || Row->Address.si_family != AF_INET6 ||
                Row->DadState == IpDadStateDuplicate)
                continue;

            /* one group per distinct low 24 bits */
            for (k = 0; k < j; k++)
            {
                const MIB_UNICASTIPADDRESS_ROW *Prev = &Table->Table[k];

                if (Prev->InterfaceIndex == List[i].Index && Prev->Address.si_family == AF_INET6 &&
                    memcmp(&Prev->Address.Ipv6.sin6_addr.u.Byte[13], &a[13], 3) == 0 &&
                    Prev->DadState != IpDadStateDuplicate)
                    Seen = TRUE;
            }
            if (!Seen)
                PrintMessage(L"%-10u  %10u  %-4s  ff02::1:ff%02x:%02x%02x\n", 0, 1, L"Yes", a[13], a[14], a[15]);
        }
    }

    if (Count != 0)
        PrintMessage(L"\n");

    if (Table)
        FreeMibTable(Table);
    FreeInterfaces(List);
    return ERROR_SUCCESS;
}

/* The stack keeps no destination cache that can be read: the cache of each interface is listed empty. */
static
DWORD
WINAPI
Ipv6ShowDestinationCache(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PCWSTR Filter;
    ULONG Count, i;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < Count; i++)
    {
        if (!MatchesFilter(&List[i], Filter))
            continue;

        PrintMessage(L"\nInterface %lu: %s\n\n\n", List[i].Index, List[i].Name);
        PrintMessage(L"PMTU Destination Address                           Next Hop Address\n");
        PrintMessage(L"---- --------------------------------------------- -------------------------\n");
    }

    if (Count != 0)
        PrintMessage(L"\n");

    FreeInterfaces(List);
    return ERROR_SUCCESS;
}


/* show dnsservers **********************************************************/

#define DNS_LABEL_STATIC   L"    Statically Configured DNS Servers:    "
#define DNS_LABEL_DHCP     L"    DNS servers configured through DHCP:  "
#define DNS_CONTINUATION   L"                                          "

/* Is Address in the NameServer value of the adapter (addresses separated by comma, semicolon or blank)? */
static
BOOL
IsConfiguredServer(
    _In_ PCWSTR Configured,
    _In_ const IN6_ADDR *Address)
{
    WCHAR Copy[512];
    PWCHAR Token, Context = NULL;
    IN6_ADDR Parsed;
    PCWSTR End;

    if (Configured == NULL)
        return FALSE;
    StringCchCopyW(Copy, ARRAYSIZE(Copy), Configured);
    for (Token = wcstok_s(Copy, L",; ", &Context); Token; Token = wcstok_s(NULL, L",; ", &Context))
    {
        PWCHAR Percent = wcschr(Token, L'%');

        if (Percent)
            *Percent = UNICODE_NULL;
        if (RtlIpv6StringToAddressW(Token, &End, &Parsed) == 0 &&
            memcmp(&Parsed, Address, sizeof(Parsed)) == 0)
            return TRUE;
    }
    return FALSE;
}

static
VOID
ReadConfiguredServers(
    _In_ PCSTR AdapterName,
    _Out_writes_(Size) PWSTR Value,
    _In_ ULONG Size)
{
    WCHAR Path[256];
    HKEY hKey;
    DWORD Type, Bytes = (Size - 1) * sizeof(WCHAR);

    Value[0] = UNICODE_NULL;
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s%S", IPV6_INTERFACES_KEY, AdapterName);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;
    if (RegQueryValueExW(hKey, L"NameServer", NULL, &Type, (LPBYTE)Value, &Bytes) != ERROR_SUCCESS || Type != REG_SZ)
        Value[0] = UNICODE_NULL;
    else
        Value[Bytes / sizeof(WCHAR)] = UNICODE_NULL;
    RegCloseKey(hKey);
}

static
VOID
PrintServerList(
    _In_ PCWSTR Label,
    _In_ PWSTR *Servers,
    _In_ ULONG Count)
{
    ULONG i;

    if (Count == 0)
    {
        PrintMessage(L"%sNone\n", Label);
        return;
    }
    for (i = 0; i < Count; i++)
        PrintMessage(L"%s%s\n", (i == 0) ? Label : DNS_CONTINUATION, Servers[i]);
}

static
DWORD
WINAPI
Ipv6ShowDnsServers(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PIPV6_IF List = NULL;
    PIP_ADAPTER_ADDRESSES Adapters = NULL, Adapter;
    PCWSTR Filter;
    ULONG Count, Size = 16384, Tries;
    DWORD Error;

    Error = ParseShowArguments(argv, dwCurrentIndex, dwArgCount, &Filter);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (!FilterMatchesAny(List, Count, Filter))
    {
        FreeInterfaces(List);
        return ERROR_INVALID_PARAMETER;
    }

    if (Count == 0)
    {
        FreeInterfaces(List);
        return ERROR_SUCCESS;
    }

    for (Tries = 0; Tries < 4; Tries++)
    {
        Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
        if (Adapters == NULL)
        {
            FreeInterfaces(List);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        Error = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, Adapters, &Size);
        if (Error != ERROR_BUFFER_OVERFLOW)
            break;
        HeapFree(GetProcessHeap(), 0, Adapters);
        Adapters = NULL;
    }

    for (Adapter = (Error == NO_ERROR) ? Adapters : NULL; Adapter; Adapter = Adapter->Next)
    {
        PIPV6_IF If = FindInterface(List, Count, Adapter->Ipv6IfIndex);
        PIP_ADAPTER_DNS_SERVER_ADDRESS Server;
        WCHAR Configured[512];
        WCHAR Text[8][80];
        PWSTR Static[8], Dynamic[8];
        ULONG StaticCount = 0, DynamicCount = 0;

        if (If == NULL || !MatchesFilter(If, Filter))
            continue;

        ReadConfiguredServers(Adapter->AdapterName, Configured, ARRAYSIZE(Configured));
        for (Server = Adapter->FirstDnsServerAddress; Server; Server = Server->Next)
        {
            const SOCKADDR_IN6 *Sa = (const SOCKADDR_IN6 *)Server->Address.lpSockaddr;
            ULONG n = StaticCount + DynamicCount;
            BOOL IsStatic;
            SIZE_T Length;

            if (Sa->sin6_family != AF_INET6 || n >= 8)
                continue;

            FormatAddress(Text[n], &Sa->sin6_addr);
            Length = wcslen(Text[n]);
            if (Sa->sin6_scope_id != 0)
                StringCchPrintfW(Text[n] + Length, 80 - Length, L"%%%lu", (ULONG)Sa->sin6_scope_id);

            IsStatic = IsConfiguredServer(Configured, &Sa->sin6_addr);
            if (IsStatic)
                Static[StaticCount++] = Text[n];
            else
                Dynamic[DynamicCount++] = Text[n];
        }

        PrintMessage(L"Configuration for interface \"%s\"\n", If->Name);
        if (StaticCount != 0)
            PrintServerList(DNS_LABEL_STATIC, Static, StaticCount);
        if (DynamicCount != 0 || StaticCount == 0)
        {
            if (DynamicCount == 0 && Adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                PrintServerList(DNS_LABEL_STATIC, Dynamic, 0);
            else
                PrintServerList(DNS_LABEL_DHCP, Dynamic, DynamicCount);
        }
        PrintMessage(L"    Register with which suffix:           Primary only\n\n");
    }

    if (Adapters)
        HeapFree(GetProcessHeap(), 0, Adapters);
    FreeInterfaces(List);
    return ERROR_SUCCESS;
}


/* show global, privacy, prefixpolicies *************************************/

static
BOOL
ReadParameter(
    _In_ PCWSTR Name,
    _Out_ PDWORD Value)
{
    HKEY hKey;
    DWORD Type, Size = sizeof(*Value);
    BOOL Found = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IPV6_PARAMETERS_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, Name, NULL, &Type, (LPBYTE)Value, &Size) == ERROR_SUCCESS && Type == REG_DWORD)
        Found = TRUE;
    RegCloseKey(hKey);
    return Found;
}

/*
 * What the stack is asked for here is the default hop limit, the forwarding switch and RandomizeIdentifiers
 * (the registry value the stack reads when an interface starts, enabled when absent). The other lines are the
 * documented defaults of the parameter they name: the stack has no setting for them.
 */
static
DWORD
WINAPI
Ipv6ShowGlobal(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    MIB_IPSTATS Stats;
    DWORD HopLimit = 128, Randomize = 1;

    ZeroMemory(&Stats, sizeof(Stats));
    if (GetIpStatisticsEx(&Stats, AF_INET6) == NO_ERROR && Stats.dwDefaultTTL != 0)
        HopLimit = Stats.dwDefaultTTL;
    if (!ReadParameter(L"RandomizeIdentifiers", &Randomize))
        Randomize = 1;

    PrintMessage(L"Querying active state...\n\n");
    PrintMessage(L"General Global Parameters\n");
    PrintMessage(L"---------------------------------------------\n");
    PrintMessage(L"Default Hop Limit                   : %lu hops\n", HopLimit);
    PrintMessage(L"Neighbor Cache Limit                : 256 entries per interface\n");
    PrintMessage(L"Route Cache Limit                   : 4096 entries per compartment\n");
    PrintMessage(L"Reassembly Limit                    : 67070176 bytes\n");
    PrintMessage(L"ICMP Redirects                      : enabled\n");
    PrintMessage(L"Source Routing Behavior             : dontforward\n");
    PrintMessage(L"Task Offload                        : enabled\n");
    PrintMessage(L"Dhcp Media Sense                    : enabled\n");
    PrintMessage(L"Media Sense Logging                 : disabled\n");
    PrintMessage(L"MLD Level                           : all\n");
    PrintMessage(L"MLD Version                         : version3\n");
    PrintMessage(L"Multicast Forwarding                : disabled\n");
    PrintMessage(L"Group Forwarded Fragments           : disabled\n");
    PrintMessage(L"Randomize Identifiers               : %s\n", Randomize ? L"enabled" : L"disabled");
    PrintMessage(L"Address Mask Reply                  : disabled\n");
    PrintMessage(L"Minimum Mtu                         : 1280\n");
    PrintMessage(L"Flow Label                          : enabled\n");
    PrintMessage(L"Loopback Large Mtu                  : enabled\n");
    PrintMessage(L"Loopback Worker Count               : 1\n");
    PrintMessage(L"Loopback Execution Mode             : adaptive\n");
    PrintMessage(L"Source Based ECMP                   : enabled\n");
    PrintMessage(L"Reassembly Out Of Order Limit       : 32 fragments\n\n");
    PrintMessage(L"Current Global Statistics\n");
    PrintMessage(L"---------------------------------------------\n");
    PrintMessage(L"Number of Compartments              : 1\n");
    PrintMessage(L"Number of NL clients                : 5\n");
    PrintMessage(L"Number of FL providers              : 4\n\n");

    return ERROR_SUCCESS;
}

/* Temporary addresses are not generated yet: they are disabled, and the lifetimes are the ones they will get */
static
DWORD
WINAPI
Ipv6ShowPrivacy(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    PrintMessage(L"Querying active state...\n\n");
    PrintMessage(L"Temporary Address Parameters\n");
    PrintMessage(L"---------------------------------------------\n");
    PrintMessage(L"Use Temporary Addresses             : disabled\n");
    PrintMessage(L"Duplicate Address Detection Attempts: 3\n");
    PrintMessage(L"Maximum Valid Lifetime              : 7d\n");
    PrintMessage(L"Maximum Preferred Lifetime          : 1d\n");
    PrintMessage(L"Regenerate Time                     : 5s\n");
    PrintMessage(L"Maximum Random Time                 : 10m\n");
    PrintMessage(L"Random Time                         : 0s\n\n");

    return ERROR_SUCCESS;
}

/* The Windows default policy table (RFC 6724 and the entries Windows adds), until the policy store is readable */
static
DWORD
WINAPI
Ipv6ShowPrefixPolicies(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    static const struct { UINT Precedence, Label; PCWSTR Prefix; } Policies[] =
    {
        {50,  0, L"::1/128"},
        {40,  1, L"::/0"},
        {35,  4, L"::ffff:0:0/96"},
        {30,  2, L"2002::/16"},
        { 5,  5, L"2001::/32"},
        { 3, 13, L"fc00::/7"},
        { 1, 11, L"fec0::/10"},
        { 1, 12, L"3ffe::/16"},
        { 1,  3, L"::/96"},
    };
    ULONG i;

    PrintMessage(L"Querying active state...\n\n");
    PrintMessage(L"Precedence  Label  Prefix\n");
    PrintMessage(L"----------  -----  --------------------------------\n");
    for (i = 0; i < ARRAYSIZE(Policies); i++)
        PrintMessage(L"%10u  %5u  %s\n", Policies[i].Precedence, Policies[i].Label, Policies[i].Prefix);
    PrintMessage(L"\n");

    return ERROR_SUCCESS;
}


/* Helper registration ******************************************************/

static
DWORD
WINAPI
Ipv6Start(
    _In_ const GUID *pguidParent,
    _In_ DWORD dwVersion)
{
    NS_CONTEXT_ATTRIBUTES ContextAttributes;

    ZeroMemory(&ContextAttributes, sizeof(ContextAttributes));
    ContextAttributes.dwVersion = 1;
    ContextAttributes.pwszContext = L"ipv6";
    ContextAttributes.guidHelper = GUID_IFMON_IPV6;

    ContextAttributes.ulNumTopCmds = 0;
    ContextAttributes.pTopCmds = NULL;

    ContextAttributes.ulNumGroups = sizeof(Ipv6Groups) / sizeof(CMD_GROUP_ENTRY);
    ContextAttributes.pCmdGroups = Ipv6Groups;

    RegisterContext(&ContextAttributes);

    return ERROR_SUCCESS;
}


DWORD
WINAPI
RegisterIpv6Helper(VOID)
{
    NS_HELPER_ATTRIBUTES HelperAttributes;
    GUID guidParent = GUID_IFMON_INTERFACE;

    ZeroMemory(&HelperAttributes, sizeof(HelperAttributes));
    HelperAttributes.dwVersion = 1;
    HelperAttributes.guidHelper = GUID_IFMON_IPV6;
    HelperAttributes.pfnStart = Ipv6Start;
    HelperAttributes.pfnStop = NULL;
    RegisterHelper(&guidParent, &HelperAttributes);

    return ERROR_SUCCESS;
}
