/*
 * PROJECT:    ReactOS IF Monitor DLL
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    IPv6 context functions (netsh interface ipv6 show ...)
 * COPYRIGHT:  Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <ws2tcpip.h>
#include <wctype.h>
#include <wine/netioapi.h>
#include <guiddef.h>
#include <iphlpapi_nitro.h>

#define NDEBUG
#include <debug.h>

#include "guid.h"
#include "resource.h"

/*
 * The show commands take the optional "interface=<name or index>" (and accept "level=" and "store=", which change
 * nothing about what the stack can tell).
 *
 * The add, set and delete commands configure what the stack has an API for: addresses and routes through its IPv6
 * configuration requests (iphlpapi's NitroConfigureIpv6Address and NitroConfigureIpv6Route, the requests behind
 * CreateUnicastIpAddressEntry and CreateIpForwardEntry2, with the persistent store of New-NetIPAddress and
 * New-NetRoute -PolicyStore PersistentStore), the static DNS servers (the NameServer value of the interface in
 * Tcpip6, where iphlpapi and Set-DnsClientServerAddress look) and the one global parameter the stack reads,
 * RandomizeIdentifiers. What has no backing in the stack (interface parameters such as mtu, metric and
 * routerdiscovery, privacy, prefix policies, anycast addresses) has no command.
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
static FN_HANDLE_CMD Ipv6AddAddress;
static FN_HANDLE_CMD Ipv6AddDnsServers;
static FN_HANDLE_CMD Ipv6AddRoute;
static FN_HANDLE_CMD Ipv6DeleteAddress;
static FN_HANDLE_CMD Ipv6DeleteDnsServers;
static FN_HANDLE_CMD Ipv6DeleteRoute;
static FN_HANDLE_CMD Ipv6SetAddress;
static FN_HANDLE_CMD Ipv6SetGlobal;

static
CMD_ENTRY
Ipv6AddCommands[] =
{
    {L"address", Ipv6AddAddress, IDS_HLP_IPV6_ADD_ADDRESS, IDS_HLP_IPV6_ADD_ADDRESS_EX, 0},
    {L"dnsservers", Ipv6AddDnsServers, IDS_HLP_IPV6_ADD_DNSSERVERS, IDS_HLP_IPV6_ADD_DNSSERVERS_EX, 0},
    {L"route", Ipv6AddRoute, IDS_HLP_IPV6_ADD_ROUTE, IDS_HLP_IPV6_ADD_ROUTE_EX, 0},
};

static
CMD_ENTRY
Ipv6DeleteCommands[] =
{
    {L"address", Ipv6DeleteAddress, IDS_HLP_IPV6_DELETE_ADDRESS, IDS_HLP_IPV6_DELETE_ADDRESS_EX, 0},
    {L"dnsservers", Ipv6DeleteDnsServers, IDS_HLP_IPV6_DELETE_DNSSERVERS, IDS_HLP_IPV6_DELETE_DNSSERVERS_EX, 0},
    {L"route", Ipv6DeleteRoute, IDS_HLP_IPV6_DELETE_ROUTE, IDS_HLP_IPV6_DELETE_ROUTE_EX, 0},
};

static
CMD_ENTRY
Ipv6SetCommands[] =
{
    {L"address", Ipv6SetAddress, IDS_HLP_IPV6_SET_ADDRESS, IDS_HLP_IPV6_SET_ADDRESS_EX, 0},
    {L"global", Ipv6SetGlobal, IDS_HLP_IPV6_SET_GLOBAL, IDS_HLP_IPV6_SET_GLOBAL_EX, 0},
};

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
    {L"add", IDS_HLP_IPV6_ADD, sizeof(Ipv6AddCommands) / sizeof(CMD_ENTRY), 0, Ipv6AddCommands, NULL},
    {L"delete", IDS_HLP_IPV6_DELETE, sizeof(Ipv6DeleteCommands) / sizeof(CMD_ENTRY), 0, Ipv6DeleteCommands, NULL},
    {L"set", IDS_HLP_IPV6_SET, sizeof(Ipv6SetCommands) / sizeof(CMD_ENTRY), 0, Ipv6SetCommands, NULL},
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


/* add, set and delete: arguments *******************************************/

/* The values of the tags of a command (NULL for a tag not given or given empty); a missing required tag is a syntax
   error (the usage is printed) */
static
DWORD
ParseTags(
    _In_ LPWSTR *argv,
    _In_ DWORD dwCurrentIndex,
    _In_ DWORD dwArgCount,
    _Inout_ TAG_TYPE *Tags,
    _In_ DWORD TagCount,
    _Out_writes_(TagCount) PWSTR *Values)
{
    PDWORD Types;
    DWORD i, Error = ERROR_SUCCESS;

    for (i = 0; i < TagCount; i++)
        Values[i] = NULL;

    if (dwArgCount > dwCurrentIndex)
    {
        Types = HeapAlloc(GetProcessHeap(), 0, (dwArgCount - dwCurrentIndex) * sizeof(DWORD));
        if (Types == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;

        Error = MatchTagsInCmdLine(hDllInstance, argv, dwCurrentIndex, dwArgCount, Tags, TagCount, Types);
        for (i = 0; Error == ERROR_SUCCESS && i < dwArgCount - dwCurrentIndex; i++)
        {
            /* more values than tags */
            if (Types[i] >= TagCount)
                Error = ERROR_INVALID_SYNTAX;
            else
                Values[Types[i]] = argv[dwCurrentIndex + i];
        }
        HeapFree(GetProcessHeap(), 0, Types);
        if (Error != ERROR_SUCCESS)
            return Error;
    }

    for (i = 0; i < TagCount; i++)
    {
        if (Values[i] != NULL && Values[i][0] == UNICODE_NULL)
            Values[i] = NULL;
        if ((Tags[i].dwRequired & NS_REQ_PRESENT) && Values[i] == NULL)
            return ERROR_INVALID_SYNTAX;
    }
    return ERROR_SUCCESS;
}

static
DWORD
BadValue(
    _In_ PCWSTR Value,
    _In_ PCWSTR Tag)
{
    PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Value, Tag);
    return ERROR_SUPPRESS_OUTPUT;
}

/* A word of a list of values, as netsh takes it: any start of it ("per" for persistent) */
static
BOOL
IsWord(
    _In_ PCWSTR Text,
    _In_ PCWSTR Word)
{
    return Text[0] != UNICODE_NULL && _wcsnicmp(Text, Word, wcslen(Text)) == 0;
}

/* store=active|persistent: persistent (both stores) when not given */
static
DWORD
ParseStore(
    _In_opt_ PCWSTR Value,
    _Out_ PBOOL Persistent)
{
    *Persistent = TRUE;
    if (Value == NULL)
        return ERROR_SUCCESS;
    if (IsWord(Value, L"persistent"))
        return ERROR_SUCCESS;
    if (IsWord(Value, L"active"))
    {
        *Persistent = FALSE;
        return ERROR_SUCCESS;
    }
    return BadValue(Value, L"store");
}

/* A decimal number of seconds, a time such as 1d2h3m4s, or "infinite" */
static
BOOL
ParseLifetime(
    _In_ PCWSTR Text,
    _Out_ PULONG Seconds)
{
    ULONGLONG Total = 0;
    PCWSTR p = Text;

    if (_wcsicmp(Text, L"infinite") == 0)
    {
        *Seconds = INFINITE_LIFETIME;
        return TRUE;
    }

    while (*p != UNICODE_NULL)
    {
        ULONGLONG Number = 0;

        if (!iswdigit(*p))
            return FALSE;
        while (iswdigit(*p))
        {
            Number = Number * 10 + (*p - L'0');
            if (Number > 0xffffffffULL)
                return FALSE;
            p++;
        }
        switch (towlower(*p))
        {
            case L'd': Number *= 86400; p++; break;
            case L'h': Number *= 3600; p++; break;
            case L'm': Number *= 60; p++; break;
            case L's': p++; break;
            case UNICODE_NULL: break;   /* a bare number of seconds */
            default: return FALSE;
        }
        Total += Number;
        if (Total >= INFINITE_LIFETIME)
            return FALSE;
    }
    *Seconds = (ULONG)Total;
    return Text[0] != UNICODE_NULL;
}

/* A lifetime tag, or its default when it is not given */
static
DWORD
LifetimeValue(
    _In_opt_ PCWSTR Value,
    _In_ PCWSTR Tag,
    _Out_ PULONG Seconds)
{
    *Seconds = INFINITE_LIFETIME;
    if (Value == NULL)
        return ERROR_SUCCESS;
    if (!ParseLifetime(Value, Seconds))
        return BadValue(Value, Tag);
    return ERROR_SUCCESS;
}

/* "<IPv6 address>[/<length>]" (no scope: the interface names it); Length is DefaultLength when the text has none */
static
BOOL
ParseAddress(
    _In_ PCWSTR Text,
    _In_ BOOL AllowLength,
    _In_ ULONG DefaultLength,
    _Out_ PIN6_ADDR Address,
    _Out_opt_ PULONG Length)
{
    WCHAR Copy[80];
    PCWSTR Slash = wcschr(Text, L'/');
    SIZE_T Count = Slash ? (SIZE_T)(Slash - Text) : wcslen(Text);
    ULONG ScopeId = 0, Value = DefaultLength;
    USHORT Port = 0;
    PWSTR End;

    if (Count == 0 || Count >= ARRAYSIZE(Copy) || (Slash && !AllowLength))
        return FALSE;
    StringCchCopyNW(Copy, ARRAYSIZE(Copy), Text, Count);
    if (RtlIpv6StringToAddressExW(Copy, Address, &ScopeId, &Port) != 0 || Port != 0 || ScopeId != 0)
        return FALSE;
    if (Slash)
    {
        if (!iswdigit(Slash[1]))
            return FALSE;
        Value = wcstoul(Slash + 1, &End, 10);
        if (*End != UNICODE_NULL || Value > 128)
            return FALSE;
    }
    if (Length)
        *Length = Value;
    return TRUE;
}

/* The IPv6 interface of a name or index. A system without IPv6 has none: the request is not supported. */
static
DWORD
ResolveInterface(
    _In_ PCWSTR Text,
    _Out_ PULONG IfIndex)
{
    PIPV6_IF List = NULL;
    ULONG Count, i;
    DWORD Error = ERROR_INVALID_PARAMETER;

    *IfIndex = 0;
    Error = LoadInterfaces(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (Count == 0)
    {
        FreeInterfaces(List);
        return ERROR_NOT_SUPPORTED;
    }

    Error = ERROR_INVALID_PARAMETER;
    for (i = 0; i < Count; i++)
    {
        if (MatchesFilter(&List[i], Text))
        {
            *IfIndex = List[i].Index;
            Error = ERROR_SUCCESS;
            break;
        }
    }
    FreeInterfaces(List);
    return Error;
}

/* netsh answers "Ok." for a change that worked */
static
DWORD
Finish(
    _In_ DWORD Error)
{
    return (Error == ERROR_SUCCESS) ? ERROR_NETSH_OK : Error;
}


/* add, set and delete address **********************************************/

static
VOID
InitAddressRow(
    _Out_ PMIB_UNICASTIPADDRESS_ROW Row,
    _In_ ULONG IfIndex,
    _In_ const IN6_ADDR *Address,
    _In_ ULONG Length)
{
    InitializeUnicastIpAddressEntry(Row);
    Row->Address.si_family = AF_INET6;
    Row->Address.Ipv6.sin6_addr = *Address;
    Row->InterfaceIndex = IfIndex;
    Row->OnLinkPrefixLength = (UINT8)Length;
    Row->ValidLifetime = INFINITE_LIFETIME;
    Row->PreferredLifetime = INFINITE_LIFETIME;
}

static
DWORD
WINAPI
Ipv6AddAddress(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_PRESENT, FALSE},
                       {L"type", NS_REQ_ZERO, FALSE},
                       {L"validlifetime", NS_REQ_ZERO, FALSE},
                       {L"preferredlifetime", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE},
                       {L"skipassource", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    MIB_UNICASTIPADDRESS_ROW Row;
    IN6_ADDR Address;
    ULONG IfIndex, Length, Valid, Preferred;
    BOOL Persistent, Skip = FALSE;
    DWORD Error;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!ParseAddress(Values[1], TRUE, 64, &Address, &Length))
        return BadValue(Values[1], L"address");
    if (Values[2] != NULL)
    {
        if (IsWord(Values[2], L"anycast"))
            return ERROR_NOT_SUPPORTED;
        if (!IsWord(Values[2], L"unicast"))
            return BadValue(Values[2], L"type");
    }
    Error = LifetimeValue(Values[3], L"validlifetime", &Valid);
    if (Error == ERROR_SUCCESS)
        Error = LifetimeValue(Values[4], L"preferredlifetime", &Preferred);
    if (Error == ERROR_SUCCESS)
        Error = ParseStore(Values[5], &Persistent);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (Values[6] != NULL)
    {
        if (IsWord(Values[6], L"true"))
            Skip = TRUE;
        else if (!IsWord(Values[6], L"false"))
            return BadValue(Values[6], L"skipassource");
    }

    Error = ResolveInterface(Values[0], &IfIndex);
    if (Error != ERROR_SUCCESS)
        return Error;

    InitAddressRow(&Row, IfIndex, &Address, Length);
    Row.ValidLifetime = Valid;
    Row.PreferredLifetime = Preferred;
    Row.PrefixOrigin = IpPrefixOriginManual;
    Row.SuffixOrigin = IpSuffixOriginManual;
    Row.SkipAsSource = Skip;
    return Finish(NitroConfigureIpv6Address(NITRO_IPV6_CREATE, Persistent, &Row));
}

static
DWORD
WINAPI
Ipv6SetAddress(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_PRESENT, FALSE},
                       {L"type", NS_REQ_ZERO, FALSE},
                       {L"validlifetime", NS_REQ_ZERO, FALSE},
                       {L"preferredlifetime", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    MIB_UNICASTIPADDRESS_ROW Row;
    IN6_ADDR Address;
    ULONG IfIndex, Valid, Preferred;
    BOOL Persistent;
    DWORD Error;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!ParseAddress(Values[1], FALSE, 0, &Address, NULL))
        return BadValue(Values[1], L"address");
    if (Values[2] != NULL)
    {
        if (IsWord(Values[2], L"anycast"))
            return ERROR_NOT_SUPPORTED;
        if (!IsWord(Values[2], L"unicast"))
            return BadValue(Values[2], L"type");
    }
    Error = LifetimeValue(Values[3], L"validlifetime", &Valid);
    if (Error == ERROR_SUCCESS)
        Error = LifetimeValue(Values[4], L"preferredlifetime", &Preferred);
    if (Error == ERROR_SUCCESS)
        Error = ParseStore(Values[5], &Persistent);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = ResolveInterface(Values[0], &IfIndex);
    if (Error != ERROR_SUCCESS)
        return Error;

    /* the address as it is (its length, origins and skip-as-source stay), with the new lifetimes */
    InitAddressRow(&Row, IfIndex, &Address, 255);
    Error = GetUnicastIpAddressEntry(&Row);
    if (Error != NO_ERROR)
        return Error;
    Row.ValidLifetime = Valid;
    Row.PreferredLifetime = Preferred;
    return Finish(NitroConfigureIpv6Address(NITRO_IPV6_SET, Persistent, &Row));
}

static
DWORD
WINAPI
Ipv6DeleteAddress(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"interface", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_PRESENT, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    MIB_UNICASTIPADDRESS_ROW Row;
    IN6_ADDR Address;
    ULONG IfIndex;
    BOOL Persistent;
    DWORD Error;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!ParseAddress(Values[1], FALSE, 0, &Address, NULL))
        return BadValue(Values[1], L"address");
    Error = ParseStore(Values[2], &Persistent);
    if (Error == ERROR_SUCCESS)
        Error = ResolveInterface(Values[0], &IfIndex);
    if (Error != ERROR_SUCCESS)
        return Error;

    InitAddressRow(&Row, IfIndex, &Address, 255);
    return Finish(NitroConfigureIpv6Address(NITRO_IPV6_DELETE, Persistent, &Row));
}


/* add and delete route *****************************************************/

/* The bits after the prefix length name nothing */
static
VOID
MaskPrefix(
    _Inout_ PIN6_ADDR Address,
    _In_ ULONG Length)
{
    ULONG i;

    for (i = 0; i < 16; i++)
    {
        LONG Bits = (LONG)Length - (LONG)i * 8;

        if (Bits < 8)
            Address->u.Byte[i] = Bits <= 0 ? 0 : (UCHAR)(Address->u.Byte[i] & (0xff << (8 - Bits)));
    }
}

static
VOID
InitRouteRow(
    _Out_ PMIB_IPFORWARD_ROW2 Row,
    _In_ ULONG IfIndex,
    _In_ const IN6_ADDR *Prefix,
    _In_ ULONG Length,
    _In_opt_ const IN6_ADDR *NextHop)
{
    InitializeIpForwardEntry(Row);
    Row->InterfaceIndex = IfIndex;
    Row->DestinationPrefix.Prefix.si_family = AF_INET6;
    Row->DestinationPrefix.Prefix.Ipv6.sin6_addr = *Prefix;
    Row->DestinationPrefix.PrefixLength = (UINT8)Length;
    Row->NextHop.si_family = AF_INET6;
    if (NextHop)
        Row->NextHop.Ipv6.sin6_addr = *NextHop;
}

static
DWORD
WINAPI
Ipv6AddRoute(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"prefix", NS_REQ_PRESENT, FALSE},
                       {L"interface", NS_REQ_PRESENT, FALSE},
                       {L"nexthop", NS_REQ_ZERO, FALSE},
                       {L"siteprefixlength", NS_REQ_ZERO, FALSE},
                       {L"metric", NS_REQ_ZERO, FALSE},
                       {L"publish", NS_REQ_ZERO, FALSE},
                       {L"validlifetime", NS_REQ_ZERO, FALSE},
                       {L"preferredlifetime", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    MIB_IPFORWARD_ROW2 Row;
    IN6_ADDR Prefix, NextHop;
    ULONG IfIndex, Length, Metric = 256, SiteLength = 0, Valid, Preferred;
    BOOL Persistent, Publish = FALSE, Immortal = FALSE;
    PWSTR End;
    DWORD Error;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!ParseAddress(Values[0], TRUE, 128, &Prefix, &Length))
        return BadValue(Values[0], L"prefix");
    ZeroMemory(&NextHop, sizeof(NextHop));
    if (Values[2] != NULL && !ParseAddress(Values[2], FALSE, 0, &NextHop, NULL))
        return BadValue(Values[2], L"nexthop");
    if (Values[3] != NULL)
    {
        SiteLength = iswdigit(Values[3][0]) ? wcstoul(Values[3], &End, 10) : 0xffff;
        if (SiteLength > 128 || *End != UNICODE_NULL)
            return BadValue(Values[3], L"siteprefixlength");
    }
    if (Values[4] != NULL)
    {
        Metric = iswdigit(Values[4][0]) ? wcstoul(Values[4], &End, 10) : 0xffffffff;
        if (Metric > 0xffff || *End != UNICODE_NULL)
            return BadValue(Values[4], L"metric");
    }
    if (Values[5] != NULL)
    {
        if (IsWord(Values[5], L"yes"))
            Publish = Immortal = TRUE;
        else if (IsWord(Values[5], L"age"))
            Publish = TRUE;
        else if (!IsWord(Values[5], L"no"))
            return BadValue(Values[5], L"publish");
    }
    Error = LifetimeValue(Values[6], L"validlifetime", &Valid);
    if (Error == ERROR_SUCCESS)
        Error = LifetimeValue(Values[7], L"preferredlifetime", &Preferred);
    if (Error == ERROR_SUCCESS)
        Error = ParseStore(Values[8], &Persistent);
    if (Error == ERROR_SUCCESS)
        Error = ResolveInterface(Values[1], &IfIndex);
    if (Error != ERROR_SUCCESS)
        return Error;

    InitRouteRow(&Row, IfIndex, &Prefix, Length, &NextHop);
    if (Values[3] != NULL)
        Row.SitePrefixLength = (UINT8)SiteLength;
    Row.Metric = Metric;
    Row.ValidLifetime = Valid;
    Row.PreferredLifetime = Preferred;
    Row.Publish = Publish;
    Row.Immortal = Immortal;
    return Finish(NitroConfigureIpv6Route(NITRO_IPV6_CREATE, Persistent, &Row));
}

static
BOOL
RouteMatches(
    _In_ const MIB_IPFORWARD_ROW2 *Row,
    _In_ ULONG IfIndex,
    _In_ const IN6_ADDR *Prefix,
    _In_ ULONG Length)
{
    return Row->InterfaceIndex == IfIndex &&
           Row->DestinationPrefix.Prefix.si_family == AF_INET6 &&
           Row->DestinationPrefix.PrefixLength == Length &&
           memcmp(&Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, Prefix, sizeof(*Prefix)) == 0;
}

static
DWORD
WINAPI
Ipv6DeleteRoute(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"prefix", NS_REQ_PRESENT, FALSE},
                       {L"interface", NS_REQ_PRESENT, FALSE},
                       {L"nexthop", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    MIB_IPFORWARD_ROW2 Row;
    PMIB_IPFORWARD_TABLE2 Tables[2] = {NULL, NULL};
    IN6_ADDR Prefix, NextHop;
    ULONG IfIndex, Length, t, i;
    BOOL Persistent, Found = FALSE, Deleted = FALSE;
    DWORD Error, Failed = ERROR_NOT_FOUND;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!ParseAddress(Values[0], TRUE, 128, &Prefix, &Length))
        return BadValue(Values[0], L"prefix");
    MaskPrefix(&Prefix, Length);
    ZeroMemory(&NextHop, sizeof(NextHop));
    if (Values[2] != NULL && !ParseAddress(Values[2], FALSE, 0, &NextHop, NULL))
        return BadValue(Values[2], L"nexthop");
    Error = ParseStore(Values[3], &Persistent);
    if (Error == ERROR_SUCCESS)
        Error = ResolveInterface(Values[1], &IfIndex);
    if (Error != ERROR_SUCCESS)
        return Error;

    /* a next hop names the route; without one the routes of the prefix over the interface go */
    if (Values[2] != NULL)
    {
        InitRouteRow(&Row, IfIndex, &Prefix, Length, &NextHop);
        return Finish(NitroConfigureIpv6Route(NITRO_IPV6_DELETE, Persistent, &Row));
    }

    GetIpForwardTable2(AF_INET6, &Tables[0]);
    if (Persistent)
        NitroGetPersistentIpv6Routes(&Tables[1]);
    for (t = 0; t < 2; t++)
    {
        for (i = 0; Tables[t] != NULL && i < Tables[t]->NumEntries; i++)
        {
            if (!RouteMatches(&Tables[t]->Table[i], IfIndex, &Prefix, Length))
                continue;
            Found = TRUE;
            Error = NitroConfigureIpv6Route(NITRO_IPV6_DELETE, Persistent, &Tables[t]->Table[i]);
            if (Error == ERROR_SUCCESS)
                Deleted = TRUE;
            else if (Error != ERROR_NOT_FOUND)     /* a route of both tables is deleted by the first */
                Failed = Error;
        }
        if (Tables[t] != NULL)
            FreeMibTable(Tables[t]);
    }

    if (Deleted)
        return ERROR_NETSH_OK;
    return Found ? Failed : ERROR_NOT_FOUND;
}


/* add and delete dnsservers ************************************************/

#define MAX_DNS_SERVERS  16

typedef struct _DNS_LIST
{
    ULONG Count;
    WCHAR Server[MAX_DNS_SERVERS][64];
} DNS_LIST, *PDNS_LIST;

/* Tcpip6\Parameters\Interfaces\{adapter GUID} of an interface */
static
BOOL
AdapterKeyPath(
    _In_ ULONG IfIndex,
    _Out_writes_(Count) PWSTR Path,
    _In_ SIZE_T Count)
{
    NET_LUID Luid;
    GUID Guid;
    WCHAR GuidText[64];

    if (ConvertInterfaceIndexToLuid(IfIndex, &Luid) != NO_ERROR ||
        ConvertInterfaceLuidToGuid(&Luid, &Guid) != NO_ERROR ||
        StringFromGUID2(&Guid, GuidText, ARRAYSIZE(GuidText)) == 0)
        return FALSE;
    return SUCCEEDED(StringCchPrintfW(Path, Count, L"%s%s", IPV6_INTERFACES_KEY, GuidText));
}

/* The statically configured servers of the interface, in order (the NameServer value, separated by commas) */
static
DWORD
ReadServerList(
    _In_ ULONG IfIndex,
    _Out_ PDNS_LIST List)
{
    WCHAR Path[256], Value[1024], *Token, *Context = NULL;
    HKEY hKey;
    DWORD Type, Bytes = sizeof(Value) - sizeof(WCHAR), Error;

    List->Count = 0;
    if (!AdapterKeyPath(IfIndex, Path, ARRAYSIZE(Path)))
        return ERROR_INVALID_PARAMETER;
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey);
    if (Error != ERROR_SUCCESS)
        return ERROR_SUCCESS;       /* nothing configured: the key is made by the first server */
    Error = RegQueryValueExW(hKey, L"NameServer", NULL, &Type, (LPBYTE)Value, &Bytes);
    RegCloseKey(hKey);
    if (Error != ERROR_SUCCESS || Type != REG_SZ)
        return ERROR_SUCCESS;
    Value[Bytes / sizeof(WCHAR)] = UNICODE_NULL;

    for (Token = wcstok_s(Value, L",; ", &Context); Token && List->Count < MAX_DNS_SERVERS;
         Token = wcstok_s(NULL, L",; ", &Context))
    {
        StringCchCopyW(List->Server[List->Count++], ARRAYSIZE(List->Server[0]), Token);
    }
    return ERROR_SUCCESS;
}

static
DWORD
WriteServerList(
    _In_ ULONG IfIndex,
    _In_ const DNS_LIST *List)
{
    WCHAR Path[256], Value[1024];
    HKEY hKey;
    ULONG i;
    DWORD Error;

    if (!AdapterKeyPath(IfIndex, Path, ARRAYSIZE(Path)))
        return ERROR_INVALID_PARAMETER;
    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, Path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                            &hKey, NULL);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (List->Count == 0)
    {
        Error = RegDeleteValueW(hKey, L"NameServer");
        if (Error == ERROR_FILE_NOT_FOUND)
            Error = ERROR_SUCCESS;
    }
    else
    {
        Value[0] = UNICODE_NULL;
        for (i = 0; i < List->Count; i++)
        {
            if (i != 0)
                StringCchCatW(Value, ARRAYSIZE(Value), L",");
            StringCchCatW(Value, ARRAYSIZE(Value), List->Server[i]);
        }
        Error = RegSetValueExW(hKey, L"NameServer", 0, REG_SZ, (const BYTE *)Value,
                               (DWORD)((wcslen(Value) + 1) * sizeof(WCHAR)));
    }
    RegCloseKey(hKey);
    return Error;
}

static
BOOL
SameServer(
    _In_ PCWSTR Text,
    _In_ const IN6_ADDR *Address)
{
    WCHAR Copy[64];
    PWCHAR Percent;
    IN6_ADDR Parsed;
    PCWSTR End;

    StringCchCopyW(Copy, ARRAYSIZE(Copy), Text);
    Percent = wcschr(Copy, L'%');
    if (Percent)
        *Percent = UNICODE_NULL;
    return RtlIpv6StringToAddressW(Copy, &End, &Parsed) == 0 && memcmp(&Parsed, Address, sizeof(Parsed)) == 0;
}

static
DWORD
WINAPI
Ipv6AddDnsServers(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"name", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_PRESENT, FALSE},
                       {L"index", NS_REQ_ZERO, FALSE},
                       {L"validate", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    DNS_LIST List;
    IN6_ADDR Address;
    ULONG IfIndex, Index = 0, i;
    PWSTR End;
    DWORD Error;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (!ParseAddress(Values[1], FALSE, 0, &Address, NULL))
        return BadValue(Values[1], L"address");
    if (Values[2] != NULL)
    {
        Index = iswdigit(Values[2][0]) ? wcstoul(Values[2], &End, 10) : 0;
        if (Index == 0 || *End != UNICODE_NULL)
            return BadValue(Values[2], L"index");
    }
    if (Values[3] != NULL && !IsWord(Values[3], L"yes") && !IsWord(Values[3], L"no"))
        return BadValue(Values[3], L"validate");

    Error = ResolveInterface(Values[0], &IfIndex);
    if (Error == ERROR_SUCCESS)
        Error = ReadServerList(IfIndex, &List);
    if (Error != ERROR_SUCCESS)
        return Error;

    for (i = 0; i < List.Count; i++)
    {
        if (SameServer(List.Server[i], &Address))
            return ERROR_OBJECT_ALREADY_EXISTS;
    }
    if (List.Count >= MAX_DNS_SERVERS || (Index != 0 && Index > List.Count + 1))
        return ERROR_INVALID_PARAMETER;

    /* the server goes to the end, or to the place of the index with the others moved down */
    if (Index == 0)
        Index = List.Count + 1;
    for (i = List.Count; i >= Index; i--)
        wcscpy(List.Server[i], List.Server[i - 1]);
    StringCchCopyW(List.Server[Index - 1], ARRAYSIZE(List.Server[0]), Values[1]);
    List.Count++;

    return Finish(WriteServerList(IfIndex, &List));
}

static
DWORD
WINAPI
Ipv6DeleteDnsServers(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"name", NS_REQ_PRESENT, FALSE},
                       {L"address", NS_REQ_ZERO, FALSE},
                       {L"validate", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    DNS_LIST List;
    IN6_ADDR Address;
    ULONG IfIndex, i;
    BOOL All;
    DWORD Error;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    All = (Values[1] == NULL || _wcsicmp(Values[1], L"all") == 0);
    if (!All && !ParseAddress(Values[1], FALSE, 0, &Address, NULL))
        return BadValue(Values[1], L"address");
    if (Values[2] != NULL && !IsWord(Values[2], L"yes") && !IsWord(Values[2], L"no"))
        return BadValue(Values[2], L"validate");

    Error = ResolveInterface(Values[0], &IfIndex);
    if (Error == ERROR_SUCCESS)
        Error = ReadServerList(IfIndex, &List);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (All)
    {
        List.Count = 0;
    }
    else
    {
        for (i = 0; i < List.Count; i++)
        {
            if (SameServer(List.Server[i], &Address))
                break;
        }
        if (i == List.Count)
            return ERROR_NOT_FOUND;
        for (; i + 1 < List.Count; i++)
            wcscpy(List.Server[i], List.Server[i + 1]);
        List.Count--;
    }
    return Finish(WriteServerList(IfIndex, &List));
}


/* set global ***************************************************************/

static
DWORD
WINAPI
Ipv6SetGlobal(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    /* the order of the Windows command; only randomizeidentifiers and store mean anything to the stack */
    TAG_TYPE Tags[] = {{L"defaultcurhoplimit", NS_REQ_ZERO, FALSE},
                       {L"neighborcachelimit", NS_REQ_ZERO, FALSE},
                       {L"routecachelimit", NS_REQ_ZERO, FALSE},
                       {L"reassemblylimit", NS_REQ_ZERO, FALSE},
                       {L"icmpredirects", NS_REQ_ZERO, FALSE},
                       {L"sourceroutingbehavior", NS_REQ_ZERO, FALSE},
                       {L"taskoffload", NS_REQ_ZERO, FALSE},
                       {L"dhcpmediasense", NS_REQ_ZERO, FALSE},
                       {L"mediasenseeventlog", NS_REQ_ZERO, FALSE},
                       {L"mldlevel", NS_REQ_ZERO, FALSE},
                       {L"mldversion", NS_REQ_ZERO, FALSE},
                       {L"multicastforwarding", NS_REQ_ZERO, FALSE},
                       {L"groupforwardedfragments", NS_REQ_ZERO, FALSE},
                       {L"randomizeidentifiers", NS_REQ_ZERO, FALSE},
                       {L"store", NS_REQ_ZERO, FALSE},
                       {L"addressmaskreply", NS_REQ_ZERO, FALSE},
                       {L"minmtu", NS_REQ_ZERO, FALSE},
                       {L"flowlabel", NS_REQ_ZERO, FALSE},
                       {L"loopbacklargemtu", NS_REQ_ZERO, FALSE},
                       {L"loopbackworkercount", NS_REQ_ZERO, FALSE},
                       {L"loopbackexecutionmode", NS_REQ_ZERO, FALSE},
                       {L"sourcebasedecmp", NS_REQ_ZERO, FALSE},
                       {L"reassemblyoutoforderlimit", NS_REQ_ZERO, FALSE}};
    enum { RANDOMIZE = 13, STORE = 14 };
    PWSTR Values[ARRAYSIZE(Tags)];
    DWORD Randomize = 0, Error, i;
    HKEY hKey;
    BOOL Persistent;

    Error = ParseTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = ParseStore(Values[STORE], &Persistent);
    if (Error != ERROR_SUCCESS)
        return Error;
    if (Values[RANDOMIZE] != NULL)
    {
        if (IsWord(Values[RANDOMIZE], L"enabled"))
            Randomize = 1;
        else if (!IsWord(Values[RANDOMIZE], L"disabled"))
            return BadValue(Values[RANDOMIZE], L"randomizeidentifiers");
    }

    /* what the stack has no setting for is refused, not taken and ignored */
    for (i = 0; i < ARRAYSIZE(Tags); i++)
    {
        if (i != RANDOMIZE && i != STORE && Values[i] != NULL)
            return ERROR_NOT_SUPPORTED;
    }
    /* the stack reads the value when an interface starts: it cannot be applied to the running stack alone */
    if (Values[RANDOMIZE] == NULL)
        return ERROR_NETSH_OK;
    if (!Persistent)
        return ERROR_NOT_SUPPORTED;

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, IPV6_PARAMETERS_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_SET_VALUE, NULL, &hKey, NULL);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = RegSetValueExW(hKey, L"RandomizeIdentifiers", 0, REG_DWORD, (const BYTE *)&Randomize, sizeof(Randomize));
    RegCloseKey(hKey);
    if (Error == ERROR_SUCCESS)
        PrintMessage(L"The change takes effect when the computer restarts.\n");
    return Finish(Error);
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
