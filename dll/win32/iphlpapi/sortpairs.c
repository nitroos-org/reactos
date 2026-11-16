/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CreateSortedAddressPairs: the environment of the address ordering (addrsort.c) from the stack
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include "addrsort.h"
#include <wine/netioapi.h>
#include <strsafe.h>
#include <iphlpapi_nitro.h>

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

#define TCP6_PARAMETERS_KEY     ADDRSEL_PARAMETERS_KEY
#define TCP4_PARAMETERS_KEY     L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define PREFIX_POLICIES_VALUE   ADDRSEL_POLICY_VALUE
/* the documented limit: more destinations are rejected with ERROR_INVALID_PARAMETER */
#define MAX_SORT_ADDRESSES      500

/*
 * The prefix policy table is the Windows default one. HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters,
 * value PrefixPolicies (REG_MULTI_SZ, one "prefix/length precedence label" per string, e.g. "fc00::/7 3 13")
 * replaces the whole table when it holds at least one valid line; netsh can write it. Windows keeps its table in
 * the NSI store, which is not documented, so there is no Windows location to follow. It is read on every call
 * (a few microseconds), so a change applies to the next sort; the stack, which chooses the source addresses with
 * the same table, reads it again when NitroSetPrefixPolicies tells it to (addrsel.h).
 */
/* "netsh interface ipv6 add prefixpolicy ... store=active" keeps its table in a volatile key below the one above, which
   wins over the stored value while it exists (it is gone when the computer restarts); a stored change removes it */
#define ACTIVE_STATE_KEY        ADDRSEL_ACTIVE_STATE_KEY
#define POLICY_LINE_CHARS       ADDRSEL_POLICY_LINE_CHARS
#define POLICY_BUFFER_CHARS     ADDRSEL_POLICY_BUFFER_CHARS

/* The table of the value PrefixPolicies of Key, if it has at least one valid line */
static
ULONG
ReadPolicyValue(HKEY Key, PADDRSORT_POLICY_TABLE Table)
{
    WCHAR *Buffer;
    DWORD Type, Size = POLICY_BUFFER_CHARS * sizeof(WCHAR) - sizeof(WCHAR);
    ULONG Count = 0;

    Buffer = HeapAlloc(GetProcessHeap(), 0, POLICY_BUFFER_CHARS * sizeof(WCHAR));
    if (!Buffer)
        return 0;
    if (RegQueryValueExW(Key, PREFIX_POLICIES_VALUE, NULL, &Type, (LPBYTE)Buffer, &Size) == ERROR_SUCCESS &&
        Type == REG_MULTI_SZ)
    {
        Buffer[Size / sizeof(WCHAR)] = 0;
        Count = AddrSortParsePolicy(Buffer, Size / sizeof(WCHAR) + 1, Table);
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return Count;
}

/* Tcpip\Parameters\Ipv6Enable = 0 is an alias of DisabledComponents = 0xFF (IPv6 on the loopback interface only), which
   includes bit 0x20: prefer IPv4. A DWORD of 0 only; absent or any other value is "on".
   This is read at every call (like DisabledComponents bit 0x20 below), while tcpip reads Ipv6Enable once, at boot:
   after a change without a restart the order follows the new value at once, and the adapters keep their IPv6 until
   the restart. That mixed state is the one a DisabledComponents of 0x20 gives, and it is by design */
static
BOOL
Ipv6EnableIsZero(VOID)
{
    HKEY Key;
    DWORD Type, Value = 1, Size = sizeof(Value);
    BOOL Zero = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TCP4_PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(Key, L"Ipv6Enable", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
        Type == REG_DWORD && Size == sizeof(Value) && Value == 0)
        Zero = TRUE;
    RegCloseKey(Key);
    return Zero;
}

/* Stored: only the stored table (an active-only one is left out) */
static
VOID
LoadPolicyEx(PADDRSORT_POLICY_TABLE Table, BOOL Stored)
{
    HKEY Key, Active;
    DWORD Type, Components = 0, ComponentsSize = sizeof(Components);

    AddrSortDefaultPolicy(Table);
    if (Ipv6EnableIsZero())
        AddrSortPreferIpv4(Table);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TCP6_PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return;
    /* DisabledComponents bit 0x20: prefer IPv4 (a PrefixPolicies value below still replaces the whole table) */
    if (RegQueryValueExW(Key, L"DisabledComponents", NULL, &Type, (LPBYTE)&Components, &ComponentsSize) == ERROR_SUCCESS &&
        Type == REG_DWORD && ComponentsSize == sizeof(Components) && (Components & 0x20))
        AddrSortPreferIpv4(Table);
    ReadPolicyValue(Key, Table);
    if (!Stored && RegOpenKeyExW(Key, ACTIVE_STATE_KEY, 0, KEY_QUERY_VALUE, &Active) == ERROR_SUCCESS)
    {
        ReadPolicyValue(Active, Table);
        RegCloseKey(Active);
    }
    RegCloseKey(Key);
}

VOID
AddrSortLoadPolicy(PADDRSORT_POLICY_TABLE Table)
{
    LoadPolicyEx(Table, FALSE);
}

/* The stack reads the table again (IOCTL_IP6_POLICY_RELOAD); IPv6 off or an older stack: nothing to tell */
static
VOID
ReloadStackPolicy(VOID)
{
    HANDLE TcpFile;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    Status = openTcpFile(&TcpFile, FILE_READ_DATA | FILE_WRITE_DATA);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtDeviceIoControlFile(TcpFile, NULL, NULL, NULL, &Iosb, IOCTL_IP6_POLICY_RELOAD, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(Status))
        TRACE("the stack did not reload the prefix policies: 0x%lx\n", Status);
    closeTcpFile(TcpFile);
}

/* NitroGetPrefixPolicies (iphlpapi_nitro.h): the table CreateSortedAddressPairs uses now, or the stored one */
DWORD WINAPI
NitroGetPrefixPolicies(BOOL Stored, PNITRO_PREFIX_POLICY Rows, PULONG Count)
{
    PADDRSORT_POLICY_TABLE Table;
    ULONG i;

    if (!Count || (*Count && !Rows))
        return ERROR_INVALID_PARAMETER;
    Table = HeapAlloc(GetProcessHeap(), 0, sizeof(*Table));
    if (!Table)
        return ERROR_NOT_ENOUGH_MEMORY;
    LoadPolicyEx(Table, Stored);
    if (Table->Count > *Count)
    {
        *Count = Table->Count;
        HeapFree(GetProcessHeap(), 0, Table);
        return ERROR_MORE_DATA;
    }
    for (i = 0; i < Table->Count; i++)
    {
        RtlCopyMemory(Rows[i].Prefix, Table->Entry[i].Prefix, 16);
        Rows[i].PrefixLength = Table->Entry[i].Length;
        Rows[i].Precedence = Table->Entry[i].Precedence;
        Rows[i].Label = Table->Entry[i].Label;
    }
    *Count = Table->Count;
    HeapFree(GetProcessHeap(), 0, Table);
    return NO_ERROR;
}

/* The lines of the value: "<8 hex groups>/<length> <precedence> <label>" (the full form needs no "::" handling) */
static
DWORD
FormatPolicyLines(const NITRO_PREFIX_POLICY *Rows, ULONG Count, WCHAR *Buffer, ULONG Chars, PULONG Used)
{
    ULONG i, g, Position = 0;

    for (i = 0; i < Count; i++)
    {
        WCHAR Line[POLICY_LINE_CHARS];
        HRESULT hr = S_OK;
        size_t Length;

        Line[0] = UNICODE_NULL;
        for (g = 0; g < 8 && SUCCEEDED(hr); g++)
            hr = StringCchPrintfW(Line + wcslen(Line), ARRAYSIZE(Line) - wcslen(Line), g ? L":%x" : L"%x",
                                  (Rows[i].Prefix[g * 2] << 8) | Rows[i].Prefix[g * 2 + 1]);
        if (SUCCEEDED(hr))
            hr = StringCchPrintfW(Line + wcslen(Line), ARRAYSIZE(Line) - wcslen(Line), L"/%lu %lu %lu",
                                  Rows[i].PrefixLength, Rows[i].Precedence, Rows[i].Label);
        if (FAILED(hr))
            return ERROR_INVALID_PARAMETER;
        Length = wcslen(Line) + 1;
        if (Position + Length + 1 > Chars)
            return ERROR_INSUFFICIENT_BUFFER;
        RtlCopyMemory(Buffer + Position, Line, Length * sizeof(WCHAR));
        Position += (ULONG)Length;
    }
    Buffer[Position++] = UNICODE_NULL;
    *Used = Position;
    return NO_ERROR;
}

/* NitroSetPrefixPolicies (iphlpapi_nitro.h) */
DWORD WINAPI
NitroSetPrefixPolicies(BOOL Persistent, const NITRO_PREFIX_POLICY *Rows, ULONG Count)
{
    WCHAR *Buffer;
    HKEY Key, Active;
    ULONG i, Used = 0, Bits;
    DWORD Error;

    if (!Rows || Count == 0 || Count > NITRO_MAX_PREFIX_POLICIES)
        return ERROR_INVALID_PARAMETER;
    for (i = 0; i < Count; i++)
    {
        if (Rows[i].PrefixLength > 128 || Rows[i].Precedence > NITRO_MAX_POLICY_VALUE ||
            Rows[i].Label > NITRO_MAX_POLICY_VALUE)
            return ERROR_INVALID_PARAMETER;
        /* the bits of the prefix beyond its length are zero */
        for (Bits = Rows[i].PrefixLength; Bits < 128; Bits++)
            if (Rows[i].Prefix[Bits / 8] & (0x80 >> (Bits % 8)))
                return ERROR_INVALID_PARAMETER;
    }

    Buffer = HeapAlloc(GetProcessHeap(), 0, POLICY_BUFFER_CHARS * sizeof(WCHAR));
    if (!Buffer)
        return ERROR_NOT_ENOUGH_MEMORY;
    Error = FormatPolicyLines(Rows, Count, Buffer, POLICY_BUFFER_CHARS, &Used);
    if (Error == NO_ERROR)
        Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, TCP6_PARAMETERS_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                                KEY_SET_VALUE | KEY_CREATE_SUB_KEY, NULL, &Key, NULL);
    if (Error == NO_ERROR)
    {
        if (Persistent)
        {
            Error = RegSetValueExW(Key, PREFIX_POLICIES_VALUE, 0, REG_MULTI_SZ, (const BYTE *)Buffer,
                                   Used * sizeof(WCHAR));
            /* the stored table is in force now: an active-only one must not hide it */
            if (Error == NO_ERROR)
            {
                Error = RegDeleteKeyW(Key, ACTIVE_STATE_KEY);
                if (Error == ERROR_FILE_NOT_FOUND)
                    Error = NO_ERROR;
            }
        }
        else
        {
            Error = RegCreateKeyExW(Key, ACTIVE_STATE_KEY, 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL,
                                    &Active, NULL);
            if (Error == NO_ERROR)
            {
                Error = RegSetValueExW(Active, PREFIX_POLICIES_VALUE, 0, REG_MULTI_SZ, (const BYTE *)Buffer,
                                       Used * sizeof(WCHAR));
                RegCloseKey(Active);
            }
        }
        RegCloseKey(Key);
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    /* the source addresses the stack chooses follow the new table at once, as the sort does */
    if (Error == NO_ERROR)
        ReloadStackPolicy();
    return Error;
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
        /* configured skip-as-source: only the source of a packet to itself, as the stack has it */
        L->SkipAsSource = Row->SkipAsSource ? TRUE : FALSE;
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

    AddrSortLoadPolicy(&Policy);
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
