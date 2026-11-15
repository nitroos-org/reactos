/* Poor man's route
 *
 * Supported commands:
 *
 * "print"
 * "add" target ["mask" mask] gw ["metric" metric]
 * "delete" target gw
 *
 * Goals:
 *
 * Flexible, simple
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <wine/netioapi.h>
#include <ip2string.h>

#include <conutils.h>

#include "resource.h"

#define IPBUF 17
#define IN_ADDR_OF(x) *((struct in_addr *)&(x))

#define DELETE_FLAG       0x1
#define PERSISTENT_FLAG   0x2
#define IPV4_FLAG         0x4
#define IPV6_FLAG         0x8

static
BOOL
MatchWildcard(
    _In_ PWSTR Text,
    _In_ PWSTR Pattern)
{
    size_t TextLength, PatternLength, TextIndex = 0, PatternIndex = 0;
    size_t StartIndex = -1, MatchIndex = 0;

    if (Pattern == NULL)
        return TRUE;

    TextLength = wcslen(Text);
    PatternLength = wcslen(Pattern);

    while (TextIndex < TextLength)
    {
        if ((PatternIndex < PatternLength) &&
            ((Pattern[PatternIndex] == L'?') ||
             (towlower(Pattern[PatternIndex]) == towlower(Text[TextIndex]))))
        {
            TextIndex++;
            PatternIndex++;
        }
        else if ((PatternIndex < PatternLength) &&
                 (Pattern[PatternIndex] == L'*'))
        {
            StartIndex = PatternIndex;
            MatchIndex = TextIndex;
            PatternIndex++;
        }
        else if (StartIndex != -1)
        {
            PatternIndex = StartIndex + 1;
            MatchIndex++;
            TextIndex = MatchIndex;
        }
        else
        {
            return FALSE;
        }
    }

    while ((PatternIndex < PatternLength) &&
           (Pattern[PatternIndex] == L'*'))
    {
        PatternIndex++;
    }

    return (PatternIndex == PatternLength);
}

static
VOID
ParsePersistentRouteValue(
    _In_ PWSTR RouteValue,
    _Out_ PWSTR *Destination,
    _Out_ PWSTR *Netmask,
    _Out_ PWSTR *Gateway,
    _Out_ PWSTR *Metric)
{
    PWSTR Ptr, DestPtr;

    if (Destination)
        *Destination = NULL;

    if (Netmask)
        *Netmask = NULL;

    if (Gateway)
        *Gateway = NULL;

    if (Metric)
        *Metric = NULL;

    DestPtr = RouteValue;
    if (Destination)
        *Destination = DestPtr;

    Ptr = wcschr(DestPtr, L',');
    if (Ptr == NULL)
        return;

    *Ptr = L'\0';
    Ptr++;

    DestPtr = Ptr;
    if (Netmask)
        *Netmask = DestPtr;

    Ptr = wcschr(DestPtr, L',');
    if (Ptr == NULL)
        return;

    *Ptr = L'\0';
    Ptr++;

    DestPtr = Ptr;
    if (Gateway)
        *Gateway = DestPtr;

    Ptr = wcschr(DestPtr, L',');
    if (Ptr == NULL)
        return;

    *Ptr = L'\0';
    Ptr++;

    if (Metric)
        *Metric = Ptr;
}

static
BOOL
ParseCmdLine(
    _In_ int argc,
    _In_ WCHAR **argv,
    _In_ int start,
    _Out_ PWSTR *Destination,
    _Out_ PWSTR *Netmask,
    _Out_ PWSTR *Gateway,
    _Out_ PWSTR *Metric)
{
    int i;

    if (Destination)
        *Destination = NULL;

    if (Netmask)
        *Netmask = NULL;

    if (Gateway)
        *Gateway = NULL;

    if (Metric)
        *Metric = NULL;

    if (argc > start)
    {
        if (Destination)
            *Destination = argv[start];
    }
    else
        return FALSE;

    for (i = start + 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], L"mask"))
        {
            i++;
            if (i >= argc)
                return FALSE;
            if (Netmask)
                *Netmask = argv[i];
        }
        else if (!_wcsicmp(argv[i], L"metric"))
        {
            i++;
            if (i >= argc) 
                return FALSE;
            if (Metric)
                *Metric = argv[i];
        }
        else
        {
            if (Gateway)
                *Gateway = argv[i];
        }
    }

    return TRUE;
}

static
VOID
PrintMacAddress(
    _In_ PBYTE Mac,
    _In_ PWSTR Buffer)
{
    swprintf(Buffer, L"%02x %02x %02x %02x %02x %02x ",
        Mac[0], Mac[1], Mac[2], Mac[3], Mac[4],  Mac[5]);
}

static
DWORD
PrintPersistentRoutes(
    _In_ PWSTR Filter)
{
    WCHAR szBuffer[64];
    DWORD dwIndex = 0, dwBufferSize;
    BOOL EntriesFound = FALSE;
    HKEY hKey;
    DWORD Error = ERROR_SUCCESS;
    PWSTR Destination, Netmask, Gateway, Metric;

    ConResPrintf(StdOut, IDS_SEPARATOR);
    ConResPrintf(StdOut, IDS_PERSISTENT_ROUTES);

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes",
                          0,
                          KEY_READ,
                          &hKey);
    if (Error == ERROR_SUCCESS)
    {
        for (;;)
        {
            dwBufferSize = 64;

            Error = RegEnumValueW(hKey,
                                  dwIndex,
                                  szBuffer,
                                  &dwBufferSize,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL);
            if (Error != ERROR_SUCCESS)
            {
                if (Error == ERROR_NO_MORE_ITEMS)
                    Error = ERROR_SUCCESS;

                break;
            }

            ParsePersistentRouteValue(szBuffer,
                                      &Destination,
                                      &Netmask,
                                      &Gateway,
                                      &Metric);

            if (MatchWildcard(Destination, Filter))
            {
                if (EntriesFound == FALSE)
                    ConResPrintf(StdOut, IDS_PERSISTENT_HEADER);
                ConResPrintf(StdOut, IDS_PERSISTENT_ENTRY, Destination, Netmask, Gateway, Metric);
                EntriesFound = TRUE;
            }

            dwIndex++;
        }

        RegCloseKey(hKey);
    }

    if (EntriesFound == FALSE)
        ConResPrintf(StdOut, IDS_NONE);

    return Error;
}

static
VOID
FormatIPv4Address(
    _Out_ PWCHAR pBuffer,
    _In_ PIP_ADAPTER_UNICAST_ADDRESS UnicastAddress,
    _In_ DWORD IfIndex)
{
    PIP_ADAPTER_UNICAST_ADDRESS Ptr = UnicastAddress;

    while (Ptr)
    {
        if (Ptr->Address.lpSockaddr->sa_family == AF_INET)
        {
            struct sockaddr_in *si = (struct sockaddr_in *)(Ptr->Address.lpSockaddr);
            // DWORD dwStrLen = IPV4_ADDR_STRING_MAX_LEN;
            // WSAAddressToStringW(Ptr->Address.lpSockaddr, (DWORD)Ptr->Address.iSockaddrLength, NULL, pBuffer, &dwStrLen);
            // (void)InetNtopW(AF_INET, &(si->sin_addr), pBuffer, IPV4_ADDR_STRING_MAX_LEN);
            RtlIpv4AddressToStringW(&(si->sin_addr), pBuffer);
            return;
        }

        Ptr = Ptr->Next;
    }

    swprintf(pBuffer, L"%lx", IfIndex);
}

static
VOID
GetFirstIPv4AddressFromIndex(
    _Out_ PWSTR pBuffer,
    _In_ PIP_ADAPTER_ADDRESSES pAdapterAddresses,
    _In_ DWORD IfIndex)
{
    PIP_ADAPTER_ADDRESSES Ptr = pAdapterAddresses;

    while (Ptr)
    {
        if (Ptr->IfIndex == IfIndex)
        {
            FormatIPv4Address(pBuffer, Ptr->FirstUnicastAddress, Ptr->IfIndex);
            return;
        }

        Ptr = Ptr->Next;
    }

    swprintf(pBuffer, L"%lx", IfIndex);
}

static
int
CompareAdapters(
    _In_ const void *elem1,
    _In_ const void *elem2)
{
    PIP_ADAPTER_ADDRESSES a1 = *(PIP_ADAPTER_ADDRESSES *)elem1;
    PIP_ADAPTER_ADDRESSES a2 = *(PIP_ADAPTER_ADDRESSES *)elem2;

    /* highest index first, as the Interface List of Windows */
    if (a1->IfIndex == a2->IfIndex)
        return 0;
    return (a1->IfIndex < a2->IfIndex) ? 1 : -1;
}

/* The adapters of both families, highest index first. The caller frees *ppAdapters and *ppSorted. */
static
DWORD
GetSortedAdapters(
    _Out_ PIP_ADAPTER_ADDRESSES *ppAdapters,
    _Out_ PIP_ADAPTER_ADDRESSES **ppSorted,
    _Out_ unsigned int *pCount)
{
    PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL, Ptr, *pSorted;
    ULONG Size = 15000;
    ULONG Flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    unsigned int Count = 0, i;
    DWORD Error;
    int Tries;

    *ppAdapters = NULL;
    *ppSorted = NULL;
    *pCount = 0;

    for (Tries = 0; Tries < 4; Tries++)
    {
        pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(Size);
        if (pAdapterAddresses == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;

        Error = GetAdaptersAddresses(AF_UNSPEC, Flags, NULL, pAdapterAddresses, &Size);
        if (Error != ERROR_BUFFER_OVERFLOW)
            break;

        free(pAdapterAddresses);
        pAdapterAddresses = NULL;
    }

    if (Error != NO_ERROR)
    {
        free(pAdapterAddresses);
        return Error;
    }

    for (Ptr = pAdapterAddresses; Ptr; Ptr = Ptr->Next)
        Count++;

    pSorted = (PIP_ADAPTER_ADDRESSES *)malloc((Count + 1) * sizeof(PVOID));
    if (pSorted == NULL)
    {
        free(pAdapterAddresses);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    for (Ptr = pAdapterAddresses, i = 0; Ptr; Ptr = Ptr->Next)
        pSorted[i++] = Ptr;
    qsort(pSorted, Count, sizeof(PVOID), CompareAdapters);

    *ppAdapters = pAdapterAddresses;
    *ppSorted = pSorted;
    *pCount = Count;
    return ERROR_SUCCESS;
}

static
VOID
PrintInterfaceList(
    _In_ PIP_ADAPTER_ADDRESSES *pSorted,
    _In_ unsigned int Count)
{
    unsigned int i;
    PIP_ADAPTER_ADDRESSES Ptr;

    ConResPrintf(StdOut, IDS_SEPARATOR);
    ConResPrintf(StdOut, IDS_INTERFACE_LIST);

    for (i = 0; i < Count; i++)
    {
        Ptr = pSorted[i];
        if (Ptr->IfType == IF_TYPE_ETHERNET_CSMACD && Ptr->PhysicalAddressLength == 6)
        {
            WCHAR PhysicalAddress[20];
            PrintMacAddress(Ptr->PhysicalAddress, PhysicalAddress);
            ConResPrintf(StdOut, IDS_ETHERNET_ENTRY, Ptr->IfIndex, PhysicalAddress, Ptr->Description);
        }
        else
        {
            ConResPrintf(StdOut, IDS_INTERFACE_ENTRY, Ptr->IfIndex, Ptr->Description);
        }
    }
    ConResPrintf(StdOut, IDS_SEPARATOR);
}

static
DWORD
PrintIPv4Routes(
    _In_ PWSTR DestinationPattern,
    _In_ PIP_ADAPTER_ADDRESSES pAdapterAddresses)
{
    PMIB_IPFORWARDTABLE IpForwardTable = NULL;
    ULONG Size = 0;
    DWORD Error = ERROR_SUCCESS;
    WCHAR Destination[IPBUF], Gateway[IPBUF], Netmask[IPBUF], Interface[IPBUF];
    unsigned int i;
    BOOL EntriesFound = FALSE;

    if ((GetIpForwardTable(NULL, &Size, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
    {
        if (!(IpForwardTable = malloc(Size)))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Error = GetIpForwardTable(IpForwardTable, &Size, TRUE);
    if (Error != NO_ERROR)
    {
        free(IpForwardTable);
        return Error;
    }

    ConResPrintf(StdOut, IDS_IPV4_ROUTE_TABLE);
    ConResPrintf(StdOut, IDS_SEPARATOR);
    ConResPrintf(StdOut, IDS_ACTIVE_ROUTES);

    for (i = 0; i < IpForwardTable->dwNumEntries; i++)
    {
        PMIB_IPFORWARDROW Row = &IpForwardTable->table[i];
        BOOL OnLink;
        mbstowcs(Destination, inet_ntoa(IN_ADDR_OF(Row->dwForwardDest)), IPBUF);
        mbstowcs(Netmask, inet_ntoa(IN_ADDR_OF(Row->dwForwardMask)), IPBUF);
        mbstowcs(Gateway, inet_ntoa(IN_ADDR_OF(Row->dwForwardNextHop)), IPBUF);
        GetFirstIPv4AddressFromIndex(Interface, pAdapterAddresses, Row->dwForwardIfIndex);
        /* The stack reports every route as direct, so a route is on-link when its next hop is nothing or the
           interface's own address, and goes through a gateway otherwise */
        OnLink = (Row->dwForwardNextHop == 0) || (wcscmp(Gateway, Interface) == 0);

        if (MatchWildcard(Destination, DestinationPattern))
        {
            if (EntriesFound == FALSE)
                ConResPrintf(StdOut, IDS_ROUTES_HEADER);
            /* Windows writes "On-link" one column to the left of an address */
            if (OnLink)
                ConPrintf(StdOut, L"%17s%17s%16s %17s%7lu\n", Destination, Netmask, L"On-link", Interface, Row->dwForwardMetric1);
            else
                ConPrintf(StdOut, L"%17s%17s%17s%17s%7lu\n", Destination, Netmask, Gateway, Interface, Row->dwForwardMetric1);
            EntriesFound = TRUE;
        }
    }

    free(IpForwardTable);
    return ERROR_SUCCESS;
}

static
int
CompareIPv6Routes(
    _In_ const void *elem1,
    _In_ const void *elem2)
{
    const MIB_IPFORWARD_ROW2 *r1 = *(const MIB_IPFORWARD_ROW2 **)elem1;
    const MIB_IPFORWARD_ROW2 *r2 = *(const MIB_IPFORWARD_ROW2 **)elem2;
    int Cmp;

    Cmp = memcmp(&r1->DestinationPrefix.Prefix.Ipv6.sin6_addr,
                 &r2->DestinationPrefix.Prefix.Ipv6.sin6_addr,
                 sizeof(IN6_ADDR));
    if (Cmp != 0)
        return Cmp;
    if (r1->DestinationPrefix.PrefixLength != r2->DestinationPrefix.PrefixLength)
        return (r1->DestinationPrefix.PrefixLength < r2->DestinationPrefix.PrefixLength) ? -1 : 1;
    if (r1->InterfaceIndex != r2->InterfaceIndex)
        return (r1->InterfaceIndex < r2->InterfaceIndex) ? -1 : 1;
    return 0;
}

/* An IPv6 stack that is off (Ipv6Enable=0) has no table: the section stays empty, as for a failed query */
static
DWORD
PrintIPv6Routes(
    _In_ PWSTR DestinationPattern)
{
    PMIB_IPFORWARD_TABLE2 Table = NULL;
    const MIB_IPFORWARD_ROW2 **Rows = NULL;
    ULONG i, Count = 0;
    BOOL EntriesFound = FALSE;

    ConResPrintf(StdOut, IDS_IPV6_ROUTE_TABLE);
    ConResPrintf(StdOut, IDS_SEPARATOR);
    ConResPrintf(StdOut, IDS_ACTIVE_ROUTES);

    if (GetIpForwardTable2(AF_INET6, &Table) != NO_ERROR || Table == NULL)
        return ERROR_SUCCESS;

    if (Table->NumEntries != 0)
        Rows = (const MIB_IPFORWARD_ROW2 **)malloc(Table->NumEntries * sizeof(PVOID));
    if (Rows == NULL)
    {
        FreeMibTable(Table);
        return ERROR_SUCCESS;
    }

    for (i = 0; i < Table->NumEntries; i++)
    {
        if (Table->Table[i].DestinationPrefix.Prefix.si_family == AF_INET6)
            Rows[Count++] = &Table->Table[i];
    }
    qsort(Rows, Count, sizeof(PVOID), CompareIPv6Routes);

    for (i = 0; i < Count; i++)
    {
        const MIB_IPFORWARD_ROW2 *Row = Rows[i];
        MIB_IPINTERFACE_ROW IfRow;
        WCHAR Address[64], Prefix[80], Gateway[64];
        ULONG Metric = Row->Metric;
        static const IN6_ADDR Unspecified = {{{0}}};

        RtlIpv6AddressToStringW(&Row->DestinationPrefix.Prefix.Ipv6.sin6_addr, Address);
        if (!MatchWildcard(Address, DestinationPattern))
            continue;
        swprintf(Prefix, L"%s/%u", Address, (unsigned int)Row->DestinationPrefix.PrefixLength);

        /* the metric shown is the route's plus the interface's, as Windows does */
        memset(&IfRow, 0, sizeof(IfRow));
        IfRow.Family = AF_INET6;
        IfRow.InterfaceIndex = Row->InterfaceIndex;
        if (GetIpInterfaceEntry(&IfRow) == NO_ERROR)
            Metric += IfRow.Metric;

        if (Row->NextHop.si_family != AF_INET6 ||
            memcmp(&Row->NextHop.Ipv6.sin6_addr, &Unspecified, sizeof(Unspecified)) == 0)
            wcscpy(Gateway, L"On-link");
        else
            RtlIpv6AddressToStringW(&Row->NextHop.Ipv6.sin6_addr, Gateway);

        if (EntriesFound == FALSE)
            ConResPrintf(StdOut, IDS_IPV6_ROUTES_HEADER);
        EntriesFound = TRUE;

        ConPrintf(StdOut, L"%3lu %6lu ", Row->InterfaceIndex, Metric);
        /* a prefix that does not fit the column puts the gateway on the next line */
        if (wcslen(Prefix) < 25)
            ConPrintf(StdOut, L"%-25s%s\n", Prefix, Gateway);
        else
            ConPrintf(StdOut, L"%s\n%36s%s\n", Prefix, L"", Gateway);
    }

    free(Rows);
    FreeMibTable(Table);
    return ERROR_SUCCESS;
}

static
DWORD
PrintIPv6PersistentRoutes(VOID)
{
    /* IPv6 persistent routes need the route configuration API: none can exist yet */
    ConResPrintf(StdOut, IDS_SEPARATOR);
    ConResPrintf(StdOut, IDS_PERSISTENT_ROUTES);
    ConResPrintf(StdOut, IDS_NONE);
    return ERROR_SUCCESS;
}

static
DWORD
PrintActiveRoutes(
    _In_ PWSTR DestinationPattern,
    _In_ int flags)
{
    PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL, *pSorted = NULL;
    unsigned int Count = 0;
    DWORD Error;
    BOOL Both = !!(flags & IPV4_FLAG) == !!(flags & IPV6_FLAG);

    Error = GetSortedAdapters(&pAdapterAddresses, &pSorted, &Count);
    if (Error != ERROR_SUCCESS)
    {
        ConResPrintf(StdErr, IDS_ROUTE_ENUM_ERROR);
        return Error;
    }

    PrintInterfaceList(pSorted, Count);

    if (Both || (flags & IPV4_FLAG))
    {
        Error = PrintIPv4Routes(DestinationPattern, pAdapterAddresses);
        if (Error == ERROR_SUCCESS)
            Error = PrintPersistentRoutes(DestinationPattern);
    }

    if (Error == ERROR_SUCCESS && (Both || (flags & IPV6_FLAG)))
    {
        Error = PrintIPv6Routes(DestinationPattern);
        if (Error == ERROR_SUCCESS)
            Error = PrintIPv6PersistentRoutes();
    }

    free(pSorted);
    free(pAdapterAddresses);

    if (Error != ERROR_SUCCESS)
        ConResPrintf(StdErr, IDS_ROUTE_ENUM_ERROR);

    return Error;
}

static
int
PrintRoutes(
    _In_ int argc,
    _In_ WCHAR **argv,
    _In_ int start,
    _In_ int flags)
{
    PWSTR DestinationPattern = NULL;
    DWORD Error;

    /* "route print -4" and "route print -6" work as well as "route -4 print" (Windows 10) */
    while (argc > start && (!wcscmp(argv[start], L"-4") || !wcscmp(argv[start], L"-6")))
    {
        flags |= (argv[start][1] == L'4') ? IPV4_FLAG : IPV6_FLAG;
        start++;
    }

    if (argc > start)
        ParseCmdLine(argc, argv, start, 
                     &DestinationPattern, NULL, NULL, NULL);

    Error = PrintActiveRoutes(DestinationPattern, flags);

    return (Error == ERROR_SUCCESS) ? 0 : 2;
}

static
BOOL
ConvertAddCmdLine(
    _Out_ PMIB_IPFORWARDROW RowToAdd,
    _In_ int argc,
    _In_ WCHAR **argv,
    _In_ int start)
{
    int i;
    char addr[16];

    if (argc > start)
    {
        wcstombs(addr, argv[start], 16);
        RowToAdd->dwForwardDest = inet_addr(addr);
    }
    else
        return FALSE;

    for (i = start + 1; i < argc; i++)
    {
        if (!_wcsicmp(argv[i], L"mask"))
        {
            i++;
            if (i >= argc)
                return FALSE;
            wcstombs(addr, argv[i], 16);
            RowToAdd->dwForwardMask = inet_addr(addr);
        }
        else if (!_wcsicmp(argv[i], L"metric"))
        {
            i++;
            if (i >= argc) 
                return FALSE;
            RowToAdd->dwForwardMetric1 = _wtoi(argv[i]);
        }
        else
        {
            wcstombs(addr, argv[i], 16);
            RowToAdd->dwForwardNextHop = inet_addr(addr);
        }
    }

    /* Restrict metric value to range 1 to 9999 */
    if (RowToAdd->dwForwardMetric1 == 0)
        RowToAdd->dwForwardMetric1 = 1;
    else if (RowToAdd->dwForwardMetric1 > 9999)
        RowToAdd->dwForwardMetric1 = 9999;

    return TRUE;
}

static
DWORD
CreatePersistentIpForwardEntry(
    _In_ PMIB_IPFORWARDROW RowToAdd)
{
    WCHAR Destination[IPBUF], Gateway[IPBUF], Netmask[IPBUF];
    WCHAR ValueName[64];
    HKEY hKey;
    DWORD Error = ERROR_SUCCESS;

    mbstowcs(Destination, inet_ntoa(IN_ADDR_OF(RowToAdd->dwForwardDest)), IPBUF);
    mbstowcs(Netmask, inet_ntoa(IN_ADDR_OF(RowToAdd->dwForwardMask)), IPBUF);
    mbstowcs(Gateway, inet_ntoa(IN_ADDR_OF(RowToAdd->dwForwardNextHop)), IPBUF);

    swprintf(ValueName, L"%s,%s,%s,%ld", Destination, Netmask, Gateway, RowToAdd->dwForwardMetric1);

    Error = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes",
                            0,
                            NULL,
                            REG_OPTION_NON_VOLATILE,
                            KEY_WRITE,
                            NULL,
                            &hKey,
                            NULL);
    if (Error == ERROR_SUCCESS)
    {
        Error = RegSetValueEx(hKey,
                              ValueName,
                              0,
                              REG_SZ,
                              (LPBYTE)L"",
                              sizeof(WCHAR));

        RegCloseKey(hKey);
    }

    return Error;
}

static
DWORD
DeleteCustomRoutes(VOID)
{
    WCHAR Destination[IPBUF], Netmask[IPBUF];
    PMIB_IPFORWARDTABLE IpForwardTable = NULL;
    ULONG Size = 0;
    DWORD Error = ERROR_SUCCESS;
    ULONG i;

    if ((GetIpForwardTable(NULL, &Size, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
    {
        if (!(IpForwardTable = malloc(Size)))
        {
            Error = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }
    }

    Error = GetIpForwardTable(IpForwardTable, &Size, TRUE);
    if (Error != ERROR_SUCCESS)
        goto done;

    for (i = 0; i < IpForwardTable->dwNumEntries; i++)
    {
        mbstowcs(Destination, inet_ntoa(IN_ADDR_OF(IpForwardTable->table[i].dwForwardDest)), IPBUF);
        mbstowcs(Netmask, inet_ntoa(IN_ADDR_OF(IpForwardTable->table[i].dwForwardMask)), IPBUF);

        if ((wcscmp(Netmask, L"255.255.255.255") != 0) &&
            ((wcscmp(Destination, L"127.0.0.0") != 0) || (wcscmp(Netmask, L"255.0.0.0") != 0)) &&
            ((wcscmp(Destination, L"224.0.0.0") != 0) || (wcscmp(Netmask, L"240.0.0.0") != 0)))
        {
            Error = DeleteIpForwardEntry(&IpForwardTable->table[i]);
            if (Error != ERROR_SUCCESS)
                break;
        }
    }

done:
    if (IpForwardTable)
        free(IpForwardTable);

    return Error;
}

static
int
ReportV6Unsupported(
    _In_ UINT ResourceId)
{
    PWSTR Text = NULL;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, ERROR_NOT_SUPPORTED, 0, (PWSTR)&Text, 0, NULL);
    ConResPrintf(StdErr, ResourceId, Text ? Text : L"");
    if (Text)
        LocalFree(Text);
    return 2;
}

static
int
AddRoute(
    _In_ int argc,
    _In_ WCHAR **argv,
    _In_ int start,
    _In_ int flags)
{
    MIB_IPFORWARDROW RowToAdd = { 0 };
    DWORD Error;

    if (argc <= start)
        return 1;

    /* IPv6 routes need the route configuration API of the stack (CreateIpForwardEntry2): until it exists the
       request fails the way Windows words a failed addition, instead of being read as an IPv4 address */
    if ((flags & IPV6_FLAG) || wcschr(argv[start], L':'))
        return ReportV6Unsupported(IDS_ROUTE_ADD_ERROR_EX);

    if (!ConvertAddCmdLine(&RowToAdd, argc, argv, start))
        return 1;

    /* The route leaves through the interface that reaches its gateway: the row needs the interface
       index, and index 0 is no interface (it used to select the first IP entity, the loopback) */
    if (RowToAdd.dwForwardIfIndex == 0)
        GetBestInterface(RowToAdd.dwForwardNextHop, &RowToAdd.dwForwardIfIndex);

    if (flags & DELETE_FLAG)
        DeleteCustomRoutes();

    if (flags & PERSISTENT_FLAG)
        Error = CreatePersistentIpForwardEntry(&RowToAdd);
    else
        Error = CreateIpForwardEntry(&RowToAdd);
    if (Error != ERROR_SUCCESS)
    {
        ConResPrintf(StdErr, IDS_ROUTE_ADD_ERROR);
        return 2;
    }

    return 0;
}

static
DWORD
DeleteActiveRoutes(
    PWSTR DestinationPattern)
{
    WCHAR Destination[IPBUF], Netmask[IPBUF];
    PMIB_IPFORWARDTABLE IpForwardTable = NULL;
    ULONG Size = 0;
    DWORD Error = ERROR_SUCCESS;
    ULONG i;

    if ((GetIpForwardTable(NULL, &Size, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
    {
        if (!(IpForwardTable = malloc(Size)))
        {
            Error = ERROR_NOT_ENOUGH_MEMORY;
            goto done;
        }
    }

    Error = GetIpForwardTable(IpForwardTable, &Size, TRUE);
    if (Error != ERROR_SUCCESS)
        goto done;

    for (i = 0; i < IpForwardTable->dwNumEntries; i++)
    {
        mbstowcs(Destination, inet_ntoa(IN_ADDR_OF(IpForwardTable->table[i].dwForwardDest)), IPBUF);
        mbstowcs(Netmask, inet_ntoa(IN_ADDR_OF(IpForwardTable->table[i].dwForwardMask)), IPBUF);

        if (MatchWildcard(Destination, DestinationPattern))
        {
            Error = DeleteIpForwardEntry(&IpForwardTable->table[i]);
            if (Error != ERROR_SUCCESS)
                break;
        }
    }

done:
    if (IpForwardTable)
        free(IpForwardTable);

    return Error;
}

static
DWORD
DeletePersistentRoutes(
    PWSTR DestinationPattern)
{

    WCHAR szBuffer[64];
    DWORD dwIndex = 0, dwBufferSize;
    HKEY hKey;
    DWORD Error = ERROR_SUCCESS;
    PWSTR Destination = NULL;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes",
                          0,
                          KEY_READ,
                          &hKey);
    if (Error == ERROR_SUCCESS)
    {
        for (;;)
        {
            dwBufferSize = 64;

            Error = RegEnumValueW(hKey,
                                  dwIndex,
                                  szBuffer,
                                  &dwBufferSize,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL);
            if (Error != ERROR_SUCCESS)
            {
                if (Error == ERROR_NO_MORE_ITEMS)
                    Error = ERROR_SUCCESS;

                break;
            }

            ParsePersistentRouteValue(szBuffer,
                                      &Destination,
                                      NULL,
                                      NULL,
                                      NULL);

            if (MatchWildcard(Destination, DestinationPattern))
            {
                Error = RegDeleteValueW(hKey, szBuffer);
                if (Error != ERROR_SUCCESS)
                    break;
            }

            dwIndex++;
        }

        RegCloseKey(hKey);
    }

    return Error;
}

static int
DeleteRoutes(
    _In_ int argc,
    _In_ WCHAR **argv,
    _In_ int start,
    _In_ int flags)
{
    PWSTR DestinationPattern = NULL;
    DWORD Error;

    if ((argc <= start) ||
        !ParseCmdLine(argc, argv, start, 
                      &DestinationPattern, NULL, NULL, NULL))
        return 1;

    if ((flags & IPV6_FLAG) || wcschr(DestinationPattern, L':'))
        return ReportV6Unsupported(IDS_ROUTE_DEL_ERROR_EX);

    if (flags & DELETE_FLAG)
        DeleteCustomRoutes();

    Error = DeleteActiveRoutes(DestinationPattern);
    if (Error == ERROR_SUCCESS)
        Error = DeletePersistentRoutes(DestinationPattern);

    if (Error != ERROR_SUCCESS)
    {
        ConResPrintf(StdErr, IDS_ROUTE_DEL_ERROR);
        return 2;
    }

    return 0;
}

int
wmain(
    _In_ int argc,
    _In_ WCHAR **argv)
{
    int i, flags = 0, ret = 0;

    /* Initialize the Console Standard Streams */
    ConInitStdStreams();

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == L'-' || argv[i][0] == L'/')
        {
            if (!_wcsicmp(&argv[i][1], L"f"))
            {
                flags |= DELETE_FLAG;
            }
            else if (!_wcsicmp(&argv[i][1], L"p"))
            {
                flags |= PERSISTENT_FLAG;
            }
            else if (!wcscmp(&argv[i][1], L"4"))
            {
                flags |= IPV4_FLAG;
            }
            else if (!wcscmp(&argv[i][1], L"6"))
            {
                flags |= IPV6_FLAG;
            }
            else
            {
                ret = 1;
                break;
            }
        }
        else
        {
            if (!_wcsicmp(argv[i], L"print"))
                ret = PrintRoutes(argc, argv, i + 1, flags);
            else if (!_wcsicmp(argv[i], L"add"))
                ret = AddRoute(argc, argv, i + 1, flags);
            else if (!_wcsicmp(argv[i], L"delete"))
                ret = DeleteRoutes(argc, argv, i + 1, flags);
            else
                ret = 1;

            break;
        }
    }

    if (argc == 1)
        ret = 1;

    if (ret == 1)
    {
        ConResPrintf(StdErr, IDS_USAGE1);
//        ConResPrintf(StdErr, IDS_USAGE2);
        ConResPrintf(StdErr, IDS_USAGE3);
    }

    return (ret == 0) ? 0 : 1;
}
