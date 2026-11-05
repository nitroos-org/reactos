/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the Vista interface and address tables: GetIfTable2, GetIpInterfaceTable,
 *              GetUnicastIpAddressTable, InitializeIpInterfaceEntry, the interface name and luid conversions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

/* The rows of the Windows SDK, under private names: the headers of this tree do not declare them. */
typedef struct
{
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    GUID InterfaceGuid;
    WCHAR Alias[IF_MAX_STRING_SIZE + 1];
    WCHAR Description[IF_MAX_STRING_SIZE + 1];
    ULONG PhysicalAddressLength;
    UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
    UCHAR PermanentPhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
    ULONG Mtu;
    ULONG Type;
    ULONG TunnelType;
    ULONG MediaType;
    ULONG PhysicalMediumType;
    ULONG AccessType;
    ULONG DirectionType;
    UCHAR Flags;
    ULONG OperStatus;
    ULONG AdminStatus;
    ULONG MediaConnectState;
    GUID NetworkGuid;
    ULONG ConnectionType;
    ULONG64 TransmitLinkSpeed;
    ULONG64 ReceiveLinkSpeed;
    ULONG64 InOctets;
    ULONG64 InUcastPkts;
    ULONG64 InNUcastPkts;
    ULONG64 InDiscards;
    ULONG64 InErrors;
    ULONG64 InUnknownProtos;
    ULONG64 InUcastOctets;
    ULONG64 InMulticastOctets;
    ULONG64 InBroadcastOctets;
    ULONG64 OutOctets;
    ULONG64 OutUcastPkts;
    ULONG64 OutNUcastPkts;
    ULONG64 OutDiscards;
    ULONG64 OutErrors;
    ULONG64 OutUcastOctets;
    ULONG64 OutMulticastOctets;
    ULONG64 OutBroadcastOctets;
    ULONG64 OutQLen;
} IF_ROW2;

typedef struct
{
    ULONG NumEntries;
    IF_ROW2 Table[1];
} IF_TABLE2;

#define IF_FLAG_NOT_MEDIA_CONNECTED 0x10
#define OPER_UP 1
#define MEDIA_CONNECTED 1
#define ADMIN_UP 1
#define ACCESS_LOOPBACK 1
#define ACCESS_BROADCAST 2

typedef struct
{
    USHORT Family;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    ULONG MaxReassemblySize;
    ULONG64 InterfaceIdentifier;
    ULONG MinRouterAdvertisementInterval;
    ULONG MaxRouterAdvertisementInterval;
    BOOLEAN AdvertisingEnabled;
    BOOLEAN ForwardingEnabled;
    BOOLEAN WeakHostSend;
    BOOLEAN WeakHostReceive;
    BOOLEAN UseAutomaticMetric;
    BOOLEAN UseNeighborUnreachabilityDetection;
    BOOLEAN ManagedAddressConfigurationSupported;
    BOOLEAN OtherStatefulConfigurationSupported;
    BOOLEAN AdvertiseDefaultRoute;
    ULONG RouterDiscoveryBehavior;
    ULONG DadTransmits;
    ULONG BaseReachableTime;
    ULONG RetransmitTime;
    ULONG PathMtuDiscoveryTimeout;
    ULONG LinkLocalAddressBehavior;
    ULONG LinkLocalAddressTimeout;
    ULONG ZoneIndices[16];
    ULONG SitePrefixLength;
    ULONG Metric;
    ULONG NlMtu;
    BOOLEAN Connected;
    BOOLEAN SupportsWakeUpPatterns;
    BOOLEAN SupportsNeighborDiscovery;
    BOOLEAN SupportsRouterDiscovery;
    ULONG ReachableTime;
    UCHAR TransmitOffload;
    UCHAR ReceiveOffload;
    BOOLEAN DisableDefaultRoutes;
} IPIF_ROW;

typedef struct
{
    ULONG NumEntries;
    IPIF_ROW Table[1];
} IPIF_TABLE;

typedef struct
{
    SOCKADDR_INET Address;
    NET_LUID InterfaceLuid;
    ULONG InterfaceIndex;
    ULONG PrefixOrigin;
    ULONG SuffixOrigin;
    ULONG ValidLifetime;
    ULONG PreferredLifetime;
    UINT8 OnLinkPrefixLength;
    BOOLEAN SkipAsSource;
    ULONG DadState;
    ULONG ScopeId;
    LARGE_INTEGER CreationTimeStamp;
} UNI_ROW;

typedef struct
{
    ULONG NumEntries;
    UNI_ROW Table[1];
} UNI_TABLE;

typedef DWORD (WINAPI *PGET_IF_TABLE2)(IF_TABLE2 **);
typedef DWORD (WINAPI *PGET_IF_TABLE2EX)(ULONG, IF_TABLE2 **);
typedef DWORD (WINAPI *PGET_IF_ENTRY2)(IF_ROW2 *);
typedef DWORD (WINAPI *PGET_IPIF_TABLE)(USHORT, IPIF_TABLE **);
typedef DWORD (WINAPI *PGET_IPIF_ENTRY)(IPIF_ROW *);
typedef VOID (WINAPI *PINIT_IPIF_ENTRY)(IPIF_ROW *);
typedef DWORD (WINAPI *PGET_UNI_TABLE)(USHORT, UNI_TABLE **);
typedef DWORD (WINAPI *PGET_UNI_ENTRY)(UNI_ROW *);
typedef VOID (WINAPI *PFREE_MIB_TABLE)(PVOID);
typedef PCHAR (WINAPI *PIF_INDEXTONAME)(ULONG, PCHAR);
typedef ULONG (WINAPI *PIF_NAMETOINDEX)(PCSTR);
typedef DWORD (WINAPI *PCONV_INDEX_TO_LUID)(ULONG, NET_LUID *);
typedef DWORD (WINAPI *PCONV_LUID_TO_INDEX)(const NET_LUID *, ULONG *);
typedef DWORD (WINAPI *PCONV_LUID_TO_NAMEA)(const NET_LUID *, PSTR, SIZE_T);
typedef DWORD (WINAPI *PCONV_NAMEA_TO_LUID)(const char *, NET_LUID *);
typedef DWORD (WINAPI *PCONV_LUID_TO_ALIAS)(const NET_LUID *, PWSTR, SIZE_T);
typedef DWORD (WINAPI *PCONV_ALIAS_TO_LUID)(const WCHAR *, NET_LUID *);
typedef DWORD (WINAPI *PCONV_LUID_TO_GUID)(const NET_LUID *, GUID *);
typedef DWORD (WINAPI *PCONV_GUID_TO_LUID)(const GUID *, NET_LUID *);

static PGET_IF_TABLE2 pGetIfTable2;
static PGET_IF_TABLE2EX pGetIfTable2Ex;
static PGET_IF_ENTRY2 pGetIfEntry2;
static PGET_IPIF_TABLE pGetIpInterfaceTable;
static PGET_IPIF_ENTRY pGetIpInterfaceEntry;
static PINIT_IPIF_ENTRY pInitializeIpInterfaceEntry;
static PGET_UNI_TABLE pGetUnicastIpAddressTable;
static PGET_UNI_ENTRY pGetUnicastIpAddressEntry;
static PFREE_MIB_TABLE pFreeMibTable;
static PIF_INDEXTONAME pif_indextoname;
static PIF_NAMETOINDEX pif_nametoindex;
static PCONV_INDEX_TO_LUID pConvertInterfaceIndexToLuid;
static PCONV_LUID_TO_INDEX pConvertInterfaceLuidToIndex;
static PCONV_LUID_TO_NAMEA pConvertInterfaceLuidToNameA;
static PCONV_NAMEA_TO_LUID pConvertInterfaceNameToLuidA;
static PCONV_LUID_TO_ALIAS pConvertInterfaceLuidToAlias;
static PCONV_ALIAS_TO_LUID pConvertInterfaceAliasToLuid;
static PCONV_LUID_TO_GUID pConvertInterfaceLuidToGuid;
static PCONV_GUID_TO_LUID pConvertInterfaceGuidToLuid;

#define LOOPBACK_LUID 0x0018000000000000ULL
#define SENTINEL ((PVOID)(ULONG_PTR)0x12345678)

static BOOL is_loopback(const IF_ROW2 *Row)
{
    return Row->Type == IF_TYPE_SOFTWARE_LOOPBACK;
}

static const IF_ROW2 *find_if_luid(const IF_TABLE2 *Table, ULONG64 Luid)
{
    ULONG i;

    for (i = 0; i < Table->NumEntries; i++)
        if (Table->Table[i].InterfaceLuid.Value == Luid)
            return &Table->Table[i];
    return NULL;
}

static void test_initialize(void)
{
    IPIF_ROW Row;
    ULONG i;

    memset(&Row, 0xcc, sizeof(Row));
    pInitializeIpInterfaceEntry(&Row);
    ok(Row.Family == AF_UNSPEC, "Family %u\n", Row.Family);
    ok(Row.InterfaceLuid.Value == 0, "Luid %I64x\n", Row.InterfaceLuid.Value);
    ok(Row.InterfaceIndex == 0, "Index %lu\n", Row.InterfaceIndex);
    ok(Row.NlMtu == 0, "NlMtu %lu\n", Row.NlMtu);
    ok(Row.BaseReachableTime == 0, "BaseReachableTime %lu\n", Row.BaseReachableTime);
    ok(Row.RetransmitTime == 0, "RetransmitTime %lu\n", Row.RetransmitTime);
    ok(Row.PathMtuDiscoveryTimeout == 0, "PathMtuDiscoveryTimeout %lu\n", Row.PathMtuDiscoveryTimeout);
    ok(Row.MaxReassemblySize == 0xffffffff, "MaxReassemblySize %lx\n", Row.MaxReassemblySize);
    ok(Row.Metric == 0xffffffff, "Metric %lx\n", Row.Metric);
    ok(Row.DadTransmits == 0xffffffff, "DadTransmits %lx\n", Row.DadTransmits);
    ok(Row.LinkLocalAddressTimeout == 0xffffffff, "LinkLocalAddressTimeout %lx\n", Row.LinkLocalAddressTimeout);
    ok(Row.SitePrefixLength == 0xffffffff, "SitePrefixLength %lx\n", Row.SitePrefixLength);
    ok(Row.ReachableTime == 0xffffffff, "ReachableTime %lx\n", Row.ReachableTime);
    for (i = 0; i < 16; i++)
        ok(Row.ZoneIndices[i] == 0xffffffff, "ZoneIndices[%lu] %lx\n", i, Row.ZoneIndices[i]);
    ok(Row.AdvertisingEnabled == 0xff, "AdvertisingEnabled %x\n", Row.AdvertisingEnabled);
    ok(Row.DisableDefaultRoutes == 0xff, "DisableDefaultRoutes %x\n", Row.DisableDefaultRoutes);
}

static void test_if_table2(IF_TABLE2 *Table)
{
    ULONG i, j, Loopbacks = 0;
    IF_TABLE2 *Other;
    DWORD Error;

    ok(Table->NumEntries >= 1, "No interfaces\n");
    for (i = 0; i < Table->NumEntries; i++)
    {
        const IF_ROW2 *Row = &Table->Table[i];

        ok(Row->InterfaceLuid.Value != 0, "Row %lu has no luid\n", i);
        ok((ULONG)(Row->InterfaceLuid.Value >> 48) == Row->Type,
           "Row %lu: luid %I64x does not carry type %lu\n", i, Row->InterfaceLuid.Value, Row->Type);
        ok(Row->Alias[0] != 0, "Row %lu has no alias\n", i);
        ok(Row->Description[0] != 0, "Row %lu has no description\n", i);
        ok(Row->PhysicalAddressLength <= IF_MAX_PHYS_ADDRESS_LENGTH, "Row %lu: address length %lu\n",
           i, Row->PhysicalAddressLength);
        ok(Row->AdminStatus >= 1 && Row->AdminStatus <= 3, "Row %lu: admin status %d\n", i, Row->AdminStatus);
        ok(Row->OperStatus >= 1 && Row->OperStatus <= 7, "Row %lu: oper status %d\n", i, Row->OperStatus);
        for (j = i + 1; j < Table->NumEntries; j++)
        {
            ok(Row->InterfaceLuid.Value != Table->Table[j].InterfaceLuid.Value, "Rows %lu and %lu share a luid\n", i, j);
            ok(Row->InterfaceIndex != Table->Table[j].InterfaceIndex, "Rows %lu and %lu share index %lu\n",
               i, j, Row->InterfaceIndex);
        }
        if (Row->OperStatus == OPER_UP)
            ok(Row->MediaConnectState == MEDIA_CONNECTED, "Row %lu: up but media state %d\n",
               i, Row->MediaConnectState);
        ok(Row->InterfaceIndex != 0, "Row %lu has no index\n", i);

        if (is_loopback(Row))
        {
            Loopbacks++;
            ok(Row->InterfaceLuid.Value == LOOPBACK_LUID, "Loopback luid %I64x\n", Row->InterfaceLuid.Value);
            ok(Row->AccessType == ACCESS_LOOPBACK, "Loopback access type %d\n", Row->AccessType);
            ok(Row->OperStatus == OPER_UP, "Loopback oper status %d\n", Row->OperStatus);
            ok(Row->MediaConnectState == MEDIA_CONNECTED, "Loopback media state %d\n", Row->MediaConnectState);
            ok(Row->AdminStatus == ADMIN_UP, "Loopback admin status %d\n", Row->AdminStatus);
            ok(Row->PhysicalAddressLength == 0, "Loopback address length %lu\n", Row->PhysicalAddressLength);
            ok(Row->Mtu > 0, "Loopback MTU\n");
        }
        else if (Row->Type == IF_TYPE_ETHERNET_CSMACD && Row->OperStatus == OPER_UP &&
                 Row->PhysicalAddressLength == 6)
        {
            ok(Row->AccessType == ACCESS_BROADCAST, "Ethernet access type %d\n", Row->AccessType);
            ok(Row->Mtu >= 576 && Row->Mtu <= 65535, "Ethernet MTU %lu\n", Row->Mtu);
            ok(Row->TransmitLinkSpeed > 0 && Row->ReceiveLinkSpeed > 0, "Ethernet speed\n");
            ok(!(Row->Flags & IF_FLAG_NOT_MEDIA_CONNECTED), "Ethernet flagged as not connected\n");
        }
    }
    ok(Loopbacks == 1, "%lu loopback interfaces\n", Loopbacks);

    /* level 0 and 1 carry statistics, level 2 does not */
    Other = SENTINEL;
    Error = pGetIfTable2Ex(2, &Other);
    ok(Error == NO_ERROR, "GetIfTable2Ex(2): %lu\n", Error);
    if (Error == NO_ERROR)
    {
        ok(Other->NumEntries == Table->NumEntries, "Level 2 has %lu entries, level 0 has %lu\n",
           Other->NumEntries, Table->NumEntries);
        for (i = 0; i < Other->NumEntries; i++)
        {
            ok(Other->Table[i].InOctets == 0 && Other->Table[i].OutOctets == 0 && Other->Table[i].InUcastPkts == 0,
               "Level 2 row %lu carries statistics\n", i);
        }
        pFreeMibTable(Other);
    }
    Other = SENTINEL;
    Error = pGetIfTable2Ex(1, &Other);
    ok(Error == NO_ERROR, "GetIfTable2Ex(1): %lu\n", Error);
    if (Error == NO_ERROR)
        pFreeMibTable(Other);
    Other = SENTINEL;
    Error = pGetIfTable2Ex(3, &Other);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIfTable2Ex(3): %lu\n", Error);
}

static void test_if_entry2(const IF_TABLE2 *Table)
{
    IF_ROW2 Row, ByLuid;
    ULONG i;
    DWORD Error;

    memset(&Row, 0, sizeof(Row));
    Error = pGetIfEntry2(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIfEntry2(empty): %lu\n", Error);
    Error = pGetIfEntry2(NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIfEntry2(NULL): %lu\n", Error);

    memset(&Row, 0, sizeof(Row));
    Row.InterfaceLuid.Value = 0x0006FFFFFF000000ULL;
    Error = pGetIfEntry2(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "GetIfEntry2(unknown luid): %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.InterfaceIndex = 0x7ffffff0;
    Error = pGetIfEntry2(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "GetIfEntry2(unknown index): %lu\n", Error);

    for (i = 0; i < Table->NumEntries; i++)
    {
        const IF_ROW2 *Expected = &Table->Table[i];

        memset(&ByLuid, 0, sizeof(ByLuid));
        ByLuid.InterfaceLuid = Expected->InterfaceLuid;
        Error = pGetIfEntry2(&ByLuid);
        ok(Error == NO_ERROR, "GetIfEntry2(luid %I64x): %lu\n", Expected->InterfaceLuid.Value, Error);
        if (Error != NO_ERROR)
            continue;
        ok(ByLuid.InterfaceIndex == Expected->InterfaceIndex, "Index %lu, expected %lu\n",
           ByLuid.InterfaceIndex, Expected->InterfaceIndex);
        ok(ByLuid.Type == Expected->Type && ByLuid.Mtu == Expected->Mtu, "Type or MTU differ\n");
        ok(!wcscmp(ByLuid.Alias, Expected->Alias), "Alias %ls, expected %ls\n", ByLuid.Alias, Expected->Alias);
        ok(!memcmp(&ByLuid.InterfaceGuid, &Expected->InterfaceGuid, sizeof(GUID)), "Guid differs\n");
        ok(ByLuid.OperStatus == Expected->OperStatus, "Oper status differs\n");

        memset(&Row, 0, sizeof(Row));
        Row.InterfaceIndex = Expected->InterfaceIndex;
        Error = pGetIfEntry2(&Row);
        ok(Error == NO_ERROR, "GetIfEntry2(index %lu): %lu\n", Expected->InterfaceIndex, Error);
        ok(Row.InterfaceLuid.Value == Expected->InterfaceLuid.Value, "Luid %I64x, expected %I64x\n",
           Row.InterfaceLuid.Value, Expected->InterfaceLuid.Value);
    }

    /* the luid wins over the index */
    memset(&Row, 0, sizeof(Row));
    Row.InterfaceLuid.Value = LOOPBACK_LUID;
    Row.InterfaceIndex = 0x7ffffff0;
    Error = pGetIfEntry2(&Row);
    ok(Error == NO_ERROR, "GetIfEntry2(loopback luid, bad index): %lu\n", Error);
    ok(Row.Type == IF_TYPE_SOFTWARE_LOOPBACK, "Type %lu\n", Row.Type);
}

static void test_ip_interface(const IF_TABLE2 *IfTable, USHORT Family)
{
    IPIF_TABLE *Table = SENTINEL;
    ULONG i, Loopbacks = 0;
    DWORD Error;

    Error = pGetIpInterfaceTable(Family, &Table);
    ok(Error == NO_ERROR, "GetIpInterfaceTable(%u): %lu\n", Family, Error);
    if (Error != NO_ERROR)
        return;
    ok(Table != NULL && Table != SENTINEL, "Table %p\n", Table);
    if (!Table || Table == SENTINEL)
        return;

    for (i = 0; i < Table->NumEntries; i++)
    {
        const IPIF_ROW *Row = &Table->Table[i];
        const IF_ROW2 *If = find_if_luid(IfTable, Row->InterfaceLuid.Value);
        IPIF_ROW Entry;

        ok(Row->Family == AF_INET || Row->Family == AF_INET6, "Row %lu: family %u\n", i, Row->Family);
        if (Family != AF_UNSPEC)
            ok(Row->Family == Family, "Row %lu: family %u, asked for %u\n", i, Row->Family, Family);
        ok(If != NULL, "Row %lu: luid %I64x is not in GetIfTable2\n", i, Row->InterfaceLuid.Value);
        if (!If)
            continue;
        ok(Row->InterfaceIndex == If->InterfaceIndex, "Row %lu: index %lu, GetIfTable2 says %lu\n",
           i, Row->InterfaceIndex, If->InterfaceIndex);
        ok(Row->Connected == (If->OperStatus == OPER_UP), "Row %lu: connected %u, oper status %d\n",
           i, Row->Connected, If->OperStatus);
        ok(Row->NlMtu != 0, "Row %lu: no MTU\n", i);
        ok(Row->Metric != 0 && Row->Metric < 1000, "Row %lu: metric %lu\n", i, Row->Metric);
        /* a metric set by hand (Tcpip registry InterfaceMetric) is not automatic: test_manual_metric covers that */
        ok(Row->UseAutomaticMetric || Row->Metric <= 9999, "Row %lu: metric %lu\n", i, Row->Metric);
        ok(Row->ZoneIndices[0] == Row->InterfaceIndex, "Row %lu: zone %lu, index %lu\n",
           i, Row->ZoneIndices[0], Row->InterfaceIndex);
        ok(!Row->ForwardingEnabled && !Row->AdvertisingEnabled, "Row %lu: router\n", i);

        if (If->Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            if (Row->Family == AF_INET)
                Loopbacks++;
            ok(Row->NlMtu == 0xffffffff, "Loopback MTU %lx\n", Row->NlMtu);
            ok(Row->Metric == 75, "Loopback metric %lu\n", Row->Metric);
            ok(Row->Connected, "Loopback not connected\n");
        }
        else
        {
            ok(Row->NlMtu == If->Mtu, "Row %lu: MTU %lu, GetIfTable2 says %lu\n", i, Row->NlMtu, If->Mtu);
        }

        /* the same row by luid, and by index */
        memset(&Entry, 0, sizeof(Entry));
        Entry.Family = Row->Family;
        Entry.InterfaceLuid = Row->InterfaceLuid;
        Error = pGetIpInterfaceEntry(&Entry);
        ok(Error == NO_ERROR, "GetIpInterfaceEntry(luid %I64x): %lu\n", Row->InterfaceLuid.Value, Error);
        if (Error == NO_ERROR)
        {
            ok(Entry.InterfaceIndex == Row->InterfaceIndex && Entry.Metric == Row->Metric &&
               Entry.NlMtu == Row->NlMtu && Entry.Connected == Row->Connected, "Entry differs from the table row\n");
        }
        if (Row->InterfaceIndex)
        {
            memset(&Entry, 0, sizeof(Entry));
            Entry.Family = Row->Family;
            Entry.InterfaceIndex = Row->InterfaceIndex;
            Error = pGetIpInterfaceEntry(&Entry);
            ok(Error == NO_ERROR, "GetIpInterfaceEntry(index %lu): %lu\n", Row->InterfaceIndex, Error);
            ok(Entry.InterfaceLuid.Value == Row->InterfaceLuid.Value, "Entry luid %I64x\n", Entry.InterfaceLuid.Value);
        }
    }
    if (Family == AF_INET)
        ok(Loopbacks == 1, "%lu IPv4 loopback interfaces\n", Loopbacks);
    pFreeMibTable(Table);
}

static void test_ip_interface_errors(void)
{
    IPIF_TABLE *Table;
    IPIF_ROW Row;
    DWORD Error;

    Table = SENTINEL;
    Error = pGetIpInterfaceTable(99, &Table);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIpInterfaceTable(99): %lu\n", Error);
    Error = pGetIpInterfaceTable(AF_INET, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIpInterfaceTable(NULL): %lu\n", Error);

    Error = pGetIpInterfaceEntry(NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIpInterfaceEntry(NULL): %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIpInterfaceEntry(empty): %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.Family = 99;
    Row.InterfaceLuid.Value = LOOPBACK_LUID;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIpInterfaceEntry(family 99): %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceIndex = 0x7ffffff0;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "GetIpInterfaceEntry(unknown index): %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid.Value = 0x0006FFFFFF000000ULL;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == ERROR_NOT_FOUND, "GetIpInterfaceEntry(unknown luid): %lu\n", Error);
    /* the luid wins over the index */
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid.Value = LOOPBACK_LUID;
    Row.InterfaceIndex = 0x7ffffff0;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "GetIpInterfaceEntry(loopback luid, bad index): %lu\n", Error);
    ok(Row.InterfaceLuid.Value == LOOPBACK_LUID, "Luid %I64x\n", Row.InterfaceLuid.Value);
}

/* ReactOS: the stack reads the InterfaceMetric value of Tcpip\Parameters\Interfaces\{guid} at bind time, and the IP interface
 * rows report it (the same value netsh and Set-NetIPInterface write): a value is a fixed metric (at most 9999), none or 0 the
 * automatic one. Windows takes the change from its own stack, not from the registry, so this is a ReactOS-only check. */
static void test_manual_metric(const IF_TABLE2 *IfTable)
{
    static const WCHAR Prefix[] = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
    WCHAR Path[160], GuidText[40];
    const IF_ROW2 *Nic = NULL;
    IPIF_ROW Row;
    HKEY Key;
    DWORD Old = 0, Size, Type, Value, Error;
    BOOL HadOld;
    ULONG i;

    for (i = 0; i < IfTable->NumEntries; i++)
    {
        if (!is_loopback(&IfTable->Table[i]) && IfTable->Table[i].InterfaceGuid.Data1 != 0)
        {
            Nic = &IfTable->Table[i];
            break;
        }
    }
    if (!Nic)
    {
        skip("No adapter\n");
        return;
    }
    _snwprintf(GuidText, ARRAYSIZE(GuidText), L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", Nic->InterfaceGuid.Data1, Nic->InterfaceGuid.Data2,
             Nic->InterfaceGuid.Data3, Nic->InterfaceGuid.Data4[0], Nic->InterfaceGuid.Data4[1], Nic->InterfaceGuid.Data4[2],
             Nic->InterfaceGuid.Data4[3], Nic->InterfaceGuid.Data4[4], Nic->InterfaceGuid.Data4[5], Nic->InterfaceGuid.Data4[6],
             Nic->InterfaceGuid.Data4[7]);
    wcscpy(Path, Prefix);
    wcscat(Path, GuidText);
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &Key);
    if (Error != ERROR_SUCCESS)
    {
        skip("Cannot open the adapter key: %lu\n", Error);
        return;
    }
    Size = sizeof(Old);
    HadOld = RegQueryValueExW(Key, L"InterfaceMetric", NULL, &Type, (LPBYTE)&Old, &Size) == ERROR_SUCCESS && Type == REG_DWORD;

    Value = 1234;
    RegSetValueExW(Key, L"InterfaceMetric", 0, REG_DWORD, (LPBYTE)&Value, sizeof(Value));
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid = Nic->InterfaceLuid;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "GetIpInterfaceEntry: %lu\n", Error);
    ok(Row.Metric == 1234, "Metric %lu, expected 1234\n", Row.Metric);
    ok(!Row.UseAutomaticMetric, "Automatic metric with a fixed one\n");

    Value = 20000;
    RegSetValueExW(Key, L"InterfaceMetric", 0, REG_DWORD, (LPBYTE)&Value, sizeof(Value));
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid = Nic->InterfaceLuid;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "GetIpInterfaceEntry: %lu\n", Error);
    ok(Row.Metric == 9999, "Metric %lu, expected 9999\n", Row.Metric);

    Value = 0;
    RegSetValueExW(Key, L"InterfaceMetric", 0, REG_DWORD, (LPBYTE)&Value, sizeof(Value));
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid = Nic->InterfaceLuid;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "GetIpInterfaceEntry: %lu\n", Error);
    ok(Row.UseAutomaticMetric && Row.Metric != 0 && Row.Metric != 1234, "Metric %lu, automatic %u\n", Row.Metric, Row.UseAutomaticMetric);

    RegDeleteValueW(Key, L"InterfaceMetric");
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid = Nic->InterfaceLuid;
    Error = pGetIpInterfaceEntry(&Row);
    ok(Error == NO_ERROR, "GetIpInterfaceEntry: %lu\n", Error);
    ok(Row.UseAutomaticMetric, "No automatic metric without a value\n");

    if (HadOld)
        RegSetValueExW(Key, L"InterfaceMetric", 0, REG_DWORD, (LPBYTE)&Old, sizeof(Old));
    RegCloseKey(Key);
}

/* every adapter of GetAdaptersAddresses is an interface of the IP interface table, with the same luid */
static void test_adapters_addresses(void)
{
    PIP_ADAPTER_ADDRESSES Buffer = NULL, Adapter;
    IPIF_TABLE *Table;
    ULONG Size = 0, Tries;
    DWORD Error = ERROR_BUFFER_OVERFLOW;

    for (Tries = 0; Tries < 3 && Error == ERROR_BUFFER_OVERFLOW; Tries++)
    {
        free(Buffer);
        Buffer = Size ? malloc(Size) : NULL;
        Error = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL, Buffer, &Size);
    }
    ok(Error == NO_ERROR, "GetAdaptersAddresses: %lu\n", Error);
    if (Error != NO_ERROR)
    {
        free(Buffer);
        return;
    }

    Table = SENTINEL;
    Error = pGetIpInterfaceTable(AF_INET, &Table);
    ok(Error == NO_ERROR, "GetIpInterfaceTable: %lu\n", Error);
    if (Error != NO_ERROR)
    {
        free(Buffer);
        return;
    }

    for (Adapter = Buffer; Adapter; Adapter = Adapter->Next)
    {
        IP_ADAPTER_ADDRESSES_LH *Lh = (IP_ADAPTER_ADDRESSES_LH *)Adapter;
        const IPIF_ROW *Found = NULL;
        ULONG i;

        if (Adapter->Length < FIELD_OFFSET(IP_ADAPTER_ADDRESSES_LH, Luid) + sizeof(NET_LUID))
            continue;
        for (i = 0; i < Table->NumEntries; i++)
            if (Table->Table[i].InterfaceLuid.Value == Lh->Luid.Value)
                Found = &Table->Table[i];
        ok(Found != NULL, "Adapter %lu (luid %I64x) is not in the IP interface table\n", Adapter->IfIndex, Lh->Luid.Value);
        if (!Found)
            continue;
        ok(Found->InterfaceIndex == Adapter->IfIndex, "Index %lu, adapter says %lu\n", Found->InterfaceIndex, Adapter->IfIndex);
        if (Adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
            ok(Found->NlMtu == Adapter->Mtu, "MTU %lu, adapter says %lu\n", Found->NlMtu, Adapter->Mtu);
        ok(Found->Connected == (Adapter->OperStatus == OPER_UP), "Connected %u, adapter oper status %d\n",
           Found->Connected, Adapter->OperStatus);
    }
    pFreeMibTable(Table);
    free(Buffer);
}

static BOOL adapter_has_address(PIP_ADAPTER_ADDRESSES Buffer, ULONG Index, ULONG Address)
{
    PIP_ADAPTER_ADDRESSES Adapter;
    PIP_ADAPTER_UNICAST_ADDRESS Unicast;

    for (Adapter = Buffer; Adapter; Adapter = Adapter->Next)
    {
        if (Adapter->IfIndex != Index)
            continue;
        for (Unicast = Adapter->FirstUnicastAddress; Unicast; Unicast = Unicast->Next)
        {
            const SOCKADDR_IN *In = (const SOCKADDR_IN *)Unicast->Address.lpSockaddr;

            if (In && In->sin_family == AF_INET && In->sin_addr.s_addr == Address)
                return TRUE;
        }
    }
    return FALSE;
}

static void test_unicast(const IF_TABLE2 *IfTable)
{
    PIP_ADAPTER_ADDRESSES Buffer = NULL;
    UNI_TABLE *Table = SENTINEL;
    UNI_ROW Row;
    ULONG i, Size = 0, Tries, Loopbacks = 0;
    DWORD Error = ERROR_BUFFER_OVERFLOW;
    const UNI_ROW *Other = NULL;

    for (Tries = 0; Tries < 3 && Error == ERROR_BUFFER_OVERFLOW; Tries++)
    {
        free(Buffer);
        Buffer = Size ? malloc(Size) : NULL;
        Error = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL, Buffer, &Size);
    }
    if (Error != NO_ERROR)
    {
        free(Buffer);
        Buffer = NULL;
    }

    Error = pGetUnicastIpAddressTable(AF_INET, &Table);
    ok(Error == NO_ERROR, "GetUnicastIpAddressTable(AF_INET): %lu\n", Error);
    if (Error != NO_ERROR || !Table || Table == SENTINEL)
    {
        free(Buffer);
        return;
    }

    for (i = 0; i < Table->NumEntries; i++)
    {
        const UNI_ROW *Entry = &Table->Table[i];
        const IF_ROW2 *If = find_if_luid(IfTable, Entry->InterfaceLuid.Value);

        ok(Entry->Address.si_family == AF_INET, "Row %lu: family %u\n", i, Entry->Address.si_family);
        ok(Entry->Address.Ipv4.sin_addr.s_addr != 0, "Row %lu: no address\n", i);
        ok(If != NULL, "Row %lu: luid %I64x is not in GetIfTable2\n", i, Entry->InterfaceLuid.Value);
        if (If)
            ok(Entry->InterfaceIndex == If->InterfaceIndex, "Row %lu: index %lu, GetIfTable2 says %lu\n",
               i, Entry->InterfaceIndex, If->InterfaceIndex);
        ok(Entry->OnLinkPrefixLength >= 1 && Entry->OnLinkPrefixLength <= 32, "Row %lu: prefix length %u\n",
           i, Entry->OnLinkPrefixLength);
        ok(Entry->DadState == 4 /* IpDadStatePreferred */, "Row %lu: DAD state %lu\n", i, Entry->DadState);
        ok(Entry->PreferredLifetime <= Entry->ValidLifetime, "Row %lu: lifetimes %lu, %lu\n",
           i, Entry->PreferredLifetime, Entry->ValidLifetime);
        ok(Entry->CreationTimeStamp.QuadPart != 0, "Row %lu: no time stamp\n", i);
        ok(Entry->ScopeId == 0, "Row %lu: scope %lu\n", i, Entry->ScopeId);
        if (Buffer)
            ok(adapter_has_address(Buffer, Entry->InterfaceIndex, Entry->Address.Ipv4.sin_addr.s_addr),
               "Row %lu: GetAdaptersAddresses does not list the address for interface %lu\n", i, Entry->InterfaceIndex);

        if (Entry->InterfaceLuid.Value == LOOPBACK_LUID)
        {
            Loopbacks++;
            ok(Entry->Address.Ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "Loopback address %08lx\n",
               Entry->Address.Ipv4.sin_addr.s_addr);
            ok(Entry->OnLinkPrefixLength == 8, "Loopback prefix length %u\n", Entry->OnLinkPrefixLength);
            ok(Entry->PrefixOrigin == 2 && Entry->SuffixOrigin == 2, "Loopback origins %lu, %lu\n",
               Entry->PrefixOrigin, Entry->SuffixOrigin);
            ok(Entry->ValidLifetime == 0xffffffff && Entry->PreferredLifetime == 0xffffffff, "Loopback lifetimes\n");
        }
        else
        {
            Other = Entry;
        }

        /* the same address by interface luid and by index */
        memset(&Row, 0, sizeof(Row));
        Row.Address = Entry->Address;
        Row.InterfaceLuid = Entry->InterfaceLuid;
        Error = pGetUnicastIpAddressEntry(&Row);
        ok(Error == NO_ERROR, "GetUnicastIpAddressEntry(luid): %lu\n", Error);
        ok(Row.OnLinkPrefixLength == Entry->OnLinkPrefixLength && Row.InterfaceIndex == Entry->InterfaceIndex &&
           Row.PrefixOrigin == Entry->PrefixOrigin, "Entry differs from the table row\n");
        if (Entry->InterfaceIndex)
        {
            memset(&Row, 0, sizeof(Row));
            Row.Address = Entry->Address;
            Row.InterfaceIndex = Entry->InterfaceIndex;
            Error = pGetUnicastIpAddressEntry(&Row);
            ok(Error == NO_ERROR, "GetUnicastIpAddressEntry(index): %lu\n", Error);
            ok(Row.InterfaceLuid.Value == Entry->InterfaceLuid.Value, "Entry luid %I64x\n", Row.InterfaceLuid.Value);
        }

        /* an address alone is not enough */
        memset(&Row, 0, sizeof(Row));
        Row.Address = Entry->Address;
        Error = pGetUnicastIpAddressEntry(&Row);
        ok(Error == ERROR_FILE_NOT_FOUND, "GetUnicastIpAddressEntry(no interface): %lu\n", Error);
    }
    ok(Loopbacks == 1, "%lu loopback addresses\n", Loopbacks);

    if (Other)
    {
        /* an address of another interface */
        memset(&Row, 0, sizeof(Row));
        Row.Address = Other->Address;
        Row.InterfaceLuid.Value = LOOPBACK_LUID;
        Error = pGetUnicastIpAddressEntry(&Row);
        ok(Error == ERROR_NOT_FOUND, "GetUnicastIpAddressEntry(wrong interface): %lu\n", Error);
    }
    else
    {
        skip("No address besides the loopback one\n");
    }
    pFreeMibTable(Table);
    free(Buffer);

    Table = SENTINEL;
    Error = pGetUnicastIpAddressTable(99, &Table);
    ok(Error == ERROR_INVALID_PARAMETER, "GetUnicastIpAddressTable(99): %lu\n", Error);
    Error = pGetUnicastIpAddressTable(AF_INET, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "GetUnicastIpAddressTable(NULL): %lu\n", Error);
    Error = pGetUnicastIpAddressEntry(NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "GetUnicastIpAddressEntry(NULL): %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Error = pGetUnicastIpAddressEntry(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "GetUnicastIpAddressEntry(empty): %lu\n", Error);

    Table = SENTINEL;
    Error = pGetUnicastIpAddressTable(AF_UNSPEC, &Table);
    ok(Error == NO_ERROR, "GetUnicastIpAddressTable(AF_UNSPEC): %lu\n", Error);
    if (Error == NO_ERROR && Table && Table != SENTINEL)
    {
        ok(Table->NumEntries >= 1, "No addresses\n");
        pFreeMibTable(Table);
    }
}

static void test_names(const IF_TABLE2 *IfTable)
{
    IPIF_TABLE *Table = SENTINEL;
    NET_LUID Luid;
    ULONG i, Index;
    char Name[64], Other[64];
    WCHAR Alias[IF_MAX_STRING_SIZE + 1];
    GUID Guid;
    DWORD Error;

    Error = pGetIpInterfaceTable(AF_INET, &Table);
    ok(Error == NO_ERROR, "GetIpInterfaceTable: %lu\n", Error);
    if (Error != NO_ERROR)
        return;

    for (i = 0; i < Table->NumEntries; i++)
    {
        const IF_ROW2 *If = find_if_luid(IfTable, Table->Table[i].InterfaceLuid.Value);

        if (!If)
            continue;

        Luid.Value = If->InterfaceLuid.Value;
        Index = 0x55555555;
        Error = pConvertInterfaceLuidToIndex(&Luid, &Index);
        ok(Error == NO_ERROR, "ConvertInterfaceLuidToIndex: %lu\n", Error);
        ok(Index == If->InterfaceIndex, "Index %lu, expected %lu\n", Index, If->InterfaceIndex);

        Error = pConvertInterfaceLuidToNameA(&Luid, Name, sizeof(Name));
        ok(Error == NO_ERROR, "ConvertInterfaceLuidToNameA: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            if (If->Type == IF_TYPE_SOFTWARE_LOOPBACK)
                ok(!strcmp(Name, "loopback_0"), "Loopback name %s\n", Name);
            else if (If->Type == IF_TYPE_ETHERNET_CSMACD)
                ok(!strncmp(Name, "ethernet_", 9), "Ethernet name %s\n", Name);
            Error = pConvertInterfaceLuidToNameA(&Luid, Other, strlen(Name));
            ok(Error == ERROR_NOT_ENOUGH_MEMORY, "ConvertInterfaceLuidToNameA(short buffer): %lu\n", Error);

            Luid.Value = 0;
            Error = pConvertInterfaceNameToLuidA(Name, &Luid);
            ok(Error == NO_ERROR, "ConvertInterfaceNameToLuidA(%s): %lu\n", Name, Error);
            ok(Luid.Value == If->InterfaceLuid.Value, "Luid %I64x, expected %I64x\n", Luid.Value, If->InterfaceLuid.Value);
            ok(pif_nametoindex(Name) == If->InterfaceIndex, "if_nametoindex(%s) is %lu, expected %lu\n",
               Name, pif_nametoindex(Name), If->InterfaceIndex);
            if (If->InterfaceIndex)
            {
                memset(Other, 0, sizeof(Other));
                ok(pif_indextoname(If->InterfaceIndex, Other) == Other, "if_indextoname(%lu) failed\n", If->InterfaceIndex);
                ok(!strcmp(Name, Other), "if_indextoname(%lu) is %s, expected %s\n", If->InterfaceIndex, Other, Name);
            }
        }

        if (If->InterfaceIndex)
        {
            Luid.Value = 0;
            Error = pConvertInterfaceIndexToLuid(If->InterfaceIndex, &Luid);
            ok(Error == NO_ERROR, "ConvertInterfaceIndexToLuid: %lu\n", Error);
            ok(Luid.Value == If->InterfaceLuid.Value, "Luid %I64x, expected %I64x\n", Luid.Value, If->InterfaceLuid.Value);
        }

        Luid.Value = If->InterfaceLuid.Value;
        Error = pConvertInterfaceLuidToAlias(&Luid, Alias, ARRAYSIZE(Alias));
        ok(Error == NO_ERROR, "ConvertInterfaceLuidToAlias: %lu\n", Error);
        ok(!wcscmp(Alias, If->Alias), "Alias %ls, expected %ls\n", Alias, If->Alias);
        Luid.Value = 0;
        Error = pConvertInterfaceAliasToLuid(If->Alias, &Luid);
        ok(Error == NO_ERROR, "ConvertInterfaceAliasToLuid(%ls): %lu\n", If->Alias, Error);
        ok(Luid.Value == If->InterfaceLuid.Value, "Luid %I64x, expected %I64x\n", Luid.Value, If->InterfaceLuid.Value);

        Luid.Value = If->InterfaceLuid.Value;
        Error = pConvertInterfaceLuidToGuid(&Luid, &Guid);
        ok(Error == NO_ERROR, "ConvertInterfaceLuidToGuid: %lu\n", Error);
        ok(!memcmp(&Guid, &If->InterfaceGuid, sizeof(GUID)), "Guid differs from GetIfTable2\n");
        Luid.Value = 0;
        Error = pConvertInterfaceGuidToLuid(&Guid, &Luid);
        ok(Error == NO_ERROR, "ConvertInterfaceGuidToLuid: %lu\n", Error);
        ok(Luid.Value == If->InterfaceLuid.Value, "Luid %I64x, expected %I64x\n", Luid.Value, If->InterfaceLuid.Value);
    }
    pFreeMibTable(Table);

    /* unknown interfaces */
    Luid.Value = 0x7777;
    Index = 0x55555555;
    Error = pConvertInterfaceLuidToIndex(&Luid, &Index);
    ok(Error == ERROR_FILE_NOT_FOUND, "ConvertInterfaceLuidToIndex(unknown): %lu\n", Error);
    ok(Index == 0, "Index %lu\n", Index);
    Error = pConvertInterfaceIndexToLuid(0x7ffffff0, &Luid);
    ok(Error == ERROR_FILE_NOT_FOUND, "ConvertInterfaceIndexToLuid(unknown): %lu\n", Error);
    ok(Luid.Value == 0, "Luid %I64x\n", Luid.Value);
    Error = pConvertInterfaceAliasToLuid(L"No such interface alias", &Luid);
    ok(Error == ERROR_INVALID_PARAMETER, "ConvertInterfaceAliasToLuid(unknown): %lu\n", Error);
    Error = pConvertInterfaceNameToLuidA("xx", &Luid);
    ok(Error != NO_ERROR, "ConvertInterfaceNameToLuidA(xx) succeeded\n");
    ok(!pif_nametoindex("xx"), "if_nametoindex(xx) is not 0\n");
    ok(!pif_nametoindex("ethernet_16777215"), "if_nametoindex(unknown) is not 0\n");
    ok(pif_indextoname(0x7ffffff0, Name) == NULL, "if_indextoname(unknown) succeeded\n");
    ok(pif_indextoname(0, Name) == NULL, "if_indextoname(0) succeeded\n");
    Error = pConvertInterfaceLuidToIndex(NULL, &Index);
    ok(Error == ERROR_INVALID_PARAMETER, "ConvertInterfaceLuidToIndex(NULL): %lu\n", Error);
}

#ifndef GAA_FLAG_INCLUDE_ALL_INTERFACES
#define GAA_FLAG_INCLUDE_ALL_INTERFACES 0x100
#endif
#define LOOPBACK_INDEX 1

/* The loopback interface is index 1 with the luid 0x0018000000000000 in every table, as on Windows 10 */
static void test_loopback_index(const IF_TABLE2 *IfTable)
{
    const IF_ROW2 *Loop = NULL;
    IF_ROW2 Row;
    MIB_IFTABLE *Old = NULL;
    MIB_IFROW OldRow;
    NET_LUID Luid;
    ULONG i, j, Index, Size, Count;
    DWORD Error;
    char Name[64];

    for (i = 0; i < IfTable->NumEntries; i++)
    {
        if (is_loopback(&IfTable->Table[i]))
        {
            ok(Loop == NULL, "More than one loopback interface\n");
            Loop = &IfTable->Table[i];
        }
    }
    ok(Loop != NULL, "No loopback interface in GetIfTable2\n");
    if (!Loop)
        return;
    ok(Loop->InterfaceIndex == LOOPBACK_INDEX, "GetIfTable2: loopback index %lu\n", Loop->InterfaceIndex);
    ok(Loop->InterfaceLuid.Value == LOOPBACK_LUID, "GetIfTable2: loopback luid %I64x\n", Loop->InterfaceLuid.Value);

    /* GetIfEntry2 by index, and the two failure modes */
    memset(&Row, 0, sizeof(Row));
    Row.InterfaceIndex = LOOPBACK_INDEX;
    Error = pGetIfEntry2(&Row);
    ok(Error == NO_ERROR, "GetIfEntry2(index 1): %lu\n", Error);
    ok(Row.InterfaceLuid.Value == LOOPBACK_LUID, "GetIfEntry2(index 1): luid %I64x\n", Row.InterfaceLuid.Value);
    ok(Row.Type == IF_TYPE_SOFTWARE_LOOPBACK, "GetIfEntry2(index 1): type %lu\n", Row.Type);
    ok(Row.InterfaceIndex == LOOPBACK_INDEX, "GetIfEntry2(index 1): index %lu\n", Row.InterfaceIndex);
    ok(Row.OperStatus == OPER_UP, "GetIfEntry2(index 1): oper status %d\n", Row.OperStatus);
    ok(Row.Mtu > 0, "GetIfEntry2(index 1): MTU\n");
    memset(&Row, 0, sizeof(Row));
    Error = pGetIfEntry2(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "GetIfEntry2(index 0, luid 0): %lu\n", Error);

    /* the conversions */
    memset(&Luid, 0x55, sizeof(Luid));
    Error = pConvertInterfaceIndexToLuid(LOOPBACK_INDEX, &Luid);
    ok(Error == NO_ERROR, "ConvertInterfaceIndexToLuid(1): %lu\n", Error);
    ok(Luid.Value == LOOPBACK_LUID, "ConvertInterfaceIndexToLuid(1): %I64x\n", Luid.Value);
    Error = pConvertInterfaceIndexToLuid(0, &Luid);
    ok(Error == ERROR_FILE_NOT_FOUND, "ConvertInterfaceIndexToLuid(0): %lu\n", Error);
    Luid.Value = LOOPBACK_LUID;
    Index = 0x55555555;
    Error = pConvertInterfaceLuidToIndex(&Luid, &Index);
    ok(Error == NO_ERROR && Index == LOOPBACK_INDEX, "ConvertInterfaceLuidToIndex: %lu, index %lu\n", Error, Index);
    Error = pConvertInterfaceLuidToNameA(&Luid, Name, sizeof(Name));
    ok(Error == NO_ERROR && !strcmp(Name, "loopback_0"), "ConvertInterfaceLuidToNameA: %lu, %s\n", Error, Name);
    memset(&Luid, 0, sizeof(Luid));
    Error = pConvertInterfaceNameToLuidA("loopback_0", &Luid);
    ok(Error == NO_ERROR && Luid.Value == LOOPBACK_LUID, "ConvertInterfaceNameToLuidA: %lu, %I64x\n", Error, Luid.Value);
    ok(pif_nametoindex("loopback_0") == LOOPBACK_INDEX, "if_nametoindex(loopback_0): %lu\n", pif_nametoindex("loopback_0"));
    Name[0] = 0;
    ok(pif_indextoname(LOOPBACK_INDEX, Name) != NULL && !strcmp(Name, "loopback_0"), "if_indextoname(1): %s\n", Name);

    /* GetIfTable and GetIfEntry */
    Size = 0;
    Error = GetIfTable(NULL, &Size, FALSE);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "GetIfTable(size): %lu\n", Error);
    Old = malloc(Size ? Size : 1);
    Error = Old ? GetIfTable(Old, &Size, FALSE) : ERROR_NOT_ENOUGH_MEMORY;
    ok(Error == NO_ERROR, "GetIfTable: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        BOOL Found = FALSE;

        for (i = 0; i < Old->dwNumEntries; i++)
        {
            ok(Old->table[i].dwIndex != 0, "GetIfTable row %lu has index 0\n", i);
            for (j = i + 1; j < Old->dwNumEntries; j++)
                ok(Old->table[i].dwIndex != Old->table[j].dwIndex, "GetIfTable rows %lu and %lu share index %lu\n",
                   i, j, Old->table[i].dwIndex);
            if (Old->table[i].dwType == IF_TYPE_SOFTWARE_LOOPBACK)
            {
                Found = TRUE;
                ok(Old->table[i].dwIndex == LOOPBACK_INDEX, "GetIfTable: loopback index %lu\n", Old->table[i].dwIndex);
                ok(Old->table[i].dwOperStatus == IF_OPER_STATUS_OPERATIONAL, "GetIfTable: loopback status %lu\n",
                   Old->table[i].dwOperStatus);
            }
            /* the two tables list the same interfaces */
            for (j = 0; j < IfTable->NumEntries; j++)
                if (IfTable->Table[j].InterfaceIndex == Old->table[i].dwIndex)
                    break;
            ok(j < IfTable->NumEntries, "GetIfTable index %lu is not in GetIfTable2\n", Old->table[i].dwIndex);
        }
        ok(Found, "No loopback row in GetIfTable\n");
        ok(Old->dwNumEntries == IfTable->NumEntries, "GetIfTable has %lu rows, GetIfTable2 %lu\n",
           Old->dwNumEntries, IfTable->NumEntries);
    }
    memset(&OldRow, 0, sizeof(OldRow));
    OldRow.dwIndex = LOOPBACK_INDEX;
    Error = GetIfEntry(&OldRow);
    ok(Error == NO_ERROR, "GetIfEntry(1): %lu\n", Error);
    ok(OldRow.dwType == IF_TYPE_SOFTWARE_LOOPBACK, "GetIfEntry(1): type %lu\n", OldRow.dwType);
    memset(&OldRow, 0, sizeof(OldRow));
    Error = GetIfEntry(&OldRow);
    ok(Error != NO_ERROR, "GetIfEntry(0) succeeded\n");

    /* GetAdaptersAddresses lists it too */
    {
        PIP_ADAPTER_ADDRESSES Buffer = NULL, Adapter;
        BOOL Found = FALSE;

        Size = 0;
        Error = ERROR_BUFFER_OVERFLOW;
        for (i = 0; i < 3 && Error == ERROR_BUFFER_OVERFLOW; i++)
        {
            free(Buffer);
            Buffer = Size ? malloc(Size) : NULL;
            Error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, Buffer, &Size);
        }
        ok(Error == NO_ERROR, "GetAdaptersAddresses(all interfaces): %lu\n", Error);
        for (Adapter = Error == NO_ERROR ? Buffer : NULL; Adapter; Adapter = Adapter->Next)
        {
            IP_ADAPTER_ADDRESSES_LH *Lh = (IP_ADAPTER_ADDRESSES_LH *)Adapter;

            ok(Adapter->IfIndex != 0, "Adapter %s has index 0\n", Adapter->AdapterName);
            if (Adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK)
                continue;
            Found = TRUE;
            ok(Adapter->IfIndex == LOOPBACK_INDEX, "GetAdaptersAddresses: loopback index %lu\n", Adapter->IfIndex);
            if (Adapter->Length >= FIELD_OFFSET(IP_ADAPTER_ADDRESSES_LH, Luid) + sizeof(NET_LUID))
                ok(Lh->Luid.Value == LOOPBACK_LUID, "GetAdaptersAddresses: loopback luid %I64x\n", Lh->Luid.Value);
            ok(adapter_has_address(Adapter, LOOPBACK_INDEX, htonl(INADDR_LOOPBACK)),
               "GetAdaptersAddresses: no 127.0.0.1 on the loopback adapter\n");
        }
        ok(Found, "GetAdaptersAddresses(all interfaces) has no loopback adapter\n");
        free(Buffer);
    }

    /* the IP interface and address tables */
    {
        IPIF_TABLE *Interfaces = SENTINEL;
        UNI_TABLE *Addresses = SENTINEL;
        BOOL Found = FALSE;

        Error = pGetIpInterfaceTable(AF_INET, &Interfaces);
        ok(Error == NO_ERROR, "GetIpInterfaceTable: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            for (i = 0; i < Interfaces->NumEntries; i++)
            {
                ok(Interfaces->Table[i].InterfaceIndex != 0, "IP interface row %lu has index 0\n", i);
                if (Interfaces->Table[i].InterfaceLuid.Value == LOOPBACK_LUID)
                {
                    Found = TRUE;
                    ok(Interfaces->Table[i].InterfaceIndex == LOOPBACK_INDEX, "GetIpInterfaceTable: loopback index %lu\n",
                       Interfaces->Table[i].InterfaceIndex);
                }
            }
            ok(Found, "GetIpInterfaceTable has no loopback\n");
            pFreeMibTable(Interfaces);
        }
        memset(&Row, 0, sizeof(Row));
        {
            IPIF_ROW IpRow;

            pInitializeIpInterfaceEntry(&IpRow);
            IpRow.Family = AF_INET;
            IpRow.InterfaceIndex = LOOPBACK_INDEX;
            Error = pGetIpInterfaceEntry(&IpRow);
            ok(Error == NO_ERROR, "GetIpInterfaceEntry(v4, index 1): %lu\n", Error);
            ok(IpRow.InterfaceLuid.Value == LOOPBACK_LUID, "GetIpInterfaceEntry(index 1): luid %I64x\n",
               IpRow.InterfaceLuid.Value);
        }

        Found = FALSE;
        Error = pGetUnicastIpAddressTable(AF_INET, &Addresses);
        ok(Error == NO_ERROR, "GetUnicastIpAddressTable: %lu\n", Error);
        if (Error == NO_ERROR)
        {
            for (i = 0; i < Addresses->NumEntries; i++)
            {
                ok(Addresses->Table[i].InterfaceIndex != 0, "Unicast row %lu has index 0\n", i);
                if (Addresses->Table[i].Address.Ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
                {
                    Found = TRUE;
                    ok(Addresses->Table[i].InterfaceIndex == LOOPBACK_INDEX, "127.0.0.1 is on index %lu\n",
                       Addresses->Table[i].InterfaceIndex);
                    ok(Addresses->Table[i].InterfaceLuid.Value == LOOPBACK_LUID, "127.0.0.1 is on luid %I64x\n",
                       Addresses->Table[i].InterfaceLuid.Value);
                }
            }
            ok(Found, "GetUnicastIpAddressTable has no 127.0.0.1\n");
            pFreeMibTable(Addresses);
        }
    }

    /* the address table, the routes and the best interface: the same indexes as the interface table */
    {
        MIB_IPADDRTABLE *Addrs = NULL;
        MIB_IPFORWARDTABLE *Routes = NULL;
        DWORD Best = 0x55555555;
        IPAddr Loopback = htonl(INADDR_LOOPBACK);
        BOOL Found = FALSE;

        Size = 0;
        GetIpAddrTable(NULL, &Size, FALSE);
        Addrs = malloc(Size ? Size : 1);
        Error = Addrs ? GetIpAddrTable(Addrs, &Size, FALSE) : ERROR_NOT_ENOUGH_MEMORY;
        ok(Error == NO_ERROR, "GetIpAddrTable: %lu\n", Error);
        for (i = 0; Error == NO_ERROR && i < Addrs->dwNumEntries; i++)
        {
            for (j = 0; j < IfTable->NumEntries; j++)
                if (IfTable->Table[j].InterfaceIndex == Addrs->table[i].dwIndex)
                    break;
            ok(j < IfTable->NumEntries, "GetIpAddrTable index %lu is not in GetIfTable2\n", Addrs->table[i].dwIndex);
            if (Addrs->table[i].dwAddr == Loopback)
            {
                Found = TRUE;
                ok(Addrs->table[i].dwIndex == LOOPBACK_INDEX, "GetIpAddrTable: 127.0.0.1 on index %lu\n",
                   Addrs->table[i].dwIndex);
            }
        }
        ok(Found, "GetIpAddrTable has no 127.0.0.1\n");
        free(Addrs);

        Size = 0;
        GetIpForwardTable(NULL, &Size, FALSE);
        Routes = malloc(Size ? Size : 1);
        Error = Routes ? GetIpForwardTable(Routes, &Size, FALSE) : ERROR_NOT_ENOUGH_MEMORY;
        ok(Error == NO_ERROR, "GetIpForwardTable: %lu\n", Error);
        Count = 0;
        for (i = 0; Error == NO_ERROR && i < Routes->dwNumEntries; i++)
        {
            const MIB_IPFORWARDROW *Route = &Routes->table[i];

            for (j = 0; j < IfTable->NumEntries; j++)
                if (IfTable->Table[j].InterfaceIndex == Route->dwForwardIfIndex)
                    break;
            ok(j < IfTable->NumEntries, "Route %08lx has index %lu, which is not in GetIfTable2\n",
               Route->dwForwardDest, Route->dwForwardIfIndex);
            /* a route that covers 127.0.0.1 and leaves through the loopback address: the /8, /32 or both
               (Windows has 127.0.0.0/8, 127.0.0.1/32 and the broadcast, the stack here the /8) */
            if ((Loopback & Route->dwForwardMask) == Route->dwForwardDest && Route->dwForwardMask != 0 &&
                Route->dwForwardNextHop == Loopback)
            {
                Count++;
                ok(Route->dwForwardIfIndex == LOOPBACK_INDEX, "Route to 127.0.0.1: index %lu\n", Route->dwForwardIfIndex);
            }
        }
        ok(Count >= 1, "No route to 127.0.0.1\n");
        free(Routes);

        Error = GetBestInterface(Loopback, &Best);
        ok(Error == NO_ERROR, "GetBestInterface(127.0.0.1): %lu\n", Error);
        ok(Best == LOOPBACK_INDEX, "GetBestInterface(127.0.0.1): %lu\n", Best);
    }
}

START_TEST(IpInterface)
{
    HMODULE hIphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    IF_TABLE2 *IfTable = SENTINEL;
    IPIF_TABLE *Table;
    DWORD Error;

    if (!hIphlpapi)
        hIphlpapi = LoadLibraryW(L"iphlpapi.dll");

#define GET(name) p##name = (void *)GetProcAddress(hIphlpapi, #name)
    GET(GetIfTable2);
    GET(GetIfTable2Ex);
    GET(GetIfEntry2);
    GET(GetIpInterfaceTable);
    GET(GetIpInterfaceEntry);
    GET(InitializeIpInterfaceEntry);
    GET(GetUnicastIpAddressTable);
    GET(GetUnicastIpAddressEntry);
    GET(FreeMibTable);
    GET(if_indextoname);
    GET(if_nametoindex);
    GET(ConvertInterfaceIndexToLuid);
    GET(ConvertInterfaceLuidToIndex);
    GET(ConvertInterfaceLuidToNameA);
    GET(ConvertInterfaceNameToLuidA);
    GET(ConvertInterfaceLuidToAlias);
    GET(ConvertInterfaceAliasToLuid);
    GET(ConvertInterfaceLuidToGuid);
    GET(ConvertInterfaceGuidToLuid);
#undef GET

    if (!pGetIpInterfaceTable && is_reactos() && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"))
    {
        skip("No NT 6 exports\n");
        return;
    }

    ok(pGetIpInterfaceTable != NULL, "GetIpInterfaceTable is not exported\n");
    ok(pGetIpInterfaceEntry != NULL, "GetIpInterfaceEntry is not exported\n");
    ok(pInitializeIpInterfaceEntry != NULL, "InitializeIpInterfaceEntry is not exported\n");
    ok(pif_indextoname != NULL && pif_nametoindex != NULL, "if_indextoname or if_nametoindex is not exported\n");
    if (!pGetIpInterfaceTable || !pGetIpInterfaceEntry || !pInitializeIpInterfaceEntry || !pGetIfTable2 ||
        !pGetIfTable2Ex || !pGetIfEntry2 || !pGetUnicastIpAddressTable || !pGetUnicastIpAddressEntry ||
        !pFreeMibTable || !pif_indextoname || !pif_nametoindex || !pConvertInterfaceIndexToLuid ||
        !pConvertInterfaceLuidToIndex || !pConvertInterfaceLuidToNameA || !pConvertInterfaceNameToLuidA ||
        !pConvertInterfaceLuidToAlias || !pConvertInterfaceAliasToLuid || !pConvertInterfaceLuidToGuid ||
        !pConvertInterfaceGuidToLuid)
        return;

    pFreeMibTable(NULL);
    test_initialize();

    Error = pGetIfTable2(&IfTable);
    ok(Error == NO_ERROR, "GetIfTable2: %lu\n", Error);
    if (Error != NO_ERROR || !IfTable || IfTable == SENTINEL)
        return;

    test_if_table2(IfTable);
    test_if_entry2(IfTable);

    test_ip_interface(IfTable, AF_INET);
    test_ip_interface(IfTable, AF_UNSPEC);
    test_ip_interface(IfTable, AF_INET6);
    Table = SENTINEL;
    Error = pGetIpInterfaceTable(AF_UNSPEC, &Table);
    if (Error == NO_ERROR)
    {
        ULONG v4 = 0, i;
        IPIF_TABLE *Only4 = SENTINEL;

        for (i = 0; i < Table->NumEntries; i++)
            if (Table->Table[i].Family == AF_INET)
                v4++;
        if (pGetIpInterfaceTable(AF_INET, &Only4) == NO_ERROR)
        {
            ok(v4 == Only4->NumEntries, "AF_UNSPEC has %lu IPv4 rows, AF_INET has %lu\n", v4, Only4->NumEntries);
            pFreeMibTable(Only4);
        }
        pFreeMibTable(Table);
    }
    test_ip_interface_errors();
    if (is_reactos())
        test_manual_metric(IfTable);
    else
        skip("test_manual_metric is ReactOS-only\n");
    test_adapters_addresses();
    test_unicast(IfTable);
    test_names(IfTable);
    test_loopback_index(IfTable);

    pFreeMibTable(IfTable);
}
