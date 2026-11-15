/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SetIpInterfaceEntry for IPv4 and IPv6 (and the private request behind it): the fields the stack has (NlMtu,
 *              UseAutomaticMetric / Metric, RouterDiscoveryBehavior, DadTransmits, ForwardingEnabled) change what
 *              GetIpInterfaceEntry and GetIpInterfaceTable report, wrong values and what the stack cannot do fail without
 *              a change, the fields the documentation lists as ignored are ignored, the active store writes no
 *              persistent value and the persistent store writes the adapter's values (which a restart reads: the
 *              reboot row is a separate run of the guest tool). Everything is put back.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"
#include <tcpioctl.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

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
} SIPIF_ROW;

typedef struct
{
    ULONG NumEntries;
    SIPIF_ROW Table[1];
} SIPIF_TABLE;

typedef DWORD (WINAPI *PFN_ROW)(SIPIF_ROW *);
typedef DWORD (WINAPI *PFN_TABLE)(USHORT, SIPIF_TABLE **);

#define RD_DISABLED 0
#define RD_ENABLED  1
#define RD_DHCP     2

static PFN_ROW pGet, pSet;
static PFN_TABLE pGetTable;
static PFN_FREE_TABLE pFree;
static BOOL V6On;

static NTSTATUS SendRequest(PVOID Request, ULONG Size)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Device;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(&Device, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, IOCTL_IP_INTERFACE_CONFIG, Request, Size, NULL, 0);
    NtClose(Device);
    return Status;
}

static NTSTATUS Request(ULONG Family, ULONG Store, ULONG IfIndex, ULONG Fields, ULONG Mtu, ULONG Metric, ULONG Rd,
                        ULONG Dad, ULONG Forwarding)
{
    TCP_IP_INTERFACE_REQUEST R;

    memset(&R, 0, sizeof(R));
    R.Family = Family;
    R.Store = Store;
    R.IfIndex = IfIndex;
    R.Fields = Fields;
    R.Mtu = Mtu;
    R.Metric = Metric;
    R.RouterDiscovery = Rd;
    R.DadTransmits = Dad;
    R.Forwarding = Forwarding;
    return SendRequest(&R, sizeof(R));
}

static BOOL GetRow(USHORT Family, ULONG Index, SIPIF_ROW *Row)
{
    memset(Row, 0, sizeof(*Row));
    Row->Family = Family;
    Row->InterfaceIndex = Index;
    return pGet(Row) == NO_ERROR;
}

/* The Ethernet interface: the first non-loopback row of the IPv4 table (index, luid), and its adapter's GUID text */
static char Guid[64];

static ULONG FindEthernet(void)
{
    SIPIF_TABLE *Table = NULL;
    ULONG i, Index = 0, Size = 0;
    PIP_ADAPTER_ADDRESSES Adapters, A;

    if (pGetTable(AF_INET, &Table) != NO_ERROR || !Table)
        return 0;
    for (i = 0; i < Table->NumEntries && !Index; i++)
        if (Table->Table[i].NlMtu != 0xffffffff && Table->Table[i].NlMtu != 0)
            Index = Table->Table[i].InterfaceIndex;
    pFree(Table);
    if (!Index)
        return 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &Size);
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    if (!Adapters)
        return 0;
    Guid[0] = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, Adapters, &Size) == NO_ERROR)
        for (A = Adapters; A; A = A->Next)
            if (A->IfIndex == Index || A->Ipv6IfIndex == Index)
            {
                strncpy(Guid, A->AdapterName, sizeof(Guid) - 1);
                Guid[sizeof(Guid) - 1] = 0;
                break;
            }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Guid[0] ? Index : 0;
}

static BOOL StoredValue(USHORT Family, const char *Name, DWORD *Value)
{
    char Path[200];
    HKEY Key;
    DWORD Type, Size = sizeof(*Value);
    BOOL Found;

    sprintf(Path, "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\\Interfaces\\%s",
            Family == AF_INET6 ? "Tcpip6" : "Tcpip", Guid);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return FALSE;
    Found = RegQueryValueExA(Key, Name, NULL, &Type, (LPBYTE)Value, &Size) == ERROR_SUCCESS && Type == REG_DWORD;
    RegCloseKey(Key);
    return Found;
}

static void DeleteStored(USHORT Family, const char *Name)
{
    char Path[200];
    HKEY Key;

    sprintf(Path, "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\\Interfaces\\%s",
            Family == AF_INET6 ? "Tcpip6" : "Tcpip", Guid);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, Path, 0, KEY_SET_VALUE, &Key) == ERROR_SUCCESS)
    {
        RegDeleteValueA(Key, Name);
        RegCloseKey(Key);
    }
}

static void TestArguments(ULONG Index)
{
    SIPIF_ROW Row;
    DWORD Error;

    Error = pSet(NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "NULL: %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.InterfaceIndex = Index;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "no family: %lu\n", Error);
    Row.Family = AF_UNSPEC;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "AF_UNSPEC: %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "no luid and no index: %lu\n", Error);
    Row.InterfaceIndex = 0x7ffffff0;
    Error = pSet(&Row);
    ok(Error == ERROR_FILE_NOT_FOUND, "unknown index: %lu\n", Error);
    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid.Value = 0x1234567800000000ULL;
    Error = pSet(&Row);
    ok(Error == ERROR_NOT_FOUND, "unknown luid: %lu\n", Error);
}

/* One family: every field, wrong values, what the stack refuses, the ignored fields */
static void TestFamily(USHORT Family, ULONG Index)
{
    SIPIF_ROW Start, Row, Back;
    ULONG Link;
    DWORD Error;
    BOOL V6 = (Family == AF_INET6);

    trace("family %u\n", Family);
    ok(GetRow(Family, Index, &Start), "Get\n");
    Link = Start.NlMtu;
    trace("start: mtu %lu metric %lu auto %d rd %lu dad %lu\n", Link, Start.Metric, Start.UseAutomaticMetric,
          Start.RouterDiscoveryBehavior, Start.DadTransmits);

    /* unchanged row: nothing happens; the luid is filled in when only the index was given */
    Row = Start;
    Row.InterfaceLuid.Value = 0;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "unchanged: %lu\n", Error);
    ok(Row.InterfaceLuid.Value == Start.InterfaceLuid.Value, "luid filled in: %I64x vs %I64x\n", Row.InterfaceLuid.Value,
       Start.InterfaceLuid.Value);
    /* the luid wins over a wrong index */
    Row = Start;
    Row.InterfaceIndex = 0x7ffffff0;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "luid with a wrong index: %lu\n", Error);

    /* MTU */
    Row = Start;
    Row.NlMtu = Link - 100;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "MTU %lu: %lu\n", Row.NlMtu, Error);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Link - 100, "MTU read back %lu\n", Back.NlMtu);
    {
        SIPIF_ROW Other;

        /* the other family keeps its own MTU */
        if ((V6 || V6On) && GetRow(V6 ? AF_INET : AF_INET6, Index, &Other))
            ok(Other.NlMtu == Link || Other.NlMtu != Link - 100, "the other family's MTU %lu\n", Other.NlMtu);
    }
    Row.NlMtu = V6 ? 1279 : 575;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "MTU %lu: %lu\n", Row.NlMtu, Error);
    Row.NlMtu = Link + 1;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "MTU above the link: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Link - 100, "MTU unchanged by refused values: %lu\n", Back.NlMtu);
    Row.NlMtu = V6 ? 1280 : 576;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "minimum MTU: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Row.NlMtu, "minimum MTU read back %lu\n", Back.NlMtu);
    /* 0 is "not given" */
    Row.NlMtu = 0;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "MTU 0: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == (V6 ? 1280UL : 576UL), "MTU 0 changes nothing: %lu\n", Back.NlMtu);
    Row.NlMtu = Link;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "MTU back: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Link, "MTU back read back %lu\n", Back.NlMtu);

    /* metric */
    Row = Back;
    Row.UseAutomaticMetric = FALSE;
    Row.Metric = 33;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "metric 33: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && !Back.UseAutomaticMetric && Back.Metric == 33, "metric read back %d %lu\n",
       Back.UseAutomaticMetric, Back.Metric);
    Row.Metric = 0;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "manual metric 0: %lu\n", Error);
    Row.Metric = 10000;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "metric 10000: %lu\n", Error);
    Row.Metric = 9999;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "metric 9999: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.Metric == 9999, "metric 9999 read back %lu\n", Back.Metric);
    Row.UseAutomaticMetric = TRUE;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "automatic metric: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.UseAutomaticMetric && Back.Metric == Start.Metric,
       "automatic metric read back %d %lu (was %lu)\n", Back.UseAutomaticMetric, Back.Metric, Start.Metric);

    /* router discovery */
    Row = Back;
    if (V6)
    {
        Row.RouterDiscoveryBehavior = RD_DISABLED;
        Error = pSet(&Row);
        ok(Error == NO_ERROR, "router discovery disabled: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.RouterDiscoveryBehavior == RD_DISABLED, "disabled read back %lu\n",
           Back.RouterDiscoveryBehavior);
        Row.RouterDiscoveryBehavior = RD_DHCP;
        Error = pSet(&Row);
        ok(Error == NO_ERROR, "router discovery by DHCP: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.RouterDiscoveryBehavior == RD_DHCP, "DHCP read back %lu\n",
           Back.RouterDiscoveryBehavior);
        Row.RouterDiscoveryBehavior = 3;
        Error = pSet(&Row);
        ok(Error == ERROR_INVALID_PARAMETER, "router discovery 3: %lu\n", Error);
        Row.RouterDiscoveryBehavior = RD_ENABLED;
        Error = pSet(&Row);
        ok(Error == NO_ERROR, "router discovery enabled: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.RouterDiscoveryBehavior == RD_ENABLED, "enabled read back %lu\n",
           Back.RouterDiscoveryBehavior);
    }
    else
    {
        Row.RouterDiscoveryBehavior = (Start.RouterDiscoveryBehavior == RD_DISABLED) ? RD_ENABLED : RD_DISABLED;
        Error = pSet(&Row);
        ok(Error == ERROR_NOT_SUPPORTED, "IPv4 router discovery change: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.RouterDiscoveryBehavior == Start.RouterDiscoveryBehavior,
           "IPv4 router discovery unchanged\n");
    }

    /* DAD transmits */
    Row = Back;
    if (V6)
    {
        Row.DadTransmits = 0;
        Error = pSet(&Row);
        ok(Error == NO_ERROR, "DAD transmits 0: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.DadTransmits == 0, "DAD 0 read back %lu\n", Back.DadTransmits);
        Row.DadTransmits = 7;
        Error = pSet(&Row);
        ok(Error == NO_ERROR, "DAD transmits 7: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.DadTransmits == 7, "DAD 7 read back %lu\n", Back.DadTransmits);
        Row.DadTransmits = 8;
        Error = pSet(&Row);
        ok(Error == ERROR_INVALID_PARAMETER, "DAD transmits 8: %lu\n", Error);
        Row.DadTransmits = Start.DadTransmits;
        Error = pSet(&Row);
        ok(Error == NO_ERROR, "DAD transmits back: %lu\n", Error);
        ok(GetRow(Family, Index, &Back) && Back.DadTransmits == Start.DadTransmits, "DAD back read back %lu\n",
           Back.DadTransmits);
    }
    else
    {
        Row.DadTransmits = Start.DadTransmits + 1;
        Error = pSet(&Row);
        ok(Error == ERROR_NOT_SUPPORTED, "IPv4 DAD transmits change: %lu\n", Error);
    }

    /* forwarding: off is what the stack is, on is refused */
    Row = Back;
    Row.ForwardingEnabled = TRUE;
    Error = pSet(&Row);
    ok(Error == ERROR_NOT_SUPPORTED, "forwarding on: %lu\n", Error);
    Row.ForwardingEnabled = FALSE;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "forwarding off: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && !Back.ForwardingEnabled, "forwarding reported off\n");

    /* a request with one wrong field changes nothing (the right MTU is not applied) */
    Row = Back;
    Row.NlMtu = Link - 50;
    Row.UseAutomaticMetric = FALSE;
    Row.Metric = 20000;
    Error = pSet(&Row);
    ok(Error == ERROR_INVALID_PARAMETER, "one wrong field: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Link && Back.UseAutomaticMetric, "nothing changed: mtu %lu auto %d\n",
       Back.NlMtu, Back.UseAutomaticMetric);

    /* the documented ignored fields */
    Row = Back;
    Row.MaxReassemblySize = 1;
    Row.MinRouterAdvertisementInterval = 1;
    Row.MaxRouterAdvertisementInterval = 2;
    Row.Connected = !Back.Connected;
    Row.SupportsWakeUpPatterns = !Back.SupportsWakeUpPatterns;
    Row.SupportsNeighborDiscovery = !Back.SupportsNeighborDiscovery;
    Row.SupportsRouterDiscovery = !Back.SupportsRouterDiscovery;
    Row.ReachableTime = 12345;
    Error = pSet(&Row);
    ok(Error == NO_ERROR, "ignored fields: %lu\n", Error);
    ok(GetRow(Family, Index, &Back) && Back.Connected == Start.Connected &&
       Back.SupportsRouterDiscovery == Start.SupportsRouterDiscovery && Back.ReachableTime == Start.ReachableTime &&
       Back.MaxReassemblySize == Start.MaxReassemblySize, "ignored fields did not change\n");
}

/* The active store writes nothing persistent; the persistent request writes the adapter's values */
static void TestStores(USHORT Family, ULONG Index)
{
    SIPIF_ROW Start, Row, Back;
    ULONG Link;
    DWORD Value, Fam = (Family == AF_INET6) ? TCP_IPIF_IPV6 : TCP_IPIF_IPV4;
    const char *MtuName = (Family == AF_INET6) ? "NlMtu" : "MTU";
    NTSTATUS Status;

    ok(GetRow(Family, Index, &Start), "Get\n");
    Link = Start.NlMtu;
    DeleteStored(Family, MtuName);
    DeleteStored(Family, "InterfaceMetric");

    Row = Start;
    Row.NlMtu = Link - 200;
    Row.UseAutomaticMetric = FALSE;
    Row.Metric = 44;
    ok(pSet(&Row) == NO_ERROR, "active set\n");
    ok(!StoredValue(Family, MtuName, &Value), "the active store wrote %s\n", MtuName);
    ok(!StoredValue(Family, "InterfaceMetric", &Value), "the active store wrote InterfaceMetric\n");

    /* a persistent request: the stack's values and the adapter's key */
    Status = Request(Fam, TCP_IPV6_STORE_PERSISTENT, Index, TCP_IPIF_SET_MTU | TCP_IPIF_SET_METRIC, Link - 300, 55, 0, 0, 0);
    ok(Status == STATUS_SUCCESS, "persistent request: %lx\n", Status);
    ok(StoredValue(Family, MtuName, &Value) && Value == Link - 300, "stored %s %lu\n", MtuName, Value);
    ok(StoredValue(Family, "InterfaceMetric", &Value) && Value == 55, "stored InterfaceMetric %lu\n", Value);
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Link - 300 && Back.Metric == 55, "in force: %lu %lu\n", Back.NlMtu,
       Back.Metric);
    if (Family == AF_INET6)
    {
        Status = Request(Fam, TCP_IPV6_STORE_PERSISTENT, Index, TCP_IPIF_SET_ROUTER_DISCOVERY | TCP_IPIF_SET_DAD_TRANSMITS, 0, 0,
                         RD_DISABLED, 2, 0);
        ok(Status == STATUS_SUCCESS, "persistent request 2: %lx\n", Status);
        ok(StoredValue(Family, "RouterDiscovery", &Value) && Value == RD_DISABLED, "stored RouterDiscovery %lu\n", Value);
        ok(StoredValue(Family, "DadTransmits", &Value) && Value == 2, "stored DadTransmits %lu\n", Value);
    }
    /* a refused persistent request writes nothing */
    Status = Request(Fam, TCP_IPV6_STORE_PERSISTENT, Index, TCP_IPIF_SET_MTU, 100, 0, 0, 0, 0);
    ok(Status == STATUS_INVALID_PARAMETER, "persistent request with MTU 100: %lx\n", Status);
    ok(StoredValue(Family, MtuName, &Value) && Value == Link - 300, "stored %s unchanged %lu\n", MtuName, Value);
    /* metric 0 (automatic) takes the value out */
    Status = Request(Fam, TCP_IPV6_STORE_PERSISTENT, Index, TCP_IPIF_SET_METRIC, 0, 0, 0, 0, 0);
    ok(Status == STATUS_SUCCESS, "persistent automatic metric: %lx\n", Status);
    ok(!StoredValue(Family, "InterfaceMetric", &Value), "InterfaceMetric still stored\n");

    /* put everything back: the stored values go, the stack's values are the original ones */
    DeleteStored(Family, MtuName);
    DeleteStored(Family, "InterfaceMetric");
    DeleteStored(Family, "RouterDiscovery");
    DeleteStored(Family, "DadTransmits");
    Row = Start;
    ok(pSet(&Row) == NO_ERROR, "restore\n");
    ok(GetRow(Family, Index, &Back) && Back.NlMtu == Link && Back.UseAutomaticMetric && Back.Metric == Start.Metric &&
       Back.RouterDiscoveryBehavior == Start.RouterDiscoveryBehavior && Back.DadTransmits == Start.DadTransmits,
       "restored: mtu %lu auto %d metric %lu rd %lu dad %lu\n", Back.NlMtu, Back.UseAutomaticMetric, Back.Metric,
       Back.RouterDiscoveryBehavior, Back.DadTransmits);
}

static void TestTable(ULONG Index)
{
    SIPIF_TABLE *Table = NULL;
    SIPIF_ROW Start, Row;
    ULONG i, Seen = 0;

    ok(GetRow(AF_INET, Index, &Start), "Get\n");
    Row = Start;
    Row.NlMtu = Start.NlMtu - 60;
    Row.UseAutomaticMetric = FALSE;
    Row.Metric = 66;
    ok(pSet(&Row) == NO_ERROR, "set\n");
    ok(pGetTable(AF_UNSPEC, &Table) == NO_ERROR && Table, "table\n");
    for (i = 0; Table && i < Table->NumEntries; i++)
    {
        if (Table->Table[i].InterfaceIndex == Index && Table->Table[i].Family == AF_INET)
        {
            Seen++;
            ok(Table->Table[i].NlMtu == Start.NlMtu - 60 && !Table->Table[i].UseAutomaticMetric && Table->Table[i].Metric == 66,
               "table row: mtu %lu metric %lu\n", Table->Table[i].NlMtu, Table->Table[i].Metric);
        }
    }
    ok(Seen == 1, "IPv4 rows of the interface: %lu\n", Seen);
    if (Table)
        pFree(Table);
    ok(pSet(&Start) == NO_ERROR, "restore\n");
}

static void TestLoopback(void)
{
    SIPIF_ROW Row;
    DWORD Error;

    memset(&Row, 0, sizeof(Row));
    Row.Family = AF_INET;
    Row.InterfaceLuid.Value = LOOPBACK6_LUID;
    if (pGet(&Row) != NO_ERROR)
    {
        skip("no loopback row\n");
        return;
    }
    Row.NlMtu = 1500;
    Error = pSet(&Row);
    ok(Error == ERROR_NOT_SUPPORTED, "loopback MTU: %lu\n", Error);
}

START_TEST(SetIpInterfaceEntry)
{
    WSADATA Data;
    ULONG Index;

    pGet = (PFN_ROW)Ipv6Proc("GetIpInterfaceEntry");
    pSet = (PFN_ROW)Ipv6Proc("SetIpInterfaceEntry");
    pGetTable = (PFN_TABLE)Ipv6Proc("GetIpInterfaceTable");
    pFree = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    if (!pGet || !pSet || !pGetTable || !pFree)
    {
        skip("the IP Helper functions are missing\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Data);
    V6On = Ipv6SocketsWork();

    Index = FindEthernet();
    if (!Index)
    {
        skip("no Ethernet interface\n");
        WSACleanup();
        return;
    }
    trace("interface %lu adapter %s IPv6 %d\n", Index, Guid, V6On);

    TestArguments(Index);
    TestFamily(AF_INET, Index);
    TestStores(AF_INET, Index);
    TestTable(Index);
    TestLoopback();
    if (V6On)
    {
        SIPIF_ROW Row;

        if (GetRow(AF_INET6, Index, &Row))
        {
            TestFamily(AF_INET6, Index);
            TestStores(AF_INET6, Index);
        }
        else
            skip("the interface has no IPv6\n");
    }
    else
    {
        SIPIF_ROW Row;

        memset(&Row, 0, sizeof(Row));
        Row.Family = AF_INET6;
        Row.InterfaceIndex = Index;
        ok(pSet(&Row) == ERROR_NOT_FOUND, "IPv6 off: SetIpInterfaceEntry(AF_INET6)\n");
    }
    WSACleanup();
}
