/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The persistent store of the IPv6 configuration of tcpip.sys: an address or route configured with
 *              TCP_IPV6_STORE_PERSISTENT is written under Tcpip6\Parameters\Interfaces\<adapter GUID> (the stack
 *              applies it again when the adapter starts: the reboot and adapter restart checks are run outside this
 *              test), one of the active store is not; a change of a persistent entry is written, a removal takes it
 *              out of both stores.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"
#include <tcpioctl.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>

static PFN_GET_TABLE pGetUnicastIpAddressTable;
static PFN_FREE_TABLE pFreeMibTable;

/* MIB_UNICASTIPADDRESS_ROW and its table */
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
    SCOPE_ID ScopeId;
    LARGE_INTEGER CreationTimeStamp;
} UNICAST_ROW6;

typedef struct
{
    ULONG NumEntries;
    UNICAST_ROW6 Table[1];
} UNICAST_TABLE6;

static char KeyPath[256];

static NTSTATUS SendRequest(ULONG Code, PVOID Request, ULONG Size)
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
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, Code, Request, Size, NULL, 0);
    NtClose(Device);
    return Status;
}

static NTSTATUS AddressRequest(ULONG Operation, ULONG Store, ULONG IfIndex, const char *Address, ULONG Valid)
{
    TCP_IPV6_ADDRESS_REQUEST Request;
    SOCKADDR_INET Parsed;

    memset(&Request, 0, sizeof(Request));
    Request.Operation = Operation;
    Request.Store = Store;
    Request.IfIndex = IfIndex;
    Ipv6Parse(&Parsed, Address, 0);
    memcpy(Request.Address, &Parsed.Ipv6.sin6_addr, 16);
    Request.PrefixLength = 64;
    Request.ValidLifetime = Valid;
    Request.PreferredLifetime = Valid;
    Request.PrefixOrigin = 1;
    Request.SuffixOrigin = 1;
    return SendRequest(IOCTL_IP6_ADDRESS_CONFIG, &Request, sizeof(Request));
}

static NTSTATUS RouteRequest(ULONG Operation, ULONG Store, ULONG IfIndex, const char *Prefix, ULONG Length,
                             const char *NextHop, ULONG Metric)
{
    TCP_IPV6_ROUTE_REQUEST Request;
    SOCKADDR_INET Parsed;

    memset(&Request, 0, sizeof(Request));
    Request.Operation = Operation;
    Request.Store = Store;
    Request.IfIndex = IfIndex;
    Ipv6Parse(&Parsed, Prefix, 0);
    memcpy(Request.Prefix, &Parsed.Ipv6.sin6_addr, 16);
    Request.PrefixLength = Length;
    Ipv6Parse(&Parsed, NextHop, 0);
    memcpy(Request.NextHop, &Parsed.Ipv6.sin6_addr, 16);
    Request.Metric = Metric;
    Request.ValidLifetime = ~0UL;
    Request.PreferredLifetime = ~0UL;
    Request.Protocol = 3;
    return SendRequest(IOCTL_IP6_ROUTE_CONFIG, &Request, sizeof(Request));
}

/* The first interface with a link-local address that is not the loopback interface, and the key of its adapter */
static ULONG EthernetIndex(void)
{
    UNICAST_TABLE6 *Table = NULL;
    ULONG i, Index = 0, Size = 0;
    PIP_ADAPTER_ADDRESSES Adapters, A;

    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return 0;
    for (i = 0; i < Table->NumEntries && !Index; i++)
    {
        if (Ipv6IsLinkLocal(Table->Table[i].Address.Ipv6.sin6_addr.u.Byte) &&
            (Table->Table[i].InterfaceLuid.Value >> 48) != 24)
            Index = Table->Table[i].InterfaceIndex;
    }
    pFreeMibTable(Table);
    if (!Index)
        return 0;

    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &Size);
    Adapters = HeapAlloc(GetProcessHeap(), 0, Size ? Size : 1);
    if (!Adapters)
        return 0;
    KeyPath[0] = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, Adapters, &Size) == NO_ERROR)
    {
        for (A = Adapters; A; A = A->Next)
        {
            if (A->IfIndex == Index || A->Ipv6IfIndex == Index)
            {
                sprintf(KeyPath, "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s",
                        A->AdapterName);
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return KeyPath[0] ? Index : 0;
}

/* The records of a value of the adapter's key (a HeapAlloc block), *Count of them */
static PVOID ReadRecords(const char *Value, ULONG RecordSize, ULONG *Count)
{
    HKEY Key;
    DWORD Type, Size = 0;
    PVOID Data = NULL;

    *Count = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyPath, 0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return NULL;
    if (RegQueryValueExA(Key, Value, NULL, &Type, NULL, &Size) == ERROR_SUCCESS && Size)
    {
        Data = HeapAlloc(GetProcessHeap(), 0, Size);
        if (Data && RegQueryValueExA(Key, Value, NULL, &Type, Data, &Size) == ERROR_SUCCESS)
        {
            ok(Type == REG_BINARY, "%s: type %lu\n", Value, Type);
            ok(Size % RecordSize == 0, "%s: size %lu\n", Value, Size);
            *Count = Size / RecordSize;
        }
    }
    RegCloseKey(Key);
    return Data;
}

/* The stored record of an address (a copy), FALSE: none */
static BOOL StoredAddress(const char *Text, TCP_IPV6_ADDRESS_REQUEST *Out)
{
    SOCKADDR_INET Address;
    PTCP_IPV6_ADDRESS_REQUEST Records;
    ULONG Count, i;
    BOOL Found = FALSE;

    Ipv6Parse(&Address, Text, 0);
    Records = ReadRecords("PersistentAddresses", sizeof(*Records), &Count);
    for (i = 0; i < Count && !Found; i++)
    {
        if (!memcmp(Records[i].Address, &Address.Ipv6.sin6_addr, 16))
        {
            *Out = Records[i];
            Found = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Records);
    return Found;
}

static BOOL StoredRoute(const char *Prefix, ULONG Length, TCP_IPV6_ROUTE_REQUEST *Out)
{
    SOCKADDR_INET Address;
    PTCP_IPV6_ROUTE_REQUEST Records;
    ULONG Count, i;
    BOOL Found = FALSE;

    Ipv6Parse(&Address, Prefix, 0);
    Records = ReadRecords("PersistentRoutes", sizeof(*Records), &Count);
    for (i = 0; i < Count && !Found; i++)
    {
        if (Records[i].PrefixLength == Length && !memcmp(Records[i].Prefix, &Address.Ipv6.sin6_addr, 16))
        {
            *Out = Records[i];
            Found = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Records);
    return Found;
}

static void TestAddresses(ULONG IfIndex)
{
    TCP_IPV6_ADDRESS_REQUEST Record;
    NTSTATUS Status;

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, 5, IfIndex, "2001:db8:9e::5", ~0UL);
    ok(Status == STATUS_INVALID_PARAMETER, "store 5: %lx\n", Status);

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9e::5", ~0UL);
    ok(Status == STATUS_SUCCESS, "create persistent: %lx\n", Status);
    ok(StoredAddress("2001:db8:9e::5", &Record), "persistent address not stored\n");
    ok(Record.PrefixLength == 64 && Record.ValidLifetime == ~0UL && Record.Store == TCP_IPV6_STORE_PERSISTENT &&
       Record.Operation == TCP_IPV6_CONFIG_CREATE, "record %lu %lx\n", Record.PrefixLength, Record.ValidLifetime);

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9e::6", ~0UL);
    ok(Status == STATUS_SUCCESS, "create active: %lx\n", Status);
    ok(!StoredAddress("2001:db8:9e::6", &Record), "active address stored\n");

    /* a change of the persistent one, asked for the active store: the record follows */
    Status = AddressRequest(TCP_IPV6_CONFIG_SET, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9e::5", 86400);
    ok(Status == STATUS_SUCCESS, "set: %lx\n", Status);
    ok(StoredAddress("2001:db8:9e::5", &Record) && Record.ValidLifetime == 86400, "record not changed: %lu\n",
       Record.ValidLifetime);

    /* removals: out of both stores */
    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9e::5", 0);
    ok(Status == STATUS_SUCCESS, "delete persistent: %lx\n", Status);
    ok(!StoredAddress("2001:db8:9e::5", &Record), "persistent address still stored\n");
    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9e::5", 0);
    ok(Status == STATUS_NOT_FOUND, "delete again: %lx\n", Status);
    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9e::6", 0);
    ok(Status == STATUS_SUCCESS, "delete active: %lx\n", Status);
}

static void TestRoutes(ULONG IfIndex)
{
    TCP_IPV6_ROUTE_REQUEST Record;
    NTSTATUS Status;

    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, 5, IfIndex, "2001:db8:9f::", 48, "fe80::9f", 10);
    ok(Status == STATUS_INVALID_PARAMETER, "store 5: %lx\n", Status);

    /* stored as the table names it: without the host bits */
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9f:1::1", 48,
                          "fe80::9f", 10);
    ok(Status == STATUS_SUCCESS, "create persistent: %lx\n", Status);
    ok(StoredRoute("2001:db8:9f::", 48, &Record), "persistent route not stored\n");
    ok(Record.Metric == 10 && Record.NextHop[0] == 0xfe && Record.NextHop[15] == 0x9f, "record metric %lu\n",
       Record.Metric);

    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:a0::", 48, "fe80::9f",
                          10);
    ok(Status == STATUS_SUCCESS, "create active: %lx\n", Status);
    ok(!StoredRoute("2001:db8:a0::", 48, &Record), "active route stored\n");

    Status = RouteRequest(TCP_IPV6_CONFIG_SET, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9f::", 48, "fe80::9f", 20);
    ok(Status == STATUS_SUCCESS, "set: %lx\n", Status);
    ok(StoredRoute("2001:db8:9f::", 48, &Record) && Record.Metric == 20, "record not changed: %lu\n", Record.Metric);

    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9f::", 48, "fe80::9f",
                          0);
    ok(Status == STATUS_SUCCESS, "delete persistent: %lx\n", Status);
    ok(!StoredRoute("2001:db8:9f::", 48, &Record), "persistent route still stored\n");
    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:a0::", 48, "fe80::9f", 0);
    ok(Status == STATUS_SUCCESS, "delete active: %lx\n", Status);
}

START_TEST(Ipv6Persist)
{
    WSADATA Data;
    ULONG IfIndex;
    NTSTATUS Status;

    pGetUnicastIpAddressTable = (PFN_GET_TABLE)Ipv6Proc("GetUnicastIpAddressTable");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    if (!pGetUnicastIpAddressTable || !pFreeMibTable)
    {
        skip("the IP Helper functions are missing\n");
        return;
    }
    WSAStartup(MAKEWORD(2, 2), &Data);

    if (!Ipv6SocketsWork())
    {
        Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, 2, "2001:db8:9e::5", ~0UL);
        ok(Status == STATUS_NOT_SUPPORTED, "IPv6 off: %lx\n", Status);
        WSACleanup();
        return;
    }

    IfIndex = EthernetIndex();
    if (!IfIndex)
    {
        skip("no Ethernet interface with IPv6\n");
        WSACleanup();
        return;
    }
    trace("adapter key %s\n", KeyPath);
    TestAddresses(IfIndex);
    TestRoutes(IfIndex);
    WSACleanup();
}
