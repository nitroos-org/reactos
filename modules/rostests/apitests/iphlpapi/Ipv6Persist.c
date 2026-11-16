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

static PFN_GET_TABLE pGetUnicastIpAddressTable, pGetIpForwardTable2;
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

/* Whether the address is in the active table of the interface */
static BOOL AddressActive(ULONG IfIndex, const char *Text)
{
    SOCKADDR_INET Address;
    UNICAST_TABLE6 *Table = NULL;
    BOOL Found = FALSE;
    ULONG i;

    Ipv6Parse(&Address, Text, 0);
    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries; i++)
    {
        if (Table->Table[i].InterfaceIndex == IfIndex &&
            !memcmp(&Table->Table[i].Address.Ipv6.sin6_addr, &Address.Ipv6.sin6_addr, 16))
            Found = TRUE;
    }
    pFreeMibTable(Table);
    return Found;
}

/* Whether the route (prefix, length, next hop in the table) is in the active table of the interface */
static BOOL RouteActive(ULONG IfIndex, const char *Prefix, ULONG Length)
{
    SOCKADDR_INET Address;
    ROUTE_TABLE6 *Table = NULL;
    BOOL Found = FALSE;
    ULONG i;

    Ipv6Parse(&Address, Prefix, 0);
    if (pGetIpForwardTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries; i++)
    {
        if (Table->Table[i].InterfaceIndex == IfIndex && Table->Table[i].DestinationPrefix.PrefixLength == Length &&
            !memcmp(&Table->Table[i].DestinationPrefix.Prefix.Ipv6.sin6_addr, &Address.Ipv6.sin6_addr, 16))
            Found = TRUE;
    }
    pFreeMibTable(Table);
    return Found;
}

/* Puts records in place of a value of the adapter's key (the test restores what it replaced) */
static BOOL WriteRecords(const char *Value, const VOID *Data, DWORD Size)
{
    HKEY Key;
    DWORD Error;

    Error = RegCreateKeyExA(HKEY_LOCAL_MACHINE, KeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &Key,
                            NULL);
    if (Error != ERROR_SUCCESS)
        return FALSE;
    Error = Data ? RegSetValueExA(Key, Value, 0, REG_BINARY, Data, Size) : RegDeleteValueA(Key, Value);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS || (!Data && Error == ERROR_FILE_NOT_FOUND);
}

/* A creation racing a removal of the same entry: the persistent store ends as the active table does. Two threads
   (the one that makes at a lower priority than the one that removes, so that the removal can overtake a creation
   that is between the change of the table and the write of the record) make and remove the same persistent address
   (or route) at the same moment, Rounds times; after each round, with both requests answered, the entry is in the
   store exactly when it is in the table. Each round starts with neither */
typedef struct
{
    BOOL Route;
    ULONG Operation;
    ULONG IfIndex;
    HANDLE Start;
    HANDLE Done;
    volatile LONG Stop;
    ULONG Unexpected;
} RACE_PARAM;

static DWORD WINAPI RaceThread(PVOID Param)
{
    RACE_PARAM *P = Param;
    NTSTATUS Status;

    for (;;)
    {
        WaitForSingleObject(P->Start, INFINITE);
        if (P->Stop)
            break;
        if (P->Route)
            Status = RouteRequest(P->Operation, TCP_IPV6_STORE_PERSISTENT, P->IfIndex, "2001:db8:a1::", 48,
                                  "fe80::a1", 10);
        else
            Status = AddressRequest(P->Operation, TCP_IPV6_STORE_PERSISTENT, P->IfIndex, "2001:db8:a1::5", ~0UL);
        if (Status != STATUS_SUCCESS && Status != STATUS_OBJECT_NAME_COLLISION && Status != STATUS_NOT_FOUND)
            P->Unexpected++;
        SetEvent(P->Done);
    }
    return 0;
}

/* Rounds: 10000, or the number the environment variable IPV6RACE gives */
static ULONG RaceCount(void)
{
    char Text[16];

    if (GetEnvironmentVariableA("IPV6RACE", Text, sizeof(Text)) && atol(Text) > 0)
        return atol(Text);
    return 10000;
}

static void RaceClean(ULONG IfIndex, BOOL Route)
{
    if (Route)
        RouteRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:a1::", 48, "fe80::a1", 0);
    else
        AddressRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:a1::5", 0);
}

static void TestRace(ULONG IfIndex, BOOL Route)
{
    RACE_PARAM Make, Remove;
    HANDLE Threads[2], Done[2];
    TCP_IPV6_ADDRESS_REQUEST AddressRecord;
    TCP_IPV6_ROUTE_REQUEST RouteRecord;
    BOOL Active, Stored;
    ULONG Round, Rounds = RaceCount(), Mismatches = 0, Unexpected, Left = 0, Extra = 0;

    memset(&Make, 0, sizeof(Make));
    memset(&Remove, 0, sizeof(Remove));
    Make.Route = Remove.Route = Route;
    Make.Operation = TCP_IPV6_CONFIG_CREATE;
    Remove.Operation = TCP_IPV6_CONFIG_DELETE;
    Make.IfIndex = Remove.IfIndex = IfIndex;
    Make.Start = CreateEventW(NULL, FALSE, FALSE, NULL);
    Make.Done = CreateEventW(NULL, FALSE, FALSE, NULL);
    Remove.Start = CreateEventW(NULL, FALSE, FALSE, NULL);
    Remove.Done = CreateEventW(NULL, FALSE, FALSE, NULL);
    Done[0] = Make.Done;
    Done[1] = Remove.Done;
    Threads[0] = CreateThread(NULL, 0, RaceThread, &Make, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, RaceThread, &Remove, 0, NULL);
    SetThreadPriority(Threads[0], THREAD_PRIORITY_BELOW_NORMAL);
    SetThreadPriority(Threads[1], THREAD_PRIORITY_ABOVE_NORMAL);

    RaceClean(IfIndex, Route);
    for (Round = 0; Round < Rounds; Round++)
    {
        SetEvent(Make.Start);
        SetEvent(Remove.Start);
        WaitForMultipleObjects(2, Done, TRUE, INFINITE);

        if (Route)
        {
            Active = RouteActive(IfIndex, "2001:db8:a1::", 48);
            Stored = StoredRoute("2001:db8:a1::", 48, &RouteRecord);
        }
        else
        {
            Active = AddressActive(IfIndex, "2001:db8:a1::5");
            Stored = StoredAddress("2001:db8:a1::5", &AddressRecord);
        }
        if (Active != Stored)
        {
            Mismatches++;
            if (Active)
                Left++;     /* in the table, not in the store */
            else
                Extra++;    /* in the store, not in the table */
        }
        /* neither, for the next round (a removal takes the entry out of both) */
        RaceClean(IfIndex, Route);
    }
    ok(Mismatches == 0, "%s: %lu of %lu rounds ended with the store out of step (%lu in the table only, %lu in the "
       "store only)\n", Route ? "route" : "address", Mismatches, Rounds, Left, Extra);

    Make.Stop = Remove.Stop = TRUE;
    SetEvent(Make.Start);
    SetEvent(Remove.Start);
    WaitForMultipleObjects(2, Threads, TRUE, INFINITE);
    Unexpected = Make.Unexpected + Remove.Unexpected;
    ok(Unexpected == 0, "%s race: %lu unexpected answers\n", Route ? "route" : "address", Unexpected);
    CloseHandle(Threads[0]);
    CloseHandle(Threads[1]);
    CloseHandle(Make.Start);
    CloseHandle(Make.Done);
    CloseHandle(Remove.Start);
    CloseHandle(Remove.Done);
    RaceClean(IfIndex, Route);
}

/* A store that holds as many records as the value can (65520 bytes: 1260 addresses, 910 routes): one of them can be
   changed and removed, and a creation that no longer fits is refused and leaves nothing behind */
#define FULL_ADDRESSES  1260
#define FULL_ROUTES     910

static void TestFullAddressStore(ULONG IfIndex)
{
    TCP_IPV6_ADDRESS_REQUEST *Records, Record, Saved;
    PVOID Old;
    ULONG OldCount, Count, i;
    NTSTATUS Status;

    Old = ReadRecords("PersistentAddresses", sizeof(Record), &OldCount);
    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9e::5", ~0UL);
    ok(Status == STATUS_SUCCESS, "create persistent: %lx\n", Status);
    if (!StoredAddress("2001:db8:9e::5", &Saved))
    {
        ok(0, "the persistent address is not stored\n");
        goto Done;
    }

    Records = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FULL_ADDRESSES * sizeof(Record));
    for (i = 0; i < FULL_ADDRESSES; i++)
    {
        Records[i] = Saved;
        if (i)
        {
            Records[i].Address[0] = 0x20; Records[i].Address[1] = 0x01; Records[i].Address[2] = 0x0d;
            Records[i].Address[3] = 0xb8; Records[i].Address[5] = 0xfe;
            memset(Records[i].Address + 6, 0, 10);
            Records[i].Address[14] = (UCHAR)(i >> 8);
            Records[i].Address[15] = (UCHAR)i;
        }
    }
    ok(WriteRecords("PersistentAddresses", Records, FULL_ADDRESSES * sizeof(Record)), "store not written\n");
    HeapFree(GetProcessHeap(), 0, Records);

    Status = AddressRequest(TCP_IPV6_CONFIG_SET, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9e::5", 86400);
    ok(Status == STATUS_SUCCESS, "change in a full store: %lx\n", Status);
    ok(StoredAddress("2001:db8:9e::5", &Record) && Record.ValidLifetime == 86400, "record not changed: %lu\n",
       Record.ValidLifetime);
    Records = ReadRecords("PersistentAddresses", sizeof(Record), &Count);
    ok(Count == FULL_ADDRESSES, "records after the change: %lu\n", Count);
    HeapFree(GetProcessHeap(), 0, Records);

    Status = AddressRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9e::6", ~0UL);
    ok(Status == STATUS_INSUFFICIENT_RESOURCES, "creation in a full store: %lx\n", Status);
    ok(!AddressActive(IfIndex, "2001:db8:9e::6"), "the address the store refused is active\n");
    ok(!StoredAddress("2001:db8:9e::6", &Record), "the address the store refused is stored\n");

    Status = AddressRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9e::5", 0);
    ok(Status == STATUS_SUCCESS, "removal from a full store: %lx\n", Status);
    ok(!StoredAddress("2001:db8:9e::5", &Record), "the removed address is still stored\n");
    Records = ReadRecords("PersistentAddresses", sizeof(Record), &Count);
    ok(Count == FULL_ADDRESSES - 1, "records after the removal: %lu\n", Count);
    HeapFree(GetProcessHeap(), 0, Records);

Done:
    AddressRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9e::5", 0);
    WriteRecords("PersistentAddresses", Old, OldCount * sizeof(Record));
    if (Old)
        HeapFree(GetProcessHeap(), 0, Old);
}

static void TestFullRouteStore(ULONG IfIndex)
{
    TCP_IPV6_ROUTE_REQUEST *Records, Record, Saved;
    PVOID Old;
    ULONG OldCount, Count, i;
    NTSTATUS Status;

    Old = ReadRecords("PersistentRoutes", sizeof(Record), &OldCount);
    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9f::", 48, "fe80::9f",
                          10);
    ok(Status == STATUS_SUCCESS, "create persistent: %lx\n", Status);
    if (!StoredRoute("2001:db8:9f::", 48, &Saved))
    {
        ok(0, "the persistent route is not stored\n");
        goto Done;
    }

    Records = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FULL_ROUTES * sizeof(Record));
    for (i = 0; i < FULL_ROUTES; i++)
    {
        Records[i] = Saved;
        if (i)
        {
            Records[i].Prefix[0] = 0x20; Records[i].Prefix[1] = 0x01; Records[i].Prefix[2] = 0x0d;
            Records[i].Prefix[3] = 0xb8; Records[i].Prefix[5] = 0xfd;
            memset(Records[i].Prefix + 6, 0, 10);
            Records[i].Prefix[6] = (UCHAR)(i >> 8);
            Records[i].Prefix[7] = (UCHAR)i;
            Records[i].PrefixLength = 64;
        }
    }
    ok(WriteRecords("PersistentRoutes", Records, FULL_ROUTES * sizeof(Record)), "store not written\n");
    HeapFree(GetProcessHeap(), 0, Records);

    Status = RouteRequest(TCP_IPV6_CONFIG_SET, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9f::", 48, "fe80::9f", 20);
    ok(Status == STATUS_SUCCESS, "change in a full store: %lx\n", Status);
    ok(StoredRoute("2001:db8:9f::", 48, &Record) && Record.Metric == 20, "record not changed: %lu\n", Record.Metric);
    Records = ReadRecords("PersistentRoutes", sizeof(Record), &Count);
    ok(Count == FULL_ROUTES, "records after the change: %lu\n", Count);
    HeapFree(GetProcessHeap(), 0, Records);

    Status = RouteRequest(TCP_IPV6_CONFIG_CREATE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:a0::", 48, "fe80::9f",
                          10);
    ok(Status == STATUS_INSUFFICIENT_RESOURCES, "creation in a full store: %lx\n", Status);
    ok(!RouteActive(IfIndex, "2001:db8:a0::", 48), "the route the store refused is active\n");
    ok(!StoredRoute("2001:db8:a0::", 48, &Record), "the route the store refused is stored\n");

    Status = RouteRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_ACTIVE, IfIndex, "2001:db8:9f::", 48, "fe80::9f", 0);
    ok(Status == STATUS_SUCCESS, "removal from a full store: %lx\n", Status);
    ok(!StoredRoute("2001:db8:9f::", 48, &Record), "the removed route is still stored\n");
    Records = ReadRecords("PersistentRoutes", sizeof(Record), &Count);
    ok(Count == FULL_ROUTES - 1, "records after the removal: %lu\n", Count);
    HeapFree(GetProcessHeap(), 0, Records);

Done:
    RouteRequest(TCP_IPV6_CONFIG_DELETE, TCP_IPV6_STORE_PERSISTENT, IfIndex, "2001:db8:9f::", 48, "fe80::9f", 0);
    WriteRecords("PersistentRoutes", Old, OldCount * sizeof(Record));
    if (Old)
        HeapFree(GetProcessHeap(), 0, Old);
}

START_TEST(Ipv6Persist)
{
    WSADATA Data;
    ULONG IfIndex;
    NTSTATUS Status;

    pGetUnicastIpAddressTable = (PFN_GET_TABLE)Ipv6Proc("GetUnicastIpAddressTable");
    pGetIpForwardTable2 = (PFN_GET_TABLE)Ipv6Proc("GetIpForwardTable2");
    pFreeMibTable = (PFN_FREE_TABLE)Ipv6Proc("FreeMibTable");
    if (!pGetUnicastIpAddressTable || !pGetIpForwardTable2 || !pFreeMibTable)
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
    TestFullAddressStore(IfIndex);
    TestFullRouteStore(IfIndex);
    TestRace(IfIndex, FALSE);
    TestRace(IfIndex, TRUE);
    WSACleanup();
}
