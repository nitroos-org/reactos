/*
 * PROJECT:     NitroOS TCP/IP driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The persistent store of the IPv6 configuration: configured addresses and routes that come back
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * An address or route configured with TCP_IPV6_STORE_PERSISTENT (IOCTL_IP6_ADDRESS_CONFIG, IOCTL_IP6_ROUTE_CONFIG)
 * is written to
 *
 *     HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\<adapter GUID>
 *         PersistentAddresses  REG_BINARY  TCP_IPV6_ADDRESS_REQUEST records
 *         PersistentRoutes     REG_BINARY  TCP_IPV6_ROUTE_REQUEST records
 *
 * and applied again whenever the adapter starts (ReconfigureAdapter: at boot, when it is enabled again, when its
 * link comes back), as the IPv4 configuration of Tcpip\Parameters\Interfaces\<GUID> is. The key is the adapter's,
 * so the entries follow the adapter whatever interface index it gets; Tcpip6 is the service key of the IPv6
 * configuration (Windows keeps its own in a private binary store that no application reads, so nothing depends on
 * the place). The records are the request layout (ULONGs and bytes: the same for 32-bit and 64-bit code), with the
 * interface index not used. An entry of the active store only is not written: it goes when the computer restarts or
 * the interface goes. A removal takes the entry out of both stores. Every registry access is at PASSIVE_LEVEL under
 * Persist6Lock, never under lwIP's core lock.
 */

#include "precomp.h"

#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"

#define PERSIST6_INTERFACES     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces"
#define PERSIST6_ADDRESSES      L"PersistentAddresses"
#define PERSIST6_ROUTES         L"PersistentRoutes"
#define PERSIST6_TAG            'P6pI'
/* Larger values are not read (a value of this size holds far more than an interface can have) */
#define PERSIST6_MAX_VALUE      0x10000

static FAST_MUTEX Persist6Lock;
/* One configuration request at a time, from the active table to the persistent record (taken before the core lock
   and Persist6Lock; the application of the store at an adapter start takes it too) */
static FAST_MUTEX Config6Lock;

typedef BOOLEAN (*PERSIST6_SAME_KEY)(const VOID *A, const VOID *B);

VOID
TCP6PersistInit(VOID)
{
    ExInitializeFastMutex(&Persist6Lock);
    ExInitializeFastMutex(&Config6Lock);
}

VOID
TCP6ConfigLock(VOID)
{
    ExAcquireFastMutex(&Config6Lock);
}

VOID
TCP6ConfigUnlock(VOID)
{
    ExReleaseFastMutex(&Config6Lock);
}

/* The key of the adapter of IF (Create: made if it is not there) */
static
NTSTATUS
Persist6OpenKey(PIP_INTERFACE IF, BOOLEAN Create, PHANDLE Key)
{
    UNICODE_STRING Root = RTL_CONSTANT_STRING(PERSIST6_INTERFACES);
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Parent;
    NTSTATUS Status;
    USHORT i;

    /* the adapter's GUID: one path element */
    if (!IF->Name.Buffer || IF->Name.Length == 0)
        return STATUS_OBJECT_NAME_INVALID;
    for (i = 0; i < IF->Name.Length / sizeof(WCHAR); i++)
    {
        if (IF->Name.Buffer[i] == L'\\')
            return STATUS_OBJECT_NAME_INVALID;
    }

    InitializeObjectAttributes(&Attributes, &Root, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (Create)
        Status = ZwCreateKey(&Parent, KEY_CREATE_SUB_KEY, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    else
        Status = ZwOpenKey(&Parent, KEY_ENUMERATE_SUB_KEYS, &Attributes);
    if (!NT_SUCCESS(Status))
        return Status;

    InitializeObjectAttributes(&Attributes, &IF->Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, Parent, NULL);
    if (Create)
        Status = ZwCreateKey(Key, KEY_QUERY_VALUE | KEY_SET_VALUE, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE,
                             NULL);
    else
        Status = ZwOpenKey(Key, KEY_QUERY_VALUE, &Attributes);
    ZwClose(Parent);
    return Status;
}

/* The records of a value (pool, the caller frees it), *Count of them; none: NULL and 0 */
static
VOID
Persist6ReadValue(HANDLE Key, PCWSTR Name, ULONG RecordSize, PVOID *Records, PULONG Count)
{
    UNICODE_STRING ValueName;
    PKEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG Length = 0;
    NTSTATUS Status;

    *Records = NULL;
    *Count = 0;
    RtlInitUnicodeString(&ValueName, Name);

    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, NULL, 0, &Length);
    if ((Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) || Length == 0 ||
        Length > PERSIST6_MAX_VALUE + sizeof(*Info))
        return;

    Info = ExAllocatePoolWithTag(PagedPool, Length, PERSIST6_TAG);
    if (!Info)
        return;
    Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, Length, &Length);
    if (NT_SUCCESS(Status) && Info->Type == REG_BINARY && Info->DataLength != 0 &&
        Info->DataLength <= PERSIST6_MAX_VALUE && Info->DataLength % RecordSize == 0)
    {
        *Records = ExAllocatePoolWithTag(PagedPool, Info->DataLength, PERSIST6_TAG);
        if (*Records)
        {
            RtlCopyMemory(*Records, Info->Data, Info->DataLength);
            *Count = Info->DataLength / RecordSize;
        }
    }
    ExFreePoolWithTag(Info, PERSIST6_TAG);
}

/* Puts Record into a value of the adapter's key in place of the one with its key, or (Remove) takes that one out.
   *Found: there was one. PASSIVE_LEVEL, no lock held */
static
NTSTATUS
Persist6Update(PIP_INTERFACE IF, PCWSTR Name, ULONG RecordSize, const VOID *Record, BOOLEAN Remove,
               PERSIST6_SAME_KEY SameKey, PBOOLEAN Found)
{
    UNICODE_STRING ValueName;
    HANDLE Key;
    PUCHAR Old, New;
    ULONG Count, Kept = 0, i;
    NTSTATUS Status;

    *Found = FALSE;
    RtlInitUnicodeString(&ValueName, Name);

    ExAcquireFastMutex(&Persist6Lock);

    /* a removal does not make the key */
    Status = Persist6OpenKey(IF, !Remove, &Key);
    if (!NT_SUCCESS(Status))
    {
        ExReleaseFastMutex(&Persist6Lock);
        return Remove ? STATUS_SUCCESS : Status;
    }

    /* the store holds at most PERSIST6_MAX_VALUE / RecordSize records (what is read back); Count is within it */
    Persist6ReadValue(Key, Name, RecordSize, (PVOID *)&Old, &Count);
    New = ExAllocatePoolWithTag(PagedPool, (Count + 1) * RecordSize, PERSIST6_TAG);
    if (!New)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    for (i = 0; i < Count; i++)
    {
        if (SameKey(Old + i * RecordSize, Record))
        {
            *Found = TRUE;
            continue;
        }
        RtlCopyMemory(New + Kept * RecordSize, Old + i * RecordSize, RecordSize);
        Kept++;
    }
    if (!Remove)
    {
        RtlCopyMemory(New + Kept * RecordSize, Record, RecordSize);
        Kept++;
    }

    /* judged by what the value would hold, not by what it holds: a store with exactly the most records can still
       have one of them changed or removed */
    if (Kept > PERSIST6_MAX_VALUE / RecordSize)
    {
        ExFreePoolWithTag(New, PERSIST6_TAG);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    if (Kept)
        Status = ZwSetValueKey(Key, &ValueName, 0, REG_BINARY, New, Kept * RecordSize);
    else if (Count)
        Status = ZwDeleteValueKey(Key, &ValueName);
    else
        Status = STATUS_SUCCESS;
    ExFreePoolWithTag(New, PERSIST6_TAG);

Done:
    if (Old)
        ExFreePoolWithTag(Old, PERSIST6_TAG);
    ZwClose(Key);
    ExReleaseFastMutex(&Persist6Lock);
    return Status;
}

static
BOOLEAN
Persist6SameAddress(const VOID *A, const VOID *B)
{
    const TCP_IPV6_ADDRESS_REQUEST *X = A, *Y = B;

    return RtlCompareMemory(X->Address, Y->Address, 16) == 16;
}

static
BOOLEAN
Persist6SameRoute(const VOID *A, const VOID *B)
{
    const TCP_IPV6_ROUTE_REQUEST *X = A, *Y = B;

    return X->PrefixLength == Y->PrefixLength && RtlCompareMemory(X->Prefix, Y->Prefix, 16) == 16 &&
           RtlCompareMemory(X->NextHop, Y->NextHop, 16) == 16;
}

/* The persistent record of an address (Remove: its removal). The request was checked; *Found: there was one */
NTSTATUS
TCP6PersistAddress(PIP_INTERFACE IF, const TCP_IPV6_ADDRESS_REQUEST *Request, BOOLEAN Remove, PBOOLEAN Found)
{
    TCP_IPV6_ADDRESS_REQUEST Record = *Request;

    Record.Operation = TCP_IPV6_CONFIG_CREATE;
    Record.Store = TCP_IPV6_STORE_PERSISTENT;
    Record.IfIndex = 0;
    return Persist6Update(IF, PERSIST6_ADDRESSES, sizeof(Record), &Record, Remove, Persist6SameAddress, Found);
}

/* The persistent record of a route; Request->Prefix is masked to its length already */
NTSTATUS
TCP6PersistRoute(PIP_INTERFACE IF, const TCP_IPV6_ROUTE_REQUEST *Request, BOOLEAN Remove, PBOOLEAN Found)
{
    TCP_IPV6_ROUTE_REQUEST Record = *Request;

    Record.Operation = TCP_IPV6_CONFIG_CREATE;
    Record.Store = TCP_IPV6_STORE_PERSISTENT;
    Record.IfIndex = 0;
    return Persist6Update(IF, PERSIST6_ROUTES, sizeof(Record), &Record, Remove, Persist6SameRoute, Found);
}

/*
 * The interface parameters (SetIpInterfaceEntry, ifcfg.c), values of the adapter's key:
 *
 *     Tcpip6\Parameters\Interfaces\<GUID>   NlMtu, InterfaceMetric, RouterDiscovery, DadTransmits   REG_DWORD (IPv6)
 *     Tcpip\Parameters\Interfaces\<GUID>    MTU, InterfaceMetric                                    REG_DWORD (IPv4)
 *
 * (the IPv4 values are the ones the stack and the IP configuration tools already know). A metric of 0 (automatic)
 * deletes InterfaceMetric. The IPv6 values are read by TCP6ApplyInterfaceParams when the adapter starts.
 */
#define PERSIST4_INTERFACES     L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"

static
NTSTATUS
Persist6SetDword(HANDLE Key, PCWSTR Name, ULONG Value)
{
    UNICODE_STRING ValueName;

    RtlInitUnicodeString(&ValueName, Name);
    return ZwSetValueKey(Key, &ValueName, 0, REG_DWORD, &Value, sizeof(Value));
}

static
NTSTATUS
Persist6SetMetric(HANDLE Key, ULONG Metric)
{
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"InterfaceMetric");
    NTSTATUS Status;

    if (Metric)
        return Persist6SetDword(Key, L"InterfaceMetric", Metric);
    Status = ZwDeleteValueKey(Key, &ValueName);
    return (Status == STATUS_OBJECT_NAME_NOT_FOUND) ? STATUS_SUCCESS : Status;
}

/* Writes what a request of the persistent store changed (PASSIVE_LEVEL, no lock held) */
NTSTATUS
TCP6PersistInterface(PIP_INTERFACE IF, const TCP_IP_INTERFACE_REQUEST *Request)
{
    HANDLE Key;
    NTSTATUS Status;

    ExAcquireFastMutex(&Persist6Lock);
    if (Request->Family == TCP_IPIF_IPV6)
    {
        Status = Persist6OpenKey(IF, TRUE, &Key);
        if (NT_SUCCESS(Status))
        {
            if (Request->Fields & TCP_IPIF_SET_MTU)
                Status = Persist6SetDword(Key, L"NlMtu", Request->Mtu);
            if (NT_SUCCESS(Status) && (Request->Fields & TCP_IPIF_SET_METRIC))
                Status = Persist6SetMetric(Key, Request->Metric);
            if (NT_SUCCESS(Status) && (Request->Fields & TCP_IPIF_SET_ROUTER_DISCOVERY))
                Status = Persist6SetDword(Key, L"RouterDiscovery", Request->RouterDiscovery);
            if (NT_SUCCESS(Status) && (Request->Fields & TCP_IPIF_SET_DAD_TRANSMITS))
                Status = Persist6SetDword(Key, L"DadTransmits", Request->DadTransmits);
            ZwClose(Key);
        }
    }
    else
    {
        UNICODE_STRING Root = RTL_CONSTANT_STRING(PERSIST4_INTERFACES);
        OBJECT_ATTRIBUTES Attributes;

        if (!IF->Name.Buffer || IF->Name.Length == 0)
            Status = STATUS_OBJECT_NAME_INVALID;
        else
        {
            WCHAR Path[160];
            UNICODE_STRING Full;

            Full.Buffer = Path;
            Full.Length = 0;
            Full.MaximumLength = sizeof(Path);
            Status = RtlAppendUnicodeStringToString(&Full, &Root);
            if (NT_SUCCESS(Status))
                Status = RtlAppendUnicodeToString(&Full, L"\\");
            if (NT_SUCCESS(Status))
                Status = RtlAppendUnicodeStringToString(&Full, &IF->Name);
            if (NT_SUCCESS(Status))
            {
                InitializeObjectAttributes(&Attributes, &Full, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                Status = ZwCreateKey(&Key, KEY_SET_VALUE, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
            }
            if (NT_SUCCESS(Status))
            {
                if (Request->Fields & TCP_IPIF_SET_MTU)
                    Status = Persist6SetDword(Key, L"MTU", Request->Mtu);
                if (NT_SUCCESS(Status) && (Request->Fields & TCP_IPIF_SET_METRIC))
                    Status = Persist6SetMetric(Key, Request->Metric);
                ZwClose(Key);
            }
        }
    }
    ExReleaseFastMutex(&Persist6Lock);
    return Status;
}

static
BOOLEAN
Persist6GetDword(HANDLE Key, PCWSTR Name, PULONG Value)
{
    UNICODE_STRING ValueName;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    ULONG Length;

    RtlInitUnicodeString(&ValueName, Name);
    if (!NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)))
        return FALSE;
    if (Info->Type != REG_DWORD || Info->DataLength != sizeof(ULONG))
        return FALSE;
    *Value = *(PULONG)Info->Data;
    return TRUE;
}

/* The IPv6 parameters stored for the adapter; a value that is not there stays at what it was given (PASSIVE_LEVEL) */
VOID
TCP6ReadInterfaceParams(PIP_INTERFACE IF, PULONG Mtu, PULONG Metric, PULONG RouterDiscovery, PULONG DadTransmits)
{
    HANDLE Key;

    ExAcquireFastMutex(&Persist6Lock);
    if (NT_SUCCESS(Persist6OpenKey(IF, FALSE, &Key)))
    {
        Persist6GetDword(Key, L"NlMtu", Mtu);
        Persist6GetDword(Key, L"InterfaceMetric", Metric);
        Persist6GetDword(Key, L"RouterDiscovery", RouterDiscovery);
        Persist6GetDword(Key, L"DadTransmits", DadTransmits);
        ZwClose(Key);
    }
    ExReleaseFastMutex(&Persist6Lock);
}

/* The adapter of IF started (ReconfigureAdapter, PASSIVE_LEVEL): its persistent addresses and routes that are not
   there are added (addresses first: a route may need the prefix of one) */
VOID
TCP6ApplyPersistent(PIP_INTERFACE IF)
{
    PTCP_IPV6_ADDRESS_REQUEST Addresses = NULL;
    PTCP_IPV6_ROUTE_REQUEST Routes = NULL;
    ULONG AddressCount = 0, RouteCount = 0, i, Added = 0;
    struct netif *netif = IF->TCPContext;
    HANDLE Key;

    if (!TCPIpv6Links || IF == Loopback || !netif || IF->AddressLength != 6)
        return;

    /* the interface parameters first: duplicate address detection and router discovery follow them */
    TCP6ApplyInterfaceParams(IF);

    /* a request that removes an entry must not come between the read of the store and the application of what was
       read: the entry would be added again */
    TCP6ConfigLock();
    ExAcquireFastMutex(&Persist6Lock);
    if (NT_SUCCESS(Persist6OpenKey(IF, FALSE, &Key)))
    {
        Persist6ReadValue(Key, PERSIST6_ADDRESSES, sizeof(*Addresses), (PVOID *)&Addresses, &AddressCount);
        Persist6ReadValue(Key, PERSIST6_ROUTES, sizeof(*Routes), (PVOID *)&Routes, &RouteCount);
        ZwClose(Key);
    }
    ExReleaseFastMutex(&Persist6Lock);

    if (!AddressCount && !RouteCount)
    {
        TCP6ConfigUnlock();
        return;
    }

    LOCK_TCPIP_CORE();
    if (TCP6NetifRegistered(netif))
    {
        for (i = 0; i < AddressCount; i++)
        {
            if (TCP6ApplyAddressLocked(netif, &Addresses[i]) == STATUS_SUCCESS)
                Added++;
        }
        for (i = 0; i < RouteCount; i++)
        {
            if (TCP6ApplyRouteLocked(IF, netif, &Routes[i]) == STATUS_SUCCESS)
                Added++;
        }
    }
    UNLOCK_TCPIP_CORE();
    TCP6ConfigUnlock();

    if (Added)
    {
        DbgPrint("TCPIP: IPv6 persistent configuration of interface %u: %lu of %lu addresses and routes applied\n",
                 IF->Index, Added, AddressCount + RouteCount);
        RouteChangeNotify();
    }

    if (Addresses)
        ExFreePoolWithTag(Addresses, PERSIST6_TAG);
    if (Routes)
        ExFreePoolWithTag(Routes, PERSIST6_TAG);
}
