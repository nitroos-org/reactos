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

typedef BOOLEAN (*PERSIST6_SAME_KEY)(const VOID *A, const VOID *B);

VOID
TCP6PersistInit(VOID)
{
    ExInitializeFastMutex(&Persist6Lock);
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

    Persist6ReadValue(Key, Name, RecordSize, (PVOID *)&Old, &Count);
    if (Count + 1 > PERSIST6_MAX_VALUE / RecordSize)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
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

    if (!TCPIpv6Enabled || IF == Loopback || !netif || IF->AddressLength != 6)
        return;

    ExAcquireFastMutex(&Persist6Lock);
    if (NT_SUCCESS(Persist6OpenKey(IF, FALSE, &Key)))
    {
        Persist6ReadValue(Key, PERSIST6_ADDRESSES, sizeof(*Addresses), (PVOID *)&Addresses, &AddressCount);
        Persist6ReadValue(Key, PERSIST6_ROUTES, sizeof(*Routes), (PVOID *)&Routes, &RouteCount);
        ZwClose(Key);
    }
    ExReleaseFastMutex(&Persist6Lock);

    if (!AddressCount && !RouteCount)
        return;

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
