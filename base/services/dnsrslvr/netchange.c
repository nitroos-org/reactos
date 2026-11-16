/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS DNS Resolver
 * FILE:        base/services/dnsrslvr/netchange.c
 * PURPOSE:     Flush the cache of the answers of the DNS servers when the network configuration changes
 *
 * Windows 10 and Server 2022 were measured (IPv4 address added to and removed from an adapter, IPv6 addresses
 * added and removed, DNS server list changed, adapter disabled and enabled; ipconfig /displaydns before and
 * after each step):
 *   - the cache is flushed when the first IPv4 address of an adapter goes (removed, replaced by another one,
 *     the adapter disabled);
 *   - it is not flushed when another IPv4 address is added or removed, when IPv6 addresses come or go, and when
 *     the list of DNS servers is changed.
 * The same rule is kept here: a thread waits for the address change notification (NotifyAddrChange) and
 * compares the first IPv4 address of every adapter with the list taken before.
 */

#include "precomp.h"
#include <iphlpapi.h>

#define NDEBUG
#include <debug.h>

#define NET_MAX_ADAPTERS    32
#define NET_MAX_ADDRESSES   256
#define NET_POLL_INTERVAL   5000    /* ms, used only when the notification cannot be had */

typedef struct _NET_ADDRESS
{
    DWORD IfIndex;
    ULONG Address;                  /* network order, never 0 */
} NET_ADDRESS;

typedef struct _NET_SNAPSHOT
{
    ULONG FirstCount;
    NET_ADDRESS First[NET_MAX_ADAPTERS];        /* the first address of every adapter */
    ULONG AllCount;
    NET_ADDRESS All[NET_MAX_ADDRESSES];         /* every address of every adapter */
    BOOL Truncated;                             /* the tables above were too small: any change is a change */
} NET_SNAPSHOT;

static HANDLE NetThread;
static HANDLE NetStopEvent;

/* "a.b.c.d" as a network order address; 0 when the text is not an address */
static
ULONG
ParseV4(
    _In_ const CHAR *Text)
{
    ULONG Part, Count = 0, Result = 0;
    const CHAR *p = Text;

    while (Count < 4)
    {
        if (*p < '0' || *p > '9')
            return 0;
        for (Part = 0; *p >= '0' && *p <= '9'; p++)
        {
            Part = Part * 10 + (*p - '0');
            if (Part > 255)
                return 0;
        }
        Result |= Part << (8 * Count);      /* the first part is the lowest byte: network order on a little endian CPU */
        Count++;
        if (Count < 4)
        {
            if (*p != '.')
                return 0;
            p++;
        }
    }
    return (*p == '\0') ? Result : 0;
}

/* The IPv4 addresses of the adapters, in the order the adapters list them. FALSE when they cannot be had */
static
BOOL
TakeSnapshot(
    _Out_ NET_SNAPSHOT *Snapshot)
{
    PIP_ADAPTER_INFO Info = NULL, Adapter;
    PIP_ADDR_STRING Address;
    ULONG Size = 0, Pass;
    DWORD Error = ERROR_BUFFER_OVERFLOW;
    BOOL First;

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    for (Pass = 0; Pass < 4 && Error == ERROR_BUFFER_OVERFLOW; Pass++)
    {
        if (Info)
            HeapFree(GetProcessHeap(), 0, Info);
        Info = Size ? HeapAlloc(GetProcessHeap(), 0, Size) : NULL;
        if (Size && !Info)
            return FALSE;
        Error = GetAdaptersInfo(Info, &Size);
    }

    /* no adapter at all is a state too */
    if (Error == ERROR_NO_DATA)
    {
        if (Info)
            HeapFree(GetProcessHeap(), 0, Info);
        return TRUE;
    }
    if (Error != ERROR_SUCCESS)
    {
        if (Info)
            HeapFree(GetProcessHeap(), 0, Info);
        return FALSE;
    }

    for (Adapter = Info; Adapter; Adapter = Adapter->Next)
    {
        First = TRUE;
        for (Address = &Adapter->IpAddressList; Address; Address = Address->Next)
        {
            ULONG Ip = ParseV4(Address->IpAddress.String);

            if (Ip == 0)
                continue;

            if (Snapshot->AllCount < NET_MAX_ADDRESSES)
            {
                Snapshot->All[Snapshot->AllCount].IfIndex = Adapter->Index;
                Snapshot->All[Snapshot->AllCount].Address = Ip;
                Snapshot->AllCount++;
            }
            else
            {
                Snapshot->Truncated = TRUE;
            }

            if (First)
            {
                First = FALSE;
                if (Snapshot->FirstCount < NET_MAX_ADAPTERS)
                {
                    Snapshot->First[Snapshot->FirstCount].IfIndex = Adapter->Index;
                    Snapshot->First[Snapshot->FirstCount].Address = Ip;
                    Snapshot->FirstCount++;
                }
                else
                {
                    Snapshot->Truncated = TRUE;
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, Info);
    return TRUE;
}

/* Has the first address of an adapter of Old gone: no adapter of New has it? */
static
BOOL
FirstAddressGone(
    _In_ const NET_SNAPSHOT *Old,
    _In_ const NET_SNAPSHOT *New)
{
    ULONG i, j;

    if (Old->Truncated || New->Truncated)
        return TRUE;

    for (i = 0; i < Old->FirstCount; i++)
    {
        for (j = 0; j < New->AllCount; j++)
        {
            if (New->All[j].IfIndex == Old->First[i].IfIndex && New->All[j].Address == Old->First[i].Address)
                break;
        }
        if (j == New->AllCount)
            return TRUE;
    }
    return FALSE;
}

static
DWORD
WINAPI
NetChangeThread(
    _In_ LPVOID Parameter)
{
    NET_SNAPSHOT Old, New;
    OVERLAPPED Overlapped;
    HANDLE Handle, Events[2];
    BOOL Armed = FALSE, HaveOld;
    DWORD Wait;

    UNREFERENCED_PARAMETER(Parameter);

    RtlZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Overlapped.hEvent)
        return 0;
    Events[0] = NetStopEvent;
    Events[1] = Overlapped.hEvent;

    /* the request is made before the list is taken: a change in between is reported by the next wait */
    ResetEvent(Overlapped.hEvent);
    Armed = (NotifyAddrChange(&Handle, &Overlapped) == ERROR_IO_PENDING);
    HaveOld = TakeSnapshot(&Old);

    for (;;)
    {
        Wait = WaitForMultipleObjects(2, Events, FALSE, Armed ? INFINITE : NET_POLL_INTERVAL);
        if (Wait == WAIT_OBJECT_0)
            break;
        if (Wait != WAIT_OBJECT_0 + 1 && Wait != WAIT_TIMEOUT)
            break;

        /* the next request first, then the list: a change after the list is taken is reported by the next wait */
        if (Wait == WAIT_OBJECT_0 + 1 || !Armed)
        {
            ResetEvent(Overlapped.hEvent);
            Armed = (NotifyAddrChange(&Handle, &Overlapped) == ERROR_IO_PENDING);
        }

        if (!TakeSnapshot(&New))
            continue;
        if (HaveOld && FirstAddressGone(&Old, &New))
        {
            DPRINT("The first address of an adapter is gone: flushing the cache\n");
            DnsIntCacheFlush(CACHE_FLUSH_NON_HOSTS_FILE_ENTRIES);
        }
        Old = New;
        HaveOld = TRUE;
    }

    /* the request is queued in the TCP/IP driver with this OVERLAPPED: end it before the structure goes */
    if (Armed)
    {
        CancelIPChangeNotify(&Overlapped);
        WaitForSingleObject(Overlapped.hEvent, 2000);
    }
    CloseHandle(Overlapped.hEvent);
    return 0;
}

VOID
DnsIntNetChangeStart(VOID)
{
    if (NetThread)
        return;

    NetStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!NetStopEvent)
        return;

    NetThread = CreateThread(NULL, 0, NetChangeThread, NULL, 0, NULL);
    if (!NetThread)
    {
        CloseHandle(NetStopEvent);
        NetStopEvent = NULL;
    }
}

VOID
DnsIntNetChangeStop(VOID)
{
    if (!NetThread)
        return;

    SetEvent(NetStopEvent);
    WaitForSingleObject(NetThread, 5000);
    CloseHandle(NetThread);
    CloseHandle(NetStopEvent);
    NetThread = NULL;
    NetStopEvent = NULL;
}
