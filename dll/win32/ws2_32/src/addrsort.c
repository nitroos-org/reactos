/*
 * PROJECT:     ReactOS WinSock 2.2 Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Destination address ordering (RFC 6724): getaddrinfo results and SIO_ADDRESS_LIST_SORT
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <ws2_32.h>

#include <ws2tcpip.h>
#include <mswsock.h>

/*
 * The ordering is CreateSortedAddressPairs of iphlpapi (its engine and the prefix policy table are there): it
 * knows the addresses of the host and the routes. iphlpapi imports this DLL, so it is loaded when the first sort
 * is asked for and never unloaded. A system where it cannot be loaded keeps the order it was given.
 */

typedef DWORD (WINAPI *PCREATE_SORTED_ADDRESS_PAIRS)(const PSOCKADDR_IN6, ULONG, const PSOCKADDR_IN6, ULONG, ULONG,
                                                     PSOCKADDR_IN6_PAIR *, ULONG *);
typedef VOID (WINAPI *PFREE_MIB_TABLE)(PVOID);

static PCREATE_SORTED_ADDRESS_PAIRS WsCreateSortedAddressPairs;
static PFREE_MIB_TABLE WsFreeMibTable;
/* 0 = not tried, 1 = loaded, 2 = not available */
static volatile LONG WsSorterState;

/* More than this is not sorted: the answer would cost more than it helps */
#define WS_SORT_MAX 256

static
BOOL
WsLoadSorter(VOID)
{
    HMODULE Module;
    PCREATE_SORTED_ADDRESS_PAIRS Create;
    PFREE_MIB_TABLE Free;

    if (WsSorterState == 1)
        return TRUE;
    if (WsSorterState == 2)
        return FALSE;

    Module = LoadLibraryW(L"iphlpapi.dll");
    Create = Module ? (PCREATE_SORTED_ADDRESS_PAIRS)GetProcAddress(Module, "CreateSortedAddressPairs") : NULL;
    Free = Module ? (PFREE_MIB_TABLE)GetProcAddress(Module, "FreeMibTable") : NULL;
    if (!Create || !Free)
    {
        InterlockedExchange(&WsSorterState, 2);
        return FALSE;
    }
    WsCreateSortedAddressPairs = Create;
    WsFreeMibTable = Free;
    InterlockedExchange(&WsSorterState, 1);
    return TRUE;
}

/* A socket address (AF_INET or AF_INET6) as the IPv6 address CreateSortedAddressPairs takes */
static
BOOL
WsToMapped(const SOCKADDR *Address, ULONG Length, PSOCKADDR_IN6 Out)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->sin6_family = AF_INET6;
    if (Address->sa_family == AF_INET && Length >= sizeof(SOCKADDR_IN))
    {
        Out->sin6_addr.u.Byte[10] = 0xff;
        Out->sin6_addr.u.Byte[11] = 0xff;
        RtlCopyMemory(Out->sin6_addr.u.Byte + 12, &((const SOCKADDR_IN *)Address)->sin_addr, 4);
        return TRUE;
    }
    if (Address->sa_family == AF_INET6 && Length >= sizeof(SOCKADDR_IN6))
    {
        Out->sin6_addr = ((const SOCKADDR_IN6 *)Address)->sin6_addr;
        Out->sin6_scope_id = ((const SOCKADDR_IN6 *)Address)->sin6_scope_id;
        return TRUE;
    }
    return FALSE;
}

/*
 * Order[0..Count-1] = the indexes of Addresses in the order a connection should try them: the destinations that
 * can be reached first (RFC 6724), then the ones that cannot, in the order they were given. FALSE: no order was
 * made (fewer than two addresses, too many, an address of another family, or no sorter): the caller keeps its
 * own order.
 */
BOOL
WsSortAddresses(const SOCKADDR *const *Addresses, const ULONG *Lengths, ULONG Count, ULONG *Order)
{
    SOCKADDR_IN6 Small[16], *Dest = Small;
    PSOCKADDR_IN6_PAIR Pairs = NULL;
    BOOLEAN Used[WS_SORT_MAX];
    ULONG Got = 0, i, k, Next = 0;
    BOOL Result = FALSE;

    if (Count < 2 || Count > WS_SORT_MAX || !WsLoadSorter())
        return FALSE;
    if (Count > RTL_NUMBER_OF(Small))
    {
        Dest = HeapAlloc(WsSockHeap, 0, Count * sizeof(*Dest));
        if (!Dest)
            return FALSE;
    }
    for (i = 0; i < Count; i++)
        if (!WsToMapped(Addresses[i], Lengths[i], &Dest[i]))
            goto Done;

    if (WsCreateSortedAddressPairs(NULL, 0, Dest, Count, 0, &Pairs, &Got) != ERROR_SUCCESS || Got > Count)
        goto Done;

    RtlZeroMemory(Used, Count * sizeof(Used[0]));
    for (i = 0; i < Got; i++)
    {
        /* the first of the destinations that is equal and not placed yet (the list may repeat an address) */
        for (k = 0; k < Count; k++)
        {
            if (!Used[k] &&
                Dest[k].sin6_scope_id == Pairs[i].DestinationAddress->sin6_scope_id &&
                RtlEqualMemory(&Dest[k].sin6_addr, &Pairs[i].DestinationAddress->sin6_addr, sizeof(IN6_ADDR)))
            {
                Used[k] = TRUE;
                Order[Next++] = k;
                break;
            }
        }
    }
    for (k = 0; k < Count; k++)
        if (!Used[k])
            Order[Next++] = k;
    Result = (Next == Count);

Done:
    if (Pairs)
        WsFreeMibTable(Pairs);
    if (Dest != Small)
        HeapFree(WsSockHeap, 0, Dest);
    return Result;
}

/* getaddrinfo: the list in the order of the destination selection; the list as it is when it cannot be sorted */
PADDRINFOW
WsSortAddrInfo(PADDRINFOW List)
{
    PADDRINFOW Entries[WS_SORT_MAX], Entry, *Tail;
    const SOCKADDR *Addresses[WS_SORT_MAX];
    ULONG Lengths[WS_SORT_MAX], Order[WS_SORT_MAX], Count = 0, i;

    for (Entry = List; Entry; Entry = Entry->ai_next)
    {
        if (Count == WS_SORT_MAX || !Entry->ai_addr)
            return List;
        Entries[Count] = Entry;
        Addresses[Count] = Entry->ai_addr;
        Lengths[Count] = (ULONG)Entry->ai_addrlen;
        Count++;
    }
    if (!WsSortAddresses(Addresses, Lengths, Count, Order))
        return List;

    List = NULL;
    Tail = &List;
    for (i = 0; i < Count; i++)
    {
        *Tail = Entries[Order[i]];
        Tail = &(*Tail)->ai_next;
    }
    *Tail = NULL;
    return List;
}

/*
 * SIO_ADDRESS_LIST_SORT: the SOCKET_ADDRESS_LIST in the input buffer (its pointers point into the buffer) comes
 * back in the output buffer, in the order of the destination selection, with the unreachable ones last; the
 * answer is laid out the same way. WSAEFAULT and the size needed when the output buffer is too small.
 * The output buffer may be the input buffer (sorting in place is the usual way to call it): the addresses are
 * copied out of the question before the answer is written.
 */
INT
WsAddressListSort(LPVOID InBuffer, DWORD InSize, LPVOID OutBuffer, DWORD OutSize, LPDWORD BytesReturned)
{
    SOCKET_ADDRESS_LIST *In = InBuffer, *Out = OutBuffer;
    const SOCKADDR *Addresses[WS_SORT_MAX];
    ULONG Lengths[WS_SORT_MAX], Offsets[WS_SORT_MAX], Order[WS_SORT_MAX], Count, i;
    SIZE_T Needed, Copied;
    PUCHAR Data, Copy, Start = InBuffer;
    ULONG_PTR End;

    if (!InBuffer || InSize < FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address) || !BytesReturned)
        return WSAEINVAL;
    if (In->iAddressCount < 0 || In->iAddressCount > WS_SORT_MAX)
        return WSAEINVAL;
    Count = In->iAddressCount;
    if (FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address) + (SIZE_T)Count * sizeof(SOCKET_ADDRESS) > InSize)
        return WSAEINVAL;

    /* every address lies inside the input buffer and is no longer than a SOCKADDR_STORAGE, so the sum below
       stays small (WS_SORT_MAX of them) */
    End = (ULONG_PTR)Start + InSize;
    Needed = FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address) + (SIZE_T)Count * sizeof(SOCKET_ADDRESS);
    Copied = 0;
    for (i = 0; i < Count; i++)
    {
        ULONG_PTR Sa = (ULONG_PTR)In->Address[i].lpSockaddr;
        INT Length = In->Address[i].iSockaddrLength;

        if (Length < (INT)sizeof(SOCKADDR_IN) || Length > (INT)sizeof(SOCKADDR_STORAGE))
            return WSAEINVAL;
        if (!Sa || Sa < (ULONG_PTR)Start || Sa > End || End - Sa < (ULONG_PTR)Length)
            return WSAEINVAL;
        if (((const SOCKADDR *)Sa)->sa_family != AF_INET && ((const SOCKADDR *)Sa)->sa_family != AF_INET6)
            return WSAEINVAL;
        if (((const SOCKADDR *)Sa)->sa_family == AF_INET6 && Length < (INT)sizeof(SOCKADDR_IN6))
            return WSAEINVAL;
        Lengths[i] = (ULONG)Length;
        Offsets[i] = (ULONG)Copied;
        Copied += Lengths[i];
    }
    Needed += Copied;

    if (!OutBuffer || OutSize < Needed)
    {
        *BytesReturned = (DWORD)Needed;
        return WSAEFAULT;
    }

    /* the question, taken out of the input buffer: the answer may be written over it */
    Copy = HeapAlloc(WsSockHeap, 0, Copied ? Copied : 1);
    if (!Copy)
        return WSAENOBUFS;
    for (i = 0; i < Count; i++)
    {
        RtlCopyMemory(Copy + Offsets[i], In->Address[i].lpSockaddr, Lengths[i]);
        Addresses[i] = (const SOCKADDR *)(Copy + Offsets[i]);
    }

    /* no sorter (or a single address): the order as it was given */
    for (i = 0; i < Count; i++)
        Order[i] = i;
    WsSortAddresses(Addresses, Lengths, Count, Order);

    Data = (PUCHAR)&Out->Address[Count];
    Out->iAddressCount = Count;
    for (i = 0; i < Count; i++)
    {
        ULONG From = Order[i];

        RtlCopyMemory(Data, Addresses[From], Lengths[From]);
        Out->Address[i].lpSockaddr = (LPSOCKADDR)Data;
        Out->Address[i].iSockaddrLength = Lengths[From];
        Data += Lengths[From];
    }
    HeapFree(WsSockHeap, 0, Copy);
    *BytesReturned = (DWORD)Needed;
    return ERROR_SUCCESS;
}
