/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SIO_ADDRESS_LIST_CHANGE (blocking, non-blocking with FD_ADDRESS_LIST_CHANGE, overlapped)
 *              and SIO_ADDRESS_LIST_QUERY
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#include <mswsock.h>
#include <iphlpapi.h>
#include <winuser.h>

/* The expected values were recorded on Windows 10 22H2. A change of the address list is made by
 * adding and deleting an IPv4 address on the first adapter, which needs an administrator; without
 * that only the tests that need no change run. */

#ifndef SIO_ADDRESS_LIST_CHANGE
#define SIO_ADDRESS_LIST_CHANGE _WSAIOW(IOC_WS2, 23)
#endif

#define TEST_ADDRESS "10.254.77.1"
#define TEST_MASK    "255.255.255.0"
#define WAIT_CHANGE  30000
#define WM_ADDRCHG   (WM_USER + 7)

static DWORD g_IfIndex;
static ULONG g_Context, g_Instance;

static
BOOL
FindInterface(void)
{
    PIP_ADAPTER_INFO Info, Adapter;
    ULONG Size = 0;
    BOOL Found = FALSE;

    GetAdaptersInfo(NULL, &Size);
    if (!Size)
        return FALSE;
    Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Info)
        return FALSE;
    if (GetAdaptersInfo(Info, &Size) == NO_ERROR)
    {
        for (Adapter = Info; Adapter; Adapter = Adapter->Next)
        {
            const char *Ip = Adapter->IpAddressList.IpAddress.String;

            if (strcmp(Ip, "0.0.0.0") != 0 && strncmp(Ip, "127.", 4) != 0)
            {
                g_IfIndex = Adapter->Index;
                Found = TRUE;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Found;
}

static
DWORD
AddAddress(void)
{
    return AddIPAddress(inet_addr(TEST_ADDRESS), inet_addr(TEST_MASK), g_IfIndex, &g_Context, &g_Instance);
}

static
void
DeleteAddress(void)
{
    DWORD Error = DeleteIPAddress(g_Context);

    ok(Error == NO_ERROR, "DeleteIPAddress failed: %lu\n", Error);
    /* Let the change this causes go by before the next test arms a request (Windows reports a
     * deleted address at once, an added one a few seconds after the call) */
    Sleep(1000);
}

static
DWORD
WINAPI
AddAddressThread(LPVOID Delay)
{
    Sleep((DWORD)(ULONG_PTR)Delay);
    return AddAddress();
}

/* Adds the address after Delay ms, in another thread */
static
HANDLE
StartChange(DWORD Delay)
{
    return CreateThread(NULL, 0, AddAddressThread, (LPVOID)(ULONG_PTR)Delay, 0, NULL);
}

static
void
FinishChange(HANDLE Thread)
{
    DWORD Error = ERROR_GEN_FAILURE;

    WaitForSingleObject(Thread, INFINITE);
    GetExitCodeThread(Thread, &Error);
    CloseHandle(Thread);
    ok(Error == NO_ERROR, "AddIPAddress failed: %lu\n", Error);
    DeleteAddress();
}

static
DWORD
WINAPI
CloseThread(LPVOID Param)
{
    Sleep(1500);
    closesocket((SOCKET)Param);
    return 0;
}

static
void
TestQuery(void)
{
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);
    char Buffer[4096];
    PSOCKET_ADDRESS_LIST List = (PSOCKET_ADDRESS_LIST)Buffer;
    DWORD Returned, Needed;
    PMIB_IPADDRTABLE Table;
    ULONG TableSize = 0;
    int Result, i, j;

    ok(Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());

    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEFAULT, "error = %d\n", WSAGetLastError());
    Needed = Returned;
    ok(Needed >= FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address), "Needed = %lu\n", Needed);

    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_QUERY, NULL, 0, Buffer, 2, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEINVAL, "error = %d\n", WSAGetLastError());
    ok(Returned == 0, "Returned = %lu\n", Returned);

    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_QUERY, NULL, 0, Buffer, sizeof(INT), &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEFAULT, "error = %d\n", WSAGetLastError());
    ok(Returned == Needed, "Returned = %lu, Needed = %lu\n", Returned, Needed);

    memset(Buffer, 0xAA, sizeof(Buffer));
    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_QUERY, NULL, 0, Buffer, sizeof(Buffer), &Returned, NULL, NULL);
    ok(Result == 0, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == Needed, "Returned = %lu, Needed = %lu\n", Returned, Needed);
    if (Result == 0)
    {
        ok(List->iAddressCount >= 0, "iAddressCount = %d\n", List->iAddressCount);
        ok(Needed == FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address) +
                     List->iAddressCount * (sizeof(SOCKET_ADDRESS) + sizeof(SOCKADDR_IN)),
           "Needed = %lu for %d addresses\n", Needed, List->iAddressCount);

        /* the SOCKADDRs are in the buffer, after the array; none of them is the loopback */
        GetIpAddrTable(NULL, &TableSize, FALSE);
        Table = HeapAlloc(GetProcessHeap(), 0, TableSize ? TableSize : 1);
        if (Table && GetIpAddrTable(Table, &TableSize, FALSE) != NO_ERROR)
        {
            HeapFree(GetProcessHeap(), 0, Table);
            Table = NULL;
        }
        for (i = 0; i < List->iAddressCount; i++)
        {
            PSOCKADDR_IN Address = (PSOCKADDR_IN)List->Address[i].lpSockaddr;
            BOOL Known = FALSE;

            ok((PUCHAR)Address >= (PUCHAR)&List->Address[List->iAddressCount] &&
               (PUCHAR)(Address + 1) <= (PUCHAR)Buffer + Returned,
               "address %d is outside of the buffer: %p\n", i, Address);
            ok(List->Address[i].iSockaddrLength == sizeof(SOCKADDR_IN),
               "length of %d = %d\n", i, List->Address[i].iSockaddrLength);
            if ((PUCHAR)Address < (PUCHAR)Buffer || (PUCHAR)(Address + 1) > (PUCHAR)Buffer + Returned)
                continue;
            ok(Address->sin_family == AF_INET, "family of %d = %d\n", i, Address->sin_family);
            ok(Address->sin_port == 0, "port of %d = %d\n", i, Address->sin_port);
            ok((ntohl(Address->sin_addr.s_addr) >> 24) != 127, "loopback listed\n");
            if (Table)
            {
                for (j = 0; j < (int)Table->dwNumEntries; j++)
                    if (Table->table[j].dwAddr == Address->sin_addr.s_addr)
                        Known = TRUE;
                ok(Known, "%s is not in the address table\n", inet_ntoa(Address->sin_addr));
            }
        }
        if (Table)
            HeapFree(GetProcessHeap(), 0, Table);
    }
    closesocket(Socket);
}

/* The requests that need no change of the address list */
static
void
TestNoChange(void)
{
    SOCKET Socket;
    WSAOVERLAPPED Overlapped;
    DWORD Returned, Flags;
    HANDLE Thread;
    char Buffer[16];
    u_long NonBlocking = 1;
    DWORD Start;
    int Result;

    /* in and out buffers are refused */
    Socket = socket(AF_INET, SOCK_STREAM, 0);
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, Buffer, 4, Buffer, 4, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEINVAL, "error = %d\n", WSAGetLastError());

    /* no byte count and no OVERLAPPED */
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, NULL, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEFAULT, "error = %d\n", WSAGetLastError());

    /* a blocked call returns WSAEINTR when the socket is closed */
    Thread = CreateThread(NULL, 0, CloseThread, (LPVOID)Socket, 0, NULL);
    Start = GetTickCount();
    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEINTR, "error = %d\n", WSAGetLastError());
    ok(GetTickCount() - Start >= 1000, "returned after %lu ms\n", GetTickCount() - Start);
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);

    /* non-blocking: the call does not wait, on a stream and on a datagram socket, and again */
    Socket = socket(AF_INET, SOCK_STREAM, 0);
    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "error = %d\n", WSAGetLastError());
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "error = %d\n", WSAGetLastError());
    closesocket(Socket);

    Socket = socket(AF_INET, SOCK_DGRAM, 0);
    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "error = %d\n", WSAGetLastError());
    closesocket(Socket);

    /* overlapped: pending; closing the socket completes it with STATUS_CANCELLED */
    Socket = socket(AF_INET, SOCK_STREAM, 0);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Returned = 0xCAFE;
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, &Overlapped, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSA_IO_PENDING, "error = %d\n", WSAGetLastError());
    Result = WSAGetOverlappedResult(Socket, &Overlapped, &Returned, FALSE, &Flags);
    ok(Result == FALSE, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSA_IO_INCOMPLETE, "error = %d\n", WSAGetLastError());
    ok(WaitForSingleObject(Overlapped.hEvent, 300) == WAIT_TIMEOUT, "the request completed\n");
    closesocket(Socket);
    ok(WaitForSingleObject(Overlapped.hEvent, 5000) == WAIT_OBJECT_0, "the request did not complete\n");
    ok((NTSTATUS)Overlapped.Internal == STATUS_CANCELLED, "Internal = %lx\n", (ULONG)Overlapped.Internal);
    WSACloseEvent(Overlapped.hEvent);
}

static
void
TestBlocking(void)
{
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE Thread;
    DWORD Returned = 0xCAFE, Start;
    int Result;

    Thread = StartChange(300);
    Start = GetTickCount();
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == 0, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == 0, "Returned = %lu\n", Returned);
    ok(GetTickCount() - Start >= 250, "returned after %lu ms\n", GetTickCount() - Start);
    FinishChange(Thread);
    closesocket(Socket);
}

static
void
TestEventSelect(void)
{
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0), Sentinel;
    WSAEVENT Event = WSACreateEvent(), SentinelEvent;
    WSANETWORKEVENTS Network;
    HANDLE Thread;
    DWORD Returned = 0xCAFE;
    u_long NonBlocking = 1;
    int Result;

    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR, "Result = %d\n", Result);
    ok(WSAGetLastError() == WSAEWOULDBLOCK, "error = %d\n", WSAGetLastError());
    Result = WSAEventSelect(Socket, Event, FD_ADDRESS_LIST_CHANGE);
    ok(Result == 0, "WSAEventSelect failed: %d\n", WSAGetLastError());
    ok(WaitForSingleObject(Event, 300) == WAIT_TIMEOUT, "event signalled without a change\n");

    Thread = StartChange(300);
    ok(WaitForSingleObject(Event, WAIT_CHANGE) == WAIT_OBJECT_0, "no event on the change\n");
    FillMemory(&Network, sizeof(Network), 0xCC);
    Result = WSAEnumNetworkEvents(Socket, Event, &Network);
    ok(Result == 0, "WSAEnumNetworkEvents failed: %d\n", WSAGetLastError());
    ok(Network.lNetworkEvents == FD_ADDRESS_LIST_CHANGE, "events = %lx\n", Network.lNetworkEvents);
    ok(Network.iErrorCode[FD_ADDRESS_LIST_CHANGE_BIT] == 0, "error = %d\n", Network.iErrorCode[FD_ADDRESS_LIST_CHANGE_BIT]);
    ok(WaitForSingleObject(Event, 300) == WAIT_TIMEOUT, "event not reset by WSAEnumNetworkEvents\n");
    Result = WSAEnumNetworkEvents(Socket, Event, &Network);
    ok(Result == 0 && Network.lNetworkEvents == 0, "again: %d, events = %lx\n", Result, Network.lNetworkEvents);
    FinishChange(Thread);

    /* one change per request: the deletion above, and a second addition, are not reported */
    ok(WaitForSingleObject(Event, 300) == WAIT_TIMEOUT, "event signalled by the deletion\n");
    Thread = StartChange(300);
    WaitForSingleObject(Thread, INFINITE);
    Sleep(6000);
    ok(WaitForSingleObject(Event, 0) == WAIT_TIMEOUT, "event signalled without a new request\n");
    FinishChange(Thread);

    /* what .NET does after each event, without enumerating: the same request and selection again,
     * which must not report the old change */
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "Result = %d, error %d\n", Result, WSAGetLastError());
    WSAResetEvent(Event);
    Result = WSAEventSelect(Socket, Event, FD_ADDRESS_LIST_CHANGE);
    ok(Result == 0, "WSAEventSelect failed: %d\n", WSAGetLastError());
    ok(WaitForSingleObject(Event, 500) == WAIT_TIMEOUT, "event signalled again for the old change\n");

    /* a change while the event is not selected is kept with the socket and reported when it is
     * selected: Sentinel, armed and selected, tells when the change has been delivered (Windows
     * reports an added address a few seconds late) */
    WSAEventSelect(Socket, NULL, 0);
    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "Result = %d, error %d\n", Result, WSAGetLastError());
    Sentinel = socket(AF_INET, SOCK_STREAM, 0);
    SentinelEvent = WSACreateEvent();
    ioctlsocket(Sentinel, FIONBIO, &NonBlocking);
    WSAIoctl(Sentinel, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    WSAEventSelect(Sentinel, SentinelEvent, FD_ADDRESS_LIST_CHANGE);
    Thread = StartChange(0);
    ok(WaitForSingleObject(SentinelEvent, WAIT_CHANGE) == WAIT_OBJECT_0, "no event on the change\n");
    Sleep(500);
    WSAResetEvent(Event);
    WSAEventSelect(Socket, Event, FD_ADDRESS_LIST_CHANGE);
    ok(WaitForSingleObject(Event, 1000) == WAIT_OBJECT_0, "no event for a change before the selection\n");
    Result = WSAEnumNetworkEvents(Socket, Event, &Network);
    ok(Result == 0 && Network.lNetworkEvents == FD_ADDRESS_LIST_CHANGE, "%d, events = %lx\n", Result, Network.lNetworkEvents);
    FinishChange(Thread);
    closesocket(Sentinel);
    WSACloseEvent(SentinelEvent);

    closesocket(Socket);
    WSACloseEvent(Event);
}

static
LRESULT
CALLBACK
WindowProc(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(Window, Message, wParam, lParam);
}

static
void
TestAsyncSelect(void)
{
    WNDCLASSW Class;
    HWND Window;
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);
    HANDLE Thread;
    DWORD Returned = 0xCAFE, Start;
    MSG Message;
    BOOL Got = FALSE;
    int Result;

    ZeroMemory(&Class, sizeof(Class));
    Class.lpfnWndProc = WindowProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"AddrChangeTest";
    RegisterClassW(&Class);
    Window = CreateWindowExW(0, L"AddrChangeTest", L"", WS_POPUP, 0, 0, 10, 10, NULL, NULL, Class.hInstance, NULL);
    ok(Window != NULL, "CreateWindowEx failed: %lu\n", GetLastError());
    if (!Window)
    {
        closesocket(Socket);
        return;
    }

    Result = WSAAsyncSelect(Socket, Window, WM_ADDRCHG, FD_ADDRESS_LIST_CHANGE);
    ok(Result == 0, "WSAAsyncSelect failed: %d\n", WSAGetLastError());
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "Result = %d, error %d\n", Result, WSAGetLastError());

    Thread = StartChange(300);
    Start = GetTickCount();
    while (!Got && GetTickCount() - Start < WAIT_CHANGE)
    {
        while (PeekMessageW(&Message, NULL, 0, 0, PM_REMOVE))
        {
            if (Message.message == WM_ADDRCHG)
            {
                ok(Message.hwnd == Window, "hwnd = %p\n", Message.hwnd);
                ok(Message.wParam == Socket, "wParam = %Ix\n", (ULONG_PTR)Message.wParam);
                ok(Message.lParam == WSAMAKESELECTREPLY(FD_ADDRESS_LIST_CHANGE, 0), "lParam = %Ix\n", (ULONG_PTR)Message.lParam);
                Got = TRUE;
            }
            DispatchMessageW(&Message);
        }
        Sleep(20);
    }
    ok(Got, "no message on the change\n");
    FinishChange(Thread);

    WSAAsyncSelect(Socket, Window, 0, 0);
    closesocket(Socket);
    DestroyWindow(Window);
    UnregisterClassW(L"AddrChangeTest", Class.hInstance);
}

static
VOID
CALLBACK
Completion(DWORD Error, DWORD Transferred, LPWSAOVERLAPPED Overlapped, DWORD Flags)
{
    Overlapped->OffsetHigh = 1 + Error;
    Overlapped->Offset = Transferred;
}

static
void
TestOverlapped(void)
{
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, 0);
    WSAOVERLAPPED Overlapped;
    HANDLE Thread;
    DWORD Returned = 0xCAFE, Flags, Start;
    int Result;

    /* completion by event */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, &Overlapped, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    Thread = StartChange(300);
    ok(WaitForSingleObject(Overlapped.hEvent, WAIT_CHANGE) == WAIT_OBJECT_0, "no completion on the change\n");
    Returned = 0xCAFE;
    Result = WSAGetOverlappedResult(Socket, &Overlapped, &Returned, FALSE, &Flags);
    ok(Result == TRUE, "Result = %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == 0, "Returned = %lu\n", Returned);
    FinishChange(Thread);
    WSACloseEvent(Overlapped.hEvent);

    /* completion by routine, in an alertable wait of the thread that issued the request */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Result = WSAIoctl(Socket, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &Returned, &Overlapped, Completion);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING, "Result = %d, error %d\n", Result, WSAGetLastError());
    Thread = StartChange(300);
    Start = GetTickCount();
    while (!Overlapped.OffsetHigh && GetTickCount() - Start < WAIT_CHANGE)
        SleepEx(50, TRUE);
    ok(Overlapped.OffsetHigh == 1, "the routine ran with error %lu (0 = not at all)\n", Overlapped.OffsetHigh - 1);
    ok(Overlapped.Offset == 0, "transferred %lu\n", Overlapped.Offset);
    FinishChange(Thread);
    closesocket(Socket);
}

START_TEST(addresschange)
{
    WSADATA WsaData;
    DWORD Error;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    TestQuery();
    TestNoChange();

    for (Error = 0; Error < 30 && !FindInterface(); Error++)
        Sleep(1000);
    if (!g_IfIndex)
    {
        skip("no IPv4 adapter to change the address list on\n");
        WSACleanup();
        return;
    }

    Error = AddAddress();
    if (Error != NO_ERROR)
    {
        skip("cannot change the address list (AddIPAddress failed: %lu)\n", Error);
        WSACleanup();
        return;
    }
    DeleteAddress();

    TestBlocking();
    TestEventSelect();
    TestAsyncSelect();
    TestOverlapped();

    WSACleanup();
}
