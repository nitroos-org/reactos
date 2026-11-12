/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Non-blocking connect to a loopback listener and to a closed loopback port: the immediate
 *              WSAEWOULDBLOCK, the select / WSAPoll / WSAEventSelect / WSAAsyncSelect notifications, the error
 *              codes they carry, SO_ERROR. Expected values were measured on Windows 10 22H2 (nbprobe).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <winuser.h>

#ifndef POLLRDNORM
#define POLLRDNORM  0x0100
#define POLLWRNORM  0x0010
#define POLLERR     0x0001
#define POLLHUP     0x0002
typedef struct pollfd
{
    SOCKET fd;
    SHORT events;
    SHORT revents;
} WSAPOLLFD, *PWSAPOLLFD, *LPWSAPOLLFD;
#endif

static int (WINAPI *pWSAPoll)(WSAPOLLFD *, ULONG, INT);

#define WM_SOCK (WM_USER + 1)
#define MAX_MSGS 8

typedef struct
{
    int Count;
    LONG Event[MAX_MSGS];
    int Error[MAX_MSGS];
    SOCKET Socket[MAX_MSGS];
} MESSAGES;

static MESSAGES g_Messages;

static LRESULT CALLBACK MessageProc(HWND Window, UINT Message, WPARAM wParam, LPARAM lParam)
{
    if (Message == WM_SOCK && g_Messages.Count < MAX_MSGS)
    {
        g_Messages.Event[g_Messages.Count] = WSAGETSELECTEVENT(lParam);
        g_Messages.Error[g_Messages.Count] = WSAGETSELECTERROR(lParam);
        g_Messages.Socket[g_Messages.Count] = (SOCKET)wParam;
        g_Messages.Count++;
        return 0;
    }
    return DefWindowProcW(Window, Message, wParam, lParam);
}

static int GetSoError(SOCKET Socket)
{
    int Error = 0xdeadbeef, Length = sizeof(Error);

    ok(getsockopt(Socket, SOL_SOCKET, SO_ERROR, (char *)&Error, &Length) == 0, "SO_ERROR failed\n");
    return Error;
}

static SOCKET NewNonBlocking(void)
{
    ULONG NonBlocking = 1;
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    ok(Socket != INVALID_SOCKET, "socket failed\n");
    ok_int(ioctlsocket(Socket, FIONBIO, &NonBlocking), 0);
    return Socket;
}

/* Loopback address of a listener (Listen) or of a port nothing listens on */
static SOCKET Bind(struct sockaddr_in *Address, BOOL Listen)
{
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int Length = sizeof(*Address);

    ZeroMemory(Address, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Socket == INVALID_SOCKET ||
        bind(Socket, (struct sockaddr *)Address, sizeof(*Address)) != 0 ||
        getsockname(Socket, (struct sockaddr *)Address, &Length) != 0 ||
        (Listen && listen(Socket, 8) != 0))
    {
        if (Socket != INVALID_SOCKET)
            closesocket(Socket);
        return INVALID_SOCKET;
    }
    if (!Listen)
    {
        closesocket(Socket);
        return 0;
    }
    return Socket;
}

/* The one wait for the connect to finish: Windows takes about 2 s to give up on a closed port */
static void WaitConnected(SOCKET Socket, int *Writable, int *Excepted)
{
    fd_set Write, Except;
    struct timeval Timeout = { 10, 0 };
    int Result;

    FD_ZERO(&Write);
    FD_ZERO(&Except);
    FD_SET(Socket, &Write);
    FD_SET(Socket, &Except);
    Result = select(0, NULL, &Write, &Except, &Timeout);
    ok_int(Result, 1);
    *Writable = FD_ISSET(Socket, &Write) != 0;
    *Excepted = FD_ISSET(Socket, &Except) != 0;
}

static void PumpMessages(HWND Window, ULONG Milliseconds, int Want)
{
    DWORD End = GetTickCount() + Milliseconds;
    MSG Msg;

    while (g_Messages.Count < Want && (LONG)(End - GetTickCount()) > 0)
    {
        if (MsgWaitForMultipleObjects(0, NULL, FALSE, 50, QS_ALLINPUT) == WAIT_OBJECT_0)
        {
            while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
                DispatchMessageW(&Msg);
        }
    }
    /* Anything else that follows, with the thread alertable: the completion of the connect runs as an APC here,
     * and must not make the socket post FD_CONNECT or FD_WRITE again */
    SleepEx(300, TRUE);
    while (PeekMessageW(&Msg, NULL, 0, 0, PM_REMOVE))
        DispatchMessageW(&Msg);
}

static void TestSuccess(const struct sockaddr_in *Listener, SOCKET ListenSocket, HWND Window)
{
    SOCKET Socket, Accepted;
    struct sockaddr_in Peer;
    WSAPOLLFD Poll;
    WSAEVENT Event;
    WSANETWORKEVENTS Events;
    int Result, Length, Writable, Excepted;

    /* select */
    Socket = NewNonBlocking();
    Result = connect(Socket, (const struct sockaddr *)Listener, sizeof(*Listener));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEWOULDBLOCK);
    WaitConnected(Socket, &Writable, &Excepted);
    ok_int(Writable, 1);
    ok_int(Excepted, 0);
    ok_int(GetSoError(Socket), 0);
    Length = sizeof(Peer);
    ok_int(getpeername(Socket, (struct sockaddr *)&Peer, &Length), 0);
    ok_int(Peer.sin_port, Listener->sin_port);
    /* Connecting again says so */
    Result = connect(Socket, (const struct sockaddr *)Listener, sizeof(*Listener));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEISCONN);
    /* WSAPoll */
    Poll.fd = Socket;
    Poll.events = POLLWRNORM;
    Poll.revents = 0;
    ok_int(pWSAPoll(&Poll, 1, 0), 1);
    ok_hex(Poll.revents, POLLWRNORM);
    Accepted = accept(ListenSocket, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());
    if (Accepted != INVALID_SOCKET)
        closesocket(Accepted);
    closesocket(Socket);

    /* WSAEventSelect: FD_CONNECT and FD_WRITE, no error */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Event = WSACreateEvent();
    ok_int(WSAEventSelect(Socket, Event, FD_CONNECT | FD_WRITE | FD_READ | FD_CLOSE), 0);
    Result = connect(Socket, (const struct sockaddr *)Listener, sizeof(*Listener));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEWOULDBLOCK);
    ok_int(WaitForSingleObject(Event, 10000), WAIT_OBJECT_0);
    ZeroMemory(&Events, sizeof(Events));
    ok_int(WSAEnumNetworkEvents(Socket, Event, &Events), 0);
    ok_hex(Events.lNetworkEvents, FD_CONNECT | FD_WRITE);
    ok_int(Events.iErrorCode[FD_CONNECT_BIT], 0);
    ok_int(Events.iErrorCode[FD_WRITE_BIT], 0);
    ok_int(WaitForSingleObject(Event, 300), WAIT_TIMEOUT);
    WSACloseEvent(Event);
    closesocket(Socket);

    /* WSAAsyncSelect: FD_CONNECT, then FD_WRITE, no error */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&g_Messages, sizeof(g_Messages));
    ok_int(WSAAsyncSelect(Socket, Window, WM_SOCK, FD_CONNECT | FD_WRITE | FD_READ | FD_CLOSE), 0);
    Result = connect(Socket, (const struct sockaddr *)Listener, sizeof(*Listener));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEWOULDBLOCK);
    PumpMessages(Window, 10000, 2);
    ok(g_Messages.Count == 2, "%d messages: %lx/%d %lx/%d\n", g_Messages.Count,
       g_Messages.Event[0], g_Messages.Error[0], g_Messages.Event[1], g_Messages.Error[1]);
    if (g_Messages.Count == 2)
    {
        ok_hex(g_Messages.Event[0], FD_CONNECT);
        ok_int(g_Messages.Error[0], 0);
        ok_hex(g_Messages.Event[1], FD_WRITE);
        ok_int(g_Messages.Error[1], 0);
    }
    closesocket(Socket);
}

static void TestRefused(const struct sockaddr_in *Closed, HWND Window)
{
    SOCKET Socket;
    WSAPOLLFD Poll;
    WSAEVENT Event;
    WSANETWORKEVENTS Events;
    int Result, Writable, Excepted;

    /* select: the except set, never the write set; SO_ERROR keeps the error */
    Socket = NewNonBlocking();
    Result = connect(Socket, (const struct sockaddr *)Closed, sizeof(*Closed));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEWOULDBLOCK);
    WaitConnected(Socket, &Writable, &Excepted);
    ok_int(Writable, 0);
    ok_int(Excepted, 1);
    ok_int(GetSoError(Socket), WSAECONNREFUSED);
    /* WSAPoll: POLLWRNORM, POLLHUP and POLLERR (0x13 on Windows 10) */
    Poll.fd = Socket;
    Poll.events = POLLWRNORM;
    Poll.revents = 0;
    ok_int(pWSAPoll(&Poll, 1, 0), 1);
    ok_hex(Poll.revents, POLLWRNORM | POLLHUP | POLLERR);
    Poll.events = POLLRDNORM | POLLWRNORM;
    Poll.revents = 0;
    ok_int(pWSAPoll(&Poll, 1, 0), 1);
    ok_hex(Poll.revents, POLLWRNORM | POLLHUP | POLLERR);
    closesocket(Socket);

    /* WSAEventSelect: FD_CONNECT carrying the error, nothing else */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Event = WSACreateEvent();
    ok_int(WSAEventSelect(Socket, Event, FD_CONNECT | FD_WRITE | FD_READ | FD_CLOSE), 0);
    Result = connect(Socket, (const struct sockaddr *)Closed, sizeof(*Closed));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEWOULDBLOCK);
    ok_int(WaitForSingleObject(Event, 10000), WAIT_OBJECT_0);
    ZeroMemory(&Events, sizeof(Events));
    ok_int(WSAEnumNetworkEvents(Socket, Event, &Events), 0);
    ok_hex(Events.lNetworkEvents, FD_CONNECT);
    ok_int(Events.iErrorCode[FD_CONNECT_BIT], WSAECONNREFUSED);
    ok_int(GetSoError(Socket), WSAECONNREFUSED);
    ok_int(WaitForSingleObject(Event, 300), WAIT_TIMEOUT);
    WSACloseEvent(Event);
    closesocket(Socket);

    /* WSAAsyncSelect: one FD_CONNECT message with the error */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&g_Messages, sizeof(g_Messages));
    ok_int(WSAAsyncSelect(Socket, Window, WM_SOCK, FD_CONNECT | FD_WRITE | FD_READ | FD_CLOSE), 0);
    Result = connect(Socket, (const struct sockaddr *)Closed, sizeof(*Closed));
    ok_int(Result, SOCKET_ERROR);
    ok_int(WSAGetLastError(), WSAEWOULDBLOCK);
    PumpMessages(Window, 10000, 1);
    ok(g_Messages.Count == 1, "%d messages: %lx/%d/%Ix %lx/%d/%Ix, socket %Ix\n", g_Messages.Count,
       g_Messages.Event[0], g_Messages.Error[0], g_Messages.Socket[0], g_Messages.Event[1], g_Messages.Error[1], g_Messages.Socket[1], Socket);
    if (g_Messages.Count >= 1)
    {
        ok_hex(g_Messages.Event[0], FD_CONNECT);
        ok_int(g_Messages.Error[0], WSAECONNREFUSED);
    }
    ok_int(GetSoError(Socket), WSAECONNREFUSED);
    closesocket(Socket);
}

START_TEST(nbconnect)
{
    WSADATA WsaData;
    WNDCLASSW Class = { 0 };
    struct sockaddr_in Listener, Closed;
    SOCKET ListenSocket;
    HWND Window;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    pWSAPoll = (void *)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSAPoll");
    if (!pWSAPoll)
    {
        skip("WSAPoll is not available\n");
        WSACleanup();
        return;
    }

    ListenSocket = Bind(&Listener, TRUE);
    if (ListenSocket == INVALID_SOCKET || Bind(&Closed, FALSE) == INVALID_SOCKET)
    {
        skip("no loopback sockets\n");
        WSACleanup();
        return;
    }

    Class.lpfnWndProc = MessageProc;
    Class.hInstance = GetModuleHandleW(NULL);
    Class.lpszClassName = L"NbConnectTest";
    RegisterClassW(&Class);
    Window = CreateWindowW(L"NbConnectTest", L"", 0, 0, 0, 1, 1, HWND_MESSAGE, NULL, Class.hInstance, NULL);
    ok(Window != NULL, "CreateWindow failed %lu\n", GetLastError());

    TestSuccess(&Listener, ListenSocket, Window);
    TestRefused(&Closed, Window);

    DestroyWindow(Window);
    UnregisterClassW(L"NbConnectTest", Class.hInstance);
    closesocket(ListenSocket);
    WSACleanup();
}
