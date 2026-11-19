/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     What a TCP socket reports after its peer closed the connection in different ways
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations were measured with the same test on a Windows Server 2022 (10.0.20348) loopback pair;
 * Windows 10 was not measured.
 */

#include "ws2_32.h"

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

/* A connected loopback pair; FALSE after a skip */
static
BOOL
MakePair(SOCKET *Client, SOCKET *Server)
{
    SOCKET Listener;
    struct sockaddr_in Addr;
    int Len = sizeof(Addr);

    *Client = *Server = INVALID_SOCKET;
    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Listener == INVALID_SOCKET)
    {
        skip("socket failed: %d\n", WSAGetLastError());
        return FALSE;
    }

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR ||
        listen(Listener, 1) == SOCKET_ERROR ||
        getsockname(Listener, (struct sockaddr *)&Addr, &Len) == SOCKET_ERROR)
    {
        skip("listener setup failed: %d\n", WSAGetLastError());
        closesocket(Listener);
        return FALSE;
    }

    *Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*Client == INVALID_SOCKET ||
        connect(*Client, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR)
    {
        skip("connect failed: %d\n", WSAGetLastError());
        if (*Client != INVALID_SOCKET)
            closesocket(*Client);
        closesocket(Listener);
        return FALSE;
    }

    *Server = accept(Listener, NULL, NULL);
    closesocket(Listener);
    if (*Server == INVALID_SOCKET)
    {
        skip("accept failed: %d\n", WSAGetLastError());
        closesocket(*Client);
        return FALSE;
    }
    return TRUE;
}

/* Wait until the socket is readable (data, the end of the stream or an error) */
static
BOOL
WaitReadable(SOCKET Socket)
{
    fd_set ReadSet;
    struct timeval Timeout = { 5, 0 };

    FD_ZERO(&ReadSet);
    FD_SET(Socket, &ReadSet);
    return select(0, &ReadSet, NULL, NULL, &Timeout) == 1;
}

/* One byte sent; the result is the byte count or the error */
static
int
SendOne(SOCKET Socket, int *Error)
{
    int Result;

    SetLastError(0xdeadbeef);
    Result = send(Socket, "x", 1, 0);
    *Error = (Result == SOCKET_ERROR) ? WSAGetLastError() : 0;
    return Result;
}

static
int
RecvOne(SOCKET Socket, char *Buffer, int *Error)
{
    int Result;

    SetLastError(0xdeadbeef);
    Result = recv(Socket, Buffer, 16, 0);
    *Error = (Result == SOCKET_ERROR) ? WSAGetLastError() : 0;
    return Result;
}

/* How the peer ends the connection */
#define PEER_CLOSE          0   /* closesocket, nothing unread */
#define PEER_CLOSE_UNREAD   1   /* closesocket with data it has not read: a reset at once */
#define PEER_CLOSE_DATA     2   /* sends data, then closesocket */
#define PEER_SHUTDOWN_SEND  3   /* shutdown(SD_SEND): the peer stays and reads */

static
void
Test_PeerClose(int How, BOOL NonBlocking)
{
    SOCKET Client, Server;
    char Buffer[16];
    int Result, Error, i;
    WSAEVENT Event = NULL;
    WSANETWORKEVENTS Events;

    if (!MakePair(&Client, &Server))
        return;
    if (NonBlocking)
    {
        /* WSAEventSelect puts the socket in non-blocking mode and reports FD_CLOSE */
        Event = WSACreateEvent();
        ok(!WSAEventSelect(Client, Event, FD_READ | FD_WRITE | FD_CLOSE), "WSAEventSelect failed: %d\n", WSAGetLastError());
        /* a connected socket reports FD_WRITE once; sends that are taken do not report it again */
        ZeroMemory(&Events, sizeof(Events));
        ok(!WSAEnumNetworkEvents(Client, Event, &Events), "WSAEnumNetworkEvents failed: %d\n", WSAGetLastError());
        ok(Events.lNetworkEvents == FD_WRITE, "initial events %lx, expected FD_WRITE\n", Events.lNetworkEvents);
    }

    switch (How)
    {
        case PEER_CLOSE:
        case PEER_SHUTDOWN_SEND:
            break;
        case PEER_CLOSE_UNREAD:
            ok(send(Client, "unread", 6, 0) == 6, "send failed: %d\n", WSAGetLastError());
            Sleep(100);
            break;
        case PEER_CLOSE_DATA:
            ok(send(Server, "hello", 5, 0) == 5, "send failed: %d\n", WSAGetLastError());
            break;
    }

    if (How == PEER_SHUTDOWN_SEND)
        ok(!shutdown(Server, SD_SEND), "shutdown failed: %d\n", WSAGetLastError());
    else
        ok(!closesocket(Server), "closesocket failed: %d\n", WSAGetLastError());
    Sleep(100);
    ok(WaitReadable(Client), "The client saw no event after the peer ended the connection\n");

    /* WSAPoll (Windows Server 2022): the end of the stream is POLLHUP, data not read yet POLLRDNORM with it, a reset
     * POLLHUP and POLLERR; the socket stays writable (the send fails at once) */
    if (pWSAPoll)
    {
        WSAPOLLFD Poll;
        SHORT Expected = (How == PEER_CLOSE) ? (POLLWRNORM | POLLHUP) :
                         (How == PEER_CLOSE_DATA) ? (POLLRDNORM | POLLWRNORM | POLLHUP) :
                         (How == PEER_CLOSE_UNREAD) ? (POLLWRNORM | POLLHUP | POLLERR) : (POLLWRNORM | POLLHUP);

        Poll.fd = Client;
        Poll.events = POLLRDNORM | POLLWRNORM;
        Poll.revents = 0;
        ok(pWSAPoll(&Poll, 1, 0) == 1, "WSAPoll found nothing: %d\n", WSAGetLastError());
        ok(Poll.revents == Expected, "WSAPoll revents 0x%x, expected 0x%x (How %d)\n", Poll.revents, Expected, How);
    }

    if (Event && How == PEER_CLOSE_DATA)
    {
        /* the data and the end of the stream at once, the data not read (Windows Server 2022) */
        ZeroMemory(&Events, sizeof(Events));
        ok(!WSAEnumNetworkEvents(Client, Event, &Events), "WSAEnumNetworkEvents failed: %d\n", WSAGetLastError());
        ok(Events.lNetworkEvents == (FD_READ | FD_CLOSE), "events %lx, expected FD_READ|FD_CLOSE\n", Events.lNetworkEvents);
    }
    if (Event)
        WSAResetEvent(Event);

    switch (How)
    {
        case PEER_CLOSE_UNREAD:
            if (Event)
            {
                /* FD_CLOSE of a reset carries WSAECONNABORTED, though recv and send fail with WSAECONNRESET
                 * (Windows Server 2022, WSAEnumNetworkEvents before any send) */
                ZeroMemory(&Events, sizeof(Events));
                ok(!WSAEnumNetworkEvents(Client, Event, &Events), "WSAEnumNetworkEvents failed: %d\n", WSAGetLastError());
                ok(Events.lNetworkEvents == FD_CLOSE, "events %lx after the reset, expected FD_CLOSE alone\n", Events.lNetworkEvents);
                ok(Events.iErrorCode[FD_CLOSE_BIT] == WSAECONNABORTED, "FD_CLOSE error %d, expected WSAECONNABORTED\n",
                   Events.iErrorCode[FD_CLOSE_BIT]);
            }
            /* the reset was sent when the peer closed: the first send fails already */
            Result = SendOne(Client, &Error);
            ok(Result == SOCKET_ERROR, "send after the reset returned %d\n", Result);
            ok(Error == WSAECONNRESET, "send error %d, expected WSAECONNRESET\n", Error);
            Result = RecvOne(Client, Buffer, &Error);
            ok(Result == SOCKET_ERROR, "recv after the reset returned %d\n", Result);
            ok(Error == WSAECONNRESET, "recv error %d, expected WSAECONNRESET\n", Error);
            break;

        case PEER_SHUTDOWN_SEND:
            /* the peer still reads: sends go on, the receive side is at its end */
            for (i = 0; i < 3; i++)
            {
                Result = SendOne(Client, &Error);
                ok(Result == 1, "send #%d returned %d, error %d\n", i + 1, Result, Error);
                Sleep(150);
            }
            Result = RecvOne(Client, Buffer, &Error);
            ok(Result == 0, "recv returned %d, error %d (expected the end of the stream)\n", Result, Error);
            break;

        default:
            /* The peer's end is gone: the first send is taken, the peer answers it with a reset, and from then on
             * the socket is aborted (WSAECONNABORTED), also for the data the peer sent before it closed */
            Result = SendOne(Client, &Error);
            ok(Result == 1, "first send returned %d, error %d\n", Result, Error);
            Sleep(300);
            for (i = 0; i < 3; i++)
            {
                Result = SendOne(Client, &Error);
                ok(Result == SOCKET_ERROR, "send #%d after the reset returned %d\n", i + 2, Result);
                ok(Error == WSAECONNABORTED, "send #%d error %d, expected WSAECONNABORTED\n", i + 2, Error);
                if (i == 0 && Event)
                {
                    /* FD_CLOSE came again with the error of the reset */
                    ZeroMemory(&Events, sizeof(Events));
                    ok(!WSAEnumNetworkEvents(Client, Event, &Events), "WSAEnumNetworkEvents failed: %d\n", WSAGetLastError());
                    ok(Events.lNetworkEvents & FD_CLOSE, "No FD_CLOSE after the reset (events %lx)\n", Events.lNetworkEvents);
                    ok(Events.iErrorCode[FD_CLOSE_BIT] == WSAECONNABORTED, "FD_CLOSE error %d, expected WSAECONNABORTED\n",
                       Events.iErrorCode[FD_CLOSE_BIT]);
                }
                Sleep(100);
            }
            ZeroMemory(Buffer, sizeof(Buffer));
            Result = RecvOne(Client, Buffer, &Error);
            ok(Result == SOCKET_ERROR, "recv after the reset returned %d (%.5s)\n", Result, Buffer);
            ok(Error == WSAECONNABORTED, "recv error %d, expected WSAECONNABORTED\n", Error);
            break;
    }

    if (Event)
        WSACloseEvent(Event);
    closesocket(Client);
    if (How == PEER_SHUTDOWN_SEND)
        closesocket(Server);
}

START_TEST(peerclose)
{
    WSADATA WsaData;
    int How;

    ok(!WSAStartup(MAKEWORD(2, 2), &WsaData), "WSAStartup failed\n");
    pWSAPoll = (void *)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "WSAPoll");
    for (How = PEER_CLOSE; How <= PEER_SHUTDOWN_SEND; How++)
    {
        Test_PeerClose(How, FALSE);
        Test_PeerClose(How, TRUE);
    }
    WSACleanup();
}
