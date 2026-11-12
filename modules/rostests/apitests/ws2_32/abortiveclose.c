/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the abortive and graceful close of a TCP connection
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

/* Make a connected loopback pair; return FALSE on failure (after a skip) */
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

/* Wait until the socket is readable; return FALSE after the timeout */
static
BOOL
WaitReadable(SOCKET Socket, LONG Seconds)
{
    fd_set ReadSet;
    struct timeval Timeout = { Seconds, 0 };

    FD_ZERO(&ReadSet);
    FD_SET(Socket, &ReadSet);
    return select(0, &ReadSet, NULL, NULL, &Timeout) == 1;
}

static
void
Test_AbortiveClose(void)
{
    SOCKET Client, Server;
    struct linger Linger = { 1, 0 };
    char Buffer[16];
    int Result, Error;
    WSABUF WsaBuf;
    LPWSAOVERLAPPED Overlapped;
    DWORD Sent;
    BOOL Pending;

    if (!MakePair(&Client, &Server))
        return;

    /* A zero linger timeout makes the close abortive: the peer gets a reset */
    Result = setsockopt(Server, SOL_SOCKET, SO_LINGER, (const char *)&Linger, sizeof(Linger));
    ok(Result == 0, "setsockopt(SO_LINGER) failed: %d\n", WSAGetLastError());
    Result = closesocket(Server);
    ok(Result == 0, "closesocket failed: %d\n", WSAGetLastError());

    if (!WaitReadable(Client, 5))
    {
        ok(0, "The client saw no event after the abortive close\n");
        closesocket(Client);
        return;
    }
    SetLastError(0xdeadbeef);
    Result = recv(Client, Buffer, sizeof(Buffer), 0);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR, "recv returned %d (expected an error, not a graceful close)\n", Result);
    ok(Error == WSAECONNRESET, "recv error %d, expected WSAECONNRESET\n", Error);

    SetLastError(0xdeadbeef);
    Result = send(Client, "x", 1, 0);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR, "send after the reset returned %d\n", Result);
    ok(Error == WSAECONNRESET, "send error %d, expected WSAECONNRESET\n", Error);

    /* A failed WSASend leaves the byte count unchanged */
    WsaBuf.buf = "x";
    WsaBuf.len = 1;
    Sent = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Result = WSASend(Client, &WsaBuf, 1, &Sent, 0, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR, "WSASend after the reset returned %d\n", Result);
    ok(Error == WSAECONNRESET, "WSASend error %d, expected WSAECONNRESET\n", Error);
    ok(Sent == 0xdeadbeef, "WSASend set the byte count to %lu\n", Sent);

    Overlapped = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Overlapped));
    if (Overlapped)
        Overlapped->hEvent = WSACreateEvent();
    if (!Overlapped || Overlapped->hEvent == WSA_INVALID_EVENT)
    {
        skip("No OVERLAPPED or event for the overlapped WSASend\n");
        if (Overlapped)
            HeapFree(GetProcessHeap(), 0, Overlapped);
        closesocket(Client);
        return;
    }
    Sent = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    Result = WSASend(Client, &WsaBuf, 1, &Sent, 0, Overlapped, NULL);
    Error = WSAGetLastError();
    Pending = (Result == SOCKET_ERROR && Error == WSA_IO_PENDING);
    ok(Result == SOCKET_ERROR, "overlapped WSASend after the reset returned %d\n", Result);
    ok(Error == WSAECONNRESET, "overlapped WSASend error %d, expected WSAECONNRESET\n", Error);
    ok(Sent == 0xdeadbeef, "overlapped WSASend set the byte count to %lu\n", Sent);

    closesocket(Client);
    /* A pending send can complete after the close: keep its OVERLAPPED until it has */
    if (Pending && WaitForSingleObject(Overlapped->hEvent, 5000) != WAIT_OBJECT_0)
    {
        ok(0, "The pending WSASend did not complete after the close\n");
        return;
    }
    WSACloseEvent(Overlapped->hEvent);
    HeapFree(GetProcessHeap(), 0, Overlapped);
}

static
void
Test_GracefulClose(BOOL Shutdown)
{
    SOCKET Client, Server;
    char Buffer[16];
    int Result;

    if (!MakePair(&Client, &Server))
        return;

    /* A shutdown of both directions, or a close without linger, is graceful:
     * the peer gets the data that was sent before it, then the end of the stream.
     * After a shutdown the server keeps its handle until the client saw both. */
    Result = send(Server, "abc", 3, 0);
    ok(Result == 3, "send returned %d, error %d\n", Result, WSAGetLastError());
    if (Shutdown)
    {
        Result = shutdown(Server, SD_BOTH);
        ok(Result == 0, "shutdown failed: %d\n", WSAGetLastError());
    }
    else
    {
        Result = closesocket(Server);
        ok(Result == 0, "closesocket failed: %d\n", WSAGetLastError());
        Server = INVALID_SOCKET;
    }

    if (!WaitReadable(Client, 5))
    {
        ok(0, "The client saw no data\n");
        goto Cleanup;
    }
    ZeroMemory(Buffer, sizeof(Buffer));
    Result = recv(Client, Buffer, sizeof(Buffer), 0);
    ok(Result == 3 && !memcmp(Buffer, "abc", 3), "recv returned %d (%.3s), error %d (expected the data)\n",
       Result, Buffer, WSAGetLastError());
    if (!WaitReadable(Client, 5))
    {
        ok(0, "The client saw no event after the graceful close\n");
        goto Cleanup;
    }
    Result = recv(Client, Buffer, sizeof(Buffer), 0);
    ok(Result == 0, "recv returned %d, error %d (expected a graceful close)\n", Result, WSAGetLastError());

Cleanup:
    if (Server != INVALID_SOCKET)
    {
        Result = closesocket(Server);
        ok(Result == 0, "closesocket failed: %d\n", WSAGetLastError());
    }
    closesocket(Client);
}

static
void
Test_ConnectRefused(void)
{
    SOCKET Socket, Reserve;
    struct sockaddr_in Addr;
    int Len = sizeof(Addr), Result, Error;

    /* Hold a bound port that nothing listens on */
    Reserve = Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Socket == INVALID_SOCKET ||
        bind(Socket, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR ||
        getsockname(Socket, (struct sockaddr *)&Addr, &Len) == SOCKET_ERROR)
    {
        skip("socket setup failed: %d\n", WSAGetLastError());
        if (Socket != INVALID_SOCKET)
            closesocket(Socket);
        return;
    }

    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET)
    {
        closesocket(Reserve);
        return;
    }
    SetLastError(0xdeadbeef);
    Result = connect(Socket, (struct sockaddr *)&Addr, sizeof(Addr));
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR, "connect to a closed port returned %d\n", Result);
    ok(Error == WSAECONNREFUSED, "connect error %d, expected WSAECONNREFUSED\n", Error);
    closesocket(Socket);
    closesocket(Reserve);
}

typedef struct _SEND_CALL
{
    SOCKET Socket;
    char *Buffer;
    int Length;
    int Result;
    int Error;
} SEND_CALL, *PSEND_CALL;

static
DWORD
WINAPI
SendThread(LPVOID Parameter)
{
    PSEND_CALL Call = Parameter;

    Call->Result = send(Call->Socket, Call->Buffer, Call->Length, 0);
    Call->Error = Call->Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    return 0;
}

/* An abortive close with data the peer has not read yet: the peer gets a
 * reset within a moment (Windows Server 2008 R2 and Windows 10), however much
 * data was still on its way. Blocking: the closing side has a send that waits
 * for buffer space when it closes */
static
void
Test_AbortiveCloseWithData(BOOL Blocking)
{
    static char Data[64 * 1024];
    static SEND_CALL Call;
    SOCKET Client, Server;
    struct linger Linger = { 1, 0 };
    u_long NonBlocking = 1;
    char Buffer[4096];
    int Result, Error = 0, Queued = 0, Received = 0;
    HANDLE Thread = NULL;
    DWORD Start, Elapsed;

    if (!MakePair(&Client, &Server))
        return;
    memset(Data, 'x', sizeof(Data));

    /* Fill the way to the client while it reads nothing */
    ok(!ioctlsocket(Server, FIONBIO, &NonBlocking), "FIONBIO failed: %d\n", WSAGetLastError());
    while (Queued < 16 * 1024 * 1024)
    {
        Result = send(Server, Data, sizeof(Data), 0);
        if (Result == SOCKET_ERROR)
        {
            Error = WSAGetLastError();
            if (Error == WSAEWOULDBLOCK)
            {
                /* The transport may still be taking the previous send (a loop that sends at once is ahead
                 * of the acknowledgements): the connection is full when no room comes for a moment */
                Sleep(300);
                Result = send(Server, Data, sizeof(Data), 0);
                if (Result != SOCKET_ERROR)
                {
                    Error = 0;
                    Queued += Result;
                    continue;
                }
                Error = WSAGetLastError();
            }
            break;
        }
        Queued += Result;
    }
    /* The receive window closes when the peer does not read, and the sender waits */
    ok(Error == WSAEWOULDBLOCK, "Filling the connection ended with %d after %d bytes\n", Error, Queued);

    if (Blocking)
    {
        NonBlocking = 0;
        ok(!ioctlsocket(Server, FIONBIO, &NonBlocking), "FIONBIO failed: %d\n", WSAGetLastError());
        Call.Socket = Server;
        Call.Buffer = Data;
        Call.Length = sizeof(Data);
        Call.Result = 1;
        Call.Error = -1;
        Thread = CreateThread(NULL, 0, SendThread, &Call, 0, NULL);
        ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
        Sleep(300);
    }

    /* The client reads a little, as a download that just started */
    ok(WaitReadable(Client, 5), "The client got no data\n");
    Result = recv(Client, Buffer, sizeof(Buffer), 0);
    ok(Result > 0, "recv returned %d, error %d\n", Result, WSAGetLastError());

    Result = setsockopt(Server, SOL_SOCKET, SO_LINGER, (const char *)&Linger, sizeof(Linger));
    ok(Result == 0, "setsockopt(SO_LINGER) failed: %d\n", WSAGetLastError());
    Result = closesocket(Server);
    ok(Result == 0, "closesocket failed: %d\n", WSAGetLastError());
    /* Let the reset arrive over loopback */
    Sleep(200);

    /* The client reads on; it must get a reset, not wait and not see the end of the stream */
    Start = GetTickCount();
    Error = 0;
    for (;;)
    {
        if (!WaitReadable(Client, 5))
        {
            Error = -1;
            break;
        }
        Result = recv(Client, Buffer, sizeof(Buffer), 0);
        if (Result <= 0)
        {
            Error = Result ? WSAGetLastError() : 0;
            break;
        }
        Received += Result;
    }
    Elapsed = GetTickCount() - Start;
    trace("Abortive close with %d bytes queued (%s): error %d after %lu ms, %d bytes read after the close\n",
          Queued, Blocking ? "blocking send" : "no send", Error, Elapsed, Received);
    ok(Error == WSAECONNRESET, "After an abortive close with data the client got %d (-1: nothing in 5 s, 0: end of stream)\n", Error);
    /* The reset discards the data the client had not read (Windows: all of it; ReactOS keeps
     * what AFD buffered before it learned of the reset, at most one receive window) */
    ok(Received <= 64 * 1024, "The client read %d bytes after the reset\n", Received);

    if (Thread)
    {
        ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "The blocked send did not return after the close\n");
        /* ReactOS AFD may complete a blocking send of more than its buffer in part */
        if (Call.Result == SOCKET_ERROR)
        {
            ok(TRUE, "The blocked send failed\n");
        }
        else
        {
            todo_ros ok(FALSE, "The blocked send returned %d\n", Call.Result);
        }
        CloseHandle(Thread);
    }
    closesocket(Client);
}

START_TEST(abortiveclose)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData))
    {
        skip("WSAStartup failed\n");
        return;
    }

    Test_AbortiveClose();
    Test_GracefulClose(TRUE);
    Test_GracefulClose(FALSE);
    Test_ConnectRefused();
    Test_AbortiveCloseWithData(FALSE);
    Test_AbortiveCloseWithData(TRUE);

    WSACleanup();
}
