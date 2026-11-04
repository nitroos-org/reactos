/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     shutdown(SD_RECEIVE) and shutdown(SD_BOTH) with a receive pending
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (x64 and x86) with sockets on the loopback: a receive that is pending when
 * the socket is shut down for receiving stays pending. It completes with the data that arrives later (as
 * a packet of the completion port, as a signalled event), with 0 bytes when the peer closes, with
 * STATUS_CONNECTION_RESET when it aborts, and with STATUS_CONNECTION_ABORTED when this side closes
 * (STATUS_CANCELLED after SD_BOTH). A receive issued afterwards fails with WSAESHUTDOWN.
 * With data queued unread at the shutdown, or arriving with no receive pending, the connection is reset
 * (TestReset).
 */

#include "ws2_32.h"

#define STATUS_PENDING_ ((ULONG)0x00000103)
#define STATUS_CANCELLED_ ((ULONG)0xC0000120)
#define STATUS_CONNECTION_RESET_ ((ULONG)0xC000020D)
#define STATUS_CONNECTION_ABORTED_ ((ULONG)0xC0000241)

typedef struct _SHUTDOWN_TEST
{
    const char *Label;
    SOCKET Socket;
    SOCKET Peer;
    HANDLE Port;
    HANDLE Event;
    OVERLAPPED Overlapped;
    char Buffer[64];
} SHUTDOWN_TEST;

static
BOOL
MakePair(int Type, SOCKET *Socket, SOCKET *Peer)
{
    struct sockaddr_in Addr;
    int Len = sizeof(Addr);
    SOCKET Listener;

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (Type == SOCK_DGRAM)
    {
        *Socket = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        *Peer = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (*Socket == INVALID_SOCKET || *Peer == INVALID_SOCKET ||
            bind(*Socket, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR ||
            getsockname(*Socket, (struct sockaddr *)&Addr, &Len) == SOCKET_ERROR ||
            connect(*Peer, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR)
            return FALSE;
        return TRUE;
    }

    Listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (Listener == INVALID_SOCKET)
        return FALSE;
    if (bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR ||
        listen(Listener, 1) == SOCKET_ERROR ||
        getsockname(Listener, (struct sockaddr *)&Addr, &Len) == SOCKET_ERROR)
    {
        closesocket(Listener);
        return FALSE;
    }
    *Peer = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (*Peer == INVALID_SOCKET || connect(*Peer, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR)
    {
        closesocket(Listener);
        return FALSE;
    }
    *Socket = accept(Listener, NULL, NULL);
    closesocket(Listener);
    return *Socket != INVALID_SOCKET;
}

/* A pair with a receive pending on Socket; UsePort: 1 completion port, 2 event, 0 neither */
static
BOOL
Start(SHUTDOWN_TEST *Test, const char *Label, int Type, int Mode)
{
    WSABUF Buf = { sizeof(Test->Buffer), Test->Buffer };
    DWORD Flags = 0;
    int Ret;

    ZeroMemory(Test, sizeof(*Test));
    Test->Label = Label;
    Test->Socket = Test->Peer = INVALID_SOCKET;
    if (!MakePair(Type, &Test->Socket, &Test->Peer))
    {
        skip("%s: socket setup failed: %d\n", Label, WSAGetLastError());
        return FALSE;
    }
    if (Mode == 1)
    {
        Test->Port = CreateIoCompletionPort((HANDLE)Test->Socket, NULL, 0x77, 0);
        ok(Test->Port != NULL, "%s: CreateIoCompletionPort failed: %lu\n", Label, GetLastError());
    }
    if (Mode == 2)
        Test->Event = CreateEventW(NULL, TRUE, FALSE, NULL);

    Test->Overlapped.Internal = 0xcccccccc;
    Test->Overlapped.hEvent = Test->Event;
    if (Type == SOCK_DGRAM)
        Ret = WSARecvFrom(Test->Socket, &Buf, 1, NULL, &Flags, NULL, NULL, (LPWSAOVERLAPPED)&Test->Overlapped, NULL);
    else
        Ret = WSARecv(Test->Socket, &Buf, 1, NULL, &Flags, (LPWSAOVERLAPPED)&Test->Overlapped, NULL);
    ok(Ret == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING, "%s: receive %d, error %d\n",
       Label, Ret, WSAGetLastError());
    Sleep(100);
    return TRUE;
}

static
void
Finish(SHUTDOWN_TEST *Test)
{
    if (Test->Socket != INVALID_SOCKET)
        closesocket(Test->Socket);
    if (Test->Peer != INVALID_SOCKET)
        closesocket(Test->Peer);
    if (Test->Event)
        CloseHandle(Test->Event);
    if (Test->Port)
        CloseHandle(Test->Port);
}

/* The receive is still pending: no packet, the event clear, the status pending */
static
void
CheckPending(SHUTDOWN_TEST *Test, const char *When)
{
    DWORD Bytes = 0, Flags = 0;
    ULONG_PTR Key;
    OVERLAPPED *Got = NULL;

    if (Test->Port)
    {
        BOOL Result = GetQueuedCompletionStatus(Test->Port, &Bytes, &Key, &Got, 300);
        ok(!Result && Got == NULL, "%s %s: packet %d, overlapped %p, error %lu\n",
           Test->Label, When, Result, Got, GetLastError());
    }
    else
        Sleep(300);
    ok((ULONG)Test->Overlapped.Internal == STATUS_PENDING_, "%s %s: Internal is %08lx\n",
       Test->Label, When, (ULONG)Test->Overlapped.Internal);
    if (Test->Event)
        ok(WaitForSingleObject(Test->Event, 0) == WAIT_TIMEOUT, "%s %s: the event is signalled\n", Test->Label, When);
    SetLastError(0xdeadbeef);
    ok(!WSAGetOverlappedResult(Test->Socket, (LPWSAOVERLAPPED)&Test->Overlapped, &Bytes, FALSE, &Flags) &&
       WSAGetLastError() == WSA_IO_INCOMPLETE, "%s %s: WSAGetOverlappedResult error %d\n",
       Test->Label, When, WSAGetLastError());
}

/* The receive completed with the status; Port: the packet with that error and byte count */
static
void
CheckCompleted(SHUTDOWN_TEST *Test, const char *When, ULONG Status, DWORD Error, DWORD ExpectedBytes)
{
    DWORD Bytes = 0xdeadbeef;
    ULONG_PTR Key = 0;
    OVERLAPPED *Got = NULL;
    BOOL Result;

    if (Test->Port)
    {
        SetLastError(0xdeadbeef);
        Result = GetQueuedCompletionStatus(Test->Port, &Bytes, &Key, &Got, 2000);
        ok(Got == &Test->Overlapped, "%s %s: no packet (overlapped %p, error %lu)\n", Test->Label, When, Got, GetLastError());
        if (Got)
        {
            ok(Result == (Error == ERROR_SUCCESS), "%s %s: result %d\n", Test->Label, When, Result);
            if (!Result)
                ok(GetLastError() == Error, "%s %s: error %lu, expected %lu\n", Test->Label, When, GetLastError(), Error);
            ok(Key == 0x77, "%s %s: key %Ix\n", Test->Label, When, Key);
            ok(Bytes == ExpectedBytes, "%s %s: %lu bytes, expected %lu\n", Test->Label, When, Bytes, ExpectedBytes);
        }
    }
    else if (Test->Event)
        ok(WaitForSingleObject(Test->Event, 2000) == WAIT_OBJECT_0, "%s %s: the event is not signalled\n", Test->Label, When);
    else
        Sleep(500);
    ok((ULONG)Test->Overlapped.Internal == Status, "%s %s: Internal is %08lx, expected %08lx\n",
       Test->Label, When, (ULONG)Test->Overlapped.Internal, Status);
    ok(Test->Overlapped.InternalHigh == ExpectedBytes, "%s %s: InternalHigh is %Iu, expected %lu\n",
       Test->Label, When, (SIZE_T)Test->Overlapped.InternalHigh, ExpectedBytes);
}

static
void
TestData(const char *Label, int Mode, int How)
{
    SHUTDOWN_TEST Test;
    WSABUF Buf;
    char Data[4];
    DWORD Flags = 0, Bytes;
    int Ret, Error;

    if (!Start(&Test, Label, SOCK_STREAM, Mode))
        return;

    ok(shutdown(Test.Socket, How) == 0, "%s: shutdown failed: %d\n", Label, WSAGetLastError());
    CheckPending(&Test, "after shutdown");

    /* shutting down again succeeds */
    ok(shutdown(Test.Socket, How) == 0, "%s: second shutdown failed: %d\n", Label, WSAGetLastError());
    CheckPending(&Test, "after the second shutdown");

    /* what the peer sends later completes it */
    ok(send(Test.Peer, "hello", 5, 0) == 5, "%s: send failed: %d\n", Label, WSAGetLastError());
    CheckCompleted(&Test, "after data", 0, ERROR_SUCCESS, 5);
    ok(memcmp(Test.Buffer, "hello", 5) == 0, "%s: the data is wrong\n", Label);

    /* a new receive fails */
    Buf.len = sizeof(Data);
    Buf.buf = Data;
    ZeroMemory(&Test.Overlapped, sizeof(Test.Overlapped));
    Ret = WSARecv(Test.Socket, &Buf, 1, NULL, &Flags, (LPWSAOVERLAPPED)&Test.Overlapped, NULL);
    Error = WSAGetLastError();
    ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "%s: new receive %d, error %d\n", Label, Ret, Error);
    Ret = WSARecv(Test.Socket, &Buf, 1, &Bytes, &Flags, NULL, NULL);
    Error = WSAGetLastError();
    ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "%s: new blocking receive %d, error %d\n", Label, Ret, Error);

    /* the other direction: open after SD_RECEIVE, closed after SD_BOTH */
    Ret = send(Test.Socket, "x", 1, 0);
    Error = WSAGetLastError();
    if (How == SD_RECEIVE)
    {
        ok(Ret == 1, "%s: send %d, error %d\n", Label, Ret, Error);
        if (Ret == 1)
        {
            DWORD Timeout = 3000;
            setsockopt(Test.Peer, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
            ok(recv(Test.Peer, Data, sizeof(Data), 0) == 1, "%s: the peer received nothing\n", Label);
        }
    }
    else
        ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "%s: send %d, error %d\n", Label, Ret, Error);

    Finish(&Test);
}

/* The receive is pending across the shutdown, then the connection ends */
static
void
TestEnding(const char *Label, int How, int Ending)
{
    SHUTDOWN_TEST Test;
    struct linger Linger = { 1, 0 };

    if (!Start(&Test, Label, SOCK_STREAM, 1))
        return;

    ok(shutdown(Test.Socket, How) == 0, "%s: shutdown failed: %d\n", Label, WSAGetLastError());
    CheckPending(&Test, "after shutdown");

    switch (Ending)
    {
        case 0: /* the peer closes: the end of the stream, 0 bytes */
            closesocket(Test.Peer);
            Test.Peer = INVALID_SOCKET;
            CheckCompleted(&Test, "peer closed", 0, ERROR_SUCCESS, 0);
            break;
        case 1: /* the peer aborts */
            setsockopt(Test.Peer, SOL_SOCKET, SO_LINGER, (char *)&Linger, sizeof(Linger));
            closesocket(Test.Peer);
            Test.Peer = INVALID_SOCKET;
            CheckCompleted(&Test, "peer aborted", STATUS_CONNECTION_RESET_, ERROR_NETNAME_DELETED, 0);
            break;
        default: /* this side closes */
            closesocket(Test.Socket);
            Test.Socket = INVALID_SOCKET;
            if (How == SD_RECEIVE)
                CheckCompleted(&Test, "closed", STATUS_CONNECTION_ABORTED_, ERROR_CONNECTION_ABORTED, 0);
            else
                CheckCompleted(&Test, "closed", STATUS_CANCELLED_, ERROR_OPERATION_ABORTED, 0);
            break;
    }

    Finish(&Test);
}

/* shutdown does not wake a blocking receive of another thread, the data does */
static SOCKET BlockingSocket;
static int BlockingResult, BlockingError;

static
DWORD
WINAPI
BlockingReceive(LPVOID Parameter)
{
    char Data[16];

    BlockingResult = recv(BlockingSocket, Data, sizeof(Data), 0);
    BlockingError = BlockingResult == SOCKET_ERROR ? WSAGetLastError() : 0;
    return 0;
}

static
void
TestBlocking(int Type)
{
    SOCKET Socket, Peer;
    HANDLE Thread;
    const char *Label = Type == SOCK_STREAM ? "tcp blocking" : "udp blocking";

    if (!MakePair(Type, &Socket, &Peer))
    {
        skip("%s: socket setup failed: %d\n", Label, WSAGetLastError());
        return;
    }
    BlockingSocket = Socket;
    BlockingResult = -99;
    Thread = CreateThread(NULL, 0, BlockingReceive, NULL, 0, NULL);
    ok(Thread != NULL, "%s: CreateThread failed: %lu\n", Label, GetLastError());
    if (Thread)
    {
        Sleep(300);
        ok(shutdown(Socket, SD_RECEIVE) == 0, "%s: shutdown failed: %d\n", Label, WSAGetLastError());
        ok(WaitForSingleObject(Thread, 700) == WAIT_TIMEOUT, "%s: shutdown woke the receive: %d, error %d\n",
           Label, BlockingResult, BlockingError);
        ok(send(Peer, "wake", 4, 0) == 4, "%s: send failed: %d\n", Label, WSAGetLastError());
        ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "%s: the data did not wake the receive\n", Label);
        ok(BlockingResult == 4, "%s: the receive returned %d, error %d\n", Label, BlockingResult, BlockingError);
        CloseHandle(Thread);
    }
    closesocket(Socket);
    closesocket(Peer);
}

static
void
TestDatagram(const char *Label, int Mode)
{
    SHUTDOWN_TEST Test;

    if (!Start(&Test, Label, SOCK_DGRAM, Mode))
        return;

    ok(shutdown(Test.Socket, SD_RECEIVE) == 0, "%s: shutdown failed: %d\n", Label, WSAGetLastError());
    CheckPending(&Test, "after shutdown");
    ok(send(Test.Peer, "hello", 5, 0) == 5, "%s: send failed: %d\n", Label, WSAGetLastError());
    CheckCompleted(&Test, "after data", 0, ERROR_SUCCESS, 5);

    Finish(&Test);
}

/* Without a receive pending: the send direction is not affected by SD_RECEIVE, and SD_SEND closes it */
static
void
TestSendDirection(void)
{
    SOCKET Socket, Peer;
    DWORD Timeout = 3000;
    char Data[8];
    int Ret, Error;

    if (!MakePair(SOCK_STREAM, &Socket, &Peer))
    {
        skip("send direction: socket setup failed: %d\n", WSAGetLastError());
        return;
    }
    setsockopt(Peer, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));

    ok(shutdown(Socket, SD_RECEIVE) == 0, "shutdown failed: %d\n", WSAGetLastError());
    Ret = send(Socket, "x", 1, 0);
    Error = WSAGetLastError();
    ok(Ret == 1, "send after SD_RECEIVE: %d, error %d\n", Ret, Error);
    if (Ret == 1)
        ok(recv(Peer, Data, sizeof(Data), 0) == 1, "the peer received nothing\n");

    ok(shutdown(Socket, SD_SEND) == 0, "shutdown(SD_SEND) failed: %d\n", WSAGetLastError());
    Ret = send(Socket, "y", 1, 0);
    Error = WSAGetLastError();
    ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "send after SD_SEND: %d, error %d\n", Ret, Error);
    ok(recv(Peer, Data, sizeof(Data), 0) == 0, "the peer did not see the end of the stream\n");

    closesocket(Socket);
    closesocket(Peer);
}

/* shutdown(SD_RECEIVE|SD_BOTH) with data queued unread, or data arriving with no receive pending: Windows
 * resets the connection. The socket fails with WSAECONNABORTED, the peer sees WSAECONNRESET (except after
 * SD_BOTH, where the peer got the end of the stream first and sees WSAECONNABORTED). SO_ERROR stays 0. */
static
BOOL
Readable(SOCKET Socket, BOOL *Writable)
{
    fd_set Read, Write;
    struct timeval Timeout = { 0, 300000 };

    FD_ZERO(&Read);
    FD_ZERO(&Write);
    FD_SET(Socket, &Read);
    FD_SET(Socket, &Write);
    select(0, &Read, &Write, NULL, &Timeout);
    if (Writable)
        *Writable = FD_ISSET(Socket, &Write) != 0;
    return FD_ISSET(Socket, &Read) != 0;
}

static
void
CheckFails(SOCKET Socket, const char *Label, int Operation, int ExpectedError)
{
    char Data[16];
    int Ret = Operation ? send(Socket, "x", 1, 0) : recv(Socket, Data, sizeof(Data), 0);
    int Error = WSAGetLastError();

    ok(Ret == SOCKET_ERROR && Error == ExpectedError, "%s %s: %d, error %d, expected %d\n",
       Label, Operation ? "send" : "recv", Ret, Error, ExpectedError);
}

static
void
TestReset(const char *Label, BOOL Queued, int How, int First)
{
    SOCKET Socket, Peer;
    char Data[16];
    char Buffer[16];
    WSABUF Buf = { sizeof(Buffer), Buffer };
    WSAOVERLAPPED Overlapped;
    WSANETWORKEVENTS Events;
    WSAEVENT Event;
    DWORD Flags = 0;
    BOOL Writable;
    int Ret, Error, Value, Len;
    int PeerError = (!Queued && How == SD_BOTH) ? WSAECONNABORTED : WSAECONNRESET;
    /* the peer that already got the end of the stream reads it as 0 bytes, not as the abort */
    BOOL PeerTodo = !Queued && How == SD_BOTH;

    if (!MakePair(SOCK_STREAM, &Socket, &Peer))
    {
        skip("%s: socket setup failed: %d\n", Label, WSAGetLastError());
        return;
    }

    if (Queued)
    {
        ok(send(Peer, "queued", 6, 0) == 6, "%s: send failed: %d\n", Label, WSAGetLastError());
        Sleep(200);
    }
    ok(shutdown(Socket, How) == 0, "%s: shutdown failed: %d\n", Label, WSAGetLastError());
    if (!Queued)
    {
        ok(send(Peer, "later", 5, 0) == 5, "%s: send failed: %d\n", Label, WSAGetLastError());
        Sleep(300);
    }

    /* whichever call comes first sees the reset */
    if (First == 1)
        CheckFails(Socket, Label, 0, WSAECONNABORTED);
    if (First == 2)
        CheckFails(Socket, Label, 1, WSAECONNABORTED);

    /* SO_ERROR reports nothing */
    Value = -1;
    Len = sizeof(Value);
    Ret = getsockopt(Socket, SOL_SOCKET, SO_ERROR, (char *)&Value, &Len);
    ok(Ret == 0 && Value == 0, "%s: SO_ERROR %d, value %d, error %d\n", Label, Ret, Value, WSAGetLastError());

    CheckFails(Socket, Label, 0, WSAECONNABORTED);
    CheckFails(Socket, Label, 0, WSAECONNABORTED);
    CheckFails(Socket, Label, 1, WSAECONNABORTED);
    CheckFails(Socket, Label, 1, WSAECONNABORTED);

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.Internal = STATUS_PENDING_;
    Ret = WSARecv(Socket, &Buf, 1, NULL, &Flags, &Overlapped, NULL);
    Error = WSAGetLastError();
    ok(Ret == SOCKET_ERROR && Error == WSAECONNABORTED, "%s: WSARecv %d, error %d\n", Label, Ret, Error);
    ok(Overlapped.Internal == STATUS_PENDING_, "%s: WSARecv left Internal %08lx\n", Label, (ULONG)Overlapped.Internal);

    ok(Readable(Socket, &Writable), "%s: not readable\n", Label);
    ok(Writable, "%s: not writable\n", Label);

    Event = WSACreateEvent();
    WSAEventSelect(Socket, Event, FD_READ | FD_WRITE | FD_CLOSE);
    Sleep(100);
    ZeroMemory(&Events, sizeof(Events));
    ok(WSAEnumNetworkEvents(Socket, Event, &Events) == 0, "%s: WSAEnumNetworkEvents failed: %d\n", Label, WSAGetLastError());
    ok((Events.lNetworkEvents & FD_CLOSE) != 0, "%s: no FD_CLOSE, events %lx\n", Label, Events.lNetworkEvents);
    ok(Events.iErrorCode[FD_CLOSE_BIT] == WSAECONNABORTED, "%s: FD_CLOSE error %d\n", Label, Events.iErrorCode[FD_CLOSE_BIT]);
    WSAEventSelect(Socket, NULL, 0);
    WSACloseEvent(Event);

    ok(shutdown(Socket, SD_SEND) == 0, "%s: shutdown(SD_SEND) failed: %d\n", Label, WSAGetLastError());
    ok(shutdown(Socket, SD_RECEIVE) == 0, "%s: second shutdown failed: %d\n", Label, WSAGetLastError());

    /* the peer sees the reset */
    ok(Readable(Peer, NULL), "%s: the peer is not readable\n", Label);
    Value = -1;
    Len = sizeof(Value);
    Ret = getsockopt(Peer, SOL_SOCKET, SO_ERROR, (char *)&Value, &Len);
    ok(Ret == 0 && Value == 0, "%s: peer SO_ERROR %d, value %d\n", Label, Ret, Value);
    Ret = recv(Peer, Data, sizeof(Data), 0);
    Error = WSAGetLastError();
    if (!PeerTodo)
    {
        ok(Ret == SOCKET_ERROR && Error == PeerError, "%s: peer recv %d, error %d, expected %d\n", Label, Ret, Error, PeerError);
        CheckFails(Peer, Label, 0, PeerError);
        CheckFails(Peer, Label, 1, PeerError);
    }
    else
    {
        /* Windows fails the receive with WSAECONNABORTED; the end of the stream the peer got first is
         * all that ReactOS reports (the send fails with WSAECONNRESET there, WSAECONNABORTED on Windows) */
        Ret = send(Peer, "x", 1, 0);
        Error = WSAGetLastError();
        ok(Ret == SOCKET_ERROR && (Error == WSAECONNABORTED || Error == WSAECONNRESET), "%s: peer send %d, error %d\n", Label, Ret, Error);
    }

    ok(closesocket(Socket) == 0, "%s: closesocket failed: %d\n", Label, WSAGetLastError());
    ok(closesocket(Peer) == 0, "%s: closesocket of the peer failed: %d\n", Label, WSAGetLastError());
}

/* What does not reset: nothing unread and nothing arriving, SD_SEND with data arriving, the graceful ends */
static
void
TestNoReset(void)
{
    SOCKET Socket, Peer;
    DWORD Timeout = 3000;
    char Data[16];
    int Ret, Error;

    /* SD_RECEIVE with nothing queued and nothing arriving: both directions keep working as they do */
    if (MakePair(SOCK_STREAM, &Socket, &Peer))
    {
        setsockopt(Peer, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
        ok(shutdown(Socket, SD_RECEIVE) == 0, "shutdown failed: %d\n", WSAGetLastError());
        Sleep(300);
        Ret = recv(Socket, Data, sizeof(Data), 0);
        Error = WSAGetLastError();
        ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "recv after SD_RECEIVE: %d, error %d\n", Ret, Error);
        ok(send(Socket, "x", 1, 0) == 1, "send after SD_RECEIVE failed: %d\n", WSAGetLastError());
        ok(recv(Peer, Data, sizeof(Data), 0) == 1, "the peer received nothing: %d\n", WSAGetLastError());
        ok(!Readable(Peer, NULL), "the peer is readable\n");
        ok(closesocket(Socket) == 0, "closesocket failed\n");
        Ret = recv(Peer, Data, sizeof(Data), 0);
        ok(Ret == 0, "the peer did not see the graceful close: %d, error %d\n", Ret, WSAGetLastError());
        closesocket(Peer);
    }

    /* SD_BOTH with nothing queued or arriving: the peer sees the end of the stream, not a reset */
    if (MakePair(SOCK_STREAM, &Socket, &Peer))
    {
        setsockopt(Peer, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
        ok(shutdown(Socket, SD_BOTH) == 0, "shutdown failed: %d\n", WSAGetLastError());
        Ret = recv(Peer, Data, sizeof(Data), 0);
        ok(Ret == 0, "the peer did not see the end of the stream: %d, error %d\n", Ret, WSAGetLastError());
        Ret = recv(Socket, Data, sizeof(Data), 0);
        Error = WSAGetLastError();
        ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "recv after SD_BOTH: %d, error %d\n", Ret, Error);
        Ret = send(Socket, "x", 1, 0);
        Error = WSAGetLastError();
        ok(Ret == SOCKET_ERROR && Error == WSAESHUTDOWN, "send after SD_BOTH: %d, error %d\n", Ret, Error);
        closesocket(Socket);
        closesocket(Peer);
    }

    /* SD_SEND: data that arrives is received, nothing resets */
    if (MakePair(SOCK_STREAM, &Socket, &Peer))
    {
        setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
        ok(shutdown(Socket, SD_SEND) == 0, "shutdown failed: %d\n", WSAGetLastError());
        ok(send(Peer, "abc", 3, 0) == 3, "send failed: %d\n", WSAGetLastError());
        Sleep(300);
        Ret = recv(Socket, Data, sizeof(Data), 0);
        ok(Ret == 3, "recv after SD_SEND: %d, error %d\n", Ret, WSAGetLastError());
        closesocket(Socket);
        closesocket(Peer);
    }

    /* data received before the shutdown and read: nothing is unread, no reset */
    if (MakePair(SOCK_STREAM, &Socket, &Peer))
    {
        setsockopt(Peer, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
        ok(send(Peer, "abc", 3, 0) == 3, "send failed: %d\n", WSAGetLastError());
        Sleep(200);
        Ret = recv(Socket, Data, sizeof(Data), 0);
        ok(Ret == 3, "recv: %d, error %d\n", Ret, WSAGetLastError());
        ok(shutdown(Socket, SD_RECEIVE) == 0, "shutdown failed: %d\n", WSAGetLastError());
        Sleep(300);
        ok(send(Socket, "x", 1, 0) == 1, "send failed: %d\n", WSAGetLastError());
        ok(recv(Peer, Data, sizeof(Data), 0) == 1, "the peer received nothing: %d\n", WSAGetLastError());
        closesocket(Socket);
        closesocket(Peer);
    }
}

START_TEST(shutdownrecv)
{
    WSADATA WsaData;
    int Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    if (Error)
    {
        skip("WSAStartup failed: %d\n", Error);
        return;
    }

    TestData("tcp plain, SD_RECEIVE", 0, SD_RECEIVE);
    TestData("tcp port, SD_RECEIVE", 1, SD_RECEIVE);
    TestData("tcp event, SD_RECEIVE", 2, SD_RECEIVE);
    TestData("tcp plain, SD_BOTH", 0, SD_BOTH);
    TestData("tcp port, SD_BOTH", 1, SD_BOTH);
    TestData("tcp event, SD_BOTH", 2, SD_BOTH);

    TestEnding("tcp SD_RECEIVE, peer closes", SD_RECEIVE, 0);
    TestEnding("tcp SD_RECEIVE, peer aborts", SD_RECEIVE, 1);
    TestEnding("tcp SD_RECEIVE, close", SD_RECEIVE, 2);
    TestEnding("tcp SD_BOTH, peer closes", SD_BOTH, 0);
    TestEnding("tcp SD_BOTH, peer aborts", SD_BOTH, 1);
    TestEnding("tcp SD_BOTH, close", SD_BOTH, 2);

    TestSendDirection();

    TestBlocking(SOCK_STREAM);
    TestBlocking(SOCK_DGRAM);

    TestDatagram("udp port", 1);
    TestDatagram("udp event", 2);

    TestReset("unread, SD_RECEIVE, getsockopt first", TRUE, SD_RECEIVE, 0);
    TestReset("unread, SD_RECEIVE, recv first", TRUE, SD_RECEIVE, 1);
    TestReset("unread, SD_RECEIVE, send first", TRUE, SD_RECEIVE, 2);
    TestReset("unread, SD_BOTH", TRUE, SD_BOTH, 1);
    TestReset("arriving, SD_RECEIVE, getsockopt first", FALSE, SD_RECEIVE, 0);
    TestReset("arriving, SD_RECEIVE, recv first", FALSE, SD_RECEIVE, 1);
    TestReset("arriving, SD_RECEIVE, send first", FALSE, SD_RECEIVE, 2);
    TestReset("arriving, SD_BOTH", FALSE, SD_BOTH, 1);
    TestNoReset();

    WSACleanup();
}
