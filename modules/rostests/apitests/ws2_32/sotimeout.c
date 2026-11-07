/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the socket receive and send time-outs (SO_RCVTIMEO, SO_SNDTIMEO)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

/* Windows waits 500 ms longer than the value, so the upper bounds are generous */
#define SLACK_BELOW 60
#define SLACK_ABOVE 4000
#define HANG_MS 4000
#define NO_BYTES 0xdeadbeef

/* msafd cancels only the timed out request through NtCancelIoFileEx, which ntdll exports from 0x600 on; below that the
 * time-out is not applied */
#if DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA
#define ROS_TIMEOUTS 1
#else
#define ROS_TIMEOUTS 0
#endif
#define TIMEOUTS_APPLY() (!is_reactos() || ROS_TIMEOUTS)

typedef enum
{
    ApiRecv,
    ApiRecvPeek,
    ApiWsaRecv,
    ApiWsaRecvFrom,
    ApiRecvFrom
} RECV_API;

typedef struct
{
    SOCKET Socket;
    RECV_API Api;
    int Result;
    int Error;
    DWORD Bytes;
    DWORD Elapsed;
    char Buffer[64];
} RECV_JOB;

static
DWORD
WINAPI
RecvThread(LPVOID Context)
{
    RECV_JOB *Job = Context;
    WSABUF Buffer;
    DWORD Flags = 0;
    struct sockaddr_in From;
    int FromLength = sizeof(From);
    DWORD Start = GetTickCount();

    Job->Bytes = NO_BYTES;
    Buffer.buf = Job->Buffer;
    Buffer.len = sizeof(Job->Buffer);

    switch (Job->Api)
    {
        case ApiRecv:
            Job->Result = recv(Job->Socket, Job->Buffer, sizeof(Job->Buffer), 0);
            break;
        case ApiRecvPeek:
            Job->Result = recv(Job->Socket, Job->Buffer, sizeof(Job->Buffer), MSG_PEEK);
            break;
        case ApiWsaRecv:
            Job->Result = WSARecv(Job->Socket, &Buffer, 1, &Job->Bytes, &Flags, NULL, NULL);
            break;
        case ApiWsaRecvFrom:
            Job->Result = WSARecvFrom(Job->Socket, &Buffer, 1, &Job->Bytes, &Flags,
                                      (struct sockaddr *)&From, &FromLength, NULL, NULL);
            break;
        case ApiRecvFrom:
            Job->Result = recvfrom(Job->Socket, Job->Buffer, sizeof(Job->Buffer), 0,
                                   (struct sockaddr *)&From, &FromLength);
            break;
    }
    Job->Error = (Job->Result == SOCKET_ERROR) ? WSAGetLastError() : 0;
    Job->Elapsed = GetTickCount() - Start;
    return 0;
}

/* Runs the receive on a thread so that a missing time-out fails the test and does not hang it.
 * A hung receive is released with a byte sent from Peer (to RescueTo for a datagram socket). */
static
BOOL
RunRecv(RECV_JOB *Job, SOCKET Socket, RECV_API Api, SOCKET Peer, const struct sockaddr_in *RescueTo, const char *What)
{
    HANDLE Thread;
    BOOL Hung = FALSE;

    ZeroMemory(Job, sizeof(*Job));
    Job->Socket = Socket;
    Job->Api = Api;
    Thread = CreateThread(NULL, 0, RecvThread, Job, 0, NULL);
    if (!Thread)
    {
        ok(0, "%s: CreateThread failed: %lu\n", What, GetLastError());
        return FALSE;
    }

    if (WaitForSingleObject(Thread, HANG_MS) != WAIT_OBJECT_0)
    {
        ok(0, "%s: the receive did not return within %d ms\n", What, HANG_MS);
        Hung = TRUE;
        if (RescueTo)
            sendto(Peer, "R", 1, 0, (const struct sockaddr *)RescueTo, sizeof(*RescueTo));
        else
            send(Peer, "R", 1, 0);
        if (WaitForSingleObject(Thread, HANG_MS) != WAIT_OBJECT_0)
        {
            skip("%s: the receive is stuck, leaving its thread\n", What);
            CloseHandle(Thread);
            return FALSE;
        }
    }
    CloseHandle(Thread);
    return !Hung;
}

static
BOOL
OpenListener(SOCKET *Listener, struct sockaddr_in *Address)
{
    int Length = sizeof(*Address);

    *Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*Listener == INVALID_SOCKET)
        return FALSE;

    ZeroMemory(Address, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(*Listener, (struct sockaddr *)Address, sizeof(*Address)) == SOCKET_ERROR ||
        getsockname(*Listener, (struct sockaddr *)Address, &Length) == SOCKET_ERROR ||
        listen(*Listener, 4) == SOCKET_ERROR)
    {
        closesocket(*Listener);
        *Listener = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

/* A connected pair; the client socket is created with Flags */
static
BOOL
OpenPair(SOCKET *Client, SOCKET *Server, DWORD Flags)
{
    SOCKET Listener;
    struct sockaddr_in Address;

    *Client = *Server = INVALID_SOCKET;
    if (!OpenListener(&Listener, &Address))
    {
        ok(0, "listener failed: %d\n", WSAGetLastError());
        return FALSE;
    }

    *Client = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, Flags);
    if (*Client == INVALID_SOCKET ||
        connect(*Client, (struct sockaddr *)&Address, sizeof(Address)) == SOCKET_ERROR)
    {
        ok(0, "connect failed: %d\n", WSAGetLastError());
        goto Fail;
    }

    *Server = accept(Listener, NULL, NULL);
    if (*Server == INVALID_SOCKET)
    {
        ok(0, "accept failed: %d\n", WSAGetLastError());
        goto Fail;
    }

    closesocket(Listener);
    return TRUE;

Fail:
    if (*Client != INVALID_SOCKET)
        closesocket(*Client);
    closesocket(Listener);
    *Client = *Server = INVALID_SOCKET;
    return FALSE;
}

/* Removes the byte a rescue sent, if the receive that was rescued did not consume it */
static
void
DrainSocket(SOCKET Socket)
{
    u_long Pending = 0;
    char Data[64];

    while (ioctlsocket(Socket, FIONREAD, &Pending) == 0 && Pending != 0)
        recv(Socket, Data, sizeof(Data), 0);
}

static
void
SetTimeout(SOCKET Socket, int Option, DWORD Value)
{
    int Result = setsockopt(Socket, SOL_SOCKET, Option, (const char *)&Value, sizeof(Value));

    ok(Result == 0, "setsockopt(%d) failed: %d\n", Option, WSAGetLastError());
}

static
DWORD
GetTimeout(SOCKET Socket, int Option)
{
    DWORD Value = NO_BYTES;
    int Length = sizeof(Value);
    int Result = getsockopt(Socket, SOL_SOCKET, Option, (char *)&Value, &Length);

    ok(Result == 0, "getsockopt(%d) failed: %d\n", Option, WSAGetLastError());
    ok(Length == sizeof(Value), "getsockopt(%d) returned length %d\n", Option, Length);
    return Value;
}

static
void
CheckTimedOut(const RECV_JOB *Job, DWORD Timeout, const char *What)
{
    ok(Job->Result == SOCKET_ERROR, "%s: result %d\n", What, Job->Result);
    ok(Job->Error == WSAETIMEDOUT, "%s: error %d, expected %d\n", What, Job->Error, WSAETIMEDOUT);
    ok(Job->Elapsed + SLACK_BELOW >= Timeout, "%s: returned after %lu ms, before the %lu ms time-out\n",
       What, Job->Elapsed, Timeout);
    ok(Job->Elapsed < Timeout + SLACK_ABOVE, "%s: returned after %lu ms\n", What, Job->Elapsed);
}

static
void
Test_Defaults(void)
{
    SOCKET Client, Server;
    DWORD Value;
    char Raw[2];
    int Length, Result;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    ok(GetTimeout(Client, SO_RCVTIMEO) == 0, "default SO_RCVTIMEO is %lu\n", GetTimeout(Client, SO_RCVTIMEO));
    ok(GetTimeout(Client, SO_SNDTIMEO) == 0, "default SO_SNDTIMEO is %lu\n", GetTimeout(Client, SO_SNDTIMEO));

    SetTimeout(Client, SO_RCVTIMEO, 1234);
    SetTimeout(Client, SO_SNDTIMEO, 5678);
    Value = GetTimeout(Client, SO_RCVTIMEO);
    ok(Value == 1234, "SO_RCVTIMEO is %lu\n", Value);
    Value = GetTimeout(Client, SO_SNDTIMEO);
    ok(Value == 5678, "SO_SNDTIMEO is %lu\n", Value);
    ok(GetTimeout(Server, SO_RCVTIMEO) == 0, "the other socket got the time-out\n");

    Value = 99;
    Result = setsockopt(Client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Value, 2);
    ok(Result == SOCKET_ERROR, "a 2 byte value was accepted\n");
    ok(WSAGetLastError() == WSAEFAULT, "error %d\n", WSAGetLastError());
    Length = sizeof(Raw);
    Result = getsockopt(Client, SOL_SOCKET, SO_RCVTIMEO, Raw, &Length);
    ok(Result == SOCKET_ERROR, "a 2 byte buffer was accepted\n");
    ok(WSAGetLastError() == WSAEFAULT, "error %d\n", WSAGetLastError());
    ok(GetTimeout(Client, SO_RCVTIMEO) == 1234, "a rejected value changed the time-out\n");

    closesocket(Client);
    closesocket(Server);
}

static
void
Test_RecvTimeout(void)
{
    static const DWORD Timeout = 300;
    SOCKET Client, Server;
    RECV_JOB Job;
    int Error = -1, Length = sizeof(Error);
    fd_set Readable;
    struct timeval Zero = { 0, 0 };
    char Buffer[16];

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    SetTimeout(Client, SO_RCVTIMEO, Timeout);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv"))
        CheckTimedOut(&Job, Timeout, "recv");

    /* The socket stays usable: no error is pending and no data is lost or invented */
    ok(getsockopt(Client, SOL_SOCKET, SO_ERROR, (char *)&Error, &Length) == 0, "SO_ERROR failed\n");
    ok(Error == 0, "SO_ERROR is %d after the time-out\n", Error);
    FD_ZERO(&Readable);
    FD_SET(Client, &Readable);
    ok(select(0, &Readable, NULL, NULL, &Zero) == 0, "the socket is readable after the time-out\n");
    ok(send(Client, "x", 1, 0) == 1, "send after the time-out failed: %d\n", WSAGetLastError());
    ok(recv(Server, Buffer, sizeof(Buffer), 0) == 1, "the peer did not get the byte: %d\n", WSAGetLastError());

    ok(send(Server, "abc", 3, 0) == 3, "send failed: %d\n", WSAGetLastError());
    ok(RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv after the time-out"), "recv did not return\n");
    ok(Job.Result == 3, "recv after the time-out returned %d, error %d\n", Job.Result, Job.Error);
    ok(Job.Result != 3 || memcmp(Job.Buffer, "abc", 3) == 0, "wrong data after the time-out\n");

    /* the next receive times out again, and the option is unchanged */
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "second recv"))
        CheckTimedOut(&Job, Timeout, "second recv");
    ok(GetTimeout(Client, SO_RCVTIMEO) == Timeout, "the time-out changed to %lu\n", GetTimeout(Client, SO_RCVTIMEO));

    closesocket(Client);
    closesocket(Server);
}

static
void
Test_RecvApis(void)
{
    static const DWORD Timeout = 250;
    static const struct
    {
        RECV_API Api;
        const char *Name;
    } Apis[] =
    {
        { ApiRecvPeek, "recv MSG_PEEK" },
        { ApiWsaRecv, "WSARecv" },
        { ApiWsaRecvFrom, "WSARecvFrom" },
        { ApiRecvFrom, "recvfrom on a stream socket" },
    };
    SOCKET Client, Server;
    RECV_JOB Job;
    ULONG i;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    SetTimeout(Client, SO_RCVTIMEO, Timeout);
    for (i = 0; i < _countof(Apis); i++)
    {
        if (!RunRecv(&Job, Client, Apis[i].Api, Server, NULL, Apis[i].Name))
        {
            DrainSocket(Client);
            continue;
        }
        CheckTimedOut(&Job, Timeout, Apis[i].Name);
        if (Apis[i].Api == ApiWsaRecv || Apis[i].Api == ApiWsaRecvFrom)
            ok(Job.Bytes == NO_BYTES, "%s: the byte count changed to 0x%lx\n", Apis[i].Name, Job.Bytes);
    }

    closesocket(Client);
    closesocket(Server);
}

typedef struct
{
    SOCKET Socket;
    DWORD Delay;
    const char *Data;
    int Length;
} SEND_LATER;

static
DWORD
WINAPI
SendLaterThread(LPVOID Context)
{
    SEND_LATER *Later = Context;

    Sleep(Later->Delay);
    send(Later->Socket, Later->Data, Later->Length, 0);
    return 0;
}

static
HANDLE
StartSendLater(SEND_LATER *Later, SOCKET Socket, DWORD Delay)
{
    Later->Socket = Socket;
    Later->Delay = Delay;
    Later->Data = "late";
    Later->Length = 4;
    return CreateThread(NULL, 0, SendLaterThread, Later, 0, NULL);
}

static
void
Test_NoTimeout(void)
{
    SOCKET Client, Server;
    RECV_JOB Job;
    SEND_LATER Later;
    HANDLE Thread;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    /* zero means no time-out */
    SetTimeout(Client, SO_RCVTIMEO, 0);
    Thread = StartSendLater(&Later, Server, 900);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv with time-out 0"))
    {
        ok(Job.Result == 4, "recv returned %d, error %d\n", Job.Result, Job.Error);
        ok(Job.Elapsed + SLACK_BELOW >= 900, "recv returned after %lu ms\n", Job.Elapsed);
    }
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }

    /* a long time-out lets late data through */
    SetTimeout(Client, SO_RCVTIMEO, 60000);
    Thread = StartSendLater(&Later, Server, 600);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv with a long time-out"))
    {
        ok(Job.Result == 4, "recv returned %d, error %d\n", Job.Result, Job.Error);
        ok(Job.Elapsed < 5000, "recv returned after %lu ms\n", Job.Elapsed);
    }
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }

    /* a time-out of 1 ms still ends a receive that has nothing to read */
    SetTimeout(Client, SO_RCVTIMEO, 1);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv with 1 ms"))
        CheckTimedOut(&Job, 1, "recv with 1 ms");

    closesocket(Client);
    closesocket(Server);
}

static
void
Test_Accepted(void)
{
    static const DWORD Timeout = 250;
    SOCKET Listener, Client, Server;
    struct sockaddr_in Address;
    RECV_JOB Job;

    if (!OpenListener(&Listener, &Address))
    {
        ok(0, "listener failed: %d\n", WSAGetLastError());
        return;
    }

    SetTimeout(Listener, SO_RCVTIMEO, Timeout);
    SetTimeout(Listener, SO_SNDTIMEO, Timeout + 1);
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(Client, (struct sockaddr *)&Address, sizeof(Address)) == 0, "connect failed: %d\n", WSAGetLastError());
    Server = accept(Listener, NULL, NULL);
    ok(Server != INVALID_SOCKET, "accept failed: %d\n", WSAGetLastError());
    if (Server != INVALID_SOCKET)
    {
        /* the accepted socket takes the time-outs of the listener */
        ok(GetTimeout(Server, SO_RCVTIMEO) == Timeout, "SO_RCVTIMEO of the accepted socket is %lu\n", GetTimeout(Server, SO_RCVTIMEO));
        ok(GetTimeout(Server, SO_SNDTIMEO) == Timeout + 1, "SO_SNDTIMEO of the accepted socket is %lu\n", GetTimeout(Server, SO_SNDTIMEO));
        if (RunRecv(&Job, Server, ApiRecv, Client, NULL, "recv on the accepted socket"))
            CheckTimedOut(&Job, Timeout, "recv on the accepted socket");
        closesocket(Server);
    }
    closesocket(Client);
    closesocket(Listener);
}

static
void
Test_Udp(void)
{
    static const DWORD Timeout = 250;
    SOCKET Receiver, Sender;
    struct sockaddr_in Address;
    int Length = sizeof(Address);
    int i, Result;
    RECV_JOB Job;

    if (!TIMEOUTS_APPLY())
    {
        skip("ReactOS does not apply the time-out of a blocking receive below 0x600\n");
        return;
    }

    Receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Receiver == INVALID_SOCKET || Sender == INVALID_SOCKET ||
        bind(Receiver, (struct sockaddr *)&Address, sizeof(Address)) == SOCKET_ERROR ||
        getsockname(Receiver, (struct sockaddr *)&Address, &Length) == SOCKET_ERROR)
    {
        ok(0, "UDP setup failed: %d\n", WSAGetLastError());
        goto Done;
    }

    SetTimeout(Receiver, SO_RCVTIMEO, Timeout);
    if (RunRecv(&Job, Receiver, ApiRecvFrom, Sender, &Address, "recvfrom"))
        CheckTimedOut(&Job, Timeout, "recvfrom");
    else
        goto Done;

    /* the datagram that comes later is received */
    ok(sendto(Sender, "dgram", 5, 0, (struct sockaddr *)&Address, sizeof(Address)) == 5, "sendto failed: %d\n", WSAGetLastError());
    ok(RunRecv(&Job, Receiver, ApiRecvFrom, Sender, &Address, "recvfrom after the time-out"), "recvfrom did not return\n");
    ok(Job.Result == 5, "recvfrom returned %d, error %d\n", Job.Result, Job.Error);

    if (RunRecv(&Job, Receiver, ApiWsaRecvFrom, Sender, &Address, "WSARecvFrom"))
        CheckTimedOut(&Job, Timeout, "WSARecvFrom");

    /* recv, WSARecv and a peek time out as well (recv on a datagram socket was the receive that hung) */
    if (RunRecv(&Job, Receiver, ApiRecv, Sender, &Address, "recv on a datagram socket"))
        CheckTimedOut(&Job, Timeout, "recv on a datagram socket");
    if (RunRecv(&Job, Receiver, ApiWsaRecv, Sender, &Address, "WSARecv on a datagram socket"))
        CheckTimedOut(&Job, Timeout, "WSARecv on a datagram socket");
    if (RunRecv(&Job, Receiver, ApiRecvPeek, Sender, &Address, "recv MSG_PEEK on a datagram socket"))
        CheckTimedOut(&Job, Timeout, "recv MSG_PEEK on a datagram socket");

    /* the time-out leaves no stale request behind: many cancelled receives, then a datagram arrives intact */
    SetTimeout(Receiver, SO_RCVTIMEO, 1);
    for (i = 0; i < 300; i++)
    {
        char Dummy[64];

        Result = recvfrom(Receiver, Dummy, sizeof(Dummy), 0, NULL, NULL);
        if (Result != SOCKET_ERROR || WSAGetLastError() != WSAETIMEDOUT)
        {
            ok(0, "receive %d with a 1 ms time-out returned %d, error %d\n", i, Result, WSAGetLastError());
            break;
        }
    }
    ok(i == 300, "only %d of 300 short time-outs completed\n", i);
    SetTimeout(Receiver, SO_RCVTIMEO, 5000);
    ok(sendto(Sender, "again", 5, 0, (struct sockaddr *)&Address, sizeof(Address)) == 5, "sendto failed: %d\n", WSAGetLastError());
    ok(RunRecv(&Job, Receiver, ApiRecvFrom, Sender, &Address, "recvfrom after the short time-outs"), "recvfrom did not return\n");
    ok(Job.Result == 5, "recvfrom after the short time-outs returned %d, error %d\n", Job.Result, Job.Error);
    ok(Job.Result != 5 || memcmp(Job.Buffer, "again", 5) == 0, "wrong datagram after the short time-outs\n");

Done:
    if (Receiver != INVALID_SOCKET)
        closesocket(Receiver);
    if (Sender != INVALID_SOCKET)
        closesocket(Sender);
}

static
void
Test_Overlapped(void)
{
    SOCKET Client, Server;
    WSAOVERLAPPED Overlapped;
    WSABUF Buffer;
    char Data[16];
    DWORD Bytes = NO_BYTES, Flags = 0, Transferred = 0;
    int Result;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    /* the time-out does not apply to overlapped requests */
    SetTimeout(Client, SO_RCVTIMEO, 150);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    Buffer.buf = Data;
    Buffer.len = sizeof(Data);
    Result = WSARecv(Client, &Buffer, 1, &Bytes, &Flags, &Overlapped, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING, "WSARecv returned %d, error %d\n", Result, WSAGetLastError());
    ok(WaitForSingleObject(Overlapped.hEvent, 1200) == WAIT_TIMEOUT, "the overlapped receive completed without data\n");
    ok(send(Server, "ov", 2, 0) == 2, "send failed: %d\n", WSAGetLastError());
    ok(WaitForSingleObject(Overlapped.hEvent, 5000) == WAIT_OBJECT_0, "the overlapped receive did not complete\n");
    Result = WSAGetOverlappedResult(Client, &Overlapped, &Transferred, FALSE, &Flags);
    ok(Result, "WSAGetOverlappedResult failed: %d\n", WSAGetLastError());
    ok(Transferred == 2, "received %lu bytes\n", Transferred);
    WSACloseEvent(Overlapped.hEvent);

    closesocket(Client);
    closesocket(Server);
}

typedef struct
{
    SOCKET Socket;
    HANDLE Issued;
    HANDLE Done;
    WSAOVERLAPPED Overlapped;
    char Data[16];
    int Result;
    int Error;
    DWORD Elapsed;
    int Pending;
} SAME_THREAD;

static
DWORD
WINAPI
SameThreadProc(LPVOID Context)
{
    SAME_THREAD *Job = Context;
    WSABUF Buffer;
    DWORD Bytes = 0, Flags = 0, Start;
    char Small[16];
    int Result;

    Buffer.buf = Job->Data;
    Buffer.len = sizeof(Job->Data);
    Result = WSARecv(Job->Socket, &Buffer, 1, &Bytes, &Flags, &Job->Overlapped, NULL);
    Job->Pending = (Result == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING);

    /* the blocking receive of the same thread on the same socket */
    Start = GetTickCount();
    Job->Result = recv(Job->Socket, Small, sizeof(Small), 0);
    Job->Error = (Job->Result == SOCKET_ERROR) ? WSAGetLastError() : 0;
    Job->Elapsed = GetTickCount() - Start;
    SetEvent(Job->Issued);

    /* a request of an exiting thread is cancelled, so the thread stays until the test has looked at it */
    WaitForSingleObject(Job->Done, 20000);
    return 0;
}

static
void
Test_PendingSurvives(void)
{
    static const DWORD Timeout = 250;
    SOCKET Client, Server;
    SAME_THREAD Job;
    HANDLE Thread;
    DWORD Transferred = 0, Flags = 0;
    BOOL Ok, Ended;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    /* the time-out of a blocking receive cancels that request and no other one of the thread */
    SetTimeout(Client, SO_RCVTIMEO, Timeout);
    ZeroMemory(&Job, sizeof(Job));
    Job.Socket = Client;
    Job.Issued = CreateEventW(NULL, TRUE, FALSE, NULL);
    Job.Done = CreateEventW(NULL, TRUE, FALSE, NULL);
    Job.Overlapped.hEvent = WSACreateEvent();
    Thread = CreateThread(NULL, 0, SameThreadProc, &Job, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    if (!Thread)
        goto Done;

    if (WaitForSingleObject(Job.Issued, HANG_MS) != WAIT_OBJECT_0)
    {
        ok(0, "the blocking receive did not return within %d ms\n", HANG_MS);
        send(Server, "R", 1, 0);
        WaitForSingleObject(Job.Issued, HANG_MS);
    }
    else
    {
        ok(Job.Pending, "the overlapped receive was not pending\n");
        ok(Job.Result == SOCKET_ERROR && Job.Error == WSAETIMEDOUT, "recv returned %d, error %d\n", Job.Result, Job.Error);
        ok(Job.Elapsed + SLACK_BELOW >= Timeout, "recv returned after %lu ms\n", Job.Elapsed);
    }

    Ended = (WaitForSingleObject(Job.Overlapped.hEvent, 300) == WAIT_OBJECT_0);
    if (is_reactos())
        ok(!Ended, "the overlapped receive ended with the time-out of the other one\n");

    if (Ended && !is_reactos())
    {
        /* Windows 10 aborts it (error 995): its time-out cancels all the thread's requests on the socket */
        skip("Windows cancelled the overlapped receive with the time-out of the other one\n");
    }
    else if (!Ended)
    {
        ok(send(Server, "ov", 2, 0) == 2, "send failed: %d\n", WSAGetLastError());
        ok(WaitForSingleObject(Job.Overlapped.hEvent, 5000) == WAIT_OBJECT_0, "the overlapped receive did not complete\n");
        Ok = WSAGetOverlappedResult(Client, &Job.Overlapped, &Transferred, FALSE, &Flags);
        ok(Ok && Transferred >= 1, "the overlapped receive failed: %d, %lu bytes\n", WSAGetLastError(), Transferred);
    }

    SetEvent(Job.Done);
    WaitForSingleObject(Thread, 5000);
    CloseHandle(Thread);

Done:
    WSACloseEvent(Job.Overlapped.hEvent);
    CloseHandle(Job.Issued);
    CloseHandle(Job.Done);
    closesocket(Client);
    closesocket(Server);
}

static
void
Test_NonBlocking(void)
{
    static const DWORD Timeout = 250;
    SOCKET Client, Server;
    RECV_JOB Job;
    u_long Mode = 1;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    SetTimeout(Client, SO_RCVTIMEO, Timeout);
    ok(ioctlsocket(Client, FIONBIO, &Mode) == 0, "FIONBIO failed\n");
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "non-blocking recv"))
    {
        ok(Job.Result == SOCKET_ERROR && Job.Error == WSAEWOULDBLOCK, "recv returned %d, error %d\n", Job.Result, Job.Error);
        ok(Job.Elapsed < Timeout, "a non-blocking recv took %lu ms\n", Job.Elapsed);
    }
    else
    {
        DrainSocket(Client);
    }

    Mode = 0;
    ok(ioctlsocket(Client, FIONBIO, &Mode) == 0, "FIONBIO failed\n");
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv after blocking mode again"))
        CheckTimedOut(&Job, Timeout, "recv after blocking mode again");

    closesocket(Client);
    closesocket(Server);
}

static
void
Test_NonOverlappedSocket(void)
{
    SOCKET Client, Server;
    RECV_JOB Job;
    SEND_LATER Later;
    HANDLE Thread;

    if (!OpenPair(&Client, &Server, 0))
        return;

    /* Windows does not apply the time-out to a socket created without WSA_FLAG_OVERLAPPED */
    SetTimeout(Client, SO_RCVTIMEO, 200);
    Thread = StartSendLater(&Later, Server, 1000);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv on a socket without WSA_FLAG_OVERLAPPED"))
    {
        ok(Job.Result == 4, "recv returned %d, error %d\n", Job.Result, Job.Error);
        ok(Job.Elapsed + SLACK_BELOW >= 1000, "recv returned after %lu ms\n", Job.Elapsed);
    }
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }

    closesocket(Client);
    closesocket(Server);
}

typedef struct
{
    SOCKET Socket;
    ULONG Count;
} SENDER;

static
void
SpinMs(DWORD Ms)
{
    DWORD Start = GetTickCount();

    while (GetTickCount() - Start < Ms)
        Sleep(1);
}

static
DWORD
WINAPI
SenderThread(LPVOID Context)
{
    SENDER *Sender = Context;
    ULONG i;

    for (i = 0; i < Sender->Count; i++)
    {
        unsigned char Value = (unsigned char)i;

        /* spread the arrivals over the time-out so that some meet the cancellation */
        SpinMs(6 + (i % 7) * 2);
        send(Sender->Socket, (const char *)&Value, 1, 0);
    }
    return 0;
}

static
void
Test_Race(void)
{
    enum { Count = 120 };
    SOCKET Client, Server;
    SENDER Sender;
    HANDLE Thread;
    ULONG Got = 0, Timeouts = 0, Wrong = 0;
    DWORD Start;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    /* data that arrives while a receive times out is neither lost nor delivered twice */
    SetTimeout(Client, SO_RCVTIMEO, 10);
    Sender.Socket = Server;
    Sender.Count = Count;
    Thread = CreateThread(NULL, 0, SenderThread, &Sender, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");

    Start = GetTickCount();
    while (Got < Count && GetTickCount() - Start < 20000)
    {
        unsigned char Value;
        int Result = recv(Client, (char *)&Value, 1, 0);

        if (Result == 1)
        {
            if (Value != (unsigned char)Got)
                Wrong++;
            Got++;
        }
        else if (Result == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT)
        {
            Timeouts++;
        }
        else
        {
            ok(0, "recv returned %d, error %d\n", Result, WSAGetLastError());
            break;
        }
    }

    if (Thread)
    {
        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
    }

    ok(Got == Count, "received %lu of %d bytes\n", Got, Count);
    ok(Wrong == 0, "%lu bytes arrived out of order, lost or repeated\n", Wrong);
    /* Windows waits 500 ms past the time-out, longer than the gaps between the bytes */
    ok(Timeouts > 0 || !is_reactos(), "no receive timed out\n");

    closesocket(Client);
    closesocket(Server);
}

static
DWORD
WINAPI
CloseThread(LPVOID Context)
{
    Sleep(300);
    closesocket((SOCKET)(ULONG_PTR)Context);
    return 0;
}

static
void
Test_Close(void)
{
    SOCKET Client, Server;
    RECV_JOB Job;
    HANDLE Thread;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    /* a socket closed under a waiting receive ends it at once, not at the time-out */
    SetTimeout(Client, SO_RCVTIMEO, 5000);
    Thread = CreateThread(NULL, 0, CloseThread, (LPVOID)(ULONG_PTR)Client, 0, NULL);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv on a socket that is closed"))
    {
        ok(Job.Result == SOCKET_ERROR, "recv returned %d\n", Job.Result);
        ok(Job.Error != WSAETIMEDOUT, "recv reported a time-out\n");
        ok(Job.Elapsed < 3000, "recv returned after %lu ms\n", Job.Elapsed);
    }
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }

    /* a peer that closes ends the receive with end of stream before the time-out */
    closesocket(Server);
    OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED);
    SetTimeout(Client, SO_RCVTIMEO, 5000);
    Thread = CreateThread(NULL, 0, CloseThread, (LPVOID)(ULONG_PTR)Server, 0, NULL);
    if (RunRecv(&Job, Client, ApiRecv, Server, NULL, "recv when the peer closes"))
    {
        ok(Job.Result == 0, "recv returned %d, error %d\n", Job.Result, Job.Error);
        ok(Job.Elapsed < 3000, "recv returned after %lu ms\n", Job.Elapsed);
    }
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    closesocket(Client);
}

typedef struct
{
    SOCKET Socket;
    int Result;
    int Error;
    DWORD Elapsed;
    ULONG Calls;
    ULONGLONG Total;
    BOOL Blocked;
} SEND_JOB;

#define SEND_CHUNK 8192
#define SEND_LIMIT (8ull * 1024 * 1024)

static
DWORD
WINAPI
FillThread(LPVOID Context)
{
    SEND_JOB *Job = Context;
    static char Chunk[SEND_CHUNK];

    while (Job->Total < SEND_LIMIT)
    {
        DWORD Start = GetTickCount();
        int Result = send(Job->Socket, Chunk, sizeof(Chunk), 0);

        if (Result == SOCKET_ERROR)
        {
            Job->Result = Result;
            Job->Error = WSAGetLastError();
            Job->Elapsed = GetTickCount() - Start;
            Job->Blocked = TRUE;
            return 0;
        }
        Job->Total += Result;
        Job->Calls++;
    }
    return 0;
}

static
void
Test_SendTimeout(void)
{
    static const DWORD Timeout = 300;
    SOCKET Client, Server;
    SEND_JOB Job;
    HANDLE Thread;
    int Size = 4096;
    char Drain[65536];
    DWORD Start;

    if (!OpenPair(&Client, &Server, WSA_FLAG_OVERLAPPED))
        return;

    setsockopt(Client, SOL_SOCKET, SO_SNDBUF, (const char *)&Size, sizeof(Size));
    setsockopt(Server, SOL_SOCKET, SO_RCVBUF, (const char *)&Size, sizeof(Size));
    SetTimeout(Client, SO_SNDTIMEO, Timeout);

    /* the peer does not read, so a send blocks once the buffers are full */
    ZeroMemory(&Job, sizeof(Job));
    Job.Socket = Client;
    Thread = CreateThread(NULL, 0, FillThread, &Job, 0, NULL);
    if (!Thread)
    {
        ok(0, "CreateThread failed\n");
        goto Done;
    }

    if (WaitForSingleObject(Thread, HANG_MS * 2) != WAIT_OBJECT_0)
    {
        ok(0, "a send did not time out after %lu bytes\n", (ULONG)Job.Total);

        /* release the sender by reading */
        Start = GetTickCount();
        while (WaitForSingleObject(Thread, 0) != WAIT_OBJECT_0 && GetTickCount() - Start < 20000)
        {
            if (recv(Server, Drain, sizeof(Drain), 0) <= 0)
                break;
        }
        WaitForSingleObject(Thread, 5000);
    }
    else if (!Job.Blocked)
    {
        skip("%lu bytes were sent without blocking\n", (ULONG)Job.Total);
    }
    else
    {
        ok(Job.Result == SOCKET_ERROR, "send returned %d\n", Job.Result);
        ok(Job.Error == WSAETIMEDOUT, "send error %d, expected %d\n", Job.Error, WSAETIMEDOUT);
        ok(Job.Elapsed + SLACK_BELOW >= Timeout, "send returned after %lu ms, before the %lu ms time-out\n", Job.Elapsed, Timeout);
        ok(Job.Elapsed < Timeout + SLACK_ABOVE, "send returned after %lu ms\n", Job.Elapsed);
    }
    CloseHandle(Thread);

Done:
    closesocket(Client);
    closesocket(Server);
}

START_TEST(sotimeout)
{
    WSADATA Data;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    Test_Defaults();
    if (!TIMEOUTS_APPLY())
    {
        skip("this build of msafd does not apply time-outs (DLL_EXPORT_VERSION below 0x600)\n");
        WSACleanup();
        return;
    }

    Test_RecvTimeout();
    Test_RecvApis();
    Test_NoTimeout();
    Test_Accepted();
    Test_Udp();
    Test_Overlapped();
    Test_PendingSurvives();
    Test_NonBlocking();
    Test_NonOverlappedSocket();
    Test_Race();
    Test_Close();
    Test_SendTimeout();

    WSACleanup();
}
