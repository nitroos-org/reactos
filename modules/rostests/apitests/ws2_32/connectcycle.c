/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Loopback TCP connect, exchange and close cycles from several threads at once
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#define CYCLE_THREADS 4
#define CYCLES_PER_THREAD 150
#define IO_TIMEOUT_MS 10000

typedef struct _CYCLE_WORK
{
    SOCKET Listener;
    struct sockaddr_in Addr;
    LONG Failures;
    LONG Done;
    int LastError;
    const char *FailedCall;
} CYCLE_WORK, *PCYCLE_WORK;

/* Static: a thread that never finishes must not write to a returned stack */
static CYCLE_WORK Work[CYCLE_THREADS];

static
void
Fail(PCYCLE_WORK W, const char *Call)
{
    W->Failures++;
    W->LastError = WSAGetLastError();
    W->FailedCall = Call;
}

static
BOOL
RecvAll(SOCKET s, char *Buf, int Len)
{
    int Got = 0, r;

    while (Got < Len)
    {
        r = recv(s, Buf + Got, Len - Got, 0);
        if (r <= 0)
            return FALSE;
        Got += r;
    }
    return TRUE;
}

/* Accepts the connections of one client thread: reads a number, sends it back, then waits for the end
 * of the client (or its reset) and closes */
static
DWORD
WINAPI
AcceptThread(LPVOID Parameter)
{
    PCYCLE_WORK W = Parameter;
    int i, Timeout = IO_TIMEOUT_MS;

    for (i = 0; i < CYCLES_PER_THREAD; i++)
    {
        SOCKET s = accept(W->Listener, NULL, NULL);
        char Buf[4];

        if (s == INVALID_SOCKET)
        {
            Fail(W, "accept");
            break;
        }
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
        if (!RecvAll(s, Buf, sizeof(Buf)))
            Fail(W, "server recv");
        else if (send(s, Buf, sizeof(Buf), 0) != sizeof(Buf))
            Fail(W, "server send");
        else
        {
            /* the client ends the connection: 0 (graceful) or an error (reset) */
            char Tail[8];
            int r = recv(s, Tail, sizeof(Tail), 0);

            if (r > 0)
                Fail(W, "server recv tail");
        }
        closesocket(s);
    }
    return 0;
}

static
DWORD
WINAPI
ClientThread(LPVOID Parameter)
{
    PCYCLE_WORK W = Parameter;
    HANDLE Acceptor = CreateThread(NULL, 0, AcceptThread, W, 0, NULL);
    int i, Timeout = IO_TIMEOUT_MS;

    if (!Acceptor)
    {
        Fail(W, "CreateThread");
        return 0;
    }

    for (i = 0; i < CYCLES_PER_THREAD; i++)
    {
        SOCKET c = socket(AF_INET, SOCK_STREAM, 0);
        char Out[4], In[4];
        struct linger Linger = { 1, 0 };
        int Mode = i % 3;

        if (c == INVALID_SOCKET)
        {
            Fail(W, "socket");
            break;
        }
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
        if (connect(c, (const struct sockaddr *)&W->Addr, sizeof(W->Addr)) != 0)
        {
            Fail(W, "connect");
            closesocket(c);
            continue;
        }
        memcpy(Out, &i, sizeof(Out));
        if (send(c, Out, sizeof(Out), 0) != sizeof(Out))
            Fail(W, "client send");
        else if (!RecvAll(c, In, sizeof(In)) || memcmp(In, Out, sizeof(In)))
            Fail(W, "client recv");

        /* graceful with shutdown, plain close, abortive close */
        if (Mode == 0)
            shutdown(c, SD_SEND);
        else if (Mode == 2)
            setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&Linger, sizeof(Linger));
        if (closesocket(c) != 0)
            Fail(W, "closesocket");
        W->Done++;
    }

    if (WaitForSingleObject(Acceptor, IO_TIMEOUT_MS * 3) != WAIT_OBJECT_0)
        Fail(W, "acceptor did not finish");
    CloseHandle(Acceptor);
    return 0;
}

static
void
TestDefaults(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    int Value = 0, Len = sizeof(Value);

    ok(s != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;

    /* a stream socket reads SO_RCVBUF as 64K until it is set, and SO_SNDBUF as a window size */
    ok(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&Value, &Len) == 0, "SO_RCVBUF: %d\n", WSAGetLastError());
    ok(Value == 0x10000, "Default SO_RCVBUF of a stream socket is %d, expected 65536\n", Value);
    Value = 0;
    Len = sizeof(Value);
    ok(getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&Value, &Len) == 0, "SO_SNDBUF: %d\n", WSAGetLastError());
    ok(Value > 0, "Default SO_SNDBUF of a stream socket is %d\n", Value);
    closesocket(s);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    ok(s != INVALID_SOCKET, "udp socket failed: %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;
    Value = 0;
    Len = sizeof(Value);
    ok(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&Value, &Len) == 0, "udp SO_RCVBUF: %d\n", WSAGetLastError());
    ok(Value > 0, "Default SO_RCVBUF of a datagram socket is %d\n", Value);
    closesocket(s);
}

START_TEST(connectcycle)
{
    WSADATA WsaData;
    HANDLE Threads[CYCLE_THREADS];
    ULONG i, Started = 0;
    DWORD Wait = WAIT_FAILED;
    LONG Done = 0;
    int Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    if (Error)
    {
        skip("WSAStartup failed: %d\n", Error);
        return;
    }

    TestDefaults();

    for (i = 0; i < CYCLE_THREADS; i++)
    {
        int Len = sizeof(Work[i].Addr);

        Work[i].Listener = socket(AF_INET, SOCK_STREAM, 0);
        ok(Work[i].Listener != INVALID_SOCKET, "listener: %d\n", WSAGetLastError());
        if (Work[i].Listener == INVALID_SOCKET)
            break;
        memset(&Work[i].Addr, 0, sizeof(Work[i].Addr));
        Work[i].Addr.sin_family = AF_INET;
        Work[i].Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ok(bind(Work[i].Listener, (struct sockaddr *)&Work[i].Addr, sizeof(Work[i].Addr)) == 0, "bind: %d\n", WSAGetLastError());
        ok(getsockname(Work[i].Listener, (struct sockaddr *)&Work[i].Addr, &Len) == 0, "getsockname: %d\n", WSAGetLastError());
        ok(listen(Work[i].Listener, 16) == 0, "listen: %d\n", WSAGetLastError());
        Threads[i] = CreateThread(NULL, 0, ClientThread, &Work[i], 0, NULL);
        ok(Threads[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!Threads[i])
            break;
        Started++;
    }

    if (Started)
    {
        Wait = WaitForMultipleObjects(Started, Threads, TRUE, 120 * 1000);
        ok(Wait == WAIT_OBJECT_0, "The threads did not finish: %lu\n", Wait);
    }

    /* Threads still running keep their sockets; the process exit ends them */
    if (Wait != WAIT_OBJECT_0)
        return;

    for (i = 0; i < Started; i++)
    {
        ok(Work[i].Failures == 0, "Thread %lu: %ld failures, last %s error %d\n",
           i, Work[i].Failures, Work[i].FailedCall ? Work[i].FailedCall : "-", Work[i].LastError);
        ok(Work[i].Done == CYCLES_PER_THREAD, "Thread %lu finished %ld of %d cycles\n", i, Work[i].Done, CYCLES_PER_THREAD);
        Done += Work[i].Done;
        closesocket(Work[i].Listener);
        CloseHandle(Threads[i]);
    }

    trace("%ld cycles in %lu threads\n", Done, Started);

    WSACleanup();
}
