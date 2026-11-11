/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the listen backlog
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"
#include <mswsock.h>
#include <ndk/exfuncs.h>
#include <ndk/ketypes.h>

#define MAX_CLIENTS 300

/* Windows Server 2008 R2 and Windows 10 queue at most 200 connections for
 * a larger backlog, SOMAXCONN included */
#define MAX_BACKLOG 200

enum { CLIENT_PENDING, CLIENT_CONNECTED, CLIENT_FAILED };

/* On 64-bit ReactOS msafd returns a failed accept as a 32-bit SOCKET_ERROR
 * (0xFFFFFFFF, no valid handle has that value) and ws2_32 then sets no
 * error code */
static BOOL TruncatedAcceptError;

static SOCKET
Checked(SOCKET Socket)
{
    TruncatedAcceptError = sizeof(SOCKET) != sizeof(ULONG) && Socket == (SOCKET)(ULONG)SOCKET_ERROR;
    return TruncatedAcceptError ? INVALID_SOCKET : Socket;
}

/* Connect one more client and accept it on the nonblocking listener */
static BOOL
ConnectAndAccept(SOCKET Server, const struct sockaddr_in *Addr)
{
    SOCKET Client, Accepted = INVALID_SOCKET;
    DWORD Start;

    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client == INVALID_SOCKET)
        return FALSE;
    if (connect(Client, (const struct sockaddr *)Addr, sizeof(*Addr)) == 0)
    {
        Start = GetTickCount();
        do
        {
            Accepted = Checked(accept(Server, NULL, NULL));
            if (Accepted != INVALID_SOCKET ||
                (WSAGetLastError() != WSAEWOULDBLOCK && !TruncatedAcceptError))
                break;
            Sleep(50);
        } while (GetTickCount() - Start < 5000);
    }
    closesocket(Client);
    if (Accepted == INVALID_SOCKET)
        return FALSE;
    closesocket(Accepted);
    return TRUE;
}

static BOOL
WaitReadable(SOCKET Socket, DWORD Milliseconds)
{
    fd_set ReadSet;
    struct timeval Timeout;

    Timeout.tv_sec = Milliseconds / 1000;
    Timeout.tv_usec = (Milliseconds % 1000) * 1000;
    FD_ZERO(&ReadSet);
    FD_SET(Socket, &ReadSet);
    return select(0, &ReadSet, NULL, NULL, &Timeout) == 1;
}

/* A connected socket whose peer has not reset or closed it */
static BOOL
IsAlive(SOCKET Socket)
{
    u_long NonBlocking = 1, Blocking = 0;
    char Byte;
    BOOL Alive;

    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    Alive = recv(Socket, &Byte, 1, 0) == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK;
    ioctlsocket(Socket, FIONBIO, &Blocking);
    return Alive;
}

/* Connect clients until the listener queues one and accept it. Accept is
 * called only when select reports a connection, so a listener that stopped
 * listening gets no help from it. Each refused or reset client is retried,
 * since a connection may also arrive between two listens. */
static BOOL
ConnectAndAcceptRetry(SOCKET Server, const struct sockaddr_in *Addr, int Tries)
{
    SOCKET Client, Accepted;
    int i;

    for (i = 0; i < Tries; i++)
    {
        Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Client == INVALID_SOCKET)
            return FALSE;
        if (connect(Client, (const struct sockaddr *)Addr, sizeof(*Addr)) == 0 &&
            WaitReadable(Server, 1000))
        {
            Accepted = Checked(accept(Server, NULL, NULL));
            if (Accepted != INVALID_SOCKET)
            {
                closesocket(Accepted);
                closesocket(Client);
                return TRUE;
            }
        }
        closesocket(Client);
        Sleep(100);
    }
    return FALSE;
}

/* Bind a listener to the loopback address, with a given port or any */
static SOCKET
Listen(int Backlog, USHORT Port, struct sockaddr_in *Addr)
{
    SOCKET Server;
    int AddrLen = sizeof(*Addr);

    Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Server != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Server == INVALID_SOCKET)
        return INVALID_SOCKET;

    ZeroMemory(Addr, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Addr->sin_port = htons(Port);
    if (bind(Server, (struct sockaddr *)Addr, sizeof(*Addr)) != 0 ||
        getsockname(Server, (struct sockaddr *)Addr, &AddrLen) != 0 ||
        listen(Server, Backlog) != 0)
    {
        skip("Cannot listen on port %u: %d\n", Port, WSAGetLastError());
        closesocket(Server);
        return INVALID_SOCKET;
    }
    return Server;
}

/* Connect a client. A listener without room for it does not answer, and the connect fails with
 * WSAECONNREFUSED about two seconds later, as on Windows; the test gives up on it after one second */
static SOCKET
Connect(const struct sockaddr_in *Addr)
{
    SOCKET Client;
    u_long Mode = 1;
    fd_set WriteSet, ExceptSet;
    struct timeval Timeout = { 1, 0 };

    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client == INVALID_SOCKET)
        return INVALID_SOCKET;
    ioctlsocket(Client, FIONBIO, &Mode);
    if (connect(Client, (const struct sockaddr *)Addr, sizeof(*Addr)) != 0)
    {
        FD_ZERO(&WriteSet);
        FD_ZERO(&ExceptSet);
        FD_SET(Client, &WriteSet);
        FD_SET(Client, &ExceptSet);
        if (WSAGetLastError() != WSAEWOULDBLOCK ||
            select(0, NULL, &WriteSet, &ExceptSet, &Timeout) != 1 || !FD_ISSET(Client, &WriteSet))
        {
            closesocket(Client);
            return INVALID_SOCKET;
        }
    }
    Mode = 0;
    ioctlsocket(Client, FIONBIO, &Mode);
    return Client;
}

/* Connect clients until one stays connected, which only a listener that
 * listens or queues it allows */
static SOCKET
ConnectAlive(const struct sockaddr_in *Addr, int Tries)
{
    SOCKET Client;
    int i;

    for (i = 0; i < Tries; i++)
    {
        Client = Connect(Addr);
        if (Client != INVALID_SOCKET)
        {
            Sleep(300);
            if (IsAlive(Client))
                return Client;
            closesocket(Client);
        }
        Sleep(100);
    }
    return INVALID_SOCKET;
}

/* Connect Count nonblocking clients to a listener that does not accept while
 * they connect, then count the connections that are still alive and the
 * ones the listener accepts afterwards. Connections beyond the backlog are
 * refused or reset. Windows 10 sometimes queues more than a small backlog
 * (up to 25 for a backlog of 5 in our runs), so only ReactOS is held to the
 * exact limit. */
static void
TestBacklog(int Backlog, int Count)
{
    SOCKET Server, Accepted, Clients[MAX_CLIENTS];
    int State[MAX_CLIENTS];
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr);
    u_long NonBlocking = 1;
    int i, Error, Alive = 0, Failed = 0, Pending, AcceptCount = 0;
    int Limit = (Backlog > MAX_BACKLOG) ? MAX_BACKLOG : Backlog;
    DWORD Start;
    char Byte;
    fd_set WriteSet, ExceptSet;
    struct timeval Zero = { 0, 0 };

    ok(Count <= MAX_CLIENTS, "Count %d\n", Count);
    if (Count > MAX_CLIENTS)
        return;

    Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Server != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Server == INVALID_SOCKET)
        return;

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Error = bind(Server, (struct sockaddr *)&Addr, sizeof(Addr));
    ok(Error == 0, "bind failed: %d\n", WSAGetLastError());
    Error = getsockname(Server, (struct sockaddr *)&Addr, &AddrLen);
    ok(Error == 0, "getsockname failed: %d\n", WSAGetLastError());
    Error = listen(Server, Backlog);
    ok(Error == 0, "listen failed: %d\n", WSAGetLastError());
    Error = ioctlsocket(Server, FIONBIO, &NonBlocking);
    ok(Error == 0, "ioctlsocket failed: %d\n", WSAGetLastError());

    for (i = 0; i < Count; i++)
    {
        State[i] = CLIENT_FAILED;
        Clients[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Clients[i] == INVALID_SOCKET)
            continue;
        ioctlsocket(Clients[i], FIONBIO, &NonBlocking);
        Error = connect(Clients[i], (struct sockaddr *)&Addr, sizeof(Addr));
        if (Error == 0)
            State[i] = CLIENT_CONNECTED;
        else if (WSAGetLastError() == WSAEWOULDBLOCK)
            State[i] = CLIENT_PENDING;
    }

    /* A refused connect may be retried for a few seconds */
    Start = GetTickCount();
    do
    {
        Pending = 0;
        for (i = 0; i < Count; i++)
        {
            if (State[i] != CLIENT_PENDING)
                continue;
            FD_ZERO(&WriteSet);
            FD_ZERO(&ExceptSet);
            FD_SET(Clients[i], &WriteSet);
            FD_SET(Clients[i], &ExceptSet);
            if (select(0, NULL, &WriteSet, &ExceptSet, &Zero) > 0)
                State[i] = FD_ISSET(Clients[i], &ExceptSet) ? CLIENT_FAILED : CLIENT_CONNECTED;
            else
                Pending++;
        }
        if (Pending)
            Sleep(100);
    } while (Pending && GetTickCount() - Start < 30000);

    /* A connection the listener had no room for may also be reset */
    Sleep(1000);
    for (i = 0; i < Count; i++)
    {
        if (State[i] == CLIENT_CONNECTED &&
            recv(Clients[i], &Byte, 1, 0) == SOCKET_ERROR &&
            WSAGetLastError() == WSAEWOULDBLOCK)
        {
            Alive++;
        }
        else if (State[i] != CLIENT_PENDING)
        {
            Failed++;
        }
    }

    for (i = 0; i <= Count; i++)
    {
        Accepted = Checked(accept(Server, NULL, NULL));
        if (Accepted == INVALID_SOCKET)
            break;
        AcceptCount++;
        closesocket(Accepted);
    }
    ok(WSAGetLastError() == WSAEWOULDBLOCK || TruncatedAcceptError, "accept failed: %d\n", WSAGetLastError());

    trace("Backlog %d, %d clients: %d alive, %d failed, %d pending, %d accepted\n",
          Backlog, Count, Alive, Failed, Pending, AcceptCount);
    ok(Pending == 0, "Backlog %d: %d connects still pending\n", Backlog, Pending);
    if (Count > Limit)
    {
        ok(Alive >= Limit && Alive < Count,
           "Backlog %d, %d clients: %d connections alive\n", Backlog, Count, Alive);
        if (is_reactos())
        {
            ok(Alive <= Limit,
               "Backlog %d, %d clients: %d connections alive\n", Backlog, Count, Alive);
        }
    }
    else
    {
        ok(Alive == Count, "Backlog %d, %d clients: %d connections alive\n", Backlog, Count, Alive);
    }
    ok(AcceptCount == Alive, "Backlog %d: %d accepted, %d alive\n", Backlog, AcceptCount, Alive);

    /* With the queue drained, the listener takes new connections again */
    ok(ConnectAndAccept(Server, &Addr), "Backlog %d: no connection after the queue was drained\n", Backlog);

    for (i = 0; i < Count; i++)
    {
        if (Clients[i] != INVALID_SOCKET)
            closesocket(Clients[i]);
    }
    closesocket(Server);
}

static LPFN_ACCEPTEX
GetAcceptEx(SOCKET Server)
{
    LPFN_ACCEPTEX pAcceptEx = NULL;
    GUID AcceptExGuid = WSAID_ACCEPTEX;
    DWORD Bytes = 0;

    if (WSAIoctl(Server, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptExGuid, sizeof(AcceptExGuid),
                 &pAcceptEx, sizeof(pAcceptEx), &Bytes, NULL, NULL) != 0)
        return NULL;
    return pAcceptEx;
}

typedef struct _ACCEPT_REQUEST
{
    SOCKET Socket;
    OVERLAPPED Overlapped;
    char Buffer[2 * (sizeof(struct sockaddr_in) + 16)];
    BOOL Pending;
} ACCEPT_REQUEST, *PACCEPT_REQUEST;

static BOOL
PostAcceptEx(LPFN_ACCEPTEX pAcceptEx, SOCKET Server, PACCEPT_REQUEST Request)
{
    DWORD Bytes = 0;

    ZeroMemory(Request, sizeof(*Request));
    Request->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Request->Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (Request->Socket == INVALID_SOCKET || !Request->Overlapped.hEvent)
        return FALSE;
    if (pAcceptEx(Server, Request->Socket, Request->Buffer, 0,
                  sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
                  &Bytes, &Request->Overlapped) ||
        WSAGetLastError() == ERROR_IO_PENDING)
    {
        Request->Pending = TRUE;
    }
    return Request->Pending;
}

/* TRUE when the request completed with a connection */
static BOOL
AcceptExDone(SOCKET Server, PACCEPT_REQUEST Request, DWORD Milliseconds)
{
    DWORD Bytes, Flags;

    if (!Request->Pending ||
        WaitForSingleObject(Request->Overlapped.hEvent, Milliseconds) != WAIT_OBJECT_0)
        return FALSE;
    return WSAGetOverlappedResult(Server, &Request->Overlapped, &Bytes, FALSE, &Flags);
}

/* Call after the listener is closed, which cancels a pending request */
static void
FreeAcceptEx(PACCEPT_REQUEST Request)
{
    if (Request->Pending)
        WaitForSingleObject(Request->Overlapped.hEvent, 5000);
    if (Request->Overlapped.hEvent)
        CloseHandle(Request->Overlapped.hEvent);
    if (Request->Socket != INVALID_SOCKET)
        closesocket(Request->Socket);
}

static USHORT
LocalPort(SOCKET Socket)
{
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr);

    if (getsockname(Socket, (struct sockaddr *)&Addr, &AddrLen) != 0)
        return 0;
    return Addr.sin_port;
}

static USHORT
PeerPort(SOCKET Server, SOCKET Accepted)
{
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr);

    setsockopt(Accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&Server, sizeof(Server));
    if (getpeername(Accepted, (struct sockaddr *)&Addr, &AddrLen) != 0)
        return 0;
    return Addr.sin_port;
}

/* Two AcceptEx requests posted while the queue is full take the queued
 * connection and the next one, in order. Neither may wait for good. */
static void
TestAcceptExFullBacklog(void)
{
    SOCKET Server, Clients[2] = { INVALID_SOCKET, INVALID_SOCKET };
    struct sockaddr_in Addr;
    LPFN_ACCEPTEX pAcceptEx;
    ACCEPT_REQUEST Requests[2];
    int i;

    Server = Listen(1, 0, &Addr);
    if (Server == INVALID_SOCKET)
        return;
    ZeroMemory(Requests, sizeof(Requests));
    Requests[0].Socket = Requests[1].Socket = INVALID_SOCKET;
    pAcceptEx = GetAcceptEx(Server);
    if (!pAcceptEx)
    {
        skip("No AcceptEx: %d\n", WSAGetLastError());
        goto Cleanup;
    }

    /* Fill the queue: the listener reports the connection once it is queued */
    Clients[0] = Connect(&Addr);
    ok(Clients[0] != INVALID_SOCKET, "connect failed: %d\n", WSAGetLastError());
    ok(WaitReadable(Server, 5000), "the first connection was not queued\n");

    for (i = 0; i < 2; i++)
        ok(PostAcceptEx(pAcceptEx, Server, &Requests[i]), "AcceptEx %d failed: %d\n", i, WSAGetLastError());

    /* The first request takes the queued connection */
    ok(AcceptExDone(Server, &Requests[0], 5000), "AcceptEx 0 did not complete\n");
    ok(!AcceptExDone(Server, &Requests[1], 0), "AcceptEx 1 completed without a connection\n");

    /* The second one takes the next connection; a client that arrives
     * between two listens is reset, so try a few */
    for (i = 0; i < 10 && !AcceptExDone(Server, &Requests[1], 0); i++)
    {
        if (Clients[1] != INVALID_SOCKET)
            closesocket(Clients[1]);
        Clients[1] = Connect(&Addr);
        AcceptExDone(Server, &Requests[1], 1000);
    }
    ok(AcceptExDone(Server, &Requests[1], 0), "AcceptEx 1 did not complete\n");

    for (i = 0; i < 2; i++)
    {
        if (Clients[i] != INVALID_SOCKET && AcceptExDone(Server, &Requests[i], 0))
        {
            ok(PeerPort(Server, Requests[i].Socket) == LocalPort(Clients[i]),
               "AcceptEx %d took port %u, client %d has %u\n", i,
               ntohs(PeerPort(Server, Requests[i].Socket)), i, ntohs(LocalPort(Clients[i])));
        }
    }

Cleanup:
    closesocket(Server);
    for (i = 0; i < 2; i++)
    {
        FreeAcceptEx(&Requests[i]);
        if (Clients[i] != INVALID_SOCKET)
            closesocket(Clients[i]);
    }
}

typedef struct _ACCEPT_THREAD
{
    SOCKET Server;
    HANDLE Release;
    LONG *Offered;
    BOOL HoldExpired;
    SOCKET Accepted;
    int Error;
} ACCEPT_THREAD, *PACCEPT_THREAD;

/* Holds the offered connection unaccepted until the test releases it */
static int CALLBACK
HoldCondition(LPWSABUF CallerId, LPWSABUF CallerData, LPQOS Sqos, LPQOS Gqos,
              LPWSABUF CalleeId, LPWSABUF CalleeData, GROUP *Group, DWORD_PTR Context)
{
    PACCEPT_THREAD Thread = (PACCEPT_THREAD)Context;

    InterlockedIncrement(Thread->Offered);
    Thread->HoldExpired = WaitForSingleObject(Thread->Release, 120000) != WAIT_OBJECT_0;
    return CF_ACCEPT;
}

static DWORD WINAPI
AcceptThread(LPVOID Parameter)
{
    PACCEPT_THREAD Thread = Parameter;

    Thread->Accepted = Checked(WSAAccept(Thread->Server, NULL, NULL, HoldCondition, (DWORD_PTR)Thread));
    Thread->Error = (Thread->Accepted == INVALID_SOCKET) ? WSAGetLastError() : 0;
    return 0;
}

/* TRUE when the thread of this process is in a wait */
static BOOL
ThreadWaits(DWORD ThreadId)
{
    PSYSTEM_PROCESS_INFORMATION Process;
    PSYSTEM_THREAD_INFORMATION Threads;
    ULONG Size = 0x40000, i;
    PVOID Buffer;
    NTSTATUS Status;
    BOOL Waits = FALSE;

    for (;;)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Buffer)
            return FALSE;
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, NULL);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, Buffer);
        Size *= 2;
    }

    for (Process = Buffer; NT_SUCCESS(Status); )
    {
        if (HandleToUlong(Process->UniqueProcessId) == GetCurrentProcessId())
        {
            Threads = (PSYSTEM_THREAD_INFORMATION)(Process + 1);
            for (i = 0; i < Process->NumberOfThreads; i++)
            {
                if (HandleToUlong(Threads[i].ClientId.UniqueThread) == ThreadId)
                    Waits = (Threads[i].ThreadState == Waiting);
            }
            break;
        }
        if (!Process->NextEntryOffset)
            break;
        Process = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)Process + Process->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    return Waits;
}

/* Wait until both threads wait in a row of samples: a thread in WSAAccept
 * waits only once its request for a connection is pending in AFD */
static BOOL
ThreadsWait(const DWORD *ThreadIds)
{
    int i, InRow = 0;

    for (i = 0; i < 100 && InRow < 3; i++)
    {
        InRow = (ThreadWaits(ThreadIds[0]) && ThreadWaits(ThreadIds[1])) ? InRow + 1 : 0;
        Sleep(50);
    }
    return InRow == 3;
}

#define MIXED_CLIENTS 8

/* Two threads wait in WSAAccept and hold the connection they are offered,
 * and an AcceptEx request waits too. Offered connections stay queued until
 * they are accepted, so with a backlog of one, only the connection held by
 * the first thread and the one the AcceptEx request takes stay alive.
 * Afterwards every request completes. */
static void
TestMixedAccept(void)
{
    SOCKET Server, Clients[MIXED_CLIENTS], Extra[16];
    struct sockaddr_in Addr;
    LPFN_ACCEPTEX pAcceptEx;
    ACCEPT_REQUEST Request;
    ACCEPT_THREAD Threads[2];
    HANDLE ThreadHandles[2] = { NULL, NULL }, Waits[3], Release;
    DWORD ThreadIds[2];
    LONG Offered = 0;
    int i, Alive = 0, Done, Extras = 0;
    BOOL RequestDone;

    for (i = 0; i < MIXED_CLIENTS; i++)
        Clients[i] = INVALID_SOCKET;
    ZeroMemory(&Request, sizeof(Request));
    Request.Socket = INVALID_SOCKET;

    Server = Listen(1, 0, &Addr);
    if (Server == INVALID_SOCKET)
        return;
    Release = CreateEventW(NULL, TRUE, FALSE, NULL);
    pAcceptEx = GetAcceptEx(Server);
    if (!pAcceptEx || !Release)
    {
        skip("No AcceptEx or event: %d\n", WSAGetLastError());
        goto Cleanup;
    }

    for (i = 0; i < 2; i++)
    {
        Threads[i].Server = Server;
        Threads[i].Release = Release;
        Threads[i].Offered = &Offered;
        Threads[i].Accepted = INVALID_SOCKET;
        Threads[i].HoldExpired = FALSE;
        Threads[i].Error = 0;
        ThreadHandles[i] = CreateThread(NULL, 0, AcceptThread, &Threads[i], 0, &ThreadIds[i]);
        ok(ThreadHandles[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!ThreadHandles[i])
            goto Cleanup;
    }

    /* Both threads wait before the AcceptEx request does */
    ok(ThreadsWait(ThreadIds), "Mixed accept: the threads do not wait in WSAAccept\n");
    ok(PostAcceptEx(pAcceptEx, Server, &Request), "AcceptEx failed: %d\n", WSAGetLastError());

    for (i = 0; i < MIXED_CLIENTS; i++)
        Clients[i] = Connect(&Addr);

    /* A connection the listener had no room for may also be reset */
    Sleep(1000);
    for (i = 0; i < MIXED_CLIENTS; i++)
    {
        if (Clients[i] != INVALID_SOCKET && IsAlive(Clients[i]))
            Alive++;
    }
    RequestDone = AcceptExDone(Server, &Request, 0);
    trace("Mixed accept: %d clients alive, %ld offered, AcceptEx %s\n",
          Alive, Offered, RequestDone ? "done" : "waiting");
    ok(Alive >= 1, "Mixed accept: no connection alive\n");
    ok(Offered >= 1, "Mixed accept: no connection offered to a waiting thread\n");
    if (is_reactos())
    {
        ok(Alive <= 1 + RequestDone, "Mixed accept: %d connections alive, AcceptEx %s\n",
           Alive, RequestDone ? "done" : "waiting");

        /* The first thread holds the first connection; the full queue takes
         * no other, so neither the second thread nor AcceptEx gets one */
        ok(Offered == 1 && !RequestDone, "Mixed accept: %ld offered, AcceptEx %s\n",
           Offered, RequestDone ? "done" : "waiting");
    }

    /* Let the threads accept, and connect until every request has a connection */
    SetEvent(Release);
    for (i = 0; i < 16; i++)
    {
        Done = 0;
        if (WaitForSingleObject(ThreadHandles[0], 0) != WAIT_OBJECT_0)
            Waits[Done++] = ThreadHandles[0];
        if (WaitForSingleObject(ThreadHandles[1], 0) != WAIT_OBJECT_0)
            Waits[Done++] = ThreadHandles[1];
        if (WaitForSingleObject(Request.Overlapped.hEvent, 0) != WAIT_OBJECT_0)
            Waits[Done++] = Request.Overlapped.hEvent;
        if (!Done)
            break;
        Extra[Extras] = Connect(&Addr);
        if (Extra[Extras] != INVALID_SOCKET)
            Extras++;
        WaitForMultipleObjects(Done, Waits, FALSE, 1000);
    }
    ok(AcceptExDone(Server, &Request, 0), "Mixed accept: AcceptEx did not complete\n");
    for (i = 0; i < 2; i++)
    {
        ok(WaitForSingleObject(ThreadHandles[i], 0) == WAIT_OBJECT_0, "Mixed accept: thread %d still waits\n", i);
        ok(Threads[i].Accepted != INVALID_SOCKET, "Mixed accept: thread %d failed: %d\n", i, Threads[i].Error);
        ok(!Threads[i].HoldExpired, "Mixed accept: thread %d held its connection too long\n", i);
    }

Cleanup:
    if (Release)
        SetEvent(Release);
    closesocket(Server);
    for (i = 0; i < 2; i++)
    {
        if (!ThreadHandles[i])
            continue;
        ok(WaitForSingleObject(ThreadHandles[i], 10000) == WAIT_OBJECT_0, "Mixed accept: thread %d hangs\n", i);
        CloseHandle(ThreadHandles[i]);
        if (Threads[i].Accepted != INVALID_SOCKET)
            closesocket(Threads[i].Accepted);
    }
    FreeAcceptEx(&Request);
    for (i = 0; i < MIXED_CLIENTS; i++)
    {
        if (Clients[i] != INVALID_SOCKET)
            closesocket(Clients[i]);
    }
    for (i = 0; i < Extras; i++)
        closesocket(Extra[i]);
    if (Release)
        CloseHandle(Release);
}

static DWORD WINAPI
AcceptOnceThread(LPVOID Parameter)
{
    SOCKET *Socket = Parameter;

    *Socket = Checked(accept(*Socket, NULL, NULL));
    return 0;
}

typedef struct _LISTEN_THREAD
{
    struct sockaddr_in Addr;
    SOCKET Server;
} LISTEN_THREAD, *PLISTEN_THREAD;

static DWORD WINAPI
ListenThread(LPVOID Parameter)
{
    PLISTEN_THREAD Listener = Parameter;

    Listener->Server = Listen(1, 0, &Listener->Addr);
    return 0;
}

/* A thread that accepts from a full queue, or that calls listen, and then
 * exits must not stop the listener */
static void
TestThreadExit(void)
{
    SOCKET Server, Client, Accepted;
    struct sockaddr_in Addr;
    LISTEN_THREAD Listener;
    HANDLE Thread;

    Server = Listen(1, 0, &Addr);
    if (Server == INVALID_SOCKET)
        return;
    Client = Connect(&Addr);
    ok(Client != INVALID_SOCKET, "connect failed: %d\n", WSAGetLastError());
    ok(WaitReadable(Server, 5000), "the connection was not queued\n");

    Accepted = Server;
    Thread = CreateThread(NULL, 0, AcceptOnceThread, &Accepted, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (Thread)
    {
        ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "accept hangs\n");
        CloseHandle(Thread);
        ok(Accepted != INVALID_SOCKET && Accepted != Server, "accept failed\n");
        if (Accepted != INVALID_SOCKET && Accepted != Server)
            closesocket(Accepted);
        ok(ConnectAndAcceptRetry(Server, &Addr, 10), "no connection after the accepting thread exited\n");
    }
    if (Client != INVALID_SOCKET)
        closesocket(Client);
    closesocket(Server);

    Listener.Server = INVALID_SOCKET;
    Thread = CreateThread(NULL, 0, ListenThread, &Listener, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
        return;
    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0, "listen hangs\n");
    CloseHandle(Thread);
    if (Listener.Server == INVALID_SOCKET)
        return;
    ok(ConnectAndAcceptRetry(Listener.Server, &Listener.Addr, 10), "no connection after the listening thread exited\n");
    closesocket(Listener.Server);
}

typedef struct _ACCEPTEX_THREAD
{
    SOCKET Server;
    LPFN_ACCEPTEX pAcceptEx;
    ACCEPT_REQUEST Request;
    BOOL Done;
} ACCEPTEX_THREAD, *PACCEPTEX_THREAD;

static DWORD WINAPI
AcceptExThread(LPVOID Parameter)
{
    PACCEPTEX_THREAD Thread = Parameter;

    if (PostAcceptEx(Thread->pAcceptEx, Thread->Server, &Thread->Request))
        Thread->Done = AcceptExDone(Thread->Server, &Thread->Request, 5000);
    return 0;
}

/* A thread posts AcceptEx for a queued connection, gets it and exits; the
 * accepted socket must still receive what the client sends afterwards */
static void
TestAcceptExThreadExit(void)
{
    SOCKET Server, Client = INVALID_SOCKET;
    struct sockaddr_in Addr;
    ACCEPTEX_THREAD Thread;
    HANDLE Handle;
    char Byte = 'x';

    ZeroMemory(&Thread, sizeof(Thread));
    Thread.Request.Socket = INVALID_SOCKET;
    Server = Listen(1, 0, &Addr);
    if (Server == INVALID_SOCKET)
        return;
    Thread.Server = Server;
    Thread.pAcceptEx = GetAcceptEx(Server);
    if (!Thread.pAcceptEx)
    {
        skip("No AcceptEx: %d\n", WSAGetLastError());
        goto Cleanup;
    }

    Client = Connect(&Addr);
    ok(Client != INVALID_SOCKET, "connect failed: %d\n", WSAGetLastError());
    ok(WaitReadable(Server, 5000), "the connection was not queued\n");

    Handle = CreateThread(NULL, 0, AcceptExThread, &Thread, 0, NULL);
    ok(Handle != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Handle)
        goto Cleanup;
    ok(WaitForSingleObject(Handle, 10000) == WAIT_OBJECT_0, "the AcceptEx thread hangs\n");
    CloseHandle(Handle);
    ok(Thread.Done, "AcceptEx did not complete in its thread\n");

    if (Thread.Done && Client != INVALID_SOCKET)
    {
        setsockopt(Thread.Request.Socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&Server, sizeof(Server));
        ok(send(Client, &Byte, 1, 0) == 1, "send failed: %d\n", WSAGetLastError());
        Byte = 0;
        ok(WaitReadable(Thread.Request.Socket, 5000), "no data on the accepted socket\n");
        ok(recv(Thread.Request.Socket, &Byte, 1, 0) == 1 && Byte == 'x',
           "recv on the accepted socket: byte %d, error %d\n", Byte, WSAGetLastError());
    }

Cleanup:
    closesocket(Server);
    FreeAcceptEx(&Thread.Request);
    if (Client != INVALID_SOCKET)
        closesocket(Client);
}

/* Fault injection for a local build (not part of the change) makes the
 * listener on these ports fail one step; elsewhere the tests only check
 * the normal path:
 * - 47311: opening the second connection object for the listener fails
 * - 47312: tcpip fails the second listen request at once
 * - 47313: opening the third connection object fails */
#define PORT_OPEN_FAILS     47311
#define PORT_LISTEN_FAILS   47312
#define PORT_REPLACE_FAILS  47313

/* After a failure the listener listens again without help from accept */
static void
TestListenRecovery(USHORT Port, int Backlog)
{
    SOCKET Server, Client, Accepted, Second = INVALID_SOCKET;
    struct sockaddr_in Addr;

    Server = Listen(Backlog, Port, &Addr);
    if (Server == INVALID_SOCKET)
        return;

    Client = Connect(&Addr);
    ok(Client != INVALID_SOCKET, "Port %u: connect failed: %d\n", Port, WSAGetLastError());
    ok(WaitReadable(Server, 5000), "Port %u: the connection was not queued\n", Port);

    /* With room left, the listener listens again before anyone accepts */
    if (Backlog > 1)
    {
        Second = ConnectAlive(&Addr, 10);
        ok(Second != INVALID_SOCKET, "Port %u: the listener did not listen again before accept\n", Port);
    }

    Accepted = Checked(accept(Server, NULL, NULL));
    ok(Accepted != INVALID_SOCKET, "Port %u: accept failed: %d\n", Port, WSAGetLastError());

    ok(ConnectAndAcceptRetry(Server, &Addr, 10), "Port %u: the listener did not listen again\n", Port);

    if (Second != INVALID_SOCKET)
        closesocket(Second);

    if (Accepted != INVALID_SOCKET)
        closesocket(Accepted);
    if (Client != INVALID_SOCKET)
        closesocket(Client);
    closesocket(Server);
}

#define REPLACE_CLIENTS 4

/* Fill the queue, post an AcceptEx request and cancel it at once, then let
 * more clients arrive. Before this change a full queue with an AcceptEx
 * request outstanding listened anyway, and a connection that arrived after
 * the request was cancelled was closed and its connection object replaced.
 * The queue must stay within the backlog, the listener must take new
 * connections after the queue is drained, and closing it must not release
 * anything twice. */
static void
TestCancelAndReplace(USHORT Port, int Backlog)
{
    SOCKET Server, Clients[REPLACE_CLIENTS], Accepted;
    struct sockaddr_in Addr;
    LPFN_ACCEPTEX pAcceptEx;
    ACCEPT_REQUEST Request;
    int i, Alive = 0, Queued, Drained = 0;
    BOOL RequestDone;

    for (i = 0; i < REPLACE_CLIENTS; i++)
        Clients[i] = INVALID_SOCKET;
    ZeroMemory(&Request, sizeof(Request));
    Request.Socket = INVALID_SOCKET;

    Server = Listen(Backlog, Port, &Addr);
    if (Server == INVALID_SOCKET)
        return;
    pAcceptEx = GetAcceptEx(Server);
    if (!pAcceptEx)
    {
        skip("No AcceptEx: %d\n", WSAGetLastError());
        goto Cleanup;
    }

    for (Queued = 0; Queued < Backlog; Queued++)
    {
        Clients[Queued] = Connect(&Addr);
        ok(Clients[Queued] != INVALID_SOCKET, "Port %u: connect failed: %d\n", Port, WSAGetLastError());
    }
    ok(WaitReadable(Server, 5000), "Port %u: no connection queued\n", Port);

    /* Unaccepted clients stay connected only while queued: the queue is full */
    Sleep(300);
    for (i = 0; i < Backlog; i++)
        ok(Clients[i] != INVALID_SOCKET && IsAlive(Clients[i]), "Port %u: client %d is not queued\n", Port, i);

    ok(PostAcceptEx(pAcceptEx, Server, &Request), "Port %u: AcceptEx failed: %d\n", Port, WSAGetLastError());
    CancelIo((HANDLE)Server);
    if (Request.Pending)
        ok(WaitForSingleObject(Request.Overlapped.hEvent, 5000) == WAIT_OBJECT_0, "Port %u: AcceptEx still waits\n", Port);
    RequestDone = AcceptExDone(Server, &Request, 0);

    for (i = Backlog; i < REPLACE_CLIENTS; i++)
        Clients[i] = Connect(&Addr);

    Sleep(1000);
    for (i = 0; i < REPLACE_CLIENTS; i++)
    {
        if (Clients[i] != INVALID_SOCKET && IsAlive(Clients[i]))
            Alive++;
    }
    if (is_reactos())
    {
        ok(Alive <= Backlog + RequestDone, "Port %u: %d connections alive, backlog %d, AcceptEx %s\n",
           Port, Alive, Backlog, RequestDone ? "done" : "cancelled");
    }

    while (WaitReadable(Server, 200))
    {
        Accepted = Checked(accept(Server, NULL, NULL));
        if (Accepted == INVALID_SOCKET)
            break;
        Drained++;
        closesocket(Accepted);
    }
    ok(Drained + RequestDone >= 1, "Port %u: nothing was accepted\n", Port);
    ok(ConnectAndAcceptRetry(Server, &Addr, 10), "Port %u: no connection after the queue was drained\n", Port);

Cleanup:
    closesocket(Server);
    FreeAcceptEx(&Request);
    for (i = 0; i < REPLACE_CLIENTS; i++)
    {
        if (Clients[i] != INVALID_SOCKET)
            closesocket(Clients[i]);
    }
}

static BOOL
Startup(void)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return FALSE;
    }
    return TRUE;
}

START_TEST(backlog)
{
    int i;

    if (!Startup())
        return;

    TestBacklog(1, 16);
    TestBacklog(2, 32);
    TestBacklog(5, 48);
    TestBacklog(SOMAXCONN, 40);
    TestBacklog(SOMAXCONN, 300);
    TestAcceptExFullBacklog();
    TestMixedAccept();
    TestThreadExit();
    TestAcceptExThreadExit();
    for (i = 0; i < 10; i++)
        TestCancelAndReplace(0, 1 + i % 3);

    WSACleanup();
}

/* The fixed-port cases run one per process, so that a crash in one does not
 * hide the result of another */
START_TEST(backlog_open)
{
    if (!Startup())
        return;
    TestListenRecovery(PORT_OPEN_FAILS, 2);
    WSACleanup();
}

START_TEST(backlog_listen)
{
    if (!Startup())
        return;
    TestListenRecovery(PORT_LISTEN_FAILS, 1);
    WSACleanup();
}

START_TEST(backlog_replace)
{
    if (!Startup())
        return;
    TestCancelAndReplace(PORT_REPLACE_FAILS, 1);
    WSACleanup();
}
