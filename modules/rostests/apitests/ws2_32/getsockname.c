/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test getsockname on TCP sockets whose connect failed or is in progress
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

/* AFD used to free the getsockname buffer MDL a second time when the transport
 * query failed (a socket whose connect was refused, still pending or torn down),
 * after the transport request's completion had already freed it. The MDL then sat
 * on the lookaside list twice and two later I/O requests shared it, corrupting
 * page reference counts. Repeat the failing query many times, and keep checking
 * that loopback data still arrives intact so damage shows up inside the test. */

#define LOOPS 1000
#define BATCH 50
#define CHUNK 65536

static USHORT GetClosedPort(void)
{
    SOCKADDR_IN Address;
    int Length = sizeof(Address);
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    USHORT Port = 0;

    /* A port that was just bound and released has no listener */
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Socket != INVALID_SOCKET &&
        bind(Socket, (struct sockaddr *)&Address, sizeof(Address)) == 0 &&
        getsockname(Socket, (struct sockaddr *)&Address, &Length) == 0)
    {
        Port = ntohs(Address.sin_port);
    }
    if (Socket != INVALID_SOCKET)
        closesocket(Socket);
    return Port;
}

/* getsockname either reports an IPv4 address or fails with a socket error */
static void CheckQuery(SOCKET Socket, BOOL *Failed, const char *What)
{
    SOCKADDR_IN Address;
    int Length = sizeof(Address);
    int Result, Error;

    memset(&Address, 0x55, sizeof(Address));
    Result = getsockname(Socket, (struct sockaddr *)&Address, &Length);
    if (Result == 0)
    {
        if (Address.sin_family != AF_INET || Length != sizeof(Address))
        {
            ok(0, "%s: family %u length %d\n", What, Address.sin_family, Length);
            *Failed = TRUE;
        }
        return;
    }
    Error = WSAGetLastError();
    if (Result != SOCKET_ERROR || (Error != WSAEINVAL && Error != WSAENOTCONN))
    {
        ok(0, "%s: result %d error %d\n", What, Result, Error);
        *Failed = TRUE;
    }
}

/* After a refused connect the implicit local binding persists: Windows reports
 * the wildcard address with the automatically assigned port, and the same one
 * on every later call. A socket bound by the caller keeps its address. */
static void CheckKeptBinding(SOCKET Socket, ULONG Addr, USHORT *Port, BOOL *Failed, const char *What)
{
    SOCKADDR_IN Address;
    int Length = sizeof(Address);
    int Result;

    memset(&Address, 0x55, sizeof(Address));
    WSASetLastError(0);
    Result = getsockname(Socket, (struct sockaddr *)&Address, &Length);
    if (Result != 0)
    {
        ok(0, "%s: getsockname failed: result %d error %d\n", What, Result, WSAGetLastError());
        *Failed = TRUE;
        return;
    }
    if (Address.sin_family != AF_INET || Length != sizeof(Address) ||
        Address.sin_addr.s_addr != Addr || Address.sin_port == 0 ||
        (*Port != 0 && Address.sin_port != *Port))
    {
        ok(0, "%s: family %u length %d address %08lx port %u (expected address %08lx, port %u)\n",
           What, Address.sin_family, Length, Address.sin_addr.s_addr, ntohs(Address.sin_port),
           Addr, ntohs(*Port));
        *Failed = TRUE;
        return;
    }
    *Port = Address.sin_port;
}

static void TestRefusedConnect(USHORT ClosedPort)
{
    SOCKADDR_IN Address, Bound;
    SOCKET Socket;
    USHORT Port;
    BOOL Failed = FALSE;
    int Result;
    u_long NonBlocking = 1;
    fd_set Write, Except;
    struct timeval Timeout = { 5, 0 };

    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Address.sin_port = htons(ClosedPort);

    /* Blocking connect: refused, implicit binding kept */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET) return;
    Result = connect(Socket, (struct sockaddr *)&Address, sizeof(Address));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAECONNREFUSED,
       "blocking connect: result %d error %d\n", Result, WSAGetLastError());
    Port = 0;
    CheckKeptBinding(Socket, INADDR_ANY, &Port, &Failed, "blocking refused");
    CheckKeptBinding(Socket, INADDR_ANY, &Port, &Failed, "blocking refused, again");
    closesocket(Socket);

    /* Non-blocking connect: refused, implicit binding kept */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET) return;
    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    connect(Socket, (struct sockaddr *)&Address, sizeof(Address));
    FD_ZERO(&Write);
    FD_ZERO(&Except);
    FD_SET(Socket, &Write);
    FD_SET(Socket, &Except);
    Result = select(0, NULL, &Write, &Except, &Timeout);
    ok(Result == 1 && FD_ISSET(Socket, &Except), "select: %d\n", Result);
    Port = 0;
    CheckKeptBinding(Socket, INADDR_ANY, &Port, &Failed, "non-blocking refused");
    CheckKeptBinding(Socket, INADDR_ANY, &Port, &Failed, "non-blocking refused, again");
    closesocket(Socket);

    /* An explicit binding survives a refused connect unchanged */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET) return;
    ZeroMemory(&Bound, sizeof(Bound));
    Bound.sin_family = AF_INET;
    Bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Socket, (struct sockaddr *)&Bound, sizeof(Bound)) == 0, "bind failed: %d\n", WSAGetLastError());
    Port = 0;
    CheckKeptBinding(Socket, htonl(INADDR_LOOPBACK), &Port, &Failed, "bound before connect");
    Result = connect(Socket, (struct sockaddr *)&Address, sizeof(Address));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAECONNREFUSED,
       "bound connect: result %d error %d\n", Result, WSAGetLastError());
    CheckKeptBinding(Socket, htonl(INADDR_LOOPBACK), &Port, &Failed, "bound after refused");
    closesocket(Socket);
}

/* Push a patterned buffer through a loopback connection and compare it */
static BOOL CheckLoopbackData(SOCKET Listener, USHORT Port, PUCHAR Send, PUCHAR Receive, ULONG Seed)
{
    SOCKADDR_IN Address;
    SOCKET Client, Server;
    int Sent = 0, Got = 0, Result, i;
    BOOL Same;

    for (i = 0; i < CHUNK; i++)
        Send[i] = (UCHAR)(i * 7 + Seed);
    memset(Receive, 0, CHUNK);

    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client == INVALID_SOCKET)
        return FALSE;
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Address.sin_port = htons(Port);
    if (connect(Client, (struct sockaddr *)&Address, sizeof(Address)) != 0)
    {
        closesocket(Client);
        return FALSE;
    }
    Server = accept(Listener, NULL, NULL);
    if (Server == INVALID_SOCKET)
    {
        closesocket(Client);
        return FALSE;
    }
    while (Sent < CHUNK || Got < CHUNK)
    {
        if (Sent < CHUNK)
        {
            Result = send(Client, (char *)Send + Sent, min(CHUNK - Sent, 8192), 0);
            if (Result <= 0)
                break;
            Sent += Result;
        }
        if (Got < CHUNK)
        {
            Result = recv(Server, (char *)Receive + Got, CHUNK - Got, 0);
            if (Result <= 0)
                break;
            Got += Result;
        }
    }
    Same = (Got == CHUNK && memcmp(Send, Receive, CHUNK) == 0);
    closesocket(Server);
    closesocket(Client);
    return Same;
}

START_TEST(getsockname)
{
    WSADATA WsaData;
    SOCKADDR_IN Address;
    SOCKET Listener;
    USHORT ClosedPort, ListenPort;
    int Length, i;
    u_long NonBlocking = 1;
    BOOL Failed = FALSE, DataOk = TRUE;
    PUCHAR Send, Receive;

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");

    Send = HeapAlloc(GetProcessHeap(), 0, CHUNK);
    Receive = HeapAlloc(GetProcessHeap(), 0, CHUNK);
    if (!Send || !Receive)
    {
        skip("out of memory\n");
        return;
    }

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) == 0, "bind failed: %d\n", WSAGetLastError());
    ok(listen(Listener, 4) == 0, "listen failed: %d\n", WSAGetLastError());
    Length = sizeof(Address);
    ok(getsockname(Listener, (struct sockaddr *)&Address, &Length) == 0, "getsockname failed: %d\n", WSAGetLastError());
    ListenPort = ntohs(Address.sin_port);

    /* A connected socket reports its loopback address */
    ok(CheckLoopbackData(Listener, ListenPort, Send, Receive, 0), "loopback data mismatch before the loop\n");

    ClosedPort = GetClosedPort();
    ok(ClosedPort != 0, "no closed port\n");

    TestRefusedConnect(ClosedPort);

    /* A refused connect takes about 2 s, as on Windows (the SYN is sent again after each reset): the attempts run
       BATCH at a time, and each is given up to 5 s to fail */
    for (i = 0; i < LOOPS && !Failed && DataOk; i += BATCH)
    {
        SOCKET Batch[BATCH];
        int j, n = 0;

        for (j = 0; j < BATCH; j++)
        {
            Batch[j] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (Batch[j] == INVALID_SOCKET)
            {
                ok(0, "socket failed: %d\n", WSAGetLastError());
                break;
            }
            n++;
            ioctlsocket(Batch[j], FIONBIO, &NonBlocking);
            Address.sin_family = AF_INET;
            Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            Address.sin_port = htons(ClosedPort);
            connect(Batch[j], (struct sockaddr *)&Address, sizeof(Address));

            CheckQuery(Batch[j], &Failed, "connect in progress");
        }

        for (j = 0; j < n; j++)
        {
            fd_set Write, Except;
            struct timeval Timeout = { 5, 0 };
            USHORT KeptPort = 0;

            FD_ZERO(&Write);
            FD_ZERO(&Except);
            FD_SET(Batch[j], &Write);
            FD_SET(Batch[j], &Except);
            select(0, NULL, &Write, &Except, &Timeout);

            CheckKeptBinding(Batch[j], INADDR_ANY, &KeptPort, &Failed, "connect refused");
            CheckKeptBinding(Batch[j], INADDR_ANY, &KeptPort, &Failed, "connect refused, again");
            closesocket(Batch[j]);
        }
        if (n < BATCH)
            break;

        DataOk = CheckLoopbackData(Listener, ListenPort, Send, Receive, i);
    }
    ok(!Failed, "getsockname misbehaved at iteration %d\n", i);
    ok(DataOk, "loopback data mismatch at iteration %d\n", i);
    ok(CheckLoopbackData(Listener, ListenPort, Send, Receive, 0xA5), "loopback data mismatch after the loop\n");

    closesocket(Listener);
    HeapFree(GetProcessHeap(), 0, Send);
    HeapFree(GetProcessHeap(), 0, Receive);
    WSACleanup();
}
