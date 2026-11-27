/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A port held in TIME-WAIT towards one server must stay usable for a connect to another server,
 *              for IPv4 and IPv6 alike
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A connection is identified by its four values: a local port that is in TIME-WAIT towards one remote endpoint is free
 * for a connect to any other. Windows 10 22H2 (the row recorded in ephport.c, IPv4): a loop of connects to one loopback
 * listener succeeds 16382 times, and a connect to another listener meanwhile succeeds on those very ports.
 * IPv6: Windows row not recorded here (the rule has no address family in it): verify on the Windows reference
 * with this very test.
 *
 * The test fills the ports with TIME-WAITs of two servers in a way that leaves no port without one, then connects to
 * the first server again: ports exist that only the second server's TIME-WAITs hold, so every connect must succeed.
 */

#include "ws2_32.h"

#define FIRST_CONNECTS  12000
#define SECOND_CONNECTS 4000
#define THIRD_CONNECTS  1500

typedef struct
{
    SOCKET Socket;
    int Family;
    USHORT Port;
    volatile LONG Stop;
    volatile LONG Accepted;
    volatile USHORT PeerPort;   /* the remote port of the last accepted connection, host order */
} LISTENER;

static
void
FillAddress(int Family, USHORT Port, SOCKADDR_STORAGE *Addr, int *Length)
{
    ZeroMemory(Addr, sizeof(*Addr));
    if (Family == AF_INET6)
    {
        SOCKADDR_IN6 *Addr6 = (SOCKADDR_IN6 *)Addr;

        Addr6->sin6_family = AF_INET6;
        Addr6->sin6_port = htons(Port);
        Addr6->sin6_addr.u.Byte[15] = 1;
        *Length = sizeof(*Addr6);
    }
    else
    {
        SOCKADDR_IN *Addr4 = (SOCKADDR_IN *)Addr;

        Addr4->sin_family = AF_INET;
        Addr4->sin_port = htons(Port);
        Addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *Length = sizeof(*Addr4);
    }
}

static
DWORD
WINAPI
AcceptThread(LPVOID Context)
{
    LISTENER *Listener = Context;
    SOCKET Client;
    SOCKADDR_STORAGE Peer;
    int Length;
    char Byte;

    for (;;)
    {
        Length = sizeof(Peer);
        Client = accept(Listener->Socket, (SOCKADDR *)&Peer, &Length);
        if (Client == INVALID_SOCKET)
        {
            if (WSAGetLastError() == WSAECONNRESET && !Listener->Stop)
                continue;
            break;
        }
        Listener->PeerPort = ntohs(Peer.ss_family == AF_INET6 ? ((SOCKADDR_IN6 *)&Peer)->sin6_port :
                                                                 ((SOCKADDR_IN *)&Peer)->sin_port);
        InterlockedIncrement(&Listener->Accepted);
        /* The client closes first, so its end is the one that goes to TIME-WAIT */
        while (recv(Client, &Byte, 1, 0) > 0)
            ;
        closesocket(Client);
    }
    return 0;
}

static
HANDLE
StartListener(LISTENER *Listener, int Family)
{
    SOCKADDR_STORAGE Addr;
    int Length;

    ZeroMemory(Listener, sizeof(*Listener));
    Listener->Family = Family;
    Listener->Socket = socket(Family, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener->Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Listener->Socket == INVALID_SOCKET)
        return NULL;
    FillAddress(Family, 0, &Addr, &Length);
    ok(bind(Listener->Socket, (SOCKADDR *)&Addr, Length) == 0, "bind failed: %d\n", WSAGetLastError());
    ok(getsockname(Listener->Socket, (SOCKADDR *)&Addr, &Length) == 0, "getsockname failed: %d\n", WSAGetLastError());
    ok(listen(Listener->Socket, 512) == 0, "listen failed: %d\n", WSAGetLastError());
    Listener->Port = ntohs(Family == AF_INET6 ? ((SOCKADDR_IN6 *)&Addr)->sin6_port : ((SOCKADDR_IN *)&Addr)->sin_port);
    return CreateThread(NULL, 0, AcceptThread, Listener, 0, NULL);
}

static
void
StopListener(LISTENER *Listener, HANDLE Thread)
{
    Listener->Stop = 1;
    closesocket(Listener->Socket);
    if (Thread)
    {
        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
    }
}

/* One connect from an unbound socket, closed at once; 0 or the WSA error */
static
int
ConnectOnce(const LISTENER *To)
{
    SOCKADDR_STORAGE Addr;
    int Length, Error = 0;
    SOCKET Socket = socket(To->Family, SOCK_STREAM, IPPROTO_TCP);

    if (Socket == INVALID_SOCKET)
        return WSAGetLastError();
    FillAddress(To->Family, To->Port, &Addr, &Length);
    if (connect(Socket, (SOCKADDR *)&Addr, Length) != 0)
        Error = WSAGetLastError();
    closesocket(Socket);
    return Error;
}

/* A connect whose local port is checked: getsockname must name the port the server sees the connection come from,
   whether or not the stack had to take another port than the one it first gave the socket */
static
int
ConnectChecked(LISTENER *To)
{
    SOCKADDR_STORAGE Addr;
    int Length, Error = 0, i;
    LONG Before = To->Accepted;
    USHORT Local = 0;
    SOCKET Socket = socket(To->Family, SOCK_STREAM, IPPROTO_TCP);

    if (Socket == INVALID_SOCKET)
        return WSAGetLastError();
    FillAddress(To->Family, To->Port, &Addr, &Length);
    if (connect(Socket, (SOCKADDR *)&Addr, Length) != 0)
    {
        Error = WSAGetLastError();
        closesocket(Socket);
        return Error;
    }
    Length = sizeof(Addr);
    if (getsockname(Socket, (SOCKADDR *)&Addr, &Length) == 0)
        Local = ntohs(To->Family == AF_INET6 ? ((SOCKADDR_IN6 *)&Addr)->sin6_port : ((SOCKADDR_IN *)&Addr)->sin_port);
    for (i = 0; i < 100 && To->Accepted == Before; i++)
        Sleep(10);
    ok(To->Accepted != Before, "the server did not accept the connection\n");
    ok(Local != 0 && Local == To->PeerPort, "family %d: getsockname says local port %u, the server sees %u\n",
       To->Family, Local, To->PeerPort);
    closesocket(Socket);
    return 0;
}

/* Connects Count times; returns how many succeeded, the first error in *FirstError */
static
int
ConnectMany(const LISTENER *To, int Count, int *FirstError)
{
    int Ok = 0, Error, i;

    for (i = 0; i < Count; i++)
    {
        Error = ConnectOnce(To);
        if (Error)
        {
            if (!*FirstError)
                *FirstError = Error;
            continue;
        }
        Ok++;
    }
    return Ok;
}

static
void
TestFamily(int Family)
{
    LISTENER First, Second;
    HANDLE FirstThread, SecondThread;
    int Error = 0, Ok, Result, i;

    FirstThread = StartListener(&First, Family);
    SecondThread = StartListener(&Second, Family);
    if (!FirstThread || !SecondThread)
    {
        StopListener(&First, FirstThread);
        StopListener(&Second, SecondThread);
        return;
    }

    Ok = ConnectMany(&First, FIRST_CONNECTS, &Error);
    ok(Ok == FIRST_CONNECTS, "family %d: %d of %d connects to the first server succeeded (error %d)\n",
       Family, Ok, FIRST_CONNECTS, Error);

    Error = 0;
    Ok = ConnectMany(&Second, SECOND_CONNECTS, &Error);
    ok(Ok == SECOND_CONNECTS, "family %d: %d of %d connects to the second server succeeded (error %d)\n",
       Family, Ok, SECOND_CONNECTS, Error);

    /* Every port has a TIME-WAIT now, those of the first server are about 12000 of 16384: a port that holds only the
       second server's is free for the first server */
    Error = 0;
    Ok = 0;
    for (i = 0; i < 50; i++)
    {
        Result = ConnectChecked(&First);
        if (Result)
            Error = Error ? Error : Result;
        else
            Ok++;
    }
    Ok += ConnectMany(&First, THIRD_CONNECTS - 50, &Error);
    ok(Ok == THIRD_CONNECTS, "family %d: %d of %d connects to the first server again succeeded (error %d)\n",
       Family, Ok, THIRD_CONNECTS, Error);

    StopListener(&First, FirstThread);
    StopListener(&Second, SecondThread);
}

START_TEST(ephportremote)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    TestFamily(AF_INET);

    if (Ipv6SocketsOn())
        TestFamily(AF_INET6);
    else
        skip("the stack has no IPv6 sockets (state 0x%lx)\n", Ipv6StackFlags());

    WSACleanup();
}
