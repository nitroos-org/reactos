/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     connect() on a stream socket that is connecting, connected, listening or whose connect failed.
 *              Qt asks a non-blocking socket whether it is connected by connecting it again and loops
 *              while it gets WSAEINVAL; Windows answers WSAEISCONN (connected) or WSAEALREADY (connecting)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <iphlpapi.h>

static
int
ConnectError(SOCKET Socket, const struct sockaddr_in *Address)
{
    if (connect(Socket, (const struct sockaddr *)Address, sizeof(*Address)) == 0)
        return 0;
    return WSAGetLastError();
}

/* 1 when the socket is writable within the time, 0 when the connect is still going on, -1 on an error */
static
int
WaitWritable(SOCKET Socket, LONG Milliseconds, BOOL *Failed)
{
    fd_set Write, Except;
    struct timeval Timeout = { Milliseconds / 1000, (Milliseconds % 1000) * 1000 };
    int Result;

    FD_ZERO(&Write);
    FD_ZERO(&Except);
    FD_SET(Socket, &Write);
    FD_SET(Socket, &Except);
    Result = select(0, NULL, &Write, &Except, &Timeout);
    *Failed = FD_ISSET(Socket, &Except) != 0;
    if (Result < 0)
        return -1;
    return Result > 0;
}

static
BOOL
Listener(SOCKET *Server, struct sockaddr_in *Address)
{
    int Length = sizeof(*Address);

    *Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(Address, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return *Server != INVALID_SOCKET &&
           bind(*Server, (struct sockaddr *)Address, sizeof(*Address)) == 0 &&
           listen(*Server, 5) == 0 &&
           getsockname(*Server, (struct sockaddr *)Address, &Length) == 0;
}

/* A port nothing listens on */
static
BOOL
ClosedPort(struct sockaddr_in *Address)
{
    SOCKET Server;
    BOOL Ok = Listener(&Server, Address);

    if (Server != INVALID_SOCKET)
        closesocket(Server);
    return Ok;
}

/* An address of the local subnet that nobody answers for, so a connect to it stays pending for seconds */
static
BOOL
SilentAddress(struct sockaddr_in *Addr)
{
    IP_ADAPTER_INFO *Info, *Adapter;
    IP_ADDR_STRING *Ip;
    ULONG Size = 0, Local = 0, Mask = 0, Candidate;

    if (GetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return FALSE;
    Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Info)
        return FALSE;
    if (GetAdaptersInfo(Info, &Size) == ERROR_SUCCESS)
    {
        for (Adapter = Info; Adapter && !Local; Adapter = Adapter->Next)
        {
            for (Ip = &Adapter->IpAddressList; Ip && !Local; Ip = Ip->Next)
            {
                Candidate = ntohl(inet_addr(Ip->IpAddress.String));
                Mask = ntohl(inet_addr(Ip->IpMask.String));
                if (Candidate && Candidate != INADDR_NONE && (Candidate >> 24) != 127 &&
                    (Candidate >> 16) != 0xA9FE && Mask && (~Mask) >= 8)
                    Local = Candidate;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    if (!Local)
        return FALSE;

    Candidate = (Local & Mask) | (~Mask - 5);
    if (Candidate == Local)
        Candidate--;
    ZeroMemory(Addr, sizeof(*Addr));
    Addr->sin_family = AF_INET;
    Addr->sin_port = htons(9);
    Addr->sin_addr.s_addr = htonl(Candidate);
    return TRUE;
}

START_TEST(connectstate)
{
    WSADATA WsaData;
    SOCKET Server, Client, Accepted;
    struct sockaddr_in Address, Silent, Closed;
    ULONG NonBlocking = 1, Blocking = 0;
    BOOL Failed;
    int Error, Result;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }
    if (!Listener(&Server, &Address))
    {
        skip("no loopback listener\n");
        WSACleanup();
        return;
    }

    /* Blocking: connected once, then WSAEISCONN, also for the accepted end */
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok_int(ConnectError(Client, &Address), 0);
    ok_int(ConnectError(Client, &Address), WSAEISCONN);
    ok_int(ConnectError(Client, &Address), WSAEISCONN);
    Accepted = accept(Server, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());
    ok_int(ConnectError(Accepted, &Address), WSAEISCONN);
    closesocket(Accepted);
    closesocket(Client);

    /* A listening socket cannot connect */
    ok_int(ConnectError(Server, &Address), WSAEINVAL);

    /* Non-blocking: WSAEWOULDBLOCK, then connected; asking again, also after going back to blocking mode,
     * is WSAEISCONN. In between the loopback connect may or may not be done yet */
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok_int(ioctlsocket(Client, FIONBIO, &NonBlocking), 0);
    Error = ConnectError(Client, &Address);
    ok(Error == WSAEWOULDBLOCK || Error == 0, "first non-blocking connect: error %d\n", Error);
    Error = ConnectError(Client, &Address);
    ok(Error == WSAEALREADY || Error == WSAEISCONN, "second non-blocking connect: error %d\n", Error);
    Result = WaitWritable(Client, 10000, &Failed);
    ok_int(Result, 1);
    ok(!Failed, "connected socket is in the except set\n");
    ok_int(ConnectError(Client, &Address), WSAEISCONN);
    ok_int(ConnectError(Client, &Address), WSAEISCONN);
    ok_int(ioctlsocket(Client, FIONBIO, &Blocking), 0);
    ok_int(ConnectError(Client, &Address), WSAEISCONN);
    closesocket(Client);

    /* Connecting: the second connect does not wait for the first, it fails with WSAEALREADY */
    if (SilentAddress(&Silent))
    {
        Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok_int(ioctlsocket(Client, FIONBIO, &NonBlocking), 0);
        ok_int(ConnectError(Client, &Silent), WSAEWOULDBLOCK);
        Result = WaitWritable(Client, 300, &Failed);
        if (Result == 0)
        {
            ok_int(ConnectError(Client, &Silent), WSAEALREADY);
            ok_int(ConnectError(Client, &Silent), WSAEALREADY);
        }
        else
        {
            skip("the connect to the silent address ended: %d\n", Result);
        }
        closesocket(Client);
    }
    else
    {
        skip("No local IPv4 subnet to connect into\n");
    }

    /* A refused connect leaves the socket able to connect again (WSAEWOULDBLOCK), as on Windows */
    if (ClosedPort(&Closed))
    {
        Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok_int(ioctlsocket(Client, FIONBIO, &NonBlocking), 0);
        ok_int(ConnectError(Client, &Closed), WSAEWOULDBLOCK);
        Result = WaitWritable(Client, 10000, &Failed);
        ok_int(Result, 1);
        ok(Failed, "refused socket is not in the except set\n");
        ok_int(ConnectError(Client, &Closed), WSAEWOULDBLOCK);
        closesocket(Client);
    }

    closesocket(Server);
    WSACleanup();
}
