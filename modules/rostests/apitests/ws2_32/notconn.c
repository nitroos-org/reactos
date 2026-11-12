/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     recv() and send() on a stream socket that is not connected (new, bound, listening, after a
 *              refused connect) fail with WSAENOTCONN, with a length of one byte and with a length of zero.
 *              recv() returned WSAEINVAL; Oracle Net (lsnrctl start of Oracle Database 21c XE) reads the
 *              socket after a refused connect.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values are what Windows 10 22H2 returns (checked on the reference machine).
 */

#include "ws2_32.h"

static void Check(const char *What, SOCKET s)
{
    char Buffer[4];
    int Result;

    Result = recv(s, Buffer, 1, 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOTCONN, "%s: recv(1) = %d, error %d\n", What, Result, WSAGetLastError());
    Result = recv(s, Buffer, 0, 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOTCONN, "%s: recv(0) = %d, error %d\n", What, Result, WSAGetLastError());
    Result = send(s, "x", 1, 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOTCONN, "%s: send(1) = %d, error %d\n", What, Result, WSAGetLastError());
    Result = send(s, "x", 0, 0);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOTCONN, "%s: send(0) = %d, error %d\n", What, Result, WSAGetLastError());
}

static void Loopback(struct sockaddr_in *Address, USHORT Port)
{
    ZeroMemory(Address, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Address->sin_port = htons(Port);
}

START_TEST(notconn)
{
    WSADATA Data;
    SOCKET s;
    struct sockaddr_in Address;
    int Length = sizeof(Address), Result;
    USHORT Closed;
    u_long One = 1;
    fd_set Except;
    struct timeval Timeout;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    s = socket(AF_INET, SOCK_STREAM, 0);
    Check("new", s);
    closesocket(s);

    Loopback(&Address, 0);
    s = socket(AF_INET, SOCK_STREAM, 0);
    ok(bind(s, (struct sockaddr *)&Address, sizeof(Address)) == 0, "bind failed\n");
    Check("bound", s);
    closesocket(s);

    s = socket(AF_INET, SOCK_STREAM, 0);
    ok(bind(s, (struct sockaddr *)&Address, sizeof(Address)) == 0, "bind failed\n");
    ok(getsockname(s, (struct sockaddr *)&Address, &Length) == 0, "getsockname failed\n");
    Closed = ntohs(Address.sin_port);
    ok(listen(s, 1) == 0, "listen failed\n");
    Check("listening", s);
    closesocket(s);

    /* Nothing listens on Closed now */
    Loopback(&Address, Closed);
    s = socket(AF_INET, SOCK_STREAM, 0);
    Result = connect(s, (struct sockaddr *)&Address, sizeof(Address));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAECONNREFUSED, "connect = %d, error %d\n", Result, WSAGetLastError());
    Check("after a refused connect", s);
    closesocket(s);

    s = socket(AF_INET, SOCK_STREAM, 0);
    ok(ioctlsocket(s, FIONBIO, &One) == 0, "FIONBIO failed\n");
    Result = connect(s, (struct sockaddr *)&Address, sizeof(Address));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "connect = %d, error %d\n", Result, WSAGetLastError());
    FD_ZERO(&Except);
    FD_SET(s, &Except);
    Timeout.tv_sec = 10;
    Timeout.tv_usec = 0;
    Result = select(0, NULL, NULL, &Except, &Timeout);
    ok(Result == 1 && FD_ISSET(s, &Except), "select = %d, the refused connect is not reported\n", Result);
    Check("after a refused non-blocking connect", s);
    closesocket(s);

    WSACleanup();
}
