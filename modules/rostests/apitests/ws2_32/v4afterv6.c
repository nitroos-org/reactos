/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv4 sockets around IPv6 addresses: a failed bind of an IPv6 address leaves an IPv4 socket that binds
 *              and works as any other (UDP receives, TCP accepts), and the stated length of an IPv4 address does
 *              not change a bind, however long it is
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

static void InitLoopback4(SOCKADDR_IN *Sa)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin_family = AF_INET;
    Sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static void InitLoopback6(SOCKADDR_IN6_LH *Sa)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    ((PUCHAR)&Sa->sin6_addr)[15] = 1;
}

/* A UDP socket whose first bind was given an IPv6 address: the bind fails, the next one (IPv4) works, and the
   socket receives what it sends itself */
static void TestUdpAfterV6Bind(void)
{
    SOCKET s;
    SOCKADDR_IN6_LH Sa6;
    SOCKADDR_IN Sa4, Me, From;
    int Result, Length;
    DWORD Timeout = 3000;
    char Buffer[16];

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(s != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;

    InitLoopback6(&Sa6);
    Result = bind(s, (struct sockaddr *)&Sa6, sizeof(Sa6));
    ok(Result == SOCKET_ERROR, "UDP: bind of an IPv6 address on an IPv4 socket succeeded\n");
    trace("UDP: bind of an IPv6 address: %d\n", Result == SOCKET_ERROR ? WSAGetLastError() : 0);

    InitLoopback4(&Sa4);
    Result = bind(s, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == 0, "UDP: bind of 127.0.0.1:0 after it: %d\n", WSAGetLastError());

    Length = sizeof(Me);
    Result = getsockname(s, (struct sockaddr *)&Me, &Length);
    ok(Result == 0 && Me.sin_family == AF_INET && Me.sin_port != 0, "UDP: getsockname: %d %u %u\n",
       Result == 0 ? 0 : WSAGetLastError(), Me.sin_family, ntohs(Me.sin_port));

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));
    Result = sendto(s, "hi", 2, 0, (struct sockaddr *)&Me, sizeof(Me));
    ok(Result == 2, "UDP: sendto itself: %d %d\n", Result, WSAGetLastError());

    memset(&From, 0xcc, sizeof(From));
    Length = sizeof(From);
    Result = recvfrom(s, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &Length);
    ok(Result == 2, "UDP: recvfrom: %d %d (the socket does not receive)\n", Result, WSAGetLastError());
    if (Result == 2)
    {
        ok(Length == sizeof(SOCKADDR_IN) && From.sin_family == AF_INET &&
           From.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && From.sin_port == Me.sin_port,
           "UDP: from %d %u %08lx %u\n", Length, From.sin_family, ntohl(From.sin_addr.s_addr), ntohs(From.sin_port));
    }

    closesocket(s);
}

/* The same for a TCP listener: it accepts after the failed bind */
static void TestTcpAfterV6Bind(void)
{
    SOCKET l, c, a;
    SOCKADDR_IN6_LH Sa6;
    SOCKADDR_IN Sa4, Me, Peer;
    int Result, Length;
    char Buffer[8];

    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(l != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
    if (l == INVALID_SOCKET)
        return;

    InitLoopback6(&Sa6);
    Result = bind(l, (struct sockaddr *)&Sa6, sizeof(Sa6));
    ok(Result == SOCKET_ERROR, "TCP: bind of an IPv6 address on an IPv4 socket succeeded\n");

    InitLoopback4(&Sa4);
    Result = bind(l, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == 0, "TCP: bind of 127.0.0.1:0 after it: %d\n", WSAGetLastError());
    Length = sizeof(Me);
    getsockname(l, (struct sockaddr *)&Me, &Length);
    ok(listen(l, 5) == 0, "TCP: listen: %d\n", WSAGetLastError());

    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Result = connect(c, (struct sockaddr *)&Me, sizeof(Me));
    ok(Result == 0, "TCP: connect: %d\n", WSAGetLastError());
    if (Result != 0)
    {
        /* Nothing to accept: an accept would wait for ever */
        closesocket(c);
        closesocket(l);
        return;
    }

    Length = sizeof(Peer);
    a = accept(l, (struct sockaddr *)&Peer, &Length);
    ok(a != INVALID_SOCKET, "TCP: accept: %d\n", WSAGetLastError());
    if (a != INVALID_SOCKET)
    {
        ok(Length == sizeof(SOCKADDR_IN) && Peer.sin_family == AF_INET && Peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "TCP: peer %d %u %08lx\n", Length, Peer.sin_family, ntohl(Peer.sin_addr.s_addr));
        ok(send(c, "abc", 3, 0) == 3, "TCP: send: %d\n", WSAGetLastError());
        ok(recv(a, Buffer, sizeof(Buffer), 0) == 3, "TCP: recv: %d\n", WSAGetLastError());
        closesocket(a);
    }
    closesocket(c);
    closesocket(l);
}

/* An IPv4 address with a stated length far above its size: bind takes the address, as it always did (the length
   of what the transport is given does not follow the stated one) */
static void TestLongLength(int NameLength)
{
    static UCHAR Big[70000];
    SOCKET s;
    int Result, i;

    for (i = 0; i < 2; i++)
    {
        memset(Big, 0, sizeof(Big));
        InitLoopback4((SOCKADDR_IN *)Big);
        s = socket(AF_INET, i ? SOCK_STREAM : SOCK_DGRAM, i ? IPPROTO_TCP : IPPROTO_UDP);
        ok(s != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
        if (s == INVALID_SOCKET)
            continue;
        Result = bind(s, (struct sockaddr *)Big, NameLength);
        ok(Result == 0, "%s: bind with namelen %d: %d\n", i ? "TCP" : "UDP", NameLength,
           Result == 0 ? 0 : WSAGetLastError());
        closesocket(s);
    }
}

START_TEST(v4afterv6)
{
    WSADATA wsaData;

    ok(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, "WSAStartup failed\n");

    TestUdpAfterV6Bind();
    TestTcpAfterV6Bind();
    TestLongLength(4000);
    TestLongLength(65530);
    TestLongLength(65535);
    TestLongLength(65537);

    WSACleanup();
}
