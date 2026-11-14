/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AF_INET6 TCP sockets on ::1 and through the dual stack: connect, accept, data both ways, shutdown,
 *              the address layout of getsockname, getpeername, accept and AcceptEx, IPV6_V6ONLY both ways,
 *              ::ffff:a.b.c.d on a dual stack socket, and the IPv6 forms of WSAAddressToString and
 *              WSAStringToAddress. Runs only while the stack takes IPv6 sockets (Tcpip\Parameters\Ipv6Enable);
 *              the error codes asserted only as "not success" are to be verified on Windows.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>
#include <iphlpapi.h>

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

#define DATA_SIZE (256 * 1024)

static const UCHAR Loopback6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
static const UCHAR Mapped127[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1 };
static const UCHAR Any6[16];

static void Init6(SOCKADDR_IN6_LH *Sa, const UCHAR *Address, USHORT PortN)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    Sa->sin6_port = PortN;
    memcpy(&Sa->sin6_addr, Address, 16);
}

static void Init4(SOCKADDR_IN *Sa, ULONG AddressH, USHORT PortN)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin_family = AF_INET;
    Sa->sin_addr.s_addr = htonl(AddressH);
    Sa->sin_port = PortN;
}

/* A SOCKADDR_IN6 of Length bytes with this address, port (when not 0), flow 0, scope 0 */
static void Check6(const char *What, const SOCKADDR_IN6_LH *Sa, int Length, const UCHAR *Address, USHORT PortN)
{
    ok(Length == (int)sizeof(SOCKADDR_IN6_LH), "%s: length %d\n", What, Length);
    ok(Sa->sin6_family == AF_INET6, "%s: family %u\n", What, Sa->sin6_family);
    ok(!memcmp(&Sa->sin6_addr, Address, 16), "%s: address %02x%02x..%02x%02x%02x%02x%02x%02x\n", What,
       ((PUCHAR)&Sa->sin6_addr)[0], ((PUCHAR)&Sa->sin6_addr)[1], ((PUCHAR)&Sa->sin6_addr)[10],
       ((PUCHAR)&Sa->sin6_addr)[11], ((PUCHAR)&Sa->sin6_addr)[12], ((PUCHAR)&Sa->sin6_addr)[13],
       ((PUCHAR)&Sa->sin6_addr)[14], ((PUCHAR)&Sa->sin6_addr)[15]);
    if (PortN)
        ok(Sa->sin6_port == PortN, "%s: port %u, expected %u\n", What, ntohs(Sa->sin6_port), ntohs(PortN));
    else
        ok(Sa->sin6_port != 0, "%s: port 0\n", What);
    ok(Sa->sin6_flowinfo == 0, "%s: flow %lx\n", What, (ULONG)Sa->sin6_flowinfo);
    ok(Sa->sin6_scope_id == 0, "%s: scope %lu\n", What, (ULONG)Sa->sin6_scope_id);
}

static SOCKET Socket6(BOOL V6Only)
{
    SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    DWORD Value = V6Only ? 1 : 0;

    ok(s != INVALID_SOCKET, "socket(AF_INET6): %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
        ok(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, sizeof(Value)) == 0,
           "IPV6_V6ONLY %lu: %d\n", Value, WSAGetLastError());
    return s;
}

/* A listener of the family Family on Address (16 bytes for IPv6, a host order IPv4 address in *Address4 else);
   returns its port (network order) */
static SOCKET Listener6(const UCHAR *Address, BOOL V6Only, USHORT *PortN)
{
    SOCKADDR_IN6_LH Sa;
    int Length = sizeof(Sa);
    SOCKET l = Socket6(V6Only);

    *PortN = 0;
    if (l == INVALID_SOCKET)
        return l;
    Init6(&Sa, Address, 0);
    ok(bind(l, (struct sockaddr *)&Sa, sizeof(Sa)) == 0, "bind of the listener: %d\n", WSAGetLastError());
    ok(listen(l, 5) == 0, "listen: %d\n", WSAGetLastError());
    ok(getsockname(l, (struct sockaddr *)&Sa, &Length) == 0, "getsockname of the listener: %d\n", WSAGetLastError());
    *PortN = Sa.sin6_port;
    return l;
}

static BOOL MoveData(SOCKET From, SOCKET To, int Size)
{
    static UCHAR Out[DATA_SIZE], In[DATA_SIZE];
    int Sent = 0, Got = 0, Result, i;

    for (i = 0; i < Size; i++)
        Out[i] = (UCHAR)(i * 7 + (i >> 9));

    /* Small enough for the socket buffers in steps: send a piece, read what came */
    while (Got < Size)
    {
        if (Sent < Size)
        {
            Result = send(From, (char *)Out + Sent, min(Size - Sent, 16384), 0);
            if (Result <= 0)
            {
                ok(0, "send: %d %d\n", Result, WSAGetLastError());
                return FALSE;
            }
            Sent += Result;
        }
        Result = recv(To, (char *)In + Got, Size - Got, 0);
        if (Result <= 0)
        {
            ok(0, "recv: %d %d after %d\n", Result, WSAGetLastError(), Got);
            return FALSE;
        }
        Got += Result;
    }
    ok(!memcmp(In, Out, Size), "the data differs\n");
    return TRUE;
}

/* ::1: connect, accept, the four names, data both ways, shutdown */
static void TestLoopback(void)
{
    SOCKET l, c, a;
    SOCKADDR_IN6_LH Sa, Peer, Name;
    USHORT Port, ClientPort;
    int Length, Result;
    char Byte;
    DWORD Value = 0xcc;

    l = Listener6(Loopback6, TRUE, &Port);
    if (l == INVALID_SOCKET)
        return;
    ok(Port != 0, "listener port 0\n");

    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getsockname(l, (struct sockaddr *)&Name, &Length) == 0, "getsockname: %d\n", WSAGetLastError());
    Check6("listener getsockname", &Name, Length, Loopback6, Port);

    /* IPV6_V6ONLY reads back what was set (a DWORD) */
    Length = sizeof(Value);
    ok(getsockopt(l, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, &Length) == 0 && Value == 1 && Length == sizeof(DWORD),
       "IPV6_V6ONLY of the listener: %lu %d\n", Value, Length);

    c = Socket6(TRUE);
    Init6(&Sa, Loopback6, Port);
    Result = connect(c, (struct sockaddr *)&Sa, sizeof(Sa));
    ok(Result == 0, "connect to [::1]: %d\n", WSAGetLastError());

    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getsockname(c, (struct sockaddr *)&Name, &Length) == 0, "client getsockname: %d\n", WSAGetLastError());
    Check6("client getsockname", &Name, Length, Loopback6, 0);
    ClientPort = Name.sin6_port;

    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getpeername(c, (struct sockaddr *)&Name, &Length) == 0, "client getpeername: %d\n", WSAGetLastError());
    Check6("client getpeername", &Name, Length, Loopback6, Port);

    Length = sizeof(Peer);
    memset(&Peer, 0xcc, sizeof(Peer));
    a = accept(l, (struct sockaddr *)&Peer, &Length);
    ok(a != INVALID_SOCKET, "accept: %d\n", WSAGetLastError());
    if (a == INVALID_SOCKET)
    {
        closesocket(c);
        closesocket(l);
        return;
    }
    Check6("accept", &Peer, Length, Loopback6, ClientPort);

    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getsockname(a, (struct sockaddr *)&Name, &Length) == 0, "accepted getsockname: %d\n", WSAGetLastError());
    Check6("accepted getsockname", &Name, Length, Loopback6, Port);
    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getpeername(a, (struct sockaddr *)&Name, &Length) == 0, "accepted getpeername: %d\n", WSAGetLastError());
    Check6("accepted getpeername", &Name, Length, Loopback6, ClientPort);

    /* A short buffer for the name of an IPv6 socket */
    Length = sizeof(SOCKADDR_IN);
    ok(getsockname(a, (struct sockaddr *)&Name, &Length) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT,
       "getsockname with 16 bytes: %d\n", WSAGetLastError());

    MoveData(c, a, DATA_SIZE);
    MoveData(a, c, DATA_SIZE);

    ok(shutdown(c, SD_SEND) == 0, "shutdown: %d\n", WSAGetLastError());
    Result = recv(a, &Byte, 1, 0);
    ok(Result == 0, "recv after the peer's shutdown: %d %d\n", Result, WSAGetLastError());
    ok(send(a, "z", 1, 0) == 1, "send after the peer's shutdown: %d\n", WSAGetLastError());
    ok(recv(c, &Byte, 1, 0) == 1 && Byte == 'z', "recv on the half closed socket: %d\n", WSAGetLastError());

    closesocket(a);
    Result = recv(c, &Byte, 1, 0);
    ok(Result == 0, "recv after the close: %d %d\n", Result, WSAGetLastError());
    closesocket(c);
    closesocket(l);
}

/* IPV6_V6ONLY on (the default): [::] takes IPv6 only, and its port is free for an IPv4 socket */
static void TestV6Only(void)
{
    SOCKET l, c, b;
    SOCKADDR_IN Sa4;
    SOCKADDR_IN6_LH Sa6;
    USHORT Port;
    DWORD Value = 0xcc;
    int Length = sizeof(Value), Result;

    c = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    ok(getsockopt(c, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, &Length) == 0 && Value == 1,
       "IPV6_V6ONLY default: %lu (%d)\n", Value, WSAGetLastError());
    closesocket(c);

    l = Listener6(Any6, TRUE, &Port);
    if (l == INVALID_SOCKET)
        return;

    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init4(&Sa4, INADDR_LOOPBACK, Port);
    Result = connect(c, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == SOCKET_ERROR, "an IPv4 connect reached an IPv6 only listener\n");
    trace("IPv4 connect to an IPv6 only listener: %d\n", Result ? WSAGetLastError() : 0);
    closesocket(c);

    /* No IPv4 socket holds the port: an IPv4 bind of it works */
    b = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init4(&Sa4, INADDR_ANY, Port);
    ok(bind(b, (struct sockaddr *)&Sa4, sizeof(Sa4)) == 0, "IPv4 bind of the port of an IPv6 only listener: %d\n",
       WSAGetLastError());
    closesocket(b);

    c = Socket6(TRUE);
    Init6(&Sa6, Loopback6, Port);
    ok(connect(c, (struct sockaddr *)&Sa6, sizeof(Sa6)) == 0, "IPv6 connect to [::]: %d\n", WSAGetLastError());
    closesocket(c);

    /* An IPv6 only socket does not connect to ::ffff:a.b.c.d */
    c = Socket6(TRUE);
    Init6(&Sa6, Mapped127, Port);
    Result = connect(c, (struct sockaddr *)&Sa6, sizeof(Sa6));
    ok(Result == SOCKET_ERROR, "an IPv6 only socket connected to ::ffff:127.0.0.1\n");
    trace("IPv6 only connect to a mapped address: %d\n", Result ? WSAGetLastError() : 0);
    closesocket(c);

    closesocket(l);
}

/* IPV6_V6ONLY off: [::] takes IPv4 as well (peers as ::ffff:a.b.c.d), and holds the IPv4 port */
static void TestDualStackListener(void)
{
    SOCKET l, c, a, b;
    SOCKADDR_IN Sa4, Me4;
    SOCKADDR_IN6_LH Sa6, Peer, Name;
    UCHAR Mapped[16];
    USHORT Port;
    int Length, Result;

    l = Listener6(Any6, FALSE, &Port);
    if (l == INVALID_SOCKET)
        return;

    Length = sizeof(Name);
    ok(getsockname(l, (struct sockaddr *)&Name, &Length) == 0, "getsockname: %d\n", WSAGetLastError());
    Check6("dual stack listener getsockname", &Name, Length, Any6, Port);

    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init4(&Sa4, INADDR_LOOPBACK, Port);
    Result = connect(c, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == 0, "IPv4 connect to a dual stack listener: %d\n", WSAGetLastError());
    Length = sizeof(Me4);
    getsockname(c, (struct sockaddr *)&Me4, &Length);

    memcpy(Mapped, Mapped127, 16);
    Length = sizeof(Peer);
    memset(&Peer, 0xcc, sizeof(Peer));
    a = accept(l, (struct sockaddr *)&Peer, &Length);
    ok(a != INVALID_SOCKET, "accept of an IPv4 peer: %d\n", WSAGetLastError());
    if (a != INVALID_SOCKET)
    {
        Check6("accept of an IPv4 peer", &Peer, Length, Mapped, Me4.sin_port);

        Length = sizeof(Name);
        memset(&Name, 0xcc, sizeof(Name));
        ok(getsockname(a, (struct sockaddr *)&Name, &Length) == 0, "getsockname: %d\n", WSAGetLastError());
        Check6("accepted IPv4 getsockname", &Name, Length, Mapped, Port);
        Length = sizeof(Name);
        memset(&Name, 0xcc, sizeof(Name));
        ok(getpeername(a, (struct sockaddr *)&Name, &Length) == 0, "getpeername: %d\n", WSAGetLastError());
        Check6("accepted IPv4 getpeername", &Name, Length, Mapped, Me4.sin_port);

        MoveData(c, a, 64 * 1024);
        MoveData(a, c, 64 * 1024);
        closesocket(a);
    }
    closesocket(c);

    /* IPv6 to the same listener */
    c = Socket6(TRUE);
    Init6(&Sa6, Loopback6, Port);
    ok(connect(c, (struct sockaddr *)&Sa6, sizeof(Sa6)) == 0, "IPv6 connect to a dual stack listener: %d\n",
       WSAGetLastError());
    Length = sizeof(Peer);
    a = accept(l, (struct sockaddr *)&Peer, &Length);
    ok(a != INVALID_SOCKET, "accept of an IPv6 peer: %d\n", WSAGetLastError());
    if (a != INVALID_SOCKET)
    {
        Check6("accept of an IPv6 peer", &Peer, Length, Loopback6, 0);
        closesocket(a);
    }
    closesocket(c);

    /* The dual stack socket does not hold the IPv4 wildcard of its port: an IPv4 socket binds 0.0.0.0 there
       (Windows 10 does), and once it listens it gets the IPv4 connections (VERIFY ON ORACLE: which socket) */
    b = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init4(&Sa4, INADDR_ANY, Port);
    Result = bind(b, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == 0, "IPv4 bind of the port of a dual stack listener: %d %d\n", Result, WSAGetLastError());
    if (Result == 0 && listen(b, 5) == 0)
    {
        fd_set Set;
        struct timeval Wait = { 5, 0 };

        c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Init4(&Sa4, INADDR_LOOPBACK, Port);
        ok(connect(c, (struct sockaddr *)&Sa4, sizeof(Sa4)) == 0, "IPv4 connect: %d\n", WSAGetLastError());
        FD_ZERO(&Set);
        FD_SET(b, &Set);
        Result = select(0, &Set, NULL, NULL, &Wait);
        ok(Result == 1, "the IPv4 listener did not get the IPv4 connection: %d\n", Result);
        if (Result == 1)
        {
            Length = sizeof(Me4);
            a = accept(b, (struct sockaddr *)&Me4, &Length);
            ok(a != INVALID_SOCKET, "accept on the IPv4 listener: %d\n", WSAGetLastError());
            if (a != INVALID_SOCKET)
                closesocket(a);
        }
        closesocket(c);
    }
    closesocket(b);

    closesocket(l);
}

/* A dual stack client: ::ffff:a.b.c.d is an IPv4 connect; the names are mapped */
static void TestDualStackClient(void)
{
    SOCKET l, c, a;
    SOCKADDR_IN Sa4, Peer4;
    SOCKADDR_IN6_LH Sa6, Name;
    USHORT Port;
    int Length;

    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init4(&Sa4, INADDR_LOOPBACK, 0);
    ok(bind(l, (struct sockaddr *)&Sa4, sizeof(Sa4)) == 0, "bind: %d\n", WSAGetLastError());
    ok(listen(l, 5) == 0, "listen: %d\n", WSAGetLastError());
    Length = sizeof(Sa4);
    getsockname(l, (struct sockaddr *)&Sa4, &Length);
    Port = Sa4.sin_port;

    c = Socket6(FALSE);
    Init6(&Sa6, Mapped127, Port);
    ok(connect(c, (struct sockaddr *)&Sa6, sizeof(Sa6)) == 0, "dual stack connect to ::ffff:127.0.0.1: %d\n",
       WSAGetLastError());

    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getpeername(c, (struct sockaddr *)&Name, &Length) == 0, "getpeername: %d\n", WSAGetLastError());
    Check6("dual stack client getpeername", &Name, Length, Mapped127, Port);
    Length = sizeof(Name);
    memset(&Name, 0xcc, sizeof(Name));
    ok(getsockname(c, (struct sockaddr *)&Name, &Length) == 0, "getsockname: %d\n", WSAGetLastError());
    Check6("dual stack client getsockname", &Name, Length, Mapped127, 0);

    Length = sizeof(Peer4);
    a = accept(l, (struct sockaddr *)&Peer4, &Length);
    ok(a != INVALID_SOCKET, "accept: %d\n", WSAGetLastError());
    if (a != INVALID_SOCKET)
    {
        ok(Length == sizeof(SOCKADDR_IN) && Peer4.sin_family == AF_INET &&
           Peer4.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && Peer4.sin_port == Name.sin6_port,
           "the IPv4 listener's peer: %d %u %08lx %u\n", Length, Peer4.sin_family,
           ntohl(Peer4.sin_addr.s_addr), ntohs(Peer4.sin_port));
        MoveData(c, a, 64 * 1024);
        closesocket(a);
    }
    closesocket(c);
    closesocket(l);
}

/* Binds: ::ffff:a.b.c.d on a dual stack socket is the IPv4 address; other addresses must be this machine's */
static void TestBinds(void)
{
    static const UCHAR Documentation[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    SOCKET s;
    SOCKADDR_IN6_LH Sa6, Name;
    int Length, Result;

    s = Socket6(FALSE);
    Init6(&Sa6, Mapped127, 0);
    ok(bind(s, (struct sockaddr *)&Sa6, sizeof(Sa6)) == 0, "dual stack bind of ::ffff:127.0.0.1: %d\n",
       WSAGetLastError());
    Length = sizeof(Name);
    ok(getsockname(s, (struct sockaddr *)&Name, &Length) == 0, "getsockname: %d\n", WSAGetLastError());
    Check6("bound to ::ffff:127.0.0.1", &Name, Length, Mapped127, 0);
    closesocket(s);

    s = Socket6(TRUE);
    Init6(&Sa6, Mapped127, 0);
    Result = bind(s, (struct sockaddr *)&Sa6, sizeof(Sa6));
    ok(Result == SOCKET_ERROR, "IPv6 only bind of ::ffff:127.0.0.1 succeeded\n");
    trace("IPv6 only bind of a mapped address: %d\n", Result ? WSAGetLastError() : 0);
    closesocket(s);

    s = Socket6(TRUE);
    Init6(&Sa6, Documentation, 0);
    Result = bind(s, (struct sockaddr *)&Sa6, sizeof(Sa6));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEADDRNOTAVAIL, "bind of 2001:db8::1: %d %d\n",
       Result, WSAGetLastError());
    closesocket(s);

    /* The same IPv6 address and port twice */
    {
        SOCKET s2;
        USHORT Port;

        s = Listener6(Loopback6, TRUE, &Port);
        s2 = Socket6(TRUE);
        Init6(&Sa6, Loopback6, Port);
        Result = bind(s2, (struct sockaddr *)&Sa6, sizeof(Sa6));
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEADDRINUSE, "second bind of [::1]:%u: %d %d\n",
           ntohs(Port), Result, WSAGetLastError());
        closesocket(s2);
        closesocket(s);
    }

    /* A connect to :: or a multicast address is not made */
    s = Socket6(TRUE);
    Init6(&Sa6, Any6, htons(80));
    Result = connect(s, (struct sockaddr *)&Sa6, sizeof(Sa6));
    ok(Result == SOCKET_ERROR, "connect to [::]:80 succeeded\n");
    trace("connect to [::]: %d\n", Result ? WSAGetLastError() : 0);
    closesocket(s);
}

/* Answers checked against Windows 10 (one oracle probe per bitness): IPV6_V6ONLY sizes and after bind, an IPv6
   address on an IPv4 socket, the short buffers of the string conversions */
static void TestOracleAnswers(void)
{
    SOCKET s;
    SOCKADDR_IN6_LH Sa;
    DWORD Value;
    char Byte, Text[64];
    int Length, Result;
    DWORD TextLength;

    s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    Byte = 0x55;
    Length = 1;
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &Byte, &Length);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT && Length == 0,
       "stream IPV6_V6ONLY in one byte: %d %d %d\n", Result, WSAGetLastError(), Length);
    Init6(&Sa, Loopback6, 0);
    ok(bind(s, (struct sockaddr *)&Sa, sizeof(Sa)) == 0, "bind: %d\n", WSAGetLastError());
    Value = 0;
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, sizeof(Value));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "IPV6_V6ONLY after bind: %d %d\n", Result,
       WSAGetLastError());
    closesocket(s);

    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    Value = 0xcccccccc;
    Length = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, &Length);
    ok(Result == 0 && Length == 1 && (Value & 0xff) == 1 && (Value >> 8) == 0xcccccc,
       "datagram IPV6_V6ONLY: %d %d %lx\n", Result, Length, Value);
    closesocket(s);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init6(&Sa, Loopback6, 0);
    Result = bind(s, (struct sockaddr *)&Sa, sizeof(Sa));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT, "IPv4 socket, IPv6 address: %d %d\n",
       Result, WSAGetLastError());
    closesocket(s);

    Init6(&Sa, Loopback6, htons(8080));
    TextLength = sizeof(Text);
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, 24, NULL, Text, &TextLength);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "a 24 byte SOCKADDR_IN6 to text: %d %d\n",
       Result, WSAGetLastError());

    Length = 27;
    Result = WSAStringToAddressA("::1", AF_INET6, NULL, (struct sockaddr *)&Sa, &Length);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT && Length == sizeof(Sa),
       "a 27 byte buffer from text: %d %d %d\n", Result, WSAGetLastError(), Length);
}

/* AcceptEx on a dual stack listener: both addresses are SOCKADDR_IN6 */
static void TestAcceptEx(void)
{
    GUID AcceptExId = WSAID_ACCEPTEX, SockaddrsId = WSAID_GETACCEPTEXSOCKADDRS;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    LPFN_GETACCEPTEXSOCKADDRS pGetSockaddrs = NULL;
    SOCKET l, c, a;
    SOCKADDR_IN Sa4, Me4;
    SOCKADDR_IN6_LH *Local, *Remote;
    UCHAR Buffer[2 * (sizeof(SOCKADDR_IN6_LH) + 16)];
    OVERLAPPED Overlapped;
    DWORD Bytes = 0;
    USHORT Port;
    int LocalLength = 0, RemoteLength = 0, Length;
    BOOL Result;

    l = Listener6(Any6, FALSE, &Port);
    if (l == INVALID_SOCKET)
        return;
    WSAIoctl(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptExId, sizeof(AcceptExId), &pAcceptEx, sizeof(pAcceptEx),
             &Bytes, NULL, NULL);
    WSAIoctl(l, SIO_GET_EXTENSION_FUNCTION_POINTER, &SockaddrsId, sizeof(SockaddrsId), &pGetSockaddrs,
             sizeof(pGetSockaddrs), &Bytes, NULL, NULL);
    if (!pAcceptEx || !pGetSockaddrs)
    {
        skip("no AcceptEx\n");
        closesocket(l);
        return;
    }

    a = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    memset(&Overlapped, 0, sizeof(Overlapped));
    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    Result = pAcceptEx(l, a, Buffer, 0, sizeof(SOCKADDR_IN6_LH) + 16, sizeof(SOCKADDR_IN6_LH) + 16, &Bytes,
                       &Overlapped);
    ok(Result || WSAGetLastError() == ERROR_IO_PENDING, "AcceptEx: %d\n", WSAGetLastError());

    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Init4(&Sa4, INADDR_LOOPBACK, Port);
    ok(connect(c, (struct sockaddr *)&Sa4, sizeof(Sa4)) == 0, "IPv4 connect: %d\n", WSAGetLastError());
    Length = sizeof(Me4);
    getsockname(c, (struct sockaddr *)&Me4, &Length);

    ok(WaitForSingleObject(Overlapped.hEvent, 5000) == WAIT_OBJECT_0, "AcceptEx did not complete\n");
    ok(GetOverlappedResult((HANDLE)l, &Overlapped, &Bytes, FALSE), "AcceptEx result: %lu\n", GetLastError());

    pGetSockaddrs(Buffer, 0, sizeof(SOCKADDR_IN6_LH) + 16, sizeof(SOCKADDR_IN6_LH) + 16,
                  (struct sockaddr **)&Local, &LocalLength, (struct sockaddr **)&Remote, &RemoteLength);
    if (Local && Remote)
    {
        Check6("AcceptEx local", Local, LocalLength, Mapped127, Port);
        Check6("AcceptEx remote", Remote, RemoteLength, Mapped127, Me4.sin_port);
    }
    else
    {
        ok(0, "GetAcceptExSockaddrs gave no address\n");
    }

    CloseHandle(Overlapped.hEvent);
    closesocket(c);
    closesocket(a);
    closesocket(l);
}

/* The IPv6 forms of WSAAddressToString and WSAStringToAddress, and the round trip */
static void TestStrings(void)
{
    static const UCHAR LinkLocal[16] = { 0xfe,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    SOCKADDR_IN6_LH Sa, Back;
    char Text[80];
    DWORD Length;
    int SaLength, Result;

    Init6(&Sa, Loopback6, htons(8080));
    Length = sizeof(Text);
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, sizeof(Sa), NULL, Text, &Length);
    ok(Result == 0 && !strcmp(Text, "[::1]:8080") && Length == strlen(Text) + 1,
       "[::1]:8080 as text: %d %d '%s' %lu\n", Result, WSAGetLastError(), Result ? "" : Text, Length);

    Init6(&Sa, Loopback6, 0);
    Length = sizeof(Text);
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, sizeof(Sa), NULL, Text, &Length);
    ok(Result == 0 && !strcmp(Text, "::1"), "::1 as text: %d '%s'\n", Result, Result ? "" : Text);

    Init6(&Sa, LinkLocal, 0);
    Sa.sin6_scope_id = 3;
    Length = sizeof(Text);
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, sizeof(Sa), NULL, Text, &Length);
    ok(Result == 0 && !strcmp(Text, "fe80::1%3"), "fe80::1%%3 as text: %d '%s'\n", Result, Result ? "" : Text);

    Init6(&Sa, Mapped127, htons(1));
    Length = sizeof(Text);
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, sizeof(Sa), NULL, Text, &Length);
    ok(Result == 0 && !strcmp(Text, "[::ffff:127.0.0.1]:1"), "mapped as text: %d '%s'\n", Result, Result ? "" : Text);

    /* Too small a buffer: the length needed */
    Init6(&Sa, Loopback6, htons(8080));
    Length = 3;
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, sizeof(Sa), NULL, Text, &Length);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT && Length == sizeof("[::1]:8080"),
       "short buffer: %d %d %lu\n", Result, WSAGetLastError(), Length);

    memset(&Back, 0xcc, sizeof(Back));
    SaLength = sizeof(Back);
    Result = WSAStringToAddressA("[fe80::1%3]:80", AF_INET6, NULL, (struct sockaddr *)&Back, &SaLength);
    ok(Result == 0 && SaLength == sizeof(Back) && Back.sin6_family == AF_INET6 && Back.sin6_port == htons(80) &&
       Back.sin6_scope_id == 3 && !memcmp(&Back.sin6_addr, LinkLocal, 16) && Back.sin6_flowinfo == 0,
       "[fe80::1%%3]:80 from text: %d %d len %d port %u scope %lu\n", Result, WSAGetLastError(), SaLength,
       ntohs(Back.sin6_port), (ULONG)Back.sin6_scope_id);

    SaLength = sizeof(Back);
    Result = WSAStringToAddressA("::1", AF_INET6, NULL, (struct sockaddr *)&Back, &SaLength);
    ok(Result == 0 && !memcmp(&Back.sin6_addr, Loopback6, 16) && Back.sin6_port == 0, "::1 from text: %d %d\n",
       Result, WSAGetLastError());

    SaLength = sizeof(Back);
    Result = WSAStringToAddressA("not an address", AF_INET6, NULL, (struct sockaddr *)&Back, &SaLength);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "a bad string: %d %d\n", Result, WSAGetLastError());

    SaLength = sizeof(Back) - 1;
    Result = WSAStringToAddressA("::1", AF_INET6, NULL, (struct sockaddr *)&Back, &SaLength);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "a 27 byte buffer: %d %d\n", Result,
       WSAGetLastError());

    /* Round trip */
    Init6(&Sa, LinkLocal, htons(443));
    Sa.sin6_scope_id = 12;
    Length = sizeof(Text);
    Result = WSAAddressToStringA((struct sockaddr *)&Sa, sizeof(Sa), NULL, Text, &Length);
    ok(Result == 0, "round trip to text: %d\n", WSAGetLastError());
    SaLength = sizeof(Back);
    Result = WSAStringToAddressA(Text, AF_INET6, NULL, (struct sockaddr *)&Back, &SaLength);
    ok(Result == 0 && !memcmp(&Back, &Sa, sizeof(Sa)), "round trip of '%s': %d %d\n", Text, Result,
       WSAGetLastError());
}

/* GetExtendedTcpTable(AF_INET6): the listener and both ends of a connection over ::1, owned by this process; the
   IPv4 table does not list them */
static void TestTcpTables(void)
{
    SOCKET l, c, a;
    SOCKADDR_IN6_LH Sa;
    USHORT Port;
    DWORD Size = 0, Result, i, Pid = GetCurrentProcessId();
    PMIB_TCP6TABLE_OWNER_PID Table6;
    PMIB_TCPTABLE_OWNER_PID Table4;
    BOOL Listener = FALSE;
    int Established = 0;
    int Length;

    l = Listener6(Loopback6, TRUE, &Port);
    if (l == INVALID_SOCKET)
        return;
    c = Socket6(TRUE);
    Init6(&Sa, Loopback6, Port);
    ok(connect(c, (struct sockaddr *)&Sa, sizeof(Sa)) == 0, "connect: %d\n", WSAGetLastError());
    Length = sizeof(Sa);
    a = accept(l, (struct sockaddr *)&Sa, &Length);

    Result = GetExtendedTcpTable(NULL, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    ok(Result == ERROR_INSUFFICIENT_BUFFER && Size >= FIELD_OFFSET(MIB_TCP6TABLE_OWNER_PID, table),
       "IPv6 TCP table size: %lu %lu\n", Result, Size);
    Size += 16 * sizeof(MIB_TCP6ROW_OWNER_PID);
    Table6 = HeapAlloc(GetProcessHeap(), 0, Size);
    Result = GetExtendedTcpTable(Table6, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    ok(Result == NO_ERROR, "IPv6 TCP table: %lu\n", Result);
    if (Result == NO_ERROR)
    {
        for (i = 0; i < Table6->dwNumEntries; i++)
        {
            PMIB_TCP6ROW_OWNER_PID Row = &Table6->table[i];

            if (Row->dwOwningPid != Pid || memcmp(Row->ucLocalAddr, Loopback6, 16) != 0)
                continue;
            if (Row->dwState == MIB_TCP_STATE_LISTEN && Row->dwLocalPort == Port)
                Listener = TRUE;
            if (Row->dwState == MIB_TCP_STATE_ESTAB && !memcmp(Row->ucRemoteAddr, Loopback6, 16) &&
                (Row->dwLocalPort == Port || Row->dwRemotePort == Port))
                Established++;
        }
        ok(Listener, "the [::1] listener is not in the IPv6 TCP table (%lu rows)\n", Table6->dwNumEntries);
        ok(Established >= 1, "no established [::1] connection in the IPv6 TCP table (%d)\n", Established);
    }
    HeapFree(GetProcessHeap(), 0, Table6);

    Size = 0;
    GetExtendedTcpTable(NULL, &Size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    Size += 16 * sizeof(MIB_TCPROW_OWNER_PID);
    Table4 = HeapAlloc(GetProcessHeap(), 0, Size);
    Result = GetExtendedTcpTable(Table4, &Size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    ok(Result == NO_ERROR, "IPv4 TCP table: %lu\n", Result);
    if (Result == NO_ERROR)
    {
        for (i = 0; i < Table4->dwNumEntries; i++)
            ok(Table4->table[i].dwLocalPort != Port || Table4->table[i].dwOwningPid != Pid,
               "the IPv4 table lists the IPv6 socket of port %u\n", ntohs(Port));
    }
    HeapFree(GetProcessHeap(), 0, Table4);

    /* No IPv6 UDP sockets (the stack takes IPv6 addresses for TCP only): the IPv6 UDP table is there, empty */
    {
        MIB_UDP6TABLE_OWNER_PID Udp6;

        Size = 0;
        Result = GetExtendedUdpTable(NULL, &Size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        ok(Result == ERROR_INSUFFICIENT_BUFFER && Size == FIELD_OFFSET(MIB_UDP6TABLE_OWNER_PID, table),
           "IPv6 UDP table size: %lu %lu\n", Result, Size);
        Size = sizeof(Udp6);
        Udp6.dwNumEntries = 0xcccccccc;
        Result = GetExtendedUdpTable(&Udp6, &Size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        ok(Result == NO_ERROR && Udp6.dwNumEntries == 0, "IPv6 UDP table: %lu %lu\n", Result, Udp6.dwNumEntries);
    }

    if (a != INVALID_SOCKET)
        closesocket(a);
    closesocket(c);
    closesocket(l);
}

START_TEST(ipv6tcp)
{
    WSADATA wsaData;

    ok(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, "WSAStartup failed\n");

    if (!Ipv6SocketsOn())
    {
        SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

        /* No IPv6 sockets: the answer of a system without IPv6 */
        ok(s == INVALID_SOCKET && WSAGetLastError() == WSAEAFNOSUPPORT, "socket(AF_INET6) without IPv6: %d\n",
           s == INVALID_SOCKET ? WSAGetLastError() : 0);
        if (s != INVALID_SOCKET)
            closesocket(s);
        skip("the stack has no IPv6 sockets (state 0x%lx)\n", Ipv6StackFlags());
        WSACleanup();
        return;
    }

    TestLoopback();
    TestV6Only();
    TestDualStackListener();
    TestDualStackClient();
    TestBinds();
    TestAcceptEx();
    TestStrings();
    TestTcpTables();
    TestOracleAnswers();

    WSACleanup();
}
