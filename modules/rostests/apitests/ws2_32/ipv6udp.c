/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     AF_INET6 UDP sockets: datagrams on ::1 (small, empty, fragmented), the source address recvfrom
 *              reports, connected sockets, the dual stack (IPv4 datagrams as ::ffff:a.b.c.d, replies to them,
 *              IPV6_V6ONLY), WSARecvMsg with IPV6_PKTINFO and IPV6_HOPLIMIT, the hop limit options reaching the
 *              stack, multicast groups with the loop, and the IPv6 UDP table. Runs only while the stack takes
 *              IPv6 datagram sockets (Tcpip\Parameters\Ipv6Enable); the Windows answers marked VERIFY ON ORACLE
 *              in the code are this stack's, not measured on Windows.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>
#include <iphlpapi.h>

#define TEST_IPV6_STATE_DATAGRAMS 0x4

static const UCHAR Loopback6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
static const UCHAR Mapped127[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1 };
static const UCHAR Any6[16];
/* A transient group of organisation-local scope, for this test only */
static const UCHAR Group6[16] = { 0xff,0x15,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x42,0x42 };

static LPFN_WSARECVMSG pWSARecvMsg;

static void Init6(SOCKADDR_IN6_LH *Sa, const UCHAR *Address, USHORT PortN)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    Sa->sin6_port = PortN;
    memcpy(&Sa->sin6_addr, Address, 16);
}

static SOCKET Udp6(BOOL V6Only, const UCHAR *Address, USHORT *PortN)
{
    SOCKADDR_IN6_LH Sa;
    int Length = sizeof(Sa);
    DWORD Value = V6Only ? 1 : 0;
    SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    ok(s != INVALID_SOCKET, "socket(AF_INET6, SOCK_DGRAM): %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return s;
    ok(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, sizeof(Value)) == 0, "IPV6_V6ONLY: %d\n",
       WSAGetLastError());
    Init6(&Sa, Address, 0);
    ok(bind(s, (struct sockaddr *)&Sa, sizeof(Sa)) == 0, "bind: %d\n", WSAGetLastError());
    ok(getsockname(s, (struct sockaddr *)&Sa, &Length) == 0, "getsockname: %d\n", WSAGetLastError());
    ok(Length == (int)sizeof(Sa) && Sa.sin6_family == AF_INET6 && Sa.sin6_port != 0, "bound name: %d %u %u\n",
       Length, Sa.sin6_family, ntohs(Sa.sin6_port));
    *PortN = Sa.sin6_port;
    return s;
}

/* A datagram waits within Ms milliseconds */
static BOOL Readable(SOCKET s, DWORD Ms)
{
    fd_set Set;
    struct timeval Tv;

    FD_ZERO(&Set);
    FD_SET(s, &Set);
    Tv.tv_sec = Ms / 1000;
    Tv.tv_usec = (Ms % 1000) * 1000;
    return select(0, &Set, NULL, NULL, &Tv) == 1;
}

/* Receives one datagram of Expected bytes (filled with Fill) from Address:PortN */
static void Receive6(const char *What, SOCKET s, char *Buffer, int Size, int Expected, char Fill,
                     const UCHAR *Address, USHORT PortN)
{
    SOCKADDR_IN6_LH From;
    int FromLength = sizeof(From), Result, i;

    if (!Readable(s, 3000))
    {
        ok(0, "%s: nothing received\n", What);
        return;
    }
    memset(&From, 0xcc, sizeof(From));
    Result = recvfrom(s, Buffer, Size, 0, (struct sockaddr *)&From, &FromLength);
    ok(Result == Expected, "%s: received %d, expected %d (%d)\n", What, Result, Expected, WSAGetLastError());
    for (i = 0; i < Result && i < Expected; i++)
    {
        if (Buffer[i] != Fill)
        {
            ok(0, "%s: byte %d is %02x\n", What, i, (UCHAR)Buffer[i]);
            break;
        }
    }
    ok(FromLength == (int)sizeof(From), "%s: source length %d\n", What, FromLength);
    ok(From.sin6_family == AF_INET6, "%s: source family %u\n", What, From.sin6_family);
    ok(!memcmp(&From.sin6_addr, Address, 16), "%s: source address ..%02x%02x%02x%02x%02x%02x\n", What,
       ((PUCHAR)&From.sin6_addr)[10], ((PUCHAR)&From.sin6_addr)[11], ((PUCHAR)&From.sin6_addr)[12],
       ((PUCHAR)&From.sin6_addr)[13], ((PUCHAR)&From.sin6_addr)[14], ((PUCHAR)&From.sin6_addr)[15]);
    ok(From.sin6_port == PortN, "%s: source port %u, expected %u\n", What, ntohs(From.sin6_port), ntohs(PortN));
    ok(From.sin6_flowinfo == 0 && From.sin6_scope_id == 0, "%s: flow %lu scope %lu\n", What,
       (ULONG)From.sin6_flowinfo, (ULONG)From.sin6_scope_id);
}

static void TestLoopback(void)
{
    static char Out[60000], In[65536];
    SOCKADDR_IN6_LH To, From;
    USHORT PortA, PortB;
    SOCKET a, b;
    int Result, Length;
    char Small[2];

    a = Udp6(TRUE, Loopback6, &PortA);
    b = Udp6(TRUE, Loopback6, &PortB);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET)
        goto Done;

    Init6(&To, Loopback6, PortB);
    memset(Out, 'a', sizeof(Out));
    Result = sendto(a, Out, 100, 0, (struct sockaddr *)&To, sizeof(To));
    ok(Result == 100, "sendto [::1]: %d %d\n", Result, WSAGetLastError());
    Receive6("100 bytes", b, In, sizeof(In), 100, 'a', Loopback6, PortA);

    /* Empty */
    Result = sendto(a, Out, 0, 0, (struct sockaddr *)&To, sizeof(To));
    ok(Result == 0, "empty sendto: %d %d\n", Result, WSAGetLastError());
    Receive6("empty", b, In, sizeof(In), 0, 'a', Loopback6, PortA);

    /* Larger than the loopback MTU: fragments, reassembled */
    memset(Out, 'b', sizeof(Out));
    Result = sendto(a, Out, sizeof(Out), 0, (struct sockaddr *)&To, sizeof(To));
    ok(Result == (int)sizeof(Out), "sendto 60000: %d %d\n", Result, WSAGetLastError());
    Receive6("60000 bytes", b, In, sizeof(In), sizeof(Out), 'b', Loopback6, PortA);

    /* Windows sends up to 65535 - 8 bytes and answers WSAEMSGSIZE beyond (oracle). This stack's limit is 65487
       (lwIP holds a datagram with its IPv6 header in 16-bit lengths): the largest it takes goes, 65528 is
       WSAEMSGSIZE as on Windows; 65488 to 65527 are a known difference (WSAEMSGSIZE here, sent on Windows) */
    {
        static char Big[65528];

        memset(Big, 'z', sizeof(Big));
        Result = sendto(a, Big, 65487, 0, (struct sockaddr *)&To, sizeof(To));
        ok(Result == 65487, "sendto 65487: %d %d\n", Result, WSAGetLastError());
        if (Result == 65487)
            Receive6("65487 bytes", b, In, sizeof(In), 65487, 'z', Loopback6, PortA);
        Result = sendto(a, Big, 65527, 0, (struct sockaddr *)&To, sizeof(To));
        trace("sendto 65527: %d %d (Windows: sent)\n", Result, Result < 0 ? WSAGetLastError() : 0);
        Result = sendto(a, Big, 65528, 0, (struct sockaddr *)&To, sizeof(To));
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEMSGSIZE, "sendto 65528: %d %d\n", Result,
           WSAGetLastError());
    }

    /* The other way */
    Init6(&To, Loopback6, PortA);
    Result = sendto(b, Out, 1000, 0, (struct sockaddr *)&To, sizeof(To));
    ok(Result == 1000, "sendto back: %d %d\n", Result, WSAGetLastError());
    Receive6("reply", a, In, sizeof(In), 1000, 'b', Loopback6, PortB);

    /* A source address buffer smaller than a SOCKADDR_IN6 (VERIFY ON ORACLE: WSAEFAULT) */
    Init6(&To, Loopback6, PortB);
    sendto(a, Out, 10, 0, (struct sockaddr *)&To, sizeof(To));
    ok(Readable(b, 3000), "short source buffer: nothing received\n");
    Length = sizeof(SOCKADDR_IN);
    Result = recvfrom(b, In, sizeof(In), 0, (struct sockaddr *)&From, &Length);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "recvfrom with 16 bytes of address: %d %d\n",
       Result, WSAGetLastError());
    Length = sizeof(From);
    Result = recvfrom(b, In, sizeof(In), 0, (struct sockaddr *)&From, &Length);
    ok(Result == 10, "the datagram is still there: %d %d\n", Result, WSAGetLastError());

    /* A datagram larger than the buffer: WSAEMSGSIZE, as IPv4 */
    sendto(a, Out, 10, 0, (struct sockaddr *)&To, sizeof(To));
    ok(Readable(b, 3000), "cut datagram: nothing received\n");
    Length = sizeof(From);
    Result = recvfrom(b, Small, sizeof(Small), 0, (struct sockaddr *)&From, &Length);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEMSGSIZE, "cut datagram: %d %d\n", Result,
       WSAGetLastError());

    /* Connected: send/recv and the peer's name */
    ok(connect(a, (struct sockaddr *)&To, sizeof(To)) == 0, "connect: %d\n", WSAGetLastError());
    Result = send(a, Out, 33, 0);
    ok(Result == 33, "send connected: %d %d\n", Result, WSAGetLastError());
    Receive6("connected", b, In, sizeof(In), 33, 'b', Loopback6, PortA);
    Length = sizeof(From);
    ok(getpeername(a, (struct sockaddr *)&From, &Length) == 0 && Length == (int)sizeof(From) &&
       From.sin6_port == PortB && !memcmp(&From.sin6_addr, Loopback6, 16), "getpeername: %d\n", WSAGetLastError());

Done:
    closesocket(a);
    closesocket(b);
}

static void TestDualStack(void)
{
    SOCKADDR_IN6_LH To6;
    SOCKADDR_IN To4, From4;
    USHORT PortDual, PortOnly, Port4;
    SOCKET d, v6, v4;
    char Buffer[100];
    int Result, Length;

    d = Udp6(FALSE, Any6, &PortDual);
    v6 = Udp6(TRUE, Any6, &PortOnly);
    v4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(v4 != INVALID_SOCKET, "socket(AF_INET): %d\n", WSAGetLastError());
    if (d == INVALID_SOCKET || v6 == INVALID_SOCKET || v4 == INVALID_SOCKET)
        goto Done;
    memset(&To4, 0, sizeof(To4));
    To4.sin_family = AF_INET;
    To4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(v4, (struct sockaddr *)&To4, sizeof(To4)) == 0, "bind 127.0.0.1: %d\n", WSAGetLastError());
    Length = sizeof(To4);
    getsockname(v4, (struct sockaddr *)&To4, &Length);
    Port4 = To4.sin_port;

    /* An IPv4 datagram to the dual stack socket: from ::ffff:127.0.0.1 */
    To4.sin_port = PortDual;
    memset(Buffer, 'c', sizeof(Buffer));
    Result = sendto(v4, Buffer, 20, 0, (struct sockaddr *)&To4, sizeof(To4));
    ok(Result == 20, "IPv4 sendto the dual stack socket: %d %d\n", Result, WSAGetLastError());
    Receive6("IPv4 to dual stack", d, Buffer, sizeof(Buffer), 20, 'c', Mapped127, Port4);

    /* The reply to ::ffff:127.0.0.1 is an IPv4 datagram from 127.0.0.1 */
    Init6(&To6, Mapped127, Port4);
    memset(Buffer, 'd', sizeof(Buffer));
    Result = sendto(d, Buffer, 30, 0, (struct sockaddr *)&To6, sizeof(To6));
    ok(Result == 30, "dual stack sendto ::ffff:127.0.0.1: %d %d\n", Result, WSAGetLastError());
    if (Readable(v4, 3000))
    {
        Length = sizeof(From4);
        Result = recvfrom(v4, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From4, &Length);
        ok(Result == 30, "IPv4 reply: %d %d\n", Result, WSAGetLastError());
        ok(Length == (int)sizeof(From4) && From4.sin_family == AF_INET &&
           From4.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && From4.sin_port == PortDual,
           "IPv4 reply source: %d %u %lx %u\n", Length, From4.sin_family, ntohl(From4.sin_addr.s_addr),
           ntohs(From4.sin_port));
    }
    else
    {
        ok(0, "no IPv4 reply from the dual stack socket\n");
    }

    /* IPV6_V6ONLY: no IPv4 datagram, and no send to a mapped address (VERIFY ON ORACLE: the error) */
    To4.sin_port = PortOnly;
    sendto(v4, Buffer, 5, 0, (struct sockaddr *)&To4, sizeof(To4));
    ok(!Readable(v6, 500), "an IPV6_V6ONLY socket received an IPv4 datagram\n");
    Result = sendto(v6, Buffer, 5, 0, (struct sockaddr *)&To6, sizeof(To6));
    ok(Result == SOCKET_ERROR, "IPV6_V6ONLY sendto ::ffff:127.0.0.1: %d\n", Result);
    trace("IPV6_V6ONLY sendto a mapped address: %d\n", WSAGetLastError());

    /* IPv4 and IPv6 sockets on one port: separate (an IPv4 socket binds 0.0.0.0 on a dual stack socket's port) */
    {
        SOCKET Same = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKADDR_IN Sa;

        memset(&Sa, 0, sizeof(Sa));
        Sa.sin_family = AF_INET;
        Sa.sin_port = PortOnly;
        ok(bind(Same, (struct sockaddr *)&Sa, sizeof(Sa)) == 0, "IPv4 bind on an IPv6 socket's port: %d\n",
           WSAGetLastError());
        closesocket(Same);
    }

Done:
    closesocket(d);
    closesocket(v6);
    closesocket(v4);
}

/* WSARecvMsg: IPV6_PKTINFO (destination, interface) and IPV6_HOPLIMIT, set by the sender's IPV6_UNICAST_HOPS */
static void TestRecvMsg(void)
{
    SOCKADDR_IN6_LH To, From;
    USHORT PortA, PortB;
    SOCKET a, b;
    GUID Guid = WSAID_WSARECVMSG;
    DWORD Bytes, Value;
    WSAMSG Msg;
    WSABUF Buf;
    char Data[64], Control[256];
    int Result, Length, Found = 0;
    WSACMSGHDR *Cmsg;

    a = Udp6(TRUE, Loopback6, &PortA);
    b = Udp6(TRUE, Loopback6, &PortB);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET)
        goto Done;

    if (WSAIoctl(b, SIO_GET_EXTENSION_FUNCTION_POINTER, &Guid, sizeof(Guid), &pWSARecvMsg, sizeof(pWSARecvMsg),
                 &Bytes, NULL, NULL) != 0 || !pWSARecvMsg)
    {
        skip("no WSARecvMsg\n");
        goto Done;
    }

    Value = 0xcc;
    Length = sizeof(Value);
    ok(getsockopt(b, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&Value, &Length) == 0 && Value == 0,
       "IPV6_PKTINFO default: %d %lu\n", WSAGetLastError(), Value);
    Value = 1;
    ok(setsockopt(b, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&Value, sizeof(Value)) == 0, "IPV6_PKTINFO: %d\n",
       WSAGetLastError());
    ok(setsockopt(b, IPPROTO_IPV6, IPV6_HOPLIMIT, (char *)&Value, sizeof(Value)) == 0, "IPV6_HOPLIMIT: %d\n",
       WSAGetLastError());
    Value = 0;
    Length = sizeof(Value);
    ok(getsockopt(b, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&Value, &Length) == 0 && Value == 1,
       "IPV6_PKTINFO read back: %d %lu\n", WSAGetLastError(), Value);

    Value = 77;
    ok(setsockopt(a, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, sizeof(Value)) == 0,
       "IPV6_UNICAST_HOPS: %d\n", WSAGetLastError());

    Init6(&To, Loopback6, PortB);
    ok(sendto(a, "hello", 5, 0, (struct sockaddr *)&To, sizeof(To)) == 5, "sendto: %d\n", WSAGetLastError());
    ok(Readable(b, 3000), "WSARecvMsg: nothing received\n");

    memset(&Msg, 0, sizeof(Msg));
    memset(Control, 0xcc, sizeof(Control));
    Buf.buf = Data;
    Buf.len = sizeof(Data);
    Msg.name = (LPSOCKADDR)&From;
    Msg.namelen = sizeof(From);
    Msg.lpBuffers = &Buf;
    Msg.dwBufferCount = 1;
    Msg.Control.buf = Control;
    Msg.Control.len = sizeof(Control);
    Bytes = 0;
    Result = pWSARecvMsg(b, &Msg, &Bytes, NULL, NULL);
    ok(Result == 0 && Bytes == 5, "WSARecvMsg: %d %d %lu\n", Result, WSAGetLastError(), Bytes);
    ok(Msg.namelen == (int)sizeof(From) && From.sin6_port == PortA, "WSARecvMsg source: %d %u\n", Msg.namelen,
       ntohs(From.sin6_port));
    ok(Msg.dwFlags == 0, "WSARecvMsg flags %lx\n", Msg.dwFlags);
    trace("control length %lu\n", Msg.Control.len);

    for (Cmsg = WSA_CMSG_FIRSTHDR(&Msg); Cmsg; Cmsg = WSA_CMSG_NXTHDR(&Msg, Cmsg))
    {
        if (Cmsg->cmsg_level == IPPROTO_IPV6 && Cmsg->cmsg_type == IPV6_PKTINFO)
        {
            IN6_PKTINFO *Info = (IN6_PKTINFO *)WSA_CMSG_DATA(Cmsg);

            ok(Cmsg->cmsg_len == WSA_CMSG_LEN(sizeof(IN6_PKTINFO)), "IPV6_PKTINFO length %lu\n",
               (ULONG)Cmsg->cmsg_len);
            ok(!memcmp(&Info->ipi6_addr, Loopback6, 16), "IPV6_PKTINFO address\n");
            ok(Info->ipi6_ifindex != 0, "IPV6_PKTINFO interface 0\n");
            trace("IPV6_PKTINFO interface %lu\n", Info->ipi6_ifindex);
            Found |= 1;
        }
        else if (Cmsg->cmsg_level == IPPROTO_IPV6 && Cmsg->cmsg_type == IPV6_HOPLIMIT)
        {
            ok(Cmsg->cmsg_len == WSA_CMSG_LEN(sizeof(INT)), "IPV6_HOPLIMIT length %lu\n", (ULONG)Cmsg->cmsg_len);
            ok(*(INT *)WSA_CMSG_DATA(Cmsg) == 77, "IPV6_HOPLIMIT %d, expected 77\n", *(INT *)WSA_CMSG_DATA(Cmsg));
            Found |= 2;
        }
        else
        {
            ok(0, "control message %d/%d\n", Cmsg->cmsg_level, Cmsg->cmsg_type);
        }
    }
    ok(Found == 3, "control messages found: %d\n", Found);

Done:
    closesocket(a);
    closesocket(b);
}

static void TestMulticast(void)
{
    SOCKADDR_IN6_LH To;
    IPV6_MREQ Mreq;
    USHORT PortR, PortS;
    SOCKET r, s, other;
    DWORD Value;
    int Length;
    char Buffer[64];

    r = Udp6(TRUE, Any6, &PortR);
    s = Udp6(TRUE, Any6, &PortS);
    other = INVALID_SOCKET;
    if (r == INVALID_SOCKET || s == INVALID_SOCKET)
        goto Done;

    /* Defaults (Windows 10 oracle) */
    Value = 0xcc;
    Length = sizeof(Value);
    ok(getsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, &Length) == 0 && Value == 128,
       "IPV6_UNICAST_HOPS default: %d %lu\n", WSAGetLastError(), Value);
    Value = 0xcc;
    Length = sizeof(Value);
    ok(getsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&Value, &Length) == 0 && Value == 1,
       "IPV6_MULTICAST_HOPS default: %d %lu\n", WSAGetLastError(), Value);
    Value = 0xcc;
    Length = sizeof(Value);
    ok(getsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&Value, &Length) == 0 && Value == 1,
       "IPV6_MULTICAST_LOOP default: %d %lu\n", WSAGetLastError(), Value);

    Init6(&To, Group6, PortR);

    /* Not joined: nothing */
    ok(sendto(s, "x", 1, 0, (struct sockaddr *)&To, sizeof(To)) == 1, "sendto the group: %d\n", WSAGetLastError());
    ok(!Readable(r, 500), "a socket that did not join received the group's datagram\n");

    memset(&Mreq, 0, sizeof(Mreq));
    memcpy(&Mreq.ipv6mr_multiaddr, Group6, 16);
    Mreq.ipv6mr_interface = 0;
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == 0,
       "IPV6_ADD_MEMBERSHIP: %d\n", WSAGetLastError());
    /* The errors as Windows 10 answers them (oracle) */
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == SOCKET_ERROR &&
       WSAGetLastError() == WSAEINVAL, "a second IPV6_ADD_MEMBERSHIP: %d\n", WSAGetLastError());
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq) - 1) == SOCKET_ERROR &&
       WSAGetLastError() == WSAEFAULT, "short IPV6_ADD_MEMBERSHIP: %d\n", WSAGetLastError());

    /* Joined, looped back (on by default) */
    memset(Buffer, 'm', sizeof(Buffer));
    ok(sendto(s, Buffer, 40, 0, (struct sockaddr *)&To, sizeof(To)) == 40, "sendto the group: %d\n",
       WSAGetLastError());
    if (Readable(r, 3000))
    {
        SOCKADDR_IN6_LH From;
        int FromLength = sizeof(From);
        int Result = recvfrom(r, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &FromLength);

        ok(Result == 40, "group datagram: %d %d\n", Result, WSAGetLastError());
        ok(From.sin6_port == PortS, "group datagram source port %u\n", ntohs(From.sin6_port));
    }
    else
    {
        ok(0, "the member did not receive the group's datagram\n");
    }

    /* Another socket on the port that did not join gets none */
    {
        SOCKADDR_IN6_LH Sa;
        BOOL Reuse = TRUE;

        other = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(other, SOL_SOCKET, SO_REUSEADDR, (char *)&Reuse, sizeof(Reuse));
        Init6(&Sa, Any6, PortR);
        if (bind(other, (struct sockaddr *)&Sa, sizeof(Sa)) == 0)
        {
            sendto(s, Buffer, 8, 0, (struct sockaddr *)&To, sizeof(To));
            ok(!Readable(other, 500), "a non-member on the port received the group's datagram\n");
            if (Readable(r, 3000))
                recv(r, Buffer, sizeof(Buffer), 0);
        }
        else
        {
            trace("second bind on the port: %d\n", WSAGetLastError());
        }
    }

    /* Hop limit and loop options read back */
    Value = 5;
    ok(setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&Value, sizeof(Value)) == 0,
       "IPV6_MULTICAST_HOPS: %d\n", WSAGetLastError());
    Value = 0;
    Length = sizeof(Value);
    ok(getsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&Value, &Length) == 0 && Value == 5,
       "IPV6_MULTICAST_HOPS read back: %lu\n", Value);

    /* Left: nothing more */
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == 0,
       "IPV6_DROP_MEMBERSHIP: %d\n", WSAGetLastError());
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == SOCKET_ERROR &&
       WSAGetLastError() == WSAEADDRNOTAVAIL, "a second IPV6_DROP_MEMBERSHIP: %d\n", WSAGetLastError());
    sendto(s, Buffer, 8, 0, (struct sockaddr *)&To, sizeof(To));
    ok(!Readable(r, 500), "a socket that left the group received its datagram\n");

    /* An interface that does not exist; not a group (oracle: WSAEADDRNOTAVAIL both) */
    Mreq.ipv6mr_interface = 9999;
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == SOCKET_ERROR &&
       WSAGetLastError() == WSAEADDRNOTAVAIL, "IPV6_ADD_MEMBERSHIP on interface 9999: %d\n", WSAGetLastError());
    Mreq.ipv6mr_interface = 0;
    memcpy(&Mreq.ipv6mr_multiaddr, Loopback6, 16);
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == SOCKET_ERROR &&
       WSAGetLastError() == WSAEADDRNOTAVAIL, "IPV6_ADD_MEMBERSHIP of ::1: %d\n", WSAGetLastError());

Done:
    closesocket(r);
    closesocket(s);
    if (other != INVALID_SOCKET)
        closesocket(other);
}

/* Datagrams to a group sent back to back, the member reading each one before the next send: none is lost, whatever
   the sender is bound to and also when it is the member itself (its looped copies must reach it one by one) */
#define BURST_COUNT 100

static int MulticastBurst(const char *What, SOCKET Member, SOCKET Sender, USHORT MemberPort)
{
    SOCKADDR_IN6_LH To;
    int i, Lost = 0, Sent = 0;
    ULONG Out, In;

    Init6(&To, Group6, MemberPort);
    for (i = 0; i < BURST_COUNT; i++)
    {
        Out = 0x4d430000 + i;
        if (sendto(Sender, (char *)&Out, sizeof(Out), 0, (struct sockaddr *)&To, sizeof(To)) != sizeof(Out))
        {
            ok(0, "%s: sendto %d: %d\n", What, i, WSAGetLastError());
            return -1;
        }
        Sent++;
        if (Readable(Member, 1000))
        {
            In = 0;
            if (recv(Member, (char *)&In, sizeof(In), 0) != sizeof(In) || In != Out)
                ok(0, "%s: datagram %d reads %08lx\n", What, i, In);
        }
        else
        {
            Lost++;
        }
    }
    ok(Lost == 0, "%s: %d of %d group datagrams lost\n", What, Lost, Sent);
    return Lost;
}

static void TestMulticastBurst(void)
{
    IPV6_MREQ Mreq;
    USHORT PortR, PortS;
    SOCKET r, s, l;
    SOCKADDR_IN6_LH To;
    char Scratch[4];

    r = Udp6(TRUE, Any6, &PortR);
    s = Udp6(TRUE, Any6, &PortS);
    l = Udp6(TRUE, Loopback6, &PortS);
    if (r == INVALID_SOCKET || s == INVALID_SOCKET || l == INVALID_SOCKET)
        goto Done;

    memset(&Mreq, 0, sizeof(Mreq));
    memcpy(&Mreq.ipv6mr_multiaddr, Group6, 16);
    ok(setsockopt(r, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&Mreq, sizeof(Mreq)) == 0,
       "IPV6_ADD_MEMBERSHIP: %d\n", WSAGetLastError());

    /* No interface to send multicast on: nothing to test */
    Init6(&To, Group6, PortR);
    if (sendto(s, "x", 1, 0, (struct sockaddr *)&To, sizeof(To)) != 1)
    {
        skip("no multicast interface: %d\n", WSAGetLastError());
        goto Done;
    }
    if (Readable(r, 1000))
        recv(r, Scratch, sizeof(Scratch), 0);

    MulticastBurst("sender bound to ::", r, s, PortR);
    MulticastBurst("sender bound to ::1", r, l, PortR);
    MulticastBurst("the member as the sender", r, r, PortR);

Done:
    if (r != INVALID_SOCKET)
        closesocket(r);
    if (s != INVALID_SOCKET)
        closesocket(s);
    if (l != INVALID_SOCKET)
        closesocket(l);
}

static void TestTables(void)
{
    USHORT PortN;
    SOCKET s = Udp6(TRUE, Loopback6, &PortN);
    PMIB_UDP6TABLE_OWNER_PID Table;
    PMIB_UDPTABLE_OWNER_PID Table4;
    PMIB_UDP6TABLE Basic;
    DWORD Size = 0, Ret, i;
    BOOL Found = FALSE;

    if (s == INVALID_SOCKET)
        return;

    Ret = GetExtendedUdpTable(NULL, &Size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    ok(Ret == ERROR_INSUFFICIENT_BUFFER, "GetExtendedUdpTable(AF_INET6) size: %lu\n", Ret);
    Size += 1024;
    Table = HeapAlloc(GetProcessHeap(), 0, Size);
    Ret = GetExtendedUdpTable(Table, &Size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    ok(Ret == NO_ERROR, "GetExtendedUdpTable(AF_INET6): %lu\n", Ret);
    for (i = 0; Ret == NO_ERROR && i < Table->dwNumEntries; i++)
    {
        if (Table->table[i].dwLocalPort == PortN && !memcmp(Table->table[i].ucLocalAddr, Loopback6, 16))
        {
            Found = TRUE;
            ok(Table->table[i].dwOwningPid == GetCurrentProcessId(), "row pid %lu\n", Table->table[i].dwOwningPid);
        }
    }
    ok(Found, "the socket is not in the IPv6 UDP table\n");
    HeapFree(GetProcessHeap(), 0, Table);

    /* Not in the IPv4 table */
    Size = 0;
    GetExtendedUdpTable(NULL, &Size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    Size += 1024;
    Table4 = HeapAlloc(GetProcessHeap(), 0, Size);
    Ret = GetExtendedUdpTable(Table4, &Size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    ok(Ret == NO_ERROR, "GetExtendedUdpTable(AF_INET): %lu\n", Ret);
    for (i = 0; Ret == NO_ERROR && i < Table4->dwNumEntries; i++)
    {
        ok(!(Table4->table[i].dwLocalPort == PortN && Table4->table[i].dwOwningPid == GetCurrentProcessId()),
           "the IPv6 socket is a row of the IPv4 table\n");
    }
    HeapFree(GetProcessHeap(), 0, Table4);

    /* The basic class */
    Size = 0;
    GetExtendedUdpTable(NULL, &Size, TRUE, AF_INET6, UDP_TABLE_BASIC, 0);
    Size += 1024;
    Basic = HeapAlloc(GetProcessHeap(), 0, Size);
    Ret = GetExtendedUdpTable(Basic, &Size, TRUE, AF_INET6, UDP_TABLE_BASIC, 0);
    ok(Ret == NO_ERROR, "GetExtendedUdpTable(AF_INET6, basic): %lu\n", Ret);
    Found = FALSE;
    for (i = 0; Ret == NO_ERROR && i < Basic->dwNumEntries; i++)
        Found |= (Basic->table[i].dwLocalPort == PortN && !memcmp(&Basic->table[i].dwLocalAddr, Loopback6, 16));
    ok(Found, "the socket is not in the basic IPv6 UDP table\n");
    HeapFree(GetProcessHeap(), 0, Basic);

    closesocket(s);
}

START_TEST(ipv6udp)
{
    WSADATA wsaData;
    SOCKET s;

    ok(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, "WSAStartup failed\n");

    if (!Ipv6SocketsOn() || !(Ipv6StackFlags() & TEST_IPV6_STATE_DATAGRAMS))
    {
        /* No IPv6 datagram sockets: the answer of a system without them */
        s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        ok(s == INVALID_SOCKET && WSAGetLastError() == WSAEAFNOSUPPORT, "socket(AF_INET6, SOCK_DGRAM): %d\n",
           s == INVALID_SOCKET ? WSAGetLastError() : 0);
        if (s != INVALID_SOCKET)
            closesocket(s);
        skip("the stack has no IPv6 datagram sockets (state 0x%lx)\n", Ipv6StackFlags());
        WSACleanup();
        return;
    }

    TestLoopback();
    TestDualStack();
    TestRecvMsg();
    TestMulticast();
    TestMulticastBurst();
    TestTables();

    WSACleanup();
}
