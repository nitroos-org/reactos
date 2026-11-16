/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Raw sockets (AF_INET and AF_INET6): who may open them and what an unprivileged one may do, raw
 *              ICMPv6 echo on ::1, the header-include options; UDP port unreachable as WSAECONNRESET on the next
 *              receive (SIO_UDP_CONNRESET) for both families; the IPv6 socket options IPV6_RECVIF,
 *              IPV6_RECVTCLASS, IPV6_UNICAST_IF, IPV6_MTU_DISCOVER, IPV6_TCLASS, IPV6_MTU.
 *              Expected values are Windows Server 2022 and Windows 10 22H2 answers (evidence v6raw-20261116). The
 *              standard user is a token of this process with Administrators, LocalSystem, LocalService and
 *              NetworkService made deny-only, impersonated while the sockets are made and used.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#define T_IPV6_HDRINCL      2
#define T_IPV6_RECVIF       24
#define T_IPV6_UNICAST_IF   31
#define T_IPV6_TCLASS       39
#define T_IPV6_RECVTCLASS   40
#define T_IPV6_MTU_DISCOVER 71
#define T_IPV6_MTU          72
#define T_IPPROTO_ICMPV6    58

static const UCHAR Loopback6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
/* The stack makes IPv6 sockets (not with Tcpip\\Parameters\\Ipv6Enable 0 on this stack): the IPv6 rows run only then */
static BOOL Have6;

static void Init6(SOCKADDR_IN6_LH *Sa, USHORT PortN)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    Sa->sin6_port = PortN;
    memcpy(&Sa->sin6_addr, Loopback6, 16);
}

static void Init4(struct sockaddr_in *Sa, USHORT PortN)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin_family = AF_INET;
    Sa->sin_port = PortN;
    Sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static BOOL IsPrivileged(void)
{
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    PSID Admins;
    BOOL Member = FALSE;

    if (AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins))
    {
        CheckTokenMembership(NULL, Admins, &Member);
        FreeSid(Admins);
    }
    return Member;
}

/* This process's token with the groups that may use any raw socket made deny-only, as an impersonation token */
static HANDLE StandardUserToken(void)
{
    static const ULONG Rids[][2] = { { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS },
                                     { SECURITY_LOCAL_SYSTEM_RID, 0 },
                                     { SECURITY_LOCAL_SERVICE_RID, 0 },
                                     { SECURITY_NETWORK_SERVICE_RID, 0 } };
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    SID_AND_ATTRIBUTES Disable[4];
    HANDLE Token = NULL, Restricted = NULL, Impersonation = NULL;
    ULONG i;

    for (i = 0; i < 4; i++)
    {
        Disable[i].Attributes = 0;
        if (!AllocateAndInitializeSid(&Nt, Rids[i][1] ? 2 : 1, Rids[i][0], Rids[i][1], 0, 0, 0, 0, 0, 0,
                                      &Disable[i].Sid))
            return NULL;
    }
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token) &&
        CreateRestrictedToken(Token, 0, 4, Disable, 0, NULL, 0, NULL, &Restricted))
    {
        if (!DuplicateToken(Restricted, SecurityImpersonation, &Impersonation))
            Impersonation = NULL;
    }
    if (Restricted)
        CloseHandle(Restricted);
    if (Token)
        CloseHandle(Token);
    for (i = 0; i < 4; i++)
        FreeSid(Disable[i].Sid);
    return Impersonation;
}

/* Waits up to Ms for a datagram */
static int RecvWait(SOCKET s, char *Buffer, int Size, DWORD Ms, int *Error)
{
    fd_set Set;
    struct timeval Tv;
    int Result;

    FD_ZERO(&Set);
    FD_SET(s, &Set);
    Tv.tv_sec = Ms / 1000;
    Tv.tv_usec = (Ms % 1000) * 1000;
    if (select(0, &Set, NULL, NULL, &Tv) != 1)
    {
        *Error = WSAETIMEDOUT;
        return SOCKET_ERROR;
    }
    Result = recvfrom(s, Buffer, Size, 0, NULL, NULL);
    *Error = (Result == SOCKET_ERROR) ? WSAGetLastError() : 0;
    return Result;
}

/* An ICMPv6 echo request to ::1 through a raw socket: the reply comes without an IPv6 header, the checksum the
   stack put in whatever the data held */
static void Echo6(SOCKET s, const char *Label, USHORT Checksum)
{
    SOCKADDR_IN6_LH To;
    UCHAR Request[16], Reply[64];
    int Result, Error, Tries;

    Init6(&To, 0);
    memset(Request, 0x5a, sizeof(Request));
    Request[0] = 128; Request[1] = 0;
    Request[2] = (UCHAR)(Checksum >> 8); Request[3] = (UCHAR)Checksum;
    Request[4] = 0x6b; Request[5] = 0x72; Request[6] = 0; Request[7] = 1;
    Result = sendto(s, (char *)Request, sizeof(Request), 0, (struct sockaddr *)&To, sizeof(To));
    ok(Result == (int)sizeof(Request), "%s: sendto %d, error %d\n", Label, Result, WSAGetLastError());

    /* The reply (type 129); the stack does not give the request it answers itself to the socket */
    for (Tries = 0; Tries < 4; Tries++)
    {
        Result = RecvWait(s, (char *)Reply, sizeof(Reply), 2000, &Error);
        if (Result == SOCKET_ERROR || Reply[0] != 128)
            break;
    }
    ok(Result == (int)sizeof(Request), "%s: reply %d, error %d\n", Label, Result, Error);
    if (Result == (int)sizeof(Request))
    {
        ok(Reply[0] == 129 && Reply[1] == 0, "%s: reply type %u code %u (an IPv6 header in front?)\n", Label,
           Reply[0], Reply[1]);
        ok(!memcmp(Reply + 4, Request + 4, sizeof(Request) - 4), "%s: reply data differs\n", Label);
    }
}

static void TestRawAccess(BOOL Privileged)
{
    static const int Protocols[] = { 0, IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_TCP, IPPROTO_UDP, 41, 50, T_IPPROTO_ICMPV6,
                                     59, 103, 253, 255 };
    static const int Families[] = { AF_INET, AF_INET6 };
    const char *Who = Privileged ? "admin" : "standard";
    int f, i, Error, Value;
    SOCKET s;

    for (f = 0; f < (Have6 ? 2 : 1); f++)
    {
        for (i = 0; i < (int)(sizeof(Protocols) / sizeof(Protocols[0])); i++)
        {
            BOOL Icmp = (Protocols[i] == IPPROTO_ICMP || Protocols[i] == T_IPPROTO_ICMPV6);
            int Result;

            s = socket(Families[f], SOCK_RAW, Protocols[i]);
            Error = WSAGetLastError();
            if (Privileged || Icmp)
            {
                ok(s != INVALID_SOCKET, "%s: socket(%d, SOCK_RAW, %d) failed %d\n", Who, Families[f], Protocols[i],
                   Error);
            }
            else
            {
                ok(s == INVALID_SOCKET && Error == WSAEACCES, "%s: socket(%d, SOCK_RAW, %d): %d error %d\n", Who,
                   Families[f], Protocols[i], s != INVALID_SOCKET, Error);
            }
            if (s == INVALID_SOCKET)
                continue;

            /* The header-include option: an administrator's */
            Value = 1;
            Result = setsockopt(s, Families[f] == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                                Families[f] == AF_INET6 ? T_IPV6_HDRINCL : IP_HDRINCL, (char *)&Value, sizeof(Value));
            Error = WSAGetLastError();
            if (Privileged)
            {
                int Got = -1, Length = sizeof(Got);

                ok(Result == 0, "%s: HDRINCL on %d/%d: %d\n", Who, Families[f], Protocols[i], Error);
                Result = getsockopt(s, Families[f] == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP,
                                    Families[f] == AF_INET6 ? T_IPV6_HDRINCL : IP_HDRINCL, (char *)&Got, &Length);
                ok(Result == 0 && Got == 1, "%s: HDRINCL reads %d (%d, error %d)\n", Who, Got, Result,
                   WSAGetLastError());
            }
            else
            {
                ok(Result == SOCKET_ERROR && Error == WSAEACCES, "%s: HDRINCL on %d/%d: %d error %d\n", Who,
                   Families[f], Protocols[i], Result, Error);
            }
            closesocket(s);
        }
    }
}

/* What a standard user's ICMP sockets may send: echo requests of 8 bytes or more of their own family */
static void TestUnprivilegedSend(void)
{
    static const UCHAR Types6[] = { 129, 1, 3, 133, 135, 136, 200 };
    static const UCHAR Types4[] = { 0, 3, 5, 13 };
    SOCKADDR_IN6_LH To6;
    struct sockaddr_in To4;
    UCHAR Packet[16];
    int i, Result, Error;
    SOCKET s;

    Init6(&To6, 0);
    Init4(&To4, 0);

    s = Have6 ? socket(AF_INET6, SOCK_RAW, T_IPPROTO_ICMPV6) : INVALID_SOCKET;
    ok(!Have6 || s != INVALID_SOCKET, "standard: ICMPv6 socket %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
    {
        for (i = 0; i < (int)sizeof(Types6); i++)
        {
            memset(Packet, 0, sizeof(Packet));
            Packet[0] = Types6[i];
            Result = sendto(s, (char *)Packet, 8, 0, (struct sockaddr *)&To6, sizeof(To6));
            Error = WSAGetLastError();
            ok(Result == SOCKET_ERROR && Error == WSAEACCES, "standard: ICMPv6 type %u sent (%d, error %d)\n",
               Types6[i], Result, Error);
        }
        memset(Packet, 0, sizeof(Packet));
        Packet[0] = 128;
        Result = sendto(s, (char *)Packet, 4, 0, (struct sockaddr *)&To6, sizeof(To6));
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEACCES, "standard: 4-byte echo request sent (%d, %d)\n", Result,
           Error);
        Echo6(s, "standard echo6", 0);
        closesocket(s);
    }

    s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ok(s != INVALID_SOCKET, "standard: ICMP socket %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
    {
        for (i = 0; i < (int)sizeof(Types4); i++)
        {
            memset(Packet, 0, sizeof(Packet));
            Packet[0] = Types4[i];
            Result = sendto(s, (char *)Packet, 8, 0, (struct sockaddr *)&To4, sizeof(To4));
            Error = WSAGetLastError();
            ok(Result == SOCKET_ERROR && Error == WSAEACCES, "standard: ICMP type %u sent (%d, error %d)\n",
               Types4[i], Result, Error);
        }
        memset(Packet, 0, sizeof(Packet));
        Packet[0] = 8;
        Packet[2] = 0xf7; Packet[3] = 0xff;    /* the checksum of an all-zero echo request */
        Result = sendto(s, (char *)Packet, 8, 0, (struct sockaddr *)&To4, sizeof(To4));
        ok(Result == 8, "standard: echo request %d, error %d\n", Result, WSAGetLastError());
        closesocket(s);
    }

    /* The other family's ICMP in a socket: may be made, may not send */
    s = Have6 ? socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP) : INVALID_SOCKET;
    ok(!Have6 || s != INVALID_SOCKET, "standard: AF_INET6 ICMP socket %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
    {
        memset(Packet, 0, sizeof(Packet));
        Packet[0] = 8;
        Result = sendto(s, (char *)Packet, 8, 0, (struct sockaddr *)&To6, sizeof(To6));
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEACCES, "standard: ICMP over IPv6 sent (%d, %d)\n", Result, Error);
        closesocket(s);
    }
}

/* An administrator's raw ICMPv6 socket: echo with a zero and a wrong checksum, a second socket bound to ::1 gets the
   reply as well, and another protocol's packets reach that protocol's sockets without the IPv6 header */
static void TestRaw6(void)
{
    SOCKADDR_IN6_LH To, Bound;
    char Data[32], In[64];
    int Result, Error;
    SOCKET s, t, a, b;

    s = socket(AF_INET6, SOCK_RAW, T_IPPROTO_ICMPV6);
    ok(s != INVALID_SOCKET, "admin: ICMPv6 socket %d\n", WSAGetLastError());
    if (s == INVALID_SOCKET)
        return;
    Echo6(s, "echo6 checksum 0", 0);
    Echo6(s, "echo6 checksum wrong", 0x1234);

    t = socket(AF_INET6, SOCK_RAW, T_IPPROTO_ICMPV6);
    Init6(&Bound, 0);
    ok(bind(t, (struct sockaddr *)&Bound, sizeof(Bound)) == 0, "bind ::1: %d\n", WSAGetLastError());
    Echo6(s, "echo6 second socket (sender)", 0);
    Result = RecvWait(t, In, sizeof(In), 2000, &Error);
    ok(Result == 16 && (UCHAR)In[0] == 129, "the bound socket got %d (type %u), error %d\n", Result, (UCHAR)In[0],
       Error);
    closesocket(t);
    closesocket(s);

    /* Protocol 253 (experimental): one socket sends, both get it, without a header */
    a = socket(AF_INET6, SOCK_RAW, 253);
    b = socket(AF_INET6, SOCK_RAW, 253);
    ok(a != INVALID_SOCKET && b != INVALID_SOCKET, "admin: protocol 253 sockets %d\n", WSAGetLastError());
    if (a != INVALID_SOCKET && b != INVALID_SOCKET)
    {
        /* An unbound raw socket cannot receive (Windows: WSAEINVAL) */
        Result = recvfrom(b, In, sizeof(In), 0, NULL, NULL);
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEINVAL, "recvfrom unbound raw: %d %d\n", Result, Error);
        Init6(&Bound, 0);
        memset(&Bound.sin6_addr, 0, 16);
        ok(bind(b, (struct sockaddr *)&Bound, sizeof(Bound)) == 0, "bind ::: %d\n", WSAGetLastError());
        Init6(&To, 0);
        memcpy(Data, "proto253-payload", 16);
        Result = sendto(a, Data, 16, 0, (struct sockaddr *)&To, sizeof(To));
        ok(Result == 16, "sendto 253: %d %d\n", Result, WSAGetLastError());
        Result = RecvWait(b, In, sizeof(In), 2000, &Error);
        ok(Result == 16 && !memcmp(In, Data, 16), "receiver got %d, error %d\n", Result, Error);
        Result = RecvWait(a, In, sizeof(In), 2000, &Error);
        ok(Result == 16 && !memcmp(In, Data, 16), "sender got %d, error %d\n", Result, Error);
    }
    if (a != INVALID_SOCKET) closesocket(a);
    if (b != INVALID_SOCKET) closesocket(b);

    /* The largest raw datagram: 65535 (65536 is WSAEMSGSIZE); to this machine the stack's limit is lower */
    s = socket(AF_INET6, SOCK_RAW, 253);
    if (s != INVALID_SOCKET)
    {
        char *Big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);

        Init6(&To, 0);
        Result = sendto(s, Big, 65536, 0, (struct sockaddr *)&To, sizeof(To));
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAEMSGSIZE, "raw 65536: %d %d\n", Result, Error);
        Result = sendto(s, Big, 65495, 0, (struct sockaddr *)&To, sizeof(To));
        ok(Result == 65495, "raw 65495 to ::1: %d %d\n", Result, WSAGetLastError());
        HeapFree(GetProcessHeap(), 0, Big);
        closesocket(s);
    }
}

/* A UDP datagram to a port nobody has on the loopback address: the next receive fails with WSAECONNRESET, once
   per datagram, not with SIO_UDP_CONNRESET off; connected or not; IPv4 and IPv6 */
static void ConnReset(int Family, BOOL Off, BOOL Connect)
{
    struct sockaddr_storage Any, To, Name;
    int Length = sizeof(Name), ToLength, Result, Error;
    BOOL Flag = FALSE;
    DWORD Returned;
    char Buffer[16] = "probe";
    const char *Label = Family == AF_INET6 ? (Off ? "v6 off" : (Connect ? "v6 connected" : "v6"))
                                           : (Off ? "v4 off" : (Connect ? "v4 connected" : "v4"));
    SOCKET s = socket(Family, SOCK_DGRAM, IPPROTO_UDP), Closed = socket(Family, SOCK_DGRAM, IPPROTO_UDP);

    ok(s != INVALID_SOCKET && Closed != INVALID_SOCKET, "%s: sockets %d\n", Label, WSAGetLastError());
    if (s == INVALID_SOCKET || Closed == INVALID_SOCKET)
        return;

    memset(&Any, 0, sizeof(Any));
    if (Family == AF_INET6)
    {
        Init6((SOCKADDR_IN6_LH *)&To, 0);
        ((SOCKADDR_IN6_LH *)&Any)->sin6_family = AF_INET6;
        ToLength = sizeof(SOCKADDR_IN6_LH);
    }
    else
    {
        Init4((struct sockaddr_in *)&To, 0);
        ((struct sockaddr_in *)&Any)->sin_family = AF_INET;
        ToLength = sizeof(struct sockaddr_in);
    }
    /* A port that nobody has: bound by a socket that is then closed */
    ok(bind(Closed, (struct sockaddr *)&To, ToLength) == 0, "%s: bind %d\n", Label, WSAGetLastError());
    ok(getsockname(Closed, (struct sockaddr *)&Name, &Length) == 0, "%s: getsockname %d\n", Label, WSAGetLastError());
    closesocket(Closed);
    if (Family == AF_INET6)
        ((SOCKADDR_IN6_LH *)&To)->sin6_port = ((SOCKADDR_IN6_LH *)&Name)->sin6_port;
    else
        ((struct sockaddr_in *)&To)->sin_port = ((struct sockaddr_in *)&Name)->sin_port;

    ok(bind(s, (struct sockaddr *)&Any, ToLength) == 0, "%s: bind %d\n", Label, WSAGetLastError());
    if (Off)
    {
        Result = WSAIoctl(s, SIO_UDP_CONNRESET, &Flag, sizeof(Flag), NULL, 0, &Returned, NULL, NULL);
        ok(Result == 0, "%s: SIO_UDP_CONNRESET %d\n", Label, WSAGetLastError());
    }
    if (Connect)
    {
        ok(connect(s, (struct sockaddr *)&To, ToLength) == 0, "%s: connect %d\n", Label, WSAGetLastError());
        Result = send(s, Buffer, 5, 0);
    }
    else
    {
        Result = sendto(s, Buffer, 5, 0, (struct sockaddr *)&To, ToLength);
    }
    ok(Result == 5, "%s: send %d %d\n", Label, Result, WSAGetLastError());

    Result = RecvWait(s, Buffer, sizeof(Buffer), 1500, &Error);
    /* The stack rate limits its ICMP errors (as Windows does): right after a test that sent many datagrams to
       closed ports there may be none to give for a second; the datagram is sent once more then */
    if (!Off && Result == SOCKET_ERROR && Error == WSAETIMEDOUT)
    {
        Sleep(1000);
        if (Connect)
            send(s, "probe", 5, 0);
        else
            sendto(s, "probe", 5, 0, (struct sockaddr *)&To, ToLength);
        Result = RecvWait(s, Buffer, sizeof(Buffer), 1500, &Error);
    }
    if (Off)
        ok(Result == SOCKET_ERROR && Error == WSAETIMEDOUT, "%s: receive %d error %d (nothing expected)\n", Label,
           Result, Error);
    else
        ok(Result == SOCKET_ERROR && Error == WSAECONNRESET, "%s: receive %d error %d (WSAECONNRESET expected)\n",
           Label, Result, Error);
    /* Only once */
    Result = RecvWait(s, Buffer, sizeof(Buffer), 500, &Error);
    ok(Result == SOCKET_ERROR && Error == WSAETIMEDOUT, "%s: second receive %d error %d\n", Label, Result, Error);

    /* The socket still works: a datagram to itself arrives */
    if (!Connect)
    {
        Length = sizeof(Name);
        getsockname(s, (struct sockaddr *)&Name, &Length);
        if (Family == AF_INET6)
            memcpy(&((SOCKADDR_IN6_LH *)&Name)->sin6_addr, Loopback6, 16);
        else
            ((struct sockaddr_in *)&Name)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        Result = sendto(s, "self", 4, 0, (struct sockaddr *)&Name, Length);
        ok(Result == 4, "%s: send to itself %d %d\n", Label, Result, WSAGetLastError());
        Result = RecvWait(s, Buffer, sizeof(Buffer), 2000, &Error);
        ok(Result == 4, "%s: datagram after the reset %d error %d\n", Label, Result, Error);
    }
    closesocket(s);
}

/* ---- Windows parity rows measured on the Windows Server 2022 peer (evidence rawfu-20261116) ---- */

static USHORT Sum16(const UCHAR *Data, int Length, ULONG Sum)
{
    for (; Length > 1; Data += 2, Length -= 2)
        Sum += (Data[0] << 8) | Data[1];
    if (Length)
        Sum += Data[0] << 8;
    while (Sum >> 16)
        Sum = (Sum & 0xFFFF) + (Sum >> 16);
    return (USHORT)~Sum;
}

/* An ICMP destination unreachable (port) as a whole IPv4 packet on 127.0.0.1: the invoking datagram came from
   127.0.0.1:InnerSrcPort and went to InnerDst:InnerDstPort (host order ports, InnerDst network order) */
static int Build4Unreachable(UCHAR *Pkt, ULONG InnerDst, USHORT InnerSrcPort, USHORT InnerDstPort)
{
    ULONG Lo = htonl(INADDR_LOOPBACK);
    USHORT Sum;

    memset(Pkt, 0, 56);
    Pkt[0] = 0x45; Pkt[3] = 56; Pkt[8] = 128; Pkt[9] = 1;
    memcpy(Pkt + 12, &Lo, 4); memcpy(Pkt + 16, &Lo, 4);
    Sum = Sum16(Pkt, 20, 0); Pkt[10] = Sum >> 8; Pkt[11] = Sum & 255;
    Pkt[20] = 3; Pkt[21] = 3;                                   /* port unreachable */
    Pkt[28] = 0x45; Pkt[31] = 32; Pkt[36] = 128; Pkt[37] = 17;   /* the invoking datagram: UDP, 4 data bytes */
    memcpy(Pkt + 40, &Lo, 4); memcpy(Pkt + 44, &InnerDst, 4);
    Sum = Sum16(Pkt + 28, 20, 0); Pkt[38] = Sum >> 8; Pkt[39] = Sum & 255;
    Pkt[48] = InnerSrcPort >> 8; Pkt[49] = InnerSrcPort & 255; Pkt[50] = InnerDstPort >> 8; Pkt[51] = InnerDstPort & 255;
    Pkt[53] = 12;
    Sum = Sum16(Pkt + 20, 36, 0); Pkt[22] = Sum >> 8; Pkt[23] = Sum & 255;
    return 56;
}

/* The same for IPv6 on ::1 (ICMPv6 type 1 code 4, checksum with the pseudo header) */
static int Build6Unreachable(UCHAR *Pkt, const UCHAR *InnerDst, USHORT InnerSrcPort, USHORT InnerDstPort)
{
    UCHAR Pseudo[40];
    ULONG Sum;
    USHORT Fold;

    memset(Pkt, 0, 96);
    Pkt[0] = 0x60; Pkt[5] = 56; Pkt[6] = 58; Pkt[7] = 64;
    memcpy(Pkt + 8, Loopback6, 16); memcpy(Pkt + 24, Loopback6, 16);
    Pkt[40] = 1; Pkt[41] = 4;
    Pkt[48] = 0x60; Pkt[53] = 12; Pkt[54] = 17; Pkt[55] = 128;
    memcpy(Pkt + 56, Loopback6, 16); memcpy(Pkt + 72, InnerDst, 16);
    Pkt[88] = InnerSrcPort >> 8; Pkt[89] = InnerSrcPort & 255; Pkt[90] = InnerDstPort >> 8; Pkt[91] = InnerDstPort & 255;
    Pkt[93] = 12;
    memset(Pseudo, 0, sizeof(Pseudo));
    memcpy(Pseudo, Loopback6, 16); memcpy(Pseudo + 16, Loopback6, 16);
    Pseudo[35] = 56; Pseudo[39] = 58;
    Sum = (USHORT)~Sum16(Pseudo, 40, 0);
    Fold = Sum16(Pkt + 40, 56, Sum);
    Pkt[42] = Fold >> 8; Pkt[43] = Fold & 255;
    return 96;
}

static USHORT PortOf(SOCKET s, int Family)
{
    struct sockaddr_storage Name;
    int Length = sizeof(Name);

    getsockname(s, (struct sockaddr *)&Name, &Length);
    return Family == AF_INET6 ? ((SOCKADDR_IN6_LH *)&Name)->sin6_port : ((struct sockaddr_in *)&Name)->sin_port;
}

/* An ICMP or ICMPv6 port unreachable is matched to a UDP socket by the local port of its invoking datagram: Windows
   resets a connected socket (and an unconnected one) whatever destination address or port the invoking datagram
   names, and not when the source port is another (peer row: crafted messages from another host, fire wall off,
   both families, 64 and 32 bit). Needs a privileged process: the message is made by hand through a raw socket with
   a header of its own */
static void TestInnerDestination(int Family, BOOL Connect)
{
    static const char *Names[] = { "same destination", "other port", "other address", "other source port" };
    static const UCHAR Other6[16] = { 0xfd,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x77,0x77 };
    struct sockaddr_storage Lo;
    SOCKET s, Peer, Raw;
    UCHAR Pkt[128];
    DWORD One = 1;
    USHORT SPort, PPort;
    int i, Length, Result, Error, SaLen = Family == AF_INET6 ? (int)sizeof(SOCKADDR_IN6_LH) : (int)sizeof(struct sockaddr_in);
    char Label[64], Buf[16];
    BOOL Control = TRUE;

    if (Family == AF_INET6)
        Init6((SOCKADDR_IN6_LH *)&Lo, 0);
    else
        Init4((struct sockaddr_in *)&Lo, 0);
    sprintf(Label, "inner destination v%d%s", Family == AF_INET6 ? 6 : 4, Connect ? " connected" : "");

    Raw = Family == AF_INET6 ? socket(AF_INET6, SOCK_RAW, T_IPPROTO_ICMPV6) : socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    ok(Raw != INVALID_SOCKET, "%s: raw socket %d\n", Label, WSAGetLastError());
    if (Raw == INVALID_SOCKET)
        return;
    Result = setsockopt(Raw, Family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP, Family == AF_INET6 ? T_IPV6_HDRINCL : IP_HDRINCL,
                        (char *)&One, sizeof(One));
    ok(Result == 0, "%s: HDRINCL %d\n", Label, WSAGetLastError());

    Peer = socket(Family, SOCK_DGRAM, IPPROTO_UDP);
    ok(bind(Peer, (struct sockaddr *)&Lo, SaLen) == 0, "%s: bind peer %d\n", Label, WSAGetLastError());
    PPort = ntohs(PortOf(Peer, Family));

    for (i = 0; i < 4; i++)
    {
        s = socket(Family, SOCK_DGRAM, IPPROTO_UDP);
        ok(bind(s, (struct sockaddr *)&Lo, SaLen) == 0, "%s: bind %d\n", Label, WSAGetLastError());
        SPort = ntohs(PortOf(s, Family));
        if (Connect)
        {
            if (Family == AF_INET6)
                ((SOCKADDR_IN6_LH *)&Lo)->sin6_port = htons(PPort);
            else
                ((struct sockaddr_in *)&Lo)->sin_port = htons(PPort);
            ok(connect(s, (struct sockaddr *)&Lo, SaLen) == 0, "%s: connect %d\n", Label, WSAGetLastError());
            if (Family == AF_INET6)
                ((SOCKADDR_IN6_LH *)&Lo)->sin6_port = 0;
            else
                ((struct sockaddr_in *)&Lo)->sin_port = 0;
        }

        if (Family == AF_INET6)
        {
            Length = Build6Unreachable(Pkt, i == 2 ? Other6 : Loopback6, i == 3 ? SPort + 1 : SPort,
                                       i == 1 ? PPort + 1 : PPort);
            Result = sendto(Raw, (char *)Pkt, Length, 0, (struct sockaddr *)&Lo, SaLen);
        }
        else
        {
            Length = Build4Unreachable(Pkt, i == 2 ? htonl(0x7F000063) : htonl(INADDR_LOOPBACK), i == 3 ? SPort + 1 : SPort,
                                       i == 1 ? PPort + 1 : PPort);
            Result = sendto(Raw, (char *)Pkt, Length, 0, (struct sockaddr *)&Lo, SaLen);
        }
        ok(Result == Length, "%s (%s): crafted send %d error %d\n", Label, Names[i], Result, WSAGetLastError());

        Result = RecvWait(s, Buf, sizeof(Buf), i == 0 ? 1500 : 1000, &Error);
        if (i == 0 && Result == SOCKET_ERROR && Error == WSAETIMEDOUT)
        {
            /* The rows need a message that a raw socket sent to this machine to arrive (Windows does not deliver an
               ICMPv6 one to ::1; this stack does not honour a header of its own in IPv4 raw sends): no verdict */
            skip("%s: a hand-made message to the loopback address is not delivered\n", Label);
            Control = FALSE;
        }
        else if (i == 3)
        {
            ok(Result == SOCKET_ERROR && Error == WSAETIMEDOUT, "%s (%s): receive %d error %d (nothing expected)\n", Label,
               Names[i], Result, Error);
        }
        else if (Control)
        {
            ok(Result == SOCKET_ERROR && Error == WSAECONNRESET, "%s (%s): receive %d error %d (WSAECONNRESET expected)\n",
               Label, Names[i], Result, Error);
        }
        closesocket(s);
        if (!Control)
            break;
    }
    closesocket(Peer);
    closesocket(Raw);
}

/* recv(MSG_PEEK) of a queued port unreachable report does not consume it: every peek fails WSAECONNRESET, so does
   the first receive, the one after it does not (Windows Server 2022, both families, 64 and 32 bit; a datagram that
   arrives after the report is behind it) */
static void TestPeekReport(int Family, int Variant)
{
    struct sockaddr_storage Lo, Closed;
    SOCKET s, t;
    char Buf[16], Label[48];
    int i, Result, Error, SaLen = Family == AF_INET6 ? (int)sizeof(SOCKADDR_IN6_LH) : (int)sizeof(struct sockaddr_in), Length;

    sprintf(Label, "peek v%d %s", Family == AF_INET6 ? 6 : 4, Variant == 0 ? "connected" : (Variant == 1 ? "unconnected" : "data behind"));
    if (Family == AF_INET6)
        Init6((SOCKADDR_IN6_LH *)&Lo, 0);
    else
        Init4((struct sockaddr_in *)&Lo, 0);
    s = socket(Family, SOCK_DGRAM, IPPROTO_UDP);
    t = socket(Family, SOCK_DGRAM, IPPROTO_UDP);
    ok(bind(s, (struct sockaddr *)&Lo, SaLen) == 0, "%s: bind %d\n", Label, WSAGetLastError());
    ok(bind(t, (struct sockaddr *)&Lo, SaLen) == 0, "%s: bind %d\n", Label, WSAGetLastError());
    Length = sizeof(Closed);
    getsockname(t, (struct sockaddr *)&Closed, &Length);
    closesocket(t);                           /* a port nobody has */

    if (Variant == 0)
    {
        ok(connect(s, (struct sockaddr *)&Closed, SaLen) == 0, "%s: connect %d\n", Label, WSAGetLastError());
        Result = send(s, "x", 1, 0);
    }
    else
    {
        Result = sendto(s, "x", 1, 0, (struct sockaddr *)&Closed, SaLen);
    }
    ok(Result == 1, "%s: send %d %d\n", Label, Result, WSAGetLastError());
    Sleep(700);
    if (Variant == 2)
    {
        struct sockaddr_storage To = Lo;

        t = socket(Family, SOCK_DGRAM, IPPROTO_UDP);
        if (Family == AF_INET6)
            ((SOCKADDR_IN6_LH *)&To)->sin6_port = PortOf(s, Family);
        else
            ((struct sockaddr_in *)&To)->sin_port = PortOf(s, Family);
        ok(sendto(t, "DATA", 4, 0, (struct sockaddr *)&To, SaLen) == 4, "%s: data send %d\n", Label, WSAGetLastError());
        closesocket(t);
        Sleep(300);
    }

    for (i = 1; i <= 3; i++)
    {
        Result = recv(s, Buf, sizeof(Buf), MSG_PEEK);
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAECONNRESET, "%s: peek %d returned %d error %d\n", Label, i, Result, Error);
    }
    Result = recv(s, Buf, sizeof(Buf), 0);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR && Error == WSAECONNRESET, "%s: receive after the peeks %d error %d\n", Label, Result, Error);
    Result = RecvWait(s, Buf, sizeof(Buf), 800, &Error);
    if (Variant == 2)
        ok(Result == 4 && !memcmp(Buf, "DATA", 4), "%s: the datagram behind the report: %d error %d\n", Label, Result, Error);
    else
        ok(Result == SOCKET_ERROR && Error == WSAETIMEDOUT, "%s: second receive %d error %d\n", Label, Result, Error);
    closesocket(s);
}

/* IPV6_HDRINCL on a privileged raw socket sends a header whose source is not an address of this machine (Windows
   Server 2022 put such packets on the wire for an administrator, with a global, a unique-local, another link-local
   and the unspecified source); to ::1 the receiving raw socket gets the payload */
static void TestHdrInclSource6(void)
{
    static const UCHAR Sources[][16] = {
        { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 },
        { 0xfd,0x00,0x5e,0xad, 0,0,0,0, 0,0,0,0, 0,0,0,1 },
        { 0xfe,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x12,0x34 } };
    SOCKADDR_IN6_LH To, Bound;
    SOCKET Tx, Rx;
    DWORD One = 1;
    UCHAR Pkt[64];
    char In[64];
    int i, Tries, Result, Error;

    Rx = socket(AF_INET6, SOCK_RAW, 253);
    Tx = socket(AF_INET6, SOCK_RAW, 253);
    ok(Rx != INVALID_SOCKET && Tx != INVALID_SOCKET, "hdrincl source: sockets %d\n", WSAGetLastError());
    if (Rx == INVALID_SOCKET || Tx == INVALID_SOCKET)
        return;
    Init6(&Bound, 0);
    ok(bind(Rx, (struct sockaddr *)&Bound, sizeof(Bound)) == 0, "hdrincl source: bind %d\n", WSAGetLastError());
    ok(setsockopt(Tx, IPPROTO_IPV6, T_IPV6_HDRINCL, (char *)&One, sizeof(One)) == 0, "hdrincl source: option %d\n",
       WSAGetLastError());
    Init6(&To, 0);
    for (i = 0; i < 3; i++)
    {
        memset(Pkt, 0, sizeof(Pkt));
        Pkt[0] = 0x60; Pkt[5] = 12; Pkt[6] = 253; Pkt[7] = 64;
        memcpy(Pkt + 8, Sources[i], 16); memcpy(Pkt + 24, Loopback6, 16);
        memcpy(Pkt + 40, "RAWFU-SRC-", 10); Pkt[50] = (UCHAR)('0' + i); Pkt[51] = 'x';
        Result = sendto(Tx, (char *)Pkt, 52, 0, (struct sockaddr *)&To, sizeof(To));
        ok(Result == 52, "hdrincl source %d: sent %d error %d\n", i, Result, WSAGetLastError());
        /* (a datagram of protocol 253 that an earlier test sent to ::1, 65495 bytes, may still arrive: skipped) */
        for (Tries = 0; Tries < 4; Tries++)
        {
            Result = RecvWait(Rx, In, sizeof(In), 2000, &Error);
            if ((Result == 12 && !memcmp(In, "RAWFU-SRC-", 10)) || (Result == SOCKET_ERROR && Error == WSAETIMEDOUT))
                break;
        }
        ok(Result == 12 && !memcmp(In, "RAWFU-SRC-", 10), "hdrincl source %d: received %d error %d\n", i, Result, Error);
    }
    closesocket(Tx);
    closesocket(Rx);
}

static void TestConnResetIoctl(void)
{
    BOOL Flag = TRUE;
    DWORD Returned;
    int Result, Error;
    SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    /* Any input of one byte or more is taken; none is WSAEFAULT */
    Result = WSAIoctl(s, SIO_UDP_CONNRESET, &Flag, 1, NULL, 0, &Returned, NULL, NULL);
    ok(Result == 0, "1-byte input: %d %d\n", Result, WSAGetLastError());
    Result = WSAIoctl(s, SIO_UDP_CONNRESET, &Flag, 0, NULL, 0, &Returned, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "0-byte input: %d %d\n", Result, Error);
    closesocket(s);

    /* A raw socket takes it too */
    s = socket(AF_INET6, SOCK_RAW, T_IPPROTO_ICMPV6);
    if (s != INVALID_SOCKET)
    {
        Result = WSAIoctl(s, SIO_UDP_CONNRESET, &Flag, sizeof(Flag), NULL, 0, &Returned, NULL, NULL);
        ok(Result == 0, "raw socket: %d %d\n", Result, WSAGetLastError());
        closesocket(s);
    }
}

static void SetGet(SOCKET s, const char *Label, int Option, int Value, int SetError, int Expect)
{
    int Got = -7, Length = sizeof(Got), Result, Error;

    Result = setsockopt(s, IPPROTO_IPV6, Option, (char *)&Value, sizeof(Value));
    Error = WSAGetLastError();
    if (SetError)
        ok(Result == SOCKET_ERROR && Error == SetError, "%s: set %d = %d: %d error %d, expected %d\n", Label, Option,
           Value, Result, Error, SetError);
    else
        ok(Result == 0, "%s: set %d = %d: error %d\n", Label, Option, Value, Error);
    Result = getsockopt(s, IPPROTO_IPV6, Option, (char *)&Got, &Length);
    if (Expect == -WSAENOPROTOOPT || Expect == -WSAEINVAL || Expect == -WSAENOTCONN)
    {
        Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == -Expect, "%s: get %d: %d error %d, expected %d\n", Label, Option, Result,
           Error, -Expect);
    }
    else
    {
        ok(Result == 0 && Got == Expect && Length == 4, "%s: get %d: %d value %d length %d, expected %d\n", Label,
           Option, Result, Got, Length, Expect);
    }
}

static void TestOptions(void)
{
    SOCKET u = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP), t = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    /* IPV6_TCLASS: not an option on Windows (WSAENOPROTOOPT both ways) */
    SetGet(u, "udp6", T_IPV6_TCLASS, 0x28, WSAENOPROTOOPT, -WSAENOPROTOOPT);
    SetGet(u, "udp6", T_IPV6_RECVTCLASS, 5, 0, 1);
    SetGet(u, "udp6", T_IPV6_RECVIF, 1, 0, 1);
    SetGet(u, "udp6", T_IPV6_UNICAST_IF, 1, 0, 1);
    SetGet(u, "udp6", T_IPV6_UNICAST_IF, 999, WSAEINVAL, 1);
    SetGet(u, "udp6", T_IPV6_UNICAST_IF, 0, 0, 0);
    SetGet(u, "udp6", T_IPV6_MTU_DISCOVER, 2, 0, 2);
    SetGet(u, "udp6", T_IPV6_MTU_DISCOVER, 4, WSAEINVAL, 2);
    SetGet(u, "udp6", T_IPV6_HDRINCL, 1, WSAEINVAL, -WSAEINVAL);
    /* IPV6_MTU cannot be set (WSAENOPROTOOPT, as on Windows). Reading it is a known difference: Windows answers
       WSAENOTCONN on an unconnected socket and the path MTU on a connected one, this stack WSAENOPROTOOPT */
    {
        int Value = 1400, Result = setsockopt(u, IPPROTO_IPV6, T_IPV6_MTU, (char *)&Value, sizeof(Value));
        int Error = WSAGetLastError();
        ok(Result == SOCKET_ERROR && Error == WSAENOPROTOOPT, "udp6: set IPV6_MTU %d error %d\n", Result, Error);
    }
    SetGet(t, "tcp6", T_IPV6_RECVTCLASS, 1, WSAEINVAL, -WSAEINVAL);
    SetGet(t, "tcp6", T_IPV6_RECVIF, 1, WSAEINVAL, -WSAEINVAL);
    SetGet(t, "tcp6", T_IPV6_UNICAST_IF, 1, 0, 1);
    SetGet(t, "tcp6", T_IPV6_MTU_DISCOVER, 1, 0, 1);
    closesocket(u);
    closesocket(t);
}

START_TEST(rawsock)
{
    WSADATA WsaData;
    HANDLE Standard;
    BOOL Privileged;

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");
    {
        SOCKET s6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

        Have6 = (s6 != INVALID_SOCKET);
        if (Have6)
            closesocket(s6);
        else
            skip("No IPv6 sockets (%d): the IPv4 rows only\n", WSAGetLastError());
    }
    Privileged = IsPrivileged();
    trace("privileged: %d, %d-bit\n", Privileged, (int)sizeof(void *) * 8);

    if (Privileged)
    {
        TestRawAccess(TRUE);
        if (Have6)
        {
            TestRaw6();
            TestHdrInclSource6();
        }
        TestInnerDestination(AF_INET, TRUE);
        TestInnerDestination(AF_INET, FALSE);
        if (Have6)
        {
            TestInnerDestination(AF_INET6, TRUE);
            TestInnerDestination(AF_INET6, FALSE);
        }
    }
    else
    {
        skip("Not an administrator: the administrator rows are skipped\n");
    }

    Standard = StandardUserToken();
    ok(Standard != NULL, "no restricted token: %lu\n", GetLastError());
    if (Standard && SetThreadToken(NULL, Standard))
    {
        TestRawAccess(FALSE);
        TestUnprivilegedSend();
        RevertToSelf();
    }
    else
    {
        skip("Cannot impersonate a standard user: %lu\n", GetLastError());
    }
    if (Standard)
        CloseHandle(Standard);

    ConnReset(AF_INET, FALSE, FALSE);
    ConnReset(AF_INET, TRUE, FALSE);
    ConnReset(AF_INET, FALSE, TRUE);
    TestPeekReport(AF_INET, 0);
    TestPeekReport(AF_INET, 1);
    TestPeekReport(AF_INET, 2);
    if (Have6)
    {
        TestPeekReport(AF_INET6, 0);
        TestPeekReport(AF_INET6, 1);
        TestPeekReport(AF_INET6, 2);
        ConnReset(AF_INET6, FALSE, FALSE);
        ConnReset(AF_INET6, TRUE, FALSE);
        ConnReset(AF_INET6, FALSE, TRUE);
        TestConnResetIoctl();
        TestOptions();
    }

    WSACleanup();
}
