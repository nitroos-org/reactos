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
            TestRaw6();
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
    if (Have6)
    {
        ConnReset(AF_INET6, FALSE, FALSE);
        ConnReset(AF_INET6, TRUE, FALSE);
        ConnReset(AF_INET6, FALSE, TRUE);
        TestConnResetIoctl();
        TestOptions();
    }

    WSACleanup();
}
