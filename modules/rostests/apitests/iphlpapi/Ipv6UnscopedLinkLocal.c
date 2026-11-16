/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A link-local IPv6 destination without a scope id (sin6_scope_id 0). Measured on Windows Server 2022
 *              (ping, connect, sendto, with one adapter and with two; the name resolver leaves the scope id 0): the
 *              stack takes the adapter of the lowest metric, so with one adapter ping, connect and sendto to an
 *              unscoped link-local address work exactly as with the scope id of that adapter. This test runs the
 *              three against the machine's own link-local address (no peer needed) and compares each with the scoped
 *              form. It needs exactly one adapter with a link-local address and skips otherwise; the two-adapter rows
 *              (the lowest metric wins, a peer on the other link) need a peer on each link and are in the harness.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

static struct sockaddr_in6 g_Own;       /* the link-local address of the one adapter, scope id set */
static ULONG g_IfIndex;

/* The one up adapter with a link-local IPv6 address; FALSE when there is none or more than one */
static BOOL FindOwnLinkLocal(void)
{
    ULONG Size = 32768, Error, Found = 0;
    PIP_ADAPTER_ADDRESSES Buffer = NULL, A;
    PIP_ADAPTER_UNICAST_ADDRESS U;
    int Try;

    for (Try = 0; Try < 4; Try++)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Buffer)
            return FALSE;
        Error = GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL, Buffer, &Size);
        if (Error != ERROR_BUFFER_OVERFLOW)
            break;
        HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = NULL;
    }
    if (!Buffer || Error != ERROR_SUCCESS)
    {
        if (Buffer)
            HeapFree(GetProcessHeap(), 0, Buffer);
        return FALSE;
    }

    for (A = Buffer; A; A = A->Next)
    {
        if (A->OperStatus != IfOperStatusUp || A->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        for (U = A->FirstUnicastAddress; U; U = U->Next)
        {
            struct sockaddr_in6 *Sa = (struct sockaddr_in6 *)U->Address.lpSockaddr;

            if (Sa->sin6_family == AF_INET6 && Sa->sin6_addr.s6_addr[0] == 0xfe && (Sa->sin6_addr.s6_addr[1] & 0xc0) == 0x80 &&
                U->DadState == IpDadStatePreferred)
            {
                g_Own = *Sa;
                g_IfIndex = A->Ipv6IfIndex;
                g_Own.sin6_scope_id = A->Ipv6IfIndex;
                Found++;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return Found == 1;
}

static DWORD EchoOnce(const struct sockaddr_in6 *Dest, DWORD *ReplyStatus)
{
    HANDLE Icmp = Icmp6CreateFile();
    struct sockaddr_in6 Source;
    char Data[16] = "unscoped-ll-ech";
    UCHAR Reply[sizeof(ICMPV6_ECHO_REPLY) + sizeof(Data) + 8 + 64];
    PICMPV6_ECHO_REPLY R = (PICMPV6_ECHO_REPLY)Reply;
    DWORD Ret, Error;

    if (Icmp == INVALID_HANDLE_VALUE)
        return 0xFFFFFFFF;
    memset(&Source, 0, sizeof(Source));
    Source.sin6_family = AF_INET6;
    memset(Reply, 0xcc, sizeof(Reply));
    SetLastError(0);
    Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, (struct sockaddr_in6 *)Dest, Data, sizeof(Data), NULL, Reply,
                         sizeof(Reply), 3000);
    Error = GetLastError();
    *ReplyStatus = (Ret == 1) ? R->Status : 0xFFFFFFFF;
    IcmpCloseHandle(Icmp);
    return Ret == 1 ? 0 : Error;
}

static void TestEcho(void)
{
    struct sockaddr_in6 Unscoped = g_Own;
    DWORD ScopedErr, ScopedStatus, UnscopedErr, UnscopedStatus;

    Unscoped.sin6_scope_id = 0;
    ScopedErr = EchoOnce(&g_Own, &ScopedStatus);
    UnscopedErr = EchoOnce(&Unscoped, &UnscopedStatus);
    ok(ScopedErr == 0 && ScopedStatus == IP_SUCCESS, "echo to the own link-local address with its scope id: %lu status %lu\n",
       ScopedErr, ScopedStatus);
    ok(UnscopedErr == ScopedErr && UnscopedStatus == ScopedStatus,
       "echo to the own link-local address without a scope id: error %lu status %lu (scoped: %lu, %lu)\n",
       UnscopedErr, UnscopedStatus, ScopedErr, ScopedStatus);
}

static void TestTcp(void)
{
    SOCKET L, C, A;
    struct sockaddr_in6 Bind, Dest, Local, Peer;
    int Len;
    int Pass;
    BOOL Connected;
    char Byte = 'x', In = 0;

    for (Pass = 0; Pass < 2; Pass++)
    {
        /* Pass 0: with the scope id, Pass 1: without */
        L = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        ok(L != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
        if (L == INVALID_SOCKET)
            return;
        memset(&Bind, 0, sizeof(Bind));
        Bind.sin6_family = AF_INET6;
        ok(bind(L, (struct sockaddr *)&Bind, sizeof(Bind)) == 0, "bind: %d\n", WSAGetLastError());
        ok(listen(L, 1) == 0, "listen: %d\n", WSAGetLastError());
        Len = sizeof(Bind);
        ok(getsockname(L, (struct sockaddr *)&Bind, &Len) == 0, "getsockname: %d\n", WSAGetLastError());

        Dest = g_Own;
        Dest.sin6_port = Bind.sin6_port;
        if (Pass == 1)
            Dest.sin6_scope_id = 0;

        C = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        ok(C != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
        if (C == INVALID_SOCKET)
        {
            closesocket(L);
            return;
        }
        SetLastError(0);
        Connected = connect(C, (struct sockaddr *)&Dest, sizeof(Dest)) == 0;
        ok(Connected, "connect to the own link-local address (%s scope id): %d\n", Pass ? "no" : "with", WSAGetLastError());
        if (!Connected)
        {
            closesocket(C);
            closesocket(L);
            continue;
        }

        A = accept(L, NULL, NULL);
        ok(A != INVALID_SOCKET, "accept: %d\n", WSAGetLastError());
        if (A != INVALID_SOCKET)
        {
            /* the connection works in both directions and the local end is the adapter's link-local address, with its scope id */
            ok(send(C, &Byte, 1, 0) == 1, "send: %d\n", WSAGetLastError());
            ok(recv(A, &In, 1, 0) == 1 && In == 'x', "recv: %d\n", WSAGetLastError());
            Len = sizeof(Local);
            ok(getsockname(C, (struct sockaddr *)&Local, &Len) == 0, "getsockname: %d\n", WSAGetLastError());
            ok(!memcmp(&Local.sin6_addr, &g_Own.sin6_addr, 16), "local address of the client (pass %d)\n", Pass);
            ok(Local.sin6_scope_id == g_IfIndex, "local scope id of the client %lu, expected %lu (pass %d)\n",
               (ULONG)Local.sin6_scope_id, g_IfIndex, Pass);
            Len = sizeof(Peer);
            ok(getpeername(C, (struct sockaddr *)&Peer, &Len) == 0, "getpeername: %d\n", WSAGetLastError());
            ok(!memcmp(&Peer.sin6_addr, &g_Own.sin6_addr, 16), "peer address of the client (pass %d)\n", Pass);
            closesocket(A);
        }
        closesocket(C);
        closesocket(L);
    }
}

static void TestUdp(void)
{
    SOCKET R, S;
    struct sockaddr_in6 Bind, Dest, From;
    int Len, Pass;
    BOOL Arrived;
    char Data[8] = "udp-ll", In[16];
    fd_set Set;
    struct timeval Tv;

    for (Pass = 0; Pass < 2; Pass++)
    {
        R = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        S = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        ok(R != INVALID_SOCKET && S != INVALID_SOCKET, "sockets: %d\n", WSAGetLastError());
        if (R == INVALID_SOCKET || S == INVALID_SOCKET)
            return;
        memset(&Bind, 0, sizeof(Bind));
        Bind.sin6_family = AF_INET6;
        ok(bind(R, (struct sockaddr *)&Bind, sizeof(Bind)) == 0, "bind: %d\n", WSAGetLastError());
        Len = sizeof(Bind);
        ok(getsockname(R, (struct sockaddr *)&Bind, &Len) == 0, "getsockname: %d\n", WSAGetLastError());

        Dest = g_Own;
        Dest.sin6_port = Bind.sin6_port;
        if (Pass == 1)
            Dest.sin6_scope_id = 0;
        ok(sendto(S, Data, sizeof(Data), 0, (struct sockaddr *)&Dest, sizeof(Dest)) == (int)sizeof(Data),
           "sendto the own link-local address (%s scope id): %d\n", Pass ? "no" : "with", WSAGetLastError());

        FD_ZERO(&Set);
        FD_SET(R, &Set);
        Tv.tv_sec = 3;
        Tv.tv_usec = 0;
        Arrived = select(0, &Set, NULL, NULL, &Tv) == 1;
        ok(Arrived, "datagram arrived (pass %d)\n", Pass);
        if (!Arrived)
        {
            closesocket(S);
            closesocket(R);
            continue;
        }
        Len = sizeof(From);
        memset(&From, 0, sizeof(From));
        ok(recvfrom(R, In, sizeof(In), 0, (struct sockaddr *)&From, &Len) == (int)sizeof(Data), "recvfrom: %d\n", WSAGetLastError());
        ok(!memcmp(&From.sin6_addr, &g_Own.sin6_addr, 16), "datagram source (pass %d)\n", Pass);
        ok(From.sin6_scope_id == g_IfIndex, "datagram source scope id %lu, expected %lu (pass %d)\n", (ULONG)From.sin6_scope_id,
           g_IfIndex, Pass);
        closesocket(S);
        closesocket(R);
    }
}

/* The name resolver leaves the scope id of a numeric link-local address as given: 0 without a %id (Windows Server 2022) */
static void TestGetAddrInfo(void)
{
    char Text[INET6_ADDRSTRLEN + 16];
    struct addrinfo Hints, *Res = NULL;
    DWORD Size = sizeof(Text);
    struct sockaddr_in6 Plain = g_Own;
    int Err;

    Plain.sin6_scope_id = 0;
    ok(WSAAddressToStringA((struct sockaddr *)&Plain, sizeof(Plain), NULL, Text, &Size) == 0, "AddressToString: %d\n", WSAGetLastError());
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = AF_INET6;
    Hints.ai_flags = AI_NUMERICHOST;
    Hints.ai_socktype = SOCK_STREAM;
    Err = getaddrinfo(Text, "80", &Hints, &Res);
    ok(Err == 0, "getaddrinfo(%s): %d\n", Text, Err);
    if (Err == 0 && Res)
    {
        struct sockaddr_in6 *Sa = (struct sockaddr_in6 *)Res->ai_addr;

        ok(Sa->sin6_scope_id == 0, "scope id of an unscoped numeric link-local address: %lu\n", (ULONG)Sa->sin6_scope_id);
        ok(!memcmp(&Sa->sin6_addr, &g_Own.sin6_addr, 16), "address\n");
        freeaddrinfo(Res);
    }
}

START_TEST(Ipv6UnscopedLinkLocal)
{
    WSADATA Data;

    if (WSAStartup(MAKEWORD(2, 2), &Data) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }
    if (!FindOwnLinkLocal())
    {
        skip("needs exactly one adapter that is up with a preferred link-local IPv6 address\n");
        WSACleanup();
        return;
    }

    TestEcho();
    TestTcp();
    TestUdp();
    TestGetAddrInfo();
    WSACleanup();
}
