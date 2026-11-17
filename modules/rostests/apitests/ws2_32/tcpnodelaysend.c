/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     TCP_NODELAY reaches the connection whenever it was set: before connect (on an unbound socket, on a bound
 *              one), after connect, on a listener before and after listen (the accepted connection has it), IPv4 and IPv6
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Two one byte sends follow each other. With Nagle's algorithm the second waits for the acknowledgement of the first,
 * which the receiver delays (lwIP: its 250 ms timer; Linux and Windows: up to 40 / 200 ms): it arrives 40 ms or more
 * after the first. With TCP_NODELAY set on the connection both bytes are there at once. The test sends the pair a few
 * times and takes the best time of the rounds, so a slow moment of the machine cannot fail it: the stall of a
 * connection without TCP_NODELAY happens in every round.
 *
 * VERIFY ON ORACLE (Windows 10 22H2): that an accepted socket sends with the TCP_NODELAY of its listener. The probe:
 * this test built for the reference system (the rows "listener, before listen" and "listener, after listen") prints the
 * time of the accepted side's pair; the value expected here is "fast".
 *
 * The loopback of the stack acknowledges at once, so on it these rows catch the refusals of the option (a socket that
 * is bound or listening); the stall itself needs a peer that delays its acknowledgements. With the environment
 * variable NODELAY_PEER=<address>:<port> (or [<IPv6 address>]:<port>), a peer on another machine reached over a NIC
 * that reads two bytes and answers one in a loop (tools/nodelay-peer.py of the lane evidence), the test runs 30
 * rounds of two one byte sends and one answer with the option not set, set before connect and set after connect,
 * and requires the last two to take less than half the time of the first.
 */

#include "ws2_32.h"
#include <mswsock.h>

#define ROUNDS      4
#define FAST_MS     100

typedef enum
{
    MODE_NONE,
    MODE_BEFORE_CONNECT,        /* the option on a new, unbound socket */
    MODE_AFTER_BIND,            /* the option on a bound, not connected socket */
    MODE_AFTER_CONNECT,
    MODE_LISTENER_BEFORE_LISTEN,/* the accepted socket sends */
    MODE_LISTENER_AFTER_LISTEN,
} NODELAY_MODE;

static const char *ModeName(NODELAY_MODE Mode)
{
    switch (Mode)
    {
        case MODE_NONE: return "not set";
        case MODE_BEFORE_CONNECT: return "before connect";
        case MODE_AFTER_BIND: return "after bind";
        case MODE_AFTER_CONNECT: return "after connect";
        case MODE_LISTENER_BEFORE_LISTEN: return "listener, before listen";
        case MODE_LISTENER_AFTER_LISTEN: return "listener, after listen";
    }
    return "?";
}

static void SetNoDelay(SOCKET s, const char *What)
{
    int One = 1;

    ok(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&One, sizeof(One)) == 0, "%s: setsockopt(TCP_NODELAY) failed: %d\n",
       What, WSAGetLastError());
}

static void MakeAddress(int Family, struct sockaddr_storage *Addr, int *Len, int Port)
{
    memset(Addr, 0, sizeof(*Addr));
    if (Family == AF_INET)
    {
        struct sockaddr_in *In = (struct sockaddr_in *)Addr;

        In->sin_family = AF_INET;
        In->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        In->sin_port = htons((USHORT)Port);
        *Len = sizeof(*In);
    }
    else
    {
        struct sockaddr_in6 *In6 = (struct sockaddr_in6 *)Addr;

        In6->sin6_family = AF_INET6;
        In6->sin6_addr.s6_addr[15] = 1;
        In6->sin6_port = htons((USHORT)Port);
        *Len = sizeof(*In6);
    }
}

/* Receives Count bytes from s, waiting at most 2 seconds; returns the bytes received */
static int ReceiveBytes(SOCKET s, int Count)
{
    int Got = 0;

    while (Got < Count)
    {
        fd_set Set;
        struct timeval Timeout = { 2, 0 };
        char Byte[8];
        int Result;

        FD_ZERO(&Set);
        FD_SET(s, &Set);
        if (select(0, &Set, NULL, NULL, &Timeout) != 1)
            break;
        Result = recv(s, Byte, sizeof(Byte), 0);
        if (Result <= 0)
            break;
        Got += Result;
    }
    return Got;
}

/* One run: the milliseconds from the first send to the arrival of the second byte, or -1 on a failure */
static int PairTime(int Family, NODELAY_MODE Mode)
{
    struct sockaddr_storage Addr;
    SOCKET Listener, Client, Accepted, Sender, Receiver;
    LARGE_INTEGER Freq, Start, End;
    int Len, Time = -1;

    MakeAddress(Family, &Addr, &Len, 0);

    Listener = socket(Family, SOCK_STREAM, 0);
    ok(Listener != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Listener == INVALID_SOCKET)
        return -1;
    ok(bind(Listener, (struct sockaddr *)&Addr, Len) == 0, "bind failed: %d\n", WSAGetLastError());
    Len = sizeof(Addr);
    ok(getsockname(Listener, (struct sockaddr *)&Addr, &Len) == 0, "getsockname failed\n");

    if (Mode == MODE_LISTENER_BEFORE_LISTEN)
        SetNoDelay(Listener, ModeName(Mode));
    ok(listen(Listener, 1) == 0, "listen failed: %d\n", WSAGetLastError());
    if (Mode == MODE_LISTENER_AFTER_LISTEN)
        SetNoDelay(Listener, ModeName(Mode));

    Client = socket(Family, SOCK_STREAM, 0);
    ok(Client != INVALID_SOCKET, "socket failed\n");
    if (Mode == MODE_BEFORE_CONNECT)
        SetNoDelay(Client, ModeName(Mode));
    if (Mode == MODE_AFTER_BIND)
    {
        struct sockaddr_storage Local;
        int LocalLen;

        MakeAddress(Family, &Local, &LocalLen, 0);
        ok(bind(Client, (struct sockaddr *)&Local, LocalLen) == 0, "bind (client) failed: %d\n", WSAGetLastError());
        SetNoDelay(Client, ModeName(Mode));
    }
    ok(connect(Client, (struct sockaddr *)&Addr, Len) == 0, "connect failed: %d\n", WSAGetLastError());
    if (Mode == MODE_AFTER_CONNECT)
        SetNoDelay(Client, ModeName(Mode));
    Accepted = accept(Listener, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "accept failed: %d\n", WSAGetLastError());

    if (Accepted != INVALID_SOCKET)
    {
        BOOL ServerSends = (Mode == MODE_LISTENER_BEFORE_LISTEN || Mode == MODE_LISTENER_AFTER_LISTEN);

        Sender = ServerSends ? Accepted : Client;
        Receiver = ServerSends ? Client : Accepted;

        QueryPerformanceFrequency(&Freq);
        QueryPerformanceCounter(&Start);
        ok(send(Sender, "a", 1, 0) == 1, "send failed\n");
        ok(send(Sender, "b", 1, 0) == 1, "send failed\n");
        if (ReceiveBytes(Receiver, 2) == 2)
        {
            QueryPerformanceCounter(&End);
            Time = (int)((End.QuadPart - Start.QuadPart) * 1000 / Freq.QuadPart);
        }
        closesocket(Accepted);
    }
    closesocket(Client);
    closesocket(Listener);
    return Time;
}

static int BestTime(int Family, NODELAY_MODE Mode)
{
    int Round, Best = 100000, Time;

    for (Round = 0; Round < ROUNDS; Round++)
    {
        Time = PairTime(Family, Mode);
        if (Time >= 0 && Time < Best)
            Best = Time;
    }
    return Best;
}

static void TestFamily(int Family)
{
    const char *Name = (Family == AF_INET) ? "IPv4" : "IPv6";
    NODELAY_MODE Mode;
    int Time;
    SOCKET s;

    s = socket(Family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        skip("%s: no such socket (%d)\n", Name, WSAGetLastError());
        return;
    }
    closesocket(s);

    for (Mode = MODE_NONE; Mode <= MODE_LISTENER_AFTER_LISTEN; Mode++)
    {
        Time = BestTime(Family, Mode);
        trace("%s, %-24s: best of %d, two one byte sends in %d ms\n", Name, ModeName(Mode), ROUNDS, Time);
        if (Mode == MODE_NONE)
        {
            /* Nagle holds the second byte: informational only, a peer that acknowledges at once hides it */
            continue;
        }
        ok(Time < FAST_MS, "%s, option %s: the second byte arrived after %d ms (Nagle's algorithm still applies)\n",
           Name, ModeName(Mode), Time);
    }
}

/* The connection AcceptEx makes has the option of the listener: the pair it sends is not held back, and
   getsockopt answers 1 once SO_UPDATE_ACCEPT_CONTEXT ran (VERIFY ON ORACLE) */
static void TestAcceptEx(void)
{
    GUID AcceptExGuid = WSAID_ACCEPTEX;
    LPFN_ACCEPTEX pAcceptEx = NULL;
    struct sockaddr_storage Addr;
    SOCKET Listener, Client, Accepted;
    OVERLAPPED Overlapped;
    char Buffer[2 * (sizeof(struct sockaddr_in) + 16)];
    DWORD Bytes = 0;
    int Len, Value = 0, ValueLen = sizeof(Value), Round, Best = 100000, Time;
    LARGE_INTEGER Freq, Start, End;

    for (Round = 0; Round < ROUNDS; Round++)
    {
        MakeAddress(AF_INET, &Addr, &Len, 0);
        Listener = socket(AF_INET, SOCK_STREAM, 0);
        ok(bind(Listener, (struct sockaddr *)&Addr, Len) == 0, "bind failed\n");
        Len = sizeof(Addr);
        getsockname(Listener, (struct sockaddr *)&Addr, &Len);
        ok(listen(Listener, 1) == 0, "listen failed\n");
        SetNoDelay(Listener, "AcceptEx listener");
        WSAIoctl(Listener, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptExGuid, sizeof(AcceptExGuid), &pAcceptEx,
                 sizeof(pAcceptEx), &Bytes, NULL, NULL);
        if (!pAcceptEx)
        {
            skip("no AcceptEx\n");
            closesocket(Listener);
            return;
        }
        Accepted = socket(AF_INET, SOCK_STREAM, 0);
        memset(&Overlapped, 0, sizeof(Overlapped));
        Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        pAcceptEx(Listener, Accepted, Buffer, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
                  &Bytes, &Overlapped);
        Client = socket(AF_INET, SOCK_STREAM, 0);
        ok(connect(Client, (struct sockaddr *)&Addr, sizeof(struct sockaddr_in)) == 0, "connect failed\n");
        ok(WaitForSingleObject(Overlapped.hEvent, 10000) == WAIT_OBJECT_0, "AcceptEx never completed\n");
        ok(setsockopt(Accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&Listener, sizeof(Listener)) == 0,
           "SO_UPDATE_ACCEPT_CONTEXT failed %d\n", WSAGetLastError());
        Value = 0;
        ValueLen = 1;
        ok(getsockopt(Accepted, IPPROTO_TCP, TCP_NODELAY, (char *)&Value, &ValueLen) == 0 && (Value & 0xff) == 1,
           "AcceptEx socket: TCP_NODELAY reads %d\n", Value & 0xff);

        QueryPerformanceFrequency(&Freq);
        QueryPerformanceCounter(&Start);
        send(Accepted, "a", 1, 0);
        send(Accepted, "b", 1, 0);
        if (ReceiveBytes(Client, 2) == 2)
        {
            QueryPerformanceCounter(&End);
            Time = (int)((End.QuadPart - Start.QuadPart) * 1000 / Freq.QuadPart);
            if (Time < Best)
                Best = Time;
        }
        CloseHandle(Overlapped.hEvent);
        closesocket(Accepted);
        closesocket(Client);
        closesocket(Listener);
    }
    trace("IPv4, AcceptEx listener, option before listen: best of %d, two one byte sends in %d ms\n", ROUNDS, Best);
    ok(Best < FAST_MS, "AcceptEx socket: the second byte arrived after %d ms\n", Best);
}

/* The rows over a NIC: a peer that is not this machine */
static void TestPeer(const char *Spec)
{
    /* Spec: "address:port" or "[IPv6 address]:port". The peer reads two bytes, answers one, in a loop (a request and
       its answer, so that it delays its acknowledgements as a Linux or Windows peer does) */
    char Host[128], PortText[16];
    const char *Colon = strrchr(Spec, ':');
    struct addrinfo Hints, *Res;
    int Variant, Round, Rounds = 30;
    ULONG Time[3];
    static const char *Names[3] = { "not set", "before connect", "after connect" };

    if (!Colon || Colon == Spec || (size_t)(Colon - Spec) >= sizeof(Host))
        return;
    memcpy(Host, Spec, Colon - Spec);
    Host[Colon - Spec] = 0;
    if (Host[0] == '[')
    {
        size_t n = strlen(Host);

        if (Host[n - 1] == ']')
            Host[n - 1] = 0;
        memmove(Host, Host + 1, strlen(Host));
    }
    strncpy(PortText, Colon + 1, sizeof(PortText) - 1);
    PortText[sizeof(PortText) - 1] = 0;

    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(Host, PortText, &Hints, &Res) != 0)
    {
        skip("NIC peer %s: cannot resolve it\n", Spec);
        return;
    }

    for (Variant = 0; Variant < 3; Variant++)
    {
        SOCKET s = socket(Res->ai_family, SOCK_STREAM, 0);
        DWORD Start;
        char Byte;

        if (Variant == 1)
            SetNoDelay(s, "NIC, before connect");
        if (connect(s, Res->ai_addr, (int)Res->ai_addrlen) != 0)
        {
            skip("NIC peer %s: connect failed: %d\n", Spec, WSAGetLastError());
            closesocket(s);
            freeaddrinfo(Res);
            return;
        }
        if (Variant == 2)
            SetNoDelay(s, "NIC, after connect");
        Start = GetTickCount();
        for (Round = 0; Round < Rounds; Round++)
        {
            send(s, "a", 1, 0);
            send(s, "b", 1, 0);
            if (ReceiveBytes(s, 1) != 1)
                break;
            (void)Byte;
        }
        Time[Variant] = GetTickCount() - Start;
        trace("NICROW %s: %d request/answer rounds of two one byte sends took %lu ms\n", Names[Variant], Round, Time[Variant]);
        closesocket(s);
    }
    freeaddrinfo(Res);

    /* The peer delays its acknowledgements: without the option each round waits for one (40 ms or more). The rows
       with the option must be far from that. Judged only when the stall shows in the default row. */
    if (Time[0] > 400)
    {
        ok(Time[1] < Time[0] / 2, "NIC, option before connect: %lu ms, without the option %lu ms\n", Time[1], Time[0]);
        ok(Time[2] < Time[0] / 2, "NIC, option after connect: %lu ms, without the option %lu ms\n", Time[2], Time[0]);
    }
    else
        skip("NIC peer %s does not delay its acknowledgements (%lu ms for the default)\n", Spec, Time[0]);
}

START_TEST(tcpnodelaysend)
{
    WSADATA Data;
    char Peer[160];

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    TestFamily(AF_INET);
    TestFamily(AF_INET6);
    TestAcceptEx();

    if (GetEnvironmentVariableA("NODELAY_PEER", Peer, sizeof(Peer)) > 0)
        TestPeer(Peer);

    WSACleanup();
}
