/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Which sockets may bind a port that others hold: SO_REUSEADDR,
 *              SO_EXCLUSIVEADDRUSE, a specific address against the wildcard,
 *              and what live connections do (and do not) hold
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

/* The expected values were recorded on Windows 10 22H2 by binding every pair of
 * sockets (three options, three addresses each, TCP bound, TCP listening and UDP:
 * 243 results) and by the live-connection scenarios below. The rules they follow:
 *
 *  - Only bound sockets count. A listener that has been closed frees the port even
 *    while the connections it accepted are alive, TIME-WAIT holds nothing, and the
 *    implicit bind of a connect() is a wildcard bind like any other.
 *  - Same address: SO_EXCLUSIVEADDRUSE on either socket is WSAEADDRINUSE (the second
 *    asking for SO_REUSEADDR against an exclusive first is WSAEACCES); both with
 *    SO_REUSEADDR succeed; SO_REUSEADDR on the second socket only is WSAEACCES, on
 *    the first only WSAEADDRINUSE; neither is WSAEADDRINUSE.
 *  - Wildcard first, specific second: allowed, WSAEACCES if the first is exclusive.
 *  - Specific first, wildcard second: allowed, WSAEADDRINUSE if the second is exclusive.
 *  - Two different specific addresses never conflict.
 */

enum { OPT_NONE, OPT_REUSE, OPT_EXCL };

static const char *OptNames[] = { "none", "reuse", "excl" };
static const char *AddrNames[] = { "127.0.0.1", "0.0.0.0", "127.0.0.2" };
static int NextPort = 47600;

static
int
Expected(int Opt1, int Addr1, int Opt2, int Addr2)
{
    if (Addr1 == Addr2)
    {
        if (Opt1 == OPT_EXCL || Opt2 == OPT_EXCL)
            return (Opt1 == OPT_EXCL && Opt2 == OPT_REUSE) ? WSAEACCES : WSAEADDRINUSE;
        if (Opt1 == OPT_REUSE && Opt2 == OPT_REUSE)
            return 0;
        return (Opt2 == OPT_REUSE) ? WSAEACCES : WSAEADDRINUSE;
    }
    if (Addr1 == 1)
        return (Opt1 == OPT_EXCL) ? WSAEACCES : 0;
    if (Addr2 == 1)
        return (Opt2 == OPT_EXCL) ? WSAEADDRINUSE : 0;
    return 0;
}

static
SOCKET
MakeSocket(int Type, int Opt)
{
    SOCKET Socket = socket(AF_INET, Type, Type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    BOOL One = TRUE;

    ok(Socket != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    if (Opt == OPT_REUSE)
        ok(setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (char *)&One, sizeof(One)) == 0, "SO_REUSEADDR failed\n");
    if (Opt == OPT_EXCL)
        ok(setsockopt(Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&One, sizeof(One)) == 0, "SO_EXCLUSIVEADDRUSE failed\n");
    return Socket;
}

/* 0 or the WSA error */
static
int
BindTo(SOCKET Socket, int Address, int Port)
{
    struct sockaddr_in Name;

    memset(&Name, 0, sizeof(Name));
    Name.sin_family = AF_INET;
    Name.sin_port = htons((USHORT)Port);
    Name.sin_addr.s_addr = inet_addr(AddrNames[Address]);
    if (bind(Socket, (struct sockaddr *)&Name, sizeof(Name)) == 0)
        return 0;
    return WSAGetLastError();
}

static
void
TestMatrix(int Type, BOOL Listen)
{
    int Opt1, Addr1, Opt2, Addr2;
    const char *What = Type == SOCK_DGRAM ? "UDP" : Listen ? "TCP listening" : "TCP bound";

    for (Addr1 = 0; Addr1 < 3; Addr1++)
    for (Addr2 = 0; Addr2 < 3; Addr2++)
    for (Opt1 = 0; Opt1 < 3; Opt1++)
    for (Opt2 = 0; Opt2 < 3; Opt2++)
    {
        int Port = NextPort++;
        SOCKET First = MakeSocket(Type, Opt1), Second;
        int Result;

        ok(BindTo(First, Addr1, Port) == 0, "%s: first bind failed\n", What);
        if (Listen)
            ok(listen(First, 5) == 0, "%s: listen failed %d\n", What, WSAGetLastError());

        Second = MakeSocket(Type, Opt2);
        Result = BindTo(Second, Addr2, Port);
        ok(Result == Expected(Opt1, Addr1, Opt2, Addr2),
           "%s: %s/%s then %s/%s: error %d, expected %d\n", What,
           OptNames[Opt1], AddrNames[Addr1], OptNames[Opt2], AddrNames[Addr2],
           Result, Expected(Opt1, Addr1, Opt2, Addr2));
        closesocket(Second);
        closesocket(First);
    }
}

static
SOCKET
MakeListener(int Address, int Port, int Opt)
{
    SOCKET Socket = MakeSocket(SOCK_STREAM, Opt);

    ok(BindTo(Socket, Address, Port) == 0, "listener bind failed\n");
    ok(listen(Socket, 5) == 0, "listen failed\n");
    return Socket;
}

static
SOCKET
ConnectTo(int Port, int ClientPort)
{
    struct sockaddr_in Name;
    SOCKET Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (ClientPort)
        ok(BindTo(Client, 0, ClientPort) == 0, "client bind failed\n");
    memset(&Name, 0, sizeof(Name));
    Name.sin_family = AF_INET;
    Name.sin_port = htons((USHORT)Port);
    Name.sin_addr.s_addr = inet_addr("127.0.0.1");
    ok(connect(Client, (struct sockaddr *)&Name, sizeof(Name)) == 0, "connect failed %d\n", WSAGetLastError());
    return Client;
}

/* Binds a fresh socket with each option; Expected has the result for none, reuse, excl */
static
void
CheckBinds(const char *What, int Address, int Port, int None, int Reuse, int Excl)
{
    static const int Opts[] = { OPT_NONE, OPT_REUSE, OPT_EXCL };
    int Want[3], i;

    Want[0] = None;
    Want[1] = Reuse;
    Want[2] = Excl;
    for (i = 0; i < 3; i++)
    {
        SOCKET Socket = MakeSocket(SOCK_STREAM, Opts[i]);
        int Result = BindTo(Socket, Address, Port);

        ok(Result == Want[i], "%s: bind %s with %s: error %d, expected %d\n",
           What, AddrNames[Address], OptNames[Opts[i]], Result, Want[i]);
        closesocket(Socket);
    }
}

static
void
TestLive(void)
{
    SOCKET Listener, Client, Accepted;
    int Port;
    struct sockaddr_in Name;
    int Length;

    /* A listener on a specific address with a live connection */
    Port = NextPort++;
    Listener = MakeListener(0, Port, OPT_NONE);
    Client = ConnectTo(Port, 0);
    Accepted = accept(Listener, NULL, NULL);
    ok(Accepted != INVALID_SOCKET, "accept failed\n");
    CheckBinds("listener open", 0, Port, WSAEADDRINUSE, WSAEACCES, WSAEADDRINUSE);
    CheckBinds("listener open", 1, Port, 0, 0, WSAEADDRINUSE);
    CheckBinds("listener open", 2, Port, 0, 0, 0);

    /* Closing the listener frees the port, though the accepted connection lives on */
    closesocket(Listener);
    CheckBinds("listener closed, connection alive", 0, Port, 0, 0, 0);
    CheckBinds("listener closed, connection alive", 1, Port, 0, 0, 0);
    CheckBinds("listener closed, connection alive", 2, Port, 0, 0, 0);

    /* Neither does it matter what became of the connection */
    closesocket(Accepted);
    Sleep(200);
    closesocket(Client);
    Sleep(200);
    CheckBinds("connection in TIME-WAIT", 0, Port, 0, 0, 0);
    CheckBinds("connection in TIME-WAIT", 1, Port, 0, 0, 0);

    /* The same for a wildcard listener */
    Port = NextPort++;
    Listener = MakeListener(1, Port, OPT_NONE);
    Client = ConnectTo(Port, 0);
    Accepted = accept(Listener, NULL, NULL);
    CheckBinds("wildcard listener open", 0, Port, 0, 0, 0);
    CheckBinds("wildcard listener open", 1, Port, WSAEADDRINUSE, WSAEACCES, WSAEADDRINUSE);
    closesocket(Listener);
    CheckBinds("wildcard listener closed, connection alive", 0, Port, 0, 0, 0);
    CheckBinds("wildcard listener closed, connection alive", 1, Port, 0, 0, 0);
    closesocket(Accepted);
    closesocket(Client);

    /* A listener with SO_REUSEADDR, then closed */
    Port = NextPort++;
    Listener = MakeListener(0, Port, OPT_REUSE);
    Client = ConnectTo(Port, 0);
    Accepted = accept(Listener, NULL, NULL);
    CheckBinds("reuse listener open", 0, Port, WSAEADDRINUSE, 0, WSAEADDRINUSE);
    CheckBinds("reuse listener open", 1, Port, 0, 0, WSAEADDRINUSE);
    closesocket(Listener);
    CheckBinds("reuse listener closed, connection alive", 0, Port, 0, 0, 0);
    closesocket(Accepted);
    closesocket(Client);

    /* The port of an outgoing connection is held like a wildcard bind */
    Port = NextPort++;
    Listener = MakeListener(0, Port, OPT_NONE);
    Client = ConnectTo(Port, 0);
    Accepted = accept(Listener, NULL, NULL);
    Length = sizeof(Name);
    ok(getsockname(Client, (struct sockaddr *)&Name, &Length) == 0, "getsockname failed\n");
    CheckBinds("outgoing connection", 0, ntohs(Name.sin_port), 0, 0, 0);
    CheckBinds("outgoing connection", 1, ntohs(Name.sin_port), WSAEADDRINUSE, WSAEACCES, WSAEADDRINUSE);
    closesocket(Accepted);
    closesocket(Client);
    closesocket(Listener);

    /* A client that bound its port itself keeps it against SO_REUSEADDR of another */
    {
        int ServerPort = NextPort++, ClientPort = NextPort++;
        SOCKET Other;

        Listener = MakeListener(0, ServerPort, OPT_NONE);
        Client = ConnectTo(ServerPort, ClientPort);
        Accepted = accept(Listener, NULL, NULL);
        Other = MakeSocket(SOCK_STREAM, OPT_REUSE);
        ok(BindTo(Other, 0, ClientPort) == WSAEACCES, "reuse bind over a connected client: %d\n", WSAGetLastError());
        closesocket(Other);
        closesocket(Accepted);
        closesocket(Client);
        closesocket(Listener);
    }
}

/* Listeners that share a port: a connection goes to the one bound to the address it was made
 * to, the wildcard one takes the rest */
static
void
TestListenerChoice(void)
{
    int Port = NextPort++;
    SOCKET Wild, Specific, Client, Accepted;
    fd_set Set;
    struct timeval Timeout = { 1, 0 };
    int Count;

    Wild = MakeListener(1, Port, OPT_NONE);
    Specific = MakeListener(0, Port, OPT_NONE);
    Client = ConnectTo(Port, 0);

    FD_ZERO(&Set);
    FD_SET(Specific, &Set);
    FD_SET(Wild, &Set);
    Count = select(0, &Set, NULL, NULL, &Timeout);
    ok(Count == 1, "%d listeners readable, expected 1\n", Count);
    ok(FD_ISSET(Specific, &Set), "the listener bound to 127.0.0.1 did not get the connection\n");
    if (FD_ISSET(Specific, &Set))
    {
        Accepted = accept(Specific, NULL, NULL);
        ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());
        closesocket(Accepted);
    }

    closesocket(Client);
    closesocket(Specific);
    closesocket(Wild);
}

/* Sockets that share a port: a unicast datagram reaches one of them, the one bound to
 * its address rather than the wildcard */
static
void
TestUdpDelivery(void)
{
    int Port = NextPort++;
    SOCKET Wild, Specific, Sender;
    struct sockaddr_in Name;
    char Buffer[16];
    fd_set Set;
    struct timeval Timeout = { 1, 0 };
    int Count;

    Wild = MakeSocket(SOCK_DGRAM, OPT_NONE);
    Specific = MakeSocket(SOCK_DGRAM, OPT_NONE);
    ok(BindTo(Wild, 1, Port) == 0, "wildcard bind failed\n");
    ok(BindTo(Specific, 0, Port) == 0, "specific bind failed\n");

    Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&Name, 0, sizeof(Name));
    Name.sin_family = AF_INET;
    Name.sin_port = htons((USHORT)Port);
    Name.sin_addr.s_addr = inet_addr("127.0.0.1");
    ok(sendto(Sender, "x", 1, 0, (struct sockaddr *)&Name, sizeof(Name)) == 1, "sendto failed\n");

    FD_ZERO(&Set);
    FD_SET(Specific, &Set);
    FD_SET(Wild, &Set);
    Count = select(0, &Set, NULL, NULL, &Timeout);
    ok(Count == 1, "%d sockets readable, expected 1\n", Count);
    ok(FD_ISSET(Specific, &Set), "the socket bound to 127.0.0.1 did not get the datagram\n");
    if (FD_ISSET(Specific, &Set))
        ok(recv(Specific, Buffer, sizeof(Buffer), 0) == 1, "recv failed\n");

    closesocket(Sender);
    closesocket(Specific);
    closesocket(Wild);
}

START_TEST(bindconflict)
{
    WSADATA WsaData;
    int Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok_dec(Error, 0);

    TestMatrix(SOCK_STREAM, FALSE);
    TestMatrix(SOCK_STREAM, TRUE);
    TestMatrix(SOCK_DGRAM, FALSE);
    TestLive();
    TestListenerChoice();
    TestUdpDelivery();

    Error = WSACleanup();
    ok_dec(Error, 0);
}
