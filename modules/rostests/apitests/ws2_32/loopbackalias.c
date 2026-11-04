/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The whole 127.0.0.0/8 is loopback: bind, listen, connect and UDP
 *              work on any 127.x.y.z address, not only on 127.0.0.1
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

/* Recorded on Windows 10 22H2 for 127.0.0.2: connect() and accept() work, the accepted
 * socket's local address is 127.0.0.2 and its peer 127.0.0.1, the client's local address
 * is 127.0.0.1 and its peer 127.0.0.2. */

static
void
MakeAddress(struct sockaddr_in *Address, const char *Text, USHORT Port)
{
    ZeroMemory(Address, sizeof(*Address));
    Address->sin_family = AF_INET;
    Address->sin_addr.s_addr = inet_addr(Text);
    Address->sin_port = Port;
}

static
void
CheckSockName(const char *What, SOCKET Socket, const char *Text, USHORT Port, BOOL Peer)
{
    struct sockaddr_in Name;
    int Length = sizeof(Name);
    int Result;

    ZeroMemory(&Name, sizeof(Name));
    Result = Peer ? getpeername(Socket, (struct sockaddr *)&Name, &Length)
                  : getsockname(Socket, (struct sockaddr *)&Name, &Length);
    ok(Result == 0, "%s: %s failed %d\n", What, Peer ? "getpeername" : "getsockname", WSAGetLastError());
    if (Result != 0)
        return;
    ok(Name.sin_addr.s_addr == inet_addr(Text), "%s: %s address %s, expected %s\n",
       What, Peer ? "peer" : "local", inet_ntoa(Name.sin_addr), Text);
    if (Port != 0)
        ok(Name.sin_port == Port, "%s: port %u, expected %u\n", What, ntohs(Name.sin_port), ntohs(Port));
}

static
void
TestTcp(const char *Alias)
{
    struct sockaddr_in Address;
    SOCKET Listener, Client, Accepted, Other;
    USHORT Port, ClientPort;
    int Length, Result, Pass;
    char What[64], Byte;

    /* A listener bound to the alias, and a wildcard listener reached through it */
    for (Pass = 0; Pass < 2; Pass++)
    {
        sprintf(What, "%s listener %s", Pass ? "wildcard" : "bound", Alias);
        Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(Listener != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
        if (Listener == INVALID_SOCKET)
            return;
        MakeAddress(&Address, Pass ? "0.0.0.0" : Alias, 0);
        Result = bind(Listener, (struct sockaddr *)&Address, sizeof(Address));
        ok(Result == 0, "%s: bind failed %d\n", What, WSAGetLastError());
        Result = listen(Listener, 5);
        ok(Result == 0, "%s: listen failed %d\n", What, WSAGetLastError());
        Length = sizeof(Address);
        getsockname(Listener, (struct sockaddr *)&Address, &Length);
        Port = Address.sin_port;
        CheckSockName(What, Listener, Pass ? "0.0.0.0" : Alias, Port, FALSE);

        Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        MakeAddress(&Address, Alias, Port);
        Result = connect(Client, (struct sockaddr *)&Address, sizeof(Address));
        ok(Result == 0, "%s: connect failed %d\n", What, WSAGetLastError());
        if (Result == 0)
        {
            Accepted = accept(Listener, NULL, NULL);
            ok(Accepted != INVALID_SOCKET, "%s: accept failed %d\n", What, WSAGetLastError());
            if (Accepted != INVALID_SOCKET)
            {
                CheckSockName(What, Accepted, Alias, Port, FALSE);
                CheckSockName(What, Accepted, "127.0.0.1", 0, TRUE);
                CheckSockName(What, Client, "127.0.0.1", 0, FALSE);
                CheckSockName(What, Client, Alias, Port, TRUE);
                ok(send(Client, "x", 1, 0) == 1, "%s: send failed %d\n", What, WSAGetLastError());
                Byte = 0;
                ok(recv(Accepted, &Byte, 1, 0) == 1 && Byte == 'x', "%s: recv failed %d\n", What, WSAGetLastError());
                closesocket(Accepted);
            }
        }
        closesocket(Client);

        /* A client bound to another alias of its own */
        if (Pass == 0)
        {
            Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            MakeAddress(&Address, Alias, 0);
            Result = bind(Client, (struct sockaddr *)&Address, sizeof(Address));
            ok(Result == 0, "%s: client bind failed %d\n", What, WSAGetLastError());
            Length = sizeof(Address);
            getsockname(Client, (struct sockaddr *)&Address, &Length);
            ClientPort = Address.sin_port;
            MakeAddress(&Address, Alias, Port);
            Result = connect(Client, (struct sockaddr *)&Address, sizeof(Address));
            ok(Result == 0, "%s: connect from the alias failed %d\n", What, WSAGetLastError());
            if (Result == 0)
            {
                Accepted = accept(Listener, NULL, NULL);
                ok(Accepted != INVALID_SOCKET, "%s: accept failed %d\n", What, WSAGetLastError());
                if (Accepted != INVALID_SOCKET)
                {
                    CheckSockName(What, Accepted, Alias, Port, FALSE);
                    CheckSockName(What, Accepted, Alias, ClientPort, TRUE);
                    closesocket(Accepted);
                }
                CheckSockName(What, Client, Alias, ClientPort, FALSE);
            }
            closesocket(Client);
        }
        closesocket(Listener);
    }

    /* Nothing listens on that port any more */
    sprintf(What, "refused %s", Alias);
    Other = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    MakeAddress(&Address, Alias, Port);
    Result = connect(Other, (struct sockaddr *)&Address, sizeof(Address));
    ok(Result == SOCKET_ERROR, "%s: connect succeeded\n", What);
    ok(WSAGetLastError() == WSAECONNREFUSED, "%s: connect error %d\n", What, WSAGetLastError());
    closesocket(Other);
}

static
void
TestUdp(const char *Alias)
{
    struct sockaddr_in Address, From;
    SOCKET Receiver, Sender;
    USHORT Port;
    int Length, Pass, Result;
    char Buffer[8];
    fd_set Set;
    struct timeval Timeout;

    for (Pass = 0; Pass < 2; Pass++)
    {
        Receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        MakeAddress(&Address, Pass ? Alias : "0.0.0.0", 0);
        Result = bind(Receiver, (struct sockaddr *)&Address, sizeof(Address));
        ok(Result == 0, "UDP %s pass %d: bind failed %d\n", Alias, Pass, WSAGetLastError());
        Length = sizeof(Address);
        getsockname(Receiver, (struct sockaddr *)&Address, &Length);
        Port = Address.sin_port;

        MakeAddress(&Address, Alias, Port);
        Result = sendto(Sender, "ping", 4, 0, (struct sockaddr *)&Address, sizeof(Address));
        ok(Result == 4, "UDP %s pass %d: sendto failed %d\n", Alias, Pass, WSAGetLastError());

        FD_ZERO(&Set);
        FD_SET(Receiver, &Set);
        Timeout.tv_sec = 5;
        Timeout.tv_usec = 0;
        Result = select(0, &Set, NULL, NULL, &Timeout);
        ok(Result == 1, "UDP %s pass %d: nothing arrived (%d)\n", Alias, Pass, Result);
        if (Result == 1)
        {
            Length = sizeof(From);
            Result = recvfrom(Receiver, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &Length);
            ok(Result == 4 && !memcmp(Buffer, "ping", 4), "UDP %s pass %d: recvfrom %d error %d\n",
               Alias, Pass, Result, WSAGetLastError());
            ok((ntohl(From.sin_addr.s_addr) >> 24) == 127, "UDP %s pass %d: sender %s\n",
               Alias, Pass, inet_ntoa(From.sin_addr));
        }
        closesocket(Sender);
        closesocket(Receiver);
    }
}

START_TEST(loopbackalias)
{
    WSADATA WsaData;
    struct sockaddr_in Address;
    SOCKET Socket;
    INT Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok(Error == 0, "WSAStartup failed with %d\n", Error);
    if (Error != 0)
        return;

    TestTcp("127.0.0.2");
    TestTcp("127.1.2.3");
    TestUdp("127.0.0.5");

    /* An address that is not ours still cannot be bound */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    MakeAddress(&Address, "203.0.113.9", 0);
    ok(bind(Socket, (struct sockaddr *)&Address, sizeof(Address)) == SOCKET_ERROR, "bind to a foreign address succeeded\n");
    ok(WSAGetLastError() == WSAEADDRNOTAVAIL, "bind to a foreign address: %d\n", WSAGetLastError());
    closesocket(Socket);

    WSACleanup();
}
