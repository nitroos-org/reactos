/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The local name of an accepted TCP socket is the connection's own
 *              address, not the wildcard address the listener is bound to
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>

/* The expected values were recorded on Windows 10 22H2: a listener bound to
 * 0.0.0.0 keeps reporting 0.0.0.0, while the socket returned by accept(),
 * WSAAccept() and AcceptEx() (before and after SO_UPDATE_ACCEPT_CONTEXT) reports
 * the address the client connected to and the listener's port, and its peer is
 * the client's own name. */

#define ADDRLEN (sizeof(struct sockaddr_in) + 16)

static
void
CheckName(const char *What, const char *Which, const struct sockaddr *Name, int Length,
          ULONG Address, USHORT Port)
{
    const struct sockaddr_in *In = (const struct sockaddr_in *)Name;

    ok(Length == sizeof(*In), "%s: %s length %d\n", What, Which, Length);
    ok(In->sin_family == AF_INET, "%s: %s family %u\n", What, Which, In->sin_family);
    ok(In->sin_addr.s_addr == Address, "%s: %s address 0x%08lx, expected 0x%08lx\n",
       What, Which, In->sin_addr.s_addr, Address);
    ok(In->sin_port == Port, "%s: %s port %u, expected %u\n",
       What, Which, ntohs(In->sin_port), ntohs(Port));
}

static
void
CheckSocketNames(const char *What, SOCKET Accepted, SOCKET Client, ULONG Target, USHORT ListenPort)
{
    struct sockaddr_in Name, ClientName;
    int Length;

    Length = sizeof(Name);
    memset(&Name, 0x55, sizeof(Name));
    ok(getsockname(Accepted, (struct sockaddr *)&Name, &Length) == 0,
       "%s: getsockname failed %d\n", What, WSAGetLastError());
    CheckName(What, "accepted local", (struct sockaddr *)&Name, Length, Target, ListenPort);

    Length = sizeof(ClientName);
    ok(getsockname(Client, (struct sockaddr *)&ClientName, &Length) == 0, "%s: client getsockname failed\n", What);
    Length = sizeof(Name);
    memset(&Name, 0x55, sizeof(Name));
    ok(getpeername(Accepted, (struct sockaddr *)&Name, &Length) == 0,
       "%s: getpeername failed %d\n", What, WSAGetLastError());
    CheckName(What, "accepted peer", (struct sockaddr *)&Name, Length, ClientName.sin_addr.s_addr, ClientName.sin_port);

    /* The client's own view is the mirror image */
    Length = sizeof(Name);
    ok(getpeername(Client, (struct sockaddr *)&Name, &Length) == 0, "%s: client getpeername failed\n", What);
    CheckName(What, "client peer", (struct sockaddr *)&Name, Length, Target, ListenPort);
    ok(ClientName.sin_addr.s_addr == Target, "%s: client local address %s\n", What, inet_ntoa(ClientName.sin_addr));
}

static
SOCKET
ConnectClient(ULONG Target, USHORT Port)
{
    struct sockaddr_in Address;
    SOCKET Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    ok(Client != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    if (Client == INVALID_SOCKET)
        return INVALID_SOCKET;
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = Target;
    Address.sin_port = Port;
    if (connect(Client, (struct sockaddr *)&Address, sizeof(Address)) != 0)
    {
        ok(0, "connect to %s failed %d\n", inet_ntoa(Address.sin_addr), WSAGetLastError());
        closesocket(Client);
        return INVALID_SOCKET;
    }
    return Client;
}

static
void
CheckSocketPair(const char *What, SOCKET Accepted, SOCKET Client)
{
    char Byte = 0;

    ok(send(Client, "x", 1, 0) == 1, "%s: send failed %d\n", What, WSAGetLastError());
    ok(recv(Accepted, &Byte, 1, 0) == 1 && Byte == 'x', "%s: recv failed %d\n", What, WSAGetLastError());
}

static
void
TestAccepted(ULONG Target, ULONG BindAddress)
{
    struct sockaddr_in Address, Peer;
    SOCKET Listener, Client, Accepted;
    USHORT Port;
    int Length;
    char What[64];

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    if (Listener == INVALID_SOCKET)
        return;
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = BindAddress;
    ok(bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) == 0, "bind failed %d\n", WSAGetLastError());
    ok(listen(Listener, 5) == 0, "listen failed %d\n", WSAGetLastError());
    Length = sizeof(Address);
    getsockname(Listener, (struct sockaddr *)&Address, &Length);
    Port = Address.sin_port;

    /* accept() */
    sprintf(What, "accept to %s", inet_ntoa(*(struct in_addr *)&Target));
    Client = ConnectClient(Target, Port);
    if (Client != INVALID_SOCKET)
    {
        Length = sizeof(Peer);
        Accepted = accept(Listener, (struct sockaddr *)&Peer, &Length);
        ok(Accepted != INVALID_SOCKET, "%s: accept failed %d\n", What, WSAGetLastError());
        if (Accepted != INVALID_SOCKET)
        {
            CheckSocketNames(What, Accepted, Client, Target, Port);
            CheckSocketPair(What, Accepted, Client);
            closesocket(Accepted);
        }
        closesocket(Client);
    }

    /* WSAAccept() */
    sprintf(What, "WSAAccept to %s", inet_ntoa(*(struct in_addr *)&Target));
    Client = ConnectClient(Target, Port);
    if (Client != INVALID_SOCKET)
    {
        Length = sizeof(Peer);
        Accepted = WSAAccept(Listener, (struct sockaddr *)&Peer, &Length, NULL, 0);
        ok(Accepted != INVALID_SOCKET, "%s: WSAAccept failed %d\n", What, WSAGetLastError());
        if (Accepted != INVALID_SOCKET)
        {
            CheckSocketNames(What, Accepted, Client, Target, Port);
            closesocket(Accepted);
        }
        closesocket(Client);
    }

    /* AcceptEx() with GetAcceptExSockaddrs() and SO_UPDATE_ACCEPT_CONTEXT */
    sprintf(What, "AcceptEx to %s", inet_ntoa(*(struct in_addr *)&Target));
    {
        GUID AcceptExGuid = WSAID_ACCEPTEX, GetAddrsGuid = WSAID_GETACCEPTEXSOCKADDRS;
        LPFN_ACCEPTEX pAcceptEx = NULL;
        LPFN_GETACCEPTEXSOCKADDRS pGetAddrs = NULL;
        DWORD Bytes, Flags;
        char Buffer[2 * ADDRLEN];
        OVERLAPPED Overlapped;
        struct sockaddr *Local = NULL, *Remote = NULL;
        int LocalLength = 0, RemoteLength = 0;
        BOOL Done;

        WSAIoctl(Listener, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptExGuid, sizeof(AcceptExGuid),
                 &pAcceptEx, sizeof(pAcceptEx), &Bytes, NULL, NULL);
        WSAIoctl(Listener, SIO_GET_EXTENSION_FUNCTION_POINTER, &GetAddrsGuid, sizeof(GetAddrsGuid),
                 &pGetAddrs, sizeof(pGetAddrs), &Bytes, NULL, NULL);
        ok(pAcceptEx && pGetAddrs, "extension functions missing\n");
        Accepted = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (pAcceptEx && pGetAddrs && Accepted != INVALID_SOCKET)
        {
            ZeroMemory(&Overlapped, sizeof(Overlapped));
            Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            ZeroMemory(Buffer, sizeof(Buffer));
            Done = pAcceptEx(Listener, Accepted, Buffer, 0, ADDRLEN, ADDRLEN, &Bytes, &Overlapped);
            ok(Done || WSAGetLastError() == ERROR_IO_PENDING, "%s: AcceptEx failed %d\n", What, WSAGetLastError());
            Client = ConnectClient(Target, Port);
            if (Client != INVALID_SOCKET)
            {
                ok(WaitForSingleObject(Overlapped.hEvent, 10000) == WAIT_OBJECT_0, "%s: AcceptEx never completed\n", What);
                ok(WSAGetOverlappedResult(Listener, &Overlapped, &Bytes, FALSE, &Flags), "%s: completion failed %d\n",
                   What, WSAGetLastError());
                pGetAddrs(Buffer, 0, ADDRLEN, ADDRLEN, &Local, &LocalLength, &Remote, &RemoteLength);
                ok(Local && Remote, "%s: no addresses\n", What);
                if (Local && Remote)
                {
                    struct sockaddr_in ClientName;
                    int Length = sizeof(ClientName);

                    getsockname(Client, (struct sockaddr *)&ClientName, &Length);
                    CheckName(What, "GetAcceptExSockaddrs local", Local, LocalLength, Target, Port);
                    CheckName(What, "GetAcceptExSockaddrs remote", Remote, RemoteLength,
                              ClientName.sin_addr.s_addr, ClientName.sin_port);
                }
                ok(setsockopt(Accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&Listener, sizeof(Listener)) == 0,
                   "%s: SO_UPDATE_ACCEPT_CONTEXT failed %d\n", What, WSAGetLastError());
                CheckSocketNames(What, Accepted, Client, Target, Port);
                CheckSocketPair(What, Accepted, Client);
                closesocket(Client);
            }
            CloseHandle(Overlapped.hEvent);
        }
        if (Accepted != INVALID_SOCKET)
            closesocket(Accepted);
    }

    /* The listener's own name is unchanged */
    Length = sizeof(Address);
    memset(&Address, 0x55, sizeof(Address));
    ok(getsockname(Listener, (struct sockaddr *)&Address, &Length) == 0, "listener getsockname failed\n");
    CheckName("listener", "local", (struct sockaddr *)&Address, Length, BindAddress, Port);
    closesocket(Listener);
}

/* The address of the interface that reaches an outside peer; connect() on UDP sends nothing */
static
ULONG
FindInterfaceAddress(void)
{
    struct sockaddr_in Address;
    int Length;
    SOCKET Socket;
    ULONG Result = 0;
    int Tries;

    /* A freshly booted machine may still be waiting for its address */
    for (Tries = 0; Tries < 30 && Result == 0; Tries++)
    {
        Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (Socket == INVALID_SOCKET)
            return 0;
        ZeroMemory(&Address, sizeof(Address));
        Address.sin_family = AF_INET;
        Address.sin_port = htons(9);
        Address.sin_addr.s_addr = inet_addr("203.0.113.9");
        Length = sizeof(Address);
        /* connect() on a datagram socket sends nothing */
        if (connect(Socket, (struct sockaddr *)&Address, sizeof(Address)) == 0 &&
            getsockname(Socket, (struct sockaddr *)&Address, &Length) == 0)
            Result = Address.sin_addr.s_addr;
        closesocket(Socket);
        if (Result == 0)
            Sleep(500);
    }
    return Result;
}

START_TEST(acceptname)
{
    WSADATA WsaData;
    ULONG Interface;
    INT Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok(Error == 0, "WSAStartup failed with %d\n", Error);
    if (Error != 0)
        return;

    /* wildcard listener, connected through loopback and through the interface address */
    TestAccepted(htonl(INADDR_LOOPBACK), htonl(INADDR_ANY));
    Interface = FindInterfaceAddress();
    if (Interface != 0 && Interface != htonl(INADDR_LOOPBACK))
        TestAccepted(Interface, htonl(INADDR_ANY));
    else
        skip("no interface address to connect through\n");

    /* a listener bound to a concrete address keeps it */
    TestAccepted(htonl(INADDR_LOOPBACK), htonl(INADDR_LOOPBACK));

    WSACleanup();
}
