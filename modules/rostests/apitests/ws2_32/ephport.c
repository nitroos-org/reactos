/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test the ephemeral port range of connect and the reuse of ports held in TIME-WAIT
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

/* Windows 10 22H2 (oracle probe, 2026-11-12): the dynamic range is 49152-65535 (16384 ports). A loop of connects that
 * the client closes first, to one loopback listener, succeeds 16382 times and then fails with WSAEADDRINUSE: every
 * port has a TIME-WAIT of that remote endpoint (120 s). A connect to another listener meanwhile succeeds on those
 * very ports (16368 of its 16371 connects used a local port that was in TIME-WAIT towards the first listener). */
#define RANGE_FIRST 49152
#define RANGE_LAST  65535
#define LOOP_CAP    20000

typedef struct
{
    SOCKET Socket;
    USHORT Port;
    volatile LONG Accepted;
} LISTENER;

static
DWORD
WINAPI
AcceptThread(LPVOID Context)
{
    LISTENER *Listener = Context;
    SOCKET Client;
    char Byte;

    for (;;)
    {
        Client = accept(Listener->Socket, NULL, NULL);
        if (Client == INVALID_SOCKET)
        {
            if (WSAGetLastError() == WSAECONNRESET)
                continue;
            break;
        }
        InterlockedIncrement(&Listener->Accepted);
        /* The client closes first, so its end is the one that goes to TIME-WAIT: wait for its FIN */
        while (recv(Client, &Byte, 1, 0) > 0)
            ;
        closesocket(Client);
    }
    return 0;
}

static
HANDLE
StartListener(LISTENER *Listener)
{
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr);

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Listener->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener->Socket != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Listener->Socket == INVALID_SOCKET)
        return NULL;
    ok(bind(Listener->Socket, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed: %d\n", WSAGetLastError());
    ok(getsockname(Listener->Socket, (struct sockaddr *)&Addr, &AddrLen) == 0, "getsockname failed: %d\n", WSAGetLastError());
    ok(listen(Listener->Socket, 512) == 0, "listen failed: %d\n", WSAGetLastError());
    Listener->Port = ntohs(Addr.sin_port);
    Listener->Accepted = 0;
    return CreateThread(NULL, 0, AcceptThread, Listener, 0, NULL);
}

static
void
StopListener(LISTENER *Listener, HANDLE Thread)
{
    closesocket(Listener->Socket);
    if (Thread)
    {
        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
    }
}

/* One connect from an unbound socket that is closed at once; returns 0 or the WSA error, the local port in *LocalPort */
static
int
ConnectOnce(const LISTENER *To, USHORT *LocalPort)
{
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr), Error = 0;
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    *LocalPort = 0;
    if (Socket == INVALID_SOCKET)
        return WSAGetLastError();
    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Addr.sin_port = htons(To->Port);
    if (connect(Socket, (struct sockaddr *)&Addr, sizeof(Addr)) != 0)
        Error = WSAGetLastError();
    else if (getsockname(Socket, (struct sockaddr *)&Addr, &AddrLen) == 0)
        *LocalPort = ntohs(Addr.sin_port);
    closesocket(Socket);
    return Error;
}

static
void
Test_EphemeralPortsAndTimeWait(void)
{
    static BYTE UsedFirst[65536];
    LISTENER First, Second;
    HANDLE FirstThread, SecondThread;
    USHORT Port;
    int Count, Error = 0, Ok = 0, OutOfRange = 0, Reused = 0, SecondOk = 0, SecondError = 0, i;

    FirstThread = StartListener(&First);
    SecondThread = StartListener(&Second);
    if (!FirstThread || !SecondThread)
    {
        StopListener(&First, FirstThread);
        StopListener(&Second, SecondThread);
        return;
    }

    /* Connects to one listener until none gets a port */
    for (Count = 0; Count < LOOP_CAP; Count++)
    {
        Error = ConnectOnce(&First, &Port);
        if (Error)
            break;
        Ok++;
        if (Port < RANGE_FIRST || Port > RANGE_LAST)
            OutOfRange++;
        UsedFirst[Port] = 1;
    }
    ok(OutOfRange == 0, "%d connects used a local port outside %d-%d\n", OutOfRange, RANGE_FIRST, RANGE_LAST);
    ok(Count < LOOP_CAP, "no connect failed in %d attempts\n", LOOP_CAP);
    ok(Ok >= 15000 && Ok <= RANGE_LAST - RANGE_FIRST + 1, "%d connects succeeded before the first failure\n", Ok);
    ok(Error == WSAEADDRINUSE, "connect with every port in TIME-WAIT towards the listener failed with %d\n", Error);

    /* Another listener: the same local ports are free for it */
    for (i = 0; i < 200; i++)
    {
        int E = ConnectOnce(&Second, &Port);
        if (E)
        {
            SecondError = E;
            break;
        }
        SecondOk++;
        if (UsedFirst[Port])
            Reused++;
    }
    ok(SecondOk == 200, "%d of 200 connects to another listener succeeded (error %d)\n", SecondOk, SecondError);
    ok(Reused > 100, "only %d of the connects to another listener reused a port in TIME-WAIT\n", Reused);

    /* The first listener still finds its connections taken, with the same error */
    Error = ConnectOnce(&First, &Port);
    ok(Error == WSAEADDRINUSE, "connect to the first listener again failed with %d\n", Error);

    /* Every connect that succeeded was accepted */
    for (i = 0; i < 50 && (First.Accepted < Ok || Second.Accepted < SecondOk); i++)
        Sleep(100);
    ok(First.Accepted == Ok, "first listener accepted %ld of %d\n", First.Accepted, Ok);
    ok(Second.Accepted == SecondOk, "second listener accepted %ld of %d\n", Second.Accepted, SecondOk);

    StopListener(&First, FirstThread);
    StopListener(&Second, SecondThread);
}

START_TEST(ephport)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    Test_EphemeralPortsAndTimeWait();

    WSACleanup();
}
