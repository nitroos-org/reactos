/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a listener refuses the connections its backlog has no room for
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"

#define MAX_CLIENTS 256

/* Windows 10 22H2, measured on a loopback listener that does not accept: with a backlog of 5 and
 * 24 clients at once, exactly 5 connects succeed and are all accepted later; the other 19 do not
 * complete the handshake and fail with WSAECONNREFUSED about 2 s later. A connect that succeeded
 * is never reset afterwards. */
static void
TestRefuse(int Backlog, int Count)
{
    SOCKET Server, Clients[MAX_CLIENTS], Accepted;
    int State[MAX_CLIENTS]; /* 0 pending, 1 connected, 2 refused, 3 other failure */
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr);
    u_long NonBlocking = 1;
    int i, Error, Connected = 0, Refused = 0, Other = 0, Pending, Reset = 0, AcceptCount = 0;
    DWORD Start;
    char Byte;

    Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Server != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Server == INVALID_SOCKET)
        return;
    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Server, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed: %d\n", WSAGetLastError());
    ok(getsockname(Server, (struct sockaddr *)&Addr, &AddrLen) == 0, "getsockname failed: %d\n", WSAGetLastError());
    ok(listen(Server, Backlog) == 0, "listen failed: %d\n", WSAGetLastError());
    ioctlsocket(Server, FIONBIO, &NonBlocking);

    for (i = 0; i < Count; i++)
    {
        State[i] = 3;
        Clients[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Clients[i] == INVALID_SOCKET)
            continue;
        ioctlsocket(Clients[i], FIONBIO, &NonBlocking);
        Error = connect(Clients[i], (struct sockaddr *)&Addr, sizeof(Addr));
        if (Error == 0)
            State[i] = 1;
        else if (WSAGetLastError() == WSAEWOULDBLOCK)
            State[i] = 0;
        else
            State[i] = WSAGetLastError() == WSAECONNREFUSED ? 2 : 3;
    }

    /* A refused connect is retried for a few seconds first */
    Start = GetTickCount();
    do
    {
        fd_set WriteSet, ExceptSet;
        struct timeval Zero = { 0, 0 };

        Pending = 0;
        for (i = 0; i < Count; i++)
        {
            int SoError = 0, Len = sizeof(SoError);

            if (State[i] != 0)
                continue;
            FD_ZERO(&WriteSet);
            FD_ZERO(&ExceptSet);
            FD_SET(Clients[i], &WriteSet);
            FD_SET(Clients[i], &ExceptSet);
            if (select(0, NULL, &WriteSet, &ExceptSet, &Zero) > 0)
            {
                if (FD_ISSET(Clients[i], &ExceptSet))
                {
                    getsockopt(Clients[i], SOL_SOCKET, SO_ERROR, (char *)&SoError, &Len);
                    State[i] = SoError == WSAECONNREFUSED ? 2 : 3;
                    if (State[i] == 3)
                        trace("Client %d failed with %d\n", i, SoError);
                }
                else
                {
                    State[i] = 1;
                }
            }
            else
            {
                Pending++;
            }
        }
        if (Pending)
            Sleep(100);
    } while (Pending && GetTickCount() - Start < 30000);

    /* A connection the listener took must stay up: none is reset behind the application's back */
    Sleep(1000);
    for (i = 0; i < Count; i++)
    {
        if (State[i] == 1)
        {
            Connected++;
            if (recv(Clients[i], &Byte, 1, 0) != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK)
                Reset++;
        }
        else if (State[i] == 2)
            Refused++;
        else
            Other++;
    }

    for (i = 0; i <= Count; i++)
    {
        Accepted = accept(Server, NULL, NULL);
        if (Accepted == INVALID_SOCKET)
            break;
        AcceptCount++;
        closesocket(Accepted);
    }

    trace("Backlog %d, %d clients: %d connected, %d refused, %d other, %d pending, %d reset, %d accepted\n",
          Backlog, Count, Connected, Refused, Other, Pending, Reset, AcceptCount);
    ok(Pending == 0, "Backlog %d: %d connects still pending\n", Backlog, Pending);
    ok(Other == 0, "Backlog %d: %d connects failed with something else than a refusal\n", Backlog, Other);
    ok(Reset == 0, "Backlog %d: %d connections were reset after connect succeeded\n", Backlog, Reset);
    ok(Connected >= Backlog, "Backlog %d: only %d connects succeeded\n", Backlog, Connected);
    ok(Connected < Count, "Backlog %d: all %d connects succeeded\n", Backlog, Count);
    ok(AcceptCount == Connected, "Backlog %d: %d accepted, %d connects succeeded\n", Backlog, AcceptCount, Connected);
    if (is_reactos())
        ok(Connected == Backlog, "Backlog %d: %d connects succeeded\n", Backlog, Connected);

    for (i = 0; i < Count; i++)
    {
        if (Clients[i] != INVALID_SOCKET)
            closesocket(Clients[i]);
    }
    closesocket(Server);
}

START_TEST(backlogrefuse)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    TestRefuse(5, 24);
    TestRefuse(1, 8);
    TestRefuse(16, 64);

    WSACleanup();
}
