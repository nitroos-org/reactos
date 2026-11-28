/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a listener takes the connections its backlog has room for after accepts made room
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"

#define BACKLOG 100
#define EXTRA   50
#define ROUNDS  3

/* A connect to a listener whose queue is full is not answered, or is refused, and its SYN comes again: after half a
 * second (IPv4 over loopback, after a reset) or a second (IPv6, a SYN that was dropped). When accepts made room
 * meanwhile, the connect must complete with the next SYN.
 *
 * The listener went by the room it had stated when the queue was full, until the next connection arrived: of the
 * SYNs that came together, one found room and the others were refused or dropped again, and a connect took a
 * second more (IPv4) or two more (IPv6).
 *
 * Windows is not measured for this (verify on the Windows reference): the test expects that no connect fails and,
 * on ReactOS, that every one of them completes with the SYN that follows the accepts: the first retransmission
 * comes at 0.5 s (IPv4) or 1 s (IPv6), the one after it at 1 s or 3 s, and the limits below lie between the two,
 * with room for a guest that is slow. */
typedef struct
{
    int Family;
    SOCKADDR_STORAGE Addr;
    int Length;
    HANDLE Start;
    SOCKET Socket;
    DWORD Done;
    int Result;
} CLIENT;

static
void
FillAddress(int Family, SOCKADDR_STORAGE *Addr, int *Length)
{
    ZeroMemory(Addr, sizeof(*Addr));
    if (Family == AF_INET6)
    {
        ((SOCKADDR_IN6 *)Addr)->sin6_family = AF_INET6;
        ((SOCKADDR_IN6 *)Addr)->sin6_addr.u.Byte[15] = 1;
        *Length = sizeof(SOCKADDR_IN6);
    }
    else
    {
        ((SOCKADDR_IN *)Addr)->sin_family = AF_INET;
        ((SOCKADDR_IN *)Addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *Length = sizeof(SOCKADDR_IN);
    }
}

/* Waits for the start event, connects, and notes how long that took and how it ended */
static
DWORD
WINAPI
ConnectThread(LPVOID Context)
{
    CLIENT *Client = Context;
    DWORD Begin;

    WaitForSingleObject(Client->Start, INFINITE);
    Begin = GetTickCount();
    Client->Result = connect(Client->Socket, (const struct sockaddr *)&Client->Addr, Client->Length) == 0 ?
                     0 : WSAGetLastError();
    Client->Done = GetTickCount() - Begin;
    return 0;
}

/* Prepares Count clients that connect from threads as soon as Start is set */
static
void
PrepareClients(int Family, const SOCKADDR_STORAGE *Addr, int Length, HANDLE Start, CLIENT *Clients, HANDLE *Threads,
               int Count)
{
    int i;

    for (i = 0; i < Count; i++)
    {
        Clients[i].Family = Family;
        Clients[i].Addr = *Addr;
        Clients[i].Length = Length;
        Clients[i].Start = Start;
        Clients[i].Socket = socket(Family, SOCK_STREAM, IPPROTO_TCP);
        Clients[i].Done = (DWORD)-1;
        Clients[i].Result = -1;
        Threads[i] = CreateThread(NULL, 0, ConnectThread, &Clients[i], 0, NULL);
    }
}

static
void
FinishClients(HANDLE *Threads, int Count)
{
    int i;

    for (i = 0; i < Count; i++)
    {
        WaitForSingleObject(Threads[i], 30000);
        CloseHandle(Threads[i]);
    }
}

static
void
TestRound(int Family, int Round)
{
    SOCKET Server, Accepted;
    SOCKADDR_STORAGE Addr;
    CLIENT Fill[BACKLOG], Extra[EXTRA];
    HANDLE Threads[BACKLOG], Start;
    int Length, i, Connected = 0, Refused = 0, Taken = 0;
    DWORD Slowest = 0, Limit = Family == AF_INET6 ? 2000 : 900;

    Server = socket(Family, SOCK_STREAM, IPPROTO_TCP);
    if (Server == INVALID_SOCKET && Family == AF_INET6)
    {
        skip("No IPv6 sockets: %d\n", WSAGetLastError());
        return;
    }
    ok(Server != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Server == INVALID_SOCKET)
        return;
    FillAddress(Family, &Addr, &Length);
    ok(bind(Server, (struct sockaddr *)&Addr, Length) == 0, "bind failed: %d\n", WSAGetLastError());
    ok(getsockname(Server, (struct sockaddr *)&Addr, &Length) == 0, "getsockname failed: %d\n", WSAGetLastError());
    ok(listen(Server, BACKLOG) == 0, "listen failed: %d\n", WSAGetLastError());

    /* Fill the queue */
    Start = CreateEventW(NULL, TRUE, FALSE, NULL);
    PrepareClients(Family, &Addr, Length, Start, Fill, Threads, BACKLOG);
    Sleep(50);
    SetEvent(Start);
    FinishClients(Threads, BACKLOG);
    for (i = 0; i < BACKLOG; i++)
    {
        if (Fill[i].Result == 0)
            Connected++;
    }
    ok(Connected == BACKLOG, "Family %d: %d of %d connects to an empty queue succeeded\n", Family, Connected, BACKLOG);
    CloseHandle(Start);

    /* More clients connect to the full queue: their SYN is answered with a reset or not at all, and comes again */
    Start = CreateEventW(NULL, TRUE, FALSE, NULL);
    PrepareClients(Family, &Addr, Length, Start, Extra, Threads, EXTRA);
    Sleep(50);
    SetEvent(Start);
    Sleep(100);

    /* One accept, a pause in which the listener goes by what that made, the rest of the accepts at once */
    for (i = 0; i < EXTRA; i++)
    {
        Accepted = accept(Server, NULL, NULL);
        ok(Accepted != INVALID_SOCKET, "Family %d: accept %d failed: %d\n", Family, i, WSAGetLastError());
        if (Accepted != INVALID_SOCKET)
        {
            Taken++;
            closesocket(Accepted);
        }
        if (i == 0)
            Sleep(150);
    }

    /* The queue has room for all of them now */
    FinishClients(Threads, EXTRA);
    CloseHandle(Start);
    Connected = 0;
    for (i = 0; i < EXTRA; i++)
    {
        if (Extra[i].Result == 0)
            Connected++;
        else if (Extra[i].Result == WSAECONNREFUSED)
            Refused++;
        if (Extra[i].Done != (DWORD)-1 && Extra[i].Done > Slowest)
            Slowest = Extra[i].Done;
    }
    trace("Family %d round %d: %d accepted, then %d connects: %d connected, %d refused, the slowest took %lu ms\n",
          Family, Round, Taken, EXTRA, Connected, Refused, Slowest);
    ok(Connected == EXTRA, "Family %d round %d: %d of %d connects succeeded, %d refused, with room for all of them\n",
       Family, Round, Connected, EXTRA, Refused);
    if (is_reactos())
        ok(Slowest < Limit, "Family %d round %d: a connect took %lu ms with room in the queue\n", Family, Round, Slowest);

    for (i = 0; i < BACKLOG; i++)
        closesocket(Fill[i].Socket);
    for (i = 0; i < EXTRA; i++)
        closesocket(Extra[i].Socket);
    closesocket(Server);
}

START_TEST(backlogroom)
{
    WSADATA WsaData;
    int Round;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    for (Round = 0; Round < ROUNDS; Round++)
    {
        TestRound(AF_INET, Round);
        TestRound(AF_INET6, Round);
    }

    WSACleanup();
}
