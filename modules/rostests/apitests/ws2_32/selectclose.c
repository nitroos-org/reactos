/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a select() without a time-out comes back when its socket is closed by another thread
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Windows 10: a select() that waits for a socket that another thread closes returns 1 with the socket in the
 * read set (or in the except set), as it does when only the except set holds it; a socket that is only in the
 * write set gives WSAENOTSOCK. When closesocket() ends before select() looks at the socket, select() gives
 * WSAENOTSOCK.
 */

#include "ws2_32.h"

#define ROUNDS      5000
#define END_WAIT    5000

typedef enum { SELMODE_READ, SELMODE_WRITE, SELMODE_EXCEPT } SELMODE;

typedef struct
{
    SOCKET Socket;
    SELMODE Mode;
    int Result;
    int Error;
    BOOL InSet;
    volatile LONG GoFlag;
    volatile LONG *Go;      /* when set, both threads of a race round are released together */
    DWORD Spin;             /* the closing thread waits this long (loop counts) after the release */
} SELECT_PARAM;

static DWORD WINAPI
SelectThread(PVOID Param)
{
    SELECT_PARAM *Select = Param;
    fd_set Set;

    while (Select->Go && !*Select->Go)
        YieldProcessor();
    FD_ZERO(&Set);
    FD_SET(Select->Socket, &Set);
    switch (Select->Mode)
    {
        case SELMODE_READ:
            Select->Result = select(0, &Set, NULL, NULL, NULL);
            break;
        case SELMODE_WRITE:
            Select->Result = select(0, NULL, &Set, NULL, NULL);
            break;
        default:
            Select->Result = select(0, NULL, NULL, &Set, NULL);
            break;
    }
    Select->Error = Select->Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    Select->InSet = Select->Result != SOCKET_ERROR && FD_ISSET(Select->Socket, &Set);
    return 0;
}

static SOCKET
MakeSocket(int Type, BOOL Listen)
{
    struct sockaddr_in Addr;
    SOCKET Socket = socket(AF_INET, Type, 0);

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Socket == INVALID_SOCKET)
        return Socket;
    if (bind(Socket, (struct sockaddr *)&Addr, sizeof(Addr)) != 0 ||
        (Listen && listen(Socket, 4) != 0))
    {
        closesocket(Socket);
        return INVALID_SOCKET;
    }
    return Socket;
}

/* The thread is in select() when the socket is closed */
static void
BlockedSelect(const char *Name, int Type, BOOL Listen, SELMODE Mode)
{
    SELECT_PARAM Select;
    HANDLE Thread;
    int i;

    for (i = 0; i < 3; i++)
    {
        ZeroMemory(&Select, sizeof(Select));
        Select.Socket = MakeSocket(Type, Listen);
        Select.Mode = Mode;
        ok(Select.Socket != INVALID_SOCKET, "%s: socket failed: %d\n", Name, WSAGetLastError());
        if (Select.Socket == INVALID_SOCKET)
            return;
        Thread = CreateThread(NULL, 0, SelectThread, &Select, 0, NULL);
        ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!Thread)
        {
            closesocket(Select.Socket);
            return;
        }

        /* Let the thread block in select() */
        Sleep(200);
        closesocket(Select.Socket);
        if (WaitForSingleObject(Thread, END_WAIT) != WAIT_OBJECT_0)
        {
            ok(0, "%s: the thread in select() did not end within %d ms of closesocket()\n", Name, END_WAIT);
            /* The thread uses Select: leave it */
            return;
        }
        if (Mode == SELMODE_WRITE)
        {
            ok(Select.Result == SOCKET_ERROR && Select.Error == WSAENOTSOCK,
               "%s: select returned %d, error %d, expected WSAENOTSOCK\n", Name, Select.Result, Select.Error);
        }
        else
        {
            ok(Select.Result == 1 && Select.InSet, "%s: select returned %d (error %d, in the set %d), expected 1\n",
               Name, Select.Result, Select.Error, Select.InSet);
        }
        CloseHandle(Thread);
    }
}

static DWORD WINAPI
CloseThread(PVOID Param)
{
    SELECT_PARAM *Select = Param;
    volatile DWORD Spin;
    DWORD i;

    while (!*Select->Go)
        YieldProcessor();
    for (i = 0, Spin = 0; i < Select->Spin; i++)
        Spin++;
    closesocket(Select->Socket);
    return 0;
}

/* closesocket() runs while the select() request is on its way to the driver: the request can be queued after
 * the socket's cleanup, and must not wait for ever. The two threads are released together, and the closing
 * one waits a little longer each round to meet every stage of the request */
static void
RaceSelect(const char *Name, int Type, BOOL Listen)
{
    int Round, Stuck = 0, Bad = 0, Reported = 0, NotSock = 0;

    for (Round = 0; Round < ROUNDS; Round++)
    {
        SELECT_PARAM *Select = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Select));
        HANDLE Threads[2];

        Select->Socket = MakeSocket(Type, Listen);
        Select->Mode = SELMODE_READ;
        Select->Go = &Select->GoFlag;
        Select->Spin = (Round % 5) ? (Round % 97) * 150 : 0;
        if (Select->Socket == INVALID_SOCKET)
        {
            ok(0, "%s round %d: socket failed: %d\n", Name, Round, WSAGetLastError());
            HeapFree(GetProcessHeap(), 0, Select);
            break;
        }
        Threads[0] = CreateThread(NULL, 0, SelectThread, Select, 0, NULL);
        Threads[1] = CreateThread(NULL, 0, CloseThread, Select, 0, NULL);
        if (!Threads[0] || !Threads[1])
        {
            ok(0, "%s round %d: CreateThread failed: %lu\n", Name, Round, GetLastError());
            /* Release what runs, and leave the allocation to it */
            Select->GoFlag = 1;
            break;
        }
        Sleep(0);
        Select->GoFlag = 1;

        if (WaitForMultipleObjects(2, Threads, TRUE, END_WAIT) != WAIT_OBJECT_0)
        {
            Stuck++;
            if (Stuck <= 3)
                ok(0, "%s round %d: the thread in select() did not end within %d ms of closesocket()\n",
                   Name, Round, END_WAIT);
            /* A stuck thread still uses Select: leave it */
            if (Stuck >= 20)
                break;
            continue;
        }
        if (Select->Result == 1 && Select->InSet)
            Reported++;
        else if (Select->Result == SOCKET_ERROR && Select->Error == WSAENOTSOCK)
            NotSock++;
        else
        {
            Bad++;
            if (Bad <= 3)
                ok(0, "%s round %d: select returned %d, error %d, in the set %d\n",
                   Name, Round, Select->Result, Select->Error, Select->InSet);
        }
        CloseHandle(Threads[0]);
        CloseHandle(Threads[1]);
        HeapFree(GetProcessHeap(), 0, Select);
    }

    trace("%s: %d rounds, %d select() calls report the closed socket, %d WSAENOTSOCK, %d other, %d stuck\n",
          Name, Round, Reported, NotSock, Bad, Stuck);
    ok(Stuck == 0, "%s: %d threads did not come back from select()\n", Name, Stuck);
    ok(Bad == 0, "%s: %d select() calls returned something else\n", Name, Bad);
}

START_TEST(selectclose)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    BlockedSelect("udp read", SOCK_DGRAM, FALSE, SELMODE_READ);
    BlockedSelect("listener read", SOCK_STREAM, TRUE, SELMODE_READ);
    BlockedSelect("tcp except", SOCK_STREAM, FALSE, SELMODE_EXCEPT);
    BlockedSelect("tcp write", SOCK_STREAM, FALSE, SELMODE_WRITE);

    RaceSelect("udp", SOCK_DGRAM, FALSE);
    RaceSelect("listener", SOCK_STREAM, TRUE);

    WSACleanup();
}
