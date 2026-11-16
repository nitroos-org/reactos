/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test select() with more sockets in its sets than FD_SETSIZE
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * An application may define a larger FD_SETSIZE and pass sets that hold more sockets than 64.
 * Whatever select() does with them, it must not depend on which set the extra socket is in:
 * a socket over the limit in the except set is handled as one in the read or the write set.
 */

#include "ws2_32.h"

#define SOCKETS 65

typedef struct
{
    u_int fd_count;
    SOCKET fd_array[SOCKETS];
} BIG_FD_SET;

static void
AddTo(BIG_FD_SET *Set, SOCKET Socket)
{
    Set->fd_array[Set->fd_count++] = Socket;
}

static int
SelectSplit(SOCKET *Sockets, int Count, int Where, int *Error)
{
    BIG_FD_SET Read, Write, Except;
    struct timeval Timeout = { 0, 0 };
    int i, Result;

    Read.fd_count = Write.fd_count = Except.fd_count = 0;
    for (i = 0; i < Count - 1; i++)
        AddTo(&Read, Sockets[i]);
    /* The last socket goes to the read (0), the write (1) or the except (2) set */
    AddTo(Where == 0 ? &Read : Where == 1 ? &Write : &Except, Sockets[Count - 1]);

    Result = select(0, (fd_set *)&Read, (fd_set *)&Write, (fd_set *)&Except, &Timeout);
    *Error = Result == SOCKET_ERROR ? WSAGetLastError() : 0;
    return Result;
}

START_TEST(selectsets)
{
    static const char * const Names[] = { "read", "write", "except" };
    WSADATA WsaData;
    SOCKET Sockets[SOCKETS];
    struct sockaddr_in Addr;
    int i, Count, Where, Result[3], Error[3];

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (Count = 0; Count < SOCKETS; Count++)
    {
        /* Bound UDP sockets: never readable here, a write set reports them all */
        Sockets[Count] = socket(AF_INET, SOCK_DGRAM, 0);
        if (Sockets[Count] == INVALID_SOCKET)
            break;
        if (bind(Sockets[Count], (struct sockaddr *)&Addr, sizeof(Addr)) != 0)
        {
            closesocket(Sockets[Count]);
            break;
        }
    }
    ok(Count == SOCKETS, "only %d sockets: %d\n", Count, WSAGetLastError());

    if (Count == SOCKETS)
    {
        /* 64 sockets fit whichever set holds the last one: nothing is readable, so select() returns 0
           unless the last socket is in the write set */
        for (Where = 0; Where < 3; Where++)
        {
            Result[Where] = SelectSplit(Sockets, SOCKETS - 1, Where, &Error[Where]);
            ok(Result[Where] == (Where == 1 ? 1 : 0), "64 sockets, the last in the %s set: select returned %d, error %d\n",
               Names[Where], Result[Where], Error[Where]);
        }

        /* 65: the same answer whether the 65th is in the read or the except set (Windows: 0, ReactOS: WSAEFAULT) */
        for (Where = 0; Where < 3; Where++)
            Result[Where] = SelectSplit(Sockets, SOCKETS, Where, &Error[Where]);
        trace("65 sockets: read %d (%d), write %d (%d), except %d (%d)\n",
              Result[0], Error[0], Result[1], Error[1], Result[2], Error[2]);
        ok(Result[0] == 0 || (Result[0] == SOCKET_ERROR && Error[0] == WSAEFAULT),
           "65 sockets, the last in the read set: select returned %d, error %d\n", Result[0], Error[0]);
        ok(Result[2] == Result[0] && Error[2] == Error[0],
           "65 sockets, the last in the except set: select returned %d, error %d; in the read set %d, error %d\n",
           Result[2], Error[2], Result[0], Error[0]);
    }

    for (i = 0; i < Count; i++)
        closesocket(Sockets[i]);
    WSACleanup();
}
