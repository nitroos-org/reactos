/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a thread waiting in accept() comes back when another thread closes the listener
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"

#define ROUNDS      3000
#define CLIENTS     3
#define END_WAIT    5000

static DWORD WINAPI
AcceptLoop(PVOID Param)
{
    SOCKET Listener = (SOCKET)(ULONG_PTR)Param, Accepted;
    char Buffer[16];
    int Length;

    for (;;)
    {
        Accepted = accept(Listener, NULL, NULL);
        if (Accepted == INVALID_SOCKET)
            return WSAGetLastError();
        Length = recv(Accepted, Buffer, sizeof(Buffer), 0);
        if (Length > 0)
            send(Accepted, Buffer, Length, 0);
        closesocket(Accepted);
    }
}

/* The accepting thread is on its way back into accept() when the listener closes: its request can
 * reach the driver after the socket's last handle is closed, and must not wait for ever */
START_TEST(acceptclose)
{
    WSADATA WsaData;
    int Round, i, Stuck = 0, Failed = 0;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    for (Round = 0; Round < ROUNDS; Round++)
    {
        struct sockaddr_in Addr;
        int AddrLen = sizeof(Addr);
        SOCKET Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        HANDLE Thread;
        DWORD ExitCode;

        ZeroMemory(&Addr, sizeof(Addr));
        Addr.sin_family = AF_INET;
        Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (Listener == INVALID_SOCKET ||
            bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) != 0 ||
            listen(Listener, 8) != 0 ||
            getsockname(Listener, (struct sockaddr *)&Addr, &AddrLen) != 0)
        {
            ok(0, "round %d: listener failed: %d\n", Round, WSAGetLastError());
            break;
        }
        Thread = CreateThread(NULL, 0, AcceptLoop, (PVOID)(ULONG_PTR)Listener, 0, NULL);
        ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!Thread)
            break;

        for (i = 0; i < CLIENTS; i++)
        {
            SOCKET Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            char Buffer[16];

            if (Client == INVALID_SOCKET)
                continue;
            if (connect(Client, (struct sockaddr *)&Addr, sizeof(Addr)) == 0)
            {
                send(Client, "ping", 4, 0);
                recv(Client, Buffer, sizeof(Buffer), 0);
            }
            else
            {
                Failed++;
            }
            closesocket(Client);
        }

        closesocket(Listener);
        if (WaitForSingleObject(Thread, END_WAIT) != WAIT_OBJECT_0)
        {
            Stuck++;
            if (Stuck <= 3)
                ok(0, "round %d: the thread in accept() did not end within %d ms of closesocket()\n", Round, END_WAIT);
        }
        else
        {
            GetExitCodeThread(Thread, &ExitCode);
            ok(ExitCode == WSAEINTR || ExitCode == WSAENOTSOCK || ExitCode == WSAECONNABORTED ||
               ExitCode == ERROR_OPERATION_ABORTED,
               "round %d: accept ended with error %lu\n", Round, ExitCode);
        }
        CloseHandle(Thread);
    }

    trace("%d rounds, %d threads still in accept(), %d connects failed\n", Round, Stuck, Failed);
    ok(Stuck == 0, "%d threads did not come back from accept()\n", Stuck);
    WSACleanup();
}
