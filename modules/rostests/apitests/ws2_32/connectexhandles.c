/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A socket connected with ConnectEx and SO_UPDATE_CONNECT_CONTEXT (what .NET does for
 *              every Socket.ConnectAsync) must not leave a handle behind once it is closed
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>

#define ROUNDS 64

static
DWORD
HandleCount(VOID)
{
    DWORD Count = 0;

    GetProcessHandleCount(GetCurrentProcess(), &Count);
    return Count;
}

static
BOOL
ConnectOnce(LPFN_CONNECTEX pConnectEx, HANDLE Port, const struct sockaddr_in *Server, SOCKET ListenSocket, BOOL Update)
{
    SOCKET Client, Accepted;
    struct sockaddr_in Local;
    OVERLAPPED Overlapped;
    LPOVERLAPPED Completed;
    DWORD Bytes;
    ULONG_PTR Key;
    BOOL Ok = FALSE;

    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Client == INVALID_SOCKET)
        return FALSE;
    ZeroMemory(&Local, sizeof(Local));
    Local.sin_family = AF_INET;
    Local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Client, (struct sockaddr *)&Local, sizeof(Local)) == SOCKET_ERROR ||
        CreateIoCompletionPort((HANDLE)Client, Port, 1, 0) != Port)
        goto Done;

    ZeroMemory(&Overlapped, sizeof(Overlapped));
    if (!pConnectEx(Client, (const struct sockaddr *)Server, sizeof(*Server), NULL, 0, &Bytes, &Overlapped) &&
        WSAGetLastError() != ERROR_IO_PENDING)
        goto Done;
    if (!GetQueuedCompletionStatus(Port, &Bytes, &Key, &Completed, 10000) || Completed != &Overlapped)
        goto Done;

    if (Update && setsockopt(Client, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR)
        goto Done;

    Accepted = accept(ListenSocket, NULL, NULL);
    if (Accepted != INVALID_SOCKET)
    {
        closesocket(Accepted);
        Ok = TRUE;
    }

Done:
    closesocket(Client);
    return Ok;
}

START_TEST(connectexhandles)
{
    WSADATA Data;
    GUID Guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX pConnectEx = NULL;
    SOCKET ListenSocket;
    struct sockaddr_in Server;
    int Len = sizeof(Server);
    HANDLE Port;
    DWORD Bytes, Before, After;
    int Round, Pass;

    ok_int(WSAStartup(MAKEWORD(2, 2), &Data), 0);

    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(ListenSocket != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    if (ListenSocket == INVALID_SOCKET)
        goto Cleanup;
    ZeroMemory(&Server, sizeof(Server));
    Server.sin_family = AF_INET;
    Server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok_int(bind(ListenSocket, (struct sockaddr *)&Server, sizeof(Server)), 0);
    ok_int(listen(ListenSocket, ROUNDS), 0);
    ok_int(getsockname(ListenSocket, (struct sockaddr *)&Server, &Len), 0);

    ok_int(WSAIoctl(ListenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &Guid, sizeof(Guid),
                    &pConnectEx, sizeof(pConnectEx), &Bytes, NULL, NULL), 0);
    Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    ok(Port != NULL, "no completion port\n");
    if (!pConnectEx || !Port)
        goto Cleanup;

    /* Pass 0: plain ConnectEx. Pass 1: with SO_UPDATE_CONNECT_CONTEXT, which leaked one handle per socket */
    for (Pass = 0; Pass < 2; Pass++)
    {
        /* Warm up: one-time handles (the library, helper DLLs) are not a leak */
        ok(ConnectOnce(pConnectEx, Port, &Server, ListenSocket, Pass), "pass %d: warm-up connect failed\n", Pass);

        Before = HandleCount();
        for (Round = 0; Round < ROUNDS; Round++)
        {
            if (!ConnectOnce(pConnectEx, Port, &Server, ListenSocket, Pass))
            {
                ok(0, "pass %d: connect %d failed\n", Pass, Round);
                break;
            }
        }
        After = HandleCount();
        ok(After <= Before + 2, "pass %d (SO_UPDATE_CONNECT_CONTEXT %s): %d handles before, %d after %d sockets\n",
           Pass, Pass ? "set" : "not set", Before, After, Round);
    }

Cleanup:
    if (Port)
        CloseHandle(Port);
    if (ListenSocket != INVALID_SOCKET)
        closesocket(ListenSocket);
    WSACleanup();
}
