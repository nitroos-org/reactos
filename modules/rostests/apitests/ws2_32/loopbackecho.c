/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A recv returns what is queued (up to its buffer), and an echo exchange of a
 *              program that sends 64 KB and then reads what is ready does not fall behind
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows Server 2022 (loopback): with 64 KB queued a recv with a 64 KB buffer returns
 * 64 KB, and a 64 MB echo exchange that sends 64 KB and then does one recv of what is ready
 * finishes in about 0.2 s with at most 256 KB unread. A receive buffer of 8 KB made every recv
 * return 8 KB: the unread data of that exchange grew to tens of MB and it stalled for seconds
 * or never finished.
 */

#include "ws2_32.h"

#define CHUNK       65536
#define EXCHANGE_MB 16

static
BOOL
MakePair(
    _Out_ SOCKET *Client,
    _Out_ SOCKET *Server)
{
    SOCKET Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in Address;
    INT Length = sizeof(Address);

    *Client = *Server = INVALID_SOCKET;
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (Listener == INVALID_SOCKET ||
        bind(Listener, (struct sockaddr *)&Address, sizeof(Address)) != 0 ||
        listen(Listener, 1) != 0 ||
        getsockname(Listener, (struct sockaddr *)&Address, &Length) != 0)
    {
        ok(0, "listener setup failed, error %d\n", WSAGetLastError());
        closesocket(Listener);
        return FALSE;
    }
    *Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect(*Client, (struct sockaddr *)&Address, sizeof(Address)) != 0)
    {
        ok(0, "connect failed, error %d\n", WSAGetLastError());
        closesocket(Listener);
        return FALSE;
    }
    *Server = accept(Listener, NULL, NULL);
    closesocket(Listener);
    ok(*Server != INVALID_SOCKET, "accept failed, error %d\n", WSAGetLastError());
    return *Server != INVALID_SOCKET;
}

static
VOID
TestRecvTakesWhatIsQueued(VOID)
{
    static UCHAR Buffer[CHUNK];
    SOCKET Client, Server;
    ULONG Available = 0, Tick, Timeout = 5000;
    INT Sent, Length, Round;

    if (!MakePair(&Client, &Server))
        return;
    setsockopt(Server, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&Timeout, sizeof(Timeout));
    FillMemory(Buffer, sizeof(Buffer), 0x5A);

    /* From the first recv of a socket on, a recv returns what is queued, up to its buffer (Windows Server 2022) */
    for (Round = 0; Round < 3; Round++)
    {
        Sent = send(Client, (PCHAR)Buffer, CHUNK, 0);
        ok(Sent == CHUNK, "send returned %d, error %d\n", Sent, WSAGetLastError());

        /* Everything arrives on loopback within a moment */
        Tick = GetTickCount();
        Sleep(100);
        while (GetTickCount() - Tick < 3000 &&
               ioctlsocket(Server, FIONREAD, &Available) == 0 && Available < CHUNK)
            Sleep(10);
        Sleep(100);

        ZeroMemory(Buffer, sizeof(Buffer));
        Length = recv(Server, (PCHAR)Buffer, sizeof(Buffer), 0);
        ok(Length > 0, "round %d: recv returned %d, error %d\n", Round, Length, WSAGetLastError());
        ok(Length == CHUNK, "round %d: recv with %d bytes queued returned %d\n", Round, CHUNK, Length);
        if (Length > 0 && Length < CHUNK)
        {
            /* Drains the rest of the chunk */
            while (Length < CHUNK)
            {
                INT More = recv(Server, (PCHAR)Buffer, CHUNK - Length, 0);
                if (More <= 0)
                    break;
                Length += More;
            }
        }
        FillMemory(Buffer, sizeof(Buffer), 0x5A);
    }

    closesocket(Client);
    closesocket(Server);
}

typedef struct
{
    SOCKET Socket;
} ECHO_CONTEXT;

static
DWORD
WINAPI
EchoThread(
    _In_ PVOID Parameter)
{
    ECHO_CONTEXT *Context = Parameter;
    static UCHAR Buffer[CHUNK];
    INT Length, Offset, Written;

    while ((Length = recv(Context->Socket, (PCHAR)Buffer, sizeof(Buffer), 0)) > 0)
    {
        for (Offset = 0; Offset < Length; Offset += Written)
        {
            Written = send(Context->Socket, (PCHAR)Buffer + Offset, Length - Offset, 0);
            if (Written <= 0)
                return 1;
        }
    }
    return 0;
}

typedef struct
{
    SOCKET Socket;
    ULONGLONG Total;
    INT Result;
    ULONGLONG MaxUnread;
    volatile LONG Done;
} EXCHANGE_CONTEXT;

/* The exchange of a program that sends one chunk and then reads what is ready, once */
static
DWORD
WINAPI
ExchangeThread(
    _In_ PVOID Parameter)
{
    EXCHANGE_CONTEXT *Context = Parameter;
    static UCHAR SendBuffer[CHUNK], RecvBuffer[CHUNK];
    ULONGLONG Sent = 0, Received = 0;

    FillMemory(SendBuffer, sizeof(SendBuffer), 0xA5);
    while (Received < Context->Total)
    {
        fd_set Set;
        struct timeval Timeout = { Sent < Context->Total ? 0 : 20, 0 };
        INT Length;

        if (Sent < Context->Total)
        {
            Length = send(Context->Socket, (PCHAR)SendBuffer, CHUNK, 0);
            if (Length <= 0)
            {
                Context->Result = 1;
                break;
            }
            Sent += Length;
            if (Sent - Received > Context->MaxUnread)
                Context->MaxUnread = Sent - Received;
        }
        FD_ZERO(&Set);
        FD_SET(Context->Socket, &Set);
        if (select(0, &Set, NULL, NULL, &Timeout) > 0)
        {
            Length = recv(Context->Socket, (PCHAR)RecvBuffer, sizeof(RecvBuffer), 0);
            if (Length <= 0)
            {
                Context->Result = 2;
                break;
            }
            Received += Length;
        }
        else if (Sent >= Context->Total)
        {
            Context->Result = 3;
            break;
        }
    }
    InterlockedExchange(&Context->Done, 1);
    return 0;
}

static
VOID
TestEchoExchange(VOID)
{
    SOCKET Client, Server;
    ECHO_CONTEXT Echo;
    EXCHANGE_CONTEXT Exchange;
    HANDLE Threads[2];
    ULONG Start, Elapsed;

    if (!MakePair(&Client, &Server))
        return;
    Echo.Socket = Server;
    ZeroMemory(&Exchange, sizeof(Exchange));
    Exchange.Socket = Client;
    Exchange.Total = (ULONGLONG)EXCHANGE_MB << 20;

    Start = GetTickCount();
    Threads[0] = CreateThread(NULL, 0, EchoThread, &Echo, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, ExchangeThread, &Exchange, 0, NULL);
    ok(Threads[0] && Threads[1], "CreateThread failed\n");
    if (Threads[0] && Threads[1])
        WaitForSingleObject(Threads[1], 30000);
    Elapsed = GetTickCount() - Start;

    ok(Exchange.Done, "the %d MB echo exchange did not finish in %lu ms (unread %I64u KB)\n",
       EXCHANGE_MB, Elapsed, Exchange.MaxUnread >> 10);
    if (Exchange.Done)
    {
        ok(Exchange.Result == 0, "exchange result %d\n", Exchange.Result);
        ok(Elapsed < 10000, "the %d MB echo exchange took %lu ms\n", EXCHANGE_MB, Elapsed);
        /* Windows: at most 256 KB unread; a few MB would be a recv that returns less than it was asked for */
        ok(Exchange.MaxUnread <= 2 * 1024 * 1024, "unread data grew to %I64u KB\n", Exchange.MaxUnread >> 10);
    }

    /* Unblocks whatever is left of the two threads */
    closesocket(Client);
    closesocket(Server);
    if (Threads[0])
    {
        WaitForSingleObject(Threads[0], 5000);
        CloseHandle(Threads[0]);
    }
    if (Threads[1])
    {
        WaitForSingleObject(Threads[1], 5000);
        CloseHandle(Threads[1]);
    }
}

START_TEST(loopbackecho)
{
    WSADATA wsaData;
    INT Result;

    Result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    ok(Result == 0, "WSAStartup failed, error %d\n", Result);
    if (Result != 0)
        return;

    TestRecvTakesWhatIsQueued();
    TestEchoExchange();

    WSACleanup();
}
