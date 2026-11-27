/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Many overlapped WSASend calls on a loopback stream socket whose peer starts to read late: every send
 *              completes with its length, and the peer gets the bytes in the order of the sends, whether the sends
 *              complete through an event, a completion port or a completion routine. (A send whose bytes went out
 *              while the window counted them for a request after it waited for ever, and so did every send behind
 *              it; a send queued while the window had room passed one that waited for room.)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values are what Windows Server 2022 does (every send completes, the peer gets every byte in order).
 */

#include "ws2_32.h"

#define SEND_COUNT 128
#define SEND_LEN   16384
#define RUNS       6

/* The byte at a position of the stream */
#define ORDER_BYTE(Pos) ((BYTE)((Pos) ^ ((Pos) >> 8) ^ ((Pos) >> 14) * 7))

typedef struct _ORDER_SEND
{
    WSAOVERLAPPED Overlapped;   /* first: the completion routine gets it back */
    WSABUF Buffer;
    volatile LONG Done;
    DWORD Bytes;
    DWORD Error;
} ORDER_SEND;

typedef struct _ORDER_READER
{
    SOCKET Socket;
    LONG64 Received;
    LONG64 FirstBad;
} ORDER_READER;

static ORDER_SEND Sends[SEND_COUNT];
static volatile LONG RoutineCount;

static void CALLBACK OrderSendDone(DWORD Error, DWORD Bytes, LPWSAOVERLAPPED Overlapped, DWORD Flags)
{
    ORDER_SEND *Send = (ORDER_SEND *)Overlapped;

    Send->Bytes = Bytes;
    Send->Error = Error;
    Send->Done = 1;
    InterlockedIncrement(&RoutineCount);
}

/* Starts reading after the sender has queued everything, then reads all of it */
static DWORD WINAPI OrderReader(LPVOID Param)
{
    ORDER_READER *Reader = Param;
    static BYTE Buffer[65536];
    int Count, i;

    Sleep(500);
    while ((Count = recv(Reader->Socket, (char *)Buffer, sizeof(Buffer), 0)) > 0)
    {
        for (i = 0; i < Count && Reader->FirstBad < 0; i++)
        {
            if (Buffer[i] != ORDER_BYTE(Reader->Received + i))
                Reader->FirstBad = Reader->Received + i;
        }
        Reader->Received += Count;
    }
    return 0;
}

static BOOL MakePair(SOCKET *Client, SOCKET *Server)
{
    SOCKET Listener;
    struct sockaddr_in Addr = { 0 };
    int Len = sizeof(Addr);

    *Client = *Server = INVALID_SOCKET;
    Listener = socket(AF_INET, SOCK_STREAM, 0);
    if (Listener == INVALID_SOCKET)
        return FALSE;
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) || listen(Listener, 1) ||
        getsockname(Listener, (struct sockaddr *)&Addr, &Len))
    {
        closesocket(Listener);
        return FALSE;
    }
    *Client = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (*Client == INVALID_SOCKET || connect(*Client, (struct sockaddr *)&Addr, sizeof(Addr)))
    {
        if (*Client != INVALID_SOCKET)
            closesocket(*Client);
        *Client = INVALID_SOCKET;
        closesocket(Listener);
        return FALSE;
    }
    *Server = accept(Listener, NULL, NULL);
    closesocket(Listener);
    if (*Server == INVALID_SOCKET)
    {
        closesocket(*Client);
        *Client = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

/* Mode: 'e' event, 'i' completion port, 'r' completion routine */
static void OrderRun(char Mode, int Run)
{
    SOCKET Client, Server;
    HANDLE Port = NULL, Thread;
    ORDER_READER Reader;
    DWORD Start, Bytes, Flags;
    LONG64 Reported = 0;
    int i, k, Left, Failed = 0;

    if (!MakePair(&Client, &Server))
    {
        ok(0, "%c run %d: no connection, error %d\n", Mode, Run, WSAGetLastError());
        return;
    }
    if (Mode == 'i')
    {
        Port = CreateIoCompletionPort((HANDLE)Client, NULL, 1, 0);
        ok(Port != NULL, "CreateIoCompletionPort failed %lu\n", GetLastError());
    }

    /* Every send its own buffer, filled first, so that they are queued as fast as possible */
    for (i = 0; i < SEND_COUNT; i++)
    {
        ZeroMemory(&Sends[i], sizeof(Sends[i]));
        Sends[i].Buffer.len = SEND_LEN;
        Sends[i].Buffer.buf = HeapAlloc(GetProcessHeap(), 0, SEND_LEN);
        for (k = 0; k < SEND_LEN; k++)
            Sends[i].Buffer.buf[k] = (char)ORDER_BYTE((LONG64)i * SEND_LEN + k);
        if (Mode == 'e')
            Sends[i].Overlapped.hEvent = WSACreateEvent();
    }
    RoutineCount = 0;
    Reader.Socket = Server;
    Reader.Received = 0;
    Reader.FirstBad = -1;
    Thread = CreateThread(NULL, 0, OrderReader, &Reader, 0, NULL);

    for (i = 0; i < SEND_COUNT; i++)
    {
        if (WSASend(Client, &Sends[i].Buffer, 1, &Bytes, 0, &Sends[i].Overlapped,
                    Mode == 'r' ? OrderSendDone : NULL) && WSAGetLastError() != WSA_IO_PENDING)
        {
            ok(0, "%c run %d: WSASend %d failed with %d\n", Mode, Run, i, WSAGetLastError());
            Sends[i].Done = 2;
            if (Mode == 'r')
                InterlockedIncrement(&RoutineCount);
        }
    }

    /* Every send completes while the peer reads */
    Start = GetTickCount();
    Left = SEND_COUNT;
    while (Left && GetTickCount() - Start < 20000)
    {
        if (Mode == 'e')
        {
            Left = 0;
            for (i = 0; i < SEND_COUNT; i++)
            {
                if (Sends[i].Done)
                    continue;
                if (WaitForSingleObject(Sends[i].Overlapped.hEvent, 0) == WAIT_OBJECT_0)
                {
                    if (WSAGetOverlappedResult(Client, &Sends[i].Overlapped, &Bytes, FALSE, &Flags))
                        Sends[i].Bytes = Bytes;
                    else
                        Sends[i].Error = WSAGetLastError();
                    Sends[i].Done = 1;
                }
                else
                {
                    Left++;
                }
            }
            if (Left)
                Sleep(5);
        }
        else if (Mode == 'i')
        {
            ULONG_PTR Key;
            LPOVERLAPPED Overlapped = NULL;
            BOOL Ok = GetQueuedCompletionStatus(Port, &Bytes, &Key, &Overlapped, 50);

            if (Overlapped)
            {
                ORDER_SEND *Send = (ORDER_SEND *)Overlapped;

                if (!Send->Done)
                {
                    Send->Bytes = Bytes;
                    Send->Error = Ok ? 0 : GetLastError();
                    Send->Done = 1;
                    Left--;
                }
            }
        }
        else
        {
            SleepEx(20, TRUE);
            Left = SEND_COUNT - RoutineCount;
        }
    }
    ok(Left == 0, "%c run %d: %d of %d sends did not complete in 20 s\n", Mode, Run, Left, SEND_COUNT);
    if (Left)
        Failed = 1;

    for (i = 0; i < SEND_COUNT; i++)
    {
        if (Sends[i].Done == 1)
        {
            ok(Sends[i].Error == 0 && Sends[i].Bytes == SEND_LEN, "%c run %d: send %d completed with error %lu, %lu bytes\n",
               Mode, Run, i, Sends[i].Error, Sends[i].Bytes);
            if (Sends[i].Error == 0)
                Reported += Sends[i].Bytes;
        }
    }

    /* The end of the stream: the peer gets what the sends reported, in order. A send that waits is released by the close */
    if (Failed)
    {
        closesocket(Client);
        Client = INVALID_SOCKET;
        for (Start = GetTickCount(); GetTickCount() - Start < 10000; )
        {
            for (Left = 0, i = 0; i < SEND_COUNT; i++)
            {
                if (Sends[i].Done)
                    continue;
                if (Mode == 'e' && WaitForSingleObject(Sends[i].Overlapped.hEvent, 0) == WAIT_OBJECT_0)
                    Sends[i].Done = 3;
                else if (Mode == 'i' && Sends[i].Overlapped.Internal != STATUS_PENDING)
                    Sends[i].Done = 3;
                else if (Mode != 'r')
                    Left++;
            }
            if (Mode == 'r')
            {
                SleepEx(20, TRUE);
                Left = SEND_COUNT - RoutineCount;
            }
            if (!Left)
                break;
            Sleep(5);
        }
    }
    else
    {
        shutdown(Client, SD_SEND);
    }
    ok(WaitForSingleObject(Thread, 20000) == WAIT_OBJECT_0, "%c run %d: the reader did not end\n", Mode, Run);
    if (!Failed)
    {
        ok(Reader.Received == Reported, "%c run %d: the peer got %I64d bytes, the sends reported %I64d\n",
           Mode, Run, Reader.Received, Reported);
        ok(Reader.FirstBad < 0, "%c run %d: the stream is out of order from byte %I64d (send %I64d)\n",
           Mode, Run, Reader.FirstBad, Reader.FirstBad / SEND_LEN);
    }
    CloseHandle(Thread);

    if (Client != INVALID_SOCKET)
        closesocket(Client);
    closesocket(Server);
    if (Port)
        CloseHandle(Port);
    if (Mode == 'r')
        SleepEx(0, TRUE);
    for (i = 0; i < SEND_COUNT; i++)
    {
        /* A request that never completed may still use its buffer */
        if (Sends[i].Done)
            HeapFree(GetProcessHeap(), 0, Sends[i].Buffer.buf);
        if (Mode == 'e')
            WSACloseEvent(Sends[i].Overlapped.hEvent);
    }
}

START_TEST(sendorder)
{
    WSADATA Data;
    int Run;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    for (Run = 0; Run < RUNS; Run++)
        OrderRun('e', Run);
    for (Run = 0; Run < RUNS; Run++)
        OrderRun('i', Run);
    for (Run = 0; Run < RUNS; Run++)
        OrderRun('r', Run);

    WSACleanup();
}
