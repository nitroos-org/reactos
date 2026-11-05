/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The receive window of a TCP connection closes when the application does not read, and
 *              reading reopens it; SO_RCVBUF sets its size
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Recorded on Windows 10 22H2 (loopback, a non-blocking sender of 4K sends, a receiver that never reads):
 *   default SO_RCVBUF reads 65536 (accepted socket too); the sender is stopped by WSAEWOULDBLOCK after 2.7-2.9 MB
 *   SO_RCVBUF 8192:    86016 bytes      SO_RCVBUF 65536: 196608-258048      SO_RCVBUF 1048576: 2.16-2.36 MB
 *   FIONREAD of the idle receiver is SO_RCVBUF; getsockopt(SO_RCVBUF) never changes by itself.
 * The bounds below are wide: they check that the sender is stopped, by about the size asked for, and that
 * everything that was accepted arrives, in order, once the receiver reads.
 */

#include "ws2_32.h"

#define CHUNK 4096
#define CAP (32ULL * 1024 * 1024)

static
UCHAR
PatternByte(ULONGLONG Offset)
{
    return (UCHAR)((Offset * 131 + Offset / 251) & 0xFF);
}

/* Sends non-blocking chunks until WSAEWOULDBLOCK holds for 1.5 s (or CAP); returns the bytes accepted */
static
ULONGLONG
PushUntilBlocked(
    _In_ SOCKET Sender,
    _Inout_ ULONGLONG *Offset,
    _Out_ BOOLEAN *Capped)
{
    UCHAR Buffer[CHUNK];
    ULONGLONG Total = 0;
    ULONG Last = GetTickCount();
    ULONG Mode = 1;
    ULONG i;

    *Capped = FALSE;
    ioctlsocket(Sender, FIONBIO, &Mode);
    for (;;)
    {
        INT Result;

        for (i = 0; i < CHUNK; i++)
            Buffer[i] = PatternByte(*Offset + i);
        Result = send(Sender, (PCHAR)Buffer, CHUNK, 0);
        if (Result > 0)
        {
            *Offset += Result;
            Total += Result;
            Last = GetTickCount();
            if (Total >= CAP)
            {
                *Capped = TRUE;
                break;
            }
            continue;
        }
        if (WSAGetLastError() != WSAEWOULDBLOCK)
        {
            ok(0, "send failed, error %d\n", WSAGetLastError());
            break;
        }
        if (GetTickCount() - Last > 1500)
            break;
        Sleep(10);
    }
    Mode = 0;
    ioctlsocket(Sender, FIONBIO, &Mode);
    return Total;
}

/* Reads exactly Wanted bytes (5 s without data fails) and checks the pattern from *Offset */
static
ULONGLONG
ReadAndVerify(
    _In_ SOCKET Receiver,
    _In_ ULONGLONG Wanted,
    _Inout_ ULONGLONG *Offset,
    _Out_ ULONG *Bad)
{
    static UCHAR Buffer[65536];
    ULONGLONG Got = 0;
    ULONG Timeout = 5000;

    *Bad = 0;
    setsockopt(Receiver, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&Timeout, sizeof(Timeout));
    while (Got < Wanted)
    {
        INT Length = recv(Receiver, (PCHAR)Buffer, (INT)min(Wanted - Got, sizeof(Buffer)), 0);
        INT i;

        if (Length <= 0)
            break;
        for (i = 0; i < Length; i++)
        {
            if (Buffer[i] != PatternByte(*Offset + i))
            {
                (*Bad)++;
                break;
            }
        }
        *Offset += Length;
        Got += Length;
    }
    return Got;
}

static
INT
GetRcvBuf(SOCKET Socket)
{
    INT Value = -1;
    INT Length = sizeof(Value);

    getsockopt(Socket, SOL_SOCKET, SO_RCVBUF, (PCHAR)&Value, &Length);
    return Value;
}

/* SetOnListener: SO_RCVBUF (0 = not set) is set on the listener before it listens */
static
VOID
TestSize(
    _In_ INT SetOnListener,
    _In_ ULONGLONG MinBytes,
    _In_ ULONGLONG MaxBytes)
{
    SOCKET Listener, Sender, Receiver;
    SOCKADDR_IN Address;
    INT Length = sizeof(Address);
    ULONGLONG SendOffset = 0, ReadOffset = 0, Pushed, Got;
    BOOLEAN Capped;
    ULONG Bad, Mode = 0;
    INT ExpectedBuf = SetOnListener ? SetOnListener : 65536;

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Sender = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener != INVALID_SOCKET && Sender != INVALID_SOCKET, "socket failed, error %d\n", WSAGetLastError());
    if (Listener == INVALID_SOCKET || Sender == INVALID_SOCKET)
        return;

    ok(GetRcvBuf(Sender) == 65536 || SetOnListener, "default SO_RCVBUF is %d, expected 65536\n", GetRcvBuf(Sender));

    if (SetOnListener)
        ok(setsockopt(Listener, SOL_SOCKET, SO_RCVBUF, (PCHAR)&SetOnListener, sizeof(SetOnListener)) == 0,
           "setsockopt failed, error %d\n", WSAGetLastError());

    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Listener, (SOCKADDR *)&Address, sizeof(Address)) == 0, "bind failed, error %d\n", WSAGetLastError());
    ok(listen(Listener, 1) == 0, "listen failed, error %d\n", WSAGetLastError());
    ok(getsockname(Listener, (SOCKADDR *)&Address, &Length) == 0, "getsockname failed\n");
    ok(connect(Sender, (SOCKADDR *)&Address, sizeof(Address)) == 0, "connect failed, error %d\n", WSAGetLastError());
    Receiver = accept(Listener, NULL, NULL);
    ok(Receiver != INVALID_SOCKET, "accept failed, error %d\n", WSAGetLastError());
    if (Receiver == INVALID_SOCKET)
        goto Done;

    ok(GetRcvBuf(Receiver) == ExpectedBuf, "accepted SO_RCVBUF is %d, expected %d\n", GetRcvBuf(Receiver), ExpectedBuf);

    /* The receiver never reads: the sender must be stopped */
    Pushed = PushUntilBlocked(Sender, &SendOffset, &Capped);
    ok(!Capped, "SO_RCVBUF %d: %I64u bytes accepted and the sender was never stopped\n", SetOnListener, Pushed);
    ok(Pushed >= MinBytes && Pushed <= MaxBytes, "SO_RCVBUF %d: the sender was stopped after %I64u bytes, expected %I64u..%I64u\n",
       SetOnListener, Pushed, MinBytes, MaxBytes);

    /* Reading gives everything back, in order, with nothing lost */
    Got = ReadAndVerify(Receiver, Pushed, &ReadOffset, &Bad);
    ok(Got == Pushed, "SO_RCVBUF %d: read %I64u of %I64u bytes\n", SetOnListener, Got, Pushed);
    ok(Bad == 0, "SO_RCVBUF %d: data corrupted\n", SetOnListener);

    /* The window is open again: the sender is stopped at about the same amount again */
    Pushed = PushUntilBlocked(Sender, &SendOffset, &Capped);
    ok(!Capped, "SO_RCVBUF %d: second round never stopped (%I64u bytes)\n", SetOnListener, Pushed);
    ok(Pushed >= MinBytes && Pushed <= MaxBytes, "SO_RCVBUF %d: second round stopped after %I64u bytes, expected %I64u..%I64u\n",
       SetOnListener, Pushed, MinBytes, MaxBytes);
    Got = ReadAndVerify(Receiver, Pushed, &ReadOffset, &Bad);
    ok(Got == Pushed && Bad == 0, "SO_RCVBUF %d: second round read %I64u of %I64u bytes, %lu bad\n",
       SetOnListener, Got, Pushed, Bad);

    /* The end of the stream follows the data */
    shutdown(Sender, SD_SEND);
    ok(recv(Receiver, (PCHAR)&Mode, 1, 0) == 0, "no end of stream after the sender shut down\n");

    closesocket(Receiver);
Done:
    closesocket(Sender);
    closesocket(Listener);
}

/* Every connection of a run that queues megabytes and reads them late: the refill of AFD's buffer must not nest
 * once per 8K of the queue (a kernel stack overflow, bugcheck 0x7F, on an i386 Debug build) */
static
VOID
TestQueueDrain(
    _In_ ULONG Rounds,
    _In_ INT ReadSize)
{
    static UCHAR Buffer[65536];
    ULONG Round;

    for (Round = 0; Round < Rounds; Round++)
    {
        SOCKET Listener, Sender, Receiver;
        SOCKADDR_IN Address;
        INT Length = sizeof(Address);
        ULONGLONG SendOffset = 0, ReadOffset = 0, Pushed, Got = 0;
        BOOLEAN Capped;
        ULONG Bad = 0, Timeout = 5000;

        Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Sender = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ZeroMemory(&Address, sizeof(Address));
        Address.sin_family = AF_INET;
        Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(Listener, (SOCKADDR *)&Address, sizeof(Address)) || listen(Listener, 1) ||
            getsockname(Listener, (SOCKADDR *)&Address, &Length) ||
            connect(Sender, (SOCKADDR *)&Address, sizeof(Address)))
        {
            ok(0, "queue-drain: setup failed, error %d\n", WSAGetLastError());
            closesocket(Listener);
            closesocket(Sender);
            return;
        }
        Receiver = accept(Listener, NULL, NULL);
        setsockopt(Receiver, SOL_SOCKET, SO_RCVTIMEO, (PCHAR)&Timeout, sizeof(Timeout));

        /* about 2 MB queue up behind the idle receiver, then they are read in small or large pieces */
        Pushed = PushUntilBlocked(Sender, &SendOffset, &Capped);
        while (Got < Pushed)
        {
            INT Count = recv(Receiver, (PCHAR)Buffer, (INT)min((ULONGLONG)ReadSize, Pushed - Got), 0), i;

            if (Count <= 0)
                break;
            for (i = 0; i < Count; i++)
                if (Buffer[i] != PatternByte(ReadOffset + i))
                    Bad++;
            ReadOffset += Count;
            Got += Count;
        }
        ok(Got == Pushed && Bad == 0, "queue-drain %lu (read size %d): read %I64u of %I64u bytes, %lu bad\n",
           Round, ReadSize, Got, Pushed, Bad);
        closesocket(Receiver);
        closesocket(Sender);
        closesocket(Listener);
    }
}

typedef struct { SOCKET Socket; volatile LONG Done; INT Result; } SHUTDOWN_JOB;

static
DWORD
WINAPI
ShutdownThread(LPVOID Context)
{
    SHUTDOWN_JOB *Job = Context;

    Job->Result = shutdown(Job->Socket, SD_SEND);
    InterlockedExchange(&Job->Done, 1);
    return 0;
}

/* Windows 10 22H2: shutdown(SD_SEND) returns at once while the sent data waits behind a receiver that does not
 * read; the end of the stream follows the data */
static
VOID
TestShutdownQueued(
    _In_ INT SetOnListener)
{
    SOCKET Listener, Sender, Receiver;
    SOCKADDR_IN Address;
    INT Length = sizeof(Address);
    ULONGLONG SendOffset = 0, ReadOffset = 0, Pushed, Got;
    BOOLEAN Capped;
    ULONG Bad, Waited = 0;
    SHUTDOWN_JOB Job;
    HANDLE Thread;
    CHAR Byte;

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Sender = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (SetOnListener)
        setsockopt(Listener, SOL_SOCKET, SO_RCVBUF, (PCHAR)&SetOnListener, sizeof(SetOnListener));
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (SOCKADDR *)&Address, sizeof(Address)) || listen(Listener, 1) ||
        getsockname(Listener, (SOCKADDR *)&Address, &Length) ||
        connect(Sender, (SOCKADDR *)&Address, sizeof(Address)))
    {
        ok(0, "shutdown: setup failed, error %d\n", WSAGetLastError());
        closesocket(Listener);
        closesocket(Sender);
        return;
    }
    Receiver = accept(Listener, NULL, NULL);

    Pushed = PushUntilBlocked(Sender, &SendOffset, &Capped);
    ok(!Capped && Pushed != 0, "SO_RCVBUF %d: the sender was not stopped (%I64u bytes)\n", SetOnListener, Pushed);

    Job.Socket = Sender;
    Job.Done = 0;
    Job.Result = -2;
    Thread = CreateThread(NULL, 0, ShutdownThread, &Job, 0, NULL);
    while (!Job.Done && Waited < 5000)
    {
        Sleep(50);
        Waited += 50;
    }
    ok(Job.Done, "SO_RCVBUF %d: shutdown(SD_SEND) with %I64u bytes queued did not return in 5 s\n", SetOnListener, Pushed);
    ok(Job.Result == 0 || !Job.Done, "SO_RCVBUF %d: shutdown returned %d\n", SetOnListener, Job.Result);

    Got = ReadAndVerify(Receiver, Pushed, &ReadOffset, &Bad);
    ok(Got == Pushed && Bad == 0, "SO_RCVBUF %d: read %I64u of %I64u bytes, %lu bad\n", SetOnListener, Got, Pushed, Bad);
    ok(recv(Receiver, &Byte, 1, 0) == 0, "SO_RCVBUF %d: no end of stream after the data\n", SetOnListener);
    if (Thread)
    {
        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
    }
    closesocket(Receiver);
    closesocket(Sender);
    closesocket(Listener);
}

/* One thread sends 8K pieces on a non-blocking socket and reads what has arrived before it sends the next
 * (the loop of a .NET program with non-blocking sockets). The short last segment of a piece waits for the
 * acknowledgement of the one before it (Nagle), and the loop waits for the piece: without an acknowledgement
 * at once, a tick per piece (2 MB/s here, 50 MB/s with it; Windows gives GB/s) */
static
VOID
TestNonBlockingLoop(VOID)
{
    static UCHAR Buffer[65536];
    SOCKET Listener, Sender, Receiver;
    SOCKADDR_IN Address;
    INT Length = sizeof(Address);
    ULONGLONG Total = 16ULL * 1024 * 1024, Sent = 0, Got = 0;
    ULONG Mode = 1, Start;

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Sender = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (SOCKADDR *)&Address, sizeof(Address)) || listen(Listener, 1) ||
        getsockname(Listener, (SOCKADDR *)&Address, &Length) ||
        connect(Sender, (SOCKADDR *)&Address, sizeof(Address)))
    {
        ok(0, "loop: setup failed, error %d\n", WSAGetLastError());
        return;
    }
    Receiver = accept(Listener, NULL, NULL);
    ioctlsocket(Sender, FIONBIO, &Mode);

    Start = GetTickCount();
    while (Got < Total && GetTickCount() - Start < 60000)
    {
        ULONG Available = 0;
        INT Count;

        if (Sent < Total)
        {
            Count = send(Sender, (PCHAR)Buffer, 8192, 0);
            if (Count > 0)
                Sent += Count;
        }
        Sleep(0);
        while (ioctlsocket(Receiver, FIONREAD, &Available) == 0 && Available != 0)
        {
            Count = recv(Receiver, (PCHAR)Buffer, sizeof(Buffer), 0);
            if (Count <= 0)
                break;
            Got += Count;
        }
        if (Sent < Total && Available == 0 && Got < Sent)
        {
            fd_set Set;
            TIMEVAL Wait = { 0, 1000 };

            FD_ZERO(&Set);
            FD_SET(Receiver, &Set);
            select(0, &Set, NULL, NULL, &Wait);
        }
    }
    Start = GetTickCount() - Start;
    ok(Got == Total, "loop: read %I64u of %I64u bytes\n", Got, Total);
    ok(Start < 15000, "loop: %I64u MB took %lu ms\n", Total >> 20, Start);
    closesocket(Receiver);
    closesocket(Sender);
    closesocket(Listener);
}

START_TEST(rcvwindow)
{
    WSADATA wsaData;
    INT Result;

    Result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    ok(Result == 0, "WSAStartup failed, error %d\n", Result);
    if (Result != 0)
        return;

    /* Not set: the receiver takes at least its 64K and at most what the 32 MB cap leaves out */
    TestSize(0, 65536, CAP - 1);
    TestSize(8192, 8192, 8192 * 8 + 256 * 1024);
    TestSize(65536, 65536, 65536 * 8 + 256 * 1024);
    TestSize(1048576, 1048576, 1048576 * 8 + 256 * 1024);
    TestNonBlockingLoop();
    TestQueueDrain(24, 65536);
    TestQueueDrain(4, 1460);
    TestShutdownQueued(0);
    TestShutdownQueued(8192);
    TestShutdownQueued(1048576);

    WSACleanup();
}
