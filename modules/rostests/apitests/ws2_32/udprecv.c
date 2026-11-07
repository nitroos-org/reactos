/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that UDP receive keeps working after a full receive buffer or an oversized datagram
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"

#define SMALL_DATAGRAM 1000
#define SMALL_COUNT 32
#define LARGE_DATAGRAM 12000

static
BOOL
OpenPair(SOCKET *Receiver, SOCKET *Sender, struct sockaddr_in *To)
{
    int Length = sizeof(*To);

    *Receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    *Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(*Receiver != INVALID_SOCKET && *Sender != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (*Receiver == INVALID_SOCKET || *Sender == INVALID_SOCKET)
        goto Fail;

    ZeroMemory(To, sizeof(*To));
    To->sin_family = AF_INET;
    To->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    To->sin_port = 0;
    if (bind(*Receiver, (struct sockaddr *)To, sizeof(*To)) == SOCKET_ERROR ||
        getsockname(*Receiver, (struct sockaddr *)To, &Length) == SOCKET_ERROR)
    {
        ok(0, "bind/getsockname failed: %d\n", WSAGetLastError());
        goto Fail;
    }
    return TRUE;

Fail:
    if (*Receiver != INVALID_SOCKET)
        closesocket(*Receiver);
    if (*Sender != INVALID_SOCKET)
        closesocket(*Sender);
    *Receiver = *Sender = INVALID_SOCKET;
    return FALSE;
}

/* Receive one datagram, waiting at most TimeoutMs; returns its length or -1 */
static
int
RecvWithTimeout(SOCKET Socket, char *Buffer, int Size, DWORD TimeoutMs)
{
    fd_set ReadSet;
    struct timeval Timeout;

    FD_ZERO(&ReadSet);
    FD_SET(Socket, &ReadSet);
    Timeout.tv_sec = TimeoutMs / 1000;
    Timeout.tv_usec = (TimeoutMs % 1000) * 1000;
    if (select(0, &ReadSet, NULL, NULL, &Timeout) != 1)
        return -1;
    return recv(Socket, Buffer, Size, 0);
}

/* Loopback delivery is asynchronous: wait until the bytes queued on the
 * socket stop growing and return them (-1 on error) */
static
long
WaitForQueuedBytes(SOCKET Socket)
{
    u_long Queued = 0, Last = (u_long)-1;
    int Stable = 0, i;

    for (i = 0; i < 50 && Stable < 3; i++)
    {
        Sleep(100);
        if (ioctlsocket(Socket, FIONREAD, &Queued) == SOCKET_ERROR)
            return -1;
        if (Queued == Last)
            Stable++;
        else
            Stable = 0;
        Last = Queued;
    }
    return (long)Queued;
}

/* Wait for the datagram that starts with Marker; datagrams before it are skipped */
static
BOOL
WaitForMarker(SOCKET Socket, char *Buffer, int Size, const char *Marker, DWORD TimeoutMs)
{
    DWORD Start = GetTickCount();
    int Received;

    while (GetTickCount() - Start < TimeoutMs)
    {
        Received = RecvWithTimeout(Socket, Buffer, Size, 200);
        if (Received >= (int)strlen(Marker) && !memcmp(Buffer, Marker, strlen(Marker)))
            return TRUE;
    }
    return FALSE;
}

static
void
Test_FullReceiveBuffer(void)
{
    SOCKET Receiver, Sender;
    struct sockaddr_in To;
    static char Buffer[0x10000];
    int i, Sent = 0, Drained = 0;
    long Queued;

    if (!OpenPair(&Receiver, &Sender, &To))
        return;

    /* Fill the receiver's buffer: more than 8 KB that nobody reads yet */
    memset(Buffer, 'x', SMALL_DATAGRAM);
    for (i = 0; i < SMALL_COUNT; i++)
    {
        if (sendto(Sender, Buffer, SMALL_DATAGRAM, 0, (struct sockaddr *)&To, sizeof(To)) == SMALL_DATAGRAM)
            Sent++;
    }
    ok(Sent == SMALL_COUNT, "Sent %d of %d datagrams\n", Sent, SMALL_COUNT);

    /* Before anything is read, the kept datagrams must fill the buffer
     * (ReactOS keeps 8 KB of them) */
    Queued = WaitForQueuedBytes(Receiver);
    trace("%ld bytes queued before draining\n", Queued);
    ok(Queued > 0, "FIONREAD returned %ld\n", Queued);
    if (is_reactos())
        ok(Queued >= 0x2000, "Only %ld bytes were queued\n", Queued);

    /* Drain what was kept */
    while (RecvWithTimeout(Receiver, Buffer, sizeof(Buffer), 500) == SMALL_DATAGRAM)
        Drained++;
    ok(Drained > 0, "No datagram was kept\n");
    trace("%d of %d datagrams were kept\n", Drained, Sent);

    /* The buffer is empty again, so a new datagram must arrive */
    if (sendto(Sender, "AFTER-FULL", 10, 0, (struct sockaddr *)&To, sizeof(To)) != 10)
        ok(0, "sendto failed: %d\n", WSAGetLastError());
    else
        ok(WaitForMarker(Receiver, Buffer, sizeof(Buffer), "AFTER-FULL", 3000),
           "No datagram received after the receive buffer was drained\n");

    closesocket(Sender);
    closesocket(Receiver);
}

static
void
Test_LargeDatagram(void)
{
    SOCKET Receiver, Sender;
    struct sockaddr_in To;
    static char Buffer[0x10000];
    int Result;

    if (!OpenPair(&Receiver, &Sender, &To))
        return;

    /* A datagram larger than the default receive buffer */
    memset(Buffer, 'y', LARGE_DATAGRAM);
    Result = sendto(Sender, Buffer, LARGE_DATAGRAM, 0, (struct sockaddr *)&To, sizeof(To));
    if (Result != LARGE_DATAGRAM)
    {
        skip("sendto of %d bytes returned %d, error %d\n", LARGE_DATAGRAM, Result, WSAGetLastError());
        goto Cleanup;
    }

    /* Take the large datagram if it is delivered: while it is queued, a full
     * receive buffer may drop the next one (Windows Server 2008 R2 does) */
    Result = RecvWithTimeout(Receiver, Buffer, sizeof(Buffer), 1000);
    trace("Large datagram: recv returned %d\n", Result);
    /* Windows delivers it (the default buffer of a UDP socket is 64 KB) */
    ok(Result == LARGE_DATAGRAM, "recv returned %d\n", Result);

    /* Whether the large datagram was delivered or dropped, the next one must arrive */
    if (sendto(Sender, "AFTER-LARGE", 11, 0, (struct sockaddr *)&To, sizeof(To)) != 11)
        ok(0, "sendto failed: %d\n", WSAGetLastError());
    else
        ok(WaitForMarker(Receiver, Buffer, sizeof(Buffer), "AFTER-LARGE", 3000),
           "No datagram received after a datagram of %d bytes\n", LARGE_DATAGRAM);

Cleanup:
    closesocket(Sender);
    closesocket(Receiver);
}

static
DWORD
WINAPI
DrainThread(LPVOID Parameter)
{
    SOCKET Socket = (SOCKET)(ULONG_PTR)Parameter;
    static char Buffer[0x10000];
    struct sockaddr_in From;
    int FromLength, Drained = 0;
    fd_set ReadSet;
    struct timeval Timeout = { 0, 500000 };

    for (;;)
    {
        FD_ZERO(&ReadSet);
        FD_SET(Socket, &ReadSet);
        if (select(0, &ReadSet, NULL, NULL, &Timeout) != 1)
            break;
        FromLength = sizeof(From);
        if (recvfrom(Socket, Buffer, sizeof(Buffer), 0, (struct sockaddr *)&From, &FromLength) != SMALL_DATAGRAM)
            break;
        Drained++;
    }
    return Drained;
}

static
void
Test_DrainOnExitingThread(void)
{
    SOCKET Receiver, Sender;
    struct sockaddr_in To;
    static char Buffer[0x10000];
    HANDLE Thread;
    DWORD Drained = 0, Wait;
    int i, Sent = 0;
    long Queued;

    if (!OpenPair(&Receiver, &Sender, &To))
        return;

    memset(Buffer, 'z', SMALL_DATAGRAM);
    for (i = 0; i < SMALL_COUNT; i++)
    {
        if (sendto(Sender, Buffer, SMALL_DATAGRAM, 0, (struct sockaddr *)&To, sizeof(To)) == SMALL_DATAGRAM)
            Sent++;
    }
    ok(Sent == SMALL_COUNT, "Sent %d of %d datagrams\n", Sent, SMALL_COUNT);

    /* The buffer must be full, so the drain thread is the one that restarts
     * the receive */
    Queued = WaitForQueuedBytes(Receiver);
    ok(Queued > 0, "FIONREAD returned %ld\n", Queued);
    if (is_reactos())
        ok(Queued >= 0x2000, "Only %ld bytes were queued\n", Queued);

    /* Drain the full buffer with recvfrom on a thread that then exits */
    Thread = CreateThread(NULL, 0, DrainThread, (LPVOID)(ULONG_PTR)Receiver, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (!Thread)
        goto Cleanup;
    Wait = WaitForSingleObject(Thread, 10000);
    ok(Wait == WAIT_OBJECT_0, "The drain thread did not finish: %lu\n", Wait);
    if (Wait != WAIT_OBJECT_0 || !GetExitCodeThread(Thread, &Drained))
        Drained = 0;
    CloseHandle(Thread);
    ok(Drained > 0, "No datagram was kept\n");
    Sleep(200);

    /* The socket must still receive after the reading thread is gone */
    if (sendto(Sender, "AFTER-EXIT", 10, 0, (struct sockaddr *)&To, sizeof(To)) != 10)
        ok(0, "sendto failed: %d\n", WSAGetLastError());
    else
        ok(WaitForMarker(Receiver, Buffer, sizeof(Buffer), "AFTER-EXIT", 3000),
           "No datagram received after the thread that drained the buffer exited\n");

Cleanup:
    closesocket(Sender);
    closesocket(Receiver);
}

START_TEST(udprecv)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }

    Test_FullReceiveBuffer();
    Test_LargeDatagram();
    Test_DrainOnExitingThread();

    WSACleanup();
}
