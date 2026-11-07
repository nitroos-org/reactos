/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Default receive buffer of a UDP socket: SO_RCVBUF and how much of a burst is kept
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (build 19045, 2026-11-07): the default SO_RCVBUF of a UDP socket is 65536,
 * and datagrams are kept while the bytes already queued are below it (the datagram that crosses the
 * limit is kept too): 200 x 1400 bytes -> 47, 2000 x 100 -> 656, 20 x 8000 -> 9, 2000 x 1 -> 2000.
 */

#include "ws2_32.h"

static
int
Burst(int Size, int Count, int *DefaultRcvBuf)
{
    SOCKET Receiver, Sender;
    struct sockaddr_in Addr;
    int Length = sizeof(Addr), OptLength = sizeof(int), i, Got = 0;
    static char Buffer[0x10000];
    fd_set ReadSet;
    struct timeval Timeout;

    *DefaultRcvBuf = -1;
    Receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Receiver != INVALID_SOCKET && Sender != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Receiver == INVALID_SOCKET || Sender == INVALID_SOCKET)
        return -1;

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Receiver, (struct sockaddr *)&Addr, sizeof(Addr)) == SOCKET_ERROR ||
        getsockname(Receiver, (struct sockaddr *)&Addr, &Length) == SOCKET_ERROR)
    {
        ok(0, "bind/getsockname failed: %d\n", WSAGetLastError());
        closesocket(Receiver);
        closesocket(Sender);
        return -1;
    }

    getsockopt(Receiver, SOL_SOCKET, SO_RCVBUF, (char *)DefaultRcvBuf, &OptLength);

    memset(Buffer, 'b', Size);
    for (i = 0; i < Count; i++)
        sendto(Sender, Buffer, Size, 0, (struct sockaddr *)&Addr, sizeof(Addr));

    for (;;)
    {
        FD_ZERO(&ReadSet);
        FD_SET(Receiver, &ReadSet);
        Timeout.tv_sec = 2;
        Timeout.tv_usec = 0;
        if (select(0, &ReadSet, NULL, NULL, &Timeout) != 1)
            break;
        if (recv(Receiver, Buffer, sizeof(Buffer), 0) < 0)
            break;
        Got++;
    }

    closesocket(Receiver);
    closesocket(Sender);
    return Got;
}

static
void
TestBurst(int Size, int Count, int Expected)
{
    int Got, Default;

    Got = Burst(Size, Count, &Default);
    ok(Default == 65536, "default SO_RCVBUF is %d\n", Default);
    ok(Got == Expected, "%d datagrams of %d bytes: %d kept, expected %d\n", Count, Size, Got, Expected);
}

static
void
TestBigDatagram(void)
{
    SOCKET Receiver, Sender;
    struct sockaddr_in Addr;
    int Length = sizeof(Addr), Result;
    static char Buffer[0x10000];
    fd_set ReadSet;
    struct timeval Timeout = { 2, 0 };

    Receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    Sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Receiver == INVALID_SOCKET || Sender == INVALID_SOCKET)
    {
        ok(0, "socket failed: %d\n", WSAGetLastError());
        return;
    }
    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(Receiver, (struct sockaddr *)&Addr, sizeof(Addr));
    getsockname(Receiver, (struct sockaddr *)&Addr, &Length);

    /* A datagram far above the old 8 KB buffer */
    memset(Buffer, 'g', 60000);
    Result = sendto(Sender, Buffer, 60000, 0, (struct sockaddr *)&Addr, sizeof(Addr));
    ok(Result == 60000, "sendto returned %d, error %d\n", Result, WSAGetLastError());

    FD_ZERO(&ReadSet);
    FD_SET(Receiver, &ReadSet);
    Result = -1;
    if (select(0, &ReadSet, NULL, NULL, &Timeout) == 1)
        Result = recv(Receiver, Buffer, sizeof(Buffer), 0);
    ok(Result == 60000, "a 60000 byte datagram: recv returned %d\n", Result);

    closesocket(Receiver);
    closesocket(Sender);
}

START_TEST(udpburst)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed: %d\n", WSAGetLastError());
        return;
    }

    TestBurst(1400, 200, 47);
    TestBurst(1400, 40, 40);
    TestBurst(100, 2000, 656);
    TestBurst(1, 2000, 2000);
    TestBurst(8000, 20, 9);
    TestBigDatagram();

    WSACleanup();
}
