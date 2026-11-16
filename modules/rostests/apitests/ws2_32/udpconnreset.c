/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for SIO_UDP_CONNRESET and SIO_UDP_NETRESET on a datagram socket
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <mswsock.h>

START_TEST(udpconnreset)
{
    WSADATA WsaData;
    SOCKET Socket;
    BOOL Flag;
    DWORD Returned;
    INT Result, Error;
    WSAOVERLAPPED Overlapped;

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");

    Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Socket != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());

    Flag = FALSE;
    Returned = 0xdeadbeef;
    Result = WSAIoctl(Socket, SIO_UDP_CONNRESET, &Flag, sizeof(Flag), NULL, 0, &Returned, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == 0, "SIO_UDP_CONNRESET returned %d, error %d\n", Result, Error);
    ok(Returned == 0, "SIO_UDP_CONNRESET returned %lu bytes\n", Returned);

    Flag = FALSE;
    Returned = 0xdeadbeef;
    Result = WSAIoctl(Socket, SIO_UDP_NETRESET, &Flag, sizeof(Flag), NULL, 0, &Returned, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == 0, "SIO_UDP_NETRESET returned %d, error %d\n", Result, Error);
    ok(Returned == 0, "SIO_UDP_NETRESET returned %lu bytes\n", Returned);

    Flag = TRUE;
    Returned = 0xdeadbeef;
    Result = WSAIoctl(Socket, SIO_UDP_CONNRESET, &Flag, sizeof(Flag), NULL, 0, &Returned, NULL, NULL);
    ok(Result == 0, "SIO_UDP_CONNRESET(TRUE) returned %d, error %d\n", Result, WSAGetLastError());
    ok(Returned == 0, "SIO_UDP_CONNRESET(TRUE) returned %lu bytes\n", Returned);

    /* A missing input buffer is rejected, also for an overlapped request; a short one is taken (Windows Server 2022
       and 10 take 1 and 2 bytes for SIO_UDP_CONNRESET, evidence v6raw-20261116) */
    Result = WSAIoctl(Socket, SIO_UDP_CONNRESET, NULL, 0, NULL, 0, &Returned, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "NULL input returned %d, error %d\n", Result, Error);
    Result = WSAIoctl(Socket, SIO_UDP_CONNRESET, &Flag, 1, NULL, 0, &Returned, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == 0, "short input returned %d, error %d\n", Result, Error);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = WSACreateEvent();
    ok(Overlapped.hEvent != WSA_INVALID_EVENT, "WSACreateEvent failed %d\n", WSAGetLastError());
    Result = WSAIoctl(Socket, SIO_UDP_CONNRESET, NULL, 0, NULL, 0, &Returned, &Overlapped, NULL);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR && Error == WSAEFAULT, "overlapped NULL input returned %d, error %d\n", Result, Error);
    WSACloseEvent(Overlapped.hEvent);

    closesocket(Socket);

    /* On a stream socket these controls are invalid */
    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Socket != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    Flag = FALSE;
    Result = WSAIoctl(Socket, SIO_UDP_CONNRESET, &Flag, sizeof(Flag), NULL, 0, &Returned, NULL, NULL);
    Error = WSAGetLastError();
    ok(Result == SOCKET_ERROR && Error == WSAEINVAL, "stream SIO_UDP_CONNRESET returned %d, error %d\n", Result, Error);
    closesocket(Socket);

    WSACleanup();
}
