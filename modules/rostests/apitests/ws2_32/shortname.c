/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A socket address shorter than the generic sockaddr is refused with WSAEFAULT by bind,
 *              connect, WSAConnect, sendto and WSASendTo, for stream and datagram sockets (measured on
 *              Windows 10 22H2, name lengths 8, 12 and 15); the socket stays usable
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"

START_TEST(shortname)
{
    static const int Lengths[] = { 8, 12, 15 };
    WSADATA WsaData;
    SOCKET Listener, Stream, Datagram, Accepted;
    struct sockaddr_in Peer, Local;
    int PeerLength = sizeof(Peer), i, Result;
    char Message[8];

    ok_int(WSAStartup(MAKEWORD(2, 2), &WsaData), 0);

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&Peer, sizeof(Peer));
    Peer.sin_family = AF_INET;
    Peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(Listener != INVALID_SOCKET && !bind(Listener, (struct sockaddr *)&Peer, sizeof(Peer)) &&
       !listen(Listener, 4) && !getsockname(Listener, (struct sockaddr *)&Peer, &PeerLength), "listener failed\n");
    Local = Peer;
    Local.sin_port = 0;

    for (i = 0; i < 3; i++)
    {
        int Length = Lengths[i];

        Stream = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        SetLastError(0xdeadbeef);
        Result = bind(Stream, (struct sockaddr *)&Local, Length);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "bind %d bytes: %d, %d\n", Length, Result, WSAGetLastError());
        ok_int(bind(Stream, (struct sockaddr *)&Local, sizeof(Local)), 0);
        SetLastError(0xdeadbeef);
        Result = connect(Stream, (struct sockaddr *)&Peer, Length);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "connect %d bytes: %d, %d\n", Length, Result, WSAGetLastError());
        SetLastError(0xdeadbeef);
        Result = WSAConnect(Stream, (struct sockaddr *)&Peer, Length, NULL, NULL, NULL, NULL);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "WSAConnect %d bytes: %d, %d\n", Length, Result, WSAGetLastError());
        ok_int(connect(Stream, (struct sockaddr *)&Peer, sizeof(Peer)), 0);
        Accepted = accept(Listener, NULL, NULL);
        ok(Accepted != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());
        if (Accepted != INVALID_SOCKET)
            closesocket(Accepted);
        closesocket(Stream);

        Datagram = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ok_int(bind(Datagram, (struct sockaddr *)&Local, sizeof(Local)), 0);
        SetLastError(0xdeadbeef);
        Result = connect(Datagram, (struct sockaddr *)&Peer, Length);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "UDP connect %d bytes: %d, %d\n", Length, Result, WSAGetLastError());
        SetLastError(0xdeadbeef);
        Result = sendto(Datagram, "x", 1, 0, (struct sockaddr *)&Peer, Length);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "sendto %d bytes: %d, %d\n", Length, Result, WSAGetLastError());
        {
            WSABUF Buf = { 1, Message };
            DWORD Sent = 0;

            SetLastError(0xdeadbeef);
            Result = WSASendTo(Datagram, &Buf, 1, &Sent, 0, (struct sockaddr *)&Peer, Length, NULL, NULL);
            ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "WSASendTo %d bytes: %d, %d\n", Length, Result, WSAGetLastError());
        }
        ok_int(connect(Datagram, (struct sockaddr *)&Peer, sizeof(Peer)), 0);
        closesocket(Datagram);
    }

    closesocket(Listener);
    WSACleanup();
}
