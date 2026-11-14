/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     A send on a stream socket that is not connected yet fails, and the connect that
 *              follows still completes (a checked AFD asserted that the send window did not
 *              exist when the connection was made, and the failed send had allocated it)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "precomp.h"

START_TEST(sendbeforeconnect)
{
    WSADATA wsa;
    SOCKET lst, cli, srv;
    struct sockaddr_in a;
    int len = sizeof(a), r, i, opt;
    char c = 'x', rc = 0;
    u_long nb;
    fd_set wfds;
    struct timeval tv;

    ok(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "WSAStartup failed\n");

    lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(lst != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(lst, (struct sockaddr *)&a, sizeof(a)) == 0, "bind failed %d\n", WSAGetLastError());
    getsockname(lst, (struct sockaddr *)&a, &len);
    ok(listen(lst, SOMAXCONN) == 0, "listen failed %d\n", WSAGetLastError());

    for (i = 0; i < 2; i++)
    {
        /* i == 0: blocking connect; i == 1: non-blocking connect */
        cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(cli != INVALID_SOCKET, "socket failed %d\n", WSAGetLastError());

        /* Not connected: the send fails, whatever it allocated on the way */
        r = send(cli, &c, 1, 0);
        ok(r == SOCKET_ERROR, "[%d] send on an unconnected socket returned %d\n", i, r);
        r = send(cli, &c, 1, 0);
        ok(r == SOCKET_ERROR, "[%d] second send on an unconnected socket returned %d\n", i, r);

        if (i == 1)
        {
            nb = 1;
            ok(ioctlsocket(cli, FIONBIO, &nb) == 0, "FIONBIO failed %d\n", WSAGetLastError());
        }
        r = connect(cli, (struct sockaddr *)&a, sizeof(a));
        if (i == 1 && r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
        {
            FD_ZERO(&wfds);
            FD_SET(cli, &wfds);
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            ok(select(0, NULL, &wfds, NULL, &tv) == 1, "connect did not complete\n");
            r = 0;
        }
        ok(r == 0, "[%d] connect failed %d\n", i, WSAGetLastError());

        srv = accept(lst, NULL, NULL);
        ok(srv != INVALID_SOCKET, "accept failed %d\n", WSAGetLastError());

        len = sizeof(opt);
        opt = 0;
        ok(getsockopt(cli, SOL_SOCKET, SO_SNDBUF, (char *)&opt, &len) == 0, "SO_SNDBUF failed\n");

        /* The connection carries data both ways */
        nb = 0;
        ioctlsocket(cli, FIONBIO, &nb);
        r = send(cli, &c, 1, 0);
        ok(r == 1, "[%d] send on the connection returned %d (%d)\n", i, r, WSAGetLastError());
        rc = 0;
        r = recv(srv, &rc, 1, 0);
        ok(r == 1 && rc == 'x', "[%d] recv returned %d, %d\n", i, r, rc);
        r = send(srv, &c, 1, 0);
        ok(r == 1, "[%d] send from the peer returned %d\n", i, r);
        rc = 0;
        r = recv(cli, &rc, 1, 0);
        ok(r == 1 && rc == 'x', "[%d] recv on the client returned %d, %d\n", i, r, rc);

        closesocket(srv);
        closesocket(cli);
    }
    closesocket(lst);
    WSACleanup();
}
