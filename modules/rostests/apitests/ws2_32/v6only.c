/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     getsockopt(IPPROTO_IPV6, IPV6_V6ONLY) on an IPv4 datagram socket
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 22H2 answers success for an AF_INET UDP socket, bound or not, and writes the first
 * byte of the buffer as 1 (the rest of a larger buffer is left alone). Rust's quinn-udp, which
 * Firefox's HTTP/3 uses, asks every UDP socket for it and gave up on the WSAEINVAL ReactOS used
 * to return ("failed to initialize socket ... os error 10022").
 */

#include "ws2_32.h"

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

static void CheckV6Only(SOCKET s, const char *What)
{
    BYTE Value[4];
    int Len = sizeof(Value), Result;

    memset(Value, 0xcc, sizeof(Value));
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)Value, &Len);
    ok(Result == 0, "%s: getsockopt(IPV6_V6ONLY) failed: %d\n", What, WSAGetLastError());
    if (Result != 0)
        return;
    ok(Value[0] == 1, "%s: value %02x, expected 1\n", What, Value[0]);
    ok(Value[1] == 0xcc && Value[2] == 0xcc && Value[3] == 0xcc,
       "%s: wrote past the first byte: %02x %02x %02x\n", What, Value[1], Value[2], Value[3]);
}

START_TEST(v6only)
{
    WSADATA wsaData;
    SOCKET Udp;
    struct sockaddr_in Addr;
    int Result;

    ok(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, "WSAStartup failed\n");

    Udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Udp != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    if (Udp != INVALID_SOCKET)
    {
        CheckV6Only(Udp, "unbound");

        memset(&Addr, 0, sizeof(Addr));
        Addr.sin_family = AF_INET;
        Result = bind(Udp, (struct sockaddr *)&Addr, sizeof(Addr));
        ok(Result == 0, "bind failed: %d\n", WSAGetLastError());
        CheckV6Only(Udp, "bound");
        closesocket(Udp);
    }

    WSACleanup();
}
