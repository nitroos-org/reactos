/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     getsockopt and setsockopt(IPPROTO_IPV6, IPV6_V6ONLY) on an IPv4 socket
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 22H2 answers success for an AF_INET UDP socket, bound or not, and writes the first
 * byte of the buffer as 1 (the rest of a larger buffer is left alone). Rust's quinn-udp, which
 * Firefox's HTTP/3 uses, asks every UDP socket for it and gave up on the WSAEINVAL ReactOS used
 * to return ("failed to initialize socket ... os error 10022").
 *
 * setsockopt(IPV6_V6ONLY) on an IPv4 socket is not refused either (Windows 10 oracle probe, datagram and stream
 * sockets): a DWORD of 0 or 1 is accepted and has no effect, a request one byte long fails with WSAEFAULT (probed on a
 * stream socket).
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

/* setsockopt on an IPv4 socket: accepted and ignored, WSAEFAULT for a request that is too short */
static void CheckSetV6Only(SOCKET s, const char *What)
{
    DWORD On = 1, Off = 0;
    BYTE Short = 1;
    BYTE Value[4];
    int Len = sizeof(Value), Result;

    Result = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&On, sizeof(On));
    ok(Result == 0, "%s: setsockopt(IPV6_V6ONLY, 1) failed: %d\n", What, WSAGetLastError());
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&Off, sizeof(Off));
    ok(Result == 0, "%s: setsockopt(IPV6_V6ONLY, 0) failed: %d\n", What, WSAGetLastError());

    /* it has no effect: an IPv4 socket is still "v6 only" afterwards */
    memset(Value, 0xcc, sizeof(Value));
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)Value, &Len);
    ok(Result == 0 && Value[0] == 1, "%s: after setsockopt(0): %d, value %02x\n", What, Result, Value[0]);

    SetLastError(0xdeadbeef);
    WSASetLastError(0);
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&Short, sizeof(Short));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "%s: setsockopt(IPV6_V6ONLY, one byte): %d, error %d\n",
       What, Result, WSAGetLastError());
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
        CheckSetV6Only(Udp, "udp");
        closesocket(Udp);
    }

    {
        SOCKET Tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        ok(Tcp != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
        if (Tcp != INVALID_SOCKET)
        {
            CheckSetV6Only(Tcp, "tcp");
            closesocket(Tcp);
        }
    }

    WSACleanup();
}
