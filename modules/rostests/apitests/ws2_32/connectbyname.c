/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     WSAConnectByNameA / WSAConnectByNameW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010    /* mswsock.h */
#endif

/*
 * "localhost" resolves to ::1 and 127.0.0.1. With a listener on 127.0.0.1 only, the call must try past the refused
 * IPv6 address and leave the caller's dual-stack socket connected to the IPv4 one (as an IPv4-mapped address).
 */

typedef BOOL (PASCAL *FN_BYNAMEA)(SOCKET, LPCSTR, LPCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                  const struct timeval *, LPWSAOVERLAPPED);
typedef BOOL (PASCAL *FN_BYNAMEW)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                  const struct timeval *, LPWSAOVERLAPPED);

static SOCKET Listen4(USHORT *Port)
{
    SOCKADDR_IN Sa;
    int Len = sizeof(Sa);
    SOCKET L = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    ZeroMemory(&Sa, sizeof(Sa));
    Sa.sin_family = AF_INET;
    Sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (L == INVALID_SOCKET || bind(L, (SOCKADDR *)&Sa, sizeof(Sa)) || listen(L, 4) || getsockname(L, (SOCKADDR *)&Sa, &Len))
    {
        if (L != INVALID_SOCKET)
            closesocket(L);
        return INVALID_SOCKET;
    }
    *Port = ntohs(Sa.sin_port);
    return L;
}

static SOCKET DualSocket(void)
{
    DWORD Off = 0;
    SOCKET S = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    if (S != INVALID_SOCKET)
        setsockopt(S, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&Off, sizeof(Off));
    return S;
}

/* The caller's socket is connected to the IPv4 listener: the byte it sends arrives on one of the connections the
   listener has (WSAConnectByName may have made a short probe connection before it) */
static void CheckConnected(SOCKET S, SOCKET L, USHORT Port, const SOCKADDR_IN6 *Remote, DWORD RemoteLength, const char *What)
{
    static const UCHAR Mapped[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1 };
    char Byte = 'x', Got;
    DWORD Timeout = 2000;
    int i;
    BOOL Arrived = FALSE;

    ok(RemoteLength == sizeof(SOCKADDR_IN6), "%s: remote address length %lu\n", What, RemoteLength);
    ok(Remote->sin6_family == AF_INET6 && !memcmp(&Remote->sin6_addr, Mapped, 16) && ntohs(Remote->sin6_port) == Port,
       "%s: remote address family %u port %u\n", What, Remote->sin6_family, ntohs(Remote->sin6_port));
    ok(send(S, &Byte, 1, 0) == 1, "%s: send failed: %d\n", What, WSAGetLastError());
    for (i = 0; i < 3 && !Arrived; i++)
    {
        fd_set Read;
        struct timeval Tv = { 2, 0 };
        SOCKET A;

        FD_ZERO(&Read);
        FD_SET(L, &Read);
        if (select(0, &Read, NULL, NULL, &Tv) != 1)
            break;
        A = accept(L, NULL, NULL);
        if (A == INVALID_SOCKET)
            break;
        setsockopt(A, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
        Got = 0;
        Arrived = recv(A, &Got, 1, 0) == 1 && Got == Byte;
        closesocket(A);
    }
    ok(Arrived, "%s: the byte did not arrive at the listener\n", What);
}

START_TEST(connectbyname)
{
    WSADATA Wsa;
    HMODULE Module;
    FN_BYNAMEA pA;
    FN_BYNAMEW pW;
    SOCKET L, S;
    USHORT Port = 0;
    char PortA[8];
    WCHAR PortW[8], Host[] = L"localhost";
    SOCKADDR_IN6 Local, Remote;
    DWORD LocalLength, RemoteLength;
    struct timeval Tv = { 10, 0 };
    BOOL Ret;

    ok(WSAStartup(MAKEWORD(2, 2), &Wsa) == 0, "WSAStartup failed\n");
    Module = GetModuleHandleW(L"ws2_32.dll");
    pA = (FN_BYNAMEA)GetProcAddress(Module, "WSAConnectByNameA");
    pW = (FN_BYNAMEW)GetProcAddress(Module, "WSAConnectByNameW");
    if (!pA || !pW)
    {
        skip("WSAConnectByName is not exported\n");
        WSACleanup();
        return;
    }

    L = Listen4(&Port);
    ok(L != INVALID_SOCKET, "no IPv4 loopback listener: %d\n", WSAGetLastError());
    if (L == INVALID_SOCKET)
    {
        WSACleanup();
        return;
    }
    sprintf(PortA, "%u", Port);
    _snwprintf(PortW, ARRAYSIZE(PortW) - 1, L"%u", Port);
    PortW[ARRAYSIZE(PortW) - 1] = 0;

    /* A, no time limit */
    S = DualSocket();
    LocalLength = sizeof(Local);
    RemoteLength = sizeof(Remote);
    SetLastError(0xdeadbeef);
    Ret = pA(S, "localhost", PortA, &LocalLength, (LPSOCKADDR)&Local, &RemoteLength, (LPSOCKADDR)&Remote, NULL, NULL);
    ok(Ret, "WSAConnectByNameA failed: %lu\n", GetLastError());
    if (Ret)
    {
        setsockopt(S, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        ok(LocalLength == sizeof(SOCKADDR_IN6), "A: local address length %lu\n", LocalLength);
        CheckConnected(S, L, Port, &Remote, RemoteLength, "A");
    }
    closesocket(S);

    /* W, with a time limit */
    S = DualSocket();
    LocalLength = sizeof(Local);
    RemoteLength = sizeof(Remote);
    Ret = pW(S, Host, PortW, &LocalLength, (LPSOCKADDR)&Local, &RemoteLength, (LPSOCKADDR)&Remote, &Tv, NULL);
    ok(Ret, "WSAConnectByNameW failed: %lu\n", GetLastError());
    if (Ret)
    {
        setsockopt(S, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        CheckConnected(S, L, Port, &Remote, RemoteLength, "W");
    }
    closesocket(S);

    /* no address wanted back */
    S = DualSocket();
    Ret = pA(S, "localhost", PortA, NULL, NULL, NULL, NULL, NULL, NULL);
    ok(Ret, "WSAConnectByNameA without addresses failed: %lu\n", GetLastError());
    if (Ret)
    {
        RemoteLength = sizeof(Remote);
        ok(getpeername(S, (SOCKADDR *)&Remote, (int *)&RemoteLength) == 0, "getpeername failed: %d\n", WSAGetLastError());
        CheckConnected(S, L, Port, &Remote, RemoteLength, "no addresses");
    }
    closesocket(S);

    /* nothing listens on the port any more: no address answers */
    closesocket(L);
    S = DualSocket();
    Ret = pA(S, "localhost", PortA, NULL, NULL, NULL, NULL, &Tv, NULL);
    ok(!Ret, "WSAConnectByNameA to a closed port succeeded\n");
    closesocket(S);

    WSACleanup();
}
