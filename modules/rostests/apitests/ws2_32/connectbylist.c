/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     WSAConnectByList against loopback listeners; the statuses are those measured on Windows Server 2022
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#ifndef SO_UPDATE_CONNECT_CONTEXT
#define SO_UPDATE_CONNECT_CONTEXT 0x7010    /* mswsock.h */
#endif

typedef BOOL (PASCAL *FN_BYLIST)(SOCKET, PSOCKET_ADDRESS_LIST, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR,
                                 const struct timeval *, LPWSAOVERLAPPED);

static FN_BYLIST pByList;
static SOCKET Listener;
static USHORT Port, ClosedPort;

static SOCKET Listen4(USHORT *OutPort)
{
    SOCKADDR_IN Sa;
    int Len = sizeof(Sa);
    SOCKET L = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    ZeroMemory(&Sa, sizeof(Sa));
    Sa.sin_family = AF_INET;
    Sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (L == INVALID_SOCKET || bind(L, (SOCKADDR *)&Sa, sizeof(Sa)) || listen(L, 64) || getsockname(L, (SOCKADDR *)&Sa, &Len))
    {
        if (L != INVALID_SOCKET)
            closesocket(L);
        return INVALID_SOCKET;
    }
    *OutPort = ntohs(Sa.sin_port);
    return L;
}

/* take the connections the earlier rows left in the listener's queue */
static void Drain(void)
{
    u_long On = 1, Off = 0;
    SOCKET A;

    ioctlsocket(Listener, FIONBIO, &On);
    while ((A = accept(Listener, NULL, NULL)) != INVALID_SOCKET)
        closesocket(A);
    ioctlsocket(Listener, FIONBIO, &Off);
}

static void Addr4(SOCKADDR_STORAGE *Sa, USHORT P)
{
    SOCKADDR_IN *V4 = (SOCKADDR_IN *)Sa;

    ZeroMemory(Sa, sizeof(*Sa));
    V4->sin_family = AF_INET;
    V4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    V4->sin_port = htons(P);
}

static void Addr6(SOCKADDR_STORAGE *Sa, USHORT P)
{
    SOCKADDR_IN6 *V6 = (SOCKADDR_IN6 *)Sa;

    ZeroMemory(Sa, sizeof(*Sa));
    V6->sin6_family = AF_INET6;
    V6->sin6_addr.s6_addr[15] = 1;
    V6->sin6_port = htons(P);
}

static PSOCKET_ADDRESS_LIST MakeList(ULONG Count, SOCKADDR_STORAGE *Sa, const int *Lens)
{
    PSOCKET_ADDRESS_LIST List = HeapAlloc(GetProcessHeap(), 0, sizeof(SOCKET_ADDRESS_LIST) + Count * sizeof(SOCKET_ADDRESS));
    ULONG i;

    List->iAddressCount = Count;
    for (i = 0; i < Count; i++)
    {
        List->Address[i].lpSockaddr = (LPSOCKADDR)&Sa[i];
        List->Address[i].iSockaddrLength = Lens[i];
    }
    return List;
}

/* One row: the status of the call (0 = success) */
static int Call(SOCKET S, PSOCKET_ADDRESS_LIST List, DWORD *LocalLen, SOCKADDR_STORAGE *Local, DWORD *RemoteLen,
                SOCKADDR_STORAGE *Remote, const struct timeval *Tv, LPWSAOVERLAPPED Reserved)
{
    BOOL Ret;

    Drain();
    WSASetLastError(0);
    Ret = pByList(S, List, LocalLen, (LPSOCKADDR)Local, RemoteLen, (LPSOCKADDR)Remote, Tv, Reserved);
    return Ret ? 0 : WSAGetLastError();
}

START_TEST(connectbylist)
{
    WSADATA Wsa;
    SOCKADDR_STORAGE Sa[2], Local, Remote;
    int Lens[2];
    PSOCKET_ADDRESS_LIST List;
    DWORD LocalLen, RemoteLen, Off = 0, On = 1;
    struct timeval Tv = { 5, 0 }, Neg = { -1, 0 }, Zero = { 0, 0 };
    SOCKET S, Tmp;
    SOCKADDR_STORAGE Peer;
    int PeerLen, Status;
    WSAOVERLAPPED Overlapped;
    u_long NonBlocking = 1;

    ok(WSAStartup(MAKEWORD(2, 2), &Wsa) == 0, "WSAStartup failed\n");
    pByList = (FN_BYLIST)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "WSAConnectByList");
    if (!pByList)
    {
        skip("WSAConnectByList is not exported\n");
        WSACleanup();
        return;
    }
    Listener = Listen4(&Port);
    if (Listener == INVALID_SOCKET)
    {
        skip("no IPv4 loopback listener: %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }
    Tmp = Listen4(&ClosedPort);
    closesocket(Tmp);

    Lens[0] = Lens[1] = sizeof(SOCKADDR_IN);
#define RESET_OUT() do { LocalLen = RemoteLen = sizeof(Local); ZeroMemory(&Local, sizeof(Local)); ZeroMemory(&Remote, sizeof(Remote)); } while (0)

    /* L1: one open address; the local address comes back without a port, the remote one with it */
    Addr4(&Sa[0], Port);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == 0, "L1: status %d\n", Status);
    if (Status == 0)
    {
        ok(LocalLen == sizeof(SOCKADDR_IN) && Local.ss_family == AF_INET && ((SOCKADDR_IN *)&Local)->sin_port == 0 &&
           ((SOCKADDR_IN *)&Local)->sin_addr.s_addr == htonl(INADDR_LOOPBACK), "L1: local length %lu port %u\n", LocalLen, ntohs(((SOCKADDR_IN *)&Local)->sin_port));
        ok(RemoteLen == sizeof(SOCKADDR_IN) && ((SOCKADDR_IN *)&Remote)->sin_port == htons(Port), "L1: remote length %lu port %u\n", RemoteLen, ntohs(((SOCKADDR_IN *)&Remote)->sin_port));
        ok(setsockopt(S, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0, "L1: SO_UPDATE_CONNECT_CONTEXT failed\n");
        PeerLen = sizeof(Peer);
        ok(getpeername(S, (SOCKADDR *)&Peer, &PeerLen) == 0, "L1: getpeername after the update: %d\n", WSAGetLastError());
        /* L9b: the socket is connected now */
        RESET_OUT();
        Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
        ok(Status == WSAEISCONN, "L9b: status %d, expected WSAEISCONN\n", Status);
    }
    closesocket(S);

    /* L2: a refused address first, the open one second; L24: the other way round; L3: only a refused one */
    Addr4(&Sa[0], ClosedPort);
    Addr4(&Sa[1], Port);
    List = MakeList(2, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == 0, "L2: status %d\n", Status);
    ok(Status != 0 || ((SOCKADDR_IN *)&Remote)->sin_port == htons(Port), "L2: connected to port %u\n", ntohs(((SOCKADDR_IN *)&Remote)->sin_port));
    closesocket(S);
    Addr4(&Sa[0], Port);
    Addr4(&Sa[1], ClosedPort);
    List = MakeList(2, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == 0, "L24: status %d\n", Status);
    closesocket(S);
    Addr4(&Sa[0], ClosedPort);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAECONNREFUSED, "L3: status %d, expected WSAECONNREFUSED\n", Status);
    closesocket(S);

    /* the parameter errors, all WSAEINVAL */
    Addr4(&Sa[0], Port);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, NULL, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L4 NULL list: status %d\n", Status);
    Status = Call(S, MakeList(0, Sa, Lens), &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L5 empty list: status %d\n", Status);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, &Overlapped);
    ok(Status == WSAEINVAL, "L6 Reserved: status %d\n", Status);
    closesocket(S);
    S = socket(AF_INET, SOCK_DGRAM, 0);
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L8 UDP socket: status %d\n", Status);
    closesocket(S);

    /* L10-L12: an address of another family than the socket's own is no address for it; L15: AF_UNSPEC */
    Addr6(&Sa[0], Port);
    Lens[0] = sizeof(SOCKADDR_IN6);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L10 AF_INET socket, IPv6 entry: status %d\n", Status);
    closesocket(S);
    Addr4(&Sa[0], Port);
    Lens[0] = sizeof(SOCKADDR_IN);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(S, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Off, sizeof(Off));
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L11 dual-stack socket, IPv4 entry: status %d\n", Status);
    closesocket(S);
    S = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(S, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&On, sizeof(On));
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L12 IPv6-only socket, IPv4 entry: status %d\n", Status);
    closesocket(S);
    Addr4(&Sa[0], Port);
    Sa[0].ss_family = AF_UNSPEC;
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEINVAL, "L15 AF_UNSPEC entry: status %d\n", Status);
    closesocket(S);

    /* L13/L14: a buffer that is too small: WSAEFAULT and the length stays as given; L16: a closed socket */
    Addr4(&Sa[0], Port);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    RemoteLen = 4;
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEFAULT, "L13 remote buffer too small: status %d\n", Status);
    ok(RemoteLen == 4, "L13: remote length changed to %lu\n", RemoteLen);
    closesocket(S);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    LocalLen = 4;
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAEFAULT, "L14 local buffer too small: status %d\n", Status);
    ok(LocalLen == 4, "L14: local length changed to %lu\n", LocalLen);
    closesocket(S);
    S = socket(AF_INET, SOCK_STREAM, 0);
    closesocket(S);
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == WSAENOTSOCK, "L16 closed socket: status %d\n", Status);

    /* L17-L22: no address outputs, a non-blocking socket, no timeout, a short second entry, negative and zero timeouts */
    S = socket(AF_INET, SOCK_STREAM, 0);
    Status = Call(S, List, NULL, NULL, NULL, NULL, &Tv, NULL);
    ok(Status == 0, "L17 no address outputs: status %d\n", Status);
    closesocket(S);
    S = socket(AF_INET, SOCK_STREAM, 0);
    ioctlsocket(S, FIONBIO, &NonBlocking);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == 0, "L18 non-blocking socket: status %d\n", Status);
    closesocket(S);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, NULL, NULL);
    ok(Status == 0, "L19 no timeout: status %d\n", Status);
    closesocket(S);
    Addr4(&Sa[0], Port);
    Sa[1] = Sa[0];
    Lens[1] = 4;
    List = MakeList(2, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Tv, NULL);
    ok(Status == 0, "L20 short second entry: status %d\n", Status);
    closesocket(S);
    List = MakeList(1, Sa, Lens);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Neg, NULL);
    ok(Status == 0, "L7 negative timeout: status %d\n", Status);
    closesocket(S);
    S = socket(AF_INET, SOCK_STREAM, 0);
    RESET_OUT();
    Status = Call(S, List, &LocalLen, &Local, &RemoteLen, &Remote, &Zero, NULL);
    ok(Status == 0, "L22 zero timeout: status %d\n", Status);
    closesocket(S);

    closesocket(Listener);
    WSACleanup();
}
