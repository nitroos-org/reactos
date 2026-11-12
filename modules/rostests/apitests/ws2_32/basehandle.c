/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     WSAIoctl(SIO_BASE_HANDLE, SIO_BSP_HANDLE, SIO_BSP_HANDLE_SELECT, SIO_BSP_HANDLE_POLL)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * mio (tokio, so rustup and cargo) asks for the base handle of every socket it registers, and a
 * failure there showed as "tcp connect error: An invalid argument was supplied (os error 10022)".
 * The expected values are what Windows 10 22H2 x64 does (probe on the oracle): the output is the
 * socket handle itself (the base provider is the only one), eight bytes, for stream and datagram
 * sockets; an output buffer under sizeof(SOCKET) bytes, or none, is WSAEFAULT and leaves the
 * byte count untouched; a buffer of 16 bytes receives 8.
 */

#include "ws2_32.h"
#include <mswsock.h>

#ifndef SIO_BASE_HANDLE
/* mswsock.h has these for _WIN32_WINNT >= 0x0600 only */
#define SIO_BSP_HANDLE          _WSAIOR(IOC_WS2,27)
#define SIO_BSP_HANDLE_SELECT   _WSAIOR(IOC_WS2,28)
#define SIO_BSP_HANDLE_POLL     _WSAIOR(IOC_WS2,29)
#define SIO_BASE_HANDLE         _WSAIOR(IOC_WS2,34)
#endif

static void CheckIoctl(SOCKET s, DWORD Code, const char *Name)
{
    BYTE Out[32];
    DWORD Ret;
    int Result;
    SOCKET Got;
    DWORD Sizes[] = { 0, 4, sizeof(SOCKET), 16 };
    int i;

    for (i = 0; i < 4; i++)
    {
        memset(Out, 0xcc, sizeof(Out));
        Ret = 0xdead;
        Result = WSAIoctl(s, Code, NULL, 0, Out, Sizes[i], &Ret, NULL, NULL);
        if (Sizes[i] < sizeof(SOCKET))
        {
            ok(Result == SOCKET_ERROR, "%s: out %lu: result %d\n", Name, Sizes[i], Result);
            ok(WSAGetLastError() == WSAEFAULT, "%s: out %lu: error %d\n", Name, Sizes[i], WSAGetLastError());
            ok(Out[0] == 0xcc, "%s: out %lu: buffer written\n", Name, Sizes[i]);
        }
        else
        {
            ok(Result == 0, "%s: out %lu: failed, error %d\n", Name, Sizes[i], WSAGetLastError());
            ok(Ret == sizeof(SOCKET), "%s: out %lu: byte count %lu\n", Name, Sizes[i], Ret);
            memcpy(&Got, Out, sizeof(Got));
            ok(Got == s, "%s: out %lu: handle %p, socket %p\n", Name, Sizes[i], (void *)Got, (void *)s);
            ok(Sizes[i] != 16 || Out[sizeof(SOCKET)] == 0xcc, "%s: wrote past the handle\n", Name);
        }
    }

    Ret = 0xdead;
    Result = WSAIoctl(s, Code, NULL, 0, NULL, sizeof(SOCKET), &Ret, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "%s: no buffer: %d, error %d\n", Name, Result, WSAGetLastError());

    Result = WSAIoctl(s, Code, NULL, 0, Out, sizeof(SOCKET), NULL, NULL, NULL);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "%s: no byte count: %d, error %d\n", Name, Result, WSAGetLastError());
}

START_TEST(basehandle)
{
    WSADATA Data;
    SOCKET Tcp, Udp;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");
    Tcp = socket(AF_INET, SOCK_STREAM, 0);
    Udp = socket(AF_INET, SOCK_DGRAM, 0);
    ok(Tcp != INVALID_SOCKET && Udp != INVALID_SOCKET, "socket failed\n");

    CheckIoctl(Tcp, SIO_BASE_HANDLE, "SIO_BASE_HANDLE tcp");
    CheckIoctl(Udp, SIO_BASE_HANDLE, "SIO_BASE_HANDLE udp");
    CheckIoctl(Tcp, SIO_BSP_HANDLE, "SIO_BSP_HANDLE");
    CheckIoctl(Tcp, SIO_BSP_HANDLE_SELECT, "SIO_BSP_HANDLE_SELECT");
    CheckIoctl(Tcp, SIO_BSP_HANDLE_POLL, "SIO_BSP_HANDLE_POLL");

    closesocket(Tcp);
    closesocket(Udp);
    WSACleanup();
}
