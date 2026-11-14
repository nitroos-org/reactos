/*
 * PROJECT:     ws2_32.dll API tests
 * LICENSE:     GPLv2 or any later version
 * FILE:        apitests/ws2_32/ws2_32.h
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2008 Colin Finck <mail@colinfinck.de>
 */

#ifndef _WS2_32_APITESTS_H
#define _WS2_32_APITESTS_H

#include <ntstatus.h>
#include <stdio.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <apitest.h>
#include <ws2tcpip.h>
#include <ndk/rtlfuncs.h>
#include <ndk/mmfuncs.h>

/* Simple macro for executing a socket command and doing cleanup operations in case of a failure */
#define SCKTEST(_cmd_) \
    iResult = _cmd_; \
    ok(iResult != SOCKET_ERROR, "iResult = %d\n", iResult); \
    if(iResult == SOCKET_ERROR) \
    { \
        printf("Winsock error code is %u\n", WSAGetLastError()); \
        closesocket(sck); \
        WSACleanup(); \
        return 0; \
    }

/* helpers.c */
int CreateSocket(SOCKET* sck);
int ConnectToReactOSWebsite(SOCKET sck);
int GetRequestAndWait(SOCKET sck);

/* ws2_32.c */
extern HANDLE g_hHeap;

/* ipv6stack.c: the IPv6 state of the stack (TCP_IPV6_STATE_ flags of tcpioctl.h) */
#define TEST_IPV6_STATE_ON      0x1
#define TEST_IPV6_STATE_SOCKETS 0x2
ULONG Ipv6StackFlags(void);
BOOL Ipv6SocketsOn(void);

#endif /* !_WS2_32_APITESTS_H */
