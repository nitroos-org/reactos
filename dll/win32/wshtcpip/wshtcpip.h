/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS WinSock Helper DLL for TCP/IP
 * FILE:        include/wshtcpip.h
 * PURPOSE:     WinSock Helper DLL for TCP/IP header
 */
#ifndef __WSHTCPIP_H
#define __WSHTCPIP_H

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <stdarg.h>

#include <windef.h>
#include <winbase.h>
#include <wsahelp.h>
#include <tdiinfo.h>
#include <tcpioctl.h>
#include <tdilib.h>
#include <ws2tcpip.h>
#include <rtlfuncs.h>
#include <mstcpip.h>
#include <winreg.h>

#define EXPORT WINAPI

#define DD_TCP_DEVICE_NAME      L"\\Device\\Tcp"
#define DD_UDP_DEVICE_NAME      L"\\Device\\Udp"
#define DD_RAW_IP_DEVICE_NAME   L"\\Device\\RawIp"

typedef enum _SOCKET_STATE {
    SocketStateCreated,
    SocketStateBound,
    SocketStateListening,
    SocketStateConnected
} SOCKET_STATE, *PSOCKET_STATE;

typedef struct _QUEUED_REQUEST {
    PTCP_REQUEST_SET_INFORMATION_EX Info;
    PVOID Next;
} QUEUED_REQUEST, *PQUEUED_REQUEST;

typedef struct _SOCKET_CONTEXT {
    INT AddressFamily;
    INT SocketType;
    INT Protocol;
    DWORD Flags;
    DWORD AddrFileEntityType;
    DWORD AddrFileInstance;
    SOCKET_STATE SocketState;
    PQUEUED_REQUEST RequestQueue;
    BOOL DontRoute;
    /* IP and UDP options of a socket as set, for getsockopt (WshGetKeptOption); WSH_OPT_SET_* marks the set ones */
    DWORD OptionsSet;
    LONG IpTtl;
    LONG IpTos;
    LONG IpDontFragment;
    LONG IpRecvTos;
    LONG IpRecvEcn;
    LONG IpMulticastLoop;
    LONG IpMulticastTtl;
    LONG IpMtuDiscover;
    LONG UdpSendMsgSize;
    LONG UdpRecvMaxCoalescedSize;
    /* IPPROTO_IPV6 options of an AF_INET6 socket as set, for getsockopt (WshKeptIpv6Option) */
    DWORD Ipv6OptionsSet;
    LONG Ipv6V6Only;
    LONG Ipv6UnicastHops;
    LONG Ipv6MulticastHops;
    LONG Ipv6MulticastLoop;
    LONG Ipv6DontFragment;
    LONG Ipv6MulticastIf;
    LONG Ipv6HdrIncl;
    LONG Ipv6RecvTclass;
    LONG Ipv6RecvIf;
    LONG Ipv6UnicastIf;
    LONG Ipv6MtuDiscover;
    /* IP_HDRINCL of a raw IPv4 socket as set */
    LONG IpHdrIncl;
    /* The multicast groups of a datagram socket with their source filters (mcast.c) */
    struct _WSH_MCAST *Mcast;
} SOCKET_CONTEXT, *PSOCKET_CONTEXT;

/* Which IPPROTO_IPV6 options of an AF_INET6 socket were set (SOCKET_CONTEXT Ipv6OptionsSet) */
#define WSH_SET6_V6ONLY     0x01
#define WSH_SET6_UNIHOPS    0x02
#define WSH_SET6_MCASTHOPS  0x04
#define WSH_SET6_MCASTLOOP  0x08
#define WSH_SET6_DONTFRAG   0x10
#define WSH_SET6_MCASTIF    0x20
#define WSH_SET6_HDRINCL    0x40
#define WSH_SET6_RECVTCLASS 0x80
#define WSH_SET6_RECVIF     0x100
#define WSH_SET6_UNICASTIF  0x200
#define WSH_SET6_MTUD       0x400

/* mcast.c: multicast groups and source filters (MCAST_*, IP_*_MEMBERSHIP, IP_*_SOURCE*, IPV6_*_MEMBERSHIP, the
   multicast filter ioctls); AddressHandle: the socket's address handle the requests go on (NULL before the bind) */
BOOLEAN WshMcastIsOption(INT Level, INT OptionName);
INT WshMcastSetOption(PSOCKET_CONTEXT Context, HANDLE AddressHandle, INT Level, INT OptionName, PCHAR OptionValue,
                      INT OptionLength, PBOOLEAN Handled);
INT WshMcastIoctl(PSOCKET_CONTEXT Context, HANDLE AddressHandle, DWORD Code, PVOID InputBuffer,
                  DWORD InputBufferLength, PVOID OutputBuffer, DWORD OutputBufferLength, LPDWORD Returned,
                  PBOOLEAN Handled);
INT WshMcastBind(PSOCKET_CONTEXT Context, HANDLE AddressHandle);
VOID WshMcastFree(PSOCKET_CONTEXT Context);

/* A socket option request to the stack on the socket's address handle, else a control channel (wshtcpip.c) */
DWORD WshSetInformationEx(HANDLE AddressHandle, DWORD IOCTL, PVOID Request, DWORD RequestSize);

INT
WSHIoctl_GetInterfaceList(
    IN  LPVOID OutputBuffer,
    IN  DWORD OutputBufferLength,
    OUT LPDWORD NumberOfBytesReturned,
    OUT LPBOOL NeedsCompletion);

INT
SendRequest(
    IN HANDLE AddressHandle,
    IN PVOID Request,
    IN DWORD RequestSize,
    IN DWORD IOCTL);

#endif /* __WSHTCPIP_H */

/* EOF */
