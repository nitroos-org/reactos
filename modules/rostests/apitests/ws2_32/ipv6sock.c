/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     AF_INET6 sockets before the stack has IPv6 sockets: with the stack's IPv6 switch off
 *              (Tcpip\Parameters\Ipv6Enable) an IPv6 socket fails with WSAEAFNOSUPPORT, as it always did; with
 *              the switch on one is made and its address buffers are checked (lengths, family) before any
 *              address reaches the stack, which says no (a defined error) until it takes IPv6 sockets.
 *              The Winsock helper (wshtcpip) is tested directly: socket address kinds, the wildcard address
 *              and the refusal of an IPv6 socket.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <winreg.h>
#include <wsahelp.h>

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#ifndef IPV6_UNICAST_HOPS
#define IPV6_UNICAST_HOPS 4
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO 19
#endif
#ifndef IPV6_MULTICAST_HOPS
#define IPV6_MULTICAST_HOPS 10
#endif

typedef INT (WINAPI *PWSH_GET_SOCKADDR_TYPE_T)(PSOCKADDR, DWORD, PSOCKADDR_INFO);
typedef INT (WINAPI *PWSH_GET_WILDCARD_T)(PVOID, PSOCKADDR, PINT);
typedef INT (WINAPI *PWSH_GET_BROADCAST_T)(PVOID, PSOCKADDR, PINT);
typedef INT (WINAPI *PWSH_OPEN_SOCKET2_T)(PINT, PINT, PINT, GROUP, DWORD, PUNICODE_STRING, PVOID *, PDWORD);
typedef INT (WINAPI *PWSH_NOTIFY_T)(PVOID, SOCKET, HANDLE, HANDLE, DWORD);

static BOOL SwitchOn;

static BOOL ReadSwitch(void)
{
    HKEY Key;
    DWORD Type, Value = 0, Size = sizeof(Value);
    BOOL On = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                      0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(Key, L"Ipv6Enable", NULL, &Type, (LPBYTE)&Value, &Size) == ERROR_SUCCESS &&
            Type == REG_DWORD && Value != 0)
            On = TRUE;
        RegCloseKey(Key);
    }
    return On;
}

static void InitIn6(SOCKADDR_IN6_LH *Sa, const USHORT Words[8], USHORT Port, ULONG Scope)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    Sa->sin6_port = htons(Port);
    if (Words)
        memcpy(&Sa->sin6_addr, Words, 16);
    Sa->sin6_scope_id = Scope;
}

static void CheckKind(PWSH_GET_SOCKADDR_TYPE_T GetType, PVOID Sa, DWORD Length, INT Expected,
                      SOCKADDR_ADDRESS_INFO Address, SOCKADDR_ENDPOINT_INFO Endpoint, const char *What)
{
    SOCKADDR_INFO Info;
    INT Result;

    memset(&Info, 0xcc, sizeof(Info));
    Result = GetType(Sa, Length, &Info);
    ok(Result == Expected, "%s: result %d, expected %d\n", What, Result, Expected);
    if (Result == NO_ERROR && Expected == NO_ERROR)
    {
        ok(Info.AddressInfo == Address, "%s: address kind %d, expected %d\n", What, Info.AddressInfo, Address);
        ok(Info.EndpointInfo == Endpoint, "%s: endpoint kind %d, expected %d\n", What, Info.EndpointInfo, Endpoint);
    }
}

static void TestHelper(void)
{
    HMODULE Dll = LoadLibraryW(L"wshtcpip.dll");
    PWSH_GET_SOCKADDR_TYPE_T GetType;
    PWSH_GET_WILDCARD_T GetWildcard;
    PWSH_GET_BROADCAST_T GetBroadcast;
    PWSH_OPEN_SOCKET2_T Open2;
    PWSH_NOTIFY_T Notify;
    SOCKADDR_IN6_LH Sa6;
    SOCKADDR_IN Sa4;
    union { SOCKADDR_IN6_LH In6; BYTE Raw[128]; } Big;
    static const USHORT Loopback[8] = { 0, 0, 0, 0, 0, 0, 0, 0x0100 };         /* ::1 */
    static const USHORT LinkLocal[8] = { 0x80fe, 0, 0, 0, 0, 0, 0, 0x0100 };   /* fe80::1 */
    static const USHORT Mapped[8] = { 0, 0, 0, 0, 0, 0xffff, 0x007f, 0x0100 }; /* ::ffff:127.0.0.1 */
    static const USHORT MappedNormal[8] = { 0, 0, 0, 0, 0, 0xffff, 0x0201, 0x0403 }; /* ::ffff:1.2.3.4 */
    static const USHORT MappedAny[8] = { 0, 0, 0, 0, 0, 0xffff, 0, 0 };        /* ::ffff:0.0.0.0 */
    static const USHORT Multicast[8] = { 0x02ff, 0, 0, 0, 0, 0, 0, 0x0100 };   /* ff02::1 */
    INT Family, Type, Protocol, Length, Result;
    UNICODE_STRING Transport;
    PVOID Context;
    DWORD Events;

    if (!Dll)
    {
        skip("wshtcpip.dll not found\n");
        return;
    }
    GetType = (PWSH_GET_SOCKADDR_TYPE_T)GetProcAddress(Dll, "WSHGetSockaddrType");
    GetWildcard = (PWSH_GET_WILDCARD_T)GetProcAddress(Dll, "WSHGetWildcardSockaddr");
    GetBroadcast = (PWSH_GET_BROADCAST_T)GetProcAddress(Dll, "WSHGetBroadcastSockaddr");
    Open2 = (PWSH_OPEN_SOCKET2_T)GetProcAddress(Dll, "WSHOpenSocket2");
    Notify = (PWSH_NOTIFY_T)GetProcAddress(Dll, "WSHNotify");
    if (!GetType || !GetWildcard || !GetBroadcast || !Open2 || !Notify)
    {
        skip("wshtcpip.dll does not export the helper functions\n");
        FreeLibrary(Dll);
        return;
    }

    /* IPv6 socket addresses: kinds of address and port */
    InitIn6(&Sa6, NULL, 0, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoWildcard, SockaddrEndpointInfoWildcard, "[::]:0");
    InitIn6(&Sa6, NULL, 80, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoWildcard, SockaddrEndpointInfoReserved, "[::]:80");
    InitIn6(&Sa6, Loopback, 8080, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoLoopback, SockaddrEndpointInfoNormal, "[::1]:8080");
    InitIn6(&Sa6, LinkLocal, 8080, 5);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoNormal, SockaddrEndpointInfoNormal, "[fe80::1%5]:8080");
    InitIn6(&Sa6, Multicast, 8080, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoNormal, SockaddrEndpointInfoNormal, "[ff02::1]:8080");
    InitIn6(&Sa6, Mapped, 8080, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoLoopback, SockaddrEndpointInfoNormal, "[::ffff:127.0.0.1]:8080");
    InitIn6(&Sa6, MappedNormal, 8080, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoNormal, SockaddrEndpointInfoNormal, "[::ffff:1.2.3.4]:8080");
    InitIn6(&Sa6, MappedAny, 8080, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6), NO_ERROR, SockaddrAddressInfoWildcard, SockaddrEndpointInfoNormal, "[::ffff:0.0.0.0]:8080");

    /* Lengths: the whole SOCKADDR_IN6 (28 bytes, scope id included) is needed, more is fine */
    InitIn6(&Sa6, Loopback, 8080, 0);
    CheckKind(GetType, &Sa6, sizeof(Sa6) - 1, WSAEINVAL, 0, 0, "27 bytes");
    CheckKind(GetType, &Sa6, 24, WSAEINVAL, 0, 0, "24 bytes (no scope id)");
    CheckKind(GetType, &Sa6, sizeof(USHORT), WSAEINVAL, 0, 0, "2 bytes");
    memset(&Big, 0, sizeof(Big));
    Big.In6 = Sa6;
    CheckKind(GetType, &Big, sizeof(Big), NO_ERROR, SockaddrAddressInfoLoopback, SockaddrEndpointInfoNormal, "128 bytes");
    CheckKind(GetType, NULL, sizeof(Sa6), WSAEINVAL, 0, 0, "NULL address");

    /* IPv4 is as it was */
    memset(&Sa4, 0, sizeof(Sa4));
    Sa4.sin_family = AF_INET;
    Sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Sa4.sin_port = htons(8080);
    CheckKind(GetType, &Sa4, sizeof(Sa4), NO_ERROR, SockaddrAddressInfoLoopback, SockaddrEndpointInfoNormal, "127.0.0.1:8080");
    CheckKind(GetType, &Sa4, sizeof(Sa4) - 1, WSAEINVAL, 0, 0, "IPv4, 15 bytes");

    /* An IPv6 socket: the switch decides */
    Family = AF_INET6; Type = SOCK_STREAM; Protocol = IPPROTO_TCP;
    Context = (PVOID)(ULONG_PTR)0x12345678;
    memset(&Transport, 0, sizeof(Transport));
    Events = 0;
    Result = Open2(&Family, &Type, &Protocol, 0, 0, &Transport, &Context, &Events);
    if (!SwitchOn)
    {
        ok(Result == WSAEAFNOSUPPORT, "WSHOpenSocket2(AF_INET6) with the switch off: %d\n", Result);
        ok(Context == (PVOID)(ULONG_PTR)0x12345678, "context touched: %p\n", Context);
        ok(Transport.Buffer == NULL, "transport name allocated\n");

        Type = SOCK_DGRAM; Protocol = IPPROTO_UDP;
        Result = Open2(&Family, &Type, &Protocol, 0, 0, &Transport, &Context, &Events);
        ok(Result == WSAEAFNOSUPPORT, "WSHOpenSocket2(AF_INET6 UDP) with the switch off: %d\n", Result);
        Type = SOCK_RAW; Protocol = IPPROTO_ICMPV6;
        Result = Open2(&Family, &Type, &Protocol, 0, 0, &Transport, &Context, &Events);
        ok(Result == WSAEAFNOSUPPORT, "WSHOpenSocket2(AF_INET6 RAW) with the switch off: %d\n", Result);
    }
    else
    {
        ok(Result == NO_ERROR, "WSHOpenSocket2(AF_INET6) with the switch on: %d\n", Result);
        if (Result == NO_ERROR)
        {
            ok(Context != NULL && Context != (PVOID)(ULONG_PTR)0x12345678, "no context: %p\n", Context);
            ok(Transport.Buffer && !_wcsicmp(Transport.Buffer, L"\\Device\\Tcp"), "transport %ls\n",
               Transport.Buffer ? Transport.Buffer : L"(null)");

            /* The wildcard address of an IPv6 socket: a whole SOCKADDR_IN6 */
            memset(&Big, 0xcc, sizeof(Big));
            Length = sizeof(Big);
            Result = GetWildcard(Context, (PSOCKADDR)&Big, &Length);
            ok(Result == NO_ERROR, "wildcard: %d\n", Result);
            ok(Length == 28, "wildcard length %d\n", Length);
            ok(Big.In6.sin6_family == AF_INET6, "wildcard family %u\n", Big.In6.sin6_family);
            {
                static const BYTE Zero[26];
                ok(!memcmp((BYTE *)&Big + 2, Zero, 26), "wildcard is not all zero\n");
            }
            ok(Big.Raw[28] == 0xcc, "wildcard wrote past 28 bytes\n");
            Length = 27;
            Result = GetWildcard(Context, (PSOCKADDR)&Big, &Length);
            ok(Result == WSAEFAULT, "short wildcard buffer: %d\n", Result);
            Length = sizeof(Big);
            Result = GetBroadcast(Context, (PSOCKADDR)&Big, &Length);
            ok(Result != NO_ERROR, "an IPv6 socket has a broadcast address\n");

            Notify(Context, INVALID_SOCKET, NULL, NULL, WSH_NOTIFY_CLOSE);
            RtlFreeUnicodeString(&Transport);
        }
    }

    /* IPv4 is made whatever the switch says */
    Family = AF_INET; Type = SOCK_STREAM; Protocol = IPPROTO_TCP;
    memset(&Transport, 0, sizeof(Transport));
    Context = NULL;
    Result = Open2(&Family, &Type, &Protocol, 0, 0, &Transport, &Context, &Events);
    ok(Result == NO_ERROR, "WSHOpenSocket2(AF_INET): %d\n", Result);
    if (Result == NO_ERROR)
    {
        memset(&Big, 0xcc, sizeof(Big));
        Length = sizeof(Big);
        Result = GetWildcard(Context, (PSOCKADDR)&Big, &Length);
        ok(Result == NO_ERROR, "IPv4 wildcard: %d\n", Result);
        ok(Big.In6.sin6_family == AF_INET, "IPv4 wildcard family %u\n", Big.In6.sin6_family);
        Notify(Context, INVALID_SOCKET, NULL, NULL, WSH_NOTIFY_CLOSE);
        RtlFreeUnicodeString(&Transport);
    }

    FreeLibrary(Dll);
}

/* The error of an address the stack does not take yet (or any success) */
static BOOL IsDefinedStackError(int Error)
{
    return Error == WSAEINVAL || Error == WSAEAFNOSUPPORT || Error == WSAEADDRNOTAVAIL ||
           Error == WSAEOPNOTSUPP || Error == WSAEPROTONOSUPPORT || Error == WSAECONNREFUSED ||
           Error == WSAENETUNREACH || Error == WSAEHOSTUNREACH || Error == WSAETIMEDOUT;
}

static void TestSocketOptions(SOCKET s)
{
    DWORD Value;
    int Length, Result;

    /* IPV6_V6ONLY: kept; on by default on Windows (VERIFY ON ORACLE) */
    Value = 0xcccccccc;
    Length = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, &Length);
    ok(Result == 0, "getsockopt(IPV6_V6ONLY): %d\n", WSAGetLastError());
    if (Result == 0)
        ok(Value == 1 && Length == sizeof(Value), "IPV6_V6ONLY default %lu, length %d\n", Value, Length);
    Value = 0;
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, sizeof(Value));
    ok(Result == 0, "setsockopt(IPV6_V6ONLY 0): %d\n", WSAGetLastError());
    Value = 0xcccccccc;
    Length = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, &Length);
    ok(Result == 0 && Value == 0, "IPV6_V6ONLY after 0: %d %lu\n", Result, Value);
    Value = 1;
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&Value, sizeof(Value));
    ok(Result == 0, "setsockopt(IPV6_V6ONLY 1): %d\n", WSAGetLastError());

    /* The hop limit: 0 to 255, or -1 */
    Value = 64;
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, sizeof(Value));
    ok(Result == 0, "setsockopt(IPV6_UNICAST_HOPS 64): %d\n", WSAGetLastError());
    Value = 0;
    Length = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, &Length);
    ok(Result == 0 && Value == 64, "IPV6_UNICAST_HOPS: %d %lu\n", Result, Value);
    Value = 256;
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, sizeof(Value));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "IPV6_UNICAST_HOPS 256: %d %d\n", Result, WSAGetLastError());
    Value = (DWORD)-1;
    Result = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, sizeof(Value));
    ok(Result == 0, "setsockopt(IPV6_UNICAST_HOPS -1): %d\n", WSAGetLastError());

    /* An IPv6 option the stack has no part for yet */
    Value = 0;
    Length = sizeof(Value);
    Result = getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&Value, &Length);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAENOPROTOOPT, "getsockopt(IPV6_PKTINFO): %d %d\n", Result, WSAGetLastError());
}

static void TestSocketAddresses(SOCKET s, BOOL Stream)
{
    SOCKADDR_IN6_LH Sa6;
    SOCKADDR_IN Sa4;
    union { SOCKADDR_IN6_LH In6; BYTE Raw[64]; } Out;
    static const USHORT Loopback[8] = { 0, 0, 0, 0, 0, 0, 0, 0x0100 };
    int Result, Error, Length;
    char Data[4] = "abc";

    InitIn6(&Sa6, Loopback, 0, 0);

    /* A short address: the whole SOCKADDR_IN6 is needed */
    Result = bind(s, (struct sockaddr *)&Sa6, sizeof(Sa6) - 1);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "bind 27 bytes: %d %d\n", Result, WSAGetLastError());
    memset(&Sa4, 0, sizeof(Sa4));
    Sa4.sin_family = AF_INET;
    Result = bind(s, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "bind an IPv4 address (16 bytes): %d %d\n", Result, WSAGetLastError());

    /* The right length, the wrong family */
    memset(&Out, 0, sizeof(Out));
    ((SOCKADDR_IN *)&Out)->sin_family = AF_INET;
    Result = bind(s, (struct sockaddr *)&Out, sizeof(Sa6));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT, "bind a wrong family: %d %d\n", Result, WSAGetLastError());
    Result = connect(s, (struct sockaddr *)&Out, sizeof(Sa6));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT, "connect a wrong family: %d %d\n", Result, WSAGetLastError());
    Result = connect(s, (struct sockaddr *)&Sa6, sizeof(Sa6) - 1);
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "connect 27 bytes: %d %d\n", Result, WSAGetLastError());
    Result = connect(s, (struct sockaddr *)&Sa4, sizeof(Sa4));
    ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "connect an IPv4 address (16 bytes): %d %d\n", Result, WSAGetLastError());
    if (!Stream)
    {
        Result = sendto(s, Data, sizeof(Data), 0, (struct sockaddr *)&Sa6, sizeof(Sa6) - 1);
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "sendto 27 bytes: %d %d\n", Result, WSAGetLastError());
        Result = sendto(s, Data, sizeof(Data), 0, (struct sockaddr *)&Out, sizeof(Sa6));
        ok(Result == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT, "sendto a wrong family: %d %d\n", Result, WSAGetLastError());
    }

    /* Not named yet */
    memset(&Out, 0xcc, sizeof(Out));
    Length = sizeof(Out);
    Result = getsockname(s, (struct sockaddr *)&Out, &Length);
    if (Result == SOCKET_ERROR)
        ok(IsDefinedStackError(WSAGetLastError()), "getsockname on a new socket: %d\n", WSAGetLastError());

    /* A whole address: the stack takes it or answers with a defined error, and the socket is still usable after */
    Result = bind(s, (struct sockaddr *)&Sa6, sizeof(Sa6));
    Error = Result == 0 ? 0 : WSAGetLastError();
    ok(Result == 0 || IsDefinedStackError(Error), "bind [::1]:0: %d %d\n", Result, Error);
    if (Result == 0)
    {
        memset(&Out, 0xcc, sizeof(Out));
        Length = sizeof(Out);
        Result = getsockname(s, (struct sockaddr *)&Out, &Length);
        ok(Result == 0, "getsockname: %d\n", WSAGetLastError());
        if (Result == 0)
        {
            ok(Length == 28, "getsockname length %d\n", Length);
            ok(Out.In6.sin6_family == AF_INET6, "getsockname family %u\n", Out.In6.sin6_family);
        }
    }
    else
    {
        trace("bind of an IPv6 address answered %d (the stack has no IPv6 sockets yet)\n", Error);
    }
}

static void TestSockets(void)
{
    SOCKET s;
    int Error;

    if (!SwitchOn)
    {
        /* The answer an application has always got */
        s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        Error = WSAGetLastError();
        ok(s == INVALID_SOCKET, "socket(AF_INET6, SOCK_STREAM) made a socket with the switch off\n");
        if (s != INVALID_SOCKET)
            closesocket(s);
        else
            ok(Error == WSAEAFNOSUPPORT, "socket(AF_INET6, SOCK_STREAM): %d\n", Error);

        s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        Error = WSAGetLastError();
        ok(s == INVALID_SOCKET, "socket(AF_INET6, SOCK_DGRAM) made a socket with the switch off\n");
        if (s != INVALID_SOCKET)
            closesocket(s);
        else
            ok(Error == WSAEAFNOSUPPORT, "socket(AF_INET6, SOCK_DGRAM): %d\n", Error);

        s = socket(AF_INET6, SOCK_STREAM, 0);
        Error = WSAGetLastError();
        ok(s == INVALID_SOCKET && Error == WSAEAFNOSUPPORT, "socket(AF_INET6, SOCK_STREAM, 0): %d %d\n", (int)s, Error);
        if (s != INVALID_SOCKET)
            closesocket(s);

        s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        Error = WSAGetLastError();
        ok(s == INVALID_SOCKET && Error == WSAEAFNOSUPPORT, "socket(AF_INET6, SOCK_RAW): %d %d\n", (int)s, Error);
        if (s != INVALID_SOCKET)
            closesocket(s);

        /* IPv4 is made, and has no IPv6 half */
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok(s != INVALID_SOCKET, "socket(AF_INET): %d\n", WSAGetLastError());
        if (s != INVALID_SOCKET)
            closesocket(s);
        return;
    }

    s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    ok(s != INVALID_SOCKET, "socket(AF_INET6, SOCK_STREAM) with the switch on: %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
    {
        TestSocketOptions(s);
        TestSocketAddresses(s, TRUE);
        closesocket(s);
    }

    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    ok(s != INVALID_SOCKET, "socket(AF_INET6, SOCK_DGRAM) with the switch on: %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
    {
        TestSocketAddresses(s, FALSE);
        closesocket(s);
    }

    /* An IPv4 socket still has no IPv6 options of its own to set */
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(s != INVALID_SOCKET, "socket(AF_INET): %d\n", WSAGetLastError());
    if (s != INVALID_SOCKET)
    {
        DWORD Value = 0xcc;
        int Length = sizeof(Value), Result;

        Result = getsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&Value, &Length);
        ok(Result == SOCKET_ERROR, "IPV6_UNICAST_HOPS on an IPv4 socket: %d\n", Result);
        closesocket(s);
    }
}

START_TEST(ipv6sock)
{
    WSADATA wsaData;

    ok(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, "WSAStartup failed\n");

    /* IPv6 sockets exist when the stack says IPv6 is on and it takes IPv6 sockets (the value alone, with a stack
       that has no IPv6 sockets, gives the answers of a system without IPv6) */
    SwitchOn = Ipv6SocketsOn();
    trace("IPv6 switch (Tcpip\\Parameters\\Ipv6Enable): %s; stack state 0x%lx: IPv6 sockets %s\n",
          ReadSwitch() ? "on" : "off", Ipv6StackFlags(), SwitchOn ? "on" : "off");

    TestHelper();
    TestSockets();

    WSACleanup();
}
