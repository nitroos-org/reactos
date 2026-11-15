/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetIpStatisticsEx, GetTcpStatisticsEx and GetIcmpStatisticsEx for AF_INET6 report the IPv6 path: the
 *              datagrams, TCP segments and connections and ICMPv6 messages by type (Windows 10: echo request 128 and
 *              reply 129 count in and out over the loopback, not forwarding (2), hop limit 128, reassembly timeout 60).
 *              Without IPv6 the ICMP statistics are written as zeros (they were left unwritten).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"
#include <icmpapi.h>

/* the headers of this tree do not declare them */
DWORD WINAPI GetTcpStatisticsEx(PMIB_TCPSTATS Statistics, DWORD Family);
DWORD WINAPI GetIcmpStatisticsEx(PMIB_ICMP_EX Statistics, DWORD Family);

static void TestArguments(void)
{
    MIB_IPSTATS Ip;
    MIB_TCPSTATS Tcp;
    MIB_ICMP_EX Icmp;

    ok(GetIpStatisticsEx(NULL, AF_INET6) == ERROR_INVALID_PARAMETER, "GetIpStatisticsEx(NULL)\n");
    ok(GetIpStatisticsEx(&Ip, 99) == ERROR_INVALID_PARAMETER, "GetIpStatisticsEx(family 99)\n");
    ok(GetTcpStatisticsEx(NULL, AF_INET6) == ERROR_INVALID_PARAMETER, "GetTcpStatisticsEx(NULL)\n");
    ok(GetTcpStatisticsEx(&Tcp, 99) == ERROR_INVALID_PARAMETER, "GetTcpStatisticsEx(family 99)\n");
    ok(GetIcmpStatisticsEx(NULL, AF_INET6) == ERROR_INVALID_PARAMETER, "GetIcmpStatisticsEx(NULL)\n");
    ok(GetIcmpStatisticsEx(&Icmp, 99) == ERROR_INVALID_PARAMETER, "GetIcmpStatisticsEx(family 99)\n");
}

/* every counter of the statistics is written, whatever the buffer held */
static void TestWritten(ADDRESS_FAMILY Family)
{
    MIB_ICMP_EX Icmp;
    DWORD Error, i;
    BOOL Garbage = FALSE;

    memset(&Icmp, 0xcd, sizeof(Icmp));
    Error = GetIcmpStatisticsEx(&Icmp, Family);
    ok(Error == NO_ERROR, "GetIcmpStatisticsEx(%u): %lu\n", Family, Error);
    if (Error != NO_ERROR)
        return;
    Garbage = Icmp.icmpInStats.dwMsgs == 0xcdcdcdcd || Icmp.icmpOutStats.dwMsgs == 0xcdcdcdcd ||
              Icmp.icmpInStats.dwErrors == 0xcdcdcdcd || Icmp.icmpOutStats.dwErrors == 0xcdcdcdcd;
    for (i = 0; i < 256; i++)
        if (Icmp.icmpInStats.rgdwTypeCount[i] == 0xcdcdcdcd || Icmp.icmpOutStats.rgdwTypeCount[i] == 0xcdcdcdcd)
            Garbage = TRUE;
    ok(!Garbage, "GetIcmpStatisticsEx(%u) left part of the buffer unwritten\n", Family);
}

static void Echo(HANDLE Icmp, ULONG Count)
{
    static const UCHAR Loopback6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    struct sockaddr_in6 Source, Dest;
    char Data[16];
    UCHAR Reply[sizeof(ICMPV6_ECHO_REPLY) + sizeof(Data) + 8 + 64];
    ULONG i;

    memset(&Source, 0, sizeof(Source));
    Source.sin6_family = AF_INET6;
    memset(&Dest, 0, sizeof(Dest));
    Dest.sin6_family = AF_INET6;
    memcpy(&Dest.sin6_addr, Loopback6, 16);
    memset(Data, 'p', sizeof(Data));
    for (i = 0; i < Count; i++)
    {
        DWORD Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, &Dest, Data, sizeof(Data), NULL, Reply, sizeof(Reply),
                                   2000);
        ok(Ret == 1, "echo %lu to ::1: %lu (%lu)\n", i, Ret, GetLastError());
    }
}

START_TEST(Ipv6Statistics)
{
    WSADATA Wsa;
    MIB_IPSTATS Ip0, Ip1;
    MIB_TCPSTATS Tcp0, Tcp1, TcpUp;
    MIB_ICMP_EX Icmp0, Icmp1;
    SOCKET Listener, Client, Server;
    SOCKADDR_IN6 Address;
    int Length = sizeof(Address);
    HANDLE Echoes;
    DWORD Error;
    char Byte = 'x';

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    TestArguments();

    if (!Ipv6SocketsWork())
    {
        TestWritten(AF_INET6);
        return;
    }
    TestWritten(AF_INET6);
    TestWritten(AF_INET);

    ok(GetIpStatisticsEx(&Ip0, AF_INET6) == NO_ERROR, "GetIpStatisticsEx\n");
    ok(GetTcpStatisticsEx(&Tcp0, AF_INET6) == NO_ERROR, "GetTcpStatisticsEx\n");
    ok(GetIcmpStatisticsEx(&Icmp0, AF_INET6) == NO_ERROR, "GetIcmpStatisticsEx\n");
    ok(Ip0.dwForwarding == MIB_IP_NOT_FORWARDING, "forwarding %d\n", Ip0.dwForwarding);
    ok(Ip0.dwDefaultTTL == 128, "default hop limit %lu\n", Ip0.dwDefaultTTL);
    ok(Ip0.dwReasmTimeout == 60, "reassembly timeout %lu\n", Ip0.dwReasmTimeout);
    ok(Ip0.dwNumIf >= 1 && Ip0.dwNumAddr >= 1 && Ip0.dwNumRoutes >= 2, "interfaces %lu, addresses %lu, routes %lu\n",
       Ip0.dwNumIf, Ip0.dwNumAddr, Ip0.dwNumRoutes);

    /* a connection over ::1 and three echoes */
    Listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    memset(&Address, 0, sizeof(Address));
    Address.sin6_family = AF_INET6;
    Address.sin6_addr.u.Byte[15] = 1;
    ok(bind(Listener, (SOCKADDR *)&Address, sizeof(Address)) == 0, "bind: %d\n", WSAGetLastError());
    ok(listen(Listener, 4) == 0, "listen: %d\n", WSAGetLastError());
    getsockname(Listener, (SOCKADDR *)&Address, &Length);
    Client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(Client, (SOCKADDR *)&Address, sizeof(Address)) == 0, "connect: %d\n", WSAGetLastError());
    Server = accept(Listener, NULL, NULL);
    ok(send(Client, &Byte, 1, 0) == 1, "send: %d\n", WSAGetLastError());
    ok(recv(Server, &Byte, 1, 0) == 1, "recv: %d\n", WSAGetLastError());

    /* the connection is up: two established connections */
    Error = GetTcpStatisticsEx(&TcpUp, AF_INET6);
    ok(Error == NO_ERROR, "GetTcpStatisticsEx: %lu\n", Error);
    ok(TcpUp.dwCurrEstab >= Tcp0.dwCurrEstab + 2, "established %lu, was %lu\n", TcpUp.dwCurrEstab, Tcp0.dwCurrEstab);
    ok(TcpUp.dwNumConns >= Tcp0.dwNumConns + 3, "connections %lu, was %lu\n", TcpUp.dwNumConns, Tcp0.dwNumConns);

    Echoes = Icmp6CreateFile();
    if (Echoes != INVALID_HANDLE_VALUE)
    {
        Echo(Echoes, 3);
        IcmpCloseHandle(Echoes);
    }
    else
        skip("Icmp6CreateFile: %lu\n", GetLastError());

    closesocket(Server);
    closesocket(Client);
    closesocket(Listener);

    ok(GetIpStatisticsEx(&Ip1, AF_INET6) == NO_ERROR, "GetIpStatisticsEx\n");
    ok(GetTcpStatisticsEx(&Tcp1, AF_INET6) == NO_ERROR, "GetTcpStatisticsEx\n");
    ok(GetIcmpStatisticsEx(&Icmp1, AF_INET6) == NO_ERROR, "GetIcmpStatisticsEx\n");

    /* the SYN, its answer, the data and its acknowledgement are at least four segments each way over the loopback */
    ok(Tcp1.dwActiveOpens >= Tcp0.dwActiveOpens + 1, "active opens %lu, was %lu\n", Tcp1.dwActiveOpens, Tcp0.dwActiveOpens);
    ok(Tcp1.dwPassiveOpens >= Tcp0.dwPassiveOpens + 1, "passive opens %lu, was %lu\n", Tcp1.dwPassiveOpens,
       Tcp0.dwPassiveOpens);
    ok(Tcp1.dwInSegs >= Tcp0.dwInSegs + 4, "segments in %lu, was %lu\n", Tcp1.dwInSegs, Tcp0.dwInSegs);
    ok(Tcp1.dwOutSegs >= Tcp0.dwOutSegs + 4, "segments out %lu, was %lu\n", Tcp1.dwOutSegs, Tcp0.dwOutSegs);

    /* every datagram of those and of the echoes entered and left the IPv6 layer */
    ok(Ip1.dwInReceives >= Ip0.dwInReceives + 4, "datagrams in %lu, was %lu\n", Ip1.dwInReceives, Ip0.dwInReceives);
    ok(Ip1.dwInDelivers >= Ip0.dwInDelivers + 4, "datagrams delivered %lu, was %lu\n", Ip1.dwInDelivers, Ip0.dwInDelivers);
    ok(Ip1.dwOutRequests >= Ip0.dwOutRequests + 4, "datagrams out %lu, was %lu\n", Ip1.dwOutRequests, Ip0.dwOutRequests);

    if (Echoes != INVALID_HANDLE_VALUE)
    {
        /* echo request (128) and reply (129): each is sent and received over the loopback */
        ok(Icmp1.icmpOutStats.rgdwTypeCount[128] >= Icmp0.icmpOutStats.rgdwTypeCount[128] + 3, "echo requests out %lu, was %lu\n",
           Icmp1.icmpOutStats.rgdwTypeCount[128], Icmp0.icmpOutStats.rgdwTypeCount[128]);
        ok(Icmp1.icmpInStats.rgdwTypeCount[128] >= Icmp0.icmpInStats.rgdwTypeCount[128] + 3, "echo requests in %lu, was %lu\n",
           Icmp1.icmpInStats.rgdwTypeCount[128], Icmp0.icmpInStats.rgdwTypeCount[128]);
        ok(Icmp1.icmpOutStats.rgdwTypeCount[129] >= Icmp0.icmpOutStats.rgdwTypeCount[129] + 3, "echo replies out %lu, was %lu\n",
           Icmp1.icmpOutStats.rgdwTypeCount[129], Icmp0.icmpOutStats.rgdwTypeCount[129]);
        ok(Icmp1.icmpInStats.rgdwTypeCount[129] >= Icmp0.icmpInStats.rgdwTypeCount[129] + 3, "echo replies in %lu, was %lu\n",
           Icmp1.icmpInStats.rgdwTypeCount[129], Icmp0.icmpInStats.rgdwTypeCount[129]);
        ok(Icmp1.icmpInStats.dwMsgs >= Icmp0.icmpInStats.dwMsgs + 6, "messages in %lu, was %lu\n", Icmp1.icmpInStats.dwMsgs,
           Icmp0.icmpInStats.dwMsgs);
        ok(Icmp1.icmpOutStats.dwMsgs >= Icmp0.icmpOutStats.dwMsgs + 6, "messages out %lu, was %lu\n", Icmp1.icmpOutStats.dwMsgs,
           Icmp0.icmpOutStats.dwMsgs);
    }
}
