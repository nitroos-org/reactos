/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Icmp6SendEcho2: echoes to ::1 (synchronous, with an event, data echoed back, no options, the hop
 *              limit), a destination without a route, Icmp6ParseReplies. Without IPv6 Icmp6CreateFile fails and
 *              the test is skipped. Answers marked VERIFY ON ORACLE are this stack's.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

static const UCHAR Loopback6[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
/* RFC 3849 documentation prefix: no route to it in a test guest */
static const UCHAR Doc6[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 };

static void Init6(struct sockaddr_in6 *Sa, const UCHAR *Address)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    memcpy(&Sa->sin6_addr, Address, 16);
}

START_TEST(Icmp6Echo)
{
    HANDLE Icmp, Event;
    struct sockaddr_in6 Source, Dest;
    IP_OPTION_INFORMATION Options;
    char Data[32];
    UCHAR Reply[sizeof(ICMPV6_ECHO_REPLY) + sizeof(Data) + 8 + 64];
    PICMPV6_ECHO_REPLY R = (PICMPV6_ECHO_REPLY)Reply;
    DWORD Ret, i;

    SetLastError(0xdeadbeef);
    Icmp = Icmp6CreateFile();
    if (Icmp == INVALID_HANDLE_VALUE)
    {
        skip("no IPv6 (Icmp6CreateFile: %lu)\n", GetLastError());
        return;
    }

    memset(Data, 'p', sizeof(Data));
    Init6(&Source, (const UCHAR *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    Init6(&Dest, Loopback6);
    memset(&Options, 0, sizeof(Options));
    Options.Ttl = 64;

    /* ::1, synchronous */
    for (i = 0; i < 3; i++)
    {
        memset(Reply, 0xcc, sizeof(Reply));
        Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, &Dest, Data, sizeof(Data), &Options, Reply,
                             sizeof(Reply), 2000);
        ok(Ret == 1, "echo %lu to ::1: %lu (%lu)\n", i, Ret, GetLastError());
        ok(R->Status == IP_SUCCESS, "status %lu\n", R->Status);
        ok(!memcmp(R->Address.sin6_addr, Loopback6, 16), "reply address\n");
        ok(R->RoundTripTime < 2000, "round trip %u\n", R->RoundTripTime);
        ok(!memcmp(R + 1, Data, sizeof(Data)), "echoed data\n");
        ok(Icmp6ParseReplies(Reply, sizeof(Reply)) == 1, "Icmp6ParseReplies\n");
    }

    /* The reply buffer must hold the reply and the echoed data: IP_GENERAL_FAILURE otherwise, also in the reply
       (Windows 10, oracle) */
    memset(Reply, 0xcc, sizeof(Reply));
    SetLastError(0xdeadbeef);
    Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, &Dest, Data, sizeof(Data), &Options, Reply,
                         sizeof(ICMPV6_ECHO_REPLY) + 8, 2000);
    ok(Ret == 0 && GetLastError() == IP_GENERAL_FAILURE && R->Status == IP_GENERAL_FAILURE,
       "small reply buffer: %lu %lu %lu\n", Ret, GetLastError(), R->Status);
    memset(Reply, 0xcc, sizeof(Reply));
    Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, &Dest, Data, sizeof(Data), &Options, Reply,
                         sizeof(ICMPV6_ECHO_REPLY) + sizeof(Data), 2000);
    ok(Ret == 1 && R->Status == IP_SUCCESS && !memcmp(R + 1, Data, sizeof(Data)), "exact reply buffer: %lu %lu\n",
       Ret, R->Status);

    /* No options: the default hop limit */
    memset(Reply, 0xcc, sizeof(Reply));
    Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, &Dest, Data, 0, NULL, Reply, sizeof(Reply), 2000);
    ok(Ret == 1 && R->Status == IP_SUCCESS, "echo without data or options: %lu %lu\n", Ret, R->Status);

    /* With an event: pending, then the answer in the buffer */
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    memset(Reply, 0xcc, sizeof(Reply));
    Ret = Icmp6SendEcho2(Icmp, Event, NULL, NULL, &Source, &Dest, Data, sizeof(Data), &Options, Reply,
                         sizeof(Reply), 2000);
    ok(Ret == 0 && GetLastError() == ERROR_IO_PENDING, "echo with an event: %lu %lu\n", Ret, GetLastError());
    ok(WaitForSingleObject(Event, 5000) == WAIT_OBJECT_0, "the event was not set\n");
    ok(R->Status == IP_SUCCESS && !memcmp(R + 1, Data, sizeof(Data)), "event echo status %lu\n", R->Status);
    CloseHandle(Event);

    /* No route (VERIFY ON ORACLE: the status, here IP_DEST_NET_UNREACHABLE or a timeout) */
    Init6(&Dest, Doc6);
    memset(Reply, 0xcc, sizeof(Reply));
    SetLastError(0xdeadbeef);
    Ret = Icmp6SendEcho2(Icmp, NULL, NULL, NULL, &Source, &Dest, Data, sizeof(Data), &Options, Reply,
                         sizeof(Reply), 1000);
    ok(Ret == 0, "echo to 2001:db8::1 answered\n");
    trace("2001:db8::1: last error %lu, status %lu\n", GetLastError(), R->Status);

    IcmpCloseHandle(Icmp);
}
