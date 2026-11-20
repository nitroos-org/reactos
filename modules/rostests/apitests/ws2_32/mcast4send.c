/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     Sending to an IPv4 multicast group: IP_MULTICAST_TTL, IP_MULTICAST_LOOP and IP_MULTICAST_IF (defaults,
 *              values, errors), the local copy of a group's datagram and the neighbour entry of the group
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected answers are those of Windows Server 2022 (peer probe, 64 bit). Windows applies IP_MULTICAST_LOOP to
 * the receiving socket: a sender with the option off still reaches a joined socket of this computer, a receiver
 * with it off gets nothing that this computer sent. What reaches the wire (the group's Ethernet address, the TTL)
 * is checked from a capture of the link, not here. Groups are administratively scoped.
 */

#include "ws2_32.h"
#include <iphlpapi.h>
#include <stdlib.h>

static ULONG If4;
static IN_ADDR IfAddr4;

static BOOL
find_interface(void)
{
    ULONG size = 0;
    IP_ADAPTER_ADDRESSES *aa, *a;

    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &size);
    aa = malloc(size);
    if (!aa || GetAdaptersAddresses(AF_INET, 0, NULL, aa, &size))
    {
        free(aa);
        return FALSE;
    }
    for (a = aa; a && !If4; a = a->Next)
    {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->OperStatus != IfOperStatusUp || !a->FirstUnicastAddress)
            continue;
        If4 = a->IfIndex;
        IfAddr4 = ((SOCKADDR_IN *)a->FirstUnicastAddress->Address.lpSockaddr)->sin_addr;
    }
    free(aa);
    return If4 != 0;
}

static void
get_long(SOCKET s, int name, int expect_rc, int expect_err, int expect_len, LONG expect_value, int line)
{
    char buf[8];
    int len = sizeof(buf), rc;

    memset(buf, 0xAA, sizeof(buf));
    rc = getsockopt(s, IPPROTO_IP, name, buf, &len);
    ok_(__FILE__, line)(rc == expect_rc, "getsockopt %d: rc %d, expected %d\n", name, rc, expect_rc);
    if (rc)
    {
        ok_(__FILE__, line)(WSAGetLastError() == expect_err, "getsockopt %d: error %d, expected %d\n", name,
                            WSAGetLastError(), expect_err);
        return;
    }
    ok_(__FILE__, line)(len == expect_len, "getsockopt %d: length %d, expected %d\n", name, len, expect_len);
    ok_(__FILE__, line)(*(LONG *)buf == expect_value, "getsockopt %d: value %ld, expected %ld\n", name,
                        *(LONG *)buf, expect_value);
}

static void
set_long(SOCKET s, int name, LONG value, int length, int expect_err, int line)
{
    int rc = setsockopt(s, IPPROTO_IP, name, (char *)&value, length);

    if (expect_err)
        ok_(__FILE__, line)(rc == SOCKET_ERROR && WSAGetLastError() == expect_err,
                            "setsockopt %d = %ld (%d bytes): rc %d error %d, expected error %d\n", name, value, length,
                            rc, WSAGetLastError(), expect_err);
    else
        ok_(__FILE__, line)(rc == 0, "setsockopt %d = %ld (%d bytes): rc %d error %d\n", name, value, length, rc,
                            WSAGetLastError());
}

#define GET(s, n, rc, err, len, v) get_long(s, n, rc, err, len, v, __LINE__)
#define SET(s, n, v, len, err) set_long(s, n, v, len, err, __LINE__)

static void
option_rows(void)
{
    SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), t = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKET u6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    LONG bad = (LONG)inet_addr("192.0.2.77");

    ok(u != INVALID_SOCKET && t != INVALID_SOCKET, "sockets: %d\n", WSAGetLastError());

    /* defaults */
    GET(u, IP_MULTICAST_TTL, 0, 0, 4, 1);
    GET(u, IP_MULTICAST_LOOP, 0, 0, 4, 1);
    GET(u, IP_MULTICAST_IF, 0, 0, 4, 0);

    /* TTL: 0 to 255; 256 fails and changes nothing; -1 changes nothing; one byte is taken */
    SET(u, IP_MULTICAST_TTL, 0, 4, 0);      GET(u, IP_MULTICAST_TTL, 0, 0, 4, 0);
    SET(u, IP_MULTICAST_TTL, 255, 4, 0);    GET(u, IP_MULTICAST_TTL, 0, 0, 4, 255);
    SET(u, IP_MULTICAST_TTL, 256, 4, WSAEINVAL); GET(u, IP_MULTICAST_TTL, 0, 0, 4, 255);
    SET(u, IP_MULTICAST_TTL, -1, 4, 0);     GET(u, IP_MULTICAST_TTL, 0, 0, 4, 255);
    SET(u, IP_MULTICAST_TTL, 7, 1, 0);      GET(u, IP_MULTICAST_TTL, 0, 0, 4, 7);

    /* LOOP: a switch */
    SET(u, IP_MULTICAST_LOOP, 0, 4, 0);     GET(u, IP_MULTICAST_LOOP, 0, 0, 4, 0);
    SET(u, IP_MULTICAST_LOOP, 2, 4, 0);     GET(u, IP_MULTICAST_LOOP, 0, 0, 4, 1);

    /* IF: an address of this computer or an index as 0.0.0.x, read back as set */
    SET(u, IP_MULTICAST_IF, (LONG)IfAddr4.s_addr, 4, 0);     GET(u, IP_MULTICAST_IF, 0, 0, 4, (LONG)IfAddr4.s_addr);
    SET(u, IP_MULTICAST_IF, (LONG)htonl(If4), 4, 0);          GET(u, IP_MULTICAST_IF, 0, 0, 4, (LONG)htonl(If4));
    SET(u, IP_MULTICAST_IF, bad, 4, WSAEADDRNOTAVAIL);       GET(u, IP_MULTICAST_IF, 0, 0, 4, (LONG)htonl(If4));
    SET(u, IP_MULTICAST_IF, (LONG)htonl(250), 4, WSAEINVAL);  GET(u, IP_MULTICAST_IF, 0, 0, 4, (LONG)htonl(If4));
    SET(u, IP_MULTICAST_IF, 0, 4, 0);                         GET(u, IP_MULTICAST_IF, 0, 0, 4, 0);
    SET(u, IP_MULTICAST_IF, (LONG)IfAddr4.s_addr, 2, WSAEFAULT);

    /* a stream socket has none of them; an IPv6 socket reads the TTL but cannot set it */
    GET(t, IP_MULTICAST_TTL, SOCKET_ERROR, WSAEINVAL, 0, 0);
    SET(t, IP_MULTICAST_TTL, 5, 4, WSAEINVAL);
    SET(t, IP_MULTICAST_IF, (LONG)IfAddr4.s_addr, 4, WSAEINVAL);
    if (u6 != INVALID_SOCKET)
    {
        GET(u6, IP_MULTICAST_TTL, 0, 0, 4, 1);
        SET(u6, IP_MULTICAST_TTL, 5, 4, WSAEINVAL);
        closesocket(u6);
    }
    closesocket(u);
    closesocket(t);
}

/* One datagram (its text is its tag) from s to group:port; whether r gets it within 700 ms */
static BOOL
send_one(SOCKET s, SOCKET r, const char *group, USHORT port, const char *tag)
{
    SOCKADDR_IN g;
    char buf[64];
    fd_set fs;
    struct timeval tv = { 0, 700000 };
    int n;
    BOOL got = FALSE;

    memset(&g, 0, sizeof(g));
    g.sin_family = AF_INET;
    g.sin_port = htons(port);
    g.sin_addr.s_addr = inet_addr(group);
    n = sendto(s, tag, (int)strlen(tag), 0, (SOCKADDR *)&g, sizeof(g));
    ok(n == (int)strlen(tag), "%s: sendto %d error %d\n", tag, n, WSAGetLastError());
    for (;;)
    {
        FD_ZERO(&fs);
        FD_SET(r, &fs);
        if (select(0, &fs, NULL, NULL, &tv) <= 0)
            break;
        n = recv(r, buf, sizeof(buf) - 1, 0);
        if (n <= 0)
            break;
        buf[n] = 0;
        if (!strcmp(buf, tag))
            got = TRUE;
    }
    return got;
}

static void
loop_rows(void)
{
    const char *group = "239.77.4.1";
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), r = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKADDR_IN b;
    struct ip_mreq m;
    LONG v;
    BOOL on = TRUE;

    setsockopt(r, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    memset(&b, 0, sizeof(b));
    b.sin_family = AF_INET;
    b.sin_port = htons(5598);
    ok(bind(r, (SOCKADDR *)&b, sizeof(b)) == 0, "bind %d\n", WSAGetLastError());
    m.imr_multiaddr.s_addr = inet_addr(group);
    m.imr_interface = IfAddr4;
    ok(setsockopt(r, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&m, sizeof(m)) == 0, "join %d\n", WSAGetLastError());

    ok(send_one(s, r, group, 5598, "default"), "default: the joined socket did not get the local copy\n");
    v = 0; setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&v, sizeof(v));
    ok(send_one(s, r, group, 5598, "ttl0"), "TTL 0: the joined socket did not get the local copy\n");
    v = 1; setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&v, sizeof(v));
    v = 0; setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&v, sizeof(v));
    ok(send_one(s, r, group, 5598, "sender-loop0"), "sender loop off: the joined socket did not get it (Windows: it does)\n");
    v = (LONG)IfAddr4.s_addr; setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (char *)&v, sizeof(v));
    ok(send_one(s, r, group, 5598, "if-addr"), "IP_MULTICAST_IF address: no local copy\n");
    v = 0; setsockopt(r, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&v, sizeof(v));
    ok(!send_one(s, r, group, 5598, "receiver-loop0"), "receiver loop off: it got this computer's datagram\n");

    closesocket(s);
    closesocket(r);
}

/* After a datagram to a group, the neighbour table holds the group with its Ethernet address as a static entry */
static void
neighbour_rows(void)
{
    const char *group = "239.77.4.2";
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKADDR_IN g;
    PMIB_IPNETTABLE table = NULL;
    ULONG size = 0, i;
    DWORD addr = inet_addr(group);
    BOOL found = FALSE;

    memset(&g, 0, sizeof(g));
    g.sin_family = AF_INET;
    g.sin_port = htons(5597);
    g.sin_addr.s_addr = addr;
    ok(sendto(s, "x", 1, 0, (SOCKADDR *)&g, sizeof(g)) == 1, "sendto %d\n", WSAGetLastError());
    closesocket(s);
    Sleep(200);

    GetIpNetTable(NULL, &size, FALSE);
    table = malloc(size + 1024);
    size += 1024;
    ok(table && GetIpNetTable(table, &size, FALSE) == NO_ERROR, "GetIpNetTable failed\n");
    for (i = 0; table && i < table->dwNumEntries; i++)
    {
        MIB_IPNETROW *row = &table->table[i];

        if (row->dwAddr != addr)
            continue;
        found = TRUE;
        ok(row->dwIndex == If4, "group entry on interface %lu, expected %lu\n", row->dwIndex, If4);
        ok(row->dwPhysAddrLen == 6 && row->bPhysAddr[0] == 0x01 && row->bPhysAddr[1] == 0x00 &&
           row->bPhysAddr[2] == 0x5e && row->bPhysAddr[3] == 0x4d && row->bPhysAddr[4] == 0x04 &&
           row->bPhysAddr[5] == 0x02, "group entry: link address %02x-%02x-%02x-%02x-%02x-%02x\n",
           row->bPhysAddr[0], row->bPhysAddr[1], row->bPhysAddr[2], row->bPhysAddr[3], row->bPhysAddr[4],
           row->bPhysAddr[5]);
        ok(row->dwType == MIB_IPNET_TYPE_STATIC, "group entry type %lu, expected static\n", row->dwType);
    }
    ok(found, "no neighbour entry for %s after a datagram to it\n", group);
    free(table);
}

START_TEST(mcast4send)
{
    WSADATA wd;

    ok(WSAStartup(MAKEWORD(2, 2), &wd) == 0, "WSAStartup\n");
    if (!find_interface())
    {
        skip("no IPv4 interface with an address\n");
        WSACleanup();
        return;
    }
    trace("interface %lu address %s\n", If4, inet_ntoa(IfAddr4));
    option_rows();
    loop_rows();
    neighbour_rows();
    WSACleanup();
}
