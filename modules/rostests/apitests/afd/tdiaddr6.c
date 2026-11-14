/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later
 * PURPOSE:     The address conversions between Winsock socket addresses and TDI transport addresses of
 *              <tdiaddr.h> (IPv6 and the IPv4 mapped ones): a round trip, and every length that does not fit.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ws2ipdef.h>
#include <tdiaddr.h>

/* The private layout is the real one */
C_ASSERT(FIELD_OFFSET(SOCKADDR_IN6_LH, sin6_port) == FIELD_OFFSET(TDIADDR_SOCKADDR6, Port));
C_ASSERT(FIELD_OFFSET(SOCKADDR_IN6_LH, sin6_flowinfo) == FIELD_OFFSET(TDIADDR_SOCKADDR6, FlowInfo));
C_ASSERT(FIELD_OFFSET(SOCKADDR_IN6_LH, sin6_addr) == FIELD_OFFSET(TDIADDR_SOCKADDR6, Address));
C_ASSERT(FIELD_OFFSET(SOCKADDR_IN6_LH, sin6_scope_id) == FIELD_OFFSET(TDIADDR_SOCKADDR6, ScopeId));
C_ASSERT(sizeof(SOCKADDR_IN6_LH) == TDIADDR_SOCKADDR_IN6_LENGTH);
C_ASSERT(sizeof(SOCKADDR_IN) == TDIADDR_SOCKADDR_IN_LENGTH);

static const UCHAR Addr6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

static void MakeSockaddr6(SOCKADDR_IN6_LH *Sa)
{
    memset(Sa, 0, sizeof(*Sa));
    Sa->sin6_family = AF_INET6;
    Sa->sin6_port = htons(0x1234);
    Sa->sin6_flowinfo = 0x04030201;
    memcpy(&Sa->sin6_addr, Addr6, 16);
    Sa->sin6_scope_id = 7;
}

static void TestRoundTrip(void)
{
    SOCKADDR_IN6_LH Sa, Back;
    UCHAR Buffer[1 + TDIADDR_TA_LENGTH_IP6 + 8];
    PUCHAR Ta = Buffer + 1; /* not aligned on purpose */
    PTA_IP6_ADDRESS Ip6 = (PTA_IP6_ADDRESS)Ta;
    TDIADDR_SOCKADDR6 Out;
    ULONG Length;

    MakeSockaddr6(&Sa);
    memset(Buffer, 0xcc, sizeof(Buffer));
    Length = TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), Ta, TDIADDR_TA_LENGTH_IP6);
    ok(Length == TDIADDR_TA_LENGTH_IP6, "length %lu\n", Length);
    ok(Length == sizeof(TA_IP6_ADDRESS), "TA_IP6_ADDRESS is %u bytes\n", (UINT)sizeof(TA_IP6_ADDRESS));
    ok(Ip6->TAAddressCount == 1, "count %ld\n", Ip6->TAAddressCount);
    ok(Ip6->Address[0].AddressLength == TDI_ADDRESS_LENGTH_IP6, "address length %u\n", Ip6->Address[0].AddressLength);
    ok(Ip6->Address[0].AddressType == TDI_ADDRESS_TYPE_IP6, "address type %u\n", Ip6->Address[0].AddressType);
    ok(Ip6->Address[0].Address[0].sin6_port == htons(0x1234), "port %x\n", Ip6->Address[0].Address[0].sin6_port);
    ok(Ip6->Address[0].Address[0].sin6_flowinfo == 0x04030201, "flow %lx\n", Ip6->Address[0].Address[0].sin6_flowinfo);
    ok(!memcmp(Ip6->Address[0].Address[0].sin6_addr, Addr6, 16), "address\n");
    ok(Ip6->Address[0].Address[0].sin6_scope_id == 7, "scope %lu\n", Ip6->Address[0].Address[0].sin6_scope_id);
    ok(Buffer[0] == 0xcc && Buffer[1 + TDIADDR_TA_LENGTH_IP6] == 0xcc, "wrote outside the address\n");

    memset(&Out, 0xcc, sizeof(Out));
    ok(TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "TA to sockaddr failed\n");
    ok(!memcmp(&Out, &Sa, sizeof(Sa)), "round trip differs\n");

    /* The same through the general conversion, from the body of the address */
    memset(&Back, 0xcc, sizeof(Back));
    Length = TdiAddrToSockaddr(AF_INET6, TDI_ADDRESS_TYPE_IP6, TDI_ADDRESS_LENGTH_IP6,
                               (const UCHAR *)Ip6->Address[0].Address, &Back, sizeof(Back));
    ok(Length == sizeof(Back), "general conversion %lu\n", Length);
    ok(!memcmp(&Back, &Sa, sizeof(Sa)), "general conversion differs\n");

    /* A longer socket address is fine, only the SOCKADDR_IN6 is taken */
    memset(Buffer, 0xcc, sizeof(Buffer));
    Length = TdiAddrSockaddr6ToTa(&Sa, 100, Ta, TDIADDR_TA_LENGTH_IP6 + 8);
    ok(Length == TDIADDR_TA_LENGTH_IP6, "long socket address: %lu\n", Length);
}

static void TestBadLengths(void)
{
    SOCKADDR_IN6_LH Sa;
    UCHAR Ta[TDIADDR_TA_LENGTH_IP6 + 4], Guard[TDIADDR_TA_LENGTH_IP6 + 4];
    TDIADDR_SOCKADDR6 Out;
    ULONG Length;
    PTA_IP6_ADDRESS Ip6 = (PTA_IP6_ADDRESS)Ta;

    MakeSockaddr6(&Sa);
    memset(Guard, 0xcc, sizeof(Guard));

    /* Socket address too short (the scope id is part of a SOCKADDR_IN6) */
    memset(Ta, 0xcc, sizeof(Ta));
    ok(TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa) - 1, Ta, sizeof(Ta)) == 0, "27 byte socket address taken\n");
    ok(TdiAddrSockaddr6ToTa(&Sa, 24, Ta, sizeof(Ta)) == 0, "24 byte socket address taken\n");
    ok(TdiAddrSockaddr6ToTa(&Sa, 0, Ta, sizeof(Ta)) == 0, "empty socket address taken\n");
    /* Too little room */
    ok(TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), Ta, TDIADDR_TA_LENGTH_IP6 - 1) == 0, "33 bytes of room taken\n");
    ok(TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), Ta, 0) == 0, "no room taken\n");
    /* The wrong family */
    Sa.sin6_family = AF_INET;
    ok(TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), Ta, sizeof(Ta)) == 0, "AF_INET socket address taken as IPv6\n");
    Sa.sin6_family = 0;
    ok(TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), Ta, sizeof(Ta)) == 0, "AF_UNSPEC socket address taken as IPv6\n");
    ok(!memcmp(Ta, Guard, sizeof(Ta)), "a refused address wrote into the buffer\n");

    /* The way back: a complete address of exactly one IPv6 entry */
    MakeSockaddr6(&Sa);
    Length = TdiAddrSockaddr6ToTa(&Sa, sizeof(Sa), Ta, sizeof(Ta));
    ok(Length == TDIADDR_TA_LENGTH_IP6, "length %lu\n", Length);
    memset(&Out, 0xcc, sizeof(Out));
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6 - 1, &Out), "33 byte address taken\n");
    ok(!TdiAddrTaToSockaddr6(Ta, 0, &Out), "empty address taken\n");
    ok(!TdiAddrTaToSockaddr6(Ta, 7, &Out), "7 byte address taken\n");

    Ip6->TAAddressCount = 0;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "no address in the list taken\n");
    Ip6->TAAddressCount = 2;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "two addresses taken\n");
    Ip6->TAAddressCount = 1;

    Ip6->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6 - 1;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "a 25 byte body taken\n");
    Ip6->Address[0].AddressLength = 0;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "an empty body taken\n");
    Ip6->Address[0].AddressLength = 0xffff;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "a body longer than the buffer taken\n");
    Ip6->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6 + 1;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "a body one byte longer than the buffer taken\n");
    Ip6->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6 + 1;
    ok(TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6 + 1, &Out), "a body of 27 bytes in a buffer of 35 refused\n");
    Ip6->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP6;

    Ip6->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    ok(!TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "an IPv4 address taken as IPv6\n");
    Ip6->Address[0].AddressType = TDI_ADDRESS_TYPE_IP6;
    ok(TdiAddrTaToSockaddr6(Ta, TDIADDR_TA_LENGTH_IP6, &Out), "the good address refused after the others\n");
}

static void TestConversions(void)
{
    UCHAR Body4[TDIADDR_BODY_LENGTH_IP];
    UCHAR Body6[TDIADDR_BODY_LENGTH_IP6] = { 0 };
    UCHAR Out[40];
    PUCHAR Sock = Out;
    SOCKADDR_IN *In4 = (SOCKADDR_IN *)Out;
    SOCKADDR_IN6_LH *In6 = (SOCKADDR_IN6_LH *)Out;
    ULONG Length;

    /* A TDI IPv4 address body: port, address, padding */
    memset(Body4, 0, sizeof(Body4));
    Body4[0] = 0x50; Body4[1] = 0x00;
    Body4[2] = 1; Body4[3] = 2; Body4[4] = 3; Body4[5] = 4;

    /* IPv4 on an IPv4 socket: sockaddr_in as it always was */
    memset(Out, 0xcc, sizeof(Out));
    Length = TdiAddrToSockaddr(AF_INET, TDI_ADDRESS_TYPE_IP, sizeof(Body4), Body4, Out, 16);
    ok(Length == 16, "IPv4: %lu\n", Length);
    ok(In4->sin_family == AF_INET && In4->sin_port == 0x0050 && In4->sin_addr.s_addr == 0x04030201, "IPv4 fields\n");
    ok(Out[16] == 0xcc, "IPv4 wrote past 16 bytes\n");
    memset(Out, 0xcc, sizeof(Out));
    ok(TdiAddrToSockaddr(AF_INET, TDI_ADDRESS_TYPE_IP, sizeof(Body4) - 1, Body4, Out, 16) == 0, "short IPv4 body taken\n");
    ok(TdiAddrToSockaddr(AF_INET, TDI_ADDRESS_TYPE_IP, sizeof(Body4), Body4, Out, 15) == 0, "IPv4 in 15 bytes taken\n");
    ok(TdiAddrToSockaddr(AF_INET, TDI_ADDRESS_TYPE_IP6, TDI_ADDRESS_LENGTH_IP6, Body6, Out, 40) == 0, "IPv6 address on an IPv4 socket taken\n");
    ok(Out[0] == 0xcc, "a refused conversion wrote\n");

    /* IPv4 on an IPv6 socket: ::ffff:1.2.3.4 */
    memset(Out, 0xcc, sizeof(Out));
    Length = TdiAddrToSockaddr(AF_INET6, TDI_ADDRESS_TYPE_IP, sizeof(Body4), Body4, Out, 28);
    ok(Length == 28, "mapped: %lu\n", Length);
    ok(In6->sin6_family == AF_INET6 && In6->sin6_port == 0x0050 && In6->sin6_flowinfo == 0 && In6->sin6_scope_id == 0,
       "mapped fields\n");
    ok(TdiAddrIsV4Mapped((const UCHAR *)&In6->sin6_addr), "not mapped\n");
    ok(((UCHAR *)&In6->sin6_addr)[12] == 1 && ((UCHAR *)&In6->sin6_addr)[15] == 4, "mapped address\n");
    ok(Out[28] == 0xcc, "mapped wrote past 28 bytes\n");
    memset(Out, 0xcc, sizeof(Out));
    ok(TdiAddrToSockaddr(AF_INET6, TDI_ADDRESS_TYPE_IP, sizeof(Body4), Body4, Out, 27) == 0, "mapped in 27 bytes taken\n");
    ok(TdiAddrToSockaddr(AF_INET6, TDI_ADDRESS_TYPE_IP, 5, Body4, Out, 28) == 0, "5 byte IPv4 body taken\n");
    ok(Out[0] == 0xcc, "a refused mapped conversion wrote\n");

    /* IPv6 on an IPv6 socket */
    memset(Body6, 0, sizeof(Body6));
    Body6[0] = 0x12; Body6[1] = 0x34;
    memset(Out, 0xcc, sizeof(Out));
    ok(TdiAddrToSockaddr(AF_INET6, TDI_ADDRESS_TYPE_IP6, sizeof(Body6) - 1, Body6, Out, 28) == 0, "25 byte IPv6 body taken\n");
    ok(TdiAddrToSockaddr(AF_INET6, TDI_ADDRESS_TYPE_IP6, sizeof(Body6), Body6, Out, 27) == 0, "IPv6 in 27 bytes taken\n");
    ok(Out[0] == 0xcc, "a refused IPv6 conversion wrote\n");

    /* Nothing else converts */
    ok(TdiAddrToSockaddr(AF_UNSPEC, TDI_ADDRESS_TYPE_IP, sizeof(Body4), Body4, Out, 40) == 0, "unspecified family taken\n");
    ok(TdiAddrToSockaddr(AF_INET, TDI_ADDRESS_TYPE_NETBIOS, 20, Body6, Out, 40) == 0, "NetBIOS taken\n");
    (void)Sock;
}

static void TestMapped(void)
{
    UCHAR A[16];

    memset(A, 0, sizeof(A));
    ok(!TdiAddrIsV4Mapped(A), "::\n");
    A[10] = A[11] = 0xff;
    ok(TdiAddrIsV4Mapped(A), "::ffff:0.0.0.0\n");
    A[15] = 1;
    ok(TdiAddrIsV4Mapped(A), "::ffff:0.0.0.1\n");
    A[9] = 1;
    ok(!TdiAddrIsV4Mapped(A), "0:0:0:0:1:ffff:0:1\n");
    A[9] = 0; A[11] = 0xfe;
    ok(!TdiAddrIsV4Mapped(A), "::ffff:feff:...\n");
    memcpy(A, Addr6, 16);
    ok(!TdiAddrIsV4Mapped(A), "2001:db8::1\n");
}

START_TEST(tdiaddr6)
{
    TestRoundTrip();
    TestBadLengths();
    TestConversions();
    TestMapped();
}
