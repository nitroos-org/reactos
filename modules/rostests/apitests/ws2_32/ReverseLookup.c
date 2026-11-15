/*
 * PROJECT:     ws2_32.dll API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Reverse lookups of addresses that are not the machine's own go to DNS (PTR records):
 *              getnameinfo, GetNameInfoW and gethostbyaddr. Needs a working name server; skipped without one.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <winnls.h>

/* Google Public DNS has had the PTR record 8.8.8.8 -> dns.google for years */
#define KNOWN_IP    "8.8.8.8"
#define KNOWN_NAME  "dns.google"
/* TEST-NET-1 (RFC 5737) never has a PTR record */
#define NOPTR_IP    "192.0.2.77"

static void test_getnameinfo(const char *Ip, int Flags, int ExpectedError, const char *Expected)
{
    SOCKADDR_IN Sin;
    CHAR Host[NI_MAXHOST] = "";
    WCHAR HostW[NI_MAXHOST] = L"";
    WCHAR ExpectedW[NI_MAXHOST];
    int Error;

    ZeroMemory(&Sin, sizeof(Sin));
    Sin.sin_family = AF_INET;
    Sin.sin_addr.S_un.S_addr = inet_addr(Ip);

    Error = getnameinfo((PSOCKADDR)&Sin, sizeof(Sin), Host, sizeof(Host), NULL, 0, Flags);
    ok(Error == ExpectedError, "getnameinfo(%s, 0x%x) returned %d, expected %d\n", Ip, Flags, Error, ExpectedError);
    if (Error == 0 && Expected)
        ok(!lstrcmpiA(Host, Expected), "getnameinfo(%s, 0x%x) named '%s', expected '%s'\n", Ip, Flags, Host, Expected);

    Error = GetNameInfoW((PSOCKADDR)&Sin, sizeof(Sin), HostW, RTL_NUMBER_OF(HostW), NULL, 0, Flags);
    ok(Error == ExpectedError, "GetNameInfoW(%s, 0x%x) returned %d, expected %d\n", Ip, Flags, Error, ExpectedError);
    if (Error == 0 && Expected)
    {
        MultiByteToWideChar(CP_ACP, 0, Expected, -1, ExpectedW, RTL_NUMBER_OF(ExpectedW));
        ok(!lstrcmpiW(HostW, ExpectedW), "GetNameInfoW(%s, 0x%x) named '%ls', expected '%ls'\n", Ip, Flags, HostW, ExpectedW);
    }
}

START_TEST(ReverseLookup)
{
    WSADATA WsaData;
    struct hostent *Host;
    struct in_addr Addr;
    int Error;

    Error = WSAStartup(MAKEWORD(2, 2), &WsaData);
    ok_dec(Error, 0);

    /* an address shorter than its family needs is not read: WSAEFAULT (no name server needed) */
    {
        static const BYTE Short[16] = { 0x20, 0x01, 0x0d, 0xb8 };

        WSASetLastError(0xdeadbeef);
        Host = gethostbyaddr((const char *)Short, 4, AF_INET6);
        ok(Host == NULL, "gethostbyaddr(AF_INET6, len 4) returned '%s'\n", Host ? Host->h_name : "");
        ok_dec(WSAGetLastError(), WSAEFAULT);
        WSASetLastError(0xdeadbeef);
        Host = gethostbyaddr((const char *)Short, 2, AF_INET);
        ok(Host == NULL, "gethostbyaddr(AF_INET, len 2) returned '%s'\n", Host ? Host->h_name : "");
        ok_dec(WSAGetLastError(), WSAEFAULT);
    }

    /* no name server, no test */
    Host = gethostbyname(KNOWN_NAME);
    if (!Host)
    {
        skip("Cannot resolve %s (no network or no DNS), skipping the reverse lookup tests\n", KNOWN_NAME);
        WSACleanup();
        return;
    }

    /* an address with a PTR record, by name, with the same result with and without NI_NAMEREQD */
    test_getnameinfo(KNOWN_IP, 0, 0, KNOWN_NAME);
    test_getnameinfo(KNOWN_IP, NI_NAMEREQD, 0, KNOWN_NAME);
    test_getnameinfo(KNOWN_IP, NI_NUMERICHOST, 0, KNOWN_IP);
    test_getnameinfo(KNOWN_IP, NI_NUMERICHOST | NI_NAMEREQD, 0, KNOWN_IP);
    test_getnameinfo(KNOWN_IP, NI_NOFQDN, 0, "dns");

    Addr.S_un.S_addr = inet_addr(KNOWN_IP);
    Host = gethostbyaddr((const char *)&Addr, sizeof(Addr), AF_INET);
    ok(Host != NULL, "gethostbyaddr(%s) failed: %d\n", KNOWN_IP, WSAGetLastError());
    if (Host)
    {
        ok(Host->h_name && !lstrcmpiA(Host->h_name, KNOWN_NAME), "gethostbyaddr(%s) named '%s'\n", KNOWN_IP, Host->h_name);
        ok(Host->h_addrtype == AF_INET, "h_addrtype %d\n", Host->h_addrtype);
        ok(Host->h_length == sizeof(Addr), "h_length %d\n", Host->h_length);
        ok(Host->h_addr_list && Host->h_addr_list[0] &&
           ((PIN_ADDR)Host->h_addr_list[0])->S_un.S_addr == Addr.S_un.S_addr, "h_addr_list does not hold the address\n");
    }

    /* an address without a PTR record: numeric, unless the name is required */
    test_getnameinfo(NOPTR_IP, 0, 0, NOPTR_IP);
    test_getnameinfo(NOPTR_IP, NI_NAMEREQD, WSAHOST_NOT_FOUND, NULL);
    Addr.S_un.S_addr = inet_addr(NOPTR_IP);
    Host = gethostbyaddr((const char *)&Addr, sizeof(Addr), AF_INET);
    ok(Host == NULL, "gethostbyaddr(%s) returned '%s'\n", NOPTR_IP, Host ? Host->h_name : "");
    Error = WSAGetLastError();
    ok(Error == WSANO_DATA || Error == WSAHOST_NOT_FOUND, "gethostbyaddr(%s) failed with %d\n", NOPTR_IP, Error);

    WSACleanup();
}
