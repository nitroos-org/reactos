/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     WSAStringToAddress returns the IPv4 address and the port in network order
 *              (the Wine test only uses palindromic addresses)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

static
void
Check(PCSTR Text, const BYTE *Address, USHORT Port, const char *Name)
{
    SOCKADDR_IN Sockaddr;
    WCHAR Wide[64];
    INT Length, Result;
    ULONG i;

    for (i = 0; Text[i]; i++)
        Wide[i] = Text[i];
    Wide[i] = 0;

    memset(&Sockaddr, 0xAA, sizeof(Sockaddr));
    Length = sizeof(Sockaddr);
    Result = WSAStringToAddressA((LPSTR)Text, AF_INET, NULL, (LPSOCKADDR)&Sockaddr, &Length);
    ok(Result == 0, "%s: WSAStringToAddressA: %d, error %d\n", Name, Result, WSAGetLastError());
    ok(Length == sizeof(Sockaddr), "%s: length %d\n", Name, Length);
    ok(Sockaddr.sin_family == AF_INET, "%s: family %d\n", Name, Sockaddr.sin_family);
    ok(memcmp(&Sockaddr.sin_addr, Address, 4) == 0, "%s: address bytes %02x.%02x.%02x.%02x\n", Name,
       ((BYTE *)&Sockaddr.sin_addr)[0], ((BYTE *)&Sockaddr.sin_addr)[1],
       ((BYTE *)&Sockaddr.sin_addr)[2], ((BYTE *)&Sockaddr.sin_addr)[3]);
    ok(Sockaddr.sin_port == htons(Port), "%s: port %04x\n", Name, Sockaddr.sin_port);

    /* Python's _overlapped hands this length on to ConnectEx: it must be the size of the address */
    memset(&Sockaddr, 0xAA, sizeof(Sockaddr));
    Length = sizeof(Sockaddr) + 12;
    Result = WSAStringToAddressW(Wide, AF_INET, NULL, (LPSOCKADDR)&Sockaddr, &Length);
    ok(Result == 0, "%s: WSAStringToAddressW: %d, error %d\n", Name, Result, WSAGetLastError());
    ok(Length == sizeof(Sockaddr), "%s: length %d with a larger buffer\n", Name, Length);
    ok(memcmp(&Sockaddr.sin_addr, Address, 4) == 0, "%s: address bytes (W)\n", Name);
    ok(Sockaddr.sin_port == htons(Port), "%s: port %04x (W)\n", Name, Sockaddr.sin_port);
}

START_TEST(stringtoaddress)
{
    WSADATA WsaData;
    static const BYTE Loopback[4] = { 127, 0, 0, 1 };
    static const BYTE Other[4] = { 10, 1, 2, 3 };
    static const BYTE High[4] = { 192, 168, 77, 254 };

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }

    Check("127.0.0.1", Loopback, 0, "loopback");
    Check("10.1.2.3:8080", Other, 8080, "with a port");
    Check("192.168.77.254:1", High, 1, "high bytes");

    WSACleanup();
}
