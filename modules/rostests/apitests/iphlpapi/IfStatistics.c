/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the packet counters of GetIfEntry / GetIfTable: they agree with the byte counters
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

/* An interface that moved bytes moved packets: Windows counts a frame in the unicast or in the non-unicast
 * counter. Without this .NET GetIPStatistics read 126 MB received in 0 packets. */
static void CheckRow(const MIB_IFROW *Row, const char *Source)
{
    ok(Row->dwInOctets == 0 || Row->dwInUcastPkts + Row->dwInNUcastPkts != 0,
       "%s, interface %lu: %lu bytes received in 0 packets\n", Source, Row->dwIndex, Row->dwInOctets);
    ok(Row->dwOutOctets == 0 || Row->dwOutUcastPkts + Row->dwOutNUcastPkts != 0,
       "%s, interface %lu: %lu bytes sent in 0 packets\n", Source, Row->dwIndex, Row->dwOutOctets);
}

static void TestTable(void)
{
    MIB_IFTABLE *Table;
    ULONG Size = 0, i;
    BOOL Moved = FALSE;
    DWORD Error;

    GetIfTable(NULL, &Size, FALSE);
    Table = malloc(Size);
    Error = Table ? GetIfTable(Table, &Size, FALSE) : ERROR_OUTOFMEMORY;
    ok(Error == NO_ERROR, "GetIfTable: %lu\n", Error);
    if (Error != NO_ERROR)
    {
        free(Table);
        return;
    }

    for (i = 0; i < Table->dwNumEntries; i++)
    {
        MIB_IFROW Row;

        CheckRow(&Table->table[i], "GetIfTable");
        if (Table->table[i].dwType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        memset(&Row, 0, sizeof(Row));
        Row.dwIndex = Table->table[i].dwIndex;
        Error = GetIfEntry(&Row);
        ok(Error == NO_ERROR, "GetIfEntry(%lu): %lu\n", Row.dwIndex, Error);
        if (Error == NO_ERROR)
            CheckRow(&Row, "GetIfEntry");
        Moved |= Table->table[i].dwInOctets != 0 || Table->table[i].dwOutOctets != 0;
    }
    if (!Moved)
        skip("No interface carried traffic yet\n");
    free(Table);
}

/* A datagram to the default gateway is sent as one unicast frame (after the ARP exchange, which has
 * broadcast frames): the unicast counter of the interface goes up */
static void TestSend(void)
{
    IP_ADAPTER_INFO *Info = NULL, *I;
    ULONG Size = 0, Gateway = 0, Index = 0, Tries;
    MIB_IFROW Before, After;
    SOCKET Socket;
    SOCKADDR_IN To;
    BOOL Seen = FALSE;
    char Data[16] = "iphlpapi-test";

    if (GetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW || !(Info = malloc(Size)) ||
        GetAdaptersInfo(Info, &Size) != NO_ERROR)
    {
        free(Info);
        skip("No adapter\n");
        return;
    }
    for (I = Info; I && !Gateway; I = I->Next)
    {
        ULONG Address = inet_addr(I->GatewayList.IpAddress.String);

        if (Address != 0 && Address != INADDR_NONE)
        {
            Gateway = Address;
            Index = I->Index;
        }
    }
    free(Info);
    if (!Gateway)
    {
        skip("No default gateway\n");
        return;
    }

    memset(&Before, 0, sizeof(Before));
    Before.dwIndex = Index;
    if (GetIfEntry(&Before) != NO_ERROR)
    {
        skip("No interface row\n");
        return;
    }

    Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ok(Socket != INVALID_SOCKET, "socket: %d\n", WSAGetLastError());
    if (Socket == INVALID_SOCKET)
        return;
    memset(&To, 0, sizeof(To));
    To.sin_family = AF_INET;
    To.sin_port = htons(9);
    To.sin_addr.S_un.S_addr = Gateway;
    ok(sendto(Socket, Data, sizeof(Data), 0, (SOCKADDR *)&To, sizeof(To)) == sizeof(Data), "sendto: %d\n", WSAGetLastError());

    for (Tries = 0; Tries < 30 && !Seen; Tries++)
    {
        Sleep(100);
        memset(&After, 0, sizeof(After));
        After.dwIndex = Index;
        ok(GetIfEntry(&After) == NO_ERROR, "GetIfEntry(%lu) failed\n", Index);
        Seen = After.dwOutUcastPkts > Before.dwOutUcastPkts;
    }
    closesocket(Socket);

    ok(Seen, "interface %lu: unicast packets sent %lu -> %lu after a datagram to the gateway\n", Index,
       Before.dwOutUcastPkts, After.dwOutUcastPkts);
    ok(After.dwOutOctets > Before.dwOutOctets, "interface %lu: bytes sent %lu -> %lu\n", Index, Before.dwOutOctets,
       After.dwOutOctets);
    CheckRow(&After, "GetIfEntry after send");
}

START_TEST(IfStatistics)
{
    WSADATA Wsa;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    TestTable();
    TestSend();
    WSACleanup();
}
