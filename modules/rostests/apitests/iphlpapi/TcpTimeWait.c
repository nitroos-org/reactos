/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The TCP tables list the connections in TIME_WAIT
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <iphlpapi.h>

static PVOID GetTable(TCP_TABLE_CLASS Class)
{
    DWORD Size = 0, ret;
    PVOID Table = NULL;

    for (;;)
    {
        ret = GetExtendedTcpTable(Table, &Size, FALSE, AF_INET, Class, 0);
        if (ret == NO_ERROR)
            return Table;
        HeapFree(GetProcessHeap(), 0, Table);
        Table = NULL;
        if (ret != ERROR_INSUFFICIENT_BUFFER)
            return NULL;
        Table = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Table)
            return NULL;
    }
}

/* Rows of the four tables for the connection (local port, remote port) that are in TIME_WAIT */
static void CountTimeWait(WORD LocalPort, WORD RemotePort, int Counts[4])
{
    PMIB_TCPTABLE Basic;
    PMIB_TCPTABLE_OWNER_PID OwnerPid;
    PMIB_TCPTABLE_OWNER_MODULE OwnerModule;
    PMIB_TCPTABLE Legacy = NULL;
    DWORD i, Size = 0;

#define IS_ROW(Row) ((Row)->dwState == MIB_TCP_STATE_TIME_WAIT && \
                     (Row)->dwLocalAddr == htonl(INADDR_LOOPBACK) && \
                     (Row)->dwRemoteAddr == htonl(INADDR_LOOPBACK) && \
                     (WORD)(Row)->dwLocalPort == LocalPort && (WORD)(Row)->dwRemotePort == RemotePort)

    ZeroMemory(Counts, 4 * sizeof(int));

    Basic = GetTable(TCP_TABLE_BASIC_ALL);
    if (Basic)
    {
        for (i = 0; i < Basic->dwNumEntries; i++)
            if (IS_ROW(&Basic->table[i]))
                Counts[0]++;
        HeapFree(GetProcessHeap(), 0, Basic);
    }

    OwnerPid = GetTable(TCP_TABLE_OWNER_PID_ALL);
    if (OwnerPid)
    {
        for (i = 0; i < OwnerPid->dwNumEntries; i++)
        {
            if (IS_ROW(&OwnerPid->table[i]))
            {
                Counts[1]++;
                ok(OwnerPid->table[i].dwOwningPid == 0, "Owner PID %lu\n", OwnerPid->table[i].dwOwningPid);
            }
        }
        HeapFree(GetProcessHeap(), 0, OwnerPid);
    }

    OwnerModule = GetTable(TCP_TABLE_OWNER_MODULE_ALL);
    if (OwnerModule)
    {
        for (i = 0; i < OwnerModule->dwNumEntries; i++)
        {
            if (IS_ROW(&OwnerModule->table[i]))
            {
                Counts[2]++;
                ok(OwnerModule->table[i].dwOwningPid == 0, "Owner PID %lu\n", OwnerModule->table[i].dwOwningPid);
            }
        }
        HeapFree(GetProcessHeap(), 0, OwnerModule);
    }

    if (GetTcpTable(NULL, &Size, FALSE) == ERROR_INSUFFICIENT_BUFFER)
    {
        Legacy = HeapAlloc(GetProcessHeap(), 0, Size);
        if (Legacy && GetTcpTable(Legacy, &Size, FALSE) == NO_ERROR)
        {
            for (i = 0; i < Legacy->dwNumEntries; i++)
                if (IS_ROW(&Legacy->table[i]))
                    Counts[3]++;
        }
        HeapFree(GetProcessHeap(), 0, Legacy);
    }
#undef IS_ROW
}

START_TEST(TcpTimeWait)
{
    WSADATA wsaData;
    SOCKET Listener = INVALID_SOCKET, Client = INVALID_SOCKET, Server = INVALID_SOCKET;
    SOCKADDR_IN Addr, ClientAddr;
    int Len, i, Counts[4];
    char Byte;
    WORD ClientPort, ServerPort;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        skip("Failed to init WS2\n");
        return;
    }

    Listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Listener == INVALID_SOCKET || Client == INVALID_SOCKET)
    {
        skip("Cannot create sockets\n");
        goto quit;
    }

    ZeroMemory(&Addr, sizeof(Addr));
    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(Listener, (SOCKADDR *)&Addr, sizeof(Addr)) || listen(Listener, 1))
    {
        skip("Cannot listen\n");
        goto quit;
    }
    Len = sizeof(Addr);
    ok_int(getsockname(Listener, (SOCKADDR *)&Addr, &Len), 0);
    ServerPort = Addr.sin_port;

    if (connect(Client, (SOCKADDR *)&Addr, sizeof(Addr)))
    {
        skip("Cannot connect: %d\n", WSAGetLastError());
        goto quit;
    }
    Server = accept(Listener, NULL, NULL);
    ok(Server != INVALID_SOCKET, "accept failed: %d\n", WSAGetLastError());
    if (Server == INVALID_SOCKET)
        goto quit;

    Len = sizeof(ClientAddr);
    ok_int(getsockname(Client, (SOCKADDR *)&ClientAddr, &Len), 0);
    ClientPort = ClientAddr.sin_port;

    /* While it is open, it is established and not in TIME_WAIT */
    CountTimeWait(ClientPort, ServerPort, Counts);
    ok(Counts[0] == 0 && Counts[1] == 0 && Counts[2] == 0 && Counts[3] == 0,
       "TIME_WAIT rows of an open connection: %d %d %d %d\n", Counts[0], Counts[1], Counts[2], Counts[3]);

    /* The client closes first, the server follows: the client side ends in TIME_WAIT */
    ok_int(closesocket(Client), 0);
    Client = INVALID_SOCKET;
    ok_int(recv(Server, &Byte, 1, 0), 0);
    ok_int(closesocket(Server), 0);
    Server = INVALID_SOCKET;

    for (i = 0; i < 100; i++)
    {
        CountTimeWait(ClientPort, ServerPort, Counts);
        if (Counts[0] && Counts[1] && Counts[2] && Counts[3])
            break;
        Sleep(100);
    }
    ok_int(Counts[0], 1);
    ok_int(Counts[1], 1);
    ok_int(Counts[2], 1);
    ok_int(Counts[3], 1);

quit:
    if (Client != INVALID_SOCKET)
        closesocket(Client);
    if (Server != INVALID_SOCKET)
        closesocket(Server);
    if (Listener != INVALID_SOCKET)
        closesocket(Listener);
    WSACleanup();
}
