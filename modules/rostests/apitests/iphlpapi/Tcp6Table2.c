/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     GetTcp6Table2 and GetTcp6Table list the IPv6 TCP listeners and connections that
 *              GetExtendedTcpTable(AF_INET6) lists (Windows 10: a listener on ::1 is a row in state LISTEN with the
 *              owner and the port in network order, remote address ::, and a loopback connection is two ESTABLISHED
 *              rows); the sizes are asked for with a NULL table; without IPv6 the table is empty
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "Ipv6Common.h"
#include <tcpmib.h>

typedef DWORD (WINAPI *PFN_TCP6_TABLE2)(PMIB_TCP6TABLE2, PULONG, BOOL);
typedef DWORD (WINAPI *PFN_TCP6_TABLE)(PMIB_TCP6TABLE, PULONG, BOOL);

static PFN_TCP6_TABLE2 pGetTcp6Table2;
static PFN_TCP6_TABLE pGetTcp6Table;

static PMIB_TCP6TABLE2 Get2(BOOL Order)
{
    ULONG Size = 0;
    PMIB_TCP6TABLE2 Table;
    DWORD Error = pGetTcp6Table2(NULL, &Size, Order);

    ok(Error == ERROR_INSUFFICIENT_BUFFER, "GetTcp6Table2(NULL): %lu\n", Error);
    ok(Size >= FIELD_OFFSET(MIB_TCP6TABLE2, table), "GetTcp6Table2(NULL): size %lu\n", Size);
    Size += 8192;
    Table = HeapAlloc(GetProcessHeap(), 0, Size);
    Error = pGetTcp6Table2(Table, &Size, Order);
    ok(Error == NO_ERROR, "GetTcp6Table2: %lu\n", Error);
    if (Error != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, Table);
        return NULL;
    }
    ok(Size >= FIELD_OFFSET(MIB_TCP6TABLE2, table) + Table->dwNumEntries * sizeof(MIB_TCP6ROW2), "size %lu for %lu rows\n",
       Size, Table->dwNumEntries);
    return Table;
}

static PMIB_TCP6TABLE_OWNER_PID GetExtended(void)
{
    DWORD Size = 0, Error;
    PMIB_TCP6TABLE_OWNER_PID Table;

    GetExtendedTcpTable(NULL, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    Size += 8192;
    Table = HeapAlloc(GetProcessHeap(), 0, Size);
    Error = GetExtendedTcpTable(Table, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    ok(Error == NO_ERROR, "GetExtendedTcpTable(AF_INET6): %lu\n", Error);
    if (Error != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, Table);
        return NULL;
    }
    return Table;
}

/* the rows of this process */
static ULONG CountOwn(const MIB_TCP6TABLE2 *Table, ULONG Port, ULONG State)
{
    ULONG i, Count = 0;

    for (i = 0; i < Table->dwNumEntries; i++)
    {
        const MIB_TCP6ROW2 *Row = &Table->table[i];

        if (Row->dwOwningPid == GetCurrentProcessId() &&
            (ntohs((USHORT)Row->dwLocalPort) == Port || ntohs((USHORT)Row->dwRemotePort) == Port) &&
            (!State || Row->State == State))
            Count++;
    }
    return Count;
}

static void TestEmpty(void)
{
    ULONG Size = 0;
    BYTE Buffer[64];
    DWORD Error;

    Error = pGetTcp6Table2(NULL, &Size, FALSE);
    ok(Error == ERROR_INSUFFICIENT_BUFFER && Size >= FIELD_OFFSET(MIB_TCP6TABLE2, table), "size query: %lu, %lu\n", Error,
       Size);
    Size = sizeof(Buffer);
    memset(Buffer, 0xcc, sizeof(Buffer));
    Error = pGetTcp6Table2((PMIB_TCP6TABLE2)Buffer, &Size, FALSE);
    ok(Error == NO_ERROR, "GetTcp6Table2: %lu\n", Error);
    ok(((PMIB_TCP6TABLE2)Buffer)->dwNumEntries == 0, "IPv6 is off: %lu rows\n", ((PMIB_TCP6TABLE2)Buffer)->dwNumEntries);
    Error = pGetTcp6Table2(NULL, NULL, FALSE);
    ok(Error == ERROR_INVALID_PARAMETER, "no size: %lu\n", Error);
}

START_TEST(Tcp6Table2)
{
    WSADATA Wsa;
    SOCKET Listener, Client, Server;
    SOCKADDR_IN6 Address;
    int Length = sizeof(Address);
    USHORT Port;
    PMIB_TCP6TABLE2 Table;
    PMIB_TCP6TABLE_OWNER_PID Ours;
    ULONG i, Size, Rows;
    BYTE Small[8];
    DWORD Error;
    BOOL Found;

    WSAStartup(MAKEWORD(2, 2), &Wsa);
    pGetTcp6Table2 = (PFN_TCP6_TABLE2)Ipv6Proc("GetTcp6Table2");
    pGetTcp6Table = (PFN_TCP6_TABLE)Ipv6Proc("GetTcp6Table");
    if (!pGetTcp6Table2)
    {
        skip("GetTcp6Table2 is not available\n");
        return;
    }

    if (!Ipv6SocketsWork())
    {
        TestEmpty();
        return;
    }

    Listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    memset(&Address, 0, sizeof(Address));
    Address.sin6_family = AF_INET6;
    Address.sin6_addr.u.Byte[15] = 1;
    ok(bind(Listener, (SOCKADDR *)&Address, sizeof(Address)) == 0, "bind: %d\n", WSAGetLastError());
    ok(listen(Listener, 4) == 0, "listen: %d\n", WSAGetLastError());
    getsockname(Listener, (SOCKADDR *)&Address, &Length);
    Port = ntohs(Address.sin6_port);

    /* the listener is a row, with the owner, the port in network order and the unspecified remote address */
    Table = Get2(TRUE);
    if (!Table)
        return;
    ok(CountOwn(Table, Port, 0) == 1, "listener: %lu rows\n", CountOwn(Table, Port, 0));
    Found = FALSE;
    for (i = 0; i < Table->dwNumEntries; i++)
    {
        const MIB_TCP6ROW2 *Row = &Table->table[i];

        if (Row->dwOwningPid != GetCurrentProcessId() || ntohs((USHORT)Row->dwLocalPort) != Port)
            continue;
        Found = TRUE;
        ok(Row->State == MIB_TCP_STATE_LISTEN, "listener state %d\n", Row->State);
        ok(Row->LocalAddr.u.Byte[15] == 1 && Row->LocalAddr.u.Word[0] == 0 && Row->dwLocalScopeId == 0, "local address\n");
        ok(Row->RemoteAddr.u.Word[0] == 0 && Row->RemoteAddr.u.Word[7] == 0 && Row->dwRemotePort == 0 &&
           Row->dwRemoteScopeId == 0, "remote address\n");
        ok(Row->dwOffloadState == TcpConnectionOffloadStateInHost, "offload state %d\n", Row->dwOffloadState);
    }
    ok(Found, "the listener is not in the table\n");
    HeapFree(GetProcessHeap(), 0, Table);

    /* a connection over the loopback is two rows */
    Client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    ok(connect(Client, (SOCKADDR *)&Address, sizeof(Address)) == 0, "connect: %d\n", WSAGetLastError());
    Server = accept(Listener, NULL, NULL);
    ok(Server != INVALID_SOCKET, "accept: %d\n", WSAGetLastError());

    Table = Get2(FALSE);
    if (Table)
    {
        ok(CountOwn(Table, Port, MIB_TCP_STATE_ESTAB) == 2, "established rows: %lu\n", CountOwn(Table, Port, MIB_TCP_STATE_ESTAB));
        ok(CountOwn(Table, Port, MIB_TCP_STATE_LISTEN) == 1, "listener rows: %lu\n", CountOwn(Table, Port, MIB_TCP_STATE_LISTEN));
        HeapFree(GetProcessHeap(), 0, Table);
    }

    /* the table is the one GetExtendedTcpTable(AF_INET6) lists, in the same (sorted) order */
    Table = Get2(TRUE);
    Ours = GetExtended();
    if (Table && Ours)
    {
        ok(Table->dwNumEntries == Ours->dwNumEntries || Table->dwNumEntries + 1 >= Ours->dwNumEntries,
           "%lu rows against %lu\n", Table->dwNumEntries, Ours->dwNumEntries);
        for (i = 0; i < min(Table->dwNumEntries, Ours->dwNumEntries); i++)
        {
            const MIB_TCP6ROW2 *A = &Table->table[i];
            const MIB_TCP6ROW_OWNER_PID *B = &Ours->table[i];

            if (memcmp(&A->LocalAddr, B->ucLocalAddr, 16) || A->dwLocalPort != B->dwLocalPort)
                break;
            ok(A->State == B->dwState && A->dwOwningPid == B->dwOwningPid && A->dwRemotePort == B->dwRemotePort &&
               !memcmp(&A->RemoteAddr, B->ucRemoteAddr, 16), "row %lu differs\n", i);
        }
    }
    HeapFree(GetProcessHeap(), 0, Table);
    HeapFree(GetProcessHeap(), 0, Ours);

    /* the table without the owner: the same endpoints */
    if (pGetTcp6Table)
    {
        PMIB_TCP6TABLE Plain;
        ULONG Own = 0;

        Size = 0;
        Error = pGetTcp6Table(NULL, &Size, FALSE);
        ok(Error == ERROR_INSUFFICIENT_BUFFER && Size >= FIELD_OFFSET(MIB_TCP6TABLE, table), "GetTcp6Table(NULL): %lu, %lu\n",
           Error, Size);
        Size += 8192;
        Plain = HeapAlloc(GetProcessHeap(), 0, Size);
        Error = pGetTcp6Table(Plain, &Size, TRUE);
        ok(Error == NO_ERROR, "GetTcp6Table: %lu\n", Error);
        for (i = 0; Error == NO_ERROR && i < Plain->dwNumEntries; i++)
            if (ntohs((USHORT)Plain->table[i].dwLocalPort) == Port || ntohs((USHORT)Plain->table[i].dwRemotePort) == Port)
                Own++;
        ok(Own == 3, "GetTcp6Table: %lu rows of the test\n", Own);
        HeapFree(GetProcessHeap(), 0, Plain);
    }

    /* a buffer that is too small gets the size that is not */
    Size = sizeof(Small);
    Error = pGetTcp6Table2((PMIB_TCP6TABLE2)Small, &Size, FALSE);
    Rows = Size;
    ok(Error == ERROR_INSUFFICIENT_BUFFER && Rows > sizeof(Small), "small buffer: %lu, size %lu\n", Error, Rows);
    Error = pGetTcp6Table2(NULL, NULL, FALSE);
    ok(Error == ERROR_INVALID_PARAMETER, "no size: %lu\n", Error);

    closesocket(Server);
    closesocket(Client);
    closesocket(Listener);
}
