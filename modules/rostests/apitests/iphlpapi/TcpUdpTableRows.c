/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Every socket of the process is a row of the TCP and UDP tables
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

typedef struct _ROW
{
    DWORD State;
    DWORD LocalAddr;
    DWORD RemoteAddr;
    USHORT LocalPort;
    USHORT RemotePort;
    DWORD Pid;
} ROW;

typedef struct _ROWS
{
    DWORD Count;
    ROW *Row;
} ROWS;

static const char *const TcpClassNames[] =
{
    "BASIC_LISTENER", "BASIC_CONNECTIONS", "BASIC_ALL",
    "OWNER_PID_LISTENER", "OWNER_PID_CONNECTIONS", "OWNER_PID_ALL",
    "OWNER_MODULE_LISTENER", "OWNER_MODULE_CONNECTIONS", "OWNER_MODULE_ALL",
};

static const char *const UdpClassNames[] = { "BASIC", "OWNER_PID", "OWNER_MODULE" };

static DWORD g_Pid;

static void FreeRows(ROWS *Rows)
{
    HeapFree(GetProcessHeap(), 0, Rows->Row);
    Rows->Row = NULL;
    Rows->Count = 0;
}

static BOOL InitRows(ROWS *Rows, DWORD Count)
{
    Rows->Count = 0;
    Rows->Row = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Count + 1) * sizeof(ROW));
    return Rows->Row != NULL;
}

static void AddRow(ROWS *Rows, DWORD State, DWORD LocalAddr, DWORD LocalPort,
                   DWORD RemoteAddr, DWORD RemotePort, DWORD Pid)
{
    ROW *Row = &Rows->Row[Rows->Count++];

    Row->State = State;
    Row->LocalAddr = LocalAddr;
    Row->RemoteAddr = RemoteAddr;
    Row->LocalPort = ntohs((USHORT)LocalPort);
    Row->RemotePort = ntohs((USHORT)RemotePort);
    Row->Pid = Pid;
}

enum { GET_TCP, GET_UDP, GET_EXT_TCP, GET_EXT_UDP };

static DWORD GetTable(int Kind, int Class, PVOID *Table)
{
    DWORD Size = 0, ret = ERROR_INSUFFICIENT_BUFFER;
    int Try;

    *Table = NULL;
    for (Try = 0; Try < 10 && ret == ERROR_INSUFFICIENT_BUFFER; Try++)
    {
        switch (Kind)
        {
            case GET_TCP:
                ret = GetTcpTable(*Table, &Size, TRUE);
                break;
            case GET_UDP:
                ret = GetUdpTable(*Table, &Size, TRUE);
                break;
            case GET_EXT_TCP:
                ret = GetExtendedTcpTable(*Table, &Size, TRUE, AF_INET, Class, 0);
                break;
            default:
                ret = GetExtendedUdpTable(*Table, &Size, TRUE, AF_INET, Class, 0);
                break;
        }

        if (ret != ERROR_INSUFFICIENT_BUFFER)
            break;

        HeapFree(GetProcessHeap(), 0, *Table);
        Size += 512;
        *Table = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!*Table)
            return ERROR_OUTOFMEMORY;
    }

    if (ret != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, *Table);
        *Table = NULL;
    }
    return ret;
}

static void TcpBasicRows(PMIB_TCPTABLE T, ROWS *Rows)
{
    DWORD i;

    for (i = 0; i < T->dwNumEntries; i++)
    {
        AddRow(Rows, T->table[i].dwState, T->table[i].dwLocalAddr, T->table[i].dwLocalPort,
               T->table[i].dwRemoteAddr, T->table[i].dwRemotePort, 0);
    }
}

static DWORD GetTcpRows(TCP_TABLE_CLASS Class, ROWS *Rows)
{
    PVOID Table;
    DWORD ret = GetTable(GET_EXT_TCP, Class, &Table), i;

    Rows->Count = 0;
    Rows->Row = NULL;
    if (ret != NO_ERROR)
        return ret;

    if (Class <= TCP_TABLE_BASIC_ALL)
    {
        PMIB_TCPTABLE T = Table;

        if (InitRows(Rows, T->dwNumEntries))
            TcpBasicRows(T, Rows);
    }
    else if (Class <= TCP_TABLE_OWNER_PID_ALL)
    {
        PMIB_TCPTABLE_OWNER_PID T = Table;

        if (InitRows(Rows, T->dwNumEntries))
        {
            for (i = 0; i < T->dwNumEntries; i++)
            {
                AddRow(Rows, T->table[i].dwState, T->table[i].dwLocalAddr,
                       T->table[i].dwLocalPort, T->table[i].dwRemoteAddr,
                       T->table[i].dwRemotePort, T->table[i].dwOwningPid);
            }
        }
    }
    else
    {
        PMIB_TCPTABLE_OWNER_MODULE T = Table;

        if (InitRows(Rows, T->dwNumEntries))
        {
            for (i = 0; i < T->dwNumEntries; i++)
            {
                AddRow(Rows, T->table[i].dwState, T->table[i].dwLocalAddr,
                       T->table[i].dwLocalPort, T->table[i].dwRemoteAddr,
                       T->table[i].dwRemotePort, T->table[i].dwOwningPid);
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, Table);
    return Rows->Row ? NO_ERROR : ERROR_OUTOFMEMORY;
}

static void UdpBasicRows(PMIB_UDPTABLE T, ROWS *Rows)
{
    DWORD i;

    for (i = 0; i < T->dwNumEntries; i++)
        AddRow(Rows, 0, T->table[i].dwLocalAddr, T->table[i].dwLocalPort, 0, 0, 0);
}

static DWORD GetUdpRows(UDP_TABLE_CLASS Class, ROWS *Rows)
{
    PVOID Table;
    DWORD ret = GetTable(GET_EXT_UDP, Class, &Table), i;

    Rows->Count = 0;
    Rows->Row = NULL;
    if (ret != NO_ERROR)
        return ret;

    if (Class == UDP_TABLE_BASIC)
    {
        PMIB_UDPTABLE T = Table;

        if (InitRows(Rows, T->dwNumEntries))
            UdpBasicRows(T, Rows);
    }
    else if (Class == UDP_TABLE_OWNER_PID)
    {
        PMIB_UDPTABLE_OWNER_PID T = Table;

        if (InitRows(Rows, T->dwNumEntries))
        {
            for (i = 0; i < T->dwNumEntries; i++)
            {
                AddRow(Rows, 0, T->table[i].dwLocalAddr, T->table[i].dwLocalPort, 0, 0,
                       T->table[i].dwOwningPid);
            }
        }
    }
    else
    {
        PMIB_UDPTABLE_OWNER_MODULE T = Table;

        if (InitRows(Rows, T->dwNumEntries))
        {
            for (i = 0; i < T->dwNumEntries; i++)
            {
                AddRow(Rows, 0, T->table[i].dwLocalAddr, T->table[i].dwLocalPort, 0, 0,
                       T->table[i].dwOwningPid);
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, Table);
    return Rows->Row ? NO_ERROR : ERROR_OUTOFMEMORY;
}

static const ROW *FindTcp(const ROWS *Rows, DWORD State, DWORD LocalAddr, USHORT LocalPort,
                          DWORD RemoteAddr, USHORT RemotePort)
{
    DWORD i;

    for (i = 0; i < Rows->Count; i++)
    {
        const ROW *Row = &Rows->Row[i];

        if (Row->State == State && Row->LocalAddr == LocalAddr && Row->LocalPort == LocalPort &&
            (State == MIB_TCP_STATE_LISTEN ||
             (Row->RemoteAddr == RemoteAddr && Row->RemotePort == RemotePort)))
        {
            return Row;
        }
    }
    return NULL;
}

static const ROW *FindUdp(const ROWS *Rows, DWORD LocalAddr, USHORT LocalPort)
{
    DWORD i;

    for (i = 0; i < Rows->Count; i++)
    {
        if (Rows->Row[i].LocalAddr == LocalAddr && Rows->Row[i].LocalPort == LocalPort)
            return &Rows->Row[i];
    }
    return NULL;
}

static BOOL GetPort(SOCKET s, USHORT *Port)
{
    SOCKADDR_IN sa;
    int len = sizeof(sa);

    if (getsockname(s, (SOCKADDR *)&sa, &len) == SOCKET_ERROR)
        return FALSE;

    *Port = ntohs(sa.sin_port);
    return *Port != 0;
}

static SOCKET Bind(int Type, int Protocol, DWORD Addr)
{
    SOCKET s = socket(AF_INET, Type, Protocol);
    SOCKADDR_IN sa;

    if (s == INVALID_SOCKET)
        return s;

    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = Addr;
    if (bind(s, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR)
    {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static void CheckOwner(const ROW *Row, BOOL Owner, const char *Name)
{
    if (Row && Owner)
        ok(Row->Pid == g_Pid, "%s: owner %lu, expected %lu\n", Name, Row->Pid, g_Pid);
}

static void TestTcp(DWORD Loopback, USHORT AnyPort, USHORT LoopPort, USHORT ClientPort)
{
    ROWS Rows;
    int Class;

    for (Class = TCP_TABLE_BASIC_LISTENER; Class <= TCP_TABLE_OWNER_MODULE_ALL; Class++)
    {
        const char *Name = TcpClassNames[Class];
        BOOL Owner = Class >= TCP_TABLE_OWNER_PID_LISTENER;
        BOOL WantListen = (Class % 3) != 1;
        BOOL WantConn = (Class % 3) != 0;
        const ROW *Row;
        DWORD ret = GetTcpRows(Class, &Rows);

        ok(ret == NO_ERROR, "%s: error %lu\n", Name, ret);
        if (ret != NO_ERROR)
            continue;

        Row = FindTcp(&Rows, MIB_TCP_STATE_LISTEN, 0, AnyPort, 0, 0);
        ok(!!Row == WantListen, "%s: any-address listener %s\n", Name, Row ? "listed" : "missing");
        CheckOwner(Row, Owner, Name);
        if (Row && Class == TCP_TABLE_BASIC_ALL)
        {
            todo_if(is_reactos())
            ok(Row->RemoteAddr == 0 && Row->RemotePort == 0, "remote %08lx:%u of a listener\n",
               Row->RemoteAddr, Row->RemotePort);
        }

        Row = FindTcp(&Rows, MIB_TCP_STATE_LISTEN, Loopback, LoopPort, 0, 0);
        ok(!!Row == WantListen, "%s: loopback listener %s\n", Name, Row ? "listed" : "missing");
        CheckOwner(Row, Owner, Name);

        Row = FindTcp(&Rows, MIB_TCP_STATE_ESTAB, Loopback, ClientPort, Loopback, AnyPort);
        ok(!!Row == WantConn, "%s: client end %s\n", Name, Row ? "listed" : "missing");
        CheckOwner(Row, Owner, Name);

        Row = FindTcp(&Rows, MIB_TCP_STATE_ESTAB, Loopback, AnyPort, Loopback, ClientPort);
        ok(!!Row == WantConn, "%s: accepted end %s\n", Name, Row ? "listed" : "missing");
        CheckOwner(Row, Owner, Name);

        FreeRows(&Rows);
    }
}

static void TestGetTcpTable(DWORD Loopback, USHORT AnyPort, USHORT LoopPort, USHORT ClientPort)
{
    ROWS Rows;
    PVOID Table;
    DWORD ret = GetTable(GET_TCP, 0, &Table);

    ok(ret == NO_ERROR, "GetTcpTable: error %lu\n", ret);
    if (ret != NO_ERROR)
        return;

    if (!InitRows(&Rows, ((PMIB_TCPTABLE)Table)->dwNumEntries))
    {
        HeapFree(GetProcessHeap(), 0, Table);
        return;
    }

    TcpBasicRows(Table, &Rows);
    HeapFree(GetProcessHeap(), 0, Table);

    ok(FindTcp(&Rows, MIB_TCP_STATE_LISTEN, 0, AnyPort, 0, 0) != NULL,
       "GetTcpTable: any-address listener missing\n");
    ok(FindTcp(&Rows, MIB_TCP_STATE_LISTEN, Loopback, LoopPort, 0, 0) != NULL,
       "GetTcpTable: loopback listener missing\n");
    ok(FindTcp(&Rows, MIB_TCP_STATE_ESTAB, Loopback, ClientPort, Loopback, AnyPort) != NULL,
       "GetTcpTable: client end missing\n");
    ok(FindTcp(&Rows, MIB_TCP_STATE_ESTAB, Loopback, AnyPort, Loopback, ClientPort) != NULL,
       "GetTcpTable: accepted end missing\n");
    FreeRows(&Rows);
}

/* The rows of AF_INET6 TCP sockets: both ends of a loopback connection, and the listener. Needs the IPv6 switch
   (Ipv6Enable); skipped without */
static const UCHAR Loopback6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

static BOOL Has6Row(const MIB_TCP6TABLE_OWNER_PID *T, DWORD State, USHORT LocalPort, USHORT RemotePort, DWORD *Count)
{
    DWORD i;
    BOOL Found = FALSE;

    *Count = 0;
    for (i = 0; i < T->dwNumEntries; i++)
    {
        const MIB_TCP6ROW_OWNER_PID *Row = &T->table[i];

        if (Row->dwState == State && ntohs((USHORT)Row->dwLocalPort) == LocalPort &&
            memcmp(Row->ucLocalAddr, Loopback6, 16) == 0 &&
            (State == MIB_TCP_STATE_LISTEN ||
             (ntohs((USHORT)Row->dwRemotePort) == RemotePort && memcmp(Row->ucRemoteAddr, Loopback6, 16) == 0)))
        {
            ok(Row->dwOwningPid == g_Pid, "IPv6 row: owner %lu, expected %lu\n", Row->dwOwningPid, g_Pid);
            (*Count)++;
            Found = TRUE;
        }
    }
    return Found;
}

static void TestTcp6(void)
{
    SOCKET Listen, Client = INVALID_SOCKET, Accepted = INVALID_SOCKET, Second = INVALID_SOCKET, SecondAccepted = INVALID_SOCKET;
    SOCKADDR_IN6 sa;
    int len = sizeof(sa);
    USHORT ListenPort, ClientPort, SecondPort;
    PMIB_TCP6TABLE_OWNER_PID Table = NULL;
    DWORD Size = 0, ret, Count, Try;

    Listen = socket(AF_INET6, SOCK_STREAM, 0);
    if (Listen == INVALID_SOCKET)
    {
        skip("No IPv6 sockets\n");
        return;
    }

    ZeroMemory(&sa, sizeof(sa));
    sa.sin6_family = AF_INET6;
    memcpy(&sa.sin6_addr, Loopback6, 16);
    if (bind(Listen, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR || listen(Listen, SOMAXCONN) == SOCKET_ERROR ||
        getsockname(Listen, (SOCKADDR *)&sa, &len) == SOCKET_ERROR)
    {
        skip("Cannot listen on ::1\n");
        goto quit;
    }
    ListenPort = ntohs(sa.sin6_port);

    Client = socket(AF_INET6, SOCK_STREAM, 0);
    Second = socket(AF_INET6, SOCK_STREAM, 0);
    if (Client == INVALID_SOCKET || Second == INVALID_SOCKET ||
        connect(Client, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR ||
        connect(Second, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR)
    {
        skip("Cannot connect over ::1\n");
        goto quit;
    }
    len = sizeof(sa);
    getsockname(Client, (SOCKADDR *)&sa, &len);
    ClientPort = ntohs(sa.sin6_port);
    len = sizeof(sa);
    getsockname(Second, (SOCKADDR *)&sa, &len);
    SecondPort = ntohs(sa.sin6_port);
    Accepted = accept(Listen, NULL, NULL);
    SecondAccepted = accept(Listen, NULL, NULL);
    if (Accepted == INVALID_SOCKET || SecondAccepted == INVALID_SOCKET)
    {
        skip("Cannot accept the connections\n");
        goto quit;
    }

    for (Try = 0, ret = ERROR_INSUFFICIENT_BUFFER; Try < 10 && ret == ERROR_INSUFFICIENT_BUFFER; Try++)
    {
        ret = GetExtendedTcpTable(Table, &Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret != ERROR_INSUFFICIENT_BUFFER)
            break;
        HeapFree(GetProcessHeap(), 0, Table);
        Size += 512;
        Table = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Table)
            goto quit;
    }
    ok(ret == NO_ERROR, "GetExtendedTcpTable(AF_INET6): error %lu\n", ret);
    if (ret != NO_ERROR)
        goto quit;

    {
        DWORD i;

        for (i = 0; i < Table->dwNumEntries; i++)
        {
            const MIB_TCP6ROW_OWNER_PID *Row = &Table->table[i];

            if (memcmp(Row->ucLocalAddr, Loopback6, 16) == 0)
                trace("IPv6 row %lu: state %lu local port %u remote port %u pid %lu\n", i, Row->dwState,
                      ntohs((USHORT)Row->dwLocalPort), ntohs((USHORT)Row->dwRemotePort), Row->dwOwningPid);
        }
        trace("listen %u, client %u, second %u\n", ListenPort, ClientPort, SecondPort);
    }

    Has6Row(Table, MIB_TCP_STATE_LISTEN, ListenPort, 0, &Count);
    ok(Count == 1, "IPv6 listener: %lu rows\n", Count);
    Has6Row(Table, MIB_TCP_STATE_ESTAB, ClientPort, ListenPort, &Count);
    ok(Count == 1, "IPv6 client end: %lu rows\n", Count);
    Has6Row(Table, MIB_TCP_STATE_ESTAB, ListenPort, ClientPort, &Count);
    ok(Count == 1, "IPv6 accepted end: %lu rows\n", Count);
    Has6Row(Table, MIB_TCP_STATE_ESTAB, SecondPort, ListenPort, &Count);
    ok(Count == 1, "IPv6 second client end: %lu rows\n", Count);
    Has6Row(Table, MIB_TCP_STATE_ESTAB, ListenPort, SecondPort, &Count);
    ok(Count == 1, "IPv6 second accepted end (two on one listener): %lu rows\n", Count);

quit:
    HeapFree(GetProcessHeap(), 0, Table);
    closesocket(SecondAccepted);
    closesocket(Second);
    closesocket(Accepted);
    closesocket(Client);
    closesocket(Listen);
}

static void TestUdp(DWORD Loopback, USHORT AnyPort, USHORT LoopPort, BOOL HaveRaw)
{
    ROWS Rows;
    PVOID Table;
    DWORD ret, i;
    int Class;

    for (Class = UDP_TABLE_BASIC; Class <= UDP_TABLE_OWNER_MODULE; Class++)
    {
        const char *Name = UdpClassNames[Class];
        BOOL Owner = Class != UDP_TABLE_BASIC;
        const ROW *Row;

        ret = GetUdpRows(Class, &Rows);
        ok(ret == NO_ERROR, "%s: error %lu\n", Name, ret);
        if (ret != NO_ERROR)
            continue;

        Row = FindUdp(&Rows, 0, AnyPort);
        ok(Row != NULL, "%s: any-address socket missing\n", Name);
        CheckOwner(Row, Owner, Name);

        Row = FindUdp(&Rows, Loopback, LoopPort);
        ok(Row != NULL, "%s: loopback socket missing\n", Name);
        CheckOwner(Row, Owner, Name);

        if (!HaveRaw && Class == UDP_TABLE_BASIC)
            skip("Raw sockets are not available\n");

        if (HaveRaw && Owner)
        {
            /* a raw IP socket has no port and is not a UDP socket */
            for (i = 0; i < Rows.Count; i++)
            {
                if (Rows.Row[i].Pid == g_Pid && Rows.Row[i].LocalPort == 0)
                {
                    ok(0, "%s: raw socket listed as %08lx:0\n", Name, Rows.Row[i].LocalAddr);
                    break;
                }
            }
        }

        FreeRows(&Rows);
    }

    ret = GetTable(GET_UDP, 0, &Table);
    ok(ret == NO_ERROR, "GetUdpTable: error %lu\n", ret);
    if (ret != NO_ERROR || !InitRows(&Rows, ((PMIB_UDPTABLE)Table)->dwNumEntries))
    {
        HeapFree(GetProcessHeap(), 0, Table);
        return;
    }

    UdpBasicRows(Table, &Rows);
    HeapFree(GetProcessHeap(), 0, Table);

    ok(FindUdp(&Rows, 0, AnyPort) != NULL, "GetUdpTable: any-address socket missing\n");
    ok(FindUdp(&Rows, Loopback, LoopPort) != NULL, "GetUdpTable: loopback socket missing\n");
    FreeRows(&Rows);
}

START_TEST(TcpUdpTableRows)
{
    WSADATA wsaData;
    SOCKET Any, Loop, Client = INVALID_SOCKET, Accepted = INVALID_SOCKET;
    SOCKET UdpAny, UdpLoop, Raw;
    SOCKADDR_IN sa;
    DWORD Loopback = htonl(INADDR_LOOPBACK);
    USHORT AnyPort, LoopPort, ClientPort, UdpAnyPort, UdpLoopPort;

    g_Pid = GetCurrentProcessId();

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        skip("Failed to init WS2\n");
        return;
    }

    Any = Bind(SOCK_STREAM, 0, htonl(INADDR_ANY));
    Loop = Bind(SOCK_STREAM, 0, Loopback);
    UdpAny = Bind(SOCK_DGRAM, 0, htonl(INADDR_ANY));
    UdpLoop = Bind(SOCK_DGRAM, 0, Loopback);
    /* needs administrator rights on Windows; the raw part of the test is skipped without */
    Raw = Bind(SOCK_RAW, IPPROTO_RAW, Loopback);
    if (Any == INVALID_SOCKET || Loop == INVALID_SOCKET ||
        UdpAny == INVALID_SOCKET || UdpLoop == INVALID_SOCKET ||
        listen(Any, SOMAXCONN) == SOCKET_ERROR || listen(Loop, SOMAXCONN) == SOCKET_ERROR ||
        !GetPort(Any, &AnyPort) || !GetPort(Loop, &LoopPort) ||
        !GetPort(UdpAny, &UdpAnyPort) || !GetPort(UdpLoop, &UdpLoopPort))
    {
        skip("Cannot set up the sockets\n");
        goto quit;
    }

    Client = socket(AF_INET, SOCK_STREAM, 0);
    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = Loopback;
    sa.sin_port = htons(AnyPort);
    if (Client == INVALID_SOCKET || connect(Client, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR)
    {
        skip("Cannot connect over loopback\n");
        goto quit;
    }

    if (!GetPort(Client, &ClientPort))
    {
        skip("Cannot get the client address\n");
        goto quit;
    }

    Accepted = accept(Any, NULL, NULL);
    if (Accepted == INVALID_SOCKET)
    {
        skip("Cannot accept the connection\n");
        goto quit;
    }

    TestTcp(Loopback, AnyPort, LoopPort, ClientPort);
    TestGetTcpTable(Loopback, AnyPort, LoopPort, ClientPort);
    TestTcp6();
    TestUdp(Loopback, UdpAnyPort, UdpLoopPort, Raw != INVALID_SOCKET);

quit:
    closesocket(Raw);
    closesocket(Accepted);
    closesocket(Client);
    closesocket(Loop);
    closesocket(Any);
    closesocket(UdpLoop);
    closesocket(UdpAny);
    WSACleanup();
}
