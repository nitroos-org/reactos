/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     TCP connections that are made, queried and aborted from several threads at once: the stack must
 *              stay up and keep working. The connections are over loopback and over the address of a network
 *              adapter, IPv4 and IPv6. Threads connect and abort, ask for the names of the sockets other
 *              threads are closing, set the options that reach the connection (TCP_NODELAY, keep-alive) and
 *              read the table of connections, and every result is either success or an error: nothing may
 *              crash the system, and a connection made afterwards still carries data.
 *              TCPCHURN_SECONDS sets the length of the run (default 10 s, split between the targets).
 */

#include "ws2_32.h"
#include <iphlpapi.h>
#include <mstcpip.h>

#define SLOTS       32
#define WORKERS     3
#define LISTENERS   2

typedef struct
{
    int Family;
    SOCKADDR_STORAGE Address;
    int AddressLength;
    SOCKET Listener;
} TARGET;

static volatile LONG g_Stop;
static volatile LONG g_Connects, g_Failed, g_Queries, g_Options, g_Tables, g_Aborts;
static volatile SOCKET g_Slots[SLOTS];
static volatile PCSTR g_Where[LISTENERS];   /* what each accept thread is doing, for a thread that does not end */
static TARGET g_Target;
static BOOL g_Peer;

static void SetLinger0(SOCKET s)
{
    struct linger Linger = { 1, 0 };

    setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&Linger, sizeof(Linger));
}

/* Accepts what comes, keeps a few and aborts or closes them at random */
static DWORD WINAPI AcceptThread(PVOID Context)
{
    SOCKET Held[4] = { INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET };
    ULONG Seed = GetTickCount() ^ (ULONG)(ULONG_PTR)Context;
    SOCKET Client;
    SOCKADDR_STORAGE Name;
    int Length, Slot;
    fd_set Set;
    struct timeval Wait;

    volatile PCSTR *Where = &g_Where[(ULONG_PTR)Context];

    while (!g_Stop)
    {
        FD_ZERO(&Set);
        FD_SET(g_Target.Listener, &Set);
        Wait.tv_sec = 0;
        Wait.tv_usec = 100000;
        *Where = "select";
        if (select(0, &Set, NULL, NULL, &Wait) <= 0)
            continue;

        *Where = "accept";
        Client = accept(g_Target.Listener, NULL, NULL);
        if (Client == INVALID_SOCKET)
            continue;

        Length = sizeof(Name);
        *Where = "getpeername";
        getpeername(Client, (PSOCKADDR)&Name, &Length);
        Length = sizeof(Name);
        *Where = "getsockname";
        getsockname(Client, (PSOCKADDR)&Name, &Length);

        Seed = Seed * 1103515245 + 12345;
        Slot = (Seed >> 16) & 3;
        if (Held[Slot] != INVALID_SOCKET)
        {
            if (Seed & 0x100000)
            {
                *Where = "linger";
                SetLinger0(Held[Slot]);
                InterlockedIncrement(&g_Aborts);
            }
            *Where = "closesocket";
            closesocket(Held[Slot]);
        }
        Held[Slot] = Client;
    }

    *Where = "end: closing the held sockets";
    for (Slot = 0; Slot < 4; Slot++)
        if (Held[Slot] != INVALID_SOCKET)
            closesocket(Held[Slot]);
    *Where = "ended";
    return 0;
}

/* Makes connections and publishes them for the query threads, then aborts or closes them */
static DWORD WINAPI ChurnThread(PVOID Context)
{
    ULONG Seed = GetTickCount() ^ ((ULONG)(ULONG_PTR)Context * 7919);
    SOCKET s, Old;
    int Slot;
    BOOL On = TRUE;
    char Data[16] = "churn";
    u_long NonBlocking;
    struct tcp_keepalive Keep;
    DWORD Returned;

    while (!g_Stop)
    {
        s = socket(g_Target.Family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET)
        {
            Sleep(1);
            continue;
        }

        Seed = Seed * 1103515245 + 12345;
        if (Seed & 0x10000)
        {
            /* a non-blocking connect that is abandoned half way sometimes */
            NonBlocking = 1;
            ioctlsocket(s, FIONBIO, &NonBlocking);
        }
        if (connect(s, (PSOCKADDR)&g_Target.Address, g_Target.AddressLength) == 0 ||
            WSAGetLastError() == WSAEWOULDBLOCK)
        {
            InterlockedIncrement(&g_Connects);
            if (Seed & 0x20000)
                send(s, Data, sizeof(Data), 0);
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&On, sizeof(On));

            /* Only this thread has the socket yet: the keep-alive values, the third option of the stack */
            Keep.onoff = 1;
            Keep.keepalivetime = 7200000;
            Keep.keepaliveinterval = 1000;
            WSAIoctl(s, SIO_KEEPALIVE_VALS, &Keep, sizeof(Keep), NULL, 0, &Returned, NULL, NULL);
        }
        else
        {
            InterlockedIncrement(&g_Failed);
        }

        /* Another thread may ask about, or close, what is in the slot */
        Slot = (Seed >> 8) % SLOTS;
        Old = (SOCKET)InterlockedExchangePointer((PVOID volatile *)&g_Slots[Slot], (PVOID)s);
        if (Old != INVALID_SOCKET && Old != 0)
        {
            if (Seed & 0x40000)
            {
                SetLinger0(Old);
                InterlockedIncrement(&g_Aborts);
            }
            closesocket(Old);
        }
    }
    return 0;
}

/* Asks for the names and sets options on sockets that are being replaced and closed */
static DWORD WINAPI QueryThread(PVOID Context)
{
    ULONG Seed = GetTickCount() ^ ((ULONG)(ULONG_PTR)Context * 104729);
    SOCKADDR_STORAGE Name;
    SOCKET s;
    int Length, Slot, Value;
    BOOL On;

    while (!g_Stop)
    {
        Seed = Seed * 1103515245 + 12345;
        Slot = (Seed >> 8) % SLOTS;
        /* The socket is taken out of its slot while it is used: no thread closes a socket that another uses (the
         * Winsock helper does not stand that), but the stack still aborts connections under it, when the peer
         * resets them or a timer ends them, which is what is asked of the stack here */
        s = (SOCKET)InterlockedExchangePointer((PVOID volatile *)&g_Slots[Slot], (PVOID)INVALID_SOCKET);
        if (s == INVALID_SOCKET || s == 0)
        {
            Sleep(0);
            continue;
        }

        Length = sizeof(Name);
        getsockname(s, (PSOCKADDR)&Name, &Length);
        Length = sizeof(Name);
        getpeername(s, (PSOCKADDR)&Name, &Length);
        InterlockedIncrement(&g_Queries);

        On = (Seed >> 20) & 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&On, sizeof(On));
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&On, sizeof(On));
        Length = sizeof(Value);
        getsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&Value, &Length);
        InterlockedIncrement(&g_Options);

        /* Back into the slot, unless a new socket took it meanwhile */
        if (InterlockedCompareExchangePointer((PVOID volatile *)&g_Slots[Slot], (PVOID)s, (PVOID)INVALID_SOCKET) !=
            (PVOID)INVALID_SOCKET)
            closesocket(s);
    }
    return 0;
}

/* Reads the table of connections: it walks the connections and their sockets */
static DWORD WINAPI TableThread(PVOID Context)
{
    PVOID Table;
    ULONG Size;
    DWORD Result;

    while (!g_Stop)
    {
        Size = 0;
        Result = GetExtendedTcpTable(NULL, &Size, FALSE, g_Target.Family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (Result == ERROR_INSUFFICIENT_BUFFER && Size)
        {
            Size += 4096;
            Table = HeapAlloc(GetProcessHeap(), 0, Size);
            if (Table)
            {
                GetExtendedTcpTable(Table, &Size, FALSE, g_Target.Family, TCP_TABLE_OWNER_PID_ALL, 0);
                HeapFree(GetProcessHeap(), 0, Table);
            }
        }
        InterlockedIncrement(&g_Tables);
        Sleep(5);
    }
    return 0;
}

/* A connection made after the churn, to a listener of its own, must carry data */
static void CheckStillWorks(const char *What)
{
    SOCKET Listener, Client, Server;
    SOCKADDR_STORAGE Address;
    char Out[8] = "after", In[8] = { 0 };
    int Got, Length = sizeof(Address);
    DWORD Timeout = 5000;
    int Attempt;

    if (g_Peer)
    {
        /* The peer drops or resets some connections at random: one of a few must come back with its bytes. After a
         * long run every local port may be in TIME-WAIT towards the peer (120 s): the attempts wait for that */
        for (Attempt = 0; Attempt < 90; Attempt++)
        {
            if (Attempt)
                Sleep(2000);
            memset(In, 0, sizeof(In));
            Client = socket(g_Target.Family, SOCK_STREAM, IPPROTO_TCP);
            if (Client == INVALID_SOCKET)
                break;
            setsockopt(Client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
            if (connect(Client, (PSOCKADDR)&g_Target.Address, g_Target.AddressLength) == 0 &&
                send(Client, Out, sizeof(Out), 0) == sizeof(Out) &&
                recv(Client, In, sizeof(In), 0) == sizeof(In) && !memcmp(In, Out, sizeof(In)))
            {
                closesocket(Client);
                return;
            }
            closesocket(Client);
        }
        ok(0, "%s: no connection to the peer carried data after the churn\n", What);
        return;
    }

    memcpy(&Address, &g_Target.Address, g_Target.AddressLength);
    if (g_Target.Family == AF_INET6)
        ((struct sockaddr_in6 *)&Address)->sin6_port = 0;
    else
        ((struct sockaddr_in *)&Address)->sin_port = 0;

    Listener = socket(g_Target.Family, SOCK_STREAM, IPPROTO_TCP);
    ok(Listener != INVALID_SOCKET, "%s: socket failed %d\n", What, WSAGetLastError());
    if (Listener == INVALID_SOCKET)
        return;
    ok(bind(Listener, (PSOCKADDR)&Address, g_Target.AddressLength) == 0, "%s: bind failed %d\n", What, WSAGetLastError());
    ok(listen(Listener, 4) == 0, "%s: listen failed %d\n", What, WSAGetLastError());
    ok(getsockname(Listener, (PSOCKADDR)&Address, &Length) == 0, "%s: getsockname failed\n", What);
    if (g_Target.Family == AF_INET6)
        ((struct sockaddr_in6 *)&Address)->sin6_addr = ((struct sockaddr_in6 *)&g_Target.Address)->sin6_addr;
    else
        ((struct sockaddr_in *)&Address)->sin_addr = ((struct sockaddr_in *)&g_Target.Address)->sin_addr;

    Client = socket(g_Target.Family, SOCK_STREAM, IPPROTO_TCP);
    ok(Client != INVALID_SOCKET, "%s: socket failed %d\n", What, WSAGetLastError());
    setsockopt(Client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
    ok(connect(Client, (PSOCKADDR)&Address, g_Target.AddressLength) == 0,
       "%s: connect failed %d\n", What, WSAGetLastError());

    Server = accept(Listener, NULL, NULL);
    ok(Server != INVALID_SOCKET, "%s: accept failed %d\n", What, WSAGetLastError());
    if (Server != INVALID_SOCKET)
    {
        setsockopt(Server, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
        ok(send(Client, Out, sizeof(Out), 0) == sizeof(Out), "%s: send failed %d\n", What, WSAGetLastError());
        Got = recv(Server, In, sizeof(In), 0);
        ok(Got == sizeof(In) && !memcmp(In, Out, sizeof(In)), "%s: recv gave %d\n", What, Got);
        closesocket(Server);
    }
    closesocket(Client);
    closesocket(Listener);
}

/* Peer: Address is a listener on another machine (it answers "after" with the same bytes), not made here */
static void ChurnTarget(int Family, PSOCKADDR Address, int AddressLength, const char *What, DWORD Millis, BOOL Peer)
{
    HANDLE Threads[LISTENERS + WORKERS + 3];
    SOCKADDR_STORAGE Bound;
    int Count = 0, Length, i;
    DWORD Start;
    ULONG_PTR n;
    SOCKET Old;
    u_long NonBlocking;

    memset(&g_Target, 0, sizeof(g_Target));
    g_Target.Family = Family;
    g_Target.AddressLength = AddressLength;
    g_Target.Listener = INVALID_SOCKET;
    g_Peer = Peer;
    memcpy(&g_Target.Address, Address, AddressLength);

    if (!Peer)
    {
        g_Target.Listener = socket(Family, SOCK_STREAM, IPPROTO_TCP);
        ok(g_Target.Listener != INVALID_SOCKET, "%s: socket failed\n", What);
        if (g_Target.Listener == INVALID_SOCKET)
            return;
        if (bind(g_Target.Listener, Address, AddressLength) != 0 || listen(g_Target.Listener, 64) != 0)
        {
            skip("%s: cannot listen on this address (%d)\n", What, WSAGetLastError());
            closesocket(g_Target.Listener);
            return;
        }

        /* A connection that was reset after select reported it is gone when accept is called: a blocking accept
         * would then wait for the next one, and the thread could not end when the run does */
        NonBlocking = 1;
        ioctlsocket(g_Target.Listener, FIONBIO, &NonBlocking);

        /* connect to the address that was given, at the port that was chosen */
        Length = sizeof(Bound);
        ok(getsockname(g_Target.Listener, (PSOCKADDR)&Bound, &Length) == 0, "%s: getsockname failed\n", What);
        if (Family == AF_INET6)
            ((struct sockaddr_in6 *)&g_Target.Address)->sin6_port = ((struct sockaddr_in6 *)&Bound)->sin6_port;
        else
            ((struct sockaddr_in *)&g_Target.Address)->sin_port = ((struct sockaddr_in *)&Bound)->sin_port;
    }

    for (i = 0; i < SLOTS; i++)
        g_Slots[i] = INVALID_SOCKET;
    g_Stop = 0;
    g_Connects = g_Failed = g_Queries = g_Options = g_Tables = g_Aborts = 0;

    for (n = 0; n < (Peer ? 0 : LISTENERS); n++)
        Threads[Count++] = CreateThread(NULL, 0, AcceptThread, (PVOID)n, 0, NULL);
    for (n = 0; n < WORKERS; n++)
        Threads[Count++] = CreateThread(NULL, 0, ChurnThread, (PVOID)n, 0, NULL);
    for (n = 0; n < 2; n++)
        Threads[Count++] = CreateThread(NULL, 0, QueryThread, (PVOID)n, 0, NULL);
    Threads[Count++] = CreateThread(NULL, 0, TableThread, NULL, 0, NULL);
    for (i = 0; i < Count; i++)
        ok(Threads[i] != NULL, "%s: CreateThread failed\n", What);

    Start = GetTickCount();
    while (GetTickCount() - Start < Millis)
        Sleep(100);
    InterlockedExchange(&g_Stop, 1);

    for (i = 0; i < Count; i++)
    {
        if (!Threads[i])
            continue;
        if (WaitForSingleObject(Threads[i], 30000) != WAIT_OBJECT_0)
            ok(0, "%s: thread %d does not end (in %s)\n", What, i, i < LISTENERS && !Peer ? g_Where[i] : "?");
        CloseHandle(Threads[i]);
    }

    for (i = 0; i < SLOTS; i++)
    {
        Old = g_Slots[i];
        if (Old != INVALID_SOCKET && Old != 0)
            closesocket(Old);
    }
    if (!Peer)
        closesocket(g_Target.Listener);

    trace("%s: %ld connects, %ld failed, %ld name queries, %ld option sets, %ld aborts, %ld table reads\n",
          What, g_Connects, g_Failed, g_Queries, g_Options, g_Aborts, g_Tables);
    ok(g_Connects > 0, "%s: no connection was made\n", What);

    CheckStillWorks(What);
}

/* The first unicast address of an adapter that is not loopback or link-local. IfIndex, when it is wanted, is
 * the IPv6 index of the first adapter that is up, with or without such an address, for a link-local scope */
static BOOL FindAdapterAddress(ULONG Family, SOCKADDR_STORAGE *Address, int *Length, ULONG *IfIndex)
{
    ULONG Size = 16384;
    PIP_ADAPTER_ADDRESSES Adapters, Adapter;
    PIP_ADAPTER_UNICAST_ADDRESS Unicast;
    BOOL Found = FALSE;

    Adapters = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Adapters)
        return FALSE;
    if (GetAdaptersAddresses(Family, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             NULL, Adapters, &Size) != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, Adapters);
        return FALSE;
    }
    for (Adapter = Adapters; Adapter && !Found; Adapter = Adapter->Next)
    {
        if (Adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || Adapter->OperStatus != IfOperStatusUp)
            continue;
        if (IfIndex && !*IfIndex)
            *IfIndex = Adapter->Ipv6IfIndex;
        for (Unicast = Adapter->FirstUnicastAddress; Unicast && !Found; Unicast = Unicast->Next)
        {
            PSOCKADDR Sock = Unicast->Address.lpSockaddr;

            /* an address that works without a scope: not link-local */
            if (Sock->sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)Sock)->sin6_addr))
                continue;
            memcpy(Address, Sock, Unicast->Address.iSockaddrLength);
            *Length = Unicast->Address.iSockaddrLength;
            Found = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Adapters);
    return Found;
}

/* A fault in this process is reported where it is, in module and offset, before the process ends: the run is long
 * and its output is a file, so nothing may stay in a buffer */
static LONG WINAPI ReportFault(PEXCEPTION_POINTERS Pointers)
{
    PVOID Base = NULL;
    char Module[MAX_PATH] = "?";

    RtlPcToFileHeader(Pointers->ExceptionRecord->ExceptionAddress, &Base);
    if (Base)
        GetModuleFileNameA(Base, Module, sizeof(Module));
    fprintf(stderr, "tcpchurn: exception %08lx at %p (%s+%lx), information %p %p\n",
            Pointers->ExceptionRecord->ExceptionCode, Pointers->ExceptionRecord->ExceptionAddress, Module,
            (ULONG)((ULONG_PTR)Pointers->ExceptionRecord->ExceptionAddress - (ULONG_PTR)Base),
            (PVOID)Pointers->ExceptionRecord->ExceptionInformation[0],
            (PVOID)Pointers->ExceptionRecord->ExceptionInformation[1]);
    fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}

START_TEST(tcpchurn)
{
    WSADATA Data;
    SOCKADDR_STORAGE Address;
    struct sockaddr_in Loop4;
    struct sockaddr_in6 Loop6;
    int Length;
    DWORD Seconds = 10, Slice;
    char Text[16], Peer[96];
    ULONG IfIndex = 0;
    SOCKET Probe;

    setvbuf(stdout, NULL, _IONBF, 0);
    SetUnhandledExceptionFilter(ReportFault);

    if (GetEnvironmentVariableA("TCPCHURN_SECONDS", Text, sizeof(Text)))
        Seconds = atoi(Text);
    if (!Seconds)
        Seconds = 10;
    Slice = Seconds * 1000 / 6;

    ok(WSAStartup(MAKEWORD(2, 2), &Data) == 0, "WSAStartup failed\n");

    memset(&Loop4, 0, sizeof(Loop4));
    Loop4.sin_family = AF_INET;
    Loop4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ChurnTarget(AF_INET, (PSOCKADDR)&Loop4, sizeof(Loop4), "IPv4 loopback", Slice, FALSE);

    if (FindAdapterAddress(AF_INET, &Address, &Length, NULL))
    {
        ((struct sockaddr_in *)&Address)->sin_port = 0;
        ChurnTarget(AF_INET, (PSOCKADDR)&Address, Length, "IPv4 adapter", Slice, FALSE);
    }
    else
    {
        skip("no IPv4 adapter address\n");
    }

    /* A listener on another machine, over the adapter: TCPCHURN_PEER4 is "a.b.c.d:port" */
    if (GetEnvironmentVariableA("TCPCHURN_PEER4", Peer, sizeof(Peer)))
    {
        Length = sizeof(Address);
        if (WSAStringToAddressA(Peer, AF_INET, NULL, (PSOCKADDR)&Address, &Length) == 0)
            ChurnTarget(AF_INET, (PSOCKADDR)&Address, Length, "IPv4 peer", Slice, TRUE);
        else
            ok(0, "bad TCPCHURN_PEER4 %s\n", Peer);
    }

    Probe = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (Probe == INVALID_SOCKET)
    {
        skip("no IPv6 sockets\n");
        WSACleanup();
        return;
    }
    closesocket(Probe);

    memset(&Loop6, 0, sizeof(Loop6));
    Loop6.sin6_family = AF_INET6;
    Loop6.sin6_addr.s6_addr[15] = 1;
    ChurnTarget(AF_INET6, (PSOCKADDR)&Loop6, sizeof(Loop6), "IPv6 loopback", Slice, FALSE);

    if (FindAdapterAddress(AF_INET6, &Address, &Length, &IfIndex))
    {
        ((struct sockaddr_in6 *)&Address)->sin6_port = 0;
        ChurnTarget(AF_INET6, (PSOCKADDR)&Address, Length, "IPv6 adapter", Slice, FALSE);
    }
    else
    {
        skip("no global IPv6 adapter address\n");
    }

    /* TCPCHURN_PEER6 is "[address]:port", a link-local address gets the scope of the first adapter */
    if (GetEnvironmentVariableA("TCPCHURN_PEER6", Peer, sizeof(Peer)))
    {
        Length = sizeof(Address);
        if (WSAStringToAddressA(Peer, AF_INET6, NULL, (PSOCKADDR)&Address, &Length) == 0)
        {
            struct sockaddr_in6 *Address6 = (struct sockaddr_in6 *)&Address;

            if (IN6_IS_ADDR_LINKLOCAL(&Address6->sin6_addr) && !Address6->sin6_scope_id)
                Address6->sin6_scope_id = IfIndex;
            ChurnTarget(AF_INET6, (PSOCKADDR)&Address, Length, "IPv6 peer", Slice, TRUE);
        }
        else
        {
            ok(0, "bad TCPCHURN_PEER6 %s\n", Peer);
        }
    }

    WSACleanup();
}
