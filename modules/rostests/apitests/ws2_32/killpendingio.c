/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Terminate processes that have named pipe, socket and I/O completion port I/O pending
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"
#include <ndk/extypes.h>
#include <ndk/exfuncs.h>

/*
 * The child opens named pipe pairs with overlapped reads and a listen pending,
 * loopback TCP connections with overlapped receives re-armed from an I/O
 * completion port while the parent streams data into them, threads blocked in
 * recv, and a UDP socket with a receive pending. The parent kills children
 * after a random delay, several at a time, and requires each to be gone in time:
 * process rundown must cancel and complete all of that I/O.
 */

#define KPI_ITERATIONS 60
#define KPI_CONCURRENT 3
#define KPI_MAX_DELAY_MS 300
#define KPI_PIPES 8
#define KPI_SOCKETS 8


#define KPI_SYSTEM_POOLTAG_CLASS 22
#define KPI_LWIP_TAG ('l' | ('w' << 8) | ('I' << 16) | ('P' << 24))
#define KPI_POOL_SLACK (4 * 1024 * 1024)

typedef LONG (WINAPI *PKPI_QUERY_SYSTEM_INFORMATION)(ULONG, PVOID, ULONG, PULONG);

typedef struct _KPI_POOL_TAG_ENTRY
{
    ULONG TagUlong;
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} KPI_POOL_TAG_ENTRY;

/* The non-paged pool bytes and outstanding allocations of one tag */
static
BOOL
KpiQueryPool(ULONG Tag, SIZE_T *Bytes, LONG *Allocations)
{
    static PKPI_QUERY_SYSTEM_INFORMATION pQuery;
    ULONG Size = 256 * 1024, Returned = 0, Count, i;
    PUCHAR Buffer;
    LONG Status;

    if (!pQuery)
        pQuery = (PKPI_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!pQuery)
        return FALSE;
    for (;;)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Buffer)
            return FALSE;
        Status = pQuery(KPI_SYSTEM_POOLTAG_CLASS, Buffer, Size, &Returned);
        if (Status != (LONG)0xC0000004 || Size >= 16 * 1024 * 1024)
            break;
        HeapFree(GetProcessHeap(), 0, Buffer);
        Size *= 2;
    }
    if (Status < 0)
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        return FALSE;
    }
    Count = *(PULONG)Buffer;
    *Bytes = 0;
    *Allocations = 0;
    for (i = 0; i < Count; i++)
    {
        KPI_POOL_TAG_ENTRY *Entry = (KPI_POOL_TAG_ENTRY *)(Buffer + sizeof(SIZE_T) + i * sizeof(KPI_POOL_TAG_ENTRY));
        if (Entry->TagUlong == Tag)
        {
            *Bytes += Entry->NonPagedUsed;
            *Allocations += (LONG)(Entry->NonPagedAllocs - Entry->NonPagedFrees);
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return TRUE;
}

static HANDLE ChildPort;
static SOCKET ListenSocket = INVALID_SOCKET;
static volatile LONG StopFeeding;

static
DWORD
WINAPI
ChildDrainThread(LPVOID Parameter)
{
    DWORD Bytes;
    ULONG_PTR Key;
    OVERLAPPED *Overlapped;

    for (;;)
    {
        Overlapped = NULL;
        if (!GetQueuedCompletionStatus(ChildPort, &Bytes, &Key, &Overlapped, INFINITE) && !Overlapped)
            Sleep(1);
        if (Overlapped && Key)
        {
            /* Re-arm a receive on the socket */
            WSABUF Buffer;
            DWORD Flags = 0;
            Buffer.buf = (char *)(Overlapped + 1);
            Buffer.len = 4096;
            ZeroMemory(Overlapped, sizeof(*Overlapped));
            WSARecv((SOCKET)Key, &Buffer, 1, NULL, &Flags, Overlapped, NULL);
        }
    }
    return 0;
}

static
DWORD
WINAPI
ChildBlockingRecvThread(LPVOID Parameter)
{
    char Buffer[4096];
    while (recv((SOCKET)Parameter, Buffer, sizeof(Buffer), 0) > 0);
    return 0;
}

static
DWORD
WINAPI
ChildPipeWriterThread(LPVOID Parameter)
{
    char Buffer[2048];
    DWORD Written;

    memset(Buffer, 'p', sizeof(Buffer));
    for (;;)
    {
        OVERLAPPED Overlapped = { 0 };
        Overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!WriteFile((HANDLE)Parameter, Buffer, sizeof(Buffer), &Written, &Overlapped) &&
            GetLastError() == ERROR_IO_PENDING)
        {
            WaitForSingleObject(Overlapped.hEvent, 50);
        }
        CloseHandle(Overlapped.hEvent);
    }
    return 0;
}

static
OVERLAPPED *
AllocOverlapped(void)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OVERLAPPED) + 4096);
}

static
void
RunChild(int Port, int Tag)
{
    WSADATA WsaData;
    struct sockaddr_in Address = { 0 };
    SOCKET Udp;
    WSABUF Buffer;
    DWORD Flags;
    OVERLAPPED *Overlapped;
    int i, j;

    WSAStartup(MAKEWORD(2, 2), &WsaData);
    ChildPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    for (i = 0; i < 2; i++)
        CloseHandle(CreateThread(NULL, 0, ChildDrainThread, NULL, 0, NULL));

    for (i = 0; i < KPI_PIPES; i++)
    {
        char Name[128];
        HANDLE Server, Listener, Client;

        sprintf(Name, "\\\\.\\pipe\\ws2_32_apitest_kpi_%lu_%d_%d", GetCurrentProcessId(), Tag, i);
        Server = CreateNamedPipeA(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE,
                                  PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
        Listener = CreateNamedPipeA(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE,
                                    PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
        /* Stays pending: nobody connects to this instance */
        ConnectNamedPipe(Listener, AllocOverlapped());
        Client = CreateFileA(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (Server == INVALID_HANDLE_VALUE || Client == INVALID_HANDLE_VALUE)
            continue;
        CreateIoCompletionPort(Server, ChildPort, 0, 0);
        CreateIoCompletionPort(Client, ChildPort, 0, 0);
        for (j = 0; j < 4; j++)
        {
            Overlapped = AllocOverlapped();
            ReadFile(Server, Overlapped + 1, 4096, NULL, Overlapped);
            Overlapped = AllocOverlapped();
            ReadFile(Client, Overlapped + 1, 4096, NULL, Overlapped);
        }
        if (i & 1)
            CloseHandle(CreateThread(NULL, 0, ChildPipeWriterThread, Client, 0, NULL));
    }

    Address.sin_family = AF_INET;
    Address.sin_port = htons((USHORT)Port);
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (i = 0; i < KPI_SOCKETS; i++)
    {
        char Data[1024];
        SOCKET Socket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);

        if (connect(Socket, (struct sockaddr *)&Address, sizeof(Address)))
        {
            closesocket(Socket);
            continue;
        }
        if (i % 4 == 3)
        {
            CloseHandle(CreateThread(NULL, 0, ChildBlockingRecvThread, (LPVOID)Socket, 0, NULL));
            continue;
        }
        CreateIoCompletionPort((HANDLE)Socket, ChildPort, (ULONG_PTR)Socket, 0);
        for (j = 0; j < 3; j++)
        {
            Overlapped = AllocOverlapped();
            Buffer.buf = (char *)(Overlapped + 1);
            Buffer.len = 4096;
            Flags = 0;
            WSARecv(Socket, &Buffer, 1, NULL, &Flags, Overlapped, NULL);
        }
        /* The parent reads little of this: its receive window fills */
        memset(Data, 'c', sizeof(Data));
        for (j = 0; j < 8; j++)
            send(Socket, Data, sizeof(Data), 0);
    }

    Udp = WSASocketA(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
    Address.sin_port = 0;
    bind(Udp, (struct sockaddr *)&Address, sizeof(Address));
    Overlapped = AllocOverlapped();
    Buffer.buf = (char *)(Overlapped + 1);
    Buffer.len = 4096;
    Flags = 0;
    WSARecvFrom(Udp, &Buffer, 1, NULL, &Flags, NULL, NULL, Overlapped, NULL);

    Sleep(INFINITE);
}

static
DWORD
WINAPI
FeederThread(LPVOID Parameter)
{
    SOCKET Socket = (SOCKET)Parameter;
    char Buffer[4096];
    u_long NonBlocking = 1;

    memset(Buffer, 'f', sizeof(Buffer));
    ioctlsocket(Socket, FIONBIO, &NonBlocking);
    while (!StopFeeding)
    {
        if (send(Socket, Buffer, sizeof(Buffer), 0) < 0)
        {
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                break;
            Sleep(1);
            recv(Socket, Buffer, sizeof(Buffer), 0);
        }
    }
    closesocket(Socket);
    return 0;
}

static
DWORD
WINAPI
AcceptorThread(LPVOID Parameter)
{
    for (;;)
    {
        HANDLE Thread;
        SOCKET Socket = accept(ListenSocket, NULL, NULL);

        if (Socket == INVALID_SOCKET)
        {
            if (StopFeeding)
                break;
            continue;
        }
        Thread = CreateThread(NULL, 0, FeederThread, (LPVOID)Socket, 0, NULL);
        if (Thread)
            CloseHandle(Thread);
        else
            closesocket(Socket);
    }
    return 0;
}

/* What the threads of a process that does not exit are waiting for */
static
void
KpiTraceThreads(DWORD Pid)
{
    ULONG Size = 512 * 1024, Done;
    PUCHAR Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
    PSYSTEM_PROCESS_INFORMATION Info;
    ULONG i;

    if (!Buffer)
        return;
    if (NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, &Done)))
    {
        for (Info = (PSYSTEM_PROCESS_INFORMATION)Buffer; ; Info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset))
        {
            if ((DWORD)(ULONG_PTR)Info->UniqueProcessId == Pid)
            {
                trace("process %lu: %lu threads\n", Pid, Info->NumberOfThreads);
                for (i = 0; i < Info->NumberOfThreads; i++)
                {
                    PSYSTEM_THREAD_INFORMATION Thread = (PSYSTEM_THREAD_INFORMATION)(Info + 1) + i;

                    trace("  thread %Iu: state %lu wait reason %lu\n", (ULONG_PTR)Thread->ClientId.UniqueThread,
                          (ULONG)Thread->ThreadState, (ULONG)Thread->WaitReason);
                }
                break;
            }
            if (!Info->NextEntryOffset)
                break;
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
}

static
void
KillChild(PROCESS_INFORMATION *Child, int *Killed)
{
    DWORD Wait, Begin = GetTickCount();

    ok(TerminateProcess(Child->hProcess, 1), "TerminateProcess failed: %lu\n", GetLastError());
    Wait = WaitForSingleObject(Child->hProcess, 5000);
    if (Wait != WAIT_OBJECT_0)
    {
        KpiTraceThreads(Child->dwProcessId);
        Wait = WaitForSingleObject(Child->hProcess, 25000);
    }
    if (GetTickCount() - Begin > 2000)
        trace("child %lu took %lu ms to exit\n", Child->dwProcessId, GetTickCount() - Begin);
    ok(Wait == WAIT_OBJECT_0, "Child %lu did not exit: %lu\n", Child->dwProcessId, Wait);
    CloseHandle(Child->hProcess);
    CloseHandle(Child->hThread);
    Child->hProcess = NULL;
    (*Killed)++;
}

/*
 * A receive with an event, on a socket associated with a completion port, that is pending when the thread
 * that issued it exits is cancelled (Windows 10 22H2, x86 and x64): the event is signalled and the port
 * gets a packet for the overlapped with ERROR_OPERATION_ABORTED. An event with the low bit set asks for
 * no packet.
 */
static SOCKET ExitSocket;
static OVERLAPPED ExitOverlapped;
static char ExitBuffer[16];

static
DWORD
WINAPI
ExitIssuerThread(LPVOID Parameter)
{
    WSABUF Buf = { sizeof(ExitBuffer), ExitBuffer };
    DWORD Flags = 0;

    /* Leave with the receive pending */
    WSARecv(ExitSocket, &Buf, 1, NULL, &Flags, &ExitOverlapped, NULL);
    return 0;
}

static
void
TestThreadExitEventPort(const char *Label, BOOL LowBit)
{
    SOCKET Listener, Client;
    struct sockaddr_in Addr = { 0 };
    int Len = sizeof(Addr);
    HANDLE Port, Event, Thread;
    DWORD Bytes = 0xdeadbeef, Error;
    ULONG_PTR Key = 0;
    OVERLAPPED *Got = NULL;
    BOOL Result;

    Addr.sin_family = AF_INET;
    Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Listener = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    Client = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (Listener == INVALID_SOCKET || Client == INVALID_SOCKET ||
        bind(Listener, (struct sockaddr *)&Addr, sizeof(Addr)) || listen(Listener, 1) ||
        getsockname(Listener, (struct sockaddr *)&Addr, &Len) ||
        connect(Client, (struct sockaddr *)&Addr, sizeof(Addr)))
    {
        skip("%s: socket setup failed: %d\n", Label, WSAGetLastError());
        goto Done;
    }
    ExitSocket = accept(Listener, NULL, NULL);
    ok(ExitSocket != INVALID_SOCKET, "%s: accept failed: %d\n", Label, WSAGetLastError());
    if (ExitSocket == INVALID_SOCKET)
        goto Done;

    Port = CreateIoCompletionPort((HANDLE)ExitSocket, NULL, 0x99, 0);
    ok(Port != NULL, "%s: CreateIoCompletionPort failed: %lu\n", Label, GetLastError());
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    ZeroMemory(&ExitOverlapped, sizeof(ExitOverlapped));
    ExitOverlapped.Internal = 0xcccccccc;
    ExitOverlapped.hEvent = LowBit ? (HANDLE)((ULONG_PTR)Event | 1) : Event;

    Thread = CreateThread(NULL, 0, ExitIssuerThread, NULL, 0, NULL);
    ok(Thread != NULL, "%s: CreateThread failed: %lu\n", Label, GetLastError());
    if (Thread)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    Sleep(200);

    ok(WaitForSingleObject(Event, 1000) == WAIT_OBJECT_0, "%s: the event is not signalled\n", Label);
    ok((ULONG)ExitOverlapped.Internal == 0xC0000120, "%s: Internal is %08lx\n", Label, (ULONG)ExitOverlapped.Internal);
    SetLastError(0xdeadbeef);
    Result = GetQueuedCompletionStatus(Port, &Bytes, &Key, &Got, LowBit ? 300 : 2000);
    Error = GetLastError();
    if (LowBit)
    {
        ok(!Result && Got == NULL && Error == WAIT_TIMEOUT, "%s: GetQueuedCompletionStatus %d, %p, error %lu\n", Label, Result, Got, Error);
    }
    else
    {
        ok(!Result && Got == &ExitOverlapped, "%s: GetQueuedCompletionStatus %d, %p\n", Label, Result, Got);
        ok(Error == ERROR_OPERATION_ABORTED, "%s: error %lu\n", Label, Error);
        ok(Key == 0x99, "%s: key %Ix\n", Label, Key);
        ok(Bytes == 0, "%s: bytes %lu\n", Label, Bytes);
    }

    CloseHandle(Event);
    if (Port)
        CloseHandle(Port);
    closesocket(ExitSocket);
Done:
    if (Client != INVALID_SOCKET)
        closesocket(Client);
    if (Listener != INVALID_SOCKET)
        closesocket(Listener);
}

START_TEST(killpendingio)
{
    WSADATA WsaData;
    struct sockaddr_in Address = { 0 };
    int AddressLength = sizeof(Address);
    PROCESS_INFORMATION Children[KPI_CONCURRENT] = { { 0 } };
    char **Argv, CommandLine[MAX_PATH + 64];
    HANDLE Acceptor;
    DWORD Start;
    int Argc, i, Slot, Killed = 0, Started = 0;
    SIZE_T BytesBefore = 0, BytesAfter = 0, BytesPeak = 0, BytesNow;
    LONG AllocsBefore = 0, AllocsAfter = 0, AllocsNow;
    BOOL PoolOk;

    Argc = winetest_get_mainargs(&Argv);
    if (Argc >= 5 && !strcmp(Argv[2], "child"))
    {
        RunChild(atoi(Argv[3]), atoi(Argv[4]));
        return;
    }

    ok_int(WSAStartup(MAKEWORD(2, 2), &WsaData), 0);
    TestThreadExitEventPort("thread exit, port+event", FALSE);
    TestThreadExitEventPort("thread exit, port+event|1", TRUE);
    ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
    Address.sin_family = AF_INET;
    Address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ListenSocket == INVALID_SOCKET ||
        bind(ListenSocket, (struct sockaddr *)&Address, sizeof(Address)) ||
        listen(ListenSocket, 64) ||
        getsockname(ListenSocket, (struct sockaddr *)&Address, &AddressLength))
    {
        skip("Listening on loopback failed: %d\n", WSAGetLastError());
        if (ListenSocket != INVALID_SOCKET)
            closesocket(ListenSocket);
        WSACleanup();
        return;
    }
    Acceptor = CreateThread(NULL, 0, AcceptorThread, NULL, 0, NULL);
    ok(Acceptor != NULL, "CreateThread failed: %lu\n", GetLastError());

    PoolOk = KpiQueryPool(KPI_LWIP_TAG, &BytesBefore, &AllocsBefore);
    srand(GetTickCount());
    Start = GetTickCount();
    for (i = 0; i < KPI_ITERATIONS; i++)
    {
        STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };

        Slot = i % KPI_CONCURRENT;
        if (Children[Slot].hProcess)
            KillChild(&Children[Slot], &Killed);
        if (PoolOk && KpiQueryPool(KPI_LWIP_TAG, &BytesNow, &AllocsNow) && BytesNow > BytesPeak)
            BytesPeak = BytesNow;

        sprintf(CommandLine, "\"%s\" killpendingio child %d %d", Argv[0], ntohs(Address.sin_port), i);
        if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                            &StartupInfo, &Children[Slot]))
        {
            ok(0, "CreateProcess failed: %lu\n", GetLastError());
            Children[Slot].hProcess = NULL;
            break;
        }
        Started++;
        Sleep(20 + rand() % (KPI_MAX_DELAY_MS / KPI_CONCURRENT + 1));
    }
    for (Slot = 0; Slot < KPI_CONCURRENT; Slot++)
    {
        if (Children[Slot].hProcess)
            KillChild(&Children[Slot], &Killed);
    }

    ok_int(Killed, Started);
    trace("%d children killed in %lu ms\n", Killed, GetTickCount() - Start);

    StopFeeding = 1;
    closesocket(ListenSocket);
    if (Acceptor)
    {
        ok(WaitForSingleObject(Acceptor, 10000) == WAIT_OBJECT_0, "Acceptor thread did not exit\n");
        CloseHandle(Acceptor);
    }

    /* Every connection of a killed child is gone: what lwIP holds for them goes back to the pool */
    if (PoolOk)
    {
        Sleep(5000);
        if (KpiQueryPool(KPI_LWIP_TAG, &BytesAfter, &AllocsAfter))
        {
            trace("lwIP pool: before %Iu bytes / %ld allocations, peak %Iu bytes, after %Iu bytes / %ld allocations\n",
                  BytesBefore, AllocsBefore, BytesPeak, BytesAfter, AllocsAfter);
            ok(BytesAfter <= BytesBefore + KPI_POOL_SLACK,
               "lwIP pool grew from %Iu to %Iu bytes after %d killed children\n", BytesBefore, BytesAfter, Killed);
        }
    }
    WSACleanup();
}
