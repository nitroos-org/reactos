/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     WSAStartup/WSACleanup cycles and socket/closesocket pairs must not grow the process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#define WARMUP      200
#define ITERATIONS  10000
/* Averaged over ITERATIONS: below 1 byte per iteration */
#define MAX_GROWTH  ITERATIONS

typedef struct
{
    ULONGLONG HeapBytes;
    DWORD Handles;
} MEM_SNAPSHOT;

static
VOID
Snapshot(MEM_SNAPSHOT *Snap)
{
    HANDLE Heaps[64];
    DWORD Count, i;

    Snap->HeapBytes = 0;
    Snap->Handles = 0;
    GetProcessHandleCount(GetCurrentProcess(), &Snap->Handles);
    Count = GetProcessHeaps(_countof(Heaps), Heaps);
    if (Count > _countof(Heaps))
        Count = _countof(Heaps);
    for (i = 0; i < Count; i++)
    {
        PROCESS_HEAP_ENTRY Entry;

        Entry.lpData = NULL;
        if (!HeapLock(Heaps[i]))
            continue;
        while (HeapWalk(Heaps[i], &Entry))
        {
            if (Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
                Snap->HeapBytes += Entry.cbData;
        }
        HeapUnlock(Heaps[i]);
    }
}

typedef VOID (*ITERATION)(INT Family, INT Type);

static
VOID
CycleStartup(INT Family, INT Type)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) == 0)
        WSACleanup();
}

static
VOID
SocketPair(INT Family, INT Type)
{
    SOCKET Sock = socket(Family, Type, 0);

    if (Sock != INVALID_SOCKET)
        closesocket(Sock);
}

static
VOID
StartupSocketCleanup(INT Family, INT Type)
{
    WSADATA WsaData;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) == 0)
    {
        SocketPair(Family, Type);
        WSACleanup();
    }
}

static
VOID
Measure(const char *Name, ITERATION Iteration, INT Family, INT Type)
{
    MEM_SNAPSHOT Before, After;
    ULONG i;
    LONGLONG Growth;

    for (i = 0; i < WARMUP; i++)
        Iteration(Family, Type);
    Snapshot(&Before);
    for (i = 0; i < ITERATIONS; i++)
        Iteration(Family, Type);
    Snapshot(&After);

    Growth = (LONGLONG)After.HeapBytes - (LONGLONG)Before.HeapBytes;
    ok(Growth < MAX_GROWTH, "%s: heap grew by %I64d bytes in %d iterations\n", Name, Growth, ITERATIONS);
    ok(After.Handles <= Before.Handles + 2, "%s: handles %lu -> %lu\n", Name, Before.Handles, After.Handles);
}

/* A socket left open across the last WSACleanup: the provider and its helper are unloaded and loaded again,
 * the next socket works, and closing the old handle afterwards does not crash (Windows closes it in WSACleanup) */
static
VOID
SocketOutlivesCleanup(VOID)
{
    WSADATA WsaData;
    SOCKET Old, New;
    struct sockaddr_in Addr;
    int AddrLen = sizeof(Addr);
    char Buffer[8];
    DWORD Timeout = 5000;

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");
    Old = socket(AF_INET, SOCK_DGRAM, 0);
    ok(Old != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    ok(WSACleanup() == 0, "WSACleanup failed: %d\n", WSAGetLastError());

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");
    New = socket(AF_INET, SOCK_DGRAM, 0);
    ok(New != INVALID_SOCKET, "socket after WSACleanup failed: %d\n", WSAGetLastError());
    if (New != INVALID_SOCKET)
    {
        ZeroMemory(&Addr, sizeof(Addr));
        Addr.sin_family = AF_INET;
        Addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ok(bind(New, (struct sockaddr *)&Addr, sizeof(Addr)) == 0, "bind failed: %d\n", WSAGetLastError());
        ok(getsockname(New, (struct sockaddr *)&Addr, &AddrLen) == 0, "getsockname failed: %d\n", WSAGetLastError());
        setsockopt(New, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Timeout, sizeof(Timeout));
        ok(sendto(New, "ping", 4, 0, (struct sockaddr *)&Addr, sizeof(Addr)) == 4, "sendto failed: %d\n", WSAGetLastError());
        ok(recv(New, Buffer, sizeof(Buffer), 0) == 4, "recv failed: %d\n", WSAGetLastError());
        closesocket(New);
    }
    if (Old != INVALID_SOCKET)
        closesocket(Old);
    WSACleanup();
}

#define CYCLE_THREADS       4
#define CYCLE_PER_THREAD    500

static LONG CycleFailures;

static
DWORD
WINAPI
CycleThread(PVOID Param)
{
    WSADATA WsaData;
    SOCKET Sock;
    ULONG i;

    for (i = 0; i < CYCLE_PER_THREAD; i++)
    {
        if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
        {
            InterlockedIncrement(&CycleFailures);
            continue;
        }
        Sock = socket(AF_INET, (i & 1) ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (Sock == INVALID_SOCKET)
            InterlockedIncrement(&CycleFailures);
        else
            closesocket(Sock);
        WSACleanup();
    }
    return 0;
}

/* Threads that start, make a socket and clean up concurrently: the provider is unloaded and loaded again
 * while other threads make sockets */
static
VOID
ParallelCycles(VOID)
{
    HANDLE Threads[CYCLE_THREADS];
    DWORD i, Started = 0, Wait;

    CycleFailures = 0;
    for (i = 0; i < CYCLE_THREADS; i++)
    {
        Threads[Started] = CreateThread(NULL, 0, CycleThread, NULL, 0, NULL);
        if (Threads[Started])
            Started++;
    }
    ok(Started == CYCLE_THREADS, "started %lu threads\n", Started);
    Wait = WaitForMultipleObjects(Started, Threads, TRUE, 120000);
    ok(Wait < WAIT_OBJECT_0 + Started, "threads did not end: %lu\n", Wait);
    ok(CycleFailures == 0, "%ld of %d startups or sockets failed\n", CycleFailures, CYCLE_THREADS * CYCLE_PER_THREAD);
    for (i = 0; i < Started; i++)
        CloseHandle(Threads[i]);
}

START_TEST(memleak)
{
    WSADATA WsaData;
    SOCKET Probe;
    BOOL HaveIpv6;

    SocketOutlivesCleanup();
    ParallelCycles();

    Measure("WSAStartup+WSACleanup", CycleStartup, 0, 0);
    Measure("WSAStartup+socket(AF_INET)+WSACleanup", StartupSocketCleanup, AF_INET, SOCK_DGRAM);

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");
    /* The namespace catalog was freed and read again in every cycle: its display strings are intact */
    {
        static BYTE Buffer[16384];
        DWORD Length = sizeof(Buffer);
        LPWSANAMESPACE_INFOW Info = (LPWSANAMESPACE_INFOW)Buffer;
        INT Count, i;

        Count = WSAEnumNameSpaceProvidersW(&Length, Info);
        ok(Count > 0, "WSAEnumNameSpaceProvidersW: %d, error %d\n", Count, WSAGetLastError());
        for (i = 0; i < Count; i++)
        {
            ok(Info[i].lpszIdentifier && Info[i].lpszIdentifier[0] &&
               (PBYTE)Info[i].lpszIdentifier >= Buffer && (PBYTE)Info[i].lpszIdentifier < Buffer + sizeof(Buffer),
               "provider %d: bad identifier\n", i);
        }
    }
    Measure("socket(AF_INET, SOCK_STREAM)", SocketPair, AF_INET, SOCK_STREAM);
    Measure("socket(AF_INET, SOCK_DGRAM)", SocketPair, AF_INET, SOCK_DGRAM);
    Probe = socket(AF_INET6, SOCK_DGRAM, 0);
    HaveIpv6 = Probe != INVALID_SOCKET;
    if (HaveIpv6)
        closesocket(Probe);
    if (HaveIpv6)
    {
        Measure("socket(AF_INET6, SOCK_STREAM)", SocketPair, AF_INET6, SOCK_STREAM);
        Measure("socket(AF_INET6, SOCK_DGRAM)", SocketPair, AF_INET6, SOCK_DGRAM);
    }
    else
    {
        skip("no IPv6 sockets\n");
    }
    WSACleanup();
}
