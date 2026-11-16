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

START_TEST(memleak)
{
    WSADATA WsaData;
    SOCKET Probe;
    BOOL HaveIpv6;

    Measure("WSAStartup+WSACleanup", CycleStartup, 0, 0);
    Measure("WSAStartup+socket(AF_INET)+WSACleanup", StartupSocketCleanup, AF_INET, SOCK_DGRAM);

    ok(WSAStartup(MAKEWORD(2, 2), &WsaData) == 0, "WSAStartup failed\n");
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
