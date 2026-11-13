/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Measure the longest loopback connect while a thread accepts, in the first seconds after boot
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#include "ws2_32.h"

/* The window after boot in which connects are timed, and the longest connect that is tolerated.
 * A connect the server has not answered is retried by the client's TCP after seconds, so anything
 * near a second means a SYN was dropped.
 *
 * One connecting thread against one accepting thread must never wait for a retransmitted SYN. With
 * ACCEPTLAG_CLIENTS=n (n > 1) several threads connect against the one that accepts; they can get
 * ahead of it by the whole backlog, and tcpip then drops the SYN as designed (a full backlog), so
 * that mode only reports the numbers. ACCEPTLAG_DELAY=ms waits before the loop starts. */
#define WINDOW_END_MS   30000
#define MIN_RUN_MS      3000
#define MAX_RUN_MS      40000
#define MAX_CONNECTS    12000 /* stay well below the ephemeral port range */
#define LIMIT_MS        1000

static volatile LONG StopAccept;
static volatile LONG Accepted;

static DWORD WINAPI
AcceptThread(PVOID Param)
{
    SOCKET Server = (SOCKET)(ULONG_PTR)Param;

    while (!StopAccept)
    {
        SOCKET Client = accept(Server, NULL, NULL);
        if (Client == INVALID_SOCKET)
            break;
        InterlockedIncrement(&Accepted);
        closesocket(Client);
    }
    return 0;
}


#define MAX_CLIENTS 16

static int ClientCount = 1;

static struct sockaddr_in ServerAddr;
static LARGE_INTEGER Freq;
static DWORD BeginTick;
static volatile LONG Connects, Failures, SlowCount;
static volatile LONG MaxMs, MaxAtMs;

static DWORD WINAPI
ClientThread(PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    for (;;)
    {
        LARGE_INTEGER T0, T1;
        SOCKET Client;
        DWORD Uptime = GetTickCount(), Elapsed = Uptime - BeginTick;
        LONG Ms;

        if (Connects + Failures >= MAX_CONNECTS || Elapsed >= MAX_RUN_MS || (Elapsed >= MIN_RUN_MS && Uptime >= WINDOW_END_MS))
            break;

        Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (Client == INVALID_SOCKET)
        {
            InterlockedIncrement(&Failures);
            break;
        }
        QueryPerformanceCounter(&T0);
        if (connect(Client, (struct sockaddr *)&ServerAddr, sizeof(ServerAddr)) != 0)
        {
            if (InterlockedIncrement(&Failures) <= 3)
                trace("connect failed: %d\n", WSAGetLastError());
        }
        else
            InterlockedIncrement(&Connects);
        QueryPerformanceCounter(&T1);
        Ms = (LONG)((T1.QuadPart - T0.QuadPart) * 1000 / Freq.QuadPart);
        if (Ms > LIMIT_MS)
        {
            InterlockedIncrement(&SlowCount);
            trace("connect took %ld ms at %lu ms after boot\n", Ms, Uptime);
        }
        if (Ms > MaxMs)
        {
            MaxMs = Ms;
            MaxAtMs = (LONG)Uptime;
        }
        closesocket(Client);
    }
    return 0;
}

START_TEST(acceptlag)
{
    WSADATA WsaData;
    SOCKET Server;
    int AddrLen = sizeof(ServerAddr), i;
    HANDLE Thread, Clients[MAX_CLIENTS];
    char Env[16];

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        skip("WSAStartup failed\n");
        return;
    }
    QueryPerformanceFrequency(&Freq);
    if (GetEnvironmentVariableA("ACCEPTLAG_DELAY", Env, sizeof(Env)) && atoi(Env) > 0)
        Sleep(atoi(Env));
    if (GetEnvironmentVariableA("ACCEPTLAG_CLIENTS", Env, sizeof(Env)) && atoi(Env) > 0)
        ClientCount = min(atoi(Env), MAX_CLIENTS);

    Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ok(Server != INVALID_SOCKET, "socket failed: %d\n", WSAGetLastError());
    ZeroMemory(&ServerAddr, sizeof(ServerAddr));
    ServerAddr.sin_family = AF_INET;
    ServerAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ok(bind(Server, (struct sockaddr *)&ServerAddr, sizeof(ServerAddr)) == 0, "bind failed: %d\n", WSAGetLastError());
    ok(getsockname(Server, (struct sockaddr *)&ServerAddr, &AddrLen) == 0, "getsockname failed: %d\n", WSAGetLastError());
    ok(listen(Server, SOMAXCONN) == 0, "listen failed: %d\n", WSAGetLastError());
    Thread = CreateThread(NULL, 0, AcceptThread, (PVOID)(ULONG_PTR)Server, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());

    /* Connect back to back until the system is WINDOW_END_MS old, but for at least MIN_RUN_MS */
    BeginTick = GetTickCount();
    trace("Started %lu ms after boot\n", BeginTick);
    for (i = 0; i < ClientCount; i++)
        Clients[i] = CreateThread(NULL, 0, ClientThread, NULL, 0, NULL);
    WaitForMultipleObjects(ClientCount, Clients, TRUE, MAX_RUN_MS + 60000);
    for (i = 0; i < ClientCount; i++)
        CloseHandle(Clients[i]);

    trace("%ld connects in %lu ms, %ld accepted, max connect %ld ms at %ld ms after boot, %ld slower than %u ms\n",
          Connects, GetTickCount() - BeginTick, Accepted, MaxMs, MaxAtMs, SlowCount, LIMIT_MS);
    printf("ACCEPTLAG start=%lu connects=%ld maxms=%ld at=%ld slow=%ld failed=%ld\n",
           BeginTick, Connects, MaxMs, MaxAtMs, SlowCount, Failures);
    if (ClientCount == 1)
    {
        ok(Failures == 0, "%ld connects failed\n", Failures);
        ok(MaxMs <= LIMIT_MS, "longest connect took %ld ms (at %ld ms after boot), the listener did not answer a SYN\n", MaxMs, MaxAtMs);
    }

    InterlockedExchange(&StopAccept, 1);
    closesocket(Server);
    if (Thread)
    {
        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
    }
    WSACleanup();
}
