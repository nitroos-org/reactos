/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Several threads resolving at the same instant. Every thread that asks for a name that exists
 *              must get an address, however many others ask at the same time, whether the name is the same,
 *              each has its own, or it was cached already (Qt resolves one host from two threads at once).
 *              ws2_32_apitest gaiconcurrent [rounds [threads]]: the default is a short run, a soak takes
 *              several hundred rounds.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "ws2_32.h"

#define MAX_THREADS 16

/* nip.io answers every <label>.a.b.c.d.nip.io with a.b.c.d, so each round can use a name nobody has asked for
   (a label that ends in -<digits> is read as part of the address: keep digits away from dashes) */
#define ADDRESS_SUFFIX  "10.20.30.40.nip.io"
#define ADDRESS_VALUE   "10.20.30.40"

typedef enum { MODE_SAME_FRESH, MODE_DISTINCT_FRESH, MODE_SAME_CACHED, MODE_MIXED, MODE_DNSAPI, MODE_COUNT } RMODE;

static const char *ModeName[MODE_COUNT] = { "same fresh name", "distinct fresh names", "same cached name", "gethostbyname and getaddrinfo", "DnsQuery_A" };

static LONG g_Threads;
static LONG g_Round;
static RMODE g_Mode;
static ULONG g_Nonce;
static HANDLE g_Start[MAX_THREADS];
static HANDLE g_Done[MAX_THREADS];
static volatile LONG g_Quit;
static volatile LONG g_Failures[MODE_COUNT];
static volatile LONG g_Calls;
static char g_Message[MAX_THREADS][160];
static char g_Cached[128];

static
void
NameFor(char *Buffer, size_t Size, RMODE Mode, LONG Round, LONG Thread)
{
    if (Mode == MODE_SAME_CACHED)
        lstrcpynA(Buffer, g_Cached, (int)Size);
    else if (Mode == MODE_DISTINCT_FRESH)
        _snprintf(Buffer, Size, "d%lxk%lxr%ldt%ld.%s", g_Nonce, GetTickCount(), Round, Thread, ADDRESS_SUFFIX);
    else
        _snprintf(Buffer, Size, "s%lxr%ldm%ld.%s", g_Nonce, Round, (long)Mode, ADDRESS_SUFFIX);
    Buffer[Size - 1] = '\0';
}

static
BOOL
CheckAddress(const struct addrinfo *Info)
{
    for (; Info; Info = Info->ai_next)
    {
        if (Info->ai_family == AF_INET &&
            ((struct sockaddr_in *)Info->ai_addr)->sin_addr.s_addr == inet_addr(ADDRESS_VALUE))
            return TRUE;
    }
    return FALSE;
}

static
DWORD
WINAPI
Worker(LPVOID Context)
{
    LONG Id = (LONG)(LONG_PTR)Context;

    for (;;)
    {
        char Name[160];
        struct addrinfo Hints, *Result = NULL;
        BOOL Good;
        int Error = 0;
        RMODE Mode;

        WaitForSingleObject(g_Start[Id], INFINITE);
        if (g_Quit)
            break;

        Mode = g_Mode;
        NameFor(Name, sizeof(Name), Mode, g_Round, Id);
        g_Message[Id][0] = '\0';

        if (Mode == MODE_DNSAPI)
        {
            /* The resolver without Winsock around it: what status does the failing caller see? */
            typedef LONG (WINAPI *DNSQUERY_A)(const char *, WORD, DWORD, PVOID, PVOID *, PVOID *);
            static DNSQUERY_A Query;
            static void (WINAPI *Free)(PVOID, int);
            PVOID Records = NULL;
            LONG Status;

            if (!Query)
            {
                HMODULE Dns = LoadLibraryA("dnsapi.dll");
                Query = (DNSQUERY_A)GetProcAddress(Dns, "DnsQuery_A");
                Free = (void (WINAPI *)(PVOID, int))GetProcAddress(Dns, "DnsRecordListFree");
            }
            Status = Query(Name, 1 /* DNS_TYPE_A */, 0, NULL, &Records, NULL);
            Good = Status == 0 && Records != NULL;
            Error = Status;
            if (Records)
                Free(Records, 1 /* DnsFreeRecordList */);
        }
        else if (Mode == MODE_MIXED && (Id & 1))
        {
            struct hostent *Host = gethostbyname(Name);

            Good = Host && Host->h_addrtype == AF_INET && Host->h_addr_list[0] &&
                   ((struct in_addr *)Host->h_addr_list[0])->s_addr == inet_addr(ADDRESS_VALUE);
            if (!Good)
                Error = WSAGetLastError();
        }
        else
        {
            ZeroMemory(&Hints, sizeof(Hints));
            Hints.ai_family = AF_UNSPEC;
            Hints.ai_socktype = SOCK_STREAM;
            Error = getaddrinfo(Name, "80", &Hints, &Result);
            Good = Error == 0 && CheckAddress(Result);
            if (Result)
                freeaddrinfo(Result);
        }
        InterlockedIncrement(&g_Calls);
        if (!Good)
            _snprintf(g_Message[Id], sizeof(g_Message[Id]), "thread %ld round %ld %s: %s error %d",
                      Id, g_Round, ModeName[Mode], Name, Error);
        SetEvent(g_Done[Id]);
    }
    return 0;
}

static
BOOL
TryOnce(const char *Name)
{
    struct addrinfo Hints, *Result = NULL;
    BOOL Good;

    ZeroMemory(&Hints, sizeof(Hints));
    Hints.ai_family = AF_UNSPEC;
    Hints.ai_socktype = SOCK_STREAM;
    Good = getaddrinfo(Name, "80", &Hints, &Result) == 0 && CheckAddress(Result);
    if (Result)
        freeaddrinfo(Result);
    return Good;
}

START_TEST(gaiconcurrent)
{
    WSADATA WsaData;
    HANDLE Threads[MAX_THREADS];
    LONG Rounds = 12, Index, Round;
    RMODE Mode;
    char Name[160];
    const char *Arguments = GetCommandLineA();
    LONG Total = 0;

    /* Arguments after the test name: rounds, threads */
    g_Threads = 6;
    {
        int Count = 0;
        const char *p = Arguments;
        long Values[2] = { 0, 0 };

        while (*p)
        {
            while (*p == ' ') p++;
            if (!*p) break;
            if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; }
            else while (*p && *p != ' ') p++;
            Count++;
            if (Count >= 3 && Count <= 4)
            {
                const char *q = p;
                while (q > Arguments && q[-1] != ' ') q--;
                Values[Count - 3] = atol(q);
            }
        }
        if (Values[0] > 0) Rounds = Values[0];
        if (Values[1] > 1 && Values[1] <= MAX_THREADS) g_Threads = Values[1];
    }

    ok_dec(WSAStartup(MAKEWORD(2, 2), &WsaData), 0);
    g_Nonce = GetCurrentProcessId() ^ (GetTickCount() << 8);

    /* Needs the network: one name outside the cache first */
    _snprintf(Name, sizeof(Name), "w%lx.%s", g_Nonce, ADDRESS_SUFFIX);
    /* A machine that has just started may not have its address and name server yet */
    for (Index = 0; Index < 40 && !TryOnce(Name); Index++)
        Sleep(1000);
    if (Index == 40)
    {
        skip("The wildcard name did not resolve (no network)\n");
        WSACleanup();
        return;
    }
    _snprintf(g_Cached, sizeof(g_Cached), "c%lx.%s", g_Nonce, ADDRESS_SUFFIX);
    TryOnce(g_Cached);

    for (Index = 0; Index < g_Threads; Index++)
    {
        g_Start[Index] = CreateEventW(NULL, FALSE, FALSE, NULL);
        g_Done[Index] = CreateEventW(NULL, FALSE, FALSE, NULL);
        Threads[Index] = CreateThread(NULL, 0, Worker, (LPVOID)(LONG_PTR)Index, 0, NULL);
    }

    for (Round = 0; Round < Rounds; Round++)
    {
        for (Mode = 0; Mode < MODE_COUNT; Mode++)
        {
            g_Round = Round;
            g_Mode = Mode;
            /* Every thread is parked on its event: release them together */
            for (Index = 0; Index < g_Threads; Index++)
                SetEvent(g_Start[Index]);
            WaitForMultipleObjects(g_Threads, g_Done, TRUE, 60000);
            for (Index = 0; Index < g_Threads; Index++)
            {
                if (g_Message[Index][0])
                {
                    InterlockedIncrement(&g_Failures[Mode]);
                    ok(0, "%s\n", g_Message[Index]);
                    g_Message[Index][0] = '\0';
                }
            }
        }
    }

    g_Quit = 1;
    for (Index = 0; Index < g_Threads; Index++)
        SetEvent(g_Start[Index]);
    WaitForMultipleObjects(g_Threads, Threads, TRUE, 30000);
    for (Index = 0; Index < g_Threads; Index++)
    {
        CloseHandle(Threads[Index]);
        CloseHandle(g_Start[Index]);
        CloseHandle(g_Done[Index]);
    }

    for (Mode = 0; Mode < MODE_COUNT; Mode++)
    {
        Total += g_Failures[Mode];
        printf("GAICONC %s: %ld failed\n", ModeName[Mode], g_Failures[Mode]);
    }
    printf("GAICONC rounds=%ld threads=%ld calls=%ld failures=%ld\n", Rounds, g_Threads, g_Calls, Total);
    ok_dec(WSACleanup(), 0);
}
