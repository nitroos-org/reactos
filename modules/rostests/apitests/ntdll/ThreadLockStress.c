/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Stress of the scheduler paths that take a thread's lock while other processors wake it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Pairs of threads wake each other through semaphores and events (the unwait and deferred-ready path that takes the
 * woken thread's lock), while other threads query their base priority (NtQueryInformationThread, which locks the
 * thread), change their priority, boost setting, affinity and their process's priority class, suspend and resume them,
 * and create and terminate short-lived threads (a terminating thread has its priority set); two threads create
 * processes in a loop, so they wait in their subsystem (CSR) call while they are queried and reprioritised. On a multiprocessor this
 * must neither hang nor bug check, every helper must stop and every pair must have made progress.
 * Duration: THREADLOCKSTRESS_SECONDS (default 30).
 */

#include "precomp.h"

#define PAIRS 6
#define STOP_WAIT_MS 30000

typedef struct _PAIR
{
    HANDLE Sem[2];
    HANDLE Event[2];
    HANDLE Thread[2];
    volatile LONG Rounds;
} PAIR, *PPAIR;

typedef struct _SIDE
{
    PPAIR Pair;
    ULONG Side;
} SIDE, *PSIDE;

#define SPAWNERS 2

static PAIR Pairs[PAIRS];
static HANDLE Spawners[SPAWNERS];
static volatile LONG Spawned;
static WCHAR SelfPath[MAX_PATH];
static SIDE Sides[PAIRS][2];
static volatile LONG Stop;
static volatile LONG Queries, PriorityChanges, ClassChanges, Suspends, AffinityChanges, Churned;
static ULONG Seed = 0x2545F491;
static DWORD_PTR AllMask;

static ULONG Rand(VOID)
{
    /* Racy on purpose; any value is fine */
    Seed = Seed * 1103515245 + 12345;
    return Seed >> 8;
}

static DWORD WINAPI PairThread(PVOID Param)
{
    PSIDE Side = Param;
    PPAIR Pair = Side->Pair;
    ULONG Me = Side->Side, Other = Side->Side ^ 1;

    while (!Stop)
    {
        /* Semaphore round (as an LPC reply), then an event round */
        if (WaitForSingleObject(Pair->Sem[Me], 50) == WAIT_OBJECT_0)
        {
            InterlockedIncrement(&Pair->Rounds);
            ReleaseSemaphore(Pair->Sem[Other], 1, NULL);
        }
        if (WaitForSingleObject(Pair->Event[Me], 50) == WAIT_OBJECT_0)
        {
            SetEvent(Pair->Event[Other]);
        }
        if (!(Rand() & 255)) SwitchToThread();
    }
    /* Let the other side out of its wait */
    ReleaseSemaphore(Pair->Sem[Other], 1, NULL);
    SetEvent(Pair->Event[Other]);
    return 0;
}

static HANDLE AnyPairThread(VOID)
{
    ULONG i = Rand() % (PAIRS * 2);
    return Pairs[i / 2].Thread[i & 1];
}

/* A pair thread, or (for the queries and priority changes) a thread that is
   creating a process and waits in its call to the subsystem */
static HANDLE AnyTargetThread(VOID)
{
    ULONG i = Rand() % (PAIRS * 2 + SPAWNERS);
    if (i >= PAIRS * 2 && Spawners[i - PAIRS * 2]) return Spawners[i - PAIRS * 2];
    return AnyPairThread();
}

static DWORD WINAPI SpawnThread(PVOID Param)
{
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    WCHAR CmdLine[MAX_PATH + 32];

    UNREFERENCED_PARAMETER(Param);
    /* The child runs no test (unknown name) and exits at once */
    _snwprintf(CmdLine, ARRAYSIZE(CmdLine), L"\"%s\" ThreadLockStressNoSuchTest", SelfPath);
    while (!Stop)
    {
        if (CreateProcessW(SelfPath, CmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &Si, &Pi))
        {
            WaitForSingleObject(Pi.hProcess, STOP_WAIT_MS);
            CloseHandle(Pi.hThread);
            CloseHandle(Pi.hProcess);
            InterlockedIncrement(&Spawned);
        }
    }
    return 0;
}

static DWORD WINAPI QueryThread(PVOID Param)
{
    THREAD_BASIC_INFORMATION Info;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Param);
    while (!Stop)
    {
        Status = NtQueryInformationThread(AnyTargetThread(), ThreadBasicInformation, &Info, sizeof(Info), NULL);
        if (NT_SUCCESS(Status)) InterlockedIncrement(&Queries);
    }
    return 0;
}

static DWORD WINAPI PriorityThread(PVOID Param)
{
    static const int Levels[] = { THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
                                  THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST };
    HANDLE Thread;

    UNREFERENCED_PARAMETER(Param);
    while (!Stop)
    {
        Thread = AnyTargetThread();
        SetThreadPriority(Thread, Levels[Rand() % ARRAYSIZE(Levels)]);
        SetThreadPriorityBoost(Thread, (Rand() & 1) != 0);
        InterlockedIncrement(&PriorityChanges);
    }
    return 0;
}

static DWORD WINAPI ClassThread(PVOID Param)
{
    static const DWORD Classes[] = { NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, ABOVE_NORMAL_PRIORITY_CLASS,
                                     IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS };

    UNREFERENCED_PARAMETER(Param);
    while (!Stop)
    {
        SetPriorityClass(GetCurrentProcess(), Classes[Rand() % ARRAYSIZE(Classes)]);
        InterlockedIncrement(&ClassChanges);
        Sleep(Rand() % 3);
    }
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    return 0;
}

static DWORD WINAPI SuspendThreadProc(PVOID Param)
{
    HANDLE Thread;

    UNREFERENCED_PARAMETER(Param);
    while (!Stop)
    {
        Thread = AnyPairThread();
        if (SuspendThread(Thread) != (DWORD)-1)
        {
            if (Rand() & 1) Sleep(0);
            ResumeThread(Thread);
            InterlockedIncrement(&Suspends);
        }
    }
    return 0;
}

static DWORD WINAPI AffinityThread(PVOID Param)
{
    HANDLE Thread;
    DWORD_PTR Mask;
    ULONG Cpu;

    UNREFERENCED_PARAMETER(Param);
    while (!Stop)
    {
        Thread = AnyPairThread();
        Mask = AllMask;
        if (Rand() & 1)
        {
            /* One processor of the process mask */
            do
            {
                Cpu = Rand() % (sizeof(DWORD_PTR) * 8);
            } while (!(AllMask & ((DWORD_PTR)1 << Cpu)));
            Mask = (DWORD_PTR)1 << Cpu;
        }
        SetThreadAffinityMask(Thread, Mask);
        InterlockedIncrement(&AffinityChanges);
        Sleep(Rand() % 2);
    }
    return 0;
}

typedef struct _SHORT
{
    HANDLE Started;
    ULONG Spin;
    BOOLEAN Victim;
} SHORT_ARGS, *PSHORT_ARGS;

static HANDLE NeverSet;

static DWORD WINAPI ShortThread(PVOID Param)
{
    PSHORT_ARGS Args = Param;
    ULONG Spin = Args->Spin;
    BOOLEAN Victim = Args->Victim;

    /* Started is set once the loader has initialised the thread: a thread terminated
       before that point (or in its own exit) would leave the loader lock held */
    SetEvent(Args->Started);
    while (Spin--) YieldProcessor();
    if (Victim)
    {
        /* Terminated from outside, never ends by itself */
        for (;;) WaitForSingleObject(NeverSet, Rand() % 3);
    }
    WaitForSingleObject(NeverSet, Rand() % 3);
    return 0;
}

static DWORD WINAPI ChurnThread(PVOID Param)
{
    HANDLE Threads[8];
    SHORT_ARGS Args[8];
    ULONG i;

    UNREFERENCED_PARAMETER(Param);
    for (i = 0; i < ARRAYSIZE(Threads); i++)
    {
        Args[i].Started = CreateEventW(NULL, FALSE, FALSE, NULL);
    }
    while (!Stop)
    {
        for (i = 0; i < ARRAYSIZE(Threads); i++)
        {
            Args[i].Spin = Rand() % 200000;
            Args[i].Victim = (Rand() & 1) != 0;
            Threads[i] = CreateThread(NULL, 0, ShortThread, &Args[i], 0, NULL);
        }
        for (i = 0; i < ARRAYSIZE(Threads); i++)
        {
            if (!Threads[i]) continue;
            WaitForSingleObject(Args[i].Started, STOP_WAIT_MS);
            if (Args[i].Victim)
            {
                SetThreadPriority(Threads[i], (Rand() & 1) ? THREAD_PRIORITY_IDLE : THREAD_PRIORITY_HIGHEST);
                if (Rand() & 1) Sleep(0);
                TerminateThread(Threads[i], 1);
            }
            WaitForSingleObject(Threads[i], STOP_WAIT_MS);
            CloseHandle(Threads[i]);
            InterlockedIncrement(&Churned);
        }
    }
    for (i = 0; i < ARRAYSIZE(Threads); i++)
    {
        CloseHandle(Args[i].Started);
    }
    return 0;
}

static DWORD WINAPI SpinThread(PVOID Param)
{
    /* One spinner competes at normal priority, the others only use idle time */
    if (Param) SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    while (!Stop) YieldProcessor();
    return 0;
}

START_TEST(ThreadLockStress)
{
    HANDLE Helpers[20];
    ULONG HelperCount = 0, i, Seconds = 30, Stalled;
    LONG Before[PAIRS];
    DWORD_PTR SystemMask;
    SYSTEM_INFO Si;
    char Buffer[16];
    DWORD Wait;

    if (GetEnvironmentVariableA("THREADLOCKSTRESS_SECONDS", Buffer, sizeof(Buffer)) && atoi(Buffer) > 0)
        Seconds = atoi(Buffer);

    NeverSet = CreateEventW(NULL, TRUE, FALSE, NULL);
    GetSystemInfo(&Si);
    GetProcessAffinityMask(GetCurrentProcess(), &AllMask, &SystemMask);
    if (Si.dwNumberOfProcessors < 2)
    {
        skip("ThreadLockStress needs more than one processor\n");
        return;
    }

    /* The test thread keeps control while the class changes */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    for (i = 0; i < PAIRS; i++)
    {
        Pairs[i].Sem[0] = CreateSemaphoreW(NULL, 1, 2, NULL);
        Pairs[i].Sem[1] = CreateSemaphoreW(NULL, 0, 2, NULL);
        Pairs[i].Event[0] = CreateEventW(NULL, FALSE, TRUE, NULL);
        Pairs[i].Event[1] = CreateEventW(NULL, FALSE, FALSE, NULL);
        ok(Pairs[i].Sem[0] && Pairs[i].Sem[1] && Pairs[i].Event[0] && Pairs[i].Event[1], "pair %lu: objects\n", i);
        Sides[i][0].Pair = Sides[i][1].Pair = &Pairs[i];
        Sides[i][0].Side = 0;
        Sides[i][1].Side = 1;
        Pairs[i].Thread[0] = CreateThread(NULL, 0, PairThread, &Sides[i][0], 0, NULL);
        Pairs[i].Thread[1] = CreateThread(NULL, 0, PairThread, &Sides[i][1], 0, NULL);
        ok(Pairs[i].Thread[0] && Pairs[i].Thread[1], "pair %lu: threads\n", i);
        if (!Pairs[i].Thread[0] || !Pairs[i].Thread[1]) return;
    }

    GetModuleFileNameW(NULL, SelfPath, ARRAYSIZE(SelfPath));
    for (i = 0; i < SPAWNERS; i++)
    {
        Spawners[i] = CreateThread(NULL, 0, SpawnThread, NULL, 0, NULL);
        Helpers[HelperCount++] = Spawners[i];
    }
    Helpers[HelperCount++] = CreateThread(NULL, 0, QueryThread, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, QueryThread, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, PriorityThread, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, ClassThread, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, SuspendThreadProc, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, AffinityThread, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, ChurnThread, NULL, 0, NULL);
    Helpers[HelperCount++] = CreateThread(NULL, 0, ChurnThread, NULL, 0, NULL);
    for (i = 0; i < Si.dwNumberOfProcessors && HelperCount < ARRAYSIZE(Helpers); i++)
    {
        Helpers[HelperCount++] = CreateThread(NULL, 0, SpinThread, (PVOID)(ULONG_PTR)i, 0, NULL);
    }
    for (i = 0; i < HelperCount; i++) ok(Helpers[i] != NULL, "helper %lu: %lu\n", i, GetLastError());

    /* Count 5-second windows in which a pair made no progress (an idle-priority pair may starve for a while) */
    Stalled = 0;
    for (i = 0; i < Seconds; i += 5)
    {
        ULONG p;
        for (p = 0; p < PAIRS; p++) Before[p] = Pairs[p].Rounds;
        Sleep(5000);
        for (p = 0; p < PAIRS; p++)
        {
            if (Pairs[p].Rounds == Before[p]) Stalled++;
        }
    }

    InterlockedExchange(&Stop, 1);
    for (i = 0; i < HelperCount; i++)
    {
        if (!Helpers[i]) continue;
        if (i < SPAWNERS)
        {
            /* Every other helper may still use a spawner's handle: close those last */
            Wait = WaitForSingleObject(Helpers[i], STOP_WAIT_MS);
            ok(Wait == WAIT_OBJECT_0, "spawner %lu did not stop: %lu\n", i, Wait);
            continue;
        }
        Wait = WaitForSingleObject(Helpers[i], STOP_WAIT_MS);
        ok(Wait == WAIT_OBJECT_0, "helper %lu did not stop: %lu\n", i, Wait);
        CloseHandle(Helpers[i]);
    }
    for (i = 0; i < SPAWNERS; i++)
    {
        if (Spawners[i]) CloseHandle(Spawners[i]);
    }
    for (i = 0; i < PAIRS; i++)
    {
        ResumeThread(Pairs[i].Thread[0]);
        ResumeThread(Pairs[i].Thread[1]);
        Wait = WaitForMultipleObjects(2, Pairs[i].Thread, TRUE, STOP_WAIT_MS);
        ok(Wait == WAIT_OBJECT_0, "pair %lu did not stop: %lu\n", i, Wait);
        ok(Pairs[i].Rounds > 0, "pair %lu made no progress\n", i);
        CloseHandle(Pairs[i].Thread[0]);
        CloseHandle(Pairs[i].Thread[1]);
        CloseHandle(Pairs[i].Sem[0]);
        CloseHandle(Pairs[i].Sem[1]);
        CloseHandle(Pairs[i].Event[0]);
        CloseHandle(Pairs[i].Event[1]);
    }
    CloseHandle(NeverSet);
    trace("%lu s: %lu pair windows without progress (idle-priority pairs may starve); queries %lu, priority %lu, class %lu, "
          "suspends %lu, affinity %lu, churned %lu, processes %lu\n",
          Seconds, Stalled, (ULONG)Queries, (ULONG)PriorityChanges, (ULONG)ClassChanges, (ULONG)Suspends,
          (ULONG)AffinityChanges, (ULONG)Churned, (ULONG)Spawned);
}
