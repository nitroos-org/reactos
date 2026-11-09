/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtWaitForKeyedEvent and NtReleaseKeyedEvent: a timeout that races a release
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A release that has paired with a waiter must make that waiter succeed, even when the
 * waiter's own timeout expired at the same moment. The pair then agrees on the outcome:
 * the call that was paired reports STATUS_SUCCESS on both sides, never SUCCESS on one side
 * and STATUS_TIMEOUT on the other. The same holds with the roles swapped, because a release
 * with a timeout waits for a waiter.
 *
 * The race is made on purpose: both threads run on one processor, the late party runs at a
 * strictly higher priority and spins past the other's deadline. The other thread's timer then fires
 * while it cannot run, and the late party arrives while the first is still queued.
 */

#include "precomp.h"

#define MSECS(n) (-(LONGLONG)(n) * 10000)

#define RACE_TIMEOUT_MS   60
#define RACE_MARGIN_MS    50
#define RACE_ROUNDS       8

static HANDLE g_KeyedEvent;

static
DWORD_PTR
GetLaneMask(void)
{
    DWORD_PTR ProcessMask, SystemMask;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask) || ProcessMask == 0)
        return 0;

    /* The lowest processor the process may use. */
    return ProcessMask & (~ProcessMask + 1);
}

static
LONGLONG
QpcNow(void)
{
    LARGE_INTEGER Counter;

    QueryPerformanceCounter(&Counter);
    return Counter.QuadPart;
}

/* Convert a millisecond span to raw performance-counter ticks. Comparing raw
   counter deltas avoids the overflow of scaling an absolute counter to 100 ns. */
static
LONGLONG
QpcTicksForMs(LONGLONG Ms)
{
    LARGE_INTEGER Frequency;

    QueryPerformanceFrequency(&Frequency);
    return Frequency.QuadPart * Ms / 1000;
}

typedef struct _RACE_PARTY
{
    DWORD_PTR Mask;
    /* The first party waits for this long, or releases for this long. */
    LONGLONG TimeoutMs;
    BOOLEAN Release;
    PVOID Key;
    volatile LONGLONG Started;
    volatile NTSTATUS Status;
} RACE_PARTY;

static
DWORD
WINAPI
EarlyThread(PVOID Context)
{
    RACE_PARTY *Party = Context;
    LARGE_INTEGER Timeout;

    if (Party->Mask != 0)
        ok(SetThreadAffinityMask(GetCurrentThread(), Party->Mask) != 0,
           "SetThreadAffinityMask failed: %lu\n", GetLastError());

    Timeout.QuadPart = MSECS(Party->TimeoutMs);
    Party->Started = QpcNow();
    if (Party->Release)
        Party->Status = NtReleaseKeyedEvent(g_KeyedEvent, Party->Key, FALSE, &Timeout);
    else
        Party->Status = NtWaitForKeyedEvent(g_KeyedEvent, Party->Key, FALSE, &Timeout);
    return 0;
}

/* The early thread waits (or releases) with a timeout and the calling thread, which is the late
   party, arrives only after that timeout has expired. */
static
void
Race(BOOLEAN EarlyReleases, ULONG *Paired, ULONG *Unpaired)
{
    static LONG KeyStorage[RACE_ROUNDS];
    DWORD_PTR Mask = GetLaneMask();
    DWORD_PTR OldMask = 0;
    int OldPriority = GetThreadPriority(GetCurrentThread());
    LARGE_INTEGER Zero;
    NTSTATUS LateStatus;
    LONGLONG Deadline;
    RACE_PARTY Early;
    HANDLE Thread;
    DWORD Wait;
    int Round;

    Zero.QuadPart = 0;
    if (Mask != 0)
        OldMask = SetThreadAffinityMask(GetCurrentThread(), Mask);

    for (Round = 0; Round < RACE_ROUNDS; Round++)
    {
        RtlZeroMemory(&Early, sizeof(Early));
        Early.Mask = Mask;
        Early.TimeoutMs = RACE_TIMEOUT_MS;
        Early.Release = EarlyReleases;
        Early.Key = &KeyStorage[Round];

        Thread = CreateThread(NULL, 0, EarlyThread, &Early, 0, NULL);
        ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (Thread == NULL)
            break;

        /* Let the early thread get into its call; both run at the same priority on one processor. */
        while (Early.Started == 0)
            Sleep(1);
        Sleep(10);

        /* The early thread's wake-up from its timeout can boost it to the priority of a HIGHEST
           thread. It then shares the processor with the spinning caller once the caller's quantum
           ends, and the short quantum of a workstation ends within the spin. A TIME_CRITICAL
           caller stays above any boost, so the early thread cannot run before the late call. */
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        Deadline = Early.Started + QpcTicksForMs(RACE_TIMEOUT_MS + RACE_MARGIN_MS);
        while (QpcNow() < Deadline)
            YieldProcessor();

        if (EarlyReleases)
            LateStatus = NtWaitForKeyedEvent(g_KeyedEvent, Early.Key, FALSE, &Zero);
        else
            LateStatus = NtReleaseKeyedEvent(g_KeyedEvent, Early.Key, FALSE, &Zero);

        SetThreadPriority(GetCurrentThread(), OldPriority);
        Wait = WaitForSingleObject(Thread, 10000);
        ok(Wait == WAIT_OBJECT_0, "early thread did not finish: %lu\n", Wait);
        if (Wait != WAIT_OBJECT_0)
        {
            /* It could still use the stack of this call. */
            ExitProcess(1);
        }
        CloseHandle(Thread);

        if (LateStatus == STATUS_SUCCESS)
        {
            /* The late call found the early one still queued: the pair agrees, or the
               early call lost the wake-up although the late one counted it. */
            (*Paired)++;
            ok(Early.Status == STATUS_SUCCESS,
               "%s round %d: late call paired with the early call (0x%08lx), early call returned 0x%08lx\n",
               EarlyReleases ? "release/wait" : "wait/release", Round, (ULONG)LateStatus, (ULONG)Early.Status);
        }
        else
        {
            (*Unpaired)++;
            ok(LateStatus == STATUS_TIMEOUT, "late call returned 0x%08lx\n", (ULONG)LateStatus);
            ok(Early.Status == STATUS_TIMEOUT,
               "%s round %d: late call found nobody (0x%08lx), early call returned 0x%08lx\n",
               EarlyReleases ? "release/wait" : "wait/release", Round, (ULONG)LateStatus, (ULONG)Early.Status);
        }
    }

    if (OldMask != 0)
        SetThreadAffinityMask(GetCurrentThread(), OldMask);
    SetThreadPriority(GetCurrentThread(), OldPriority);
}

static
void
Test_TimeoutRacesRelease(void)
{
    ULONG Paired = 0, Unpaired = 0;

    /* The waiter's timeout expires, then the release arrives. */
    Race(FALSE, &Paired, &Unpaired);
    trace("waiter timed out first: %lu paired, %lu not paired\n", Paired, Unpaired);
    ok(Paired > 0, "no round reached the race: the release never met the waiter\n");

    /* The release's timeout expires, then the waiter arrives. */
    Paired = Unpaired = 0;
    Race(TRUE, &Paired, &Unpaired);
    trace("release timed out first: %lu paired, %lu not paired\n", Paired, Unpaired);
    ok(Paired > 0, "no round reached the race: the waiter never met the release\n");
}

/* Many threads on a few keys, with timeouts that expire all the time. Each pairing counts once on
   each side, so when all the calls are over the number of successful waits of a key equals the
   number of successful releases of that key. */
#define STRESS_KEYS      4
#define STRESS_PER_SIDE  3
#define STRESS_MS        1500

typedef struct _STRESS_SIDE
{
    PVOID Key;
    BOOLEAN Release;
    ULONG Seed;
    volatile LONG *Stop;
    volatile LONG Successes;
} STRESS_SIDE;

static
DWORD
WINAPI
StressThread(PVOID Context)
{
    STRESS_SIDE *Side = Context;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    ULONG Spin;

    while (!*Side->Stop)
    {
        Side->Seed = Side->Seed * 1103515245 + 12345;
        /* Zero, 1 ms or 2 ms: timeouts of different ages meet the other side. */
        Timeout.QuadPart = MSECS((Side->Seed >> 16) % 3);

        if (Side->Release)
            Status = NtReleaseKeyedEvent(g_KeyedEvent, Side->Key, FALSE, &Timeout);
        else
            Status = NtWaitForKeyedEvent(g_KeyedEvent, Side->Key, FALSE, &Timeout);

        if (Status == STATUS_SUCCESS)
            InterlockedIncrement(&Side->Successes);
        else if (Status != STATUS_TIMEOUT)
            break;

        /* A short pause moves the two sides against each other. */
        for (Spin = (Side->Seed >> 8) % 400; Spin != 0; Spin--)
            YieldProcessor();
    }
    return 0;
}

static
void
Test_Stress(void)
{
    static LONG KeyStorage[STRESS_KEYS];
    STRESS_SIDE Sides[STRESS_KEYS][2][STRESS_PER_SIDE];
    HANDLE Threads[STRESS_KEYS * 2 * STRESS_PER_SIDE];
    volatile LONG Stop = 0;
    ULONG Count = 0, Total = 0;
    int Key, Kind, Index;
    DWORD Wait;

    RtlZeroMemory(Sides, sizeof(Sides));
    for (Key = 0; Key < STRESS_KEYS; Key++)
    {
        for (Kind = 0; Kind < 2; Kind++)
        {
            for (Index = 0; Index < STRESS_PER_SIDE; Index++)
            {
                STRESS_SIDE *Side = &Sides[Key][Kind][Index];

                Side->Key = &KeyStorage[Key];
                Side->Release = (Kind == 1);
                Side->Seed = (Key * 7 + Kind * 3 + Index) * 7919 + 1;
                Side->Stop = &Stop;
                Threads[Count] = CreateThread(NULL, 0, StressThread, Side, 0, NULL);
                ok(Threads[Count] != NULL, "CreateThread failed: %lu\n", GetLastError());
                if (Threads[Count] == NULL)
                {
                    /* Threads that did start still use Sides, so end the process. */
                    ExitProcess(1);
                }
                Count++;
            }
        }
    }

    Sleep(STRESS_MS);
    Stop = 1;
    Wait = WaitForMultipleObjects(Count, Threads, TRUE, 30000);
    ok(Wait == WAIT_OBJECT_0, "stress threads did not finish: %lu\n", Wait);
    if (Wait != WAIT_OBJECT_0)
        ExitProcess(1);

    for (Key = 0; Key < STRESS_KEYS; Key++)
    {
        LONG Waits = 0, Releases = 0;

        for (Index = 0; Index < STRESS_PER_SIDE; Index++)
        {
            Waits += Sides[Key][0][Index].Successes;
            Releases += Sides[Key][1][Index].Successes;
        }
        ok(Waits == Releases, "key %d: %ld successful waits, %ld successful releases\n", Key, Waits, Releases);
        Total += Waits;
    }
    trace("stress: %lu pairs in %d ms\n", Total, STRESS_MS);
    ok(Total > 0, "no wait ever met a release\n");

    for (Index = 0; Index < (int)Count; Index++)
        CloseHandle(Threads[Index]);
}

/* The NULL handle is the system's default keyed event (what condition variables and critical sections use): it pairs a
   wait with a release, and is not the event a handle names. */
static LONG g_NullKey;
static NTSTATUS g_NullWaitStatus;

static
DWORD
WINAPI
NullWaitThread(PVOID Context)
{
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -50000000LL; /* 5 s */
    g_NullWaitStatus = NtWaitForKeyedEvent(NULL, &g_NullKey, FALSE, &Timeout);
    return 0;
}

static
void
Test_NullHandle(void)
{
    LARGE_INTEGER Timeout, Zero;
    NTSTATUS Status;
    HANDLE Thread;

    Zero.QuadPart = 0;
    Status = NtWaitForKeyedEvent(NULL, &g_NullKey, FALSE, &Zero);
    ok(Status == STATUS_TIMEOUT, "wait on the default event, nobody there: 0x%08lx\n", (ULONG)Status);
    Status = NtReleaseKeyedEvent(NULL, &g_NullKey, FALSE, &Zero);
    ok(Status == STATUS_TIMEOUT, "release on the default event, nobody there: 0x%08lx\n", (ULONG)Status);

    g_NullWaitStatus = STATUS_PENDING;
    Thread = CreateThread(NULL, 0, NullWaitThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed: %lu\n", GetLastError());
    if (Thread == NULL)
        return;
    Sleep(100);
    /* The event a handle names is another one: the waiter there is not released from here. */
    Status = NtReleaseKeyedEvent(g_KeyedEvent, &g_NullKey, FALSE, &Zero);
    ok(Status == STATUS_TIMEOUT, "release on a created event, waiter on the default one: 0x%08lx\n", (ULONG)Status);
    Timeout.QuadPart = -50000000LL;
    Status = NtReleaseKeyedEvent(NULL, &g_NullKey, FALSE, &Timeout);
    ok(Status == STATUS_SUCCESS, "release on the default event: 0x%08lx\n", (ULONG)Status);
    ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "waiter did not finish\n");
    ok(g_NullWaitStatus == STATUS_SUCCESS, "wait on the default event: 0x%08lx\n", (ULONG)g_NullWaitStatus);
    CloseHandle(Thread);
}

START_TEST(NtKeyedEvent)
{
    NTSTATUS Status;

    Status = NtCreateKeyedEvent(&g_KeyedEvent, KEYEDEVENT_ALL_ACCESS, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        skip("NtCreateKeyedEvent failed with 0x%08lx\n", Status);
        return;
    }

    Test_NullHandle();
    Test_TimeoutRacesRelease();
    Test_Stress();

    NtClose(g_KeyedEvent);
}
