/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     Tests for streams of QueueUserWorkItem items: every item runs once, items that wait for
 *              later items still run, items queued from items and from several threads, wake-up after idle
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */
#include "precomp.h"

static volatile LONG s_Count;
static LONG s_Total;
static HANDLE s_Done;

static DWORD WINAPI
CountItem(PVOID Context)
{
    if (InterlockedIncrement(&s_Count) == s_Total)
        SetEvent(s_Done);
    return 0;
}

static void
RunStream(LONG Total, const char *What)
{
    LONG i, Queued = 0;
    DWORD Wait;

    s_Count = 0;
    s_Total = Total;
    s_Done = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < Total; i++)
        Queued += QueueUserWorkItem(CountItem, NULL, 0);
    ok(Queued == Total, "%s: %ld of %ld items were queued\n", What, Queued, Total);
    Wait = WaitForSingleObject(s_Done, 60000);
    ok(Wait == WAIT_OBJECT_0, "%s: items did not all run, %ld of %ld\n", What, s_Count, Total);
    Sleep(50);
    ok(s_Count == Total, "%s: %ld items ran for %ld queued\n", What, s_Count, Total);
    CloseHandle(s_Done);
}

/* Item i waits for item i + 1: it needs a thread of its own, one more than the items before it */
#define CHAIN 6
static HANDLE s_Link[CHAIN + 1];
static volatile LONG s_ChainRan;

static DWORD WINAPI
ChainItem(PVOID Context)
{
    ULONG_PTR Index = (ULONG_PTR)Context;

    if (Index + 1 < CHAIN)
        WaitForSingleObject(s_Link[Index + 1], 60000);
    InterlockedIncrement(&s_ChainRan);
    SetEvent(s_Link[Index]);
    return 0;
}

static void
TestChain(void)
{
    ULONG_PTR i;

    s_ChainRan = 0;
    for (i = 0; i <= CHAIN; i++)
        s_Link[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < CHAIN; i++)
        ok(QueueUserWorkItem(ChainItem, (PVOID)i, 0), "QueueUserWorkItem failed %lu\n", GetLastError());
    ok(WaitForSingleObject(s_Link[0], 60000) == WAIT_OBJECT_0, "items that wait for later items did not finish, %ld ran\n", s_ChainRan);
    ok(s_ChainRan == CHAIN, "%ld of %d chained items ran\n", s_ChainRan, CHAIN);
    for (i = 0; i <= CHAIN; i++)
        CloseHandle(s_Link[i]);
}

/* An item queues the next one, a thousand times over */
static volatile LONG s_Depth;
static HANDLE s_DepthDone;

static DWORD WINAPI
NestedItem(PVOID Context)
{
    if (InterlockedIncrement(&s_Depth) < 1000)
        QueueUserWorkItem(NestedItem, NULL, 0);
    else
        SetEvent(s_DepthDone);
    return 0;
}

static void
TestNested(void)
{
    s_Depth = 0;
    s_DepthDone = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(QueueUserWorkItem(NestedItem, NULL, 0), "QueueUserWorkItem failed\n");
    ok(WaitForSingleObject(s_DepthDone, 60000) == WAIT_OBJECT_0, "nested items stopped at %ld\n", s_Depth);
    CloseHandle(s_DepthDone);
}

/* Several threads queue at once */
static DWORD WINAPI
Producer(PVOID Context)
{
    LONG i;

    for (i = 0; i < 5000; i++)
        QueueUserWorkItem(CountItem, NULL, 0);
    return 0;
}

static void
TestProducers(void)
{
    HANDLE Threads[4];
    int i;

    s_Count = 0;
    s_Total = 4 * 5000;
    s_Done = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < 4; i++)
        Threads[i] = CreateThread(NULL, 0, Producer, NULL, 0, NULL);
    WaitForMultipleObjects(4, Threads, TRUE, 60000);
    ok(WaitForSingleObject(s_Done, 60000) == WAIT_OBJECT_0, "items of 4 threads did not all run, %ld of %ld\n", s_Count, s_Total);
    Sleep(50);
    ok(s_Count == s_Total, "%ld items ran for %ld queued\n", s_Count, s_Total);
    for (i = 0; i < 4; i++)
        CloseHandle(Threads[i]);
    CloseHandle(s_Done);
}

/* After a pause the workers sleep: every single item must still wake one in good time */
static void
TestWakeAfterIdle(void)
{
    int i, Late = 0;
    DWORD Start, Elapsed;

    for (i = 0; i < 20; i++)
    {
        s_Count = 0;
        s_Total = 1;
        s_Done = CreateEventW(NULL, TRUE, FALSE, NULL);
        Sleep(i < 3 ? 400 : 5);
        Start = GetTickCount();
        QueueUserWorkItem(CountItem, NULL, 0);
        ok(WaitForSingleObject(s_Done, 30000) == WAIT_OBJECT_0, "item %d did not run\n", i);
        Elapsed = GetTickCount() - Start;
        if (Elapsed > 2000)
            Late++;
        CloseHandle(s_Done);
    }
    ok(Late == 0, "%d single items took more than 2 s to run\n", Late);
}

static DWORD WINAPI
LongItem(PVOID Context)
{
    InterlockedIncrement(&s_Count);
    return 0;
}

START_TEST(QueueUserWorkItemStream)
{
    ULONG i;

    RunStream(20000, "stream");
    TestChain();
    TestNested();
    TestProducers();
    TestWakeAfterIdle();

    /* The flags still select what they did */
    s_Count = 0;
    for (i = 0; i < 50; i++)
        ok(QueueUserWorkItem(LongItem, NULL, (i % 2) ? WT_EXECUTELONGFUNCTION : WT_EXECUTEINIOTHREAD), "QueueUserWorkItem failed\n");
    for (i = 0; i < 200 && s_Count < 50; i++)
        Sleep(50);
    ok(s_Count == 50, "%ld of 50 items with flags ran\n", s_Count);
}
