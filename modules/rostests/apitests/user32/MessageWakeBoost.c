/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test the priority boost of a thread woken by a posted message
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A thread blocked in GetMessage and woken by a posted message runs with a priority boost of 2 on Windows,
 * one more than a thread woken by SetEvent (EVENT_INCREMENT, 1); Windows 10 measured 8 and 7 at base 6.
 * Without the boost a normal-priority GUI thread woke at its base priority, and waited behind every
 * CPU-bound thread of that priority for a quantum (one or more 15.6 ms clock ticks) before it ran.
 */

#include "precomp.h"

typedef struct _TEST_THREAD_BASIC_INFORMATION
{
    LONG ExitStatus;
    PVOID TebBaseAddress;
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} TEST_THREAD_BASIC_INFORMATION;

typedef LONG (NTAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#define ROUNDS 3
/* A boost is not given while an earlier one (the resume of a new thread) has not decayed: the waiter
   first runs for a few quanta, each quantum end takes one step of it away */
#define SETTLE_MS 600

static PFN_NtQueryInformationThread pNtQueryInformationThread;
static HANDLE g_Ready, g_Go, g_Done;
static volatile LONG g_Priority, g_BasePriority;

static void ReadPriority(void)
{
    TEST_THREAD_BASIC_INFORMATION Info;
    ULONG Length;

    g_Priority = g_BasePriority = -1;
    if (pNtQueryInformationThread(GetCurrentThread(), 0 /* ThreadBasicInformation */,
                                  &Info, sizeof(Info), &Length) == 0)
    {
        g_Priority = Info.Priority;
        g_BasePriority = Info.BasePriority;
    }
}

static void Settle(void)
{
    DWORD Start = GetTickCount();
    volatile ULONG i;
    while (GetTickCount() - Start < SETTLE_MS)
    {
        for (i = 0; i < 10000; i++);
    }
}

static DWORD WINAPI EventWaiter(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    Settle();
    SetEvent(g_Ready);
    WaitForSingleObject(g_Go, INFINITE);
    ReadPriority();
    SetEvent(g_Done);
    return 0;
}

static DWORD WINAPI MessageWaiter(PVOID Parameter)
{
    MSG Msg;
    UNREFERENCED_PARAMETER(Parameter);
    PeekMessageW(&Msg, NULL, 0, 0, PM_NOREMOVE);
    Settle();
    SetEvent(g_Ready);
    GetMessageW(&Msg, NULL, 0, 0);
    ReadPriority();
    SetEvent(g_Done);
    return 0;
}

static int __cdecl CompareLong(const void *A, const void *B)
{
    return *(const LONG *)A - *(const LONG *)B;
}

/* Returns the median boost (priority above the base priority) at the wake, or -100 */
static LONG MeasureBoost(BOOL Message)
{
    LONG Boost[ROUNDS];
    ULONG i, Count = 0;
    HANDLE Thread;
    DWORD Tid;

    for (i = 0; i < ROUNDS; i++)
    {
        Thread = CreateThread(NULL, 0, Message ? MessageWaiter : EventWaiter, NULL, 0, &Tid);
        ok(Thread != NULL, "CreateThread failed (%lu)\n", GetLastError());
        if (!Thread) break;
        ok(WaitForSingleObject(g_Ready, 10000) == WAIT_OBJECT_0, "waiter not ready\n");
        /* Let it block */
        Sleep(50);
        if (Message)
            ok(PostThreadMessageW(Tid, WM_USER + 1, 0, 0), "PostThreadMessageW failed (%lu)\n", GetLastError());
        else
            SetEvent(g_Go);
        ok(WaitForSingleObject(g_Done, 5000) == WAIT_OBJECT_0, "waiter did not wake\n");
        WaitForSingleObject(Thread, 5000);
        CloseHandle(Thread);
        if (g_Priority >= 0 && g_BasePriority >= 0)
            Boost[Count++] = g_Priority - g_BasePriority;
    }
    if (!Count) return -100;
    qsort(Boost, Count, sizeof(Boost[0]), CompareLong);
    return Boost[Count / 2];
}

START_TEST(MessageWakeBoost)
{
    LONG EventBoost, MessageBoost;

    pNtQueryInformationThread = (PFN_NtQueryInformationThread)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!pNtQueryInformationThread)
    {
        skip("NtQueryInformationThread not available\n");
        return;
    }

    g_Ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_Go = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_Done = CreateEventW(NULL, FALSE, FALSE, NULL);

    EventBoost = MeasureBoost(FALSE);
    MessageBoost = MeasureBoost(TRUE);
    ok(EventBoost != -100 && MessageBoost != -100, "priorities not read\n");
    trace("boost at the wake: event %ld, message %ld\n", EventBoost, MessageBoost);

    /* Both include the foreground boost when this process is in the foreground */
    ok(MessageBoost == EventBoost + 1, "message wake boost %ld, event wake boost %ld (Windows: one more than the event)\n",
       MessageBoost, EventBoost);

    CloseHandle(g_Ready);
    CloseHandle(g_Go);
    CloseHandle(g_Done);
}
