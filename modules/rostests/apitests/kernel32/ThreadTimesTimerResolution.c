/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that thread and system CPU times follow the wall clock at a raised timer resolution
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * One busy thread pinned to each processor for a second, with the timer resolution raised to 1 ms (what
 * timeBeginPeriod(1) does). Every clock interrupt of the other processors was charged as a full clock tick,
 * so a thread on any processor but the first one got about 16 times its run time (31.5 s for 2 s), and its
 * quantum ended that much earlier. Windows 10 charges no more than the elapsed time, at any resolution.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_NtSetTimerResolution)(ULONG, BOOLEAN, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryTimerResolution)(PULONG, PULONG, PULONG);

#define SPIN_MS 1000
#define MAX_CPUS 32
/* The run time is counted in clock ticks of up to 15.6 ms: two ticks and a tenth of the wall time of slack */
#define SLACK_MS(Wall) (32 + (Wall) / 10)

static LARGE_INTEGER g_Frequency;

static DWORD WINAPI Spinner(PVOID Parameter)
{
    LARGE_INTEGER Start, Now;
    UNREFERENCED_PARAMETER(Parameter);
    QueryPerformanceCounter(&Start);
    do
    {
        QueryPerformanceCounter(&Now);
    } while ((Now.QuadPart - Start.QuadPart) * 1000 / g_Frequency.QuadPart < SPIN_MS);
    return 0;
}

static ULONGLONG FileTimeMs(const FILETIME *Time)
{
    return ((((ULONGLONG)Time->dwHighDateTime) << 32) | Time->dwLowDateTime) / 10000;
}

static void RunPhase(PCSTR Name, ULONG Processors)
{
    HANDLE Threads[MAX_CPUS];
    FILETIME Idle0, Kernel0, User0, Idle1, Kernel1, User1, Create, Exit, Kernel, User;
    LARGE_INTEGER Begin, End;
    ULONGLONG Wall, Cpu, SystemWall, SystemBusy;
    ULONG i, Created = 0;

    ok(GetSystemTimes(&Idle0, &Kernel0, &User0), "%s: GetSystemTimes failed (%lu)\n", Name, GetLastError());
    QueryPerformanceCounter(&Begin);
    for (i = 0; i < Processors; i++)
    {
        Threads[i] = CreateThread(NULL, 0, Spinner, NULL, CREATE_SUSPENDED, NULL);
        ok(Threads[i] != NULL, "%s: CreateThread failed (%lu)\n", Name, GetLastError());
        if (!Threads[i]) break;
        SetThreadAffinityMask(Threads[i], (DWORD_PTR)1 << i);
        Created++;
    }
    for (i = 0; i < Created; i++) ResumeThread(Threads[i]);
    ok(WaitForMultipleObjects(Created, Threads, TRUE, 60000) == WAIT_OBJECT_0, "%s: spinners did not end\n", Name);
    QueryPerformanceCounter(&End);
    ok(GetSystemTimes(&Idle1, &Kernel1, &User1), "%s: GetSystemTimes failed (%lu)\n", Name, GetLastError());

    for (i = 0; i < Created; i++)
    {
        ok(GetThreadTimes(Threads[i], &Create, &Exit, &Kernel, &User), "%s: GetThreadTimes failed (%lu)\n", Name, GetLastError());
        Wall = FileTimeMs(&Exit) - FileTimeMs(&Create);
        Cpu = FileTimeMs(&Kernel) + FileTimeMs(&User);
        ok(Cpu <= Wall + SLACK_MS(Wall), "%s: thread on processor %lu charged %I64u ms for %I64u ms of wall time\n",
           Name, i, Cpu, Wall);
        trace("%s: processor %lu wall %I64u ms user %I64u ms kernel %I64u ms\n",
              Name, i, Wall, FileTimeMs(&User), FileTimeMs(&Kernel));
        CloseHandle(Threads[i]);
    }

    /* The kernel time of GetSystemTimes includes the idle time */
    SystemWall = (End.QuadPart - Begin.QuadPart) * 1000 / g_Frequency.QuadPart;
    SystemBusy = (FileTimeMs(&Kernel1) - FileTimeMs(&Kernel0)) + (FileTimeMs(&User1) - FileTimeMs(&User0));
    ok(SystemBusy <= Processors * (SystemWall + SLACK_MS(SystemWall)),
       "%s: system times grew by %I64u ms in %I64u ms on %lu processors\n", Name, SystemBusy, SystemWall, Processors);
}

START_TEST(ThreadTimesTimerResolution)
{
    PFN_NtSetTimerResolution pNtSetTimerResolution;
    PFN_NtQueryTimerResolution pNtQueryTimerResolution;
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    ULONG Minimum, Maximum, Current, Actual;
    SYSTEM_INFO Info;
    NTSTATUS Status;
    ULONG Processors;

    pNtSetTimerResolution = (PFN_NtSetTimerResolution)GetProcAddress(Ntdll, "NtSetTimerResolution");
    pNtQueryTimerResolution = (PFN_NtQueryTimerResolution)GetProcAddress(Ntdll, "NtQueryTimerResolution");
    if (!pNtSetTimerResolution || !pNtQueryTimerResolution)
    {
        skip("NtSetTimerResolution not available\n");
        return;
    }

    QueryPerformanceFrequency(&g_Frequency);
    GetSystemInfo(&Info);
    Processors = min(Info.dwNumberOfProcessors, MAX_CPUS);

    RunPhase("default resolution", Processors);

    Status = pNtQueryTimerResolution(&Minimum, &Maximum, &Current);
    ok(Status == 0, "NtQueryTimerResolution returned 0x%lx\n", Status);
    if (Status != 0 || Maximum >= Minimum)
    {
        skip("The timer resolution cannot be raised (%lu-%lu)\n", Minimum, Maximum);
        return;
    }

    /* 1 ms, or the finest the system has if that is coarser */
    Status = pNtSetTimerResolution(max(Maximum, 10000), TRUE, &Actual);
    ok(Status == 0, "NtSetTimerResolution returned 0x%lx\n", Status);
    if (Status != 0) return;
    Sleep(100);
    trace("timer resolution %lu (range %lu-%lu), %lu processors\n", Actual, Maximum, Minimum, Processors);

    RunPhase("raised resolution", Processors);

    pNtSetTimerResolution(0, FALSE, &Actual);
}
