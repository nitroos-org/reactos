/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a wait which is satisfied at once does not cost the thread its time slice
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A worker thread loops on a wait that never blocks (a signaled event or semaphore, a mutex it owns,
 * a timeout of 0, alertable variants, multiple objects, a delay that is already due) plus a little work,
 * while a spinner of the same priority runs on the same processor. NT 5.2 charged such a wait a quantum
 * unit, so the worker gave the processor to the spinner every few waits and got almost no CPU time.
 * Windows 10 does not: both threads get about the same CPU time (worker/spinner 0.80-1.09 measured).
 */

#include "precomp.h"

#define WINDOW_MS 1000

typedef NTSTATUS (NTAPI *PFN_NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
static PFN_NtDelayExecution pNtDelayExecution;

enum
{
    OP_NONE, OP_EVENT, OP_SEMAPHORE, OP_TIMEOUT0, OP_MUTEX, OP_ALERTABLE,
    OP_TIMEOUT0_ALERTABLE, OP_WAIT_ANY, OP_WAIT_ALL, OP_DELAY_DUE
};

static volatile LONG g_Stop;
static LONG g_Op;
static LONGLONG g_Waits;
static DWORD g_Unexpected;
static HANDLE g_Signaled, g_Signaled2, g_Unsignaled, g_Semaphore, g_Mutex;

static void Work(void)
{
    volatile ULONG i;
    for (i = 0; i < 1000; i++);
}

static DWORD WINAPI Spinner(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    while (!g_Stop) Work();
    return 0;
}

static DWORD WINAPI Worker(PVOID Parameter)
{
    HANDLE Two[2] = { g_Signaled, g_Signaled2 };
    LARGE_INTEGER Due;
    DWORD Result, Expected = WAIT_OBJECT_0;
    UNREFERENCED_PARAMETER(Parameter);

    Due.QuadPart = 1; /* absolute: 1601-01-01, long past */
    if (g_Op == OP_TIMEOUT0 || g_Op == OP_TIMEOUT0_ALERTABLE) Expected = WAIT_TIMEOUT;
    if (g_Op == OP_MUTEX && WaitForSingleObject(g_Mutex, INFINITE) != WAIT_OBJECT_0) g_Unexpected = 0xFFFFFFFF;
    while (!g_Stop)
    {
        switch (g_Op)
        {
            case OP_EVENT: Result = WaitForSingleObject(g_Signaled, INFINITE); break;
            case OP_SEMAPHORE: Result = WaitForSingleObject(g_Semaphore, INFINITE); break;
            case OP_TIMEOUT0: Result = WaitForSingleObject(g_Unsignaled, 0); break;
            case OP_MUTEX: Result = WaitForSingleObject(g_Mutex, INFINITE); break;
            case OP_ALERTABLE: Result = WaitForSingleObjectEx(g_Signaled, INFINITE, TRUE); break;
            case OP_TIMEOUT0_ALERTABLE: Result = WaitForSingleObjectEx(g_Unsignaled, 0, TRUE); break;
            case OP_WAIT_ANY: Result = WaitForMultipleObjects(2, Two, FALSE, INFINITE); break;
            case OP_WAIT_ALL: Result = WaitForMultipleObjects(2, Two, TRUE, INFINITE); break;
            case OP_DELAY_DUE: Result = (DWORD)pNtDelayExecution(FALSE, &Due); break;
            default: Result = Expected; break;
        }
        if (Result != Expected && !g_Unexpected) g_Unexpected = Result | 0x80000000;
        Work();
        g_Waits++;
    }
    return 0;
}

static ULONGLONG CpuTime(HANDLE Thread)
{
    FILETIME Create, Exit, Kernel, User;
    if (!GetThreadTimes(Thread, &Create, &Exit, &Kernel, &User)) return 0;
    return ((((ULONGLONG)Kernel.dwHighDateTime << 32) | Kernel.dwLowDateTime) +
            (((ULONGLONG)User.dwHighDateTime << 32) | User.dwLowDateTime)) / 10000;
}

/* Returns 100 * worker CPU time / spinner CPU time */
static ULONG RunOne(LONG Op, PCSTR Name, DWORD_PTR Cpu)
{
    HANDLE Threads[2];
    ULONGLONG WorkerMs, SpinnerMs;
    ULONG Ratio;
    DWORD Wait;

    g_Stop = 0;
    g_Op = Op;
    g_Waits = 0;
    g_Unexpected = 0;
    g_Mutex = CreateMutexW(NULL, FALSE, NULL);
    Threads[0] = CreateThread(NULL, 0, Worker, NULL, CREATE_SUSPENDED, NULL);
    Threads[1] = CreateThread(NULL, 0, Spinner, NULL, CREATE_SUSPENDED, NULL);
    ok(Threads[0] != NULL && Threads[1] != NULL, "%s: CreateThread failed (%lu)\n", Name, GetLastError());
    if (!Threads[0] || !Threads[1])
    {
        g_Stop = 1;
        if (Threads[0]) { ResumeThread(Threads[0]); WaitForSingleObject(Threads[0], 10000); CloseHandle(Threads[0]); }
        if (Threads[1]) { ResumeThread(Threads[1]); WaitForSingleObject(Threads[1], 10000); CloseHandle(Threads[1]); }
        CloseHandle(g_Mutex);
        return 0;
    }
    SetThreadAffinityMask(Threads[0], Cpu);
    SetThreadAffinityMask(Threads[1], Cpu);
    ResumeThread(Threads[0]);
    ResumeThread(Threads[1]);
    Sleep(WINDOW_MS);
    g_Stop = 1;
    Wait = WaitForMultipleObjects(2, Threads, TRUE, 10000);
    ok(Wait == WAIT_OBJECT_0, "%s: threads did not stop (%lu)\n", Name, Wait);
    WorkerMs = CpuTime(Threads[0]);
    SpinnerMs = CpuTime(Threads[1]);
    CloseHandle(Threads[0]);
    CloseHandle(Threads[1]);
    CloseHandle(g_Mutex);

    Ratio = SpinnerMs ? (ULONG)(WorkerMs * 100 / SpinnerMs) : 0;
    trace("%s: worker %I64u ms, spinner %I64u ms, ratio %lu.%02lu, %I64d waits\n",
          Name, WorkerMs, SpinnerMs, Ratio / 100, Ratio % 100, g_Waits);
    ok(g_Unexpected == 0, "%s: unexpected wait result 0x%lx\n", Name, g_Unexpected & 0x7FFFFFFF);
    return Ratio;
}

START_TEST(WaitQuantum)
{
    static const struct { LONG Op; PCSTR Name; } Tests[] =
    {
        { OP_EVENT, "signaled event" },
        { OP_SEMAPHORE, "signaled semaphore" },
        { OP_TIMEOUT0, "timeout 0" },
        { OP_MUTEX, "owned mutex" },
        { OP_ALERTABLE, "alertable, signaled" },
        { OP_TIMEOUT0_ALERTABLE, "alertable, timeout 0" },
        { OP_WAIT_ANY, "wait any, signaled" },
        { OP_WAIT_ALL, "wait all, signaled" },
        { OP_DELAY_DUE, "delay already due" },
    };
    DWORD_PTR ProcessMask, SystemMask, Cpu;
    ULONG i, Ratio;
    int OldPriority;

    pNtDelayExecution = (PFN_NtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
    g_Signaled = CreateEventW(NULL, TRUE, TRUE, NULL);
    g_Signaled2 = CreateEventW(NULL, TRUE, TRUE, NULL);
    g_Unsignaled = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_Semaphore = CreateSemaphoreW(NULL, 0x7FFFFFFF, 0x7FFFFFFF, NULL);
    ok(pNtDelayExecution && g_Signaled && g_Signaled2 && g_Unsignaled && g_Semaphore, "setup failed\n");
    if (!pNtDelayExecution || !g_Signaled || !g_Signaled2 || !g_Unsignaled || !g_Semaphore) return;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask) || !ProcessMask)
    {
        skip("no process affinity mask\n");
        return;
    }
    Cpu = ProcessMask & (~ProcessMask + 1); /* lowest processor of the process */

    /* The main thread only has to wake up at the end of each window */
    OldPriority = GetThreadPriority(GetCurrentThread());
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    /* Control: two spinners must share the processor about evenly, or the measurement means nothing */
    Ratio = RunOne(OP_NONE, "control (no wait)", Cpu);
    if (Ratio < 50 || Ratio > 200)
    {
        skip("two spinners on one processor got worker/spinner %lu.%02lu, the processor is not shared evenly\n",
             Ratio / 100, Ratio % 100);
    }
    else
    {
        for (i = 0; i < RTL_NUMBER_OF(Tests); i++)
        {
            Ratio = RunOne(Tests[i].Op, Tests[i].Name, Cpu);
            /* Charged: about 0.0x. Not charged: about 1 (Windows 10: 0.80-1.09) */
            ok(Ratio >= 40 && Ratio <= 250, "%s: worker/spinner CPU time %lu.%02lu, expected about 1\n",
               Tests[i].Name, Ratio / 100, Ratio % 100);
        }
    }

    SetThreadPriority(GetCurrentThread(), OldPriority);
    CloseHandle(g_Semaphore);
    CloseHandle(g_Unsignaled);
    CloseHandle(g_Signaled2);
    CloseHandle(g_Signaled);
}
