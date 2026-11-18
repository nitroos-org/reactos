/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Load/unload cycles of DLLs with per-thread state, alone and while threads start and exit
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * ntdll_apitest LdrLoadUnloadStress [SECONDS]  (default 60)
 *
 * 1. A load/unload cycle gives back what the DLL took from the process: the number of free TLS indexes and the
 *    number of critical sections in the process lock list are the same after 300 cycles as after the first one.
 *    (ws2_32 kept its TLS index on FreeLibrary: after about a thousand cycles its DLL_PROCESS_ATTACH failed, and
 *    the DLL_PROCESS_DETACH the C runtime sends then entered a critical section that was never initialized, with
 *    the loader lock held: the whole process hung.)
 * 2. Stress: threads load, use and free the DLLs while another thread starts and ends threads (each start and
 *    end calls every loaded DLL with DLL_THREAD_ATTACH / DLL_THREAD_DETACH); every thread must keep making
 *    progress. A thread stuck for 30 seconds is a failure; the test then ends the process itself (with the
 *    loader lock held by a stuck thread, a normal exit would hang as well).
 */

#include "precomp.h"

static const WCHAR *Dlls[] = { L"ws2_32.dll", L"iphlpapi.dll", L"rpcrt4.dll", L"urlmon.dll", L"wininet.dll" };
#define NDLLS RTL_NUMBER_OF(Dlls)
#define NWORKERS 8
#define STUCK_SECONDS 30

static volatile LONG Stop;
static volatile LONG64 Progress[NWORKERS];
static volatile LONG LoadFailures;
static volatile DWORD LastLoadError;

static ULONG CountFreeTlsIndexes(VOID)
{
    static DWORD Index[2048];
    ULONG n = 0, i;

    while (n < RTL_NUMBER_OF(Index) && (Index[n] = TlsAlloc()) != TLS_OUT_OF_INDEXES)
        n++;
    for (i = 0; i < n; i++)
        TlsFree(Index[i]);
    return n;
}

static ULONG CountProcessLocks(VOID)
{
    PRTL_CRITICAL_SECTION LoaderLock = (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock;
    PLIST_ENTRY Head = &LoaderLock->DebugInfo->ProcessLocksList, Entry;
    ULONG n = 0;

    /* The list changes under its own lock in ntdll; this thread is the only one running here */
    for (Entry = Head->Flink; Entry != Head && n < 1000000; Entry = Entry->Flink)
        n++;
    return n;
}

static VOID TestNoLeak(VOID)
{
    ULONG d, i, Tls0, Tls1, Locks0, Locks1;
    HMODULE Module;

    for (d = 0; d < NDLLS; d++)
    {
        if (GetModuleHandleW(Dlls[d]))
        {
            skip("%ls is loaded already\n", Dlls[d]);
            continue;
        }

        /* the first cycle may keep things for good (a dependency another module pins, a one-time allocation) */
        Module = LoadLibraryW(Dlls[d]);
        ok(Module != NULL, "LoadLibrary(%ls) failed with %lu\n", Dlls[d], GetLastError());
        if (!Module)
            continue;
        FreeLibrary(Module);

        Tls0 = CountFreeTlsIndexes();
        Locks0 = CountProcessLocks();
        for (i = 0; i < 300; i++)
        {
            Module = LoadLibraryW(Dlls[d]);
            if (!Module)
                break;
            FreeLibrary(Module);
        }
        ok(i == 300, "%ls: LoadLibrary failed with %lu in cycle %lu\n", Dlls[d], GetLastError(), i);
        Tls1 = CountFreeTlsIndexes();
        Locks1 = CountProcessLocks();
        ok(Tls1 == Tls0, "%ls: %lu free TLS indexes after 300 load/unload cycles, %lu before\n", Dlls[d], Tls1, Tls0);
        ok(Locks1 <= Locks0, "%ls: %lu critical sections in the process list after 300 load/unload cycles, %lu before\n",
           Dlls[d], Locks1, Locks0);
        ok(GetModuleHandleW(Dlls[d]) == NULL, "%ls is still loaded\n", Dlls[d]);
    }
}

static DWORD WINAPI ShortThread(PVOID Parameter)
{
    return 0;
}

static DWORD WINAPI Worker(PVOID Parameter)
{
    ULONG Id = (ULONG)(ULONG_PTR)Parameter, Seed = 31 * (Id + 1);
    HMODULE Module;
    HANDLE Thread;

    while (!Stop)
    {
        if (Id == 0)
        {
            Thread = CreateThread(NULL, 0, ShortThread, NULL, 0, NULL);
            if (Thread)
            {
                WaitForSingleObject(Thread, INFINITE);
                CloseHandle(Thread);
            }
        }
        else
        {
            Seed = Seed * 1103515245 + 12345;
            Module = LoadLibraryW(Dlls[(Seed >> 8) % NDLLS]);
            if (Module)
            {
                GetProcAddress(Module, "DllGetVersion");
                FreeLibrary(Module);
            }
            else
            {
                LastLoadError = GetLastError();
                InterlockedIncrement(&LoadFailures);
            }
        }
        Progress[Id]++;
    }
    return 0;
}

static VOID TestStress(ULONG Seconds)
{
    HANDLE Threads[NWORKERS];
    LONG64 Last[NWORKERS] = { 0 }, Total = 0;
    ULONG Since[NWORKERS] = { 0 }, s, i;
    PRTL_CRITICAL_SECTION LoaderLock = (PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock;

    for (i = 0; i < NWORKERS; i++)
    {
        Threads[i] = CreateThread(NULL, 0, Worker, (PVOID)(ULONG_PTR)i, 0, NULL);
        ok(Threads[i] != NULL, "CreateThread failed with %lu\n", GetLastError());
        if (!Threads[i])
            return;
    }

    for (s = 0; s < Seconds; s++)
    {
        Sleep(1000);
        for (i = 0; i < NWORKERS; i++)
        {
            if (Progress[i] != Last[i])
            {
                Since[i] = 0;
                Last[i] = Progress[i];
                continue;
            }
            if (++Since[i] < STUCK_SECONDS)
                continue;

            ok(FALSE, "thread %lu made no progress for %u s (after %lu s); loader lock owner %p, recursion %ld\n",
               i, STUCK_SECONDS, s + 1, LoaderLock->OwningThread, LoaderLock->RecursionCount);
            trace("%ld load failures, last error %lu\n", LoadFailures, LastLoadError);
            /* A normal exit needs the loader lock too */
            fflush(stdout);
            TerminateProcess(GetCurrentProcess(), 3);
        }
    }

    Stop = 1;
    for (i = 0; i < NWORKERS; i++)
    {
        ok(WaitForSingleObject(Threads[i], 60000) == WAIT_OBJECT_0, "thread %lu did not stop\n", i);
        CloseHandle(Threads[i]);
        Total += Progress[i];
    }
    ok(LoadFailures == 0, "%ld loads failed, last error %lu\n", LoadFailures, LastLoadError);
    trace("%lu s, %I64d operations, %I64d thread starts\n", Seconds, Total, Progress[0]);
}

START_TEST(LdrLoadUnloadStress)
{
    char **argv;
    int argc;
    ULONG Seconds = 60;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && atoi(argv[2]) > 0)
        Seconds = atoi(argv[2]);

    TestNoLeak();
    TestStress(Seconds);
}
