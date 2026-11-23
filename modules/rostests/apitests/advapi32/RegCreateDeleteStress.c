/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Creating and deleting keys from many threads does not make creates fail
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every key handle that is closed hands its reference on the key's control block to a delayed dereference queue,
 * and a queued control block keeps its reference on its parent until the queue is drained. With more threads
 * closing keys than processors the queue used to grow without bound: a parent reached the 16-bit reference limit
 * of its control block and every create below it failed with ERROR_NO_SYSTEM_RESOURCES (1450), whoever made it
 * (the delayed dereference queue of the configuration manager, measured: 96% of creates failed at 8 threads on
 * 2 processors).
 *
 * Threads create, delete and close keys in a loop, three of every four below the one parent they share and the
 * fourth below a parent of their own, and a witness thread does the same, slowly, below the shared parent (another
 * caller's creates). No create may fail. HBK_STRESS_SECONDS (default 45) and HBK_STRESS_THREADS (default 8 per
 * processor, at least 16) set the load.
 */

#include "precomp.h"

#define ROOT L"Software\\HbkCreateDeleteStress"

static volatile LONG s_Stop;
static volatile LONG s_Creates, s_Failures, s_LastError, s_WitnessCreates, s_WitnessFailures;

static DWORD WINAPI StressThread(PVOID Param)
{
    ULONG Id = (ULONG)(ULONG_PTR)Param, n = 0;
    WCHAR Own[64], Name[32];
    HKEY Parent[2], Key;
    LONG Error;

    StringCbPrintfW(Own, sizeof(Own), ROOT L"\\t%lu", Id);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, Own, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Parent[0], NULL) != ERROR_SUCCESS ||
        RegCreateKeyExW(HKEY_CURRENT_USER, ROOT L"\\shared", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Parent[1], NULL) != ERROR_SUCCESS)
        return 1;
    while (!s_Stop)
    {
        HKEY Where = Parent[(n & 3) != 0];

        StringCbPrintfW(Name, sizeof(Name), L"k%lu-%lu", Id, n++);
        Error = RegCreateKeyExW(Where, Name, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Key, NULL);
        InterlockedIncrement(&s_Creates);
        if (Error != ERROR_SUCCESS)
        {
            InterlockedIncrement(&s_Failures);
            InterlockedExchange(&s_LastError, Error);
            continue;
        }
        RegDeleteKeyW(Where, Name);
        RegCloseKey(Key);
    }
    RegCloseKey(Parent[1]);
    RegCloseKey(Parent[0]);
    return 0;
}

static DWORD WINAPI WitnessThread(PVOID Unused)
{
    HKEY Parent, Key;
    ULONG n = 0;
    WCHAR Name[32];

    if (RegCreateKeyExW(HKEY_CURRENT_USER, ROOT L"\\shared", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Parent, NULL) != ERROR_SUCCESS)
        return 1;
    while (!s_Stop)
    {
        StringCbPrintfW(Name, sizeof(Name), L"w%lu", n++);
        InterlockedIncrement(&s_WitnessCreates);
        if (RegCreateKeyExW(Parent, Name, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Key, NULL) != ERROR_SUCCESS)
        {
            InterlockedIncrement(&s_WitnessFailures);
        }
        else
        {
            RegDeleteKeyW(Parent, Name);
            RegCloseKey(Key);
        }
        Sleep(10);
    }
    RegCloseKey(Parent);
    return 0;
}

START_TEST(RegCreateDeleteStress)
{
    SYSTEM_INFO Si;
    HANDLE Threads[65];
    ULONG Seconds = 45, Count, i;
    WCHAR Env[16];

    GetSystemInfo(&Si);
    Count = max(16, 8 * Si.dwNumberOfProcessors);
    if (GetEnvironmentVariableW(L"HBK_STRESS_SECONDS", Env, ARRAYSIZE(Env)))
        Seconds = wcstoul(Env, NULL, 10);
    if (GetEnvironmentVariableW(L"HBK_STRESS_THREADS", Env, ARRAYSIZE(Env)))
        Count = wcstoul(Env, NULL, 10);
    Count = min(Count, ARRAYSIZE(Threads) - 1);

    s_Stop = 0;
    for (i = 0; i < Count; i++)
        Threads[i] = CreateThread(NULL, 0, StressThread, (PVOID)(ULONG_PTR)i, 0, NULL);
    Threads[Count] = CreateThread(NULL, 0, WitnessThread, NULL, 0, NULL);
    Sleep(Seconds * 1000);
    InterlockedExchange(&s_Stop, 1);
    for (i = 0; i <= Count; i++)
    {
        if (Threads[i])
        {
            WaitForSingleObject(Threads[i], INFINITE);
            CloseHandle(Threads[i]);
        }
    }

    trace("%lu threads on %lu processors for %lu s: %ld creates, %ld failed (last error %ld); witness %ld creates, %ld failed\n",
          Count, Si.dwNumberOfProcessors, Seconds, s_Creates, s_Failures, s_LastError, s_WitnessCreates, s_WitnessFailures);
    ok(s_Creates > 0, "no create ran\n");
    ok(s_Failures == 0, "%ld of %ld creates failed (last error %ld)\n", s_Failures, s_Creates, s_LastError);
    ok(s_WitnessFailures == 0, "%ld of %ld creates of the witness failed\n", s_WitnessFailures, s_WitnessCreates);

    for (i = 0; i < Count; i++)
    {
        StringCbPrintfW(Env, sizeof(Env), L"t%lu", i);
        {
            WCHAR Path[64];
            StringCbPrintfW(Path, sizeof(Path), ROOT L"\\%s", Env);
            RegDeleteKeyW(HKEY_CURRENT_USER, Path);
        }
    }
    RegDeleteKeyW(HKEY_CURRENT_USER, ROOT L"\\shared");
    RegDeleteKeyW(HKEY_CURRENT_USER, ROOT);
}
