/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for QueryUnbiasedInterruptTime
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef BOOL (WINAPI *FN_QueryUnbiasedInterruptTime)(PULONGLONG);
typedef ULONGLONG (WINAPI *FN_GetTickCount64)(VOID);
typedef VOID (WINAPI *FN_QueryUnbiasedInterruptTimePrecise)(PULONGLONG);

/* Windows 10 (and kernel32 here) exports the precise unbiased interrupt time; it has no result value */
static
VOID
test_Precise(
    _In_ HMODULE hKernel32,
    _In_ FN_QueryUnbiasedInterruptTime pQueryUnbiasedInterruptTime)
{
    FN_QueryUnbiasedInterruptTimePrecise pPrecise;
    ULONGLONG Coarse1, Coarse2, Time1, Time2, Prev;
    int i;

    /*
     * Windows exports it from kernelbase.dll only (programs reach it through api-ms-win-core-realtime-l1-1-1, which is
     * kernelbase there); the apisets of this system name kernel32, which implements it
     */
    pPrecise = (FN_QueryUnbiasedInterruptTimePrecise)GetProcAddress(hKernel32, "QueryUnbiasedInterruptTimePrecise");
    if (is_reactos() && pPrecise)
    {
        /*
         * Chrome delay-loads it through api-ms-win-core-realtime-l1-1-1 inside its sandbox, after lockdown, where loading
         * another DLL fails: the api set must resolve to kernel32, which implements the function, and not to kernelbase.dll
         * (it forwarded there once, and the renderer crashed in the delay-load failure handler). Whether kernelbase.dll
         * is loaded in the process does not matter: shlwapi imports it
         */
        HMODULE hApi = LoadLibraryW(L"api-ms-win-core-realtime-l1-1-1.dll");
        ok(hApi != NULL, "api-ms-win-core-realtime-l1-1-1.dll does not load, error %lu\n", GetLastError());
        if (hApi)
            ok(GetProcAddress(hApi, "QueryUnbiasedInterruptTimePrecise") == (FARPROC)pPrecise,
               "The api set does not resolve to the kernel32 export\n");
        ok(hApi == hKernel32, "The api set resolves to module %p, not to kernel32 %p\n", hApi, hKernel32);
    }
    if (!pPrecise && !is_reactos())
        pPrecise = (FN_QueryUnbiasedInterruptTimePrecise)GetProcAddress(LoadLibraryW(L"kernelbase.dll"),
                                                                         "QueryUnbiasedInterruptTimePrecise");
    if (!pPrecise && is_reactos() && !GetProcAddress(hKernel32, "K32EnumProcesses"))
    {
        skip("No NT 6.1 exports\n");
        return;
    }
    ok(pPrecise != NULL, "QueryUnbiasedInterruptTimePrecise is not exported\n");
    if (!pPrecise)
        return;

    /* It agrees with the coarse time to within a clock tick or two (15.6 ms each) */
    pQueryUnbiasedInterruptTime(&Coarse1);
    pPrecise(&Time1);
    pQueryUnbiasedInterruptTime(&Coarse2);
    ok(Time1 + 400000 >= Coarse1, "Precise %I64u is behind the coarse time %I64u\n", Time1, Coarse1);
    ok(Time1 <= Coarse2 + 400000, "Precise %I64u is ahead of the coarse time %I64u\n", Time1, Coarse2);

    Sleep(100);
    pPrecise(&Time2);
    ok(Time2 >= Time1 + 80 * 10000, "Precise time advanced by only %I64u\n", Time2 - Time1);
    ok(Time2 <= Time1 + 400 * 10000, "Precise time advanced by %I64u\n", Time2 - Time1);

    /* Never goes backwards, and it moves in steps finer than the clock tick */
    Prev = Time2;
    for (i = 0; i < 100000; i++)
    {
        pPrecise(&Time2);
        if (Time2 < Prev)
            break;
        Prev = Time2;
    }
    ok(i == 100000, "Precise time went backwards at %d: %I64u -> %I64u\n", i, Prev, Time2);

    /* Not a multiple of the clock tick that the coarse time is read from */
    Time1 = 0;
    for (i = 0; i < 1000; i++)
    {
        pPrecise(&Time2);
        if (Time2 % 156250)
            Time1++;
    }
    ok(Time1 > 900, "Precise time is on clock tick boundaries (%I64u of 1000 off the tick)\n", Time1);
}

typedef VOID (WINAPI *FN_QueryInterruptTime)(PULONGLONG);

/*
 * QueryInterruptTime and QueryInterruptTimePrecise (the biased interrupt time) must resolve through
 * api-ms-win-core-realtime-l1-1-1, which is kernel32 here: Chrome 158 delay-loads QueryInterruptTimePrecise
 * through the api set, and a failed lookup ends the browser process in its delay-load failure handler.
 */
static
VOID
test_InterruptTime(
    _In_ HMODULE hKernel32,
    _In_ FN_QueryUnbiasedInterruptTime pQueryUnbiasedInterruptTime)
{
    FN_QueryInterruptTime pInterrupt, pInterruptPrecise, pApiInterrupt, pApiPrecise;
    HMODULE hHost = hKernel32, hApi;
    ULONGLONG Unbiased1, Unbiased2, Time1, Time2, Prev;
    int i;

    if (!is_reactos())
    {
        /* Windows exports them from kernelbase.dll */
        hHost = LoadLibraryW(L"kernelbase.dll");
        if (!hHost)
        {
            skip("kernelbase.dll does not load\n");
            return;
        }
    }
    pInterrupt = (FN_QueryInterruptTime)GetProcAddress(hHost, "QueryInterruptTime");
    pInterruptPrecise = (FN_QueryInterruptTime)GetProcAddress(hHost, "QueryInterruptTimePrecise");
    if (!pInterrupt && !pInterruptPrecise && is_reactos() && !GetProcAddress(hKernel32, "K32EnumProcesses"))
    {
        skip("No NT 6.1 exports\n");
        return;
    }
    ok(pInterrupt != NULL, "QueryInterruptTime is not exported\n");
    ok(pInterruptPrecise != NULL, "QueryInterruptTimePrecise is not exported\n");
    if (!pInterrupt || !pInterruptPrecise)
        return;

    /* The lookups the delay-load helper makes: the api set module, then the function by name */
    hApi = LoadLibraryW(L"api-ms-win-core-realtime-l1-1-1.dll");
    if (hApi)
    {
        pApiInterrupt = (FN_QueryInterruptTime)GetProcAddress(hApi, "QueryInterruptTime");
        pApiPrecise = (FN_QueryInterruptTime)GetProcAddress(hApi, "QueryInterruptTimePrecise");
        ok(pApiInterrupt != NULL, "The api set has no QueryInterruptTime, error %lu\n", GetLastError());
        ok(pApiPrecise != NULL, "The api set has no QueryInterruptTimePrecise, error %lu\n", GetLastError());
        if (is_reactos())
        {
            ok(pApiInterrupt == pInterrupt, "The api set does not resolve to the kernel32 QueryInterruptTime\n");
            ok(pApiPrecise == pInterruptPrecise, "The api set does not resolve to the kernel32 QueryInterruptTimePrecise\n");
        }
    }
    else
    {
        ok(0, "api-ms-win-core-realtime-l1-1-1.dll does not load, error %lu\n", GetLastError());
    }

    /* The interrupt time includes sleep, so it is never behind the unbiased time (it is the same while the bias is 0) */
    pQueryUnbiasedInterruptTime(&Unbiased1);
    pInterrupt(&Time1);
    pQueryUnbiasedInterruptTime(&Unbiased2);
    ok(Time1 + 400000 >= Unbiased1, "Interrupt time %I64u is behind the unbiased time %I64u\n", Time1, Unbiased1);
    ok(Time1 <= Unbiased2 + 400000, "Interrupt time %I64u is ahead of the unbiased time %I64u\n", Time1, Unbiased2);

    Time1 = 0;
    pInterrupt(&Time1);
    ok(Time1 != 0, "QueryInterruptTime gave 0\n");
    Sleep(100);
    pInterrupt(&Time2);
    ok(Time2 >= Time1 + 80 * 10000, "QueryInterruptTime advanced by only %I64u\n", Time2 - Time1);

    /* The precise time agrees with the coarse one to within a clock tick or two, and never goes backwards */
    pInterrupt(&Time1);
    pInterruptPrecise(&Time2);
    ok(Time2 + 400000 >= Time1, "Precise %I64u is behind the interrupt time %I64u\n", Time2, Time1);
    pInterrupt(&Time1);
    ok(Time2 <= Time1 + 400000, "Precise %I64u is ahead of the interrupt time %I64u\n", Time2, Time1);

    Sleep(100);
    pInterruptPrecise(&Time1);
    ok(Time1 >= Time2 + 80 * 10000, "Precise time advanced by only %I64u\n", Time1 - Time2);

    Prev = Time1;
    for (i = 0; i < 100000; i++)
    {
        pInterruptPrecise(&Time2);
        if (Time2 < Prev)
            break;
        Prev = Time2;
    }
    ok(i == 100000, "Precise time went backwards at %d: %I64u -> %I64u\n", i, Prev, Time2);
}

START_TEST(QueryUnbiasedInterruptTime)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FN_QueryUnbiasedInterruptTime pQueryUnbiasedInterruptTime;
    FN_GetTickCount64 pGetTickCount64;
    ULONGLONG Time1, Time2, Ticks;
    BOOL Ret;
    int i;

    pQueryUnbiasedInterruptTime = (FN_QueryUnbiasedInterruptTime)GetProcAddress(hKernel32, "QueryUnbiasedInterruptTime");
    if (!pQueryUnbiasedInterruptTime && is_reactos() && !GetProcAddress(hKernel32, "K32EnumProcesses"))
    {
        skip("No NT 6.1 exports\n");
        return;
    }
    ok(pQueryUnbiasedInterruptTime != NULL, "QueryUnbiasedInterruptTime is not exported\n");
    if (!pQueryUnbiasedInterruptTime)
        return;
    pGetTickCount64 = (FN_GetTickCount64)GetProcAddress(hKernel32, "GetTickCount64");

    SetLastError(0xdeadbeef);
    Ret = pQueryUnbiasedInterruptTime(NULL);
    ok(Ret == FALSE, "Ret = %d\n", Ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError() = %lu\n", GetLastError());

    Time1 = 0;
    SetLastError(0xdeadbeef);
    Ret = pQueryUnbiasedInterruptTime(&Time1);
    ok(Ret == TRUE, "Ret = %d\n", Ret);
    ok(GetLastError() == 0xdeadbeef, "GetLastError() = %lu\n", GetLastError());
    ok(Time1 != 0, "Time1 is 0\n");

    /* The unbiased time leaves out sleep, so it can never run ahead of the tick count (100 ns units vs ms) */
    if (pGetTickCount64)
    {
        Ticks = pGetTickCount64();
        ok(Time1 <= (Ticks + 1000) * 10000, "Time1 %I64u is ahead of the tick count %I64u ms\n", Time1, Ticks);
    }

    Sleep(100);
    Ret = pQueryUnbiasedInterruptTime(&Time2);
    ok(Ret == TRUE, "Ret = %d\n", Ret);
    ok(Time2 >= Time1 + 80 * 10000, "Time advanced by only %I64u\n", Time2 - Time1);

    /* Never goes backwards */
    for (i = 0; i < 100000; i++)
    {
        Time1 = Time2;
        pQueryUnbiasedInterruptTime(&Time2);
        if (Time2 < Time1)
            break;
    }
    ok(i == 100000, "Time went backwards at %d: %I64u -> %I64u\n", i, Time1, Time2);

    test_Precise(hKernel32, pQueryUnbiasedInterruptTime);
    test_InterruptTime(hKernel32, pQueryUnbiasedInterruptTime);
}
