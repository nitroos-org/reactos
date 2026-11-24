/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The first call of a delay-loaded function keeps its floating point arguments
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The delay-load stub calls the helper, which loads the DLL and resolves the import; the helper (and the hooks
 * it calls) may use xmm0-xmm3, which carry the first four floating point arguments on x64. The notify hook
 * of this program overwrites them, so that the result does not depend on what the helper happens to use.
 */

#define WIN32_NO_STATUS
#include <windows.h>
#include <delayimp.h>
#include <wine/test.h>

double WINAPI DelayXmmSum(double a, double b, double c, double d);
float WINAPI DelayXmmSumFloat(float a, float b, float c, float d);

static LONG g_HookCalls;
static LONG g_ResolveCalls;

static FARPROC WINAPI NotifyHook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    InterlockedIncrement(&g_HookCalls);
    if (dliNotify == dliStartProcessing)
        InterlockedIncrement(&g_ResolveCalls);
#ifdef _M_AMD64
    /* volatile registers: this is allowed, a caller cannot rely on them */
    __asm__ __volatile__("xorpd %%xmm0, %%xmm0\n\t"
                         "xorpd %%xmm1, %%xmm1\n\t"
                         "xorpd %%xmm2, %%xmm2\n\t"
                         "xorpd %%xmm3, %%xmm3\n\t"
                         ::: "xmm0", "xmm1", "xmm2", "xmm3");
#endif
    return NULL;
}

PfnDliHook __pfnDliNotifyHook2 = NotifyHook;

START_TEST(delayxmm)
{
    double d;
    float f;
    LONG calls;

    d = DelayXmmSum(1.0, 2.0, 3.0, 4.0);
    ok(d == 1234.0, "first call returned %f, expected 1234\n", d);
    ok(g_ResolveCalls == 1, "the import was resolved %ld times\n", g_ResolveCalls);
    ok(g_HookCalls > 0, "the notify hook was not called\n");

    calls = g_HookCalls;
    d = DelayXmmSum(5.0, 6.0, 7.0, 8.0);
    ok(d == 5678.0, "second call returned %f, expected 5678\n", d);
    ok(g_HookCalls == calls, "the second call went through the helper again\n");

    /* another function of the same DLL: its first call resolves it */
    f = DelayXmmSumFloat(2.0f, 4.0f, 6.0f, 8.0f);
    ok(f == 2468.0f, "first call of the float function returned %f, expected 2468\n", f);
    f = DelayXmmSumFloat(1.0f, 3.0f, 5.0f, 7.0f);
    ok(f == 1357.0f, "second call of the float function returned %f, expected 1357\n", f);
}
