/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for DwmFlush
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <dwmapi.h>

/* With composition enabled, DwmFlush blocks until the next composition pass.
 * Measured on Windows 10 22H2 (interactive session, 64 Hz display): 30 calls,
 * min 11.4 ms, avg 16-23 ms, max 34 ms; never under 1 ms. Applications pace
 * vsync threads with it, so an immediate return makes them spin. */
typedef HRESULT (WINAPI *PFN_DWMISCOMPOSITIONENABLED)(BOOL *);
typedef HRESULT (WINAPI *PFN_DWMFLUSH)(void);

START_TEST(DwmFlush)
{
    PFN_DWMISCOMPOSITIONENABLED pDwmIsCompositionEnabled;
    PFN_DWMFLUSH pDwmFlush;
    HMODULE hDwmapi;
    LARGE_INTEGER freq, start, end;
    BOOL enabled = FALSE;
    HRESULT hr;
    double ms, total = 0.0, min = 1e9;
    int i, fast = 0;

    hDwmapi = LoadLibraryW(L"dwmapi.dll");
    if (!hDwmapi)
    {
        skip("dwmapi.dll not available\n");
        return;
    }
    pDwmIsCompositionEnabled = (PFN_DWMISCOMPOSITIONENABLED)GetProcAddress(hDwmapi, "DwmIsCompositionEnabled");
    pDwmFlush = (PFN_DWMFLUSH)GetProcAddress(hDwmapi, "DwmFlush");
    ok(pDwmIsCompositionEnabled != NULL && pDwmFlush != NULL, "dwmapi exports missing\n");
    if (!pDwmIsCompositionEnabled || !pDwmFlush)
    {
        FreeLibrary(hDwmapi);
        return;
    }

    hr = pDwmIsCompositionEnabled(&enabled);
    ok(hr == S_OK, "DwmIsCompositionEnabled returned 0x%08lx\n", hr);
    if (hr != S_OK || !enabled)
    {
        skip("Desktop composition is disabled\n");
        FreeLibrary(hDwmapi);
        return;
    }

    QueryPerformanceFrequency(&freq);
    for (i = 0; i < 10; i++)
    {
        QueryPerformanceCounter(&start);
        hr = pDwmFlush();
        QueryPerformanceCounter(&end);
        ok(hr == S_OK, "DwmFlush #%d returned 0x%08lx\n", i, hr);
        ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        if (ms < 0.5)
            fast++;
        if (ms < min)
            min = ms;
        total += ms;
    }

    ok(fast == 0, "%d of 10 DwmFlush calls returned in under 0.5 ms (min %.3f ms)\n", fast, min);
    ok(total / 10 < 100.0, "DwmFlush took %.1f ms on average\n", total / 10);

    FreeLibrary(hDwmapi);
}
