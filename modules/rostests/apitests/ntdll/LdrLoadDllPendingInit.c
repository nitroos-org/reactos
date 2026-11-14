/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LoadLibrary of a module that is mapped but whose DllMain has not run yet
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * ntdll_loadinit_p imports ntdll_loadinit_a and then ntdll_loadinit_b, so loading it maps both, runs A's DllMain
 * first and B's later. A's DllMain loads B (no import of A names B): B is mapped, but not initialized, and
 * what LoadLibrary returns must be ready to use, that is, initialized (what Office's c2r64.dll relies on to call
 * into rpcrt4 and the C runtime that rpcrt4 imports, from its DllMain at process start).
 */

#include "precomp.h"

typedef LONG (WINAPI *PGETSTATE)(VOID);

START_TEST(LdrLoadDllPendingInit)
{
    HMODULE hP, hA, hB;
    PGETSTATE GetAState, GetBInitialized;
    LONG State;

    hP = LoadLibraryW(L"ntdll_loadinit_p.dll");
    if (!hP)
    {
        skip("ntdll_loadinit_p.dll is missing or does not load (error %lu)\n", GetLastError());
        return;
    }

    hA = GetModuleHandleW(L"ntdll_loadinit_a.dll");
    hB = GetModuleHandleW(L"ntdll_loadinit_b.dll");
    ok(hA != NULL, "A was not loaded as an import of P\n");
    ok(hB != NULL, "B was not loaded as an import of P\n");
    if (!hA || !hB)
        goto Done;

    GetAState = (PGETSTATE)GetProcAddress(hA, "LoadInitAState");
    GetBInitialized = (PGETSTATE)GetProcAddress(hB, "LoadInitBInitialized");
    ok(GetAState != NULL && GetBInitialized != NULL, "exports missing\n");
    if (!GetAState || !GetBInitialized)
        goto Done;

    State = GetAState();
    if (State == 3)
    {
        skip("B was initialized before A, the import order is not the one the test needs\n");
    }
    else
    {
        ok(State == 1, "A's DllMain saw B %s after LoadLibrary (state %ld)\n",
           State == 2 ? "not initialized" : "in an unexpected state", State);
    }
    ok(GetBInitialized() == 1, "B is not initialized at the end\n");

Done:
    FreeLibrary(hP);
}
