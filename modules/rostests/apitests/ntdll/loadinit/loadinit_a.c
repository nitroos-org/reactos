/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: its DllMain loads loadinit_b, which is already mapped
 *              (a static import of the module that is being loaded) but whose DllMain has not run yet
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

typedef LONG (WINAPI *PGETSTATE)(VOID);

/* 0: not observed; 1: loaded, B ready when LoadLibrary returned; 2: loaded, B not initialized;
 * 3: B was already initialized when this DllMain started (the test's precondition does not hold);
 * negative: a step failed */
static volatile LONG State;

LONG
WINAPI
LoadInitAState(VOID)
{
    return State;
}

BOOL
WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HMODULE hB;
    PGETSTATE GetBState;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);

        hB = GetModuleHandleW(L"ntdll_loadinit_b.dll");
        GetBState = hB ? (PGETSTATE)GetProcAddress(hB, "LoadInitBInitialized") : NULL;
        if (!GetBState)
        {
            State = -1;
            return TRUE;
        }
        if (GetBState())
        {
            State = 3;
            return TRUE;
        }

        hB = LoadLibraryW(L"ntdll_loadinit_b.dll");
        if (!hB)
        {
            State = -2;
            return TRUE;
        }
        GetBState = (PGETSTATE)GetProcAddress(hB, "LoadInitBInitialized");
        if (!GetBState)
        {
            State = -3;
            return TRUE;
        }
        State = GetBState() ? 1 : 2;
        FreeLibrary(hB);
    }
    return TRUE;
}
