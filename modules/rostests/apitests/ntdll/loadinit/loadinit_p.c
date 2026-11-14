/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: imports loadinit_a, then loadinit_b
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

__declspec(dllimport) LONG WINAPI LoadInitAState(VOID);
__declspec(dllimport) LONG WINAPI LoadInitBInitialized(VOID);

/* Uses both imports so that the linker keeps them, in this order */
LONG g_Sum;

BOOL
WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        g_Sum = LoadInitAState() + LoadInitBInitialized();
    }
    return TRUE;
}
