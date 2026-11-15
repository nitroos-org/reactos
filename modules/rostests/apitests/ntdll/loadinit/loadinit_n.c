/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: imports loadinit_b, nobody imports it; loadinit_a's
 *              DllMain loads it while B is mapped but not yet initialized
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "loadinit.h"

__declspec(dllimport) LONG WINAPI LoadInitBInitialized(VOID);

BOOL
WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        LoadInitLog(LoadInitBInitialized() ? "N+(B=1)" : "N+(B=0)");
    }
    return TRUE;
}
