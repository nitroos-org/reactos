/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: imports loadinit_c, logs whether C was initialized
 *              before it, and fails its DllMain when NTDLL_LOADINIT_BFAIL=1
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "loadinit.h"

__declspec(dllimport) LONG WINAPI LoadInitCInitialized(VOID);

static volatile LONG Initialized;

LONG
WINAPI
LoadInitBInitialized(VOID)
{
    return Initialized;
}

BOOL
WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        LoadInitLog(LoadInitCInitialized() ? "B+(C=1)" : "B+(C=0)");
        if (LoadInitEnvIs("NTDLL_LOADINIT_BFAIL", "1"))
        {
            LoadInitLog("B:FALSE");
            return FALSE;
        }
        Initialized = 1;
    }
    return TRUE;
}
