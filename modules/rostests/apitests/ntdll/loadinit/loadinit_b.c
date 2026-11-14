/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: a DLL that says whether its DllMain has run
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

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
        Initialized = 1;
    }
    return TRUE;
}
