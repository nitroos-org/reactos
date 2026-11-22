/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: imported by loadinit_b only
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "loadinit.h"

static volatile LONG Initialized;

LONG
WINAPI
LoadInitCInitialized(VOID)
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
        LoadInitLog("C+");
        Initialized = 1;
        if (LoadInitEnvIs("NTDLL_LOADINIT_MODE", "cll"))
        {
            /* the module that imports C, while C's DllMain runs (mode cll) */
            HMODULE hModule;

            LoadInitLog("C:LL(B)");
            hModule = LoadLibraryW(L"ntdll_loadinit_b.dll");
            LoadInitLog(hModule ? "C:LL(B)=ok" : "C:LL(B)=NULL");
            if (hModule) FreeLibrary(hModule);
        }
    }
    return TRUE;
}
