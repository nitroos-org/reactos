/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the LdrLoadDllPendingInit test: loadinit_p imports it before loadinit_b, so its DllMain
 *              runs while B (and C, which B imports) are mapped but not yet initialized. NTDLL_LOADINIT_MODE:
 *              ll = LoadLibrary(B), gpa = GetModuleHandle(B) + GetProcAddress(B), lln = LoadLibrary(N), a module
 *              that is not mapped yet and imports B
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "loadinit.h"

LONG
WINAPI
LoadInitAState(VOID)
{
    return 1;
}

BOOL
WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HMODULE hModule;

    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hinstDLL);
    LoadInitLog("A+");
    if (LoadInitEnvIs("NTDLL_LOADINIT_MODE", "ll"))
    {
        LoadInitLog("A:LL(B)");
        SetLastError(0);
        hModule = LoadLibraryW(L"ntdll_loadinit_b.dll");
        if (hModule)
        {
            LoadInitLog("A:LL(B)=ok");
            FreeLibrary(hModule);
        }
        else
        {
            LoadInitLog(GetLastError() == ERROR_DLL_INIT_FAILED ? "A:LL(B)=NULL,1114" : "A:LL(B)=NULL,other");
        }
    }
    else if (LoadInitEnvIs("NTDLL_LOADINIT_MODE", "gpa"))
    {
        hModule = GetModuleHandleW(L"ntdll_loadinit_b.dll");
        LoadInitLog("A:GPA(B)");
        if (hModule && GetProcAddress(hModule, "LoadInitBInitialized"))
            LoadInitLog("A:GPA(B)=ok");
        else
            LoadInitLog("A:GPA(B)=NULL");
    }
    else if (LoadInitEnvIs("NTDLL_LOADINIT_MODE", "lln"))
    {
        LoadInitLog("A:LL(N)");
        hModule = LoadLibraryW(L"ntdll_loadinit_n.dll");
        if (hModule)
        {
            LoadInitLog("A:LL(N)=ok");
            FreeLibrary(hModule);
        }
        else
        {
            LoadInitLog("A:LL(N)=NULL");
        }
    }
    LoadInitLog("A:ret");
    return TRUE;
}
