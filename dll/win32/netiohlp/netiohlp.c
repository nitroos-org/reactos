/*
 * PROJECT:     ReactOS Net IO Helper DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     netsh helper DLL entry point
 */

#include "precomp.h"

HINSTANCE hDllInstance;

DWORD
WINAPI
InitHelperDll(
    _In_ DWORD dwNetshVersion,
    _Out_ PVOID pReserved)
{
    return RegisterPortProxyHelper();
}

BOOL
WINAPI
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD dwReason,
    _In_ LPVOID lpvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        hDllInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
