/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     childmod
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* T116 loader-contract helper: "child" module.
 *
 * Models the real-world mscoreei.dll DllMain precondition: a private child
 * component DLL that refuses to initialize unless its parent module is already
 * loaded in the process. mscoreei.dll's DllMain calls
 * GetModuleHandleW(L"mscoree.dll") as its first required step and returns FALSE
 * (so LoadLibrary fails with ERROR_DLL_INIT_FAILED / 1114) when it is absent.
 * This reproduces that behavior without .NET, so the loader contract can be
 * asserted generally. */
#include <windows.h>

DWORD
WINAPI
GetMarker(void)
{
    return 42;
}

BOOL
WINAPI
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        if (GetModuleHandleW(L"t116_dllinit_parent.dll") == NULL)
            return FALSE; /* parent-presence gate */
    }
    return TRUE;
}
