/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The library of the LoadLibraryEx search order test: it imports ll_search_dep.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

__declspec(dllimport) DWORD WINAPI LlSearchDepMarker(void);

DWORD WINAPI LlSearchLibCall(void)
{
    return LlSearchDepMarker();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
