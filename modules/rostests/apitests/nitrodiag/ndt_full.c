/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper DLL of the compatibility log tool tests: exports two functions
 */

#include <windows.h>

int WINAPI NdFuncA(void) { return 1; }
int WINAPI NdFuncB(void) { return 2; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    return TRUE;
}
