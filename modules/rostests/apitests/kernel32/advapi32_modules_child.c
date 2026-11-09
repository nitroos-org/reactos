/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Console process that imports advapi32 and reports which window and socket modules are loaded
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

int mainCRTStartup(void)
{
    static const WCHAR *Names[] = { L"ws2_32.dll", L"user32.dll", L"gdi32.dll", L"lpk.dll", L"usp10.dll", L"imm32.dll" };
    int ExitCode = 0, i;
    HKEY Key;

    /* A registry call keeps the advapi32 import used and makes sure its initialization ran */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &Key) == ERROR_SUCCESS)
        RegCloseKey(Key);
    if (!GetModuleHandleW(L"advapi32.dll"))
        return 0x100;
    for (i = 0; i < 6; i++)
        if (GetModuleHandleW(Names[i]))
            ExitCode |= 1 << i;
    return ExitCode;
}
