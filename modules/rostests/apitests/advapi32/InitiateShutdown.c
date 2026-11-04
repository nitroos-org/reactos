/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for InitiateShutdownW/A: the export, and the argument checks (which do not shut anything down)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * InitiateShutdownW always returned success without doing anything here, and was not even exported.
 */

#include "precomp.h"

typedef DWORD (WINAPI *PFN_InitiateShutdownW)(LPWSTR, LPWSTR, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_InitiateShutdownA)(LPSTR, LPSTR, DWORD, DWORD, DWORD);

START_TEST(InitiateShutdown)
{
    HMODULE Advapi32 = GetModuleHandleW(L"advapi32.dll");
    PFN_InitiateShutdownW pInitiateShutdownW = (PFN_InitiateShutdownW)GetProcAddress(Advapi32, "InitiateShutdownW");
    PFN_InitiateShutdownA pInitiateShutdownA = (PFN_InitiateShutdownA)GetProcAddress(Advapi32, "InitiateShutdownA");
    DWORD Ret;

    if (!pInitiateShutdownW || !pInitiateShutdownA)
    {
        ok(!is_reactos(), "InitiateShutdownW or InitiateShutdownA is not exported\n");
        skip("InitiateShutdown is not available\n");
        return;
    }

    /* a flag that does not exist: refused before anything happens */
    Ret = pInitiateShutdownW(NULL, NULL, 0, 0x80000000, 0);
    ok(Ret == ERROR_INVALID_PARAMETER, "W with an invalid flag: %lu\n", Ret);
    Ret = pInitiateShutdownA(NULL, NULL, 0, 0x80000000, 0);
    ok(Ret == ERROR_INVALID_PARAMETER, "A with an invalid flag: %lu\n", Ret);
}
